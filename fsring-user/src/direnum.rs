//! The volatile directory-enumeration engine.
//!
//! Holds a per-`(kernel_open_id, enumeration_generation)` immutable match
//! sequence (provider candidates filtered through the slice-3 name matcher, in
//! provider order) and emits capacity-bounded batches of canonical `DirEntryV1`
//! records with verified-ordinal cookies. Each produced batch is self-validated
//! by the frozen, grant-free `validate_query_dir_result_v1`. Pure and `std`-only
//! — no ring, no section, no `unsafe`. The U2K output write-back (copying the
//! produced bytes into the grant) and the native formatting/spill are E's /
//! kernel's (PENDING).
//!
//! Snapshot immutability holds per key: `open` (an initial/RESTART request)
//! (re)builds the sequence for its `(kernel_open_id, generation)`, so
//! `05-irp-dispatch.md` §12.7's "only a genuine next generation may supersede a
//! snapshot" rests on the caller always supplying a fresh generation. Enforcing
//! generation monotonicity (and the wrap latch, §12.5-12.6) is the PENDING
//! kernel `snapshot_state` machine's job, not this volatile engine's.

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::ids::{FileId, LinkId};
use fsring_abi::limits::MAX_COMPONENT_UTF16_CODE_UNITS;
use fsring_abi::msgs::{
    query_dir_result_flags, BlobSlice, ControlHeader, DirEntryV1, QueryDirResultV1, SizeState,
};
use fsring_abi::validate::{validate_query_dir_result_v1, QueryDirFormV21};

use std::collections::HashMap;

use crate::error::EnumError;
use crate::namematch::NameMatcher;
use crate::querydir::QueryDirRequest;

/// The `DirEntryV1` scalar fields the provider supplies for a candidate entry
/// (`reparse_tag`/`flags`/`reserved` are always zero — REPARSE is unselectable).
#[derive(Clone)]
pub struct DirEntryFields {
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub namespace_generation: u64,
    pub attributes: u32,
}

/// A provider-supplied enumeration candidate: a UTF-16LE name (even length, no
/// wildcard token) plus its entry fields.
#[derive(Clone)]
pub struct DirCandidate {
    pub name: Box<[u8]>,
    pub fields: DirEntryFields,
}

/// One emitted enumeration batch: the encoded `QueryDirResultV1` + entries blob
/// (which E copies into the U2K output grant) and its decoded scalars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryDirBatch {
    pub blob: Vec<u8>,
    pub entry_count: u32,
    pub next_cookie: u64,
    pub eof: bool,
}

/// Round up to the next multiple of 8.
fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Encode `entries` into a `QueryDirResultV1` blob (40-byte prefix + entries),
/// with the given cookie/EOF. The bytes are shaped to satisfy
/// `validate_query_dir_result_v1`.
fn encode_result(
    entries: &[DirCandidate],
    input_cookie: u64,
    next_cookie: u64,
    eof: bool,
) -> Result<Vec<u8>, EnumError> {
    // Pack the entries: each is a 136-byte DirEntryV1 prefix + the UTF-16LE name
    // at offset 136, zero-padded to align8(136 + name).
    let mut entries_bytes: Vec<u8> = Vec::new();
    for candidate in entries {
        let name_len = candidate.name.len();
        if name_len > MAX_COMPONENT_UTF16_CODE_UNITS as usize * 2 {
            return Err(EnumError::NameTooLong);
        }
        let struct_size = align8(136 + name_len);
        let fields = &candidate.fields;
        let entry = DirEntryV1 {
            header: ControlHeader {
                struct_size: struct_size as u32,
                struct_version: 1,
                required_flags: 0,
            },
            file_id: fields.file_id,
            link_id: fields.link_id,
            sizes: fields.sizes,
            creation_time: fields.creation_time,
            last_access_time: fields.last_access_time,
            last_write_time: fields.last_write_time,
            change_time: fields.change_time,
            namespace_generation: fields.namespace_generation,
            attributes: fields.attributes,
            reparse_tag: 0,
            flags: 0,
            reserved: 0,
            name: BlobSlice {
                offset: 136,
                length: name_len as u32,
            },
        };
        let start = entries_bytes.len();
        entries_bytes.resize(start + struct_size, 0);
        try_encode(&entry, &mut entries_bytes[start..start + 136])
            .expect("DirEntryV1 is 136 bytes");
        entries_bytes[start + 136..start + 136 + name_len].copy_from_slice(&candidate.name);
    }

    // Frame the QueryDirResultV1 (40-byte prefix) over the entries.
    let entries_len = entries_bytes.len();
    let total = 40 + entries_len;
    let entries_slice = if entries_len == 0 {
        BlobSlice {
            offset: 0,
            length: 0,
        }
    } else {
        BlobSlice {
            offset: 40,
            length: entries_len as u32,
        }
    };
    let result = QueryDirResultV1 {
        header: ControlHeader {
            struct_size: total as u32,
            struct_version: 1,
            required_flags: 0,
        },
        next_cookie,
        flags: if eof { query_dir_result_flags::EOF } else { 0 },
        entry_count: entries.len() as u32,
        entries: entries_slice,
        required_length: 0,
        reserved: 0,
    };
    let mut blob = vec![0u8; total];
    try_encode(&result, &mut blob[..40]).expect("QueryDirResultV1 is 40 bytes");
    blob[40..].copy_from_slice(&entries_bytes);

    // Self-validate: prove the produced bytes satisfy the frozen ABI (a malformed
    // candidate surfaces here rather than as illegal wire output).
    let decoded: QueryDirResultV1 = try_decode(&blob).expect("just encoded 40+ bytes");
    validate_query_dir_result_v1(&decoded, &blob, input_cookie).map_err(EnumError::Encode)?;
    Ok(blob)
}

/// Decode a UTF-16LE candidate name into `u16` code units for the matcher.
fn utf16le_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// The volatile directory-enumeration engine for one mount/session: a snapshot
/// (the immutable filtered match sequence) per `(kernel_open_id, generation)`.
#[derive(Default)]
pub struct DirEnumerator {
    snapshots: HashMap<(u64, u64), Vec<DirCandidate>>,
}

impl DirEnumerator {
    /// A fresh enumerator with no snapshots.
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin an enumeration (an initial/RESTART request): compile the matcher,
    /// filter `candidates` into the immutable match sequence keyed by
    /// `(kernel_open_id, generation)`, and emit the first batch from cookie 0.
    pub fn open(
        &mut self,
        kernel_open_id: u64,
        request: &QueryDirRequest,
        candidates: Vec<DirCandidate>,
    ) -> Result<QueryDirBatch, EnumError> {
        debug_assert!(
            !matches!(request.form, QueryDirFormV21::Continuation),
            "open expects an initial (RESTART) form, not a Continuation"
        );
        let matcher = match &request.pattern {
            None => NameMatcher::MatchAll,
            Some(pattern) => NameMatcher::compile(pattern)?,
        };
        let sequence: Vec<DirCandidate> = candidates
            .into_iter()
            .filter(|candidate| matcher.matches(&utf16le_units(&candidate.name)))
            .collect();
        let key = (kernel_open_id, request.enumeration_generation);
        self.snapshots.insert(key, sequence);
        batch(
            &self.snapshots[&key],
            request.enumeration_cookie,
            request.output_capacity,
            request.single,
        )
    }

    /// Resume an enumeration (a `Continuation` request): resolve the snapshot by
    /// `(kernel_open_id, generation)` and emit the next batch from the request's
    /// cookie.
    pub fn continue_(
        &mut self,
        kernel_open_id: u64,
        request: &QueryDirRequest,
    ) -> Result<QueryDirBatch, EnumError> {
        debug_assert!(
            request.form == QueryDirFormV21::Continuation,
            "continue_ expects a Continuation form"
        );
        let sequence = self
            .snapshots
            .get(&(kernel_open_id, request.enumeration_generation))
            .ok_or(EnumError::UnknownGeneration)?;
        batch(
            sequence,
            request.enumeration_cookie,
            request.output_capacity,
            request.single,
        )
    }
}

/// Emit one batch from `seq` starting at `input_cookie`, bounded by `capacity`
/// (and by one entry if `single`). A produced batch always carries at least one
/// entry; an empty/exhausted sequence is `NoMoreEntries` for the daemon to map
/// to its form-specific terminal completion, and EOF is set when the batch
/// consumes the final entry (`next_cookie = 0`, else `input_cookie + count`).
fn batch(
    seq: &[DirCandidate],
    input_cookie: u64,
    capacity: u32,
    single: bool,
) -> Result<QueryDirBatch, EnumError> {
    let start = usize::try_from(input_cookie).map_err(|_| EnumError::CookieOutOfRange)?;
    if start > seq.len() {
        return Err(EnumError::CookieOutOfRange);
    }
    if start == seq.len() {
        return Err(EnumError::NoMoreEntries);
    }
    let budget = (capacity as usize)
        .checked_sub(40)
        .ok_or(EnumError::OutputTooSmall)?;
    let mut used = 0usize;
    let mut count = 0usize;
    for candidate in &seq[start..] {
        // Reject on the same 255-code-unit (510-byte) stored-component bound the
        // encoder uses, so the batch/encode name limit is identical.
        if candidate.name.len() > MAX_COMPONENT_UTF16_CODE_UNITS as usize * 2 {
            return Err(EnumError::NameTooLong);
        }
        let size = align8(136 + candidate.name.len());
        if used + size > budget {
            if count == 0 {
                // The kernel always issues a grant fitting one maximum entry, so
                // this only fires if that guarantee was violated.
                return Err(EnumError::OutputTooSmall);
            }
            break;
        }
        used += size;
        count += 1;
        if single {
            break;
        }
    }
    let end = start + count;
    let eof = end == seq.len();
    let next_cookie = if eof { 0 } else { input_cookie + count as u64 };
    let blob = encode_result(&seq[start..end], input_cookie, next_cookie, eof)?;
    Ok(QueryDirBatch {
        blob,
        entry_count: count as u32,
        next_cookie,
        eof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::codec::try_decode;
    use fsring_abi::msgs::{file_attributes, BufferRef, QueryDirResultV1};
    use fsring_abi::validate::{validate_query_dir_result_v1, QueryDirFormV21};

    fn candidate(name: &str) -> DirCandidate {
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        DirCandidate {
            name: utf16.into_boxed_slice(),
            fields: DirEntryFields {
                file_id: FileId { lo: 1, hi: 0 },
                link_id: LinkId { lo: 1, hi: 0 },
                sizes: SizeState {
                    allocation_size: 0,
                    file_size: 0,
                    valid_data_length: 0,
                    size_epoch: 1,
                },
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                namespace_generation: 1,
                attributes: file_attributes::NORMAL,
            },
        }
    }

    #[test]
    fn one_entry_batch_validates() {
        let entries = vec![candidate("a.txt")];
        let blob = encode_result(&entries, 0, 1, false).expect("encode");
        let result: QueryDirResultV1 = try_decode(&blob).unwrap();
        let validated =
            validate_query_dir_result_v1(&result, &blob, 0).expect("ABI accepts our bytes");
        assert_eq!(validated.entry_count(), 1);
        assert_eq!(validated.next_cookie(), 1);
        assert!(!validated.eof());
    }

    #[test]
    fn eof_batch_has_zero_next_cookie() {
        let entries = vec![candidate("a.txt")];
        let blob = encode_result(&entries, 0, 0, true).expect("encode");
        let result: QueryDirResultV1 = try_decode(&blob).unwrap();
        let validated = validate_query_dir_result_v1(&result, &blob, 0).expect("ABI accepts");
        assert!(validated.eof());
        assert_eq!(validated.next_cookie(), 0);
    }

    // "a.txt" = 5 UTF-16 units = 10 bytes -> align8(136 + 10) = 152 bytes/entry.
    const ENTRY_SIZE: u32 = 152;

    fn match_all_request(output_capacity: u32, single: bool) -> QueryDirRequest {
        QueryDirRequest {
            form: QueryDirFormV21::InitialMatchAll,
            enumeration_generation: 5,
            enumeration_cookie: 0,
            single,
            output_capacity,
            output: BufferRef {
                length: output_capacity,
                ..Default::default()
            },
            pattern: None,
        }
    }

    fn validates(batch: &QueryDirBatch, input_cookie: u64) {
        let result: QueryDirResultV1 = try_decode(&batch.blob).unwrap();
        validate_query_dir_result_v1(&result, &batch.blob, input_cookie).expect("batch validates");
    }

    #[test]
    fn open_returns_all_matching_entries_with_eof() {
        let mut eng = DirEnumerator::new();
        let candidates = vec![candidate("a.txt"), candidate("b.txt"), candidate("c.txt")];
        let batch = eng
            .open(0x33, &match_all_request(4096, false), candidates)
            .expect("open");
        assert_eq!(batch.entry_count, 3);
        assert!(batch.eof);
        assert_eq!(batch.next_cookie, 0);
        validates(&batch, 0);
    }

    #[test]
    fn single_returns_one_entry() {
        let mut eng = DirEnumerator::new();
        let candidates = vec![candidate("a.txt"), candidate("b.txt")];
        let batch = eng
            .open(0x33, &match_all_request(4096, true), candidates)
            .expect("open");
        assert_eq!(batch.entry_count, 1);
        assert!(!batch.eof);
        assert_eq!(batch.next_cookie, 1);
        validates(&batch, 0);
    }

    #[test]
    fn capacity_bounds_the_batch() {
        let mut eng = DirEnumerator::new();
        let candidates = vec![candidate("a.txt"), candidate("b.txt"), candidate("c.txt")];
        // Room for exactly 2 entries (40 + 2 * 152).
        let batch = eng
            .open(
                0x33,
                &match_all_request(40 + 2 * ENTRY_SIZE, false),
                candidates,
            )
            .expect("open");
        assert_eq!(batch.entry_count, 2);
        assert!(!batch.eof);
        assert_eq!(batch.next_cookie, 2);
        validates(&batch, 0);
    }

    #[test]
    fn empty_candidates_is_no_more_entries() {
        let mut eng = DirEnumerator::new();
        assert_eq!(
            eng.open(0x33, &match_all_request(4096, false), vec![]),
            Err(EnumError::NoMoreEntries)
        );
    }

    fn continuation_request(cookie: u64, output_capacity: u32) -> QueryDirRequest {
        QueryDirRequest {
            form: QueryDirFormV21::Continuation,
            enumeration_generation: 5,
            enumeration_cookie: cookie,
            single: false,
            output_capacity,
            output: BufferRef {
                length: output_capacity,
                ..Default::default()
            },
            pattern: None,
        }
    }

    #[test]
    fn continue_resumes_to_eof() {
        let mut eng = DirEnumerator::new();
        let candidates = vec![candidate("a.txt"), candidate("b.txt"), candidate("c.txt")];
        let first = eng
            .open(
                0x33,
                &match_all_request(40 + 2 * ENTRY_SIZE, false),
                candidates,
            )
            .expect("open");
        assert_eq!(first.entry_count, 2);
        assert_eq!(first.next_cookie, 2);

        let second = eng
            .continue_(0x33, &continuation_request(first.next_cookie, 4096))
            .expect("continue");
        assert_eq!(second.entry_count, 1);
        assert!(second.eof);
        assert_eq!(second.next_cookie, 0);
        validates(&second, first.next_cookie);
    }

    #[test]
    fn continue_unknown_generation_is_rejected() {
        let mut eng = DirEnumerator::new();
        assert_eq!(
            eng.continue_(0x99, &continuation_request(1, 4096)),
            Err(EnumError::UnknownGeneration)
        );
    }

    #[test]
    fn continue_past_the_end_is_out_of_range() {
        let mut eng = DirEnumerator::new();
        eng.open(
            0x33,
            &match_all_request(4096, false),
            vec![candidate("a.txt")],
        )
        .expect("open");
        assert_eq!(
            eng.continue_(0x33, &continuation_request(5, 4096)),
            Err(EnumError::CookieOutOfRange)
        );
    }
}
