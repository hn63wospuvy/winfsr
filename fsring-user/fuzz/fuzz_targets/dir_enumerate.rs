#![no_main]
//! Fuzz the directory-enumeration engine: an arbitrary candidate set enumerated
//! over arbitrary (capacity, single) with cookie continuation must never panic,
//! must emit only batches of >= 1 entry, and every produced batch must
//! re-validate through the frozen grant-free `validate_query_dir_result_v1`.

use libfuzzer_sys::fuzz_target;

use fsring_abi::codec::try_decode;
use fsring_abi::ids::{FileId, LinkId};
use fsring_abi::msgs::{file_attributes, BufferRef, QueryDirResultV1, SizeState};
use fsring_abi::validate::{validate_query_dir_result_v1, QueryDirFormV21};
use fsring_user::{DirCandidate, DirEntryFields, DirEnumerator, EnumError, QueryDirRequest};

/// A valid candidate: an even-length UTF-16LE name of `units` code units (all
/// `A`..`Z`, no wildcard token), with legal identity/attribute fields.
fn candidate(seed: u8, units: usize) -> DirCandidate {
    let units = units.max(1);
    let ch = 0x41u16 + u16::from(seed % 26);
    let name: Vec<u8> = (0..units).flat_map(|_| ch.to_le_bytes()).collect();
    DirCandidate {
        name: name.into_boxed_slice(),
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

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let single = selector & 0x80 != 0;
    // Capacity >= 40 + 648, so the kernel-grant guarantee (one max entry fits)
    // holds; the candidate names are short, so many entries fit.
    let capacity = 40 + 648 + (u32::from(selector) & 0x3f) * 64;
    let candidates: Vec<DirCandidate> = data
        .iter()
        .skip(1)
        .take(16)
        .enumerate()
        .map(|(i, &b)| candidate(b, (i % 4) + 1))
        .collect();

    let base = QueryDirRequest {
        form: QueryDirFormV21::InitialMatchAll,
        enumeration_generation: 5,
        enumeration_cookie: 0,
        single,
        output_capacity: capacity,
        output: BufferRef {
            length: capacity,
            ..Default::default()
        },
        pattern: None,
    };

    let mut eng = DirEnumerator::new();
    let mut cookie = 0u64;
    loop {
        let outcome = if cookie == 0 {
            eng.open(1, &base, candidates.clone())
        } else {
            let mut req = base.clone();
            req.form = QueryDirFormV21::Continuation;
            req.enumeration_cookie = cookie;
            eng.continue_(1, &req)
        };
        let batch = match outcome {
            Ok(batch) => batch,
            // These candidates are in-contract (nonzero ids, NORMAL attrs, short
            // even names) and capacity >= 40 + 648, so the ONLY legitimate
            // terminal is NoMoreEntries; any other error would be a real
            // enumeration regression (a valid set failing to fully enumerate).
            Err(EnumError::NoMoreEntries) => break,
            Err(other) => panic!("unexpected enumeration error: {other:?}"),
        };
        assert!(batch.entry_count >= 1, "a produced batch is never empty");
        let result: QueryDirResultV1 = try_decode(&batch.blob).expect("decode result");
        validate_query_dir_result_v1(&result, &batch.blob, cookie).expect("batch re-validates");
        if batch.eof {
            break;
        }
        cookie = batch.next_cookie;
    }
});
