//! Decode a granted `QueryDirV2` directory-enumeration request.
//!
//! `QUERY_DIR`'s SQ is a `PControl` whose `body` grant holds the control blob:
//! a `QueryDirV2` (64 bytes) followed, for an expression request, by the
//! align8-padded UTF-16LE pattern. The `output` field is a separate U2K grant
//! where the daemon writes entries. The frozen ABI owns the wire rules
//! (`validate_query_dir_v2` classifies the form and validates the pattern layout
//! together with the output grant); this module drives it and extracts the
//! pattern bytes for the enumerator to compile via the slice-3 name matcher.
//! Only the K2U control blob is single-fetched; the U2K output is validated,
//! never fetched here.

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::layout::{op, SqeBody};
use fsring_abi::msgs::{query_dir_flags, BufferRef, OControl, QueryDirV2};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    validate_completion_output_v21, validate_query_dir_v2, CompletionOutputContextV21,
    GrantBindingV21, QueryDirFormV21,
};

use crate::control::pcontrol_body_ref;
use crate::error::{GrantError, QueryDirError};
use crate::grant::{resolve_body, GrantTable};
use crate::provider::{Completion, OutBuf};
use crate::section::SharedSection;

/// A decoded, ABI-validated `QUERY_DIR` request.
///
/// `pattern` is `Some` only for `InitialExpression` — the align8-stripped UTF-16
/// pattern the enumerator compiles into a `NameMatcher` (`MatchAll`/`Continuation`
/// carry no pattern). `single` and `output_capacity` are read from the request.
/// `output` is the U2K grant the daemon writes enumerated entries into; it is
/// validated here but never fetched (the enumerator writes it directly), and is
/// what [`build_query_dir_completion`] echoes back shrunk to the written length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryDirRequest {
    pub form: QueryDirFormV21,
    pub enumeration_generation: u64,
    pub enumeration_cookie: u64,
    pub single: bool,
    pub output_capacity: u32,
    pub output: BufferRef,
    pub pattern: Option<Box<[u16]>>,
}

/// Decode and ABI-validate the granted `QueryDirV2` an SQE's `PControl` points at.
pub fn decode_query_dir<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<QueryDirRequest, QueryDirError> {
    // 1. The outer PControl points at the K2U control blob (QueryDirV2 + pattern).
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let blob = resolve_body(section, &validated_outer)?;
    let request: QueryDirV2 = try_decode(blob.as_slice()).map_err(|_| QueryDirError::Truncated)?;

    // 2. Bind the U2K output grant and run the frozen ABI query validator, which
    //    classifies the form and validates the pattern layout + output grant.
    let output_grant = table
        .grant_for(request.output.token)
        .ok_or(QueryDirError::Grant(GrantError::UnknownToken))?;
    let output_binding = GrantBindingV21 {
        grant: output_grant,
        expected_session_epoch: table.session_epoch(),
        expected_owner: owner,
    };
    let validated = validate_query_dir_v2(&request, blob.as_slice(), output_binding)?;

    // 3. For an expression, extract the align8-stripped UTF-16 pattern bytes
    //    (bounds already proven by the validator) for the enumerator to compile.
    let pattern = match validated.form() {
        QueryDirFormV21::InitialExpression { .. } => {
            let start = request.pattern.offset as usize;
            let end = start + request.pattern.length as usize;
            Some(utf16le_to_units(&blob.as_slice()[start..end]))
        }
        QueryDirFormV21::InitialMatchAll | QueryDirFormV21::Continuation => None,
    };

    Ok(QueryDirRequest {
        form: validated.form(),
        enumeration_generation: request.enumeration_generation,
        enumeration_cookie: request.enumeration_cookie,
        single: request.flags & query_dir_flags::SINGLE != 0,
        output_capacity: request.output.length,
        output: request.output,
        pattern,
    })
}

/// Build the `QUERY_DIR` success completion for an enumeration batch of
/// `blob_len` canonical bytes, and self-validate it against the frozen ABI
/// output matrix (`validate_completion_output_v21`) before handing it to
/// [`crate::provider::resolve_completion`].
///
/// The 24-byte output is an `OControl` echo of the request's `output` grant,
/// shrunk to `blob_len` — the enumerator already wrote the batch directly into
/// that U2K grant; this only reports how much of it is valid. Mirrors
/// [`crate::querysecurity::build_query_security_completion`] exactly, save for
/// the opcode and the `CanonicalBlobLength` context QUERY_DIR's matrix row
/// requires.
pub fn build_query_dir_completion(
    request: &QueryDirRequest,
    blob_len: u32,
) -> Result<Completion, QueryDirError> {
    let echo = OControl {
        body: BufferRef {
            token: request.output.token,
            offset: 0,
            length: blob_len,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        },
    };
    let mut out_bytes = vec![0u8; core::mem::size_of::<OControl>()];
    try_encode(&echo, &mut out_bytes).expect("OControl is its own size");
    let out = OutBuf::new(&out_bytes).expect("size_of::<OControl>() <= CQE_OUT_LEN");
    let context = CompletionOutputContextV21::CanonicalBlobLength(blob_len as u64);

    // Self-validate the exact matrix check `resolve_completion` wraps; it
    // rejects a zero `blob_len` before this ever reaches the ring. `out_len`
    // shares the same `size_of::<OControl>()` source of truth as the `OutBuf`
    // allocation above, rather than a separately-maintained literal.
    validate_completion_output_v21(
        op::QUERY_DIR,
        0,
        core::mem::size_of::<OControl>() as u32,
        blob_len as u64,
        context,
    )
    .map_err(QueryDirError::Completion)?;

    Ok(Completion::complete_with(0, blob_len as u64, out, context))
}

/// Decode a UTF-16LE byte run into `u16` code units (the pattern length is even,
/// enforced by `validate_dir_pattern_utf16`).
fn utf16le_to_units(bytes: &[u8]) -> Box<[u16]> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::provider::resolve_completion;
    use crate::testkit::QueryDirFixture;

    #[test]
    fn decodes_match_all() {
        let fx = QueryDirFixture::match_all();
        let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decodes");
        assert_eq!(req.form, QueryDirFormV21::InitialMatchAll);
        assert!(req.pattern.is_none());
        assert!(req.output_capacity >= 40);
        assert_eq!(req.enumeration_generation, fx.enumeration_generation);
    }

    #[test]
    fn retains_the_output_grant_ref() {
        // The fixture's output U2K grant is exactly 4096 bytes (`QUERY_OUTPUT_LEN`
        // in testkit.rs); `output` must be the same ref `output_capacity` was
        // read from, not dropped.
        let fx = QueryDirFixture::match_all();
        let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decodes");
        assert_eq!(req.output.length, 4096);
        assert_eq!(req.output.length, req.output_capacity);
        let output_grant = fx
            .table
            .grant_for(req.output.token)
            .expect("output grant")
            .issued;
        assert_eq!(req.output, output_grant);
    }

    #[test]
    fn builds_and_self_validates_a_completion() {
        let fx = QueryDirFixture::match_all();
        let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decodes");
        let completion = build_query_dir_completion(&req, 128).expect("builds");
        // End-to-end: the built completion is wire-legal for a QUERY_DIR CQE.
        let cqe = resolve_completion(&fx.sqe, completion)
            .expect("legal")
            .expect("a completion");
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 128);
    }

    #[test]
    fn rejects_out_of_range_blob_len() {
        let fx = QueryDirFixture::match_all();
        let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decodes");
        assert!(build_query_dir_completion(&req, 0).is_err());
    }

    #[test]
    fn decodes_continuation() {
        let fx = QueryDirFixture::continuation(7);
        let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decodes");
        assert_eq!(req.form, QueryDirFormV21::Continuation);
        assert_eq!(req.enumeration_cookie, 7);
        assert!(req.pattern.is_none());
    }

    #[test]
    fn decodes_expression() {
        // "*.txt" is a wildcard pattern -> exact_pattern is false. FFI-free: decode
        // only extracts the pattern bytes; the matcher is compiled in the engine.
        let pattern: Vec<u16> = "*.txt".encode_utf16().collect();
        let fx = QueryDirFixture::expression(&pattern, false);
        let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decodes");
        assert_eq!(
            req.form,
            QueryDirFormV21::InitialExpression {
                exact_pattern: false
            }
        );
        assert_eq!(req.pattern.as_deref(), Some(pattern.as_slice()));
    }

    #[test]
    fn rejects_zero_generation() {
        let fx = QueryDirFixture::with_zero_generation();
        assert!(matches!(
            decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(QueryDirError::Query(_))
        ));
    }

    #[test]
    fn rejects_bad_output_len() {
        let fx = QueryDirFixture::with_bad_output_len(39);
        assert!(matches!(
            decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(QueryDirError::Query(_))
        ));
    }

    #[test]
    fn rejects_exact_flag_mismatch() {
        let fx = QueryDirFixture::with_exact_flag_mismatch();
        assert!(matches!(
            decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(QueryDirError::Query(_))
        ));
    }

    #[test]
    fn rejects_restart_with_a_nonzero_cookie() {
        // RESTART requires cookie zero (the cookie/RESTART relationship rule).
        let fx = QueryDirFixture::with_restart_and_cookie();
        assert!(matches!(
            decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(QueryDirError::Query(_))
        ));
    }
}
