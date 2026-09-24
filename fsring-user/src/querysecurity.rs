//! Decode a granted `QuerySecurityV1` security-descriptor query request.
//!
//! `QUERY_SECURITY`'s SQ is a `PControl` whose `body` grant holds the 40-byte
//! `QuerySecurityV1` control blob — a fixed-size struct with no variable tail,
//! unlike `QUERY_DIR`'s `QueryDirV2` + pattern. Its `output` field is a
//! separate U2K grant, always exactly 65536 bytes, where the daemon writes the
//! returned security descriptor. The frozen ABI owns the wire rules
//! (`validate_query_security_v1` checks `security_information` against the
//! accepted read mask, `flags == 0`, and the exact output length together with
//! the grant); this module drives it and extracts nothing further — there is
//! no tail to parse. Only the K2U control blob is single-fetched; the U2K
//! output is validated, never fetched here.

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::layout::{op, SqeBody};
use fsring_abi::msgs::{BufferRef, OControl, QuerySecurityV1};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    validate_completion_output_v21, validate_query_security_v1, CompletionOutputContextV21,
    GrantBindingV21,
};

use crate::control::pcontrol_body_ref;
use crate::error::{GrantError, QuerySecurityError};
use crate::grant::{resolve_body, GrantTable};
use crate::provider::{Completion, OutBuf};
use crate::section::SharedSection;

/// A decoded, ABI-validated `QUERY_SECURITY` request.
///
/// `output` is the U2K grant the daemon writes the returned security
/// descriptor into; it is validated here but never fetched (the provider
/// writes it directly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuerySecurityRequest {
    pub security_information: u32,
    pub output: BufferRef,
}

/// Decode and ABI-validate the granted `QuerySecurityV1` an SQE's `PControl`
/// points at.
pub fn decode_query_security<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<QuerySecurityRequest, QuerySecurityError> {
    // 1. The outer PControl points at the K2U control blob (QuerySecurityV1,
    //    a fixed 40 bytes with no variable tail).
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let blob = resolve_body(section, &validated_outer)?;
    let request: QuerySecurityV1 =
        try_decode(blob.as_slice()).map_err(|_| QuerySecurityError::Truncated)?;

    // 2. Bind the U2K output grant and run the frozen ABI query validator,
    //    which checks the security_information mask, flags, and the exact
    //    output length together with the grant. There is no tail to extract.
    let output_grant = table
        .grant_for(request.output.token)
        .ok_or(QuerySecurityError::Grant(GrantError::UnknownToken))?;
    let output_binding = GrantBindingV21 {
        grant: output_grant,
        expected_session_epoch: table.session_epoch(),
        expected_owner: owner,
    };
    validate_query_security_v1(&request, output_binding)?;

    Ok(QuerySecurityRequest {
        security_information: request.security_information,
        output: request.output,
    })
}

/// Build the `QUERY_SECURITY` success completion for a returned security
/// descriptor of `descriptor_len` bytes, and self-validate it against the
/// frozen ABI's `(opcode, status, out_len, information, context)` matrix
/// before handing it to [`crate::provider::resolve_completion`].
///
/// The 24-byte output is an `OControl` echo of the request's `output` grant,
/// shrunk to `descriptor_len` — the daemon already wrote the descriptor
/// directly into that U2K grant; this only reports how much of it is valid.
pub fn build_query_security_completion(
    request: &QuerySecurityRequest,
    descriptor_len: u32,
) -> Result<Completion, QuerySecurityError> {
    let echo = OControl {
        body: BufferRef {
            token: request.output.token,
            offset: 0,
            length: descriptor_len,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        },
    };
    let mut out_bytes = vec![0u8; core::mem::size_of::<OControl>()];
    try_encode(&echo, &mut out_bytes).expect("OControl is exactly its own size");
    let out = OutBuf::new(&out_bytes).expect("size_of::<OControl>() (24) <= CQE_OUT_LEN");
    let context = CompletionOutputContextV21::DescriptorLength(descriptor_len);

    // Self-validate the exact matrix check `resolve_completion` wraps; it
    // rejects a `descriptor_len` outside `[20, 65536]` before this ever
    // reaches the ring. `out_len` shares the same `size_of::<OControl>()`
    // source of truth as the `OutBuf` allocation above, rather than a
    // separately-maintained literal.
    validate_completion_output_v21(
        op::QUERY_SECURITY,
        0,
        core::mem::size_of::<OControl>() as u32,
        descriptor_len as u64,
        context,
    )
    .map_err(QuerySecurityError::Message)?;

    Ok(Completion::complete_with(
        0,
        descriptor_len as u64,
        out,
        context,
    ))
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::provider::resolve_completion;
    use crate::testkit::QuerySecurityFixture;

    #[test]
    fn decodes_valid_request() {
        let fx = QuerySecurityFixture::valid();
        let req =
            decode_query_security(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        assert_eq!(req.security_information, 0x7);
        assert_eq!(req.output.length, 65_536);
    }

    #[test]
    fn rejects_mask_flags_and_output_len() {
        for fx in [
            QuerySecurityFixture::with_bad_mask(),
            QuerySecurityFixture::with_nonzero_flags(),
            QuerySecurityFixture::with_bad_output_len(65_535),
        ] {
            assert!(matches!(
                decode_query_security(&fx.sqe, &fx.table, fx.section(), fx.owner),
                Err(QuerySecurityError::Message(_))
            ));
        }
    }

    #[test]
    fn builds_and_self_validates_a_completion() {
        let fx = QuerySecurityFixture::valid();
        let req = decode_query_security(&fx.sqe, &fx.table, fx.section(), fx.owner).unwrap();
        let completion = build_query_security_completion(&req, 64).expect("builds");
        // End-to-end: the built completion is wire-legal for a QUERY_SECURITY CQE.
        let cqe = resolve_completion(&fx.sqe, completion)
            .expect("legal")
            .expect("a completion");
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 64);
    }

    #[test]
    fn rejects_out_of_range_descriptor_len() {
        let fx = QuerySecurityFixture::valid();
        let req = decode_query_security(&fx.sqe, &fx.table, fx.section(), fx.owner).unwrap();
        assert!(build_query_security_completion(&req, 19).is_err()); // below MIN 20
        assert!(build_query_security_completion(&req, 65_537).is_err()); // above MAX 65536
    }
}
