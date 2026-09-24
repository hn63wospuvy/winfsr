//! Decode a granted `QueryInfoV1` file-information query request, and build +
//! self-validate the `FileInfoV1` result.
//!
//! `QUERY_INFO`'s SQ is a `PControl` whose `body` grant holds the 40-byte
//! `QueryInfoV1` control blob — a fixed-size struct with no variable tail,
//! shaped exactly like `QUERY_SECURITY`'s `QuerySecurityV1` (`querysecurity.rs`).
//! Its `output` field is a separate U2K grant, at least 104 bytes, where the
//! daemon writes the returned `FileInfoV1`. The frozen ABI owns the wire rules
//! (`validate_query_info_v1` checks `info_class == CANONICAL`, `flags`/
//! `reserved` zero, and the minimum output length together with the grant);
//! this module drives it and extracts nothing further — there is no tail to
//! parse. Only the K2U control blob is single-fetched; the U2K output is
//! validated, never fetched here.
//!
//! `build_file_info` frames a `FileInfoV1` from a provider-supplied
//! [`FileInfoFields`] (the wire fields minus the header, `reparse_tag`, and
//! `flags`, which are fixed at the canonical header / zero), self-validates it
//! host-side via the frozen, **grant-free** `validate_file_info_v1` (flags
//! zero, both generations nonzero, attributes within the accepted mask with
//! `NORMAL` alone, `reparse_tag` zero, all four timestamps non-negative, a
//! legal `SizeState`), and returns the encoded bytes. Unlike
//! `dataio::build_write_result` / `mutation::build_mutation_result`, there is
//! no grant/echo to bind — the result carries no output `BufferRef` of its own
//! to validate against.

use fsring_abi::codec::try_decode;
use fsring_abi::layout::SqeBody;
use fsring_abi::msgs::{
    BufferRef, ControlHeader, FileInfoV1, QueryInfoV1, SizeState, CONTROL_VERSION_V1,
};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{validate_file_info_v1, validate_query_info_v1, GrantBindingV21};

use crate::control::pcontrol_body_ref;
use crate::error::{GrantError, QueryInfoError};
use crate::grant::{encode_pod, resolve_body, GrantTable};
use crate::section::SharedSection;

/// A decoded, ABI-validated `QUERY_INFO` request.
///
/// `output` is the U2K grant the daemon writes the returned `FileInfoV1`
/// into; it is validated here but never fetched (the provider writes it
/// directly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryInfoRequest {
    pub output: BufferRef,
}

/// The provider-supplied `FileInfoV1` fields: everything but the header,
/// `reparse_tag` (ABI 2.1 registers no reparse tag), and `flags` (always
/// zero), which [`build_file_info`] fixes itself.
#[derive(Clone, Copy)]
pub struct FileInfoFields {
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub attributes: u32,
    pub link_count: u32,
}

/// Decode and ABI-validate the granted `QueryInfoV1` an SQE's `PControl`
/// points at.
pub fn decode_query_info<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<QueryInfoRequest, QueryInfoError> {
    // 1. The outer PControl points at the K2U control blob (QueryInfoV1, a
    //    fixed 40 bytes with no variable tail).
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let blob = resolve_body(section, &validated_outer)?;
    let request: QueryInfoV1 =
        try_decode(blob.as_slice()).map_err(|_| QueryInfoError::Truncated)?;

    // 2. Bind the U2K output grant and run the frozen ABI query validator,
    //    which checks info_class, flags/reserved, and the minimum output
    //    length together with the grant. There is no tail to extract.
    let output_grant = table
        .grant_for(request.output.token)
        .ok_or(QueryInfoError::Grant(GrantError::UnknownToken))?;
    let output_binding = GrantBindingV21 {
        grant: output_grant,
        expected_session_epoch: table.session_epoch(),
        expected_owner: owner,
    };
    validate_query_info_v1(&request, output_binding)?;

    Ok(QueryInfoRequest {
        output: request.output,
    })
}

/// Build the `FileInfoV1` result from provider-supplied `fields`, self-validate
/// it host-side via the frozen, grant-free `validate_file_info_v1`, and return
/// the encoded 104 bytes.
pub fn build_file_info(fields: &FileInfoFields) -> Result<Vec<u8>, QueryInfoError> {
    let info = FileInfoV1 {
        header: ControlHeader {
            struct_size: core::mem::size_of::<FileInfoV1>() as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        creation_time: fields.creation_time,
        last_access_time: fields.last_access_time,
        last_write_time: fields.last_write_time,
        change_time: fields.change_time,
        sizes: fields.sizes,
        namespace_generation: fields.namespace_generation,
        security_generation: fields.security_generation,
        attributes: fields.attributes,
        link_count: fields.link_count,
        reparse_tag: 0,
        flags: 0,
    };

    validate_file_info_v1(&info).map_err(QueryInfoError::Message)?;

    Ok(encode_pod(&info))
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::testkit::QueryInfoFixture;
    use fsring_abi::msgs::file_attributes;

    #[test]
    fn decodes_valid_request() {
        let fx = QueryInfoFixture::valid();
        let req = decode_query_info(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        assert_eq!(req.output.length, 104);
    }

    #[test]
    fn rejects_bad_class_and_output_len() {
        for fx in [
            QueryInfoFixture::with_bad_class(),
            QueryInfoFixture::with_bad_output_len(103),
        ] {
            assert!(matches!(
                decode_query_info(&fx.sqe, &fx.table, fx.section(), fx.owner),
                Err(QueryInfoError::Message(_))
            ));
        }
    }

    /// A valid `FileInfoFields` (nonzero generations, `ARCHIVE`-only
    /// attributes, a legal `SizeState`).
    fn valid_fields() -> FileInfoFields {
        FileInfoFields {
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            sizes: SizeState {
                allocation_size: 8192,
                file_size: 4096,
                valid_data_length: 4096,
                size_epoch: 2,
            },
            namespace_generation: 1,
            security_generation: 1,
            attributes: file_attributes::ARCHIVE,
            link_count: 1,
        }
    }

    #[test]
    fn build_file_info_builds_and_self_validates() {
        let bytes = build_file_info(&valid_fields()).expect("builds");
        assert_eq!(bytes.len(), 104);
    }

    #[test]
    fn build_file_info_rejects_zero_generation() {
        let mut fields = valid_fields();
        fields.namespace_generation = 0;
        assert!(matches!(
            build_file_info(&fields),
            Err(QueryInfoError::Message(_))
        ));

        let mut fields = valid_fields();
        fields.security_generation = 0;
        assert!(matches!(
            build_file_info(&fields),
            Err(QueryInfoError::Message(_))
        ));
    }

    #[test]
    fn build_file_info_rejects_bad_attributes() {
        // NORMAL set alongside another bit is illegal: NORMAL must be alone.
        let mut fields = valid_fields();
        fields.attributes = file_attributes::NORMAL | file_attributes::ARCHIVE;
        assert!(matches!(
            build_file_info(&fields),
            Err(QueryInfoError::Message(_))
        ));
    }
}
