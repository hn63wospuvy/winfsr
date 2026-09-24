//! Decode a granted `QueryVolumeV1` volume-information query request, and
//! build + self-validate the `VolumeSizeInfoV1` result.
//!
//! `QUERY_VOLUME`'s SQ is a `PControl` whose `body` grant holds the 40-byte
//! `QueryVolumeV1` control blob — the same fixed shape as `QUERY_INFO`'s
//! `QueryInfoV1` (`queryinfo.rs`), just a different `info_class` registry
//! (`query_volume_class::SIZE`). Its `output` field is a separate U2K grant,
//! at least 40 bytes, where the daemon writes the returned
//! `VolumeSizeInfoV1`. The frozen ABI owns the wire rules
//! (`validate_query_volume_v1` checks `info_class == SIZE`, `flags`/
//! `reserved` zero, and the minimum output length together with the grant);
//! this module drives it and extracts nothing further — there is no tail to
//! parse. Only the K2U control blob is single-fetched; the U2K output is
//! validated, never fetched here.
//!
//! `build_volume_size_info` frames a `VolumeSizeInfoV1` from a
//! provider-supplied [`VolumeSizeFields`] (the wire fields minus the header
//! and `flags`/`reserved`, which are fixed at the canonical header / zero),
//! self-validates it host-side via the frozen, **grant-free**
//! `validate_volume_size_info_v1` (`available <= total`, `bytes_per_sector` a
//! power of two in `[512, 65536]`, `sectors_per_allocation_unit` a nonzero
//! power of two, and the derived cluster size `<= 16 MiB`), and returns the
//! encoded bytes. Unlike `dataio::build_write_result` /
//! `mutation::build_mutation_result`, there is no grant/echo to bind — the
//! result carries no output `BufferRef` of its own to validate against.

use fsring_abi::codec::try_decode;
use fsring_abi::layout::SqeBody;
use fsring_abi::msgs::{
    BufferRef, ControlHeader, QueryVolumeV1, VolumeSizeInfoV1, CONTROL_VERSION_V1,
};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    validate_query_volume_v1, validate_volume_size_info_v1, GrantBindingV21,
};

use crate::control::pcontrol_body_ref;
use crate::error::{GrantError, QueryVolumeError};
use crate::grant::{encode_pod, resolve_body, GrantTable};
use crate::section::SharedSection;

/// A decoded, ABI-validated `QUERY_VOLUME` request.
///
/// `output` is the U2K grant the daemon writes the returned
/// `VolumeSizeInfoV1` into; it is validated here but never fetched (the
/// provider writes it directly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryVolumeRequest {
    pub output: BufferRef,
}

/// The provider-supplied `VolumeSizeInfoV1` fields: everything but the header
/// and `flags`/`reserved` (always zero), which
/// [`build_volume_size_info`] fixes itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeSizeFields {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// Decode and ABI-validate the granted `QueryVolumeV1` an SQE's `PControl`
/// points at.
pub fn decode_query_volume<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<QueryVolumeRequest, QueryVolumeError> {
    // 1. The outer PControl points at the K2U control blob (QueryVolumeV1, a
    //    fixed 40 bytes with no variable tail).
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let blob = resolve_body(section, &validated_outer)?;
    let request: QueryVolumeV1 =
        try_decode(blob.as_slice()).map_err(|_| QueryVolumeError::Truncated)?;

    // 2. Bind the U2K output grant and run the frozen ABI query validator,
    //    which checks info_class, flags/reserved, and the minimum output
    //    length together with the grant. There is no tail to extract.
    let output_grant = table
        .grant_for(request.output.token)
        .ok_or(QueryVolumeError::Grant(GrantError::UnknownToken))?;
    let output_binding = GrantBindingV21 {
        grant: output_grant,
        expected_session_epoch: table.session_epoch(),
        expected_owner: owner,
    };
    validate_query_volume_v1(&request, output_binding)?;

    Ok(QueryVolumeRequest {
        output: request.output,
    })
}

/// Build the `VolumeSizeInfoV1` result from provider-supplied `fields`,
/// self-validate it host-side via the frozen, grant-free
/// `validate_volume_size_info_v1`, and return the encoded 40 bytes.
pub fn build_volume_size_info(fields: &VolumeSizeFields) -> Result<Vec<u8>, QueryVolumeError> {
    let info = VolumeSizeInfoV1 {
        header: ControlHeader {
            struct_size: core::mem::size_of::<VolumeSizeInfoV1>() as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        total_allocation_units: fields.total_allocation_units,
        available_allocation_units: fields.available_allocation_units,
        sectors_per_allocation_unit: fields.sectors_per_allocation_unit,
        bytes_per_sector: fields.bytes_per_sector,
        flags: 0,
        reserved: 0,
    };

    validate_volume_size_info_v1(&info).map_err(QueryVolumeError::Message)?;

    Ok(encode_pod(&info))
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::testkit::QueryVolumeFixture;

    #[test]
    fn decodes_valid_request() {
        let fx = QueryVolumeFixture::valid();
        let req = decode_query_volume(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        assert_eq!(req.output.length, 40);
    }

    #[test]
    fn rejects_bad_class_and_output_len() {
        for fx in [
            QueryVolumeFixture::with_bad_class(),
            QueryVolumeFixture::with_bad_output_len(39),
        ] {
            assert!(matches!(
                decode_query_volume(&fx.sqe, &fx.table, fx.section(), fx.owner),
                Err(QueryVolumeError::Message(_))
            ));
        }
    }

    /// A valid `VolumeSizeFields` (available <= total, pow2 sector/allocation
    /// sizes, a cluster size well under the 16 MiB cap).
    fn valid_fields() -> VolumeSizeFields {
        VolumeSizeFields {
            total_allocation_units: 1_000_000,
            available_allocation_units: 500_000,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        }
    }

    #[test]
    fn build_volume_size_info_builds_and_self_validates() {
        let bytes = build_volume_size_info(&valid_fields()).expect("builds");
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn build_volume_size_info_rejects_available_over_total() {
        let mut fields = valid_fields();
        fields.available_allocation_units = fields.total_allocation_units + 1;
        assert!(matches!(
            build_volume_size_info(&fields),
            Err(QueryVolumeError::Message(_))
        ));
    }

    #[test]
    fn build_volume_size_info_rejects_non_power_of_two_sectors() {
        let mut fields = valid_fields();
        fields.sectors_per_allocation_unit = 3;
        assert!(matches!(
            build_volume_size_info(&fields),
            Err(QueryVolumeError::Message(_))
        ));
    }
}
