use core::mem::{align_of, offset_of, size_of};

use crate::{
    codec::Pod,
    msgs::{BlobSlice, ControlHeader},
    BootInstanceId, FeatureSet, MountId, OpId, RetireToken,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProviderMountRootV1 {
    pub version: u32,
    pub state: u32,
    pub boot_instance_id: BootInstanceId,
    pub mount_id: MountId,
    pub latest_session_epoch: u64,
    pub selected_features: FeatureSet,
    pub journal_version: u32,
    pub service_sid_length: u32,
    pub service_sid: [u8; 68],
    pub reserved: [u8; 4],
    pub latest_proof_token: RetireToken,
}

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct DurableChildValueV1 {
    pub header: ControlHeader,
    pub value_kind: u16,
    pub state: u16,
    pub flags: u32,
    pub identity_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub payload: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AccountingReservationV1 {
    pub target_child_kind: u16,
    pub flags: u16,
    pub target_key_length: u32,
    pub charged_bytes: u64,
    pub target_key_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrepareTxIndexValueV1 {
    pub op_id: OpId,
    pub identity_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LatestProcessedV1 {
    pub first_ordinal: u64,
    pub through_ordinal: u64,
    pub volume_commit_sequence: u64,
    pub semantic_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RetireReceiptV1 {
    pub retire_token: RetireToken,
    pub state: u32,
    pub reserved: [u8; 12],
}

// SAFETY: repr(C) fields are Pod, all bit patterns are valid, and the
// assertions below prove the layout has no implicit padding.
unsafe impl Pod for ProviderMountRootV1 {}
// SAFETY: repr(C, align(8)) fields are Pod, all bit patterns are valid, and the
// assertions below prove the explicit alignment introduces no hidden bytes.
unsafe impl Pod for DurableChildValueV1 {}
// SAFETY: repr(C) integer/byte-array fields are Pod and the assertions below
// prove every byte belongs to a field.
unsafe impl Pod for AccountingReservationV1 {}
// SAFETY: repr(C) OpId and byte-array fields are Pod and the assertions below
// prove every byte belongs to a field.
unsafe impl Pod for PrepareTxIndexValueV1 {}
// SAFETY: repr(C) integer/byte-array fields are Pod and the assertions below
// prove every byte belongs to a field.
unsafe impl Pod for LatestProcessedV1 {}
// SAFETY: repr(C) RetireToken/integer/byte-array fields are Pod and the
// assertions below prove every byte belongs to a field.
unsafe impl Pod for RetireReceiptV1 {}

const _: () = {
    assert!(size_of::<ProviderMountRootV1>() == 160);
    assert!(align_of::<ProviderMountRootV1>() == 8);
    assert!(offset_of!(ProviderMountRootV1, version) == 0);
    assert!(offset_of!(ProviderMountRootV1, state) == 4);
    assert!(offset_of!(ProviderMountRootV1, boot_instance_id) == 8);
    assert!(offset_of!(ProviderMountRootV1, mount_id) == 24);
    assert!(offset_of!(ProviderMountRootV1, latest_session_epoch) == 40);
    assert!(offset_of!(ProviderMountRootV1, selected_features) == 48);
    assert!(offset_of!(ProviderMountRootV1, journal_version) == 64);
    assert!(offset_of!(ProviderMountRootV1, service_sid_length) == 68);
    assert!(offset_of!(ProviderMountRootV1, service_sid) == 72);
    assert!(offset_of!(ProviderMountRootV1, reserved) == 140);
    assert!(offset_of!(ProviderMountRootV1, latest_proof_token) == 144);
    assert!(offset_of!(ProviderMountRootV1, latest_proof_token) + 16 == 160);

    assert!(size_of::<DurableChildValueV1>() == 88);
    assert!(align_of::<DurableChildValueV1>() == 8);
    assert!(offset_of!(DurableChildValueV1, header) == 0);
    assert!(offset_of!(DurableChildValueV1, value_kind) == 8);
    assert!(offset_of!(DurableChildValueV1, state) == 10);
    assert!(offset_of!(DurableChildValueV1, flags) == 12);
    assert!(offset_of!(DurableChildValueV1, identity_digest) == 16);
    assert!(offset_of!(DurableChildValueV1, payload_digest) == 48);
    assert!(offset_of!(DurableChildValueV1, payload) == 80);
    assert!(offset_of!(DurableChildValueV1, payload) + 8 == 88);

    assert!(size_of::<AccountingReservationV1>() == 48);
    assert!(align_of::<AccountingReservationV1>() == 8);
    assert!(offset_of!(AccountingReservationV1, target_child_kind) == 0);
    assert!(offset_of!(AccountingReservationV1, flags) == 2);
    assert!(offset_of!(AccountingReservationV1, target_key_length) == 4);
    assert!(offset_of!(AccountingReservationV1, charged_bytes) == 8);
    assert!(offset_of!(AccountingReservationV1, target_key_digest) == 16);
    assert!(offset_of!(AccountingReservationV1, target_key_digest) + 32 == 48);

    assert!(size_of::<PrepareTxIndexValueV1>() == 48);
    assert!(align_of::<PrepareTxIndexValueV1>() == 8);
    assert!(offset_of!(PrepareTxIndexValueV1, op_id) == 0);
    assert!(offset_of!(PrepareTxIndexValueV1, identity_digest) == 16);
    assert!(offset_of!(PrepareTxIndexValueV1, identity_digest) + 32 == 48);

    assert!(size_of::<LatestProcessedV1>() == 56);
    assert!(align_of::<LatestProcessedV1>() == 8);
    assert!(offset_of!(LatestProcessedV1, first_ordinal) == 0);
    assert!(offset_of!(LatestProcessedV1, through_ordinal) == 8);
    assert!(offset_of!(LatestProcessedV1, volume_commit_sequence) == 16);
    assert!(offset_of!(LatestProcessedV1, semantic_digest) == 24);
    assert!(offset_of!(LatestProcessedV1, semantic_digest) + 32 == 56);

    assert!(size_of::<RetireReceiptV1>() == 32);
    assert!(align_of::<RetireReceiptV1>() == 8);
    assert!(offset_of!(RetireReceiptV1, retire_token) == 0);
    assert!(offset_of!(RetireReceiptV1, state) == 16);
    assert!(offset_of!(RetireReceiptV1, reserved) == 20);
    assert!(offset_of!(RetireReceiptV1, reserved) + 12 == 32);
};

pub fn durable_payload_digest_v1(payload: &[u8]) -> [u8; 32] {
    crate::digest::sha256_bytes(payload)
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::{
        durable_payload_digest_v1, AccountingReservationV1, DurableChildValueV1, LatestProcessedV1,
        PrepareTxIndexValueV1, ProviderMountRootV1, RetireReceiptV1,
    };
    use crate::{
        codec::Pod,
        durable::{
            durable_committed_result_state, durable_immutable_request_state, durable_journal_state,
            durable_open_state, durable_prepare_state, durable_pt_epoch_intent_state,
            durable_pt_lane_state, durable_query_dir_attempt_state, durable_query_dir_cookie_state,
            durable_query_dir_snapshot_state, provider_mount_root_state, retire_receipt_state,
        },
    };

    fn assert_pod<T: Pod>() {}

    #[test]
    fn fixed_records_are_pod_with_exact_layouts() {
        assert_pod::<ProviderMountRootV1>();
        assert_pod::<DurableChildValueV1>();
        assert_pod::<AccountingReservationV1>();
        assert_pod::<PrepareTxIndexValueV1>();
        assert_pod::<LatestProcessedV1>();
        assert_pod::<RetireReceiptV1>();

        assert_eq!(
            (
                size_of::<ProviderMountRootV1>(),
                align_of::<ProviderMountRootV1>()
            ),
            (160, 8)
        );
        assert_eq!(offset_of!(ProviderMountRootV1, latest_proof_token), 144);
        assert_eq!(
            (
                size_of::<DurableChildValueV1>(),
                align_of::<DurableChildValueV1>()
            ),
            (88, 8)
        );
        assert_eq!(offset_of!(DurableChildValueV1, payload), 80);
        assert_eq!(
            (
                size_of::<AccountingReservationV1>(),
                align_of::<AccountingReservationV1>()
            ),
            (48, 8)
        );
        assert_eq!(
            (
                size_of::<PrepareTxIndexValueV1>(),
                align_of::<PrepareTxIndexValueV1>()
            ),
            (48, 8)
        );
        assert_eq!(
            (
                size_of::<LatestProcessedV1>(),
                align_of::<LatestProcessedV1>()
            ),
            (56, 8)
        );
        assert_eq!(
            (size_of::<RetireReceiptV1>(), align_of::<RetireReceiptV1>()),
            (32, 8)
        );
    }

    #[test]
    fn state_registries_and_payload_digest_are_closed() {
        assert_eq!(
            [
                provider_mount_root_state::ACTIVE as u16,
                provider_mount_root_state::RECOVERING as u16,
                provider_mount_root_state::RETIRING as u16,
                durable_open_state::LIVE,
                durable_open_state::CLEANED,
                durable_prepare_state::PREPARED,
                durable_immutable_request_state::RETAINED,
                durable_committed_result_state::COMMITTED,
                durable_journal_state::PREPARED,
                durable_journal_state::COMMITTED,
                durable_query_dir_snapshot_state::ACTIVE,
                durable_query_dir_attempt_state::ACCEPTED,
                durable_query_dir_cookie_state::ACTIVE,
                durable_pt_epoch_intent_state::PENDING,
                durable_pt_epoch_intent_state::ACCEPTED,
                durable_pt_epoch_intent_state::REVOKED,
                durable_pt_lane_state::PRESENT,
                retire_receipt_state::RECEIPT_PENDING_ACK as u16,
            ],
            [1, 2, 3, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 3, 1, 1],
        );
        assert_eq!(
            durable_payload_digest_v1(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }
}
