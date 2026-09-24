use core::mem::{align_of, offset_of, size_of};

use crate::{
    codec::Pod,
    ids::{AckToken, FileId, LinkId, OpId, TransactionId},
    msgs::{BlobSlice, ControlHeader, SizeState},
};

/// cbindgen:ignore
pub const OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES: u32 = 152;
/// cbindgen:ignore
pub const PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES: u32 = 184;
/// cbindgen:ignore
pub const JOURNAL_STATE_V1_BYTES: u32 = 64;
/// cbindgen:ignore
pub const QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES: u32 = 56;
/// cbindgen:ignore
pub const QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES: u32 = 56;
/// cbindgen:ignore
pub const PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES: u32 = 32;
/// cbindgen:ignore
pub const PT_LANE_PAYLOAD_V1_PREFIX_BYTES: u32 = 72;
/// cbindgen:ignore
pub const IMMUTABLE_REQUEST_DIGEST_BYTES: u32 = 32;
/// cbindgen:ignore
pub const COMMITTED_RESULT_V1_PREFIX_BYTES: u32 = 40;
/// cbindgen:ignore
pub const COMMITTED_OPEN_RESULT_V1_BYTES: u32 = 96;
/// cbindgen:ignore
pub const COMMITTED_WRITE_RESULT_V1_BYTES: u32 = 40;
/// cbindgen:ignore
pub const COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES: u32 = 72;
/// cbindgen:ignore
pub const MAX_COMMITTED_RESULT_BYTES: u32 = 224;

/// Closed section 12 committed-result kinds. EMPTY is reserved and never
/// emitted in base 2.1.
/// cbindgen:ignore
pub mod committed_result_kind {
    pub const INVALID: u16 = 0;
    pub const EMPTY: u16 = 1;
    pub const COMMIT_OPEN: u16 = 2;
    pub const WRITE: u16 = 3;
    pub const MUTATION: u16 = 4;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenRecoveryPayloadV1 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub parent_id: FileId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub kernel_open_id: u64,
    pub desired_access: u32,
    pub granted_access: u32,
    pub share_access: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub disposition: u32,
    pub name: BlobSlice,
    pub security_descriptor: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrepareRecoveryPayloadV1 {
    pub header: ControlHeader,
    pub parent_id: FileId,
    pub transaction_id: TransactionId,
    pub result_file_id: FileId,
    pub result_link_id: LinkId,
    pub result_sizes: SizeState,
    pub result_namespace_generation: u64,
    pub result_security_generation: u64,
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub open_flags: u32,
    pub result_object_flags: u32,
    pub reserved: u32,
    pub name: BlobSlice,
    pub requested_security_descriptor: BlobSlice,
    pub ea: BlobSlice,
    pub result_security_descriptor: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalStateV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub opcode: u16,
    pub mutation_kind: u16,
    pub state: u32,
    pub operation_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryDirSnapshotPayloadV1 {
    pub header: ControlHeader,
    pub pattern_digest: [u8; 32],
    pub entry_count: u64,
    pub entries: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryDirCookiePayloadV1 {
    pub header: ControlHeader,
    pub next_cookie: u64,
    pub result_flags: u32,
    pub reserved: u32,
    pub attempt_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtEpochIntentPayloadV1 {
    pub header: ControlHeader,
    pub pt_epoch: u64,
    pub sector_size: u32,
    pub flags: u32,
    pub backing_path: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtLanePayloadV1 {
    pub header: ControlHeader,
    pub high_watermark: u64,
    pub latest_token: AckToken,
    pub latest_file_id: FileId,
    pub latest_pt_epoch: u64,
    pub latest_notify_code: u16,
    pub flags: u16,
    pub reserved: u32,
    pub pending_envelope: BlobSlice,
}

/// Durable committed-result outer prefix; the payload slice begins at byte
/// 40 and contains exactly the matching inner result blob.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommittedResultV1 {
    pub header: ControlHeader,
    pub opcode: u16,
    pub result_kind: u16,
    pub status: i32,
    pub information: u64,
    pub payload: BlobSlice,
    pub volume_commit_sequence: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommittedOpenResultV1 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub create_result: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommittedWriteResultV1 {
    pub header: ControlHeader,
    pub sizes: SizeState,
}

/// Durable committed-mutation prefix; `kind_payload` is `{0,0}` except for
/// RENAME/LINK/UNLINK, whose exact result record follows inline.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommittedMutationResultV1 {
    pub header: ControlHeader,
    pub mutation_kind: u16,
    pub flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub kind_payload: BlobSlice,
}

// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for OpenRecoveryPayloadV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for PrepareRecoveryPayloadV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for JournalStateV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for QueryDirSnapshotPayloadV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for QueryDirCookiePayloadV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for PtEpochIntentPayloadV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for PtLanePayloadV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for CommittedResultV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for CommittedOpenResultV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for CommittedWriteResultV1 {}
// SAFETY: repr(C) Pod fields accept every bit pattern, and the assertions
// below prove every byte belongs to an explicit field.
unsafe impl Pod for CommittedMutationResultV1 {}

const _: () = {
    assert!(size_of::<OpenRecoveryPayloadV1>() == 152);
    assert!(align_of::<OpenRecoveryPayloadV1>() == 8);
    assert!(offset_of!(OpenRecoveryPayloadV1, header) == 0);
    assert!(offset_of!(OpenRecoveryPayloadV1, file_id) == 8);
    assert!(offset_of!(OpenRecoveryPayloadV1, link_id) == 24);
    assert!(offset_of!(OpenRecoveryPayloadV1, parent_id) == 40);
    assert!(offset_of!(OpenRecoveryPayloadV1, sizes) == 56);
    assert!(offset_of!(OpenRecoveryPayloadV1, namespace_generation) == 88);
    assert!(offset_of!(OpenRecoveryPayloadV1, security_generation) == 96);
    assert!(offset_of!(OpenRecoveryPayloadV1, kernel_open_id) == 104);
    assert!(offset_of!(OpenRecoveryPayloadV1, desired_access) == 112);
    assert!(offset_of!(OpenRecoveryPayloadV1, granted_access) == 116);
    assert!(offset_of!(OpenRecoveryPayloadV1, share_access) == 120);
    assert!(offset_of!(OpenRecoveryPayloadV1, create_options) == 124);
    assert!(offset_of!(OpenRecoveryPayloadV1, file_attributes) == 128);
    assert!(offset_of!(OpenRecoveryPayloadV1, disposition) == 132);
    assert!(offset_of!(OpenRecoveryPayloadV1, name) == 136);
    assert!(offset_of!(OpenRecoveryPayloadV1, security_descriptor) == 144);
    assert!(offset_of!(OpenRecoveryPayloadV1, security_descriptor) + 8 == 152);

    assert!(size_of::<PrepareRecoveryPayloadV1>() == 184);
    assert!(align_of::<PrepareRecoveryPayloadV1>() == 8);
    assert!(offset_of!(PrepareRecoveryPayloadV1, header) == 0);
    assert!(offset_of!(PrepareRecoveryPayloadV1, parent_id) == 8);
    assert!(offset_of!(PrepareRecoveryPayloadV1, transaction_id) == 24);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_file_id) == 40);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_link_id) == 56);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_sizes) == 72);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_namespace_generation) == 104);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_security_generation) == 112);
    assert!(offset_of!(PrepareRecoveryPayloadV1, desired_access) == 120);
    assert!(offset_of!(PrepareRecoveryPayloadV1, share_access) == 124);
    assert!(offset_of!(PrepareRecoveryPayloadV1, disposition) == 128);
    assert!(offset_of!(PrepareRecoveryPayloadV1, create_options) == 132);
    assert!(offset_of!(PrepareRecoveryPayloadV1, file_attributes) == 136);
    assert!(offset_of!(PrepareRecoveryPayloadV1, open_flags) == 140);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_object_flags) == 144);
    assert!(offset_of!(PrepareRecoveryPayloadV1, reserved) == 148);
    assert!(offset_of!(PrepareRecoveryPayloadV1, name) == 152);
    assert!(offset_of!(PrepareRecoveryPayloadV1, requested_security_descriptor) == 160);
    assert!(offset_of!(PrepareRecoveryPayloadV1, ea) == 168);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_security_descriptor) == 176);
    assert!(offset_of!(PrepareRecoveryPayloadV1, result_security_descriptor) + 8 == 184);

    assert!(size_of::<JournalStateV1>() == 64);
    assert!(align_of::<JournalStateV1>() == 8);
    assert!(offset_of!(JournalStateV1, header) == 0);
    assert!(offset_of!(JournalStateV1, op_id) == 8);
    assert!(offset_of!(JournalStateV1, opcode) == 24);
    assert!(offset_of!(JournalStateV1, mutation_kind) == 26);
    assert!(offset_of!(JournalStateV1, state) == 28);
    assert!(offset_of!(JournalStateV1, operation_digest) == 32);
    assert!(offset_of!(JournalStateV1, operation_digest) + 32 == 64);

    assert!(size_of::<QueryDirSnapshotPayloadV1>() == 56);
    assert!(align_of::<QueryDirSnapshotPayloadV1>() == 8);
    assert!(offset_of!(QueryDirSnapshotPayloadV1, header) == 0);
    assert!(offset_of!(QueryDirSnapshotPayloadV1, pattern_digest) == 8);
    assert!(offset_of!(QueryDirSnapshotPayloadV1, entry_count) == 40);
    assert!(offset_of!(QueryDirSnapshotPayloadV1, entries) == 48);
    assert!(offset_of!(QueryDirSnapshotPayloadV1, entries) + 8 == 56);

    assert!(size_of::<QueryDirCookiePayloadV1>() == 56);
    assert!(align_of::<QueryDirCookiePayloadV1>() == 8);
    assert!(offset_of!(QueryDirCookiePayloadV1, header) == 0);
    assert!(offset_of!(QueryDirCookiePayloadV1, next_cookie) == 8);
    assert!(offset_of!(QueryDirCookiePayloadV1, result_flags) == 16);
    assert!(offset_of!(QueryDirCookiePayloadV1, reserved) == 20);
    assert!(offset_of!(QueryDirCookiePayloadV1, attempt_digest) == 24);
    assert!(offset_of!(QueryDirCookiePayloadV1, attempt_digest) + 32 == 56);

    assert!(size_of::<PtEpochIntentPayloadV1>() == 32);
    assert!(align_of::<PtEpochIntentPayloadV1>() == 8);
    assert!(offset_of!(PtEpochIntentPayloadV1, header) == 0);
    assert!(offset_of!(PtEpochIntentPayloadV1, pt_epoch) == 8);
    assert!(offset_of!(PtEpochIntentPayloadV1, sector_size) == 16);
    assert!(offset_of!(PtEpochIntentPayloadV1, flags) == 20);
    assert!(offset_of!(PtEpochIntentPayloadV1, backing_path) == 24);
    assert!(offset_of!(PtEpochIntentPayloadV1, backing_path) + 8 == 32);

    assert!(size_of::<PtLanePayloadV1>() == 72);
    assert!(align_of::<PtLanePayloadV1>() == 8);
    assert!(offset_of!(PtLanePayloadV1, header) == 0);
    assert!(offset_of!(PtLanePayloadV1, high_watermark) == 8);
    assert!(offset_of!(PtLanePayloadV1, latest_token) == 16);
    assert!(offset_of!(PtLanePayloadV1, latest_file_id) == 32);
    assert!(offset_of!(PtLanePayloadV1, latest_pt_epoch) == 48);
    assert!(offset_of!(PtLanePayloadV1, latest_notify_code) == 56);
    assert!(offset_of!(PtLanePayloadV1, flags) == 58);
    assert!(offset_of!(PtLanePayloadV1, reserved) == 60);
    assert!(offset_of!(PtLanePayloadV1, pending_envelope) == 64);
    assert!(offset_of!(PtLanePayloadV1, pending_envelope) + 8 == 72);

    assert!(size_of::<CommittedResultV1>() == 40);
    assert!(align_of::<CommittedResultV1>() == 8);
    assert!(offset_of!(CommittedResultV1, header) == 0);
    assert!(offset_of!(CommittedResultV1, opcode) == 8);
    assert!(offset_of!(CommittedResultV1, result_kind) == 10);
    assert!(offset_of!(CommittedResultV1, status) == 12);
    assert!(offset_of!(CommittedResultV1, information) == 16);
    assert!(offset_of!(CommittedResultV1, payload) == 24);
    assert!(offset_of!(CommittedResultV1, volume_commit_sequence) == 32);
    assert!(offset_of!(CommittedResultV1, volume_commit_sequence) + 8 == 40);

    assert!(size_of::<CommittedOpenResultV1>() == 96);
    assert!(align_of::<CommittedOpenResultV1>() == 8);
    assert!(offset_of!(CommittedOpenResultV1, header) == 0);
    assert!(offset_of!(CommittedOpenResultV1, file_id) == 8);
    assert!(offset_of!(CommittedOpenResultV1, link_id) == 24);
    assert!(offset_of!(CommittedOpenResultV1, sizes) == 40);
    assert!(offset_of!(CommittedOpenResultV1, namespace_generation) == 72);
    assert!(offset_of!(CommittedOpenResultV1, security_generation) == 80);
    assert!(offset_of!(CommittedOpenResultV1, create_result) == 88);
    assert!(offset_of!(CommittedOpenResultV1, flags) == 92);
    assert!(offset_of!(CommittedOpenResultV1, flags) + 4 == 96);

    assert!(size_of::<CommittedWriteResultV1>() == 40);
    assert!(align_of::<CommittedWriteResultV1>() == 8);
    assert!(offset_of!(CommittedWriteResultV1, header) == 0);
    assert!(offset_of!(CommittedWriteResultV1, sizes) == 8);
    assert!(offset_of!(CommittedWriteResultV1, sizes) + 32 == 40);

    assert!(size_of::<CommittedMutationResultV1>() == 72);
    assert!(align_of::<CommittedMutationResultV1>() == 8);
    assert!(offset_of!(CommittedMutationResultV1, header) == 0);
    assert!(offset_of!(CommittedMutationResultV1, mutation_kind) == 8);
    assert!(offset_of!(CommittedMutationResultV1, flags) == 10);
    assert!(offset_of!(CommittedMutationResultV1, reserved) == 12);
    assert!(offset_of!(CommittedMutationResultV1, sizes) == 16);
    assert!(offset_of!(CommittedMutationResultV1, namespace_generation) == 48);
    assert!(offset_of!(CommittedMutationResultV1, security_generation) == 56);
    assert!(offset_of!(CommittedMutationResultV1, kind_payload) == 64);
    assert!(offset_of!(CommittedMutationResultV1, kind_payload) + 8 == 72);
};
