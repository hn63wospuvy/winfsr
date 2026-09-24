//! Fixed authenticated-control and session wire prefixes.

use core::mem::{align_of, offset_of, size_of};

use crate::{
    codec::Pod,
    features::FeatureSet,
    ids::{BootInstanceId, FileId, MountId, RetireToken},
    layout::SLOT_CLASS_COUNT,
    msgs::{BlobSlice, BufferRef, ControlHeader},
};

/// cbindgen:ignore
pub const SLOT_CLASS_REQUEST_SIZE: u32 = 8;
/// cbindgen:ignore
pub const SETUP_REQUEST_V1_SIZE: u32 = 160;
/// cbindgen:ignore
pub const USER_VIEW_DESC_SIZE: u32 = 32;
/// cbindgen:ignore
pub const NOTIFICATION_CREDIT_V1_SIZE: u32 = 32;
/// cbindgen:ignore
pub const SESSION_RESULT_V1_PREFIX_SIZE: u32 = 136;
/// cbindgen:ignore
pub const ENTER_REQUEST_V1_SIZE: u32 = 48;
/// cbindgen:ignore
pub const ENTER_RESULT_V1_PREFIX_SIZE: u32 = 48;
/// cbindgen:ignore
pub const DETACH_REQUEST_V1_SIZE: u32 = 40;
/// cbindgen:ignore
pub const DONATE_BACKING_V2_PREFIX_SIZE: u32 = 48;
/// cbindgen:ignore
pub const RETIRE_MOUNT_V1_SIZE: u32 = 48;
/// cbindgen:ignore
pub const RETIRE_MOUNT_RESULT_V1_SIZE: u32 = 96;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotClassRequest {
    pub slot_size: u32,
    pub slot_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetupRequestV1 {
    pub header: ControlHeader,
    pub abi_major: u16,
    pub min_abi_minor: u16,
    pub max_abi_minor: u16,
    pub reserved0: u16,
    pub offered_features: FeatureSet,
    pub required_features: FeatureSet,
    pub required_os_capabilities: FeatureSet,
    pub ring_count: u32,
    pub sq_capacity: u32,
    pub cq_capacity: u32,
    pub max_inflight: u32,
    pub k2u_slot_classes: [SlotClassRequest; SLOT_CLASS_COUNT],
    pub u2k_slot_classes: [SlotClassRequest; SLOT_CLASS_COUNT],
    pub notification_credit_count: u32,
    pub notification_credit_size: u32,
    pub flags: u32,
    pub reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserViewDesc {
    pub section_offset: u64,
    pub length: u64,
    pub user_address: u64,
    pub ring_index: u32,
    pub kind: u16,
    pub access: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotificationCreditV1 {
    pub buffer: BufferRef,
    pub ring_index: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionResultV1 {
    pub header: ControlHeader,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub reserved0: u32,
    pub mount_id: MountId,
    pub boot_instance_id: BootInstanceId,
    pub session_epoch: u64,
    pub section_size: u64,
    pub selected_features: FeatureSet,
    pub os_capabilities: FeatureSet,
    pub view_count: u32,
    pub view_desc_size: u32,
    pub views_offset: u32,
    pub notification_credit_count: u32,
    pub notification_credit_desc_size: u32,
    pub notification_credits_offset: u32,
    pub ring_count: u32,
    pub max_inflight: u32,
    pub flags: u32,
    pub reserved1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnterRequestV1 {
    pub header: ControlHeader,
    pub mount_id: MountId,
    pub session_epoch: u64,
    pub ring_index: u32,
    pub flags: u32,
    pub cq_budget: u32,
    pub timeout_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnterResultV1 {
    pub header: ControlHeader,
    pub session_epoch: u64,
    pub ring_index: u32,
    pub flags: u32,
    pub cq_drained: u32,
    pub sq_ready: u32,
    pub notification_credit_count: u32,
    pub notification_credit_desc_size: u32,
    pub notification_credits_offset: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DetachRequestV1 {
    pub header: ControlHeader,
    pub mount_id: MountId,
    pub session_epoch: u64,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DonateBackingV2 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub pt_epoch: u64,
    pub sector_size: u32,
    pub flags: u32,
    pub backing_path: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetireMountV1 {
    pub header: ControlHeader,
    pub mount_id: MountId,
    pub token: RetireToken,
    pub action: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetireMountResultV1 {
    pub header: ControlHeader,
    pub mount_id: MountId,
    pub boot_instance_id: BootInstanceId,
    pub proof_token: RetireToken,
    pub latest_session_epoch: u64,
    pub selected_features: FeatureSet,
    pub journal_version: u32,
    pub mount_state: u16,
    pub flags: u16,
    pub reserved: u64,
}

// SAFETY: every type below is repr(C), contains only integer or already-Pod
// fields, has no implicit gap or tail padding under the asserted offsets, and
// accepts every possible bit pattern. Semantic validation is separate.
unsafe impl Pod for SlotClassRequest {}
unsafe impl Pod for SetupRequestV1 {}
unsafe impl Pod for UserViewDesc {}
unsafe impl Pod for NotificationCreditV1 {}
unsafe impl Pod for SessionResultV1 {}
unsafe impl Pod for EnterRequestV1 {}
unsafe impl Pod for EnterResultV1 {}
unsafe impl Pod for DetachRequestV1 {}
unsafe impl Pod for DonateBackingV2 {}
unsafe impl Pod for RetireMountV1 {}
unsafe impl Pod for RetireMountResultV1 {}

macro_rules! assert_layout {
    ($ty:ty, $size:expr, $align:expr; $($field:ident => $offset:expr),+ $(,)?) => {
        const _: () = {
            assert!(size_of::<$ty>() == $size);
            assert!(align_of::<$ty>() == $align);
            $(assert!(offset_of!($ty, $field) == $offset);)+
        };
    };
}

assert_layout!(SlotClassRequest, 8, 4;
    slot_size => 0, slot_count => 4);
assert_layout!(SetupRequestV1, 160, 8;
    header => 0, abi_major => 8, min_abi_minor => 10,
    max_abi_minor => 12, reserved0 => 14, offered_features => 16,
    required_features => 32, required_os_capabilities => 48,
    ring_count => 64, sq_capacity => 68, cq_capacity => 72,
    max_inflight => 76, k2u_slot_classes => 80,
    u2k_slot_classes => 112, notification_credit_count => 144,
    notification_credit_size => 148, flags => 152, reserved1 => 156);
assert_layout!(UserViewDesc, 32, 8;
    section_offset => 0, length => 8, user_address => 16,
    ring_index => 24, kind => 28, access => 30);
assert_layout!(NotificationCreditV1, 32, 8;
    buffer => 0, ring_index => 24, reserved => 28);
assert_layout!(SessionResultV1, 136, 8;
    header => 0, abi_major => 8, abi_minor => 10, reserved0 => 12,
    mount_id => 16, boot_instance_id => 32, session_epoch => 48,
    section_size => 56, selected_features => 64, os_capabilities => 80,
    view_count => 96, view_desc_size => 100, views_offset => 104,
    notification_credit_count => 108, notification_credit_desc_size => 112,
    notification_credits_offset => 116, ring_count => 120,
    max_inflight => 124, flags => 128, reserved1 => 132);
assert_layout!(EnterRequestV1, 48, 8;
    header => 0, mount_id => 8, session_epoch => 24,
    ring_index => 32, flags => 36, cq_budget => 40, timeout_ms => 44);
assert_layout!(EnterResultV1, 48, 8;
    header => 0, session_epoch => 8, ring_index => 16, flags => 20,
    cq_drained => 24, sq_ready => 28, notification_credit_count => 32,
    notification_credit_desc_size => 36, notification_credits_offset => 40,
    reserved => 44);
assert_layout!(DetachRequestV1, 40, 8;
    header => 0, mount_id => 8, session_epoch => 24,
    flags => 32, reserved => 36);
assert_layout!(DonateBackingV2, 48, 8;
    header => 0, file_id => 8, pt_epoch => 24, sector_size => 32,
    flags => 36, backing_path => 40);
assert_layout!(RetireMountV1, 48, 8;
    header => 0, mount_id => 8, token => 24, action => 40, reserved => 44);
assert_layout!(RetireMountResultV1, 96, 8;
    header => 0, mount_id => 8, boot_instance_id => 24,
    proof_token => 40, latest_session_epoch => 56,
    selected_features => 64, journal_version => 80, mount_state => 84,
    flags => 86, reserved => 88);
