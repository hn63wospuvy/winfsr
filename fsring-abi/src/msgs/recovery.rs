//! Version 1 attach, replay, and durable-result control blobs.

use core::mem::{align_of, size_of};

use crate::{
    codec::Pod,
    features::FeatureSet,
    ids::{FileId, LinkId, MountId, OpId},
};

use super::{BufferRef, ControlHeader};

/// cbindgen:ignore
pub mod query_op_state {
    pub const INVALID: u16 = 0;
    pub const NOT_FOUND: u16 = 1;
    pub const PREPARED: u16 = 2;
    pub const COMMITTED: u16 = 3;
}

/// cbindgen:ignore
pub mod journal_version {
    pub const NONE: u32 = 0;
    pub const V1: u32 = 1;
}

/// cbindgen:ignore
pub mod query_op_required_flags {
    pub const ABORT_IF_PREPARED: u16 = 0x0001;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReplayOpenV1 {
    pub header: ControlHeader,
    pub kernel_open_id: u64,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub desired_access: u32,
    pub share_access: u32,
    pub create_options: u32,
    pub disposition: u32,
    pub ccb_sequence: u64,
    pub state_flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReplayOpenV2 {
    pub header: ControlHeader,
    pub kernel_open_id: u64,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub desired_access: u32,
    pub share_access: u32,
    pub create_options: u32,
    pub disposition: u32,
    pub ccb_sequence: u64,
    pub state_flags: u64,
    pub reply: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReplayOpenResultV1 {
    pub header: ControlHeader,
    pub provider_open_cookie: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AttachV1 {
    pub header: ControlHeader,
    pub prior_session_epoch: u64,
    pub requested_features: FeatureSet,
    pub mount_id: MountId,
    pub journal_version: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryOpV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub operation_digest: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryOpV2 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub operation_digest: [u8; 32],
    pub reply: BufferRef,
    pub committed_result: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryOpResultV1 {
    pub header: ControlHeader,
    pub state: u16,
    pub flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub op_id: OpId,
    pub result: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AckResultV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AckResultV2 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub operation_digest: [u8; 32],
}

unsafe impl Pod for ReplayOpenV1 {}
unsafe impl Pod for ReplayOpenResultV1 {}
unsafe impl Pod for AttachV1 {}
unsafe impl Pod for QueryOpV1 {}
unsafe impl Pod for QueryOpResultV1 {}
unsafe impl Pod for AckResultV1 {}
// SAFETY: all three records are repr(C), gapless, and contain only all-bit-valid POD fields.
unsafe impl Pod for ReplayOpenV2 {}
unsafe impl Pod for QueryOpV2 {}
unsafe impl Pod for AckResultV2 {}

const _: () = assert!(size_of::<ReplayOpenV1>() == 80);
const _: () = assert!(align_of::<ReplayOpenV1>() == 8);
const _: () = assert!(size_of::<ReplayOpenResultV1>() == 16);
const _: () = assert!(align_of::<ReplayOpenResultV1>() == 8);
const _: () = assert!(size_of::<AttachV1>() == 56);
const _: () = assert!(align_of::<AttachV1>() == 8);
const _: () = assert!(size_of::<QueryOpV1>() == 56);
const _: () = assert!(align_of::<QueryOpV1>() == 8);
const _: () = assert!(size_of::<QueryOpResultV1>() == 56);
const _: () = assert!(align_of::<QueryOpResultV1>() == 8);
const _: () = assert!(size_of::<AckResultV1>() == 24);
const _: () = assert!(align_of::<AckResultV1>() == 8);
const _: () = assert!(size_of::<ReplayOpenV2>() == 104);
const _: () = assert!(align_of::<ReplayOpenV2>() == 8);
const _: () = assert!(size_of::<QueryOpV2>() == 104);
const _: () = assert!(align_of::<QueryOpV2>() == 8);
const _: () = assert!(size_of::<AckResultV2>() == 56);
const _: () = assert!(align_of::<AckResultV2>() == 8);
