//! Common fixed payloads and control-blob primitives.

use core::mem::{align_of, size_of};

use crate::{
    codec::Pod,
    ids::{AckToken, OpId},
};

pub const CONTROL_VERSION_V1: u16 = 1;
pub const CONTROL_VERSION_V2: u16 = 2;

pub mod buffer_kind {
    pub const NONE: u16 = 0;
    pub const SLOT: u16 = 1;
    pub const MAPPING: u16 = 2;
}

pub mod buffer_access {
    pub const K2U_READ_ONLY: u16 = 1;
    pub const U2K_WRITE: u16 = 2;
}

/// cbindgen:ignore
pub mod file_attributes {
    pub const READONLY: u32 = 0x0000_0001;
    pub const HIDDEN: u32 = 0x0000_0002;
    pub const SYSTEM: u32 = 0x0000_0004;
    pub const DIRECTORY: u32 = 0x0000_0010;
    pub const ARCHIVE: u32 = 0x0000_0020;
    pub const NORMAL: u32 = 0x0000_0080;
    pub const TEMPORARY: u32 = 0x0000_0100;
    pub const SPARSE_FILE: u32 = 0x0000_0200;
    pub const REPARSE_POINT: u32 = 0x0000_0400;
    pub const COMPRESSED: u32 = 0x0000_0800;
    pub const OFFLINE: u32 = 0x0000_1000;
    pub const NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
    pub const ENCRYPTED: u32 = 0x0000_4000;
    pub const REGISTRY_MASK: u32 = 0x0000_7fb7;
    pub const ACCEPTED_MASK_V21: u32 = 0x0000_7bb7;
    pub const SETTABLE_BASIC_MASK: u32 = 0x0000_31a7;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlHeader {
    pub struct_size: u32,
    pub struct_version: u16,
    pub required_flags: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobSlice {
    pub offset: u32,
    pub length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferRef {
    pub token: u64,
    pub offset: u32,
    pub length: u32,
    pub kind: u16,
    pub access: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SizeState {
    pub allocation_size: u64,
    pub file_size: u64,
    pub valid_data_length: u64,
    pub size_epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PControl {
    pub body: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OControl {
    pub body: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PBarrier {
    pub op_id: OpId,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PCancel {
    pub target_req_id: u64,
    pub target_session_epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PNotifyAck {
    pub token: AckToken,
    pub epoch: u64,
}

unsafe impl Pod for ControlHeader {}
unsafe impl Pod for BlobSlice {}
unsafe impl Pod for BufferRef {}
unsafe impl Pod for SizeState {}
unsafe impl Pod for PControl {}
unsafe impl Pod for OControl {}
unsafe impl Pod for PBarrier {}
unsafe impl Pod for PCancel {}
unsafe impl Pod for PNotifyAck {}

const _: () = assert!(size_of::<ControlHeader>() == 8);
const _: () = assert!(align_of::<ControlHeader>() == 4);
const _: () = assert!(size_of::<BlobSlice>() == 8);
const _: () = assert!(align_of::<BlobSlice>() == 4);
const _: () = assert!(size_of::<BufferRef>() == 24);
const _: () = assert!(align_of::<BufferRef>() == 8);
const _: () = assert!(size_of::<SizeState>() == 32);
const _: () = assert!(align_of::<SizeState>() == 8);
const _: () = assert!(size_of::<PControl>() == 24);
const _: () = assert!(align_of::<PControl>() == 8);
const _: () = assert!(size_of::<OControl>() == 24);
const _: () = assert!(align_of::<OControl>() == 8);
const _: () = assert!(size_of::<PBarrier>() == 24);
const _: () = assert!(align_of::<PBarrier>() == 8);
const _: () = assert!(size_of::<PCancel>() == 16);
const _: () = assert!(align_of::<PCancel>() == 8);
const _: () = assert!(size_of::<PNotifyAck>() == 24);
const _: () = assert!(align_of::<PNotifyAck>() == 8);
