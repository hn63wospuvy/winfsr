//! Fixed ABI-major READ and WRITE payloads.

use core::mem::{align_of, size_of};

use crate::{codec::Pod, ids::OpId};

use super::BufferRef;

pub mod rw_flags {
    pub const PAGING: u32 = 1 << 0;
    pub const NOCACHE: u32 = 1 << 1;
    pub const WRITE_THROUGH: u32 = 1 << 2;
    pub const MAPPED: u32 = 1 << 3;
    pub const SYNC_PAGING: u32 = 1 << 4;
    pub const EXTENDING: u32 = 1 << 5;
    pub const ZERO_RANGE_VALID: u32 = 1 << 6;
}

/// READ uses `OpId::ZERO` plus a U2K-writable buffer; WRITE uses a nonzero
/// operation ID plus a K2U-read-only buffer. Receivers validate that semantic
/// direction after decoding this all-bit-valid wire representation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PRw {
    pub op_id: OpId,
    pub offset: u64,
    pub size_epoch: u64,
    pub initialized_offset: u64,
    pub data: BufferRef,
    pub length: u32,
    pub initialized_length: u32,
    pub rw_flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ORw {
    pub file_size: u64,
    pub valid_data_length: u64,
    pub size_epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WriteV2 {
    pub header: super::ControlHeader,
    pub op_id: OpId,
    pub offset: u64,
    pub expected_size_epoch: u64,
    pub initialized_offset: u64,
    pub data: BufferRef,
    pub length: u32,
    pub initialized_length: u32,
    pub rw_flags: u32,
    pub reserved: u32,
    pub reply: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WriteResultV2 {
    pub header: super::ControlHeader,
    pub sizes: super::SizeState,
    pub volume_commit_sequence: u64,
    pub flags: u32,
    pub reserved: u32,
}

unsafe impl Pod for PRw {}
unsafe impl Pod for ORw {}
// SAFETY: both records are repr(C), gapless, and contain only all-bit-valid POD fields.
unsafe impl Pod for WriteV2 {}
unsafe impl Pod for WriteResultV2 {}

const _: () = assert!(size_of::<PRw>() == 80);
const _: () = assert!(align_of::<PRw>() == 8);
const _: () = assert!(size_of::<ORw>() == 24);
const _: () = assert!(align_of::<ORw>() == 8);
const _: () = assert!(size_of::<WriteV2>() == 112);
const _: () = assert!(align_of::<WriteV2>() == 8);
const _: () = assert!(size_of::<WriteResultV2>() == 56);
const _: () = assert!(align_of::<WriteResultV2>() == 8);
