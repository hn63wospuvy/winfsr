//! Version 1 transactional OPEN control blobs.

use core::mem::{align_of, size_of};

use crate::{
    codec::Pod,
    ids::{FileId, LinkId, OpId, TransactionId},
};

use super::{BufferRef, ControlHeader, SizeState};

/// cbindgen:ignore
pub mod create_result {
    pub const SUPERSEDED: u32 = 0;
    pub const OPENED: u32 = 1;
    pub const CREATED: u32 = 2;
    pub const OVERWRITTEN: u32 = 3;
    /// Reference constant only; never a legal successful wire result.
    pub const EXISTS: u32 = 4;
    /// Reference constant only; never a legal successful wire result.
    pub const DOES_NOT_EXIST: u32 = 5;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrepareOpenV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub parent_id: FileId,
    pub name: BufferRef,
    pub security_context_id: u64,
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub open_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrepareOpenV2 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub parent_id: FileId,
    pub name: BufferRef,
    pub security_context_id: u64,
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub open_flags: u32,
    pub requested_security_descriptor: BufferRef,
    pub extended_attributes: BufferRef,
    pub reply: BufferRef,
    pub result_security_descriptor: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrepareOpenResultV1 {
    pub header: ControlHeader,
    pub transaction_id: TransactionId,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub security_descriptor: BufferRef,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub object_flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitOpenV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub transaction_id: TransactionId,
    pub expected_namespace_generation: u64,
    pub expected_security_generation: u64,
    pub kernel_open_id: u64,
    pub commit_flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitOpenV2 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub transaction_id: TransactionId,
    pub expected_namespace_generation: u64,
    pub expected_security_generation: u64,
    pub kernel_open_id: u64,
    pub commit_flags: u32,
    pub reserved: u32,
    pub granted_access: u32,
    pub reserved2: u32,
    pub reply: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitOpenResultV1 {
    pub header: ControlHeader,
    pub provider_open_cookie: u64,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub create_result: u32,
    pub result_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommitOpenResultV2 {
    pub header: ControlHeader,
    pub provider_open_cookie: u64,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub create_result: u32,
    pub result_flags: u32,
    pub volume_commit_sequence: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbortOpenV1 {
    pub header: ControlHeader,
    pub transaction_id: TransactionId,
}

unsafe impl Pod for PrepareOpenV1 {}
unsafe impl Pod for PrepareOpenResultV1 {}
unsafe impl Pod for CommitOpenV1 {}
unsafe impl Pod for CommitOpenResultV1 {}
unsafe impl Pod for AbortOpenV1 {}
// SAFETY: each V2 record is repr(C), gapless, and contains only all-bit-valid
// integer or POD fields. The assertions below pin its complete layout.
unsafe impl Pod for PrepareOpenV2 {}
unsafe impl Pod for CommitOpenV2 {}
unsafe impl Pod for CommitOpenResultV2 {}

const _: () = assert!(size_of::<PrepareOpenV1>() == 96);
const _: () = assert!(align_of::<PrepareOpenV1>() == 8);
const _: () = assert!(size_of::<PrepareOpenResultV1>() == 136);
const _: () = assert!(align_of::<PrepareOpenResultV1>() == 8);
const _: () = assert!(size_of::<CommitOpenV1>() == 72);
const _: () = assert!(align_of::<CommitOpenV1>() == 8);
const _: () = assert!(size_of::<CommitOpenResultV1>() == 104);
const _: () = assert!(align_of::<CommitOpenResultV1>() == 8);
const _: () = assert!(size_of::<AbortOpenV1>() == 24);
const _: () = assert!(align_of::<AbortOpenV1>() == 8);
const _: () = assert!(size_of::<PrepareOpenV2>() == 192);
const _: () = assert!(align_of::<PrepareOpenV2>() == 8);
const _: () = assert!(size_of::<CommitOpenV2>() == 104);
const _: () = assert!(align_of::<CommitOpenV2>() == 8);
const _: () = assert!(size_of::<CommitOpenResultV2>() == 112);
const _: () = assert!(align_of::<CommitOpenResultV2>() == 8);
