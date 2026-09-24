//! Versioned exactly-once mutation control blobs and their closed registries.

use core::mem::{align_of, size_of};

use crate::{
    codec::Pod,
    ids::{FileId, LinkId, OpId},
};

use super::{BlobSlice, BufferRef, ControlHeader, SizeState};

/// cbindgen:ignore
pub mod mutation_kind {
    pub const INVALID: u16 = 0;
    pub const SET_BASIC_INFO: u16 = 1;
    pub const SET_ALLOCATION_SIZE: u16 = 2;
    pub const SET_END_OF_FILE: u16 = 3;
    pub const SET_VALID_DATA_LENGTH: u16 = 4;
    pub const RENAME: u16 = 5;
    pub const LINK: u16 = 6;
    pub const UNLINK: u16 = 7;
    pub const SET_SECURITY: u16 = 8;
    pub const SET_REPARSE: u16 = 9;
    pub const DELETE_REPARSE: u16 = 10;
    /// Assigned/reserved registry value; never selectable in base 2.1.
    pub const SET_SPARSE: u16 = 11;
}

/// cbindgen:ignore
pub mod basic_info_set_mask {
    pub const CREATION_TIME: u32 = 0x0000_0001;
    pub const LAST_ACCESS_TIME: u32 = 0x0000_0002;
    pub const LAST_WRITE_TIME: u32 = 0x0000_0004;
    pub const CHANGE_TIME: u32 = 0x0000_0008;
    pub const FILE_ATTRIBUTES: u32 = 0x0000_0010;
    pub const ALL: u32 = 0x0000_001f;
}

/// cbindgen:ignore
pub mod rename_flags {
    pub const REPLACE_IF_EXISTS: u32 = 0x0000_0001;
}

/// cbindgen:ignore
pub mod link_flags {
    pub const REPLACE_IF_EXISTS: u32 = 0x0000_0001;
}

/// cbindgen:ignore
pub mod security_information {
    pub const OWNER: u32 = 0x0000_0001;
    pub const GROUP: u32 = 0x0000_0002;
    pub const DACL: u32 = 0x0000_0004;
    pub const SACL: u32 = 0x0000_0008;
    pub const LABEL: u32 = 0x0000_0010;
    pub const ATTRIBUTE: u32 = 0x0000_0020;
    pub const SCOPE: u32 = 0x0000_0040;
    pub const BACKUP: u32 = 0x0001_0000;
    pub const UNPROTECTED_SACL: u32 = 0x1000_0000;
    pub const UNPROTECTED_DACL: u32 = 0x2000_0000;
    pub const PROTECTED_SACL: u32 = 0x4000_0000;
    pub const PROTECTED_DACL: u32 = 0x8000_0000;
    pub const SET_MASK: u32 = 0xf001_007f;
    pub const QUERY_ACCEPTED_MASK: u32 = 0x0000_000f;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MutationV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub mutation_kind: u16,
    pub mutation_flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub expected_namespace_generation: u64,
    pub expected_size_epoch: u64,
    pub body: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MutationResultV1 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub volume_commit_sequence: u64,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub result_flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetBasicInfoV1 {
    pub header: ControlHeader,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
    pub set_mask: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetSizeV1 {
    pub header: ControlHeader,
    pub new_size: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameV1 {
    pub header: ControlHeader,
    pub source_link_id: LinkId,
    pub target_parent_id: FileId,
    pub expected_source_parent_generation: u64,
    pub expected_target_parent_generation: u64,
    pub name: BlobSlice,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkV1 {
    pub header: ControlHeader,
    pub source_file_id: FileId,
    pub target_parent_id: FileId,
    pub expected_target_parent_generation: u64,
    pub name: BlobSlice,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkV1 {
    pub header: ControlHeader,
    pub link_id: LinkId,
    pub parent_id: FileId,
    pub expected_parent_generation: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetSecurityV1 {
    pub header: ControlHeader,
    pub security_information: u32,
    pub flags: u32,
    pub security_descriptor: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetReparseV1 {
    pub header: ControlHeader,
    pub tag: u32,
    pub flags: u32,
    pub reparse_data: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeleteReparseV1 {
    pub header: ControlHeader,
    pub tag: u32,
    pub flags: u32,
}

/// Registry-only assigned layout; illegal in base 2.1 and accepted by no
/// validator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SetSparseV1 {
    pub header: ControlHeader,
    pub sparse: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MutationV2 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub mutation_kind: u16,
    pub mutation_flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub expected_namespace_generation: u64,
    pub expected_size_epoch: u64,
    pub expected_security_generation: u64,
    pub body: BufferRef,
    pub reply: BufferRef,
    pub kind_result: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MutationResultV2 {
    pub header: ControlHeader,
    pub op_id: OpId,
    pub volume_commit_sequence: u64,
    pub mutation_kind: u16,
    pub result_flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub kind_result: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameResultV2 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub replaced_file_id: FileId,
    pub replaced_link_id: LinkId,
    pub source_parent_generation: u64,
    pub target_parent_generation: u64,
    pub replaced_namespace_generation: u64,
    pub link_count: u32,
    pub replaced_link_count: u32,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinkResultV2 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub new_link_id: LinkId,
    pub replaced_file_id: FileId,
    pub replaced_link_id: LinkId,
    pub target_parent_generation: u64,
    pub replaced_namespace_generation: u64,
    pub link_count: u32,
    pub replaced_link_count: u32,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnlinkResultV1 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub removed_link_id: LinkId,
    pub parent_generation: u64,
    pub remaining_link_count: u32,
    pub flags: u32,
}

unsafe impl Pod for MutationV1 {}
unsafe impl Pod for MutationResultV1 {}

// SAFETY: every Wave 7a record is repr(C), consists only of gapless
// all-bit-valid integer/POD fields, and the assertions below pin its complete
// layout.
unsafe impl Pod for SetBasicInfoV1 {}
unsafe impl Pod for SetSizeV1 {}
unsafe impl Pod for RenameV1 {}
unsafe impl Pod for LinkV1 {}
unsafe impl Pod for UnlinkV1 {}
unsafe impl Pod for SetSecurityV1 {}
unsafe impl Pod for SetReparseV1 {}
unsafe impl Pod for DeleteReparseV1 {}
unsafe impl Pod for SetSparseV1 {}
unsafe impl Pod for MutationV2 {}
unsafe impl Pod for MutationResultV2 {}
unsafe impl Pod for RenameResultV2 {}
unsafe impl Pod for LinkResultV2 {}
unsafe impl Pod for UnlinkResultV1 {}

const _: () = assert!(size_of::<MutationV1>() == 72);
const _: () = assert!(align_of::<MutationV1>() == 8);
const _: () = assert!(size_of::<MutationResultV1>() == 80);
const _: () = assert!(align_of::<MutationResultV1>() == 8);

const _: () = assert!(size_of::<SetBasicInfoV1>() == 48);
const _: () = assert!(align_of::<SetBasicInfoV1>() == 8);
const _: () = assert!(size_of::<SetSizeV1>() == 24);
const _: () = assert!(align_of::<SetSizeV1>() == 8);
const _: () = assert!(size_of::<RenameV1>() == 72);
const _: () = assert!(align_of::<RenameV1>() == 8);
const _: () = assert!(size_of::<LinkV1>() == 64);
const _: () = assert!(align_of::<LinkV1>() == 8);
const _: () = assert!(size_of::<UnlinkV1>() == 56);
const _: () = assert!(align_of::<UnlinkV1>() == 8);
const _: () = assert!(size_of::<SetSecurityV1>() == 24);
const _: () = assert!(align_of::<SetSecurityV1>() == 4);
const _: () = assert!(size_of::<SetReparseV1>() == 24);
const _: () = assert!(align_of::<SetReparseV1>() == 4);
const _: () = assert!(size_of::<DeleteReparseV1>() == 16);
const _: () = assert!(align_of::<DeleteReparseV1>() == 4);
const _: () = assert!(size_of::<SetSparseV1>() == 16);
const _: () = assert!(align_of::<SetSparseV1>() == 4);
const _: () = assert!(size_of::<MutationV2>() == 128);
const _: () = assert!(align_of::<MutationV2>() == 8);
const _: () = assert!(size_of::<MutationResultV2>() == 112);
const _: () = assert!(align_of::<MutationResultV2>() == 8);
const _: () = assert!(size_of::<RenameResultV2>() == 112);
const _: () = assert!(align_of::<RenameResultV2>() == 8);
const _: () = assert!(size_of::<LinkResultV2>() == 104);
const _: () = assert!(align_of::<LinkResultV2>() == 8);
const _: () = assert!(size_of::<UnlinkResultV1>() == 56);
const _: () = assert!(align_of::<UnlinkResultV1>() == 8);
