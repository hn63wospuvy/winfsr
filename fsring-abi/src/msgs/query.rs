//! Versioned query control blobs and their closed registries.

use core::mem::{align_of, size_of};

use crate::{
    codec::Pod,
    ids::{FileId, LinkId},
};

use super::{BlobSlice, BufferRef, ControlHeader, SizeState};

/// cbindgen:ignore
pub mod query_info_class {
    pub const INVALID: u16 = 0;
    pub const CANONICAL: u16 = 1;
}

/// cbindgen:ignore
pub mod query_volume_class {
    pub const INVALID: u16 = 0;
    pub const SIZE: u16 = 1;
}

/// cbindgen:ignore
pub mod query_dir_flags {
    pub const RESTART: u32 = 0x0000_0001;
    pub const SINGLE: u32 = 0x0000_0002;
    pub const EXACT_PATTERN: u32 = 0x0000_0004;
    pub const ALL: u32 = 0x0000_0007;
}

/// cbindgen:ignore
pub mod query_dir_result_flags {
    pub const EOF: u32 = 0x0000_0001;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryInfoV1 {
    pub header: ControlHeader,
    pub info_class: u16,
    pub flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub output: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileInfoV1 {
    pub header: ControlHeader,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub sizes: SizeState,
    pub namespace_generation: u64,
    pub security_generation: u64,
    pub attributes: u32,
    pub link_count: u32,
    pub reparse_tag: u32,
    pub flags: u32,
}

/// Registry-only fixed prefix; the QUERY_DIR version map requires
/// [`QueryDirV2`] in ABI 2.1.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryDirV1 {
    pub header: ControlHeader,
    pub enumeration_cookie: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub pattern: BlobSlice,
    pub output: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryDirV2 {
    pub header: ControlHeader,
    pub enumeration_cookie: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub pattern: BlobSlice,
    pub output: BufferRef,
    pub enumeration_generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryDirResultV1 {
    pub header: ControlHeader,
    pub next_cookie: u64,
    pub flags: u32,
    pub entry_count: u32,
    pub entries: BlobSlice,
    pub required_length: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirEntryV1 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub link_id: LinkId,
    pub sizes: SizeState,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub namespace_generation: u64,
    pub attributes: u32,
    pub reparse_tag: u32,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub name: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueryVolumeV1 {
    pub header: ControlHeader,
    pub info_class: u16,
    pub flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub output: BufferRef,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VolumeSizeInfoV1 {
    pub header: ControlHeader,
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct QuerySecurityV1 {
    pub header: ControlHeader,
    pub security_information: u32,
    pub flags: u32,
    pub output: BufferRef,
}

/// Registry-only layout; ABI 2.1 registers no FSCTL code and the kernel
/// never emits one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsctlV1 {
    pub header: ControlHeader,
    pub code: u32,
    pub flags: u32,
    pub input: BufferRef,
    pub output: BufferRef,
}

// SAFETY: every Wave 7b record is repr(C), consists only of gapless
// all-bit-valid integer/POD fields, and the assertions below pin its complete
// layout.
unsafe impl Pod for QueryInfoV1 {}
unsafe impl Pod for FileInfoV1 {}
unsafe impl Pod for QueryDirV1 {}
unsafe impl Pod for QueryDirV2 {}
unsafe impl Pod for QueryDirResultV1 {}
unsafe impl Pod for DirEntryV1 {}
unsafe impl Pod for QueryVolumeV1 {}
unsafe impl Pod for VolumeSizeInfoV1 {}
unsafe impl Pod for QuerySecurityV1 {}
unsafe impl Pod for FsctlV1 {}

const _: () = assert!(size_of::<QueryInfoV1>() == 40);
const _: () = assert!(align_of::<QueryInfoV1>() == 8);
const _: () = assert!(size_of::<FileInfoV1>() == 104);
const _: () = assert!(align_of::<FileInfoV1>() == 8);
const _: () = assert!(size_of::<QueryDirV1>() == 56);
const _: () = assert!(align_of::<QueryDirV1>() == 8);
const _: () = assert!(size_of::<QueryDirV2>() == 64);
const _: () = assert!(align_of::<QueryDirV2>() == 8);
const _: () = assert!(size_of::<QueryDirResultV1>() == 40);
const _: () = assert!(align_of::<QueryDirResultV1>() == 8);
const _: () = assert!(size_of::<DirEntryV1>() == 136);
const _: () = assert!(align_of::<DirEntryV1>() == 8);
const _: () = assert!(size_of::<QueryVolumeV1>() == 40);
const _: () = assert!(align_of::<QueryVolumeV1>() == 8);
const _: () = assert!(size_of::<VolumeSizeInfoV1>() == 40);
const _: () = assert!(align_of::<VolumeSizeInfoV1>() == 8);
const _: () = assert!(size_of::<QuerySecurityV1>() == 40);
const _: () = assert!(align_of::<QuerySecurityV1>() == 8);
const _: () = assert!(size_of::<FsctlV1>() == 64);
const _: () = assert!(align_of::<FsctlV1>() == 8);
