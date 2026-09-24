#![allow(clippy::upper_case_acronyms, dead_code, non_snake_case)]

use std::ffi::c_void;

pub(super) type BOOL = i32;
pub(super) type DWORD = u32;
pub(super) type HANDLE = *mut c_void;

pub(super) const INVALID_HANDLE_VALUE: HANDLE = -1_isize as HANDLE;
pub(super) const INVALID_FILE_ATTRIBUTES: DWORD = u32::MAX;

pub(super) const FILE_GENERIC_READ: DWORD = 0x0012_0089;
pub(super) const FILE_GENERIC_WRITE: DWORD = 0x0012_0116;
pub(super) const FILE_SHARE_READ: DWORD = 0x0000_0001;
pub(super) const FILE_SHARE_WRITE: DWORD = 0x0000_0002;
pub(super) const FILE_SHARE_DELETE: DWORD = 0x0000_0004;

pub(super) const CREATE_NEW: DWORD = 1;
pub(super) const CREATE_ALWAYS: DWORD = 2;
pub(super) const OPEN_EXISTING: DWORD = 3;
pub(super) const OPEN_ALWAYS: DWORD = 4;
pub(super) const TRUNCATE_EXISTING: DWORD = 5;

pub(super) const FILE_ATTRIBUTE_READONLY: DWORD = 0x0000_0001;
pub(super) const FILE_ATTRIBUTE_HIDDEN: DWORD = 0x0000_0002;
pub(super) const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x0000_0010;
pub(super) const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0000_0080;
pub(super) const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x0000_0400;
pub(super) const FILE_FLAG_BACKUP_SEMANTICS: DWORD = 0x0200_0000;

pub(super) const FILE_BASIC_INFO_CLASS: i32 = 0;
pub(super) const FILE_STANDARD_INFO_CLASS: i32 = 1;
pub(super) const FILE_ALLOCATION_INFO_CLASS: i32 = 5;

pub(super) const MOVEFILE_REPLACE_EXISTING: DWORD = 0x0000_0001;
pub(super) const DRIVE_UNKNOWN: DWORD = 0;
pub(super) const DRIVE_NO_ROOT_DIR: DWORD = 1;
pub(super) const DRIVE_FIXED: DWORD = 3;

pub(super) const OWNER_SECURITY_INFORMATION: DWORD = 0x0000_0001;
pub(super) const GROUP_SECURITY_INFORMATION: DWORD = 0x0000_0002;
pub(super) const DACL_SECURITY_INFORMATION: DWORD = 0x0000_0004;
pub(super) const SACL_SECURITY_INFORMATION: DWORD = 0x0000_0008;
pub(super) const SE_SELF_RELATIVE: u16 = 0x8000;
pub(super) const SECURITY_DESCRIPTOR_REVISION: DWORD = 1;

pub(super) const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
pub(super) const ERROR_ALREADY_EXISTS: i32 = 183;

pub(super) const LCMAP_UPPERCASE: DWORD = 0x0000_0200;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct BY_HANDLE_FILE_INFORMATION {
    pub dwFileAttributes: DWORD,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub dwVolumeSerialNumber: DWORD,
    pub nFileSizeHigh: DWORD,
    pub nFileSizeLow: DWORD,
    pub nNumberOfLinks: DWORD,
    pub nFileIndexHigh: DWORD,
    pub nFileIndexLow: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FILE_STANDARD_INFO {
    pub AllocationSize: i64,
    pub EndOfFile: i64,
    pub NumberOfLinks: DWORD,
    pub DeletePending: u8,
    pub Directory: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FILE_BASIC_INFO {
    pub CreationTime: i64,
    pub LastAccessTime: i64,
    pub LastWriteTime: i64,
    pub ChangeTime: i64,
    pub FileAttributes: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FILE_ALLOCATION_INFO {
    pub AllocationSize: i64,
}

#[repr(C)]
pub(super) struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: *mut c_void,
    pub bInheritHandle: BOOL,
}

#[repr(C)]
pub(super) union FILE_LINK_INFO_REPLACE_OR_FLAGS {
    pub ReplaceIfExists: u8,
    pub Flags: DWORD,
}

#[repr(C)]
pub(super) union FILE_RENAME_INFO_REPLACE_OR_FLAGS {
    pub ReplaceIfExists: u8,
    pub Flags: DWORD,
}

// These are the fixed prefixes of the SDK's trailing-WCHAR FILE_LINK_INFO and
// FILE_RENAME_INFO structures. FileNameLength counts bytes, excluding any
// trailing NUL.
#[repr(C)]
pub(super) struct FILE_LINK_INFO_PREFIX {
    pub ReplaceOrFlags: FILE_LINK_INFO_REPLACE_OR_FLAGS,
    pub RootDirectory: HANDLE,
    pub FileNameLength: DWORD,
    pub FileName: [u16; 1],
}

#[repr(C)]
pub(super) struct FILE_RENAME_INFO_PREFIX {
    pub ReplaceOrFlags: FILE_RENAME_INFO_REPLACE_OR_FLAGS,
    pub RootDirectory: HANDLE,
    pub FileNameLength: DWORD,
    pub FileName: [u16; 1],
}

const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<FILETIME>() == 8);
    assert!(align_of::<FILETIME>() == 4);
    assert!(offset_of!(FILETIME, dwLowDateTime) == 0);
    assert!(offset_of!(FILETIME, dwHighDateTime) == 4);
    assert!(size_of::<BY_HANDLE_FILE_INFORMATION>() == 52);
    assert!(align_of::<BY_HANDLE_FILE_INFORMATION>() == 4);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, dwFileAttributes) == 0);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, ftCreationTime) == 4);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, ftLastAccessTime) == 12);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, ftLastWriteTime) == 20);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, dwVolumeSerialNumber) == 28);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, nFileSizeHigh) == 32);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, nFileSizeLow) == 36);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, nNumberOfLinks) == 40);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, nFileIndexHigh) == 44);
    assert!(offset_of!(BY_HANDLE_FILE_INFORMATION, nFileIndexLow) == 48);
    assert!(size_of::<FILE_STANDARD_INFO>() == 24);
    assert!(align_of::<FILE_STANDARD_INFO>() == 8);
    assert!(offset_of!(FILE_STANDARD_INFO, AllocationSize) == 0);
    assert!(offset_of!(FILE_STANDARD_INFO, EndOfFile) == 8);
    assert!(offset_of!(FILE_STANDARD_INFO, NumberOfLinks) == 16);
    assert!(offset_of!(FILE_STANDARD_INFO, DeletePending) == 20);
    assert!(offset_of!(FILE_STANDARD_INFO, Directory) == 21);
    assert!(size_of::<FILE_BASIC_INFO>() == 40);
    assert!(align_of::<FILE_BASIC_INFO>() == 8);
    assert!(offset_of!(FILE_BASIC_INFO, CreationTime) == 0);
    assert!(offset_of!(FILE_BASIC_INFO, LastAccessTime) == 8);
    assert!(offset_of!(FILE_BASIC_INFO, LastWriteTime) == 16);
    assert!(offset_of!(FILE_BASIC_INFO, ChangeTime) == 24);
    assert!(offset_of!(FILE_BASIC_INFO, FileAttributes) == 32);
    assert!(size_of::<FILE_ALLOCATION_INFO>() == 8);
    assert!(align_of::<FILE_ALLOCATION_INFO>() == 8);
    assert!(offset_of!(FILE_ALLOCATION_INFO, AllocationSize) == 0);
    assert!(size_of::<FILE_LINK_INFO_REPLACE_OR_FLAGS>() == 4);
    assert!(align_of::<FILE_LINK_INFO_REPLACE_OR_FLAGS>() == 4);
    assert!(size_of::<FILE_RENAME_INFO_REPLACE_OR_FLAGS>() == 4);
    assert!(align_of::<FILE_RENAME_INFO_REPLACE_OR_FLAGS>() == 4);

    #[cfg(target_pointer_width = "64")]
    {
        assert!(size_of::<SECURITY_ATTRIBUTES>() == 24);
        assert!(align_of::<SECURITY_ATTRIBUTES>() == 8);
        assert!(offset_of!(SECURITY_ATTRIBUTES, nLength) == 0);
        assert!(offset_of!(SECURITY_ATTRIBUTES, lpSecurityDescriptor) == 8);
        assert!(offset_of!(SECURITY_ATTRIBUTES, bInheritHandle) == 16);
        assert!(size_of::<FILE_LINK_INFO_PREFIX>() == 24);
        assert!(offset_of!(FILE_LINK_INFO_PREFIX, RootDirectory) == 8);
        assert!(offset_of!(FILE_LINK_INFO_PREFIX, FileNameLength) == 16);
        assert!(offset_of!(FILE_LINK_INFO_PREFIX, FileName) == 20);
        assert!(size_of::<FILE_RENAME_INFO_PREFIX>() == 24);
        assert!(offset_of!(FILE_RENAME_INFO_PREFIX, RootDirectory) == 8);
        assert!(offset_of!(FILE_RENAME_INFO_PREFIX, FileNameLength) == 16);
        assert!(offset_of!(FILE_RENAME_INFO_PREFIX, FileName) == 20);
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert!(size_of::<SECURITY_ATTRIBUTES>() == 12);
        assert!(align_of::<SECURITY_ATTRIBUTES>() == 4);
        assert!(offset_of!(SECURITY_ATTRIBUTES, nLength) == 0);
        assert!(offset_of!(SECURITY_ATTRIBUTES, lpSecurityDescriptor) == 4);
        assert!(offset_of!(SECURITY_ATTRIBUTES, bInheritHandle) == 8);
        assert!(size_of::<FILE_LINK_INFO_PREFIX>() == 16);
        assert!(offset_of!(FILE_LINK_INFO_PREFIX, RootDirectory) == 4);
        assert!(offset_of!(FILE_LINK_INFO_PREFIX, FileNameLength) == 8);
        assert!(offset_of!(FILE_LINK_INFO_PREFIX, FileName) == 12);
        assert!(size_of::<FILE_RENAME_INFO_PREFIX>() == 16);
        assert!(offset_of!(FILE_RENAME_INFO_PREFIX, RootDirectory) == 4);
        assert!(offset_of!(FILE_RENAME_INFO_PREFIX, FileNameLength) == 8);
        assert!(offset_of!(FILE_RENAME_INFO_PREFIX, FileName) == 12);
    }
};

#[link(name = "kernel32")]
extern "system" {
    pub(super) fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    pub(super) fn CreateDirectoryW(
        lpPathName: *const u16,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
    ) -> BOOL;
    pub(super) fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub(super) fn GetFileInformationByHandle(
        hFile: HANDLE,
        lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
    ) -> BOOL;
    pub(super) fn GetFileInformationByHandleEx(
        hFile: HANDLE,
        FileInformationClass: i32,
        lpFileInformation: *mut c_void,
        dwBufferSize: DWORD,
    ) -> BOOL;
    pub(super) fn SetFileInformationByHandle(
        hFile: HANDLE,
        FileInformationClass: i32,
        lpFileInformation: *mut c_void,
        dwBufferSize: DWORD,
    ) -> BOOL;
    pub(super) fn SetFileTime(
        hFile: HANDLE,
        lpCreationTime: *const FILETIME,
        lpLastAccessTime: *const FILETIME,
        lpLastWriteTime: *const FILETIME,
    ) -> BOOL;
    pub(super) fn GetFileAttributesW(lpFileName: *const u16) -> DWORD;
    pub(super) fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: DWORD) -> BOOL;
    pub(super) fn GetDiskFreeSpaceW(
        lpRootPathName: *const u16,
        lpSectorsPerCluster: *mut DWORD,
        lpBytesPerSector: *mut DWORD,
        lpNumberOfFreeClusters: *mut DWORD,
        lpTotalNumberOfClusters: *mut DWORD,
    ) -> BOOL;
    pub(super) fn GetDiskFreeSpaceExW(
        lpDirectoryName: *const u16,
        lpFreeBytesAvailableToCaller: *mut u64,
        lpTotalNumberOfBytes: *mut u64,
        lpTotalNumberOfFreeBytes: *mut u64,
    ) -> BOOL;
    pub(super) fn GetVolumeInformationW(
        lpRootPathName: *const u16,
        lpVolumeNameBuffer: *mut u16,
        nVolumeNameSize: DWORD,
        lpVolumeSerialNumber: *mut DWORD,
        lpMaximumComponentLength: *mut DWORD,
        lpFileSystemFlags: *mut DWORD,
        lpFileSystemNameBuffer: *mut u16,
        nFileSystemNameSize: DWORD,
    ) -> BOOL;
    pub(super) fn GetDriveTypeW(lpRootPathName: *const u16) -> DWORD;
    pub(super) fn CreateHardLinkW(
        lpFileName: *const u16,
        lpExistingFileName: *const u16,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
    ) -> BOOL;
    pub(super) fn MoveFileExW(
        lpExistingFileName: *const u16,
        lpNewFileName: *const u16,
        dwFlags: DWORD,
    ) -> BOOL;
    pub(super) fn SetFileValidData(hFile: HANDLE, ValidDataLength: i64) -> BOOL;
    pub(super) fn LCMapStringEx(
        lpLocaleName: *const u16,
        dwMapFlags: DWORD,
        lpSrcStr: *const u16,
        cchSrc: i32,
        lpDestStr: *mut u16,
        cchDest: i32,
        lpVersionInformation: *mut c_void,
        lpReserved: *mut c_void,
        sortHandle: isize,
    ) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    pub(super) fn GetFileSecurityW(
        lpFileName: *const u16,
        RequestedInformation: DWORD,
        pSecurityDescriptor: *mut c_void,
        nLength: DWORD,
        lpnLengthNeeded: *mut DWORD,
    ) -> BOOL;
    pub(super) fn SetFileSecurityW(
        lpFileName: *const u16,
        SecurityInformation: DWORD,
        pSecurityDescriptor: *mut c_void,
    ) -> BOOL;
    pub(super) fn IsValidSecurityDescriptor(pSecurityDescriptor: *mut c_void) -> BOOL;
    pub(super) fn GetSecurityDescriptorControl(
        pSecurityDescriptor: *mut c_void,
        pControl: *mut u16,
        lpdwRevision: *mut DWORD,
    ) -> BOOL;
}
