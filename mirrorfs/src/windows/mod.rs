mod sys;

use std::ffi::{c_void, OsString};
use std::fmt;
use std::fs::File;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::FileExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Component as PathComponent, Path, PathBuf, Prefix};
use std::ptr;

use crate::identity::NativeKey;

pub(crate) const FILE_GENERIC_READ: u32 = sys::FILE_GENERIC_READ;
pub(crate) const FILE_GENERIC_WRITE: u32 = sys::FILE_GENERIC_WRITE;
pub(crate) const FILE_READ_DATA: u32 = 0x0000_0001;
pub(crate) const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
pub(crate) const WRITE_OWNER: u32 = 0x0008_0000;
pub(crate) const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub(crate) const FILE_SHARE_READ: u32 = sys::FILE_SHARE_READ;
pub(crate) const FILE_SHARE_WRITE: u32 = sys::FILE_SHARE_WRITE;
pub(crate) const FILE_SHARE_DELETE: u32 = sys::FILE_SHARE_DELETE;
pub(crate) const CREATE_NEW: u32 = sys::CREATE_NEW;
pub(crate) const CREATE_ALWAYS: u32 = sys::CREATE_ALWAYS;
pub(crate) const OPEN_EXISTING: u32 = sys::OPEN_EXISTING;
pub(crate) const OPEN_ALWAYS: u32 = sys::OPEN_ALWAYS;
pub(crate) const TRUNCATE_EXISTING: u32 = sys::TRUNCATE_EXISTING;
pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = sys::FILE_ATTRIBUTE_READONLY;
pub(crate) const FILE_ATTRIBUTE_HIDDEN: u32 = sys::FILE_ATTRIBUTE_HIDDEN;
pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = sys::FILE_ATTRIBUTE_DIRECTORY;
pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = sys::FILE_ATTRIBUTE_NORMAL;
pub(crate) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = sys::FILE_ATTRIBUTE_REPARSE_POINT;
pub(crate) const OWNER_SECURITY_INFORMATION: u32 = sys::OWNER_SECURITY_INFORMATION;
pub(crate) const GROUP_SECURITY_INFORMATION: u32 = sys::GROUP_SECURITY_INFORMATION;
pub(crate) const DACL_SECURITY_INFORMATION: u32 = sys::DACL_SECURITY_INFORMATION;
pub(crate) const SACL_SECURITY_INFORMATION: u32 = sys::SACL_SECURITY_INFORMATION;
pub(crate) const DRIVE_FIXED: u32 = sys::DRIVE_FIXED;

const MIN_SECURITY_DESCRIPTOR_SIZE: usize = 20;
const MAX_SECURITY_DESCRIPTOR_SIZE: usize = 65_536;
const MAX_LONG_PATH_UNITS_WITH_NUL: usize = 32_767;

#[derive(Debug)]
pub(crate) struct NativeHandle(File);

impl Deref for NativeHandle {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NativeHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NativeHandle {
    fn raw(&self) -> sys::HANDLE {
        self.0.as_raw_handle().cast::<c_void>()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMetadata {
    pub key: NativeKey,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
    pub change_time: i64,
    pub allocation_size: u64,
    pub file_size: u64,
    pub attributes: u32,
    pub link_count: u32,
    pub is_directory: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VolumeGeometry {
    pub root: PathBuf,
    pub filesystem_name: OsString,
    pub drive_type: u32,
    pub volume_serial: u32,
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeBasicInfoUpdate {
    pub creation_time: Option<i64>,
    pub last_access_time: Option<i64>,
    pub last_write_time: Option<i64>,
    pub change_time: Option<i64>,
    pub attributes: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct NativeEffectError {
    source: io::Error,
    effect_applied: bool,
}

impl NativeEffectError {
    fn new(source: io::Error, effect_applied: bool) -> Self {
        Self {
            source,
            effect_applied,
        }
    }

    pub(crate) fn effect_applied(&self) -> bool {
        self.effect_applied
    }

    pub(crate) fn source_io(&self) -> &io::Error {
        &self.source
    }
}

impl fmt::Display for NativeEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.effect_applied {
            write!(
                formatter,
                "native operation failed after an earlier native effect: {}",
                self.source
            )
        } else {
            self.source.fmt(formatter)
        }
    }
}

impl std::error::Error for NativeEffectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) fn open_existing(
    path: &Path,
    access: u32,
    share: u32,
    directory: bool,
) -> io::Result<NativeHandle> {
    let flags = if directory {
        sys::FILE_FLAG_BACKUP_SEMANTICS
    } else {
        sys::FILE_ATTRIBUTE_NORMAL
    };
    create_file(path, access, share, sys::OPEN_EXISTING, flags, None).map(|(handle, _)| handle)
}

pub(crate) fn create_file(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    attributes: u32,
    descriptor: Option<&[u8]>,
) -> io::Result<(NativeHandle, bool)> {
    if !matches!(
        disposition,
        sys::CREATE_NEW
            | sys::CREATE_ALWAYS
            | sys::OPEN_EXISTING
            | sys::OPEN_ALWAYS
            | sys::TRUNCATE_EXISTING
    ) {
        return Err(invalid_input("invalid CreateFileW disposition"));
    }

    let path = long_path(path)?;
    let mut descriptor = descriptor
        .map(|bytes| ValidatedDescriptor::new(bytes, io::ErrorKind::InvalidInput))
        .transpose()?;
    let mut security_attributes = security_attributes(descriptor.as_mut())?;
    let security_attributes_ptr = security_attributes
        .as_mut()
        .map_or(ptr::null_mut(), ptr::from_mut);

    // SAFETY: `path` is NUL-terminated and remains live for the call;
    // `security_attributes_ptr` is null or points to a live descriptor-backed
    // structure; all scalar values are passed with their SDK-declared types.
    let raw = unsafe {
        sys::CreateFileW(
            path.as_ptr(),
            access,
            share,
            security_attributes_ptr,
            disposition,
            attributes,
            ptr::null_mut(),
        )
    };
    if raw == sys::INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    let create_status = io::Error::last_os_error().raw_os_error();
    if raw.is_null() {
        return Err(invalid_data("CreateFileW returned a null success handle"));
    }

    let existed = match disposition {
        sys::CREATE_NEW => false,
        sys::OPEN_EXISTING | sys::TRUNCATE_EXISTING => true,
        sys::CREATE_ALWAYS | sys::OPEN_ALWAYS => create_status == Some(sys::ERROR_ALREADY_EXISTS),
        _ => return Err(invalid_data("validated disposition became inconsistent")),
    };

    // SAFETY: successful CreateFileW returned one valid owned handle. This is
    // its sole ownership transfer; `File` closes it exactly once on drop.
    let file = unsafe { File::from_raw_handle(raw.cast()) };
    Ok((NativeHandle(file), existed))
}

pub(crate) fn create_directory(path: &Path, descriptor: Option<&[u8]>) -> io::Result<()> {
    let path = long_path(path)?;
    let mut descriptor = descriptor
        .map(|bytes| ValidatedDescriptor::new(bytes, io::ErrorKind::InvalidInput))
        .transpose()?;
    let mut security_attributes = security_attributes(descriptor.as_mut())?;
    let security_attributes_ptr = security_attributes
        .as_mut()
        .map_or(ptr::null_mut(), ptr::from_mut);

    // SAFETY: `path` is a live NUL-terminated buffer and the optional security
    // attributes point to live, structurally validated descriptor storage.
    let result = unsafe { sys::CreateDirectoryW(path.as_ptr(), security_attributes_ptr) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

pub(crate) fn metadata(handle: &NativeHandle) -> io::Result<NativeMetadata> {
    let mut identity = zeroed_by_handle_information();
    // SAFETY: `handle.raw()` is live and owned by `handle`; `identity` is a
    // correctly sized writable SDK-layout output structure.
    let result = unsafe { sys::GetFileInformationByHandle(handle.raw(), &mut identity) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }

    let basic = basic_info(handle)?;
    let standard = standard_info(handle)?;
    validate_basic_info(&basic)?;
    if standard.AllocationSize < 0 || standard.EndOfFile < 0 {
        return Err(invalid_data("Win32 returned a negative native file size"));
    }
    if standard.AllocationSize < standard.EndOfFile {
        return Err(invalid_data(
            "native allocation size is smaller than end of file",
        ));
    }
    if standard.DeletePending > 1 || standard.Directory > 1 {
        return Err(invalid_data("Win32 returned an invalid BOOLEAN field"));
    }

    let by_handle_size = join_u32(identity.nFileSizeHigh, identity.nFileSizeLow);
    let file_size = u64::try_from(standard.EndOfFile)
        .map_err(|_| invalid_data("native end-of-file conversion failed"))?;
    if by_handle_size != file_size {
        return Err(invalid_data("native file-size queries disagree"));
    }

    Ok(NativeMetadata {
        key: NativeKey {
            volume_serial: identity.dwVolumeSerialNumber,
            file_index: join_u32(identity.nFileIndexHigh, identity.nFileIndexLow),
        },
        creation_time: basic.CreationTime,
        last_access_time: basic.LastAccessTime,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
        allocation_size: u64::try_from(standard.AllocationSize)
            .map_err(|_| invalid_data("native allocation-size conversion failed"))?,
        file_size,
        attributes: basic.FileAttributes,
        link_count: standard.NumberOfLinks,
        is_directory: standard.Directory != 0,
    })
}

pub(crate) fn read_at(handle: &NativeHandle, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
    handle.seek_read(buffer, offset)
}

pub(crate) fn write_at(handle: &NativeHandle, offset: u64, data: &[u8]) -> io::Result<usize> {
    #[cfg(test)]
    let data = SHORT_WRITE_LIMIT.with(|limit| {
        let limit = limit.get().unwrap_or(data.len());
        &data[..data.len().min(limit)]
    });
    handle.seek_write(data, offset)
}

pub(crate) fn flush(handle: &NativeHandle) -> io::Result<()> {
    handle.sync_all()
}

#[cfg(test)]
thread_local! {
    static SHORT_WRITE_LIMIT: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_short_write_limit<T>(limit: usize, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<usize>);

    impl Drop for Restore {
        fn drop(&mut self) {
            SHORT_WRITE_LIMIT.with(|slot| slot.set(self.0));
        }
    }

    SHORT_WRITE_LIMIT.with(|slot| {
        let restore = Restore(slot.replace(Some(limit)));
        let result = action();
        drop(restore);
        result
    })
}

pub(crate) fn volume_geometry(path: &Path) -> io::Result<VolumeGeometry> {
    let root = volume_root(path)?;
    let root_wide = long_path(&root)?;
    let mut sectors_per_allocation_unit = 0;
    let mut bytes_per_sector = 0;
    let mut free_clusters = 0;
    let mut total_clusters = 0;

    // SAFETY: `root_wide` is live and NUL-terminated; every output pointer is
    // valid for one SDK-declared DWORD.
    let result = unsafe {
        sys::GetDiskFreeSpaceW(
            root_wide.as_ptr(),
            &mut sectors_per_allocation_unit,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }

    let mut available_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut total_free_bytes = 0_u64;
    // SAFETY: `root_wide` is live and NUL-terminated; every output pointer is
    // valid for one SDK-declared ULARGE_INTEGER (represented as `u64`).
    let result = unsafe {
        sys::GetDiskFreeSpaceExW(
            root_wide.as_ptr(),
            &mut available_bytes,
            &mut total_bytes,
            &mut total_free_bytes,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    let (total_allocation_units, available_allocation_units) = validate_volume_counts(
        sectors_per_allocation_unit,
        bytes_per_sector,
        free_clusters,
        total_clusters,
        available_bytes,
        total_bytes,
        total_free_bytes,
    )?;

    let mut volume_serial = 0;
    let mut maximum_component_length = 0;
    let mut filesystem_flags = 0;
    let mut filesystem_name = [0_u16; 64];
    let filesystem_name_len = u32::try_from(filesystem_name.len())
        .map_err(|_| invalid_input("filesystem-name buffer is too large"))?;
    // SAFETY: `root_wide` and `filesystem_name` are live with the exact lengths
    // supplied; omitted optional volume-name output is represented by null/0.
    let result = unsafe {
        sys::GetVolumeInformationW(
            root_wide.as_ptr(),
            ptr::null_mut(),
            0,
            &mut volume_serial,
            &mut maximum_component_length,
            &mut filesystem_flags,
            filesystem_name.as_mut_ptr(),
            filesystem_name_len,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    let filesystem_name_end = filesystem_name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| invalid_data("filesystem name was not NUL-terminated"))?;
    if filesystem_name_end == 0 || maximum_component_length == 0 {
        return Err(invalid_data("volume information omitted required values"));
    }

    // SAFETY: `root_wide` is a live NUL-terminated root path. GetDriveTypeW
    // reads no other memory and returns one DWORD discriminator.
    let drive_type = unsafe { sys::GetDriveTypeW(root_wide.as_ptr()) };
    let drive_type = validate_drive_type(drive_type)?;

    Ok(VolumeGeometry {
        root,
        filesystem_name: OsString::from_wide(&filesystem_name[..filesystem_name_end]),
        drive_type,
        volume_serial,
        total_allocation_units,
        available_allocation_units,
        sectors_per_allocation_unit,
        bytes_per_sector,
    })
}

fn validate_drive_type(drive_type: u32) -> io::Result<u32> {
    match drive_type {
        sys::DRIVE_UNKNOWN => Err(invalid_data("GetDriveTypeW returned DRIVE_UNKNOWN")),
        sys::DRIVE_NO_ROOT_DIR => Err(invalid_data("GetDriveTypeW returned DRIVE_NO_ROOT_DIR")),
        _ => Ok(drive_type),
    }
}

fn validate_volume_counts(
    sectors_per_allocation_unit: u32,
    bytes_per_sector: u32,
    free_clusters: u32,
    total_clusters: u32,
    available_bytes: u64,
    total_bytes: u64,
    total_free_bytes: u64,
) -> io::Result<(u64, u64)> {
    if sectors_per_allocation_unit == 0 || bytes_per_sector == 0 || free_clusters > total_clusters {
        return Err(invalid_data("GetDiskFreeSpaceW returned invalid geometry"));
    }

    let allocation_unit_size = u64::from(sectors_per_allocation_unit)
        .checked_mul(u64::from(bytes_per_sector))
        .filter(|size| *size != 0)
        .ok_or_else(|| invalid_data("allocation-unit size overflowed"))?;
    u64::from(total_clusters)
        .checked_mul(allocation_unit_size)
        .ok_or_else(|| invalid_data("total volume geometry overflowed"))?;
    u64::from(free_clusters)
        .checked_mul(allocation_unit_size)
        .ok_or_else(|| invalid_data("free volume geometry overflowed"))?;

    if available_bytes > total_bytes || available_bytes > total_free_bytes {
        return Err(invalid_data("GetDiskFreeSpaceExW returned invalid sizes"));
    }

    let total_allocation_units = total_bytes
        .checked_div(allocation_unit_size)
        .filter(|units| *units != 0)
        .ok_or_else(|| invalid_data("total bytes do not contain an allocation unit"))?;
    let available_allocation_units = available_bytes
        .checked_div(allocation_unit_size)
        .ok_or_else(|| invalid_data("allocation-unit size became zero"))?;

    Ok((total_allocation_units, available_allocation_units))
}

pub(crate) fn query_security(path: &Path, information: u32) -> io::Result<Box<[u8]>> {
    let path = long_path(path)?;
    let mut needed = 0;
    // SAFETY: `path` is live and NUL-terminated; the documented sizing call
    // uses a null descriptor with zero length and one writable DWORD output.
    let sizing_result = unsafe {
        sys::GetFileSecurityW(path.as_ptr(), information, ptr::null_mut(), 0, &mut needed)
    };
    if sizing_result != 0 {
        return Err(invalid_data(
            "GetFileSecurityW sizing unexpectedly succeeded without output",
        ));
    }
    let sizing_error = io::Error::last_os_error();
    if sizing_error.raw_os_error() != Some(sys::ERROR_INSUFFICIENT_BUFFER) {
        return Err(sizing_error);
    }

    let needed = usize::try_from(needed)
        .map_err(|_| invalid_data("security descriptor size did not fit usize"))?;
    validate_descriptor_length(needed, io::ErrorKind::InvalidData)?;
    let word_count = needed
        .checked_add(3)
        .ok_or_else(|| invalid_data("security descriptor word count overflowed"))?
        / 4;
    let mut words = vec![0_u32; word_count];
    let buffer_len = u32::try_from(needed)
        .map_err(|_| invalid_data("security descriptor size did not fit DWORD"))?;
    let mut returned = 0;
    // SAFETY: `words` is DWORD-aligned writable storage of at least
    // `buffer_len` bytes, `path` is live/NUL-terminated, and `returned` is a
    // writable DWORD output.
    let result = unsafe {
        sys::GetFileSecurityW(
            path.as_ptr(),
            information,
            words.as_mut_ptr().cast(),
            buffer_len,
            &mut returned,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    let returned = usize::try_from(returned)
        .map_err(|_| invalid_data("returned descriptor size did not fit usize"))?;
    if returned > needed {
        return Err(invalid_data(
            "GetFileSecurityW returned more bytes than its output buffer",
        ));
    }
    validate_descriptor_length(returned, io::ErrorKind::InvalidData)?;

    let mut bytes = words
        .into_iter()
        .flat_map(u32::to_ne_bytes)
        .take(returned)
        .collect::<Vec<_>>();
    let validated = ValidatedDescriptor::new(&bytes, io::ErrorKind::InvalidData)?;
    if validated.len != returned {
        return Err(invalid_data("validated descriptor length changed"));
    }
    bytes.shrink_to_fit();
    Ok(bytes.into_boxed_slice())
}

pub(crate) fn set_security(path: &Path, information: u32, descriptor: &[u8]) -> io::Result<()> {
    let path = long_path(path)?;
    let mut descriptor = ValidatedDescriptor::new(descriptor, io::ErrorKind::InvalidInput)?;
    // SAFETY: `path` is live/NUL-terminated and `descriptor` is live,
    // DWORD-aligned, bounded, self-relative, and structurally/API validated.
    let result =
        unsafe { sys::SetFileSecurityW(path.as_ptr(), information, descriptor.as_mut_ptr()) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

/// Validate one bounded, revision-1 self-relative descriptor without applying
/// it to a backing object. This is the PREPARE-side form of the same validation
/// used by the effecting create/set wrappers below.
pub(crate) fn validate_security_descriptor(descriptor: &[u8]) -> io::Result<()> {
    ValidatedDescriptor::new(descriptor, io::ErrorKind::InvalidInput).map(drop)
}

pub(crate) fn uppercase_invariant(units: &[u16]) -> io::Result<Box<[u16]>> {
    if units.is_empty() {
        return Ok(Box::new([]));
    }
    if char::decode_utf16(units.iter().copied()).any(|scalar| scalar.is_err()) {
        return Err(invalid_input("uppercase input is not well-formed UTF-16"));
    }
    let source_len = i32::try_from(units.len())
        .map_err(|_| invalid_input("uppercase input exceeds Win32 length range"))?;
    let invariant_locale = [0_u16];

    // SAFETY: source and invariant-locale buffers are live for their declared
    // lengths; the documented sizing call uses a null destination and zero.
    let required = unsafe {
        sys::LCMapStringEx(
            invariant_locale.as_ptr(),
            sys::LCMAP_UPPERCASE,
            units.as_ptr(),
            source_len,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    if required == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    let required_usize = usize::try_from(required)
        .map_err(|_| invalid_data("uppercase result length was negative"))?;
    let mut output = vec![0_u16; required_usize];

    // SAFETY: all input buffers remain live, and `output` has exactly
    // `required` writable WCHAR elements as established by the sizing call.
    let written = unsafe {
        sys::LCMapStringEx(
            invariant_locale.as_ptr(),
            sys::LCMAP_UPPERCASE,
            units.as_ptr(),
            source_len,
            output.as_mut_ptr(),
            required,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    if written == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    if written != required {
        return Err(invalid_data(
            "uppercase output length changed between calls",
        ));
    }
    Ok(output.into_boxed_slice())
}

pub(crate) fn create_hard_link(new_link: &Path, existing: &Path) -> io::Result<()> {
    let new_link = long_path(new_link)?;
    let existing = long_path(existing)?;
    // SAFETY: both paths are live NUL-terminated WCHAR buffers and the
    // reserved security-attributes argument is correctly null.
    let result =
        unsafe { sys::CreateHardLinkW(new_link.as_ptr(), existing.as_ptr(), ptr::null_mut()) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

pub(crate) fn move_file(source: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    let source = long_path(source)?;
    let destination = long_path(destination)?;
    let flags = if replace {
        sys::MOVEFILE_REPLACE_EXISTING
    } else {
        0
    };
    // SAFETY: both paths are live NUL-terminated WCHAR buffers and `flags`
    // contains only the supported MOVEFILE_REPLACE_EXISTING bit.
    let result = unsafe { sys::MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

pub(crate) fn set_basic_info(
    handle: &NativeHandle,
    path: &Path,
    update: NativeBasicInfoUpdate,
) -> Result<(), NativeEffectError> {
    // Validate the path argument even when this particular update does not
    // select attributes and therefore will not pass it to Win32.
    let _checked_path = long_path(path).map_err(|error| NativeEffectError::new(error, false))?;
    for time in [
        update.creation_time,
        update.last_access_time,
        update.last_write_time,
        update.change_time,
    ]
    .into_iter()
    .flatten()
    {
        if time < 0 {
            return Err(NativeEffectError::new(
                invalid_input("NT file times must be nonnegative"),
                false,
            ));
        }
    }

    let creation = update
        .creation_time
        .map(filetime_from_i64)
        .transpose()
        .map_err(|error| NativeEffectError::new(error, false))?;
    let access = update
        .last_access_time
        .map(filetime_from_i64)
        .transpose()
        .map_err(|error| NativeEffectError::new(error, false))?;
    let write = update
        .last_write_time
        .map(filetime_from_i64)
        .transpose()
        .map_err(|error| NativeEffectError::new(error, false))?;
    let mut effect_applied = false;

    if let Some(attributes) = update.attributes {
        apply_native_effect(&mut effect_applied, set_attributes(path, attributes))?;
    }

    if creation.is_some() || access.is_some() || write.is_some() {
        // SAFETY: `handle` is live and each optional pointer is null or points
        // to a live FILETIME with the exact SDK layout.
        let result = unsafe {
            sys::SetFileTime(
                handle.raw(),
                option_ptr(creation.as_ref()),
                option_ptr(access.as_ref()),
                option_ptr(write.as_ref()),
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            return Err(NativeEffectError::new(error, effect_applied));
        }
        effect_applied = true;
    }

    if let Some(change_time) = update.change_time {
        let mut current =
            basic_info(handle).map_err(|error| NativeEffectError::new(error, effect_applied))?;
        current.ChangeTime = change_time;
        apply_native_effect(
            &mut effect_applied,
            set_file_information(
                handle,
                sys::FILE_BASIC_INFO_CLASS,
                ptr::from_mut(&mut current).cast(),
                std::mem::size_of::<sys::FILE_BASIC_INFO>(),
            ),
        )?;
    }
    Ok(())
}

fn apply_native_effect(
    effect_applied: &mut bool,
    result: io::Result<()>,
) -> Result<(), NativeEffectError> {
    match result {
        Ok(()) => {
            *effect_applied = true;
            Ok(())
        }
        Err(error) => Err(NativeEffectError::new(error, *effect_applied)),
    }
}

pub(crate) fn set_allocation_size(handle: &NativeHandle, size: u64) -> io::Result<()> {
    let size = i64::try_from(size)
        .map_err(|_| invalid_input("allocation size exceeds native signed range"))?;
    let mut info = sys::FILE_ALLOCATION_INFO {
        AllocationSize: size,
    };
    set_file_information(
        handle,
        sys::FILE_ALLOCATION_INFO_CLASS,
        ptr::from_mut(&mut info).cast(),
        std::mem::size_of::<sys::FILE_ALLOCATION_INFO>(),
    )
}

pub(crate) fn set_valid_data_length(handle: &NativeHandle, size: u64) -> io::Result<()> {
    let size = i64::try_from(size)
        .map_err(|_| invalid_input("valid-data length exceeds native signed range"))?;
    // SAFETY: `handle` is live and `size` was checked to fit the SDK's signed
    // LONGLONG parameter.
    let result = unsafe { sys::SetFileValidData(handle.raw(), size) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

pub(crate) fn attributes(path: &Path) -> io::Result<u32> {
    let path = long_path(path)?;
    // SAFETY: `path` is a live NUL-terminated WCHAR buffer.
    let attributes = unsafe { sys::GetFileAttributesW(path.as_ptr()) };
    if attributes == sys::INVALID_FILE_ATTRIBUTES {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(attributes)
}

pub(crate) fn set_attributes(path: &Path, attributes: u32) -> io::Result<()> {
    if attributes == sys::INVALID_FILE_ATTRIBUTES {
        return Err(invalid_input("invalid file-attributes sentinel"));
    }
    let path = long_path(path)?;
    // SAFETY: `path` is live/NUL-terminated and the invalid sentinel was
    // rejected before passing the DWORD to Win32.
    let result = unsafe { sys::SetFileAttributesW(path.as_ptr(), attributes) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

fn basic_info(handle: &NativeHandle) -> io::Result<sys::FILE_BASIC_INFO> {
    let mut info = sys::FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: 0,
    };
    get_file_information(
        handle,
        sys::FILE_BASIC_INFO_CLASS,
        ptr::from_mut(&mut info).cast(),
        std::mem::size_of::<sys::FILE_BASIC_INFO>(),
    )?;
    Ok(info)
}

fn standard_info(handle: &NativeHandle) -> io::Result<sys::FILE_STANDARD_INFO> {
    let mut info = sys::FILE_STANDARD_INFO {
        AllocationSize: 0,
        EndOfFile: 0,
        NumberOfLinks: 0,
        DeletePending: 0,
        Directory: 0,
    };
    get_file_information(
        handle,
        sys::FILE_STANDARD_INFO_CLASS,
        ptr::from_mut(&mut info).cast(),
        std::mem::size_of::<sys::FILE_STANDARD_INFO>(),
    )?;
    Ok(info)
}

fn get_file_information(
    handle: &NativeHandle,
    class: i32,
    output: *mut c_void,
    output_len: usize,
) -> io::Result<()> {
    let output_len = u32::try_from(output_len)
        .map_err(|_| invalid_input("native information buffer exceeds DWORD"))?;
    // SAFETY: callers pass a live handle and a writable pointer to the exact
    // fixed SDK structure selected by `class`, with its checked byte size.
    let result =
        unsafe { sys::GetFileInformationByHandleEx(handle.raw(), class, output, output_len) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

fn set_file_information(
    handle: &NativeHandle,
    class: i32,
    input: *mut c_void,
    input_len: usize,
) -> io::Result<()> {
    let input_len = u32::try_from(input_len)
        .map_err(|_| invalid_input("native information buffer exceeds DWORD"))?;
    // SAFETY: callers pass a live handle and a readable pointer to the exact
    // fixed SDK structure selected by `class`, with its checked byte size.
    let result = unsafe { sys::SetFileInformationByHandle(handle.raw(), class, input, input_len) };
    if result == 0 {
        let error = io::Error::last_os_error();
        return Err(error);
    }
    Ok(())
}

fn security_attributes(
    descriptor: Option<&mut ValidatedDescriptor>,
) -> io::Result<Option<sys::SECURITY_ATTRIBUTES>> {
    let length = u32::try_from(std::mem::size_of::<sys::SECURITY_ATTRIBUTES>())
        .map_err(|_| invalid_input("SECURITY_ATTRIBUTES size exceeds DWORD"))?;
    Ok(descriptor.map(|descriptor| sys::SECURITY_ATTRIBUTES {
        nLength: length,
        lpSecurityDescriptor: descriptor.as_mut_ptr(),
        bInheritHandle: 0,
    }))
}

struct ValidatedDescriptor {
    words: Vec<u32>,
    len: usize,
}

impl ValidatedDescriptor {
    fn new(bytes: &[u8], kind: io::ErrorKind) -> io::Result<Self> {
        validate_descriptor_structure(bytes, kind)?;
        let mut words = vec![0_u32; bytes.len().div_ceil(4)];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
            let mut encoded = [0_u8; 4];
            encoded[..chunk.len()].copy_from_slice(chunk);
            *word = u32::from_ne_bytes(encoded);
        }
        let mut descriptor = Self {
            words,
            len: bytes.len(),
        };

        // SAFETY: structural validation bounded every self-relative component;
        // `words` is DWORD-aligned live storage containing the complete bytes.
        let valid = unsafe { sys::IsValidSecurityDescriptor(descriptor.as_mut_ptr()) };
        if valid == 0 {
            return Err(io::Error::new(kind, "invalid security descriptor"));
        }

        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: the descriptor passed API validation above; both outputs are
        // live pointers to their exact SDK-declared scalar types.
        let result = unsafe {
            sys::GetSecurityDescriptorControl(descriptor.as_mut_ptr(), &mut control, &mut revision)
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            return Err(error);
        }
        if revision != sys::SECURITY_DESCRIPTOR_REVISION || control & sys::SE_SELF_RELATIVE == 0 {
            return Err(io::Error::new(
                kind,
                "security descriptor is not revision-1 self-relative data",
            ));
        }
        Ok(descriptor)
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }
}

fn validate_descriptor_structure(bytes: &[u8], kind: io::ErrorKind) -> io::Result<()> {
    validate_descriptor_length(bytes.len(), kind)?;
    if bytes[0] != 1 {
        return Err(io::Error::new(
            kind,
            "unsupported security descriptor revision",
        ));
    }
    let control = read_u16(bytes, 2, kind)?;
    if control & sys::SE_SELF_RELATIVE == 0 {
        return Err(io::Error::new(
            kind,
            "security descriptor is not self-relative",
        ));
    }

    validate_sid_at(bytes, read_u32(bytes, 4, kind)?, kind)?;
    validate_sid_at(bytes, read_u32(bytes, 8, kind)?, kind)?;
    validate_acl_at(bytes, read_u32(bytes, 12, kind)?, kind)?;
    validate_acl_at(bytes, read_u32(bytes, 16, kind)?, kind)?;
    Ok(())
}

fn validate_descriptor_length(len: usize, kind: io::ErrorKind) -> io::Result<()> {
    if !(MIN_SECURITY_DESCRIPTOR_SIZE..=MAX_SECURITY_DESCRIPTOR_SIZE).contains(&len) {
        return Err(io::Error::new(
            kind,
            "security descriptor length must be in 20..=65536",
        ));
    }
    Ok(())
}

fn validate_sid_at(bytes: &[u8], offset: u32, kind: io::ErrorKind) -> io::Result<()> {
    if offset == 0 {
        return Ok(());
    }
    let offset = component_offset(bytes, offset, 8, kind)?;
    let sub_authority_count = usize::from(bytes[offset + 1]);
    let sid_len = 8_usize
        .checked_add(
            sub_authority_count
                .checked_mul(4)
                .ok_or_else(|| io::Error::new(kind, "SID length overflowed"))?,
        )
        .ok_or_else(|| io::Error::new(kind, "SID length overflowed"))?;
    checked_range(bytes, offset, sid_len, kind)?;
    Ok(())
}

fn validate_acl_at(bytes: &[u8], offset: u32, kind: io::ErrorKind) -> io::Result<()> {
    if offset == 0 {
        return Ok(());
    }
    let offset = component_offset(bytes, offset, 8, kind)?;
    let acl_size = usize::from(read_u16(bytes, offset + 2, kind)?);
    if acl_size < 8 {
        return Err(io::Error::new(kind, "ACL is shorter than its header"));
    }
    let acl = checked_range(bytes, offset, acl_size, kind)?;
    let ace_count = usize::from(read_u16(bytes, offset + 4, kind)?);
    let mut cursor = 8_usize;
    for _ in 0..ace_count {
        if cursor.checked_add(4).is_none_or(|end| end > acl.len()) {
            return Err(io::Error::new(kind, "ACE header exceeds ACL bounds"));
        }
        let ace_size = usize::from(u16::from_le_bytes([acl[cursor + 2], acl[cursor + 3]]));
        if ace_size < 4
            || cursor
                .checked_add(ace_size)
                .is_none_or(|end| end > acl.len())
        {
            return Err(io::Error::new(kind, "ACE exceeds ACL bounds"));
        }
        cursor += ace_size;
    }
    Ok(())
}

fn component_offset(
    bytes: &[u8],
    offset: u32,
    minimum_len: usize,
    kind: io::ErrorKind,
) -> io::Result<usize> {
    let offset = usize::try_from(offset)
        .map_err(|_| io::Error::new(kind, "descriptor offset did not fit usize"))?;
    if offset % 4 != 0 {
        return Err(io::Error::new(
            kind,
            "descriptor component is not DWORD-aligned",
        ));
    }
    checked_range(bytes, offset, minimum_len, kind)?;
    Ok(offset)
}

fn checked_range(
    bytes: &[u8],
    offset: usize,
    len: usize,
    kind: io::ErrorKind,
) -> io::Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| io::Error::new(kind, "descriptor component range overflowed"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| io::Error::new(kind, "descriptor component exceeds buffer"))
}

fn read_u16(bytes: &[u8], offset: usize, kind: io::ErrorKind) -> io::Result<u16> {
    let encoded = checked_range(bytes, offset, 2, kind)?;
    Ok(u16::from_le_bytes([encoded[0], encoded[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, kind: io::ErrorKind) -> io::Result<u32> {
    let encoded = checked_range(bytes, offset, 4, kind)?;
    Ok(u32::from_le_bytes([
        encoded[0], encoded[1], encoded[2], encoded[3],
    ]))
}

fn long_path(path: &Path) -> io::Result<Vec<u16>> {
    if !path.is_absolute() {
        return Err(invalid_input("Win32 path must be absolute"));
    }
    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.contains(&0) {
        return Err(invalid_input("Win32 path contains an interior NUL"));
    }

    let Some(PathComponent::Prefix(prefix)) = path.components().next() else {
        return Err(invalid_input("Win32 path has no supported prefix"));
    };
    let mut long = match prefix.kind() {
        Prefix::Disk(_) => {
            let mut result = r"\\?\".encode_utf16().collect::<Vec<_>>();
            result.extend_from_slice(&units);
            result
        }
        Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _) => units,
        Prefix::UNC(_, _) => {
            let mut result = r"\\?\UNC\".encode_utf16().collect::<Vec<_>>();
            result.extend_from_slice(&units[2..]);
            result
        }
        Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
            return Err(invalid_input("unsupported absolute Win32 path prefix"));
        }
    };

    let length_with_nul = long
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_input("Win32 path length overflow"))?;
    if length_with_nul > MAX_LONG_PATH_UNITS_WITH_NUL {
        return Err(invalid_input("Win32 path exceeds the long-path limit"));
    }
    long.push(0);
    Ok(long)
}

fn volume_root(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid_input("volume path must be absolute"));
    }
    let Some(PathComponent::Prefix(prefix)) = path.components().next() else {
        return Err(invalid_input("volume path has no Windows prefix"));
    };

    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            Ok(PathBuf::from(format!("{}:\\", char::from(letter))))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut units = r"\\".encode_utf16().collect::<Vec<_>>();
            units.extend(server.encode_wide());
            units.push(u16::from(b'\\'));
            units.extend(share.encode_wide());
            units.push(u16::from(b'\\'));
            Ok(PathBuf::from(OsString::from_wide(&units)))
        }
        Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
            Err(invalid_input("unsupported Windows volume prefix"))
        }
    }
}

fn validate_basic_info(info: &sys::FILE_BASIC_INFO) -> io::Result<()> {
    if [
        info.CreationTime,
        info.LastAccessTime,
        info.LastWriteTime,
        info.ChangeTime,
    ]
    .into_iter()
    .any(|time| time < 0)
    {
        return Err(invalid_data("Win32 returned a negative NT timestamp"));
    }
    if info.FileAttributes == sys::INVALID_FILE_ATTRIBUTES {
        return Err(invalid_data("Win32 returned invalid file attributes"));
    }
    Ok(())
}

fn filetime_from_i64(value: i64) -> io::Result<sys::FILETIME> {
    let value = u64::try_from(value).map_err(|_| invalid_input("NT file time is negative"))?;
    Ok(sys::FILETIME {
        dwLowDateTime: value as u32,
        dwHighDateTime: (value >> 32) as u32,
    })
}

fn option_ptr<T>(value: Option<&T>) -> *const T {
    value.map_or(ptr::null(), ptr::from_ref)
}

fn join_u32(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

fn zeroed_by_handle_information() -> sys::BY_HANDLE_FILE_INFORMATION {
    let zero = sys::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    sys::BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: 0,
        ftCreationTime: zero,
        ftLastAccessTime: zero,
        ftLastWriteTime: zero,
        dwVolumeSerialNumber: 0,
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        nNumberOfLinks: 0,
        nFileIndexHigh: 0,
        nFileIndexLow: 0,
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write as _};
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        attributes, create_directory, create_file, create_hard_link, long_path, metadata,
        move_file, open_existing, query_security, set_allocation_size, set_attributes,
        set_basic_info, set_security, set_valid_data_length, uppercase_invariant,
        validate_drive_type, validate_volume_counts, volume_geometry, NativeBasicInfoUpdate,
        ValidatedDescriptor, CREATE_ALWAYS, DACL_SECURITY_INFORMATION, DRIVE_FIXED,
        FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GROUP_SECURITY_INFORMATION,
        MAX_LONG_PATH_UNITS_WITH_NUL, OPEN_ALWAYS, OPEN_EXISTING, OWNER_SECURITY_INFORMATION,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct OwnedTempDir(PathBuf);

    impl OwnedTempDir {
        fn new() -> io::Result<Self> {
            for _ in 0..100 {
                let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = PathBuf::from(r"D:\").join(format!(
                    "winfsr-mirrorfs-task6-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self(path)),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }

            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique Task 6 directory on D:",
            ))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for OwnedTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn long_path_converts_only_supported_disk_and_unc_prefixes() {
        fn expected(value: &str) -> Vec<u16> {
            value.encode_utf16().chain([0]).collect()
        }

        assert_eq!(
            long_path(Path::new(r"D:\folder\name")).unwrap(),
            expected(r"\\?\D:\folder\name")
        );
        assert_eq!(
            long_path(Path::new(r"\\?\D:\folder\name")).unwrap(),
            expected(r"\\?\D:\folder\name")
        );
        assert_eq!(
            long_path(Path::new(r"\\server\share\folder")).unwrap(),
            expected(r"\\?\UNC\server\share\folder")
        );
        assert_eq!(
            long_path(Path::new(r"\\?\UNC\server\share\folder")).unwrap(),
            expected(r"\\?\UNC\server\share\folder")
        );
    }

    #[test]
    fn long_path_rejects_non_filesystem_names_and_enforces_the_pre_nul_limit() {
        for rejected in [
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\file",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\file",
            r"\\.\PhysicalDrive0",
            r"D:relative",
            r"relative",
        ] {
            let error = long_path(Path::new(rejected)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{rejected}");
        }

        let with_nul = PathBuf::from(OsString::from_wide(&[
            b'D' as u16,
            b':' as u16,
            b'\\' as u16,
            b'a' as u16,
            0,
            b'b' as u16,
        ]));
        assert_eq!(
            long_path(&with_nul).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        let mut boundary = r"\\?\D:\".encode_utf16().collect::<Vec<_>>();
        boundary.resize(MAX_LONG_PATH_UNITS_WITH_NUL - 1, b'a' as u16);
        let boundary = PathBuf::from(OsString::from_wide(&boundary));
        let encoded = long_path(&boundary).unwrap();
        assert_eq!(encoded.len(), MAX_LONG_PATH_UNITS_WITH_NUL);
        assert_eq!(encoded.last(), Some(&0));

        let mut too_long = boundary.as_os_str().encode_wide().collect::<Vec<_>>();
        too_long.push(b'a' as u16);
        let too_long = PathBuf::from(OsString::from_wide(&too_long));
        assert_eq!(
            long_path(&too_long).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn volume_counts_allow_quota_domains_and_unaligned_byte_counts() {
        let counts = validate_volume_counts(8, 512, 25, 100, 100_001, 400_003, 500_009).unwrap();

        assert_eq!(
            counts,
            (97, 24),
            "reported units come from the quota-aware Ex byte counts"
        );

        assert!(validate_volume_counts(8, 512, 25, 100, 401, 400, 500).is_err());
        assert!(validate_volume_counts(8, 512, 25, 100, 501, 600, 500).is_err());
        assert!(validate_volume_counts(0, 512, 25, 100, 100, 400, 500).is_err());
        assert!(validate_volume_counts(8, 512, 101, 100, 100, 400, 500).is_err());
        assert!(validate_volume_counts(u32::MAX, u32::MAX, 1, 2, 1, u64::MAX, u64::MAX,).is_err());
    }

    #[test]
    fn drive_type_errors_do_not_depend_on_the_thread_last_error() {
        for (drive_type, message) in [
            (0, "GetDriveTypeW returned DRIVE_UNKNOWN"),
            (1, "GetDriveTypeW returned DRIVE_NO_ROOT_DIR"),
        ] {
            let error = validate_drive_type(drive_type).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.raw_os_error(), None);
            assert_eq!(error.to_string(), message);
        }
        assert_eq!(validate_drive_type(3).unwrap(), 3);
    }

    #[test]
    fn native_handle_releases_an_exclusive_open_when_dropped() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("exclusive.txt");
        fs::write(&path, b"owned").unwrap();

        let handle = open_existing(&path, FILE_GENERIC_READ, 0, false).unwrap();
        let sharing_error = OpenOptions::new().read(true).open(&path).unwrap_err();
        assert_eq!(sharing_error.raw_os_error(), Some(32));

        drop(handle);
        OpenOptions::new().read(true).open(&path).unwrap();
    }

    #[test]
    fn hard_links_share_a_native_key_and_report_legal_metadata() {
        let temp = OwnedTempDir::new().unwrap();
        let original = temp.path().join("original.txt");
        let link = temp.path().join("linked.txt");
        fs::write(&original, b"native identity").unwrap();
        create_hard_link(&link, &original).unwrap();

        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let original_handle = open_existing(&original, FILE_GENERIC_READ, share, false).unwrap();
        let link_handle = open_existing(&link, FILE_GENERIC_READ, share, false).unwrap();
        let original_metadata = metadata(&original_handle).unwrap();
        let link_metadata = metadata(&link_handle).unwrap();

        assert_eq!(original_metadata.key, link_metadata.key);
        assert!(original_metadata.creation_time >= 0);
        assert!(original_metadata.last_access_time >= 0);
        assert!(original_metadata.last_write_time >= 0);
        assert!(original_metadata.change_time >= 0);
        assert!(original_metadata.allocation_size >= original_metadata.file_size);
        assert_eq!(original_metadata.file_size, 15);
        assert!(original_metadata.link_count >= 2);
        assert!(!original_metadata.is_directory);
        assert_ne!(original_metadata.attributes, u32::MAX);
    }

    #[test]
    fn volume_geometry_asserts_the_required_fixed_ntfs_environment() {
        let temp = OwnedTempDir::new().unwrap();
        let geometry = volume_geometry(temp.path()).unwrap();

        assert_eq!(geometry.root, PathBuf::from(r"D:\"));
        assert_eq!(geometry.filesystem_name.to_string_lossy(), "NTFS");
        assert_eq!(
            geometry.drive_type, DRIVE_FIXED,
            "D: must remain a fixed drive"
        );
        assert_ne!(geometry.volume_serial, 0);
        assert!(geometry.total_allocation_units > 0);
        assert!(geometry.available_allocation_units <= geometry.total_allocation_units);
        assert!(geometry.sectors_per_allocation_unit > 0);
        assert!(geometry.bytes_per_sector > 0);
    }

    #[test]
    fn security_query_returns_a_self_relative_valid_descriptor() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("secured.txt");
        fs::write(&path, b"secured").unwrap();

        let descriptor = query_security(
            &path,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        )
        .unwrap();

        assert!((20..=65_536).contains(&descriptor.len()));
        assert_eq!(descriptor[0], 1, "SECURITY_DESCRIPTOR_REVISION");
        let control = u16::from_le_bytes([descriptor[2], descriptor[3]]);
        assert_ne!(control & 0x8000, 0, "SE_SELF_RELATIVE must be set");

        set_security(&path, DACL_SECURITY_INFORMATION, &descriptor).unwrap();
    }

    #[test]
    fn invalid_security_descriptor_error_does_not_use_stale_last_error() {
        let _ = attributes(Path::new(
            r"D:\winfsr-task6-definitely-missing-last-error-primer",
        ));

        let mut descriptor = [0_u8; 28];
        descriptor[0] = 1;
        descriptor[2..4].copy_from_slice(&0x8000_u16.to_le_bytes());
        descriptor[4..8].copy_from_slice(&20_u32.to_le_bytes());
        // The structural preflight deliberately permits this bounded SID,
        // while IsValidSecurityDescriptor rejects its zero revision.
        descriptor[20] = 0;
        descriptor[21] = 0;

        let error = ValidatedDescriptor::new(&descriptor, io::ErrorKind::InvalidInput)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.raw_os_error(), None);
        assert_eq!(error.to_string(), "invalid security descriptor");
    }

    #[test]
    fn invariant_uppercase_is_case_insensitive_for_non_ascii_names() {
        let lower: Vec<u16> = "ångström.txt".encode_utf16().collect();
        let upper: Vec<u16> = "ÅNGSTRÖM.TXT".encode_utf16().collect();

        assert_eq!(
            uppercase_invariant(&lower).unwrap(),
            uppercase_invariant(&upper).unwrap()
        );
    }

    #[test]
    fn path_wrappers_reject_interior_nul_without_calling_win32() {
        let units = [
            u16::from(b'D'),
            u16::from(b':'),
            u16::from(b'\\'),
            u16::from(b'a'),
            0,
            u16::from(b'b'),
        ];
        let path = PathBuf::from(OsString::from_wide(&units));

        let error = open_existing(&path, FILE_GENERIC_READ, FILE_SHARE_READ, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn create_and_mutation_wrappers_apply_real_owned_object_effects() {
        let temp = OwnedTempDir::new().unwrap();
        let directory = temp.path().join("created-dir");
        create_directory(&directory, None).unwrap();
        assert!(directory.is_dir());

        let source = directory.join("created.txt");
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let (mut handle, existed) = create_file(
            &source,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            share,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap();
        assert!(!existed);
        handle.write_all(b"data").unwrap();

        set_allocation_size(&handle, 4096).unwrap();
        let after_allocation = metadata(&handle).unwrap();
        assert!(after_allocation.allocation_size >= 4096);
        assert_eq!(after_allocation.file_size, 4);

        let change_time = after_allocation.change_time;
        set_basic_info(
            &handle,
            &source,
            NativeBasicInfoUpdate {
                change_time: Some(change_time),
                ..NativeBasicInfoUpdate::default()
            },
        )
        .unwrap();
        set_attributes(&source, FILE_ATTRIBUTE_HIDDEN).unwrap();
        assert_ne!(
            super::attributes(&source).unwrap() & FILE_ATTRIBUTE_HIDDEN,
            0
        );

        let destination = directory.join("moved.txt");
        drop(handle);
        move_file(&source, &destination, false).unwrap();
        assert!(!source.exists());
        assert!(destination.exists());

        let handle = open_existing(
            &destination,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            share,
            false,
        )
        .unwrap();
        let privilege_outcome = set_valid_data_length(&handle, 4);
        if let Err(error) = privilege_outcome {
            assert!(matches!(error.raw_os_error(), Some(5) | Some(1314)));
        }

        let (_, existed) = create_file(
            &destination,
            FILE_GENERIC_READ,
            share,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap();
        assert!(existed);
    }

    #[test]
    fn create_always_reports_new_and_existing_real_files() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("create-always.txt");
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        let (handle, existed) = create_file(
            &path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            share,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap();
        assert!(!existed);
        drop(handle);

        fs::write(&path, b"existing contents").unwrap();
        let (handle, existed) = create_file(
            &path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            share,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap();
        assert!(existed);
        assert_eq!(metadata(&handle).unwrap().file_size, 0);
    }

    #[test]
    fn open_always_reports_new_and_existing_real_files() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("open-always.txt");
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        let (mut handle, existed) = create_file(
            &path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            share,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap();
        assert!(!existed);
        handle.write_all(b"preserved contents").unwrap();
        drop(handle);

        let (handle, existed) = create_file(
            &path,
            FILE_GENERIC_READ,
            share,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .unwrap();
        assert!(existed);
        assert_eq!(metadata(&handle).unwrap().file_size, 18);
        drop(handle);
        assert_eq!(fs::read(&path).unwrap(), b"preserved contents");
    }

    #[test]
    fn combined_basic_info_update_preserves_every_requested_final_value() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("combined-basic-info.txt");
        fs::write(&path, b"metadata").unwrap();
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let handle =
            open_existing(&path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, share, false).unwrap();
        let before = metadata(&handle).unwrap();
        assert_eq!(before.attributes & FILE_ATTRIBUTE_HIDDEN, 0);

        let requested = NativeBasicInfoUpdate {
            creation_time: Some(132_000_000_000_000_000),
            last_access_time: Some(132_000_001_000_000_000),
            last_write_time: Some(132_000_002_000_000_000),
            change_time: Some(132_000_003_000_000_000),
            attributes: Some(before.attributes | FILE_ATTRIBUTE_HIDDEN),
        };
        set_basic_info(&handle, &path, requested).unwrap();

        let after = metadata(&handle).unwrap();
        assert_eq!(after.creation_time, requested.creation_time.unwrap());
        assert_eq!(after.last_access_time, requested.last_access_time.unwrap());
        assert_eq!(after.last_write_time, requested.last_write_time.unwrap());
        assert_eq!(after.change_time, requested.change_time.unwrap());
        assert_eq!(after.attributes, requested.attributes.unwrap());
    }

    #[test]
    fn basic_info_errors_distinguish_no_effect_from_an_earlier_native_effect() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("basic-info-effects.txt");
        fs::write(&path, b"metadata").unwrap();
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let handle = open_existing(&path, FILE_GENERIC_READ, share, false).unwrap();
        let before = metadata(&handle).unwrap();
        assert_eq!(before.attributes & FILE_ATTRIBUTE_HIDDEN, 0);

        let no_effect = set_basic_info(
            &handle,
            &path,
            NativeBasicInfoUpdate {
                creation_time: Some(before.creation_time),
                ..NativeBasicInfoUpdate::default()
            },
        )
        .unwrap_err();
        assert!(!no_effect.effect_applied());
        assert_eq!(no_effect.source_io().raw_os_error(), Some(5));
        assert!(no_effect.source().is_some());

        let post_effect = set_basic_info(
            &handle,
            &path,
            NativeBasicInfoUpdate {
                creation_time: Some(before.creation_time),
                attributes: Some(before.attributes | FILE_ATTRIBUTE_HIDDEN),
                ..NativeBasicInfoUpdate::default()
            },
        )
        .unwrap_err();
        assert!(post_effect.effect_applied());
        assert_eq!(post_effect.source_io().raw_os_error(), Some(5));
        assert!(post_effect
            .to_string()
            .contains("after an earlier native effect"));
        assert_ne!(super::attributes(&path).unwrap() & FILE_ATTRIBUTE_HIDDEN, 0);
    }

    #[test]
    fn size_wrappers_reject_values_above_the_native_signed_range() {
        let temp = OwnedTempDir::new().unwrap();
        let path = temp.path().join("sizes.txt");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"size").unwrap();
        drop(file);
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let handle =
            open_existing(&path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, share, false).unwrap();

        let allocation_error = set_allocation_size(&handle, i64::MAX as u64 + 1).unwrap_err();
        assert_eq!(allocation_error.kind(), io::ErrorKind::InvalidInput);
        let vdl_error = set_valid_data_length(&handle, i64::MAX as u64 + 1).unwrap_err();
        assert_eq!(vdl_error.kind(), io::ErrorKind::InvalidInput);
    }
}
