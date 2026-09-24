//! Typed Rust adapters for the C exception boundary around mapping DDIs.

use core::ptr::NonNull;

pub use fsring_core::mapping::MappingResourceError;

const KERNEL_MODE: fsring_sys::KPROCESSOR_MODE = 0;
const USER_MODE: fsring_sys::KPROCESSOR_MODE = 1;
const MM_CACHED: fsring_sys::MEMORY_CACHING_TYPE = 1;

/// The two probe operations the C4 design permits. `IoWriteAccess` is
/// intentionally unrepresentable: writable aliases require modify access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeAccess {
    Read,
    Modify,
}

impl ProbeAccess {
    const fn raw(self) -> fsring_sys::LOCK_OPERATION {
        match self {
            Self::Read => fsring_sys::c4::IoReadAccess,
            Self::Modify => fsring_sys::c4::IoModifyAccess,
        }
    }
}

/// Probe and lock one valid MDL without allowing a structured exception to
/// cross into Rust.
///
/// # Safety
/// `mdl` must designate a live MDL whose pages are not already locked, and the
/// caller must satisfy `MmProbeAndLockPages`' IRQL and lifetime requirements.
pub unsafe fn probe_and_lock_pages(
    mdl: NonNull<fsring_sys::MDL>,
    access: ProbeAccess,
) -> Result<(), MappingResourceError> {
    // SAFETY: the caller supplies the MDL state/lifetime contract. The C shim
    // contains every structured exception and returns an NTSTATUS instead.
    let status =
        unsafe { fsring_sys::FsRingProbeAndLockPagesSeh(mdl.as_ptr(), KERNEL_MODE, access.raw()) };
    fsring_core::mapping::normalize_probe_status(status)
}

/// Map a locked MDL into the current user process with a non-executable,
/// non-bugchecking cached mapping policy encoded in `flags`.
///
/// # Safety
/// `mdl` must designate a live locked MDL. The caller must be attached to the
/// intended process, keep the MDL live through unmapping, and pass the
/// profile/direction-specific closed mapping flags.
pub unsafe fn map_locked_pages(
    mdl: NonNull<fsring_sys::MDL>,
    flags: fsring_core::mapping::MappingFlags,
) -> Result<NonNull<core::ffi::c_void>, MappingResourceError> {
    let mut status: fsring_sys::NTSTATUS = i32::MIN;
    // SAFETY: the caller supplies the locked-MDL and process-attachment
    // contract. UserMode, MmCached, null requested address and FALSE bugcheck
    // policy are fixed here; the C shim contains every structured exception.
    let address = unsafe {
        fsring_sys::FsRingMapLockedPagesSeh(
            mdl.as_ptr(),
            USER_MODE,
            MM_CACHED,
            core::ptr::null_mut(),
            0,
            flags.raw(),
            &raw mut status,
        )
    };
    fsring_core::mapping::normalize_mapping_result(status, address)
}
