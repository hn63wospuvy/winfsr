//! The separate named filesystem-registration control device.
//!
//! Design section 6.5: `IoRegisterFileSystem` requires a named
//! `FILE_DEVICE_DISK_FILE_SYSTEM` device, which the provider control endpoint
//! (`\Device\FsRing`, `FILE_DEVICE_UNKNOWN`) cannot also be. This module owns
//! that second role and nothing else; it never carries a DOS link.

use fsring_core::adapter::ascii_utf16_name;
use fsring_core::volume::DeviceKind;
use wdk_sys::{
    BOOLEAN, DO_DEVICE_INITIALIZING, DRIVER_OBJECT, FILE_DEVICE_DISK_FILE_SYSTEM,
    FILE_DEVICE_SECURE_OPEN, GUID, NTSTATUS, PDEVICE_OBJECT, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER, ULONG,
};

use crate::driver::{DispatchReadyRoot, ExtensionHeader};

/// `\FileSystem\FsRing`.
const FSCONTROL_DEVICE_NAME: [u16; 18] = ascii_utf16_name("\\FileSystem\\FsRing");

/// The exact SDDL both named C4 roles are created with.
/// NUL-terminated on purpose: this is the `DefaultSDDLString` convention,
/// not the counted Object Manager name convention beside it.
const FSCONTROL_SDDL: [u16; 28] = ascii_utf16_name("D:P(A;;GA;;;SY)(A;;GA;;;BA)\0");

/// `{201DC259-6F66-4682-A3CD-04CCEBE3D8B2}`: the filesystem-control role class.
/// A static security-class selector, not a per-volume identity and not a wire
/// field.
const FSCONTROL_CLASS_GUID: GUID = GUID {
    Data1: 0x201D_C259,
    Data2: 0x6F66,
    Data3: 0x4682,
    Data4: [0xA3, 0xCD, 0x04, 0xCC, 0xEB, 0xE3, 0xD8, 0xB2],
};

/// The filesystem-control device extension.
#[repr(C)]
pub(crate) struct FsControlExtension {
    pub(crate) header: ExtensionHeader,
}

const EXTENSION_SIZE: ULONG = core::mem::size_of::<FsControlExtension>() as ULONG;
const _: () = assert!(
    core::mem::size_of::<FsControlExtension>() <= ULONG::MAX as usize,
    "the filesystem-control extension must fit the WDM ULONG size"
);

/// Create the named secure filesystem-control device.
///
/// The device stays `DO_DEVICE_INITIALIZING` until its dispatch table and
/// extension are complete, which is what makes a later `IoRegisterFileSystem`
/// safe.
///
/// # Safety
/// Must run once at PASSIVE_LEVEL during load, with `driver` the loader-owned
/// driver object and `root` the sealed ready authority for the initialized
/// driver root.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn create(
    driver: &mut DRIVER_OBJECT,
    root: &DispatchReadyRoot,
) -> Result<PDEVICE_OBJECT, NTSTATUS> {
    let state = root.endpoint_state();
    let mut name_units = FSCONTROL_DEVICE_NAME;
    let mut sddl_units = FSCONTROL_SDDL;
    let Some(mut name) = crate::kernel::counted_unicode_units(&mut name_units) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let Some(sddl) = crate::kernel::counted_unicode_sz(&mut sddl_units) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let class_guid = FSCONTROL_CLASS_GUID;
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();

    // SAFETY: every descriptor borrows a local for this synchronous
    // PASSIVE_LEVEL call, and the out pointer is writable for one device.
    let status = unsafe {
        crate::kernel::create_secure_device(
            driver,
            EXTENSION_SIZE,
            &raw mut name,
            FILE_DEVICE_DISK_FILE_SYSTEM,
            FILE_DEVICE_SECURE_OPEN,
            0 as BOOLEAN,
            &raw const sddl,
            &raw const class_guid,
            &raw mut device,
        )
    };
    if status < 0 {
        return Err(status);
    }
    if device.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }

    // SAFETY: a nonzero extension size was requested, so successful creation
    // owns exactly this storage until the device is deleted.
    let extension = unsafe { (*device).DeviceExtension.cast::<FsControlExtension>() };
    if extension.is_null() {
        // SAFETY: the device was created and is deleted exactly once here.
        unsafe { crate::kernel::delete_device(device) };
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: uninitialized storage of the exact requested size, written once
    // while the device is still initializing and therefore unreachable.
    unsafe {
        core::ptr::write(
            extension,
            FsControlExtension {
                header: ExtensionHeader {
                    kind: DeviceKind::FileSystemControl as u32,
                    state,
                },
            },
        );
    }
    Ok(device)
}

/// Clear `DO_DEVICE_INITIALIZING`. Only after both dispatch tables are complete.
///
/// # Safety
/// `device` must be this driver's filesystem-control device.
pub(crate) unsafe fn publish(device: PDEVICE_OBJECT) {
    // SAFETY: the caller's device contract; this is the single publication
    // store for the role.
    unsafe {
        (*device).Flags &= !DO_DEVICE_INITIALIZING;
    }
}

/// Make the device un-openable again during a failed load's unwind.
///
/// # Safety
/// As [`publish`].
pub(crate) unsafe fn unpublish(device: PDEVICE_OBJECT) {
    // SAFETY: the caller's device contract.
    unsafe {
        (*device).Flags |= DO_DEVICE_INITIALIZING;
    }
}

/// Register the device with the I/O manager's filesystem list.
///
/// # Safety
/// `device` must be published and its dispatch table complete.
pub(crate) unsafe fn register(device: PDEVICE_OBJECT) {
    // SAFETY: the caller's contract; the DDI returns no status.
    unsafe { fsring_sys::c4::IoRegisterFileSystem(device) };
}

/// Remove the device from the filesystem list.
///
/// # Safety
/// `device` must currently be registered.
pub(crate) unsafe fn unregister(device: PDEVICE_OBJECT) {
    // SAFETY: the caller's contract; the DDI returns no status.
    unsafe { fsring_sys::c4::IoUnregisterFileSystem(device) };
}
