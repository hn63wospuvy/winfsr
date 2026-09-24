//! The per-mount named virtual-disk device object.
//!
//! Design section 6.5 gives every active `MountId` one named
//! `FILE_DEVICE_VIRTUAL_DISK` VDO, created by SETUP so the I/O manager supplies
//! its VPB. This module owns that role's name derivation, its exact security,
//! and its staging lifetime; the mount, verify, and dismount transitions that
//! run against it belong to the volume slice.
//!
//! The VDO stays `DO_DEVICE_INITIALIZING` for the whole of SETUP. That is not
//! bookkeeping: a VDO that became openable before the session published would
//! expose a volume whose backing section, grants, and aliases might still be
//! rolled back.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

use fsring_abi::MountId;
use fsring_abi::validate::SessionIdentity;
use fsring_core::adapter::ascii_utf16_name;
use fsring_core::adapter::volume::{self as adapter, RetainedAccessGuard};
use fsring_core::session::{SessionLocator, StrongSessionRef};
use fsring_core::volume::{
    DeviceKind, MountEffect, MountRevalidation, MountRollbackEffect, VerifyDecision,
    VolumeDispatchDecision, VolumeState, begin_mount, decide_volume_dispatch,
};
use wdk_sys::{
    BOOLEAN, DO_DEVICE_INITIALIZING, DRIVER_OBJECT, FILE_DEVICE_SECURE_OPEN,
    FILE_DEVICE_VIRTUAL_DISK, GUID, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS, ULONG,
};

/// STATUS_VOLUME_DISMOUNTED, the normative answer to a verify after teardown.
const STATUS_VOLUME_DISMOUNTED: NTSTATUS = 0xC000_026Eu32 as NTSTATUS;

use crate::driver::{DriverState, ExtensionHeader};

/// The exact SDDL both named C4 roles are created with.
/// NUL-terminated on purpose: this is the `DefaultSDDLString` convention,
/// not the counted Object Manager name convention beside it.
const VOLUME_SDDL: [u16; 28] = ascii_utf16_name("D:P(A;;GA;;;SY)(A;;GA;;;BA)\0");

/// `{92AC3ED3-4505-42D5-A81C-901212229852}`: the per-mount VDO role class.
///
/// One static selector shared by every VDO. It is a security class, not a
/// per-volume identity, and it is deliberately distinct from both the
/// provider-control and filesystem-control class GUIDs.
const VOLUME_CLASS_GUID: GUID = GUID {
    Data1: 0x92AC_3ED3,
    Data2: 0x4505,
    Data3: 0x42D5,
    Data4: [0xA8, 0x1C, 0x90, 0x12, 0x12, 0x22, 0x98, 0x52],
};

/// `\Device\FsRingVolume-` — the fixed prefix of every VDO name.
const VOLUME_NAME_PREFIX: [u16; 21] = ascii_utf16_name("\\Device\\FsRingVolume-");

/// `\Device\FsRingVolume-<lo:016X>-<hi:016X>`: 21 prefix units, 16 hex digits,
/// one separator, 16 hex digits.
pub(crate) const VOLUME_NAME_UNITS: usize = 54;

const _: () = assert!(
    VOLUME_NAME_UNITS == VOLUME_NAME_PREFIX.len() + 16 + 1 + 16,
    "the VDO name is exactly its prefix plus two 16-digit words and a separator"
);

/// The per-mount VDO extension.
#[repr(C)]
pub(crate) struct VolumeExtension {
    pub(crate) header: ExtensionHeader,
    /// The session this VDO belongs to, as a locator that must be re-resolved.
    ///
    /// A VDO is created before `InstallStaging` has chosen a locator, so this
    /// is uninitialized while `DO_DEVICE_INITIALIZING` is set — the window in
    /// which nothing can open the device. The locked publication suffix writes
    /// the exact locator and only then clears the flag, and a failed SETUP
    /// deletes the still-initializing device without ever reading it.
    locator: UnsafeCell<MaybeUninit<SessionLocator>>,
    locator_state: AtomicU32,
    pub(crate) mount_lo: u64,
    pub(crate) mount_hi: u64,
}

/// Whether a VDO's locator field has been written.
///
/// A bare `MaybeUninit` cannot answer that question, and a null-pointer
/// sentinel is exactly the raw-address authority this task removes.
///
/// The state is an `AtomicU32` because it is the *publication* word for the
/// locator beside it: the writer stores it with Release after the locator
/// bytes, and every reader loads it with Acquire before reading them. Plain
/// stores leave the two writes unordered against each other on a weakly
/// ordered target, and this driver ships an ARM64 image -- a reader could then
/// observe `INITIALIZED` while `locator` still held the uninitialized pool
/// bytes `create_staging` left there.
const VDO_LOCATOR_INITIALIZING: u32 = 0x5644_0001;
const VDO_LOCATOR_INITIALIZED: u32 = 0x5644_0002;

impl VolumeExtension {
    /// The locator this VDO names, once publication has written it.
    ///
    /// # Safety
    /// `extension` must be the extension of a VDO this driver created.
    pub(crate) unsafe fn locator_of(extension: *const Self) -> Option<SessionLocator> {
        if extension.is_null() {
            return None;
        }
        // SAFETY: the caller's contract; the extension outlives the device.
        //
        // Acquire pairs with the Release store in `publish_locator`: observing
        // `INITIALIZED` here therefore also observes the locator bytes written
        // before it.
        let state = unsafe { (*extension).locator_state.load(Ordering::Acquire) };
        if state != VDO_LOCATOR_INITIALIZED {
            return None;
        }
        // SAFETY: the Acquire load proves the initializing store happened
        // before this read, and the field is never written again.
        Some(unsafe { (*(*extension).locator.get()).assume_init() })
    }

    /// Write the exact locator into a still-initializing VDO.
    ///
    /// This is the locked publication suffix's step, and the only writer. It
    /// refuses a device that has already left `DO_DEVICE_INITIALIZING` or whose
    /// locator was already written, so the ordering the suffix proves cannot be
    /// bypassed by a second caller.
    ///
    /// # Safety
    /// `device` must be a VDO this driver created, still initializing, and the
    /// caller must hold the registry lock of the publication suffix.
    pub(crate) unsafe fn publish_locator(
        device: PDEVICE_OBJECT,
        locator: SessionLocator,
    ) -> Result<(), NTSTATUS> {
        if device.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SAFETY: the caller's device contract.
        let initializing = unsafe { (*device).Flags & DO_DEVICE_INITIALIZING } != 0;
        if !initializing {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        // SAFETY: a nonzero extension size was requested at creation.
        let extension = unsafe { (*device).DeviceExtension.cast::<Self>() };
        if extension.is_null() {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        // SAFETY: as above; the fields are this driver's own storage, and the
        // device is still initializing so no reader exists yet.
        unsafe {
            if (*extension).locator_state.load(Ordering::Acquire) != VDO_LOCATOR_INITIALIZING {
                return Err(STATUS_INVALID_DEVICE_STATE);
            }
            (*(*extension).locator.get()).write(locator);
            // Release: everything written above is visible to anything that
            // observes this store, and the caller clears
            // `DO_DEVICE_INITIALIZING` only after this returns.
            (*extension)
                .locator_state
                .store(VDO_LOCATOR_INITIALIZED, Ordering::Release);
        }
        Ok(())
    }
}

const EXTENSION_SIZE: ULONG = core::mem::size_of::<VolumeExtension>() as ULONG;
const _: () = assert!(
    core::mem::size_of::<VolumeExtension>() <= ULONG::MAX as usize,
    "the volume extension must fit the WDM ULONG size"
);

/// Uppercase hex digits, indexed by nibble.
const HEX: [u8; 16] = *b"0123456789ABCDEF";

/// Write one 64-bit word as exactly sixteen uppercase hex code units.
///
/// Returns the new cursor, or `None` if the buffer is too short — which is a
/// build error the compile-time length assertion above already excludes, but
/// the runtime path still refuses rather than truncating a device name.
fn write_hex64(buffer: &mut [u16], mut cursor: usize, value: u64) -> Option<usize> {
    let mut shift = 60i32;
    while shift >= 0 {
        let nibble = value
            .checked_shr(u32::try_from(shift).ok()?)
            .unwrap_or(0)
            .checked_rem(16)?;
        let digit = *HEX.get(usize::try_from(nibble).ok()?)?;
        *buffer.get_mut(cursor)? = u16::from(digit);
        cursor = cursor.checked_add(1)?;
        shift = shift.checked_sub(4)?;
    }
    Some(cursor)
}

/// Derive the deterministic native VDO name for one burned `MountId`.
///
/// The name is *routing*, not authentication: it discloses nothing the daemon
/// did not already receive in its own session result, and the SDDL above is
/// what actually restricts the object.
pub(crate) fn volume_name(mount_id: MountId) -> Option<[u16; VOLUME_NAME_UNITS]> {
    let mut units = [0u16; VOLUME_NAME_UNITS];
    let mut cursor = 0usize;
    for unit in VOLUME_NAME_PREFIX {
        *units.get_mut(cursor)? = unit;
        cursor = cursor.checked_add(1)?;
    }
    cursor = write_hex64(&mut units, cursor, mount_id.lo)?;
    *units.get_mut(cursor)? = u16::from(b'-');
    cursor = cursor.checked_add(1)?;
    cursor = write_hex64(&mut units, cursor, mount_id.hi)?;
    if cursor != VOLUME_NAME_UNITS {
        return None;
    }
    Some(units)
}

/// Create one secure per-mount VDO, still initializing.
///
/// # Safety
/// Must run at PASSIVE_LEVEL on a SETUP thread, with `driver` the loader-owned
/// driver object and `state` the live root. The VDO carries no session
/// authority yet: `InstallStaging` has not chosen a locator, and the locked
/// publication suffix is what writes one.
pub(crate) unsafe fn create_staging(
    driver: &mut DRIVER_OBJECT,
    state: *mut DriverState,
    mount_id: MountId,
) -> Result<PDEVICE_OBJECT, NTSTATUS> {
    let Some(mut name_units) = volume_name(mount_id) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let mut sddl_units = VOLUME_SDDL;
    let Some(mut name) = crate::kernel::counted_unicode_units(&mut name_units) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let Some(sddl) = crate::kernel::counted_unicode_sz(&mut sddl_units) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let class_guid = VOLUME_CLASS_GUID;
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();

    // SAFETY: every descriptor borrows a local for this synchronous
    // PASSIVE_LEVEL call, and the out pointer is writable for one device.
    let status = unsafe {
        crate::kernel::create_secure_device(
            driver,
            EXTENSION_SIZE,
            &raw mut name,
            FILE_DEVICE_VIRTUAL_DISK,
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
    let extension = unsafe { (*device).DeviceExtension.cast::<VolumeExtension>() };
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
            VolumeExtension {
                header: ExtensionHeader {
                    kind: DeviceKind::VirtualDisk as u32,
                    state,
                },
                locator: UnsafeCell::new(MaybeUninit::uninit()),
                locator_state: AtomicU32::new(VDO_LOCATOR_INITIALIZING),
                mount_lo: mount_id.lo,
                mount_hi: mount_id.hi,
            },
        );
    }
    Ok(device)
}

/// Clear `DO_DEVICE_INITIALIZING` once the session is published.
///
/// # Safety
/// `device` must be a VDO this driver created, and the session it belongs to
/// must already be reachable.
pub(crate) unsafe fn clear_initializing(device: PDEVICE_OBJECT) {
    if device.is_null() {
        return;
    }
    // SAFETY: the caller's device contract; the single publication store.
    unsafe {
        (*device).Flags &= !DO_DEVICE_INITIALIZING;
    }
}

/// Delete one VDO during a failed SETUP's unwind or a session fence.
///
/// # Safety
/// `device` must be a VDO this driver created and has not already deleted, and
/// this must run at APC_LEVEL or lower.
pub(crate) unsafe fn delete(device: PDEVICE_OBJECT) {
    if device.is_null() {
        return;
    }
    // SAFETY: the caller's device contract; deleted exactly once.
    unsafe { crate::kernel::delete_device(device) };
}

// ---------------------------------------------------------------------------
// The mounted-volume role
// ---------------------------------------------------------------------------

/// `VPB_MOUNTED`, `wdm.h`.
const VPB_MOUNTED: u16 = 0x0001;

/// The volume control block.
///
/// C4 owns the binding, not yet the namespace: the VCB carries the identity the
/// verify path compares and the lifecycle state the fence advances, and nothing
/// a filesystem operation would need. Growing it belongs to the slice that adds
/// those operations.
#[repr(C)]
pub(crate) struct VolumeControlBlock {
    pub(crate) identity: SessionIdentity,
    pub(crate) state: AtomicU32,
}

/// `VolumeState` as the raw discriminants the VCB stores.
const VCB_MOUNTED: u32 = 3;
const VCB_TEARDOWN: u32 = 4;

fn vcb_state(raw: u32) -> VolumeState {
    match raw {
        VCB_MOUNTED => VolumeState::Mounted,
        VCB_TEARDOWN => VolumeState::Teardown,
        _ => VolumeState::Destroyed,
    }
}

/// The unnamed mounted-volume device extension.
#[repr(C)]
pub(crate) struct MountedVolumeExtension {
    pub(crate) header: ExtensionHeader,
    /// The session this mounted volume belongs to, as a locator.
    ///
    /// Written at mount and, in this tranche, read by nothing: the mounted
    /// volume's own dispatches answer from the VCB beside it. It replaces the
    /// predecessor's stored session pointer so the field cannot become one
    /// again, and the mounted-volume operations that will re-resolve it arrive
    /// with the slices that add them.
    pub(crate) locator: SessionLocator,
    pub(crate) vdo: PDEVICE_OBJECT,
    /// Inline storage allocated with the device object. `AllocateVcb`
    /// projects this storage into an affine right; only
    /// `InitializeDeviceAndVcb` may consume that right and initialize it.
    pub(crate) vcb: MaybeUninit<VolumeControlBlock>,
}

const MOUNTED_EXTENSION_SIZE: ULONG = core::mem::size_of::<MountedVolumeExtension>() as ULONG;
const _: () = assert!(
    core::mem::size_of::<MountedVolumeExtension>() <= ULONG::MAX as usize,
    "the mounted-volume extension must fit the WDM ULONG size"
);

/// The one uninitialized inline VCB allocation owned by an in-flight mount.
///
/// `IoCreateDevice` allocates the extension bytes together with the device, so
/// allocating the VCB is necessarily a typed projection rather than a second
/// pool allocation. Keeping the projection affine makes `AllocateVcb` a real
/// operation: initialization, rollback, and publication cannot bypass it.
struct NativeVcbStorage {
    extension: NonNull<MountedVolumeExtension>,
}

impl NativeVcbStorage {
    /// Project the exact mounted device's inline VCB storage.
    ///
    /// # Safety
    /// `device` is a newly created, still-initializing mounted-volume device
    /// owned by this mount.
    unsafe fn allocate(device: PDEVICE_OBJECT) -> Option<Self> {
        let extension =
            NonNull::new(unsafe { (*device).DeviceExtension.cast::<MountedVolumeExtension>() })?;
        Some(Self { extension })
    }

    /// Initialize the allocation exactly once and return its publication
    /// owner.
    ///
    /// # Safety
    /// The device remains initializing and unreachable.
    unsafe fn initialize(self, identity: SessionIdentity) -> NativeInitializedVcb {
        unsafe {
            (*self.extension.as_ptr()).vcb.write(VolumeControlBlock {
                identity,
                state: AtomicU32::new(VCB_MOUNTED),
            });
        }
        NativeInitializedVcb {
            extension: self.extension,
        }
    }
}

/// An initialized inline VCB that has not yet fused into the mounted-device
/// owner published in the session cell.
struct NativeInitializedVcb {
    extension: NonNull<MountedVolumeExtension>,
}

impl NativeInitializedVcb {
    fn belongs_to(&self, device: PDEVICE_OBJECT) -> bool {
        !device.is_null()
            && unsafe {
                (*device).DeviceExtension.cast::<MountedVolumeExtension>()
                    == self.extension.as_ptr()
            }
    }

    /// Undo initialization while the containing device is still private.
    ///
    /// # Safety
    /// This marker is the sole initialization owner and the device has not
    /// been published.
    unsafe fn rollback(self) {
        unsafe { (*self.extension.as_ptr()).vcb.assume_init_drop() };
    }
}

/// Everything one in-flight mount owns before the VPB is bound.
struct MountContext<'access, 'registry> {
    vdo: PDEVICE_OBJECT,
    vpb: Option<crate::lifecycle::NativeMountedVpbOwner>,
    mounted: Option<crate::lifecycle::NativeMountedDeviceOwner>,
    vcb_storage: Option<NativeVcbStorage>,
    initialized_vcb: Option<NativeInitializedVcb>,
    publication: Option<crate::lifecycle::NativeMountOwnerPublication>,
    owner_published: bool,
    /// The resolved session, held for the whole mount.
    ///
    /// The guard is retained until the commit or rollback suffix has finished,
    /// so the shell cannot be freed between the checks and the VPB store. It is
    /// deliberately held *across* both VPB lock holds -- that is the point of
    /// retaining it. What must not overlap is the guard's own *registry* lock,
    /// which `resolve` releases before it returns, so no VPB acquire here is
    /// ever nested inside a registry lock hold.
    access: &'access crate::lifecycle::SessionAccessGuard<'registry>,
    locator: SessionLocator,
    state: *mut DriverState,
    identity: SessionIdentity,
    vpb_held: bool,
    vpb_irql: wdk_sys::KIRQL,
    /// The core registry reference this mount holds.
    ///
    /// It is a `StrongSessionRef`, not a driver-root reference. The two were
    /// conflated before: `DriverState::acquire` bumps a root counter that says
    /// nothing about whether this *session* is still Live, so a mount could
    /// hold a "reference" to a generation the registry had already removed.
    reference: Option<StrongSessionRef>,
}

fn mount_vpb(context: &MountContext<'_, '_>) -> Option<*mut wdk_sys::VPB> {
    context.vpb.as_ref().map(|owner| owner.as_ptr())
}

fn mounted_device(context: &MountContext<'_, '_>) -> Option<PDEVICE_OBJECT> {
    context.mounted.as_ref().map(|owner| owner.as_ptr())
}

/// Acquire the VPB spin lock.
///
/// # Safety
/// Must run at DISPATCH_LEVEL or lower, exactly once per matching release.
unsafe fn acquire_vpb(context: &mut MountContext<'_, '_>) -> bool {
    if context.vpb_held {
        return false;
    }
    let mut irql: wdk_sys::KIRQL = 0;
    // SAFETY: the out parameter is a local live across the paired release.
    unsafe { fsring_sys::c4::IoAcquireVpbSpinLock(&raw mut irql) };
    context.vpb_irql = irql;
    context.vpb_held = true;
    true
}

/// The commit revalidation consumes the lock state established by the
/// immediately preceding `AcquireCommitVpb` roster effect. It must not try to
/// acquire that non-reentrant spin lock a second time.
const fn commit_revalidation_has_vpb_lock(vpb_held: bool) -> bool {
    vpb_held
}

/// Release the VPB spin lock.
///
/// # Safety
/// This thread must hold the lock at the recorded IRQL.
unsafe fn release_vpb(context: &mut MountContext<'_, '_>) -> bool {
    if !context.vpb_held {
        return false;
    }
    // SAFETY: the caller's lock contract.
    unsafe { fsring_sys::c4::IoReleaseVpbSpinLock(context.vpb_irql) };
    context.vpb_held = false;
    true
}

/// The retained MOUNT root.
///
/// # Safety
/// The I/O manager supplies a live filesystem-control device and a live
/// `IRP_MN_MOUNT_VOLUME` IRP whose stack names the target VDO and its VPB.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_mount(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    if device.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the filesystem-control extension was written before its device
    // left `DO_DEVICE_INITIALIZING`.
    let state = unsafe { (*device).DeviceExtension.cast::<ExtensionHeader>() };
    if state.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: as above.
    let root = unsafe { (*state).state };
    if root.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: dispatch owns a live IRP whose current stack location satisfies
    // the WDK inline's invariant.
    let stack = unsafe { fsring_sys::io_get_current_irp_stack_location(irp) };
    if stack.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the mount parameters are the active union member of an
    // `IRP_MN_MOUNT_VOLUME` stack location.
    let parameters = unsafe { (*stack).Parameters.MountVolume };
    let target = parameters.DeviceObject;
    let vpb = parameters.Vpb;
    if target.is_null() || vpb.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // The routing preflight, and the ownership question comes first. A device
    // object names the driver that created it, and only that driver knows the
    // layout of the memory behind `DeviceExtension`: reading a tag out of
    // another driver's extension is reading a foreign struct at a guessed
    // offset, and a 4-byte value matching proves nothing about memory this
    // driver does not own. The comparison is between the device this dispatch
    // was invoked on and the mount target -- two different objects, so a
    // rewrite that compares either one with itself is not this check.
    // SAFETY: both pointers are non-null device objects owned by the I/O
    // manager for the duration of this dispatch.
    let own_driver = unsafe { (*device).DriverObject };
    // SAFETY: as above.
    let target_driver = unsafe { (*target).DriverObject };
    if own_driver.is_null() || target_driver != own_driver {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Only now, with the target proved to be one of this driver's own devices,
    // may its extension be projected. It is deliberately not a VPB read - the
    // authoritative one happens under the lock, inside the transaction.
    // SAFETY: every device this driver creates writes its extension header
    // before it leaves `DO_DEVICE_INITIALIZING`.
    let target_extension = unsafe { (*target).DeviceExtension.cast::<ExtensionHeader>() };
    // SAFETY: the projection null-checks the extension itself.
    let routing_target_matches = matches!(
        unsafe { ExtensionHeader::kind_of(target_extension) },
        Some(DeviceKind::VirtualDisk)
    );
    if !routing_target_matches {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the driver-object comparison above proves this device is this
    // driver's own, and the tag then proves it is a VDO rather than one of the
    // driver's other device kinds.
    let volume_extension = unsafe { (*target).DeviceExtension.cast::<VolumeExtension>() };
    // SAFETY: as above; the fields are immutable after publication.
    let (locator, mount_lo, mount_hi) = unsafe {
        (
            VolumeExtension::locator_of(volume_extension.cast_const()),
            (*volume_extension).mount_lo,
            (*volume_extension).mount_hi,
        )
    };
    // A still-initializing VDO carries no locator, so it cannot be mounted.
    let Some(locator) = locator else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    // SAFETY: the root is live for the whole dispatch.
    let registry = unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*root).sessions)) };
    // The locator is re-resolved rather than followed: the VDO records which
    // session it belongs to, and only the registry can say whether that session
    // is still live. The guard is retained for the whole mount.
    // SAFETY: PASSIVE_LEVEL mount thread; `registry` is the live root registry.
    let access = match unsafe { registry.as_ref().resolve(locator) } {
        Ok(access) => access,
        Err(error) => return error.status(),
    };
    let identity = access.view().identity();
    if identity.mount_id.lo != mount_lo || identity.mount_id.hi != mount_hi {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let volume_state = if access.is_published() {
        VolumeState::Active
    } else {
        VolumeState::Teardown
    };

    let Ok(progress) = begin_mount(volume_state, identity, routing_target_matches) else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };

    let Some(vpb_owner) = (unsafe { crate::lifecycle::NativeMountedVpbOwner::from_mount_vpb(vpb) })
    else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    let retained = RetainedAccessGuard::new(access);
    let mut status = STATUS_INVALID_DEVICE_REQUEST;
    retained.run(|access| {
        let mut context = MountContext {
            vdo: target,
            vpb: Some(vpb_owner),
            mounted: None,
            vcb_storage: None,
            initialized_vcb: None,
            publication: None,
            owner_published: false,
            access,
            locator,
            state: root,
            identity,
            vpb_held: false,
            vpb_irql: 0,
            reference: None,
        };
        // SAFETY: PASSIVE_LEVEL mount thread; the context owns everything the
        // transaction acquires. `run` retains the access guard through either
        // the commit or rollback suffix.
        status = unsafe {
            drive_mount(
                &mut context,
                device,
                adapter::NativeVolumePlan::mount(progress),
            )
        };
    });
    status
}

/// Drive the whole mount bridge.
///
/// # Safety
/// PASSIVE_LEVEL, once per MOUNT IRP, with `context` owning nothing yet.
unsafe fn drive_mount(
    context: &mut MountContext<'_, '_>,
    fscontrol: PDEVICE_OBJECT,
    progress: adapter::VolumeProgress,
) -> NTSTATUS {
    let result = {
        let mut native = NativeMountOps {
            context: &mut *context,
            fscontrol,
        };
        adapter::run_r3_mount(progress, &mut native)
    };
    match result {
        Ok(_) => {
            if !context.owner_published
                || context.publication.is_some()
                || context.reference.is_some()
                || context.mounted.is_some()
                || context.vcb_storage.is_some()
                || context.initialized_vcb.is_some()
                || context.vpb.is_some()
                || context.vpb_held
            {
                unreachable!("mount success requires published ownership and a consumed receipt");
            }
            STATUS_SUCCESS
        }
        Err(adapter::R3MountRunFailure::Native(plan)) => {
            if context.owner_published {
                unreachable!("a published mount effect cannot refuse");
            }
            match plan {
                adapter::VolumeFailurePlan::Mount(rollback) => {
                    // SAFETY: the plan lists only what this mount still owns.
                    unsafe { unwind_mount(context, rollback.effects()) };
                    STATUS_INSUFFICIENT_RESOURCES
                }
                adapter::VolumeFailurePlan::Complete { status, .. } => status,
                adapter::VolumeFailurePlan::ContinueDismount(_) => STATUS_INVALID_DEVICE_REQUEST,
            }
        }
        Err(adapter::R3MountRunFailure::Plan(plan)) => match plan {
            adapter::VolumeFailurePlan::Mount(rollback) => {
                if context.owner_published {
                    unreachable!("a published mount has no rollback transition");
                }
                // SAFETY: the core returned the exact post-effect rollback. In
                // particular, a refused pre-Bind revalidation cannot clear a
                // foreign VPB binding.
                unsafe { unwind_mount(context, rollback.effects()) };
                STATUS_INVALID_DEVICE_REQUEST
            }
            adapter::VolumeFailurePlan::Complete { .. }
            | adapter::VolumeFailurePlan::ContinueDismount(_) => {
                unreachable!("the mount executor returned an invalid typed plan")
            }
        },
        Err(adapter::R3MountRunFailure::Invalid(_)) => {
            unreachable!("the mount executor returned an invalid typed outcome")
        }
    }
}

/// The production implementation of the core's closed R3 mount operation
/// surface. Each method names one native operation; the core runner owns the
/// exhaustive ordering and refusal boundary.
struct NativeMountOps<'context, 'access, 'registry> {
    context: &'context mut MountContext<'access, 'registry>,
    fscontrol: PDEVICE_OBJECT,
}

impl adapter::R3VolumeNativeOps for NativeMountOps<'_, '_, '_> {
    fn acquire_vpb(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::AcquireVpb),
            )
        }
    }

    fn validate_target(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::ValidateTarget),
            )
        }
    }

    fn release_vpb(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::ReleaseVpb),
            )
        }
    }

    fn acquire_session_reference(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::AcquireSessionReference),
            )
        }
    }

    fn create_mounted_device(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::CreateMountedDevice),
            )
        }
    }

    fn allocate_vcb(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::AllocateVcb),
            )
        }
    }

    fn initialize_device_and_vcb(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::InitializeDeviceAndVcb),
            )
        }
    }

    fn revalidate_target_identity_admission_and_binding(
        &mut self,
    ) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(
                    MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
                ),
            )
        }
    }

    fn bind_vpb(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::BindVpb),
            )
        }
    }

    fn set_vpb_mounted(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::Mount(MountEffect::SetVpbMounted),
            )
        }
    }

    fn publish_mount_owner(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::PublishMountOwner,
            )
        }
    }

    fn clear_device_initializing(&mut self) {
        unsafe { expose_published_mount(self.context) };
    }

    fn emit_mount_published(&mut self) -> Option<adapter::VolumeEffectOutcome> {
        unsafe {
            perform_mount(
                self.context,
                self.fscontrol,
                adapter::VolumeEffect::EmitMountPublished,
            )
        }
    }
}

/// Perform exactly one mount effect. `None` is a native failure.
///
/// # Safety
/// PASSIVE_LEVEL, in the transaction's order.
unsafe fn perform_mount(
    context: &mut MountContext<'_, '_>,
    fscontrol: PDEVICE_OBJECT,
    effect: adapter::VolumeEffect,
) -> Option<adapter::VolumeEffectOutcome> {
    if matches!(effect, adapter::VolumeEffect::PublishMountOwner) {
        if context.vpb_held
            || context.publication.is_some()
            || context.owner_published
            || context.vcb_storage.is_some()
        {
            return None;
        }
        let (Some(reference), Some(mounted), Some(vpb), Some(initialized_vcb)) = (
            context.reference.as_ref(),
            context.mounted.as_ref(),
            context.vpb.as_ref(),
            context.initialized_vcb.as_ref(),
        ) else {
            return None;
        };
        if !initialized_vcb.belongs_to(mounted.as_ptr()) {
            return None;
        }
        // The registry publication runs only after the commit VPB lock was
        // released, so these two locks never overlap.
        let registry =
            unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*context.state).sessions)) };
        let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_ptr(context.locator.slot_index()) }) else {
            unsafe { lock.release() };
            return None;
        };
        let prepared = match unsafe {
            (*cell).prepare_mount_install(context.locator, reference, mounted, vpb)
        } {
            Ok(prepared) => prepared,
            Err(_) => {
                unsafe { lock.release() };
                return None;
            }
        };
        let reference = context.reference.take().unwrap_or_else(|| unreachable!());
        let initialized_vcb = context
            .initialized_vcb
            .take()
            .unwrap_or_else(|| unreachable!());
        let mounted = context.mounted.take().unwrap_or_else(|| unreachable!());
        debug_assert!(initialized_vcb.belongs_to(mounted.as_ptr()));
        // Consuming this marker fuses the initialized inline VCB into the
        // mounted-device owner that the locked commit publishes.
        let _ = initialized_vcb;
        let vpb = context.vpb.take().unwrap_or_else(|| unreachable!());
        let publication =
            unsafe { (*cell).commit_prepared_mount_install(prepared, reference, mounted, vpb) };
        unsafe { lock.release() };
        context.publication = Some(publication);
        context.owner_published = true;
        return Some(adapter::VolumeEffectOutcome::Done);
    }

    let adapter::VolumeEffect::Mount(effect) = effect else {
        // Only the evidence effect is not a transaction step.
        if matches!(effect, adapter::VolumeEffect::EmitMountPublished) {
            // SAFETY: the root is live and the mount is published.
            let _ = unsafe {
                crate::trace::emit(
                    &(*context.state).trace,
                    crate::trace::EvidenceEvent::MountPublished,
                    context.identity.boot_instance_id,
                    context.identity.mount_id,
                    context.identity.session_epoch,
                    None,
                )
            };
            return Some(adapter::VolumeEffectOutcome::Done);
        }
        return None;
    };

    match effect {
        // SAFETY: paired with exactly one release below.
        MountEffect::AcquireVpb => {
            unsafe { acquire_vpb(context) }.then_some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::ValidateTarget => {
            if !context.vpb_held {
                return None;
            }
            // SAFETY: the VPB lock is held, so these fields are stable.
            let vpb = mount_vpb(context)?;
            let (real_device, flags) = unsafe { ((*vpb).RealDevice, (*vpb).Flags) };
            // The authoritative check: this VPB must belong to the target VDO
            // and must not already be mounted.
            (real_device == context.vdo && flags & VPB_MOUNTED == 0)
                .then_some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::AcquireSessionReference => {
            // The initial VPB lock is already released at this point in the
            // roster, which is what makes taking the registry lock here legal:
            // the two never overlap.
            // SAFETY: the root outlives every session it admitted.
            let registry = unsafe {
                NonNull::new_unchecked(core::ptr::addr_of_mut!((*context.state).sessions))
            };
            let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
            // SAFETY: the lock is held for this one call.
            let acquired = unsafe { lock.core_mut() }.acquire(context.locator);
            unsafe { lock.release() };
            match acquired {
                Ok(reference) => {
                    context.reference = Some(reference);
                    Some(adapter::VolumeEffectOutcome::Done)
                }
                // A generation that is no longer Live refuses the mount rather
                // than binding a VPB to a session that is being torn down.
                Err(_) => None,
            }
        }
        // SAFETY: this thread holds the lock it acquired above.
        MountEffect::ReleaseVpb => {
            unsafe { release_vpb(context) }.then_some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::CreateMountedDevice => {
            // SAFETY: the filesystem-control device names this driver, and the
            // unnamed mounted device carries no role-class GUID.
            let device = unsafe { create_mounted_device(fscontrol, context) }?;
            context.mounted =
                unsafe { crate::lifecycle::NativeMountedDeviceOwner::from_created(device) };
            if context.mounted.is_none() {
                unsafe { crate::kernel::delete_device(device) };
                return None;
            }
            Some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::AllocateVcb => {
            if context.vcb_storage.is_some() || context.initialized_vcb.is_some() {
                return None;
            }
            let mounted = mounted_device(context)?;
            context.vcb_storage = unsafe { NativeVcbStorage::allocate(mounted) };
            context
                .vcb_storage
                .is_some()
                .then_some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::InitializeDeviceAndVcb => {
            let mounted = mounted_device(context)?;
            let storage = context.vcb_storage.take()?;
            let initialized = unsafe { storage.initialize(context.identity) };
            if !initialized.belongs_to(mounted) {
                unsafe { initialized.rollback() };
                return None;
            }
            // SAFETY: the device is still initializing and unreachable.
            unsafe {
                (*mounted).Flags |= wdk_sys::DO_DIRECT_IO;
                (*mounted).Flags &= !wdk_sys::DO_BUFFERED_IO;
            }
            context.initialized_vcb = Some(initialized);
            Some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::RevalidateTargetIdentityAdmissionAndBinding => {
            // `AcquireCommitVpb` is the immediately preceding roster effect;
            // revalidation runs inside that same lock hold and the later
            // `ReleaseVpb` effect performs the one matching release.
            if !commit_revalidation_has_vpb_lock(context.vpb_held) {
                return None;
            }
            // SAFETY: the VPB lock is held.
            let vpb = mount_vpb(context)?;
            let (real_device, flags) = unsafe { ((*vpb).RealDevice, (*vpb).Flags) };
            // The guard this mount holds keeps the shell alive; this reads the
            // session's own admission word.
            let session_active = context.access.is_published();
            // Global admission is proven by the reference, not re-read from a
            // word beside it. `SessionRegistry::acquire` refuses outright once
            // admission is closed, so holding a `StrongSessionRef` *is* the
            // statement that admission was open when this mount was let in, and
            // the count that reference carries is what keeps the generation
            // alive from then on. Re-reading a driver-global flag here was the
            // predecessor's substitute for that count; it would also mean taking
            // the registry lock underneath the commit VPB lock, which is the
            // exact overlap the roster's `ReleaseInitialVpb`-before-
            // `AcquireSessionReference` order exists to forbid.
            let admission_open = context.reference.is_some();
            Some(adapter::VolumeEffectOutcome::MountRevalidated(
                MountRevalidation {
                    target_identity_matches: real_device == context.vdo,
                    admission_open,
                    binding_unchanged: flags & VPB_MOUNTED == 0,
                    session_active,
                },
            ))
        }
        MountEffect::BindVpb => {
            if !context.vpb_held || context.initialized_vcb.is_none() {
                return None;
            }
            let vpb = mount_vpb(context)?;
            let mounted = mounted_device(context)?;
            // SAFETY: the VPB lock is held and the device is fully built.
            unsafe {
                (*vpb).DeviceObject = mounted;
            }
            Some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::SetVpbMounted => {
            if !context.vpb_held {
                return None;
            }
            let vpb = mount_vpb(context)?;
            // SAFETY: the VPB lock is held; this is the publication store.
            unsafe {
                (*vpb).Flags |= VPB_MOUNTED;
            }
            Some(adapter::VolumeEffectOutcome::Done)
        }
        MountEffect::ClearDeviceInitializing => {
            unreachable!("device exposure uses the infallible affine operation")
        }
        MountEffect::PublishMountOwner => {
            unreachable!("owner publication is a distinct adapter effect")
        }
    }
}

/// Consume the exact publication receipt and expose the mounted device.
///
/// This terminal operation deliberately has no refusal or outcome channel.
/// The commit VPB lock was released before owner publication. The permanent
/// registry lock remains held across the flag clear and `Publishing ->
/// Present` acknowledgement, so terminal teardown cannot take and delete the
/// owner between those two actions.
///
/// # Safety
/// Called once after `PublishMountOwner` accepted for this context.
unsafe fn expose_published_mount(context: &mut MountContext<'_, '_>) {
    let publication = context
        .publication
        .take()
        .unwrap_or_else(|| unreachable!("owner publication must precede device exposure"));
    let registry =
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*context.state).sessions)) };
    let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
    let cell = unsafe {
        lock.cell_ptr(context.locator.slot_index())
            .unwrap_or_else(|| unreachable!("publication retains its permanent cell"))
    };
    let exposed = unsafe { publication.clear_device_initializing((*cell).mount_rendezvous_mut()) };
    unsafe { lock.release() };
    if let Err((_error, returned)) = exposed {
        let _retained = returned;
        unreachable!("the affine receipt must expose its exact publishing owner")
    }
}

/// Create the unnamed mounted-volume device and write its extension.
///
/// # Safety
/// PASSIVE_LEVEL, once per mount.
unsafe fn create_mounted_device(
    fscontrol: PDEVICE_OBJECT,
    context: &MountContext<'_, '_>,
) -> Option<PDEVICE_OBJECT> {
    if fscontrol.is_null() {
        return None;
    }
    // SAFETY: a live device object names its own driver.
    let driver = unsafe { (*fscontrol).DriverObject };
    if driver.is_null() {
        return None;
    }
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();
    // SAFETY: an unnamed device with no SDDL and no role-class GUID, as the
    // design requires of the mounted-volume object.
    let status = unsafe {
        fsring_sys::c4::IoCreateDevice(
            driver,
            MOUNTED_EXTENSION_SIZE,
            core::ptr::null_mut(),
            wdk_sys::FILE_DEVICE_DISK_FILE_SYSTEM,
            0,
            0 as BOOLEAN,
            &raw mut device,
        )
    };
    if status < 0 || device.is_null() {
        return None;
    }
    // SAFETY: a nonzero extension size was requested.
    let extension = unsafe { (*device).DeviceExtension.cast::<MountedVolumeExtension>() };
    if extension.is_null() {
        // SAFETY: created above and deleted exactly once here.
        unsafe { crate::kernel::delete_device(device) };
        return None;
    }
    // SAFETY: uninitialized storage of the exact requested size, written once
    // while the device is still initializing.
    unsafe {
        core::ptr::write(
            extension,
            MountedVolumeExtension {
                header: ExtensionHeader {
                    kind: DeviceKind::MountedVolume as u32,
                    state: context.state,
                },
                locator: context.locator,
                vdo: context.vdo,
                vcb: MaybeUninit::uninit(),
            },
        );
    }
    Some(device)
}

/// Run one reverse-order mount unwind.
///
/// # Safety
/// The effects come from the transaction's own rollback.
unsafe fn unwind_mount(context: &mut MountContext<'_, '_>, effects: &[MountRollbackEffect]) {
    for effect in effects.iter().copied() {
        // SAFETY: each release below is guarded and idempotent.
        unsafe { undo_mount(context, effect) };
    }
    // A rollback that never named the lock must still not leave it held.
    // SAFETY: idempotent.
    unsafe {
        let _ = release_vpb(context);
    }
}

/// # Safety
/// PASSIVE_LEVEL teardown for one effect the transaction selected.
unsafe fn undo_mount(context: &mut MountContext<'_, '_>, effect: MountRollbackEffect) {
    match effect {
        MountRollbackEffect::ClearUnpublishedVpbBinding => {
            let semantics = effect.vpb_clear_semantics();
            let reacquire = semantics.is_some_and(|semantics| semantics.acquire_release_if_unheld);
            let mut acquired_here = false;
            if !context.vpb_held && reacquire {
                // SAFETY: the clear must happen under the lock even when the
                // failed phase no longer holds it.
                acquired_here = unsafe { acquire_vpb(context) };
            }
            if context.vpb_held {
                let Some(vpb) = mount_vpb(context) else {
                    unreachable!("rollback retains the VPB owner until publication");
                };
                // SAFETY: the lock is held, and this binding was never
                // published: clearing it cannot be observed by a mounted user.
                unsafe {
                    (*vpb).DeviceObject = core::ptr::null_mut();
                    (*vpb).Flags &= !VPB_MOUNTED;
                }
            }
            if acquired_here {
                // The compound acquire/clear/release semantics end here, so
                // later device deletion and registry release run outside the
                // VPB lock.
                let released = unsafe { release_vpb(context) };
                debug_assert!(released);
            }
        }
        MountRollbackEffect::FreeVcb => {
            // The allocation itself is inline, but this effect consumes the
            // exact typed storage/initialization right before device deletion.
            let _ = context.vcb_storage.take();
            if let Some(initialized) = context.initialized_vcb.take() {
                unsafe { initialized.rollback() };
            }
        }
        MountRollbackEffect::ReleaseVpbIfHeld => {
            // SAFETY: idempotent; a released lock is a no-op.
            unsafe {
                let _ = release_vpb(context);
            }
        }
        MountRollbackEffect::DeleteMountedDevice => {
            debug_assert!(context.vcb_storage.is_none());
            debug_assert!(context.initialized_vcb.is_none());
            if let Some(device) = context.mounted.take() {
                // SAFETY: this mount created it and deletes it once. It never
                // became reachable, because the initializing flag is cleared
                // only by the terminal effect.
                unsafe { device.delete() };
            }
        }
        MountRollbackEffect::ReleaseSessionReference => {
            if let Some(reference) = context.reference.take() {
                // SAFETY: the root outlives every session it admitted.
                let registry = unsafe {
                    NonNull::new_unchecked(core::ptr::addr_of_mut!((*context.state).sessions))
                };
                let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
                // SAFETY: the lock is held. The live cell's registry lease and
                // control reference make this exact rollback release Retained.
                let released = unsafe {
                    crate::fence::release_strong_and_deposit(
                        &mut lock,
                        crate::fence::R4ReleaseAuthority::Stable(reference),
                        None,
                    )
                };
                unsafe { lock.release() };
                match released {
                    Ok(crate::fence::StrongReleaseDisposition::Retained) => {}
                    Ok(crate::fence::StrongReleaseDisposition::Finalizer(_)) => {
                        unreachable!("a live mount rollback cannot be the final release")
                    }
                    Err((_error, authority, readiness)) => {
                        debug_assert!(readiness.is_none());
                        let crate::fence::R4ReleaseAuthority::Stable(reference) = authority else {
                            unreachable!("mount rollback owns a stable reference")
                        };
                        context.reference = Some(reference);
                        unreachable!("the live rollback release was fully preflighted")
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// The retained VERIFY root.
///
/// # Safety
/// The I/O manager supplies a live filesystem-control device and a live
/// `IRP_MN_VERIFY_VOLUME` IRP.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_verify(
    device: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    if device.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the extension was written before the device was published.
    let header = unsafe { (*device).DeviceExtension.cast::<ExtensionHeader>() };
    if header.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: as above.
    let root = unsafe { (*header).state };
    // SAFETY: dispatch owns a live IRP.
    let stack = unsafe { fsring_sys::io_get_current_irp_stack_location(irp) };
    if stack.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the verify parameters are the active union member of an
    // `IRP_MN_VERIFY_VOLUME` stack location.
    let parameters = unsafe { (*stack).Parameters.VerifyVolume };
    let vpb = parameters.Vpb;
    if vpb.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    let mut progress: Option<SessionIdentity> = None;
    // SAFETY: the VPB spin lock brackets every read of its fields.
    let observation = unsafe { read_verify_under_lock(vpb, &mut progress) };
    let Some(identity) = progress else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };

    let mut plan = adapter::NativeVolumePlan::verify(identity);
    loop {
        match plan {
            adapter::VolumeProgress::Verified(decision) => {
                return match decision {
                    VerifyDecision::Success => STATUS_SUCCESS,
                    // The normative dismounted status; never `VERIFY_REQUIRED`,
                    // and `DO_VERIFY_VOLUME` is never set anywhere.
                    VerifyDecision::VolumeDismounted => STATUS_VOLUME_DISMOUNTED,
                    VerifyDecision::InvalidTarget => STATUS_INVALID_DEVICE_REQUEST,
                };
            }
            adapter::VolumeProgress::Effect(pending) => {
                let outcome = match pending.effect() {
                    adapter::VolumeEffect::ReadVerifyUnderVpbLock => {
                        adapter::VolumeEffectOutcome::VerifyObserved(observation)
                    }
                    adapter::VolumeEffect::EmitVerifySucceeded => {
                        if !root.is_null() {
                            // SAFETY: the root is live and the verify already
                            // committed.
                            let _ = unsafe {
                                crate::trace::emit(
                                    &(*root).trace,
                                    crate::trace::EvidenceEvent::VerifySucceeded,
                                    identity.boot_instance_id,
                                    identity.mount_id,
                                    identity.session_epoch,
                                    None,
                                )
                            };
                        }
                        adapter::VolumeEffectOutcome::Done
                    }
                    _ => return STATUS_INVALID_DEVICE_REQUEST,
                };
                match pending.succeeded(outcome) {
                    Ok(next) => plan = next,
                    Err(_) => return STATUS_INVALID_DEVICE_REQUEST,
                }
            }
            adapter::VolumeProgress::Mounted(_) | adapter::VolumeProgress::Dismounted => {
                return STATUS_INVALID_DEVICE_REQUEST;
            }
        }
    }
}

/// The one locked read a verify performs.
///
/// # Safety
/// `vpb` must be the live VPB the verify names.
unsafe fn read_verify_under_lock(
    vpb: *mut wdk_sys::VPB,
    identity_out: &mut Option<SessionIdentity>,
) -> adapter::VerifyObservation {
    let mut irql: wdk_sys::KIRQL = 0;
    // SAFETY: the out parameter is a local live across the paired release.
    unsafe { fsring_sys::c4::IoAcquireVpbSpinLock(&raw mut irql) };
    // SAFETY: the lock is held, so these fields are stable.
    let (mounted_device, flags) = unsafe { ((*vpb).DeviceObject, (*vpb).Flags) };
    let mut observation = adapter::VerifyObservation {
        state: VolumeState::Destroyed,
        identity_matches: false,
    };
    if !mounted_device.is_null() && flags & VPB_MOUNTED != 0 {
        // SAFETY: a bound VPB names one of this driver's mounted devices; the
        // closed device-kind tag is checked before the extension is projected.
        let header = unsafe { (*mounted_device).DeviceExtension.cast::<ExtensionHeader>() };
        // SAFETY: the projection null-checks the extension.
        if matches!(
            unsafe { ExtensionHeader::kind_of(header) },
            Some(DeviceKind::MountedVolume)
        ) {
            // SAFETY: the tag proves the extension shape.
            let mounted = unsafe {
                (*mounted_device)
                    .DeviceExtension
                    .cast::<MountedVolumeExtension>()
            };
            // SAFETY: the extension is live while its device is.
            let vcb = unsafe { (*mounted).vcb.assume_init_ref() };
            let identity = vcb.identity;
            // SAFETY: as above.
            let raw = vcb.state.load(Ordering::Acquire);
            *identity_out = Some(identity);
            observation = adapter::VerifyObservation {
                state: vcb_state(raw),
                identity_matches: true,
            };
        }
    }
    // SAFETY: this thread acquired the lock immediately above.
    unsafe { fsring_sys::c4::IoReleaseVpbSpinLock(irql) };
    observation
}

// ---------------------------------------------------------------------------
// Role dispatch
// ---------------------------------------------------------------------------

/// The retained filesystem-control role root.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_fscontrol(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    major: u8,
    minor: u32,
    root_open: bool,
) -> NTSTATUS {
    match decide_volume_dispatch(DeviceKind::FileSystemControl, major, minor, root_open) {
        VolumeDispatchDecision::Complete(status) => status,
        // SAFETY: the classifier admitted exactly this role and minor.
        VolumeDispatchDecision::Mount => unsafe { fsring_dispatch_mount(device, irp) },
        // SAFETY: as above.
        VolumeDispatchDecision::Verify => unsafe { fsring_dispatch_verify(device, irp) },
    }
}

/// The retained VDO role root.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_vdo(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    major: u8,
    minor_or_ioctl: u32,
    root_open: bool,
) -> NTSTATUS {
    match decide_volume_dispatch(DeviceKind::VirtualDisk, major, minor_or_ioctl, root_open) {
        VolumeDispatchDecision::Complete(status) => {
            if status == STATUS_SUCCESS && major == wdk_sys::IRP_MJ_DEVICE_CONTROL as u8 {
                // SAFETY: the classifier admitted exactly the two storage
                // check-verify controls on exactly this role.
                unsafe { fsring_dispatch_vdo_ioctl(device, irp, minor_or_ioctl) }
            } else {
                status
            }
        }
        // A VDO neither mounts nor verifies; the classifier never routes one
        // here, and answering would let a raw device act as a filesystem.
        VolumeDispatchDecision::Mount | VolumeDispatchDecision::Verify => {
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// The retained VDO device-control root.
///
/// `IOCTL_STORAGE_CHECK_VERIFY{,2}` report a fixed unchanged-media generation:
/// a virtual volume has no removable media, so the answer never varies and no
/// private trigger is added.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_vdo_ioctl(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    code: u32,
) -> NTSTATUS {
    let _ = (device, irp, code);
    STATUS_SUCCESS
}

/// The retained mounted-volume role root.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_volume(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    major: u8,
    minor_or_ioctl: u32,
    root_open: bool,
) -> NTSTATUS {
    let _ = (device, irp);
    match decide_volume_dispatch(DeviceKind::MountedVolume, major, minor_or_ioctl, root_open) {
        VolumeDispatchDecision::Complete(status) => status,
        // A mounted volume is not the mount/verify target; only the
        // filesystem-control role is.
        VolumeDispatchDecision::Mount | VolumeDispatchDecision::Verify => {
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Route one request to the role its trusted device-kind tag names.
///
/// A closed `match`, never a function-pointer table: the stack audit must be
/// able to see every edge, and an indirect call it cannot resolve is exactly
/// the shape that hides one.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
pub(crate) unsafe fn route_by_kind(
    kind: DeviceKind,
    device: PDEVICE_OBJECT,
    irp: PIRP,
    major: u8,
    minor_or_ioctl: u32,
    root_open: bool,
) -> NTSTATUS {
    match kind {
        // The provider endpoint has its own authorization and classifier; the
        // volume roles never answer for it.
        DeviceKind::ProviderControl => STATUS_INVALID_DEVICE_REQUEST,
        // SAFETY: forwarded under the caller's device and IRP contract.
        DeviceKind::FileSystemControl => unsafe {
            fsring_dispatch_fscontrol(device, irp, major, minor_or_ioctl, root_open)
        },
        // SAFETY: as above.
        DeviceKind::VirtualDisk => unsafe {
            fsring_dispatch_vdo(device, irp, major, minor_or_ioctl, root_open)
        },
        // SAFETY: as above.
        DeviceKind::MountedVolume => unsafe {
            fsring_dispatch_volume(device, irp, major, minor_or_ioctl, root_open)
        },
    }
}

#[cfg(test)]
mod native_shape_tests {
    use super::*;

    /// `AcquireCommitVpb` is the immediately preceding roster effect, so
    /// revalidation must accept the already-held lock and refuse a missing
    /// one. Reacquiring here would deterministically reject every valid mount.
    const _: () = assert!(commit_revalidation_has_vpb_lock(true));
    const _: () = assert!(!commit_revalidation_has_vpb_lock(false));
}
