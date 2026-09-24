//! Native ownership of the two permanent BootContext objects.
//!
//! `02-transport.md` section 10.10 and `10-lifecycle.md` section 3 define the
//! named `SynchronizationEvent` publication lock, the named 64-KiB section, and
//! the seqlock protocol that publishes the header. This module performs those
//! native operations and nothing else: every payload, status branch, and
//! acceptance rule comes from `fsring_core::adapter::load`, and every decision
//! about context *content* comes from `fsring_core::bootctx`.
//!
//! The module owns handles, object references, and one kernel system view. It
//! decides nothing.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::control::{
    BOOT_CONTEXT_HEADER_BYTES, BOOT_CONTEXT_INITIAL_SEQUENCE, BOOT_CONTEXT_SECTION_BYTES,
    BOOT_CONTEXT_SLOT_BYTES, BOOT_CONTEXT_SLOT_COUNT, BootContextHeaderV1, BootContextSlotV1,
    boot_context_slot_offset_v1, boot_context_slot_state,
};
use fsring_abi::digest::boot_context_slot_digest_v1;
use fsring_abi::{BootInstanceId, MountId};
use fsring_core::adapter::load as plan;
use fsring_core::alloc::{pool_policy, try_alloc};
use fsring_core::bootctx::{BootHeaderPublication, BootLoadPlan, plan_existing_context};

/// The two header images one load will publish, already encoded.
///
/// Byte images rather than `BootHeaderPublication`: the wire record type is
/// `align(64)`, and the driver root that ends up owning this value is a tagged
/// pool block whose guaranteed alignment is `MEMORY_ALLOCATION_ALIGNMENT`.
/// Encoding here keeps the root inside that guarantee.
struct PreparedPublication {
    initial: [u8; RECORD_BYTES],
    committed: [u8; RECORD_BYTES],
}

fn prepare(publication: &BootHeaderPublication) -> Option<PreparedPublication> {
    Some(PreparedPublication {
        initial: encode_header(&publication.initial)?,
        committed: encode_header(&publication.committed)?,
    })
}
use fsring_core::random::RandomSource;
use fsring_core::resolver::ResolvedDdis;

use wdk_sys::{
    ACL, BOOLEAN, HANDLE, LARGE_INTEGER, NTSTATUS, OBJECT_ATTRIBUTES, PVOID,
    SECURITY_DESCRIPTOR_RELATIVE, SIZE_T, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_DEVICE_STATE, STATUS_SUCCESS, UNICODE_STRING,
};

/// Every WDK-free constant this module hands to a DDI, compared against the
/// installed kit rather than against another literal.
///
/// A literal-to-literal assertion only fires when someone edits the driver; it
/// cannot fire when a WDK upgrade moves a value, which is the drift that
/// actually matters. These are checked on every x64, ARM64, and legacy build.
const _: () = {
    assert!(plan::OBJ_KERNEL_HANDLE == wdk_sys::OBJ_KERNEL_HANDLE);
    assert!(plan::OBJ_PERMANENT == wdk_sys::OBJ_PERMANENT);
    assert!(plan::OBJ_CASE_INSENSITIVE == wdk_sys::OBJ_CASE_INSENSITIVE);
    assert!(plan::OBJ_OPENIF == wdk_sys::OBJ_OPENIF);
    assert!(plan::SEC_COMMIT == wdk_sys::SEC_COMMIT);
    assert!(plan::PAGE_READWRITE == wdk_sys::PAGE_READWRITE);
    assert!(plan::STATUS_SUCCESS == wdk_sys::STATUS_SUCCESS);
    assert!(plan::STATUS_OBJECT_NAME_NOT_FOUND == wdk_sys::STATUS_OBJECT_NAME_NOT_FOUND);
    assert!(plan::STATUS_OBJECT_NAME_COLLISION == wdk_sys::STATUS_OBJECT_NAME_COLLISION);
    assert!(plan::SYNCHRONIZATION_EVENT as i32 == wdk_sys::_EVENT_TYPE::SynchronizationEvent);
    assert!(plan::NOTIFICATION_EVENT as i32 == wdk_sys::_EVENT_TYPE::NotificationEvent);
    assert!(plan::KERNEL_MODE as i32 == wdk_sys::_MODE::KernelMode);
    assert!(plan::WAIT_REASON_EXECUTIVE as i32 == wdk_sys::_KWAIT_REASON::Executive);
    assert!(plan::IO_NO_INCREMENT as u32 == wdk_sys::IO_NO_INCREMENT);
    assert!(plan::ACL_HEADER_BYTES as usize == core::mem::size_of::<ACL>());
    // The canonical descriptor is written as bytes; its header must still be
    // exactly the kit's self-relative header.
    assert!(core::mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>() == 20);
};

/// One BootContext record: the header and every slot are 256 bytes.
const RECORD_BYTES: usize = BOOT_CONTEXT_SLOT_BYTES as usize;
const WORDS_PER_RECORD: usize = RECORD_BYTES / 8;
const _: () = assert!(BOOT_CONTEXT_HEADER_BYTES as usize == RECORD_BYTES);

/// `BootContextHeaderV1.header_sequence` byte offset inside its record.
const HEADER_SEQUENCE_OFFSET: usize = core::mem::offset_of!(BootContextHeaderV1, header_sequence);
/// `BootContextSlotV1.sequence` byte offset inside its record.
const SLOT_SEQUENCE_OFFSET: usize = core::mem::offset_of!(BootContextSlotV1, sequence);
const _: () = {
    assert!(HEADER_SEQUENCE_OFFSET == 40);
    assert!(SLOT_SEQUENCE_OFFSET == 0);
    assert!(HEADER_SEQUENCE_OFFSET % 8 == 0);
};

/// How many times a capture retries before the context is declared unstable.
///
/// A BootContext writer holds the publication lock and performs a bounded
/// number of stores, so an image that will not settle is a corrupt or
/// contended object rather than a slow one: fail the load instead of spinning.
const CAPTURE_ATTEMPTS: u32 = 64;

/// Largest security descriptor this driver will copy before deciding.
const MAX_DESCRIPTOR_BYTES: usize = 512;

/// Everything one driver load owns in the permanent BootContext namespace.
///
/// Null handles and pointers mean "not owned". Each release path clears the
/// field it consumed, so the reverse-order unwind that
/// `fsring_core::adapter::load` dictates cannot release the same object twice
/// even if it were driven twice.
pub(crate) struct BootObjects {
    lock_handle: HANDLE,
    lock_object: PVOID,
    section_handle: HANDLE,
    section_object: PVOID,
    view: PVOID,
    view_size: SIZE_T,
    cell: plan::BootLockCell,
    guard: Option<plan::BootLockGuard>,
    publication: Option<PreparedPublication>,
}

impl BootObjects {
    pub(crate) const fn new() -> Self {
        Self {
            lock_handle: core::ptr::null_mut(),
            lock_object: core::ptr::null_mut(),
            section_handle: core::ptr::null_mut(),
            section_object: core::ptr::null_mut(),
            view: core::ptr::null_mut(),
            view_size: 0,
            cell: plan::BootLockCell::new(),
            guard: None,
            publication: None,
        }
    }
}

fn object_attributes(name: *mut UNICODE_STRING, security: PVOID) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: name,
        Attributes: plan::BOOT_OBJECT_ATTRIBUTES,
        SecurityDescriptor: security,
        SecurityQualityOfService: core::ptr::null_mut(),
    }
}

/// Read one naturally aligned 64-bit word of a record.
///
/// # Safety
/// `base` must address a mapped 8-aligned region of at least
/// `offset + 8` bytes that is only ever accessed through these helpers.
unsafe fn load_word(base: *const u8, offset: usize, ordering: Ordering) -> u64 {
    // SAFETY: the caller guarantees the region and alignment; `offset` is a
    // multiple of eight produced by the fixed record walk below.
    let word = unsafe { base.add(offset) }.cast::<u64>().cast_mut();
    // SAFETY: the pointer is aligned and valid for the lifetime of this call,
    // and nothing else accesses these bytes non-atomically.
    unsafe { AtomicU64::from_ptr(word) }.load(ordering)
}

/// Write one naturally aligned 64-bit word of a record.
///
/// # Safety
/// As [`load_word`], and the caller must own the publication lock.
unsafe fn store_word(base: *mut u8, offset: usize, value: u64, ordering: Ordering) {
    // SAFETY: as `load_word`.
    let word = unsafe { base.add(offset) }.cast::<u64>();
    // SAFETY: as `load_word`; the caller owns the publication guard.
    unsafe { AtomicU64::from_ptr(word) }.store(value, ordering);
}

/// Capture one stable 256-byte record through the seqlock protocol.
///
/// # Safety
/// `base` must address the mapped record inside this driver's own system view.
unsafe fn capture_record(base: *const u8, sequence_offset: usize) -> Option<[u8; RECORD_BYTES]> {
    let mut attempt = 0u32;
    while attempt < CAPTURE_ATTEMPTS {
        attempt = attempt.saturating_add(1);
        // SAFETY: the caller's record contract.
        let first = unsafe { load_word(base, sequence_offset, Ordering::Acquire) };
        if first == 0 || first % 2 != 0 {
            // Zero is "never published"; odd is "publication in progress".
            continue;
        }

        let mut words = [0u64; WORDS_PER_RECORD];
        let mut offset = 0usize;
        for word in words.iter_mut() {
            // SAFETY: the walk stays inside the 256-byte record.
            *word = unsafe { load_word(base, offset, Ordering::Relaxed) };
            offset = offset.saturating_add(8);
        }

        // The full compiler-and-processor barrier the protocol requires
        // between the body copy and the second sequence read.
        fence(Ordering::SeqCst);
        // SAFETY: as above.
        let second = unsafe { load_word(base, sequence_offset, Ordering::Acquire) };
        if second != first {
            continue;
        }

        let mut image = [0u8; RECORD_BYTES];
        for (chunk, word) in image.chunks_exact_mut(8).zip(words.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        return Some(image);
    }
    None
}

/// Publish one complete 256-byte record image under the held guard.
///
/// The in-progress sequence is derived from the image itself rather than
/// passed in: it is exactly one less than the committed value, which is the
/// odd marker for an even commit and the never-published zero for the first
/// odd INITIALIZING image. A caller-supplied value is one more thing a call
/// site can get wrong, and a sequence that moves backwards is unrecoverable.
///
/// # Safety
/// `base` must address the mapped record and the caller must hold the
/// BootContext publication guard.
unsafe fn publish_record(
    base: *mut u8,
    sequence_offset: usize,
    image: &[u8; RECORD_BYTES],
) -> Option<()> {
    let committed = read_image_word(image, sequence_offset)?;
    let in_progress_sequence = committed.checked_sub(1)?;

    // SAFETY: the caller's record and guard contract, for every store below.
    unsafe {
        store_word(
            base,
            sequence_offset,
            in_progress_sequence,
            Ordering::Release,
        );
    }
    fence(Ordering::SeqCst);

    let mut offset = 0usize;
    for chunk in image.chunks_exact(8) {
        if offset != sequence_offset {
            let word: [u8; 8] = chunk.try_into().ok()?;
            // SAFETY: the walk stays inside the 256-byte record.
            unsafe {
                store_word(base, offset, u64::from_le_bytes(word), Ordering::Relaxed);
            }
        }
        offset = offset.saturating_add(8);
    }

    fence(Ordering::SeqCst);
    // SAFETY: the body is complete; this is the single publication commit.
    unsafe {
        store_word(base, sequence_offset, committed, Ordering::Release);
    }
    Some(())
}

fn read_image_word(image: &[u8; RECORD_BYTES], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let word: [u8; 8] = image.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(word))
}

fn encode_header(header: &BootContextHeaderV1) -> Option<[u8; RECORD_BYTES]> {
    let mut bytes = [0u8; RECORD_BYTES];
    try_encode(header, &mut bytes).ok()?;
    Some(bytes)
}

fn encode_slot(slot: &BootContextSlotV1) -> Option<[u8; RECORD_BYTES]> {
    let mut bytes = [0u8; RECORD_BYTES];
    try_encode(slot, &mut bytes).ok()?;
    Some(bytes)
}

// ---------------------------------------------------------------------------
// Security descriptor projection
// ---------------------------------------------------------------------------

/// Copy the parts of a self-relative descriptor the contract inspects.
///
/// The Object Manager builds every descriptor it returns, so its internal
/// offsets and sizes are self-consistent; what is *not* trusted is the
/// content, which is exactly what the caller then decides on. Anything that
/// does not fit the fixed window is refused rather than copied.
///
/// # Safety
/// `descriptor` must be the live self-relative descriptor `ObGetObjectSecurity`
/// returned and must remain valid for this copy.
unsafe fn copy_descriptor(
    descriptor: PVOID,
    out: &mut [u8; MAX_DESCRIPTOR_BYTES],
) -> Option<usize> {
    let base = descriptor.cast::<u8>().cast_const();
    // SAFETY: a self-relative descriptor is at least its 20-byte header.
    unsafe { core::ptr::copy_nonoverlapping(base, out.as_mut_ptr(), 20) };

    let owner = read_out_u32(out, 4)?;
    let group = read_out_u32(out, 8)?;
    let dacl = read_out_u32(out, 16)?;
    let mut extent = 20usize;

    for offset in [owner, group] {
        if offset == 0 {
            continue;
        }
        let start = usize::try_from(offset).ok()?;
        if start.checked_add(8)? > MAX_DESCRIPTOR_BYTES {
            return None;
        }
        // SAFETY: a SID is at least its 8-byte fixed prefix.
        unsafe { core::ptr::copy_nonoverlapping(base.add(start), out.as_mut_ptr().add(start), 8) };
        let count = usize::from(*out.get(start.checked_add(1)?)?);
        let length = count.checked_mul(4)?.checked_add(8)?;
        let end = start.checked_add(length)?;
        if end > MAX_DESCRIPTOR_BYTES {
            return None;
        }
        // SAFETY: the SID declares this length through its own subauthority
        // count, and the window bound above keeps the copy inside `out`.
        unsafe {
            core::ptr::copy_nonoverlapping(base.add(start), out.as_mut_ptr().add(start), length);
        }
        extent = extent.max(end);
    }

    if dacl != 0 {
        let start = usize::try_from(dacl).ok()?;
        if start.checked_add(8)? > MAX_DESCRIPTOR_BYTES {
            return None;
        }
        // SAFETY: an ACL is at least its 8-byte header.
        unsafe { core::ptr::copy_nonoverlapping(base.add(start), out.as_mut_ptr().add(start), 8) };
        let size = usize::from(read_out_u16(out, start.checked_add(2)?)?);
        let end = start.checked_add(size)?;
        if size < 8 || end > MAX_DESCRIPTOR_BYTES {
            return None;
        }
        // SAFETY: the ACL declares this length in its own header.
        unsafe {
            core::ptr::copy_nonoverlapping(base.add(start), out.as_mut_ptr().add(start), size);
        }
        extent = extent.max(end);
    }

    Some(extent)
}

fn read_out_u16(bytes: &[u8; MAX_DESCRIPTOR_BYTES], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let field: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(field))
}

fn read_out_u32(bytes: &[u8; MAX_DESCRIPTOR_BYTES], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let field: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(field))
}

/// Obtain, validate, and always release one object's security descriptor.
///
/// # Safety
/// `object` must be a live referenced object owned by this driver.
unsafe fn validate_object_security(object: PVOID) -> NTSTATUS {
    let mut descriptor: PVOID = core::ptr::null_mut();
    let mut allocated: BOOLEAN = 0;
    // SAFETY: both out parameters are live locals for the duration of the call.
    let status = unsafe {
        fsring_sys::c4::ObGetObjectSecurity(object, &raw mut descriptor, &raw mut allocated)
    };
    if status != STATUS_SUCCESS {
        return status;
    }
    if descriptor.is_null() {
        // SAFETY: the query succeeded, so its result must be released even
        // when it is not usable.
        unsafe { fsring_sys::c4::ObReleaseObjectSecurity(descriptor, allocated) };
        return STATUS_INVALID_DEVICE_STATE;
    }

    let mut window = [0u8; MAX_DESCRIPTOR_BYTES];
    // SAFETY: `descriptor` is the live descriptor the query just returned.
    let extent = unsafe { copy_descriptor(descriptor, &mut window) };
    // SAFETY: released exactly once on every path, as the DDI pair requires.
    unsafe { fsring_sys::c4::ObReleaseObjectSecurity(descriptor, allocated) };

    let Some(extent) = extent else {
        return STATUS_INVALID_DEVICE_STATE;
    };
    let Some(image) = window.get(..extent) else {
        return STATUS_INVALID_DEVICE_STATE;
    };
    let Some(facts) = plan::parse_boot_object_security(image) else {
        return STATUS_INVALID_DEVICE_STATE;
    };
    if plan::boot_object_security_is_canonical(facts) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_DEVICE_STATE
    }
}

// ---------------------------------------------------------------------------
// Effect 1: open or create and acquire the publication lock event
// ---------------------------------------------------------------------------

/// Open, create, or reopen the permanent lock event and acquire it.
///
/// This is one closed executor operation: every reference and handle it opens
/// is closed again before it returns a failure, so a failed acquisition leaves
/// the load owning nothing.
///
/// # Safety
/// Must run once at PASSIVE_LEVEL on the DriverEntry thread.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn open_and_acquire_lock_event(
    boot: &mut BootObjects,
) -> Result<plan::ObjectDisposition, NTSTATUS> {
    let mut name_units = plan::BOOT_CONTEXT_LOCK_OBJECT_NAME;
    let Some(mut name) = crate::kernel::counted_unicode_units(&mut name_units) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let mut security = plan::CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    let mut attributes = object_attributes(&raw mut name, security.as_mut_ptr().cast());

    let mut handle: HANDLE = core::ptr::null_mut();
    // SAFETY: every out parameter and descriptor lives on this frame for the
    // duration of the synchronous PASSIVE_LEVEL call.
    let open_status = unsafe {
        fsring_sys::c4::ZwOpenEvent(
            &raw mut handle,
            plan::BOOT_LOCK_EVENT_ACCESS,
            &raw mut attributes,
        )
    };
    let disposition = match plan::decide_open(open_status) {
        plan::OpenDecision::Opened => plan::ObjectDisposition::OpenedExisting,
        plan::OpenDecision::Fail => return Err(open_status),
        plan::OpenDecision::Create => {
            // SAFETY: as above. The event subtype and initial state are the
            // frozen payload, not caller input.
            let create_status = unsafe {
                fsring_sys::c4::ZwCreateEvent(
                    &raw mut handle,
                    plan::BOOT_LOCK_EVENT_ACCESS,
                    &raw mut attributes,
                    plan::BOOT_LOCK_EVENT_CREATE.event_type as i32,
                    BOOLEAN::from(plan::BOOT_LOCK_EVENT_CREATE.initial_state),
                )
            };
            match plan::decide_create(create_status) {
                plan::CreateDecision::Created => plan::ObjectDisposition::CreatedNew,
                plan::CreateDecision::Fail => return Err(create_status),
                plan::CreateDecision::Reopen => {
                    // SAFETY: as above.
                    let reopen_status = unsafe {
                        fsring_sys::c4::ZwOpenEvent(
                            &raw mut handle,
                            plan::BOOT_LOCK_EVENT_ACCESS,
                            &raw mut attributes,
                        )
                    };
                    match plan::decide_reopen(reopen_status) {
                        plan::ReopenDecision::Opened => {
                            plan::ObjectDisposition::ReopenedAfterCollision
                        }
                        plan::ReopenDecision::Fail => return Err(reopen_status),
                    }
                }
            }
        }
    };
    if handle.is_null() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }

    // SAFETY: `ExEventObjectType` is the kernel's exported pointer to the
    // event object type; the design requires the typed reference to use it.
    let event_type = unsafe {
        let cell: *mut fsring_sys::c4::POBJECT_TYPE =
            core::ptr::read(&raw const fsring_sys::c4::ExEventObjectType);
        core::ptr::read(cell.cast_const())
    };
    let mut object: PVOID = core::ptr::null_mut();
    // SAFETY: the handle is the one just opened; the out parameter is local.
    let reference_status = unsafe {
        fsring_sys::c4::ObReferenceObjectByHandle(
            handle,
            plan::BOOT_LOCK_EVENT_ACCESS,
            event_type,
            plan::KERNEL_MODE as i8,
            &raw mut object,
            core::ptr::null_mut(),
        )
    };
    if reference_status != STATUS_SUCCESS {
        // SAFETY: only the handle was opened; close it exactly once.
        unsafe { close_handle(handle) };
        return Err(reference_status);
    }

    // SAFETY: the reference is live for this validation.
    let security_status = unsafe { validate_object_security(object) };
    if security_status != STATUS_SUCCESS {
        // SAFETY: reference and handle are both owned here and released once.
        unsafe {
            fsring_sys::ObfDereferenceObject(object);
            close_handle(handle);
        }
        return Err(security_status);
    }

    match unsafe { acquire_guard(boot, object) } {
        Ok(()) => {}
        Err(status) => {
            // SAFETY: acquisition failed without a guard, so the reference and
            // handle this operation opened are released exactly once.
            unsafe {
                fsring_sys::ObfDereferenceObject(object);
                close_handle(handle);
            }
            return Err(status);
        }
    }

    boot.lock_handle = handle;
    boot.lock_object = object;
    Ok(disposition)
}

/// Enter the critical region, wait the bounded wait, and check the subtype.
///
/// # Safety
/// `object` must be the referenced event object.
unsafe fn acquire_guard(boot: &mut BootObjects, object: PVOID) -> Result<(), NTSTATUS> {
    let Ok(region) = boot.cell.enter() else {
        // A guard is already live on this driver: recursive acquisition is a
        // refusal, never a second wait.
        return Err(STATUS_INVALID_DEVICE_STATE);
    };

    // SAFETY: PASSIVE_LEVEL, and the matching leave happens on every path
    // below through either the guard or the rejection token.
    unsafe { fsring_sys::c4::KeEnterCriticalRegion() };

    let mut timeout = LARGE_INTEGER {
        QuadPart: plan::BOOT_LOCK_WAIT.relative_timeout_100ns,
    };
    // SAFETY: `object` is the referenced event; the timeout lives on this
    // frame for the duration of the synchronous wait.
    let wait_status = unsafe {
        fsring_sys::c4::KeWaitForSingleObject(
            object,
            plan::BOOT_LOCK_WAIT.wait_reason as i32,
            plan::BOOT_LOCK_WAIT.processor_mode as i8,
            BOOLEAN::from(plan::BOOT_LOCK_WAIT.alertable),
            &raw mut timeout,
        )
    };
    // A satisfied wait on a SynchronizationEvent leaves it non-signaled; a
    // nonzero state is a same-name NotificationEvent and is refused.
    let state = if wait_status == STATUS_SUCCESS {
        // SAFETY: `object` is the referenced event.
        unsafe { fsring_sys::c4::KeReadStateEvent(object.cast()) }
    } else {
        0
    };
    let state = u32::try_from(state).unwrap_or(u32::MAX);

    match boot.cell.finish_wait(region, wait_status, state) {
        plan::BootLockAcquisition::Acquired(guard) => {
            boot.guard = Some(guard);
            Ok(())
        }
        plan::BootLockAcquisition::Rejected(region) => {
            plan::leave_critical_region(region);
            // SAFETY: no ownership was claimed, so the event is not set here.
            unsafe { fsring_sys::c4::KeLeaveCriticalRegion() };
            Err(if wait_status == STATUS_SUCCESS {
                STATUS_INVALID_DEVICE_STATE
            } else {
                wait_status
            })
        }
    }
}

/// Read this boot's durable instance identity from the published context.
///
/// A SETUP names its session with `BootInstanceId + MountId`, and the instance
/// half is not the driver's to invent: it comes from the same stable header
/// capture every other reader uses.
///
/// # Safety
/// Must run after a successful load, with the system view mapped.
pub(crate) unsafe fn boot_instance_id(boot: &BootObjects) -> Option<BootInstanceId> {
    if boot.view.is_null() {
        return None;
    }
    // SAFETY: the view covers the whole permanent section; the seqlock capture
    // is what makes the read stable without holding the publication lock.
    let image =
        unsafe { capture_record(boot.view.cast::<u8>().cast_const(), HEADER_SEQUENCE_OFFSET) }?;
    let header = try_decode::<BootContextHeaderV1>(&image).ok()?;
    Some(header.boot_instance_id)
}

/// Re-acquire the already-open publication lock.
///
/// The load opened and referenced the permanent event once; a SETUP's MountId
/// burn needs the same bounded wait, the same subtype check, and the same
/// recursive-acquisition refusal, but must not open a second handle.
///
/// # Safety
/// Must run at PASSIVE_LEVEL after a successful load, so the lock object is
/// referenced and the driver root owns it.
pub(crate) unsafe fn acquire_lock_event(boot: &mut BootObjects) -> Result<(), NTSTATUS> {
    if boot.lock_object.is_null() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    let object = boot.lock_object;
    // SAFETY: `object` is the load's referenced permanent event.
    unsafe { acquire_guard(boot, object) }
}

/// Burn one volatile `MountId` under the held publication guard.
///
/// The whole transaction is decided by `fsring_core::bootctx::plan_mount_burn`
/// from a private snapshot: this function captures the stable header image,
/// hands it to the pure planner, and publishes exactly the committed image the
/// planner produced. It writes no slot — a mount identity is volatile, and the
/// permanent slot bytes must be observably unchanged by a burn.
///
/// # Safety
/// Must run at PASSIVE_LEVEL with the system view mapped and the publication
/// guard held by this thread.
pub(crate) unsafe fn burn_mount_id(
    boot: &mut BootObjects,
    random_high: u64,
) -> Result<MountId, NTSTATUS> {
    if boot.view.is_null() || boot.guard.is_none() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    let view = boot.view.cast::<u8>();
    // SAFETY: the view covers the whole permanent section and the guard is
    // held, so the header record is stable for this capture.
    let Some(image) = (unsafe { capture_record(view.cast_const(), HEADER_SEQUENCE_OFFSET) }) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let Ok(header) = try_decode::<BootContextHeaderV1>(&image) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };

    let Ok(burn) = fsring_core::bootctx::plan_mount_burn(&header, random_high) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let Some(committed) = encode_header(&burn.committed()) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    // SAFETY: the guard is held and the view is this driver's; this is the one
    // seqlock publication of the burn.
    if unsafe { publish_record(view, HEADER_SEQUENCE_OFFSET, &committed) }.is_none() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    Ok(burn.mount_id())
}

/// Release the publication guard exactly once.
///
/// # Safety
/// Must run at PASSIVE_LEVEL while this driver holds the guard.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn release_lock_event(boot: &mut BootObjects) -> Result<(), NTSTATUS> {
    let Some(guard) = boot.guard.take() else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    // SAFETY: the guard proves this driver owns the event; the release is the
    // single documented set, with no wait and no priority boost.
    let previous = unsafe {
        fsring_sys::c4::KeSetEvent(
            boot.lock_object.cast(),
            plan::BOOT_LOCK_RELEASE.priority_increment as i32,
            BOOLEAN::from(plan::BOOT_LOCK_RELEASE.wait),
        )
    };
    let previous = u32::try_from(previous).unwrap_or(u32::MAX);
    let release = boot.cell.release(guard, previous);
    let violation = release.violation();
    release.leave();
    // SAFETY: the critical region entered by the acquisition is left here,
    // exactly once, after the event has been set.
    unsafe { fsring_sys::c4::KeLeaveCriticalRegion() };

    if violation.is_some() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Effect 2: open or create the permanent section
// ---------------------------------------------------------------------------

/// Open, create, or reopen the permanent 64-KiB BootContext section.
///
/// # Safety
/// Must run at PASSIVE_LEVEL while this load holds the publication guard.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn open_or_create_section(
    boot: &mut BootObjects,
) -> Result<plan::ObjectDisposition, NTSTATUS> {
    let mut name_units = plan::BOOT_CONTEXT_SECTION_OBJECT_NAME;
    let Some(mut name) = crate::kernel::counted_unicode_units(&mut name_units) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let mut security = plan::CANONICAL_BOOT_SECURITY_DESCRIPTOR;
    let mut attributes = object_attributes(&raw mut name, security.as_mut_ptr().cast());

    let mut handle: HANDLE = core::ptr::null_mut();
    // SAFETY: every out parameter lives on this frame for the call.
    let open_status = unsafe {
        fsring_sys::c4::ZwOpenSection(
            &raw mut handle,
            plan::BOOT_SECTION_ACCESS,
            &raw mut attributes,
        )
    };
    let disposition = match plan::decide_open(open_status) {
        plan::OpenDecision::Opened => plan::ObjectDisposition::OpenedExisting,
        plan::OpenDecision::Fail => return Err(open_status),
        plan::OpenDecision::Create => {
            let mut maximum = LARGE_INTEGER {
                QuadPart: plan::BOOT_SECTION_CREATE.maximum_size as i64,
            };
            // SAFETY: as above. A null file handle is the pagefile-backed
            // creation the design requires.
            let create_status = unsafe {
                fsring_sys::c4::ZwCreateSection(
                    &raw mut handle,
                    plan::BOOT_SECTION_ACCESS,
                    &raw mut attributes,
                    &raw mut maximum,
                    plan::BOOT_SECTION_CREATE.page_protection,
                    plan::BOOT_SECTION_CREATE.allocation_attributes,
                    core::ptr::null_mut(),
                )
            };
            match plan::decide_create(create_status) {
                plan::CreateDecision::Created => plan::ObjectDisposition::CreatedNew,
                plan::CreateDecision::Fail => return Err(create_status),
                plan::CreateDecision::Reopen => {
                    // SAFETY: as above.
                    let reopen_status = unsafe {
                        fsring_sys::c4::ZwOpenSection(
                            &raw mut handle,
                            plan::BOOT_SECTION_ACCESS,
                            &raw mut attributes,
                        )
                    };
                    match plan::decide_reopen(reopen_status) {
                        plan::ReopenDecision::Opened => {
                            plan::ObjectDisposition::ReopenedAfterCollision
                        }
                        plan::ReopenDecision::Fail => return Err(reopen_status),
                    }
                }
            }
        }
    };
    if handle.is_null() {
        return Err(STATUS_INVALID_DEVICE_STATE);
    }

    // SAFETY: `MmSectionObjectType` is the kernel's exported pointer to the
    // section object type; the design requires the typed reference to use it.
    let section_type = unsafe {
        let cell: *mut fsring_sys::c4::POBJECT_TYPE =
            core::ptr::read(&raw const fsring_sys::c4::MmSectionObjectType);
        core::ptr::read(cell.cast_const())
    };
    let mut object: PVOID = core::ptr::null_mut();
    // SAFETY: the handle is the one just opened; the out parameter is local.
    let reference_status = unsafe {
        fsring_sys::c4::ObReferenceObjectByHandle(
            handle,
            plan::BOOT_SECTION_ACCESS,
            section_type,
            plan::KERNEL_MODE as i8,
            &raw mut object,
            core::ptr::null_mut(),
        )
    };
    if reference_status != STATUS_SUCCESS {
        // SAFETY: only the handle was opened.
        unsafe { close_handle(handle) };
        return Err(reference_status);
    }

    // SAFETY: the reference is live for this validation.
    let security_status = unsafe { validate_object_security(object) };
    if security_status != STATUS_SUCCESS {
        // SAFETY: both are owned here and released exactly once.
        unsafe {
            fsring_sys::ObfDereferenceObject(object);
            close_handle(handle);
        }
        return Err(security_status);
    }

    // An object this load did not create must already have the exact geometry;
    // the typed and descriptor checks above precede this content query.
    if !matches!(disposition, plan::ObjectDisposition::CreatedNew) {
        // SAFETY: the handle is live and the information buffer is local.
        let geometry = unsafe { query_section_geometry(handle) };
        match geometry {
            Ok(facts) if plan::existing_section_is_canonical(facts) => {}
            Ok(_) => {
                // SAFETY: released exactly once on this refusal path.
                unsafe {
                    fsring_sys::ObfDereferenceObject(object);
                    close_handle(handle);
                }
                return Err(STATUS_INVALID_DEVICE_STATE);
            }
            Err(status) => {
                // SAFETY: as above.
                unsafe {
                    fsring_sys::ObfDereferenceObject(object);
                    close_handle(handle);
                }
                return Err(status);
            }
        }
    }

    boot.section_handle = handle;
    boot.section_object = object;
    Ok(disposition)
}

/// # Safety
/// `handle` must be the live section handle.
unsafe fn query_section_geometry(handle: HANDLE) -> Result<plan::SectionBasicFacts, NTSTATUS> {
    let mut information = fsring_sys::c4::SECTION_BASIC_INFORMATION {
        BaseAddress: core::ptr::null_mut(),
        AllocationAttributes: 0,
        MaximumSize: LARGE_INTEGER { QuadPart: 0 },
    };
    let mut returned: SIZE_T = 0;
    // SAFETY: the information buffer and its length live on this frame.
    let status = unsafe {
        fsring_sys::c4::ZwQuerySection(
            handle,
            fsring_sys::c4::SECTION_BASIC_INFORMATION_CLASS,
            (&raw mut information).cast(),
            core::mem::size_of::<fsring_sys::c4::SECTION_BASIC_INFORMATION>() as SIZE_T,
            &raw mut returned,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    // SAFETY: the union's `QuadPart` member is always readable.
    let maximum = unsafe { information.MaximumSize.QuadPart };
    Ok(plan::SectionBasicFacts {
        maximum_size: u64::try_from(maximum).unwrap_or(u64::MAX),
        allocation_attributes: information.AllocationAttributes,
    })
}

// ---------------------------------------------------------------------------
// Effect 3: map the kernel system view
// ---------------------------------------------------------------------------

/// Map the whole section into system space. Only kernel views are ever made.
///
/// # Safety
/// Must run at PASSIVE_LEVEL with the section referenced.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn map_system_view(boot: &mut BootObjects) -> Result<(), NTSTATUS> {
    let mut view: PVOID = core::ptr::null_mut();
    let mut size: SIZE_T = BOOT_CONTEXT_SECTION_BYTES as SIZE_T;
    // SAFETY: `section_object` is this load's referenced section; both out
    // parameters are local.
    let status = unsafe {
        fsring_sys::c4::MmMapViewInSystemSpace(boot.section_object, &raw mut view, &raw mut size)
    };
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    if view.is_null() || size < BOOT_CONTEXT_SECTION_BYTES as SIZE_T {
        // SAFETY: the map succeeded, so the view is unmapped before failing.
        unsafe {
            let _ = fsring_sys::c4::MmUnmapViewInSystemSpace(view);
        }
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    boot.view = view;
    boot.view_size = size;
    Ok(())
}

// ---------------------------------------------------------------------------
// Effect 4: validate an existing context or prepare a new one
// ---------------------------------------------------------------------------

/// Decide what the mapped context is, and prepare its header publication.
///
/// Every decision here belongs to `fsring_core::bootctx`; this function only
/// captures private snapshots and reports which case the planner chose.
///
/// # Safety
/// Must run at PASSIVE_LEVEL with the view mapped and the guard held.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn validate_or_initialize<S: RandomSource>(
    boot: &mut BootObjects,
    ddis: &ResolvedDdis,
    rng: &mut S,
) -> Result<plan::BootValidation, NTSTATUS> {
    let view = boot.view.cast::<u8>().cast_const();
    // SAFETY: the view covers the whole section.
    let sequence = unsafe { load_word(view, HEADER_SEQUENCE_OFFSET, Ordering::Acquire) };

    if sequence == 0 {
        // A never-published context is acceptable only when it is entirely
        // zero. An interrupted initializer is fail-closed, never reinitialized.
        // SAFETY: the whole mapped section is this driver's own view.
        if !unsafe { section_is_entirely_zero(view) } {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        let publication = prepare_new_context(rng)?;
        boot.publication = Some(publication);
        return Ok(plan::BootValidation::NewPrepared);
    }

    // SAFETY: the header record lives at the start of this driver's view.
    let Some(header_image) = (unsafe { capture_record(view, HEADER_SEQUENCE_OFFSET) }) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let Ok(header) = try_decode::<BootContextHeaderV1>(&header_image) else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };

    // The slot array is 16 KiB: far past any kernel stack budget, so it is a
    // transient tagged allocation freed before this function returns.
    let slot_bytes = (BOOT_CONTEXT_SLOT_COUNT as usize)
        .checked_mul(core::mem::size_of::<BootContextSlotV1>())
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut pool = crate::kernel::KernelPool::new(ddis);
    let policy = pool_policy(crate::platform::PROFILE, ddis.all_resolved());
    let Ok(block) = try_alloc(&mut pool, policy, slot_bytes) else {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let slots = block.cast::<BootContextSlotV1>();

    let capture = unsafe { capture_slots(view, slots) };
    let outcome = match capture {
        Err(status) => Err(status),
        Ok(()) => {
            // SAFETY: every element was initialized by the capture above and
            // the block is this load's private copy.
            let slice = unsafe {
                core::slice::from_raw_parts(slots.cast_const(), BOOT_CONTEXT_SLOT_COUNT as usize)
            };
            match plan_existing_context(header, slice) {
                Ok(BootLoadPlan::Adopt(publication) | BootLoadPlan::Initialize(publication)) => {
                    prepare(&publication).ok_or(STATUS_INVALID_DEVICE_STATE)
                }
                Err(_) => Err(STATUS_INVALID_DEVICE_STATE),
            }
        }
    };

    // SAFETY: the transient scratch is freed exactly once on every path.
    unsafe { crate::kernel::free_pool(block) };

    boot.publication = Some(outcome?);
    Ok(plan::BootValidation::ExistingReady)
}

/// # Safety
/// `view` must address this driver's own mapped section.
unsafe fn section_is_entirely_zero(view: *const u8) -> bool {
    let mut offset = 0usize;
    while offset < BOOT_CONTEXT_SECTION_BYTES as usize {
        // SAFETY: the walk stays inside the mapped 64-KiB view.
        if unsafe { load_word(view, offset, Ordering::Relaxed) } != 0 {
            return false;
        }
        offset = offset.saturating_add(8);
    }
    true
}

/// # Safety
/// `view` must address the mapped section and `slots` a writable array of
/// exactly `BOOT_CONTEXT_SLOT_COUNT` uninitialized records.
unsafe fn capture_slots(view: *const u8, slots: *mut BootContextSlotV1) -> Result<(), NTSTATUS> {
    let mut index = 0u32;
    while index < BOOT_CONTEXT_SLOT_COUNT {
        let Some(offset) = boot_context_slot_offset_v1(index) else {
            return Err(STATUS_INVALID_DEVICE_STATE);
        };
        // SAFETY: the offset is inside the section by the ABI's own bound.
        let record = unsafe { view.add(offset as usize) };
        // SAFETY: the record is one 256-byte slot of this driver's view.
        let Some(image) = (unsafe { capture_record(record, SLOT_SEQUENCE_OFFSET) }) else {
            return Err(STATUS_INVALID_DEVICE_STATE);
        };
        let Ok(slot) = try_decode::<BootContextSlotV1>(&image) else {
            return Err(STATUS_INVALID_DEVICE_STATE);
        };
        // SAFETY: `index` is below the array's element count.
        unsafe { core::ptr::write(slots.add(index as usize), slot) };
        index = index.saturating_add(1);
    }
    Ok(())
}

fn prepare_new_context<S: RandomSource>(rng: &mut S) -> Result<PreparedPublication, NTSTATUS> {
    let lo = fsring_core::random::draw_nonzero(rng).map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
    let hi = fsring_core::random::draw_nonzero(rng).map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
    let mut key = [0u8; 32];
    for chunk in key.chunks_exact_mut(8) {
        let word =
            fsring_core::random::draw_nonzero(rng).map_err(|_| STATUS_INVALID_DEVICE_STATE)?;
        chunk.copy_from_slice(&word.to_le_bytes());
    }

    match fsring_core::bootctx::plan_new_context(BootInstanceId { lo, hi }, key) {
        Ok(BootLoadPlan::Initialize(publication) | BootLoadPlan::Adopt(publication)) => {
            prepare(&publication).ok_or(STATUS_INVALID_DEVICE_STATE)
        }
        Err(_) => Err(STATUS_INVALID_DEVICE_STATE),
    }
}

// ---------------------------------------------------------------------------
// Effect 5: publish the load generation
// ---------------------------------------------------------------------------

/// Commit the prepared header publication under the held guard.
///
/// # Safety
/// Must run at PASSIVE_LEVEL with the view mapped and the guard held.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn publish_load_generation(
    boot: &mut BootObjects,
    validation: plan::BootValidation,
) -> Result<plan::BootOrigin, NTSTATUS> {
    let Some(publication) = boot.publication.take() else {
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let view = boot.view.cast::<u8>();
    let initial = publication.initial;
    let committed = publication.committed;

    match validation {
        plan::BootValidation::ExistingReady => {
            // A stable image exists: the odd in-progress sequence, the new
            // body, then the even commit.
            // SAFETY: the guard is held and the view is this driver's.
            let published = unsafe { publish_record(view, HEADER_SEQUENCE_OFFSET, &committed) };
            if published.is_none() {
                return Err(STATUS_INVALID_DEVICE_STATE);
            }
            Ok(plan::BootOrigin::ExistingReady)
        }
        plan::BootValidation::NewPrepared => {
            // No stable image exists yet. Publish the odd INITIALIZING header,
            // fill every FREE slot, then Release-publish READY. A reader that
            // arrives in between sees an odd sequence and never adopts it.
            // SAFETY: the guard is held and the view is this driver's.
            let staged = unsafe { publish_record(view, HEADER_SEQUENCE_OFFSET, &initial) };
            if staged.is_none() {
                return Err(STATUS_INVALID_DEVICE_STATE);
            }
            // SAFETY: as above.
            unsafe { initialize_free_slots(view) }?;
            // SAFETY: as above; this is the READY commit.
            let published = unsafe { publish_record(view, HEADER_SEQUENCE_OFFSET, &committed) };
            if published.is_none() {
                return Err(STATUS_INVALID_DEVICE_STATE);
            }
            Ok(plan::BootOrigin::NewlyInitializedReady)
        }
    }
}

/// Write all `BOOT_CONTEXT_SLOT_COUNT` FREE slot records.
///
/// # Safety
/// Must run with the guard held over this driver's mapped view.
unsafe fn initialize_free_slots(view: *mut u8) -> Result<(), NTSTATUS> {
    let mut index = 0u32;
    while index < BOOT_CONTEXT_SLOT_COUNT {
        let mut slot = BootContextSlotV1 {
            sequence: BOOT_CONTEXT_INITIAL_SEQUENCE,
            state: boot_context_slot_state::FREE,
            service_sid_length: 0,
            load_generation: 0,
            mount_sequence: 0,
            mount_id: fsring_abi::MountId { lo: 0, hi: 0 },
            boot_instance_id: BootInstanceId { lo: 0, hi: 0 },
            latest_session_epoch: 0,
            selected_features: fsring_abi::features::FeatureSet { words: [0, 0] },
            journal_version: 0,
            flags: 0,
            service_sid: [0; 68],
            reserved: [0; 60],
            digest: [0; 32],
        };
        let Some(digest) = boot_context_slot_digest_v1(index, &slot) else {
            return Err(STATUS_INVALID_DEVICE_STATE);
        };
        slot.digest = digest;
        let Some(image) = encode_slot(&slot) else {
            return Err(STATUS_INVALID_DEVICE_STATE);
        };
        let Some(offset) = boot_context_slot_offset_v1(index) else {
            return Err(STATUS_INVALID_DEVICE_STATE);
        };
        // SAFETY: the offset is inside the section by the ABI's own bound.
        let record = unsafe { view.add(offset as usize) };
        // SAFETY: the guard is held; each record is published exactly once
        // through the odd-then-even protocol before READY is committed.
        let published = unsafe { publish_record(record, SLOT_SEQUENCE_OFFSET, &image) };
        if published.is_none() {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rollback and unload releases
// ---------------------------------------------------------------------------

/// # Safety
/// `handle` must be a live kernel handle this driver owns.
unsafe fn close_handle(handle: HANDLE) {
    // SAFETY: forwarded under the caller's contract; the status is not
    // actionable on a teardown path.
    unsafe {
        let _ = fsring_sys::c4::ZwClose(handle);
    }
}

/// Unmap the kernel system view. Idempotent: a cleared field is a no-op.
///
/// # Safety
/// Must run at PASSIVE_LEVEL.
pub(crate) unsafe fn unmap_system_view(boot: &mut BootObjects) {
    if boot.view.is_null() {
        return;
    }
    // SAFETY: this driver mapped exactly this view.
    unsafe {
        let _ = fsring_sys::c4::MmUnmapViewInSystemSpace(boot.view);
    }
    boot.view = core::ptr::null_mut();
    boot.view_size = 0;
}

/// Convert a section this load created, and never published as READY, into a
/// temporary object so that closing its last handle destroys it.
///
/// # Safety
/// Must run at PASSIVE_LEVEL while the section handle is still live.
pub(crate) unsafe fn make_new_section_temporary(boot: &mut BootObjects) {
    if boot.section_handle.is_null() {
        return;
    }
    // SAFETY: the handle is this load's own, and the plan only reaches this
    // effect for a section this load created before it reached READY.
    unsafe {
        let _ = fsring_sys::c4::ZwMakeTemporaryObject(boot.section_handle);
    }
}

/// Release the section reference and handle. Idempotent.
///
/// # Safety
/// Must run at PASSIVE_LEVEL.
pub(crate) unsafe fn close_section(boot: &mut BootObjects) {
    if !boot.section_object.is_null() {
        // SAFETY: this load took exactly one reference.
        unsafe { fsring_sys::ObfDereferenceObject(boot.section_object) };
        boot.section_object = core::ptr::null_mut();
    }
    if !boot.section_handle.is_null() {
        // SAFETY: this load opened exactly this handle.
        unsafe { close_handle(boot.section_handle) };
        boot.section_handle = core::ptr::null_mut();
    }
}

/// Release the lock-event reference and handle. Idempotent.
///
/// # Safety
/// Must run at PASSIVE_LEVEL after the guard has been released.
pub(crate) unsafe fn close_lock_event(boot: &mut BootObjects) {
    if !boot.lock_object.is_null() {
        // SAFETY: this load took exactly one reference.
        unsafe { fsring_sys::ObfDereferenceObject(boot.lock_object) };
        boot.lock_object = core::ptr::null_mut();
    }
    if !boot.lock_handle.is_null() {
        // SAFETY: this load opened exactly this handle.
        unsafe { close_handle(boot.lock_handle) };
        boot.lock_handle = core::ptr::null_mut();
    }
}
