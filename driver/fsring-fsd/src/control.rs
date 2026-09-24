//! Native secure control-device publication and per-file lifetime.

use core::{
    cell::UnsafeCell,
    ffi::c_void,
    mem::MaybeUninit,
    ptr::NonNull,
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};
use fsring_core::{
    adapter::stackexpand::{CleanupExpansionBudget, CleanupExpansionRecourse, resolve_cleanup},
    alloc::{pool_policy, try_alloc},
    controldev::{
        Authorization, ControlDispatchDecision, ControlIoctlRequest, CreateRequest, RequestorId,
        RequestorMode, authorize, decide_control_ioctl, decide_create, demux,
    },
    resolver::ResolvedDdis,
    session::{CleanupBindingClaim, ControlBinding, ControlBindingState},
};
use fsring_sys::{
    BOOLEAN, CCHAR, EX_RUNDOWN_REF, FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, GUID,
    IO_NO_INCREMENT, KPROCESSOR_MODE, MEMORY_ALLOCATION_ALIGNMENT, NTSTATUS, PDEVICE_OBJECT,
    PEPROCESS, PEX_RUNDOWN_REF, PIO_STACK_LOCATION, PIRP, ULONG,
};
use wdk_sys::{
    DO_DEVICE_INITIALIZING, DRIVER_OBJECT, IRP_MJ_CLEANUP, IRP_MJ_CLOSE, IRP_MJ_CREATE,
    IRP_MJ_DEVICE_CONTROL, KEVENT, PFILE_OBJECT, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INTEGER_OVERFLOW, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_DEVICE_STATE,
    STATUS_INVALID_PARAMETER, STATUS_PENDING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

/// The ABI required by `DRIVER_OBJECT::MajorFunction`.
pub type ControlDispatch = unsafe extern "C" fn(PDEVICE_OBJECT, PIRP) -> NTSTATUS;

#[repr(C)]
struct ControlDeviceExtension {
    /// Design section 6.3: every extension begins with the closed device-kind
    /// tag and its root, so a common thunk decides what it is looking at
    /// before it projects one.
    header: crate::driver::ExtensionHeader,
    ddis: ResolvedDdis,
}

#[repr(C)]
pub(crate) struct ControlFileContext {
    rundown: MaybeUninit<EX_RUNDOWN_REF>,
    requestor: AtomicPtr<c_void>,
    binding_phase_tag: AtomicU32,
    binding: UnsafeCell<ControlBinding>,
    lifetime: UnsafeCell<ControlContextLifetime>,
    setup_cancel: MaybeUninit<KEVENT>,
    setup_complete: MaybeUninit<KEVENT>,
}

#[allow(dead_code)]
pub(crate) enum ControlContextLifetime {
    Lease(crate::lifecycle::ControlContextLease),
    LiveCellOwned,
    Completed(crate::lifecycle::CompletedControlRecord),
    Close(crate::lifecycle::CloseContextRight),
    BlockedCellOwned,
}

const BINDING_PHASE_EMPTY: u32 = 0;
const BINDING_PHASE_STAGING: u32 = 1;
const BINDING_PHASE_ACTIVE: u32 = 2;
const BINDING_PHASE_CLOSING_SETUP: u32 = 3;
const BINDING_PHASE_CLOSING_LIVE: u32 = 4;
const BINDING_PHASE_CLOSING_COMPLETE: u32 = 5;
const BINDING_PHASE_CLOSING_BLOCKED: u32 = 6;
const BINDING_PHASE_CLOSING_OPAQUE_RETAINED: u32 = 7;
const BINDING_PHASE_CLOSED: u32 = 8;

pub(crate) const fn binding_phase_tag(state: ControlBindingState) -> u32 {
    match state {
        ControlBindingState::Empty(_) => BINDING_PHASE_EMPTY,
        ControlBindingState::Staging(_) => BINDING_PHASE_STAGING,
        ControlBindingState::Active(_) => BINDING_PHASE_ACTIVE,
        ControlBindingState::ClosingSetup(_) => BINDING_PHASE_CLOSING_SETUP,
        ControlBindingState::ClosingLive(_) => BINDING_PHASE_CLOSING_LIVE,
        ControlBindingState::ClosingComplete { .. } => BINDING_PHASE_CLOSING_COMPLETE,
        ControlBindingState::ClosingBlocked { .. } => BINDING_PHASE_CLOSING_BLOCKED,
        ControlBindingState::ClosingOpaqueRetained { .. } => BINDING_PHASE_CLOSING_OPAQUE_RETAINED,
        ControlBindingState::Closed => BINDING_PHASE_CLOSED,
    }
}

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(struct $name(());)+
    };
}

private_authority_seals!(
    PrivateControlDispatchRundownAuthority,
    PrivateReleasedControlDispatchAuthority,
);

pub(crate) struct ControlDispatchRundownGuard {
    context: NonNull<ControlFileContext>,
    authority: PrivateControlDispatchRundownAuthority,
}

pub(crate) struct NativeCleanupClaim {
    guard: ControlDispatchRundownGuard,
    claim: CleanupBindingClaim,
}

pub(crate) struct ReleasedNativeCleanupClaim {
    context: NonNull<ControlFileContext>,
    claim: CleanupBindingClaim,
    authority: PrivateReleasedControlDispatchAuthority,
}

// `MEMORY_ALLOCATION_ALIGNMENT` is generated from the selected WDK target
// (`shared/ntdef.h:160-165`: 16 on `_WIN64`). Both pool allocation paths
// guarantee at least this alignment. Reject any future context field/layout
// whose Rust alignment would make the typed projection invalid.
const _: () = assert!(
    core::mem::align_of::<ControlFileContext>() <= MEMORY_ALLOCATION_ALIGNMENT as usize,
    "control-file context alignment exceeds the WDK pool allocation guarantee"
);

struct AllocatedFileContext {
    context: *mut ControlFileContext,
}

struct ReferencedFileContext {
    context: *mut ControlFileContext,
}

enum FileContextTerminal {
    Published(NTSTATUS),
    RolledBack(NTSTATUS),
}

impl FileContextTerminal {
    fn status(self) -> NTSTATUS {
        match self {
            Self::Published(status) | Self::RolledBack(status) => status,
        }
    }
}

impl AllocatedFileContext {
    /// Initialize a context in one block returned by the WDK pool allocator.
    ///
    /// # Safety
    /// `block` must be non-null, valid for exactly
    /// `size_of::<ControlFileContext>()` writable bytes, and aligned to
    /// `MEMORY_ALLOCATION_ALIGNMENT`. The compile-time bound above proves that
    /// the WDK pool guarantee satisfies this type's alignment.
    unsafe fn initialize(
        block: *mut u8,
        lease: crate::lifecycle::ControlContextLease,
    ) -> Result<Self, (NTSTATUS, crate::lifecycle::ControlContextLease)> {
        let binding = match ControlBinding::new() {
            Ok(binding) => binding,
            Err(_) => return Err((STATUS_INTEGER_OVERFLOW, lease)),
        };
        let context = block.cast::<ControlFileContext>();
        // SAFETY: `block` is a non-null allocation of exactly the context
        // size. This writes every Rust field without reading the pool bytes.
        unsafe {
            core::ptr::write(
                context,
                ControlFileContext {
                    rundown: MaybeUninit::uninit(),
                    requestor: AtomicPtr::new(core::ptr::null_mut()),
                    binding_phase_tag: AtomicU32::new(binding_phase_tag(binding.state())),
                    binding: UnsafeCell::new(binding),
                    lifetime: UnsafeCell::new(ControlContextLifetime::Lease(lease)),
                    setup_cancel: MaybeUninit::uninit(),
                    setup_complete: MaybeUninit::uninit(),
                },
            );
            fsring_sys::ExInitializeRundownProtection(rundown_ptr(context));
            fsring_sys::c4::KeInitializeEvent(
                core::ptr::addr_of_mut!((*context).setup_cancel).cast::<KEVENT>(),
                fsring_sys::c4::NotificationEvent,
                0,
            );
            fsring_sys::c4::KeInitializeEvent(
                core::ptr::addr_of_mut!((*context).setup_complete).cast::<KEVENT>(),
                fsring_sys::c4::NotificationEvent,
                1,
            );
        }
        Ok(Self { context })
    }

    unsafe fn reference(self, process: PEPROCESS) -> ReferencedFileContext {
        // SAFETY: CREATE obtained a non-null requestor process from its live
        // IRP. The object reference is taken before the pointer is published.
        let _ = unsafe { fsring_sys::ObfReferenceObject(process.cast()) };
        // SAFETY: initialization wrote the atomic field, and this unpublished
        // owner is the only code that can access it yet.
        unsafe { &*core::ptr::addr_of!((*self.context).requestor) }
            .store(process.cast(), Ordering::Release);
        ReferencedFileContext {
            context: self.context,
        }
    }

    unsafe fn rollback(self, status: NTSTATUS) -> FileContextTerminal {
        // SAFETY: this unpublished owner came from the tagged allocation and
        // has not captured a process reference.
        unsafe {
            release_close_or_lease(self.context);
            fsring_sys::ExFreePoolWithTag(self.context.cast(), crate::kernel::POOL_TAG);
        }
        FileContextTerminal::RolledBack(status)
    }
}

impl ControlDispatchRundownGuard {
    unsafe fn acquire(context: NonNull<ControlFileContext>) -> Option<Self> {
        let acquired =
            unsafe { fsring_sys::ExAcquireRundownProtection(rundown_ptr(context.as_ptr())) };
        if acquired == 0 {
            None
        } else {
            Some(Self {
                context,
                authority: PrivateControlDispatchRundownAuthority(()),
            })
        }
    }

    pub(crate) unsafe fn release(self) {
        let Self {
            context,
            authority: PrivateControlDispatchRundownAuthority(()),
        } = self;
        unsafe { fsring_sys::ExReleaseRundownProtection(rundown_ptr(context.as_ptr())) };
    }
}

impl NativeCleanupClaim {
    pub(crate) const fn new(
        guard: ControlDispatchRundownGuard,
        claim: CleanupBindingClaim,
    ) -> Self {
        Self { guard, claim }
    }

    pub(crate) unsafe fn release_outer(self) -> ReleasedNativeCleanupClaim {
        let Self { guard, claim } = self;
        let context = guard.context;
        unsafe { guard.release() };
        ReleasedNativeCleanupClaim {
            context,
            claim,
            authority: PrivateReleasedControlDispatchAuthority(()),
        }
    }
}

impl ReleasedNativeCleanupClaim {
    pub(crate) fn into_parts(self) -> (NonNull<ControlFileContext>, CleanupBindingClaim) {
        let Self {
            context,
            claim,
            authority: PrivateReleasedControlDispatchAuthority(()),
        } = self;
        (context, claim)
    }
}

impl ReferencedFileContext {
    unsafe fn publish(self, file: PFILE_OBJECT, status: NTSTATUS) -> FileContextTerminal {
        // SAFETY: `file` is the live CREATE file object. The context is fully
        // initialized and owns exactly one process reference before this sole
        // publication store.
        unsafe {
            core::ptr::addr_of_mut!((*file).FsContext).write(self.context.cast());
        }
        FileContextTerminal::Published(status)
    }
}

pub(crate) unsafe fn rundown_ptr(context: *mut ControlFileContext) -> PEX_RUNDOWN_REF {
    // SAFETY: callers provide a live context whose `rundown` field is reserved
    // as exact in-place storage for the generated WDK type.
    unsafe { core::ptr::addr_of_mut!((*context).rundown).cast::<EX_RUNDOWN_REF>() }
}

pub(crate) unsafe fn wait_and_release_requestor(context: *mut ControlFileContext) {
    // SAFETY: the stable context shell and initialized rundown object remain
    // live through CLEANUP and until CLOSE frees them. These dispatches run at
    // APC_LEVEL or lower, as required by the blocking rundown wait.
    unsafe {
        fsring_sys::ExWaitForRundownProtectionRelease(rundown_ptr(context));
    }
    // SAFETY: the context remains allocated after the wait. A field-scoped
    // shared reference to the initialized atomic is valid for this one swap;
    // AcqRel pairs with the publication store and makes duplicate teardown
    // observe null.
    let process = unsafe { &*core::ptr::addr_of!((*context).requestor) }
        .swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !process.is_null() {
        // SAFETY: the non-null value is the one reference CREATE stored.
        // Atomic exchange grants this path sole responsibility to release it.
        let _ = unsafe { fsring_sys::ObfDereferenceObject(process) };
    }
}

pub(crate) unsafe fn binding_mut(
    context: NonNull<ControlFileContext>,
) -> &'static mut ControlBinding {
    unsafe { &mut *context.as_ref().binding.get() }
}

pub(crate) unsafe fn binding_ref(context: NonNull<ControlFileContext>) -> &'static ControlBinding {
    unsafe { &*context.as_ref().binding.get() }
}

pub(crate) unsafe fn publish_binding_phase(context: NonNull<ControlFileContext>) {
    let state = unsafe { binding_ref(context).state() };
    unsafe {
        context
            .as_ref()
            .binding_phase_tag
            .store(binding_phase_tag(state), Ordering::Release)
    };
}

pub(crate) unsafe fn setup_cancel_ptr(context: NonNull<ControlFileContext>) -> *mut KEVENT {
    unsafe {
        core::ptr::addr_of!((*context.as_ptr()).setup_cancel)
            .cast_mut()
            .cast::<KEVENT>()
    }
}

pub(crate) unsafe fn setup_complete_ptr(context: NonNull<ControlFileContext>) -> *mut KEVENT {
    unsafe {
        core::ptr::addr_of!((*context.as_ptr()).setup_complete)
            .cast_mut()
            .cast::<KEVENT>()
    }
}

pub(crate) unsafe fn take_lease_for_live(
    context: NonNull<ControlFileContext>,
) -> Result<crate::lifecycle::ControlContextLease, NTSTATUS> {
    let lifetime = unsafe { &mut *context.as_ref().lifetime.get() };
    let previous = core::mem::replace(lifetime, ControlContextLifetime::LiveCellOwned);
    match previous {
        ControlContextLifetime::Lease(lease) => Ok(lease),
        other => {
            *lifetime = other;
            Err(STATUS_INVALID_DEVICE_STATE)
        }
    }
}

/// Take the finalizer's `CompletedControlRecord` out of a context.
///
/// CLEANUP is its only consumer, and it consumes it exactly once: the record
/// carries the `CloseContextRight` that CLOSE later needs, so the caller must
/// put that right back with [`store_close_right`] in the same lock hold. A
/// context that never received a record answers `None` rather than fabricating
/// one.
///
/// # Safety
/// The registry lock is held and `context` is live.
pub(crate) unsafe fn take_completed_record(
    context: NonNull<ControlFileContext>,
) -> Option<crate::lifecycle::CompletedControlRecord> {
    let lifetime = unsafe { &mut *context.as_ref().lifetime.get() };
    let previous = core::mem::replace(lifetime, ControlContextLifetime::BlockedCellOwned);
    match previous {
        ControlContextLifetime::Completed(record) => Some(record),
        other => {
            *lifetime = other;
            None
        }
    }
}

/// Leave the exact close right and its lease in an acknowledged context.
///
/// # Safety
/// The registry lock is held, `context` is live, and its lifetime slot was
/// emptied by [`take_completed_record`] in this same hold.
pub(crate) unsafe fn store_close_right(
    context: NonNull<ControlFileContext>,
    right: crate::lifecycle::CloseContextRight,
) -> Result<(), crate::lifecycle::CloseContextRight> {
    let lifetime = unsafe { &mut *context.as_ref().lifetime.get() };
    match lifetime {
        ControlContextLifetime::BlockedCellOwned => {
            *lifetime = ControlContextLifetime::Close(right);
            Ok(())
        }
        _ => Err(right),
    }
}

/// Whether this context is still owned by its live cell.
///
/// `LiveCellOwned` is exactly the state a generation is in between the terminal
/// claim — which moved the lease into `ClosingControlOwner` — and the
/// finalizer's completed-record transfer. So one predicate answers both "the
/// binding is still ClosingLive with a live lease" and "no completed record has
/// been stored", which are the two deletion-preflight fields the permanent cell
/// cannot see.
///
/// # Safety
/// The registry lock is held and `context` is live.
/// Store the record after the seven-predicate deletion preflight.
///
/// # Safety
/// The registry lock is held and the caller owns the exact `LiveCellOwned`
/// context whose empty completed-record slot was preflighted.
pub(crate) unsafe fn store_completed_control_record_prepared(
    context: NonNull<ControlFileContext>,
    record: crate::lifecycle::CompletedControlRecord,
) {
    let lifetime = unsafe { &mut *context.as_ref().lifetime.get() };
    *lifetime = ControlContextLifetime::Completed(record);
}

/// Publish the already-preflighted closing binding without a refusal edge.
///
/// # Safety
/// The registry lock is held and the matching completed record was installed
/// immediately before this call.
pub(crate) unsafe fn publish_closing_complete_prepared(
    context: NonNull<ControlFileContext>,
    locator: fsring_core::session::SessionLocator,
    result: fsring_core::session::TerminalResult,
) {
    let binding = unsafe { binding_mut(context) };
    unsafe { binding.publish_closing_complete_prepared(locator, result) };
    unsafe { publish_binding_phase(context) };
}

pub(crate) unsafe fn lifetime_is_cell_owned(context: NonNull<ControlFileContext>) -> bool {
    matches!(
        unsafe { &*context.as_ref().lifetime.get() },
        ControlContextLifetime::LiveCellOwned
    )
}

/// Whether the binding is still ClosingLive for this exact generation.
///
/// # Safety
/// The registry lock is held and `context` is live.
pub(crate) unsafe fn binding_is_closing_live(
    context: NonNull<ControlFileContext>,
    locator: fsring_core::session::SessionLocator,
) -> bool {
    matches!(
        unsafe { binding_ref(context).state() },
        ControlBindingState::ClosingLive(current) if current == locator
    )
}

/// Whether the completed-record slot is independently still empty.
///
/// # Safety
/// The registry lock is held and `context` is live.
pub(crate) unsafe fn completed_record_is_absent(context: NonNull<ControlFileContext>) -> bool {
    !matches!(
        unsafe { &*context.as_ref().lifetime.get() },
        ControlContextLifetime::Completed(_)
    )
}

pub(crate) unsafe fn lifetime_is_lease(context: NonNull<ControlFileContext>) -> bool {
    matches!(
        unsafe { &*context.as_ref().lifetime.get() },
        ControlContextLifetime::Lease(_)
    )
}

pub(crate) unsafe fn move_lease_to_close(
    context: NonNull<ControlFileContext>,
) -> Result<(), NTSTATUS> {
    let lifetime = unsafe { &mut *context.as_ref().lifetime.get() };
    let previous = core::mem::replace(lifetime, ControlContextLifetime::BlockedCellOwned);
    match previous {
        ControlContextLifetime::Lease(lease) => {
            *lifetime =
                ControlContextLifetime::Close(crate::lifecycle::CloseContextRight::new(lease));
            Ok(())
        }
        other => {
            *lifetime = other;
            Err(STATUS_INVALID_DEVICE_STATE)
        }
    }
}

/// Consume and release the one CREATE admission lease/right stored in a context.
///
/// # Safety
/// `context` is exclusively owned by an unpublished rollback or CLOSE. Its
/// lease field was initialized and has not already been taken.
unsafe fn release_close_or_lease(context: *mut ControlFileContext) {
    let lifetime = unsafe { &mut *(*context).lifetime.get() };
    let previous = core::mem::replace(lifetime, ControlContextLifetime::BlockedCellOwned);
    match previous {
        ControlContextLifetime::Lease(lease) => unsafe { lease.release() },
        ControlContextLifetime::Close(close) => unsafe { close.release() },
        other => {
            *lifetime = other;
        }
    }
}

/// Take the close authority out of a context *without releasing anything*.
///
/// Deciding and releasing were one step before, and the release happened first:
/// the admission lease went back while `FsContext` still named a live context
/// and the allocation was still there. That is the exact inversion
/// `ControlContextClosePlan` exists to forbid, and unload waits on precisely
/// that admission before it frees callback-visible state.
///
/// The caller holds the registry lock. The finalizer preflights and stores this
/// same slot under that lock, and this function empties the slot before it
/// classifies, so an unlocked caller could let a store land between the two.
unsafe fn take_close_ownership(
    context: *mut ControlFileContext,
) -> (
    fsring_core::adapter::setup::ControlContextCloseOwnership,
    Option<crate::lifecycle::CloseContextRight>,
) {
    use fsring_core::adapter::setup::{
        ControlContextCloseOwnership, ControlContextLifetimeKind, binding_holds_no_installation,
    };
    // The binding's own answer, read in the same hold that takes the slot, so
    // it cannot change between the question and the free. This is what makes
    // the adoption below a check rather than an argument about what a lease in
    // the slot implies.
    //
    // SAFETY: the caller holds the registry lock and CLOSE owns the file
    // object, so this binding is live and cannot move under the read.
    let holds_no_installation = binding_holds_no_installation(unsafe {
        binding_ref(NonNull::new_unchecked(context)).state()
    });
    // SAFETY: the caller holds the registry lock the finalizer preflights and
    // stores this slot under, and CLOSE owns the file object.
    let lifetime = unsafe { &mut *(*context).lifetime.get() };
    let previous = core::mem::replace(lifetime, ControlContextLifetime::BlockedCellOwned);
    // This crate says WHAT is in the slot; core says what CLOSE may do about it.
    // The split is deliberate: `fsring-fsd` has no host test target, so a
    // classification decided here is decided where nothing can watch it be
    // wrong. Core's `for_lifetime` is a total `match`, so a new lifetime
    // without a decision is an E0004 rather than a silent "somebody else owns
    // it".
    let kind = match &previous {
        ControlContextLifetime::Lease(_) => ControlContextLifetimeKind::Lease,
        ControlContextLifetime::LiveCellOwned => ControlContextLifetimeKind::LiveCellOwned,
        ControlContextLifetime::Completed(_) => ControlContextLifetimeKind::Completed,
        ControlContextLifetime::Close(_) => ControlContextLifetimeKind::Close,
        ControlContextLifetime::BlockedCellOwned => ControlContextLifetimeKind::BlockedCellOwned,
    };
    let ownership =
        ControlContextCloseOwnership::for_lifetime(kind).adopt_unused_lease(holds_no_installation);
    match previous {
        ControlContextLifetime::Close(close) => (ownership, Some(close)),
        // The CREATE admission lease nobody else owns. CLOSE adopts it exactly
        // as CLEANUP's precommit would have, with the same constructor, so the
        // plan's third effect releases the admission it was always going to
        // release. Without this the block and the lease were both lost and
        // unload waited for ever on a rundown with no signaller (native review
        // N18-2). A lease core did NOT adopt falls to the arm below and stays
        // in the slot: still a leak, and a disclosed one, because freeing a
        // context something else may still name is the worse failure.
        ControlContextLifetime::Lease(lease) if ownership.may_free() => (
            ownership,
            Some(crate::lifecycle::CloseContextRight::new(lease)),
        ),
        // A `Completed` record stays in the slot: only CLEANUP consumes it, and
        // core answers `CellOwned` until it has. Round 17 took the close right
        // out of it here, and the process-loss and unload scans then
        // dereferenced the freed context (native review N17-1).
        other => {
            *lifetime = other;
            (ownership, None)
        }
    }
}

/// Run one CLOSE deallocation in the order [`ControlContextClosePlan`] fixes.
///
/// The plan is the authority for the order, not this function: each effect is
/// performed exactly as the plan hands it over, and the completion's own proof
/// is checked before returning. A context this CLOSE does not own is detached
/// from the file object and nothing else — no free, no admission release.
///
/// # Safety
/// `file` is the closing file object and `context` its `FsContext`, and CLOSE
/// has exclusive lifecycle ownership of both. `registry`, when present, is the
/// live permanent root this context's cell lives in.
unsafe fn run_close_plan(
    file: *mut wdk_sys::FILE_OBJECT,
    context: *mut ControlFileContext,
    registry: Option<NonNull<crate::lifecycle::KernelSessionRegistry>>,
) {
    use fsring_core::adapter::setup::{
        ControlContextCloseEffect, ControlContextClosePlan, ControlContextCloseProgress,
    };

    // Observe and take the lifetime UNDER the registry lock. The finalizer
    // preflights and stores this slot under that lock, and
    // `take_close_ownership` empties the slot before it classifies: unlocked, a
    // store could land between the two and be overwritten by the restore, or
    // the finalizer's preflight could see the emptied slot and fail-stop. The
    // free and the admission release stay outside -- a spin lock holds
    // DISPATCH_LEVEL.
    let Some(registry) = registry else {
        // No registry, no lock to serialize against: observe nothing, detach,
        // and leave the allocation. A leak, never a race.
        // SAFETY: the caller's ownership contract.
        unsafe { core::ptr::addr_of_mut!((*file).FsContext).write(core::ptr::null_mut()) };
        return;
    };
    // SAFETY (all three lines): the caller's ownership contract; `registry` is
    // the live root, and the lock is held across the take.
    let lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
    let taken = unsafe { take_close_ownership(context) };
    unsafe { lock.release() };
    let (ownership, mut right) = taken;
    let Ok(mut progress) = ControlContextClosePlan::begin(ownership) else {
        // Cell-owned or still leased: detach the handle-facing pointer so no
        // stale `FsContext` survives, and leave the allocation to whoever owns
        // it. Deliberately not a free and not a release.
        // SAFETY: as above.
        unsafe { core::ptr::addr_of_mut!((*file).FsContext).write(core::ptr::null_mut()) };
        return;
    };
    loop {
        match progress {
            ControlContextCloseProgress::Effect(pending) => {
                match pending.effect() {
                    // SAFETY: the caller's ownership contract.
                    ControlContextCloseEffect::DetachFsContext => unsafe {
                        core::ptr::addr_of_mut!((*file).FsContext).write(core::ptr::null_mut());
                    },
                    ControlContextCloseEffect::DestroyAndFreeContext => {
                        // SAFETY: detached above, so nothing can reach it, and
                        // this is the one free of this allocation.
                        unsafe {
                            fsring_sys::ExFreePoolWithTag(context.cast(), crate::kernel::POOL_TAG);
                        }
                    }
                    ControlContextCloseEffect::ReleaseControlContextAdmission => {
                        if let Some(close) = right.take() {
                            // SAFETY: the right was moved out of the context
                            // before the free, and it owns only a registry
                            // pointer, so releasing it after the free is sound.
                            // Unload may observe the rundown reach zero only
                            // here, with the context already gone.
                            unsafe { close.release() };
                        }
                    }
                }
                progress = pending.succeeded();
            }
            ControlContextCloseProgress::Complete(completion) => {
                if !completion.freed_before_admission_release() {
                    unreachable!("the CLOSE plan frees before it releases admission")
                }
                return;
            }
        }
    }
}

unsafe fn state_from_device(device: PDEVICE_OBJECT) -> *mut crate::driver::DriverState {
    if device.is_null() {
        return core::ptr::null_mut();
    }
    let extension = unsafe { (*device).DeviceExtension.cast::<ControlDeviceExtension>() };
    if extension.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { (*extension).header.state }
    }
}

const DEVICE_NAME: [u16; 15] = [
    b'\\' as u16,
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
    b'\\' as u16,
    b'F' as u16,
    b's' as u16,
    b'R' as u16,
    b'i' as u16,
    b'n' as u16,
    b'g' as u16,
    0,
];

const DOS_DEVICE_NAME: [u16; 19] = [
    b'\\' as u16,
    b'D' as u16,
    b'o' as u16,
    b's' as u16,
    b'D' as u16,
    b'e' as u16,
    b'v' as u16,
    b'i' as u16,
    b'c' as u16,
    b'e' as u16,
    b's' as u16,
    b'\\' as u16,
    b'F' as u16,
    b's' as u16,
    b'R' as u16,
    b'i' as u16,
    b'n' as u16,
    b'g' as u16,
    0,
];

const CONTROL_SDDL: [u16; 28] = [
    b'D' as u16,
    b':' as u16,
    b'P' as u16,
    b'(' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b'G' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b';' as u16,
    b'S' as u16,
    b'Y' as u16,
    b')' as u16,
    b'(' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b'G' as u16,
    b'A' as u16,
    b';' as u16,
    b';' as u16,
    b';' as u16,
    b'B' as u16,
    b'A' as u16,
    b')' as u16,
    0,
];

const CONTROL_CLASS_GUID: GUID = GUID {
    Data1: 0xBE80_9396,
    Data2: 0xA636,
    Data3: 0x4F76,
    Data4: [0x9F, 0x01, 0x52, 0x62, 0xF4, 0xBE, 0x35, 0x20],
};

const CONTROL_EXTENSION_SIZE: ULONG = core::mem::size_of::<ControlDeviceExtension>() as ULONG;
const _: () = assert!(
    core::mem::size_of::<ControlDeviceExtension>() <= ULONG::MAX as usize,
    "control-device extension must fit the WDM ULONG size"
);

/// The terminated convention, shared with every other `DefaultSDDLString`
/// site so the two cannot drift apart again. Kept as a local name because
/// this module's callers read better for it.
fn counted_unicode(buffer: &mut [u16]) -> Option<UNICODE_STRING> {
    crate::kernel::counted_unicode_sz(buffer)
}

fn set_major(driver: &mut DRIVER_OBJECT, major: ULONG, dispatch: ControlDispatch) -> bool {
    if let Some(slot) = driver.MajorFunction.get_mut(major as usize) {
        *slot = Some(dispatch);
        true
    } else {
        false
    }
}

/// Install the native dispatch table.
///
/// Runs before any device exists, so no dispatch can arrive against a device
/// whose major functions are still absent.
///
/// # Safety
/// `driver` must be the live loader-owned driver object and this must run once
/// at PASSIVE_LEVEL before DriverEntry returns.
pub(crate) unsafe fn install_dispatch_table(driver: &mut DRIVER_OBJECT) -> NTSTATUS {
    for slot in &mut driver.MajorFunction {
        *slot = Some(dispatch_default);
    }

    if !set_major(driver, IRP_MJ_CREATE, fsring_dispatch_create)
        || !set_major(driver, IRP_MJ_CLEANUP, fsring_dispatch_cleanup)
        || !set_major(driver, IRP_MJ_CLOSE, fsring_dispatch_close)
        || !set_major(
            driver,
            IRP_MJ_DEVICE_CONTROL,
            fsring_dispatch_device_control,
        )
        || !set_major(
            driver,
            wdk_sys::IRP_MJ_FILE_SYSTEM_CONTROL,
            fsring_dispatch_file_system_control,
        )
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    driver.DriverUnload = Some(crate::driver::fsring_driver_unload);
    STATUS_SUCCESS
}

/// Create the secure provider control device, still initializing.
///
/// # Safety
/// `driver` must be the live loader-owned driver object, and this must run
/// once at PASSIVE_LEVEL after the dispatch table is installed. `root` is the
/// sealed proof that every dispatch-visible root owner is initialized.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn create_provider_device(
    driver: &mut DRIVER_OBJECT,
    root: &crate::driver::DispatchReadyRoot,
    ddis: ResolvedDdis,
) -> Result<PDEVICE_OBJECT, NTSTATUS> {
    let state = root.endpoint_state();
    let mut device_name_buffer = DEVICE_NAME;
    let mut sddl_buffer = CONTROL_SDDL;
    let Some(mut device_name) = counted_unicode(&mut device_name_buffer) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    // Named through the mint's own path, not through this module's local
    // alias. A review reinstated the pre-repair defect by pointing a local
    // alias of exactly this shape at the counted mint, in a role whose rule
    // only checked that SOME local name was used; a fully qualified call has
    // no local name to repoint.
    let Some(sddl) = crate::kernel::counted_unicode_sz(&mut sddl_buffer) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let class_guid = CONTROL_CLASS_GUID;
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();

    // SAFETY: the counted descriptors borrow stack arrays for this
    // synchronous PASSIVE_LEVEL call; the class GUID and writable out pointer
    // also remain live through the call.
    let create_status = unsafe {
        crate::kernel::create_secure_device(
            driver,
            CONTROL_EXTENSION_SIZE,
            &raw mut device_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0 as BOOLEAN,
            &raw const sddl,
            &raw const class_guid,
            &raw mut device,
        )
    };
    if create_status < 0 {
        return Err(create_status);
    }
    if device.is_null() {
        return Err(STATUS_UNSUCCESSFUL);
    }

    // SAFETY: a nonzero extension size was requested and successful device
    // creation owns this exact extension storage until delete.
    let extension = unsafe { (*device).DeviceExtension.cast::<ControlDeviceExtension>() };
    if extension.is_null() {
        // SAFETY: the device was created and is deleted exactly once here.
        unsafe { crate::kernel::delete_device(device) };
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: the extension is uninitialized storage of the exact requested
    // size. It is written once while the device is still initializing.
    unsafe {
        core::ptr::write(
            extension,
            ControlDeviceExtension {
                header: crate::driver::ExtensionHeader {
                    kind: fsring_core::volume::DeviceKind::ProviderControl as u32,
                    state,
                },
                ddis,
            },
        );
    }
    Ok(device)
}

/// Create the provider's DOS link.
///
/// # Safety
/// Must run at PASSIVE_LEVEL after the provider device exists.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
pub(crate) unsafe fn create_dos_link() -> Result<(), NTSTATUS> {
    let mut device_name_buffer = DEVICE_NAME;
    let mut dos_name_buffer = DOS_DEVICE_NAME;
    let Some(mut device_name) = counted_unicode(&mut device_name_buffer) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let Some(mut dos_name) = counted_unicode(&mut dos_name_buffer) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    // SAFETY: both descriptors are backed by stack arrays for this
    // synchronous call.
    let status =
        unsafe { crate::kernel::create_symbolic_link(&raw mut dos_name, &raw mut device_name) };
    if status < 0 {
        return Err(status);
    }
    Ok(())
}

/// Remove the provider's DOS link. Idempotent on a teardown path.
///
/// # Safety
/// Must run at PASSIVE_LEVEL.
pub(crate) unsafe fn remove_dos_link() {
    let mut dos_name_buffer = DOS_DEVICE_NAME;
    if let Some(mut dos_name) = counted_unicode(&mut dos_name_buffer) {
        // SAFETY: the descriptor is backed by the local array for the
        // synchronous delete.
        let _ = unsafe { crate::kernel::delete_symbolic_link(&raw mut dos_name) };
    }
}

/// Clear `DO_DEVICE_INITIALIZING` on the provider endpoint.
///
/// # Safety
/// `device` must be this driver's provider control device.
pub(crate) unsafe fn publish(device: PDEVICE_OBJECT) {
    // SAFETY: the caller's device contract; the single publication store.
    unsafe {
        (*device).Flags &= !DO_DEVICE_INITIALIZING;
    }
}

/// Make the provider endpoint un-openable again during a failed load's unwind.
///
/// # Safety
/// As [`publish`].
pub(crate) unsafe fn unpublish(device: PDEVICE_OBJECT) {
    // SAFETY: the caller's device contract.
    unsafe {
        (*device).Flags |= DO_DEVICE_INITIALIZING;
    }
}

unsafe fn complete(irp: PIRP, status: NTSTATUS) -> NTSTATUS {
    // SAFETY: dispatch receives a live IRP; the zero-information form is the
    // one every control path except SETUP uses.
    unsafe { complete_with(irp, status, 0) }
}

unsafe fn complete_with(irp: PIRP, status: NTSTATUS, information: usize) -> NTSTATUS {
    // SAFETY: dispatch receives a live IRP. Both output fields are written
    // before the single completion call, and the IRP is never touched after.
    unsafe {
        core::ptr::addr_of_mut!((*irp).IoStatus.__bindgen_anon_1.Status).write(status);
        core::ptr::addr_of_mut!((*irp).IoStatus.Information).write(information as u64);
        crate::kernel::complete_request(irp, IO_NO_INCREMENT as CCHAR);
    }
    status
}

fn requestor_mode(mode: KPROCESSOR_MODE) -> RequestorMode {
    if i32::from(mode) == wdk_sys::_MODE::UserMode {
        RequestorMode::UserMode
    } else {
        RequestorMode::KernelMode
    }
}

const _: () = assert!(
    usize::BITS == u64::BITS,
    "control requestor identity requires a 64-bit kernel target"
);

fn requestor_id(process: *mut c_void) -> RequestorId {
    // The core identity is deliberately opaque: this exposes only the pointer
    // address for equality and never projects or dereferences EPROCESS. The
    // compile-time width assertion above makes this cast non-truncating on both
    // supported kernel targets.
    RequestorId(process.addr() as u64)
}

fn decision_status(decision: ControlDispatchDecision) -> NTSTATUS {
    match decision {
        ControlDispatchDecision::Complete(status) => status,
        // An adapter-owned decision that reaches here was never routed, which
        // is a driver bug; refusing is the only safe synchronous answer.
        ControlDispatchDecision::Unknown
        | ControlDispatchDecision::DispatchSetup
        | ControlDispatchDecision::DispatchEnter => STATUS_INVALID_DEVICE_REQUEST,
    }
}

unsafe fn current_file_object(irp: PIRP) -> PFILE_OBJECT {
    // SAFETY: dispatch owns a live IRP whose current stack location satisfies
    // the WDK inline's invariant for the duration of this projection.
    let stack = unsafe { fsring_sys::io_get_current_irp_stack_location(irp) };
    if stack.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the non-null current stack location remains borrowed from
        // the live IRP; this copies its nullable file-object pointer once.
        unsafe { (*stack).FileObject }
    }
}

unsafe fn decide_acquired_control_ioctl(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    stack: PIO_STACK_LOCATION,
    context: *mut ControlFileContext,
    information: *mut usize,
) -> NTSTATUS {
    // SAFETY: the caller holds this context's rundown protection, so the
    // initialized atomic field and any captured process reference remain live.
    let captured_process =
        unsafe { &*core::ptr::addr_of!((*context).requestor) }.load(Ordering::Acquire);
    if captured_process.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // SAFETY: the live IRP owns its current requestor-process pointer for this
    // synchronous query. A null result fails closed before any process or
    // buffered-input dereference.
    let current_process = unsafe { fsring_sys::IoGetRequestorProcess(irp) };
    if current_process.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // SAFETY: the live IRP remains owned by this dispatch. This direct scalar
    // field is read only after both native process identities are non-null.
    let mode = requestor_mode(unsafe { (*irp).RequestorMode });
    let captured = requestor_id(captured_process);
    let current = requestor_id(current_process.cast());
    match authorize(mode, captured, current) {
        Authorization::Admitted(_) => {}
        refused @ Authorization::Refused => return refused.status(),
    }

    // SAFETY: this is the current IRP_MJ_DEVICE_CONTROL stack location. The
    // generated anonymous union member is copied into a local before its
    // scalar fields are read. Authorization above precedes this demux.
    let parameters = unsafe { (*stack).Parameters.DeviceIoControl };
    let code = parameters.IoControlCode;
    if demux(code).is_none() {
        // The pure decision performs the authoritative unknown-code
        // classification. Its input is deliberately empty because an unknown
        // transfer method must not cause SystemBuffer to be interpreted.
        return decision_status(decide_control_ioctl(ControlIoctlRequest {
            mode,
            captured,
            current,
            code,
            input: &[],
        }));
    }

    let input_length = parameters.InputBufferLength as usize;
    // SAFETY: every registered control code is METHOD_BUFFERED, so the active
    // AssociatedIrp union member is SystemBuffer. The pointer is copied only
    // after authorization and the closed-registry check.
    let system_buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer }
        .cast::<u8>()
        .cast_const();
    let input = if input_length == 0 || system_buffer.is_null() {
        // Rust requires a non-null pointer even for a zero-length
        // `from_raw_parts`. Null plus nonzero declared length is intentionally
        // represented as empty-invalid input for the pure validator.
        &[]
    } else {
        // SAFETY: METHOD_BUFFERED makes the I/O manager's non-null
        // SystemBuffer valid for InputBufferLength bytes for this IRP. The
        // slice cannot escape this synchronous decision.
        unsafe { core::slice::from_raw_parts(system_buffer, input_length) }
    };

    let decision = decide_control_ioctl(ControlIoctlRequest {
        mode,
        captured,
        current,
        code,
        input,
    });
    match decision {
        ControlDispatchDecision::DispatchSetup => {
            // SAFETY: the rundown is held, the device and IRP are live, and the
            // decision above proves the caller was admitted.
            unsafe {
                run_setup(
                    device,
                    irp,
                    stack,
                    context,
                    current_process.cast(),
                    information,
                )
            }
        }
        ControlDispatchDecision::DispatchEnter => {
            // SAFETY: the rundown is held and the decision above proves the
            // caller was admitted; the binding lives inside this context.
            unsafe { run_enter(device, irp, stack, context, information) }
        }
        ControlDispatchDecision::Complete(_) | ControlDispatchDecision::Unknown => {
            decision_status(decision)
        }
    }
}

/// The trusted device-kind tag of one dispatch target.
///
/// Every common thunk reads only this before it projects anything, so a
/// provider path can never reinterpret a mounted volume as a control device.
///
/// # Safety
/// `device` must be null or a live device this driver created.
unsafe fn device_kind(device: PDEVICE_OBJECT) -> Option<fsring_core::volume::DeviceKind> {
    if device.is_null() {
        return None;
    }
    // SAFETY: every device this driver creates writes its extension header
    // before it leaves `DO_DEVICE_INITIALIZING`.
    let header = unsafe {
        (*device)
            .DeviceExtension
            .cast::<crate::driver::ExtensionHeader>()
    };
    // SAFETY: the projection null-checks the extension itself.
    unsafe { crate::driver::ExtensionHeader::kind_of(header) }
}

/// Is this CREATE a root open of the device itself?
///
/// # Safety
/// `file` must be null or the live file object of a CREATE.
unsafe fn is_root_open(file: PFILE_OBJECT) -> bool {
    if file.is_null() {
        return false;
    }
    // SAFETY: the caller's file-object contract; both fields are read once.
    unsafe { (*file).FileName.Length == 0 && (*file).RelatedFileObject.is_null() }
}

/// Route one non-provider request to the role its tag names.
///
/// Returns `None` for the provider endpoint, whose own authorization and
/// classifier stay in this module.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
unsafe fn route_volume_role(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    major: u8,
    minor_or_ioctl: u32,
    root_open: bool,
) -> Option<NTSTATUS> {
    // SAFETY: the caller's device contract.
    let kind = unsafe { device_kind(device) }?;
    if matches!(kind, fsring_core::volume::DeviceKind::ProviderControl) {
        return None;
    }
    // SAFETY: as above; the closed match inside is the only edge, so the stack
    // audit can see every one of them.
    Some(unsafe {
        crate::volume::route_by_kind(kind, device, irp, major, minor_or_ioctl, root_open)
    })
}

/// Hand one admitted ENTER to its native adapter.
///
/// # Safety
/// The file's rundown is held and `stack` is the current control stack
/// location of the live `irp`.
unsafe fn run_enter(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    stack: PIO_STACK_LOCATION,
    context: *mut ControlFileContext,
    information: *mut usize,
) -> NTSTATUS {
    if device.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let extension = unsafe { (*device).DeviceExtension.cast::<ControlDeviceExtension>() };
    if extension.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    let state = unsafe { (*extension).header.state };
    // SAFETY: this is the current IRP_MJ_DEVICE_CONTROL stack location; the
    // generated anonymous union member is copied into a local first.
    let parameters = unsafe { (*stack).Parameters.DeviceIoControl };
    // SAFETY: ENTER is METHOD_BUFFERED, so the active AssociatedIrp union
    // member is SystemBuffer.
    let system_buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer }.cast::<u8>();
    // SAFETY: the retained root owns every native operation the ENTER performs.
    unsafe {
        crate::session::fsring_dispatch_enter(
            state,
            context.cast(),
            irp,
            system_buffer,
            parameters.InputBufferLength as usize,
            parameters.OutputBufferLength as usize,
            information,
        )
    }
}

/// Hand one admitted SETUP to its native adapter.
///
/// # Safety
/// The file's rundown is held, `device` is this driver's provider endpoint, and
/// `requestor` is the live IRP requestor process.
unsafe fn run_setup(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    stack: PIO_STACK_LOCATION,
    context: *mut ControlFileContext,
    requestor: fsring_sys::PEPROCESS,
    information: *mut usize,
) -> NTSTATUS {
    if device.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: a live device this driver created owns both fields.
    let (driver, extension) = unsafe {
        (
            (*device).DriverObject,
            (*device).DeviceExtension.cast::<ControlDeviceExtension>(),
        )
    };
    if driver.is_null() || extension.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the extension is immutable after device publication.
    let state = unsafe { (*extension).header.state };
    if state.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // SAFETY: this is the current IRP_MJ_DEVICE_CONTROL stack location; the
    // generated anonymous union member is copied into a local first.
    let parameters = unsafe { (*stack).Parameters.DeviceIoControl };
    let input_length = parameters.InputBufferLength as usize;
    let output_length = parameters.OutputBufferLength as usize;
    // SAFETY: SETUP is METHOD_BUFFERED, so the active AssociatedIrp union
    // member is SystemBuffer.
    let system_buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer }.cast::<u8>();

    // SAFETY: the retained root owns every native operation the SETUP performs;
    // the binding lives inside the per-file context whose rundown is held.
    unsafe {
        crate::session::fsring_dispatch_setup(
            driver,
            state,
            context.cast(),
            system_buffer,
            input_length,
            output_length,
            requestor,
            information,
        )
    }
}

unsafe extern "C" fn dispatch_default(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    // SAFETY: the I/O manager supplies a live IRP to dispatch.
    unsafe { complete(irp, STATUS_INVALID_DEVICE_REQUEST) }
}

/// # Safety
/// The I/O manager supplies a live device object and a live IRP whose
/// current stack location has not yet been completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_dispatch_create(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    // SAFETY: the I/O manager supplies a live IRP and current stack location.
    let file = unsafe { current_file_object(irp) };
    if file.is_null() {
        // SAFETY: the I/O manager still owns the live IRP on this defensive
        // malformed-stack path.
        return unsafe { complete(irp, STATUS_INVALID_DEVICE_REQUEST) };
    }

    // SAFETY: a new FILE_OBJECT has no installed per-file context. Writing
    // null before any fallible operation makes that failure invariant local.
    unsafe {
        core::ptr::addr_of_mut!((*file).FsContext).write(core::ptr::null_mut());
    }
    // SAFETY: the tag is read before any extension is projected.
    if let Some(status) =
        unsafe { route_volume_role(device, irp, IRP_MJ_CREATE as u8, 0, is_root_open(file)) }
    {
        // SAFETY: the role answered; the IRP is live and uncompleted.
        return unsafe { complete(irp, status) };
    }
    // SAFETY: `irp` and `file` stay live through dispatch; these direct fields
    // are copied before allocation so precedence cannot allocate early.
    let (mode, file_name_empty, related_file_object_null) = unsafe {
        (
            requestor_mode((*irp).RequestorMode),
            (*file).FileName.Length == 0,
            (*file).RelatedFileObject.is_null(),
        )
    };
    let eligible = decide_create(CreateRequest {
        mode,
        file_name_empty,
        related_file_object_null,
        context_alloc_ok: true,
    });
    if !eligible.context_installed {
        // SAFETY: no context was allocated or published and the IRP remains
        // live for its one completion.
        return unsafe { complete(irp, eligible.status) };
    }

    let extension = if device.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: a live dispatch device owns the extension initialized before
        // `DO_DEVICE_INITIALIZING` was cleared.
        unsafe { (*device).DeviceExtension.cast::<ControlDeviceExtension>() }
    };
    if extension.is_null() {
        let failed = decide_create(CreateRequest {
            mode,
            file_name_empty,
            related_file_object_null,
            context_alloc_ok: false,
        });
        // SAFETY: no allocation exists and the IRP remains live.
        return unsafe { complete(irp, failed.status) };
    }

    // Acquire CREATE/control-context admission before allocating or publishing
    // `FsContext`. The typed lease is the only release authority; neither the
    // raw registry pointer nor the WDK BOOLEAN escapes this transition.
    // SAFETY: the trusted extension points to the initialized driver root,
    // which remains permanent while this dispatch is reachable.
    let state = unsafe { (*extension).header.state };
    let registry = if state.is_null() {
        None
    } else {
        // SAFETY: the root is live, and `sessions` is permanent in-place
        // storage initialized before provider creation.
        NonNull::new(unsafe { core::ptr::addr_of_mut!((*state).sessions) })
    };
    let Some(registry) = registry else {
        // SAFETY: no allocation or context publication occurred.
        return unsafe { complete(irp, STATUS_UNSUCCESSFUL) };
    };
    // SAFETY: `registry` is the initialized permanent root from the trusted
    // provider extension.
    let lease = match unsafe { crate::lifecycle::ControlContextLease::acquire(registry) } {
        Ok(lease) => lease,
        Err(status) => {
            // SAFETY: acquisition failed without minting authority or
            // publishing a context.
            return unsafe { complete(irp, status) };
        }
    };

    // SAFETY: the extension is immutable after device publication; copying the
    // latched table creates no long-lived reference into the device object.
    let ddis = unsafe { (*extension).ddis };
    let mut pool = crate::kernel::KernelPool::new(&ddis);
    let policy = pool_policy(crate::platform::PROFILE, ddis.all_resolved());
    let block = match try_alloc(
        &mut pool,
        policy,
        core::mem::size_of::<ControlFileContext>(),
    ) {
        Ok(block) => block,
        Err(_) => {
            // SAFETY: allocation failed, so the unpublished lease has no
            // context owner and is consumed here.
            unsafe { lease.release() };
            let failed = decide_create(CreateRequest {
                mode,
                file_name_empty,
                related_file_object_null,
                context_alloc_ok: false,
            });
            // SAFETY: allocation failed, so no shell/reference exists and the
            // live IRP has not been completed.
            return unsafe { complete(irp, failed.status) };
        }
    };
    // SAFETY: `try_alloc` returned a non-null block of the requested exact
    // size. WDK pool allocations are aligned to
    // `MEMORY_ALLOCATION_ALIGNMENT` (16 on both supported 64-bit targets), and
    // the compile-time bound above proves that is sufficient for this context.
    // Initialization writes the Rust fields and initializes rundown.
    let allocated = match unsafe { AllocatedFileContext::initialize(block, lease) } {
        Ok(allocated) => allocated,
        Err((status, lease)) => {
            unsafe {
                lease.release();
                fsring_sys::ExFreePoolWithTag(block.cast(), crate::kernel::POOL_TAG);
            }
            return unsafe { complete_with(irp, status, 0) };
        }
    };
    // SAFETY: the dispatch owns a live IRP for this synchronous query.
    let process = unsafe { fsring_sys::IoGetRequestorProcess(irp) };

    let terminal = if process.is_null() {
        let failed = decide_create(CreateRequest {
            mode,
            file_name_empty,
            related_file_object_null,
            context_alloc_ok: false,
        });
        // SAFETY: no process reference was captured, so rollback frees the
        // unpublished tagged allocation and leaves `FsContext` null.
        unsafe { allocated.rollback(failed.status) }
    } else {
        let succeeded = decide_create(CreateRequest {
            mode,
            file_name_empty,
            related_file_object_null,
            context_alloc_ok: true,
        });
        // SAFETY: the non-null requestor belongs to the live CREATE IRP.
        let referenced = unsafe { allocated.reference(process) };
        // SAFETY: context initialization and its sole process reference are
        // complete, and `file` remains live until CREATE completes.
        unsafe { referenced.publish(file, succeeded.status) }
    };

    // SAFETY: the typed terminal consumed the context through rollback or
    // publication, and the IRP has not yet been completed.
    unsafe { complete(irp, terminal.status()) }
}

/// The stack this driver asks the kernel for before it runs a CLEANUP
/// terminal claim.
///
/// The audit enforces a 30720-byte chain against this 40960-byte request.
/// That gap is declared headroom: the gate turns red well before the stack
/// actually ends.
///
/// Sized to match `SETUP_STACK_EXPANSION_BYTES`, and for the same reason. The
/// deepest CLEANUP terminal chain measures 9976 bytes, which is 1784 over the
/// 8192-byte bound every non-expansion root is held to, and that overrun is
/// not slack: it is `run_terminal` (3240) and `run_checkpoint_teardown` (2808)
/// holding the affine owners of a whole generation live across the teardown
/// they are performing. Five attempts to fold, split, or re-inline those
/// frames were each refuted by measuring the linked image -- three of them
/// made the chain longer. The path needs the stack; it does not need
/// rewriting.
///
/// Well below the DDI's 71680-byte `MAXIMUM_EXPANSION_SIZE` ceiling.
pub const CLEANUP_STACK_EXPANSION_BYTES: usize = 40960;

// The DDI refuses a size above `MAXIMUM_EXPANSION_SIZE`, which WDK 10.0.26100
// `km/ntddk.h:9805` defines as `KERNEL_LARGE_STACK_SIZE - (PAGE_SIZE / 2)`.
// `KERNEL_LARGE_STACK_SIZE` is `0x12000` under `_AMD64_` and `_ARM64_` -- this
// driver's two targets -- 61440 under `_X86_` and `0xF000` under `_ARM_`, so
// the smallest ceiling any of the four yields is 61440 - 2048. The bound is
// written as that smallest value, not this target's, so it holds wherever this
// driver is built.
//
// This assertion turns one listed refusal, `STATUS_INVALID_PARAMETER_3` ("the
// Size parameter is greater than MAXIMUM_EXPANSION_SIZE"), into a build failure.
// It excludes that cause only. `STATUS_STACK_OVERFLOW` is another the DDI
// lists, and no wait clears it, which is why the retry reads the status rather
// than assuming every refusal is a shortage (round-20 native review, N1). See
// `stackexpand::resolve_cleanup`.
const _: () = assert!(
    CLEANUP_STACK_EXPANSION_BYTES <= 59392,
    "CLEANUP stack expansion exceeds the smallest MAXIMUM_EXPANSION_SIZE"
);

// The one refusal the CLEANUP retry waits on, pinned to the WDK's own
// definition: core writes the literal because it cannot see `ntstatus.h`.
const _: () = assert!(
    fsring_core::adapter::stackexpand::STATUS_NO_MEMORY == wdk_sys::STATUS_NO_MEMORY,
    "core's STATUS_NO_MEMORY is not ntstatus.h's"
);

/// One wait between a refused expansion and the next attempt, in 100ns units.
///
/// 10 ms: long enough that a machine which cannot allocate a kernel stack is
/// not asked thousands of times a second, short enough that the handle close
/// this blocks resumes as soon as the condition clears. Core's
/// `CLEANUP_EXPANSION_ATTEMPTS` bounds how many of these one arrival waits.
const EXPANSION_RETRY_INTERVAL_100NS: i64 = 100_000;

/// What the CLEANUP dispatch must do once the terminal claim has run.
///
/// Deliberately not the terminal outcome itself. Every variant of that outcome
/// carries owners, and this value is what crosses back out of an expanded
/// stack that is released the instant the callout returns.
#[derive(Clone, Copy)]
enum CleanupTerminalOutcome {
    /// Teardown is done, absent, or not this route's business.
    Proceed,
    /// A permanent fail-stop, a route that refuses this arrival, or an
    /// expansion this dispatch gave up on.
    Refuse,
}

/// What `fsring_cleanup_callout` reads, and where it leaves its answer.
///
/// This block lives on `fsring_dispatch_cleanup`'s own frame, not on the
/// expanded stack, so it OUTLIVES the callout that writes into it — `outcome`
/// is read back only after the callout has already returned. The expanded
/// stack itself is released the moment the callout returns; a pointer into
/// *it* that escaped the callout would dangle immediately, which is the
/// property this layout exists to prevent.
///
/// No affine owner crosses this boundary in either direction. The counted
/// claim is taken inside the callout, so a refused expansion leaves the
/// generation exactly as it found it.
#[repr(C)]
struct CleanupCalloutBlock {
    registry: *mut crate::lifecycle::KernelSessionRegistry,
    context: *mut ControlFileContext,
    /// `None` until the callout completes. A `None` seen after a successful
    /// expansion is the fault `stackexpand::resolve` names, not a success.
    outcome: Option<CleanupTerminalOutcome>,
}

/// The counted CLEANUP terminal claim, on whatever stack the callout gave it.
///
/// # Safety
/// Invoked only by `fsring_cleanup_callout`, at PASSIVE_LEVEL, holding no outer
/// file rundown -- released before the callout, or never acquired because the
/// fence had already run it down -- which is what makes the wait inside
/// `claim_native_cleanup_route` legal, and with `registry` and `context` live
/// for the whole call.
unsafe fn run_cleanup_terminal(
    registry: NonNull<crate::lifecycle::KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
) -> CleanupTerminalOutcome {
    use fsring_core::adapter::lifecycle::{CleanupContinuation, CleanupPass, continue_cleanup};

    let mut pass = CleanupPass::First;
    loop {
        // SAFETY: the caller's contract, unchanged across passes.
        let result = unsafe { run_cleanup_route_pass(registry, context) };
        match continue_cleanup(pass, result) {
            // The pass ran or joined terminal work, which consumed its binding
            // claim before the finalizer published. Only a second claim observes
            // `ClosingComplete` and acknowledges the record; without it CLOSE,
            // which frees only an acknowledged context, frees nothing.
            CleanupContinuation::ReclaimOnce if pass == CleanupPass::First => {
                pass = CleanupPass::Reclaim;
            }
            // Core never answers this for a reclaim. Refusing rather than
            // looping keeps a future wrong answer finite.
            CleanupContinuation::ReclaimOnce | CleanupContinuation::Refuse => {
                return CleanupTerminalOutcome::Refuse;
            }
            CleanupContinuation::Proceed => return CleanupTerminalOutcome::Proceed,
        }
    }
}

/// One claim of CLEANUP's committed route, reduced to what `continue_cleanup`
/// decides on.
///
/// # Safety
/// As `run_cleanup_terminal`: PASSIVE_LEVEL, no lock and no dispatch rundown
/// held, `registry` and `context` live for the whole call.
unsafe fn run_cleanup_route_pass(
    registry: NonNull<crate::lifecycle::KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
) -> fsring_core::adapter::lifecycle::CleanupRouteResult {
    use fsring_core::adapter::lifecycle::{CleanupRouteResult, TerminalOutcomeKind};

    // `claim_native_cleanup_route` takes the claim under the registry lock, and
    // acknowledges a completed record inside that same hold.
    let route = unsafe {
        crate::lifecycle::claim_native_cleanup_route(
            registry,
            context,
            fsring_core::session::TerminalRequest::Cleanup,
        )
    };
    match route {
        Ok(crate::lifecycle::NativeCleanupRoute::Terminal(disposition)) => {
            // SAFETY: PASSIVE_LEVEL, no lock and no short guard held.
            let outcome = unsafe {
                crate::fence::run_terminal_from_disposition(registry, context, disposition)
            };
            match outcome {
                crate::fence::TerminalOutcome::Completed(_) => {
                    CleanupRouteResult::Terminal(TerminalOutcomeKind::Completed)
                }
                crate::fence::TerminalOutcome::Blocked(_) => {
                    CleanupRouteResult::Terminal(TerminalOutcomeKind::Blocked)
                }
                // Nothing was claimed, which is what `Refused` says. Core
                // carried a `NotLive` kind for this and answered `ReclaimOnce`;
                // that row was unreachable and unfalsifiable (native review
                // N18-5). The variant is constructed only in
                // `run_terminal_arrival`, which has no production caller --
                // not "never constructed", as this comment said until round 21
                // (round-20 native review, N4).
                crate::fence::TerminalOutcome::NotLive => CleanupRouteResult::Refused,
            }
        }
        // This route used to carry the finalizer's `CompletedControlRecord` out
        // of the registry lock, and a catch-all arm dropped it, taking the
        // `CloseContextRight` with it. The record is acknowledged inside the
        // hold that took it, and what arrives here is only the answer.
        Ok(crate::lifecycle::NativeCleanupRoute::CompletedControl { .. }) => {
            CleanupRouteResult::CompletedAcknowledged
        }
        Ok(crate::lifecycle::NativeCleanupRoute::OpaqueRetained(_)) => {
            CleanupRouteResult::OpaqueRetained
        }
        Ok(crate::lifecycle::NativeCleanupRoute::Blocked { .. }) => CleanupRouteResult::Blocked,
        Ok(crate::lifecycle::NativeCleanupRoute::Empty) => CleanupRouteResult::Empty,
        Ok(crate::lifecycle::NativeCleanupRoute::Setup(_)) => CleanupRouteResult::Setup,
        Ok(crate::lifecycle::NativeCleanupRoute::AlreadyClosed) => {
            CleanupRouteResult::AlreadyClosed
        }
        Err(_status) => CleanupRouteResult::Refused,
    }
}

/// The retained CLEANUP callout root.
///
/// A stable link-map and PDB name: this exact spelling is declared as an
/// expansion root in `driver/audit/c4-stack-roots.json`, judged against the
/// stack this driver asks for rather than against the default kernel stack
/// every other root is judged by.
///
/// This symbol is EXPORTED from the final image, so the audit's refusal of a
/// direct call is IMAGE-LOCAL: it sees every call instruction in this image's
/// own disassembly, not a call a separately loaded module could make into this
/// export from outside it. Within that scope, reaching it other than through
/// `KeExpandKernelStackAndCallout` would put roughly 9976 bytes back on the
/// 24576-byte default x64 kernel stack (32768 on ARM64) — past the 8192-byte
/// chain bound every non-expansion root is held to, which is the whole reason
/// this callout exists.
///
/// # Safety
/// Invoked only by `KeExpandKernelStackAndCallout` from
/// `fsring_dispatch_cleanup`, at PASSIVE_LEVEL, with `parameter` the live
/// `CleanupCalloutBlock` on that dispatch's own frame.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_cleanup_callout(parameter: fsring_sys::PVOID) {
    if parameter.is_null() {
        // Leaving the slot unwritten is the honest report: the dispatch reads
        // it as `SlotUnwritten` and refuses the arrival, which claims nothing.
        return;
    }
    let block = parameter.cast::<CleanupCalloutBlock>();
    // SAFETY: the caller's contract is a live block whose two pointer fields
    // were written by the dispatch before the expansion was requested.
    let outcome = unsafe {
        run_cleanup_terminal(
            NonNull::new_unchecked((*block).registry),
            NonNull::new_unchecked((*block).context),
        )
    };
    // SAFETY: the block is this callout's only writer for the whole call.
    unsafe {
        (*block).outcome = Some(outcome);
    }
}

/// # Safety
/// The I/O manager supplies a live device object and a live IRP whose
/// current stack location has not yet been completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_dispatch_cleanup(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    // SAFETY: the tag is read before any extension is projected.
    if let Some(status) = unsafe { route_volume_role(device, irp, IRP_MJ_CLEANUP as u8, 0, true) } {
        // SAFETY: the role answered; the IRP is live and uncompleted.
        return unsafe { complete(irp, status) };
    }
    // SAFETY: the I/O manager supplies a live IRP and current stack location.
    let file = unsafe { current_file_object(irp) };
    if !file.is_null() {
        // SAFETY: successful CREATE published this stable pointer before
        // completion; CLEANUP reads but deliberately does not detach it.
        let context = unsafe { (*file).FsContext.cast::<ControlFileContext>() };
        if let Some(context) = NonNull::new(context) {
            let state = unsafe { state_from_device(device) };
            if state.is_null() {
                return unsafe { complete(irp, STATUS_INVALID_DEVICE_STATE) };
            }
            let registry =
                unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*state).sessions)) };

            // Only a precommit binding needs this dispatch's rundown. A refused
            // acquisition means the fence's `WaitControlRundown` already ran it
            // down: a process-loss or unload terminal won while this handle was
            // open, so the binding is committed. Completing the IRP at once here
            // is what left that terminal's record unacknowledged and CLOSE with
            // nothing it may free (native review N17-2). The committed route
            // holds no dispatch rundown and needs none: IRP_MJ_CLEANUP completes
            // before IRP_MJ_CLOSE for this file object, and CLOSE frees only a
            // context that route acknowledged.
            let precommit = match unsafe { ControlDispatchRundownGuard::acquire(context) } {
                None => None,
                Some(guard) => {
                    let lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
                    let claim = unsafe { binding_mut(context).claim_cleanup() };
                    if claim.is_ok() {
                        unsafe { publish_binding_phase(context) };
                    }
                    unsafe { lock.release() };
                    let Ok(claim) = claim else {
                        unsafe { guard.release() };
                        return unsafe { complete(irp, STATUS_INVALID_DEVICE_STATE) };
                    };
                    // The affine wrapper proves that the exact acquisition used
                    // to claim CLEANUP is gone before either blocking wait can
                    // begin.
                    let (_, claim) =
                        unsafe { NativeCleanupClaim::new(guard, claim).release_outer() }
                            .into_parts();
                    fsring_core::adapter::setup::PrecommitCleanupPlan::begin(claim).ok()
                }
            };
            match precommit {
                Some(mut progress) => loop {
                    progress = match progress {
                        fsring_core::adapter::setup::PrecommitCleanupProgress::Effect(effect) => {
                            use fsring_core::adapter::setup::PrecommitCleanupEffect;
                            match effect.effect() {
                                PrecommitCleanupEffect::ReleaseOuterGuard => {}
                                PrecommitCleanupEffect::SignalSetupCancel => unsafe {
                                    fsring_sys::c4::KeSetEvent(
                                        setup_cancel_ptr(context),
                                        IO_NO_INCREMENT as i32,
                                        0,
                                    );
                                },
                                PrecommitCleanupEffect::WaitFileRundown => unsafe {
                                    wait_and_release_requestor(context.as_ptr());
                                },
                                PrecommitCleanupEffect::WaitSetupComplete => unsafe {
                                    let _ = fsring_sys::c4::KeWaitForSingleObject(
                                        setup_complete_ptr(context).cast(),
                                        0,
                                        0,
                                        0,
                                        core::ptr::null_mut(),
                                    );
                                },
                                PrecommitCleanupEffect::PublishClosedAndTransferLease => {
                                    let completed = effect.succeeded();
                                    let fsring_core::adapter::setup::PrecommitCleanupProgress::Complete(completed) = completed else {
                                        unreachable!("publication is the terminal cleanup effect")
                                    };
                                    let lock = unsafe {
                                        crate::lifecycle::KernelSessionRegistry::lock(registry)
                                    };
                                    if let Some(right) = completed.into_setup_right() {
                                        if unsafe {
                                            binding_mut(context).finish_setup_cleanup(right)
                                        }
                                        .is_err()
                                        {
                                            unreachable!(
                                                "setup completion preserves the claimed epoch"
                                            )
                                        }
                                    }
                                    unsafe {
                                        publish_binding_phase(context);
                                        // The lease is this context's own and
                                        // has not been moved out, so the
                                        // transfer cannot refuse. Panicking in
                                        // a kernel dispatch is not an option;
                                        // a refusal here leaves the lifetime
                                        // exactly as it was, which CLOSE then
                                        // observes as a context it may not
                                        // free — a leak rather than a
                                        // double free.
                                        let _transferred = move_lease_to_close(context);
                                        lock.release();
                                    }
                                    break;
                                }
                            }
                            effect.succeeded()
                        }
                        fsring_core::adapter::setup::PrecommitCleanupProgress::Complete(_) => {
                            unreachable!("cleanup completes only through publication")
                        }
                    };
                },
                // A committed binding: claimed under this dispatch's rundown and
                // released above, or arriving after the fence ran it down.
                None => {
                    // The live/closing generation goes through the one counted
                    // terminal route, and that route runs on a stack this
                    // dispatch asks the kernel for rather than on the IRP's
                    // own -- see `CLEANUP_STACK_EXPANSION_BYTES`. The claim is
                    // taken inside the callout, under the registry lock; the
                    // outer file rundown is already released above, which is
                    // what makes the wait inside it legal.
                    //
                    // The DDI call is written HERE, in the exported dispatch,
                    // rather than in a helper: the stack audit binds a declared
                    // expansion caller to a symbol in the link map, and a
                    // private helper's symbol carries a build-dependent hash no
                    // manifest can name stably.
                    //
                    // A refused expansion is asked again only while the kernel
                    // reports a memory shortage and core's budget lasts: nothing
                    // was claimed, so completing here strands the generation,
                    // CLOSE frees nothing, and unload waits on an admission
                    // nothing releases (native review N18-1). A refusal no wait
                    // clears, or a spent budget, gives up anyway -- the strand is
                    // disclosed, and a closing thread that never returns is
                    // worse (round-20 native review, N1). One budget per
                    // arrival, made before the loop: made inside it, it would
                    // start again on every attempt.
                    let mut budget = CleanupExpansionBudget::per_arrival();
                    let outcome = loop {
                        let mut block = CleanupCalloutBlock {
                            registry: registry.as_ptr(),
                            context: context.as_ptr(),
                            outcome: None,
                        };
                        // SAFETY: this dispatch runs at PASSIVE_LEVEL, so the
                        // DDI's APC_LEVEL ceiling holds; the block outlives the
                        // callout because it is this frame's own local. A fresh
                        // block per attempt keeps an unwritten slot meaning what
                        // it means.
                        let status = unsafe {
                            fsring_sys::c4::KeExpandKernelStackAndCallout(
                                Some(fsring_cleanup_callout),
                                core::ptr::addr_of_mut!(block).cast::<c_void>(),
                                CLEANUP_STACK_EXPANSION_BYTES as fsring_sys::SIZE_T,
                            )
                        };
                        let fault = match resolve_cleanup(status, block.outcome.take()) {
                            Ok(outcome) => break outcome,
                            Err(fault) => fault,
                        };
                        match budget.answer_refusal(fault) {
                            CleanupExpansionRecourse::DelayAndRetry => {
                                let mut interval = fsring_sys::c4::LARGE_INTEGER {
                                    QuadPart: -EXPANSION_RETRY_INTERVAL_100NS,
                                };
                                // The returned status is discarded for the
                                // reason the pending drain's delay discards it:
                                // a non-alertable `KernelMode` delay has exactly
                                // one outcome, the interval elapsed.
                                //
                                // SAFETY: PASSIVE_LEVEL holding nothing -- the
                                // outer file rundown was released before the
                                // callout and the registry lock is taken inside
                                // it -- so this blocks the closing thread only,
                                // and the interval lives on this frame for the
                                // whole synchronous call.
                                let _elapsed = unsafe {
                                    fsring_sys::c4::KeDelayExecutionThread(
                                        0,
                                        0 as BOOLEAN,
                                        core::ptr::addr_of_mut!(interval),
                                    )
                                };
                            }
                            // Out of budget, or a refusal no wait clears. The
                            // arrival completes unclaimed, as round 18 did for
                            // every refusal: the context is stranded and unload
                            // waits on its admission. Disclosed, and chosen over
                            // a closing thread that never returns (round-20
                            // native review, N1).
                            CleanupExpansionRecourse::Exhausted
                            | CleanupExpansionRecourse::Surrender => {
                                break CleanupTerminalOutcome::Refuse;
                            }
                        }
                    };
                    match outcome {
                        CleanupTerminalOutcome::Proceed => {}
                        // The route refused this arrival, or the expansion was
                        // given up. Neither leaves a record this CLEANUP
                        // acknowledged, so CLOSE frees nothing: a blocked or
                        // opaque-retained generation keeps its context by
                        // design, and a given-up expansion leaves the generation
                        // live for the process-loss or unload terminal to find
                        // -- the disclosed strand. `Contradicted` is the one
                        // exception, and the DDI's documented contract does not
                        // produce it: its callout may have acknowledged.
                        CleanupTerminalOutcome::Refuse => {
                            unsafe { wait_and_release_requestor(context.as_ptr()) };
                            return unsafe { complete(irp, STATUS_INVALID_DEVICE_STATE) };
                        }
                    }
                    // SAFETY: the context shell is live until CLOSE frees it.
                    unsafe { wait_and_release_requestor(context.as_ptr()) };
                }
            }
        }
    }

    // SAFETY: teardown is complete (or idempotently absent), and this path
    // still owns the live IRP for its one completion.
    unsafe { complete(irp, STATUS_SUCCESS) }
}

/// # Safety
/// The I/O manager supplies a live device object and a live IRP whose
/// current stack location has not yet been completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_dispatch_close(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    // SAFETY: the tag is read before any extension is projected.
    if let Some(status) = unsafe { route_volume_role(device, irp, IRP_MJ_CLOSE as u8, 0, true) } {
        // SAFETY: the role answered; the IRP is live and uncompleted.
        return unsafe { complete(irp, status) };
    }
    // SAFETY: the I/O manager supplies a live IRP and current stack location.
    let file = unsafe { current_file_object(irp) };
    if !file.is_null() {
        // SAFETY: CLOSE runs after other file-object I/O references have gone.
        // The pointer is stable through this load and is null after the one
        // freeing CLOSE path.
        let context = unsafe { (*file).FsContext.cast::<ControlFileContext>() };
        if !context.is_null() {
            // SAFETY: this defensively repeats CLEANUP's idempotent wait/swap.
            // The context shell remains live until the free below.
            unsafe { wait_and_release_requestor(context) };
            let state = unsafe { state_from_device(device) };
            let registry = if state.is_null() {
                None
            } else {
                Some(unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*state).sessions)) })
            };
            // SAFETY: CLOSE has exclusive lifecycle ownership of the file
            // object now. The order — detach, free, then release admission —
            // is the plan's, not this call site's.
            unsafe { run_close_plan(file, context, registry) };
        }
    }

    // SAFETY: close teardown is complete (or idempotently absent), and the
    // live IRP has not otherwise been completed.
    unsafe { complete(irp, STATUS_SUCCESS) }
}

/// The `IRP_MJ_DEVICE_CONTROL` thunk.
///
/// It owns the single completion and nothing else; every decision and side
/// effect belongs to [`fsring_dispatch_provider`].
///
/// # Safety
/// The I/O manager supplies a live device and a live IRP that no other path has
/// completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_dispatch_device_control(
    device: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    let mut information = 0usize;
    // SAFETY: the I/O manager supplies a live device and IRP; the retained
    // provider root owns every decision and side effect below.
    let status = unsafe { fsring_dispatch_provider(device, irp, &raw mut information) };
    if status == STATUS_PENDING {
        // The pending context owns the IRP; this thunk must not complete it
        // or touch it after IoCsqInsertIrp.
        return STATUS_PENDING;
    }
    // SAFETY: every acquired path released rundown, and this is the dispatch's
    // sole completion and final IRP touch.
    unsafe { complete_with(irp, status, information) }
}

/// The retained provider IOCTL root.
///
/// A stable link-map and PDB name so the static audit can anchor the whole
/// provider control branch on one symbol; it must survive release LTO. It owns
/// the rundown acquisition, the pure decision, and the routing of an admitted
/// operation to its native adapter, but never the IRP completion — the
/// major-function thunk above keeps that.
///
/// # Safety
/// The I/O manager supplies a live device and IRP, and `information` must be
/// writable for one value.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn fsring_dispatch_provider(
    device: PDEVICE_OBJECT,
    irp: PIRP,
    information: *mut usize,
) -> NTSTATUS {
    if information.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: dispatch owns a live IRP whose current stack location satisfies
    // the WDK inline's invariant for this projection.
    let stack = unsafe { fsring_sys::io_get_current_irp_stack_location(irp) };
    if !stack.is_null() {
        // SAFETY: the control parameters are the active union member of an
        // `IRP_MJ_DEVICE_CONTROL` stack location.
        let code = unsafe { (*stack).Parameters.DeviceIoControl }.IoControlCode;
        // SAFETY: the tag is read before any extension is projected, so a
        // VDO's storage controls never reach the provider registry.
        if let Some(status) =
            unsafe { route_volume_role(device, irp, IRP_MJ_DEVICE_CONTROL as u8, code, true) }
        {
            return status;
        }
    }
    let file = if stack.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: the non-null current stack location remains borrowed from
        // the live IRP. This copies its nullable file-object pointer once.
        unsafe { (*stack).FileObject }
    };
    let context = if file.is_null() {
        core::ptr::null_mut()
    } else {
        // SAFETY: successful CREATE published this stable pointer before
        // completion. CLEANUP preserves it, and CLOSE cannot run while this
        // file-object IRP is outstanding.
        unsafe { (*file).FsContext.cast::<ControlFileContext>() }
    };

    if context.is_null() {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: the stable context shell contains initialized rundown storage.
    // Acquire is valid through DISPATCH_LEVEL.
    let Some(guard) =
        (unsafe { ControlDispatchRundownGuard::acquire(NonNull::new_unchecked(context)) })
    else {
        // A failed acquisition never reads the captured requestor, current
        // requestor, mode, control parameters, or SystemBuffer.
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    // SAFETY: rundown is held, and the non-null stack and context remain live
    // for the synchronous native-to-core projection.
    let status = unsafe { decide_acquired_control_ioctl(device, irp, stack, context, information) };
    // SAFETY: this path owns the successful rundown acquisition and releases it
    // exactly once. The returned status contains no process or IRP borrow.
    unsafe { guard.release() };
    status
}

/// The retained filesystem-control ingress.
///
/// It routes on the trusted device-kind tag rather than on which device object
/// happened to arrive, so a provider request can never be answered by the
/// volume classifier and vice versa. Mount and verify belong to the volume
/// slice; until a VDO can exist there is nothing to mount, so a request for
/// one is refused rather than answered with a fabricated success.
///
/// # Safety
/// The I/O manager supplies a live device and IRP.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_dispatch_file_system_control(
    device: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    // SAFETY: dispatch owns a live IRP whose current stack location satisfies
    // the WDK inline's invariant for this projection.
    let stack = unsafe { fsring_sys::io_get_current_irp_stack_location(irp) };
    let minor = if stack.is_null() {
        u32::MAX
    } else {
        // SAFETY: the non-null current stack location is borrowed from the
        // live IRP for this one scalar read.
        u32::from(unsafe { (*stack).MinorFunction })
    };

    let extension = if device.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: every device this driver creates writes its extension header
        // before it leaves `DO_DEVICE_INITIALIZING`.
        unsafe {
            (*device)
                .DeviceExtension
                .cast::<crate::driver::ExtensionHeader>()
        }
    };
    // SAFETY: the extension is null-checked inside the projection.
    let Some(kind) = (unsafe { crate::driver::ExtensionHeader::kind_of(extension) }) else {
        // SAFETY: the IRP is live and has not been completed.
        return unsafe { complete(irp, STATUS_INVALID_DEVICE_REQUEST) };
    };

    // SAFETY: the trusted tag selects the role root through a closed match.
    let status = unsafe {
        crate::volume::route_by_kind(
            kind,
            device,
            irp,
            wdk_sys::IRP_MJ_FILE_SYSTEM_CONTROL as u8,
            minor,
            false,
        )
    };
    // SAFETY: this dispatch's sole completion and final IRP touch.
    unsafe { complete(irp, status) }
}
