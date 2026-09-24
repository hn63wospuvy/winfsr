//! The driver root: `DriverState`, the mount registry, and the executors that
//! turn `fsring_core::adapter::load` plans into native calls.
//!
//! This module restates none of the load or unload order. It receives one typed
//! effect at a time, performs exactly one native operation, and reports the
//! matching outcome; when an operation fails it drives the reverse-order unwind
//! the plan derives from what the load still owns.
//!
//! # Bounded load frames
//!
//! Every effect executor is `#[inline(never)]`, and that attribute is
//! load-bearing rather than a hint. The effects run strictly one after another,
//! so their buffers - two 256-byte BootContext record images, a 512-byte
//! security-descriptor window, the encoded publication - never need to coexist.
//! Inlined into one function they do anyway: LLVM gives each its own slot, so
//! `DriverEntry`'s frame became the *sum* of every effect rather than the
//! largest one. It measured 3576 bytes against the frozen 2048-byte bound of
//! `driver/audit/c4-stack-roots.json`; with one frame per effect it measures
//! 744, and the deepest chain from the root falls from 6128 to 5848 of the
//! 8192-byte bound.
//!
//! Outlining the choreography as a whole would have moved the same sum into one
//! callee and left the peak where it was. The bound this obeys is the real one:
//! peak kernel stack, which is the root plus the deepest effect, not the root
//! plus all of them.
//!
//! `driver/scripts/audit_c4_stack.py` measures both bounds on every release
//! image, so a removed attribute that matters shows up as a failed build.

use core::sync::atomic::{AtomicU32, Ordering};

use fsring_core::adapter::load as plan;
use fsring_core::resolver::ResolvedDdis;
use fsring_core::volume::DeviceKind;

use wdk_sys::{
    BOOLEAN, DRIVER_OBJECT, NTSTATUS, PDEVICE_OBJECT, PDRIVER_OBJECT, PEPROCESS,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

use crate::boot::BootObjects;
use crate::lifecycle::{KernelSessionRegistry, NonPagedAllocationOwner};
use crate::trace::TraceRegistration;

/// The first field of every device, file, and session extension in the driver.
///
/// A trusted closed tag comes first so a common dispatch thunk can decide which
/// extension it is looking at before it projects one; without it a provider
/// path could reinterpret a mounted volume as a control device.
#[repr(C)]
pub(crate) struct ExtensionHeader {
    pub(crate) kind: u32,
    pub(crate) state: *mut DriverState,
}

impl ExtensionHeader {
    /// Project the closed device kind from a trusted extension.
    ///
    /// # Safety
    /// `extension` must be a live extension this driver initialized.
    pub(crate) unsafe fn kind_of(extension: *const ExtensionHeader) -> Option<DeviceKind> {
        if extension.is_null() {
            return None;
        }
        // SAFETY: the caller's extension contract; the tag is written once,
        // before the device leaves `DO_DEVICE_INITIALIZING`.
        DeviceKind::from_raw(unsafe { (*extension).kind })
    }
}

/// The one root every device, file, and session extension refers to.
///
/// Device deletion never serves as an implicit reference count: this explicit
/// counter is the only ownership signal.
#[repr(C)]
pub struct DriverState {
    allocation: Option<NonPagedAllocationOwner>,
    references: AtomicU32,
    pub(crate) ddis: ResolvedDdis,
    pub(crate) boot: BootObjects,
    pub(crate) trace: TraceRegistration,
    pub(crate) provider_device: PDEVICE_OBJECT,
    pub(crate) fscontrol_device: PDEVICE_OBJECT,
    pub(crate) sessions: KernelSessionRegistry,
    unload_proof: Option<plan::LoadedDriver>,
}

impl DriverState {
    /// Acquire one root reference.
    // Task 11's per-file and per-session extensions are the first callers.
    #[allow(dead_code)]
    pub(crate) fn acquire(&self) -> bool {
        self.references
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .is_ok()
    }

    /// Release one root reference.
    pub(crate) fn release(&self) {
        let _ = self
            .references
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            });
    }

    pub(crate) fn reference_count(&self) -> u32 {
        self.references.load(Ordering::Acquire)
    }
}

/// The retained driver-root anchor.
///
/// A WDM driver image is loaded once, so one anchor is the whole population.
/// It is a stable exported symbol for the same reason the resolver edge is: the
/// static audit must be able to point at it.
// SAFETY-OF-NAME: the audit matches this exact spelling.
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static mut fsring_driver_state: *mut DriverState = core::ptr::null_mut();

/// Read the driver root.
///
/// # Safety
/// Callable only after `DriverEntry` published it and before unload releases
/// it, which is exactly the window in which any dispatch path can run.
pub(crate) unsafe fn root() -> *mut DriverState {
    // SAFETY: a plain machine-word read; `&raw const` forms no reference.
    unsafe { core::ptr::read(&raw const fsring_driver_state) }
}

/// Private proof that every field dispatch can observe is initialized and the
/// root owns the live boot/trace authorities.
///
/// Endpoint constructors accept this type, never an unready root pointer.
/// Its sole constructor consumes the exact owners and returns only at the last
/// production initialization step.
pub(crate) struct DispatchReadyRoot {
    state: core::ptr::NonNull<DriverState>,
}

/// Affine proof that the final-address registry initialization (including both
/// admissions and every permanent cell) completed successfully.
struct InitializedSessionRoot {
    state: core::ptr::NonNull<DriverState>,
}

/// # Safety
/// `state` is final writable storage and its `sessions` field is uninitialized.
unsafe fn initialize_session_root(
    state: core::ptr::NonNull<DriverState>,
) -> Result<InitializedSessionRoot, NTSTATUS> {
    unsafe {
        KernelSessionRegistry::initialize_in_place(
            core::ptr::addr_of_mut!((*state.as_ptr()).sessions).cast(),
        )?;
    }
    Ok(InitializedSessionRoot { state })
}

#[derive(Clone, Copy)]
enum DriverRootInitializationStep {
    Allocation,
    References,
    Ddis,
    Boot,
    Trace,
    ProviderDevice,
    FscontrolDevice,
    UnloadProof,
    DispatchReady,
}

const DRIVER_ROOT_INITIALIZATION_PLAN: [DriverRootInitializationStep; 9] = [
    DriverRootInitializationStep::Allocation,
    DriverRootInitializationStep::References,
    DriverRootInitializationStep::Ddis,
    DriverRootInitializationStep::Boot,
    DriverRootInitializationStep::Trace,
    DriverRootInitializationStep::ProviderDevice,
    DriverRootInitializationStep::FscontrolDevice,
    DriverRootInitializationStep::UnloadProof,
    DriverRootInitializationStep::DispatchReady,
];

impl DispatchReadyRoot {
    /// Write the provider device into the root BEFORE its endpoint becomes
    /// dispatchable.
    ///
    /// `PublishProvider` clears `DO_DEVICE_INITIALIZING`, and a dispatch
    /// reaches the root through the device extension rather than through
    /// `fsring_driver_state`, so from that instant a SETUP can read this field.
    /// It used to be written in `finish`, after the publish, and a SETUP
    /// arriving in that window read null and refused with
    /// `STATUS_INVALID_DEVICE_STATE` at `build_pending_runtime`'s provider
    /// check -- a load-time race that turned a correct driver into one that
    /// refuses the first session.
    ///
    /// `fscontrol_device` deliberately stays in `finish`: nothing outside
    /// unload reads it, which is what `finish`'s own comment claims for every
    /// field it writes, and is now true of the ones left there.
    ///
    /// # Safety
    /// The provider device exists and is still initializing, so no dispatch can
    /// have reached the extension yet.
    unsafe fn publish_provider_device(&self, device: fsring_sys::PDEVICE_OBJECT) {
        // SAFETY: the root is live for the whole load and this is the only
        // writer of this field before the endpoint is published.
        unsafe { (*self.state.as_ptr()).provider_device = device };
    }

    /// Write every infallible root field after the permanent registry and move
    /// the live dispatch owners before minting endpoint authority.
    ///
    /// # Safety
    /// `initialized` proves final-address `sessions` initialization; none of
    /// the other fields has been initialized and no endpoint exists.
    unsafe fn initialize(
        initialized: InitializedSessionRoot,
        allocation: NonPagedAllocationOwner,
        ddis: ResolvedDdis,
        boot: BootObjects,
        trace: TraceRegistration,
    ) -> Self {
        let state = initialized.state;
        let state_ptr = state.as_ptr();
        let mut allocation = Some(allocation);
        let mut boot = Some(boot);
        let mut trace = Some(trace);
        for step in DRIVER_ROOT_INITIALIZATION_PLAN {
            match step {
                DriverRootInitializationStep::Allocation => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).allocation).write(allocation.take());
                },
                DriverRootInitializationStep::References => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).references).write(AtomicU32::new(1));
                },
                DriverRootInitializationStep::Ddis => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).ddis).write(ddis);
                },
                DriverRootInitializationStep::Boot => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).boot).write(
                        boot.take()
                            .unwrap_or_else(|| core::hint::unreachable_unchecked()),
                    );
                },
                DriverRootInitializationStep::Trace => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).trace).write(
                        trace
                            .take()
                            .unwrap_or_else(|| core::hint::unreachable_unchecked()),
                    );
                },
                DriverRootInitializationStep::ProviderDevice => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).provider_device)
                        .write(core::ptr::null_mut());
                },
                DriverRootInitializationStep::FscontrolDevice => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).fscontrol_device)
                        .write(core::ptr::null_mut());
                },
                DriverRootInitializationStep::UnloadProof => unsafe {
                    core::ptr::addr_of_mut!((*state_ptr).unload_proof).write(None);
                },
                DriverRootInitializationStep::DispatchReady => return Self { state },
            }
        }
        // The compile-time production-plan proof requires DispatchReady last.
        unsafe { core::hint::unreachable_unchecked() }
    }

    const fn as_ptr(&self) -> *mut DriverState {
        self.state.as_ptr()
    }

    /// Project the root pointer only for an endpoint constructor that already
    /// received this nonconstructible ready authority.
    pub(crate) const fn endpoint_state(&self) -> *mut DriverState {
        self.state.as_ptr()
    }
}

/// Everything one in-flight load owns, before and while the ready root exists.
/// Boot/trace are `Some` before root allocation, `None` while the ready root
/// owns them, and restored to `Some` before the pre-root rollback effects run.
struct LoadContext {
    ddis: ResolvedDdis,
    boot: Option<BootObjects>,
    trace: Option<TraceRegistration>,
    state: Option<DispatchReadyRoot>,
    provider_device: PDEVICE_OBJECT,
    fscontrol_device: PDEVICE_OBJECT,
    dos_link: bool,
    process_notify: bool,
    validation: Option<plan::BootValidation>,
}

impl LoadContext {
    fn new(ddis: ResolvedDdis) -> Self {
        Self {
            ddis,
            boot: Some(BootObjects::new()),
            trace: Some(TraceRegistration::new()),
            state: None,
            provider_device: core::ptr::null_mut(),
            fscontrol_device: core::ptr::null_mut(),
            dos_link: false,
            process_notify: false,
            validation: None,
        }
    }

    fn boot_mut(&mut self) -> Result<&mut BootObjects, NTSTATUS> {
        self.boot.as_mut().ok_or(STATUS_UNSUCCESSFUL)
    }

    fn trace_mut(&mut self) -> Result<&mut TraceRegistration, NTSTATUS> {
        self.trace.as_mut().ok_or(STATUS_UNSUCCESSFUL)
    }

    fn dispatch_ready_root(&self) -> Result<&DispatchReadyRoot, NTSTATUS> {
        self.state.as_ref().ok_or(STATUS_UNSUCCESSFUL)
    }
}

#[allow(dead_code)]
mod native_load_shape_tests {
    use super::*;

    fn dispatchable_endpoints_require_a_root_with_live_boot_and_trace_owners(
        context: &LoadContext,
        driver: &mut DRIVER_OBJECT,
    ) -> Result<(), NTSTATUS> {
        let ready: &DispatchReadyRoot = context.dispatch_ready_root()?;
        let _: unsafe fn(
            &mut DRIVER_OBJECT,
            &DispatchReadyRoot,
            ResolvedDdis,
        ) -> Result<PDEVICE_OBJECT, NTSTATUS> = crate::control::create_provider_device;
        let _: unsafe fn(
            &mut DRIVER_OBJECT,
            &DispatchReadyRoot,
        ) -> Result<PDEVICE_OBJECT, NTSTATUS> = crate::fscontrol::create;
        let _ = (driver, ready);
        Ok(())
    }

    fn dispatch_ready_authority_requires_completed_permanent_registry_initialization() {
        let _: unsafe fn(
            core::ptr::NonNull<DriverState>,
        ) -> Result<InitializedSessionRoot, NTSTATUS> = initialize_session_root;
        let _: unsafe fn(
            InitializedSessionRoot,
            NonPagedAllocationOwner,
            ResolvedDdis,
            BootObjects,
            TraceRegistration,
        ) -> DispatchReadyRoot = DispatchReadyRoot::initialize;
    }

    const fn live_root_owners_precede_dispatch_ready_publication() {
        assert!(matches!(
            DRIVER_ROOT_INITIALIZATION_PLAN,
            [
                DriverRootInitializationStep::Allocation,
                DriverRootInitializationStep::References,
                DriverRootInitializationStep::Ddis,
                DriverRootInitializationStep::Boot,
                DriverRootInitializationStep::Trace,
                DriverRootInitializationStep::ProviderDevice,
                DriverRootInitializationStep::FscontrolDevice,
                DriverRootInitializationStep::UnloadProof,
                DriverRootInitializationStep::DispatchReady,
            ]
        ));
    }

    const _: () = live_root_owners_precede_dispatch_ready_publication();
}

/// Drive the whole load plan.
///
/// # Safety
/// Must run once at PASSIVE_LEVEL from `DriverEntry`, with `driver` the
/// loader-owned driver object.
pub(crate) unsafe fn load(driver: &mut DRIVER_OBJECT, ddis: ResolvedDdis) -> NTSTATUS {
    let mut context = LoadContext::new(ddis);
    let mut progress = plan::LoadPlan::begin();

    loop {
        match progress {
            plan::LoadProgress::Ready(proof) => {
                // SAFETY: every effect succeeded, so the root exists and owns
                // nothing yet; this is the single hand-off.
                unsafe { finish(&mut context, proof) };
                return STATUS_SUCCESS;
            }
            plan::LoadProgress::Effect(pending) => {
                let effect = pending.effect();
                // SAFETY: PASSIVE_LEVEL load thread; each arm performs exactly
                // one native operation for the effect it was handed.
                match unsafe { perform(&mut context, driver, effect) } {
                    Ok(outcome) => match pending.succeeded(outcome) {
                        Ok(next) => progress = next,
                        Err(_) => {
                            // The executor builds each outcome in the same arm
                            // that issues its call, so this is unreachable in a
                            // released image. Unwind everything still owned
                            // rather than leaving a half-built driver behind.
                            // SAFETY: every release below is null-guarded.
                            unsafe { unwind_all(&mut context) };
                            return STATUS_UNSUCCESSFUL;
                        }
                    },
                    Err(status) => {
                        let rollback = pending.failed();
                        // SAFETY: the plan lists only resources this load owns.
                        unsafe { unwind(&mut context, rollback.effects()) };
                        return status;
                    }
                }
            }
        }
    }
}

/// Perform exactly one load effect.
///
/// # Safety
/// PASSIVE_LEVEL, on the load thread, in the plan's order.
unsafe fn perform(
    context: &mut LoadContext,
    driver: &mut DRIVER_OBJECT,
    effect: plan::LoadEffect,
) -> Result<plan::LoadEffectOutcome, NTSTATUS> {
    match effect {
        plan::LoadEffect::OpenAndAcquireBootLockEvent => {
            // SAFETY: the load thread's first BootContext operation.
            let disposition =
                unsafe { crate::boot::open_and_acquire_lock_event(context.boot_mut()?) }?;
            Ok(plan::LoadEffectOutcome::BootLockEventAcquired(disposition))
        }
        plan::LoadEffect::OpenOrCreateBootSection => {
            // SAFETY: the guard is held.
            let disposition = unsafe { crate::boot::open_or_create_section(context.boot_mut()?) }?;
            Ok(plan::LoadEffectOutcome::BootSectionOpened(disposition))
        }
        plan::LoadEffect::MapSystemView => {
            // SAFETY: the section is referenced.
            unsafe { crate::boot::map_system_view(context.boot_mut()?) }?;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::ValidateOrInitialize => {
            let mut rng = crate::kernel::CngRandom;
            let ddis = context.ddis;
            // SAFETY: the view is mapped and the guard is held.
            let validation = unsafe {
                crate::boot::validate_or_initialize(context.boot_mut()?, &ddis, &mut rng)
            }?;
            context.validation = Some(validation);
            Ok(plan::LoadEffectOutcome::BootContextValidated(validation))
        }
        plan::LoadEffect::PublishLoadGeneration => {
            let Some(validation) = context.validation else {
                return Err(STATUS_UNSUCCESSFUL);
            };
            // SAFETY: the view is mapped and the guard is held.
            let origin =
                unsafe { crate::boot::publish_load_generation(context.boot_mut()?, validation) }?;
            Ok(plan::LoadEffectOutcome::BootContextPublished(origin))
        }
        plan::LoadEffect::ReleaseBootLockEvent => {
            // SAFETY: the guard is held and released exactly once.
            unsafe { crate::boot::release_lock_event(context.boot_mut()?) }?;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::RegisterEtw => {
            // SAFETY: before either endpoint is published.
            unsafe { crate::trace::register(context.trace_mut()?) }?;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::AllocateDriverState => {
            // SAFETY: PASSIVE_LEVEL, fallible tagged allocation only.
            unsafe { allocate_state(context) }?;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::RegisterProcessNotify => {
            // SAFETY: after ETW and before either endpoint is published.
            let status = unsafe {
                fsring_sys::c4::PsSetCreateProcessNotifyRoutineEx(
                    Some(fsring_process_loss),
                    0 as BOOLEAN,
                )
            };
            if status != STATUS_SUCCESS {
                return Err(status);
            }
            context.process_notify = true;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::CreateProviderSecure => {
            // SAFETY: the ready-root proof owns live boot/trace authorities and
            // the dispatch table is installed before any device exists.
            let device = unsafe {
                crate::control::create_provider_device(
                    driver,
                    context.dispatch_ready_root()?,
                    context.ddis,
                )
            }?;
            // Work items are permanently associated with this provider, so
            // allocate all 64 only after creation and before any endpoint can
            // be published. Failure deletes this just-created provider in the
            // same effect because the pure plan has not adopted it yet.
            // SAFETY: the root was initialized before endpoints and `device`
            // is the live, still-unpublished permanent provider.
            let state = context.dispatch_ready_root()?.as_ptr();
            if let Err(status) = unsafe { (*state).sessions.initialize_work_items(device) } {
                // SAFETY: initialization already reverse-freed its partial
                // prefix; this effect still uniquely owns the device.
                unsafe { crate::kernel::delete_device(device) };
                return Err(status);
            }
            context.provider_device = device;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::CreateFscontrolSecure => {
            // SAFETY: as above; only a dispatch-ready root can enter an
            // endpoint extension.
            let device =
                unsafe { crate::fscontrol::create(driver, context.dispatch_ready_root()?) }?;
            context.fscontrol_device = device;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::CreateProviderDosLink => {
            // SAFETY: the provider device exists and is still initializing.
            unsafe { crate::control::create_dos_link() }?;
            context.dos_link = true;
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::PublishProvider => {
            let ready = context.dispatch_ready_root()?;
            // The order is the point: a dispatch reaches the root through the
            // device extension, so the field must be there before the publish
            // below makes the endpoint reachable.
            //
            // SAFETY: the device exists and is still initializing.
            unsafe { ready.publish_provider_device(context.provider_device) };
            // SAFETY: the extension and link are complete.
            unsafe { crate::control::publish(context.provider_device) };
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::PublishFscontrol => {
            // SAFETY: the extension and dispatch table are complete.
            unsafe { crate::fscontrol::publish(context.fscontrol_device) };
            Ok(plan::LoadEffectOutcome::Done)
        }
        plan::LoadEffect::RegisterFilesystem => {
            // SAFETY: the device is published and its dispatch is complete.
            unsafe { crate::fscontrol::register(context.fscontrol_device) };
            Ok(plan::LoadEffectOutcome::Done)
        }
    }
}

/// # Safety
/// PASSIVE_LEVEL, once, before the process-notify registration.
// One load effect, one frame: see `driver`'s "Bounded load frames".
#[inline(never)]
unsafe fn allocate_state(context: &mut LoadContext) -> Result<(), NTSTATUS> {
    // SAFETY: PASSIVE load, nonzero checked type size, and the fixed pool tag.
    let allocation = unsafe {
        NonPagedAllocationOwner::allocate(
            core::mem::size_of::<DriverState>(),
            crate::kernel::POOL_TAG,
        )
    }?;
    let (region, bytes) = allocation.region();
    if bytes != core::mem::size_of::<DriverState>() {
        // SAFETY: no typed field was initialized and the owner is still unique.
        unsafe { allocation.release() };
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let state = region.cast::<DriverState>();
    // SAFETY: the allocation is aligned writable storage for DriverState. The
    // permanent native root initializes directly in its final address before
    // any endpoint exists.
    let initialized = match unsafe { initialize_session_root(state) } {
        Ok(initialized) => initialized,
        Err(status) => {
            // SAFETY: no field owns the allocation yet.
            unsafe { allocation.release() };
            return Err(status);
        }
    };
    let Some(boot) = context.boot.take() else {
        // SAFETY: only the permanent registry was initialized and it owns no
        // fallible resource yet.
        unsafe { allocation.release() };
        return Err(STATUS_UNSUCCESSFUL);
    };
    let Some(trace) = context.trace.take() else {
        context.boot = Some(boot);
        // SAFETY: as above.
        unsafe { allocation.release() };
        return Err(STATUS_UNSUCCESSFUL);
    };
    // SAFETY: `sessions` is initialized and the remaining fields are written
    // exactly once. This consumes the live boot/trace owners before minting
    // the only authority accepted by endpoint constructors.
    context.state = Some(unsafe {
        DispatchReadyRoot::initialize(initialized, allocation, context.ddis, boot, trace)
    });
    Ok(())
}

const _: () = assert!(
    core::mem::align_of::<DriverState>() <= fsring_sys::MEMORY_ALLOCATION_ALIGNMENT as usize,
    "the driver root's alignment exceeds the WDK pool allocation guarantee"
);

/// Publish the already dispatch-ready root after the load plan completes.
///
/// # Safety
/// Every load effect succeeded.
unsafe fn finish(context: &mut LoadContext, proof: plan::LoadedDriver) {
    let state = context
        .state
        .take()
        .unwrap_or_else(|| unsafe { core::hint::unreachable_unchecked() })
        .as_ptr();
    // SAFETY: boot/trace and every dispatch-visible field were written before
    // endpoint creation. These remaining fields are unload-only and the root
    // anchor is published only after they are complete.
    //
    // That claim is now true of every field written here. `provider_device`
    // used to be one of them and is not: it IS dispatch-visible -- a SETUP
    // reads it through the device extension -- so it moved to
    // `PublishProvider`, ahead of the publish that clears
    // `DO_DEVICE_INITIALIZING`.
    unsafe {
        (*state).fscontrol_device = context.fscontrol_device;
        (*state).unload_proof = Some(proof);
        core::ptr::write(&raw mut fsring_driver_state, state);
    }
}

/// Run one reverse-order unwind.
///
/// # Safety
/// The effects come from a plan derived from what this load still owns.
unsafe fn unwind(context: &mut LoadContext, effects: &[plan::LoadRollbackEffect]) {
    for effect in effects.iter().copied() {
        // SAFETY: each release below is null-guarded and idempotent.
        unsafe { undo(context, effect) };
    }
}

/// Release everything still owned, in the full reverse order.
///
/// # Safety
/// PASSIVE_LEVEL teardown; every release is null-guarded.
unsafe fn unwind_all(context: &mut LoadContext) {
    // SAFETY: as above.
    unsafe {
        unwind(
            context,
            &[
                plan::LoadRollbackEffect::UnregisterFilesystem,
                plan::LoadRollbackEffect::UnpublishFscontrol,
                plan::LoadRollbackEffect::UnpublishProvider,
                plan::LoadRollbackEffect::RemoveProviderDosLink,
                plan::LoadRollbackEffect::DeleteFscontrol,
                plan::LoadRollbackEffect::DeleteProvider,
                plan::LoadRollbackEffect::UnregisterProcessNotify,
                plan::LoadRollbackEffect::ReleaseDriverState,
                plan::LoadRollbackEffect::UnregisterEtw,
                plan::LoadRollbackEffect::UnmapSystemView,
                plan::LoadRollbackEffect::CloseBootSection,
                plan::LoadRollbackEffect::ReleaseBootLockEvent,
                plan::LoadRollbackEffect::CloseBootLockEvent,
            ],
        );
    }
}

/// # Safety
/// PASSIVE_LEVEL teardown for one effect the plan selected.
unsafe fn undo(context: &mut LoadContext, effect: plan::LoadRollbackEffect) {
    match effect {
        plan::LoadRollbackEffect::UnregisterFilesystem => {
            if !context.fscontrol_device.is_null() {
                // SAFETY: the device was registered.
                unsafe { crate::fscontrol::unregister(context.fscontrol_device) };
            }
        }
        plan::LoadRollbackEffect::UnpublishFscontrol => {
            if !context.fscontrol_device.is_null() {
                // SAFETY: the device exists.
                unsafe { crate::fscontrol::unpublish(context.fscontrol_device) };
            }
        }
        plan::LoadRollbackEffect::UnpublishProvider => {
            if !context.provider_device.is_null() {
                // SAFETY: the device exists.
                unsafe { crate::control::unpublish(context.provider_device) };
            }
        }
        plan::LoadRollbackEffect::RemoveProviderDosLink => {
            if context.dos_link {
                // SAFETY: this load created exactly this link.
                unsafe { crate::control::remove_dos_link() };
                context.dos_link = false;
            }
        }
        plan::LoadRollbackEffect::DeleteFscontrol => {
            if !context.fscontrol_device.is_null() {
                // SAFETY: this load created the device and deletes it once.
                unsafe { crate::kernel::delete_device(context.fscontrol_device) };
                context.fscontrol_device = core::ptr::null_mut();
            }
        }
        plan::LoadRollbackEffect::DeleteProvider => {
            if !context.provider_device.is_null() {
                // SAFETY: no endpoint remains published and no Task 6 work
                // item was queued; reverse-free items before their associated
                // provider is deleted.
                let state = context
                    .state
                    .as_ref()
                    .unwrap_or_else(|| unsafe { core::hint::unreachable_unchecked() })
                    .as_ptr();
                unsafe { (*state).sessions.rollback_initialization() };
                // SAFETY: as above.
                unsafe { crate::kernel::delete_device(context.provider_device) };
                context.provider_device = core::ptr::null_mut();
            }
        }
        plan::LoadRollbackEffect::UnregisterProcessNotify => {
            if context.process_notify {
                // SAFETY: this load registered exactly this routine.
                unsafe {
                    let _ = fsring_sys::c4::PsSetCreateProcessNotifyRoutineEx(
                        Some(fsring_process_loss),
                        1 as BOOLEAN,
                    );
                }
                context.process_notify = false;
            }
        }
        plan::LoadRollbackEffect::ReleaseDriverState => {
            if let Some(root) = context.state.take() {
                let state = root.as_ptr();
                // SAFETY: the root was allocated from the tagged pool and no
                // extension can reference it: every endpoint was unpublished
                // and deleted earlier in the plan. Move the exact live owners
                // back before dropping/freeing the root so the remaining
                // pre-root rollback effects can release them in plan order.
                unsafe {
                    (*state).sessions.rollback_initialization();
                    let boot = core::mem::replace(&mut (*state).boot, BootObjects::new());
                    let trace = core::mem::replace(&mut (*state).trace, TraceRegistration::new());
                    context.boot = Some(boot);
                    context.trace = Some(trace);
                    let allocation = (*state).allocation.take();
                    core::ptr::drop_in_place(state);
                    if let Some(allocation) = allocation {
                        allocation.release();
                    }
                }
            }
        }
        plan::LoadRollbackEffect::UnregisterEtw => {
            // SAFETY: idempotent; a never-registered provider is a no-op.
            if let Some(trace) = context.trace.as_mut() {
                unsafe { crate::trace::unregister(trace) };
            }
        }
        plan::LoadRollbackEffect::UnmapSystemView => {
            // SAFETY: idempotent.
            if let Some(boot) = context.boot.as_mut() {
                unsafe { crate::boot::unmap_system_view(boot) };
            }
        }
        plan::LoadRollbackEffect::MakeNewBootSectionTemporary => {
            // SAFETY: the plan reaches this only for a section this load
            // created that never reached READY.
            if let Some(boot) = context.boot.as_mut() {
                unsafe { crate::boot::make_new_section_temporary(boot) };
            }
        }
        plan::LoadRollbackEffect::CloseBootSection => {
            // SAFETY: idempotent.
            if let Some(boot) = context.boot.as_mut() {
                unsafe { crate::boot::close_section(boot) };
            }
        }
        plan::LoadRollbackEffect::ReleaseBootLockEvent => {
            // SAFETY: idempotent; a released guard is a no-op.
            if let Some(boot) = context.boot.as_mut() {
                unsafe {
                    let _ = crate::boot::release_lock_event(boot);
                }
            }
        }
        plan::LoadRollbackEffect::CloseBootLockEvent => {
            // SAFETY: idempotent.
            if let Some(boot) = context.boot.as_mut() {
                unsafe { crate::boot::close_lock_event(boot) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unload
// ---------------------------------------------------------------------------

/// The retained unload ingress.
///
/// The ABI is `extern "C"` because `PDRIVER_UNLOAD` is; Rust keeps `"system"`
/// and `"C"` distinct in the type system even where the target ABI is
/// identical. The retained exported *name* is what the static audit anchors on.
///
/// # Safety
/// The I/O manager calls this once, at PASSIVE_LEVEL, after dispatch activity
/// has drained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_driver_unload(_driver: PDRIVER_OBJECT) {
    // SAFETY: the load published the root before any endpoint became
    // reachable, and this is the last code the image runs.
    let state = unsafe { root() };
    if state.is_null() {
        unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, 0, 1, 0, 0) }
    }
    // SAFETY: the root is live until the release below.
    unsafe { unload(state) };
}

/// Drive the exact 16-effect R3 unload ledger.
///
/// # Safety
/// PASSIVE_LEVEL, once, with `state` the live driver root.
#[inline(never)]
unsafe fn unload(state: *mut DriverState) {
    let proof = unsafe { (*state).unload_proof.take() };
    let Some(proof) = proof else {
        unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, 0, 0, 0, 0) }
    };
    let state = unsafe { core::ptr::NonNull::new_unchecked(state) };
    unsafe { plan::run_r3_unload(proof, NativeR3UnloadOps { state }) };
}

struct NativeR3UnloadOps {
    state: core::ptr::NonNull<DriverState>,
}

impl NativeR3UnloadOps {
    unsafe fn registry(&self) -> core::ptr::NonNull<KernelSessionRegistry> {
        unsafe {
            core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!(
                (*self.state.as_ptr()).sessions
            ))
        }
    }
}

struct NativeProcessNotifyUnregistered {
    scan: crate::lifecycle::R3UnloadScanAdmission,
    process: crate::lifecycle::ProcessCallbackAdmissionClosed,
    setup: crate::lifecycle::SetupAdmissionClosed,
    control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeProcessCallbacksDrained {
    scan: crate::lifecycle::R3UnloadScanAdmission,
    process: crate::lifecycle::ProcessCallbacksDrained,
    setup: crate::lifecycle::SetupAdmissionClosed,
    control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeSetupAdmissionDrained {
    scan: crate::lifecycle::R3UnloadScanAdmission,
    process: crate::lifecycle::ProcessCallbacksDrained,
    setup: crate::lifecycle::SetupAdmissionDrained,
    control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeOneSessionObserved {
    first: crate::fence::R3UnloadScanStep,
    process: crate::lifecycle::ProcessCallbacksDrained,
    setup: crate::lifecycle::SetupAdmissionDrained,
    control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeStableSessionScan {
    stable: crate::fence::R3StableEmptyPass,
    process: crate::lifecycle::ProcessCallbacksDrained,
    setup: crate::lifecycle::SetupAdmissionDrained,
    control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeBlockedSessionScan {
    blocked: crate::fence::R3BlockedUnloadWait,
    _process: crate::lifecycle::ProcessCallbacksDrained,
    _setup: crate::lifecycle::SetupAdmissionDrained,
    _control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeFinalizersDrained {
    process: crate::lifecycle::ProcessCallbacksDrained,
    setup: crate::lifecycle::SetupAdmissionDrained,
    finalizers: crate::fence::R3FinalizersDrained,
    control: crate::lifecycle::ControlContextAdmissionClosed,
}

struct NativeControlContextsDrained {
    process: crate::lifecycle::ProcessCallbacksDrained,
    setup: crate::lifecycle::SetupAdmissionDrained,
    finalizers: crate::fence::R3FinalizersDrained,
    control: crate::lifecycle::ControlContextAdmissionDrained,
}

unsafe impl plan::R3UnloadNativeOps for NativeR3UnloadOps {
    type ClosedAdmissions = crate::lifecycle::ClosedGlobalAdmissions;
    type ProcessNotifyUnregistered = NativeProcessNotifyUnregistered;
    type ProcessCallbacksDrained = NativeProcessCallbacksDrained;
    type SetupAdmissionDrained = NativeSetupAdmissionDrained;
    type OneSessionObserved = NativeOneSessionObserved;
    type StableSessionScan = NativeStableSessionScan;
    type BlockedSessionScan = NativeBlockedSessionScan;
    type FinalizersDrained = NativeFinalizersDrained;
    type ControlContextsDrained = NativeControlContextsDrained;
    type PreparedDestruction = PreparedUnloadDestruction;
    type FilesystemUnregistered = R3UnloadSuffix<11>;
    type FscontrolDeleted = R3UnloadSuffix<12>;
    type ProviderDosLinkRemoved = R3UnloadSuffix<13>;
    type ProviderDeleted = R3UnloadSuffix<14>;
    type BootObjectsReleased = R3UnloadSuffix<15>;
    type DriverStateReleased = R3UnloadSuffix<16>;

    unsafe fn close_global_admissions(&mut self) -> Self::ClosedAdmissions {
        let registry = unsafe { self.registry() };
        let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
        let closed = unsafe { crate::lifecycle::close_global_admissions(&mut lock) };
        unsafe { lock.release() };
        closed
    }

    unsafe fn unregister_process_notify(
        &mut self,
        closed: Self::ClosedAdmissions,
    ) -> Self::ProcessNotifyUnregistered {
        let (scan, process, setup, control) = closed.into_waits();
        let status = unsafe {
            fsring_sys::c4::PsSetCreateProcessNotifyRoutineEx(
                Some(fsring_process_loss),
                1 as BOOLEAN,
            )
        };
        if plan::classify_process_notify_unregister(status)
            == plan::ProcessNotifyUnregisterDisposition::FailStop
        {
            unsafe {
                fsring_sys::KeBugCheckEx(
                    crate::FSRING_PANIC_BUGCHECK,
                    status as u32 as u64,
                    2,
                    0,
                    0,
                )
            }
        }
        NativeProcessNotifyUnregistered {
            scan,
            process,
            setup,
            control,
        }
    }

    unsafe fn wait_process_callbacks(
        &mut self,
        stage: Self::ProcessNotifyUnregistered,
    ) -> Self::ProcessCallbacksDrained {
        NativeProcessCallbacksDrained {
            scan: stage.scan,
            process: unsafe { crate::lifecycle::wait_process_callbacks_drained(stage.process) },
            setup: stage.setup,
            control: stage.control,
        }
    }

    unsafe fn wait_setup_admission(
        &mut self,
        stage: Self::ProcessCallbacksDrained,
    ) -> Self::SetupAdmissionDrained {
        NativeSetupAdmissionDrained {
            scan: stage.scan,
            process: stage.process,
            setup: unsafe { crate::lifecycle::wait_setup_admission_drained(stage.setup) },
            control: stage.control,
        }
    }

    unsafe fn claim_or_join_one_session(
        &mut self,
        stage: Self::SetupAdmissionDrained,
    ) -> Self::OneSessionObserved {
        let first = unsafe {
            crate::fence::R3UnloadProgress::begin_after_drains(
                stage.scan,
                &stage.process,
                &stage.setup,
            )
            .observe_one()
        };
        NativeOneSessionObserved {
            first,
            process: stage.process,
            setup: stage.setup,
            control: stage.control,
        }
    }

    unsafe fn restart_session_scan(
        &mut self,
        stage: Self::OneSessionObserved,
    ) -> plan::R3UnloadSessionScan<Self::StableSessionScan, Self::BlockedSessionScan> {
        match unsafe { finish_r3_session_scan(stage.first) } {
            Ok(stable) => plan::R3UnloadSessionScan::Stable(NativeStableSessionScan {
                stable,
                process: stage.process,
                setup: stage.setup,
                control: stage.control,
            }),
            Err(blocked) => plan::R3UnloadSessionScan::Blocked(NativeBlockedSessionScan {
                blocked,
                _process: stage.process,
                _setup: stage.setup,
                _control: stage.control,
            }),
        }
    }

    unsafe fn wait_blocked_unload_forever(&mut self, blocked: Self::BlockedSessionScan) -> ! {
        unsafe { blocked.blocked.wait_forever() }
    }

    unsafe fn drain_r3_finalizers(
        &mut self,
        stage: Self::StableSessionScan,
    ) -> Self::FinalizersDrained {
        NativeFinalizersDrained {
            process: stage.process,
            setup: stage.setup,
            finalizers: unsafe { crate::fence::drain_r3_finalizers(stage.stable) },
            control: stage.control,
        }
    }

    unsafe fn wait_control_context_admission(
        &mut self,
        stage: Self::FinalizersDrained,
    ) -> Self::ControlContextsDrained {
        NativeControlContextsDrained {
            process: stage.process,
            setup: stage.setup,
            finalizers: stage.finalizers,
            control: unsafe {
                crate::lifecycle::wait_control_context_admission_drained(stage.control)
            },
        }
    }

    unsafe fn preflight_r3_ledgers_and_root(
        &mut self,
        boundary: plan::R3UnloadPreflightBoundary,
        stage: Self::ControlContextsDrained,
    ) -> Self::PreparedDestruction {
        unsafe {
            PreparedUnloadDestruction::prepare(
                self.state.as_ptr(),
                boundary,
                stage.process,
                stage.setup,
                stage.finalizers,
                stage.control,
            )
        }
    }

    unsafe fn unregister_filesystem(
        &mut self,
        prepared: Self::PreparedDestruction,
    ) -> Self::FilesystemUnregistered {
        unsafe { R3UnloadSuffix::<10> { prepared }.unregister_filesystem() }
    }

    unsafe fn delete_fscontrol(
        &mut self,
        stage: Self::FilesystemUnregistered,
    ) -> Self::FscontrolDeleted {
        unsafe { stage.delete_fscontrol() }
    }

    unsafe fn remove_provider_dos_link(
        &mut self,
        stage: Self::FscontrolDeleted,
    ) -> Self::ProviderDosLinkRemoved {
        unsafe { stage.remove_provider_dos_link() }
    }

    unsafe fn delete_provider(
        &mut self,
        stage: Self::ProviderDosLinkRemoved,
    ) -> Self::ProviderDeleted {
        unsafe { stage.delete_provider() }
    }

    unsafe fn release_boot_objects(
        &mut self,
        stage: Self::ProviderDeleted,
    ) -> Self::BootObjectsReleased {
        unsafe { stage.release_boot_objects() }
    }

    unsafe fn release_driver_state(
        &mut self,
        stage: Self::BootObjectsReleased,
    ) -> Self::DriverStateReleased {
        unsafe { stage.release_driver_state() }
    }

    unsafe fn unregister_etw(self, stage: Self::DriverStateReleased) {
        debug_assert_eq!(self.state, stage.prepared.state);
        unsafe { stage.unregister_etw() };
    }
}

unsafe fn finish_r3_session_scan(
    mut step: crate::fence::R3UnloadScanStep,
) -> Result<crate::fence::R3StableEmptyPass, crate::fence::R3BlockedUnloadWait> {
    loop {
        step = match step {
            crate::fence::R3UnloadScanStep::Scanning(progress) => unsafe { progress.observe_one() },
            crate::fence::R3UnloadScanStep::Work(work) => unsafe { work.discharge() },
            crate::fence::R3UnloadScanStep::StableEmpty(stable) => return Ok(stable),
            crate::fence::R3UnloadScanStep::Blocked(blocked) => return Err(blocked),
        };
    }
}

/// Stack-local effect-nine capability. Its private constructor consumes the
/// core boundary plus every drain/locked-ledger receipt. The fixed effects
/// 10-16 below return `()` and contain no refusal edge.
struct PreparedUnloadDestruction {
    state: core::ptr::NonNull<DriverState>,
    _boundary: plan::R3UnloadPreflightBoundary,
    _native_ledgers: crate::lifecycle::R3NativeLedgersClear,
    _sole_root: crate::lifecycle::R3SoleDriverRoot,
    _process: crate::lifecycle::ProcessCallbacksDrained,
    _setup: crate::lifecycle::SetupAdmissionDrained,
    _finalizers: crate::fence::R3FinalizersDrained,
    _control: crate::lifecycle::ControlContextAdmissionDrained,
    authority: PrivatePreparedUnloadDestruction,
}

struct PrivatePreparedUnloadDestruction(());

impl PreparedUnloadDestruction {
    unsafe fn prepare(
        state: *mut DriverState,
        boundary: plan::R3UnloadPreflightBoundary,
        process: crate::lifecycle::ProcessCallbacksDrained,
        setup: crate::lifecycle::SetupAdmissionDrained,
        finalizers: crate::fence::R3FinalizersDrained,
        control: crate::lifecycle::ControlContextAdmissionDrained,
    ) -> Self {
        let state = unsafe { core::ptr::NonNull::new_unchecked(state) };
        let registry = unsafe {
            core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*state.as_ptr()).sessions))
        };
        let (native_ledgers, sole_root) = unsafe {
            let mut lock = crate::lifecycle::KernelSessionRegistry::lock(registry);
            let observed = lock.prepare_r3_unload_locked_root(state);
            lock.release();
            match observed {
                Ok(observed) => observed,
                Err(predicate) => bugcheck_r3_unload_preflight(predicate),
            }
        };
        let named_receipts = [
            (
                process.admission_closed_for(registry),
                plan::R3UnloadPredicate::ProcessCallbackAdmissionClosed,
            ),
            (
                process.callbacks_drained_for(registry),
                plan::R3UnloadPredicate::ProcessCallbacksDrained,
            ),
            (
                setup.admission_closed_for(registry),
                plan::R3UnloadPredicate::SetupAdmissionClosed,
            ),
            (
                setup.admission_drained_for(registry),
                plan::R3UnloadPredicate::SetupAdmissionDrained,
            ),
            (
                finalizers.session_scan_stable_empty_for(registry),
                plan::R3UnloadPredicate::SessionScanStableEmpty,
            ),
            (
                finalizers.admission_closed_for(registry),
                plan::R3UnloadPredicate::FinalizerAdmissionClosed,
            ),
            (
                finalizers.callbacks_drained_for(registry),
                plan::R3UnloadPredicate::FinalizersDrained,
            ),
            (
                control.admission_closed_for(registry),
                plan::R3UnloadPredicate::ControlContextAdmissionClosed,
            ),
            (
                control.admission_drained_for(registry),
                plan::R3UnloadPredicate::ControlContextAdmissionDrained,
            ),
            (
                control.bindings_closed_for(registry),
                plan::R3UnloadPredicate::ControlBindingsClosed,
            ),
            (
                control.completed_records_absent_for(registry),
                plan::R3UnloadPredicate::CompletedControlRecordsAbsent,
            ),
            (
                control.close_rights_absent_for(registry),
                plan::R3UnloadPredicate::CloseRightsAbsent,
            ),
            (
                control.contexts_absent_for(registry),
                plan::R3UnloadPredicate::ControlContextsAbsent,
            ),
            (
                sole_root.matches_registry(registry),
                plan::R3UnloadPredicate::SoleDriverRootReference,
            ),
        ];
        for (clear, predicate) in named_receipts {
            if !clear {
                unsafe { bugcheck_r3_unload_preflight(predicate) }
            }
        }
        let destructive_roots_present = unsafe {
            !state.as_ref().fscontrol_device.is_null()
                && !state.as_ref().provider_device.is_null()
                && state.as_ref().allocation.is_some()
                && state.as_ref().trace.is_registered()
        };
        if !native_ledgers.matches_registry(registry) {
            unsafe { bugcheck_r3_unload_invariant(1) }
        }
        if !destructive_roots_present {
            unsafe { bugcheck_r3_unload_invariant(2) }
        }
        Self {
            state,
            _boundary: boundary,
            _native_ledgers: native_ledgers,
            _sole_root: sole_root,
            _process: process,
            _setup: setup,
            _finalizers: finalizers,
            _control: control,
            authority: PrivatePreparedUnloadDestruction(()),
        }
    }
}

/// FSD-private affine cursor for the infallible destructive suffix. The
/// effect-nine capability remains owned by exactly one cursor value until ETW
/// teardown consumes the allocation, so no suffix operation can be entered
/// directly or repeated.
struct R3UnloadSuffix<const NEXT: u8> {
    prepared: PreparedUnloadDestruction,
}

impl R3UnloadSuffix<10> {
    unsafe fn unregister_filesystem(self) -> R3UnloadSuffix<11> {
        let state = self.prepared.state.as_ptr();
        unsafe { crate::fscontrol::unregister((*state).fscontrol_device) };
        R3UnloadSuffix {
            prepared: self.prepared,
        }
    }
}

impl R3UnloadSuffix<11> {
    unsafe fn delete_fscontrol(self) -> R3UnloadSuffix<12> {
        let state = self.prepared.state.as_ptr();
        let fscontrol =
            unsafe { core::mem::replace(&mut (*state).fscontrol_device, core::ptr::null_mut()) };
        unsafe { crate::kernel::delete_device(fscontrol) };
        R3UnloadSuffix {
            prepared: self.prepared,
        }
    }
}

impl R3UnloadSuffix<12> {
    unsafe fn remove_provider_dos_link(self) -> R3UnloadSuffix<13> {
        unsafe { crate::control::remove_dos_link() };
        R3UnloadSuffix {
            prepared: self.prepared,
        }
    }
}

impl R3UnloadSuffix<13> {
    unsafe fn delete_provider(self) -> R3UnloadSuffix<14> {
        let state = self.prepared.state.as_ptr();
        let provider = unsafe {
            (*state)
                .sessions
                .destroy_prepared_work_items(&self.prepared._native_ledgers);
            core::mem::replace(&mut (*state).provider_device, core::ptr::null_mut())
        };
        unsafe { crate::kernel::delete_device(provider) };
        R3UnloadSuffix {
            prepared: self.prepared,
        }
    }
}

impl R3UnloadSuffix<14> {
    unsafe fn release_boot_objects(self) -> R3UnloadSuffix<15> {
        let state = self.prepared.state.as_ptr();
        unsafe {
            crate::boot::unmap_system_view(&mut (*state).boot);
            crate::boot::close_section(&mut (*state).boot);
            crate::boot::close_lock_event(&mut (*state).boot);
        }
        R3UnloadSuffix {
            prepared: self.prepared,
        }
    }
}

impl R3UnloadSuffix<15> {
    unsafe fn release_driver_state(self) -> R3UnloadSuffix<16> {
        let state = self.prepared.state.as_ptr();
        unsafe {
            core::ptr::write(&raw mut fsring_driver_state, core::ptr::null_mut());
            (*state).release();
        }
        R3UnloadSuffix {
            prepared: self.prepared,
        }
    }
}

impl R3UnloadSuffix<16> {
    unsafe fn unregister_etw(self) {
        let PreparedUnloadDestruction {
            state,
            _boundary,
            _native_ledgers,
            _sole_root,
            _process,
            _setup,
            _finalizers,
            _control,
            authority: PrivatePreparedUnloadDestruction(()),
        } = self.prepared;
        let state = state.as_ptr();
        unsafe {
            crate::trace::unregister(&mut (*state).trace);
            let allocation = (*state).allocation.take().unwrap_unchecked();
            core::ptr::drop_in_place(state);
            allocation.release();
        }
    }
}

unsafe fn bugcheck_r3_unload_preflight(predicate: plan::R3UnloadPredicate) -> ! {
    unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, 9, predicate as u64, 0, 0) }
}

unsafe fn bugcheck_r3_unload_invariant(reason: u64) -> ! {
    unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, 9, u64::MAX, reason, 0) }
}

/// The retained process-loss ingress.
///
/// A null `create_info` is process *exit*. If the exiting process is a
/// session's captured daemon, this claims that session with one exchange and
/// runs the same bounded six-stage fence CLEANUP and unload use, before
/// returning from the last exiting thread — so address-space teardown cannot
/// erase the retained stage-6 aliases first. It allocates nothing, issues no
/// user callback, performs no alertable wait, and never waits on daemon
/// progress.
///
/// The ABI is `extern "C"` because `PCREATE_PROCESS_NOTIFY_ROUTINE_EX` is.
///
/// # Safety
/// Invoked by the process manager at PASSIVE_LEVEL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsring_process_loss(
    process: PEPROCESS,
    _process_id: wdk_sys::HANDLE,
    create_info: wdk_sys::PPS_CREATE_NOTIFY_INFO,
) {
    if !create_info.is_null() || process.is_null() {
        // Process creation carries no session decision.
        return;
    }
    // SAFETY: the load published the root before the callback could fire, and
    // unregistration waits for in-flight callbacks before it is released.
    let state = unsafe { root() };
    if state.is_null() {
        return;
    }
    // SAFETY: the root outlives every callback it admitted.
    let registry =
        unsafe { core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*state).sessions)) };
    unsafe { plan::run_r3_process_callback(NativeR3ProcessCallbackOps { registry, process }) };
}

struct NativeR3ProcessCallbackOps {
    registry: core::ptr::NonNull<KernelSessionRegistry>,
    process: PEPROCESS,
}

impl plan::R3ProcessCallbackNativeOps for NativeR3ProcessCallbackOps {
    type Guard = crate::lifecycle::ProcessCallbackGuard;

    unsafe fn acquire_guard(&mut self) -> plan::R3ProcessCallbackAdmission<Self::Guard> {
        match unsafe { crate::lifecycle::ProcessCallbackGuard::acquire(self.registry) } {
            Some(guard) => plan::R3ProcessCallbackAdmission::Admitted(guard),
            None => plan::R3ProcessCallbackAdmission::Refused,
        }
    }

    unsafe fn observe_one(
        &mut self,
        guard: &Self::Guard,
        cursor: u32,
    ) -> plan::R3ProcessCallbackStep {
        let registry = guard.registry();
        debug_assert_eq!(registry, self.registry);
        match unsafe {
            crate::lifecycle::KernelSessionRegistry::scan_one_cell_for_process(
                guard,
                self.process,
                cursor,
            )
        } {
            crate::lifecycle::ProcessScanStep::Action(action) => {
                match action {
                    crate::lifecycle::ProcessScanAction::Winner {
                        context,
                        disposition,
                    } => {
                        let _ = unsafe {
                            crate::fence::run_terminal_from_disposition(
                                registry,
                                context,
                                disposition,
                            )
                        };
                    }
                    crate::lifecycle::ProcessScanAction::Join(join) => {
                        unsafe { crate::fence::discharge_process_join(join) };
                    }
                    crate::lifecycle::ProcessScanAction::Completed(_)
                    | crate::lifecycle::ProcessScanAction::Blocked(_)
                    | crate::lifecycle::ProcessScanAction::Opaque(_) => {}
                }
                plan::R3ProcessCallbackStep::Restart
            }
            crate::lifecycle::ProcessScanStep::Skip {
                resume_at: Some(next),
            } => plan::R3ProcessCallbackStep::ResumeAt(next),
            crate::lifecycle::ProcessScanStep::Skip { resume_at: None }
            | crate::lifecycle::ProcessScanStep::Complete => plan::R3ProcessCallbackStep::Complete,
            crate::lifecycle::ProcessScanStep::FailStop => plan::R3ProcessCallbackStep::Invariant,
        }
    }

    unsafe fn release_guard(self, guard: Self::Guard) {
        debug_assert_eq!(guard.registry(), self.registry);
        unsafe { guard.release() };
    }

    unsafe fn wait_process_scan_invariant_forever(self, guard: Self::Guard) -> ! {
        debug_assert_eq!(guard.registry(), self.registry);
        let _retained_guard = guard;
        unsafe { crate::lifecycle::wait_process_scan_invariant_forever(self.registry) }
    }
}
