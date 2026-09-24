//! Permanent native C4 session cells and affine control-context ownership.

// MEASURED, round 19, in the WDK environment this crate needs: removing the
// three module-wide `#![allow(dead_code)]` in `fsring-fsd` and running
// `cargo check -p fsring-fsd --all-targets` gives 63 unique dead-code
// diagnostics -- 33 here, 28 in `fence.rs`, 2 in `trace.rs` -- counted from
// `--message-format=json` by lint code and location. Round-18 native review
// N18-3 raised that this population had never been measured, because round
// 18's sweep of false allow comments stopped at the crate boundary. The allow
// stays: it is what makes `-D warnings` builds possible while this surface is
// still being wired. It is not a claim that anything here is reachable, and no
// comment in this crate may name a task as the future caller of an item.
#![allow(dead_code)]

use core::{cell::UnsafeCell, mem::MaybeUninit, ptr::NonNull};

use fsring_abi::validate::SessionIdentity;
use fsring_core::{
    adapter::lifecycle::{
        ExpectedMountTeardown, FinalizerState, JoinedMountCompletion, JoinedMountResetProof,
        LifecycleError, MountClaim, MountCompleteSignal, MountDoneAcknowledgement,
        MountDonePublication, MountDrainRight, MountJoinAcknowledgement, MountJoinConversion,
        MountJoinTicket, MountOwnerPublication, MountPublicationKind, MountPublicationObservation,
        MountRendezvous, MountResetAcknowledgement, MountResetCompleteSignal,
        MountResetJoinAcknowledgement, MountResetJoinRelease, MountResetJoinTicket,
        MountResetProof, MountResetPublication, MountResetWaitersDrainedSignal, MountTeardownRight,
        MountWaitEvent, MountWaitObservation, MountWaitersDrainedSignal, NativeCellPhase,
        NativeCellProcessObservation, NativeOwnerSlotObservation,
        NativeSessionOwner as CoreNativeSessionOwner, NativeSessionSharedOps, OwnerMountCompletion,
        PreparedMountActivation, PreparedMountInstall, PreparedMountReset, ResolvePlan,
        ResolveProgress, ResolveRejection, ResolveStep, SavedIrql,
        SessionRootReleaseRight as CoreSessionRootReleaseRight, SharedSessionProjection,
        TerminalWaitDisposition, acquire_saved_irql, native_owner_slots_match,
        observe_cell_process, resolve_terminal_release,
    },
    session::{
        CoreTerminalClaimKind, CoreTerminalDisposition, PreparedTerminalClaim,
        R3FinalizerCellBindRight, RegistryLease, SessionLocator, SessionRegistry, StrongSessionRef,
        TerminalRendezvous, TerminalRequest, TerminalResult,
    },
};
use fsring_sys::c4::{
    DEVICE_OBJECT, EX_RUNDOWN_REF, KDPC, KEVENT, KIRQL, KSPIN_LOCK, KTIMER, NotificationEvent,
    PDEVICE_OBJECT, PEPROCESS, PIO_WORKITEM, PIRP, VPB,
};
use wdk_sys::{NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER};

use crate::{control::ControlFileContext, session::NativeSession};

pub(crate) const SESSION_CELL_COUNT: usize = crate::platform::MOUNT_REGISTRY_CAPACITY;
const _: () = assert!(SESSION_CELL_COUNT == fsring_abi::control::BOOT_CONTEXT_SLOT_COUNT as usize);
const _: () = assert!(SESSION_CELL_COUNT == 64);

#[repr(C)]
pub(crate) struct KernelSessionRegistry {
    lock: UnsafeCell<MaybeUninit<KSPIN_LOCK>>,
    /// Software admission doors closed atomically by unload effect one.
    ///
    /// WDK rundown cannot be closed nonblocking: ExWait both starts rundown
    /// and blocks, and ExRundownCompleted is legal only after it. Acquirers
    /// therefore take the native rundown first, serialize this check through
    /// the same registry lock as unload, and release/refuse if their door was
    /// closed meanwhile.
    setup_admission_open: UnsafeCell<bool>,
    control_context_admission_open: UnsafeCell<bool>,
    process_callback_admission_open: UnsafeCell<bool>,
    finalizer_admission_open: UnsafeCell<bool>,
    setup_admission: UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,
    control_context_admission: UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,
    /// The process-notify callback's own admission.
    ///
    /// It is separate from `setup_admission` because the two close at different
    /// points and wait for different things: unload unregisters the callback and
    /// waits *this* rundown before it enumerates cells, while setup admission
    /// covers in-flight SETUPs. Sharing one rundown would mean either waiting
    /// for SETUPs before unregistering the callback or letting a callback run
    /// after the wait it was supposed to be inside.
    process_callback_admission: UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,
    finalizer_admission: UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,
    /// A permanently nonsignaled event, and the only thing a blocked unload
    /// waits on.
    ///
    /// There is deliberately no API that signals it. An unload that reaches a
    /// permanently blocked generation must not return -- returning would unload
    /// an image a stuck thread is still inside -- and it must not spin, and it
    /// must not reuse `terminal_outcome` or `joiners_drained`, both of which
    /// *do* get signalled and would turn the permanent wait into a successful
    /// drain. A nonsignaled `NotificationEvent` nobody sets is the only shape
    /// that cannot be mistaken for progress.
    blocked_unload: UnsafeCell<MaybeUninit<KEVENT>>,
    core: UnsafeCell<SessionRegistry<SESSION_CELL_COUNT>>,
    cells: [UnsafeCell<NativeSessionCell>; SESSION_CELL_COUNT],
}

/// Permanent callback context for one preallocated finalizer work item.
///
/// The I/O manager gives the callback only this address. Keeping both the
/// registry and the permanent cell index here preserves the identity consumed
/// from `R3FinalizerKick` across the asynchronous queue boundary.
#[repr(C)]
struct FinalizerWorkItemContext {
    registry: NonNull<KernelSessionRegistry>,
    cell_index: u32,
    queued: Option<fsring_core::adapter::fence::R3FinalizerCallbackContext>,
}

#[repr(C)]
pub(crate) struct NativeSessionCell {
    access: EX_RUNDOWN_REF,
    terminal_outcome: KEVENT,
    joiners_drained: KEVENT,
    /// Broadcast generation visibility: set after either ordinary finalizer
    /// resolution or durable Published/Opaque storage. Unlike the take-once
    /// `finalizer_handoff`, every counted joiner may wait on this event.
    visibility_resolution: KEVENT,
    mount_complete: KEVENT,
    mount_waiters_drained: KEVENT,
    mount_reset_complete: KEVENT,
    mount_reset_waiters_drained: KEVENT,
    generation: u64,
    identity: Option<SessionIdentity>,
    phase: NativeCellPhase,
    session: *mut NativeSession,
    process: PEPROCESS,
    registry_lease: Option<RegistryLease>,
    control_owner: Option<ControlOwner>,
    recorded_control_context: Option<NonNull<ControlFileContext>>,
    /// The authentic shell and root owners, deposited by the locked
    /// publication suffix and moved out again at the winning terminal claim.
    /// Empty while Staging; `session` above stays a nonowning mirror.
    shell_owner: Option<NativeSessionOwner>,
    root_release: Option<SessionRootReleaseRight>,
    mount_rendezvous: NativeMountRendezvous,
    terminal_rendezvous: TerminalRendezvous,
    /// The process mirror is retained for fail-stop diagnostics, while this
    /// generation marker is consumed after one callback observes it. This is
    /// what makes restart-after-Completed/Blocked reach later cells without
    /// erasing retained process or durable-slot state.
    process_loss_handled: bool,
    /// The active-version deletion readiness, parked when the checkpoint
    /// finished while other stable owners still held the generation. Exactly
    /// one of this and `finalizer_deposit` is ever occupied: the release that
    /// reaches zero moves the readiness out and stores the combined deposit.
    checkpoint_readiness: Option<crate::fence::FenceDeletionReadiness>,
    /// This generation's pending-ENTER runtime.
    ///
    /// It lives in the *permanent* cell rather than in `NativeSession` because
    /// the checkpoint releases the session's transient backing while contexts
    /// may still have to be observed: a fail-stopped publication keeps its
    /// packet in its context, and unload has to be able to look at it after the
    /// shell is gone. Installed by the locked publication suffix between core
    /// preparation and core commit, so no observer ever sees a Live session
    /// without its runtime or an installed runtime on a Staging session.
    pending_runtime: Option<crate::pending_enter::PendingRuntimeReady>,
    /// The bound pending control ledger this generation's installs link into.
    ///
    /// It arrives out of the same aggregate publication as the runtime, and it
    /// is the only thing that can mint a `PendingControlLinkRight`, so a cell
    /// holding a runtime and no ledger could park an ENTER that nothing could
    /// later unlink.
    pending_ledger:
        Option<fsring_core::session::PendingControlLedger<{ crate::session::MAX_PENDING_LINKS }>>,
    /// Closed durable storage for one whole checkpoint or delete refusal.
    /// Once occupied it is never cleared, projected, retried, or converted.
    fail_stop: crate::fence::R3FailStopSlot,
    finalizer_handoff: Option<FinalizerVisibilityHandoff>,
    /// The active-version deposit: readiness plus the one deletion right.
    finalizer: fsring_core::adapter::fence::R3FinalizerCell<crate::fence::R4DeletionOwners>,
    finalizer_context: FinalizerWorkItemContext,
    finalizer_work_item: PIO_WORKITEM,
    finalizer_callback_admitted: Option<FinalizerCallbackAdmission>,
    fence_retry_timer: MaybeUninit<KTIMER>,
    fence_retry_dpc: MaybeUninit<KDPC>,
    fence_retry_dpc_exit: MaybeUninit<KEVENT>,
    fence_retry_work_item: PIO_WORKITEM,
    fence_retry_park: Option<crate::fence::ParkedFenceResidual>,
}

#[derive(Clone, Copy)]
enum RegistryInitializationStep {
    Lock,
    AdmissionDoors,
    SetupAdmission,
    ControlContextAdmission,
    ProcessCallbackAdmission,
    FinalizerAdmission,
    BlockedUnloadEvent,
    Core,
    Cells,
}

const REGISTRY_INITIALIZATION_PLAN: [RegistryInitializationStep; 9] = [
    RegistryInitializationStep::Lock,
    RegistryInitializationStep::AdmissionDoors,
    RegistryInitializationStep::SetupAdmission,
    RegistryInitializationStep::ControlContextAdmission,
    RegistryInitializationStep::ProcessCallbackAdmission,
    RegistryInitializationStep::FinalizerAdmission,
    RegistryInitializationStep::BlockedUnloadEvent,
    RegistryInitializationStep::Core,
    RegistryInitializationStep::Cells,
];

#[derive(Clone, Copy)]
enum CellEvent {
    TerminalOutcome,
    JoinersDrained,
    VisibilityResolution,
    MountComplete,
    MountWaitersDrained,
    MountResetComplete,
    MountResetWaitersDrained,
}

#[derive(Clone, Copy)]
enum CellInitializationStep {
    AccessRundown,
    Event(CellEvent, bool),
    EmptyObservations,
}

const CELL_INITIALIZATION_PLAN: [CellInitializationStep; 9] = [
    CellInitializationStep::AccessRundown,
    CellInitializationStep::Event(CellEvent::TerminalOutcome, false),
    CellInitializationStep::Event(CellEvent::JoinersDrained, true),
    CellInitializationStep::Event(CellEvent::VisibilityResolution, false),
    CellInitializationStep::Event(CellEvent::MountComplete, false),
    CellInitializationStep::Event(CellEvent::MountWaitersDrained, true),
    CellInitializationStep::Event(CellEvent::MountResetComplete, false),
    CellInitializationStep::Event(CellEvent::MountResetWaitersDrained, true),
    CellInitializationStep::EmptyObservations,
];

const fn rollback_cell_index(step: usize) -> usize {
    let Some(one_past) = SESSION_CELL_COUNT.checked_sub(step) else {
        panic!("rollback step exceeds the permanent cell count")
    };
    let Some(index) = one_past.checked_sub(1) else {
        panic!("rollback step exceeds the permanent cell count")
    };
    index
}

const fn take_and_clear_slot<T: Copy>(slot: &mut T, empty: T) -> T {
    let value = *slot;
    *slot = empty;
    value
}

pub(crate) struct NativeMountedDeviceOwner {
    device: NonNull<DEVICE_OBJECT>,
}

pub(crate) struct NativeMountedVpbOwner {
    vpb: NonNull<VPB>,
}

pub(crate) struct PreparedNativeMountInstall {
    core: PreparedMountInstall,
}

/// Receipt that the complete native mount owner is registry-visible.
///
/// The mounted-device owner itself moved into the rendezvous during commit;
/// consuming core's exact affine receipt under the registry lock is the sole
/// authorization to borrow and expose it.
pub(crate) struct NativeMountOwnerPublication {
    core: MountOwnerPublication,
}

pub(crate) struct NativeMountRendezvous {
    core: MountRendezvous<NativeMountedDeviceOwner, NativeMountedVpbOwner>,
}

impl NativeMountedDeviceOwner {
    /// # Safety
    /// `device` is the unique, still-initializing device just returned by this
    /// driver's successful `IoCreateDevice` call.
    pub(crate) unsafe fn from_created(device: PDEVICE_OBJECT) -> Option<Self> {
        NonNull::new(device).map(|device| Self { device })
    }

    pub(crate) fn as_ptr(&self) -> PDEVICE_OBJECT {
        self.device.as_ptr()
    }

    /// # Safety
    /// The VPB no longer names this device and no registry or VPB lock is held.
    pub(crate) unsafe fn delete(self) {
        unsafe { crate::kernel::delete_device(self.device.as_ptr()) };
    }
}

impl NativeMountedVpbOwner {
    /// # Safety
    /// `vpb` is the non-null VPB supplied for this exact mount transaction.
    pub(crate) unsafe fn from_mount_vpb(vpb: *mut VPB) -> Option<Self> {
        NonNull::new(vpb).map(|vpb| Self { vpb })
    }

    pub(crate) fn as_ptr(&self) -> *mut VPB {
        self.vpb.as_ptr()
    }

    /// Clear the published binding while consuming its one native owner.
    ///
    /// # Safety
    /// PASSIVE_LEVEL, no registry lock held, and `self` came from the owner
    /// claim for the mounted device that is about to be deleted.
    pub(crate) unsafe fn clear_binding(self) {
        let mut irql: KIRQL = 0;
        unsafe { fsring_sys::c4::IoAcquireVpbSpinLock(&raw mut irql) };
        unsafe {
            (*self.vpb.as_ptr()).DeviceObject = core::ptr::null_mut();
            (*self.vpb.as_ptr()).Flags &= !(wdk_sys::VPB_MOUNTED as u16);
        }
        unsafe { fsring_sys::c4::IoReleaseVpbSpinLock(irql) };
    }
}

impl NativeMountOwnerPublication {
    /// Consume this exact receipt and clear the initializing flag while the
    /// owner is still protected by the `Publishing` rendezvous phase.
    ///
    /// # Safety
    /// The commit VPB lock has been released, `rendezvous` belongs to the exact
    /// permanent cell selected under its registry lock, and that lock remains
    /// held until this call returns.
    pub(crate) unsafe fn clear_device_initializing(
        self,
        rendezvous: &mut NativeMountRendezvous,
    ) -> Result<(), (LifecycleError, Self)> {
        let Self { core } = self;
        match rendezvous
            .core
            .commit_owner_exposure(core, |mounted| unsafe {
                (*mounted.as_ptr()).Flags &= !wdk_sys::DO_DEVICE_INITIALIZING;
            }) {
            Ok(()) => Ok(()),
            Err((error, core)) => Err((error, Self { core })),
        }
    }
}

impl NativeMountRendezvous {
    pub(crate) const fn new_inactive() -> Self {
        Self {
            core: MountRendezvous::new_inactive(),
        }
    }

    /// The four fused signal/acknowledgement windows.
    ///
    /// Each forwards to the core runner with this rendezvous' own `core`, so
    /// there is no projection that hands a native caller a
    /// `&mut MountRendezvous`: the core rendezvous cannot be extracted, and a
    /// typed signal cannot be split from the acknowledgement that matches it.
    /// Core still performs both halves in one call, which is what makes the
    /// split structurally impossible rather than merely discouraged.
    ///
    /// # Safety
    /// `signal` synchronously signals the matching permanent cell's event
    /// exactly once with `Wait = FALSE` and returns before core acknowledges.
    pub(crate) unsafe fn run_done_signal_ack(
        &mut self,
        publication: MountDonePublication,
        signal: impl FnOnce(&MountCompleteSignal),
    ) -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {
        // SAFETY: forwarded from this method's caller.
        unsafe {
            fsring_core::adapter::lifecycle::run_r3_mount_done_signal_ack(
                &mut self.core,
                publication,
                signal,
            )
        }
    }

    /// # Safety
    /// As `run_done_signal_ack`, for the ordinary-waiters-drained window.
    pub(crate) unsafe fn run_ordinary_drained_signal_ack(
        &mut self,
        conversion: MountJoinConversion,
        signal: impl FnOnce(&MountWaitersDrainedSignal),
    ) -> Result<MountResetJoinTicket, (LifecycleError, MountJoinAcknowledgement)> {
        // SAFETY: forwarded from this method's caller.
        unsafe {
            fsring_core::adapter::lifecycle::run_r3_mount_ordinary_drained_signal_ack(
                &mut self.core,
                conversion,
                signal,
            )
        }
    }

    /// # Safety
    /// As `run_done_signal_ack`, for the reset-complete window.
    pub(crate) unsafe fn run_reset_complete_signal_ack(
        &mut self,
        publication: MountResetPublication,
        signal: impl FnOnce(&MountResetCompleteSignal),
    ) -> Result<MountResetProof, (LifecycleError, MountResetAcknowledgement)> {
        // SAFETY: forwarded from this method's caller.
        unsafe {
            fsring_core::adapter::lifecycle::run_r3_mount_reset_complete_signal_ack(
                &mut self.core,
                publication,
                signal,
            )
        }
    }

    /// # Safety
    /// As `run_done_signal_ack`, for the reset-waiters-drained window.
    pub(crate) unsafe fn run_reset_waiters_drained_signal_ack(
        &mut self,
        release: MountResetJoinRelease,
        signal: impl FnOnce(&MountResetWaitersDrainedSignal),
    ) -> Result<JoinedMountResetProof, (LifecycleError, MountResetJoinAcknowledgement)> {
        // SAFETY: forwarded from this method's caller.
        unsafe {
            fsring_core::adapter::lifecycle::run_r3_mount_reset_waiters_drained_signal_ack(
                &mut self.core,
                release,
                signal,
            )
        }
    }

    const fn r3_unload_is_inactive(&self) -> bool {
        self.core.r3_unload_is_inactive()
    }

    const fn r3_unload_owner_is_absent(&self) -> bool {
        self.core.r3_unload_owner_is_absent()
    }

    const fn r3_unload_tickets_and_waiters_are_drained(&self) -> bool {
        self.core.r3_unload_tickets_and_waiters_are_drained()
    }

    const fn r3_unload_signals_are_acknowledged(&self) -> bool {
        self.core.r3_unload_signals_are_acknowledged()
    }

    pub(crate) fn activate(&mut self, locator: SessionLocator) -> Result<(), LifecycleError> {
        self.core.activate(locator)
    }

    /// Mutation-free preflight for the locked publication suffix.
    pub(crate) fn preflight_activate(
        &self,
        locator: SessionLocator,
    ) -> Result<PreparedNativeMountActivation, LifecycleError> {
        self.core
            .prepare_activation(locator)
            .map(|core| PreparedNativeMountActivation {
                core,
                authority: PrivateNativeMountActivationAuthority(()),
            })
    }

    /// # Safety
    /// `prepared` came from `preflight_activate` on this exact rendezvous under
    /// the registry lock that is still held. The commit cannot refuse.
    pub(crate) unsafe fn commit_prepared_activation(
        &mut self,
        prepared: PreparedNativeMountActivation,
    ) {
        let PreparedNativeMountActivation {
            core,
            authority: PrivateNativeMountActivationAuthority(()),
        } = prepared;
        unsafe { self.core.commit_prepared_activation(core) };
    }

    /// Borrow-check every owner piece before the locked publication commit.
    pub(crate) fn prepare_install(
        &self,
        locator: SessionLocator,
        reference: &StrongSessionRef,
        mounted: &NativeMountedDeviceOwner,
        vpb: &NativeMountedVpbOwner,
    ) -> Result<PreparedNativeMountInstall, LifecycleError> {
        self.core
            .prepare_install(locator, reference, mounted, vpb)
            .map(|core| PreparedNativeMountInstall { core })
    }

    /// # Safety
    /// `prepared` was produced by this exact rendezvous in the same registry
    /// lock hold and the three consumed owners are the values it borrowed.
    pub(crate) unsafe fn commit_prepared_install(
        &mut self,
        prepared: PreparedNativeMountInstall,
        reference: StrongSessionRef,
        mounted: NativeMountedDeviceOwner,
        vpb: NativeMountedVpbOwner,
    ) -> NativeMountOwnerPublication {
        let core = unsafe {
            self.core
                .commit_prepared_install(prepared.core, reference, mounted, vpb)
        };
        NativeMountOwnerPublication { core }
    }

    /// The exact expectation `take_or_join` will accept right now.
    pub(crate) fn expected_teardown(
        &self,
        locator: SessionLocator,
    ) -> Option<ExpectedMountTeardown> {
        self.core.expected_teardown(locator)
    }

    /// Validate the sealed locator, mount generation, and wait phase while the
    /// permanent cell remains protected by the registry lock.
    pub(crate) fn matches_wait_observation(&self, observation: &MountWaitObservation) -> bool {
        self.core.matches_wait_observation(observation)
    }

    fn matches_publication_observation<Kind: MountPublicationKind>(
        &self,
        observation: &MountPublicationObservation<Kind>,
    ) -> bool {
        self.core.matches_publication_observation(observation)
    }

    /// Take the mount, join the teardown already running, or observe absence.
    ///
    /// The `expected` value it returns inside the claim is what the completion
    /// must later be bound to, which is why the caller passes one in: the
    /// expectation and the completion come from the same call or they do not
    /// match.
    fn take_or_join(
        &mut self,
        expected: ExpectedMountTeardown,
    ) -> Result<MountClaim<NativeMountedDeviceOwner, NativeMountedVpbOwner>, LifecycleError> {
        self.core.take_or_join(expected)
    }

    pub(crate) fn publish_done(
        &mut self,
        right: MountTeardownRight,
    ) -> Result<MountDonePublication, (LifecycleError, MountTeardownRight)> {
        self.core.publish_done(right)
    }

    fn release_join(
        &mut self,
        ticket: MountJoinTicket,
    ) -> Result<MountJoinConversion, (LifecycleError, MountJoinTicket)> {
        self.core.release_join(ticket)
    }

    pub(crate) fn poll_drain(
        &mut self,
        right: MountDrainRight,
    ) -> Result<PreparedMountReset, (LifecycleError, MountDrainRight)> {
        self.core.poll_drain(right)
    }

    // Every refusal returns the affine owners it was handed, which is the
    // property proving nothing was consumed on the refused path; boxing it
    // would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub(crate) fn finish_reset(
        &mut self,
        prepared: PreparedMountReset,
    ) -> Result<MountResetPublication, (LifecycleError, PreparedMountReset)> {
        self.core.finish_reset(prepared)
    }

    pub(crate) fn finish_joined_reset(
        &mut self,
        ticket: MountResetJoinTicket,
    ) -> Result<MountResetJoinRelease, (LifecycleError, MountResetJoinTicket)> {
        self.core.finish_joined_reset(ticket)
    }

    pub(crate) fn complete_owner(
        &self,
        proof: MountResetProof,
    ) -> Result<OwnerMountCompletion, (LifecycleError, MountResetProof)> {
        self.core.complete_owner(proof)
    }

    pub(crate) fn complete_joined(
        &self,
        proof: JoinedMountResetProof,
    ) -> Result<JoinedMountCompletion, (LifecycleError, JoinedMountResetProof)> {
        self.core.complete_joined(proof)
    }

    /// # Safety
    /// The final delete cursor minted `right` after both native owners and all
    /// mount waiters were consumed.
    pub(crate) unsafe fn deactivate_after_delete_prepared(
        &mut self,
        right: fsring_core::adapter::fence::MountRendezvousResetRight,
    ) {
        unsafe { self.core.deactivate_after_delete_prepared(right) };
    }
}

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(struct $name(());)+
    };
}

private_authority_seals!(
    PrivateControlContextLeaseAuthority,
    PrivateCloseContextRightAuthority,
    PrivateClosingCompletionObligation,
    PrivateNonPagedAllocationAuthority,
    PrivateNativeMountActivationAuthority,
    PrivateUnpublishedNativeSessionShellAuthority,
);

/// Sole ownership of a freshly allocated, not-yet-published setup shell.
///
/// Allocation is the only place this can come from, and it is consumed either
/// by `bind` (into the locator-branded owner) or by `destroy`. There is no
/// pointer-to-owner conversion, so no rollback or teardown path can invent
/// destruction authority from an address it happens to be holding.
pub(crate) struct UnpublishedNativeSessionShell {
    session: NonNull<NativeSession>,
    authority: PrivateUnpublishedNativeSessionShellAuthority,
}

/// The private WDK-bearing payload stored only inside core's affine envelope.
pub(crate) struct NativeSessionShell {
    session: NonNull<NativeSession>,
}

/// The private payload for the session's one driver-root release.
pub(crate) struct DriverRootRelease {
    state: NonNull<crate::driver::DriverState>,
}

pub(crate) type NativeSessionOwner = CoreNativeSessionOwner<NativeSessionShell>;
pub(crate) type SessionRootReleaseRight = CoreSessionRootReleaseRight<DriverRootRelease>;

impl UnpublishedNativeSessionShell {
    /// # Safety
    /// `session` is the unique freshly allocated, initialized setup shell and
    /// no other owning record exists. This exact allocation site is audited.
    pub(crate) unsafe fn from_fresh_allocation(session: NonNull<NativeSession>) -> Self {
        Self {
            session,
            authority: PrivateUnpublishedNativeSessionShellAuthority(()),
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut NativeSession {
        self.session.as_ptr()
    }

    pub(crate) fn into_published_payload(self) -> NativeSessionShell {
        let Self {
            session,
            authority: PrivateUnpublishedNativeSessionShellAuthority(()),
        } = self;
        NativeSessionShell { session }
    }

    /// # Safety
    /// Every native resource reachable from the shell has already been
    /// unwound, and the shell is unpublished, so nothing can still reach it.
    pub(crate) unsafe fn destroy(self) {
        let Self {
            session,
            authority: PrivateUnpublishedNativeSessionShellAuthority(()),
        } = self;
        unsafe { crate::session::free_session_shell_allocation(session.as_ptr()) };
    }
}

impl NativeSessionSharedOps for NativeSessionShell {
    type Mirror = *mut NativeSession;

    fn matches_mirror(&self, mirror: Self::Mirror) -> bool {
        self.session.as_ptr() == mirror
    }

    fn checkpoint_close_session_admission(&self) -> bool {
        unsafe { crate::session::checkpoint_close_session_admission(self.session.as_ptr()) }
    }

    fn checkpoint_signal_existing_enter_waiters(&self) -> bool {
        unsafe { crate::session::checkpoint_signal_existing_enter_waiters(self.session.as_ptr()) }
    }

    fn checkpoint_wait_existing_sq_cq_roles_and_consumers(&self) -> bool {
        unsafe {
            crate::session::checkpoint_wait_existing_sq_cq_roles_and_consumers(
                self.session.as_ptr(),
            )
        }
    }

    fn checkpoint_remove_producer_mappings_reverse(&self) -> bool {
        unsafe {
            crate::session::checkpoint_remove_producer_mappings_reverse(self.session.as_ptr())
        }
    }

    fn checkpoint_wait_producer_and_mapping_capture_rundown(&self) -> bool {
        unsafe {
            crate::session::checkpoint_wait_producer_and_mapping_capture_rundown(
                self.session.as_ptr(),
            )
        }
    }

    fn checkpoint_retire_existing_grant_and_credit_state(&self) -> bool {
        unsafe {
            crate::session::checkpoint_retire_existing_grant_and_credit_state(self.session.as_ptr())
        }
    }

    fn checkpoint_deposit_pending_fence_wakes(&self) -> bool {
        unsafe { crate::session::checkpoint_deposit_pending_fence_wakes(self.session.as_ptr()) }
    }

    fn checkpoint_acquire_consumers_increasing(&self) -> bool {
        unsafe { crate::session::checkpoint_acquire_consumers_increasing(self.session.as_ptr()) }
    }

    fn checkpoint_release_consumers(&self) -> bool {
        unsafe { crate::session::checkpoint_release_consumers(self.session.as_ptr()) }
    }

    fn checkpoint_queue_installed_work(&self) -> bool {
        unsafe { crate::session::checkpoint_queue_installed_work(self.session.as_ptr()) }
    }

    fn checkpoint_wait_pending_and_owners(&self) -> bool {
        unsafe { crate::session::checkpoint_wait_pending_and_owners(self.session.as_ptr()) }
    }

    fn checkpoint_release_read_only_mappings_reverse(&self) -> bool {
        unsafe {
            crate::session::checkpoint_release_read_only_mappings_reverse(self.session.as_ptr())
        }
    }

    fn checkpoint_release_mdls_and_system_view(&self) -> bool {
        unsafe { crate::session::checkpoint_release_mdls_and_system_view(self.session.as_ptr()) }
    }

    fn checkpoint_release_captured_process(&self) -> bool {
        unsafe { crate::session::checkpoint_release_captured_process(self.session.as_ptr()) }
    }

    fn checkpoint_release_transient_arrays_and_backing(&self) -> bool {
        unsafe {
            crate::session::checkpoint_release_transient_arrays_and_backing(self.session.as_ptr())
        }
    }

    fn checkpoint_delete_vdo_once(&self) -> bool {
        // Mounted-device and VPB ownership live exclusively in the mount
        // rendezvous. The session shell owns only this named take-once VDO.
        unsafe { crate::session::delete_vdo_once(self.session.as_ptr()) }
    }
}

impl DriverRootRelease {
    /// Perform the one checked `DriverState` acquire before publication.
    ///
    /// # Safety
    /// `state` is the live driver root and stays live for the whole lifetime of
    /// the returned right. This is the only constructor of a session
    /// root-release authority.
    pub(crate) unsafe fn acquire(
        state: NonNull<crate::driver::DriverState>,
    ) -> Result<Self, LifecycleError> {
        // SAFETY: the caller guarantees the root is live.
        if !unsafe { state.as_ref() }.acquire() {
            return Err(LifecycleError::Invariant);
        }
        Ok(Self { state })
    }

    /// # Safety
    /// Called once, at a point where dropping the session's root reference
    /// cannot race the root's own destruction.
    pub(crate) unsafe fn release_unpublished(self) {
        let Self { state } = self;
        // SAFETY: the right was minted from a live root that outlives it.
        unsafe { state.as_ref() }.release();
    }
}

// SAFETY: this is the sole production payload consumer. Core supplies the
// unforgeable successful-delete permit and fixes the call order around it.
unsafe impl fsring_core::adapter::fence::PreparedDeleteStorageOps<DriverRootRelease>
    for NativeSessionShell
{
    unsafe fn destroy_shell_then_release_root(
        self,
        root: DriverRootRelease,
        _permit: &fsring_core::adapter::fence::PreparedDeleteExecutionPermit,
    ) {
        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };
        unsafe { root.state.as_ref() }.release();
    }
}

/// A preflighted native mount activation.
///
/// It seals the core decision behind an fsd-private authority so the locked
/// publication suffix cannot be handed an activation minted anywhere else.
pub(crate) struct PreparedNativeMountActivation {
    core: PreparedMountActivation,
    authority: PrivateNativeMountActivationAuthority,
}

pub(crate) struct NonPagedAllocationOwner {
    base: NonNull<u8>,
    bytes: usize,
    tag: u32,
    authority: PrivateNonPagedAllocationAuthority,
}

impl NonPagedAllocationOwner {
    /// # Safety
    /// Called only at PASSIVE setup with a nonzero checked size and the fixed
    /// C4 pool tag. Success uniquely owns the exact returned allocation.
    pub(crate) unsafe fn allocate(bytes: usize, tag: u32) -> Result<Self, NTSTATUS> {
        if bytes == 0 || tag != crate::kernel::POOL_TAG {
            return Err(STATUS_INVALID_PARAMETER);
        }
        #[cfg(feature = "platform-win7")]
        let pool_type = fsring_sys::pool_type::NON_PAGED;
        #[cfg(not(feature = "platform-win7"))]
        let pool_type = fsring_sys::pool_type::NON_PAGED_NX;
        let size = fsring_sys::SIZE_T::try_from(bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;

        // SAFETY: the caller guarantees PASSIVE setup; both selected pool
        // types are nonpaged and the nonzero size/tag were checked above.
        let base = unsafe { fsring_sys::ExAllocatePoolWithTag(pool_type, size, tag) }.cast::<u8>();
        let Some(base) = NonNull::new(base) else {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        #[cfg(feature = "platform-win7")]
        unsafe {
            // SAFETY: Win7's legacy allocator does not zero. This owner must
            // never expose old pool bytes to typed initialization.
            core::ptr::write_bytes(base.as_ptr(), 0, bytes);
        }
        Ok(Self {
            base,
            bytes,
            tag,
            authority: PrivateNonPagedAllocationAuthority(()),
        })
    }

    pub(crate) const fn region(&self) -> (NonNull<u8>, usize) {
        (self.base, self.bytes)
    }

    /// # Safety
    /// Every embedded context/token/work item has already been destroyed and
    /// no pointer or borrow into this region remains. Pool free is the final,
    /// infallible action; the consumed owner cannot be recovered afterward.
    pub(crate) unsafe fn release(self) {
        let Self {
            base,
            bytes: _,
            tag,
            authority: PrivateNonPagedAllocationAuthority(()),
        } = self;
        // SAFETY: this consumed owner uniquely owns the allocation and exposes
        // no pointer after the final free.
        unsafe { fsring_sys::ExFreePoolWithTag(base.as_ptr().cast(), tag) };
    }
}

pub(crate) struct ControlContextLease {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateControlContextLeaseAuthority,
}

pub(crate) struct SetupAdmissionGuard {
    registry: NonNull<KernelSessionRegistry>,
}

pub(crate) struct ClosedGlobalAdmissions {
    scan: R3UnloadScanAdmission,
    process: ProcessCallbackAdmissionClosed,
    setup: SetupAdmissionClosed,
    control: ControlContextAdmissionClosed,
}

pub(crate) struct R3UnloadScanAdmission {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateR3UnloadScanAdmission,
}
pub(crate) struct ProcessCallbackAdmissionClosed {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateProcessAdmissionClosed,
}
pub(crate) struct SetupAdmissionClosed {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateSetupAdmissionClosed,
}
pub(crate) struct ControlContextAdmissionClosed {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateControlAdmissionClosed,
}
pub(crate) struct FinalizerAdmissionClosed {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateFinalizerAdmissionClosed,
}
pub(crate) struct FinalizerRundownDrained {
    closed: FinalizerAdmissionClosed,
}
pub(crate) struct FinalizersDrained {
    _closed: FinalizerAdmissionClosed,
}

/// One callback admission acquired while the exact deletion deposit is still
/// under the registry lock.  It moves with the queued kick and remains parked
/// in that permanent cell until the callback has completely finished (or is
/// retained by an authenticated fail-stop forever).
pub(crate) struct FinalizerCallbackAdmission {
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
    authority: PrivateFinalizerCallbackAdmissionAuthority,
}

pub(crate) struct AdmittedR3FinalizerKick {
    admitted: fsring_core::adapter::fence::R3AdmittedFinalizerKick<FinalizerCallbackAdmission>,
}
pub(crate) struct ProcessCallbacksDrained {
    _closed: ProcessCallbackAdmissionClosed,
    registry: NonNull<KernelSessionRegistry>,
}
pub(crate) struct SetupAdmissionDrained {
    _closed: SetupAdmissionClosed,
    registry: NonNull<KernelSessionRegistry>,
}
pub(crate) struct ControlContextAdmissionDrained {
    _closed: ControlContextAdmissionClosed,
    registry: NonNull<KernelSessionRegistry>,
}

struct PrivateR3UnloadScanAdmission(());
struct PrivateProcessAdmissionClosed(());
struct PrivateSetupAdmissionClosed(());
struct PrivateControlAdmissionClosed(());
struct PrivateFinalizerAdmissionClosed(());
struct PrivateFinalizerCallbackAdmissionAuthority(());

pub(crate) struct RegistryLockGuard {
    registry: NonNull<KernelSessionRegistry>,
    old_irql: KIRQL,
}

/// One exact affine mount bundle packaged with the prevalidated permanent cell
/// event and the registry-lock borrow that keeps both stable until its fused
/// signal and acknowledgement finish.
///
/// Fields and construction stay private. The bundle type prevents cross-kind
/// substitution, while storing the bundle itself prevents same-kind A/B
/// substitution after its copy-only observation was validated.
pub(crate) struct PreparedLockedMountPublication<'lock, Bundle> {
    lock: &'lock mut RegistryLockGuard,
    cell: NonNull<NativeSessionCell>,
    event: Option<NonNull<KEVENT>>,
    bundle: Bundle,
}

impl ControlContextLease {
    /// Acquire the permanent CREATE/control-context admission rundown and mint
    /// its one affine release authority.
    ///
    /// # Safety
    /// `registry` is the initialized permanent root and remains allocated
    /// until every acquired lease is released.
    pub(crate) unsafe fn acquire(
        registry: NonNull<KernelSessionRegistry>,
    ) -> Result<Self, NTSTATUS> {
        // SAFETY: the registry contract guarantees initialized permanent
        // rundown storage.
        let acquired = unsafe {
            fsring_sys::c4::ExAcquireRundownProtection(
                registry.as_ref().control_context_admission.get().cast(),
            )
        };
        if acquired == 0 {
            return Err(wdk_sys::STATUS_DELETE_PENDING);
        }
        // Linearize the native acquisition with effect one's software close.
        let lock = unsafe { KernelSessionRegistry::lock(registry) };
        let open = unsafe { *registry.as_ref().control_context_admission_open.get() };
        unsafe { lock.release() };
        if !open {
            unsafe {
                fsring_sys::c4::ExReleaseRundownProtection(
                    registry.as_ref().control_context_admission.get().cast(),
                )
            };
            return Err(wdk_sys::STATUS_DELETE_PENDING);
        }
        Ok(Self {
            registry,
            authority: PrivateControlContextLeaseAuthority(()),
        })
    }

    /// Release the exact acquisition represented by this consumed lease.
    ///
    /// # Safety
    /// The registry remains live through this call.
    pub(crate) unsafe fn release(self) {
        let Self {
            registry,
            authority: PrivateControlContextLeaseAuthority(()),
        } = self;
        // SAFETY: consuming the private authority proves exactly one matching
        // successful acquisition is released.
        unsafe {
            fsring_sys::c4::ExReleaseRundownProtection(
                registry.as_ref().control_context_admission.get().cast(),
            )
        };
    }
}

pub(crate) struct CloseContextRight {
    lease: ControlContextLease,
    authority: PrivateCloseContextRightAuthority,
}

pub(crate) struct CompletedControlRecord {
    generation: u64,
    result: TerminalResult,
    close: CloseContextRight,
}

pub(crate) struct ControlOwner {
    reference: StrongSessionRef,
    context: NonNull<ControlFileContext>,
    lease: ControlContextLease,
}

pub(crate) struct ClosingControlOwner {
    context: NonNull<ControlFileContext>,
    lease: ControlContextLease,
    completion_obligation: PrivateClosingCompletionObligation,
}

impl KernelSessionRegistry {
    pub(crate) unsafe fn lock(registry: NonNull<Self>) -> RegistryLockGuard {
        let old_irql = unsafe {
            fsring_sys::c4::KeAcquireSpinLockRaiseToDpc(registry.as_ref().lock.get().cast())
        };
        RegistryLockGuard { registry, old_irql }
    }

    /// Initialize the permanent registry directly in its final nonpaged home.
    ///
    /// # Safety
    /// `target` is non-null, aligned, writable for one `Self`, and no reference
    /// to its bytes exists until this function returns success.
    pub(crate) unsafe fn initialize_in_place(
        target: *mut MaybeUninit<Self>,
    ) -> Result<(), NTSTATUS> {
        if target.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let registry = target.cast::<Self>();

        // This exact plan is shared with the compile-time shape proof. The
        // production loop makes order/state changes observable to that proof.
        for step in REGISTRY_INITIALIZATION_PLAN {
            match step {
                RegistryInitializationStep::Lock => unsafe {
                    fsring_sys::c4::KeInitializeSpinLock(
                        core::ptr::addr_of_mut!((*registry).lock).cast::<KSPIN_LOCK>(),
                    );
                },
                RegistryInitializationStep::AdmissionDoors => unsafe {
                    core::ptr::addr_of_mut!((*registry).setup_admission_open)
                        .write(UnsafeCell::new(true));
                    core::ptr::addr_of_mut!((*registry).control_context_admission_open)
                        .write(UnsafeCell::new(true));
                    core::ptr::addr_of_mut!((*registry).process_callback_admission_open)
                        .write(UnsafeCell::new(true));
                    core::ptr::addr_of_mut!((*registry).finalizer_admission_open)
                        .write(UnsafeCell::new(true));
                },
                RegistryInitializationStep::SetupAdmission => unsafe {
                    fsring_sys::c4::ExInitializeRundownProtection(
                        core::ptr::addr_of_mut!((*registry).setup_admission)
                            .cast::<EX_RUNDOWN_REF>(),
                    );
                },
                RegistryInitializationStep::ControlContextAdmission => unsafe {
                    fsring_sys::c4::ExInitializeRundownProtection(
                        core::ptr::addr_of_mut!((*registry).control_context_admission)
                            .cast::<EX_RUNDOWN_REF>(),
                    );
                },
                RegistryInitializationStep::ProcessCallbackAdmission => unsafe {
                    fsring_sys::c4::ExInitializeRundownProtection(
                        core::ptr::addr_of_mut!((*registry).process_callback_admission)
                            .cast::<EX_RUNDOWN_REF>(),
                    );
                },
                RegistryInitializationStep::FinalizerAdmission => unsafe {
                    fsring_sys::c4::ExInitializeRundownProtection(
                        core::ptr::addr_of_mut!((*registry).finalizer_admission)
                            .cast::<EX_RUNDOWN_REF>(),
                    );
                },
                RegistryInitializationStep::BlockedUnloadEvent => unsafe {
                    // Manual-reset, *nonsignaled*, and never set anywhere.
                    initialize_manual_event(
                        core::ptr::addr_of_mut!((*registry).blocked_unload).cast::<KEVENT>(),
                        false,
                    );
                },
                RegistryInitializationStep::Core => unsafe {
                    core::ptr::write(
                        core::ptr::addr_of_mut!((*registry).core)
                            .cast::<SessionRegistry<SESSION_CELL_COUNT>>(),
                        SessionRegistry::new(),
                    );
                },
                RegistryInitializationStep::Cells => unsafe {
                    initialize_cells_in_place(registry);
                },
            }
        }
        Ok(())
    }

    /// Allocate every permanent finalizer work item after provider creation.
    ///
    /// # Safety
    /// The registry is initialized, `provider` is the live unpublished
    /// permanent provider, and this method is called at PASSIVE exactly once.
    pub(crate) unsafe fn initialize_work_items(
        &mut self,
        provider: PDEVICE_OBJECT,
    ) -> Result<(), NTSTATUS> {
        if provider.is_null() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for cell in &mut self.cells {
            let cell = cell.get();
            // SAFETY: provider is live and each cell starts with a null item.
            let item = unsafe { fsring_sys::c4::IoAllocateWorkItem(provider) };
            if item.is_null() {
                // SAFETY: frees only the successfully allocated prefix, in
                // exact reverse order, and restores null observations.
                unsafe { self.rollback_initialization() };
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            // SAFETY: this cell is exclusively initialized on the load thread.
            unsafe { core::ptr::addr_of_mut!((*cell).finalizer_work_item).write(item) };
            let retry_item = unsafe { fsring_sys::c4::IoAllocateWorkItem(provider) };
            if retry_item.is_null() {
                unsafe { self.rollback_initialization() };
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            unsafe { core::ptr::addr_of_mut!((*cell).fence_retry_work_item).write(retry_item) };
        }
        Ok(())
    }

    /// Reverse the work-item prefix of a failed unpublished initialization.
    ///
    /// # Safety
    /// No endpoint can reach this registry and no work item was queued.
    pub(crate) unsafe fn rollback_initialization(&mut self) {
        let mut step = 0;
        while step < SESSION_CELL_COUNT {
            let index = rollback_cell_index(step);
            // SAFETY: the loop bound and checked reverse mapping prove range.
            let cell = unsafe { self.cells.get_unchecked_mut(index) }.get();
            // SAFETY: exclusive load-thread ownership; the field is initialized.
            let item = unsafe {
                take_and_clear_slot(&mut (*cell).finalizer_work_item, core::ptr::null_mut())
            };
            if !item.is_null() {
                // SAFETY: the item belongs to this cell and was never queued.
                unsafe { fsring_sys::c4::IoFreeWorkItem(item) };
            }
            let retry = unsafe {
                take_and_clear_slot(&mut (*cell).fence_retry_work_item, core::ptr::null_mut())
            };
            if !retry.is_null() {
                unsafe { fsring_sys::c4::IoFreeWorkItem(retry) };
            }
            step = step.saturating_add(1);
        }
    }

    /// Destroy permanent provider work items after every callback and session
    /// ledger was proved quiescent by effect nine.
    ///
    /// # Safety
    /// Endpoint admission is closed, callbacks/work items are quiescent, and
    /// the provider remains live until this method returns.
    pub(crate) unsafe fn destroy_prepared_work_items(&mut self, proof: &R3NativeLedgersClear) {
        let registry = NonNull::from(&mut *self);
        if !proof.matches_registry(registry) {
            unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, 9, u64::MAX, 3, 0) }
        }
        let mut step = 0;
        while step < SESSION_CELL_COUNT {
            let index = rollback_cell_index(step);
            // SAFETY: the loop bound and checked reverse mapping prove range.
            let cell = unsafe { self.cells.get_unchecked_mut(index) }.get();
            unsafe {
                let item =
                    take_and_clear_slot(&mut (*cell).finalizer_work_item, core::ptr::null_mut());
                if !item.is_null() {
                    fsring_sys::c4::IoFreeWorkItem(item);
                }
                let retry =
                    take_and_clear_slot(&mut (*cell).fence_retry_work_item, core::ptr::null_mut());
                if !retry.is_null() {
                    fsring_sys::c4::IoFreeWorkItem(retry);
                }
            }
            step = step.saturating_add(1);
        }
    }
}

/// One process-notify callback's admission to the registry.
///
/// It is affine and carries no `Copy`/`Clone`: the callback must take it once,
/// before it touches any cell, and release it once, after its *whole* restarted
/// scan. A guard released between restarts would let unload's rundown wait
/// return while the callback is about to re-enter the cell table.
pub(crate) struct ProcessCallbackGuard {
    registry: NonNull<KernelSessionRegistry>,
}

impl ProcessCallbackGuard {
    /// Admit one callback, or refuse because unload has closed the door.
    ///
    /// # Safety
    /// `registry` is the live permanent registry.
    pub(crate) unsafe fn acquire(registry: NonNull<KernelSessionRegistry>) -> Option<Self> {
        let acquired = unsafe {
            fsring_sys::c4::ExAcquireRundownProtection(
                registry.as_ref().process_callback_admission.get().cast(),
            )
        };
        if acquired == 0 {
            return None;
        }
        let lock = unsafe { KernelSessionRegistry::lock(registry) };
        let open = unsafe { *registry.as_ref().process_callback_admission_open.get() };
        unsafe { lock.release() };
        if open {
            Some(Self { registry })
        } else {
            unsafe {
                fsring_sys::c4::ExReleaseRundownProtection(
                    registry.as_ref().process_callback_admission.get().cast(),
                )
            };
            None
        }
    }

    /// The registry this guard admits access to.
    ///
    /// Reaching the registry *through the guard* is what makes "no cell access
    /// without admission" a shape rather than a comment: the scan cannot name
    /// the table without holding one.
    pub(crate) const fn registry(&self) -> NonNull<KernelSessionRegistry> {
        self.registry
    }

    /// # Safety
    /// The whole restarted scan has finished and no cell borrow survives.
    pub(crate) unsafe fn release(self) {
        unsafe {
            fsring_sys::c4::ExReleaseRundownProtection(
                self.registry
                    .as_ref()
                    .process_callback_admission
                    .get()
                    .cast(),
            )
        };
    }
}

/// Close and drain the process-callback admission. Every later callback is
/// refused.
///
/// # Safety
/// PASSIVE_LEVEL, the registry is initialized, and the caller holds no spin
/// lock. The core/global admission was already closed under the registry lock,
/// so no new session can publish while this independent rundown drains. WDK
/// requires the wait to precede `ExRundownCompleted`; both calls therefore run
/// here after the registry lock has been released.
pub(crate) unsafe fn close_global_admissions(
    lock: &mut RegistryLockGuard,
) -> ClosedGlobalAdmissions {
    let registry = lock.registry;
    unsafe {
        lock.core_mut().close_admission();
        *registry.as_ref().process_callback_admission_open.get() = false;
        *registry.as_ref().setup_admission_open.get() = false;
        *registry.as_ref().control_context_admission_open.get() = false;
    }
    ClosedGlobalAdmissions {
        scan: R3UnloadScanAdmission {
            registry,
            authority: PrivateR3UnloadScanAdmission(()),
        },
        process: ProcessCallbackAdmissionClosed {
            registry,
            authority: PrivateProcessAdmissionClosed(()),
        },
        setup: SetupAdmissionClosed {
            registry,
            authority: PrivateSetupAdmissionClosed(()),
        },
        control: ControlContextAdmissionClosed {
            registry,
            authority: PrivateControlAdmissionClosed(()),
        },
    }
}

impl ClosedGlobalAdmissions {
    pub(crate) fn into_waits(
        self,
    ) -> (
        R3UnloadScanAdmission,
        ProcessCallbackAdmissionClosed,
        SetupAdmissionClosed,
        ControlContextAdmissionClosed,
    ) {
        (self.scan, self.process, self.setup, self.control)
    }
}

impl ProcessCallbacksDrained {
    pub(crate) fn matches_registry(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }

    pub(crate) fn admission_closed_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn callbacks_drained_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
}

impl SetupAdmissionDrained {
    pub(crate) fn matches_registry(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn admission_closed_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn admission_drained_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
}

impl ControlContextAdmissionDrained {
    pub(crate) fn matches_registry(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn admission_closed_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn admission_drained_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn bindings_closed_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn completed_records_absent_for(
        &self,
        registry: NonNull<KernelSessionRegistry>,
    ) -> bool {
        self.registry == registry
    }
    pub(crate) fn close_rights_absent_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn contexts_absent_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
}

pub(crate) unsafe fn wait_process_callbacks_drained(
    closed: ProcessCallbackAdmissionClosed,
) -> ProcessCallbacksDrained {
    let registry = closed.registry;
    unsafe {
        let rundown = registry.as_ref().process_callback_admission.get().cast();
        fsring_sys::c4::ExWaitForRundownProtectionRelease(rundown);
        fsring_sys::c4::ExRundownCompleted(rundown);
    }
    ProcessCallbacksDrained {
        _closed: closed,
        registry,
    }
}

/// Wait until every admitted process callback has left.
///
/// # Safety
/// PASSIVE_LEVEL, no lock held, admission already closed and the callback
/// already unregistered. The first wait ran before `ExRundownCompleted`; WDK
/// specifies that this repeated wait returns immediately and is harmless.
pub(crate) unsafe fn wait_setup_admission_drained(
    closed: SetupAdmissionClosed,
) -> SetupAdmissionDrained {
    let registry = closed.registry;
    unsafe {
        let rundown = registry.as_ref().setup_admission.get().cast();
        fsring_sys::c4::ExWaitForRundownProtectionRelease(rundown);
        fsring_sys::c4::ExRundownCompleted(rundown);
    }
    SetupAdmissionDrained {
        _closed: closed,
        registry,
    }
}

pub(crate) unsafe fn wait_control_context_admission_drained(
    closed: ControlContextAdmissionClosed,
) -> ControlContextAdmissionDrained {
    let registry = closed.registry;
    unsafe {
        let rundown = registry.as_ref().control_context_admission.get().cast();
        fsring_sys::c4::ExWaitForRundownProtectionRelease(rundown);
        fsring_sys::c4::ExRundownCompleted(rundown);
    }
    ControlContextAdmissionDrained {
        _closed: closed,
        registry,
    }
}

impl R3UnloadScanAdmission {
    pub(crate) fn into_registry_after_drains(
        self,
        process: &ProcessCallbacksDrained,
        setup: &SetupAdmissionDrained,
    ) -> NonNull<KernelSessionRegistry> {
        let Self {
            registry,
            authority: PrivateR3UnloadScanAdmission(()),
        } = self;
        // All three receipts are private, affine, and minted for a concrete
        // registry. Cross-root substitution is an invariant failure, never a
        // weaker scan authority.
        assert!(process.registry == registry && setup.registry == registry);
        registry
    }
}

impl FinalizerCallbackAdmission {
    /// Acquire the queue-to-callback rundown while the exact deposit/Queued
    /// transition is still protected by `lock`.
    ///
    /// # Safety
    /// `lock` guards the initialized registry and `locator` is the deletion
    /// generation whose intact release packet is still owned by the caller.
    pub(crate) unsafe fn acquire_locked(
        lock: &mut RegistryLockGuard,
        locator: SessionLocator,
    ) -> Option<Self> {
        let registry = lock.registry;
        let acquired = unsafe {
            fsring_sys::c4::ExAcquireRundownProtection(
                registry.as_ref().finalizer_admission.get().cast(),
            )
        };
        if acquired == 0 {
            return None;
        }
        let open = unsafe { *registry.as_ref().finalizer_admission_open.get() };
        if !open {
            unsafe {
                fsring_sys::c4::ExReleaseRundownProtection(
                    registry.as_ref().finalizer_admission.get().cast(),
                )
            };
            return None;
        }
        Some(Self {
            registry,
            locator,
            authority: PrivateFinalizerCallbackAdmissionAuthority(()),
        })
    }

    fn matches(&self, registry: NonNull<KernelSessionRegistry>, locator: SessionLocator) -> bool {
        self.registry == registry && self.locator == locator
    }

    /// Release only after the callback no longer has any generation-local
    /// epilogue left to perform.
    ///
    /// # Safety
    /// The permanent registry remains live and this admission is released
    /// exactly once.
    unsafe fn release(self) {
        let Self {
            registry,
            locator: _,
            authority: PrivateFinalizerCallbackAdmissionAuthority(()),
        } = self;
        unsafe {
            fsring_sys::c4::ExReleaseRundownProtection(
                registry.as_ref().finalizer_admission.get().cast(),
            )
        };
    }
}

impl AdmittedR3FinalizerKick {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.admitted.locator()
    }

    /// Fuse the already-admitted callback with the sole core queue kick after
    /// the release/deposit commit.  All equality checks ran before that commit.
    ///
    /// # Safety
    /// `kick` and `admission` name the same prevalidated generation.
    pub(crate) unsafe fn new_prevalidated(
        kick: fsring_core::adapter::fence::R3FinalizerKick,
        admission: FinalizerCallbackAdmission,
    ) -> Self {
        let locator = kick.locator();
        unsafe { core::hint::assert_unchecked(admission.locator == locator) };
        Self {
            admitted: kick.admit(admission),
        }
    }

    fn into_parts(
        self,
    ) -> (
        NonNull<KernelSessionRegistry>,
        fsring_core::adapter::fence::R3AdmittedFinalizerKick<FinalizerCallbackAdmission>,
    ) {
        (self.admitted.admission().registry, self.admitted)
    }
}

pub(crate) unsafe fn close_finalizer_admission(
    lock: &mut RegistryLockGuard,
) -> FinalizerAdmissionClosed {
    unsafe { *lock.registry.as_ref().finalizer_admission_open.get() = false };
    FinalizerAdmissionClosed {
        registry: lock.registry,
        authority: PrivateFinalizerAdmissionClosed(()),
    }
}

pub(crate) unsafe fn wait_finalizers_drained(
    full_pass: crate::fence::R3FinalizerFullPass,
    closed: FinalizerAdmissionClosed,
) -> FinalizerRundownDrained {
    let registry = closed.registry;
    // The fixed-domain full pass and the closed admission must be for the same
    // root; both are affine and their fields are private to their minting
    // modules.
    assert_eq!(full_pass.into_registry(), registry);
    unsafe {
        let rundown = registry.as_ref().finalizer_admission.get().cast();
        fsring_sys::c4::ExWaitForRundownProtectionRelease(rundown);
        fsring_sys::c4::ExRundownCompleted(rundown);
    }
    FinalizerRundownDrained { closed }
}

pub(crate) fn finish_finalizers_drained(
    acknowledged: crate::fence::R3FinalizerAcknowledgedPass,
    rundown: FinalizerRundownDrained,
) -> FinalizersDrained {
    let registry = rundown.closed.registry;
    assert_eq!(acknowledged.into_registry(), registry);
    FinalizersDrained {
        _closed: rundown.closed,
    }
}

pub(crate) enum R3FinalizerDrainObservation {
    NonMatch(LockedR3FinalizerDrainNonMatch),
    OrdinaryInFlight(LockedR3FinalizerOrdinaryInFlight),
    WaitForVisibility(*mut KEVENT),
    Published(BlockedUnloadWaitGuard),
    Opaque(OpaqueFailStopWaitGuard),
    FailStop,
}

pub(crate) struct LockedR3FinalizerDrainNonMatch {
    index: u32,
    authority: PrivateLockedR3FinalizerDrainNonMatch,
}

struct PrivateLockedR3FinalizerDrainNonMatch(());

pub(crate) struct LockedR3FinalizerOrdinaryInFlight {
    index: u32,
    authority: PrivateLockedR3FinalizerOrdinaryInFlight,
}

struct PrivateLockedR3FinalizerOrdinaryInFlight(());

impl LockedR3FinalizerDrainNonMatch {
    pub(crate) fn into_index(self) -> u32 {
        let Self {
            index,
            authority: PrivateLockedR3FinalizerDrainNonMatch(()),
        } = self;
        index
    }
}

impl LockedR3FinalizerOrdinaryInFlight {
    pub(crate) fn into_index(self) -> u32 {
        let Self {
            index,
            authority: PrivateLockedR3FinalizerOrdinaryInFlight(()),
        } = self;
        index
    }
}

impl RegistryLockGuard {
    /// Effect-seven observation for exactly one permanent cell. A callback
    /// admission that has not yet made terminal visibility durable forces a
    /// visibility wait; durable fail-stop is authenticated here and never
    /// reaches the global rundown wait.
    pub(crate) unsafe fn observe_r3_finalizer_for_drain(
        &mut self,
        index: u32,
    ) -> R3FinalizerDrainObservation {
        let Some(cell) = (unsafe { self.cell_ptr(index) }) else {
            return R3FinalizerDrainObservation::FailStop;
        };
        if unsafe {
            (*cell).r3_unload_scan_is_exactly_empty()
                || (*cell).r3_unload_scan_is_exactly_empty_except_finalizer_callback()
        } {
            // `visibility_resolution` is a generation latch. Ordinary reset
            // deliberately leaves it signalled so an observer that unlocked
            // before the callback completed cannot miss the wake. This exact
            // locked non-match is the sole acknowledgement that clears it.
            unsafe {
                fsring_sys::c4::KeClearEvent(
                    core::ptr::addr_of_mut!((*cell).visibility_resolution).cast(),
                )
            };
            return R3FinalizerDrainObservation::NonMatch(LockedR3FinalizerDrainNonMatch {
                index,
                authority: PrivateLockedR3FinalizerDrainNonMatch(()),
            });
        }
        let Some(locator) = (unsafe { (*cell).terminal_rendezvous.r3_locked_locator() }) else {
            return if unsafe {
                (*cell).finalizer_callback_admitted.is_some()
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!((*cell).visibility_resolution)
                            .cast_mut()
                            .cast(),
                    ) == 0
            } {
                R3FinalizerDrainObservation::WaitForVisibility(unsafe {
                    (*cell).visibility_resolution_event()
                })
            } else {
                R3FinalizerDrainObservation::FailStop
            };
        };
        if unsafe {
            (*cell).r3_finalizer_is_authenticated_ordinary_in_flight(self.registry, locator)
        } {
            // Completed is the authenticated ordinary visibility decision.
            // The callback may still be between publication and its final
            // reset/rundown release; the fixed pass may resolve it now because
            // the subsequent global ExWait still consumes that admission.
            return R3FinalizerDrainObservation::OrdinaryInFlight(
                LockedR3FinalizerOrdinaryInFlight {
                    index,
                    authority: PrivateLockedR3FinalizerOrdinaryInFlight(()),
                },
            );
        }
        match unsafe { (*cell).authenticate_closed_fail_stop(locator) } {
            Some(crate::fence::ClosedFailStopAuthentication::Published(_)) => {
                match self.prepare_published_unload_wait(locator) {
                    Some(wait) => R3FinalizerDrainObservation::Published(wait),
                    None => R3FinalizerDrainObservation::FailStop,
                }
            }
            Some(crate::fence::ClosedFailStopAuthentication::Opaque(_)) => {
                match self.prepare_opaque_unload_wait(locator) {
                    Some(wait) => R3FinalizerDrainObservation::Opaque(wait),
                    None => R3FinalizerDrainObservation::FailStop,
                }
            }
            None => {
                if unsafe {
                    (*cell).finalizer_callback_admitted.is_some()
                        && fsring_sys::c4::KeReadStateEvent(
                            core::ptr::addr_of!((*cell).visibility_resolution)
                                .cast_mut()
                                .cast(),
                        ) == 0
                } {
                    R3FinalizerDrainObservation::WaitForVisibility(unsafe {
                        (*cell).visibility_resolution_event()
                    })
                } else {
                    R3FinalizerDrainObservation::FailStop
                }
            }
        }
    }

    /// Post-rundown acknowledgement for exactly one permanent cell. Unlike
    /// the pre-wait resolution pass, no callback epilogue may remain after
    /// ExWait+Completed, so only the fully empty predicate is accepted.
    pub(crate) unsafe fn acknowledge_r3_finalizer_after_rundown(
        &mut self,
        index: u32,
    ) -> Option<LockedR3FinalizerDrainNonMatch> {
        let cell = unsafe { self.cell_ptr(index) }?;
        if !unsafe { (*cell).r3_unload_scan_is_exactly_empty() } {
            return None;
        }
        unsafe {
            fsring_sys::c4::KeClearEvent(
                core::ptr::addr_of_mut!((*cell).visibility_resolution).cast(),
            )
        };
        Some(LockedR3FinalizerDrainNonMatch {
            index,
            authority: PrivateLockedR3FinalizerDrainNonMatch(()),
        })
    }
}

/// Park this unload forever on the permanently nonsignaled event.
///
/// This never returns. It is the correct outcome for an unload that reached a
/// generation whose terminal work is permanently blocked: the image cannot be
/// torn down around a stuck thread, and reporting the wait as a drain would be
/// a lie about exactly the state that makes teardown unsafe.
///
/// # Safety
/// PASSIVE_LEVEL, no lock held, and each counted admission is either already
/// released or remains nested in the affine permanent-wait guard invoking
/// this function. A retained invalid ticket deliberately keeps the generation
/// undrainable; it must never be presented as a successful release.
pub(crate) unsafe fn wait_blocked_unload_forever(registry: NonNull<KernelSessionRegistry>) -> ! {
    loop {
        unsafe {
            let _ = fsring_sys::c4::KeWaitForSingleObject(
                registry.as_ref().blocked_unload.get().cast(),
                0,
                0,
                0,
                core::ptr::null_mut(),
            );
        }
    }
}

/// Retain an authenticated process-scan invariant failure. The scanner emits
/// this only after the locked permanent cell matched the recorded process and
/// exact generation but no complete typed action could be minted; it must
/// never be reclassified as a non-match/cursor advance.
pub(crate) unsafe fn wait_process_scan_invariant_forever(
    registry: NonNull<KernelSessionRegistry>,
) -> ! {
    unsafe { wait_blocked_unload_forever(registry) }
}

impl SetupAdmissionGuard {
    pub(crate) unsafe fn acquire(
        registry: NonNull<KernelSessionRegistry>,
    ) -> Result<Self, NTSTATUS> {
        let acquired = unsafe {
            fsring_sys::c4::ExAcquireRundownProtection(
                registry.as_ref().setup_admission.get().cast(),
            )
        };
        if acquired == 0 {
            return Err(wdk_sys::STATUS_DELETE_PENDING);
        }
        let lock = unsafe { KernelSessionRegistry::lock(registry) };
        let open = unsafe { *registry.as_ref().setup_admission_open.get() };
        unsafe { lock.release() };
        if open {
            Ok(Self { registry })
        } else {
            unsafe {
                fsring_sys::c4::ExReleaseRundownProtection(
                    registry.as_ref().setup_admission.get().cast(),
                )
            };
            Err(wdk_sys::STATUS_DELETE_PENDING)
        }
    }

    pub(crate) unsafe fn release(self) {
        unsafe {
            fsring_sys::c4::ExReleaseRundownProtection(
                self.registry.as_ref().setup_admission.get().cast(),
            )
        };
    }
}

impl RegistryLockGuard {
    pub(crate) unsafe fn core_ptr(&mut self) -> *mut SessionRegistry<SESSION_CELL_COUNT> {
        unsafe { self.registry.as_ref().core.get() }
    }

    /// A cell's storage, reached through a *shared* registry reference.
    ///
    /// `cells` is an array of `UnsafeCell`, so `&KernelSessionRegistry` is
    /// enough to obtain the pointer. The predecessor took `as_mut()` here,
    /// which fabricated a `&mut KernelSessionRegistry` over storage that other
    /// threads legitimately hold shared references to — an alias LLVM is
    /// entitled to assume does not exist.
    pub(crate) unsafe fn cell_ptr(&mut self, index: u32) -> Option<*mut NativeSessionCell> {
        let index = usize::try_from(index).ok()?;
        unsafe { self.registry.as_ref() }
            .cells
            .get(index)
            .map(|cell| cell.get())
    }

    /// Project a permanent cell after an affine locator/cursor preflight.
    ///
    /// This stays private to the defining module and never returns a pointer to
    /// callers. Post-destruction helpers use it only after their consumed
    /// capabilities proved the slot index is in the fixed array.
    pub(crate) unsafe fn cell_mut_prevalidated(&mut self, index: u32) -> &mut NativeSessionCell {
        let cell = unsafe {
            self.registry
                .as_ref()
                .cells
                .get_unchecked(index as usize)
                .get()
        };
        unsafe { &mut *cell }
    }

    pub(crate) unsafe fn core_mut(&mut self) -> &mut SessionRegistry<SESSION_CELL_COUNT> {
        unsafe { &mut *self.registry.as_ref().core.get() }
    }

    pub(crate) unsafe fn cell_mut(&mut self, index: u32) -> Option<&mut NativeSessionCell> {
        // SAFETY: as `cell_ptr`; this lock guard is what makes the projection
        // exclusive, and the borrow it returns cannot outlive the guard.
        unsafe { self.cell_ptr(index) }.map(|cell| unsafe { &mut *cell })
    }

    /// Publish the completed control record, binding, and terminal outcome in
    /// one preflighted lock hold.
    ///
    /// # Safety
    /// The final-delete preparation proved every member of this exact
    /// cross-product and the caller holds this registry lock.
    pub(crate) unsafe fn publish_completed_generation(
        &mut self,
        locator: SessionLocator,
        closing: ClosingControlOwner,
        winner: fsring_core::session::TerminalWinner,
        result: TerminalResult,
    ) -> fsring_core::session::TerminalOutcomeSignal {
        let (context, record) = closing.into_completed_record(locator.generation(), result);
        unsafe { crate::control::store_completed_control_record_prepared(context, record) };
        unsafe { crate::control::publish_closing_complete_prepared(context, locator, result) };
        let cell = unsafe { self.cell_mut_prevalidated(locator.slot_index()) };
        // Retire the recorded control-context pointer in THIS hold, before the
        // record can be acknowledged and CLOSE can free the context. The
        // process-loss scan (`scan_one_cell_for_process`) and the unload scan
        // (`observe_r3_unload_cell`) dereference whatever it names; left set,
        // both dereference freed pool once CLOSE frees (native review N17-1).
        // Both already route a `None` pointer through the cell's rendezvous,
        // which answers a closed generation without touching any context.
        //
        // "Both" is the two scans exactly, and not every reader of this
        // pointer: `claim_committed_protocol` reads it too and bugchecks on
        // `None`. It has no production caller, and its own comment carries
        // that condition (native review N18-4).
        cell.recorded_control_context = None;
        unsafe {
            cell.terminal_rendezvous
                .close_and_publish_completed_prepared(winner, result)
        }
    }

    /// Bind the already validated live shell to its access-rundown lifetime.
    ///
    /// This is deliberately module-private and returns the sealed shared
    /// projection directly: no caller can receive the cell's raw mirror or a
    /// reusable `NonNull<NativeSession>`. The lifetime is chosen by the unsafe
    /// resolver caller because the registry lock alone cannot prove it.
    ///
    /// # Safety
    /// The caller is the exact `ResolveStep::ProjectSessionPointer` executor.
    /// It holds this registry lock, owns an acquired access-rundown reference
    /// for `index`, and has successfully validated the core Live state, cell
    /// locator, and native owner slots for this same `locator`. That rundown
    /// remains owned until the returned `SessionAccessGuard` drops.
    unsafe fn project_resolved_session<'registry>(
        &mut self,
        index: u32,
        locator: SessionLocator,
    ) -> Option<SharedSessionProjection<'registry, NativeSession>> {
        let cell = unsafe { self.cell_mut(index) }?;
        if !cell.matches_live_locator(locator) {
            return None;
        }
        Some(unsafe { SharedSessionProjection::from_non_null(NonNull::new(cell.session)?) })
    }

    pub(crate) unsafe fn release(self) {
        unsafe {
            fsring_sys::c4::KeReleaseSpinLock(
                self.registry.as_ref().lock.get().cast(),
                self.old_irql,
            )
        };
    }
}

impl CloseContextRight {
    pub(crate) const fn new(lease: ControlContextLease) -> Self {
        Self {
            lease,
            authority: PrivateCloseContextRightAuthority(()),
        }
    }

    pub(crate) unsafe fn release(self) {
        let Self {
            lease,
            authority: PrivateCloseContextRightAuthority(()),
        } = self;
        unsafe { lease.release() };
    }
}

impl ControlOwner {
    pub(crate) const fn new(
        reference: StrongSessionRef,
        context: NonNull<ControlFileContext>,
        lease: ControlContextLease,
    ) -> Self {
        Self {
            reference,
            context,
            lease,
        }
    }
}

impl CompletedControlRecord {
    pub(crate) const fn new(
        generation: u64,
        result: TerminalResult,
        close: CloseContextRight,
    ) -> Self {
        Self {
            generation,
            result,
            close,
        }
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn result(&self) -> TerminalResult {
        self.result
    }

    fn into_parts(self) -> (u64, TerminalResult, CloseContextRight) {
        let Self {
            generation,
            result,
            close,
        } = self;
        (generation, result, close)
    }
}

/// CLEANUP's acknowledgment of a completed generation.
///
/// It consumes the record the finalizer stored, leaves the exact
/// `CloseContextRight` — and therefore the same `ControlContextLease` — in the
/// context for CLOSE, and reports the immutable observation. A refusal returns
/// the whole record so nothing is stranded.
///
/// This is PRODUCTION: `claim_native_cleanup_route` calls it, and that route
/// is reached from the CLEANUP dispatch path in `control.rs`. The previous wording, "This is staged. Task 12 is the sole
/// commit that routes production CLEANUP through it", described the tree before
/// Task 12 landed.
///
/// # Safety
/// The registry lock is held and `context` is the live control context the
/// record was taken from in this same hold.
pub(crate) unsafe fn acknowledge_completed_control(
    context: NonNull<ControlFileContext>,
    record: CompletedControlRecord,
) -> Result<(u64, TerminalResult), CompletedControlRecord> {
    let (generation, result, close) = record.into_parts();
    match unsafe { crate::control::store_close_right(context, close) } {
        Ok(()) => Ok((generation, result)),
        Err(close) => Err(CompletedControlRecord::new(generation, result, close)),
    }
}

impl ControlOwner {
    /// The one consumption of a published control owner.
    ///
    /// It splits into two authorities with deliberately different lifetimes:
    /// the strong reference is released as soon as the fence's approved order
    /// reaches it, while the closing owner keeps the context and its admission
    /// lease until the completion transfer — or forever, if the generation
    /// fail-stops. Splitting them is what stops a runner from releasing the
    /// registry count and the context together.
    fn split(self) -> (ControlStrongRef, ClosingControlOwner) {
        let Self {
            reference,
            context,
            lease,
        } = self;
        (
            ControlStrongRef { reference },
            ClosingControlOwner {
                context,
                lease,
                completion_obligation: PrivateClosingCompletionObligation(()),
            },
        )
    }

    const fn context(&self) -> NonNull<ControlFileContext> {
        self.context
    }

    const fn locator(&self) -> SessionLocator {
        self.reference.locator()
    }
}

/// The separately releasable half of a consumed [`ControlOwner`].
pub(crate) struct ControlStrongRef {
    reference: StrongSessionRef,
}

impl ControlStrongRef {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.reference.locator()
    }

    pub(crate) fn into_reference(self) -> StrongSessionRef {
        self.reference
    }

    /// Rewrap a reference a refused release handed straight back.
    ///
    /// This is not a second way to *make* a control reference — the argument is
    /// the same affine value `into_reference` produced, and a refusal owes it
    /// back to whoever is still responsible for releasing it.
    pub(crate) const fn from_reference(reference: StrongSessionRef) -> Self {
        Self { reference }
    }
}

impl ClosingControlOwner {
    pub(crate) const fn context(&self) -> NonNull<ControlFileContext> {
        self.context
    }

    pub(crate) fn into_completed_record(
        self,
        generation: u64,
        result: TerminalResult,
    ) -> (NonNull<ControlFileContext>, CompletedControlRecord) {
        let Self {
            context,
            lease,
            completion_obligation: PrivateClosingCompletionObligation(()),
        } = self;
        (
            context,
            CompletedControlRecord::new(generation, result, CloseContextRight::new(lease)),
        )
    }
}

/// Everything one terminal winner owns while it runs a generation down.
///
/// It carries no caller-supplied reason and no raw session pointer: the reason
/// is the core-authenticated one inside `winner`, and destruction authority is
/// the authentic `NativeSessionOwner`/`SessionRootReleaseRight` pair the SETUP
/// publication suffix deposited in the cell.
pub(crate) struct TerminalWork {
    locator: SessionLocator,
    winner: fsring_core::session::TerminalWinner,
    terminal: fsring_core::session::TerminalSessionRef,
    control: ControlStrongRef,
    closing: ClosingControlOwner,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
}

impl TerminalWork {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub(crate) const fn reason(&self) -> fsring_core::session::TerminalReason {
        self.winner.reason()
    }

    pub(crate) const fn control_context(&self) -> NonNull<ControlFileContext> {
        self.closing.context
    }

    /// Split the winner without projecting the native payload or cell mirror.
    pub(crate) fn into_checkpoint_parts(self) -> (ControlStrongRef, TerminalOwners) {
        let Self {
            locator,
            winner,
            terminal,
            control,
            closing,
            shell,
            root,
        } = self;
        (
            control,
            TerminalOwners {
                locator,
                winner,
                terminal,
                closing,
                shell,
                root,
            },
        )
    }
}

/// Everything a terminal winner owns apart from its control reference.
pub(crate) struct TerminalOwners {
    locator: SessionLocator,
    winner: fsring_core::session::TerminalWinner,
    terminal: fsring_core::session::TerminalSessionRef,
    closing: ClosingControlOwner,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
}

impl TerminalOwners {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub(crate) const fn reason(&self) -> fsring_core::session::TerminalReason {
        self.winner.reason()
    }

    /// Borrow the intact core envelope for the one closed checkpoint executor.
    pub(crate) const fn shell_owner(&self) -> &NativeSessionOwner {
        &self.shell
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        fsring_core::session::TerminalWinner,
        fsring_core::session::TerminalSessionRef,
        ClosingControlOwner,
        NativeSessionOwner,
        SessionRootReleaseRight,
    ) {
        let Self {
            locator: _,
            winner,
            terminal,
            closing,
            shell,
            root,
        } = self;
        (winner, terminal, closing, shell, root)
    }
}

/// A counted admission to one exact terminal generation.
///
/// Holding one is the only way to run or wait a generation down. It names the
/// registry so the release can retake the same lock without the holder having
/// to carry a second pointer that could name a different root.
const _: fn() = || {
    let _from_fence = fsring_core::session::TerminalBlocked::from_fence;
    let _from_delete = fsring_core::session::TerminalBlocked::from_delete;
};

pub(crate) enum NativeProtocolTerminalDisposition {
    Terminal(TerminalDisposition),
    Reject(fsring_core::adapter::lifecycle::ProtocolRejectReceipt),
}

pub(crate) enum NativeTerminalJoinAuthority {
    Ordinary(fsring_core::session::TerminalJoinTicket),
    Protocol(fsring_core::adapter::lifecycle::CommittedProtocolJoin),
}

pub(crate) struct TerminalJoinGuard {
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
    ticket: NativeTerminalJoinAuthority,
}

/// Result of consuming an opaque slot receipt together with one authentic
/// terminal admission while the registry lock is held.
pub(crate) enum OpaqueFailStopWaitPreparation {
    Released {
        wait: OpaqueFailStopWaitGuard,
        drained: Option<fsring_core::session::TerminalJoinersDrainedSignal>,
    },
    Retained(OpaqueFailStopWaitGuard),
}

/// Result of the broadcast visibility wake for any ordinary counted joiner.
/// Published/Opaque unload paths consume their stronger guards elsewhere;
/// process/CLEANUP joins use this to avoid sleeping forever on an event that
/// Opaque intentionally never signals.
pub(crate) enum TerminalVisibilityResolution {
    Completed {
        result: TerminalResult,
        drained: Option<fsring_core::session::TerminalJoinersDrainedSignal>,
    },
    Blocked {
        blocked: fsring_core::session::TerminalBlocked,
        drained: Option<fsring_core::session::TerminalJoinersDrainedSignal>,
    },
    Opaque(OpaqueFailStopWaitPreparation),
    FailStop(TerminalJoinGuard),
}

/// Unload-specific result after one counted terminal arrival resolves its
/// exact generation. Every blocked arm already owns the authenticated wait
/// guard; no raw ticket crosses back into the unload runner.
pub(crate) enum R3UnloadVisibilityResolution {
    Completed(TerminalResult),
    Published {
        wait: BlockedUnloadWaitGuard,
        drained: Option<fsring_core::session::TerminalJoinersDrainedSignal>,
    },
    RetainedPublished(RetainedPublishedJoinWaitGuard),
    Opaque(OpaqueFailStopWaitPreparation),
}

/// The sole consumer of an opaque-quarantine receipt.
///
/// A foreign ticket remains nested here forever. An exact ticket is released
/// before this guard is minted, but the slot receipt stays nested in both
/// cases so neither path can be mistaken for an ordinary Blocked outcome.
pub(crate) struct OpaqueFailStopWaitGuard {
    registry: NonNull<KernelSessionRegistry>,
    receipt: crate::fence::OpaqueFailStopReceipt,
    retained_ticket: Option<fsring_core::session::TerminalJoinTicket>,
}

pub(crate) struct BlockedUnloadWaitGuard {
    registry: NonNull<KernelSessionRegistry>,
    receipt: crate::fence::PublishedFailStopReceipt,
}

pub(crate) struct RetainedPublishedJoinWaitGuard {
    registry: NonNull<KernelSessionRegistry>,
    receipt: crate::fence::PublishedFailStopReceipt,
    retained_ticket: fsring_core::session::TerminalJoinTicket,
}

struct ReleasedPublishedJoin {
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
    drained: Option<fsring_core::session::TerminalJoinersDrainedSignal>,
}

impl BlockedUnloadWaitGuard {
    fn from_blocked_slot(
        registry: NonNull<KernelSessionRegistry>,
        receipt: crate::fence::PublishedFailStopReceipt,
    ) -> Self {
        Self { registry, receipt }
    }

    fn from_released_join(
        released: ReleasedPublishedJoin,
        receipt: crate::fence::PublishedFailStopReceipt,
    ) -> Result<
        (
            Self,
            Option<fsring_core::session::TerminalJoinersDrainedSignal>,
        ),
        (
            ReleasedPublishedJoin,
            crate::fence::PublishedFailStopReceipt,
        ),
    > {
        if !receipt.matches(released.locator) {
            return Err((released, receipt));
        }
        let ReleasedPublishedJoin {
            registry,
            locator: _,
            drained,
        } = released;
        Ok((Self { registry, receipt }, drained))
    }

    pub(crate) unsafe fn wait_forever(self) -> ! {
        let Self { registry, receipt } = self;
        let _keep_receipt = receipt;
        unsafe { wait_blocked_unload_forever(registry) }
    }
}

impl RetainedPublishedJoinWaitGuard {
    pub(crate) unsafe fn wait_forever(self) -> ! {
        let Self {
            registry,
            receipt,
            retained_ticket,
        } = self;
        let _keep_receipt = receipt;
        let _keep_ticket = retained_ticket;
        unsafe { wait_blocked_unload_forever(registry) }
    }
}

impl RegistryLockGuard {
    /// Fuse the durable Published slot receipt with this exact cell into the
    /// no-ticket unload wait.  No release signal is fabricated for a direct
    /// scan observation.
    pub(crate) fn prepare_published_unload_wait(
        &mut self,
        locator: SessionLocator,
    ) -> Option<BlockedUnloadWaitGuard> {
        let registry = self.registry;
        let cell = unsafe { self.cell_mut_prevalidated(locator.slot_index()) };
        match cell.authenticate_closed_fail_stop(locator)? {
            crate::fence::ClosedFailStopAuthentication::Published(receipt) => {
                Some(BlockedUnloadWaitGuard::from_blocked_slot(registry, receipt))
            }
            crate::fence::ClosedFailStopAuthentication::Opaque(_) => None,
        }
    }

    /// Consume an exact released-join proof only after authenticating the
    /// same locator's occupied Published slot in this lock hold.
    fn prepare_released_published_unload_wait(
        &mut self,
        released: ReleasedPublishedJoin,
    ) -> Result<
        (
            BlockedUnloadWaitGuard,
            Option<fsring_core::session::TerminalJoinersDrainedSignal>,
        ),
        ReleasedPublishedJoin,
    > {
        if released.registry != self.registry {
            return Err(released);
        }
        let locator = released.locator;
        let cell = unsafe { self.cell_mut_prevalidated(locator.slot_index()) };
        let Some(crate::fence::ClosedFailStopAuthentication::Published(receipt)) =
            cell.authenticate_closed_fail_stop(locator)
        else {
            return Err(released);
        };
        match BlockedUnloadWaitGuard::from_released_join(released, receipt) {
            Ok(prepared) => Ok(prepared),
            Err((released, _receipt)) => Err(released),
        }
    }

    /// Authenticate the exact Published slot while retaining a ticket the
    /// rendezvous refused to release. This is a corruption/fail-stop path, not
    /// the no-ticket path, and it never claims a drained signal.
    fn prepare_retained_published_join_wait(
        &mut self,
        registry: NonNull<KernelSessionRegistry>,
        locator: SessionLocator,
        ticket: fsring_core::session::TerminalJoinTicket,
    ) -> Result<RetainedPublishedJoinWaitGuard, fsring_core::session::TerminalJoinTicket> {
        if registry != self.registry {
            return Err(ticket);
        }
        let cell = unsafe { self.cell_mut_prevalidated(locator.slot_index()) };
        let Some(crate::fence::ClosedFailStopAuthentication::Published(receipt)) =
            cell.authenticate_closed_fail_stop(locator)
        else {
            return Err(ticket);
        };
        Ok(RetainedPublishedJoinWaitGuard {
            registry,
            receipt,
            retained_ticket: ticket,
        })
    }

    /// Fused no-ticket Opaque authentication.  The factory checks both the
    /// durable slot and the terminal rendezvous while the registry lock holds;
    /// callers cannot mint a wait from a slot receipt alone.
    pub(crate) fn prepare_opaque_unload_wait(
        &mut self,
        locator: SessionLocator,
    ) -> Option<OpaqueFailStopWaitGuard> {
        let registry = self.registry;
        let cell = unsafe { self.cell_mut_prevalidated(locator.slot_index()) };
        cell.terminal_rendezvous
            .opaque_retained_admitted_for_locator(locator)?;
        match cell.authenticate_closed_fail_stop(locator)? {
            crate::fence::ClosedFailStopAuthentication::Opaque(receipt) => {
                Some(OpaqueFailStopWaitGuard {
                    registry,
                    receipt,
                    retained_ticket: None,
                })
            }
            crate::fence::ClosedFailStopAuthentication::Published(_) => None,
        }
    }
}

/// Affine authority to publish the one finalizer-resolution handoff for the
/// exact callback cell that yielded the running finalizer deposit.
///
/// Only `take_deposit_and_run_for_callback` can mint this right. In particular,
/// a copied locator in a sibling module cannot manufacture an ordinary handoff.
pub(crate) struct FinalizerHandoffRight {
    locator: SessionLocator,
}

impl FinalizerHandoffRight {
    fn matches(&self, locator: SessionLocator) -> bool {
        self.locator == locator
    }
}

pub(crate) enum FinalizerVisibilityHandoff {
    Ordinary(FinalizerHandoffRight),
    Opaque {
        right: FinalizerHandoffRight,
        receipt: crate::fence::OpaqueFailStopReceipt,
    },
}

pub(crate) struct FinalizerMissingHandoffGuard {
    join: TerminalJoinGuard,
    handoff: Option<FinalizerVisibilityHandoff>,
}

pub(crate) enum FinalizerWinnerResolution {
    Ordinary(TerminalJoinGuard),
    Opaque(OpaqueFailStopWaitPreparation),
    Missing(FinalizerMissingHandoffGuard),
}

impl FinalizerMissingHandoffGuard {
    /// Retain an absent or foreign handoff together with the authentic counted
    /// winner admission. This path has no success, signal, or fabricated
    /// release edge.
    pub(crate) unsafe fn wait_forever(self) -> ! {
        let Self { join, handoff } = self;
        let registry = join.registry;
        let _keep_join = join;
        let _keep_handoff = handoff;
        unsafe { wait_blocked_unload_forever(registry) }
    }
}

impl OpaqueFailStopWaitGuard {
    /// Consume the only opaque continuation into the permanent wait.
    ///
    /// # Safety
    /// PASSIVE_LEVEL, no registry lock, and an exact counted ticket (if any)
    /// has either already been released or remains owned by this guard.
    pub(crate) unsafe fn wait_forever(self) -> ! {
        let Self {
            registry,
            receipt,
            retained_ticket,
        } = self;
        let _keep_receipt = receipt;
        let _keep_ticket = retained_ticket;
        unsafe { wait_blocked_unload_forever(registry) }
    }
}

impl TerminalJoinGuard {
    fn ordinary(
        registry: NonNull<KernelSessionRegistry>,
        locator: SessionLocator,
        ticket: fsring_core::session::TerminalJoinTicket,
    ) -> Self {
        Self {
            registry,
            locator,
            ticket: NativeTerminalJoinAuthority::Ordinary(ticket),
        }
    }

    pub(crate) const fn registry(&self) -> NonNull<KernelSessionRegistry> {
        self.registry
    }

    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Authenticate an opaque slot and release only this exact ticket.
    /// A mismatched ticket is preserved inside the permanent wait guard.
    ///
    /// # Safety
    /// `cell` is the exact permanent cell named by this guard and the caller
    /// holds its registry lock.
    pub(crate) unsafe fn prepare_opaque_wait(
        self,
        cell: &mut NativeSessionCell,
        receipt: crate::fence::OpaqueFailStopReceipt,
    ) -> OpaqueFailStopWaitPreparation {
        let Self {
            registry,
            // The caller already selected `cell` by this locator, and
            // `release_opaque_join` authenticates against the receipt's own
            // locator, so re-reading it here would prove nothing new.
            locator: _,
            ticket,
        } = self;
        let ticket = match ticket {
            NativeTerminalJoinAuthority::Ordinary(ticket) => ticket,
            NativeTerminalJoinAuthority::Protocol(join) => {
                return match join.release_opaque_protocol_join(&mut cell.terminal_rendezvous) {
                    Ok(drained) => OpaqueFailStopWaitPreparation::Released {
                        wait: OpaqueFailStopWaitGuard {
                            registry,
                            receipt,
                            retained_ticket: None,
                        },
                        drained,
                    },
                    Err(_join) => {
                        OpaqueFailStopWaitPreparation::Retained(OpaqueFailStopWaitGuard {
                            registry,
                            receipt,
                            retained_ticket: None,
                        })
                    }
                };
            }
        };
        let released = cell.release_opaque_join(&receipt, ticket);
        match released {
            Ok(drained) => OpaqueFailStopWaitPreparation::Released {
                wait: OpaqueFailStopWaitGuard {
                    registry,
                    receipt,
                    retained_ticket: None,
                },
                drained,
            },
            Err(ticket) => OpaqueFailStopWaitPreparation::Retained(OpaqueFailStopWaitGuard {
                registry,
                receipt,
                retained_ticket: Some(ticket),
            }),
        }
    }

    /// Wait for the finalizer's distinct visibility decision, then consume it
    /// under the original permanent cell lock. Opaque never touches the
    /// ordinary terminal-outcome event.
    pub(crate) unsafe fn wait_for_finalizer_resolution(self) -> FinalizerWinnerResolution {
        let registry = self.registry;
        let index = self.locator.slot_index();
        let event = {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let event = unsafe {
                lock.cell_mut_prevalidated(index)
                    .visibility_resolution_event()
            };
            unsafe { lock.release() };
            event
        };
        unsafe {
            let _ =
                fsring_sys::c4::KeWaitForSingleObject(event.cast(), 0, 0, 0, core::ptr::null_mut());
        }
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let cell = unsafe { lock.cell_mut_prevalidated(index) };
        let handoff = cell.take_finalizer_handoff();
        match handoff {
            Some(FinalizerVisibilityHandoff::Ordinary(right)) if right.matches(self.locator) => {
                unsafe { lock.release() };
                FinalizerWinnerResolution::Ordinary(self)
            }
            Some(FinalizerVisibilityHandoff::Opaque { right, receipt })
                if right.matches(self.locator) =>
            {
                let prepared = unsafe { self.prepare_opaque_wait(cell, receipt) };
                unsafe { lock.release() };
                FinalizerWinnerResolution::Opaque(prepared)
            }
            None => match cell.authenticate_closed_fail_stop(self.locator) {
                Some(crate::fence::ClosedFailStopAuthentication::Published(_receipt)) => {
                    unsafe { lock.release() };
                    FinalizerWinnerResolution::Ordinary(self)
                }
                Some(crate::fence::ClosedFailStopAuthentication::Opaque(receipt)) => {
                    let prepared = unsafe { self.prepare_opaque_wait(cell, receipt) };
                    unsafe { lock.release() };
                    FinalizerWinnerResolution::Opaque(prepared)
                }
                None => {
                    unsafe { lock.release() };
                    FinalizerWinnerResolution::Missing(FinalizerMissingHandoffGuard {
                        join: self,
                        handoff: None,
                    })
                }
            },
            handoff @ Some(_) => {
                unsafe { lock.release() };
                FinalizerWinnerResolution::Missing(FinalizerMissingHandoffGuard {
                    join: self,
                    handoff,
                })
            }
        }
    }

    /// Wait for the generation's broadcast visibility resolution. Every
    /// Completed, Published, and Opaque decision signals this event; unlike
    /// the finalizer handoff it is not consumed by one winner.
    ///
    /// On ordinary closed outcomes this releases the exact ticket. Opaque
    /// authenticates the durable slot and quarantined rendezvous before the
    /// conditional exact release. An impossible wake/state combination keeps
    /// the ticket in a fail-stop value rather than advancing.
    pub(crate) unsafe fn wait_for_visibility_resolution(self) -> TerminalVisibilityResolution {
        let registry = self.registry;
        let locator = self.locator;
        let index = locator.slot_index();
        let event = {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let event = unsafe {
                lock.cell_mut_prevalidated(index)
                    .visibility_resolution_event()
            };
            unsafe { lock.release() };
            event
        };
        unsafe {
            let _ =
                fsring_sys::c4::KeWaitForSingleObject(event.cast(), 0, 0, 0, core::ptr::null_mut());
        }

        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let cell = unsafe { lock.cell_mut_prevalidated(index) };
        let ticket = match self.ticket {
            NativeTerminalJoinAuthority::Ordinary(ticket) => ticket,
            NativeTerminalJoinAuthority::Protocol(join) => {
                return unsafe { wait_protocol_join_visibility(registry, locator, lock, join) };
            }
        };
        match cell.terminal_rendezvous.outcome_for_locator(locator) {
            Some(fsring_core::session::TerminalRendezvousOutcome::Completed(_))
            | Some(fsring_core::session::TerminalRendezvousOutcome::Blocked(_)) => {
                let released = cell.terminal_rendezvous.release(ticket);
                unsafe { lock.release() };
                match released {
                    Ok(release) => match resolve_terminal_release(release) {
                        TerminalWaitDisposition::Completed { result, drained } => {
                            TerminalVisibilityResolution::Completed { result, drained }
                        }
                        TerminalWaitDisposition::Blocked { blocked, drained } => {
                            TerminalVisibilityResolution::Blocked { blocked, drained }
                        }
                        TerminalWaitDisposition::Open(ticket) => {
                            TerminalVisibilityResolution::FailStop(TerminalJoinGuard::ordinary(
                                registry, locator, ticket,
                            ))
                        }
                    },
                    Err((_error, ticket)) => TerminalVisibilityResolution::FailStop(
                        TerminalJoinGuard::ordinary(registry, locator, ticket),
                    ),
                }
            }
            Some(fsring_core::session::TerminalRendezvousOutcome::Open) => {
                // An ordinary finalizer publishes its authenticated handoff
                // before running the infallible delete suffix. At that point
                // Opaque has been ruled out, but the terminal outcome is
                // legitimately still Open. Waiting on terminal_outcome is now
                // safe and cannot strand this ticket on an Opaque generation.
                let terminal_event = cell.terminal_outcome_event();
                unsafe { lock.release() };
                unsafe {
                    let _ = fsring_sys::c4::KeWaitForSingleObject(
                        terminal_event.cast(),
                        0,
                        0,
                        0,
                        core::ptr::null_mut(),
                    );
                }
                let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                let cell = unsafe { lock.cell_mut_prevalidated(index) };
                let released = cell.terminal_rendezvous.release(ticket);
                unsafe { lock.release() };
                match released {
                    Ok(release) => match resolve_terminal_release(release) {
                        TerminalWaitDisposition::Completed { result, drained } => {
                            TerminalVisibilityResolution::Completed { result, drained }
                        }
                        TerminalWaitDisposition::Blocked { blocked, drained } => {
                            TerminalVisibilityResolution::Blocked { blocked, drained }
                        }
                        TerminalWaitDisposition::Open(ticket) => {
                            TerminalVisibilityResolution::FailStop(TerminalJoinGuard::ordinary(
                                registry, locator, ticket,
                            ))
                        }
                    },
                    Err((_error, ticket)) => TerminalVisibilityResolution::FailStop(
                        TerminalJoinGuard::ordinary(registry, locator, ticket),
                    ),
                }
            }
            None => {
                let join = TerminalJoinGuard::ordinary(registry, locator, ticket);
                match cell.authenticate_closed_fail_stop(locator) {
                    Some(crate::fence::ClosedFailStopAuthentication::Opaque(receipt)) => {
                        let prepared = unsafe { join.prepare_opaque_wait(cell, receipt) };
                        unsafe { lock.release() };
                        TerminalVisibilityResolution::Opaque(prepared)
                    }
                    Some(crate::fence::ClosedFailStopAuthentication::Published(_)) | None => {
                        unsafe { lock.release() };
                        TerminalVisibilityResolution::FailStop(join)
                    }
                }
            }
        }
    }

    /// Unload-specific counted arrival. A Published Blocked generation first
    /// releases this exact ticket and only then authenticates the occupied
    /// durable slot; Opaque authenticates slot+rendezvous before any
    /// conditional release. Every blocked outcome returns an authenticated
    /// affine wait guard instead of entering the permanent wait here.
    pub(crate) unsafe fn wait_for_unload_visibility(self) -> R3UnloadVisibilityResolution {
        let Self {
            registry,
            locator,
            ticket,
        } = self;
        let index = locator.slot_index();
        let visibility_event = {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let event = unsafe {
                lock.cell_mut_prevalidated(index)
                    .visibility_resolution_event()
            };
            unsafe { lock.release() };
            event
        };
        unsafe {
            let _ = fsring_sys::c4::KeWaitForSingleObject(
                visibility_event.cast(),
                0,
                0,
                0,
                core::ptr::null_mut(),
            );
        }

        let mut ticket = ticket;
        loop {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let cell = unsafe { lock.cell_mut_prevalidated(index) };
            let ordinary = match ticket {
                NativeTerminalJoinAuthority::Ordinary(ticket) => ticket,
                NativeTerminalJoinAuthority::Protocol(join) => {
                    match unsafe { wait_protocol_join_visibility(registry, locator, lock, join) } {
                        TerminalVisibilityResolution::Completed { result, drained } => {
                            if let Some(signal) = drained {
                                unsafe { signal_joiners_drained(registry, signal) };
                            }
                            return R3UnloadVisibilityResolution::Completed(result);
                        }
                        TerminalVisibilityResolution::Opaque(prepared) => {
                            return R3UnloadVisibilityResolution::Opaque(prepared);
                        }
                        TerminalVisibilityResolution::Blocked { drained, .. } => {
                            if let Some(signal) = drained {
                                unsafe { signal_joiners_drained(registry, signal) };
                            }
                            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                            let wait = lock.prepare_published_unload_wait(locator);
                            unsafe { lock.release() };
                            match wait {
                                Some(wait) => {
                                    return R3UnloadVisibilityResolution::Published {
                                        wait,
                                        drained: None,
                                    };
                                }
                                None => unsafe { bugcheck_unload_visibility_invariant(8) },
                            }
                        }
                        TerminalVisibilityResolution::FailStop(guard) => {
                            ticket = guard.ticket;
                            let terminal_event = {
                                let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                                let event = unsafe {
                                    lock.cell_mut_prevalidated(index).terminal_outcome_event()
                                };
                                unsafe { lock.release() };
                                event
                            };
                            unsafe {
                                let _ = fsring_sys::c4::KeWaitForSingleObject(
                                    terminal_event.cast(),
                                    0,
                                    0,
                                    0,
                                    core::ptr::null_mut(),
                                );
                            }
                            continue;
                        }
                    }
                }
            };
            match cell.terminal_rendezvous.outcome_for_locator(locator) {
                Some(fsring_core::session::TerminalRendezvousOutcome::Completed(_)) => {
                    let released = cell.terminal_rendezvous.release(ordinary);
                    unsafe { lock.release() };
                    match released {
                        Ok(release) => match resolve_terminal_release(release) {
                            TerminalWaitDisposition::Completed { result, drained } => {
                                if let Some(signal) = drained {
                                    unsafe { signal_joiners_drained(registry, signal) };
                                }
                                return R3UnloadVisibilityResolution::Completed(result);
                            }
                            TerminalWaitDisposition::Open(returned) => {
                                ticket = NativeTerminalJoinAuthority::Ordinary(returned)
                            }
                            TerminalWaitDisposition::Blocked { .. } => unsafe {
                                bugcheck_unload_visibility_invariant(1)
                            },
                        },
                        Err((_error, _retained)) => unsafe {
                            bugcheck_unload_visibility_invariant(2)
                        },
                    }
                }
                Some(fsring_core::session::TerminalRendezvousOutcome::Blocked(_)) => {
                    // Published asymmetry: release the real ticket first.
                    let released = cell.terminal_rendezvous.release(ordinary);
                    match released {
                        Ok(release) => match resolve_terminal_release(release) {
                            TerminalWaitDisposition::Blocked { drained, .. } => {
                                let released = ReleasedPublishedJoin {
                                    registry,
                                    locator,
                                    drained,
                                };
                                let prepared =
                                    lock.prepare_released_published_unload_wait(released);
                                unsafe { lock.release() };
                                let (wait, drained) = match prepared {
                                    Ok(prepared) => prepared,
                                    Err(_released) => unsafe {
                                        bugcheck_unload_visibility_invariant(3)
                                    },
                                };
                                return R3UnloadVisibilityResolution::Published { wait, drained };
                            }
                            TerminalWaitDisposition::Open(returned) => {
                                unsafe { lock.release() };
                                ticket = NativeTerminalJoinAuthority::Ordinary(returned);
                            }
                            TerminalWaitDisposition::Completed { .. } => {
                                unsafe { lock.release() };
                                unsafe { bugcheck_unload_visibility_invariant(4) }
                            }
                        },
                        Err((_error, retained)) => {
                            let prepared = lock
                                .prepare_retained_published_join_wait(registry, locator, retained);
                            unsafe { lock.release() };
                            match prepared {
                                Ok(wait) => {
                                    return R3UnloadVisibilityResolution::RetainedPublished(wait);
                                }
                                Err(_retained) => unsafe {
                                    bugcheck_unload_visibility_invariant(5)
                                },
                            }
                        }
                    }
                }
                Some(fsring_core::session::TerminalRendezvousOutcome::Open) => {
                    // Ordinary finalizer resolution precedes its infallible
                    // suffix. Visibility ruled Opaque out, so this one follow-
                    // up wait on the terminal outcome is safe.
                    ticket = NativeTerminalJoinAuthority::Ordinary(ordinary);
                    let terminal_event = cell.terminal_outcome_event();
                    unsafe { lock.release() };
                    unsafe {
                        let _ = fsring_sys::c4::KeWaitForSingleObject(
                            terminal_event.cast(),
                            0,
                            0,
                            0,
                            core::ptr::null_mut(),
                        );
                    }
                }
                None => match cell.authenticate_closed_fail_stop(locator) {
                    Some(crate::fence::ClosedFailStopAuthentication::Opaque(receipt)) => {
                        let join = TerminalJoinGuard::ordinary(registry, locator, ordinary);
                        let prepared = unsafe { join.prepare_opaque_wait(cell, receipt) };
                        unsafe { lock.release() };
                        return R3UnloadVisibilityResolution::Opaque(prepared);
                    }
                    Some(crate::fence::ClosedFailStopAuthentication::Published(_)) | None => {
                        unsafe { lock.release() };
                        unsafe { bugcheck_unload_visibility_invariant(6) }
                    }
                },
            }
        }
    }

    /// The locked half of one counted arrival's wake: validate, copy, release.
    ///
    /// This function blocks on the generation's outcome event. Its
    /// admissibility is
    /// [`fsring_core::adapter::lifecycle::decide_terminal_wait`]: every short
    /// guard must already be gone. This call is what runs *after* that wake —
    /// it retakes the registry lock, resolves the release against this exact
    /// generation, and hands back what the arrival woke up to see. Binding the
    /// production wait loop around it is Task 12's cutover.
    ///
    /// The drained signal inside the disposition is returned rather than
    /// raised, because the event may only be set once the lock is dropped.
    /// `Open` hands the ticket back: the runner parked a transient residual and
    /// the arrival stays counted, which is the safety-over-liveness result.
    ///
    /// # Safety
    /// The registry named by this guard is the live permanent root, the caller
    /// holds no registry lock, and it runs at PASSIVE_LEVEL.
    const LEGACY_TERMINAL_OUTCOME_WAIT_REMOVED: () = ();
}

unsafe fn bugcheck_unload_visibility_invariant(site: u64) -> ! {
    unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, site, 0, 0, 0) }
}

pub(crate) unsafe fn bugcheck_direct_blocked_unload_without_slot_auth() -> ! {
    unsafe { bugcheck_unload_visibility_invariant(7) }
}

/// What one native terminal arrival received.
pub(crate) enum TerminalDisposition {
    Winner {
        work: TerminalWork,
        join: TerminalJoinGuard,
    },
    Join(TerminalJoinGuard),
    Completed(TerminalResult),
    Blocked(fsring_core::session::TerminalBlocked),
}

/// The native half of one prepared terminal claim.
///
/// It holds the exact cell fields the commit will move, as disjoint borrows of
/// the same cell the core claim was preflighted against, so nothing between
/// preparation and commit can substitute another cell's owners.
pub(crate) struct PreparedNativeCellClaim<'objects> {
    phase: &'objects mut NativeCellPhase,
    control_owner: &'objects mut Option<ControlOwner>,
    shell_owner: &'objects mut Option<NativeSessionOwner>,
    root_release: &'objects mut Option<SessionRootReleaseRight>,
}

pub(crate) struct PreparedNativeTerminalClaim<'objects> {
    core: PreparedTerminalClaim<'objects, SESSION_CELL_COUNT>,
    cell: PreparedNativeCellClaim<'objects>,
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
}

/// Preflight one whole native terminal claim without mutating anything.
///
/// `context` is the arriving path's own control-file context. It is a parameter
/// rather than a cell field for a reason that is easy to get wrong: the winning
/// commit *takes* the cell's `ControlOwner`, so a cell that has already been
/// claimed has no context left to hand a joiner. Reading the binding out of the
/// cell would therefore work exactly once per generation and refuse every
/// joiner afterwards. While the cell still owns a `ControlOwner`, the supplied
/// context must be that exact one — a caller cannot claim this generation
/// against some other file's binding.
///
/// # Safety
/// `lock` is the held registry lock of the live permanent root, and `context`
/// is a live control-file context whose dispatch rundown the caller holds.
// The Task 12 grammar freezes this header. Eliding the same lifetime in
// core was tried and reverted: it is a SHAPE change, and the grammar
// caught it.
#[allow(clippy::needless_lifetimes)]
pub(crate) unsafe fn prepare_native_terminal_claim<'objects>(
    lock: &'objects mut RegistryLockGuard,
    context: NonNull<ControlFileContext>,
    locator: SessionLocator,
    request: TerminalRequest,
) -> Result<PreparedNativeTerminalClaim<'objects>, LifecycleError> {
    let registry = lock.registry;
    let Some(cell) = (unsafe { lock.cell_ptr(locator.slot_index()) }) else {
        return Err(LifecycleError::WrongLocator);
    };
    let core = unsafe { lock.core_ptr() };

    // SAFETY: the lock is held; `cell` and `core` name disjoint fields of the
    // same initialized permanent root, and the split below borrows disjoint
    // fields of one cell.
    let NativeSessionCell {
        generation,
        identity,
        phase,
        session,
        registry_lease,
        control_owner,
        shell_owner,
        root_release,
        terminal_rendezvous,
        ..
    } = unsafe { &mut *cell };

    if *generation != locator.generation() || *identity != Some(locator.identity()) {
        return Err(LifecycleError::WrongLocator);
    }

    // An unclaimed generation is still owned by exactly one control file, and
    // this must be it.
    if let Some(owner) = control_owner.as_ref() {
        if owner.locator() != locator {
            return Err(LifecycleError::WrongLocator);
        }
        if owner.context() != context {
            return Err(LifecycleError::WrongLocator);
        }
    }
    // SAFETY: the caller's contract keeps its context live, and the registry
    // lock serializes every binding transition.
    let binding = unsafe { crate::control::binding_mut(context) };

    // SAFETY: the lock is held and no other reference to the core registry
    // exists inside this call.
    let core = unsafe { &mut *core };
    let core_claim = fsring_core::session::prepare_terminal_claim(
        core,
        binding,
        terminal_rendezvous,
        registry_lease,
        locator,
        request,
    )?;

    match core_claim.kind() {
        CoreTerminalClaimKind::Winner => {
            if *phase != NativeCellPhase::Live {
                return Err(LifecycleError::Invariant);
            }
            // The winner is the one arrival that consumes the owner, so it is
            // the one arrival that must find it present.
            if control_owner.is_none() {
                return Err(LifecycleError::Invariant);
            }
            let (Some(shell), Some(root)) = (shell_owner.as_ref(), root_release.as_ref()) else {
                return Err(LifecycleError::Invariant);
            };
            if shell.locator() != locator
                || root.locator() != locator
                || !shell.matches_mirror(*session)
                || session.is_null()
            {
                return Err(LifecycleError::Invariant);
            }
        }
        CoreTerminalClaimKind::Join => {
            if !matches!(
                *phase,
                NativeCellPhase::Removing | NativeCellPhase::Deleting
            ) {
                return Err(LifecycleError::Invariant);
            }
        }
        CoreTerminalClaimKind::Completed | CoreTerminalClaimKind::Blocked => {}
    }

    Ok(PreparedNativeTerminalClaim {
        core: core_claim,
        cell: PreparedNativeCellClaim {
            phase,
            control_owner,
            shell_owner,
            root_release,
        },
        registry,
        locator,
    })
}

impl PreparedNativeCellClaim<'_> {
    fn take_winner_owners(
        &mut self,
    ) -> (ControlOwner, NativeSessionOwner, SessionRootReleaseRight) {
        let Some(owner) = self.control_owner.take() else {
            unreachable!("the prepared winner preflighted its exact control owner")
        };
        let (Some(shell), Some(root)) = (self.shell_owner.take(), self.root_release.take()) else {
            unreachable!("the prepared winner preflighted both native owners")
        };
        (owner, shell, root)
    }
}

impl PreparedNativeTerminalClaim<'_> {
    /// The one indivisible native suffix. It cannot refuse.
    ///
    /// # Safety
    /// The registry lock is still held and the preflighted cell has not been
    /// mutated since preparation, which the retained borrows guarantee.
    pub(crate) unsafe fn commit(self) -> TerminalDisposition {
        let Self {
            core,
            cell,
            registry,
            locator,
        } = self;
        let mut cell = cell;
        match core.commit() {
            CoreTerminalDisposition::Winner(winner) => {
                let (winner, terminal, ticket) = winner.into_parts();
                let (owner, shell, root) = cell.take_winner_owners();
                let (control, closing) = owner.split();
                *cell.phase = NativeCellPhase::Removing;
                TerminalDisposition::Winner {
                    work: TerminalWork {
                        locator,
                        winner,
                        terminal,
                        control,
                        closing,
                        shell,
                        root,
                    },
                    join: TerminalJoinGuard::ordinary(registry, locator, ticket),
                }
            }
            CoreTerminalDisposition::Join(ticket) => {
                TerminalDisposition::Join(TerminalJoinGuard::ordinary(registry, locator, ticket))
            }
            CoreTerminalDisposition::Completed(result) => TerminalDisposition::Completed(result),
            CoreTerminalDisposition::Blocked(blocked) => TerminalDisposition::Blocked(blocked),
        }
    }
}

unsafe fn wait_protocol_join_visibility(
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
    mut lock: RegistryLockGuard,
    join: fsring_core::adapter::lifecycle::CommittedProtocolJoin,
) -> TerminalVisibilityResolution {
    let cell = unsafe { lock.cell_mut_prevalidated(locator.slot_index()) };
    match join.release_protocol_join(&mut cell.terminal_rendezvous) {
        Ok(fsring_core::adapter::lifecycle::CommittedProtocolJoinRelease::Released {
            outcome,
            drained,
        }) => {
            unsafe { lock.release() };
            match outcome {
                fsring_core::session::TerminalClosedOutcome::Completed(result) => {
                    TerminalVisibilityResolution::Completed { result, drained }
                }
                fsring_core::session::TerminalClosedOutcome::Blocked(blocked) => {
                    TerminalVisibilityResolution::Blocked { blocked, drained }
                }
            }
        }
        Ok(fsring_core::adapter::lifecycle::CommittedProtocolJoinRelease::Open(join)) => {
            unsafe { lock.release() };
            TerminalVisibilityResolution::FailStop(TerminalJoinGuard {
                registry,
                locator,
                ticket: NativeTerminalJoinAuthority::Protocol(join),
            })
        }
        Err((_error, join)) => {
            unsafe { lock.release() };
            TerminalVisibilityResolution::FailStop(TerminalJoinGuard {
                registry,
                locator,
                ticket: NativeTerminalJoinAuthority::Protocol(join),
            })
        }
    }
}

impl KernelSessionRegistry {
    pub(crate) fn claim_committed_protocol(
        &self,
        committed: fsring_core::adapter::enter::CommittedProtocolAbort,
    ) -> NativeProtocolTerminalDisposition {
        let locator = committed.authenticated_locator();
        let registry = unsafe { NonNull::new_unchecked((self as *const Self).cast_mut()) };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_ptr(locator.slot_index()) }) else {
            unsafe { lock.release() };
            unreachable!("a committed protocol abort names a published cell");
        };
        // NO PRODUCTION CALLER, and this arm is why that matters. Since round
        // 18 the finalizer retires `recorded_control_context` in the hold that
        // stores the completed record, so a completed generation answers `None`
        // here and this bugchecks -- permanently, under `panic = "abort"`.
        // Nothing reaches it today: `claim_committed_protocol` is called from
        // nowhere. Wiring it means replacing this arm with the answer the scans
        // give a retired pointer (the cell's rendezvous outcome), NOT leaving a
        // bugcheck on a generation that merely finished (native review N18-4).
        let Some(context) = (unsafe { (*cell).recorded_control_context() }) else {
            unsafe { lock.release() };
            unreachable!("a live protocol abort has a recorded control context");
        };
        let core = unsafe { lock.core_ptr() };
        let NativeSessionCell {
            phase,
            control_owner,
            shell_owner,
            root_release,
            terminal_rendezvous,
            registry_lease,
            ..
        } = unsafe { &mut *cell };
        let binding = unsafe { crate::control::binding_mut(context) };
        let prepared = fsring_core::adapter::lifecycle::prepare_protocol_terminal_claim(
            unsafe { &mut *core },
            binding,
            terminal_rendezvous,
            registry_lease,
            committed,
        );
        let disposition = prepared.commit_protocol_claim();
        let result = match disposition {
            fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Winner {
                work,
                join,
            } => {
                let (winner, terminal) = work.into_terminal_authorities();
                let mut cell_claim = PreparedNativeCellClaim {
                    phase,
                    control_owner,
                    shell_owner,
                    root_release,
                };
                let (owner, shell, root) = cell_claim.take_winner_owners();
                let (control, closing) = owner.split();
                *cell_claim.phase = NativeCellPhase::Removing;
                NativeProtocolTerminalDisposition::Terminal(TerminalDisposition::Winner {
                    work: TerminalWork {
                        locator,
                        winner,
                        terminal,
                        control,
                        closing,
                        shell,
                        root,
                    },
                    join: TerminalJoinGuard {
                        registry,
                        locator,
                        ticket: NativeTerminalJoinAuthority::Protocol(join),
                    },
                })
            }
            fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Join(join) => {
                NativeProtocolTerminalDisposition::Terminal(TerminalDisposition::Join(
                    TerminalJoinGuard {
                        registry,
                        locator,
                        ticket: NativeTerminalJoinAuthority::Protocol(join),
                    },
                ))
            }
            fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Completed(
                completed,
            ) => NativeProtocolTerminalDisposition::Terminal(TerminalDisposition::Completed(
                completed.into_result(),
            )),
            fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Reject(
                receipt,
            ) => NativeProtocolTerminalDisposition::Reject(receipt),
        };
        unsafe { lock.release() };
        result
    }
}

/// What CLEANUP found for one control file, with its affine authority attached.
///
/// The three closed routes answer without resolving a cell at all: the record
/// and the blocked observation are stable copies, so a CLEANUP that arrives
/// after the generation is gone cannot touch a reused cell.
pub(crate) enum NativeCleanupRoute {
    Empty,
    Setup(fsring_core::session::SetupCleanupRight),
    Terminal(TerminalDisposition),
    /// The record is ACKNOWLEDGED before this route is built, inside the same
    /// registry-lock hold that took it, so the `CloseContextRight` is already
    /// back in the context and only these two values leave the hold. Carrying
    /// the record itself out was the defect: the lock was released, the one
    /// consumer's catch-all arm dropped it, and CLOSE lost the right that makes
    /// it free the context and release its rundown.
    CompletedControl {
        generation: u64,
        result: TerminalResult,
    },
    /// DEVIATION (recorded in the Task 9 evidence): the plan's interface sketch
    /// writes `Blocked(TerminalBlocked)`, but a late CLEANUP reads the *binding*
    /// — the stable copy that survives cell reuse — and the binding holds only
    /// `{locator, class}`, and a binding cannot produce the rest of a
    /// `TerminalBlocked` however inhabited that type is. The
    /// rendezvous-sourced blocked observation, which *is* a `TerminalBlocked`,
    /// arrives through `Terminal(TerminalDisposition::Blocked(_))`.
    ///
    /// This doc used to justify the arm with "`TerminalBlocked`'s production
    /// representation is still uninhabited until Task 10 introduces it". Task 10
    /// closed and the type is inhabited -- `TerminalBlocked::from_fence` in
    /// `fsring-core`'s `session.rs` builds one from a fence fail-stop --
    /// so the deviation now rests on what a binding holds, which is the reason
    /// that does not expire.
    Blocked {
        locator: SessionLocator,
        class: fsring_core::session::TerminalBlockedClass,
    },
    /// Opaque quarantine is authenticated but deliberately has no ordinary
    /// terminal outcome or signal. Task 6 consumes it into unload guards.
    OpaqueRetained(SessionLocator),
    AlreadyClosed,
}

/// Claim one control file's CLEANUP route under the registry lock.
///
/// Both models move under the same lock hold: the binding phase and the cell's
/// terminal state cannot be observed in different generations, so a CLEANUP
/// cannot interleave between the core publication and the binding publication.
///
/// This is PRODUCTION: the CLEANUP dispatch path in `control.rs` calls it.
/// The previous wording, "This is staged. Task 12 is the sole commit that routes
/// production CLEANUP through it", described the tree before Task 12 landed; the
/// graph manifest's own r3 staging note already records the same symbol as
/// production-reachable since the cutover.
///
/// # Safety
/// `registry` is the live permanent root, `context` is the calling CLEANUP's
/// own control-file context, and the caller holds no registry lock and no
/// dispatch rundown. The context stays live without that rundown:
/// IRP_MJ_CLEANUP completes before IRP_MJ_CLOSE for the same file object, and
/// CLOSE frees only a context CLEANUP has acknowledged. This contract used to
/// say the caller held the rundown; the dispatch released it before the
/// callout even then, and a CLEANUP the fence's rundown wait refused never
/// acquired it.
pub(crate) unsafe fn claim_native_cleanup_route(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    request: TerminalRequest,
) -> Result<NativeCleanupRoute, NTSTATUS> {
    use fsring_core::adapter::lifecycle::{CleanupRoute, decide_cleanup_route};

    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    // SAFETY: the registry lock serializes every binding transition.
    let claim = unsafe { crate::control::binding_mut(context) }.claim_cleanup();
    let claim = match claim {
        Ok(claim) => claim,
        Err(_) => {
            unsafe { lock.release() };
            return Err(wdk_sys::STATUS_INVALID_DEVICE_STATE);
        }
    };
    let route = decide_cleanup_route(&claim);
    // The phase word is republished inside the same hold, so no observer sees
    // the old phase after the claim.
    unsafe { crate::control::publish_binding_phase(context) };

    let answer = match route {
        CleanupRoute::Empty => Ok(NativeCleanupRoute::Empty),
        CleanupRoute::Setup => match claim {
            fsring_core::session::CleanupBindingClaim::Setup(right) => {
                Ok(NativeCleanupRoute::Setup(right))
            }
            _ => unreachable!("the setup route is decided from the setup claim"),
        },
        CleanupRoute::AlreadyClosed => Ok(NativeCleanupRoute::AlreadyClosed),
        CleanupRoute::Blocked(locator) => match claim {
            fsring_core::session::CleanupBindingClaim::Blocked { class, .. } => {
                Ok(NativeCleanupRoute::Blocked { locator, class })
            }
            _ => unreachable!("the blocked route is decided from the blocked claim"),
        },
        CleanupRoute::OpaqueRetained(locator) => Ok(NativeCleanupRoute::OpaqueRetained(locator)),
        CleanupRoute::CompletedRecord { .. } => {
            // SAFETY: the finalizer stored this record under the same lock.
            match unsafe { crate::control::take_completed_record(context) } {
                // The record carries the `CloseContextRight` that CLOSE needs,
                // and `take_completed_record` leaves the context
                // `BlockedCellOwned` -- so the right MUST go back in this same
                // hold, which is what that function's own contract says and
                // what `acknowledge_completed_control` exists to do. It was
                // never called: the route carried the record out instead, the
                // lock was released, and `run_cleanup_terminal`'s catch-all arm
                // dropped it. CLOSE then took the `CellOwned` path, which frees
                // no pool and releases no rundown, so unload's
                // `ExWaitForRundownProtectionRelease(control_context_admission)`
                // waited for a release that could never happen.
                //
                // Acknowledged HERE, under the lock the contract names, and
                // only the resulting values leave the hold.
                Some(record) => {
                    // SAFETY: the registry lock is still held and `context` is
                    // the live context this record was just taken from.
                    match unsafe { acknowledge_completed_control(context, record) } {
                        Ok((generation, result)) => {
                            Ok(NativeCleanupRoute::CompletedControl { generation, result })
                        }
                        // The slot was not the `BlockedCellOwned` this hold
                        // just created, so the right cannot be stored. Put the
                        // record back rather than dropping it: a dropped record
                        // is the leak above, and a restored one leaves the
                        // context exactly as it was found.
                        Err(record) => {
                            // SAFETY: same hold, same context, and the slot is
                            // the one `take_completed_record` emptied.
                            unsafe {
                                crate::control::store_completed_control_record_prepared(
                                    context, record,
                                )
                            };
                            Err(wdk_sys::STATUS_INVALID_DEVICE_STATE)
                        }
                    }
                }
                None => Err(wdk_sys::STATUS_INVALID_DEVICE_STATE),
            }
        }
        CleanupRoute::ClaimTerminal(locator) | CleanupRoute::JoinTerminal(locator) => {
            // SAFETY: the lock is held, and this CLEANUP's own context -- and
            // the binding in it -- stays live across the claim because CLOSE
            // cannot run before this CLEANUP completes.
            match unsafe { prepare_native_terminal_claim(&mut lock, context, locator, request) } {
                // SAFETY: the retained borrows kept the whole cross-product
                // fixed since the preflight.
                Ok(prepared) => Ok(NativeCleanupRoute::Terminal(unsafe { prepared.commit() })),
                Err(_) => Err(wdk_sys::STATUS_INVALID_DEVICE_STATE),
            }
        }
    };
    // The winning claim republished the binding as ClosingLive inside the same
    // hold; the phase word has to follow it before any observer runs.
    unsafe { crate::control::publish_binding_phase(context) };
    unsafe { lock.release() };
    answer
}

impl NativeSessionCell {
    fn r3_finalizer_ledger_is_exactly_empty(&self) -> bool {
        self.finalizer_callback_admitted.is_none()
            && self.finalizer_context.queued.is_none()
            && self.finalizer.locator().is_none()
            && self.finalizer.deposit_is_none()
            && matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
            && self.finalizer_handoff.is_none()
    }

    fn r3_finalizer_is_authenticated_ordinary_in_flight(
        &self,
        registry: NonNull<KernelSessionRegistry>,
        locator: SessionLocator,
    ) -> bool {
        let handoff_is_ordinary_for_locator = match &self.finalizer_handoff {
            None => true,
            Some(FinalizerVisibilityHandoff::Ordinary(right)) => right.matches(locator),
            Some(FinalizerVisibilityHandoff::Opaque { .. }) => false,
        };
        self.phase == NativeCellPhase::Deleting
            && self.generation == locator.generation()
            && self.identity == Some(locator.identity())
            && self
                .finalizer_callback_admitted
                .as_ref()
                .is_some_and(|admitted| {
                    admitted.registry == registry && admitted.locator == locator
                })
            && self.finalizer.locator() == Some(locator)
            && self.finalizer.deposit_is_none()
            && matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Running
            )
            && handoff_is_ordinary_for_locator
            && self.checkpoint_readiness.is_none()
            && self.fail_stop.is_empty()
            && matches!(
                self.terminal_rendezvous.outcome_for_locator(locator),
                Some(fsring_core::session::TerminalRendezvousOutcome::Completed(
                    _
                ))
            )
    }

    fn matches_live_locator(&self, locator: SessionLocator) -> bool {
        self.phase == NativeCellPhase::Live
            && self.generation == locator.generation()
            && self.identity == Some(locator.identity())
            && !self.session.is_null()
    }

    pub(crate) fn staging_publication_preflight(
        &self,
        locator: SessionLocator,
        session: *mut NativeSession,
        process: PEPROCESS,
    ) -> Result<(), NTSTATUS> {
        if self.phase != NativeCellPhase::Staging
            || self.generation != locator.generation()
            || self.identity != Some(locator.identity())
            || self.session != session
            || self.process != process
            || self.registry_lease.is_some()
            || self.control_owner.is_some()
            || self.shell_owner.is_some()
            || self.root_release.is_some()
            || self.finalizer.locator().is_some()
            || !self.fail_stop.is_empty()
            || self.finalizer_handoff.is_some()
            || self.finalizer_callback_admitted.is_some()
            || self.finalizer_context.queued.is_some()
            || !self.finalizer.deposit_is_none()
            || !matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
        {
            Err(wdk_sys::STATUS_INVALID_DEVICE_STATE)
        } else {
            Ok(())
        }
    }

    pub(crate) fn install_staging(
        &mut self,
        locator: SessionLocator,
        session: *mut NativeSession,
        process: PEPROCESS,
    ) -> Result<(), NTSTATUS> {
        if self.phase != NativeCellPhase::Free
            || !self.session.is_null()
            || !self.process.is_null()
            || self.registry_lease.is_some()
            || self.control_owner.is_some()
            || self.finalizer.locator().is_some()
            || !self.fail_stop.is_empty()
            || self.finalizer_handoff.is_some()
            || self.finalizer_callback_admitted.is_some()
            || self.finalizer_context.queued.is_some()
            || !self.finalizer.deposit_is_none()
            || !matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
        {
            return Err(wdk_sys::STATUS_INVALID_DEVICE_STATE);
        }
        self.generation = locator.generation();
        self.identity = Some(locator.identity());
        self.phase = NativeCellPhase::Staging;
        self.session = session;
        self.process = process;
        self.process_loss_handled = false;
        Ok(())
    }

    pub(crate) fn clear_staging(&mut self, locator: SessionLocator) -> Result<(), NTSTATUS> {
        if self.phase != NativeCellPhase::Staging
            || self.generation != locator.generation()
            || self.identity != Some(locator.identity())
        {
            return Err(wdk_sys::STATUS_INVALID_DEVICE_STATE);
        }
        self.identity = None;
        self.phase = NativeCellPhase::Free;
        self.session = core::ptr::null_mut();
        self.process = core::ptr::null_mut();
        self.process_loss_handled = false;
        Ok(())
    }

    /// Publish the cell and take custody of all install-origin authorities.
    ///
    /// The shell and root owners are deposited in the same transition that
    /// makes the cell `Live`, so there is no window in which a reachable cell
    /// owns a lease but not the shell it points at. Every fallible check ran in
    /// `staging_publication_preflight`; this consuming commit has no refusal.
    pub(crate) unsafe fn publish_live(
        &mut self,
        locator: SessionLocator,
        registry_lease: RegistryLease,
        control_owner: ControlOwner,
        shell_owner: NativeSessionOwner,
        root_release: SessionRootReleaseRight,
        finalizer_right: R3FinalizerCellBindRight,
    ) {
        if self.phase != NativeCellPhase::Staging
            || self.generation != locator.generation()
            || self.identity != Some(locator.identity())
            || self.registry_lease.is_some()
            || self.control_owner.is_some()
            || self.shell_owner.is_some()
            || self.root_release.is_some()
            || self.finalizer.locator().is_some()
            || !self.fail_stop.is_empty()
            || !self.finalizer.deposit_is_none()
            || !matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
            // The owners must be the ones this exact locator branded, and the
            // shell must be the allocation this cell already mirrors.
            || shell_owner.locator() != locator
            || root_release.locator() != locator
            || !shell_owner.matches_mirror(self.session)
        {
            unreachable!("the native publication commit retained its exact preflight")
        }
        if self.finalizer.bind(finalizer_right).is_err() {
            unreachable!("the install-origin finalizer bind right targets the empty cell")
        }
        self.registry_lease = Some(registry_lease);
        self.recorded_control_context = Some(control_owner.context());
        self.control_owner = Some(control_owner);
        self.shell_owner = Some(shell_owner);
        self.root_release = Some(root_release);
        self.phase = NativeCellPhase::Live;
    }

    pub(crate) fn terminal_rendezvous_mut(&mut self) -> &mut TerminalRendezvous {
        &mut self.terminal_rendezvous
    }

    /// The same rendezvous, borrowed for a decision rather than a mutation.
    ///
    /// The publication predicate reads it and returns, so nothing is live while
    /// the locked suffix reborrows this cell whole. Asking through the mutable
    /// accessor instead would put an exclusive borrow of one field up against
    /// three whole-cell reborrows in the same lock hold.
    pub(crate) const fn terminal_rendezvous_ref(&self) -> &TerminalRendezvous {
        &self.terminal_rendezvous
    }

    /// This cell's locator while it is Live, and only then.
    ///
    /// Rebuilt from the owner the publication suffix deposited, not from the
    /// three mirror fields: a cell with no authentic owner has no locator to
    /// report, however its mirror happens to read.
    pub(crate) fn live_locator(&self) -> Option<SessionLocator> {
        if self.phase != NativeCellPhase::Live {
            return None;
        }
        let locator = self.shell_owner.as_ref()?.locator();
        if self.identity != Some(locator.identity()) || self.generation != locator.generation() {
            return None;
        }
        Some(locator)
    }

    /// The control context this generation recorded, until its completion.
    ///
    /// A process-loss or unload arrival has no context of its own, so it uses
    /// the cell's. `publish_live` records it, and it stays set through the
    /// winning claim -- the winner's `ClosingControlOwner` keeps the context
    /// alive, and an arrival that finds the pointer prepares a claim that joins.
    /// `RegistryLockGuard::publish_completed_generation` retires it in the hold
    /// that stores the completed record, before CLEANUP can acknowledge that
    /// record and CLOSE can free the context; from then on an arrival takes the
    /// rendezvous route and touches no context.
    pub(crate) fn recorded_control_context(&self) -> Option<NonNull<ControlFileContext>> {
        self.recorded_control_context
            .or_else(|| self.control_owner.as_ref().map(ControlOwner::context))
    }

    pub(crate) const fn session_mirror(&self) -> *mut NativeSession {
        self.session
    }

    /// The cell half of the checkpoint-finish cross-product. It mutates nothing.
    pub(crate) fn checkpoint_finish_preflight(
        &self,
        locator: SessionLocator,
    ) -> Result<(), LifecycleError> {
        if self.generation != locator.generation() || self.identity != Some(locator.identity()) {
            return Err(LifecycleError::WrongLocator);
        }
        if self.phase != NativeCellPhase::Removing {
            return Err(LifecycleError::WrongState);
        }
        // The winner took these at its claim; a cell still holding one would
        // mean two owners of the same shell.
        if self.control_owner.is_some() || self.shell_owner.is_some() || self.root_release.is_some()
        {
            return Err(LifecycleError::Invariant);
        }
        if self.checkpoint_readiness.is_some() || !self.finalizer.deposit_is_none() {
            return Err(LifecycleError::Invariant);
        }
        if !self.fail_stop.is_empty() {
            return Err(LifecycleError::FinalizerBusy);
        }
        if self.finalizer.locator() != Some(locator)
            || !matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
        {
            return Err(LifecycleError::FinalizerBusy);
        }
        Ok(())
    }

    /// The cell half of the release/deposit cross-product. It mutates nothing.
    ///
    /// `deletes` is the core's own answer, so the two halves cannot disagree
    /// about which release this is; `supplies_readiness` distinguishes the
    /// finishing release, which brings one, from the later last release, which
    /// must find the parked one.
    pub(crate) fn release_deposit_preflight(
        &self,
        locator: SessionLocator,
        deletes: bool,
        supplies_readiness: bool,
    ) -> Result<(), LifecycleError> {
        if self.generation != locator.generation() || self.identity != Some(locator.identity()) {
            return Err(LifecycleError::WrongLocator);
        }
        if !self.finalizer.deposit_is_none() {
            return Err(LifecycleError::Invariant);
        }
        if !self.fail_stop.is_empty() {
            return Err(LifecycleError::FinalizerBusy);
        }
        if self.finalizer.locator() != Some(locator)
            || !matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
        {
            return Err(LifecycleError::FinalizerBusy);
        }
        // Mount rollback releases an ordinary stable reference while the
        // generation remains Live. It cannot carry readiness or be the last
        // reference because the live cell still owns its registry lease and
        // control reference. This exact arm is the only non-Removing use of
        // the sole release/deposit boundary.
        if self.phase == NativeCellPhase::Live {
            return if !deletes && !supplies_readiness && self.checkpoint_readiness.is_none() {
                Ok(())
            } else {
                Err(LifecycleError::Invariant)
            };
        }
        if self.phase != NativeCellPhase::Removing {
            return Err(LifecycleError::WrongState);
        }
        match (
            deletes,
            supplies_readiness,
            self.checkpoint_readiness.is_some(),
        ) {
            // The finishing release deletes immediately and brings its own.
            (true, true, false) => Ok(()),
            // The later last release finds the parked one.
            (true, false, true) => Ok(()),
            // The finishing release parks its readiness for a later one.
            (false, true, false) => Ok(()),
            // An ordinary nonfinal release changes only the count.
            (false, false, _) => Ok(()),
            // Two readiness values, or none where one is required.
            _ => Err(LifecycleError::Invariant),
        }
    }

    /// Whether this generation's ledgers show every owner discharged.
    ///
    /// The claim "no other stable owner remains" is checked here rather than
    /// assumed by the roster: a cell that still holds a shell, root, control
    /// owner, readiness, or deposit has not discharged them, whatever the
    /// roster reported.
    pub(crate) fn checkpoint_ledger_is_discharged(&self, locator: SessionLocator) -> bool {
        self.generation == locator.generation()
            && self.identity == Some(locator.identity())
            && self.phase == NativeCellPhase::Removing
            && self.shell_owner.is_none()
            && self.root_release.is_none()
            && self.control_owner.is_none()
            && self.checkpoint_readiness.is_none()
            && self.finalizer.locator() == Some(locator)
            && self.finalizer.deposit_is_none()
            && self.fail_stop.is_empty()
            && matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
    }

    /// The cell half of the deletion cross-product, read without mutation.
    ///
    /// It answers every field the core decision needs, so the *order* of the
    /// checks lives in one place — `decide_delete_preflight` — instead of being
    /// re-derived by whichever native call site got there first.
    pub(crate) fn delete_preflight_observation(
        &self,
        locator: SessionLocator,
    ) -> fsring_core::adapter::fence::DeletePreflightObservation {
        let admitted_joiners = self.terminal_rendezvous.admitted_for_locator(locator);
        let outcome_is_open = matches!(
            self.terminal_rendezvous.outcome_for_locator(locator),
            Some(fsring_core::session::TerminalRendezvousOutcome::Open)
        );
        // SAFETY: the event is permanent initialized cell storage. The
        // registry lock is held by every caller of this observation.
        let outcome_event_is_nonsignaled = unsafe {
            fsring_sys::c4::KeReadStateEvent(
                core::ptr::addr_of!(self.terminal_outcome).cast_mut().cast(),
            ) == 0
        };
        fsring_core::adapter::fence::DeletePreflightObservation {
            // Only the deposit can authenticate the core delete right. The
            // caller overwrites this placeholder with that borrowed check.
            core_deleting_with_exact_right: false,
            mirror_matches_generation:
                fsring_core::adapter::lifecycle::native_delete_mirror_matches(
                    self.phase,
                    self.generation,
                    self.identity,
                    !self.session.is_null(),
                    locator,
                ),
            // The winner moved both owners into the readiness, so a cell still
            // holding either one is exactly the double-ownership this refuses.
            shell_and_root_owned_by_readiness: self.shell_owner.is_none()
                && self.root_release.is_none()
                && self.control_owner.is_none(),
            // Not observable from the cell: the binding and the completed
            // record live in the control context, which this generation now
            // reaches only through the readiness. Both start fail-closed and
            // the caller fills them from the `ClosingControlOwner` it owns.
            closing_live_context_and_lease: false,
            completed_record_absent: false,
            outcome_open_and_admission_open: outcome_is_open
                && outcome_event_is_nonsignaled
                && admitted_joiners > 0
                && admitted_joiners < u32::MAX,
            // The running finalizer took both slots out of the cell before it
            // preflighted; a cell still holding either would mean a second
            // callback could take it too.
            running_with_sole_authorities: matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Running
            ) && self.finalizer.locator() == Some(locator)
                && self.finalizer.deposit_is_none()
                && self.checkpoint_readiness.is_none()
                && self.fail_stop.is_empty(),
            admitted_joiners,
        }
    }

    /// Store one complete refusal packet before resolving its visibility.
    ///
    /// # Safety
    /// The registry lock is held and the packet belongs to this permanent cell.
    pub(crate) unsafe fn store_and_resolve_fail_stop(
        &mut self,
        packet: crate::fence::R3FailStopPacket,
    ) -> crate::fence::R3FailStopVisibility {
        let locator = packet.locator();
        // The locator's index selected this permanent cell. Mirror identity
        // and phase are deletion predicates, not storage authority: predicate
        // 2 must still store and quarantine its whole packet on mismatch.
        let commit_delete_fail_stop =
            packet.is_delete() && self.finalizer.fail_stop_preflight(locator);
        let visibility = unsafe {
            self.fail_stop.store_and_resolve(
                locator,
                &mut self.terminal_rendezvous,
                &mut self.finalizer,
                commit_delete_fail_stop,
                &self.terminal_outcome,
                packet,
            )
        };
        match visibility {
            Ok(visibility) => visibility,
            // The permanent slot was checked empty before the refusal path
            // entered this unchanged lock hold. The slot operation still
            // validates occupancy and returns the intact packet on mismatch.
            Err(packet) => crate::fence::R3FailStopVisibility::ReentryRetained(
                crate::fence::R3FailStopReentryGuard::retain(packet),
            ),
        }
    }

    /// Authenticate the occupied opaque slot and consume an exact counted
    /// admission. Foreign tickets and non-opaque observations are untouched.
    fn release_opaque_join(
        &mut self,
        receipt: &crate::fence::OpaqueFailStopReceipt,
        ticket: fsring_core::session::TerminalJoinTicket,
    ) -> Result<
        Option<fsring_core::session::TerminalJoinersDrainedSignal>,
        fsring_core::session::TerminalJoinTicket,
    > {
        let locator = receipt.locator();
        if !matches!(
            self.fail_stop.visibility_for_locator(locator),
            Some(crate::fence::R3FailStopObservation::OpaqueRetained)
        ) || self
            .terminal_rendezvous
            .opaque_retained_admitted_for_locator(locator)
            .is_none()
        {
            return Err(ticket);
        }
        self.terminal_rendezvous.release_opaque_retained(ticket)
    }

    fn authenticate_closed_fail_stop(
        &self,
        locator: SessionLocator,
    ) -> Option<crate::fence::ClosedFailStopAuthentication> {
        self.fail_stop.authenticate_closed_slot(locator)
    }

    /// Install this generation's pending runtime.
    ///
    /// The one caller is the locked publication suffix, between core
    /// preparation and the core commit that makes the session Live. A second
    /// install would orphan the first runtime's arena, so it is refused.
    ///
    /// # Safety
    /// The caller holds the enclosing registry lock and has already prepared
    /// the matching core publication for this exact cell.
    pub(crate) unsafe fn install_pending_runtime(
        &mut self,
        runtime: crate::pending_enter::PendingRuntimeReady,
    ) {
        if self.pending_runtime.is_some() {
            unreachable!("a staging cell has no runtime for a second install to replace")
        }
        self.pending_runtime = Some(runtime);
    }

    /// Borrow this generation's runtime for a checkpoint or unload walk.
    pub(crate) const fn pending_runtime(
        &self,
    ) -> Option<&crate::pending_enter::PendingRuntimeReady> {
        self.pending_runtime.as_ref()
    }

    /// Take the runtime out for release, once every context is drained.
    pub(crate) fn take_pending_runtime(
        &mut self,
    ) -> Option<crate::pending_enter::PendingRuntimeReady> {
        // The ledger goes with it: a runtime that is being freed can no longer
        // host an install, so a ledger left behind could only ever mint a link
        // right for storage that is about to be released.
        self.pending_ledger = None;
        self.pending_runtime.take()
    }

    /// Store the bound ledger the same publication produced.
    ///
    /// # Safety
    /// The caller holds the enclosing registry lock and has just committed this
    /// cell's core publication.
    pub(crate) unsafe fn install_pending_ledger(
        &mut self,
        ledger: fsring_core::session::PendingControlLedger<{ crate::session::MAX_PENDING_LINKS }>,
    ) {
        if self.pending_ledger.is_some() {
            unreachable!("a staging cell has no ledger for a second install to replace")
        }
        self.pending_ledger = Some(ledger);
    }

    /// Close pending admission, so no later ENTER can link a new install.
    ///
    /// Called by the checkpoint's `CloseSessionAdmission`, before any wake is
    /// deposited: a link admitted after the deposit would be a parked ENTER the
    /// fence never signalled.
    pub(crate) fn pending_ledger_mut(
        &mut self,
    ) -> Option<
        &mut fsring_core::session::PendingControlLedger<{ crate::session::MAX_PENDING_LINKS }>,
    > {
        self.pending_ledger.as_mut()
    }

    pub(crate) fn close_pending_admission(&mut self) {
        if let Some(ledger) = self.pending_ledger.as_mut() {
            ledger.close_admission();
        }
    }

    pub(crate) fn park_fence_retry(&mut self, parked: crate::fence::ParkedFenceResidual) {
        self.fence_retry_park = Some(parked);
    }

    pub(crate) fn fence_retry_timer_ptr(&mut self) -> *mut KTIMER {
        self.fence_retry_timer.as_mut_ptr()
    }

    pub(crate) fn fence_retry_dpc_ptr(&mut self) -> *mut KDPC {
        self.fence_retry_dpc.as_mut_ptr()
    }

    pub(crate) fn take_fence_retry_park(&mut self) -> Option<crate::fence::ParkedFenceResidual> {
        self.fence_retry_park.take()
    }

    pub(crate) fn fence_retry_registry(&self) -> NonNull<KernelSessionRegistry> {
        self.finalizer_context.registry
    }

    pub(crate) fn fence_retry_work_item(&self) -> PIO_WORKITEM {
        self.fence_retry_work_item
    }

    pub(crate) fn fence_retry_dpc_exit_ptr(&mut self) -> *mut KEVENT {
        self.fence_retry_dpc_exit.as_mut_ptr()
    }

    /// Park the readiness for the one later release that reaches zero.
    pub(crate) fn park_readiness(&mut self, readiness: crate::fence::FenceDeletionReadiness) {
        if self.checkpoint_readiness.is_some() {
            unreachable!("the release preflight proved the readiness slot empty")
        }
        self.checkpoint_readiness = Some(readiness);
    }

    pub(crate) fn take_parked_readiness(
        &mut self,
        locator: SessionLocator,
    ) -> Option<crate::fence::FenceDeletionReadiness> {
        match self.checkpoint_readiness.as_ref() {
            Some(readiness) if readiness.locator() == locator => self.checkpoint_readiness.take(),
            _ => None,
        }
    }

    /// Store the complete core deposit and transition Idle -> Queued before a
    /// queue capability can exist. The held registry lock is the sole caller.
    pub(crate) unsafe fn store_deposit_and_mint_kick(
        &mut self,
        readiness: crate::fence::FenceDeletionReadiness,
        right: fsring_core::session::DeleteSessionRight,
    ) -> Result<
        fsring_core::adapter::fence::R3FinalizerKick,
        (
            crate::fence::FenceDeletionReadiness,
            fsring_core::session::DeleteSessionRight,
        ),
    > {
        if self.phase != NativeCellPhase::Removing {
            return Err((readiness, right));
        }
        match self.finalizer.store_deposit_and_mint_kick(readiness, right) {
            Ok(kick) => {
                self.phase = NativeCellPhase::Deleting;
                Ok(kick)
            }
            Err(returned) => Err(returned),
        }
    }

    /// Infallible half of the release/deposit transition after
    /// `release_deposit_preflight` accepted this exact cell.
    ///
    /// # Safety
    /// The registry lock remains held and the complete release/deposit
    /// cross-product has not changed since its preflight.
    pub(crate) unsafe fn store_deposit_and_mint_kick_prevalidated(
        &mut self,
        readiness: crate::fence::FenceDeletionReadiness,
        right: fsring_core::session::DeleteSessionRight,
    ) -> fsring_core::adapter::fence::R3FinalizerKick {
        self.phase = NativeCellPhase::Deleting;
        unsafe {
            self.finalizer
                .store_deposit_and_mint_kick_prevalidated(readiness, right)
        }
    }

    pub(crate) fn mount_rendezvous(&self) -> &NativeMountRendezvous {
        &self.mount_rendezvous
    }

    pub(crate) fn mount_rendezvous_mut(&mut self) -> &mut NativeMountRendezvous {
        &mut self.mount_rendezvous
    }

    /// Mutation-free preflight for the mount owner's locked publication.
    pub(crate) fn prepare_mount_install(
        &self,
        locator: SessionLocator,
        reference: &StrongSessionRef,
        mounted: &NativeMountedDeviceOwner,
        vpb: &NativeMountedVpbOwner,
    ) -> Result<PreparedNativeMountInstall, LifecycleError> {
        if !self.matches_live_locator(locator) {
            return Err(LifecycleError::WrongState);
        }
        self.mount_rendezvous
            .prepare_install(locator, reference, mounted, vpb)
    }

    /// Commit a preflighted owner and reset only the two generation-completion
    /// events. Both drained events remain signalled while their waiter counts
    /// are zero.
    ///
    /// # Safety
    /// The registry lock is held and `prepared` came from this exact cell in
    /// the same hold.
    pub(crate) unsafe fn commit_prepared_mount_install(
        &mut self,
        prepared: PreparedNativeMountInstall,
        reference: StrongSessionRef,
        mounted: NativeMountedDeviceOwner,
        vpb: NativeMountedVpbOwner,
    ) -> NativeMountOwnerPublication {
        unsafe {
            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_complete));
            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_reset_complete));
        }
        unsafe {
            self.mount_rendezvous
                .commit_prepared_install(prepared, reference, mounted, vpb)
        }
    }

    /// Take one authentic mount claim and reset the drained event corresponding
    /// to any newly admitted waiter before the lock is released.
    pub(crate) unsafe fn take_or_join_mount(
        &mut self,
        expected: ExpectedMountTeardown,
    ) -> Result<MountClaim<NativeMountedDeviceOwner, NativeMountedVpbOwner>, LifecycleError> {
        let claim = self.mount_rendezvous.take_or_join(expected)?;
        unsafe {
            match &claim {
                MountClaim::Join { .. } => {
                    fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(
                        self.mount_waiters_drained
                    ));
                }
                MountClaim::ResetJoin { .. } => {
                    fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(
                        self.mount_reset_waiters_drained
                    ));
                }
                MountClaim::Owner { .. } | MountClaim::Absent { .. } => {}
            }
        }
        Ok(claim)
    }

    /// Convert an ordinary waiter into a reset waiter and close the reset-drain
    /// event in the same locked transition.
    pub(crate) unsafe fn release_mount_join(
        &mut self,
        ticket: MountJoinTicket,
    ) -> Result<MountJoinConversion, (LifecycleError, MountJoinTicket)> {
        let conversion = self.mount_rendezvous.release_join(ticket)?;
        unsafe {
            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_reset_waiters_drained));
        }
        Ok(conversion)
    }

    pub(crate) unsafe fn permanently_close_access(&mut self) {
        self.phase = NativeCellPhase::Retired;
        unsafe { fsring_sys::c4::ExRundownCompleted(core::ptr::addr_of_mut!(self.access)) };
    }

    /// This cell's locator, if it records exactly this process observation.
    ///
    /// The comparison is of the *recorded* observation, not of anything read
    /// through the shell: the whole point of the permanent cell is that a
    /// process scan never dereferences a session it has not resolved.
    fn process_locator(&self, process: PEPROCESS) -> Option<SessionLocator> {
        if self.process_loss_handled {
            return None;
        }
        // The rendezvous remains locator-branded after a winner moves the
        // shell/root/control owners out of the cell. Validate its nonowning
        // observation against the permanent cell identity/generation rather
        // than rebuilding authority from raw mirror fields.
        let published_locator = self
            .terminal_rendezvous
            .r3_locked_locator()
            .and_then(|locator| {
                (self.identity == Some(locator.identity())
                    && self.generation == locator.generation())
                .then_some(locator)
            });
        observe_cell_process(
            &NativeCellProcessObservation {
                recorded_process: NonNull::new(self.process),
                phase: self.phase,
                published_locator,
            },
            NonNull::new(process)?,
        )
    }

    fn mark_process_loss_handled(&mut self, locator: SessionLocator) -> bool {
        if self.process_loss_handled
            || self.identity != Some(locator.identity())
            || self.generation != locator.generation()
        {
            return false;
        }
        self.process_loss_handled = true;
        true
    }

    /// The authentic owners the locked publication suffix deposited.
    ///
    /// A Live cell without them, or with owners branded for another locator, is
    /// not resolvable: the shell the mirror names would then be one no owner
    /// vouches for.
    fn owners_match(&self, locator: SessionLocator) -> bool {
        native_owner_slots_match(
            locator,
            NativeOwnerSlotObservation {
                shell_locator: self.shell_owner.as_ref().map(NativeSessionOwner::locator),
                root_locator: self
                    .root_release
                    .as_ref()
                    .map(SessionRootReleaseRight::locator),
                shell_matches_mirror: self
                    .shell_owner
                    .as_ref()
                    .is_some_and(|shell| shell.matches_mirror(self.session)),
            },
        )
    }
}

/// Queue the preallocated finalizer work item for one exact cell.
///
/// The work item is the cell's own and is associated with the permanent
/// provider device, so queueing it cannot outlive the root. The deposit and the
/// Idle→Queued transition already happened together under the registry lock;
/// this is only the kick.
///
/// # Safety
/// `registry` is live, no lock is held, and the deposit for this generation is
/// stored with the worker already Queued.
pub(crate) unsafe fn queue_cell_finalizer(admitted: AdmittedR3FinalizerKick) {
    let (registry, admitted) = admitted.into_parts();
    let locator = admitted.locator();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    // SAFETY: the kick was minted only after an exact permanent cell stored
    // this generation's deposit. Every permanent cell receives its work item
    // and callback context before the registry is published.
    let cell = unsafe { lock.cell_ptr(locator.slot_index()).unwrap_unchecked() };
    unsafe {
        core::hint::assert_unchecked((*cell).finalizer.locator() == Some(locator));
        core::hint::assert_unchecked((*cell).finalizer_context.registry == registry);
        core::hint::assert_unchecked((*cell).finalizer_context.cell_index == locator.slot_index());
        core::hint::assert_unchecked((*cell).finalizer_context.queued.is_none());
        core::hint::assert_unchecked(!(*cell).finalizer_work_item.is_null());
        core::hint::assert_unchecked(admitted.admission().matches(registry, locator));
        core::hint::assert_unchecked((*cell).finalizer_callback_admitted.is_none());
    }
    fsring_core::adapter::fence::run_r3_finalizer_queue(
        admitted,
        |queued, admission| {
            // The rundown was acquired before the destructive release/deposit
            // commit; the core runner consumes the fused admitted kick before
            // parking its affine release authority beside Queued.
            unsafe { (*cell).finalizer_callback_admitted = Some(admission) };
            // The core runner minted this affine context from the exact kick;
            // publish it into the permanent native callback context before the
            // work item becomes visible to the I/O manager.
            unsafe {
                core::hint::assert_unchecked(queued.cell_index() == locator.slot_index());
                (*cell).finalizer_context.queued = Some(queued);
            }
            // SAFETY: `cell` names the permanent initialized cell selected
            // above. Releasing the lock publishes both admission and context.
            let queued_work = unsafe {
                (
                    (*cell).finalizer_work_item,
                    core::ptr::addr_of_mut!((*cell).finalizer_context).cast(),
                )
            };
            unsafe { lock.release() };
            queued_work
        },
        |(item, context)| unsafe {
            // SAFETY: the item was preallocated for the permanent provider
            // device and the worker state is Queued, so exactly one callback
            // receives the context just published by the first runner stage.
            fsring_sys::c4::IoQueueWorkItem(
                item,
                Some(fsring_finalizer_callback),
                fsring_sys::c4::DelayedWorkQueue,
                context,
            );
        },
    );
}

/// The PASSIVE finalizer callback.
///
/// # Safety
/// The I/O manager invokes this at PASSIVE_LEVEL for a queued work item.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fsring_finalizer_callback(
    _device: PDEVICE_OBJECT,
    context: *mut core::ffi::c_void,
) {
    // SAFETY: `queue_cell_finalizer` supplies the address of the permanent
    // context embedded in the exact cell whose work item invoked us.
    let context = unsafe { NonNull::new_unchecked(context.cast::<FinalizerWorkItemContext>()) };
    // SAFETY: this context is embedded in the permanent cell whose work item
    // invoked us; unload drains and frees every work item before the registry.
    let (registry, cell_index) = unsafe {
        let context = context.as_ref();
        (context.registry, context.cell_index)
    };
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let queued = unsafe {
        lock.cell_ptr(cell_index)
            .and_then(|cell| (*cell).finalizer_context.queued.take())
    };
    unsafe { lock.release() };
    let Some(queued) = queued else {
        unsafe { wait_blocked_unload_forever(registry) }
    };
    if queued.cell_index() != cell_index {
        unsafe { wait_blocked_unload_forever(registry) }
    }
    // SAFETY: the root outlives every work item it owns, and unload drains
    // them before freeing it. The permanent context preserves the exact cell
    // selected by the consumed kick, so the worker never scans for another.
    unsafe { crate::fence::run_queued_finalizer(registry, queued) };
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let admitted = unsafe {
        lock.cell_ptr(cell_index)
            .and_then(|cell| (*cell).finalizer_callback_admitted.take())
    };
    unsafe { lock.release() };
    let Some(admitted) = admitted else {
        unsafe { wait_blocked_unload_forever(registry) }
    };
    unsafe { admitted.release() };
}

impl NativeSessionCell {
    /// Take the deposit and become the running finalizer, together.
    ///
    /// One transition because they are one: a deposit taken without the
    /// Queued→Running move lets a second callback take it too, and the move
    /// without the deposit is a runner with nothing to run.
    pub(crate) fn take_deposit_and_run_for_callback(
        &mut self,
        cell_index: u32,
        context: fsring_core::adapter::fence::R3FinalizerCallbackContext,
    ) -> Option<(
        crate::fence::FinalizerDeposit,
        fsring_core::adapter::fence::R3FinalizerRunningRight,
        FinalizerHandoffRight,
    )> {
        let (deposit, running) =
            fsring_core::adapter::fence::run_r3_finalizer_callback(context, |embedded_index| {
                if embedded_index != cell_index {
                    return None;
                }
                Some(&mut self.finalizer)
            })?;
        let locator = running.locator();
        debug_assert_eq!(deposit.locator(), locator);
        Some((deposit, running, FinalizerHandoffRight { locator }))
    }

    /// The generation-specific outcome and drained events.
    pub(crate) fn terminal_outcome_event(&mut self) -> *mut KEVENT {
        core::ptr::addr_of_mut!(self.terminal_outcome)
    }

    pub(crate) fn joiners_drained_event(&mut self) -> *mut KEVENT {
        core::ptr::addr_of_mut!(self.joiners_drained)
    }

    pub(crate) fn visibility_resolution_event(&mut self) -> *mut KEVENT {
        core::ptr::addr_of_mut!(self.visibility_resolution)
    }

    pub(crate) fn store_ordinary_finalizer_handoff(
        &mut self,
        right: FinalizerHandoffRight,
    ) -> Result<(), FinalizerHandoffRight> {
        if self.finalizer_handoff.is_some() {
            return Err(right);
        }
        self.finalizer_handoff = Some(FinalizerVisibilityHandoff::Ordinary(right));
        Ok(())
    }

    pub(crate) fn store_opaque_finalizer_handoff(
        &mut self,
        right: FinalizerHandoffRight,
        receipt: crate::fence::OpaqueFailStopReceipt,
    ) -> Result<(), (FinalizerHandoffRight, crate::fence::OpaqueFailStopReceipt)> {
        if self.finalizer_handoff.is_some() {
            return Err((right, receipt));
        }
        self.finalizer_handoff = Some(FinalizerVisibilityHandoff::Opaque { right, receipt });
        Ok(())
    }

    fn take_finalizer_handoff(&mut self) -> Option<FinalizerVisibilityHandoff> {
        self.finalizer_handoff.take()
    }

    /// Reset the two terminal-generation events before admission opens.
    ///
    /// # Safety
    /// The registry lock is held, the cell is Staging, and no arrival can yet
    /// observe this generation.
    pub(crate) unsafe fn clear_terminal_generation_events(&mut self) {
        unsafe {
            fsring_sys::c4::KeClearEvent(self.terminal_outcome_event());
            fsring_sys::c4::KeClearEvent(self.joiners_drained_event());
            fsring_sys::c4::KeClearEvent(self.visibility_resolution_event());
        }
        self.finalizer_handoff = None;
    }

    /// Clear every generation-specific observation in one commit.
    ///
    /// Before it, process and unload see the intact Deleting generation; after
    /// it, only the complete Free or Retired successor. There is no state in
    /// between that either can observe.
    pub(crate) unsafe fn reset_after_delete(
        &mut self,
        core: &mut SessionRegistry<SESSION_CELL_COUNT>,
        pending: fsring_core::adapter::fence::PendingFinalDeleteReset<
            crate::fence::PreparedCellResetRight,
        >,
    ) -> (
        fsring_core::session::SlotDisposition,
        fsring_core::adapter::fence::FinalDeleteProof,
    ) {
        let (disposition, proof, cell_reset, terminal_reset, mount_reset) =
            unsafe { self.finalizer.finish_run_and_reset(core, pending) };
        cell_reset.consume();
        unsafe {
            self.terminal_rendezvous
                .deactivate_after_delete_prepared(terminal_reset)
        };
        unsafe {
            self.mount_rendezvous
                .deactivate_after_delete_prepared(mount_reset)
        };
        // Every terminal/mount ticket and waiter was consumed by the prepared
        // reset inputs above. Clear stale NotificationEvent state now, while
        // the old generation is still exclusively locked, so effect nine can
        // distinguish quiescent reusable storage from a live pending signal.
        unsafe {
            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.terminal_outcome));
            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_complete));
            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_reset_complete));
        }
        self.identity = None;
        self.session = core::ptr::null_mut();
        self.process = core::ptr::null_mut();
        self.process_loss_handled = false;
        self.registry_lease = None;
        self.control_owner = None;
        self.shell_owner = None;
        self.root_release = None;
        self.checkpoint_readiness = None;
        self.phase = match disposition {
            fsring_core::session::SlotDisposition::Free => NativeCellPhase::Free,
            // A generation that cannot be incremented is retired, and its
            // access rundown stays permanently closed.
            fsring_core::session::SlotDisposition::Retired => NativeCellPhase::Retired,
        };
        (disposition, proof)
    }

    /// Complete the access rundown after every counted arrival drains.
    ///
    /// # Safety
    /// Every counted arrival has drained and no resolver can be inside.
    pub(crate) unsafe fn complete_access_rundown(&mut self) {
        // SAFETY: the caller's contract.
        unsafe { fsring_sys::c4::ExRundownCompleted(core::ptr::addr_of_mut!(self.access)) };
    }

    /// Reopen a completed rundown for a reusable successor generation.
    ///
    /// # Safety
    /// The rundown is completed and no resolver is inside it.
    pub(crate) unsafe fn reinitialize_access_rundown(&mut self) {
        unsafe {
            fsring_sys::c4::ExReInitializeRundownProtection(core::ptr::addr_of_mut!(self.access))
        };
    }
}

/// Signal this generation's terminal-outcome event, after the lock is dropped.
///
/// # Safety
/// `registry` is live and no registry lock is held.
pub(crate) unsafe fn signal_terminal_outcome(
    registry: NonNull<KernelSessionRegistry>,
    signal: fsring_core::session::TerminalOutcomeSignal,
) {
    let locator = signal.into_locator();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let (visibility, outcome) = unsafe {
        let cell = lock.cell_mut_prevalidated(locator.slot_index());
        (
            cell.visibility_resolution_event(),
            cell.terminal_outcome_event(),
        )
    };
    unsafe { lock.release() };
    // SAFETY: signalled outside the lock, which is what stops a woken arrival
    // from blocking on the lock its waker holds. Visibility precedes the
    // ordinary outcome wake, and both are broadcast notification events.
    unsafe {
        fsring_sys::c4::KeSetEvent(visibility, 0, 0 as fsring_sys::BOOLEAN);
        fsring_sys::c4::KeSetEvent(outcome, 0, 0 as fsring_sys::BOOLEAN);
    }
}

/// Signal that the last counted terminal arrival released, after the registry
/// lock used for that release has been dropped.
///
/// # Safety
/// `signal` was minted by the exact permanent rendezvous and `registry` stays
/// live for the duration of the callback/waiter protocol.
pub(crate) unsafe fn signal_joiners_drained(
    registry: NonNull<KernelSessionRegistry>,
    signal: fsring_core::session::TerminalJoinersDrainedSignal,
) {
    let locator = signal.into_locator();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let event = unsafe {
        lock.cell_mut_prevalidated(locator.slot_index())
            .joiners_drained_event()
    };
    unsafe { lock.release() };
    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };
}

/// Wait until every counted arrival has released.
///
/// # Safety
/// PASSIVE_LEVEL, no registry lock and no short guard held.
pub(crate) unsafe fn wait_joiners_drained(
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
) {
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let event = unsafe {
        lock.cell_mut_prevalidated(locator.slot_index())
            .joiners_drained_event()
    };
    unsafe { lock.release() };
    // SAFETY: the wait happens with no lock held, which is the whole reason
    // the pointer was taken out of the hold first.
    unsafe {
        let _ = fsring_sys::c4::KeWaitForSingleObject(event.cast(), 0, 0, 0, core::ptr::null_mut());
    }
}

/// Complete this cell's access rundown.
///
/// # Safety
/// Every counted arrival has drained and no resolver can be inside.
pub(crate) unsafe fn complete_cell_access_rundown(
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
) {
    let lock = unsafe { KernelSessionRegistry::lock(registry) };
    // The permanent rundown address remains valid after unlock. Selecting it
    // under the lock binds this effect to the exact deleting generation, while
    // invoking the DDI afterwards keeps its IRQL at PASSIVE_LEVEL.
    let rundown = unsafe {
        lock.registry
            .as_ref()
            .access_rundown_ptr(locator.slot_index())
            .unwrap_unchecked()
    };
    unsafe { lock.release() };
    unsafe { fsring_sys::c4::ExRundownCompleted(rundown) };
}

/// Reinitialize one already-completed reusable cell access rundown.
///
/// # Safety
/// The prior plan step completed this rundown and no resolver is inside it.
pub(crate) unsafe fn reinitialize_cell_access_rundown(
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
) {
    let lock = unsafe { KernelSessionRegistry::lock(registry) };
    let rundown = unsafe {
        lock.registry
            .as_ref()
            .access_rundown_ptr(locator.slot_index())
            .unwrap_unchecked()
    };
    unsafe { lock.release() };
    unsafe { fsring_sys::c4::ExReInitializeRundownProtection(rundown) };
}

/// Consume the bundled final cursor and publish core/native disposition in one
/// registry-lock hold.
///
/// # Safety
/// The full infallible suffix precedes this call. The cursor contains the
/// post-storage commit, running-callback proof, native reset authority, and
/// exact final plan position as one non-cross-wireable value.
pub(crate) unsafe fn reset_cell_and_publish(
    registry: NonNull<KernelSessionRegistry>,
    pending: fsring_core::adapter::fence::PendingFinalDeleteReset<
        crate::fence::PreparedCellResetRight,
    >,
) -> fsring_core::adapter::fence::FinalDeleteProof {
    let locator = pending.locator();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let core = unsafe { lock.core_ptr() };
    let cell = unsafe { lock.cell_mut_prevalidated(locator.slot_index()) };
    // SAFETY: the lock is held; core and cell are disjoint fields of the root.
    let (_disposition, proof) = unsafe { cell.reset_after_delete(&mut *core, pending) };
    unsafe { lock.release() };
    proof
}

// ---------------------------------------------------------------------------
// Mount signal-then-acknowledge helpers
// ---------------------------------------------------------------------------
//
// Mount signalling is one narrow exception to the usual signal-after-unlock
// rule. `KeSetEvent(..., Wait = FALSE)` is nonblocking and valid through
// DISPATCH_LEVEL, so each helper sets its permanent notification event and
// immediately consumes the core acknowledgement in the same registry lock
// hold. A waiter may wake, but it cannot acquire this lock and observe the
// signal-pending bit before the helper clears it.
//
// So there are exactly four helpers, each owning one whole window. They are the
// only fsd callers of the four distinct fused core
// `run_r3_mount_*_signal_ack` runners.

/// Which permanent-cell event a mount signal names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountCellEvent {
    Complete,
    WaitersDrained,
    ResetComplete,
    ResetWaitersDrained,
}

const fn observed_mount_event(event: MountWaitEvent) -> MountCellEvent {
    match event {
        MountWaitEvent::Complete => MountCellEvent::Complete,
        MountWaitEvent::OrdinaryWaitersDrained => MountCellEvent::WaitersDrained,
        MountWaitEvent::ResetComplete => MountCellEvent::ResetComplete,
        MountWaitEvent::ResetWaitersDrained => MountCellEvent::ResetWaitersDrained,
    }
}

/// Address the named event inside one permanent cell.
///
/// The selection is a value rather than four copies of the same pointer
/// arithmetic: a helper that signalled the wrong event would wake the wrong
/// waiters and still return a well-typed acknowledgement.
const fn mount_event_ptr(cell: *mut NativeSessionCell, event: MountCellEvent) -> *mut KEVENT {
    // This is address arithmetic on a permanent cell, not a dereference.
    unsafe {
        match event {
            MountCellEvent::Complete => core::ptr::addr_of_mut!((*cell).mount_complete),
            MountCellEvent::WaitersDrained => {
                core::ptr::addr_of_mut!((*cell).mount_waiters_drained)
            }
            MountCellEvent::ResetComplete => {
                core::ptr::addr_of_mut!((*cell).mount_reset_complete)
            }
            MountCellEvent::ResetWaitersDrained => {
                core::ptr::addr_of_mut!((*cell).mount_reset_waiters_drained)
            }
        }
    }
}

/// Signal one prevalidated cell event exactly once inside the fused registry
/// lock hold.
///
/// # Safety
/// `event` came from `PreparedLockedMountPublication` while its registry-lock
/// borrow remains live. `Wait = FALSE` makes this DDI valid and nonblocking at
/// DISPATCH_LEVEL.
unsafe fn set_prepared_mount_event(event: NonNull<KEVENT>) {
    // SAFETY: the caller's contract; the event was initialized by the cell
    // initialization plan before any generation could be published.
    unsafe {
        fsring_sys::c4::KeSetEvent(event.as_ptr(), 0, 0 as fsring_sys::BOOLEAN);
    }
}

/// Wait for the exact permanent-cell event named by an affine core authority.
///
/// The observation carries no continuation power: callers retain the ticket,
/// drain right, or proof across this wait and consume it only in the following
/// locked transition.
///
/// # Safety
/// PASSIVE_LEVEL with no registry or VPB lock held. `registry` is the live
/// permanent root for `observation.locator()`.
pub(crate) unsafe fn wait_mount_observation(
    registry: NonNull<KernelSessionRegistry>,
    observation: MountWaitObservation,
) -> bool {
    let locator = observation.locator();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let event = match unsafe { lock.cell_ptr(locator.slot_index()) } {
        Some(cell)
            if unsafe {
                (*cell).generation == locator.generation()
                    && (*cell).identity == Some(locator.identity())
                    && (*cell)
                        .mount_rendezvous()
                        .matches_wait_observation(&observation)
            } =>
        {
            mount_event_ptr(cell, observed_mount_event(observation.event()))
        }
        _ => {
            unsafe { lock.release() };
            return false;
        }
    };
    unsafe { lock.release() };
    unsafe {
        let _ = fsring_sys::c4::KeWaitForSingleObject(event.cast(), 0, 0, 0, core::ptr::null_mut());
    }
    true
}

/// Package one exact affine bundle with the only cell/event its typed core
/// observation authenticates.
///
/// Every refusal returns the unchanged bundle. The observation is copy-only;
/// storing the bundle beside the guard borrow is what prevents a caller from
/// validating publication A and signalling same-kind publication B.
///
/// # Safety
/// `lock` is held for the live permanent registry that owns the bundle's cell.
trait LockedMountPublicationBundle {
    type Kind: MountPublicationKind;

    fn publication_observation(&self) -> MountPublicationObservation<Self::Kind>;
}

impl LockedMountPublicationBundle for MountDonePublication {
    type Kind = fsring_core::adapter::lifecycle::MountDonePublicationKind;

    fn publication_observation(&self) -> MountPublicationObservation<Self::Kind> {
        MountDonePublication::publication_observation(self)
    }
}

impl LockedMountPublicationBundle for MountJoinConversion {
    type Kind = fsring_core::adapter::lifecycle::MountJoinConversionKind;

    fn publication_observation(&self) -> MountPublicationObservation<Self::Kind> {
        MountJoinConversion::publication_observation(self)
    }
}

impl LockedMountPublicationBundle for MountResetPublication {
    type Kind = fsring_core::adapter::lifecycle::MountResetPublicationKind;

    fn publication_observation(&self) -> MountPublicationObservation<Self::Kind> {
        MountResetPublication::publication_observation(self)
    }
}

impl LockedMountPublicationBundle for MountResetJoinRelease {
    type Kind = fsring_core::adapter::lifecycle::MountResetJoinReleaseKind;

    fn publication_observation(&self) -> MountPublicationObservation<Self::Kind> {
        MountResetJoinRelease::publication_observation(self)
    }
}

// The Task 12 grammar freezes this header. Eliding the same lifetime in
// core was tried and reverted: it is a SHAPE change, and the grammar
// caught it.
#[allow(clippy::needless_lifetimes)]
unsafe fn prepare_locked_mount_publication<'lock, Bundle>(
    lock: &'lock mut RegistryLockGuard,
    bundle: Bundle,
) -> Result<PreparedLockedMountPublication<'lock, Bundle>, (LifecycleError, Bundle)>
where
    Bundle: LockedMountPublicationBundle,
{
    // This private sealed trait derives the observation from the exact bundle
    // that will be stored below; there is no second observation argument where
    // a same-kind publication could be substituted.
    let observation = bundle.publication_observation();
    let locator = observation.locator();
    let cell = match unsafe { lock.cell_ptr(locator.slot_index()) } {
        Some(cell) => cell,
        None => return Err((LifecycleError::WrongLocator, bundle)),
    };
    let matches = unsafe {
        (*cell).generation == locator.generation()
            && (*cell).identity == Some(locator.identity())
            && (*cell)
                .mount_rendezvous()
                .matches_publication_observation(&observation)
    };
    if !matches {
        return Err((LifecycleError::AdmissionClosed, bundle));
    }
    let event = observation.event().map(|event| {
        // The permanent cell owns initialized storage for every event kind.
        unsafe { NonNull::new_unchecked(mount_event_ptr(cell, observed_mount_event(event))) }
    });
    Ok(PreparedLockedMountPublication {
        lock,
        // The fixed cell array is permanent for the registry lifetime.
        cell: unsafe { NonNull::new_unchecked(cell) },
        event,
        bundle,
    })
}

impl RegistryLockGuard {
    /// Consume an exact Done publication into its guard-borrowed native
    /// publication aggregate.
    // Every refusal returns the affine owners it was handed, which is the
    // property proving nothing was consumed on the refused path; boxing it
    // would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub(crate) unsafe fn prepare_locked_mount_done_publication(
        &mut self,
        publication: MountDonePublication,
    ) -> Result<
        PreparedLockedMountPublication<'_, MountDonePublication>,
        (LifecycleError, MountDonePublication),
    > {
        unsafe { prepare_locked_mount_publication(self, publication) }
    }

    /// As above, preserving the typed `None` observation of a nonlast ordinary
    /// waiter without inventing an event.
    // Every refusal returns the affine owners it was handed, which is the
    // property proving nothing was consumed on the refused path; boxing it
    // would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub(crate) unsafe fn prepare_locked_mount_join_conversion(
        &mut self,
        conversion: MountJoinConversion,
    ) -> Result<
        PreparedLockedMountPublication<'_, MountJoinConversion>,
        (LifecycleError, MountJoinConversion),
    > {
        unsafe { prepare_locked_mount_publication(self, conversion) }
    }

    // Every refusal returns the affine owners it was handed, which is the
    // property proving nothing was consumed on the refused path; boxing it
    // would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub(crate) unsafe fn prepare_locked_mount_reset_publication(
        &mut self,
        publication: MountResetPublication,
    ) -> Result<
        PreparedLockedMountPublication<'_, MountResetPublication>,
        (LifecycleError, MountResetPublication),
    > {
        unsafe { prepare_locked_mount_publication(self, publication) }
    }

    /// As above, preserving the typed `None` observation of a nonlast reset
    /// waiter without inventing an event.
    // Every refusal returns the affine owners it was handed, which is the
    // property proving nothing was consumed on the refused path; boxing it
    // would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub(crate) unsafe fn prepare_locked_mount_reset_join_release(
        &mut self,
        release: MountResetJoinRelease,
    ) -> Result<
        PreparedLockedMountPublication<'_, MountResetJoinRelease>,
        (LifecycleError, MountResetJoinRelease),
    > {
        unsafe { prepare_locked_mount_publication(self, release) }
    }
}

/// # Safety
/// `prepared` owns the exact publication and borrows its prevalidated registry
/// lock through the fused signal and acknowledgement.
pub(crate) unsafe fn publish_mount_complete_locked(
    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,
) -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {
    let PreparedLockedMountPublication {
        lock: _lock,
        cell,
        event,
        bundle: publication,
    } = prepared;
    unsafe {
        (*cell.as_ptr())
            .mount_rendezvous_mut()
            .run_done_signal_ack(publication, |_| {
                let Some(event) = event else {
                    core::hint::unreachable_unchecked()
                };
                set_prepared_mount_event(event);
            })
    }
}

/// # Safety
/// As above, for the ordinary-waiters-drained window.
pub(crate) unsafe fn publish_mount_waiters_drained_locked(
    prepared: PreparedLockedMountPublication<'_, MountJoinConversion>,
) -> Result<MountResetJoinTicket, (LifecycleError, MountJoinAcknowledgement)> {
    let PreparedLockedMountPublication {
        lock: _lock,
        cell,
        event,
        bundle: conversion,
    } = prepared;
    // The callback fires only for the last ordinary waiter; the conversion
    // decides that, not this helper.
    unsafe {
        (*cell.as_ptr())
            .mount_rendezvous_mut()
            .run_ordinary_drained_signal_ack(conversion, |_| {
                let Some(event) = event else {
                    core::hint::unreachable_unchecked()
                };
                set_prepared_mount_event(event);
            })
    }
}

/// # Safety
/// As above, for the reset-complete window.
pub(crate) unsafe fn publish_mount_reset_complete_locked(
    prepared: PreparedLockedMountPublication<'_, MountResetPublication>,
) -> Result<MountResetProof, (LifecycleError, MountResetAcknowledgement)> {
    let PreparedLockedMountPublication {
        lock: _lock,
        cell,
        event,
        bundle: publication,
    } = prepared;
    unsafe {
        (*cell.as_ptr())
            .mount_rendezvous_mut()
            .run_reset_complete_signal_ack(publication, |_| {
                let Some(event) = event else {
                    core::hint::unreachable_unchecked()
                };
                set_prepared_mount_event(event);
            })
    }
}

/// # Safety
/// As above, for the reset-waiters-drained window. The last release keeps reuse
/// closed for the whole of it.
pub(crate) unsafe fn publish_mount_reset_waiters_drained_locked(
    prepared: PreparedLockedMountPublication<'_, MountResetJoinRelease>,
) -> Result<JoinedMountResetProof, (LifecycleError, MountResetJoinAcknowledgement)> {
    let PreparedLockedMountPublication {
        lock: _lock,
        cell,
        event,
        bundle: release,
    } = prepared;
    unsafe {
        (*cell.as_ptr())
            .mount_rendezvous_mut()
            .run_reset_waiters_drained_signal_ack(release, |_| {
                let Some(event) = event else {
                    core::hint::unreachable_unchecked()
                };
                set_prepared_mount_event(event);
            })
    }
}

// ---------------------------------------------------------------------------
// Checked locator resolution
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionAccessError {
    RundownRefused,
    StaleLocator,
    WrongRing,
}

impl SessionAccessError {
    pub(crate) const fn status(self) -> NTSTATUS {
        match self {
            Self::RundownRefused => wdk_sys::STATUS_DELETE_PENDING,
            Self::StaleLocator | Self::WrongRing => STATUS_INVALID_PARAMETER,
        }
    }

    const fn from_rejection(rejection: ResolveRejection) -> Self {
        match rejection {
            ResolveRejection::RundownRefused => Self::RundownRefused,
            ResolveRejection::OutOfRange
            | ResolveRejection::NotLive
            | ResolveRejection::StaleCell
            | ResolveRejection::MissingOwners => Self::StaleLocator,
        }
    }
}

/// A resolved, still-live session.
///
/// The guard *is* the lifetime: it holds the cell's access rundown from before
/// the pointer was read until `Drop`, which is what
/// effect-nine preflight proves drained before the root frees
/// the cells. It is neither `Clone` nor `Copy`, never yields `&NativeSession`,
/// and has no constructor outside [`KernelSessionRegistry::resolve`]. It is
/// *not* free of addresses internally: field-specific native operations still
/// project the shell while the guard is live, but no raw shell getter lets that
/// address escape the operation boundary.
///
/// `registry` is a raw pointer with a `PhantomData` lifetime rather than a
/// `&'registry KernelSessionRegistry`. A live shared reference here would
/// overlap, for the guard's whole lifetime, every `&mut` a concurrent
/// `RegistryLockGuard` forms over the same storage — an alias the compiler is
/// entitled to assume away. The `PhantomData` keeps the borrow-checker
/// lifetime; only `Drop` dereferences the pointer, and only to release the one
/// rundown reference this guard owns.
pub(crate) struct SessionAccessGuard<'registry> {
    registry: *const KernelSessionRegistry,
    slot_index: u32,
    locator: SessionLocator,
    session: SharedSessionProjection<'registry, NativeSession>,
}

/// One ring's state, held under that ring's own spin lock.
///
/// The plan sketched this as a raw `NonNull<NativeRingSlot>`; a shared
/// reference borrowed from the access guard carries the same slot with the
/// no-escape rule expressed in the type instead of in a comment.
pub(crate) struct NativeRingGuard<'access, 'registry> {
    access: &'access SessionAccessGuard<'registry>,
    ring_index: u32,
    slot: &'access crate::session::NativeRingSlot,
    old_irql: Option<SavedIrql<KIRQL>>,
}

impl KernelSessionRegistry {
    /// The one address of a cell's access rundown.
    ///
    /// Cells are permanent storage inside the root, so this needs no lock: the
    /// rundown object itself is what serializes acquire against the drain.
    /// The permanent access-rundown object for one cell.
    ///
    /// It is the cell's own storage and outlives every generation, so the
    /// pointer stays valid after the registry lock is dropped — which the
    /// checkpoint roster's blocking wait requires. This is production code
    /// the resolver already uses; the checkpoint executor shares it rather
    /// than adding a second helper with the same name.
    pub(crate) fn access_rundown_ptr(&self, slot_index: u32) -> Option<*mut EX_RUNDOWN_REF> {
        let index = usize::try_from(slot_index).ok()?;
        let cell = self.cells.get(index)?;
        // SAFETY: the cell is permanent, initialized before any dispatch can
        // run, and `access` is only ever touched through the rundown DDIs.
        Some(unsafe { core::ptr::addr_of_mut!((*cell.get()).access) })
    }

    /// Resolve a locator into a guarded session, or refuse without a trace.
    ///
    /// The step order is not written here: it is
    /// [`fsring_core::adapter::lifecycle::ResolvePlan`], the same closed model
    /// the host tests drive, and this function performs exactly the step the
    /// plan hands it. The unwind after a refusal is likewise the model's, so
    /// the five refusal points cannot each grow their own release.
    ///
    /// # Safety
    /// Runs at or below APC_LEVEL -- the rundown DDIs' own ceiling -- with
    /// `self` the live permanent registry, i.e. inside a dispatch or callback
    /// the root has not finished tearing down. No caller-held rundown is
    /// required: the reference this takes on the cell's own access rundown is
    /// what keeps the cell and the shell alive afterwards, and it is the same
    /// object effect-nine preflight proves drained. MOUNT arrives with no control
    /// file, and therefore no file rundown at all.
    pub(crate) unsafe fn resolve(
        &self,
        locator: SessionLocator,
    ) -> Result<SessionAccessGuard<'_>, SessionAccessError> {
        let slot_index = locator.slot_index();
        let mut rundown: Option<*mut EX_RUNDOWN_REF> = None;
        let mut lock: Option<RegistryLockGuard> = None;
        let mut session: Option<SharedSessionProjection<'_, NativeSession>> = None;
        let mut progress = ResolvePlan::begin();
        loop {
            let pending = match progress {
                ResolveProgress::Step(pending) => pending,
                ResolveProgress::Resolved(_) => {
                    let Some(session) = session else {
                        // Unreachable: the projection step is what completes the
                        // walk. The rundown is still held here and the lock is
                        // not, so this releases exactly the one thing it owns.
                        if let Some(held) = rundown.take() {
                            // SAFETY: acquired once by this frame.
                            unsafe { fsring_sys::c4::ExReleaseRundownProtection(held.cast()) };
                        }
                        return Err(SessionAccessError::StaleLocator);
                    };
                    return Ok(SessionAccessGuard {
                        registry: core::ptr::from_ref(self),
                        slot_index,
                        locator,
                        session,
                    });
                }
                ResolveProgress::Refused(refusal) => {
                    if refusal.releases_lock() {
                        if let Some(held) = lock.take() {
                            // SAFETY: this frame took the lock and releases it
                            // once, at the IRQL the acquire returned.
                            unsafe { held.release() };
                        }
                    }
                    if refusal.releases_rundown() {
                        if let Some(held) = rundown.take() {
                            // SAFETY: this frame acquired exactly one rundown
                            // reference on that cell and releases it once.
                            unsafe { fsring_sys::c4::ExReleaseRundownProtection(held.cast()) };
                        }
                    }
                    return Err(SessionAccessError::from_rejection(refusal.reason()));
                }
            };
            progress = match pending.step() {
                ResolveStep::BoundsCheckLocator => match self.access_rundown_ptr(slot_index) {
                    Some(_) => pending.succeeded(),
                    None => pending.refused(ResolveRejection::OutOfRange),
                },
                ResolveStep::AcquireAccessRundown => {
                    let Some(target) = self.access_rundown_ptr(slot_index) else {
                        // Unreachable: the bounds check just resolved it. Routed
                        // through the model anyway, because a bare `return` here
                        // would skip the unwind below.
                        progress = pending.refused(ResolveRejection::OutOfRange);
                        continue;
                    };
                    // SAFETY: the cell's rundown is permanently initialized.
                    let acquired =
                        unsafe { fsring_sys::c4::ExAcquireRundownProtection(target.cast()) };
                    if acquired == 0 {
                        pending.refused(ResolveRejection::RundownRefused)
                    } else {
                        rundown = Some(target);
                        pending.succeeded()
                    }
                }
                ResolveStep::AcquireRegistryLock => {
                    // SAFETY: `self` is the live permanent registry.
                    let held =
                        unsafe { Self::lock(NonNull::from(self).cast::<KernelSessionRegistry>()) };
                    lock = Some(held);
                    pending.succeeded()
                }
                ResolveStep::ValidateCoreLive => {
                    let Some(held) = lock.as_mut() else {
                        // Unreachable: the lock step precedes every one of
                        // these. Routed through the model so the unwind that
                        // releases the rundown still runs.
                        progress = pending.refused(ResolveRejection::StaleCell);
                        continue;
                    };
                    // SAFETY: the lock is held, and this borrow ends here.
                    let core = unsafe { held.core_mut() };
                    match core.validate_live(locator) {
                        Ok(()) => pending.succeeded(),
                        Err(_) => pending.refused(ResolveRejection::NotLive),
                    }
                }
                ResolveStep::ValidateCellIdentity => {
                    let Some(held) = lock.as_mut() else {
                        // Unreachable: the lock step precedes every one of
                        // these. Routed through the model so the unwind that
                        // releases the rundown still runs.
                        progress = pending.refused(ResolveRejection::StaleCell);
                        continue;
                    };
                    // SAFETY: the lock is held.
                    match unsafe { held.cell_mut(slot_index) } {
                        Some(cell) if cell.matches_live_locator(locator) => pending.succeeded(),
                        Some(_) | None => pending.refused(ResolveRejection::StaleCell),
                    }
                }
                ResolveStep::ValidateNativeOwnerSlots => {
                    let Some(held) = lock.as_mut() else {
                        // Unreachable: the lock step precedes every one of
                        // these. Routed through the model so the unwind that
                        // releases the rundown still runs.
                        progress = pending.refused(ResolveRejection::StaleCell);
                        continue;
                    };
                    // SAFETY: the lock is held.
                    match unsafe { held.cell_mut(slot_index) } {
                        Some(cell) if cell.owners_match(locator) => pending.succeeded(),
                        Some(_) | None => pending.refused(ResolveRejection::MissingOwners),
                    }
                }
                ResolveStep::ProjectSessionPointer => {
                    let Some(held) = lock.as_mut() else {
                        // Unreachable: the lock step precedes every one of
                        // these. Routed through the model so the unwind that
                        // releases the rundown still runs.
                        progress = pending.refused(ResolveRejection::StaleCell);
                        continue;
                    };
                    // SAFETY: access rundown is owned, this lock is held, and
                    // the three validation steps above all succeeded for this
                    // exact locator.
                    let projected = unsafe { held.project_resolved_session(slot_index, locator) };
                    match projected {
                        Some(pointer) => {
                            session = Some(pointer);
                            pending.succeeded()
                        }
                        None => pending.refused(ResolveRejection::StaleCell),
                    }
                }
                ResolveStep::ReleaseRegistryLock => {
                    if let Some(held) = lock.take() {
                        // SAFETY: this frame took the lock and releases it once.
                        unsafe { held.release() };
                    }
                    pending.succeeded()
                }
            };
        }
    }
}

pub(crate) enum ProcessScanAction {
    Winner {
        context: NonNull<ControlFileContext>,
        disposition: TerminalDisposition,
    },
    Join(TerminalJoinGuard),
    Completed(TerminalResult),
    Blocked(fsring_core::session::TerminalBlocked),
    Opaque(crate::fence::OpaqueFailStopReceipt),
}

/// One fully authenticated process-loss action awaiting the single locked
/// take-once marker commit. Construction is private to the scanner, so every
/// successful matrix arm consumes the marker through the same function and no
/// sibling can mark a generation without also carrying its action.
struct PreparedProcessScanAction {
    cell: NonNull<NativeSessionCell>,
    locator: SessionLocator,
    action: ProcessScanAction,
}

impl PreparedProcessScanAction {
    /// # Safety
    /// The registry lock is held and preparation authenticated `cell` and
    /// `locator` in this unchanged hold.
    unsafe fn commit(self) -> ProcessScanAction {
        let Self {
            mut cell,
            locator,
            action,
        } = self;
        let marked = unsafe { cell.as_mut().mark_process_loss_handled(locator) };
        // Every fallible cell/action check precedes this commit. A false result
        // would mean the same locked generation changed without releasing the
        // registry lock.
        unsafe { core::hint::assert_unchecked(marked) };
        action
    }
}

pub(crate) enum ProcessScanStep {
    Skip { resume_at: Option<u32> },
    Action(ProcessScanAction),
    FailStop,
    Complete,
}

pub(crate) struct LockedR3UnloadNonMatch(PrivateLockedR3UnloadNonMatch);
struct PrivateLockedR3UnloadNonMatch(());

pub(crate) enum R3UnloadCellAction {
    Winner {
        context: NonNull<ControlFileContext>,
        disposition: TerminalDisposition,
    },
    Join(TerminalJoinGuard),
    Completed(TerminalResult),
    Published(BlockedUnloadWaitGuard),
    Opaque(OpaqueFailStopWaitGuard),
    /// Ordinary delete has published exact Free/Inactive, and the queued
    /// callback owns only its last no-more-cell-access rundown epilogue. The
    /// unload scan retries this authenticated transient rather than either
    /// forging empty or treating a valid callback tail as corruption.
    FinalizerEpiloguePending,
}

pub(crate) enum R3UnloadCellObservation {
    NonMatch(LockedR3UnloadNonMatch),
    Action(R3UnloadCellAction),
    FailStop,
}

/// Named, copy-only effect-nine observations made under one registry hold.
/// No constructor or owner projection is exposed outside this module. Keeping
/// every predicate as its own field prevents an aggregate "empty" shortcut
/// from silently standing in for one omitted ledger.
struct R3NativeUnloadPreflightObservation {
    core_admission_closed: bool,
    core_session_slots_empty: bool,
    native_session_cells_empty: bool,
    terminal_rendezvous_inactive: bool,
    terminal_joiners_drained: bool,
    terminal_events_quiescent: bool,
    mount_owner_absent: bool,
    mount_tickets_and_waiters_drained: bool,
    mount_signals_acknowledged: bool,
    finalizer_deposits_absent: bool,
    finalizer_handoffs_absent: bool,
    fail_stop_slots_empty: bool,
    session_shell_owners_absent: bool,
    session_root_owners_absent: bool,
    registry_leases_absent: bool,
    control_owners_absent: bool,
    checkpoint_readiness_absent: bool,
}

/// Sealed locked receipt for the 17 native/core cell-ledger predicates.
pub(crate) struct R3NativeLedgersClear {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateR3NativeLedgersClear,
}

/// Sole-root count sampled in the same registry hold as every session ledger.
/// A later raw count would race the state it purports to summarize.
pub(crate) struct R3SoleDriverRoot {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateR3SoleDriverRoot,
}

struct PrivateR3NativeLedgersClear(());
struct PrivateR3SoleDriverRoot(());

impl R3NativeLedgersClear {
    pub(crate) fn matches_registry(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
}

impl R3SoleDriverRoot {
    pub(crate) fn matches_registry(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
}

impl NativeSessionCell {
    /// Effect-nine base-cell predicate. This intentionally excludes every
    /// terminal, mount, finalizer, fail-stop, and owner ledger that has its own
    /// independently named R3 predicate below. The stronger aggregate remains
    /// the authority for effects five and six's stable scan only.
    fn r3_unload_preflight_cell_is_empty(&self) -> bool {
        matches!(self.phase, NativeCellPhase::Free | NativeCellPhase::Retired)
            && self.identity.is_none()
            && self.session.is_null()
            && self.process.is_null()
            && !self.process_loss_handled
    }

    /// Exact native half of one session-scan non-match. Free/Retired alone is
    /// insufficient: every owner, durable slot, rendezvous, finalizer deposit,
    /// callback admission, and handoff must also be absent/inactive.
    fn r3_unload_scan_is_exactly_empty(&self) -> bool {
        matches!(self.phase, NativeCellPhase::Free | NativeCellPhase::Retired)
            && self.identity.is_none()
            && self.session.is_null()
            && self.process.is_null()
            && !self.process_loss_handled
            && self.registry_lease.is_none()
            && self.control_owner.is_none()
            && self.shell_owner.is_none()
            && self.root_release.is_none()
            && self.mount_rendezvous.r3_unload_is_inactive()
            && self.terminal_rendezvous.r3_unload_is_inactive()
            && self.checkpoint_readiness.is_none()
            && self.fail_stop.is_empty()
            && self.finalizer_handoff.is_none()
            && self.finalizer.locator().is_none()
            && self.finalizer.deposit_is_none()
            && matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
            && self.finalizer_callback_admitted.is_none()
            && self.finalizer_context.queued.is_none()
    }

    fn r3_unload_scan_is_exactly_empty_except_finalizer_callback(&self) -> bool {
        matches!(self.phase, NativeCellPhase::Free | NativeCellPhase::Retired)
            && self.identity.is_none()
            && self.session.is_null()
            && self.process.is_null()
            && !self.process_loss_handled
            && self.registry_lease.is_none()
            && self.control_owner.is_none()
            && self.shell_owner.is_none()
            && self.root_release.is_none()
            && self.mount_rendezvous.r3_unload_is_inactive()
            && self.terminal_rendezvous.r3_unload_is_inactive()
            && self.checkpoint_readiness.is_none()
            && self.fail_stop.is_empty()
            && self.finalizer_handoff.is_none()
            && self.finalizer.locator().is_none()
            && self.finalizer.deposit_is_none()
            && matches!(
                self.finalizer.state(),
                fsring_core::adapter::lifecycle::FinalizerState::Idle
            )
            && self.finalizer_callback_admitted.is_some()
            && self.finalizer_context.queued.is_none()
    }
}

impl RegistryLockGuard {
    /// Observe exactly one fixed-domain unload cell. Only an exact native-empty
    /// cross-product mints the advance receipt. Every authentic nonempty
    /// generation yields one owned action, or a fail-stop that cannot advance.
    pub(crate) unsafe fn observe_r3_unload_cell(&mut self, index: u32) -> R3UnloadCellObservation {
        let Some(cell) = (unsafe { self.cell_ptr(index) }) else {
            return R3UnloadCellObservation::FailStop;
        };
        if unsafe { (*cell).r3_unload_scan_is_exactly_empty() } {
            return R3UnloadCellObservation::NonMatch(LockedR3UnloadNonMatch(
                PrivateLockedR3UnloadNonMatch(()),
            ));
        }

        if unsafe { (*cell).r3_unload_scan_is_exactly_empty_except_finalizer_callback() } {
            return R3UnloadCellObservation::Action(R3UnloadCellAction::FinalizerEpiloguePending);
        }

        let Some(locator) = (unsafe { (*cell).terminal_rendezvous.r3_locked_locator() }) else {
            return R3UnloadCellObservation::FailStop;
        };
        if unsafe {
            (*cell).identity != Some(locator.identity())
                || (*cell).generation != locator.generation()
        } {
            return R3UnloadCellObservation::FailStop;
        }

        if let Some(context) = unsafe { (*cell).recorded_control_context() } {
            return match unsafe {
                prepare_native_terminal_claim(self, context, locator, TerminalRequest::Unload)
            } {
                Ok(prepared) => R3UnloadCellObservation::Action(R3UnloadCellAction::Winner {
                    context,
                    disposition: unsafe { prepared.commit() },
                }),
                Err(_) => R3UnloadCellObservation::FailStop,
            };
        }

        match unsafe { (*cell).terminal_rendezvous.outcome_for_locator(locator) } {
            Some(fsring_core::session::TerminalRendezvousOutcome::Open) => {
                match unsafe { &mut (*cell).terminal_rendezvous }.r3_join_open_locked(locator) {
                    Ok(ticket) => R3UnloadCellObservation::Action(R3UnloadCellAction::Join(
                        TerminalJoinGuard::ordinary(self.registry, locator, ticket),
                    )),
                    Err(_) => R3UnloadCellObservation::FailStop,
                }
            }
            Some(fsring_core::session::TerminalRendezvousOutcome::Completed(result)) => {
                // A closed-but-not-reset generation is not a non-match. The
                // restart re-observes it until the callback finishes reset;
                // parked readiness/later-last can therefore never cross into
                // effect seven as a false empty pass.
                R3UnloadCellObservation::Action(R3UnloadCellAction::Completed(result))
            }
            Some(fsring_core::session::TerminalRendezvousOutcome::Blocked(_)) => {
                match self.prepare_published_unload_wait(locator) {
                    Some(wait) => {
                        R3UnloadCellObservation::Action(R3UnloadCellAction::Published(wait))
                    }
                    None => R3UnloadCellObservation::FailStop,
                }
            }
            None => match self.prepare_opaque_unload_wait(locator) {
                Some(wait) => R3UnloadCellObservation::Action(R3UnloadCellAction::Opaque(wait)),
                None => R3UnloadCellObservation::FailStop,
            },
        }
    }

    /// Effect nine's sole native observation. All 64 cells and both core/native
    /// ledgers are sampled in this unchanged registry-lock hold.
    unsafe fn observe_r3_unload_preflight(&mut self) -> R3NativeUnloadPreflightObservation {
        let core = unsafe { self.core_mut() };
        let core_admission_closed = core.r3_unload_admission_is_closed();
        let core_session_slots_empty = core.r3_unload_slots_are_empty();

        let mut native_session_cells_empty = true;
        let mut terminal_rendezvous_inactive = true;
        let mut terminal_joiners_drained = true;
        let mut terminal_events_quiescent = true;
        let mut mount_owner_absent = true;
        let mut mount_tickets_and_waiters_drained = true;
        let mut mount_signals_acknowledged = true;
        let mut finalizer_deposits_absent = true;
        let mut finalizer_handoffs_absent = true;
        let mut fail_stop_slots_empty = true;
        let mut session_shell_owners_absent = true;
        let mut session_root_owners_absent = true;
        let mut registry_leases_absent = true;
        let mut control_owners_absent = true;
        let mut checkpoint_readiness_absent = true;

        let mut index = 0usize;
        while index < SESSION_CELL_COUNT {
            // SAFETY: fixed-domain bound and held registry lock.
            let cell = unsafe { &*self.registry.as_ref().cells.get_unchecked(index).get() };
            native_session_cells_empty &= cell.r3_unload_preflight_cell_is_empty();
            terminal_rendezvous_inactive &= cell.terminal_rendezvous.r3_unload_is_inactive();
            terminal_joiners_drained &= cell.terminal_rendezvous.r3_unload_joiners_are_drained();
            // All seven generation events have well-defined quiescent states:
            // terminal/visibility/mount completion events nonsignaled, each
            // drained event signaled. Exact state reads make event reuse a
            // separate predicate from rendezvous inactivity.
            terminal_events_quiescent &= unsafe {
                fsring_sys::c4::KeReadStateEvent(
                    core::ptr::addr_of!(cell.terminal_outcome).cast_mut().cast(),
                ) == 0
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!(cell.visibility_resolution)
                            .cast_mut()
                            .cast(),
                    ) == 0
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!(cell.joiners_drained).cast_mut().cast(),
                    ) != 0
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!(cell.mount_complete).cast_mut().cast(),
                    ) == 0
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!(cell.mount_waiters_drained)
                            .cast_mut()
                            .cast(),
                    ) != 0
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!(cell.mount_reset_complete)
                            .cast_mut()
                            .cast(),
                    ) == 0
                    && fsring_sys::c4::KeReadStateEvent(
                        core::ptr::addr_of!(cell.mount_reset_waiters_drained)
                            .cast_mut()
                            .cast(),
                    ) != 0
            };
            mount_owner_absent &= cell.mount_rendezvous.r3_unload_owner_is_absent();
            mount_tickets_and_waiters_drained &= cell
                .mount_rendezvous
                .r3_unload_tickets_and_waiters_are_drained();
            mount_signals_acknowledged &=
                cell.mount_rendezvous.r3_unload_signals_are_acknowledged();
            finalizer_deposits_absent &= cell.finalizer.locator().is_none()
                && cell.finalizer.deposit_is_none()
                && matches!(cell.finalizer.state(), FinalizerState::Idle)
                && cell.finalizer_callback_admitted.is_none()
                && cell.finalizer_context.queued.is_none();
            finalizer_handoffs_absent &= cell.finalizer_handoff.is_none();
            fail_stop_slots_empty &= cell.fail_stop.is_empty();
            session_shell_owners_absent &= cell.shell_owner.is_none();
            session_root_owners_absent &= cell.root_release.is_none();
            registry_leases_absent &= cell.registry_lease.is_none();
            control_owners_absent &= cell.control_owner.is_none();
            checkpoint_readiness_absent &= cell.checkpoint_readiness.is_none();
            index = index.saturating_add(1);
        }

        R3NativeUnloadPreflightObservation {
            core_admission_closed,
            core_session_slots_empty,
            native_session_cells_empty,
            terminal_rendezvous_inactive,
            terminal_joiners_drained,
            terminal_events_quiescent,
            mount_owner_absent,
            mount_tickets_and_waiters_drained,
            mount_signals_acknowledged,
            finalizer_deposits_absent,
            finalizer_handoffs_absent,
            fail_stop_slots_empty,
            session_shell_owners_absent,
            session_root_owners_absent,
            registry_leases_absent,
            control_owners_absent,
            checkpoint_readiness_absent,
        }
    }

    /// Mint the effect-nine receipt only if every independently named locked
    /// observation is satisfied. Failure returns the exact predicate rather
    /// than an aggregate mask or caller-constructible boolean set.
    unsafe fn prepare_r3_native_ledgers_clear(
        &mut self,
    ) -> Result<R3NativeLedgersClear, fsring_core::adapter::load::R3UnloadPredicate> {
        use fsring_core::adapter::load::R3UnloadPredicate as P;
        let observed = unsafe { self.observe_r3_unload_preflight() };
        for (clear, predicate) in [
            (observed.core_admission_closed, P::CoreAdmissionClosed),
            (observed.core_session_slots_empty, P::CoreSessionSlotsEmpty),
            (
                observed.native_session_cells_empty,
                P::NativeSessionCellsEmpty,
            ),
            (
                observed.terminal_rendezvous_inactive,
                P::TerminalRendezvousInactive,
            ),
            (observed.terminal_joiners_drained, P::TerminalJoinersDrained),
            (
                observed.terminal_events_quiescent,
                P::TerminalEventsQuiescent,
            ),
            (observed.mount_owner_absent, P::MountOwnerAbsent),
            (
                observed.mount_tickets_and_waiters_drained,
                P::MountTicketsAndWaitersDrained,
            ),
            (
                observed.mount_signals_acknowledged,
                P::MountSignalsAcknowledged,
            ),
            (
                observed.finalizer_deposits_absent,
                P::FinalizerDepositsAbsent,
            ),
            (
                observed.finalizer_handoffs_absent,
                P::FinalizerHandoffsAbsent,
            ),
            (observed.fail_stop_slots_empty, P::FailStopSlotsEmpty),
            (
                observed.session_shell_owners_absent,
                P::SessionShellOwnersAbsent,
            ),
            (
                observed.session_root_owners_absent,
                P::SessionRootOwnersAbsent,
            ),
            (observed.registry_leases_absent, P::RegistryLeasesAbsent),
            (observed.control_owners_absent, P::ControlOwnersAbsent),
            (
                observed.checkpoint_readiness_absent,
                P::CheckpointReadinessAbsent,
            ),
        ] {
            if !clear {
                return Err(predicate);
            }
        }
        Ok(R3NativeLedgersClear {
            registry: self.registry,
            authority: PrivateR3NativeLedgersClear(()),
        })
    }

    /// Extend the locked ledger observation with the sole root reference in
    /// the same hold. `state` is the containing DriverState for this registry.
    pub(crate) unsafe fn prepare_r3_unload_locked_root(
        &mut self,
        state: core::ptr::NonNull<crate::driver::DriverState>,
    ) -> Result<
        (R3NativeLedgersClear, R3SoleDriverRoot),
        fsring_core::adapter::load::R3UnloadPredicate,
    > {
        let expected_registry = unsafe {
            core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*state.as_ptr()).sessions))
        };
        if expected_registry != self.registry {
            unsafe { fsring_sys::KeBugCheckEx(crate::FSRING_PANIC_BUGCHECK, 9, u64::MAX, 4, 0) }
        }
        let ledgers = unsafe { self.prepare_r3_native_ledgers_clear()? };
        if unsafe { state.as_ref().reference_count() } != 1 {
            return Err(fsring_core::adapter::load::R3UnloadPredicate::SoleDriverRootReference);
        }
        Ok((
            ledgers,
            R3SoleDriverRoot {
                registry: self.registry,
                authority: PrivateR3SoleDriverRoot(()),
            },
        ))
    }
}

/// Why a parked WAIT could not be stored.
///
/// Named rather than boolean because the caller has to act on it: the IRP is
/// already in the CSQ with no plan behind it, so a refusal that is merely
/// counted leaves the client waiting on a request this driver has just decided
/// it cannot serve. Every arm means the session or its pending runtime went
/// away underneath a dispatch that had already parked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub(crate) enum ParkedStoreRefusal {
    /// The ring index no longer resolves to a slot on this session.
    NoRing,
    /// The registry pointer this access guard was built from is gone.
    NoRegistry,
    /// The registry no longer holds this session's cell.
    NoCell,
    /// The cell carries no pending runtime to store into.
    NoPendingRuntime,
    /// The slot itself refused: a ring-state disagreement, a released slot
    /// runtime, or a role the ring would not mark.
    SlotRefused,
}

impl KernelSessionRegistry {
    /// Examine exactly one permanent cell for a process observation.
    ///
    /// One cell per lock hold, and the lock is dropped before returning. The
    /// predecessor scanned an array of raw session pointers and dereferenced
    /// each candidate to read its captured process — a read of storage another
    /// thread could be freeing. Here the process observation is a field of the
    /// permanent cell, compared while locked, and what leaves the lock is a
    /// locator: a value that has to be resolved again before it can be used.
    ///
    /// This step records; it claims nothing. It runs no terminal work, mints no
    /// authority, and reaches no finalizer. Task 9 stages the typed claim and
    /// Task 12 binds this scan to it.
    ///
    /// # Safety
    /// `registry` is the live permanent registry and the caller is at or below
    /// APC_LEVEL: this takes the registry spin lock, which raises to
    /// DISPATCH_LEVEL for the duration.
    pub(crate) unsafe fn scan_one_cell_for_process(
        guard: &ProcessCallbackGuard,
        process: PEPROCESS,
        index: u32,
    ) -> ProcessScanStep {
        let registry = guard.registry();
        let Ok(cell_count) = u32::try_from(SESSION_CELL_COUNT) else {
            return ProcessScanStep::Complete;
        };
        if index >= cell_count || process.is_null() {
            return ProcessScanStep::Complete;
        }
        let resume_at = index.checked_add(1).filter(|next| *next < cell_count);
        // SAFETY: the caller's registry contract.
        let mut lock = unsafe { Self::lock(registry) };
        // SAFETY: the lock is held for the whole observation.
        let mut matched_without_action = false;
        let prepared = match unsafe { lock.cell_ptr(index) } {
            Some(cell) => match unsafe { (*cell).process_locator(process) } {
                Some(locator) => {
                    let context = unsafe { (*cell).recorded_control_context() };
                    if let Some(context) = context {
                        match unsafe {
                            prepare_native_terminal_claim(
                                &mut lock,
                                context,
                                locator,
                                TerminalRequest::ProcessLoss,
                            )
                        } {
                            Ok(claim) => Some(PreparedProcessScanAction {
                                cell: unsafe { NonNull::new_unchecked(cell) },
                                locator,
                                action: ProcessScanAction::Winner {
                                    context,
                                    disposition: unsafe { claim.commit() },
                                },
                            }),
                            Err(_) => {
                                matched_without_action = true;
                                None
                            }
                        }
                    } else {
                        match unsafe { (*cell).terminal_rendezvous.outcome_for_locator(locator) } {
                            Some(fsring_core::session::TerminalRendezvousOutcome::Open) => {
                                match unsafe { &mut (*cell).terminal_rendezvous }
                                    .r3_join_open_locked(locator)
                                {
                                    Ok(ticket) => Some(PreparedProcessScanAction {
                                        cell: unsafe { NonNull::new_unchecked(cell) },
                                        locator,
                                        action: ProcessScanAction::Join(
                                            TerminalJoinGuard::ordinary(registry, locator, ticket),
                                        ),
                                    }),
                                    Err(_) => {
                                        matched_without_action = true;
                                        None
                                    }
                                }
                            }
                            Some(fsring_core::session::TerminalRendezvousOutcome::Completed(
                                result,
                            )) => Some(PreparedProcessScanAction {
                                cell: unsafe { NonNull::new_unchecked(cell) },
                                locator,
                                action: ProcessScanAction::Completed(result),
                            }),
                            Some(fsring_core::session::TerminalRendezvousOutcome::Blocked(
                                blocked,
                            )) => Some(PreparedProcessScanAction {
                                cell: unsafe { NonNull::new_unchecked(cell) },
                                locator,
                                action: ProcessScanAction::Blocked(blocked),
                            }),
                            None => match unsafe { (*cell).authenticate_closed_fail_stop(locator) }
                            {
                                Some(crate::fence::ClosedFailStopAuthentication::Opaque(
                                    receipt,
                                )) => Some(PreparedProcessScanAction {
                                    cell: unsafe { NonNull::new_unchecked(cell) },
                                    locator,
                                    action: ProcessScanAction::Opaque(receipt),
                                }),
                                _ => {
                                    matched_without_action = true;
                                    None
                                }
                            },
                        }
                    }
                }
                None => None,
            },
            None => None,
        };
        let action = prepared.map(|prepared| unsafe { prepared.commit() });
        // SAFETY: this frame took the lock and releases it once.
        unsafe { lock.release() };
        match action {
            Some(action) => ProcessScanStep::Action(action),
            None if matched_without_action => ProcessScanStep::FailStop,
            None => match resume_at {
                Some(resume_at) => ProcessScanStep::Skip {
                    resume_at: Some(resume_at),
                },
                None => ProcessScanStep::Complete,
            },
        }
    }
}

impl<'registry> SessionAccessGuard<'registry> {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// The pointer-free observations, by value.
    pub(crate) fn view(&self) -> crate::session::NativeSessionView {
        // SAFETY: the access rundown this guard holds keeps the shell alive,
        // and every field `view` copies was written before publication.
        self.session.get().view()
    }

    /// True once the session's own admission word says the fence has started.
    pub(crate) fn is_published(&self) -> bool {
        // SAFETY: as `view`; this reads one atomic word.
        self.session.get().is_published()
    }

    /// Take one ring's spin lock.
    ///
    /// The returned guard borrows `self`, so it cannot outlive the access that
    /// proved the session is still live, and it releases the lock in `Drop` at
    /// the exact IRQL the acquire returned.
    pub(crate) fn lock_ring<'access>(
        &'access self,
        ring_index: u32,
    ) -> Result<NativeRingGuard<'access, 'registry>, SessionAccessError> {
        // SAFETY: the rundown keeps the shell, and its ring array, alive.
        let slot = self
            .session
            .get()
            .ring_slot(ring_index)
            .ok_or(SessionAccessError::WrongRing)?;
        // SAFETY: the slot's lock was initialized before publication and this
        // is a plain acquire; the matching release is this guard's `Drop`.
        let old_irql = acquire_saved_irql(|| unsafe { slot.acquire_lock() });
        Ok(NativeRingGuard {
            access: self,
            ring_index,
            slot,
            old_irql: Some(old_irql),
        })
    }

    /// Validate one copied ENTER request without exposing the stored SETUP.
    pub(crate) fn validate_enter_request(
        &self,
        input: &[u8],
    ) -> Result<fsring_abi::control::EnterRequestV1, fsring_abi::validate::SessionValidationError>
    {
        // SAFETY: the access rundown keeps the shell alive; the operation
        // returns only the decoded request value.
        self.session.get().validate_enter_request(input)
    }

    /// Park a WAIT ENTER on this session's pending runtime.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with the access rundown held; `irp` is the live ENTER.
    pub(crate) unsafe fn park_wait_enter(
        &self,
        ring_index: u32,
        irp: PIRP,
        timeout_ms: u32,
    ) -> Result<(), NTSTATUS> {
        let registry = NonNull::new(self.registry as *mut KernelSessionRegistry)
            .ok_or(wdk_sys::STATUS_INVALID_DEVICE_STATE)?;
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_mut(self.slot_index) }) else {
            unsafe { lock.release() };
            return Err(wdk_sys::STATUS_INVALID_DEVICE_STATE);
        };
        let Some(runtime) = cell.pending_runtime() else {
            unsafe { lock.release() };
            return Err(wdk_sys::STATUS_INVALID_DEVICE_STATE);
        };
        let runtime = runtime as *const crate::pending_enter::PendingRuntimeReady;
        unsafe { lock.release() };
        // `park_wait_enter` reaches the session's control ledger itself, under
        // the registry lock alone and only for the instant it links -- never
        // pre-fetched and held across the per-ring lock the way `runtime` is
        // here, which is exactly the race its own doc comment fixes.
        unsafe { crate::pending_enter::park_wait_enter(&*runtime, ring_index, irp, timeout_ms) }
    }

    /// Wake parked WAITs whose mapped SQ is now ready.
    ///
    /// Reports whether every ready ring accepted its wake. The sweep went to
    /// the trouble of computing an accurate aggregate refusal and this call
    /// site threw it away, so nothing anywhere could observe a ring whose
    /// readiness deposit was refused -- and refusals here are no longer
    /// routine: `deposit_locked_wake` counts an install already delivering its
    /// terminal as accepted, so what is left means the wake slot, the schedule
    /// and the owner ledger disagree about who owns the ring.
    ///
    /// A session with no pending runtime, or no cell, has nothing to refuse
    /// and answers `true`.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with the access rundown held.
    pub(crate) unsafe fn wake_ready_parked_waits(&self) -> bool {
        let Some(registry) = NonNull::new(self.registry as *mut KernelSessionRegistry) else {
            return true;
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_mut(self.slot_index) }) else {
            unsafe { lock.release() };
            return true;
        };
        let Some(runtime) = cell.pending_runtime() else {
            unsafe { lock.release() };
            return true;
        };
        let runtime = runtime as *const crate::pending_enter::PendingRuntimeReady;
        unsafe { lock.release() };
        unsafe {
            (*runtime)
                .deposit_readiness_wakes(self.session.get() as *const crate::session::NativeSession)
        }
    }

    /// Store the owned parked WAIT plan. Must not complete the IRP on failure:
    /// `IoCsqInsertIrp` has already transferred it.
    ///
    /// A refusal releases `owned`'s ring-wide `RoleLease` back to the ring
    /// rather than dropping it: `RoleLease` has no `Drop`, and a caller that
    /// only discards this function's `bool` (as `execute_enter` does) would
    /// otherwise leak the ring's sole SQ-wait-owner bit forever, permanently
    /// refusing every later WAIT on this ring with `DEVICE_BUSY`.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with the access rundown held; the ring slot outlives the
    /// parked install.
    pub(crate) unsafe fn store_parked_wait(
        &self,
        ring_index: u32,
        owned: fsring_core::adapter::enter::ParkedWaitInstall,
        request: fsring_abi::control::EnterRequestV1,
    ) -> Result<(), ParkedStoreRefusal> {
        let Some(ring) = self.session.get().ring_slot(ring_index) else {
            // No ring to hand the role back to either; nothing further to do.
            return Err(ParkedStoreRefusal::NoRing);
        };
        let Some(registry) = NonNull::new(self.registry as *mut KernelSessionRegistry) else {
            Self::release_parked_wait_role(ring, owned);
            return Err(ParkedStoreRefusal::NoRegistry);
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_mut(self.slot_index) }) else {
            unsafe { lock.release() };
            Self::release_parked_wait_role(ring, owned);
            return Err(ParkedStoreRefusal::NoCell);
        };
        let Some(runtime) = cell.pending_runtime() else {
            unsafe { lock.release() };
            Self::release_parked_wait_role(ring, owned);
            return Err(ParkedStoreRefusal::NoPendingRuntime);
        };
        let runtime = runtime as *const crate::pending_enter::PendingRuntimeReady;
        unsafe { lock.release() };
        match unsafe {
            crate::pending_enter::store_parked_session_wait(
                &*runtime,
                ring_index,
                owned,
                ring as *const crate::session::NativeRingSlot,
                request,
                self.session.get() as *const crate::session::NativeSession,
            )
        } {
            Ok(()) => Ok(()),
            Err(owned) => {
                Self::release_parked_wait_role(ring, owned);
                Err(ParkedStoreRefusal::SlotRefused)
            }
        }
    }

    /// Fail the WAIT a refused `store_parked_wait` left parked with no plan.
    ///
    /// Bounded and idempotent: it removes the IRP the CSQ still holds and
    /// completes it once, or does nothing at all when the framework's cancel
    /// routine already owns the request.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no slot lock held.
    pub(crate) unsafe fn fail_unstored_parked_wait(&self, ring_index: u32) -> bool {
        let Some(registry) = NonNull::new(self.registry as *mut KernelSessionRegistry) else {
            return false;
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let runtime = match unsafe { lock.cell_mut(self.slot_index) } {
            Some(cell) => cell
                .pending_runtime()
                .map(|runtime| runtime as *const crate::pending_enter::PendingRuntimeReady),
            None => None,
        };
        unsafe { lock.release() };
        let Some(runtime) = runtime else {
            return false;
        };
        // SAFETY: the runtime outlives this dispatch; the ring index is the
        // caller's own and is range-checked inside.
        unsafe { crate::pending_enter::fail_unstored_parked_wait(&*runtime, ring_index) }
    }

    /// Release the leased SQ-wait role a refused `store_parked_wait` would
    /// otherwise drop. `RoleLease` has no `Drop`, so every refusal path that
    /// still holds `owned` must reach this instead of letting it fall.
    fn release_parked_wait_role(
        ring: &crate::session::NativeRingSlot,
        mut owned: fsring_core::adapter::enter::ParkedWaitInstall,
    ) {
        if let Some(lease) = owned.take_role() {
            // SAFETY: this lease was minted for exactly this ring by
            // `EnterEffect::AcquireRole` moments before `owned` was built, and
            // a refused store never published it anywhere else to compete for
            // release.
            unsafe { ring.release_parked_session_role(lease) };
        }
    }

    /// Acquire the stable `StrongSessionRef` a parked WAIT holds until
    /// completion. Must run before `IoCsqInsertIrp`. This is not the
    /// access/control rundown the fence waits.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with the access rundown held; `irp` is the live ENTER.
    pub(crate) unsafe fn acquire_parked_strong_refs(&self, ring_index: u32, irp: PIRP) -> bool {
        let _ = irp;
        let Some(registry) = NonNull::new(self.registry as *mut KernelSessionRegistry) else {
            return false;
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_mut(self.slot_index) }) else {
            unsafe { lock.release() };
            return false;
        };
        let Some(runtime) = cell.pending_runtime() else {
            unsafe { lock.release() };
            return false;
        };
        let runtime = runtime as *const crate::pending_enter::PendingRuntimeReady;
        let Ok(reference) = (unsafe { lock.core_mut().acquire(self.locator) }) else {
            unsafe { lock.release() };
            return false;
        };
        unsafe { lock.release() };
        match unsafe {
            crate::pending_enter::store_parked_strong_session(
                &*runtime,
                ring_index,
                reference,
                registry.as_ptr(),
            )
        } {
            Ok(()) => true,
            Err(reference) => {
                let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                let _ = unsafe { lock.core_mut().release(reference) };
                unsafe { lock.release() };
                false
            }
        }
    }

    /// Release a parked WAIT's session SQ role after a refused store.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with the access rundown held.
    pub(crate) unsafe fn release_parked_session_role(
        &self,
        ring_index: u32,
        lease: fsring_core::enter::RoleLease,
    ) {
        let Some(ring) = self.session.get().ring_slot(ring_index) else {
            return;
        };
        unsafe { ring.release_parked_session_role(lease) };
    }

    /// Release extra rundown a refused WAIT acquired before insert.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with the access rundown held.
    pub(crate) unsafe fn release_parked_strong_refs(&self, ring_index: u32) {
        let registry = match NonNull::new(self.registry as *mut KernelSessionRegistry) {
            Some(registry) => registry,
            None => return,
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let Some(cell) = (unsafe { lock.cell_mut(self.slot_index) }) else {
            unsafe { lock.release() };
            return;
        };
        let Some(runtime) = cell.pending_runtime() else {
            unsafe { lock.release() };
            return;
        };
        let runtime = runtime as *const crate::pending_enter::PendingRuntimeReady;
        unsafe { lock.release() };
        let Some(reference) =
            (unsafe { crate::pending_enter::take_parked_strong_session(&*runtime, ring_index) })
        else {
            return;
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let _ = unsafe { lock.core_mut().release(reference) };
        unsafe { lock.release() };
    }

    /// Release-store one ring's CQ consumer head.
    ///
    /// # Safety
    /// The access rundown is held and `ring_index` is inside the topology.
    pub(crate) unsafe fn store_cq_head(&self, ring_index: u32, next_head: u64) {
        unsafe { self.session.get().store_cq_head(ring_index, next_head) };
    }

    pub(crate) fn cq_cursors(&self, ring_index: u32) -> Option<(u64, u64)> {
        self.session.get().cq_cursors(ring_index)
    }

    pub(crate) fn read_cqe(
        &self,
        ring_index: u32,
        consumed: u64,
    ) -> Option<fsring_abi::layout::Cqe> {
        self.session.get().read_cqe(ring_index, consumed)
    }

    pub(crate) fn session(&self) -> &crate::session::NativeSession {
        self.session.get()
    }

    /// Read one ring's SQ cursors without exposing the mapped address.
    pub(crate) fn sq_cursors(&self, ring_index: u32) -> Option<(u64, u64)> {
        // SAFETY: the access rundown keeps the mapping alive; the operation
        // returns only the two atomic cursor values.
        self.session.get().sq_cursors(ring_index)
    }
}

impl Drop for SessionAccessGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: the `'registry` lifetime this guard carries outlives it, so
        // the registry storage is still there; the read is shared and touches
        // only the permanent cell array.
        let registry = unsafe { &*self.registry };
        if let Some(target) = registry.access_rundown_ptr(self.slot_index) {
            // SAFETY: `resolve` acquired exactly one reference on this cell's
            // rundown and this is its one release.
            unsafe { fsring_sys::c4::ExReleaseRundownProtection(target.cast()) };
        }
    }
}

impl NativeRingGuard<'_, '_> {
    pub(crate) const fn ring_index(&self) -> u32 {
        self.ring_index
    }

    pub(crate) const fn locator(&self) -> SessionLocator {
        self.access.locator
    }

    pub(crate) fn classify_cq(
        &self,
        observation: fsring_core::enter::CqObservation,
        grants: &fsring_core::grant::GrantTable<'_>,
    ) -> fsring_core::enter::DrainPlan {
        // SAFETY: this guard holds the ring spin lock for the whole borrow.
        unsafe { self.slot.classify_cq(observation, grants) }
    }

    pub(crate) fn acquire_role(
        &mut self,
        invocation: u64,
        role: fsring_core::enter::EnterRole,
    ) -> Result<fsring_core::enter::RoleLease, fsring_core::enter::EnterError> {
        // SAFETY: the projection is created, used by one fixed non-waiting
        // transition, and destroyed before this method returns.
        unsafe { self.slot.acquire_role(invocation, role) }
    }

    pub(crate) unsafe fn release_held_role(
        &mut self,
        lease: fsring_core::enter::RoleLease,
    ) -> Result<
        (),
        (
            fsring_core::enter::EnterError,
            fsring_core::enter::RoleLease,
        ),
    > {
        unsafe { self.slot.release_held_role(lease) }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn release_pending<'g>(
        &mut self,
        pending: fsring_core::adapter::enter::PendingRoleRelease<'g>,
    ) -> Result<
        fsring_core::adapter::enter::EnterProgress<'g>,
        (
            fsring_core::enter::EnterError,
            fsring_core::adapter::enter::PendingRoleRelease<'g>,
        ),
    > {
        // SAFETY: as `acquire_role`; no projection is returned to the caller.
        unsafe { self.slot.release_pending(pending) }
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn release_rollback(
        &mut self,
        pending: fsring_core::adapter::enter::PendingRollbackRoleRelease,
    ) -> Result<
        fsring_core::adapter::enter::EnterRollbackProgress,
        (
            fsring_core::enter::EnterError,
            fsring_core::adapter::enter::PendingRollbackRoleRelease,
        ),
    > {
        // SAFETY: as `acquire_role`; no projection is returned to the caller.
        unsafe { self.slot.release_rollback(pending) }
    }

    pub(crate) fn release(self) {}
}

impl Drop for NativeRingGuard<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: this guard took the lock and releases it exactly once, at the
        // IRQL `KeAcquireSpinLockRaiseToDpc` returned.
        if let Some(saved) = self.old_irql.take() {
            saved.release_with(|old_irql| unsafe { self.slot.release_lock(old_irql) });
        }
    }
}

/// # Safety
/// `registry` points to final writable storage and no cell is reachable yet.
unsafe fn initialize_cells_in_place(registry: *mut KernelSessionRegistry) {
    for index in 0..SESSION_CELL_COUNT {
        // SAFETY: the fixed array starts here, the index is in range, and each
        // cell is initialized exactly once in increasing order.
        let cell = unsafe {
            core::ptr::addr_of_mut!((*registry).cells)
                .cast::<NativeSessionCell>()
                .add(index)
        };
        for step in CELL_INITIALIZATION_PLAN {
            match step {
                CellInitializationStep::AccessRundown => unsafe {
                    fsring_sys::c4::ExInitializeRundownProtection(core::ptr::addr_of_mut!(
                        (*cell).access
                    ));
                },
                CellInitializationStep::Event(event, signaled) => unsafe {
                    let target = match event {
                        CellEvent::TerminalOutcome => {
                            core::ptr::addr_of_mut!((*cell).terminal_outcome)
                        }
                        CellEvent::JoinersDrained => {
                            core::ptr::addr_of_mut!((*cell).joiners_drained)
                        }
                        CellEvent::VisibilityResolution => {
                            core::ptr::addr_of_mut!((*cell).visibility_resolution)
                        }
                        CellEvent::MountComplete => {
                            core::ptr::addr_of_mut!((*cell).mount_complete)
                        }
                        CellEvent::MountWaitersDrained => {
                            core::ptr::addr_of_mut!((*cell).mount_waiters_drained)
                        }
                        CellEvent::MountResetComplete => {
                            core::ptr::addr_of_mut!((*cell).mount_reset_complete)
                        }
                        CellEvent::MountResetWaitersDrained => {
                            core::ptr::addr_of_mut!((*cell).mount_reset_waiters_drained)
                        }
                    };
                    initialize_manual_event(target, signaled);
                },
                CellInitializationStep::EmptyObservations => unsafe {
                    core::ptr::addr_of_mut!((*cell).generation).write(0);
                    core::ptr::addr_of_mut!((*cell).identity).write(None);
                    core::ptr::addr_of_mut!((*cell).phase).write(NativeCellPhase::Free);
                    core::ptr::addr_of_mut!((*cell).session).write(core::ptr::null_mut());
                    core::ptr::addr_of_mut!((*cell).process).write(core::ptr::null_mut());
                    core::ptr::addr_of_mut!((*cell).registry_lease).write(None);
                    core::ptr::addr_of_mut!((*cell).control_owner).write(None);
                    core::ptr::addr_of_mut!((*cell).recorded_control_context).write(None);
                    core::ptr::addr_of_mut!((*cell).shell_owner).write(None);
                    core::ptr::addr_of_mut!((*cell).root_release).write(None);
                    core::ptr::addr_of_mut!((*cell).mount_rendezvous)
                        .write(NativeMountRendezvous::new_inactive());
                    core::ptr::addr_of_mut!((*cell).terminal_rendezvous)
                        .write(TerminalRendezvous::new_inactive());
                    core::ptr::addr_of_mut!((*cell).process_loss_handled).write(false);
                    core::ptr::addr_of_mut!((*cell).checkpoint_readiness).write(None);
                    core::ptr::addr_of_mut!((*cell).pending_runtime).write(None);
                    core::ptr::addr_of_mut!((*cell).pending_ledger).write(None);
                    core::ptr::addr_of_mut!((*cell).fail_stop)
                        .write(crate::fence::R3FailStopSlot::new_empty());
                    core::ptr::addr_of_mut!((*cell).finalizer_handoff).write(None);
                    core::ptr::addr_of_mut!((*cell).finalizer)
                        .write(fsring_core::adapter::fence::R3FinalizerCell::new_unbound());
                    let cell_index = match u32::try_from(index) {
                        Ok(index) => index,
                        Err(_) => unreachable!("the fixed 64-cell registry index fits u32"),
                    };
                    core::ptr::addr_of_mut!((*cell).finalizer_context).write(
                        FinalizerWorkItemContext {
                            registry: NonNull::new_unchecked(registry),
                            cell_index,
                            queued: None,
                        },
                    );
                    core::ptr::addr_of_mut!((*cell).finalizer_work_item)
                        .write(core::ptr::null_mut());
                    core::ptr::addr_of_mut!((*cell).finalizer_callback_admitted).write(None);
                    fsring_sys::c4::KeInitializeTimer(
                        core::ptr::addr_of_mut!((*cell).fence_retry_timer).cast(),
                    );
                    fsring_sys::c4::KeInitializeDpc(
                        core::ptr::addr_of_mut!((*cell).fence_retry_dpc).cast(),
                        Some(crate::fence::fsring_fence_retry_dpc),
                        cell.cast::<core::ffi::c_void>(),
                    );
                    // Unsignalled: no DPC has run, so nothing has exited. It
                    // was created signalled, which made the retry worker's
                    // indefinite wait a no-op on the first use and every use
                    // after, because nothing ever cleared it.
                    initialize_manual_event(
                        core::ptr::addr_of_mut!((*cell).fence_retry_dpc_exit).cast(),
                        false,
                    );
                    core::ptr::addr_of_mut!((*cell).fence_retry_work_item)
                        .write(core::ptr::null_mut());
                    core::ptr::addr_of_mut!((*cell).fence_retry_park).write(None);
                },
            }
        }
    }
}

/// # Safety
/// `event` is aligned writable storage for one permanent cell event and is
/// initialized exactly once here.
unsafe fn initialize_manual_event(event: *mut KEVENT, signaled: bool) {
    unsafe {
        fsring_sys::c4::KeInitializeEvent(event, NotificationEvent, u8::from(signaled));
    }
}

// These compile-only native-shape tests deliberately remain part of every
// kernel check. They name the structural break each probe catches; Task 6's
// implementation below must make them type-check without a host test harness.
#[cfg(test)]
#[allow(dead_code)]
mod native_shape_tests {
    use super::*;

    fn native_registry_capacity_matches_boot_context_slots_and_sixty_four() {
        let _: [(); 64] = [(); SESSION_CELL_COUNT];
        let _: [(); fsring_abi::control::BOOT_CONTEXT_SLOT_COUNT as usize] =
            [(); SESSION_CELL_COUNT];
    }

    const fn both_admission_rundowns_initialize_before_endpoint_publication() {
        assert!(matches!(
            REGISTRY_INITIALIZATION_PLAN,
            [
                RegistryInitializationStep::Lock,
                RegistryInitializationStep::AdmissionDoors,
                RegistryInitializationStep::SetupAdmission,
                RegistryInitializationStep::ControlContextAdmission,
                RegistryInitializationStep::ProcessCallbackAdmission,
                RegistryInitializationStep::FinalizerAdmission,
                RegistryInitializationStep::BlockedUnloadEvent,
                RegistryInitializationStep::Core,
                RegistryInitializationStep::Cells,
            ]
        ));
    }

    /// `process_callback_rundown_and_blocked_event_initialize_before_registration`
    ///
    /// The callback is registered by a *load effect*, and the registry is
    /// initialized in place before any load effect runs — so the ordering that
    /// matters is the one inside this plan: both of the new slots must be
    /// written before `Cells`, which is the last thing standing between the
    /// registry and its first observer. A plan that initialized either of them
    /// after `Cells` would leave a registered callback able to acquire an
    /// uninitialized rundown, and a blocked unload able to wait on an
    /// uninitialized event — the second of which would not fail loudly, it
    /// would return immediately and read as a drain.
    // PROOF: this is a `const fn` reached only through `const _: () = ...`,
    // so it is evaluated at compile time and never on a driver input path.
    // An index past the plan or an overflowed counter is a compilation
    // failure, which is a stronger refusal than the runtime panic section 5
    // forbids.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    const fn process_callback_rundown_and_blocked_event_initialize_before_registration() {
        let mut index = 0;
        let mut admission_doors = usize::MAX;
        let mut callback_admission = usize::MAX;
        let mut finalizer_admission = usize::MAX;
        let mut blocked_event = usize::MAX;
        let mut cells = usize::MAX;
        while index < REGISTRY_INITIALIZATION_PLAN.len() {
            match REGISTRY_INITIALIZATION_PLAN[index] {
                RegistryInitializationStep::AdmissionDoors => admission_doors = index,
                RegistryInitializationStep::ProcessCallbackAdmission => {
                    callback_admission = index;
                }
                RegistryInitializationStep::FinalizerAdmission => finalizer_admission = index,
                RegistryInitializationStep::BlockedUnloadEvent => blocked_event = index,
                RegistryInitializationStep::Cells => cells = index,
                _ => {}
            }
            index += 1;
        }
        assert!(admission_doors != usize::MAX, "no software admission doors");
        assert!(
            callback_admission != usize::MAX,
            "no callback admission step"
        );
        assert!(
            finalizer_admission != usize::MAX,
            "no finalizer admission step"
        );
        assert!(blocked_event != usize::MAX, "no blocked-unload event step");
        assert!(cells != usize::MAX, "no cell step");
        assert!(admission_doors < cells);
        assert!(callback_admission < cells);
        assert!(finalizer_admission < cells);
        assert!(blocked_event < cells);
    }

    /// `process_callback_guard_spans_all_restarts_and_blocks_unload`
    ///
    /// The guard is affine and reaches the registry only through itself. A
    /// callback therefore cannot name the cell table without holding one, and
    /// cannot hold two, and cannot release one and keep scanning — the release
    /// consumes it. That is the whole "spans all restarts" property expressed as
    /// a type rather than as a loop invariant a reader has to verify by eye.
    const fn process_callback_guard_spans_all_restarts_and_blocks_unload() {
        let _: unsafe fn(NonNull<KernelSessionRegistry>) -> Option<ProcessCallbackGuard> =
            ProcessCallbackGuard::acquire;
        // `release` consumes the guard: no `&self` variant exists to call twice.
        let _: unsafe fn(ProcessCallbackGuard) = ProcessCallbackGuard::release;
        // Reaching the table goes through the guard.
        let _: fn(&ProcessCallbackGuard) -> NonNull<KernelSessionRegistry> =
            ProcessCallbackGuard::registry;
        // And unload's side of the same rundown: close, then wait.
        let _: unsafe fn(&mut RegistryLockGuard) -> ClosedGlobalAdmissions =
            close_global_admissions;
        // One parameter, not two: the closed token carries its own registry, so
        // there is no caller-supplied registry that could disagree with it.
        let _: unsafe fn(ProcessCallbackAdmissionClosed) -> ProcessCallbacksDrained =
            wait_process_callbacks_drained;
    }

    /// `blocked_unload_wait_cannot_become_a_successful_drain`
    ///
    /// The permanent wait diverges (`-> !`), so no caller can treat it as having
    /// completed, and there is no function anywhere that signals
    /// `blocked_unload` — the two cell events that *do* get signalled are named
    /// by `CellEvent`, which has no blocked-unload variant.
    const fn blocked_unload_wait_cannot_become_a_successful_drain() {
        let _: unsafe fn(NonNull<KernelSessionRegistry>) -> ! = wait_blocked_unload_forever;
        assert!(matches!(
            CELL_INITIALIZATION_PLAN[1],
            CellInitializationStep::Event(CellEvent::TerminalOutcome, false)
        ));
    }

    const fn every_cell_event_and_rundown_is_initialized_before_use() {
        assert!(matches!(
            CELL_INITIALIZATION_PLAN,
            [
                CellInitializationStep::AccessRundown,
                CellInitializationStep::Event(CellEvent::TerminalOutcome, false),
                CellInitializationStep::Event(CellEvent::JoinersDrained, true),
                CellInitializationStep::Event(CellEvent::VisibilityResolution, false),
                CellInitializationStep::Event(CellEvent::MountComplete, false),
                CellInitializationStep::Event(CellEvent::MountWaitersDrained, true),
                CellInitializationStep::Event(CellEvent::MountResetComplete, false),
                CellInitializationStep::Event(CellEvent::MountResetWaitersDrained, true),
                CellInitializationStep::EmptyObservations,
            ]
        ));
    }

    fn finalizer_callback_admission_is_affine_and_queue_endpoint_is_fused(
        admitted: AdmittedR3FinalizerKick,
    ) {
        <FinalizerCallbackAdmission as AmbiguousIfClone<_>>::assert_not_clone();
        <AdmittedR3FinalizerKick as AmbiguousIfClone<_>>::assert_not_clone();
        let _: unsafe fn(AdmittedR3FinalizerKick) = queue_cell_finalizer;
        let _ = admitted;
    }

    trait AmbiguousIfClone<Marker> {
        fn assert_not_clone() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    fn control_context_lease_is_noncloneable_and_releases_once(lease: ControlContextLease) {
        <ControlContextLease as AmbiguousIfClone<_>>::assert_not_clone();
        // The same probe consumes the only affine release authority.
        unsafe { lease.release() };
    }

    fn completed_record_moves_the_same_lease_into_close_right(record: CompletedControlRecord) {
        let CompletedControlRecord {
            generation: _,
            result: _,
            close:
                CloseContextRight {
                    lease,
                    authority: _,
                },
        } = record;
        unsafe { lease.release() };
    }

    fn closing_control_owner_has_no_separable_closing_or_session_reference(
        owner: ClosingControlOwner,
    ) {
        let ClosingControlOwner {
            context: _,
            lease,
            completion_obligation: _,
        } = owner;
        unsafe { lease.release() };
    }

    // -- Task 9 -----------------------------------------------------------
    //
    // These four name the native halves of the counted terminal claim. They
    // are consumption probes rather than assertions: each one type-checks only
    // while the authority it names is affine and reaches its destination.

    /// The runner takes the cell's `ControlOwner` out exactly once.
    ///
    /// `Option::take` is the only way in, and the slot it came from is left
    /// empty, so a second winner for the same generation has nothing to take.
    fn terminal_runner_moves_control_owner_out_once(slot: &mut Option<ControlOwner>) {
        let Some(owner) = slot.take() else { return };
        // Taking it again cannot produce a second owner.
        assert!(slot.is_none());
        let (control, closing) = owner.split();
        let _reference: StrongSessionRef = control.into_reference();
        let ClosingControlOwner {
            context: _,
            lease,
            completion_obligation: _,
        } = closing;
        unsafe { lease.release() };
    }

    /// The split produces exactly two authorities with different lifetimes.
    ///
    /// The strong reference is separately releasable; the closing owner is not,
    /// and it carries the context, the admission lease, and the one
    /// nonseparable completion obligation.
    fn control_owner_splits_into_strong_ref_and_one_closing_owner(owner: ControlOwner) {
        let (control, closing) = owner.split();
        <ControlStrongRef as AmbiguousIfClone<_>>::assert_not_clone();
        <ClosingControlOwner as AmbiguousIfClone<_>>::assert_not_clone();
        let _locator: SessionLocator = control.locator();
        let _context: NonNull<ControlFileContext> = closing.context();
        let ClosingControlOwner {
            context: _,
            lease,
            completion_obligation: _,
        } = closing;
        unsafe { lease.release() };
        let _reference: StrongSessionRef = control.into_reference();
    }

    /// The closing owner either becomes a completed record or stays parked.
    ///
    /// Both destinations consume the same value, so there is no path on which
    /// a generation both transfers the obligation and keeps it.
    fn closing_control_owner_transfers_once_or_remains_in_fail_stop(
        owner: ClosingControlOwner,
        transfer: bool,
        generation: u64,
        result: TerminalResult,
    ) -> Option<ClosingControlOwner> {
        if !transfer {
            // Fail-stop: the cell keeps the exact owner, and CLOSE may detach
            // the handle-facing pointer but never free the context.
            return Some(owner);
        }
        let ClosingControlOwner {
            context: _,
            lease,
            completion_obligation: _,
        } = owner;
        let record = CompletedControlRecord {
            generation,
            result,
            close: CloseContextRight::new(lease),
        };
        let CompletedControlRecord {
            generation: _,
            result: _,
            close,
        } = record;
        unsafe { close.release() };
        None
    }

    /// The four helpers fuse the whole signal-then-acknowledge window into the
    /// registry lock hold that produced each publication or conversion.
    ///
    /// Each takes a publication or conversion *by value* and returns the
    /// authority that only its acknowledgement can produce. There is no way to
    /// obtain the drain right, the reset ticket, or either proof except by
    /// going through the helper — so a caller cannot signal without
    /// acknowledging, acknowledge without signalling, or split the two across
    /// a lock hold. These four calls are also the only fsd uses of the four
    /// distinct fused core `run_r3_mount_*_signal_ack` runners.
    fn native_mount_signal_helpers_ack_before_the_registry_unlock(
        lock: &mut RegistryLockGuard,
        publication: MountDonePublication,
        conversion: MountJoinConversion,
        reset: MountResetPublication,
        release: MountResetJoinRelease,
    ) {
        let prepared = match unsafe { lock.prepare_locked_mount_done_publication(publication) } {
            Ok(prepared) => prepared,
            Err((_error, returned)) => {
                let _retained = returned;
                return;
            }
        };
        <PreparedLockedMountPublication<'_, MountDonePublication> as AmbiguousIfClone<
            _,
        >>::assert_not_clone();
        match unsafe { publish_mount_complete_locked(prepared) } {
            Ok(drain) => {
                let _ = drain;
            }
            Err((_error, acknowledgement)) => {
                let _ = acknowledgement;
            }
        }

        let prepared = match unsafe { lock.prepare_locked_mount_join_conversion(conversion) } {
            Ok(prepared) => prepared,
            Err((_error, returned)) => {
                let _retained = returned;
                return;
            }
        };
        match unsafe { publish_mount_waiters_drained_locked(prepared) } {
            Ok(ticket) => {
                let _ = ticket;
            }
            Err((_error, acknowledgement)) => {
                let _ = acknowledgement;
            }
        }

        let prepared = match unsafe { lock.prepare_locked_mount_reset_publication(reset) } {
            Ok(prepared) => prepared,
            Err((_error, returned)) => {
                let _retained = returned;
                return;
            }
        };
        match unsafe { publish_mount_reset_complete_locked(prepared) } {
            Ok(proof) => {
                let _ = proof;
            }
            Err((_error, acknowledgement)) => {
                let _ = acknowledgement;
            }
        }

        let prepared = match unsafe { lock.prepare_locked_mount_reset_join_release(release) } {
            Ok(prepared) => prepared,
            Err((_error, returned)) => {
                let _retained = returned;
                return;
            }
        };
        match unsafe { publish_mount_reset_waiters_drained_locked(prepared) } {
            Ok(proof) => {
                let _ = proof;
            }
            Err((_error, acknowledgement)) => {
                let _ = acknowledgement;
            }
        }
    }

    // Each component is a distinct affine owner, so a type alias would name
    // the shape without simplifying it.
    #[allow(clippy::type_complexity)]
    fn superseded_raw_mount_signal_helper_shape_cannot_be_restored() {
        let _: unsafe fn(
            PreparedLockedMountPublication<'_, MountDonePublication>,
        )
            -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> =
            publish_mount_complete_locked;
        let _: unsafe fn(
            PreparedLockedMountPublication<'_, MountJoinConversion>,
        ) -> Result<
            MountResetJoinTicket,
            (LifecycleError, MountJoinAcknowledgement),
        > = publish_mount_waiters_drained_locked;
        let _: unsafe fn(
            PreparedLockedMountPublication<'_, MountResetPublication>,
        )
            -> Result<MountResetProof, (LifecycleError, MountResetAcknowledgement)> =
            publish_mount_reset_complete_locked;
        let _: unsafe fn(
            PreparedLockedMountPublication<'_, MountResetJoinRelease>,
        ) -> Result<
            JoinedMountResetProof,
            (LifecycleError, MountResetJoinAcknowledgement),
        > = publish_mount_reset_waiters_drained_locked;
    }

    /// Preparing A consumes A into its aggregate; the A publisher has no
    /// parameter in which a concurrent same-kind bundle B could be substituted.
    fn same_kind_mount_publications_cannot_cross_wire_a_and_b(
        lock: &mut RegistryLockGuard,
        publication_a: MountDonePublication,
        publication_b: MountDonePublication,
    ) {
        let prepared_a = match unsafe { lock.prepare_locked_mount_done_publication(publication_a) }
        {
            Ok(prepared) => prepared,
            Err((_error, returned)) => {
                let _retained = returned;
                return;
            }
        };
        let drain_a = unsafe { publish_mount_complete_locked(prepared_a) };
        match drain_a {
            Ok(drain) => {
                let _ = drain;
            }
            Err((_error, acknowledgement)) => {
                let _ = acknowledgement;
            }
        }

        // B remains independently affine; the only way to publish it is to
        // prepare a second aggregate that owns B itself.
        match unsafe { lock.prepare_locked_mount_done_publication(publication_b) } {
            Ok(prepared_b) => match unsafe { publish_mount_complete_locked(prepared_b) } {
                Ok(drain) => {
                    let _ = drain;
                }
                Err((_error, acknowledgement)) => {
                    let _ = acknowledgement;
                }
            },
            Err((_error, returned)) => {
                let _ = returned;
            }
        }
    }

    /// Publication consumes all three rollback owners and returns the one
    /// receipt accepted by the terminal initializing-flag clear.
    fn native_mount_install_moves_complete_owner_before_device_exposure(
        cell: &mut NativeSessionCell,
        prepared: PreparedNativeMountInstall,
        reference: StrongSessionRef,
        mounted: NativeMountedDeviceOwner,
        vpb: NativeMountedVpbOwner,
    ) {
        let publication =
            unsafe { cell.commit_prepared_mount_install(prepared, reference, mounted, vpb) };
        <NativeMountOwnerPublication as AmbiguousIfClone<_>>::assert_not_clone();
        unsafe {
            publication
                .clear_device_initializing(cell.mount_rendezvous_mut())
                .unwrap_or_else(|(_error, returned)| {
                    let _ = returned;
                    unreachable!("the receipt belongs to this exact locked cell")
                });
        }
    }

    /// A wait borrows only a copy observation; the original affine ticket is
    /// still required by the following locked transition.
    fn native_mount_wait_keeps_join_authority_live(
        registry: NonNull<KernelSessionRegistry>,
        ticket: MountJoinTicket,
        cell: &mut NativeSessionCell,
    ) {
        let observation = ticket.wait_observation();
        let _waited = unsafe { wait_mount_observation(registry, observation) };
        let _conversion = unsafe { cell.release_mount_join(ticket) };
    }

    /// `TerminalWork` receives the authentic setup-deposited owners.
    ///
    /// Destruction authority is the branded `NativeSessionOwner` and the one
    /// `SessionRootReleaseRight` the publication suffix put in the cell, never
    /// a raw pointer rebuilt from the mirror.
    fn terminal_work_receives_the_original_setup_shell_and_root_owners(work: TerminalWork) {
        let locator = work.locator();
        let TerminalWork {
            locator: _,
            winner: _winner,
            terminal: _terminal,
            control,
            closing,
            shell,
            root,
        } = work;
        assert!(shell.locator() == locator);
        assert!(root.locator() == locator);
        let _reference: StrongSessionRef = control.into_reference();
        let ClosingControlOwner {
            context: _,
            lease,
            completion_obligation: _,
        } = closing;
        unsafe {
            lease.release();
        }
        // Published payloads have no direct consuming destructor. They move
        // intact into core deletion readiness and sealed prepared storage.
        let _ = shell;
        let _ = root;
    }

    // PROOF: both loop counters are bounded by SESSION_CELL_COUNT, and
    // rollback_cell_index proves every derived index is in the same array.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    const fn partial_work_item_allocation_rolls_back_in_reverse() {
        let mut slots = [0_usize; SESSION_CELL_COUNT];
        slots[0] = 1;
        slots[1] = 2;
        slots[2] = 3;
        let mut released = [0_usize; SESSION_CELL_COUNT];
        let mut step = 0;
        while step < SESSION_CELL_COUNT {
            let index = rollback_cell_index(step);
            released[step] = take_and_clear_slot(&mut slots[index], 0);
            step += 1;
        }
        assert!(released[SESSION_CELL_COUNT - 3] == 3);
        assert!(released[SESSION_CELL_COUNT - 2] == 2);
        assert!(released[SESSION_CELL_COUNT - 1] == 1);
        step = 0;
        while step < SESSION_CELL_COUNT {
            assert!(slots[step] == 0);
            step += 1;
        }
    }

    const _: () = both_admission_rundowns_initialize_before_endpoint_publication();
    const _: () = process_callback_rundown_and_blocked_event_initialize_before_registration();
    const _: () = process_callback_guard_spans_all_restarts_and_blocks_unload();
    const _: () = blocked_unload_wait_cannot_become_a_successful_drain();
    const _: () = every_cell_event_and_rundown_is_initialized_before_use();
    const _: () = partial_work_item_allocation_rolls_back_in_reverse();
}
