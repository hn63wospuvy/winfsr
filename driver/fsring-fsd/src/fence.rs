//! The staged R3 checkpoint: teardown, versioned readiness, and prepared delete.
//!
//! `driver/scripts/audit_c4_production_graph.py` proves the shape of this
//! module on every source edit. `run_terminal` below is the sole terminal
//! runner: the gate pins it as the only direct caller of the teardown,
//! preparation, and finish boundaries.
//!
//! The shape is dictated by one rule: **there is no refusal after the first
//! destructive instruction.** Every fallible check runs while the intact
//! authority packet is still owned, so a refusal returns the whole packet and
//! the generation stays retained rather than half-destroyed. The types are what
//! enforce it — `PreparedNativeFenceFinish` and `PreparedDelete` are the only
//! values that may cross into their infallible suffixes, and neither can be
//! constructed except by a preflight that already checked the whole
//! cross-product.

// MEASURED, round 19: this allow hides 28 of the 63 dead-code diagnostics
// `fsring-fsd` reports without its three module-wide allows; the count and
// the method are recorded on the one in `lifecycle.rs` (native review
// N18-3). Among them are `incomplete_from_refusal`, which round-18 evidence
// E1 independently found unreachable, and `TerminalOutcome::NotLive`, whose
// only construction is in `run_terminal_arrival`, which has no caller.
#![allow(dead_code)]

use core::ptr::NonNull;

use fsring_core::adapter::fence::{
    AuthenticatedTerminalResult, BoundCompletedMountTeardown, ClosedFenceRosterComplete,
    CompletedMountTeardown, ConsumerPrefix, ConsumerReleaseProof, ConsumerTokenSlabOwner,
    DeleteTerminalBlocked, DrainCompletedProof,
    FenceDeletionReadiness as CoreFenceDeletionReadiness, FenceKernelDdi, FencePassCursor,
    FenceReport, FenceRunOutcome, FinalDeleteProof, FinalizerDeposit as CoreFinalizerDeposit,
    KernelFenceOps, MountTeardownCallError, PendingFinalDeleteReset, PendingMountBind,
    PendingOwnerWaitFailure, PreparedConsumerDrain, PreparedDeleteStorage, PreparedRetireCall,
    R3CheckpointNativeOps, R3FailStopPreparedContinuation, R3FailStopVisibilityWake,
    R3FinalizerRunningRight, R3PreparedDeleteNativeOps, R4DeletionOwnerChain, R4DeletionTailOps,
    RefusedCheckpointTeardown, bind_completed_mount_teardown, delete_failure_requires_opaque,
    mount_teardown_permits_delete, run_r3_fail_stop_two_phase, run_r3_fail_stop_visibility_wake,
    run_r3_prepared_delete_suffix,
};
use fsring_core::adapter::lifecycle::{
    FinalizerState, LifecycleError, MountClaim, MountDrainRight, PreparedMountReset,
};
use fsring_core::session::{
    CommittedStoredFailStopResolution, DiagnosticId, DurableFailStopObservation,
    DurableFailStopSlot, FinalizerPreflightStep, PreparedReleaseKind, RegistryRelease,
    SessionLocator, SlotDisposition, StoredFailStopPublicationMode, StoredFailStopReceipt,
    StoredFailStopResolution, StrongSessionRef, TerminalBlocked, TerminalOutcomeSignal,
    TerminalRendezvous, TerminalRequest, TerminalSessionRef, commit_stored_fail_stop_visibility,
    prepare_strong_release, prepare_terminal_release,
};

use crate::control::ControlFileContext;
use crate::lifecycle::{
    AdmittedR3FinalizerKick, ClosingControlOwner, ControlStrongRef, DriverRootRelease,
    FinalizerCallbackAdmission, FinalizerHandoffRight, FinalizerWinnerResolution,
    KernelSessionRegistry, NativeSessionOwner, NativeSessionShell, OpaqueFailStopWaitPreparation,
    RegistryLockGuard, SESSION_CELL_COUNT, SessionRootReleaseRight, TerminalDisposition,
    TerminalJoinGuard, TerminalOwners, TerminalWork, prepare_native_terminal_claim,
};

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(struct $name(());)+
    };
}

private_authority_seals!(
    PrivateTerminalOutcomePublisherAuthority,
    PrivateCellResetAuthority,
    PrivatePreparedCellResetAuthority,
    PrivateOpaqueFailStopReceiptAuthority,
    PrivatePublishedFailStopReceiptAuthority,
);

enum R3FailStopPayload {
    Checkpoint(FenceIncompletePacket),
    Delete(DeleteFailStop<FinalizerDeposit>),
}

/// Opaque complete packet accepted by the permanent cell. Its heterogeneous
/// payload enum is private to this module, so sibling modules can store it but
/// cannot project either retained authority packet.
pub(crate) struct R3FailStopPacket(R3FailStopPayload);

pub(crate) struct R3FailStopSlot {
    inner: DurableFailStopSlot<R3FailStopPacket>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3FailStopObservation {
    Published,
    OpaqueRetained,
}

pub(crate) enum ClosedFailStopAuthentication {
    Published(PublishedFailStopReceipt),
    Opaque(OpaqueFailStopReceipt),
}

pub(crate) struct PublishedFailStopReceipt {
    locator: SessionLocator,
    authority: PrivatePublishedFailStopReceiptAuthority,
}

impl PublishedFailStopReceipt {
    pub(crate) fn matches(&self, locator: SessionLocator) -> bool {
        self.locator == locator
    }
}

/// Affine proof that the exact permanent slot contains an opaque quarantine.
/// It projects no packet and can only be consumed by the locked join-release
/// preparation or retained forever by its wait guard.
pub(crate) struct OpaqueFailStopReceipt {
    locator: SessionLocator,
    authority: PrivateOpaqueFailStopReceiptAuthority,
}

pub(crate) enum R3FailStopVisibility {
    Published(TerminalOutcomeSignal),
    OpaqueRetained(OpaqueFailStopReceipt),
    ReentryRetained(R3FailStopReentryGuard),
}

pub(crate) struct R3FailStopReentryGuard {
    packet: R3FailStopPacket,
}

impl R3FailStopReentryGuard {
    pub(crate) const fn retain(packet: R3FailStopPacket) -> Self {
        Self { packet }
    }
}

impl OpaqueFailStopReceipt {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

impl R3FailStopPacket {
    const fn checkpoint(packet: FenceIncompletePacket) -> Self {
        Self(R3FailStopPayload::Checkpoint(packet))
    }

    const fn delete(packet: DeleteFailStop<FinalizerDeposit>) -> Self {
        Self(R3FailStopPayload::Delete(packet))
    }

    pub(crate) const fn locator(&self) -> SessionLocator {
        match &self.0 {
            R3FailStopPayload::Checkpoint(packet) => packet.locator(),
            R3FailStopPayload::Delete(packet) => packet.locator(),
        }
    }

    const fn blocked_observation(&self) -> TerminalBlocked {
        match &self.0 {
            R3FailStopPayload::Checkpoint(packet) => packet.blocked_observation(),
            R3FailStopPayload::Delete(packet) => packet.blocked_observation(),
        }
    }

    const fn publication_mode(&self) -> StoredFailStopPublicationMode {
        match &self.0 {
            R3FailStopPayload::Checkpoint(_) => StoredFailStopPublicationMode::PublishIfExact,
            R3FailStopPayload::Delete(packet) => packet.publication_mode(),
        }
    }

    fn publication_substrate_is_exact(&self) -> bool {
        match &self.0 {
            R3FailStopPayload::Checkpoint(packet) => packet.publication_substrate_is_exact(),
            R3FailStopPayload::Delete(packet) => packet.publication_substrate_is_exact(),
        }
    }

    pub(crate) const fn is_delete(&self) -> bool {
        matches!(self.0, R3FailStopPayload::Delete(_))
    }
}

impl R3FailStopSlot {
    pub(crate) const fn new_empty() -> Self {
        Self {
            inner: DurableFailStopSlot::new_empty(),
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub(crate) fn visibility_for_locator(
        &self,
        locator: SessionLocator,
    ) -> Option<R3FailStopObservation> {
        match self.inner.observation_for(locator) {
            Some(DurableFailStopObservation::Published) => Some(R3FailStopObservation::Published),
            Some(DurableFailStopObservation::OpaqueRetained) => {
                Some(R3FailStopObservation::OpaqueRetained)
            }
            None => None,
        }
    }

    pub(crate) fn authenticate_closed_slot(
        &self,
        locator: SessionLocator,
    ) -> Option<ClosedFailStopAuthentication> {
        match self.visibility_for_locator(locator)? {
            R3FailStopObservation::Published => Some(ClosedFailStopAuthentication::Published(
                PublishedFailStopReceipt {
                    locator,
                    authority: PrivatePublishedFailStopReceiptAuthority(()),
                },
            )),
            R3FailStopObservation::OpaqueRetained => Some(ClosedFailStopAuthentication::Opaque(
                OpaqueFailStopReceipt {
                    locator,
                    authority: PrivateOpaqueFailStopReceiptAuthority(()),
                },
            )),
        }
    }

    /// Store the whole packet first, then consume the private receipt into one
    /// permanent visibility. The transient `Stored` arm cannot escape this
    /// method or the caller's registry-lock hold.
    pub(crate) unsafe fn store_and_resolve(
        &mut self,
        expected: SessionLocator,
        rendezvous: &mut TerminalRendezvous,
        finalizer: &mut fsring_core::adapter::fence::R3FinalizerCell<R4DeletionOwners>,
        commit_delete_fail_stop: bool,
        publication_event: &fsring_sys::c4::KEVENT,
        packet: R3FailStopPacket,
    ) -> Result<R3FailStopVisibility, R3FailStopPacket> {
        if packet.locator() != expected {
            return Err(packet);
        }
        // SAFETY: this is the sole production metadata projector. Both values
        // are derived by exhaustive match from the complete private packet
        // after core has moved that packet into the durable slot.
        let resolved = unsafe {
            self.inner.store_and_resolve(
                rendezvous,
                packet,
                |stored_packet| {
                    (
                        stored_packet.blocked_observation(),
                        stored_packet.publication_mode(),
                    )
                },
                |packet, receipt| {
                    // The enclosing `unsafe` block covers this closure body:
                    // it is built and run inside the same projection.
                    if commit_delete_fail_stop {
                        finalizer.commit_fail_stop_prepared();
                    }
                    let publication_event_nonsignaled = fsring_sys::c4::KeReadStateEvent(
                        core::ptr::from_ref(publication_event).cast_mut().cast(),
                    ) == 0;
                    let receipt = if publication_event_nonsignaled
                        && packet.publication_substrate_is_exact()
                    {
                        receipt
                    } else {
                        receipt.require_opaque()
                    };
                    match &packet.0 {
                        R3FailStopPayload::Checkpoint(packet) => {
                            packet.commit_fail_stop_visibility(receipt)
                        }
                        R3FailStopPayload::Delete(packet) => {
                            packet.commit_fail_stop_visibility(receipt)
                        }
                    }
                },
            )
        };
        match resolved {
            Err(packet) => Err(packet),
            Ok(StoredFailStopResolution::Published(signal)) => {
                Ok(R3FailStopVisibility::Published(signal))
            }
            Ok(StoredFailStopResolution::OpaqueRetained) => Ok(
                R3FailStopVisibility::OpaqueRetained(OpaqueFailStopReceipt {
                    locator: expected,
                    authority: PrivateOpaqueFailStopReceiptAuthority(()),
                }),
            ),
        }
    }
}

/// The sole authority to publish this generation's closed outcome.
pub(crate) struct TerminalOutcomePublisher {
    locator: SessionLocator,
    diagnostic: DiagnosticId,
    authority: PrivateTerminalOutcomePublisherAuthority,
}

/// The sole authority to reset the permanent cell after destruction.
pub(crate) struct CellResetRight {
    locator: SessionLocator,
    authority: PrivateCellResetAuthority,
}

impl CellResetRight {
    fn matches_locator(&self, expected: SessionLocator) -> bool {
        self.locator == expected
    }

    /// Consume the brand after predicate seven checked this exact locator.
    ///
    /// # Safety
    /// `self.locator == expected` was included in the successful canonical
    /// delete-preflight observation.
    unsafe fn into_prepared_prevalidated(self) -> PreparedCellResetRight {
        let Self {
            locator: _,
            authority: PrivateCellResetAuthority(()),
        } = self;
        PreparedCellResetRight {
            authority: PrivatePreparedCellResetAuthority(()),
        }
    }
}

/// Native reset authority after its locator was checked, before destruction.
pub(crate) struct PreparedCellResetRight {
    authority: PrivatePreparedCellResetAuthority,
}

impl PreparedCellResetRight {
    pub(crate) fn consume(self) {
        let Self {
            authority: PrivatePreparedCellResetAuthority(()),
        } = self;
    }
}

impl TerminalOutcomePublisher {
    fn into_parts(self) -> (SessionLocator, DiagnosticId) {
        let Self {
            locator,
            diagnostic,
            authority: PrivateTerminalOutcomePublisherAuthority(()),
        } = self;
        (locator, diagnostic)
    }
}

/// Everything a completed checkpoint hands to preparation.
///
/// It is one value, not six arguments: preparation must be able to return the
/// *whole* candidate unchanged on refusal, and a six-argument signature is how
/// a refusal ends up returning five of them.
pub(crate) struct R4CheckpointCandidate {
    complete: fsring_core::adapter::fence::FenceCompletedTerminalResult,
    terminal: TerminalSessionRef,
    closing: ClosingControlOwner,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
}

impl R4CheckpointCandidate {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.complete.locator()
    }
}

/// The one value that may enter the infallible finish.
pub(crate) struct PreparedNativeFenceFinish {
    candidate: R4CheckpointCandidate,
}

/// The FSD-only tail nested beside the two core-owned native envelopes.
pub(crate) struct R4DeletionTail {
    result: AuthenticatedTerminalResult,
    closing: ClosingControlOwner,
}

impl R4DeletionTailOps for R4DeletionTail {
    fn diagnostic(&self) -> DiagnosticId {
        self.result.diagnostic()
    }

    fn closing_live_context_and_lease(&self, locator: SessionLocator) -> bool {
        // SAFETY: this tail owns the closing context and its admission lease;
        // the registry lock protects both binding and lifetime observations.
        unsafe {
            crate::control::binding_is_closing_live(self.closing.context(), locator)
                && crate::control::lifetime_is_cell_owned(self.closing.context())
        }
    }

    fn completed_record_is_absent(&self) -> bool {
        // SAFETY: the registry lock is held and the closing owner keeps the
        // control context live through this mutation-free observation.
        unsafe { crate::control::completed_record_is_absent(self.closing.context()) }
    }

    fn publication_substrate_is_exact(&self, locator: SessionLocator) -> bool {
        self.closing_live_context_and_lease(locator) && self.completed_record_is_absent()
    }

    unsafe fn commit_fail_stop_visibility<'stored>(
        &self,
        receipt: StoredFailStopReceipt<'stored>,
    ) -> CommittedStoredFailStopResolution<'stored> {
        let context = self.closing.context();
        let binding = unsafe { crate::control::binding_mut(context) };
        let resolution = commit_stored_fail_stop_visibility(receipt, binding);
        unsafe { crate::control::publish_binding_phase(context) };
        resolution
    }
}

pub(crate) type R4DeletionOwners =
    R4DeletionOwnerChain<R4DeletionTail, NativeSessionShell, DriverRootRelease>;
pub(crate) type FenceDeletionReadiness = CoreFenceDeletionReadiness<R4DeletionOwners>;
pub(crate) type FinalizerDeposit = CoreFinalizerDeposit<R4DeletionOwners>;
type R3PreparedDeleteStorage =
    PreparedDeleteStorage<NativeSessionShell, DriverRootRelease, PreparedCellResetRight>;

/// A durable checkpoint refusal. It owns everything the generation still holds.
///
/// It has no finish, deposit, retry, or completion method by construction: a
/// packet that could resume would make "permanent fail-stop" a lie.
pub(crate) struct FenceIncompletePacket {
    progress: FenceIncompletePacketProgress,
    terminal: TerminalSessionRef,
    result: AuthenticatedTerminalResult,
    closing: ClosingControlOwner,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
    // A take-or-join completion that did not match its expectation.
    //
    // It is parked here rather than dropped because both halves matter: the
    // completion says a teardown already happened, and dropping it is how a
    // later path convinces itself it must run one — which is a second
    // `IoDeleteDevice` on a device the real owner already deleted.
    // A successfully bound mount completion whose later roster step refused.
    // Keeping it here prevents executor drop from discarding final mount-reset
    // authority after native device teardown already completed.
}

// The variants carry exactly the owners their stage must return; boxing
// the largest would add an allocation to a refusal path whose whole
// point is that it consumes nothing.
#[allow(clippy::large_enum_variant)]
enum FenceIncompletePacketProgress {
    Roster {
        cursor: FencePassCursor,
        report: FenceReport,
        complete: Option<ClosedFenceRosterComplete>,
        control: Option<ControlStrongRef>,
        pending_mount_bind: Option<PendingMountBind>,
        bound_mount: Option<BoundCompletedMountTeardown>,
    },
    Finish,
    Residual {
        residual: fsring_core::adapter::fence::FenceResidual,
        control: Option<ControlStrongRef>,
    },
}

impl FenceIncompletePacket {
    pub(crate) const fn cursor(&self) -> FencePassCursor {
        match self.progress {
            FenceIncompletePacketProgress::Roster { cursor, .. } => cursor,
            FenceIncompletePacketProgress::Finish
            | FenceIncompletePacketProgress::Residual { .. } => FencePassCursor::FinishPreparation,
        }
    }

    pub(crate) const fn locator(&self) -> SessionLocator {
        self.result.locator()
    }

    /// The exact observation a blocked publisher must publish for this packet.
    ///
    /// The diagnostic is *copied* from the authenticated result, never minted:
    /// a packet cannot relabel which generation failed.
    pub(crate) const fn blocked_observation(&self) -> TerminalBlocked {
        TerminalBlocked::from_fence(
            self.result.locator(),
            fsring_core::adapter::fence::FenceTerminalBlocked::new(
                fsring_core::adapter::fence::FenceFailStopReason::CoreInvariant,
                self.result.diagnostic(),
            ),
        )
    }

    fn publication_substrate_is_exact(&self) -> bool {
        unsafe {
            crate::control::binding_is_closing_live(self.closing.context(), self.locator())
                && crate::control::lifetime_is_cell_owned(self.closing.context())
                && crate::control::completed_record_is_absent(self.closing.context())
        }
    }

    unsafe fn commit_fail_stop_visibility<'stored>(
        &self,
        receipt: StoredFailStopReceipt<'stored>,
    ) -> CommittedStoredFailStopResolution<'stored> {
        let context = self.closing.context();
        let binding = unsafe { crate::control::binding_mut(context) };
        let resolution = commit_stored_fail_stop_visibility(receipt, binding);
        unsafe { crate::control::publish_binding_phase(context) };
        resolution
    }
}

impl R4CheckpointCandidate {
    /// The sole finish-preparation refusal conversion. It consumes the whole
    /// candidate and retains the already discharged roster, bound mount
    /// authority, terminal/result/closing owners, shell, and root together.
    pub(crate) fn into_finish_preparation_incomplete(self) -> FenceIncompletePacket {
        let Self {
            complete,
            terminal,
            closing,
            shell,
            root,
        } = self;
        FenceIncompletePacket {
            progress: FenceIncompletePacketProgress::Finish,
            terminal,
            result: complete.into_authenticated(),
            closing,
            shell,
            root,
        }
    }
}

/// What one prepared release did to the generation.
pub(crate) enum StrongReleaseDisposition {
    Retained,
    Finalizer(AdmittedR3FinalizerKick),
}

/// The two references that can be the last one out.
pub(crate) enum R4ReleaseAuthority {
    Stable(StrongSessionRef),
    Terminal(TerminalSessionRef),
}

impl R4ReleaseAuthority {
    const fn locator(&self) -> SessionLocator {
        match self {
            Self::Stable(reference) => reference.locator(),
            Self::Terminal(terminal) => terminal.locator(),
        }
    }
}

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------

/// The native side of one closed-roster effect.
///
/// Splitting the executor out is what lets the *order* be proven on a host that
/// cannot load a driver: `fsring-core` owns the roster and the stop-at-first-
/// refusal rule, and this trait owns only "perform exactly this one operation".
pub(crate) trait CheckpointExecutor:
    fsring_core::adapter::fence::R3CheckpointNativeOps
{
    /// The mismatched take-or-join pair, if the mount effect produced one.
    ///
    /// The scheduler asks for it on every refusal so the fail-stop packet
    /// retains it. An executor with nothing to report answers `None`; there is
    /// no path on which a mismatch is dropped instead of parked.
    fn take_pending_mount_bind(&mut self) -> Option<PendingMountBind> {
        None
    }

    fn take_bound_mount(&mut self) -> Option<BoundCompletedMountTeardown> {
        None
    }

    /// The control strong reference, if the roster has not released it yet.
    ///
    /// A refusal before that roster position owes it to the fail-stop packet; a
    /// refusal after it must not claim to still hold one. Asking the executor
    /// keeps a single answer: the scheduler used to track a shadow copy beside
    /// the one the executor actually owns.
    fn take_unreleased_control(&mut self) -> Option<ControlStrongRef> {
        None
    }
}

/// Predecessor 20-row roster walker. Task 25's `run_kernel_fence` is the only
/// production scheduler; this name remains only so the executor type still
/// type-checks beside the DDI methods it owns.
#[allow(dead_code)]
unsafe fn run_native_fence_pass(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    owners: TerminalOwners,
    control: ControlStrongRef,
) {
    let _ = (registry, context, owners, control);
}

#[allow(clippy::too_many_arguments)]
fn incomplete_from_refusal(
    refused: RefusedCheckpointTeardown,
    complete: Option<ClosedFenceRosterComplete>,
    terminal: TerminalSessionRef,
    result: AuthenticatedTerminalResult,
    closing: ClosingControlOwner,
    control: Option<ControlStrongRef>,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
    pending_mount_bind: Option<PendingMountBind>,
    bound_mount: Option<BoundCompletedMountTeardown>,
) -> FenceIncompletePacket {
    let (cursor, report) = refused.into_parts();
    FenceIncompletePacket {
        progress: FenceIncompletePacketProgress::Roster {
            cursor,
            report,
            complete,
            control,
            pending_mount_bind,
            bound_mount,
        },
        terminal,
        result,
        closing,
        shell,
        root,
    }
}

// ---------------------------------------------------------------------------
// Preparation and the infallible finish
// ---------------------------------------------------------------------------

/// Validate the whole candidate against the cell without mutating anything.
///
/// DEVIATION (recorded in the Task 10 evidence): the plan writes this as
/// `PreparedNativeFenceFinish::prepare`. The production-graph auditor's node
/// identity is a bare function name, and `prepare` already names a method the
/// mount path reaches — so declaring the staged rows below produced a false
/// `fsring_dispatch_mount -> mount -> prepare -> …` route. A free function with
/// a unique name is what makes this checkpoint's preparation a measurable row
/// rather than one measured only by inference.
///
/// # Safety
/// The registry lock is held and `lock` guards the live permanent root.
#[inline(never)]
pub(crate) unsafe fn prepare_finish_fence(
    lock: &mut RegistryLockGuard,
    candidate: R4CheckpointCandidate,
) -> Result<PreparedNativeFenceFinish, (LifecycleError, R4CheckpointCandidate)> {
    match unsafe { checkpoint_finish_preflight(lock, &candidate) } {
        Ok(()) => Ok(PreparedNativeFenceFinish { candidate }),
        Err(error) => Err((error, candidate)),
    }
}

/// Every fallible check the finish depends on, with nothing mutated.
///
/// # Safety
/// The registry lock is held.
unsafe fn checkpoint_finish_preflight(
    lock: &mut RegistryLockGuard,
    candidate: &R4CheckpointCandidate,
) -> Result<(), LifecycleError> {
    let locator = candidate.locator();
    // The proof, the terminal reference, the result, and both owners must all
    // name the same generation. A candidate assembled from two generations is
    // the exact shape a six-argument finish would have accepted.
    if candidate.terminal.locator() != locator
        || candidate.shell.locator() != locator
        || candidate.root.locator() != locator
        || candidate.complete.locator() != locator
    {
        return Err(LifecycleError::WrongLocator);
    }
    if !candidate.complete.pass_report().is_complete() {
        return Err(LifecycleError::Invariant);
    }
    unsafe { cell_finish_preflight(lock, locator) }
}

/// # Safety
/// The registry lock is held.
unsafe fn cell_finish_preflight(
    lock: &mut RegistryLockGuard,
    locator: SessionLocator,
) -> Result<(), LifecycleError> {
    let Some(cell) = (unsafe { lock.cell_ptr(locator.slot_index()) }) else {
        return Err(LifecycleError::WrongLocator);
    };
    // SAFETY: the lock is held and the index is in range.
    unsafe { (*cell).checkpoint_finish_preflight(locator) }
}

/// Move the candidate into readiness and take the sole release boundary.
///
/// It cannot refuse: every fallible check ran in `prepare`, and the retained
/// terminal reference inside the aggregate is what stops a second finish.
///
/// # Safety
/// The registry lock is held and `prepared` was produced by `prepare` in this
/// same lock hold.
#[inline(never)]
pub(crate) unsafe fn finish_fence(
    lock: &mut RegistryLockGuard,
    prepared: PreparedNativeFenceFinish,
) -> StrongReleaseDisposition {
    let PreparedNativeFenceFinish { candidate } = prepared;
    let R4CheckpointCandidate {
        complete,
        terminal,
        closing,
        shell,
        root,
    } = candidate;
    let (authenticated, mount, locator) = complete.split_for_deletion_tail();
    let tail = R4DeletionTail {
        result: authenticated,
        closing,
    };
    let readiness = unsafe {
        fsring_core::adapter::fence::FenceCompletedTerminalResult::bind_deletion_owners_from_split(
            locator, mount, tail, shell, root,
        )
    };
    match unsafe {
        release_strong_and_deposit(
            lock,
            R4ReleaseAuthority::Terminal(terminal),
            Some(readiness),
        )
    } {
        Ok(disposition) => disposition,
        Err(_) => {
            unreachable!("the prepared finish preflighted the whole release cross-product")
        }
    }
}

// ---------------------------------------------------------------------------
// The sole release/deposit boundary
// ---------------------------------------------------------------------------

/// The only route from a reference release to a queued finalizer.
///
/// Its result never contains a bare right or a bare readiness. That is the
/// point: the right is minted and combined with the readiness inside one lock
/// hold, so no local caller can be holding deletion authority on its own.
///
/// # Safety
/// The registry lock is held and `registry` is the live permanent root.
#[allow(clippy::type_complexity)]
pub(crate) unsafe fn release_strong_and_deposit(
    lock: &mut RegistryLockGuard,
    authority: R4ReleaseAuthority,
    readiness: Option<FenceDeletionReadiness>,
) -> Result<
    StrongReleaseDisposition,
    (
        LifecycleError,
        R4ReleaseAuthority,
        Option<FenceDeletionReadiness>,
    ),
> {
    let locator = authority.locator();
    if let Some(present) = readiness.as_ref() {
        if present.locator() != locator {
            return Err((LifecycleError::WrongLocator, authority, readiness));
        }
    }

    let core = unsafe { lock.core_ptr() };
    let Some(cell) = (unsafe { lock.cell_ptr(locator.slot_index()) }) else {
        return Err((LifecycleError::WrongLocator, authority, readiness));
    };

    // SAFETY: the lock is held; core and cell are disjoint fields of the root.
    let core = unsafe { &mut *core };
    let prepared = match authority {
        R4ReleaseAuthority::Stable(reference) => match prepare_strong_release(core, reference) {
            Ok(prepared) => PreparedRelease::Stable(prepared),
            Err((_error, reference)) => {
                return Err((
                    LifecycleError::WrongState,
                    R4ReleaseAuthority::Stable(reference),
                    readiness,
                ));
            }
        },
        R4ReleaseAuthority::Terminal(terminal) => match prepare_terminal_release(core, terminal) {
            Ok(prepared) => PreparedRelease::Terminal(prepared),
            Err((_error, terminal)) => {
                return Err((
                    LifecycleError::WrongState,
                    R4ReleaseAuthority::Terminal(terminal),
                    readiness,
                ));
            }
        },
    };

    // A release that will delete needs the readiness now; one that will not must
    // not be handed one to store twice.
    let deletes = matches!(prepared.kind(), PreparedReleaseKind::Delete);
    // SAFETY: the lock is held and the index is in range.
    let native =
        unsafe { (*cell).release_deposit_preflight(locator, deletes, readiness.is_some()) };
    if let Err(error) = native {
        return Err((error, prepared.into_authority(), readiness));
    }

    // Queue-to-callback rundown is acquired while the exact intact release
    // packet is still owned and this registry lock still protects the
    // deposit->Queued transition. Effect seven cannot race a late acquisition
    // after closing its software door.
    let finalizer_admission = if deletes {
        match unsafe { FinalizerCallbackAdmission::acquire_locked(lock, locator) } {
            Some(admission) => Some(admission),
            None => {
                return Err((
                    LifecycleError::WrongState,
                    prepared.into_authority(),
                    readiness,
                ));
            }
        }
    } else {
        None
    };

    // Past this point nothing can refuse.
    // SAFETY: the prepared release preflighted this exact slot in this hold.
    let released = unsafe { prepared.commit() };
    match released {
        RegistryRelease::Retained => {
            if let Some(readiness) = readiness {
                // SAFETY: the preflight proved the slot empty and the worker idle.
                unsafe { (*cell).park_readiness(readiness) };
            }
            Ok(StrongReleaseDisposition::Retained)
        }
        RegistryRelease::Delete(right) => {
            let readiness = match readiness {
                Some(readiness) => readiness,
                None => {
                    // SAFETY: the preflight proved a parked readiness exists.
                    match unsafe { (*cell).take_parked_readiness(locator) } {
                        Some(readiness) => readiness,
                        None => unreachable!(
                            "the release preflight proved exactly one readiness is available"
                        ),
                    }
                }
            };
            let kick =
                unsafe { (*cell).store_deposit_and_mint_kick_prevalidated(readiness, right) };
            let admission = match finalizer_admission {
                Some(admission) => admission,
                None => unreachable!("a deleting release pre-acquired finalizer admission"),
            };
            Ok(StrongReleaseDisposition::Finalizer(unsafe {
                AdmittedR3FinalizerKick::new_prevalidated(kick, admission)
            }))
        }
    }
}

enum PreparedRelease<'objects> {
    Stable(fsring_core::session::PreparedStrongRelease<'objects, { SESSION_CELL_COUNT }>),
    Terminal(fsring_core::session::PreparedTerminalRelease<'objects, { SESSION_CELL_COUNT }>),
}

impl PreparedRelease<'_> {
    fn kind(&self) -> PreparedReleaseKind {
        match self {
            Self::Stable(prepared) => prepared.kind(),
            Self::Terminal(prepared) => prepared.kind(),
        }
    }

    /// Recover the exact affine input for a refusal that mutated nothing.
    fn into_authority(self) -> R4ReleaseAuthority {
        // A prepared release borrows the registry and owns its reference; the
        // reference is what a refusal owes the caller back.
        match self {
            Self::Stable(prepared) => R4ReleaseAuthority::Stable(prepared.into_reference()),
            Self::Terminal(prepared) => R4ReleaseAuthority::Terminal(prepared.into_terminal()),
        }
    }

    /// # Safety
    /// Same contract as the core prepared-release commits.
    unsafe fn commit(self) -> RegistryRelease {
        match self {
            Self::Stable(prepared) => unsafe { prepared.commit() },
            Self::Terminal(prepared) => unsafe { prepared.commit() },
        }
    }
}

// ---------------------------------------------------------------------------
// Prepared deletion
// ---------------------------------------------------------------------------

/// The one value that may cross the first destructive instruction.
pub(crate) struct PreparedDelete {
    storage: R3PreparedDeleteStorage,
    tail: R4DeletionTail,
    publisher: TerminalOutcomePublisher,
}

/// A deletion preflight that refused. It owns the entire intact deposit.
pub(crate) struct DeleteFailStop<Deposit> {
    deposit: Deposit,
    running: R3FinalizerRunningRight,
    publisher: TerminalOutcomePublisher,
    reset: CellResetRight,
    step: FinalizerPreflightStep,
    diagnostic: DiagnosticId,
}

impl<Deposit> DeleteFailStop<Deposit> {
    /// The exact observation this fail-stop publishes.
    pub(crate) const fn blocked_observation(&self) -> TerminalBlocked {
        TerminalBlocked::from_delete(
            self.publisher.locator,
            DeleteTerminalBlocked::new(self.step, self.diagnostic),
        )
    }

    pub(crate) const fn locator(&self) -> SessionLocator {
        self.publisher.locator
    }

    const fn publication_mode(&self) -> StoredFailStopPublicationMode {
        if delete_failure_requires_opaque(self.step) {
            StoredFailStopPublicationMode::RequireOpaque
        } else {
            StoredFailStopPublicationMode::PublishIfExact
        }
    }

    fn publication_substrate_is_exact(&self) -> bool
    where
        Deposit: R4DeleteFailStopVisibility,
    {
        self.deposit.delete_publication_substrate_is_exact()
    }

    unsafe fn commit_fail_stop_visibility<'stored>(
        &self,
        receipt: StoredFailStopReceipt<'stored>,
    ) -> CommittedStoredFailStopResolution<'stored>
    where
        Deposit: R4DeleteFailStopVisibility,
    {
        unsafe { self.deposit.commit_delete_fail_stop_visibility(receipt) }
    }
}

trait R4DeleteFailStopVisibility {
    fn delete_publication_substrate_is_exact(&self) -> bool;
    unsafe fn commit_delete_fail_stop_visibility<'stored>(
        &self,
        receipt: StoredFailStopReceipt<'stored>,
    ) -> CommittedStoredFailStopResolution<'stored>;
}

impl R4DeleteFailStopVisibility for FinalizerDeposit {
    fn delete_publication_substrate_is_exact(&self) -> bool {
        self.publication_substrate_is_exact()
    }
    unsafe fn commit_delete_fail_stop_visibility<'stored>(
        &self,
        receipt: StoredFailStopReceipt<'stored>,
    ) -> CommittedStoredFailStopResolution<'stored> {
        unsafe { self.commit_fail_stop_visibility(receipt) }
    }
}

/// Build the one value that may cross the first destructive instruction.
///
/// Every fallible check runs while the intact `FinalizerDeposit` is still
/// owned by this call, so a refusal returns that exact deposit — including the
/// shell and root owners inside its readiness — and destroys nothing. Only on
/// success is the deposit destructured, its right consumed by
/// `prepare_finish_delete`, and the *readiness* — never the consumed deposit —
/// moved beside the core commit.
///
/// # Safety
/// The registry lock is held and `running` proves this callback is the running
/// finalizer for this exact generation.
#[allow(clippy::result_large_err)]
pub(crate) unsafe fn prepare_final_delete(
    lock: &mut RegistryLockGuard,
    deposit: FinalizerDeposit,
    running: R3FinalizerRunningRight,
) -> Result<PreparedDelete, DeleteFailStop<FinalizerDeposit>> {
    let locator = deposit.locator();
    let diagnostic = deposit.diagnostic();
    let publisher = TerminalOutcomePublisher {
        locator,
        diagnostic,
        authority: PrivateTerminalOutcomePublisherAuthority(()),
    };
    let reset = CellResetRight {
        locator,
        authority: PrivateCellResetAuthority(()),
    };
    // SAFETY: the lock is held; the cell index came from a validated locator.
    let observation = match unsafe { observe_delete_preflight(lock, locator) } {
        Some(observation) => observation,
        None => {
            return Err(DeleteFailStop {
                deposit,
                running,
                publisher,
                reset,
                step: FinalizerPreflightStep::MirrorAndShell,
                diagnostic,
            });
        }
    };
    let core = unsafe { &*lock.core_ptr() };
    let observation = fsring_core::adapter::fence::DeletePreflightObservation {
        core_deleting_with_exact_right: deposit.validate_final_delete_core(core).is_ok(),
        closing_live_context_and_lease: deposit.closing_live_context_and_lease(),
        completed_record_absent: deposit.completed_record_is_absent(),
        running_with_sole_authorities: observation.running_with_sole_authorities
            && running.locator() == locator
            && reset.matches_locator(locator)
            && publisher.locator == locator,
        ..observation
    };
    if let Err(step) = fsring_core::adapter::fence::decide_delete_preflight(observation) {
        return Err(DeleteFailStop {
            deposit,
            running,
            publisher,
            reset,
            step,
            diagnostic,
        });
    }

    // Past this point nothing may refuse. The borrowed core predicate above
    // makes this consuming transition an exact-match commit; a disagreement is
    // a fail-stop invariant breach, still before native destruction.
    let (readiness, commit) = match deposit.prepare_final_delete_core(core) {
        Ok(prepared) => prepared,
        Err((_error, deposit)) => {
            // The observation said the core slot was Deleting at this exact
            // right, so this is unreachable — but reconstructing the deposit
            // rather than panicking keeps the "no destruction on refusal" rule
            // true even if the two ever disagree.
            return Err(DeleteFailStop {
                deposit,
                running,
                publisher,
                reset,
                step: FinalizerPreflightStep::CoreDeleting,
                diagnostic,
            });
        }
    };
    // SAFETY: predicate seven checked the native reset brand before the
    // consuming core transition, and nothing mutated that brand.
    let reset = unsafe { reset.into_prepared_prevalidated() };
    // SAFETY: the intact deposit, core validation, running right and branded
    // native reset were all checked against `locator` above while refusal was
    // still possible. This transition only moves them into sealed storage.
    let (tail, storage) =
        unsafe { readiness.into_prepared_delete_storage_prevalidated(commit, running, reset) };
    Ok(PreparedDelete {
        storage,
        tail,
        publisher,
    })
}

/// Read the cell half of the deletion cross-product. It mutates nothing.
///
/// # Safety
/// The registry lock is held.
unsafe fn observe_delete_preflight(
    lock: &mut RegistryLockGuard,
    locator: SessionLocator,
) -> Option<fsring_core::adapter::fence::DeletePreflightObservation> {
    let cell = unsafe { lock.cell_ptr(locator.slot_index()) }?;
    // SAFETY: the lock is held and the index is in range.
    Some(unsafe { (*cell).delete_preflight_observation(locator) })
}

/// Affine record that the terminal outcome signal ran and the already-counted
/// population may now drain. The locator comes from the prepared publisher,
/// not from a copied argument to a later operation.
struct SignalledCountedArrivals {
    locator: SessionLocator,
}

/// Affine handoff from the explicit drain step to the blocking drained wait.
struct PreparedJoinersDrainedWait {
    locator: SessionLocator,
}

/// The explicit result of logical step nine. `Retired` consumes the step while
/// deliberately skipping the reinitialization DDI.
enum PreparedRundownDisposition {
    Reinitialized,
    RetiredWithoutReinitialize,
}

/// Private FSD implementation of the core-owned prepared-delete runner.
///
/// The fields that move between named operations are affine local records, so
/// no operation is an empty acknowledgement and the blocking wait cannot be
/// reached before the explicit counted-arrival drain transition.
struct NativePreparedDeleteOps {
    registry: NonNull<KernelSessionRegistry>,
    authentic_locator: SessionLocator,
    tail: Option<R4DeletionTail>,
    publisher: Option<TerminalOutcomePublisher>,
    outcome_signal: Option<TerminalOutcomeSignal>,
    signalled_arrivals: Option<SignalledCountedArrivals>,
    prepared_wait: Option<PreparedJoinersDrainedWait>,
    rundown_disposition: Option<PreparedRundownDisposition>,
}

impl NativePreparedDeleteOps {
    fn new(
        registry: NonNull<KernelSessionRegistry>,
        tail: R4DeletionTail,
        publisher: TerminalOutcomePublisher,
    ) -> Self {
        Self {
            registry,
            authentic_locator: publisher.locator,
            tail: Some(tail),
            publisher: Some(publisher),
            outcome_signal: None,
            signalled_arrivals: None,
            prepared_wait: None,
            rundown_disposition: None,
        }
    }
}

unsafe impl R3PreparedDeleteNativeOps<PreparedCellResetRight> for NativePreparedDeleteOps {
    unsafe fn transfer_closing_owner_to_completed_record_and_publish_outcome(
        &mut self,
        _locator: SessionLocator,
    ) {
        // SAFETY: the core runner invokes this first and exactly once. Both
        // owners came from the same PreparedDelete aggregate as its storage.
        let tail = unsafe { self.tail.take().unwrap_unchecked() };
        let publisher = unsafe { self.publisher.take().unwrap_unchecked() };
        let R4DeletionTail { result, closing } = tail;
        let (winner, terminal_result) = result.into_parts();
        self.outcome_signal = Some(unsafe {
            publish_completed_generation(self.registry, publisher, closing, winner, terminal_result)
        });
    }

    unsafe fn signal_terminal_outcome(&mut self, _locator: SessionLocator) {
        // SAFETY: the preceding fused publication produced the one signal and
        // the runner cannot replay this operation.
        let signal = unsafe { self.outcome_signal.take().unwrap_unchecked() };
        unsafe { crate::lifecycle::signal_terminal_outcome(self.registry, signal) };
        self.signalled_arrivals = Some(SignalledCountedArrivals {
            locator: self.authentic_locator,
        });
    }

    unsafe fn drain_counted_arrivals(&mut self, _locator: SessionLocator) {
        // This consuming handoff is the logical drain operation: signalling
        // has closed the producer side, and only its affine record can prepare
        // the later blocking wait.
        let signalled = unsafe { self.signalled_arrivals.take().unwrap_unchecked() };
        self.prepared_wait = Some(PreparedJoinersDrainedWait {
            locator: signalled.locator,
        });
    }

    unsafe fn wait_joiners_drained(&mut self, _locator: SessionLocator) {
        // SAFETY: the prepared wait was minted by the immediately preceding
        // drain step; the lifecycle helper drops its registry lock before the
        // blocking KeWaitForSingleObject call.
        let wait = unsafe { self.prepared_wait.take().unwrap_unchecked() };
        unsafe { crate::lifecycle::wait_joiners_drained(self.registry, wait.locator) };
    }

    unsafe fn complete_access_rundown(&mut self, _locator: SessionLocator) {
        unsafe {
            crate::lifecycle::complete_cell_access_rundown(self.registry, self.authentic_locator)
        };
    }

    unsafe fn reinitialize_access_rundown_if_reusable(
        &mut self,
        _locator: SessionLocator,
        disposition: SlotDisposition,
    ) {
        self.rundown_disposition = Some(match disposition {
            SlotDisposition::Free => {
                unsafe {
                    crate::lifecycle::reinitialize_cell_access_rundown(
                        self.registry,
                        self.authentic_locator,
                    )
                };
                PreparedRundownDisposition::Reinitialized
            }
            SlotDisposition::Retired => PreparedRundownDisposition::RetiredWithoutReinitialize,
        });
    }

    unsafe fn reset_cell_and_publish_disposition(
        &mut self,
        pending: PendingFinalDeleteReset<PreparedCellResetRight>,
    ) -> FinalDeleteProof {
        // SAFETY: step nine always records either the real Free DDI or the
        // explicit Retired skip before the core runner can hand us this final
        // consuming cursor.
        let _rundown_disposition = unsafe { self.rundown_disposition.take().unwrap_unchecked() };
        unsafe { crate::lifecycle::reset_cell_and_publish(self.registry, pending) }
    }
}

impl PreparedDelete {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.publisher.locator
    }

    pub(crate) const fn diagnostic(&self) -> DiagnosticId {
        self.publisher.diagnostic
    }

    /// Consume the sealed aggregate through the ten-step infallible suffix.
    /// No payload or authority is returned to the caller.
    unsafe fn execute(self, registry: NonNull<KernelSessionRegistry>) {
        let Self {
            storage,
            tail,
            publisher,
        } = self;
        let mut native = NativePreparedDeleteOps::new(registry, tail, publisher);
        let _proof = unsafe { run_r3_prepared_delete_suffix(storage, &mut native) };
    }
}

/// The production executor for the closed R3 roster.
///
/// It performs each effect concretely and answers `false` the moment one
/// refuses. Nothing is deferred and nothing inapplicable is reported as
/// success: every session-local operation crosses its own closed owner method,
/// while registry-side operations run here against the registry and control
/// context this generation actually owns.
pub(crate) struct NativeCheckpointExecutor<'owners> {
    registry: NonNull<KernelSessionRegistry>,
    shell: &'owners NativeSessionOwner,
    locator: SessionLocator,
    context: NonNull<ControlFileContext>,
    /// Consumed at `ReleaseControlStrongRef`, which is its approved roster
    /// position and the only place it may go.
    control: Option<ControlStrongRef>,
    /// The take-or-join pair the mount effect could not bind, if any.
    pending_mount_bind: Option<PendingMountBind>,
    /// The bound completion, once the mount effect produced one. Only this
    /// satisfies the roster's `DismountAndDeleteDevices`.
    bound_mount: Option<BoundCompletedMountTeardown>,
}

impl<'owners> NativeCheckpointExecutor<'owners> {
    /// # Safety
    /// `registry` is the live permanent root, `shell` is this generation's
    /// intact core owner, and `context` is the control context recorded for it.
    pub(crate) const unsafe fn new(
        registry: NonNull<KernelSessionRegistry>,
        shell: &'owners NativeSessionOwner,
        context: NonNull<ControlFileContext>,
        control: ControlStrongRef,
    ) -> Self {
        unsafe { Self::resume(registry, shell, context, Some(control)) }
    }

    /// Reconstruct the executor for a residual retry. `control` is `None` when
    /// the first pass already released it at its roster position.
    pub(crate) const unsafe fn resume(
        registry: NonNull<KernelSessionRegistry>,
        shell: &'owners NativeSessionOwner,
        context: NonNull<ControlFileContext>,
        control: Option<ControlStrongRef>,
    ) -> Self {
        Self {
            registry,
            shell,
            locator: shell.locator(),
            context,
            control,
            pending_mount_bind: None,
            bound_mount: None,
        }
    }

    unsafe fn session_ptr(&self) -> *mut crate::session::NativeSession {
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let session = match unsafe { lock.cell_ptr(self.locator.slot_index()) } {
            Some(cell) => unsafe { (*cell).session_mirror() },
            None => core::ptr::null_mut(),
        };
        unsafe { lock.release() };
        session
    }

    /// The address of this generation's pending runtime, or null.
    ///
    /// Read under the registry lock and used after it. That is sound and it is
    /// not a shortcut: the runtime is installed once by the locked publication
    /// suffix and taken once by this same checkpoint's
    /// `ReleaseTransientBacking`, the permanent cell that holds it never moves,
    /// and the three rows below must not hold the registry lock -- two of them
    /// take per-slot spin locks and one of them blocks.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held.
    unsafe fn pending_runtime_ptr(&self) -> *const crate::pending_enter::PendingRuntimeReady {
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let runtime = match unsafe { lock.cell_ptr(self.locator.slot_index()) } {
            // SAFETY: the cell is the permanent per-slot storage and the lock is
            // held for the whole borrow below.
            Some(cell) => unsafe { (*cell).pending_runtime() }
                .map_or(core::ptr::null(), |runtime| runtime as *const _),
            None => core::ptr::null(),
        };
        unsafe { lock.release() };
        runtime
    }

    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held.
    unsafe fn wait_access_rundown(&self) -> bool {
        // The rundown object is the cell's own permanent storage, so the
        // pointer stays valid without the lock — and the lock must not be held,
        // because the wait below blocks.
        let Some(rundown) = (unsafe {
            self.registry
                .as_ref()
                .access_rundown_ptr(self.locator.slot_index())
        }) else {
            return false;
        };
        // SAFETY: the permanent cell outlives every generation, and this runs
        // at PASSIVE_LEVEL as the roster requires.
        unsafe { fsring_sys::ExWaitForRundownProtectionRelease(rundown) };
        true
    }

    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held.
    unsafe fn release_control_strong_ref(&mut self) -> bool {
        let Some(control) = self.control.take() else {
            // Reaching the release position twice would be a roster bug, and
            // reporting success for a release that did not happen is exactly
            // what this checkpoint must not do.
            return false;
        };
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let outcome = unsafe {
            release_strong_and_deposit(
                &mut lock,
                R4ReleaseAuthority::Stable(control.into_reference()),
                None,
            )
        };
        unsafe { lock.release() };
        match outcome {
            // The control reference is never the last one out: the terminal
            // reference is still held by the runner that is executing this
            // roster, so a Finalizer disposition here would mean the count was
            // already wrong.
            Ok(StrongReleaseDisposition::Retained) => true,
            Ok(StrongReleaseDisposition::Finalizer(_kick)) => unsafe {
                // The terminal runner still owns its terminal reference, so
                // this stable control release cannot be the last reference.
                // Treating the impossible capability as unreachable preserves
                // queue_cell_finalizer as the sole production kick sink.
                core::hint::unreachable_unchecked()
            },
            Err((_error, authority, readiness)) => {
                if let R4ReleaseAuthority::Stable(reference) = authority {
                    self.control = Some(ControlStrongRef::from_reference(reference));
                }
                let _ = readiness;
                false
            }
        }
    }

    /// Release the mount owner's stable reference through the one approved
    /// registry boundary. The terminal reference is still held, so this exact
    /// release is necessarily retained.
    ///
    /// # Safety
    /// No registry or VPB lock is held and `reference` came from this claim's
    /// authentic mount owner.
    unsafe fn release_mount_reference(&self, reference: StrongSessionRef) {
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let outcome = unsafe {
            release_strong_and_deposit(&mut lock, R4ReleaseAuthority::Stable(reference), None)
        };
        unsafe { lock.release() };
        match outcome {
            Ok(StrongReleaseDisposition::Retained) => {}
            Ok(StrongReleaseDisposition::Finalizer(_)) => {
                unreachable!("the terminal owner keeps a mount release nonfinal")
            }
            Err(_) => unreachable!("the mount-owner release cross-product was fixed by claim"),
        }
    }

    /// Wait while retaining the affine authority that produced `observation`.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no lock held.
    unsafe fn wait_mount(
        &self,
        observation: fsring_core::adapter::lifecycle::MountWaitObservation,
    ) {
        if !unsafe { crate::lifecycle::wait_mount_observation(self.registry, observation) } {
            unreachable!("an authentic mount wait observation names its permanent cell")
        }
    }

    /// Close ordinary Join admission after every waiter from the current
    /// observation has left.
    ///
    /// A Join may be admitted after the drained event wakes this Owner but
    /// before it acquires the registry lock. Core returns the same affine drain
    /// right with `AdmissionClosed`; the Join admission cleared the event in
    /// that same lock hold, so the next wait blocks until the new waiter leaves.
    /// No destructive Owner work or signal is inside this loop.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no lock held, and `drain` belongs to this cell's
    /// authentic Owner claim.
    unsafe fn wait_until_mount_drained(&self, mut drain: MountDrainRight) -> PreparedMountReset {
        loop {
            unsafe { self.wait_mount(drain.wait_observation()) };
            let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
            let cell = unsafe {
                lock.cell_ptr(self.locator.slot_index())
                    .unwrap_or_else(|| unreachable!())
            };
            match unsafe { (*cell).mount_rendezvous_mut() }.poll_drain(drain) {
                Ok(prepared) => {
                    unsafe { lock.release() };
                    return prepared;
                }
                Err((LifecycleError::AdmissionClosed, returned)) => {
                    unsafe { lock.release() };
                    drain = returned;
                }
                Err((_error, returned)) => {
                    unsafe { lock.release() };
                    let _retained = returned;
                    unreachable!("an authentic drain right can only race a late ordinary Join")
                }
            }
        }
    }

    fn delete_shell_vdo(&self) {
        if !self.shell.checkpoint_delete_vdo_once() {
            unreachable!("the affine native shell owns a live take-once VDO slot")
        }
    }

    /// Bind one authentic claim completion, then and only then consume the
    /// terminal shell's take-once VDO slot.
    ///
    /// The mounted device, VPB, and mount reference remain Owner-only. The VDO
    /// instead belongs to the unique terminal shell, so this shared suffix also
    /// covers a session that reaches terminal teardown before its first mount.
    /// A bind refusal retains the pending pair and leaves the VDO untouched.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no registry or VPB lock held; `expected` and
    /// `completed` came from the same authentic take-or-join attempt.
    unsafe fn bind_mount_completion_and_delete_shell_vdo(
        &mut self,
        expected: fsring_core::adapter::lifecycle::ExpectedMountTeardown,
        completed: CompletedMountTeardown,
    ) -> bool {
        match bind_completed_mount_teardown(expected, completed) {
            Ok(bound) => {
                let permitted = mount_teardown_permits_delete(&bound);
                self.bound_mount = Some(bound);
                self.delete_shell_vdo();
                permitted
            }
            Err(pending) => {
                self.pending_mount_bind = Some(pending);
                false
            }
        }
    }

    /// Finish the sole Owner path after the registry claim moved every native
    /// owner to this executor.
    ///
    /// # Safety
    /// PASSIVE_LEVEL, no lock held, and the claim belongs to `self.locator`.
    unsafe fn complete_mount_owner(
        &self,
        owner: fsring_core::adapter::lifecycle::MountOwner<
            crate::lifecycle::NativeMountedDeviceOwner,
            crate::lifecycle::NativeMountedVpbOwner,
        >,
        teardown: fsring_core::adapter::lifecycle::MountTeardownRight,
    ) -> CompletedMountTeardown {
        struct NativeMountOwnerPrefix<'executor, 'owners>(
            &'executor NativeCheckpointExecutor<'owners>,
        );

        impl
            fsring_core::adapter::lifecycle::R3MountOwnerTeardownOps<
                crate::lifecycle::NativeMountedDeviceOwner,
                crate::lifecycle::NativeMountedVpbOwner,
            > for NativeMountOwnerPrefix<'_, '_>
        {
            fn clear_vpb_binding(&mut self, vpb: crate::lifecycle::NativeMountedVpbOwner) {
                // SAFETY: the owner claim transferred the unique VPB binding
                // owner here with no registry lock held.
                unsafe { vpb.clear_binding() };
            }

            fn delete_mounted_device(
                &mut self,
                mounted: crate::lifecycle::NativeMountedDeviceOwner,
            ) {
                // SAFETY: the immediately preceding named operation cleared
                // this device's unique VPB binding and released its lock.
                unsafe { mounted.delete() };
            }

            fn release_mount_reference(&mut self, reference: StrongSessionRef) {
                // SAFETY: this exact reference was consumed from the same
                // authentic owner, after both native device operations.
                unsafe { self.0.release_mount_reference(reference) };
            }
        }

        let teardown = match fsring_core::adapter::lifecycle::run_r3_mount_owner_teardown_prefix(
            owner,
            teardown,
            &mut NativeMountOwnerPrefix(self),
        ) {
            Ok(teardown) => teardown,
            Err((_error, returned_owner, returned_teardown)) => {
                let _retained = (returned_owner, returned_teardown);
                unreachable!("one Owner claim binds its owner and teardown continuation")
            }
        };

        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe {
            lock.cell_ptr(self.locator.slot_index())
                .unwrap_or_else(|| unreachable!())
        };
        let publication = match unsafe { (*cell).mount_rendezvous_mut() }.publish_done(teardown) {
            Ok(publication) => publication,
            Err((_error, returned)) => {
                let _retained = returned;
                unreachable!("the Owner claim left its rendezvous TearingDown")
            }
        };
        let prepared_publication =
            match unsafe { lock.prepare_locked_mount_done_publication(publication) } {
                Ok(prepared) => prepared,
                Err((_error, returned)) => {
                    let _retained = returned;
                    unreachable!("the Done publication authenticates its exact permanent cell")
                }
            };
        let drain = match unsafe {
            crate::lifecycle::publish_mount_complete_locked(prepared_publication)
        } {
            Ok(drain) => drain,
            Err((_error, acknowledgement)) => {
                let _retained = acknowledgement;
                unreachable!("the fused complete signal acknowledges the same generation")
            }
        };
        unsafe { lock.release() };

        let prepared = unsafe { self.wait_until_mount_drained(drain) };
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe {
            lock.cell_ptr(self.locator.slot_index())
                .unwrap_or_else(|| unreachable!())
        };
        let reset = match unsafe { (*cell).mount_rendezvous_mut() }.finish_reset(prepared) {
            Ok(reset) => reset,
            Err((_error, returned)) => {
                let _retained = returned;
                unreachable!("the reset was prepared for this exact generation")
            }
        };
        let prepared_publication =
            match unsafe { lock.prepare_locked_mount_reset_publication(reset) } {
                Ok(prepared) => prepared,
                Err((_error, returned)) => {
                    let _retained = returned;
                    unreachable!("the reset publication authenticates its exact permanent cell")
                }
            };
        let proof = match unsafe {
            crate::lifecycle::publish_mount_reset_complete_locked(prepared_publication)
        } {
            Ok(proof) => proof,
            Err((_error, acknowledgement)) => {
                let _retained = acknowledgement;
                unreachable!("the fused reset signal acknowledges the same generation")
            }
        };
        unsafe { lock.release() };
        unsafe { self.wait_mount(proof.wait_observation()) };

        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe {
            lock.cell_ptr(self.locator.slot_index())
                .unwrap_or_else(|| unreachable!())
        };
        let completion = match unsafe { (*cell).mount_rendezvous() }.complete_owner(proof) {
            Ok(completion) => completion,
            Err((_error, returned)) => {
                let _retained = returned;
                unreachable!("reset-waiter drain proves Owner completion")
            }
        };
        unsafe { lock.release() };
        CompletedMountTeardown::from_owner(completion)
    }

    /// Finish either ordinary Join or ResetJoin from the point where a reset
    /// ticket exists.
    ///
    /// # Safety
    /// PASSIVE_LEVEL, no lock held, and the ticket belongs to this cell.
    unsafe fn complete_mount_reset_join(
        &self,
        ticket: fsring_core::adapter::lifecycle::MountResetJoinTicket,
    ) -> CompletedMountTeardown {
        unsafe { self.wait_mount(ticket.wait_observation()) };
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe {
            lock.cell_ptr(self.locator.slot_index())
                .unwrap_or_else(|| unreachable!())
        };
        let release = match unsafe { (*cell).mount_rendezvous_mut() }.finish_joined_reset(ticket) {
            Ok(release) => release,
            Err((_error, returned)) => {
                let _retained = returned;
                unreachable!("reset completion admits this counted reset waiter")
            }
        };
        let prepared_publication =
            match unsafe { lock.prepare_locked_mount_reset_join_release(release) } {
                Ok(prepared) => prepared,
                Err((_error, returned)) => {
                    let _retained = returned;
                    unreachable!("the reset release authenticates its exact permanent cell")
                }
            };
        let proof = match unsafe {
            crate::lifecycle::publish_mount_reset_waiters_drained_locked(prepared_publication)
        } {
            Ok(proof) => proof,
            Err((_error, acknowledgement)) => {
                let _retained = acknowledgement;
                unreachable!("the fused reset-waiter signal acknowledges the same generation")
            }
        };
        unsafe { lock.release() };
        unsafe { self.wait_mount(proof.wait_observation()) };

        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe {
            lock.cell_ptr(self.locator.slot_index())
                .unwrap_or_else(|| unreachable!())
        };
        let completion = match unsafe { (*cell).mount_rendezvous() }.complete_joined(proof) {
            Ok(completion) => completion,
            Err((_error, returned)) => {
                let _retained = returned;
                unreachable!("the last reset-waiter acknowledgement completes Join")
            }
        };
        unsafe { lock.release() };
        CompletedMountTeardown::from_joined(completion)
    }

    /// Finish an ordinary Join, including its transfer to the reset-waiter
    /// population.
    ///
    /// # Safety
    /// PASSIVE_LEVEL, no lock held, and the ticket belongs to this cell.
    unsafe fn complete_mount_join(
        &self,
        ticket: fsring_core::adapter::lifecycle::MountJoinTicket,
    ) -> CompletedMountTeardown {
        unsafe { self.wait_mount(ticket.wait_observation()) };
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe {
            lock.cell_ptr(self.locator.slot_index())
                .unwrap_or_else(|| unreachable!())
        };
        let conversion = match unsafe { (*cell).release_mount_join(ticket) } {
            Ok(conversion) => conversion,
            Err((_error, returned)) => {
                let _retained = returned;
                unreachable!("the complete event admits this counted ordinary waiter")
            }
        };
        let prepared_publication =
            match unsafe { lock.prepare_locked_mount_join_conversion(conversion) } {
                Ok(prepared) => prepared,
                Err((_error, returned)) => {
                    let _retained = returned;
                    unreachable!("the Join conversion authenticates its exact permanent cell")
                }
            };
        let reset_ticket = match unsafe {
            crate::lifecycle::publish_mount_waiters_drained_locked(prepared_publication)
        } {
            Ok(ticket) => ticket,
            Err((_error, acknowledgement)) => {
                let _retained = acknowledgement;
                unreachable!("the fused ordinary-drain signal acknowledges the same generation")
            }
        };
        unsafe { lock.release() };
        unsafe { self.complete_mount_reset_join(reset_ticket) }
    }

    /// Run the mount teardown as exactly one take, join, or absence.
    ///
    /// The expectation comes from the same locked call that produced the claim,
    /// and the completion is bound to it before the roster may advance. A
    /// mismatch parks the whole pair and refuses; it never runs a second
    /// teardown, which is the failure this bind exists to prevent.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held.
    unsafe fn dismount_and_delete_devices(&mut self) -> bool {
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let Some(cell) = (unsafe { lock.cell_ptr(self.locator.slot_index()) }) else {
            unsafe { lock.release() };
            return false;
        };
        // SAFETY: the lock is held and the index is in range.
        let Some(expected) =
            (unsafe { (*cell).mount_rendezvous() }).expected_teardown(self.locator)
        else {
            unsafe { lock.release() };
            return false;
        };
        let claim = unsafe { (*cell).take_or_join_mount(expected) };
        unsafe { lock.release() };

        let completed = match claim {
            Ok(MountClaim::Owner {
                owner,
                teardown,
                expected,
            }) => {
                let _ = expected;
                unsafe { self.complete_mount_owner(owner, teardown) }
            }
            Ok(MountClaim::Join { ticket, expected }) => {
                let _ = expected;
                unsafe { self.complete_mount_join(ticket) }
            }
            Ok(MountClaim::ResetJoin { ticket, expected }) => {
                let _ = expected;
                unsafe { self.complete_mount_reset_join(ticket) }
            }
            Ok(MountClaim::Absent {
                expected: _,
                completed,
            }) => CompletedMountTeardown::from_absent(completed),
            Err(_) => return false,
        };

        unsafe { self.bind_mount_completion_and_delete_shell_vdo(expected, completed) }
    }

    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held.
    unsafe fn verify_session_and_root_ledgers(&self) -> bool {
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };
        let verdict = match cell {
            // SAFETY: the lock is held and the index is in range.
            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },
            None => false,
        };
        unsafe { lock.release() };
        verdict
    }

    /// Effect 15 observes the core strong ledger independently of every native
    /// owner checked by effect 16. The registry lock spans that exact read.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held.
    unsafe fn has_only_terminal_strong_owner(&self) -> bool {
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let verdict = unsafe {
            lock.core_mut()
                .r3_checkpoint_has_only_terminal_strong_owner(self.locator)
        };
        unsafe { lock.release() };
        verdict
    }
}

impl CheckpointExecutor for NativeCheckpointExecutor<'_> {
    fn take_pending_mount_bind(&mut self) -> Option<PendingMountBind> {
        self.pending_mount_bind.take()
    }

    fn take_unreleased_control(&mut self) -> Option<ControlStrongRef> {
        self.control.take()
    }

    fn take_bound_mount(&mut self) -> Option<BoundCompletedMountTeardown> {
        self.bound_mount.take()
    }
}

impl fsring_core::adapter::fence::R3CheckpointNativeOps for NativeCheckpointExecutor<'_> {
    fn checkpoint_locator(&self) -> SessionLocator {
        self.shell.locator()
    }

    unsafe fn close_session_admission(&mut self) -> bool {
        // Pending admission closes together with session admission, and before
        // the deposit walk two rows later: a link admitted after that walk would
        // be a parked ENTER the fence never signalled and never waits for.
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        if let Some(cell) = unsafe { lock.cell_ptr(self.locator.slot_index()) } {
            // SAFETY: the permanent cell, mutated under the lock just taken.
            unsafe { (*cell).close_pending_admission() };
        }
        unsafe { lock.release() };
        self.shell.checkpoint_close_session_admission()
    }

    unsafe fn signal_pending_enter(&mut self) -> bool {
        // The carried half first: every existing ENTER waiter is woken before
        // any pending context is touched, because a waiter that is still asleep
        // when the deposit runs would be woken by the deposit and then find a
        // session whose admission is already closed.
        if !self.shell.checkpoint_signal_existing_enter_waiters() {
            return false;
        }
        // The pending half: a Fence wake in every installed context, before
        // either rundown wait. A context still `Installing` stores the reason;
        // an installed one parks the one queue obligation `QueueInstalledWork`
        // discharges below.
        // SAFETY: PASSIVE_LEVEL with no registry lock held.
        let runtime = unsafe { self.pending_runtime_ptr() };
        if runtime.is_null() {
            // Every Live generation was published with a runtime, so a null
            // here is a shape violation rather than an empty session, and
            // refusing is what parks it instead of deleting underneath it.
            return false;
        }
        // SAFETY: the runtime lives in the permanent cell and this checkpoint
        // owns the generation, so nothing else can take it before the release.
        unsafe { (*runtime).deposit_fence_wakes() }
    }

    unsafe fn wait_control_rundown(&mut self) -> bool {
        // CLEANUP is the sole rundown waiter for Empty/ClosingSetup; the
        // committed terminal winner is the sole waiter for ClosingLive.
        unsafe { crate::control::wait_and_release_requestor(self.context.as_ptr()) };
        true
    }

    unsafe fn wait_session_access_rundown(&mut self) -> bool {
        unsafe { self.wait_access_rundown() }
    }

    unsafe fn wait_existing_sq_cq_roles_and_consumers(&mut self) -> bool {
        self.shell
            .checkpoint_wait_existing_sq_cq_roles_and_consumers()
    }

    unsafe fn remove_producer_mappings_reverse(&mut self) -> bool {
        self.shell.checkpoint_remove_producer_mappings_reverse()
    }

    unsafe fn wait_producer_and_mapping_capture_rundown(&mut self) -> bool {
        self.shell
            .checkpoint_wait_producer_and_mapping_capture_rundown()
    }

    unsafe fn retire_existing_grant_and_credit_state(&mut self) -> bool {
        self.shell
            .checkpoint_retire_existing_grant_and_credit_state()
    }

    unsafe fn acquire_consumers_increasing(&mut self) -> bool {
        self.shell.checkpoint_acquire_consumers_increasing()
    }

    unsafe fn release_consumers(&mut self) -> bool {
        self.shell.checkpoint_release_consumers()
    }

    unsafe fn queue_installed_work(&mut self) -> bool {
        // SAFETY: PASSIVE_LEVEL with no registry lock held.
        let runtime = unsafe { self.pending_runtime_ptr() };
        if runtime.is_null() {
            return false;
        }
        // SAFETY: as in `signal_pending_enter`. The queue DDI runs outside the
        // per-slot lock, which is why this is its own roster entry.
        unsafe { (*runtime).queue_installed_work() }
    }

    unsafe fn wait_pending_and_owners(&mut self) -> bool {
        // SAFETY: PASSIVE_LEVEL with no registry lock held; this row blocks.
        let runtime = unsafe { self.pending_runtime_ptr() };
        if runtime.is_null() {
            return false;
        }
        // SAFETY: as above. Observation alone cannot mint success: an Active
        // context or a parked publication refuses here rather than being called
        // drained, which is what stops a fail-stopped session being deleted
        // underneath its own still-parked IRP.
        unsafe { (*runtime).wait_contexts_drained() }
    }

    unsafe fn release_read_only_mappings_reverse(&mut self) -> bool {
        self.shell.checkpoint_release_read_only_mappings_reverse()
    }

    unsafe fn release_mdls_and_system_view(&mut self) -> bool {
        self.shell.checkpoint_release_mdls_and_system_view()
    }

    unsafe fn release_captured_process(&mut self) -> bool {
        self.shell.checkpoint_release_captured_process()
    }

    unsafe fn dismount_and_delete_devices(&mut self) -> bool {
        unsafe { NativeCheckpointExecutor::dismount_and_delete_devices(self) }
    }

    unsafe fn release_transient_arrays_and_backing(&mut self) -> bool {
        // The pending runtime goes first, and only here: `WaitPendingAndOwners`
        // has already proven every context drained, so no callback of any slot
        // is running or can be started. Freeing the arena before that proof
        // would free storage a queued worker still names.
        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };
        let runtime = match unsafe { lock.cell_ptr(self.locator.slot_index()) } {
            // SAFETY: the permanent cell, borrowed under the lock just taken.
            Some(cell) => unsafe { (*cell).take_pending_runtime() },
            None => None,
        };
        unsafe { lock.release() };
        if let Some(runtime) = runtime {
            // SAFETY: quiescence was proven by `WaitPendingAndOwners`, and the
            // free happens outside the registry lock because it touches pool.
            unsafe {
                runtime.release_pending_runtime(&mut crate::pending_enter::NativePendingRuntimeDdi)
            };
        }
        self.shell.checkpoint_release_transient_arrays_and_backing()
    }

    unsafe fn release_control_strong_ref(&mut self) -> bool {
        unsafe { NativeCheckpointExecutor::release_control_strong_ref(self) }
    }

    unsafe fn release_remaining_stable_session_owners(&mut self) -> bool {
        unsafe { self.has_only_terminal_strong_owner() }
    }

    unsafe fn verify_session_and_root_ledgers(&mut self) -> bool {
        unsafe { NativeCheckpointExecutor::verify_session_and_root_ledgers(self) }
    }
}

// ---------------------------------------------------------------------------
// The one terminal runner
// ---------------------------------------------------------------------------

/// What one arrival at `run_terminal_arrival` observed.
///
/// Every terminal source — CLEANUP, process loss, protocol abort, unload —
/// converges here, so there is exactly one place a generation can be torn down
/// and exactly one place a caller learns what happened.
pub(crate) enum TerminalOutcome {
    /// The generation is gone or going; the caller returns success.
    Completed(fsring_core::session::TerminalResult),
    /// A permanent fail-stop. Ordinary callers report
    /// `STATUS_INVALID_DEVICE_STATE`; unload must not return.
    Blocked(TerminalBlocked),
    /// Nothing to do for this locator.
    NotLive,
}

#[derive(Clone, Copy)]
enum TerminalArrivalMode {
    Ordinary,
    Unload,
}

enum TerminalArrivalResolution {
    Ordinary(TerminalOutcome),
    Unload(R3UnloadTerminalResolution),
}

/// Run one generation down, or join the run already in progress.
///
/// It takes the counted claim, and then either runs the closed R3 roster to a
/// deposit or waits on the outcome its winner will publish. It has no
/// production caller on this tree: CLEANUP (`control.rs`) and the
/// process-loss callback (`driver.rs`) claim first and then run
/// `run_terminal_from_disposition`. This comment
/// called it "the sole production terminal path" until round 21 (round-20
/// native review, N4, found the `NotLive` it returns unreachable for the
/// same reason).
///
/// # Safety
/// PASSIVE_LEVEL, no registry lock and no short guard held, with `registry`
/// live and `context` the arriving path's own control context.
pub(crate) unsafe fn run_terminal_arrival(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    locator: SessionLocator,
    request: TerminalRequest,
) -> TerminalOutcome {
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let claimed =
        match unsafe { prepare_native_terminal_claim(&mut lock, context, locator, request) } {
            // SAFETY: the retained borrows kept the cross-product fixed since the
            // preflight, and the lock is still held.
            Ok(prepared) => Some(unsafe { prepared.commit() }),
            Err(_) => None,
        };
    unsafe { lock.release() };

    let Some(disposition) = claimed else {
        return TerminalOutcome::NotLive;
    };
    match disposition {
        TerminalDisposition::Winner { work, join } => {
            // SAFETY: the winner owns the whole generation from here.
            unsafe { run_terminal_as_winner_ordinary(registry, context, work, join) }
        }
        // SAFETY: a counted joiner waits only after every short guard is gone,
        // which is this function's own contract.
        TerminalDisposition::Join(join) => unsafe { join_terminal_outcome(join) },
        TerminalDisposition::Completed(result) => TerminalOutcome::Completed(result),
        TerminalDisposition::Blocked(blocked) => TerminalOutcome::Blocked(blocked),
    }
}

/// Run one process-loss arrival at an observed cell.
///
/// Returns whether terminal work ran or waited outside the registry lock — in
/// which case the caller must restart its scan from the top, because the index
/// it was carrying names a generation that may already be gone.
///
/// # Safety
/// PASSIVE_LEVEL callback with no registry lock and no short guard held.
pub(crate) unsafe fn run_terminal_for_process(
    registry: NonNull<KernelSessionRegistry>,
    locator: SessionLocator,
) -> bool {
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    // The control context is the one the cell recorded; a process-loss arrival
    // has none of its own.
    let context = match unsafe { lock.cell_ptr(locator.slot_index()) } {
        // SAFETY: the lock is held and the index is in range.
        Some(cell) => unsafe { (*cell).recorded_control_context() },
        None => None,
    };
    let claimed = match context {
        Some(context) => {
            match unsafe {
                prepare_native_terminal_claim(
                    &mut lock,
                    context,
                    locator,
                    TerminalRequest::ProcessLoss,
                )
            } {
                // SAFETY: the retained borrows kept the cross-product fixed.
                Ok(prepared) => Some((context, unsafe { prepared.commit() })),
                Err(_) => None,
            }
        }
        None => None,
    };
    unsafe { lock.release() };

    let Some((context, disposition)) = claimed else {
        return false;
    };
    // SAFETY: the lock is released and no short guard is held.
    let _outcome = unsafe { run_terminal_from_disposition(registry, context, disposition) };
    true
}

/// The queued finalizer: take the deposit, preflight, then destroy.
///
/// Every fallible check runs while the intact deposit is still owned, so a
/// refusal returns it whole and destroys nothing. Only `PreparedDelete` crosses
/// into the suffix, and the suffix has no refusal edge.
///
/// # Safety
/// PASSIVE_LEVEL work item with `registry` live and no lock held.
pub(crate) unsafe fn run_queued_finalizer(
    registry: NonNull<KernelSessionRegistry>,
    context: fsring_core::adapter::fence::R3FinalizerCallbackContext,
) {
    let cell_index = context.cell_index();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    // SAFETY: the permanent callback context came from the exact cell selected
    // by a consumed kick. That kick exists only after this cell stored the
    // complete deposit and entered Queued, and the OS invokes its work item
    // once, so neither lookup nor take may refuse.
    let Some(cell) = (unsafe { lock.cell_ptr(cell_index) }) else {
        unsafe { lock.release() };
        unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
    };
    let Some((deposit, running, handoff_right)) =
        (unsafe { (*cell).take_deposit_and_run_for_callback(cell_index, context) })
    else {
        unsafe { lock.release() };
        unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
    };
    let locator = running.locator();
    if locator.slot_index() != cell_index || deposit.locator() != locator {
        let diagnostic = deposit.diagnostic();
        let fail_stop = DeleteFailStop {
            deposit,
            running,
            publisher: TerminalOutcomePublisher {
                locator,
                diagnostic,
                authority: PrivateTerminalOutcomePublisherAuthority(()),
            },
            reset: CellResetRight {
                locator,
                authority: PrivateCellResetAuthority(()),
            },
            step: FinalizerPreflightStep::MirrorAndShell,
            diagnostic,
        };
        let visibility =
            unsafe { (*cell).store_and_resolve_fail_stop(R3FailStopPacket::delete(fail_stop)) };
        let event = unsafe { (*cell).visibility_resolution_event() };
        let visibility = match visibility {
            R3FailStopVisibility::Published(signal) => {
                if let Err(right) =
                    unsafe { (*cell).store_ordinary_finalizer_handoff(handoff_right) }
                {
                    let _keep_right = right;
                    unsafe { lock.release() };
                    unsafe {
                        wake_fail_stop_visibility(
                            registry,
                            Some(event),
                            R3FailStopVisibilityWake::Published(signal),
                        )
                    };
                    unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
                }
                Some((R3FailStopVisibility::Published(signal), None))
            }
            R3FailStopVisibility::OpaqueRetained(receipt) => {
                match unsafe { (*cell).store_opaque_finalizer_handoff(handoff_right, receipt) } {
                    Ok(()) => None,
                    Err((right, receipt)) => {
                        Some((R3FailStopVisibility::OpaqueRetained(receipt), Some(right)))
                    }
                }
            }
            R3FailStopVisibility::ReentryRetained(packet) => Some((
                R3FailStopVisibility::ReentryRetained(packet),
                Some(handoff_right),
            )),
        };
        unsafe { lock.release() };
        match visibility {
            Some((visibility, retained_handoff)) => unsafe {
                finish_finalizer_fail_stop_visibility(registry, event, visibility, retained_handoff)
            },
            None => unsafe {
                wake_fail_stop_visibility(
                    registry,
                    Some(event),
                    R3FailStopVisibilityWake::LatchOnly,
                )
            },
        }
        return;
    }
    // SAFETY: the lock is held and this callback is the running finalizer.
    match unsafe { prepare_final_delete(&mut lock, deposit, running) } {
        Ok(prepared) => {
            let event = unsafe { (*cell).visibility_resolution_event() };
            if let Err(right) = unsafe { (*cell).store_ordinary_finalizer_handoff(handoff_right) } {
                let _keep_right = right;
                let _keep_prepared = prepared;
                unsafe { lock.release() };
                unsafe { signal_visibility_resolution(event) };
                unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
            }
            unsafe { lock.release() };
            unsafe { execute_prepared_delete(registry, prepared) };
        }
        Err(fail_stop) => {
            let packet = R3FailStopPacket::delete(fail_stop);
            let visibility = unsafe { (*cell).store_and_resolve_fail_stop(packet) };
            let event = unsafe { (*cell).visibility_resolution_event() };
            let visibility = match visibility {
                R3FailStopVisibility::Published(signal) => {
                    if let Err(right) =
                        unsafe { (*cell).store_ordinary_finalizer_handoff(handoff_right) }
                    {
                        let _keep_right = right;
                        unsafe { lock.release() };
                        unsafe {
                            wake_fail_stop_visibility(
                                registry,
                                Some(event),
                                R3FailStopVisibilityWake::Published(signal),
                            )
                        };
                        unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
                    }
                    Some((R3FailStopVisibility::Published(signal), None))
                }
                R3FailStopVisibility::OpaqueRetained(receipt) => {
                    match unsafe { (*cell).store_opaque_finalizer_handoff(handoff_right, receipt) }
                    {
                        Ok(()) => None,
                        Err((right, receipt)) => {
                            Some((R3FailStopVisibility::OpaqueRetained(receipt), Some(right)))
                        }
                    }
                }
                R3FailStopVisibility::ReentryRetained(packet) => Some((
                    R3FailStopVisibility::ReentryRetained(packet),
                    Some(handoff_right),
                )),
            };
            unsafe { lock.release() };
            match visibility {
                Some((visibility, retained_handoff)) => unsafe {
                    finish_finalizer_fail_stop_visibility(
                        registry,
                        event,
                        visibility,
                        retained_handoff,
                    )
                },
                None => unsafe {
                    wake_fail_stop_visibility(
                        registry,
                        Some(event),
                        R3FailStopVisibilityWake::LatchOnly,
                    )
                },
            }
        }
    }
}

unsafe fn finish_finalizer_fail_stop_visibility(
    registry: NonNull<KernelSessionRegistry>,
    event: *mut fsring_sys::c4::KEVENT,
    visibility: R3FailStopVisibility,
    retained_handoff: Option<FinalizerHandoffRight>,
) {
    let _keep_handoff = retained_handoff;
    match visibility {
        R3FailStopVisibility::Published(signal) => unsafe {
            wake_fail_stop_visibility(
                registry,
                Some(event),
                R3FailStopVisibilityWake::Published(signal),
            )
        },
        R3FailStopVisibility::OpaqueRetained(receipt) => {
            let locator = receipt.locator();
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            // Re-authenticate both durable storage and the quarantined
            // rendezvous through the locked no-ticket factory. The receipt
            // returned by storage remains retained if the cross-product is
            // inconsistent.
            let wait = lock.prepare_opaque_unload_wait(locator);
            unsafe { lock.release() };
            unsafe {
                wake_fail_stop_visibility(
                    registry,
                    Some(event),
                    R3FailStopVisibilityWake::LatchOnly,
                )
            };
            match wait {
                Some(wait) => unsafe { wait.wait_forever() },
                None => {
                    let _retain_receipt = receipt;
                    unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
                }
            }
        }
        R3FailStopVisibility::ReentryRetained(packet) => {
            unsafe {
                wake_fail_stop_visibility(
                    registry,
                    Some(event),
                    R3FailStopVisibilityWake::LatchOnly,
                )
            };
            unsafe { wait_fail_stop_reentry_forever(registry, packet, None) }
        }
    }
}

unsafe fn signal_visibility_resolution(event: *mut fsring_sys::c4::KEVENT) {
    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };
}

/// Perform the one post-unlock wake selected by the WDK-free fail-stop
/// continuation. Published owns the combined visibility/outcome signal;
/// opaque and retained invariant paths own only the visibility latch.
///
/// # Safety
/// No registry lock is held, `registry` remains live, and `event` is either the
/// permanent visibility event for this exact packet or absent because the cell
/// lookup failed before storage.
#[inline(never)]
unsafe fn wake_fail_stop_visibility(
    registry: NonNull<KernelSessionRegistry>,
    event: Option<*mut fsring_sys::c4::KEVENT>,
    wake: R3FailStopVisibilityWake<TerminalOutcomeSignal>,
) {
    run_r3_fail_stop_visibility_wake(
        wake,
        || {
            if let Some(event) = event {
                unsafe { signal_visibility_resolution(event) };
            }
        },
        |signal| unsafe { crate::lifecycle::signal_terminal_outcome(registry, signal) },
    );
}

/// Move one complete refusal packet into the exact permanent cell and resolve
/// its visibility before the registry lock may be released.
#[inline(never)]
unsafe fn store_fail_stop_locked(
    lock: &mut RegistryLockGuard,
    packet: R3FailStopPacket,
) -> R3FailStopVisibility {
    let locator = packet.locator();
    match unsafe { lock.cell_ptr(locator.slot_index()) } {
        Some(cell) => unsafe { (*cell).store_and_resolve_fail_stop(packet) },
        None => R3FailStopVisibility::ReentryRetained(R3FailStopReentryGuard::retain(packet)),
    }
}

/// The infallible destructive suffix, in the order `FinalDeletePlan` fixes.
///
/// The plan is the authority for the order, not this function: each step is
/// performed exactly as the plan hands it over, and the completion's own proofs
/// are checked before returning.
///
/// # Safety
/// PASSIVE_LEVEL, no lock held, and `prepared` was produced by
/// `prepare_final_delete` for this exact generation.
unsafe fn execute_prepared_delete(
    registry: NonNull<KernelSessionRegistry>,
    prepared: PreparedDelete,
) {
    unsafe { prepared.execute(registry) };
}

/// Transfer the closing owner and publish the closed outcome, in one lock hold.
///
/// A cell result must never be the only copy a later CLEANUP can read, so the
/// completed record reaches the control context *before* the binding moves to
/// ClosingComplete — and both happen before the event is signalled.
///
/// # Safety
/// PASSIVE_LEVEL with no registry lock held; `closing` and `winner` are this
/// generation's.
unsafe fn publish_completed_generation(
    registry: NonNull<KernelSessionRegistry>,
    publisher: TerminalOutcomePublisher,
    closing: ClosingControlOwner,
    winner: fsring_core::session::TerminalWinner,
    result: fsring_core::session::TerminalResult,
) -> TerminalOutcomeSignal {
    let (locator, _diagnostic) = publisher.into_parts();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    let signal = unsafe { lock.publish_completed_generation(locator, closing, winner, result) };
    let visibility_event = unsafe {
        lock.cell_mut_prevalidated(locator.slot_index())
            .visibility_resolution_event()
    };
    unsafe { lock.release() };
    unsafe { signal_visibility_resolution(visibility_event) };
    signal
}

/// Private fixed 64-cell unload cursor. No public constructor or generic cell
/// count exists, so a caller cannot select `N=1` or mint stable-empty from a
/// partial pass.
pub(crate) struct R3UnloadProgress {
    registry: NonNull<KernelSessionRegistry>,
    cursor: u32,
}

pub(crate) struct R3UnloadWork {
    registry: NonNull<KernelSessionRegistry>,
    action: crate::lifecycle::R3UnloadCellAction,
}

/// Affine authority for the one nonreturning branch of the native unload
/// runner.  Published and Opaque carry the authenticated lifecycle guards;
/// an inconsistent observation receives its own sealed authority instead of
/// leaking a bare registry pointer through the runner boundary.
pub(crate) struct R3BlockedUnloadWait {
    continuation: R3BlockedUnloadContinuation,
    authority: PrivateR3BlockedUnloadWaitAuthority,
}

enum R3BlockedUnloadContinuation {
    Published(crate::lifecycle::BlockedUnloadWaitGuard),
    RetainedPublished(crate::lifecycle::RetainedPublishedJoinWaitGuard),
    Opaque(crate::lifecycle::OpaqueFailStopWaitGuard),
    Reentry {
        registry: NonNull<KernelSessionRegistry>,
        guard: R3FailStopReentryGuard,
        join: Option<TerminalJoinGuard>,
    },
    MissingFinalizer(crate::lifecycle::FinalizerMissingHandoffGuard),
    Invariant(NonNull<KernelSessionRegistry>),
}

pub(crate) enum R3UnloadTerminalResolution {
    Completed(fsring_core::session::TerminalResult),
    Blocked(R3BlockedUnloadWait),
}

pub(crate) struct R3StableEmptyPass {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateR3StableEmptyPassAuthority,
}

/// Effect-seven's sole proof that every permanent cell was observed after
/// finalizer admission closed. Construction is private to the fixed-domain
/// cursor below; the lifecycle wait consumes it before calling ExWait.
pub(crate) struct R3FinalizerFullPass {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateR3FinalizerFullPassAuthority,
}

/// Effect-seven's post-rundown acknowledgement that every ordinary callback
/// finished its reset and that every generation visibility latch was cleared
/// under the registry lock.  This prevents effect nine from racing a callback
/// tail or observing a stale NotificationEvent.
pub(crate) struct R3FinalizerAcknowledgedPass {
    registry: NonNull<KernelSessionRegistry>,
    authority: PrivateR3FinalizerAcknowledgedPassAuthority,
}

struct R3FinalizerDrainProgress {
    registry: NonNull<KernelSessionRegistry>,
    cursor: u32,
}

pub(crate) struct R3FinalizersDrained {
    registry: NonNull<KernelSessionRegistry>,
    _stable_authority: PrivateR3StableEmptyPassAuthority,
    _native: crate::lifecycle::FinalizersDrained,
}

struct PrivateR3StableEmptyPassAuthority(());
struct PrivateR3FinalizerFullPassAuthority(());
struct PrivateR3FinalizerAcknowledgedPassAuthority(());
struct PrivateR3BlockedUnloadWaitAuthority(());

pub(crate) enum R3UnloadScanStep {
    Scanning(R3UnloadProgress),
    Work(R3UnloadWork),
    StableEmpty(R3StableEmptyPass),
    Blocked(R3BlockedUnloadWait),
}

impl R3UnloadProgress {
    /// Effect five entry. The affine global-close authority plus both prior
    /// drain receipts prevent constructing a stable pass before callbacks or
    /// SETUP frames have actually left the table.
    pub(crate) fn begin_after_drains(
        admission: crate::lifecycle::R3UnloadScanAdmission,
        process: &crate::lifecycle::ProcessCallbacksDrained,
        setup: &crate::lifecycle::SetupAdmissionDrained,
    ) -> Self {
        let registry = admission.into_registry_after_drains(process, setup);
        Self::restart(registry)
    }

    fn restart(registry: NonNull<KernelSessionRegistry>) -> Self {
        Self {
            registry,
            cursor: 0,
        }
    }

    /// Observe one cell in one registry hold. Advancing consumes the locked
    /// exact-nonmatch receipt; a match moves one affine action into Work.
    pub(crate) unsafe fn observe_one(self) -> R3UnloadScanStep {
        let Self { registry, cursor } = self;
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let observed = unsafe { lock.observe_r3_unload_cell(cursor) };
        unsafe { lock.release() };
        match observed {
            crate::lifecycle::R3UnloadCellObservation::NonMatch(_receipt) => {
                let next = cursor.saturating_add(1);
                if usize::try_from(next).map_or(true, |next| next >= SESSION_CELL_COUNT) {
                    R3UnloadScanStep::StableEmpty(R3StableEmptyPass {
                        registry,
                        authority: PrivateR3StableEmptyPassAuthority(()),
                    })
                } else {
                    R3UnloadScanStep::Scanning(Self {
                        registry,
                        cursor: next,
                    })
                }
            }
            crate::lifecycle::R3UnloadCellObservation::Action(action) => {
                R3UnloadScanStep::Work(R3UnloadWork { registry, action })
            }
            crate::lifecycle::R3UnloadCellObservation::FailStop => {
                R3UnloadScanStep::Blocked(R3BlockedUnloadWait::invariant(registry))
            }
        }
    }
}

impl R3UnloadWork {
    /// Discharge exactly one action outside the lock. Every returning arm
    /// yields a restart at zero. Published/Opaque move their already
    /// authenticated guards into the runner's sole nonreturning branch.
    pub(crate) unsafe fn discharge(self) -> R3UnloadScanStep {
        let Self { registry, action } = self;
        match action {
            crate::lifecycle::R3UnloadCellAction::Winner {
                context,
                disposition,
            } => match unsafe {
                run_terminal_from_disposition_for_unload(registry, context, disposition)
            } {
                R3UnloadTerminalResolution::Completed(_) => {}
                R3UnloadTerminalResolution::Blocked(blocked) => {
                    return R3UnloadScanStep::Blocked(blocked);
                }
            },
            crate::lifecycle::R3UnloadCellAction::Join(join) => match unsafe {
                R3BlockedUnloadWait::from_visibility_resolution(
                    registry,
                    join.wait_for_unload_visibility(),
                )
            } {
                R3UnloadTerminalResolution::Completed(_) => {}
                R3UnloadTerminalResolution::Blocked(blocked) => {
                    return R3UnloadScanStep::Blocked(blocked);
                }
            },
            crate::lifecycle::R3UnloadCellAction::Completed(_) => {
                // The admitted finalizer callback still owns reset; yielding
                // lets it publish exact empty before the restarted observation.
                core::hint::spin_loop();
            }
            crate::lifecycle::R3UnloadCellAction::Published(wait) => {
                return R3UnloadScanStep::Blocked(R3BlockedUnloadWait::published(wait));
            }
            crate::lifecycle::R3UnloadCellAction::Opaque(wait) => {
                return R3UnloadScanStep::Blocked(R3BlockedUnloadWait::opaque(wait));
            }
            crate::lifecycle::R3UnloadCellAction::FinalizerEpiloguePending => {
                // A real callback still owns its last rundown release. Keep
                // restarting until that affine epilogue has completed; only
                // exact empty cells may contribute to the stable pass.
                core::hint::spin_loop();
            }
        }
        R3UnloadScanStep::Scanning(R3UnloadProgress::restart(registry))
    }
}

impl R3BlockedUnloadWait {
    fn published(wait: crate::lifecycle::BlockedUnloadWaitGuard) -> Self {
        Self {
            continuation: R3BlockedUnloadContinuation::Published(wait),
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        }
    }

    fn opaque(wait: crate::lifecycle::OpaqueFailStopWaitGuard) -> Self {
        Self {
            continuation: R3BlockedUnloadContinuation::Opaque(wait),
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        }
    }

    fn retained_published(wait: crate::lifecycle::RetainedPublishedJoinWaitGuard) -> Self {
        Self {
            continuation: R3BlockedUnloadContinuation::RetainedPublished(wait),
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        }
    }

    fn reentry(
        registry: NonNull<KernelSessionRegistry>,
        guard: R3FailStopReentryGuard,
        join: Option<TerminalJoinGuard>,
    ) -> Self {
        Self {
            continuation: R3BlockedUnloadContinuation::Reentry {
                registry,
                guard,
                join,
            },
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        }
    }

    fn missing_finalizer(guard: crate::lifecycle::FinalizerMissingHandoffGuard) -> Self {
        Self {
            continuation: R3BlockedUnloadContinuation::MissingFinalizer(guard),
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        }
    }

    fn invariant(registry: NonNull<KernelSessionRegistry>) -> Self {
        Self {
            continuation: R3BlockedUnloadContinuation::Invariant(registry),
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        }
    }

    /// Convert one authenticated opaque preparation after performing its sole
    /// validated drained wake. Neither arm enters the permanent wait here.
    unsafe fn from_opaque_preparation(
        registry: NonNull<KernelSessionRegistry>,
        prepared: OpaqueFailStopWaitPreparation,
    ) -> Self {
        match prepared {
            OpaqueFailStopWaitPreparation::Released { wait, drained } => {
                if let Some(signal) = drained {
                    unsafe { crate::lifecycle::signal_joiners_drained(registry, signal) };
                }
                Self::opaque(wait)
            }
            OpaqueFailStopWaitPreparation::Retained(wait) => Self::opaque(wait),
        }
    }

    /// Translate the lifecycle's ticket/authentication result into the one
    /// typed unload branch consumed by the core runner.
    unsafe fn from_visibility_resolution(
        registry: NonNull<KernelSessionRegistry>,
        resolution: crate::lifecycle::R3UnloadVisibilityResolution,
    ) -> R3UnloadTerminalResolution {
        match resolution {
            crate::lifecycle::R3UnloadVisibilityResolution::Completed(result) => {
                R3UnloadTerminalResolution::Completed(result)
            }
            crate::lifecycle::R3UnloadVisibilityResolution::Published { wait, drained } => {
                if let Some(signal) = drained {
                    unsafe { crate::lifecycle::signal_joiners_drained(registry, signal) };
                }
                R3UnloadTerminalResolution::Blocked(Self::published(wait))
            }
            crate::lifecycle::R3UnloadVisibilityResolution::RetainedPublished(wait) => {
                R3UnloadTerminalResolution::Blocked(Self::retained_published(wait))
            }
            crate::lifecycle::R3UnloadVisibilityResolution::Opaque(prepared) => {
                R3UnloadTerminalResolution::Blocked(unsafe {
                    Self::from_opaque_preparation(registry, prepared)
                })
            }
        }
    }

    /// Consume the authenticated wait authority into the dedicated permanent
    /// unload wait. This is intentionally the only public operation on the
    /// token and has no success or refusal return.
    pub(crate) unsafe fn wait_forever(self) -> ! {
        let Self {
            continuation,
            authority: PrivateR3BlockedUnloadWaitAuthority(()),
        } = self;
        match continuation {
            R3BlockedUnloadContinuation::Published(wait) => unsafe { wait.wait_forever() },
            R3BlockedUnloadContinuation::RetainedPublished(wait) => unsafe { wait.wait_forever() },
            R3BlockedUnloadContinuation::Opaque(wait) => unsafe { wait.wait_forever() },
            R3BlockedUnloadContinuation::Reentry {
                registry,
                guard,
                join,
            } => unsafe { wait_fail_stop_reentry_forever(registry, guard, join) },
            R3BlockedUnloadContinuation::MissingFinalizer(guard) => unsafe { guard.wait_forever() },
            R3BlockedUnloadContinuation::Invariant(registry) => unsafe {
                crate::lifecycle::wait_blocked_unload_forever(registry)
            },
        }
    }
}

impl R3StableEmptyPass {
    pub(crate) const fn registry(&self) -> NonNull<KernelSessionRegistry> {
        self.registry
    }
}

impl R3FinalizersDrained {
    pub(crate) fn matches_registry(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn session_scan_stable_empty_for(
        &self,
        registry: NonNull<KernelSessionRegistry>,
    ) -> bool {
        self.registry == registry
    }
    pub(crate) fn admission_closed_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
    pub(crate) fn callbacks_drained_for(&self, registry: NonNull<KernelSessionRegistry>) -> bool {
        self.registry == registry
    }
}

/// Effect seven: close finalizer queue admission after the stable session
/// pass, resolve every admitted callback across the fixed 64-cell domain, and
/// only then invoke the native rundown wait. Opaque/Published durable storage
/// consumes an authenticated permanent-wait guard before that global wait can
/// be reached.
impl R3FinalizerFullPass {
    pub(crate) fn into_registry(self) -> NonNull<KernelSessionRegistry> {
        let Self {
            registry,
            authority: PrivateR3FinalizerFullPassAuthority(()),
        } = self;
        registry
    }
}

impl R3FinalizerAcknowledgedPass {
    pub(crate) fn into_registry(self) -> NonNull<KernelSessionRegistry> {
        let Self {
            registry,
            authority: PrivateR3FinalizerAcknowledgedPassAuthority(()),
        } = self;
        registry
    }
}

pub(crate) unsafe fn drain_r3_finalizers(stable: R3StableEmptyPass) -> R3FinalizersDrained {
    let R3StableEmptyPass {
        registry,
        authority: stable_authority @ PrivateR3StableEmptyPassAuthority(()),
    } = stable;
    let closed = {
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let closed = unsafe { crate::lifecycle::close_finalizer_admission(&mut lock) };
        unsafe { lock.release() };
        closed
    };

    let mut progress = R3FinalizerDrainProgress {
        registry,
        cursor: 0,
    };
    let full_pass = loop {
        let cursor = progress.cursor;
        let observed = {
            let mut lock = unsafe { KernelSessionRegistry::lock(progress.registry) };
            let observed = unsafe { lock.observe_r3_finalizer_for_drain(cursor) };
            unsafe { lock.release() };
            observed
        };
        match observed {
            crate::lifecycle::R3FinalizerDrainObservation::NonMatch(receipt) => {
                let observed_index = receipt.into_index();
                unsafe { core::hint::assert_unchecked(observed_index == cursor) };
                let next = cursor.saturating_add(1);
                if usize::try_from(next).map_or(true, |next| next >= SESSION_CELL_COUNT) {
                    break R3FinalizerFullPass {
                        registry,
                        authority: PrivateR3FinalizerFullPassAuthority(()),
                    };
                }
                progress = R3FinalizerDrainProgress {
                    registry,
                    cursor: next,
                };
            }
            crate::lifecycle::R3FinalizerDrainObservation::OrdinaryInFlight(receipt) => {
                let observed_index = receipt.into_index();
                unsafe { core::hint::assert_unchecked(observed_index == cursor) };
                let next = cursor.saturating_add(1);
                if usize::try_from(next).map_or(true, |next| next >= SESSION_CELL_COUNT) {
                    break R3FinalizerFullPass {
                        registry,
                        authority: PrivateR3FinalizerFullPassAuthority(()),
                    };
                }
                progress = R3FinalizerDrainProgress {
                    registry,
                    cursor: next,
                };
            }
            crate::lifecycle::R3FinalizerDrainObservation::WaitForVisibility(event) => {
                unsafe {
                    let _ = fsring_sys::c4::KeWaitForSingleObject(
                        event.cast(),
                        0,
                        0,
                        0,
                        core::ptr::null_mut(),
                    );
                }
                // Re-authenticate the same cell after the wake; never advance
                // from a stale pre-wait observation.
                progress = R3FinalizerDrainProgress { registry, cursor };
            }
            crate::lifecycle::R3FinalizerDrainObservation::Published(wait) => unsafe {
                wait.wait_forever()
            },
            crate::lifecycle::R3FinalizerDrainObservation::Opaque(wait) => unsafe {
                wait.wait_forever()
            },
            crate::lifecycle::R3FinalizerDrainObservation::FailStop => unsafe {
                crate::lifecycle::wait_process_scan_invariant_forever(registry)
            },
        }
    };

    let rundown = unsafe { crate::lifecycle::wait_finalizers_drained(full_pass, closed) };

    // The resolution pass may legitimately observe Completed while its
    // callback still owns rundown. ExWait makes every such callback tail
    // complete. A second fixed-domain locked pass then authenticates every
    // reset and acknowledges the visibility latch before effect nine.
    let mut cursor = 0u32;
    loop {
        let receipt = {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let receipt = unsafe { lock.acknowledge_r3_finalizer_after_rundown(cursor) };
            unsafe { lock.release() };
            receipt
        };
        let Some(receipt) = receipt else {
            unsafe { crate::lifecycle::wait_process_scan_invariant_forever(registry) }
        };
        let observed_index = receipt.into_index();
        unsafe { core::hint::assert_unchecked(observed_index == cursor) };
        let next = cursor.saturating_add(1);
        if usize::try_from(next).map_or(true, |next| next >= SESSION_CELL_COUNT) {
            break;
        }
        cursor = next;
    }
    let acknowledged = R3FinalizerAcknowledgedPass {
        registry,
        authority: PrivateR3FinalizerAcknowledgedPassAuthority(()),
    };
    let native = crate::lifecycle::finish_finalizers_drained(acknowledged, rundown);
    R3FinalizersDrained {
        registry,
        _stable_authority: stable_authority,
        _native: native,
    }
}

/// Continue from a disposition another path already claimed.
///
/// CLEANUP takes its claim inside `claim_native_cleanup_route`, under the same
/// lock hold that moved the binding, so it arrives here holding the result
/// rather than the locator. Splitting the entry rather than re-claiming is what
/// keeps "one counted claim per arrival" true.
///
/// # Safety
/// PASSIVE_LEVEL, no registry lock and no short guard held.
#[inline(never)]
pub(crate) unsafe fn run_terminal_from_disposition(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    disposition: TerminalDisposition,
) -> TerminalOutcome {
    match disposition {
        TerminalDisposition::Winner { work, join } => {
            // SAFETY: the winner owns the whole generation from here.
            unsafe { run_terminal_as_winner_ordinary(registry, context, work, join) }
        }
        // SAFETY: a counted joiner waits only after every short guard is gone.
        TerminalDisposition::Join(join) => unsafe { join_terminal_outcome(join) },
        TerminalDisposition::Completed(result) => TerminalOutcome::Completed(result),
        TerminalDisposition::Blocked(blocked) => TerminalOutcome::Blocked(blocked),
    }
}

pub(crate) unsafe fn run_terminal_from_disposition_for_unload(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    disposition: TerminalDisposition,
) -> R3UnloadTerminalResolution {
    match disposition {
        TerminalDisposition::Winner { work, join } => unsafe {
            run_terminal_as_winner_for_unload(registry, context, work, join)
        },
        TerminalDisposition::Join(join) => unsafe { resolve_unload_join(registry, join) },
        TerminalDisposition::Completed(result) => R3UnloadTerminalResolution::Completed(result),
        TerminalDisposition::Blocked(_) => {
            R3UnloadTerminalResolution::Blocked(R3BlockedUnloadWait::invariant(registry))
        }
    }
}

unsafe fn run_terminal_as_winner_ordinary(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    work: TerminalWork,
    join: TerminalJoinGuard,
) -> TerminalOutcome {
    match unsafe { run_terminal::<false>(registry, context, work, join) } {
        TerminalArrivalResolution::Ordinary(outcome) => outcome,
        TerminalArrivalResolution::Unload(_) => {
            unreachable!("the ordinary winner wrapper fixes the arrival mode")
        }
    }
}

unsafe fn run_terminal_as_winner_for_unload(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    work: TerminalWork,
    join: TerminalJoinGuard,
) -> R3UnloadTerminalResolution {
    match unsafe { run_terminal::<true>(registry, context, work, join) } {
        TerminalArrivalResolution::Unload(outcome) => outcome,
        TerminalArrivalResolution::Ordinary(_) => {
            unreachable!("the unload winner wrapper fixes the arrival mode")
        }
    }
}

pub(crate) struct NativeFenceDdi<'pass> {
    inner: NativeCheckpointExecutor<'pass>,
    set: fsring_core::session::SessionRingSetBrand,
    slab: Option<ConsumerTokenSlabOwner>,
}

impl<'pass> NativeFenceDdi<'pass> {
    unsafe fn new(
        registry: NonNull<KernelSessionRegistry>,
        shell: &'pass NativeSessionOwner,
        context: NonNull<ControlFileContext>,
        control: ControlStrongRef,
        set: fsring_core::session::SessionRingSetBrand,
        slab: Option<ConsumerTokenSlabOwner>,
    ) -> Self {
        unsafe { Self::resume(registry, shell, context, Some(control), set, slab) }
    }

    unsafe fn resume(
        registry: NonNull<KernelSessionRegistry>,
        shell: &'pass NativeSessionOwner,
        context: NonNull<ControlFileContext>,
        control: Option<ControlStrongRef>,
        set: fsring_core::session::SessionRingSetBrand,
        slab: Option<ConsumerTokenSlabOwner>,
    ) -> Self {
        Self {
            inner: unsafe { NativeCheckpointExecutor::resume(registry, shell, context, control) },
            set,
            slab,
        }
    }

    fn take_unreleased_control(&mut self) -> Option<ControlStrongRef> {
        self.inner.take_unreleased_control()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeGrantLockError {
    WrongSession,
    WrongRingSet,
    GrantBusy,
}

pub(crate) struct NativeFenceGrantGuard<'pass> {
    drained: &'pass DrainCompletedProof,
    entries: NonNull<fsring_core::grant::GrantEntry>,
    entry_count: usize,
    old_irql: fsring_sys::c4::KIRQL,
    set: fsring_core::session::SessionRingSetBrand,
    session: *mut crate::session::NativeSession,
}

impl NativeFenceGrantGuard<'_> {
    /// # Safety
    /// `ddi` borrows the exact resident session whose complete prefix and
    /// Drain proof are owned by `call`; no ENTER ring/grant guard is live.
    /// All brand/slot checks occur before GrantSpin acquisition or mutation.
    pub(crate) unsafe fn lock_for_fence<'pass>(
        ddi: &'pass mut NativeFenceDdi<'_>,
        call: &'pass mut PreparedRetireCall,
    ) -> Result<NativeFenceGrantGuard<'pass>, NativeGrantLockError> {
        if call.drain_proof().set_brand() != ddi.set {
            return Err(NativeGrantLockError::WrongRingSet);
        }
        let session = unsafe { ddi.inner.session_ptr() };
        if session.is_null() {
            return Err(NativeGrantLockError::WrongSession);
        }
        let Some(observed) = (unsafe { (*session).ring_set() }) else {
            return Err(NativeGrantLockError::WrongSession);
        };
        if observed != ddi.set {
            return Err(NativeGrantLockError::WrongRingSet);
        }
        let old_irql = unsafe { (*session).acquire_grant_spin() };
        let grants = unsafe { (*session).grants_slice_mut() };
        let Some(entries) = NonNull::new(grants.as_mut_ptr()) else {
            unsafe { (*session).release_grant_spin(old_irql) };
            return Err(NativeGrantLockError::GrantBusy);
        };
        let entry_count = grants.len();
        let drained = call.drain_proof();
        Ok(NativeFenceGrantGuard {
            drained,
            entries,
            entry_count,
            old_irql,
            set: ddi.set,
            session,
        })
    }

    pub(crate) fn with_entries<R>(
        &mut self,
        f: impl FnOnce(&mut [fsring_core::grant::GrantEntry], &DrainCompletedProof) -> R,
    ) -> R {
        let entries = if self.entry_count == 0 {
            &mut []
        } else {
            unsafe { core::slice::from_raw_parts_mut(self.entries.as_ptr(), self.entry_count) }
        };
        f(entries, self.drained)
    }
}

impl Drop for NativeFenceGrantGuard<'_> {
    fn drop(&mut self) {
        if !self.session.is_null() {
            unsafe { (*self.session).release_grant_spin(self.old_irql) };
            self.session = core::ptr::null_mut();
        }
    }
}

unsafe impl FenceKernelDdi for NativeFenceDdi<'_> {
    type Error = ();

    unsafe fn native_close_generation_admission(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.close_session_admission() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_schedule_linked_pending(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.signal_pending_enter() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_wait_control_and_access_rundown(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.wait_control_rundown() && self.inner.wait_session_access_rundown() }
        {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_unmap_producer_aliases_reverse(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.remove_producer_mappings_reverse() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_wait_producer_capture_rundown(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.wait_producer_and_mapping_capture_rundown() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_acquire_consumers_increasing(
        &mut self,
        prefix: &mut ConsumerPrefix,
    ) -> Result<(), ()> {
        let session = unsafe { self.inner.session_ptr() };
        if session.is_null() {
            return Err(());
        }
        while let Some(ring) = prefix.next_acquire_ring() {
            let token = match unsafe { crate::session::fence_acquire_cq_consumer_at(session, ring) }
            {
                Ok(token) => token,
                Err(()) => return Err(()),
            };
            if let Err((_error, token)) = prefix.push_acquired(ring, token) {
                let _ =
                    unsafe { crate::session::fence_release_cq_consumer_at(session, ring, token) };
                return Err(());
            }
        }
        Ok(())
    }
    unsafe fn native_drain_stable_prefixes_bounded(
        &mut self,
        prepared: &mut PreparedConsumerDrain,
    ) -> Result<(), ()> {
        if prepared.consumer_prefix().prefix_phase()
            != fsring_core::adapter::fence::ConsumerPrefixPhase::AcquiredComplete
        {
            return Err(());
        }
        let session = unsafe { self.inner.session_ptr() };
        if session.is_null() {
            return Err(());
        }
        // The SQ side only. This row runs between `AcquireConsumersIncreasing`
        // and `ReleaseConsumers`, so THIS FENCE holds every ring's CQ consumer
        // -- the phase assertion above is what proves it. The R3 predicate asks
        // `cq_owner.is_none()`, which is false on precisely the rings the
        // acquire just succeeded on, so this row refused every fence whose
        // acquire worked. Nothing noticed while the acquire could never
        // succeed at all.
        if unsafe { crate::session::checkpoint_wait_sq_roles_with_consumers_held(session) } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_retire_grants(&mut self, call: &mut PreparedRetireCall) -> Result<(), ()> {
        match unsafe { NativeFenceGrantGuard::lock_for_fence(self, call) } {
            Ok(mut guard) => {
                guard.with_entries(|entries, _proof| {
                    let _ = fsring_core::grant::retire_entries_for_fence(entries);
                });
                Ok(())
            }
            Err(_) => Err(()),
        }
    }
    unsafe fn native_release_consumers(&mut self, prefix: &mut ConsumerPrefix) -> Result<(), ()> {
        let session = unsafe { self.inner.session_ptr() };
        if session.is_null() {
            return Err(());
        }
        // Every token this cursor pops goes BACK TO ITS OWN RING. Dropping one
        // leaves that ring's consumer role owned by nobody -- `cq_owner` stays
        // `Some(..)` with no holder -- and every later acquire finds it busy
        // for ever. `consumer_release_returns_each_token_to_its_ring` in
        // `adapter/fence/tests.rs` states this as the DDI's contract.
        //
        // This used to be `let _ = prefix;` followed by
        // `checkpoint_release_consumers`, which is the OTHER consumer model:
        // that helper takes nothing and gives nothing back, it only re-proves
        // `cq_consumer_is_free()`. Against the acquire row -- which really does
        // take a token per ring -- it asked whether a role the fence itself was
        // holding was free, so it answered false on every ring that had just
        // been acquired.
        //
        // Core owns the phase either side of this: it has already called
        // `begin_release`, and it calls `finish_release` or
        // `park_partial_release` on the way out. This drains, and reports.
        while prefix.release_remaining() > 0 {
            let Ok((ring, token)) = prefix.pop_for_release() else {
                return Err(());
            };
            // SAFETY: PASSIVE_LEVEL, no registry lock held; the helper takes
            // the ring's own slot lock around the release.
            if let Err(token) =
                unsafe { crate::session::fence_release_cq_consumer_at(session, ring, token) }
            {
                // Put it back at the ring it came from, so core's
                // `park_partial_release` parks a cursor that still owns every
                // token it has not handed back.
                //
                // The refusal is not discarded. It carries the affine
                // `CqConsumerToken`, and dropping it leaves this ring's
                // `cq_owner` `Some(..)` with no holder, which wedges every later
                // fence acquire AND every later DRAIN ENTER for the life of the
                // session. `restore_released_token` is gated on the in-flight
                // ring, so it always accepts the token this loop just popped --
                // the last ring included, which is where round 15's N1 lost it.
                if let Err((_, _unreturnable)) = prefix.restore_released_token(ring, token) {
                    // Unreachable through that gate. If it were reached, the
                    // cursor still has `ring` marked in flight, so core can
                    // neither park it nor mint a `ConsumerReleaseProof` over it:
                    // the pass fails loudly instead of reporting a role back
                    // that is not. The token binds and falls out of scope here
                    // -- with no ring to give it to and no allocator to park it
                    // in, that is the whole of what this arm can do. It is a
                    // binding rather than a `drop(..)` call on purpose: `drop`
                    // is a bare identifier to the production graph, and calling
                    // it here would make every `Drop` impl in the tree
                    // production-reachable from this effect.
                }
                return Err(());
            }
            // The token reached its own ring. This is the only statement that
            // can move the cursor to `ReleasedComplete`, so a pass that skips it
            // -- or that never gets here -- mints no proof.
            if prefix.confirm_released_token(ring).is_err() {
                return Err(());
            }
        }
        Ok(())
    }
    unsafe fn native_queue_installed_work(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.queue_installed_work() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_wait_pending_and_owner_rundown(
        &mut self,
    ) -> Result<(), PendingOwnerWaitFailure<()>> {
        if unsafe { self.inner.wait_pending_and_owners() } {
            Ok(())
        } else {
            Err(PendingOwnerWaitFailure::Native(()))
        }
    }
    unsafe fn native_unmap_readonly_aliases_reverse(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.release_read_only_mappings_reverse() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_release_mdls_and_system_view(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.release_mdls_and_system_view() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_dereference_process(&mut self) -> Result<(), ()> {
        if unsafe { self.inner.release_captured_process() } {
            Ok(())
        } else {
            Err(())
        }
    }
    unsafe fn native_take_or_join_mount_and_delete(
        &mut self,
    ) -> Result<BoundCompletedMountTeardown, MountTeardownCallError<()>> {
        if !unsafe { self.inner.dismount_and_delete_devices() } {
            return Err(MountTeardownCallError::Native(()));
        }
        match self.inner.take_bound_mount() {
            Some(bound) => Ok(bound),
            None => Err(MountTeardownCallError::Native(())),
        }
    }
    unsafe fn native_release_transient_arrays(
        &mut self,
        proof: ConsumerReleaseProof,
    ) -> Result<(), ((), ConsumerReleaseProof)> {
        if unsafe { self.inner.release_transient_arrays_and_backing() } {
            let _ = proof;
            Ok(())
        } else {
            Err(((), proof))
        }
    }
    unsafe fn native_take_consumer_slab(&mut self) -> Result<ConsumerTokenSlabOwner, ()> {
        if let Some(slab) = self.slab.take() {
            return Ok(slab);
        }
        let session = unsafe { self.inner.session_ptr() };
        if session.is_null() {
            return Err(());
        }
        unsafe { crate::session::bind_fence_consumer_slab(session, self.set) }.map_err(|_| ())
    }
}

enum KernelFencePassOutcome {
    Complete(R4CheckpointCandidate),
    RetryQueued,
    FailStop(FenceIncompletePacket),
}

unsafe fn run_kernel_fence(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    owners: TerminalOwners,
    control: ControlStrongRef,
) -> KernelFencePassOutcome {
    let locator = owners.locator();
    let session = {
        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
        let session = match unsafe { lock.cell_ptr(locator.slot_index()) } {
            Some(cell) => unsafe { (*cell).session_mirror() },
            None => core::ptr::null_mut(),
        };
        unsafe { lock.release() };
        session
    };
    if session.is_null() {
        return KernelFencePassOutcome::FailStop(incomplete_from_missing_session(owners, control));
    }
    let Some(set) = (unsafe { (*session).ring_set() }) else {
        return KernelFencePassOutcome::FailStop(incomplete_from_missing_session(owners, control));
    };
    let (mut lifecycle, initial) =
        match fsring_core::adapter::fence::FenceRetryLifecycle::try_new_fence_retry_lifecycle(
            locator,
        ) {
            Ok(pair) => pair,
            Err(_) => {
                return KernelFencePassOutcome::FailStop(incomplete_from_missing_session(
                    owners, control,
                ));
            }
        };
    let _prepare_complete = fsring_core::adapter::fence::FenceRetryLifecycle::prepare_complete;
    let _commit_retry =
        fsring_core::adapter::fence::PreparedFenceRetryComplete::commit_retry_complete;
    let _begin_run = fsring_core::adapter::fence::FenceRetryLifecycle::begin_fence_retry_run;
    let ddi =
        unsafe { NativeFenceDdi::new(registry, owners.shell_owner(), context, control, set, None) };
    let outcome = match KernelFenceOps::try_new(ddi, set) {
        Ok(ops) => ops.finish(),
        Err(failure) => {
            let (ddi, incomplete) = failure.into_start_failure_parts();
            FenceRunOutcome::Residual { ddi, incomplete }
        }
    };
    match outcome {
        FenceRunOutcome::Complete { mut ddi, completed } => {
            let released_control = ddi.take_unreleased_control();
            if let Some(control) = released_control {
                let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                let _ = unsafe {
                    release_strong_and_deposit(
                        &mut lock,
                        R4ReleaseAuthority::Stable(control.into_reference()),
                        None,
                    )
                };
                unsafe { lock.release() };
            }
            let _ = ddi;
            let (winner, terminal, closing, shell, root) = owners.into_parts();
            let reason = winner.reason();
            let result = fsring_core::session::TerminalResult {
                reason,
                fence_failures: completed.report().failed_mask(),
            };
            let authenticated = match AuthenticatedTerminalResult::new(winner, result) {
                Ok(authenticated) => authenticated,
                Err(_) => {
                    unreachable!("a winner's own reason always matches the result built from it")
                }
            };
            let accumulated =
                fsring_core::adapter::fence::begin_accumulated_terminal_result(authenticated);
            let prepared = match fsring_core::adapter::fence::prepare_terminal_winner_finalize(
                accumulated,
                completed,
            ) {
                Ok(prepared) => prepared,
                Err(_failed) => {
                    return KernelFencePassOutcome::FailStop(
                        incomplete_from_missing_session_parts(terminal, closing, shell, root),
                    );
                }
            };
            {
                let observation = prepared.completion_observation();
                match lifecycle.prepare_initial_complete(initial, observation) {
                    Ok(ready) => ready.commit_initial_complete(),
                    Err(_refused) => {
                        return KernelFencePassOutcome::FailStop(
                            incomplete_from_missing_session_parts(terminal, closing, shell, root),
                        );
                    }
                }
            }
            let completed_result = prepared.commit();
            KernelFencePassOutcome::Complete(R4CheckpointCandidate {
                complete: completed_result,
                terminal,
                closing,
                shell,
                root,
            })
        }
        FenceRunOutcome::Residual {
            mut ddi,
            incomplete,
        } => {
            let control = ddi.take_unreleased_control();
            let _ = ddi;
            let (winner, terminal, closing, shell, root) = owners.into_parts();
            let reason = winner.reason();
            let result = fsring_core::session::TerminalResult {
                reason,
                fence_failures: incomplete.report().failed_mask(),
            };
            let authenticated = match AuthenticatedTerminalResult::new(winner, result) {
                Ok(authenticated) => authenticated,
                Err(_) => {
                    unreachable!("a winner's own reason always matches the result built from it")
                }
            };
            let (_report, residual, needed) = incomplete.into_residual_run_parts();
            match lifecycle.prepare_fence_retry(initial, needed) {
                Ok(fsring_core::adapter::fence::FenceRetryDisposition::Delay(delay)) => {
                    park_and_arm_fence_retry(
                        registry,
                        residual,
                        delay,
                        lifecycle,
                        terminal,
                        authenticated,
                        closing,
                        control,
                        shell,
                        root,
                    )
                }
                Ok(fsring_core::adapter::fence::FenceRetryDisposition::FailStop(_right)) => {
                    KernelFencePassOutcome::FailStop(FenceIncompletePacket {
                        progress: FenceIncompletePacketProgress::Residual { residual, control },
                        terminal,
                        result: authenticated,
                        closing,
                        shell,
                        root,
                    })
                }
                Err(_refused) => KernelFencePassOutcome::FailStop(FenceIncompletePacket {
                    progress: FenceIncompletePacketProgress::Residual { residual, control },
                    terminal,
                    result: authenticated,
                    closing,
                    shell,
                    root,
                }),
            }
        }
    }
}

fn incomplete_from_missing_session(
    owners: TerminalOwners,
    control: ControlStrongRef,
) -> FenceIncompletePacket {
    let _ = (owners, control);
    unreachable!("a live terminal winner always has a published session and ring set")
}

fn incomplete_from_missing_session_parts(
    terminal: TerminalSessionRef,
    closing: ClosingControlOwner,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
) -> FenceIncompletePacket {
    let _ = (terminal, closing, shell, root);
    unreachable!("a completed fence that cannot finalize is a core invariant")
}

#[allow(clippy::too_many_arguments)]
fn park_and_arm_fence_retry(
    registry: NonNull<KernelSessionRegistry>,
    residual: fsring_core::adapter::fence::FenceResidual,
    delay: fsring_core::adapter::fence::FenceRetryDelayRight,
    lifecycle: fsring_core::adapter::fence::FenceRetryLifecycle,
    terminal: TerminalSessionRef,
    result: AuthenticatedTerminalResult,
    closing: ClosingControlOwner,
    control: Option<ControlStrongRef>,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
) -> KernelFencePassOutcome {
    let locator = terminal.locator();
    let due = delay.due_time_100ns();
    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
    if let Some(cell) = unsafe { lock.cell_ptr(locator.slot_index()) } {
        unsafe {
            (*cell).park_fence_retry(ParkedFenceResidual {
                residual,
                delay: Some(delay),
                queued: None,
                lifecycle,
                terminal,
                result,
                closing,
                control,
                shell,
                root,
            });
        }
    }
    let timer = unsafe {
        lock.cell_ptr(locator.slot_index())
            .map(|cell| (*cell).fence_retry_timer_ptr())
    };
    let dpc = unsafe {
        lock.cell_ptr(locator.slot_index())
            .map(|cell| (*cell).fence_retry_dpc_ptr())
    };
    unsafe { lock.release() };
    if let (Some(timer), Some(dpc)) = (timer, dpc) {
        let due_time = wdk_sys::LARGE_INTEGER { QuadPart: due };
        unsafe {
            let _ = fsring_sys::c4::KeSetTimer(timer, due_time, dpc);
        }
        let _ = due_time;
    }
    KernelFencePassOutcome::RetryQueued
}

pub(crate) struct ParkedFenceResidual {
    residual: fsring_core::adapter::fence::FenceResidual,
    delay: Option<fsring_core::adapter::fence::FenceRetryDelayRight>,
    queued: Option<fsring_core::adapter::fence::FenceRetryRight>,
    lifecycle: fsring_core::adapter::fence::FenceRetryLifecycle,
    terminal: TerminalSessionRef,
    result: AuthenticatedTerminalResult,
    closing: ClosingControlOwner,
    control: Option<ControlStrongRef>,
    shell: NativeSessionOwner,
    root: SessionRootReleaseRight,
}

pub(crate) struct FenceRetryBeginRunFailStopDeposit {
    _private: (),
}
pub(crate) struct FenceNativeBorrowFailStopDeposit {
    _private: (),
}
pub(crate) struct NativeFenceBorrowRefusal {
    _private: (),
}
pub(crate) enum FenceNativeBorrowFailStopPass {
    Initial(fsring_core::adapter::fence::FenceInitialLifecycleBinding),
    Retry,
}
const _: fn(FenceNativeBorrowFailStopPass) -> bool = |pass| {
    matches!(
        pass,
        FenceNativeBorrowFailStopPass::Initial(_) | FenceNativeBorrowFailStopPass::Retry
    )
};
pub(crate) struct FenceCompletionFailStopDeposit {
    _private: (),
}
pub(crate) struct FinishFenceFailStopDeposit {
    _private: (),
}
pub(crate) struct FinishFenceFailure {
    _private: (),
}

/// Preallocated residual-retry DPC. Queues `fsring_fence_retry_worker`.
pub(crate) unsafe extern "C" fn fsring_fence_retry_dpc(
    _dpc: *mut fsring_sys::c4::KDPC,
    deferred_context: *mut core::ffi::c_void,
    _argument1: *mut core::ffi::c_void,
    _argument2: *mut core::ffi::c_void,
) {
    let Some(cell) = NonNull::new(deferred_context.cast::<crate::lifecycle::NativeSessionCell>())
    else {
        return;
    };
    let registry = unsafe { (*cell.as_ptr()).fence_retry_registry() };
    let lock = unsafe { KernelSessionRegistry::lock(registry) };
    if let Some(mut parked) = unsafe { (*cell.as_ptr()).take_fence_retry_park() } {
        if let Some(delay) = parked.delay.take() {
            if let Ok(dpc_right) = parked.lifecycle.begin_delay_dpc(delay) {
                if let Ok(queued) = parked.lifecycle.queue_from_dpc(dpc_right) {
                    parked.queued = Some(queued);
                }
            }
        }
        unsafe { (*cell.as_ptr()).park_fence_retry(parked) };
    }
    let work_item = unsafe { (*cell.as_ptr()).fence_retry_work_item() };
    unsafe { lock.release() };
    // Clear BEFORE the queue call, set after. This is a NotificationEvent: it
    // stays signalled until cleared, and it was created already signalled and
    // never cleared anywhere, so the worker's indefinite wait below was
    // unconditional success -- a required drain discharged by nothing, which is
    // the construction recovery design section 16 item 8 forbids by name. The
    // worker cannot run before `IoQueueWorkItem` queues it, so clearing here
    // cannot lose a signal: the only setter is the line after the queue call.
    let exit = unsafe { (*cell.as_ptr()).fence_retry_dpc_exit_ptr() };
    unsafe {
        fsring_sys::c4::KeClearEvent(exit);
    }
    if !work_item.is_null() {
        unsafe {
            fsring_sys::c4::IoQueueWorkItem(
                work_item,
                Some(fsring_fence_retry_worker),
                fsring_sys::c4::DelayedWorkQueue,
                cell.as_ptr().cast(),
            );
        }
    }
    unsafe {
        fsring_sys::c4::KeSetEvent(exit, 0, 0);
    }
}

/// Preallocated residual-retry worker. The DPC queues this exact callback.
pub(crate) unsafe extern "C" fn fsring_fence_retry_worker(
    _device: wdk_sys::PDEVICE_OBJECT,
    context: *mut core::ffi::c_void,
) {
    let Some(cell) = NonNull::new(context.cast::<crate::lifecycle::NativeSessionCell>()) else {
        return;
    };
    let exit = unsafe { (*cell.as_ptr()).fence_retry_dpc_exit_ptr() };
    unsafe {
        let _ = fsring_sys::c4::KeWaitForSingleObject(exit.cast(), 0, 0, 0, core::ptr::null_mut());
    }
    let parked = unsafe { (*cell.as_ptr()).take_fence_retry_park() };
    let Some(parked) = parked else {
        return;
    };
    let ParkedFenceResidual {
        residual,
        delay: _,
        queued,
        mut lifecycle,
        terminal,
        result,
        closing,
        control,
        shell,
        root,
    } = parked;
    let Some(queued) = queued else {
        return;
    };
    let Ok(run) = lifecycle.begin_fence_retry_run(queued) else {
        return;
    };
    let Some(context) = (unsafe { (*cell.as_ptr()).recorded_control_context() }) else {
        return;
    };
    let registry = unsafe { (*cell.as_ptr()).fence_retry_registry() };
    let set = residual.set_brand();
    let ddi = unsafe { NativeFenceDdi::resume(registry, &shell, context, control, set, None) };
    let outcome = match KernelFenceOps::resume(ddi, set, residual) {
        Ok(ops) => ops.finish(),
        Err(failure) => {
            let (ddi, incomplete) = failure.into_start_failure_parts();
            FenceRunOutcome::Residual { ddi, incomplete }
        }
    };
    match outcome {
        FenceRunOutcome::Complete { mut ddi, completed } => {
            // The control strong reference is RELEASED here, exactly as the
            // primary path does at its own `Complete` arm. Discarding it left
            // `strong_count` one too high, so the terminal release answered
            // `Retained` and the session was never deleted -- a fence that
            // completed on a retry could not finish what a fence that
            // completed first time did.
            let released_control = ddi.take_unreleased_control();
            if let Some(control) = released_control {
                let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                let _ = unsafe {
                    release_strong_and_deposit(
                        &mut lock,
                        R4ReleaseAuthority::Stable(control.into_reference()),
                        None,
                    )
                };
                unsafe { lock.release() };
            }
            let _ = ddi;
            let accumulated =
                fsring_core::adapter::fence::begin_accumulated_terminal_result(result);
            let prepared = match fsring_core::adapter::fence::prepare_terminal_winner_finalize(
                accumulated,
                completed,
            ) {
                Ok(prepared) => prepared,
                Err(_) => return,
            };
            {
                let observation = prepared.completion_observation();
                match lifecycle.prepare_complete(run, observation) {
                    Ok(ready) => ready.commit_retry_complete(),
                    Err(_) => return,
                }
            }
            let completed_result = prepared.commit();
            let candidate = R4CheckpointCandidate {
                complete: completed_result,
                terminal,
                closing,
                shell,
                root,
            };
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let disposition = match unsafe { prepare_finish_fence(&mut lock, candidate) } {
                Ok(prepared) => Some(unsafe { finish_fence(&mut lock, prepared) }),
                Err(_) => None,
            };
            unsafe { lock.release() };
            // `finish_fence`'s answer is the whole point of calling it. A
            // `Finalizer(kick)` names the generation whose finalizer still owes
            // a run; discarding it meant a fence that completed after a retry
            // never queued one and lost its admission rundown reference, while
            // the same fence completing on the primary path did queue it.
            // Queued outside the lock, as the primary path does.
            match disposition {
                Some(StrongReleaseDisposition::Finalizer(kick)) => {
                    // SAFETY: the kick names this exact generation, and the
                    // registry lock is released above.
                    unsafe { queue_finalizer(kick) };
                }
                Some(StrongReleaseDisposition::Retained) | None => {}
            }
        }
        FenceRunOutcome::Residual {
            mut ddi,
            incomplete,
        } => {
            let control = ddi.take_unreleased_control();
            let _ = ddi;
            let (_report, residual, needed) = incomplete.into_residual_run_parts();
            match lifecycle.defer(run, needed) {
                Ok(fsring_core::adapter::fence::FenceRetryDisposition::Delay(delay)) => {
                    let _ = park_and_arm_fence_retry(
                        registry, residual, delay, lifecycle, terminal, result, closing, control,
                        shell, root,
                    );
                }
                Ok(fsring_core::adapter::fence::FenceRetryDisposition::FailStop(_)) | Err(_) => {
                    // The retry may not run again, and every owner this arm
                    // holds is affine with no `Drop`. Dropping them is not a
                    // memory leak that ends with the session: it loses the
                    // shell block, the `DriverState` reference whose absence
                    // makes unload's sole-reference predicate bugcheck, and a
                    // control-context rundown reference that
                    // `wait_control_context_admission_drained` then waits on
                    // for ever. The empty arm was the whole defect.
                    //
                    // So this deposits exactly what the initial pass's own
                    // fail-stop hands back to its caller -- the same packet,
                    // built from the same parts -- through the same
                    // store-and-resolve the finalizer fail-stop uses. The
                    // worker has no `TerminalJoinGuard`, which is why the
                    // finalizer helper and not the join-based resolver is the
                    // right one: it settles all three visibility answers from
                    // the registry alone.
                    let packet = R3FailStopPacket::checkpoint(FenceIncompletePacket {
                        progress: FenceIncompletePacketProgress::Residual { residual, control },
                        terminal,
                        result,
                        closing,
                        shell,
                        root,
                    });
                    // SAFETY: the cell outlives this work item; the retry park
                    // was taken from it above.
                    let event = unsafe { (*cell.as_ptr()).visibility_resolution_event() };
                    // SAFETY: PASSIVE worker with no lock held.
                    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
                    // SAFETY: the packet names this cell's own locator.
                    let visibility = unsafe { store_fail_stop_locked(&mut lock, packet) };
                    // SAFETY: paired with the acquire above.
                    unsafe { lock.release() };
                    // SAFETY: no lock held, and the visibility answer is this
                    // deposit's own.
                    unsafe {
                        finish_finalizer_fail_stop_visibility(registry, event, visibility, None)
                    };
                }
            }
        }
    }
}

/// The sole terminal runner.
///
/// Every intended cleanup, process-loss, unload, and local-fence root reaches
/// this one body, and it is the only direct caller of `KernelFenceOps::try_new`
/// and the finish/deposit path. The Task 25 graph gate pins those edges.
///
/// # Safety
/// The caller holds no lock and owns `work` and `join`.
#[inline(never)]
unsafe fn run_terminal<const UNLOAD: bool>(
    registry: NonNull<KernelSessionRegistry>,
    context: NonNull<ControlFileContext>,
    work: TerminalWork,
    join: TerminalJoinGuard,
) -> TerminalArrivalResolution {
    // The arrival mode travels as the const parameter, not as a value: every
    // branch below forwards `UNLOAD` to a `_for_mode` callee that rebuilds it
    // where it is actually read, so this body has one specialised copy per
    // mode in the linked image without ever holding the mode itself.
    let (control, owners) = work.into_checkpoint_parts();

    match unsafe { run_kernel_fence(registry, context, owners, control) } {
        KernelFencePassOutcome::Complete(candidate) => {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let prepared = unsafe { prepare_finish_fence(&mut lock, candidate) };
            let disposition = match prepared {
                // SAFETY: preparation validated the whole cross-product in this
                // same lock hold.
                Ok(prepared) => Some(unsafe { finish_fence(&mut lock, prepared) }),
                Err((_error, candidate)) => {
                    let incomplete = candidate.into_finish_preparation_incomplete();
                    let locator = incomplete.locator();
                    let visibility_event = unsafe {
                        lock.cell_ptr(locator.slot_index())
                            .map(|cell| (*cell).visibility_resolution_event())
                    };
                    return unsafe {
                        resolve_checkpoint_fail_stop_for_mode::<UNLOAD>(
                            registry,
                            lock,
                            R3FailStopPacket::checkpoint(incomplete),
                            join,
                            visibility_event,
                        )
                    };
                }
            };
            unsafe { lock.release() };
            match disposition {
                Some(StrongReleaseDisposition::Finalizer(kick)) => {
                    // SAFETY: the kick names this exact generation.
                    unsafe { queue_finalizer(kick) };
                    return unsafe {
                        resolve_finalizer_winner_for_mode::<UNLOAD>(
                            registry,
                            join.wait_for_finalizer_resolution(),
                        )
                    };
                }
                Some(StrongReleaseDisposition::Retained) | None => {}
            }
        }
        KernelFencePassOutcome::RetryQueued => {}
        KernelFencePassOutcome::FailStop(incomplete) => {
            let mut lock = unsafe { KernelSessionRegistry::lock(registry) };
            let locator = incomplete.locator();
            let visibility_event = unsafe {
                lock.cell_ptr(locator.slot_index())
                    .map(|cell| (*cell).visibility_resolution_event())
            };
            return unsafe {
                resolve_checkpoint_fail_stop_for_mode::<UNLOAD>(
                    registry,
                    lock,
                    R3FailStopPacket::checkpoint(incomplete),
                    join,
                    visibility_event,
                )
            };
        }
    }

    // SAFETY: the winner is a counted arrival like any other, and every short
    // guard is gone by now.
    unsafe { resolve_join_for_mode::<UNLOAD>(join) }
}

/// Store one checkpoint refusal and select its post-unlock continuation.
/// Unload returns an authenticated token to its outer runner; ordinary callers
/// retain their existing terminal outcome/permanent-wait behavior.
#[inline(never)]
unsafe fn resolve_checkpoint_fail_stop_for_mode<const UNLOAD: bool>(
    registry: NonNull<KernelSessionRegistry>,
    mut lock: RegistryLockGuard,
    packet: R3FailStopPacket,
    join: TerminalJoinGuard,
    visibility_event: Option<*mut fsring_sys::c4::KEVENT>,
) -> TerminalArrivalResolution {
    // Rebuilt from the const so the matches below fold at compile time,
    // giving one specialised copy per arrival mode in the linked image.
    let mode = if UNLOAD {
        TerminalArrivalMode::Unload
    } else {
        TerminalArrivalMode::Ordinary
    };
    match mode {
        TerminalArrivalMode::Ordinary => {
            let visibility = unsafe { store_fail_stop_locked(&mut lock, packet) };
            match visibility {
                R3FailStopVisibility::Published(signal) => {
                    unsafe { lock.release() };
                    unsafe {
                        wake_fail_stop_visibility(
                            registry,
                            visibility_event,
                            R3FailStopVisibilityWake::Published(signal),
                        )
                    };
                    TerminalArrivalResolution::Ordinary(unsafe { join_terminal_outcome(join) })
                }
                R3FailStopVisibility::OpaqueRetained(receipt) => {
                    let cell = unsafe { lock.cell_mut_prevalidated(join.locator().slot_index()) };
                    let prepared = unsafe { join.prepare_opaque_wait(cell, receipt) };
                    unsafe { lock.release() };
                    unsafe {
                        wake_fail_stop_visibility(
                            registry,
                            visibility_event,
                            R3FailStopVisibilityWake::LatchOnly,
                        )
                    };
                    unsafe { enter_opaque_wait(registry, prepared) }
                }
                R3FailStopVisibility::ReentryRetained(guard) => {
                    unsafe { lock.release() };
                    unsafe {
                        wake_fail_stop_visibility(
                            registry,
                            visibility_event,
                            R3FailStopVisibilityWake::LatchOnly,
                        )
                    };
                    unsafe { wait_fail_stop_reentry_forever(registry, guard, Some(join)) }
                }
            }
        }
        TerminalArrivalMode::Unload => {
            let blocked = run_r3_fail_stop_two_phase(
                lock,
                |lock| match unsafe { store_fail_stop_locked(lock, packet) } {
                    R3FailStopVisibility::Published(signal) => {
                        R3FailStopPreparedContinuation::Published {
                            signal,
                            continuation: join,
                        }
                    }
                    R3FailStopVisibility::OpaqueRetained(receipt) => {
                        let cell =
                            unsafe { lock.cell_mut_prevalidated(join.locator().slot_index()) };
                        R3FailStopPreparedContinuation::Opaque(unsafe {
                            join.prepare_opaque_wait(cell, receipt)
                        })
                    }
                    R3FailStopVisibility::ReentryRetained(guard) => {
                        R3FailStopPreparedContinuation::Retained((guard, join))
                    }
                },
                |lock| unsafe { lock.release() },
                || {
                    if let Some(event) = visibility_event {
                        unsafe { signal_visibility_resolution(event) };
                    }
                },
                |signal| unsafe { crate::lifecycle::signal_terminal_outcome(registry, signal) },
                |join| match unsafe { resolve_unload_join(registry, join) } {
                    R3UnloadTerminalResolution::Blocked(blocked) => blocked,
                    R3UnloadTerminalResolution::Completed(_) => {
                        R3BlockedUnloadWait::invariant(registry)
                    }
                },
                |prepared| unsafe {
                    R3BlockedUnloadWait::from_opaque_preparation(registry, prepared)
                },
                |(guard, join)| R3BlockedUnloadWait::reentry(registry, guard, Some(join)),
            );
            TerminalArrivalResolution::Unload(R3UnloadTerminalResolution::Blocked(blocked))
        }
    }
}

unsafe fn resolve_finalizer_winner_for_mode<const UNLOAD: bool>(
    registry: NonNull<KernelSessionRegistry>,
    resolution: FinalizerWinnerResolution,
) -> TerminalArrivalResolution {
    // Rebuilt from the const so the matches below fold at compile time,
    // giving one specialised copy per arrival mode in the linked image.
    let mode = if UNLOAD {
        TerminalArrivalMode::Unload
    } else {
        TerminalArrivalMode::Ordinary
    };
    match (mode, resolution) {
        (TerminalArrivalMode::Ordinary, FinalizerWinnerResolution::Ordinary(join)) => {
            TerminalArrivalResolution::Ordinary(unsafe { join_terminal_outcome(join) })
        }
        (TerminalArrivalMode::Ordinary, FinalizerWinnerResolution::Opaque(prepared)) => unsafe {
            enter_opaque_wait(registry, prepared)
        },
        (TerminalArrivalMode::Ordinary, FinalizerWinnerResolution::Missing(guard)) => unsafe {
            guard.wait_forever()
        },
        (TerminalArrivalMode::Unload, FinalizerWinnerResolution::Ordinary(join)) => {
            TerminalArrivalResolution::Unload(unsafe { resolve_unload_join(registry, join) })
        }
        (TerminalArrivalMode::Unload, FinalizerWinnerResolution::Opaque(prepared)) => {
            TerminalArrivalResolution::Unload(R3UnloadTerminalResolution::Blocked(unsafe {
                R3BlockedUnloadWait::from_opaque_preparation(registry, prepared)
            }))
        }
        (TerminalArrivalMode::Unload, FinalizerWinnerResolution::Missing(guard)) => {
            TerminalArrivalResolution::Unload(R3UnloadTerminalResolution::Blocked(
                R3BlockedUnloadWait::missing_finalizer(guard),
            ))
        }
    }
}

/// Signal only a validated counted release, then consume the opaque slot
/// receipt into its sole permanent-wait continuation.
#[inline(never)]
unsafe fn enter_opaque_wait(
    registry: NonNull<KernelSessionRegistry>,
    prepared: OpaqueFailStopWaitPreparation,
) -> ! {
    match prepared {
        OpaqueFailStopWaitPreparation::Released { wait, drained } => {
            if let Some(signal) = drained {
                unsafe { crate::lifecycle::signal_joiners_drained(registry, signal) };
            }
            unsafe { wait.wait_forever() }
        }
        OpaqueFailStopWaitPreparation::Retained(wait) => unsafe { wait.wait_forever() },
    }
}

/// Retain an impossible second refusal and any counted admission forever.
/// The already occupied permanent slot still seals the generation; this
/// continuation prevents the rejected second packet from being dropped or
/// requeued and never fabricates a ticket release.
#[inline(never)]
unsafe fn wait_fail_stop_reentry_forever(
    registry: NonNull<KernelSessionRegistry>,
    guard: R3FailStopReentryGuard,
    join: Option<TerminalJoinGuard>,
) -> ! {
    let R3FailStopReentryGuard { packet } = guard;
    let _keep_packet = packet;
    let _keep_join = join;
    unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
}

/// # Safety
/// The caller holds no lock and no short guard.
#[inline(never)]
unsafe fn join_terminal_outcome(join: TerminalJoinGuard) -> TerminalOutcome {
    let registry = join.registry();
    match unsafe { join.wait_for_visibility_resolution() } {
        crate::lifecycle::TerminalVisibilityResolution::Completed { result, drained } => {
            if let Some(signal) = drained {
                unsafe { crate::lifecycle::signal_joiners_drained(registry, signal) };
            }
            TerminalOutcome::Completed(result)
        }
        crate::lifecycle::TerminalVisibilityResolution::Blocked { blocked, drained } => {
            if let Some(signal) = drained {
                unsafe { crate::lifecycle::signal_joiners_drained(registry, signal) };
            }
            TerminalOutcome::Blocked(blocked)
        }
        crate::lifecycle::TerminalVisibilityResolution::Opaque(prepared) => unsafe {
            enter_opaque_wait(registry, prepared)
        },
        crate::lifecycle::TerminalVisibilityResolution::FailStop(join) => unsafe {
            wait_join_visibility_invariant_forever(join)
        },
    }
}

#[inline(never)]
unsafe fn resolve_unload_join(
    registry: NonNull<KernelSessionRegistry>,
    join: TerminalJoinGuard,
) -> R3UnloadTerminalResolution {
    debug_assert_eq!(registry, join.registry());
    unsafe {
        R3BlockedUnloadWait::from_visibility_resolution(registry, join.wait_for_unload_visibility())
    }
}

unsafe fn resolve_join_for_mode<const UNLOAD: bool>(
    join: TerminalJoinGuard,
) -> TerminalArrivalResolution {
    // Rebuilt from the const so the matches below fold at compile time,
    // giving one specialised copy per arrival mode in the linked image.
    let mode = if UNLOAD {
        TerminalArrivalMode::Unload
    } else {
        TerminalArrivalMode::Ordinary
    };
    match mode {
        TerminalArrivalMode::Ordinary => {
            TerminalArrivalResolution::Ordinary(unsafe { join_terminal_outcome(join) })
        }
        TerminalArrivalMode::Unload => {
            TerminalArrivalResolution::Unload(unsafe { resolve_unload_join(join.registry(), join) })
        }
    }
}

/// Process-loss discharge for one counted Open-state join. It shares the
/// broadcast visibility resolver with CLEANUP/winner joins, so Opaque is
/// authenticated instead of sleeping forever on `terminal_outcome`.
pub(crate) unsafe fn discharge_process_join(join: TerminalJoinGuard) {
    let _ = unsafe { join_terminal_outcome(join) };
}

unsafe fn wait_join_visibility_invariant_forever(join: TerminalJoinGuard) -> ! {
    let registry = join.registry();
    let _retain_ticket = join;
    unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }
}

/// Queue the one finalizer work item this kick names.
///
/// # Safety
/// `registry` is live and the deposit for this generation is stored.
#[inline(never)]
unsafe fn queue_finalizer(kick: AdmittedR3FinalizerKick) {
    // SAFETY: the cell owns a preallocated work item associated with the
    // permanent provider device.
    unsafe { crate::lifecycle::queue_cell_finalizer(kick) };
}

/// The finalizer worker states this checkpoint uses.
pub(crate) type CheckpointFinalizerState = FinalizerState;

// These compile-only native-shape tests deliberately remain part of every
// kernel check. Each names one of Task 10's native-only RED rows, and each
// type-checks only while the authority it names is affine and reaches its one
// destination. They prove ownership and destination, not runtime ordering —
// the ordering rules live in `fsring-core::adapter::fence`, where a host test
// can observe them.
#[cfg(test)]
#[allow(dead_code)]
mod native_shape_tests {
    use super::*;

    /// A late ordinary Join returns the same affine drain right to one
    /// condition loop; the destructive Owner prefix and Done signal are not
    /// accepted by this retry boundary and therefore cannot be replayed.
    fn late_join_drain_retry_carries_only_the_returned_right(
        executor: &NativeCheckpointExecutor<'_>,
        drain: fsring_core::adapter::lifecycle::MountDrainRight,
    ) -> fsring_core::adapter::lifecycle::PreparedMountReset {
        unsafe { executor.wait_until_mount_drained(drain) }
    }

    /// Owner, Join, ResetJoin, and initial Absent all converge on this one
    /// post-bind shell boundary. No claim-specific helper can delete the VDO,
    /// and a refused bind returns before this method consumes its take-once
    /// slot.
    fn shell_vdo_deletion_requires_an_authentically_bound_mount_completion(
        executor: &mut NativeCheckpointExecutor<'_>,
        expected: fsring_core::adapter::lifecycle::ExpectedMountTeardown,
        completed: CompletedMountTeardown,
    ) -> bool {
        unsafe { executor.bind_mount_completion_and_delete_shell_vdo(expected, completed) }
    }

    /// Both native queue boundaries consume the one core-minted kick by value.
    /// Neither endpoint accepts a copied locator, readiness, right, or deposit.
    fn finalizer_queue_endpoints_consume_only_the_stored_deposit_kick() {
        let _local: unsafe fn(AdmittedR3FinalizerKick) = queue_finalizer;
        let _cell: unsafe fn(AdmittedR3FinalizerKick) = crate::lifecycle::queue_cell_finalizer;
    }

    trait AmbiguousIfClone<Marker> {
        fn assert_not_clone() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    /// Preparation returns the whole candidate or one aggregate — never parts.
    ///
    /// The refusal arm below binds the candidate as a single value. A signature
    /// that returned its six fields separately could not type-check here, which
    /// is the shape that lets a caller drop one of them.
    fn task12_finish_preparation_returns_all_inputs_or_one_r3_aggregate(
        lock: &mut RegistryLockGuard,
        candidate: R4CheckpointCandidate,
    ) -> Result<PreparedNativeFenceFinish, R4CheckpointCandidate> {
        match unsafe { prepare_finish_fence(lock, candidate) } {
            Ok(prepared) => Ok(prepared),
            Err((_error, candidate)) => Err(candidate),
        }
    }

    /// The proof, result, and closing owner travel together or not at all.
    ///
    /// They are fields of one candidate with no public constructor, so a
    /// foreign proof cannot be paired with this generation's result: there is
    /// no expression that builds such a pair.
    fn foreign_proof_terminal_result_and_closing_owner_each_return_all_inputs(
        candidate: R4CheckpointCandidate,
    ) -> R4CheckpointCandidate {
        <R4CheckpointCandidate as AmbiguousIfClone<_>>::assert_not_clone();
        let _locator: SessionLocator = candidate.locator();
        candidate
    }

    /// A refused candidate still owns the shell and root it arrived with.
    fn foreign_checkpoint_candidate_returns_shell_and_root_unchanged(
        lock: &mut RegistryLockGuard,
        candidate: R4CheckpointCandidate,
    ) -> Option<(NativeSessionOwner, SessionRootReleaseRight)> {
        match unsafe { prepare_finish_fence(lock, candidate) } {
            Ok(_prepared) => None,
            Err((_error, candidate)) => {
                let R4CheckpointCandidate {
                    complete: _,
                    terminal,
                    closing,
                    shell,
                    root,
                } = candidate;
                // The other three are still here too; consuming them keeps this
                // probe honest about the packet being whole.
                let _ = terminal;
                let _ = closing;
                Some((shell, root))
            }
        }
    }

    /// The finish has no `Result` and no returned-authority edge.
    ///
    /// Its signature is the proof: a caller cannot write a refusal arm because
    /// there is none to write.
    fn infallible_checkpoint_finish_has_no_refusal_or_returned_authority_edge(
        lock: &mut RegistryLockGuard,
        prepared: PreparedNativeFenceFinish,
    ) -> StrongReleaseDisposition {
        unsafe { finish_fence(lock, prepared) }
    }

    /// The deposit is the only thing that reaches the finalizer.
    ///
    /// `FinalizerDeposit` has no public constructor and its fields are
    /// private, so the readiness and the right can only arrive combined.
    fn task12_r3_readiness_is_the_only_finalizer_deposit(
        lock: &mut RegistryLockGuard,
        deposit: FinalizerDeposit,
        running: R3FinalizerRunningRight,
    ) -> Result<PreparedDelete, DeleteFailStop<FinalizerDeposit>> {
        <FinalizerDeposit as AmbiguousIfClone<_>>::assert_not_clone();
        <FenceDeletionReadiness as AmbiguousIfClone<_>>::assert_not_clone();
        unsafe { prepare_final_delete(lock, deposit, running) }
    }

    /// Both release orders move the *same* owners into the same readiness.
    ///
    /// There is one `FenceDeletionReadiness` constructor site, inside
    /// `finish_fence`, and both the immediate and the later-last
    /// path go through `release_strong_and_deposit`. A second construction site
    /// would be a second pair of owners.
    fn immediate_and_later_last_preserve_the_same_shell_and_root_owner_ids(
        lock: &mut RegistryLockGuard,
        authority: R4ReleaseAuthority,
        readiness: Option<FenceDeletionReadiness>,
    ) {
        match unsafe { release_strong_and_deposit(lock, authority, readiness) } {
            Ok(StrongReleaseDisposition::Retained) => {}
            Ok(StrongReleaseDisposition::Finalizer(kick)) => {
                let _locator: SessionLocator = kick.locator();
                let _ = kick;
            }
            Err((_error, authority, readiness)) => {
                // A refusal returns both affine inputs, so neither the
                // reference nor the owners inside the readiness are stranded.
                let _ = authority;
                let _ = readiness;
            }
        }
    }

    /// A checkpoint refusal keeps every authority the generation still holds.
    fn r3_checkpoint_refusal_retains_terminal_control_shell_root_and_native_owners(
        incomplete: FenceIncompletePacket,
    ) -> TerminalBlocked {
        <FenceIncompletePacket as AmbiguousIfClone<_>>::assert_not_clone();
        let observation = incomplete.blocked_observation();
        let FenceIncompletePacket {
            progress,
            terminal,
            result,
            closing,
            shell,
            root,
        } = incomplete;
        match progress {
            FenceIncompletePacketProgress::Roster {
                cursor: _,
                report: _,
                complete,
                control,
                pending_mount_bind,
                bound_mount,
            } => {
                let _ = complete;
                let _ = control;
                let _ = pending_mount_bind;
                let _ = bound_mount;
            }
            FenceIncompletePacketProgress::Finish
            | FenceIncompletePacketProgress::Residual { .. } => {}
        }
        // Every one of them is still here; the packet is what retains them.
        let _ = terminal;
        let _ = result;
        let _ = closing;
        let _ = shell;
        let _ = root;
        observation
    }
}
