//! The checkpoint-local R3 teardown roster, its proofs, and its refusal cursor.
//!
//! The final six-stage `SessionFence` in [`crate::session`] is the *destination*
//! of this recovery, not its next step: it names effects — pending-ENTER
//! quiescence, CQ credit retirement, residual retry — that the Task 12 binary
//! cannot produce and therefore cannot honestly discharge. A scheduler that ran
//! the final roster here would have to report success for operations that never
//! happened, which is the exact dishonesty the whole checkpoint idea exists to
//! avoid.
//!
//! So this module states a *different*, smaller, closed roster: one entry per
//! resource the then-current production setup, access, ENTER, CQ, and mount
//! paths can actually create, in the dependency order the final fence uses.
//! Every entry is executed concretely. Nothing is deferred, and nothing is
//! recorded as successful because it was inapplicable.
//!
//! Two consequences are load-bearing:
//!
//! * A refusal stops the pass *at* that effect. Later entries are never
//!   attempted, so a report can never claim an operation that a failed
//!   predecessor made meaningless.
//! * The proof this scheduler mints, [`ClosedFenceRosterComplete`], is checkpoint-local
//!   and has no conversion to the final `FenceObligationsDischarged`. A binary
//!   that accepted one for the other would let a checkpoint discharge
//!   obligations it never had.

use crate::adapter::lifecycle::{
    ExpectedMountTeardown, FinalizerState, JoinedMountCompletion, LifecycleError,
    MountAbsenceCursor, MountAbsentProof, NativeSessionOwner, OwnerMountCompletion,
    SessionRootReleaseRight,
};
use crate::enter::CqConsumerToken;
#[cfg(test)]
use crate::session::injected_r4_authority_absence_for_test;
use crate::session::{
    DeleteSessionRight, DiagnosticId, FinalizerPreflightStep, MAX_SESSION_RING_COUNT,
    PreparedDeleteCoreCommit, ProductionAttestationError, ProductionGraphArtifactIdentity,
    SessionError, SessionLocator, SessionRegistry, SessionRingSetBrand, SlotDisposition,
    TerminalResult, TerminalWinner, embedded_r4_authority_absence,
};

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug)]
            struct $name(());
        )+
    };
}

private_authority_seals!(
    PrivateFenceReportAuthority,
    PrivateAuthenticatedTerminalResultAuthority,
    PrivateCheckpointCompletionAuthority,
    PrivateFenceDeletionReadinessAuthority,
    PrivateFinalizerDepositSeal,
    PrivateR3FinalizerKickAuthority,
    PrivateR3AdmittedFinalizerKickAuthority,
    PrivateR3FinalizerCallbackContextAuthority,
    PrivateR3FinalizerRunningAuthority,
    PrivateR3FinalizerRunningPermitAuthority,
    PrivatePreparedDeleteExecutionPermitAuthority,
    PrivateFinalDeleteCursorAuthority,
    PrivateTerminalRendezvousResetAuthority,
    PrivatePreparedMountDeactivationAuthority,
    PrivateMountRendezvousResetAuthority,
);

/// The complete native owner chain nested inside R3 deletion readiness.
pub struct R4DeletionOwnerChain<Tail, Shell, RootRelease> {
    tail: Tail,
    shell: NativeSessionOwner<Shell>,
    root: SessionRootReleaseRight<RootRelease>,
}

/// Copy-only observations needed while the affine deletion tail stays nested.
/// Implementations expose neither the tail nor a control-context address.
pub trait R4DeletionTailOps {
    fn diagnostic(&self) -> DiagnosticId;
    fn closing_live_context_and_lease(&self, locator: SessionLocator) -> bool;
    fn completed_record_is_absent(&self) -> bool;
    fn publication_substrate_is_exact(&self, locator: SessionLocator) -> bool;
    /// # Safety
    /// The receipt must name this tail's own generation, and the caller must
    /// hold the durable slot for it, because committing visibility publishes
    /// the stored packet exactly once.
    unsafe fn commit_fail_stop_visibility<'stored>(
        &self,
        receipt: crate::session::StoredFailStopReceipt<'stored>,
    ) -> crate::session::CommittedStoredFailStopResolution<'stored>;
}

/// The complete native owner packet after a successful R3 finish.
pub struct FenceDeletionReadiness<Owners> {
    locator: SessionLocator,
    owners: Owners,
    mount: PreparedMountDeactivation,
    authority: PrivateFenceDeletionReadinessAuthority,
}

/// Readiness combined with the sole delete right inside the locked boundary.
///
/// There is no public constructor: neither a bare right nor readiness can
/// bypass the future consuming release/deposit transition.
pub struct FinalizerDeposit<Owners> {
    readiness: FenceDeletionReadiness<Owners>,
    right: DeleteSessionRight,
    authority: PrivateFinalizerDepositSeal,
}

/// The sole affine capability accepted by the finalizer queue endpoint.
///
/// `R3FinalizerCell::store_deposit_and_mint_kick` (and its prevalidated twin)
/// is the only place one is minted, and only after the complete deposit is
/// stored. It is intentionally non-`Clone`, non-`Default`, and unconstructible
/// by callers.
pub struct R3FinalizerKick {
    locator: SessionLocator,
    authority: PrivateR3FinalizerKickAuthority,
}

/// One admitted native callback fused to the sole stored-deposit queue kick.
///
/// The admission remains opaque to core, but cannot be separated from the kick
/// until [`run_r3_finalizer_queue`] consumes both at the production boundary.
pub struct R3AdmittedFinalizerKick<Admission> {
    kick: R3FinalizerKick,
    admission: Admission,
    authority: PrivateR3AdmittedFinalizerKickAuthority,
}

impl<Admission> R3AdmittedFinalizerKick<Admission> {
    pub const fn locator(&self) -> SessionLocator {
        self.kick.locator
    }

    pub const fn admission(&self) -> &Admission {
        &self.admission
    }
}

/// Affine identity carried by the native queue callback context.
///
/// It is minted only by [`run_r3_finalizer_queue`] from the one stored-deposit
/// kick and consumed only by [`run_r3_finalizer_callback`]. Keeping the full
/// locator (rather than only its array index) prevents a stale callback from
/// entering a competing generation that reused the same permanent cell.
pub struct R3FinalizerCallbackContext {
    locator: SessionLocator,
    authority: PrivateR3FinalizerCallbackContextAuthority,
}

impl R3FinalizerCallbackContext {
    pub const fn cell_index(&self) -> u32 {
        self.locator.slot_index()
    }
}

/// Proof that one exact permanent finalizer cell completed Queued -> Running.
///
/// The right is minted together with taking the stored deposit, so neither a
/// bare callback nor a copied locator can authorize the final reset.
pub struct R3FinalizerRunningRight {
    locator: SessionLocator,
    authority: PrivateR3FinalizerRunningAuthority,
}

/// Locator equality discharged before the destructive suffix begins.
///
/// `R3FinalizerRunningRight` carries the locator while preparation can still
/// refuse. The successful storage transition checks it against readiness and
/// the core commit, then turns it into this locator-free permit. Consequently
/// the final reset consumes a proven running authority instead of discarding a
/// locator after shell destruction.
struct R3FinalizerRunningPermit {
    authority: PrivateR3FinalizerRunningPermitAuthority,
}

impl R3FinalizerRunningRight {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    #[cfg(test)]
    pub(crate) fn for_test(locator: SessionLocator) -> Self {
        Self {
            locator,
            authority: PrivateR3FinalizerRunningAuthority(()),
        }
    }
}

/// The sole authority accepted by terminal-rendezvous deactivation.
///
/// It is minted only while the final reset cursor is consumed, after every
/// destructive suffix effect has completed.
pub struct TerminalRendezvousResetRight {
    locator: SessionLocator,
    authority: PrivateTerminalRendezvousResetAuthority,
}

impl TerminalRendezvousResetRight {
    pub(crate) fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateTerminalRendezvousResetAuthority(()),
        } = self;
        locator
    }
}

/// The sole successful-delete authority accepted by native storage execution.
pub struct PreparedDeleteExecutionPermit {
    commit: PreparedDeleteCoreCommit,
    authority: PrivatePreparedDeleteExecutionPermitAuthority,
}

/// Shell/root storage kept opaque until the first destructive suffix step.
pub struct PreparedDeleteStorage<Shell, RootRelease, NativeReset> {
    shell: NativeSessionOwner<Shell>,
    root: SessionRootReleaseRight<RootRelease>,
    mount: PreparedMountDeactivation,
    permit: PreparedDeleteExecutionPermit,
    running: R3FinalizerRunningPermit,
    native_reset: NativeReset,
}

/// The one exact native payload operation allowed to cross shell destruction.
///
/// # Safety
/// Implementations must destroy the shell first, release the root second, and
/// return no payload or authority. The core commit remains sealed inside
/// `permit` and is advanced only by the core-owned storage transition.
// The one method's obligation IS the trait contract stated above; repeating
// it per method would duplicate, not sharpen, it.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait PreparedDeleteStorageOps<RootRelease>: Sized {
    unsafe fn destroy_shell_then_release_root(
        self,
        root: RootRelease,
        permit: &PreparedDeleteExecutionPermit,
    );
}

/// Core-owned finalizer storage embedded in one permanent native cell.
///
/// It starts unbound and can name a generation only by consuming the third
/// install-origin bind right. The complete deposit and worker state live in
/// this one value, so no external trait can claim a no-op store and receive a
/// queue kick.
pub struct R3FinalizerCell<Owners> {
    locator: Option<SessionLocator>,
    deposit: Option<FinalizerDeposit<Owners>>,
    state: FinalizerState,
}

impl<Owners> FenceDeletionReadiness<Owners> {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    #[doc(hidden)]
    pub fn from_fence_complete(
        locator: SessionLocator,
        owners: Owners,
        mount: PreparedMountDeactivation,
    ) -> Self {
        Self {
            locator,
            owners,
            mount,
            authority: PrivateFenceDeletionReadinessAuthority(()),
        }
    }
}

#[cfg(test)]
impl<Owners> FenceDeletionReadiness<Owners> {
    pub(crate) fn for_test(locator: SessionLocator, owners: Owners) -> Self {
        Self {
            locator,
            owners,
            mount: PreparedMountDeactivation::for_test(locator),
            authority: PrivateFenceDeletionReadinessAuthority(()),
        }
    }
}

impl<Owners> FinalizerDeposit<Owners> {
    pub const fn locator(&self) -> SessionLocator {
        let _right = &self.right;
        let _authority = &self.authority;
        self.readiness.locator
    }

    /// Consume the bare delete right only inside core and return the complete
    /// deposit unchanged if the core slot refuses preparation.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // the error to shrink it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn prepare_final_delete_core<const N: usize>(
        self,
        registry: &SessionRegistry<N>,
    ) -> Result<(FenceDeletionReadiness<Owners>, PreparedDeleteCoreCommit), (SessionError, Self)>
    {
        let Self {
            readiness,
            right,
            authority: PrivateFinalizerDepositSeal(()),
        } = self;
        match registry.prepare_finish_delete_with_mount(right, &readiness.mount) {
            Ok(commit) => Ok((readiness, commit)),
            Err((error, right)) => Err((
                error,
                Self {
                    readiness,
                    right,
                    authority: PrivateFinalizerDepositSeal(()),
                },
            )),
        }
    }
}

impl R3FinalizerKick {
    /// Copy-only identity observation used to bind native callback admission.
    /// Queue authority remains affine and is consumed only by the core runner.
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Fuse a native callback admission to this one stored-deposit kick.
    pub fn admit<Admission>(self, admission: Admission) -> R3AdmittedFinalizerKick<Admission> {
        R3AdmittedFinalizerKick {
            kick: self,
            admission,
            authority: PrivateR3AdmittedFinalizerKickAuthority(()),
        }
    }

    /// Consume the sole kick at the real queue endpoint.
    fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateR3FinalizerKickAuthority(()),
        } = self;
        locator
    }
}

/// Consume one finalizer kick and drive the native publish/queue boundary.
///
/// Both callbacks are `FnOnce`; the affine context is published exactly once
/// and the exact value returned by that publication is queued exactly once.
/// The generic return lets WDK code publish a permanent-cell context and then
/// queue its preallocated work item without exposing either operation to core.
pub fn run_r3_finalizer_queue<Admission, Published, Queued>(
    admitted: R3AdmittedFinalizerKick<Admission>,
    publish: impl FnOnce(R3FinalizerCallbackContext, Admission) -> Published,
    queue: impl FnOnce(Published) -> Queued,
) -> Queued {
    let R3AdmittedFinalizerKick {
        kick,
        admission,
        authority: PrivateR3AdmittedFinalizerKickAuthority(()),
    } = admitted;
    let locator = kick.into_locator();
    let context = R3FinalizerCallbackContext {
        locator,
        authority: PrivateR3FinalizerCallbackContextAuthority(()),
    };
    queue(publish(context, admission))
}

/// Enter the exact permanent finalizer cell named across the queue boundary.
///
/// A matching array index is insufficient: a delayed callback must also name
/// the currently bound generation. Refusal consumes the stale callback context
/// and leaves the cell and its stored deposit untouched.
pub fn run_r3_finalizer_callback<'cell, Owners: 'cell>(
    context: R3FinalizerCallbackContext,
    enter_exact_cell: impl FnOnce(u32) -> Option<&'cell mut R3FinalizerCell<Owners>>,
) -> Option<(FinalizerDeposit<Owners>, R3FinalizerRunningRight)> {
    let R3FinalizerCallbackContext {
        locator,
        authority: PrivateR3FinalizerCallbackContextAuthority(()),
    } = context;
    let cell = enter_exact_cell(locator.slot_index())?;
    if cell.locator() != Some(locator) {
        return None;
    }
    cell.take_deposit_and_begin_run()
}

/// Which native wake completes one finalizer visibility resolution.
///
/// Published already owns the combined visibility/outcome wake. Every other
/// durable resolution owns only the visibility latch. Keeping this choice in a
/// WDK-free runner prevents a Published continuation from setting the latch
/// once directly and then a second time through its combined outcome signal.
pub enum R3FailStopVisibilityWake<Published> {
    Published(Published),
    LatchOnly,
}

/// Drive exactly one native wake for one finalizer visibility resolution.
pub fn run_r3_fail_stop_visibility_wake<Published>(
    wake: R3FailStopVisibilityWake<Published>,
    signal_latch: impl FnOnce(),
    signal_published: impl FnOnce(Published),
) {
    match wake {
        R3FailStopVisibilityWake::Published(published) => signal_published(published),
        R3FailStopVisibilityWake::LatchOnly => signal_latch(),
    }
}

/// Continuation prepared while the registry lock still protects both the
/// durable fail-stop slot and its terminal rendezvous.
///
/// Payloads are deliberately caller-defined affine values: the native adapter
/// can carry the exact authenticated join/wait authority across the unlock
/// boundary without this WDK-free core fabricating a ticket or rescanning a
/// registry.
pub enum R3FailStopPreparedContinuation<PublishedSignal, Published, Opaque, Retained> {
    Published {
        signal: PublishedSignal,
        continuation: Published,
    },
    Opaque(Opaque),
    Retained(Retained),
}

/// Run one fail-stop continuation in two ordered phases.
///
/// `prepare_locked` stores/commits the packet and authenticates any rendezvous
/// continuation while `locked` is still held. The runner then consumes that
/// lock exactly once, emits the one wake selected by the committed resolution,
/// and only afterwards converts the matching affine continuation into the
/// caller's one shared output. For unload that output is the authenticated
/// blocked-wait token consumed by the outer unload runner; the seam itself
/// never nests a permanent wait inside the cell scan.
// The eight parameters are the eight distinct stages of one seam. Grouping
// them into a struct would let a caller build a partial seam and hold it,
// which is exactly what taking them together prevents.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn run_r3_fail_stop_two_phase<Locked, PublishedSignal, Published, Opaque, Retained, Output>(
    mut locked: Locked,
    prepare_locked: impl FnOnce(
        &mut Locked,
    ) -> R3FailStopPreparedContinuation<
        PublishedSignal,
        Published,
        Opaque,
        Retained,
    >,
    unlock: impl FnOnce(Locked),
    signal_latch: impl FnOnce(),
    signal_published: impl FnOnce(PublishedSignal),
    continue_published: impl FnOnce(Published) -> Output,
    continue_opaque: impl FnOnce(Opaque) -> Output,
    continue_retained: impl FnOnce(Retained) -> Output,
) -> Output {
    let continuation = prepare_locked(&mut locked);
    unlock(locked);

    match continuation {
        R3FailStopPreparedContinuation::Published {
            signal,
            continuation,
        } => {
            run_r3_fail_stop_visibility_wake(
                R3FailStopVisibilityWake::Published(signal),
                signal_latch,
                signal_published,
            );
            continue_published(continuation)
        }
        R3FailStopPreparedContinuation::Opaque(continuation) => {
            run_r3_fail_stop_visibility_wake(
                R3FailStopVisibilityWake::LatchOnly,
                signal_latch,
                signal_published,
            );
            continue_opaque(continuation)
        }
        R3FailStopPreparedContinuation::Retained(continuation) => {
            run_r3_fail_stop_visibility_wake(
                R3FailStopVisibilityWake::LatchOnly,
                signal_latch,
                signal_published,
            );
            continue_retained(continuation)
        }
    }
}

impl<Owners> R3FinalizerCell<Owners> {
    pub const fn new_unbound() -> Self {
        Self {
            locator: None,
            deposit: None,
            state: FinalizerState::Idle,
        }
    }

    /// Bind the permanent cell to the same install that minted shell/root
    /// rights. Refusal returns the affine right unchanged.
    pub fn bind(
        &mut self,
        right: crate::session::R3FinalizerCellBindRight,
    ) -> Result<(), crate::session::R3FinalizerCellBindRight> {
        if self.locator.is_some()
            || self.deposit.is_some()
            || !matches!(self.state, FinalizerState::Idle)
        {
            return Err(right);
        }
        self.locator = Some(right.into_locator());
        Ok(())
    }

    pub const fn locator(&self) -> Option<SessionLocator> {
        self.locator
    }

    pub const fn state(&self) -> FinalizerState {
        self.state
    }

    pub const fn deposit_is_none(&self) -> bool {
        self.deposit.is_none()
    }

    /// The sole locked store+queue transition. The complete deposit is moved
    /// here before the returned kick exists.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // the error to shrink it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn store_deposit_and_mint_kick(
        &mut self,
        readiness: FenceDeletionReadiness<Owners>,
        right: DeleteSessionRight,
    ) -> Result<R3FinalizerKick, (FenceDeletionReadiness<Owners>, DeleteSessionRight)> {
        let locator = readiness.locator;
        if self.locator != Some(locator)
            || right.locator() != locator
            || self.deposit.is_some()
            || !matches!(self.state, FinalizerState::Idle)
        {
            return Err((readiness, right));
        }
        if self.state.queue().is_err() {
            return Err((readiness, right));
        }
        // SAFETY: every precondition was checked above and `queue` committed
        // the exact Idle -> Queued transition.
        Ok(unsafe { self.store_deposit_and_mint_kick_prevalidated(readiness, right) })
    }

    /// Commit the already-preflighted permanent-cell deposit infallibly.
    ///
    /// # Safety
    /// The cell is bound to `readiness`, its deposit is empty, `right` names
    /// that locator, and state is already `Queued` or is exact `Idle`.
    pub unsafe fn store_deposit_and_mint_kick_prevalidated(
        &mut self,
        readiness: FenceDeletionReadiness<Owners>,
        right: DeleteSessionRight,
    ) -> R3FinalizerKick {
        let locator = readiness.locator;
        if matches!(self.state, FinalizerState::Idle) {
            self.state = FinalizerState::Queued;
        }
        self.deposit = Some(FinalizerDeposit {
            readiness,
            right,
            authority: PrivateFinalizerDepositSeal(()),
        });
        R3FinalizerKick {
            locator,
            authority: PrivateR3FinalizerKickAuthority(()),
        }
    }

    /// Take the exact stored deposit and become its one running callback.
    fn take_deposit_and_begin_run(
        &mut self,
    ) -> Option<(FinalizerDeposit<Owners>, R3FinalizerRunningRight)> {
        if !matches!(self.state, FinalizerState::Queued) {
            return None;
        }
        let deposit = self.deposit.take()?;
        if self.state.begin_run().is_err() {
            self.deposit = Some(deposit);
            return None;
        }
        let locator = deposit.locator();
        Some((
            deposit,
            R3FinalizerRunningRight {
                locator,
                authority: PrivateR3FinalizerRunningAuthority(()),
            },
        ))
    }

    pub fn fail_stop(&mut self) -> Result<(), LifecycleError> {
        self.state.fail_stop()
    }

    pub fn fail_stop_preflight(&self, locator: SessionLocator) -> bool {
        self.locator == Some(locator)
            && self.deposit.is_none()
            && matches!(self.state, FinalizerState::Running)
    }

    /// # Safety
    /// `fail_stop_preflight(locator)` was true in this unchanged registry-lock
    /// hold, before the complete delete refusal packet entered durable storage.
    pub unsafe fn commit_fail_stop_prepared(&mut self) {
        self.state = FinalizerState::DeleteFailStop;
    }

    /// Consume the one bundled final cursor and reset the core registry plus
    /// finalizer binding in one transition.
    ///
    /// # Safety
    /// The remaining infallible delete suffix has completed and `registry` is
    /// the core registry paired with this permanent native finalizer cell.
    pub unsafe fn finish_run_and_reset<const N: usize, NativeReset>(
        &mut self,
        registry: &mut SessionRegistry<N>,
        pending: PendingFinalDeleteReset<NativeReset>,
    ) -> (
        SlotDisposition,
        FinalDeleteProof,
        NativeReset,
        TerminalRendezvousResetRight,
        MountRendezvousResetRight,
    ) {
        let (commit, running, native_reset, proof, terminal_reset, mount_reset) =
            pending.finish_after_reset();
        let R3FinalizerRunningPermit {
            authority: PrivateR3FinalizerRunningPermitAuthority(()),
        } = running;
        // SAFETY: the post-storage right proves both native owners were
        // consumed, the running right proves the deposit was taken exactly
        // once, and the final cursor proves every later suffix step completed.
        let disposition = unsafe { registry.finish_delete(commit) };
        self.state = FinalizerState::Idle;
        self.locator = None;
        (
            disposition,
            proof,
            native_reset,
            terminal_reset,
            mount_reset,
        )
    }
}

impl PreparedDeleteExecutionPermit {
    fn into_commit(self) -> PreparedDeleteCoreCommit {
        let Self {
            commit,
            authority: PrivatePreparedDeleteExecutionPermitAuthority(()),
        } = self;
        commit
    }
}

impl<Tail, Shell, RootRelease>
    FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>>
{
    /// Move the native owners directly into sealed prepared-delete storage;
    /// only the non-native tail is returned to the suffix.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // the error to shrink it would need an allocator this path does not have.
    // The tuple is equally irreducible: each component is a distinct affine
    // owner, so a type alias would name the shape without simplifying it.
    #[allow(clippy::result_large_err)]
    #[allow(clippy::type_complexity)]
    pub fn into_prepared_delete_storage<NativeReset>(
        self,
        commit: PreparedDeleteCoreCommit,
        running: R3FinalizerRunningRight,
        native_reset: NativeReset,
    ) -> Result<
        (Tail, PreparedDeleteStorage<Shell, RootRelease, NativeReset>),
        (
            Self,
            PreparedDeleteCoreCommit,
            R3FinalizerRunningRight,
            NativeReset,
        ),
    > {
        if commit.locator() != self.locator || running.locator() != self.locator {
            return Err((self, commit, running, native_reset));
        }
        // SAFETY: the comparisons above discharged every locator before any
        // destructive operation can begin.
        Ok(
            unsafe {
                self.into_prepared_delete_storage_prevalidated(commit, running, native_reset)
            },
        )
    }

    /// Commit a storage transition whose complete locator cross-product was
    /// already checked while all affine inputs were intact.
    ///
    /// # Safety
    /// `self`, `commit`, and `running` name the same exact locator. Callers
    /// must establish that before invoking this infallible transition.
    #[doc(hidden)]
    pub unsafe fn into_prepared_delete_storage_prevalidated<NativeReset>(
        self,
        commit: PreparedDeleteCoreCommit,
        running: R3FinalizerRunningRight,
        native_reset: NativeReset,
    ) -> (Tail, PreparedDeleteStorage<Shell, RootRelease, NativeReset>) {
        let Self {
            locator: _,
            owners,
            mount,
            authority: PrivateFenceDeletionReadinessAuthority(()),
        } = self;
        let R3FinalizerRunningRight {
            locator: _,
            authority: PrivateR3FinalizerRunningAuthority(()),
        } = running;
        let R4DeletionOwnerChain { tail, shell, root } = owners;
        (
            tail,
            PreparedDeleteStorage {
                shell,
                root,
                mount,
                permit: PreparedDeleteExecutionPermit {
                    commit,
                    authority: PrivatePreparedDeleteExecutionPermitAuthority(()),
                },
                running: R3FinalizerRunningPermit {
                    authority: PrivateR3FinalizerRunningPermitAuthority(()),
                },
                native_reset,
            },
        )
    }
}

impl<Tail, Shell, RootRelease>
    FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>>
where
    Tail: R4DeletionTailOps,
{
    pub fn diagnostic(&self) -> DiagnosticId {
        self.owners.tail.diagnostic()
    }

    pub fn closing_live_context_and_lease(&self) -> bool {
        self.owners
            .tail
            .closing_live_context_and_lease(self.locator)
    }

    pub fn completed_record_is_absent(&self) -> bool {
        self.owners.tail.completed_record_is_absent()
    }

    pub fn publication_substrate_is_exact(&self) -> bool {
        self.owners
            .tail
            .publication_substrate_is_exact(self.locator)
    }

    /// # Safety
    /// Forwards to the nested tail, so the receipt must name this exact
    /// generation's durable slot and be committed once. The tail itself is
    /// never exposed by this call.
    pub unsafe fn commit_fail_stop_visibility<'stored>(
        &self,
        receipt: crate::session::StoredFailStopReceipt<'stored>,
    ) -> crate::session::CommittedStoredFailStopResolution<'stored> {
        unsafe { self.owners.tail.commit_fail_stop_visibility(receipt) }
    }
}

impl<Tail, Shell, RootRelease> FinalizerDeposit<R4DeletionOwnerChain<Tail, Shell, RootRelease>>
where
    Tail: R4DeletionTailOps,
{
    pub fn diagnostic(&self) -> DiagnosticId {
        self.readiness.diagnostic()
    }

    pub fn closing_live_context_and_lease(&self) -> bool {
        self.readiness.closing_live_context_and_lease()
    }

    pub fn completed_record_is_absent(&self) -> bool {
        self.readiness.completed_record_is_absent()
    }

    pub fn publication_substrate_is_exact(&self) -> bool {
        self.readiness.publication_substrate_is_exact()
    }

    /// # Safety
    /// Forwards to the nested tail, so the receipt must name this exact
    /// generation's durable slot and be committed once. The tail itself is
    /// never exposed by this call.
    pub unsafe fn commit_fail_stop_visibility<'stored>(
        &self,
        receipt: crate::session::StoredFailStopReceipt<'stored>,
    ) -> crate::session::CommittedStoredFailStopResolution<'stored> {
        unsafe { self.readiness.commit_fail_stop_visibility(receipt) }
    }

    pub fn validate_final_delete_core<const N: usize>(
        &self,
        registry: &SessionRegistry<N>,
    ) -> Result<SlotDisposition, SessionError> {
        registry.validate_finish_delete_with_mount(&self.right, &self.readiness.mount)
    }
}

impl<Shell, RootRelease, NativeReset> PreparedDeleteStorage<Shell, RootRelease, NativeReset>
where
    Shell: PreparedDeleteStorageOps<RootRelease>,
{
    /// Execute the fixed shell-destroy/root-release operation.
    ///
    /// # Safety
    /// This is the first destructive step of the already-prepared suffix.
    unsafe fn execute(self) -> PendingCompletedPublication<NativeReset> {
        let Self {
            shell,
            root,
            mount,
            permit,
            running,
            native_reset,
        } = self;
        unsafe {
            crate::adapter::lifecycle::execute_prepared_delete_payloads(shell, root, &permit)
        };
        let commit = permit.into_commit();
        FinalDeleteCursor {
            locator: commit.locator(),
            record: FinalDeleteRecord {
                freed: Some(0),
                transferred: None,
                published: None,
                signalled: None,
                arrivals_drained: None,
                drained: None,
                rundown_completed: None,
                reset: None,
                steps: 2,
            },
            bundle: FinalDeleteResetBundle {
                commit,
                running,
                mount,
                native_reset,
            },
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }
}

/// The closed native operation surface for the post-preflight delete suffix.
///
/// The shell/root storage operation supplies logical steps 1 and 2. The core
/// runner below owns steps 3 through 10 and their consuming cursors. Every
/// method is infallible: after shell destruction begins there is no recovery
/// state to which a refusal could safely return.
///
/// # Safety
/// Implementations perform each named operation exactly once for `locator`,
/// preserve the fused lock hold of transfer+publication, and consume the final
/// reset cursor only after every earlier operation returned.
// Every method below is one step of the single ordered suffix whose
// once-each, fused-hold, cursor-last contract the trait states above; a
// per-method copy would restate the same paragraph eight times.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait R3PreparedDeleteNativeOps<NativeReset> {
    /// Logical steps 3 and 4, fused under the native registry lock.
    unsafe fn transfer_closing_owner_to_completed_record_and_publish_outcome(
        &mut self,
        locator: SessionLocator,
    );
    unsafe fn signal_terminal_outcome(&mut self, locator: SessionLocator);
    unsafe fn drain_counted_arrivals(&mut self, locator: SessionLocator);
    unsafe fn wait_joiners_drained(&mut self, locator: SessionLocator);
    unsafe fn complete_access_rundown(&mut self, locator: SessionLocator);
    /// Logical step 9. For `Retired`, this records the explicit skipped
    /// reinitialization and performs no DDI.
    unsafe fn reinitialize_access_rundown_if_reusable(
        &mut self,
        locator: SessionLocator,
        disposition: SlotDisposition,
    );
    unsafe fn reset_cell_and_publish_disposition(
        &mut self,
        pending: PendingFinalDeleteReset<NativeReset>,
    ) -> FinalDeleteProof;
}

/// Execute the exact ten-step prepared-delete suffix used by production.
///
/// There is deliberately no `Result`, refusal callback, or success enum. The
/// caller has already crossed the complete seven-predicate preflight; this
/// function can only consume forward to one final proof.
///
/// # Safety
/// `storage` and `native` belong to the same prepared generation, no registry
/// lock is held on entry, and the native implementation satisfies
/// [`R3PreparedDeleteNativeOps`].
#[inline(never)]
pub unsafe fn run_r3_prepared_delete_suffix<Shell, RootRelease, NativeReset, Native>(
    storage: PreparedDeleteStorage<Shell, RootRelease, NativeReset>,
    native: &mut Native,
) -> FinalDeleteProof
where
    Shell: PreparedDeleteStorageOps<RootRelease>,
    Native: R3PreparedDeleteNativeOps<NativeReset>,
{
    let cursor = unsafe { storage.execute() };
    let locator = cursor.locator();

    unsafe { native.transfer_closing_owner_to_completed_record_and_publish_outcome(locator) };
    let cursor = cursor.completed_publication_completed();

    unsafe { native.signal_terminal_outcome(locator) };
    let cursor = cursor.outcome_signalled();

    unsafe { native.drain_counted_arrivals(locator) };
    let cursor = cursor.counted_arrivals_drained();

    unsafe { native.wait_joiners_drained(locator) };
    let cursor = cursor.joiners_drained();

    unsafe { native.complete_access_rundown(locator) };
    let cursor = cursor.access_rundown_completed();
    let disposition = cursor.disposition();

    unsafe { native.reinitialize_access_rundown_if_reusable(locator, disposition) };
    let cursor = match disposition {
        SlotDisposition::Free => cursor.reinitialized_for_reuse(),
        SlotDisposition::Retired => cursor.retired_without_reinitialize(),
    };

    unsafe { native.reset_cell_and_publish_disposition(cursor) }
}

/// The closed R3 checkpoint roster.
///
/// DEVIATION (recorded in the Task 10 evidence): the plan's interface sketch
/// writes `FencePassCursor::Roster(FenceEffect)`. These are not
/// `FenceEffect` values. Nine of the sixteen names below do not exist in that
/// enum — `WaitSessionAccessRundown`, `WaitExistingSqCqRolesAndConsumers`,
/// `ReleaseControlStrongRef`, `VerifySessionAndRootLedgers`, and the rest — and
/// the global constraint fixes `FenceEffect` at exactly the sixteen values Task
/// 25 must execute. Widening `FenceEffect` to hold both rosters would make
/// "all 16 `FenceEffect` values" ambiguous at the one place it has to be exact.
/// A separate closed enum keeps both rosters honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointFenceEffect {
    CloseSessionAdmission,
    /// Wake every existing ENTER waiter AND deposit a Fence wake in every
    /// installed pending context.
    ///
    /// Renamed from `SignalPendingEnter` because it gained the second
    /// half rather than acquiring a synonym: the carried waiter wake still runs
    /// first, and the pending deposit happens before either rundown wait, so no
    /// parked ENTER is still asleep when the checkpoint begins waiting on it.
    SignalPendingEnter,
    WaitControlRundown,
    WaitSessionAccessRundown,
    WaitExistingSqCqRolesAndConsumers,
    RemoveProducerMappingsReverse,
    WaitProducerAndMappingCaptureRundown,
    RetireExistingGrantAndCreditState,
    /// Take every ring's consumer role, in increasing ring order.
    ///
    /// Increasing order is the content: two checkpoints taking the same set in
    /// opposite orders is the deadlock this row exists to make impossible.
    AcquireConsumersIncreasing,
    ReleaseConsumers,
    /// Turn each stored HandoffDone wake into at most one queued Worker owner,
    /// after unlock.
    QueueInstalledWork,
    /// Wait every Active context out: scheduled, drained, and reporting Vacant
    /// or EpochExhausted with an empty fail-stop slot.
    ///
    /// Real typed execution, not an observation. A same-epoch publication
    /// witness refuses here and never becomes a drained proof.
    WaitPendingAndOwners,
    ReleaseReadOnlyMappingsReverse,
    ReleaseMdlsAndSystemView,
    ReleaseCapturedProcess,
    DismountAndDeleteDevices,
    ReleaseTransientArraysAndBacking,
    ReleaseControlStrongRef,
    ReleaseRemainingStableSessionOwners,
    VerifySessionAndRootLedgers,
}

/// The R3 roster in dependency order. It is the only order this module runs.
pub const R4_CHECKPOINT_ROSTER: [CheckpointFenceEffect; 20] = [
    CheckpointFenceEffect::CloseSessionAdmission,
    CheckpointFenceEffect::SignalPendingEnter,
    CheckpointFenceEffect::WaitControlRundown,
    CheckpointFenceEffect::WaitSessionAccessRundown,
    CheckpointFenceEffect::WaitExistingSqCqRolesAndConsumers,
    CheckpointFenceEffect::RemoveProducerMappingsReverse,
    CheckpointFenceEffect::WaitProducerAndMappingCaptureRundown,
    CheckpointFenceEffect::RetireExistingGrantAndCreditState,
    CheckpointFenceEffect::AcquireConsumersIncreasing,
    CheckpointFenceEffect::ReleaseConsumers,
    CheckpointFenceEffect::QueueInstalledWork,
    CheckpointFenceEffect::WaitPendingAndOwners,
    CheckpointFenceEffect::ReleaseReadOnlyMappingsReverse,
    CheckpointFenceEffect::ReleaseMdlsAndSystemView,
    CheckpointFenceEffect::ReleaseCapturedProcess,
    CheckpointFenceEffect::DismountAndDeleteDevices,
    CheckpointFenceEffect::ReleaseTransientArraysAndBacking,
    CheckpointFenceEffect::ReleaseControlStrongRef,
    CheckpointFenceEffect::ReleaseRemainingStableSessionOwners,
    CheckpointFenceEffect::VerifySessionAndRootLedgers,
];

impl CheckpointFenceEffect {
    /// This effect's position in the closed roster.
    ///
    /// The index is the bit position in a report mask, so it is derived from the
    /// roster rather than written twice.
    pub const fn roster_index(self) -> u8 {
        let mut index = 0usize;
        while index < R4_CHECKPOINT_ROSTER.len() {
            // PROOF: `index` is bounded by the array length on every iteration,
            // and `<[T]>::get` is unavailable in a const context.
            #[allow(clippy::indexing_slicing)]
            if matches_effect(R4_CHECKPOINT_ROSTER[index], self) {
                // PROOF: the roster has 16 entries, so the index fits a u8.
                #[allow(clippy::cast_possible_truncation)]
                return index as u8;
            }
            // PROOF: bounded by the loop condition.
            #[allow(clippy::arithmetic_side_effects)]
            {
                index += 1;
            }
        }
        unreachable!()
    }

    const fn mask_bit(self) -> u32 {
        1u32 << self.roster_index()
    }
}

const fn matches_effect(left: CheckpointFenceEffect, right: CheckpointFenceEffect) -> bool {
    left as u8 == right as u8
}

/// Which roster entries one checkpoint pass attempted, and which refused.
///
/// Two masks rather than one cursor: "stopped at entry 8" does not say whether
/// entry 8 was tried, and a report that cannot distinguish those two is a report
/// a fail-stop packet cannot be read from.
#[derive(Debug)]
pub struct FenceReport {
    locator: SessionLocator,
    attempted_mask: u32,
    failed_mask: u32,
    authority: PrivateFenceReportAuthority,
}

impl FenceReport {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.locator
    }

    pub const fn attempted_mask(&self) -> u32 {
        self.attempted_mask
    }

    pub const fn failed_mask(&self) -> u32 {
        self.failed_mask
    }

    pub const fn attempted(&self, effect: CheckpointFenceEffect) -> bool {
        self.attempted_mask & effect.mask_bit() != 0
    }

    pub const fn failed(&self, effect: CheckpointFenceEffect) -> bool {
        self.failed_mask & effect.mask_bit() != 0
    }

    /// Every roster entry was attempted and none refused.
    pub const fn is_complete(&self) -> bool {
        self.attempted_mask == FULL_ROSTER_MASK && self.failed_mask == 0
    }
}

/// Every bit of the 20-entry roster, derived from the roster length rather
/// than written as a literal: a roster that grows without this growing would
/// make  unsatisfiable, and one that shrinks would make it
/// satisfiable by a pass that skipped the tail.
const FULL_ROSTER_MASK: u32 = (1u32 << R4_CHECKPOINT_ROSTER.len()) - 1;

/// Where a checkpoint pass stopped.
///
/// `FinishPreparation` is not a roster entry: the teardown itself succeeded and
/// the *preparation* that follows it refused, which is a different failure with
/// a different owner set to return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FencePassCursor {
    /// The native executor was bound to a different generation, so the runner
    /// refused before attempting the first roster operation.
    ExecutorBinding,
    Roster(CheckpointFenceEffect),
    FinishPreparation,
}

/// The terminal result a counted winner authenticated.
///
/// It carries the winner itself, so a result can never be paired with a
/// diagnostic or reason from another generation: the publication path reads
/// both out of the same value.
#[derive(Debug)]
pub struct AuthenticatedTerminalResult {
    winner: TerminalWinner,
    result: TerminalResult,
    authority: PrivateAuthenticatedTerminalResultAuthority,
}

impl AuthenticatedTerminalResult {
    /// Bind one counted winner to the result its own run produced.
    ///
    /// The reason must match: a winner that claimed for CLEANUP cannot publish a
    /// process-loss result, and refusing here is what stops a runner from
    /// relabelling why a generation died.
    #[allow(clippy::result_large_err)]
    pub fn new(
        winner: TerminalWinner,
        result: TerminalResult,
    ) -> Result<Self, (TerminalWinner, TerminalResult)> {
        if winner.reason() != result.reason {
            return Err((winner, result));
        }
        Ok(Self {
            winner,
            result,
            authority: PrivateAuthenticatedTerminalResultAuthority(()),
        })
    }

    pub const fn locator(&self) -> SessionLocator {
        self.winner.locator()
    }

    pub const fn result(&self) -> TerminalResult {
        self.result
    }

    pub const fn diagnostic(&self) -> DiagnosticId {
        self.winner.diagnostic()
    }

    pub fn into_parts(self) -> (TerminalWinner, TerminalResult) {
        let Self {
            winner,
            result,
            authority: PrivateAuthenticatedTerminalResultAuthority(()),
        } = self;
        (winner, result)
    }
}

/// Proof that no authority a later checkpoint introduces exists for this cell.
///
/// The constructor is keyed to the embedded artifact identity, so this cannot be
/// minted by a binary whose production graph was never proven. It is the reason
/// an R3 checkpoint may delete at all: everything the *Task 12* binary can
/// produce is discharged, and everything a later binary could produce is absent
/// because this binary cannot construct it.
#[derive(Debug)]
pub struct ProductionAbsenceWitness {
    locator: SessionLocator,
    artifact: ProductionGraphArtifactIdentity,
}

impl ProductionAbsenceWitness {
    /// The production constructor: only an embedded, verified witness admits it.
    #[doc(hidden)]
    pub fn from_embedded_artifact(
        locator: SessionLocator,
    ) -> Result<Self, ProductionAttestationError> {
        let artifact = embedded_r4_authority_absence()?;
        Ok(Self { locator, artifact })
    }

    /// Tasks 9-11 expose only this, bound to injected PASS evidence.
    #[cfg(test)]
    pub(crate) fn injected_for_test(
        locator: SessionLocator,
    ) -> Result<Self, ProductionAttestationError> {
        let artifact = injected_r4_authority_absence_for_test()?;
        Ok(Self { locator, artifact })
    }

    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn artifact(&self) -> ProductionGraphArtifactIdentity {
        self.artifact
    }
}

/// A checkpoint-local completion proof. Never `FenceObligationsDischarged`.
///
/// The absence proof is stored inside rather than beside it, so no caller can
/// hold a completion that is not accompanied by the artifact identity that makes
/// it admissible.
#[derive(Debug)]
pub struct ClosedFenceRosterComplete {
    locator: SessionLocator,
    report: FenceReport,
    absence: ProductionAbsenceWitness,
}

/// Checkpoint completion paired with the exact mount deactivation authority.
///
/// Only this carrier may enter production deletion readiness. The earlier
/// `ClosedFenceRosterComplete` deliberately has no production owner-binding method,
/// preventing a completed roster from bypassing mount absence.
pub struct R4TeardownWithMount {
    complete: ClosedFenceRosterComplete,
    mount: PreparedMountDeactivation,
}

impl ClosedFenceRosterComplete {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn report(&self) -> &FenceReport {
        &self.report
    }

    pub const fn absence(&self) -> &ProductionAbsenceWitness {
        &self.absence
    }

    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // the error to shrink it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn with_mount(
        self,
        bound: BoundCompletedMountTeardown,
    ) -> Result<R4TeardownWithMount, (Self, BoundCompletedMountTeardown)> {
        if bound.locator() != self.locator {
            return Err((self, bound));
        }
        Ok(R4TeardownWithMount {
            complete: self,
            mount: bound.into_prepared_deactivation(),
        })
    }

    /// Bind this completed checkpoint to the exact native shell/root owners.
    /// A crossed owner is returned intact; no partial readiness is minted.
    ///
    /// # Safety
    /// The three owners must be the live native owners of this exact
    /// generation. A crossed owner is returned intact rather than bound, so
    /// the caller keeps whatever it passed in either outcome.
    #[cfg(test)]
    // Every refusal hands all four owners back, which is the property the
    // large `Err` exists to carry; boxing it would need an allocator.
    #[allow(clippy::type_complexity, clippy::result_large_err)]
    pub unsafe fn bind_deletion_owners<Tail, Shell, RootRelease>(
        self,
        tail: Tail,
        shell: NativeSessionOwner<Shell>,
        root: SessionRootReleaseRight<RootRelease>,
    ) -> Result<
        FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>>,
        (
            Self,
            Tail,
            NativeSessionOwner<Shell>,
            SessionRootReleaseRight<RootRelease>,
        ),
    > {
        let locator = self.locator;
        if shell.locator() != locator || root.locator() != locator {
            return Err((self, tail, shell, root));
        }
        Ok(FenceDeletionReadiness {
            locator,
            owners: R4DeletionOwnerChain { tail, shell, root },
            mount: PreparedMountDeactivation::for_test(locator),
            authority: PrivateFenceDeletionReadinessAuthority(()),
        })
    }
}

impl R4TeardownWithMount {
    pub const fn locator(&self) -> SessionLocator {
        self.complete.locator
    }

    pub const fn mount_cursor(&self) -> MountAbsenceCursor {
        self.mount.cursor()
    }

    pub const fn report(&self) -> &FenceReport {
        &self.complete.report
    }

    pub const fn absence(&self) -> &ProductionAbsenceWitness {
        &self.complete.absence
    }

    /// Bind the complete checkpoint and authentic mount deactivation to the
    /// exact native owners in model tests. Production uses the prevalidated
    /// consuming constructor below after checking the complete owner tuple.
    ///
    /// # Safety
    /// The three owners must be the live native owners of this exact
    /// generation. A crossed owner is returned intact rather than bound, so
    /// the caller keeps whatever it passed in either outcome.
    #[cfg(test)]
    // Every refusal hands all four owners back, which is the property the
    // large `Err` exists to carry; boxing it would need an allocator.
    #[allow(clippy::type_complexity, clippy::result_large_err)]
    pub unsafe fn bind_deletion_owners<Tail, Shell, RootRelease>(
        self,
        tail: Tail,
        shell: NativeSessionOwner<Shell>,
        root: SessionRootReleaseRight<RootRelease>,
    ) -> Result<
        FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>>,
        (
            Self,
            Tail,
            NativeSessionOwner<Shell>,
            SessionRootReleaseRight<RootRelease>,
        ),
    > {
        let locator = self.complete.locator;
        if shell.locator() != locator || root.locator() != locator {
            return Err((self, tail, shell, root));
        }
        Ok(unsafe { self.bind_deletion_owners_prevalidated(tail, shell, root) })
    }

    /// Move the complete owner chain into readiness after the locator
    /// cross-product was checked without mutation.
    ///
    /// # Safety
    /// Both native owner envelopes name `self.locator()`.
    pub unsafe fn bind_deletion_owners_prevalidated<Tail, Shell, RootRelease>(
        self,
        tail: Tail,
        shell: NativeSessionOwner<Shell>,
        root: SessionRootReleaseRight<RootRelease>,
    ) -> FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>> {
        let locator = self.complete.locator;
        FenceDeletionReadiness {
            locator,
            owners: R4DeletionOwnerChain { tail, shell, root },
            mount: self.mount,
            authority: PrivateFenceDeletionReadinessAuthority(()),
        }
    }
}

/// A permanent checkpoint fail-stop observation.
///
/// It is deliberately copyable and owns nothing: publishing it must not move any
/// authority out of the fail-stop packet that keeps the generation retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetiredCheckpointBlocked {
    R4 {
        effect: FencePassCursor,
        diagnostic: DiagnosticId,
    },
}

impl RetiredCheckpointBlocked {
    pub const fn diagnostic(&self) -> DiagnosticId {
        match self {
            Self::R4 { diagnostic, .. } => *diagnostic,
        }
    }

    pub const fn effect(&self) -> FencePassCursor {
        match self {
            Self::R4 { effect, .. } => *effect,
        }
    }
}

/// A permanent deletion fail-stop observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeleteTerminalBlocked {
    step: FinalizerPreflightStep,
    diagnostic: DiagnosticId,
}

impl DeleteTerminalBlocked {
    #[doc(hidden)]
    pub const fn new(step: FinalizerPreflightStep, diagnostic: DiagnosticId) -> Self {
        Self { step, diagnostic }
    }

    pub const fn step(&self) -> FinalizerPreflightStep {
        self.step
    }

    pub const fn diagnostic(&self) -> DiagnosticId {
        self.diagnostic
    }
}

// ---------------------------------------------------------------------------
// The scheduler
// ---------------------------------------------------------------------------

/// One roster entry the native executor must now perform.
#[derive(Debug)]
pub struct PendingCheckpointEffect {
    roster: [CheckpointFenceEffect; 20],
    next: u8,
    locator: SessionLocator,
    attempted_mask: u32,
    failed_mask: u32,
}

/// A pass that ran every roster entry successfully.
#[derive(Debug)]
pub struct CompletedCheckpointTeardown {
    locator: SessionLocator,
    report: FenceReport,
    authority: PrivateCheckpointCompletionAuthority,
}

/// A pass that stopped at one exact refusing entry.
#[derive(Debug)]
pub struct RefusedCheckpointTeardown {
    cursor: FencePassCursor,
    report: FenceReport,
}

#[derive(Debug)]
pub enum CheckpointTeardownProgress {
    Effect(PendingCheckpointEffect),
    Complete(CompletedCheckpointTeardown),
    Refused(RefusedCheckpointTeardown),
}

pub struct CheckpointTeardownPlan;

impl CheckpointTeardownPlan {
    pub const ROSTER: [CheckpointFenceEffect; 20] = R4_CHECKPOINT_ROSTER;

    pub const fn begin(locator: SessionLocator) -> CheckpointTeardownProgress {
        Self::begin_inner(locator, Self::ROSTER)
    }

    /// Begin from an explicit roster.
    ///
    /// Production has exactly one roster and [`Self::begin`] is its only caller.
    /// Tests drive a deliberately reordered one through this seam so
    /// [`CompletedCheckpointTeardown::ran_the_closed_roster_in_order`] can be
    /// observed reporting `false`; without it that proof could be a constant.
    #[cfg(test)]
    pub(crate) const fn begin_with_roster(
        locator: SessionLocator,
        roster: [CheckpointFenceEffect; 20],
    ) -> CheckpointTeardownProgress {
        Self::begin_inner(locator, roster)
    }

    const fn begin_inner(
        locator: SessionLocator,
        roster: [CheckpointFenceEffect; 20],
    ) -> CheckpointTeardownProgress {
        CheckpointTeardownProgress::Effect(PendingCheckpointEffect {
            roster,
            next: 0,
            locator,
            attempted_mask: 0,
            failed_mask: 0,
        })
    }
}

impl PendingCheckpointEffect {
    pub const fn effect(&self) -> CheckpointFenceEffect {
        // PROOF: `next` is only advanced while the following entry exists, and
        // `succeeded` returns `Complete` instead of advancing past the end.
        #[allow(clippy::indexing_slicing)]
        self.roster[self.next as usize]
    }

    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// The executor performed this exact effect and it succeeded.
    pub fn succeeded(mut self) -> CheckpointTeardownProgress {
        let effect = self.effect();
        self.attempted_mask |= effect.mask_bit();
        self.next = self.next.saturating_add(1);
        if usize::from(self.next) < self.roster.len() {
            return CheckpointTeardownProgress::Effect(self);
        }
        CheckpointTeardownProgress::Complete(CompletedCheckpointTeardown {
            locator: self.locator,
            report: FenceReport {
                locator: self.locator,
                attempted_mask: self.attempted_mask,
                failed_mask: self.failed_mask,
                authority: PrivateFenceReportAuthority(()),
            },
            authority: PrivateCheckpointCompletionAuthority(()),
        })
    }

    /// The executor performed this exact effect and it refused.
    ///
    /// The pass stops here. Nothing later is attempted, so the report can never
    /// claim an operation a failed predecessor made meaningless.
    pub fn refused(mut self) -> CheckpointTeardownProgress {
        let effect = self.effect();
        self.attempted_mask |= effect.mask_bit();
        self.failed_mask |= effect.mask_bit();
        CheckpointTeardownProgress::Refused(RefusedCheckpointTeardown {
            cursor: FencePassCursor::Roster(effect),
            report: FenceReport {
                locator: self.locator,
                attempted_mask: self.attempted_mask,
                failed_mask: self.failed_mask,
                authority: PrivateFenceReportAuthority(()),
            },
        })
    }
}

impl CompletedCheckpointTeardown {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn report(&self) -> &FenceReport {
        &self.report
    }

    /// Every closed-roster entry was attempted, in order, and none refused.
    pub const fn ran_the_closed_roster(&self) -> bool {
        self.report.is_complete()
    }

    /// Turn a completed pass into a preparation refusal.
    ///
    /// A teardown that ran cleanly but cannot obtain an admissible absence proof
    /// has not failed an *operation*; it has failed the step after them. Giving
    /// it the `FinishPreparation` cursor is what lets a reader tell the two
    /// apart, and consuming the completion is what stops it from also being
    /// used to build a candidate.
    pub fn into_preparation_refusal(self) -> RefusedCheckpointTeardown {
        let Self {
            locator: _,
            report,
            authority: PrivateCheckpointCompletionAuthority(()),
        } = self;
        RefusedCheckpointTeardown::preparation_refusal(report)
    }

    /// Bind the completed pass to its authority-absence proof.
    ///
    /// The absence is requested only after every operation succeeded, which is
    /// why this consumes the completion rather than taking a borrow: there is no
    /// state in which a caller holds a completion and decides later whether to
    /// prove absence.
    pub fn with_absence(
        self,
        absence: ProductionAbsenceWitness,
    ) -> Result<ClosedFenceRosterComplete, Self> {
        if absence.locator() != self.locator {
            return Err(self);
        }
        let Self {
            locator,
            report,
            authority: PrivateCheckpointCompletionAuthority(()),
        } = self;
        Ok(ClosedFenceRosterComplete {
            locator,
            report,
            absence,
        })
    }
}

impl RefusedCheckpointTeardown {
    pub const fn cursor(&self) -> FencePassCursor {
        self.cursor
    }

    pub const fn report(&self) -> &FenceReport {
        &self.report
    }

    pub fn into_parts(self) -> (FencePassCursor, FenceReport) {
        let Self { cursor, report } = self;
        (cursor, report)
    }

    /// The refusal cursor for a preparation that failed after a complete pass.
    pub fn preparation_refusal(report: FenceReport) -> Self {
        Self {
            cursor: FencePassCursor::FinishPreparation,
            report,
        }
    }

    fn executor_binding(locator: SessionLocator) -> Self {
        Self {
            cursor: FencePassCursor::ExecutorBinding,
            report: FenceReport {
                locator,
                attempted_mask: 0,
                failed_mask: 0,
                authority: PrivateFenceReportAuthority(()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Bound mount teardown
// ---------------------------------------------------------------------------

private_authority_seals!(
    PrivateOwnerCompletedMountTeardownAuthority,
    PrivateJoinedCompletedMountTeardownAuthority,
    PrivateAbsentCompletedMountTeardownAuthority,
);

/// This teardown took the mount owner and finished it.
#[derive(Debug)]
pub struct OwnerCompletedMountTeardown {
    completion: OwnerMountCompletion,
    authority: PrivateOwnerCompletedMountTeardownAuthority,
}

/// This teardown joined another one and observed its completion.
#[derive(Debug)]
pub struct JoinedCompletedMountTeardown {
    completion: JoinedMountCompletion,
    authority: PrivateJoinedCompletedMountTeardownAuthority,
}

/// There was nothing mounted; the cell is already Unmounted or Exhausted.
#[derive(Debug)]
pub struct AbsentCompletedMountTeardown {
    completion: MountAbsentProof,
    authority: PrivateAbsentCompletedMountTeardownAuthority,
}

/// Exactly one of the three ways a mount teardown can be finished.
#[derive(Debug)]
pub enum CompletedMountTeardown {
    Owner(OwnerCompletedMountTeardown),
    Joined(JoinedCompletedMountTeardown),
    Absent(AbsentCompletedMountTeardown),
}

impl OwnerCompletedMountTeardown {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.completion.locator()
    }

    pub const fn mount_generation(&self) -> u64 {
        self.completion.mount_generation()
    }

    pub const fn cursor(&self) -> MountAbsenceCursor {
        self.completion.cursor()
    }
}

impl JoinedCompletedMountTeardown {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        match &self.completion {
            JoinedMountCompletion::Join(completion) => completion.locator(),
            JoinedMountCompletion::ResetJoin(completion) => completion.locator(),
        }
    }

    pub const fn mount_generation(&self) -> u64 {
        match &self.completion {
            JoinedMountCompletion::Join(completion) => completion.mount_generation(),
            JoinedMountCompletion::ResetJoin(completion) => completion.mount_generation(),
        }
    }

    pub const fn cursor(&self) -> MountAbsenceCursor {
        match &self.completion {
            JoinedMountCompletion::Join(completion) => completion.cursor(),
            JoinedMountCompletion::ResetJoin(completion) => completion.cursor(),
        }
    }
}

impl AbsentCompletedMountTeardown {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.completion.locator()
    }

    pub const fn cursor(&self) -> MountAbsenceCursor {
        self.completion.cursor()
    }
}

impl CompletedMountTeardown {
    pub fn from_owner(completion: OwnerMountCompletion) -> Self {
        Self::Owner(OwnerCompletedMountTeardown {
            completion,
            authority: PrivateOwnerCompletedMountTeardownAuthority(()),
        })
    }

    pub fn from_joined(completion: JoinedMountCompletion) -> Self {
        Self::Joined(JoinedCompletedMountTeardown {
            completion,
            authority: PrivateJoinedCompletedMountTeardownAuthority(()),
        })
    }

    pub fn from_absent(completion: MountAbsentProof) -> Self {
        Self::Absent(AbsentCompletedMountTeardown {
            completion,
            authority: PrivateAbsentCompletedMountTeardownAuthority(()),
        })
    }

    pub const fn locator(&self) -> SessionLocator {
        match self {
            Self::Owner(owner) => owner.locator(),
            Self::Joined(joined) => joined.locator(),
            Self::Absent(absent) => absent.locator(),
        }
    }

    /// The absence cursor, for the one variant that has one.
    pub const fn cursor(&self) -> Option<MountAbsenceCursor> {
        match self {
            Self::Owner(owner) => Some(owner.cursor()),
            Self::Joined(joined) => Some(joined.cursor()),
            Self::Absent(absent) => Some(absent.cursor()),
        }
    }

    const fn matches(&self, expected: &ExpectedMountTeardown) -> bool {
        let locator = self.locator();
        if !locator_eq(locator, expected.locator()) {
            return false;
        }
        match (self, expected) {
            (
                Self::Owner(owner),
                ExpectedMountTeardown::Owner {
                    mount_generation, ..
                },
            ) => owner.mount_generation() == *mount_generation,
            (
                Self::Joined(joined),
                ExpectedMountTeardown::Join {
                    mount_generation, ..
                },
            ) => joined.mount_generation() == *mount_generation,
            (Self::Absent(absent), ExpectedMountTeardown::Absent { cursor, .. }) => {
                absence_cursor_eq(absent.cursor(), *cursor)
            }
            _ => false,
        }
    }
}

const fn absence_cursor_eq(left: MountAbsenceCursor, right: MountAbsenceCursor) -> bool {
    match (left, right) {
        (MountAbsenceCursor::Next(left), MountAbsenceCursor::Next(right)) => left == right,
        (MountAbsenceCursor::Exhausted, MountAbsenceCursor::Exhausted) => true,
        (MountAbsenceCursor::Next(_), MountAbsenceCursor::Exhausted)
        | (MountAbsenceCursor::Exhausted, MountAbsenceCursor::Next(_)) => false,
    }
}

/// A completion bound to the expectation from the same `take_or_join` call.
///
/// This is the only thing that satisfies the roster's
/// `DismountAndDeleteDevices`. Binding is what stops an Owner completion from
/// being presented for a call that returned a Join expectation — which is the
/// shape that produces a *second* `IoDeleteDevice` on a device the real owner
/// already deleted.
#[derive(Debug)]
pub struct BoundCompletedMountTeardown {
    expected: ExpectedMountTeardown,
    completed: CompletedMountTeardown,
}

/// Sealed final mount absence carried through delete preparation.
///
/// This is minted only by consuming an exact bound completion. It has no
/// constructor from a locator, generation, boolean, or caller-chosen slot
/// disposition, so `Exhausted` cannot be rewritten into reusable `Free`.
#[derive(Debug)]
pub struct PreparedMountDeactivation {
    locator: SessionLocator,
    cursor: MountAbsenceCursor,
    authority: PrivatePreparedMountDeactivationAuthority,
}

/// Sole final-delete authority accepted by the mount rendezvous reset.
pub struct MountRendezvousResetRight {
    mount: PreparedMountDeactivation,
    authority: PrivateMountRendezvousResetAuthority,
}

impl MountRendezvousResetRight {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.mount.locator()
    }

    pub const fn cursor(&self) -> MountAbsenceCursor {
        self.mount.cursor()
    }

    pub(crate) fn into_prepared(self) -> PreparedMountDeactivation {
        let Self {
            mount,
            authority: PrivateMountRendezvousResetAuthority(()),
        } = self;
        mount
    }
}

impl PreparedMountDeactivation {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.locator
    }

    pub const fn cursor(&self) -> MountAbsenceCursor {
        self.cursor
    }

    pub(crate) const fn required_disposition(&self) -> SlotDisposition {
        match self.cursor {
            MountAbsenceCursor::Next(_) => SlotDisposition::Free,
            MountAbsenceCursor::Exhausted => SlotDisposition::Retired,
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_test(locator: SessionLocator) -> Self {
        Self {
            locator,
            cursor: MountAbsenceCursor::Next(1),
            authority: PrivatePreparedMountDeactivationAuthority(()),
        }
    }
}

impl BoundCompletedMountTeardown {
    pub const fn locator(&self) -> SessionLocator {
        self.completed.locator()
    }

    pub const fn cursor(&self) -> Option<MountAbsenceCursor> {
        self.completed.cursor()
    }

    pub const fn expected(&self) -> &ExpectedMountTeardown {
        &self.expected
    }

    pub fn into_prepared_deactivation(self) -> PreparedMountDeactivation {
        PreparedMountDeactivation {
            locator: self.completed.locator(),
            cursor: match self.completed.cursor() {
                Some(cursor) => cursor,
                None => unreachable!("every lifecycle-authenticated completion carries a cursor"),
            },
            authority: PrivatePreparedMountDeactivationAuthority(()),
        }
    }
}

/// A mismatched pair, retained whole.
///
/// It performs no second delete and cannot mint a completion: the point of
/// keeping both halves is that the caller can park them in the fail-stop packet
/// rather than dropping one and retrying the other.
#[derive(Debug)]
pub struct PendingMountBind {
    error: LifecycleError,
    expected: ExpectedMountTeardown,
    completed: CompletedMountTeardown,
}

impl PendingMountBind {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    pub const fn expected(&self) -> &ExpectedMountTeardown {
        &self.expected
    }

    pub const fn completed(&self) -> &CompletedMountTeardown {
        &self.completed
    }
}

/// Bind one completion to the expectation it must answer.
#[allow(clippy::result_large_err)]
pub fn bind_completed_mount_teardown(
    expected: ExpectedMountTeardown,
    completed: CompletedMountTeardown,
) -> Result<BoundCompletedMountTeardown, PendingMountBind> {
    if completed.matches(&expected) {
        Ok(BoundCompletedMountTeardown {
            expected,
            completed,
        })
    } else {
        let error = if locator_eq(completed.locator(), expected.locator()) {
            LifecycleError::WrongState
        } else {
            LifecycleError::WrongLocator
        };
        Err(PendingMountBind {
            error,
            expected,
            completed,
        })
    }
}

const fn locator_eq(left: SessionLocator, right: SessionLocator) -> bool {
    left.slot_index() == right.slot_index()
        && left.generation() == right.generation()
        && identity_eq(left.identity(), right.identity())
}

const fn identity_eq(
    left: fsring_abi::validate::SessionIdentity,
    right: fsring_abi::validate::SessionIdentity,
) -> bool {
    left.mount_id.lo == right.mount_id.lo
        && left.mount_id.hi == right.mount_id.hi
        && left.boot_instance_id.lo == right.boot_instance_id.lo
        && left.boot_instance_id.hi == right.boot_instance_id.hi
        && left.session_epoch == right.session_epoch
}

/// Whether a bound completion satisfies the R3 deletion predicate.
///
/// Owner and Joined completions say the mount is gone; an Absent completion
/// says so only with an exact cursor. All three additionally require the cell's
/// waiter counts and pending-signal bits to be clear, which the native ledger
/// check reports separately — this decides the *completion* half.
pub const fn mount_teardown_permits_delete(bound: &BoundCompletedMountTeardown) -> bool {
    match bound.completed {
        CompletedMountTeardown::Owner(_) | CompletedMountTeardown::Joined(_) => true,
        CompletedMountTeardown::Absent(ref absent) => match absent.cursor() {
            // Both are exact answers. Exhausted is not a refusal: a cell whose
            // mount generation cannot be incremented is retired, and refusing
            // to delete it would strand the generation forever.
            MountAbsenceCursor::Next(_) | MountAbsenceCursor::Exhausted => true,
        },
    }
}

// ---------------------------------------------------------------------------
// The deletion cross-product
// ---------------------------------------------------------------------------

/// Everything the finalizer checks before the first destructive instruction.
///
/// It is one flat observation rather than a series of `if` statements at the
/// call site for a reason: the checks have a canonical *order*, and the step
/// that fails is what a `DeleteTerminalBlocked` carries. A hand-written chain
/// reports whichever condition the author happened to test first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeletePreflightObservation {
    /// The core slot is Deleting at the deposit's slot/identity/generation and
    /// `prepare_finish_delete` accepts its unique right.
    pub core_deleting_with_exact_right: bool,
    /// The native mirror names the same generation and phase.
    pub mirror_matches_generation: bool,
    /// The shell and root owners are the ones inside the readiness.
    pub shell_and_root_owned_by_readiness: bool,
    /// The binding is ClosingLive at this exact locator with a live lease.
    pub closing_live_context_and_lease: bool,
    /// No completed record has been stored yet.
    pub completed_record_absent: bool,
    /// The outcome is still Open, its event nonsignaled, admission open.
    pub outcome_open_and_admission_open: bool,
    /// This callback is the running finalizer and holds every sole authority.
    pub running_with_sole_authorities: bool,
    /// Ordinary joiners admitted so far. It may grow before publication.
    pub admitted_joiners: u32,
}

impl DeletePreflightObservation {
    /// Every field satisfied, with no joiners yet.
    pub const fn satisfied() -> Self {
        Self {
            core_deleting_with_exact_right: true,
            mirror_matches_generation: true,
            shell_and_root_owned_by_readiness: true,
            closing_live_context_and_lease: true,
            completed_record_absent: true,
            outcome_open_and_admission_open: true,
            running_with_sole_authorities: true,
            admitted_joiners: 1,
        }
    }
}

/// The first failing check, in the canonical order, or `Ok` for a clean pass.
///
/// The order is the same `FinalizerPreflightStep` sequence the fail-stop
/// payload names, so the step a refusal reports is the step that actually
/// refused rather than the last one anyone looked at.
pub const fn decide_delete_preflight(
    observation: DeletePreflightObservation,
) -> Result<(), FinalizerPreflightStep> {
    if !observation.core_deleting_with_exact_right {
        return Err(FinalizerPreflightStep::CoreDeleting);
    }
    if !observation.mirror_matches_generation {
        return Err(FinalizerPreflightStep::MirrorAndShell);
    }
    if !observation.shell_and_root_owned_by_readiness {
        return Err(FinalizerPreflightStep::ShellAndRootOwnership);
    }
    if !observation.closing_live_context_and_lease {
        return Err(FinalizerPreflightStep::ClosingContextAndLease);
    }
    if !observation.completed_record_absent {
        return Err(FinalizerPreflightStep::EmptyCompletedRecord);
    }
    if !observation.outcome_open_and_admission_open
        || observation.admitted_joiners == 0
        || observation.admitted_joiners == u32::MAX
    {
        return Err(FinalizerPreflightStep::OpenOutcomeAndJoinAdmission);
    }
    if !observation.running_with_sole_authorities {
        return Err(FinalizerPreflightStep::RunningDepositAndPublisher);
    }
    Ok(())
}

/// The canonical order the checks run in, for tests that must cover each one.
pub const DELETE_PREFLIGHT_ORDER: [FinalizerPreflightStep; 7] = [
    FinalizerPreflightStep::CoreDeleting,
    FinalizerPreflightStep::MirrorAndShell,
    FinalizerPreflightStep::ShellAndRootOwnership,
    FinalizerPreflightStep::ClosingContextAndLease,
    FinalizerPreflightStep::EmptyCompletedRecord,
    FinalizerPreflightStep::OpenOutcomeAndJoinAdmission,
    FinalizerPreflightStep::RunningDepositAndPublisher,
];

/// Physical publication predicates cannot safely reuse ordinary Blocked
/// visibility. Every other refusal may publish only if the independently
/// re-observed publication substrate is still exact.
pub const fn delete_failure_requires_opaque(step: FinalizerPreflightStep) -> bool {
    matches!(
        step,
        FinalizerPreflightStep::ClosingContextAndLease
            | FinalizerPreflightStep::EmptyCompletedRecord
            | FinalizerPreflightStep::OpenOutcomeAndJoinAdmission
    )
}

/// Whether the state may still be considered prepared after re-observation.
///
/// Between the preflight and the publication the registry lock is dropped, and
/// exactly one thing is allowed to change: another ordinary arrival may join,
/// so `admitted_joiners` may grow. Anything else changing means the state the
/// preparation was computed over is gone, and destruction must not proceed on
/// it. Growth-only is the whole rule — a count that *shrank* means somebody
/// released against a generation this finalizer believes nobody has left.
pub const fn delete_preparation_survives(
    before: DeletePreflightObservation,
    after: DeletePreflightObservation,
) -> bool {
    if after.admitted_joiners < before.admitted_joiners {
        return false;
    }
    let normalized = DeletePreflightObservation {
        admitted_joiners: before.admitted_joiners,
        ..after
    };
    observations_equal(before, normalized)
}

const fn observations_equal(
    left: DeletePreflightObservation,
    right: DeletePreflightObservation,
) -> bool {
    left.core_deleting_with_exact_right == right.core_deleting_with_exact_right
        && left.mirror_matches_generation == right.mirror_matches_generation
        && left.shell_and_root_owned_by_readiness == right.shell_and_root_owned_by_readiness
        && left.closing_live_context_and_lease == right.closing_live_context_and_lease
        && left.completed_record_absent == right.completed_record_absent
        && left.outcome_open_and_admission_open == right.outcome_open_and_admission_open
        && left.running_with_sole_authorities == right.running_with_sole_authorities
        && left.admitted_joiners == right.admitted_joiners
}

// ---------------------------------------------------------------------------
// The infallible destructive suffix
// ---------------------------------------------------------------------------

/// One step of the deletion sequence that runs after the last preflight.
///
/// The order is the content. The sealed native-storage step destroys the shell
/// and releases the root before the non-native completion record is moved;
/// signalling before that record and outcome are published would wake arrivals
/// that then read `Open`; resetting the cell before the joiners drained would
/// reuse a generation somebody is still waiting on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalDeleteStep {
    DestroyAndFreeShell,
    ReleaseRootReference,
    TransferClosingOwnerToCompletedRecord,
    PublishClosingCompleteAndOutcome,
    SignalTerminalOutcome,
    DrainCountedArrivals,
    WaitJoinersDrained,
    CompleteAccessRundown,
    ReinitializeAccessRundownIfReusable,
    ResetCellAndPublishDisposition,
}

#[derive(Clone, Copy, Debug, Default)]
struct FinalDeleteRecord {
    freed: Option<u8>,
    transferred: Option<u8>,
    published: Option<u8>,
    signalled: Option<u8>,
    arrivals_drained: Option<u8>,
    drained: Option<u8>,
    rundown_completed: Option<u8>,
    reset: Option<u8>,
    steps: u8,
}

/// One step the native executor must now perform.
///
/// It has exactly one continuation — [`Self::performed`]. There is deliberately
/// no `refused`: this whole sequence runs after the last fallible check, and a
/// refusal edge here is precisely the "half-destroyed generation" state the
/// prepared-delete cross-product exists to make unreachable.
struct FinalDeleteResetBundle<NativeReset> {
    commit: PreparedDeleteCoreCommit,
    running: R3FinalizerRunningPermit,
    mount: PreparedMountDeactivation,
    native_reset: NativeReset,
}

pub struct FinalDeleteCursor<const NEXT: u8, NativeReset = ()> {
    locator: SessionLocator,
    record: FinalDeleteRecord,
    bundle: FinalDeleteResetBundle<NativeReset>,
    authority: PrivateFinalDeleteCursorAuthority,
}

pub type PendingCompletedPublication<NativeReset = ()> = FinalDeleteCursor<2, NativeReset>;
pub type PendingOutcomeSignal<NativeReset = ()> = FinalDeleteCursor<4, NativeReset>;
pub type PendingCountedArrivalDrain<NativeReset = ()> = FinalDeleteCursor<5, NativeReset>;
pub type PendingJoinerDrain<NativeReset = ()> = FinalDeleteCursor<6, NativeReset>;
pub type PendingAccessRundown<NativeReset = ()> = FinalDeleteCursor<7, NativeReset>;
pub type PendingRundownDisposition<NativeReset = ()> = FinalDeleteCursor<8, NativeReset>;
pub type PendingFinalDeleteReset<NativeReset = ()> = FinalDeleteCursor<9, NativeReset>;

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct PendingFinalDeleteStep {
    roster: [FinalDeleteStep; 10],
    next: u8,
    locator: SessionLocator,
    record: FinalDeleteRecord,
}

#[derive(Debug)]
pub struct FinalDeleteProof {
    locator: SessionLocator,
    record: FinalDeleteRecord,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum FinalDeleteProgress {
    Step(PendingFinalDeleteStep),
    Complete(FinalDeleteProof),
}

pub struct FinalDeletePlan;

impl FinalDeletePlan {
    pub const STEPS: [FinalDeleteStep; 10] = [
        FinalDeleteStep::DestroyAndFreeShell,
        FinalDeleteStep::ReleaseRootReference,
        FinalDeleteStep::TransferClosingOwnerToCompletedRecord,
        FinalDeleteStep::PublishClosingCompleteAndOutcome,
        FinalDeleteStep::SignalTerminalOutcome,
        FinalDeleteStep::DrainCountedArrivals,
        FinalDeleteStep::WaitJoinersDrained,
        FinalDeleteStep::CompleteAccessRundown,
        FinalDeleteStep::ReinitializeAccessRundownIfReusable,
        FinalDeleteStep::ResetCellAndPublishDisposition,
    ];

    pub const fn first_step() -> FinalDeleteStep {
        FinalDeleteStep::DestroyAndFreeShell
    }

    /// Begin from an explicit roster, so the proofs below can be observed
    /// reporting `false` on the orders they forbid.
    #[cfg(test)]
    pub(crate) const fn begin_with_roster(
        locator: SessionLocator,
        roster: [FinalDeleteStep; 10],
    ) -> FinalDeleteProgress {
        Self::begin_inner(locator, roster)
    }

    #[cfg(test)]
    const fn begin_inner(
        locator: SessionLocator,
        roster: [FinalDeleteStep; 10],
    ) -> FinalDeleteProgress {
        FinalDeleteProgress::Step(PendingFinalDeleteStep {
            roster,
            next: 0,
            locator,
            record: FinalDeleteRecord {
                freed: None,
                transferred: None,
                published: None,
                signalled: None,
                arrivals_drained: None,
                drained: None,
                rundown_completed: None,
                reset: None,
                steps: 0,
            },
        })
    }
}

impl<const NEXT: u8, NativeReset> FinalDeleteCursor<NEXT, NativeReset> {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

impl<NativeReset> FinalDeleteCursor<2, NativeReset> {
    #[cfg(test)]
    pub(crate) fn for_test(
        commit: PreparedDeleteCoreCommit,
        running: R3FinalizerRunningRight,
        native_reset: NativeReset,
    ) -> Self {
        let locator = commit.locator();
        assert_eq!(running.locator(), locator);
        let R3FinalizerRunningRight {
            locator: _,
            authority: PrivateR3FinalizerRunningAuthority(()),
        } = running;
        Self {
            locator,
            record: FinalDeleteRecord {
                freed: Some(0),
                transferred: None,
                published: None,
                signalled: None,
                arrivals_drained: None,
                drained: None,
                rundown_completed: None,
                reset: None,
                steps: 2,
            },
            bundle: FinalDeleteResetBundle {
                mount: PreparedMountDeactivation::for_test(locator),
                commit,
                running: R3FinalizerRunningPermit {
                    authority: PrivateR3FinalizerRunningPermitAuthority(()),
                },
                native_reset,
            },
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn into_final_reset_for_test(self) -> PendingFinalDeleteReset<NativeReset> {
        let cursor = self
            .completed_publication_completed()
            .outcome_signalled()
            .counted_arrivals_drained()
            .joiners_drained()
            .access_rundown_completed();
        match cursor.disposition() {
            SlotDisposition::Free => cursor.reinitialized_for_reuse(),
            SlotDisposition::Retired => cursor.retired_without_reinitialize(),
        }
    }

    fn completed_publication_completed(self) -> PendingOutcomeSignal<NativeReset> {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        record.transferred = Some(2);
        record.published = Some(3);
        record.steps = 4;
        FinalDeleteCursor {
            locator,
            record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }
}

impl<NativeReset> FinalDeleteCursor<4, NativeReset> {
    fn outcome_signalled(self) -> PendingCountedArrivalDrain<NativeReset> {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        record.signalled = Some(4);
        record.steps = 5;
        FinalDeleteCursor {
            locator,
            record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }
}

impl<NativeReset> FinalDeleteCursor<5, NativeReset> {
    /// Record the handoff from outcome publication to the already-counted
    /// arrival population. This is a consuming production transition, not an
    /// enum-only marker: the later blocking wait cannot be reached without it.
    fn counted_arrivals_drained(self) -> PendingJoinerDrain<NativeReset> {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        record.arrivals_drained = Some(5);
        record.steps = 6;
        FinalDeleteCursor {
            locator,
            record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }
}

impl<NativeReset> FinalDeleteCursor<6, NativeReset> {
    fn joiners_drained(self) -> PendingAccessRundown<NativeReset> {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        record.drained = Some(6);
        record.steps = 7;
        FinalDeleteCursor {
            locator,
            record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }
}

impl<NativeReset> FinalDeleteCursor<7, NativeReset> {
    fn access_rundown_completed(self) -> PendingRundownDisposition<NativeReset> {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        record.rundown_completed = Some(7);
        record.steps = 8;
        FinalDeleteCursor {
            locator,
            record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }
}

impl<NativeReset> FinalDeleteCursor<8, NativeReset> {
    const fn disposition(&self) -> SlotDisposition {
        self.bundle.commit.disposition()
    }

    fn disposition_recorded(self) -> PendingFinalDeleteReset<NativeReset> {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        record.steps = 9;
        FinalDeleteCursor {
            locator,
            record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        }
    }

    fn reinitialized_for_reuse(self) -> PendingFinalDeleteReset<NativeReset> {
        self.disposition_recorded()
    }

    fn retired_without_reinitialize(self) -> PendingFinalDeleteReset<NativeReset> {
        self.disposition_recorded()
    }
}

impl<NativeReset> FinalDeleteCursor<9, NativeReset> {
    fn finish_after_reset(
        self,
    ) -> (
        PreparedDeleteCoreCommit,
        R3FinalizerRunningPermit,
        NativeReset,
        FinalDeleteProof,
        TerminalRendezvousResetRight,
        MountRendezvousResetRight,
    ) {
        let Self {
            locator,
            mut record,
            bundle,
            authority: PrivateFinalDeleteCursorAuthority(()),
        } = self;
        let FinalDeleteResetBundle {
            commit,
            running,
            mount,
            native_reset,
        } = bundle;
        record.reset = Some(9);
        record.steps = 10;
        (
            commit,
            running,
            native_reset,
            FinalDeleteProof { locator, record },
            TerminalRendezvousResetRight {
                locator,
                authority: PrivateTerminalRendezvousResetAuthority(()),
            },
            MountRendezvousResetRight {
                mount,
                authority: PrivateMountRendezvousResetAuthority(()),
            },
        )
    }
}

#[cfg(test)]
impl PendingFinalDeleteStep {
    pub const fn step(&self) -> FinalDeleteStep {
        // PROOF: `next` only advances while the following entry exists.
        #[allow(clippy::indexing_slicing)]
        self.roster[self.next as usize]
    }

    pub fn performed(mut self) -> FinalDeleteProgress {
        let at = self.next;
        match self.step() {
            FinalDeleteStep::DestroyAndFreeShell => self.record.freed = Some(at),
            FinalDeleteStep::TransferClosingOwnerToCompletedRecord => {
                self.record.transferred = Some(at);
            }
            FinalDeleteStep::PublishClosingCompleteAndOutcome => self.record.published = Some(at),
            FinalDeleteStep::SignalTerminalOutcome => self.record.signalled = Some(at),
            FinalDeleteStep::DrainCountedArrivals => self.record.arrivals_drained = Some(at),
            FinalDeleteStep::WaitJoinersDrained => self.record.drained = Some(at),
            FinalDeleteStep::CompleteAccessRundown => self.record.rundown_completed = Some(at),
            FinalDeleteStep::ResetCellAndPublishDisposition => self.record.reset = Some(at),
            FinalDeleteStep::ReleaseRootReference
            | FinalDeleteStep::ReinitializeAccessRundownIfReusable => {}
        }
        self.record.steps = self.record.steps.saturating_add(1);
        self.next = self.next.saturating_add(1);
        if usize::from(self.next) < self.roster.len() {
            return FinalDeleteProgress::Step(self);
        }
        FinalDeleteProgress::Complete(FinalDeleteProof {
            locator: self.locator,
            record: self.record,
        })
    }
}

impl FinalDeleteProof {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Every step ran exactly once.
    pub const fn ran_every_step(&self) -> bool {
        self.record.steps == 10
    }

    /// The completed record was transferred before its binding was published.
    pub const fn transferred_record_before_publishing(&self) -> bool {
        match (self.record.transferred, self.record.published) {
            (Some(transferred), Some(published)) => transferred < published,
            _ => false,
        }
    }

    /// The outcome was stored under the lock before the event was signalled.
    pub const fn published_before_signalling(&self) -> bool {
        match (self.record.published, self.record.signalled) {
            (Some(published), Some(signalled)) => published < signalled,
            _ => false,
        }
    }

    /// The counted population is handed off before the blocking drained wait.
    pub const fn counted_arrivals_drained_before_wait(&self) -> bool {
        match (self.record.arrivals_drained, self.record.drained) {
            (Some(arrivals), Some(waited)) => arrivals < waited,
            _ => false,
        }
    }

    /// Nothing reinitialized the access rundown before the joiners drained.
    pub const fn drained_before_completing_rundown(&self) -> bool {
        match (self.record.drained, self.record.rundown_completed) {
            (Some(drained), Some(completed)) => drained < completed,
            _ => false,
        }
    }

    /// The cell reset is last: before it, process/unload sees the intact
    /// Deleting generation; after it, only the complete Free/Retired successor.
    pub const fn reset_is_last(&self) -> bool {
        match self.record.reset {
            Some(at) => at == 9,
            None => false,
        }
    }

    /// The shell was freed before the cell was reset, so no reset publishes a
    /// Free slot whose allocation is still live.
    pub const fn freed_before_reset(&self) -> bool {
        match (self.record.freed, self.record.reset) {
            (Some(freed), Some(reset)) => freed < reset,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// The roster walk itself
// ---------------------------------------------------------------------------

/// The closed, named native operation surface for the R3 checkpoint roster.
///
/// The runner below owns the exhaustive effect mapping. Recording fakes and
/// the native FSD therefore implement the same sixteen calls instead of an
/// executor-controlled catch-all that could silently group or omit one.
/// # Safety
/// Each of the sixteen effects below is driven only by `run_checkpoint_roster`
/// after it has matched `checkpoint_locator`, at most once per pass, and in
/// roster order. An implementation may not perform another generation's
/// effect, repeat one, or run one after a refusal stopped the walk.
// The obligation is identical for all sixteen and is stated once above,
// because it is a property of the roster walk rather than of any one effect.
#[allow(clippy::missing_safety_doc)]
pub trait R3CheckpointNativeOps {
    /// The exact generation whose affine owners this executor retains.
    ///
    /// The runner compares it with its requested locator before the first
    /// operation. A mismatch therefore cannot close admission or consume any
    /// owner from a different generation.
    fn checkpoint_locator(&self) -> SessionLocator;

    unsafe fn close_session_admission(&mut self) -> bool;
    unsafe fn signal_pending_enter(&mut self) -> bool;
    unsafe fn wait_control_rundown(&mut self) -> bool;
    unsafe fn wait_session_access_rundown(&mut self) -> bool;
    unsafe fn wait_existing_sq_cq_roles_and_consumers(&mut self) -> bool;
    unsafe fn remove_producer_mappings_reverse(&mut self) -> bool;
    unsafe fn wait_producer_and_mapping_capture_rundown(&mut self) -> bool;
    unsafe fn retire_existing_grant_and_credit_state(&mut self) -> bool;
    unsafe fn acquire_consumers_increasing(&mut self) -> bool;
    unsafe fn release_consumers(&mut self) -> bool;
    unsafe fn queue_installed_work(&mut self) -> bool;
    unsafe fn wait_pending_and_owners(&mut self) -> bool;
    unsafe fn release_read_only_mappings_reverse(&mut self) -> bool;
    unsafe fn release_mdls_and_system_view(&mut self) -> bool;
    unsafe fn release_captured_process(&mut self) -> bool;
    unsafe fn dismount_and_delete_devices(&mut self) -> bool;
    unsafe fn release_transient_arrays_and_backing(&mut self) -> bool;
    unsafe fn release_control_strong_ref(&mut self) -> bool;
    unsafe fn release_remaining_stable_session_owners(&mut self) -> bool;
    unsafe fn verify_session_and_root_ledgers(&mut self) -> bool;
}

/// What one whole roster pass decided.
#[cfg_attr(test, derive(Debug))]
pub enum CheckpointRosterOutcome {
    /// Every effect succeeded.
    Complete(CompletedCheckpointTeardown),
    /// One effect refused; the pass stopped there.
    Refused(RefusedCheckpointTeardown),
}

/// Walk the closed R3 roster, stopping at the first refusal.
///
/// This is the whole of "the order is the content", and it needs nothing but a
/// locator and something that can perform one effect. Living here rather than in
/// `fsring-fsd` is what lets a host test drive every refusal position with a
/// recording executor — the roster walk was previously reachable only through a
/// function whose signature named four fsd-native affine types, so no test
/// could call it at all.
///
/// # Safety
/// Forwarded to the executor: the caller holds no registry lock and runs at
/// PASSIVE_LEVEL.
pub unsafe fn run_checkpoint_roster<E: R3CheckpointNativeOps + ?Sized>(
    locator: SessionLocator,
    executor: &mut E,
) -> CheckpointRosterOutcome {
    if executor.checkpoint_locator() != locator {
        return CheckpointRosterOutcome::Refused(RefusedCheckpointTeardown::executor_binding(
            locator,
        ));
    }
    let mut progress = CheckpointTeardownPlan::begin(locator);
    loop {
        progress = match progress {
            CheckpointTeardownProgress::Effect(pending) => {
                let effect = pending.effect();
                // SAFETY: the caller's contract, forwarded unchanged.
                let succeeded = match effect {
                    CheckpointFenceEffect::CloseSessionAdmission => unsafe {
                        executor.close_session_admission()
                    },
                    CheckpointFenceEffect::SignalPendingEnter => unsafe {
                        executor.signal_pending_enter()
                    },
                    CheckpointFenceEffect::WaitControlRundown => unsafe {
                        executor.wait_control_rundown()
                    },
                    CheckpointFenceEffect::WaitSessionAccessRundown => unsafe {
                        executor.wait_session_access_rundown()
                    },
                    CheckpointFenceEffect::WaitExistingSqCqRolesAndConsumers => unsafe {
                        executor.wait_existing_sq_cq_roles_and_consumers()
                    },
                    CheckpointFenceEffect::RemoveProducerMappingsReverse => unsafe {
                        executor.remove_producer_mappings_reverse()
                    },
                    CheckpointFenceEffect::WaitProducerAndMappingCaptureRundown => unsafe {
                        executor.wait_producer_and_mapping_capture_rundown()
                    },
                    CheckpointFenceEffect::RetireExistingGrantAndCreditState => unsafe {
                        executor.retire_existing_grant_and_credit_state()
                    },
                    CheckpointFenceEffect::AcquireConsumersIncreasing => unsafe {
                        executor.acquire_consumers_increasing()
                    },
                    CheckpointFenceEffect::ReleaseConsumers => unsafe {
                        executor.release_consumers()
                    },
                    CheckpointFenceEffect::QueueInstalledWork => unsafe {
                        executor.queue_installed_work()
                    },
                    CheckpointFenceEffect::WaitPendingAndOwners => unsafe {
                        executor.wait_pending_and_owners()
                    },
                    CheckpointFenceEffect::ReleaseReadOnlyMappingsReverse => unsafe {
                        executor.release_read_only_mappings_reverse()
                    },
                    CheckpointFenceEffect::ReleaseMdlsAndSystemView => unsafe {
                        executor.release_mdls_and_system_view()
                    },
                    CheckpointFenceEffect::ReleaseCapturedProcess => unsafe {
                        executor.release_captured_process()
                    },
                    CheckpointFenceEffect::DismountAndDeleteDevices => unsafe {
                        executor.dismount_and_delete_devices()
                    },
                    CheckpointFenceEffect::ReleaseTransientArraysAndBacking => unsafe {
                        executor.release_transient_arrays_and_backing()
                    },
                    CheckpointFenceEffect::ReleaseControlStrongRef => unsafe {
                        executor.release_control_strong_ref()
                    },
                    CheckpointFenceEffect::ReleaseRemainingStableSessionOwners => unsafe {
                        executor.release_remaining_stable_session_owners()
                    },
                    CheckpointFenceEffect::VerifySessionAndRootLedgers => unsafe {
                        executor.verify_session_and_root_ledgers()
                    },
                };
                if succeeded {
                    pending.succeeded()
                } else {
                    pending.refused()
                }
            }
            CheckpointTeardownProgress::Complete(complete) => {
                return CheckpointRosterOutcome::Complete(complete);
            }
            CheckpointTeardownProgress::Refused(refused) => {
                return CheckpointRosterOutcome::Refused(refused);
            }
        };
    }
}

// ---------------------------------------------------------------------------
// R5 staging: the sixteen operations the final fence advertises
// ---------------------------------------------------------------------------

/// The sixteen native operations the final six-stage `SessionFence` advertises.
///
/// **This is not a second copy of [`R3CheckpointNativeOps`],** and the two
/// differences are the whole reason it exists.
///
/// * **A refusal keeps its cause.** `R3CheckpointNativeOps` answers `bool`, so
///   every native failure arrives as one indistinguishable `false` and only the
///   effect's name survives into the report. Here the associated `Error`
///   travels out of the exact method that produced it, which is the input
///   Task 24's residual algebra and Task 25's retry point need in order to
///   decide anything at all.
/// * **It is stated over the normative sixteen.** [`CheckpointFenceEffect`] is
///   the twenty-row roster the Task 12 binary can honestly discharge;
///   [`FenceEffect`] is what the ABI's six approved stages advertise, and it
///   contains `DrainStablePrefixesBounded` and `RetireCredits` — operations the
///   checkpoint roster carries only as their pre-R5 predecessors
///   (`WaitExistingSqCqRolesAndConsumers`, `RetireExistingGrantAndCreditState`).
///
/// There is deliberately no default body anywhere in this trait. A default
/// returning `Ok(())` is exactly the "advertised effect represented as
/// unconditional success" the C4 constraints forbid, and a trait with sixteen
/// required methods makes that unrepresentable rather than merely discouraged.
///
/// Task 25 owns the only implementation that can reach a kernel
/// (`KernelFenceOps` over a `FenceKernelDdi`). Until then nothing
/// production-reachable names this trait, and
/// `task20_24_r5_staging_is_production_unreachable` is what proves it.
pub trait FenceNativeOps {
    /// What a refused operation reports.
    ///
    /// Associated rather than fixed: the recording implementation Task 25 uses
    /// for host proofs and the native one that calls the WDK do not report the
    /// same thing, and collapsing them to a shared error type would mean one of
    /// the two carries values it can never produce.
    type Error;

    fn close_session_admission(&mut self) -> Result<(), Self::Error>;
    fn signal_pending_enter(&mut self) -> Result<(), Self::Error>;
    fn remove_producer_mappings_reverse(&mut self) -> Result<(), Self::Error>;
    fn wait_producer_and_mapping_capture_rundown(&mut self) -> Result<(), Self::Error>;
    fn acquire_consumers_increasing(&mut self) -> Result<(), Self::Error>;
    fn drain_stable_prefixes_bounded(&mut self) -> Result<(), Self::Error>;
    fn retire_credits(&mut self) -> Result<(), Self::Error>;
    fn release_consumers(&mut self) -> Result<(), Self::Error>;
    fn queue_installed_work(&mut self) -> Result<(), Self::Error>;
    fn wait_pending_and_owners(&mut self) -> Result<(), Self::Error>;
    fn wait_control_rundown(&mut self) -> Result<(), Self::Error>;
    fn release_read_only_mappings_reverse(&mut self) -> Result<(), Self::Error>;
    fn release_mdls_and_system_view(&mut self) -> Result<(), Self::Error>;
    fn release_captured_process(&mut self) -> Result<(), Self::Error>;
    fn dismount_and_delete_devices(&mut self) -> Result<(), Self::Error>;
    fn release_transient_backing(&mut self) -> Result<(), Self::Error>;
}

/// Perform one advertised effect through the one method that performs it.
///
/// The match is exhaustive over [`FenceEffect`] with **no wildcard arm and no
/// ordinal indirection**: adding a seventeenth effect is a compile error here
/// rather than a silent fall-through to a default success, and no arm can be
/// answered by dispatching on a number that happens to line up.
///
/// The result is propagated unchanged. This function neither retries, nor
/// classifies, nor records: a caller that needs to know *which* effect refused
/// already knows, because it chose the effect.
pub fn execute_effect<O: FenceNativeOps + ?Sized>(
    ops: &mut O,
    effect: crate::session::FenceEffect,
) -> Result<(), O::Error> {
    use crate::session::FenceEffect;

    match effect {
        FenceEffect::CloseSessionAdmission => ops.close_session_admission(),
        FenceEffect::SignalPendingEnter => ops.signal_pending_enter(),
        FenceEffect::RemoveProducerMappingsReverse => ops.remove_producer_mappings_reverse(),
        FenceEffect::WaitProducerAndMappingCaptureRundown => {
            ops.wait_producer_and_mapping_capture_rundown()
        }
        FenceEffect::AcquireConsumersIncreasing => ops.acquire_consumers_increasing(),
        FenceEffect::DrainStablePrefixesBounded => ops.drain_stable_prefixes_bounded(),
        FenceEffect::RetireCredits => ops.retire_credits(),
        FenceEffect::ReleaseConsumers => ops.release_consumers(),
        FenceEffect::QueueInstalledWork => ops.queue_installed_work(),
        FenceEffect::WaitPendingAndOwners => ops.wait_pending_and_owners(),
        FenceEffect::WaitControlRundown => ops.wait_control_rundown(),
        FenceEffect::ReleaseReadOnlyMappingsReverse => ops.release_read_only_mappings_reverse(),
        FenceEffect::ReleaseMdlsAndSystemView => ops.release_mdls_and_system_view(),
        FenceEffect::ReleaseCapturedProcess => ops.release_captured_process(),
        FenceEffect::DismountAndDeleteDevices => ops.dismount_and_delete_devices(),
        FenceEffect::ReleaseTransientBacking => ops.release_transient_backing(),
    }
}

// ---------------------------------------------------------------------------
// R5 staging: consumer recovery — the prefix, its four proofs, and the DDI
// ---------------------------------------------------------------------------

/// Why a fence operation refused for a reason of its own, rather than because a
/// kernel call failed.
///
/// Every variant here is a *typed invariant*: the caller asked for something the
/// cursor's own state forbids. Task 25's runner treats these differently from a
/// native refusal — they set no diagnostic bit and never schedule an automatic
/// retry, because retrying an invariant violation just violates it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceError {
    RingCountOutOfRange,
    WrongRingSet,
    WrongRing,
    NonIncreasingRing,
    DuplicateConsumer,
    InvalidConsumerPhase,
    IncompleteConsumerSet,
    ConsumerTokensRemain,
    ReleaseProofMissing,
    PrerequisiteOutstanding,
    RetryBrandMismatch,
}

/// A refusal from an operation that can fail either way.
///
/// The split is the whole point: `Native` means a DDI was actually invoked and
/// said no, `Core` means it never was. Collapsing them would make "which
/// operations did this driver really attempt" unanswerable, which is exactly the
/// question the sixteen-effect obligation exists to answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelFenceError<E> {
    Core(FenceError),
    Native(E),
}

/// How the pending-owner wait refused.
///
/// A publication fail-stop is **not** a native failure: the wait ran and found a
/// context that can never drain. It carries the sealed witness rather than a
/// boolean so the residual can say which install blocked it.
#[derive(Debug)]
pub enum PendingOwnerWaitFailure<E> {
    Native(E),
    PublicationFailStop(crate::enter::PublicationFailStopWitness),
}

/// How the mount/device delete refused.
#[derive(Debug)]
pub enum MountTeardownCallError<E> {
    Native(E),
    Bind(PendingMountBind),
}

/// Where one consumer prefix is in the acquire/release cycle.
///
/// Six states, not a pair of booleans: "released three of five and stopped" and
/// "released all five" authorize different next steps, and a bool pair makes the
/// illegal fourth combination representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerPrefixPhase {
    /// Taking roles in increasing ring order; `high_water` says how many.
    Acquiring,
    /// Every ring of the set is held.
    AcquiredComplete,
    /// Giving roles back in decreasing order, and some remain.
    ReleasingPartial,
    /// Giving roles back, and the last one is about to go.
    ReleasingComplete,
    /// Stopped mid-release; `release_remaining` still counts live tokens.
    ReleasedPartial,
    /// Every role is back. This is the only phase a release proof can mint from.
    ReleasedComplete,
}

private_authority_seals!(
    PrivateConsumerTokenSlabAuthority,
    PrivateConsumerReleaseAuthority,
    PrivateDrainCompletedAuthority,
    PrivateRetireCompletedAuthority,
    PrivatePreparedConsumerDrainAuthority,
    PrivatePreparedRetireCallAuthority,
);

/// Indirect, affine ownership of one session's consumer-token storage.
///
/// **Indirect on purpose.** `CqConsumerToken` is affine and a session may have
/// 64 rings; an inline `[Option<CqConsumerToken>; 64]` inside `ConsumerPrefix`
/// would put the whole array on every stack frame that moves a prefix by value,
/// and the fence path already runs on an expanded kernel stack. The storage is
/// native; this owns it, and `consumer_authority_slab_is_indirect_and_affine`
/// asserts both the size budget and that no such array occurs by value.
pub struct ConsumerTokenSlabOwner {
    base: core::ptr::NonNull<core::mem::MaybeUninit<Option<CqConsumerToken>>>,
    capacity: u32,
    /// The cell and generation this storage belongs to.
    ///
    /// **Two words, not a whole `SessionLocator`.** A locator is 56 bytes here,
    /// which alone puts this type over the 64-byte budget
    /// `consumer_authority_slab_is_indirect_and_affine` asserts -- and the
    /// budget is the point, because a slab owner that had to be large would
    /// push the indirection back into the caller's frame. A cell's generation
    /// counter is nonwrapping and never reused, so `(slot, generation)`
    /// identifies the session as exactly as the locator does for the one thing
    /// this pairing check needs to decide.
    slot_index: u32,
    generation: u64,
    // Read by nobody, by design. A seal's whole job is that it cannot be named
    // outside this module, so the type cannot be constructed outside it either;
    // reading it would prove nothing that its presence does not.
    #[allow(dead_code)]
    authority: PrivateConsumerTokenSlabAuthority,
}

#[allow(dead_code)]
impl ConsumerTokenSlabOwner {
    /// Take ownership of one native slab.
    ///
    /// # Safety
    /// `base` is one uniquely owned, nonpaged slab of at least `capacity`
    /// entries reserved in the matching native session, suitably aligned, with
    /// every entry already written as `None`, and no other owner or borrow
    /// exists. The single audited fsd setup call must never invoke this twice
    /// for the same storage.
    pub unsafe fn bind_native_storage(
        set: SessionRingSetBrand,
        base: core::ptr::NonNull<core::mem::MaybeUninit<Option<CqConsumerToken>>>,
        capacity: u32,
    ) -> Result<Self, FenceError> {
        if capacity == 0 || capacity > MAX_SESSION_RING_COUNT || capacity < set.ring_count() {
            return Err(FenceError::RingCountOutOfRange);
        }
        Ok(Self {
            base,
            capacity,
            slot_index: set.locator().slot_index(),
            generation: set.locator().generation(),
            authority: PrivateConsumerTokenSlabAuthority(()),
        })
    }

    const fn slab_capacity(&self) -> u32 {
        self.capacity
    }

    /// Store a token at `index`.
    ///
    /// # Safety
    /// `index < capacity`, the slab is live, and the entry currently holds
    /// `None` — which the prefix's phase and `high_water` establish.
    unsafe fn write_slot(&mut self, index: u32, token: CqConsumerToken) {
        // SAFETY: the caller's contract bounds `index` and keeps the slab live.
        unsafe {
            self.base
                .as_ptr()
                .add(index as usize)
                .write(core::mem::MaybeUninit::new(Some(token)));
        }
    }

    /// Take the token at `index`, leaving `None`.
    ///
    /// # Safety
    /// `index < capacity`, the slab is live, and the entry was written by
    /// `write_slot` and not taken since.
    unsafe fn take_slot(&mut self, index: u32) -> Option<CqConsumerToken> {
        // SAFETY: the caller's contract bounds `index` and keeps the slab live.
        unsafe {
            let slot = self.base.as_ptr().add(index as usize);
            let taken = slot.read().assume_init();
            slot.write(core::mem::MaybeUninit::new(None));
            taken
        }
    }
}

/// The consumer roles this fence pass holds, and how far through it is.
///
/// One cursor owns every live token. There is deliberately no way to hold a
/// prefix *and* a loose token beside it: an "optional prefix plus an optional
/// spare" would make the illegal combination — a spare token with no cursor to
/// release it — representable, and that token would be leaked for the life of
/// the session.
///
/// Acquisition is strictly increasing by ring index and release is its exact
/// reverse. Increasing order is not tidiness: two fences taking the same set in
/// opposite orders is the deadlock this cursor exists to make impossible.
pub struct ConsumerPrefix {
    set: SessionRingSetBrand,
    slab: ConsumerTokenSlabOwner,
    /// How many rings, counting from zero, have ever been acquired this pass.
    high_water: u32,
    /// How many acquired tokens are still live during a release.
    release_remaining: u32,
    /// The ring whose token is out of the slab and in the caller's hands.
    ///
    /// A token between `pop_for_release` and the native call that gives it back
    /// is owned by neither the slab nor its ring, and only the caller knows
    /// which. `release_remaining` cannot express that: it counts what is in the
    /// slab, so it reads 0 both for "every role is home" and for "the last one
    /// is in flight". Keeping the in-flight ring here is what makes
    /// `finish_release` unable to mint a proof over a token nobody confirmed.
    in_flight: Option<u32>,
    /// The ring whose native call refused, retained so a retry resumes there.
    failed_ring: Option<u32>,
    phase: ConsumerPrefixPhase,
}

#[allow(dead_code)]
impl ConsumerPrefix {
    /// Begin an empty prefix over one completed ring set.
    pub fn begin_consumer_prefix(
        set: SessionRingSetBrand,
        slab: ConsumerTokenSlabOwner,
    ) -> Result<Self, FenceError> {
        if slab.slot_index != set.locator().slot_index()
            || slab.generation != set.locator().generation()
        {
            return Err(FenceError::WrongRingSet);
        }
        if slab.slab_capacity() < set.ring_count() {
            return Err(FenceError::RingCountOutOfRange);
        }
        Ok(Self {
            set,
            slab,
            high_water: 0,
            release_remaining: 0,
            in_flight: None,
            failed_ring: None,
            phase: ConsumerPrefixPhase::Acquiring,
        })
    }

    pub const fn prefix_phase(&self) -> ConsumerPrefixPhase {
        self.phase
    }

    pub const fn acquired_prefix(&self) -> u32 {
        self.high_water
    }

    pub const fn release_remaining(&self) -> u32 {
        self.release_remaining
    }

    pub const fn failed_ring(&self) -> Option<u32> {
        self.failed_ring
    }

    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.set
    }

    /// The next ring to acquire, or `None` once the set is complete.
    ///
    /// Named `next_acquire_ring` because `next_ring` already names the
    /// session-ring initializer's mint.
    #[doc(hidden)]
    pub fn record_native_set_acquired(&mut self) {
        self.high_water = self.set.ring_count();
        self.release_remaining = 0;
        self.phase = ConsumerPrefixPhase::AcquiredComplete;
    }

    pub const fn next_acquire_ring(&self) -> Option<u32> {
        if self.high_water < self.set.ring_count() {
            Some(self.high_water)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn mark_set_acquired_for_test(&mut self) {
        self.high_water = self.set.ring_count();
        self.release_remaining = 0;
        self.phase = ConsumerPrefixPhase::AcquiredComplete;
    }

    /// Record one acquired role.
    ///
    /// **The refused token comes back.** Every rejection path returns it, so a
    /// caller that got the ring order wrong still owns the role it took and can
    /// release it; a `Result<(), FenceError>` here would strand it.
    pub fn push_acquired(
        &mut self,
        ring_index: u32,
        token: CqConsumerToken,
    ) -> Result<(), (FenceError, CqConsumerToken)> {
        if !matches!(self.phase, ConsumerPrefixPhase::Acquiring) {
            return Err((FenceError::InvalidConsumerPhase, token));
        }
        if ring_index >= self.set.ring_count() {
            return Err((FenceError::WrongRing, token));
        }
        // The two refusals split the rule's two failure directions: a ring at or
        // below the water mark was already taken, and one above it skips a ring
        // the ordering requires. Both break "strictly increasing by one", which
        // is the property that makes two concurrent fences over one set
        // deadlock-free, so neither is a lenient case.
        if ring_index < self.high_water {
            return Err((FenceError::DuplicateConsumer, token));
        }
        if ring_index > self.high_water {
            return Err((FenceError::NonIncreasingRing, token));
        }
        // SAFETY: `ring_index == high_water < ring_count <= capacity`, and every
        // slot at or above `high_water` is `None` because this is the only
        // writer and it advances the water mark exactly once per write.
        unsafe { self.slab.write_slot(ring_index, token) };
        self.high_water = self.high_water.saturating_add(1);
        self.release_remaining = self.high_water;
        if self.high_water == self.set.ring_count() {
            self.phase = ConsumerPrefixPhase::AcquiredComplete;
        }
        self.failed_ring = None;
        Ok(())
    }

    /// Record that ring `ring_index` refused to give up its role.
    pub fn record_failed_ring(&mut self, ring_index: u32) -> Result<(), FenceError> {
        if ring_index >= self.set.ring_count() {
            return Err(FenceError::WrongRing);
        }
        self.failed_ring = Some(ring_index);
        Ok(())
    }
}

/// Every consumer role is back in the ring, and the slab is empty.
///
/// The empty slab travels *inside* the proof rather than beside it: releasing
/// the transient backing needs both, and a caller holding the proof but not the
/// slab could free storage the tokens still lived in.
pub struct ConsumerReleaseProof {
    set: SessionRingSetBrand,
    empty_slab: ConsumerTokenSlabOwner,
    // Read by nobody, by design. A seal's whole job is that it cannot be named
    // outside this module, so the type cannot be constructed outside it either;
    // reading it would prove nothing that its presence does not.
    #[allow(dead_code)]
    authority: PrivateConsumerReleaseAuthority,
}

/// The bounded drain completed for this exact ring set.
pub struct DrainCompletedProof {
    set: SessionRingSetBrand,
    // Read by nobody, by design. A seal's whole job is that it cannot be named
    // outside this module, so the type cannot be constructed outside it either;
    // reading it would prove nothing that its presence does not.
    #[allow(dead_code)]
    authority: PrivateDrainCompletedAuthority,
}

/// Credits were retired, after the drain that made retiring meaningful.
///
/// It *contains* the drain proof rather than referring to one: retiring credits
/// for entries a consumer never drained would discard completions the provider
/// still owns, so the ordering is a containment, not a comment.
pub struct RetireCompletedProof {
    drain: DrainCompletedProof,
    // Read by nobody, by design. A seal's whole job is that it cannot be named
    // outside this module, so the type cannot be constructed outside it either;
    // reading it would prove nothing that its presence does not.
    #[allow(dead_code)]
    authority: PrivateRetireCompletedAuthority,
}

/// Both consumer obligations, discharged.
pub struct ConsumerFenceComplete {
    retired: RetireCompletedProof,
    released: ConsumerReleaseProof,
}

/// A complete prefix, ready for the one Drain call.
pub struct PreparedConsumerDrain {
    prefix: ConsumerPrefix,
    // Read by nobody, by design. A seal's whole job is that it cannot be named
    // outside this module, so the type cannot be constructed outside it either;
    // reading it would prove nothing that its presence does not.
    #[allow(dead_code)]
    authority: PrivatePreparedConsumerDrainAuthority,
}

/// The prefix, plus the proof its drain succeeded.
pub struct DrainedConsumerPrefix {
    prefix: ConsumerPrefix,
    drained: DrainCompletedProof,
}

/// A drained prefix, ready for the one Retire call.
///
/// Minted only by `retire_credits_with_proof`, and consumed by it: safe code
/// cannot build one, so the raw Retire DDI cannot be replayed.
pub struct PreparedRetireCall {
    drained: DrainedConsumerPrefix,
    // Read by nobody, by design. A seal's whole job is that it cannot be named
    // outside this module, so the type cannot be constructed outside it either;
    // reading it would prove nothing that its presence does not.
    #[allow(dead_code)]
    authority: PrivatePreparedRetireCallAuthority,
}

/// The prefix, plus the proof its credits were retired.
pub struct RetiredConsumerPrefix {
    prefix: ConsumerPrefix,
    retired: RetireCompletedProof,
}

/// A release that stopped part-way. The prefix still owns the live tokens.
pub struct ReleasedPartialConsumers {
    prefix: ConsumerPrefix,
}

/// What one reverse-release pass decided.
pub enum ConsumerReleaseOutcome {
    Complete(ConsumerReleaseProof),
    Partial(ReleasedPartialConsumers),
}

/// Which consumer effect a reacquired prefix resumes at.
///
/// `RetireCredits` carries the drain proof, so a resume cannot skip back past a
/// drain that already succeeded, nor claim one that did not.
pub enum ConsumerResumeEffect {
    DrainStablePrefixesBounded,
    RetireCredits(DrainCompletedProof),
}

/// What happens after a release finishes.
pub enum ConsumerReleaseNext {
    ReacquireThen(ConsumerResumeEffect),
    ContinueAtQueueInstalledWork(RetireCompletedProof),
}

/// Where a retried fence pass resumes.
pub enum FenceRetryPoint {
    Effect(crate::session::FenceEffect),
    ReleaseConsumersThen {
        prefix: ConsumerPrefix,
        next: ConsumerReleaseNext,
    },
    ReacquireConsumersThen {
        prefix: ConsumerPrefix,
        resume: ConsumerResumeEffect,
    },
}

/// A copyable mirror of [`ConsumerResumeEffect`], for reports and keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerResumeObservation {
    DrainStablePrefixesBounded,
    RetireCredits,
}

/// A copyable mirror of [`ConsumerReleaseNext`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumerReleaseNextObservation {
    ReacquireThen(ConsumerResumeObservation),
    ContinueAtQueueInstalledWork,
}

#[allow(dead_code)]
impl ConsumerPrefix {
    /// Enter the reverse release.
    ///
    /// **The core phase moves before the fallible native call**, which is the
    /// property `release_begins_core_phase_before_the_fallible_native_ddi`
    /// pins: a cursor that were still `AcquiredComplete` while a release was in
    /// flight would admit an acquire, and the two would race for the same ring.
    pub fn begin_release(&mut self) -> Result<(), FenceError> {
        match self.phase {
            // `Acquiring` is admitted deliberately. A pass that acquired three
            // of five rings and then refused still owns three roles, and they
            // are released down the same reverse cursor as a complete set --
            // "ReleaseConsumers takes any owned prefix" is what keeps a partial
            // acquisition from stranding its roles.
            ConsumerPrefixPhase::Acquiring
            | ConsumerPrefixPhase::AcquiredComplete
            | ConsumerPrefixPhase::ReleasedPartial => {}
            _ => return Err(FenceError::InvalidConsumerPhase),
        }
        self.phase = match self.release_remaining {
            // Nothing was ever acquired: the release is already over, and a
            // `ReleasingComplete` here would leave `finish_release` unable to
            // mint the proof a zero-token pass has honestly earned.
            0 => ConsumerPrefixPhase::ReleasedComplete,
            1 => ConsumerPrefixPhase::ReleasingComplete,
            _ => ConsumerPrefixPhase::ReleasingPartial,
        };
        Ok(())
    }

    /// Take the highest live token, for the caller to hand back to its ring.
    /// Put a refused token back at the ring it was taken from.
    ///
    /// Named `restore_released_token` because `restore_last` is not a unique
    /// definition across these crates.
    ///
    /// Gated on `in_flight` and not on the phase. The phase is the same for the
    /// last ring as for any other while its token is out, and a restore that
    /// read the phase instead refused exactly ring 0 -- round 15's N1, where the
    /// refusal carried the affine token into a caller that dropped it.
    pub fn restore_released_token(
        &mut self,
        ring_index: u32,
        token: CqConsumerToken,
    ) -> Result<(), (FenceError, CqConsumerToken)> {
        if self.in_flight != Some(ring_index) {
            return Err((FenceError::InvalidConsumerPhase, token));
        }
        if ring_index != self.release_remaining {
            return Err((FenceError::NonIncreasingRing, token));
        }
        if ring_index >= self.set.ring_count() {
            return Err((FenceError::WrongRing, token));
        }
        // SAFETY: `ring_index == release_remaining < high_water <= ring_count`,
        // and the slot is `None` because `pop_for_release` is the only take.
        unsafe { self.slab.write_slot(ring_index, token) };
        self.release_remaining = self.release_remaining.saturating_add(1);
        self.in_flight = None;
        self.phase = if self.release_remaining == 1 {
            ConsumerPrefixPhase::ReleasingComplete
        } else {
            ConsumerPrefixPhase::ReleasingPartial
        };
        Ok(())
    }

    /// Account for a token that reached its own ring.
    ///
    /// The caller is the only party that knows a native release succeeded, so
    /// it is the caller that must say so. This is the sole path to
    /// `ReleasedComplete`, which is the sole phase `finish_release` mints from:
    /// a pass that pops the last token and never confirms it cannot produce a
    /// `ConsumerReleaseProof` at all.
    pub fn confirm_released_token(&mut self, ring_index: u32) -> Result<(), FenceError> {
        if self.in_flight != Some(ring_index) {
            return Err(FenceError::InvalidConsumerPhase);
        }
        self.in_flight = None;
        self.phase = if self.release_remaining == 0 {
            ConsumerPrefixPhase::ReleasedComplete
        } else if self.release_remaining == 1 {
            ConsumerPrefixPhase::ReleasingComplete
        } else {
            ConsumerPrefixPhase::ReleasingPartial
        };
        Ok(())
    }

    pub fn pop_for_release(&mut self) -> Result<(u32, CqConsumerToken), FenceError> {
        if !matches!(
            self.phase,
            ConsumerPrefixPhase::ReleasingPartial | ConsumerPrefixPhase::ReleasingComplete
        ) {
            return Err(FenceError::InvalidConsumerPhase);
        }
        // One token out at a time. Two would make `restore_released_token`'s
        // ring argument ambiguous, and the reverse order the release depends on
        // would no longer be a property of the cursor.
        if self.in_flight.is_some() {
            return Err(FenceError::DuplicateConsumer);
        }
        let Some(index) = self.release_remaining.checked_sub(1) else {
            return Err(FenceError::IncompleteConsumerSet);
        };
        // SAFETY: `index < release_remaining <= high_water <= ring_count <=
        // capacity`, and every slot below `release_remaining` was written by
        // `push_acquired` and not taken since — `release_remaining` is
        // decremented only here, exactly once per take.
        let Some(token) = (unsafe { self.slab.take_slot(index) }) else {
            return Err(FenceError::IncompleteConsumerSet);
        };
        self.release_remaining = index;
        self.in_flight = Some(index);
        // Never `ReleasedComplete` here. The token has left the slab, not
        // reached its ring, and `ReleasedComplete`'s own contract is that every
        // role is back. `confirm_released_token` is what may say that.
        self.phase = if index == 0 {
            ConsumerPrefixPhase::ReleasingComplete
        } else {
            ConsumerPrefixPhase::ReleasingPartial
        };
        Ok((index, token))
    }

    /// Stop a release that could not finish, keeping the live tokens.
    ///
    /// Refuses while a token is in flight: parking then would record a cursor
    /// owning `release_remaining` tokens when one more is unaccounted for, and
    /// the resumed pass would never look for it.
    pub fn park_partial_release(&mut self) -> Result<(), FenceError> {
        if self.in_flight.is_some() {
            return Err(FenceError::IncompleteConsumerSet);
        }
        match self.phase {
            ConsumerPrefixPhase::ReleasingPartial | ConsumerPrefixPhase::ReleasingComplete => {
                self.phase = ConsumerPrefixPhase::ReleasedPartial;
                Ok(())
            }
            _ => Err(FenceError::InvalidConsumerPhase),
        }
    }

    /// Conclude a release: a proof when nothing is left, a parked cursor
    /// otherwise.
    ///
    /// This is the **only** mint of `ConsumerReleaseProof`, and it consumes the
    /// prefix, so the slab it hands over is the same one every token came from.
    pub fn finish_release(mut self) -> ConsumerReleaseOutcome {
        if self.in_flight.is_none()
            && self.release_remaining == 0
            && matches!(self.phase, ConsumerPrefixPhase::ReleasedComplete)
        {
            let Self { set, slab, .. } = self;
            return ConsumerReleaseOutcome::Complete(ConsumerReleaseProof {
                set,
                empty_slab: slab,
                authority: PrivateConsumerReleaseAuthority(()),
            });
        }
        self.phase = ConsumerPrefixPhase::ReleasedPartial;
        ConsumerReleaseOutcome::Partial(ReleasedPartialConsumers { prefix: self })
    }

    /// Prepare the one Drain call.
    ///
    /// Refuses anything but a complete acquisition, and returns the prefix
    /// unchanged so a partial pass can go on to release what it holds.
    // The refusal returns the affine owner, which is the whole design: this
    // crate has no allocator, and boxing to satisfy the lint would mean an
    // allocation on the refusal path of a teardown that runs when the system is
    // already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn prepare_drain(self) -> Result<PreparedConsumerDrain, (FenceError, Self)> {
        if !matches!(self.phase, ConsumerPrefixPhase::AcquiredComplete) {
            return Err((FenceError::IncompleteConsumerSet, self));
        }
        Ok(PreparedConsumerDrain {
            prefix: self,
            authority: PrivatePreparedConsumerDrainAuthority(()),
        })
    }
}

#[allow(dead_code)]
impl ReleasedPartialConsumers {
    /// Resume acquiring from where the release stopped.
    ///
    /// Named `restart_released_partial` rather than `restart`: `restart` is
    /// already answered elsewhere in these two crates, and a staged row on it
    /// would merge unrelated bodies.
    pub fn restart_released_partial(self) -> ConsumerPrefix {
        let mut prefix = self.prefix;
        prefix.high_water = prefix.release_remaining;
        prefix.phase = if prefix.high_water == prefix.set.ring_count() {
            ConsumerPrefixPhase::AcquiredComplete
        } else {
            ConsumerPrefixPhase::Acquiring
        };
        prefix
    }
}

#[allow(dead_code)]
impl ConsumerReleaseProof {
    /// Rebuild an empty prefix from a complete release, for a reacquire.
    pub fn restart_from_complete(self) -> ConsumerPrefix {
        let Self {
            set, empty_slab, ..
        } = self;
        ConsumerPrefix {
            set,
            slab: empty_slab,
            high_water: 0,
            release_remaining: 0,
            in_flight: None,
            failed_ring: None,
            phase: ConsumerPrefixPhase::Acquiring,
        }
    }
}

/// The sixteen raw kernel operations one fence pass may perform.
///
/// Every method is `unsafe` and carries its own cursor/owner obligation, and
/// the two that take a prepared packet are reachable only through the safe
/// wrappers below. That is what makes "a successful native operation happened
/// exactly once" a property of the type system rather than of the caller's
/// discipline: safe code cannot construct a `PreparedRetireCall`, so it cannot
/// call `native_retire_grants` twice for one drain.
///
/// # Safety
/// An implementation must bind exactly one resident session owner set, return
/// every named affine owner unchanged on refusal, perform each successful
/// effect at most once, and obey every method's local lock/IRQL contract.
#[allow(clippy::missing_safety_doc)]
pub unsafe trait FenceKernelDdi {
    type Error;

    unsafe fn native_close_generation_admission(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_schedule_linked_pending(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_wait_control_and_access_rundown(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_unmap_producer_aliases_reverse(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_wait_producer_capture_rundown(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_acquire_consumers_increasing(
        &mut self,
        prefix: &mut ConsumerPrefix,
    ) -> Result<(), Self::Error>;
    unsafe fn native_drain_stable_prefixes_bounded(
        &mut self,
        prepared: &mut PreparedConsumerDrain,
    ) -> Result<(), Self::Error>;
    unsafe fn native_retire_grants(
        &mut self,
        call: &mut PreparedRetireCall,
    ) -> Result<(), Self::Error>;
    unsafe fn native_release_consumers(
        &mut self,
        prefix: &mut ConsumerPrefix,
    ) -> Result<(), Self::Error>;
    unsafe fn native_queue_installed_work(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_wait_pending_and_owner_rundown(
        &mut self,
    ) -> Result<(), PendingOwnerWaitFailure<Self::Error>>;
    unsafe fn native_unmap_readonly_aliases_reverse(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_release_mdls_and_system_view(&mut self) -> Result<(), Self::Error>;
    unsafe fn native_dereference_process(&mut self) -> Result<(), Self::Error>;
    // The refusal returns the affine owner, which is the whole design: this
    // crate has no allocator, and boxing to satisfy the lint would mean an
    // allocation on the refusal path of a teardown that runs when the system is
    // already unhappy.
    #[allow(clippy::result_large_err)]
    unsafe fn native_take_or_join_mount_and_delete(
        &mut self,
    ) -> Result<BoundCompletedMountTeardown, MountTeardownCallError<Self::Error>>;
    unsafe fn native_release_transient_arrays(
        &mut self,
        proof: ConsumerReleaseProof,
    ) -> Result<(), (Self::Error, ConsumerReleaseProof)>;
    /// Take this session's consumer-token slab so the runner can construct its
    /// acquiring prefix. Called at most once per pass that still needs to
    /// acquire; a residual that already owns a prefix does not call it.
    unsafe fn native_take_consumer_slab(&mut self) -> Result<ConsumerTokenSlabOwner, Self::Error>;
}

/// Run the one bounded drain, and mint its proof only if it succeeded.
///
/// The sole caller of `native_drain_stable_prefixes_bounded`. A refusal returns
/// **the same prepared packet**, so the caller has exactly one thing to retry
/// and cannot construct a second.
// Same position as `native_take_or_join_mount_and_delete` above: the refusal
// returns the affine prepared packet, which is what stops the caller
// constructing a second one, and this crate has no allocator -- boxing to
// satisfy the lint would allocate on the refusal path of a teardown that runs
// when the system is already unhappy. The prefix crossed the lint's 128-byte
// threshold when it gained the in-flight ring; the reason it is returned by
// value did not change.
#[allow(clippy::result_large_err)]
#[allow(dead_code)]
pub fn drain_stable_prefixes_with_proof<D: FenceKernelDdi>(
    ddi: &mut D,
    mut prepared: PreparedConsumerDrain,
) -> Result<DrainedConsumerPrefix, (KernelFenceError<D::Error>, PreparedConsumerDrain)> {
    // SAFETY: `prepared` is the one current prepared Drain call, minted by
    // `ConsumerPrefix::prepare_drain` from a complete acquisition, and this is
    // the only call site.
    match unsafe { ddi.native_drain_stable_prefixes_bounded(&mut prepared) } {
        Ok(()) => {
            let PreparedConsumerDrain { prefix, .. } = prepared;
            let set = prefix.set;
            Ok(DrainedConsumerPrefix {
                prefix,
                drained: DrainCompletedProof {
                    set,
                    authority: PrivateDrainCompletedAuthority(()),
                },
            })
        }
        Err(error) => Err((KernelFenceError::Native(error), prepared)),
    }
}

/// Retire credits for a drained prefix, and mint its proof only if it succeeded.
///
/// The sole caller of `native_retire_grants`, and the only minter of
/// `PreparedRetireCall`. The drained packet goes in and — on refusal — comes
/// back out unchanged, drain proof included, so a retry retires against the same
/// drain rather than a fresh one.
#[allow(dead_code)]
// The refusal returns the affine owner, which is the whole design: this crate
// has no allocator, and boxing to satisfy the lint would mean an allocation on
// the refusal path of a teardown that runs when the system is already unhappy.
#[allow(clippy::result_large_err)]
pub fn retire_credits_with_proof<D: FenceKernelDdi>(
    ddi: &mut D,
    drained: DrainedConsumerPrefix,
) -> Result<RetiredConsumerPrefix, (KernelFenceError<D::Error>, DrainedConsumerPrefix)> {
    let mut call = PreparedRetireCall {
        drained,
        authority: PrivatePreparedRetireCallAuthority(()),
    };
    // SAFETY: `call` owns the exact drained proof and complete prefix for this
    // session, it was minted immediately above, and this is the only call site.
    match unsafe { ddi.native_retire_grants(&mut call) } {
        Ok(()) => {
            let PreparedRetireCall { drained, .. } = call;
            let DrainedConsumerPrefix { prefix, drained } = drained;
            Ok(RetiredConsumerPrefix {
                prefix,
                retired: RetireCompletedProof {
                    drain: drained,
                    authority: PrivateRetireCompletedAuthority(()),
                },
            })
        }
        Err(error) => {
            let PreparedRetireCall { drained, .. } = call;
            Err((KernelFenceError::Native(error), drained))
        }
    }
}

#[allow(dead_code)]
impl PreparedConsumerDrain {
    pub const fn consumer_prefix(&self) -> &ConsumerPrefix {
        &self.prefix
    }

    /// Give up on draining and get the prefix back, so it can be released.
    pub fn into_prefix(self) -> ConsumerPrefix {
        self.prefix
    }
}

#[allow(dead_code)]
impl DrainedConsumerPrefix {
    pub const fn consumer_prefix(&self) -> &ConsumerPrefix {
        &self.prefix
    }

    pub(crate) fn from_parts(prefix: ConsumerPrefix, drained: DrainCompletedProof) -> Self {
        Self { prefix, drained }
    }

    /// Split, for a release that has to happen before the retire retry.
    pub fn into_drained_parts(self) -> (ConsumerPrefix, DrainCompletedProof) {
        (self.prefix, self.drained)
    }
}

#[allow(dead_code)]
impl PreparedRetireCall {
    pub const fn consumer_prefix(&self) -> &ConsumerPrefix {
        &self.drained.prefix
    }

    /// Named `drain_proof`, not `drained`.
    ///
    /// The graph's edge model is bare-identifier, so **defining** a name gives
    /// every pre-existing textual `name(` in production a destination. There
    /// was no `drained` definition before this one, and thirteen production
    /// bodies already contained that token; adding the accessor made all
    /// thirteen point at a staged method and reported it production-reachable.
    /// The usual rule is "check a new name against both source roots" -- this
    /// is the same rule extended to call sites, not just definitions.
    pub const fn drain_proof(&self) -> &DrainCompletedProof {
        &self.drained.drained
    }
}

#[allow(dead_code)]
impl RetiredConsumerPrefix {
    pub const fn consumer_prefix(&self) -> &ConsumerPrefix {
        &self.prefix
    }

    pub fn into_retired_parts(self) -> (ConsumerPrefix, RetireCompletedProof) {
        (self.prefix, self.retired)
    }
}

#[allow(dead_code)]
impl DrainCompletedProof {
    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.set
    }
}

#[allow(dead_code)]
impl RetireCompletedProof {
    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.drain.set
    }
}

#[allow(dead_code)]
impl ConsumerReleaseProof {
    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.set
    }
}

#[allow(dead_code)]
impl ConsumerFenceComplete {
    /// Pair the two consumer obligations, checking they are one session's.
    ///
    /// Fallible on purpose: a retire proof from one generation and a release
    /// proof from another would together claim a discharge neither earned, and
    /// both are otherwise indistinguishable values of the same types.
    // The refusal returns the affine owner, which is the whole design: this
    // crate has no allocator, and boxing to satisfy the lint would mean an
    // allocation on the refusal path of a teardown that runs when the system is
    // already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn pair(
        retired: RetireCompletedProof,
        released: ConsumerReleaseProof,
    ) -> Result<Self, (FenceError, RetireCompletedProof, ConsumerReleaseProof)> {
        if retired.set_brand() != released.set_brand() {
            return Err((FenceError::RetryBrandMismatch, retired, released));
        }
        Ok(Self { retired, released })
    }

    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.released.set
    }

    /// Spend the release proof on the transient backing, keeping the retire
    /// proof, which the report still needs.
    pub fn into_release_proof(self) -> (RetireCompletedProof, ConsumerReleaseProof) {
        (self.retired, self.released)
    }
}

#[allow(dead_code)]
impl ConsumerResumeEffect {
    pub const fn resume_effect(&self) -> ConsumerResumeObservation {
        match self {
            Self::DrainStablePrefixesBounded => {
                ConsumerResumeObservation::DrainStablePrefixesBounded
            }
            Self::RetireCredits(_) => ConsumerResumeObservation::RetireCredits,
        }
    }
}

#[allow(dead_code)]
impl ConsumerReleaseNext {
    pub const fn release_next(&self) -> ConsumerReleaseNextObservation {
        match self {
            Self::ReacquireThen(effect) => {
                ConsumerReleaseNextObservation::ReacquireThen(effect.resume_effect())
            }
            Self::ContinueAtQueueInstalledWork(_) => {
                ConsumerReleaseNextObservation::ContinueAtQueueInstalledWork
            }
        }
    }
}

#[allow(dead_code)]
impl FenceRetryPoint {
    /// Which effect a retry resumes at, without projecting any owner.
    pub const fn retry_point(&self) -> crate::session::FenceEffect {
        match self {
            Self::Effect(effect) => *effect,
            Self::ReleaseConsumersThen { .. } => crate::session::FenceEffect::ReleaseConsumers,
            Self::ReacquireConsumersThen { .. } => {
                crate::session::FenceEffect::AcquireConsumersIncreasing
            }
        }
    }

    /// Copyable key for this cursor, without projecting any owner.
    pub fn cursor_retry_key(&self) -> FenceRetryKey {
        match self {
            Self::Effect(effect) => FenceRetryKey::Effect(*effect),
            Self::ReleaseConsumersThen { prefix, next } => FenceRetryKey::ReleaseConsumersThen {
                phase: prefix.phase,
                owned_prefix: prefix.high_water,
                high_water: prefix.high_water,
                release_remaining: prefix.release_remaining,
                failed_ring: prefix.failed_ring,
                next: next.release_next(),
            },
            Self::ReacquireConsumersThen { prefix, resume } => {
                FenceRetryKey::ReacquireConsumersThen {
                    phase: prefix.phase,
                    owned_prefix: prefix.high_water,
                    high_water: prefix.high_water,
                    next_ring: prefix.next_acquire_ring(),
                    failed_ring: prefix.failed_ring,
                    resume: resume.resume_effect(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// R5 staging: the residual retry lifecycle
// ---------------------------------------------------------------------------

/// The backoff table, exactly as the contract states it.
///
/// A closed constant the rows walk rather than a formula they restate: a
/// doubling expression and this table agree for nine entries and disagree at the
/// tenth, where the schedule deliberately stops at thirty seconds.
pub const FENCE_RETRY_DELAY_MS: [u32; 10] =
    [100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 30000];

/// A relative due time in 100ns units, for a kernel timer.
///
/// Negative because the kernel reads a negative due time as relative; `checked`
/// because a caller-supplied delay must not be able to produce a positive
/// (absolute) time by overflowing, which would arm a timer for 1601 AD and fire
/// it immediately.
#[allow(dead_code)]
pub const fn checked_retry_due_time_100ns(delay_ms: u32) -> Option<i64> {
    match (delay_ms as i64).checked_mul(10_000) {
        Some(scaled) => scaled.checked_neg(),
        None => None,
    }
}

/// Where one cell's residual retry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceRetryLifecycleState {
    Idle,
    DelayArmed,
    DelayDpcRunning,
    Queued,
    Running,
    /// Permanent. No transition leaves it.
    FailStop,
}

/// Which effect or consumer cursor a retry resumes at, as a copyable key.
///
/// Comparing the **whole** key is what decides whether a retry made progress.
/// A key that only carried the effect would call two passes equal when one had
/// released three consumers and the other none, and the backoff would stop
/// growing on a fence that was making no progress at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceRetryKey {
    Effect(crate::session::FenceEffect),
    ReleaseConsumersThen {
        phase: ConsumerPrefixPhase,
        owned_prefix: u32,
        high_water: u32,
        release_remaining: u32,
        failed_ring: Option<u32>,
        next: ConsumerReleaseNextObservation,
    },
    ReacquireConsumersThen {
        phase: ConsumerPrefixPhase,
        owned_prefix: u32,
        high_water: u32,
        next_ring: Option<u32>,
        failed_ring: Option<u32>,
        resume: ConsumerResumeObservation,
    },
}

/// Why a fence pass could not finish.
///
/// Private, and derived from the refusal that produced it rather than passed in:
/// a caller that could label its own refusal `TransientNative` would get an
/// automatic retry for an invariant violation, which retries the violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateFenceRetryCause {
    /// A DDI was actually invoked and refused.
    TransientNative,
    /// Something the cursor's own rules forbid. Never retried automatically.
    Invariant(FenceFailStopReason),
}

/// Why a fence permanently stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceFailStopReason {
    CoreInvariant,
    BrandMismatch,
    MountBindMismatch,
    PendingPublication(crate::enter::PublicationFailStopWitness),
}

private_authority_seals!(
    PrivateFenceRetryNeededAuthority,
    PrivateFenceRetryDelayAuthority,
    PrivateFenceRetryDelayDpcAuthority,
    PrivateFenceRetryAuthority,
    PrivateFenceRetryRunAuthority,
    PrivateFenceRetryFailStopAuthority,
    PrivateFenceRunCompleteObservationAuthority,
    PrivateFenceInitialLifecycleBindingAuthority,
    PrivateFenceInitialPrepareRefusalAuthority,
    PrivateFenceRetryBeginRunRefusalAuthority,
    PrivateFenceRetryDeferRefusalAuthority,
    PrivatePreparedFenceRetryCompleteAuthority,
    PrivatePreparedFenceInitialCompleteAuthority,
    PrivateFenceRetryCompletePreparationFailureAuthority,
    PrivateFenceRetryCompleteRefusalAuthority,
    PrivateFenceInitialCompletePreparationFailureAuthority,
    PrivateFenceInitialCompleteRefusalAuthority,
    PrivateFenceObligationsDischargedAuthority,
);

/// One cell's retry identity. Private, nonzero, never reused.
///
/// Two lifecycles for the same locator must reject one another's rights, and a
/// locator cannot decide that: a cell is reused across generations, so a
/// locator-only check would let a previous generation's parked right drive the
/// next one's retry. The ID is what distinguishes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FenceRetryLifecycleId(core::num::NonZeroU64);

/// The process-local source of lifecycle identities.
///
/// Checked, not wrapping: a wrap would silently make two live lifecycles equal,
/// which is exactly the confusion the ID exists to prevent, so exhaustion
/// refuses instead.
static NEXT_FENCE_RETRY_LIFECYCLE_ID: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Allocate one identity from `next_id`.
///
/// **The source is a parameter, exactly as `allocate_grant_table_id` takes
/// one.** A closed-over static would put the exhaustion branch 2^64 allocations
/// out of reach of any test, and an unreachable refusal is an unproven one.
fn allocate_fence_retry_lifecycle_id(
    next_id: &core::sync::atomic::AtomicU64,
) -> Result<FenceRetryLifecycleId, LifecycleError> {
    use core::num::NonZeroU64;
    use core::sync::atomic::Ordering;

    let mut current = next_id.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return Err(LifecycleError::GenerationExhausted);
        }
        if current == 0 {
            match next_id.compare_exchange_weak(0, 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => current = 1,
                Err(observed) => current = observed,
            }
            continue;
        }
        let next = current.checked_add(1).unwrap_or(u64::MAX);
        match next_id.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                let Some(identity) = NonZeroU64::new(current) else {
                    return Err(LifecycleError::GenerationExhausted);
                };
                return Ok(FenceRetryLifecycleId(identity));
            }
            Err(observed) => current = observed,
        }
    }
}

/// The one token an initial fence run must present to end.
///
/// Opaque, non-`Clone`, no getter, one constructor. Task 25 stores it in a
/// take-once cell slot, so an initial run cannot select a different
/// same-locator lifecycle to report its result to.
#[must_use = "an initial fence run must consume its lifecycle binding"]
pub struct FenceInitialLifecycleBinding {
    locator: SessionLocator,
    lifecycle: FenceRetryLifecycleId,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceInitialLifecycleBindingAuthority,
}

/// A pass that could not finish, and the first thing that stopped it.
///
/// The cause is private and the constructor is crate-internal: there is no
/// argument through which a caller labels its own refusal transient.
#[must_use = "a retry-needed authority must be consumed by a lifecycle transition"]
pub struct FenceRetryNeeded {
    locator: SessionLocator,
    key: FenceRetryKey,
    cause: PrivateFenceRetryCause,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryNeededAuthority,
}

#[allow(dead_code)]
impl FenceRetryNeeded {
    /// Mint from a native refusal that was actually invoked.
    pub(crate) fn from_invoked_native_refusal(locator: SessionLocator, key: FenceRetryKey) -> Self {
        Self {
            locator,
            key,
            cause: PrivateFenceRetryCause::TransientNative,
            authority: PrivateFenceRetryNeededAuthority(()),
        }
    }

    /// Mint from a rule the cursor itself refused. Never retried automatically.
    pub(crate) fn from_invariant_refusal(
        locator: SessionLocator,
        key: FenceRetryKey,
        reason: FenceFailStopReason,
    ) -> Self {
        Self {
            locator,
            key,
            cause: PrivateFenceRetryCause::Invariant(reason),
            authority: PrivateFenceRetryNeededAuthority(()),
        }
    }

    pub const fn retry_key(&self) -> FenceRetryKey {
        self.key
    }

    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Whether this refusal is the automatically retryable kind.
    ///
    /// Observation only: it reports the private classification, and nothing
    /// accepts it as an argument.
    pub const fn is_transient_native(&self) -> bool {
        matches!(self.cause, PrivateFenceRetryCause::TransientNative)
    }
}

/// The right to arm one delay timer, and the exact delay it was granted.
#[must_use = "an unconsumed delay right leaves a retry armed for nobody"]
pub struct FenceRetryDelayRight {
    locator: SessionLocator,
    lifecycle: FenceRetryLifecycleId,
    retry_key: FenceRetryKey,
    same_point_attempts: u32,
    due_time_100ns: i64,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryDelayAuthority,
}

/// The right to run the delay DPC that queues the retry.
#[must_use]
pub struct FenceRetryDelayDpcRight {
    locator: SessionLocator,
    lifecycle: FenceRetryLifecycleId,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryDelayDpcAuthority,
}

/// The right to be picked up by the retry worker.
#[must_use]
pub struct FenceRetryRight {
    locator: SessionLocator,
    lifecycle: FenceRetryLifecycleId,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryAuthority,
}

/// The right to be *running* one retry pass. Exactly one exists at a time.
#[must_use]
pub struct FenceRetryRunRight {
    locator: SessionLocator,
    lifecycle: FenceRetryLifecycleId,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryRunAuthority,
}

/// The permanent stop. There is no transition out of it.
#[must_use]
pub struct FenceRetryFailStopRight {
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    locator: SessionLocator,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    lifecycle: FenceRetryLifecycleId,
    retry_key: FenceRetryKey,
    reason: FenceFailStopReason,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryFailStopAuthority,
}

/// A borrow-bound witness that one fence run completed.
///
/// The lifetime is the point: it borrows the completion proof it was minted
/// from, so it cannot outlive it and be replayed against a later pass.
#[must_use]
pub struct FenceRunCompleteObservation<'proof> {
    locator: SessionLocator,
    marker: core::marker::PhantomData<&'proof ()>,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRunCompleteObservationAuthority,
}

/// What `prepare` decided for one refusal.
#[must_use = "a disposition carries the only right its transition minted"]
pub enum FenceRetryDisposition {
    /// Retry after the delay this right names.
    Delay(FenceRetryDelayRight),
    /// Permanent. Nothing is scheduled and no timer is armed.
    FailStop(FenceRetryFailStopRight),
}

#[allow(dead_code)]
impl FenceRetryDelayRight {
    pub const fn due_time_100ns(&self) -> i64 {
        self.due_time_100ns
    }

    pub const fn same_point_attempts(&self) -> u32 {
        self.same_point_attempts
    }

    pub const fn retry_key(&self) -> FenceRetryKey {
        self.retry_key
    }
}

#[allow(dead_code)]
impl FenceRetryFailStopRight {
    pub const fn fail_stop_reason(&self) -> FenceFailStopReason {
        self.reason
    }

    pub const fn retry_key(&self) -> FenceRetryKey {
        self.retry_key
    }
}

/// One permanent cell's residual retry machine.
///
/// Pure: it owns no timer, no work item and no cell. Every transition consumes
/// the right the previous one minted and checks the private lifecycle ID before
/// mutating, so two lifecycles that deliberately share a locator still reject
/// one another's rights.
pub struct FenceRetryLifecycle {
    id: FenceRetryLifecycleId,
    locator: SessionLocator,
    state: FenceRetryLifecycleState,
    last_key: Option<FenceRetryKey>,
    same_key_attempts: u32,
}

/// A refusal from the initial preparation, sealed with everything it owns.
#[must_use]
pub struct FenceInitialPrepareRefusal {
    error: LifecycleError,
    initial: FenceInitialLifecycleBinding,
    needed: FenceRetryNeeded,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceInitialPrepareRefusalAuthority,
}

/// A refusal from `begin_fence_retry_run`, owning the exact queued right.
#[must_use]
pub struct FenceRetryBeginRunRefusal {
    error: LifecycleError,
    queued: FenceRetryRight,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryBeginRunRefusalAuthority,
}

/// A refusal from `defer`, owning the exact Running right.
#[must_use]
pub struct FenceRetryDeferRefusal {
    error: LifecycleError,
    run: FenceRetryRunRight,
    needed: FenceRetryNeeded,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryDeferRefusalAuthority,
}

#[allow(dead_code)]
impl FenceInitialPrepareRefusal {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    /// Take back both authorities. There is no partial recovery.
    ///
    /// Named apart from `into_parts` for the node-merge reason above.
    pub fn into_initial_prepare_parts(self) -> (FenceInitialLifecycleBinding, FenceRetryNeeded) {
        (self.initial, self.needed)
    }
}

#[allow(dead_code)]
impl FenceRetryBeginRunRefusal {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    pub fn into_queued_right(self) -> FenceRetryRight {
        self.queued
    }
}

#[allow(dead_code)]
impl FenceRetryDeferRefusal {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    pub fn into_defer_parts(self) -> (FenceRetryRunRight, FenceRetryNeeded) {
        (self.run, self.needed)
    }
}

#[allow(dead_code)]
impl FenceRetryLifecycle {
    /// Build one lifecycle and its sole initial binding.
    ///
    /// The two come out together and the binding has no second constructor, so
    /// "exactly one initial run per lifecycle" is a property of the type rather
    /// than of the caller.
    pub fn try_new_fence_retry_lifecycle(
        locator: SessionLocator,
    ) -> Result<(Self, FenceInitialLifecycleBinding), LifecycleError> {
        Self::try_new_from_source(locator, &NEXT_FENCE_RETRY_LIFECYCLE_ID)
    }

    /// The same, over a caller-supplied identity source.
    ///
    /// Separate so a test can prime the source to its last value and reach the
    /// exhaustion refusal, which is otherwise 2^64 allocations away. An
    /// unreachable refusal is an unproven one.
    pub(crate) fn try_new_from_source(
        locator: SessionLocator,
        next_id: &core::sync::atomic::AtomicU64,
    ) -> Result<(Self, FenceInitialLifecycleBinding), LifecycleError> {
        let id = allocate_fence_retry_lifecycle_id(next_id)?;
        Ok((
            Self {
                id,
                locator,
                state: FenceRetryLifecycleState::Idle,
                last_key: None,
                same_key_attempts: 0,
            },
            FenceInitialLifecycleBinding {
                locator,
                lifecycle: id,
                authority: PrivateFenceInitialLifecycleBindingAuthority(()),
            },
        ))
    }

    pub const fn lifecycle_state(&self) -> FenceRetryLifecycleState {
        self.state
    }

    pub const fn same_key_attempts(&self) -> u32 {
        self.same_key_attempts
    }

    /// Turn a refusal into a delay or a permanent stop.
    ///
    /// The whole key decides progress. An equal key saturating-increments the
    /// attempt count; any difference resets it to zero, because a fence that
    /// moved to the next effect, or released one more consumer, has made
    /// progress and must not inherit the previous point's backoff.
    ///
    /// Only `FENCE_RETRY_DELAY_MS[min(attempts, 9)]` is ever indexed.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn prepare_fence_retry(
        &mut self,
        initial: FenceInitialLifecycleBinding,
        needed: FenceRetryNeeded,
    ) -> Result<FenceRetryDisposition, FenceInitialPrepareRefusal> {
        // Every check precedes every mutation, so a refusal leaves the machine
        // exactly as it was and both authorities go back whole.
        // A foreign binding and a wrong state share one error value but are two
        // different refusals; collapsing them would hide which one fired, and
        // "this lifecycle is not yours" and "this lifecycle is busy" want
        // different responses from a caller.
        #[allow(clippy::if_same_then_else)]
        let refusal = if initial.lifecycle != self.id {
            Some(LifecycleError::WrongState)
        } else if !matches!(self.state, FenceRetryLifecycleState::Idle) {
            Some(LifecycleError::WrongState)
        } else if needed.locator != self.locator || initial.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else {
            None
        };
        if let Some(error) = refusal {
            return Err(FenceInitialPrepareRefusal {
                error,
                initial,
                needed,
                authority: PrivateFenceInitialPrepareRefusalAuthority(()),
            });
        }

        let FenceInitialLifecycleBinding { .. } = initial;
        let FenceRetryNeeded { key, cause, .. } = needed;

        if let PrivateFenceRetryCause::Invariant(reason) = cause {
            self.state = FenceRetryLifecycleState::FailStop;
            self.last_key = Some(key);
            return Ok(FenceRetryDisposition::FailStop(FenceRetryFailStopRight {
                locator: self.locator,
                lifecycle: self.id,
                retry_key: key,
                reason,
                authority: PrivateFenceRetryFailStopAuthority(()),
            }));
        }

        self.same_key_attempts = if self.last_key == Some(key) {
            self.same_key_attempts.saturating_add(1)
        } else {
            0
        };
        self.last_key = Some(key);
        let last = FENCE_RETRY_DELAY_MS.len().saturating_sub(1);
        let index = if self.same_key_attempts as usize >= last {
            last
        } else {
            self.same_key_attempts as usize
        };
        let Some(delay_ms) = FENCE_RETRY_DELAY_MS.get(index).copied() else {
            unreachable!("the index is clamped to the table it indexes")
        };
        let Some(due_time_100ns) = checked_retry_due_time_100ns(delay_ms) else {
            unreachable!("every entry of a 30-second table converts")
        };
        self.state = FenceRetryLifecycleState::DelayArmed;
        Ok(FenceRetryDisposition::Delay(FenceRetryDelayRight {
            locator: self.locator,
            lifecycle: self.id,
            retry_key: key,
            same_point_attempts: self.same_key_attempts,
            due_time_100ns,
            authority: PrivateFenceRetryDelayAuthority(()),
        }))
    }

    /// The armed timer fired; its DPC is now running.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn begin_delay_dpc(
        &mut self,
        right: FenceRetryDelayRight,
    ) -> Result<FenceRetryDelayDpcRight, (LifecycleError, FenceRetryDelayRight)> {
        if right.lifecycle != self.id || right.locator != self.locator {
            return Err((LifecycleError::WrongLocator, right));
        }
        if !matches!(self.state, FenceRetryLifecycleState::DelayArmed) {
            return Err((LifecycleError::WrongState, right));
        }
        self.state = FenceRetryLifecycleState::DelayDpcRunning;
        Ok(FenceRetryDelayDpcRight {
            locator: self.locator,
            lifecycle: self.id,
            authority: PrivateFenceRetryDelayDpcAuthority(()),
        })
    }

    /// The DPC queued the retry work.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn queue_from_dpc(
        &mut self,
        right: FenceRetryDelayDpcRight,
    ) -> Result<FenceRetryRight, (LifecycleError, FenceRetryDelayDpcRight)> {
        if right.lifecycle != self.id || right.locator != self.locator {
            return Err((LifecycleError::WrongLocator, right));
        }
        if !matches!(self.state, FenceRetryLifecycleState::DelayDpcRunning) {
            return Err((LifecycleError::WrongState, right));
        }
        self.state = FenceRetryLifecycleState::Queued;
        Ok(FenceRetryRight {
            locator: self.locator,
            lifecycle: self.id,
            authority: PrivateFenceRetryAuthority(()),
        })
    }

    /// The worker picked the queued retry up.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn begin_fence_retry_run(
        &mut self,
        right: FenceRetryRight,
    ) -> Result<FenceRetryRunRight, FenceRetryBeginRunRefusal> {
        let error = if right.lifecycle != self.id || right.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else if !matches!(self.state, FenceRetryLifecycleState::Queued) {
            Some(LifecycleError::WrongState)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(FenceRetryBeginRunRefusal {
                error,
                queued: right,
                authority: PrivateFenceRetryBeginRunRefusalAuthority(()),
            });
        }
        let FenceRetryRight { .. } = right;
        self.state = FenceRetryLifecycleState::Running;
        Ok(FenceRetryRunRight {
            locator: self.locator,
            lifecycle: self.id,
            authority: PrivateFenceRetryRunAuthority(()),
        })
    }

    /// A retry pass refused again: schedule the next one, or stop permanently.
    ///
    /// It reaches Idle first and then runs the same scheduling body the initial
    /// path runs, so there is exactly one place that decides a delay or a
    /// fail-stop. A second copy here is how the two would drift.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn defer(
        &mut self,
        run: FenceRetryRunRight,
        needed: FenceRetryNeeded,
    ) -> Result<FenceRetryDisposition, FenceRetryDeferRefusal> {
        // A foreign right and a foreign observation share one error value and
        // are two different refusals: one says the caller brought the wrong
        // authority, the other that it brought the wrong proof.
        #[allow(clippy::if_same_then_else)]
        let error = if run.lifecycle != self.id || run.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else if needed.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else if !matches!(self.state, FenceRetryLifecycleState::Running) {
            Some(LifecycleError::WrongState)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(FenceRetryDeferRefusal {
                error,
                run,
                needed,
                authority: PrivateFenceRetryDeferRefusalAuthority(()),
            });
        }
        let FenceRetryRunRight { .. } = run;
        self.state = FenceRetryLifecycleState::Idle;
        let initial = FenceInitialLifecycleBinding {
            locator: self.locator,
            lifecycle: self.id,
            authority: PrivateFenceInitialLifecycleBindingAuthority(()),
        };
        match self.prepare_fence_retry(initial, needed) {
            Ok(disposition) => Ok(disposition),
            Err(refusal) => {
                let (_binding, needed) = refusal.into_initial_prepare_parts();
                unreachable!(
                    "the defer path rebuilt this lifecycle's own binding at Idle: {:?}",
                    needed.retry_key()
                )
            }
        }
    }
}

/// A prepared Running to Idle transition.
///
/// It retains an exclusive borrow of the exact lifecycle it validated, so a
/// preparation made on one lifecycle cannot be committed on another -- the
/// borrow makes the second lifecycle unnameable while this packet lives.
#[must_use = "a prepared completion must be committed"]
pub struct PreparedFenceRetryComplete<'lifecycle, 'proof> {
    lifecycle: &'lifecycle mut FenceRetryLifecycle,
    run: FenceRetryRunRight,
    observation: FenceRunCompleteObservation<'proof>,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivatePreparedFenceRetryCompleteAuthority,
}

/// A prepared initial completion. It mutates nothing, so it borrows immutably.
#[must_use = "a prepared initial completion must be committed"]
pub struct PreparedFenceInitialComplete<'lifecycle, 'proof> {
    lifecycle: &'lifecycle FenceRetryLifecycle,
    initial: FenceInitialLifecycleBinding,
    observation: FenceRunCompleteObservation<'proof>,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivatePreparedFenceInitialCompleteAuthority,
}

/// A completion preparation that refused, still owning the run right.
///
/// It holds the observation too, and hands it back through `end_observation` --
/// which is what lets the caller drop the borrow the observation carries before
/// deciding what to do with the run.
#[must_use]
pub struct FenceRetryCompletePreparationFailure<'proof> {
    error: LifecycleError,
    run: FenceRetryRunRight,
    observation: FenceRunCompleteObservation<'proof>,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryCompletePreparationFailureAuthority,
}

/// The same refusal with its borrow ended, so it can be parked.
#[must_use]
pub struct FenceRetryCompleteRefusal {
    error: LifecycleError,
    run: FenceRetryRunRight,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceRetryCompleteRefusalAuthority,
}

#[must_use]
pub struct FenceInitialCompletePreparationFailure<'proof> {
    error: LifecycleError,
    initial: FenceInitialLifecycleBinding,
    observation: FenceRunCompleteObservation<'proof>,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceInitialCompletePreparationFailureAuthority,
}

#[must_use]
pub struct FenceInitialCompleteRefusal {
    error: LifecycleError,
    initial: FenceInitialLifecycleBinding,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceInitialCompleteRefusalAuthority,
}

#[allow(dead_code)]
impl FenceRetryCompletePreparationFailure<'_> {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    /// Drop the observation and keep the run.
    ///
    /// Consuming, and it returns a type with no lifetime parameter: the point is
    /// that the borrow the observation carried is over, so the run can be parked
    /// somewhere that outlives the proof.
    pub fn end_observation(self) -> FenceRetryCompleteRefusal {
        let Self {
            error,
            run,
            observation,
            authority: _,
        } = self;
        let _ = observation;
        FenceRetryCompleteRefusal {
            error,
            run,
            authority: PrivateFenceRetryCompleteRefusalAuthority(()),
        }
    }
}

#[allow(dead_code)]
impl FenceRetryCompleteRefusal {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    pub fn into_run_right(self) -> FenceRetryRunRight {
        self.run
    }
}

#[allow(dead_code)]
impl FenceInitialCompletePreparationFailure<'_> {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    pub fn end_observation(self) -> FenceInitialCompleteRefusal {
        let Self {
            error,
            initial,
            observation,
            authority: _,
        } = self;
        let _ = observation;
        FenceInitialCompleteRefusal {
            error,
            initial,
            authority: PrivateFenceInitialCompleteRefusalAuthority(()),
        }
    }
}

#[allow(dead_code)]
impl FenceInitialCompleteRefusal {
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    pub fn into_initial_binding(self) -> FenceInitialLifecycleBinding {
        self.initial
    }
}

#[allow(dead_code)]
impl PreparedFenceRetryComplete<'_, '_> {
    /// The one infallible Running to Idle transition.
    ///
    /// Parameterless: everything it needs was validated and is retained, so
    /// there is no argument through which another lifecycle, run right or
    /// observation could be substituted between preparation and commit.
    ///
    /// **Named `commit_retry_complete`, not `commit`.** Thirteen definitions
    /// answer `commit` across the two source roots and one of them is
    /// production-reachable, so a body here would attach its edges to that
    /// merged node -- which is how a staged accessor reports as production
    /// code. Same reason as `commit_protocol_abort` and `commit_protocol_claim`.
    pub fn commit_retry_complete(self) {
        let Self {
            lifecycle,
            run,
            observation,
            authority: _,
        } = self;
        let _ = run;
        let _ = observation;
        lifecycle.state = FenceRetryLifecycleState::Idle;
        lifecycle.last_key = None;
        lifecycle.same_key_attempts = 0;
    }
}

#[allow(dead_code)]
impl PreparedFenceInitialComplete<'_, '_> {
    /// The initial completion commits nothing: the lifecycle was already Idle
    /// and stays Idle, which is exactly why it borrows immutably.
    ///
    /// Named `commit_initial_complete` for the same node-merge reason as its
    /// retry counterpart.
    ///
    /// A commit that *set* Idle here would be indistinguishable from one that
    /// found it, and the difference is the whole claim -- an initial run that
    /// completed cleanly never armed a retry, so there is no state to leave.
    pub fn commit_initial_complete(self) {
        let Self {
            lifecycle,
            initial,
            observation,
            authority: _,
        } = self;
        debug_assert!(matches!(lifecycle.state, FenceRetryLifecycleState::Idle));
        let _ = initial;
        let _ = observation;
    }
}

#[allow(dead_code)]
impl FenceRetryLifecycle {
    /// Prepare the Running to Idle transition for a completed retry pass.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn prepare_complete<'lifecycle, 'proof>(
        &'lifecycle mut self,
        run: FenceRetryRunRight,
        completed: FenceRunCompleteObservation<'proof>,
    ) -> Result<
        PreparedFenceRetryComplete<'lifecycle, 'proof>,
        FenceRetryCompletePreparationFailure<'proof>,
    > {
        // A foreign right and a foreign observation share one error value and
        // are two different refusals: one says the caller brought the wrong
        // authority, the other that it brought the wrong proof.
        #[allow(clippy::if_same_then_else)]
        let error = if run.lifecycle != self.id || run.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else if completed.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else if !matches!(self.state, FenceRetryLifecycleState::Running) {
            Some(LifecycleError::WrongState)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(FenceRetryCompletePreparationFailure {
                error,
                run,
                observation: completed,
                authority: PrivateFenceRetryCompletePreparationFailureAuthority(()),
            });
        }
        Ok(PreparedFenceRetryComplete {
            lifecycle: self,
            run,
            observation: completed,
            authority: PrivatePreparedFenceRetryCompleteAuthority(()),
        })
    }

    /// Prepare the initial run's clean exit, which mutates nothing.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn prepare_initial_complete<'lifecycle, 'proof>(
        &'lifecycle self,
        initial: FenceInitialLifecycleBinding,
        completed: FenceRunCompleteObservation<'proof>,
    ) -> Result<
        PreparedFenceInitialComplete<'lifecycle, 'proof>,
        FenceInitialCompletePreparationFailure<'proof>,
    > {
        // Same reason as `prepare_fence_retry`: a foreign binding and a busy
        // lifecycle report one value and are two distinct checks.
        #[allow(clippy::if_same_then_else)]
        let error = if initial.lifecycle != self.id || initial.locator != self.locator {
            Some(LifecycleError::WrongState)
        } else if completed.locator != self.locator {
            Some(LifecycleError::WrongLocator)
        } else if !matches!(self.state, FenceRetryLifecycleState::Idle) {
            Some(LifecycleError::WrongState)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(FenceInitialCompletePreparationFailure {
                error,
                initial,
                observation: completed,
                authority: PrivateFenceInitialCompletePreparationFailureAuthority(()),
            });
        }
        Ok(PreparedFenceInitialComplete {
            lifecycle: self,
            initial,
            observation: completed,
            authority: PrivatePreparedFenceInitialCompleteAuthority(()),
        })
    }
}

#[cfg(test)]
impl FenceRunCompleteObservation<'_> {
    /// The only mint of this observation.
    ///
    /// The type the prepared terminal finalizer's completion observation uses is
    /// deliberately still not named here, now for a narrower reason than when
    /// this was written: Task 24's forbidden-surface scan is a text scan, and it
    /// is right to be, so a mention here would cost a scan entry for nothing.
    /// The original reason -- "a comment naming a type the cutover has not
    /// landed yet is exactly how a premature surface gets introduced one mention
    /// at a time" -- expired when Task 25 landed.
    ///
    /// `cfg(test)`, so no production caller exists and the graph auditor strips
    /// it before it can appear as a staged symbol at all.
    pub(crate) fn for_test(locator: SessionLocator) -> Self {
        Self {
            locator,
            marker: core::marker::PhantomData,
            authority: PrivateFenceRunCompleteObservationAuthority(()),
        }
    }
}

/// Everything one incomplete fence pass leaves behind.
///
/// It owns the retry point and, when the consumer half finished, its completed
/// proof -- so a retry cannot re-run a drain and retire that already succeeded,
/// and cannot skip one that did not. There is deliberately **no**
/// `FenceObligationsDischarged` here and no way to put one in: a residual is by
/// definition a pass that did not discharge, and a type that could carry the
/// discharge would make "residual" and "complete" the same shape.
#[must_use = "a residual owns the only record of what a pass left undone"]
pub struct FenceResidual {
    set: SessionRingSetBrand,
    /// Cumulative, never cleared by a later success: the report answers "what
    /// did this fence ever fail at", and a retry that succeeded does not make
    /// the earlier failure not have happened.
    failed_mask: u16,
    retry: FenceRetryPoint,
    completed_consumers: Option<ConsumerFenceComplete>,
    pending_mount_bind: Option<PendingMountBind>,
    bound_mount: Option<BoundCompletedMountTeardown>,
}

#[allow(dead_code)]
impl FenceResidual {
    /// Build one, checking the whole cursor/proof cross-product.
    ///
    /// Fallible and returning every input: the illegal combinations are the
    /// point. A retry point that still owns a consumer prefix cannot also carry
    /// a completed-consumer proof -- that would claim the roles were both held
    /// and released -- and a prefix branded for another ring set cannot belong
    /// to this residual at all.
    // The refusal owns every affine input, which is the design: this crate
    // has no allocator, and boxing to satisfy the lint would allocate on the
    // refusal path of a teardown that runs when the system is already unhappy.
    #[allow(clippy::result_large_err)]
    pub fn try_new_fence_residual(
        set: SessionRingSetBrand,
        failed_mask: u16,
        retry: FenceRetryPoint,
        completed_consumers: Option<ConsumerFenceComplete>,
        pending_mount_bind: Option<PendingMountBind>,
    ) -> Result<
        Self,
        (
            FenceError,
            FenceRetryPoint,
            Option<ConsumerFenceComplete>,
            Option<PendingMountBind>,
        ),
    > {
        let holds_prefix = matches!(
            retry,
            FenceRetryPoint::ReleaseConsumersThen { .. }
                | FenceRetryPoint::ReacquireConsumersThen { .. }
        );
        let error = if holds_prefix && completed_consumers.is_some() {
            // Both at once would say the consumer roles are simultaneously held
            // by the cursor and given back by the proof.
            Some(FenceError::ConsumerTokensRemain)
        } else if let Some(complete) = completed_consumers.as_ref() {
            if complete.set_brand() != set {
                Some(FenceError::WrongRingSet)
            } else {
                None
            }
        } else {
            None
        };
        let error = error.or_else(|| match &retry {
            FenceRetryPoint::ReleaseConsumersThen { prefix, .. }
            | FenceRetryPoint::ReacquireConsumersThen { prefix, .. } => {
                if prefix.set_brand() != set {
                    Some(FenceError::WrongRingSet)
                } else {
                    None
                }
            }
            FenceRetryPoint::Effect(_) => None,
        });
        if let Some(error) = error {
            return Err((error, retry, completed_consumers, pending_mount_bind));
        }
        Ok(Self {
            set,
            failed_mask,
            retry,
            completed_consumers,
            pending_mount_bind,
            bound_mount: None,
        })
    }

    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.set
    }

    /// Named `residual_failed_mask`, not `failed_mask`: `FenceReport` already
    /// answers the latter, and one node for both would attach this body to a
    /// production-reachable name.
    pub const fn residual_failed_mask(&self) -> u16 {
        self.failed_mask
    }

    /// Where a retry resumes, without projecting any owner.
    pub const fn residual_retry_point(&self) -> crate::session::FenceEffect {
        self.retry.retry_point()
    }

    pub const fn has_completed_consumers(&self) -> bool {
        self.completed_consumers.is_some()
    }

    pub const fn has_pending_mount_bind(&self) -> bool {
        self.pending_mount_bind.is_some()
    }

    /// Fold this pass's newly attempted failures into the cumulative mask.
    ///
    /// OR only. A retry that succeeded never clears history, and a deferred row
    /// -- one whose prerequisites were not met, so no DDI was invoked -- adds
    /// none, which is the difference between "we tried and it refused" and "we
    /// never got there".
    pub fn accumulate_failed_mask(&mut self, newly_failed: u16) {
        self.failed_mask |= newly_failed;
    }
}

/// The final fence's discharge proof.
///
/// Declared here, with **no constructor at all**, so that Task 24's
/// compile-fail fixture can name it: the property under test is that the R4
/// checkpoint's completion proof cannot become one of these, and a fixture that
/// could not name the destination type would fail on an unresolved import
/// instead of on the missing conversion.
///
/// Task 25's `KernelFenceOps::finish` is the only thing that will ever mint one,
/// and only for a pass with no residual. The two proofs are not
/// interchangeable: `ClosedFenceRosterComplete` says a twenty-row checkpoint roster
/// finished, and this says the *sixteen* advertised effects were discharged --
/// including the bounded drain and the credit retirement, which the checkpoint
/// binary has no way to perform.
#[must_use]
pub struct FenceObligationsDischarged {
    set: SessionRingSetBrand,
    // Read by nobody, by design: see the note on the consumer-recovery seals.
    #[allow(dead_code)]
    authority: PrivateFenceObligationsDischargedAuthority,
}

#[allow(dead_code)]
impl FenceObligationsDischarged {
    pub const fn set_brand(&self) -> SessionRingSetBrand {
        self.set
    }
}

// ---------------------------------------------------------------------------
// Task 25: the generic 16-effect runner, packaging, and fail-stop binds
// ---------------------------------------------------------------------------

/// The approved execution order, which is *not* `ALL_FENCE_EFFECTS`.
///
/// WaitControlRundown is the third operation even though the advertised enum
/// lists it later: stage one is close+signal+control-rundown, then producer
/// teardown, then consumers, then pending/owners, then the remaining destructors.
pub const KERNEL_FENCE_PASS_ORDER: [crate::session::FenceEffect; 16] = [
    crate::session::FenceEffect::CloseSessionAdmission,
    crate::session::FenceEffect::SignalPendingEnter,
    crate::session::FenceEffect::WaitControlRundown,
    crate::session::FenceEffect::RemoveProducerMappingsReverse,
    crate::session::FenceEffect::WaitProducerAndMappingCaptureRundown,
    crate::session::FenceEffect::AcquireConsumersIncreasing,
    crate::session::FenceEffect::DrainStablePrefixesBounded,
    crate::session::FenceEffect::RetireCredits,
    crate::session::FenceEffect::ReleaseConsumers,
    crate::session::FenceEffect::QueueInstalledWork,
    crate::session::FenceEffect::WaitPendingAndOwners,
    crate::session::FenceEffect::ReleaseReadOnlyMappingsReverse,
    crate::session::FenceEffect::ReleaseMdlsAndSystemView,
    crate::session::FenceEffect::ReleaseCapturedProcess,
    crate::session::FenceEffect::DismountAndDeleteDevices,
    crate::session::FenceEffect::ReleaseTransientBacking,
];

const fn kernel_fence_bit(effect: crate::session::FenceEffect) -> u16 {
    match effect {
        crate::session::FenceEffect::CloseSessionAdmission => 1 << 0,
        crate::session::FenceEffect::SignalPendingEnter => 1 << 1,
        crate::session::FenceEffect::WaitControlRundown => 1 << 2,
        crate::session::FenceEffect::RemoveProducerMappingsReverse => 1 << 3,
        crate::session::FenceEffect::WaitProducerAndMappingCaptureRundown => 1 << 4,
        crate::session::FenceEffect::AcquireConsumersIncreasing => 1 << 5,
        crate::session::FenceEffect::DrainStablePrefixesBounded => 1 << 6,
        crate::session::FenceEffect::RetireCredits => 1 << 7,
        crate::session::FenceEffect::ReleaseConsumers => 1 << 8,
        crate::session::FenceEffect::QueueInstalledWork => 1 << 9,
        crate::session::FenceEffect::WaitPendingAndOwners => 1 << 10,
        crate::session::FenceEffect::ReleaseReadOnlyMappingsReverse => 1 << 11,
        crate::session::FenceEffect::ReleaseMdlsAndSystemView => 1 << 12,
        crate::session::FenceEffect::ReleaseCapturedProcess => 1 << 13,
        crate::session::FenceEffect::DismountAndDeleteDevices => 1 << 14,
        crate::session::FenceEffect::ReleaseTransientBacking => 1 << 15,
    }
}

const KERNEL_FENCE_FULL_MASK: u16 = 0xFFFF;

private_authority_seals!(
    PrivateCompletedFenceStateAuthority,
    PrivateFencePassReportAuthority,
    PrivatePreparedTerminalWinnerFinalizeAuthority,
    PrivateTerminalWinnerFinalizeFailureAuthority,
    PrivateFenceResidualMergeFailureAuthority,
    PrivateFenceInitialResidualFailStopPacketAuthority,
    PrivateFenceResidualMergeFailStopPacketAuthority,
    PrivateFenceRetryDeferFailStopPacketAuthority,
    PrivateFenceCompletionFailStopPacketAuthority,
);

/// One 16-effect pass report. Distinct from the checkpoint `FenceReport`.
#[derive(Debug)]
#[allow(dead_code)]
pub struct FencePassReport {
    locator: SessionLocator,
    attempted_mask: u16,
    failed_mask: u16,
    authority: PrivateFencePassReportAuthority,
}

impl FencePassReport {
    fn zero(locator: SessionLocator) -> Self {
        Self {
            locator,
            attempted_mask: 0,
            failed_mask: 0,
            authority: PrivateFencePassReportAuthority(()),
        }
    }

    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn failed_mask(&self) -> u16 {
        self.failed_mask
    }

    pub const fn attempted_mask(&self) -> u16 {
        self.attempted_mask
    }

    pub const fn is_complete(&self) -> bool {
        self.attempted_mask == KERNEL_FENCE_FULL_MASK && self.failed_mask == 0
    }
}

pub struct ResidualFenceRun {
    report: FencePassReport,
    residual: FenceResidual,
    retry: FenceRetryNeeded,
}

impl ResidualFenceRun {
    pub const fn report(&self) -> &FencePassReport {
        &self.report
    }

    pub fn into_residual_run_parts(self) -> (FencePassReport, FenceResidual, FenceRetryNeeded) {
        (self.report, self.residual, self.retry)
    }
}

pub struct FenceRunnerStartFailure<D> {
    ddi: D,
    incomplete: ResidualFenceRun,
}

impl<D> FenceRunnerStartFailure<D> {
    pub fn into_start_failure_parts(self) -> (D, ResidualFenceRun) {
        (self.ddi, self.incomplete)
    }
}

pub struct AccumulatedTerminalResult {
    authenticated: AuthenticatedTerminalResult,
    report: FencePassReport,
}

impl AccumulatedTerminalResult {
    pub const fn report(&self) -> &FencePassReport {
        &self.report
    }
}

pub fn begin_accumulated_terminal_result(
    authenticated: AuthenticatedTerminalResult,
) -> AccumulatedTerminalResult {
    let locator = authenticated.locator();
    AccumulatedTerminalResult {
        authenticated,
        report: FencePassReport::zero(locator),
    }
}

pub struct MergedFenceResidual {
    outcome: AccumulatedTerminalResult,
    residual: FenceResidual,
    retry: FenceRetryNeeded,
}

impl MergedFenceResidual {
    pub fn into_merged_residual_parts(
        self,
    ) -> (AccumulatedTerminalResult, FenceResidual, FenceRetryNeeded) {
        (self.outcome, self.residual, self.retry)
    }
}

#[allow(dead_code)]
pub struct FenceResidualMergeFailure {
    error: FenceError,
    outcome: AccumulatedTerminalResult,
    incomplete: ResidualFenceRun,
    authority: PrivateFenceResidualMergeFailureAuthority,
}

impl FenceResidualMergeFailure {
    #[doc(hidden)]
    pub fn error(&self) -> &FenceError {
        &self.error
    }
}

// The refusal owns every affine input, which is the design: this crate
// has no allocator, and boxing to satisfy the lint would allocate on the
// residual merge of a teardown that runs when the system is already unhappy.
#[allow(clippy::result_large_err)]
pub fn merge_residual_terminal_outcome(
    mut outcome: AccumulatedTerminalResult,
    incomplete: ResidualFenceRun,
) -> Result<MergedFenceResidual, FenceResidualMergeFailure> {
    if outcome.authenticated.locator() != incomplete.report.locator {
        return Err(FenceResidualMergeFailure {
            error: FenceError::RetryBrandMismatch,
            outcome,
            incomplete,
            authority: PrivateFenceResidualMergeFailureAuthority(()),
        });
    }
    let ResidualFenceRun {
        report,
        residual,
        retry,
    } = incomplete;
    outcome.report.attempted_mask |= report.attempted_mask;
    outcome.report.failed_mask |= report.failed_mask;
    Ok(MergedFenceResidual {
        outcome,
        residual,
        retry,
    })
}

#[allow(dead_code)]
struct CompletedFenceState {
    set: SessionRingSetBrand,
    report: FencePassReport,
    completed_effect_mask: u16,
    consumers: ConsumerFenceComplete,
    mount: PreparedMountDeactivation,
    authority: PrivateCompletedFenceStateAuthority,
}

pub struct CompletedFenceRun {
    report: FencePassReport,
    discharge: FenceObligationsDischarged,
    mount: PreparedMountDeactivation,
}

impl CompletedFenceRun {
    pub const fn report(&self) -> &FencePassReport {
        &self.report
    }

    pub const fn locator(&self) -> SessionLocator {
        self.report.locator
    }

    /// Move the discharged 16-effect run into deletion readiness after the
    /// locator cross-product was checked without mutation.
    ///
    /// # Safety
    /// Both native owner envelopes name `self.locator()`.
    pub unsafe fn bind_deletion_owners_prevalidated<Tail, Shell, RootRelease>(
        self,
        tail: Tail,
        shell: crate::adapter::lifecycle::NativeSessionOwner<Shell>,
        root: crate::adapter::lifecycle::SessionRootReleaseRight<RootRelease>,
    ) -> FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>> {
        let locator = self.report.locator;
        FenceDeletionReadiness {
            locator,
            owners: R4DeletionOwnerChain { tail, shell, root },
            mount: self.mount,
            authority: PrivateFenceDeletionReadinessAuthority(()),
        }
    }
}

fn package_completed_fence(state: CompletedFenceState) -> CompletedFenceRun {
    let CompletedFenceState {
        set,
        report,
        consumers,
        mount,
        ..
    } = state;
    let _ = consumers;
    CompletedFenceRun {
        report,
        discharge: FenceObligationsDischarged {
            set,
            authority: PrivateFenceObligationsDischargedAuthority(()),
        },
        mount,
    }
}

// ResidualFenceRun carries the still-owned prefix, residual, and retry
// rights. Boxing it would need an allocator this crate does not have.
#[allow(clippy::large_enum_variant)]
pub enum FenceRunOutcome<D> {
    Complete {
        ddi: D,
        completed: CompletedFenceRun,
    },
    Residual {
        ddi: D,
        incomplete: ResidualFenceRun,
    },
}

#[allow(dead_code)]
pub struct PreparedTerminalWinnerFinalize {
    outcome: AccumulatedTerminalResult,
    completed: CompletedFenceRun,
    authority: PrivatePreparedTerminalWinnerFinalizeAuthority,
}

impl PreparedTerminalWinnerFinalize {
    #[doc(hidden)]
    pub fn completion_observation(&self) -> FenceRunCompleteObservation<'_> {
        FenceRunCompleteObservation {
            locator: self.outcome.authenticated.locator(),
            marker: core::marker::PhantomData,
            authority: PrivateFenceRunCompleteObservationAuthority(()),
        }
    }

    #[doc(hidden)]
    pub fn commit(self) -> FenceCompletedTerminalResult {
        let Self {
            outcome, completed, ..
        } = self;
        FenceCompletedTerminalResult {
            authenticated: outcome.authenticated,
            report: completed.report,
            discharge: completed.discharge,
            mount: completed.mount,
        }
    }
}

#[allow(dead_code)]
pub struct TerminalWinnerFinalizeFailure {
    error: FenceError,
    outcome: AccumulatedTerminalResult,
    completed: CompletedFenceRun,
    authority: PrivateTerminalWinnerFinalizeFailureAuthority,
}

impl TerminalWinnerFinalizeFailure {
    #[doc(hidden)]
    pub fn error(&self) -> &FenceError {
        &self.error
    }
}

pub struct FenceCompletedTerminalResult {
    authenticated: AuthenticatedTerminalResult,
    report: FencePassReport,
    discharge: FenceObligationsDischarged,
    mount: PreparedMountDeactivation,
}

impl FenceCompletedTerminalResult {
    pub const fn result(&self) -> TerminalResult {
        let mut result = self.authenticated.result();
        result.fence_failures = self.report.failed_mask;
        result
    }

    pub const fn discharge_set(&self) -> SessionRingSetBrand {
        self.discharge.set
    }

    pub const fn diagnostic(&self) -> crate::session::DiagnosticId {
        self.authenticated.diagnostic()
    }

    pub fn into_authenticated(self) -> AuthenticatedTerminalResult {
        self.authenticated
    }

    pub fn split_for_deletion_tail(
        self,
    ) -> (
        AuthenticatedTerminalResult,
        PreparedMountDeactivation,
        SessionLocator,
    ) {
        let locator = self.authenticated.locator();
        (self.authenticated, self.mount, locator)
    }

    pub const fn locator(&self) -> SessionLocator {
        self.authenticated.locator()
    }

    pub const fn pass_report(&self) -> &FencePassReport {
        &self.report
    }

    /// # Safety
    /// Both native owner envelopes name `self.locator()`.
    pub unsafe fn bind_deletion_owners_prevalidated<Tail, Shell, RootRelease>(
        self,
        tail: Tail,
        shell: crate::adapter::lifecycle::NativeSessionOwner<Shell>,
        root: crate::adapter::lifecycle::SessionRootReleaseRight<RootRelease>,
    ) -> FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>> {
        let locator = self.authenticated.locator();
        FenceDeletionReadiness {
            locator,
            owners: R4DeletionOwnerChain { tail, shell, root },
            mount: self.mount,
            authority: PrivateFenceDeletionReadinessAuthority(()),
        }
    }

    /// # Safety
    /// Both native owner envelopes name `locator`.
    pub unsafe fn bind_deletion_owners_from_split<Tail, Shell, RootRelease>(
        locator: SessionLocator,
        mount: PreparedMountDeactivation,
        tail: Tail,
        shell: crate::adapter::lifecycle::NativeSessionOwner<Shell>,
        root: crate::adapter::lifecycle::SessionRootReleaseRight<RootRelease>,
    ) -> FenceDeletionReadiness<R4DeletionOwnerChain<Tail, Shell, RootRelease>> {
        FenceDeletionReadiness {
            locator,
            owners: R4DeletionOwnerChain { tail, shell, root },
            mount,
            authority: PrivateFenceDeletionReadinessAuthority(()),
        }
    }
}

// The refusal owns every affine input, which is the design: this crate
// has no allocator, and boxing to satisfy the lint would allocate on the
// finalize path of a teardown that runs when the system is already unhappy.
#[allow(clippy::result_large_err)]
pub fn prepare_terminal_winner_finalize(
    outcome: AccumulatedTerminalResult,
    completed: CompletedFenceRun,
) -> Result<PreparedTerminalWinnerFinalize, TerminalWinnerFinalizeFailure> {
    if outcome.authenticated.locator() != completed.report.locator {
        return Err(TerminalWinnerFinalizeFailure {
            error: FenceError::RetryBrandMismatch,
            outcome,
            completed,
            authority: PrivateTerminalWinnerFinalizeFailureAuthority(()),
        });
    }
    Ok(PreparedTerminalWinnerFinalize {
        outcome,
        completed,
        authority: PrivatePreparedTerminalWinnerFinalizeAuthority(()),
    })
}

/// Permanent fence fail-stop observation published through `TerminalBlocked`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FenceTerminalBlocked {
    reason: FenceFailStopReason,
    diagnostic: DiagnosticId,
}

impl FenceTerminalBlocked {
    #[doc(hidden)]
    pub const fn new(reason: FenceFailStopReason, diagnostic: DiagnosticId) -> Self {
        Self { reason, diagnostic }
    }

    pub const fn reason(&self) -> FenceFailStopReason {
        self.reason
    }

    pub const fn diagnostic(&self) -> DiagnosticId {
        self.diagnostic
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FenceCompletionFailStopObservation {
    locator: SessionLocator,
    reason: FenceFailStopReason,
}

impl FenceCompletionFailStopObservation {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn reason(&self) -> FenceFailStopReason {
        self.reason
    }
}

#[allow(dead_code)]
pub struct FenceInitialResidualFailStopPacket {
    terminal: crate::session::TerminalSessionRef,
    outcome: AccumulatedTerminalResult,
    residual: FenceResidual,
    refused: FenceInitialPrepareRefusal,
    observation: FenceCompletionFailStopObservation,
    authority: PrivateFenceInitialResidualFailStopPacketAuthority,
}

impl FenceInitialResidualFailStopPacket {
    #[doc(hidden)]
    pub const fn observation(&self) -> FenceCompletionFailStopObservation {
        self.observation
    }
}

pub enum FenceResidualMergeFailStopInput {
    Initial {
        initial: FenceInitialLifecycleBinding,
        failed: FenceResidualMergeFailure,
    },
    Retry {
        run: FenceRetryRunRight,
        failed: FenceResidualMergeFailure,
    },
}

#[allow(dead_code)]
pub struct FenceResidualMergeFailStopPacket {
    terminal: crate::session::TerminalSessionRef,
    failure: FenceResidualMergeFailStopInput,
    observation: FenceCompletionFailStopObservation,
    authority: PrivateFenceResidualMergeFailStopPacketAuthority,
}

impl FenceResidualMergeFailStopPacket {
    #[doc(hidden)]
    pub const fn observation(&self) -> FenceCompletionFailStopObservation {
        self.observation
    }
}

#[allow(dead_code)]
pub struct FenceRetryDeferFailStopPacket {
    terminal: crate::session::TerminalSessionRef,
    outcome: AccumulatedTerminalResult,
    residual: FenceResidual,
    refused: FenceRetryDeferRefusal,
    observation: FenceCompletionFailStopObservation,
    authority: PrivateFenceRetryDeferFailStopPacketAuthority,
}

impl FenceRetryDeferFailStopPacket {
    #[doc(hidden)]
    pub const fn observation(&self) -> FenceCompletionFailStopObservation {
        self.observation
    }
}

pub enum FenceCompletionFailStopInput {
    InitialFinalize {
        initial: FenceInitialLifecycleBinding,
        failed: TerminalWinnerFinalizeFailure,
    },
    RetryFinalize {
        run: FenceRetryRunRight,
        failed: TerminalWinnerFinalizeFailure,
    },
    InitialLifecycle {
        refused: FenceInitialCompleteRefusal,
        prepared: PreparedTerminalWinnerFinalize,
    },
    RetryLifecycle {
        refused: FenceRetryCompleteRefusal,
        prepared: PreparedTerminalWinnerFinalize,
    },
}

#[allow(dead_code)]
pub struct FenceCompletionFailStopPacket {
    terminal: crate::session::TerminalSessionRef,
    failure: FenceCompletionFailStopInput,
    observation: FenceCompletionFailStopObservation,
    authority: PrivateFenceCompletionFailStopPacketAuthority,
}

impl FenceCompletionFailStopPacket {
    #[doc(hidden)]
    pub const fn observation(&self) -> FenceCompletionFailStopObservation {
        self.observation
    }
}

pub struct KernelFenceOps<D: FenceKernelDdi> {
    ddi: D,
    set: SessionRingSetBrand,
    diagnostic_failed_mask: u16,
    attempted_mask: u16,
    pass_start: FenceRetryKey,
    first_retry: Option<(FenceRetryPoint, PrivateFenceRetryCause)>,
    completed_consumers: Option<ConsumerFenceComplete>,
    pending_mount_bind: Option<PendingMountBind>,
    bound_mount: Option<BoundCompletedMountTeardown>,
    prefix: Option<ConsumerPrefix>,
    drain_proof: Option<DrainCompletedProof>,
    retire_proof: Option<RetireCompletedProof>,
    close_done: bool,
    signal_done: bool,
    wait_control_done: bool,
    unmap_producer_done: bool,
    wait_producer_done: bool,
    queue_done: bool,
    wait_pending_done: bool,
    unmap_readonly_done: bool,
    mdls_done: bool,
    process_done: bool,
    dismount_done: bool,
    consumer_release_next: Option<ConsumerReleaseNext>,
    consumer_resume: Option<ConsumerResumeEffect>,
}

impl<D: FenceKernelDdi> KernelFenceOps<D> {
    // The start-failure packet returns the DDI and the residual together so a
    // refused construction cannot drop either. Boxing it would need an allocator.
    #[allow(clippy::result_large_err)]
    pub fn try_new(ddi: D, set: SessionRingSetBrand) -> Result<Self, FenceRunnerStartFailure<D>> {
        let locator = set.locator();
        let start = crate::session::FenceEffect::CloseSessionAdmission;
        let mut ops = Self::blank(ddi, set, FenceRetryKey::Effect(start));
        ops.run_from(start);
        let _ = locator;
        Ok(ops)
    }

    // Same by-value start-failure packet as `try_new`: the DDI and residual
    // must come back together, and this crate has no allocator to box them.
    #[allow(clippy::result_large_err)]
    pub fn resume(
        ddi: D,
        set: SessionRingSetBrand,
        residual: FenceResidual,
    ) -> Result<Self, FenceRunnerStartFailure<D>> {
        if residual.set != set {
            let locator = set.locator();
            let retry = FenceRetryNeeded::from_invariant_refusal(
                locator,
                residual.retry.cursor_retry_key(),
                FenceFailStopReason::BrandMismatch,
            );
            let report = FencePassReport {
                locator,
                attempted_mask: 0,
                failed_mask: residual.failed_mask,
                authority: PrivateFencePassReportAuthority(()),
            };
            return Err(FenceRunnerStartFailure {
                ddi,
                incomplete: ResidualFenceRun {
                    report,
                    residual,
                    retry,
                },
            });
        }
        let pass_start = residual.retry.cursor_retry_key();
        let mut ops = Self::blank(ddi, set, pass_start);
        ops.diagnostic_failed_mask = residual.failed_mask;
        ops.completed_consumers = residual.completed_consumers;
        ops.pending_mount_bind = residual.pending_mount_bind;
        ops.bound_mount = residual.bound_mount;
        match residual.retry {
            FenceRetryPoint::Effect(effect) => ops.run_from(effect),
            FenceRetryPoint::ReleaseConsumersThen { prefix, next } => {
                ops.prefix = Some(prefix);
                ops.consumer_release_next = Some(next);
                ops.run_consumer_recovery();
            }
            FenceRetryPoint::ReacquireConsumersThen { prefix, resume } => {
                ops.prefix = Some(prefix);
                ops.consumer_resume = Some(resume);
                ops.run_consumer_recovery();
            }
        }
        Ok(ops)
    }

    pub const fn pass_start(&self) -> FenceRetryKey {
        self.pass_start
    }

    pub fn run_consumer_recovery(&mut self) {
        if let Some(next) = self.consumer_release_next.take() {
            self.release_then(next);
            return;
        }
        if let Some(resume) = self.consumer_resume.take() {
            self.reacquire_then(resume);
        }
    }

    pub fn finish(self) -> FenceRunOutcome<D> {
        let Self {
            ddi,
            set,
            diagnostic_failed_mask,
            attempted_mask,
            first_retry,
            completed_consumers,
            pending_mount_bind,
            bound_mount,
            prefix,
            drain_proof,
            retire_proof,
            ..
        } = self;
        let locator = set.locator();
        let report = FencePassReport {
            locator,
            attempted_mask,
            failed_mask: diagnostic_failed_mask,
            authority: PrivateFencePassReportAuthority(()),
        };
        let roster_complete = first_retry.is_none()
            && prefix.is_none()
            && pending_mount_bind.is_none()
            && drain_proof.is_none()
            && retire_proof.is_none()
            && report.is_complete();
        match (roster_complete, completed_consumers, bound_mount) {
            (true, Some(consumers), Some(mount)) => {
                let completed = package_completed_fence(CompletedFenceState {
                    set,
                    report,
                    completed_effect_mask: attempted_mask,
                    consumers,
                    mount: mount.into_prepared_deactivation(),
                    authority: PrivateCompletedFenceStateAuthority(()),
                });
                FenceRunOutcome::Complete { ddi, completed }
            }
            (_, completed_consumers, bound_mount) => {
                let (retry_point, cause) = match first_retry {
                    Some((point, cause)) => (point, cause),
                    None => {
                        let effect = KERNEL_FENCE_PASS_ORDER
                            .into_iter()
                            .find(|effect| attempted_mask & kernel_fence_bit(*effect) == 0)
                            .unwrap_or(crate::session::FenceEffect::ReleaseTransientBacking);
                        let restored = match prefix {
                            Some(prefix) => FenceRetryPoint::ReleaseConsumersThen {
                                prefix,
                                next: ConsumerReleaseNext::ReacquireThen(
                                    ConsumerResumeEffect::DrainStablePrefixesBounded,
                                ),
                            },
                            None => FenceRetryPoint::Effect(effect),
                        };
                        (
                            restored,
                            PrivateFenceRetryCause::Invariant(FenceFailStopReason::CoreInvariant),
                        )
                    }
                };
                let mut residual = match FenceResidual::try_new_fence_residual(
                    set,
                    diagnostic_failed_mask,
                    retry_point,
                    completed_consumers,
                    pending_mount_bind,
                ) {
                    Ok(residual) => residual,
                    Err((_, retry, completed_consumers, pending_mount_bind)) => FenceResidual {
                        set,
                        failed_mask: diagnostic_failed_mask,
                        retry,
                        completed_consumers,
                        pending_mount_bind,
                        bound_mount: None,
                    },
                };
                residual.bound_mount = bound_mount;
                let retry = match cause {
                    PrivateFenceRetryCause::TransientNative => {
                        FenceRetryNeeded::from_invoked_native_refusal(
                            locator,
                            residual.retry.cursor_retry_key(),
                        )
                    }
                    PrivateFenceRetryCause::Invariant(reason) => {
                        FenceRetryNeeded::from_invariant_refusal(
                            locator,
                            residual.retry.cursor_retry_key(),
                            reason,
                        )
                    }
                };
                FenceRunOutcome::Residual {
                    ddi,
                    incomplete: ResidualFenceRun {
                        report,
                        residual,
                        retry,
                    },
                }
            }
        }
    }

    fn blank(ddi: D, set: SessionRingSetBrand, pass_start: FenceRetryKey) -> Self {
        Self {
            ddi,
            set,
            diagnostic_failed_mask: 0,
            attempted_mask: 0,
            pass_start,
            first_retry: None,
            completed_consumers: None,
            pending_mount_bind: None,
            bound_mount: None,
            prefix: None,
            drain_proof: None,
            retire_proof: None,
            close_done: false,
            signal_done: false,
            wait_control_done: false,
            unmap_producer_done: false,
            wait_producer_done: false,
            queue_done: false,
            wait_pending_done: false,
            unmap_readonly_done: false,
            mdls_done: false,
            process_done: false,
            dismount_done: false,
            consumer_release_next: None,
            consumer_resume: None,
        }
    }

    fn run_from(&mut self, start: crate::session::FenceEffect) {
        let mut started = false;
        for effect in KERNEL_FENCE_PASS_ORDER {
            if effect == start {
                started = true;
            }
            if !started {
                self.mark_predecessor_satisfied(effect);
                continue;
            }
            if self.first_retry.is_some() {
                break;
            }
            self.dispatch_one(effect);
        }
    }

    fn mark_predecessor_satisfied(&mut self, effect: crate::session::FenceEffect) {
        // A residual resume begins mid-roster; predecessors are already done.
        match effect {
            crate::session::FenceEffect::CloseSessionAdmission => self.close_done = true,
            crate::session::FenceEffect::SignalPendingEnter => self.signal_done = true,
            crate::session::FenceEffect::WaitControlRundown => self.wait_control_done = true,
            crate::session::FenceEffect::RemoveProducerMappingsReverse => {
                self.unmap_producer_done = true
            }
            crate::session::FenceEffect::WaitProducerAndMappingCaptureRundown => {
                self.wait_producer_done = true
            }
            crate::session::FenceEffect::QueueInstalledWork => self.queue_done = true,
            crate::session::FenceEffect::WaitPendingAndOwners => self.wait_pending_done = true,
            crate::session::FenceEffect::ReleaseReadOnlyMappingsReverse => {
                self.unmap_readonly_done = true
            }
            crate::session::FenceEffect::ReleaseMdlsAndSystemView => self.mdls_done = true,
            crate::session::FenceEffect::ReleaseCapturedProcess => self.process_done = true,
            crate::session::FenceEffect::DismountAndDeleteDevices => self.dismount_done = true,
            _ => {}
        }
        self.attempted_mask |= kernel_fence_bit(effect);
    }

    fn dispatch_one(&mut self, effect: crate::session::FenceEffect) {
        if !self.prereq_ready(effect) {
            self.record_first_retry(
                FenceRetryPoint::Effect(effect),
                PrivateFenceRetryCause::Invariant(FenceFailStopReason::CoreInvariant),
            );
            return;
        }
        match effect {
            crate::session::FenceEffect::AcquireConsumersIncreasing => self.do_acquire(),
            crate::session::FenceEffect::DrainStablePrefixesBounded => self.do_drain(),
            crate::session::FenceEffect::RetireCredits => self.do_retire(),
            crate::session::FenceEffect::ReleaseConsumers => {
                let Some(proof) = self.retire_proof.take() else {
                    self.record_first_retry(
                        FenceRetryPoint::Effect(effect),
                        PrivateFenceRetryCause::Invariant(FenceFailStopReason::CoreInvariant),
                    );
                    return;
                };
                self.release_then(ConsumerReleaseNext::ContinueAtQueueInstalledWork(proof));
            }
            crate::session::FenceEffect::ReleaseTransientBacking => self.do_release_backing(),
            crate::session::FenceEffect::WaitPendingAndOwners => self.do_wait_pending(),
            crate::session::FenceEffect::DismountAndDeleteDevices => self.do_dismount(),
            other => self.do_simple(other),
        }
    }

    fn prereq_ready(&self, effect: crate::session::FenceEffect) -> bool {
        use crate::session::FenceEffect::*;
        match effect {
            CloseSessionAdmission | SignalPendingEnter => true,
            WaitControlRundown => self.close_done && self.signal_done,
            RemoveProducerMappingsReverse => self.wait_control_done,
            WaitProducerAndMappingCaptureRundown => self.unmap_producer_done,
            AcquireConsumersIncreasing => self.wait_producer_done,
            DrainStablePrefixesBounded => matches!(
                self.prefix.as_ref().map(ConsumerPrefix::prefix_phase),
                Some(ConsumerPrefixPhase::AcquiredComplete)
            ),
            RetireCredits => self.drain_proof.is_some() || self.prefix.is_some(),
            ReleaseConsumers => self.prefix.is_some(),
            QueueInstalledWork => self.signal_done,
            WaitPendingAndOwners => {
                self.queue_done && self.wait_control_done && self.completed_consumers.is_some()
            }
            ReleaseReadOnlyMappingsReverse => {
                self.wait_pending_done && self.completed_consumers.is_some()
            }
            ReleaseMdlsAndSystemView => self.unmap_readonly_done,
            ReleaseCapturedProcess => self.mdls_done,
            DismountAndDeleteDevices => self.process_done,
            ReleaseTransientBacking => {
                self.dismount_done && self.completed_consumers.is_some() && self.prefix.is_none()
            }
        }
    }

    fn do_simple(&mut self, effect: crate::session::FenceEffect) {
        self.attempted_mask |= kernel_fence_bit(effect);
        match execute_effect(self, effect) {
            Ok(()) => self.mark_simple_success(effect),
            Err(KernelFenceError::Native(_)) => self.record_native(effect),
            Err(KernelFenceError::Core(_)) => self.record_invariant(effect),
        }
    }

    fn mark_simple_success(&mut self, effect: crate::session::FenceEffect) {
        use crate::session::FenceEffect::*;
        match effect {
            CloseSessionAdmission => self.close_done = true,
            SignalPendingEnter => self.signal_done = true,
            WaitControlRundown => self.wait_control_done = true,
            RemoveProducerMappingsReverse => self.unmap_producer_done = true,
            WaitProducerAndMappingCaptureRundown => self.wait_producer_done = true,
            QueueInstalledWork => self.queue_done = true,
            WaitPendingAndOwners => self.wait_pending_done = true,
            ReleaseReadOnlyMappingsReverse => self.unmap_readonly_done = true,
            ReleaseMdlsAndSystemView => self.mdls_done = true,
            ReleaseCapturedProcess => self.process_done = true,
            DismountAndDeleteDevices => self.dismount_done = true,
            _ => {}
        }
    }

    fn do_acquire(&mut self) {
        let effect = crate::session::FenceEffect::AcquireConsumersIncreasing;
        if self.prefix.is_none() {
            match unsafe { self.ddi.native_take_consumer_slab() } {
                Ok(slab) => match ConsumerPrefix::begin_consumer_prefix(self.set, slab) {
                    Ok(prefix) => self.prefix = Some(prefix),
                    Err(_) => {
                        self.record_invariant(effect);
                        return;
                    }
                },
                Err(_) => {
                    self.record_native(effect);
                    return;
                }
            }
        }
        let Some(prefix) = self.prefix.as_mut() else {
            self.record_invariant(effect);
            return;
        };
        self.attempted_mask |= kernel_fence_bit(effect);
        match unsafe { self.ddi.native_acquire_consumers_increasing(prefix) } {
            Ok(()) => {
                if prefix.prefix_phase() != ConsumerPrefixPhase::AcquiredComplete {
                    self.park_release_for_rebuild(ConsumerResumeEffect::DrainStablePrefixesBounded);
                }
            }
            Err(_) => {
                let _ = prefix.record_failed_ring(prefix.next_acquire_ring().unwrap_or(0));
                self.park_release_for_rebuild(ConsumerResumeEffect::DrainStablePrefixesBounded);
            }
        }
    }

    fn do_drain(&mut self) {
        let effect = crate::session::FenceEffect::DrainStablePrefixesBounded;
        let Some(prefix) = self.prefix.take() else {
            self.record_invariant(effect);
            return;
        };
        match prefix.prepare_drain() {
            Ok(prepared) => {
                self.attempted_mask |= kernel_fence_bit(effect);
                match drain_stable_prefixes_with_proof(&mut self.ddi, prepared) {
                    Ok(drained) => {
                        let (prefix, proof) = drained.into_drained_parts();
                        self.prefix = Some(prefix);
                        self.drain_proof = Some(proof);
                    }
                    Err((_, prepared)) => {
                        self.prefix = Some(prepared.into_prefix());
                        self.park_release_for_rebuild(
                            ConsumerResumeEffect::DrainStablePrefixesBounded,
                        );
                    }
                }
            }
            Err((_, prefix)) => {
                self.prefix = Some(prefix);
                self.park_release_for_rebuild(ConsumerResumeEffect::DrainStablePrefixesBounded);
            }
        }
    }

    fn do_retire(&mut self) {
        let effect = crate::session::FenceEffect::RetireCredits;
        let (Some(prefix), Some(drain)) = (self.prefix.take(), self.drain_proof.take()) else {
            if let Some(prefix) = self.prefix.take() {
                self.prefix = Some(prefix);
            }
            self.record_invariant(effect);
            return;
        };
        let drained = DrainedConsumerPrefix::from_parts(prefix, drain);
        self.attempted_mask |= kernel_fence_bit(effect);
        match retire_credits_with_proof(&mut self.ddi, drained) {
            Ok(retired) => {
                let (prefix, proof) = retired.into_retired_parts();
                self.prefix = Some(prefix);
                self.retire_proof = Some(proof);
            }
            Err((_, drained)) => {
                let (prefix, drain) = drained.into_drained_parts();
                self.prefix = Some(prefix);
                self.park_release_for_rebuild(ConsumerResumeEffect::RetireCredits(drain));
            }
        }
    }

    fn do_wait_pending(&mut self) {
        let effect = crate::session::FenceEffect::WaitPendingAndOwners;
        if self.prefix.is_some() {
            self.record_first_retry(
                FenceRetryPoint::Effect(effect),
                PrivateFenceRetryCause::Invariant(FenceFailStopReason::CoreInvariant),
            );
            return;
        }
        self.attempted_mask |= kernel_fence_bit(effect);
        match unsafe { self.ddi.native_wait_pending_and_owner_rundown() } {
            Ok(()) => self.wait_pending_done = true,
            Err(PendingOwnerWaitFailure::Native(_)) => self.record_native(effect),
            Err(PendingOwnerWaitFailure::PublicationFailStop(witness)) => {
                self.record_first_retry(
                    FenceRetryPoint::Effect(effect),
                    PrivateFenceRetryCause::Invariant(FenceFailStopReason::PendingPublication(
                        witness,
                    )),
                );
            }
        }
    }

    fn do_dismount(&mut self) {
        let effect = crate::session::FenceEffect::DismountAndDeleteDevices;
        if let Some(bind) = self.pending_mount_bind.take() {
            self.pending_mount_bind = Some(bind);
            self.record_first_retry(
                FenceRetryPoint::Effect(effect),
                PrivateFenceRetryCause::Invariant(FenceFailStopReason::MountBindMismatch),
            );
            return;
        }
        self.attempted_mask |= kernel_fence_bit(effect);
        match unsafe { self.ddi.native_take_or_join_mount_and_delete() } {
            Ok(bound) => {
                self.bound_mount = Some(bound);
                self.dismount_done = true;
            }
            Err(MountTeardownCallError::Native(_)) => self.record_native(effect),
            Err(MountTeardownCallError::Bind(bind)) => {
                self.pending_mount_bind = Some(bind);
                self.record_first_retry(
                    FenceRetryPoint::Effect(effect),
                    PrivateFenceRetryCause::Invariant(FenceFailStopReason::MountBindMismatch),
                );
            }
        }
    }

    fn do_release_backing(&mut self) {
        let effect = crate::session::FenceEffect::ReleaseTransientBacking;
        let Some(complete) = self.completed_consumers.take() else {
            self.record_invariant(effect);
            return;
        };
        let (retired, proof) = complete.into_release_proof();
        self.attempted_mask |= kernel_fence_bit(effect);
        match unsafe { self.ddi.native_release_transient_arrays(proof) } {
            Ok(()) => {
                let _ = retired;
            }
            Err((_, proof)) => {
                if let Ok(complete) = ConsumerFenceComplete::pair(retired, proof) {
                    self.completed_consumers = Some(complete);
                }
                self.record_native(effect);
            }
        }
    }

    fn park_release_for_rebuild(&mut self, resume: ConsumerResumeEffect) {
        let Some(mut prefix) = self.prefix.take() else {
            return;
        };
        let _ = prefix.begin_release();
        self.record_first_retry(
            FenceRetryPoint::ReleaseConsumersThen {
                prefix,
                next: ConsumerReleaseNext::ReacquireThen(resume),
            },
            PrivateFenceRetryCause::TransientNative,
        );
    }

    fn release_then(&mut self, next: ConsumerReleaseNext) {
        let effect = crate::session::FenceEffect::ReleaseConsumers;
        let Some(mut prefix) = self.prefix.take() else {
            self.record_invariant(effect);
            return;
        };
        if !matches!(
            prefix.prefix_phase(),
            ConsumerPrefixPhase::ReleasingPartial
                | ConsumerPrefixPhase::ReleasingComplete
                | ConsumerPrefixPhase::ReleasedComplete
        ) {
            let _ = prefix.begin_release();
        }
        self.attempted_mask |= kernel_fence_bit(effect);
        match unsafe { self.ddi.native_release_consumers(&mut prefix) } {
            Ok(()) => match prefix.finish_release() {
                ConsumerReleaseOutcome::Complete(released) => match next {
                    ConsumerReleaseNext::ContinueAtQueueInstalledWork(retired) => {
                        match ConsumerFenceComplete::pair(retired, released) {
                            Ok(complete) => {
                                self.completed_consumers = Some(complete);
                                self.queue_done = self.signal_done;
                                self.run_from(crate::session::FenceEffect::QueueInstalledWork);
                            }
                            Err(_) => self.record_invariant(effect),
                        }
                    }
                    ConsumerReleaseNext::ReacquireThen(resume) => {
                        let prefix = released.restart_from_complete();
                        self.prefix = Some(prefix);
                        self.reacquire_then(resume);
                    }
                },
                ConsumerReleaseOutcome::Partial(partial) => match next {
                    ConsumerReleaseNext::ReacquireThen(resume) => {
                        self.prefix = Some(partial.restart_released_partial());
                        self.reacquire_then(resume);
                    }
                    ConsumerReleaseNext::ContinueAtQueueInstalledWork(_) => {
                        self.prefix = Some(partial.restart_released_partial());
                        self.record_invariant(effect);
                    }
                },
            },
            Err(_) => {
                let _ = prefix.park_partial_release();
                self.record_first_retry(
                    FenceRetryPoint::ReleaseConsumersThen { prefix, next },
                    PrivateFenceRetryCause::TransientNative,
                );
            }
        }
    }

    fn reacquire_then(&mut self, resume: ConsumerResumeEffect) {
        self.consumer_resume = None;
        self.do_acquire();
        if self.first_retry.is_some() {
            return;
        }
        match resume {
            ConsumerResumeEffect::DrainStablePrefixesBounded => {
                self.do_drain();
                if self.first_retry.is_none() {
                    self.do_retire();
                    if self.first_retry.is_none() {
                        if let Some(proof) = self.retire_proof.take() {
                            self.release_then(ConsumerReleaseNext::ContinueAtQueueInstalledWork(
                                proof,
                            ));
                        }
                    }
                }
            }
            ConsumerResumeEffect::RetireCredits(drain) => {
                self.drain_proof = Some(drain);
                self.do_retire();
                if self.first_retry.is_none() {
                    if let Some(proof) = self.retire_proof.take() {
                        self.release_then(ConsumerReleaseNext::ContinueAtQueueInstalledWork(proof));
                    }
                }
            }
        }
    }

    fn record_native(&mut self, effect: crate::session::FenceEffect) {
        self.diagnostic_failed_mask |= kernel_fence_bit(effect);
        self.record_first_retry(
            FenceRetryPoint::Effect(effect),
            PrivateFenceRetryCause::TransientNative,
        );
    }

    fn record_invariant(&mut self, effect: crate::session::FenceEffect) {
        self.record_first_retry(
            FenceRetryPoint::Effect(effect),
            PrivateFenceRetryCause::Invariant(FenceFailStopReason::CoreInvariant),
        );
    }

    fn record_first_retry(&mut self, point: FenceRetryPoint, cause: PrivateFenceRetryCause) {
        if self.first_retry.is_none() {
            self.first_retry = Some((point, cause));
        }
    }
}

impl<D: FenceKernelDdi> FenceNativeOps for KernelFenceOps<D> {
    type Error = KernelFenceError<D::Error>;

    fn close_session_admission(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_close_generation_admission() }.map_err(KernelFenceError::Native)
    }
    fn signal_pending_enter(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_schedule_linked_pending() }.map_err(KernelFenceError::Native)
    }
    fn wait_control_rundown(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_wait_control_and_access_rundown() }
            .map_err(KernelFenceError::Native)
    }
    fn remove_producer_mappings_reverse(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_unmap_producer_aliases_reverse() }
            .map_err(KernelFenceError::Native)
    }
    fn wait_producer_and_mapping_capture_rundown(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_wait_producer_capture_rundown() }.map_err(KernelFenceError::Native)
    }
    fn acquire_consumers_increasing(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn drain_stable_prefixes_bounded(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn retire_credits(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn release_consumers(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn queue_installed_work(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_queue_installed_work() }.map_err(KernelFenceError::Native)
    }
    fn wait_pending_and_owners(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn release_read_only_mappings_reverse(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_unmap_readonly_aliases_reverse() }
            .map_err(KernelFenceError::Native)
    }
    fn release_mdls_and_system_view(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_release_mdls_and_system_view() }.map_err(KernelFenceError::Native)
    }
    fn release_captured_process(&mut self) -> Result<(), Self::Error> {
        unsafe { self.ddi.native_dereference_process() }.map_err(KernelFenceError::Native)
    }
    fn dismount_and_delete_devices(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn release_transient_backing(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl FenceRetryLifecycle {
    fn fail_stop_observation(
        &self,
        reason: FenceFailStopReason,
    ) -> FenceCompletionFailStopObservation {
        FenceCompletionFailStopObservation {
            locator: self.locator,
            reason,
        }
    }

    fn classify_lifecycle_error(error: LifecycleError) -> FenceFailStopReason {
        match error {
            LifecycleError::WrongLocator => FenceFailStopReason::BrandMismatch,
            _ => FenceFailStopReason::CoreInvariant,
        }
    }

    #[doc(hidden)]
    pub fn bind_residual_merge_fail_stop(
        &self,
        terminal: crate::session::TerminalSessionRef,
        failure: FenceResidualMergeFailStopInput,
    ) -> FenceResidualMergeFailStopPacket {
        let reason = match &failure {
            FenceResidualMergeFailStopInput::Initial { failed, .. }
            | FenceResidualMergeFailStopInput::Retry { failed, .. } => match failed.error {
                FenceError::RetryBrandMismatch | FenceError::WrongRingSet => {
                    FenceFailStopReason::BrandMismatch
                }
                _ => FenceFailStopReason::CoreInvariant,
            },
        };
        FenceResidualMergeFailStopPacket {
            terminal,
            failure,
            observation: self.fail_stop_observation(reason),
            authority: PrivateFenceResidualMergeFailStopPacketAuthority(()),
        }
    }

    #[doc(hidden)]
    pub fn bind_initial_residual_fail_stop(
        &self,
        terminal: crate::session::TerminalSessionRef,
        outcome: AccumulatedTerminalResult,
        residual: FenceResidual,
        refused: FenceInitialPrepareRefusal,
    ) -> FenceInitialResidualFailStopPacket {
        let reason = Self::classify_lifecycle_error(refused.error());
        FenceInitialResidualFailStopPacket {
            terminal,
            outcome,
            residual,
            refused,
            observation: self.fail_stop_observation(reason),
            authority: PrivateFenceInitialResidualFailStopPacketAuthority(()),
        }
    }

    #[doc(hidden)]
    pub fn bind_retry_defer_fail_stop(
        &self,
        terminal: crate::session::TerminalSessionRef,
        outcome: AccumulatedTerminalResult,
        residual: FenceResidual,
        refused: FenceRetryDeferRefusal,
    ) -> FenceRetryDeferFailStopPacket {
        let reason = Self::classify_lifecycle_error(refused.error());
        FenceRetryDeferFailStopPacket {
            terminal,
            outcome,
            residual,
            refused,
            observation: self.fail_stop_observation(reason),
            authority: PrivateFenceRetryDeferFailStopPacketAuthority(()),
        }
    }

    #[doc(hidden)]
    pub fn bind_completion_fail_stop(
        &self,
        terminal: crate::session::TerminalSessionRef,
        failure: FenceCompletionFailStopInput,
    ) -> FenceCompletionFailStopPacket {
        let reason = match &failure {
            FenceCompletionFailStopInput::InitialFinalize { failed, .. }
            | FenceCompletionFailStopInput::RetryFinalize { failed, .. } => match failed.error {
                FenceError::RetryBrandMismatch | FenceError::WrongRingSet => {
                    FenceFailStopReason::BrandMismatch
                }
                _ => FenceFailStopReason::CoreInvariant,
            },
            FenceCompletionFailStopInput::InitialLifecycle { refused, .. } => {
                Self::classify_lifecycle_error(refused.error())
            }
            FenceCompletionFailStopInput::RetryLifecycle { refused, .. } => {
                Self::classify_lifecycle_error(refused.error())
            }
        };
        FenceCompletionFailStopPacket {
            terminal,
            failure,
            observation: self.fail_stop_observation(reason),
            authority: PrivateFenceCompletionFailStopPacketAuthority(()),
        }
    }
}

#[cfg(test)]
mod tests;
