//! WDK-free lifecycle, terminal-scan, and mount-rendezvous decisions.

use core::{
    marker::PhantomData,
    num::NonZeroU64,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::adapter::enter::{
    EnterProgress, EnterRollbackProgress, PendingRoleRelease, PendingRollbackRoleRelease,
};
use crate::enter::{EnterError, EnterRole, RingEnterState, RoleLease};
use crate::session::{
    SessionLocator, StrongSessionRef, TerminalBlocked, TerminalRendezvousOutcome, TerminalResult,
};
use fsring_abi::validate::SessionIdentity;

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug)]
            struct $name(());
        )+
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCellPhase {
    Free,
    Staging,
    Live,
    Removing,
    Deleting,
    Retired,
}

/// Authenticate the native mirror immediately before destructive deletion.
///
/// This pure decision is shared with the WDK-backed permanent cell so the
/// required `Deleting` phase is covered by ordinary host tests.
pub fn native_delete_mirror_matches(
    phase: NativeCellPhase,
    generation: u64,
    identity: Option<SessionIdentity>,
    shell_present: bool,
    requested: SessionLocator,
) -> bool {
    phase == NativeCellPhase::Deleting
        && generation == requested.generation()
        && identity == Some(requested.identity())
        && shell_present
}

/// The process observation stored in one permanent native cell.
///
/// There is intentionally no session address here. A process-loss scan can
/// compare this record while the registry lock is held and carry only the
/// locator out of that lock hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeCellProcessObservation<P> {
    pub recorded_process: Option<P>,
    pub phase: NativeCellPhase,
    pub published_locator: Option<SessionLocator>,
}

/// Compare a process-loss arrival with the permanent cell's own observation.
pub fn observe_cell_process<P: PartialEq>(
    observed: &NativeCellProcessObservation<P>,
    requested_process: P,
) -> Option<SessionLocator> {
    if observed.recorded_process.as_ref() != Some(&requested_process) {
        return None;
    }
    if !matches!(
        observed.phase,
        NativeCellPhase::Live | NativeCellPhase::Removing | NativeCellPhase::Deleting
    ) {
        return None;
    }
    observed.published_locator
}

/// The two authentic native owner slots and their shell-mirror relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeOwnerSlotObservation {
    pub shell_locator: Option<SessionLocator>,
    pub root_locator: Option<SessionLocator>,
    pub shell_matches_mirror: bool,
}

/// The only shared operations a published native shell exposes through its
/// affine core owner. Every checkpoint operation is named: neither the owner
/// nor its native payload exposes a generic effect dispatcher or an address.
pub trait NativeSessionSharedOps {
    type Mirror: Copy;

    fn matches_mirror(&self, mirror: Self::Mirror) -> bool;
    fn checkpoint_close_session_admission(&self) -> bool;
    fn checkpoint_signal_existing_enter_waiters(&self) -> bool;
    fn checkpoint_wait_existing_sq_cq_roles_and_consumers(&self) -> bool;
    fn checkpoint_remove_producer_mappings_reverse(&self) -> bool;
    fn checkpoint_wait_producer_and_mapping_capture_rundown(&self) -> bool;
    fn checkpoint_retire_existing_grant_and_credit_state(&self) -> bool;
    /// The second half of `SignalPendingEnter`: deposit a Fence wake in every
    /// installed pending context, after the carried waiter wake and before
    /// either rundown wait.
    fn checkpoint_deposit_pending_fence_wakes(&self) -> bool;
    /// Take every ring's consumer, in increasing ring order.
    fn checkpoint_acquire_consumers_increasing(&self) -> bool;
    fn checkpoint_release_consumers(&self) -> bool;
    /// Turn each stored HandoffDone wake into at most one queued Worker owner.
    fn checkpoint_queue_installed_work(&self) -> bool;
    /// Wait every Active context out. Real execution, not an observation.
    fn checkpoint_wait_pending_and_owners(&self) -> bool;
    fn checkpoint_release_read_only_mappings_reverse(&self) -> bool;
    fn checkpoint_release_mdls_and_system_view(&self) -> bool;
    fn checkpoint_release_captured_process(&self) -> bool;
    fn checkpoint_release_transient_arrays_and_backing(&self) -> bool;
    fn checkpoint_delete_vdo_once(&self) -> bool;
}

/// Core-owned affine envelope for the native session allocation.
///
/// This WDK-free shape deliberately exposes neither a constructor nor its
/// payload. Task 3's consuming setup transition is the sole minting path; a raw
/// address or copied locator without the install-minted bind right is not
/// ownership authority.
pub struct NativeSessionOwner<Shell> {
    locator: SessionLocator,
    payload: Shell,
}

/// Core-owned affine authority for the session's one driver-root release.
///
/// The payload remains opaque to core and has no public constructor or
/// projection. Task 3's setup transition consumes the install-minted bind
/// right to bind it to the exact locator.
pub struct SessionRootReleaseRight<RootRelease> {
    locator: SessionLocator,
    payload: RootRelease,
}

/// Consume the install-minted right and the allocation-origin payload.
#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
pub(crate) fn bind_native_session_owner<Shell>(
    right: crate::session::NativeSessionOwnerBindRight,
    payload: Shell,
) -> NativeSessionOwner<Shell> {
    NativeSessionOwner {
        locator: right.into_locator(),
        payload,
    }
}

/// Consume the install-minted right and the already-acquired root payload.
#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
pub(crate) fn bind_session_root_release<RootRelease>(
    right: crate::session::SessionRootReleaseBindRight,
    payload: RootRelease,
) -> SessionRootReleaseRight<RootRelease> {
    SessionRootReleaseRight {
        locator: right.into_locator(),
        payload,
    }
}

impl<Shell> NativeSessionOwner<Shell> {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

impl<Shell: NativeSessionSharedOps> NativeSessionOwner<Shell> {
    pub fn matches_mirror(&self, mirror: Shell::Mirror) -> bool {
        self.payload.matches_mirror(mirror)
    }

    pub fn checkpoint_close_session_admission(&self) -> bool {
        self.payload.checkpoint_close_session_admission()
    }

    pub fn checkpoint_signal_existing_enter_waiters(&self) -> bool {
        self.payload.checkpoint_signal_existing_enter_waiters()
    }

    pub fn checkpoint_wait_existing_sq_cq_roles_and_consumers(&self) -> bool {
        self.payload
            .checkpoint_wait_existing_sq_cq_roles_and_consumers()
    }

    pub fn checkpoint_remove_producer_mappings_reverse(&self) -> bool {
        self.payload.checkpoint_remove_producer_mappings_reverse()
    }

    pub fn checkpoint_wait_producer_and_mapping_capture_rundown(&self) -> bool {
        self.payload
            .checkpoint_wait_producer_and_mapping_capture_rundown()
    }

    pub fn checkpoint_retire_existing_grant_and_credit_state(&self) -> bool {
        self.payload
            .checkpoint_retire_existing_grant_and_credit_state()
    }

    pub fn checkpoint_deposit_pending_fence_wakes(&self) -> bool {
        self.payload.checkpoint_deposit_pending_fence_wakes()
    }

    pub fn checkpoint_acquire_consumers_increasing(&self) -> bool {
        self.payload.checkpoint_acquire_consumers_increasing()
    }

    pub fn checkpoint_release_consumers(&self) -> bool {
        self.payload.checkpoint_release_consumers()
    }

    pub fn checkpoint_queue_installed_work(&self) -> bool {
        self.payload.checkpoint_queue_installed_work()
    }

    pub fn checkpoint_wait_pending_and_owners(&self) -> bool {
        self.payload.checkpoint_wait_pending_and_owners()
    }

    pub fn checkpoint_release_read_only_mappings_reverse(&self) -> bool {
        self.payload.checkpoint_release_read_only_mappings_reverse()
    }

    pub fn checkpoint_release_mdls_and_system_view(&self) -> bool {
        self.payload.checkpoint_release_mdls_and_system_view()
    }

    pub fn checkpoint_release_captured_process(&self) -> bool {
        self.payload.checkpoint_release_captured_process()
    }

    pub fn checkpoint_release_transient_arrays_and_backing(&self) -> bool {
        self.payload
            .checkpoint_release_transient_arrays_and_backing()
    }

    pub fn checkpoint_delete_vdo_once(&self) -> bool {
        self.payload.checkpoint_delete_vdo_once()
    }
}

impl<RootRelease> SessionRootReleaseRight<RootRelease> {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

/// Invoke the one non-returning native payload consumer while keeping owner
/// fields private to their defining module.
pub(in crate::adapter) unsafe fn execute_prepared_delete_payloads<Shell, RootRelease>(
    shell: NativeSessionOwner<Shell>,
    root: SessionRootReleaseRight<RootRelease>,
    permit: &crate::adapter::fence::PreparedDeleteExecutionPermit,
) where
    Shell: crate::adapter::fence::PreparedDeleteStorageOps<RootRelease>,
{
    let NativeSessionOwner {
        locator: shell_locator,
        payload: shell,
    } = shell;
    let SessionRootReleaseRight {
        locator: root_locator,
        payload: root,
    } = root;
    if shell_locator != root_locator {
        unreachable!("prepared storage was branded for one locator")
    }
    unsafe { shell.destroy_shell_then_release_root(root, permit) };
}

/// Accept only two present owners branded for the exact requested generation.
pub fn native_owner_slots_match(
    requested: SessionLocator,
    observed: NativeOwnerSlotObservation,
) -> bool {
    observed.shell_locator == Some(requested)
        && observed.root_locator == Some(requested)
        && observed.shell_matches_mirror
}

/// A live shell projection shared by any number of access-rundown guards.
///
/// The wrapper deliberately has no mutable projection. Multiple successful
/// locators may refer to the same live generation, so manufacturing `&mut T`
/// from any one of them would alias every other access guard.
pub struct SharedSessionProjection<'access, T: ?Sized> {
    pointer: NonNull<T>,
    marker: PhantomData<&'access T>,
}

// The impl header is frozen by the Task 12 grammar, so the lifetime stays
// named rather than elided.
#[allow(clippy::needless_lifetimes)]
impl<'access, T: ?Sized> SharedSessionProjection<'access, T> {
    /// Bind a non-null live-shell address to its access-rundown lifetime.
    ///
    /// # Safety
    /// `pointer` remains valid and immutable for `'access`. Interior mutation
    /// requires its own lock and is not authorized by this wrapper.
    pub unsafe fn from_non_null(pointer: NonNull<T>) -> Self {
        Self {
            pointer,
            marker: PhantomData,
        }
    }

    pub fn get(&self) -> &T {
        // SAFETY: the constructor's contract binds validity to `'access` and
        // this API exposes only a shared reference.
        unsafe { self.pointer.as_ref() }
    }
}

/// A ring ENTER state projected only for fixed, non-waiting transitions.
///
/// It exposes no raw state/reference getter. The native adapter still owes the
/// structural rule that it must not call a wait while this value is live; the
/// type enforces the complementary no-escape and disjoint-state rules.
pub struct LockedEnterState<'lock> {
    state: &'lock mut RingEnterState,
}

impl<'lock> LockedEnterState<'lock> {
    pub fn from_locked(state: &'lock mut RingEnterState) -> Self {
        Self { state }
    }

    pub fn acquire_role(
        &mut self,
        invocation: u64,
        role: EnterRole,
    ) -> Result<RoleLease, EnterError> {
        self.state.acquire_role(invocation, role)
    }

    pub fn release_role(&mut self, lease: RoleLease) -> Result<(), (EnterError, RoleLease)> {
        self.state.release_role(lease)
    }

    #[allow(clippy::result_large_err)]
    pub fn release_pending<'g>(
        &mut self,
        pending: PendingRoleRelease<'g>,
    ) -> Result<EnterProgress<'g>, (EnterError, PendingRoleRelease<'g>)> {
        pending.release(self.state)
    }

    #[allow(clippy::result_large_err)]
    pub fn release_rollback(
        &mut self,
        pending: PendingRollbackRoleRelease,
    ) -> Result<EnterRollbackProgress, (EnterError, PendingRollbackRoleRelease)> {
        pending.release(self.state)
    }
}

/// Affine proof that the initialization callback ran once for every ring.
#[derive(Debug)]
pub struct InitializedRingLocks {
    ring_count: u32,
}

impl InitializedRingLocks {
    pub const fn ring_count(&self) -> u32 {
        self.ring_count
    }
}

/// Run the production-supplied lock initializer over the complete ring set.
pub fn initialize_ring_locks(
    ring_count: u32,
    mut initialize: impl FnMut(u32),
) -> InitializedRingLocks {
    for index in 0..ring_count {
        initialize(index);
    }
    InitializedRingLocks { ring_count }
}

/// The exact IRQL returned by one ring-lock acquire.
pub struct SavedIrql<I> {
    value: Option<I>,
}

pub fn acquire_saved_irql<I>(acquire: impl FnOnce() -> I) -> SavedIrql<I> {
    SavedIrql {
        value: Some(acquire()),
    }
}

impl<I> SavedIrql<I> {
    /// Consume the saved value into the one matching release.
    pub fn release_with(mut self, release: impl FnOnce(I)) {
        if let Some(value) = self.value.take() {
            release(value);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    WrongLocator,
    WrongState,
    GenerationExhausted,
    AdmissionClosed,
    JoinerOverflow,
    JoinerUnderflow,
    FinalizerBusy,
    MountBusy,
    Invariant,
}

use crate::adapter::enter::ValidatedCompletion;
use crate::session::{CoreTerminalDisposition, TerminalJoinTicket, TerminalWinner};
use fsring_abi::control::status;

/// Why a committed protocol abort could not become a terminal claim.
///
/// Every variant describes something observed **after** the CQ head advanced and
/// the consumer role was released, so none of them is recoverable and none is an
/// error return. They exist to be reported, once, through
/// [`complete_protocol_reject`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolRejectReason {
    /// The cell moved to a later generation before the registry lock.
    StaleGeneration,
    /// The cell has no live generation at all.
    NoActiveGeneration,
    /// The cell is not in a phase a terminal claim can start from.
    CellPhaseMismatch,
    /// The completion identity does not match the arrival.
    CompletionIdentityMismatch,
    /// The control owner a terminal claim needs is gone.
    MissingControlOwner,
    /// A finalizer deposit is already occupied.
    DepositOccupied,
    /// The control binding names a different session.
    BindingMismatch,
    /// The stream brand does not match the cell the lease names.
    ProtocolBrandMismatch,
    /// The terminal rendezvous cannot admit a joiner.
    JoinGuardUnavailable,
    /// A lifecycle rule refused, carrying its own reason.
    Lifecycle(LifecycleError),
}

/// Proof that a committed protocol abort was reported and nothing else.
///
/// It is what a reject branch produces, and it carries the sealed authority that
/// says the consumer role was **already released** before the registry lock was
/// taken. That matters more than the reason: without it a reject would be
/// indistinguishable from "nothing happened", and a caller could reasonably
/// release the role a second time.
///
/// There is no constructor outside this module and no way to read the seal, so
/// safe code can neither fabricate a receipt nor turn one back into an arrival.
#[must_use = "a rejected protocol arrival must still complete its request"]
#[derive(Debug)]
pub struct ProtocolRejectReceipt {
    reason: ProtocolRejectReason,
    // Never read: the seal exists so no caller outside this module can build a
    // receipt claiming a release that did not happen.
    #[allow(dead_code)]
    authority: PrivateReleasedCommittedProtocolAuthority,
}

#[allow(dead_code)]
impl ProtocolRejectReceipt {
    pub const fn reason(&self) -> ProtocolRejectReason {
        self.reason
    }
}

/// Mint the one receipt a rejected arrival produces.
///
/// Crate-private and consuming: the record is the proof that the head advanced
/// and the role was released, and a reject spends it. A branch that could mint a
/// receipt without consuming the record could report a reject for an arrival
/// that never committed.
#[allow(dead_code)]
pub(crate) fn reject_committed_protocol(
    reason: ProtocolRejectReason,
    record: crate::adapter::enter::CommittedProtocolRecord,
) -> ProtocolRejectReceipt {
    // The record is consumed rather than stored: everything a reject reports is
    // the reason, and retaining the arrival would let a later branch act on an
    // abort that has already been answered.
    let _ = record;
    ProtocolRejectReceipt {
        reason,
        authority: PrivateReleasedCommittedProtocolAuthority(()),
    }
}

/// Complete a rejected protocol arrival: invalid device state, zero information.
///
/// Deterministic and total. The reason is deliberately *not* mapped onto
/// distinct statuses: every one of them describes a session that stopped being
/// usable between the abort and the registry lock, and a caller that could tell
/// them apart from the wire would be reading kernel scheduling into a status
/// code. The receipt is consumed, so one arrival completes once.
#[allow(dead_code)]
pub fn complete_protocol_reject(receipt: ProtocolRejectReceipt) -> ValidatedCompletion {
    let ProtocolRejectReceipt { reason, authority } = receipt;
    let _ = reason;
    let _ = authority;
    ValidatedCompletion::prepare(status::INVALID_DEVICE_STATE, 0, 0, 0)
        .unwrap_or_else(|error| unreachable!("a zero-length failure always validates: {error:?}"))
}

/// What a committed protocol arrival became.
///
/// Hidden-public only because `fsring-fsd` is a separate crate. Every payload is
/// an opaque wrapper with private fields, so `-D warnings` sees no private
/// interface and safe downstream code sees neither a raw `TerminalJoinTicket`
/// nor a `RegistryLease` nor the committed record.
#[doc(hidden)]
#[must_use = "a committed protocol arrival must be routed or completed"]
pub enum CommittedProtocolTerminalDisposition {
    /// This arrival won the terminal for its generation.
    ///
    /// The work authorities and the generation join are **separate payloads**.
    /// A winner still holds a join against its own generation, and handing both
    /// out inside one `CoreTerminalWinner` would force the caller to take a bare
    /// `TerminalJoinTicket` out of it in order to reach the work -- which is
    /// exactly what every other arm is sealed against.
    Winner {
        work: CommittedProtocolTerminalWork,
        join: CommittedProtocolJoin,
    },
    /// Another source won; this arrival joined it.
    Join(CommittedProtocolJoin),
    /// The terminal had already completed; the result is copied.
    Completed(CommittedProtocolCompleted),
    /// Nothing could be claimed, and the consumer was already released.
    Reject(ProtocolRejectReceipt),
}

/// The winner's two work authorities, and nothing else.
///
/// Deliberately not a `CoreTerminalWinner`: that carries the join ticket too.
#[doc(hidden)]
#[must_use]
pub struct CommittedProtocolTerminalWork {
    winner: TerminalWinner,
    terminal: crate::session::TerminalSessionRef,
}

/// A joiner's ticket, sealed.
///
/// No accessor yields the ticket. The only consuming routes are
/// [`CommittedProtocolJoin::release_protocol_join`] and
/// [`CommittedProtocolJoin::release_opaque_protocol_join`], and neither hands
/// the ticket out on any arm -- an open release returns this wrapper again, and
/// a refusal returns it unchanged. So no sequence of safe calls turns a protocol
/// arrival into a bare `TerminalJoinTicket`.
#[doc(hidden)]
#[must_use = "an unreleased protocol join still counts against its generation"]
pub struct CommittedProtocolJoin {
    ticket: TerminalJoinTicket,
}

/// A copied terminal result.
#[doc(hidden)]
#[must_use]
pub struct CommittedProtocolCompleted {
    result: TerminalResult,
}

/// What releasing a protocol join decided.
///
/// Not [`crate::session::TerminalJoinRelease`]: its `Open` arm returns a bare
/// `TerminalJoinTicket`. Here `Open` returns the same sealed wrapper, so a
/// caller that has to wait and retry still holds nothing it could join a second
/// generation with.
#[doc(hidden)]
#[must_use = "an open release still owns the join"]
pub enum CommittedProtocolJoinRelease {
    /// The generation is still open; the join is unchanged.
    Open(CommittedProtocolJoin),
    /// The generation closed. `drained` is minted at most once, for whichever
    /// arrival took the last admitted count.
    Released {
        outcome: crate::session::TerminalClosedOutcome,
        drained: Option<crate::session::TerminalJoinersDrainedSignal>,
    },
}

#[allow(dead_code)]
impl CommittedProtocolTerminalWork {
    /// Consume into exactly the two authorities Task 9's terminal work takes.
    #[doc(hidden)]
    pub fn into_terminal_authorities(self) -> (TerminalWinner, crate::session::TerminalSessionRef) {
        (self.winner, self.terminal)
    }
}

#[allow(dead_code)]
impl CommittedProtocolJoin {
    /// Release this join against the rendezvous that admitted it.
    ///
    /// Consuming, and the ticket never leaves the wrapper on any arm: open puts
    /// it straight back inside one, and a refusal returns the wrapper together
    /// with the rule that refused. A caller cannot obtain a bare ticket by
    /// handling the error.
    ///
    /// **Named `release_protocol_join`, not `release`.** `release` has 23
    /// definitions across the two source roots, so a staged row on it would
    /// merge unrelated bodies and report a production route that does not
    /// exist. Same reason as `commit_protocol_abort` and
    /// `commit_protocol_claim`.
    #[doc(hidden)]
    pub fn release_protocol_join(
        self,
        rendezvous: &mut crate::session::TerminalRendezvous,
    ) -> Result<CommittedProtocolJoinRelease, (LifecycleError, Self)> {
        use crate::session::TerminalJoinRelease;
        match rendezvous.release(self.ticket) {
            Ok(TerminalJoinRelease::Open(ticket)) => {
                Ok(CommittedProtocolJoinRelease::Open(Self { ticket }))
            }
            Ok(TerminalJoinRelease::Released { outcome, drained }) => {
                Ok(CommittedProtocolJoinRelease::Released { outcome, drained })
            }
            Err((error, ticket)) => Err((error, Self { ticket })),
        }
    }

    /// The opaque-retained counterpart, for a generation whose fail-stop is
    /// visible only through its slot receipt.
    ///
    /// The ordinary release cannot serve here: an opaque generation deliberately
    /// never signals the terminal-outcome event, so its admitted count is drawn
    /// down through the retained slot instead. A refusal returns the wrapper,
    /// for the same reason as above.
    #[doc(hidden)]
    pub fn release_opaque_protocol_join(
        self,
        rendezvous: &mut crate::session::TerminalRendezvous,
    ) -> Result<Option<crate::session::TerminalJoinersDrainedSignal>, Self> {
        match rendezvous.release_opaque_retained(self.ticket) {
            Ok(drained) => Ok(drained),
            Err(ticket) => Err(Self { ticket }),
        }
    }
}

#[allow(dead_code)]
impl CommittedProtocolCompleted {
    #[doc(hidden)]
    pub fn into_result(self) -> TerminalResult {
        self.result
    }
}

/// One protocol arrival, preflighted against the exact four lifecycle objects.
///
/// It holds Task 9's prepared claim when there is one to hold, and the record
/// in either case: the record is what proves the head advanced and the role was
/// released, and every arm consumes it exactly once.
#[doc(hidden)]
#[must_use = "a prepared protocol terminal claim must be committed"]
pub struct PreparedProtocolTerminalClaim<'objects, const N: usize> {
    state: PreparedProtocolState<'objects, N>,
    record: crate::adapter::enter::CommittedProtocolRecord,
}

// The Claim arm keeps the four exclusive borrows that make a second arrival
// unnameable. Boxing it would need an allocator this crate does not have.
#[allow(clippy::large_enum_variant)]
enum PreparedProtocolState<'objects, const N: usize> {
    /// The claim Task 9's aggregate preflighted, still holding its four borrows.
    Claim(crate::session::PreparedTerminalClaim<'objects, N>),
    /// Nothing to claim. The four objects were left exactly as they were.
    Reject(ProtocolRejectReason),
}

/// Preflight a committed protocol arrival against the exact lifecycle objects.
///
/// **The locator is the arrival's, never an argument.** It comes from
/// `CommittedProtocolAbort::authenticated_locator`, which delegates to the
/// private CQ stream brand -- so the only session this can claim a terminal for
/// is the one whose ring the abort was drained from. A caller-supplied locator
/// would make a cross-session claim a matter of getting one argument right.
///
/// Preparation mutates nothing. A refusal from Task 9's preflight becomes the
/// Reject arm carrying its `LifecycleError`, and the four objects -- registry,
/// binding, rendezvous and lease slot -- are left byte-for-byte as they were.
/// Turn a native-side preflight refusal into a prepared typed reject.
///
/// The native aggregate observes things core cannot -- cell phase, generation
/// word, control owner, deposit occupancy -- and any of them can refuse after
/// the CQ head has already advanced. It may not mint a receipt itself:
/// `reject_committed_protocol` is crate-private to `fsring-core` precisely so
/// that a receipt cannot exist for an arrival nobody claimed.
///
/// So the refusal comes back through here, and it takes the same four exclusive
/// borrows the claim would have: the reject is minted under the same exclusive
/// access, so no second arrival can be mid-claim on this generation while this
/// one is being answered. Nothing is mutated -- the reject arm of the returned
/// value carries only the reason.
#[doc(hidden)]
#[allow(dead_code)]
pub fn prepare_protocol_terminal_reject<'objects, const N: usize>(
    registry: &'objects mut crate::session::SessionRegistry<N>,
    binding: &'objects mut crate::session::ControlBinding,
    rendezvous: &'objects mut crate::session::TerminalRendezvous,
    lease: &'objects mut Option<crate::session::RegistryLease>,
    reason: ProtocolRejectReason,
    committed: crate::adapter::enter::CommittedProtocolAbort,
) -> PreparedProtocolTerminalClaim<'objects, N> {
    // The four borrows are held by the returned value's lifetime; naming them
    // here is what makes that true, and dropping them would let another
    // arrival claim between this refusal and its receipt.
    let _ = (registry, binding, rendezvous, lease);
    PreparedProtocolTerminalClaim {
        state: PreparedProtocolState::Reject(reason),
        record: committed.into_terminal_record(),
    }
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn prepare_protocol_terminal_claim<'objects, const N: usize>(
    registry: &'objects mut crate::session::SessionRegistry<N>,
    binding: &'objects mut crate::session::ControlBinding,
    rendezvous: &'objects mut crate::session::TerminalRendezvous,
    lease: &'objects mut Option<crate::session::RegistryLease>,
    committed: crate::adapter::enter::CommittedProtocolAbort,
) -> PreparedProtocolTerminalClaim<'objects, N> {
    let locator = committed.authenticated_locator();
    let record = committed.into_terminal_record();
    match crate::session::prepare_terminal_claim(
        registry,
        binding,
        rendezvous,
        lease,
        locator,
        crate::session::TerminalRequest::ProtocolFault,
    ) {
        Ok(claim) => PreparedProtocolTerminalClaim {
            state: PreparedProtocolState::Claim(claim),
            record,
        },
        Err(error) => PreparedProtocolTerminalClaim {
            state: PreparedProtocolState::Reject(ProtocolRejectReason::Lifecycle(error)),
            record,
        },
    }
}

#[allow(dead_code)]
impl<const N: usize> PreparedProtocolTerminalClaim<'_, N> {
    /// The one indivisible suffix. No argument, no `Result`, no second chance.
    ///
    /// Task 9's claim commits infallibly under the same four borrows it was
    /// preflighted over, so no other cell can be substituted here. Its Blocked
    /// arm becomes the typed reject: a blocked terminal is exactly the case
    /// where nothing can be claimed *and* the consumer has already been
    /// released, which is what the receipt exists to say.
    ///
    /// **Named `commit_protocol_claim`, not `commit`, for the same reason
    /// `commit_protocol_abort` is.** A method called `commit` here merges into
    /// one node with production's setup commit, and the consequence is not
    /// cosmetic: `reject_committed_protocol` -- the sole minter of a reject
    /// receipt -- would start reporting as production-reachable through it, and
    /// its staged row would have to become a recorded excuse. Renaming keeps
    /// the proof.
    #[doc(hidden)]
    pub fn commit_protocol_claim(self) -> CommittedProtocolTerminalDisposition {
        let Self { state, record } = self;
        let claim = match state {
            PreparedProtocolState::Reject(reason) => {
                return CommittedProtocolTerminalDisposition::Reject(reject_committed_protocol(
                    reason, record,
                ));
            }
            PreparedProtocolState::Claim(claim) => claim,
        };
        match claim.commit() {
            CoreTerminalDisposition::Winner(winner) => {
                // The record is consumed here as everywhere else: one arrival
                // produces one disposition, and a retained record would let a
                // second branch act on an abort already answered.
                let _ = record;
                // Split at the moment the winner exists, not at the crate
                // boundary: there is then no window in which any caller holds
                // the ticket bare.
                let (winner, terminal, ticket) = winner.into_parts();
                CommittedProtocolTerminalDisposition::Winner {
                    work: CommittedProtocolTerminalWork { winner, terminal },
                    join: CommittedProtocolJoin { ticket },
                }
            }
            CoreTerminalDisposition::Join(ticket) => {
                let _ = record;
                CommittedProtocolTerminalDisposition::Join(CommittedProtocolJoin { ticket })
            }
            CoreTerminalDisposition::Completed(result) => {
                let _ = record;
                CommittedProtocolTerminalDisposition::Completed(CommittedProtocolCompleted {
                    result,
                })
            }
            CoreTerminalDisposition::Blocked(blocked) => {
                // A blocked terminal is not an error and not a claim: the
                // arrival is answered, and the receipt carries the proof that
                // its consumer was released before the registry lock.
                //
                // **COVERED**, together with Winner, Join and Completed, by
                // `task21_a_published_cell_yields_every_protocol_terminal_disposition`.
                // All four were unreachable for one reason -- the CQ module
                // could only build arrivals for sessions it had never published,
                // so every claim refused at Task 9's preflight -- and one shared
                // fixture (`session::tests::published_cell_with_rings`, which
                // takes the ring set between installation and publication) fixed
                // all four at once. Each arm is falsified by a plant.
                let _ = blocked;
                CommittedProtocolTerminalDisposition::Reject(reject_committed_protocol(
                    ProtocolRejectReason::JoinGuardUnavailable,
                    record,
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveDecision {
    Reject,
    ProjectSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellObservation {
    locator: SessionLocator,
    phase: NativeCellPhase,
    access_rundown_acquired: bool,
}

impl CellObservation {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn phase(&self) -> NativeCellPhase {
        self.phase
    }

    pub const fn access_rundown_acquired(&self) -> bool {
        self.access_rundown_acquired
    }
}

pub fn decide_resolve(
    requested: SessionLocator,
    observed: Option<CellObservation>,
    rundown_acquired: bool,
) -> ResolveDecision {
    match observed {
        Some(observation)
            if observation.locator == requested
                && matches!(observation.phase, NativeCellPhase::Live)
                && observation.access_rundown_acquired
                && rundown_acquired =>
        {
            ResolveDecision::ProjectSession
        }
        Some(_) | None => ResolveDecision::Reject,
    }
}

// ---------------------------------------------------------------------------
// The ordered access resolution
// ---------------------------------------------------------------------------

/// One step of resolving a `SessionLocator` into a live session, in the only
/// order that is safe.
///
/// The per-cell access rundown is acquired *before* the registry lock and
/// before any pointer is read, because it — not the lock, and not a strong
/// reference this path never takes — is what keeps the shell alive after the
/// lock is dropped. Every rejection taken after that acquisition owes exactly
/// one release; a rejection that forgets it leaks the rundown and deadlocks the
/// terminal wait that drains it, and one that releases twice frees a shell a
/// second caller still holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveStep {
    BoundsCheckLocator,
    AcquireAccessRundown,
    AcquireRegistryLock,
    ValidateCoreLive,
    ValidateCellIdentity,
    ValidateNativeOwnerSlots,
    ProjectSessionPointer,
    ReleaseRegistryLock,
}

/// Why a resolution refused.
///
/// The reasons are distinct so a test can prove each step is the one that
/// refused, rather than accepting any refusal as proof of the rule it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveRejection {
    /// The locator's slot index is outside the permanent cell array.
    OutOfRange,
    /// The cell's access rundown is already draining for a terminal fence.
    RundownRefused,
    /// The core registry does not hold this exact locator `Live`.
    NotLive,
    /// The native cell disagrees with the core registry or the caller.
    StaleCell,
    /// The cell is Live but holds no authentic shell/root owner, or holds one
    /// branded for another locator.
    MissingOwners,
}

/// Indices of the order-critical resolver actions, filled in as the walk runs.
#[derive(Clone, Copy, Default)]
struct ResolveRecord {
    rundown_acquired: Option<u8>,
    rundown_released: Option<u8>,
    rundown_releases: u8,
    lock_acquired: Option<u8>,
    lock_released: Option<u8>,
    core_validated: Option<u8>,
    cell_validated: Option<u8>,
    owners_validated: Option<u8>,
    projected: Option<u8>,
}

pub struct PendingResolveStep {
    roster: [ResolveStep; 8],
    next: u8,
    step: ResolveStep,
    record: ResolveRecord,
}

/// A completed resolution: the caller now holds the access rundown.
pub struct ResolveProof {
    record: ResolveRecord,
}

/// A refused resolution and the unwind it performed.
pub struct ResolveRefusal {
    reason: ResolveRejection,
    record: ResolveRecord,
}

pub enum ResolveProgress {
    Step(PendingResolveStep),
    Resolved(ResolveProof),
    Refused(ResolveRefusal),
}

pub struct ResolvePlan;

impl ResolvePlan {
    pub const STEPS: [ResolveStep; 8] = [
        ResolveStep::BoundsCheckLocator,
        ResolveStep::AcquireAccessRundown,
        ResolveStep::AcquireRegistryLock,
        ResolveStep::ValidateCoreLive,
        ResolveStep::ValidateCellIdentity,
        ResolveStep::ValidateNativeOwnerSlots,
        ResolveStep::ProjectSessionPointer,
        ResolveStep::ReleaseRegistryLock,
    ];

    pub const fn begin() -> ResolveProgress {
        Self::begin_inner(Self::STEPS)
    }

    /// Begin from an explicit roster.
    ///
    /// Production has exactly one roster, and [`Self::begin`] is its only
    /// caller. Tests drive deliberately wrong orders through this seam so the
    /// proofs below can be observed reporting `false`.
    #[cfg(test)]
    pub(crate) const fn begin_with_roster(roster: [ResolveStep; 8]) -> ResolveProgress {
        Self::begin_inner(roster)
    }

    const fn begin_inner(roster: [ResolveStep; 8]) -> ResolveProgress {
        ResolveProgress::Step(PendingResolveStep {
            roster,
            next: 0,
            step: roster[0],
            record: ResolveRecord {
                rundown_acquired: None,
                rundown_released: None,
                rundown_releases: 0,
                lock_acquired: None,
                lock_released: None,
                core_validated: None,
                cell_validated: None,
                owners_validated: None,
                projected: None,
            },
        })
    }
}

impl PendingResolveStep {
    pub const fn step(&self) -> ResolveStep {
        self.step
    }

    /// The native executor performed this step and it succeeded.
    pub fn succeeded(mut self) -> ResolveProgress {
        let at = self.next;
        match self.step {
            ResolveStep::AcquireAccessRundown => self.record.rundown_acquired = Some(at),
            ResolveStep::AcquireRegistryLock => self.record.lock_acquired = Some(at),
            ResolveStep::ValidateCoreLive => self.record.core_validated = Some(at),
            ResolveStep::ValidateCellIdentity => self.record.cell_validated = Some(at),
            ResolveStep::ValidateNativeOwnerSlots => self.record.owners_validated = Some(at),
            ResolveStep::ProjectSessionPointer => self.record.projected = Some(at),
            ResolveStep::ReleaseRegistryLock => self.record.lock_released = Some(at),
            ResolveStep::BoundsCheckLocator => {}
        }
        self.next = self.next.saturating_add(1);
        match self.roster.get(usize::from(self.next)) {
            Some(step) => {
                self.step = *step;
                ResolveProgress::Step(self)
            }
            None => ResolveProgress::Resolved(ResolveProof {
                record: self.record,
            }),
        }
    }

    /// This step refused, and the resolver unwinds whatever it already took.
    ///
    /// The unwind is part of the model rather than of each native call site:
    /// there are five refusal points and only one of them is reached by the
    /// common path, so a hand-written release at each site is exactly the shape
    /// that leaks one of them.
    pub fn refused(mut self, reason: ResolveRejection) -> ResolveProgress {
        let at = self.next;
        if self.record.lock_acquired.is_some() && self.record.lock_released.is_none() {
            self.record.lock_released = Some(at);
        }
        if self.record.rundown_acquired.is_some() && self.record.rundown_released.is_none() {
            self.record.rundown_released = Some(at);
            self.record.rundown_releases = self.record.rundown_releases.saturating_add(1);
        }
        ResolveProgress::Refused(ResolveRefusal {
            reason,
            record: self.record,
        })
    }
}

impl ResolveProof {
    /// The access rundown was held before the registry lock was taken.
    pub const fn rundown_acquired_before_lock(&self) -> bool {
        match (self.record.rundown_acquired, self.record.lock_acquired) {
            (Some(rundown), Some(lock)) => rundown < lock,
            _ => false,
        }
    }

    /// No session pointer was read before the rundown that keeps it alive.
    pub const fn rundown_acquired_before_projection(&self) -> bool {
        match (self.record.rundown_acquired, self.record.projected) {
            (Some(rundown), Some(projected)) => rundown < projected,
            _ => false,
        }
    }

    /// Core `Live`, cell identity, and owner slots were all proven first.
    pub const fn validated_before_projection(&self) -> bool {
        match (
            self.record.core_validated,
            self.record.cell_validated,
            self.record.owners_validated,
            self.record.projected,
        ) {
            (Some(core), Some(cell), Some(owners), Some(projected)) => {
                core < projected && cell < projected && owners < projected
            }
            _ => false,
        }
    }

    /// The pointer was copied out while the lock still held the cell still.
    pub const fn projected_before_lock_release(&self) -> bool {
        match (self.record.projected, self.record.lock_released) {
            (Some(projected), Some(released)) => projected < released,
            _ => false,
        }
    }

    /// A successful resolution keeps the rundown: it is the guard's to release.
    pub const fn rundown_retained(&self) -> bool {
        self.record.rundown_acquired.is_some() && self.record.rundown_released.is_none()
    }
}

impl ResolveRefusal {
    pub const fn reason(&self) -> ResolveRejection {
        self.reason
    }

    /// A refusal after acquisition released the rundown exactly once, and a
    /// refusal before acquisition released nothing.
    pub const fn rundown_balanced(&self) -> bool {
        match self.record.rundown_acquired {
            Some(_) => self.record.rundown_releases == 1,
            None => self.record.rundown_releases == 0,
        }
    }

    /// A refusal never hands out a session pointer.
    pub const fn projected(&self) -> bool {
        self.record.projected.is_some()
    }

    /// The unwind this refusal requires of the native executor.
    ///
    /// These are what make the model load-bearing rather than descriptive: the
    /// production resolver performs exactly the releases named here, so the
    /// balance proofs above are proofs about the code that runs.
    pub const fn releases_lock(&self) -> bool {
        self.record.lock_released.is_some()
    }

    pub const fn releases_rundown(&self) -> bool {
        self.record.rundown_released.is_some()
    }

    /// A refusal that had taken the lock gave it back.
    pub const fn lock_balanced(&self) -> bool {
        match self.record.lock_acquired {
            Some(_) => self.record.lock_released.is_some(),
            None => self.record.lock_released.is_none(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizerState {
    Idle,
    Queued,
    Running,
    DeleteFailStop,
}

impl FinalizerState {
    pub fn queue(&mut self) -> Result<(), LifecycleError> {
        if !matches!(self, Self::Idle) {
            return Err(LifecycleError::FinalizerBusy);
        }
        *self = Self::Queued;
        Ok(())
    }

    pub fn begin_run(&mut self) -> Result<(), LifecycleError> {
        if !matches!(self, Self::Queued) {
            return Err(LifecycleError::FinalizerBusy);
        }
        *self = Self::Running;
        Ok(())
    }

    pub fn finish_run(&mut self) -> Result<(), LifecycleError> {
        if !matches!(self, Self::Running) {
            return Err(LifecycleError::WrongState);
        }
        *self = Self::Idle;
        Ok(())
    }

    pub fn fail_stop(&mut self) -> Result<(), LifecycleError> {
        if !matches!(self, Self::Running) {
            return Err(LifecycleError::WrongState);
        }
        *self = Self::DeleteFailStop;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanAction {
    Skip,
    Claim,
    Join,
    ObserveCompleted(TerminalResult),
    ObserveBlocked(TerminalBlocked),
}

const fn decide_scan(phase: NativeCellPhase, outcome: TerminalRendezvousOutcome) -> ScanAction {
    match outcome {
        TerminalRendezvousOutcome::Completed(result) => ScanAction::ObserveCompleted(result),
        TerminalRendezvousOutcome::Blocked(blocked) => ScanAction::ObserveBlocked(blocked),
        TerminalRendezvousOutcome::Open => match phase {
            NativeCellPhase::Live => ScanAction::Claim,
            NativeCellPhase::Removing | NativeCellPhase::Deleting => ScanAction::Join,
            NativeCellPhase::Free | NativeCellPhase::Staging | NativeCellPhase::Retired => {
                ScanAction::Skip
            }
        },
    }
}

pub const fn decide_process_scan(
    phase: NativeCellPhase,
    outcome: TerminalRendezvousOutcome,
) -> ScanAction {
    decide_scan(phase, outcome)
}

pub const fn decide_unload_scan(
    phase: NativeCellPhase,
    outcome: TerminalRendezvousOutcome,
) -> ScanAction {
    decide_scan(phase, outcome)
}

/// What one process-loss or unload scan does after observing a cell.
///
/// A process-loss winner may not hold the registry lock while it runs terminal
/// work, so the scan must give the lock back and then start again from the top
/// of the cell array: the generation it observed may already be gone. Encoding
/// "restart" as a value rather than a loop shape is what lets a test prove the
/// scan does not simply continue with a stale index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanContinuation {
    /// Nothing to do for this cell; the same pass advances to the next index.
    NextCell,
    /// Terminal work ran or waited outside the lock; the pass starts over.
    RestartScan,
}

/// Whether an observed cell suspends the one-cell-at-a-time scan.
pub const fn decide_scan_continuation(action: &ScanAction) -> ScanContinuation {
    match action {
        // Every matching generation is handled outside the observation hold,
        // including stable Completed/Blocked records. Only a non-match can
        // advance the same pass.
        ScanAction::Claim
        | ScanAction::Join
        | ScanAction::ObserveCompleted(_)
        | ScanAction::ObserveBlocked(_) => ScanContinuation::RestartScan,
        ScanAction::Skip => ScanContinuation::NextCell,
    }
}

/// One authenticated process-cell observation supplied to the common callback
/// runner.  There is deliberately no generic `Match(ScanAction, A)` arm: a
/// caller cannot smuggle `Skip` into the restart path or make one of the four
/// matching outcomes advance a stale cursor.
pub enum ProcessCallbackCell<Action> {
    Skip,
    Claim(Action),
    Join(Action),
    Completed(Action),
    Blocked(Action),
}

/// Run the one-guard process callback scan used by native production and by
/// the host fake below.
///
/// Refusal (`None`) returns before `observe` can name the registry or a cell.
/// Every admitted observation and handler receives the same borrowed guard;
/// every matching arm is discharged by `handle` and only then restarts at
/// cell zero.  Returning the guard happens only after a full no-match pass so
/// native code can perform its exact rundown release once.
pub fn run_process_callback_scan<Guard, Action>(
    guard: Option<Guard>,
    cell_count: u32,
    mut observe: impl FnMut(&Guard, u32) -> ProcessCallbackCell<Action>,
    mut handle: impl FnMut(&Guard, Action),
) -> Option<Guard> {
    let guard = guard?;
    let mut cursor = 0u32;
    while cursor < cell_count {
        match observe(&guard, cursor) {
            ProcessCallbackCell::Skip => cursor = cursor.saturating_add(1),
            ProcessCallbackCell::Claim(action)
            | ProcessCallbackCell::Join(action)
            | ProcessCallbackCell::Completed(action)
            | ProcessCallbackCell::Blocked(action) => {
                handle(&guard, action);
                cursor = 0;
            }
        }
    }
    Some(guard)
}

// The host-only generic unload model exercises the same capability rule as
// the private fixed-domain FSD cursor: a cursor can advance only by consuming
// a locked non-match receipt, and work can yield a restart only after its one
// action has been discharged.  It is not compiled into production and cannot
// mint native stable-empty authority.
#[cfg(test)]
pub(crate) struct R3UnloadTestProgress<const CELL_COUNT: usize> {
    cursor: u32,
}

#[cfg(test)]
pub(crate) enum R3UnloadTestObservation<Action> {
    NonMatch(PrivateLockedNonMatch),
    Action(Action),
}

#[cfg(test)]
pub(crate) enum R3UnloadTestStep<Action, const CELL_COUNT: usize> {
    Scanning(R3UnloadTestProgress<CELL_COUNT>),
    Work(R3UnloadTestWork<Action, CELL_COUNT>),
    StableEmpty(R3UnloadTestStableEmpty),
}

#[cfg(test)]
pub(crate) struct R3UnloadTestWork<Action, const CELL_COUNT: usize> {
    action: Action,
}

#[cfg(test)]
pub(crate) struct R3UnloadTestStableEmpty(PrivateR3TestStableEmpty);

#[cfg(test)]
pub(crate) struct PrivateLockedNonMatch(());

#[cfg(test)]
pub(crate) struct PrivateR3TestStableEmpty(());

#[cfg(test)]
impl PrivateLockedNonMatch {
    pub(crate) const fn observed_under_fake_lock() -> Self {
        Self(())
    }
}

#[cfg(test)]
impl<Action> R3UnloadTestObservation<Action> {
    pub(crate) const fn non_match() -> Self {
        Self::NonMatch(PrivateLockedNonMatch::observed_under_fake_lock())
    }
}

#[cfg(test)]
impl<const CELL_COUNT: usize> R3UnloadTestProgress<CELL_COUNT> {
    pub(crate) const fn begin() -> Self {
        assert!(CELL_COUNT > 0);
        Self { cursor: 0 }
    }

    pub(crate) const fn cursor(&self) -> u32 {
        self.cursor
    }

    pub(crate) fn observe<Action>(
        self,
        observation: R3UnloadTestObservation<Action>,
    ) -> R3UnloadTestStep<Action, CELL_COUNT> {
        match observation {
            R3UnloadTestObservation::NonMatch(PrivateLockedNonMatch(())) => {
                let next = self.cursor.saturating_add(1);
                if usize::try_from(next).map_or(true, |next| next >= CELL_COUNT) {
                    R3UnloadTestStep::StableEmpty(R3UnloadTestStableEmpty(
                        PrivateR3TestStableEmpty(()),
                    ))
                } else {
                    R3UnloadTestStep::Scanning(Self { cursor: next })
                }
            }
            R3UnloadTestObservation::Action(action) => {
                R3UnloadTestStep::Work(R3UnloadTestWork { action })
            }
        }
    }
}

#[cfg(test)]
impl<Action, const CELL_COUNT: usize> R3UnloadTestWork<Action, CELL_COUNT> {
    pub(crate) fn discharge(
        self,
        perform: impl FnOnce(Action),
    ) -> R3UnloadTestProgress<CELL_COUNT> {
        perform(self.action);
        R3UnloadTestProgress::begin()
    }
}

/// Host-only fake of the native process rundown. It exists to exercise the
/// refusal boundary and the identity of the one guard spanning all restarts;
/// production uses the WDK rundown plus the structural lifetime gate.
#[cfg(test)]
pub(crate) struct ProcessCallbackAdmissionHarness {
    open: bool,
    next_identity: u64,
    live_guards: u32,
}

#[cfg(test)]
pub(crate) struct ProcessCallbackHarnessGuard {
    identity: u64,
}

#[cfg(test)]
pub(crate) struct ProcessCallbacksDrainedHarnessReceipt(());

#[cfg(test)]
pub(crate) struct ProcessCallbackTrace {
    refused: bool,
    registry_touches: u32,
    cell_touches: u32,
    guard_identity: Option<u64>,
    one_guard: bool,
    restarts: u32,
    last_matching_cell: Option<usize>,
}

#[cfg(test)]
impl ProcessCallbackAdmissionHarness {
    pub(crate) const fn new() -> Self {
        Self {
            open: true,
            next_identity: 1,
            live_guards: 0,
        }
    }

    pub(crate) fn close(&mut self) {
        self.open = false;
    }

    fn acquire(&mut self) -> Option<ProcessCallbackHarnessGuard> {
        if !self.open {
            return None;
        }
        let identity = self.next_identity;
        self.next_identity = self.next_identity.saturating_add(1);
        self.live_guards = self.live_guards.saturating_add(1);
        Some(ProcessCallbackHarnessGuard { identity })
    }

    pub(crate) fn acquire_for_test(&mut self) -> Option<ProcessCallbackHarnessGuard> {
        self.acquire()
    }

    pub(crate) fn release(&mut self, _guard: ProcessCallbackHarnessGuard) {
        self.live_guards = self.live_guards.saturating_sub(1);
    }

    pub(crate) fn drain(&self) -> Option<ProcessCallbacksDrainedHarnessReceipt> {
        (!self.open && self.live_guards == 0).then_some(ProcessCallbacksDrainedHarnessReceipt(()))
    }
}

/// Host fake for the control-context admission receipt consumed by effect 9.
/// The old lease is deliberately independent of a reusable session cell.
#[cfg(test)]
pub(crate) struct ControlContextAdmissionHarness {
    open: bool,
    leases: u32,
}

#[cfg(test)]
pub(crate) struct ControlContextLeaseHarness(());

#[cfg(test)]
pub(crate) struct ControlContextsDrainedHarnessReceipt(());

#[cfg(test)]
impl ControlContextAdmissionHarness {
    pub(crate) const fn new() -> Self {
        Self {
            open: true,
            leases: 0,
        }
    }

    pub(crate) fn acquire(&mut self) -> Option<ControlContextLeaseHarness> {
        if !self.open {
            return None;
        }
        self.leases = self.leases.saturating_add(1);
        Some(ControlContextLeaseHarness(()))
    }

    pub(crate) fn close(&mut self) {
        self.open = false;
    }

    pub(crate) fn release(&mut self, _lease: ControlContextLeaseHarness) {
        self.leases = self.leases.saturating_sub(1);
    }

    pub(crate) fn drain(&self) -> Option<ControlContextsDrainedHarnessReceipt> {
        (!self.open && self.leases == 0).then_some(ControlContextsDrainedHarnessReceipt(()))
    }
}

/// Host oracle for the asymmetric unload authentication rules.  The native
/// implementation owns the actual affine tickets and slot receipts; this
/// trace keeps the required order independently mutation-visible on a host.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3UnloadVisibilityForTest {
    Published,
    Opaque,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3UnloadTicketForTest {
    None,
    Exact,
    Foreign,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3UnloadVisibilityTraceStep {
    ObserveVisibility,
    ReleaseExactTicket,
    AuthenticatePublishedSlot,
    AuthenticateOpaqueSlotAndRendezvous,
    RetainForeignTicket,
    Unlock,
    WaitForever,
}

/// Pure used-cell history oracle for effect nine's generation events. Delete
/// reset clears terminal/mount completion after their tickets drain, but the
/// visibility notification remains latched until effect seven authenticates
/// exact empty under lock (or a later Staging generation clears it before
/// publication). The three drained events remain signalled.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct R3UnloadEventStatesForTest {
    pub(crate) terminal_outcome: bool,
    pub(crate) visibility_resolution: bool,
    pub(crate) joiners_drained: bool,
    pub(crate) mount_complete: bool,
    pub(crate) mount_waiters_drained: bool,
    pub(crate) mount_reset_complete: bool,
    pub(crate) mount_reset_waiters_drained: bool,
}

#[cfg(test)]
pub(crate) const fn reset_r3_unload_events_after_delete_for_test(
    mut events: R3UnloadEventStatesForTest,
) -> R3UnloadEventStatesForTest {
    events.terminal_outcome = false;
    events.mount_complete = false;
    events.mount_reset_complete = false;
    events
}

#[cfg(test)]
pub(crate) const fn acknowledge_r3_unload_visibility_after_effect_seven_for_test(
    mut events: R3UnloadEventStatesForTest,
) -> R3UnloadEventStatesForTest {
    events.visibility_resolution = false;
    events
}

#[cfg(test)]
pub(crate) const fn clear_r3_unload_visibility_before_staging_for_test(
    mut events: R3UnloadEventStatesForTest,
) -> R3UnloadEventStatesForTest {
    events.visibility_resolution = false;
    events
}

#[cfg(test)]
pub(crate) const fn r3_unload_events_are_quiescent_for_test(
    events: R3UnloadEventStatesForTest,
) -> bool {
    !events.terminal_outcome
        && !events.visibility_resolution
        && events.joiners_drained
        && !events.mount_complete
        && events.mount_waiters_drained
        && !events.mount_reset_complete
        && events.mount_reset_waiters_drained
}

#[cfg(test)]
pub(crate) fn trace_r3_unload_visibility_wait(
    visibility: R3UnloadVisibilityForTest,
    ticket: R3UnloadTicketForTest,
) -> Vec<R3UnloadVisibilityTraceStep> {
    use R3UnloadTicketForTest::{Exact, Foreign, None};
    use R3UnloadVisibilityForTest::{Opaque, Published};
    use R3UnloadVisibilityTraceStep::{
        AuthenticateOpaqueSlotAndRendezvous, AuthenticatePublishedSlot, ObserveVisibility,
        ReleaseExactTicket, RetainForeignTicket, Unlock, WaitForever,
    };

    let mut trace = vec![ObserveVisibility];
    match (visibility, ticket) {
        (Published, Exact) => {
            trace.push(ReleaseExactTicket);
            trace.push(AuthenticatePublishedSlot);
        }
        (Published, None) => trace.push(AuthenticatePublishedSlot),
        (Published, Foreign) => {
            trace.push(AuthenticatePublishedSlot);
            trace.push(RetainForeignTicket);
        }
        (Opaque, Exact) => {
            trace.push(AuthenticateOpaqueSlotAndRendezvous);
            trace.push(ReleaseExactTicket);
        }
        (Opaque, Foreign) => {
            trace.push(AuthenticateOpaqueSlotAndRendezvous);
            trace.push(RetainForeignTicket);
        }
        (Opaque, None) => trace.push(AuthenticateOpaqueSlotAndRendezvous),
    }
    trace.push(Unlock);
    trace.push(WaitForever);
    trace
}

/// Host fake of effect seven's separate queue-to-callback admission.  A guard
/// is acquired at the locked deposit/Queued transition and stays associated
/// with that generation until the callback epilogue.  Therefore a Free cell
/// is not reusable while an old callback can still mutate it.
#[cfg(test)]
pub(crate) struct R3FinalizerAdmissionHarness {
    open: bool,
    live: [bool; 64],
    ledger_empty: [bool; 64],
    resolution: [Option<R3FinalizerResolutionForTest>; 64],
    visibility_latched: [bool; 64],
    handoff: [R3FinalizerHandoffForTest; 64],
}

#[cfg(test)]
pub(crate) struct R3FinalizerHarnessGuard {
    cell: usize,
}

#[cfg(test)]
pub(crate) struct R3FinalizersDrainedHarnessReceipt(());

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3FinalizerResolutionForTest {
    Ordinary,
    Published,
    Opaque,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R3FinalizerHandoffForTest {
    None,
    Ordinary(usize),
    Opaque,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3FinalizerDrainStep {
    WaitForVisibility,
    WaitForRundown,
    AuthenticatedPermanentWait,
    FailStop,
    Drained,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum R3FinalizerFullScanOutcome {
    WaitForVisibility(usize),
    AuthenticatedPermanentWait(usize),
    FailStop(usize),
    WaitForRundown,
    Drained,
}

// Proof of safety for the suppression below. Every index here is either
// carried by `R3FinalizerHarnessGuard`, whose private `cell` is minted only
// after `acquire_for_queue` rejects `cell >= self.live.len()`, or supplied
// directly by a test, where an out-of-range cell is a bug in the test that
// must panic loudly rather than be masked. The harness is `#[cfg(test)]`: it
// is a host model, never a driver input path, so section 5's rule about
// panicking indexes on those paths does not reach it.
#[allow(clippy::indexing_slicing)]
#[cfg(test)]
impl R3FinalizerAdmissionHarness {
    pub(crate) const fn new() -> Self {
        Self {
            open: true,
            live: [false; 64],
            ledger_empty: [true; 64],
            resolution: [None; 64],
            visibility_latched: [false; 64],
            handoff: [R3FinalizerHandoffForTest::None; 64],
        }
    }

    pub(crate) fn acquire_for_queue(&mut self, cell: usize) -> Option<R3FinalizerHarnessGuard> {
        if !self.open || cell >= self.live.len() || self.live[cell] {
            return None;
        }
        self.live[cell] = true;
        self.ledger_empty[cell] = false;
        self.resolution[cell] = None;
        // This is the locked Staging-generation reset. A new callback cannot
        // inherit an old NotificationEvent signal from the permanent cell.
        self.visibility_latched[cell] = false;
        self.handoff[cell] = R3FinalizerHandoffForTest::None;
        Some(R3FinalizerHarnessGuard { cell })
    }

    pub(crate) fn close(&mut self) {
        self.open = false;
    }

    pub(crate) fn publish_resolution(
        &mut self,
        cell: usize,
        resolution: R3FinalizerResolutionForTest,
    ) {
        assert!(self.live[cell], "only an admitted callback can resolve");
        self.resolution[cell] = Some(resolution);
        self.visibility_latched[cell] = true;
    }

    pub(crate) fn store_ordinary_handoff_for_test(&mut self, cell: usize) {
        assert!(self.live[cell]);
        self.handoff[cell] = R3FinalizerHandoffForTest::Ordinary(cell);
    }

    pub(crate) fn take_ordinary_handoff_for_test(&mut self, cell: usize) {
        assert_eq!(
            self.handoff[cell],
            R3FinalizerHandoffForTest::Ordinary(cell),
        );
        self.handoff[cell] = R3FinalizerHandoffForTest::None;
    }

    pub(crate) fn store_opaque_handoff_for_test(&mut self, cell: usize) {
        assert!(self.live[cell]);
        self.handoff[cell] = R3FinalizerHandoffForTest::Opaque;
    }

    /// Model the callback publishing durable visibility, signaling its
    /// broadcast event, and then releasing the rundown before effect seven
    /// retakes the registry lock. The durable cell state must remain visible
    /// even though the callback admission is already gone.
    pub(crate) fn release_after_durable_resolution(&mut self, guard: R3FinalizerHarnessGuard) {
        assert!(self.live[guard.cell]);
        assert!(self.resolution[guard.cell].is_some());
        self.live[guard.cell] = false;
    }

    fn ordinary_handoff_matches(&self, cell: usize) -> bool {
        match self.handoff[cell] {
            R3FinalizerHandoffForTest::None => true,
            R3FinalizerHandoffForTest::Ordinary(owner) => owner == cell,
            R3FinalizerHandoffForTest::Opaque => false,
        }
    }

    pub(crate) fn effect_seven_step(&mut self, cell: usize) -> R3FinalizerDrainStep {
        assert!(!self.open, "effect seven closes its own door first");
        if !self.live[cell] {
            if matches!(
                self.resolution[cell],
                Some(
                    R3FinalizerResolutionForTest::Published | R3FinalizerResolutionForTest::Opaque
                )
            ) {
                return R3FinalizerDrainStep::AuthenticatedPermanentWait;
            }
            if !self.ledger_empty[cell] {
                return R3FinalizerDrainStep::FailStop;
            }
            // The exact locked non-match acknowledges the generation latch.
            // Reset cannot clear it earlier without losing an observed wake.
            self.visibility_latched[cell] = false;
            return if self.live.iter().any(|live| *live) {
                R3FinalizerDrainStep::WaitForRundown
            } else {
                R3FinalizerDrainStep::Drained
            };
        }
        match self.resolution[cell] {
            None => R3FinalizerDrainStep::WaitForVisibility,
            Some(R3FinalizerResolutionForTest::Ordinary) => {
                if self.ordinary_handoff_matches(cell) {
                    R3FinalizerDrainStep::WaitForRundown
                } else {
                    R3FinalizerDrainStep::FailStop
                }
            }
            Some(
                R3FinalizerResolutionForTest::Published | R3FinalizerResolutionForTest::Opaque,
            ) => R3FinalizerDrainStep::AuthenticatedPermanentWait,
        }
    }

    pub(crate) fn effect_seven_full_scan(&mut self) -> R3FinalizerFullScanOutcome {
        assert!(!self.open, "effect seven closes its own door first");
        let mut ordinary_admitted = false;
        let mut cell = 0usize;
        while cell < self.live.len() {
            if !self.live[cell] {
                if matches!(
                    self.resolution[cell],
                    Some(
                        R3FinalizerResolutionForTest::Published
                            | R3FinalizerResolutionForTest::Opaque
                    )
                ) {
                    return R3FinalizerFullScanOutcome::AuthenticatedPermanentWait(cell);
                }
                if !self.ledger_empty[cell] {
                    return R3FinalizerFullScanOutcome::FailStop(cell);
                }
                self.visibility_latched[cell] = false;
            }
            if self.live[cell] {
                match self.resolution[cell] {
                    None => return R3FinalizerFullScanOutcome::WaitForVisibility(cell),
                    Some(
                        R3FinalizerResolutionForTest::Published
                        | R3FinalizerResolutionForTest::Opaque,
                    ) => {
                        return R3FinalizerFullScanOutcome::AuthenticatedPermanentWait(cell);
                    }
                    Some(R3FinalizerResolutionForTest::Ordinary) => {
                        if !self.ordinary_handoff_matches(cell) {
                            return R3FinalizerFullScanOutcome::FailStop(cell);
                        }
                        ordinary_admitted = true;
                    }
                }
            }
            cell = cell.saturating_add(1);
        }
        if ordinary_admitted {
            R3FinalizerFullScanOutcome::WaitForRundown
        } else {
            R3FinalizerFullScanOutcome::Drained
        }
    }

    pub(crate) fn release_after_callback(&mut self, guard: R3FinalizerHarnessGuard) {
        assert!(self.live[guard.cell]);
        self.live[guard.cell] = false;
        self.ledger_empty[guard.cell] = true;
        self.resolution[guard.cell] = None;
        self.handoff[guard.cell] = R3FinalizerHandoffForTest::None;
        // Deliberately keep visibility_latched set. This models the native
        // reset publishing Free while preserving the callback's prior wake
        // until effect seven reauthenticates the exact empty cell under lock.
    }

    pub(crate) fn corrupt_inactive_finalizer_ledger_for_test(&mut self, cell: usize) {
        assert!(!self.live[cell]);
        self.ledger_empty[cell] = false;
    }

    pub(crate) fn cell_reusable(&self, cell: usize) -> bool {
        !self.live[cell] && self.ledger_empty[cell]
    }

    pub(crate) fn visibility_latched_for_test(&self, cell: usize) -> bool {
        self.visibility_latched[cell]
    }

    pub(crate) fn drain_receipt(&self) -> Option<R3FinalizersDrainedHarnessReceipt> {
        (!self.open
            && !self.live.iter().any(|live| *live)
            && self.ledger_empty.iter().all(|empty| *empty)
            && !self.visibility_latched.iter().any(|latched| *latched))
        .then_some(R3FinalizersDrainedHarnessReceipt(()))
    }
}

#[cfg(test)]
impl ProcessCallbackTrace {
    pub(crate) const fn refused(&self) -> bool {
        self.refused
    }

    pub(crate) const fn registry_touches(&self) -> u32 {
        self.registry_touches
    }

    pub(crate) const fn cell_touches(&self) -> u32 {
        self.cell_touches
    }

    pub(crate) const fn guard_identity(&self) -> Option<u64> {
        self.guard_identity
    }

    pub(crate) const fn one_guard_spanned_every_touch(&self) -> bool {
        self.one_guard && self.guard_identity.is_some()
    }

    pub(crate) const fn restarts(&self) -> u32 {
        self.restarts
    }

    pub(crate) const fn last_matching_cell(&self) -> Option<usize> {
        self.last_matching_cell
    }
}

#[cfg(test)]
pub(crate) fn trace_process_callback_entry(
    admission: &mut ProcessCallbackAdmissionHarness,
    actions: &[ScanAction],
) -> ProcessCallbackTrace {
    let cells = core::cell::RefCell::new(actions.to_vec());
    let trace = core::cell::RefCell::new(ProcessCallbackTrace {
        refused: false,
        registry_touches: 0,
        cell_touches: 0,
        guard_identity: None,
        one_guard: true,
        restarts: 0,
        last_matching_cell: None,
    });
    let admitted = run_process_callback_scan(
        admission.acquire(),
        u32::try_from(actions.len()).unwrap_or(u32::MAX),
        |guard, index| {
            let mut trace = trace.borrow_mut();
            trace.registry_touches = trace.registry_touches.saturating_add(1);
            trace.cell_touches = trace.cell_touches.saturating_add(1);
            match trace.guard_identity {
                Some(identity) if identity != guard.identity => trace.one_guard = false,
                Some(_) => {}
                None => trace.guard_identity = Some(guard.identity),
            }
            let action = cells
                .borrow()
                .get(usize::try_from(index).unwrap_or(usize::MAX))
                .copied()
                .unwrap_or(ScanAction::Skip);
            match action {
                ScanAction::Skip => ProcessCallbackCell::Skip,
                ScanAction::Claim => ProcessCallbackCell::Claim(index),
                ScanAction::Join => ProcessCallbackCell::Join(index),
                ScanAction::ObserveCompleted(_) => ProcessCallbackCell::Completed(index),
                ScanAction::ObserveBlocked(_) => ProcessCallbackCell::Blocked(index),
            }
        },
        |guard, index| {
            let mut trace = trace.borrow_mut();
            if trace.guard_identity != Some(guard.identity) {
                trace.one_guard = false;
            }
            trace.restarts = trace.restarts.saturating_add(1);
            trace.last_matching_cell = usize::try_from(index).ok();
            if let Some(cell) = cells
                .borrow_mut()
                .get_mut(usize::try_from(index).unwrap_or(usize::MAX))
            {
                // Model the out-of-lock handler discharging this exact
                // observation.  The subsequent restart genuinely re-observes
                // it as empty; no separate `done` bitmap can hide a live row.
                *cell = ScanAction::Skip;
            }
        },
    );
    if let Some(guard) = admitted {
        admission.release(guard);
    }
    let mut trace = trace.into_inner();
    trace.refused = trace.guard_identity.is_none();
    trace
}

/// What CLEANUP does with a control binding whose phase it already claimed.
///
/// The point of the enum is the *negative* space: three of these six routes
/// answer a closing generation without resolving a cell or projecting a control
/// context at all, which is what makes a late CLEANUP safe against cell reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupRoute {
    /// No SETUP ever ran on this file.
    Empty,
    /// A precommit SETUP is being cancelled; there is no session generation.
    Setup,
    /// This file owns the live generation: contend for the terminal claim.
    ClaimTerminal(SessionLocator),
    /// Another source already won: join that exact generation's rendezvous.
    JoinTerminal(SessionLocator),
    /// The finalizer already published; read the stable record.
    CompletedRecord {
        generation: u64,
        result: TerminalResult,
    },
    /// A permanent fail-stop. CLEANUP reports it and frees nothing.
    Blocked(SessionLocator),
    /// A durably retained generation without an ordinary published outcome.
    OpaqueRetained(SessionLocator),
    /// CLEANUP already ran on this file.
    AlreadyClosed,
}

impl CleanupRoute {
    /// Whether this route must resolve the locator against a registry cell.
    ///
    /// `CompletedRecord` deliberately does not: the generation it names may
    /// already have been deleted and its cell reused, so a route that resolved
    /// it would either fail or answer about a different session.
    pub const fn resolves_a_cell(&self) -> bool {
        matches!(self, Self::ClaimTerminal(_) | Self::JoinTerminal(_))
    }

    /// Whether this route projects the recorded control context.
    ///
    /// Only the winning claim does, and only after it has moved the binding to
    /// ClosingLive under the registry lock.
    pub const fn projects_the_control_context(&self) -> bool {
        matches!(self, Self::ClaimTerminal(_))
    }

    /// Whether this route may free the control context.
    ///
    /// None of them may: CLOSE is the sole deallocator. `Blocked` is the case
    /// worth naming, because its context stays cell-owned forever.
    pub const fn frees_the_control_context(&self) -> bool {
        false
    }
}

/// A control-binding claim, translated into the route CLEANUP will run.
///
/// The translation is total and lives in core so the native dispatcher cannot
/// invent a seventh route or reorder two of them.
pub const fn decide_cleanup_route(claim: &crate::session::CleanupBindingClaim) -> CleanupRoute {
    use crate::session::CleanupBindingClaim;
    match claim {
        CleanupBindingClaim::Empty => CleanupRoute::Empty,
        CleanupBindingClaim::Setup(_) => CleanupRoute::Setup,
        CleanupBindingClaim::NeedsLiveClaim(locator) => CleanupRoute::ClaimTerminal(*locator),
        CleanupBindingClaim::JoinLive(locator) => CleanupRoute::JoinTerminal(*locator),
        CleanupBindingClaim::Completed { generation, result } => CleanupRoute::CompletedRecord {
            generation: *generation,
            result: *result,
        },
        CleanupBindingClaim::Blocked { locator, .. } => CleanupRoute::Blocked(*locator),
        CleanupBindingClaim::OpaqueRetained { locator } => CleanupRoute::OpaqueRetained(*locator),
        CleanupBindingClaim::AlreadyClosed => CleanupRoute::AlreadyClosed,
    }
}

/// Which of CLEANUP's at most two committed-route passes is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupPass {
    /// The pass taken on arrival.
    First,
    /// The one claim after terminal work. This is the pass that finds
    /// `ClosingComplete` and acknowledges the finalizer's record.
    Reclaim,
}

/// How a terminal the CLEANUP route ran or joined ended, without its payload.
///
/// There is no `NotLive`. Round 18 carried one, mapped from
/// `fsring-fsd`'s `TerminalOutcome::NotLive`, and `continue_cleanup` answered
/// `ReclaimOnce` for it -- a row nothing in production could reach and nothing
/// could falsify, which would have stranded the context if it ever fired
/// (native review N18-5). Measuring `fsring-fsd`'s dead code showed why it was
/// unreachable: the variant is constructed only in `run_terminal_arrival`,
/// which has no production caller (round 19 wrote "never constructed", which
/// round-20 native review N4 showed false). The driver maps it to
/// `CleanupRouteResult::Refused`, which is what "nothing was claimed" means on
/// the CLEANUP route. In `run_terminal_arrival` it means nothing was claimed
/// AND the generation may still be live, so wiring that entry means deciding
/// this mapping again rather than inheriting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalOutcomeKind {
    Completed,
    Blocked,
}

/// What one committed-route pass produced, without its affine payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupRouteResult {
    /// The pass ran or joined terminal work to this outcome.
    Terminal(TerminalOutcomeKind),
    /// The finalizer's record became the close right inside the claiming hold.
    CompletedAcknowledged,
    Blocked,
    OpaqueRetained,
    AlreadyClosed,
    Empty,
    Setup,
    /// The claim, the terminal preparation or the acknowledgement refused.
    Refused,
}

/// What CLEANUP does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupContinuation {
    /// Claim the binding once more: the terminal published, and its record is
    /// waiting for this CLEANUP to acknowledge it.
    ReclaimOnce,
    Proceed,
    Refuse,
}

/// The total continuation of CLEANUP's committed route.
///
/// Lives in core for the same reason `decide_cleanup_route` does: `fsring-fsd`
/// has no host test target, and this is the decision whose absence stranded
/// every published session's context. A pass that ran or joined terminal work
/// consumed its binding claim before that work, so without a second claim
/// nothing observes the `ClosingComplete` the finalizer published, the record
/// is never acknowledged, and CLOSE -- which frees only an acknowledged context
/// -- can free nothing.
pub const fn continue_cleanup(
    pass: CleanupPass,
    result: CleanupRouteResult,
) -> CleanupContinuation {
    use CleanupContinuation::{Proceed, ReclaimOnce, Refuse};
    match (pass, result) {
        (CleanupPass::First, CleanupRouteResult::Terminal(TerminalOutcomeKind::Completed)) => {
            ReclaimOnce
        }
        (_, CleanupRouteResult::Terminal(TerminalOutcomeKind::Blocked)) => Refuse,
        // A terminal found by the reclaim is an invariant break, never a
        // reason for a third pass.
        (CleanupPass::Reclaim, CleanupRouteResult::Terminal(_)) => Refuse,
        (_, CleanupRouteResult::CompletedAcknowledged) => Proceed,
        (_, CleanupRouteResult::Blocked | CleanupRouteResult::OpaqueRetained) => Refuse,
        // First-pass answers unchanged from the route this replaces.
        (
            CleanupPass::First,
            CleanupRouteResult::AlreadyClosed
            | CleanupRouteResult::Empty
            | CleanupRouteResult::Setup
            | CleanupRouteResult::Refused,
        ) => Proceed,
        // After a completed terminal the reclaim must find the record. Anything
        // else means it is gone unacknowledged.
        (
            CleanupPass::Reclaim,
            CleanupRouteResult::AlreadyClosed
            | CleanupRouteResult::Empty
            | CleanupRouteResult::Setup
            | CleanupRouteResult::Refused,
        ) => Refuse,
    }
}

/// The ordered actions one terminal arrival performs around its claim.
///
/// Order is the whole content: a winner that still holds the outer file
/// rundown when it runs terminal work deadlocks against the fence's own wait
/// for that rundown, and a joiner that still holds it deadlocks against the
/// winner. Both are invisible to a type checker and to any test that only
/// inspects the final state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalRouteStep {
    /// Take the registry lock and run the prepared claim.
    ClaimUnderRegistryLock,
    /// Drop every short guard the dispatcher still owns.
    ReleaseOuterFileRundown,
    /// The winner runs the terminal sequence.
    RunTerminal,
    /// A joiner (or a winner parked on an Open residual) waits on the event.
    WaitTerminalOutcome,
    /// Copy the published outcome and release join accounting.
    AcknowledgeOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalRouteKind {
    Winner,
    Join,
}

#[derive(Clone, Copy, Default)]
struct TerminalRouteRecord {
    claimed: Option<u8>,
    outer_released: Option<u8>,
    ran: Option<u8>,
    waited: Option<u8>,
    acknowledged: Option<u8>,
}

pub struct PendingTerminalRouteStep {
    roster: [TerminalRouteStep; 4],
    next: u8,
    step: TerminalRouteStep,
    record: TerminalRouteRecord,
}

pub struct TerminalRouteProof {
    kind: TerminalRouteKind,
    record: TerminalRouteRecord,
}

pub enum TerminalRouteProgress {
    Step(PendingTerminalRouteStep),
    Complete(TerminalRouteProof),
}

pub struct TerminalRoutePlan;

impl TerminalRoutePlan {
    pub const WINNER_STEPS: [TerminalRouteStep; 4] = [
        TerminalRouteStep::ClaimUnderRegistryLock,
        TerminalRouteStep::ReleaseOuterFileRundown,
        TerminalRouteStep::RunTerminal,
        TerminalRouteStep::AcknowledgeOutcome,
    ];

    pub const JOIN_STEPS: [TerminalRouteStep; 4] = [
        TerminalRouteStep::ClaimUnderRegistryLock,
        TerminalRouteStep::ReleaseOuterFileRundown,
        TerminalRouteStep::WaitTerminalOutcome,
        TerminalRouteStep::AcknowledgeOutcome,
    ];

    pub const fn begin(kind: TerminalRouteKind) -> TerminalRouteProgress {
        Self::begin_inner(
            kind,
            match kind {
                TerminalRouteKind::Winner => Self::WINNER_STEPS,
                TerminalRouteKind::Join => Self::JOIN_STEPS,
            },
        )
    }

    /// Begin from an explicit roster.
    ///
    /// Production has exactly one roster per kind. Tests drive deliberately
    /// wrong orders through this seam so the proofs below can be observed
    /// reporting `false`; without it every proof could be `true` unconditionally
    /// and no test would notice.
    #[cfg(test)]
    pub(crate) const fn begin_with_roster(
        kind: TerminalRouteKind,
        roster: [TerminalRouteStep; 4],
    ) -> TerminalRouteProgress {
        Self::begin_inner(kind, roster)
    }

    const fn begin_inner(
        kind: TerminalRouteKind,
        roster: [TerminalRouteStep; 4],
    ) -> TerminalRouteProgress {
        let _ = kind;
        TerminalRouteProgress::Step(PendingTerminalRouteStep {
            roster,
            next: 0,
            step: roster[0],
            record: TerminalRouteRecord {
                claimed: None,
                outer_released: None,
                ran: None,
                waited: None,
                acknowledged: None,
            },
        })
    }
}

impl PendingTerminalRouteStep {
    pub const fn step(&self) -> TerminalRouteStep {
        self.step
    }

    pub fn performed(mut self, kind: TerminalRouteKind) -> TerminalRouteProgress {
        let at = self.next;
        match self.step {
            TerminalRouteStep::ClaimUnderRegistryLock => self.record.claimed = Some(at),
            TerminalRouteStep::ReleaseOuterFileRundown => self.record.outer_released = Some(at),
            TerminalRouteStep::RunTerminal => self.record.ran = Some(at),
            TerminalRouteStep::WaitTerminalOutcome => self.record.waited = Some(at),
            TerminalRouteStep::AcknowledgeOutcome => self.record.acknowledged = Some(at),
        }
        self.next = self.next.saturating_add(1);
        match self.roster.get(usize::from(self.next)) {
            Some(step) => {
                self.step = *step;
                TerminalRouteProgress::Step(self)
            }
            None => TerminalRouteProgress::Complete(TerminalRouteProof {
                kind,
                record: self.record,
            }),
        }
    }
}

impl TerminalRouteProof {
    pub const fn kind(&self) -> TerminalRouteKind {
        self.kind
    }

    /// The claim was taken before anything else happened.
    pub const fn claimed_first(&self) -> bool {
        match self.record.claimed {
            Some(at) => at == 0,
            None => false,
        }
    }

    /// No terminal work ran while the dispatcher still held its outer rundown.
    pub const fn released_outer_before_running(&self) -> bool {
        match (self.record.outer_released, self.record.ran) {
            (Some(released), Some(ran)) => released < ran,
            // A route that never ran cannot violate this; a route that ran
            // without releasing must.
            (_, None) => true,
            (None, Some(_)) => false,
        }
    }

    /// No arrival waited while it still held its outer rundown.
    pub const fn released_outer_before_waiting(&self) -> bool {
        match (self.record.outer_released, self.record.waited) {
            (Some(released), Some(waited)) => released < waited,
            (_, None) => true,
            (None, Some(_)) => false,
        }
    }

    /// The outcome was acknowledged last.
    pub const fn acknowledged_last(&self) -> bool {
        match (
            self.record.acknowledged,
            self.record.ran,
            self.record.waited,
        ) {
            (Some(at), Some(ran), _) => at > ran,
            (Some(at), None, Some(waited)) => at > waited,
            _ => false,
        }
    }
}

/// What an admitted arrival does after waking on the terminal-outcome event.
///
/// `Open` is the safety-over-liveness result: the runner parked a transient
/// residual, so the arrival goes back to the wait loop still counted. It is
/// deliberately not a completion and not a timeout.
#[derive(Debug)]
pub enum TerminalWaitDisposition {
    Open(crate::session::TerminalJoinTicket),
    Completed {
        result: TerminalResult,
        drained: Option<crate::session::TerminalJoinersDrainedSignal>,
    },
    Blocked {
        blocked: TerminalBlocked,
        drained: Option<crate::session::TerminalJoinersDrainedSignal>,
    },
}

/// The short guards an arrival must have given up before it may wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalWaitPreconditions {
    pub outer_file_rundown_released: bool,
    pub session_access_guard_released: bool,
    pub registry_lock_released: bool,
}

/// Whether a counted arrival is allowed to block on the outcome event.
///
/// A wait taken with any of these still held is the deadlock this whole
/// checkpoint exists to prevent, so the decision is a value the native waiter
/// must consult rather than a comment above its call site.
pub const fn decide_terminal_wait(pre: TerminalWaitPreconditions) -> Result<(), LifecycleError> {
    if pre.outer_file_rundown_released
        && pre.session_access_guard_released
        && pre.registry_lock_released
    {
        Ok(())
    } else {
        Err(LifecycleError::WrongState)
    }
}

/// Translate one locked release of a counted arrival into its disposition.
///
/// The signal decision is returned rather than performed: `joiners_drained` is
/// signalled after the registry lock is dropped, and a model that performed it
/// here would be describing an operation the native caller must not do yet.
pub fn resolve_terminal_release(
    release: crate::session::TerminalJoinRelease,
) -> TerminalWaitDisposition {
    use crate::session::{TerminalClosedOutcome, TerminalJoinRelease};
    match release {
        TerminalJoinRelease::Open(ticket) => TerminalWaitDisposition::Open(ticket),
        TerminalJoinRelease::Released {
            outcome: TerminalClosedOutcome::Completed(result),
            drained,
        } => TerminalWaitDisposition::Completed { result, drained },
        TerminalJoinRelease::Released {
            outcome: TerminalClosedOutcome::Blocked(blocked),
            drained,
        } => TerminalWaitDisposition::Blocked { blocked, drained },
    }
}

/// How a woken arrival reports a `Blocked` generation to its own caller.
///
/// Every ordinary arrival substitutes `STATUS_INVALID_DEVICE_STATE`/zero.
/// Unload alone must not return: a blocked generation still owns callback-
/// visible state, so returning would let the image unload under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedArrivalAction {
    ReportInvalidDeviceState,
    BlockForever,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalArrivalSource {
    Cleanup,
    ProcessLoss,
    CompleteAfterTerminal,
    Unload,
}

pub const fn decide_blocked_arrival(source: TerminalArrivalSource) -> BlockedArrivalAction {
    match source {
        TerminalArrivalSource::Cleanup
        | TerminalArrivalSource::ProcessLoss
        | TerminalArrivalSource::CompleteAfterTerminal => {
            BlockedArrivalAction::ReportInvalidDeviceState
        }
        TerminalArrivalSource::Unload => BlockedArrivalAction::BlockForever,
    }
}

private_authority_seals!(
    PrivateReleasedCommittedProtocolAuthority,
    PrivateMountJoinAuthority,
    PrivateMountResetJoinAuthority,
    PrivateMountTeardownAuthority,
    PrivateMountDrainAuthority,
    PrivateMountWaitersDrainedAuthority,
    PrivateMountCompleteSignalAuthority,
    PrivateMountWaitersDrainedSignalAuthority,
    PrivateMountCompleteAcknowledgementAuthority,
    PrivateMountWaitersDrainedAcknowledgementAuthority,
    PrivateMountResetAuthority,
    PrivateJoinedMountResetAuthority,
    PrivateMountResetCompleteSignalAuthority,
    PrivateMountResetWaitersDrainedSignalAuthority,
    PrivateMountResetCompleteAcknowledgementAuthority,
    PrivateMountResetWaitersDrainedAcknowledgementAuthority,
    PrivateMountAbsentAuthority,
    PrivateMountActivationAuthority,
    PrivateMountInstallAuthority,
    PrivateMountPublicationAuthority,
    PrivateOwnerMountCompletionAuthority,
    PrivateJoinedMountCompletionAuthority,
    PrivateResetJoinedMountCompletionAuthority,
);

#[derive(Debug)]
pub struct MountOwner<Device, Vpb> {
    locator: SessionLocator,
    /// Zero only on the test-only pre-install carrier. Production mints a
    /// nonzero generation from `PreparedMountInstall` when it constructs the
    /// owner stored by the rendezvous.
    mount_generation: u64,
    reference: StrongSessionRef,
    mounted: Device,
    vpb: Vpb,
}

impl<Device, Vpb> MountOwner<Device, Vpb> {
    #[cfg(test)]
    #[allow(clippy::result_large_err)]
    pub fn try_new(
        locator: SessionLocator,
        reference: StrongSessionRef,
        mounted: Device,
        vpb: Vpb,
    ) -> Result<Self, (LifecycleError, StrongSessionRef, Device, Vpb)> {
        if reference.locator() != locator {
            return Err((LifecycleError::WrongLocator, reference, mounted, vpb));
        }
        Ok(Self {
            locator,
            mount_generation: 0,
            reference,
            mounted,
            vpb,
        })
    }

    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (StrongSessionRef, Device, Vpb) {
        (self.reference, self.mounted, self.vpb)
    }
}

/// The three destructive native operations owned by one R3 mount claim.
///
/// Keeping these operations named prevents a recording trace from proving a
/// test-only copy of the teardown. Production and the WDK-free fake both pass
/// through [`run_r3_mount_owner_teardown_prefix`], which consumes the affine
/// owner before returning the exact teardown continuation.
pub trait R3MountOwnerTeardownOps<Device, Vpb> {
    fn clear_vpb_binding(&mut self, vpb: Vpb);
    fn delete_mounted_device(&mut self, mounted: Device);
    fn release_mount_reference(&mut self, reference: StrongSessionRef);
}

/// Consume one authentic mount owner through its nonreplayable native prefix.
///
/// A cross-wired owner/right pair is rejected before any operation runs and
/// both authorities are returned intact. Once the first operation runs there
/// is no refusal channel: the returned [`MountTeardownRight`] is the typed
/// continuation into Done publication and the later late-Join drain loop.
#[allow(clippy::result_large_err)]
pub fn run_r3_mount_owner_teardown_prefix<Device, Vpb>(
    owner: MountOwner<Device, Vpb>,
    teardown: MountTeardownRight,
    native: &mut impl R3MountOwnerTeardownOps<Device, Vpb>,
) -> Result<MountTeardownRight, (LifecycleError, MountOwner<Device, Vpb>, MountTeardownRight)> {
    if owner.locator != teardown.locator || owner.mount_generation != teardown.mount_generation {
        return Err((LifecycleError::WrongLocator, owner, teardown));
    }

    let MountOwner {
        locator: _,
        mount_generation: _,
        reference,
        mounted,
        vpb,
    } = owner;
    native.clear_vpb_binding(vpb);
    native.delete_mounted_device(mounted);
    native.release_mount_reference(reference);
    Ok(teardown)
}

#[derive(Debug)]
pub struct MountJoinTicket {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountJoinAuthority,
}

#[derive(Debug)]
pub struct MountResetJoinTicket {
    locator: SessionLocator,
    mount_generation: u64,
    origin: MountJoinOrigin,
    authority: PrivateMountResetJoinAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountJoinOrigin {
    Ordinary,
    Reset,
}

#[derive(Debug)]
pub struct MountTeardownRight {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountTeardownAuthority,
}

#[derive(Debug)]
pub struct MountDrainRight {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountDrainAuthority,
}

#[derive(Debug)]
pub struct MountWaitersDrainedProof {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountWaitersDrainedAuthority,
}

#[derive(Debug)]
pub struct PreparedMountReset {
    drain: MountDrainRight,
    waiters: MountWaitersDrainedProof,
}

macro_rules! mount_generation_observers {
    ($($name:ident),+ $(,)?) => {
        $(
            impl $name {
                pub const fn locator(&self) -> SessionLocator {
                    self.locator
                }

                pub const fn mount_generation(&self) -> u64 {
                    self.mount_generation
                }
            }
        )+
    };
}

mount_generation_observers!(
    MountJoinTicket,
    MountResetJoinTicket,
    MountTeardownRight,
    MountDrainRight,
    MountWaitersDrainedProof,
    MountResetProof,
    JoinedMountResetProof,
);

/// The mutation-free outcome of a mount-activation preflight.
///
/// It names the exact locator whose rendezvous was observed `Inactive` and is
/// the only value `commit_prepared_activation` accepts. It is not `Clone` or
/// `Copy`, has no public constructor, and cannot be minted from a locator, so
/// the locked SETUP suffix cannot activate a mount it never preflighted.
#[derive(Debug)]
pub struct PreparedMountActivation {
    locator: SessionLocator,
    authority: PrivateMountActivationAuthority,
}

/// Mutation-free authorization to install one exact mount generation.
///
/// The owner pieces remain with the caller during preflight. The native
/// adapter can therefore refuse and run its existing reverse rollback without
/// first extracting any owner from the mount context.
#[derive(Debug)]
pub struct PreparedMountInstall {
    locator: SessionLocator,
    mount_generation: u64,
    publication_id: NonZeroU64,
    authority: PrivateMountInstallAuthority,
}

/// One-shot receipt that the complete owner is now registry-visible.
///
/// It is intentionally neither `Clone` nor `Copy`: the immediately following
/// flag-clear step consumes the native wrapper around this receipt, and there
/// is no post-publication rollback route.
#[derive(Debug)]
pub struct MountOwnerPublication {
    locator: SessionLocator,
    mount_generation: u64,
    publication_id: NonZeroU64,
    authority: PrivateMountPublicationAuthority,
}

impl MountOwnerPublication {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.locator
    }

    pub const fn mount_generation(&self) -> u64 {
        self.mount_generation
    }
}

impl PreparedMountActivation {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

#[derive(Debug)]
pub struct MountResetProof {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountResetAuthority,
}

#[derive(Debug)]
pub struct JoinedMountResetProof {
    locator: SessionLocator,
    mount_generation: u64,
    origin: MountJoinOrigin,
    authority: PrivateJoinedMountResetAuthority,
}

#[derive(Debug)]
pub struct OwnerMountCompletion {
    locator: SessionLocator,
    mount_generation: u64,
    cursor: MountAbsenceCursor,
    authority: PrivateOwnerMountCompletionAuthority,
}

#[derive(Debug)]
pub struct JoinedMountGenerationCompletion {
    locator: SessionLocator,
    mount_generation: u64,
    cursor: MountAbsenceCursor,
    authority: PrivateJoinedMountCompletionAuthority,
}

#[derive(Debug)]
pub struct ResetJoinedMountGenerationCompletion {
    locator: SessionLocator,
    mount_generation: u64,
    cursor: MountAbsenceCursor,
    authority: PrivateResetJoinedMountCompletionAuthority,
}

#[derive(Debug)]
pub enum JoinedMountCompletion {
    Join(JoinedMountGenerationCompletion),
    ResetJoin(ResetJoinedMountGenerationCompletion),
}

macro_rules! mount_completion_observers {
    ($name:ident) => {
        impl $name {
            pub const fn locator(&self) -> SessionLocator {
                let _authority = &self.authority;
                self.locator
            }

            pub const fn mount_generation(&self) -> u64 {
                self.mount_generation
            }

            pub const fn cursor(&self) -> MountAbsenceCursor {
                self.cursor
            }
        }
    };
}

mount_completion_observers!(OwnerMountCompletion);
mount_completion_observers!(JoinedMountGenerationCompletion);
mount_completion_observers!(ResetJoinedMountGenerationCompletion);

#[derive(Debug)]
pub struct MountAbsentProof {
    locator: SessionLocator,
    cursor: MountAbsenceCursor,
    authority: PrivateMountAbsentAuthority,
}

#[derive(Debug)]
pub struct MountCompleteSignal {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountCompleteSignalAuthority,
}

#[derive(Debug)]
pub struct MountWaitersDrainedSignal {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountWaitersDrainedSignalAuthority,
}

#[derive(Debug)]
pub struct MountResetCompleteSignal {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountResetCompleteSignalAuthority,
}

#[derive(Debug)]
pub struct MountResetWaitersDrainedSignal {
    locator: SessionLocator,
    mount_generation: u64,
    authority: PrivateMountResetWaitersDrainedSignalAuthority,
}

#[derive(Debug)]
pub struct MountDonePublication {
    drain: MountDrainRight,
    signal: MountCompleteSignal,
}

#[derive(Debug)]
pub struct MountJoinConversion {
    reset_ticket: MountResetJoinTicket,
    drained_signal: Option<MountWaitersDrainedSignal>,
}

#[derive(Debug)]
pub struct MountResetPublication {
    owner_proof: MountResetProof,
    signal: MountResetCompleteSignal,
}

#[derive(Debug)]
pub struct MountResetJoinRelease {
    joined_proof: JoinedMountResetProof,
    drained_signal: Option<MountResetWaitersDrainedSignal>,
}

#[derive(Debug)]
pub struct MountDoneAcknowledgement {
    drain: MountDrainRight,
    authority: PrivateMountCompleteAcknowledgementAuthority,
}

#[derive(Debug)]
pub struct MountJoinAcknowledgement {
    reset_ticket: MountResetJoinTicket,
    signaled: bool,
    authority: PrivateMountWaitersDrainedAcknowledgementAuthority,
}

#[derive(Debug)]
pub struct MountResetAcknowledgement {
    owner_proof: MountResetProof,
    authority: PrivateMountResetCompleteAcknowledgementAuthority,
}

#[derive(Debug)]
pub struct MountResetJoinAcknowledgement {
    joined_proof: JoinedMountResetProof,
    signaled: bool,
    authority: PrivateMountResetWaitersDrainedAcknowledgementAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountWaitEvent {
    Complete,
    OrdinaryWaitersDrained,
    ResetComplete,
    ResetWaitersDrained,
}

/// Copy-only address of the exact permanent-cell event one affine right may
/// wait on. It carries no continuation authority and cannot complete a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountWaitObservation {
    locator: SessionLocator,
    mount_generation: u64,
    event: MountWaitEvent,
}

mod mount_publication_kind_seal {
    pub(super) const DONE: u8 = 0;
    pub(super) const JOIN_CONVERSION: u8 = 1;
    pub(super) const RESET: u8 = 2;
    pub(super) const RESET_JOIN_RELEASE: u8 = 3;

    pub trait Sealed {
        const KIND: u8;
    }
}

/// Sealed type-level identity of one mount publication protocol step.
pub trait MountPublicationKind: mount_publication_kind_seal::Sealed + Copy {}

macro_rules! mount_publication_kinds {
    ($($name:ident => $kind:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, PartialEq, Eq)]
            pub enum $name {}

            impl mount_publication_kind_seal::Sealed for $name {
                const KIND: u8 = mount_publication_kind_seal::$kind;
            }

            impl MountPublicationKind for $name {}
        )+
    };
}

mount_publication_kinds!(
    MountDonePublicationKind => DONE,
    MountJoinConversionKind => JOIN_CONVERSION,
    MountResetPublicationKind => RESET,
    MountResetJoinReleaseKind => RESET_JOIN_RELEASE,
);

/// Copy-only address of the exact permanent-cell event one typed publication
/// may signal. `None` records that a non-last waiter conversion has no signal.
/// It carries no signal, acknowledgement, or continuation authority.
///
/// This is a validation address, not a publication-instance identity. Two
/// same-kind non-last conversions in one generation may produce equal `None`
/// observations: those acknowledgements commute, while each original affine
/// bundle retains its own reset ticket or joined proof. A caller must package
/// and consume that exact bundle; the observation alone cannot acknowledge it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MountPublicationObservation<Kind: MountPublicationKind> {
    locator: SessionLocator,
    mount_generation: u64,
    event: Option<MountWaitEvent>,
    kind: PhantomData<fn() -> Kind>,
}

impl MountWaitObservation {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn event(&self) -> MountWaitEvent {
        self.event
    }
}

impl<Kind: MountPublicationKind> MountPublicationObservation<Kind> {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn event(&self) -> Option<MountWaitEvent> {
        self.event
    }
}

impl MountDonePublication {
    pub const fn publication_observation(
        &self,
    ) -> MountPublicationObservation<MountDonePublicationKind> {
        MountPublicationObservation {
            locator: self.signal.locator,
            mount_generation: self.signal.mount_generation,
            event: Some(MountWaitEvent::Complete),
            kind: PhantomData,
        }
    }
}

impl MountJoinConversion {
    pub const fn publication_observation(
        &self,
    ) -> MountPublicationObservation<MountJoinConversionKind> {
        MountPublicationObservation {
            locator: self.reset_ticket.locator,
            mount_generation: self.reset_ticket.mount_generation,
            event: if self.drained_signal.is_some() {
                Some(MountWaitEvent::OrdinaryWaitersDrained)
            } else {
                None
            },
            kind: PhantomData,
        }
    }
}

impl MountResetPublication {
    pub const fn publication_observation(
        &self,
    ) -> MountPublicationObservation<MountResetPublicationKind> {
        MountPublicationObservation {
            locator: self.signal.locator,
            mount_generation: self.signal.mount_generation,
            event: Some(MountWaitEvent::ResetComplete),
            kind: PhantomData,
        }
    }
}

impl MountResetJoinRelease {
    pub const fn publication_observation(
        &self,
    ) -> MountPublicationObservation<MountResetJoinReleaseKind> {
        MountPublicationObservation {
            locator: self.joined_proof.locator,
            mount_generation: self.joined_proof.mount_generation,
            event: if self.drained_signal.is_some() {
                Some(MountWaitEvent::ResetWaitersDrained)
            } else {
                None
            },
            kind: PhantomData,
        }
    }
}

macro_rules! mount_wait_observer {
    ($name:ident, $event:expr) => {
        impl $name {
            pub const fn wait_observation(&self) -> MountWaitObservation {
                MountWaitObservation {
                    locator: self.locator,
                    mount_generation: self.mount_generation,
                    event: $event,
                }
            }
        }
    };
}

mount_wait_observer!(MountJoinTicket, MountWaitEvent::Complete);
mount_wait_observer!(MountDrainRight, MountWaitEvent::OrdinaryWaitersDrained);
mount_wait_observer!(MountResetJoinTicket, MountWaitEvent::ResetComplete);
mount_wait_observer!(MountResetProof, MountWaitEvent::ResetWaitersDrained);
mount_wait_observer!(JoinedMountResetProof, MountWaitEvent::ResetWaitersDrained);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedMountTeardown {
    Owner {
        locator: SessionLocator,
        mount_generation: u64,
    },
    Join {
        locator: SessionLocator,
        mount_generation: u64,
    },
    Absent {
        locator: SessionLocator,
        cursor: MountAbsenceCursor,
    },
}

impl ExpectedMountTeardown {
    pub const fn locator(&self) -> SessionLocator {
        match self {
            Self::Owner { locator, .. }
            | Self::Join { locator, .. }
            | Self::Absent { locator, .. } => *locator,
        }
    }

    /// The active generation for an Owner or Join expectation.
    ///
    /// Absence has no active generation. Its exact `Next`/`Exhausted` answer
    /// is available only through [`Self::cursor`], so the discriminant cannot
    /// be collapsed into a numeric sentinel.
    pub const fn mount_generation(&self) -> Option<u64> {
        match self {
            Self::Owner {
                mount_generation, ..
            }
            | Self::Join {
                mount_generation, ..
            } => Some(*mount_generation),
            Self::Absent { .. } => None,
        }
    }

    pub const fn cursor(&self) -> Option<MountAbsenceCursor> {
        match self {
            Self::Absent { cursor, .. } => Some(*cursor),
            Self::Owner { .. } | Self::Join { .. } => None,
        }
    }
}

/// Whether an absent mount can still be reused, or is permanently exhausted.
///
/// A cell whose mount generation cannot be incremented is retired rather than
/// wrapped, and the two answers are different values rather than one value plus
/// a sentinel: a reader that treated exhaustion as "next generation `0`" would
/// reuse the one generation the design forbids reusing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountAbsenceCursor {
    Next(u64),
    Exhausted,
}

impl MountAbsentProof {
    pub const fn locator(&self) -> SessionLocator {
        let _authority = &self.authority;
        self.locator
    }

    /// Build an absence proof directly.
    ///
    /// The rendezvous mints these only after its counts reach zero and its
    /// signal bits clear, which a test cannot reach without driving a whole
    /// teardown. The cursor rule is a property of the *value*, so it needs a
    /// value the test can name.
    #[cfg(test)]
    pub(crate) const fn for_test(locator: SessionLocator, cursor: MountAbsenceCursor) -> Self {
        Self {
            locator,
            cursor,
            authority: PrivateMountAbsentAuthority(()),
        }
    }

    /// The exact cursor this absence proof carries.
    ///
    /// `Next(u64::MAX)` remains installable. Only after generation `u64::MAX`
    /// completes does the rendezvous report `Exhausted`.
    pub const fn cursor(&self) -> MountAbsenceCursor {
        self.cursor
    }
}

pub enum MountClaim<Device, Vpb> {
    Owner {
        owner: MountOwner<Device, Vpb>,
        teardown: MountTeardownRight,
        expected: ExpectedMountTeardown,
    },
    Join {
        ticket: MountJoinTicket,
        expected: ExpectedMountTeardown,
    },
    ResetJoin {
        ticket: MountResetJoinTicket,
        expected: ExpectedMountTeardown,
    },
    Absent {
        expected: ExpectedMountTeardown,
        completed: MountAbsentProof,
    },
}

pub struct MountRendezvous<Device, Vpb> {
    state: PrivateMountRendezvousState<Device, Vpb>,
    ordinary_waiters: u32,
    reset_waiters: u32,
    last_completed_generation: Option<u64>,
    mount_complete_signal_pending: bool,
    ordinary_drained_signal_pending: bool,
    reset_complete_signal_pending: bool,
    reset_waiters_drained_signal_pending: bool,
}

enum PrivateMountRendezvousState<Device, Vpb> {
    Inactive,
    Unmounted {
        locator: SessionLocator,
        next_generation: Option<NonZeroU64>,
    },
    Publishing {
        generation: u64,
        publication_id: NonZeroU64,
        owner: MountOwner<Device, Vpb>,
    },
    Present {
        generation: u64,
        owner: MountOwner<Device, Vpb>,
    },
    TearingDown {
        locator: SessionLocator,
        generation: u64,
    },
    Done {
        locator: SessionLocator,
        generation: u64,
    },
    Resetting {
        locator: SessionLocator,
        generation: u64,
    },
    Exhausted {
        locator: SessionLocator,
    },
}

static NEXT_MOUNT_PUBLICATION_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_mount_publication_id() -> Result<NonZeroU64, LifecycleError> {
    NEXT_MOUNT_PUBLICATION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            if current == 0 {
                None
            } else {
                current.checked_add(1).or(Some(0))
            }
        })
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(LifecycleError::GenerationExhausted)
}

impl MountDonePublication {
    /// # Safety
    /// The callback synchronously signals the matching permanent cell's event
    /// exactly once before returning.
    #[doc(hidden)]
    unsafe fn signal_then_ack(
        self,
        signal: impl FnOnce(&MountCompleteSignal),
    ) -> MountDoneAcknowledgement {
        signal(&self.signal);
        let MountCompleteSignal {
            locator,
            mount_generation,
            authority: PrivateMountCompleteSignalAuthority(()),
        } = self.signal;
        debug_assert_eq!(locator, self.drain.locator);
        debug_assert_eq!(mount_generation, self.drain.mount_generation);
        MountDoneAcknowledgement {
            drain: self.drain,
            authority: PrivateMountCompleteAcknowledgementAuthority(()),
        }
    }
}

impl MountJoinConversion {
    /// # Safety
    /// If present, the callback synchronously signals the matching permanent
    /// cell's ordinary-drained event exactly once before returning.
    #[doc(hidden)]
    unsafe fn signal_then_ack(
        self,
        signal: impl FnOnce(&MountWaitersDrainedSignal),
    ) -> MountJoinAcknowledgement {
        let signaled = match self.drained_signal {
            Some(drained) => {
                signal(&drained);
                let MountWaitersDrainedSignal {
                    locator,
                    mount_generation,
                    authority: PrivateMountWaitersDrainedSignalAuthority(()),
                } = drained;
                debug_assert_eq!(locator, self.reset_ticket.locator);
                debug_assert_eq!(mount_generation, self.reset_ticket.mount_generation);
                true
            }
            None => false,
        };
        MountJoinAcknowledgement {
            reset_ticket: self.reset_ticket,
            signaled,
            authority: PrivateMountWaitersDrainedAcknowledgementAuthority(()),
        }
    }
}

impl MountResetPublication {
    /// # Safety
    /// The callback synchronously signals the matching permanent cell's reset
    /// event exactly once before returning.
    #[doc(hidden)]
    unsafe fn signal_then_ack(
        self,
        signal: impl FnOnce(&MountResetCompleteSignal),
    ) -> MountResetAcknowledgement {
        signal(&self.signal);
        let MountResetCompleteSignal {
            locator,
            mount_generation,
            authority: PrivateMountResetCompleteSignalAuthority(()),
        } = self.signal;
        debug_assert_eq!(locator, self.owner_proof.locator);
        debug_assert_eq!(mount_generation, self.owner_proof.mount_generation);
        MountResetAcknowledgement {
            owner_proof: self.owner_proof,
            authority: PrivateMountResetCompleteAcknowledgementAuthority(()),
        }
    }
}

impl MountResetJoinRelease {
    /// # Safety
    /// If present, the callback synchronously signals the matching permanent
    /// cell's reset-waiters-drained event exactly once before returning.
    #[doc(hidden)]
    unsafe fn signal_then_ack(
        self,
        signal: impl FnOnce(&MountResetWaitersDrainedSignal),
    ) -> MountResetJoinAcknowledgement {
        let signaled = match self.drained_signal {
            Some(drained) => {
                signal(&drained);
                let MountResetWaitersDrainedSignal {
                    locator,
                    mount_generation,
                    authority: PrivateMountResetWaitersDrainedSignalAuthority(()),
                } = drained;
                debug_assert_eq!(locator, self.joined_proof.locator);
                debug_assert_eq!(mount_generation, self.joined_proof.mount_generation);
                true
            }
            None => false,
        };
        MountResetJoinAcknowledgement {
            joined_proof: self.joined_proof,
            signaled,
            authority: PrivateMountResetWaitersDrainedAcknowledgementAuthority(()),
        }
    }
}

/// Run the fused native Done signal/acknowledgement transition.
///
/// This is the WDK-free production seam for the corresponding permanent-cell
/// helper. The native caller keeps its registry lock around this call and
/// supplies only the synchronous event signal; core consumes both the exact
/// Done publication and its matching acknowledgement.
///
/// # Safety
/// `signal` synchronously signals the matching permanent cell's mount-complete
/// event exactly once with `Wait = FALSE`, and returns before this function
/// acknowledges the publication.
///
/// The raw halves are deliberately inaccessible outside this module:
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::MountDonePublication;
/// # fn cannot_split_signal(publication: MountDonePublication) {
/// let _ = unsafe { publication.signal_then_ack(|_| {}) };
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::{MountDoneAcknowledgement, MountRendezvous};
/// # fn cannot_split_ack<Device, Vpb>(
/// #     rendezvous: &mut MountRendezvous<Device, Vpb>,
/// #     acknowledgement: MountDoneAcknowledgement,
/// # ) {
/// let _ = rendezvous.acknowledge_done_signal(acknowledgement);
/// # }
/// ```
pub unsafe fn run_r3_mount_done_signal_ack<Device, Vpb>(
    rendezvous: &mut MountRendezvous<Device, Vpb>,
    publication: MountDonePublication,
    signal: impl FnOnce(&MountCompleteSignal),
) -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {
    // SAFETY: forwarded from this function's caller; the typed publication
    // keeps the callback bound to the exact Done generation.
    let acknowledgement = unsafe { publication.signal_then_ack(signal) };
    rendezvous.acknowledge_done_signal(acknowledgement)
}

/// Run the fused native ordinary-waiters-drained signal/ack transition.
///
/// A non-last conversion contains no signal authority, so `signal` is not
/// called in that case; its distinct acknowledgement still consumes the exact
/// conversion and yields its reset-join ticket.
///
/// # Safety
/// If invoked, `signal` synchronously signals the matching permanent cell's
/// ordinary-waiters-drained event exactly once with `Wait = FALSE` and returns
/// before acknowledgement.
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::MountJoinConversion;
/// # fn cannot_split_signal(conversion: MountJoinConversion) {
/// let _ = unsafe { conversion.signal_then_ack(|_| {}) };
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::{MountJoinAcknowledgement, MountRendezvous};
/// # fn cannot_split_ack<Device, Vpb>(
/// #     rendezvous: &mut MountRendezvous<Device, Vpb>,
/// #     acknowledgement: MountJoinAcknowledgement,
/// # ) {
/// let _ = rendezvous.acknowledge_join_signal(acknowledgement);
/// # }
/// ```
pub unsafe fn run_r3_mount_ordinary_drained_signal_ack<Device, Vpb>(
    rendezvous: &mut MountRendezvous<Device, Vpb>,
    conversion: MountJoinConversion,
    signal: impl FnOnce(&MountWaitersDrainedSignal),
) -> Result<MountResetJoinTicket, (LifecycleError, MountJoinAcknowledgement)> {
    // SAFETY: forwarded from this function's caller; the typed conversion
    // decides whether this exact ordinary population owns the last signal.
    let acknowledgement = unsafe { conversion.signal_then_ack(signal) };
    rendezvous.acknowledge_join_signal(acknowledgement)
}

/// Run the fused native reset-complete signal/acknowledgement transition.
///
/// # Safety
/// `signal` synchronously signals the matching permanent cell's reset-complete
/// event exactly once with `Wait = FALSE`, and returns before acknowledgement.
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::MountResetPublication;
/// # fn cannot_split_signal(publication: MountResetPublication) {
/// let _ = unsafe { publication.signal_then_ack(|_| {}) };
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::{MountResetAcknowledgement, MountRendezvous};
/// # fn cannot_split_ack<Device, Vpb>(
/// #     rendezvous: &mut MountRendezvous<Device, Vpb>,
/// #     acknowledgement: MountResetAcknowledgement,
/// # ) {
/// let _ = rendezvous.acknowledge_reset_signal(acknowledgement);
/// # }
/// ```
pub unsafe fn run_r3_mount_reset_complete_signal_ack<Device, Vpb>(
    rendezvous: &mut MountRendezvous<Device, Vpb>,
    publication: MountResetPublication,
    signal: impl FnOnce(&MountResetCompleteSignal),
) -> Result<MountResetProof, (LifecycleError, MountResetAcknowledgement)> {
    // SAFETY: forwarded from this function's caller; the typed publication
    // keeps the callback bound to the exact reset generation.
    let acknowledgement = unsafe { publication.signal_then_ack(signal) };
    rendezvous.acknowledge_reset_signal(acknowledgement)
}

/// Run the fused native reset-waiters-drained signal/ack transition.
///
/// A non-last release contains no signal authority, so `signal` is not called
/// in that case; the distinct acknowledgement still consumes that release and
/// yields its joined reset proof.
///
/// # Safety
/// If invoked, `signal` synchronously signals the matching permanent cell's
/// reset-waiters-drained event exactly once with `Wait = FALSE` and returns
/// before acknowledgement.
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::MountResetJoinRelease;
/// # fn cannot_split_signal(release: MountResetJoinRelease) {
/// let _ = unsafe { release.signal_then_ack(|_| {}) };
/// # }
/// ```
///
/// ```compile_fail,E0624
/// # use fsring_core::adapter::lifecycle::{
/// #     MountResetJoinAcknowledgement, MountRendezvous,
/// # };
/// # fn cannot_split_ack<Device, Vpb>(
/// #     rendezvous: &mut MountRendezvous<Device, Vpb>,
/// #     acknowledgement: MountResetJoinAcknowledgement,
/// # ) {
/// let _ = rendezvous.acknowledge_reset_join_signal(acknowledgement);
/// # }
/// ```
pub unsafe fn run_r3_mount_reset_waiters_drained_signal_ack<Device, Vpb>(
    rendezvous: &mut MountRendezvous<Device, Vpb>,
    release: MountResetJoinRelease,
    signal: impl FnOnce(&MountResetWaitersDrainedSignal),
) -> Result<JoinedMountResetProof, (LifecycleError, MountResetJoinAcknowledgement)> {
    // SAFETY: forwarded from this function's caller; the typed release decides
    // whether this exact reset population owns the last signal.
    let acknowledgement = unsafe { release.signal_then_ack(signal) };
    rendezvous.acknowledge_reset_join_signal(acknowledgement)
}

impl<Device, Vpb> MountRendezvous<Device, Vpb> {
    pub const fn new_inactive() -> Self {
        Self {
            state: PrivateMountRendezvousState::Inactive,
            ordinary_waiters: 0,
            reset_waiters: 0,
            last_completed_generation: None,
            mount_complete_signal_pending: false,
            ordinary_drained_signal_pending: false,
            reset_complete_signal_pending: false,
            reset_waiters_drained_signal_pending: false,
        }
    }

    /// Narrow locked effect-nine observation. It exposes no owner, locator,
    /// ticket, waiter, or acknowledgement authority.
    pub const fn r3_unload_is_inactive(&self) -> bool {
        matches!(self.state, PrivateMountRendezvousState::Inactive)
            && self.ordinary_waiters == 0
            && self.reset_waiters == 0
            && self.last_completed_generation.is_none()
            && !self.mount_complete_signal_pending
            && !self.ordinary_drained_signal_pending
            && !self.reset_complete_signal_pending
            && !self.reset_waiters_drained_signal_pending
    }

    /// Independent effect-nine observations. They deliberately project only
    /// booleans so native code cannot recover owners, tickets, wait rights, or
    /// pending acknowledgement capabilities from the preflight.
    pub const fn r3_unload_owner_is_absent(&self) -> bool {
        matches!(self.state, PrivateMountRendezvousState::Inactive)
    }

    pub const fn r3_unload_tickets_and_waiters_are_drained(&self) -> bool {
        self.ordinary_waiters == 0 && self.reset_waiters == 0
    }

    pub const fn r3_unload_signals_are_acknowledged(&self) -> bool {
        self.last_completed_generation.is_none()
            && !self.mount_complete_signal_pending
            && !self.ordinary_drained_signal_pending
            && !self.reset_complete_signal_pending
            && !self.reset_waiters_drained_signal_pending
    }

    /// Authenticate a copy-only native wait address against the exact current
    /// mount generation and the phases in which its event may still complete.
    ///
    /// The observation's generation stays private: native code can resolve
    /// the permanent cell and event, but only this rendezvous can decide that
    /// the copied address is not stale after cell-event reuse.
    pub fn matches_wait_observation(&self, observation: &MountWaitObservation) -> bool {
        match (observation.event, &self.state) {
            (
                MountWaitEvent::Complete,
                PrivateMountRendezvousState::TearingDown {
                    locator,
                    generation,
                }
                | PrivateMountRendezvousState::Done {
                    locator,
                    generation,
                },
            ) => *locator == observation.locator && *generation == observation.mount_generation,
            (
                MountWaitEvent::OrdinaryWaitersDrained,
                PrivateMountRendezvousState::Done {
                    locator,
                    generation,
                },
            ) => *locator == observation.locator && *generation == observation.mount_generation,
            (
                MountWaitEvent::ResetComplete,
                PrivateMountRendezvousState::Done {
                    locator,
                    generation,
                }
                | PrivateMountRendezvousState::Resetting {
                    locator,
                    generation,
                },
            ) => *locator == observation.locator && *generation == observation.mount_generation,
            (
                MountWaitEvent::ResetComplete | MountWaitEvent::ResetWaitersDrained,
                PrivateMountRendezvousState::Unmounted { locator, .. }
                | PrivateMountRendezvousState::Exhausted { locator },
            ) => {
                *locator == observation.locator
                    && self.last_completed_generation == Some(observation.mount_generation)
            }
            _ => false,
        }
    }

    /// Authenticate the pending signal named by a copy-only publication
    /// address. The observation never grants permission to signal or advance;
    /// the original affine publication remains necessary for both actions.
    /// A true answer validates the address and current predicate, not the
    /// identity of one of several commuting same-kind non-last publications.
    pub fn matches_publication_observation<Kind: MountPublicationKind>(
        &self,
        observation: &MountPublicationObservation<Kind>,
    ) -> bool {
        if self.locator() != Some(observation.locator) {
            return false;
        }
        if !matches_generation(self, observation.locator, observation.mount_generation) {
            return false;
        }
        let kind = <Kind as mount_publication_kind_seal::Sealed>::KIND;
        match (kind, observation.event, &self.state) {
            (
                mount_publication_kind_seal::DONE,
                Some(MountWaitEvent::Complete),
                PrivateMountRendezvousState::Done { .. },
            ) => self.mount_complete_signal_pending,
            (
                mount_publication_kind_seal::JOIN_CONVERSION,
                Some(MountWaitEvent::OrdinaryWaitersDrained),
                PrivateMountRendezvousState::Done { .. },
            ) => self.ordinary_drained_signal_pending,
            (
                mount_publication_kind_seal::JOIN_CONVERSION,
                None,
                PrivateMountRendezvousState::Done { .. },
            ) => {
                self.ordinary_waiters != 0
                    && self.reset_waiters != 0
                    && !self.mount_complete_signal_pending
                    && !self.ordinary_drained_signal_pending
            }
            (
                mount_publication_kind_seal::RESET,
                Some(MountWaitEvent::ResetComplete),
                PrivateMountRendezvousState::Resetting { .. },
            ) => self.reset_complete_signal_pending,
            (
                mount_publication_kind_seal::RESET_JOIN_RELEASE,
                Some(MountWaitEvent::ResetWaitersDrained),
                PrivateMountRendezvousState::Unmounted { .. }
                | PrivateMountRendezvousState::Exhausted { .. },
            ) => self.reset_waiters_drained_signal_pending,
            (
                mount_publication_kind_seal::RESET_JOIN_RELEASE,
                None,
                PrivateMountRendezvousState::Unmounted { .. }
                | PrivateMountRendezvousState::Exhausted { .. },
            ) => {
                self.reset_waiters != 0
                    && !self.reset_complete_signal_pending
                    && !self.reset_waiters_drained_signal_pending
            }
            _ => false,
        }
    }

    /// The exact expectation `take_or_join` will accept right now.
    ///
    /// A caller cannot construct one itself: the generation lives here, and an
    /// expectation built from a guessed generation is refused. Returning it
    /// from an observer — rather than letting `take_or_join` infer it — is what
    /// keeps the expectation and the completion halves of a bind bound to the
    /// same call.
    pub fn expected_teardown(&self, locator: SessionLocator) -> Option<ExpectedMountTeardown> {
        match &self.state {
            PrivateMountRendezvousState::Publishing { .. } => None,
            PrivateMountRendezvousState::Present { generation, owner } => {
                if owner.locator == locator {
                    Some(ExpectedMountTeardown::Owner {
                        locator,
                        mount_generation: *generation,
                    })
                } else {
                    None
                }
            }
            PrivateMountRendezvousState::TearingDown {
                locator: current,
                generation,
            }
            | PrivateMountRendezvousState::Done {
                locator: current,
                generation,
            }
            | PrivateMountRendezvousState::Resetting {
                locator: current,
                generation,
            } => {
                if *current == locator {
                    Some(ExpectedMountTeardown::Join {
                        locator,
                        mount_generation: *generation,
                    })
                } else {
                    None
                }
            }
            PrivateMountRendezvousState::Unmounted {
                locator: current,
                next_generation,
            } => {
                if *current == locator {
                    Some(ExpectedMountTeardown::Absent {
                        locator,
                        cursor: match next_generation {
                            Some(next) => MountAbsenceCursor::Next(next.get()),
                            None => MountAbsenceCursor::Exhausted,
                        },
                    })
                } else {
                    None
                }
            }
            PrivateMountRendezvousState::Exhausted { locator: current } => {
                if *current == locator {
                    Some(ExpectedMountTeardown::Absent {
                        locator,
                        cursor: MountAbsenceCursor::Exhausted,
                    })
                } else {
                    None
                }
            }
            PrivateMountRendezvousState::Inactive => None,
        }
    }

    /// Observe, without mutating, that this rendezvous can still be activated
    /// for `locator`.
    ///
    /// The locked SETUP suffix must activate the native mount before core goes
    /// `Live`, and by then no fallible step may remain. Splitting the refusal
    /// out here is what lets the suffix stay infallible: a refusal returns
    /// `Err` while every object is still untouched.
    pub fn prepare_activation(
        &self,
        locator: SessionLocator,
    ) -> Result<PreparedMountActivation, LifecycleError> {
        if !matches!(self.state, PrivateMountRendezvousState::Inactive) {
            return Err(LifecycleError::WrongState);
        }
        Ok(PreparedMountActivation {
            locator,
            authority: PrivateMountActivationAuthority(()),
        })
    }

    /// # Safety
    /// `prepared` was produced by `prepare_activation` on this exact rendezvous
    /// under the registry lock that is still held, and nothing has changed the
    /// state since. The commit is infallible and has no refusal edge.
    pub unsafe fn commit_prepared_activation(&mut self, prepared: PreparedMountActivation) {
        let PreparedMountActivation {
            locator,
            authority: PrivateMountActivationAuthority(()),
        } = prepared;
        debug_assert!(matches!(self.state, PrivateMountRendezvousState::Inactive));
        self.state = PrivateMountRendezvousState::Unmounted {
            locator,
            next_generation: NonZeroU64::new(1),
        };
    }

    /// Safe convenience wrapper over the prepared pair.
    ///
    /// It exists only to compose `prepare_activation` with
    /// `commit_prepared_activation`; it must never grow a second mutation path,
    /// or the prepared split stops being the sole activation authority.
    pub fn activate(&mut self, locator: SessionLocator) -> Result<(), LifecycleError> {
        let prepared = self.prepare_activation(locator)?;
        // SAFETY: `prepared` was just produced by this exact rendezvous and
        // nothing observed or mutated the state in between.
        unsafe { self.commit_prepared_activation(prepared) };
        Ok(())
    }

    /// Put an already activated test rendezvous at one exact next generation.
    ///
    /// This does not mint any completion authority. Tests outside this module
    /// still have to install, tear down, signal, acknowledge, reset, and claim
    /// absence through the production transitions before they can obtain one.
    #[cfg(test)]
    pub(crate) fn set_next_mount_generation_for_test(
        &mut self,
        next_generation: NonZeroU64,
    ) -> Result<(), LifecycleError> {
        let PrivateMountRendezvousState::Unmounted {
            next_generation: current,
            ..
        } = &mut self.state
        else {
            return Err(LifecycleError::WrongState);
        };
        *current = Some(next_generation);
        Ok(())
    }

    /// Borrow-check every piece of the complete owner before publication.
    ///
    /// Nothing moves on refusal. In particular, the session strong reference,
    /// mounted-device owner, and VPB owner all remain in the caller's rollback
    /// context until the infallible commit below.
    pub fn prepare_install(
        &self,
        locator: SessionLocator,
        reference: &StrongSessionRef,
        mounted: &Device,
        vpb: &Vpb,
    ) -> Result<PreparedMountInstall, LifecycleError> {
        let _complete_native_owner = (mounted, vpb);
        let generation = match self.state {
            PrivateMountRendezvousState::Unmounted {
                locator: current,
                next_generation: Some(generation),
            } if current == locator => generation.get(),
            PrivateMountRendezvousState::Unmounted {
                locator: current, ..
            }
            | PrivateMountRendezvousState::Exhausted { locator: current }
                if current != locator =>
            {
                return Err(LifecycleError::WrongLocator);
            }
            PrivateMountRendezvousState::Exhausted { .. }
            | PrivateMountRendezvousState::Unmounted {
                next_generation: None,
                ..
            } => return Err(LifecycleError::GenerationExhausted),
            PrivateMountRendezvousState::Inactive => return Err(LifecycleError::WrongState),
            PrivateMountRendezvousState::Publishing { .. }
            | PrivateMountRendezvousState::Present { .. }
            | PrivateMountRendezvousState::TearingDown { .. }
            | PrivateMountRendezvousState::Done { .. }
            | PrivateMountRendezvousState::Resetting { .. }
            | PrivateMountRendezvousState::Unmounted { .. } => {
                return Err(LifecycleError::MountBusy);
            }
        };
        if reference.locator() != locator {
            return Err(LifecycleError::WrongLocator);
        }
        if self.ordinary_waiters != 0 || self.reset_waiters != 0 || self.any_signal_pending() {
            return Err(LifecycleError::MountBusy);
        }
        Ok(PreparedMountInstall {
            locator,
            mount_generation: generation,
            publication_id: allocate_mount_publication_id()?,
            authority: PrivateMountInstallAuthority(()),
        })
    }

    /// Commit the exact owner pieces validated by [`Self::prepare_install`].
    ///
    /// # Safety
    /// `prepared` came from this rendezvous while the registry lock remained
    /// held; `reference`, `mounted`, and `vpb` are the exact values borrowed by
    /// that preflight, and no rendezvous state changed in between.
    pub unsafe fn commit_prepared_install(
        &mut self,
        prepared: PreparedMountInstall,
        reference: StrongSessionRef,
        mounted: Device,
        vpb: Vpb,
    ) -> MountOwnerPublication {
        let PreparedMountInstall {
            locator,
            mount_generation,
            publication_id,
            authority: PrivateMountInstallAuthority(()),
        } = prepared;
        self.state = PrivateMountRendezvousState::Publishing {
            generation: mount_generation,
            publication_id,
            owner: MountOwner {
                locator,
                mount_generation,
                reference,
                mounted,
                vpb,
            },
        };
        MountOwnerPublication {
            locator,
            mount_generation,
            publication_id,
            authority: PrivateMountPublicationAuthority(()),
        }
    }

    /// Consume the exact publication receipt while exposing its mounted
    /// device, then and only then make the complete owner available to
    /// teardown.
    ///
    /// The callback runs while the rendezvous remains `Publishing`. Native
    /// code invokes this method under the permanent registry lock, so a
    /// terminal claimant cannot take and delete the owner before the callback
    /// returns. A refusal returns the affine receipt unchanged.
    pub fn commit_owner_exposure(
        &mut self,
        publication: MountOwnerPublication,
        expose: impl FnOnce(&Device),
    ) -> Result<(), (LifecycleError, MountOwnerPublication)> {
        let (locator, generation, publication_id) = match &self.state {
            PrivateMountRendezvousState::Publishing {
                generation,
                publication_id,
                owner,
            } => (owner.locator, *generation, *publication_id),
            _ => return Err((LifecycleError::WrongState, publication)),
        };
        if publication.locator != locator
            || publication.mount_generation != generation
            || publication.publication_id != publication_id
        {
            return Err((LifecycleError::WrongLocator, publication));
        }

        let PrivateMountRendezvousState::Publishing { owner, .. } = &self.state else {
            unreachable!("the publication state was validated above")
        };
        expose(&owner.mounted);

        let MountOwnerPublication {
            locator: _,
            mount_generation: _,
            publication_id: _,
            authority: PrivateMountPublicationAuthority(()),
        } = publication;
        let state = core::mem::replace(&mut self.state, PrivateMountRendezvousState::Inactive);
        let PrivateMountRendezvousState::Publishing {
            generation, owner, ..
        } = state
        else {
            unreachable!("the exposure callback cannot reenter the borrowed rendezvous")
        };
        self.state = PrivateMountRendezvousState::Present { generation, owner };
        Ok(())
    }

    /// Test-only composition of the production prepare/commit pair.
    #[cfg(test)]
    pub fn install(
        &mut self,
        owner: MountOwner<Device, Vpb>,
    ) -> Result<(), (LifecycleError, MountOwner<Device, Vpb>)> {
        let MountOwner {
            locator,
            mount_generation,
            reference,
            mounted,
            vpb,
        } = owner;
        let prepared = match self.prepare_install(locator, &reference, &mounted, &vpb) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err((
                    error,
                    MountOwner {
                        locator,
                        mount_generation,
                        reference,
                        mounted,
                        vpb,
                    },
                ));
            }
        };
        // SAFETY: the exact destructured owner pieces were borrowed above and
        // this test-only wrapper performs no intervening mutation.
        let publication =
            unsafe { self.commit_prepared_install(prepared, reference, mounted, vpb) };
        self.commit_owner_exposure(publication, |_| {})
            .unwrap_or_else(|(error, _)| {
                unreachable!("the just-minted test receipt must expose its own owner: {error:?}")
            });
        Ok(())
    }

    pub fn take_or_join(
        &mut self,
        expected: ExpectedMountTeardown,
    ) -> Result<MountClaim<Device, Vpb>, LifecycleError> {
        match &self.state {
            PrivateMountRendezvousState::Publishing { .. } => Err(LifecycleError::WrongState),
            PrivateMountRendezvousState::Present { generation, owner } => {
                require_expected(expected, owner.locator, *generation, ExpectedKind::Owner)?;
                let state =
                    core::mem::replace(&mut self.state, PrivateMountRendezvousState::Inactive);
                let PrivateMountRendezvousState::Present { generation, owner } = state else {
                    unreachable!("the present state was matched before its move")
                };
                let locator = owner.locator;
                self.state = PrivateMountRendezvousState::TearingDown {
                    locator,
                    generation,
                };
                Ok(MountClaim::Owner {
                    owner,
                    teardown: MountTeardownRight {
                        locator,
                        mount_generation: generation,
                        authority: PrivateMountTeardownAuthority(()),
                    },
                    expected,
                })
            }
            PrivateMountRendezvousState::TearingDown {
                locator,
                generation,
            }
            | PrivateMountRendezvousState::Done {
                locator,
                generation,
            } => {
                let locator = *locator;
                let generation = *generation;
                require_expected(expected, locator, generation, ExpectedKind::Join)?;
                if matches!(self.state, PrivateMountRendezvousState::Done { .. })
                    && (self.mount_complete_signal_pending || self.ordinary_drained_signal_pending)
                {
                    return Err(LifecycleError::AdmissionClosed);
                }
                let Some(next) = self.ordinary_waiters.checked_add(1) else {
                    return Err(LifecycleError::JoinerOverflow);
                };
                self.ordinary_waiters = next;
                Ok(MountClaim::Join {
                    ticket: MountJoinTicket {
                        locator,
                        mount_generation: generation,
                        authority: PrivateMountJoinAuthority(()),
                    },
                    expected,
                })
            }
            PrivateMountRendezvousState::Resetting {
                locator,
                generation,
            } => {
                let locator = *locator;
                let generation = *generation;
                require_expected(expected, locator, generation, ExpectedKind::Join)?;
                let Some(next) = self.reset_waiters.checked_add(1) else {
                    return Err(LifecycleError::JoinerOverflow);
                };
                self.reset_waiters = next;
                Ok(MountClaim::ResetJoin {
                    ticket: MountResetJoinTicket {
                        locator,
                        mount_generation: generation,
                        origin: MountJoinOrigin::Reset,
                        authority: PrivateMountResetJoinAuthority(()),
                    },
                    expected,
                })
            }
            PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: Some(next),
            } => {
                require_expected_absence(expected, *locator, MountAbsenceCursor::Next(next.get()))?;
                if self.ordinary_waiters != 0
                    || self.reset_waiters != 0
                    || self.any_signal_pending()
                {
                    return Err(LifecycleError::AdmissionClosed);
                }
                Ok(MountClaim::Absent {
                    expected,
                    completed: MountAbsentProof {
                        locator: *locator,
                        cursor: MountAbsenceCursor::Next(next.get()),
                        authority: PrivateMountAbsentAuthority(()),
                    },
                })
            }
            PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: None,
            }
            | PrivateMountRendezvousState::Exhausted { locator } => {
                require_expected_absence(expected, *locator, MountAbsenceCursor::Exhausted)?;
                if self.ordinary_waiters != 0
                    || self.reset_waiters != 0
                    || self.any_signal_pending()
                {
                    return Err(LifecycleError::AdmissionClosed);
                }
                Ok(MountClaim::Absent {
                    expected,
                    completed: MountAbsentProof {
                        locator: *locator,
                        cursor: MountAbsenceCursor::Exhausted,
                        authority: PrivateMountAbsentAuthority(()),
                    },
                })
            }
            PrivateMountRendezvousState::Inactive => Err(LifecycleError::WrongState),
        }
    }

    pub fn publish_done(
        &mut self,
        right: MountTeardownRight,
    ) -> Result<MountDonePublication, (LifecycleError, MountTeardownRight)> {
        let (locator, generation) = match self.state {
            PrivateMountRendezvousState::TearingDown {
                locator,
                generation,
            } => (locator, generation),
            _ => return Err((LifecycleError::WrongState, right)),
        };
        if locator != right.locator || generation != right.mount_generation {
            return Err((LifecycleError::WrongLocator, right));
        }
        if self.mount_complete_signal_pending {
            return Err((LifecycleError::Invariant, right));
        }
        let MountTeardownRight {
            authority: PrivateMountTeardownAuthority(()),
            ..
        } = right;
        self.state = PrivateMountRendezvousState::Done {
            locator,
            generation,
        };
        self.mount_complete_signal_pending = true;
        Ok(MountDonePublication {
            drain: MountDrainRight {
                locator,
                mount_generation: generation,
                authority: PrivateMountDrainAuthority(()),
            },
            signal: MountCompleteSignal {
                locator,
                mount_generation: generation,
                authority: PrivateMountCompleteSignalAuthority(()),
            },
        })
    }

    pub fn release_join(
        &mut self,
        ticket: MountJoinTicket,
    ) -> Result<MountJoinConversion, (LifecycleError, MountJoinTicket)> {
        let (locator, generation) = match self.state {
            PrivateMountRendezvousState::Done {
                locator,
                generation,
            } => (locator, generation),
            _ => return Err((LifecycleError::WrongState, ticket)),
        };
        if locator != ticket.locator || generation != ticket.mount_generation {
            return Err((LifecycleError::WrongLocator, ticket));
        }
        if self.mount_complete_signal_pending {
            return Err((LifecycleError::AdmissionClosed, ticket));
        }
        let Some(ordinary) = self.ordinary_waiters.checked_sub(1) else {
            return Err((LifecycleError::JoinerUnderflow, ticket));
        };
        let Some(reset) = self.reset_waiters.checked_add(1) else {
            return Err((LifecycleError::JoinerOverflow, ticket));
        };
        let MountJoinTicket {
            authority: PrivateMountJoinAuthority(()),
            ..
        } = ticket;
        self.ordinary_waiters = ordinary;
        self.reset_waiters = reset;
        let drained_signal = if ordinary == 0 {
            self.ordinary_drained_signal_pending = true;
            Some(MountWaitersDrainedSignal {
                locator,
                mount_generation: generation,
                authority: PrivateMountWaitersDrainedSignalAuthority(()),
            })
        } else {
            None
        };
        Ok(MountJoinConversion {
            reset_ticket: MountResetJoinTicket {
                locator,
                mount_generation: generation,
                origin: MountJoinOrigin::Ordinary,
                authority: PrivateMountResetJoinAuthority(()),
            },
            drained_signal,
        })
    }

    pub fn poll_drain(
        &mut self,
        right: MountDrainRight,
    ) -> Result<PreparedMountReset, (LifecycleError, MountDrainRight)> {
        let (locator, generation) = match self.state {
            PrivateMountRendezvousState::Done {
                locator,
                generation,
            } => (locator, generation),
            _ => return Err((LifecycleError::WrongState, right)),
        };
        if locator != right.locator || generation != right.mount_generation {
            return Err((LifecycleError::WrongLocator, right));
        }
        if self.ordinary_waiters != 0
            || self.mount_complete_signal_pending
            || self.ordinary_drained_signal_pending
        {
            return Err((LifecycleError::AdmissionClosed, right));
        }
        self.state = PrivateMountRendezvousState::Resetting {
            locator,
            generation,
        };
        Ok(PreparedMountReset {
            drain: right,
            waiters: MountWaitersDrainedProof {
                locator,
                mount_generation: generation,
                authority: PrivateMountWaitersDrainedAuthority(()),
            },
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn finish_reset(
        &mut self,
        prepared: PreparedMountReset,
    ) -> Result<MountResetPublication, (LifecycleError, PreparedMountReset)> {
        let (locator, generation) = match self.state {
            PrivateMountRendezvousState::Resetting {
                locator,
                generation,
            } => (locator, generation),
            _ => return Err((LifecycleError::WrongState, prepared)),
        };
        if prepared.drain.locator != locator
            || prepared.waiters.locator != locator
            || prepared.drain.mount_generation != generation
            || prepared.waiters.mount_generation != generation
        {
            return Err((LifecycleError::WrongLocator, prepared));
        }
        if self.reset_complete_signal_pending {
            return Err((LifecycleError::Invariant, prepared));
        }
        let PreparedMountReset {
            drain:
                MountDrainRight {
                    authority: PrivateMountDrainAuthority(()),
                    ..
                },
            waiters:
                MountWaitersDrainedProof {
                    authority: PrivateMountWaitersDrainedAuthority(()),
                    ..
                },
        } = prepared;
        self.reset_complete_signal_pending = true;
        Ok(MountResetPublication {
            owner_proof: MountResetProof {
                locator,
                mount_generation: generation,
                authority: PrivateMountResetAuthority(()),
            },
            signal: MountResetCompleteSignal {
                locator,
                mount_generation: generation,
                authority: PrivateMountResetCompleteSignalAuthority(()),
            },
        })
    }

    pub fn finish_joined_reset(
        &mut self,
        ticket: MountResetJoinTicket,
    ) -> Result<MountResetJoinRelease, (LifecycleError, MountResetJoinTicket)> {
        if self.reset_complete_signal_pending {
            return Err((LifecycleError::AdmissionClosed, ticket));
        }
        if self.last_completed_generation != Some(ticket.mount_generation) {
            return Err((LifecycleError::WrongState, ticket));
        }
        let Some(locator) = self.locator() else {
            return Err((LifecycleError::WrongState, ticket));
        };
        if locator != ticket.locator {
            return Err((LifecycleError::WrongLocator, ticket));
        }
        if !matches!(
            self.state,
            PrivateMountRendezvousState::Unmounted { .. }
                | PrivateMountRendezvousState::Exhausted { .. }
        ) {
            return Err((LifecycleError::WrongState, ticket));
        }
        let Some(reset_waiters) = self.reset_waiters.checked_sub(1) else {
            return Err((LifecycleError::JoinerUnderflow, ticket));
        };
        let MountResetJoinTicket {
            authority: PrivateMountResetJoinAuthority(()),
            mount_generation,
            origin,
            ..
        } = ticket;
        self.reset_waiters = reset_waiters;
        let drained_signal = if reset_waiters == 0 {
            self.reset_waiters_drained_signal_pending = true;
            Some(MountResetWaitersDrainedSignal {
                locator,
                mount_generation,
                authority: PrivateMountResetWaitersDrainedSignalAuthority(()),
            })
        } else {
            None
        };
        Ok(MountResetJoinRelease {
            joined_proof: JoinedMountResetProof {
                locator,
                mount_generation,
                origin,
                authority: PrivateJoinedMountResetAuthority(()),
            },
            drained_signal,
        })
    }

    fn acknowledge_done_signal(
        &mut self,
        acknowledgement: MountDoneAcknowledgement,
    ) -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {
        if !self.mount_complete_signal_pending {
            return Err((LifecycleError::WrongState, acknowledgement));
        }
        if !matches_generation(
            self,
            acknowledgement.drain.locator,
            acknowledgement.drain.mount_generation,
        ) || !matches!(self.state, PrivateMountRendezvousState::Done { .. })
        {
            return Err((LifecycleError::WrongLocator, acknowledgement));
        }
        let MountDoneAcknowledgement {
            drain,
            authority: PrivateMountCompleteAcknowledgementAuthority(()),
        } = acknowledgement;
        self.mount_complete_signal_pending = false;
        Ok(drain)
    }

    fn acknowledge_join_signal(
        &mut self,
        acknowledgement: MountJoinAcknowledgement,
    ) -> Result<MountResetJoinTicket, (LifecycleError, MountJoinAcknowledgement)> {
        if !matches_generation(
            self,
            acknowledgement.reset_ticket.locator,
            acknowledgement.reset_ticket.mount_generation,
        ) {
            return Err((LifecycleError::WrongLocator, acknowledgement));
        }
        if acknowledgement.signaled {
            if !self.ordinary_drained_signal_pending {
                return Err((LifecycleError::WrongState, acknowledgement));
            }
            self.ordinary_drained_signal_pending = false;
        }
        let MountJoinAcknowledgement {
            reset_ticket,
            authority: PrivateMountWaitersDrainedAcknowledgementAuthority(()),
            ..
        } = acknowledgement;
        Ok(reset_ticket)
    }

    fn acknowledge_reset_signal(
        &mut self,
        acknowledgement: MountResetAcknowledgement,
    ) -> Result<MountResetProof, (LifecycleError, MountResetAcknowledgement)> {
        let (locator, generation) = match self.state {
            PrivateMountRendezvousState::Resetting {
                locator,
                generation,
            } => (locator, generation),
            _ => return Err((LifecycleError::WrongState, acknowledgement)),
        };
        if acknowledgement.owner_proof.locator != locator
            || acknowledgement.owner_proof.mount_generation != generation
        {
            return Err((LifecycleError::WrongLocator, acknowledgement));
        }
        if !self.reset_complete_signal_pending {
            return Err((LifecycleError::WrongState, acknowledgement));
        }
        let _authority = &acknowledgement.owner_proof.authority;
        let MountResetAcknowledgement {
            owner_proof,
            authority: PrivateMountResetCompleteAcknowledgementAuthority(()),
        } = acknowledgement;
        self.reset_complete_signal_pending = false;
        self.last_completed_generation = Some(generation);
        self.state = match generation.checked_add(1).and_then(NonZeroU64::new) {
            Some(next_generation) => PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: Some(next_generation),
            },
            None => PrivateMountRendezvousState::Exhausted { locator },
        };
        Ok(owner_proof)
    }

    fn acknowledge_reset_join_signal(
        &mut self,
        acknowledgement: MountResetJoinAcknowledgement,
    ) -> Result<JoinedMountResetProof, (LifecycleError, MountResetJoinAcknowledgement)> {
        if self.last_completed_generation != Some(acknowledgement.joined_proof.mount_generation)
            || self.locator() != Some(acknowledgement.joined_proof.locator)
        {
            return Err((LifecycleError::WrongLocator, acknowledgement));
        }
        if acknowledgement.signaled {
            if !self.reset_waiters_drained_signal_pending {
                return Err((LifecycleError::WrongState, acknowledgement));
            }
            self.reset_waiters_drained_signal_pending = false;
        }
        let _authority = &acknowledgement.joined_proof.authority;
        let MountResetJoinAcknowledgement {
            joined_proof,
            authority: PrivateMountResetWaitersDrainedAcknowledgementAuthority(()),
            ..
        } = acknowledgement;
        Ok(joined_proof)
    }

    /// Mint the owner's completion only after Done, ordinary drain, reset
    /// signal, and the final reset-waiter drain are all acknowledged.
    pub fn complete_owner(
        &self,
        proof: MountResetProof,
    ) -> Result<OwnerMountCompletion, (LifecycleError, MountResetProof)> {
        let cursor = match self.completion_cursor(proof.locator, proof.mount_generation) {
            Ok(cursor) => cursor,
            Err(error) => return Err((error, proof)),
        };
        let MountResetProof {
            locator,
            mount_generation,
            authority: PrivateMountResetAuthority(()),
        } = proof;
        Ok(OwnerMountCompletion {
            locator,
            mount_generation,
            cursor,
            authority: PrivateOwnerMountCompletionAuthority(()),
        })
    }

    /// Mint an ordinary-join or reset-join completion from its authentic
    /// post-reset acknowledgement, preserving which admission path it used.
    pub fn complete_joined(
        &self,
        proof: JoinedMountResetProof,
    ) -> Result<JoinedMountCompletion, (LifecycleError, JoinedMountResetProof)> {
        let cursor = match self.completion_cursor(proof.locator, proof.mount_generation) {
            Ok(cursor) => cursor,
            Err(error) => return Err((error, proof)),
        };
        let JoinedMountResetProof {
            locator,
            mount_generation,
            origin,
            authority: PrivateJoinedMountResetAuthority(()),
        } = proof;
        Ok(match origin {
            MountJoinOrigin::Ordinary => {
                JoinedMountCompletion::Join(JoinedMountGenerationCompletion {
                    locator,
                    mount_generation,
                    cursor,
                    authority: PrivateJoinedMountCompletionAuthority(()),
                })
            }
            MountJoinOrigin::Reset => {
                JoinedMountCompletion::ResetJoin(ResetJoinedMountGenerationCompletion {
                    locator,
                    mount_generation,
                    cursor,
                    authority: PrivateResetJoinedMountCompletionAuthority(()),
                })
            }
        })
    }

    #[cfg(test)]
    pub fn deactivate_after_delete(
        &mut self,
        absent: MountAbsentProof,
    ) -> Result<(), (LifecycleError, MountAbsentProof)> {
        if self.any_signal_pending() || self.ordinary_waiters != 0 || self.reset_waiters != 0 {
            return Err((LifecycleError::AdmissionClosed, absent));
        }
        match self.state {
            PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: Some(next),
            } if locator == absent.locator
                && absent.cursor == MountAbsenceCursor::Next(next.get()) => {}
            PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: None,
            }
            | PrivateMountRendezvousState::Exhausted { locator }
                if locator == absent.locator && absent.cursor == MountAbsenceCursor::Exhausted => {}
            PrivateMountRendezvousState::Unmounted { .. }
            | PrivateMountRendezvousState::Exhausted { .. } => {
                return Err((LifecycleError::WrongLocator, absent));
            }
            _ => return Err((LifecycleError::WrongState, absent)),
        }
        let MountAbsentProof {
            authority: PrivateMountAbsentAuthority(()),
            ..
        } = absent;
        self.state = PrivateMountRendezvousState::Inactive;
        Ok(())
    }

    /// Final delete deactivation for any authentically completed Owner, Join,
    /// ResetJoin, or Absent path.
    ///
    /// # Safety
    /// The right is minted only by the final delete cursor after shell/root
    /// destruction and every waiter/signal acknowledgement has completed.
    pub unsafe fn deactivate_after_delete_prepared(
        &mut self,
        right: crate::adapter::fence::MountRendezvousResetRight,
    ) {
        let prepared = right.into_prepared();
        debug_assert_eq!(self.locator(), Some(prepared.locator()));
        debug_assert!(self.ordinary_waiters == 0);
        debug_assert!(self.reset_waiters == 0);
        debug_assert!(!self.any_signal_pending());
        debug_assert!(match self.state {
            PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: Some(next),
            } => {
                locator == prepared.locator()
                    && prepared.cursor() == MountAbsenceCursor::Next(next.get())
            }
            PrivateMountRendezvousState::Unmounted {
                locator,
                next_generation: None,
            }
            | PrivateMountRendezvousState::Exhausted { locator } => {
                locator == prepared.locator() && prepared.cursor() == MountAbsenceCursor::Exhausted
            }
            _ => false,
        });
        self.state = PrivateMountRendezvousState::Inactive;
        self.last_completed_generation = None;
    }

    fn any_signal_pending(&self) -> bool {
        self.mount_complete_signal_pending
            || self.ordinary_drained_signal_pending
            || self.reset_complete_signal_pending
            || self.reset_waiters_drained_signal_pending
    }

    fn completion_cursor(
        &self,
        locator: SessionLocator,
        mount_generation: u64,
    ) -> Result<MountAbsenceCursor, LifecycleError> {
        if self.last_completed_generation != Some(mount_generation) {
            return Err(LifecycleError::WrongState);
        }
        if self.locator() != Some(locator) {
            return Err(LifecycleError::WrongLocator);
        }
        if self.ordinary_waiters != 0 || self.reset_waiters != 0 || self.any_signal_pending() {
            return Err(LifecycleError::AdmissionClosed);
        }
        match self.state {
            PrivateMountRendezvousState::Unmounted {
                next_generation: Some(next),
                ..
            } => Ok(MountAbsenceCursor::Next(next.get())),
            PrivateMountRendezvousState::Unmounted {
                next_generation: None,
                ..
            }
            | PrivateMountRendezvousState::Exhausted { .. } => Ok(MountAbsenceCursor::Exhausted),
            _ => Err(LifecycleError::WrongState),
        }
    }

    fn locator(&self) -> Option<SessionLocator> {
        match &self.state {
            PrivateMountRendezvousState::Inactive => None,
            PrivateMountRendezvousState::Unmounted { locator, .. }
            | PrivateMountRendezvousState::Exhausted { locator } => Some(*locator),
            PrivateMountRendezvousState::Publishing { owner, .. }
            | PrivateMountRendezvousState::Present { owner, .. } => Some(owner.locator),
            PrivateMountRendezvousState::TearingDown { locator, .. }
            | PrivateMountRendezvousState::Done { locator, .. }
            | PrivateMountRendezvousState::Resetting { locator, .. } => Some(*locator),
        }
    }

    #[cfg(test)]
    fn pending_signal_count_for_test(&self) -> usize {
        [
            self.mount_complete_signal_pending,
            self.ordinary_drained_signal_pending,
            self.reset_complete_signal_pending,
            self.reset_waiters_drained_signal_pending,
        ]
        .into_iter()
        .filter(|pending| *pending)
        .count()
    }
}

#[derive(Clone, Copy)]
enum ExpectedKind {
    Owner,
    Join,
}

fn require_expected(
    expected: ExpectedMountTeardown,
    locator: SessionLocator,
    generation: u64,
    kind: ExpectedKind,
) -> Result<(), LifecycleError> {
    let (current_locator, current_generation, matches_kind) = match expected {
        ExpectedMountTeardown::Owner {
            locator,
            mount_generation,
        } => (
            locator,
            mount_generation,
            matches!(kind, ExpectedKind::Owner),
        ),
        ExpectedMountTeardown::Join {
            locator,
            mount_generation,
        } => (
            locator,
            mount_generation,
            matches!(kind, ExpectedKind::Join),
        ),
        ExpectedMountTeardown::Absent { .. } => return Err(LifecycleError::WrongState),
    };
    if current_locator != locator {
        Err(LifecycleError::WrongLocator)
    } else if current_generation != generation || !matches_kind {
        Err(LifecycleError::WrongState)
    } else {
        Ok(())
    }
}

fn require_expected_absence(
    expected: ExpectedMountTeardown,
    locator: SessionLocator,
    cursor: MountAbsenceCursor,
) -> Result<(), LifecycleError> {
    match expected {
        ExpectedMountTeardown::Absent {
            locator: current,
            cursor: current_cursor,
        } if current == locator && current_cursor == cursor => Ok(()),
        ExpectedMountTeardown::Absent {
            locator: current, ..
        } if current != locator => Err(LifecycleError::WrongLocator),
        ExpectedMountTeardown::Absent { .. }
        | ExpectedMountTeardown::Owner { .. }
        | ExpectedMountTeardown::Join { .. } => Err(LifecycleError::WrongState),
    }
}

fn matches_generation<Device, Vpb>(
    rendezvous: &MountRendezvous<Device, Vpb>,
    locator: SessionLocator,
    generation: u64,
) -> bool {
    rendezvous.locator() == Some(locator)
        && match rendezvous.state {
            PrivateMountRendezvousState::Publishing {
                generation: current,
                ..
            }
            | PrivateMountRendezvousState::Present {
                generation: current,
                ..
            }
            | PrivateMountRendezvousState::TearingDown {
                generation: current,
                ..
            }
            | PrivateMountRendezvousState::Done {
                generation: current,
                ..
            }
            | PrivateMountRendezvousState::Resetting {
                generation: current,
                ..
            } => current == generation,
            PrivateMountRendezvousState::Unmounted { .. }
            | PrivateMountRendezvousState::Exhausted { .. } => {
                rendezvous.last_completed_generation == Some(generation)
            }
            PrivateMountRendezvousState::Inactive => false,
        }
}

#[cfg(test)]
mod tests;
