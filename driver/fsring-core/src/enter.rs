//! Allocation-free ENTER role, readiness, CQ, and terminal arbitration model.
//!
//! This module decides native ENTER behavior without waiting, touching an
//! event, completing an IRP, or retaining daemon-owned bytes. The native
//! adapter supplies actual SQ polls and a stable private CQ copy.

use core::{
    cmp,
    num::{NonZeroU64, NonZeroUsize},
    sync::atomic::{AtomicU64, Ordering},
};

use fsring_abi::{
    MAX_ENTER_CQ_BUDGET, SlotToken,
    codec::try_encode,
    control::{
        ENTER_RESULT_V1_PREFIX_SIZE, EnterRequestV1, EnterResultV1, NOTIFICATION_CREDIT_V1_SIZE,
        enter_request_flags, enter_result_flags,
    },
    layout::{ConsumerPage, Cqe, ProducerPage, cq_kind},
    msgs::{CONTROL_VERSION_V1, ControlHeader},
    ring::SingleConsumer,
    validate::{SessionIdentity, ValidatedTopology, enter_result_size_v1},
};

use core::ptr::NonNull;

use crate::session::{
    CqStorageBindRight, MAX_SESSION_RING_COUNT, PendingControlLinkRight, PendingError,
    PendingInstallId, RoleError, SessionRingBrand, TerminalRequest,
};
use crate::{
    grant::{GrantError, GrantTable, NotifyPreflight},
    terminal::{ClaimOutcome, ClaimantKind, TerminalClaim, TerminalOwner},
};

/// Stable provenance for role leases. It survives moves of the state value.
///
/// This follows the same monotonic-provenance model as `TerminalOwner`: wrap
/// requires 2^64 distinct state constructions in one boot.
static NEXT_ENTER_STATE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterRole {
    Sq,
    Cq,
}

/// Per-ring role and missed-wake state. It has one identity and cannot be
/// duplicated with its live owners:
///
/// ```compile_fail
/// use fsring_core::enter::RingEnterState;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<RingEnterState>();
/// ```
pub struct RingEnterState {
    ring_index: u32,
    sq_owner: Option<u64>,
    cq_owner: Option<u64>,
    sq_publish_generation: u64,
    signaled_generation: u64,
    state_id: u64,
    /// The R4 brand, present only on a state built by `for_brand`.
    ///
    /// `None` on a predecessor state, and the R4 acquisition API refuses those
    /// outright rather than inventing a brand for them.
    brand: Option<SessionRingBrand>,
    /// This state's own nonwrapping invocation source.
    ///
    /// Per-state rather than process-wide: two rings issuing invocation 7 is
    /// fine because every authority also carries the ring brand, and a shared
    /// counter would make the identity space a contention point for no gain.
    /// `None` means permanently exhausted.
    next_invocation: Option<NonZeroU64>,
    /// Set when a CSQ-parked WAIT still holds `sq_owner`. Fence
    /// `WaitExistingSqCqRolesAndConsumers` must not treat that waiter as a
    /// leftover dispatch ENTER; `WaitPendingAndOwners` drains it later.
    sq_wait_pending: bool,
}

/// Affine authority over one role in one exact [`RingEnterState`].
///
/// A released lease cannot be reused:
///
/// ```compile_fail
/// use fsring_core::enter::{EnterRole, RingEnterState};
///
/// let mut state = RingEnterState::new(0);
/// let lease = state.acquire_role(1, EnterRole::Sq).unwrap();
/// let _ = state.release_role(lease);
/// let _ = state.release_role(lease);
/// ```
///
/// External code also cannot forge the private provenance brand:
///
/// ```compile_fail
/// use fsring_core::enter::{EnterRole, RoleLease};
///
/// let _forged = RoleLease {
///     ring_index: 0,
///     invocation: 1,
///     role: EnterRole::Sq,
///     state_id: 1,
/// };
/// ```
///
/// The lease implements neither `Clone` nor `Default`:
///
/// ```compile_fail
/// use fsring_core::enter::RoleLease;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<RoleLease>();
/// ```
///
/// ```compile_fail
/// use fsring_core::enter::RoleLease;
///
/// fn needs_default<T: Default>() {}
/// needs_default::<RoleLease>();
/// ```
#[derive(Debug)]
#[must_use]
pub struct RoleLease {
    ring_index: u32,
    invocation: u64,
    role: EnterRole,
    state_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    pub generation: u64,
    /// The adapter's actual first SQ poll; never inferred from event state.
    pub ready: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnterPollObservation {
    /// Actual SQ readiness from the native ring poll.
    pub sq_ready: bool,
    /// Relevant only to a finite, nonzero WAIT timeout.
    pub timeout_expired: bool,
    /// Session admission/terminal state observed by the native adapter.
    pub fenced: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterError {
    DeviceBusy,
    InvalidFlags,
    InvalidIdentity,
    InvalidBudget,
    InvalidTimeout,
    GenerationExhausted,
    Fenced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterDecision {
    Ready,
    Pending,
    TimedOut,
    Empty,
}

/// Semantic validation result for the same stable private CQ copy whose raw
/// kind is carried by [`CqObservation`]. No variant authorizes a second read of
/// daemon-writable memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqSemantic {
    Notify,
    ProtocolAbort,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqObservation {
    pub kind: u16,
    pub sequence_stable: bool,
    /// Whether the bounded stable-prefix observation found a ready record.
    pub record_ready: bool,
    pub semantic: CqSemantic,
    /// Bytes reserved in the ENTER tail for the next returned credit.
    pub output_bytes_available: usize,
    pub credit: Option<SlotToken>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DrainPlan {
    Empty,
    Contended,
    NotifyBlocked,
    Notify(NotifyPreflight),
    GenerationExhausted,
    ProtocolAbort,
    CompletionFault,
    ProtocolFault,
}

/// Closed set of successful CQ outcomes that may reach ENTER result encoding.
/// Fault plans are deliberately not representable here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqResultState {
    None,
    Remaining,
    NotifyBlocked,
    Contended,
}

/// External terminal contenders cannot name the private successful commit:
///
/// ```compile_fail
/// use fsring_core::enter::EnterContender;
///
/// let _ = EnterContender::SuccessCommit;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterContender {
    Cancel,
    Timeout,
    Wake,
    Fence,
    Unload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimedEnterTerminal {
    // Constructed only by `PendingEnter::claim_first_commit`, which exists only
    // under `cfg(test)`. Production ENTER claims its terminals through
    // `PendingEnter::contend`, whose `EnterContender` has no success tag. The
    // variant stays because `claimant` and `completion` must stay total over
    // what the tests drive. This allow used to name "Task 12's crate-private
    // adapter" as the production caller; none exists (round-17 evidence E3).
    #[allow(dead_code)]
    SuccessCommit,
    Cancel,
    Timeout,
    Wake,
    Fence,
    Unload,
}

impl ClaimedEnterTerminal {
    const fn claimant(self) -> ClaimantKind {
        match self {
            Self::SuccessCommit | Self::Wake => ClaimantKind::EnterContinuation,
            Self::Cancel => ClaimantKind::Cancellation,
            Self::Timeout => ClaimantKind::Timeout,
            Self::Fence => ClaimantKind::Fence,
            Self::Unload => ClaimantKind::Unload,
        }
    }

    const fn completion(self) -> PendingCompletion {
        match self {
            Self::SuccessCommit => PendingCompletion::SuccessAfterCommit,
            Self::Cancel => PendingCompletion::Cancelled,
            Self::Timeout => PendingCompletion::TimedOut,
            Self::Wake => PendingCompletion::Ready,
            Self::Fence => PendingCompletion::Fenced,
            Self::Unload => PendingCompletion::Unloaded,
        }
    }
}

/// The sole affine result of winning a pending ENTER terminal CAS.
///
/// Finishing consumes the right, so completion cannot happen twice:
///
/// ```compile_fail
/// use fsring_core::enter::PendingTerminalRight;
///
/// fn finish_twice(right: PendingTerminalRight) {
///     let _ = right.finish();
///     let _ = right.finish();
/// }
/// ```
///
/// Its [`TerminalClaim`] cannot be forged either; that type's fields remain
/// private to the terminal-owner module:
///
/// ```compile_fail
/// use fsring_core::terminal::{ClaimantKind, TerminalClaim, TerminalOwner};
///
/// let owner = TerminalOwner::new();
/// let _forged = TerminalClaim {
///     winner: ClaimantKind::EnterContinuation,
///     arbitration: owner.id(),
/// };
/// ```
///
/// [`TerminalClaim`]: crate::terminal::TerminalClaim
///
/// The right implements neither `Clone` nor `Default`:
///
/// ```compile_fail
/// use fsring_core::enter::PendingTerminalRight;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<PendingTerminalRight>();
/// ```
///
/// ```compile_fail
/// use fsring_core::enter::PendingTerminalRight;
///
/// fn needs_default<T: Default>() {}
/// needs_default::<PendingTerminalRight>();
/// ```
#[derive(Debug)]
#[must_use]
pub struct PendingTerminalRight {
    terminal: ClaimedEnterTerminal,
    claim: TerminalClaim,
}

#[derive(Debug)]
pub enum PendingOutcome {
    Won(PendingTerminalRight),
    Lost { winner: Option<ClaimantKind> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCompletion {
    Cancelled,
    TimedOut,
    Ready,
    Fenced,
    Unloaded,
    SuccessAfterCommit,
}

impl RingEnterState {
    /// The R4 constructor: the ring index and state identity both come from the
    /// brand, so the two cannot disagree.
    ///
    /// `new` below keeps the predecessor shape while Tasks 15-18 stage the rest
    /// of the runtime; it allocates its own state identity from the process
    /// counter, which is exactly the drift this constructor removes. Only
    /// `build_ring_runtime_parts` calls this one.
    #[allow(dead_code)]
    pub(crate) fn for_brand(brand: SessionRingBrand) -> Self {
        Self {
            ring_index: brand.ring_index(),
            sq_owner: None,
            cq_owner: None,
            sq_publish_generation: 0,
            signaled_generation: 0,
            state_id: NEXT_ENTER_STATE_ID.fetch_add(1, Ordering::Relaxed),
            brand: Some(brand),
            next_invocation: NonZeroU64::new(1),
            sq_wait_pending: false,
        }
    }

    /// The ring index this state serves, for the factory test.
    ///
    /// `ring_index` is otherwise private and read only by `classify_request`;
    /// without this the assertion that `for_brand` carries the brand's index
    /// would have to restate the constructor, which is no check at all.
    #[cfg(test)]
    pub(crate) const fn brand_ring_index_for_test(&self) -> u32 {
        self.ring_index
    }

    /// Adopt this ring's R4 brand into a state that `new` built without one.
    ///
    /// SETUP allocates the session shell's per-ring states in
    /// `allocate_events_and_scratch`, which runs BEFORE `build_pending_runtime`
    /// mints the ring set, so the shell cannot call `for_brand`. Until this
    /// exists there is no other way to give it one, and an unbranded state
    /// answers `WrongState` to `acquire_sq_wait`, `acquire_cq_consumer` and
    /// every `check_release` — which is why the fence could never acquire a CQ
    /// consumer on any ring, and why every terminal retried for ever.
    ///
    /// One-shot and checked, so this cannot become a way to re-identify a live
    /// ring: an already-branded state is refused, a brand for a different ring
    /// index is refused, and a state that has already issued a role is refused
    /// because its outstanding tokens carry the identity this would replace.
    pub fn adopt_ring_brand(&mut self, brand: SessionRingBrand) -> Result<(), RoleError> {
        if self.brand.is_some() {
            return Err(RoleError::WrongState);
        }
        if self.ring_index != brand.ring_index() {
            return Err(RoleError::WrongRing);
        }
        if self.sq_owner.is_some() || self.cq_owner.is_some() {
            return Err(RoleError::DeviceBusy);
        }
        self.brand = Some(brand);
        Ok(())
    }

    pub fn new(ring_index: u32) -> Self {
        Self {
            ring_index,
            sq_owner: None,
            cq_owner: None,
            sq_publish_generation: 0,
            signaled_generation: 0,
            state_id: NEXT_ENTER_STATE_ID.fetch_add(1, Ordering::Relaxed),
            brand: None,
            next_invocation: NonZeroU64::new(1),
            sq_wait_pending: false,
        }
    }

    /// Classify an ENTER value that the caller already decoded and validated
    /// with `validate_enter_request_v1` at the ABI byte/header boundary.
    ///
    /// This defense-in-depth pass intentionally rechecks only forgeable
    /// operational fields: flags, identity/ring, budget, timeout, and fence.
    pub fn classify_request(
        &self,
        request: &EnterRequestV1,
        identity: SessionIdentity,
        topology: &ValidatedTopology,
        observation: EnterPollObservation,
    ) -> Result<(EnterRole, EnterDecision), EnterError> {
        let drains = request.flags & enter_request_flags::DRAIN_CQ != 0;
        let waits = request.flags & enter_request_flags::WAIT_SQ != 0;

        if request.flags & !enter_request_flags::KNOWN_MASK != 0 || (drains && waits) {
            return Err(EnterError::InvalidFlags);
        }
        if request.mount_id != identity.mount_id
            || request.session_epoch != identity.session_epoch
            || request.ring_index >= topology.ring_count()
            || request.ring_index != self.ring_index
        {
            return Err(EnterError::InvalidIdentity);
        }

        let maximum_budget = cmp::min(topology.cq_capacity(), MAX_ENTER_CQ_BUDGET);
        if (drains && (request.cq_budget == 0 || request.cq_budget > maximum_budget))
            || (!drains && request.cq_budget != 0)
        {
            return Err(EnterError::InvalidBudget);
        }
        if !waits && request.timeout_ms != 0 {
            return Err(EnterError::InvalidTimeout);
        }
        if observation.fenced {
            return Err(EnterError::Fenced);
        }

        let role = if drains { EnterRole::Cq } else { EnterRole::Sq };
        let decision = if observation.sq_ready {
            EnterDecision::Ready
        } else if drains || request.timeout_ms == 0 {
            EnterDecision::Empty
        } else if request.timeout_ms == u32::MAX {
            EnterDecision::Pending
        } else if observation.timeout_expired {
            EnterDecision::TimedOut
        } else {
            EnterDecision::Pending
        };
        Ok((role, decision))
    }

    pub fn acquire_role(
        &mut self,
        invocation: u64,
        role: EnterRole,
    ) -> Result<RoleLease, EnterError> {
        let owner = match role {
            EnterRole::Sq => &mut self.sq_owner,
            EnterRole::Cq => &mut self.cq_owner,
        };
        if owner.is_some() {
            return Err(EnterError::DeviceBusy);
        }
        *owner = Some(invocation);
        Ok(RoleLease {
            ring_index: self.ring_index,
            invocation,
            role,
            state_id: self.state_id,
        })
    }

    pub fn release_role(&mut self, lease: RoleLease) -> Result<(), (EnterError, RoleLease)> {
        if lease.state_id != self.state_id || lease.ring_index != self.ring_index {
            return Err((EnterError::InvalidIdentity, lease));
        }
        let owner = match lease.role {
            EnterRole::Sq => &mut self.sq_owner,
            EnterRole::Cq => &mut self.cq_owner,
        };
        if *owner != Some(lease.invocation) {
            return Err((EnterError::InvalidIdentity, lease));
        }
        *owner = None;
        if lease.role == EnterRole::Sq {
            self.sq_wait_pending = false;
        }
        Ok(())
    }

    /// Whether this ring's consumer slot is free right now.
    ///
    /// Separate from `r3_checkpoint_roles_and_consumers_are_drained`, which
    /// answers about BOTH roles: the checkpoint's `AcquireConsumersIncreasing`
    /// row is about the consumer alone, and a row that refused because an SQ
    /// waiter existed would be reporting the wrong thing.
    pub const fn cq_consumer_is_free(&self) -> bool {
        self.cq_owner.is_none()
    }

    /// Read-only checkpoint observation that neither predecessor ENTER role is
    /// still owned.
    ///
    /// In the R3 transport the SQ/CQ role slots are the complete resident
    /// consumer ledger. Later transports add their own owner ledgers, but this
    /// checkpoint must validate the state that this binary can actually
    /// create instead of reporting a literal-success wait.
    pub const fn r3_checkpoint_roles_and_consumers_are_drained(&self) -> bool {
        self.sq_owner.is_none() && self.cq_owner.is_none()
    }

    /// Mark the SQ owner as a CSQ-parked WAIT rather than a dispatch-thread
    /// ENTER that forgot to release.
    pub fn mark_sq_wait_pending(&mut self, lease: &RoleLease) -> Result<(), EnterError> {
        if lease.state_id != self.state_id
            || lease.ring_index != self.ring_index
            || lease.role != EnterRole::Sq
            || self.sq_owner != Some(lease.invocation)
        {
            return Err(EnterError::InvalidIdentity);
        }
        self.sq_wait_pending = true;
        Ok(())
    }

    /// True when no leftover *dispatch* SQ/CQ owner remains.
    ///
    /// A CSQ-parked WAIT still occupies `sq_owner` until its worker completes;
    /// that occupancy is a pending owner drained by `WaitPendingAndOwners`, not
    /// a stuck dispatch ENTER that `WaitExistingSqCqRolesAndConsumers` refuses.
    pub const fn leftover_dispatch_roles_are_absent(&self) -> bool {
        self.cq_owner.is_none() && (self.sq_owner.is_none() || self.sq_wait_pending)
    }

    /// The same drain, for a caller that is ITSELF this ring's CQ consumer.
    ///
    /// The R4 fence acquires every ring's consumer in
    /// `AcquireConsumersIncreasing` and only gives them back in
    /// `ReleaseConsumers`, so at `DrainStablePrefixesBounded` -- between the
    /// two -- `cq_owner` is `Some` on every ring BY CONSTRUCTION. Asking
    /// `leftover_dispatch_roles_are_absent` there asks whether a role the
    /// caller is holding is free, which is false on exactly the rings the
    /// acquire succeeded on.
    ///
    /// What is left to wait for is the SQ side. The CQ side needs no check
    /// here and gets a stronger one than a re-read would be:
    /// `acquire_cq_consumer` refuses with `DeviceBusy` when the role is
    /// already owned, so a foreign holder fails the ACQUIRE and the drain is
    /// never reached -- the caller asserts `AcquiredComplete` before calling.
    pub const fn leftover_sq_dispatch_role_is_absent(&self) -> bool {
        self.sq_owner.is_none() || self.sq_wait_pending
    }

    /// Snapshot generation alongside an actual adapter-supplied SQ poll.
    pub const fn observe_readiness(&self, sq_ready: bool) -> ReadinessSnapshot {
        ReadinessSnapshot {
            generation: self.sq_publish_generation,
            ready: sq_ready,
        }
    }

    /// Model the SQ owner's event clear. A foreign, stale, or CQ lease cannot
    /// clear; a ready observation and a post-snapshot publication both leave
    /// the signal intact.
    pub fn clear_event_after(
        &mut self,
        lease: &RoleLease,
        snapshot: ReadinessSnapshot,
    ) -> Result<(), EnterError> {
        if lease.state_id != self.state_id
            || lease.ring_index != self.ring_index
            || lease.role != EnterRole::Sq
            || self.sq_owner != Some(lease.invocation)
        {
            return Err(EnterError::InvalidIdentity);
        }
        if !snapshot.ready && self.sq_publish_generation == snapshot.generation {
            self.signaled_generation = 0;
        }
        Ok(())
    }

    /// Record a successful SQ Release publication and the generation whose
    /// native event must be signaled. The state is unchanged on exhaustion.
    pub fn publish_sq(&mut self) -> Result<u64, EnterError> {
        let next = self
            .sq_publish_generation
            .checked_add(1)
            .ok_or(EnterError::GenerationExhausted)?;
        self.sq_publish_generation = next;
        self.signaled_generation = next;
        Ok(next)
    }

    /// The generation the native event still owes a signal for.
    ///
    /// Named `owed_signal_generation` rather than matching the field: the
    /// graph auditor models an edge as a bare-name mention and merges a method
    /// with a field of the same name, which is how Task 18's core half already
    /// had to rename `next_index`.
    pub const fn owed_signal_generation(&self) -> u64 {
        self.signaled_generation
    }

    /// Publish one SQ generation, or terminalize because the counter is spent.
    ///
    /// The checked increment is `publish_sq`'s; this is the one mapping every
    /// native producer uses, so no caller decides for itself what an exhausted
    /// counter means. Because `publish_sq` leaves the state alone on refusal,
    /// a terminalized publish wraps nothing and signals nothing: the event's
    /// owed generation is exactly what it was before the attempt.
    pub fn publish_sq_or_terminalize(&mut self) -> Result<u64, TerminalRequest> {
        self.publish_sq()
            .map_err(|_| TerminalRequest::SqGenerationExhausted)
    }

    /// Place a state at an exact publish generation.
    ///
    /// `u64::MAX` is otherwise 2^64 publications away, so the exhaustion arm
    /// would be unreachable from any test and the checked increment would be
    /// asserted rather than exercised.
    #[cfg(test)]
    pub(crate) fn for_test_at_generation(ring_index: u32, generation: u64) -> Self {
        let mut state = Self::new(ring_index);
        state.sq_publish_generation = generation;
        state.signaled_generation = generation;
        state
    }

    /// Complete the poll/clear/recheck protocol from a second actual SQ poll.
    pub fn recheck_after_clear(
        &self,
        snapshot: ReadinessSnapshot,
        sq_ready_after_clear: bool,
        fenced_after_clear: bool,
    ) -> Result<EnterDecision, EnterError> {
        if fenced_after_clear {
            return Err(EnterError::Fenced);
        }
        let current_generation = self.sq_publish_generation;
        let changed = current_generation != snapshot.generation;
        if sq_ready_after_clear || changed {
            Ok(EnterDecision::Ready)
        } else {
            Ok(EnterDecision::Pending)
        }
    }

    /// Classify one bounded stable-prefix CQ observation. Notification
    /// preflight is delegated exactly once to the owning grant table and this
    /// method never claims or mutates the credit.
    pub fn classify_cq(&self, observation: CqObservation, grants: &GrantTable<'_>) -> DrainPlan {
        if !observation.sequence_stable {
            return DrainPlan::Contended;
        }
        if !observation.record_ready {
            return DrainPlan::Empty;
        }

        match observation.kind {
            cq_kind::COMPLETION => DrainPlan::CompletionFault,
            cq_kind::PROTOCOL => {
                if observation.semantic == CqSemantic::ProtocolAbort {
                    DrainPlan::ProtocolAbort
                } else {
                    DrainPlan::ProtocolFault
                }
            }
            cq_kind::NOTIFY => {
                let descriptor_size = match usize::try_from(NOTIFICATION_CREDIT_V1_SIZE) {
                    Ok(size) => size,
                    Err(_) => return DrainPlan::ProtocolFault,
                };
                if observation.output_bytes_available < descriptor_size {
                    return DrainPlan::NotifyBlocked;
                }
                if observation.semantic != CqSemantic::Notify {
                    return DrainPlan::ProtocolFault;
                }
                let Some(token) = observation.credit else {
                    return DrainPlan::ProtocolFault;
                };
                // Keep this as the sole mapping point for the complete result;
                // in particular GenerationExhausted cannot be shadowed by a
                // parallel token/error mapping in ENTER.
                classify_notify_preflight(grants.preflight_notify(
                    self.ring_index,
                    token,
                    observation.output_bytes_available,
                    token.generation(),
                ))
            }
            _ => DrainPlan::ProtocolFault,
        }
    }
}

fn classify_notify_preflight(result: Result<NotifyPreflight, GrantError>) -> DrainPlan {
    match result {
        Ok(preflight) => DrainPlan::Notify(preflight),
        Err(GrantError::ReturnBufferTooSmall) => DrainPlan::NotifyBlocked,
        Err(GrantError::GenerationExhausted) => DrainPlan::GenerationExhausted,
        Err(
            GrantError::InvalidBacking
            | GrantError::InvalidTopology
            | GrantError::TableIdentityExhausted
            | GrantError::InvalidToken
            | GrantError::WrongRing
            | GrantError::StaleGeneration,
        ) => DrainPlan::ProtocolFault,
    }
}

/// One pending ENTER and its one terminal-owner CAS.
///
/// External callers cannot mint the successful first-commit terminal -- the
/// method is crate-private and exists only under `cfg(test)`:
///
/// ```compile_fail
/// use fsring_core::enter::PendingEnter;
///
/// let pending = PendingEnter::new(1);
/// let _ = pending.claim_first_commit();
/// ```
///
/// The private success tag is not part of the public surface:
///
/// ```compile_fail
/// use fsring_core::enter::ClaimedEnterTerminal;
/// ```
///
/// Nor can a caller fabricate a notification preflight for a claimed commit:
///
/// ```compile_fail
/// use fsring_core::grant::NotifyPreflight;
///
/// let _forged = NotifyPreflight::default();
/// ```
///
/// A real preflight cannot be relabelled with a private field update either:
///
/// ```compile_fail
/// use fsring_core::grant::NotifyPreflight;
///
/// fn rebrand(seed: NotifyPreflight) {
///     let _forged = NotifyPreflight { ring_index: 0, ..seed };
/// }
/// ```
///
/// Finally, the arbitration owner itself cannot be cloned:
///
/// ```compile_fail
/// use fsring_core::enter::PendingEnter;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<PendingEnter>();
/// ```
#[cfg_attr(test, derive(Debug))]
pub struct PendingEnter {
    invocation: u64,
    terminal: TerminalOwner,
}

impl PendingEnter {
    pub fn new(invocation: u64) -> Self {
        Self {
            invocation,
            terminal: TerminalOwner::new(),
        }
    }

    pub const fn invocation(&self) -> u64 {
        self.invocation
    }

    /// Test-only. No production path claims a first commit: this allow used to
    /// name "Task 12's crate-private adapter" as the caller, and none exists
    /// (round-17 evidence E3).
    #[cfg(test)]
    pub(crate) fn claim_first_commit(&self) -> PendingOutcome {
        self.claim_terminal(ClaimedEnterTerminal::SuccessCommit)
    }

    pub fn contend(&self, terminal: EnterContender) -> PendingOutcome {
        let terminal = match terminal {
            EnterContender::Cancel => ClaimedEnterTerminal::Cancel,
            EnterContender::Timeout => ClaimedEnterTerminal::Timeout,
            EnterContender::Wake => ClaimedEnterTerminal::Wake,
            EnterContender::Fence => ClaimedEnterTerminal::Fence,
            EnterContender::Unload => ClaimedEnterTerminal::Unload,
        };
        self.claim_terminal(terminal)
    }

    fn claim_terminal(&self, terminal: ClaimedEnterTerminal) -> PendingOutcome {
        match self.terminal.claim(terminal.claimant()) {
            ClaimOutcome::Won(claim) => {
                PendingOutcome::Won(PendingTerminalRight { terminal, claim })
            }
            ClaimOutcome::Lost { winner } => PendingOutcome::Lost { winner },
        }
    }
}

impl PendingTerminalRight {
    pub fn finish(self) -> PendingCompletion {
        debug_assert_eq!(self.claim.winner(), self.terminal.claimant());
        self.terminal.completion()
    }
}

/// Derive returned-credit capacity from an entire ENTER output buffer.
///
/// Test-only: its allow named a production caller that does not exist
/// (round-17 evidence E3).
#[cfg(test)]
pub(crate) fn notification_capacity(output_bytes: usize) -> Option<usize> {
    let prefix = usize::try_from(ENTER_RESULT_V1_PREFIX_SIZE).ok()?;
    let descriptor = usize::try_from(NOTIFICATION_CREDIT_V1_SIZE).ok()?;
    output_bytes.checked_sub(prefix)?.checked_div(descriptor)
}

/// Exact successful ENTER output size: 48-byte prefix plus 32 bytes per credit.
///
/// Test-only, for the same reason as `notification_capacity`.
#[cfg(test)]
pub(crate) fn enter_result_size(notification_credit_count: u32) -> Option<usize> {
    usize::try_from(enter_result_size_v1(notification_credit_count).ok()?).ok()
}

/// Pure, role-bound ABI flag projection for an already-classified result.
pub fn result_flags(role: EnterRole, decision: EnterDecision, cq: CqResultState) -> Option<u32> {
    let readiness = match (role, decision) {
        (EnterRole::Sq | EnterRole::Cq, EnterDecision::Ready) => enter_result_flags::SQ_READY,
        (EnterRole::Sq, EnterDecision::TimedOut) => enter_result_flags::TIMED_OUT,
        (EnterRole::Sq | EnterRole::Cq, EnterDecision::Empty) => 0,
        (EnterRole::Sq, EnterDecision::Pending)
        | (EnterRole::Cq, EnterDecision::Pending | EnterDecision::TimedOut) => return None,
    };
    let cq = match (role, cq) {
        (EnterRole::Sq | EnterRole::Cq, CqResultState::None) => 0,
        (EnterRole::Cq, CqResultState::Remaining) => enter_result_flags::CQ_REMAINING,
        (EnterRole::Cq, CqResultState::NotifyBlocked) => {
            enter_result_flags::CQ_REMAINING | enter_result_flags::NOTIFY_BLOCKED
        }
        (EnterRole::Cq, CqResultState::Contended) => enter_result_flags::CQ_CONTENDED,
        (EnterRole::Sq, _) => return None,
    };
    Some(readiness | cq)
}

/// Construct the fixed, zero-credit successful prefix for an immediate ENTER.
///
/// The executor calls this rather than assembling a prefix of its own: the
/// timeout/decision consistency rules below are the wire's, and a second copy
/// of them in the image is a second place for them to drift.
pub fn build_empty_result(
    request: &EnterRequestV1,
    decision: EnterDecision,
) -> Result<EnterResultV1, EnterError> {
    build_enter_result(request, decision, 0, CqResultState::None)
}

/// Encode the parked WAIT's zero-credit prefix into `dst`.
///
/// The METHOD_BUFFERED IRP still owns this buffer until `IoCompleteRequest`.
/// Zero-filling without encoding is not a legal `EnterResultV1`.
pub fn encode_parked_empty_result(
    dst: &mut [u8],
    request: &EnterRequestV1,
    decision: EnterDecision,
) -> Result<usize, EnterError> {
    let prefix = usize::try_from(ENTER_RESULT_V1_PREFIX_SIZE).unwrap_or(usize::MAX);
    let Some(slot) = dst.get_mut(..prefix) else {
        return Err(EnterError::InvalidTimeout);
    };
    let result = build_empty_result(request, decision)?;
    slot.fill(0);
    try_encode(&result, slot).map_err(|_| EnterError::InvalidTimeout)?;
    Ok(prefix)
}

/// Construct the ENTER prefix for a drain that returned `credit_count`
/// descriptors. Zero credits and `CqResultState::None` is [`build_empty_result`].
pub fn build_enter_result(
    request: &EnterRequestV1,
    decision: EnterDecision,
    credit_count: u32,
    cq: CqResultState,
) -> Result<EnterResultV1, EnterError> {
    if decision == EnterDecision::Empty && request.timeout_ms != 0 {
        return Err(EnterError::InvalidTimeout);
    }
    if decision == EnterDecision::TimedOut
        && (request.flags & enter_request_flags::WAIT_SQ == 0
            || request.flags & enter_request_flags::DRAIN_CQ != 0
            || request.timeout_ms == 0
            || request.timeout_ms == u32::MAX)
    {
        return Err(EnterError::InvalidTimeout);
    }
    let role = if request.flags & enter_request_flags::DRAIN_CQ != 0 {
        EnterRole::Cq
    } else {
        EnterRole::Sq
    };
    if credit_count != 0 && role != EnterRole::Cq {
        return Err(EnterError::InvalidTimeout);
    }
    let flags = result_flags(role, decision, cq).ok_or(EnterError::InvalidTimeout)?;
    let struct_size = enter_result_size_v1(credit_count).map_err(|_| EnterError::InvalidBudget)?;
    let offset = if credit_count == 0 {
        0
    } else {
        ENTER_RESULT_V1_PREFIX_SIZE
    };
    Ok(EnterResultV1 {
        header: ControlHeader {
            struct_size,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        session_epoch: request.session_epoch,
        ring_index: request.ring_index,
        flags,
        cq_drained: credit_count,
        sq_ready: u32::from(decision == EnterDecision::Ready),
        notification_credit_count: credit_count,
        notification_credit_desc_size: NOTIFICATION_CREDIT_V1_SIZE,
        notification_credits_offset: offset,
        reserved: 0,
    })
}

// ---------------------------------------------------------------------------
// R4 Task 14.1: the ring runtime aggregate and its sealed factory
// ---------------------------------------------------------------------------
//
// Staged. `build_ring_runtime_parts` is the only way to construct any of the
// three components below, and the only way to construct the aggregate. That is
// the point of the whole block: a sibling module that could build a
// `PendingResultSlot` on its own could build one whose brand names a ring it
// does not own, and every later pending-install check compares against exactly
// that brand.

// R4 surface. The attributes below stop the compiler restating one diagnostic
// per item; they are not a claim that anything here is reachable.
//
// This comment used to read "the only consumers until Task 19's cutover are
// `enter::tests`, and the gate `task13_18_r4_staging_is_production_unreachable`
// is what proves that is still true." Task 19 closed, and that gate is one of
// the RETIRED staging gates -- it FAILs by design and no profile carries it, so
// it proves nothing about this block or any other.
//
// MEASURED, round 16, and NOT swept. Removing 103 of the 116 dead-code allows
// across this file and `session.rs` produces 57 dead-code diagnostics in the
// non-test build and 63 under `--all-targets`, so a substantial part of this
// surface has no consumer at all -- not production, and not these crates' own
// tests either.
//
// THE BOUNDARY, because round 16 published this as "all 103" and it is not all
// of them. The 116 were 108 bare `#[allow(dead_code)]` lines (79 here, 29 in
// `session.rs`) plus 8 `cfg_attr(not(feature = "production-attested"),
// allow(dead_code))` in `session.rs`. The 103 removed were the lines that are
// exactly the bare attribute; the 5 left in force each carried a trailing
// comment naming "Task 12's crate-private adapter" as the production caller,
// and the 8 `cfg_attr` forms were never touched. So the 57 and 63 were a LOWER
// bound, measured with 13 allows still suppressing.
//
// Those five comments were false (round-17 evidence E3): four hid a warning,
// and no such caller exists. Round 18 resolved them -- `claim_first_commit`,
// `notification_capacity` and `enter_result_size` are `cfg(test)`, the allow on
// `CqResultState` is gone (`fsring-fsd` uses it), and `SuccessCommit`'s allow
// states its real reason. MEASURED again after that: 112 allows, 104 bare lines
// (75 here, 29 in `session.rs`) plus the 8 `cfg_attr`. Removing the 104 gives
// 58 dead-code diagnostics in the non-test build and 64 under `--all-targets`,
// counted from `cargo check --message-format=json` by lint code and unique
// location -- the method that reproduces 57 and 63 on the tree before. The +1
// is `SuccessCommit`, whose allow is now a bare line the measurement removes.
// Only the 8 `cfg_attr` forms still suppress, so 58 and 64 are a lower bound too.
//
// THE OTHER CRATE, measured in round 19 because native review N18-3 raised
// that nobody had: `fsring-fsd` carries three module-wide
// `#![allow(dead_code)]` (`lifecycle.rs`, `fence.rs`, `trace.rs`) and without
// them `cargo check -p fsring-fsd --all-targets` reports 63 unique dead-code
// diagnostics -- 33, 28 and 2. That measurement needs the WDK environment,
// which is why it is a number here rather than a row anywhere.
//
// That population is recorded rather than resolved here: each item needs its own
// keep-or-delete decision, and a documentation sweep is not where those get
// made. What is true today is only that the allow is hiding them; nothing in
// this comment should be read as proof that it should.

/// One ring's parked-result storage, sized once at construction.
///
/// The capacity is fixed here and never re-derived: a slot that could be
/// re-sized after a park would let a result be written against a capacity the
/// installer never agreed to.
#[allow(dead_code)]
pub struct PendingResultSlot {
    brand: SessionRingBrand,
    install: Option<PendingInstallId>,
    capacity: usize,
}

/// The owners currently attached to one ring's pending install.
///
/// Installer, cancel, DPC, and worker are *kinds*, and at most one owner of
/// each kind may exist at a time. The ledger holds the count rather than the
/// owner values because the owner tokens themselves are affine and live with
/// their callbacks; what the ledger answers is "may another owner of this kind
/// be minted", which is the question that keeps two cancel callbacks from
/// running against one install.
#[allow(dead_code)]
pub struct PendingOwnerLedger {
    brand: SessionRingBrand,
    install: Option<PendingInstallId>,
    owners: u32,
    occupied_kinds: u8,
    closing: bool,
}

/// One ring's wake bookkeeping across a parked install.
///
/// A wake that arrives while an install is parked must not be lost, and must
/// not be replayed after the install completes. `covered` records that the
/// pending completion has already accounted for every wake seen so far.
#[allow(dead_code)]
pub struct PendingWakeSlot {
    brand: SessionRingBrand,
    wake: Option<StoredPendingWake>,
}

/// Everything one ring needs at runtime, built as one aggregate or not at all.
///
/// It retains the `CqStorageBindRight` unconsumed: Task 13 mints exactly one
/// per ring, and holding it here is what proves this aggregate — and no other —
/// speaks for that ring's CQ storage.
#[allow(dead_code)]
pub struct RingRuntimeParts {
    state: RingEnterState,
    result_slot: PendingResultSlot,
    owners: PendingOwnerLedger,
    wake: PendingWakeSlot,
    cq_bind: CqStorageBindRight,
}

/// Why a runtime build refused. Distinct variants on purpose.
///
/// A caller that passed the wrong ring and a caller that passed a nonsense
/// capacity have made different mistakes, and collapsing them into one error
/// would make the first look like the second in a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRuntimeBuildError {
    Role(RoleError),
    InvalidPendingResultCapacity,
}

/// The largest parked-result capacity a ring may declare.
pub const MAX_PENDING_RESULT_CAPACITY: usize = 1 << 20;

#[allow(dead_code)]
impl PendingResultSlot {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) const fn install(&self) -> Option<PendingInstallId> {
        self.install
    }
}

#[allow(dead_code)]
impl PendingOwnerLedger {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.owners == 0 && self.occupied_kinds == 0
    }
}

#[allow(dead_code)]
impl PendingWakeSlot {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    pub(crate) const fn is_covered(&self) -> bool {
        self.wake.is_none()
    }
}

#[allow(dead_code)]
impl RingRuntimeParts {
    /// Split the aggregate into its five owned parts.
    pub fn into_parts(
        self,
    ) -> (
        RingEnterState,
        PendingResultSlot,
        PendingOwnerLedger,
        PendingWakeSlot,
        CqStorageBindRight,
    ) {
        let Self {
            state,
            result_slot,
            owners,
            wake,
            cq_bind,
        } = self;
        (state, result_slot, owners, wake, cq_bind)
    }

    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.result_slot.brand
    }
}

/// Everything one native pending slot stores, built as one aggregate.
///
/// Task 19's `fsring-fsd` slot holds exactly these five values. They are
/// returned as one bundle rather than five results because they are only
/// meaningful together: a slot that acquired four of them and refused on the
/// fifth would be a ring whose wake slot names an install its ledger does not.
#[doc(hidden)]
#[must_use]
#[allow(dead_code)]
pub struct PendingSlotParts {
    pub state: RingEnterState,
    pub result_slot: PendingResultSlot,
    pub owners: PendingOwnerLedger,
    pub wake: PendingWakeSlot,
    pub schedule: PendingWorkerSchedule,
    /// The successor of the consumed `CqStorageBindRight`.
    ///
    /// PLAN DEVIATION, recorded because the plan cannot be followed literally.
    /// Task 20's `BrandedCqStorage::bind_storage` takes a `CqStorageBindRight`,
    /// but Task 19 already spends the one-per-ring right here — and that
    /// spending is exactly what makes "one runtime per ring" unforgeable. One
    /// right, two would-be owners, and it is not `Clone`.
    ///
    /// Splitting the right at `next_ring` would make the per-ring identity rest
    /// on two affine values instead of one; handing the right back would delete
    /// Task 19's property outright. So the right is still spent here, once, and
    /// its spending *mints* the storage ticket. Both exclusivity properties
    /// survive with a single original right, and the ticket's provenance is
    /// precisely the right that was consumed to make it.
    pub cq_storage: CqStorageBindTicket,
}

/// The one-per-ring authority to bind that ring's CQ storage.
///
/// Affine and non-`Clone`, minted only by [`build_pending_slot_parts`], which is
/// itself reachable only by consuming the ring's one-shot
/// `CqStorageBindRight`. A second storage binding for one ring therefore has
/// nothing to call with, which is the property Task 20's signature was reaching
/// for when it asked for the right directly.
#[doc(hidden)]
#[must_use]
#[derive(Debug)]
pub struct CqStorageBindTicket {
    brand: SessionRingBrand,
}

#[allow(dead_code)]
impl CqStorageBindTicket {
    /// Which ring this ticket binds storage for.
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    /// Consume the ticket, yielding the ring it spoke for.
    ///
    /// Consuming rather than borrowing is the point: after this there is no
    /// ticket left to bind a second storage with.
    pub(crate) fn into_brand(self) -> SessionRingBrand {
        let Self { brand } = self;
        brand
    }
}

impl PendingSlotParts {
    /// Which ring these five values were built for.
    ///
    /// The native builder consumes the one-shot right and never sees a brand,
    /// so this is the only thing it can compare against the set brand it is
    /// about to publish under. It reports; it cannot rebind.
    #[doc(hidden)]
    pub const fn ring_brand(&self) -> SessionRingBrand {
        self.result_slot.brand
    }
}

/// Build one pending slot's runtime from the ring's one-shot bind right.
///
/// The right is consumed, which is what makes "one runtime per ring" a fact
/// rather than a convention: `SessionRingSetInitializer::next_ring` mints
/// exactly one per ring, it is not `Clone`, and this is where it ends. A
/// second call for the same ring has nothing to call with.
///
/// A refusal returns the right exactly as received, so the caller can still
/// abort the whole set cleanly. `fsring-fsd` never sees the brand: it hands
/// over the right and gets back the five values, so there is no path on which
/// a native caller holds a brand it could pair with the wrong ring.
#[doc(hidden)]
pub fn build_pending_slot_parts(
    cq_bind: CqStorageBindRight,
    pending_result_capacity: usize,
) -> Result<PendingSlotParts, (RingRuntimeBuildError, CqStorageBindRight)> {
    let brand = cq_bind.brand();
    let parts = build_ring_runtime_parts(brand, pending_result_capacity, cq_bind)?;
    let (state, result_slot, owners, wake, cq_bind) = parts.into_parts();
    // The bind right ends here. It proved which ring this runtime is for, and
    // retaining it would leave a second thing able to speak for the ring. What
    // succeeds it is the storage ticket below: one right in, one runtime and one
    // storage authority out, both for the ring the right named.
    let consumed = cq_bind.into_brand();
    Ok(PendingSlotParts {
        state,
        result_slot,
        owners,
        wake,
        schedule: PendingWorkerSchedule::for_brand(brand),
        cq_storage: CqStorageBindTicket { brand: consumed },
    })
}

/// The sole construction bridge for a ring's runtime parts.
///
/// Order matters and is the content of the function. Capacity is validated
/// *first*, before any component exists, and the brand cross-check follows —
/// both before anything is built, so a refusal has constructed nothing at all
/// and returns the caller's `CqStorageBindRight` exactly as received. A factory
/// that built the components first and validated afterwards would have to drop
/// three half-initialized values on the refusal path, and dropping an affine
/// component is how a ring loses the only token that speaks for it.
#[allow(dead_code)]
/// Hidden-public for Task 19: `fsring-fsd` builds one of these per ring when
/// SETUP installs the pending runtime into the permanent cell.
///
/// Still the ONLY constructor for all four components. A sibling that could
/// build a `PendingResultSlot` on its own could build one whose brand names a
/// ring it does not own, and every later pending-install check compares against
/// exactly that brand -- so the seal is on the construction, not on the crate.
#[doc(hidden)]
pub fn build_ring_runtime_parts(
    brand: SessionRingBrand,
    pending_result_capacity: usize,
    cq_bind: CqStorageBindRight,
) -> Result<RingRuntimeParts, (RingRuntimeBuildError, CqStorageBindRight)> {
    if pending_result_capacity == 0 || pending_result_capacity > MAX_PENDING_RESULT_CAPACITY {
        return Err((RingRuntimeBuildError::InvalidPendingResultCapacity, cq_bind));
    }
    if cq_bind.brand() != brand {
        return Err((RingRuntimeBuildError::Role(RoleError::WrongRing), cq_bind));
    }
    Ok(RingRuntimeParts {
        state: RingEnterState::for_brand(brand),
        result_slot: PendingResultSlot {
            brand,
            install: None,
            capacity: pending_result_capacity,
        },
        owners: PendingOwnerLedger {
            brand,
            install: None,
            owners: 0,
            occupied_kinds: 0,
            closing: false,
        },
        wake: PendingWakeSlot { brand, wake: None },
        cq_bind,
    })
}

// ---------------------------------------------------------------------------
// R5 Task 20: binding the ABI CQ cursor to one live session ring
// ---------------------------------------------------------------------------
//
// The ABI owns the cursor arithmetic and the deferred pop; this layer owns
// *whose* cursor it is. A `SingleConsumer` attached to the right memory but the
// wrong ring would drain a queue the caller has no authority over, and nothing
// in the ABI can tell those apart — it sees pointers, not sessions.

/// Why one CQ storage or consumer binding was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqBindError {
    WrongLocator,
    WrongRing,
    WrongExecutionDomain,
    WrongStorage,
    ZeroCapacity,
    NonPowerOfTwoCapacity,
    StorageOverflow,
}

/// The three spans of one pinned CQ mapping, and its entry count.
///
/// Validated on construction so a descriptor that exists is one whose capacity
/// the ABI's mask arithmetic accepts. `SingleConsumer::attach_cq` documents a
/// power-of-two capacity of at least two as a *precondition*; checking it here
/// turns that into a refusal instead of a debug assertion in a release driver.
#[doc(hidden)]
#[derive(Debug)]
pub struct CqStorageDescriptor {
    producer_page: NonNull<ProducerPage>,
    consumer_page: NonNull<ConsumerPage>,
    entries: NonNull<Cqe>,
    capacity: usize,
}

impl CqStorageDescriptor {
    /// # Safety
    /// All three spans are aligned, initialized, nonoverlapping parts of the
    /// same pinned live CQ mapping and stay valid until fence teardown. In
    /// particular `entries` is valid for exactly `capacity` `Cqe` objects: the
    /// checks below decide only what the *number* has to be for the ABI's mask
    /// arithmetic to work, and no check here can observe how much memory the
    /// pointer actually covers.
    #[doc(hidden)]
    pub unsafe fn from_raw_parts(
        producer_page: NonNull<ProducerPage>,
        consumer_page: NonNull<ConsumerPage>,
        entries: NonNull<Cqe>,
        capacity: usize,
    ) -> Result<Self, CqBindError> {
        if capacity == 0 {
            return Err(CqBindError::ZeroCapacity);
        }
        if capacity < 2 || !capacity.is_power_of_two() {
            return Err(CqBindError::NonPowerOfTwoCapacity);
        }
        // The entry span must be expressible at all. A capacity whose byte size
        // overflows would make every later bounds argument vacuous.
        if capacity.checked_mul(core::mem::size_of::<Cqe>()).is_none() {
            return Err(CqBindError::StorageOverflow);
        }
        Ok(Self {
            producer_page,
            consumer_page,
            entries,
            capacity,
        })
    }

    /// No caller, in production or in tests. Kept rather than deleted because a
    /// descriptor that could not report its capacity would push every later
    /// reader at the private field instead.
    ///
    /// This doc used to read "`CqDrainAuthority` and the credit preflight read
    /// it when the rest of Task 20 lands." Task 20 closed without either reading
    /// it, and the CQ storage lane this type belongs to has no production
    /// constructor at all -- see the gate document's section 11 non-claim. The
    /// accessor's justification is the design reason above, which does not turn
    /// on any commit.
    #[allow(dead_code)]
    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The byte span the entry array occupies.
    ///
    /// Checked at construction, so this cannot overflow here.
    pub(crate) const fn entry_bytes(&self) -> usize {
        self.capacity.saturating_mul(core::mem::size_of::<Cqe>())
    }
}

/// One ring's CQ storage, bound to the ring that owns it.
///
/// The ticket is consumed, so a second storage binding for one ring has nothing
/// to call with — the same shape `build_pending_slot_parts` uses for the runtime
/// itself, and for the same reason.
#[doc(hidden)]
#[derive(Debug)]
pub struct BrandedCqStorage {
    brand: SessionRingBrand,
    descriptor: CqStorageDescriptor,
}

impl BrandedCqStorage {
    /// # Safety
    /// `descriptor` is the one pinned CQ mapping of the ring this ticket names,
    /// and it remains owned by that session until fence teardown.
    #[doc(hidden)]
    pub unsafe fn bind_storage(
        ticket: CqStorageBindTicket,
        descriptor: CqStorageDescriptor,
    ) -> Self {
        Self {
            brand: ticket.into_brand(),
            descriptor,
        }
    }

    /// No caller, in production or in tests. It is what would make "this storage
    /// is that ring's" answerable at all, and it is kept for that reason.
    ///
    /// This doc used to read "the drain authority compares it against the stream
    /// it was handed when the rest of Task 20 lands." Task 20 closed without the
    /// comparison arriving, on a type whose lane has no production constructor.
    #[allow(dead_code)]
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    /// Attach the sole CQ consumer over the exact backing this storage names.
    ///
    /// **What the length check is and is not.** `backing.len()` is compared
    /// against the entry span, which catches a mapping shorter than the
    /// capacity claims -- the case that makes a drain read past the end of a
    /// section. It is a comparison of two integers: it does not, and cannot,
    /// relate `backing`'s address range to the descriptor's pointers, and the
    /// cursor is attached over the descriptor's own spans rather than over
    /// `backing`. That `backing` is the same mapping is the caller's obligation
    /// below, not something this function establishes.
    ///
    /// `backing` therefore does two things: it bounds `'guard`, so the returned
    /// consumer cannot outlive the guard hold, and it is the length witness.
    ///
    /// # Safety
    /// `backing` is the live mapping the descriptor's spans point into, and the
    /// caller holds the matching per-ring guard for `'guard`. Because the
    /// returned consumer is the sole owner of the shared head field, the caller
    /// must not hold two of them over one storage at the same time.
    #[doc(hidden)]
    pub unsafe fn borrow_consumer<'guard>(
        &self,
        backing: &'guard mut [u8],
    ) -> Result<ScopedBrandedCqConsumer<'guard>, CqBindError> {
        if backing.len() < self.descriptor.entry_bytes() {
            return Err(CqBindError::WrongStorage);
        }
        // SAFETY: the caller's mapping contract, plus the capacity checked at
        // descriptor construction and the span checked just above.
        let consumer = unsafe {
            SingleConsumer::<Cqe>::attach_cq(
                self.descriptor.producer_page.as_ptr(),
                self.descriptor.consumer_page.as_ptr(),
                self.descriptor.entries.as_ptr(),
                self.descriptor.capacity,
            )
        };
        Ok(ScopedBrandedCqConsumer {
            brand: self.brand,
            consumer,
        })
    }
}

/// A CQ consumer that knows which ring it drains, borrowed for one guard hold.
#[doc(hidden)]
pub struct ScopedBrandedCqConsumer<'guard> {
    brand: SessionRingBrand,
    consumer: SingleConsumer<'guard, Cqe>,
}

#[allow(dead_code)]
impl<'guard> ScopedBrandedCqConsumer<'guard> {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    /// Whether this consumer drains the ring `stream` speaks for.
    ///
    /// The question a drain authority must ask before it pops: a consumer bound
    /// to the right memory but the wrong ring is exactly what the brand exists
    /// to catch, and the ABI cursor cannot tell the difference.
    pub(crate) fn serves(&self, stream: CqStreamBrand) -> bool {
        self.brand == stream.ring_brand()
    }

    pub(crate) fn cursor_mut(&mut self) -> &mut SingleConsumer<'guard, Cqe> {
        &mut self.consumer
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.1: the state-owned invocation source and two disjoint authorities
// ---------------------------------------------------------------------------
//
// The predecessor `acquire_role(invocation, role)` takes the invocation id from
// its caller and tags the returned lease with a `role` field. Both are the
// defects this block removes:
//
//   * A caller-supplied invocation means two callers can name the same one, and
//     a lease that compares equal to another lease is not an authority.
//   * A tagged role means "is this the SQ lease?" is a runtime question. Two
//     distinct types make it a compile-time one, so a CQ token can never be
//     passed where an SQ lease is required no matter what the value holds.
//
// Staged: the R4 API refuses on a state the predecessor `new` built, because
// only `for_brand` records a brand. That is the staging boundary expressed in
// the type rather than in the gate alone.

/// One ENTER invocation's identity. Nonwrapping and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EnterInvocationId(NonZeroU64);

impl EnterInvocationId {
    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Which of the two disjoint execution domains an authority speaks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnterExecutionDomain {
    SqWait,
    CqConsumer,
}

/// The full brand one execution carries: ring, invocation, and domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EnterExecutionBrand {
    ring: SessionRingBrand,
    invocation: EnterInvocationId,
    domain: EnterExecutionDomain,
}

#[allow(dead_code)]
impl EnterExecutionBrand {
    pub(crate) const fn ring(&self) -> SessionRingBrand {
        self.ring
    }

    pub(crate) const fn invocation(&self) -> EnterInvocationId {
        self.invocation
    }

    pub(crate) const fn domain(&self) -> EnterExecutionDomain {
        self.domain
    }
}

/// Affine authority over one ring's SQ-wait role.
///
/// Neither `Clone` nor `Copy`, and it shares no type with the CQ token below.
/// The disjointness is the point, so it is checked rather than asserted in
/// prose -- a CQ token cannot be released as an SQ lease:
///
/// ```compile_fail
/// use fsring_core::enter::{CqConsumerToken, RingEnterState};
///
/// fn release(state: &mut RingEnterState, token: CqConsumerToken) {
///     let _ = state.release_sq_wait(token);
/// }
/// ```
///
/// nor an SQ lease as a CQ token:
///
/// ```compile_fail
/// use fsring_core::enter::{RingEnterState, SqWaitRoleLease};
///
/// fn release(state: &mut RingEnterState, lease: SqWaitRoleLease) {
///     let _ = state.release_cq_consumer(lease);
/// }
/// ```
///
/// and neither is `Clone`, so an authority cannot be held twice:
///
/// ```compile_fail
/// use fsring_core::enter::SqWaitRoleLease;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<SqWaitRoleLease>();
/// ```
///
/// ```compile_fail
/// use fsring_core::enter::CqConsumerToken;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<CqConsumerToken>();
/// ```
#[must_use]
#[derive(Debug)]
pub struct SqWaitRoleLease {
    execution: EnterExecutionBrand,
}

/// Affine authority over one ring's CQ-consumer role.
#[must_use]
#[derive(Debug)]
pub struct CqConsumerToken {
    execution: EnterExecutionBrand,
}

#[allow(dead_code)]
impl SqWaitRoleLease {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }
}

#[allow(dead_code)]
impl CqConsumerToken {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.execution.ring
    }

    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    /// The CQ stream this token speaks for.
    ///
    /// Borrows rather than consumes: binding a drain must not spend the role, or
    /// a refused bind would have released the ring's consumer to nobody.
    pub(crate) const fn cq_stream(&self) -> CqStreamBrand {
        CqStreamBrand {
            execution: self.execution,
        }
    }
}

/// One CQ stream's identity: which ring, which invocation, which domain.
///
/// It is `EnterExecutionBrand` narrowed to the CQ side, and it exists as its own
/// type rather than as a reused execution brand because Tasks 20 and 21 hang
/// every CQ authority off it — a pop, a preflight, a protocol commit. Reusing
/// the wider brand would let an SQ-domain execution be presented where a CQ
/// stream is required, and the whole point of the two disjoint domains is that
/// it cannot.
///
/// The only production route is [`CqConsumerToken::cq_stream`], so a stream
/// brand cannot exist without the affine consumer role that speaks for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CqStreamBrand {
    execution: EnterExecutionBrand,
}

#[allow(dead_code)]
impl CqStreamBrand {
    pub(crate) const fn ring_brand(&self) -> SessionRingBrand {
        self.execution.ring
    }

    pub(crate) const fn locator(&self) -> crate::session::SessionLocator {
        self.execution.ring.locator()
    }

    pub(crate) const fn ring_index(&self) -> u32 {
        self.execution.ring.ring_index()
    }

    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    /// Whether this stream is the CQ-consumer domain.
    ///
    /// A stream minted from `CqConsumerToken` always is; the predicate exists so
    /// a later packet type can *check* rather than assume, which is what keeps
    /// the narrowing honest if another minter is ever added.
    pub(crate) const fn is_cq_domain(&self) -> bool {
        matches!(self.execution.domain, EnterExecutionDomain::CqConsumer)
    }
}

impl RingEnterState {
    /// The brand this state serves, if it was built by the R4 factory.
    ///
    /// `None` for a predecessor state built by `new`. The R4 acquisition API
    /// below refuses those outright rather than inventing a brand for them,
    /// which is what keeps the two models from quietly meeting.
    #[allow(dead_code)]
    pub(crate) const fn brand(&self) -> Option<SessionRingBrand> {
        self.brand
    }

    /// Mint the next invocation for this state, or report permanent exhaustion.
    ///
    /// `u64::MAX` is issued **once** and the source then latches shut: the next
    /// call and every call after it return `InvocationIdExhausted`. Wrapping to
    /// 1 would hand out an identity a live authority already carries, and
    /// refusing at `MAX - 1` would silently discard the last usable one.
    fn mint_invocation(&mut self) -> Result<EnterInvocationId, RoleError> {
        let Some(current) = self.next_invocation else {
            return Err(RoleError::InvocationIdExhausted);
        };
        self.next_invocation = current.get().checked_add(1).and_then(NonZeroU64::new);
        Ok(EnterInvocationId(current))
    }

    /// Acquire this ring's SQ-wait role.
    ///
    /// The invocation is minted **after** the preflight, so a refused
    /// acquisition consumes no identity — `failed_role_preflight_does_not_consume_an_invocation`
    /// is the check, and the ordering is the reason it holds. Minting first
    /// would burn one identity per busy poll, and a busy ring is polled often.
    pub fn acquire_sq_wait(&mut self) -> Result<SqWaitRoleLease, RoleError> {
        let Some(ring) = self.brand else {
            return Err(RoleError::WrongState);
        };
        if self.sq_owner.is_some() {
            return Err(RoleError::DeviceBusy);
        }
        let invocation = self.mint_invocation()?;
        self.sq_owner = Some(invocation.get());
        Ok(SqWaitRoleLease {
            execution: EnterExecutionBrand {
                ring,
                invocation,
                domain: EnterExecutionDomain::SqWait,
            },
        })
    }

    /// Acquire this ring's CQ-consumer role.
    pub fn acquire_cq_consumer(&mut self) -> Result<CqConsumerToken, RoleError> {
        let Some(ring) = self.brand else {
            return Err(RoleError::WrongState);
        };
        if self.cq_owner.is_some() {
            return Err(RoleError::DeviceBusy);
        }
        let invocation = self.mint_invocation()?;
        self.cq_owner = Some(invocation.get());
        Ok(CqConsumerToken {
            execution: EnterExecutionBrand {
                ring,
                invocation,
                domain: EnterExecutionDomain::CqConsumer,
            },
        })
    }

    /// Release an SQ-wait lease. Refusal returns the exact lease, unconsumed.
    pub fn release_sq_wait(
        &mut self,
        lease: SqWaitRoleLease,
    ) -> Result<(), (RoleError, SqWaitRoleLease)> {
        match self.check_release(lease.execution, EnterExecutionDomain::SqWait) {
            Ok(()) => {
                self.sq_owner = None;
                Ok(())
            }
            Err(error) => Err((error, lease)),
        }
    }

    /// Release a CQ-consumer token. Refusal returns the exact token.
    pub fn release_cq_consumer(
        &mut self,
        token: CqConsumerToken,
    ) -> Result<(), (RoleError, CqConsumerToken)> {
        match self.check_release(token.execution, EnterExecutionDomain::CqConsumer) {
            Ok(()) => {
                self.cq_owner = None;
                Ok(())
            }
            Err(error) => Err((error, token)),
        }
    }

    /// The whole-brand check both releases share.
    ///
    /// One body rather than two so the SQ and CQ paths cannot drift into
    /// checking different things — the failure mode where one domain quietly
    /// stops comparing the ring.
    fn check_release(
        &self,
        execution: EnterExecutionBrand,
        expected: EnterExecutionDomain,
    ) -> Result<(), RoleError> {
        let Some(ring) = self.brand else {
            return Err(RoleError::WrongState);
        };
        if execution.domain != expected {
            return Err(RoleError::WrongState);
        }
        if execution.ring != ring {
            return Err(RoleError::WrongRing);
        }
        let owner = match expected {
            EnterExecutionDomain::SqWait => self.sq_owner,
            EnterExecutionDomain::CqConsumer => self.cq_owner,
        };
        if owner != Some(execution.invocation.get()) {
            return Err(RoleError::WrongInvocation);
        }
        Ok(())
    }

    /// Force the invocation source to its last usable value, for the
    /// exhaustion test.
    ///
    /// Burning 2^64 invocations through the real API is not a test anybody can
    /// run, and without this seam the latch-shut branch would be unreachable —
    /// which is exactly the kind of code that rots into being wrong.
    #[cfg(test)]
    pub(crate) fn seed_last_invocation_for_test(&mut self) {
        self.next_invocation = NonZeroU64::new(u64::MAX);
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.3: owner kinds, coalescing wakes, and the worker schedule machine
// ---------------------------------------------------------------------------

macro_rules! pending_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug)]
            struct $name(());
        )+
    };
}

// R4 surface, same boundary as the block above -- including the measured
// dead-code population recorded there. The previous wording ("`enter::tests` is
// the only consumer until Task 19, and the staging gate is what proves it")
// named a task that has closed and a gate that is retired.
#[allow(dead_code)]
mod _r4_task_14_3_staging_marker {}

pending_authority_seals!(
    PrivatePendingOwnerAuthority,
    PrivateStoredPendingWakeAuthority,
    PrivateWorkerWakeBatchAuthority,
    PrivatePendingWakeDecisionAuthority,
    PrivateSelectedPendingInstallAuthority,
    PrivateHandoffDoneReceiptAuthority,
    PrivateQueueWorkRightAuthority,
    PrivatePendingRuntimeReadyAuthority,
);

/// The four callback kinds that may own a pending install.
///
/// Kinds, not instances: at most one owner of each kind exists at a time, which
/// is what keeps two cancel callbacks from running against one install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingOwnerKind {
    Installer,
    Worker,
    Dpc,
    Cancel,
}

impl PendingOwnerKind {
    const fn bit(self) -> u8 {
        match self {
            Self::Installer => 1,
            Self::Worker => 1 << 1,
            Self::Dpc => 1 << 2,
            Self::Cancel => 1 << 3,
        }
    }
}

/// One callback's affine ownership of one pending install.
#[must_use]
#[derive(Debug)]
#[allow(dead_code)]
pub struct PendingOwnerToken {
    install: PendingInstallId,
    kind: PendingOwnerKind,
    authority: PrivatePendingOwnerAuthority,
}

#[allow(dead_code)]
impl PendingOwnerToken {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub(crate) const fn kind(&self) -> PendingOwnerKind {
        self.kind
    }
}

/// Whether the install has finished handing off to the queue.
///
/// A wake that arrives while `Installing` must not schedule anything: the
/// installer is still publishing the state a worker would read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallAxis {
    Installing,
    HandoffDone,
}

/// Why a pending install was woken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingReason {
    Cancel,
    Timeout,
    Readiness,
    Fence,
    Unload,
}

impl PendingReason {
    const fn bit(self) -> u8 {
        match self {
            Self::Cancel => 1,
            Self::Timeout => 1 << 1,
            Self::Readiness => 1 << 2,
            Self::Fence => 1 << 3,
            Self::Unload => 1 << 4,
        }
    }

    /// The closed noncancel priority, highest first.
    ///
    /// Unload outranks everything because the driver is going away and no other
    /// reason can still be serviced; Fence outranks Timeout because a fenced
    /// session must not report an ordinary expiry; Timeout outranks Readiness
    /// because a request that already expired must not be answered as ready.
    /// The order is a constant rather than a chain of comparisons so a test can
    /// walk every pair.
    pub const NONCANCEL_PRIORITY: [Self; 4] =
        [Self::Unload, Self::Fence, Self::Timeout, Self::Readiness];

    /// Reasons a PASSIVE worker pass may select, highest first.
    ///
    /// Cancel sits above Timeout/Readiness because a CSQ cancel callback has
    /// already dequeued the IRP: the worker must complete STATUS_CANCELLED
    /// rather than treat the request as ready or expired. Unload and Fence
    /// still outrank it.
    pub const WORKER_PRIORITY: [Self; 5] = [
        Self::Unload,
        Self::Fence,
        Self::Cancel,
        Self::Timeout,
        Self::Readiness,
    ];
}

/// The coalesced reasons stored against one install.
#[derive(Debug)]
#[allow(dead_code)]
pub struct StoredPendingWake {
    install: PendingInstallId,
    reasons: u8,
    authority: PrivateStoredPendingWakeAuthority,
}

/// The reasons handed to one worker pass, moved rather than copied.
#[must_use]
#[derive(Debug)]
#[allow(dead_code)]
pub struct WorkerWakeBatch {
    install: PendingInstallId,
    reasons: u8,
    authority: PrivateWorkerWakeBatchAuthority,
}

#[allow(dead_code)]
impl WorkerWakeBatch {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub(crate) const fn covers(&self, reason: PendingReason) -> bool {
        self.reasons & reason.bit() != 0
    }
}

/// One selected noncancel wake, with the batch that produced it.
#[must_use]
#[derive(Debug)]
#[allow(dead_code)]
pub struct PendingWakeDecision {
    batch: WorkerWakeBatch,
    reason: PendingReason,
    authority: PrivatePendingWakeDecisionAuthority,
}

#[allow(dead_code)]
impl PendingWakeDecision {
    /// Which coalesced wake this pass is completing.
    ///
    /// Public because the native worker turns it into the reason on its CSQ
    /// dequeue receipt: the precedence in `WORKER_PRIORITY` is the only thing
    /// that decides which of several stored wakes owns the completion, and a
    /// worker that re-derived it from the raw flags would be a second copy of
    /// that order.
    pub const fn reason(&self) -> PendingReason {
        self.reason
    }

    pub(crate) const fn batch(&self) -> &WorkerWakeBatch {
        &self.batch
    }

    pub(crate) fn into_batch(self) -> WorkerWakeBatch {
        let Self {
            batch,
            reason: _,
            authority: PrivatePendingWakeDecisionAuthority(()),
        } = self;
        batch
    }
}

/// The closed worker scheduling machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerScheduleState {
    Idle,
    Queued,
    Running,
    RunningReschedule,
    Completing,
}

impl PendingOwnerLedger {
    /// Bind this ledger to the one install it serves.
    pub fn bind_install(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if install.brand() != self.brand {
            return Err(PendingError::WrongRing);
        }
        if self.install.is_some() {
            return Err(PendingError::SlotOccupied);
        }
        self.install = Some(install);
        Ok(())
    }

    /// Release the install this ledger served, so the ring can serve another.
    ///
    /// The closing half of [`Self::bind_install`]. Without it a ring binds one
    /// install for the life of the session and every later park refuses at
    /// `SlotOccupied`. Unbinding while an owner is still outstanding would
    /// strand that owner with no ledger to release it into, so a live owner
    /// refuses instead.
    pub fn unbind_install(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if self.install != Some(install) {
            return Err(PendingError::WrongInstall);
        }
        if self.owners != 0 {
            return Err(PendingError::OwnersRemain);
        }
        self.install = None;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) const fn bound_install(&self) -> Option<PendingInstallId> {
        self.install
    }

    #[allow(dead_code)]
    pub(crate) const fn owner_count(&self) -> u32 {
        self.owners
    }

    pub(crate) const fn holds(&self, kind: PendingOwnerKind) -> bool {
        self.occupied_kinds & kind.bit() != 0
    }

    /// Mint the one owner token of `kind` for this install.
    pub fn acquire_owner(
        &mut self,
        install: PendingInstallId,
        kind: PendingOwnerKind,
    ) -> Result<PendingOwnerToken, PendingError> {
        if self.closing {
            return Err(PendingError::Closing);
        }
        if self.install != Some(install) {
            return Err(PendingError::WrongInstall);
        }
        if self.holds(kind) {
            return Err(PendingError::DuplicateOwner);
        }
        let Some(owners) = self.owners.checked_add(1) else {
            return Err(PendingError::OwnerOverflow);
        };
        self.owners = owners;
        self.occupied_kinds |= kind.bit();
        Ok(PendingOwnerToken {
            install,
            kind,
            authority: PrivatePendingOwnerAuthority(()),
        })
    }

    /// Release one owner. Refusal returns the exact token.
    pub fn release_owner(
        &mut self,
        token: PendingOwnerToken,
    ) -> Result<(), (PendingError, PendingOwnerToken)> {
        if self.install != Some(token.install) {
            return Err((PendingError::WrongInstall, token));
        }
        if !self.holds(token.kind) {
            return Err((PendingError::WrongOwnerKind, token));
        }
        self.occupied_kinds &= !token.kind.bit();
        self.owners = self.owners.saturating_sub(1);
        Ok(())
    }

    /// Stop admitting new owners. Existing ones still release.
    pub fn begin_closing(&mut self) {
        self.closing = true;
    }

    /// Whether every owner has left. Closing alone is not empty.
    #[allow(dead_code)]
    pub(crate) const fn owners_drained(&self) -> bool {
        self.owners == 0 && self.occupied_kinds == 0
    }
}

impl PendingWakeSlot {
    /// Coalesce one wake reason against this install.
    ///
    /// Reasons accumulate rather than replace: a Readiness that arrives after a
    /// Fence must not erase the Fence, and a second Fence must not queue a
    /// second worker pass. That is what makes the slot a *set* of reasons with
    /// one owner rather than a queue.
    pub fn record_wake(
        &mut self,
        install: PendingInstallId,
        reason: PendingReason,
    ) -> Result<(), PendingError> {
        if install.brand() != self.brand {
            return Err(PendingError::WrongRing);
        }
        match &mut self.wake {
            Some(stored) if stored.install == install => {
                stored.reasons |= reason.bit();
                Ok(())
            }
            Some(_) => Err(PendingError::WrongInstall),
            slot @ None => {
                *slot = Some(StoredPendingWake {
                    install,
                    reasons: reason.bit(),
                    authority: PrivateStoredPendingWakeAuthority(()),
                });
                Ok(())
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn has_wake(&self) -> bool {
        self.wake.is_some()
    }

    /// Whether a stored wake for this install still carries `reason`.
    ///
    /// The PASSIVE completion pass peeks Cancel before taking the batch: the
    /// CSQ callback already dequeued, and the result write must be
    /// `STATUS_CANCELLED` with zero information rather than a successful
    /// empty ENTER.
    pub fn stored_covers(&self, reason: PendingReason) -> bool {
        self.wake
            .as_ref()
            .is_some_and(|stored| stored.reasons & reason.bit() != 0)
    }

    /// Take the coalesced batch for one worker pass and select its reason.
    ///
    /// Cancel is selectable: the CSQ cancel callback runs at DISPATCH and
    /// cannot complete the IRP, so the PASSIVE worker is the path that
    /// completes STATUS_CANCELLED. A stored Cancel-only wake therefore yields
    /// `Cancel` rather than `WrongReason`.
    pub fn take_for_worker(
        &mut self,
        install: PendingInstallId,
    ) -> Result<PendingWakeDecision, PendingError> {
        let Some(stored) = self.wake.as_ref() else {
            return Err(PendingError::NotDequeued);
        };
        if stored.install != install {
            return Err(PendingError::WrongInstall);
        }
        let reasons = stored.reasons;
        let Some(selected) = PendingReason::WORKER_PRIORITY
            .iter()
            .copied()
            .find(|reason| reasons & reason.bit() != 0)
        else {
            return Err(PendingError::WrongReason);
        };
        let Some(taken) = self.wake.take() else {
            unreachable!("the stored wake was observed above")
        };
        let StoredPendingWake {
            install,
            reasons,
            authority: PrivateStoredPendingWakeAuthority(()),
        } = taken;
        Ok(PendingWakeDecision {
            batch: WorkerWakeBatch {
                install,
                reasons,
                authority: PrivateWorkerWakeBatchAuthority(()),
            },
            reason: selected,
            authority: PrivatePendingWakeDecisionAuthority(()),
        })
    }

    /// Put a refused decision back exactly as it was.
    ///
    /// A preflight that refuses after the batch left the slot must not drop it:
    /// the reasons it carries are the only record that those wakes happened.
    pub fn restore(
        &mut self,
        decision: PendingWakeDecision,
    ) -> Result<(), (PendingError, PendingWakeDecision)> {
        if self.wake.is_some() {
            return Err((PendingError::SlotOccupied, decision));
        }
        if decision.batch.install.brand() != self.brand {
            return Err((PendingError::WrongRing, decision));
        }
        let batch = decision.into_batch();
        let WorkerWakeBatch {
            install,
            reasons,
            authority: PrivateWorkerWakeBatchAuthority(()),
        } = batch;
        self.wake = Some(StoredPendingWake {
            install,
            reasons,
            authority: PrivateStoredPendingWakeAuthority(()),
        });
        Ok(())
    }
}

/// One install's worker scheduling, coupled to its install axis.
///
/// Kept beside the wake slot rather than inside it because the two answer
/// different questions: the slot says *what* happened, this says *who is
/// allowed to act on it*.
#[derive(Debug)]
#[allow(dead_code)]
pub struct PendingWorkerSchedule {
    brand: SessionRingBrand,
    install: Option<PendingInstallId>,
    axis: InstallAxis,
    state: WorkerScheduleState,
}

#[allow(dead_code)]
impl PendingWorkerSchedule {
    /// Hidden-public for Task 19, for the same reason as
    /// [`build_ring_runtime_parts`]: the schedule is per-ring state the native
    /// slot owns, and it can only be built from a brand.
    #[doc(hidden)]
    pub const fn for_brand(brand: SessionRingBrand) -> Self {
        Self {
            brand,
            install: None,
            axis: InstallAxis::Installing,
            state: WorkerScheduleState::Idle,
        }
    }

    pub(crate) const fn state(&self) -> WorkerScheduleState {
        self.state
    }

    pub(crate) const fn axis(&self) -> InstallAxis {
        self.axis
    }

    /// Bind the install this schedule serves, still `Installing`.
    pub fn begin_install(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if install.brand() != self.brand {
            return Err(PendingError::WrongRing);
        }
        if self.install.is_some() {
            return Err(PendingError::SlotOccupied);
        }
        self.install = Some(install);
        Ok(())
    }

    /// Release the install this schedule served, resetting it for the next park.
    ///
    /// The closing half of [`Self::begin_install`]. The axis returns to
    /// `Installing` and the state to `Idle` because that is what a fresh
    /// schedule looks like; leaving either behind would let the next install
    /// skip its own handoff or inherit a pass it never queued. A schedule that
    /// is not `Idle` still names a pass that has this install's IRP in flight,
    /// so it refuses rather than releasing underneath it.
    pub fn end_install(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if self.install != Some(install) {
            return Err(PendingError::WrongInstall);
        }
        // `Idle` is an install bound and torn down without a pass ever running;
        // `Completing` is one that finished through `begin_worker_completion`.
        // Every other state still names a pass holding this install's IRP.
        if !matches!(
            self.state,
            WorkerScheduleState::Idle | WorkerScheduleState::Completing
        ) {
            return Err(PendingError::WrongRingState);
        }
        self.install = None;
        self.axis = InstallAxis::Installing;
        self.state = WorkerScheduleState::Idle;
        Ok(())
    }

    /// The installer has published everything a worker would read.
    pub fn handoff_done(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if self.install != Some(install) {
            return Err(PendingError::WrongInstall);
        }
        if self.axis != InstallAxis::Installing {
            return Err(PendingError::WrongRingState);
        }
        self.axis = InstallAxis::HandoffDone;
        Ok(())
    }

    /// Queue a worker pass.
    ///
    /// Refused while `Installing`: the installer is still publishing state a
    /// worker would read, so a wake deposited then is *stored* by the slot and
    /// queued after handoff, never lost and never acted on early.
    pub fn queue_worker(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if self.install != Some(install) {
            return Err(PendingError::WrongInstall);
        }
        if self.axis != InstallAxis::HandoffDone {
            return Err(PendingError::WrongRingState);
        }
        self.state = match self.state {
            WorkerScheduleState::Idle => WorkerScheduleState::Queued,
            // A wake during a pass reschedules that same worker instead of
            // queuing a second one. Two workers on one install would each hold
            // the Worker owner kind, which the ledger refuses anyway -- this is
            // where that refusal stops being needed.
            WorkerScheduleState::Running | WorkerScheduleState::RunningReschedule => {
                WorkerScheduleState::RunningReschedule
            }
            WorkerScheduleState::Queued => WorkerScheduleState::Queued,
            WorkerScheduleState::Completing => return Err(PendingError::Closing),
        };
        Ok(())
    }

    /// Begin one worker pass: Queued -> Running, moving the batch and the token.
    ///
    /// Takes both by value and returns both on refusal. A raw Worker token is
    /// not sufficient on its own — the state transition and the batch move
    /// happen together, so a pass cannot run against reasons somebody else has
    /// already taken.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn begin_worker_pass(
        &mut self,
        token: PendingOwnerToken,
        batch: WorkerWakeBatch,
    ) -> Result<
        (PendingOwnerToken, WorkerWakeBatch),
        (PendingError, PendingOwnerToken, WorkerWakeBatch),
    > {
        if let Err(error) = self.check_worker_pass(&token, &batch, WorkerScheduleState::Queued) {
            return Err((error, token, batch));
        }
        self.state = WorkerScheduleState::Running;
        Ok((token, batch))
    }

    /// Finish one pass. `RunningReschedule` atomically becomes the next `Queued`.
    ///
    /// The reschedule arm returns a [`QueueWorkRight`], not a `bool`. Publishing
    /// `Queued` is a promise that a work item will be queued, and `Queued`
    /// refuses to queue again -- so a caller that published it and then did not
    /// queue wedges the ring, with every later wake stored and nothing
    /// scheduled to take any of them. The right's `Drop` is what makes that
    /// omission loud, and it is the same obligation `record_and_schedule_pending`
    /// mints for the `Idle -> Queued` transition. The Worker token is NOT
    /// re-acquired: the pass that just finished still holds the only one, and
    /// the queued pass inherits it.
    pub fn finish_worker_pass(
        &mut self,
        token: PendingOwnerToken,
    ) -> Result<(PendingOwnerToken, Option<QueueWorkRight>), (PendingError, PendingOwnerToken)>
    {
        if self.install != Some(token.install) {
            return Err((PendingError::WrongInstall, token));
        }
        if token.kind != PendingOwnerKind::Worker {
            return Err((PendingError::WrongOwnerKind, token));
        }
        match self.state {
            WorkerScheduleState::Running => {
                self.state = WorkerScheduleState::Idle;
                Ok((token, None))
            }
            WorkerScheduleState::RunningReschedule => {
                self.state = WorkerScheduleState::Queued;
                let install = token.install;
                Ok((
                    token,
                    Some(QueueWorkRight {
                        install,
                        authority: PrivateQueueWorkRightAuthority(()),
                    }),
                ))
            }
            _ => Err((PendingError::WrongRingState, token)),
        }
    }

    /// A queued pass ran and could not begin. Return the schedule to `Idle`.
    ///
    /// Only `Queued` is accepted, because that is the one state a work item
    /// that has ALREADY RUN can leave behind: the wake that queued it acquired
    /// the Worker token and published `Queued`, and the pass then found the
    /// parked plan not yet stored and never began. Without this the ring
    /// wedges — `Queued` refuses to queue again, so every later wake answers
    /// `Stored` with nothing scheduled to take any of them, and a request whose
    /// IRP the worker already dequeued from the CSQ is stranded and no longer
    /// cancellable.
    ///
    /// The token comes back so the caller can RELEASE it. Nothing is queued any
    /// more; the work item this state stood for is the one that just ran, and
    /// leaving the Worker owner held would make the next wake refuse with
    /// `DuplicateOwner` — a second wedge one state along.
    pub fn abandon_queued_pass(
        &mut self,
        token: PendingOwnerToken,
    ) -> Result<PendingOwnerToken, (PendingError, PendingOwnerToken)> {
        if self.install != Some(token.install) {
            return Err((PendingError::WrongInstall, token));
        }
        if token.kind != PendingOwnerKind::Worker {
            return Err((PendingError::WrongOwnerKind, token));
        }
        if self.state != WorkerScheduleState::Queued {
            return Err((PendingError::WrongRingState, token));
        }
        self.state = WorkerScheduleState::Idle;
        Ok(token)
    }

    /// Move a drained pass into `Completing`, consuming the Worker token.
    pub fn begin_worker_completion(
        &mut self,
        token: PendingOwnerToken,
    ) -> Result<PendingOwnerToken, (PendingError, PendingOwnerToken)> {
        if self.install != Some(token.install) {
            return Err((PendingError::WrongInstall, token));
        }
        if token.kind != PendingOwnerKind::Worker {
            return Err((PendingError::WrongOwnerKind, token));
        }
        // Only a pass with nothing rescheduled may complete. A
        // `RunningReschedule` still owes one pass over reasons already
        // recorded, and completing it would drop them.
        if self.state != WorkerScheduleState::Running {
            return Err((PendingError::WrongRingState, token));
        }
        self.state = WorkerScheduleState::Completing;
        Ok(token)
    }

    /// A completing pass could not take the IRP after all. Return to `Running`.
    ///
    /// `Completing` is the one state `finish_worker_pass` refuses, so a pass
    /// that declares completion and then cannot proceed has no way to close
    /// itself: `queue_worker` and `record_and_schedule_pending` both answer
    /// `Closing` on `Completing`, so no later wake can ever schedule another
    /// pass either. Without this inverse the slot wedges exactly as
    /// `abandon_queued_pass` documents for the state one step earlier.
    ///
    /// `Running` rather than `Idle`, because the pass IS still running: its
    /// caller still owes the roster's finish step, and that step is what
    /// decides between `Idle` and a re-queue for wakes that landed meanwhile.
    pub fn abandon_worker_completion(
        &mut self,
        token: PendingOwnerToken,
    ) -> Result<PendingOwnerToken, (PendingError, PendingOwnerToken)> {
        if self.install != Some(token.install) {
            return Err((PendingError::WrongInstall, token));
        }
        if token.kind != PendingOwnerKind::Worker {
            return Err((PendingError::WrongOwnerKind, token));
        }
        if self.state != WorkerScheduleState::Completing {
            return Err((PendingError::WrongRingState, token));
        }
        self.state = WorkerScheduleState::Running;
        Ok(token)
    }

    fn check_worker_pass(
        &self,
        token: &PendingOwnerToken,
        batch: &WorkerWakeBatch,
        expected: WorkerScheduleState,
    ) -> Result<(), PendingError> {
        if self.install != Some(token.install) {
            return Err(PendingError::WrongInstall);
        }
        if batch.install != token.install {
            return Err(PendingError::WrongInstall);
        }
        if token.kind != PendingOwnerKind::Worker {
            return Err(PendingError::WrongOwnerKind);
        }
        if self.state != expected {
            return Err(PendingError::WrongRingState);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// R4 Task 17: the atomic handoff commit
// ---------------------------------------------------------------------------
//
// Everything the installer publishes has to become visible to a worker in one
// step, and the Installer owner has to stop existing in that same step. Split
// into separately callable pieces -- publish the axis, then release the owner,
// then acquire a worker, then publish Queued -- every ordering between them is
// a window where a worker either runs against half-published state or cannot
// run at all. So there is exactly one function, it takes every participant, and
// there is no public axis publish, owner release, token store, or state publish
// to call instead.

/// The install a selected disposition owns, minted only by
/// [`select_pending_install`].
///
/// Affine and non-`Clone`: one selection installs one parked ENTER. It carries
/// the observed IRP so the receipt it eventually becomes names the same one.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct SelectedPendingInstall {
    install: PendingInstallId,
    irp: IrpObservation,
    authority: PrivateSelectedPendingInstallAuthority,
}

/// Proof that one install finished its handoff and a worker may now read it.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct HandoffDoneReceipt {
    install: PendingInstallId,
    irp: IrpObservation,
    authority: PrivateHandoffDoneReceiptAuthority,
}

/// A handoff that also owes one queue call before its receipt is readable.
///
/// The receipt is *inside* this and there is no accessor: the only way out is
/// [`PendingHandoffQueue::commit_after_queue`], which the caller may invoke
/// only after the void queue side effect has happened. A caller that returned
/// `STATUS_PENDING` before queueing would have nothing to return it with.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingHandoffQueue {
    receipt: HandoffDoneReceipt,
}

/// What one atomic handoff produced.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum PendingHandoffCommit {
    /// Nothing was stored, so nothing is queued and the receipt is immediate.
    Ready(HandoffDoneReceipt),
    /// A wake was stored during `Installing`; one worker pass is now Queued.
    Queue(PendingHandoffQueue),
}

#[allow(dead_code)]
impl SelectedPendingInstall {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub(crate) const fn irp(&self) -> IrpObservation {
        self.irp
    }
}

#[allow(dead_code)]
impl HandoffDoneReceipt {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub const fn irp(&self) -> IrpObservation {
        self.irp
    }
}

impl PendingHandoffQueue {
    /// Reveal the receipt, after the queue call this value represents.
    ///
    /// # Safety
    /// The caller has already performed the one void queue side effect for
    /// this install and is outside the context lock.
    pub unsafe fn commit_after_queue(self) -> HandoffDoneReceipt {
        let Self { receipt } = self;
        receipt
    }
}

/// Finish one install's handoff, atomically, or refuse having changed nothing.
///
/// In one transition it verifies the exact install, releases the Installer
/// owner, moves `Installing -> HandoffDone`, and — only if a wake was stored
/// while the installer was still publishing — acquires exactly one Worker
/// token and publishes `Queued`. The stored reasons stay in the slot: the
/// worker takes them when its pass begins, so a coalesced Fence that arrived
/// during installation is neither lost nor acted on early.
///
/// Every refusal happens before any mutation, and returns the Installer token
/// so the caller still owns what it came with.
///
/// The pieces this composes -- `handoff_done`, `queue_worker`, `acquire_owner`,
/// `release_owner` -- are individually `pub`, so this is not a seal against
/// calling them; the staging gate and the native module's structure are what
/// keep production on this path. What it does guarantee is that *this*
/// transition performs all of them or none, which is the property a caller
/// assembling them by hand would not have.
// The Installer token comes back on every refusal, which is what proves the
// refused path consumed nothing. Boxing it would need an allocator this path
// does not have.
#[allow(clippy::result_large_err)]
pub fn commit_pending_handoff(
    selected: SelectedPendingInstall,
    installer: PendingOwnerToken,
    schedule: &mut PendingWorkerSchedule,
    wake: &mut PendingWakeSlot,
    owners: &mut PendingOwnerLedger,
    worker_owner: &mut Option<PendingOwnerToken>,
) -> Result<PendingHandoffCommit, (PendingError, SelectedPendingInstall, PendingOwnerToken)> {
    let install = selected.install;
    // Every precondition first. Nothing below this block may fail, which is
    // what makes the transition atomic rather than merely short.
    if installer.install != install || installer.kind != PendingOwnerKind::Installer {
        return Err((PendingError::WrongInstall, selected, installer));
    }
    if schedule.install != Some(install) || schedule.axis != InstallAxis::Installing {
        return Err((PendingError::WrongRingState, selected, installer));
    }
    if schedule.state != WorkerScheduleState::Idle {
        return Err((PendingError::WrongRingState, selected, installer));
    }
    if wake.brand != install.brand() || owners.brand != install.brand() {
        return Err((PendingError::WrongRing, selected, installer));
    }
    if owners.install != Some(install) {
        return Err((PendingError::WrongInstall, selected, installer));
    }
    // The ledger must actually hold an Installer kind. Holding a token that
    // names this install is not the same claim: a token whose kind was already
    // released would pass every check above and then make `release_owner`
    // below refuse, reaching an `unreachable!` that nothing had established.
    if !owners.holds(PendingOwnerKind::Installer) {
        return Err((PendingError::WrongOwnerKind, selected, installer));
    }
    if worker_owner.is_some() || owners.holds(PendingOwnerKind::Worker) {
        return Err((PendingError::DuplicateOwner, selected, installer));
    }
    // Any stored wake for this install, including Cancel, owes one worker
    // pass: the cancel callback cannot complete at DISPATCH, so HandoffDone
    // is what transfers that wake to a Worker and queues after unlock.
    //
    // `stored.install == install` is load-bearing: the slot is per-ring, not
    // per-install, so a wake left by a previous generation would otherwise
    // decide whether *this* one queues a pass. Both `record_wake` and
    // `take_for_worker` check the same thing.
    let needs_worker = wake.wake.as_ref().is_some_and(|stored| {
        stored.install == install
            && PendingReason::WORKER_PRIORITY
                .iter()
                .any(|reason| stored.reasons & reason.bit() != 0)
    });
    if needs_worker {
        // Checked here rather than after the release so a ledger that cannot
        // mint the Worker refuses while the Installer is still whole.
        if owners.closing {
            return Err((PendingError::Closing, selected, installer));
        }
        if owners.owners.checked_add(1).is_none() {
            return Err((PendingError::OwnerOverflow, selected, installer));
        }
    }

    let SelectedPendingInstall {
        install: _,
        irp,
        authority: PrivateSelectedPendingInstallAuthority(()),
    } = selected;
    let Ok(()) = owners.release_owner(installer) else {
        unreachable!("the installer owner was checked against this ledger above")
    };
    schedule.axis = InstallAxis::HandoffDone;
    let receipt = HandoffDoneReceipt {
        install,
        irp,
        authority: PrivateHandoffDoneReceiptAuthority(()),
    };
    if !needs_worker {
        return Ok(PendingHandoffCommit::Ready(receipt));
    }
    let Ok(token) = owners.acquire_owner(install, PendingOwnerKind::Worker) else {
        unreachable!("worker capacity and admission were checked above")
    };
    *worker_owner = Some(token);
    schedule.state = WorkerScheduleState::Queued;
    Ok(PendingHandoffCommit::Queue(PendingHandoffQueue { receipt }))
}

// ---------------------------------------------------------------------------
// R4 Task 18: the producer wrapper
// ---------------------------------------------------------------------------
//
// Every staged producer, cancel and DPC source reaches the schedule through
// this one function, under the context lock. Splitting it -- record the wake
// here, decide there, publish Queued somewhere else -- is how a state and its
// owner slot drift apart, and `WorkerScheduleState` is the *sole* publication
// of whether a pass is queued or running. There is no second boolean.

/// The one right a queued wake produces, consumed after unlock.
///
/// Non-`Clone` and with no accessor: it exists so that "publish Queued" and
/// "call the queue DDI" cannot happen in the wrong order or twice. The queue
/// call happens outside the lock, which is why the right leaves the critical
/// section at all.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct QueueWorkRight {
    install: PendingInstallId,
    authority: PrivateQueueWorkRightAuthority,
}

/// What one recorded wake did to the schedule.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum PendingWakeOutcome {
    /// Coalesced into the slot and nothing else. Either the installer is still
    /// publishing, a pass is already queued, or the only reason is Cancel --
    /// which belongs to the cancel callback, never to a worker.
    Stored,
    /// This wake queued the one pass. Exactly one Worker token was acquired.
    Queued(QueueWorkRight),
    /// A pass is running and was told to run again. Deliberately no second
    /// token: the running pass still holds the only one, and no queue right
    /// either -- the schedule is still `RunningReschedule`, so nothing has been
    /// promised yet. `finish_worker_pass` is what publishes the `Queued` and
    /// mints the obligation that goes with it.
    Rescheduled,
}

#[allow(dead_code)]
impl QueueWorkRight {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    /// Discharge the right, after the one void queue call it stands for.
    ///
    /// `forget` rather than a destructure, because this type has a `Drop` that
    /// exists to catch the opposite case. Forgetting is the *correct* discharge
    /// here: the right owns no resource, only an obligation, and that
    /// obligation has just been met.
    ///
    /// # Safety
    /// The caller has left the context lock and performed exactly one queue
    /// DDI call for this install.
    pub unsafe fn commit_after_work_queued(self) {
        core::mem::forget(self);
    }
}

// Dropping this right is never recoverable, so it is never silent.
//
// By the time one exists, `WorkerScheduleState::Queued` is already published
// and a Worker token is already stored. Losing the right on an early return
// means the queue call never happens: the schedule says a pass is queued, the
// ledger says its owner is held, and no pass will ever run to release either.
// The parked IRP is then hung until the driver unloads, and nothing in the
// state is wrong enough for any other check to notice.
//
// `#[must_use]` only warns, and warns nowhere at all if the value is bound.
// This is the driver's standing policy applied to a liveness invariant: a
// panic here is a coded bugcheck, which is what `11-rust-implementation.md`
// section 5 asks for when a proven bug is found at runtime -- diagnosable,
// rather than an IRP that never completes and a machine that looks healthy.
impl Drop for QueueWorkRight {
    fn drop(&mut self) {
        panic!(
            "QueueWorkRight dropped without queueing: a worker pass is              published Queued and its owner is held, so the parked ENTER can              never complete"
        );
    }
}

/// Coalesce one wake and schedule at most one worker pass, atomically.
///
/// Refusals happen before any mutation, so a refused wake leaves the slot and
/// the schedule exactly as they were.
/// Begin one native worker pass, returning the reason it is completing.
///
/// The native worker cannot drive `begin_worker_pass` itself: that needs a
/// `WorkerWakeBatch`, which only `take_for_worker` mints and which stays
/// crate-private so a caller cannot assemble one beside the wake it describes.
/// This is the seam, in the same shape as [`record_and_schedule_pending`] --
/// core owns the transition, the native side passes its own state in.
///
/// Every check precedes the take. `take_for_worker` empties the wake slot, so a
/// refusal afterwards would lose the very reasons the pass was scheduled for
/// and strand the parked IRP.
pub fn begin_native_worker_pass(
    install: PendingInstallId,
    schedule: &mut PendingWorkerSchedule,
    wake: &mut PendingWakeSlot,
    worker_owner: &mut Option<PendingOwnerToken>,
) -> Result<PendingReason, PendingError> {
    let Some(token) = worker_owner.as_ref() else {
        return Err(PendingError::WrongOwnerKind);
    };
    if schedule.install != Some(install) || token.install != install {
        return Err(PendingError::WrongInstall);
    }
    if token.kind != PendingOwnerKind::Worker {
        return Err(PendingError::WrongOwnerKind);
    }
    if schedule.state != WorkerScheduleState::Queued {
        return Err(PendingError::WrongRingState);
    }
    if wake.brand != install.brand() {
        return Err(PendingError::WrongRing);
    }
    let decision = wake.take_for_worker(install)?;
    let reason = decision.reason();
    let batch = decision.into_batch();
    let Some(token) = worker_owner.take() else {
        unreachable!("the token was observed present above")
    };
    match schedule.begin_worker_pass(token, batch) {
        Ok((token, _batch)) => {
            *worker_owner = Some(token);
            Ok(reason)
        }
        // Unreachable: every condition `begin_worker_pass` checks was checked
        // above. The token still comes back, because losing it would leave the
        // install with no owner able to complete it.
        Err((error, token, _batch)) => {
            *worker_owner = Some(token);
            Err(error)
        }
    }
}

/// Finish one native worker pass that completed nothing.
///
/// Returns the obligation to queue the next pass, if one is due: a
/// `RunningReschedule` becomes the next `Queued` atomically, which is what lets
/// a pass that found its slot not yet ready be retried instead of stranding the
/// request. `Some` is a `QueueWorkRight` and not a `true`, so the caller cannot
/// publish `Queued` and then quietly fail to queue.
pub fn finish_native_worker_pass(
    schedule: &mut PendingWorkerSchedule,
    owners: &mut PendingOwnerLedger,
    worker_owner: &mut Option<PendingOwnerToken>,
) -> Result<Option<QueueWorkRight>, PendingError> {
    let Some(token) = worker_owner.take() else {
        return Err(PendingError::WrongOwnerKind);
    };
    match schedule.finish_worker_pass(token) {
        Ok((token, Some(right))) => {
            // `RunningReschedule` became the next `Queued`. That pass has not
            // run yet and inherits this very token, so the ledger's count is
            // still telling the truth.
            *worker_owner = Some(token);
            Ok(Some(right))
        }
        Ok((token, None)) => {
            // `Idle`: no successor pass exists to inherit the token. Holding
            // it here is not a leak of memory but of admission -- the next
            // wake reads `worker_owner.is_some() || owners.holds(Worker)` and
            // refuses `DuplicateOwner`, so nothing can ever queue a pass for
            // this install again and the parked request is never served. The
            // release belongs at the transition that stranded it, not in a
            // caller that has to remember.
            match owners.release_owner(token) {
                Ok(()) => Ok(None),
                Err((error, token)) => {
                    *worker_owner = Some(token);
                    Err(error)
                }
            }
        }
        Err((error, token)) => {
            *worker_owner = Some(token);
            Err(error)
        }
    }
}

pub fn record_and_schedule_pending(
    install: PendingInstallId,
    reason: PendingReason,
    schedule: &mut PendingWorkerSchedule,
    wake: &mut PendingWakeSlot,
    owners: &mut PendingOwnerLedger,
    worker_owner: &mut Option<PendingOwnerToken>,
) -> Result<PendingWakeOutcome, PendingError> {
    if schedule.install != Some(install) || owners.install != Some(install) {
        return Err(PendingError::WrongInstall);
    }
    if wake.brand != install.brand() {
        return Err(PendingError::WrongRing);
    }
    if schedule.state == WorkerScheduleState::Completing {
        return Err(PendingError::Closing);
    }
    // Whether this wake will need a Worker token, decided before anything is
    // recorded so a refusal cannot leave a stored wake nobody will act on.
    let will_queue =
        schedule.axis == InstallAxis::HandoffDone && schedule.state == WorkerScheduleState::Idle;
    if will_queue {
        if worker_owner.is_some() || owners.holds(PendingOwnerKind::Worker) {
            return Err(PendingError::DuplicateOwner);
        }
        if owners.closing {
            return Err(PendingError::Closing);
        }
        if owners.owners.checked_add(1).is_none() {
            return Err(PendingError::OwnerOverflow);
        }
    }

    // The reason is recorded whatever happens next: a wake that arrived is a
    // fact, and the slot is the only record of it.
    wake.record_wake(install, reason)?;

    // A wake during `Installing` is stored and cannot schedule -- the installer
    // is still publishing state a worker would read. `commit_pending_handoff`
    // is what turns that stored wake into the first Queued.
    if schedule.axis != InstallAxis::HandoffDone {
        return Ok(PendingWakeOutcome::Stored);
    }
    match schedule.state {
        WorkerScheduleState::Idle => {
            if !will_queue {
                return Ok(PendingWakeOutcome::Stored);
            }
            let Ok(token) = owners.acquire_owner(install, PendingOwnerKind::Worker) else {
                unreachable!("worker capacity and admission were checked above")
            };
            *worker_owner = Some(token);
            schedule.state = WorkerScheduleState::Queued;
            Ok(PendingWakeOutcome::Queued(QueueWorkRight {
                install,
                authority: PrivateQueueWorkRightAuthority(()),
            }))
        }
        // Already queued: the pending pass has not begun, so it will take these
        // reasons with the rest. Queueing a second is what the one-token rule
        // exists to prevent.
        WorkerScheduleState::Queued => Ok(PendingWakeOutcome::Stored),
        WorkerScheduleState::Running | WorkerScheduleState::RunningReschedule => {
            schedule.state = WorkerScheduleState::RunningReschedule;
            Ok(PendingWakeOutcome::Rescheduled)
        }
        WorkerScheduleState::Completing => Err(PendingError::Closing),
    }
}

/// Queue the pass a stored wake is still owed, now that the plan exists.
///
/// `commit_pending_handoff` transfers a wake stored during `Installing` into
/// the first `Queued`, and `record_and_schedule_pending` queues every wake that
/// arrives after it. Between those two there is one instant neither covers: the
/// handoff is committed, the schedule reads `HandoffDone`/`Idle`, and the plan
/// has not been stored yet. A wake landing there IS queued -- and the pass then
/// runs before the plan exists, finds nothing to begin, and abandons back to
/// `Idle` leaving its reason in the slot. Nothing re-reads a stored wake, so
/// the request is owed a pass that no later event will queue: a finite WAIT
/// stops timing out, a cancelled IRP is never completed.
///
/// So the store asks this question at the first instant the answer can be
/// acted on. The predicate is `commit_pending_handoff`'s `needs_worker`, not a
/// paraphrase of it -- the two decide the same thing one phase apart.
///
/// `Ok(None)` is the ordinary answer: no wake is owed, or a pass is already
/// queued or running and will take these reasons with the rest.
pub fn schedule_stored_wake(
    install: PendingInstallId,
    schedule: &mut PendingWorkerSchedule,
    wake: &PendingWakeSlot,
    owners: &mut PendingOwnerLedger,
    worker_owner: &mut Option<PendingOwnerToken>,
) -> Result<Option<QueueWorkRight>, PendingError> {
    if schedule.install != Some(install) || owners.install != Some(install) {
        return Err(PendingError::WrongInstall);
    }
    if wake.brand != install.brand() {
        return Err(PendingError::WrongRing);
    }
    // Only the window this exists for. `Queued` already owes a call, `Running`
    // and `RunningReschedule` belong to a pass that will re-read the slot, and
    // `Completing` is a terminal being delivered.
    if schedule.axis != InstallAxis::HandoffDone || schedule.state != WorkerScheduleState::Idle {
        return Ok(None);
    }
    // `stored.install == install` is load-bearing for the same reason it is in
    // `commit_pending_handoff`: the slot is per-ring, so a previous
    // generation's wake must not queue a pass for this one.
    let needs_worker = wake.wake.as_ref().is_some_and(|stored| {
        stored.install == install
            && PendingReason::WORKER_PRIORITY
                .iter()
                .any(|reason| stored.reasons & reason.bit() != 0)
    });
    if !needs_worker {
        return Ok(None);
    }
    if worker_owner.is_some() || owners.holds(PendingOwnerKind::Worker) {
        return Err(PendingError::DuplicateOwner);
    }
    if owners.closing {
        return Err(PendingError::Closing);
    }
    if owners.owners.checked_add(1).is_none() {
        return Err(PendingError::OwnerOverflow);
    }
    let Ok(token) = owners.acquire_owner(install, PendingOwnerKind::Worker) else {
        unreachable!("worker capacity and admission were checked above")
    };
    *worker_owner = Some(token);
    schedule.state = WorkerScheduleState::Queued;
    Ok(Some(QueueWorkRight {
        install,
        authority: PrivateQueueWorkRightAuthority(()),
    }))
}

// ---------------------------------------------------------------------------
// R4 Task 18: timer quiescence
// ---------------------------------------------------------------------------
//
// `KeCancelTimer` answers one question -- was the timer still queued -- and the
// answer decides who is responsible for the DPC. TRUE means it was dequeued
// before running, so the canceller owns the DPC token and nothing has to be
// waited for. FALSE means it either already ran or is running *now*, so the DPC
// owns itself and the canceller must wait for its exit event before the slot
// can be reused. Getting that backwards frees a slot a running DPC still holds.

/// Where one install's timer is in its life.
///
/// `Armed` and `Running` carry the epoch they belong to, so a DPC that arrives
/// for a previous install can be recognised as stale rather than acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerState {
    Quiesced,
    Armed { epoch: u64 },
    Running { epoch: u64 },
}

/// What a cancel attempt obliges the canceller to do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingTimerCancel {
    /// Nothing was armed. There is no DPC owner and nothing to wait for.
    NotArmed,
    /// `KeCancelTimer` returned TRUE: dequeued before running. The canceller
    /// takes the DPC owner back and does not wait.
    DequeuedBeforeRun,
    /// `KeCancelTimer` returned FALSE: the DPC already ran or is running. The
    /// canceller waits the exit event and does NOT take the owner -- the DPC
    /// releases it on its own way out.
    RequiresDpcExitWait,
    /// The caller named a different epoch than the one armed. It owns neither
    /// the timer nor its DPC, so it takes no owner and waits for nothing.
    NotThisInstall,
}

impl TimerState {
    /// The epoch this state belongs to, if any.
    pub const fn epoch(self) -> Option<u64> {
        match self {
            Self::Quiesced => None,
            Self::Armed { epoch } | Self::Running { epoch } => Some(epoch),
        }
    }

    /// Arm for one install. Only a quiesced timer may be armed: arming over a
    /// live one would leave two epochs believing they own the same DPC.
    pub fn arm(&mut self, epoch: u64) -> Result<(), PendingError> {
        if !matches!(self, Self::Quiesced) {
            return Err(PendingError::WrongRingState);
        }
        *self = Self::Armed { epoch };
        Ok(())
    }

    /// The DPC for `epoch` entered. A mismatched epoch is a stale DPC: it is
    /// refused here and must still signal its exit, which is why the refusal
    /// carries no state change rather than quiescing somebody else's timer.
    pub fn dpc_entered(&mut self, epoch: u64) -> Result<(), PendingError> {
        match *self {
            Self::Armed { epoch: armed } if armed == epoch => {
                *self = Self::Running { epoch };
                Ok(())
            }
            Self::Armed { .. } | Self::Running { .. } => Err(PendingError::WrongInstall),
            Self::Quiesced => Err(PendingError::WrongRingState),
        }
    }

    /// The DPC for `epoch` is leaving. Quiesced is published *before* the exit
    /// event is signalled, so a waiter that wakes can never observe a timer
    /// still claiming to run.
    pub fn dpc_exiting(&mut self, epoch: u64) -> Result<(), PendingError> {
        match *self {
            Self::Running { epoch: running } if running == epoch => {
                *self = Self::Quiesced;
                Ok(())
            }
            _ => Err(PendingError::WrongRingState),
        }
    }

    /// Interpret one `KeCancelTimer` return for this state.
    ///
    /// `dequeued` is the DDI's BOOLEAN. The state is only cleared on the arm
    /// that owns the DPC; the wait arm leaves `Running` in place, because the
    /// DPC has not exited yet and `dpc_exiting` is what publishes Quiesced.
    pub fn cancel(&mut self, epoch: u64, dequeued: bool) -> PendingTimerCancel {
        match *self {
            Self::Quiesced => PendingTimerCancel::NotArmed,
            // A caller naming a different epoch does not own this timer, and
            // must be told so rather than handed an obligation. Returning
            // `RequiresDpcExitWait` here would send a stale generation to wait
            // on a DPC-exit event that only the *live* generation's DPC will
            // ever signal -- an unbounded PASSIVE_LEVEL block, not a refusal.
            // Every other transition on this type refuses a mismatched epoch;
            // this one used to be the exception that answered anyway.
            Self::Armed { epoch: armed } | Self::Running { epoch: armed } if armed != epoch => {
                PendingTimerCancel::NotThisInstall
            }
            Self::Armed { .. } if dequeued => {
                *self = Self::Quiesced;
                PendingTimerCancel::DequeuedBeforeRun
            }
            // Armed-but-not-dequeued means the DPC is already on its way in;
            // it is treated exactly like Running.
            Self::Armed { .. } | Self::Running { .. } => PendingTimerCancel::RequiresDpcExitWait,
        }
    }
}

/// Convert a finite millisecond timeout into a relative 100ns due time.
///
/// Relative due times are negative. Overflow returns `None` so the caller
/// terminalizes *before* arming rather than arming something wrong: a wrapped
/// due time is a timer that fires immediately or never.
pub const fn finite_due_time_100ns(milliseconds: u32) -> Option<i64> {
    let Some(hundred_ns) = (milliseconds as i64).checked_mul(10_000) else {
        return None;
    };
    hundred_ns.checked_neg()
}

// ---------------------------------------------------------------------------
// R4 Task 18: what each pending callback does, and in what order
// ---------------------------------------------------------------------------
//
// The timer DPC and the PASSIVE worker are built from ONE action vocabulary.
// That is the point rather than an economy: "the DPC never dequeues, waits,
// writes output, or completes" is then the *absence* from its roster of
// variants the worker's roster actually contains, so the claim can be false.
// A private four-variant list nothing else used would agree with itself.

/// One action a pending-install callback performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCallbackAction {
    /// Under the first hold: `Armed{epoch}` -> `Running{epoch}`, taking the
    /// DPC owner out of its slot.
    EnterRunning,
    /// Under the same hold: record Timeout through the shared scheduling
    /// helper, which is the only thing that may publish Queued.
    RecordTimeoutWake,
    /// Outside the hold: the one void queue call a [`QueueWorkRight`] stands
    /// for. A wake that coalesced produced no right and so owes no call.
    QueueWorker,
    /// Under the second hold: release the exact DPC owner in the ledger.
    ReleaseDpcOwner,
    /// Under the same hold: publish `Quiesced`.
    PublishQuiesced,
    /// `Queued` -> `Running`, moving the one stored Worker token and its batch.
    BeginWorkerPass,
    /// Poll / clear / recheck. Reads readiness; owns no IRP.
    PollAndRecheck,
    /// `IoCsqRemoveIrp`. The worker alone dequeues, and only a non-null return
    /// mints the reason-bearing receipt.
    RemoveIrpFromCsq,
    /// The out-of-line result write.
    WriteResultStorage,
    /// `IoCompleteRequest`.
    CompleteIrp,
    /// Reschedule, or release the exact Worker owner and publish `Idle`.
    FinishWorkerPass,
}

impl PendingCallbackAction {
    /// Whether this action dequeues the IRP, writes the output result, or
    /// completes the request.
    ///
    /// Those three are exactly what a DPC running at DISPATCH_LEVEL may not do,
    /// and all three for one reason: they belong to whoever owns the request. A
    /// fourth stood here -- `WaitDpcExitEvent`, on the ground that a DPC
    /// waiting for its own exit event is a deadlock -- and it left with the
    /// roster entry that was its only member. The blocking action the worker
    /// still performs is `PendingCompletionEffect::WaitDpcExitIfRequired`,
    /// whose own contract is PASSIVE-only, and no DPC reaches a completion plan.
    pub const fn forbidden_at_dispatch_level(self) -> bool {
        matches!(
            self,
            Self::RemoveIrpFromCsq | Self::WriteResultStorage | Self::CompleteIrp
        )
    }
}

/// The timer DPC's effects when the epoch it was armed for is still the live
/// one, in order.
///
/// `SignalDpcExit` is deliberately absent: it is not an effect the walk can
/// reach past, it is the [`PendingDpcExitTicket`] the completed walk mints.
pub const PENDING_DPC_OWN_EPOCH_ORDER: [PendingCallbackAction; 5] = [
    PendingCallbackAction::EnterRunning,
    PendingCallbackAction::RecordTimeoutWake,
    PendingCallbackAction::QueueWorker,
    PendingCallbackAction::ReleaseDpcOwner,
    PendingCallbackAction::PublishQuiesced,
];

/// The timer DPC's effects when it arrived for an epoch that is no longer live.
///
/// Empty, and that is the content: a stale DPC owns nothing on this slot, so
/// it releases no owner and quiesces nobody else's timer. It still exits, and
/// the exit is the ticket every path mints.
pub const PENDING_DPC_STALE_EPOCH_ORDER: [PendingCallbackAction; 0] = [];

/// The PASSIVE worker pass, in order.
///
/// It contains every action the DPC may not perform, which is what makes
/// `forbidden_at_dispatch_level` a predicate rather than a constant.
///
/// There is NO DPC-exit rendezvous in this order, and that is deliberate.
///
/// One stood second here, on the argument that a timer DPC still in flight
/// holds a slot owner the final publication is about to require gone. Two
/// rounds of repair established that it cannot do that job from this position.
/// A rendezvous is sound only after something has asked the timer to stop:
/// cancelled-and-queued is a bounded wait, an unfired deadline is the client's
/// whole `timeout_ms` on a `DelayedWorkQueue` thread, and `Armed` alone cannot
/// tell them apart. Narrowing it to `Running` instead made it unreachable --
/// the DPC holds the slot lock for its entire body, so no observer can ever see
/// that state -- which is unconditional success, exactly what section 16 item 8
/// forbids.
///
/// The correct pair already exists in [`PENDING_COMPLETION_ORDER`]:
/// `CancelTimer` immediately followed by `WaitDpcExitIfRequired`. This was a
/// second copy of it with no cancel in front. The concurrent access it was said
/// to prevent is prevented by the slot lock that every worker effect and the
/// whole DPC body take; what that lock does not cover is the DPC's post-unlock
/// `KeSetEvent`, and that is an arena-lifetime question owned by teardown, not
/// by a worker pass.
pub const PENDING_WORKER_PASS_ORDER: [PendingCallbackAction; 6] = [
    PendingCallbackAction::BeginWorkerPass,
    PendingCallbackAction::PollAndRecheck,
    PendingCallbackAction::RemoveIrpFromCsq,
    PendingCallbackAction::WriteResultStorage,
    PendingCallbackAction::CompleteIrp,
    PendingCallbackAction::FinishWorkerPass,
];

/// Which of the two DPC paths a pass is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingDpcPath {
    /// `dpc_entered` accepted: this DPC's epoch is the live one.
    OwnEpoch,
    /// `dpc_entered` refused: a previous install's DPC arrived late.
    StaleEpoch,
}

impl PendingDpcPath {
    /// The exact effects this path performs, in order.
    pub const fn effects(self) -> &'static [PendingCallbackAction] {
        match self {
            Self::OwnEpoch => &PENDING_DPC_OWN_EPOCH_ORDER,
            Self::StaleEpoch => &PENDING_DPC_STALE_EPOCH_ORDER,
        }
    }
}

pending_authority_seals!(PrivateDpcExitTicketAuthority);

/// The one authority to call `KeSetEvent(dpc_exited)`.
///
/// Affine, non-`Clone`, with no public constructor: a completed
/// [`PendingDpcPass`] is the only minter. Signalling the exit event before the
/// owner is released and `Quiesced` is published is therefore not a mistake a
/// callback can make — it has nothing to signal with until the walk is done.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct PendingDpcExitTicket {
    epoch: u64,
    path: PendingDpcPath,
    authority: PrivateDpcExitTicketAuthority,
}

#[allow(dead_code)]
impl PendingDpcExitTicket {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn path(&self) -> PendingDpcPath {
        self.path
    }

    /// Discharge the ticket, after the one `KeSetEvent` it stands for.
    ///
    /// # Safety
    /// The caller has left the context lock and signalled `dpc_exited` exactly
    /// once for this pass.
    pub unsafe fn commit_after_exit_signalled(self) {
        let Self {
            epoch: _,
            path: _,
            authority: PrivateDpcExitTicketAuthority(()),
        } = self;
    }
}

/// One step of a DPC pass.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum PendingDpcStep {
    /// Perform this action, then continue with the returned pass.
    Perform(PendingCallbackAction, PendingDpcPass),
    /// Every effect of this path is done. Signal the exit event, last.
    SignalExit(PendingDpcExitTicket),
}

/// A timer DPC pass over one slot, from entry to exit.
///
/// Consuming `run_next_dpc_effect` rather than a `&mut` walk, so a pass cannot
/// be restarted, skipped, or run twice — and cannot be abandoned partway with
/// a ticket already in hand, because the ticket does not exist until the walk
/// ends.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingDpcPass {
    epoch: u64,
    path: PendingDpcPath,
    index: usize,
}

impl PendingDpcPass {
    /// Enter the DPC for `epoch` and decide which path this pass is on.
    ///
    /// The timer transition happens here rather than as the first effect,
    /// because *which roster applies* is exactly what it answers. A stale DPC
    /// changes nothing: `dpc_entered` refuses without touching the live
    /// install's state, and this pass then performs no effect at all.
    pub fn begin_dpc_pass(timer: &mut TimerState, epoch: u64) -> Self {
        let path = match timer.dpc_entered(epoch) {
            Ok(()) => PendingDpcPath::OwnEpoch,
            Err(_) => PendingDpcPath::StaleEpoch,
        };
        Self {
            epoch,
            path,
            index: 0,
        }
    }

    pub const fn path(&self) -> PendingDpcPath {
        self.path
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Take the next effect, or end the pass with its exit ticket.
    ///
    /// Running off the end of the roster IS the exit, so the bounds check and
    /// the terminal step are the same decision rather than two that could
    /// disagree. `saturating_add` only ever runs on an index the roster just
    /// answered, and no roster is longer than five.
    pub fn run_next_dpc_effect(self) -> PendingDpcStep {
        let Self { epoch, path, index } = self;
        match path.effects().get(index) {
            Some(&action) => PendingDpcStep::Perform(
                action,
                Self {
                    epoch,
                    path,
                    index: index.saturating_add(1),
                },
            ),
            None => PendingDpcStep::SignalExit(PendingDpcExitTicket {
                epoch,
                path,
                authority: PrivateDpcExitTicketAuthority(()),
            }),
        }
    }
}

/// Mint the one selection for an install that the outer thunk chose to park.
///
/// # Safety
/// The outer thunk selected Pending for this exact install and IRP, and the
/// remaining suffix has no refusal edge.
pub const unsafe fn select_pending_install(
    install: PendingInstallId,
    irp: IrpObservation,
) -> SelectedPendingInstall {
    SelectedPendingInstall {
        install,
        irp,
        authority: PrivateSelectedPendingInstallAuthority(()),
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.2: owned parking, take-once dequeue receipts, and handoff
// ---------------------------------------------------------------------------
//
// The predecessor `PendingEnter::contend(&self, EnterContender)` takes a shared
// borrow and any contender value, so *anything* that can name the plan can win
// the terminal CAS — before the IRP has left the queue, and as many times as it
// likes because nothing is consumed. The rule this block installs is:
//
//   authentic receipt -> contend(reason) -> retain PendingTerminalRight
//
// A contender with no receipt cannot call `contend` at all: the receipt is a
// by-value parameter whose only constructor is a successful dequeue. A loser
// holds no receipt, no right, and no IRP.

// `IrpObservation` needs no seal: its single field is private and its only
// constructor already refuses null, so there is nothing a seal would add
// that the `NonZeroUsize` does not already say.
pending_authority_seals!(PrivateDequeueReceipt);

/// A non-null IRP pointer, observed once.
///
/// `NonZeroUsize` rather than `usize` so "the CSQ returned nothing" is
/// unrepresentable rather than merely checked: a null return cannot become an
/// observation at all, so it cannot reach the receipt that authorises a CAS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrpObservation(NonZeroUsize);

/// What a CSQ cancel-completion callback must do with the slot's IRP pointer.
///
/// The framework's cancel path calls `CsqRemoveIrp` and only then
/// `CsqCompleteCanceledIrp`. The remove callback is the one that stops the slot
/// naming an IRP the queue no longer holds, so by the time the completion
/// callback runs the slot is already empty. A completion callback that
/// *requires* the slot to still name the IRP requires a state the callback
/// before it has just destroyed -- which is not a check but a bugcheck on every
/// cancel, and that is exactly what stood here from `079ec55` until this
/// classification replaced it.
///
/// The worker's own `IoCsqRemoveIrp` path already restores the non-null return
/// into the slot for the same reason. This makes the cancel path do what that
/// path always did, instead of asserting it had happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsqCancelCompletion {
    /// The remove callback ran first and emptied the slot. Adopt the IRP the
    /// framework handed over: the slot is the only place a cancelled IRP is
    /// named, and nothing else can find it again.
    AdoptRemoved,
    /// The slot already names this exact IRP, so the pointer needs no repair.
    AlreadyNamed,
    /// The slot names a different IRP. Two installs believe they own one slot,
    /// which no completion can make safe.
    ForeignIrp,
    /// The framework handed over no IRP. There is nothing to adopt and nothing
    /// to refuse; the caller publishes the axis and stops.
    NoIrp,
}

/// Decide what a cancel completion does to the slot pointer.
///
/// `slot` is what the slot names when the callback runs -- normally `None`,
/// because the remove callback preceded it. `handed` is what the framework
/// passed. Total in both arguments so "the remove callback did not run" and
/// "it ran" are the same function, answered differently.
pub fn classify_csq_cancel_completion(
    slot: Option<IrpObservation>,
    handed: Option<IrpObservation>,
) -> CsqCancelCompletion {
    match (slot, handed) {
        (_, None) => CsqCancelCompletion::NoIrp,
        (None, Some(_)) => CsqCancelCompletion::AdoptRemoved,
        (Some(named), Some(handed)) if named == handed => CsqCancelCompletion::AlreadyNamed,
        (Some(_), Some(_)) => CsqCancelCompletion::ForeignIrp,
    }
}

/// Which authority, if any, has released the parked IRP to this driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum WorkerDequeueAuthority {
    /// The slot has been handed the IRP. `IrpAxis::Dequeued` has exactly two
    /// writers and both are that handoff: a pass's own non-null
    /// `IoCsqRemoveIrp` return, and the framework's cancel completion
    /// callback. This pass may complete it.
    ReleasedToDriver(IrpObservation),
    /// The slot still reads `Queued`: no handoff has been published into it.
    /// A pass holding the authorities may attempt the dequeue itself, and it
    /// is `IoCsqRemoveIrp`'s NULL return -- not this answer -- that says the
    /// cancel routine owns the request. A pass that has already had that NULL
    /// completes nothing; the cancel path deposits its own wake.
    NoHandoffPublished,
    /// Nothing is parked here, or a completion is already under way.
    NoParkedIrp,
}

/// Decide, from ONE locked observation, whether a worker pass may complete.
///
/// Total in both arguments, because the pointer alone cannot tell "the driver
/// was handed this IRP" from "the CSQ still owns it" -- which is the whole of
/// the cancel race. The completion-side twin of `classify_csq_cancel_completion`
/// and of the rule that the axis decides, not the pointer.
///
/// `(Queued, None)` is the window between the framework's `CsqRemoveIrp`
/// nulling the slot pointer and its cancel completion publishing `Dequeued`:
/// the same answer, because neither is a published handoff.
/// `Completing`/`Completed` authorise nothing, because a completion already
/// under way is not a second authority.
pub fn classify_worker_dequeue(
    axis: Option<IrpAxis>,
    slot: Option<IrpObservation>,
) -> WorkerDequeueAuthority {
    match (axis, slot) {
        (Some(IrpAxis::Queued), _) => WorkerDequeueAuthority::NoHandoffPublished,
        (Some(IrpAxis::Dequeued), Some(irp)) => WorkerDequeueAuthority::ReleasedToDriver(irp),
        _ => WorkerDequeueAuthority::NoParkedIrp,
    }
}

#[allow(dead_code)]
impl IrpObservation {
    /// Observe a raw CSQ return. `None` for null.
    pub fn from_raw(value: usize) -> Option<Self> {
        NonZeroUsize::new(value).map(Self)
    }

    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }

    /// The observed address, for the one native frame that must complete it.
    ///
    /// Hidden-public since Task 19: the worker completes the exact IRP the
    /// plan's receipt names, and it can only do that with the address. Named
    /// distinctly rather than making `get` public, because `get` is answered by
    /// a dozen unrelated impls across both source roots and the production
    /// graph auditor models an edge as a bare-name mention.
    #[doc(hidden)]
    pub const fn observed_address(self) -> usize {
        self.0.get()
    }
}

/// Proof that one exact IRP left the queue for one exact reason.
///
/// The seal is private to this module and there is no public constructor, so a
/// caller cannot fabricate one:
///
/// ```compile_fail
/// use fsring_core::enter::{DequeuedIrp, IrpObservation, PendingReason};
/// use fsring_core::session::PendingInstallId;
///
/// fn forge(install: PendingInstallId, irp: IrpObservation) -> DequeuedIrp {
///     DequeuedIrp { install, reason: PendingReason::Cancel, irp }
/// }
/// ```
///
/// and it is affine, so one dequeue cannot authorise two contentions:
///
/// ```compile_fail
/// use fsring_core::enter::DequeuedIrp;
///
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<DequeuedIrp>();
/// ```
///
/// The observation it carries cannot be fabricated either -- which is what
/// makes "the CSQ returned this exact IRP" a fact rather than an argument:
///
/// ```compile_fail
/// use fsring_core::enter::IrpObservation;
/// use core::num::NonZeroUsize;
///
/// fn forge() -> IrpObservation {
///     IrpObservation(NonZeroUsize::new(1).unwrap())
/// }
/// ```
#[must_use]
#[derive(Debug)]
pub struct DequeuedIrp {
    install: PendingInstallId,
    reason: PendingReason,
    irp: IrpObservation,
    authority: PrivateDequeueReceipt,
}

#[allow(dead_code)]
impl DequeuedIrp {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub(crate) const fn reason(&self) -> PendingReason {
        self.reason
    }

    pub(crate) const fn irp(&self) -> IrpObservation {
        self.irp
    }
}

/// One parked ENTER, owned outright.
///
/// It owns its `PendingEnter` rather than borrowing a grant: a parked request
/// outlives the dispatch call that parked it, so a borrow would either pin that
/// frame or dangle. `parked_plan_is_owned_and_has_no_grant_borrow` is the check,
/// and the absence of a lifetime parameter on this type is the reason it holds.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct OwnedParkedEnter {
    install: PendingInstallId,
    irp: IrpObservation,
    terminal: PendingEnter,
}

#[allow(dead_code)]
impl OwnedParkedEnter {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub(crate) const fn irp(&self) -> IrpObservation {
        self.irp
    }
}

/// What a dequeue that arrived before handoff permits.
///
/// Only the Cancel owner may be released on this path: the installer is still
/// mid-publication and the worker has not run, so releasing either would drop
/// an owner that still has work to do. The cancel callback, by contrast, is
/// finished the moment it has the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyDequeueDisposition {
    ReleaseCancelOwnerOnly,
}

/// The lease-bound owner of one ring's parked IRP.
///
/// Bound to an `EnterExecutionBrand`, so an arbiter minted under one SQ-wait
/// lease cannot serve a later invocation of the same ring: the brand carries the
/// invocation, and every operation compares the whole brand.
#[cfg_attr(test, derive(Debug))]
pub struct PendingIrpArbiter {
    execution: EnterExecutionBrand,
    parked: Option<OwnedParkedEnter>,
    early: Option<DequeuedIrp>,
    handed_off: bool,
}

#[allow(dead_code)]
impl PendingIrpArbiter {
    /// Bind an arbiter to the SQ-wait lease that will park through it.
    pub fn bind(lease: &SqWaitRoleLease) -> Self {
        Self {
            execution: lease.execution(),
            parked: None,
            early: None,
            handed_off: false,
        }
    }

    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    pub(crate) const fn has_parked(&self) -> bool {
        self.parked.is_some()
    }

    pub(crate) const fn handoff_is_done(&self) -> bool {
        self.handed_off
    }

    /// Park one owned ENTER against one observed IRP.
    ///
    /// Refusal returns the whole plan: a parked request that failed to install
    /// still has to be completed by somebody, and dropping it here would strand
    /// the IRP.
    pub fn park(
        &mut self,
        install: PendingInstallId,
        irp: IrpObservation,
        terminal: PendingEnter,
    ) -> Result<(), (PendingError, PendingEnter)> {
        if install.brand() != self.execution.ring() {
            return Err((PendingError::WrongRing, terminal));
        }
        if self.parked.is_some() {
            return Err((PendingError::SlotOccupied, terminal));
        }
        self.parked = Some(OwnedParkedEnter {
            install,
            irp,
            terminal,
        });
        Ok(())
    }

    /// Mint the one receipt for a CSQ return.
    ///
    /// `csq_return` is the raw pointer the CSQ handed back. A null return, or a
    /// return naming a different IRP than the one parked, mints nothing at all —
    /// which is the whole of `null_or_wrong_csq_return_never_mints_a_receipt`.
    pub fn dequeue(
        &mut self,
        install: PendingInstallId,
        csq_return: usize,
        reason: PendingReason,
    ) -> Result<DequeuedIrp, PendingError> {
        let Some(parked) = self.parked.as_ref() else {
            return Err(PendingError::NotDequeued);
        };
        if parked.install != install {
            return Err(PendingError::WrongInstall);
        }
        let Some(observed) = IrpObservation::from_raw(csq_return) else {
            return Err(PendingError::WrongIrp);
        };
        if observed != parked.irp {
            return Err(PendingError::WrongIrp);
        }
        if self.early.is_some() {
            return Err(PendingError::AlreadyDequeued);
        }
        let receipt = DequeuedIrp {
            install,
            reason,
            irp: observed,
            authority: PrivateDequeueReceipt(()),
        };
        if self.handed_off {
            return Ok(receipt);
        }
        // Before handoff the receipt is *stored* rather than handed out: the
        // installer has not finished publishing, so nobody may act on it yet.
        // `handoff_done` reschedules exactly this one.
        self.early = Some(receipt);
        Err(PendingError::Closing)
    }

    /// What an early dequeue permits right now.
    pub(crate) const fn early_disposition(&self) -> Option<EarlyDequeueDisposition> {
        if self.early.is_some() {
            Some(EarlyDequeueDisposition::ReleaseCancelOwnerOnly)
        } else {
            None
        }
    }

    /// Finish the handoff, reporting whether one early dequeue is now due.
    pub fn handoff_done(&mut self) -> Result<bool, PendingError> {
        if self.parked.is_none() {
            return Err(PendingError::NotDequeued);
        }
        if self.handed_off {
            return Err(PendingError::WrongRingState);
        }
        self.handed_off = true;
        Ok(self.early.is_some())
    }

    /// Take the stored early receipt. Exactly once.
    pub fn take_early_receipt(&mut self) -> Option<DequeuedIrp> {
        if !self.handed_off {
            return None;
        }
        self.early.take()
    }

    /// Contend for the terminal, presenting an authentic receipt.
    ///
    /// The receipt is consumed and the parked plan is taken, so a second
    /// contention has neither. A refusal returns the receipt so the real owner
    /// can still use it.
    pub fn contend(
        &mut self,
        receipt: DequeuedIrp,
    ) -> Result<(PendingTerminalRight, IrpObservation), (PendingError, DequeuedIrp)> {
        let Some(parked) = self.parked.as_ref() else {
            return Err((PendingError::NotDequeued, receipt));
        };
        if parked.install != receipt.install {
            return Err((PendingError::WrongInstall, receipt));
        }
        if parked.irp != receipt.irp {
            return Err((PendingError::WrongIrp, receipt));
        }
        let contender = match receipt.reason {
            PendingReason::Cancel => EnterContender::Cancel,
            PendingReason::Timeout => EnterContender::Timeout,
            PendingReason::Readiness => EnterContender::Wake,
            PendingReason::Fence => EnterContender::Fence,
            PendingReason::Unload => EnterContender::Unload,
        };
        let Some(parked) = self.parked.take() else {
            unreachable!("the parked plan was observed above")
        };
        let OwnedParkedEnter {
            install: _,
            irp,
            terminal,
        } = parked;
        let DequeuedIrp {
            install: _,
            reason: _,
            irp: _,
            authority: PrivateDequeueReceipt(()),
        } = receipt;
        match terminal.contend(contender) {
            PendingOutcome::Won(right) => Ok((right, irp)),
            PendingOutcome::Lost { winner } => unreachable!(
                "the parked plan is taken with the receipt, so no second contender exists;                  a claim was already held by {winner:?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.5: the pending-completion typestate
// ---------------------------------------------------------------------------
//
// Completing one parked ENTER is eight effects in one order, and the order is
// the content. Writing the result after completing the IRP would write into a
// buffer the caller already owns again; releasing the SQ role before the write
// would let the next invocation reuse a slot this result is still being copied
// into; publishing the slot Vacant before the IRP completed would hand the slot
// to a new request while the old one is still in flight.
//
// `run_next` is the only progress API and it takes `self`, so a stage cannot be
// re-run or skipped: to be at stage N you must hold a plan that stage N-1
// returned.

// The witness needs no seal: it is `Copy` and carries only a reason and an
// install, so forging one gains nothing -- it holds no authority at all.
pending_authority_seals!(PrivateWrittenResultAuthority, PrivateCompletedIrpAuthority);

/// The eight completion effects, in the one order they may run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCompletionEffect {
    CancelTimer,
    WaitDpcExitIfRequired,
    WriteExactResult,
    ReleaseSqWaitRole,
    UnlinkControlPending,
    ReleaseStrongSessionRef,
    CompleteIrpOnce,
    PublishVacantOrEpochExhausted,
}

/// The canonical order, for the tests that must cover each stage.
pub const PENDING_COMPLETION_ORDER: [PendingCompletionEffect; 8] = [
    PendingCompletionEffect::CancelTimer,
    PendingCompletionEffect::WaitDpcExitIfRequired,
    PendingCompletionEffect::WriteExactResult,
    PendingCompletionEffect::ReleaseSqWaitRole,
    PendingCompletionEffect::UnlinkControlPending,
    PendingCompletionEffect::ReleaseStrongSessionRef,
    PendingCompletionEffect::CompleteIrpOnce,
    PendingCompletionEffect::PublishVacantOrEpochExhausted,
];

/// Proof that core copied one exact result into the slot.
///
/// Native performs the bounded copy, but only core mints this: the receipt
/// carries the status and information the *core* recorded, so a native caller
/// cannot claim a write that did not happen or claim different bytes than it
/// wrote.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct WrittenResultReceipt {
    install: PendingInstallId,
    status: u32,
    information: usize,
    authority: PrivateWrittenResultAuthority,
}

/// Proof that the one IRP completed exactly once.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct CompletedIrpReceipt {
    install: PendingInstallId,
    irp: IrpObservation,
    authority: PrivateCompletedIrpAuthority,
}

#[allow(dead_code)]
impl WrittenResultReceipt {
    pub(crate) const fn status(&self) -> u32 {
        self.status
    }

    pub(crate) const fn information(&self) -> usize {
        self.information
    }
}

#[allow(dead_code)]
impl CompletedIrpReceipt {
    pub(crate) const fn irp(&self) -> IrpObservation {
        self.irp
    }
}

/// The stable-session release owner, which may downgrade exactly once.
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub enum PendingStableReleaseOwner {
    Strong,
    Delete,
}

/// One in-flight completion.
///
/// Every affine authority the sequence will consume is held here from the
/// start, so a stage cannot discover halfway through that the thing it must
/// release was never handed over.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingCompletionPlan {
    install: PendingInstallId,
    stage: usize,
    irp: IrpObservation,
    role: Option<SqWaitRoleLease>,
    control_link: Option<PendingControlLinkRight>,
    stable_release: Option<PendingStableReleaseOwner>,
    written_result: Option<WrittenResultReceipt>,
    completed_irp: Option<CompletedIrpReceipt>,
    worker: Option<PendingOwnerToken>,
}

const _: [(); 1] = [(); { (core::mem::size_of::<PendingCompletionPlan>() <= 1024) as usize }];

/// What `run_next` did, and what the caller must do before calling it again.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum PendingCompletionStep {
    /// An ordinary stage ran; call `run_next` on the returned plan.
    Advanced(PendingCompletionPlan),
    /// Native must copy the result, then commit through core.
    NeedResultWrite(PendingResultWrite),
    /// Native must complete the IRP, then commit through core.
    NeedIrpCompletion(PendingIrpCompletion),
    /// Core must jointly publish with the owning slot and ledger.
    NeedFinalPublication(PendingFinalPublication),
}

/// The result-write boundary. Native copies; only core mints the receipt.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingResultWrite {
    plan: PendingCompletionPlan,
}

/// The IRP-completion boundary.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingIrpCompletion {
    plan: PendingCompletionPlan,
}

/// The final joint publication boundary.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingFinalPublication {
    plan: PendingCompletionPlan,
}

/// What one completed pending install leaves behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct PendingCompletionResult {
    install: PendingInstallId,
    exhausted: bool,
}

#[allow(dead_code)]
impl PendingCompletionResult {
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub(crate) const fn exhausted(&self) -> bool {
        self.exhausted
    }
}

/// A refused final publication, holding the plan whole.
///
/// It does **not** decompose the plan: a refusal at the last stage leaves an
/// IRP already completed and a result already written, so handing the pieces
/// back separately would let a caller reassemble a plan that repeats them. The
/// packet is the only thing that can carry the state forward, and it has no
/// method that clears or retries it.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PublicationFailStop {
    plan: PendingCompletionPlan,
    reason: PendingError,
}

/// A typed observation of a fail-stop. It can report; it cannot repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationFailStopWitness {
    install: PendingInstallId,
    reason: PendingError,
}

impl PublicationFailStop {
    /// Observe the refusal without consuming the packet.
    pub const fn witness(&self) -> PublicationFailStopWitness {
        PublicationFailStopWitness {
            install: self.plan.install,
            reason: self.reason,
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn reason(&self) -> PendingError {
        self.reason
    }
}

#[allow(dead_code)]
impl PublicationFailStopWitness {
    #[allow(dead_code)]
    pub(crate) const fn reason(&self) -> PendingError {
        self.reason
    }

    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }
}

impl PendingCompletionPlan {
    /// Begin one completion, taking every authority it will consume.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn begin(
        install: PendingInstallId,
        irp: IrpObservation,
        role: SqWaitRoleLease,
        control_link: PendingControlLinkRight,
        worker: PendingOwnerToken,
    ) -> Result<
        Self,
        (
            PendingError,
            SqWaitRoleLease,
            PendingControlLinkRight,
            PendingOwnerToken,
        ),
    > {
        if worker.kind() != PendingOwnerKind::Worker {
            return Err((PendingError::WrongOwnerKind, role, control_link, worker));
        }
        if worker.install() != install {
            return Err((PendingError::WrongInstall, role, control_link, worker));
        }
        if control_link.install() != install {
            return Err((PendingError::WrongInstall, role, control_link, worker));
        }
        Ok(Self {
            install,
            stage: 0,
            irp,
            role: Some(role),
            control_link: Some(control_link),
            stable_release: Some(PendingStableReleaseOwner::Strong),
            written_result: None,
            completed_irp: None,
            worker: Some(worker),
        })
    }

    /// The effect this plan will run next, if any.
    pub fn stage(&self) -> Option<PendingCompletionEffect> {
        PENDING_COMPLETION_ORDER.get(self.stage).copied()
    }

    /// Take the SQ-wait lease at [`PendingCompletionEffect::ReleaseSqWaitRole`].
    ///
    /// Native releases it into the slot under the pending lock, then continues
    /// with the returned plan. Advancing here is what keeps `run_next` from
    /// dropping the same lease a second time.
    pub fn take_sq_wait_role(mut self) -> (Self, Option<SqWaitRoleLease>) {
        let role = if matches!(
            self.stage(),
            Some(PendingCompletionEffect::ReleaseSqWaitRole)
        ) {
            self.stage = self.stage.saturating_add(1);
            self.role.take()
        } else {
            None
        };
        (self, role)
    }

    /// Take the control-ledger link at [`PendingCompletionEffect::UnlinkControlPending`].
    ///
    /// Native reaches the session's `PendingControlLedger` and calls its own
    /// `unlink` with the returned right, then continues with the returned
    /// plan. Without this method, `run_next` for this stage only clears the
    /// local `Option` -- the right is dropped (it has no `Drop`) and the
    /// ledger slot never frees, so a ring can serve only one parked ENTER-WAIT
    /// for the life of the session. Mirrors `take_sq_wait_role` exactly: the
    /// taking method is the one path that advances past this stage in
    /// production, so a walk that only calls `run_next` cannot skip the
    /// unlink and still progress.
    pub fn take_control_link(mut self) -> (Self, Option<PendingControlLinkRight>) {
        let link = if matches!(
            self.stage(),
            Some(PendingCompletionEffect::UnlinkControlPending)
        ) {
            self.stage = self.stage.saturating_add(1);
            self.control_link.take()
        } else {
            None
        };
        (self, link)
    }

    #[allow(dead_code)]
    pub(crate) const fn install(&self) -> PendingInstallId {
        self.install
    }

    /// Run exactly one effect.
    ///
    /// Takes `self`, so there is no way to re-run or skip a stage: to be at
    /// stage N you must hold a plan that stage N-1 returned. There is
    /// deliberately no `skip`, no `reset`, and no `stage` setter.
    pub fn run_next(mut self) -> PendingCompletionStep {
        let Some(effect) = self.stage() else {
            return PendingCompletionStep::Advanced(self);
        };
        match effect {
            // The two bookkeeping stages have no affine consequence here; the
            // DPC-owner handoff they carry is Task 19's native aggregate.
            PendingCompletionEffect::CancelTimer
            | PendingCompletionEffect::WaitDpcExitIfRequired => {
                self.stage = self.stage.saturating_add(1);
                PendingCompletionStep::Advanced(self)
            }
            PendingCompletionEffect::WriteExactResult => {
                PendingCompletionStep::NeedResultWrite(PendingResultWrite { plan: self })
            }
            PendingCompletionEffect::ReleaseSqWaitRole => {
                // Native must release this into the slot state. `take_sq_wait_role`
                // is the consuming path; `run_next` only advances when the lease
                // is already gone so a walk cannot skip the write-then-release
                // order.
                if self.role.is_some() {
                    self.role = None;
                }
                self.stage = self.stage.saturating_add(1);
                PendingCompletionStep::Advanced(self)
            }
            PendingCompletionEffect::UnlinkControlPending => {
                self.control_link = None;
                self.stage = self.stage.saturating_add(1);
                PendingCompletionStep::Advanced(self)
            }
            PendingCompletionEffect::ReleaseStrongSessionRef => {
                self.stable_release = None;
                self.stage = self.stage.saturating_add(1);
                PendingCompletionStep::Advanced(self)
            }
            PendingCompletionEffect::CompleteIrpOnce => {
                PendingCompletionStep::NeedIrpCompletion(PendingIrpCompletion { plan: self })
            }
            PendingCompletionEffect::PublishVacantOrEpochExhausted => {
                PendingCompletionStep::NeedFinalPublication(PendingFinalPublication { plan: self })
            }
        }
    }

    /// Downgrade the stable release owner exactly once.
    ///
    /// Used when core release succeeded but the finalizer deposit refused: the
    /// retry may perform only the deposit, and can never release the strong
    /// reference twice.
    pub fn downgrade_stable_release(&mut self) -> Result<(), PendingError> {
        match self.stable_release {
            Some(PendingStableReleaseOwner::Strong) => {
                self.stable_release = Some(PendingStableReleaseOwner::Delete);
                Ok(())
            }
            Some(PendingStableReleaseOwner::Delete) => Err(PendingError::AlreadyDequeued),
            None => Err(PendingError::WrongRingState),
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn holds_role(&self) -> bool {
        self.role.is_some()
    }

    #[allow(dead_code)]
    pub(crate) const fn holds_control_link(&self) -> bool {
        self.control_link.is_some()
    }

    #[allow(dead_code)]
    pub(crate) const fn has_written_result(&self) -> bool {
        self.written_result.is_some()
    }

    #[allow(dead_code)]
    pub(crate) const fn has_completed_irp(&self) -> bool {
        self.completed_irp.is_some()
    }
}

impl PendingResultWrite {
    /// The exact slot view native must copy into.
    pub const fn view(&self) -> (PendingInstallId, IrpObservation) {
        (self.plan.install, self.plan.irp)
    }

    /// Commit the copy native just performed, minting the one receipt.
    ///
    /// Named `commit_result_write`, not `commit`: the production graph auditor's
    /// edge model is a bare identifier mention, and `commit` is answered by a
    /// dozen unrelated impls including production-reachable ones. A method
    /// called `commit` here made `release_owner` look reachable from CLEANUP.
    ///
    /// There is no `abort`. Safe code cannot recreate a same-stage plan after
    /// the native effect, because the only way back to a plan is through this
    /// method and it advances the stage.
    pub fn commit_result_write(self, status: u32, information: usize) -> PendingCompletionPlan {
        let Self { mut plan } = self;
        plan.written_result = Some(WrittenResultReceipt {
            install: plan.install,
            status,
            information,
            authority: PrivateWrittenResultAuthority(()),
        });
        plan.stage = plan.stage.saturating_add(1);
        plan
    }
}

impl PendingIrpCompletion {
    /// The IRP and the status/information the write recorded.
    pub fn view(&self) -> Option<(IrpObservation, u32, usize)> {
        self.plan
            .written_result
            .as_ref()
            .map(|written| (self.plan.irp, written.status, written.information))
    }

    /// Commit the completion native just performed.
    pub fn commit_irp_completion(self) -> PendingCompletionPlan {
        let Self { mut plan } = self;
        plan.completed_irp = Some(CompletedIrpReceipt {
            install: plan.install,
            irp: plan.irp,
            authority: PrivateCompletedIrpAuthority(()),
        });
        plan.stage = plan.stage.saturating_add(1);
        plan
    }
}

impl PendingFinalPublication {
    /// Jointly publish, consuming the slot's occupancy and the Worker owner.
    ///
    /// Neither the IRP receipt nor the worker token alone authorises slot
    /// reuse: this validates the completed receipt, the exact Worker owner with
    /// no other owner outstanding, an occupied result slot, and a drained wake
    /// slot *together*, and only then clears them. A refusal returns a fail-stop
    /// packet holding the plan whole.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn commit_final_publication(
        self,
        slot: &mut PendingResultSlot,
        owners: &mut PendingOwnerLedger,
        wake: &PendingWakeSlot,
        exhausted: bool,
    ) -> Result<PendingCompletionResult, PublicationFailStop> {
        let plan = self.plan;
        // Each arm is a distinct property that happens to share an error
        // value; collapsing them would hide which check refused.
        #[allow(clippy::if_same_then_else)]
        let reason = if plan.completed_irp.is_none() {
            Some(PendingError::NotDequeued)
        } else if plan.written_result.is_none() {
            Some(PendingError::WrongSlot)
        } else if slot.install != Some(plan.install) {
            Some(PendingError::WrongSlot)
        } else if wake.has_wake() {
            Some(PendingError::OwnersRemain)
        } else if owners.owner_count() != 1 || !owners.holds(PendingOwnerKind::Worker) {
            Some(PendingError::OwnersRemain)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(PublicationFailStop { plan, reason });
        }
        let mut plan = plan;
        let Some(worker) = plan.worker.take() else {
            return Err(PublicationFailStop {
                plan,
                reason: PendingError::WrongOwnerKind,
            });
        };
        if owners.release_owner(worker).is_err() {
            return Err(PublicationFailStop {
                plan,
                reason: PendingError::WrongOwnerKind,
            });
        }
        slot.install = None;
        Ok(PendingCompletionResult {
            install: plan.install,
            exhausted,
        })
    }
}

impl PendingResultSlot {
    /// Claim this slot for one install.
    pub fn occupy(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if install.brand() != self.brand {
            return Err(PendingError::WrongRing);
        }
        if self.install.is_some() {
            return Err(PendingError::SlotOccupied);
        }
        self.install = Some(install);
        Ok(())
    }

    /// Release this slot's reservation, so it can be occupied by another install.
    ///
    /// The closing half of [`Self::occupy`], mirroring
    /// [`PendingOwnerLedger::unbind_install`] and
    /// [`PendingWorkerSchedule::end_install`]: a park attempt that reserved
    /// this slot and then failed a later step must give it back, or every
    /// later install on this ring refuses at `SlotOccupied` forever.
    pub fn vacate(&mut self, install: PendingInstallId) -> Result<(), PendingError> {
        if self.install != Some(install) {
            return Err(PendingError::WrongInstall);
        }
        self.install = None;
        Ok(())
    }

    /// Whether the slot may be reused right now.
    #[allow(dead_code)]
    pub(crate) const fn is_reusable(&self) -> bool {
        self.install.is_none()
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.1/14.4: the commit tracker, the two acquisition aggregates, and
// the sealed SQ -> CQ resume bridge
// ---------------------------------------------------------------------------

pending_authority_seals!(PrivateCommitTrackerAuthority, PrivateResumeAuthority);

/// Whether one execution has performed a real mutation yet.
///
/// Affine and non-`Clone`, and it travels *with* the authority that could
/// mutate. A copyable flag would let a caller assert "nothing committed" from a
/// stale copy taken before the mutation it is asserting about.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct EnterCommitTracker {
    execution: EnterExecutionBrand,
    committed: bool,
    authority: PrivateCommitTrackerAuthority,
}

#[allow(dead_code)]
impl EnterCommitTracker {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    pub(crate) const fn committed(&self) -> bool {
        self.committed
    }

    /// Record the first real mutation. Idempotent by design: the question this
    /// answers is "did anything commit", not "how many times".
    pub fn record_commit(&mut self) {
        self.committed = true;
    }
}

/// One SQ-wait acquisition: the lease, its tracker, and its terminal seed.
///
/// The three are minted together and handed out together, so an SQ execution
/// cannot exist holding a lease whose tracker belongs to a different
/// invocation. Non-`Clone` and non-`Copy`.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct AcquiredSqWait {
    lease: SqWaitRoleLease,
    tracker: EnterCommitTracker,
    terminal: PendingEnter,
}

/// One CQ-consumer acquisition: the token and its tracker.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct AcquiredCqConsumer {
    token: CqConsumerToken,
    tracker: EnterCommitTracker,
}

#[allow(dead_code)]
impl AcquiredSqWait {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.lease.execution()
    }

    /// Split into the three parts. The only way to reach any of them.
    pub fn into_plan_parts(self) -> (SqWaitRoleLease, EnterCommitTracker, PendingEnter) {
        let Self {
            lease,
            tracker,
            terminal,
        } = self;
        (lease, tracker, terminal)
    }
}

#[allow(dead_code)]
impl AcquiredCqConsumer {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.token.execution()
    }

    pub fn into_plan_parts(self) -> (CqConsumerToken, EnterCommitTracker) {
        let Self { token, tracker } = self;
        (token, tracker)
    }
}

/// The authority a readiness resume needs, borrowed rather than reacquired.
///
/// It holds a *shared borrow* of the original SQ lease. Reacquiring the role
/// would mint a new invocation and a new tracker, and the resumed execution
/// would then be a different execution than the one that parked — which is
/// exactly the confusion `sq_to_cq_bridge_does_not_consume_the_next_invocation`
/// exists to prevent.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct SqWaitResume<'lease> {
    lease: &'lease SqWaitRoleLease,
    authority: PrivateResumeAuthority,
}

/// A CQ-consumer authority derived from an authentic SQ resume.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct AuthenticatedCqResume {
    execution: EnterExecutionBrand,
    authority: PrivateResumeAuthority,
}

#[allow(dead_code)]
impl AuthenticatedCqResume {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    pub(crate) const fn ring(&self) -> SessionRingBrand {
        self.execution.ring()
    }
}

impl RingEnterState {
    /// Acquire the SQ-wait role as one aggregate.
    pub fn acquire_sq_wait_aggregate(&mut self) -> Result<AcquiredSqWait, RoleError> {
        let lease = self.acquire_sq_wait()?;
        let execution = lease.execution();
        Ok(AcquiredSqWait {
            terminal: PendingEnter::new(execution.invocation().get()),
            tracker: EnterCommitTracker {
                execution,
                committed: false,
                authority: PrivateCommitTrackerAuthority(()),
            },
            lease,
        })
    }

    /// Acquire the CQ-consumer role as one aggregate.
    pub fn acquire_cq_consumer_aggregate(&mut self) -> Result<AcquiredCqConsumer, RoleError> {
        let token = self.acquire_cq_consumer()?;
        let execution = token.execution();
        Ok(AcquiredCqConsumer {
            tracker: EnterCommitTracker {
                execution,
                committed: false,
                authority: PrivateCommitTrackerAuthority(()),
            },
            token,
        })
    }

    /// Authorise a readiness resume against a lease this state still owns.
    ///
    /// Borrowing the lease rather than taking it is the point: the resumed
    /// execution *is* the parked one. A foreign state refuses, because the lease
    /// it was handed names a ring this state does not serve.
    pub fn authorize_resume<'lease>(
        &self,
        lease: &'lease SqWaitRoleLease,
    ) -> Result<SqWaitResume<'lease>, RoleError> {
        let Some(ring) = self.brand else {
            return Err(RoleError::WrongState);
        };
        let execution = lease.execution();
        if execution.ring() != ring {
            return Err(RoleError::WrongRing);
        }
        if self.sq_owner != Some(execution.invocation().get()) {
            return Err(RoleError::WrongInvocation);
        }
        Ok(SqWaitResume {
            lease,
            authority: PrivateResumeAuthority(()),
        })
    }
}

#[allow(dead_code)]
impl SqWaitResume<'_> {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.lease.execution()
    }

    /// Derive the one CQ-consumer authority for this exact SQ request.
    ///
    /// It reuses the parked invocation rather than minting a new one, so the
    /// SQ→CQ bridge does not consume the next invocation and the two halves of
    /// one request stay one execution. The domain is the only component that
    /// changes.
    pub(crate) fn bind_cq_consumer(self) -> AuthenticatedCqResume {
        let Self {
            lease,
            authority: PrivateResumeAuthority(()),
        } = self;
        let parked = lease.execution();
        AuthenticatedCqResume {
            execution: EnterExecutionBrand::for_resume(parked),
            authority: PrivateResumeAuthority(()),
        }
    }
}

impl EnterExecutionBrand {
    /// The CQ-consumer view of one parked SQ execution.
    ///
    /// Private to this module. A caller cannot build one, which is what makes
    /// `AuthenticatedCqResume` unforgeable: the only route to a CQ-domain brand
    /// carrying a parked invocation is through `bind_cq_consumer`.
    const fn for_resume(parked: Self) -> Self {
        Self {
            ring: parked.ring,
            invocation: parked.invocation,
            domain: EnterExecutionDomain::CqConsumer,
        }
    }
}

// ---------------------------------------------------------------------------
// R4 Task 17 (core half): the pending slot's epoch machine and IRP axis
// ---------------------------------------------------------------------------
//
// Task 17's `PendingEnterContext` is an fsd struct of roughly forty fields --
// `IO_CSQ`, `KTIMER`, `KDPC`, `IO_WORKITEM`, raw `PIRP`. None of it is testable
// on this host. What *is* testable, and what the native struct is a container
// for, is the pair of state machines it carries: the slot's nonwrapping epoch
// machine and the IRP's one-way axis. Those land here.

/// One pending slot's lifecycle, keyed by a nonwrapping install epoch.
///
/// `Vacant { next_epoch }` carries the epoch the *next* install will take, so a
/// reused slot never hands out an epoch a previous install carried — the whole
/// reason a slot index alone is not an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingSlotState {
    Vacant { next_epoch: u64 },
    Installing { epoch: u64 },
    Active { epoch: u64 },
    Quiescing { epoch: u64 },
    PublicationFailStop { epoch: u64 },
    EpochExhausted,
}

/// Where the IRP is. One way only, and never back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrpAxis {
    Queued,
    Dequeued,
    Completing,
    Completed,
}

impl IrpAxis {
    /// The one legal successor, or `None` at the end.
    ///
    /// A total function rather than a set of allowed pairs: with a successor
    /// function there is no way to express "Completed back to Queued" at all,
    /// whereas an allow-list has to remember to exclude it.
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Queued => Some(Self::Dequeued),
            Self::Dequeued => Some(Self::Completing),
            Self::Completing => Some(Self::Completed),
            Self::Completed => None,
        }
    }

    /// Whether the IRP is still the driver's to complete.
    pub const fn driver_owns_completion(self) -> bool {
        matches!(self, Self::Queued | Self::Dequeued | Self::Completing)
    }
}

/// What one observation of a draining pending context decided.
///
/// The checkpoint's `WaitPendingAndOwners` has to *wait*, not merely look: the
/// Fence wake is deposited and the worker queued two roster rows earlier, so a
/// context can be legitimately Active with a pass queued and not yet running.
/// Refusing that would park a session whose worker was about to complete it.
///
/// The decision lives here rather than in the native row for the usual reason —
/// "how many times, and what may never be retried" is exactly the part a host
/// can test, and the native side supplies only the delay.
#[derive(Debug)]
#[must_use]
pub enum PendingDrainStep {
    /// Wait, then observe this context again.
    Observe(PendingDrainWait),
    /// This context is drained. Move to the next one.
    Drained,
    /// This context will not drain. The roster entry refuses here.
    Refused(PendingDrainRefusal),
}

/// Why a context stopped being waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingDrainRefusal {
    /// A refused final publication is parked in the context. It can never
    /// become drained, so waiting for it would be waiting forever.
    PublicationFailStop,
    /// The context stayed active for the whole bounded wait.
    StillActive,
}

/// One context's bounded drain wait.
///
/// Affine and non-`Copy`: an observation consumes the cursor and returns the
/// next one, so a caller cannot observe twice against the same attempt count and
/// call the result progress.
#[derive(Debug)]
#[must_use]
pub struct PendingDrainWait {
    remaining: u32,
}

impl PendingDrainWait {
    /// How many times an active context is re-observed before the entry
    /// refuses.
    ///
    /// A bound rather than an unbounded wait: `WaitPendingAndOwners` runs on the
    /// terminal thread with session admission already closed, so a context that
    /// is still active after the whole budget is not "slow", it is stuck — and
    /// refusing parks the generation, which is recoverable, where blocking
    /// forever wedges unload.
    pub const MAX_OBSERVATIONS: u32 = 1024;

    /// Begin waiting for one context.
    pub const fn begin_drain_wait() -> Self {
        Self {
            remaining: Self::MAX_OBSERVATIONS,
        }
    }

    /// Observations left before this wait gives up.
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }

    /// The context reported Vacant or EpochExhausted with an empty packet slot.
    pub const fn observed_drained(self) -> PendingDrainStep {
        PendingDrainStep::Drained
    }

    /// The context still holds a live install.
    ///
    /// The count is what decides, and it only ever goes down: there is no method
    /// that raises it, so a context cannot keep the roster entry alive by
    /// staying busy.
    pub const fn observed_active(self) -> PendingDrainStep {
        match self.remaining.checked_sub(1) {
            Some(0) | None => PendingDrainStep::Refused(PendingDrainRefusal::StillActive),
            Some(remaining) => PendingDrainStep::Observe(Self { remaining }),
        }
    }

    /// The context has a parked publication fail-stop.
    ///
    /// Refuses immediately and consumes the cursor, so there is no path on which
    /// a fail-stop is retried into a drained proof. That is the property the
    /// whole packet exists for: it is permanent, and a roster entry that waited
    /// on it would be waiting for something that cannot happen.
    pub const fn observed_publication_fail_stop(self) -> PendingDrainStep {
        PendingDrainStep::Refused(PendingDrainRefusal::PublicationFailStop)
    }
}

impl PendingSlotState {
    /// A fresh slot, starting at epoch 1.
    pub const fn fresh() -> Self {
        Self::Vacant { next_epoch: 1 }
    }

    /// The epoch this state is about, if it has one.
    pub const fn epoch(self) -> Option<u64> {
        match self {
            Self::Installing { epoch }
            | Self::Active { epoch }
            | Self::Quiescing { epoch }
            | Self::PublicationFailStop { epoch } => Some(epoch),
            Self::Vacant { .. } | Self::EpochExhausted => None,
        }
    }

    /// Begin one install, consuming the next epoch.
    ///
    /// Only a `Vacant` slot admits one. `u64::MAX` is issued once and the slot
    /// then latches `EpochExhausted` — wrapping to 1 would reuse an epoch a
    /// live install may still carry, and refusing at `MAX - 1` would discard the
    /// last usable one.
    pub const fn begin_install(self) -> Result<Self, (PendingError, Self)> {
        match self {
            Self::Vacant { next_epoch } => Ok(Self::Installing { epoch: next_epoch }),
            other => Err((PendingError::SlotOccupied, other)),
        }
    }

    /// The installer finished publishing.
    pub const fn handoff_done(self) -> Result<Self, (PendingError, Self)> {
        match self {
            Self::Installing { epoch } => Ok(Self::Active { epoch }),
            other => Err((PendingError::WrongRingState, other)),
        }
    }

    /// Terminal work has begun; no new arrival may join this epoch.
    pub const fn begin_quiesce(self) -> Result<Self, (PendingError, Self)> {
        match self {
            Self::Installing { epoch } | Self::Active { epoch } => Ok(Self::Quiescing { epoch }),
            other => Err((PendingError::WrongRingState, other)),
        }
    }

    /// The coupled final publication succeeded: the slot is reusable.
    ///
    /// This is the *only* transition that produces a reusable slot, and it
    /// advances the epoch as it does — so the successor cannot be handed the
    /// epoch its predecessor used.
    pub const fn publish_vacant(self) -> Result<Self, (PendingError, Self)> {
        match self {
            Self::Quiescing { epoch } => match epoch.checked_add(1) {
                Some(next_epoch) => Ok(Self::Vacant { next_epoch }),
                None => Ok(Self::EpochExhausted),
            },
            other => Err((PendingError::WrongRingState, other)),
        }
    }

    /// The final publication refused. The slot is parked, not reusable.
    ///
    /// Named `park_publication_fail_stop`, not `fail_stop`: the R3 finalizer has
    /// its own `fail_stop`, and the graph auditor's bare-identifier edge model
    /// merged the two into a route from CLEANUP into this staged machine.
    pub const fn park_publication_fail_stop(self) -> Result<Self, (PendingError, Self)> {
        match self {
            Self::Quiescing { epoch } => Ok(Self::PublicationFailStop { epoch }),
            other => Err((PendingError::WrongRingState, other)),
        }
    }

    /// Whether a new install may begin right now.
    pub const fn admits_install(self) -> bool {
        matches!(self, Self::Vacant { .. })
    }
}

// ---------------------------------------------------------------------------
// R4 Task 18 (core half): the counted initialization cursor
// ---------------------------------------------------------------------------
//
// `PendingRuntimePrefix` owns a `PendingContextArenaOwner` — `NonNull`,
// `NonPagedAllocationOwner`, `IO_WORKITEM` — so the prefix itself is fsd. The
// rule it exists to enforce is not: a partially initialized arena must be
// reversed over *exactly* the prefix that was initialized, and readiness must
// require every ring, not merely a plausible number of them. That cursor lands
// here, and the fsd prefix holds one.

/// How far a staged runtime initialization has got.
///
/// The count is the whole state. A prefix that tracked "initialized" as a bool
/// would have to guess how much to reverse on rollback, and guessing high frees
/// storage that was never constructed while guessing low leaks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRuntimeInitCursor {
    ring_count: u32,
    initialized: u32,
}

/// Proof that one ring set's pending runtime is completely initialized.
///
/// Affine and non-`Clone`, with no public constructor: the only way to hold one
/// is to have driven a `PendingRuntimeInitCursor` to completion and agreed
/// about the ring count. Task 19's atomic cutover is the only thing permitted
/// to consume it into a Live session, which is why it carries the count rather
/// than being a marker -- a proof for a different set is not this set's proof.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct PendingRuntimeReadyProof {
    ring_count: u32,
    authority: PrivatePendingRuntimeReadyAuthority,
}

#[allow(dead_code)]
impl PendingRuntimeReadyProof {
    pub const fn ring_count(&self) -> u32 {
        self.ring_count
    }
}

/// What a rollback must reverse: the exact initialized prefix, and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRuntimeRollbackSpan {
    initialized: u32,
}

impl PendingRuntimeRollbackSpan {
    /// The number of constructed contexts to tear down, highest index first.
    pub const fn len(self) -> u32 {
        self.initialized
    }

    pub const fn is_empty(self) -> bool {
        self.initialized == 0
    }

    /// Take the next index to tear down, highest first.
    ///
    /// The reverse order lives here rather than in the caller's loop for the
    /// same reason the R3 roster does: the order *is* the content. A native
    /// rollback that counted upward would free the arena's first work item
    /// while later ones still referenced it, and a loop written at the call
    /// site is a loop no host test can drive.
    ///
    /// Consuming, so the span cannot be walked twice, and it yields exactly
    /// `len()` indices, `len() - 1` down to 0 — never an uninitialized one.
    pub const fn next_reverse(self) -> Option<(u32, Self)> {
        if self.initialized == 0 {
            return None;
        }
        let next = self.initialized.saturating_sub(1);
        Some((next, Self { initialized: next }))
    }
}

impl PendingRuntimeInitCursor {
    /// Begin one initialization for a set of `ring_count` rings.
    ///
    /// A zero-ring set is refused: a ready runtime with no rings would satisfy
    /// `finish` vacuously, and every later check that asks "is every ring
    /// initialized" would pass without any ring existing.
    pub const fn begin(ring_count: u32) -> Result<Self, PendingError> {
        if ring_count == 0 || ring_count > MAX_SESSION_RING_COUNT {
            return Err(PendingError::InvalidCapacity);
        }
        Ok(Self {
            ring_count,
            initialized: 0,
        })
    }

    /// The next index to initialize, or `None` once the set is covered.
    ///
    /// Named `next_uninitialized_index`: `SessionRingSetInitializer` has a
    /// *field* called `next_index` -- itself a rename to dodge an earlier
    /// collision -- and the graph auditor merges a method with a field of the
    /// same name, producing `driver_entry -> load -> finish -> next_index`.
    pub const fn next_uninitialized_index(self) -> Option<u32> {
        if self.initialized < self.ring_count {
            Some(self.initialized)
        } else {
            None
        }
    }

    /// Record one successful context initialization.
    ///
    /// Refuses past the end rather than saturating: a cursor that silently
    /// stopped counting would make `finish` pass for a set whose later rings
    /// were never constructed.
    pub const fn record_initialized(self) -> Result<Self, (PendingError, Self)> {
        match self.initialized.checked_add(1) {
            Some(initialized) if initialized <= self.ring_count => Ok(Self {
                ring_count: self.ring_count,
                initialized,
            }),
            _ => Err((PendingError::SlotOccupied, self)),
        }
    }

    /// Readiness requires **every** ring, and the caller's count must agree.
    ///
    /// Two separate checks on purpose: `initialized == self.ring_count` is the
    /// cursor's own completeness, and `ring_count == self.ring_count` is the
    /// caller agreeing about which set this is. A caller passing a smaller count
    /// would otherwise be able to declare a partial arena ready.
    /// Success yields a *proof*, not a unit. A completed prefix is the only
    /// thing that can mint [`PendingRuntimeReadyProof`], and Task 19's cutover
    /// is the only thing allowed to consume one into a Live session — so
    /// "ready" is a value that has to be produced and carried rather than a
    /// belief a caller can hold.
    pub const fn finish(
        self,
        ring_count: u32,
    ) -> Result<PendingRuntimeReadyProof, (PendingError, Self)> {
        if ring_count != self.ring_count {
            return Err((PendingError::WrongRing, self));
        }
        if self.initialized != self.ring_count {
            return Err((PendingError::OwnersRemain, self));
        }
        Ok(PendingRuntimeReadyProof {
            ring_count,
            authority: PrivatePendingRuntimeReadyAuthority(()),
        })
    }

    /// The exact prefix a rollback must reverse.
    pub const fn rollback_span(self) -> PendingRuntimeRollbackSpan {
        PendingRuntimeRollbackSpan {
            initialized: self.initialized,
        }
    }

    pub const fn initialized(self) -> u32 {
        self.initialized
    }

    pub const fn ring_count(self) -> u32 {
        self.ring_count
    }
}

// ---------------------------------------------------------------------------
// R5 Task 21 (core half): the CQ release preflight
// ---------------------------------------------------------------------------
//
// A protocol abort commits a CQ mutation and then has to release the consumer
// role. The order matters and the naive shapes both fail:
//
//   * Release first, then commit — the mutation now runs without a role, and
//     nothing says which invocation it belonged to.
//   * Commit, then release with a fresh lookup — the lookup can find a *later*
//     invocation of the same ring, so the release credits the wrong execution.
//
// The preflight records the exact still-owned identity *without* releasing or
// copying the token, and the release consumes that record. Between the two the
// role stays held, so there is no window in which the ring looks free.

/// The exact role identity a protocol commit will release, recorded up front.
///
/// Non-`Clone`: one preflight authorises one release. It records the identity
/// rather than taking the token, so the role is still held while the commit
/// runs — a token taken here would leave the mutation roleless.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PreparedCqReleasePreflight {
    brand: SessionRingBrand,
    invocation: EnterInvocationId,
}

/// Proof that the exact preflighted consumer role was released.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct ProtocolConsumerReleased {
    brand: SessionRingBrand,
    invocation: EnterInvocationId,
}

#[allow(dead_code)]
impl PreparedCqReleasePreflight {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    pub(crate) const fn invocation(&self) -> EnterInvocationId {
        self.invocation
    }
}

#[allow(dead_code)]
impl ProtocolConsumerReleased {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    pub(crate) const fn invocation(&self) -> EnterInvocationId {
        self.invocation
    }
}

impl RingEnterState {
    /// Record the CQ-consumer identity a protocol commit will release.
    ///
    /// Takes `&self` and the token by reference: nothing is released and
    /// nothing is copied, so the role is still held when the caller goes on to
    /// mutate. A version that took the token would hand the mutation a ring
    /// with no consumer.
    pub fn prepare_cq_release(
        &self,
        token: &CqConsumerToken,
    ) -> Result<PreparedCqReleasePreflight, RoleError> {
        let Some(ring) = self.brand else {
            return Err(RoleError::WrongState);
        };
        let execution = token.execution();
        if execution.ring() != ring {
            return Err(RoleError::WrongRing);
        }
        if execution.domain() != EnterExecutionDomain::CqConsumer {
            return Err(RoleError::WrongState);
        }
        if self.cq_owner != Some(execution.invocation().get()) {
            return Err(RoleError::WrongInvocation);
        }
        Ok(PreparedCqReleasePreflight {
            brand: ring,
            invocation: execution.invocation(),
        })
    }

    /// Release exactly the preflighted role, consuming both the record and the
    /// token.
    ///
    /// Both are required and both are checked against each other and against the
    /// state, so a commit cannot release a *later* invocation of the same ring —
    /// which is what a fresh lookup at release time would do.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn commit_cq_release(
        &mut self,
        preflight: PreparedCqReleasePreflight,
        token: CqConsumerToken,
    ) -> Result<ProtocolConsumerReleased, (RoleError, PreparedCqReleasePreflight, CqConsumerToken)>
    {
        let execution = token.execution();
        if execution.invocation() != preflight.invocation || execution.ring() != preflight.brand {
            return Err((RoleError::WrongInvocation, preflight, token));
        }
        match self.release_cq_consumer(token) {
            Ok(()) => Ok(ProtocolConsumerReleased {
                brand: preflight.brand,
                invocation: preflight.invocation,
            }),
            Err((error, token)) => Err((error, preflight, token)),
        }
    }
}

#[cfg(test)]
mod tests;
