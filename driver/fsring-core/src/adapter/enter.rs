//! WDK-free ENTER choreography: poll, drain, pending wait, and the fence.
//!
//! `02-transport.md` section 10.4 and `10-lifecycle.md` sections 5-7 fix the
//! order in which an ENTER snapshots its request, zeroes its output, takes a
//! ring role, polls with the clear-and-recheck protocol, drains a bounded stable
//! CQ prefix, installs a pending IRP, and resolves exactly one terminal. This
//! module owns all of that as a closed ordered plan; `fsring-fsd` translates one
//! typed effect into exactly one native call.
//!
//! Three things here are deliberately *types* rather than tag effects, because
//! each is a place where an executor could otherwise silently skip a step:
//!
//! * [`PendingCreditClaim`] consumes the stored preflight through the caller's
//!   grant table, so a credit cannot be claimed twice or from another table.
//! * [`PendingCqHeadAdvance`] exposes only a checked copyable command, and its
//!   `unsafe` consuming method is the sole way to convert the private claim —
//!   so the Release store is a precondition of progress, not a convention.
//! * [`PendingRoleRelease`] takes the retained lease and hands it to the ring
//!   state, so the affine role can neither be dropped nor released twice.
//!
//! Like every module under [`super`], a plan is an ordering and ownership model.
//! It owns no IRP, event, timer, CSQ entry, or reference.

use fsring_abi::{
    control::{
        ENTER_RESULT_V1_PREFIX_SIZE, NOTIFICATION_CREDIT_V1_SIZE, NotificationCreditV1, status,
    },
    validate::SessionIdentity,
};

use super::AdapterPlanError;
use crate::enter::{
    DrainPlan, EnterDecision, EnterError, PendingCompletion, PendingOutcome, PendingTerminalRight,
    RingEnterState, RoleLease,
};
use crate::grant::{
    ClaimedNotification, GrantError, GrantFault, GrantRange, GrantTable, HeadAdvancedNotification,
    NotifyPreflight, PreparedCreditClaim, RefreshedCredit, SlotArenaGeometry,
};
use crate::session::{FenceEffect, RoleError, SessionFence};

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// The ordered ENTER choreography
// ---------------------------------------------------------------------------

/// One native operation in an ENTER.
///
/// Not every ENTER performs every effect: a POLL never installs a pending IRP,
/// and a synchronous DRAIN never claims a terminal. The order among the effects
/// that *do* run is what this roster fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterEffect {
    SnapshotAndValidateInput,
    ValidateAndZeroOutput,
    AcquireRole,
    PollClearRecheck,
    PreflightCqAndCredit,
    ClaimFirstCommit,
    ClaimCredit,
    AdvanceCqHeadRelease,
    RefreshCredit,
    WriteExactOutput,
    AllocatePendingContext,
    InitializeEventTimerAndCsq,
    AcquireSessionAndFileReferences,
    MarkIrpPending,
    InsertCsq,
    ExchangeDispatchRundown,
    ReturnPending,
    ClaimTerminal,
    RemoveCsq,
    ReleaseSessionAndFileReferences,
    ReleaseRole,
    CompleteOnce,
}

/// The four shapes an admitted ENTER request can have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeEnterKind {
    Poll,
    WaitFinite,
    WaitInfinite,
    Drain,
}

/// Everything one ENTER is planned from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeEnterInput {
    pub kind: NativeEnterKind,
    pub ring_index: u32,
    pub output_capacity: usize,
    pub cq_budget: u32,
    pub timeout_ms: u32,
}

/// The closed outcome vocabulary a native executor may report.
///
/// The executor supplies *observations*; it never picks a branch. Every
/// branch below is taken by this module from the observation's own value.
#[allow(clippy::large_enum_variant)]
pub enum EnterEffectOutcome {
    Done,
    RoleAcquired(RoleLease),
    ReadinessObserved(EnterDecision),
    CqClassified(DrainPlan),
    TerminalClaimed(PendingOutcome),
    PendingInstalled,
    TerminalFinished(PendingCompletion),
}

/// The exact CQ-head store one drain iteration must perform.
///
/// Copyable and checked: it is a *command*, not a capability. The capability is
/// [`PendingCqHeadAdvance`] itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqHeadAdvance {
    pub ring_index: u32,
    pub observed_head: u64,
    pub next_head: u64,
}

/// Why a native ENTER operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterNativeFailure {
    Resource,
    Cancelled,
    Protocol,
    Completion,
    Fenced,
    InvalidState,
}

impl EnterNativeFailure {
    const fn status(self) -> i32 {
        match self {
            Self::Resource => status::INSUFFICIENT_RESOURCES,
            Self::Cancelled => status::CANCELLED,
            Self::Protocol | Self::Completion => status::INVALID_DEVICE_STATE,
            Self::Fenced | Self::InvalidState => status::INVALID_DEVICE_STATE,
        }
    }
}

/// One native action in a reverse-order unwind of a failed ENTER installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterRollbackEffect {
    RemoveCsq,
    ReleaseDispatchRundown,
    CancelTimerAndEvent,
    ReleaseSessionAndFileReferences,
    ReleaseRole,
    FreePendingContext,
    CompleteMarkedIrpOnce,
}

/// The frozen zero-information result every rolled-back ENTER returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnterAdapterResult {
    pub information: usize,
    pub status: i32,
}

/// The ordering state of one failed ENTER's unwind.
pub struct EnterRollbackPlan {
    next: u8,
    completed_prefix: u32,
    result: EnterAdapterResult,
    role: Option<RoleLease>,
}

pub struct PendingEnterRollbackEffect {
    plan: EnterRollbackPlan,
    effect: EnterRollbackEffect,
}

/// The one rollback step that must consume the affine lease.
pub struct PendingRollbackRoleRelease {
    plan: EnterRollbackPlan,
}

pub enum EnterRollbackProgress {
    Effect(PendingEnterRollbackEffect),
    ReleaseRole(PendingRollbackRoleRelease),
    Complete(EnterAdapterResult),
}

/// What a failure means, depending on whether a CQ commit already happened.
pub enum EnterFailurePlan {
    Rollback(EnterRollbackPlan),
    CompleteCommitted(EnterAdapterResult),
}

/// Where one ENTER is in its choreography.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnterPhase {
    Snapshot,
    ValidateOutput,
    AcquireRole,
    PollClearRecheck,
    PreflightCq,
    FirstCommit,
    ClaimCredit,
    AdvanceCqHead,
    RefreshCredit,
    WriteOutput,
    AllocatePending,
    InitEventTimerCsq,
    AcquireReferences,
    MarkPending,
    InsertCsq,
    ExchangeRundown,
    ReturnPending,
    Parked,
    ClaimTerminal,
    RemoveCsq,
    ReleaseReferences,
    ReleaseRole,
    CompleteOnce,
}

impl EnterPhase {
    const fn effect(self) -> Option<EnterEffect> {
        Some(match self {
            Self::Snapshot => EnterEffect::SnapshotAndValidateInput,
            Self::ValidateOutput => EnterEffect::ValidateAndZeroOutput,
            Self::AcquireRole => EnterEffect::AcquireRole,
            Self::PollClearRecheck => EnterEffect::PollClearRecheck,
            Self::PreflightCq => EnterEffect::PreflightCqAndCredit,
            Self::FirstCommit => EnterEffect::ClaimFirstCommit,
            Self::ClaimCredit => EnterEffect::ClaimCredit,
            Self::AdvanceCqHead => EnterEffect::AdvanceCqHeadRelease,
            Self::RefreshCredit => EnterEffect::RefreshCredit,
            Self::WriteOutput => EnterEffect::WriteExactOutput,
            Self::AllocatePending => EnterEffect::AllocatePendingContext,
            Self::InitEventTimerCsq => EnterEffect::InitializeEventTimerAndCsq,
            Self::AcquireReferences => EnterEffect::AcquireSessionAndFileReferences,
            Self::MarkPending => EnterEffect::MarkIrpPending,
            Self::InsertCsq => EnterEffect::InsertCsq,
            Self::ExchangeRundown => EnterEffect::ExchangeDispatchRundown,
            Self::ReturnPending => EnterEffect::ReturnPending,
            Self::ClaimTerminal => EnterEffect::ClaimTerminal,
            Self::RemoveCsq => EnterEffect::RemoveCsq,
            Self::ReleaseReferences => EnterEffect::ReleaseSessionAndFileReferences,
            Self::ReleaseRole => EnterEffect::ReleaseRole,
            Self::CompleteOnce => EnterEffect::CompleteOnce,
            Self::Parked => return None,
        })
    }

    /// How much of the installation prefix has completed once this phase is
    /// the *next* one. The rollback subset is derived from exactly this number.
    const fn installation_prefix(self) -> u32 {
        match self {
            Self::AllocatePending => 0,
            Self::InitEventTimerCsq => 1,
            Self::AcquireReferences => 2,
            Self::MarkPending => 3,
            Self::InsertCsq => 4,
            Self::ExchangeRundown => 5,
            Self::ReturnPending => 6,
            _ => 0,
        }
    }
}

/// The ordering and ownership state of one ENTER.
pub struct NativeEnterPlan<'g> {
    phase: EnterPhase,
    kind: NativeEnterKind,
    ring_index: u32,
    remaining_budget: u32,
    credit_count: u32,
    first_commit_won: bool,
    role: Option<RoleLease>,
    notify_preflight: Option<NotifyPreflight>,
    claimed_credit: Option<ClaimedNotification<'g>>,
    advanced_credit: Option<HeadAdvancedNotification<'g>>,
    cq_head_advance: Option<CqHeadAdvance>,
    completed_prefix: u32,
    status: i32,
}

/// A one-shot capability requesting exactly one ordinary native effect.
pub struct PendingEnterEffect<'g> {
    plan: NativeEnterPlan<'g>,
    effect: EnterEffect,
}

/// The credit-claim state: the preflight is spent through a grant table.
pub struct PendingCreditClaim<'g> {
    plan: NativeEnterPlan<'g>,
}

/// The CQ-head state: the store must happen before the claim converts.
pub struct PendingCqHeadAdvance<'g> {
    plan: NativeEnterPlan<'g>,
}

/// The refresh state: the advanced proof is spent into the output slot.
pub struct PendingCreditRefresh<'g> {
    plan: NativeEnterPlan<'g>,
}

/// The role-release state: the retained lease is handed back to its ring.
pub struct PendingRoleRelease<'g> {
    plan: NativeEnterPlan<'g>,
}

/// The parked state of a pending ENTER.
///
/// It privately owns the entire plan, including the affine [`RoleLease`], while
/// the IRP is pending. The native pending context stores this value, and only
/// the claimant that won the terminal CAS consumes it.
pub struct PendingAdapterResult<'g> {
    plan: NativeEnterPlan<'g>,
}

/// A WAIT parked before any grant borrow, so the plan is owned rather than
/// borrowed from a dispatch-thread grant table.
pub struct ParkedWaitInstall {
    plan: NativeEnterPlan<'static>,
}

/// What completing one parked WAIT produced.
#[must_use]
pub struct ParkedWaitOutcome {
    /// The exact status and information the arbitrated winner decided.
    pub result: EnterAdapterResult,
    /// The session-ring lease, if the parked plan was still holding one.
    ///
    /// It is handed back rather than released here so that the completion
    /// plan's own `ReleaseSqWaitRole` stage stays the only place a ring role is
    /// given up. The native worker takes the lease out of the parked plan
    /// before it arbitrates -- it has to, because a pass that fails to
    /// arbitrate must still release the ring -- so in production this is
    /// `None` and the worker's own `session_role` carries the lease. It is
    /// `Some` for a caller that hands over a plan still holding its role, and
    /// the field exists so that caller cannot lose it.
    pub role: Option<RoleLease>,
}

#[allow(clippy::large_enum_variant)]
pub enum EnterProgress<'g> {
    Effect(PendingEnterEffect<'g>),
    ClaimCredit(PendingCreditClaim<'g>),
    AdvanceCqHead(PendingCqHeadAdvance<'g>),
    RefreshCredit(PendingCreditRefresh<'g>),
    ReleaseRole(PendingRoleRelease<'g>),
    Complete(EnterAdapterResult),
    Pending(PendingAdapterResult<'g>),
}

/// The checked ENTER result length: the frozen prefix plus one descriptor per
/// returned credit. Never supplied by an executor.
fn information_for(credit_count: u32) -> Result<usize, AdapterPlanError> {
    let tail = credit_count
        .checked_mul(NOTIFICATION_CREDIT_V1_SIZE)
        .ok_or(AdapterPlanError::ArithmeticOverflow)?;
    let total = ENTER_RESULT_V1_PREFIX_SIZE
        .checked_add(tail)
        .ok_or(AdapterPlanError::ArithmeticOverflow)?;
    usize::try_from(total).map_err(|_| AdapterPlanError::ArithmeticOverflow)
}

const fn completion_status(completion: PendingCompletion) -> i32 {
    match completion {
        // A timed-out WAIT is a successful ENTER that found no work; the result
        // body, not the status, says so.
        PendingCompletion::Ready
        | PendingCompletion::TimedOut
        | PendingCompletion::SuccessAfterCommit => status::SUCCESS,
        PendingCompletion::Cancelled => status::CANCELLED,
        PendingCompletion::Fenced | PendingCompletion::Unloaded => status::INVALID_DEVICE_STATE,
    }
}

impl<'g> NativeEnterPlan<'g> {
    /// Begin one ENTER.
    ///
    /// The request shape is checked against the frozen budget and timeout rules
    /// before the first effect, so a malformed request never takes a ring role.
    pub fn begin(input: NativeEnterInput) -> Result<EnterProgress<'g>, AdapterPlanError> {
        let NativeEnterInput {
            kind,
            ring_index,
            output_capacity,
            cq_budget,
            timeout_ms,
        } = input;

        match kind {
            NativeEnterKind::Drain => {
                if cq_budget == 0 || cq_budget > fsring_abi::MAX_ENTER_CQ_BUDGET || timeout_ms != 0
                {
                    return Err(AdapterPlanError::InvalidInput);
                }
            }
            NativeEnterKind::Poll => {
                if cq_budget != 0 || timeout_ms != 0 {
                    return Err(AdapterPlanError::InvalidInput);
                }
            }
            // 02-transport: `timeout_ms = 0` polls, `0xffffffff` waits
            // indefinitely but cancel-safely, and every other value is a
            // relative millisecond timeout. A WAIT whose timeout is zero is
            // therefore a poll, and one whose timeout is the sentinel must
            // never be answered TIMED_OUT — which is exactly what
            // `enter::build_empty_result` already enforces.
            NativeEnterKind::WaitFinite => {
                if cq_budget != 0 || timeout_ms == 0 || timeout_ms == u32::MAX {
                    return Err(AdapterPlanError::InvalidInput);
                }
            }
            NativeEnterKind::WaitInfinite => {
                if cq_budget != 0 || timeout_ms != u32::MAX {
                    return Err(AdapterPlanError::InvalidInput);
                }
            }
        }
        // The zero-credit result is the smallest an ENTER can return, so a
        // buffer that cannot hold it is refused before anything is acquired.
        if output_capacity < information_for(0)? {
            return Err(AdapterPlanError::Capacity);
        }

        Ok(EnterProgress::Effect(PendingEnterEffect {
            plan: Self {
                phase: EnterPhase::Snapshot,
                kind,
                ring_index,
                remaining_budget: cq_budget,
                credit_count: 0,
                first_commit_won: false,
                role: None,
                notify_preflight: None,
                claimed_credit: None,
                advanced_credit: None,
                cq_head_advance: None,
                completed_prefix: 0,
                status: status::SUCCESS,
            },
            effect: EnterEffect::SnapshotAndValidateInput,
        }))
    }

    /// Package the current phase as the caller-visible progress value.
    fn progress(self) -> Result<EnterProgress<'g>, AdapterPlanError> {
        Ok(match self.phase {
            EnterPhase::ClaimCredit => {
                EnterProgress::ClaimCredit(PendingCreditClaim { plan: self })
            }
            EnterPhase::AdvanceCqHead => {
                EnterProgress::AdvanceCqHead(PendingCqHeadAdvance { plan: self })
            }
            EnterPhase::RefreshCredit => {
                EnterProgress::RefreshCredit(PendingCreditRefresh { plan: self })
            }
            EnterPhase::ReleaseRole => {
                EnterProgress::ReleaseRole(PendingRoleRelease { plan: self })
            }
            EnterPhase::Parked => EnterProgress::Pending(PendingAdapterResult { plan: self }),
            phase => {
                let effect = phase.effect().ok_or(AdapterPlanError::InvalidTransition)?;
                EnterProgress::Effect(PendingEnterEffect { plan: self, effect })
            }
        })
    }

    fn finish(self) -> Result<EnterProgress<'g>, AdapterPlanError> {
        let information = information_for(self.credit_count)?;
        Ok(EnterProgress::Complete(EnterAdapterResult {
            information,
            status: self.status,
        }))
    }
}

impl<'g> PendingEnterEffect<'g> {
    pub const fn effect(&self) -> EnterEffect {
        self.effect
    }

    /// Consume this capability after its native effect completed.
    pub fn succeeded(
        self,
        outcome: EnterEffectOutcome,
    ) -> Result<EnterProgress<'g>, AdapterPlanError> {
        let Self { mut plan, effect } = self;

        match (effect, outcome) {
            (EnterEffect::SnapshotAndValidateInput, EnterEffectOutcome::Done) => {
                plan.phase = EnterPhase::ValidateOutput;
            }
            (EnterEffect::ValidateAndZeroOutput, EnterEffectOutcome::Done) => {
                plan.phase = EnterPhase::AcquireRole;
            }
            (EnterEffect::AcquireRole, EnterEffectOutcome::RoleAcquired(lease)) => {
                if plan.role.is_some() {
                    return Err(AdapterPlanError::InvalidTransition);
                }
                plan.role = Some(lease);
                plan.phase = EnterPhase::PollClearRecheck;
            }
            (EnterEffect::PollClearRecheck, EnterEffectOutcome::ReadinessObserved(decision)) => {
                plan.phase = readiness_phase(plan.kind, decision)?;
            }
            (EnterEffect::PreflightCqAndCredit, EnterEffectOutcome::CqClassified(classified)) => {
                plan.phase = classify_phase(&mut plan, classified)?;
            }
            (EnterEffect::ClaimFirstCommit, EnterEffectOutcome::Done) => {
                if plan.notify_preflight.is_none() {
                    return Err(AdapterPlanError::InvalidTransition);
                }
                plan.phase = EnterPhase::ClaimCredit;
            }
            (EnterEffect::WriteExactOutput, EnterEffectOutcome::Done) => {
                plan.phase = EnterPhase::ReleaseRole;
            }
            (EnterEffect::AllocatePendingContext, EnterEffectOutcome::Done) => {
                plan.completed_prefix = 1;
                plan.phase = EnterPhase::InitEventTimerCsq;
            }
            (EnterEffect::InitializeEventTimerAndCsq, EnterEffectOutcome::Done) => {
                plan.completed_prefix = 2;
                plan.phase = EnterPhase::AcquireReferences;
            }
            (EnterEffect::AcquireSessionAndFileReferences, EnterEffectOutcome::Done) => {
                plan.completed_prefix = 3;
                plan.phase = EnterPhase::MarkPending;
            }
            (EnterEffect::MarkIrpPending, EnterEffectOutcome::Done) => {
                plan.completed_prefix = 4;
                plan.phase = EnterPhase::InsertCsq;
            }
            (EnterEffect::InsertCsq, EnterEffectOutcome::Done) => {
                plan.completed_prefix = 5;
                plan.phase = EnterPhase::ExchangeRundown;
            }
            (EnterEffect::ExchangeDispatchRundown, EnterEffectOutcome::Done) => {
                plan.completed_prefix = 6;
                plan.phase = EnterPhase::ReturnPending;
            }
            (EnterEffect::ReturnPending, EnterEffectOutcome::PendingInstalled) => {
                plan.phase = EnterPhase::Parked;
            }
            (EnterEffect::ClaimTerminal, EnterEffectOutcome::TerminalClaimed(outcome)) => {
                match outcome {
                    PendingOutcome::Won(_) => {
                        plan.phase = EnterPhase::RemoveCsq;
                    }
                    // A claimant that lost the terminal CAS never owns the
                    // completion, so it cannot be the one driving this plan:
                    // the affine parked value went to the winner.
                    PendingOutcome::Lost { .. } => {
                        return Err(AdapterPlanError::InvalidTransition);
                    }
                }
            }
            (EnterEffect::RemoveCsq, EnterEffectOutcome::Done) => {
                plan.phase = EnterPhase::ReleaseReferences;
            }
            (EnterEffect::ReleaseSessionAndFileReferences, EnterEffectOutcome::Done) => {
                plan.phase = EnterPhase::ReleaseRole;
            }
            (EnterEffect::CompleteOnce, EnterEffectOutcome::TerminalFinished(completion)) => {
                if plan.first_commit_won {
                    // A committed CQ advance cannot be undone, so a cancel or
                    // timeout that arrives after it loses.
                    plan.status = status::SUCCESS;
                } else {
                    plan.status = completion_status(completion);
                }
                return plan.finish();
            }
            _ => return Err(AdapterPlanError::InvalidInput),
        }

        if matches!(plan.phase, EnterPhase::CompleteOnce) && plan.role.is_some() {
            return Err(AdapterPlanError::InvalidTransition);
        }
        plan.progress()
    }

    /// Consume a failed or cancelled native effect.
    pub fn failed(self, reason: EnterNativeFailure) -> EnterFailurePlan {
        let Self { plan, effect: _ } = self;
        plan.into_failure(reason)
    }
}

impl NativeEnterPlan<'_> {
    fn into_failure(mut self, reason: EnterNativeFailure) -> EnterFailurePlan {
        if self.first_commit_won {
            // After the first committed CQ head advance the daemon has already
            // consumed work; the ENTER completes successfully.
            self.status = status::SUCCESS;
            let information =
                information_for(self.credit_count).unwrap_or(ENTER_RESULT_V1_PREFIX_SIZE as usize);
            return EnterFailurePlan::CompleteCommitted(EnterAdapterResult {
                information,
                status: status::SUCCESS,
            });
        }
        let prefix = self.phase.installation_prefix();
        EnterFailurePlan::Rollback(EnterRollbackPlan {
            next: 0,
            completed_prefix: prefix,
            result: EnterAdapterResult {
                information: 0,
                status: reason.status(),
            },
            role: self.role.take(),
        })
    }
}

/// Which phase a readiness observation leads to.
///
/// A POLL and a DRAIN can never park: the frozen request shape gives them no
/// timeout, so `Pending` from either is a contract violation rather than a
/// state.
fn readiness_phase(
    kind: NativeEnterKind,
    decision: EnterDecision,
) -> Result<EnterPhase, AdapterPlanError> {
    Ok(match (kind, decision) {
        (NativeEnterKind::Drain, EnterDecision::Ready | EnterDecision::Empty) => {
            EnterPhase::PreflightCq
        }
        (NativeEnterKind::Poll, EnterDecision::Ready | EnterDecision::Empty) => {
            EnterPhase::WriteOutput
        }
        (NativeEnterKind::WaitFinite | NativeEnterKind::WaitInfinite, EnterDecision::Ready) => {
            EnterPhase::WriteOutput
        }
        (
            NativeEnterKind::WaitFinite | NativeEnterKind::WaitInfinite,
            EnterDecision::Pending | EnterDecision::Empty,
        ) => EnterPhase::AllocatePending,
        (NativeEnterKind::WaitFinite, EnterDecision::TimedOut) => EnterPhase::WriteOutput,
        (
            NativeEnterKind::Poll | NativeEnterKind::Drain,
            EnterDecision::Pending | EnterDecision::TimedOut,
        )
        | (NativeEnterKind::WaitInfinite, EnterDecision::TimedOut) => {
            return Err(AdapterPlanError::InvalidTransition);
        }
    })
}

/// Which phase a CQ classification leads to.
fn classify_phase(
    plan: &mut NativeEnterPlan<'_>,
    classified: DrainPlan,
) -> Result<EnterPhase, AdapterPlanError> {
    Ok(match classified {
        DrainPlan::Notify(preflight) => {
            if plan.remaining_budget == 0 {
                // A notify classified with no budget left would drain past the
                // daemon's own bound.
                return Err(AdapterPlanError::InvalidTransition);
            }
            plan.notify_preflight = Some(preflight);
            // The affine first-commit claim happens once per ENTER, before any
            // credit is spent: from that point a cancellation loses.
            if plan.credit_count == 0 {
                EnterPhase::FirstCommit
            } else {
                EnterPhase::ClaimCredit
            }
        }
        // Nothing to take this round; the result reports the reason.
        DrainPlan::Empty | DrainPlan::Contended | DrainPlan::NotifyBlocked => {
            EnterPhase::WriteOutput
        }
        // The credit generation is spent: zero output for it and, critically,
        // no CQ-head advance.
        DrainPlan::GenerationExhausted => EnterPhase::WriteOutput,
        DrainPlan::ProtocolAbort | DrainPlan::ProtocolFault => {
            plan.status = status::INVALID_DEVICE_STATE;
            EnterPhase::WriteOutput
        }
        DrainPlan::CompletionFault => {
            plan.status = status::INVALID_DEVICE_STATE;
            EnterPhase::WriteOutput
        }
    })
}

impl<'g> PendingCreditClaim<'g> {
    pub const fn effect(&self) -> EnterEffect {
        EnterEffect::ClaimCredit
    }

    /// Spend the stored preflight through the caller's grant table.
    ///
    /// The preflight is taken out of the plan here, so a second claim is not
    /// representable.
    pub fn claim(
        self,
        grants: &'g mut GrantTable<'_>,
    ) -> Result<EnterProgress<'g>, EnterFailurePlan> {
        let Self { mut plan } = self;
        let Some(preflight) = plan.notify_preflight.take() else {
            return Err(plan.into_failure(EnterNativeFailure::InvalidState));
        };
        // The head command is expressed as *this ENTER's* drain ordinal: the
        // number of CQ records it has already consumed. The pure core cannot
        // read the ring's head, and pretending otherwise would put a
        // daemon-writable number inside the plan. The executor adds its own
        // observed base, and the capability below is what forces the Release
        // store to happen before the claim converts.
        let ring_index = plan.ring_index;
        let observed_head = u64::from(plan.credit_count);
        let Ok(claim) = grants.claim_notify(preflight) else {
            return Err(plan.into_failure(EnterNativeFailure::Protocol));
        };
        let Some(next_head) = observed_head.checked_add(1) else {
            return Err(plan.into_failure(EnterNativeFailure::Protocol));
        };
        plan.cq_head_advance = Some(CqHeadAdvance {
            ring_index,
            observed_head,
            next_head,
        });
        plan.claimed_credit = Some(claim);
        plan.phase = EnterPhase::AdvanceCqHead;
        plan.progress().map_err(|_| {
            EnterFailurePlan::Rollback(EnterRollbackPlan {
                next: 0,
                completed_prefix: 0,
                result: EnterAdapterResult {
                    information: 0,
                    status: status::INVALID_DEVICE_STATE,
                },
                role: None,
            })
        })
    }
}

impl<'g> PendingCqHeadAdvance<'g> {
    pub const fn effect(&self) -> EnterEffect {
        EnterEffect::AdvanceCqHeadRelease
    }

    /// The exact store the executor must perform. A copyable command, so
    /// reading it grants nothing.
    pub fn command(&self) -> CqHeadAdvance {
        self.plan.cq_head_advance.unwrap_or(CqHeadAdvance {
            ring_index: 0,
            observed_head: 0,
            next_head: 0,
        })
    }

    /// Convert the private claim after the Release store.
    ///
    /// # Safety
    /// The caller performed this exact command's CQ-head store with Release
    /// ordering exactly once immediately before this call.
    pub unsafe fn completed_release(self) -> EnterProgress<'g> {
        let Self { mut plan } = self;
        // This is the first committed CQ advance: from here a cancellation
        // loses, because the daemon has already been handed the entry.
        plan.first_commit_won = true;
        plan.advanced_credit = plan.claimed_credit.take().map(|claim| {
            // SAFETY: forwarded verbatim from this function's own contract —
            // the caller performed the matching Release store exactly once.
            unsafe { claim.after_release_head_advance() }
        });
        plan.phase = EnterPhase::RefreshCredit;
        PendingCreditRefreshProgress::from(plan)
    }
}

/// Local helper so `completed_release` is total: the refresh phase always maps
/// to its own capability.
struct PendingCreditRefreshProgress;

impl PendingCreditRefreshProgress {
    fn from(plan: NativeEnterPlan<'_>) -> EnterProgress<'_> {
        EnterProgress::RefreshCredit(PendingCreditRefresh { plan })
    }
}

impl<'g> PendingCreditRefresh<'g> {
    pub const fn effect(&self) -> EnterEffect {
        EnterEffect::RefreshCredit
    }

    /// Spend the advanced proof into the already-preflighted output slot.
    pub fn refresh(self, output: &mut NotificationCreditV1) -> EnterProgress<'g> {
        let Self { mut plan } = self;
        match plan.advanced_credit.take() {
            Some(advanced) => {
                let _ = advanced.refresh(output);
                plan.credit_count = plan.credit_count.saturating_add(1);
                plan.remaining_budget = plan.remaining_budget.saturating_sub(1);
            }
            None => {
                // Unreachable: `completed_release` always stores the proof.
                plan.status = status::INVALID_DEVICE_STATE;
            }
        }
        plan.phase = if plan.remaining_budget > 0 {
            EnterPhase::PreflightCq
        } else {
            EnterPhase::WriteOutput
        };
        match plan.progress() {
            Ok(progress) => progress,
            Err(_) => EnterProgress::Complete(EnterAdapterResult {
                information: ENTER_RESULT_V1_PREFIX_SIZE as usize,
                status: status::INVALID_DEVICE_STATE,
            }),
        }
    }
}

impl<'g> PendingRoleRelease<'g> {
    pub const fn effect(&self) -> EnterEffect {
        EnterEffect::ReleaseRole
    }

    /// Hand the retained lease back to its ring.
    ///
    /// A mismatch restores the lease and returns this capability, so the role
    /// can neither leak nor be released against the wrong ring.
    #[allow(clippy::result_large_err)]
    pub fn release(
        self,
        roles: &mut RingEnterState,
    ) -> Result<EnterProgress<'g>, (EnterError, Self)> {
        let Self { mut plan } = self;
        let Some(lease) = plan.role.take() else {
            return Err((EnterError::Fenced, Self { plan }));
        };
        match roles.release_role(lease) {
            Ok(()) => {
                plan.phase = if plan.completed_prefix > 0 {
                    EnterPhase::CompleteOnce
                } else {
                    // A synchronous ENTER has no pending terminal to finish.
                    return plan.finish().map_err(|error| {
                        let _ = error;
                        (
                            EnterError::Fenced,
                            Self {
                                plan: NativeEnterPlan::poisoned(),
                            },
                        )
                    });
                };
                plan.progress().map_err(|_| {
                    (
                        EnterError::Fenced,
                        Self {
                            plan: NativeEnterPlan::poisoned(),
                        },
                    )
                })
            }
            Err((error, lease)) => {
                plan.role = Some(lease);
                Err((error, Self { plan }))
            }
        }
    }
}

impl NativeEnterPlan<'_> {
    /// A plan that can only report the fail-stop state.
    ///
    /// Reached only from a transition the type system cannot express as
    /// unreachable; it owns no lease, so nothing can be lost through it.
    fn poisoned() -> Self {
        Self {
            phase: EnterPhase::WriteOutput,
            kind: NativeEnterKind::Poll,
            ring_index: 0,
            remaining_budget: 0,
            credit_count: 0,
            first_commit_won: false,
            role: None,
            notify_preflight: None,
            claimed_credit: None,
            advanced_credit: None,
            cq_head_advance: None,
            completed_prefix: 0,
            status: status::INVALID_DEVICE_STATE,
        }
    }
}

impl<'g> PendingAdapterResult<'g> {
    /// The terminal winner resumes the parked plan.
    pub fn resume(self) -> EnterProgress<'g> {
        // `Drop` forbids moving `plan` out of `self`. The resume consumes the
        // parked value into the next progress arm, so the destructor must not
        // run.
        let mut plan = {
            let this = core::mem::ManuallyDrop::new(self);
            unsafe { core::ptr::read(&this.plan) }
        };
        plan.phase = EnterPhase::ClaimTerminal;
        match plan.progress() {
            Ok(progress) => progress,
            Err(_) => EnterProgress::Complete(EnterAdapterResult {
                information: ENTER_RESULT_V1_PREFIX_SIZE as usize,
                status: status::INVALID_DEVICE_STATE,
            }),
        }
    }

    /// Take the ring role the parked plan still owns.
    ///
    /// Extracting does not release the ring: `sq_owner` stays occupied until
    /// `RingEnterState::release_role`. The native slot stores this lease so
    /// dropping the parked plan cannot silently leak the waiter.
    pub fn into_held_role(mut self) -> RoleLease {
        match self.plan.role.take() {
            Some(lease) => lease,
            None => unreachable!("a parked WAIT always acquired a role"),
        }
    }

    /// Keep the parked plan. A WAIT that reached `Pending` has no grant-table
    /// borrow, so the native CSQ slot can own it until the terminal winner
    /// resumes.
    pub fn into_owned_wait(self) -> ParkedWaitInstall {
        if self.plan.claimed_credit.is_some() || self.plan.advanced_credit.is_some() {
            unreachable!("WAIT parks before any grant borrow");
        }
        let this = core::mem::ManuallyDrop::new(self);
        let plan = unsafe { core::ptr::read(&this.plan) };
        let plan: NativeEnterPlan<'static> = unsafe { core::mem::transmute(plan) };
        ParkedWaitInstall { plan }
    }
}

impl ParkedWaitInstall {
    /// The SQ lease the parked WAIT still holds.
    pub fn role(&self) -> Option<&RoleLease> {
        self.plan.role.as_ref()
    }

    /// Take the SQ lease without resuming. The worker still owns the plan.
    pub fn take_role(&mut self) -> Option<RoleLease> {
        self.plan.role.take()
    }

    /// Resume the parked plan from the terminal-claim phase.
    pub fn resume(self) -> EnterProgress<'static> {
        PendingAdapterResult { plan: self.plan }.resume()
    }

    /// Complete this parked WAIT with the reason its arbitration decided.
    ///
    /// Two wakes can be stored before the worker runs, so an *observed* wake is
    /// not an arbitration. `PendingTerminalRight` is the only thing that is: it
    /// exists only downstream of `PendingIrpArbiter::contend`, it is affine and
    /// unforgeable, and consuming it is the sole way to learn which claimant won
    /// the terminal CAS. Both routes out of a parked WAIT -- this one, and
    /// `resume` into the `ClaimTerminal` effect -- consume that right, so a
    /// worker cannot deliver the status of a wake that lost.
    ///
    /// The lease travels out rather than being released here: the completion
    /// plan's `ReleaseSqWaitRole` stage stays the sole release site.
    ///
    /// A parked WAIT holds no grant borrow and claimed no credit, so the result
    /// is the zero-credit prefix for every winner. A readiness winner tells the
    /// daemon the SQ is ready and the daemon re-ENTERs to drain it; delivering
    /// credits on the wake itself would need the SQ->CQ resume bridge, which no
    /// production path binds.
    pub fn finish_arbitrated(self, right: PendingTerminalRight) -> ParkedWaitOutcome {
        let completion = right.finish();
        let mut plan = self.plan;
        // The role leaves before the completion runs, which is the invariant
        // `CompleteOnce` itself enforces: a plan that still holds the ring
        // cannot complete.
        let role = plan.role.take();
        plan.phase = EnterPhase::CompleteOnce;
        let progress = PendingEnterEffect {
            plan,
            effect: EnterEffect::CompleteOnce,
        }
        .succeeded(EnterEffectOutcome::TerminalFinished(completion));
        let EnterProgress::Complete(mut result) = progress
            .unwrap_or_else(|_| unreachable!("a parked WAIT that released its role completes"))
        else {
            unreachable!("CompleteOnce is terminal")
        };
        if result.status != status::SUCCESS {
            // A cancelled or fenced IRP copied nothing back. Reporting the
            // prefix size would tell the daemon to read bytes the completion
            // never wrote.
            result.information = 0;
        }
        ParkedWaitOutcome { result, role }
    }
}

impl Drop for PendingAdapterResult<'_> {
    fn drop(&mut self) {
        if self.plan.role.is_some() {
            panic!("parked ENTER dropped while still holding the ring role");
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

/// The full reverse installation order. A rollback runs the suffix its
/// completed prefix earned, and nothing else.
const ROLLBACK_ORDER: [EnterRollbackEffect; 7] = [
    EnterRollbackEffect::ReleaseDispatchRundown,
    EnterRollbackEffect::RemoveCsq,
    EnterRollbackEffect::CompleteMarkedIrpOnce,
    EnterRollbackEffect::ReleaseSessionAndFileReferences,
    EnterRollbackEffect::CancelTimerAndEvent,
    EnterRollbackEffect::FreePendingContext,
    EnterRollbackEffect::ReleaseRole,
];

/// The completed installation prefix each reverse step requires.
const ROLLBACK_REQUIRES: [u32; 7] = [6, 5, 4, 3, 2, 1, 0];

impl EnterRollbackPlan {
    /// Yield the next unwind step, or the frozen zero-information result.
    pub fn next(self) -> EnterRollbackProgress {
        let mut cursor = usize::from(self.next);
        while let (Some(effect), Some(required)) =
            (ROLLBACK_ORDER.get(cursor), ROLLBACK_REQUIRES.get(cursor))
        {
            if self.completed_prefix >= *required {
                let effect = *effect;
                let mut plan = self;
                plan.next = match u8::try_from(cursor) {
                    Ok(value) => value,
                    Err(_) => return EnterRollbackProgress::Complete(plan.result),
                };
                return if matches!(effect, EnterRollbackEffect::ReleaseRole) {
                    if plan.role.is_none() {
                        // No lease was ever taken, so there is nothing to
                        // release and the step is skipped rather than faked.
                        plan.next = plan.next.saturating_add(1);
                        plan.next()
                    } else {
                        EnterRollbackProgress::ReleaseRole(PendingRollbackRoleRelease { plan })
                    }
                } else {
                    EnterRollbackProgress::Effect(PendingEnterRollbackEffect { plan, effect })
                };
            }
            cursor = cursor.saturating_add(1);
        }
        EnterRollbackProgress::Complete(self.result)
    }
}

impl PendingEnterRollbackEffect {
    pub const fn effect(&self) -> EnterRollbackEffect {
        self.effect
    }

    /// This step completed.
    pub fn succeeded(self) -> EnterRollbackProgress {
        self.advance()
    }

    /// This step failed.
    ///
    /// Ordinary native cleanup failure records evidence and continues: the
    /// remaining resources are no less owned for one release having failed.
    pub fn failed(self) -> EnterRollbackProgress {
        self.advance()
    }

    fn advance(self) -> EnterRollbackProgress {
        let Self {
            mut plan,
            effect: _,
        } = self;
        plan.next = plan.next.saturating_add(1);
        plan.next()
    }
}

impl PendingRollbackRoleRelease {
    pub const fn effect(&self) -> EnterRollbackEffect {
        EnterRollbackEffect::ReleaseRole
    }

    /// Hand the retained lease back during an unwind.
    ///
    /// An impossible ring mismatch preserves the whole continuation *and* the
    /// lease rather than losing authority over either.
    #[allow(clippy::result_large_err)]
    pub fn release(
        self,
        roles: &mut RingEnterState,
    ) -> Result<EnterRollbackProgress, (EnterError, Self)> {
        let Self { mut plan } = self;
        let Some(lease) = plan.role.take() else {
            return Err((EnterError::Fenced, Self { plan }));
        };
        match roles.release_role(lease) {
            Ok(()) => {
                plan.next = plan.next.saturating_add(1);
                Ok(plan.next())
            }
            Err((error, lease)) => {
                plan.role = Some(lease);
                Err((error, Self { plan }))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The six-stage fence
// ---------------------------------------------------------------------------

/// The native execution of `session::SessionFence`.
///
/// It neither allocates nor retries. A failed cleanup effect records evidence
/// and the remaining bounded effects still run: stopping halfway through a
/// teardown is how a mapping outlives its session.
pub struct FenceExecutionPlan {
    core: Option<SessionFence>,
    stage_effects: &'static [FenceEffect],
    next_effect: usize,
}

pub struct PendingFenceEffect {
    plan: FenceExecutionPlan,
    effect: FenceEffect,
}

pub enum FenceProgress {
    Effect(PendingFenceEffect),
    Complete,
}

impl FenceExecutionPlan {
    /// Build the fence for one session. Allocation-free, so the process-loss
    /// callback can construct it from preallocated state.
    pub const fn begin(identity: SessionIdentity) -> Self {
        Self {
            core: Some(SessionFence::begin(identity)),
            stage_effects: &[],
            next_effect: 0,
        }
    }

    /// Yield the next effect, advancing a stage when the current one is spent.
    pub fn next(mut self) -> FenceProgress {
        loop {
            if let Some(effect) = self.stage_effects.get(self.next_effect).copied() {
                self.next_effect = self.next_effect.saturating_add(1);
                return FenceProgress::Effect(PendingFenceEffect { plan: self, effect });
            }
            let Some(fence) = self.core.take() else {
                return FenceProgress::Complete;
            };
            let advance = fence.advance();
            self.stage_effects = advance.effects();
            self.next_effect = 0;
            self.core = advance.into_next();
            if self.stage_effects.is_empty() && self.core.is_none() {
                return FenceProgress::Complete;
            }
        }
    }
}

impl PendingFenceEffect {
    pub const fn effect(&self) -> FenceEffect {
        self.effect
    }

    pub fn succeeded(self) -> FenceProgress {
        self.plan.next()
    }

    /// A failed teardown step is recorded, not obeyed: the fence continues.
    pub fn failed(self) -> FenceProgress {
        self.plan.next()
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.4: the plan-side role bind, the CQ mutation witness, and the
// exact-IRP cancel observation
// ---------------------------------------------------------------------------
//
// Staged beside the predecessor `NativeEnterPlan` rather than inside it. That
// plan carries a `'g` lifetime and the predecessor `RoleLease` through an
// eight-phase machine with its own test file, and a half-converted machine
// would have two role models live at once -- the exact thing the R4
// authorities exist to prevent.
//
// NOT converted. This used to call the conversion "Task 19's cutover"; Task 19
// closed without making it. Production ENTER on this tree still runs
// `NativeEnterPlan::begin` (`fsring-fsd`'s `execute_enter`), and
// `R4EnterPlan` has no `fsring-fsd` reference beyond a doc comment
// (round-17 evidence E1).

use crate::enter::{
    AcquiredCqConsumer, AcquiredSqWait, AuthenticatedCqResume, EnterCommitTracker,
    EnterExecutionBrand, EnterExecutionDomain, IrpObservation, PendingEnter, PendingSlotState,
};
use crate::session::{PendingError, PendingInstallId, TerminalRequest};

/// One R4 execution as the native side sees it.
///
/// It owns the tracker and never lends it out. `fsring-fsd` gets decisions and
/// permits, never the tracker itself: a sibling crate holding the tracker could
/// record a commit for a mutation core never arbitrated.
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct R4EnterPlan {
    execution: EnterExecutionBrand,
    tracker: EnterCommitTracker,
    terminal: Option<PendingEnter>,
    irp: Option<IrpObservation>,
}

/// Proof that one typed CQ packet is about to mutate.
///
/// The lifetime binds it to the packet it came from, and it is neither `Clone`
/// nor `Copy`, so one packet authorises one mutation. There is no public
/// constructor: production minting belongs inside the `impl` of the typed
/// packets Tasks 20 and 21 add, and Task 14 provides only a `#[cfg(test)]`
/// factory so the arbitration boundary can be tested without a raw-token API.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct CqMutationWitness<'packet> {
    execution: EnterExecutionBrand,
    identity: CqPacketIdentity,
    packet: core::marker::PhantomData<&'packet ()>,
}

/// Which CQ entry one witness or permit speaks for.
///
/// The execution alone is not enough, and the gap is not theoretical: a drain
/// loop keeps ring, invocation and domain constant across every iteration, so a
/// permit arbitrated for entry N would otherwise satisfy every check entry
/// N+1's preparation makes. The head store for N+1 would then be authorised by
/// an arbitration performed for N -- skipping exactly the cancel-spin decision
/// the four-stage split exists to force.
///
/// The sequence and the next head together, not either alone: the sequence
/// names the producer's cell and the next head names the store that would
/// account for it, and a lane that checked only one could still be handed a
/// permit minted against the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqPacketIdentity {
    sequence: u64,
    next_head: u64,
}

impl CqPacketIdentity {
    pub(crate) const fn new(sequence: u64, next_head: u64) -> Self {
        Self {
            sequence,
            next_head,
        }
    }
}

/// The one permit an arbitrated mutation carries.
///
/// **It borrows the tracker, and that is the correction this type exists to
/// carry.** Arbitration used to call `record_commit` itself, so a *refused*
/// preparation left the plan marked committed with zero mutations performed --
/// and cancellation precedence is decided by exactly that bit, so a cancel that
/// should have won would lose to a commit that never happened.
///
/// The borrow does two things at once. It moves the transition to
/// [`Self::record_first_mutation`], which only an infallible commit suffix
/// calls; and it makes the plan unusable while a permit is outstanding, so a
/// second arbitration cannot be in flight beside the first. That second
/// property is why the borrow is the right shape rather than a flag: the
/// exclusivity is the borrow checker's, not a convention.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct EnterMutationPermit<'tracker> {
    execution: EnterExecutionBrand,
    identity: CqPacketIdentity,
    tracker: &'tracker mut EnterCommitTracker,
}

/// A cancel bound to one exact IRP on one exact execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelObservation {
    execution: EnterExecutionBrand,
    irp: IrpObservation,
}

// The lifetime is only needless without `cfg(test)`: `for_test_packet` names
// it to bind a witness to a borrowed packet, which is the whole point of
// the type.
#[allow(clippy::needless_lifetimes)]
impl<'packet> CqMutationWitness<'packet> {
    /// Mint a witness for a test packet.
    ///
    /// Refuses an SQ-wait execution outright. The CQ arbitration boundary is
    /// the only thing this authorises, and an SQ execution reaching it would
    /// mean the domain split had been undone at exactly the point it matters.
    #[cfg(test)]
    pub(crate) fn for_test_packet(
        execution: EnterExecutionBrand,
        packet: &'packet (),
    ) -> Result<Self, PendingError> {
        Self::for_test_packet_at(execution, packet, CqPacketIdentity::new(0, 0))
    }

    /// The same factory, for a test that needs to name *which* entry.
    #[cfg(test)]
    pub(crate) fn for_test_packet_at(
        execution: EnterExecutionBrand,
        _packet: &'packet (),
        identity: CqPacketIdentity,
    ) -> Result<Self, PendingError> {
        if execution.domain() != EnterExecutionDomain::CqConsumer {
            return Err(PendingError::WrongExecutionDomain);
        }
        Ok(Self {
            execution,
            identity,
            packet: core::marker::PhantomData,
        })
    }

    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    pub(crate) const fn identity(&self) -> CqPacketIdentity {
        self.identity
    }
}

#[allow(dead_code)]
impl EnterMutationPermit<'_> {
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    pub(crate) const fn identity(&self) -> CqPacketIdentity {
        self.identity
    }

    /// Record that the first real mutation of this execution has happened.
    ///
    /// Consuming, and called only from an infallible commit suffix: the whole
    /// point of moving the transition off arbitration is that a refusal must
    /// leave the tracker untouched, and a permit that could record twice would
    /// be a second arbitration wearing the first one's clothes.
    pub(crate) fn record_first_mutation(self) {
        self.tracker.record_commit();
    }
}

#[allow(dead_code)]
impl CancelObservation {
    pub(crate) const fn irp(&self) -> IrpObservation {
        self.irp
    }

    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }
}

impl R4EnterPlan {
    /// Bind an SQ-wait acquisition, consuming the whole aggregate.
    ///
    /// By value, so one aggregate binds one plan: a second bind needs a second
    /// aggregate, and `RingEnterState` mints one per acquisition.
    pub fn bind_sq_wait(acquired: AcquiredSqWait) -> Self {
        let execution = acquired.execution();
        let (lease, tracker, terminal) = acquired.into_plan_parts();
        // The lease is consumed into the plan's identity rather than stored:
        // the plan speaks for the execution, and releasing the role is the
        // completion sequence's business, not this boundary's.
        let _ = lease;
        Self {
            execution,
            tracker,
            terminal: Some(terminal),
            irp: None,
        }
    }

    /// Bind a CQ-consumer acquisition, consuming the whole aggregate.
    pub fn bind_cq_consumer(acquired: AcquiredCqConsumer) -> Self {
        let execution = acquired.execution();
        let (token, tracker) = acquired.into_plan_parts();
        let _ = token;
        Self {
            execution,
            tracker,
            terminal: None,
            irp: None,
        }
    }

    /// Bind a CQ-consumer acquisition that will *drain*, keeping the role alive.
    ///
    /// [`Self::bind_cq_consumer`] spends the token into the plan's identity,
    /// which is right for a CQ execution that never touches the queue. A drain
    /// needs the opposite: the plan keeps the tracker, and the affine role
    /// survives inside a [`CqDrainAuthority`] that carries it from peek to
    /// commit to the next iteration and finally back to the ring state that
    /// releases it. One aggregate in, one plan and one drain authority out --
    /// the same shape `build_pending_slot_parts` uses for the ring's one-shot
    /// bind right, and for the same reason: two owners, one affine value.
    ///
    /// The bind is preflighted before the aggregate is decomposed, so a refusal
    /// returns it whole rather than a pile of parts the caller cannot reassemble.
    // Returning the whole aggregate is the property; boxing it would need an
    // allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn bind_cq_drain(
        acquired: AcquiredCqConsumer,
        cq: &BrandedCqStorage,
    ) -> Result<(Self, CqDrainAuthority), (CqBindError, AcquiredCqConsumer)> {
        let execution = acquired.execution();
        if let Some(error) = CqDrainAuthority::bind_refusal(cq, execution) {
            return Err((error, acquired));
        }
        let (token, tracker) = acquired.into_plan_parts();
        let brand = token.cq_stream();
        Ok((
            Self {
                execution,
                tracker,
                terminal: None,
                irp: None,
            },
            CqDrainAuthority {
                brand,
                consumer: token,
            },
        ))
    }

    /// Rebind this plan onto a resumed CQ execution.
    ///
    /// Refusal returns the unchanged plan **and** the exact aggregate, because
    /// a caller whose rebind failed still owns a live role and still has to
    /// release it.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn rebind_resumed(
        self,
        resume: &AuthenticatedCqResume,
        acquired: AcquiredCqConsumer,
    ) -> Result<Self, (PendingError, Self, AcquiredCqConsumer)> {
        if resume.execution().ring() != self.execution.ring() {
            return Err((PendingError::WrongRing, self, acquired));
        }
        if resume.execution().invocation() != self.execution.invocation() {
            return Err((PendingError::WrongInvocation, self, acquired));
        }
        if acquired.execution().ring() != self.execution.ring() {
            return Err((PendingError::WrongRing, self, acquired));
        }
        let mut plan = self;
        plan.execution = resume.execution();
        let _ = acquired;
        Ok(plan)
    }

    /// Record the IRP this execution parked, for cancel arbitration.
    pub fn observe_irp(&mut self, irp: IrpObservation) -> Result<(), PendingError> {
        if self.irp.is_some() {
            return Err(PendingError::SlotOccupied);
        }
        self.irp = Some(irp);
        Ok(())
    }

    /// Bind a cancel to one exact IRP.
    ///
    /// Synchronous and resumed cancels go through the same check: the IRP the
    /// cancel names must be the IRP this execution parked. A cancel for a
    /// different IRP is another request's, and answering it here would complete
    /// the wrong one.
    pub fn observe_cancel(&self, irp: IrpObservation) -> Result<CancelObservation, PendingError> {
        let Some(parked) = self.irp else {
            return Err(PendingError::NotDequeued);
        };
        if parked != irp {
            return Err(PendingError::WrongIrp);
        }
        Ok(CancelObservation {
            execution: self.execution,
            irp,
        })
    }

    /// Arbitrate one CQ mutation, consuming the witness.
    ///
    /// A naked `CqConsumerToken` cannot reach this: the parameter is a
    /// `CqMutationWitness`, whose only production minters are the typed packets
    /// Tasks 20 and 21 add. Holding the role is necessary and *not* sufficient —
    /// a mutation also has to be about a packet.
    pub fn arbitrate_cq_mutation(
        &mut self,
        witness: CqMutationWitness<'_>,
    ) -> Result<EnterMutationPermit<'_>, PendingError> {
        if witness.execution() != self.execution {
            return Err(PendingError::WrongExecutionDomain);
        }
        if self.execution.domain() != EnterExecutionDomain::CqConsumer {
            return Err(PendingError::WrongExecutionDomain);
        }
        // Deliberately NOT `self.tracker.record_commit()`. Arbitration
        // authorises a mutation; it does not perform one, and a refused
        // preparation downstream must leave the tracker exactly as it was.
        // The permit carries the transition to the commit that earns it.
        let execution = self.execution;
        Ok(EnterMutationPermit {
            execution,
            identity: witness.identity(),
            tracker: &mut self.tracker,
        })
    }

    #[allow(dead_code)]
    pub(crate) const fn execution(&self) -> EnterExecutionBrand {
        self.execution
    }

    /// Whether anything has committed. A *decision*, not the tracker.
    ///
    /// There is deliberately no accessor returning the tracker itself, by value
    /// or by reference: a sibling crate holding it could record a commit for a
    /// mutation core never arbitrated.
    pub const fn has_committed(&self) -> bool {
        self.tracker.committed()
    }

    #[allow(dead_code)]
    pub(crate) const fn holds_terminal(&self) -> bool {
        self.terminal.is_some()
    }
}

// ---------------------------------------------------------------------------
// R5 Task 20: the deferred CQ drain, from role to committed head advance
// ---------------------------------------------------------------------------
//
// The ABI's `try_peek` defers the head store; this layer decides *who* may
// perform it. Four stages are separated on purpose, and each separation is a
// place an executor could otherwise skip a step:
//
//   * `CqDrainAuthority` is the affine consumer role plus the stream it speaks
//     for. It is what a drain loop carries between iterations, and *every*
//     refusal hands it back -- a refused peek that consumed the role would
//     leave the ring's consumer owned by nobody, and nothing could ever drain
//     that ring again.
//   * `BrandedPendingCqPop` is one entry read and not yet accounted for. It
//     deliberately has no mutation witness and no commit-prepare method: an
//     unclassified entry is not authority to mutate anything.
//   * `NotifyCqPreflight` is that entry after its *privately copied* body was
//     checked against the conservative ordinary set. Only it lends a witness.
//   * `PreparedNotifyCqCommit` holds the checked preflight and the permit
//     that arbitration returned, and its parameterless commit is the only route
//     to the Release head store.
//
// **Deviation from the plan's wording, recorded here and not only in the
// evidence.** The plan says `preflight_notify_shape` returns the pop unchanged for
// "NOTIFY, PROTOCOL, COMPLETION, unknown" kinds, and `cq_kind` has exactly
// those three members -- read literally the accepted set is empty and the whole
// ordinary lane is dead code, which contradicts the same task's RED row
// "ordinary invalidation kinds accepted by the conservative C4 set". The
// reading that leaves every phrase a referent is the one implemented below: an
// *ordinary* row is a NOTIFY that names no arena body, so the drain accounts
// for it by advancing the head alone; a NOTIFY that names one belongs to the
// credit lane and `GrantTable::preflight_notify` consumes it.
//
// That split is also the only one decidable from the fixed CQE, which is all a
// parameterless preflight can read: `03-messages.md` section 2.4 puts the
// notification code in `NotifyEnvelopeV2.notify_code` -- inside the granted
// body -- and states it is *not* in `CqeBody.opcode`, so classifying by opcode
// here would contradict the normative document to reach a body this stage has
// not yet claimed the credit for.

use fsring_abi::{
    SlotToken,
    layout::{CQE_OUT_LEN, Cqe, CqeBody, cq_kind},
    msgs::{BufferRef, OControl, ProtocolAbortV1, validate_protocol_abort_v1},
    ring::{HeadAdvanceReceipt, PendingPop, PopError},
};

use crate::enter::{
    BrandedCqStorage, CqBindError, CqConsumerToken, CqStreamBrand, PreparedCqReleasePreflight,
    ProtocolConsumerReleased, ScopedBrandedCqConsumer,
};

/// The CQ kinds the conservative C4 drain accounts for without a credit claim.
///
/// A closed array rather than a `match` arm so the test walks the same values
/// production does; a `match` would let a test restate the set and agree with
/// itself. Extending C4's conservative slice means adding a value here, and the
/// shape predicate below still has to accept the row.
const CONSERVATIVE_NOTIFY_CQ_KINDS: [u16; 1] = [cq_kind::NOTIFY];

/// The exact `out_len` a notification CQE carries: one `OControl`.
const NOTIFY_OUT_LEN: u16 = CQE_OUT_LEN as u16;

/// Whether this row has the exact fixed-CQE shape `03-messages.md` section 9.1
/// gives a notification.
///
/// Section 9.1 is normative **and exhaustive**: "A notification CQE has
/// `kind = NOTIFY`, opcode 0, flags 0, `req_id = 0`, success status, reserved 0,
/// `out_len = 24`, and `out = OControl` pointing at one valid
/// `NotifyEnvelopeV2` in a notification credit." Every field it names is
/// checked here except the two that cannot be decided from the fixed CQE: the
/// envelope's validity, and the equality of `information` with the `OControl`
/// length and `NotifyEnvelopeV2.struct_size`, which needs the claimed credit.
/// `information` is required *nonzero* here, because section 9.1 makes it a
/// total byte length and a zero length names no envelope at all.
///
/// The `out` bytes are read as an `OControl` token rather than compared against
/// zero: a notification that named no arena body would be a row section 9.1
/// does not describe, and admitting it would hand a hostile producer a lane
/// that advances the head while claiming no credit.
fn has_conservative_notify_shape(body: &CqeBody) -> bool {
    const _: () = assert!(core::mem::size_of::<OControl>() == CQE_OUT_LEN);

    body.req_id == 0
        && body.opcode == 0
        && body.flags == 0
        && body.status == 0
        && body.reserved == 0
        && body.out_len == NOTIFY_OUT_LEN
        && body.information != 0
        && names_an_arena_body(body)
}

/// Whether the CQE's 24 output bytes name a slot at all.
///
/// The `out` array is exactly one `OControl`, whose first eight bytes are the
/// `BufferRef` slot token. A zero token names no slot, so it cannot point at
/// the `NotifyEnvelopeV2` section 9.1 requires. Read as native-endian bytes
/// rather than decoded: the array is byte-aligned inside the CQE and an
/// unaligned struct read would be `unsafe` for a question eight bytes answer.
fn names_an_arena_body(body: &CqeBody) -> bool {
    read_out_control(body).token != 0
}

/// Why one CQ peek was refused.
///
/// The two arms stay distinct because they mean different things to a drain
/// loop: a bind refusal says this authority does not speak for this consumer
/// and never will, while a cursor fault says the queue itself is unusable.
/// Folding them into one error would make "retry" and "fail-stop" the same
/// observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CqPeekError {
    Bind(CqBindError),
    Cursor(PopError),
}

/// Why one entry was not admitted to the ordinary lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyShapeError {
    NotConservativeNotifyKind,
    MalformedNotifyShape,
}

/// The affine right to drain one ring's CQ.
///
/// It owns the consumer token, so holding one *is* holding the role. `bind`
/// takes no caller-supplied locator, ring, invocation, IRP, or domain: the
/// stream comes out of the token itself, and the storage is compared against
/// it. There is therefore no copyable value a caller could present to drain a
/// ring it does not own.
#[must_use]
#[derive(Debug)]
pub struct CqDrainAuthority {
    brand: CqStreamBrand,
    consumer: CqConsumerToken,
}

/// One entry read and not yet accounted for, with the authority that read it.
///
/// No `mutation_witness`, no `prepare_*`: an entry whose kind and body have not
/// been checked authorises nothing. The only ways out are [`Self::abort`] and a
/// typed preflight.
#[must_use]
pub struct BrandedPendingCqPop<'consumer, 'storage> {
    authority: CqDrainAuthority,
    pop: PendingPop<'consumer, 'storage, Cqe>,
}

/// What one peek found.
///
/// `Empty` carries the authority back rather than borrowing it, so an empty
/// queue costs a drain loop nothing and loses it nothing.
#[must_use]
pub enum CqPeek<'consumer, 'storage> {
    Empty(CqDrainAuthority),
    Ready(BrandedPendingCqPop<'consumer, 'storage>),
}

/// An entry whose copied body belongs to the conservative ordinary set.
///
/// It retains the pop -- therefore the CQ token -- so nothing can be swapped
/// between validation and commit. The sequence and next head are captured here
/// rather than re-read later, because re-reading would consult shared memory
/// the producer may already have rewritten.
#[must_use]
pub struct NotifyCqPreflight<'consumer, 'storage> {
    pop: BrandedPendingCqPop<'consumer, 'storage>,
    brand: CqStreamBrand,
    copied_body: CqeBody,
    cq_sequence: u64,
    next_head: u64,
}

/// A checked preflight bound to the permit arbitration returned for it.
///
/// Its commit takes no parameters and cannot fail, which is the property that
/// matters: there is no fallible bind and no substitutable value between the
/// arbitration that authorised this mutation and the head store that performs
/// it.
#[must_use]
pub struct PreparedNotifyCqCommit<'consumer, 'storage, 'tracker> {
    preflight: NotifyCqPreflight<'consumer, 'storage>,
    permit: EnterMutationPermit<'tracker>,
}

/// A committed ordinary row: the copied body, the receipt, and the authority.
#[must_use]
pub struct BrandedCommittedCqPop {
    authority: CqDrainAuthority,
    body: CqeBody,
    receipt: HeadAdvanceReceipt<Cqe>,
}

#[allow(dead_code)]
impl CqDrainAuthority {
    /// Bind one ring's CQ storage to the affine role that may drain it.
    ///
    /// Refusal returns the exact token: a caller whose bind failed still owns a
    /// live consumer role and still has to release it through the ring state.
    /// Named `bind_drain` rather than `bind` deliberately: the production
    /// graph gate models edges by bare identifier, and four unrelated `bind`
    /// methods already exist across the two source roots -- one of them on the
    /// SETUP publication suffix. A method called `bind` here made the gate
    /// report `driver_entry -> ... -> bind -> cq_stream`, a route that does not
    /// exist. The eighth instance of that trap; check a new name against both
    /// roots before writing it.
    pub fn bind_drain(
        cq: &BrandedCqStorage,
        consumer: CqConsumerToken,
    ) -> Result<Self, (CqBindError, CqConsumerToken)> {
        if let Some(error) = Self::bind_refusal(cq, consumer.execution()) {
            return Err((error, consumer));
        }
        let brand = consumer.cq_stream();
        Ok(Self { brand, consumer })
    }

    /// Whether this storage and this execution name the same ring.
    ///
    /// Asked *before* anything is consumed, so both this and
    /// [`R4EnterPlan::bind_cq_drain`] can decide the same question from the
    /// same code without one of them having to reassemble an aggregate it had
    /// already taken apart.
    pub(crate) fn bind_refusal(
        cq: &BrandedCqStorage,
        execution: EnterExecutionBrand,
    ) -> Option<CqBindError> {
        if execution.domain() != EnterExecutionDomain::CqConsumer {
            return Some(CqBindError::WrongExecutionDomain);
        }
        let storage = cq.brand();
        let role = execution.ring();
        // Locator first, so a cross-session bind is distinguishable from a
        // cross-ring one. Both are refusals; only one of them means the caller
        // is looking at another session's memory.
        if storage.locator() != role.locator() {
            return Some(CqBindError::WrongLocator);
        }
        if storage != role {
            return Some(CqBindError::WrongRing);
        }
        None
    }

    /// Read the next entry of the consumer this authority speaks for.
    ///
    /// Empty, a cursor fault, and a consumer that serves another ring all
    /// return the same authority; only a ready entry moves it, and it moves it
    /// into the pop rather than copying it.
    // Every refusal hands the affine authority back, which is the property
    // under test; boxing it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn try_peek<'consumer, 'storage>(
        self,
        cq: &'consumer mut ScopedBrandedCqConsumer<'storage>,
    ) -> Result<CqPeek<'consumer, 'storage>, (CqPeekError, Self)> {
        if !cq.serves(self.brand) {
            return Err((CqPeekError::Bind(CqBindError::WrongRing), self));
        }
        match cq.cursor_mut().try_peek() {
            Ok(Some(pop)) => Ok(CqPeek::Ready(BrandedPendingCqPop {
                authority: self,
                pop,
            })),
            Ok(None) => Ok(CqPeek::Empty(self)),
            Err(error) => Err((CqPeekError::Cursor(error), self)),
        }
    }

    /// Give the role back to the caller that will release it.
    pub fn into_consumer_token(self) -> CqConsumerToken {
        let Self { consumer, .. } = self;
        consumer
    }

    pub(crate) const fn brand(&self) -> CqStreamBrand {
        self.brand
    }

    /// Borrow the role without spending it.
    pub(crate) const fn consumer_token(&self) -> &CqConsumerToken {
        &self.consumer
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage> BrandedPendingCqPop<'consumer, 'storage> {
    pub(crate) const fn brand(&self) -> CqStreamBrand {
        self.authority.brand()
    }

    pub const fn body(&self) -> CqeBody {
        self.pop.body()
    }

    pub const fn sequence(&self) -> u64 {
        self.pop.sequence()
    }

    pub const fn next_head(&self) -> u64 {
        self.pop.next_head()
    }

    /// Borrow the consumer token this pop's authority holds.
    ///
    /// Crate-private and by reference: the protocol lane needs the ring state
    /// to *record* the role's identity without releasing it, which is the whole
    /// point of Task 21's split preflight. A consuming accessor here would let
    /// a caller strand the role between the record and the release.
    pub(crate) fn consumer_token(&self) -> &CqConsumerToken {
        self.authority.consumer_token()
    }

    /// Mint the witness a typed protocol packet lends.
    ///
    /// Crate-private, and reachable only from `PreparedProtocolCommit`, which
    /// exists only after the ABI accepted the whole fixed CQE and the ring
    /// state accepted the release preflight. The generic pop still has no
    /// witness of its own -- this is the protocol lane's equivalent of
    /// `NotifyCqPreflight::mutation_witness`, not a way around it.
    pub(crate) fn protocol_mutation_witness(&self) -> CqMutationWitness<'_> {
        CqMutationWitness {
            execution: self.authority.brand().execution(),
            identity: self.pop_packet_identity(),
            packet: core::marker::PhantomData,
        }
    }

    /// Which CQ entry this pop is, for a typed packet's permit binding.
    ///
    /// Distinct name from `NotifyCqPreflight::packet_identity` on purpose: the
    /// two compute the same value from different captures, and one node for
    /// both would be unstageable.
    pub(crate) const fn pop_packet_identity(&self) -> CqPacketIdentity {
        CqPacketIdentity::new(self.pop.sequence(), self.pop.next_head())
    }

    /// Decline this entry. The head does not move and the authority survives.
    pub fn abort(self) -> CqDrainAuthority {
        let Self { authority, pop } = self;
        pop.release();
        authority
    }

    /// Admit this entry to the ordinary lane, or return it unchanged.
    ///
    /// The body is copied out of shared memory *before* the decision, so the
    /// value the preflight carries is the one that was classified, not whatever
    /// the producer writes next.
    // The error arm carries the whole pop back, which is the property being
    // proved -- a refusal that dropped it would drop the CQ token with it.
    // Boxing it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn preflight_notify_shape(
        self,
    ) -> Result<NotifyCqPreflight<'consumer, 'storage>, (NotifyShapeError, Self)> {
        let copied_body = self.pop.body();
        if !CONSERVATIVE_NOTIFY_CQ_KINDS.contains(&copied_body.kind) {
            return Err((NotifyShapeError::NotConservativeNotifyKind, self));
        }
        if !has_conservative_notify_shape(&copied_body) {
            return Err((NotifyShapeError::MalformedNotifyShape, self));
        }
        let brand = self.authority.brand();
        let cq_sequence = self.pop.sequence();
        let next_head = self.pop.next_head();
        Ok(NotifyCqPreflight {
            pop: self,
            brand,
            copied_body,
            cq_sequence,
            next_head,
        })
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage> NotifyCqPreflight<'consumer, 'storage> {
    pub const fn body(&self) -> CqeBody {
        self.copied_body
    }

    pub const fn sequence(&self) -> u64 {
        self.cq_sequence
    }

    pub const fn next_head(&self) -> u64 {
        self.next_head
    }

    pub(crate) const fn brand(&self) -> CqStreamBrand {
        self.brand
    }

    /// Lend the one witness this packet may lend.
    ///
    /// It borrows `self`, so the borrow ends before the packet can be moved
    /// into a preparation -- which is what lets native arbitrate under the
    /// cancel spin lock and *then* commit, without the witness outliving the
    /// decision it was minted for.
    pub fn mutation_witness(&self) -> CqMutationWitness<'_> {
        CqMutationWitness {
            execution: self.brand.execution(),
            identity: self.packet_identity(),
            packet: core::marker::PhantomData,
        }
    }

    /// Which CQ entry this packet is.
    ///
    /// Taken from the values captured at peek, not re-read: re-reading would
    /// consult shared memory the producer may already own again.
    pub(crate) const fn packet_identity(&self) -> CqPacketIdentity {
        CqPacketIdentity::new(self.cq_sequence, self.next_head)
    }

    /// Decline this entry after classification. The head still does not move.
    pub fn abort(self) -> CqDrainAuthority {
        self.pop.abort()
    }

    /// Bind the arbitrated permit to this exact packet.
    ///
    /// Ring, invocation and domain are checked separately so a refusal names
    /// which one failed. The domain check is what refuses an SQ-domain permit
    /// for the identical request: a resumed CQ execution reuses the parked
    /// invocation, so ring and invocation alone can be bit-for-bit equal.
    // As above: every refusal returns both affine values.
    #[allow(clippy::result_large_err)]
    pub fn prepare_notify_commit<'tracker>(
        self,
        permit: EnterMutationPermit<'tracker>,
    ) -> Result<
        PreparedNotifyCqCommit<'consumer, 'storage, 'tracker>,
        (PendingError, Self, EnterMutationPermit<'tracker>),
    > {
        let expected = self.brand.execution();
        let observed = permit.execution();
        if observed.ring() != expected.ring() {
            return Err((PendingError::WrongRing, self, permit));
        }
        if observed.invocation() != expected.invocation() {
            return Err((PendingError::WrongInvocation, self, permit));
        }
        if observed.domain() != EnterExecutionDomain::CqConsumer {
            return Err((PendingError::WrongExecutionDomain, self, permit));
        }
        // Last, and the reason it is not redundant with the three above: a
        // drain loop holds ring, invocation and domain constant across every
        // iteration, so those three cannot tell entry N's arbitration from
        // entry N+1's. Only the packet identity can.
        if permit.identity() != self.packet_identity() {
            return Err((PendingError::WrongSlot, self, permit));
        }
        Ok(PreparedNotifyCqCommit {
            preflight: self,
            permit,
        })
    }
}

#[allow(dead_code)]
impl PreparedNotifyCqCommit<'_, '_, '_> {
    /// Perform the sole Release head store for this entry.
    ///
    /// Parameterless and infallible: the permit was consumed to build this
    /// value, so there is nothing left to check and nothing left to substitute.
    pub fn commit(self) -> BrandedCommittedCqPop {
        let Self { preflight, permit } = self;
        // The permit is spent here rather than retained: one arbitration
        // authorises one mutation, and a retained permit would be a second.
        // Spending it is also what records the transition -- this is the first
        // real mutation of this execution, and the tracker learns it here
        // rather than at arbitration.
        permit.record_first_mutation();
        let NotifyCqPreflight {
            pop,
            copied_body,
            brand: _,
            cq_sequence: _,
            next_head: _,
        } = preflight;
        let BrandedPendingCqPop { authority, pop } = pop;
        let (_shared_body, receipt) = pop.commit().into_parts();
        // The privately copied body wins over the one the ABI carries: the copy
        // is what was classified, and the cell became the producer's again the
        // instant the head store above landed.
        BrandedCommittedCqPop {
            authority,
            body: copied_body,
            receipt,
        }
    }
}

#[allow(dead_code)]
impl BrandedCommittedCqPop {
    pub const fn body(&self) -> CqeBody {
        self.body
    }

    pub const fn sequence(&self) -> u64 {
        self.receipt.sequence()
    }

    pub const fn next_head(&self) -> u64 {
        self.receipt.next_head()
    }

    /// Return the authority for the next iteration of the drain.
    pub fn into_authority(self) -> CqDrainAuthority {
        let Self { authority, .. } = self;
        authority
    }
}

// ---------------------------------------------------------------------------
// R5 Task 20: the credit lane, from a shaped notification to a refreshed credit
// ---------------------------------------------------------------------------
//
// The shape preflight above proves the fixed CQE is a notification. It cannot
// prove the credit it names is claimable, because that is grant-table state.
// This layer joins the two, and the join is where the ordering rule lives:
//
//   packet -> bind_credit -> BrandedNotifyPreflight   (nothing mutated)
//          -> arbitrate under cancel spin             (still nothing mutated)
//          -> prepare_credit_claim(permit)            (last fallible step)
//          -> commit()  = the credit mutation         (infallible)
//          -> commit()  = the sole Release head store (infallible)
//          -> refresh() = the next descriptor          (infallible)
//
// Everything fallible happens before the first mutation, and every refusal
// returns the packet -- therefore the CQ token -- unchanged.

/// One notification packet bound to the credit its `OControl` names.
///
/// The grant record is `Copy`, but the packet is not: this value owns the pop,
/// so nothing can be swapped between the credit check and the head store.
#[must_use]
pub struct BrandedNotifyPreflight<'consumer, 'storage> {
    packet: NotifyCqPreflight<'consumer, 'storage>,
    record: NotifyPreflight,
    source: GrantRange,
}

/// A bound credit claim that has passed every check and mutated nothing.
#[must_use]
pub struct PreparedNotifyMutation<'consumer, 'storage, 'claim, 'tracker> {
    preflight: BrandedNotifyPreflight<'consumer, 'storage>,
    claim: PreparedCreditClaim<'claim>,
    permit: EnterMutationPermit<'tracker>,
}

/// A claimed credit whose CQ head has not moved yet.
///
/// It owns the pop and the claim together and has no self-reference, which is
/// what lets the head store be the next thing that happens with no fallible
/// step in between.
#[must_use]
pub struct PendingCqCommit<'consumer, 'storage, 'claim> {
    pop: BrandedPendingCqPop<'consumer, 'storage>,
    claim: ClaimedNotification<'claim>,
    source: GrantRange,
}

/// A claimed credit whose CQ head has moved exactly once.
#[must_use]
pub struct BrandedHeadAdvancedNotification<'claim> {
    authority: CqDrainAuthority,
    receipt: HeadAdvanceReceipt<Cqe>,
    advanced: HeadAdvancedNotification<'claim>,
    source: GrantRange,
}

/// Read the `OControl` the CQE's 24 output bytes carry.
///
/// Six field reads out of a byte array rather than a pointer cast: the array is
/// byte-aligned inside the CQE, so a struct read would be unaligned and
/// `unsafe`, and this answers the same question in safe code. Native-endian
/// because the CQE is shared memory on one machine, not a wire format crossing
/// hosts.
fn read_out_control(body: &CqeBody) -> BufferRef {
    // Destructured rather than sliced. An index expression would need bounds
    // arithmetic this crate's lints refuse, and refusing it is right: the
    // pattern below is exhaustive over exactly `CQE_OUT_LEN` bytes, so a change
    // to the CQE's output length is a compile error here rather than a panic in
    // a release driver.
    let [
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        t6,
        t7,
        o0,
        o1,
        o2,
        o3,
        l0,
        l1,
        l2,
        l3,
        k0,
        k1,
        a0,
        a1,
        r0,
        r1,
        r2,
        r3,
    ] = body.out;
    BufferRef {
        token: u64::from_ne_bytes([t0, t1, t2, t3, t4, t5, t6, t7]),
        offset: u32::from_ne_bytes([o0, o1, o2, o3]),
        length: u32::from_ne_bytes([l0, l1, l2, l3]),
        kind: u16::from_ne_bytes([k0, k1]),
        access: u16::from_ne_bytes([a0, a1]),
        reserved: u32::from_ne_bytes([r0, r1, r2, r3]),
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage> NotifyCqPreflight<'consumer, 'storage> {
    /// Bind this packet to the credit its `OControl` names.
    ///
    /// The token comes out of the packet's own copied body, never from a
    /// caller argument: a caller-supplied token would let a well-formed
    /// notification be paired with somebody else's credit.
    ///
    /// A refusal returns the exact packet, so the caller still owns the pop and
    /// can abort it -- which is the only way the CQ token gets back to the ring.
    // The error arm carries the packet back, which is the property; boxing it
    // would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn bind_credit(
        self,
        grants: &GrantTable<'_>,
        geometry: &SlotArenaGeometry,
        return_bytes_available: usize,
    ) -> Result<BrandedNotifyPreflight<'consumer, 'storage>, (GrantError, Self)> {
        let control = read_out_control(&self.copied_body);
        let Ok(token) = SlotToken::from_raw(control.token) else {
            return Err((GrantError::InvalidToken, self));
        };
        let ring_index = self.brand.ring_index();
        let record = match grants.preflight_notify(
            ring_index,
            token,
            return_bytes_available,
            token.generation(),
        ) {
            Ok(record) => record,
            Err(error) => return Err((error, self)),
        };
        if control.reserved != 0 {
            return Err((GrantError::InvalidToken, self));
        }
        // The absolute arena offset comes from the caller's published geometry,
        // never from a sum over the earlier classes: the section validator
        // requires only 64-byte alignment inside the arena, so padding between
        // classes is legal and a derived offset would point between slots.
        let source = match grants.grant_source_range(geometry, token, &control) {
            Ok(range) => range,
            Err(error) => return Err((error, self)),
        };
        Ok(BrandedNotifyPreflight {
            packet: self,
            record,
            source,
        })
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage> BrandedNotifyPreflight<'consumer, 'storage> {
    /// Where the body this notification names lives.
    pub const fn source_range(&self) -> GrantRange {
        self.source
    }

    pub const fn body(&self) -> CqeBody {
        self.packet.body()
    }

    pub(crate) const fn brand(&self) -> CqStreamBrand {
        self.packet.brand()
    }

    /// Lend the witness this already-validated packet may lend.
    ///
    /// Same borrow discipline as the shape preflight: native reads cancellation
    /// under the cancel spin lock while holding it, and the borrow ends before
    /// the packet moves into the preparation.
    ///
    /// Named apart from `NotifyCqPreflight::mutation_witness` rather than
    /// shadowing it: the production graph gate models edges by bare identifier,
    /// so two methods called `mutation_witness` are one node and neither can be
    /// staged. The gate refused this exact pair the moment it was written.
    pub fn credit_mutation_witness(&self) -> CqMutationWitness<'_> {
        self.packet.mutation_witness()
    }

    /// Decline after binding. The head does not move and no credit is claimed.
    pub fn abort(self) -> CqDrainAuthority {
        self.packet.abort()
    }

    /// The last fallible step before the first mutation.
    ///
    /// It rechecks the mutable grant state and the permit's full identity, and
    /// returns the preflight, the permit and an untouched table on any refusal.
    // As above: every refusal returns the affine values it was handed.
    #[allow(clippy::result_large_err)]
    pub fn prepare_credit_claim<'claim, 'tracker>(
        self,
        grants: &'claim mut GrantTable<'_>,
        permit: EnterMutationPermit<'tracker>,
    ) -> Result<
        PreparedNotifyMutation<'consumer, 'storage, 'claim, 'tracker>,
        (NotifyClaimError, Self, EnterMutationPermit<'tracker>),
    > {
        let expected = self.packet.brand().execution();
        let observed = permit.execution();
        if observed.ring() != expected.ring() {
            return Err((
                NotifyClaimError::Pending(PendingError::WrongRing),
                self,
                permit,
            ));
        }
        if observed.invocation() != expected.invocation() {
            return Err((
                NotifyClaimError::Pending(PendingError::WrongInvocation),
                self,
                permit,
            ));
        }
        if observed.domain() != EnterExecutionDomain::CqConsumer {
            return Err((
                NotifyClaimError::Pending(PendingError::WrongExecutionDomain),
                self,
                permit,
            ));
        }
        if permit.identity() != self.packet.packet_identity() {
            return Err((
                NotifyClaimError::Pending(PendingError::WrongSlot),
                self,
                permit,
            ));
        }
        match grants.prepare_claim_notify(self.record) {
            Ok(claim) => Ok(PreparedNotifyMutation {
                preflight: self,
                claim,
                permit,
            }),
            Err(fault) => Err((NotifyClaimError::Grant(fault), self, permit)),
        }
    }
}

/// Why one bound credit claim was refused.
///
/// The two arms stay distinct because they say different things about who was
/// wrong: a `Pending` refusal means the permit does not speak for this packet,
/// a `Grant` fault means the table no longer holds what the preflight saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyClaimError {
    Pending(PendingError),
    Grant(GrantFault),
}

#[allow(dead_code)]
impl<'consumer, 'storage, 'claim> PreparedNotifyMutation<'consumer, 'storage, 'claim, '_> {
    /// Claim the credit. Parameterless and infallible.
    pub fn commit(self) -> PendingCqCommit<'consumer, 'storage, 'claim> {
        let Self {
            preflight,
            claim,
            permit,
        } = self;
        // One arbitration authorises one mutation; a retained permit would be a
        // second. Spending it records the transition: the credit mutation below
        // is the first real one of this execution.
        permit.record_first_mutation();
        let BrandedNotifyPreflight {
            packet,
            record: _,
            source,
        } = preflight;
        // Destructured in place rather than through an accessor. A method that
        // handed the pop back would be one more bare identifier for the
        // production graph to merge with the eleven other `commit`-adjacent
        // helpers, and it would be a way for a caller outside this lane to get
        // the unclassified pop and start over with a different classification.
        let NotifyCqPreflight { pop, .. } = packet;
        PendingCqCommit {
            pop,
            claim: claim.commit(),
            source,
        }
    }
}

#[allow(dead_code)]
impl<'claim> PendingCqCommit<'_, '_, 'claim> {
    /// Perform the sole Release head store for this entry.
    ///
    /// The credit is already claimed, so there is nothing left to decide and
    /// nothing left that can fail. The head advance is what converts the claim
    /// into the proof the refresh requires.
    pub const fn source_range(&self) -> GrantRange {
        self.source
    }

    pub fn commit(self) -> BrandedHeadAdvancedNotification<'claim> {
        let Self { pop, claim, source } = self;
        let BrandedPendingCqPop { authority, pop } = pop;
        let (_shared_body, receipt) = pop.commit().into_parts();
        // SAFETY: the Release head store is the line immediately above, it
        // happened exactly once, and this is the only route from this type to
        // the advanced one.
        let advanced = unsafe { claim.after_release_head_advance() };
        BrandedHeadAdvancedNotification {
            authority,
            receipt,
            advanced,
            source,
        }
    }
}

#[allow(dead_code)]
impl BrandedHeadAdvancedNotification<'_> {
    pub const fn sequence(&self) -> u64 {
        self.receipt.sequence()
    }

    pub const fn next_head(&self) -> u64 {
        self.receipt.next_head()
    }

    /// Where the body this notification named lives, still readable after the
    /// head has moved: the range was copied out of the descriptor, so it does
    /// not become stale when the producer reclaims the CQ cell.
    pub const fn source_range(&self) -> GrantRange {
        self.source
    }

    /// Publish the refreshed credit and hand the drain authority back.
    ///
    /// Returning the authority is the loop's continuation: one iteration ends
    /// holding exactly what the next one needs, and there is no point at which
    /// the ring's consumer role is owned by nobody.
    pub fn refresh(self, output: &mut NotificationCreditV1) -> (RefreshedCredit, CqDrainAuthority) {
        let Self {
            authority,
            receipt: _,
            advanced,
            source: _,
        } = self;
        (advanced.refresh(output), authority)
    }
}

// ---------------------------------------------------------------------------
// R5 Task 20 Steps 5-6: the recording-only drain executor
// ---------------------------------------------------------------------------
//
// `#[cfg(test)]`, and that is the design rather than a convenience. Task 16
// established the shape: a recording projection lives in core, because
// `fsring-fsd` is a kernel cdylib with no host test target, and the property it
// owes is that it consumes the staged surface **without becoming a production
// root**. Being `cfg(test)` makes that structural -- the production graph
// strips `cfg(test)` before it walks, so nothing here can add an edge.
//
// It answers the two questions no test of an individual stage can: what a whole
// drain writes into the caller's buffer, and what it does when a credit's
// generation is exhausted.

/// One effect the drain performed, in the order it performed it.
///
/// A recorded *roster*, not a log. The tests compare the whole sequence, so an
/// executor that claimed twice, refreshed without advancing, or advanced before
/// claiming produces a different vector rather than a subtly different line.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordedCqEffect {
    ClaimCredit,
    AdvanceCqHead,
    RefreshCredit,
}

/// What one recorded drain decided.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct RecordedDrain {
    effects: std::vec::Vec<RecordedCqEffect>,
    credits: u32,
    /// The status and information the disposition carries.
    ///
    /// Recorded beside it rather than read back out of `ValidatedCompletion`,
    /// which deliberately has no repeatable getters -- reading them is what
    /// `prepare_for_irp` does, once. A harness whose whole job is to prove the
    /// output contract has to be able to state what it decided, and a test that
    /// re-derived the expected size from its own assumption would be checking
    /// its assumption rather than the code.
    status: i32,
    information: usize,
    disposition: ProviderDisposition<TerminalRequest>,
}

#[cfg(test)]
#[allow(dead_code)]
impl RecordedDrain {
    pub(crate) fn effects(&self) -> &[RecordedCqEffect] {
        &self.effects
    }

    pub(crate) const fn credits(&self) -> u32 {
        self.credits
    }

    pub(crate) const fn disposition(&self) -> &ProviderDisposition<TerminalRequest> {
        &self.disposition
    }

    pub(crate) const fn status(&self) -> i32 {
        self.status
    }

    pub(crate) const fn information(&self) -> usize {
        self.information
    }
}

/// Drive one bounded drain over the recording projection.
///
/// **The output contract, and why it is checkable here and nowhere else.** The
/// buffer is zeroed before any effect runs, each refreshed descriptor is
/// appended at its exact ordinal in the `48 + count * 32` tail, and nothing else
/// is written. A test can therefore assert three separate things after the fact:
/// the prefix is untouched, the tail holds exactly the committed descriptors,
/// and the suffix beyond `information` is still zero -- which is what "never
/// expose drain scratch, padding, uncommitted descriptors, or a larger caller
/// buffer suffix" means operationally.
///
/// Generation exhaustion is Step 6 and is deliberately *not* an error return:
/// the credit stays live, the CQ head does not move, and the decision is a
/// `CompleteAfterTerminal(CreditGenerationExhausted)` carrying
/// `STATUS_INVALID_DEVICE_STATE` and zero information. A drain that reported it
/// as a refusal would leave the caller unable to distinguish "nothing to do"
/// from "this session can never claim another credit".
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_bounded_drain(
    plan: &mut R4EnterPlan,
    authority: CqDrainAuthority,
    consumer: &mut ScopedBrandedCqConsumer<'_>,
    grants: &mut GrantTable<'_>,
    geometry: &SlotArenaGeometry,
    output: &mut [u8],
    budget: u32,
) -> (RecordedDrain, CqDrainAuthority) {
    // Zeroed before execution, not after: a buffer cleared at the end would
    // still have held the scratch in between.
    output.fill(0);

    let mut effects = std::vec::Vec::new();
    let mut credits = 0u32;
    let mut authority = authority;
    let mut exhausted = false;

    while credits < budget && !exhausted {
        let peeked = match authority.try_peek(consumer) {
            Ok(peeked) => peeked,
            Err((_error, returned)) => {
                authority = returned;
                break;
            }
        };
        let pop = match peeked {
            CqPeek::Empty(returned) => {
                authority = returned;
                break;
            }
            CqPeek::Ready(pop) => pop,
        };
        let packet = match pop.preflight_notify_shape() {
            Ok(packet) => packet,
            Err((_error, pop)) => {
                authority = pop.abort();
                break;
            }
        };
        let bound = match packet.bind_credit(grants, geometry, remaining_tail(output, credits)) {
            Ok(bound) => bound,
            Err((error, packet)) => {
                exhausted = matches!(error, GrantError::GenerationExhausted);
                authority = packet.abort();
                break;
            }
        };
        let permit = match plan.arbitrate_cq_mutation(bound.credit_mutation_witness()) {
            Ok(permit) => permit,
            Err(_error) => {
                authority = bound.abort();
                break;
            }
        };
        let prepared = match bound.prepare_credit_claim(grants, permit) {
            Ok(prepared) => prepared,
            Err((_error, bound, _permit)) => {
                authority = bound.abort();
                break;
            }
        };

        let pending = prepared.commit();
        effects.push(RecordedCqEffect::ClaimCredit);
        let advanced = pending.commit();
        effects.push(RecordedCqEffect::AdvanceCqHead);

        let mut descriptor = NotificationCreditV1::default();
        let (_refreshed, returned) = advanced.refresh(&mut descriptor);
        effects.push(RecordedCqEffect::RefreshCredit);
        write_descriptor(output, credits, &descriptor);
        credits = credits.saturating_add(1);
        authority = returned;
    }

    let information = if exhausted { 0 } else { result_size(credits) };
    let status = if exhausted {
        status::INVALID_DEVICE_STATE
    } else {
        status::SUCCESS
    };
    let completion = ValidatedCompletion::prepare(status, information, output.len(), information)
        .unwrap_or_else(|error| unreachable!("{error:?}"));
    let disposition = if exhausted {
        ProviderDisposition::CompleteAfterTerminal {
            completion,
            terminal: TerminalRequest::CreditGenerationExhausted,
        }
    } else {
        ProviderDisposition::Complete(completion)
    };

    (
        RecordedDrain {
            effects,
            credits,
            status,
            information,
            disposition,
        },
        authority,
    )
}

/// `48 + count * 32`, the exact ENTER result size for `count` credits.
#[cfg(test)]
fn result_size(count: u32) -> usize {
    let prefix = ENTER_RESULT_V1_PREFIX_SIZE as usize;
    let tail = (count as usize).saturating_mul(NOTIFICATION_CREDIT_V1_SIZE as usize);
    prefix.saturating_add(tail)
}

/// Bytes still available for one more descriptor.
#[cfg(test)]
fn remaining_tail(output: &[u8], written: u32) -> usize {
    output.len().saturating_sub(result_size(written))
}

/// Append one refreshed descriptor at its exact ordinal.
///
/// Encoded through the ABI's own `try_encode` rather than a local byte copy, so
/// the recorded tail is the wire form a real caller would read and not this
/// harness's idea of it.
#[cfg(test)]
fn write_descriptor(output: &mut [u8], ordinal: u32, descriptor: &NotificationCreditV1) {
    let at = result_size(ordinal);
    let Some(slot) = output.get_mut(at..) else {
        unreachable!("the tail was sized before the claim that produced this descriptor")
    };
    fsring_abi::codec::try_encode(descriptor, slot)
        .unwrap_or_else(|error| unreachable!("{error:?}"));
}

// ---------------------------------------------------------------------------
// R5 Task 21: the private provider-fatal protocol abort
// ---------------------------------------------------------------------------
//
// A PROTOCOL CQE says the provider has declared its own session unusable. The
// driver's answer is terminal, so the order in which it stops trusting the
// session matters more than usual, and the two naive orders both fail:
//
//   * releasing the consumer role first leaves the CQ mutation running on a
//     roleless ring with nothing saying which invocation it belonged to;
//   * committing first and re-looking-up the consumer at release time can find
//     a LATER invocation of the same ring, so the release credits the wrong
//     execution.
//
// Task 21's first half (`prepare_cq_release` / `commit_cq_release`) resolved
// that by recording the role identity without consuming it. This is the half
// that drives it from an actual CQ entry: validate, preflight the release,
// arbitrate, then commit the head advance and the release together.
//
// **Deviation from the plan's signature, and it is the same one the notify lane
// already makes.** The plan writes
// `validate_protocol_abort(pop, copied_cqe, copied_abort)` -- a free function
// taking the CQE and the decoded abort as arguments. A caller-supplied body is
// exactly what `bind_credit` refuses to accept, for the same reason: it would
// let a well-formed packet be paired with somebody else's payload. Here the
// validation consumes the pop and reads the pop's own privately copied body,
// through the ABI's `validate_protocol_abort_v1`, which is normative and
// exhaustive over every fixed-CQE field.

/// Why a protocol arrival was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// The fixed CQE is not the exact `ABORT_SESSION` shape the ABI defines.
    NotProviderFatalAbort,
    /// The permit does not speak for this packet.
    Pending(PendingError),
    /// The ring state refused the consumer-release preflight.
    Role(RoleError),
}

/// One PROTOCOL entry whose whole fixed CQE the ABI accepted.
///
/// It owns the pop, so the entry cannot be reclassified or swapped between
/// validation and the terminal it asks for.
#[must_use]
pub struct PendingProtocolCommit<'consumer, 'storage> {
    pop: BrandedPendingCqPop<'consumer, 'storage>,
    brand: CqStreamBrand,
    copied_cqe: CqeBody,
    abort: ProtocolAbortV1,
}

/// The same entry, with the consumer role's identity recorded.
///
/// Recorded and **not** released: the role is still held while the mutation
/// runs, so no second consumer can slip in, and the release at the end names
/// this exact invocation rather than whatever the ring holds by then.
#[must_use]
pub struct PreparedProtocolCommit<'consumer, 'storage> {
    pending: PendingProtocolCommit<'consumer, 'storage>,
    release: PreparedCqReleasePreflight,
}

/// A prepared abort bound to the permit arbitration returned for it.
#[must_use]
pub struct BoundProtocolCommit<'consumer, 'storage, 'tracker, 'state> {
    prepared: PreparedProtocolCommit<'consumer, 'storage>,
    permit: EnterMutationPermit<'tracker>,
    ring_state: &'state mut RingEnterState,
}

/// A committed provider-fatal abort: head advanced, consumer released.
#[must_use]
pub struct CommittedProtocolAbort {
    brand: CqStreamBrand,
    released: ProtocolConsumerReleased,
    cq_sequence: u64,
    next_head: u64,
    copied_cqe: CqeBody,
    abort: ProtocolAbortV1,
}

/// A release preflight that failed, with the entry it was about.
#[must_use]
pub struct ProtocolReleasePrepareFailure<'consumer, 'storage> {
    error: RoleError,
    pending: PendingProtocolCommit<'consumer, 'storage>,
}

/// A permit bind that failed, with both affine values it was handed.
#[must_use]
pub struct ProtocolMutationBindFailure<'consumer, 'storage, 'tracker> {
    error: ProtocolError,
    prepared: PreparedProtocolCommit<'consumer, 'storage>,
    permit: EnterMutationPermit<'tracker>,
}

#[allow(dead_code)]
impl<'consumer, 'storage> BrandedPendingCqPop<'consumer, 'storage> {
    /// Admit this entry to the protocol lane, or return it unchanged.
    ///
    /// The whole fixed CQE is checked by the ABI's own validator, which is
    /// exhaustive: kind, opcode, flags, `out_len`, `req_id`, status, reserved
    /// and information, then the decoded record's header, reason and reserved.
    /// Nothing is re-stated here, so this lane cannot drift from the document.
    // The refusal carries the pop back, which is the property; boxing it would
    // need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn preflight_protocol(
        self,
    ) -> Result<PendingProtocolCommit<'consumer, 'storage>, (ProtocolError, Self)> {
        let copied_cqe = self.pop.body();
        let Some(abort) = validate_protocol_abort_v1(&copied_cqe) else {
            return Err((ProtocolError::NotProviderFatalAbort, self));
        };
        let brand = self.authority.brand();
        Ok(PendingProtocolCommit {
            pop: self,
            brand,
            copied_cqe,
            abort,
        })
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage> PendingProtocolCommit<'consumer, 'storage> {
    pub const fn body(&self) -> CqeBody {
        self.copied_cqe
    }

    pub const fn abort_record(&self) -> ProtocolAbortV1 {
        self.abort
    }

    pub(crate) const fn brand(&self) -> CqStreamBrand {
        self.brand
    }

    /// Decline the entry. The head does not move and the role is not released.
    pub fn abort(self) -> CqDrainAuthority {
        self.pop.abort()
    }

    /// Record the consumer role's identity without releasing it.
    ///
    /// `&RingEnterState`, deliberately: preflighting must not be able to change
    /// the ring, and the release it authorises happens in the same infallible
    /// suffix as the head advance.
    #[allow(clippy::result_large_err)]
    pub fn prepare_consumer_release(
        self,
        ring_state: &RingEnterState,
    ) -> Result<
        PreparedProtocolCommit<'consumer, 'storage>,
        ProtocolReleasePrepareFailure<'consumer, 'storage>,
    > {
        match ring_state.prepare_cq_release(self.pop.consumer_token()) {
            Ok(release) => Ok(PreparedProtocolCommit {
                pending: self,
                release,
            }),
            Err(error) => Err(ProtocolReleasePrepareFailure {
                error,
                pending: self,
            }),
        }
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage> PreparedProtocolCommit<'consumer, 'storage> {
    pub(crate) const fn brand(&self) -> CqStreamBrand {
        self.pending.brand
    }

    /// Decline after the release preflight. Nothing was released.
    pub fn abort(self) -> CqDrainAuthority {
        self.pending.abort()
    }

    /// Lend the witness this already-validated packet may lend.
    ///
    /// Named apart from `NotifyCqPreflight::mutation_witness` for the same
    /// reason `credit_mutation_witness` is: the production graph models edges by
    /// bare identifier, so two methods sharing a name are one node and neither
    /// can be staged.
    pub fn protocol_commit_witness(&self) -> CqMutationWitness<'_> {
        self.pending.pop.protocol_mutation_witness()
    }

    /// Bind the arbitrated permit and the ring state that will be mutated.
    ///
    /// The ring state arrives here rather than at commit because the commit is
    /// infallible by construction: everything that can refuse -- the permit's
    /// identity, the packet it names -- refuses before the mutating borrow is
    /// taken.
    #[allow(clippy::result_large_err)]
    pub fn bind_mutation<'tracker, 'state>(
        self,
        permit: EnterMutationPermit<'tracker>,
        ring_state: &'state mut RingEnterState,
    ) -> Result<
        BoundProtocolCommit<'consumer, 'storage, 'tracker, 'state>,
        ProtocolMutationBindFailure<'consumer, 'storage, 'tracker>,
    > {
        let expected = self.pending.brand.execution();
        let observed = permit.execution();
        let refusal = if observed.ring() != expected.ring() {
            Some(PendingError::WrongRing)
        } else if observed.invocation() != expected.invocation() {
            Some(PendingError::WrongInvocation)
        } else if observed.domain() != EnterExecutionDomain::CqConsumer {
            Some(PendingError::WrongExecutionDomain)
        } else if permit.identity() != self.pending.pop.pop_packet_identity() {
            Some(PendingError::WrongSlot)
        } else {
            None
        };
        if let Some(error) = refusal {
            return Err(ProtocolMutationBindFailure {
                error: ProtocolError::Pending(error),
                prepared: self,
                permit,
            });
        }
        Ok(BoundProtocolCommit {
            prepared: self,
            permit,
            ring_state,
        })
    }
}

#[allow(dead_code)]
impl BoundProtocolCommit<'_, '_, '_, '_> {
    /// Advance the head and release the exact preflighted consumer, together.
    ///
    /// Parameterless and infallible. The release cannot fail here because
    /// `commit_cq_release` is being handed the identity `prepare_cq_release`
    /// recorded from this same still-held token, and nothing between the two
    /// could have released it -- the token has been inside this packet the
    /// whole time.
    ///
    /// **Named `commit_protocol_abort`, not `commit`, and the reason is a
    /// proof rather than a preference.** `commit` already has a dozen
    /// definitions, so a method by that name here merges into one node with
    /// production's setup commit -- and `commit_cq_release`, a Task 21
    /// first-half staged row, would have started reporting as
    /// production-reachable through it. Excusing that row would have traded a
    /// direct proof for a recorded excuse; renaming keeps the proof.
    pub fn commit_protocol_abort(self) -> CommittedProtocolAbort {
        let Self {
            prepared,
            permit,
            ring_state,
        } = self;
        // The abort IS the first real mutation of this execution.
        permit.record_first_mutation();
        let PreparedProtocolCommit { pending, release } = prepared;
        let PendingProtocolCommit {
            pop,
            brand,
            copied_cqe,
            abort,
        } = pending;
        let cq_sequence = pop.sequence();
        let next_head = pop.next_head();
        let BrandedPendingCqPop { authority, pop } = pop;
        let (_shared, _receipt) = pop.commit().into_parts();
        let token = authority.into_consumer_token();
        let released = match ring_state.commit_cq_release(release, token) {
            Ok(released) => released,
            Err((error, _, _)) => unreachable!(
                "the release names the token this packet has held since the preflight: {error:?}"
            ),
        };
        CommittedProtocolAbort {
            brand,
            released,
            cq_sequence,
            next_head,
            copied_cqe,
            abort,
        }
    }
}

#[allow(dead_code)]
impl CommittedProtocolAbort {
    /// The session this abort authenticates a terminal for.
    ///
    /// Read off the stream brand rather than from the wire: `ProtocolAbortV1`
    /// carries diagnostics, never an identity, so the only thing that can say
    /// *whose* session this was is the branded role that drained it.
    /// Hidden-public because `fsring-fsd` is a separate crate and this is the
    /// sole routing getter it needs: the native claim has to pick a cell before
    /// it can preflight one. It mints nothing and observes only.
    #[doc(hidden)]
    pub fn authenticated_locator(&self) -> crate::session::SessionLocator {
        self.brand.locator()
    }

    pub const fn sequence(&self) -> u64 {
        self.cq_sequence
    }

    pub const fn next_head(&self) -> u64 {
        self.next_head
    }

    pub const fn body(&self) -> CqeBody {
        self.copied_cqe
    }

    pub const fn abort_record(&self) -> ProtocolAbortV1 {
        self.abort
    }

    pub(crate) const fn consumer_released(&self) -> &ProtocolConsumerReleased {
        &self.released
    }

    /// Consume the abort into the record a terminal claim requires.
    ///
    /// Consuming, and the only route: a terminal branch cannot be driven twice
    /// from one arrival, and nothing can rebuild the record from copies,
    /// because `ProtocolConsumerReleased` has no public constructor.
    pub(crate) fn into_terminal_record(self) -> CommittedProtocolRecord {
        let Self {
            brand,
            released,
            cq_sequence,
            next_head,
            copied_cqe,
            abort,
        } = self;
        CommittedProtocolRecord {
            brand,
            released,
            cq_sequence,
            next_head,
            copied_cqe,
            abort,
        }
    }

    /// The execution this abort released, for a test that must prove the next
    /// consumer is a different one.
    #[cfg(test)]
    pub(crate) const fn brand_execution_for_test(&self) -> EnterExecutionBrand {
        self.brand.execution()
    }
}

/// Everything a committed abort carries into the terminal claim.
///
/// Crate-private and consumed by value: it is the *only* thing that proves the
/// CQ head advanced and the consumer role was released, so a terminal branch
/// that did not consume one would be acting on an arrival it cannot show
/// happened.
// No `Debug`: the wire body and the release proof have none, and deriving one
// here would mean printing an arrival that has already been answered.
#[must_use]
pub(crate) struct CommittedProtocolRecord {
    brand: CqStreamBrand,
    released: ProtocolConsumerReleased,
    cq_sequence: u64,
    next_head: u64,
    copied_cqe: CqeBody,
    abort: ProtocolAbortV1,
}

#[allow(dead_code)]
impl CommittedProtocolRecord {
    pub(crate) const fn locator(&self) -> crate::session::SessionLocator {
        self.brand.locator()
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.cq_sequence
    }

    pub(crate) const fn next_head(&self) -> u64 {
        self.next_head
    }

    pub(crate) const fn abort(&self) -> ProtocolAbortV1 {
        self.abort
    }

    pub(crate) const fn body(&self) -> CqeBody {
        self.copied_cqe
    }

    pub(crate) const fn consumer_released(&self) -> &ProtocolConsumerReleased {
        &self.released
    }
}

#[allow(dead_code)]
impl ProtocolReleasePrepareFailure<'_, '_> {
    pub const fn error(&self) -> RoleError {
        self.error
    }

    /// Give back the role. A failed preflight released nothing.
    pub fn abort(self) -> (RoleError, CqDrainAuthority) {
        let Self { error, pending } = self;
        (error, pending.abort())
    }
}

#[allow(dead_code)]
impl<'consumer, 'storage, 'tracker> ProtocolMutationBindFailure<'consumer, 'storage, 'tracker> {
    pub const fn error(&self) -> ProtocolError {
        self.error
    }

    /// Both affine values, unchanged.
    pub fn into_parts(
        self,
    ) -> (
        ProtocolError,
        PreparedProtocolCommit<'consumer, 'storage>,
        EnterMutationPermit<'tracker>,
    ) {
        let Self {
            error,
            prepared,
            permit,
        } = self;
        (error, prepared, permit)
    }
}

// ---------------------------------------------------------------------------
// R4 Task 15: the typed outer disposition and its completion closure
// ---------------------------------------------------------------------------
//
// The outer dispatch thunk returns one of exactly three things, and which one it
// is decides who owns the IRP afterwards. Making that a *type* rather than a
// status code is the whole point: a copyable `(status, information)` pair says
// nothing about ownership, so a thunk that returned `STATUS_PENDING` alongside a
// completed IRP would compile.

/// `STATUS_PENDING`, which a synchronous completion may never carry.
pub const STATUS_PENDING: i32 = 0x0000_0103;

/// A completion whose status and information were checked against the output
/// capacity that will receive them.
///
/// Minted only by [`ValidatedCompletion::prepare`]. It has no repeatable
/// status/information getters: reading them is what `prepare_for_irp` does,
/// once, on the way to the one write.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct ValidatedCompletion {
    status: i32,
    information: usize,
}

#[cfg(test)]
impl ValidatedCompletion {
    /// The pair this completion carries, for a test that must state it.
    ///
    /// `#[cfg(test)]` because production deliberately has no repeatable
    /// status/information getters -- reading them is what `prepare_for_irp`
    /// does, once. A test asserting "the reject completes invalid-device-state
    /// with zero" has to be able to see the pair, and deriving the expected
    /// value from its own arithmetic instead is how two plants survived the
    /// first round here and two more survived it in the drain recorder.
    pub(crate) const fn observed_for_test(&self) -> (i32, usize) {
        (self.status, self.information)
    }
}

/// Why a candidate completion was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionValidationError {
    /// `STATUS_PENDING` never describes a finished synchronous request.
    PendingStatus,
    /// The information exceeds the buffer that will receive it.
    InformationBeyondCapacity,
    /// A success status must report the exact expected result size.
    InformationNotExact,
}

/// The one-use view an outer thunk writes through.
///
/// It is produced by `unsafe prepare_for_irp` and consumed by
/// `commit_after_io_complete`; there is no abort, no clone, and no second
/// prepare, so safe code cannot complete one request twice.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PreparedSynchronousCompletion {
    status: i32,
    information: usize,
}

/// Proof that exactly one IRP was completed synchronously.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct CompletedSynchronousIrpReceipt {
    status: i32,
}

/// Proof that one IRP was handed to the pending machinery after handoff.
///
/// Only Task 17's split selected -> post-handoff transition may mint one in
/// production, through [`PendingDispatchReceipt::from_handoff`]; Task 15 also
/// provides a `#[cfg(test)]` factory so the disposition boundary can be tested
/// without driving a whole install. A merely selected or CSQ-inserted IRP is
/// not ownership proof.
#[must_use]
#[cfg_attr(test, derive(Debug))]
#[allow(dead_code)]
pub struct PendingDispatchReceipt {
    irp: IrpObservation,
}

/// What the outer thunk returns, and who owns the IRP after it.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum ProviderDisposition<T> {
    /// The thunk completes the IRP itself and returns its status.
    Complete(ValidatedCompletion),
    /// The pending context owns the IRP; the thunk touches it no further.
    Pending(PendingDispatchReceipt),
    /// The thunk completes the IRP *and* owes terminal work afterwards.
    CompleteAfterTerminal {
        completion: ValidatedCompletion,
        terminal: T,
    },
}

impl ValidatedCompletion {
    /// Validate one candidate completion against the capacity that receives it.
    ///
    /// `expected` is the exact result size a success must report. A success that
    /// reported fewer bytes would tell the caller to read a prefix of a
    /// structure the driver actually filled in full; more would send it past
    /// the buffer.
    pub const fn prepare(
        status: i32,
        information: usize,
        capacity: usize,
        expected: usize,
    ) -> Result<Self, CompletionValidationError> {
        if status == STATUS_PENDING {
            return Err(CompletionValidationError::PendingStatus);
        }
        if information > capacity {
            return Err(CompletionValidationError::InformationBeyondCapacity);
        }
        if status >= 0 && information != expected {
            return Err(CompletionValidationError::InformationNotExact);
        }
        Ok(Self {
            status,
            information,
        })
    }

    /// Take the one view the thunk writes through.
    ///
    /// # Safety
    /// The caller writes `IoStatus` from the returned view and calls
    /// `IoCompleteRequest` exactly once, then immediately consumes
    /// [`PreparedSynchronousCompletion::commit_after_io_complete`]. There is no
    /// path back to a `ValidatedCompletion` afterwards.
    pub unsafe fn prepare_for_irp(self) -> PreparedSynchronousCompletion {
        let Self {
            status,
            information,
        } = self;
        PreparedSynchronousCompletion {
            status,
            information,
        }
    }
}

impl PreparedSynchronousCompletion {
    /// The exact `(status, information)` to write, read once.
    pub const fn view(&self) -> (i32, usize) {
        (self.status, self.information)
    }

    /// # Safety
    /// `IoCompleteRequest` has already been called for this exact IRP.
    pub unsafe fn commit_after_io_complete(self) -> CompletedSynchronousIrpReceipt {
        let Self {
            status,
            information: _,
        } = self;
        CompletedSynchronousIrpReceipt { status }
    }
}

impl CompletedSynchronousIrpReceipt {
    /// The only way a synchronous completion becomes a dispatch return value.
    pub const fn into_dispatch_status(self) -> i32 {
        self.status
    }
}

#[allow(dead_code)]
impl PendingDispatchReceipt {
    /// The one production route in: consume an authentic post-handoff receipt.
    ///
    /// By value and exactly once. The receipt is only obtainable from
    /// [`crate::enter::commit_pending_handoff`], and on the queued arm only
    /// after the queue call, so a dispatch that returned `STATUS_PENDING`
    /// before the pending machinery could run has nothing to return it with.
    /// The seal stays on this side of the boundary — root `enter.rs` mints the
    /// handoff receipt and never the dispatch one.
    pub(crate) fn from_handoff(receipt: crate::enter::HandoffDoneReceipt) -> Self {
        Self { irp: receipt.irp() }
    }

    #[cfg(test)]
    pub(crate) const fn for_test_after_handoff(irp: IrpObservation) -> Self {
        Self { irp }
    }

    pub(crate) const fn irp(&self) -> IrpObservation {
        self.irp
    }
}

// ---------------------------------------------------------------------------
// R4 Task 18: the exhausted-slot fence
// ---------------------------------------------------------------------------

/// `STATUS_INVALID_DEVICE_STATE`, which an exhausted pending slot completes
/// with.
pub const STATUS_INVALID_DEVICE_STATE: i32 = 0xC000_0184_u32 as i32;

/// What a WAIT that wants to park may do with one pending slot.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingParkDecision {
    /// The slot admits one install; the caller may begin one.
    Install,
    /// The slot's epoch space is permanently spent. The request completes
    /// after terminal work and is never marked pending or queued.
    CompleteAfterTerminal(TerminalRequest),
    /// A live install already owns the slot. Not terminal: this arrival is
    /// refused and the existing install is untouched.
    Refuse(PendingError),
}

/// Decide, from the slot state alone, whether a parking WAIT may install.
///
/// It takes the slot state and *nothing else* — no IRP observation, no install
/// identity, no schedule, no queue — so there is nothing it could mark pending
/// or queue even if its body wanted to. That is where the fence lives: not in
/// the order some caller happened to write its statements, but in what this
/// decision is able to name.
///
/// The caller's half is equally structural. Installing needs a
/// [`PendingInstallId`], and the only thing that produces one is a successful
/// `PendingSlotState::begin_install`, which `EpochExhausted` refuses — so an
/// exhausted slot yields no install identity, hence no
/// `SelectedPendingInstall`, hence no CSQ insert and no queued pass.
pub const fn decide_pending_park(slot: PendingSlotState) -> PendingParkDecision {
    match slot {
        PendingSlotState::Vacant { .. } => PendingParkDecision::Install,
        PendingSlotState::EpochExhausted => {
            PendingParkDecision::CompleteAfterTerminal(TerminalRequest::PendingEpochExhausted)
        }
        PendingSlotState::Installing { .. }
        | PendingSlotState::Active { .. }
        | PendingSlotState::Quiescing { .. } => {
            PendingParkDecision::Refuse(PendingError::SlotOccupied)
        }
        // A parked fail-stop is not reusable and never becomes reusable. It is
        // still not an epoch-space exhaustion, so it refuses rather than
        // terminalizing the arrival with the wrong reason.
        PendingSlotState::PublicationFailStop { .. } => {
            PendingParkDecision::Refuse(PendingError::WrongRingState)
        }
    }
}

/// The exact completion an exhausted slot returns: `STATUS_INVALID_DEVICE_STATE`
/// with information zero.
///
/// Built through `ValidatedCompletion::prepare` like every other completion, so
/// the capacity check is the same one — an exhaustion is not a licence to
/// bypass validation.
pub const fn exhausted_pending_completion(
    capacity: usize,
    expected: usize,
) -> Result<ValidatedCompletion, CompletionValidationError> {
    ValidatedCompletion::prepare(STATUS_INVALID_DEVICE_STATE, 0, capacity, expected)
}

// ---------------------------------------------------------------------------
// R4 Task 17: the closed pending-install trace, its selection cut, and the
// exact reverse rollback
// ---------------------------------------------------------------------------
//
// The order is the content, so it lives here rather than in `fsring-fsd`: the
// same reason the R3 checkpoint roster moved into core. `fsring-fsd` supplies
// the WDK-typed payloads and performs one effect at a time; nothing about
// *which* effect comes next, *whether* it may refuse, or *what* a refusal owes
// back is expressible on the native side.

/// The closed production order for installing one parked ENTER.
///
/// Thirteen effects, and the boundary between the seventh and the eighth is the
/// selection cut: everything up to and including
/// [`PendingInstallEffect::SelectPendingDisposition`] may refuse and unwind,
/// and nothing after it can. That is not a comment — see
/// [`PendingSelectedEffect`], which has no refusal method to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingInstallEffect {
    ReservePendingSlotEpoch,
    AcquireStrongSessionReference,
    InitializeCancelVisibleOwners,
    PrepareFiniteTimer,
    LinkControlPendingInstalling,
    PreparePendingSelection,
    SelectPendingDisposition,
    PublishOwnedParkedAndSelectedRight,
    ArmPreparedFiniteTimer,
    InsertAndMarkCsq,
    ReleaseControlRundownAndAccessGuard,
    CommitHandoffDoneAndOwnerTransfer,
    QueueStoredWorkAfterUnlock,
}

/// The closed install order, as a constant a test can walk.
pub const PENDING_INSTALL_ORDER: [PendingInstallEffect; 13] = [
    PendingInstallEffect::ReservePendingSlotEpoch,
    PendingInstallEffect::AcquireStrongSessionReference,
    PendingInstallEffect::InitializeCancelVisibleOwners,
    PendingInstallEffect::PrepareFiniteTimer,
    PendingInstallEffect::LinkControlPendingInstalling,
    PendingInstallEffect::PreparePendingSelection,
    PendingInstallEffect::SelectPendingDisposition,
    PendingInstallEffect::PublishOwnedParkedAndSelectedRight,
    PendingInstallEffect::ArmPreparedFiniteTimer,
    PendingInstallEffect::InsertAndMarkCsq,
    PendingInstallEffect::ReleaseControlRundownAndAccessGuard,
    PendingInstallEffect::CommitHandoffDoneAndOwnerTransfer,
    PendingInstallEffect::QueueStoredWorkAfterUnlock,
];

/// The index of the last effect that may refuse.
const PENDING_INSTALL_CUT: usize = 6;

/// The authorities a refused pre-selection install owes back, in the exact
/// order it owes them.
///
/// Control is unlinked first so no new arrival can reach a half-built install;
/// the owners go next because a callback holding one could still run; then the
/// park tuple, the role, and the result reservation, which are the affine
/// values the caller handed in; then the strong reference; then the native
/// observations; and only then is the slot republished as reusable. Publishing
/// a vacant slot earlier would advertise reuse while an owner was still live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingInstallRollbackEffect {
    UnlinkControl,
    AbortOwners,
    AbortUnpublishedPark,
    ReleaseSqWaitRole,
    AbortResultReservation,
    ReleaseStrongReference,
    ClearNativeObservations,
    PublishVacantOrExhausted,
}

/// The closed rollback order, as a constant a test can walk.
pub const PENDING_INSTALL_ROLLBACK_ORDER: [PendingInstallRollbackEffect; 8] = [
    PendingInstallRollbackEffect::UnlinkControl,
    PendingInstallRollbackEffect::AbortOwners,
    PendingInstallRollbackEffect::AbortUnpublishedPark,
    PendingInstallRollbackEffect::ReleaseSqWaitRole,
    PendingInstallRollbackEffect::AbortResultReservation,
    PendingInstallRollbackEffect::ReleaseStrongReference,
    PendingInstallRollbackEffect::ClearNativeObservations,
    PendingInstallRollbackEffect::PublishVacantOrExhausted,
];

impl PendingInstallEffect {
    const fn index(self) -> usize {
        match self {
            Self::ReservePendingSlotEpoch => 0,
            Self::AcquireStrongSessionReference => 1,
            Self::InitializeCancelVisibleOwners => 2,
            Self::PrepareFiniteTimer => 3,
            Self::LinkControlPendingInstalling => 4,
            Self::PreparePendingSelection => 5,
            Self::SelectPendingDisposition => 6,
            Self::PublishOwnedParkedAndSelectedRight => 7,
            Self::ArmPreparedFiniteTimer => 8,
            Self::InsertAndMarkCsq => 9,
            Self::ReleaseControlRundownAndAccessGuard => 10,
            Self::CommitHandoffDoneAndOwnerTransfer => 11,
            Self::QueueStoredWorkAfterUnlock => 12,
        }
    }

    /// Whether this effect is on the refusable side of the selection cut.
    pub const fn may_refuse(self) -> bool {
        self.index() <= PENDING_INSTALL_CUT
    }

    /// The rollback effects completing this one makes owed.
    ///
    /// A closed table rather than a rule: `PrepareFiniteTimer` records a due
    /// time and clears the exit event without arming anything, so it owes
    /// nothing of its own — its DPC owner is an *owner*, already covered by
    /// `AbortOwners`. That is the whole of "rollback never arms a timer".
    const fn owed_rollback(self) -> &'static [PendingInstallRollbackEffect] {
        match self {
            Self::ReservePendingSlotEpoch => {
                &[PendingInstallRollbackEffect::PublishVacantOrExhausted]
            }
            Self::AcquireStrongSessionReference => {
                &[PendingInstallRollbackEffect::ReleaseStrongReference]
            }
            Self::InitializeCancelVisibleOwners => &[PendingInstallRollbackEffect::AbortOwners],
            Self::PrepareFiniteTimer => &[],
            Self::LinkControlPendingInstalling => &[PendingInstallRollbackEffect::UnlinkControl],
            Self::PreparePendingSelection => &[
                PendingInstallRollbackEffect::AbortUnpublishedPark,
                PendingInstallRollbackEffect::ReleaseSqWaitRole,
                PendingInstallRollbackEffect::AbortResultReservation,
                PendingInstallRollbackEffect::ClearNativeObservations,
            ],
            Self::SelectPendingDisposition => &[],
            Self::PublishOwnedParkedAndSelectedRight
            | Self::ArmPreparedFiniteTimer
            | Self::InsertAndMarkCsq
            | Self::ReleaseControlRundownAndAccessGuard
            | Self::CommitHandoffDoneAndOwnerTransfer
            | Self::QueueStoredWorkAfterUnlock => &[],
        }
    }
}

impl PendingInstallRollbackEffect {
    const fn index(self) -> usize {
        match self {
            Self::UnlinkControl => 0,
            Self::AbortOwners => 1,
            Self::AbortUnpublishedPark => 2,
            Self::ReleaseSqWaitRole => 3,
            Self::AbortResultReservation => 4,
            Self::ReleaseStrongReference => 5,
            Self::ClearNativeObservations => 6,
            Self::PublishVacantOrExhausted => 7,
        }
    }

    const fn mask_bit(self) -> u8 {
        1u8 << self.index()
    }
}

/// One refusable effect on the pre-selection side of the cut.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingPreselectEffect {
    install: PendingInstallId,
    next: u8,
    completed: u16,
}

/// One infallible effect on the selected side of the cut.
///
/// This type deliberately has **no** `refused` constructor. The property
/// `selected_suffix_has_no_refusal_edge` is therefore not an assertion a future
/// edit could weaken; a suffix that wanted to refuse would have nothing to
/// call, and the native trait method it came from returns `()`.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingSelectedEffect {
    install: PendingInstallId,
    next: u8,
    completed: u16,
}

/// A fully installed parked ENTER: all thirteen effects ran.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct InstalledPendingEnter {
    install: PendingInstallId,
    completed: u16,
}

/// Where one install is in its choreography.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum PendingInstallProgress {
    Preselect(PendingPreselectEffect),
    Selected(PendingSelectedEffect),
    Installed(InstalledPendingEnter),
    Rollback(PendingInstallRollbackPlan),
}

/// The reverse unwind owed by one refused pre-selection install.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingInstallRollbackPlan {
    install: PendingInstallId,
    refused_at: PendingInstallEffect,
    owed: u8,
    next: u8,
}

/// One reverse effect the native side must now perform.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct PendingRollbackEffectStep {
    plan: PendingInstallRollbackPlan,
    effect: PendingInstallRollbackEffect,
}

/// A rollback that gave every owed authority back.
#[must_use]
#[cfg_attr(test, derive(Debug))]
pub struct CompletedPendingRollback {
    install: PendingInstallId,
    refused_at: PendingInstallEffect,
    owed: u8,
}

#[must_use]
#[cfg_attr(test, derive(Debug))]
pub enum PendingRollbackProgress {
    Effect(PendingRollbackEffectStep),
    /// One reverse stage refused. The plan is returned whole so a retry
    /// resumes at exactly this stage rather than replaying the ones that
    /// already gave their value back.
    Stalled(PendingInstallRollbackPlan),
    Complete(CompletedPendingRollback),
}

impl PendingInstallProgress {
    /// Begin the closed install trace for one install identity.
    ///
    /// Named `begin_pending_install` rather than `begin` deliberately: the
    /// production-graph gate models an edge as a mention of a bare function
    /// name, so a method called `begin` merges with the eighteen other `begin`s
    /// across the two source roots and cannot be staged as a target. A staged
    /// surface whose only entry point is unguardable is a surface the gate
    /// silently stops covering.
    pub const fn begin_pending_install(install: PendingInstallId) -> Self {
        Self::Preselect(PendingPreselectEffect {
            install,
            next: 0,
            completed: 0,
        })
    }
}

impl PendingPreselectEffect {
    pub const fn effect(&self) -> PendingInstallEffect {
        // PROOF: `next` starts at 0 and `succeeded` hands the cursor to
        // `PendingSelectedEffect` rather than advancing past
        // `PENDING_INSTALL_CUT`, so this side never indexes beyond it.
        #[allow(clippy::indexing_slicing)]
        PENDING_INSTALL_ORDER[self.next as usize]
    }

    pub const fn install(&self) -> PendingInstallId {
        self.install
    }

    /// The native side performed this exact effect and it succeeded.
    pub fn succeeded(mut self) -> PendingInstallProgress {
        let effect = self.effect();
        self.completed |= 1u16 << effect.index();
        self.next = self.next.saturating_add(1);
        if usize::from(self.next) <= PENDING_INSTALL_CUT {
            return PendingInstallProgress::Preselect(self);
        }
        PendingInstallProgress::Selected(PendingSelectedEffect {
            install: self.install,
            next: self.next,
            completed: self.completed,
        })
    }

    /// The native side performed this exact effect and it refused.
    ///
    /// The refusing effect is *not* marked completed, so its own authority is
    /// never owed back — a reservation that failed did not reserve anything.
    pub fn refused(self) -> PendingInstallProgress {
        let refused_at = self.effect();
        let mut owed = 0u8;
        for candidate in PENDING_INSTALL_ORDER {
            if self.completed & (1u16 << candidate.index()) != 0 {
                for rollback in candidate.owed_rollback() {
                    owed |= rollback.mask_bit();
                }
            }
        }
        PendingInstallProgress::Rollback(PendingInstallRollbackPlan::begin(
            self.install,
            refused_at,
            owed,
        ))
    }
}

impl PendingSelectedEffect {
    pub const fn effect(&self) -> PendingInstallEffect {
        // PROOF: this cursor is only ever built past the cut and `performed`
        // returns `Installed` instead of advancing past the last entry.
        #[allow(clippy::indexing_slicing)]
        PENDING_INSTALL_ORDER[self.next as usize]
    }

    pub const fn install(&self) -> PendingInstallId {
        self.install
    }

    /// The native side performed this exact effect. There is no other outcome.
    pub fn performed(mut self) -> PendingInstallProgress {
        let effect = self.effect();
        self.completed |= 1u16 << effect.index();
        self.next = self.next.saturating_add(1);
        if usize::from(self.next) < PENDING_INSTALL_ORDER.len() {
            return PendingInstallProgress::Selected(self);
        }
        PendingInstallProgress::Installed(InstalledPendingEnter {
            install: self.install,
            completed: self.completed,
        })
    }
}

impl InstalledPendingEnter {
    pub const fn install(&self) -> PendingInstallId {
        self.install
    }

    /// Every one of the thirteen effects ran, in order.
    pub const fn ran_the_closed_order(&self) -> bool {
        self.completed == all_pending_install_effects_mask()
    }
}

/// One bit per entry of [`PENDING_INSTALL_ORDER`].
///
/// Folded rather than written as `(1 << len) - 1` so the crate-wide arithmetic
/// denial stays in force here: a shift-then-subtract would need an exception,
/// and this needs none.
const fn all_pending_install_effects_mask() -> u16 {
    let mut mask = 0u16;
    let mut index = 0usize;
    while index < PENDING_INSTALL_ORDER.len() {
        mask |= 1u16 << index;
        index = index.saturating_add(1);
    }
    mask
}

impl PendingInstallRollbackPlan {
    const fn begin(install: PendingInstallId, refused_at: PendingInstallEffect, owed: u8) -> Self {
        Self {
            install,
            refused_at,
            owed,
            next: 0,
        }
    }

    pub const fn install(&self) -> PendingInstallId {
        self.install
    }

    /// Which effect refused. Reported, never acted on: the owed set is derived
    /// from what completed, not from where the refusal happened.
    pub const fn refused_at(&self) -> PendingInstallEffect {
        self.refused_at
    }

    pub const fn owes(&self, effect: PendingInstallRollbackEffect) -> bool {
        self.owed & effect.mask_bit() != 0
    }

    /// Advance to the next owed reverse effect, skipping the ones this install
    /// never acquired.
    pub fn next(mut self) -> PendingRollbackProgress {
        while usize::from(self.next) < PENDING_INSTALL_ROLLBACK_ORDER.len() {
            // PROOF: the loop condition is the bound, and `self.next` only
            // grows inside it.
            #[allow(clippy::indexing_slicing)]
            let effect = PENDING_INSTALL_ROLLBACK_ORDER[self.next as usize];
            if self.owed & effect.mask_bit() != 0 {
                return PendingRollbackProgress::Effect(PendingRollbackEffectStep {
                    plan: self,
                    effect,
                });
            }
            self.next = self.next.saturating_add(1);
        }
        PendingRollbackProgress::Complete(CompletedPendingRollback {
            install: self.install,
            refused_at: self.refused_at,
            owed: self.owed,
        })
    }
}

impl PendingRollbackEffectStep {
    pub const fn effect(&self) -> PendingInstallRollbackEffect {
        self.effect
    }

    /// Whether the plan behind this step still owes `effect`.
    ///
    /// Exposed so a resumed rollback can be asked what it still holds, rather
    /// than inferred from the order it happens to walk in.
    pub const fn plan_owes(&self, effect: PendingInstallRollbackEffect) -> bool {
        self.plan.owes(effect)
    }

    pub fn succeeded(mut self) -> PendingRollbackProgress {
        self.plan.next = self.plan.next.saturating_add(1);
        self.plan.next()
    }

    /// This reverse stage refused and returned its exact affine value.
    ///
    /// The cursor does not advance, so a retry resumes here. Nothing later is
    /// attempted: a stage that still owns a value cannot be stepped over.
    pub fn refused(self) -> PendingRollbackProgress {
        PendingRollbackProgress::Stalled(self.plan)
    }
}

impl CompletedPendingRollback {
    pub const fn install(&self) -> PendingInstallId {
        self.install
    }

    pub const fn refused_at(&self) -> PendingInstallEffect {
        self.refused_at
    }

    pub const fn returned(&self, effect: PendingInstallRollbackEffect) -> bool {
        self.owed & effect.mask_bit() != 0
    }
}
