//! Pure affine SETUP publication, registry, control-binding, and fence plans.

use core::num::{NonZeroU32, NonZeroU64};
use core::sync::atomic::{AtomicU64, Ordering};
use fsring_abi::validate::SessionIdentity;

use crate::adapter::fence::PreparedMountDeactivation;
use crate::adapter::lifecycle::LifecycleError;

macro_rules! private_authority_seals {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug)]
            #[cfg_attr(test, derive(PartialEq, Eq))]
            struct $name(());
        )+
    };
}

/// One affine SETUP attempt before its single terminal decision.
#[derive(Debug)]
pub struct SetupTransaction {
    staging: StagingSession,
    terminal: SetupTerminalRight,
}

/// The unpublished session state accumulated by a SETUP attempt.
#[derive(Debug)]
pub struct StagingSession {
    identity: SessionIdentity,
    stage: SetupStage,
    resource_bits: u64,
}

/// Proof that the SETUP Release publication won.
#[derive(Debug)]
pub struct PublishedSession {
    locator: SessionLocator,
    registry: RegistryLease,
    control: StrongSessionRef,
}

/// Proof that one unpublished SETUP was rolled back without reusing identity.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RollbackReceipt {
    burned_identity: SessionIdentity,
    last_stage: SetupStage,
}

#[derive(Debug)]
pub struct SetupTerminalRight(());

/// A failed consuming SETUP transition together with the exact returned right.
#[derive(Debug)]
pub struct SetupTransitionFailure {
    error: SessionError,
    transaction: SetupTransaction,
}

/// The strict fallible SETUP prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStage {
    IdentityBurned,
    LayoutPlanned,
    SectionReady,
    GrantsReady,
    VolumeReady,
    ViewsReady,
    OutputReady,
    ReferencesInstalled,
}

/// Why an unpublished SETUP consumes its rollback terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupFailure {
    Cancelled,
    Resource,
    NativeEffect,
    OutputValidation,
    Unload,
}

/// Closed errors for the pure session model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    ControlBindingIdExhausted,
    DuplicateSetup,
    InvalidTransition,
    IdentityMismatch,
    RegistryClosed,
    RegistryFull,
    ReferenceNotFound,
    ReferenceExhausted,
    SetupEpochExhausted,
}

const fn stage_prefix(stage: SetupStage) -> u64 {
    match stage {
        SetupStage::IdentityBurned => 0x01,
        SetupStage::LayoutPlanned => 0x03,
        SetupStage::SectionReady => 0x07,
        SetupStage::GrantsReady => 0x0f,
        SetupStage::VolumeReady => 0x1f,
        SetupStage::ViewsReady => 0x3f,
        SetupStage::OutputReady => 0x7f,
        SetupStage::ReferencesInstalled => 0xff,
    }
}

const fn is_next_stage(current: SetupStage, requested: SetupStage) -> bool {
    matches!(
        (current, requested),
        (SetupStage::IdentityBurned, SetupStage::LayoutPlanned)
            | (SetupStage::LayoutPlanned, SetupStage::SectionReady)
            | (SetupStage::SectionReady, SetupStage::GrantsReady)
            | (SetupStage::GrantsReady, SetupStage::VolumeReady)
            | (SetupStage::VolumeReady, SetupStage::ViewsReady)
            | (SetupStage::ViewsReady, SetupStage::OutputReady)
            | (SetupStage::OutputReady, SetupStage::ReferencesInstalled)
    )
}

const fn valid_identity(identity: SessionIdentity) -> bool {
    identity.mount_id.lo != 0
        && identity.mount_id.hi != 0
        && (identity.boot_instance_id.lo != 0 || identity.boot_instance_id.hi != 0)
        && identity.session_epoch != 0
}

impl SetupTransaction {
    /// Burn a validated nonzero identity into a fresh affine transaction.
    pub fn begin(identity: SessionIdentity) -> Result<Self, SessionError> {
        if !valid_identity(identity) {
            return Err(SessionError::IdentityMismatch);
        }
        Ok(Self {
            staging: StagingSession {
                identity,
                stage: SetupStage::IdentityBurned,
                resource_bits: stage_prefix(SetupStage::IdentityBurned),
            },
            terminal: SetupTerminalRight(()),
        })
    }

    /// Advance exactly one fallible SETUP stage, returning the right on refusal.
    pub fn stage(mut self, stage: SetupStage) -> Result<Self, SetupTransitionFailure> {
        if !is_next_stage(self.staging.stage, stage)
            || self.staging.resource_bits != stage_prefix(self.staging.stage)
        {
            return Err(SetupTransitionFailure {
                error: SessionError::InvalidTransition,
                transaction: self,
            });
        }
        self.staging.stage = stage;
        self.staging.resource_bits = stage_prefix(stage);
        Ok(self)
    }

    /// Consume the sole terminal right into a sealed rollback receipt.
    pub fn rollback(self, reason: SetupFailure) -> RollbackReceipt {
        let _ = reason;
        let SetupTerminalRight(()) = self.terminal;
        RollbackReceipt {
            burned_identity: self.staging.identity,
            last_stage: self.staging.stage,
        }
    }
}

impl SetupTransitionFailure {
    /// The refusal reason.
    pub const fn error(&self) -> SessionError {
        self.error
    }

    /// Recover the exact transaction authority supplied to the failed call.
    pub fn into_transaction(self) -> SetupTransaction {
        self.transaction
    }
}

impl PublishedSession {
    /// The generation-stamped locator committed by this publication proof.
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Transfer the committed locator and its two exact live authorities.
    pub fn into_parts(self) -> (SessionLocator, RegistryLease, StrongSessionRef) {
        (self.locator, self.registry, self.control)
    }
}

/// The nonwrapping ordinal burned before a SETUP selects a registry cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupEpoch(u64);

/// The private brand that prevents authorities from crossing control files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControlBindingId(NonZeroU64);

/// The next setup epoch or permanent exhaustion of the per-file counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupEpochCursor {
    Next(SetupEpoch),
    Exhausted,
}

/// Why a live generation reached its immutable terminal result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalReason {
    Cleanup,
    ProcessLoss,
    ProtocolAbort,
    Unload,
    PendingEpochExhausted,
    CreditGenerationExhausted,
    SqGenerationExhausted,
    ProtocolFault,
}

/// The bounded, copyable result observed after terminal completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalResult {
    pub reason: TerminalReason,
    pub fence_failures: u16,
}

/// The closed classes of permanent terminal fail-stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalBlockedClass {
    FenceInvariant,
    DeleteInvariant,
}

/// A copyable terminal request that does not include authenticated protocol
/// abort. The latter is introduced only with the committed-packet path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalRequest {
    Cleanup,
    ProcessLoss,
    Unload,
    PendingEpochExhausted,
    CreditGenerationExhausted,
    SqGenerationExhausted,
    ProtocolFault,
}

impl TerminalRequest {
    const fn reason(self) -> TerminalReason {
        match self {
            Self::Cleanup => TerminalReason::Cleanup,
            Self::ProcessLoss => TerminalReason::ProcessLoss,
            Self::Unload => TerminalReason::Unload,
            Self::PendingEpochExhausted => TerminalReason::PendingEpochExhausted,
            Self::CreditGenerationExhausted => TerminalReason::CreditGenerationExhausted,
            Self::SqGenerationExhausted => TerminalReason::SqGenerationExhausted,
            Self::ProtocolFault => TerminalReason::ProtocolFault,
        }
    }
}

/// A bounded diagnostic correlation label. It grants no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticId(NonZeroU32);

impl DiagnosticId {
    /// Visible to sibling modules' tests since Task 19: a checkpoint blocked
    /// payload is built from a locator's own label, and a test that could not
    /// name one would have to reach for a winner it does not otherwise need.
    /// It grants no authority -- it is a correlation label.
    pub(crate) const fn for_locator(locator: SessionLocator) -> Self {
        let folded = (locator.generation as u32)
            ^ ((locator.generation >> 32) as u32).rotate_left(13)
            ^ locator.slot_index.rotate_left(7)
            ^ 0xC4D1_A601;
        let value = if folded == 0 { 1 } else { folded };
        let Some(value) = NonZeroU32::new(value) else {
            panic!()
        };
        Self(value)
    }
}

/// The permanent delete preflight step vocabulary shared by later cutovers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizerPreflightStep {
    CoreDeleting,
    MirrorAndShell,
    ShellAndRootOwnership,
    ClosingContextAndLease,
    EmptyCompletedRecord,
    OpenOutcomeAndJoinAdmission,
    RunningDepositAndPublisher,
}

/// The two payloads a permanently blocked generation can carry.
///
/// Task 5 left this uninhabited in production on purpose: a checkpoint that
/// could publish `Blocked` before the typed payloads existed would be
/// publishing a fail-stop nobody could read. Task 10 fills it in with exactly
/// the two the R3 binary can produce — a checkpoint refusal and a deletion
/// preflight refusal — and no more. The arms stay private so no downstream
/// caller can name one and mint an observation from an address it happens to
/// hold; the two bridges below are the only constructors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateTerminalBlocked {
    Fence {
        locator: SessionLocator,
        blocked: crate::adapter::fence::FenceTerminalBlocked,
    },
    Delete {
        locator: SessionLocator,
        blocked: crate::adapter::fence::DeleteTerminalBlocked,
    },
}

/// A sealed, nonowning blocked observation.
///
/// It carries the exact locator brand, a closed class, and the bounded
/// diagnostic — and nothing else. No pointer, no retained packet, and no
/// retry/finish/delete/unload authority: publishing one must never move an
/// authority out of the fail-stop packet that keeps the generation retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalBlocked {
    inner: PrivateTerminalBlocked,
}

impl TerminalBlocked {
    /// The one bridge from a fence fail-stop. It takes the whole payload.
    #[doc(hidden)]
    pub const fn from_fence(
        locator: SessionLocator,
        blocked: crate::adapter::fence::FenceTerminalBlocked,
    ) -> Self {
        Self {
            inner: PrivateTerminalBlocked::Fence { locator, blocked },
        }
    }

    /// The one bridge from a deletion-preflight refusal.
    #[doc(hidden)]
    pub const fn from_delete(
        locator: SessionLocator,
        blocked: crate::adapter::fence::DeleteTerminalBlocked,
    ) -> Self {
        Self {
            inner: PrivateTerminalBlocked::Delete { locator, blocked },
        }
    }

    pub const fn locator(&self) -> SessionLocator {
        match self.inner {
            PrivateTerminalBlocked::Fence { locator, .. }
            | PrivateTerminalBlocked::Delete { locator, .. } => locator,
        }
    }

    pub const fn class(&self) -> TerminalBlockedClass {
        match self.inner {
            PrivateTerminalBlocked::Fence { .. } => TerminalBlockedClass::FenceInvariant,
            PrivateTerminalBlocked::Delete { .. } => TerminalBlockedClass::DeleteInvariant,
        }
    }

    pub const fn diagnostic(&self) -> DiagnosticId {
        match self.inner {
            PrivateTerminalBlocked::Fence { blocked, .. } => blocked.diagnostic(),
            PrivateTerminalBlocked::Delete { blocked, .. } => blocked.diagnostic(),
        }
    }

    fn matches(self, locator: SessionLocator, diagnostic: DiagnosticId) -> bool {
        self.locator() == locator && self.diagnostic() == diagnostic
    }

    #[cfg(test)]
    fn locator_matches(self, locator: SessionLocator) -> bool {
        self.locator() == locator
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalRendezvousOutcome {
    Open,
    Completed(TerminalResult),
    Blocked(TerminalBlocked),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalClosedOutcome {
    Completed(TerminalResult),
    Blocked(TerminalBlocked),
}

private_authority_seals!(
    PrivateTerminalWinnerAuthority,
    PrivateTerminalJoinAuthority,
    PrivateTerminalOutcomeSignalAuthority,
    PrivateTerminalJoinersDrainedSignalAuthority,
    PrivateStoredFailStopReceiptAuthority,
    PrivateCommittedStoredFailStopResolutionAuthority,
);

#[derive(Debug)]
pub struct TerminalWinner {
    locator: SessionLocator,
    reason: TerminalReason,
    diagnostic: DiagnosticId,
    authority: PrivateTerminalWinnerAuthority,
}

#[derive(Debug)]
pub struct TerminalJoinTicket {
    locator: SessionLocator,
    authority: PrivateTerminalJoinAuthority,
}

pub struct TerminalWinnerClaim {
    winner: TerminalWinner,
    join: TerminalJoinTicket,
}

pub enum TerminalJoinClaim {
    Join(TerminalJoinTicket),
    Completed(TerminalResult),
    Blocked(TerminalBlocked),
}

#[derive(Debug)]
pub struct TerminalOutcomeSignal {
    locator: SessionLocator,
    authority: PrivateTerminalOutcomeSignalAuthority,
}

#[derive(Debug)]
pub struct TerminalJoinersDrainedSignal {
    locator: SessionLocator,
    authority: PrivateTerminalJoinersDrainedSignalAuthority,
}

pub enum TerminalJoinRelease {
    Open(TerminalJoinTicket),
    Released {
        outcome: TerminalClosedOutcome,
        drained: Option<TerminalJoinersDrainedSignal>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateTerminalRendezvousState {
    Inactive,
    Open {
        locator: SessionLocator,
        admitted: u32,
    },
    Closed {
        locator: SessionLocator,
        admitted: u32,
        outcome: TerminalClosedOutcome,
    },
    OpaqueRetained {
        locator: SessionLocator,
        admitted: u32,
    },
}

pub struct TerminalRendezvous {
    state: PrivateTerminalRendezvousState,
}

impl TerminalWinner {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    pub const fn reason(&self) -> TerminalReason {
        self.reason
    }

    pub const fn diagnostic(&self) -> DiagnosticId {
        self.diagnostic
    }
}

impl TerminalJoinTicket {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

impl TerminalWinnerClaim {
    pub fn into_parts(self) -> (TerminalWinner, TerminalJoinTicket) {
        (self.winner, self.join)
    }
}

impl TerminalOutcomeSignal {
    pub fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateTerminalOutcomeSignalAuthority(()),
        } = self;
        locator
    }
}

impl TerminalJoinersDrainedSignal {
    pub fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateTerminalJoinersDrainedSignalAuthority(()),
        } = self;
        locator
    }
}

impl TerminalRendezvous {
    #[doc(hidden)]
    /// The private phase, for a test that must prove a refusal moved nothing.
    ///
    /// `#[cfg(test)]`: the phase is private because no production caller may
    /// branch on it -- every transition goes through a checked method. A test
    /// asserting "the four objects are byte-for-byte as they were" has to be
    /// able to see it, and comparing something it derived itself instead is the
    /// trap this session hit three times.
    ///
    /// Rendered rather than returned, because the phase type itself is private
    /// to this module and a sibling test module cannot name it. The rendering
    /// is a *reading* of the private value -- not a fingerprint the test
    /// computes -- so a phase that changed shows up as a different string.
    #[cfg(test)]
    pub(crate) fn state_debug_for_test(&self) -> std::string::String {
        std::format!("{:?}", self.state)
    }

    pub const fn new_inactive() -> Self {
        Self {
            state: PrivateTerminalRendezvousState::Inactive,
        }
    }

    /// Narrow read-only effect-nine observation. Native code can call this
    /// only through its registry-lock-derived cell borrow; it exposes neither
    /// a locator nor any terminal owner/ticket.
    pub const fn r3_unload_is_inactive(&self) -> bool {
        matches!(self.state, PrivateTerminalRendezvousState::Inactive)
    }

    /// Effect-nine's independent join-ledger observation. It intentionally
    /// exposes no locator or ticket and is consumed only while the native
    /// registry lock keeps the rendezvous stable.
    pub const fn r3_unload_joiners_are_drained(&self) -> bool {
        match self.state {
            PrivateTerminalRendezvousState::Inactive => true,
            PrivateTerminalRendezvousState::Open { admitted, .. }
            | PrivateTerminalRendezvousState::Closed { admitted, .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { admitted, .. } => admitted == 0,
        }
    }

    const fn activation_preflight(&self) -> Result<(), LifecycleError> {
        match self.state {
            PrivateTerminalRendezvousState::Inactive => Ok(()),
            PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::Closed { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                Err(LifecycleError::WrongState)
            }
        }
    }

    fn commit_activation(&mut self, locator: SessionLocator) {
        if !matches!(self.state, PrivateTerminalRendezvousState::Inactive) {
            unreachable!("activation was preflighted before the locked suffix")
        }
        self.state = PrivateTerminalRendezvousState::Open {
            locator,
            admitted: 0,
        };
    }

    // Task 5 keeps this callable only inside core; the coupled publisher uses
    // the preflight/commit halves, and later native wrappers use this exact
    // transition. It therefore has no non-test caller at this checkpoint.
    #[allow(dead_code)]
    pub(crate) fn activate(&mut self, locator: SessionLocator) -> Result<(), LifecycleError> {
        self.activation_preflight()?;
        self.commit_activation(locator);
        Ok(())
    }

    pub fn claim(
        &mut self,
        locator: SessionLocator,
        request: TerminalRequest,
    ) -> Result<TerminalWinnerClaim, LifecycleError> {
        match self.state {
            PrivateTerminalRendezvousState::Inactive => Err(LifecycleError::WrongState),
            PrivateTerminalRendezvousState::Open {
                locator: current, ..
            }
            | PrivateTerminalRendezvousState::Closed {
                locator: current, ..
            }
            | PrivateTerminalRendezvousState::OpaqueRetained {
                locator: current, ..
            } if current != locator => Err(LifecycleError::WrongLocator),
            PrivateTerminalRendezvousState::Open { admitted: 0, .. } => {
                self.state = PrivateTerminalRendezvousState::Open {
                    locator,
                    admitted: 1,
                };
                let reason = request.reason();
                Ok(TerminalWinnerClaim {
                    winner: TerminalWinner {
                        locator,
                        reason,
                        diagnostic: DiagnosticId::for_locator(locator),
                        authority: PrivateTerminalWinnerAuthority(()),
                    },
                    join: TerminalJoinTicket {
                        locator,
                        authority: PrivateTerminalJoinAuthority(()),
                    },
                })
            }
            PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::Closed { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                Err(LifecycleError::FinalizerBusy)
            }
        }
    }

    pub fn join(&mut self, locator: SessionLocator) -> Result<TerminalJoinClaim, LifecycleError> {
        match self.state {
            PrivateTerminalRendezvousState::Inactive => Err(LifecycleError::WrongState),
            PrivateTerminalRendezvousState::Open {
                locator: current, ..
            }
            | PrivateTerminalRendezvousState::Closed {
                locator: current, ..
            }
            | PrivateTerminalRendezvousState::OpaqueRetained {
                locator: current, ..
            } if current != locator => Err(LifecycleError::WrongLocator),
            PrivateTerminalRendezvousState::Open { admitted: 0, .. } => {
                Err(LifecycleError::AdmissionClosed)
            }
            PrivateTerminalRendezvousState::Open { admitted, .. } => {
                let Some(next) = admitted.checked_add(1) else {
                    return Err(LifecycleError::JoinerOverflow);
                };
                self.state = PrivateTerminalRendezvousState::Open {
                    locator,
                    admitted: next,
                };
                Ok(TerminalJoinClaim::Join(TerminalJoinTicket {
                    locator,
                    authority: PrivateTerminalJoinAuthority(()),
                }))
            }
            PrivateTerminalRendezvousState::Closed { outcome, .. } => match outcome {
                TerminalClosedOutcome::Completed(result) => {
                    Ok(TerminalJoinClaim::Completed(result))
                }
                TerminalClosedOutcome::Blocked(blocked) => Ok(TerminalJoinClaim::Blocked(blocked)),
            },
            PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                Err(LifecycleError::WrongState)
            }
        }
    }

    pub fn close_and_publish_completed(
        &mut self,
        winner: TerminalWinner,
        result: TerminalResult,
    ) -> Result<TerminalOutcomeSignal, (LifecycleError, TerminalWinner, TerminalResult)> {
        let preflight = match self.state {
            PrivateTerminalRendezvousState::Open { locator, admitted }
                if locator == winner.locator && admitted > 0 =>
            {
                if result.reason == winner.reason {
                    Ok((locator, admitted))
                } else {
                    Err(LifecycleError::Invariant)
                }
            }
            PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::Closed { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. }
                if self.r3_locked_locator() != Some(winner.locator) =>
            {
                Err(LifecycleError::WrongLocator)
            }
            PrivateTerminalRendezvousState::Inactive
            | PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::Closed { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                Err(LifecycleError::WrongState)
            }
        };
        let (locator, admitted) = match preflight {
            Ok(parts) => parts,
            Err(error) => return Err((error, winner, result)),
        };
        let TerminalWinner {
            authority: PrivateTerminalWinnerAuthority(()),
            ..
        } = winner;
        self.state = PrivateTerminalRendezvousState::Closed {
            locator,
            admitted,
            outcome: TerminalClosedOutcome::Completed(result),
        };
        Ok(TerminalOutcomeSignal {
            locator,
            authority: PrivateTerminalOutcomeSignalAuthority(()),
        })
    }

    /// Consume a preflighted winner in the post-destruction suffix.
    ///
    /// # Safety
    /// The caller already proved this exact rendezvous is Open for `winner`,
    /// the winner remains admitted, and `result` is its authenticated result.
    /// Join growth is allowed between preflight and this call, so the current
    /// admitted count is copied at the commit itself.
    pub unsafe fn close_and_publish_completed_prepared(
        &mut self,
        winner: TerminalWinner,
        result: TerminalResult,
    ) -> TerminalOutcomeSignal {
        let locator = winner.locator;
        let admitted = self.admitted_for_locator(locator);
        let TerminalWinner {
            authority: PrivateTerminalWinnerAuthority(()),
            ..
        } = winner;
        self.state = PrivateTerminalRendezvousState::Closed {
            locator,
            admitted,
            outcome: TerminalClosedOutcome::Completed(result),
        };
        TerminalOutcomeSignal {
            locator,
            authority: PrivateTerminalOutcomeSignalAuthority(()),
        }
    }

    #[allow(clippy::result_large_err)]
    #[cfg(test)]
    pub(crate) fn close_and_publish_blocked(
        &mut self,
        winner: TerminalWinner,
        blocked: TerminalBlocked,
    ) -> Result<TerminalOutcomeSignal, (LifecycleError, TerminalWinner, TerminalBlocked)> {
        let preflight = match self.state {
            PrivateTerminalRendezvousState::Open { locator, admitted }
                if locator == winner.locator && admitted > 0 =>
            {
                if !blocked.locator_matches(locator) {
                    Err(LifecycleError::WrongLocator)
                } else if !blocked.matches(locator, winner.diagnostic) {
                    Err(LifecycleError::Invariant)
                } else {
                    Ok((locator, admitted))
                }
            }
            PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::Closed { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. }
                if self.r3_locked_locator() != Some(winner.locator) =>
            {
                Err(LifecycleError::WrongLocator)
            }
            PrivateTerminalRendezvousState::Inactive
            | PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::Closed { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                Err(LifecycleError::WrongState)
            }
        };
        let (locator, admitted) = match preflight {
            Ok(parts) => parts,
            Err(error) => return Err((error, winner, blocked)),
        };
        let TerminalWinner {
            authority: PrivateTerminalWinnerAuthority(()),
            ..
        } = winner;
        self.state = PrivateTerminalRendezvousState::Closed {
            locator,
            admitted,
            outcome: TerminalClosedOutcome::Blocked(blocked),
        };
        Ok(TerminalOutcomeSignal {
            locator,
            authority: PrivateTerminalOutcomeSignalAuthority(()),
        })
    }

    pub fn release(
        &mut self,
        ticket: TerminalJoinTicket,
    ) -> Result<TerminalJoinRelease, (LifecycleError, TerminalJoinTicket)> {
        let current = match self.r3_locked_locator() {
            Some(current) => current,
            None => return Err((LifecycleError::WrongState, ticket)),
        };
        if current != ticket.locator {
            return Err((LifecycleError::WrongLocator, ticket));
        }
        match self.state {
            PrivateTerminalRendezvousState::Open { .. } => Ok(TerminalJoinRelease::Open(ticket)),
            PrivateTerminalRendezvousState::Closed {
                locator,
                admitted,
                outcome,
            } => {
                let Some(next) = admitted.checked_sub(1) else {
                    return Err((LifecycleError::JoinerUnderflow, ticket));
                };
                let TerminalJoinTicket {
                    authority: PrivateTerminalJoinAuthority(()),
                    ..
                } = ticket;
                self.state = PrivateTerminalRendezvousState::Closed {
                    locator,
                    admitted: next,
                    outcome,
                };
                Ok(TerminalJoinRelease::Released {
                    outcome,
                    drained: if next == 0 {
                        Some(TerminalJoinersDrainedSignal {
                            locator,
                            authority: PrivateTerminalJoinersDrainedSignalAuthority(()),
                        })
                    } else {
                        None
                    },
                })
            }
            PrivateTerminalRendezvousState::Inactive => Err((LifecycleError::WrongState, ticket)),
            PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                Err((LifecycleError::WrongState, ticket))
            }
        }
    }

    /// Narrow nonowning locator observation for a caller already holding the
    /// native registry lock. It mints no terminal ticket or owner.
    #[doc(hidden)]
    pub const fn r3_locked_locator(&self) -> Option<SessionLocator> {
        match self.state {
            PrivateTerminalRendezvousState::Inactive => None,
            PrivateTerminalRendezvousState::Open { locator, .. }
            | PrivateTerminalRendezvousState::Closed { locator, .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { locator, .. } => Some(locator),
        }
    }

    /// This exact generation's outcome, or `None` for any other generation.
    ///
    /// Nonowning and locator-checked: a caller that names a different
    /// generation gets no answer rather than another generation's answer.
    pub const fn outcome_for_locator(
        &self,
        locator: SessionLocator,
    ) -> Option<TerminalRendezvousOutcome> {
        match self.state {
            PrivateTerminalRendezvousState::Open {
                locator: current, ..
            } if locator_eq(current, locator) => Some(TerminalRendezvousOutcome::Open),
            PrivateTerminalRendezvousState::Closed {
                locator: current,
                outcome,
                ..
            } if locator_eq(current, locator) => Some(match outcome {
                TerminalClosedOutcome::Completed(result) => {
                    TerminalRendezvousOutcome::Completed(result)
                }
                TerminalClosedOutcome::Blocked(blocked) => {
                    TerminalRendezvousOutcome::Blocked(blocked)
                }
            }),
            PrivateTerminalRendezvousState::OpaqueRetained { .. } => None,
            _ => None,
        }
    }

    /// How many arrivals this exact generation has admitted. Zero for others.
    pub const fn admitted_for_locator(&self, locator: SessionLocator) -> u32 {
        match self.state {
            PrivateTerminalRendezvousState::Open {
                locator: current,
                admitted,
            }
            | PrivateTerminalRendezvousState::Closed {
                locator: current,
                admitted,
                ..
            }
            | PrivateTerminalRendezvousState::OpaqueRetained {
                locator: current,
                admitted,
            } if locator_eq(current, locator) => admitted,
            _ => 0,
        }
    }

    /// Native locked ingress for a process/unload path whose winner already
    /// moved the control binding. It can only mint a real counted Open-state
    /// join; closed and opaque states remain distinct observations.
    #[doc(hidden)]
    pub fn r3_join_open_locked(
        &mut self,
        locator: SessionLocator,
    ) -> Result<TerminalJoinTicket, LifecycleError> {
        match self.join(locator)? {
            TerminalJoinClaim::Join(ticket) => Ok(ticket),
            TerminalJoinClaim::Completed(_) | TerminalJoinClaim::Blocked(_) => {
                Err(LifecycleError::WrongState)
            }
        }
    }

    // The native prepared-delete wrapper lands after this decision-only
    // checkpoint. Tests exercise the exact reset guard now.
    #[allow(dead_code)]
    pub(crate) fn deactivate_after_delete(
        &mut self,
        prepared: &PreparedDeleteCoreCommit,
    ) -> Result<(), LifecycleError> {
        let locator = prepared.authority.locator();
        match self.state {
            PrivateTerminalRendezvousState::Closed {
                locator: current, ..
            } if current != locator => Err(LifecycleError::WrongLocator),
            PrivateTerminalRendezvousState::Closed {
                admitted,
                outcome: TerminalClosedOutcome::Completed(_),
                ..
            } if admitted != 0 => Err(LifecycleError::AdmissionClosed),
            PrivateTerminalRendezvousState::Closed {
                admitted: 0,
                outcome: TerminalClosedOutcome::Completed(_),
                ..
            } => {
                self.state = PrivateTerminalRendezvousState::Inactive;
                Ok(())
            }
            PrivateTerminalRendezvousState::Closed {
                outcome: TerminalClosedOutcome::Completed(_),
                ..
            } => Err(LifecycleError::AdmissionClosed),
            PrivateTerminalRendezvousState::Inactive
            | PrivateTerminalRendezvousState::Open { .. }
            | PrivateTerminalRendezvousState::OpaqueRetained { .. }
            | PrivateTerminalRendezvousState::Closed {
                outcome: TerminalClosedOutcome::Blocked(_),
                ..
            } => Err(LifecycleError::WrongState),
        }
    }

    /// Reset a preflighted, completed and fully drained generation.
    ///
    /// # Safety
    /// The final delete cursor proves publication, signalling and counted
    /// arrival drain all completed for this exact rendezvous.
    pub unsafe fn deactivate_after_delete_prepared(
        &mut self,
        right: crate::adapter::fence::TerminalRendezvousResetRight,
    ) {
        let locator = right.into_locator();
        let exact_completed_generation = matches!(
            self.state,
            PrivateTerminalRendezvousState::Closed {
                locator: current,
                admitted: 0,
                outcome: TerminalClosedOutcome::Completed(_),
            } if locator_eq(current, locator)
        );
        // SAFETY: the consuming final-delete cursor mints `right` only after
        // this exact generation published Completed and drained every counted
        // arrival. This is an infallible suffix precondition, not a fallible
        // post-destruction validation edge.
        unsafe { core::hint::assert_unchecked(exact_completed_generation) };
        self.state = PrivateTerminalRendezvousState::Inactive;
    }

    /// Authenticate one exact opaque quarantine without projecting a ticket
    /// or a terminal outcome. Task 6 uses this only while the registry lock is
    /// held to decide which permanent wait guard may be minted.
    pub const fn opaque_retained_admitted_for_locator(
        &self,
        locator: SessionLocator,
    ) -> Option<u32> {
        match self.state {
            PrivateTerminalRendezvousState::OpaqueRetained {
                locator: current,
                admitted,
            } if locator_eq(current, locator) => Some(admitted),
            _ => None,
        }
    }

    /// Release one authentic counted arrival from an opaque quarantine.
    ///
    /// Unlike ordinary terminal release this publishes no outcome. A foreign
    /// or exhausted ticket is returned intact so the native permanent-wait
    /// guard can retain it rather than fabricating a release.
    pub fn release_opaque_retained(
        &mut self,
        ticket: TerminalJoinTicket,
    ) -> Result<Option<TerminalJoinersDrainedSignal>, TerminalJoinTicket> {
        let PrivateTerminalRendezvousState::OpaqueRetained { locator, admitted } = self.state
        else {
            return Err(ticket);
        };
        if !locator_eq(locator, ticket.locator) || admitted == 0 {
            return Err(ticket);
        }
        let TerminalJoinTicket {
            locator: _,
            authority: PrivateTerminalJoinAuthority(()),
        } = ticket;
        // The refusal above already returned the ticket when `admitted == 0`,
        // so this release cannot underflow and saturating agrees with checked.
        let next = admitted.saturating_sub(1);
        self.state = PrivateTerminalRendezvousState::OpaqueRetained {
            locator,
            admitted: next,
        };
        Ok((next == 0).then_some(TerminalJoinersDrainedSignal {
            locator,
            authority: PrivateTerminalJoinersDrainedSignalAuthority(()),
        }))
    }
}

/// Copyable observation of one control-file binding. Native owners stay out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlBindingState {
    Empty(SetupEpochCursor),
    Staging(SetupEpoch),
    Active(SessionLocator),
    ClosingSetup(SetupEpoch),
    ClosingLive(SessionLocator),
    ClosingComplete {
        generation: u64,
        result: TerminalResult,
    },
    ClosingBlocked {
        locator: SessionLocator,
        class: TerminalBlockedClass,
    },
    ClosingOpaqueRetained {
        locator: SessionLocator,
    },
    Closed,
}

/// The affine reservation for one exact binding and setup epoch.
#[derive(Debug)]
pub struct SetupReservation {
    binding_id: ControlBindingId,
    setup_epoch: SetupEpoch,
}

/// CLEANUP's affine right to acknowledge one already-claimed setup epoch.
#[derive(Debug)]
pub struct SetupCleanupRight {
    binding_id: ControlBindingId,
    setup_epoch: SetupEpoch,
}

pub struct PreparedInstalledSetupRollback {
    transaction: SetupTransaction,
    reason: SetupFailure,
    reservation: SetupReservation,
    installed: InstalledSession,
    expected_closing: bool,
}

pub struct PreparedUninstalledSetupRollback {
    transaction: SetupTransaction,
    reason: SetupFailure,
    reservation: SetupReservation,
    expected_closing: bool,
}

pub struct PreparedReservedSetupRollback {
    reservation: SetupReservation,
    expected_closing: bool,
}

// The variants are the three rollback shapes, each carrying exactly the
// owners its stage must return. Boxing the largest would add an allocation
// to a refusal path whose whole point is that it consumes nothing.
#[allow(clippy::large_enum_variant)]
pub enum PreparedSetupRollback {
    Reserved(PreparedReservedSetupRollback),
    Installed(PreparedInstalledSetupRollback),
    Uninstalled(PreparedUninstalledSetupRollback),
}

#[derive(Debug)]
pub enum CleanupBindingClaim {
    Empty,
    Setup(SetupCleanupRight),
    NeedsLiveClaim(SessionLocator),
    JoinLive(SessionLocator),
    Completed {
        generation: u64,
        result: TerminalResult,
    },
    Blocked {
        locator: SessionLocator,
        class: TerminalBlockedClass,
    },
    OpaqueRetained {
        locator: SessionLocator,
    },
    AlreadyClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupRollbackDisposition {
    Reopened(SetupEpochCursor),
    RemainsClosing,
}

#[derive(Debug)]
pub struct SetupPublishFailure {
    error: SessionError,
    transaction: SetupTransaction,
    reservation: SetupReservation,
    installed: InstalledSession,
}

#[derive(Debug)]
pub struct PreparedSetupPublication {
    transaction: SetupTransaction,
    reservation: SetupReservation,
    installed: InstalledSession,
}

pub struct RegistryLiveSetup {
    locator: SessionLocator,
    registry: RegistryLease,
    control: StrongSessionRef,
    next: SetupBindingCommitRight,
}

pub struct SetupBindingCommitRight {
    locator: SessionLocator,
    reservation: SetupReservation,
    terminal: SetupTerminalRight,
}

pub struct SetupTerminalCommitRight {
    locator: SessionLocator,
    terminal: SetupTerminalRight,
}

pub struct SetupPublicationProof {
    locator: SessionLocator,
}

pub struct PrepareInstalledRollbackFailure {
    error: SessionError,
    transaction: SetupTransaction,
    reason: SetupFailure,
    reservation: SetupReservation,
    installed: InstalledSession,
}

pub struct PrepareUninstalledRollbackFailure {
    error: SessionError,
    transaction: SetupTransaction,
    reason: SetupFailure,
    reservation: SetupReservation,
}

impl SetupPublishFailure {
    pub const fn error(&self) -> SessionError {
        self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        SessionError,
        SetupTransaction,
        SetupReservation,
        InstalledSession,
    ) {
        (
            self.error,
            self.transaction,
            self.reservation,
            self.installed,
        )
    }
}

impl RegistryLiveSetup {
    pub fn into_parts(
        self,
    ) -> (
        SessionLocator,
        RegistryLease,
        StrongSessionRef,
        SetupBindingCommitRight,
    ) {
        (self.locator, self.registry, self.control, self.next)
    }
}

impl SetupPublicationProof {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }
}

impl PrepareInstalledRollbackFailure {
    pub fn into_parts(
        self,
    ) -> (
        SessionError,
        SetupTransaction,
        SetupFailure,
        SetupReservation,
        InstalledSession,
    ) {
        (
            self.error,
            self.transaction,
            self.reason,
            self.reservation,
            self.installed,
        )
    }
}

impl PrepareUninstalledRollbackFailure {
    pub fn into_parts(
        self,
    ) -> (
        SessionError,
        SetupTransaction,
        SetupFailure,
        SetupReservation,
    ) {
        (self.error, self.transaction, self.reason, self.reservation)
    }
}

static NEXT_CONTROL_BINDING_ID: AtomicU64 = AtomicU64::new(1);

/// One non-resettable control-file binding.
pub struct ControlBinding {
    binding_id: ControlBindingId,
    state: ControlBindingState,
}

impl ControlBinding {
    /// Construct an unbound control file with a fresh nonwrapping brand.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Result<Self, SessionError> {
        Self::new_from_id_source(&NEXT_CONTROL_BINDING_ID)
    }

    #[cfg(test)]
    // TEST: this fixture exists to reach the `Empty(Exhausted)` epoch cursor,
    // which is unreachable through the ordinary API without burning the whole
    // u64 binding-ID space. `Self::new()` can only fail on that same
    // exhaustion, and the process-wide source is fresh in a test binary, so the
    // `expect` documents an outcome the caller could not otherwise observe.
    // Production keeps the crate-wide denial.
    #[allow(clippy::expect_used)]
    pub(crate) fn exhausted_for_test() -> Self {
        let mut binding = Self::new().expect("the test binding source has capacity");
        binding.state = ControlBindingState::Empty(SetupEpochCursor::Exhausted);
        binding
    }

    fn new_from_id_source(source: &AtomicU64) -> Result<Self, SessionError> {
        let allocated = source
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if current == 0 {
                    None
                } else if current == u64::MAX {
                    Some(0)
                } else {
                    Some(current.saturating_add(1))
                }
            })
            .map_err(|_| SessionError::ControlBindingIdExhausted)?;
        let Some(binding_id) = NonZeroU64::new(allocated) else {
            unreachable!("the binding ID allocator never issues its exhausted sentinel")
        };
        Ok(Self {
            binding_id: ControlBindingId(binding_id),
            state: ControlBindingState::Empty(SetupEpochCursor::Next(SetupEpoch(1))),
        })
    }

    /// Burn the next epoch before any registry selection can occur.
    pub fn begin_setup(&mut self) -> Result<SetupReservation, SessionError> {
        match self.state {
            ControlBindingState::Empty(SetupEpochCursor::Next(setup_epoch)) => {
                self.state = ControlBindingState::Staging(setup_epoch);
                Ok(SetupReservation {
                    binding_id: self.binding_id,
                    setup_epoch,
                })
            }
            ControlBindingState::Empty(SetupEpochCursor::Exhausted) => {
                Err(SessionError::SetupEpochExhausted)
            }
            _ => Err(SessionError::DuplicateSetup),
        }
    }

    /// Claim CLEANUP's phase-specific action without resolving a live cell.
    pub fn claim_cleanup(&mut self) -> Result<CleanupBindingClaim, SessionError> {
        match self.state {
            ControlBindingState::Empty(_) => {
                self.state = ControlBindingState::Closed;
                Ok(CleanupBindingClaim::Empty)
            }
            ControlBindingState::Staging(setup_epoch) => {
                self.state = ControlBindingState::ClosingSetup(setup_epoch);
                Ok(CleanupBindingClaim::Setup(SetupCleanupRight {
                    binding_id: self.binding_id,
                    setup_epoch,
                }))
            }
            ControlBindingState::Active(locator) => {
                Ok(CleanupBindingClaim::NeedsLiveClaim(locator))
            }
            ControlBindingState::ClosingSetup(_) => Err(SessionError::InvalidTransition),
            ControlBindingState::ClosingLive(locator) => Ok(CleanupBindingClaim::JoinLive(locator)),
            ControlBindingState::ClosingComplete { generation, result } => {
                self.state = ControlBindingState::Closed;
                Ok(CleanupBindingClaim::Completed { generation, result })
            }
            ControlBindingState::ClosingBlocked { locator, class } => {
                Ok(CleanupBindingClaim::Blocked { locator, class })
            }
            ControlBindingState::ClosingOpaqueRetained { locator } => {
                Ok(CleanupBindingClaim::OpaqueRetained { locator })
            }
            ControlBindingState::Closed => Ok(CleanupBindingClaim::AlreadyClosed),
        }
    }

    /// Acknowledge the exact setup epoch after SETUP has completed its unwind.
    pub fn finish_setup_cleanup(
        &mut self,
        right: SetupCleanupRight,
    ) -> Result<(), (SessionError, SetupCleanupRight)> {
        if right.binding_id != self.binding_id {
            return Err((SessionError::IdentityMismatch, right));
        }
        match self.state {
            ControlBindingState::ClosingSetup(setup_epoch) if setup_epoch == right.setup_epoch => {
                self.state = ControlBindingState::Closed;
                Ok(())
            }
            ControlBindingState::ClosingSetup(_) => Err((SessionError::IdentityMismatch, right)),
            _ => Err((SessionError::InvalidTransition, right)),
        }
    }

    /// Move this binding from ClosingLive to ClosingComplete.
    ///
    /// The `record_present` argument is not a convenience: a ClosingComplete
    /// word with no completed record behind it is a generation CLEANUP could
    /// acknowledge and CLOSE could never free. The preflight below is the same
    /// one the finalizer's locked publication uses.
    #[doc(hidden)]
    pub fn publish_closing_complete(
        &mut self,
        locator: SessionLocator,
        result: TerminalResult,
        record_present: bool,
    ) -> Result<(), SessionError> {
        let prepared = prepare_closing_complete(self, locator, result, record_present)?;
        commit_prepared_closing_complete(prepared, self);
        Ok(())
    }

    /// Commit the already-preflighted ClosingLive -> ClosingComplete move.
    ///
    /// # Safety
    /// The caller owns the exact closing context and has installed its
    /// completed record under the same registry-lock hold.
    pub unsafe fn publish_closing_complete_prepared(
        &mut self,
        locator: SessionLocator,
        result: TerminalResult,
    ) {
        self.state = ControlBindingState::ClosingComplete {
            generation: locator.generation,
            result,
        };
    }

    /// Observe the data-only binding state.
    pub const fn state(&self) -> ControlBindingState {
        self.state
    }
}

#[cfg(test)]
impl SetupEpochCursor {
    pub(crate) const fn next_for_test(epoch: u64) -> Self {
        Self::Next(SetupEpoch(epoch))
    }
}

/// Locator equality usable from a `const fn`, where `PartialEq` is not.
const fn locator_eq(left: SessionLocator, right: SessionLocator) -> bool {
    left.slot_index == right.slot_index
        && left.generation == right.generation
        && identity_eq(left.identity, right.identity)
}

const fn identity_eq(left: SessionIdentity, right: SessionIdentity) -> bool {
    left.mount_id.lo == right.mount_id.lo
        && left.mount_id.hi == right.mount_id.hi
        && left.boot_instance_id.lo == right.boot_instance_id.lo
        && left.boot_instance_id.hi == right.boot_instance_id.hi
        && left.session_epoch == right.session_epoch
}

/// Copyable observation of one exact registry generation; it grants no ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLocator {
    slot_index: u32,
    generation: u64,
    identity: SessionIdentity,
}

impl SessionLocator {
    pub const fn slot_index(&self) -> u32 {
        self.slot_index
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    #[cfg(test)]
    pub(crate) const fn from_parts_for_test(
        slot_index: u32,
        generation: u64,
        identity: SessionIdentity,
    ) -> Self {
        Self {
            slot_index,
            generation,
            identity,
        }
    }
}

/// State of one registry-owned fixed-capacity cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrySlotState {
    Free,
    Staging,
    Live,
    Removing,
    Deleting,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotDisposition {
    Free,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegistrySlot {
    generation: u64,
    identity: Option<SessionIdentity>,
    state: RegistrySlotState,
    strong_count: u32,
    fence_done: bool,
}

impl RegistrySlot {
    const FREE: Self = Self {
        generation: 0,
        identity: None,
        state: RegistrySlotState::Free,
        strong_count: 0,
        fence_done: false,
    };
}

/// The private complete authority carried by every affine registry right.
#[derive(Debug, PartialEq, Eq)]
struct SessionAuthority {
    slot_index: u32,
    generation: u64,
    identity: SessionIdentity,
}

impl SessionAuthority {
    const fn locator(&self) -> SessionLocator {
        SessionLocator {
            slot_index: self.slot_index,
            generation: self.generation,
            identity: self.identity,
        }
    }
}

/// An allocation-free registry with owned fixed backing.
pub struct SessionRegistry<const N: usize> {
    admission_open: bool,
    slots: [RegistrySlot; N],
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct RegistryLease {
    authority: SessionAuthority,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct StrongSessionRef {
    authority: SessionAuthority,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct TerminalSessionRef {
    authority: SessionAuthority,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct DeleteSessionRight {
    authority: SessionAuthority,
}

private_authority_seals!(
    PrivateNativeOwnerBindRightsAuthority,
    PrivateNativeSessionOwnerBindAuthority,
    PrivateSessionRootReleaseBindAuthority,
    PrivateR3FinalizerCellBindAuthority,
);

/// The one install-origin capability bundle for native owner and finalizer
/// storage binding. It is created with `InstalledSession`, stored inside it,
/// and can never be reconstructed from its copyable locator.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
pub struct NativeOwnerBindRights {
    shell: NativeSessionOwnerBindRight,
    root: SessionRootReleaseBindRight,
    finalizer: R3FinalizerCellBindRight,
    authority: PrivateNativeOwnerBindRightsAuthority,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
pub struct NativeSessionOwnerBindRight {
    locator: SessionLocator,
    authority: PrivateNativeSessionOwnerBindAuthority,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
pub struct SessionRootReleaseBindRight {
    locator: SessionLocator,
    authority: PrivateSessionRootReleaseBindAuthority,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct R3FinalizerCellBindRight {
    locator: SessionLocator,
    authority: PrivateR3FinalizerCellBindAuthority,
}

#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
impl NativeOwnerBindRights {
    const fn mint(locator: SessionLocator) -> Self {
        Self {
            shell: NativeSessionOwnerBindRight {
                locator,
                authority: PrivateNativeSessionOwnerBindAuthority(()),
            },
            root: SessionRootReleaseBindRight {
                locator,
                authority: PrivateSessionRootReleaseBindAuthority(()),
            },
            finalizer: R3FinalizerCellBindRight {
                locator,
                authority: PrivateR3FinalizerCellBindAuthority(()),
            },
            authority: PrivateNativeOwnerBindRightsAuthority(()),
        }
    }

    /// Production-only cross-crate bridge. The default core surface keeps the
    /// same operation crate-private for its WDK-free unit tests.
    ///
    /// `production-attested` is a reviewed in-repository trust boundary, not
    /// a Rust friend capability: an external build can deliberately enable
    /// it. The production graph/lifetime census must therefore continue to
    /// prove that fsring-fsd is the sole repository dependency that enables
    /// the feature and the sole production consumer of this bridge.
    #[cfg(feature = "production-attested")]
    pub fn into_parts(
        self,
    ) -> (
        NativeSessionOwnerBindRight,
        SessionRootReleaseBindRight,
        R3FinalizerCellBindRight,
    ) {
        self.into_parts_sealed()
    }

    #[cfg(not(feature = "production-attested"))]
    pub(crate) fn into_parts(
        self,
    ) -> (
        NativeSessionOwnerBindRight,
        SessionRootReleaseBindRight,
        R3FinalizerCellBindRight,
    ) {
        self.into_parts_sealed()
    }

    fn into_parts_sealed(
        self,
    ) -> (
        NativeSessionOwnerBindRight,
        SessionRootReleaseBindRight,
        R3FinalizerCellBindRight,
    ) {
        let Self {
            shell,
            root,
            finalizer,
            authority: PrivateNativeOwnerBindRightsAuthority(()),
        } = self;
        (shell, root, finalizer)
    }

    #[cfg(test)]
    pub(crate) const fn for_test(locator: SessionLocator) -> Self {
        Self::mint(locator)
    }
}

#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
impl NativeSessionOwnerBindRight {
    #[cfg(feature = "production-attested")]
    pub fn bind<Shell>(
        self,
        payload: Shell,
    ) -> crate::adapter::lifecycle::NativeSessionOwner<Shell> {
        self.bind_sealed(payload)
    }

    #[cfg(not(feature = "production-attested"))]
    pub(crate) fn bind<Shell>(
        self,
        payload: Shell,
    ) -> crate::adapter::lifecycle::NativeSessionOwner<Shell> {
        self.bind_sealed(payload)
    }

    fn bind_sealed<Shell>(
        self,
        payload: Shell,
    ) -> crate::adapter::lifecycle::NativeSessionOwner<Shell> {
        crate::adapter::lifecycle::bind_native_session_owner(self, payload)
    }

    pub(crate) fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateNativeSessionOwnerBindAuthority(()),
        } = self;
        locator
    }
}

#[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
impl SessionRootReleaseBindRight {
    #[cfg(feature = "production-attested")]
    pub fn bind<RootRelease>(
        self,
        payload: RootRelease,
    ) -> crate::adapter::lifecycle::SessionRootReleaseRight<RootRelease> {
        self.bind_sealed(payload)
    }

    #[cfg(not(feature = "production-attested"))]
    pub(crate) fn bind<RootRelease>(
        self,
        payload: RootRelease,
    ) -> crate::adapter::lifecycle::SessionRootReleaseRight<RootRelease> {
        self.bind_sealed(payload)
    }

    fn bind_sealed<RootRelease>(
        self,
        payload: RootRelease,
    ) -> crate::adapter::lifecycle::SessionRootReleaseRight<RootRelease> {
        crate::adapter::lifecycle::bind_session_root_release(self, payload)
    }

    pub(crate) fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateSessionRootReleaseBindAuthority(()),
        } = self;
        locator
    }
}

impl R3FinalizerCellBindRight {
    pub(crate) fn into_locator(self) -> SessionLocator {
        let Self {
            locator,
            authority: PrivateR3FinalizerCellBindAuthority(()),
        } = self;
        locator
    }
}

#[cfg_attr(test, derive(Debug))]
pub struct PreparedDeleteCoreCommit {
    authority: SessionAuthority,
    disposition: SlotDisposition,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct InstalledSession {
    registry: RegistryLease,
    control: StrongSessionRef,
    /// The completed ring set, recorded by `SessionRingSetInitializer::finish`.
    ///
    /// Private, and there is no setter: the only way it becomes `Some` is a
    /// fully-allocated set sealing itself, which is what lets the superseding
    /// publication treat "the brand I was handed" and "the brand this install
    /// actually completed" as two independently checkable facts.
    ring_set: Option<SessionRingSetBrand>,
    #[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
    native_owner_bind_rights: Option<NativeOwnerBindRights>,
}

#[cfg(test)]
impl InstalledSession {
    /// Build a deliberately crossed installation for the publication check.
    ///
    /// `install_staging` always mints both halves from one slot, so the case
    /// the publication cross-check exists for — two authorities carrying the
    /// same identity but naming different slots or generations — is not
    /// reachable through the real API. Without this seam the comparison could
    /// be deleted and every test would stay green.
    pub(crate) const fn crossed_for_test(
        registry: SessionLocator,
        control: SessionLocator,
    ) -> Self {
        Self {
            registry: RegistryLease {
                authority: SessionAuthority {
                    slot_index: registry.slot_index,
                    generation: registry.generation,
                    identity: registry.identity,
                },
            },
            control: StrongSessionRef {
                authority: SessionAuthority {
                    slot_index: control.slot_index,
                    generation: control.generation,
                    identity: control.identity,
                },
            },
            ring_set: None,
            native_owner_bind_rights: Some(NativeOwnerBindRights::mint(registry)),
        }
    }
}

#[cfg_attr(test, derive(Debug))]
pub enum RegistryRelease {
    Retained,
    Delete(DeleteSessionRight),
}

macro_rules! locator_getter {
    ($right:ty) => {
        impl $right {
            pub const fn locator(&self) -> SessionLocator {
                self.authority.locator()
            }
        }
    };
}

locator_getter!(RegistryLease);
locator_getter!(StrongSessionRef);
locator_getter!(TerminalSessionRef);
locator_getter!(DeleteSessionRight);

impl InstalledSession {
    pub const fn locator(&self) -> SessionLocator {
        self.registry.authority.locator()
    }

    /// Take the one native shell/root binding pair for this installed
    /// generation. A copied locator cannot re-enter this transition.
    #[cfg(feature = "production-attested")]
    #[doc(hidden)]
    pub fn take_native_owner_bind_rights(&mut self) -> Option<NativeOwnerBindRights> {
        self.take_native_owner_bind_rights_sealed()
    }

    #[cfg(not(feature = "production-attested"))]
    #[allow(dead_code)]
    pub(crate) fn take_native_owner_bind_rights(&mut self) -> Option<NativeOwnerBindRights> {
        self.take_native_owner_bind_rights_sealed()
    }

    #[cfg_attr(not(feature = "production-attested"), allow(dead_code))]
    fn take_native_owner_bind_rights_sealed(&mut self) -> Option<NativeOwnerBindRights> {
        self.native_owner_bind_rights.take()
    }
}

fn valid_setup_transaction(transaction: &SetupTransaction) -> bool {
    valid_identity(transaction.staging.identity)
        && transaction.staging.resource_bits == stage_prefix(transaction.staging.stage)
}

fn valid_installed_setup_transaction(transaction: &SetupTransaction) -> bool {
    matches!(
        transaction.staging.stage,
        SetupStage::OutputReady | SetupStage::ReferencesInstalled
    ) && valid_setup_transaction(transaction)
}

fn setup_reservation_preflight(
    binding: &ControlBinding,
    reservation: &SetupReservation,
) -> Result<bool, SessionError> {
    if binding.binding_id != reservation.binding_id {
        return Err(SessionError::IdentityMismatch);
    }
    match binding.state {
        ControlBindingState::Staging(setup_epoch) if setup_epoch == reservation.setup_epoch => {
            Ok(false)
        }
        ControlBindingState::ClosingSetup(setup_epoch)
            if setup_epoch == reservation.setup_epoch =>
        {
            Ok(true)
        }
        ControlBindingState::Staging(_) | ControlBindingState::ClosingSetup(_) => {
            Err(SessionError::IdentityMismatch)
        }
        _ => Err(SessionError::InvalidTransition),
    }
}

fn next_setup_epoch(setup_epoch: SetupEpoch) -> SetupEpochCursor {
    match setup_epoch.0.checked_add(1) {
        Some(next) => SetupEpochCursor::Next(SetupEpoch(next)),
        None => SetupEpochCursor::Exhausted,
    }
}

fn setup_rollback_commit_preflight(
    binding: &ControlBinding,
    reservation: &SetupReservation,
    expected_closing: bool,
) -> bool {
    if binding.binding_id != reservation.binding_id {
        return false;
    }
    match (expected_closing, binding.state) {
        (false, ControlBindingState::Staging(current))
        | (false, ControlBindingState::ClosingSetup(current))
        | (true, ControlBindingState::ClosingSetup(current)) => current == reservation.setup_epoch,
        _ => false,
    }
}

fn commit_setup_binding_rollback(
    binding: &mut ControlBinding,
    reservation: SetupReservation,
    expected_closing: bool,
) -> SetupRollbackDisposition {
    let SetupReservation {
        binding_id,
        setup_epoch,
    } = reservation;
    if binding.binding_id != binding_id {
        unreachable!("a prepared rollback cannot move to another binding")
    }
    match (expected_closing, binding.state) {
        (false, ControlBindingState::Staging(current)) if current == setup_epoch => {
            let cursor = next_setup_epoch(setup_epoch);
            binding.state = ControlBindingState::Empty(cursor);
            SetupRollbackDisposition::Reopened(cursor)
        }
        (false | true, ControlBindingState::ClosingSetup(current)) if current == setup_epoch => {
            SetupRollbackDisposition::RemainsClosing
        }
        _ => unreachable!("only CLEANUP may advance a prepared setup rollback"),
    }
}

/// Why one installed setup may not be published, or `None` if it may.
///
/// Extracted so the Task 4 publisher and Task 19's aggregate preparation decide
/// by the *same* six rules rather than by two copies of them. It borrows
/// everything, so consulting it costs no affine value and it can be asked
/// before any mutation — which is exactly what makes the aggregate boundary's
/// "refuse without touching anything" possible.
fn installed_setup_publication_refusal<const N: usize>(
    transaction: &SetupTransaction,
    registry: &SessionRegistry<N>,
    binding: &ControlBinding,
    rendezvous: &TerminalRendezvous,
    reservation: &SetupReservation,
    installed: &InstalledSession,
) -> Option<SessionError> {
    if transaction.staging.stage != SetupStage::ReferencesInstalled
        || !valid_setup_transaction(transaction)
    {
        return Some(SessionError::InvalidTransition);
    }
    match setup_reservation_preflight(binding, reservation) {
        Ok(false) => {
            // One clause, and it is the only one here that decides. This binds
            // the transaction being published to the authority that was
            // installed; `publish_preflight` below owns the separate rule that
            // the registry and control halves name the same cell, and owning it
            // in both places left a comparison that could be deleted without
            // changing any outcome — indistinguishable, to a mutation operator,
            // from a check that was never load-bearing.
            if installed.registry.authority.identity != transaction.staging.identity {
                Some(SessionError::IdentityMismatch)
            } else if !registry.admission_open {
                Some(SessionError::RegistryClosed)
            } else if rendezvous.activation_preflight().is_err() {
                Some(SessionError::InvalidTransition)
            } else {
                registry.publish_preflight(installed)
            }
        }
        Ok(true) => Some(SessionError::InvalidTransition),
        Err(error) => Some(error),
    }
}

/// Prepare one installed SETUP publication without mutating any destination.
// Refusal must return four large affine inputs intact in the allocation-free core.
#[allow(clippy::result_large_err)]
pub fn prepare_installed_setup_publication<const N: usize>(
    transaction: SetupTransaction,
    registry: &SessionRegistry<N>,
    binding: &ControlBinding,
    rendezvous: &TerminalRendezvous,
    reservation: SetupReservation,
    installed: InstalledSession,
) -> Result<PreparedSetupPublication, SetupPublishFailure> {
    let failure = installed_setup_publication_refusal(
        &transaction,
        registry,
        binding,
        rendezvous,
        &reservation,
        &installed,
    );
    if let Some(error) = failure {
        return Err(SetupPublishFailure {
            error,
            transaction,
            reservation,
            installed,
        });
    }

    Ok(PreparedSetupPublication {
        transaction,
        reservation,
        installed,
    })
}

/// Commit the already-preflighted core transition while its exclusive lock is
/// continuously held.
///
/// # Safety
/// The caller must keep exclusive access to the same registry, binding, and
/// rendezvous from preparation until all staged commit rights are consumed.
pub unsafe fn commit_prepared_registry_live<const N: usize>(
    prepared: PreparedSetupPublication,
    registry: &mut SessionRegistry<N>,
) -> RegistryLiveSetup {
    let PreparedSetupPublication {
        transaction,
        reservation,
        installed,
    } = prepared;
    let Ok(slot_index) = authority_index(&installed.registry.authority) else {
        unreachable!("publication preflight validated the slot index")
    };
    let Some(slot) = registry.slots.get_mut(slot_index) else {
        unreachable!("publication preflight validated the registry slot")
    };
    let InstalledSession {
        registry: registry_lease,
        control,
        // The legacy publisher creates no ring set and consumes none. Naming
        // the field explicitly rather than eliding it is what makes a future
        // field an error here instead of a silent drop.
        ring_set: _,
        native_owner_bind_rights: _,
    } = installed;
    let locator = registry_lease.locator();
    let SetupTransaction {
        staging: _,
        terminal,
    } = transaction;

    slot.state = RegistrySlotState::Live;
    RegistryLiveSetup {
        locator,
        registry: registry_lease,
        control,
        next: SetupBindingCommitRight {
            locator,
            reservation,
            terminal,
        },
    }
}

/// Commit the already-preflighted binding transition.
///
/// # Safety
/// The caller retains the same exclusive lock described by
/// [`commit_prepared_registry_live`].
pub unsafe fn commit_prepared_binding_active(
    right: SetupBindingCommitRight,
    binding: &mut ControlBinding,
) -> SetupTerminalCommitRight {
    let SetupBindingCommitRight {
        locator,
        reservation,
        terminal,
    } = right;
    if setup_reservation_preflight(binding, &reservation) != Ok(false) {
        unreachable!("a prepared binding commit retains its exact reservation")
    }
    let SetupReservation {
        binding_id: _,
        setup_epoch: _,
    } = reservation;
    binding.state = ControlBindingState::Active(locator);
    SetupTerminalCommitRight { locator, terminal }
}

/// Activate the terminal rendezvous after the binding is Active.
///
/// # Safety
/// The caller retains the same exclusive lock described by
/// [`commit_prepared_registry_live`].
pub unsafe fn commit_prepared_terminal_activation(
    right: SetupTerminalCommitRight,
    rendezvous: &mut TerminalRendezvous,
) -> SetupPublicationProof {
    let SetupTerminalCommitRight { locator, terminal } = right;
    let SetupTerminalRight(()) = terminal;
    rendezvous.commit_activation(locator);
    SetupPublicationProof { locator }
}

/// Run the three staged commits back to back under one continuous borrow.
///
/// Task 19 deleted the `publish_installed_setup_legacy` wrapper this used to
/// live inside. The wrapper's value was that the superseding publisher *called*
/// it rather than restating its stages; that value is preserved here, and what
/// is gone is the second public entry point with its own preflight — after the
/// cutover there is exactly one production publication, and it prepares before
/// the native runtime install and commits after it.
///
/// Infallible by construction: every decision was made by
/// [`prepare_installed_setup_publication`], whose output this consumes.
fn commit_prepared_installed_setup<const N: usize>(
    prepared: PreparedSetupPublication,
    registry: &mut SessionRegistry<N>,
    binding: &mut ControlBinding,
    rendezvous: &mut TerminalRendezvous,
) -> PublishedSession {
    // SAFETY: this function owns exclusive mutable access to every destination
    // continuously across the three infallible stages.
    let live = unsafe { commit_prepared_registry_live(prepared, registry) };
    let (locator, registry, control, binding_right) = live.into_parts();
    // SAFETY: as above; no caller can interleave through these borrows.
    let terminal_right = unsafe { commit_prepared_binding_active(binding_right, binding) };
    // SAFETY: as above; activation uses the same preflighted rendezvous.
    let proof = unsafe { commit_prepared_terminal_activation(terminal_right, rendezvous) };
    if proof.locator() != locator {
        unreachable!("the staged publication rights retain one locator")
    }
    PublishedSession {
        locator,
        registry,
        control,
    }
}

/// Prepare and commit one Task 4 publication in a single host-test call.
///
/// The production route is `prepare_installed_ring_setup` ->
/// `commit_after_native_runtime_install`, which is split precisely so the
/// native runtime install lands between the two. A host test has no native
/// runtime to install, and threading a ring set and a pending reservation
/// through every predecessor lifecycle fixture would make those tests about
/// SETUP rather than about what they check. `cfg(test)`, so no production
/// caller can reach it.
#[cfg(test)]
#[allow(clippy::result_large_err)]
pub(crate) fn publish_installed_setup_for_test<const N: usize>(
    transaction: SetupTransaction,
    registry: &mut SessionRegistry<N>,
    binding: &mut ControlBinding,
    rendezvous: &mut TerminalRendezvous,
    reservation: SetupReservation,
    installed: InstalledSession,
) -> Result<PublishedSession, SetupPublishFailure> {
    let prepared = prepare_installed_setup_publication(
        transaction,
        registry,
        binding,
        rendezvous,
        reservation,
        installed,
    )?;
    Ok(commit_prepared_installed_setup(
        prepared, registry, binding, rendezvous,
    ))
}

/// Prepare rollback of a reservation that failed before an identity existed.
#[allow(clippy::result_large_err)]
pub fn prepare_reserved_setup_rollback(
    binding: &ControlBinding,
    reservation: SetupReservation,
) -> Result<PreparedReservedSetupRollback, (SessionError, SetupReservation)> {
    match setup_reservation_preflight(binding, &reservation) {
        Ok(expected_closing) => Ok(PreparedReservedSetupRollback {
            reservation,
            expected_closing,
        }),
        Err(error) => Err((error, reservation)),
    }
}

pub fn commit_prepared_reserved_setup_rollback(
    prepared: PreparedReservedSetupRollback,
    binding: &mut ControlBinding,
) -> SetupRollbackDisposition {
    if !setup_rollback_commit_preflight(binding, &prepared.reservation, prepared.expected_closing) {
        unreachable!("a prepared reserved rollback retains its exact binding")
    }
    commit_setup_binding_rollback(binding, prepared.reservation, prepared.expected_closing)
}

/// Seal an installed rollback only after all inputs pass mutation-free preflight.
// Refusal must return five large affine inputs intact in the allocation-free core.
#[allow(clippy::result_large_err)]
pub fn prepare_installed_setup_rollback<const N: usize>(
    transaction: SetupTransaction,
    reason: SetupFailure,
    registry: &SessionRegistry<N>,
    binding: &ControlBinding,
    reservation: SetupReservation,
    installed: InstalledSession,
) -> Result<PreparedInstalledSetupRollback, PrepareInstalledRollbackFailure> {
    let preflight = if !valid_installed_setup_transaction(&transaction) {
        Err(SessionError::InvalidTransition)
    } else {
        match setup_reservation_preflight(binding, &reservation) {
            Ok(expected_closing) => {
                if installed.registry.authority.identity != transaction.staging.identity {
                    Err(SessionError::IdentityMismatch)
                } else if let Some(error) = registry.publish_preflight(&installed) {
                    Err(error)
                } else {
                    Ok(expected_closing)
                }
            }
            Err(error) => Err(error),
        }
    };
    let expected_closing = match preflight {
        Ok(expected_closing) => expected_closing,
        Err(error) => {
            return Err(PrepareInstalledRollbackFailure {
                error,
                transaction,
                reason,
                reservation,
                installed,
            });
        }
    };
    Ok(PreparedInstalledSetupRollback {
        transaction,
        reason,
        reservation,
        installed,
        expected_closing,
    })
}

pub fn commit_prepared_installed_setup_rollback<const N: usize>(
    prepared: PreparedInstalledSetupRollback,
    registry: &mut SessionRegistry<N>,
    binding: &mut ControlBinding,
) -> (RollbackReceipt, SlotDisposition, SetupRollbackDisposition) {
    if registry.publish_preflight(&prepared.installed).is_some()
        || !setup_rollback_commit_preflight(
            binding,
            &prepared.reservation,
            prepared.expected_closing,
        )
    {
        unreachable!("a prepared installed rollback requires its exact destinations")
    }
    let PreparedInstalledSetupRollback {
        transaction,
        reason,
        reservation,
        installed,
        expected_closing,
    } = prepared;
    let slot_disposition = match registry.rollback_staging(installed) {
        Ok(disposition) => disposition,
        Err(_) => unreachable!("prepared installed rollback retained its exact cell authority"),
    };
    let receipt = transaction.rollback(reason);
    let binding_disposition = commit_setup_binding_rollback(binding, reservation, expected_closing);
    (receipt, slot_disposition, binding_disposition)
}

/// Seal an uninstalled rollback while returning every input on refusal.
// Refusal must return four large affine inputs intact in the allocation-free core.
#[allow(clippy::result_large_err)]
pub fn prepare_uninstalled_setup_rollback(
    transaction: SetupTransaction,
    reason: SetupFailure,
    binding: &ControlBinding,
    reservation: SetupReservation,
) -> Result<PreparedUninstalledSetupRollback, PrepareUninstalledRollbackFailure> {
    let expected_closing = match setup_reservation_preflight(binding, &reservation) {
        Ok(expected_closing) if valid_setup_transaction(&transaction) => expected_closing,
        Ok(_) => {
            return Err(PrepareUninstalledRollbackFailure {
                error: SessionError::InvalidTransition,
                transaction,
                reason,
                reservation,
            });
        }
        Err(error) => {
            return Err(PrepareUninstalledRollbackFailure {
                error,
                transaction,
                reason,
                reservation,
            });
        }
    };
    Ok(PreparedUninstalledSetupRollback {
        transaction,
        reason,
        reservation,
        expected_closing,
    })
}

pub fn commit_prepared_uninstalled_setup_rollback(
    prepared: PreparedUninstalledSetupRollback,
    binding: &mut ControlBinding,
) -> (RollbackReceipt, SetupRollbackDisposition) {
    if !setup_rollback_commit_preflight(binding, &prepared.reservation, prepared.expected_closing) {
        unreachable!("a prepared uninstalled rollback requires its exact binding")
    }
    let PreparedUninstalledSetupRollback {
        transaction,
        reason,
        reservation,
        expected_closing,
    } = prepared;
    let receipt = transaction.rollback(reason);
    let disposition = commit_setup_binding_rollback(binding, reservation, expected_closing);
    (receipt, disposition)
}

// These fragments stay module-private so later terminal/finalizer aggregates
// can contain them without exposing a separable live-closing authority.
#[allow(dead_code)]
struct PreparedLiveBindingClose {
    locator: SessionLocator,
}

#[allow(dead_code)]
enum PreparedLiveBindingClaim {
    Claim(PreparedLiveBindingClose),
    Join(SessionLocator),
}

#[allow(dead_code)]
fn prepare_live_binding_claim(
    binding: &ControlBinding,
    locator: SessionLocator,
) -> Result<PreparedLiveBindingClaim, SessionError> {
    match binding.state {
        ControlBindingState::Active(current) if current == locator => {
            Ok(PreparedLiveBindingClaim::Claim(PreparedLiveBindingClose {
                locator,
            }))
        }
        ControlBindingState::ClosingLive(current) if current == locator => {
            Ok(PreparedLiveBindingClaim::Join(locator))
        }
        ControlBindingState::Active(_) | ControlBindingState::ClosingLive(_) => {
            Err(SessionError::IdentityMismatch)
        }
        _ => Err(SessionError::InvalidTransition),
    }
}

#[allow(dead_code)]
fn commit_prepared_live_binding_claim(
    prepared: PreparedLiveBindingClose,
    binding: &mut ControlBinding,
) {
    if binding.state != ControlBindingState::Active(prepared.locator) {
        unreachable!("the enclosing locked terminal aggregate preserves Active")
    }
    binding.state = ControlBindingState::ClosingLive(prepared.locator);
}

#[allow(dead_code)]
struct PreparedClosingComplete {
    locator: SessionLocator,
    result: TerminalResult,
}

#[allow(dead_code)]
fn prepare_closing_complete(
    binding: &ControlBinding,
    locator: SessionLocator,
    result: TerminalResult,
    completed_control_record_is_present: bool,
) -> Result<PreparedClosingComplete, SessionError> {
    if !completed_control_record_is_present {
        return Err(SessionError::InvalidTransition);
    }
    match binding.state {
        ControlBindingState::ClosingLive(current) if current == locator => {
            Ok(PreparedClosingComplete { locator, result })
        }
        ControlBindingState::ClosingLive(_) => Err(SessionError::IdentityMismatch),
        _ => Err(SessionError::InvalidTransition),
    }
}

#[allow(dead_code)]
fn commit_prepared_closing_complete(
    prepared: PreparedClosingComplete,
    binding: &mut ControlBinding,
) {
    if binding.state != ControlBindingState::ClosingLive(prepared.locator) {
        unreachable!("the enclosing locked finalizer aggregate preserves ClosingLive")
    }
    binding.state = ControlBindingState::ClosingComplete {
        generation: prepared.locator.generation,
        result: prepared.result,
    };
}

#[allow(dead_code)]
struct PreparedClosingBlocked {
    locator: SessionLocator,
    class: TerminalBlockedClass,
}

#[allow(dead_code)]
fn prepare_closing_blocked(
    binding: &ControlBinding,
    locator: SessionLocator,
    class: TerminalBlockedClass,
) -> Result<PreparedClosingBlocked, SessionError> {
    match binding.state {
        ControlBindingState::ClosingLive(current) if current == locator => {
            Ok(PreparedClosingBlocked { locator, class })
        }
        ControlBindingState::ClosingLive(_) => Err(SessionError::IdentityMismatch),
        _ => Err(SessionError::InvalidTransition),
    }
}

#[allow(dead_code)]
fn commit_prepared_closing_blocked(prepared: PreparedClosingBlocked, binding: &mut ControlBinding) {
    if binding.state != ControlBindingState::ClosingLive(prepared.locator) {
        unreachable!("the enclosing locked fail-stop aggregate preserves ClosingLive")
    }
    binding.state = ControlBindingState::ClosingBlocked {
        locator: prepared.locator,
        class: prepared.class,
    };
}

/// Whether an already stored fail-stop packet may use ordinary Blocked
/// visibility, or must use the nonsignalled opaque quarantine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredFailStopPublicationMode {
    PublishIfExact,
    RequireOpaque,
}

/// The only observations returned after an occupied fail-stop slot resolves
/// its visibility. Neither variant projects or consumes the retained packet.
pub enum StoredFailStopResolution {
    Published(TerminalOutcomeSignal),
    OpaqueRetained,
}

/// Sealed proof that one public resolution was committed from the exact
/// nonescaping stored-slot receipt supplied to the resolver.
///
/// The borrowed private visibility ties this value to that invocation of
/// `DurableFailStopSlot::store_and_resolve`. Safe code cannot substitute a
/// signal minted by another rendezvous or ignore the receipt and fabricate a
/// resolution for this slot.
///
/// ```compile_fail,E0308
/// use fsring_core::session::{
///     CommittedStoredFailStopResolution, StoredFailStopReceipt,
/// };
///
/// fn substitute_foreign_commit<'short>(
///     _receipt_a: StoredFailStopReceipt<'short>,
///     foreign_b: CommittedStoredFailStopResolution<'static>,
/// ) -> CommittedStoredFailStopResolution<'short> {
///     foreign_b
/// }
/// ```
pub struct CommittedStoredFailStopResolution<'stored> {
    resolution: StoredFailStopResolution,
    stored_visibility: &'stored DurableFailStopVisibility,
    invariant_brand: core::marker::PhantomData<fn(&'stored ()) -> &'stored ()>,
    authority: PrivateCommittedStoredFailStopResolutionAuthority,
}

impl CommittedStoredFailStopResolution<'_> {
    /// Observe the committed branch without projecting its affine signal.
    pub const fn resolution(&self) -> &StoredFailStopResolution {
        &self.resolution
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableFailStopObservation {
    Published,
    OpaqueRetained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableFailStopVisibility {
    Stored,
    Published,
    OpaqueRetained,
}

enum DurableFailStopSlotState<Packet> {
    Empty,
    Occupied {
        visibility: DurableFailStopVisibility,
        packet: Packet,
        metadata: Option<StoredFailStopMetadata>,
    },
}

/// Immutable visibility metadata sealed beside a complete fail-stop packet.
struct StoredFailStopMetadata {
    blocked: TerminalBlocked,
    mode: StoredFailStopPublicationMode,
}

/// Closed durable storage for one complete heterogeneous refusal packet.
///
/// The occupied packet is never projected or removed. Its transient Stored
/// state is private to core, and the resolving closure receives a concrete
/// nonconstructible receipt that borrows the exact rendezvous supplied by the
/// permanent native cell.
pub struct DurableFailStopSlot<Packet> {
    state: DurableFailStopSlotState<Packet>,
}

/// Nonescaping proof that `DurableFailStopSlot` already owns the packet.
///
/// The private authority and the exclusive rendezvous borrow prevent native
/// code from fabricating a receipt or substituting another rendezvous during
/// the visibility transition.
pub struct StoredFailStopReceipt<'stored> {
    rendezvous: &'stored mut TerminalRendezvous,
    visibility: &'stored DurableFailStopVisibility,
    metadata: &'stored StoredFailStopMetadata,
    force_opaque: bool,
    authority: PrivateStoredFailStopReceiptAuthority,
}

impl StoredFailStopReceipt<'_> {
    /// Runtime-observable proof that the complete packet entered durable
    /// storage before native visibility resolution began.
    ///
    /// The visibility reference is borrowed from the occupied slot itself;
    /// callers cannot construct this receipt from the packet they still own.
    pub const fn packet_is_stored_before_visibility(&self) -> bool {
        matches!(self.visibility, DurableFailStopVisibility::Stored)
    }

    /// Monotonically downgrade a stored packet to the nonsignalled opaque
    /// quarantine when a native physical predicate is no longer exact.
    /// There is intentionally no inverse conversion.
    pub const fn require_opaque(mut self) -> Self {
        self.force_opaque = true;
        self
    }
}

impl<Packet> DurableFailStopSlot<Packet> {
    pub const fn new_empty() -> Self {
        Self {
            state: DurableFailStopSlotState::Empty,
        }
    }

    pub const fn is_empty(&self) -> bool {
        matches!(self.state, DurableFailStopSlotState::Empty)
    }

    pub fn observation_for(&self, locator: SessionLocator) -> Option<DurableFailStopObservation> {
        match &self.state {
            DurableFailStopSlotState::Occupied {
                visibility,
                metadata: Some(metadata),
                ..
            } if metadata.blocked.locator() == locator => match visibility {
                DurableFailStopVisibility::Published => Some(DurableFailStopObservation::Published),
                DurableFailStopVisibility::OpaqueRetained => {
                    Some(DurableFailStopObservation::OpaqueRetained)
                }
                DurableFailStopVisibility::Stored => None,
            },
            DurableFailStopSlotState::Empty | DurableFailStopSlotState::Occupied { .. } => None,
        }
    }

    /// Store the whole packet before projecting its authority metadata or
    /// invoking the sole visibility resolver.
    ///
    /// The two higher-ranked closures cannot retain the stored packet or the
    /// receipt's rendezvous borrow. The packet remains occupied for both
    /// resolutions, including if projection or resolution unwinds in a host
    /// test.
    ///
    /// # Safety
    /// `project_stored` must derive both returned values solely and faithfully
    /// from the complete `stored_packet` it receives. In particular, it must
    /// not substitute copied metadata, another packet, or caller-authored
    /// descriptors. Production satisfies this boundary in the FSD-private
    /// `R3FailStopPacket` projector after the packet has moved into this slot.
    pub unsafe fn store_and_resolve<ProjectStored, Resolve>(
        &mut self,
        rendezvous: &mut TerminalRendezvous,
        packet: Packet,
        project_stored: ProjectStored,
        resolve: Resolve,
    ) -> Result<StoredFailStopResolution, Packet>
    where
        ProjectStored: for<'stored> FnOnce(
            &'stored Packet,
        )
            -> (TerminalBlocked, StoredFailStopPublicationMode),
        Resolve: for<'stored> FnOnce(
            &'stored Packet,
            StoredFailStopReceipt<'stored>,
        ) -> CommittedStoredFailStopResolution<'stored>,
    {
        if !self.is_empty() {
            return Err(packet);
        }
        self.state = DurableFailStopSlotState::Occupied {
            visibility: DurableFailStopVisibility::Stored,
            packet,
            metadata: None,
        };
        let projected = match &self.state {
            DurableFailStopSlotState::Occupied {
                visibility: DurableFailStopVisibility::Stored,
                packet,
                metadata: None,
            } => {
                let (blocked, mode) = project_stored(packet);
                StoredFailStopMetadata { blocked, mode }
            }
            DurableFailStopSlotState::Empty | DurableFailStopSlotState::Occupied { .. } => {
                unreachable!("the just-installed durable packet awaits its one projection")
            }
        };
        match &mut self.state {
            DurableFailStopSlotState::Occupied { metadata, .. } => *metadata = Some(projected),
            DurableFailStopSlotState::Empty => {
                unreachable!("projection cannot remove the durable packet")
            }
        }
        let committed = match &self.state {
            DurableFailStopSlotState::Occupied {
                visibility,
                packet,
                metadata: Some(metadata),
            } if matches!(visibility, DurableFailStopVisibility::Stored) => resolve(
                packet,
                StoredFailStopReceipt {
                    rendezvous,
                    visibility,
                    metadata,
                    force_opaque: false,
                    authority: PrivateStoredFailStopReceiptAuthority(()),
                },
            ),
            DurableFailStopSlotState::Empty | DurableFailStopSlotState::Occupied { .. } => {
                unreachable!("the just-installed durable packet remains Stored")
            }
        };
        let CommittedStoredFailStopResolution {
            resolution,
            stored_visibility,
            invariant_brand: _,
            authority: PrivateCommittedStoredFailStopResolutionAuthority(()),
        } = committed;
        debug_assert!(matches!(
            stored_visibility,
            DurableFailStopVisibility::Stored
        ));
        let visibility = match &mut self.state {
            DurableFailStopSlotState::Occupied { visibility, .. } => visibility,
            DurableFailStopSlotState::Empty => {
                unreachable!("the visibility resolver cannot remove the durable packet")
            }
        };
        *visibility = match resolution {
            StoredFailStopResolution::Published(_) => DurableFailStopVisibility::Published,
            StoredFailStopResolution::OpaqueRetained => DurableFailStopVisibility::OpaqueRetained,
        };
        Ok(resolution)
    }
}

/// Resolve visibility for a fail-stop packet that the native permanent cell
/// has already stored.
///
/// The exact ClosingLive/Open substrate publishes ClosingBlocked/Blocked in
/// this one transition. Any mismatch, or a physical predicate that requires
/// opacity, quarantines only exact still-live/open components and never
/// overwrites foreign, completed, blocked, inactive, or already opaque state.
///
#[doc(hidden)]
pub fn commit_stored_fail_stop_visibility<'stored>(
    receipt: StoredFailStopReceipt<'stored>,
    binding: &mut ControlBinding,
) -> CommittedStoredFailStopResolution<'stored> {
    let StoredFailStopReceipt {
        rendezvous,
        visibility,
        metadata,
        force_opaque,
        authority: PrivateStoredFailStopReceiptAuthority(()),
    } = receipt;
    if !matches!(visibility, DurableFailStopVisibility::Stored) {
        return CommittedStoredFailStopResolution {
            resolution: StoredFailStopResolution::OpaqueRetained,
            stored_visibility: visibility,
            invariant_brand: core::marker::PhantomData,
            authority: PrivateCommittedStoredFailStopResolutionAuthority(()),
        };
    }
    let blocked = metadata.blocked;
    let locator = blocked.locator();
    let diagnostic = blocked.diagnostic();
    let binding_exact = matches!(
        binding.state,
        ControlBindingState::ClosingLive(current) if locator_eq(current, locator)
    );
    let rendezvous_exact = matches!(
        rendezvous.state,
        PrivateTerminalRendezvousState::Open {
            locator: current,
            admitted,
        } if locator_eq(current, locator) && admitted > 0
    ) && blocked.matches(locator, diagnostic);

    if !force_opaque
        && matches!(metadata.mode, StoredFailStopPublicationMode::PublishIfExact)
        && binding_exact
        && rendezvous_exact
    {
        let admitted = rendezvous.admitted_for_locator(locator);
        binding.state = ControlBindingState::ClosingBlocked {
            locator,
            class: blocked.class(),
        };
        rendezvous.state = PrivateTerminalRendezvousState::Closed {
            locator,
            admitted,
            outcome: TerminalClosedOutcome::Blocked(blocked),
        };
        return CommittedStoredFailStopResolution {
            resolution: StoredFailStopResolution::Published(TerminalOutcomeSignal {
                locator,
                authority: PrivateTerminalOutcomeSignalAuthority(()),
            }),
            stored_visibility: visibility,
            invariant_brand: core::marker::PhantomData,
            authority: PrivateCommittedStoredFailStopResolutionAuthority(()),
        };
    }

    if binding_exact {
        binding.state = ControlBindingState::ClosingOpaqueRetained { locator };
    }
    if let PrivateTerminalRendezvousState::Open {
        locator: current,
        admitted,
    } = rendezvous.state
    {
        if locator_eq(current, locator) {
            rendezvous.state = PrivateTerminalRendezvousState::OpaqueRetained { locator, admitted };
        }
    }
    CommittedStoredFailStopResolution {
        resolution: StoredFailStopResolution::OpaqueRetained,
        stored_visibility: visibility,
        invariant_brand: core::marker::PhantomData,
        authority: PrivateCommittedStoredFailStopResolutionAuthority(()),
    }
}

impl PreparedDeleteCoreCommit {
    pub const fn disposition(&self) -> SlotDisposition {
        self.disposition
    }

    pub const fn locator(&self) -> SessionLocator {
        self.authority.locator()
    }

    #[cfg(test)]
    pub(crate) const fn for_test(locator: SessionLocator) -> Self {
        Self {
            authority: SessionAuthority {
                slot_index: locator.slot_index,
                generation: locator.generation,
                identity: locator.identity,
            },
            disposition: SlotDisposition::Free,
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_test_with_disposition(
        locator: SessionLocator,
        disposition: SlotDisposition,
    ) -> Self {
        Self {
            authority: SessionAuthority {
                slot_index: locator.slot_index,
                generation: locator.generation,
                identity: locator.identity,
            },
            disposition,
        }
    }
}

#[cfg(test)]
impl DeleteSessionRight {
    pub(crate) const fn for_test(locator: SessionLocator) -> Self {
        Self {
            authority: SessionAuthority {
                slot_index: locator.slot_index,
                generation: locator.generation,
                identity: locator.identity,
            },
        }
    }
}

/// Translate a binding refusal into the terminal-claim vocabulary.
///
/// The claim aggregate answers in `LifecycleError` because its caller is the
/// native lifecycle, not SETUP. Only the identity/locator distinction is
/// load-bearing here; everything else is a wrong-state refusal.
const fn terminal_claim_error(error: SessionError) -> LifecycleError {
    match error {
        SessionError::IdentityMismatch => LifecycleError::WrongLocator,
        _ => LifecycleError::WrongState,
    }
}

/// The mutation-free preflight result of one locked terminal claim.
///
/// It is private so no caller can build a claim outcome without going through
/// [`prepare_terminal_claim`], and it carries the already decided binding
/// fragment so the commit suffix performs no second decision.
enum PreparedTerminalOutcome {
    Winner {
        binding: PreparedLiveBindingClose,
        request: TerminalRequest,
    },
    Join,
    Completed(TerminalResult),
    Blocked(TerminalBlocked),
}

/// The winning half of one committed terminal claim.
///
/// The winner is counted before it runs: the join ticket inside is the
/// admission the same locked suffix took, so no path can run or wait a terminal
/// generation without a counted guard.
#[derive(Debug)]
pub struct CoreTerminalWinner {
    winner: TerminalWinner,
    terminal: TerminalSessionRef,
    join: TerminalJoinTicket,
}

impl CoreTerminalWinner {
    pub const fn locator(&self) -> SessionLocator {
        self.winner.locator
    }

    pub const fn reason(&self) -> TerminalReason {
        self.winner.reason
    }

    pub const fn diagnostic(&self) -> DiagnosticId {
        self.winner.diagnostic
    }

    pub fn into_parts(self) -> (TerminalWinner, TerminalSessionRef, TerminalJoinTicket) {
        (self.winner, self.terminal, self.join)
    }
}

/// What one committed terminal claim decided for its arrival.
pub enum CoreTerminalDisposition {
    Winner(CoreTerminalWinner),
    Join(TerminalJoinTicket),
    Completed(TerminalResult),
    Blocked(TerminalBlocked),
}

/// One locked, mutation-free terminal claim over an exact object cross-product.
///
/// The production terminal edge never sequences individually fallible
/// `begin_remove`, binding, and rendezvous mutations: a refusal after the first
/// of them would publish a torn Removing/Active/Open state that no later caller
/// could repair. This aggregate preflights all of them and then commits
/// infallibly.
///
/// It retains exclusive borrows of the same four objects it preflighted, so
/// between preparation and commit nothing else can mutate them and no *other*
/// registry, binding, rendezvous, or lease slot can be substituted for the ones
/// the decision was computed over. That is why [`Self::commit`] is
/// parameterless: there is no argument through which a foreign object could
/// arrive.
pub struct PreparedTerminalClaim<'objects, const N: usize> {
    registry: &'objects mut SessionRegistry<N>,
    binding: &'objects mut ControlBinding,
    rendezvous: &'objects mut TerminalRendezvous,
    lease: &'objects mut Option<RegistryLease>,
    locator: SessionLocator,
    outcome: PreparedTerminalOutcome,
}

fn preflight_terminal_claim<const N: usize>(
    registry: &SessionRegistry<N>,
    binding: &ControlBinding,
    rendezvous: &TerminalRendezvous,
    lease: &Option<RegistryLease>,
    locator: SessionLocator,
    request: TerminalRequest,
) -> Result<PreparedTerminalOutcome, LifecycleError> {
    let index = match usize::try_from(locator.slot_index) {
        Ok(index) => index,
        Err(_) => return Err(LifecycleError::WrongLocator),
    };
    let Some(slot) = registry.slots.get(index) else {
        return Err(LifecycleError::WrongLocator);
    };
    if slot.generation != locator.generation || slot.identity != Some(locator.identity) {
        return Err(LifecycleError::WrongLocator);
    }
    match rendezvous.r3_locked_locator() {
        Some(current) if current == locator => {}
        Some(_) => return Err(LifecycleError::WrongLocator),
        None => return Err(LifecycleError::WrongState),
    }

    match slot.state {
        RegistrySlotState::Live => {
            if slot.strong_count == 0 || slot.fence_done {
                return Err(LifecycleError::WrongState);
            }
            // Only a rendezvous that has admitted nobody can mint a winner; a
            // nonzero count means another source already won this generation.
            match rendezvous.state {
                PrivateTerminalRendezvousState::Open { admitted: 0, .. } => {}
                PrivateTerminalRendezvousState::Open { .. }
                | PrivateTerminalRendezvousState::Closed { .. }
                | PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                    return Err(LifecycleError::FinalizerBusy);
                }
                PrivateTerminalRendezvousState::Inactive => {
                    return Err(LifecycleError::WrongState);
                }
            }
            let Some(present) = lease.as_ref() else {
                return Err(LifecycleError::WrongState);
            };
            if present.authority.locator() != locator {
                return Err(LifecycleError::WrongLocator);
            }
            match prepare_live_binding_claim(binding, locator) {
                Ok(PreparedLiveBindingClaim::Claim(close)) => Ok(PreparedTerminalOutcome::Winner {
                    binding: close,
                    request,
                }),
                // A Live core slot beside a ClosingLive binding is the torn
                // state the one locked suffix exists to make unreachable.
                Ok(PreparedLiveBindingClaim::Join(_)) => Err(LifecycleError::Invariant),
                Err(error) => Err(terminal_claim_error(error)),
            }
        }
        RegistrySlotState::Removing | RegistrySlotState::Deleting => {
            // The winner already converted this cell's lease; a live one here
            // would mean two owners of the same registry count.
            if lease.is_some() {
                return Err(LifecycleError::Invariant);
            }
            match binding.state {
                ControlBindingState::Active(current) if current == locator => {
                    return Err(LifecycleError::Invariant);
                }
                ControlBindingState::ClosingLive(current) if current != locator => {
                    return Err(LifecycleError::WrongLocator);
                }
                ControlBindingState::ClosingBlocked {
                    locator: current, ..
                } if current != locator => {
                    return Err(LifecycleError::WrongLocator);
                }
                ControlBindingState::ClosingOpaqueRetained { locator: current }
                    if current != locator =>
                {
                    return Err(LifecycleError::WrongLocator);
                }
                _ => {}
            }
            match rendezvous.state {
                PrivateTerminalRendezvousState::Open { admitted: 0, .. } => {
                    Err(LifecycleError::AdmissionClosed)
                }
                PrivateTerminalRendezvousState::Open { admitted, .. } => {
                    if admitted.checked_add(1).is_none() {
                        return Err(LifecycleError::JoinerOverflow);
                    }
                    Ok(PreparedTerminalOutcome::Join)
                }
                PrivateTerminalRendezvousState::Closed { outcome, .. } => Ok(match outcome {
                    TerminalClosedOutcome::Completed(result) => {
                        PreparedTerminalOutcome::Completed(result)
                    }
                    TerminalClosedOutcome::Blocked(blocked) => {
                        PreparedTerminalOutcome::Blocked(blocked)
                    }
                }),
                PrivateTerminalRendezvousState::OpaqueRetained { .. } => {
                    Err(LifecycleError::WrongState)
                }
                PrivateTerminalRendezvousState::Inactive => Err(LifecycleError::WrongState),
            }
        }
        RegistrySlotState::Free | RegistrySlotState::Staging | RegistrySlotState::Retired => {
            Err(LifecycleError::WrongState)
        }
    }
}

/// Preflight one terminal claim over an exact registry/binding/rendezvous/lease
/// cross-product without mutating any of them.
///
/// Every refusal leaves all four objects byte-identical and returns no affine
/// value, so a losing arrival costs the caller nothing.
#[doc(hidden)]
pub fn prepare_terminal_claim<'objects, const N: usize>(
    registry: &'objects mut SessionRegistry<N>,
    binding: &'objects mut ControlBinding,
    rendezvous: &'objects mut TerminalRendezvous,
    lease: &'objects mut Option<RegistryLease>,
    locator: SessionLocator,
    request: TerminalRequest,
) -> Result<PreparedTerminalClaim<'objects, N>, LifecycleError> {
    let outcome = preflight_terminal_claim(registry, binding, rendezvous, lease, locator, request)?;
    Ok(PreparedTerminalClaim {
        registry,
        binding,
        rendezvous,
        lease,
        locator,
        outcome,
    })
}

impl<const N: usize> PreparedTerminalClaim<'_, N> {
    pub const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Whether this prepared claim will win, join, or only copy an outcome.
    ///
    /// Native preparation needs the answer before it decides which of its own
    /// slots to preflight, and it must get it without a second core decision.
    pub const fn kind(&self) -> CoreTerminalClaimKind {
        match self.outcome {
            PreparedTerminalOutcome::Winner { .. } => CoreTerminalClaimKind::Winner,
            PreparedTerminalOutcome::Join => CoreTerminalClaimKind::Join,
            PreparedTerminalOutcome::Completed(_) => CoreTerminalClaimKind::Completed,
            PreparedTerminalOutcome::Blocked(_) => CoreTerminalClaimKind::Blocked,
        }
    }

    /// The one indivisible suffix. It has no `Result` and no argument.
    pub fn commit(self) -> CoreTerminalDisposition {
        let Self {
            registry,
            binding,
            rendezvous,
            lease,
            locator,
            outcome,
        } = self;
        match outcome {
            PreparedTerminalOutcome::Winner {
                binding: close,
                request,
            } => {
                let Some(taken) = lease.take() else {
                    unreachable!("the prepared winner preflighted its exact registry lease")
                };
                let terminal = registry.commit_terminal_claim(taken);
                commit_prepared_live_binding_claim(close, binding);
                let Ok(claim) = rendezvous.claim(locator, request) else {
                    unreachable!("the prepared winner preflighted open admission")
                };
                let (winner, join) = claim.into_parts();
                CoreTerminalDisposition::Winner(CoreTerminalWinner {
                    winner,
                    terminal,
                    join,
                })
            }
            PreparedTerminalOutcome::Join => {
                let Ok(TerminalJoinClaim::Join(ticket)) = rendezvous.join(locator) else {
                    unreachable!("the prepared join preflighted counted open admission")
                };
                CoreTerminalDisposition::Join(ticket)
            }
            PreparedTerminalOutcome::Completed(result) => {
                CoreTerminalDisposition::Completed(result)
            }
            PreparedTerminalOutcome::Blocked(blocked) => CoreTerminalDisposition::Blocked(blocked),
        }
    }
}

/// A copyable observation of what a prepared claim decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreTerminalClaimKind {
    Winner,
    Join,
    Completed,
    Blocked,
}

// ---------------------------------------------------------------------------
// Prepared reference releases
// ---------------------------------------------------------------------------
//
// A release that reaches zero mints a `DeleteSessionRight`, and that right must
// never be observable on its own: between minting it and depositing it beside
// the active-version readiness there is a window in which a caller holds bare
// deletion authority. Closing that window is the whole reason these exist. The
// preflight decides Retained-or-Delete without mutating; the native wrapper
// then commits the core mutation and stores the deposit under the same lock, so
// no local caller ever sees the intermediate value.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedReleaseOutcome {
    Retained,
    Delete,
}

/// One preflighted stable-reference release over an exact registry.
pub struct PreparedStrongRelease<'objects, const N: usize> {
    registry: &'objects mut SessionRegistry<N>,
    reference: StrongSessionRef,
    outcome: PreparedReleaseOutcome,
}

/// One preflighted terminal-reference release over an exact registry.
pub struct PreparedTerminalRelease<'objects, const N: usize> {
    registry: &'objects mut SessionRegistry<N>,
    terminal: TerminalSessionRef,
    outcome: PreparedReleaseOutcome,
}

/// Whether a prepared release will retain the generation or delete it.
///
/// The native wrapper needs the answer before it decides which of its own slots
/// to preflight, and it must get it without a second core decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedReleaseKind {
    Retained,
    Delete,
}

const fn release_kind(outcome: PreparedReleaseOutcome) -> PreparedReleaseKind {
    match outcome {
        PreparedReleaseOutcome::Retained => PreparedReleaseKind::Retained,
        PreparedReleaseOutcome::Delete => PreparedReleaseKind::Delete,
    }
}

fn preflight_strong_release<const N: usize>(
    registry: &SessionRegistry<N>,
    reference: &StrongSessionRef,
) -> Result<PreparedReleaseOutcome, SessionError> {
    let index = authority_index(&reference.authority)?;
    let Some(slot) = registry.slots.get(index) else {
        return Err(SessionError::ReferenceNotFound);
    };
    if !slot_matches(slot, &reference.authority) {
        return Err(SessionError::IdentityMismatch);
    }
    match slot.state {
        RegistrySlotState::Live if slot.strong_count > 1 => Ok(PreparedReleaseOutcome::Retained),
        RegistrySlotState::Removing if slot.fence_done && slot.strong_count == 1 => {
            Ok(PreparedReleaseOutcome::Delete)
        }
        RegistrySlotState::Removing if slot.strong_count > 1 => {
            Ok(PreparedReleaseOutcome::Retained)
        }
        _ => Err(SessionError::InvalidTransition),
    }
}

fn preflight_terminal_release<const N: usize>(
    registry: &SessionRegistry<N>,
    terminal: &TerminalSessionRef,
) -> Result<PreparedReleaseOutcome, SessionError> {
    let index = authority_index(&terminal.authority)?;
    let Some(slot) = registry.slots.get(index) else {
        return Err(SessionError::ReferenceNotFound);
    };
    if !slot_matches(slot, &terminal.authority) {
        return Err(SessionError::IdentityMismatch);
    }
    if slot.state != RegistrySlotState::Removing || slot.fence_done || slot.strong_count == 0 {
        return Err(SessionError::InvalidTransition);
    }
    if slot.strong_count == 1 {
        Ok(PreparedReleaseOutcome::Delete)
    } else {
        Ok(PreparedReleaseOutcome::Retained)
    }
}

/// Preflight one stable release without mutating the registry.
#[doc(hidden)]
pub fn prepare_strong_release<const N: usize>(
    registry: &mut SessionRegistry<N>,
    reference: StrongSessionRef,
) -> Result<PreparedStrongRelease<'_, N>, (SessionError, StrongSessionRef)> {
    match preflight_strong_release(registry, &reference) {
        Ok(outcome) => Ok(PreparedStrongRelease {
            registry,
            reference,
            outcome,
        }),
        Err(error) => Err((error, reference)),
    }
}

/// Preflight one terminal release without mutating the registry.
#[doc(hidden)]
pub fn prepare_terminal_release<const N: usize>(
    registry: &mut SessionRegistry<N>,
    terminal: TerminalSessionRef,
) -> Result<PreparedTerminalRelease<'_, N>, (SessionError, TerminalSessionRef)> {
    match preflight_terminal_release(registry, &terminal) {
        Ok(outcome) => Ok(PreparedTerminalRelease {
            registry,
            terminal,
            outcome,
        }),
        Err(error) => Err((error, terminal)),
    }
}

impl<const N: usize> PreparedStrongRelease<'_, N> {
    pub const fn kind(&self) -> PreparedReleaseKind {
        release_kind(self.outcome)
    }

    pub const fn locator(&self) -> SessionLocator {
        self.reference.authority.locator()
    }

    /// Abandon the preparation and take the exact reference back.
    ///
    /// A native preflight that refuses *after* this one succeeded still owes
    /// the caller its affine input; nothing was mutated, so this is a return,
    /// not a rollback.
    pub fn into_reference(self) -> StrongSessionRef {
        self.reference
    }

    /// # Safety
    /// Called only by the same-lock native deposit wrapper after its complete
    /// mirror/readiness/worker preflight; a `Delete` result may not escape it.
    #[doc(hidden)]
    pub unsafe fn commit(self) -> RegistryRelease {
        let Self {
            registry,
            reference,
            outcome,
        } = self;
        let Ok(index) = authority_index(&reference.authority) else {
            unreachable!("the prepared release validated its slot index")
        };
        let Some(slot) = registry.slots.get_mut(index) else {
            unreachable!("the prepared release validated its slot")
        };
        match outcome {
            PreparedReleaseOutcome::Retained => {
                slot.strong_count = slot.strong_count.saturating_sub(1);
                RegistryRelease::Retained
            }
            PreparedReleaseOutcome::Delete => {
                slot.strong_count = 0;
                slot.state = RegistrySlotState::Deleting;
                RegistryRelease::Delete(DeleteSessionRight {
                    authority: reference.authority,
                })
            }
        }
    }
}

impl<const N: usize> PreparedTerminalRelease<'_, N> {
    pub const fn kind(&self) -> PreparedReleaseKind {
        release_kind(self.outcome)
    }

    pub const fn locator(&self) -> SessionLocator {
        self.terminal.authority.locator()
    }

    /// Abandon the preparation and take the exact terminal reference back.
    pub fn into_terminal(self) -> TerminalSessionRef {
        self.terminal
    }

    /// # Safety
    /// Same contract as [`PreparedStrongRelease::commit`].
    #[doc(hidden)]
    pub unsafe fn commit(self) -> RegistryRelease {
        let Self {
            registry,
            terminal,
            outcome,
        } = self;
        let Ok(index) = authority_index(&terminal.authority) else {
            unreachable!("the prepared release validated its slot index")
        };
        let Some(slot) = registry.slots.get_mut(index) else {
            unreachable!("the prepared release validated its slot")
        };
        match outcome {
            PreparedReleaseOutcome::Delete => {
                slot.strong_count = 0;
                slot.state = RegistrySlotState::Deleting;
                RegistryRelease::Delete(DeleteSessionRight {
                    authority: terminal.authority,
                })
            }
            PreparedReleaseOutcome::Retained => {
                // The fence finished with other owners still holding the
                // generation. Recording `fence_done` here is what makes the one
                // later release that reaches zero the deleting one.
                slot.strong_count = slot.strong_count.saturating_sub(1);
                slot.fence_done = true;
                RegistryRelease::Retained
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The embedded production-graph witness
// ---------------------------------------------------------------------------

/// The closed set of attestation profiles a binary can have been built under.
///
/// It is an enum, not a string, because the one question asked of it is
/// "is this the profile my checkpoint requires?" — and a string comparison is
/// how a binary ends up accepting an attestation from the wrong checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionAttestationProfile {
    #[cfg(test)]
    R3Stage,
    #[cfg(test)]
    R3Cutover,
    #[cfg(test)]
    R4Stage,
    #[cfg(test)]
    R4Cutover,
    #[cfg(test)]
    R5Stage,
    R5Cutover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionAttestationError {
    /// This image was built under a different profile than the caller requires.
    WrongProfile,
    /// This image carries no verified witness at all.
    RequiredRowMissing,
}

/// The private seal that makes an artifact identity unforgeable.
///
/// Only two places can construct it, and both are textually inside this module:
/// the file `build.rs` generates after the auditor verified it, and the
/// `#[cfg(test)]` injected witness below. There is no `from_hash`, no
/// `from_bytes`, and no `Default` — an identity cannot be minted from a value
/// somebody handed the driver at runtime.
struct SealedProductionWitness(());

/// The identity of the production-graph artifact this image was built against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionGraphArtifactIdentity {
    source_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    auditor_sha256: [u8; 32],
    profile: ProductionAttestationProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProductionRowCapabilities(u8);

impl ProductionRowCapabilities {
    /// Only the unattested witness and the test witnesses claim nothing, so
    /// this exists exactly where one of them is compiled.
    #[cfg(any(test, not(feature = "production-attested")))]
    const NONE: Self = Self(0);
    #[allow(dead_code)]
    const TASK12_CUTOVER: Self = Self(1 << 0);
    #[allow(dead_code)]
    const TASK12_EXACT_DELETE: Self = Self(1 << 1);
    #[cfg(test)]
    const R4_STAGING: Self = Self(1 << 2);
    #[allow(dead_code)]
    const R5_STAGING: Self = Self(1 << 3);
    /// Task 19's cutover gate row. It *replaces* `R4_STAGING`, which is why the
    /// staging bit is now `cfg(test)`-only: after the cutover the staged surface
    /// is production-reachable by design, so a live binary claiming both bits
    /// would be claiming two contradictory things about the same tree.
    const R4_CUTOVER: Self = Self(1 << 4);
    #[allow(dead_code)]
    const R5_CUTOVER: Self = Self(1 << 5);
    #[cfg(test)]
    const UNRELATED_VERIFIED_ROW: Self = Self(1 << 7);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    #[cfg(test)]
    const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

const ACTIVE_R4_AUTHORITY_CAPABILITIES: ProductionRowCapabilities =
    ProductionRowCapabilities::TASK12_CUTOVER
        .union(ProductionRowCapabilities::TASK12_EXACT_DELETE)
        .union(ProductionRowCapabilities::R4_CUTOVER)
        .union(ProductionRowCapabilities::R5_STAGING);

#[cfg(test)]
const HISTORICAL_R3_CUTOVER_CAPABILITIES: ProductionRowCapabilities =
    ProductionRowCapabilities::TASK12_CUTOVER.union(ProductionRowCapabilities::TASK12_EXACT_DELETE);

#[cfg(test)]
const HISTORICAL_R4_STAGE_CAPABILITIES: ProductionRowCapabilities =
    HISTORICAL_R3_CUTOVER_CAPABILITIES.union(ProductionRowCapabilities::R4_STAGING);

/// The predecessor bundle Tasks 20-24 were staged under, retired by Task 19.
///
/// It is *not* the active bundle any more: `r5-stage` carries the R4 staging
/// gate, and that gate fails by design once the cutover makes R4 reachable.
#[cfg(test)]
const HISTORICAL_R5_STAGE_CAPABILITIES: ProductionRowCapabilities =
    HISTORICAL_R4_STAGE_CAPABILITIES.union(ProductionRowCapabilities::R5_STAGING);

/// The generated witness, kept private so its row count cannot be read as an
/// identity in its own right.
struct EmbeddedProductionWitness {
    identity: ProductionGraphArtifactIdentity,
    rows: u32,
    capabilities: ProductionRowCapabilities,
}

impl EmbeddedProductionWitness {
    /// Private: reachable only from a sealed witness.
    const fn sealed(
        seal: SealedProductionWitness,
        source_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        auditor_sha256: [u8; 32],
        profile: ProductionAttestationProfile,
        rows: u32,
        capabilities: ProductionRowCapabilities,
    ) -> Self {
        let SealedProductionWitness(()) = seal;
        Self {
            identity: ProductionGraphArtifactIdentity {
                source_sha256,
                manifest_sha256,
                auditor_sha256,
                profile,
            },
            rows,
            capabilities,
        }
    }

    #[cfg(test)]
    const fn sealed_for_test(
        seal: SealedProductionWitness,
        source_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        auditor_sha256: [u8; 32],
        profile: ProductionAttestationProfile,
        rows: u32,
        capabilities: ProductionRowCapabilities,
    ) -> Self {
        Self::sealed(
            seal,
            source_sha256,
            manifest_sha256,
            auditor_sha256,
            profile,
            rows,
            capabilities,
        )
    }

    const fn resolve(
        &self,
        required: ProductionAttestationProfile,
    ) -> Result<ProductionGraphArtifactIdentity, ProductionAttestationError> {
        if self.rows == 0 {
            return Err(ProductionAttestationError::RequiredRowMissing);
        }
        if !profiles_match(self.identity.profile, required) {
            return Err(ProductionAttestationError::WrongProfile);
        }
        Ok(self.identity)
    }
}

fn resolve_active_r4_authority_absence_from(
    witness: &EmbeddedProductionWitness,
) -> Result<ProductionGraphArtifactIdentity, ProductionAttestationError> {
    if witness.rows == 0 {
        return Err(ProductionAttestationError::RequiredRowMissing);
    }
    #[cfg(test)]
    let accepted = matches!(
        witness.identity.profile,
        ProductionAttestationProfile::R4Cutover
    );
    #[cfg(not(test))]
    let accepted = matches!(
        witness.identity.profile,
        ProductionAttestationProfile::R5Cutover
    );
    if !accepted {
        return Err(ProductionAttestationError::WrongProfile);
    }
    if !witness
        .capabilities
        .contains(ACTIVE_R4_AUTHORITY_CAPABILITIES)
    {
        return Err(ProductionAttestationError::RequiredRowMissing);
    }
    Ok(witness.identity)
}

pub(crate) fn embedded_r4_authority_absence()
-> Result<ProductionGraphArtifactIdentity, ProductionAttestationError> {
    resolve_active_r4_authority_absence_from(&PRODUCTION_GRAPH_WITNESS)
}

#[cfg(test)]
pub(crate) fn injected_r4_authority_absence_for_test()
-> Result<ProductionGraphArtifactIdentity, ProductionAttestationError> {
    resolve_active_r4_authority_absence_from(&ACTIVE_R4_INJECTED_GRAPH_WITNESS)
}

#[cfg(test)]
fn resolve_historical_r3_absence_for_test(
    witness: &EmbeddedProductionWitness,
) -> Result<ProductionGraphArtifactIdentity, ProductionAttestationError> {
    if witness.rows == 0 {
        return Err(ProductionAttestationError::RequiredRowMissing);
    }
    let exact = match witness.identity.profile {
        ProductionAttestationProfile::R3Cutover => HISTORICAL_R3_CUTOVER_CAPABILITIES,
        ProductionAttestationProfile::R4Stage => HISTORICAL_R4_STAGE_CAPABILITIES,
        ProductionAttestationProfile::R5Stage => HISTORICAL_R5_STAGE_CAPABILITIES,
        _ => return Err(ProductionAttestationError::WrongProfile),
    };
    if witness.capabilities != exact {
        return Err(ProductionAttestationError::RequiredRowMissing);
    }
    Ok(witness.identity)
}

const fn profiles_match(
    left: ProductionAttestationProfile,
    right: ProductionAttestationProfile,
) -> bool {
    left as u8 == right as u8
}

impl ProductionGraphArtifactIdentity {
    /// The identity this image's build script verified, if it requires it.
    ///
    /// A core built without the private feature answers `RequiredRowMissing`
    /// rather than a placeholder identity: an image with no verified witness has
    /// no artifact, and saying so is the difference between "not attested" and
    /// "attested to nothing".
    #[doc(hidden)]
    pub const fn embedded(
        required: ProductionAttestationProfile,
    ) -> Result<Self, ProductionAttestationError> {
        PRODUCTION_GRAPH_WITNESS.resolve(required)
    }

    /// The distinct witness unit tests use.
    ///
    /// Deliberately not the generated one: a test build runs no auditor, so a
    /// test that read the production witness would be reading something this
    /// build never verified.
    #[cfg(test)]
    pub(crate) const fn injected_for_test(
        required: ProductionAttestationProfile,
    ) -> Result<Self, ProductionAttestationError> {
        INJECTED_GRAPH_WITNESS.resolve(required)
    }

    pub const fn profile(&self) -> ProductionAttestationProfile {
        self.profile
    }

    pub const fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }

    pub const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }

    pub const fn auditor_sha256(&self) -> [u8; 32] {
        self.auditor_sha256
    }
}

// The build script is the *only* production source of a witness, and it speaks
// through the compile-time environment rather than a generated file: this crate
// forbids `include!` and `#[path]` source inclusion, and `tests/extern_quarantine.rs`
// enforces that. Reading the values back through in-crate `const fn` parsers is
// also stronger than trusting generated text, because a malformed digest is a
// const-evaluation failure — a hard build error — rather than a literal nobody
// checked.
#[cfg(feature = "production-attested")]
const PRODUCTION_GRAPH_WITNESS: EmbeddedProductionWitness = EmbeddedProductionWitness::sealed(
    SealedProductionWitness(()),
    parse_digest(env!("FSRING_C4_SOURCE_SHA256")),
    parse_digest(env!("FSRING_C4_MANIFEST_SHA256")),
    parse_digest(env!("FSRING_C4_AUDITOR_SHA256")),
    parse_profile(env!("FSRING_C4_PROFILE")),
    parse_rows(env!("FSRING_C4_ROWS")),
    parse_capabilities(env!("FSRING_C4_CAPABILITIES")),
);

// An unattested build carries a witness with zero rows. `resolve` answers
// `RequiredRowMissing` for it and can never return an identity, so this is not
// a placeholder that could be mistaken for an answer — it is what makes the
// "no artifact" case a value rather than a second code path.
#[cfg(not(feature = "production-attested"))]
const PRODUCTION_GRAPH_WITNESS: EmbeddedProductionWitness = EmbeddedProductionWitness::sealed(
    SealedProductionWitness(()),
    [0; 32],
    [0; 32],
    [0; 32],
    ProductionAttestationProfile::R5Cutover,
    0,
    ProductionRowCapabilities::NONE,
);

/// Parse one 64-character hex digest at compile time.
///
/// Every failure is a `panic!` in a `const` context, which is a build error.
///
/// The parsers below exist only where a witness or a test does. A default
/// core build has no attested values to parse, and a parser nothing calls is
/// dead weight that `-D warnings` would reject.
#[cfg(any(test, feature = "production-attested"))]
const fn parse_digest(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "a witness digest must be 64 hex digits");
    let mut out = [0u8; 32];
    let mut index = 0usize;
    while index < 32 {
        // PROOF: `index < 32`, so both byte offsets are below 64, the asserted
        // length. `<[T]>::get` is not available in a const context.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        {
            let high = hex_nibble(bytes[index * 2]);
            let low = hex_nibble(bytes[index * 2 + 1]);
            out[index] = (high << 4) | low;
            index += 1;
        }
    }
    out
}

#[cfg(any(test, feature = "production-attested"))]
const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte.wrapping_sub(b'0'),
        b'a'..=b'f' => byte.wrapping_sub(b'a').wrapping_add(10),
        b'A'..=b'F' => byte.wrapping_sub(b'A').wrapping_add(10),
        _ => panic!("a witness digest must be hexadecimal"),
    }
}

/// Parse the profile name into the closed enum at compile time.
#[cfg(all(feature = "production-attested", not(test)))]
const fn parse_profile(text: &str) -> ProductionAttestationProfile {
    let bytes = text.as_bytes();
    if equals(bytes, b"r5-cutover") {
        ProductionAttestationProfile::R5Cutover
    } else {
        panic!("the attested profile is not r5-cutover")
    }
}

#[cfg(test)]
const fn parse_profile(text: &str) -> ProductionAttestationProfile {
    let bytes = text.as_bytes();
    if equals(bytes, b"r3-stage") {
        ProductionAttestationProfile::R3Stage
    } else if equals(bytes, b"r3-cutover") {
        ProductionAttestationProfile::R3Cutover
    } else if equals(bytes, b"r4-stage") {
        ProductionAttestationProfile::R4Stage
    } else if equals(bytes, b"r4-cutover") {
        ProductionAttestationProfile::R4Cutover
    } else if equals(bytes, b"r5-stage") {
        ProductionAttestationProfile::R5Stage
    } else if equals(bytes, b"r5-cutover") {
        ProductionAttestationProfile::R5Cutover
    } else {
        panic!("the attested profile is not one of the closed set")
    }
}

#[cfg(any(test, feature = "production-attested"))]
const fn equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0usize;
    while index < left.len() {
        // PROOF: `index` is bounded by the equal lengths on every iteration.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        {
            if left[index] != right[index] {
                return false;
            }
            index += 1;
        }
    }
    true
}

/// Parse the attested row count at compile time. Zero is a build error: a
/// witness with no rows is exactly the "not attested" case, and a production
/// build that reached here has already verified rows exist.
#[cfg(any(test, feature = "production-attested"))]
const fn parse_rows(text: &str) -> u32 {
    let bytes = text.as_bytes();
    assert!(!bytes.is_empty(), "the attested row count is empty");
    let mut value = 0u32;
    let mut index = 0usize;
    while index < bytes.len() {
        // PROOF: `index` is bounded by the slice length on every iteration.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        {
            let digit = bytes[index];
            assert!(
                digit >= b'0' && digit <= b'9',
                "the attested row count is not decimal"
            );
            value = match value.checked_mul(10) {
                Some(scaled) => match scaled.checked_add((digit - b'0') as u32) {
                    Some(next) => next,
                    None => panic!("the attested row count overflows"),
                },
                None => panic!("the attested row count overflows"),
            };
            index += 1;
        }
    }
    assert!(value > 0, "an attested witness has at least one row");
    value
}

#[cfg(any(test, feature = "production-attested"))]
const fn parse_capabilities(text: &str) -> ProductionRowCapabilities {
    let bytes = text.as_bytes();
    assert!(!bytes.is_empty(), "the attested capability mask is empty");
    let mut value = 0u16;
    let mut index = 0usize;
    while index < bytes.len() {
        // PROOF: `index` is bounded by the slice length on every iteration.
        #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
        {
            let digit = bytes[index];
            assert!(
                digit >= b'0' && digit <= b'9',
                "the attested capability mask is not decimal"
            );
            value = match value.checked_mul(10) {
                Some(scaled) => match scaled.checked_add((digit - b'0') as u16) {
                    Some(next) => next,
                    None => panic!("the attested capability mask overflows"),
                },
                None => panic!("the attested capability mask overflows"),
            };
            index += 1;
        }
    }
    assert!(
        value <= u8::MAX as u16,
        "the attested capability mask exceeds one byte"
    );
    ProductionRowCapabilities(value as u8)
}

#[cfg(test)]
const INJECTED_GRAPH_WITNESS: EmbeddedProductionWitness = EmbeddedProductionWitness::sealed(
    SealedProductionWitness(()),
    [0x11; 32],
    [0x22; 32],
    [0x33; 32],
    ProductionAttestationProfile::R3Stage,
    3,
    ProductionRowCapabilities::NONE,
);

#[cfg(test)]
const ACTIVE_R4_INJECTED_GRAPH_WITNESS: EmbeddedProductionWitness =
    EmbeddedProductionWitness::sealed_for_test(
        SealedProductionWitness(()),
        [0x44; 32],
        [0x55; 32],
        [0x66; 32],
        ProductionAttestationProfile::R4Cutover,
        4,
        ACTIVE_R4_AUTHORITY_CAPABILITIES,
    );

#[cfg(test)]
const UNATTESTED_GRAPH_WITNESS: EmbeddedProductionWitness = EmbeddedProductionWitness::sealed(
    SealedProductionWitness(()),
    [0; 32],
    [0; 32],
    [0; 32],
    ProductionAttestationProfile::R3Stage,
    0,
    ProductionRowCapabilities::NONE,
);

impl<const N: usize> SessionRegistry<N> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            admission_open: true,
            slots: [RegistrySlot::FREE; N],
        }
    }

    pub fn close_admission(&mut self) {
        self.admission_open = false;
    }

    pub const fn admission_is_open(&self) -> bool {
        self.admission_open
    }

    /// Narrow locked observation used by unload effect nine. This is kept
    /// distinct from slot emptiness so either predicate can fail on its own.
    pub const fn r3_unload_admission_is_closed(&self) -> bool {
        !self.admission_open
    }

    /// Read-only effect-nine observation for the core half of the fixed R3
    /// registry. The native caller reaches this only from its held registry
    /// lock; no slot, locator, or ownership authority is projected out.
    pub fn r3_unload_slots_are_empty(&self) -> bool {
        self.slots.iter().all(|slot| {
            matches!(
                slot.state,
                RegistrySlotState::Free | RegistrySlotState::Retired
            ) && slot.identity.is_none()
                && slot.strong_count == 0
                && !slot.fence_done
        })
    }

    /// Read-only checkpoint observation that the exact Removing generation
    /// has discharged every stable reference except the terminal runner's.
    ///
    /// This is deliberately distinct from the later native/root-ledger check:
    /// checkpoint effect 15 establishes the reference-count fact, while
    /// effect 16 verifies the heterogeneous native owners. Neither call mints
    /// or releases authority.
    pub fn r3_checkpoint_has_only_terminal_strong_owner(&self, locator: SessionLocator) -> bool {
        let Ok(index) = usize::try_from(locator.slot_index()) else {
            return false;
        };
        self.slots.get(index).is_some_and(|slot| {
            slot.generation == locator.generation()
                && slot.identity == Some(locator.identity())
                && slot.state == RegistrySlotState::Removing
                && slot.strong_count == 1
                && !slot.fence_done
        })
    }

    pub fn install_staging(
        &mut self,
        transaction: &SetupTransaction,
        binding: &ControlBinding,
        reservation: &SetupReservation,
    ) -> Result<InstalledSession, SessionError> {
        match setup_reservation_preflight(binding, reservation) {
            Ok(false) => {}
            Ok(true) => return Err(SessionError::InvalidTransition),
            Err(error) => return Err(error),
        }
        if !self.admission_open {
            return Err(SessionError::RegistryClosed);
        }
        if transaction.staging.stage != SetupStage::OutputReady
            || transaction.staging.resource_bits != stage_prefix(SetupStage::OutputReady)
        {
            return Err(SessionError::InvalidTransition);
        }
        let identity = transaction.staging.identity;
        if self.slots.iter().any(|slot| {
            !matches!(
                slot.state,
                RegistrySlotState::Free | RegistrySlotState::Retired
            ) && slot.identity == Some(identity)
        }) {
            return Err(SessionError::DuplicateSetup);
        }

        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.state != RegistrySlotState::Free {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                slot.state = RegistrySlotState::Retired;
                continue;
            };
            let slot_index = u32::try_from(index).map_err(|_| SessionError::RegistryFull)?;
            slot.generation = generation;
            slot.identity = Some(identity);
            slot.state = RegistrySlotState::Staging;
            slot.strong_count = 2;
            slot.fence_done = false;
            return Ok(InstalledSession {
                registry: RegistryLease {
                    authority: SessionAuthority {
                        slot_index,
                        generation,
                        identity,
                    },
                },
                control: StrongSessionRef {
                    authority: SessionAuthority {
                        slot_index,
                        generation,
                        identity,
                    },
                },
                ring_set: None,
                native_owner_bind_rights: Some(NativeOwnerBindRights::mint(SessionLocator {
                    slot_index,
                    generation,
                    identity,
                })),
            });
        }
        Err(SessionError::RegistryFull)
    }

    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn rollback_staging(
        &mut self,
        installed: InstalledSession,
    ) -> Result<SlotDisposition, (SessionError, InstalledSession)> {
        if installed.registry.authority != installed.control.authority {
            return Err((SessionError::IdentityMismatch, installed));
        }
        let index = match usize::try_from(installed.registry.authority.slot_index) {
            Ok(index) => index,
            Err(_) => return Err((SessionError::ReferenceNotFound, installed)),
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return Err((SessionError::ReferenceNotFound, installed));
        };
        if slot.generation != installed.registry.authority.generation
            || slot.identity != Some(installed.registry.authority.identity)
        {
            return Err((SessionError::IdentityMismatch, installed));
        }
        if slot.state != RegistrySlotState::Staging || slot.strong_count != 2 || slot.fence_done {
            return Err((SessionError::InvalidTransition, installed));
        }
        let disposition = disposition_for_generation(slot.generation);
        reset_slot(slot, disposition);
        Ok(disposition)
    }

    /// Read-only proof that this exact locator still names a `Live` slot.
    ///
    /// The native access resolver calls this under the registry lock before it
    /// projects a session pointer. It takes `&self` and changes neither the
    /// strong count nor admission, so it can neither keep a session alive nor
    /// be mistaken for [`Self::acquire`]: the caller's lifetime comes from the
    /// per-cell access rundown, not from a reference this call did not take.
    ///
    /// Staging, Removing, Deleting, Free, Retired, a stale generation, and a
    /// foreign identity are all rejected. A closed registry rejects everything:
    /// unload has stopped admitting new work, so a resolve that succeeded after
    /// admission closed would hand out a session unload is already tearing down.
    pub fn validate_live(&self, locator: SessionLocator) -> Result<(), SessionError> {
        if !self.admission_open {
            return Err(SessionError::RegistryClosed);
        }
        let index =
            usize::try_from(locator.slot_index).map_err(|_| SessionError::ReferenceNotFound)?;
        let Some(slot) = self.slots.get(index) else {
            return Err(SessionError::ReferenceNotFound);
        };
        if slot.state != RegistrySlotState::Live
            || slot.generation != locator.generation
            || slot.identity != Some(locator.identity)
        {
            return Err(SessionError::ReferenceNotFound);
        }
        Ok(())
    }

    pub fn acquire(&mut self, locator: SessionLocator) -> Result<StrongSessionRef, SessionError> {
        if !self.admission_open {
            return Err(SessionError::RegistryClosed);
        }
        let index =
            usize::try_from(locator.slot_index).map_err(|_| SessionError::ReferenceNotFound)?;
        let Some(slot) = self.slots.get_mut(index) else {
            return Err(SessionError::ReferenceNotFound);
        };
        if slot.state != RegistrySlotState::Live
            || slot.generation != locator.generation
            || slot.identity != Some(locator.identity)
        {
            return Err(SessionError::ReferenceNotFound);
        }
        let Some(strong_count) = slot.strong_count.checked_add(1) else {
            return Err(SessionError::ReferenceExhausted);
        };
        slot.strong_count = strong_count;
        Ok(StrongSessionRef {
            authority: SessionAuthority {
                slot_index: locator.slot_index,
                generation: locator.generation,
                identity: locator.identity,
            },
        })
    }

    pub fn begin_remove(
        &mut self,
        lease: RegistryLease,
    ) -> Result<TerminalSessionRef, (SessionError, RegistryLease)> {
        let index = match authority_index(&lease.authority) {
            Ok(index) => index,
            Err(error) => return Err((error, lease)),
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return Err((SessionError::ReferenceNotFound, lease));
        };
        if !slot_matches(slot, &lease.authority) {
            return Err((SessionError::IdentityMismatch, lease));
        }
        if slot.state != RegistrySlotState::Live || slot.strong_count == 0 {
            return Err((SessionError::InvalidTransition, lease));
        }
        slot.state = RegistrySlotState::Removing;
        slot.fence_done = false;
        Ok(TerminalSessionRef {
            authority: lease.authority,
        })
    }

    /// The infallible Live -> Removing half of one prepared terminal claim.
    ///
    /// It is private and takes the cell's exact `RegistryLease` by value: the
    /// only way to reach it is through [`PreparedTerminalClaim::commit`], whose
    /// preflight already proved this slot Live at this authority with a nonzero
    /// count. `begin_remove` stays for the pre-cutover callers; this one may
    /// not refuse, because its caller has already mutated nothing and has no
    /// place to put a refusal.
    fn commit_terminal_claim(&mut self, lease: RegistryLease) -> TerminalSessionRef {
        let Ok(index) = authority_index(&lease.authority) else {
            unreachable!("the prepared terminal claim validated its slot index")
        };
        let Some(slot) = self.slots.get_mut(index) else {
            unreachable!("the prepared terminal claim validated its slot")
        };
        if slot.state != RegistrySlotState::Live
            || !slot_matches(slot, &lease.authority)
            || slot.strong_count == 0
        {
            unreachable!("the enclosing locked aggregate preserves the preflighted Live slot")
        }
        slot.state = RegistrySlotState::Removing;
        slot.fence_done = false;
        TerminalSessionRef {
            authority: lease.authority,
        }
    }

    pub fn release(
        &mut self,
        reference: StrongSessionRef,
    ) -> Result<RegistryRelease, (SessionError, StrongSessionRef)> {
        let index = match authority_index(&reference.authority) {
            Ok(index) => index,
            Err(error) => return Err((error, reference)),
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return Err((SessionError::ReferenceNotFound, reference));
        };
        if !slot_matches(slot, &reference.authority) {
            return Err((SessionError::IdentityMismatch, reference));
        }
        match slot.state {
            RegistrySlotState::Live if slot.strong_count > 1 => {
                slot.strong_count = slot.strong_count.saturating_sub(1);
                Ok(RegistryRelease::Retained)
            }
            RegistrySlotState::Removing if slot.fence_done && slot.strong_count == 1 => {
                slot.strong_count = 0;
                slot.state = RegistrySlotState::Deleting;
                Ok(RegistryRelease::Delete(DeleteSessionRight {
                    authority: reference.authority,
                }))
            }
            RegistrySlotState::Removing if slot.strong_count > 1 => {
                slot.strong_count = slot.strong_count.saturating_sub(1);
                Ok(RegistryRelease::Retained)
            }
            RegistrySlotState::Live | RegistrySlotState::Removing => {
                Err((SessionError::InvalidTransition, reference))
            }
            _ => Err((SessionError::InvalidTransition, reference)),
        }
    }

    /// Mutation-free validation of the exact delete right and current core
    /// slot. The native seven-predicate preflight uses this before making its
    /// ordered decision, while the intact deposit still owns `right`.
    pub(crate) fn validate_finish_delete_with_mount(
        &self,
        right: &DeleteSessionRight,
        mount: &PreparedMountDeactivation,
    ) -> Result<SlotDisposition, SessionError> {
        let index = authority_index(&right.authority)?;
        let Some(slot) = self.slots.get(index) else {
            return Err(SessionError::ReferenceNotFound);
        };
        if !slot_matches(slot, &right.authority) {
            return Err(SessionError::IdentityMismatch);
        }
        if slot.state != RegistrySlotState::Deleting || slot.strong_count != 0 {
            return Err(SessionError::InvalidTransition);
        }
        if mount.locator() != right.locator() {
            return Err(SessionError::IdentityMismatch);
        }
        Ok(match mount.required_disposition() {
            SlotDisposition::Retired => SlotDisposition::Retired,
            SlotDisposition::Free => disposition_for_generation(slot.generation),
        })
    }

    #[cfg(test)]
    pub(crate) fn validate_finish_delete(
        &self,
        right: &DeleteSessionRight,
    ) -> Result<SlotDisposition, SessionError> {
        let mount = PreparedMountDeactivation::for_test(right.locator());
        self.validate_finish_delete_with_mount(right, &mount)
    }

    #[doc(hidden)]
    pub(crate) fn prepare_finish_delete_with_mount(
        &self,
        right: DeleteSessionRight,
        mount: &PreparedMountDeactivation,
    ) -> Result<PreparedDeleteCoreCommit, (SessionError, DeleteSessionRight)> {
        let disposition = match self.validate_finish_delete_with_mount(&right, mount) {
            Ok(disposition) => disposition,
            Err(error) => return Err((error, right)),
        };
        Ok(PreparedDeleteCoreCommit {
            authority: right.authority,
            disposition,
        })
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub fn prepare_finish_delete(
        &self,
        right: DeleteSessionRight,
    ) -> Result<PreparedDeleteCoreCommit, (SessionError, DeleteSessionRight)> {
        let mount = PreparedMountDeactivation::for_test(right.locator());
        self.prepare_finish_delete_with_mount(right, &mount)
    }

    /// # Safety
    /// The caller must own the matching native `PreparedDelete`, must already
    /// have completed its infallible destructive suffix, and must hold the
    /// registry lock for the final mirror/reset publication.
    #[doc(hidden)]
    pub(crate) unsafe fn finish_delete(
        &mut self,
        prepared: PreparedDeleteCoreCommit,
    ) -> SlotDisposition {
        // SAFETY: `prepare_finish_delete` validated both the conversion and
        // the fixed-capacity slot before any native destruction began. The
        // sealed prepared commit is the same value carried through the suffix.
        let index = unsafe { usize::try_from(prepared.authority.slot_index).unwrap_unchecked() };
        let slot = unsafe { self.slots.get_unchecked_mut(index) };
        reset_slot(slot, prepared.disposition);
        prepared.disposition
    }

    #[allow(dead_code)]
    fn finish_removal(
        &mut self,
        terminal: TerminalSessionRef,
    ) -> Result<RegistryRelease, (SessionError, TerminalSessionRef)> {
        let index = match authority_index(&terminal.authority) {
            Ok(index) => index,
            Err(error) => return Err((error, terminal)),
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return Err((SessionError::ReferenceNotFound, terminal));
        };
        if !slot_matches(slot, &terminal.authority) {
            return Err((SessionError::IdentityMismatch, terminal));
        }
        if slot.state != RegistrySlotState::Removing || slot.fence_done || slot.strong_count == 0 {
            return Err((SessionError::InvalidTransition, terminal));
        }
        if slot.strong_count == 1 {
            slot.strong_count = 0;
            slot.state = RegistrySlotState::Deleting;
            return Ok(RegistryRelease::Delete(DeleteSessionRight {
                authority: terminal.authority,
            }));
        }
        slot.strong_count = slot.strong_count.saturating_sub(1);
        slot.fence_done = true;
        Ok(RegistryRelease::Retained)
    }

    #[cfg(test)]
    pub(crate) fn finish_removal_for_test(
        &mut self,
        terminal: TerminalSessionRef,
    ) -> Result<RegistryRelease, (SessionError, TerminalSessionRef)> {
        self.finish_removal(terminal)
    }

    fn publish_preflight(&self, installed: &InstalledSession) -> Option<SessionError> {
        let Ok(index) = authority_index(&installed.registry.authority) else {
            return Some(SessionError::ReferenceNotFound);
        };
        let Some(slot) = self.slots.get(index) else {
            return Some(SessionError::ReferenceNotFound);
        };
        if installed.registry.authority != installed.control.authority
            || !slot_matches(slot, &installed.registry.authority)
        {
            return Some(SessionError::IdentityMismatch);
        }
        if slot.state != RegistrySlotState::Staging || slot.strong_count != 2 || slot.fence_done {
            return Some(SessionError::InvalidTransition);
        }
        None
    }

    #[cfg(test)]
    fn slot_state(&self, index: usize) -> Option<RegistrySlotState> {
        self.slots.get(index).map(|slot| slot.state)
    }

    #[cfg(test)]
    fn slot_snapshot(&self, index: usize) -> Option<RegistrySlotSnapshot> {
        self.slots.get(index).map(|slot| RegistrySlotSnapshot {
            generation: slot.generation,
            identity: slot.identity,
            state: slot.state,
            strong_count: slot.strong_count,
            fence_done: slot.fence_done,
        })
    }

    #[cfg(test)]
    pub(crate) fn set_generation_for_test(&mut self, index: usize, generation: u64) {
        let Some(slot) = self.slots.get_mut(index) else {
            panic!("test slot exists")
        };
        assert_eq!(slot.state, RegistrySlotState::Free);
        slot.generation = generation;
    }
}

const fn disposition_for_generation(generation: u64) -> SlotDisposition {
    if generation == u64::MAX {
        SlotDisposition::Retired
    } else {
        SlotDisposition::Free
    }
}

fn reset_slot(slot: &mut RegistrySlot, disposition: SlotDisposition) {
    slot.identity = None;
    slot.state = match disposition {
        SlotDisposition::Free => RegistrySlotState::Free,
        SlotDisposition::Retired => RegistrySlotState::Retired,
    };
    slot.strong_count = 0;
    slot.fence_done = false;
}

fn authority_index(authority: &SessionAuthority) -> Result<usize, SessionError> {
    usize::try_from(authority.slot_index).map_err(|_| SessionError::ReferenceNotFound)
}

fn slot_matches(slot: &RegistrySlot, authority: &SessionAuthority) -> bool {
    slot.generation == authority.generation && slot.identity == Some(authority.identity)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegistrySlotSnapshot {
    generation: u64,
    identity: Option<SessionIdentity>,
    state: RegistrySlotState,
    strong_count: u32,
    fence_done: bool,
}

#[cfg(test)]
fn published_registry_at_generation<const N: usize>(
    identity: SessionIdentity,
    generation: u64,
) -> (SessionRegistry<N>, PublishedSession) {
    assert!(generation > 0);
    let mut registry = SessionRegistry::<N>::new();
    let Some(previous_generation) = generation.checked_sub(1) else {
        panic!("published test generation is nonzero")
    };
    registry.set_generation_for_test(0, previous_generation);
    let mut binding = match ControlBinding::new() {
        Ok(binding) => binding,
        Err(_) => panic!("test binding ID source has capacity"),
    };
    let reservation = match binding.begin_setup() {
        Ok(reservation) => reservation,
        Err(_) => panic!("test binding reserves its first epoch"),
    };
    let mut transaction = match SetupTransaction::begin(identity) {
        Ok(transaction) => transaction,
        Err(_) => panic!("valid test identity"),
    };
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = match transaction.stage(stage) {
            Ok(transaction) => transaction,
            Err(_) => panic!("strict test stage"),
        };
    }
    let installed = match registry.install_staging(&transaction, &binding, &reservation) {
        Ok(installed) => installed,
        Err(_) => panic!("test generation installs"),
    };
    transaction = match transaction.stage(SetupStage::ReferencesInstalled) {
        Ok(transaction) => transaction,
        Err(_) => panic!("references installed"),
    };
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = match publish_installed_setup_for_test(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        reservation,
        installed,
    ) {
        Ok(published) => published,
        Err(_) => panic!("test generation publishes"),
    };
    (registry, published)
}

/// One stage in the nonreorderable session fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceStage {
    CloseAdmissionAndSignal,
    RemoveProducerMappings,
    AcquireConsumers,
    DrainStablePrefixes,
    ReleaseAndDrainOwners,
    ReleaseViewsDevicesAndBacking,
}

/// One precisely ordered native-effect request in a fence stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceEffect {
    CloseSessionAdmission,
    SignalPendingEnter,
    RemoveProducerMappingsReverse,
    WaitProducerAndMappingCaptureRundown,
    AcquireConsumersIncreasing,
    DrainStablePrefixesBounded,
    RetireCredits,
    ReleaseConsumers,
    QueueInstalledWork,
    WaitPendingAndOwners,
    WaitControlRundown,
    ReleaseReadOnlyMappingsReverse,
    ReleaseMdlsAndSystemView,
    ReleaseCapturedProcess,
    DismountAndDeleteDevices,
    ReleaseTransientBacking,
}

/// The sole continuation capability for one committed session fence.
pub struct SessionFence {
    identity: SessionIdentity,
    next_stage: u8,
}

/// One immutable stage plan and its optional sole continuation.
pub struct FenceAdvance {
    stage: FenceStage,
    effects: &'static [FenceEffect],
    next: Option<SessionFence>,
}

impl FenceAdvance {
    /// The stage consumed to produce this plan.
    pub const fn stage(&self) -> FenceStage {
        self.stage
    }

    /// The exact immutable effect order for this stage.
    pub const fn effects(&self) -> &'static [FenceEffect] {
        self.effects
    }

    /// Consume this result into the sole next-stage capability, if any.
    pub fn into_next(self) -> Option<SessionFence> {
        self.next
    }
}

impl SessionFence {
    /// The exact six-stage teardown order.
    pub const STAGES: [FenceStage; 6] = [
        FenceStage::CloseAdmissionAndSignal,
        FenceStage::RemoveProducerMappings,
        FenceStage::AcquireConsumers,
        FenceStage::DrainStablePrefixes,
        FenceStage::ReleaseAndDrainOwners,
        FenceStage::ReleaseViewsDevicesAndBacking,
    ];
    /// Close admission, wake ENTER, then wait control rundown.
    pub const CLOSE_EFFECTS: [FenceEffect; 3] = [
        FenceEffect::CloseSessionAdmission,
        FenceEffect::SignalPendingEnter,
        FenceEffect::WaitControlRundown,
    ];
    /// Remove only producer-writable aliases, then wait capture/publication.
    pub const REMOVE_PRODUCER_EFFECTS: [FenceEffect; 2] = [
        FenceEffect::RemoveProducerMappingsReverse,
        FenceEffect::WaitProducerAndMappingCaptureRundown,
    ];
    /// Acquire every ring consumer in increasing order.
    pub const ACQUIRE_CONSUMER_EFFECTS: [FenceEffect; 1] =
        [FenceEffect::AcquireConsumersIncreasing];
    /// Drain stable prefixes and retire old-session credits.
    pub const DRAIN_EFFECTS: [FenceEffect; 2] = [
        FenceEffect::DrainStablePrefixesBounded,
        FenceEffect::RetireCredits,
    ];
    /// Release tokens before queueing and draining installed owners.
    pub const RELEASE_OWNER_EFFECTS: [FenceEffect; 3] = [
        FenceEffect::ReleaseConsumers,
        FenceEffect::QueueInstalledWork,
        FenceEffect::WaitPendingAndOwners,
    ];
    /// Release retained aliases and native backing in terminal order.
    pub const RELEASE_BACKING_EFFECTS: [FenceEffect; 5] = [
        FenceEffect::ReleaseReadOnlyMappingsReverse,
        FenceEffect::ReleaseMdlsAndSystemView,
        FenceEffect::ReleaseCapturedProcess,
        FenceEffect::DismountAndDeleteDevices,
        FenceEffect::ReleaseTransientBacking,
    ];

    /// Begin the sole fence for a committed identity.
    pub const fn begin(identity: SessionIdentity) -> Self {
        Self {
            identity,
            next_stage: 0,
        }
    }

    /// Consume one fence stage and return its sole optional continuation.
    pub fn advance(self) -> FenceAdvance {
        let (stage, effects, next_stage) = match self.next_stage {
            0 => (
                FenceStage::CloseAdmissionAndSignal,
                Self::CLOSE_EFFECTS.as_slice(),
                Some(1),
            ),
            1 => (
                FenceStage::RemoveProducerMappings,
                Self::REMOVE_PRODUCER_EFFECTS.as_slice(),
                Some(2),
            ),
            2 => (
                FenceStage::AcquireConsumers,
                Self::ACQUIRE_CONSUMER_EFFECTS.as_slice(),
                Some(3),
            ),
            3 => (
                FenceStage::DrainStablePrefixes,
                Self::DRAIN_EFFECTS.as_slice(),
                Some(4),
            ),
            4 => (
                FenceStage::ReleaseAndDrainOwners,
                Self::RELEASE_OWNER_EFFECTS.as_slice(),
                Some(5),
            ),
            _ => (
                FenceStage::ReleaseViewsDevicesAndBacking,
                Self::RELEASE_BACKING_EFFECTS.as_slice(),
                None,
            ),
        };
        FenceAdvance {
            stage,
            effects,
            next: next_stage.map(|next_stage| Self {
                identity: self.identity,
                next_stage,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// R4 Task 13: ring-set branding, the one-shot CQ bind right, and the pending
// control ledger reservation
// ---------------------------------------------------------------------------
//
// Everything below is R4 surface. Whether any of it has a production caller is
// measured by the live cutover gate
// `task19_r4_cutover_has_exactly_one_pending_terminal_delete_path` and by the
// graph auditor's rosters, not asserted here.
//
// This comment used to read "nothing in this block has a production caller
// until Task 19's atomic cutover, and the staging gate
// `task13_18_r4_staging_is_production_unreachable` is what proves that rather
// than a comment saying so." Task 19 closed, and the gate named is retired: it
// FAILs by design and no profile carries it. A comment citing a gate that does
// not run is a comment saying so, which is the thing the sentence promised it
// was not. See the measured dead-code note in `enter.rs` for the part of this
// surface that has no consumer at all.
//
// The shape these types exist to make impossible: a ring, a pending install, or
// a CQ storage bind that names one session while belonging to another. Every
// one of them therefore carries a *full* brand — locator, set identity, and
// per-ring state identity — and every transition compares the whole brand. A
// locator alone is not enough, because a slot is reused: two generations of the
// same slot share a slot index, so a check that stopped at the locator would
// accept a right minted for a session that is already gone.

private_authority_seals!(
    PrivateCqStorageBindAuthority,
    PrivateControlLinkAuthority,
    PrivatePendingLedgerReservationAuthority,
);

/// The largest ring set one session may hold, matching the cell count.
pub const MAX_SESSION_RING_COUNT: u32 = 64;

/// Per-ring enter-state identity. Nonwrapping and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RingEnterStateId(NonZeroU64);

/// Per-session ring-set identity. Nonwrapping and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SessionRingSetId(NonZeroU64);

/// Per-binding pending-ledger identity. Nonwrapping and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControlPendingLedgerId(NonZeroU64);

static NEXT_RING_SET_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RING_STATE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CONTROL_PENDING_LEDGER_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate one identity from a nonwrapping source, or report exhaustion.
///
/// `fetch_update` returning `None` at zero is what makes this nonwrapping: the
/// counter saturates into a permanent refusal instead of rolling over to an
/// identity some live brand already carries.
fn allocate_nonzero(source: &AtomicU64) -> Option<NonZeroU64> {
    source
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            if current == 0 {
                None
            } else {
                current.checked_add(1).or(Some(0))
            }
        })
        .ok()
        .and_then(NonZeroU64::new)
}

/// Every way a role, brand, or identity allocation can refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleError {
    DeviceBusy,
    WrongState,
    WrongRing,
    WrongInvocation,
    InvocationIdExhausted,
    StateIdExhausted,
    RingSetIdExhausted,
    RingCountOutOfRange,
    RingAlreadyInitialized,
}

/// Every way a pending-side operation can refuse.
///
/// The whole R4 set is declared here so later checkpoints add behaviour rather
/// than reshaping the error type under callers that already match on it. Task
/// 13 raises only the ledger variants; the rest are named by the R4 contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingError {
    WrongSession,
    WrongInstall,
    WrongIrp,
    AlreadyDequeued,
    NotDequeued,
    WrongReason,
    WrongRing,
    WrongRingState,
    WrongInvocation,
    AdmissionClosed,
    ControlLedgerIdentityExhausted,
    WrongControlLedger,
    LedgerFull,
    DuplicateLink,
    SlotOccupied,
    InvalidCapacity,
    ResultTooLarge,
    WrongSlot,
    WrongOwnerKind,
    DuplicateOwner,
    OwnerOverflow,
    OwnersRemain,
    Closing,
    InvalidCompletionStatus,
    InvalidCompletionInformation,
    WrongExecutionDomain,
    FinalPublicationAbandoned,
}

/// One ring's full brand: which session, which ring, which set, which state.
///
/// Hidden-public for Task 19: `fsring-fsd` names it to build one ring runtime
/// per slot. Every field stays private and the only producers are
/// `SessionRingSetInitializer::next_ring` and the set brand, so naming the type
/// buys a sibling nothing it could not already do -- it cannot forge one.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRingBrand {
    locator: SessionLocator,
    ring_index: u32,
    set_id: SessionRingSetId,
    state_id: RingEnterStateId,
}

impl SessionRingBrand {
    // Task 14's role/park/install transitions are the first locator readers;
    // Task 13 compares whole brands, which does not go through this accessor.
    #[allow(dead_code)]
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    // R4 surface. `session::tests` consumes this and the non-test build sees no
    // reader, which is what the attribute is for -- measured round 16: removing
    // every dead-code allow in this file does NOT produce a diagnostic for
    // `ring_index`, so the test consumers are real.
    //
    // What was false in the previous wording is the rest of it: "until Task 19's
    // cutover" named a task that has closed, and "the gate
    // `task13_18_r4_staging_is_production_unreachable` is what proves that is
    // still true" named a gate that is retired and FAILs by design.
    #[allow(dead_code)]
    pub const fn ring_index(&self) -> u32 {
        self.ring_index
    }
}

/// The completed set brand, produced only by `SessionRingSetInitializer::finish`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRingSetBrand {
    locator: SessionLocator,
    set_id: SessionRingSetId,
    ring_count: u32,
}

#[allow(dead_code)]
impl SessionRingSetBrand {
    pub const fn ring_count(&self) -> u32 {
        self.ring_count
    }

    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Whether `brand` is one of *this* set's rings.
    ///
    /// All four components are compared. Dropping the set identity would let a
    /// brand from an earlier ring set of the same session pass, which is
    /// exactly the confusion the set identity exists to prevent.
    ///
    /// Hidden-public since Task 19: the native pending runtime is built one
    /// slot at a time from rights minted *before* the set is sealed, so the
    /// only moment it can check that every slot belongs to the set it is about
    /// to be published under is at readiness — and that check happens in
    /// `fsring-fsd`, which therefore has to be able to ask.
    #[doc(hidden)]
    pub const fn contains_brand(&self, brand: SessionRingBrand) -> bool {
        locator_eq(self.locator, brand.locator)
            && self.set_id.0.get() == brand.set_id.0.get()
            && brand.ring_index < self.ring_count
    }
}

/// The one exclusive ring-set initializer an `InstalledSession` may hold.
///
/// It borrows the installed session mutably for its whole life, so a second
/// initializer cannot exist and the session cannot be published while one is
/// outstanding. That is the borrow checker enforcing "one set per install"
/// rather than a flag somebody has to remember to clear.
pub struct SessionRingSetInitializer<'installed> {
    installed: &'installed mut InstalledSession,
    set_id: SessionRingSetId,
    ring_count: u32,
    // Named `next_index`, not `next_ring`, on purpose: the production graph
    // auditor's edge model is a mention of a bare identifier, so a field
    // sharing a name with a staged *function* makes every reader of the field
    // look like a caller of the function. `finish` reads this cursor, and with
    // the field called `next_ring` the gate reported a
    // `driver_entry -> load -> finish -> next_ring` route that does not exist.
    next_index: u32,
}

/// A one-shot right to bind one ring's CQ storage.
///
/// `build_ring_runtime_parts` (Task 14) takes it by value and returns
/// `RingRuntimeParts`, and `BrandedCqStorage::bind_storage` (Task 20) spends it
/// for a `CqStorageBindTicket`. It is affine and carries no `Clone`, so the same
/// ring cannot be bound twice.
///
/// Neither path runs in production: the lane has no production constructor, and
/// the ticket the spend mints is never spent -- the gate document's section 11
/// non-claim records both. The previous wording, "Task 14 consumes it into
/// `RingRuntimeParts`", read as a description of something that happens.
#[allow(dead_code)]
pub struct CqStorageBindRight {
    brand: SessionRingBrand,
    authority: PrivateCqStorageBindAuthority,
}

#[allow(dead_code)]
impl CqStorageBindRight {
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    /// Which ring this right speaks for, for a native caller that must brand
    /// something else with the same identity before spending it.
    ///
    /// It REPORTS; it cannot rebind — the same shape, and for the same reason,
    /// as `PendingSlotParts::ring_brand`. The right stays affine and is still
    /// consumed exactly once by `build_pending_slot_parts`; reading the brand
    /// through a shared borrow mints no authority and cannot bind storage.
    ///
    /// SETUP needs this because the session shell's per-ring `RingEnterState`
    /// is allocated BEFORE the ring set exists, so it cannot be built by
    /// `RingEnterState::for_brand`. Without the brand that state answers
    /// `WrongState` to every R4 role request, which is what made the fence
    /// unable to acquire a CQ consumer on any ring.
    pub const fn ring_brand(&self) -> SessionRingBrand {
        self.brand
    }

    pub(crate) fn into_brand(self) -> SessionRingBrand {
        let Self {
            brand,
            authority: PrivateCqStorageBindAuthority(()),
        } = self;
        brand
    }
}

impl InstalledSession {
    /// Begin the one ring set this installation may have.
    ///
    /// Refuses a count outside `1..=MAX_SESSION_RING_COUNT` and refuses a
    /// second set outright: the completed set identity is recorded privately by
    /// `finish`, so a caller cannot re-enter this and mint a second brand
    /// family for a session whose first family is already published.
    pub fn begin_ring_set(
        &mut self,
        ring_count: u32,
    ) -> Result<SessionRingSetInitializer<'_>, RoleError> {
        if ring_count == 0 || ring_count > MAX_SESSION_RING_COUNT {
            return Err(RoleError::RingCountOutOfRange);
        }
        if self.ring_set.is_some() {
            return Err(RoleError::RingAlreadyInitialized);
        }
        let Some(set_id) = allocate_nonzero(&NEXT_RING_SET_ID) else {
            return Err(RoleError::RingSetIdExhausted);
        };
        Ok(SessionRingSetInitializer {
            installed: self,
            set_id: SessionRingSetId(set_id),
            ring_count,
            next_index: 0,
        })
    }

    /// The completed set brand, once `finish` has recorded one.
    pub(crate) const fn completed_ring_set(&self) -> Option<SessionRingSetBrand> {
        self.ring_set
    }
}

impl SessionRingSetInitializer<'_> {
    /// Allocate the next full brand and return only its one-shot bind right.
    ///
    /// `Ok(None)` means the set is complete. It mints only each ring's one-shot
    /// storage bind right. The pending ENTER runtime is built separately --
    /// `fsring-fsd`'s `build_pending_runtime` drives a
    /// `PendingRuntimeInitCursor` during SETUP -- so this cursor returns no
    /// runtime aggregate. (It used to say no pending component type existed
    /// yet, which stopped being true when those types arrived; round-17
    /// evidence E1.)
    pub fn next_ring(&mut self) -> Result<Option<CqStorageBindRight>, RoleError> {
        if self.next_index >= self.ring_count {
            return Ok(None);
        }
        let Some(state_id) = allocate_nonzero(&NEXT_RING_STATE_ID) else {
            // Exhaustion leaves the initializer *unchanged*, so the caller may
            // still `abort` cleanly. Advancing the cursor before the allocation
            // succeeded would burn a ring index on a brand that never existed.
            return Err(RoleError::StateIdExhausted);
        };
        let brand = SessionRingBrand {
            locator: self.installed.locator(),
            ring_index: self.next_index,
            set_id: self.set_id,
            state_id: RingEnterStateId(state_id),
        };
        self.next_index = self.next_index.saturating_add(1);
        Ok(Some(CqStorageBindRight {
            brand,
            authority: PrivateCqStorageBindAuthority(()),
        }))
    }

    /// Seal a fully-allocated set, recording it inside the installed session.
    ///
    /// A partially-allocated set is refused and returned intact: publishing a
    /// set brand whose rings were never branded would advertise a ring count no
    /// ring actually carries.
    pub fn finish(self) -> Result<SessionRingSetBrand, (RoleError, Self)> {
        if self.next_index != self.ring_count {
            return Err((RoleError::WrongRing, self));
        }
        let brand = SessionRingSetBrand {
            locator: self.installed.locator(),
            set_id: self.set_id,
            ring_count: self.ring_count,
        };
        self.installed.ring_set = Some(brand);
        Ok(brand)
    }

    /// Reverse a partial initialization.
    ///
    /// Nothing is recorded on the installed session until `finish`, so aborting
    /// is exactly dropping the borrow — but the method exists so the intent is
    /// in the call site rather than in a silent scope end.
    pub fn abort(self) {}
}

/// The full brand a pending control ledger and its links carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlPendingBrand {
    binding_id: ControlBindingId,
    locator: SessionLocator,
    ledger_id: ControlPendingLedgerId,
}

#[allow(dead_code)]
impl ControlPendingBrand {
    pub(crate) const fn locator(&self) -> SessionLocator {
        self.locator
    }

    /// Whether this brand belongs to `binding`.
    ///
    /// `ControlBindingId` never crosses the sibling boundary, so this
    /// comparison is the only way another module can ask the question.
    pub(crate) fn matches_binding(&self, binding: &ControlBinding) -> bool {
        self.binding_id == binding.binding_id
    }
}

/// One pending install's identity: which ring, and which install epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingInstallId {
    brand: SessionRingBrand,
    install_epoch: u64,
}

impl PendingInstallId {
    /// Build one install identity for a test.
    ///
    /// Task 14.2 owns the production minting path (an installer holding the
    /// ring's park authority). Until it exists, the 14.3 owner/wake/schedule
    /// tests need install identities to compare, and inventing one here is
    /// honest about that: it is `cfg(test)`, so no production path can reach it.
    #[cfg(test)]
    pub(crate) const fn for_test(brand: SessionRingBrand, install_epoch: u64) -> Self {
        Self {
            brand,
            install_epoch,
        }
    }

    // Task 14 reads both when it mints and matches install epochs; Task 13
    // only ever compares whole `PendingInstallId` values for ledger identity.
    #[allow(dead_code)]
    pub(crate) const fn brand(&self) -> SessionRingBrand {
        self.brand
    }

    /// This install's session, for reaching the session's own ledger.
    ///
    /// Hidden-public like [`PendingControlLinkRight::locator`]: native needs
    /// this to find the `PendingControlLedger` a `PendingInstallId` names
    /// *before* it holds any right into that ledger, which is exactly the
    /// case `link` itself is for.
    #[doc(hidden)]
    pub const fn locator(&self) -> SessionLocator {
        self.brand.locator
    }

    #[allow(dead_code)]
    /// The epoch this install reserved.
    ///
    /// Public because the native timer cancel must name the epoch it believes
    /// it owns rather than read it back out of the state it is validating.
    /// `TimerState::cancel` refuses a mismatch with `NotThisInstall`, and that
    /// arm exists to stop a stale generation being handed an obligation to
    /// wait on a DPC-exit event only the live generation will ever signal --
    /// an unbounded PASSIVE block. A caller that sources the epoch from the
    /// timer makes the arm unreachable and the refusal meaningless.
    pub const fn install_epoch(&self) -> u64 {
        self.install_epoch
    }

    /// The sole production minter: pair a ring with the epoch its slot just
    /// reserved.
    ///
    /// Private to this module, so the only way to reach it is the free function
    /// below — which cannot be called without a slot state that actually moves
    /// `Vacant -> Installing`. An identity therefore cannot exist for a slot
    /// that did not just reserve it, which is the whole reason a slot index
    /// alone is not an identity.
    const fn from_reserved(brand: SessionRingBrand, install_epoch: u64) -> Self {
        Self {
            brand,
            install_epoch,
        }
    }
}

/// Reserve one slot's next epoch and mint the install identity it names.
///
/// This is `PendingInstallEffect::ReservePendingSlotEpoch`, and it is the only
/// production route to a `PendingInstallId`. The transition and the identity are
/// produced together on purpose: a minter that took an epoch as an argument
/// could be handed one the slot never issued, and a transition that returned no
/// identity would leave the caller to invent one.
///
/// A refusal returns the slot state **unchanged**, so a caller that loses the
/// race for an occupied slot has reserved nothing and owes nothing back.
#[doc(hidden)]
pub fn reserve_pending_install(
    brand: SessionRingBrand,
    state: crate::enter::PendingSlotState,
) -> Result<
    (crate::enter::PendingSlotState, PendingInstallId),
    (PendingError, crate::enter::PendingSlotState),
> {
    let reserved = state.begin_install()?;
    let Some(epoch) = reserved.epoch() else {
        // `begin_install` returns `Installing`, which always has an epoch. A
        // state without one here would mean the transition changed underneath
        // this function, so refuse rather than mint an identity from a default.
        return Err((PendingError::WrongRingState, state));
    };
    Ok((reserved, PendingInstallId::from_reserved(brand, epoch)))
}

/// An affine right proving one install is linked into one exact ledger.
#[cfg_attr(test, derive(Debug))]
pub struct PendingControlLinkRight {
    brand: ControlPendingBrand,
    install: PendingInstallId,
    slot_index: u32,
    // The seal is never *read*: it exists so no sibling can construct this
    // right. `PendingControlLedger::unlink` consumes the right by value and
    // drops the seal with it, so rustc reports the field as never read, and
    // this allow is what an unread seal costs.
    #[allow(dead_code)]
    authority: PrivateControlLinkAuthority,
}

impl PendingControlLinkRight {
    #[doc(hidden)]
    pub const fn install(&self) -> PendingInstallId {
        self.install
    }

    #[doc(hidden)]
    pub const fn locator(&self) -> SessionLocator {
        self.brand.locator
    }
}

/// The bound ledger a published session owns.
///
/// `slots[ring_index]` holds that ring's live install epoch, or zero for none.
///
/// It stores the epoch and nothing else on purpose. A whole `PendingInstallId`
/// per slot is ~88 bytes, and sixty-four of them is a 5.6 KB array that the
/// aggregate publication then moves across a `Result` and onto SETUP's frame --
/// the exact shape the plan forbids, and the one the stack audit measured at a
/// 54040-byte `execute_setup` frame. Nothing is lost by dropping the rest:
/// every install in one ledger shares the ledger's own locator and ring set,
/// and a ring's `state_id` is allocated once, so `(ring_index, epoch)` already
/// names the install uniquely. Indexing by ring also makes "one install per
/// ring" structural, where a first-free scan needed a duplicate check to say so.
///
/// Epoch zero is never issued, which is what lets it mean "free" here without a
/// second occupancy word.
pub struct PendingControlLedger<const N: usize> {
    brand: ControlPendingBrand,
    slots: [u64; N],
    admission_open: bool,
}

/// The unpublished ledger, reserved while the binding is still Staging.
///
/// It is affine and carries the setup epoch it was reserved under, so a
/// reservation cannot be carried across a failed SETUP into the next one.
pub struct PendingControlLedgerReservation<const N: usize> {
    brand: ControlPendingBrand,
    slots: [u64; N],
    setup_epoch: SetupEpoch,
    authority: PrivatePendingLedgerReservationAuthority,
}

impl<const N: usize> PendingControlLedger<N> {
    /// A bound ledger for one locator, for a sibling module's tests.
    ///
    /// The production route is `reserve_for_setup` under a Staging binding
    /// followed by the aggregate publication, which needs a whole registry and
    /// control binding. `enter::tests` needs only a `PendingControlLinkRight`
    /// to hand to a completion plan, and building a session to get one would
    /// test the setup path rather than the completion path. `cfg(test)`, so no
    /// production caller can reach it.
    #[cfg(test)]
    pub(crate) fn bound_for_test(locator: SessionLocator) -> Self {
        let one = match NonZeroU64::new(u64::MAX) {
            Some(value) => value,
            None => unreachable!("u64::MAX is nonzero"),
        };
        Self {
            brand: ControlPendingBrand {
                binding_id: ControlBindingId(one),
                locator,
                ledger_id: ControlPendingLedgerId(one),
            },
            slots: [0; N],
            admission_open: true,
        }
    }

    /// Reserve one ledger for a SETUP that has a completed ring set.
    ///
    /// Runs while the binding is still the exact branded `Staging(epoch)`, so
    /// identity exhaustion refuses *before* anything is published — a Live
    /// session without its pending ledger is a state the rest of R4 has no way
    /// to represent.
    pub fn reserve_for_setup(
        binding: &ControlBinding,
        reservation: &SetupReservation,
        ring_set: SessionRingSetBrand,
    ) -> Result<PendingControlLedgerReservation<N>, PendingError> {
        if binding.binding_id != reservation.binding_id {
            return Err(PendingError::WrongControlLedger);
        }
        let setup_epoch = match binding.state {
            ControlBindingState::Staging(epoch) if epoch == reservation.setup_epoch => epoch,
            _ => return Err(PendingError::WrongSession),
        };
        let Some(ledger_id) = allocate_nonzero(&NEXT_CONTROL_PENDING_LEDGER_ID) else {
            return Err(PendingError::ControlLedgerIdentityExhausted);
        };
        Ok(PendingControlLedgerReservation {
            brand: ControlPendingBrand {
                binding_id: binding.binding_id,
                locator: ring_set.locator,
                ledger_id: ControlPendingLedgerId(ledger_id),
            },
            slots: [0; N],
            setup_epoch,
            authority: PrivatePendingLedgerReservationAuthority(()),
        })
    }

    pub fn close_admission(&mut self) {
        self.admission_open = false;
    }

    #[allow(dead_code)]
    pub(crate) const fn brand(&self) -> ControlPendingBrand {
        self.brand
    }

    /// Link one install, returning its affine right.
    ///
    /// The slot is the install's own ring index, so a second install for a ring
    /// that already has one is refused by the slot being occupied rather than by
    /// a scan that could be weakened without any other check noticing.
    pub fn link(
        &mut self,
        install: PendingInstallId,
    ) -> Result<PendingControlLinkRight, PendingError> {
        if !self.admission_open {
            return Err(PendingError::AdmissionClosed);
        }
        if !locator_eq(self.brand.locator, install.brand.locator) {
            return Err(PendingError::WrongSession);
        }
        // Zero is the free marker, so an install that carried it could never be
        // unlinked again. Task 14's minter starts at one; this refuses rather
        // than trusting that from a distance.
        if install.install_epoch == 0 {
            return Err(PendingError::WrongInstall);
        }
        let slot_index = install.brand.ring_index;
        let Ok(index) = usize::try_from(slot_index) else {
            return Err(PendingError::LedgerFull);
        };
        // Taking the slot by `get_mut` is what makes the bound structural rather
        // than a comment: section 5 keeps panicking indexes off the driver input
        // paths. A ring outside this ledger's capacity is `LedgerFull`.
        let Some(slot) = self.slots.get_mut(index) else {
            return Err(PendingError::LedgerFull);
        };
        if *slot != 0 {
            return Err(PendingError::DuplicateLink);
        }
        *slot = install.install_epoch;
        Ok(PendingControlLinkRight {
            brand: self.brand,
            install,
            slot_index,
            authority: PrivateControlLinkAuthority(()),
        })
    }

    /// Unlink one install. Refusal returns the exact right, unconsumed.
    // Every refusal returns the affine owners it was handed, which is the
    // property that proves nothing was consumed on the refused path. Boxing
    // it would need an allocator this path does not have.
    #[allow(clippy::result_large_err)]
    pub fn unlink(
        &mut self,
        right: PendingControlLinkRight,
    ) -> Result<(), (PendingError, PendingControlLinkRight)> {
        if right.brand != self.brand {
            return Err((PendingError::WrongControlLedger, right));
        }
        // The right's own two halves must agree before either is used as an
        // index or a comparand: a right whose slot index did not name its
        // install's ring would otherwise unlink a different ring's install.
        if right.slot_index != right.install.brand.ring_index {
            return Err((PendingError::WrongSlot, right));
        }
        let Ok(index) = usize::try_from(right.slot_index) else {
            return Err((PendingError::WrongSlot, right));
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return Err((PendingError::WrongSlot, right));
        };
        if *slot == 0 || *slot != right.install.install_epoch {
            return Err((PendingError::WrongSlot, right));
        }
        *slot = 0;
        Ok(())
    }
}

/// The aggregate a superseding SETUP publication returns.
pub struct PublishedRingSetup<const P: usize> {
    published: PublishedSession,
    pending: PendingControlLedger<P>,
}

impl<const P: usize> PublishedRingSetup<P> {
    pub fn into_parts(self) -> (PublishedSession, PendingControlLedger<P>) {
        (self.published, self.pending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingSetupPublishError {
    Session(SessionError),
    Pending(PendingError),
}

/// Every affine input a refused aggregate publication returns intact.
pub struct RingSetupPublishFailure<const P: usize> {
    error: RingSetupPublishError,
    transaction: SetupTransaction,
    ring_set: SessionRingSetBrand,
    reservation: SetupReservation,
    installed: InstalledSession,
    pending: PendingControlLedgerReservation<P>,
}

impl<const P: usize> RingSetupPublishFailure<P> {
    pub const fn error(&self) -> RingSetupPublishError {
        self.error
    }

    pub fn into_parts(
        self,
    ) -> (
        RingSetupPublishError,
        SetupTransaction,
        SessionRingSetBrand,
        SetupReservation,
        InstalledSession,
        PendingControlLedgerReservation<P>,
    ) {
        let Self {
            error,
            transaction,
            ring_set,
            reservation,
            installed,
            pending,
        } = self;
        (
            error,
            transaction,
            ring_set,
            reservation,
            installed,
            pending,
        )
    }
}

// ---------------------------------------------------------------------------
// R4 Task 19: the mutation-free aggregate setup boundary
// ---------------------------------------------------------------------------
//
// `publish_installed_setup_with_ring_set` preflights and commits in one call.
// That is fine while the native side has nothing to install between the two,
// and wrong the moment it does: the cutover has to write a `PendingRuntimeReady`
// into the permanent cell *and* publish Live/Active/rendezvous with no window in
// between, and a single call gives its caller nowhere to stand.
//
// The split below is the whole of it. Preparation validates everything and
// mutates nothing, so a native preflight that refuses afterwards can hand back
// all five affine inputs untouched. The commit is `unsafe`, infallible, and
// takes no arguments: by the time it runs the caller has already installed the
// runtime, and there is no decision left for it to get wrong.

/// Everything one aggregate publication validated, before anything moved.
///
/// It retains the three exclusive object borrows, which is what makes "the same
/// registry lock is held from preparation through commit" a borrow-checked fact
/// rather than a comment. Neither the borrows nor any affine input is
/// projectable: the only two exits are the mutation-free decomposition and the
/// one commit.
#[must_use]
pub struct PreparedRingSetupPublish<'objects, const N: usize, const P: usize> {
    registry: &'objects mut SessionRegistry<N>,
    binding: &'objects mut ControlBinding,
    rendezvous: &'objects mut TerminalRendezvous,
    transaction: SetupTransaction,
    ring_set: SessionRingSetBrand,
    reservation: SetupReservation,
    installed: InstalledSession,
    pending: PendingControlLedgerReservation<P>,
}

/// Validate one aggregate publication without mutating anything.
///
/// Every check `publish_installed_setup_with_ring_set` performs, in the same
/// order and with the same errors -- but the Task 4 publication that used to
/// follow immediately now waits for [`PreparedRingSetupPublish::
/// commit_after_native_runtime_install`].
// Same two reasons as the publisher below: the refusal returns every large
// affine input intact, and the eight parameters are the eight distinct inputs
// of one publication -- grouping them into a struct would let a caller build a
/// Why one aggregate publication may not proceed, or `None` if it may.
///
/// It borrows everything, so asking costs no affine value and the answer can be
/// had *before* the exclusive borrows that preparation retains exist. That
/// matters to the native caller: its locked suffix mutates the same permanent
/// cell through raw pointers between preparation and commit, so a preparation
/// held open across the suffix would have an outstanding `&mut` into a cell that
/// the suffix reborrows whole. Asking first and preparing immediately before
/// the commit keeps every borrow inside one step, and keeps the decision in one
/// place rather than two copies that drift.
///
/// The Task 4 half goes through `installed_setup_publication_refusal`, the same
/// predicate the ordinary publication uses, for the same reason.
// Eight borrows of the eight distinct inputs of one publication.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn installed_ring_setup_publication_refusal<const N: usize, const P: usize>(
    transaction: &SetupTransaction,
    registry: &SessionRegistry<N>,
    binding: &ControlBinding,
    rendezvous: &TerminalRendezvous,
    ring_set: &SessionRingSetBrand,
    reservation: &SetupReservation,
    installed: &InstalledSession,
    pending: &PendingControlLedgerReservation<P>,
) -> Option<RingSetupPublishError> {
    // Each arm is a distinct property that happens to share an error value;
    // collapsing them would hide which check refused.
    #[allow(clippy::if_same_then_else)]
    if !locator_eq(ring_set.locator, installed.locator()) {
        Some(RingSetupPublishError::Session(
            SessionError::IdentityMismatch,
        ))
    } else if installed.completed_ring_set() != Some(*ring_set) {
        Some(RingSetupPublishError::Session(
            SessionError::InvalidTransition,
        ))
    } else if !pending.brand.matches_binding(binding) {
        Some(RingSetupPublishError::Pending(
            PendingError::WrongControlLedger,
        ))
    } else if !locator_eq(pending.brand.locator, ring_set.locator) {
        Some(RingSetupPublishError::Pending(PendingError::WrongSession))
    } else if pending.setup_epoch != reservation.setup_epoch {
        Some(RingSetupPublishError::Pending(PendingError::WrongSession))
    } else {
        installed_setup_publication_refusal(
            transaction,
            registry,
            binding,
            rendezvous,
            reservation,
            installed,
        )
        .map(RingSetupPublishError::Session)
    }
}

// partial setup and hold it, which is what taking them together prevents.
#[doc(hidden)]
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub fn prepare_installed_ring_setup<'objects, const N: usize, const P: usize>(
    transaction: SetupTransaction,
    registry: &'objects mut SessionRegistry<N>,
    binding: &'objects mut ControlBinding,
    rendezvous: &'objects mut TerminalRendezvous,
    ring_set: SessionRingSetBrand,
    reservation: SetupReservation,
    installed: InstalledSession,
    pending: PendingControlLedgerReservation<P>,
) -> Result<PreparedRingSetupPublish<'objects, N, P>, RingSetupPublishFailure<P>> {
    let refusal = installed_ring_setup_publication_refusal(
        &transaction,
        registry,
        binding,
        rendezvous,
        &ring_set,
        &reservation,
        &installed,
        &pending,
    );
    if let Some(error) = refusal {
        return Err(RingSetupPublishFailure {
            error,
            transaction,
            ring_set,
            reservation,
            installed,
            pending,
        });
    }
    Ok(PreparedRingSetupPublish {
        registry,
        binding,
        rendezvous,
        transaction,
        ring_set,
        reservation,
        installed,
        pending,
    })
}

impl<const N: usize, const P: usize> PreparedRingSetupPublish<'_, N, P> {
    /// Cancel without mutating anything, returning every affine input.
    ///
    /// The three exclusive object borrows end here, which is the point: a
    /// native preflight that refuses needs them back to unwind, and a
    /// cancellation that kept them would deadlock the unwind against itself.
    #[doc(hidden)]
    pub fn into_uncommitted_parts(
        self,
    ) -> (
        SetupTransaction,
        SessionRingSetBrand,
        SetupReservation,
        InstalledSession,
        PendingControlLedgerReservation<P>,
    ) {
        let Self {
            registry: _,
            binding: _,
            rendezvous: _,
            transaction,
            ring_set,
            reservation,
            installed,
            pending,
        } = self;
        (transaction, ring_set, reservation, installed, pending)
    }

    /// The one Staging -> Live/Active/rendezvous commit.
    ///
    /// # Safety
    /// The caller holds the exact enclosing registry lock it held at
    /// preparation, has installed the matching preflighted pending runtime into
    /// this session's permanent native cell, and will neither unlock nor expose
    /// the cell before this returns. Nothing here can refuse: every decision
    /// was made by `prepare_installed_ring_setup`, which mutated nothing.
    #[doc(hidden)]
    pub unsafe fn commit_after_native_runtime_install(self) -> PublishedRingSetup<P> {
        let Self {
            registry,
            binding,
            rendezvous,
            transaction,
            ring_set: _,
            reservation,
            installed,
            pending,
        } = self;
        let prepared = match prepare_installed_setup_publication(
            transaction,
            registry,
            binding,
            rendezvous,
            reservation,
            installed,
        ) {
            Ok(prepared) => prepared,
            Err(_) => unreachable!("preparation validated every publication check"),
        };
        let published = commit_prepared_installed_setup(prepared, registry, binding, rendezvous);
        let PendingControlLedgerReservation {
            brand,
            slots,
            setup_epoch: _,
            authority: PrivatePendingLedgerReservationAuthority(()),
        } = pending;
        PublishedRingSetup {
            published,
            pending: PendingControlLedger {
                brand,
                slots,
                admission_open: true,
            },
        }
    }
}

/// The superseding aggregate publication: ring set and pending ledger together.
///
/// Nothing calls this outside tests. Measured round 16: its only callers are
/// `session::tests` and `adapter::enter::tests`.
///
/// The bound "until Task 19" has been removed: Task 19 closed and no production
/// caller arrived, so the sentence was promising a commit rather than
/// describing the tree.
///
/// The whole point of the aggregate is that the ring set and the pending ledger
/// become visible in the *same* suffix as Live/Active. Publishing the session
/// first and binding the ledger afterwards would leave a window in which a Live
/// session has no ledger, and every pending install in R4 is addressed through
/// that ledger — so the window is not a small one, it is the state in which a
/// parked ENTER cannot be found.
// The eight parameters are the eight distinct inputs of one publication.
// Grouping them into a struct would let a caller build a partial setup and hold
// it, which is exactly what taking them together prevents.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub fn publish_installed_setup_with_ring_set<const N: usize, const P: usize>(
    transaction: SetupTransaction,
    registry: &mut SessionRegistry<N>,
    binding: &mut ControlBinding,
    rendezvous: &mut TerminalRendezvous,
    ring_set: SessionRingSetBrand,
    reservation: SetupReservation,
    installed: InstalledSession,
    pending: PendingControlLedgerReservation<P>,
) -> Result<PublishedRingSetup<P>, RingSetupPublishFailure<P>> {
    // Preflight the two R4 additions *before* touching the Task 4 path, so a
    // refusal here has mutated nothing at all.
    // Each arm is a distinct property that happens to share an error
    // value; collapsing them would hide which check refused.
    #[allow(clippy::if_same_then_else)]
    let refusal = if !locator_eq(ring_set.locator, installed.locator()) {
        Some(RingSetupPublishError::Session(
            SessionError::IdentityMismatch,
        ))
    } else if installed.completed_ring_set() != Some(ring_set) {
        Some(RingSetupPublishError::Session(
            SessionError::InvalidTransition,
        ))
    } else if !pending.brand.matches_binding(binding) {
        Some(RingSetupPublishError::Pending(
            PendingError::WrongControlLedger,
        ))
    } else if !locator_eq(pending.brand.locator, ring_set.locator) {
        Some(RingSetupPublishError::Pending(PendingError::WrongSession))
    } else if pending.setup_epoch != reservation.setup_epoch {
        Some(RingSetupPublishError::Pending(PendingError::WrongSession))
    } else {
        None
    };
    if let Some(error) = refusal {
        return Err(RingSetupPublishFailure {
            error,
            transaction,
            ring_set,
            reservation,
            installed,
            pending,
        });
    }

    match prepare_installed_setup_publication(
        transaction,
        registry,
        binding,
        rendezvous,
        reservation,
        installed,
    ) {
        Ok(prepared) => {
            let published =
                commit_prepared_installed_setup(prepared, registry, binding, rendezvous);
            let PendingControlLedgerReservation {
                brand,
                slots,
                setup_epoch: _,
                authority: PrivatePendingLedgerReservationAuthority(()),
            } = pending;
            Ok(PublishedRingSetup {
                published,
                pending: PendingControlLedger {
                    brand,
                    slots,
                    admission_open: true,
                },
            })
        }
        Err(failure) => {
            let (error, transaction, reservation, installed) = failure.into_parts();
            Err(RingSetupPublishFailure {
                error: RingSetupPublishError::Session(error),
                transaction,
                ring_set,
                reservation,
                installed,
                pending,
            })
        }
    }
}

// `pub(crate)` so that other test modules can share one lifecycle-cell
// fixture rather than restating it. A second, divergent construction of a
// published cell is exactly the failure this project has already paid for.
#[cfg(test)]
pub(crate) mod tests;
