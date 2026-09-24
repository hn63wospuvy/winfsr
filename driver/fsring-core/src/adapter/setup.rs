//! WDK-free SETUP choreography: allocation, protected views, one commit.
//!
//! `02-transport.md` section 10.3 and `10-lifecycle.md` section 4 fix the order
//! in which a SETUP acquires the control rundown, burns a volatile `MountId`
//! under the BootContext lock, builds the shared section, grants, events, secure
//! VDO, and protected user aliases, validates the complete result, and only then
//! performs the single Release publication. This module owns all of that as a
//! closed ordered plan so the host test binary can prove it on a machine that
//! cannot load a driver. `fsring-fsd` translates one typed effect into exactly
//! one native operation and reports the matching outcome; it restates none of
//! the transition order and none of the unwind order.
//!
//! Like [`super::load`], a plan here is an *ordering and ownership model*, never
//! a resource owner. It cannot claim a handle, mapping, MDL, device, or
//! reference exists: only the native executor can, and it keeps those in its own
//! affine wrappers.
//!
//! The one publication rule the whole module exists to make structural: before
//! [`SetupEffect::PublishLockedSuffix`] a failure or cancellation yields the exact
//! reverse [`SetupRollbackPlan`]; at or after it there is no rollback to yield,
//! because the Release store has made the session reachable and every remaining
//! native action is designed infallible.

use core::num::NonZeroUsize;

use fsring_abi::{
    BootInstanceId, MountId,
    features::PlatformProfile,
    layout::RegionDesc,
    section_layout::SectionLayoutPlan,
    validate::{SessionIdentity, ValidatedSetupRequest, session_result_size_v1},
};

use super::AdapterPlanError;
use crate::session::{
    CleanupBindingClaim, ControlBinding, ControlBindingState, SessionError, SessionLocator,
    SetupCleanupRight, SetupEpoch, SetupReservation, SlotDisposition,
};

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// The ordered SETUP choreography
// ---------------------------------------------------------------------------

/// One native operation in the non-skippable successful SETUP sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupEffect {
    AcquireControlRundown,
    SnapshotAndValidateInput,
    ValidateOutputCapacity,
    RejectDuplicate,
    AcquireBootLockEvent,
    BurnMountId,
    ReleaseBootLockEvent,
    ComputeLayoutAndLedger,
    AllocateSectionAndSystemView,
    ConstructAndValidateSection,
    AllocateGrants,
    AllocateEventsAndScratch,
    CreateSecureVdo,
    CaptureProcess,
    BuildProtectedViews,
    BuildOutput,
    ValidateOutput,
    InstallStaging,
    CopyValidatedOutput,
    PublishLockedSuffix,
    EmitSessionPublished,
    ReleaseSetupAdmission,
    SignalSetupComplete,
    ReturnProviderDisposition,
    OuterReleaseControlRundown,
}

const SETUP_COMMIT: [SetupEffect; 2] = [
    SetupEffect::CopyValidatedOutput,
    SetupEffect::PublishLockedSuffix,
];

const SETUP_TAIL: [SetupEffect; 5] = [
    SetupEffect::EmitSessionPublished,
    SetupEffect::ReleaseSetupAdmission,
    SetupEffect::SignalSetupComplete,
    SetupEffect::ReturnProviderDisposition,
    SetupEffect::OuterReleaseControlRundown,
];

// ---------------------------------------------------------------------------
// Production-consumed control-context lifecycle plans
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlContextCreateEffect {
    AcquireLease,
    AllocateAndInitialize,
    CaptureRequestor,
    PublishFsContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlContextCreateRollbackEffect {
    ReleaseRequestor,
    FreeAllocation,
    ReleaseLease,
}

pub struct ControlContextCreateRollbackPlan {
    effects: &'static [ControlContextCreateRollbackEffect],
}

pub struct ControlContextCreatePlan;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlContextCloseOwnership {
    CloseRight,
    Lease,
    CellOwned,
}

/// What a CLOSE can find in a control context's lifetime slot.
///
/// The kernel enum carries affine payloads and lives in `fsring-fsd`, which has
/// no host test target at all. This is the same shape without the payloads, so
/// the classification below is decided HERE, where a test can drive every
/// variant and watch a wrong answer fail.
///
/// Round 16's blocker was that every published session leaked its context and
/// `fsring_driver_unload` then waited for ever on `control_context_admission`.
/// Round 17 blamed this classification and let CLOSE free `Completed`. The
/// actual cause was that CLEANUP never acknowledged the finalizer's record: its
/// winner and joiner claimed once, before the terminal ran, and a CLEANUP
/// arriving after the fence's rundown wait claimed nothing. Freeing
/// `Completed` bypassed that acknowledgement, and the process-loss and unload
/// scans then dereferenced the freed context (native review N17-1).
/// `continue_cleanup` makes the acknowledgement reachable; this classification
/// is the design's again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlContextLifetimeKind {
    /// A CREATE admission lease; no session was ever published through it.
    Lease,
    /// A live cell owns the context. No close authority is present here.
    LiveCellOwned,
    /// A terminal completed and the finalizer stored its record. The record
    /// carries the close right, but only CLEANUP consumes it -- into
    /// [`ControlContextLifetimeKind::Close`] -- and CLOSE frees nothing before
    /// that.
    Completed,
    /// An acknowledged context: the close right stands on its own.
    Close,
    /// Empty, or a fail-stopped generation that keeps its authority for ever.
    BlockedCellOwned,
}

/// Whether the binding says nothing is installed through this context.
///
/// `Empty` is what CREATE leaves in a fresh binding and what a rolled-back
/// SETUP returns to; in both, no cell, scan or terminal names this context.
/// Every other state names something that does: a staging epoch, a live
/// locator, or a terminal whose record is still being carried.
///
/// A `match` with no catch-all on purpose: a new [`ControlBindingState`]
/// without a decision here is an E0004, not a silent "nothing is installed"
/// that would let CLOSE free a context somebody still owns. Its table lives in
/// `session::tests`, which is the only module that can construct every state --
/// `SetupEpoch` holds a private field.
pub const fn binding_holds_no_installation(state: ControlBindingState) -> bool {
    match state {
        ControlBindingState::Empty(_) => true,
        ControlBindingState::Staging(_)
        | ControlBindingState::Active(_)
        | ControlBindingState::ClosingSetup(_)
        | ControlBindingState::ClosingLive(_)
        | ControlBindingState::ClosingComplete { .. }
        | ControlBindingState::ClosingBlocked { .. }
        | ControlBindingState::ClosingOpaqueRetained { .. }
        | ControlBindingState::Closed => false,
    }
}

impl ControlContextCloseOwnership {
    pub const fn may_free(self) -> bool {
        matches!(self, Self::CloseRight)
    }

    /// Adopt a CREATE admission lease no one else owns.
    ///
    /// CLEANUP's precommit route is what normally converts that lease into a
    /// close right (`move_lease_to_close`). A CLOSE can arrive with the lease
    /// still in the slot two ways: a precommit CLEANUP that refused before the
    /// transfer, and a CLOSE with no CLEANUP at all, which is how the I/O
    /// manager tears down a file object that never received a handle. Both
    /// used to leak the context AND the admission, leaving
    /// `fsring_driver_unload` waiting for ever on a rundown with no signaller
    /// (native review N18-2).
    ///
    /// `holds_no_installation` is [`binding_holds_no_installation`] of the
    /// binding's own state, read under the same registry lock that takes the
    /// slot -- not an argument about what a lease implies. A lease under a
    /// binding that still holds an installation is left alone and still leaks,
    /// because freeing a context something else may name is the worse failure.
    pub const fn adopt_unused_lease(self, holds_no_installation: bool) -> Self {
        match (self, holds_no_installation) {
            (Self::Lease, true) => Self::CloseRight,
            (other, _) => other,
        }
    }

    /// Total over every lifetime a CLOSE can observe.
    ///
    /// `match` and not a chain of `if`s on purpose: a variant added to
    /// [`ControlContextLifetimeKind`] without a decision here is an E0004, not a
    /// silent fall-through to "somebody else owns it" — which is exactly the
    /// answer that leaked every published session.
    pub const fn for_lifetime(kind: ControlContextLifetimeKind) -> Self {
        match kind {
            // Only the acknowledged lifetime frees. The approved design: "CLOSE
            // alone mutation-free preflights the exact Closed/acknowledged
            // lifetime". Round 17 also freed `Completed`, bypassing CLEANUP,
            // and the process-loss and unload scans then dereferenced the
            // freed context (native review N17-1).
            ControlContextLifetimeKind::Close => Self::CloseRight,
            // A context still holding the CREATE admission lease `publish` put
            // in it. This answer alone frees nothing. `take_close_ownership`
            // then asks `adopt_unused_lease`, which turns it into `CloseRight`
            // -- CLOSE frees the context and releases the admission -- when
            // `binding_holds_no_installation`; under any other binding the
            // lease stays, a disclosed leak (native review N18-2's repair).
            // This comment said "CLOSE detaches it and leaks it" until
            // round 21, which stopped being true at that repair.
            // Two ways to get here, and round 18 named only the first:
            //   * a precommit CLEANUP that refused before `move_lease_to_close`,
            //     for example on a null device state;
            //   * a CLOSE with no CLEANUP before it at all, which is how the I/O
            //     manager tears down a file object that never reached a handle
            //     (native review N18-2). `close_choreography` models neither:
            //     its CLEANUP always runs.
            ControlContextLifetimeKind::Lease => Self::Lease,
            // No close authority CLOSE may use: none in the slot, or one only
            // CLEANUP may consume.
            ControlContextLifetimeKind::LiveCellOwned
            | ControlContextLifetimeKind::Completed
            | ControlContextLifetimeKind::BlockedCellOwned => Self::CellOwned,
        }
    }
}

/// The three CLOSE deallocation effects, in the only order that is safe.
///
/// The admission release is last on purpose. `control_context_admission` is
/// what unload waits on before it may free callback-visible state, so releasing
/// it before the context is both detached and freed would let unload observe a
/// rundown of zero while the context is still reachable through `FsContext`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlContextCloseEffect {
    DetachFsContext,
    DestroyAndFreeContext,
    ReleaseControlContextAdmission,
}

pub struct ControlContextClosePlan;

pub struct PendingControlContextCloseEffect {
    roster: [ControlContextCloseEffect; 3],
    next: u8,
    effect: ControlContextCloseEffect,
}

pub struct ControlContextCloseCompletion {
    roster: [ControlContextCloseEffect; 3],
}

pub enum ControlContextCloseProgress {
    Effect(PendingControlContextCloseEffect),
    Complete(ControlContextCloseCompletion),
}

impl ControlContextClosePlan {
    pub const EFFECTS: [ControlContextCloseEffect; 3] = [
        ControlContextCloseEffect::DetachFsContext,
        ControlContextCloseEffect::DestroyAndFreeContext,
        ControlContextCloseEffect::ReleaseControlContextAdmission,
    ];

    /// Begin the deallocation sequence.
    ///
    /// Only `ControlContextCloseOwnership::CloseRight` may free, so any other
    /// ownership is refused here rather than deeper in, where a partial
    /// sequence would already have detached the context.
    pub fn begin(
        ownership: ControlContextCloseOwnership,
    ) -> Result<ControlContextCloseProgress, ControlContextCloseOwnership> {
        Self::begin_inner(ownership, Self::EFFECTS)
    }

    /// Begin the sequence from an explicit roster.
    ///
    /// Production has exactly one roster, and [`Self::begin`] is its only
    /// caller. The seam exists so a test can drive a deliberately wrong order
    /// and *watch the proofs below report `false`*. Without it the proofs are
    /// only ever evaluated against the one order they were written for, and a
    /// weakened proof would stay green: a guard nothing can see fail is not a
    /// guard.
    #[cfg(test)]
    pub(crate) fn begin_with_roster(
        ownership: ControlContextCloseOwnership,
        roster: [ControlContextCloseEffect; 3],
    ) -> Result<ControlContextCloseProgress, ControlContextCloseOwnership> {
        Self::begin_inner(ownership, roster)
    }

    fn begin_inner(
        ownership: ControlContextCloseOwnership,
        roster: [ControlContextCloseEffect; 3],
    ) -> Result<ControlContextCloseProgress, ControlContextCloseOwnership> {
        if !ownership.may_free() {
            return Err(ownership);
        }
        Ok(ControlContextCloseProgress::Effect(
            PendingControlContextCloseEffect {
                roster,
                next: 0,
                effect: roster[0],
            },
        ))
    }
}

impl PendingControlContextCloseEffect {
    pub const fn effect(&self) -> ControlContextCloseEffect {
        self.effect
    }

    /// True once the context has actually been freed.
    ///
    /// This scans the effects this sequence has already run rather than
    /// comparing an index against a constant, so a roster that skipped or
    /// reordered the free reports `false` here instead of inheriting the
    /// position the intended order would have put the free at.
    pub fn context_freed(&self) -> bool {
        self.roster
            .iter()
            .take(usize::from(self.next))
            .any(|effect| matches!(effect, ControlContextCloseEffect::DestroyAndFreeContext))
    }

    pub fn succeeded(mut self) -> ControlContextCloseProgress {
        self.next = self.next.saturating_add(1);
        match self.roster.get(usize::from(self.next)) {
            Some(effect) => {
                self.effect = *effect;
                ControlContextCloseProgress::Effect(self)
            }
            None => ControlContextCloseProgress::Complete(ControlContextCloseCompletion {
                roster: self.roster,
            }),
        }
    }
}

impl ControlContextCloseCompletion {
    /// The context was freed before admission was released.
    ///
    /// Derived from the roster that actually ran: both effects must be present
    /// and the free must precede the release. A sequence that released
    /// admission first, or never freed at all, reports `false`.
    pub fn freed_before_admission_release(&self) -> bool {
        let position =
            |wanted: ControlContextCloseEffect| self.roster.iter().position(|run| *run == wanted);
        match (
            position(ControlContextCloseEffect::DestroyAndFreeContext),
            position(ControlContextCloseEffect::ReleaseControlContextAdmission),
        ) {
            (Some(freed), Some(released)) => freed < released,
            _ => false,
        }
    }
}

impl ControlContextCreatePlan {
    pub const EFFECTS: [ControlContextCreateEffect; 4] = [
        ControlContextCreateEffect::AcquireLease,
        ControlContextCreateEffect::AllocateAndInitialize,
        ControlContextCreateEffect::CaptureRequestor,
        ControlContextCreateEffect::PublishFsContext,
    ];

    pub fn rollback_after(effect: ControlContextCreateEffect) -> ControlContextCreateRollbackPlan {
        use ControlContextCreateRollbackEffect as Rollback;
        let effects = match effect {
            ControlContextCreateEffect::AcquireLease => &[Rollback::ReleaseLease][..],
            ControlContextCreateEffect::AllocateAndInitialize => {
                &[Rollback::FreeAllocation, Rollback::ReleaseLease][..]
            }
            ControlContextCreateEffect::CaptureRequestor
            | ControlContextCreateEffect::PublishFsContext => &[
                Rollback::ReleaseRequestor,
                Rollback::FreeAllocation,
                Rollback::ReleaseLease,
            ][..],
        };
        ControlContextCreateRollbackPlan { effects }
    }
}

impl ControlContextCreateRollbackPlan {
    pub const fn effects(&self) -> &'static [ControlContextCreateRollbackEffect] {
        self.effects
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupEntryEffect {
    ClearSetupCancel,
    ClearSetupComplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupEntryRefusalKind {
    PriorSetupIncomplete,
    IntegerOverflow,
    Duplicate,
    Invalid,
}

#[derive(Debug)]
pub struct SetupEntryRefusal {
    kind: SetupEntryRefusalKind,
}

impl SetupEntryRefusal {
    pub const fn kind(&self) -> SetupEntryRefusalKind {
        self.kind
    }

    pub const fn information(&self) -> usize {
        0
    }
}

pub struct SetupEntryPlan;

#[derive(Debug)]
pub struct SetupEntryAdmission {
    reservation: SetupReservation,
    setup_epoch: SetupEpoch,
}

pub struct PendingSetupEntryEffect {
    admission: SetupEntryAdmission,
    next: u8,
    effect: SetupEntryEffect,
}

pub enum SetupEntryProgress {
    Effect(PendingSetupEntryEffect),
    Admitted(SetupEntryAdmission),
}

impl SetupEntryPlan {
    const EFFECTS: [SetupEntryEffect; 2] = [
        SetupEntryEffect::ClearSetupCancel,
        SetupEntryEffect::ClearSetupComplete,
    ];

    pub fn begin(
        binding: &mut ControlBinding,
        prior_setup_complete: bool,
    ) -> Result<SetupEntryProgress, SetupEntryRefusal> {
        if !prior_setup_complete {
            return Err(SetupEntryRefusal {
                kind: SetupEntryRefusalKind::PriorSetupIncomplete,
            });
        }
        let reservation = binding.begin_setup().map_err(|error| SetupEntryRefusal {
            kind: match error {
                SessionError::SetupEpochExhausted => SetupEntryRefusalKind::IntegerOverflow,
                SessionError::DuplicateSetup => SetupEntryRefusalKind::Duplicate,
                _ => SetupEntryRefusalKind::Invalid,
            },
        })?;
        let ControlBindingState::Staging(setup_epoch) = binding.state() else {
            return Err(SetupEntryRefusal {
                kind: SetupEntryRefusalKind::Invalid,
            });
        };
        Ok(SetupEntryProgress::Effect(PendingSetupEntryEffect {
            admission: SetupEntryAdmission {
                reservation,
                setup_epoch,
            },
            next: 0,
            effect: Self::EFFECTS[0],
        }))
    }
}

impl PendingSetupEntryEffect {
    pub const fn effect(&self) -> SetupEntryEffect {
        self.effect
    }

    pub fn succeeded(mut self) -> SetupEntryProgress {
        self.next = self.next.saturating_add(1);
        match SetupEntryPlan::EFFECTS.get(usize::from(self.next)) {
            Some(effect) => {
                self.effect = *effect;
                SetupEntryProgress::Effect(self)
            }
            None => SetupEntryProgress::Admitted(self.admission),
        }
    }
}

impl SetupEntryAdmission {
    pub const fn setup_epoch(&self) -> SetupEpoch {
        self.setup_epoch
    }

    pub fn into_reservation(self) -> SetupReservation {
        self.reservation
    }

    pub fn into_parts(self) -> (SetupReservation, [SetupEntryEffect; 2]) {
        (self.reservation, SetupEntryPlan::EFFECTS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecommitCleanupEffect {
    ReleaseOuterGuard,
    SignalSetupCancel,
    WaitFileRundown,
    WaitSetupComplete,
    PublishClosedAndTransferLease,
}

enum PrecommitCleanupRoute {
    Empty,
    Setup(SetupCleanupRight),
}

pub struct PrecommitCleanupPlan;

pub struct PendingPrecommitCleanupEffect {
    route: PrecommitCleanupRoute,
    next: u8,
    effect: PrecommitCleanupEffect,
}

pub struct PrecommitCleanupCompletion {
    route: PrecommitCleanupRoute,
}

pub enum PrecommitCleanupProgress {
    Effect(PendingPrecommitCleanupEffect),
    Complete(PrecommitCleanupCompletion),
}

impl PrecommitCleanupPlan {
    const EMPTY: [PrecommitCleanupEffect; 3] = [
        PrecommitCleanupEffect::ReleaseOuterGuard,
        PrecommitCleanupEffect::WaitFileRundown,
        PrecommitCleanupEffect::PublishClosedAndTransferLease,
    ];
    const SETUP: [PrecommitCleanupEffect; 5] = [
        PrecommitCleanupEffect::ReleaseOuterGuard,
        PrecommitCleanupEffect::SignalSetupCancel,
        PrecommitCleanupEffect::WaitFileRundown,
        PrecommitCleanupEffect::WaitSetupComplete,
        PrecommitCleanupEffect::PublishClosedAndTransferLease,
    ];

    pub fn begin(
        claim: CleanupBindingClaim,
    ) -> Result<PrecommitCleanupProgress, CleanupBindingClaim> {
        let route = match claim {
            CleanupBindingClaim::Empty => PrecommitCleanupRoute::Empty,
            CleanupBindingClaim::Setup(right) => PrecommitCleanupRoute::Setup(right),
            other => return Err(other),
        };
        let effect = match route {
            PrecommitCleanupRoute::Empty => Self::EMPTY[0],
            PrecommitCleanupRoute::Setup(_) => Self::SETUP[0],
        };
        Ok(PrecommitCleanupProgress::Effect(
            PendingPrecommitCleanupEffect {
                route,
                next: 0,
                effect,
            },
        ))
    }
}

impl PendingPrecommitCleanupEffect {
    pub const fn effect(&self) -> PrecommitCleanupEffect {
        self.effect
    }

    pub fn succeeded(mut self) -> PrecommitCleanupProgress {
        self.next = self.next.saturating_add(1);
        let effects: &[PrecommitCleanupEffect] = match self.route {
            PrecommitCleanupRoute::Empty => &PrecommitCleanupPlan::EMPTY,
            PrecommitCleanupRoute::Setup(_) => &PrecommitCleanupPlan::SETUP,
        };
        match effects.get(usize::from(self.next)) {
            Some(effect) => {
                self.effect = *effect;
                PrecommitCleanupProgress::Effect(self)
            }
            None => {
                PrecommitCleanupProgress::Complete(PrecommitCleanupCompletion { route: self.route })
            }
        }
    }
}

impl PrecommitCleanupCompletion {
    pub fn into_setup_right(self) -> Option<SetupCleanupRight> {
        match self.route {
            PrecommitCleanupRoute::Empty => None,
            PrecommitCleanupRoute::Setup(right) => Some(right),
        }
    }
}

/// One step of the indivisible locked publication suffix.
///
/// The native mount is activated first, before core goes `Live`: a Live cell
/// whose mount rendezvous is still inactive is reachable by terminalization
/// that then cannot find the mount to take or join.
///
/// `WriteVdoLocator` is its own step because the proof below is *about* it:
/// while
/// the write lived inside `ClearVdoInitializing`, the ordering the roster
/// claims to fix — locator first, flag second — was invisible to every proof,
/// and swapping the two native statements changed no test.
///
/// Depositing the shell/root owners into their cell slots is not a separate
/// step: the native executor performs it inside `TransferLeaseToControlOwner`,
/// out of the same `PublishedSession` the core publication yields. The ownership
/// rules themselves are modelled and tested by [`SetupOwnership`].
///
/// Task 19 replaced three separate core commits -- registry Live, binding
/// Active, rendezvous activation -- with the one aggregate
/// `commit_after_native_runtime_install`, and inserted the native runtime
/// install immediately before it. That is not a loosening: the three stages were
/// always run back to back under this one lock hold, and collapsing them removes
/// the only shape in which a suffix could have run two of the three. What the
/// roster still fixes, and what the proofs below still read, is that the mount
/// and the pending runtime are in place *before* the core cell goes Live, and
/// that the VDO is published before the lock is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockedSetupSuffixEffect {
    ActivateNativeMountRendezvous,
    InstallPendingRuntime,
    CommitCoreRingSetupPublication,
    TransferLeaseToControlOwner,
    PublishBindingPhase,
    WriteVdoLocator,
    ClearVdoInitializing,
    ReleaseRegistryLock,
}

pub struct LockedSetupSuffixPlan;

/// Indices of the order-critical effects, filled in as the walk passes them.
///
/// The proof below reads only this record, so it reports what the sequence
/// actually did rather than restating the intended order as a constant.
#[derive(Clone, Copy, Default)]
struct LockedSuffixRecord {
    mount_activated: Option<u8>,
    pending_runtime_installed: Option<u8>,
    core_live: Option<u8>,
    vdo_locator_written: Option<u8>,
    vdo_initializing_cleared: Option<u8>,
    registry_lock_released: Option<u8>,
}

pub struct PendingLockedSetupSuffixEffect {
    roster: [LockedSetupSuffixEffect; 8],
    next: u8,
    effect: LockedSetupSuffixEffect,
    record: LockedSuffixRecord,
}

pub struct LockedSetupSuffixProof {
    record: LockedSuffixRecord,
}

pub enum LockedSetupSuffixProgress {
    Effect(PendingLockedSetupSuffixEffect),
    Complete(LockedSetupSuffixProof),
}

impl LockedSetupSuffixPlan {
    pub const EFFECTS: [LockedSetupSuffixEffect; 8] = [
        LockedSetupSuffixEffect::ActivateNativeMountRendezvous,
        LockedSetupSuffixEffect::InstallPendingRuntime,
        LockedSetupSuffixEffect::CommitCoreRingSetupPublication,
        LockedSetupSuffixEffect::TransferLeaseToControlOwner,
        LockedSetupSuffixEffect::PublishBindingPhase,
        LockedSetupSuffixEffect::WriteVdoLocator,
        LockedSetupSuffixEffect::ClearVdoInitializing,
        LockedSetupSuffixEffect::ReleaseRegistryLock,
    ];

    pub const fn begin() -> LockedSetupSuffixProgress {
        Self::begin_inner(Self::EFFECTS)
    }

    /// Begin the suffix from an explicit roster.
    ///
    /// Production has exactly one roster, and [`Self::begin`] is its only
    /// caller. Tests use this seam to run a deliberately wrong order and watch
    /// [`LockedSetupSuffixProof`] report `false`; a proof that is only ever
    /// evaluated against the order it was written for cannot fail, so a
    /// weakened comparison in it would never be noticed.
    #[cfg(test)]
    pub(crate) const fn begin_with_roster(
        roster: [LockedSetupSuffixEffect; 8],
    ) -> LockedSetupSuffixProgress {
        Self::begin_inner(roster)
    }

    const fn begin_inner(roster: [LockedSetupSuffixEffect; 8]) -> LockedSetupSuffixProgress {
        LockedSetupSuffixProgress::Effect(PendingLockedSetupSuffixEffect {
            roster,
            next: 0,
            effect: roster[0],
            record: LockedSuffixRecord {
                mount_activated: None,
                pending_runtime_installed: None,
                core_live: None,
                vdo_locator_written: None,
                vdo_initializing_cleared: None,
                registry_lock_released: None,
            },
        })
    }
}

impl PendingLockedSetupSuffixEffect {
    pub const fn effect(&self) -> LockedSetupSuffixEffect {
        self.effect
    }

    pub const fn cleanup_may_interleave(&self) -> bool {
        false
    }

    pub fn succeeded(mut self) -> LockedSetupSuffixProgress {
        let at = self.next;
        match self.effect {
            LockedSetupSuffixEffect::ActivateNativeMountRendezvous => {
                self.record.mount_activated = Some(at);
            }
            LockedSetupSuffixEffect::InstallPendingRuntime => {
                self.record.pending_runtime_installed = Some(at);
            }
            LockedSetupSuffixEffect::CommitCoreRingSetupPublication => {
                self.record.core_live = Some(at);
            }
            LockedSetupSuffixEffect::WriteVdoLocator => {
                self.record.vdo_locator_written = Some(at);
            }
            LockedSetupSuffixEffect::ClearVdoInitializing => {
                self.record.vdo_initializing_cleared = Some(at);
            }
            LockedSetupSuffixEffect::ReleaseRegistryLock => {
                self.record.registry_lock_released = Some(at);
            }
            LockedSetupSuffixEffect::TransferLeaseToControlOwner
            | LockedSetupSuffixEffect::PublishBindingPhase => {}
        }
        self.next = self.next.saturating_add(1);
        match self.roster.get(usize::from(self.next)) {
            Some(effect) => {
                self.effect = *effect;
                LockedSetupSuffixProgress::Effect(self)
            }
            None => LockedSetupSuffixProgress::Complete(LockedSetupSuffixProof {
                record: self.record,
            }),
        }
    }
}

impl LockedSetupSuffixProof {
    /// The registry spin lock — the native linearization point — was released
    /// only after the VDO initializing flag was cleared.
    pub const fn registry_lock_released_only_after_vdo_publication(&self) -> bool {
        match (
            self.record.registry_lock_released,
            self.record.vdo_initializing_cleared,
        ) {
            (Some(released), Some(cleared)) => cleared < released,
            _ => false,
        }
    }

    /// The locator reached the VDO before the device became openable.
    ///
    /// A device whose `DO_DEVICE_INITIALIZING` is clear can be opened and
    /// mounted immediately; if the locator write had not happened yet, that
    /// MOUNT reads an unwritten field and the session that just published
    /// cannot be mounted at all.
    pub const fn vdo_locator_written_before_initializing_cleared(&self) -> bool {
        match (
            self.record.vdo_locator_written,
            self.record.vdo_initializing_cleared,
        ) {
            (Some(written), Some(cleared)) => written < cleared,
            _ => false,
        }
    }

    /// The pending runtime was installed before the core cell went `Live`.
    ///
    /// The order is the whole reason the install is a suffix step rather than
    /// something SETUP does earlier: a Live session whose permanent cell has no
    /// runtime is addressable by an ENTER that then has nowhere to park, and a
    /// runtime installed on a cell that never goes Live is an arena nobody
    /// frees. Both are unreachable while this holds and the lock is unbroken.
    pub const fn pending_runtime_installed_before_core_live(&self) -> bool {
        match (self.record.pending_runtime_installed, self.record.core_live) {
            (Some(installed), Some(live)) => installed < live,
            _ => false,
        }
    }

    /// The native mount rendezvous was active before the core cell went `Live`.
    pub const fn mount_activated_before_core_live(&self) -> bool {
        match (self.record.mount_activated, self.record.core_live) {
            (Some(mount), Some(live)) => mount < live,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// WDK-free shell/root ownership model
// ---------------------------------------------------------------------------

/// Identity of one setup shell allocation.
///
/// The native side owns a `NonNull<NativeSession>`; this crate cannot and must
/// not. Modelling the allocation as an opaque id is enough to prove the
/// property that matters: the owner that reaches the cell is the *same* one
/// allocation returned, never a value rebuilt from an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellOwnerId(u64);

impl ShellOwnerId {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellOwnerState {
    /// Before `AllocateSectionAndSystemView` succeeds.
    Absent,
    /// Allocation returned the sole `UnpublishedNativeSessionOwner`.
    Unpublished(ShellOwnerId),
    /// `InstallStaging` selected a locator and branded the owner.
    Branded {
        id: ShellOwnerId,
        locator: SessionLocator,
    },
    /// The locked suffix deposited it into the permanent cell slot.
    CellOwned {
        id: ShellOwnerId,
        locator: SessionLocator,
    },
    /// Rollback consumed it through its private destructor.
    Destroyed(ShellOwnerId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootRightState {
    Absent,
    Acquired(SessionLocator),
    CellOwned(SessionLocator),
    Released(SessionLocator),
}

/// The exact still-initializing VDO the publication suffix is allowed to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VdoReadiness {
    pub shell: ShellOwnerId,
    pub device_initializing: bool,
    pub locator_uninitialized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipFault {
    /// A second allocation, brand, deposit, destroy, or release.
    NotRepeatable,
    /// An owner was named that allocation never produced.
    Fabricated,
    /// Shell and root disagree about the locator, or the caller's does.
    WrongLocator,
    /// The VDO is no longer initializing, or belongs to another shell.
    UnusableVdo,
}

/// Tracks the one shell owner and one root release right across a SETUP.
///
/// Every transition is total and refuses without mutating, so a refusal can be
/// asserted byte-identical to the state before the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOwnership {
    shell: ShellOwnerState,
    root: RootRightState,
    shell_destroyed: u8,
    root_released: u8,
}

impl SetupOwnership {
    pub const fn new() -> Self {
        Self {
            shell: ShellOwnerState::Absent,
            root: RootRightState::Absent,
            shell_destroyed: 0,
            root_released: 0,
        }
    }

    pub const fn shell(&self) -> ShellOwnerState {
        self.shell
    }

    pub const fn root(&self) -> RootRightState {
        self.root
    }

    pub const fn shell_destroy_count(&self) -> u8 {
        self.shell_destroyed
    }

    pub const fn root_release_count(&self) -> u8 {
        self.root_released
    }

    /// `AllocateSectionAndSystemView` succeeded: the sole unpublished owner.
    pub fn allocate(&mut self, id: ShellOwnerId) -> Result<(), OwnershipFault> {
        match self.shell {
            ShellOwnerState::Absent => {
                self.shell = ShellOwnerState::Unpublished(id);
                Ok(())
            }
            _ => Err(OwnershipFault::NotRepeatable),
        }
    }

    /// `InstallStaging` chose the locator; brand the allocation-origin owner
    /// and acquire the one driver-root reference for the same locator.
    pub fn install_staging(&mut self, locator: SessionLocator) -> Result<(), OwnershipFault> {
        let id = match self.shell {
            ShellOwnerState::Unpublished(id) => id,
            ShellOwnerState::Absent => return Err(OwnershipFault::Fabricated),
            _ => return Err(OwnershipFault::NotRepeatable),
        };
        if !matches!(self.root, RootRightState::Absent) {
            return Err(OwnershipFault::NotRepeatable);
        }
        self.shell = ShellOwnerState::Branded { id, locator };
        self.root = RootRightState::Acquired(locator);
        Ok(())
    }

    /// The mutation-free publication preflight.
    ///
    /// It proves the shell and root name the same locator as the caller and
    /// that the VDO still belongs to this exact shell and is still
    /// initializing. Every refusal leaves `self` untouched.
    pub fn preflight_publication(
        &self,
        locator: SessionLocator,
        vdo: VdoReadiness,
    ) -> Result<(), OwnershipFault> {
        let id = match self.shell {
            ShellOwnerState::Branded { id, locator: owned } => {
                if owned != locator {
                    return Err(OwnershipFault::WrongLocator);
                }
                id
            }
            ShellOwnerState::Absent | ShellOwnerState::Unpublished(_) => {
                return Err(OwnershipFault::Fabricated);
            }
            _ => return Err(OwnershipFault::NotRepeatable),
        };
        match self.root {
            RootRightState::Acquired(owned) if owned == locator => {}
            RootRightState::Acquired(_) => return Err(OwnershipFault::WrongLocator),
            RootRightState::Absent => return Err(OwnershipFault::Fabricated),
            _ => return Err(OwnershipFault::NotRepeatable),
        }
        if vdo.shell != id {
            return Err(OwnershipFault::UnusableVdo);
        }
        if !vdo.device_initializing || !vdo.locator_uninitialized {
            return Err(OwnershipFault::UnusableVdo);
        }
        Ok(())
    }

    /// The `DepositShellAndRootOwners` step of the locked suffix.
    pub fn deposit(
        &mut self,
        locator: SessionLocator,
        vdo: VdoReadiness,
    ) -> Result<(), OwnershipFault> {
        self.preflight_publication(locator, vdo)?;
        let id = match self.shell {
            ShellOwnerState::Branded { id, .. } => id,
            _ => return Err(OwnershipFault::Fabricated),
        };
        self.shell = ShellOwnerState::CellOwned { id, locator };
        self.root = RootRightState::CellOwned(locator);
        Ok(())
    }

    /// Rollback consumes the shell through its private destructor. A cell-owned
    /// shell is not rollback's to destroy.
    pub fn destroy_shell(&mut self) -> Result<(), OwnershipFault> {
        match self.shell {
            ShellOwnerState::Unpublished(id) | ShellOwnerState::Branded { id, .. } => {
                self.shell = ShellOwnerState::Destroyed(id);
                self.shell_destroyed = self.shell_destroyed.saturating_add(1);
                Ok(())
            }
            ShellOwnerState::Absent => Err(OwnershipFault::Fabricated),
            ShellOwnerState::CellOwned { .. } | ShellOwnerState::Destroyed(_) => {
                Err(OwnershipFault::NotRepeatable)
            }
        }
    }

    /// Rollback releases the root reference exactly once, and only if
    /// `InstallStaging` ever acquired it.
    pub fn release_root(&mut self) -> Result<(), OwnershipFault> {
        match self.root {
            RootRightState::Acquired(locator) => {
                self.root = RootRightState::Released(locator);
                self.root_released = self.root_released.saturating_add(1);
                Ok(())
            }
            RootRightState::Absent => Err(OwnershipFault::Fabricated),
            RootRightState::CellOwned(_) | RootRightState::Released(_) => {
                Err(OwnershipFault::NotRepeatable)
            }
        }
    }

    /// Roll back whatever this SETUP actually holds.
    ///
    /// A reserved-stage rollback that never allocated has nothing to destroy,
    /// which is why the shell/root counts — not the call — are the property the
    /// tests assert.
    pub fn rollback(&mut self) -> Result<(), OwnershipFault> {
        if !matches!(self.root, RootRightState::Absent) {
            self.release_root()?;
        }
        if !matches!(self.shell, ShellOwnerState::Absent) {
            self.destroy_shell()?;
        }
        Ok(())
    }
}

impl Default for SetupOwnership {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstalledRollbackTailEffect {
    PermanentlyCloseAccessRundown,
}

pub struct InstalledRollbackTailPlan {
    effects: &'static [InstalledRollbackTailEffect],
}

impl InstalledRollbackTailPlan {
    const RETIRED: [InstalledRollbackTailEffect; 1] =
        [InstalledRollbackTailEffect::PermanentlyCloseAccessRundown];

    pub const fn for_disposition(disposition: SlotDisposition) -> Self {
        Self {
            effects: match disposition {
                SlotDisposition::Free => &[],
                SlotDisposition::Retired => &Self::RETIRED,
            },
        }
    }

    pub const fn effects(&self) -> &'static [InstalledRollbackTailEffect] {
        self.effects
    }
}

/// Everything one SETUP is planned from.
///
/// The profile is an input rather than something an executor reports per
/// effect, so a modern/legacy mapping mismatch is not representable.
pub struct SetupPlanInput {
    pub boot_instance_id: BootInstanceId,
    pub validated_setup: ValidatedSetupRequest,
    pub layout: SectionLayoutPlan,
    pub output_capacity: usize,
    pub profile: PlatformProfile,
}

/// The closed outcome vocabulary a native executor may report.
///
/// Only two effects produce a value; everything else reports `Done`. No byte
/// buffer, handle, or address fits in any variant, so unvalidated native state
/// cannot re-enter the plan.
// The plan freezes this outcome vocabulary, and the receipt it carries is a
// sealed by-value proof, not a pointer. Boxing the large variant would need an
// allocator the kernel half deliberately does not have.
#[allow(clippy::large_enum_variant)]
pub enum SetupEffectOutcome {
    Done,
    MountIdBurned(MountId),
    ProtectedViewsBuilt(ProtectedViewReceipt),
}

/// The result geometry SETUP derives for itself.
///
/// Derived by [`NativeSetupPlan::begin`] from the validated request with the
/// frozen ABI's own checked arithmetic. No executor supplies these numbers,
/// which is why an executor cannot talk the plan into a short output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOutputMetadata {
    required_size: usize,
    view_count: u32,
    credit_count: u32,
}

impl SetupOutputMetadata {
    pub const fn required_size(&self) -> usize {
        self.required_size
    }

    pub const fn view_count(&self) -> u32 {
        self.view_count
    }

    pub const fn credit_count(&self) -> u32 {
        self.credit_count
    }
}

/// The ordering and ownership state of one SETUP.
pub struct NativeSetupPlan {
    next: u8,
    owned: u64,
    boot_instance_id: BootInstanceId,
    identity: Option<SessionIdentity>,
    validated_setup: ValidatedSetupRequest,
    layout: SectionLayoutPlan,
    output: SetupOutputMetadata,
    output_capacity: usize,
    profile: PlatformProfile,
    protected_view_count: u32,
}

/// A one-shot capability requesting exactly one native SETUP effect.
pub struct PendingSetupEffect {
    plan: NativeSetupPlan,
    effect: SetupEffect,
}

/// The only two observable states of a SETUP.
// As above: the pending capability owns the whole retained request and layout
// by value, which is what makes it affine and unforgeable.
#[allow(clippy::large_enum_variant)]
pub enum SetupProgress {
    Effect(PendingSetupEffect),
    Published(SetupCommit),
}

/// Proof that the Release publication happened.
pub struct SetupCommit {
    identity: SessionIdentity,
    output: SetupOutputMetadata,
}

impl SetupCommit {
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    pub const fn output(&self) -> SetupOutputMetadata {
        self.output
    }
}

/// One native action in a reverse-order unwind of a failed SETUP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupRollbackEffect {
    ReleaseControlRundown,
    ReleaseStrongReferences,
    RollbackProtectedViews,
    ReleaseCapturedProcess,
    DeleteVdo,
    FreeEventsAndScratch,
    FreeGrants,
    UnmapAndCloseSection,
    /// Not a release: the marker that says the burned `MountId` is spent and
    /// this failure path must never hand it back for reuse.
    PreserveBurnedMountId,
    ReleaseBootLockEvent,
}

/// The immutable unwind plan for one failed precommit SETUP.
pub struct SetupRollbackPlan {
    effects: &'static [SetupRollbackEffect],
}

impl SetupRollbackPlan {
    pub const fn effects(&self) -> &'static [SetupRollbackEffect] {
        self.effects
    }
}

/// What a failure or cancellation means, depending on which side of the single
/// Release publication it happened.
pub enum SetupFailurePlan {
    Rollback(SetupRollbackPlan),
    CompletePublished(SetupCommit),
}

/// Keeps the unwind tables readable without a glob import.
type Undo = SetupRollbackEffect;

const R_NONE: &[Undo] = &[];

const R_RUNDOWN: &[Undo] = &[Undo::ReleaseControlRundown];

const R_LOCK: &[Undo] = &[Undo::ReleaseBootLockEvent, Undo::ReleaseControlRundown];

const R_LOCK_BURNED: &[Undo] = &[
    Undo::PreserveBurnedMountId,
    Undo::ReleaseBootLockEvent,
    Undo::ReleaseControlRundown,
];

const R_BURNED: &[Undo] = &[Undo::PreserveBurnedMountId, Undo::ReleaseControlRundown];

const R_SECTION: &[Undo] = &[
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

const R_GRANTS: &[Undo] = &[
    Undo::FreeGrants,
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

const R_EVENTS: &[Undo] = &[
    Undo::FreeEventsAndScratch,
    Undo::FreeGrants,
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

/// Also the unwind for a nested protected-view rollback that already released
/// the captured process: the outer plan must not release it a second time.
const R_VDO: &[Undo] = &[
    Undo::DeleteVdo,
    Undo::FreeEventsAndScratch,
    Undo::FreeGrants,
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

const R_PROCESS: &[Undo] = &[
    Undo::ReleaseCapturedProcess,
    Undo::DeleteVdo,
    Undo::FreeEventsAndScratch,
    Undo::FreeGrants,
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

const R_VIEWS: &[Undo] = &[
    Undo::RollbackProtectedViews,
    Undo::ReleaseCapturedProcess,
    Undo::DeleteVdo,
    Undo::FreeEventsAndScratch,
    Undo::FreeGrants,
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

const R_REFS: &[Undo] = &[
    Undo::ReleaseStrongReferences,
    Undo::RollbackProtectedViews,
    Undo::ReleaseCapturedProcess,
    Undo::DeleteVdo,
    Undo::FreeEventsAndScratch,
    Undo::FreeGrants,
    Undo::UnmapAndCloseSection,
    Undo::PreserveBurnedMountId,
    Undo::ReleaseControlRundown,
];

/// The index of the single Release commit inside [`NativeSetupPlan::SUCCESS_EFFECTS`].
const INDEX_PUBLISH_LOCKED_SUFFIX: u8 = 19;

const fn bit(index: u8) -> u64 {
    1u64.wrapping_shl(index as u32)
}

impl NativeSetupPlan {
    /// The one order a successful SETUP runs in.
    ///
    /// Read it as three phases separated by two hinges: everything before
    /// `BurnMountId` is refusable without consequence; everything between the
    /// burn and `PublishLockedSuffix` is refusable but must unwind; everything
    /// from `PublishLockedSuffix` on is committed.
    pub const SUCCESS_EFFECTS: [SetupEffect; 25] = [
        SetupEffect::AcquireControlRundown,
        SetupEffect::SnapshotAndValidateInput,
        SetupEffect::ValidateOutputCapacity,
        SetupEffect::RejectDuplicate,
        SetupEffect::AcquireBootLockEvent,
        SetupEffect::BurnMountId,
        SetupEffect::ReleaseBootLockEvent,
        SetupEffect::ComputeLayoutAndLedger,
        SetupEffect::AllocateSectionAndSystemView,
        SetupEffect::ConstructAndValidateSection,
        SetupEffect::AllocateGrants,
        SetupEffect::AllocateEventsAndScratch,
        SetupEffect::CreateSecureVdo,
        SetupEffect::CaptureProcess,
        SetupEffect::BuildProtectedViews,
        SetupEffect::BuildOutput,
        SetupEffect::ValidateOutput,
        SetupEffect::InstallStaging,
        SETUP_COMMIT[0],
        SETUP_COMMIT[1],
        SETUP_TAIL[0],
        SETUP_TAIL[1],
        SETUP_TAIL[2],
        SETUP_TAIL[3],
        SETUP_TAIL[4],
    ];

    // PROOF: a `const` context has no `<[T]>::get`, and the index is the
    // literal 18 against a fixed 23-element array, so the access is in range
    // and evaluated at compile time. A wrong index fails the build with E0080
    // rather than panicking at run time.
    #[allow(clippy::indexing_slicing)]
    const _COMMIT_INDEX_IS_PUBLISH: () = assert!(
        matches!(
            Self::SUCCESS_EFFECTS[INDEX_PUBLISH_LOCKED_SUFFIX as usize],
            SetupEffect::PublishLockedSuffix
        ),
        "the commit boundary must name PublishLockedSuffix"
    );

    /// Begin one SETUP.
    ///
    /// The plan recomputes the section layout from the validated request and
    /// requires exact equality with the supplied plan, so a caller cannot smuggle
    /// a placement the request does not imply. It then derives the complete
    /// result geometry with the frozen ABI's checked arithmetic and refuses a
    /// short output buffer *before* the first effect — which is what keeps a
    /// `MountId` from being burned for a request that cannot be answered.
    pub fn begin(input: SetupPlanInput) -> Result<SetupProgress, AdapterPlanError> {
        let SetupPlanInput {
            boot_instance_id,
            validated_setup,
            layout,
            output_capacity,
            profile,
        } = input;

        let recomputed = SectionLayoutPlan::compute(&validated_setup, layout.page_size())
            .map_err(|_| AdapterPlanError::InvalidInput)?;
        if recomputed != layout {
            return Err(AdapterPlanError::InvalidInput);
        }

        let topology = validated_setup.topology();
        let required_size = session_result_size_v1(&topology)
            .map_err(|_| AdapterPlanError::ArithmeticOverflow)
            .and_then(|size| {
                usize::try_from(size).map_err(|_| AdapterPlanError::ArithmeticOverflow)
            })?;
        let view_count = view_count_for(layout.ring_count())?;
        let output = SetupOutputMetadata {
            required_size,
            view_count,
            credit_count: topology.notification_credit_count(),
        };
        if output_capacity < required_size {
            return Err(AdapterPlanError::Capacity);
        }

        let effect = *Self::SUCCESS_EFFECTS
            .first()
            .ok_or(AdapterPlanError::InvalidTransition)?;
        Ok(SetupProgress::Effect(PendingSetupEffect {
            plan: Self {
                next: 0,
                owned: 0,
                boot_instance_id,
                identity: None,
                validated_setup,
                layout,
                output,
                output_capacity,
                profile,
                protected_view_count: view_count,
            },
            effect,
        }))
    }

    /// Derive the unwind from how far this SETUP got.
    ///
    /// The acquisitions are a strict prefix of one fixed order, so the failing
    /// index alone names everything still owned. `process_retained` is the one
    /// extra fact: a nested protected-view rollback may already have released
    /// the captured process, and releasing it twice is exactly as wrong as
    /// leaking it.
    const fn rollback_effects(next: u8, process_retained: bool) -> &'static [SetupRollbackEffect] {
        match next {
            0 => R_NONE,
            1..=4 => R_RUNDOWN,
            5 => R_LOCK,
            6 => R_LOCK_BURNED,
            7..=8 => R_BURNED,
            9..=10 => R_SECTION,
            11 => R_GRANTS,
            12 => R_EVENTS,
            13 => R_VDO,
            14 => {
                if process_retained {
                    R_PROCESS
                } else {
                    R_VDO
                }
            }
            15..=17 => R_VIEWS,
            _ => R_REFS,
        }
    }
}

/// The frozen result view roster: one read-only whole-section view, three
/// producer views per ring, and the U2K arena.
fn view_count_for(ring_count: u32) -> Result<u32, AdapterPlanError> {
    ring_count
        .checked_mul(3)
        .and_then(|rings| rings.checked_add(2))
        .ok_or(AdapterPlanError::ArithmeticOverflow)
}

impl PendingSetupEffect {
    pub const fn effect(&self) -> SetupEffect {
        self.effect
    }

    /// The burned identity, absent until `BurnMountId` succeeds.
    pub const fn identity(&self) -> Option<SessionIdentity> {
        self.plan.identity
    }

    pub const fn validated_setup(&self) -> &ValidatedSetupRequest {
        &self.plan.validated_setup
    }

    pub const fn layout(&self) -> &SectionLayoutPlan {
        &self.plan.layout
    }

    pub const fn output(&self) -> SetupOutputMetadata {
        self.plan.output
    }

    /// The output capacity this plan was admitted against.
    ///
    /// The executor compares it with the buffer it is about to fill, so a
    /// SETUP that somehow reached `BuildOutput` holding a different buffer than
    /// the one `begin` sized is caught before a byte is written.
    pub const fn output_capacity(&self) -> usize {
        self.plan.output_capacity
    }

    pub const fn profile(&self) -> PlatformProfile {
        self.plan.profile
    }

    /// Consume this capability after its native effect completed.
    ///
    /// Only the outcome variant that belongs to this effect is accepted, and
    /// the two value-carrying outcomes are checked against what the plan
    /// already knows rather than trusted.
    pub fn succeeded(self, outcome: SetupEffectOutcome) -> Result<SetupProgress, AdapterPlanError> {
        let Self { mut plan, effect } = self;

        match (effect, outcome) {
            (SetupEffect::BurnMountId, SetupEffectOutcome::MountIdBurned(mount_id)) => {
                if plan.identity.is_some() {
                    // A second burn would spend a second mount sequence and
                    // leave the first one unaccounted for.
                    return Err(AdapterPlanError::InvalidTransition);
                }
                // The session epoch of a freshly published session is 1; the
                // compact layout plan states the same number, and the two are
                // compared when the result is validated.
                plan.identity = Some(SessionIdentity {
                    boot_instance_id: plan.boot_instance_id,
                    mount_id,
                    session_epoch: 1,
                });
            }
            (
                SetupEffect::BuildProtectedViews,
                SetupEffectOutcome::ProtectedViewsBuilt(receipt),
            ) => {
                let Some(identity) = plan.identity else {
                    return Err(AdapterPlanError::InvalidTransition);
                };
                if receipt.identity() != identity
                    || receipt.profile() != plan.profile
                    || *receipt.layout() != plan.layout
                    || receipt.alias_count() != plan.protected_view_count
                {
                    return Err(AdapterPlanError::InvalidTransition);
                }
            }
            (
                SetupEffect::AcquireControlRundown
                | SetupEffect::SnapshotAndValidateInput
                | SetupEffect::ValidateOutputCapacity
                | SetupEffect::RejectDuplicate
                | SetupEffect::AcquireBootLockEvent
                | SetupEffect::ReleaseBootLockEvent
                | SetupEffect::ComputeLayoutAndLedger
                | SetupEffect::AllocateSectionAndSystemView
                | SetupEffect::ConstructAndValidateSection
                | SetupEffect::AllocateGrants
                | SetupEffect::AllocateEventsAndScratch
                | SetupEffect::CreateSecureVdo
                | SetupEffect::CaptureProcess
                | SetupEffect::BuildOutput
                | SetupEffect::ValidateOutput
                | SetupEffect::InstallStaging
                | SetupEffect::CopyValidatedOutput
                | SetupEffect::PublishLockedSuffix
                | SetupEffect::EmitSessionPublished
                | SetupEffect::ReleaseSetupAdmission
                | SetupEffect::SignalSetupComplete
                | SetupEffect::ReturnProviderDisposition
                | SetupEffect::OuterReleaseControlRundown,
                SetupEffectOutcome::Done,
            ) => {}
            (
                SetupEffect::AcquireControlRundown
                | SetupEffect::SnapshotAndValidateInput
                | SetupEffect::ValidateOutputCapacity
                | SetupEffect::RejectDuplicate
                | SetupEffect::AcquireBootLockEvent
                | SetupEffect::BurnMountId
                | SetupEffect::ReleaseBootLockEvent
                | SetupEffect::ComputeLayoutAndLedger
                | SetupEffect::AllocateSectionAndSystemView
                | SetupEffect::ConstructAndValidateSection
                | SetupEffect::AllocateGrants
                | SetupEffect::AllocateEventsAndScratch
                | SetupEffect::CreateSecureVdo
                | SetupEffect::CaptureProcess
                | SetupEffect::BuildProtectedViews
                | SetupEffect::BuildOutput
                | SetupEffect::ValidateOutput
                | SetupEffect::InstallStaging
                | SetupEffect::CopyValidatedOutput
                | SetupEffect::PublishLockedSuffix
                | SetupEffect::EmitSessionPublished
                | SetupEffect::ReleaseSetupAdmission
                | SetupEffect::SignalSetupComplete
                | SetupEffect::ReturnProviderDisposition
                | SetupEffect::OuterReleaseControlRundown,
                _,
            ) => return Err(AdapterPlanError::InvalidInput),
        }

        plan.owned |= bit(plan.next);
        plan.next = plan
            .next
            .checked_add(1)
            .ok_or(AdapterPlanError::ArithmeticOverflow)?;

        match NativeSetupPlan::SUCCESS_EFFECTS.get(usize::from(plan.next)) {
            Some(effect) => Ok(SetupProgress::Effect(PendingSetupEffect {
                plan,
                effect: *effect,
            })),
            None => {
                let identity = plan.identity.ok_or(AdapterPlanError::InvalidTransition)?;
                Ok(SetupProgress::Published(SetupCommit {
                    identity,
                    output: plan.output,
                }))
            }
        }
    }

    /// Consume a failed or cancelled native effect.
    ///
    /// Refused inside `BuildProtectedViews`, whose nested plan owns a rollback
    /// of its own; the affine capability comes straight back so rollback
    /// authority cannot be lost by calling the wrong method.
    // Returning the affine capability unchanged is the whole point: a wrong
    // call must not destroy rollback authority. Boxing the error would need an
    // allocator the kernel half does not have.
    #[allow(clippy::result_large_err)]
    pub fn failed_native(self) -> Result<SetupFailurePlan, (AdapterPlanError, Self)> {
        if matches!(self.effect, SetupEffect::BuildProtectedViews) {
            return Err((AdapterPlanError::InvalidTransition, self));
        }
        Ok(self.into_failure(true))
    }

    /// Consume a failed `BuildProtectedViews` together with the sealed receipt
    /// of its completed nested rollback.
    ///
    /// Refused anywhere else, and every affine input is returned unchanged.
    // As above, and the sealed nested receipt comes back too, so neither side
    // of the captured-process decision can be lost by a mistaken call.
    #[allow(clippy::result_large_err)]
    pub fn failed_protected_views(
        self,
        receipt: ProtectedViewRollbackReceipt,
    ) -> Result<SetupFailurePlan, (AdapterPlanError, Self, ProtectedViewRollbackReceipt)> {
        if !matches!(self.effect, SetupEffect::BuildProtectedViews) {
            return Err((AdapterPlanError::InvalidTransition, self, receipt));
        }
        if self.plan.identity != Some(receipt.identity()) {
            return Err((AdapterPlanError::InvalidTransition, self, receipt));
        }
        let retained = matches!(
            receipt.disposition(),
            CapturedProcessDisposition::RetainedBySetup
        );
        Ok(self.into_failure(retained))
    }

    fn into_failure(self, process_retained: bool) -> SetupFailurePlan {
        let Self { plan, effect: _ } = self;
        if plan.next > INDEX_PUBLISH_LOCKED_SUFFIX {
            // `plan.next` is the index of the effect that is *pending*, so this
            // is strictly greater: at `next == INDEX_PUBLISH_LOCKED_SUFFIX` the
            // Release store has not run and nothing can reach the session yet,
            // which is why `rollback_effects` has an arm for that position.
            // Past it the session is reachable, there is nothing to unwind, and
            // cancellation loses: the caller completes the published session.
            return match plan.identity {
                Some(identity) => SetupFailurePlan::CompletePublished(SetupCommit {
                    identity,
                    output: plan.output,
                }),
                // Unreachable: the identity exists from BurnMountId onward and
                // the commit is far past it. Unwinding everything is the
                // conservative answer to an impossible state.
                None => SetupFailurePlan::Rollback(SetupRollbackPlan { effects: R_REFS }),
            };
        }
        SetupFailurePlan::Rollback(SetupRollbackPlan {
            effects: NativeSetupPlan::rollback_effects(plan.next, process_retained),
        })
    }
}

// ---------------------------------------------------------------------------
// Protected views
// ---------------------------------------------------------------------------

/// One user-visible alias, numbered in exactly the order the frozen session
/// result lists its view descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AliasId(pub u32);

/// The three section spans a master MDL is allocated and locked for.
///
/// `HeaderDirectory` is the whole-section read-only spine, anchored at the
/// global header and ring directory: every byte the daemon may read, and none
/// it may write through that alias. The writable overlays are the per-ring
/// producer span and the U2K slot arena. Locking a page under both a read
/// master and a modify master is deliberate — the access rights differ, and the
/// page lock counts independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalRegion {
    HeaderDirectory,
    Ring(u32),
    U2kArena,
}

/// `MmProbeAndLockPages` access: `IoReadAccess` or `IoModifyAccess`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MdlAccess {
    Read,
    Modify,
}

/// What one alias grants its user mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasProtection {
    ReadOnly,
    ReadWrite,
}

/// The profile-fixed mapping flags for one alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MappingFlags {
    pub user_mode: bool,
    pub no_write: bool,
    pub no_execute: bool,
}

/// One native operation in the nested protected-view construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedViewEffect {
    AllocateAndLockMaster {
        region: CanonicalRegion,
        access: MdlAccess,
    },
    BuildPartial {
        alias: AliasId,
        region: CanonicalRegion,
        offset: u64,
        length: u64,
    },
    AttachCapturedProcess,
    MapAlias {
        alias: AliasId,
        protection: AliasProtection,
        flags: MappingFlags,
    },
    MapSectionView {
        alias: AliasId,
        offset: u64,
        length: u64,
        protection: AliasProtection,
    },
    DetachCapturedProcess,
}

/// The closed outcome vocabulary of one protected-view effect.
///
/// A returned user address is an *observation* the executor stores in its own
/// authoritative alias record. It never becomes an unmap key.
pub enum ProtectedViewOutcome {
    Done,
    AliasMapped {
        alias: AliasId,
        user_address: NonZeroUsize,
    },
}

/// One native action in a reverse-order unwind of a failed alias build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectedViewRollbackEffect {
    AttachCapturedProcess,
    UnmapAliasReverse { alias: AliasId },
    UnmapSectionViewReverse { alias: AliasId },
    FreePartialMdlReverse { alias: AliasId },
    DetachCapturedProcess,
    UnlockAndFreeMasterReverse { region: CanonicalRegion },
    ReleaseCapturedProcess,
}

/// Sealed proof that every alias mapped.
pub struct ProtectedViewReceipt {
    identity: SessionIdentity,
    profile: PlatformProfile,
    layout: SectionLayoutPlan,
    alias_count: u32,
}

/// The ordering and ownership state of one alias build.
pub struct ProtectedViewPlan {
    identity: SessionIdentity,
    profile: PlatformProfile,
    layout: SectionLayoutPlan,
    next: u32,
    mapped_aliases: u32,
}

/// The ordering state of one alias unwind.
pub struct ProtectedViewRollbackPlan {
    identity: SessionIdentity,
    profile: PlatformProfile,
    layout: SectionLayoutPlan,
    next: u32,
    completed_prefix: u64,
    mapped_aliases: u32,
    captured_process_released: bool,
}

/// A one-shot capability requesting exactly one native alias effect.
pub struct PendingProtectedViewEffect {
    plan: ProtectedViewPlan,
    effect: ProtectedViewEffect,
}

pub enum ProtectedViewProgress {
    Effect(PendingProtectedViewEffect),
    Complete(ProtectedViewReceipt),
}

/// Who still owns the referenced daemon process after a nested unwind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapturedProcessDisposition {
    RetainedBySetup,
    ReleasedByProtectedViews,
}

/// Sealed proof that a nested unwind ran to completion, and of what it left
/// behind for the outer plan to finish.
pub struct ProtectedViewRollbackReceipt {
    identity: SessionIdentity,
    disposition: CapturedProcessDisposition,
}

pub struct PendingProtectedViewRollbackEffect {
    plan: ProtectedViewRollbackPlan,
    effect: ProtectedViewRollbackEffect,
}

// As above.
#[allow(clippy::large_enum_variant)]
pub enum ProtectedViewRollbackProgress {
    Effect(PendingProtectedViewRollbackEffect),
    Complete(ProtectedViewRollbackReceipt),
}

impl ProtectedViewReceipt {
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    pub const fn profile(&self) -> PlatformProfile {
        self.profile
    }

    pub const fn layout(&self) -> &SectionLayoutPlan {
        &self.layout
    }

    pub const fn alias_count(&self) -> u32 {
        self.alias_count
    }
}

impl ProtectedViewRollbackReceipt {
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    pub const fn disposition(&self) -> CapturedProcessDisposition {
        self.disposition
    }
}

/// Is this a partial-MDL profile?
const fn is_modern(profile: PlatformProfile) -> bool {
    matches!(
        profile,
        PlatformProfile::Win10X64 | PlatformProfile::Win10Arm64
    )
}

/// How many master MDLs a modern profile locks: the read-only spine, one per
/// ring, and the U2K arena.
fn master_count(ring_count: u32) -> Option<u32> {
    ring_count.checked_add(2)
}

/// The section span one canonical region names.
///
/// The executor allocates and locks a master MDL over exactly this span, so the
/// span is derived here from the shared layout rather than recomputed natively.
pub fn master_region_span(
    layout: &SectionLayoutPlan,
    region: CanonicalRegion,
) -> Option<RegionDesc> {
    match region {
        // Header + ring directory, which is what this region is named for --
        // NOT the whole section. A master is locked to make the pages this
        // driver touches above APC_LEVEL resident, and every one of those is
        // already covered by a per-ring master or the U2K master. Spanning the
        // section instead put a hard cap on SETUP: `MDL.Size` is a `CSHORT`,
        // so one MDL cannot describe more than (65535 - 48) / 8 = 8185 pages
        // (~32 MiB), and `IoAllocateMdl` answers NULL above it. A 64-ring
        // topology needs a K2U arena of >= 32 MiB on its own, so the largest
        // topologies the layout accepts could never set up at all.
        CanonicalRegion::HeaderDirectory => {
            let directory = layout.ring_directory();
            let length = directory.offset.checked_add(directory.length)?;
            Some(RegionDesc { offset: 0, length })
        }
        CanonicalRegion::Ring(index) => {
            let ring = layout.ring(index)?;
            let end = ring.cq_entries.offset.checked_add(ring.cq_entries.length)?;
            let length = end.checked_sub(ring.sq_producer.offset)?;
            Some(RegionDesc {
                offset: ring.sq_producer.offset,
                length,
            })
        }
        CanonicalRegion::U2kArena => Some(layout.u2k_slots()),
    }
}

/// Which master a given master ordinal names.
fn master_at(ring_count: u32, index: u32) -> Option<(CanonicalRegion, MdlAccess)> {
    if index == 0 {
        return Some((CanonicalRegion::HeaderDirectory, MdlAccess::Read));
    }
    let ring_ordinal = index.checked_sub(1)?;
    if ring_ordinal < ring_count {
        return Some((CanonicalRegion::Ring(ring_ordinal), MdlAccess::Modify));
    }
    if ring_ordinal == ring_count {
        return Some((CanonicalRegion::U2kArena, MdlAccess::Modify));
    }
    None
}

/// One alias, in exactly the order the frozen session result lists its views.
///
/// Alias 0 is the read-only whole-section spine. Then, per ring, the three
/// regions the daemon produces into: the SQ consumer page, the CQ entries, and
/// the CQ producer page. The U2K slot arena is last.
fn alias_at(
    layout: &SectionLayoutPlan,
    alias: u32,
) -> Option<(CanonicalRegion, RegionDesc, AliasProtection)> {
    if alias == 0 {
        return Some((
            CanonicalRegion::HeaderDirectory,
            RegionDesc {
                offset: 0,
                length: layout.section_size(),
            },
            AliasProtection::ReadOnly,
        ));
    }
    let ring_alias = alias.checked_sub(1)?;
    let ring_aliases = layout.ring_count().checked_mul(3)?;
    if ring_alias < ring_aliases {
        let ring_index = ring_alias.checked_div(3)?;
        let slot = ring_alias.checked_rem(3)?;
        let ring = layout.ring(ring_index)?;
        let region = match slot {
            0 => ring.sq_consumer,
            1 => ring.cq_entries,
            _ => ring.cq_producer,
        };
        return Some((
            CanonicalRegion::Ring(ring_index),
            region,
            AliasProtection::ReadWrite,
        ));
    }
    if ring_alias == ring_aliases {
        return Some((
            CanonicalRegion::U2kArena,
            layout.u2k_slots(),
            AliasProtection::ReadWrite,
        ));
    }
    None
}

/// The profile-fixed flags for one alias mapping.
const fn mapping_flags(protection: AliasProtection) -> MappingFlags {
    MappingFlags {
        user_mode: true,
        no_write: matches!(protection, AliasProtection::ReadOnly),
        no_execute: true,
    }
}

/// The complete forward effect roster, as a total function of position.
///
/// Modern: every master locks, then every partial is built, then one attach,
/// then every alias maps, then one detach. Legacy: one attach, every section
/// view maps, one detach — and no MDL effect at all.
fn forward_effect(
    profile: PlatformProfile,
    layout: &SectionLayoutPlan,
    index: u32,
) -> Option<ProtectedViewEffect> {
    let ring_count = layout.ring_count();
    let aliases = view_count_for(ring_count).ok()?;

    if !is_modern(profile) {
        // The master MDLs are locked on EVERY profile. They are what makes the
        // system-space view of a pagefile-backed section resident, and the
        // ENTER drain reads and writes that view with the ring spin lock held,
        // i.e. at DISPATCH_LEVEL, on every profile alike. Only the ALIAS
        // mechanism is profile-split: the legacy profile hands the daemon
        // `ZwMapViewOfSection` views instead of partial MDLs, which changes
        // how the daemon's mapping is made, not whether this driver's own
        // pages may be touched above APC_LEVEL.
        let masters = master_count(ring_count)?;
        if index < masters {
            let (region, access) = master_at(ring_count, index)?;
            return Some(ProtectedViewEffect::AllocateAndLockMaster { region, access });
        }
        let index = index.checked_sub(masters)?;
        if index == 0 {
            return Some(ProtectedViewEffect::AttachCapturedProcess);
        }
        let mapping = index.checked_sub(1)?;
        if mapping < aliases {
            let (_, region, protection) = alias_at(layout, mapping)?;
            return Some(ProtectedViewEffect::MapSectionView {
                alias: AliasId(mapping),
                offset: region.offset,
                length: region.length,
                protection,
            });
        }
        if mapping == aliases {
            return Some(ProtectedViewEffect::DetachCapturedProcess);
        }
        return None;
    }

    let masters = master_count(ring_count)?;
    if index < masters {
        let (region, access) = master_at(ring_count, index)?;
        return Some(ProtectedViewEffect::AllocateAndLockMaster { region, access });
    }
    // Alias 0 is the daemon's whole-section read-only spine, and the daemon
    // validates its length against `section_size()`. A whole-section user
    // mapping cannot be a partial MDL -- `MDL.Size` is a `CSHORT`, so one MDL
    // stops at ~32 MiB -- so alias 0 is mapped by section view on EVERY
    // profile, using the same effect the legacy profile already uses for all
    // of its aliases. The per-ring and U2K aliases stay partial MDLs here:
    // they are small, and the partial is what ties them to a locked master.
    let partials = aliases.checked_sub(1)?;
    let after_masters = index.checked_sub(masters)?;
    if after_masters < partials {
        let alias = after_masters.checked_add(1)?;
        let (region, span, _) = alias_at(layout, alias)?;
        return Some(ProtectedViewEffect::BuildPartial {
            alias: AliasId(alias),
            region,
            offset: span.offset,
            length: span.length,
        });
    }
    let after_partials = after_masters.checked_sub(partials)?;
    if after_partials == 0 {
        return Some(ProtectedViewEffect::AttachCapturedProcess);
    }
    let mapping = after_partials.checked_sub(1)?;
    if mapping < aliases {
        let (_, span, protection) = alias_at(layout, mapping)?;
        if mapping == 0 {
            return Some(ProtectedViewEffect::MapSectionView {
                alias: AliasId(0),
                offset: span.offset,
                length: span.length,
                protection,
            });
        }
        return Some(ProtectedViewEffect::MapAlias {
            alias: AliasId(mapping),
            protection,
            flags: mapping_flags(protection),
        });
    }
    if mapping == aliases {
        return Some(ProtectedViewEffect::DetachCapturedProcess);
    }
    None
}

impl ProtectedViewPlan {
    /// Begin one alias build for an already-burned identity.
    pub fn begin(
        identity: SessionIdentity,
        profile: PlatformProfile,
        layout: SectionLayoutPlan,
    ) -> Result<ProtectedViewProgress, AdapterPlanError> {
        let effect =
            forward_effect(profile, &layout, 0).ok_or(AdapterPlanError::InvalidTransition)?;
        Ok(ProtectedViewProgress::Effect(PendingProtectedViewEffect {
            plan: Self {
                identity,
                profile,
                layout,
                next: 0,
                mapped_aliases: 0,
            },
            effect,
        }))
    }
}

impl PendingProtectedViewEffect {
    pub const fn effect(&self) -> ProtectedViewEffect {
        self.effect
    }

    pub fn succeeded(
        self,
        outcome: ProtectedViewOutcome,
    ) -> Result<ProtectedViewProgress, AdapterPlanError> {
        let Self { mut plan, effect } = self;

        match (effect, outcome) {
            (
                ProtectedViewEffect::MapAlias {
                    alias: expected, ..
                }
                | ProtectedViewEffect::MapSectionView {
                    alias: expected, ..
                },
                ProtectedViewOutcome::AliasMapped { alias, .. },
            ) => {
                if alias != expected {
                    // A user address reported for another alias would make the
                    // executor's authoritative record describe the wrong span.
                    return Err(AdapterPlanError::InvalidTransition);
                }
                plan.mapped_aliases = plan
                    .mapped_aliases
                    .checked_add(1)
                    .ok_or(AdapterPlanError::ArithmeticOverflow)?;
            }
            (
                ProtectedViewEffect::AllocateAndLockMaster { .. }
                | ProtectedViewEffect::BuildPartial { .. }
                | ProtectedViewEffect::AttachCapturedProcess
                | ProtectedViewEffect::DetachCapturedProcess,
                ProtectedViewOutcome::Done,
            ) => {}
            (
                ProtectedViewEffect::AllocateAndLockMaster { .. }
                | ProtectedViewEffect::BuildPartial { .. }
                | ProtectedViewEffect::AttachCapturedProcess
                | ProtectedViewEffect::MapAlias { .. }
                | ProtectedViewEffect::MapSectionView { .. }
                | ProtectedViewEffect::DetachCapturedProcess,
                _,
            ) => return Err(AdapterPlanError::InvalidInput),
        }

        plan.next = plan
            .next
            .checked_add(1)
            .ok_or(AdapterPlanError::ArithmeticOverflow)?;
        match forward_effect(plan.profile, &plan.layout, plan.next) {
            Some(effect) => Ok(ProtectedViewProgress::Effect(PendingProtectedViewEffect {
                plan,
                effect,
            })),
            None => {
                let alias_count = view_count_for(plan.layout.ring_count())?;
                if plan.mapped_aliases != alias_count {
                    return Err(AdapterPlanError::InvalidTransition);
                }
                Ok(ProtectedViewProgress::Complete(ProtectedViewReceipt {
                    identity: plan.identity,
                    profile: plan.profile,
                    layout: plan.layout,
                    alias_count,
                }))
            }
        }
    }

    /// Consume a failed native alias effect into the exact reverse unwind of
    /// what this build still owns.
    pub fn failed(self) -> ProtectedViewRollbackPlan {
        let Self { plan, effect: _ } = self;
        ProtectedViewRollbackPlan {
            identity: plan.identity,
            profile: plan.profile,
            layout: plan.layout,
            next: 0,
            completed_prefix: u64::from(plan.next),
            mapped_aliases: plan.mapped_aliases,
            captured_process_released: false,
        }
    }
}

impl ProtectedViewRollbackPlan {
    /// How many masters locked, partials were built, and aliases mapped.
    fn owned(&self) -> Option<(u32, u32, u32)> {
        let ring_count = self.layout.ring_count();
        let aliases = view_count_for(ring_count).ok()?;
        let masters = master_count(ring_count)?;
        let prefix = u32::try_from(self.completed_prefix).ok()?;
        let masters_locked = core::cmp::min(prefix, masters);
        if !is_modern(self.profile) {
            // Masters are locked on this profile too, so they are unwound on
            // this profile too. Partials remain modern-only: the legacy alias
            // is a section view, not a partial MDL.
            return Some((masters_locked, 0, self.mapped_aliases));
        }
        // Alias 0 has no partial on this profile either -- it is a section
        // view here too -- so the partial roster is one shorter than the alias
        // roster, and `rollback_effect` names alias `index + 1` for each.
        let partials = aliases.saturating_sub(1);
        let partials_built = core::cmp::min(prefix.saturating_sub(masters), partials);
        Some((masters_locked, partials_built, self.mapped_aliases))
    }

    /// The unwind roster, as a total function of position.
    ///
    /// If no alias mapped there is nothing in the daemon's address space, so
    /// there is no reattach, no detach, and no process release: the executor's
    /// own local guard already left the process, and the outer SETUP plan still
    /// owns the reference.
    fn rollback_effect(&self, index: u32) -> Option<ProtectedViewRollbackEffect> {
        let (masters_locked, partials_built, mapped) = self.owned()?;
        let modern = is_modern(self.profile);
        let mut cursor = index;

        if mapped > 0 {
            if cursor == 0 {
                return Some(ProtectedViewRollbackEffect::AttachCapturedProcess);
            }
            cursor = cursor.checked_sub(1)?;
            if cursor < mapped {
                let alias = AliasId(mapped.checked_sub(1)?.checked_sub(cursor)?);
                // The mechanism is per-alias, not per-profile: alias 0 is a
                // section view on every profile, so its unmap has to be the
                // section-view one even here.
                return Some(if modern && alias.0 != 0 {
                    ProtectedViewRollbackEffect::UnmapAliasReverse { alias }
                } else {
                    ProtectedViewRollbackEffect::UnmapSectionViewReverse { alias }
                });
            }
            cursor = cursor.checked_sub(mapped)?;
        }

        if cursor < partials_built {
            // Partials cover aliases 1..=partials_built, so the reverse walk
            // names one more than its ordinal.
            let ordinal = partials_built.checked_sub(1)?.checked_sub(cursor)?;
            let alias = AliasId(ordinal.checked_add(1)?);
            return Some(ProtectedViewRollbackEffect::FreePartialMdlReverse { alias });
        }
        cursor = cursor.checked_sub(partials_built)?;

        if mapped > 0 {
            if cursor == 0 {
                return Some(ProtectedViewRollbackEffect::DetachCapturedProcess);
            }
            cursor = cursor.checked_sub(1)?;
        }

        if cursor < masters_locked {
            let ordinal = masters_locked.checked_sub(1)?.checked_sub(cursor)?;
            let (region, _) = master_at(self.layout.ring_count(), ordinal)?;
            return Some(ProtectedViewRollbackEffect::UnlockAndFreeMasterReverse { region });
        }
        cursor = cursor.checked_sub(masters_locked)?;

        if mapped > 0 && cursor == 0 {
            return Some(ProtectedViewRollbackEffect::ReleaseCapturedProcess);
        }
        None
    }

    /// Yield the next unwind effect, or seal the receipt.
    pub fn next(self) -> ProtectedViewRollbackProgress {
        match self.rollback_effect(self.next) {
            Some(effect) => {
                ProtectedViewRollbackProgress::Effect(PendingProtectedViewRollbackEffect {
                    plan: self,
                    effect,
                })
            }
            None => ProtectedViewRollbackProgress::Complete(ProtectedViewRollbackReceipt {
                identity: self.identity,
                disposition: if self.captured_process_released {
                    CapturedProcessDisposition::ReleasedByProtectedViews
                } else {
                    CapturedProcessDisposition::RetainedBySetup
                },
            }),
        }
    }
}

impl PendingProtectedViewRollbackEffect {
    pub const fn effect(&self) -> ProtectedViewRollbackEffect {
        self.effect
    }

    /// This unwind step completed.
    pub fn succeeded(self) -> ProtectedViewRollbackProgress {
        let Self { mut plan, effect } = self;
        if matches!(effect, ProtectedViewRollbackEffect::ReleaseCapturedProcess) {
            plan.captured_process_released = true;
        }
        plan.advance()
    }

    /// This unwind step failed.
    ///
    /// The unwind still continues — the remaining resources are no less owned —
    /// but a release that did not happen is not recorded as one, so the outer
    /// plan finishes the job.
    pub fn failed(self) -> ProtectedViewRollbackProgress {
        let Self { plan, effect: _ } = self;
        plan.advance()
    }
}

impl ProtectedViewRollbackPlan {
    fn advance(mut self) -> ProtectedViewRollbackProgress {
        self.next = match self.next.checked_add(1) {
            Some(next) => next,
            // Unreachable for any real roster; sealing the receipt is the only
            // safe answer, and it reports the process as still SETUP's.
            None => {
                return ProtectedViewRollbackProgress::Complete(ProtectedViewRollbackReceipt {
                    identity: self.identity,
                    disposition: CapturedProcessDisposition::RetainedBySetup,
                });
            }
        };
        self.next()
    }
}

// ---------------------------------------------------------------------------
// Scratch identity
// ---------------------------------------------------------------------------

/// The identity of one negotiated-size scratch allocation.
///
/// A session owns exactly one DRAIN scratch per ring plus one independent fence
/// scratch. Making the identity a value rather than an index is what lets the
/// host prove all of them are pairwise distinct — sharing one buffer between a
/// ring drain and the fence would corrupt a notification refresh under a
/// concurrent teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScratchIdentity(u64);

/// Fill `out` with this session's complete scratch roster: one DRAIN identity
/// per ring, then the single fence identity.
///
/// The executor calls this rather than deriving identities itself, so the loop
/// that pairs a ring index with its scratch exists exactly once in the whole
/// driver. Aliasing two rings onto one buffer would corrupt a notification
/// refresh under a concurrent drain, and that is not a mistake a second copy
/// of this loop should be able to make.
pub fn scratch_roster(
    ring_count: u32,
    out: &mut [ScratchIdentity],
) -> Result<usize, AdapterPlanError> {
    let needed = usize::try_from(ring_count)
        .ok()
        .and_then(|rings| rings.checked_add(1))
        .ok_or(AdapterPlanError::ArithmeticOverflow)?;
    if out.len() < needed {
        return Err(AdapterPlanError::Capacity);
    }
    let mut ring_index = 0u32;
    while ring_index < ring_count {
        let scratch = ScratchIdentity::drain(ring_index);
        let slot = out
            .get_mut(usize::try_from(ring_index).map_err(|_| AdapterPlanError::Capacity)?)
            .ok_or(AdapterPlanError::Capacity)?;
        *slot = scratch;
        ring_index = ring_index
            .checked_add(1)
            .ok_or(AdapterPlanError::ArithmeticOverflow)?;
    }
    let fence = out
        .get_mut(needed.saturating_sub(1))
        .ok_or(AdapterPlanError::Capacity)?;
    *fence = ScratchIdentity::fence();
    Ok(needed)
}

impl ScratchIdentity {
    /// The DRAIN scratch of one ring. Ring indexes are bounded by
    /// `MAX_RING_COUNT`, far below the fence sentinel.
    pub const fn drain(ring_index: u32) -> Self {
        Self(ring_index as u64)
    }

    /// The one fence scratch, which belongs to no ring.
    pub const fn fence() -> Self {
        Self(u64::MAX)
    }
}
