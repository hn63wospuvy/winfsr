//! The effect vocabulary, a checked seam for effects routed through it, the
//! acquisition guards, and the host recorder.
//!
//! `06-locking.md` and `07-cache-mm.md` state most of their rules as *"X does
//! not happen while Y is held"*. [`crate::lockrank::may_acquire`] covers
//! acquisitions; this module covers the other half — what a path may DO once it
//! holds something, and whether anything observed it doing so.
//!
//! **This generalizes B5's seam rather than replacing it.**
//! [`crate::typestate::CompletionSink`] already puts kernel effects *"behind a
//! seam so the core stays WDK-free and the host can count them"*. This module's
//! sink is that pattern widened from completion to the curated C1 effect
//! vocabulary, with two additions: the boundary evaluates the held context
//! before forwarding, and the host can observe effects **in issue order** rather
//! than only count them.
//!
//! **[`Seam`] is not the crate's emission boundary, and this module does not
//! claim to be one.** [`Seam::clear_completion`] has **zero non-test callers**
//! on this SHA, because the crate has no dispatch entry at all yet and C2
//! creates no device object.
//!
//! *Round 2 correction:* rev 2 said this of **both** entry points. It is false
//! for [`Seam::emit`], which [`Guard::emit`] calls in production. Rev 2
//! sharpened a true sentence into a false one while fixing a different false
//! sentence, which is this slice's characteristic failure and the reason the
//! correction is recorded here rather than silently applied.
//!
//! What C2 changed is not that the seam runs, but that the completion path
//! **cannot compile without it**:
//! the raw [`crate::typestate::CompletionSink::complete`] method consumes a
//! [`CompletionClearance`]. The safe path obtains that proof from
//! [`Seam::clear_completion`] through the reviewed, byte-frozen
//! `effect/clearance.rs` trusted construction file.
//! [`crate::typestate::CompletionOwner::pending`] is still unconstrained and
//! performs `IoMarkIrpPending` directly through `CompletionSink` with no
//! `may_emit` and no recorder, which
//! `b5s_pending_path_still_bypasses_the_seam` measures.
//!
//! Review rounds C1-1, C1-3 and C2-1 each filed a version of this module's
//! documentation for claiming more than the code did. C2-1's was the rustdoc on
//! [`Seam::clear_completion`] calling itself *"the seam's first production
//! caller"* while the same revision's module paragraph incorrectly aggregated
//! both seam entries as having no caller. The scoped history is: production
//! [`Guard::emit`] called [`Seam::emit`], while [`Seam::clear_completion`] had
//! no non-test caller.

use crate::lockrank::{HeldLocks, LockOrderError, LockRank};
use crate::session::FenceEffect;
use crate::volume::{DismountEffect, MountEffect, MountRollbackEffect};

#[cfg(test)]
pub mod oracles;

/// What is being waited for.
///
/// `06-locking.md` §2's two corollaries make this distinction load-bearing:
/// corollary 1 keeps the size gate held **across a provider round trip on
/// purpose**, while corollary 2 forbids waiting for an admission resource under
/// that same gate. A per-gate boolean cannot express both, so the target is part
/// of the effect rather than a separate axis a caller might forget to pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitTarget {
    /// The daemon round trip of §2 corollary 1, which is legal under the size
    /// gate: *"Blocking resources are released before provider execution while
    /// the logical size gate and FCB rundown remain held."*
    ProviderRoundTrip,
    /// An application slot, ApplyReserve, grant, digest, or other admission
    /// resource — §2 corollary 2's enumerated list.
    AdmissionResource,
    /// A rundown reference draining.
    Rundown,
    /// Any other blocking resource.
    BlockingResource,
    /// The exact generation's terminal-outcome event.
    TerminalOutcomeEvent,
    /// The exact generation's terminal-joiners-drained event.
    JoinerDrainedEvent,
    /// A pending timer/DPC owner's exit event.
    PendingDpcExitEvent,
    /// One mount generation's teardown-complete event.
    MountCompletionEvent,
    /// One mount generation's ordinary-waiters-drained event.
    MountWaitersDrainedEvent,
    /// One mount generation's reset-complete event.
    MountResetCompleteEvent,
    /// One mount generation's reset-waiters-drained event.
    MountResetWaitersDrainedEvent,
}

/// What is being allocated.
///
/// `07-cache-mm.md` §5 enumerates the kinds a TRUNCATING path must not have
/// allocated: *"ReqId, grant, digest, or SQE"*. `Pool` covers ordinary kernel
/// storage, which `06-locking.md` §1 and §6 name as "allocation".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocTarget {
    /// Kernel pool.
    Pool,
    /// A request identifier.
    ReqId,
    /// A grant.
    Grant,
    /// A digest.
    Digest,
    /// A submission-queue entry.
    Sqe,
}

/// The thread's top-level IRP context.
///
/// `07-cache-mm.md` §4 states a rule no held-set can express: a paging READ
/// issued from inside `CcCopyRead`/`CcCopyWrite` runs on a thread whose
/// top-level context is already the cache sentinel, and there the path *"MUST
/// NOT synchronously wait on anything else … a second synchronous wait on that
/// same thread, stacked under the first, is a self-deadlock, not merely slow."*
/// That is a property of the thread, not of what it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopLevelContext {
    /// An ordinary dispatch context.
    Ordinary,
    /// The FSRTL cache sentinel of `07-cache-mm.md` §4.
    CacheSentinel,
}

/// Something a path may do while holding positions.
///
/// The original lock-discipline variants trace to the manually curated
/// sentences in [`oracles::FORBIDDEN_EFFECT_SENTENCES`]. Session-fence requests
/// are instead pinned to [`oracles::SESSION_FENCE_ORDER_SENTENCES`].
///
/// `every_forbidden_effect_is_representable` checks both directions only within
/// that transcribed corpus. Occurrence checks detect a curated sentence being
/// reworded; they do not discover a sentence nobody transcribed. This is not a
/// claim of document completeness or of every kernel effect Phase C will need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Block on something. §1: *"no spin lock is retained across a wait"*.
    Wait(WaitTarget),
    /// Allocate kernel storage. §1 and §6 "allocation", `07` §6.
    Allocate(AllocTarget),
    /// Free kernel storage. §6: *"allocation and free"*.
    Free,
    /// Map memory, or copy to or from a user buffer. §1 *"a mapping"*, §6
    /// *"user-buffer copies"*.
    CopyUserBuffer,
    /// A privilege or access check. §6's first named item.
    PrivilegeOrAccessCheck,
    /// Invoke a notification callback. `06-locking.md` §7.2: the sole-consumer
    /// token *"is never held while … running an access check or notification
    /// callback"*; §7.1 says the same for the fence walk.
    ///
    /// Round 1 of C1's review found this cited to §6's change-notify bullet,
    /// which names no callback. The variant had a source; the citation pointed
    /// at the wrong sentence, which is the same defect as having none.
    NotificationCallback,
    /// Call the daemon across the ring. §1 *"a provider call"*.
    CallProvider,
    /// `IoCompleteRequest`. §6 in full.
    CompleteIrp,
    /// One ordered request from the committed session-fence plan.
    SessionFence(FenceEffect),
    /// One ordered request from a mount publication transaction.
    Mount(MountEffect),
    /// One ordered request from an unpublished-mount rollback plan.
    MountRollback(MountRollbackEffect),
    /// One ordered request refining the fence's device-dismount effect.
    Dismount(DismountEffect),
}

const fn is_wait(effect: Effect) -> bool {
    matches!(effect, Effect::Wait(_))
        || matches!(
            effect,
            Effect::SessionFence(
                FenceEffect::WaitProducerAndMappingCaptureRundown
                    | FenceEffect::WaitPendingAndOwners
                    | FenceEffect::WaitControlRundown
            )
        )
}

const fn is_rundown_wait(effect: Effect) -> bool {
    matches!(effect, Effect::Wait(WaitTarget::Rundown))
        || matches!(
            effect,
            Effect::SessionFence(
                FenceEffect::WaitProducerAndMappingCaptureRundown
                    | FenceEffect::WaitPendingAndOwners
                    | FenceEffect::WaitControlRundown
            )
        )
}

const fn is_terminal_wait(effect: Effect) -> bool {
    matches!(
        effect,
        Effect::Wait(
            WaitTarget::TerminalOutcomeEvent
                | WaitTarget::JoinerDrainedEvent
                | WaitTarget::PendingDpcExitEvent
                | WaitTarget::MountCompletionEvent
                | WaitTarget::MountWaitersDrainedEvent
                | WaitTarget::MountResetCompleteEvent
                | WaitTarget::MountResetWaitersDrainedEvent
        ) | Effect::SessionFence(
            FenceEffect::WaitProducerAndMappingCaptureRundown
                | FenceEffect::WaitPendingAndOwners
                | FenceEffect::WaitControlRundown
        )
    )
}

const fn holds_terminal_wait_guard(held: HeldLocks) -> bool {
    held.holds(LockRank::MountRundown)
        || held.holds(LockRank::ControlRundown)
        || held.holds(LockRank::SessionAccessRundown)
        || held.holds(LockRank::SetupAdmissionRundown)
        || held.holds(LockRank::ControlContextAdmissionRundown)
        || held.holds(LockRank::SqWaitRole)
        || held.holds(LockRank::CqConsumerToken)
        || held.holds(LockRank::Sequencer)
        || held.holds(LockRank::AdvanceOnlyCsq)
        || held.holds(LockRank::NotifyCsq)
        || held.holds(LockRank::RegistrySpin)
        || held.holds(LockRank::CancelSpin)
        || held.holds(LockRank::VpbSpin)
}

/// Every wait target, and the exhaustive match that makes adding one a
/// **compile error** rather than a silent gap.
///
/// Round 3 measured the gap: `ALL_EFFECTS` is hand-written, `Effect::Wait(_)`
/// matches with a wildcard, and round 1's exact plant — a fifth `WaitTarget`,
/// a sixth `AllocTarget` — still compiled clean and left the suite green, under
/// a comment claiming that plant was what the fix closed. A `.len()` assertion
/// on a hand-written array cannot see a variant nobody added to the array.
///
/// `index` below is the structural catch: it matches every variant with no
/// wildcard, so a new one fails to compile here before any test runs.
pub const ALL_WAIT_TARGETS: [WaitTarget; 11] = [
    WaitTarget::ProviderRoundTrip,
    WaitTarget::AdmissionResource,
    WaitTarget::Rundown,
    WaitTarget::BlockingResource,
    WaitTarget::TerminalOutcomeEvent,
    WaitTarget::JoinerDrainedEvent,
    WaitTarget::PendingDpcExitEvent,
    WaitTarget::MountCompletionEvent,
    WaitTarget::MountWaitersDrainedEvent,
    WaitTarget::MountResetCompleteEvent,
    WaitTarget::MountResetWaitersDrainedEvent,
];

// The structural catch is `#[cfg(test)]`: it exists to make adding a variant
// a compile error, and `cargo test` is the gate that compiles it. Nothing in
// the kernel image calls it, so leaving it un-gated makes it dead code there.
#[cfg(test)]
impl WaitTarget {
    /// Position in [`ALL_WAIT_TARGETS`]. Exhaustive by construction.
    const fn index(self) -> usize {
        match self {
            Self::ProviderRoundTrip => 0,
            Self::AdmissionResource => 1,
            Self::Rundown => 2,
            Self::BlockingResource => 3,
            Self::TerminalOutcomeEvent => 4,
            Self::JoinerDrainedEvent => 5,
            Self::PendingDpcExitEvent => 6,
            Self::MountCompletionEvent => 7,
            Self::MountWaitersDrainedEvent => 8,
            Self::MountResetCompleteEvent => 9,
            Self::MountResetWaitersDrainedEvent => 10,
        }
    }
}

/// Every allocation target, with the same structural catch.
pub const ALL_ALLOC_TARGETS: [AllocTarget; 5] = [
    AllocTarget::Pool,
    AllocTarget::ReqId,
    AllocTarget::Grant,
    AllocTarget::Digest,
    AllocTarget::Sqe,
];

// The structural catch is `#[cfg(test)]`: it exists to make adding a variant
// a compile error, and `cargo test` is the gate that compiles it. Nothing in
// the kernel image calls it, so leaving it un-gated makes it dead code there.
#[cfg(test)]
impl AllocTarget {
    /// Position in [`ALL_ALLOC_TARGETS`]. Exhaustive by construction.
    const fn index(self) -> usize {
        match self {
            Self::Pool => 0,
            Self::ReqId => 1,
            Self::Grant => 2,
            Self::Digest => 3,
            Self::Sqe => 4,
        }
    }
}

/// Every fence effect, for exhaustive recorder and lock-context sweeps.
pub const ALL_FENCE_EFFECTS: [FenceEffect; 16] = [
    FenceEffect::CloseSessionAdmission,
    FenceEffect::SignalPendingEnter,
    FenceEffect::RemoveProducerMappingsReverse,
    FenceEffect::WaitProducerAndMappingCaptureRundown,
    FenceEffect::AcquireConsumersIncreasing,
    FenceEffect::DrainStablePrefixesBounded,
    FenceEffect::RetireCredits,
    FenceEffect::ReleaseConsumers,
    FenceEffect::QueueInstalledWork,
    FenceEffect::WaitPendingAndOwners,
    FenceEffect::WaitControlRundown,
    FenceEffect::ReleaseReadOnlyMappingsReverse,
    FenceEffect::ReleaseMdlsAndSystemView,
    FenceEffect::ReleaseCapturedProcess,
    FenceEffect::DismountAndDeleteDevices,
    FenceEffect::ReleaseTransientBacking,
];

// The structural catch is `#[cfg(test)]`: it makes a new fence effect fail to
// compile in the test gate until this exhaustive match and the roster sweeps
// are deliberately updated together.
#[cfg(test)]
impl FenceEffect {
    /// Position in [`ALL_FENCE_EFFECTS`]. Exhaustive by construction.
    const fn index(self) -> usize {
        match self {
            Self::CloseSessionAdmission => 0,
            Self::SignalPendingEnter => 1,
            Self::RemoveProducerMappingsReverse => 2,
            Self::WaitProducerAndMappingCaptureRundown => 3,
            Self::AcquireConsumersIncreasing => 4,
            Self::DrainStablePrefixesBounded => 5,
            Self::RetireCredits => 6,
            Self::ReleaseConsumers => 7,
            Self::QueueInstalledWork => 8,
            Self::WaitPendingAndOwners => 9,
            Self::WaitControlRundown => 10,
            Self::ReleaseReadOnlyMappingsReverse => 11,
            Self::ReleaseMdlsAndSystemView => 12,
            Self::ReleaseCapturedProcess => 13,
            Self::DismountAndDeleteDevices => 14,
            Self::ReleaseTransientBacking => 15,
        }
    }
}

/// Every distinct mount-publication effect, for exhaustive recorder and lock
/// sweeps. The transaction sequence separately contains the repeated VPB lock
/// and unlock effects.
pub const ALL_MOUNT_EFFECTS: [MountEffect; 12] = [
    MountEffect::AcquireVpb,
    MountEffect::ValidateTarget,
    MountEffect::AcquireSessionReference,
    MountEffect::ReleaseVpb,
    MountEffect::CreateMountedDevice,
    MountEffect::AllocateVcb,
    MountEffect::InitializeDeviceAndVcb,
    MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
    MountEffect::BindVpb,
    MountEffect::SetVpbMounted,
    MountEffect::ClearDeviceInitializing,
    // Appended to preserve every established effect index. Transaction order
    // is pinned separately by `MountTransaction::SUCCESS_EFFECTS`.
    MountEffect::PublishMountOwner,
];

/// Every unpublished-mount rollback effect.
pub const ALL_MOUNT_ROLLBACK_EFFECTS: [MountRollbackEffect; 5] = [
    MountRollbackEffect::ClearUnpublishedVpbBinding,
    MountRollbackEffect::FreeVcb,
    MountRollbackEffect::DeleteMountedDevice,
    MountRollbackEffect::ReleaseSessionReference,
    MountRollbackEffect::ReleaseVpbIfHeld,
];

/// Every dismount-refinement effect.
pub const ALL_DISMOUNT_EFFECTS: [DismountEffect; 7] = [
    DismountEffect::AcquireVpb,
    DismountEffect::ClearVpbBinding,
    DismountEffect::ReleaseVpb,
    DismountEffect::DeleteMountedDevice,
    DismountEffect::DeleteVdo,
    DismountEffect::RemoveRegistryEntry,
    DismountEffect::ReleaseSessionReference,
];

#[cfg(test)]
impl MountEffect {
    /// Position in [`ALL_MOUNT_EFFECTS`]. Exhaustive by construction.
    const fn index(self) -> usize {
        match self {
            Self::AcquireVpb => 0,
            Self::ValidateTarget => 1,
            Self::AcquireSessionReference => 2,
            Self::ReleaseVpb => 3,
            Self::CreateMountedDevice => 4,
            Self::AllocateVcb => 5,
            Self::InitializeDeviceAndVcb => 6,
            Self::RevalidateTargetIdentityAdmissionAndBinding => 7,
            Self::BindVpb => 8,
            Self::SetVpbMounted => 9,
            Self::ClearDeviceInitializing => 10,
            Self::PublishMountOwner => 11,
        }
    }
}

#[cfg(test)]
impl MountRollbackEffect {
    /// Position in [`ALL_MOUNT_ROLLBACK_EFFECTS`]. Exhaustive by construction.
    const fn index(self) -> usize {
        match self {
            Self::ClearUnpublishedVpbBinding => 0,
            Self::FreeVcb => 1,
            Self::DeleteMountedDevice => 2,
            Self::ReleaseSessionReference => 3,
            Self::ReleaseVpbIfHeld => 4,
        }
    }
}

#[cfg(test)]
impl DismountEffect {
    /// Position in [`ALL_DISMOUNT_EFFECTS`]. Exhaustive by construction.
    const fn index(self) -> usize {
        match self {
            Self::AcquireVpb => 0,
            Self::ClearVpbBinding => 1,
            Self::ReleaseVpb => 2,
            Self::DeleteMountedDevice => 3,
            Self::DeleteVdo => 4,
            Self::RemoveRegistryEntry => 5,
            Self::ReleaseSessionReference => 6,
        }
    }
}

/// Every effect, for exhaustive iteration.
///
/// `all_effects_has_no_duplicates` pins that this lists each variant once: a
/// duplicate would make every sweep built on it report more coverage than it
/// has.
pub const ALL_EFFECTS: [Effect; 62] = [
    Effect::Wait(WaitTarget::ProviderRoundTrip),
    Effect::Wait(WaitTarget::AdmissionResource),
    Effect::Wait(WaitTarget::Rundown),
    Effect::Wait(WaitTarget::BlockingResource),
    Effect::Wait(WaitTarget::TerminalOutcomeEvent),
    Effect::Wait(WaitTarget::JoinerDrainedEvent),
    Effect::Wait(WaitTarget::PendingDpcExitEvent),
    Effect::Wait(WaitTarget::MountCompletionEvent),
    Effect::Wait(WaitTarget::MountWaitersDrainedEvent),
    Effect::Wait(WaitTarget::MountResetCompleteEvent),
    Effect::Wait(WaitTarget::MountResetWaitersDrainedEvent),
    Effect::Allocate(AllocTarget::Pool),
    Effect::Allocate(AllocTarget::ReqId),
    Effect::Allocate(AllocTarget::Grant),
    Effect::Allocate(AllocTarget::Digest),
    Effect::Allocate(AllocTarget::Sqe),
    Effect::Free,
    Effect::CopyUserBuffer,
    Effect::PrivilegeOrAccessCheck,
    Effect::NotificationCallback,
    Effect::CallProvider,
    Effect::CompleteIrp,
    Effect::SessionFence(FenceEffect::CloseSessionAdmission),
    Effect::SessionFence(FenceEffect::SignalPendingEnter),
    Effect::SessionFence(FenceEffect::RemoveProducerMappingsReverse),
    Effect::SessionFence(FenceEffect::WaitProducerAndMappingCaptureRundown),
    Effect::SessionFence(FenceEffect::AcquireConsumersIncreasing),
    Effect::SessionFence(FenceEffect::DrainStablePrefixesBounded),
    Effect::SessionFence(FenceEffect::RetireCredits),
    Effect::SessionFence(FenceEffect::ReleaseConsumers),
    Effect::SessionFence(FenceEffect::QueueInstalledWork),
    Effect::SessionFence(FenceEffect::WaitPendingAndOwners),
    Effect::SessionFence(FenceEffect::WaitControlRundown),
    Effect::SessionFence(FenceEffect::ReleaseReadOnlyMappingsReverse),
    Effect::SessionFence(FenceEffect::ReleaseMdlsAndSystemView),
    Effect::SessionFence(FenceEffect::ReleaseCapturedProcess),
    Effect::SessionFence(FenceEffect::DismountAndDeleteDevices),
    Effect::SessionFence(FenceEffect::ReleaseTransientBacking),
    Effect::Mount(MountEffect::AcquireVpb),
    Effect::Mount(MountEffect::ValidateTarget),
    Effect::Mount(MountEffect::AcquireSessionReference),
    Effect::Mount(MountEffect::ReleaseVpb),
    Effect::Mount(MountEffect::CreateMountedDevice),
    Effect::Mount(MountEffect::AllocateVcb),
    Effect::Mount(MountEffect::InitializeDeviceAndVcb),
    Effect::Mount(MountEffect::RevalidateTargetIdentityAdmissionAndBinding),
    Effect::Mount(MountEffect::BindVpb),
    Effect::Mount(MountEffect::SetVpbMounted),
    Effect::Mount(MountEffect::ClearDeviceInitializing),
    Effect::Mount(MountEffect::PublishMountOwner),
    Effect::MountRollback(MountRollbackEffect::ClearUnpublishedVpbBinding),
    Effect::MountRollback(MountRollbackEffect::FreeVcb),
    Effect::MountRollback(MountRollbackEffect::DeleteMountedDevice),
    Effect::MountRollback(MountRollbackEffect::ReleaseSessionReference),
    Effect::MountRollback(MountRollbackEffect::ReleaseVpbIfHeld),
    Effect::Dismount(DismountEffect::AcquireVpb),
    Effect::Dismount(DismountEffect::ClearVpbBinding),
    Effect::Dismount(DismountEffect::ReleaseVpb),
    Effect::Dismount(DismountEffect::DeleteMountedDevice),
    Effect::Dismount(DismountEffect::DeleteVdo),
    Effect::Dismount(DismountEffect::RemoveRegistryEntry),
    Effect::Dismount(DismountEffect::ReleaseSessionReference),
];

/// Every top-level context, for exhaustive iteration.
pub const ALL_CONTEXTS: [TopLevelContext; 2] =
    [TopLevelContext::Ordinary, TopLevelContext::CacheSentinel];

/// A path's complete position context: what it holds, and what the thread's
/// top-level IRP context is.
///
/// The held set is private, and the **only safe** way to record a position as
/// held is [`EffectContext::acquire`] or [`EffectContext::acquire_if_unheld`],
/// both of which consult [`crate::lockrank::may_acquire`].
///
/// **The escape hatch is `unsafe`, and round 1 of C1's review is why.** This
/// type previously offered `pub const fn new(held, top_level)` taking any
/// [`HeldLocks`], while `HeldLocks::acquire` and `HeldLocks::from_bits` are also
/// public — so safe code, inside or outside the crate, could mint a context
/// claiming to hold anything with no guard and no check. That is precisely the
/// design's own falsifier 3, and the doc here asserted the opposite. The
/// constructor is now [`EffectContext::assume_held`], it is `unsafe`, and its
/// contract states what the caller is asserting.
/// **Not `Copy`, and not `Clone`.** Review round 3 measured what duplication
/// costs: safe code copied a context, acquired the sequencer through a guard,
/// and then passed the *stale* copy to the seam — which approved
/// `CompleteIrp` and `Allocate` while the spin lock was still held, with no
/// `unsafe` anywhere. A second copy could also outlive its guard and keep
/// claiming a position that had been released. Making the type move-only is
/// what makes the `unsafe` constructors mean anything: a context is a claim
/// about *now*, and a duplicate is a claim about a moment that has passed.
///
/// This is the same discipline B5 applies to `CompletionOwner`, for the same
/// reason.
#[derive(Debug, PartialEq, Eq)]
pub struct EffectContext {
    held: HeldLocks,
    top_level: TopLevelContext,
}

impl EffectContext {
    /// Build a context from a raw held set, asserting that it is truthful.
    ///
    /// This is the seam between a real call site and the model: somewhere, a
    /// path that has genuinely acquired kernel locks has to say so. Every other
    /// route into a non-empty context goes through a guard that consulted the
    /// checker.
    ///
    /// # Safety
    ///
    /// The caller asserts that `held` names exactly the modelled positions this
    /// path currently owns, and that `top_level` is the thread's real top-level
    /// IRP context. Nothing here verifies either: the model records positions,
    /// it does not acquire kernel locks and does not inspect the thread. A false
    /// context makes every verdict computed from it meaningless — the checker
    /// proves refusal *given* a context, which is the limit the gate documents
    /// carry as PENDING.
    pub const unsafe fn assume_held(held: HeldLocks, top_level: TopLevelContext) -> Self {
        Self { held, top_level }
    }

    /// Hold nothing, in an ordinary top-level context.
    ///
    /// # Safety
    ///
    /// The caller asserts that this path owns **none** of the modelled
    /// positions.
    ///
    /// **This is the most permissive claim the type can carry, not the
    /// weakest, and an earlier version of this comment had it exactly
    /// backwards.** Round 2 of C1's review measured the consequence: with a
    /// live `Sequencer` guard in scope, passing a forged `empty()` turns
    /// `Err(CompletionUnderLock)`, `Err(AllocationUnderSequencer)` and
    /// `Err(ActionUnderLock)` into `Ok(())`, and `size::publish_sizes_to_cc`
    /// approves a `CcPublication` on it. An empty held-set is what unlocks
    /// every rule, so claiming it falsely is the single most dangerous lie a
    /// caller can tell this model — which is why it is `unsafe` like
    /// [`EffectContext::assume_held`], of which it is the special case.
    pub const unsafe fn empty() -> Self {
        Self {
            held: HeldLocks::none(),
            top_level: TopLevelContext::Ordinary,
        }
    }

    /// Hold nothing, on a thread whose top-level context is the FSRTL cache
    /// sentinel (`07-cache-mm.md` §4).
    ///
    /// # Safety
    ///
    /// The same obligation as [`EffectContext::empty`]: the caller asserts this
    /// path owns none of the modelled positions. Naming the sentinel makes the
    /// checker stricter about waits, which does **not** offset the held-set
    /// half being the most permissive claim available.
    pub const unsafe fn empty_under_cache_sentinel() -> Self {
        Self {
            held: HeldLocks::none(),
            top_level: TopLevelContext::CacheSentinel,
        }
    }

    /// The held set.
    pub const fn held(&self) -> HeldLocks {
        self.held
    }

    /// The thread's top-level context.
    pub const fn top_level(&self) -> TopLevelContext {
        self.top_level
    }
}

/// May a path in `ctx` perform `effect`?
///
/// The rules, in the order checked, so the error names the **first** rule
/// broken — the convention [`crate::lockrank::may_acquire`] already follows:
///
/// 1. `07-cache-mm.md` §4 — a synchronous wait while the top-level context is
///    the cache sentinel. Checked first because it holds regardless of what is
///    owned, so no held-set rule can subsume it.
/// 2. `06-locking.md` §6 — `IoCompleteRequest` with any modelled position held.
/// 3. C4 terminal waits — no terminal event or session-fence wait while a
///    rundown, role, or spin guard is held.
/// 4. `07-cache-mm.md` §6 — an allocation while the sequencer is held.
///    **Checked before rule 5 on purpose.** The sequencer is a spin lock, so
///    rule 5 would otherwise reach this case first and report the general leaf
///    rule; §6 is the more specific sentence and naming it is the difference
///    between a diagnostic that points at the document and one that does not.
///    Placed after rule 5 this arm is unreachable, which is the shape a
///    refinement takes when it is decoration.
/// 5. `06-locking.md` §1 and §6 — a working effect under a spin lock or the
///    change-notify push lock.
/// 6. `06-locking.md` §2 corollary 2 — an admission-resource wait or an
///    allocation while the logical size gate is owned. Corollary 1's provider
///    round trip is deliberately **not** caught by this rule.
/// 7. `06-locking.md` §3.2 — a rundown drain while the per-open lifecycle gate
///    is owned. Deliberately narrow; see
///    [`crate::lockrank::LockOrderError::DrainUnderLifecycleGate`] for what the
///    sentence supports and what C1 declines to decide.
/// 8. `06-locking.md` §7.1/§7.2 — blocking work, an access check, or a
///    notification callback while the sole-consumer token is held.
/// 9. otherwise legal.
pub const fn may_emit(ctx: &EffectContext, effect: Effect) -> Result<(), LockOrderError> {
    if matches!(ctx.top_level, TopLevelContext::CacheSentinel) && is_wait(effect) {
        return Err(LockOrderError::SyncWaitUnderCacheSentinel);
    }
    if matches!(effect, Effect::CompleteIrp) {
        return if ctx.held.is_empty() {
            Ok(())
        } else {
            Err(LockOrderError::CompletionUnderLock)
        };
    }
    if is_terminal_wait(effect) && holds_terminal_wait_guard(ctx.held) {
        return Err(LockOrderError::LifecycleWaitUnderGuard);
    }
    if ctx.held.holds(LockRank::CqConsumerToken) && is_wait(effect) {
        return Err(LockOrderError::WaitUnderNoWaitRole);
    }
    if ctx.held.holds(LockRank::Sequencer) && matches!(effect, Effect::Allocate(_)) {
        return Err(LockOrderError::AllocationUnderSequencer);
    }
    if ctx.held.holds_any_spin_lock() || ctx.held.holds_push_lock() {
        return Err(LockOrderError::ActionUnderLock);
    }
    if ctx.held.holds(LockRank::SizeGate)
        && matches!(
            effect,
            Effect::Wait(WaitTarget::AdmissionResource) | Effect::Allocate(_)
        )
    {
        return Err(LockOrderError::AdmissionUnderSizeGate);
    }
    if ctx.held.holds(LockRank::PerOpenLifecycle) && is_rundown_wait(effect) {
        return Err(LockOrderError::DrainUnderLifecycleGate);
    }
    if ctx.held.holds(LockRank::SoleConsumerToken)
        && (matches!(
            effect,
            Effect::Wait(_) | Effect::PrivilegeOrAccessCheck | Effect::NotificationCallback
        ) || is_wait(effect))
    {
        return Err(LockOrderError::WorkUnderSoleConsumerToken);
    }
    Ok(())
}

/// Ownership of one position for a scope.
///
/// Dropping the guard releases **only what the guard acquired**. A conditional
/// guard that found the position already held releases nothing, which is
/// `07-cache-mm.md` §10's rule for `AcquireForCcFlush`/`ReleaseForCcFlush`:
/// they *"acquire the FCB paging resource only if the calling thread does not
/// already own it, and release only what they acquired, so a flush issued from a
/// context that already holds the paging resource does not deadlock against
/// itself."*
///
/// The guard borrows its context mutably, so the context is unreachable while a
/// guard is alive. Nesting goes through [`Guard::acquire`] and
/// [`Guard::acquire_if_unheld`], which reborrow — there is no path that records
/// a hold without passing [`crate::lockrank::may_acquire`].
#[derive(Debug)]
pub struct Guard<'a> {
    ctx: &'a mut EffectContext,
    position: LockRank,
    acquired: bool,
}

impl Guard<'_> {
    /// The context as it stands with this guard held.
    pub fn context(&self) -> &EffectContext {
        self.ctx
    }

    /// Did this guard actually take the position?
    ///
    /// `false` only for a conditional guard whose position was already held.
    #[cfg(test)]
    pub const fn acquired_for_test(&self) -> bool {
        self.acquired
    }

    /// Take a further position while holding this one.
    pub fn acquire(&mut self, position: LockRank) -> Result<Guard<'_>, LockOrderError> {
        self.ctx.acquire(position)
    }

    /// Take a further position only if it is not already held
    /// (`07-cache-mm.md` §10).
    pub fn acquire_if_unheld(&mut self, position: LockRank) -> Result<Guard<'_>, LockOrderError> {
        self.ctx.acquire_if_unheld(position)
    }

    /// Perform `effect` through `seam`, in this guard's context.
    pub fn emit<S: EffectSink>(
        &self,
        seam: &mut Seam<S>,
        effect: Effect,
    ) -> Result<(), LockOrderError> {
        seam.emit(self.ctx, effect)
    }

    /// Mint a `DISPATCH_LEVEL` token from a spin-lock guard.
    ///
    /// `06-locking.md` §1's spin locks raise IRQL to DISPATCH_LEVEL, and
    /// [`crate::typestate::Dispatch`] names *"the lock guards of `06-locking.md`
    /// section 1"* as its intended producer. This is that producer. Returns
    /// `None` for a position that is not a spin lock, because no other kind
    /// raises IRQL.
    ///
    /// # Safety
    ///
    /// The caller must have actually acquired the corresponding kernel spin
    /// lock, so the thread is genuinely at DISPATCH_LEVEL. This model records
    /// positions; it does not raise IRQL and does not inspect it. A token minted
    /// without the real acquisition is caught by Driver Verifier, not by
    /// `rustc` — the same limit [`crate::typestate::passive_at_driver_entry`]
    /// states.
    pub unsafe fn dispatch_token(&self) -> Option<crate::typestate::Dispatch> {
        if matches!(self.position.kind(), crate::lockrank::LockKind::SpinLock) {
            Some(crate::typestate::Dispatch::new())
        } else {
            None
        }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.acquired {
            self.ctx.held = self.ctx.held.release(self.position);
        }
    }
}

impl EffectContext {
    /// Take `position`, or refuse with the rule that forbids it.
    pub fn acquire(&mut self, position: LockRank) -> Result<Guard<'_>, LockOrderError> {
        crate::lockrank::may_acquire(self.held, position)?;
        self.held = self.held.acquire(position);
        Ok(Guard {
            ctx: self,
            position,
            acquired: true,
        })
    }

    /// Take `position` only if this context does not already hold it.
    ///
    /// `07-cache-mm.md` §10's `AcquireForCcFlush`/`ReleaseForCcFlush` shape. When
    /// the position is already held this acquires nothing and the returned guard
    /// releases nothing; otherwise it is exactly [`EffectContext::acquire`],
    /// **including its refusal** — an acquisition that would break the order is
    /// still an error rather than a guard that silently took nothing.
    pub fn acquire_if_unheld(&mut self, position: LockRank) -> Result<Guard<'_>, LockOrderError> {
        if self.held.holds(position) {
            return Ok(Guard {
                ctx: self,
                position,
                acquired: false,
            });
        }
        self.acquire(position)
    }
}

/// The kernel effects a path performs, behind a seam so the core stays WDK-free
/// and the host can observe them in issue order.
///
/// This is [`crate::typestate::CompletionSink`]'s pattern widened from
/// completion to the curated C1 effect vocabulary. Its obligations are the same
/// in kind: an implementation performs real kernel work, so the compiler cannot
/// check that the effect it performs is the one it was handed.
///
/// # Safety
///
/// An implementation must perform exactly the effect it is given, against the
/// resources the caller's context describes, and must not perform an effect the
/// seam has not forwarded to it.
pub unsafe trait EffectSink {
    /// Perform `effect`.
    ///
    /// # Safety
    ///
    /// Called only by [`Seam::emit`], and only after [`may_emit`] returned `Ok`
    /// for the caller's context.
    unsafe fn emit(&mut self, effect: Effect);
}

/// A checked, observed boundary for the effects routed through it.
///
/// Every effect **that crosses this type** is checked against the caller's held
/// context before it reaches the sink and — in a test build — recorded in issue
/// order. Refusal is a `Result`; `11-rust-implementation.md` §5 forbids a panic
/// on this path. A refused effect reaches neither the sink nor the recorder.
///
/// **Not "the one boundary a kernel effect crosses", which is what this comment
/// said until review round 3.** [`Seam::clear_completion`] has zero non-test
/// callers in C2, while [`Seam::emit`] has the production caller
/// [`Guard::emit`]. B5's two `CompletionSink` effects do not cross
/// [`Seam::emit`]. The type is an instrument whose two entry points have
/// different production-call boundaries.
#[derive(Debug)]
pub struct Seam<S: EffectSink> {
    sink: S,
}

impl<S: EffectSink> Seam<S> {
    /// Wrap a sink.
    pub const fn new(sink: S) -> Self {
        Self { sink }
    }

    /// Check `effect` against `ctx` and, if legal, perform it.
    pub fn emit(&mut self, ctx: &EffectContext, effect: Effect) -> Result<(), LockOrderError> {
        may_emit(ctx, effect)?;
        #[cfg(test)]
        recorder::record(ctx, effect);
        // SAFETY: `may_emit` returned `Ok` for this context and effect, which is
        // exactly the precondition `EffectSink::emit` states.
        unsafe { self.sink.emit(effect) };
        Ok(())
    }

    /// Check `Effect::CompleteIrp` against `ctx`, record it, and return the
    /// clearance required by the raw
    /// [`crate::typestate::CompletionSink::complete`] sink.
    ///
    /// **This has no non-test callers on this SHA**, and the module header says
    /// why: the crate has no dispatch entry yet. What C2 establishes is the
    /// compile-time requirement, not a live call. C2's first review round found
    /// this comment calling itself *"the seam's first production caller"*,
    /// contradicting that header in the same file.
    ///
    /// Refusal is a `Result`; `11-rust-implementation.md` §5 forbids a panic
    /// here.
    ///
    /// The returned clearance **borrows `ctx`**, so no lock can be acquired **on
    /// that same context value** while a clearance minted from it is
    /// outstanding — acquiring needs `&mut`, and the borrow checker refuses.
    /// `clearance_outlives_its_context` is the fixture.
    ///
    /// **The bound is per-value, not per-thread, and that is weaker than it
    /// sounds.** Round 2 of C2's review completed under `LockRank::Sequencer`
    /// in three lines by clearing against one `EffectContext` and acquiring on a
    /// second, ordinary one. Nothing here ties a clearance to the caller's real
    /// held-set; an `EffectContext` is a value a caller may hold several of.
    /// Closing that would need a token the caller cannot swap — a thread or IRQL
    /// witness — which this slice does not have. Until then the honest statement
    /// is the one in this paragraph, not "a lock cannot be taken before the
    /// completion runs".
    ///
    /// It does not perform the completion — `CompletionOwner` owns the sink and
    /// the at-most-once property. It grants permission.
    ///
    /// Construction occurs in the complete trusted boundary
    /// `effect/clearance.rs`, whose reviewed bytes are frozen by
    /// `verify_c2_clearance_boundary.ps1`. Safe code outside that file cannot
    /// fabricate the private-field token through normal construction. Unsafe
    /// code can still fabricate a value with `MaybeUninit`, `transmute`, or an
    /// equivalent invariant violation and call the unsafe sink; the boundary is
    /// review plus a byte freeze, not a language proof inside the defining file.
    pub fn clear_completion<'a>(
        &mut self,
        ctx: &'a EffectContext,
    ) -> Result<CompletionClearance<'a>, LockOrderError> {
        let cleared = clearance::checked(ctx)?;
        #[cfg(test)]
        recorder::record(ctx, Effect::CompleteIrp);
        Ok(cleared)
    }

    /// The wrapped sink, for tests that assert what reached it.
    #[cfg(test)]
    pub fn sink_for_test(&self) -> &S {
        &self.sink
    }
}

mod clearance;
pub use clearance::CompletionClearance;

/// Issue-order observation of the seam. Test builds only.
///
/// `#[cfg(test)]` rather than a Cargo feature: `fsring-core` deliberately
/// carries no `[features]` section — the core is profile-parameterized, not
/// profile-compiled — and A2 made that a checked property. A feature here would
/// trade a shipped property for a convenience.
///
/// The log is thread-local, so tests running in parallel do not see each
/// other's effects. Each test calls [`reset`] before emitting.
#[cfg(test)]
pub mod recorder {
    use super::{Effect, EffectContext, TopLevelContext};
    use crate::lockrank::HeldLocks;
    use std::cell::RefCell;
    use std::vec::Vec;

    thread_local! {
        static LOG: RefCell<Vec<(HeldLocks, TopLevelContext, Effect)>> =
            const { RefCell::new(Vec::new()) };
    }

    /// Forget everything recorded on this thread.
    pub fn reset() {
        LOG.with(|log| log.borrow_mut().clear());
    }

    /// Record one effect. Called by [`super::Seam::emit`] **after** the check,
    /// so a refused effect never appears.
    pub fn record(ctx: &EffectContext, effect: Effect) {
        LOG.with(|log| {
            log.borrow_mut().push((ctx.held(), ctx.top_level(), effect));
        });
    }

    /// Everything recorded on this thread, in issue order.
    pub fn entries() -> Vec<(HeldLocks, TopLevelContext, Effect)> {
        LOG.with(|log| log.borrow().clone())
    }

    fn position_of(effect: Effect) -> Option<usize> {
        entries().iter().position(|(_, _, e)| *e == effect)
    }

    fn require(effect: Effect) -> usize {
        match position_of(effect) {
            Some(i) => i,
            None => panic!("{effect:?} was never issued"),
        }
    }

    /// Assert `first` was issued before `second`, and that both were issued.
    pub fn assert_before(first: Effect, second: Effect) {
        let a = require(first);
        let b = require(second);
        assert!(
            a < b,
            "expected {first:?} before {second:?}, got {a} then {b}"
        );
    }

    /// Assert no effect matching `forbidden` was issued strictly between
    /// `start` and `end`.
    pub fn assert_none_between(forbidden: impl Fn(Effect) -> bool, start: Effect, end: Effect) {
        let a = require(start);
        let b = require(end);
        for (i, (_, _, e)) in entries().into_iter().enumerate() {
            if i > a && i < b && forbidden(e) {
                panic!(
                    "expected {e:?} to be absent between {start:?} and {end:?}, found it at {i}"
                );
            }
        }
    }

    /// Assert `effect` was issued exactly `n` times.
    pub fn assert_count(effect: Effect, n: usize) {
        let seen = entries().iter().filter(|(_, _, e)| *e == effect).count();
        assert_eq!(seen, n, "expected {effect:?} {n} times, saw {seen}");
    }

    /// Assert every position in `acquired` also appears in `released`.
    pub fn assert_rollback_complete(
        acquired: &[crate::lockrank::LockRank],
        released: &[crate::lockrank::LockRank],
    ) {
        for position in acquired {
            assert!(
                released.contains(position),
                "{position:?} was acquired and never released"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effect::oracles::{
        ALLOC_TARGET_SENTENCE, CACHE_DOC, FORBIDDEN_EFFECT_SENTENCES, LOCK_DOC,
        PROVIDER_ROUND_TRIP_IS_LEGAL,
    };

    /// Each position noun manually entered in the independent `NOUNS` list is
    /// either marked modelled or checked against the known-unmodelled list.
    ///
    /// **This is a check over the independently curated `NOUNS` list below, not
    /// a noun parser.** Adding a sentence to the corpus does not automatically
    /// add its nouns here; omitted nouns remain review-bound.
    ///
    /// The noun list is transcribed from the sentences, and every entry is
    /// required to occur in the corpus, so a noun that is not in the text fails
    /// here rather than padding the check. It caught its own first draft:
    /// "push lock" appears in no curated sentence.
    ///
    /// **Measured limit.** The `modelled` flag is trusted in the `true`
    /// direction. Flipping an entry from `false` to `true` skips its
    /// known-unmodelled assertion and the suite stays green, because "logical
    /// gate" and "spin lock" name classes rather than single `LockRank`
    /// identifiers and no mechanical map exists. What is measured is the
    /// direction that matters: removing `FCB rundown` from the known-unmodelled
    /// list turns this test **red**, so a `NOUNS` entry marked unmodelled cannot
    /// escape both classifications.
    #[test]
    fn each_curated_position_noun_occurs_and_known_unmodelled_ones_are_listed() {
        use crate::effect::oracles::KNOWN_UNMODELLED_POSITIONS_IN_C1 as UNCOVERED;

        // (noun as the sentences write it, modelled?)
        //
        // Transcribed from the nine sentences plus corollary 1. Each is
        // required to occur in the corpus below, so a noun invented here fails
        // rather than padding the check — which it did on the first attempt,
        // catching "push lock", a phrase no curated sentence contains.
        const NOUNS: &[(&str, bool)] = &[
            ("spin lock", true),
            ("sequencer lock", true),
            ("logical gate", true),
            ("logical size gate", true),
            ("lifecycle", true),
            ("cache sentinel", true),
            ("token", true),
            ("FCB", true),
            ("CCB", true),
            ("domain lock", true),
            // Named by a curated sentence and NOT modelled — each must appear
            // on the known-unmodelled list.
            ("FCB rundown", false),
            ("namespace", false),
        ];

        let corpus: String = FORBIDDEN_EFFECT_SENTENCES
            .iter()
            .map(|(_, p)| *p)
            .chain(core::iter::once(
                crate::effect::oracles::PROVIDER_ROUND_TRIP_IS_LEGAL,
            ))
            .collect::<Vec<_>>()
            .join(" ");

        let mut checked_known_unmodelled = 0usize;
        for (noun, modelled) in NOUNS {
            assert!(
                corpus.contains(noun),
                "{noun:?} is claimed to come from a curated sentence and does not"
            );
            if !modelled {
                checked_known_unmodelled = checked_known_unmodelled.saturating_add(1);
                assert!(
                    UNCOVERED
                        .iter()
                        .any(|u| u.phrase.contains(noun) || noun.contains(u.phrase)),
                    "a curated sentence names {noun:?}, no LockRank models it, \
                     and it is not on the known-unmodelled list"
                );
            }
        }

        // Anti-vacuity: the known-unmodelled assertion must actually have run.
        //
        // The C1 mutation sweep found the `!modelled` guard disablable with
        // nothing noticing — force it false and the loop body never executes,
        // so the test passes having checked no position at all. A counter is
        // the difference between "every curated noun marked unmodelled is
        // listed" and "no such noun was examined".
        assert_eq!(
            checked_known_unmodelled, 2,
            "the known-unmodelled assertion ran {checked_known_unmodelled} \
             times; it must run for every noun marked unmodelled, and this test \
             passes vacuously if it runs for none"
        );
    }

    /// Anti-vacuity: every sentence manually transcribed into the curated
    /// effect corpus must still occur in its source document. Rewording such an
    /// entry must break this; a sentence nobody transcribed is outside the
    /// check.
    #[test]
    fn every_forbidding_sentence_still_occurs() {
        assert_eq!(FORBIDDEN_EFFECT_SENTENCES.len(), 9);
        for (doc, phrase) in FORBIDDEN_EFFECT_SENTENCES {
            let text = if *doc == "06" { LOCK_DOC } else { CACHE_DOC };
            assert!(
                text.contains(phrase),
                "{doc}-*.md no longer contains {phrase:?}; the effect roster is stale"
            );
        }
        assert!(CACHE_DOC.contains(ALLOC_TARGET_SENTENCE));
        assert!(
            LOCK_DOC.contains(PROVIDER_ROUND_TRIP_IS_LEGAL),
            "06 §2 corollary 1 is what keeps the corollary-2 refinement from \
             becoming a blanket ban on waiting under the size gate"
        );
    }

    /// The manual fence-effect roster must agree with the exhaustive index.
    #[test]
    fn every_fence_effect_has_its_pinned_roster_index() {
        let expected = [
            (FenceEffect::CloseSessionAdmission, 0),
            (FenceEffect::SignalPendingEnter, 1),
            (FenceEffect::RemoveProducerMappingsReverse, 2),
            (FenceEffect::WaitProducerAndMappingCaptureRundown, 3),
            (FenceEffect::AcquireConsumersIncreasing, 4),
            (FenceEffect::DrainStablePrefixesBounded, 5),
            (FenceEffect::RetireCredits, 6),
            (FenceEffect::ReleaseConsumers, 7),
            (FenceEffect::QueueInstalledWork, 8),
            (FenceEffect::WaitPendingAndOwners, 9),
            (FenceEffect::WaitControlRundown, 10),
            (FenceEffect::ReleaseReadOnlyMappingsReverse, 11),
            (FenceEffect::ReleaseMdlsAndSystemView, 12),
            (FenceEffect::ReleaseCapturedProcess, 13),
            (FenceEffect::DismountAndDeleteDevices, 14),
            (FenceEffect::ReleaseTransientBacking, 15),
        ];

        assert_eq!(ALL_FENCE_EFFECTS.len(), expected.len());
        for (listed, (expected_effect, expected_index)) in
            ALL_FENCE_EFFECTS.iter().copied().zip(expected)
        {
            assert_eq!(listed, expected_effect);
            assert_eq!(listed.index(), expected_index);
        }
    }

    /// The three volume-effect rosters agree with exhaustive enum indexes.
    #[test]
    fn every_volume_effect_has_its_pinned_roster_index() {
        let mounts = [
            (MountEffect::AcquireVpb, 0),
            (MountEffect::ValidateTarget, 1),
            (MountEffect::AcquireSessionReference, 2),
            (MountEffect::ReleaseVpb, 3),
            (MountEffect::CreateMountedDevice, 4),
            (MountEffect::AllocateVcb, 5),
            (MountEffect::InitializeDeviceAndVcb, 6),
            (MountEffect::RevalidateTargetIdentityAdmissionAndBinding, 7),
            (MountEffect::BindVpb, 8),
            (MountEffect::SetVpbMounted, 9),
            (MountEffect::ClearDeviceInitializing, 10),
            (MountEffect::PublishMountOwner, 11),
        ];
        assert_eq!(ALL_MOUNT_EFFECTS.len(), mounts.len());
        for (listed, (expected, index)) in ALL_MOUNT_EFFECTS.into_iter().zip(mounts) {
            assert_eq!(listed, expected);
            assert_eq!(listed.index(), index);
        }

        let rollbacks = [
            (MountRollbackEffect::ClearUnpublishedVpbBinding, 0),
            (MountRollbackEffect::FreeVcb, 1),
            (MountRollbackEffect::DeleteMountedDevice, 2),
            (MountRollbackEffect::ReleaseSessionReference, 3),
            (MountRollbackEffect::ReleaseVpbIfHeld, 4),
        ];
        assert_eq!(ALL_MOUNT_ROLLBACK_EFFECTS.len(), rollbacks.len());
        for (listed, (expected, index)) in ALL_MOUNT_ROLLBACK_EFFECTS.into_iter().zip(rollbacks) {
            assert_eq!(listed, expected);
            assert_eq!(listed.index(), index);
        }

        let dismounts = [
            (DismountEffect::AcquireVpb, 0),
            (DismountEffect::ClearVpbBinding, 1),
            (DismountEffect::ReleaseVpb, 2),
            (DismountEffect::DeleteMountedDevice, 3),
            (DismountEffect::DeleteVdo, 4),
            (DismountEffect::RemoveRegistryEntry, 5),
            (DismountEffect::ReleaseSessionReference, 6),
        ];
        assert_eq!(ALL_DISMOUNT_EFFECTS.len(), dismounts.len());
        for (listed, (expected, index)) in ALL_DISMOUNT_EFFECTS.into_iter().zip(dismounts) {
            assert_eq!(listed, expected);
            assert_eq!(listed.index(), index);
        }
    }

    /// Every effect and target manually listed from the curated sentence corpus
    /// must be representable.
    ///
    /// The mapping from each hand-transcribed corpus verb to a variant is stated
    /// once here. An unmapped listed verb fails; this does not discover verbs
    /// in sentences outside the curated corpus.
    #[test]
    fn every_forbidden_effect_is_representable() {
        // The keyword that licenses each variant, taken from the sentence that
        // names it. Written as a `match` on the enum rather than as a list of
        // pairs, so a variant added later does not compile until it is given a
        // source keyword. Round 1 of C1's review found the pair-list form
        // iterating one direction only, and `NotificationCallback` — cited to a
        // §6 bullet that names no callback — passed unnoticed.
        const fn keyword(effect: Effect) -> Option<&'static str> {
            match effect {
                Effect::Wait(_) => Some("wait"),
                Effect::Allocate(_) => Some("alloc"),
                Effect::Free => Some("free"),
                Effect::CopyUserBuffer => Some("copies"),
                Effect::PrivilegeOrAccessCheck => Some("access check"),
                Effect::NotificationCallback => Some("notification callback"),
                Effect::CallProvider => Some("provider call"),
                Effect::CompleteIrp => Some("completion"),
                Effect::SessionFence(_)
                | Effect::Mount(_)
                | Effect::MountRollback(_)
                | Effect::Dismount(_) => None,
            }
        }

        // The verbs manually transcribed from the curated sentences. This is a
        // hand list and makes no claim about sentences outside the corpus. Each
        // entry is checked against the corpus below, so a listed verb that is
        // not in the transcribed text fails here.
        const DOCUMENT_VERBS: &[&str] = &[
            "wait",
            "alloc",
            "free",
            "copies",
            "access check",
            "notification callback",
            "provider call",
            "completion",
        ];

        let corpus: String = FORBIDDEN_EFFECT_SENTENCES
            .iter()
            .map(|(_, phrase)| *phrase)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();

        // Direction 1, over ALL_EFFECTS itself: no variant without a source.
        for effect in ALL_EFFECTS {
            if let Some(keyword) = keyword(effect) {
                assert!(
                    corpus.contains(keyword),
                    "{effect:?} is licensed by no curated sentence: none contains {keyword:?}"
                );
            } else {
                assert!(matches!(
                    effect,
                    Effect::SessionFence(_)
                        | Effect::Mount(_)
                        | Effect::MountRollback(_)
                        | Effect::Dismount(_)
                ));
            }
        }

        // Direction 2: every hand-transcribed DOCUMENT_VERBS entry reaches a
        // variant.
        //
        // Round 2 found the first version of this drawing its element from
        // `ALL_EFFECTS` and then searching `ALL_EFFECTS` — reflexively
        // satisfied, unable to fail for any code. The source of the keywords
        // has to be the curated corpus, not the enum, or this is not a second
        // direction within that corpus at all.
        for verb in DOCUMENT_VERBS {
            assert!(
                corpus.contains(verb),
                "{verb:?} is claimed to come from the curated sentences and \
                 does not"
            );
            assert!(
                ALL_EFFECTS.iter().any(|e| keyword(*e) == Some(*verb)),
                "the curated verb list names {verb:?} and no Effect variant covers it"
            );
        }

        // ALL_EFFECTS must contain Wait(t) for EVERY t, and Allocate(t) for
        // every t — driven from the curated target rosters, whose `index`
        // matches are exhaustive, so a new variant is a compile error before
        // this runs.
        //
        // Round 3 measured why counting is not enough: the previous form
        // counted `ALL_EFFECTS`'s own wildcard matches against a literal, so
        // round 1's plant (a fifth WaitTarget, a sixth AllocTarget) compiled
        // clean and left the suite green — under a comment naming that exact
        // plant as the thing it closed.
        for t in ALL_WAIT_TARGETS {
            assert!(
                ALL_EFFECTS.contains(&Effect::Wait(t)),
                "ALL_EFFECTS is missing Wait({t:?}); a target exists that no sweep will ever visit"
            );
            assert!(t.index() < ALL_WAIT_TARGETS.len());
        }
        for t in ALL_ALLOC_TARGETS {
            assert!(
                ALL_EFFECTS.contains(&Effect::Allocate(t)),
                "ALL_EFFECTS is missing Allocate({t:?}); a target exists that no sweep will ever visit"
            );
            assert!(t.index() < ALL_ALLOC_TARGETS.len());
        }

        for effect in ALL_FENCE_EFFECTS {
            assert!(
                ALL_EFFECTS.contains(&Effect::SessionFence(effect)),
                "ALL_EFFECTS is missing SessionFence({effect:?})"
            );
        }
        for effect in ALL_MOUNT_EFFECTS {
            assert!(
                ALL_EFFECTS.contains(&Effect::Mount(effect)),
                "ALL_EFFECTS is missing Mount({effect:?})"
            );
        }
        for effect in ALL_MOUNT_ROLLBACK_EFFECTS {
            assert!(
                ALL_EFFECTS.contains(&Effect::MountRollback(effect)),
                "ALL_EFFECTS is missing MountRollback({effect:?})"
            );
        }
        for effect in ALL_DISMOUNT_EFFECTS {
            assert!(
                ALL_EFFECTS.contains(&Effect::Dismount(effect)),
                "ALL_EFFECTS is missing Dismount({effect:?})"
            );
        }

        // …and nothing beyond the closed rosters and six nullary variants.
        let expected = ALL_WAIT_TARGETS
            .len()
            .saturating_add(ALL_ALLOC_TARGETS.len())
            .saturating_add(ALL_FENCE_EFFECTS.len())
            .saturating_add(ALL_MOUNT_EFFECTS.len())
            .saturating_add(ALL_MOUNT_ROLLBACK_EFFECTS.len())
            .saturating_add(ALL_DISMOUNT_EFFECTS.len())
            .saturating_add(6);
        assert_eq!(
            ALL_EFFECTS.len(),
            expected,
            "ALL_EFFECTS has {} entries; the closed rosters plus the six nullary variants account for {expected}",
            ALL_EFFECTS.len()
        );
        assert_eq!(ALL_CONTEXTS.len(), 2);
    }

    /// [`may_emit`] must agree with B1's rule on B1's domain, EXCEPT where a
    /// named sentence says otherwise. Every divergence is checked against the
    /// refinement list below; an unlisted one fails.
    ///
    /// This is what keeps the refinements from being decoration in the other
    /// direction too: the sweep asserts at least one divergence exists, so a
    /// `may_emit` that quietly reverted to B1's rule would fail here.
    #[test]
    fn diverges_from_b1_only_where_a_sentence_says_so() {
        use crate::lockrank::{held_sets_for_test, may_perform_legacy_shape};
        let mut divergences = 0usize;
        let mut cells = 0usize;
        for held in held_sets_for_test() {
            for effect in ALL_EFFECTS {
                for top_level in ALL_CONTEXTS {
                    cells = cells.saturating_add(1);
                    let ctx = ctx(held, top_level);
                    let refined = may_emit(&ctx, effect);
                    let legacy = may_perform_legacy_shape(held, effect);
                    if refined != legacy {
                        divergences = divergences.saturating_add(1);
                        assert!(
                            is_a_named_refinement(held, effect, top_level),
                            "unnamed divergence at {held:?} {effect:?} {top_level:?}: \
                             refined {refined:?} vs legacy {legacy:?}"
                        );
                    }
                }
            }
        }
        assert!(
            divergences > 0,
            "no refinement fired anywhere; they would be decoration"
        );
        println!("C1 SWEEP: {cells} cells, {divergences} named divergences");
    }

    /// The refinements, each named by its sentence or C4 resource rule.
    ///
    /// Deliberately written as independent predicates over the inputs, rather
    /// than by calling [`may_emit`]: a check written from the same source as
    /// the thing it checks is not a check.
    fn is_a_named_refinement(held: HeldLocks, effect: Effect, top: TopLevelContext) -> bool {
        // `07-cache-mm.md` §4.
        let sync_wait_under_sentinel =
            matches!(top, TopLevelContext::CacheSentinel) && is_wait(effect);
        // `07-cache-mm.md` §6.
        let alloc_under_sequencer =
            held.holds(LockRank::Sequencer) && matches!(effect, Effect::Allocate(_));
        // `06-locking.md` §2 corollary 2.
        let admission_under_size_gate = held.holds(LockRank::SizeGate)
            && matches!(
                effect,
                Effect::Wait(WaitTarget::AdmissionResource) | Effect::Allocate(_)
            );
        // `06-locking.md` §3.2.
        let drain_under_lifecycle_gate =
            held.holds(LockRank::PerOpenLifecycle) && is_rundown_wait(effect);
        // `06-locking.md` §7.1 and §7.2.
        let work_under_token = held.holds(LockRank::SoleConsumerToken)
            && (matches!(
                effect,
                Effect::Wait(_) | Effect::PrivilegeOrAccessCheck | Effect::NotificationCallback
            ) || is_wait(effect));
        let terminal_wait_under_guard =
            crate::effect::oracles::terminal_wait_verdict(held, effect).is_some();
        let wait_under_cq_role = held.holds(LockRank::CqConsumerToken) && is_wait(effect);
        sync_wait_under_sentinel
            || alloc_under_sequencer
            || admission_under_size_gate
            || drain_under_lifecycle_gate
            || work_under_token
            || terminal_wait_under_guard
            || wait_under_cq_role
    }

    #[test]
    fn r2_effects_match_the_independent_oracle() {
        for subset in 0..(1u32 << 9) {
            let held = HeldLocks::from_bits(subset << 15);
            let ctx = ctx(held, TopLevelContext::Ordinary);
            for effect in ALL_EFFECTS {
                let expected =
                    crate::effect::oracles::r2_effect_verdict(held, effect).map_or(Ok(()), Err);
                assert_eq!(
                    may_emit(&ctx, effect),
                    expected,
                    "R2 held={held:?} effect={effect:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_waits_are_refused_under_every_rundown_role_and_spin_guard() {
        let guards = [
            LockRank::MountRundown,
            LockRank::ControlRundown,
            LockRank::SessionAccessRundown,
            LockRank::SetupAdmissionRundown,
            LockRank::ControlContextAdmissionRundown,
            LockRank::SqWaitRole,
            LockRank::CqConsumerToken,
            LockRank::Sequencer,
            LockRank::AdvanceOnlyCsq,
            LockRank::NotifyCsq,
            LockRank::RegistrySpin,
            LockRank::CancelSpin,
            LockRank::VpbSpin,
        ];
        let waits = [
            Effect::Wait(WaitTarget::TerminalOutcomeEvent),
            Effect::Wait(WaitTarget::JoinerDrainedEvent),
            Effect::Wait(WaitTarget::PendingDpcExitEvent),
            Effect::Wait(WaitTarget::MountCompletionEvent),
            Effect::Wait(WaitTarget::MountWaitersDrainedEvent),
            Effect::Wait(WaitTarget::MountResetCompleteEvent),
            Effect::Wait(WaitTarget::MountResetWaitersDrainedEvent),
            Effect::SessionFence(FenceEffect::WaitProducerAndMappingCaptureRundown),
            Effect::SessionFence(FenceEffect::WaitPendingAndOwners),
            Effect::SessionFence(FenceEffect::WaitControlRundown),
        ];

        // Mutation caught: omit a guard or either wait family and its row is
        // admitted or falls through to a less-specific refusal.
        for guard in guards {
            let held = HeldLocks::none().acquire(guard);
            let ctx = ctx(held, TopLevelContext::Ordinary);
            for wait in waits {
                assert_eq!(
                    crate::effect::oracles::terminal_wait_verdict(held, wait),
                    Some(LockOrderError::LifecycleWaitUnderGuard),
                    "independent oracle omitted guard={guard:?} wait={wait:?}"
                );
                assert_eq!(
                    may_emit(&ctx, wait),
                    Err(LockOrderError::LifecycleWaitUnderGuard),
                    "guard={guard:?} wait={wait:?}"
                );
            }
        }
    }

    #[test]
    fn sq_wait_authority_and_cq_no_wait_authority_are_distinct() {
        let ordinary_wait = Effect::Wait(WaitTarget::BlockingResource);
        let terminal_wait = Effect::Wait(WaitTarget::TerminalOutcomeEvent);
        let sq = ctx(
            HeldLocks::none().acquire(LockRank::SqWaitRole),
            TopLevelContext::Ordinary,
        );
        assert_eq!(may_emit(&sq, ordinary_wait), Ok(()));
        assert_eq!(
            may_emit(&sq, terminal_wait),
            Err(LockOrderError::LifecycleWaitUnderGuard)
        );

        let cq = ctx(
            HeldLocks::none().acquire(LockRank::CqConsumerToken),
            TopLevelContext::Ordinary,
        );
        assert_eq!(
            may_emit(&cq, ordinary_wait),
            Err(LockOrderError::WaitUnderNoWaitRole)
        );
        assert_eq!(
            may_emit(&cq, terminal_wait),
            Err(LockOrderError::LifecycleWaitUnderGuard)
        );
    }

    /// `06-locking.md` §2 corollary 1, as its own case: the provider round trip
    /// under the size gate is DELIBERATELY legal. This exists so the corollary-2
    /// refinement cannot be implemented as a blanket ban on waiting.
    #[test]
    fn a_provider_round_trip_under_the_size_gate_is_legal() {
        let held = HeldLocks::none().acquire(LockRank::SizeGate);
        let ctx = ctx(held, TopLevelContext::Ordinary);
        assert_eq!(
            may_emit(&ctx, Effect::Wait(WaitTarget::ProviderRoundTrip)),
            Ok(()),
            "06 §2 corollary 1: blocking resources are released before provider \
             execution while the logical size gate and FCB rundown remain held"
        );
        assert_eq!(
            may_emit(&ctx, Effect::Wait(WaitTarget::AdmissionResource)),
            Err(LockOrderError::AdmissionUnderSizeGate),
            "06 §2 corollary 2 still applies to the same gate"
        );
    }

    /// `06-locking.md` §2 corollary 2, with the sentence in the message.
    #[test]
    fn no_admission_wait_or_allocation_under_the_size_gate() {
        let held = HeldLocks::none().acquire(LockRank::SizeGate);
        let ctx = ctx(held, TopLevelContext::Ordinary);
        for effect in [
            Effect::Wait(WaitTarget::AdmissionResource),
            Effect::Allocate(AllocTarget::Pool),
            Effect::Allocate(AllocTarget::ReqId),
            Effect::Allocate(AllocTarget::Grant),
            Effect::Allocate(AllocTarget::Digest),
            Effect::Allocate(AllocTarget::Sqe),
        ] {
            assert_eq!(
                may_emit(&ctx, effect),
                Err(LockOrderError::AdmissionUnderSizeGate),
                "06 §2 corollary 2: no size path waits for an application slot, \
                 ApplyReserve, allocation, grant, or other admission resource \
                 while it owns the logical gate — {effect:?}"
            );
        }
    }

    /// `07-cache-mm.md` §6.
    ///
    /// Asserts the **specific** error rather than merely `is_err`. That is the
    /// whole content of this test: the sequencer is a spin lock, so §1's leaf
    /// rule also rejects an allocation under it, and a test that only checked
    /// `is_err` would stay green with the §6 arm deleted or made unreachable.
    /// Measured on 2026-07-28: with the arm moved below the leaf rule, all 338
    /// tests passed. This one is the signal that measurement showed was
    /// missing.
    #[test]
    fn an_allocation_under_the_sequencer_names_07_section_6() {
        let held = HeldLocks::none().acquire(LockRank::Sequencer);
        let ctx = ctx(held, TopLevelContext::Ordinary);
        for target in [
            AllocTarget::Pool,
            AllocTarget::ReqId,
            AllocTarget::Grant,
            AllocTarget::Digest,
            AllocTarget::Sqe,
        ] {
            assert_eq!(
                may_emit(&ctx, Effect::Allocate(target)),
                Err(LockOrderError::AllocationUnderSequencer),
                "07 §6: the ledger never allocates while the sequencer lock is \
                 held, and that sentence — not §1's general leaf rule — is what \
                 this case must report"
            );
        }
        // The leaf rule still owns every OTHER effect under the sequencer, so
        // the §6 arm is narrow rather than a replacement.
        assert_eq!(
            may_emit(&ctx, Effect::CopyUserBuffer),
            Err(LockOrderError::ActionUnderLock)
        );
    }

    /// `07-cache-mm.md` §4, holding **nothing**.
    ///
    /// This is the case no held-set could ever express, which is why the
    /// top-level context is a dimension rather than another position.
    #[test]
    fn no_sync_wait_under_the_cache_sentinel_even_holding_nothing() {
        let ctx = unsafe { EffectContext::empty_under_cache_sentinel() };
        assert!(ctx.held().is_empty(), "the point is that nothing is held");
        for target in [
            WaitTarget::ProviderRoundTrip,
            WaitTarget::AdmissionResource,
            WaitTarget::Rundown,
            WaitTarget::BlockingResource,
        ] {
            assert_eq!(
                may_emit(&ctx, Effect::Wait(target)),
                Err(LockOrderError::SyncWaitUnderCacheSentinel),
                "07 §4: a second synchronous wait on that same thread, stacked \
                 under the first, is a self-deadlock, not merely slow"
            );
        }
        // …and the same context permits a non-wait effect, so the rule is about
        // waiting rather than about the context being poison.
        assert_eq!(may_emit(&ctx, Effect::CopyUserBuffer), Ok(()));
        assert_eq!(may_emit(&ctx, Effect::CompleteIrp), Ok(()));
    }

    /// `06-locking.md` §6 forbids completion under *"a ring token,
    /// domain/FCB/CCB lock, notification gate, or mount rundown"*.
    ///
    /// Before C1 the model represented **none** of those four classes, and
    /// `may_perform`'s own documentation said so rather than pretending
    /// otherwise. This test is the measurement that the vocabulary grew enough
    /// for the verdict to mean what its name says.
    #[test]
    fn the_completion_certificate_covers_section_sixs_four_classes() {
        let classes: &[(&str, &[LockRank])] = &[
            ("ring token", &[LockRank::SoleConsumerToken]),
            (
                "domain/FCB/CCB lock",
                &[
                    LockRank::DomainLock,
                    LockRank::FcbMain,
                    LockRank::FcbPaging,
                    LockRank::CcbLock,
                ],
            ),
            ("notification gate", &[LockRank::NotificationState]),
            ("mount rundown", &[LockRank::MountRundown]),
        ];
        for (name, positions) in classes {
            for &p in *positions {
                let ctx = ctx(HeldLocks::none().acquire(p), TopLevelContext::Ordinary);
                assert_eq!(
                    may_emit(&ctx, Effect::CompleteIrp),
                    Err(LockOrderError::CompletionUnderLock),
                    "06 §6 forbids IoCompleteRequest under {name}, and {p:?} is one"
                );
            }
        }
        // The sentence is quoted from the document, not paraphrased here.
        assert!(
            crate::effect::oracles::LOCK_DOC.contains(
                "There is no IoCompleteRequest under a ring token, domain/FCB/CCB lock, \
                 notification gate, or mount rundown."
            ),
            "06 §6's opening sentence has moved; this test's four classes are \
             transcribed from it"
        );
    }

    /// …and the certificate is not vacuous: with nothing held it is granted.
    #[test]
    fn completion_with_nothing_held_is_permitted() {
        assert_eq!(
            may_emit(&unsafe { EffectContext::empty() }, Effect::CompleteIrp),
            Ok(())
        );
    }

    /// Build a context asserting a held set the test itself chose.
    ///
    /// One place for the `unsafe`, and one place for its justification: a host
    /// test holds no kernel lock at all, so the held set is the test's own
    /// hypothesis about a call site — which is exactly what these tests exist to
    /// evaluate. No real resource is protected by it, so the assertion
    /// `assume_held` requires is vacuously discharged here in a way it never is
    /// in a driver.
    fn ctx(held: HeldLocks, top_level: TopLevelContext) -> EffectContext {
        // SAFETY: see the doc comment — no kernel lock exists in a host test,
        // so `held` describes exactly the (empty) set of real resources owned.
        unsafe { EffectContext::assume_held(held, top_level) }
    }

    /// A sink that records what reached it, so a refusal can be told apart from
    /// a forward.
    struct CountingSink(Vec<Effect>);

    // SAFETY: this test sink performs no kernel effect at all — it appends to a
    // `Vec`. `EffectSink`'s obligations about performing exactly the requested
    // effect against the caller's resources are vacuous for it.
    unsafe impl EffectSink for CountingSink {
        unsafe fn emit(&mut self, effect: Effect) {
            self.0.push(effect);
        }
    }

    fn seam() -> Seam<CountingSink> {
        recorder::reset();
        Seam::new(CountingSink(Vec::new()))
    }

    /// A refused effect must not reach the sink. This is the seam's entire
    /// reason to exist: `may_emit` alone is advice a caller may ignore.
    #[test]
    fn the_seam_refuses_without_reaching_the_sink() {
        let mut s = seam();
        let held = HeldLocks::none().acquire(LockRank::SizeGate);
        let ctx = ctx(held, TopLevelContext::Ordinary);

        assert_eq!(
            s.emit(&ctx, Effect::Allocate(AllocTarget::Grant)),
            Err(LockOrderError::AdmissionUnderSizeGate)
        );
        assert!(
            s.sink_for_test().0.is_empty(),
            "a refused effect must not reach the sink"
        );

        assert_eq!(
            s.emit(&ctx, Effect::Wait(WaitTarget::ProviderRoundTrip)),
            Ok(())
        );
        assert_eq!(s.sink_for_test().0.len(), 1);
    }

    /// A refused effect must not be recorded either: the log is the record of
    /// what the driver DID, and a refusal is something it did not do.
    #[test]
    fn a_refused_effect_is_not_recorded() {
        let mut s = seam();
        let ctx = ctx(
            HeldLocks::none().acquire(LockRank::Sequencer),
            TopLevelContext::Ordinary,
        );
        assert!(s.emit(&ctx, Effect::Allocate(AllocTarget::Pool)).is_err());
        assert!(recorder::entries().is_empty());
    }

    #[test]
    fn the_recorder_sees_issue_order() {
        let mut s = seam();
        let ctx = unsafe { EffectContext::empty() };
        assert_eq!(s.emit(&ctx, Effect::Allocate(AllocTarget::Pool)), Ok(()));
        assert_eq!(s.emit(&ctx, Effect::CopyUserBuffer), Ok(()));
        assert_eq!(s.emit(&ctx, Effect::CompleteIrp), Ok(()));

        recorder::assert_before(Effect::Allocate(AllocTarget::Pool), Effect::CompleteIrp);
        recorder::assert_count(Effect::CopyUserBuffer, 1);
        recorder::assert_none_between(
            |e| matches!(e, Effect::Free),
            Effect::Allocate(AllocTarget::Pool),
            Effect::CompleteIrp,
        );
    }

    /// A recorder that cannot report a violation is decoration. Each assertion
    /// gets a case that makes it fire.
    #[test]
    #[should_panic(expected = "to be absent between")]
    fn assert_none_between_reports_a_violation() {
        let mut s = seam();
        let ctx = unsafe { EffectContext::empty() };
        assert_eq!(s.emit(&ctx, Effect::Allocate(AllocTarget::Pool)), Ok(()));
        assert_eq!(s.emit(&ctx, Effect::Free), Ok(()));
        assert_eq!(s.emit(&ctx, Effect::CompleteIrp), Ok(()));
        recorder::assert_none_between(
            |e| matches!(e, Effect::Free),
            Effect::Allocate(AllocTarget::Pool),
            Effect::CompleteIrp,
        );
    }

    #[test]
    #[should_panic(expected = "before")]
    fn assert_before_reports_the_wrong_order() {
        let mut s = seam();
        let ctx = unsafe { EffectContext::empty() };
        assert_eq!(s.emit(&ctx, Effect::CompleteIrp), Ok(()));
        assert_eq!(s.emit(&ctx, Effect::CopyUserBuffer), Ok(()));
        recorder::assert_before(Effect::CopyUserBuffer, Effect::CompleteIrp);
    }

    #[test]
    #[should_panic(expected = "was never issued")]
    fn assert_before_reports_an_effect_that_never_happened() {
        let _s = seam();
        recorder::assert_before(Effect::CopyUserBuffer, Effect::CompleteIrp);
    }

    #[test]
    #[should_panic(expected = "saw")]
    fn assert_count_reports_the_wrong_count() {
        let mut s = seam();
        assert_eq!(
            s.emit(&unsafe { EffectContext::empty() }, Effect::Free),
            Ok(())
        );
        recorder::assert_count(Effect::Free, 2);
    }

    #[test]
    fn a_guard_releases_exactly_what_it_acquired() {
        let mut ctx = unsafe { EffectContext::empty() };
        {
            let Ok(g) = ctx.acquire(LockRank::SizeGate) else {
                panic!("acquiring from an empty context must be legal")
            };
            assert!(g.context().held().holds(LockRank::SizeGate));
        }
        assert!(
            !ctx.held().holds(LockRank::SizeGate),
            "the guard must release"
        );
    }

    /// `07-cache-mm.md` §10: *"acquire the FCB paging resource only if the
    /// calling thread does not already own it, and release only what they
    /// acquired, so a flush issued from a context that already holds the paging
    /// resource does not deadlock against itself."*
    #[test]
    fn a_conditional_guard_releases_only_what_it_acquired() {
        let mut ctx = unsafe { EffectContext::empty() };
        let Ok(mut outer) = ctx.acquire(LockRank::FcbPaging) else {
            panic!("acquiring from an empty context must be legal")
        };
        {
            let Ok(inner) = outer.acquire_if_unheld(LockRank::FcbPaging) else {
                panic!("a conditional acquisition of an already-held position cannot fail")
            };
            assert!(
                !inner.acquired_for_test(),
                "the thread already owns it, so the inner guard takes nothing"
            );
            assert!(inner.context().held().holds(LockRank::FcbPaging));
        }
        assert!(
            outer.context().held().holds(LockRank::FcbPaging),
            "07 §10: release only what they acquired — dropping the inner guard \
             must not release the outer one's position"
        );
        drop(outer);
        assert!(!ctx.held().holds(LockRank::FcbPaging));
    }

    /// …and when the position is NOT already held, the conditional guard is an
    /// ordinary acquisition that does release.
    #[test]
    fn a_conditional_guard_that_did_acquire_releases() {
        let mut ctx = unsafe { EffectContext::empty() };
        {
            let Ok(g) = ctx.acquire_if_unheld(LockRank::FcbPaging) else {
                panic!("legal from empty")
            };
            assert!(g.acquired_for_test());
        }
        assert!(!ctx.held().holds(LockRank::FcbPaging));
    }

    /// A conditional acquisition that would break the order is still an error,
    /// not a guard that silently took nothing.
    #[test]
    fn a_conditional_guard_still_refuses_an_illegal_acquisition() {
        let mut ctx = unsafe { EffectContext::empty() };
        let Ok(mut spin) = ctx.acquire(LockRank::Sequencer) else {
            panic!("legal from empty")
        };
        assert_eq!(
            spin.acquire_if_unheld(LockRank::SizeGate).err(),
            Some(LockOrderError::SpinLockNotLeaf),
            "§1: spin locks are leaves, and a conditional acquisition does not \
             exempt a path from that"
        );
    }

    /// An unconditional second acquisition remains a rule violation.
    #[test]
    fn an_unconditional_guard_rejects_a_second_acquisition() {
        let mut ctx = unsafe { EffectContext::empty() };
        let Ok(mut outer) = ctx.acquire(LockRank::FcbPaging) else {
            panic!("legal from empty")
        };
        assert_eq!(
            outer.acquire(LockRank::FcbPaging).err(),
            Some(LockOrderError::AlreadyHeld)
        );
    }

    /// The guard refuses an out-of-order acquisition, so a held position can
    /// never have been recorded without the checker agreeing to it.
    #[test]
    fn a_guard_cannot_record_an_illegal_hold() {
        let mut ctx = unsafe { EffectContext::empty() };
        let Ok(mut later) = ctx.acquire(LockRank::SizeGate) else {
            panic!("legal from empty")
        };
        assert_eq!(
            later.acquire(LockRank::LifecycleAdmission).err(),
            Some(LockOrderError::OutOfOrder)
        );
        assert!(
            !later.context().held().holds(LockRank::LifecycleAdmission),
            "a refused acquisition must not appear in the held set"
        );
    }

    /// The spin-lock guard is `Dispatch`'s producer; a gate guard is not.
    #[test]
    fn only_a_spin_lock_guard_mints_dispatch() {
        let mut ctx = unsafe { EffectContext::empty() };
        {
            let Ok(g) = ctx.acquire(LockRank::SizeGate) else {
                panic!("legal")
            };
            // SAFETY: no kernel lock is really held; this is a model guard and
            // the call is only being checked for which arm it takes.
            assert!(unsafe { g.dispatch_token() }.is_none());
        }
        let Ok(g) = ctx.acquire(LockRank::Sequencer) else {
            panic!("legal")
        };
        // SAFETY: as above — the token's IRQL contract is not being relied on,
        // only the kind dispatch is under test.
        assert!(unsafe { g.dispatch_token() }.is_some());
    }

    /// `06-locking.md` §3.2, and the boundary of what it supports.
    #[test]
    fn no_rundown_drain_under_the_per_open_lifecycle_gate() {
        let held = HeldLocks::none().acquire(LockRank::PerOpenLifecycle);
        let ctx = ctx(held, TopLevelContext::Ordinary);
        assert_eq!(
            may_emit(&ctx, Effect::Wait(WaitTarget::Rundown)),
            Err(LockOrderError::DrainUnderLifecycleGate),
            "06 §3.2: the lifecycle gate is released while any predecessor \
             waits; a retained count plus per-operation references, not a held \
             gate, detects the zero transition"
        );
        // The rule is narrow on purpose. §2's opening reads wider, but §2
        // corollary 1 keeps the SIZE gate held across a provider round trip, so
        // "every wait under every gate" is not what the document says. C1 does
        // not decide whether a provider round trip under the per-open gate is
        // legal, so it does not refuse one.
        assert_eq!(
            may_emit(&ctx, Effect::Wait(WaitTarget::ProviderRoundTrip)),
            Ok(()),
            "C1 does not decide this case, so it must not refuse it either"
        );
        assert_eq!(may_emit(&ctx, Effect::Allocate(AllocTarget::Pool)), Ok(()));
    }

    /// `06-locking.md` §7.1 and §7.2 — the sole-consumer token.
    ///
    /// Round 1 of C1's independent review found this **measurably wrong**: with
    /// only the token held, `may_emit` returned `Ok` for every wait, every
    /// allocation, the access check and the callback, and `may_acquire`
    /// returned `Ok` for `FcbMain`, `FcbPaging`, `DomainLock` and `SizeGate` —
    /// all named by §7.2 and §1 bullet 5. The token was a modelled position
    /// that carried no rule, which is worse than not modelling it: it made the
    /// §6 completion certificate look complete while the rest of §7 went
    /// unchecked.
    #[test]
    fn the_effects_and_locks_06_section_7_names_are_refused_under_the_token() {
        let held = HeldLocks::none().acquire(LockRank::SoleConsumerToken);
        let ctx = ctx(held, TopLevelContext::Ordinary);

        for effect in [
            Effect::Wait(WaitTarget::ProviderRoundTrip),
            Effect::Wait(WaitTarget::AdmissionResource),
            Effect::Wait(WaitTarget::Rundown),
            Effect::Wait(WaitTarget::BlockingResource),
            Effect::PrivilegeOrAccessCheck,
            Effect::NotificationCallback,
        ] {
            assert_eq!(
                may_emit(&ctx, effect),
                Err(LockOrderError::WorkUnderSoleConsumerToken),
                "06 §7.2: the token is never held while running an access check \
                 or notification callback, waiting for SQ, or completing an IRP \
                 — {effect:?}"
            );
        }

        // §7.1 and §7.2 enumerate FOUR lock classes, and the rule is that
        // enumeration. Round 2 found the first version refusing every rank,
        // which makes §7.1 step 4 unimplementable: the owner "retains all
        // tokens while it … [assigns each completion its] preallocated
        // semantic terminal owner **under the normal state gate**".
        for next in [
            LockRank::FcbMain,
            LockRank::FcbPaging,
            LockRank::CcbLock,
            LockRank::DomainLock,
        ] {
            assert_eq!(
                crate::lockrank::may_acquire(held, next),
                Err(LockOrderError::AcquisitionUnderSoleConsumerToken),
                "06 §7.1: no domain/FCB/CCB/namespace lock runs while a token \
                 is held — {next:?}"
            );
        }
        // …and the state gate §7.1 step 4 requires is NOT refused.
        assert_eq!(
            crate::lockrank::may_acquire(held, LockRank::OperationState),
            Ok(()),
            "§7.1 step 4 installs the terminal owner under the normal state \
             gate while every token is retained; refusing it forbids the \
             document's own sequence"
        );

        // Completion under the token was already refused by §6's rule, and
        // still is — by that rule, not this one.
        assert_eq!(
            may_emit(&ctx, Effect::CompleteIrp),
            Err(LockOrderError::CompletionUnderLock)
        );

        // **The boundary, asserted rather than described.** §7.1's list ends
        // with "or blocking action", and whether an allocation, a free, a
        // user-buffer copy or a provider call is one is not settled by that
        // sentence: a nonpaged allocation does not block, and §7.2's
        // enumeration names none of them. C1 does not decide it, so it does not
        // refuse them — and this asserts the non-decision so a later widening
        // cannot happen silently. Round 2 filed the gap between this and the
        // rule's former name, which promised "nothing blocking".
        for permitted in [
            Effect::Allocate(AllocTarget::Pool),
            Effect::Free,
            Effect::CopyUserBuffer,
            Effect::CallProvider,
        ] {
            assert_eq!(
                may_emit(&ctx, permitted),
                Ok(()),
                "C1 does not decide whether {permitted:?} is a §7.1 \"blocking \
                 action\", so it must not refuse it either"
            );
        }
    }

    /// A context cannot be duplicated, so a stale one cannot be presented.
    ///
    /// **Review round 3 exhibited this defect with a running test.** While
    /// `EffectContext` was `Copy`, safe code could copy a context, acquire the
    /// sequencer through a guard, and hand the *stale* copy to the seam — which
    /// approved `CompleteIrp` and `Allocate(Pool)` while the spin lock was
    /// still held, with no `unsafe` anywhere. The same trick carried a guard's
    /// context past the guard's death, keeping a released position "held".
    ///
    /// That defeated the whole point of making the constructors `unsafe` in
    /// round 2: a caller never had to forge a context, only to keep an old one.
    ///
    /// The type is move-only now, and the compile-fail fixture
    /// `stale_effect_context` is the structural proof. This test states the
    /// runtime half: the guard's context is a **borrow**, so it cannot outlive
    /// the guard and there is no second value to go stale.
    #[test]
    fn a_context_is_a_claim_about_now() {
        let mut ctx = ctx(HeldLocks::none(), TopLevelContext::Ordinary);
        {
            let Ok(g) = ctx.acquire(LockRank::Sequencer) else {
                panic!("legal from empty")
            };
            // The guard's view is borrowed, and it refuses what §6 forbids.
            assert_eq!(
                may_emit(g.context(), Effect::CompleteIrp),
                Err(LockOrderError::CompletionUnderLock)
            );
            assert!(g.context().held().holds(LockRank::Sequencer));
        }
        // After release the one context is truthful again. There is no second
        // copy anywhere that still says `Sequencer`.
        assert!(!ctx.held().holds(LockRank::Sequencer));
        assert_eq!(may_emit(&ctx, Effect::CompleteIrp), Ok(()));
    }

    /// The clearance is refused exactly where §6 forbids completion.
    ///
    /// This is C1's rule reaching B5's real completion path for the first time.
    /// C1 modelled §6 and left `CompletionOwner::complete` unchecked; the
    /// clearance makes the checker's verdict a precondition the compiler
    /// enforces, and this test shows the verdict is the one §6 states.
    #[test]
    fn a_clearance_is_refused_under_every_class_section_six_names() {
        let mut s = seam();
        // **Every modelled position, not a hand-picked list.** Rev 2 enumerated
        // six of the then-fifteen -- §6's opening sentence, transcribed -- and round
        // 2 showed a clearance could then be minted under `FcbPaging`,
        // `Sequencer`, `SizeGate` and four others with the whole battery green.
        // `may_emit` refuses `CompleteIrp` under ANY held position, so the test
        // must be driven by `ALL_RANKS`, which grows when the model grows.
        assert_eq!(
            crate::lockrank::ALL_RANKS.len(),
            26,
            "ALL_RANKS changed size; this sweep is only exhaustive if it is driven by the whole set"
        );
        for position in crate::lockrank::ALL_RANKS {
            let held = ctx(
                HeldLocks::none().acquire(position),
                TopLevelContext::Ordinary,
            );
            assert_eq!(
                s.clear_completion(&held).err(),
                Some(LockOrderError::CompletionUnderLock),
                "06 §6 forbids IoCompleteRequest under any held lock, including \
                 {position:?}, so no clearance may be minted there"
            );
        }
        // §6's opening sentence names four classes by hand. They must be among
        // the modelled positions, or the sweep above is exhaustive over a model
        // that lost the sentence it implements.
        for named in [
            LockRank::SoleConsumerToken,
            LockRank::DomainLock,
            LockRank::FcbMain,
            LockRank::FcbPaging,
            LockRank::CcbLock,
            LockRank::NotificationState,
            LockRank::MountRundown,
        ] {
            assert!(
                crate::lockrank::ALL_RANKS.contains(&named),
                "{named:?} is named by 06 §6 but is no longer a modelled position"
            );
        }
        // …and with nothing held it is granted, or the rule would forbid every
        // completion and the driver could never finish an IRP.
        let empty = ctx(HeldLocks::none(), TopLevelContext::Ordinary);
        assert!(s.clear_completion(&empty).is_ok());
    }

    /// A granted clearance is recorded, so the completion is observable in
    /// issue order like every other effect.
    #[test]
    fn a_granted_clearance_is_recorded() {
        let mut s = seam();
        let empty = ctx(HeldLocks::none(), TopLevelContext::Ordinary);
        assert!(s.clear_completion(&empty).is_ok());
        recorder::assert_count(Effect::CompleteIrp, 1);
    }

    /// `ALL_EFFECTS` must contain no duplicates: the exhaustive sweeps built on
    /// it would silently cover less than they report.
    #[test]
    fn all_effects_has_no_duplicates() {
        for (i, a) in ALL_EFFECTS.iter().enumerate() {
            for b in ALL_EFFECTS.iter().skip(i.saturating_add(1)) {
                assert_ne!(a, b, "{a:?} appears twice in ALL_EFFECTS");
            }
        }
    }
}
