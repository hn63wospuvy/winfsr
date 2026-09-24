//! WDK-free mount, verify, and dismount choreography.
//!
//! `05-irp-dispatch.md` section 6 and `10-lifecycle.md` section 8 own the mount
//! transaction itself; [`crate::volume`] states it as an affine capability
//! chain. This module is the *bridge* the native adapter drives: it adds the
//! two post-commit evidence effects, keeps verify and dismount as their own
//! progressions instead of folding them into the mount transaction, and turns a
//! failed destructive dismount step into a continuation that can only go
//! forward.
//!
//! It converts no native pointer into model state, and it re-decides nothing
//! [`crate::volume`] already decided.

use fsring_abi::validate::SessionIdentity;

use super::AdapterPlanError;
use crate::volume::{
    DismountEffect, DismountPlan, MountEffect, MountEffectOutcome, MountProgress,
    MountRevalidation, MountRollback, PendingClearDeviceInitializing, PendingOrdinaryMountEffect,
    PendingPublishMountOwner, PreparedMountEffect, PublishedMount, VerifyDecision, VolumeState,
    decide_verify, plan_dismount,
};

/// Own one resolved access guard for an entire mount transaction.
///
/// There is no `into_inner` or early-release method: commit and rollback code
/// may borrow the guard, but only dropping the transaction owner drops it.
pub struct RetainedAccessGuard<G> {
    guard: G,
}

impl<G> RetainedAccessGuard<G> {
    pub const fn new(guard: G) -> Self {
        Self { guard }
    }

    /// Run the complete native mount drive while this guard remains owned.
    ///
    /// The closure receives only a shared borrow and returns no borrow, so the
    /// guard cannot be extracted or released before either suffix finishes.
    pub fn run(self, operation: impl FnOnce(&G)) {
        operation(&self.guard);
    }
}

#[cfg(test)]
mod tests;

/// One native operation in a volume transition.
///
/// The two evidence effects are separate variants, so an event cannot be
/// emitted from anywhere but its own committed state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeEffect {
    Mount(MountEffect),
    /// Install the complete mount owner under the permanent registry lock.
    PublishMountOwner,
    EmitMountPublished,
    ReadVerifyUnderVpbLock,
    EmitVerifySucceeded,
    Dismount(DismountEffect),
}

/// The two facts a verify reads while the VPB spin lock is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyObservation {
    pub state: VolumeState,
    pub identity_matches: bool,
}

/// The closed outcome vocabulary a native executor may report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeEffectOutcome {
    Done,
    MountRevalidated(MountRevalidation),
    VerifyObserved(VerifyObservation),
}

/// The closed native operation surface for the R3 mount transaction.
///
/// Production and recording fakes both implement this trait. The exhaustive
/// effect-to-method mapping stays here, so a native adapter cannot collapse a
/// required operation into a generic successful effect callback.
pub trait R3VolumeNativeOps {
    fn acquire_vpb(&mut self) -> Option<VolumeEffectOutcome>;
    fn validate_target(&mut self) -> Option<VolumeEffectOutcome>;
    fn release_vpb(&mut self) -> Option<VolumeEffectOutcome>;
    fn acquire_session_reference(&mut self) -> Option<VolumeEffectOutcome>;
    fn create_mounted_device(&mut self) -> Option<VolumeEffectOutcome>;
    fn allocate_vcb(&mut self) -> Option<VolumeEffectOutcome>;
    fn initialize_device_and_vcb(&mut self) -> Option<VolumeEffectOutcome>;
    fn revalidate_target_identity_admission_and_binding(&mut self) -> Option<VolumeEffectOutcome>;
    fn bind_vpb(&mut self) -> Option<VolumeEffectOutcome>;
    fn set_vpb_mounted(&mut self) -> Option<VolumeEffectOutcome>;
    fn publish_mount_owner(&mut self) -> Option<VolumeEffectOutcome>;
    /// Consume the already-published receipt into device exposure. This is the
    /// first infallible operation: it has no refusal or outcome channel.
    fn clear_device_initializing(&mut self);
    fn emit_mount_published(&mut self) -> Option<VolumeEffectOutcome>;
}

/// Why the production-used mount runner stopped.
pub enum R3MountRunFailure {
    /// The named native operation refused before reporting an outcome.
    Native(VolumeFailurePlan),
    /// The native operation completed, but its typed observation made the
    /// core transaction refuse with its exact unwind plan.
    Plan(VolumeFailurePlan),
    /// The executor reported an outcome outside the closed vocabulary.
    Invalid(AdapterPlanError),
}

/// Drive the complete production R3 mount through named native operations.
pub fn run_r3_mount(
    mut progress: VolumeProgress,
    native: &mut impl R3VolumeNativeOps,
) -> Result<PublishedMount, R3MountRunFailure> {
    loop {
        match progress {
            VolumeProgress::Mounted(published) => return Ok(published),
            VolumeProgress::Effect(pending) => {
                let outcome = match pending.effect() {
                    VolumeEffect::Mount(MountEffect::AcquireVpb) => native.acquire_vpb(),
                    VolumeEffect::Mount(MountEffect::ValidateTarget) => native.validate_target(),
                    VolumeEffect::Mount(MountEffect::ReleaseVpb) => native.release_vpb(),
                    VolumeEffect::Mount(MountEffect::AcquireSessionReference) => {
                        native.acquire_session_reference()
                    }
                    VolumeEffect::Mount(MountEffect::CreateMountedDevice) => {
                        native.create_mounted_device()
                    }
                    VolumeEffect::Mount(MountEffect::AllocateVcb) => native.allocate_vcb(),
                    VolumeEffect::Mount(MountEffect::InitializeDeviceAndVcb) => {
                        native.initialize_device_and_vcb()
                    }
                    VolumeEffect::Mount(
                        MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
                    ) => native.revalidate_target_identity_admission_and_binding(),
                    VolumeEffect::Mount(MountEffect::BindVpb) => native.bind_vpb(),
                    VolumeEffect::Mount(MountEffect::SetVpbMounted) => native.set_vpb_mounted(),
                    VolumeEffect::PublishMountOwner => native.publish_mount_owner(),
                    VolumeEffect::Mount(MountEffect::ClearDeviceInitializing) => {
                        native.clear_device_initializing();
                        Some(VolumeEffectOutcome::Done)
                    }
                    VolumeEffect::EmitMountPublished => native.emit_mount_published(),
                    VolumeEffect::Mount(MountEffect::PublishMountOwner)
                    | VolumeEffect::ReadVerifyUnderVpbLock
                    | VolumeEffect::EmitVerifySucceeded
                    | VolumeEffect::Dismount(_) => None,
                };
                let Some(outcome) = outcome else {
                    return Err(R3MountRunFailure::Native(pending.failed()));
                };
                progress = match pending.succeeded(outcome) {
                    Ok(next) => next,
                    Err(VolumeEffectFailure::Plan(plan)) => {
                        return Err(R3MountRunFailure::Plan(plan));
                    }
                    Err(VolumeEffectFailure::Invalid(error)) => {
                        return Err(R3MountRunFailure::Invalid(error));
                    }
                };
            }
            VolumeProgress::Verified(_) | VolumeProgress::Dismounted => {
                return Err(R3MountRunFailure::Invalid(
                    AdapterPlanError::InvalidTransition,
                ));
            }
        }
    }
}

/// Where a verify is in its two-step progression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyPhase {
    /// The single locked read has not happened yet.
    Read,
    /// The read committed; the decision is fixed and evidence may be owed.
    Emit(VerifyDecision),
}

/// The private state of one volume transition.
///
/// The three mount arms hold the prepared ordinary, owner-publication, and
/// terminal-clear capabilities separately. A `PendingMountEffect` exposes no
/// effect accessor at all, so preparing it is the only way to learn which
/// native action is owed, and preparation consumes it.
enum NativeVolumeState {
    Mount(PendingOrdinaryMountEffect),
    PublishMountOwner(PendingPublishMountOwner),
    ClearDeviceInitializing(PendingClearDeviceInitializing),
    EmitMount(PublishedMount),
    Verify {
        identity: SessionIdentity,
        phase: VerifyPhase,
    },
    Dismount {
        plan: DismountPlan,
        next: usize,
    },
}

pub struct NativeVolumePlan {
    state: NativeVolumeState,
}

/// A one-shot capability requesting exactly one native volume effect.
pub struct PendingVolumeEffect {
    plan: NativeVolumePlan,
    effect: VolumeEffect,
}

#[allow(clippy::large_enum_variant)]
pub enum VolumeProgress {
    Effect(PendingVolumeEffect),
    Mounted(PublishedMount),
    Verified(VerifyDecision),
    Dismounted,
}

/// A dismount that lost one destructive step and must finish the rest.
///
/// It carries the plan and the index *past* the step that failed, so a resumed
/// dismount can neither retry that step nor restart an earlier one.
pub struct DismountContinuation {
    plan: DismountPlan,
    next: usize,
}

impl DismountContinuation {
    /// The step index the resume will start from.
    pub const fn next_index(&self) -> usize {
        self.next
    }

    pub const fn identity(&self) -> SessionIdentity {
        self.plan.identity()
    }
}

#[allow(clippy::large_enum_variant)]
pub enum VolumeFailurePlan {
    Mount(MountRollback),
    Complete { status: i32, information: usize },
    ContinueDismount(DismountContinuation),
}

/// A completed native effect either violated the trusted adapter vocabulary or
/// was validly refused with the exact unwind plan produced by the core mount
/// transaction. The latter must never be collapsed into `InvalidTransition`:
/// its phase-specific effects are the only authority to mutate native state.
pub enum VolumeEffectFailure {
    Invalid(AdapterPlanError),
    Plan(VolumeFailurePlan),
}

impl core::fmt::Debug for VolumeEffectFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(error) => formatter.debug_tuple("Invalid").field(error).finish(),
            Self::Plan(_) => formatter.write_str("Plan(..)"),
        }
    }
}

impl NativeVolumePlan {
    /// Drive a mount transaction already begun by [`crate::volume::begin_mount`].
    pub fn mount(progress: MountProgress) -> VolumeProgress {
        match progress {
            MountProgress::Effect(pending) => {
                let state = match pending.prepare() {
                    PreparedMountEffect::Ordinary(ordinary) => NativeVolumeState::Mount(ordinary),
                    PreparedMountEffect::PublishMountOwner(publish) => {
                        NativeVolumeState::PublishMountOwner(publish)
                    }
                    PreparedMountEffect::ClearDeviceInitializing(clear) => {
                        NativeVolumeState::ClearDeviceInitializing(clear)
                    }
                };
                Self { state }.next()
            }
            MountProgress::Published(published) => Self {
                state: NativeVolumeState::EmitMount(published),
            }
            .next(),
        }
    }

    /// Begin a verify. The decision is computed only from the locked read.
    pub fn verify(identity: SessionIdentity) -> VolumeProgress {
        Self {
            state: NativeVolumeState::Verify {
                identity,
                phase: VerifyPhase::Read,
            },
        }
        .next()
    }

    /// Begin a dismount from the fence's own refinement plan.
    pub fn dismount(plan: DismountPlan) -> VolumeProgress {
        Self {
            state: NativeVolumeState::Dismount { plan, next: 0 },
        }
        .next()
    }

    /// Continue a dismount past a destructive step that failed.
    pub fn resume_dismount(continuation: DismountContinuation) -> VolumeProgress {
        let DismountContinuation { plan, next } = continuation;
        Self {
            state: NativeVolumeState::Dismount { plan, next },
        }
        .next()
    }

    /// Yield the next effect, or the terminal this transition reached.
    pub fn next(self) -> VolumeProgress {
        match self.state {
            NativeVolumeState::Mount(ordinary) => {
                let effect = ordinary.effect();
                VolumeProgress::Effect(PendingVolumeEffect {
                    plan: Self {
                        state: NativeVolumeState::Mount(ordinary),
                    },
                    effect: VolumeEffect::Mount(effect),
                })
            }
            NativeVolumeState::PublishMountOwner(publish) => {
                VolumeProgress::Effect(PendingVolumeEffect {
                    plan: Self {
                        state: NativeVolumeState::PublishMountOwner(publish),
                    },
                    effect: VolumeEffect::PublishMountOwner,
                })
            }
            NativeVolumeState::ClearDeviceInitializing(clear) => {
                let effect = clear.effect();
                VolumeProgress::Effect(PendingVolumeEffect {
                    plan: Self {
                        state: NativeVolumeState::ClearDeviceInitializing(clear),
                    },
                    effect: VolumeEffect::Mount(effect),
                })
            }
            NativeVolumeState::EmitMount(published) => {
                VolumeProgress::Effect(PendingVolumeEffect {
                    plan: Self {
                        state: NativeVolumeState::EmitMount(published),
                    },
                    effect: VolumeEffect::EmitMountPublished,
                })
            }
            NativeVolumeState::Verify { identity, phase } => match phase {
                VerifyPhase::Read => VolumeProgress::Effect(PendingVolumeEffect {
                    plan: Self {
                        state: NativeVolumeState::Verify { identity, phase },
                    },
                    effect: VolumeEffect::ReadVerifyUnderVpbLock,
                }),
                // Only a real committed success earns evidence; a dismounted or
                // mismatched verify has nothing to attest.
                VerifyPhase::Emit(VerifyDecision::Success) => {
                    VolumeProgress::Effect(PendingVolumeEffect {
                        plan: Self {
                            state: NativeVolumeState::Verify { identity, phase },
                        },
                        effect: VolumeEffect::EmitVerifySucceeded,
                    })
                }
                VerifyPhase::Emit(decision) => VolumeProgress::Verified(decision),
            },
            NativeVolumeState::Dismount { plan, next } => match plan.effects().get(next).copied() {
                Some(effect) => VolumeProgress::Effect(PendingVolumeEffect {
                    plan: Self {
                        state: NativeVolumeState::Dismount { plan, next },
                    },
                    effect: VolumeEffect::Dismount(effect),
                }),
                None => VolumeProgress::Dismounted,
            },
        }
    }
}

impl PendingVolumeEffect {
    pub const fn effect(&self) -> VolumeEffect {
        self.effect
    }

    /// Consume this capability after its native effect completed.
    pub fn succeeded(
        self,
        outcome: VolumeEffectOutcome,
    ) -> Result<VolumeProgress, VolumeEffectFailure> {
        let Self { plan, effect } = self;
        match (plan.state, effect) {
            (NativeVolumeState::Mount(ordinary), VolumeEffect::Mount(_)) => {
                let mount_outcome = match outcome {
                    VolumeEffectOutcome::Done => MountEffectOutcome::Done,
                    VolumeEffectOutcome::MountRevalidated(revalidation) => {
                        MountEffectOutcome::Revalidated(revalidation)
                    }
                    VolumeEffectOutcome::VerifyObserved(_) => {
                        return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                    }
                };
                match ordinary.succeeded(mount_outcome) {
                    Ok(progress) => Ok(NativeVolumePlan::mount(progress)),
                    Err(rollback) => Err(VolumeEffectFailure::Plan(VolumeFailurePlan::Mount(
                        rollback,
                    ))),
                }
            }
            (NativeVolumeState::PublishMountOwner(publish), VolumeEffect::PublishMountOwner) => {
                if !matches!(outcome, VolumeEffectOutcome::Done) {
                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                }
                Ok(NativeVolumePlan::mount(publish.published()))
            }
            (
                NativeVolumeState::ClearDeviceInitializing(clear),
                VolumeEffect::Mount(MountEffect::ClearDeviceInitializing),
            ) => {
                if !matches!(outcome, VolumeEffectOutcome::Done) {
                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                }
                Ok(NativeVolumePlan {
                    state: NativeVolumeState::EmitMount(clear.cleared()),
                }
                .next())
            }
            (NativeVolumeState::EmitMount(published), VolumeEffect::EmitMountPublished) => {
                if !matches!(outcome, VolumeEffectOutcome::Done) {
                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                }
                Ok(VolumeProgress::Mounted(published))
            }
            (
                NativeVolumeState::Verify {
                    identity,
                    phase: VerifyPhase::Read,
                },
                VolumeEffect::ReadVerifyUnderVpbLock,
            ) => {
                let VolumeEffectOutcome::VerifyObserved(observation) = outcome else {
                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                };
                let decision = decide_verify(observation.state, observation.identity_matches);
                Ok(NativeVolumePlan {
                    state: NativeVolumeState::Verify {
                        identity,
                        phase: VerifyPhase::Emit(decision),
                    },
                }
                .next())
            }
            (
                NativeVolumeState::Verify {
                    phase: VerifyPhase::Emit(decision),
                    ..
                },
                VolumeEffect::EmitVerifySucceeded,
            ) => {
                if !matches!(outcome, VolumeEffectOutcome::Done) {
                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                }
                Ok(VolumeProgress::Verified(decision))
            }
            (NativeVolumeState::Dismount { plan, next }, VolumeEffect::Dismount(_)) => {
                if !matches!(outcome, VolumeEffectOutcome::Done) {
                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));
                }
                Ok(NativeVolumePlan {
                    state: NativeVolumeState::Dismount {
                        plan,
                        next: next.saturating_add(1),
                    },
                }
                .next())
            }
            _ => Err(VolumeEffectFailure::Invalid(
                AdapterPlanError::InvalidTransition,
            )),
        }
    }

    /// Consume a failed native effect.
    pub fn failed(self) -> VolumeFailurePlan {
        let Self { plan, effect: _ } = self;
        match plan.state {
            NativeVolumeState::Mount(ordinary) => VolumeFailurePlan::Mount(ordinary.failed()),
            NativeVolumeState::PublishMountOwner(publish) => {
                VolumeFailurePlan::Mount(publish.failed())
            }
            // The clear is specified infallible and the mounted device is
            // exposed the moment it returns. There is no unwind that could
            // un-expose it, so an impossible failure report completes the
            // published mount instead of forging a rollback.
            NativeVolumeState::ClearDeviceInitializing(clear) => {
                let _ = clear;
                VolumeFailurePlan::Complete {
                    status: fsring_abi::control::status::SUCCESS,
                    information: 0,
                }
            }
            // The mount is already published; a failed evidence write is an
            // evidence fault, not a filesystem fault.
            NativeVolumeState::EmitMount(published) => {
                let _ = published;
                VolumeFailurePlan::Complete {
                    status: fsring_abi::control::status::SUCCESS,
                    information: 0,
                }
            }
            NativeVolumeState::Verify { phase, .. } => match phase {
                // The locked read never happened, so there is no decision.
                VerifyPhase::Read => VolumeFailurePlan::Complete {
                    status: fsring_abi::control::status::INVALID_DEVICE_STATE,
                    information: 0,
                },
                // The verify already committed; only its evidence failed.
                VerifyPhase::Emit(_) => VolumeFailurePlan::Complete {
                    status: fsring_abi::control::status::SUCCESS,
                    information: 0,
                },
            },
            // A destructive teardown step that failed is recorded and skipped;
            // the continuation cannot retry it and cannot go back.
            NativeVolumeState::Dismount { plan, next } => {
                VolumeFailurePlan::ContinueDismount(DismountContinuation {
                    plan,
                    next: next.saturating_add(1),
                })
            }
        }
    }
}

/// Turn a publication proof into the fence's teardown plan.
pub fn dismount_plan(volume: PublishedMount) -> DismountPlan {
    plan_dismount(volume)
}
