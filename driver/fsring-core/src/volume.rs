//! WDK-free volume-role dispatch, mount publication, verification, rollback,
//! and dismount planning.
//!
//! The values in this module are capabilities and immutable effect plans. They
//! do not touch a device object or VPB; the later native adapter performs each
//! requested action and returns the corresponding outcome.

use fsring_abi::validate::SessionIdentity;

#[cfg(test)]
mod tests;

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010_u32 as i32;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_CLEANUP: u8 = 0x12;
const IRP_MN_MOUNT_VOLUME: u32 = 0x01;
const IRP_MN_VERIFY_VOLUME: u32 = 0x02;
const IOCTL_STORAGE_CHECK_VERIFY: u32 = 0x002D_4800;
const IOCTL_STORAGE_CHECK_VERIFY2: u32 = 0x002D_0800;

/// The extension tag shared by the four driver device-object roles.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    ProviderControl = 1,
    FileSystemControl = 2,
    VirtualDisk = 3,
    MountedVolume = 4,
}

impl DeviceKind {
    /// Project a checked raw extension tag without integer-to-enum transmute.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::ProviderControl),
            2 => Some(Self::FileSystemControl),
            3 => Some(Self::VirtualDisk),
            4 => Some(Self::MountedVolume),
            _ => None,
        }
    }
}

/// The lifecycle state relevant to volume admission and verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeState {
    Staging,
    Active,
    Mounted,
    Teardown,
    Destroyed,
}

/// One native effect in the non-skippable successful mount sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountEffect {
    AcquireVpb,
    /// Authoritative native target/VPB validation while the initial VPB lock
    /// is held. The `begin_mount` boolean is only an unlocked routing preflight.
    ValidateTarget,
    AcquireSessionReference,
    ReleaseVpb,
    CreateMountedDevice,
    AllocateVcb,
    InitializeDeviceAndVcb,
    RevalidateTargetIdentityAdmissionAndBinding,
    BindVpb,
    SetVpbMounted,
    /// Install the complete mount owner after the commit VPB lock is released.
    /// This is the last fallible publication step.
    PublishMountOwner,
    ClearDeviceInitializing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Task 13's crate-private native adapter constructs later phases.
enum MountPhase {
    Ordinary(OrdinaryMountPhase),
    PublishMountOwner,
    ClearDeviceInitializing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Task 13's crate-private native adapter constructs later phases.
enum OrdinaryMountPhase {
    AcquireInitialVpb,
    ValidateTarget,
    ReleaseInitialVpb,
    AcquireSessionReference,
    CreateMountedDevice,
    AllocateVcb,
    InitializeDeviceAndVcb,
    AcquireCommitVpb,
    RevalidateTargetIdentityAdmissionAndBinding,
    BindVpb,
    SetVpbMounted,
    ReleaseCommitVpb,
}

#[allow(dead_code)] // Task 13's crate-private native adapter advances the transaction.
impl MountPhase {
    const fn effect(self) -> MountEffect {
        match self {
            Self::Ordinary(phase) => phase.effect(),
            Self::PublishMountOwner => MountEffect::PublishMountOwner,
            Self::ClearDeviceInitializing => MountEffect::ClearDeviceInitializing,
        }
    }
}

#[allow(dead_code)] // Task 13's crate-private native adapter advances the transaction.
impl OrdinaryMountPhase {
    const fn effect(self) -> MountEffect {
        match self {
            Self::AcquireInitialVpb | Self::AcquireCommitVpb => MountEffect::AcquireVpb,
            Self::ValidateTarget => MountEffect::ValidateTarget,
            Self::AcquireSessionReference => MountEffect::AcquireSessionReference,
            Self::ReleaseInitialVpb | Self::ReleaseCommitVpb => MountEffect::ReleaseVpb,
            Self::CreateMountedDevice => MountEffect::CreateMountedDevice,
            Self::AllocateVcb => MountEffect::AllocateVcb,
            Self::InitializeDeviceAndVcb => MountEffect::InitializeDeviceAndVcb,
            Self::RevalidateTargetIdentityAdmissionAndBinding => {
                MountEffect::RevalidateTargetIdentityAdmissionAndBinding
            }
            Self::BindVpb => MountEffect::BindVpb,
            Self::SetVpbMounted => MountEffect::SetVpbMounted,
        }
    }

    const fn next(self) -> MountPhase {
        match self {
            Self::AcquireInitialVpb => MountPhase::Ordinary(Self::ValidateTarget),
            Self::ValidateTarget => MountPhase::Ordinary(Self::ReleaseInitialVpb),
            Self::ReleaseInitialVpb => MountPhase::Ordinary(Self::AcquireSessionReference),
            Self::AcquireSessionReference => MountPhase::Ordinary(Self::CreateMountedDevice),
            Self::CreateMountedDevice => MountPhase::Ordinary(Self::AllocateVcb),
            Self::AllocateVcb => MountPhase::Ordinary(Self::InitializeDeviceAndVcb),
            Self::InitializeDeviceAndVcb => MountPhase::Ordinary(Self::AcquireCommitVpb),
            Self::AcquireCommitVpb => {
                MountPhase::Ordinary(Self::RevalidateTargetIdentityAdmissionAndBinding)
            }
            Self::RevalidateTargetIdentityAdmissionAndBinding => {
                MountPhase::Ordinary(Self::BindVpb)
            }
            Self::BindVpb => MountPhase::Ordinary(Self::SetVpbMounted),
            Self::SetVpbMounted => MountPhase::Ordinary(Self::ReleaseCommitVpb),
            Self::ReleaseCommitVpb => MountPhase::PublishMountOwner,
        }
    }
}

/// The affine transaction that owns all resources acquired by prior effects.
pub struct MountTransaction {
    identity: SessionIdentity,
    phase: MountPhase,
}

/// The only two observable states of a mount operation.
pub enum MountProgress {
    Effect(PendingMountEffect),
    Published(PublishedMount),
}

/// A one-shot capability requesting exactly one native mount effect.
///
/// Crate-external safe callers may receive this opaque capability, but cannot
/// inspect or advance it. Only the trusted in-crate native adapter may assert
/// that the requested action actually occurred:
///
/// ```compile_fail
/// use fsring_abi::{BootInstanceId, MountId};
/// use fsring_abi::validate::SessionIdentity;
/// use fsring_core::volume::{begin_mount, MountProgress, VolumeState};
///
/// let identity = SessionIdentity {
///     mount_id: MountId { lo: 1, hi: 2 },
///     boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
///     session_epoch: 5,
/// };
/// let Ok(MountProgress::Effect(pending)) =
///     begin_mount(VolumeState::Active, identity, true)
/// else {
///     panic!("fixture must create a pending effect")
/// };
/// let _ = pending.effect();
/// ```
///
/// ```compile_fail
/// use fsring_abi::{BootInstanceId, MountId};
/// use fsring_abi::validate::SessionIdentity;
/// use fsring_core::volume::{
///     begin_mount, MountEffectOutcome, MountProgress, VolumeState,
/// };
///
/// let identity = SessionIdentity {
///     mount_id: MountId { lo: 1, hi: 2 },
///     boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
///     session_epoch: 5,
/// };
/// let Ok(MountProgress::Effect(pending)) =
///     begin_mount(VolumeState::Active, identity, true)
/// else {
///     panic!("fixture must create a pending effect")
/// };
/// let _ = pending.succeeded(MountEffectOutcome::Done);
/// ```
#[allow(dead_code)] // Task 13's crate-private native adapter reads the pending effect.
pub struct PendingMountEffect {
    transaction: MountTransaction,
    effect: MountEffect,
}

/// Pre-DDI affine split used by the trusted Task 13 adapter.
#[allow(dead_code)] // Task 13's crate-private native adapter matches this request.
pub(crate) enum PreparedMountEffect {
    /// One of the first twelve effects, whose post-DDI acknowledgement carries
    /// the closed [`MountEffectOutcome`] vocabulary.
    Ordinary(PendingOrdinaryMountEffect),
    /// The last fallible step. Refusal retains the complete unpublished owner
    /// bundle; success transfers it and leaves only the terminal clear.
    PublishMountOwner(PendingPublishMountOwner),
    /// The fourteenth, infallible DDI. Its success path accepts no outcome and
    /// therefore cannot observe a post-publication mismatch.
    ClearDeviceInitializing(PendingClearDeviceInitializing),
}

/// Affine capability for one of the first twelve native effects.
pub(crate) struct PendingOrdinaryMountEffect {
    identity: SessionIdentity,
    phase: OrdinaryMountPhase,
    effect: MountEffect,
}

/// Affine capability for installing the complete mount owner.
pub(crate) struct PendingPublishMountOwner {
    identity: SessionIdentity,
}

/// Affine capability for the terminal infallible device-initializing clear.
pub(crate) struct PendingClearDeviceInitializing {
    identity: SessionIdentity,
}

/// Results read while the second VPB lock is held immediately before binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountRevalidation {
    pub target_identity_matches: bool,
    pub admission_open: bool,
    pub binding_unchanged: bool,
    pub session_active: bool,
}

/// The closed outcome vocabulary accepted by a pending mount effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountEffectOutcome {
    Done,
    Revalidated(MountRevalidation),
}

/// Proof that all fourteen publication effects completed successfully.
pub struct PublishedMount {
    identity: SessionIdentity,
}

impl PublishedMount {
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }
}

/// One native action in a conservative unpublished-mount unwind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountRollbackEffect {
    /// Atomically clear the unpublished VPB device/volume binding pointers and
    /// `VPB_MOUNTED` while holding the native VPB spin lock. If the failed
    /// phase no longer owns that lock, the native adapter must acquire, clear,
    /// and release it inside this abstract rollback effect.
    ClearUnpublishedVpbBinding,
    FreeVcb,
    DeleteMountedDevice,
    ReleaseSessionReference,
    ReleaseVpbIfHeld,
}

/// Native semantics carried by [`MountRollbackEffect::ClearUnpublishedVpbBinding`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnpublishedVpbClearSemantics {
    pub clears_binding_and_pointers: bool,
    pub clears_mounted_flag: bool,
    pub requires_vpb_lock: bool,
    pub acquire_release_if_unheld: bool,
}

impl MountRollbackEffect {
    /// Describe the compound VPB clear; non-VPB rollback effects return none.
    pub const fn vpb_clear_semantics(self) -> Option<UnpublishedVpbClearSemantics> {
        match self {
            Self::ClearUnpublishedVpbBinding => Some(UnpublishedVpbClearSemantics {
                clears_binding_and_pointers: true,
                clears_mounted_flag: true,
                requires_vpb_lock: true,
                acquire_release_if_unheld: true,
            }),
            Self::FreeVcb
            | Self::DeleteMountedDevice
            | Self::ReleaseSessionReference
            | Self::ReleaseVpbIfHeld => None,
        }
    }
}

/// A fixed reverse-acquisition unwind plan for one consumed mount capability.
pub struct MountRollback {
    identity: SessionIdentity,
    effects: &'static [MountRollbackEffect],
}

impl MountRollback {
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    pub const fn effects(&self) -> &'static [MountRollbackEffect] {
        self.effects
    }
}

/// A volume-role dispatch decision with exactly one native completion owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeDispatchDecision {
    Complete(i32),
    Mount,
    Verify,
}

impl VolumeDispatchDecision {
    /// Every completion and routed operation in this pure classifier carries
    /// zero `IoStatus.Information`; Task 13 owns storage-check output bytes.
    pub const fn information(self) -> usize {
        0
    }
}

/// The closed verify result; no variant can request `DO_VERIFY_VOLUME` or
/// fabricate `STATUS_VERIFY_REQUIRED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyDecision {
    Success,
    VolumeDismounted,
    InvalidTarget,
}

/// One native action refining the session fence's existing device teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DismountEffect {
    AcquireVpb,
    ClearVpbBinding,
    ReleaseVpb,
    DeleteMountedDevice,
    DeleteVdo,
    RemoveRegistryEntry,
    ReleaseSessionReference,
}

/// The immutable refinement of `FenceEffect::DismountAndDeleteDevices`.
pub struct DismountPlan {
    identity: SessionIdentity,
    effects: &'static [DismountEffect],
}

impl DismountPlan {
    pub const fn identity(&self) -> SessionIdentity {
        self.identity
    }

    pub const fn effects(&self) -> &'static [DismountEffect] {
        self.effects
    }
}

/// Refusal reasons exposed by the pure mount boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeError {
    InvalidState,
    IdentityMismatch,
    TargetMismatch,
    AdmissionClosed,
    VpbChanged,
    NativeFailure,
    IncompleteTransaction,
}

const fn valid_identity(identity: SessionIdentity) -> bool {
    identity.mount_id.lo != 0
        && identity.mount_id.hi != 0
        && (identity.boot_instance_id.lo != 0 || identity.boot_instance_id.hi != 0)
        && identity.session_epoch != 0
}

/// Begin an ACTIVE, identity-valid mount after non-VPB routing preflight.
///
/// `routing_target_matches` is derived only from dispatch routing identity. It
/// must not contain an unlocked read of VPB binding or flags. The subsequent
/// [`MountEffect::ValidateTarget`] is the authoritative native VPB read and is
/// bracketed by the initial Acquire/Release VPB pair.
pub fn begin_mount(
    state: VolumeState,
    identity: SessionIdentity,
    routing_target_matches: bool,
) -> Result<MountProgress, VolumeError> {
    if !matches!(state, VolumeState::Active) {
        return Err(VolumeError::InvalidState);
    }
    if !valid_identity(identity) {
        return Err(VolumeError::IdentityMismatch);
    }
    if !routing_target_matches {
        return Err(VolumeError::TargetMismatch);
    }
    let transaction = MountTransaction {
        identity,
        phase: MountPhase::Ordinary(OrdinaryMountPhase::AcquireInitialVpb),
    };
    Ok(MountProgress::Effect(PendingMountEffect {
        effect: transaction.phase.effect(),
        transaction,
    }))
}

impl MountTransaction {
    pub const SUCCESS_EFFECTS: [MountEffect; 14] = [
        MountEffect::AcquireVpb,
        MountEffect::ValidateTarget,
        MountEffect::ReleaseVpb,
        MountEffect::AcquireSessionReference,
        MountEffect::CreateMountedDevice,
        MountEffect::AllocateVcb,
        MountEffect::InitializeDeviceAndVcb,
        MountEffect::AcquireVpb,
        MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
        MountEffect::BindVpb,
        MountEffect::SetVpbMounted,
        MountEffect::ReleaseVpb,
        MountEffect::PublishMountOwner,
        MountEffect::ClearDeviceInitializing,
    ];
}

const ROLLBACK_NONE: &[MountRollbackEffect] = &[];
const ROLLBACK_INITIAL_VPB: &[MountRollbackEffect] = &[MountRollbackEffect::ReleaseVpbIfHeld];
const ROLLBACK_REFERENCE: &[MountRollbackEffect] = &[MountRollbackEffect::ReleaseSessionReference];
const ROLLBACK_DEVICE: &[MountRollbackEffect] = &[
    MountRollbackEffect::DeleteMountedDevice,
    MountRollbackEffect::ReleaseSessionReference,
];
const ROLLBACK_VCB: &[MountRollbackEffect] = &[
    MountRollbackEffect::FreeVcb,
    MountRollbackEffect::DeleteMountedDevice,
    MountRollbackEffect::ReleaseSessionReference,
];
const ROLLBACK_COMMIT_VPB: &[MountRollbackEffect] = &[
    MountRollbackEffect::ReleaseVpbIfHeld,
    MountRollbackEffect::FreeVcb,
    MountRollbackEffect::DeleteMountedDevice,
    MountRollbackEffect::ReleaseSessionReference,
];
const ROLLBACK_BOUND_VPB: &[MountRollbackEffect] = &[
    MountRollbackEffect::ClearUnpublishedVpbBinding,
    MountRollbackEffect::ReleaseVpbIfHeld,
    MountRollbackEffect::FreeVcb,
    MountRollbackEffect::DeleteMountedDevice,
    MountRollbackEffect::ReleaseSessionReference,
];
const ROLLBACK_BOUND_VPB_AFTER_RELEASE: &[MountRollbackEffect] = &[
    MountRollbackEffect::ClearUnpublishedVpbBinding,
    MountRollbackEffect::FreeVcb,
    MountRollbackEffect::DeleteMountedDevice,
    MountRollbackEffect::ReleaseSessionReference,
];

#[allow(dead_code)] // Task 13's crate-private native adapter is the production caller.
impl PendingMountEffect {
    /// Split the pending request before any DDI executes. The terminal clear
    /// gets a distinct capability with no outcome-bearing success method.
    pub(crate) fn prepare(self) -> PreparedMountEffect {
        match self.transaction.phase {
            MountPhase::Ordinary(phase) => {
                PreparedMountEffect::Ordinary(PendingOrdinaryMountEffect {
                    identity: self.transaction.identity,
                    phase,
                    effect: self.effect,
                })
            }
            MountPhase::PublishMountOwner => {
                PreparedMountEffect::PublishMountOwner(PendingPublishMountOwner {
                    identity: self.transaction.identity,
                })
            }
            MountPhase::ClearDeviceInitializing => {
                PreparedMountEffect::ClearDeviceInitializing(PendingClearDeviceInitializing {
                    identity: self.transaction.identity,
                })
            }
        }
    }
}

const fn pre_effect_rollback(phase: OrdinaryMountPhase) -> &'static [MountRollbackEffect] {
    match phase {
        // Nothing is owned before the first acquisition, and nothing is
        // owned again between releasing the initial VPB lock and taking the
        // session reference. That gap is the whole point of the reorder:
        // there is no state in which both locks are held, so no unwind ever
        // has to release a registry reference while holding a VPB lock.
        OrdinaryMountPhase::AcquireInitialVpb | OrdinaryMountPhase::AcquireSessionReference => {
            ROLLBACK_NONE
        }
        OrdinaryMountPhase::ValidateTarget | OrdinaryMountPhase::ReleaseInitialVpb => {
            ROLLBACK_INITIAL_VPB
        }
        OrdinaryMountPhase::CreateMountedDevice => ROLLBACK_REFERENCE,
        OrdinaryMountPhase::AllocateVcb => ROLLBACK_DEVICE,
        OrdinaryMountPhase::InitializeDeviceAndVcb | OrdinaryMountPhase::AcquireCommitVpb => {
            ROLLBACK_VCB
        }
        OrdinaryMountPhase::RevalidateTargetIdentityAdmissionAndBinding
        | OrdinaryMountPhase::BindVpb => ROLLBACK_COMMIT_VPB,
        OrdinaryMountPhase::SetVpbMounted | OrdinaryMountPhase::ReleaseCommitVpb => {
            ROLLBACK_BOUND_VPB
        }
    }
}

#[allow(dead_code)] // Task 13's crate-private native adapter is the production caller.
impl PendingOrdinaryMountEffect {
    pub(crate) const fn effect(&self) -> MountEffect {
        self.effect
    }

    /// Consume one of the first twelve capabilities after its requested native
    /// effect completed. Ordinary effects accept only `Done`; the second-lock
    /// revalidation accepts only a fully true `Revalidated`.
    pub(crate) fn succeeded(
        self,
        outcome: MountEffectOutcome,
    ) -> Result<MountProgress, MountRollback> {
        let accepted = match (self.effect, outcome) {
            (
                MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
                MountEffectOutcome::Revalidated(revalidation),
            ) => {
                revalidation.target_identity_matches
                    && revalidation.admission_open
                    && revalidation.binding_unchanged
                    && revalidation.session_active
            }
            (
                MountEffect::RevalidateTargetIdentityAdmissionAndBinding,
                MountEffectOutcome::Done,
            ) => false,
            (_, MountEffectOutcome::Done) => true,
            (_, MountEffectOutcome::Revalidated(_)) => false,
        };
        if !accepted {
            return Err(self.post_effect_rollback());
        }

        let next = self.phase.next();
        Ok(MountProgress::Effect(PendingMountEffect {
            transaction: MountTransaction {
                identity: self.identity,
                phase: next,
            },
            effect: next.effect(),
        }))
    }

    /// Consume a completed ordinary effect whose outcome was invalid.
    fn post_effect_rollback(self) -> MountRollback {
        let effects = match self.phase {
            OrdinaryMountPhase::AcquireInitialVpb | OrdinaryMountPhase::ValidateTarget => {
                ROLLBACK_INITIAL_VPB
            }
            // After the release the VPB lock is gone and no reference has
            // been taken; after the acquisition the reference is owned and
            // the VPB lock is not. Neither state holds both.
            OrdinaryMountPhase::ReleaseInitialVpb => ROLLBACK_NONE,
            OrdinaryMountPhase::AcquireSessionReference => ROLLBACK_REFERENCE,
            OrdinaryMountPhase::CreateMountedDevice => ROLLBACK_DEVICE,
            OrdinaryMountPhase::AllocateVcb | OrdinaryMountPhase::InitializeDeviceAndVcb => {
                ROLLBACK_VCB
            }
            OrdinaryMountPhase::AcquireCommitVpb
            | OrdinaryMountPhase::RevalidateTargetIdentityAdmissionAndBinding => {
                ROLLBACK_COMMIT_VPB
            }
            OrdinaryMountPhase::BindVpb | OrdinaryMountPhase::SetVpbMounted => ROLLBACK_BOUND_VPB,
            OrdinaryMountPhase::ReleaseCommitVpb => ROLLBACK_BOUND_VPB_AFTER_RELEASE,
        };
        MountRollback {
            identity: self.identity,
            effects,
        }
    }

    /// Consume a native failure before the requested effect changed ownership.
    pub(crate) fn failed(self) -> MountRollback {
        MountRollback {
            identity: self.identity,
            effects: pre_effect_rollback(self.phase),
        }
    }
}

#[allow(dead_code)] // Task 4's crate-private native adapter is the production caller.
impl PendingPublishMountOwner {
    pub(crate) const fn effect(&self) -> MountEffect {
        MountEffect::PublishMountOwner
    }

    /// Consume the exact successful owner installation and expose only the
    /// infallible device-initializing clear.
    pub(crate) fn published(self) -> MountProgress {
        MountProgress::Effect(PendingMountEffect {
            transaction: MountTransaction {
                identity: self.identity,
                phase: MountPhase::ClearDeviceInitializing,
            },
            effect: MountEffect::ClearDeviceInitializing,
        })
    }

    /// Refuse the last fallible step with the complete post-VPB-release unwind.
    pub(crate) const fn failed(self) -> MountRollback {
        MountRollback {
            identity: self.identity,
            effects: ROLLBACK_BOUND_VPB_AFTER_RELEASE,
        }
    }
}

#[allow(dead_code)] // Task 13's crate-private native adapter is the production caller.
impl PendingClearDeviceInitializing {
    pub(crate) const fn effect(&self) -> MountEffect {
        MountEffect::ClearDeviceInitializing
    }

    /// Consume the terminal capability after the infallible native clear.
    ///
    /// There is deliberately no outcome parameter and no rollback result: the
    /// mounted device is exposed once the DDI returns, so the only legal next
    /// state is a publication proof.
    pub(crate) fn cleared(self) -> PublishedMount {
        PublishedMount {
            identity: self.identity,
        }
    }
}

const DISMOUNT_EFFECTS: &[DismountEffect] = &[
    DismountEffect::AcquireVpb,
    DismountEffect::ClearVpbBinding,
    DismountEffect::ReleaseVpb,
    DismountEffect::DeleteMountedDevice,
    DismountEffect::DeleteVdo,
    DismountEffect::RemoveRegistryEntry,
    DismountEffect::ReleaseSessionReference,
];

/// The same teardown plan, for a fence that never saw the publication proof.
///
/// A session fence must dismount whatever is bound to it, including after a
/// crash-restart path where the proof lives in another thread's frame. The plan
/// is a fixed effect list either way, so nothing is weakened: what the proof
/// buys is the *mount* transition, not the teardown.
pub const fn dismount_plan_for(identity: SessionIdentity) -> DismountPlan {
    DismountPlan {
        identity,
        effects: DISMOUNT_EFFECTS,
    }
}

/// Consume a publication proof into the existing fence owner's teardown plan.
pub fn plan_dismount(volume: PublishedMount) -> DismountPlan {
    DismountPlan {
        identity: volume.identity,
        effects: DISMOUNT_EFFECTS,
    }
}

/// Decide verify with identity mismatch taking precedence over lifecycle state.
pub const fn decide_verify(state: VolumeState, identity_matches: bool) -> VerifyDecision {
    if !identity_matches {
        return VerifyDecision::InvalidTarget;
    }
    match state {
        VolumeState::Staging | VolumeState::Active => VerifyDecision::InvalidTarget,
        VolumeState::Mounted => VerifyDecision::Success,
        VolumeState::Teardown | VolumeState::Destroyed => VerifyDecision::VolumeDismounted,
    }
}

/// Classify the three volume roles. Provider-control requests deliberately fail
/// closed here: `controldev` remains their sole authorization and classifier.
pub const fn decide_volume_dispatch(
    kind: DeviceKind,
    major: u8,
    minor_or_ioctl: u32,
    root_open: bool,
) -> VolumeDispatchDecision {
    if matches!(kind, DeviceKind::ProviderControl) {
        return VolumeDispatchDecision::Complete(STATUS_INVALID_DEVICE_REQUEST);
    }

    if major == IRP_MJ_CREATE {
        return if root_open {
            VolumeDispatchDecision::Complete(STATUS_SUCCESS)
        } else {
            VolumeDispatchDecision::Complete(STATUS_INVALID_DEVICE_REQUEST)
        };
    }
    if major == IRP_MJ_CLEANUP || major == IRP_MJ_CLOSE {
        return VolumeDispatchDecision::Complete(STATUS_SUCCESS);
    }

    match kind {
        DeviceKind::FileSystemControl if major == IRP_MJ_FILE_SYSTEM_CONTROL => {
            match minor_or_ioctl {
                IRP_MN_MOUNT_VOLUME => VolumeDispatchDecision::Mount,
                IRP_MN_VERIFY_VOLUME => VolumeDispatchDecision::Verify,
                _ => VolumeDispatchDecision::Complete(STATUS_INVALID_DEVICE_REQUEST),
            }
        }
        DeviceKind::VirtualDisk
            if major == IRP_MJ_DEVICE_CONTROL
                && (minor_or_ioctl == IOCTL_STORAGE_CHECK_VERIFY
                    || minor_or_ioctl == IOCTL_STORAGE_CHECK_VERIFY2) =>
        {
            VolumeDispatchDecision::Complete(STATUS_SUCCESS)
        }
        DeviceKind::ProviderControl
        | DeviceKind::FileSystemControl
        | DeviceKind::VirtualDisk
        | DeviceKind::MountedVolume => {
            VolumeDispatchDecision::Complete(STATUS_INVALID_DEVICE_REQUEST)
        }
    }
}
