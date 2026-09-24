// TEST: fixtures use host allocation and unchecked arithmetic over small,
// bounded numbers; the production bridge above keeps the crate-wide lint
// denials.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]

use super::*;

use fsring_abi::{BootInstanceId, MountId, validate::SessionIdentity};

use crate::volume::{
    DeviceKind, MountRollbackEffect, MountTransaction, VolumeDispatchDecision, VolumeError,
    begin_mount, decide_volume_dispatch,
};

const IDENTITY: SessionIdentity = SessionIdentity {
    boot_instance_id: BootInstanceId { lo: 3, hi: 5 },
    mount_id: MountId { lo: 7, hi: 11 },
    session_epoch: 1,
};

const GOOD: MountRevalidation = MountRevalidation {
    target_identity_matches: true,
    admission_open: true,
    binding_unchanged: true,
    session_active: true,
};

fn start() -> VolumeProgress {
    NativeVolumePlan::mount(
        begin_mount(VolumeState::Active, IDENTITY, true).expect("a live target mounts"),
    )
}

/// The outcome each mount effect requires of its executor.
fn mount_outcome(effect: MountEffect) -> VolumeEffectOutcome {
    match effect {
        MountEffect::RevalidateTargetIdentityAdmissionAndBinding => {
            VolumeEffectOutcome::MountRevalidated(GOOD)
        }
        _ => VolumeEffectOutcome::Done,
    }
}

fn volume_outcome(effect: VolumeEffect) -> VolumeEffectOutcome {
    match effect {
        VolumeEffect::Mount(mount) => mount_outcome(mount),
        VolumeEffect::PublishMountOwner
        | VolumeEffect::EmitMountPublished
        | VolumeEffect::EmitVerifySucceeded
        | VolumeEffect::Dismount(_) => VolumeEffectOutcome::Done,
        VolumeEffect::ReadVerifyUnderVpbLock => {
            panic!("a mount trace cannot request a verify observation")
        }
    }
}

fn assert_invalid_failure(failure: Option<VolumeEffectFailure>, expected: AdapterPlanError) {
    let Some(VolumeEffectFailure::Invalid(actual)) = failure else {
        panic!("the trusted native vocabulary must be rejected as invalid");
    };
    assert_eq!(actual, expected);
}

fn assert_pre_bind_revalidation_rollback(failure: VolumeEffectFailure) {
    let VolumeEffectFailure::Plan(VolumeFailurePlan::Mount(rollback)) = failure else {
        panic!("revalidation refusal must preserve the core mount rollback");
    };
    assert_eq!(
        rollback.effects(),
        [
            MountRollbackEffect::ReleaseVpbIfHeld,
            MountRollbackEffect::FreeVcb,
            MountRollbackEffect::DeleteMountedDevice,
            MountRollbackEffect::ReleaseSessionReference,
        ],
        "pre-Bind refusal must not clear another mount's VPB binding",
    );
    assert!(
        !rollback
            .effects()
            .contains(&MountRollbackEffect::ClearUnpublishedVpbBinding),
    );
}

/// Drive a whole mount, recording every effect.
fn drive_mount(fail_at: Option<usize>) -> (Vec<VolumeEffect>, Result<(), VolumeFailurePlan>) {
    let mut recorded = Vec::new();
    let mut progress = start();
    loop {
        match progress {
            VolumeProgress::Mounted(_) => return (recorded, Ok(())),
            VolumeProgress::Effect(pending) => {
                let index = recorded.len();
                let effect = pending.effect();
                recorded.push(effect);
                if fail_at == Some(index) {
                    return (recorded, Err(pending.failed()));
                }
                let outcome = volume_outcome(effect);
                progress = pending.succeeded(outcome).expect("canonical outcome");
            }
            VolumeProgress::Verified(_) | VolumeProgress::Dismounted => {
                panic!("a mount reaches neither terminal")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordedNativeMountCall {
    AcquireVpb,
    ValidateTarget,
    ReleaseVpb,
    AcquireSessionReference,
    CreateMountedDevice,
    AllocateVcb,
    InitializeDeviceAndVcb,
    RevalidateTargetIdentityAdmissionAndBinding,
    BindVpb,
    SetVpbMounted,
    PublishMountOwner,
    ClearDeviceInitializing,
}

#[derive(Default)]
struct RecordingNativeMountOps {
    calls: Vec<RecordedNativeMountCall>,
    evidence_calls: usize,
    refuse_at: Option<usize>,
    vpb_held: bool,
    session_reference: bool,
    mounted_device: bool,
    vcb: bool,
    vpb_bound: bool,
    owner_published: bool,
    exposed: bool,
}

impl RecordingNativeMountOps {
    fn record(
        &mut self,
        call: RecordedNativeMountCall,
        outcome: VolumeEffectOutcome,
    ) -> Option<VolumeEffectOutcome> {
        let position = self.calls.len();
        self.calls.push(call);
        (self.refuse_at != Some(position)).then_some(outcome)
    }

    fn done(&mut self, call: RecordedNativeMountCall) -> Option<VolumeEffectOutcome> {
        self.record(call, VolumeEffectOutcome::Done)
    }
}

impl R3VolumeNativeOps for RecordingNativeMountOps {
    fn acquire_vpb(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::AcquireVpb)?;
        assert!(!self.vpb_held);
        self.vpb_held = true;
        Some(outcome)
    }

    fn validate_target(&mut self) -> Option<VolumeEffectOutcome> {
        assert!(self.vpb_held);
        self.done(RecordedNativeMountCall::ValidateTarget)
    }

    fn release_vpb(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::ReleaseVpb)?;
        assert!(self.vpb_held);
        self.vpb_held = false;
        Some(outcome)
    }

    fn acquire_session_reference(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::AcquireSessionReference)?;
        assert!(!self.vpb_held);
        self.session_reference = true;
        Some(outcome)
    }

    fn create_mounted_device(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::CreateMountedDevice)?;
        assert!(self.session_reference);
        self.mounted_device = true;
        Some(outcome)
    }

    fn allocate_vcb(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::AllocateVcb)?;
        assert!(self.mounted_device);
        self.vcb = true;
        Some(outcome)
    }

    fn initialize_device_and_vcb(&mut self) -> Option<VolumeEffectOutcome> {
        assert!(self.mounted_device && self.vcb);
        self.done(RecordedNativeMountCall::InitializeDeviceAndVcb)
    }

    fn revalidate_target_identity_admission_and_binding(&mut self) -> Option<VolumeEffectOutcome> {
        assert!(self.vpb_held && self.session_reference && self.vcb);
        self.record(
            RecordedNativeMountCall::RevalidateTargetIdentityAdmissionAndBinding,
            VolumeEffectOutcome::MountRevalidated(GOOD),
        )
    }

    fn bind_vpb(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::BindVpb)?;
        assert!(self.vpb_held && self.mounted_device && self.vcb);
        self.vpb_bound = true;
        Some(outcome)
    }

    fn set_vpb_mounted(&mut self) -> Option<VolumeEffectOutcome> {
        assert!(self.vpb_held && self.vpb_bound);
        self.done(RecordedNativeMountCall::SetVpbMounted)
    }

    fn publish_mount_owner(&mut self) -> Option<VolumeEffectOutcome> {
        let outcome = self.done(RecordedNativeMountCall::PublishMountOwner)?;
        assert!(!self.vpb_held && self.session_reference && self.vpb_bound);
        self.session_reference = false;
        self.mounted_device = false;
        self.vcb = false;
        self.owner_published = true;
        Some(outcome)
    }

    fn clear_device_initializing(&mut self) {
        self.calls
            .push(RecordedNativeMountCall::ClearDeviceInitializing);
        assert!(self.owner_published && !self.exposed);
        self.exposed = true;
    }

    fn emit_mount_published(&mut self) -> Option<VolumeEffectOutcome> {
        self.evidence_calls = self.evidence_calls.saturating_add(1);
        Some(VolumeEffectOutcome::Done)
    }
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

#[test]
fn native_mount_trace_calls_all_fourteen_operations_once_in_order() {
    let mut native = RecordingNativeMountOps::default();
    let result = run_r3_mount(start(), &mut native);
    assert!(result.is_ok(), "the canonical native mount succeeds");
    assert_eq!(
        native.calls,
        [
            RecordedNativeMountCall::AcquireVpb,
            RecordedNativeMountCall::ValidateTarget,
            RecordedNativeMountCall::ReleaseVpb,
            RecordedNativeMountCall::AcquireSessionReference,
            RecordedNativeMountCall::CreateMountedDevice,
            RecordedNativeMountCall::AllocateVcb,
            RecordedNativeMountCall::InitializeDeviceAndVcb,
            RecordedNativeMountCall::AcquireVpb,
            RecordedNativeMountCall::RevalidateTargetIdentityAdmissionAndBinding,
            RecordedNativeMountCall::BindVpb,
            RecordedNativeMountCall::SetVpbMounted,
            RecordedNativeMountCall::ReleaseVpb,
            RecordedNativeMountCall::PublishMountOwner,
            RecordedNativeMountCall::ClearDeviceInitializing,
        ],
    );
    assert_eq!(native.evidence_calls, 1);
    assert!(!native.vpb_held);
    assert!(!native.session_reference);
    assert!(!native.mounted_device);
    assert!(!native.vcb);
    assert!(native.vpb_bound);
    assert!(native.owner_published);
    assert!(native.exposed);
}

#[test]
fn native_mount_trace_publishes_owner_after_vpb_release_before_device_exposure() {
    let mut native = RecordingNativeMountOps::default();
    assert!(run_r3_mount(start(), &mut native).is_ok());

    let commit_release = native
        .calls
        .iter()
        .rposition(|call| *call == RecordedNativeMountCall::ReleaseVpb)
        .expect("the commit VPB lock is released");
    let publish = native
        .calls
        .iter()
        .position(|call| *call == RecordedNativeMountCall::PublishMountOwner)
        .expect("the complete owner is published");
    let expose = native
        .calls
        .iter()
        .position(|call| *call == RecordedNativeMountCall::ClearDeviceInitializing)
        .expect("the mounted device is exposed");

    assert_eq!(publish, commit_release.saturating_add(1));
    assert_eq!(expose, publish.saturating_add(1));
}

#[test]
fn native_mount_trace_stops_at_each_refused_operation_without_replay() {
    // Publication is the last fallible effect. Device exposure has no refusal
    // channel, so the fake cannot even request refusal at position thirteen.
    for position in 0..MountTransaction::SUCCESS_EFFECTS.len().saturating_sub(1) {
        let mut native = RecordingNativeMountOps {
            refuse_at: Some(position),
            ..RecordingNativeMountOps::default()
        };
        assert!(matches!(
            run_r3_mount(start(), &mut native),
            Err(R3MountRunFailure::Native(_))
        ));
        assert_eq!(
            native.calls.len(),
            position.saturating_add(1),
            "the runner stops at native refusal {position}",
        );
        assert_eq!(
            native.evidence_calls, 0,
            "no refusal can skip ahead to evidence",
        );
        assert!(!native.exposed, "refusal never exposes the device");
        assert!(!native.owner_published, "refusal never publishes an owner");
        assert_eq!(
            native.vpb_held,
            matches!(position, 1 | 2 | 8 | 9 | 10 | 11),
            "only a refusal inside a VPB lock leaves it in the rollback packet",
        );
        assert_eq!(
            native.session_reference,
            (4..=12).contains(&position),
            "the exact acquired reference remains available to rollback",
        );
        assert_eq!(
            native.mounted_device,
            (5..=12).contains(&position),
            "the exact created device remains available to rollback",
        );
        assert_eq!(
            native.vcb,
            (6..=12).contains(&position),
            "the exact allocated VCB remains available to rollback",
        );
        assert_eq!(
            native.vpb_bound,
            (10..=12).contains(&position),
            "only an accepted bind leaves an unpublished VPB binding to clear",
        );
    }
}

#[test]
fn a_mount_runs_the_fourteen_transaction_effects_then_its_evidence() {
    let (recorded, terminal) = drive_mount(None);
    assert!(terminal.is_ok());
    let mut expected: Vec<VolumeEffect> = MountTransaction::SUCCESS_EFFECTS
        .iter()
        .map(|effect| match effect {
            MountEffect::PublishMountOwner => VolumeEffect::PublishMountOwner,
            ordinary => VolumeEffect::Mount(*ordinary),
        })
        .collect();
    expected.push(VolumeEffect::EmitMountPublished);
    assert_eq!(
        recorded, expected,
        "the bridge adds exactly one post-commit evidence effect and reorders nothing",
    );
}

#[test]
fn publish_owner_refusal_is_last_mount_rollback_and_clear_cannot_rollback() {
    let (recorded, terminal) = drive_mount(None);
    assert!(terminal.is_ok(), "the ordinary mount trace must complete");

    let release = recorded
        .iter()
        .rposition(|effect| matches!(effect, VolumeEffect::Mount(MountEffect::ReleaseVpb)))
        .expect("the commit VPB lock is released");
    let clear = recorded
        .iter()
        .position(|effect| {
            matches!(
                effect,
                VolumeEffect::Mount(MountEffect::ClearDeviceInitializing)
            )
        })
        .expect("the mounted device is made visible");
    let publish = recorded
        .iter()
        .position(|effect| matches!(effect, VolumeEffect::PublishMountOwner));

    let publish_refusal = publish.and_then(|index| {
        let (_attempted, terminal) = drive_mount(Some(index));
        match terminal {
            Err(VolumeFailurePlan::Mount(rollback)) => Some(rollback.effects().to_vec()),
            Ok(())
            | Err(VolumeFailurePlan::Complete { .. })
            | Err(VolumeFailurePlan::ContinueDismount(_)) => None,
        }
    });
    let expected_refusal = [
        MountRollbackEffect::ClearUnpublishedVpbBinding,
        MountRollbackEffect::FreeVcb,
        MountRollbackEffect::DeleteMountedDevice,
        MountRollbackEffect::ReleaseSessionReference,
    ];

    let (_attempted, clear_failure) = drive_mount(Some(clear));
    let clear_is_success_only = matches!(
        clear_failure,
        Err(VolumeFailurePlan::Complete {
            status: fsring_abi::control::status::SUCCESS,
            information: 0,
        })
    );

    assert_eq!(
        publish,
        Some(release.saturating_add(1)),
        "PublishMountOwner must be a dedicated adapter effect immediately after commit VPB release; trace: {recorded:?}",
    );
    assert_eq!(
        publish.map(|index| index.saturating_add(1)),
        Some(clear),
        "ClearDeviceInitializing must be the infallible successor of owner publication",
    );
    assert_eq!(
        publish_refusal.as_deref(),
        Some(expected_refusal.as_slice()),
        "publication refusal must retain the whole owner bundle and run exactly ROLLBACK_BOUND_VPB_AFTER_RELEASE",
    );
    assert!(
        clear_is_success_only,
        "once the owner is published, ClearDeviceInitializing must have no mount rollback edge",
    );
}

#[test]
fn the_evidence_effect_follows_the_device_becoming_visible() {
    let (recorded, _) = drive_mount(None);
    let clear = recorded
        .iter()
        .position(|effect| {
            matches!(
                effect,
                VolumeEffect::Mount(MountEffect::ClearDeviceInitializing)
            )
        })
        .expect("the terminal clear is in the roster");
    let emit = recorded
        .iter()
        .position(|effect| matches!(effect, VolumeEffect::EmitMountPublished))
        .expect("evidence is owed");
    assert!(
        clear < emit,
        "a mount is attested only once it is actually reachable",
    );
    assert_eq!(emit, recorded.len() - 1);
}

#[test]
fn the_second_lock_revalidation_accepts_only_four_true_fields() {
    let index = MountTransaction::SUCCESS_EFFECTS
        .iter()
        .position(|effect| {
            matches!(
                effect,
                MountEffect::RevalidateTargetIdentityAdmissionAndBinding
            )
        })
        .expect("the revalidation is in the roster");

    let falsified = [
        MountRevalidation {
            target_identity_matches: false,
            ..GOOD
        },
        MountRevalidation {
            admission_open: false,
            ..GOOD
        },
        MountRevalidation {
            binding_unchanged: false,
            ..GOOD
        },
        MountRevalidation {
            session_active: false,
            ..GOOD
        },
    ];
    for revalidation in falsified {
        let mut progress = start();
        for _ in 0..index {
            let VolumeProgress::Effect(pending) = progress else {
                panic!("the revalidation is reachable");
            };
            let outcome = volume_outcome(pending.effect());
            progress = pending.succeeded(outcome).expect("canonical");
        }
        let VolumeProgress::Effect(pending) = progress else {
            panic!("the revalidation effect");
        };
        assert_eq!(
            pending.effect(),
            VolumeEffect::Mount(MountEffect::RevalidateTargetIdentityAdmissionAndBinding),
        );
        let failure = match pending.succeeded(VolumeEffectOutcome::MountRevalidated(revalidation)) {
            Ok(_) => panic!("a falsified revalidation must not publish"),
            Err(failure) => failure,
        };
        assert_pre_bind_revalidation_rollback(failure);
    }
}

#[test]
fn rejected_pre_bind_revalidation_preserves_its_exact_rollback_plan() {
    let index = MountTransaction::SUCCESS_EFFECTS
        .iter()
        .position(|effect| {
            matches!(
                effect,
                MountEffect::RevalidateTargetIdentityAdmissionAndBinding
            )
        })
        .expect("the revalidation is in the roster");
    let mut progress = start();
    for _ in 0..index {
        let VolumeProgress::Effect(pending) = progress else {
            panic!("the revalidation is reachable");
        };
        let outcome = volume_outcome(pending.effect());
        progress = pending.succeeded(outcome).expect("canonical prefix");
    }
    let VolumeProgress::Effect(pending) = progress else {
        panic!("the revalidation effect");
    };
    let failure =
        match pending.succeeded(VolumeEffectOutcome::MountRevalidated(MountRevalidation {
            binding_unchanged: false,
            ..GOOD
        })) {
            Ok(_) => panic!("a foreign binding must refuse"),
            Err(failure) => failure,
        };
    assert_pre_bind_revalidation_rollback(failure);
}

#[test]
fn the_revalidation_refuses_a_bare_done() {
    let index = MountTransaction::SUCCESS_EFFECTS
        .iter()
        .position(|effect| {
            matches!(
                effect,
                MountEffect::RevalidateTargetIdentityAdmissionAndBinding
            )
        })
        .unwrap();
    let mut progress = start();
    for _ in 0..index {
        let VolumeProgress::Effect(pending) = progress else {
            panic!("reachable");
        };
        let outcome = volume_outcome(pending.effect());
        progress = pending.succeeded(outcome).expect("canonical");
    }
    let VolumeProgress::Effect(pending) = progress else {
        panic!("revalidation");
    };
    let failure = match pending.succeeded(VolumeEffectOutcome::Done) {
        Ok(_) => panic!("an unobserved revalidation cannot stand in for a real one"),
        Err(failure) => failure,
    };
    assert_pre_bind_revalidation_rollback(failure);
}

#[test]
fn the_terminal_clear_accepts_only_a_bare_done() {
    let index = MountTransaction::SUCCESS_EFFECTS
        .iter()
        .position(|effect| matches!(effect, MountEffect::ClearDeviceInitializing))
        .expect("the terminal clear is in the roster");
    let mut progress = start();
    for _ in 0..index {
        let VolumeProgress::Effect(pending) = progress else {
            panic!("reachable");
        };
        let outcome = volume_outcome(pending.effect());
        progress = pending.succeeded(outcome).expect("canonical");
    }
    let VolumeProgress::Effect(pending) = progress else {
        panic!("the terminal clear");
    };
    assert!(matches!(
        pending.effect(),
        VolumeEffect::Mount(MountEffect::ClearDeviceInitializing)
    ));
    assert_invalid_failure(
        pending
            .succeeded(VolumeEffectOutcome::MountRevalidated(GOOD))
            .err(),
        AdapterPlanError::InvalidInput,
    );
}

#[test]
fn a_verify_observation_is_never_a_mount_outcome() {
    let VolumeProgress::Effect(pending) = start() else {
        panic!("the first mount effect");
    };
    assert_invalid_failure(
        pending
            .succeeded(VolumeEffectOutcome::VerifyObserved(VerifyObservation {
                state: VolumeState::Mounted,
                identity_matches: true,
            }))
            .err(),
        AdapterPlanError::InvalidInput,
    );
}

#[test]
fn every_transaction_failure_yields_the_models_own_unwind() {
    for index in 0..MountTransaction::SUCCESS_EFFECTS.len() - 1 {
        let (_, terminal) = drive_mount(Some(index));
        let Err(VolumeFailurePlan::Mount(rollback)) = terminal else {
            panic!("failure at {index} must unwind the mount");
        };
        assert_eq!(rollback.identity(), IDENTITY);
        // The bridge never invents an unwind: the effects are exactly the
        // transaction's own, and nothing may be released twice.
        let mut seen = Vec::new();
        for effect in rollback.effects() {
            assert!(
                !seen.contains(effect),
                "failure at {index} releases {effect:?} twice",
            );
            seen.push(*effect);
        }
    }
}

#[test]
fn the_first_effect_owns_nothing_to_unwind() {
    let (_, terminal) = drive_mount(Some(0));
    let Err(VolumeFailurePlan::Mount(rollback)) = terminal else {
        panic!("unwind");
    };
    assert_eq!(
        rollback.effects(),
        &[] as &[MountRollbackEffect],
        "a failed VPB acquisition holds nothing",
    );
}

#[test]
fn an_exposed_mount_is_never_unwound_by_a_failed_evidence_write() {
    let emit = MountTransaction::SUCCESS_EFFECTS.len();
    let (recorded, terminal) = drive_mount(Some(emit));
    assert_eq!(recorded[emit], VolumeEffect::EmitMountPublished);
    let Err(VolumeFailurePlan::Complete {
        status,
        information,
    }) = terminal
    else {
        panic!("a published mount completes");
    };
    assert_eq!(status, fsring_abi::control::status::SUCCESS);
    assert_eq!(information, 0);
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

fn drive_verify(observation: VerifyObservation) -> (Vec<VolumeEffect>, VerifyDecision) {
    let mut recorded = Vec::new();
    let mut progress = NativeVolumePlan::verify(IDENTITY);
    loop {
        match progress {
            VolumeProgress::Verified(decision) => return (recorded, decision),
            VolumeProgress::Effect(pending) => {
                let effect = pending.effect();
                recorded.push(effect);
                let outcome = match effect {
                    VolumeEffect::ReadVerifyUnderVpbLock => {
                        VolumeEffectOutcome::VerifyObserved(observation)
                    }
                    _ => VolumeEffectOutcome::Done,
                };
                progress = pending.succeeded(outcome).expect("canonical outcome");
            }
            VolumeProgress::Mounted(_) | VolumeProgress::Dismounted => {
                panic!("a verify reaches neither terminal")
            }
        }
    }
}

#[test]
fn a_live_matching_mount_verifies_and_earns_evidence() {
    let (recorded, decision) = drive_verify(VerifyObservation {
        state: VolumeState::Mounted,
        identity_matches: true,
    });
    assert_eq!(decision, VerifyDecision::Success);
    assert_eq!(
        recorded,
        vec![
            VolumeEffect::ReadVerifyUnderVpbLock,
            VolumeEffect::EmitVerifySucceeded,
        ],
        "one locked read, then evidence",
    );
}

#[test]
fn only_a_committed_success_earns_verify_evidence() {
    for (state, identity_matches, expected) in [
        (
            VolumeState::Teardown,
            true,
            VerifyDecision::VolumeDismounted,
        ),
        (
            VolumeState::Destroyed,
            true,
            VerifyDecision::VolumeDismounted,
        ),
        (VolumeState::Active, true, VerifyDecision::InvalidTarget),
        (VolumeState::Staging, true, VerifyDecision::InvalidTarget),
        (VolumeState::Mounted, false, VerifyDecision::InvalidTarget),
    ] {
        let (recorded, decision) = drive_verify(VerifyObservation {
            state,
            identity_matches,
        });
        assert_eq!(decision, expected, "{state:?}/{identity_matches}");
        assert_eq!(
            recorded,
            vec![VolumeEffect::ReadVerifyUnderVpbLock],
            "{state:?}/{identity_matches} attests nothing",
        );
    }
}

#[test]
fn the_verify_decision_comes_only_from_the_locked_read() {
    let VolumeProgress::Effect(pending) = NativeVolumePlan::verify(IDENTITY) else {
        panic!("the locked read");
    };
    assert_invalid_failure(
        pending.succeeded(VolumeEffectOutcome::Done).err(),
        AdapterPlanError::InvalidInput,
    );
}

#[test]
fn a_failed_locked_read_decides_nothing() {
    let VolumeProgress::Effect(pending) = NativeVolumePlan::verify(IDENTITY) else {
        panic!("the locked read");
    };
    let VolumeFailurePlan::Complete { status, .. } = pending.failed() else {
        panic!("a verify has nothing to unwind");
    };
    assert_eq!(status, fsring_abi::control::status::INVALID_DEVICE_STATE);
}

// ---------------------------------------------------------------------------
// Dismount
// ---------------------------------------------------------------------------

fn published() -> PublishedMount {
    let (_, terminal) = drive_mount(None);
    assert!(terminal.is_ok());
    // Re-drive to the terminal so the proof itself can be taken.
    let mut progress = start();
    loop {
        match progress {
            VolumeProgress::Mounted(mount) => return mount,
            VolumeProgress::Effect(pending) => {
                let outcome = volume_outcome(pending.effect());
                progress = pending.succeeded(outcome).expect("canonical");
            }
            _ => panic!("a mount reaches its own terminal"),
        }
    }
}

fn drive_dismount(fail_at: Option<usize>) -> Vec<VolumeEffect> {
    let plan = dismount_plan(published());
    let mut recorded = Vec::new();
    let mut progress = NativeVolumePlan::dismount(plan);
    loop {
        match progress {
            VolumeProgress::Dismounted => return recorded,
            VolumeProgress::Effect(pending) => {
                let index = recorded.len();
                recorded.push(pending.effect());
                progress = if fail_at == Some(index) {
                    let VolumeFailurePlan::ContinueDismount(continuation) = pending.failed() else {
                        panic!("a dismount step failure continues");
                    };
                    NativeVolumePlan::resume_dismount(continuation)
                } else {
                    pending
                        .succeeded(VolumeEffectOutcome::Done)
                        .expect("canonical")
                };
            }
            _ => panic!("a dismount reaches only its own terminal"),
        }
    }
}

#[test]
fn no_post_commit_step_accepts_a_verify_observation() {
    let observed = || {
        VolumeEffectOutcome::VerifyObserved(VerifyObservation {
            state: VolumeState::Mounted,
            identity_matches: true,
        })
    };

    // The evidence effect that follows a published mount.
    let mut progress = start();
    let evidence = loop {
        let VolumeProgress::Effect(pending) = progress else {
            panic!("the evidence effect precedes the terminal");
        };
        if matches!(pending.effect(), VolumeEffect::EmitMountPublished) {
            break pending;
        }
        let outcome = volume_outcome(pending.effect());
        progress = pending.succeeded(outcome).expect("canonical");
    };
    assert_invalid_failure(
        evidence.succeeded(observed()).err(),
        AdapterPlanError::InvalidInput,
    );

    // The first destructive dismount step.
    let VolumeProgress::Effect(pending) = NativeVolumePlan::dismount(dismount_plan(published()))
    else {
        panic!("a dismount begins with an effect");
    };
    assert_invalid_failure(
        pending.succeeded(observed()).err(),
        AdapterPlanError::InvalidInput,
    );
}

#[test]
fn a_dismount_runs_its_plan_in_order() {
    let recorded = drive_dismount(None);
    let expected: Vec<VolumeEffect> = dismount_plan(published())
        .effects()
        .iter()
        .map(|effect| VolumeEffect::Dismount(*effect))
        .collect();
    assert_eq!(recorded, expected);
    assert!(
        recorded.iter().any(|effect| matches!(
            effect,
            VolumeEffect::Dismount(DismountEffect::ClearVpbBinding)
        )),
        "the VPB binding is cleared under the lock the plan brackets",
    );
}

#[test]
fn a_failed_destructive_step_is_skipped_and_never_retried() {
    let complete = drive_dismount(None);
    for index in 0..complete.len() {
        let recorded = drive_dismount(Some(index));
        assert_eq!(
            recorded, complete,
            "step {index} is attempted exactly once and the rest still run",
        );
    }
}

#[test]
fn a_continuation_can_only_move_forward() {
    let plan = dismount_plan(published());
    let VolumeProgress::Effect(pending) = NativeVolumePlan::dismount(plan) else {
        panic!("the first step");
    };
    let VolumeFailurePlan::ContinueDismount(continuation) = pending.failed() else {
        panic!("continue");
    };
    assert_eq!(continuation.next_index(), 1);
    assert_eq!(continuation.identity(), IDENTITY);
}

// ---------------------------------------------------------------------------
// Role projection
// ---------------------------------------------------------------------------

/// Every major the driver installs, plus one it does not.
const MAJORS: [u8; 6] = [
    0,  // IRP_MJ_CREATE
    2,  // IRP_MJ_CLOSE
    3,  // IRP_MJ_READ
    14, // IRP_MJ_DEVICE_CONTROL
    18, // IRP_MJ_CLEANUP
    13, // IRP_MJ_FILE_SYSTEM_CONTROL
];

#[test]
fn no_role_ever_answers_for_another() {
    const MOUNT_MINOR: u32 = 1;
    const VERIFY_MINOR: u32 = 2;
    const CHECK_VERIFY: u32 = 0x0000_2D4800;
    for kind in [
        DeviceKind::ProviderControl,
        DeviceKind::FileSystemControl,
        DeviceKind::VirtualDisk,
        DeviceKind::MountedVolume,
    ] {
        for major in MAJORS {
            for minor in [0u32, MOUNT_MINOR, VERIFY_MINOR, CHECK_VERIFY] {
                for root_open in [true, false] {
                    let decision = decide_volume_dispatch(kind, major, minor, root_open);
                    if matches!(kind, DeviceKind::ProviderControl) {
                        assert!(
                            matches!(decision, VolumeDispatchDecision::Complete(_)),
                            "the provider endpoint is never routed by the volume classifier",
                        );
                    }
                    if matches!(decision, VolumeDispatchDecision::Mount)
                        || matches!(decision, VolumeDispatchDecision::Verify)
                    {
                        assert_eq!(
                            kind,
                            DeviceKind::FileSystemControl,
                            "only the filesystem-control role mounts or verifies",
                        );
                        assert_eq!(major, 13);
                    }
                    assert_eq!(decision.information(), 0);
                }
            }
        }
    }
}

#[test]
fn a_named_create_is_refused_on_every_role() {
    for kind in [
        DeviceKind::FileSystemControl,
        DeviceKind::VirtualDisk,
        DeviceKind::MountedVolume,
    ] {
        assert!(
            matches!(
                decide_volume_dispatch(kind, 0, 0, false),
                VolumeDispatchDecision::Complete(status) if status != 0
            ),
            "{kind:?} admits only a root open",
        );
    }
}

#[test]
fn a_wrong_state_target_never_begins_a_mount() {
    for state in [
        VolumeState::Staging,
        VolumeState::Mounted,
        VolumeState::Teardown,
        VolumeState::Destroyed,
    ] {
        assert_eq!(
            begin_mount(state, IDENTITY, true).err(),
            Some(VolumeError::InvalidState),
            "{state:?} is not mountable",
        );
    }
    assert_eq!(
        begin_mount(VolumeState::Active, IDENTITY, false).err(),
        Some(VolumeError::TargetMismatch),
    );
}

#[test]
fn mount_retains_access_guard_through_commit_or_rollback() {
    use std::{cell::RefCell, rc::Rc};

    struct Guard(Rc<RefCell<Vec<String>>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.borrow_mut().push("guard-drop".into());
        }
    }

    for fail_at in [None, Some(5)] {
        let events = Rc::new(RefCell::new(Vec::new()));
        RetainedAccessGuard::new(Guard(Rc::clone(&events))).run(|guard| {
            let (effects, terminal) = drive_mount(fail_at);
            guard
                .0
                .borrow_mut()
                .extend(effects.iter().map(|effect| format!("effect:{effect:?}")));
            match terminal {
                Ok(()) => guard.0.borrow_mut().push("commit-suffix".into()),
                Err(VolumeFailurePlan::Mount(rollback)) => {
                    guard.0.borrow_mut().extend(
                        rollback
                            .effects()
                            .iter()
                            .map(|effect| format!("rollback:{effect:?}")),
                    );
                    guard.0.borrow_mut().push("rollback-suffix".into());
                }
                Err(_) => panic!("the selected failure belongs to the mount transaction"),
            }
            assert_ne!(
                guard.0.borrow().last().map(String::as_str),
                Some("guard-drop")
            );
        });
        let recorded = events.borrow();
        let suffix = if fail_at.is_some() {
            "rollback-suffix"
        } else {
            "commit-suffix"
        };
        assert_eq!(recorded[recorded.len() - 2], suffix);
        assert_eq!(recorded.last().map(String::as_str), Some("guard-drop"));
    }
}
