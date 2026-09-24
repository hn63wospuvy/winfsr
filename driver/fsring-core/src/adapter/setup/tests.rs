// TEST: fixtures use host allocation and unchecked arithmetic over small,
// bounded topology numbers; the production plan above keeps the crate-wide lint
// denials and does every step with checked arithmetic.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]

use super::*;

use fsring_abi::{
    BootInstanceId, FeatureSet, MIN_CONTROL_SLOT_SIZE, MIN_K2U_PROGRESS_SLOTS_PER_RING,
    MIN_NOTIFICATION_CREDIT_SIZE, MIN_U2K_PROGRESS_SLOTS_PER_RING, MountId,
    codec::try_encode,
    control::{SETUP_REQUEST_V1_SIZE, SetupRequestV1, SlotClassRequest},
    features::PlatformProfile,
    layout::RegionDesc,
    msgs::{CONTROL_VERSION_V1, ControlHeader},
    validate::{ValidatedSetupRequest, validate_setup_request_v1},
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SECURITY_ONLY: FeatureSet = FeatureSet { words: [0x10, 0] };
const EMPTY_CLASS: SlotClassRequest = SlotClassRequest {
    slot_size: 0,
    slot_count: 0,
};
const PAGE: u32 = 4096;
const BOOT: BootInstanceId = BootInstanceId {
    lo: 0x1122_3344_5566_7788,
    hi: 0x99AA_BBCC_DDEE_FF00,
};
const RANDOM_HIGH: u64 = 0xA5A5_A5A5_A5A5_A5A5;

const MODERN_PROFILES: [PlatformProfile; 2] =
    [PlatformProfile::Win10X64, PlatformProfile::Win10Arm64];
const ALL_PROFILES: [PlatformProfile; 3] = [
    PlatformProfile::Win10X64,
    PlatformProfile::Win10Arm64,
    PlatformProfile::Win7X64,
];

fn class(slot_size: u32, slot_count: u32) -> SlotClassRequest {
    SlotClassRequest {
        slot_size,
        slot_count,
    }
}

fn validated(ring_count: u32) -> ValidatedSetupRequest {
    let request = SetupRequestV1 {
        header: ControlHeader {
            struct_size: SETUP_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        abi_major: 2,
        min_abi_minor: 1,
        max_abi_minor: 1,
        reserved0: 0,
        offered_features: SECURITY_ONLY,
        required_features: SECURITY_ONLY,
        required_os_capabilities: FeatureSet { words: [0, 0] },
        ring_count,
        sq_capacity: 8,
        cq_capacity: 2,
        max_inflight: 1,
        k2u_slot_classes: [
            class(
                MIN_CONTROL_SLOT_SIZE,
                MIN_K2U_PROGRESS_SLOTS_PER_RING * ring_count,
            ),
            EMPTY_CLASS,
            EMPTY_CLASS,
            EMPTY_CLASS,
        ],
        u2k_slot_classes: [
            class(MIN_NOTIFICATION_CREDIT_SIZE, 2),
            class(MIN_NOTIFICATION_CREDIT_SIZE * 2, ring_count),
            class(MIN_NOTIFICATION_CREDIT_SIZE * 4, 3),
            class(
                MIN_CONTROL_SLOT_SIZE,
                MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count,
            ),
        ],
        notification_credit_count: ring_count,
        notification_credit_size: MIN_NOTIFICATION_CREDIT_SIZE * 2,
        flags: 0,
        reserved1: 0,
    };
    let mut bytes = [0u8; SETUP_REQUEST_V1_SIZE as usize];
    assert_eq!(try_encode(&request, &mut bytes), Ok(bytes.len()));
    validate_setup_request_v1(
        &bytes,
        PlatformProfile::Win10X64,
        SECURITY_ONLY,
        FeatureSet { words: [0, 0] },
        true,
    )
    .expect("the setup adapter fixture must validate")
}

fn plan_input(ring_count: u32, profile: PlatformProfile) -> SetupPlanInput {
    let validated_setup = validated(ring_count);
    let layout = SectionLayoutPlan::compute(&validated_setup, PAGE).expect("layout");
    let output_capacity = usize::try_from(
        fsring_abi::validate::session_result_size_v1(&validated_setup.topology())
            .expect("result size"),
    )
    .expect("usize");
    SetupPlanInput {
        boot_instance_id: BOOT,
        validated_setup,
        layout,
        output_capacity,
        profile,
    }
}

fn identity_of(mount_id: MountId) -> SessionIdentity {
    SessionIdentity {
        boot_instance_id: BOOT,
        mount_id,
        session_epoch: 1,
    }
}

fn burned_mount_id() -> MountId {
    MountId {
        lo: 1,
        hi: RANDOM_HIGH,
    }
}

/// Feed one effect the outcome its own arm requires.
fn canonical_outcome(pending: &PendingSetupEffect, ring_count: u32) -> SetupEffectOutcome {
    match pending.effect() {
        SetupEffect::BurnMountId => SetupEffectOutcome::MountIdBurned(burned_mount_id()),
        SetupEffect::BuildProtectedViews => {
            let identity = pending.identity().expect("identity exists after the burn");
            SetupEffectOutcome::ProtectedViewsBuilt(run_protected_views(
                identity,
                pending.profile(),
                *pending.layout(),
                ring_count,
            ))
        }
        _ => SetupEffectOutcome::Done,
    }
}

/// The WDK-free recorder: drive the plan to completion or to one injected
/// failure, recording every effect in order.
struct Recorder {
    effects: Vec<SetupEffect>,
    fail_at: Option<usize>,
}

enum RecordedEnd {
    Published(SetupCommit),
    Failure(SetupFailurePlan),
}

impl Recorder {
    fn new(fail_at: Option<usize>) -> Self {
        Self {
            effects: Vec::new(),
            fail_at,
        }
    }

    fn run(&mut self, ring_count: u32, profile: PlatformProfile) -> RecordedEnd {
        let mut progress = NativeSetupPlan::begin(plan_input(ring_count, profile)).expect("begin");
        loop {
            match progress {
                SetupProgress::Published(commit) => return RecordedEnd::Published(commit),
                SetupProgress::Effect(pending) => {
                    let index = self.effects.len();
                    self.effects.push(pending.effect());
                    if self.fail_at == Some(index) {
                        return RecordedEnd::Failure(fail(pending, ring_count));
                    }
                    let outcome = canonical_outcome(&pending, ring_count);
                    progress = pending.succeeded(outcome).expect("canonical outcome");
                }
            }
        }
    }
}

/// Fail one pending effect through the method its position admits.
fn fail(pending: PendingSetupEffect, ring_count: u32) -> SetupFailurePlan {
    if matches!(pending.effect(), SetupEffect::BuildProtectedViews) {
        let identity = pending.identity().expect("identity");
        let profile = pending.profile();
        let layout = *pending.layout();
        // Fail the nested plan on its very first effect: nothing is mapped, so
        // the nested rollback releases no process reference.
        let receipt = run_protected_views_failing(identity, profile, layout, ring_count, 0).1;
        pending
            .failed_protected_views(receipt)
            .map_err(|_| ())
            .expect("BuildProtectedViews admits the nested receipt")
    } else {
        pending
            .failed_native()
            .map_err(|_| ())
            .expect("every other effect admits a native failure")
    }
}

// ---------------------------------------------------------------------------
// Nested protected-view helpers
// ---------------------------------------------------------------------------

fn run_protected_views(
    identity: SessionIdentity,
    profile: PlatformProfile,
    layout: SectionLayoutPlan,
    _ring_count: u32,
) -> ProtectedViewReceipt {
    let (effects, terminal) = drive_protected_views(identity, profile, layout, None);
    let _ = effects;
    match terminal {
        Ok(receipt) => receipt,
        Err(_) => panic!("an unfailed protected-view plan must complete"),
    }
}

fn run_protected_views_failing(
    identity: SessionIdentity,
    profile: PlatformProfile,
    layout: SectionLayoutPlan,
    _ring_count: u32,
    fail_at: usize,
) -> (
    Vec<ProtectedViewRollbackEffect>,
    ProtectedViewRollbackReceipt,
) {
    let (_, terminal) = drive_protected_views(identity, profile, layout, Some(fail_at));
    match terminal {
        Ok(_) => panic!("the injected failure must abort the plan"),
        Err(rollback) => drain_rollback(rollback),
    }
}

/// Run the nested plan, recording every effect, optionally failing one.
fn drive_protected_views(
    identity: SessionIdentity,
    profile: PlatformProfile,
    layout: SectionLayoutPlan,
    fail_at: Option<usize>,
) -> (
    Vec<ProtectedViewEffect>,
    Result<ProtectedViewReceipt, ProtectedViewRollbackPlan>,
) {
    let mut recorded = Vec::new();
    let mut progress = ProtectedViewPlan::begin(identity, profile, layout).expect("nested begin");
    let mut address = 0x1000_0000usize;
    loop {
        match progress {
            ProtectedViewProgress::Complete(receipt) => return (recorded, Ok(receipt)),
            ProtectedViewProgress::Effect(pending) => {
                let index = recorded.len();
                let effect = pending.effect();
                recorded.push(effect);
                if fail_at == Some(index) {
                    return (recorded, Err(pending.failed()));
                }
                let outcome = match effect {
                    ProtectedViewEffect::MapAlias { alias, .. }
                    | ProtectedViewEffect::MapSectionView { alias, .. } => {
                        address += 0x1_0000;
                        ProtectedViewOutcome::AliasMapped {
                            alias,
                            user_address: NonZeroUsize::new(address).expect("nonzero"),
                        }
                    }
                    _ => ProtectedViewOutcome::Done,
                };
                progress = pending.succeeded(outcome).expect("nested outcome");
            }
        }
    }
}

fn drain_rollback(
    plan: ProtectedViewRollbackPlan,
) -> (
    Vec<ProtectedViewRollbackEffect>,
    ProtectedViewRollbackReceipt,
) {
    let mut recorded = Vec::new();
    let mut progress = plan.next();
    loop {
        match progress {
            ProtectedViewRollbackProgress::Complete(receipt) => return (recorded, receipt),
            ProtectedViewRollbackProgress::Effect(pending) => {
                recorded.push(pending.effect());
                progress = pending.succeeded();
            }
        }
    }
}

fn alias_count(ring_count: u32) -> u32 {
    2 + 3 * ring_count
}

// ---------------------------------------------------------------------------
// The ordered success sequence
// ---------------------------------------------------------------------------

#[test]
fn success_walks_the_frozen_twenty_five_effect_order() {
    for profile in ALL_PROFILES {
        let mut recorder = Recorder::new(None);
        let end = recorder.run(2, profile);
        assert_eq!(recorder.effects, NativeSetupPlan::SUCCESS_EFFECTS.to_vec());
        match end {
            RecordedEnd::Published(commit) => {
                assert_eq!(commit.identity(), identity_of(burned_mount_id()));
            }
            RecordedEnd::Failure(_) => panic!("an unfailed run must publish"),
        }
    }
}

#[test]
fn output_validation_precedes_publication() {
    let effects = NativeSetupPlan::SUCCESS_EFFECTS;
    let validate = effects
        .iter()
        .position(|effect| matches!(effect, SetupEffect::ValidateOutput))
        .expect("ValidateOutput is in the roster");
    let build = effects
        .iter()
        .position(|effect| matches!(effect, SetupEffect::BuildOutput))
        .expect("BuildOutput is in the roster");
    let publish = effects
        .iter()
        .position(|effect| matches!(effect, SetupEffect::PublishLockedSuffix))
        .expect("PublishLockedSuffix is in the roster");
    let install = effects
        .iter()
        .position(|effect| matches!(effect, SetupEffect::InstallStaging))
        .expect("InstallStaging is in the roster");
    let copy = effects
        .iter()
        .position(|effect| matches!(effect, SetupEffect::CopyValidatedOutput))
        .expect("CopyValidatedOutput is in the roster");
    assert!(
        build < validate,
        "the output is built before it is validated"
    );
    assert!(
        validate < install && install < copy && copy < publish,
        "no reference is installed and nothing is published before the complete output validates"
    );
}

#[test]
fn the_burn_precedes_every_resource_and_follows_the_lock() {
    let effects = NativeSetupPlan::SUCCESS_EFFECTS;
    let acquire = effects
        .iter()
        .position(|e| matches!(e, SetupEffect::AcquireBootLockEvent))
        .unwrap();
    let burn = effects
        .iter()
        .position(|e| matches!(e, SetupEffect::BurnMountId))
        .unwrap();
    let release = effects
        .iter()
        .position(|e| matches!(e, SetupEffect::ReleaseBootLockEvent))
        .unwrap();
    let allocate = effects
        .iter()
        .position(|e| matches!(e, SetupEffect::AllocateSectionAndSystemView))
        .unwrap();
    assert!(acquire < burn && burn < release && release < allocate);
}

#[test]
fn output_metadata_is_derived_from_the_request_not_the_executor() {
    for ring_count in [1u32, 4, 64] {
        let input = plan_input(ring_count, PlatformProfile::Win10X64);
        let expected_size = input.output_capacity;
        let progress = NativeSetupPlan::begin(input).expect("begin");
        let SetupProgress::Effect(pending) = progress else {
            panic!("the plan starts with an effect");
        };
        let output = pending.output();
        assert_eq!(output.view_count(), alias_count(ring_count));
        assert_eq!(output.credit_count(), ring_count);
        assert_eq!(output.required_size(), expected_size);
    }
}

#[test]
fn a_short_output_buffer_is_refused_before_any_effect() {
    let mut input = plan_input(2, PlatformProfile::Win10X64);
    input.output_capacity -= 1;
    assert_eq!(
        NativeSetupPlan::begin(input).err(),
        Some(AdapterPlanError::Capacity),
    );
}

#[test]
fn a_disagreeing_layout_is_refused_before_any_effect() {
    let mut input = plan_input(2, PlatformProfile::Win10X64);
    // A plan for a different ring count is not the plan this request implies.
    input.layout = SectionLayoutPlan::compute(&validated(3), PAGE).expect("other layout");
    assert_eq!(
        NativeSetupPlan::begin(input).err(),
        Some(AdapterPlanError::InvalidInput),
    );
}

#[test]
fn every_effect_rejects_a_foreign_outcome() {
    let mut progress =
        NativeSetupPlan::begin(plan_input(1, PlatformProfile::Win10X64)).expect("begin");
    loop {
        match progress {
            SetupProgress::Published(_) => break,
            SetupProgress::Effect(pending) => {
                let effect = pending.effect();
                let foreign = match effect {
                    SetupEffect::BurnMountId | SetupEffect::BuildProtectedViews => {
                        SetupEffectOutcome::Done
                    }
                    _ => SetupEffectOutcome::MountIdBurned(burned_mount_id()),
                };
                let canonical = canonical_outcome(&pending, 1);
                // A cloned plan is impossible by construction, so the rejection
                // is proven on a fresh walk to the same position instead.
                let rejected = replay_to(effect, 1).succeeded(foreign);
                assert_eq!(
                    rejected.err(),
                    Some(AdapterPlanError::InvalidInput),
                    "{effect:?} must reject a foreign outcome",
                );
                progress = pending.succeeded(canonical).expect("canonical");
            }
        }
    }
}

/// Walk a fresh plan to the pending capability for `target`.
fn replay_to(target: SetupEffect, ring_count: u32) -> PendingSetupEffect {
    let mut progress =
        NativeSetupPlan::begin(plan_input(ring_count, PlatformProfile::Win10X64)).expect("begin");
    loop {
        match progress {
            SetupProgress::Published(_) => panic!("{target:?} is not in the roster"),
            SetupProgress::Effect(pending) => {
                if pending.effect() == target {
                    return pending;
                }
                let outcome = canonical_outcome(&pending, ring_count);
                progress = pending.succeeded(outcome).expect("canonical");
            }
        }
    }
}

#[test]
fn a_second_burn_is_refused() {
    let pending = replay_to(SetupEffect::ReleaseBootLockEvent, 1);
    assert_eq!(
        pending
            .succeeded(SetupEffectOutcome::MountIdBurned(burned_mount_id()))
            .err(),
        Some(AdapterPlanError::InvalidInput),
    );
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

/// The exact reverse unwind expected for a failure at each effect index.
fn expected_rollback(index: usize) -> &'static [SetupRollbackEffect] {
    use SetupRollbackEffect as R;
    const RUNDOWN: &[SetupRollbackEffect] = &[R::ReleaseControlRundown];
    const LOCK: &[SetupRollbackEffect] = &[R::ReleaseBootLockEvent, R::ReleaseControlRundown];
    const LOCK_BURNED: &[SetupRollbackEffect] = &[
        R::PreserveBurnedMountId,
        R::ReleaseBootLockEvent,
        R::ReleaseControlRundown,
    ];
    const BURNED: &[SetupRollbackEffect] = &[R::PreserveBurnedMountId, R::ReleaseControlRundown];
    const SECTION: &[SetupRollbackEffect] = &[
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];
    const GRANTS: &[SetupRollbackEffect] = &[
        R::FreeGrants,
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];
    const EVENTS: &[SetupRollbackEffect] = &[
        R::FreeEventsAndScratch,
        R::FreeGrants,
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];
    const VDO: &[SetupRollbackEffect] = &[
        R::DeleteVdo,
        R::FreeEventsAndScratch,
        R::FreeGrants,
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];
    const PROCESS: &[SetupRollbackEffect] = &[
        R::ReleaseCapturedProcess,
        R::DeleteVdo,
        R::FreeEventsAndScratch,
        R::FreeGrants,
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];
    const VIEWS: &[SetupRollbackEffect] = &[
        R::RollbackProtectedViews,
        R::ReleaseCapturedProcess,
        R::DeleteVdo,
        R::FreeEventsAndScratch,
        R::FreeGrants,
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];
    const REFS: &[SetupRollbackEffect] = &[
        R::ReleaseStrongReferences,
        R::RollbackProtectedViews,
        R::ReleaseCapturedProcess,
        R::DeleteVdo,
        R::FreeEventsAndScratch,
        R::FreeGrants,
        R::UnmapAndCloseSection,
        R::PreserveBurnedMountId,
        R::ReleaseControlRundown,
    ];

    match index {
        0 => &[],
        1..=4 => RUNDOWN,
        5 => LOCK,
        6 => LOCK_BURNED,
        7 | 8 => BURNED,
        9 | 10 => SECTION,
        11 => GRANTS,
        12 => EVENTS,
        // 13 is CaptureProcess: it failed, so no reference was taken.
        13 => VDO,
        // 14 is BuildProtectedViews. The nested receipt decides whether the
        // captured process is still this plan's to release; the recorder fails
        // the nested plan before any alias maps, which retains it. The
        // released case is covered separately below.
        14 => PROCESS,
        15..=17 => VIEWS,
        _ => REFS,
    }
}

#[test]
fn every_precommit_failure_unwinds_in_exact_reverse() {
    let publish = NativeSetupPlan::SUCCESS_EFFECTS
        .iter()
        .position(|e| matches!(e, SetupEffect::PublishLockedSuffix))
        .unwrap();
    for index in 0..publish {
        let mut recorder = Recorder::new(Some(index));
        let end = recorder.run(2, PlatformProfile::Win10X64);
        match end {
            RecordedEnd::Failure(SetupFailurePlan::Rollback(rollback)) => {
                assert_eq!(
                    rollback.effects(),
                    expected_rollback(index),
                    "failure at effect {index} ({:?})",
                    NativeSetupPlan::SUCCESS_EFFECTS[index],
                );
            }
            _ => panic!("a precommit failure at {index} must roll back"),
        }
    }
}

#[test]
fn failure_after_publication_completes_the_published_session() {
    let publish = NativeSetupPlan::SUCCESS_EFFECTS
        .iter()
        .position(|e| matches!(e, SetupEffect::PublishLockedSuffix))
        .unwrap();
    // Strictly after: a failure reported *for* `PublishLockedSuffix` means the
    // Release store did not happen, and that case is pinned separately below.
    for index in publish.saturating_add(1)..NativeSetupPlan::SUCCESS_EFFECTS.len() {
        let mut recorder = Recorder::new(Some(index));
        match recorder.run(2, PlatformProfile::Win10X64) {
            RecordedEnd::Failure(SetupFailurePlan::CompletePublished(commit)) => {
                assert_eq!(commit.identity(), identity_of(burned_mount_id()));
            }
            _ => panic!("cancellation loses at or after the Release commit ({index})"),
        }
    }
}

#[test]
fn a_failure_reported_for_publication_itself_still_unwinds() {
    // The commit is the Release store, not the intent to perform it. A failure
    // reported *for* `PublishLockedSuffix` leaves the session unreachable: no fence
    // can ever find it, so the strong references installed by the effect before
    // it must come back here or they leak for the lifetime of the driver.
    let publish = NativeSetupPlan::SUCCESS_EFFECTS
        .iter()
        .position(|e| matches!(e, SetupEffect::PublishLockedSuffix))
        .unwrap();
    let mut recorder = Recorder::new(Some(publish));
    match recorder.run(2, PlatformProfile::Win10X64) {
        RecordedEnd::Failure(SetupFailurePlan::Rollback(rollback)) => {
            let effects = rollback.effects();
            assert!(
                effects.contains(&SetupRollbackEffect::ReleaseStrongReferences),
                "the references installed immediately before the commit are released: {effects:?}",
            );
            assert!(
                effects.contains(&SetupRollbackEffect::PreserveBurnedMountId),
                "a rollback after the burn never hands the MountId back: {effects:?}",
            );
        }
        RecordedEnd::Failure(SetupFailurePlan::CompletePublished(_)) => {
            panic!("a failure reported for the commit itself must unwind, not publish")
        }
        RecordedEnd::Published(_) => panic!("the injected failure was not observed"),
    }
}

#[test]
fn a_burned_mount_id_is_never_reused_by_the_rollback() {
    // Every rollback that happens after the burn carries the preservation
    // marker, and no rollback effect can hand a MountId back.
    for index in 6..15 {
        let mut recorder = Recorder::new(Some(index));
        let RecordedEnd::Failure(SetupFailurePlan::Rollback(rollback)) =
            recorder.run(2, PlatformProfile::Win10X64)
        else {
            panic!("precommit rollback expected at {index}");
        };
        assert!(
            rollback
                .effects()
                .contains(&SetupRollbackEffect::PreserveBurnedMountId),
            "a rollback after the burn must preserve it ({index})",
        );
    }
    for index in 0..6 {
        let mut recorder = Recorder::new(Some(index));
        let RecordedEnd::Failure(SetupFailurePlan::Rollback(rollback)) =
            recorder.run(2, PlatformProfile::Win10X64)
        else {
            panic!("precommit rollback expected at {index}");
        };
        assert!(
            !rollback
                .effects()
                .contains(&SetupRollbackEffect::PreserveBurnedMountId),
            "nothing is burned before BurnMountId succeeds ({index})",
        );
    }
}

#[test]
fn failed_native_is_refused_inside_build_protected_views() {
    let pending = replay_to(SetupEffect::BuildProtectedViews, 1);
    let (error, returned) = pending.failed_native().err().expect("refused");
    assert_eq!(error, AdapterPlanError::InvalidTransition);
    // The affine capability came back unchanged, so rollback authority is
    // never lost by calling the wrong method.
    assert_eq!(returned.effect(), SetupEffect::BuildProtectedViews);
}

#[test]
fn failed_protected_views_is_refused_outside_build_protected_views() {
    let identity = identity_of(burned_mount_id());
    let layout = SectionLayoutPlan::compute(&validated(1), PAGE).expect("layout");
    let (_, receipt) =
        run_protected_views_failing(identity, PlatformProfile::Win10X64, layout, 1, 0);
    let pending = replay_to(SetupEffect::CaptureProcess, 1);
    let (error, returned, returned_receipt) = pending
        .failed_protected_views(receipt)
        .err()
        .expect("refused");
    assert_eq!(error, AdapterPlanError::InvalidTransition);
    assert_eq!(returned.effect(), SetupEffect::CaptureProcess);
    assert_eq!(returned_receipt.identity(), identity);
}

#[test]
fn a_receipt_built_for_another_geometry_is_refused() {
    // Same ring count, so the alias count matches and the layout is the only
    // field that disagrees: this pins the layout comparison on its own.
    let pending = replay_to(SetupEffect::BuildProtectedViews, 2);
    let identity = pending.identity().expect("identity");
    let other_geometry =
        SectionLayoutPlan::compute(&validated(2), PAGE * 2).expect("a larger page still lays out");
    assert_ne!(other_geometry, *pending.layout());
    let matching = run_protected_views(identity, pending.profile(), *pending.layout(), 2);
    let receipt = run_protected_views(identity, pending.profile(), other_geometry, 2);
    assert_eq!(
        receipt.alias_count(),
        matching.alias_count(),
        "the alias count is unchanged, so only the layout can be doing the refusing",
    );
    assert_eq!(
        pending
            .succeeded(SetupEffectOutcome::ProtectedViewsBuilt(receipt))
            .err(),
        Some(AdapterPlanError::InvalidTransition),
        "a receipt answers one plan's geometry, never another's",
    );
}

#[test]
fn a_foreign_receipt_is_refused_on_the_failure_path_too() {
    let pending = replay_to(SetupEffect::BuildProtectedViews, 1);
    let foreign_identity = SessionIdentity {
        boot_instance_id: BOOT,
        mount_id: MountId { lo: 9, hi: 9 },
        session_epoch: 1,
    };
    let layout = *pending.layout();
    let (_, receipt) =
        run_protected_views_failing(foreign_identity, pending.profile(), layout, 1, 0);
    let (error, _, returned_receipt) = pending
        .failed_protected_views(receipt)
        .err()
        .expect("refused");
    assert_eq!(error, AdapterPlanError::InvalidTransition);
    assert_eq!(
        returned_receipt.identity(),
        foreign_identity,
        "the refusal hands the foreign receipt back rather than absorbing it",
    );
}

#[test]
fn a_nested_release_removes_the_outer_process_release() {
    let ring_count = 1u32;
    let pending = replay_to(SetupEffect::BuildProtectedViews, ring_count);
    let identity = pending.identity().expect("identity");
    let layout = *pending.layout();
    // Fail the last map: aliases are mapped, so the nested rollback owns the
    // reattach, the reverse unmap, and the final process release.
    let modern_total = modern_effect_count(ring_count);
    let (rollback_effects, receipt) = run_protected_views_failing(
        identity,
        PlatformProfile::Win10X64,
        layout,
        ring_count,
        modern_total - 2,
    );
    assert_eq!(
        receipt.disposition(),
        CapturedProcessDisposition::ReleasedByProtectedViews,
    );
    assert_eq!(
        rollback_effects.last(),
        Some(&ProtectedViewRollbackEffect::ReleaseCapturedProcess),
    );
    let failure = pending
        .failed_protected_views(receipt)
        .map_err(|_| ())
        .expect("accepted");
    let SetupFailurePlan::Rollback(rollback) = failure else {
        panic!("precommit");
    };
    assert!(
        !rollback
            .effects()
            .contains(&SetupRollbackEffect::ReleaseCapturedProcess),
        "the nested plan already released the reference",
    );
    // Exactly the CaptureProcess-failed unwind: everything the outer plan still
    // owns, with the process reference already gone.
    assert_eq!(rollback.effects(), expected_rollback(13));
}

#[test]
fn a_retained_process_keeps_exactly_one_outer_release() {
    let pending = replay_to(SetupEffect::BuildProtectedViews, 1);
    let identity = pending.identity().expect("identity");
    let layout = *pending.layout();
    let (rollback_effects, receipt) =
        run_protected_views_failing(identity, PlatformProfile::Win10X64, layout, 1, 0);
    assert_eq!(
        receipt.disposition(),
        CapturedProcessDisposition::RetainedBySetup,
    );
    assert!(
        !rollback_effects.contains(&ProtectedViewRollbackEffect::ReleaseCapturedProcess),
        "an unmapped nested plan releases nothing",
    );
    let failure = pending
        .failed_protected_views(receipt)
        .map_err(|_| ())
        .expect("accepted");
    let SetupFailurePlan::Rollback(rollback) = failure else {
        panic!("precommit");
    };
    assert_eq!(
        rollback
            .effects()
            .iter()
            .filter(|e| matches!(e, SetupRollbackEffect::ReleaseCapturedProcess))
            .count(),
        1,
        "exactly one release, never zero and never two",
    );
}

#[test]
fn a_foreign_protected_view_receipt_is_refused() {
    let pending = replay_to(SetupEffect::BuildProtectedViews, 2);
    let foreign_identity = SessionIdentity {
        boot_instance_id: BOOT,
        mount_id: MountId { lo: 7, hi: 7 },
        session_epoch: 1,
    };
    let layout = *pending.layout();
    let receipt = run_protected_views(foreign_identity, pending.profile(), layout, 2);
    assert_eq!(
        pending
            .succeeded(SetupEffectOutcome::ProtectedViewsBuilt(receipt))
            .err(),
        Some(AdapterPlanError::InvalidTransition),
    );
}

// ---------------------------------------------------------------------------
// Protected views: modern
// ---------------------------------------------------------------------------

fn modern_effect_count(ring_count: u32) -> usize {
    let masters = (ring_count + 2) as usize;
    let aliases = alias_count(ring_count) as usize;
    // One partial fewer than aliases: alias 0 is the whole-section spine and is
    // mapped by section view on every profile, because one MDL cannot describe
    // more than ~32 MiB and the daemon validates that view against the full
    // section size.
    let partials = aliases - 1;
    masters + partials + 1 + aliases + 1
}

#[test]
fn modern_locks_every_master_before_it_builds_a_partial() {
    for profile in MODERN_PROFILES {
        let ring_count = 3u32;
        let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
        let (effects, terminal) =
            drive_protected_views(identity_of(burned_mount_id()), profile, layout, None);
        assert!(terminal.is_ok());
        assert_eq!(effects.len(), modern_effect_count(ring_count));

        let last_master = effects
            .iter()
            .rposition(|e| matches!(e, ProtectedViewEffect::AllocateAndLockMaster { .. }))
            .expect("masters exist");
        let first_partial = effects
            .iter()
            .position(|e| matches!(e, ProtectedViewEffect::BuildPartial { .. }))
            .expect("partials exist");
        assert!(
            last_master < first_partial,
            "no partial MDL is built until every page is locked",
        );

        let attach = effects
            .iter()
            .position(|e| matches!(e, ProtectedViewEffect::AttachCapturedProcess))
            .expect("attach");
        let last_partial = effects
            .iter()
            .rposition(|e| matches!(e, ProtectedViewEffect::BuildPartial { .. }))
            .unwrap();
        let first_map = effects
            .iter()
            .position(|e| matches!(e, ProtectedViewEffect::MapAlias { .. }))
            .expect("maps");
        assert!(last_partial < attach && attach < first_map);
        assert!(matches!(
            effects.last(),
            Some(ProtectedViewEffect::DetachCapturedProcess),
        ));
        // Exactly one section view, and it is the whole-section spine. Every
        // other alias still reaches the daemon through a partial MDL tied to a
        // locked master; the spine cannot, because one MDL stops at ~32 MiB.
        let section_views: Vec<u32> = effects
            .iter()
            .filter_map(|e| match e {
                ProtectedViewEffect::MapSectionView { alias, .. } => Some(alias.0),
                _ => None,
            })
            .collect();
        assert_eq!(
            section_views,
            vec![0],
            "a modern profile maps exactly one section view, the spine",
        );
    }
}

#[test]
fn modern_master_access_matches_alias_writability() {
    let ring_count = 2u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    let (effects, _) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10X64,
        layout,
        None,
    );
    let masters: Vec<_> = effects
        .iter()
        .filter_map(|e| match e {
            ProtectedViewEffect::AllocateAndLockMaster { region, access } => {
                Some((*region, *access))
            }
            _ => None,
        })
        .collect();
    assert_eq!(masters.len(), (ring_count + 2) as usize);
    assert_eq!(
        masters[0],
        (CanonicalRegion::HeaderDirectory, MdlAccess::Read),
        "the read-only spine is locked for read access only",
    );
    for ring in 0..ring_count {
        assert_eq!(
            masters[(ring + 1) as usize],
            (CanonicalRegion::Ring(ring), MdlAccess::Modify),
        );
    }
    assert_eq!(
        masters[(ring_count + 1) as usize],
        (CanonicalRegion::U2kArena, MdlAccess::Modify),
    );
}

#[test]
fn modern_maps_are_user_mode_non_executable_and_write_gated() {
    let ring_count = 2u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    let (effects, _) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10X64,
        layout,
        None,
    );
    let maps: Vec<_> = effects
        .iter()
        .filter_map(|e| match e {
            ProtectedViewEffect::MapAlias {
                alias,
                protection,
                flags,
            } => Some((*alias, *protection, *flags)),
            _ => None,
        })
        .collect();
    // One fewer partial-MDL map than aliases: alias 0 is a section view.
    assert_eq!(maps.len(), alias_count(ring_count) as usize - 1);
    for (alias, protection, flags) in maps {
        assert!(flags.user_mode, "every alias is a user-mode mapping");
        assert!(flags.no_execute, "no alias is ever executable");
        assert_ne!(
            alias,
            AliasId(0),
            "alias 0 never maps through a partial MDL"
        );
        assert_eq!(
            flags.no_write,
            matches!(protection, AliasProtection::ReadOnly),
            "the no-write flag tracks the alias protection exactly ({alias:?})",
        );
    }
    // Alias 0 is the read-only whole-section spine; every other alias is one of
    // the daemon's three per-ring producer regions or the U2K arena. The spine
    // is mapped by section view even here, because one MDL cannot describe a
    // section this large -- and it must still be read-only, which is the
    // property this test exists for.
    let spine = effects
        .iter()
        .find(|e| {
            matches!(
                e,
                ProtectedViewEffect::MapSectionView {
                    alias: AliasId(0),
                    ..
                }
            )
        })
        .expect("alias 0 maps by section view");
    assert!(matches!(
        spine,
        ProtectedViewEffect::MapSectionView {
            protection: AliasProtection::ReadOnly,
            offset: 0,
            ..
        },
    ));
    let ProtectedViewEffect::MapSectionView { length, .. } = spine else {
        unreachable!("just matched")
    };
    assert_eq!(
        *length,
        layout.section_size(),
        "the spine still spans the whole section, which the daemon validates",
    );
}

#[test]
fn every_partial_lies_inside_its_master_region() {
    let ring_count = 4u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    let (effects, _) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10X64,
        layout,
        None,
    );
    for effect in &effects {
        let ProtectedViewEffect::BuildPartial {
            alias,
            region,
            offset,
            length,
        } = effect
        else {
            continue;
        };
        let master = region_span(&layout, *region).expect("every named region exists");
        assert!(
            *offset >= master.offset && offset + length <= master.offset + master.length,
            "alias {alias:?} escapes its master {region:?}",
        );
        assert!(*length > 0);
    }
}

/// The section span each canonical region names, recomputed by the test from
/// the frozen layout rather than read back from the plan under test.
fn region_span(layout: &SectionLayoutPlan, region: CanonicalRegion) -> Option<RegionDesc> {
    match region {
        // HeaderDirectory is not recomputed here; it is checked by property in
        // `the_published_master_span_matches_an_independent_recomputation`,
        // because any arithmetic written here would be the implementation's
        // own and would agree with whatever that said.
        CanonicalRegion::HeaderDirectory => None,
        CanonicalRegion::Ring(index) => {
            let ring = layout.ring(index)?;
            let start = ring.sq_producer.offset;
            let end = ring.cq_entries.offset + ring.cq_entries.length;
            Some(RegionDesc {
                offset: start,
                length: end - start,
            })
        }
        CanonicalRegion::U2kArena => Some(layout.u2k_slots()),
    }
}

#[test]
fn modern_rollback_reattaches_and_unwinds_in_reverse() {
    let ring_count = 2u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    let total = modern_effect_count(ring_count);
    // Fail the final map: every earlier alias is mapped.
    let (recorded, terminal) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10X64,
        layout,
        Some(total - 2),
    );
    let Err(rollback) = terminal else {
        panic!("the injected failure aborts the plan");
    };
    // Both mechanisms count: the spine maps by section view, so filtering on
    // `MapAlias` alone would under-count what the rollback owes by one and let
    // a leaked spine mapping pass as a clean unwind.
    let mapped = recorded
        .iter()
        .filter(|e| {
            matches!(
                e,
                ProtectedViewEffect::MapAlias { .. } | ProtectedViewEffect::MapSectionView { .. }
            )
        })
        .count()
        - 1;
    let (undo, receipt) = drain_rollback(rollback);

    assert_eq!(
        undo.first(),
        Some(&ProtectedViewRollbackEffect::AttachCapturedProcess)
    );
    // Both mapping mechanisms unwind in one reverse walk. Collecting only one
    // kind would let the other leak a mapping in the daemon's address space
    // and still read as a clean reverse order.
    let unmaps: Vec<u32> = undo
        .iter()
        .filter_map(|e| match e {
            ProtectedViewRollbackEffect::UnmapAliasReverse { alias }
            | ProtectedViewRollbackEffect::UnmapSectionViewReverse { alias } => Some(alias.0),
            _ => None,
        })
        .collect();
    let expected_unmaps: Vec<u32> = (0..mapped as u32).rev().collect();
    assert_eq!(unmaps, expected_unmaps, "aliases unmap in reverse order");
    // And each one unwinds by the mechanism that made it: alias 0 is a section
    // view on this profile too, so unmapping it as a partial-MDL alias would
    // hand `MmUnmapLockedPages` an address `ZwMapViewOfSection` produced.
    let section_unmaps: Vec<u32> = undo
        .iter()
        .filter_map(|e| match e {
            ProtectedViewRollbackEffect::UnmapSectionViewReverse { alias } => Some(alias.0),
            _ => None,
        })
        .collect();
    assert_eq!(
        section_unmaps,
        vec![0],
        "only the spine unwinds as a section view",
    );

    let frees: Vec<u32> = undo
        .iter()
        .filter_map(|e| match e {
            ProtectedViewRollbackEffect::FreePartialMdlReverse { alias } => Some(alias.0),
            _ => None,
        })
        .collect();
    // Partials cover aliases 1..=n: alias 0 never had one, because the spine is
    // a section view. Freeing a partial for alias 0 would hand `IoFreeMdl` a
    // null, and skipping alias n would leak one.
    let expected_frees: Vec<u32> = (1..alias_count(ring_count)).rev().collect();
    assert_eq!(frees, expected_frees, "partial MDLs free in reverse order");

    let detach = undo
        .iter()
        .position(|e| matches!(e, ProtectedViewRollbackEffect::DetachCapturedProcess))
        .expect("a reattach is always paired with a detach");
    let last_free = undo
        .iter()
        .rposition(|e| matches!(e, ProtectedViewRollbackEffect::FreePartialMdlReverse { .. }))
        .unwrap();
    let first_master = undo
        .iter()
        .position(|e| {
            matches!(
                e,
                ProtectedViewRollbackEffect::UnlockAndFreeMasterReverse { .. }
            )
        })
        .expect("masters unlock");
    assert!(last_free < detach && detach < first_master);
    assert_eq!(
        undo.last(),
        Some(&ProtectedViewRollbackEffect::ReleaseCapturedProcess),
    );
    assert_eq!(
        receipt.disposition(),
        CapturedProcessDisposition::ReleasedByProtectedViews,
    );

    let masters: Vec<CanonicalRegion> = undo
        .iter()
        .filter_map(|e| match e {
            ProtectedViewRollbackEffect::UnlockAndFreeMasterReverse { region } => Some(*region),
            _ => None,
        })
        .collect();
    let mut expected_masters = vec![CanonicalRegion::HeaderDirectory];
    for ring in 0..ring_count {
        expected_masters.push(CanonicalRegion::Ring(ring));
    }
    expected_masters.push(CanonicalRegion::U2kArena);
    expected_masters.reverse();
    assert_eq!(masters, expected_masters);
}

#[test]
fn a_probe_exception_unwinds_without_touching_the_process() {
    let ring_count = 2u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    // Effect index 1 is the second master lock: the probe raised.
    let (_, terminal) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10X64,
        layout,
        Some(1),
    );
    let Err(rollback) = terminal else {
        panic!("the probe exception aborts the plan");
    };
    let (undo, receipt) = drain_rollback(rollback);
    assert_eq!(
        undo,
        vec![ProtectedViewRollbackEffect::UnlockAndFreeMasterReverse {
            region: CanonicalRegion::HeaderDirectory,
        }],
        "only the one master that locked is unwound",
    );
    assert!(
        !undo
            .iter()
            .any(|e| matches!(e, ProtectedViewRollbackEffect::AttachCapturedProcess)),
        "an unmapped failure never attaches",
    );
    assert_eq!(
        receipt.disposition(),
        CapturedProcessDisposition::RetainedBySetup,
    );
}

#[test]
fn a_failed_release_keeps_the_reference_with_setup() {
    let ring_count = 1u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    let total = modern_effect_count(ring_count);
    let (_, terminal) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10X64,
        layout,
        Some(total - 2),
    );
    let Err(rollback) = terminal else {
        panic!("aborts");
    };
    // Drain the rollback but fail its last effect, the process release.
    let mut progress = rollback.next();
    let receipt;
    let mut recorded = Vec::new();
    loop {
        match progress {
            ProtectedViewRollbackProgress::Complete(done) => {
                receipt = Some(done);
                break;
            }
            ProtectedViewRollbackProgress::Effect(pending) => {
                let effect = pending.effect();
                recorded.push(effect);
                progress = if matches!(effect, ProtectedViewRollbackEffect::ReleaseCapturedProcess)
                {
                    pending.failed()
                } else {
                    pending.succeeded()
                };
            }
        }
    }
    assert_eq!(
        receipt.expect("complete").disposition(),
        CapturedProcessDisposition::RetainedBySetup,
        "a release that did not succeed leaves the reference with SETUP",
    );
}

// ---------------------------------------------------------------------------
// Protected views: Win7
// ---------------------------------------------------------------------------

#[test]
fn win7_locks_the_same_masters_and_maps_exact_64_kib_offsets() {
    const USER_VIEW_OFFSET_ALIGNMENT: u64 = 65_536;
    for ring_count in [1u32, 3] {
        let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
        let masters = ring_count as usize + 2;
        let (effects, terminal) = drive_protected_views(
            identity_of(burned_mount_id()),
            PlatformProfile::Win7X64,
            layout,
            None,
        );
        assert!(terminal.is_ok());
        assert_eq!(
            effects.len(),
            masters + alias_count(ring_count) as usize + 2
        );
        // The residency roster is the same on every profile: the ENTER drain
        // reads and writes this driver's system-space view of a pagefile-backed
        // section with the ring spin lock held, and a view whose pages the
        // trimmer may take cannot be touched at DISPATCH_LEVEL. What stays
        // profile-split is how the DAEMON's alias is made -- a section view
        // here, a partial MDL on the modern profiles.
        assert_eq!(
            effects
                .iter()
                .filter(|e| matches!(e, ProtectedViewEffect::AllocateAndLockMaster { .. }))
                .count(),
            masters,
            "the legacy profile locks the same master MDLs as the modern ones",
        );
        assert!(
            !effects.iter().any(|e| matches!(
                e,
                ProtectedViewEffect::BuildPartial { .. } | ProtectedViewEffect::MapAlias { .. }
            )),
            "the legacy profile builds no partial and maps no alias MDL",
        );
        assert!(matches!(
            effects.first(),
            Some(ProtectedViewEffect::AllocateAndLockMaster { .. })
        ));
        assert!(matches!(
            effects.get(masters),
            Some(ProtectedViewEffect::AttachCapturedProcess)
        ));
        assert!(matches!(
            effects.last(),
            Some(ProtectedViewEffect::DetachCapturedProcess)
        ));
        for effect in &effects {
            let ProtectedViewEffect::MapSectionView {
                alias,
                offset,
                length,
                protection,
            } = effect
            else {
                continue;
            };
            assert_eq!(
                offset % USER_VIEW_OFFSET_ALIGNMENT,
                0,
                "alias {alias:?} must start on a 64-KiB boundary",
            );
            assert!(*length > 0);
            assert!(offset + length <= layout.section_size());
            if alias.0 == 0 {
                assert_eq!(*protection, AliasProtection::ReadOnly);
                assert_eq!(*offset, 0);
                assert_eq!(*length, layout.section_size());
            } else {
                assert_eq!(*protection, AliasProtection::ReadWrite);
            }
        }
    }
}

#[test]
fn win7_rollback_unmaps_section_views_and_unlocks_masters_in_reverse() {
    let ring_count = 2u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    let masters = ring_count as usize + 2;
    let total = masters + alias_count(ring_count) as usize + 2;
    let (_, terminal) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win7X64,
        layout,
        Some(total - 2),
    );
    let Err(rollback) = terminal else {
        panic!("aborts");
    };
    let (undo, receipt) = drain_rollback(rollback);
    let unmaps: Vec<u32> = undo
        .iter()
        .filter_map(|e| match e {
            ProtectedViewRollbackEffect::UnmapSectionViewReverse { alias } => Some(alias.0),
            _ => None,
        })
        .collect();
    let expected: Vec<u32> = (0..alias_count(ring_count) - 1).rev().collect();
    assert_eq!(unmaps, expected);
    // Masters are locked on this profile, so they are unwound on this profile:
    // an abort that left them locked would leave the section pinned for the
    // life of the driver.
    assert_eq!(
        undo.iter()
            .filter(|e| matches!(
                e,
                ProtectedViewRollbackEffect::UnlockAndFreeMasterReverse { .. }
            ))
            .count(),
        masters,
        "every locked master is unlocked in the unwind",
    );
    assert!(
        !undo
            .iter()
            .any(|e| matches!(e, ProtectedViewRollbackEffect::FreePartialMdlReverse { .. })),
        "the legacy profile builds no partial MDL, so it frees none",
    );
    assert_eq!(
        receipt.disposition(),
        CapturedProcessDisposition::ReleasedByProtectedViews,
    );
}

#[test]
fn the_profile_is_fixed_by_the_plan_not_the_executor() {
    // A Win7 input never produces a modern effect, and a modern input never
    // produces a legacy one; there is no executor-supplied profile to disagree.
    let layout = SectionLayoutPlan::compute(&validated(1), PAGE).expect("layout");
    let (modern, _) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win10Arm64,
        layout,
        None,
    );
    let (legacy, _) = drive_protected_views(
        identity_of(burned_mount_id()),
        PlatformProfile::Win7X64,
        layout,
        None,
    );
    assert_ne!(modern.len(), legacy.len());
    assert!(
        modern
            .iter()
            .any(|e| matches!(e, ProtectedViewEffect::MapAlias { .. }))
    );
    assert!(
        legacy
            .iter()
            .any(|e| matches!(e, ProtectedViewEffect::MapSectionView { .. }))
    );
}

#[test]
fn a_mismatched_alias_outcome_is_refused() {
    let layout = SectionLayoutPlan::compute(&validated(1), PAGE).expect("layout");
    let mut progress = ProtectedViewPlan::begin(
        identity_of(burned_mount_id()),
        PlatformProfile::Win7X64,
        layout,
    )
    .expect("begin");
    // Walk the master locks this profile now performs, then the attach: the
    // refusal under test is about a mapping outcome naming the wrong alias,
    // and it lives after both.
    for _ in 0..(1u32 + 2) {
        let ProtectedViewProgress::Effect(master) = progress else {
            panic!("a master lock comes first on every profile");
        };
        progress = master
            .succeeded(ProtectedViewOutcome::Done)
            .expect("master");
    }
    let ProtectedViewProgress::Effect(attach) = progress else {
        panic!("the attach follows the masters");
    };
    progress = attach
        .succeeded(ProtectedViewOutcome::Done)
        .expect("attach");
    let ProtectedViewProgress::Effect(map) = progress else {
        panic!("a map follows the attach");
    };
    assert_eq!(
        map.succeeded(ProtectedViewOutcome::AliasMapped {
            alias: AliasId(99),
            user_address: NonZeroUsize::new(0x2000).unwrap(),
        })
        .err(),
        Some(AdapterPlanError::InvalidTransition),
        "a user address reported for the wrong alias is refused",
    );
}

// ---------------------------------------------------------------------------
// Scratch identity
// ---------------------------------------------------------------------------

#[test]
fn every_drain_scratch_and_the_fence_scratch_are_pairwise_distinct() {
    let mut identities = Vec::new();
    for ring_index in 0..64u32 {
        let scratch = ScratchIdentity::drain(ring_index);
        identities.push(scratch);
    }
    identities.push(ScratchIdentity::fence());
    assert_eq!(identities.len(), 65);
    for (left_index, left) in identities.iter().enumerate() {
        for (right_index, right) in identities.iter().enumerate() {
            if left_index != right_index {
                assert_ne!(
                    left, right,
                    "scratch {left_index} and {right_index} collide",
                );
            }
        }
    }
}

#[test]
fn the_published_master_span_matches_an_independent_recomputation() {
    let ring_count = 3u32;
    let layout = SectionLayoutPlan::compute(&validated(ring_count), PAGE).expect("layout");
    // The spine master is checked by property, not by recomputation. It exists
    // to keep the pages this driver reads above APC_LEVEL resident, so what
    // matters is that it covers the whole ring directory and reaches into no
    // ring -- a ring's own pages are its own master's job, and a span that
    // swallowed them would put the whole section back under one MDL, which is
    // the ~32 MiB cap this narrowing removed.
    let spine = master_region_span(&layout, CanonicalRegion::HeaderDirectory).expect("a spine");
    let directory = layout.ring_directory();
    assert_eq!(spine.offset, 0, "the spine starts at the section base");
    assert!(
        spine.length >= directory.offset + directory.length,
        "the spine covers the whole ring directory",
    );
    assert!(
        spine.length <= layout.ring(0).expect("a first ring").sq_entries.offset,
        "and reaches into no ring",
    );
    assert!(
        spine.length < layout.section_size(),
        "and is not the whole section, which no single MDL can describe",
    );

    let mut regions = Vec::new();
    for ring in 0..ring_count {
        regions.push(CanonicalRegion::Ring(ring));
    }
    regions.push(CanonicalRegion::U2kArena);
    for region in regions {
        assert_eq!(
            master_region_span(&layout, region),
            region_span(&layout, region),
            "the executor's master span must be the layout's own ({region:?})",
        );
    }
    assert_eq!(
        master_region_span(&layout, CanonicalRegion::Ring(ring_count)),
        None,
        "no master exists for a ring outside the topology",
    );
}

#[test]
fn the_plan_remembers_the_capacity_it_was_admitted_against() {
    let input = plan_input(2, PlatformProfile::Win10X64);
    let capacity = input.output_capacity;
    let SetupProgress::Effect(pending) = NativeSetupPlan::begin(input).expect("begin") else {
        panic!("an effect");
    };
    assert_eq!(pending.output_capacity(), capacity);
    assert!(pending.output_capacity() >= pending.output().required_size());
}

#[test]
fn the_scratch_roster_is_one_distinct_identity_per_ring_plus_the_fence() {
    let mut out = [ScratchIdentity::fence(); 65];
    let written = scratch_roster(64, &mut out).expect("the roster fits");
    assert_eq!(written, 65, "sixty-four ring identities plus one fence");
    for (index, scratch) in out.iter().enumerate().take(64) {
        assert_eq!(
            *scratch,
            ScratchIdentity::drain(index as u32),
            "ring {index} did not get its own identity",
        );
    }
    assert_eq!(out[64], ScratchIdentity::fence());
    for (left, first) in out.iter().enumerate() {
        for (right, second) in out.iter().enumerate() {
            if left != right {
                assert_ne!(first, second, "roster entries {left} and {right} alias");
            }
        }
    }
    let mut short = [ScratchIdentity::fence(); 4];
    assert_eq!(
        scratch_roster(64, &mut short).err(),
        Some(AdapterPlanError::Capacity),
        "a roster that does not fit is refused rather than truncated",
    );
}

#[test]
fn the_fence_scratch_is_not_any_ring_drain_scratch() {
    let fence = ScratchIdentity::fence();
    for ring_index in 0..64u32 {
        assert_ne!(ScratchIdentity::drain(ring_index), fence);
    }
}

// ---------------------------------------------------------------------------
// Task 7: coupled SETUP publication and precommit CLEANUP
// ---------------------------------------------------------------------------

use crate::session::{
    CleanupBindingClaim, ControlBinding, ControlBindingState, SessionError, SessionRegistry,
    SetupEpochCursor, SetupFailure, SetupStage, SetupTransaction, SlotDisposition,
    TerminalRendezvous, commit_prepared_installed_setup_rollback,
    commit_prepared_reserved_setup_rollback, prepare_installed_setup_publication,
    prepare_installed_setup_rollback, prepare_reserved_setup_rollback,
};

fn staged_transaction() -> SetupTransaction {
    let mut transaction = SetupTransaction::begin(identity_of(burned_mount_id())).expect("begin");
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = transaction.stage(stage).map_err(|_| ()).expect("stage");
    }
    transaction
}

fn installed_setup<const N: usize>(
    registry: &mut SessionRegistry<N>,
    binding: &mut ControlBinding,
) -> (
    SetupTransaction,
    crate::session::SetupReservation,
    crate::session::InstalledSession,
) {
    let reservation = binding.begin_setup().expect("reserve");
    let transaction = staged_transaction();
    let installed = registry
        .install_staging(&transaction, binding, &reservation)
        .expect("install staging");
    let transaction = transaction
        .stage(SetupStage::ReferencesInstalled)
        .map_err(|_| ())
        .expect("references installed");
    (transaction, reservation, installed)
}

fn drive_setup_entry(
    binding: &mut ControlBinding,
    prior_setup_complete: bool,
) -> Result<SetupEntryAdmission, SetupEntryRefusal> {
    let mut progress = SetupEntryPlan::begin(binding, prior_setup_complete)?;
    loop {
        progress = match progress {
            SetupEntryProgress::Effect(effect) => effect.succeeded(),
            SetupEntryProgress::Admitted(admission) => return Ok(admission),
        };
    }
}

fn drive_precommit_cleanup(claim: CleanupBindingClaim) -> Vec<PrecommitCleanupEffect> {
    let mut effects = Vec::new();
    let mut progress = PrecommitCleanupPlan::begin(claim).expect("precommit claim");
    loop {
        match progress {
            PrecommitCleanupProgress::Effect(effect) => {
                effects.push(effect.effect());
                progress = effect.succeeded();
            }
            PrecommitCleanupProgress::Complete(_) => return effects,
        }
    }
}

#[test]
fn cleanup_before_install_forces_exact_setup_rollback() {
    let mut binding = ControlBinding::new().expect("binding");
    let reservation = binding.begin_setup().expect("reservation");
    let claim = binding.claim_cleanup().expect("cleanup claims staging");
    assert!(matches!(claim, CleanupBindingClaim::Setup(_)));
    let prepared = prepare_reserved_setup_rollback(&binding, reservation).expect("prepare");
    assert_eq!(
        commit_prepared_reserved_setup_rollback(prepared, &mut binding),
        crate::session::SetupRollbackDisposition::RemainsClosing
    );
    assert!(matches!(
        binding.state(),
        ControlBindingState::ClosingSetup(_)
    ));
}

#[test]
fn cleanup_after_install_before_locked_suffix_cannot_publish() {
    let mut registry = SessionRegistry::<1>::new();
    let mut binding = ControlBinding::new().expect("binding");
    let (transaction, reservation, installed) = installed_setup(&mut registry, &mut binding);
    let _claim = binding.claim_cleanup().expect("cleanup claim");
    let failure = prepare_installed_setup_publication(
        transaction,
        &registry,
        &binding,
        &TerminalRendezvous::new_inactive(),
        reservation,
        installed,
    )
    .expect_err("ClosingSetup must refuse publication");
    assert_eq!(failure.error(), SessionError::InvalidTransition);
}

#[test]
fn cleanup_cannot_split_core_live_from_binding_active() {
    let mut plan = LockedSetupSuffixPlan::begin();
    while let LockedSetupSuffixProgress::Effect(effect) = plan {
        assert!(!effect.cleanup_may_interleave());
        plan = effect.succeeded();
    }
    let LockedSetupSuffixProgress::Complete(proof) = plan else {
        panic!("suffix must complete")
    };
    assert!(proof.registry_lock_released_only_after_vdo_publication());
}

fn drive_locked_suffix() -> (Vec<LockedSetupSuffixEffect>, LockedSetupSuffixProof) {
    let mut effects = Vec::new();
    let mut progress = LockedSetupSuffixPlan::begin();
    loop {
        match progress {
            LockedSetupSuffixProgress::Effect(effect) => {
                assert!(
                    !effect.cleanup_may_interleave(),
                    "the locked suffix admits no cleanup interleaving"
                );
                effects.push(effect.effect());
                progress = effect.succeeded();
            }
            LockedSetupSuffixProgress::Complete(proof) => return (effects, proof),
        }
    }
}

#[test]
fn locked_suffix_installs_runtime_then_publishes_core_then_the_vdo_flag() {
    let (effects, proof) = drive_locked_suffix();
    assert_eq!(
        effects,
        [
            LockedSetupSuffixEffect::ActivateNativeMountRendezvous,
            LockedSetupSuffixEffect::InstallPendingRuntime,
            LockedSetupSuffixEffect::CommitCoreRingSetupPublication,
            LockedSetupSuffixEffect::TransferLeaseToControlOwner,
            LockedSetupSuffixEffect::PublishBindingPhase,
            LockedSetupSuffixEffect::WriteVdoLocator,
            LockedSetupSuffixEffect::ClearVdoInitializing,
            LockedSetupSuffixEffect::ReleaseRegistryLock,
        ]
    );
    assert!(proof.registry_lock_released_only_after_vdo_publication());
    assert!(
        proof.vdo_locator_written_before_initializing_cleared(),
        "the locator must reach the VDO before the device becomes openable"
    );
    assert!(
        proof.pending_runtime_installed_before_core_live(),
        "a Live session whose cell has no pending runtime is addressable by an \
         ENTER that then has nowhere to park"
    );
}

// ---------------------------------------------------------------------------
// Task 7: shell/root owner movement
// ---------------------------------------------------------------------------

const SHELL: ShellOwnerId = ShellOwnerId::new(0x5158_0001);

/// Install one staging session whose identity is keyed by `mount_lo`, so two
/// calls with different keys yield genuinely different locators.
fn locator_for(mount_lo: u64) -> SessionLocator {
    let mut registry = SessionRegistry::<1>::new();
    let mut binding = ControlBinding::new().expect("binding");
    let reservation = binding.begin_setup().expect("reserve");
    let mut transaction = SetupTransaction::begin(identity_of(MountId {
        lo: mount_lo,
        hi: RANDOM_HIGH,
    }))
    .expect("begin");
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = transaction.stage(stage).map_err(|_| ()).expect("stage");
    }
    let installed = registry
        .install_staging(&transaction, &binding, &reservation)
        .expect("install staging");
    installed.locator()
}

fn owned_locator() -> SessionLocator {
    locator_for(1)
}

fn ready_vdo(shell: ShellOwnerId) -> VdoReadiness {
    VdoReadiness {
        shell,
        device_initializing: true,
        locator_uninitialized: true,
    }
}

#[test]
fn setup_allocation_to_staging_to_live_moves_one_shell_and_root_owner() {
    let locator = owned_locator();
    let mut ownership = SetupOwnership::new();
    assert_eq!(ownership.shell(), ShellOwnerState::Absent);
    assert_eq!(ownership.root(), RootRightState::Absent);

    // Nothing may be branded or published before allocation mints the owner.
    assert_eq!(
        ownership.install_staging(locator),
        Err(OwnershipFault::Fabricated)
    );
    assert_eq!(
        ownership.preflight_publication(locator, ready_vdo(SHELL)),
        Err(OwnershipFault::Fabricated)
    );

    ownership.allocate(SHELL).expect("sole allocation");
    assert_eq!(ownership.shell(), ShellOwnerState::Unpublished(SHELL));
    // The allocation site is audited to occur exactly once.
    assert_eq!(
        ownership.allocate(ShellOwnerId::new(0x9999)),
        Err(OwnershipFault::NotRepeatable)
    );

    ownership
        .install_staging(locator)
        .expect("brand and acquire");
    assert_eq!(
        ownership.shell(),
        ShellOwnerState::Branded { id: SHELL, locator }
    );
    assert_eq!(ownership.root(), RootRightState::Acquired(locator));

    ownership
        .deposit(locator, ready_vdo(SHELL))
        .expect("locked suffix deposit");
    assert_eq!(
        ownership.shell(),
        ShellOwnerState::CellOwned { id: SHELL, locator }
    );
    assert_eq!(ownership.root(), RootRightState::CellOwned(locator));

    // The owner the cell holds is the one allocation returned, and rollback can
    // no longer destroy or release what the cell now owns.
    assert_eq!(
        ownership.destroy_shell(),
        Err(OwnershipFault::NotRepeatable)
    );
    assert_eq!(ownership.release_root(), Err(OwnershipFault::NotRepeatable));
    assert_eq!(ownership.shell_destroy_count(), 0);
    assert_eq!(ownership.root_release_count(), 0);
}

#[test]
fn every_setup_rollback_releases_root_and_destroys_shell_exactly_once() {
    let locator = owned_locator();

    // Reserved-stage rollback: nothing was allocated, so nothing is destroyed.
    let mut reserved = SetupOwnership::new();
    reserved.rollback().expect("reserved rollback");
    assert_eq!(reserved.shell_destroy_count(), 0);
    assert_eq!(reserved.root_release_count(), 0);

    // Allocated but not yet staged: the shell is destroyed, no root exists.
    let mut uninstalled = SetupOwnership::new();
    uninstalled.allocate(SHELL).expect("allocate");
    uninstalled.rollback().expect("uninstalled rollback");
    assert_eq!(uninstalled.shell_destroy_count(), 1);
    assert_eq!(uninstalled.root_release_count(), 0);
    assert_eq!(uninstalled.shell(), ShellOwnerState::Destroyed(SHELL));

    // Installed: both exist and each is consumed exactly once.
    let mut installed = SetupOwnership::new();
    installed.allocate(SHELL).expect("allocate");
    installed.install_staging(locator).expect("stage");
    installed.rollback().expect("installed rollback");
    assert_eq!(installed.shell_destroy_count(), 1);
    assert_eq!(installed.root_release_count(), 1);
    assert_eq!(installed.root(), RootRightState::Released(locator));

    // A second rollback cannot double-free the shell or double-release the root.
    assert_eq!(installed.release_root(), Err(OwnershipFault::NotRepeatable));
    assert_eq!(
        installed.destroy_shell(),
        Err(OwnershipFault::NotRepeatable)
    );
    assert_eq!(installed.shell_destroy_count(), 1);
    assert_eq!(installed.root_release_count(), 1);
}

/// Neither destructor may run against a thing this SETUP never obtained.
///
/// `rollback` guards both calls with a state test, so its own path never
/// reaches these arms. They are what a native unwind that freed from a
/// remembered address rather than from the owner would hit, which is exactly
/// the failure the affine owners exist to make impossible — so each is asserted
/// directly rather than left to a caller that avoids it.
#[test]
fn nothing_may_be_freed_or_released_that_was_never_obtained() {
    let mut fresh = SetupOwnership::new();
    assert_eq!(fresh.destroy_shell(), Err(OwnershipFault::Fabricated));
    assert_eq!(fresh.release_root(), Err(OwnershipFault::Fabricated));
    assert_eq!(fresh.shell_destroy_count(), 0);
    assert_eq!(fresh.root_release_count(), 0);
    assert_eq!(fresh.shell(), ShellOwnerState::Absent);
    assert_eq!(fresh.root(), RootRightState::Absent);

    // Allocation alone mints no root right, so the root destructor is still
    // refused while the shell destructor is now legitimate.
    let mut allocated = SetupOwnership::new();
    allocated.allocate(SHELL).expect("allocate");
    assert_eq!(allocated.release_root(), Err(OwnershipFault::Fabricated));
    assert_eq!(allocated.root_release_count(), 0);
    allocated.destroy_shell().expect("the shell owner exists");
    assert_eq!(allocated.shell_destroy_count(), 1);
}

#[test]
fn publication_refusal_returns_shell_root_and_mount_right_without_mutation() {
    let locator = owned_locator();
    let foreign = locator_for(2);
    assert_ne!(locator, foreign);

    let mut ownership = SetupOwnership::new();
    ownership.allocate(SHELL).expect("allocate");
    ownership.install_staging(locator).expect("stage");
    let before = ownership;

    // A foreign locator is refused and mutates nothing.
    assert_eq!(
        ownership.deposit(foreign, ready_vdo(SHELL)),
        Err(OwnershipFault::WrongLocator)
    );
    assert_eq!(ownership, before, "refusal must be byte-identical");

    // So is a shell that this SETUP never allocated.
    assert_eq!(
        ownership.deposit(locator, ready_vdo(ShellOwnerId::new(0xDEAD))),
        Err(OwnershipFault::UnusableVdo)
    );
    assert_eq!(ownership, before, "refusal must be byte-identical");

    // The mount activation right is likewise returned intact. Preparation is
    // mutation-free, so a refused publication leaves the rendezvous inactive
    // and the same activation can still be prepared, naming the same locator.
    let rendezvous = crate::adapter::lifecycle::MountRendezvous::<(), ()>::new_inactive();
    let first = rendezvous
        .prepare_activation(locator)
        .expect("inactive rendezvous");
    assert_eq!(first.locator(), locator);
    let second = rendezvous
        .prepare_activation(locator)
        .expect("preparation mutated nothing, so it is still available");
    assert_eq!(second.locator(), locator);

    // After all refusals the successful publication still works, proving the
    // refusals consumed nothing.
    ownership
        .deposit(locator, ready_vdo(SHELL))
        .expect("publication still available after refusals");
    assert_eq!(ownership.root(), RootRightState::CellOwned(locator));
}

#[test]
fn publication_refuses_noninitializing_or_foreign_vdo_without_mutation() {
    let locator = owned_locator();
    let mut ownership = SetupOwnership::new();
    ownership.allocate(SHELL).expect("allocate");
    ownership.install_staging(locator).expect("stage");
    let before = ownership;

    // Each unusable-VDO reason is refused on its own, so no single check can
    // stand in for the others.
    let unusable = [
        VdoReadiness {
            shell: SHELL,
            device_initializing: false,
            locator_uninitialized: true,
        },
        VdoReadiness {
            shell: SHELL,
            device_initializing: true,
            locator_uninitialized: false,
        },
        VdoReadiness {
            shell: ShellOwnerId::new(0xBEEF),
            device_initializing: true,
            locator_uninitialized: true,
        },
    ];
    for vdo in unusable {
        assert_eq!(
            ownership.preflight_publication(locator, vdo),
            Err(OwnershipFault::UnusableVdo),
            "unusable VDO {vdo:?} must be refused"
        );
        assert_eq!(
            ownership.deposit(locator, vdo),
            Err(OwnershipFault::UnusableVdo)
        );
        assert_eq!(ownership, before, "refusal must leave the owners untouched");
    }

    ownership
        .preflight_publication(locator, ready_vdo(SHELL))
        .expect("a still-initializing VDO owned by this shell is accepted");
}

#[test]
fn locked_suffix_activates_native_mount_before_core_live() {
    let (effects, proof) = drive_locked_suffix();

    // The proof is derived from the walk, so a reordered roster flips it.
    assert!(
        proof.mount_activated_before_core_live(),
        "a Live cell whose mount rendezvous is still inactive is reachable by \
         terminalization that cannot then take or join the mount"
    );

    let position = |wanted: LockedSetupSuffixEffect| {
        effects
            .iter()
            .position(|effect| *effect == wanted)
            .expect("effect runs in the locked suffix")
    };
    assert!(
        position(LockedSetupSuffixEffect::ActivateNativeMountRendezvous)
            < position(LockedSetupSuffixEffect::CommitCoreRingSetupPublication)
    );
    // The whole publication happens under the one lock hold, before its release.
    assert!(
        position(LockedSetupSuffixEffect::CommitCoreRingSetupPublication)
            < position(LockedSetupSuffixEffect::ReleaseRegistryLock)
    );
    assert_eq!(
        effects
            .iter()
            .filter(|effect| **effect == LockedSetupSuffixEffect::ActivateNativeMountRendezvous)
            .count(),
        1,
        "the mount is activated exactly once"
    );
}

#[test]
fn vdo_locator_is_written_before_device_initializing_is_cleared() {
    // Named for the rule the native suffix depends on: a device whose
    // DO_DEVICE_INITIALIZING is clear can be opened and mounted immediately, so
    // the locator must already be there. The proof reads the walk, and
    // `locked_suffix_proofs_reject_the_orders_they_forbid` drives the two
    // rosters that make it report false.
    let (effects, proof) = drive_locked_suffix();
    assert!(proof.vdo_locator_written_before_initializing_cleared());

    let position = |wanted: LockedSetupSuffixEffect| {
        effects
            .iter()
            .position(|effect| *effect == wanted)
            .expect("effect runs in the locked suffix")
    };
    assert!(
        position(LockedSetupSuffixEffect::WriteVdoLocator)
            < position(LockedSetupSuffixEffect::ClearVdoInitializing)
    );
    // Both are inside the one lock hold, so nothing can observe the device
    // between them through the registry.
    assert!(
        position(LockedSetupSuffixEffect::ClearVdoInitializing)
            < position(LockedSetupSuffixEffect::ReleaseRegistryLock)
    );
    assert_eq!(
        effects
            .iter()
            .filter(|effect| **effect == LockedSetupSuffixEffect::WriteVdoLocator)
            .count(),
        1,
        "the locator is written exactly once"
    );
}

/// Drive an arbitrary suffix roster and return what the proof made of it.
fn proof_of_suffix_roster(roster: [LockedSetupSuffixEffect; 8]) -> LockedSetupSuffixProof {
    let mut progress = LockedSetupSuffixPlan::begin_with_roster(roster);
    loop {
        match progress {
            LockedSetupSuffixProgress::Effect(effect) => progress = effect.succeeded(),
            LockedSetupSuffixProgress::Complete(proof) => return proof,
        }
    }
}

/// Every suffix proof must be observable *failing*.
///
/// The two assertions above run only against `LockedSetupSuffixPlan::EFFECTS`,
/// the one order the proofs were written for. Against that single input a proof
/// hard-coded to `true` is indistinguishable from a proof that reads the walk,
/// so this test feeds each proof the orders it exists to reject.
#[test]
fn locked_suffix_proofs_reject_the_orders_they_forbid() {
    use LockedSetupSuffixEffect as E;

    // Core goes Live while the native mount rendezvous is still inactive.
    let core_live_first = proof_of_suffix_roster([
        E::CommitCoreRingSetupPublication,
        E::ActivateNativeMountRendezvous,
        E::InstallPendingRuntime,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::WriteVdoLocator,
        E::ClearVdoInitializing,
        E::ReleaseRegistryLock,
    ]);
    assert!(
        !core_live_first.mount_activated_before_core_live(),
        "a suffix that goes Live before activating the mount must not prove it did not"
    );
    assert!(core_live_first.registry_lock_released_only_after_vdo_publication());
    assert!(core_live_first.vdo_locator_written_before_initializing_cleared());

    // The mount is never activated at all: the step is replaced, not moved.
    let never_activated = proof_of_suffix_roster([
        E::InstallPendingRuntime,
        E::CommitCoreRingSetupPublication,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::WriteVdoLocator,
        E::ClearVdoInitializing,
        E::ReleaseRegistryLock,
        E::ReleaseRegistryLock,
    ]);
    assert!(
        !never_activated.mount_activated_before_core_live(),
        "an absent mount activation must not satisfy the ordering proof"
    );

    // The registry lock — the linearization point — is released while the VDO
    // still has DO_DEVICE_INITIALIZING set.
    let released_before_vdo = proof_of_suffix_roster([
        E::ActivateNativeMountRendezvous,
        E::InstallPendingRuntime,
        E::CommitCoreRingSetupPublication,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::WriteVdoLocator,
        E::ReleaseRegistryLock,
        E::ClearVdoInitializing,
    ]);
    assert!(
        !released_before_vdo.registry_lock_released_only_after_vdo_publication(),
        "releasing the registry lock before the VDO is published must not prove the opposite"
    );
    assert!(released_before_vdo.mount_activated_before_core_live());

    // The device becomes openable before the locator is written: a MOUNT that
    // arrives in between reads an unwritten field.
    let cleared_before_locator = proof_of_suffix_roster([
        E::ActivateNativeMountRendezvous,
        E::InstallPendingRuntime,
        E::CommitCoreRingSetupPublication,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::ClearVdoInitializing,
        E::WriteVdoLocator,
        E::ReleaseRegistryLock,
    ]);
    assert!(
        !cleared_before_locator.vdo_locator_written_before_initializing_cleared(),
        "clearing the initializing flag first must not prove the locator was there"
    );
    assert!(cleared_before_locator.registry_lock_released_only_after_vdo_publication());

    // The locator is never written at all.
    let never_written = proof_of_suffix_roster([
        E::ActivateNativeMountRendezvous,
        E::InstallPendingRuntime,
        E::CommitCoreRingSetupPublication,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::PublishBindingPhase,
        E::ClearVdoInitializing,
        E::ReleaseRegistryLock,
    ]);
    assert!(!never_written.vdo_locator_written_before_initializing_cleared());

    // Neither ordering step ran, so neither proof may claim it held.
    let neither = proof_of_suffix_roster([
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
        E::TransferLeaseToControlOwner,
        E::PublishBindingPhase,
    ]);
    assert!(!neither.mount_activated_before_core_live());
    assert!(!neither.registry_lock_released_only_after_vdo_publication());
    assert!(!neither.vdo_locator_written_before_initializing_cleared());
}

#[test]
fn unload_admission_closure_refuses_the_suffix_without_mutation() {
    let mut registry = SessionRegistry::<1>::new();
    let mut binding = ControlBinding::new().expect("binding");
    let (transaction, reservation, installed) = installed_setup(&mut registry, &mut binding);
    registry.close_admission();
    let before = binding.state();
    let failure = prepare_installed_setup_publication(
        transaction,
        &registry,
        &binding,
        &TerminalRendezvous::new_inactive(),
        reservation,
        installed,
    )
    .expect_err("closed admission");
    assert_eq!(failure.error(), SessionError::RegistryClosed);
    assert_eq!(binding.state(), before);
}

#[test]
fn setup_tail_releases_admission_then_signals_then_returns_before_outer_control_release() {
    let tail = NativeSetupPlan::SUCCESS_EFFECTS;
    let tail = &tail[tail.len() - 5..];
    assert_eq!(
        tail,
        [
            SetupEffect::EmitSessionPublished,
            SetupEffect::ReleaseSetupAdmission,
            SetupEffect::SignalSetupComplete,
            SetupEffect::ReturnProviderDisposition,
            SetupEffect::OuterReleaseControlRundown,
        ]
    );
}

#[test]
fn closing_setup_cleanup_waits_outer_control_release_before_publishing_closed() {
    let mut binding = ControlBinding::new().expect("binding");
    let _reservation = binding.begin_setup().expect("setup");
    let claim = binding.claim_cleanup().expect("claim");
    let effects = drive_precommit_cleanup(claim);
    let release = effects
        .iter()
        .position(|e| *e == PrecommitCleanupEffect::ReleaseOuterGuard)
        .unwrap();
    let wait = effects
        .iter()
        .position(|e| *e == PrecommitCleanupEffect::WaitFileRundown)
        .unwrap();
    let closed = effects
        .iter()
        .position(|e| *e == PrecommitCleanupEffect::PublishClosedAndTransferLease)
        .unwrap();
    assert!(release < wait && wait < closed);
}

#[test]
fn closing_setup_cleanup_transfers_and_releases_its_own_guard_before_file_rundown_wait() {
    let mut binding = ControlBinding::new().expect("binding");
    let _reservation = binding.begin_setup().expect("setup");
    let claim = binding.claim_cleanup().expect("claim");
    let effects = drive_precommit_cleanup(claim);
    assert_eq!(effects[0], PrecommitCleanupEffect::ReleaseOuterGuard);
    assert!(
        effects
            .iter()
            .position(|e| *e == PrecommitCleanupEffect::SignalSetupCancel)
            .unwrap()
            < effects
                .iter()
                .position(|e| *e == PrecommitCleanupEffect::WaitFileRundown)
                .unwrap()
    );
}

#[test]
fn empty_cleanup_releases_its_own_guard_before_file_rundown_wait() {
    let mut binding = ControlBinding::new().expect("binding");
    let claim = binding.claim_cleanup().expect("claim");
    assert_eq!(
        drive_precommit_cleanup(claim),
        [
            PrecommitCleanupEffect::ReleaseOuterGuard,
            PrecommitCleanupEffect::WaitFileRundown,
            PrecommitCleanupEffect::PublishClosedAndTransferLease,
        ]
    );
}

#[test]
fn setup_epoch_exhaustion_maps_to_integer_overflow_and_zero_information() {
    let mut binding = ControlBinding::exhausted_for_test();
    let refusal = drive_setup_entry(&mut binding, true).expect_err("exhausted");
    assert_eq!(refusal.kind(), SetupEntryRefusalKind::IntegerOverflow);
    assert_eq!(refusal.information(), 0);
}

#[test]
fn maximum_generation_staging_rollback_retires_and_permanently_closes_access_rundown() {
    let mut registry = SessionRegistry::<1>::new();
    registry.set_generation_for_test(0, u64::MAX - 1);
    let mut binding = ControlBinding::new().expect("binding");
    let (transaction, reservation, installed) = installed_setup(&mut registry, &mut binding);
    assert_eq!(installed.locator().generation(), u64::MAX);
    let prepared = prepare_installed_setup_rollback(
        transaction,
        SetupFailure::NativeEffect,
        &registry,
        &binding,
        reservation,
        installed,
    )
    .unwrap_or_else(|_| panic!("installed rollback preflight"));
    let (_, disposition, _) =
        commit_prepared_installed_setup_rollback(prepared, &mut registry, &mut binding);
    assert_eq!(disposition, SlotDisposition::Retired);
    let plan = InstalledRollbackTailPlan::for_disposition(disposition);
    assert_eq!(
        plan.effects(),
        &[InstalledRollbackTailEffect::PermanentlyCloseAccessRundown]
    );
}

#[test]
fn create_acquires_control_context_lease_before_fscontext_publication() {
    assert_eq!(
        ControlContextCreatePlan::EFFECTS,
        [
            ControlContextCreateEffect::AcquireLease,
            ControlContextCreateEffect::AllocateAndInitialize,
            ControlContextCreateEffect::CaptureRequestor,
            ControlContextCreateEffect::PublishFsContext,
        ]
    );
}

#[test]
fn create_rollback_releases_control_context_lease_once() {
    let rollback =
        ControlContextCreatePlan::rollback_after(ControlContextCreateEffect::CaptureRequestor);
    assert_eq!(
        rollback
            .effects()
            .iter()
            .filter(|effect| **effect == ControlContextCreateRollbackEffect::ReleaseLease)
            .count(),
        1
    );
}

/// A lease nobody else owns is CLOSE's to adopt; every other pair is untouched.
///
/// The whole table rather than the one interesting pair, so an arm that starts
/// adopting something else fails here rather than in a review.
#[test]
fn only_an_uninstalled_lease_is_adopted() {
    use ControlContextCloseOwnership as O;
    let rows = [
        ((O::Lease, true), O::CloseRight),
        ((O::Lease, false), O::Lease),
        ((O::CellOwned, true), O::CellOwned),
        ((O::CellOwned, false), O::CellOwned),
        ((O::CloseRight, true), O::CloseRight),
        ((O::CloseRight, false), O::CloseRight),
    ];
    for ((ownership, holds_no_installation), expected) in rows {
        assert_eq!(
            ownership.adopt_unused_lease(holds_no_installation),
            expected,
            "{ownership:?} with holds_no_installation={holds_no_installation}",
        );
    }
}

/// The adopted answer is one the close plan actually accepts, in the safe order.
///
/// Without this the adoption could produce a value `begin` still refuses, and
/// the table above would pass while CLOSE went on freeing nothing.
#[test]
fn an_adopted_lease_begins_the_close_plan_in_the_safe_order() {
    let adopted = ControlContextCloseOwnership::Lease.adopt_unused_lease(true);
    assert!(adopted.may_free(), "an adopted lease must be freeable");
    let (steps, freed_first) = drive_control_context_close(adopted);
    assert_eq!(
        close_effect_order(&steps),
        [
            ControlContextCloseEffect::DetachFsContext,
            ControlContextCloseEffect::DestroyAndFreeContext,
            ControlContextCloseEffect::ReleaseControlContextAdmission,
        ]
    );
    assert!(
        freed_first,
        "an adopted lease releases the admission only after the free",
    );
}

#[test]
fn close_frees_only_after_terminal_or_precommit_hands_back_close_right() {
    assert!(ControlContextCloseOwnership::CloseRight.may_free());
    assert!(!ControlContextCloseOwnership::Lease.may_free());
    assert!(!ControlContextCloseOwnership::CellOwned.may_free());
}

/// CLOSE does not free a record CLEANUP has not acknowledged.
///
/// The approved design: "CLOSE alone mutation-free preflights the exact
/// Closed/acknowledged lifetime". Round 17 answered `CloseRight` here to paper
/// over a CLEANUP that never acknowledged, and the process-loss and unload scans
/// then dereferenced the freed context (native review N17-1). The
/// acknowledgement is now reachable (`continue_cleanup`), and
/// `close_choreography` shows the only CLOSE that can still observe `Completed`
/// is one whose CLEANUP was refused its stack expansion, where the design leaves
/// the context cell-owned.
#[test]
fn close_does_not_free_a_record_cleanup_has_not_acknowledged() {
    assert!(
        !ControlContextCloseOwnership::for_lifetime(ControlContextLifetimeKind::Completed)
            .may_free(),
        "an unacknowledged Completed record is not CLOSE's to free",
    );
}

/// The classification is total, and exactly one lifetime may free.
///
/// Stated as the whole mapping rather than one variant, so adding a lifetime
/// without deciding it fails to compile, and re-deciding an existing one fails
/// here.
#[test]
fn every_control_context_lifetime_has_exactly_one_close_ownership() {
    use ControlContextLifetimeKind as K;
    let rows = [
        (K::Lease, ControlContextCloseOwnership::Lease),
        (K::LiveCellOwned, ControlContextCloseOwnership::CellOwned),
        (K::Completed, ControlContextCloseOwnership::CellOwned),
        (K::Close, ControlContextCloseOwnership::CloseRight),
        (K::BlockedCellOwned, ControlContextCloseOwnership::CellOwned),
    ];
    for (kind, expected) in rows {
        assert_eq!(
            ControlContextCloseOwnership::for_lifetime(kind),
            expected,
            "{kind:?} is classified wrongly",
        );
    }
    assert_eq!(
        rows.iter()
            .filter(|(k, _)| ControlContextCloseOwnership::for_lifetime(*k).may_free())
            .map(|(k, _)| *k)
            .collect::<Vec<_>>(),
        vec![K::Close],
        "exactly the acknowledged lifetime may free",
    );
}

/// Only the acknowledged lifetime drives the whole three-effect close sequence.
///
/// `for_lifetime` answering `CloseRight` is only half the property: the plan
/// still has to accept it. Without this, a classification the plan refused
/// would leave the context leaked in a different place. And an unacknowledged
/// record must not even begin the free.
#[test]
fn only_an_acknowledged_lifetime_drives_the_full_close_sequence() {
    let ownership = ControlContextCloseOwnership::for_lifetime(ControlContextLifetimeKind::Close);
    let (steps, freed_first) = drive_control_context_close(ownership);
    assert_eq!(
        close_effect_order(&steps),
        [
            ControlContextCloseEffect::DetachFsContext,
            ControlContextCloseEffect::DestroyAndFreeContext,
            ControlContextCloseEffect::ReleaseControlContextAdmission,
        ]
    );
    assert!(
        freed_first,
        "the admission release must follow an actual free",
    );
    assert!(
        ControlContextClosePlan::begin(ControlContextCloseOwnership::for_lifetime(
            ControlContextLifetimeKind::Completed
        ))
        .is_err(),
        "an unacknowledged Completed record must not even begin the free",
    );
}

/// Drive the CLOSE sequence, recording each effect together with whether the
/// context was already freed at the moment that effect ran.
///
/// The helper asserts nothing: each test below owns its own property, so a
/// failure names the rule that actually broke instead of tripping a shared
/// guard first.
fn drive_control_context_close(
    ownership: ControlContextCloseOwnership,
) -> (Vec<(ControlContextCloseEffect, bool)>, bool) {
    let mut steps = Vec::new();
    let mut progress = ControlContextClosePlan::begin(ownership).expect("close right may free");
    loop {
        match progress {
            ControlContextCloseProgress::Effect(pending) => {
                steps.push((pending.effect(), pending.context_freed()));
                progress = pending.succeeded();
            }
            ControlContextCloseProgress::Complete(completion) => {
                return (steps, completion.freed_before_admission_release());
            }
        }
    }
}

fn close_effect_order(
    steps: &[(ControlContextCloseEffect, bool)],
) -> Vec<ControlContextCloseEffect> {
    steps.iter().map(|(effect, _)| *effect).collect()
}

#[test]
fn close_detaches_then_frees_then_releases_control_context_admission() {
    let (steps, freed_first) =
        drive_control_context_close(ControlContextCloseOwnership::CloseRight);
    assert_eq!(
        close_effect_order(&steps),
        [
            ControlContextCloseEffect::DetachFsContext,
            ControlContextCloseEffect::DestroyAndFreeContext,
            ControlContextCloseEffect::ReleaseControlContextAdmission,
        ]
    );
    assert!(freed_first);

    // Only CLOSE may free; the two cell-owned lifetimes cannot even start the
    // sequence, so no partial run can detach a context they do not own.
    for ownership in [
        ControlContextCloseOwnership::Lease,
        ControlContextCloseOwnership::CellOwned,
    ] {
        assert!(ControlContextClosePlan::begin(ownership).is_err());
    }
}

#[test]
fn unload_cannot_pass_control_context_rundown_before_close_free() {
    let (steps, _) = drive_control_context_close(ControlContextCloseOwnership::CloseRight);

    // The release step must itself observe a freed context. This is the
    // property unload depends on: it waits on control_context_admission, so a
    // release that runs while the context is still reachable lets unload free
    // callback-visible state out from under a live FsContext.
    let (_, freed_at_release) = steps
        .iter()
        .find(|(effect, _)| *effect == ControlContextCloseEffect::ReleaseControlContextAdmission)
        .expect("admission release runs");
    assert!(
        *freed_at_release,
        "unload could observe control-context rundown zero while the context is still reachable"
    );

    let effects = close_effect_order(&steps);
    let position = |wanted: ControlContextCloseEffect| {
        effects
            .iter()
            .position(|effect| *effect == wanted)
            .expect("effect runs")
    };
    assert!(
        position(ControlContextCloseEffect::DetachFsContext)
            < position(ControlContextCloseEffect::DestroyAndFreeContext),
        "FsContext must be detached before the free"
    );
    assert_eq!(
        effects
            .iter()
            .filter(|effect| **effect == ControlContextCloseEffect::ReleaseControlContextAdmission)
            .count(),
        1,
        "the embedded lease is released exactly once"
    );
}

/// Drive an arbitrary CLOSE roster, recording per-step freed observations.
fn drive_control_context_close_roster(
    roster: [ControlContextCloseEffect; 3],
) -> (Vec<(ControlContextCloseEffect, bool)>, bool) {
    let mut steps = Vec::new();
    let mut progress = ControlContextClosePlan::begin_with_roster(
        ControlContextCloseOwnership::CloseRight,
        roster,
    )
    .expect("close right may free");
    loop {
        match progress {
            ControlContextCloseProgress::Effect(pending) => {
                steps.push((pending.effect(), pending.context_freed()));
                progress = pending.succeeded();
            }
            ControlContextCloseProgress::Complete(completion) => {
                return (steps, completion.freed_before_admission_release());
            }
        }
    }
}

/// The CLOSE proofs must be observable *failing*.
///
/// `close_detaches_then_frees_then_releases_control_context_admission` and
/// `unload_cannot_pass_control_context_rundown_before_close_free` both run only
/// against the one production roster, where every proof is true. This test
/// supplies the orders those proofs exist to reject, so a `context_freed` or
/// `freed_before_admission_release` that stopped reading the roster is visible.
#[test]
fn close_proofs_reject_the_orders_they_forbid() {
    use ControlContextCloseEffect as E;

    // Admission is released first: unload can then observe a rundown of zero
    // while FsContext still names a live context.
    let (steps, freed_first) = drive_control_context_close_roster([
        E::ReleaseControlContextAdmission,
        E::DetachFsContext,
        E::DestroyAndFreeContext,
    ]);
    assert!(
        !freed_first,
        "a release-first sequence must not prove the context was freed first"
    );
    let (_, freed_at_release) = steps
        .iter()
        .find(|(effect, _)| *effect == E::ReleaseControlContextAdmission)
        .expect("admission release runs");
    assert!(
        !freed_at_release,
        "the release step ran before any free, so it must not observe a freed context"
    );

    // The free never runs: detach and release alone must not satisfy either
    // proof.
    let (steps, freed_first) = drive_control_context_close_roster([
        E::DetachFsContext,
        E::ReleaseControlContextAdmission,
        E::ReleaseControlContextAdmission,
    ]);
    assert!(
        !freed_first,
        "an absent free must not satisfy the freed-before-release proof"
    );
    assert!(
        steps.iter().all(|(_, freed)| !freed),
        "no step may observe a free that never ran"
    );

    // The production order is the only one that satisfies both, and the last
    // step observes the free that preceded it.
    let (steps, freed_first) = drive_control_context_close_roster([
        E::DetachFsContext,
        E::DestroyAndFreeContext,
        E::ReleaseControlContextAdmission,
    ]);
    assert!(freed_first);
    assert_eq!(
        steps.iter().map(|(_, freed)| *freed).collect::<Vec<_>>(),
        [false, false, true]
    );
}

#[test]
fn empty_and_closing_setup_cleanup_move_lease_into_close_right() {
    for setup_started in [false, true] {
        let mut binding = ControlBinding::new().expect("binding");
        if setup_started {
            let _reservation = binding.begin_setup().expect("setup");
        }
        let claim = binding.claim_cleanup().expect("claim");
        let effects = drive_precommit_cleanup(claim);
        assert_eq!(
            effects.last(),
            Some(&PrecommitCleanupEffect::PublishClosedAndTransferLease)
        );
    }
}

#[test]
fn setup_publication_moves_lease_into_control_owner_without_cloning() {
    let mut registry = SessionRegistry::<1>::new();
    let mut binding = ControlBinding::new().expect("binding");
    let (transaction, reservation, installed) = installed_setup(&mut registry, &mut binding);
    let locator = installed.locator();
    let mut terminal = TerminalRendezvous::new_inactive();
    let prepared = prepare_installed_setup_publication(
        transaction,
        &registry,
        &binding,
        &terminal,
        reservation,
        installed,
    )
    .expect("publication preflight");
    let live = unsafe { crate::session::commit_prepared_registry_live(prepared, &mut registry) };
    let (published_locator, registry_lease, strong_reference, binding_right) = live.into_parts();
    assert_eq!(published_locator, locator);
    let terminal_right =
        unsafe { crate::session::commit_prepared_binding_active(binding_right, &mut binding) };
    let proof = unsafe {
        crate::session::commit_prepared_terminal_activation(terminal_right, &mut terminal)
    };
    assert_eq!(proof.locator(), locator);
    assert!(matches!(binding.state(), ControlBindingState::Active(current) if current == locator));
    // Both authorities came out of the one publication and name the exact
    // published locator; neither was cloned from the other.
    assert_eq!(registry_lease.locator(), locator);
    assert_eq!(strong_reference.locator(), locator);
}

#[test]
fn pre_identity_failure_consumes_exact_reservation_and_reopens_epoch() {
    let mut binding = ControlBinding::new().expect("binding");
    let reservation = binding.begin_setup().expect("reservation");
    let prepared = prepare_reserved_setup_rollback(&binding, reservation).expect("prepare");
    let disposition = commit_prepared_reserved_setup_rollback(prepared, &mut binding);
    assert_eq!(
        disposition,
        crate::session::SetupRollbackDisposition::Reopened(SetupEpochCursor::next_for_test(2))
    );
}

#[test]
fn pre_identity_cleanup_race_preserves_closing_setup() {
    let mut binding = ControlBinding::new().expect("binding");
    let reservation = binding.begin_setup().expect("reservation");
    let _claim = binding.claim_cleanup().expect("claim");
    let prepared = prepare_reserved_setup_rollback(&binding, reservation).expect("prepare");
    assert_eq!(
        commit_prepared_reserved_setup_rollback(prepared, &mut binding),
        crate::session::SetupRollbackDisposition::RemainsClosing
    );
}

#[test]
fn retry_cannot_clear_setup_complete_before_prior_tail_signal() {
    let mut binding = ControlBinding::new().expect("binding");
    let refusal = drive_setup_entry(&mut binding, false).expect_err("prior tail incomplete");
    assert_eq!(refusal.kind(), SetupEntryRefusalKind::PriorSetupIncomplete);
    assert!(matches!(binding.state(), ControlBindingState::Empty(_)));
    let admission = drive_setup_entry(&mut binding, true).expect("signaled completion admits");
    assert!(matches!(binding.state(), ControlBindingState::Staging(_)));
    let (_, effects) = admission.into_parts();
    assert_eq!(
        effects,
        [
            SetupEntryEffect::ClearSetupCancel,
            SetupEntryEffect::ClearSetupComplete
        ]
    );
}
