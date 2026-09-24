// TEST: the lifecycle matrices use `expect` and `expect_err` to name exact
// affine transition outcomes; production keeps the crate-wide denial.
#![allow(clippy::expect_used)]

use super::*;
use crate::effect::{Effect, EffectContext, WaitTarget, may_emit};
use crate::lockrank::{LockOrderError, LockRank};
use crate::session::{
    ControlBinding, PublishedSession, SessionLocator, SessionRegistry, SetupStage,
    SetupTransaction, StrongSessionRef, TerminalReason, TerminalRendezvous,
    TerminalRendezvousOutcome, TerminalResult, publish_installed_setup_for_test,
};
use crate::volume::{DismountEffect, MountEffect};
use fsring_abi::validate::SessionIdentity;
use fsring_abi::{BootInstanceId, MountId};

fn identity(n: u64) -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: n, hi: 9 },
        boot_instance_id: BootInstanceId { lo: 7, hi: 11 },
        session_epoch: 1,
    }
}

#[test]
fn delete_mirror_requires_the_native_cell_to_reach_deleting() {
    let requested = SessionLocator::from_parts_for_test(1, 4, identity(12));

    assert!(
        !native_delete_mirror_matches(
            NativeCellPhase::Removing,
            requested.generation(),
            Some(requested.identity()),
            true,
            requested,
        ),
        "Removing is still the pre-deposit phase and cannot authorize destruction"
    );
    assert!(native_delete_mirror_matches(
        NativeCellPhase::Deleting,
        requested.generation(),
        Some(requested.identity()),
        true,
        requested,
    ));
}

fn publish(registry: &mut SessionRegistry<2>, n: u64) -> (PublishedSession, TerminalRendezvous) {
    let id = identity(n);
    let mut binding = ControlBinding::new().expect("binding ID capacity");
    let reservation = binding.begin_setup().expect("fresh binding");
    let mut transaction = SetupTransaction::begin(id).expect("valid identity");
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = transaction.stage(stage).expect("strict setup stage");
    }
    let installed = registry
        .install_staging(&transaction, &binding, &reservation)
        .expect("free registry cell");
    transaction = transaction
        .stage(SetupStage::ReferencesInstalled)
        .expect("installed references");
    let mut terminal = TerminalRendezvous::new_inactive();
    let published = publish_installed_setup_for_test(
        transaction,
        registry,
        &mut binding,
        &mut terminal,
        reservation,
        installed,
    )
    .expect("coupled publication");
    (published, terminal)
}

/// The same publication, keeping the control binding the terminal claim needs.
fn publish_with_binding(
    registry: &mut SessionRegistry<2>,
    n: u64,
) -> (PublishedSession, TerminalRendezvous, ControlBinding) {
    let id = identity(n);
    let mut binding = ControlBinding::new().expect("binding ID capacity");
    let reservation = binding.begin_setup().expect("fresh binding");
    let mut transaction = SetupTransaction::begin(id).expect("valid identity");
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = transaction.stage(stage).expect("strict setup stage");
    }
    let installed = registry
        .install_staging(&transaction, &binding, &reservation)
        .expect("free registry cell");
    transaction = transaction
        .stage(SetupStage::ReferencesInstalled)
        .expect("installed references");
    let mut terminal = TerminalRendezvous::new_inactive();
    let published = publish_installed_setup_for_test(
        transaction,
        registry,
        &mut binding,
        &mut terminal,
        reservation,
        installed,
    )
    .expect("coupled publication");
    (published, terminal, binding)
}

fn live_reference() -> (SessionRegistry<2>, SessionLocator, StrongSessionRef) {
    let mut registry = SessionRegistry::<2>::new();
    let (published, _) = publish(&mut registry, 1);
    let (locator, _lease, reference) = published.into_parts();
    (registry, locator, reference)
}

fn present_mount_for(
    identity_number: u64,
) -> (
    MountRendezvous<u32, u32>,
    SessionRegistry<2>,
    SessionLocator,
) {
    let mut registry = SessionRegistry::<2>::new();
    let (published, _) = publish(&mut registry, identity_number);
    let (locator, _lease, reference) = published.into_parts();
    let owner = MountOwner::try_new(locator, reference, 0xD00D, 0xBEEF)
        .expect("the reference is branded for the same cell");
    let mut mount = MountRendezvous::new_inactive();
    mount.activate(locator).expect("inactive mount activates");
    mount
        .install(owner)
        .expect("first mount generation installs");
    (mount, registry, locator)
}

fn present_mount() -> (
    MountRendezvous<u32, u32>,
    SessionRegistry<2>,
    SessionLocator,
) {
    present_mount_for(1)
}

fn owner_claim(
    mount: &mut MountRendezvous<u32, u32>,
    locator: SessionLocator,
) -> (MountOwner<u32, u32>, MountTeardownRight) {
    match mount
        .take_or_join(ExpectedMountTeardown::Owner {
            locator,
            mount_generation: 1,
        })
        .expect("present mount has one owner")
    {
        MountClaim::Owner {
            owner,
            teardown,
            expected,
        } => {
            assert_eq!(
                expected,
                ExpectedMountTeardown::Owner {
                    locator,
                    mount_generation: 1,
                }
            );
            (owner, teardown)
        }
        _ => panic!("present mount must yield its owner"),
    }
}

fn signal_done(
    mount: &mut MountRendezvous<u32, u32>,
    right: MountTeardownRight,
) -> MountDrainRight {
    let publication = mount.publish_done(right).expect("owner publishes Done");
    let mut called = false;
    // SAFETY: the callback models one synchronous KeSetEvent and returns.
    let acknowledgement = unsafe {
        publication.signal_then_ack(|_| {
            assert!(!called);
            called = true;
        })
    };
    assert!(called);
    mount
        .acknowledge_done_signal(acknowledgement)
        .expect("the same cell acknowledges the signal")
}

fn convert_join(
    mount: &mut MountRendezvous<u32, u32>,
    ticket: MountJoinTicket,
) -> MountResetJoinTicket {
    let conversion = mount.release_join(ticket).expect("Done join converts");
    let mut signals = 0u8;
    // SAFETY: the callback is synchronous and signals at most once when the
    // conversion owns the last-ordinary-waiter token.
    let acknowledgement = unsafe {
        conversion.signal_then_ack(|_| {
            signals = signals.saturating_add(1);
        })
    };
    assert!(signals <= 1);
    mount
        .acknowledge_join_signal(acknowledgement)
        .expect("the same cell acknowledges the conversion")
}

fn reset_owner(mount: &mut MountRendezvous<u32, u32>, drain: MountDrainRight) -> MountResetProof {
    let prepared = mount.poll_drain(drain).expect("ordinary waiters drained");
    let publication = mount.finish_reset(prepared).expect("reset publishes");
    let mut called = false;
    // SAFETY: the callback models one synchronous reset-complete signal.
    let acknowledgement = unsafe { publication.signal_then_ack(|_| called = true) };
    assert!(called);
    mount
        .acknowledge_reset_signal(acknowledgement)
        .expect("reset signal acknowledged")
}

fn release_reset_join(
    mount: &mut MountRendezvous<u32, u32>,
    ticket: MountResetJoinTicket,
) -> JoinedMountResetProof {
    let release = mount
        .finish_joined_reset(ticket)
        .expect("stored reset generation completes the join");
    let mut signals = 0u8;
    // SAFETY: the callback synchronously signals only for the last reset
    // waiter, exactly as represented by the bundle.
    let acknowledgement = unsafe {
        release.signal_then_ack(|_| {
            signals = signals.saturating_add(1);
        })
    };
    assert!(signals <= 1);
    mount
        .acknowledge_reset_join_signal(acknowledgement)
        .expect("reset-join signal acknowledged")
}

#[test]
fn resolver_projects_only_exact_live_generation_after_rundown() {
    let (_registry, locator, _reference) = live_reference();
    let observation = |locator, phase, access_rundown_acquired| CellObservation {
        locator,
        phase,
        access_rundown_acquired,
    };
    let stale = SessionLocator::from_parts_for_test(
        locator.slot_index(),
        locator.generation().saturating_add(1),
        locator.identity(),
    );
    for (requested, observed, rundown, want) in [
        (
            locator,
            Some(observation(locator, NativeCellPhase::Live, true)),
            true,
            ResolveDecision::ProjectSession,
        ),
        (
            stale,
            Some(observation(locator, NativeCellPhase::Live, true)),
            true,
            ResolveDecision::Reject,
        ),
        (
            locator,
            Some(observation(locator, NativeCellPhase::Removing, true)),
            true,
            ResolveDecision::Reject,
        ),
        (
            locator,
            Some(observation(locator, NativeCellPhase::Live, false)),
            true,
            ResolveDecision::Reject,
        ),
        (
            locator,
            Some(observation(locator, NativeCellPhase::Live, true)),
            false,
            ResolveDecision::Reject,
        ),
        (locator, None, true, ResolveDecision::Reject),
    ] {
        assert_eq!(decide_resolve(requested, observed, rundown), want);
    }
}

// ---------------------------------------------------------------------------
// The ordered access resolution
// ---------------------------------------------------------------------------

/// Drive a resolver roster, refusing at the step whose name matches `refuse_at`.
fn drive_resolve(
    roster: [ResolveStep; 8],
    refuse_at: Option<(ResolveStep, ResolveRejection)>,
) -> (Vec<ResolveStep>, Result<ResolveProof, ResolveRefusal>) {
    let mut ran = Vec::new();
    let mut progress = ResolvePlan::begin_with_roster(roster);
    loop {
        match progress {
            ResolveProgress::Step(pending) => {
                ran.push(pending.step());
                progress = match refuse_at {
                    Some((step, reason)) if step == pending.step() => pending.refused(reason),
                    _ => pending.succeeded(),
                };
            }
            ResolveProgress::Resolved(proof) => return (ran, Ok(proof)),
            ResolveProgress::Refused(refusal) => return (ran, Err(refusal)),
        }
    }
}

#[test]
fn access_rundown_precedes_registry_revalidation_and_pointer_projection() {
    let (ran, outcome) = drive_resolve(ResolvePlan::STEPS, None);
    // Spelled out rather than compared against `ResolvePlan::STEPS`: an
    // assertion written from the same constant it checks agrees with any
    // reordering of that constant.
    assert_eq!(
        ran,
        [
            ResolveStep::BoundsCheckLocator,
            ResolveStep::AcquireAccessRundown,
            ResolveStep::AcquireRegistryLock,
            ResolveStep::ValidateCoreLive,
            ResolveStep::ValidateCellIdentity,
            ResolveStep::ValidateNativeOwnerSlots,
            ResolveStep::ProjectSessionPointer,
            ResolveStep::ReleaseRegistryLock,
        ]
    );
    let proof = outcome.map_err(|_| ()).expect("the exact order resolves");

    assert!(
        proof.rundown_acquired_before_lock(),
        "the rundown must be held before the lock, or the lock drop opens a \
         window where the shell can be freed"
    );
    assert!(proof.rundown_acquired_before_projection());
    assert!(
        proof.validated_before_projection(),
        "core Live, cell identity, and owner slots are all preconditions of the \
         projection, not observations made after it"
    );
    assert!(
        proof.projected_before_lock_release(),
        "the pointer is copied while the lock still pins the cell"
    );
    assert!(
        proof.rundown_retained(),
        "a resolved access owns the rundown; only the guard's Drop releases it"
    );
}

#[test]
fn failed_generation_revalidation_releases_rundown_once() {
    // Every refusal point that can be reached after the rundown is taken.
    for (step, reason) in [
        (ResolveStep::ValidateCoreLive, ResolveRejection::NotLive),
        (
            ResolveStep::ValidateCellIdentity,
            ResolveRejection::StaleCell,
        ),
        (
            ResolveStep::ValidateNativeOwnerSlots,
            ResolveRejection::MissingOwners,
        ),
    ] {
        let (ran, outcome) = drive_resolve(ResolvePlan::STEPS, Some((step, reason)));
        let refusal = outcome.map(|_| ()).expect_err("this step refuses");
        assert_eq!(refusal.reason(), reason);
        assert!(
            refusal.rundown_balanced(),
            "{step:?} must release the rundown exactly once"
        );
        assert!(refusal.lock_balanced(), "{step:?} must give back the lock");
        assert!(
            !refusal.projected(),
            "{step:?} must not have projected a session pointer"
        );
        assert!(
            !ran.contains(&ResolveStep::ProjectSessionPointer),
            "{step:?} refused before the projection step could run"
        );
    }

    // The two refusals reachable before the rundown exists release nothing.
    let (ran, outcome) = drive_resolve(
        ResolvePlan::STEPS,
        Some((
            ResolveStep::BoundsCheckLocator,
            ResolveRejection::OutOfRange,
        )),
    );
    let refusal = outcome.map(|_| ()).expect_err("out of range refuses");
    assert_eq!(ran, [ResolveStep::BoundsCheckLocator]);
    assert!(refusal.rundown_balanced());
    assert!(refusal.lock_balanced());
    assert!(!refusal.projected());

    let (_, outcome) = drive_resolve(
        ResolvePlan::STEPS,
        Some((
            ResolveStep::AcquireAccessRundown,
            ResolveRejection::RundownRefused,
        )),
    );
    let refusal = outcome.map(|_| ()).expect_err("a draining rundown refuses");
    assert_eq!(refusal.reason(), ResolveRejection::RundownRefused);
    assert!(
        refusal.rundown_balanced(),
        "a rundown that was never acquired must not be released"
    );
    assert!(!refusal.projected());
}

/// The two proofs the native unwind actually consumes.
///
/// `releases_lock` and `releases_rundown` are not decoration: the production
/// resolver performs exactly the releases they name, so a mutation that made
/// either always-false would leak a rundown forever and always-true would
/// release one that was never taken. Nothing else in this file observes them,
/// which is how they would have stayed unmeasured.
#[test]
fn the_unwind_the_native_resolver_performs_is_the_one_the_model_names() {
    // Refused before the rundown exists: nothing to give back.
    for (step, reason) in [
        (
            ResolveStep::BoundsCheckLocator,
            ResolveRejection::OutOfRange,
        ),
        (
            ResolveStep::AcquireAccessRundown,
            ResolveRejection::RundownRefused,
        ),
    ] {
        let (_, outcome) = drive_resolve(ResolvePlan::STEPS, Some((step, reason)));
        let refusal = outcome.map(|_| ()).expect_err("this step refuses");
        assert!(
            !refusal.releases_rundown(),
            "{step:?} runs before the acquire, so the unwind must release nothing"
        );
        assert!(
            !refusal.releases_lock(),
            "{step:?} runs before the lock is taken"
        );
    }

    // Refused after the rundown exists but before the lock: exactly one
    // release, and not a lock release.
    let (_, outcome) = drive_resolve(
        [
            ResolveStep::BoundsCheckLocator,
            ResolveStep::AcquireAccessRundown,
            ResolveStep::ValidateCoreLive,
            ResolveStep::AcquireRegistryLock,
            ResolveStep::ValidateCellIdentity,
            ResolveStep::ValidateNativeOwnerSlots,
            ResolveStep::ProjectSessionPointer,
            ResolveStep::ReleaseRegistryLock,
        ],
        Some((ResolveStep::ValidateCoreLive, ResolveRejection::NotLive)),
    );
    let refusal = outcome.map(|_| ()).expect_err("core validation refuses");
    assert!(refusal.releases_rundown());
    assert!(
        !refusal.releases_lock(),
        "no lock was taken, so the unwind must not release one"
    );

    // Refused after both: both come back, in that order.
    for (step, reason) in [
        (
            ResolveStep::ValidateCellIdentity,
            ResolveRejection::StaleCell,
        ),
        (
            ResolveStep::ValidateNativeOwnerSlots,
            ResolveRejection::MissingOwners,
        ),
    ] {
        let (_, outcome) = drive_resolve(ResolvePlan::STEPS, Some((step, reason)));
        let refusal = outcome.map(|_| ()).expect_err("this step refuses");
        assert!(refusal.releases_rundown(), "{step:?} owes the rundown back");
        assert!(refusal.releases_lock(), "{step:?} owes the lock back");
    }
}

/// The success-side proofs, observed at their failing value.
///
/// `rundown_retained` and `projected` are the two the resolved path and the
/// refused path respectively depend on, and both are trivially true on every
/// roster that completes normally.
#[test]
fn the_retained_rundown_and_absent_projection_proofs_can_both_report_false() {
    use ResolveStep as S;

    // A roster that gives the rundown back before completing cannot claim to
    // have retained it. `ReleaseRegistryLock` twice stands in for a walk whose
    // last act is a release rather than a projection.
    let (_, outcome) = drive_resolve(
        [
            S::BoundsCheckLocator,
            S::AcquireRegistryLock,
            S::ValidateCoreLive,
            S::ValidateCellIdentity,
            S::ValidateNativeOwnerSlots,
            S::ProjectSessionPointer,
            S::ReleaseRegistryLock,
            S::ReleaseRegistryLock,
        ],
        None,
    );
    let proof = outcome.map_err(|_| ()).expect("the walk completes");
    assert!(
        !proof.rundown_retained(),
        "a walk that never acquired the rundown cannot have retained it"
    );

    // A refusal taken *after* the projection reports that it projected, which
    // is what makes `!projected()` load-bearing on the real refusal points.
    let (_, outcome) = drive_resolve(
        ResolvePlan::STEPS,
        Some((
            ResolveStep::ReleaseRegistryLock,
            ResolveRejection::StaleCell,
        )),
    );
    let refusal = outcome.map(|_| ()).expect_err("the last step refuses");
    assert!(
        refusal.projected(),
        "this refusal came after the projection, so the proof must say so"
    );
    assert!(refusal.rundown_balanced());
}

/// Every resolver proof must be observable *failing*.
///
/// The proofs above are only ever evaluated against `ResolvePlan::STEPS`, the
/// one order they were written for, where each is true. Against that single
/// input a proof hard-coded to `true` grades identically to one that reads the
/// walk, so this test supplies the orders each proof exists to reject.
#[test]
fn resolver_proofs_reject_the_orders_they_forbid() {
    use ResolveStep as S;

    // The pointer is read before the rundown that keeps it alive is held, and
    // before the registry has been asked whether the locator is still Live.
    let (_, outcome) = drive_resolve(
        [
            S::BoundsCheckLocator,
            S::AcquireRegistryLock,
            S::ProjectSessionPointer,
            S::AcquireAccessRundown,
            S::ValidateCoreLive,
            S::ValidateCellIdentity,
            S::ValidateNativeOwnerSlots,
            S::ReleaseRegistryLock,
        ],
        None,
    );
    let proof = outcome.map_err(|_| ()).expect("the walk completes");
    assert!(!proof.rundown_acquired_before_lock());
    assert!(!proof.rundown_acquired_before_projection());
    assert!(!proof.validated_before_projection());
    assert!(proof.projected_before_lock_release());

    // The lock is dropped before the pointer is copied out, so the cell could
    // be reused between the check and the read.
    let (_, outcome) = drive_resolve(
        [
            S::BoundsCheckLocator,
            S::AcquireAccessRundown,
            S::AcquireRegistryLock,
            S::ValidateCoreLive,
            S::ValidateCellIdentity,
            S::ValidateNativeOwnerSlots,
            S::ReleaseRegistryLock,
            S::ProjectSessionPointer,
        ],
        None,
    );
    let proof = outcome.map_err(|_| ()).expect("the walk completes");
    assert!(!proof.projected_before_lock_release());
    assert!(proof.rundown_acquired_before_projection());

    // A roster that never validates the owner slots cannot prove it did.
    let (_, outcome) = drive_resolve(
        [
            S::BoundsCheckLocator,
            S::AcquireAccessRundown,
            S::AcquireRegistryLock,
            S::ValidateCoreLive,
            S::ValidateCellIdentity,
            S::ProjectSessionPointer,
            S::ReleaseRegistryLock,
            S::ReleaseRegistryLock,
        ],
        None,
    );
    let proof = outcome.map_err(|_| ()).expect("the walk completes");
    assert!(!proof.validated_before_projection());
    assert!(proof.rundown_acquired_before_lock());

    // Each of the three validations is separately load-bearing: a roster that
    // runs one of them *after* the projection must fail the same proof. Without
    // a case per validation, dropping one comparison from the conjunction is
    // invisible — the absent-step case above falls through the same arm whether
    // the comparison is there or not.
    for late in [
        S::ValidateCoreLive,
        S::ValidateCellIdentity,
        S::ValidateNativeOwnerSlots,
    ] {
        let mut roster = [
            S::BoundsCheckLocator,
            S::AcquireAccessRundown,
            S::AcquireRegistryLock,
            S::ValidateCoreLive,
            S::ValidateCellIdentity,
            S::ValidateNativeOwnerSlots,
            S::ProjectSessionPointer,
            S::ReleaseRegistryLock,
        ];
        // Move the chosen validation to the last slot, after the projection.
        let position = roster
            .iter()
            .position(|step| *step == late)
            .expect("the roster runs every validation");
        if let Some(slot) = roster.get_mut(position) {
            *slot = S::ReleaseRegistryLock;
        }
        if let Some(last) = roster.last_mut() {
            *last = late;
        }
        let (_, outcome) = drive_resolve(roster, None);
        let proof = outcome.map_err(|_| ()).expect("the walk completes");
        assert!(
            !proof.validated_before_projection(),
            "{late:?} ran after the projection, so the proof must not hold"
        );
    }
}

#[test]
fn finalizer_state_has_one_idle_queued_running_path() {
    let mut state = FinalizerState::Idle;
    assert_eq!(state.queue(), Ok(()));
    assert_eq!(state, FinalizerState::Queued);
    assert_eq!(state.queue(), Err(LifecycleError::FinalizerBusy));
    assert_eq!(state.begin_run(), Ok(()));
    assert_eq!(state, FinalizerState::Running);
    assert_eq!(state.begin_run(), Err(LifecycleError::FinalizerBusy));
    assert_eq!(state.finish_run(), Ok(()));
    assert_eq!(state, FinalizerState::Idle);
    assert_eq!(state.fail_stop(), Err(LifecycleError::WrongState));
    state.queue().expect("a second independent run queues");
    state.begin_run().expect("queued work runs");
    assert_eq!(state.fail_stop(), Ok(()));
    assert_eq!(state, FinalizerState::DeleteFailStop);
    assert_eq!(state.queue(), Err(LifecycleError::FinalizerBusy));
}

#[test]
fn mount_owner_rejects_same_generation_reference_from_another_cell_and_returns_all_parts() {
    let mut registry = SessionRegistry::<2>::new();
    let (first, _) = publish(&mut registry, 1);
    let (second, _) = publish(&mut registry, 2);
    let (first_locator, _first_lease, _first_control) = first.into_parts();
    let (second_locator, _second_lease, second_reference) = second.into_parts();
    assert_eq!(first_locator.generation(), second_locator.generation());
    assert_ne!(first_locator.slot_index(), second_locator.slot_index());

    let (error, returned_reference, device, vpb) =
        MountOwner::try_new(first_locator, second_reference, 0x11u32, 0x22u32)
            .expect_err("another cell's generation-one reference is foreign");
    assert_eq!(error, LifecycleError::WrongLocator);
    assert_eq!(returned_reference.locator(), second_locator);
    assert_eq!((device, vpb), (0x11, 0x22));
}

#[test]
fn mount_install_publication_blocks_teardown_until_exposure_receipt_is_consumed() {
    let (mut registry, locator, reference) = live_reference();
    let mounted = 0xD00Du32;
    let vpb = 0xBEEFu32;
    let mut mount = MountRendezvous::new_inactive();
    mount.activate(locator).expect("inactive mount activates");

    let prepared = mount
        .prepare_install(locator, &reference, &mounted, &vpb)
        .expect("all four owner pieces preflight without moving");
    assert_eq!(
        reference.locator(),
        locator,
        "the strong ref is still owned"
    );
    assert_eq!((mounted, vpb), (0xD00D, 0xBEEF));

    // SAFETY: the four values are exactly the ones borrowed by the preflight,
    // and no rendezvous mutation occurred between prepare and commit.
    let publication = unsafe { mount.commit_prepared_install(prepared, reference, mounted, vpb) };
    assert_eq!(publication.locator(), locator);
    assert_eq!(publication.mount_generation(), 1);
    assert_eq!(
        mount.expected_teardown(locator),
        None,
        "an unconsumed exposure receipt must keep the owner unavailable to teardown"
    );
    assert!(matches!(
        mount.take_or_join(ExpectedMountTeardown::Owner {
            locator,
            mount_generation: 1,
        }),
        Err(LifecycleError::WrongState)
    ));
    let mut exposed = None;
    mount
        .commit_owner_exposure(publication, |device| exposed = Some(*device))
        .expect("the exact receipt exposes the owner once");
    assert_eq!(exposed, Some(0xD00D));

    let expected = mount
        .expected_teardown(locator)
        .expect("the committed owner is now the sole present generation");
    let MountClaim::Owner { owner, .. } = mount
        .take_or_join(expected)
        .expect("the publication installed the exact complete owner")
    else {
        panic!("the committed mount must own its teardown")
    };
    let (reference, mounted, vpb) = owner.into_parts();
    assert_eq!(reference.locator(), locator);
    assert_eq!((mounted, vpb), (0xD00D, 0xBEEF));
    let _ = registry
        .release(reference)
        .expect("the published mount retained exactly one strong reference");
}

#[test]
fn mount_exposure_receipt_cannot_be_substituted_between_same_generation_rendezvous() {
    let (mut registry, locator, first_reference) = live_reference();
    let second_reference = registry
        .acquire(locator)
        .expect("the same live generation admits a second reference");
    let mut first = MountRendezvous::new_inactive();
    let mut second = MountRendezvous::new_inactive();
    first.activate(locator).expect("first rendezvous activates");
    second
        .activate(locator)
        .expect("second rendezvous activates");

    let first_prepared = first
        .prepare_install(locator, &first_reference, &0xA001u32, &0xA002u32)
        .expect("first owner preflights");
    let second_prepared = second
        .prepare_install(locator, &second_reference, &0xB001u32, &0xB002u32)
        .expect("second owner preflights");
    let first_publication =
        unsafe { first.commit_prepared_install(first_prepared, first_reference, 0xA001, 0xA002) };
    let second_publication = unsafe {
        second.commit_prepared_install(second_prepared, second_reference, 0xB001, 0xB002)
    };

    let mut crossed_device = None;
    let (error, first_publication) = second
        .commit_owner_exposure(first_publication, |device| crossed_device = Some(*device))
        .expect_err("receipt A cannot expose same-kind owner B");
    assert_eq!(error, LifecycleError::WrongLocator);
    assert_eq!(crossed_device, None);

    let mut first_device = None;
    first
        .commit_owner_exposure(first_publication, |device| first_device = Some(*device))
        .expect("refusal returned receipt A unchanged");
    let mut second_device = None;
    second
        .commit_owner_exposure(second_publication, |device| second_device = Some(*device))
        .expect("receipt B remains independently affine");
    assert_eq!((first_device, second_device), (Some(0xA001), Some(0xB001)));
}

#[test]
fn mount_transient_phases_retain_the_authenticated_locator() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    assert!(matches!(
        mount.state,
        PrivateMountRendezvousState::TearingDown {
            locator: stored,
            generation: 1,
        } if stored == locator
    ));
    let publication = mount.publish_done(teardown).expect("Done publication");
    assert!(matches!(
        mount.state,
        PrivateMountRendezvousState::Done {
            locator: stored,
            generation: 1,
        } if stored == locator
    ));
    let acknowledgement = unsafe { publication.signal_then_ack(|_| {}) };
    let drain = mount
        .acknowledge_done_signal(acknowledgement)
        .expect("same locator acknowledges Done");
    let _prepared = mount.poll_drain(drain).expect("zero-waiter drain");
    assert!(matches!(
        mount.state,
        PrivateMountRendezvousState::Resetting {
            locator: stored,
            generation: 1,
        } if stored == locator
    ));
}

#[test]
fn mount_acknowledgements_reject_same_generation_foreign_locators() {
    let (mut first, _first_registry, first_locator) = present_mount_for(41);
    let (mut second, _second_registry, second_locator) = present_mount_for(42);
    assert_eq!(first_locator.generation(), second_locator.generation());
    assert_ne!(first_locator, second_locator);

    let (_first_owner, first_teardown) = owner_claim(&mut first, first_locator);
    let (_second_owner, second_teardown) = owner_claim(&mut second, second_locator);
    let first_join = match first
        .take_or_join(ExpectedMountTeardown::Join {
            locator: first_locator,
            mount_generation: 1,
        })
        .expect("first join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("TearingDown admits an ordinary join"),
    };
    let second_join = match second
        .take_or_join(ExpectedMountTeardown::Join {
            locator: second_locator,
            mount_generation: 1,
        })
        .expect("second join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("TearingDown admits an ordinary join"),
    };

    let first_done = first.publish_done(first_teardown).expect("first Done");
    let second_done = second.publish_done(second_teardown).expect("second Done");
    let first_done_ack = unsafe { first_done.signal_then_ack(|_| {}) };
    let second_done_ack = unsafe { second_done.signal_then_ack(|_| {}) };
    let (error, second_done_ack) = first
        .acknowledge_done_signal(second_done_ack)
        .expect_err("same generation from another locator is foreign");
    assert_eq!(error, LifecycleError::WrongLocator);
    let first_drain = first
        .acknowledge_done_signal(first_done_ack)
        .expect("first exact Done acknowledgement");
    let second_drain = second
        .acknowledge_done_signal(second_done_ack)
        .expect("returned foreign acknowledgement remains exact for second");

    let first_conversion = first.release_join(first_join).expect("first conversion");
    let second_conversion = second.release_join(second_join).expect("second conversion");
    let first_join_ack = unsafe { first_conversion.signal_then_ack(|_| {}) };
    let second_join_ack = unsafe { second_conversion.signal_then_ack(|_| {}) };
    let (error, second_join_ack) = first
        .acknowledge_join_signal(second_join_ack)
        .expect_err("ordinary-drained acknowledgement retains its locator");
    assert_eq!(error, LifecycleError::WrongLocator);
    let first_reset_ticket = first
        .acknowledge_join_signal(first_join_ack)
        .expect("first exact ordinary-drained acknowledgement");
    let second_reset_ticket = second
        .acknowledge_join_signal(second_join_ack)
        .expect("second exact ordinary-drained acknowledgement");

    let first_prepared = first.poll_drain(first_drain).expect("first drain");
    let second_prepared = second.poll_drain(second_drain).expect("second drain");
    let first_reset = first.finish_reset(first_prepared).expect("first reset");
    let second_reset = second.finish_reset(second_prepared).expect("second reset");
    let first_reset_ack = unsafe { first_reset.signal_then_ack(|_| {}) };
    let second_reset_ack = unsafe { second_reset.signal_then_ack(|_| {}) };
    let (error, second_reset_ack) = first
        .acknowledge_reset_signal(second_reset_ack)
        .expect_err("reset-complete acknowledgement retains its locator");
    assert_eq!(error, LifecycleError::WrongLocator);
    let _first_owner_proof = first
        .acknowledge_reset_signal(first_reset_ack)
        .expect("first exact reset acknowledgement");
    let _second_owner_proof = second
        .acknowledge_reset_signal(second_reset_ack)
        .expect("second exact reset acknowledgement");

    let first_release = first
        .finish_joined_reset(first_reset_ticket)
        .expect("first reset join");
    let second_release = second
        .finish_joined_reset(second_reset_ticket)
        .expect("second reset join");
    let first_release_ack = unsafe { first_release.signal_then_ack(|_| {}) };
    let second_release_ack = unsafe { second_release.signal_then_ack(|_| {}) };
    let (error, second_release_ack) = first
        .acknowledge_reset_join_signal(second_release_ack)
        .expect_err("reset-drained acknowledgement retains its locator");
    assert_eq!(error, LifecycleError::WrongLocator);
    let _first_joined_proof = first
        .acknowledge_reset_join_signal(first_release_ack)
        .expect("first exact reset-drained acknowledgement");
    let _second_joined_proof = second
        .acknowledge_reset_join_signal(second_release_ack)
        .expect("second exact reset-drained acknowledgement");
}

#[test]
fn mount_publication_observations_match_only_their_pending_event_phase() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("ordinary join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down yields an ordinary join"),
    };

    let done = mount.publish_done(teardown).expect("Done publication");
    let done_observation = done.publication_observation();
    assert_eq!(done_observation.locator(), locator);
    assert_eq!(done_observation.event(), Some(MountWaitEvent::Complete));
    assert!(mount.matches_publication_observation(&done_observation));
    let wrong_event = MountPublicationObservation {
        event: Some(MountWaitEvent::ResetComplete),
        ..done_observation
    };
    assert!(!mount.matches_publication_observation(&wrong_event));
    let wrong_generation = MountPublicationObservation {
        mount_generation: 2,
        ..done_observation
    };
    assert!(!mount.matches_publication_observation(&wrong_generation));
    let done_ack = unsafe { done.signal_then_ack(|_| {}) };
    let drain = mount
        .acknowledge_done_signal(done_ack)
        .expect("Done signal acknowledged");
    assert!(
        !mount.matches_publication_observation(&done_observation),
        "the copied address cannot stand in for its consumed pending signal"
    );

    let conversion = mount.release_join(join).expect("last ordinary join");
    let ordinary_observation = conversion.publication_observation();
    assert_eq!(
        ordinary_observation.event(),
        Some(MountWaitEvent::OrdinaryWaitersDrained)
    );
    assert!(mount.matches_publication_observation(&ordinary_observation));
    let join_ack = unsafe { conversion.signal_then_ack(|_| {}) };
    let reset_ticket = mount
        .acknowledge_join_signal(join_ack)
        .expect("ordinary-drained signal acknowledged");
    assert!(!mount.matches_publication_observation(&ordinary_observation));

    let prepared = mount.poll_drain(drain).expect("ordinary drain closes");
    let reset = mount.finish_reset(prepared).expect("reset publication");
    let reset_observation = reset.publication_observation();
    assert_eq!(
        reset_observation.event(),
        Some(MountWaitEvent::ResetComplete)
    );
    assert!(mount.matches_publication_observation(&reset_observation));
    let reset_ack = unsafe { reset.signal_then_ack(|_| {}) };
    let _owner_proof = mount
        .acknowledge_reset_signal(reset_ack)
        .expect("reset-complete signal acknowledged");
    assert!(!mount.matches_publication_observation(&reset_observation));

    let release = mount
        .finish_joined_reset(reset_ticket)
        .expect("last reset join releases");
    let reset_drained_observation = release.publication_observation();
    assert_eq!(
        reset_drained_observation.event(),
        Some(MountWaitEvent::ResetWaitersDrained)
    );
    assert!(mount.matches_publication_observation(&reset_drained_observation));
    let release_ack = unsafe { release.signal_then_ack(|_| {}) };
    let _joined_proof = mount
        .acknowledge_reset_join_signal(release_ack)
        .expect("reset-drained signal acknowledged");
    assert!(!mount.matches_publication_observation(&reset_drained_observation));
}

#[test]
fn mount_publication_observation_rejects_a_crossed_cell() {
    let (mut first, _first_registry, first_locator) = present_mount_for(51);
    let (mut second, _second_registry, second_locator) = present_mount_for(52);
    assert_eq!(first_locator.generation(), second_locator.generation());
    assert_ne!(first_locator, second_locator);

    let (_first_owner, first_teardown) = owner_claim(&mut first, first_locator);
    let (_second_owner, second_teardown) = owner_claim(&mut second, second_locator);
    let first_publication = first
        .publish_done(first_teardown)
        .expect("first Done publication");
    let second_publication = second
        .publish_done(second_teardown)
        .expect("second Done publication");
    let first_observation = first_publication.publication_observation();
    let second_observation = second_publication.publication_observation();

    assert!(first.matches_publication_observation(&first_observation));
    assert!(second.matches_publication_observation(&second_observation));
    assert!(!first.matches_publication_observation(&second_observation));
    assert!(!second.matches_publication_observation(&first_observation));
}

#[test]
fn stale_mount_publication_observation_is_rejected_after_generation_reuse() {
    let (mut mount, mut registry, locator) = present_mount();
    let (owner, teardown) = owner_claim(&mut mount, locator);
    let (reference, _mounted, _vpb) = owner.into_parts();
    let _ = registry
        .release(reference)
        .expect("the first mount reference releases once");

    let first_publication = mount
        .publish_done(teardown)
        .expect("generation one publishes Done");
    let stale = first_publication.publication_observation();
    assert!(mount.matches_publication_observation(&stale));
    let first_ack = unsafe { first_publication.signal_then_ack(|_| {}) };
    let first_drain = mount
        .acknowledge_done_signal(first_ack)
        .expect("generation one Done acknowledged");
    let first_owner_proof = reset_owner(&mut mount, first_drain);
    let _first_completion = mount
        .complete_owner(first_owner_proof)
        .expect("generation one completes before reuse");

    let second_reference = registry
        .acquire(locator)
        .expect("the live session lends generation two its owner reference");
    let second_owner = MountOwner::try_new(locator, second_reference, 0xD002, 0xB002)
        .expect("generation two owner has the same session brand");
    mount
        .install(second_owner)
        .expect("generation two installs after complete reset");
    let second_expected = mount
        .expected_teardown(locator)
        .expect("generation two is present");
    let second_teardown = match mount
        .take_or_join(second_expected)
        .expect("generation two owner takes teardown")
    {
        MountClaim::Owner { teardown, .. } => teardown,
        _ => panic!("generation two yields its owner"),
    };
    let second_publication = mount
        .publish_done(second_teardown)
        .expect("generation two publishes the same event kind");
    let fresh = second_publication.publication_observation();

    assert!(!mount.matches_publication_observation(&stale));
    assert!(mount.matches_publication_observation(&fresh));
}

#[test]
fn nonlast_mount_publications_match_only_their_typed_exact_phase() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let mut ordinary = Vec::new();
    for _ in 0..2 {
        let claim = mount
            .take_or_join(ExpectedMountTeardown::Join {
                locator,
                mount_generation: 1,
            })
            .expect("ordinary join");
        match claim {
            MountClaim::Join { ticket, .. } => ordinary.push(ticket),
            _ => panic!("tearing down yields an ordinary join"),
        }
    }
    let drain = signal_done(&mut mount, teardown);

    let first_conversion = mount
        .release_join(ordinary.remove(0))
        .expect("first conversion is nonlast");
    let stale_ordinary_none = first_conversion.publication_observation();
    assert_eq!(stale_ordinary_none.event(), None);
    assert!(mount.matches_publication_observation(&stale_ordinary_none));
    let mut first_signals = 0;
    let first_ack = unsafe { first_conversion.signal_then_ack(|_| first_signals += 1) };
    assert_eq!(first_signals, 0);
    let first_reset_ticket = mount
        .acknowledge_join_signal(first_ack)
        .expect("nonlast conversion acknowledges without a signal");

    let last_conversion = mount
        .release_join(ordinary.remove(0))
        .expect("second conversion is last");
    assert!(
        !mount.matches_publication_observation(&stale_ordinary_none),
        "ordinary None stops matching when the last conversion sets its pending bit"
    );
    let last_ack = unsafe { last_conversion.signal_then_ack(|_| {}) };
    let last_reset_ticket = mount
        .acknowledge_join_signal(last_ack)
        .expect("last ordinary signal acknowledges");

    let prepared = mount.poll_drain(drain).expect("ordinary drain closes");
    let reset_publication = mount.finish_reset(prepared).expect("reset publishes");
    let reset_ack = unsafe { reset_publication.signal_then_ack(|_| {}) };
    let _owner_proof = mount
        .acknowledge_reset_signal(reset_ack)
        .expect("reset signal acknowledges");

    let first_release = mount
        .finish_joined_reset(first_reset_ticket)
        .expect("first reset release is nonlast");
    let reset_none = first_release.publication_observation();
    assert_eq!(reset_none.event(), None);
    assert!(mount.matches_publication_observation(&reset_none));
    assert!(
        !mount.matches_publication_observation(&stale_ordinary_none),
        "ordinary None cannot cross-wire into a ResetJoin None phase"
    );
    let mut reset_signals = 0;
    let first_release_ack = unsafe { first_release.signal_then_ack(|_| reset_signals += 1) };
    assert_eq!(reset_signals, 0);
    let _first_joined = mount
        .acknowledge_reset_join_signal(first_release_ack)
        .expect("nonlast reset release acknowledges without a signal");

    let last_release = mount
        .finish_joined_reset(last_reset_ticket)
        .expect("second reset release is last");
    assert!(
        !mount.matches_publication_observation(&reset_none),
        "ResetJoin None stops matching when the last release sets its pending bit"
    );
    let last_release_ack = unsafe { last_release.signal_then_ack(|_| {}) };
    let _last_joined = mount
        .acknowledge_reset_join_signal(last_release_ack)
        .expect("last reset-drained signal acknowledges");
}

#[test]
fn same_kind_eventless_publication_observations_are_addresses_not_instance_authority() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let mut ordinary = Vec::new();
    for _ in 0..3 {
        match mount
            .take_or_join(ExpectedMountTeardown::Join {
                locator,
                mount_generation: 1,
            })
            .expect("ordinary join")
        {
            MountClaim::Join { ticket, .. } => ordinary.push(ticket),
            _ => panic!("tearing down yields an ordinary join"),
        }
    }
    let drain = signal_done(&mut mount, teardown);

    let conversion_a = mount
        .release_join(ordinary.remove(0))
        .expect("first conversion is nonlast");
    let address_a = conversion_a.publication_observation();
    let conversion_b = mount
        .release_join(ordinary.remove(0))
        .expect("second conversion is also nonlast");
    let address_b = conversion_b.publication_observation();
    assert_eq!(address_a.event(), None);
    assert!(address_a == address_b);
    assert!(mount.matches_publication_observation(&address_a));
    assert!(mount.matches_publication_observation(&address_b));

    // The copy observations deliberately do not order the two instances. The
    // affine conversions do: acknowledging B before A still yields exactly
    // one reset ticket for each counted ordinary-waiter conversion.
    let ack_b = unsafe { conversion_b.signal_then_ack(|_| unreachable!()) };
    let reset_b = mount
        .acknowledge_join_signal(ack_b)
        .expect("B acknowledges without a signal");
    let ack_a = unsafe { conversion_a.signal_then_ack(|_| unreachable!()) };
    let reset_a = mount
        .acknowledge_join_signal(ack_a)
        .expect("A acknowledges without a signal");

    let last_conversion = mount
        .release_join(ordinary.remove(0))
        .expect("third conversion is last");
    assert_eq!(
        last_conversion.publication_observation().event(),
        Some(MountWaitEvent::OrdinaryWaitersDrained)
    );
    let last_ack = unsafe { last_conversion.signal_then_ack(|_| {}) };
    let reset_last = mount
        .acknowledge_join_signal(last_ack)
        .expect("last ordinary-drained signal acknowledges");
    let owner_proof = reset_owner(&mut mount, drain);

    let release_b = mount
        .finish_joined_reset(reset_b)
        .expect("B reset release is nonlast");
    let reset_address_b = release_b.publication_observation();
    let release_a = mount
        .finish_joined_reset(reset_a)
        .expect("A reset release is also nonlast");
    let reset_address_a = release_a.publication_observation();
    assert_eq!(reset_address_b.event(), None);
    assert!(reset_address_b == reset_address_a);
    assert!(mount.matches_publication_observation(&reset_address_b));
    assert!(mount.matches_publication_observation(&reset_address_a));

    let release_a_ack = unsafe { release_a.signal_then_ack(|_| unreachable!()) };
    let joined_a = mount
        .acknowledge_reset_join_signal(release_a_ack)
        .expect("A reset release acknowledges first");
    let release_b_ack = unsafe { release_b.signal_then_ack(|_| unreachable!()) };
    let joined_b = mount
        .acknowledge_reset_join_signal(release_b_ack)
        .expect("B reset release acknowledges second");

    let last_release = mount
        .finish_joined_reset(reset_last)
        .expect("last reset waiter releases");
    assert_eq!(
        last_release.publication_observation().event(),
        Some(MountWaitEvent::ResetWaitersDrained)
    );
    let last_release_ack = unsafe { last_release.signal_then_ack(|_| {}) };
    let joined_last = mount
        .acknowledge_reset_join_signal(last_release_ack)
        .expect("last reset-drained signal acknowledges");

    let _owner_completion = mount
        .complete_owner(owner_proof)
        .expect("all three reset waiters drained");
    let _joined_a = mount
        .complete_joined(joined_a)
        .expect("A retains its own affine completion proof");
    let _joined_b = mount
        .complete_joined(joined_b)
        .expect("B retains its own affine completion proof");
    let _joined_last = mount
        .complete_joined(joined_last)
        .expect("the last waiter retains its own completion proof");
}

#[test]
fn mount_wait_observations_name_only_the_exact_ticket_generation_and_event() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("ordinary join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down yields ordinary join"),
    };
    assert_eq!(
        join.wait_observation(),
        MountWaitObservation {
            locator,
            mount_generation: 1,
            event: MountWaitEvent::Complete,
        }
    );

    let drain = signal_done(&mut mount, teardown);
    assert_eq!(
        drain.wait_observation().event(),
        MountWaitEvent::OrdinaryWaitersDrained
    );
    let reset_ticket = convert_join(&mut mount, join);
    assert_eq!(
        reset_ticket.wait_observation().event(),
        MountWaitEvent::ResetComplete
    );
    let owner_reset = reset_owner(&mut mount, drain);
    assert_eq!(
        owner_reset.wait_observation().event(),
        MountWaitEvent::ResetWaitersDrained
    );
    let joined = release_reset_join(&mut mount, reset_ticket);
    assert_eq!(
        joined.wait_observation(),
        MountWaitObservation {
            locator,
            mount_generation: 1,
            event: MountWaitEvent::ResetWaitersDrained,
        }
    );
}

#[test]
fn mount_wait_observations_match_only_the_legal_phase_of_their_exact_generation() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("ordinary join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down yields ordinary join"),
    };
    let complete_observation = join.wait_observation();
    assert!(mount.matches_wait_observation(&complete_observation));
    let wrong_event = MountWaitObservation {
        event: MountWaitEvent::OrdinaryWaitersDrained,
        ..complete_observation
    };
    assert!(!mount.matches_wait_observation(&wrong_event));

    let (mut foreign, _foreign_registry, foreign_locator) = present_mount_for(2);
    let (_foreign_owner, _foreign_teardown) = owner_claim(&mut foreign, foreign_locator);
    let foreign_join = match foreign
        .take_or_join(ExpectedMountTeardown::Join {
            locator: foreign_locator,
            mount_generation: 1,
        })
        .expect("the foreign mount admits its own join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("the foreign teardown yields an ordinary join"),
    };
    assert!(!mount.matches_wait_observation(&foreign_join.wait_observation()));

    let drain = signal_done(&mut mount, teardown);
    assert!(mount.matches_wait_observation(&complete_observation));
    let drained_observation = drain.wait_observation();
    assert!(mount.matches_wait_observation(&drained_observation));
    let reset_ticket = convert_join(&mut mount, join);
    let reset_observation = reset_ticket.wait_observation();
    let prepared = mount.poll_drain(drain).expect("ordinary drain closes");
    assert!(!mount.matches_wait_observation(&complete_observation));
    assert!(!mount.matches_wait_observation(&drained_observation));
    assert!(mount.matches_wait_observation(&reset_observation));

    let reset_publication = mount.finish_reset(prepared).expect("reset publishes");
    let reset_ack = unsafe { reset_publication.signal_then_ack(|_| {}) };
    let owner_reset = mount
        .acknowledge_reset_signal(reset_ack)
        .expect("reset signal acknowledged");
    assert!(mount.matches_wait_observation(&reset_observation));
    assert!(mount.matches_wait_observation(&owner_reset.wait_observation()));
    let joined = release_reset_join(&mut mount, reset_ticket);
    assert!(mount.matches_wait_observation(&joined.wait_observation()));
}

#[test]
fn stale_copied_wait_observation_is_rejected_after_next_mount_generation_installs() {
    let (mut mount, mut registry, locator) = present_mount();
    let (owner, teardown) = owner_claim(&mut mount, locator);
    let (reference, _mounted, _vpb) = owner.into_parts();
    let _ = registry
        .release(reference)
        .expect("the first mount reference releases once");
    let first_join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("generation one admits an ordinary join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down yields an ordinary join"),
    };
    let stale = first_join.wait_observation();
    assert!(mount.matches_wait_observation(&stale));
    let drain = signal_done(&mut mount, teardown);
    let first_reset_join = convert_join(&mut mount, first_join);
    let owner_reset = reset_owner(&mut mount, drain);
    let joined_reset = release_reset_join(&mut mount, first_reset_join);
    let _owner_completion = mount
        .complete_owner(owner_reset)
        .expect("generation one completes");
    let _joined_completion = mount
        .complete_joined(joined_reset)
        .expect("generation one's join completes");

    let reference = registry
        .acquire(locator)
        .expect("the live session lends generation two its owner reference");
    let owner = MountOwner::try_new(locator, reference, 0xD002, 0xB002)
        .expect("the second owner has the exact session brand");
    mount.install(owner).expect("generation two installs");
    let expected = mount
        .expected_teardown(locator)
        .expect("generation two is present");
    let (_second_owner, _second_teardown) =
        match mount.take_or_join(expected).expect("take generation two") {
            MountClaim::Owner {
                owner, teardown, ..
            } => (owner, teardown),
            _ => panic!("generation two yields its owner"),
        };
    let second_join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 2,
        })
        .expect("generation two admits its own join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("generation two tearing down yields a join"),
    };
    let fresh = second_join.wait_observation();

    assert!(!mount.matches_wait_observation(&stale));
    assert!(mount.matches_wait_observation(&fresh));
}

#[test]
fn mount_owner_join_done_and_unmounted_claims_mint_exact_completion_authority() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("tearing-down mount admits an ordinary joiner")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down must yield Join"),
    };
    let drain = signal_done(&mut mount, teardown);
    let reset_ticket = convert_join(&mut mount, join);
    let _owner_reset = reset_owner(&mut mount, drain);
    let _joined_reset = release_reset_join(&mut mount, reset_ticket);
    match mount
        .take_or_join(ExpectedMountTeardown::Absent {
            locator,
            cursor: MountAbsenceCursor::Next(2),
        })
        .expect("fully acknowledged reset is absent")
    {
        MountClaim::Absent {
            expected,
            completed,
        } => {
            assert_eq!(
                expected,
                ExpectedMountTeardown::Absent {
                    locator,
                    cursor: MountAbsenceCursor::Next(2),
                }
            );
            assert_eq!(completed.locator, locator);
            assert_eq!(completed.cursor, MountAbsenceCursor::Next(2));
        }
        _ => panic!("unmounted state must return an absence proof"),
    }
}

#[test]
fn owner_join_and_reset_join_completions_require_full_suffix_and_carry_final_cursor() {
    let (mut mount, mut registry, locator) = present_mount();
    let (owner, teardown) = owner_claim(&mut mount, locator);
    let (reference, _mounted, _vpb) = owner.into_parts();
    let _ = registry
        .release(reference)
        .expect("native teardown releases the mount strong reference once");

    let ordinary = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("tearing down admits an ordinary join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("the pre-Done arrival must be an ordinary join"),
    };
    let drain = signal_done(&mut mount, teardown);
    let ordinary_reset = convert_join(&mut mount, ordinary);
    let prepared = mount.poll_drain(drain).expect("ordinary waiters drained");

    let reset_expected = mount
        .expected_teardown(locator)
        .expect("Resetting publishes one exact reset-join expectation");
    let reset_join = match mount
        .take_or_join(reset_expected)
        .expect("an arrival during Resetting receives a reset ticket")
    {
        MountClaim::ResetJoin { ticket, expected } => {
            assert_eq!(expected, reset_expected);
            ticket
        }
        _ => panic!("Resetting must mint ResetJoin, never ordinary Join"),
    };

    let reset_publication = mount.finish_reset(prepared).expect("owner publishes reset");
    let reset_ack = unsafe { reset_publication.signal_then_ack(|_| {}) };
    let owner_reset = mount
        .acknowledge_reset_signal(reset_ack)
        .expect("reset event is signalled before any completion");

    let (error, owner_reset) = mount
        .complete_owner(owner_reset)
        .expect_err("owner completion waits for every reset waiter");
    assert_eq!(error, LifecycleError::AdmissionClosed);

    let ordinary_release = mount
        .finish_joined_reset(ordinary_reset)
        .expect("ordinary join releases its reset ticket");
    let ordinary_ack = unsafe { ordinary_release.signal_then_ack(|_| {}) };
    let ordinary_reset = mount
        .acknowledge_reset_join_signal(ordinary_ack)
        .expect("the ordinary join acknowledges its release");
    let (error, ordinary_reset) = mount
        .complete_joined(ordinary_reset)
        .expect_err("ordinary completion waits for the last reset joiner");
    assert_eq!(error, LifecycleError::AdmissionClosed);

    let reset_release = mount
        .finish_joined_reset(reset_join)
        .expect("last reset join releases its ticket");
    let mut drained_signals = 0;
    let reset_ack = unsafe { reset_release.signal_then_ack(|_| drained_signals += 1) };
    assert_eq!(drained_signals, 1, "the last waiter signals reset drain");
    let reset_joined = mount
        .acknowledge_reset_join_signal(reset_ack)
        .expect("the last drain signal is acknowledged under the lock");

    let owner_complete = mount
        .complete_owner(owner_reset)
        .expect("owner completes only after the full suffix");
    let ordinary_complete = mount
        .complete_joined(ordinary_reset)
        .expect("ordinary join observes the same final absence");
    let reset_complete = mount
        .complete_joined(reset_joined)
        .expect("reset join observes the same final absence");

    assert_eq!(owner_complete.cursor(), MountAbsenceCursor::Next(2));
    assert!(matches!(
        ordinary_complete,
        JoinedMountCompletion::Join(ref complete)
            if complete.cursor() == MountAbsenceCursor::Next(2)
    ));
    assert!(matches!(
        reset_complete,
        JoinedMountCompletion::ResetJoin(ref complete)
            if complete.cursor() == MountAbsenceCursor::Next(2)
    ));
}

#[test]
fn mount_joiner_cannot_complete_before_owner_reset_and_reset_event() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("join admitted")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("join expected"),
    };
    let drain = signal_done(&mut mount, teardown);
    let reset_ticket = convert_join(&mut mount, join);
    let (error, reset_ticket) = mount
        .finish_joined_reset(reset_ticket)
        .expect_err("Done is not reset-complete");
    assert_eq!(error, LifecycleError::WrongState);
    let prepared = mount.poll_drain(drain).expect("ordinary drain closes");
    let publication = mount.finish_reset(prepared).expect("reset publication");
    let (error, reset_ticket) = mount
        .finish_joined_reset(reset_ticket)
        .expect_err("the reset-complete event is still pending");
    assert_eq!(error, LifecycleError::AdmissionClosed);
    let acknowledgement = unsafe { publication.signal_then_ack(|_| {}) };
    let _owner_reset = mount
        .acknowledge_reset_signal(acknowledgement)
        .expect("reset event acknowledged");
    let _joined = release_reset_join(&mut mount, reset_ticket);
}

#[test]
fn new_mount_waits_until_old_reset_observers_are_drained() {
    let (mut mount, mut registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("ordinary join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("join expected"),
    };
    let drain = signal_done(&mut mount, teardown);
    let reset_ticket = convert_join(&mut mount, join);
    let _reset = reset_owner(&mut mount, drain);

    let fresh_ref = registry.acquire(locator).expect("session remains live");
    let fresh_owner = MountOwner::try_new(locator, fresh_ref, 0x33, 0x44).expect("same cell");
    let (error, fresh_owner) = mount
        .install(fresh_owner)
        .expect_err("a reset observer still owns its ticket");
    assert_eq!(error, LifecycleError::MountBusy);
    let _joined = release_reset_join(&mut mount, reset_ticket);
    mount
        .install(fresh_owner)
        .expect("all reset observers and signals are drained");
}

#[test]
fn poll_drain_atomically_closes_ordinary_mount_admission() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let drain = signal_done(&mut mount, teardown);
    let prepared = mount.poll_drain(drain).expect("zero-waiter drain prepares");
    match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("Resetting arrival receives a reset ticket")
    {
        MountClaim::ResetJoin { .. } => {}
        _ => panic!("ordinary admission must be closed atomically"),
    }
    let _publication = mount
        .finish_reset(prepared)
        .expect("prepared reset is exact");
}

#[test]
fn multiple_reset_joiners_observe_one_reset_without_sharing_owner_proof() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let mut ordinary = Vec::new();
    for _ in 0..2 {
        match mount
            .take_or_join(ExpectedMountTeardown::Join {
                locator,
                mount_generation: 1,
            })
            .expect("ordinary join")
        {
            MountClaim::Join { ticket, .. } => ordinary.push(ticket),
            _ => panic!("join expected"),
        }
    }
    let drain = signal_done(&mut mount, teardown);
    let reset_a = convert_join(&mut mount, ordinary.remove(0));
    let reset_b = convert_join(&mut mount, ordinary.remove(0));
    let owner_proof = reset_owner(&mut mount, drain);
    let joined_a = release_reset_join(&mut mount, reset_a);
    let joined_b = release_reset_join(&mut mount, reset_b);
    assert_eq!(owner_proof.mount_generation, 1);
    assert_eq!(joined_a.mount_generation, 1);
    assert_eq!(joined_b.mount_generation, 1);
}

#[test]
fn mount_event_signal_authorities_are_nonreplayable() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let publication = mount.publish_done(teardown).expect("Done publication");
    let mut signals = 0u8;
    let acknowledgement =
        unsafe { publication.signal_then_ack(|_| signals = signals.saturating_add(1)) };
    assert_eq!(signals, 1);
    let _drain = mount
        .acknowledge_done_signal(acknowledgement)
        .expect("one acknowledgement");
}

#[test]
fn mount_continuations_are_unavailable_until_signal_callback_returns() {
    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let publication = mount.publish_done(teardown).expect("Done publication");
    let mut callback_returned = false;
    let acknowledgement = unsafe {
        publication.signal_then_ack(|_| {
            assert!(!callback_returned);
            callback_returned = true;
        })
    };
    assert!(callback_returned);
    let _drain = mount
        .acknowledge_done_signal(acknowledgement)
        .expect("continuation appears only after callback return");
}

#[test]
fn mount_generation_reuse_waits_for_all_four_signal_acknowledgements() {
    let (mut mount, mut registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let ordinary = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("join")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("join expected"),
    };

    let done_publication = mount.publish_done(teardown).expect("Done publication");
    assert_eq!(mount.pending_signal_count_for_test(), 1);
    let done_ack = unsafe { done_publication.signal_then_ack(|_| {}) };
    let drain = mount.acknowledge_done_signal(done_ack).expect("Done ack");

    let join_conversion = mount.release_join(ordinary).expect("join conversion");
    assert_eq!(mount.pending_signal_count_for_test(), 1);
    let join_ack = unsafe { join_conversion.signal_then_ack(|_| {}) };
    let reset_ticket = mount.acknowledge_join_signal(join_ack).expect("join ack");

    let prepared = mount.poll_drain(drain).expect("drain");
    let reset_publication = mount.finish_reset(prepared).expect("reset publication");
    assert_eq!(mount.pending_signal_count_for_test(), 1);
    let reset_ack = unsafe { reset_publication.signal_then_ack(|_| {}) };
    let _owner_reset = mount
        .acknowledge_reset_signal(reset_ack)
        .expect("reset ack");

    let reset_release = mount
        .finish_joined_reset(reset_ticket)
        .expect("reset join release");
    assert_eq!(mount.pending_signal_count_for_test(), 1);
    let fresh_ref = registry.acquire(locator).expect("session remains live");
    let fresh_owner = MountOwner::try_new(locator, fresh_ref, 0x55, 0x66).expect("same cell");
    let (error, fresh_owner) = mount
        .install(fresh_owner)
        .expect_err("last drained signal is not acknowledged");
    assert_eq!(error, LifecycleError::MountBusy);
    let release_ack = unsafe { reset_release.signal_then_ack(|_| {}) };
    let _joined = mount
        .acknowledge_reset_join_signal(release_ack)
        .expect("reset waiter drain ack");
    mount
        .install(fresh_owner)
        .expect("all four signals acknowledged");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeMountCompletionKind {
    Done,
    OrdinaryDrained,
    ResetComplete,
    ResetWaitersDrained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeMountCompletionTrace {
    RegistryAcquire,
    Signal {
        kind: NativeMountCompletionKind,
        wait: bool,
    },
    Acknowledge(NativeMountCompletionKind),
    RegistryRelease,
    WaitOutsideRegistry(MountWaitEvent),
    PollDrainRefused,
    PollDrainPrepared,
    ClearVpbBinding,
    DeleteMountedDevice,
    ReleaseMountReference,
}

#[derive(Default)]
struct RecordingNativeMountCompletion {
    trace: Vec<NativeMountCompletionTrace>,
    registry_held: bool,
    signal_counts: [u8; 4],
    vpb_clear_count: u8,
    delete_count: u8,
    reference_release_count: u8,
}

impl RecordingNativeMountCompletion {
    fn signal_index(kind: NativeMountCompletionKind) -> usize {
        match kind {
            NativeMountCompletionKind::Done => 0,
            NativeMountCompletionKind::OrdinaryDrained => 1,
            NativeMountCompletionKind::ResetComplete => 2,
            NativeMountCompletionKind::ResetWaitersDrained => 3,
        }
    }

    fn registry_acquire(&mut self) {
        assert!(!self.registry_held, "the registry lock is not recursive");
        self.registry_held = true;
        self.trace.push(NativeMountCompletionTrace::RegistryAcquire);
    }

    // Proof of safety: the index is a fixed fixture position in a table this
    // test just built, and this is host test code, never a driver input path.
    // An out-of-range index here is a bug in the test that must panic.
    #[allow(clippy::indexing_slicing)]
    fn signal(&mut self, kind: NativeMountCompletionKind) {
        assert!(self.registry_held, "the signal must stay inside the lock");
        let index = Self::signal_index(kind);
        self.signal_counts[index] = self.signal_counts[index].saturating_add(1);
        self.trace
            .push(NativeMountCompletionTrace::Signal { kind, wait: false });
    }

    fn acknowledge(&mut self, kind: NativeMountCompletionKind) {
        assert!(
            self.registry_held,
            "the acknowledgement must precede the registry release"
        );
        self.trace
            .push(NativeMountCompletionTrace::Acknowledge(kind));
    }

    fn registry_release(&mut self) {
        assert!(self.registry_held, "the registry lock was acquired");
        self.registry_held = false;
        self.trace.push(NativeMountCompletionTrace::RegistryRelease);
    }

    fn wait_outside_registry(&mut self, observation: MountWaitObservation) {
        assert!(
            !self.registry_held,
            "a mount event wait must not hold the registry"
        );
        self.trace
            .push(NativeMountCompletionTrace::WaitOutsideRegistry(
                observation.event(),
            ));
    }

    fn clear_vpb_binding(&mut self) {
        assert!(!self.registry_held);
        self.vpb_clear_count = self.vpb_clear_count.saturating_add(1);
        self.trace.push(NativeMountCompletionTrace::ClearVpbBinding);
    }

    fn delete_mounted_device(&mut self) {
        assert!(!self.registry_held);
        self.delete_count = self.delete_count.saturating_add(1);
        self.trace
            .push(NativeMountCompletionTrace::DeleteMountedDevice);
    }

    fn release_mount_reference(&mut self) {
        assert!(!self.registry_held);
        self.reference_release_count = self.reference_release_count.saturating_add(1);
        self.trace
            .push(NativeMountCompletionTrace::ReleaseMountReference);
    }

    fn publish_done(
        &mut self,
        mount: &mut MountRendezvous<u32, u32>,
        publication: MountDonePublication,
    ) -> MountDrainRight {
        self.registry_acquire();
        // SAFETY: the recording callback is synchronous, records one
        // `Wait = FALSE` signal, and returns before the runner acknowledges it.
        let result = unsafe {
            run_r3_mount_done_signal_ack(mount, publication, |_| {
                self.signal(NativeMountCompletionKind::Done);
            })
        };
        self.acknowledge(NativeMountCompletionKind::Done);
        self.registry_release();
        result.expect("the Done publication and rendezvous name the same generation")
    }

    fn publish_ordinary_drained(
        &mut self,
        mount: &mut MountRendezvous<u32, u32>,
        conversion: MountJoinConversion,
    ) -> MountResetJoinTicket {
        self.registry_acquire();
        // SAFETY: as above, for the distinct ordinary-drained signal type.
        let result = unsafe {
            run_r3_mount_ordinary_drained_signal_ack(mount, conversion, |_| {
                self.signal(NativeMountCompletionKind::OrdinaryDrained);
            })
        };
        self.acknowledge(NativeMountCompletionKind::OrdinaryDrained);
        self.registry_release();
        result.expect("the ordinary-drained conversion remains bound to its rendezvous")
    }

    fn publish_reset_complete(
        &mut self,
        mount: &mut MountRendezvous<u32, u32>,
        publication: MountResetPublication,
    ) -> MountResetProof {
        self.registry_acquire();
        // SAFETY: as above, for the distinct reset-complete signal type.
        let result = unsafe {
            run_r3_mount_reset_complete_signal_ack(mount, publication, |_| {
                self.signal(NativeMountCompletionKind::ResetComplete);
            })
        };
        self.acknowledge(NativeMountCompletionKind::ResetComplete);
        self.registry_release();
        result.expect("the reset-complete publication remains bound to its rendezvous")
    }

    fn publish_reset_waiters_drained(
        &mut self,
        mount: &mut MountRendezvous<u32, u32>,
        release: MountResetJoinRelease,
    ) -> JoinedMountResetProof {
        self.registry_acquire();
        // SAFETY: as above, for the distinct reset-waiters-drained signal.
        let result = unsafe {
            run_r3_mount_reset_waiters_drained_signal_ack(mount, release, |_| {
                self.signal(NativeMountCompletionKind::ResetWaitersDrained);
            })
        };
        self.acknowledge(NativeMountCompletionKind::ResetWaitersDrained);
        self.registry_release();
        result.expect("the reset-waiter release remains bound to its rendezvous")
    }
}

struct RecordingMountOwnerTeardown<'a> {
    native: &'a mut RecordingNativeMountCompletion,
    registry: &'a mut SessionRegistry<2>,
}

impl R3MountOwnerTeardownOps<u32, u32> for RecordingMountOwnerTeardown<'_> {
    fn clear_vpb_binding(&mut self, _vpb: u32) {
        self.native.clear_vpb_binding();
    }

    fn delete_mounted_device(&mut self, _mounted: u32) {
        self.native.delete_mounted_device();
    }

    fn release_mount_reference(&mut self, reference: StrongSessionRef) {
        self.registry
            .release(reference)
            .expect("the authentic mount strong reference releases once");
        self.native.release_mount_reference();
    }
}

#[test]
fn native_mount_completion_trace_records_all_four_locked_signal_ack_sequences() {
    use NativeMountCompletionKind::{Done, OrdinaryDrained, ResetComplete, ResetWaitersDrained};
    use NativeMountCompletionTrace::{Acknowledge, RegistryAcquire, RegistryRelease, Signal};

    let (mut mount, _registry, locator) = present_mount();
    let (_owner, teardown) = owner_claim(&mut mount, locator);
    let join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("the tearing-down generation admits one ordinary waiter")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("the ordinary arrival must retain a Join ticket"),
    };
    let mut native = RecordingNativeMountCompletion::default();

    let done = mount
        .publish_done(teardown)
        .expect("the owner publishes Done");
    let drain = native.publish_done(&mut mount, done);
    let conversion = mount
        .release_join(join)
        .expect("the ordinary waiter converts to a reset waiter");
    let reset_ticket = native.publish_ordinary_drained(&mut mount, conversion);
    let prepared = mount
        .poll_drain(drain)
        .expect("the ordinary population is drained");
    let reset = mount
        .finish_reset(prepared)
        .expect("the owner publishes reset complete");
    let _owner_proof = native.publish_reset_complete(&mut mount, reset);
    let release = mount
        .finish_joined_reset(reset_ticket)
        .expect("the last reset waiter releases");
    let _joined_proof = native.publish_reset_waiters_drained(&mut mount, release);

    assert!(!native.registry_held);
    assert_eq!(native.signal_counts, [1, 1, 1, 1]);
    assert_eq!(
        native.trace,
        vec![
            RegistryAcquire,
            Signal {
                kind: Done,
                wait: false,
            },
            Acknowledge(Done),
            RegistryRelease,
            RegistryAcquire,
            Signal {
                kind: OrdinaryDrained,
                wait: false,
            },
            Acknowledge(OrdinaryDrained),
            RegistryRelease,
            RegistryAcquire,
            Signal {
                kind: ResetComplete,
                wait: false,
            },
            Acknowledge(ResetComplete),
            RegistryRelease,
            RegistryAcquire,
            Signal {
                kind: ResetWaitersDrained,
                wait: false,
            },
            Acknowledge(ResetWaitersDrained),
            RegistryRelease,
        ]
    );
}

#[test]
fn native_mount_completion_trace_retries_a_late_join_without_duplicate_signal_delete_or_ref() {
    let (mut mount, mut registry, locator) = present_mount();
    let (owner, teardown) = owner_claim(&mut mount, locator);
    let mut native = RecordingNativeMountCompletion::default();
    let teardown = run_r3_mount_owner_teardown_prefix(
        owner,
        teardown,
        &mut RecordingMountOwnerTeardown {
            native: &mut native,
            registry: &mut registry,
        },
    )
    .expect("the owner and teardown continuation come from the same claim");
    assert_eq!(
        native.trace,
        vec![
            NativeMountCompletionTrace::ClearVpbBinding,
            NativeMountCompletionTrace::DeleteMountedDevice,
            NativeMountCompletionTrace::ReleaseMountReference,
        ],
        "the production-used destructive prefix has one exact native order"
    );

    let done = mount
        .publish_done(teardown)
        .expect("the owner publishes Done");
    let mut drain = native.publish_done(&mut mount, done);

    // The owner observed the previously drained notification and returned
    // from its wait with no registry lock held. The late Join wins the race
    // between that wake and the owner's next lock acquisition.
    native.wait_outside_registry(drain.wait_observation());
    let late_join = match mount
        .take_or_join(ExpectedMountTeardown::Join {
            locator,
            mount_generation: 1,
        })
        .expect("a Join may arrive after Done acknowledgement but before drain close")
    {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("the late arrival must be counted as an ordinary Join"),
    };

    native.registry_acquire();
    drain = match mount.poll_drain(drain) {
        Err((LifecycleError::AdmissionClosed, returned)) => {
            native
                .trace
                .push(NativeMountCompletionTrace::PollDrainRefused);
            returned
        }
        Err((_error, returned)) => {
            let _retained = returned;
            panic!("an authentic drain may refuse here only for the late Join")
        }
        Ok(_prepared) => panic!("the late Join must prevent the first drain close"),
    };
    native.registry_release();

    native.wait_outside_registry(late_join.wait_observation());
    let conversion = mount
        .release_join(late_join)
        .expect("the late Join converts without replaying owner teardown");
    let reset_ticket = native.publish_ordinary_drained(&mut mount, conversion);
    native.wait_outside_registry(drain.wait_observation());
    native.registry_acquire();
    let prepared = mount
        .poll_drain(drain)
        .expect("the retry closes admission after the late Join leaves");
    native
        .trace
        .push(NativeMountCompletionTrace::PollDrainPrepared);
    native.registry_release();

    let reset = mount
        .finish_reset(prepared)
        .expect("the owner publishes reset complete once");
    let _owner_proof = native.publish_reset_complete(&mut mount, reset);
    let release = mount
        .finish_joined_reset(reset_ticket)
        .expect("the late Join leaves the reset population once");
    let _joined = native.publish_reset_waiters_drained(&mut mount, release);

    assert!(!native.registry_held);
    assert_eq!(native.signal_counts, [1, 1, 1, 1]);
    assert_eq!(native.vpb_clear_count, 1);
    assert_eq!(native.delete_count, 1);
    assert_eq!(native.reference_release_count, 1);
    assert_eq!(
        native
            .trace
            .iter()
            .filter(|step| matches!(step, NativeMountCompletionTrace::PollDrainRefused))
            .count(),
        1,
        "the owner retries exactly the drain close, not its destructive prefix"
    );
}

#[test]
fn native_mount_owner_teardown_prefix_rejects_crosswire_before_destructive_call() {
    let (mut first, mut first_registry, first_locator) = present_mount_for(1);
    let (mut second, _second_registry, second_locator) = present_mount_for(2);
    let (first_owner, _first_teardown) = owner_claim(&mut first, first_locator);
    let (_second_owner, second_teardown) = owner_claim(&mut second, second_locator);
    let mut native = RecordingNativeMountCompletion::default();

    let (error, _first_owner, _second_teardown) = run_r3_mount_owner_teardown_prefix(
        first_owner,
        second_teardown,
        &mut RecordingMountOwnerTeardown {
            native: &mut native,
            registry: &mut first_registry,
        },
    )
    .expect_err("a teardown continuation from another locator must refuse before destruction");

    assert_eq!(error, LifecycleError::WrongLocator);
    assert!(native.trace.is_empty());
    assert_eq!(native.vpb_clear_count, 0);
    assert_eq!(native.delete_count, 0);
    assert_eq!(native.reference_release_count, 0);
}

#[test]
fn native_mount_owner_teardown_prefix_rejects_same_locator_different_generation_before_ops() {
    let (mut mount, mut registry, locator) = present_mount();
    let (_first_owner, first_teardown) = owner_claim(&mut mount, locator);

    let second_reference = registry
        .acquire(locator)
        .expect("the same live session can own a separate mount rendezvous");
    let second_owner = MountOwner::try_new(locator, second_reference, 0xCAFE, 0xBABE)
        .expect("the same session locator owns generation two");
    let mut second_mount = MountRendezvous::new_inactive();
    second_mount
        .activate(locator)
        .expect("the second rendezvous activates for the same session");
    second_mount
        .set_next_mount_generation_for_test(core::num::NonZeroU64::new(2).expect("two is nonzero"))
        .expect("the test rendezvous starts at generation two");
    second_mount
        .install(second_owner)
        .expect("the second mount generation installs");
    let (second_owner, _second_teardown) = match second_mount
        .take_or_join(ExpectedMountTeardown::Owner {
            locator,
            mount_generation: 2,
        })
        .expect("generation two yields its exact owner")
    {
        MountClaim::Owner {
            owner, teardown, ..
        } => (owner, teardown),
        _ => panic!("generation two must yield its Owner claim"),
    };
    let mut native = RecordingNativeMountCompletion::default();

    let (error, _second_owner, _first_teardown) = run_r3_mount_owner_teardown_prefix(
        second_owner,
        first_teardown,
        &mut RecordingMountOwnerTeardown {
            native: &mut native,
            registry: &mut registry,
        },
    )
    .expect_err("same locator cannot cross-wire mount generations");

    assert_eq!(error, LifecycleError::WrongLocator);
    assert!(native.trace.is_empty());
}

/// The exact action name, so a table row proves which action it asked for.
fn scan_action_name(action: &ScanAction) -> &'static str {
    match action {
        ScanAction::Skip => "skip",
        ScanAction::Claim => "claim",
        ScanAction::Join => "join",
        ScanAction::ObserveCompleted(_) => "completed",
        ScanAction::ObserveBlocked(_) => "blocked",
    }
}

#[test]
fn process_and_unload_scan_return_at_most_one_affine_action() {
    let result = TerminalResult {
        reason: TerminalReason::Unload,
        fence_failures: 3,
    };
    // Every phase, and the exact action rather than "not Skip". A cell that is
    // Staging or Retired has no session to terminalize — one has not published
    // and the other is already finished — and treating either as claimable is
    // how a scan tears down a SETUP that is still building its own resources.
    for (phase, outcome, want) in [
        (
            NativeCellPhase::Free,
            TerminalRendezvousOutcome::Open,
            "skip",
        ),
        (
            NativeCellPhase::Staging,
            TerminalRendezvousOutcome::Open,
            "skip",
        ),
        (
            NativeCellPhase::Retired,
            TerminalRendezvousOutcome::Open,
            "skip",
        ),
        (
            NativeCellPhase::Live,
            TerminalRendezvousOutcome::Open,
            "claim",
        ),
        (
            NativeCellPhase::Removing,
            TerminalRendezvousOutcome::Open,
            "join",
        ),
        (
            NativeCellPhase::Deleting,
            TerminalRendezvousOutcome::Open,
            "join",
        ),
        // A published outcome is reported whatever the phase says: the
        // rendezvous has already closed, so there is nothing left to claim.
        (
            NativeCellPhase::Live,
            TerminalRendezvousOutcome::Completed(result),
            "completed",
        ),
        (
            NativeCellPhase::Deleting,
            TerminalRendezvousOutcome::Completed(result),
            "completed",
        ),
    ] {
        for action in [
            decide_process_scan(phase, outcome),
            decide_unload_scan(phase, outcome),
        ] {
            assert_eq!(
                scan_action_name(&action),
                want,
                "{phase:?} with a {want} outcome"
            );
        }
    }
}

#[test]
fn no_lifecycle_wait_effect_is_emitted_while_registry_lock_is_held() {
    let effects = [
        Effect::Wait(WaitTarget::TerminalOutcomeEvent),
        Effect::Wait(WaitTarget::JoinerDrainedEvent),
        Effect::Wait(WaitTarget::PendingDpcExitEvent),
        Effect::Wait(WaitTarget::MountCompletionEvent),
        Effect::Wait(WaitTarget::MountWaitersDrainedEvent),
        Effect::Wait(WaitTarget::MountResetCompleteEvent),
        Effect::Wait(WaitTarget::MountResetWaitersDrainedEvent),
        Effect::CompleteIrp,
        Effect::SessionFence(crate::session::FenceEffect::QueueInstalledWork),
        Effect::CopyUserBuffer,
        Effect::Mount(MountEffect::AcquireVpb),
        Effect::Dismount(DismountEffect::DeleteMountedDevice),
        Effect::Free,
    ];
    let context = unsafe {
        EffectContext::assume_held(
            crate::lockrank::HeldLocks::none().acquire(LockRank::RegistrySpin),
            crate::effect::TopLevelContext::Ordinary,
        )
    };
    for effect in effects {
        assert!(may_emit(&context, effect).is_err(), "{effect:?}");
    }

    let sq = unsafe {
        EffectContext::assume_held(
            crate::lockrank::HeldLocks::none().acquire(LockRank::SqWaitRole),
            crate::effect::TopLevelContext::Ordinary,
        )
    };
    let cq = unsafe {
        EffectContext::assume_held(
            crate::lockrank::HeldLocks::none().acquire(LockRank::CqConsumerToken),
            crate::effect::TopLevelContext::Ordinary,
        )
    };
    assert_eq!(
        may_emit(&sq, Effect::Wait(WaitTarget::BlockingResource)),
        Ok(())
    );
    assert_eq!(
        may_emit(&cq, Effect::Wait(WaitTarget::BlockingResource)),
        Err(LockOrderError::WaitUnderNoWaitRole)
    );
}

// ---------------------------------------------------------------------------
// Task 9: CLEANUP routes, terminal ordering, and the counted wait
// ---------------------------------------------------------------------------

use crate::adapter::load::{UnloadEffect, UnloadPlan};
use crate::adapter::setup::{
    ControlContextCloseEffect, ControlContextCloseOwnership, ControlContextClosePlan,
    ControlContextCloseProgress,
};
use crate::session::{CleanupBindingClaim, TerminalBlockedClass};

/// Drive a whole route to its proof, performing every step in roster order.
fn run_route(kind: TerminalRouteKind, roster: [TerminalRouteStep; 4]) -> TerminalRouteProof {
    let mut progress = TerminalRoutePlan::begin_with_roster(kind, roster);
    loop {
        progress = match progress {
            TerminalRouteProgress::Step(step) => step.performed(kind),
            TerminalRouteProgress::Complete(proof) => return proof,
        };
    }
}

fn run_production_route(kind: TerminalRouteKind) -> TerminalRouteProof {
    let roster = match kind {
        TerminalRouteKind::Winner => TerminalRoutePlan::WINNER_STEPS,
        TerminalRouteKind::Join => TerminalRoutePlan::JOIN_STEPS,
    };
    let proof = run_route(kind, roster);
    // The production roster is the one `begin` hands out; driving it through
    // the test seam must not be a different plan.
    assert!(matches!(
        TerminalRoutePlan::begin(kind),
        TerminalRouteProgress::Step(ref step) if step.step() == roster[0]
    ));
    proof
}

#[test]
fn cleanup_winner_releases_outer_rundown_before_run_terminal() {
    let proof = run_production_route(TerminalRouteKind::Winner);
    assert!(proof.claimed_first());
    assert!(proof.released_outer_before_running());
    assert!(proof.acknowledged_last());

    // The proof is load-bearing, not decorative: the exact inversion this test
    // is named for has to be observable as `false`.
    let inverted = run_route(
        TerminalRouteKind::Winner,
        [
            TerminalRouteStep::ClaimUnderRegistryLock,
            TerminalRouteStep::RunTerminal,
            TerminalRouteStep::ReleaseOuterFileRundown,
            TerminalRouteStep::AcknowledgeOutcome,
        ],
    );
    assert!(!inverted.released_outer_before_running());
}

#[test]
fn cleanup_join_releases_outer_rundown_before_terminal_wait() {
    let proof = run_production_route(TerminalRouteKind::Join);
    assert!(proof.claimed_first());
    assert!(proof.released_outer_before_waiting());
    assert!(proof.acknowledged_last());

    let inverted = run_route(
        TerminalRouteKind::Join,
        [
            TerminalRouteStep::ClaimUnderRegistryLock,
            TerminalRouteStep::WaitTerminalOutcome,
            TerminalRouteStep::ReleaseOuterFileRundown,
            TerminalRouteStep::AcknowledgeOutcome,
        ],
    );
    assert!(!inverted.released_outer_before_waiting());
    // A joiner never runs terminal work, so the winner-side proof must not be
    // what makes this route look correct.
    assert!(proof.released_outer_before_running());
}

#[test]
fn cleanup_of_closing_live_joins_without_projecting_the_context() {
    let locator = SessionLocator::from_parts_for_test(0, 7, identity(9001));
    let route = decide_cleanup_route(&CleanupBindingClaim::JoinLive(locator));

    assert_eq!(route, CleanupRoute::JoinTerminal(locator));
    assert!(
        route.resolves_a_cell(),
        "a joiner still needs the rendezvous"
    );
    assert!(
        !route.projects_the_control_context(),
        "only the winner projects the recorded control context"
    );
    assert!(!route.frees_the_control_context());

    // The winning route is the one that does project it, so the assertion
    // above is a distinction and not a constant.
    let winner = decide_cleanup_route(&CleanupBindingClaim::NeedsLiveClaim(locator));
    assert_eq!(winner, CleanupRoute::ClaimTerminal(locator));
    assert!(winner.projects_the_control_context());
}

#[test]
fn cleanup_of_closing_complete_reads_the_stable_record_without_cell_resolution() {
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let route = decide_cleanup_route(&CleanupBindingClaim::Completed {
        generation: 11,
        result,
    });

    assert_eq!(
        route,
        CleanupRoute::CompletedRecord {
            generation: 11,
            result
        }
    );
    // The generation it names may already have been deleted and its cell
    // reused; a route that resolved it would answer about another session.
    assert!(!route.resolves_a_cell());
    assert!(!route.projects_the_control_context());
    assert!(!route.frees_the_control_context());
}

/// One bounded diagnostic for a locator, taken from the core's own derivation.
///
/// `DiagnosticId::for_locator` is private, which is the point: a carrier copies
/// a diagnostic, it does not mint one. A test needs *a* value, so it takes the
/// one a real winner would have.
fn sample_diagnostic(locator: SessionLocator) -> crate::session::DiagnosticId {
    let mut rendezvous = TerminalRendezvous::new_inactive();
    rendezvous.activate(locator).expect("activates");
    let (winner, ticket) = rendezvous
        .claim(locator, crate::session::TerminalRequest::Cleanup)
        .expect("first arrival wins")
        .into_parts();
    let diagnostic = winner.diagnostic();
    let _ = winner;
    let _ = ticket;
    diagnostic
}

/// Stateful fake used by the production callback runner. Handling a matching
/// row mutates that exact row to Free; a restart then really re-observes slot
/// zero, and success includes a final pass that observes every row empty.
// Proof of safety: every index below is a fixed test fixture position or a
// cursor the same test just asserted, and this is host test code, not a
// driver input path. An out-of-range index here is the test failing, which
// is exactly the outcome wanted.
// The four returned vectors are the four independent things a caller asserts
// about one pass; naming the tuple would hide which is which at the call site.
#[allow(clippy::indexing_slicing, clippy::type_complexity)]
fn run_stateful_fake_scan(
    cells: &[(NativeCellPhase, TerminalRendezvousOutcome)],
    unload: bool,
) -> (
    Vec<usize>,
    usize,
    Vec<(NativeCellPhase, TerminalRendezvousOutcome)>,
    Vec<bool>,
) {
    let cells = core::cell::RefCell::new(cells.to_vec());
    // A retained Completed/Blocked observation remains in the cell. Process
    // loss consumes only this generation's take-once observation marker, so a
    // restart does not select it forever and no test erases fail-stop state.
    let process_loss_pending = core::cell::RefCell::new(vec![true; cells.borrow().len()]);
    let visited = core::cell::RefCell::new(Vec::new());
    let restarts = core::cell::Cell::new(0usize);
    let cell_count = u32::try_from(cells.borrow().len()).expect("small fake table");
    let handled = run_process_callback_scan(
        Some(()),
        cell_count,
        |_, index| {
            let index = usize::try_from(index).expect("fake index");
            // Termination is a property of the scan under test, so it has to be
            // asserted rather than assumed. Without this bound a rule that makes
            // a non-matching phase claimable turns the pass into a loop that
            // reclaims the same reset cell forever: the run then dies by
            // exhausting memory, which the mutation harness reports as
            // NOCOMPILE and excludes from the gate, so the mutant silently
            // stops testing anything. A real table needs a handful of visits;
            // this ceiling is far above any of them.
            assert!(
                visited.borrow().len() < 4096,
                "the fake scan never reached a stable pass: every matching \
                 disposition must clear its cell so the walk can terminate"
            );
            visited.borrow_mut().push(index);
            let (phase, outcome) = {
                let current = cells.borrow();
                current[index]
            };
            let action = if unload {
                decide_unload_scan(phase, outcome)
            } else {
                decide_process_scan(phase, outcome)
            };
            if !unload
                && !process_loss_pending.borrow()[index]
                && matches!(
                    action,
                    ScanAction::ObserveCompleted(_) | ScanAction::ObserveBlocked(_)
                )
            {
                return ProcessCallbackCell::Skip;
            }
            match action {
                ScanAction::Skip => ProcessCallbackCell::Skip,
                ScanAction::Claim => ProcessCallbackCell::Claim(index),
                ScanAction::Join => ProcessCallbackCell::Join(index),
                ScanAction::ObserveCompleted(_) => ProcessCallbackCell::Completed(index),
                ScanAction::ObserveBlocked(_) => ProcessCallbackCell::Blocked(index),
            }
        },
        |_, index| {
            restarts.set(restarts.get().saturating_add(1));
            let action = {
                let current = cells.borrow();
                let (phase, outcome) = current[index];
                if unload {
                    decide_unload_scan(phase, outcome)
                } else {
                    decide_process_scan(phase, outcome)
                }
            };
            if matches!(
                action,
                ScanAction::ObserveCompleted(_) | ScanAction::ObserveBlocked(_)
            ) {
                process_loss_pending.borrow_mut()[index] = false;
            } else {
                cells.borrow_mut()[index] =
                    (NativeCellPhase::Free, TerminalRendezvousOutcome::Open);
            }
        },
    );
    assert!(handled.is_some(), "the fake admitted one callback guard");
    assert!(
        cells
            .borrow()
            .iter()
            .enumerate()
            .all(|(index, (phase, outcome))| {
                *phase == NativeCellPhase::Free
                    || (!process_loss_pending.borrow()[index]
                        && matches!(
                            outcome,
                            TerminalRendezvousOutcome::Completed(_)
                                | TerminalRendezvousOutcome::Blocked(_)
                        ))
            })
    );
    (
        visited.into_inner(),
        restarts.get(),
        cells.into_inner(),
        process_loss_pending.into_inner(),
    )
}

#[test]
fn process_loss_restarts_after_completed_and_finds_second_matching_cell() {
    let result = TerminalResult {
        reason: TerminalReason::ProcessLoss,
        fence_failures: 0,
    };
    // Cell 0 is already completed — copied under the one lock hold, no restart
    // — and cell 2 is a live generation the same process owns. The pass must
    // reach it: stopping at the first match would leave a session behind for a
    // process that is gone.
    let cells = [
        (
            NativeCellPhase::Deleting,
            TerminalRendezvousOutcome::Completed(result),
        ),
        (NativeCellPhase::Free, TerminalRendezvousOutcome::Open),
        (NativeCellPhase::Live, TerminalRendezvousOutcome::Open),
    ];
    let (visited, restarts, _, _) = run_stateful_fake_scan(&cells, false);

    assert!(
        visited.contains(&2),
        "the second matching cell was never seen"
    );
    assert_eq!(restarts, 2, "completion and the later claim each restart");
    assert_eq!(
        visited.first(),
        Some(&0),
        "the completed cell is still observed, not skipped"
    );
}

#[test]
// Proof of safety: every index below is a fixed test fixture position or a
// cursor the same test just asserted, and this is host test code, not a
// driver input path. An out-of-range index here is the test failing, which
// is exactly the outcome wanted.
#[allow(clippy::indexing_slicing)]
fn process_loss_restarts_after_permanently_blocked_and_finds_second_matching_cell() {
    let cell = SessionLocator::from_parts_for_test(0, 2, identity(9201));
    // The diagnostic is whatever a checkpoint payload carries; this row is
    // about the *scan*, so it borrows one rather than minting a second source.
    let payload = crate::adapter::fence::FenceTerminalBlocked::new(
        crate::adapter::fence::FenceFailStopReason::CoreInvariant,
        sample_diagnostic(cell),
    );
    let blocked = crate::session::TerminalBlocked::from_fence(cell, payload);
    // A permanently blocked generation is recorded and the pass continues: it
    // is retained forever, so stopping there would strand every later cell.
    let cells = [
        (
            NativeCellPhase::Removing,
            TerminalRendezvousOutcome::Blocked(blocked),
        ),
        (NativeCellPhase::Live, TerminalRendezvousOutcome::Open),
    ];
    let (visited, restarts, final_cells, pending) = run_stateful_fake_scan(&cells, false);

    assert!(
        visited.contains(&1),
        "a blocked cell must not stop the pass"
    );
    // `contains` and the restart count are both satisfied by a scan that
    // merely advanced past the blocked cell, so neither sees the rule under
    // test. The visit sequence is what distinguishes them: after the blocked
    // observation the pass must resume at cell zero, not at cell one.
    assert_eq!(
        visited,
        vec![0, 0, 1, 0, 1],
        "each discharged match restarts at cell zero: {visited:?}"
    );
    assert_eq!(restarts, 2, "blocked and the live claim each restart");
    assert_eq!(
        final_cells[0], cells[0],
        "handling process loss must not erase the retained Blocked generation"
    );
    assert!(
        !pending[0],
        "only the separate generation-scoped process observation is consumed"
    );
    assert_eq!(
        final_cells[1].0,
        NativeCellPhase::Free,
        "the later live generation was actually handled"
    );
    assert!(matches!(
        decide_process_scan(
            NativeCellPhase::Removing,
            TerminalRendezvousOutcome::Blocked(blocked)
        ),
        ScanAction::ObserveBlocked(_)
    ));
}

#[test]
fn unload_restarts_one_cell_at_a_time_until_a_stable_empty_pass() {
    // Three live generations. Each claim leaves the lock, so each costs one
    // restart, and the walk only ends on a pass that claims nothing — which is
    // what "stable empty" means.
    let cells = [
        (NativeCellPhase::Live, TerminalRendezvousOutcome::Open),
        (NativeCellPhase::Live, TerminalRendezvousOutcome::Open),
        (NativeCellPhase::Live, TerminalRendezvousOutcome::Open),
    ];
    let (visited, restarts, _, _) = run_stateful_fake_scan(&cells, true);

    assert_eq!(restarts, 3, "one restart per generation torn down");
    let final_empty_pass = [0, 1, 2];
    assert!(
        visited.ends_with(&final_empty_pass),
        "the last pass must genuinely re-observe every cell empty: {visited:?}"
    );
    assert_eq!(
        restarts,
        cells.len(),
        "every live generation cost its own restart"
    );
    // Unload and process loss share the decision: one runner, one rule.
    for phase in [
        NativeCellPhase::Free,
        NativeCellPhase::Staging,
        NativeCellPhase::Live,
        NativeCellPhase::Removing,
        NativeCellPhase::Deleting,
        NativeCellPhase::Retired,
    ] {
        assert_eq!(
            decide_scan_continuation(&decide_unload_scan(phase, TerminalRendezvousOutcome::Open)),
            decide_scan_continuation(&decide_process_scan(phase, TerminalRendezvousOutcome::Open)),
            "{phase:?}"
        );
    }
}

#[test]
fn r3_unload_progress_needs_a_complete_pass_not_one_empty_cell() {
    let progress = R3UnloadTestProgress::<3>::begin();
    assert_eq!(progress.cursor(), 0);
    let progress = match progress.observe(R3UnloadTestObservation::<()>::non_match()) {
        R3UnloadTestStep::Scanning(progress) => progress,
        _ => panic!("one empty cell is not a stable pass"),
    };
    assert_eq!(progress.cursor(), 1);
    let progress = match progress.observe(R3UnloadTestObservation::<()>::non_match()) {
        R3UnloadTestStep::Scanning(progress) => progress,
        _ => panic!("two empty cells are not a stable pass"),
    };
    assert_eq!(progress.cursor(), 2);
    assert!(matches!(
        progress.observe(R3UnloadTestObservation::<()>::non_match()),
        R3UnloadTestStep::StableEmpty(_)
    ));
}

#[test]
fn r3_unload_work_carries_one_affine_action_and_restarts_from_zero() {
    struct AffineAction(u32);

    let work = match R3UnloadTestProgress::<64>::begin()
        .observe(R3UnloadTestObservation::Action(AffineAction(41)))
    {
        R3UnloadTestStep::Work(work) => work,
        _ => panic!("an action must leave the fake lock as one work value"),
    };
    let mut performed = None;
    let restart = work.discharge(|action| performed = Some(action.0));
    assert_eq!(performed, Some(41));
    assert_eq!(restart.cursor(), 0);
}

#[test]
fn process_callback_refused_entry_touches_no_registry_or_cell() {
    let mut admission = ProcessCallbackAdmissionHarness::new();
    admission.close();
    let trace = trace_process_callback_entry(&mut admission, &[ScanAction::Claim]);
    assert!(trace.refused());
    assert_eq!(trace.registry_touches(), 0);
    assert_eq!(trace.cell_touches(), 0);
    assert_eq!(trace.guard_identity(), None);
}

#[test]
fn one_process_callback_guard_identity_spans_completed_blocked_and_second_match_restarts() {
    let locator = SessionLocator::from_parts_for_test(0, 7, identity(9202));
    let result = TerminalResult {
        reason: TerminalReason::ProcessLoss,
        fence_failures: 0,
    };
    let blocked = crate::session::TerminalBlocked::from_fence(
        locator,
        crate::adapter::fence::FenceTerminalBlocked::new(
            crate::adapter::fence::FenceFailStopReason::CoreInvariant,
            sample_diagnostic(locator),
        ),
    );
    let mut admission = ProcessCallbackAdmissionHarness::new();
    let trace = trace_process_callback_entry(
        &mut admission,
        &[
            ScanAction::ObserveCompleted(result),
            ScanAction::ObserveBlocked(blocked),
            ScanAction::Claim,
        ],
    );
    assert!(!trace.refused());
    assert_eq!(trace.registry_touches(), 9);
    assert_eq!(trace.cell_touches(), 9);
    assert!(trace.one_guard_spanned_every_touch());
    assert_eq!(trace.restarts(), 3);
    assert_eq!(trace.last_matching_cell(), Some(2));
}

#[test]
fn process_callback_admission_closes_before_unload_scan() {
    let mut admission = ProcessCallbackAdmissionHarness::new();
    let mut old_guard = admission
        .acquire_for_test()
        .map(Some)
        .expect("one callback was admitted before effect one");
    let mut drained = None;
    let mut refused_trace = None;
    let mut first_scan_had_drain_receipt = false;

    for effect in UnloadPlan::EFFECTS {
        match effect {
            UnloadEffect::CloseGlobalAdmissions => {
                admission.close();
                refused_trace = Some(trace_process_callback_entry(
                    &mut admission,
                    &[ScanAction::Claim],
                ));
                assert!(
                    admission.drain().is_none(),
                    "software close cannot hide the old in-flight guard"
                );
            }
            UnloadEffect::WaitProcessCallbacks => {
                // The old guard spans its whole restarted scan and is released
                // once only after the stable no-match pass.
                let pending = core::cell::Cell::new(true);
                let old_guard = run_process_callback_scan(
                    old_guard.take(),
                    2,
                    |_, index| {
                        if index == 0 && pending.get() {
                            ProcessCallbackCell::Completed(())
                        } else {
                            ProcessCallbackCell::Skip
                        }
                    },
                    |_, _| pending.set(false),
                )
                .expect("the already-admitted guard survives software close");
                admission.release(old_guard);
                drained = admission.drain();
            }
            UnloadEffect::ClaimOrJoinOneSession => {
                first_scan_had_drain_receipt = drained.take().is_some();
            }
            _ => {}
        }
    }
    let refused = refused_trace.expect("effect one drives the real admission fake");
    assert!(refused.refused());
    assert_eq!(refused.registry_touches(), 0);
    assert_eq!(refused.cell_touches(), 0);
    assert!(
        first_scan_had_drain_receipt,
        "effect three must mint the exact drained receipt consumed before the first session scan"
    );
}

#[test]
fn mount_absence_cursor_keeps_maximum_next_distinct_from_exhausted() {
    // A cell whose mount generation cannot be incremented is retired, never
    // wrapped. The explicit cursor keeps the maximum usable generation
    // distinct from the terminal state after that generation is consumed.
    //
    // This lives in *this* module because `MountAbsentProof::cursor` does: a
    // mutation to it is graded by this module's command, and an assertion in
    // another module would let that mutant survive.
    let cell = SessionLocator::from_parts_for_test(0, 4, identity(9101));
    let ordinary = MountAbsentProof::for_test(cell, MountAbsenceCursor::Next(5));
    assert_eq!(ordinary.cursor(), MountAbsenceCursor::Next(5));

    let maximum = MountAbsentProof::for_test(cell, MountAbsenceCursor::Next(u64::MAX));
    assert_eq!(maximum.cursor(), MountAbsenceCursor::Next(u64::MAX));

    let exhausted = MountAbsentProof::for_test(cell, MountAbsenceCursor::Exhausted);
    assert_eq!(exhausted.cursor(), MountAbsenceCursor::Exhausted);
    assert_ne!(
        exhausted.cursor(),
        MountAbsenceCursor::Next(u64::MAX),
        "the maximum generation is not a reusable next"
    );
}

#[test]
fn authentic_exhausted_mount_absence_is_claimable_after_reset() {
    let (mut registry, locator, reference) = live_reference();
    let owner = MountOwner::try_new(locator, reference, 0xD00Du32, 0xBEEFu32)
        .expect("the authentic session reference binds the owner");
    let mut mount = MountRendezvous::new_inactive();
    mount.state = PrivateMountRendezvousState::Unmounted {
        locator,
        next_generation: core::num::NonZeroU64::new(u64::MAX),
    };
    mount
        .install(owner)
        .expect("the maximum representable mount generation installs once");

    let (teardown, expected) = match mount
        .take_or_join(ExpectedMountTeardown::Owner {
            locator,
            mount_generation: u64::MAX,
        })
        .expect("the exact owner is taken once")
    {
        MountClaim::Owner {
            owner,
            teardown,
            expected,
        } => {
            let (reference, _device, _vpb) = owner.into_parts();
            let _ = registry
                .release(reference)
                .expect("the mount strong reference releases exactly once");
            (teardown, expected)
        }
        _ => panic!("the present maximum generation must yield its owner"),
    };
    assert_eq!(
        expected,
        ExpectedMountTeardown::Owner {
            locator,
            mount_generation: u64::MAX,
        }
    );

    let drain = signal_done(&mut mount, teardown);
    let reset = reset_owner(&mut mount, drain);
    assert_eq!(reset.mount_generation, u64::MAX);
    let expected = mount
        .expected_teardown(locator)
        .expect("the exhausted rendezvous still authenticates absence");

    match mount
        .take_or_join(expected)
        .expect("exhaustion is an authentic terminal absence, not a refusal")
    {
        MountClaim::Absent {
            expected: observed,
            completed,
        } => {
            assert_eq!(observed, expected);
            assert_eq!(completed.locator, locator);
            assert_eq!(completed.cursor(), MountAbsenceCursor::Exhausted);
        }
        _ => panic!("the reset maximum generation must be authentically absent"),
    }
}

#[test]
fn cleanup_of_closing_blocked_returns_blocked_without_freeing_context() {
    let locator = SessionLocator::from_parts_for_test(1, 3, identity(9002));
    let route = decide_cleanup_route(&CleanupBindingClaim::Blocked {
        locator,
        class: TerminalBlockedClass::FenceInvariant,
    });

    assert_eq!(route, CleanupRoute::Blocked(locator));
    assert!(!route.resolves_a_cell());
    assert!(!route.frees_the_control_context());

    // Nor may any other route free it: CLOSE is the sole deallocator.
    for other in [
        CleanupRoute::Empty,
        CleanupRoute::Setup,
        CleanupRoute::ClaimTerminal(locator),
        CleanupRoute::JoinTerminal(locator),
        CleanupRoute::AlreadyClosed,
    ] {
        assert!(!other.frees_the_control_context(), "{other:?}");
    }

    // And every ordinary arrival at a blocked generation reports the status
    // rather than returning success, while unload alone must not return at all:
    // a blocked generation still owns callback-visible state. This lives here,
    // beside the route it belongs to, because a mutation to
    // `decide_blocked_arrival` is graded by *this* module's command.
    for source in [
        TerminalArrivalSource::Cleanup,
        TerminalArrivalSource::ProcessLoss,
        TerminalArrivalSource::CompleteAfterTerminal,
    ] {
        assert_eq!(
            decide_blocked_arrival(source),
            BlockedArrivalAction::ReportInvalidDeviceState,
            "{source:?}"
        );
    }
    assert_eq!(
        decide_blocked_arrival(TerminalArrivalSource::Unload),
        BlockedArrivalAction::BlockForever,
        "unload never returns from a blocked generation"
    );
}

#[test]
fn close_detaches_blocked_context_but_leaves_it_cell_owned() {
    // A blocked generation keeps its context through `ClosingControlOwner`, so
    // CLOSE observes cell ownership: it may unhook the handle-facing pointer
    // and must do nothing else.
    let refused = ControlContextClosePlan::begin(ControlContextCloseOwnership::CellOwned);
    assert!(matches!(
        refused,
        Err(ControlContextCloseOwnership::CellOwned)
    ));

    // A still-leased context is likewise not CLOSE's to free.
    assert!(matches!(
        ControlContextClosePlan::begin(ControlContextCloseOwnership::Lease),
        Err(ControlContextCloseOwnership::Lease)
    ));
}

#[test]
fn blocked_unload_releases_terminal_join_before_permanent_wait() {
    use crate::adapter::fence::FenceTerminalBlocked;

    // Unload alone does not return from a blocked generation. But it must give
    // up its counted admission *first*: a permanent wait taken while still
    // counted would keep `joiners_drained` from ever signalling, so the
    // generation could never be observed drained by anyone else either.
    assert_eq!(
        decide_blocked_arrival(TerminalArrivalSource::Unload),
        BlockedArrivalAction::BlockForever
    );

    let mut registry = SessionRegistry::<2>::new();
    let (published, mut rendezvous) = publish(&mut registry, 9301);
    let cell = published.locator();
    let (_locator, lease, control) = published.into_parts();
    let (winner, winner_ticket) = rendezvous
        .claim(cell, crate::session::TerminalRequest::Unload)
        .expect("the unload arrival wins")
        .into_parts();
    let joiner = match rendezvous.join(cell).expect("the open generation admits") {
        crate::session::TerminalJoinClaim::Join(ticket) => ticket,
        _ => panic!("an open generation admits a joiner"),
    };
    let blocked = crate::session::TerminalBlocked::from_fence(
        cell,
        FenceTerminalBlocked::new(
            crate::adapter::fence::FenceFailStopReason::CoreInvariant,
            winner.diagnostic(),
        ),
    );
    rendezvous
        .close_and_publish_blocked(winner, blocked)
        .map_err(|_| ())
        .expect("the counted winner publishes its own fail-stop");

    // The unload arrival releases; only after the *last* release does the
    // drained signal exist. So a wait taken before releasing would be waiting
    // on a signal its own count is suppressing.
    let first = rendezvous
        .release(winner_ticket)
        .map_err(|_| ())
        .expect("the winner releases its own count");
    match resolve_terminal_release(first) {
        TerminalWaitDisposition::Blocked { drained, .. } => assert!(
            drained.is_none(),
            "a joiner is still counted, so nothing is drained yet"
        ),
        _ => panic!("a blocked generation publishes a blocked observation"),
    }
    let last = rendezvous
        .release(joiner)
        .map_err(|_| ())
        .expect("the joiner releases its own count");
    match resolve_terminal_release(last) {
        TerminalWaitDisposition::Blocked { drained, .. } => assert!(
            drained.is_some(),
            "the last release after closure is what mints the drained signal"
        ),
        _ => panic!("a blocked generation publishes a blocked observation"),
    }

    let _ = lease;
    let _ = control;
}

#[test]
fn r3_unload_published_and_opaque_wait_matrix_has_exact_authentication_order() {
    use R3UnloadVisibilityTraceStep::{
        AuthenticateOpaqueSlotAndRendezvous, AuthenticatePublishedSlot, ObserveVisibility,
        ReleaseExactTicket, RetainForeignTicket, Unlock, WaitForever,
    };

    assert_eq!(
        trace_r3_unload_visibility_wait(
            R3UnloadVisibilityForTest::Published,
            R3UnloadTicketForTest::Exact,
        ),
        vec![
            ObserveVisibility,
            ReleaseExactTicket,
            AuthenticatePublishedSlot,
            Unlock,
            WaitForever,
        ],
        "Published with a ticket must release that exact admission before locked slot auth",
    );
    assert_eq!(
        trace_r3_unload_visibility_wait(
            R3UnloadVisibilityForTest::Published,
            R3UnloadTicketForTest::None,
        ),
        vec![
            ObserveVisibility,
            AuthenticatePublishedSlot,
            Unlock,
            WaitForever,
        ],
        "the direct Published scan authenticates the slot but fabricates no release",
    );
    assert_eq!(
        trace_r3_unload_visibility_wait(
            R3UnloadVisibilityForTest::Published,
            R3UnloadTicketForTest::Foreign,
        ),
        vec![
            ObserveVisibility,
            AuthenticatePublishedSlot,
            RetainForeignTicket,
            Unlock,
            WaitForever,
        ],
        "a foreign Published ticket cannot be released or substituted into another slot receipt",
    );
    assert_eq!(
        trace_r3_unload_visibility_wait(
            R3UnloadVisibilityForTest::Opaque,
            R3UnloadTicketForTest::Exact,
        ),
        vec![
            ObserveVisibility,
            AuthenticateOpaqueSlotAndRendezvous,
            ReleaseExactTicket,
            Unlock,
            WaitForever,
        ],
        "Opaque authenticates slot+rendezvous before conditionally releasing",
    );
    assert_eq!(
        trace_r3_unload_visibility_wait(
            R3UnloadVisibilityForTest::Opaque,
            R3UnloadTicketForTest::Foreign,
        ),
        vec![
            ObserveVisibility,
            AuthenticateOpaqueSlotAndRendezvous,
            RetainForeignTicket,
            Unlock,
            WaitForever,
        ],
        "an invalid Opaque ticket is retained forever, never fabricated as drained",
    );
    assert_eq!(
        trace_r3_unload_visibility_wait(
            R3UnloadVisibilityForTest::Opaque,
            R3UnloadTicketForTest::None,
        ),
        vec![
            ObserveVisibility,
            AuthenticateOpaqueSlotAndRendezvous,
            Unlock,
            WaitForever,
        ],
        "the direct Opaque scan authenticates but has no ticket release edge",
    );
}

#[test]
fn r3_finalizer_admission_spans_queue_to_callback_and_effect_seven_resolves_before_wait() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let guard = admission
        .acquire_for_queue(3)
        .expect("the queue deposit is admitted before effect seven closes the door");
    assert!(!admission.cell_reusable(3));
    admission.close();
    assert!(
        admission.acquire_for_queue(4).is_none(),
        "effect seven refuses every later queue deposit"
    );
    assert_eq!(
        admission.effect_seven_step(3),
        R3FinalizerDrainStep::WaitForVisibility,
        "effect seven must resolve a queued/running callback before global rundown wait"
    );

    admission.publish_resolution(3, R3FinalizerResolutionForTest::Ordinary);
    assert_eq!(
        admission.effect_seven_step(3),
        R3FinalizerDrainStep::WaitForRundown,
        "ordinary visibility permits the rundown wait, but does not forge its completion"
    );
    assert!(!admission.cell_reusable(3));
    admission.release_after_callback(guard);
    assert!(admission.cell_reusable(3));
    assert_eq!(
        admission.effect_seven_step(3),
        R3FinalizerDrainStep::Drained,
    );
}

#[test]
fn r3_finalizer_opaque_resolution_authenticates_and_never_enters_global_wait() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let _retained_guard = admission
        .acquire_for_queue(7)
        .expect("the opaque worker was admitted with its queued deposit");
    admission.close();
    admission.publish_resolution(7, R3FinalizerResolutionForTest::Opaque);
    assert_eq!(
        admission.effect_seven_step(7),
        R3FinalizerDrainStep::AuthenticatedPermanentWait,
        "opaque visibility must divert to an authenticated nonreturn before ExWait",
    );
    assert!(!admission.cell_reusable(7));
    assert!(
        admission.drain_receipt().is_none(),
        "a permanently retained callback admission is never called drained"
    );
}

#[test]
fn r3_finalizer_effect_seven_authenticates_after_callback_publishes_then_releases() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let guard = admission
        .acquire_for_queue(17)
        .expect("the callback is admitted with its queued generation");
    admission.close();
    admission.publish_resolution(17, R3FinalizerResolutionForTest::Published);
    admission.release_after_durable_resolution(guard);

    assert_eq!(
        admission.effect_seven_step(17),
        R3FinalizerDrainStep::AuthenticatedPermanentWait,
        "the wake-to-lock recheck must authenticate durable Published visibility even after rundown release",
    );
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::AuthenticatedPermanentWait(17),
        "an admission-free durable fail-stop cell is not a generic nonmatch or invariant skip",
    );
    assert!(admission.drain_receipt().is_none());
}

#[test]
fn r3_finalizer_effect_seven_scans_all_sixty_four_before_global_wait() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let first = admission
        .acquire_for_queue(0)
        .expect("cell zero queue admitted");
    let _second = admission
        .acquire_for_queue(63)
        .expect("last cell queue admitted");
    admission.publish_resolution(0, R3FinalizerResolutionForTest::Ordinary);
    admission.close();

    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::WaitForVisibility(63),
        "an ordinary/empty prefix cannot shortcut the unresolved last cell into ExWait",
    );
    admission.publish_resolution(63, R3FinalizerResolutionForTest::Opaque);
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::AuthenticatedPermanentWait(63),
        "the full pass must divert on the later authenticated Opaque cell before ExWait",
    );
    admission.release_after_callback(first);
}

#[test]
fn r3_finalizer_effect_seven_rejects_orphan_ledger_without_callback_admission() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    admission.corrupt_inactive_finalizer_ledger_for_test(41);
    admission.close();

    assert_eq!(
        admission.effect_seven_step(41),
        R3FinalizerDrainStep::FailStop,
        "no callback admission is not a non-match unless Idle, locator, deposit, and handoff are all empty",
    );
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::FailStop(41),
        "the fixed 64-cell pass must reject an orphan finalizer ledger before ExWait",
    );
    assert!(
        admission.drain_receipt().is_none(),
        "a corrupted ledger cannot mint the effect-seven drained receipt",
    );
}

#[test]
fn r3_finalizer_visibility_latch_survives_reset_until_effect_seven_locked_ack() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let guard = admission
        .acquire_for_queue(23)
        .expect("the queued callback owns the generation-scoped admission");
    admission.close();

    assert_eq!(
        admission.effect_seven_step(23),
        R3FinalizerDrainStep::WaitForVisibility,
        "effect seven observes unresolved work before dropping the registry lock",
    );

    // Adversarial interleaving: while unload has not entered its wait yet, the
    // callback publishes ordinary visibility, resets the cell, and releases
    // its rundown admission.  Reset must not erase the only wake.
    admission.publish_resolution(23, R3FinalizerResolutionForTest::Ordinary);
    admission.release_after_callback(guard);
    assert!(
        admission.visibility_latched_for_test(23),
        "ordinary reset must leave the resolution wake latched",
    );
    assert!(
        admission.drain_receipt().is_none(),
        "effect nine cannot pass while effect seven has not acknowledged the latch",
    );

    assert_eq!(
        admission.effect_seven_step(23),
        R3FinalizerDrainStep::Drained,
        "the wake-to-lock recheck authenticates the exact empty callback epilogue",
    );
    assert!(
        !admission.visibility_latched_for_test(23),
        "the locked exact-nonmatch receipt is the sole effect-seven ACK",
    );
    assert!(admission.drain_receipt().is_some());
}

#[test]
fn r3_finalizer_completed_visibility_before_reset_is_ordinary_in_flight() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let guard = admission
        .acquire_for_queue(27)
        .expect("the callback admission spans its delete suffix");
    admission.close();
    assert_eq!(
        admission.effect_seven_step(27),
        R3FinalizerDrainStep::WaitForVisibility,
    );

    // The callback has durably published Completed and signalled visibility,
    // but it is still waiting joiners/access rundown before reset. This is a
    // healthy in-flight ordinary callback, not a signalled invariant hole.
    admission.publish_resolution(27, R3FinalizerResolutionForTest::Ordinary);
    assert!(admission.visibility_latched_for_test(27));
    assert_eq!(
        admission.effect_seven_step(27),
        R3FinalizerDrainStep::WaitForRundown,
        "Completed + the exact callback admission authenticates ordinary in-flight work",
    );
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::WaitForRundown,
        "the resolution pass reaches ExWait instead of parking on the signalled latch",
    );

    admission.release_after_callback(guard);
    assert!(admission.drain_receipt().is_none());
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::Drained,
        "the post-rundown pass authenticates reset and acknowledges the latch",
    );
    assert!(admission.drain_receipt().is_some());
}

#[test]
fn r3_finalizer_completed_visibility_with_pending_ordinary_handoff_reaches_rundown() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let guard = admission
        .acquire_for_queue(31)
        .expect("the callback owns the exact queued generation");
    admission.close();

    // The callback deposits its affine Ordinary handoff before executing the
    // delete suffix. It can then publish Completed and signal while the winner
    // has not yet retaken the lock to consume that handoff.
    admission.store_ordinary_handoff_for_test(31);
    admission.publish_resolution(31, R3FinalizerResolutionForTest::Ordinary);
    assert_eq!(
        admission.effect_seven_step(31),
        R3FinalizerDrainStep::WaitForRundown,
        "a matching Ordinary handoff is part of the authenticated healthy window",
    );
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::WaitForRundown,
    );

    admission.take_ordinary_handoff_for_test(31);
    admission.release_after_callback(guard);
    assert_eq!(
        admission.effect_seven_full_scan(),
        R3FinalizerFullScanOutcome::Drained,
    );
}

#[test]
fn r3_finalizer_completed_visibility_never_accepts_an_opaque_handoff_as_ordinary() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let _guard = admission
        .acquire_for_queue(37)
        .expect("the callback owns the exact queued generation");
    admission.close();
    admission.store_opaque_handoff_for_test(37);
    admission.publish_resolution(37, R3FinalizerResolutionForTest::Ordinary);

    assert_eq!(
        admission.effect_seven_step(37),
        R3FinalizerDrainStep::FailStop,
        "Completed alone cannot relabel an Opaque handoff as an ordinary callback",
    );
}

#[test]
fn next_staging_generation_clears_an_unload_unobserved_visibility_latch() {
    let mut admission = R3FinalizerAdmissionHarness::new();
    let guard = admission
        .acquire_for_queue(29)
        .expect("the old generation queues its callback");
    admission.publish_resolution(29, R3FinalizerResolutionForTest::Ordinary);
    admission.release_after_callback(guard);
    assert!(admission.visibility_latched_for_test(29));

    // No unload is active here.  The next Staging publication owns the same
    // locked generation-event reset used in production and must not inherit
    // the old notification into its unresolved state.
    let next = admission
        .acquire_for_queue(29)
        .expect("the fully exited callback leaves a reusable permanent cell");
    assert!(
        !admission.visibility_latched_for_test(29),
        "new-generation admission clears the previous generation's latch",
    );
    let _ = next;
}

#[test]
fn close_free_precedes_control_context_admission_release() {
    // Unload waits on the control-context admission before it frees
    // callback-visible state. So the admission must be released *after* the
    // context is gone — otherwise unload can observe the rundown reach zero
    // while the allocation is still reachable, and free the root under it.
    let mut progress =
        match ControlContextClosePlan::begin(ControlContextCloseOwnership::CloseRight) {
            Ok(progress) => progress,
            Err(_) => panic!("a transferred close right admits the deallocation plan"),
        };
    let mut freed_at = None;
    let mut released_at = None;
    let mut position = 0usize;
    loop {
        progress = match progress {
            ControlContextCloseProgress::Effect(effect) => {
                match effect.effect() {
                    ControlContextCloseEffect::DestroyAndFreeContext => freed_at = Some(position),
                    ControlContextCloseEffect::ReleaseControlContextAdmission => {
                        released_at = Some(position);
                    }
                    ControlContextCloseEffect::DetachFsContext => {}
                }
                position = position.saturating_add(1);
                effect.succeeded()
            }
            ControlContextCloseProgress::Complete(completion) => {
                // The plan's own proof says the same thing; checking both means
                // a proof that became a constant would be visible here.
                assert!(completion.freed_before_admission_release());
                break;
            }
        };
    }
    assert_eq!(freed_at, Some(1));
    assert_eq!(released_at, Some(2));
    assert!(
        freed_at < released_at,
        "the admission was released while the context was still reachable"
    );
}

#[test]
fn control_context_lease_blocks_unload_across_cell_reuse_until_close() {
    let old = SessionLocator::from_parts_for_test(0, 3, identity(9401));
    let new = SessionLocator::from_parts_for_test(0, 4, identity(9402));
    assert_eq!(old.slot_index(), new.slot_index());
    assert_ne!(
        old, new,
        "the same permanent cell now names a new generation"
    );
    let mut admission = ControlContextAdmissionHarness::new();
    let mut old_context_lease = admission
        .acquire()
        .map(Some)
        .expect("CREATE admits the old generation's context");
    admission.close();
    assert!(
        admission.drain().is_none(),
        "cell reuse cannot discharge the old completed context's lease"
    );

    let completed = decide_cleanup_route(&CleanupBindingClaim::Completed {
        generation: old.generation(),
        result: TerminalResult {
            reason: TerminalReason::Cleanup,
            fence_failures: 0,
        },
    });
    assert!(!completed.resolves_a_cell());
    assert!(matches!(
        ControlContextClosePlan::begin(ControlContextCloseOwnership::Lease),
        Err(ControlContextCloseOwnership::Lease)
    ));

    let mut close = ControlContextClosePlan::begin(ControlContextCloseOwnership::CloseRight)
        .expect("CLOSE owns the only deallocation right");
    let mut close_trace = Vec::new();
    loop {
        close = match close {
            ControlContextCloseProgress::Effect(effect) => {
                close_trace.push(effect.effect());
                if effect.effect() == ControlContextCloseEffect::ReleaseControlContextAdmission {
                    admission.release(
                        old_context_lease
                            .take()
                            .expect("the close plan releases the lease once"),
                    );
                }
                effect.succeeded()
            }
            ControlContextCloseProgress::Complete(completion) => {
                assert!(completion.freed_before_admission_release());
                break;
            }
        };
    }
    assert_eq!(
        close_trace,
        vec![
            ControlContextCloseEffect::DetachFsContext,
            ControlContextCloseEffect::DestroyAndFreeContext,
            ControlContextCloseEffect::ReleaseControlContextAdmission,
        ],
        "real CLOSE must free the old context before releasing its embedded admission lease"
    );
    let effect_nine_receipt = admission
        .drain()
        .expect("only CLOSE free then release can mint the effect-nine receipt");

    let unload: Vec<String> = UnloadPlan::EFFECTS
        .iter()
        .map(|effect| format!("{effect:?}"))
        .collect();
    let wait = unload
        .iter()
        .position(|effect| effect == "WaitControlContextAdmission");
    let destructive_suffix = unload
        .iter()
        .position(|effect| effect == "UnregisterFilesystem")
        .expect("the real unload roster contains its destructive suffix");
    assert!(
        matches!(wait, Some(index) if index < destructive_suffix),
        "unload must wait for the CLOSE-released control-context lease before root destruction after cell reuse; trace={unload:?}"
    );
    let _consumed_by_effect_nine = effect_nine_receipt;
}

#[test]
fn close_frees_only_after_close_context_right_transfer() {
    let mut progress =
        match ControlContextClosePlan::begin(ControlContextCloseOwnership::CloseRight) {
            Ok(progress) => progress,
            Err(_) => panic!("a transferred close right admits the deallocation plan"),
        };
    let mut order = Vec::new();
    loop {
        progress = match progress {
            ControlContextCloseProgress::Effect(effect) => {
                order.push(effect.effect());
                effect.succeeded()
            }
            ControlContextCloseProgress::Complete(completion) => {
                assert!(completion.freed_before_admission_release());
                break;
            }
        };
    }
    assert_eq!(
        order,
        vec![
            ControlContextCloseEffect::DetachFsContext,
            ControlContextCloseEffect::DestroyAndFreeContext,
            ControlContextCloseEffect::ReleaseControlContextAdmission,
        ],
        "the free happens after the detach and before the admission release"
    );
}

#[test]
fn process_or_unload_winner_before_cleanup_pins_control_context() {
    let mut registry = SessionRegistry::<2>::new();
    let (published, mut rendezvous, mut owning_binding) = publish_with_binding(&mut registry, 9003);
    let locator = published.locator();
    let (_locator, lease, control) = published.into_parts();
    let mut lease = Some(lease);

    // A process-loss or unload winner arrives before CLEANUP does.
    let claim = crate::session::prepare_terminal_claim(
        &mut registry,
        &mut owning_binding,
        &mut rendezvous,
        &mut lease,
        locator,
        crate::session::TerminalRequest::ProcessLoss,
    )
    .expect("the live generation admits its first arrival");
    let winner = match claim.commit() {
        crate::session::CoreTerminalDisposition::Winner(winner) => winner,
        _ => panic!("the first arrival wins"),
    };

    // The later CLEANUP now sees ClosingLive and takes the join route, which
    // neither projects nor frees the recorded control context: the cell keeps
    // it through the winner's `ClosingControlOwner`.
    let cleanup = owning_binding
        .claim_cleanup()
        .expect("a closing-live binding admits CLEANUP");
    let route = decide_cleanup_route(&cleanup);
    assert_eq!(route, CleanupRoute::JoinTerminal(locator));
    assert!(!route.projects_the_control_context());
    assert!(!route.frees_the_control_context());

    let (winner, terminal, ticket) = winner.into_parts();
    let _ = winner;
    let _ = terminal;
    let _ = ticket;
    let _ = control;
}

#[test]
fn complete_after_terminal_open_waits_without_pending_or_short_guard() {
    // A wait is only admissible once every short guard is gone. Each of the
    // three preconditions is individually load-bearing.
    let all_released = TerminalWaitPreconditions {
        outer_file_rundown_released: true,
        session_access_guard_released: true,
        registry_lock_released: true,
    };
    assert_eq!(decide_terminal_wait(all_released), Ok(()));
    for held in [
        TerminalWaitPreconditions {
            outer_file_rundown_released: false,
            ..all_released
        },
        TerminalWaitPreconditions {
            session_access_guard_released: false,
            ..all_released
        },
        TerminalWaitPreconditions {
            registry_lock_released: false,
            ..all_released
        },
    ] {
        assert_eq!(
            decide_terminal_wait(held),
            Err(LifecycleError::WrongState),
            "{held:?}"
        );
    }

    // While the runner has parked a transient residual the outcome stays Open,
    // and the owner goes back around the loop still counted. It never converts
    // that disposition into a completion.
    let mut registry = SessionRegistry::<2>::new();
    let (published, mut rendezvous) = publish(&mut registry, 9004);
    let locator = published.locator();
    let (_locator, lease, control) = published.into_parts();
    let claim = rendezvous
        .claim(locator, crate::session::TerminalRequest::Cleanup)
        .expect("the first arrival wins");
    let (winner, ticket) = claim.into_parts();
    let release = rendezvous
        .release(ticket)
        .map_err(|_| ())
        .expect("the counted owner releases against its own generation");
    match resolve_terminal_release(release) {
        TerminalWaitDisposition::Open(ticket) => {
            assert_eq!(ticket.locator(), locator);
            let _ = ticket;
        }
        _ => panic!("an Open generation must not publish a completion"),
    }
    let _ = winner;
    let _ = lease;
    let _ = control;
}

#[test]
fn process_loss_open_waits_then_restarts_generation_scan() {
    // Claim and Join both leave the registry lock to run or wait, so the
    // one-cell-at-a-time pass cannot keep its index.
    for action in [ScanAction::Claim, ScanAction::Join] {
        assert_eq!(
            decide_scan_continuation(&action),
            ScanContinuation::RestartScan
        );
    }
    // Only a nonmatching Skip stays in the same pass. Completed is still a
    // matching generation handled outside the observation hold and restarts.
    let result = TerminalResult {
        reason: TerminalReason::ProcessLoss,
        fence_failures: 0,
    };
    assert_eq!(
        decide_scan_continuation(&ScanAction::Skip),
        ScanContinuation::NextCell
    );
    assert_eq!(
        decide_scan_continuation(&ScanAction::ObserveCompleted(result)),
        ScanContinuation::RestartScan
    );
    // Blocked is pinned here for the same reason Completed is, and pinned
    // *separately* rather than through the combined arm: the two are one arm
    // today, so a table that answered only Completed would let a Blocked-only
    // regression through unseen.
    let blocked_cell = SessionLocator::from_parts_for_test(0, 2, identity(9202));
    let blocked = crate::session::TerminalBlocked::from_fence(
        blocked_cell,
        crate::adapter::fence::FenceTerminalBlocked::new(
            crate::adapter::fence::FenceFailStopReason::CoreInvariant,
            sample_diagnostic(blocked_cell),
        ),
    );
    assert_eq!(
        decide_scan_continuation(&ScanAction::ObserveBlocked(blocked)),
        ScanContinuation::RestartScan
    );

    // And the decision really is driven by the observed cell, not assumed: a
    // Live cell with an Open outcome is exactly the Claim that restarts.
    assert!(matches!(
        decide_process_scan(NativeCellPhase::Live, TerminalRendezvousOutcome::Open),
        ScanAction::Claim
    ));
    assert_eq!(
        decide_scan_continuation(&decide_process_scan(
            NativeCellPhase::Live,
            TerminalRendezvousOutcome::Open
        )),
        ScanContinuation::RestartScan
    );
    assert_eq!(
        decide_scan_continuation(&decide_process_scan(
            NativeCellPhase::Free,
            TerminalRendezvousOutcome::Open
        )),
        ScanContinuation::NextCell
    );
}

#[test]
fn process_scan_compares_the_cell_process_observation_without_projection() {
    let locator = SessionLocator::from_parts_for_test(1, 9, identity(9010));
    let observed = NativeCellProcessObservation {
        recorded_process: Some(0x1111usize),
        phase: NativeCellPhase::Live,
        published_locator: Some(locator),
    };

    assert_eq!(observe_cell_process(&observed, 0x1111), Some(locator));
    assert_eq!(observe_cell_process(&observed, 0x2222), None);
    assert_eq!(
        observe_cell_process(
            &NativeCellProcessObservation {
                phase: NativeCellPhase::Staging,
                ..observed
            },
            0x1111,
        ),
        None,
    );
    assert_eq!(
        observe_cell_process(
            &NativeCellProcessObservation {
                published_locator: None,
                ..observed
            },
            0x1111,
        ),
        None,
    );
}

#[test]
fn multiple_access_guards_never_create_aliasing_mutable_session_references() {
    let mut session = 41u32;
    let pointer = core::ptr::NonNull::from(&mut session);
    // SAFETY: the fixture keeps `session` alive and does not mutate it while
    // either shared projection exists.
    let first = unsafe { SharedSessionProjection::from_non_null(pointer) };
    // SAFETY: as above; multiple access rundowns may name the same live shell.
    let second = unsafe { SharedSessionProjection::from_non_null(pointer) };

    assert_eq!(*first.get(), 41);
    assert_eq!(*second.get(), 41);
    assert!(core::ptr::eq(first.get(), second.get()));
}

#[test]
fn ring_projection_is_disjoint_locked_and_cannot_escape_or_cross_a_wait() {
    use crate::enter::{EnterError, EnterRole, RingEnterState};

    let mut first_state = RingEnterState::new(3);
    let mut second_state = RingEnterState::new(4);
    // SAFETY: each fixture projection has exclusive access to a distinct state
    // for the complete wrapper lifetime.
    let mut first = LockedEnterState::from_locked(&mut first_state);
    let mut second = LockedEnterState::from_locked(&mut second_state);

    let lease = first
        .acquire_role(77, EnterRole::Sq)
        .expect("the first locked state admits its role");
    let (error, lease) = second
        .release_role(lease)
        .expect_err("a disjoint ring cannot consume another ring's lease");
    assert_eq!(error, EnterError::InvalidIdentity);
    first
        .release_role(lease)
        .expect("the originating locked state consumes the lease");
}

#[test]
fn every_ring_lock_is_initialized_before_publication_and_released_at_the_saved_irql() {
    let mut initialized = Vec::new();
    let proof = initialize_ring_locks(4, |index| initialized.push(index));
    assert_eq!(initialized, vec![0, 1, 2, 3]);
    assert_eq!(proof.ring_count(), 4);

    let mut released = Vec::new();
    let saved = acquire_saved_irql(|| 0x2au8);
    saved.release_with(|old_irql| released.push(old_irql));
    assert_eq!(released, vec![0x2a]);
}

#[test]
fn resolver_rejects_missing_or_foreign_shell_root_owner_slots() {
    let locator = SessionLocator::from_parts_for_test(0, 5, identity(9020));
    let foreign = SessionLocator::from_parts_for_test(0, 6, identity(9020));
    let exact = NativeOwnerSlotObservation {
        shell_locator: Some(locator),
        root_locator: Some(locator),
        shell_matches_mirror: true,
    };

    assert!(native_owner_slots_match(locator, exact));
    for rejected in [
        NativeOwnerSlotObservation {
            shell_locator: None,
            ..exact
        },
        NativeOwnerSlotObservation {
            root_locator: None,
            ..exact
        },
        NativeOwnerSlotObservation {
            shell_locator: Some(foreign),
            ..exact
        },
        NativeOwnerSlotObservation {
            root_locator: Some(foreign),
            ..exact
        },
        NativeOwnerSlotObservation {
            shell_matches_mirror: false,
            ..exact
        },
    ] {
        assert!(!native_owner_slots_match(locator, rejected));
    }
}

struct TestNativeShell {
    mirror: usize,
    effects: core::cell::RefCell<Vec<u8>>,
}

impl NativeSessionSharedOps for TestNativeShell {
    type Mirror = usize;

    fn matches_mirror(&self, mirror: Self::Mirror) -> bool {
        self.mirror == mirror
    }

    fn checkpoint_close_session_admission(&self) -> bool {
        self.effects.borrow_mut().push(0);
        true
    }

    fn checkpoint_signal_existing_enter_waiters(&self) -> bool {
        self.effects.borrow_mut().push(1);
        true
    }

    fn checkpoint_wait_existing_sq_cq_roles_and_consumers(&self) -> bool {
        self.effects.borrow_mut().push(2);
        true
    }

    fn checkpoint_remove_producer_mappings_reverse(&self) -> bool {
        self.effects.borrow_mut().push(3);
        true
    }

    fn checkpoint_wait_producer_and_mapping_capture_rundown(&self) -> bool {
        self.effects.borrow_mut().push(4);
        true
    }

    fn checkpoint_retire_existing_grant_and_credit_state(&self) -> bool {
        self.effects.borrow_mut().push(5);
        true
    }

    fn checkpoint_deposit_pending_fence_wakes(&self) -> bool {
        self.effects.borrow_mut().push(20);
        true
    }

    fn checkpoint_acquire_consumers_increasing(&self) -> bool {
        self.effects.borrow_mut().push(21);
        true
    }

    fn checkpoint_release_consumers(&self) -> bool {
        self.effects.borrow_mut().push(22);
        true
    }

    fn checkpoint_queue_installed_work(&self) -> bool {
        self.effects.borrow_mut().push(23);
        true
    }

    fn checkpoint_wait_pending_and_owners(&self) -> bool {
        self.effects.borrow_mut().push(24);
        true
    }

    fn checkpoint_release_read_only_mappings_reverse(&self) -> bool {
        self.effects.borrow_mut().push(6);
        true
    }

    fn checkpoint_release_mdls_and_system_view(&self) -> bool {
        self.effects.borrow_mut().push(7);
        true
    }

    fn checkpoint_release_captured_process(&self) -> bool {
        self.effects.borrow_mut().push(8);
        true
    }

    fn checkpoint_release_transient_arrays_and_backing(&self) -> bool {
        self.effects.borrow_mut().push(9);
        true
    }

    fn checkpoint_delete_vdo_once(&self) -> bool {
        self.effects.borrow_mut().push(10);
        true
    }
}

#[test]
fn installed_session_mints_one_native_owner_pair_with_closed_shared_operations() {
    let mut registry = SessionRegistry::<1>::new();
    let id = identity(9030);
    let mut binding = ControlBinding::new().expect("binding ID capacity");
    let reservation = binding.begin_setup().expect("fresh binding");
    let mut transaction = SetupTransaction::begin(id).expect("valid identity");
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = transaction.stage(stage).expect("strict setup stage");
    }
    let mut installed = registry
        .install_staging(&transaction, &binding, &reservation)
        .expect("free registry cell");
    let locator = installed.locator();

    let rights = installed
        .take_native_owner_bind_rights()
        .expect("the authentic install mints one owner pair");
    assert!(
        installed.take_native_owner_bind_rights().is_none(),
        "the same InstalledSession must not mint a second owner pair"
    );
    let (shell_right, root_right, finalizer_right) = rights.into_parts();
    let mut finalizer = crate::adapter::fence::R3FinalizerCell::<()>::new_unbound();
    finalizer
        .bind(finalizer_right)
        .map_err(|_| ())
        .expect("the same install binds its finalizer storage once");
    let shell = shell_right.bind(TestNativeShell {
        mirror: 0x1234,
        effects: core::cell::RefCell::new(Vec::new()),
    });
    let root = root_right.bind(0x55u64);

    assert_eq!(shell.locator(), locator);
    assert_eq!(root.locator(), locator);
    assert_eq!(finalizer.locator(), Some(locator));
    assert!(shell.matches_mirror(0x1234));
    assert!(shell.checkpoint_close_session_admission());
    assert!(shell.checkpoint_signal_existing_enter_waiters());
    assert!(shell.checkpoint_wait_existing_sq_cq_roles_and_consumers());
    assert!(shell.checkpoint_remove_producer_mappings_reverse());
    assert!(shell.checkpoint_wait_producer_and_mapping_capture_rundown());
    assert!(shell.checkpoint_retire_existing_grant_and_credit_state());
    assert!(shell.checkpoint_release_read_only_mappings_reverse());
    assert!(shell.checkpoint_release_mdls_and_system_view());
    assert!(shell.checkpoint_release_captured_process());
    assert!(shell.checkpoint_release_transient_arrays_and_backing());
    assert!(shell.checkpoint_delete_vdo_once());
}
#[test]
fn used_deleted_cell_events_become_effect_nine_quiescent() {
    let used = R3UnloadEventStatesForTest {
        terminal_outcome: true,
        visibility_resolution: true,
        joiners_drained: true,
        mount_complete: true,
        mount_waiters_drained: true,
        mount_reset_complete: true,
        mount_reset_waiters_drained: true,
    };
    assert!(!r3_unload_events_are_quiescent_for_test(used));

    let deleted = reset_r3_unload_events_after_delete_for_test(used);
    assert!(
        !r3_unload_events_are_quiescent_for_test(deleted),
        "prepared reset must retain the visibility wake until effect seven acknowledges it"
    );
    assert!(deleted.visibility_resolution);

    let acknowledged = acknowledge_r3_unload_visibility_after_effect_seven_for_test(deleted);
    assert!(
        r3_unload_events_are_quiescent_for_test(acknowledged),
        "only the locked effect-seven ACK makes a used deleted cell effect-nine quiescent",
    );

    let next_staging = clear_r3_unload_visibility_before_staging_for_test(deleted);
    assert!(
        !next_staging.visibility_resolution,
        "a later Staging generation is the only alternate consumer of an unobserved latch",
    );
    assert!(deleted.joiners_drained);
    assert!(deleted.mount_waiters_drained);
    assert!(deleted.mount_reset_waiters_drained);
}

#[test]
fn final_blocked_payloads_retain_fence_and_delete_terminal_wrappers() {
    let session = include_str!("../../session.rs");
    assert!(
        session.contains("from_fence") && session.contains("from_delete"),
        "TerminalBlocked must retain whole fence and delete wrappers"
    );
    assert!(
        !session.contains("from_checkpoint"),
        "the checkpoint blocked wrapper must not remain"
    );
}

#[test]
fn final_fence_blocked_detail_preserves_the_exact_fail_stop_reason() {
    let fence = include_str!("../fence.rs");
    assert!(
        fence.contains("struct FenceTerminalBlocked")
            && fence.contains("reason: FenceFailStopReason"),
        "FenceTerminalBlocked must store the exact fail-stop reason"
    );
}

#[test]
fn final_delete_blocked_detail_preserves_the_exact_preflight_step() {
    let fence = include_str!("../fence.rs");
    assert!(
        fence.contains("struct DeleteTerminalBlocked")
            && fence.contains("step: FinalizerPreflightStep"),
        "DeleteTerminalBlocked must store the exact preflight step"
    );
}

#[test]
fn final_fence_blocked_wakes_winner_and_joiner_not_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/lifecycle.rs");
    assert!(
        fsd.contains("from_fence") && fsd.contains("visibility_resolution"),
        "fence blocked must wake winner and joiner through the visibility event"
    );
}

#[test]
fn final_delete_blocked_wakes_winner_and_joiner_not_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/lifecycle.rs");
    assert!(
        fsd.contains("from_delete") && fsd.contains("visibility_resolution"),
        "delete blocked must wake winner and joiner through the visibility event"
    );
}

#[test]
fn closing_control_owner_transfers_once_or_remains_in_fail_stop() {
    let fsd = include_str!("../../../../fsring-fsd/src/lifecycle.rs");
    let fence = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("ClosingControlOwner")
            && (fence.contains("FinishFenceFailStopDeposit")
                || fence.contains("FenceCompletionFailStopDeposit")),
        "the closing owner must transfer once on complete or remain in fail-stop"
    );
}

/// What CLEANUP does after one pass of its committed route, for every pass and
/// every result.
///
/// The row that matters is the first: a CLEANUP whose terminal completed must
/// claim again. The winner consumed `NeedsLiveClaim` and a joiner `JoinLive`
/// before the terminal ran, so nothing else re-observes the binding, and the
/// record the finalizer stored is never acknowledged -- round 16's leak, which
/// round 17 then "fixed" by letting CLOSE free an unacknowledged record.
#[test]
fn cleanup_continuation_is_total_and_reclaims_exactly_once() {
    use CleanupContinuation::{Proceed, ReclaimOnce, Refuse};
    use CleanupPass::{First, Reclaim};
    use CleanupRouteResult as R;
    use TerminalOutcomeKind as T;

    let rows = [
        (First, R::Terminal(T::Completed), ReclaimOnce),
        (First, R::Terminal(T::Blocked), Refuse),
        (First, R::CompletedAcknowledged, Proceed),
        (First, R::Blocked, Refuse),
        (First, R::OpaqueRetained, Refuse),
        (First, R::AlreadyClosed, Proceed),
        (First, R::Empty, Proceed),
        (First, R::Setup, Proceed),
        (First, R::Refused, Proceed),
        // A second pass never asks for a third.
        (Reclaim, R::Terminal(T::Completed), Refuse),
        (Reclaim, R::Terminal(T::Blocked), Refuse),
        (Reclaim, R::CompletedAcknowledged, Proceed),
        (Reclaim, R::Blocked, Refuse),
        (Reclaim, R::OpaqueRetained, Refuse),
        // After a completed terminal the reclaim must find the record; anything
        // else means it is gone unacknowledged, and saying so is the honest
        // answer.
        (Reclaim, R::AlreadyClosed, Refuse),
        (Reclaim, R::Empty, Refuse),
        (Reclaim, R::Setup, Refuse),
        (Reclaim, R::Refused, Refuse),
    ];
    for (pass, result, expected) in rows {
        assert_eq!(
            continue_cleanup(pass, result),
            expected,
            "{pass:?} after {result:?}"
        );
    }
    assert_eq!(rows.len(), 18, "two passes times nine results");
}

mod close_choreography;
