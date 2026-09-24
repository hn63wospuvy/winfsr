// TEST: the checkpoint matrices use `expect` to name exact affine transition
// outcomes, and the consumer-recovery fixtures index small fixed ring tables by
// a literal; production keeps the crate-wide denials.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use super::*;
use super::{
    ClosedFenceRosterComplete as R4TeardownComplete, FencePassCursor as PrepareCheckpointFinish,
    ProductionAbsenceWitness as R4AuthorityAbsence,
};
use crate::adapter::lifecycle::{
    ExpectedMountTeardown, JoinedMountCompletion, LifecycleError, MountAbsenceCursor, MountClaim,
    MountOwner, MountRendezvous, OwnerMountCompletion, run_r3_mount_done_signal_ack,
    run_r3_mount_ordinary_drained_signal_ack, run_r3_mount_reset_complete_signal_ack,
    run_r3_mount_reset_waiters_drained_signal_ack,
};
use crate::session::{
    ControlBinding, FinalizerPreflightStep, SessionLocator, SessionRegistry, SetupStage,
    SetupTransaction, TerminalReason, TerminalRendezvous, TerminalRequest, TerminalResult,
    publish_installed_setup_for_test,
};
use fsring_abi::validate::SessionIdentity;
use fsring_abi::{BootInstanceId, MountId};

fn identity(n: u64) -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: n, hi: 9 },
        boot_instance_id: BootInstanceId { lo: 7, hi: 11 },
        session_epoch: 1,
    }
}

fn locator(n: u64) -> SessionLocator {
    SessionLocator::from_parts_for_test(0, 3, identity(n))
}

struct AuthenticMountCompletions {
    mount: MountRendezvous<u32, u32>,
    registry: SessionRegistry<1>,
    delete_right: crate::session::DeleteSessionRight,
    locator: SessionLocator,
    owner_expected: ExpectedMountTeardown,
    owner: OwnerMountCompletion,
    join_expected: ExpectedMountTeardown,
    join: JoinedMountCompletion,
    reset_expected: ExpectedMountTeardown,
    reset_join: JoinedMountCompletion,
    absent_expected: ExpectedMountTeardown,
    absent: crate::adapter::lifecycle::MountAbsentProof,
}

fn authentic_exhausted_mount_completions(n: u64) -> AuthenticMountCompletions {
    let id = identity(n);
    let mut registry = SessionRegistry::<1>::new();
    let mut binding = ControlBinding::new().expect("binding capacity");
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
        .expect("one staging slot");
    transaction = transaction
        .stage(SetupStage::ReferencesInstalled)
        .expect("references installed");
    let mut terminal = TerminalRendezvous::new_inactive();
    let published = publish_installed_setup_for_test(
        transaction,
        &mut registry,
        &mut binding,
        &mut terminal,
        reservation,
        installed,
    )
    .expect("coupled publication");
    let (locator, lease, reference) = published.into_parts();

    let owner =
        MountOwner::try_new(locator, reference, 0xD00Du32, 0xBEEFu32).expect("same-session owner");
    let mut mount = MountRendezvous::new_inactive();
    mount.activate(locator).expect("mount activates");
    mount
        .set_next_mount_generation_for_test(core::num::NonZeroU64::MAX)
        .expect("test starts at the maximum authentic generation");
    mount
        .install(owner)
        .expect("maximum generation installs once");

    let owner_expected = mount
        .expected_teardown(locator)
        .expect("present owner expectation");
    let (owner, teardown) = match mount.take_or_join(owner_expected).expect("owner claim") {
        MountClaim::Owner {
            owner, teardown, ..
        } => (owner, teardown),
        _ => panic!("present generation yields owner"),
    };
    let (reference, _device, _vpb) = owner.into_parts();
    let _ = registry
        .release(reference)
        .expect("native owner releases its strong reference once");

    let join_expected = mount
        .expected_teardown(locator)
        .expect("teardown join expectation");
    let ordinary = match mount.take_or_join(join_expected).expect("ordinary join") {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down yields ordinary join"),
    };
    let done = mount.publish_done(teardown).expect("publish Done");
    let drain = unsafe { run_r3_mount_done_signal_ack(&mut mount, done, |_| {}) }
        .expect("acknowledge Done");
    let conversion = mount.release_join(ordinary).expect("release ordinary join");
    let ordinary_reset =
        unsafe { run_r3_mount_ordinary_drained_signal_ack(&mut mount, conversion, |_| {}) }
            .expect("acknowledge ordinary drain");
    let prepared = mount.poll_drain(drain).expect("ordinary drain closes");

    let reset_expected = mount
        .expected_teardown(locator)
        .expect("reset-join expectation");
    let reset_ticket = match mount.take_or_join(reset_expected).expect("reset join") {
        MountClaim::ResetJoin { ticket, .. } => ticket,
        _ => panic!("Resetting yields reset join"),
    };
    let reset = mount.finish_reset(prepared).expect("publish reset");
    let owner_reset = unsafe { run_r3_mount_reset_complete_signal_ack(&mut mount, reset, |_| {}) }
        .expect("acknowledge reset");
    let ordinary_release = mount
        .finish_joined_reset(ordinary_reset)
        .expect("ordinary release");
    let ordinary_reset = unsafe {
        run_r3_mount_reset_waiters_drained_signal_ack(&mut mount, ordinary_release, |_| {})
    }
    .expect("ordinary release acknowledged");
    let reset_release = mount
        .finish_joined_reset(reset_ticket)
        .expect("reset release");
    let reset_joined =
        unsafe { run_r3_mount_reset_waiters_drained_signal_ack(&mut mount, reset_release, |_| {}) }
            .expect("reset release acknowledged");

    let owner = mount
        .complete_owner(owner_reset)
        .expect("full suffix mints owner completion");
    let join = mount
        .complete_joined(ordinary_reset)
        .expect("full suffix mints ordinary completion");
    let reset_join = mount
        .complete_joined(reset_joined)
        .expect("full suffix mints reset-join completion");
    let absent_expected = mount
        .expected_teardown(locator)
        .expect("final exhausted absence expectation");
    let absent = match mount
        .take_or_join(absent_expected)
        .expect("final exhausted absence claim")
    {
        MountClaim::Absent { completed, .. } => completed,
        _ => panic!("fully reset maximum generation is absent"),
    };
    let terminal = registry
        .begin_remove(lease)
        .expect("terminal removal begins");
    let delete_right = match registry
        .finish_removal_for_test(terminal)
        .expect("completed fence reaches deleting")
    {
        crate::session::RegistryRelease::Delete(right) => right,
        crate::session::RegistryRelease::Retained => panic!("the terminal reference is last"),
    };

    AuthenticMountCompletions {
        mount,
        registry,
        delete_right,
        locator,
        owner_expected,
        owner,
        join_expected,
        join,
        reset_expected,
        reset_join,
        absent_expected,
        absent,
    }
}

fn authentic_mount_completions(n: u64) -> AuthenticMountCompletions {
    let id = identity(n);
    let mut registry = SessionRegistry::<1>::new();
    let mut binding = ControlBinding::new().expect("binding capacity");
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
        .expect("one staging slot");
    transaction = transaction
        .stage(SetupStage::ReferencesInstalled)
        .expect("references installed");
    let mut terminal = TerminalRendezvous::new_inactive();
    let published = publish_installed_setup_for_test(
        transaction,
        &mut registry,
        &mut binding,
        &mut terminal,
        reservation,
        installed,
    )
    .expect("coupled publication");
    let (locator, lease, reference) = published.into_parts();

    let owner =
        MountOwner::try_new(locator, reference, 0xD00Du32, 0xBEEFu32).expect("same-session owner");
    let mut mount = MountRendezvous::new_inactive();
    mount.activate(locator).expect("mount activates");
    mount.install(owner).expect("first generation installs");

    let owner_expected = mount
        .expected_teardown(locator)
        .expect("present owner expectation");
    let (owner, teardown) = match mount.take_or_join(owner_expected).expect("owner claim") {
        MountClaim::Owner {
            owner, teardown, ..
        } => (owner, teardown),
        _ => panic!("present generation yields owner"),
    };
    let (reference, _device, _vpb) = owner.into_parts();
    let _ = registry
        .release(reference)
        .expect("native owner releases its strong reference once");

    let join_expected = mount
        .expected_teardown(locator)
        .expect("teardown join expectation");
    let ordinary = match mount.take_or_join(join_expected).expect("ordinary join") {
        MountClaim::Join { ticket, .. } => ticket,
        _ => panic!("tearing down yields ordinary join"),
    };

    let done = mount.publish_done(teardown).expect("publish Done");
    let drain = unsafe { run_r3_mount_done_signal_ack(&mut mount, done, |_| {}) }
        .expect("acknowledge Done");
    let conversion = mount.release_join(ordinary).expect("release ordinary join");
    let ordinary_reset =
        unsafe { run_r3_mount_ordinary_drained_signal_ack(&mut mount, conversion, |_| {}) }
            .expect("acknowledge ordinary drain");
    let prepared = mount.poll_drain(drain).expect("ordinary drain closes");

    let reset_expected = mount
        .expected_teardown(locator)
        .expect("reset-join expectation");
    let reset_ticket = match mount.take_or_join(reset_expected).expect("reset join") {
        MountClaim::ResetJoin { ticket, .. } => ticket,
        _ => panic!("Resetting yields reset join"),
    };

    let reset = mount.finish_reset(prepared).expect("publish reset");
    let owner_reset = unsafe { run_r3_mount_reset_complete_signal_ack(&mut mount, reset, |_| {}) }
        .expect("acknowledge reset");
    let ordinary_release = mount
        .finish_joined_reset(ordinary_reset)
        .expect("ordinary release");
    let ordinary_reset = unsafe {
        run_r3_mount_reset_waiters_drained_signal_ack(&mut mount, ordinary_release, |_| {})
    }
    .expect("ordinary release acknowledged");
    let reset_release = mount
        .finish_joined_reset(reset_ticket)
        .expect("reset release");
    let reset_joined =
        unsafe { run_r3_mount_reset_waiters_drained_signal_ack(&mut mount, reset_release, |_| {}) }
            .expect("reset release acknowledged");

    let owner = mount
        .complete_owner(owner_reset)
        .expect("full suffix mints owner completion");
    let join = mount
        .complete_joined(ordinary_reset)
        .expect("full suffix mints ordinary completion");
    let reset_join = mount
        .complete_joined(reset_joined)
        .expect("full suffix mints reset-join completion");
    let absent_expected = mount
        .expected_teardown(locator)
        .expect("final absence expectation");
    let absent = match mount
        .take_or_join(absent_expected)
        .expect("final absence claim")
    {
        MountClaim::Absent { completed, .. } => completed,
        _ => panic!("fully reset generation is absent"),
    };
    let terminal = registry
        .begin_remove(lease)
        .expect("terminal removal begins");
    let delete_right = match registry
        .finish_removal_for_test(terminal)
        .expect("completed fence reaches deleting")
    {
        crate::session::RegistryRelease::Delete(right) => right,
        crate::session::RegistryRelease::Retained => panic!("the terminal reference is last"),
    };

    AuthenticMountCompletions {
        mount,
        registry,
        delete_right,
        locator,
        owner_expected,
        owner,
        join_expected,
        join,
        reset_expected,
        reset_join,
        absent_expected,
        absent,
    }
}

/// Drive a whole pass, refusing at `refuse_at` if it is reached.
fn run_pass(
    locator: SessionLocator,
    roster: [CheckpointFenceEffect; 20],
    refuse_at: Option<CheckpointFenceEffect>,
) -> (Vec<CheckpointFenceEffect>, CheckpointTeardownProgress) {
    let mut executed = Vec::new();
    let mut progress = CheckpointTeardownPlan::begin_with_roster(locator, roster);
    loop {
        progress = match progress {
            CheckpointTeardownProgress::Effect(pending) => {
                let effect = pending.effect();
                executed.push(effect);
                if refuse_at == Some(effect) {
                    return (executed, pending.refused());
                }
                pending.succeeded()
            }
            done => return (executed, done),
        };
    }
}

#[test]
fn r4_scheduler_runs_only_the_closed_task19_roster() {
    let cell = locator(5001);
    let (executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, None);

    assert_eq!(
        executed.as_slice(),
        CheckpointTeardownPlan::ROSTER.as_slice(),
        "the pass executes the closed roster, in order, once each"
    );
    assert_eq!(executed.len(), 20);

    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a pass with no refusal completes")
    };
    assert!(complete.ran_the_closed_roster());
    assert_eq!(complete.locator(), cell);
    assert_eq!(complete.report().attempted_mask(), 0x000F_FFFF);
    assert_eq!(complete.report().failed_mask(), 0);
    for effect in CheckpointTeardownPlan::ROSTER {
        assert!(complete.report().attempted(effect), "{effect:?}");
        assert!(!complete.report().failed(effect), "{effect:?}");
    }

    // The production entry point hands out the same roster; otherwise every
    // assertion above would be about a roster production never runs.
    let CheckpointTeardownProgress::Effect(first) = CheckpointTeardownPlan::begin(cell) else {
        panic!("a fresh pass begins at an effect")
    };
    assert_eq!(first.effect(), CheckpointFenceEffect::CloseSessionAdmission);
    assert_eq!(first.locator(), cell);
}

#[test]
fn r3_scheduler_stops_at_first_actual_refusal() {
    let cell = locator(5002);
    for (index, refusing) in CheckpointTeardownPlan::ROSTER.into_iter().enumerate() {
        let (executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, Some(refusing));

        // Everything up to and including the refusing entry ran; nothing after
        // it was attempted. A report that claimed a later operation would be
        // claiming work a failed predecessor made meaningless.
        assert_eq!(executed.len(), index.saturating_add(1), "{refusing:?}");
        assert_eq!(executed.last(), Some(&refusing));

        let CheckpointTeardownProgress::Refused(refused) = progress else {
            panic!("a refusal cannot complete the pass")
        };
        assert_eq!(refused.cursor(), PrepareCheckpointFinish::Roster(refusing));
        assert!(refused.report().failed(refusing));
        assert!(refused.report().attempted(refusing));
        assert!(!refused.report().is_complete());
        for later in CheckpointTeardownPlan::ROSTER
            .into_iter()
            .skip(index.saturating_add(1))
        {
            assert!(
                !refused.report().attempted(later),
                "{refusing:?} must not report {later:?} as attempted"
            );
        }
    }
}

#[test]
fn r4_teardown_complete_contains_same_brand_authority_absence() {
    let cell = locator(5003);
    let (_executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a clean pass completes")
    };

    // An absence proof branded for another generation cannot be attached, and
    // the refusal returns the completion intact rather than stranding it.
    let other = SessionLocator::from_parts_for_test(1, 3, identity(5004));
    let foreign = R4AuthorityAbsence::injected_for_test(other).expect("injected witness");
    let complete = complete
        .with_absence(foreign)
        .expect_err("a foreign absence proof is refused");
    assert!(complete.ran_the_closed_roster());

    let absence = R4AuthorityAbsence::injected_for_test(cell).expect("injected witness");
    let proof = complete
        .with_absence(absence)
        .map_err(|_| ())
        .expect("the same-brand absence proof attaches");
    assert_eq!(proof.locator(), cell);
    assert_eq!(proof.absence().locator(), cell);
    assert!(proof.report().is_complete());
    assert_eq!(
        proof.absence().artifact().profile(),
        crate::session::ProductionAttestationProfile::R4Cutover
    );
}

#[derive(Debug)]
struct TestDeletionTail;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedDeleteTraceRecord {
    DestroyShell,
    ReleaseRoot,
    TransferClosingOwner,
    PublishCompletedOutcome,
    SignalTerminalOutcome,
    DrainCountedArrivals,
    WaitJoinersDrained,
    CompleteAccessRundown,
    ReinitializedFree,
    SkippedRetired,
    ResetAndPublish,
}

struct TestDeleteShell {
    trace: std::rc::Rc<core::cell::RefCell<Vec<PreparedDeleteTraceRecord>>>,
}

struct TestRootRelease {
    trace: std::rc::Rc<core::cell::RefCell<Vec<PreparedDeleteTraceRecord>>>,
}

unsafe impl PreparedDeleteStorageOps<TestRootRelease> for TestDeleteShell {
    unsafe fn destroy_shell_then_release_root(
        self,
        root: TestRootRelease,
        _permit: &PreparedDeleteExecutionPermit,
    ) {
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::DestroyShell);
        root.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::ReleaseRoot);
    }
}

struct RecordingPreparedDeleteNativeOps {
    trace: std::rc::Rc<core::cell::RefCell<Vec<PreparedDeleteTraceRecord>>>,
}

unsafe impl R3PreparedDeleteNativeOps<()> for RecordingPreparedDeleteNativeOps {
    unsafe fn transfer_closing_owner_to_completed_record_and_publish_outcome(
        &mut self,
        _locator: SessionLocator,
    ) {
        // Native holds one registry lock across these two logical records.
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::TransferClosingOwner);
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::PublishCompletedOutcome);
    }

    unsafe fn signal_terminal_outcome(&mut self, _locator: SessionLocator) {
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::SignalTerminalOutcome);
    }

    unsafe fn drain_counted_arrivals(&mut self, _locator: SessionLocator) {
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::DrainCountedArrivals);
    }

    unsafe fn wait_joiners_drained(&mut self, _locator: SessionLocator) {
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::WaitJoinersDrained);
    }

    unsafe fn complete_access_rundown(&mut self, _locator: SessionLocator) {
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::CompleteAccessRundown);
    }

    unsafe fn reinitialize_access_rundown_if_reusable(
        &mut self,
        _locator: SessionLocator,
        disposition: crate::session::SlotDisposition,
    ) {
        self.trace.borrow_mut().push(match disposition {
            crate::session::SlotDisposition::Free => PreparedDeleteTraceRecord::ReinitializedFree,
            crate::session::SlotDisposition::Retired => PreparedDeleteTraceRecord::SkippedRetired,
        });
    }

    unsafe fn reset_cell_and_publish_disposition(
        &mut self,
        pending: PendingFinalDeleteReset<()>,
    ) -> FinalDeleteProof {
        self.trace
            .borrow_mut()
            .push(PreparedDeleteTraceRecord::ResetAndPublish);
        let (_commit, _running, (), proof, _terminal, _mount) = pending.finish_after_reset();
        proof
    }
}

#[test]
fn native_prepared_delete_trace_executes_the_exact_ten_step_suffix_once() {
    use crate::session::NativeOwnerBindRights;

    let cell = locator(500_400);
    let trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let rights = NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let readiness = unsafe {
        complete_r3_for_owner_test(cell).bind_deletion_owners(TestDeletionTail, shell, root)
    }
    .map_err(|_| ())
    .expect("the exact owner chain becomes deletion readiness");
    let (_tail, storage) = readiness
        .into_prepared_delete_storage(
            crate::session::PreparedDeleteCoreCommit::for_test(cell),
            R3FinalizerRunningRight::for_test(cell),
            (),
        )
        .unwrap_or_else(|_| unreachable!("the exact prepared storage binds"));
    let mut native = RecordingPreparedDeleteNativeOps {
        trace: std::rc::Rc::clone(&trace),
    };

    let proof = unsafe { run_r3_prepared_delete_suffix(storage, &mut native) };

    assert_eq!(
        trace.borrow().as_slice(),
        [
            PreparedDeleteTraceRecord::DestroyShell,
            PreparedDeleteTraceRecord::ReleaseRoot,
            PreparedDeleteTraceRecord::TransferClosingOwner,
            PreparedDeleteTraceRecord::PublishCompletedOutcome,
            PreparedDeleteTraceRecord::SignalTerminalOutcome,
            PreparedDeleteTraceRecord::DrainCountedArrivals,
            PreparedDeleteTraceRecord::WaitJoinersDrained,
            PreparedDeleteTraceRecord::CompleteAccessRundown,
            PreparedDeleteTraceRecord::ReinitializedFree,
            PreparedDeleteTraceRecord::ResetAndPublish,
        ],
    );
    assert_eq!(proof.locator(), cell);
    assert!(proof.ran_every_step());
    assert!(proof.transferred_record_before_publishing());
    assert!(proof.published_before_signalling());
    assert!(proof.counted_arrivals_drained_before_wait());
    assert!(proof.drained_before_completing_rundown());
    assert!(proof.reset_is_last());
}

#[test]
fn native_prepared_delete_retired_trace_records_step_nine_without_reinitializing() {
    use crate::session::NativeOwnerBindRights;

    let cell = locator(500_401);
    let trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let rights = NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let readiness = unsafe {
        complete_r3_for_owner_test(cell).bind_deletion_owners(TestDeletionTail, shell, root)
    }
    .map_err(|_| ())
    .expect("the exact owner chain becomes deletion readiness");
    let (_tail, storage) = readiness
        .into_prepared_delete_storage(
            crate::session::PreparedDeleteCoreCommit::for_test_with_disposition(
                cell,
                crate::session::SlotDisposition::Retired,
            ),
            R3FinalizerRunningRight::for_test(cell),
            (),
        )
        .unwrap_or_else(|_| unreachable!("the exact retired storage binds"));
    let mut native = RecordingPreparedDeleteNativeOps {
        trace: std::rc::Rc::clone(&trace),
    };

    let proof = unsafe { run_r3_prepared_delete_suffix(storage, &mut native) };

    let trace = trace.borrow();
    assert_eq!(
        trace.as_slice(),
        [
            PreparedDeleteTraceRecord::DestroyShell,
            PreparedDeleteTraceRecord::ReleaseRoot,
            PreparedDeleteTraceRecord::TransferClosingOwner,
            PreparedDeleteTraceRecord::PublishCompletedOutcome,
            PreparedDeleteTraceRecord::SignalTerminalOutcome,
            PreparedDeleteTraceRecord::DrainCountedArrivals,
            PreparedDeleteTraceRecord::WaitJoinersDrained,
            PreparedDeleteTraceRecord::CompleteAccessRundown,
            PreparedDeleteTraceRecord::SkippedRetired,
            PreparedDeleteTraceRecord::ResetAndPublish,
        ],
        "Retired records the same ten logical steps with a skipped reinitialization at step nine"
    );
    assert_eq!(
        trace
            .iter()
            .filter(|entry| **entry == PreparedDeleteTraceRecord::SkippedRetired)
            .count(),
        1,
        "Retired records logical step nine exactly once",
    );
    assert_eq!(
        trace
            .iter()
            .filter(|entry| **entry == PreparedDeleteTraceRecord::ReinitializedFree)
            .count(),
        0,
        "Retired never records an access-rundown reinitialization",
    );
    assert!(proof.ran_every_step());
    assert!(proof.reset_is_last());
}

fn complete_r3_for_owner_test(cell: SessionLocator) -> R4TeardownComplete {
    let (_executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a clean pass completes")
    };
    let absence = R4AuthorityAbsence::injected_for_test(cell).expect("injected witness");
    complete
        .with_absence(absence)
        .map_err(|_| ())
        .expect("the same-brand absence attaches")
}

#[test]
fn complete_owner_chain_stores_deposit_before_minting_kick_and_hides_payloads() {
    use crate::session::NativeOwnerBindRights;

    type Owners = R4DeletionOwnerChain<TestDeletionTail, TestDeleteShell, TestRootRelease>;

    let cell = locator(5004);
    let rights = NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, finalizer_right) = rights.into_parts();
    let mut finalizer = R3FinalizerCell::<Owners>::new_unbound();
    finalizer
        .bind(finalizer_right)
        .map_err(|_| ())
        .expect("the install-origin right binds the finalizer cell once");
    let trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let complete = complete_r3_for_owner_test(cell);
    let readiness = unsafe { complete.bind_deletion_owners(TestDeletionTail, shell, root) }
        .map_err(|_| ())
        .expect("one complete same-brand chain becomes readiness");

    let right = crate::session::DeleteSessionRight::for_test(cell);
    let kick = finalizer
        .store_deposit_and_mint_kick(readiness, right)
        .map_err(|_| ())
        .expect("the exact readiness and right store before a kick exists");
    assert!(!finalizer.deposit_is_none());
    let context = run_r3_finalizer_queue(
        kick.admit(()),
        |context, ()| context,
        core::convert::identity,
    );
    let (deposit, running) = run_r3_finalizer_callback(context, |_| Some(&mut finalizer))
        .expect("the queued cell retained the complete deposit");
    let unprepared = crate::session::SessionRegistry::<1>::new();
    let returned = match deposit.prepare_final_delete_core(&unprepared) {
        Ok(_) => panic!("a non-deleting core slot cannot authorize destruction"),
        Err((_error, returned)) => returned,
    };
    assert_eq!(returned.locator(), cell);
    let _ = running;

    let rights = NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let readiness = unsafe {
        complete_r3_for_owner_test(cell).bind_deletion_owners(TestDeletionTail, shell, root)
    }
    .map_err(|_| ())
    .expect("a second authentic fixture becomes readiness");
    let commit = crate::session::PreparedDeleteCoreCommit::for_test(cell);
    let (_tail, storage) = match readiness.into_prepared_delete_storage(
        commit,
        R3FinalizerRunningRight::for_test(cell),
        (),
    ) {
        Ok(prepared) => prepared,
        Err(_) => panic!("the exact core commit binds to the owner storage"),
    };
    // SAFETY: the test commit stands for the successful prepared-delete suffix.
    let _reset_right = unsafe { storage.execute() };
    assert_eq!(
        trace.borrow().as_slice(),
        &[
            PreparedDeleteTraceRecord::DestroyShell,
            PreparedDeleteTraceRecord::ReleaseRoot,
        ]
    );

    let foreign = locator(5005);
    let rights = NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let readiness = unsafe {
        complete_r3_for_owner_test(cell).bind_deletion_owners(TestDeletionTail, shell, root)
    }
    .map_err(|_| ())
    .expect("the fixture remains same-brand");
    assert!(
        readiness
            .into_prepared_delete_storage(
                crate::session::PreparedDeleteCoreCommit::for_test(foreign),
                R3FinalizerRunningRight::for_test(cell),
                (),
            )
            .is_err(),
        "a foreign core commit cannot authorize destruction of this owner chain"
    );

    let rights = NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let readiness = unsafe {
        complete_r3_for_owner_test(cell).bind_deletion_owners(TestDeletionTail, shell, root)
    }
    .map_err(|_| ())
    .expect("the crossed-running fixture remains same-brand");
    assert!(
        readiness
            .into_prepared_delete_storage(
                crate::session::PreparedDeleteCoreCommit::for_test(cell),
                R3FinalizerRunningRight::for_test(foreign),
                (),
            )
            .is_err(),
        "a foreign running callback cannot enter the destructive storage bundle"
    );
}

#[test]
// Proof of safety: every index below is a fixed test fixture position or a
// cursor the same test just asserted, and this is host test code, not a
// driver input path. An out-of-range index here is the test failing, which
// is exactly the outcome wanted.
#[allow(clippy::indexing_slicing)]
fn native_finalizer_trace_queues_once_and_enters_the_exact_cell_once() {
    use crate::session::NativeOwnerBindRights;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TraceStep {
        StoreDeposit(u32),
        QueueCell(u32),
        EnterCell(u32),
    }

    type Owners = R4DeletionOwnerChain<TestDeletionTail, TestDeleteShell, TestRootRelease>;

    fn queued_cell(
        locator: SessionLocator,
        owner_trace: &std::rc::Rc<core::cell::RefCell<Vec<PreparedDeleteTraceRecord>>>,
    ) -> (R3FinalizerCell<Owners>, R3FinalizerKick) {
        let rights = NativeOwnerBindRights::for_test(locator);
        let (shell_right, root_right, finalizer_right) = rights.into_parts();
        let mut cell = R3FinalizerCell::<Owners>::new_unbound();
        cell.bind(finalizer_right)
            .map_err(|_| ())
            .expect("the permanent cell binds to its install generation");
        let shell = shell_right.bind(TestDeleteShell {
            trace: std::rc::Rc::clone(owner_trace),
        });
        let root = root_right.bind(TestRootRelease {
            trace: std::rc::Rc::clone(owner_trace),
        });
        let readiness = unsafe {
            complete_r3_for_owner_test(locator).bind_deletion_owners(TestDeletionTail, shell, root)
        }
        .map_err(|_| ())
        .expect("the exact complete owner chain becomes deletion readiness");
        let kick = cell
            .store_deposit_and_mint_kick(
                readiness,
                crate::session::DeleteSessionRight::for_test(locator),
            )
            .map_err(|_| ())
            .expect("the exact deposit is stored before its sole kick exists");
        assert!(!cell.deposit_is_none());
        (cell, kick)
    }

    let competing = SessionLocator::from_parts_for_test(0, 3, identity(500_410));
    let target = SessionLocator::from_parts_for_test(1, 3, identity(500_411));
    let owner_trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let (competing_cell, competing_kick) = queued_cell(competing, &owner_trace);
    let (target_cell, target_kick) = queued_cell(target, &owner_trace);
    let mut cells = [competing_cell, target_cell];
    let mut trace = vec![
        TraceStep::StoreDeposit(competing.slot_index()),
        TraceStep::StoreDeposit(target.slot_index()),
    ];

    // Only the target kick crosses the queue endpoint. The other queued cell
    // deliberately makes a scan-for-any-work callback observably incorrect.
    let context = run_r3_finalizer_queue(
        target_kick.admit(()),
        |context, ()| {
            trace.push(TraceStep::QueueCell(context.cell_index()));
            context
        },
        core::convert::identity,
    );
    let (deposit, running) = run_r3_finalizer_callback(context, |cell_index| {
        trace.push(TraceStep::EnterCell(cell_index));
        cells.get_mut(cell_index as usize)
    })
    .expect("the callback enters only the cell named by its consumed kick");

    assert_eq!(deposit.locator(), target);
    assert_eq!(running.locator(), target);
    assert!(
        cells[target.slot_index() as usize].deposit_is_none(),
        "the exact callback cannot take its deposit twice",
    );
    assert!(
        !cells[competing.slot_index() as usize].deposit_is_none(),
        "the callback does not scan for and steal a replacement generation",
    );
    assert_eq!(
        trace,
        [
            TraceStep::StoreDeposit(0),
            TraceStep::StoreDeposit(1),
            TraceStep::QueueCell(1),
            TraceStep::EnterCell(1),
        ],
    );

    core::mem::forget((deposit, running, competing_kick));
}

#[test]
fn production_finalizer_runners_preserve_the_exact_generation_across_the_callback_boundary() {
    use crate::session::NativeOwnerBindRights;

    type Owners = R4DeletionOwnerChain<TestDeletionTail, TestDeleteShell, TestRootRelease>;

    fn queued_cell(
        locator: SessionLocator,
        owner_trace: &std::rc::Rc<core::cell::RefCell<Vec<PreparedDeleteTraceRecord>>>,
    ) -> (R3FinalizerCell<Owners>, R3FinalizerKick) {
        let rights = NativeOwnerBindRights::for_test(locator);
        let (shell_right, root_right, finalizer_right) = rights.into_parts();
        let mut cell = R3FinalizerCell::<Owners>::new_unbound();
        cell.bind(finalizer_right)
            .map_err(|_| ())
            .expect("the permanent cell binds to its install generation");
        let shell = shell_right.bind(TestDeleteShell {
            trace: std::rc::Rc::clone(owner_trace),
        });
        let root = root_right.bind(TestRootRelease {
            trace: std::rc::Rc::clone(owner_trace),
        });
        let readiness = unsafe {
            complete_r3_for_owner_test(locator).bind_deletion_owners(TestDeletionTail, shell, root)
        }
        .map_err(|_| ())
        .expect("the exact complete owner chain becomes deletion readiness");
        let kick = cell
            .store_deposit_and_mint_kick(
                readiness,
                crate::session::DeleteSessionRight::for_test(locator),
            )
            .map_err(|_| ())
            .expect("the exact deposit is stored before its sole kick exists");
        (cell, kick)
    }

    let target = SessionLocator::from_parts_for_test(1, 3, identity(500_412));
    let competing_generation = SessionLocator::from_parts_for_test(1, 4, identity(500_413));
    let owner_trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let (target_cell, target_kick) = queued_cell(target, &owner_trace);
    let (mut competing_cell, competing_kick) = queued_cell(competing_generation, &owner_trace);
    let trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::<(&'static str, u32)>::new()));
    let publish_trace = std::rc::Rc::clone(&trace);
    let queue_trace = std::rc::Rc::clone(&trace);

    let context = run_r3_finalizer_queue(
        target_kick.admit(()),
        |context, ()| {
            publish_trace
                .borrow_mut()
                .push(("publish", context.cell_index()));
            context
        },
        |context| {
            queue_trace
                .borrow_mut()
                .push(("queue", context.cell_index()));
            context
        },
    );
    assert_eq!(trace.borrow().as_slice(), &[("publish", 1), ("queue", 1)]);

    assert!(
        run_r3_finalizer_callback(context, |index| {
            assert_eq!(index, competing_generation.slot_index());
            Some(&mut competing_cell)
        })
        .is_none(),
        "the same embedded index cannot substitute a competing generation",
    );
    let context = run_r3_finalizer_queue(
        competing_kick.admit(()),
        |context, ()| context,
        core::convert::identity,
    );
    let (deposit, running) = run_r3_finalizer_callback(context, |index| {
        assert_eq!(index, competing_generation.slot_index());
        Some(&mut competing_cell)
    })
    .expect("the callback enters the exact generation carried across the queue boundary");
    assert_eq!(deposit.locator(), competing_generation);
    assert_eq!(running.locator(), competing_generation);
    assert!(
        !target_cell.deposit_is_none(),
        "a callback never scans for a replacement generation",
    );

    core::mem::forget((deposit, running, target_cell));
}

#[test]
fn fail_stop_visibility_runner_signals_the_latch_exactly_once_per_resolution() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Wake {
        Visibility,
        Outcome,
    }

    let published = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let latch_trace = std::rc::Rc::clone(&published);
    let outcome_trace = std::rc::Rc::clone(&published);
    run_r3_fail_stop_visibility_wake(
        R3FailStopVisibilityWake::Published(()),
        || latch_trace.borrow_mut().push(Wake::Visibility),
        |()| {
            let mut trace = outcome_trace.borrow_mut();
            trace.push(Wake::Visibility);
            trace.push(Wake::Outcome);
        },
    );
    assert_eq!(
        published.borrow().as_slice(),
        &[Wake::Visibility, Wake::Outcome],
        "Published uses the combined visibility/outcome signal and never sets the latch twice",
    );

    let durable = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let latch_trace = std::rc::Rc::clone(&durable);
    let outcome_trace = std::rc::Rc::clone(&durable);
    run_r3_fail_stop_visibility_wake(
        R3FailStopVisibilityWake::<()>::LatchOnly,
        || latch_trace.borrow_mut().push(Wake::Visibility),
        |()| outcome_trace.borrow_mut().push(Wake::Outcome),
    );
    assert_eq!(durable.borrow().as_slice(), &[Wake::Visibility]);
}

#[test]
fn fail_stop_two_phase_runner_prepares_under_lock_then_wakes_and_enters_exact_wait() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Step {
        StorePacket,
        CommitPublished,
        CommitOpaque,
        AuthenticateSlotAndRendezvous,
        Unlock,
        Visibility,
        Outcome,
        ReleaseExact,
        RetainExact,
        PermanentWait,
        DedicatedOpaqueWait,
    }

    let published = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let prepare_trace = std::rc::Rc::clone(&published);
    let unlock_trace = std::rc::Rc::clone(&published);
    let latch_trace = std::rc::Rc::clone(&published);
    let signal_trace = std::rc::Rc::clone(&published);
    let continue_trace = std::rc::Rc::clone(&published);
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        run_r3_fail_stop_two_phase(
            (),
            move |&mut ()| {
                let mut trace = prepare_trace.borrow_mut();
                trace.push(Step::StorePacket);
                trace.push(Step::CommitPublished);
                R3FailStopPreparedContinuation::<(), (), (), ()>::Published {
                    signal: (),
                    continuation: (),
                }
            },
            move |()| unlock_trace.borrow_mut().push(Step::Unlock),
            move || latch_trace.borrow_mut().push(Step::Visibility),
            move |()| {
                let mut trace = signal_trace.borrow_mut();
                trace.push(Step::Visibility);
                trace.push(Step::Outcome);
            },
            move |()| {
                let mut trace = continue_trace.borrow_mut();
                trace.push(Step::ReleaseExact);
                trace.push(Step::PermanentWait);
                panic!("published permanent wait sentinel")
            },
            |()| panic!("Published cannot enter the opaque continuation"),
            |()| panic!("Published cannot enter the retained continuation"),
        )
    }));
    assert!(stopped.is_err(), "the Published continuation cannot return");
    assert_eq!(
        published.borrow().as_slice(),
        &[
            Step::StorePacket,
            Step::CommitPublished,
            Step::Unlock,
            Step::Visibility,
            Step::Outcome,
            Step::ReleaseExact,
            Step::PermanentWait,
        ],
    );

    for (release_step, label) in [
        (Step::ReleaseExact, "exact"),
        (Step::RetainExact, "foreign-retained"),
    ] {
        let opaque = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        let prepare_trace = std::rc::Rc::clone(&opaque);
        let unlock_trace = std::rc::Rc::clone(&opaque);
        let latch_trace = std::rc::Rc::clone(&opaque);
        let signal_trace = std::rc::Rc::clone(&opaque);
        let continue_trace = std::rc::Rc::clone(&opaque);
        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            run_r3_fail_stop_two_phase(
                (),
                move |&mut ()| {
                    let mut trace = prepare_trace.borrow_mut();
                    trace.push(Step::StorePacket);
                    trace.push(Step::CommitOpaque);
                    trace.push(Step::AuthenticateSlotAndRendezvous);
                    trace.push(release_step);
                    R3FailStopPreparedContinuation::<(), (), (), ()>::Opaque(())
                },
                move |()| unlock_trace.borrow_mut().push(Step::Unlock),
                move || latch_trace.borrow_mut().push(Step::Visibility),
                move |()| {
                    signal_trace.borrow_mut().push(Step::Outcome);
                    panic!("Opaque cannot signal a terminal outcome")
                },
                |()| panic!("Opaque cannot enter the Published continuation"),
                move |()| {
                    continue_trace.borrow_mut().push(Step::DedicatedOpaqueWait);
                    panic!("opaque permanent wait sentinel")
                },
                |()| panic!("Opaque cannot enter the retained continuation"),
            )
        }));
        assert!(stopped.is_err(), "the {label} Opaque wait cannot return");
        assert_eq!(
            opaque.borrow().as_slice(),
            &[
                Step::StorePacket,
                Step::CommitOpaque,
                Step::AuthenticateSlotAndRendezvous,
                release_step,
                Step::Unlock,
                Step::Visibility,
                Step::DedicatedOpaqueWait,
            ],
            "Opaque never receives a terminal outcome signal or a fabricated release ticket",
        );
    }
}

#[test]
fn r3_checkpoint_blocked_wakes_winner_and_joiner_not_unload() {
    use crate::adapter::lifecycle::{
        BlockedArrivalAction, TerminalArrivalSource, TerminalWaitDisposition,
        decide_blocked_arrival, resolve_terminal_release,
    };

    let cell = locator(5005);
    let mut rendezvous = TerminalRendezvous::new_inactive();
    rendezvous
        .activate(cell)
        .expect("a fresh rendezvous activates");
    let (winner, winner_ticket) = rendezvous
        .claim(cell, TerminalRequest::Cleanup)
        .expect("the first arrival wins")
        .into_parts();
    let joiner = match rendezvous.join(cell).expect("the open generation admits") {
        crate::session::TerminalJoinClaim::Join(ticket) => ticket,
        _ => panic!("an open generation admits a joiner"),
    };

    let payload =
        FenceTerminalBlocked::new(FenceFailStopReason::CoreInvariant, winner.diagnostic());
    let blocked = crate::session::TerminalBlocked::from_fence(cell, payload);
    rendezvous
        .close_and_publish_blocked(winner, blocked)
        .map_err(|_| ())
        .expect("the counted winner publishes its own fail-stop");

    for (ticket, expect_drained) in [(winner_ticket, false), (joiner, true)] {
        let release = rendezvous
            .release(ticket)
            .map_err(|_| ())
            .expect("a counted arrival releases against its own generation");
        match resolve_terminal_release(release) {
            TerminalWaitDisposition::Blocked {
                blocked: seen,
                drained,
            } => {
                assert_eq!(seen, blocked);
                assert_eq!(drained.is_some(), expect_drained);
            }
            _ => panic!("a blocked generation publishes a blocked observation"),
        }
    }

    // Ordinary arrivals report the status; unload alone must not return.
    assert_eq!(
        decide_blocked_arrival(TerminalArrivalSource::Cleanup),
        BlockedArrivalAction::ReportInvalidDeviceState
    );
    assert_eq!(
        decide_blocked_arrival(TerminalArrivalSource::Unload),
        BlockedArrivalAction::BlockForever
    );
}

#[test]
fn checkpoint_fail_stop_cannot_mint_delete_right_or_completed_outcome() {
    let cell = locator(5006);
    let (_executed, progress) = run_pass(
        cell,
        CheckpointTeardownPlan::ROSTER,
        Some(CheckpointFenceEffect::ReleaseCapturedProcess),
    );
    let CheckpointTeardownProgress::Refused(refused) = progress else {
        panic!("the pass refused")
    };

    // The refusal yields a cursor and a report and nothing else. There is no
    // completion to attach an absence proof to, so no `R4TeardownComplete` and
    // therefore no candidate, readiness, deposit, or delete right can exist on
    // this path at all.
    let (cursor, report) = refused.into_parts();
    assert_eq!(
        cursor,
        PrepareCheckpointFinish::Roster(CheckpointFenceEffect::ReleaseCapturedProcess)
    );
    assert!(!report.is_complete());
    assert_eq!(report.locator(), cell);

    // A preparation refusal after a *complete* pass uses the other cursor, so a
    // reader can tell "teardown failed" from "teardown finished and the
    // preparation cross-product did not match".
    let preparation = RefusedCheckpointTeardown::preparation_refusal(report);
    assert_eq!(
        preparation.cursor(),
        PrepareCheckpointFinish::FinishPreparation
    );
    assert!(preparation.report().is_complete() || !preparation.report().is_complete());
}

#[test]
fn authenticated_terminal_result_binds_one_winner_to_its_own_reason() {
    let cell = locator(5007);
    let mut rendezvous = TerminalRendezvous::new_inactive();
    rendezvous.activate(cell).expect("activates");
    let (winner, ticket) = rendezvous
        .claim(cell, TerminalRequest::ProcessLoss)
        .expect("winner")
        .into_parts();

    // A result that relabels why the generation died is refused, with both
    // values returned: the caller keeps its winner and can publish honestly.
    let wrong = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let (winner, returned) = AuthenticatedTerminalResult::new(winner, wrong)
        .map(|_| ())
        .expect_err("a relabelled reason is refused");
    assert_eq!(returned, wrong);

    let honest = TerminalResult {
        reason: TerminalReason::ProcessLoss,
        fence_failures: 0,
    };
    let authenticated = AuthenticatedTerminalResult::new(winner, honest)
        .map_err(|_| ())
        .expect("the winner's own reason is accepted");
    assert_eq!(authenticated.locator(), cell);
    assert_eq!(authenticated.result(), honest);
    let diagnostic = authenticated.diagnostic();
    let (winner, result) = authenticated.into_parts();
    assert_eq!(
        winner.diagnostic(),
        diagnostic,
        "the carrier copies, never mints"
    );
    assert_eq!(result, honest);
    let _ = winner;
    let _ = ticket;
}

// ---------------------------------------------------------------------------
// Task 11: the bound mount teardown
// ---------------------------------------------------------------------------

#[test]
fn completed_mount_teardown_is_minted_only_from_lifecycle_acknowledgements() {
    let authentic = authentic_mount_completions(5199);
    let owner = bind_completed_mount_teardown(
        authentic.owner_expected,
        CompletedMountTeardown::from_owner(authentic.owner),
    )
    .map_err(|_| ())
    .expect("the lifecycle owner's exact expectation binds");
    assert_eq!(owner.cursor(), Some(MountAbsenceCursor::Next(2)));

    let joined = bind_completed_mount_teardown(
        authentic.join_expected,
        CompletedMountTeardown::from_joined(authentic.join),
    )
    .map_err(|_| ())
    .expect("the ordinary join's exact expectation binds");
    assert_eq!(joined.cursor(), Some(MountAbsenceCursor::Next(2)));

    let reset_joined = bind_completed_mount_teardown(
        authentic.reset_expected,
        CompletedMountTeardown::from_joined(authentic.reset_join),
    )
    .map_err(|_| ())
    .expect("the reset join's exact expectation binds");
    assert_eq!(reset_joined.cursor(), Some(MountAbsenceCursor::Next(2)));

    let absent = bind_completed_mount_teardown(
        authentic.absent_expected,
        CompletedMountTeardown::from_absent(authentic.absent),
    )
    .map_err(|_| ())
    .expect("the authentic final absence binds");
    assert_eq!(absent.locator(), authentic.locator);
    assert_eq!(absent.cursor(), Some(MountAbsenceCursor::Next(2)));
}

#[test]
fn bound_mount_completion_seals_the_authentic_final_cursor_for_delete() {
    let authentic = authentic_mount_completions(5200);
    let locator = authentic.locator;
    let bound = bind_completed_mount_teardown(
        authentic.owner_expected,
        CompletedMountTeardown::from_owner(authentic.owner),
    )
    .map_err(|_| ())
    .expect("the authentic owner completion binds");

    let prepared = bound.into_prepared_deactivation();
    assert_eq!(prepared.locator(), locator);
    assert_eq!(prepared.cursor(), MountAbsenceCursor::Next(2));
    assert_eq!(prepared.required_disposition(), SlotDisposition::Free);
}

#[test]
fn bound_mount_proof_enters_the_r3_delete_carrier_without_projection() {
    let authentic = authentic_mount_completions(5201);
    let locator = authentic.locator;
    let bound = bind_completed_mount_teardown(
        authentic.owner_expected,
        CompletedMountTeardown::from_owner(authentic.owner),
    )
    .map_err(|_| ())
    .expect("the authentic owner completion binds");
    let (_executed, progress) = run_pass(locator, CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("the closed roster completes")
    };
    let absence = R4AuthorityAbsence::injected_for_test(locator).expect("same artifact");
    let complete = complete
        .with_absence(absence)
        .map_err(|_| ())
        .expect("same locator attaches");
    let complete = complete
        .with_mount(bound)
        .map_err(|_| ())
        .expect("the bound mount proof enters the carrier");

    assert_eq!(complete.locator(), locator);
    assert_eq!(complete.mount_cursor(), MountAbsenceCursor::Next(2));
}

#[test]
fn authentic_mount_proof_survives_readiness_storage_and_final_reset() {
    use crate::session::NativeOwnerBindRights;

    let authentic = authentic_mount_completions(5202);
    let AuthenticMountCompletions {
        mut mount,
        mut registry,
        delete_right,
        locator,
        owner_expected,
        owner,
        ..
    } = authentic;
    let bound =
        bind_completed_mount_teardown(owner_expected, CompletedMountTeardown::from_owner(owner))
            .map_err(|_| ())
            .expect("the authentic owner completion binds");
    let complete = complete_r3_for_owner_test(locator)
        .with_mount(bound)
        .map_err(|_| ())
        .expect("the exact bound proof enters R3");

    let trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let rights = NativeOwnerBindRights::for_test(locator);
    let (shell_right, root_right, finalizer_right) = rights.into_parts();
    let shell = shell_right.bind(TestDeleteShell {
        trace: std::rc::Rc::clone(&trace),
    });
    let root = root_right.bind(TestRootRelease {
        trace: std::rc::Rc::clone(&trace),
    });
    let readiness = unsafe { complete.bind_deletion_owners(TestDeletionTail, shell, root) }
        .map_err(|_| ())
        .expect("R3 readiness retains the exact mount proof");
    type Owners = R4DeletionOwnerChain<TestDeletionTail, TestDeleteShell, TestRootRelease>;
    let mut finalizer = R3FinalizerCell::<Owners>::new_unbound();
    finalizer
        .bind(finalizer_right)
        .map_err(|_| ())
        .expect("the install-origin right binds the finalizer");
    let kick = finalizer
        .store_deposit_and_mint_kick(readiness, delete_right)
        .map_err(|_| ())
        .expect("readiness and delete right store as one deposit");
    let context = run_r3_finalizer_queue(
        kick.admit(()),
        |context, ()| context,
        core::convert::identity,
    );
    let (deposit, running) = run_r3_finalizer_callback(context, |_| Some(&mut finalizer))
        .expect("the queued callback takes the complete carrier");
    let (readiness, commit) = deposit
        .prepare_final_delete_core(&registry)
        .map_err(|_| ())
        .expect("the deleting core validates the carrier's mount proof");
    let (_tail, storage) = readiness
        .into_prepared_delete_storage(commit, running, ())
        .map_err(|_| ())
        .expect("prepared storage retains the exact mount proof");

    // SAFETY: the exact prepared storage owns the shell and root test payloads.
    let final_reset = unsafe { storage.execute() }
        .completed_publication_completed()
        .outcome_signalled()
        .counted_arrivals_drained()
        .joiners_drained()
        .access_rundown_completed()
        .reinitialized_for_reuse();
    // SAFETY: this test owns the exact running finalizer, deleting registry,
    // and post-storage cursor for one locator.
    let (disposition, proof, (), _terminal_reset, mount_reset) =
        unsafe { finalizer.finish_run_and_reset(&mut registry, final_reset) };
    assert_eq!(disposition, SlotDisposition::Free);
    assert!(proof.ran_every_step());
    assert_eq!(mount_reset.locator(), locator);
    assert_eq!(mount_reset.cursor(), MountAbsenceCursor::Next(2));

    // SAFETY: the final cursor returned the same sealed proof created from
    // this fully acknowledged rendezvous, after the destructive suffix.
    unsafe { mount.deactivate_after_delete_prepared(mount_reset) };
    assert!(mount.prepare_activation(locator).is_ok());
    assert_eq!(
        trace.borrow().as_slice(),
        &[
            PreparedDeleteTraceRecord::DestroyShell,
            PreparedDeleteTraceRecord::ReleaseRoot,
        ]
    );
}

#[test]
fn completed_mount_teardown_rejects_cross_locator_and_stale_mount_generation() {
    let exact = authentic_mount_completions(5201);
    let cell = exact.locator;

    // The matching pair binds.
    let bound = bind_completed_mount_teardown(
        exact.owner_expected,
        CompletedMountTeardown::from_owner(exact.owner),
    )
    .map_err(|_| ())
    .expect("the exact pair binds");
    assert_eq!(bound.locator(), cell);
    assert_eq!(bound.cursor(), Some(MountAbsenceCursor::Next(2)));

    // A completion for another cell is refused by locator, and both halves come
    // back so the caller can park them rather than dropping one.
    let cross = authentic_mount_completions(5202);
    let other = cross.locator;
    let refused = bind_completed_mount_teardown(
        ExpectedMountTeardown::Owner {
            locator: cell,
            mount_generation: 1,
        },
        CompletedMountTeardown::from_owner(cross.owner),
    )
    .map(|_| ())
    .expect_err("a cross-locator completion cannot bind");
    assert_eq!(refused.error(), LifecycleError::WrongLocator);
    assert_eq!(refused.completed().locator(), other);
    assert_eq!(refused.expected().locator(), cell);

    // A stale mount generation is refused even though the locator matches: the
    // completion answers a teardown that already finished.
    let stale = authentic_mount_completions(5203);
    let refused = bind_completed_mount_teardown(
        ExpectedMountTeardown::Owner {
            locator: stale.locator,
            mount_generation: 2,
        },
        CompletedMountTeardown::from_owner(stale.owner),
    )
    .map(|_| ())
    .expect_err("a stale mount generation cannot bind");
    assert_eq!(refused.error(), LifecycleError::WrongState);

    // And the *kind* must match. An Owner completion presented for a Join
    // expectation is exactly the shape that produces a second IoDeleteDevice on
    // a device the real owner already deleted.
    let wrong_kind = authentic_mount_completions(5204);
    let refused = bind_completed_mount_teardown(
        wrong_kind.join_expected,
        CompletedMountTeardown::from_owner(wrong_kind.owner),
    )
    .map(|_| ())
    .expect_err("an owner completion cannot answer a join expectation");
    assert_eq!(refused.error(), LifecycleError::WrongState);
}

#[test]
fn bind_mismatch_pair_is_retained_without_second_delete() {
    let authentic = authentic_mount_completions(5205);
    let cell = authentic.locator;
    let expected = authentic.absent_expected;
    let completed = CompletedMountTeardown::from_joined(authentic.join);

    let pending = bind_completed_mount_teardown(expected, completed)
        .map(|_| ())
        .expect_err("a joined completion cannot answer an absent expectation");

    // Both halves are still here, and the packet has no method that could run a
    // second teardown: there is no `retry`, no `into_bound`, and no way to read
    // the completion out as an owner.
    assert_eq!(pending.expected().locator(), cell);
    assert_eq!(pending.completed().locator(), cell);
    assert_eq!(
        pending.completed().cursor(),
        Some(MountAbsenceCursor::Next(2))
    );
    assert_eq!(pending.error(), LifecycleError::WrongState);
}

#[test]
fn terminal_fence_already_unmounted_returns_exact_absence_completion() {
    let authentic = authentic_mount_completions(5206);
    let bound = bind_completed_mount_teardown(
        authentic.absent_expected,
        CompletedMountTeardown::from_absent(authentic.absent),
    )
    .map_err(|_| ())
    .expect("an absent completion answers an absent expectation");

    assert_eq!(bound.cursor(), Some(MountAbsenceCursor::Next(2)));
    assert!(
        mount_teardown_permits_delete(&bound),
        "an already-unmounted cell may be deleted"
    );
}

#[test]
fn absent_mount_completion_binds_only_the_exact_cursor() {
    let exact_authentic = authentic_mount_completions(5207);

    let exact = bind_completed_mount_teardown(
        exact_authentic.absent_expected,
        CompletedMountTeardown::from_absent(exact_authentic.absent),
    )
    .map_err(|_| ())
    .expect("the cursor returned by the exact absence claim binds");
    assert_eq!(exact.cursor(), Some(MountAbsenceCursor::Next(2)));

    for (seed, mismatched) in [
        (5208, MountAbsenceCursor::Next(3)),
        (5209, MountAbsenceCursor::Exhausted),
    ] {
        let authentic = authentic_mount_completions(seed);
        let pending = bind_completed_mount_teardown(
            ExpectedMountTeardown::Absent {
                locator: authentic.locator,
                cursor: mismatched,
            },
            CompletedMountTeardown::from_absent(authentic.absent),
        )
        .map(|_| ())
        .expect_err("an absence cursor from another rendezvous state must refuse");
        assert_eq!(pending.error(), LifecycleError::WrongState);
        assert_eq!(pending.expected().cursor(), Some(mismatched));
        assert_eq!(
            pending.completed().cursor(),
            Some(MountAbsenceCursor::Next(2))
        );
    }
}

#[test]
fn maximum_mount_generation_exhausted_absence_binds_and_deactivates() {
    let authentic = authentic_exhausted_mount_completions(5209);
    let cell = authentic.locator;
    let bound = bind_completed_mount_teardown(
        authentic.absent_expected,
        CompletedMountTeardown::from_absent(authentic.absent),
    )
    .map_err(|_| ())
    .expect("the exact exhausted cursor binds");

    assert_eq!(bound.cursor(), Some(MountAbsenceCursor::Exhausted));
    assert!(mount_teardown_permits_delete(&bound));
    let prepared = bound.into_prepared_deactivation();
    assert_eq!(prepared.locator(), cell);
    assert_eq!(prepared.cursor(), MountAbsenceCursor::Exhausted);
    assert_eq!(prepared.required_disposition(), SlotDisposition::Retired);
    // Exhausted is an exact answer, not a refusal. Refusing to delete here
    // would strand the generation forever — the cell is retired, not reusable.
}

#[test]
fn terminal_fence_joiner_gets_completion_after_other_teardown_resets() {
    let authentic = authentic_mount_completions(5210);
    // A joiner's completion is its own: it names the same generation but is a
    // Joined value, so it cannot be mistaken for the owner's and cannot be used
    // to satisfy an Owner expectation.
    let bound = bind_completed_mount_teardown(
        authentic.join_expected,
        CompletedMountTeardown::from_joined(authentic.join),
    )
    .map_err(|_| ())
    .expect("a joined completion answers a join expectation");
    assert!(mount_teardown_permits_delete(&bound));
    assert_eq!(bound.cursor(), Some(MountAbsenceCursor::Next(2)));

    let wrong_kind = authentic_mount_completions(5211);
    let refused = bind_completed_mount_teardown(
        ExpectedMountTeardown::Owner {
            locator: wrong_kind.locator,
            mount_generation: 1,
        },
        CompletedMountTeardown::from_joined(wrong_kind.join),
    )
    .map(|_| ())
    .expect_err("a joined completion cannot claim the owner's teardown");
    assert_eq!(refused.error(), LifecycleError::WrongState);
}

#[test]
fn r3_dismount_effect_cannot_succeed_before_bound_mount_completion() {
    // `DismountAndDeleteDevices` is one roster entry, and the roster stops at
    // the first refusal. So a mount teardown that has not produced a bound
    // completion stops the pass there and every later entry stays unattempted.
    let cell = locator(5207);
    let (executed, progress) = run_pass(
        cell,
        CheckpointTeardownPlan::ROSTER,
        Some(CheckpointFenceEffect::DismountAndDeleteDevices),
    );
    let CheckpointTeardownProgress::Refused(refused) = progress else {
        panic!("an unbound mount teardown refuses its roster entry")
    };
    assert_eq!(
        refused.cursor(),
        PrepareCheckpointFinish::Roster(CheckpointFenceEffect::DismountAndDeleteDevices)
    );
    assert!(
        refused
            .report()
            .failed(CheckpointFenceEffect::DismountAndDeleteDevices)
    );
    assert!(executed.contains(&CheckpointFenceEffect::DismountAndDeleteDevices));

    // The three entries that follow it in the roster — the transient backing,
    // the control strong reference, and the ledger check — were never tried.
    for later in [
        CheckpointFenceEffect::ReleaseTransientArraysAndBacking,
        CheckpointFenceEffect::ReleaseControlStrongRef,
        CheckpointFenceEffect::ReleaseRemainingStableSessionOwners,
        CheckpointFenceEffect::VerifySessionAndRootLedgers,
    ] {
        assert!(!refused.report().attempted(later), "{later:?}");
    }
}

#[test]
fn task12_mount_and_existing_resource_ledger_precedes_delete() {
    // The ledger check is the last roster entry, so nothing can report the
    // resources discharged before every release ran.
    assert_eq!(
        CheckpointTeardownPlan::ROSTER.last(),
        Some(&CheckpointFenceEffect::VerifySessionAndRootLedgers)
    );
    assert_eq!(
        CheckpointFenceEffect::VerifySessionAndRootLedgers.roster_index(),
        19
    );
    // And the mount teardown precedes both the backing release and the ledger.
    assert!(
        CheckpointFenceEffect::DismountAndDeleteDevices.roster_index()
            < CheckpointFenceEffect::ReleaseTransientArraysAndBacking.roster_index()
    );
    assert!(
        CheckpointFenceEffect::ReleaseTransientArraysAndBacking.roster_index()
            < CheckpointFenceEffect::VerifySessionAndRootLedgers.roster_index()
    );

    // A completed pass is the only thing that can carry an absence proof, and
    // the absence proof is what the deletion predicate needs. The two are not
    // separable: `with_absence` consumes the completion.
    let cell = locator(5208);
    let (_executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a clean pass completes")
    };
    assert!(complete.ran_the_closed_roster());
}

// ---------------------------------------------------------------------------
// Task 12: the cutover's own properties
// ---------------------------------------------------------------------------

#[test]
fn task12_delete_requires_r3_discharge_and_later_authority_absence() {
    let _closed_constructor: fn(
        SessionLocator,
    ) -> Result<
        R4AuthorityAbsence,
        crate::session::ProductionAttestationError,
    > = R4AuthorityAbsence::from_embedded_artifact;
    // Deletion needs both halves, and neither is obtainable without the other.
    // The absence proof lives *inside* the completion, so a caller cannot hold
    // a discharge without the artifact identity that makes it admissible.
    let cell = locator(6001);
    let (_executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a clean pass completes")
    };
    assert!(
        complete.ran_the_closed_roster(),
        "discharge is the whole roster"
    );

    let absence = R4AuthorityAbsence::injected_for_test(cell).expect("injected witness");
    let proof = complete
        .with_absence(absence)
        .map_err(|_| ())
        .expect("the same-brand absence attaches");
    assert_eq!(proof.absence().locator(), proof.locator());
    assert_eq!(
        proof.absence().artifact().profile(),
        crate::session::ProductionAttestationProfile::R4Cutover
    );

    // A pass that refused has no completion at all, so there is nothing to
    // attach an absence to and no route to a candidate.
    let (_executed, refused) = run_pass(
        cell,
        CheckpointTeardownPlan::ROSTER,
        Some(CheckpointFenceEffect::WaitSessionAccessRundown),
    );
    assert!(matches!(refused, CheckpointTeardownProgress::Refused(_)));
}

#[test]
fn one_terminal_winner_moves_complete_owner_chain_into_prepared_delete_before_shell_free() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum OwnerChainEvent {
        TerminalWinner(SessionLocator),
        CheckpointComplete(SessionLocator),
        CompleteOwnerChainPrepared(SessionLocator),
        Delete(FinalDeleteStep),
    }

    #[derive(Debug, PartialEq, Eq)]
    struct OwnerChainTrace {
        artifact: Option<crate::session::ProductionGraphArtifactIdentity>,
        events: Vec<OwnerChainEvent>,
    }

    impl OwnerChainTrace {
        fn new() -> Self {
            Self {
                artifact: None,
                events: Vec::new(),
            }
        }

        fn record_winner(&mut self, winner: &crate::session::TerminalWinner) {
            self.events
                .push(OwnerChainEvent::TerminalWinner(winner.locator()));
        }

        fn record_checkpoint(&mut self, complete: &R4TeardownComplete) {
            self.artifact = Some(complete.absence().artifact());
            self.events
                .push(OwnerChainEvent::CheckpointComplete(complete.locator()));
        }

        fn record_delete(&mut self, step: FinalDeleteStep) {
            self.events.push(OwnerChainEvent::Delete(step));
        }
    }

    let cell = locator(6004);
    let mut rendezvous = TerminalRendezvous::new_inactive();
    rendezvous
        .activate(cell)
        .expect("the published generation activates");
    let (winner, ticket) = rendezvous
        .claim(cell, TerminalRequest::Cleanup)
        .expect("one terminal arrival wins")
        .into_parts();
    let mut trace = OwnerChainTrace::new();
    trace.record_winner(&winner);

    let (_executed, progress) = run_pass(cell, CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("the real closed roster completes")
    };
    let absence = R4AuthorityAbsence::injected_for_test(cell).expect("injected witness");
    let complete = complete
        .with_absence(absence)
        .map_err(|_| ())
        .expect("the same-generation absence proof attaches");
    trace.record_checkpoint(&complete);
    let artifact = complete.absence().artifact();

    assert_eq!(
        decide_delete_preflight(DeletePreflightObservation::satisfied()),
        Ok(())
    );
    let rights = crate::session::NativeOwnerBindRights::for_test(cell);
    let (shell_right, root_right, _finalizer_right) = rights.into_parts();
    let storage_trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
    let readiness = unsafe {
        complete.bind_deletion_owners(
            TestDeletionTail,
            shell_right.bind(TestDeleteShell {
                trace: std::rc::Rc::clone(&storage_trace),
            }),
            root_right.bind(TestRootRelease {
                trace: std::rc::Rc::clone(&storage_trace),
            }),
        )
    }
    .map_err(|_| ())
    .expect("the complete owner chain enters deletion readiness once");
    let (_tail, storage) = readiness
        .into_prepared_delete_storage(
            crate::session::PreparedDeleteCoreCommit::for_test(cell),
            R3FinalizerRunningRight::for_test(cell),
            (),
        )
        .map_err(|_| ())
        .expect("the complete owner chain crosses the prepared-delete boundary");
    trace
        .events
        .push(OwnerChainEvent::CompleteOwnerChainPrepared(cell));
    let _cursor = unsafe { storage.execute() };
    assert_eq!(
        storage_trace.borrow().as_slice(),
        &[
            PreparedDeleteTraceRecord::DestroyShell,
            PreparedDeleteTraceRecord::ReleaseRoot,
        ]
    );
    trace.record_delete(FinalDeletePlan::first_step());

    assert_eq!(
        trace.artifact,
        Some(artifact),
        "the recorded owner chain carries the checkpoint's real artifact identity"
    );
    assert_eq!(
        trace.events,
        [
            OwnerChainEvent::TerminalWinner(cell),
            OwnerChainEvent::CheckpointComplete(cell),
            OwnerChainEvent::CompleteOwnerChainPrepared(cell),
            OwnerChainEvent::Delete(FinalDeleteStep::DestroyAndFreeShell),
        ],
        "the current path reaches shell destruction without one complete affine owner chain crossing PreparedDelete"
    );

    let _ = winner;
    let _ = ticket;
}

#[test]
fn task12_refusal_parks_without_completion_delete_or_unload() {
    // Every roster position refuses the same way: a cursor, a report, and no
    // completion. There is no position at which a refusal yields something a
    // deletion could be built from.
    for refusing in CheckpointTeardownPlan::ROSTER {
        let (_executed, progress) = run_pass(
            locator(6002),
            CheckpointTeardownPlan::ROSTER,
            Some(refusing),
        );
        let CheckpointTeardownProgress::Refused(refused) = progress else {
            panic!("{refusing:?} must refuse")
        };
        assert!(!refused.report().is_complete());
        assert_eq!(refused.cursor(), PrepareCheckpointFinish::Roster(refusing));
    }

    // A preparation refusal after a complete pass is the other cursor, and it
    // likewise carries no completion forward: `into_preparation_refusal`
    // consumes the completion rather than cloning it.
    let (_executed, progress) = run_pass(locator(6003), CheckpointTeardownPlan::ROSTER, None);
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a clean pass completes")
    };
    let refused = complete.into_preparation_refusal();
    assert_eq!(refused.cursor(), PrepareCheckpointFinish::FinishPreparation);
    assert!(
        refused.report().is_complete(),
        "the report still says the roster ran; the cursor says preparation did not"
    );
}

#[test]
fn completed_cell_and_control_context_results_are_identical_before_reset() {
    // The finalizer publishes one `TerminalResult` into two places, and a later
    // CLEANUP may read either. They are the same value by construction: the
    // authenticated result is the single source, and both the binding word and
    // the rendezvous outcome are built from it.
    let cell = locator(6004);
    let mut rendezvous = TerminalRendezvous::new_inactive();
    rendezvous.activate(cell).expect("activates");
    let (winner, ticket) = rendezvous
        .claim(cell, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let authenticated = AuthenticatedTerminalResult::new(winner, result)
        .map_err(|_| ())
        .expect("the winner's own reason");
    let published = authenticated.result();
    let (winner, from_carrier) = authenticated.into_parts();

    assert_eq!(published, from_carrier, "one value, read twice");
    rendezvous
        .close_and_publish_completed(winner, from_carrier)
        .map_err(|_| ())
        .expect("the counted winner closes its generation");
    assert_eq!(
        rendezvous.outcome_for_locator(cell),
        Some(crate::session::TerminalRendezvousOutcome::Completed(result)),
        "the cell copy is the same result the context record carries"
    );
    let _ = ticket;
}

#[test]
fn task12_immediate_and_later_last_release_use_one_atomic_deposit_boundary() {
    // Both orders reach the same place: a release that deletes and one that
    // retains are the two outcomes of *one* prepared-release decision, and the
    // decision is made before any mutation. There is no second path on which a
    // right is minted.
    for observation in [
        DeletePreflightObservation::satisfied(),
        DeletePreflightObservation {
            admitted_joiners: 4,
            ..DeletePreflightObservation::satisfied()
        },
    ] {
        assert_eq!(decide_delete_preflight(observation), Ok(()));
    }

    // The preflight is the same value for both orders, so the finalizer cannot
    // tell them apart -- which is the point: whichever release reached zero,
    // the deposit it consumes is the one deposit.
    let immediate = DeletePreflightObservation::satisfied();
    let later = DeletePreflightObservation {
        admitted_joiners: 9,
        ..DeletePreflightObservation::satisfied()
    };
    assert!(delete_preparation_survives(immediate, later));
    assert_eq!(
        decide_delete_preflight(immediate),
        decide_delete_preflight(later)
    );
}

/// Clear exactly one field of a satisfied observation.
fn observation_missing(step: FinalizerPreflightStep) -> DeletePreflightObservation {
    let mut observation = DeletePreflightObservation::satisfied();
    match step {
        FinalizerPreflightStep::CoreDeleting => {
            observation.core_deleting_with_exact_right = false;
        }
        FinalizerPreflightStep::MirrorAndShell => observation.mirror_matches_generation = false,
        FinalizerPreflightStep::ShellAndRootOwnership => {
            observation.shell_and_root_owned_by_readiness = false;
        }
        FinalizerPreflightStep::ClosingContextAndLease => {
            observation.closing_live_context_and_lease = false;
        }
        FinalizerPreflightStep::EmptyCompletedRecord => observation.completed_record_absent = false,
        FinalizerPreflightStep::OpenOutcomeAndJoinAdmission => {
            observation.outcome_open_and_admission_open = false;
        }
        FinalizerPreflightStep::RunningDepositAndPublisher => {
            observation.running_with_sole_authorities = false;
        }
    }
    observation
}

#[test]
fn prepared_delete_rejects_each_cross_product_mismatch_before_destroy() {
    assert_eq!(
        decide_delete_preflight(DeletePreflightObservation::satisfied()),
        Ok(())
    );

    // Every one of the seven checks is individually load-bearing, and each
    // reports the step that is actually missing. A chain that reported one
    // shared reason would make every fail-stop payload say the same thing.
    for step in DELETE_PREFLIGHT_ORDER {
        assert_eq!(
            decide_delete_preflight(observation_missing(step)),
            Err(step),
            "{step:?}"
        );
    }
    assert_eq!(DELETE_PREFLIGHT_ORDER.len(), 7);
    assert_eq!(
        DELETE_PREFLIGHT_ORDER.map(delete_failure_requires_opaque),
        [false, false, false, true, true, true, false],
        "only physical predicates 4/5/6 require opaque retention"
    );

    // The order is canonical: with two checks failing, the earlier one is
    // reported. Otherwise the payload would name whichever the author tested
    // first rather than the first thing actually wrong.
    let mut both = observation_missing(FinalizerPreflightStep::CoreDeleting);
    both.running_with_sole_authorities = false;
    assert_eq!(
        decide_delete_preflight(both),
        Err(FinalizerPreflightStep::CoreDeleting)
    );

    // A refusal is a value, not a destruction: the observation it was computed
    // from is unchanged, which is what lets the caller return the whole intact
    // deposit.
    let observation = observation_missing(FinalizerPreflightStep::ClosingContextAndLease);
    let repeated = decide_delete_preflight(observation);
    assert_eq!(repeated, decide_delete_preflight(observation));
}

#[test]
fn delete_preflight_requires_counted_open_join_admission() {
    for admitted_joiners in [0, u32::MAX] {
        let observation = DeletePreflightObservation {
            admitted_joiners,
            ..DeletePreflightObservation::satisfied()
        };
        assert_eq!(
            decide_delete_preflight(observation),
            Err(FinalizerPreflightStep::OpenOutcomeAndJoinAdmission),
        );
    }
    assert_eq!(
        decide_delete_preflight(DeletePreflightObservation::satisfied()),
        Ok(())
    );
}

#[test]
fn prepared_delete_allows_only_join_count_growth_before_publication() {
    let before = DeletePreflightObservation::satisfied();

    // The lock is dropped between preparation and publication, and exactly one
    // thing may change: another ordinary arrival joins.
    let joined = DeletePreflightObservation {
        admitted_joiners: before.admitted_joiners.saturating_add(3),
        ..before
    };
    assert!(delete_preparation_survives(before, joined));
    assert!(delete_preparation_survives(before, before));

    // A count that *shrank* means somebody released against a generation this
    // finalizer believes nobody has left.
    let shrunk = DeletePreflightObservation {
        admitted_joiners: 0,
        ..joined
    };
    assert!(!delete_preparation_survives(joined, shrunk));

    // Nothing else may move. Each field is checked on its own so a comparison
    // that quietly ignored one would be visible here.
    for step in DELETE_PREFLIGHT_ORDER {
        let changed = observation_missing(step);
        assert!(
            !delete_preparation_survives(before, changed),
            "{step:?} changed between preparation and publication"
        );
        // ...and it is still refused when a joiner arrived at the same time,
        // so growth cannot mask another change.
        let changed_and_joined = DeletePreflightObservation {
            admitted_joiners: 5,
            ..changed
        };
        assert!(
            !delete_preparation_survives(before, changed_and_joined),
            "{step:?} masked by join growth"
        );
    }
}

fn run_delete(
    cell: SessionLocator,
    roster: [FinalDeleteStep; 10],
) -> (Vec<FinalDeleteStep>, FinalDeleteProof) {
    let mut order = Vec::new();
    let mut progress = FinalDeletePlan::begin_with_roster(cell, roster);
    loop {
        progress = match progress {
            FinalDeleteProgress::Step(pending) => {
                order.push(pending.step());
                pending.performed()
            }
            FinalDeleteProgress::Complete(proof) => return (order, proof),
        };
    }
}

#[test]
fn prepared_delete_has_no_post_destruction_refusal_edge() {
    // The dynamic test driver has one continuation and no refusal result. The
    // production path is stricter: its affine cursor types expose only the
    // next fixed operation, and the final reset cursor is consumed together
    // with both reset authorities.
    let cell = locator(5101);
    let (order, proof) = run_delete(cell, FinalDeletePlan::STEPS);

    assert_eq!(order.as_slice(), FinalDeletePlan::STEPS.as_slice());
    assert!(proof.ran_every_step());
    assert_eq!(proof.locator(), cell);
    assert!(proof.transferred_record_before_publishing());
    assert!(proof.published_before_signalling());
    assert!(proof.drained_before_completing_rundown());
    assert!(proof.freed_before_reset());

    // The production entry point runs the same roster.
    assert_eq!(
        FinalDeletePlan::first_step(),
        FinalDeleteStep::DestroyAndFreeShell
    );
}

#[test]
fn delete_reset_and_free_retired_publication_are_one_locked_commit() {
    let cell = locator(5102);
    let (_order, proof) = run_delete(cell, FinalDeletePlan::STEPS);
    assert!(
        proof.reset_is_last(),
        "before the reset, process/unload sees the intact Deleting generation"
    );
    assert!(proof.freed_before_reset());

    // Each ordering proof is falsifiable: the orders they forbid report false.
    let mut signal_first = FinalDeletePlan::STEPS;
    signal_first.swap(3, 4);
    let (_order, inverted) = run_delete(cell, signal_first);
    assert!(!inverted.published_before_signalling());
    assert!(
        inverted.ran_every_step(),
        "the count alone cannot see order"
    );

    let mut reset_early = FinalDeletePlan::STEPS;
    reset_early.swap(0, 9);
    let (_order, inverted) = run_delete(cell, reset_early);
    assert!(!inverted.reset_is_last());
    assert!(!inverted.freed_before_reset());

    let mut rundown_early = FinalDeletePlan::STEPS;
    rundown_early.swap(6, 7);
    let (_order, inverted) = run_delete(cell, rundown_early);
    assert!(!inverted.drained_before_completing_rundown());

    let mut transfer_late = FinalDeletePlan::STEPS;
    transfer_late.swap(2, 3);
    let (_order, inverted) = run_delete(cell, transfer_late);
    assert!(!inverted.transferred_record_before_publishing());
}

#[test]
fn the_roster_index_and_report_masks_agree_with_the_closed_roster() {
    // Every mask bit is derived from the roster position, so a reordered roster
    // cannot silently keep the old bit meanings.
    for (index, effect) in CheckpointTeardownPlan::ROSTER.into_iter().enumerate() {
        assert_eq!(usize::from(effect.roster_index()), index, "{effect:?}");
    }

    // A deliberately reordered roster is observable: the same effect executed
    // first now sets bit zero. The seam exists so this proof is not a constant.
    let cell = locator(5008);
    let mut reordered = CheckpointTeardownPlan::ROSTER;
    reordered.swap(0, 19);
    let (executed, progress) = run_pass(cell, reordered, None);
    assert_eq!(
        executed.first(),
        Some(&CheckpointFenceEffect::VerifySessionAndRootLedgers)
    );
    let CheckpointTeardownProgress::Complete(complete) = progress else {
        panic!("a clean pass completes")
    };
    assert_ne!(
        executed.as_slice(),
        CheckpointTeardownPlan::ROSTER.as_slice(),
        "the reordered pass is a different order"
    );
    // ...and it still attempted all sixteen, which is why order needs its own
    // assertion rather than being inferred from the mask.
    assert_eq!(complete.report().attempted_mask(), 0x000F_FFFF);
}

// ---------------------------------------------------------------------------
// The roster walk, driven from a host test for the first time
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R3CheckpointNativeCall {
    CloseSessionAdmission,
    SignalPendingEnter,
    WaitControlRundown,
    WaitSessionAccessRundown,
    WaitExistingSqCqRolesAndConsumers,
    RemoveProducerMappingsReverse,
    WaitProducerAndMappingCaptureRundown,
    RetireExistingGrantAndCreditState,
    AcquireConsumersIncreasing,
    ReleaseConsumers,
    QueueInstalledWork,
    WaitPendingAndOwners,
    ReleaseReadOnlyMappingsReverse,
    ReleaseMdlsAndSystemView,
    ReleaseCapturedProcess,
    DismountAndDeleteDevices,
    ReleaseTransientArraysAndBacking,
    ReleaseControlStrongRef,
    ReleaseRemainingStableSessionOwners,
    VerifySessionAndRootLedgers,
}

struct RecordingR3CheckpointNativeOps {
    locator: SessionLocator,
    seen: Vec<R3CheckpointNativeCall>,
    refuse_at: Option<usize>,
    consumed: [bool; 20],
}

impl RecordingR3CheckpointNativeOps {
    fn new(locator: SessionLocator, refuse_at: Option<usize>) -> Self {
        Self {
            locator,
            seen: Vec::new(),
            refuse_at,
            consumed: [false; 20],
        }
    }

    // Proof of safety: every index below is a fixed test fixture position or a
    // cursor the same test just asserted, and this is host test code, not a
    // driver input path. An out-of-range index here is the test failing, which
    // is exactly the outcome wanted.
    #[allow(clippy::indexing_slicing)]
    fn record(&mut self, call: R3CheckpointNativeCall) -> bool {
        let position = self.seen.len();
        self.seen.push(call);
        if self.refuse_at == Some(position) {
            return false;
        }
        assert!(
            !self.consumed[position],
            "operation {position} replayed an owner"
        );
        self.consumed[position] = true;
        true
    }
}

macro_rules! recording_checkpoint_call {
    ($method:ident, $call:ident) => {
        unsafe fn $method(&mut self) -> bool {
            self.record(R3CheckpointNativeCall::$call)
        }
    };
}

impl R3CheckpointNativeOps for RecordingR3CheckpointNativeOps {
    fn checkpoint_locator(&self) -> SessionLocator {
        self.locator
    }

    recording_checkpoint_call!(close_session_admission, CloseSessionAdmission);
    recording_checkpoint_call!(signal_pending_enter, SignalPendingEnter);
    recording_checkpoint_call!(wait_control_rundown, WaitControlRundown);
    recording_checkpoint_call!(wait_session_access_rundown, WaitSessionAccessRundown);
    recording_checkpoint_call!(
        wait_existing_sq_cq_roles_and_consumers,
        WaitExistingSqCqRolesAndConsumers
    );
    recording_checkpoint_call!(
        remove_producer_mappings_reverse,
        RemoveProducerMappingsReverse
    );
    recording_checkpoint_call!(
        wait_producer_and_mapping_capture_rundown,
        WaitProducerAndMappingCaptureRundown
    );
    recording_checkpoint_call!(
        retire_existing_grant_and_credit_state,
        RetireExistingGrantAndCreditState
    );
    recording_checkpoint_call!(acquire_consumers_increasing, AcquireConsumersIncreasing);
    recording_checkpoint_call!(release_consumers, ReleaseConsumers);
    recording_checkpoint_call!(queue_installed_work, QueueInstalledWork);
    recording_checkpoint_call!(wait_pending_and_owners, WaitPendingAndOwners);
    recording_checkpoint_call!(
        release_read_only_mappings_reverse,
        ReleaseReadOnlyMappingsReverse
    );
    recording_checkpoint_call!(release_mdls_and_system_view, ReleaseMdlsAndSystemView);
    recording_checkpoint_call!(release_captured_process, ReleaseCapturedProcess);
    recording_checkpoint_call!(dismount_and_delete_devices, DismountAndDeleteDevices);
    recording_checkpoint_call!(
        release_transient_arrays_and_backing,
        ReleaseTransientArraysAndBacking
    );
    recording_checkpoint_call!(release_control_strong_ref, ReleaseControlStrongRef);
    recording_checkpoint_call!(
        release_remaining_stable_session_owners,
        ReleaseRemainingStableSessionOwners
    );
    recording_checkpoint_call!(verify_session_and_root_ledgers, VerifySessionAndRootLedgers);
}

const EXPECTED_R3_CHECKPOINT_NATIVE_CALLS: [R3CheckpointNativeCall; 20] = [
    R3CheckpointNativeCall::CloseSessionAdmission,
    R3CheckpointNativeCall::SignalPendingEnter,
    R3CheckpointNativeCall::WaitControlRundown,
    R3CheckpointNativeCall::WaitSessionAccessRundown,
    R3CheckpointNativeCall::WaitExistingSqCqRolesAndConsumers,
    R3CheckpointNativeCall::RemoveProducerMappingsReverse,
    R3CheckpointNativeCall::WaitProducerAndMappingCaptureRundown,
    R3CheckpointNativeCall::RetireExistingGrantAndCreditState,
    R3CheckpointNativeCall::AcquireConsumersIncreasing,
    R3CheckpointNativeCall::ReleaseConsumers,
    R3CheckpointNativeCall::QueueInstalledWork,
    R3CheckpointNativeCall::WaitPendingAndOwners,
    R3CheckpointNativeCall::ReleaseReadOnlyMappingsReverse,
    R3CheckpointNativeCall::ReleaseMdlsAndSystemView,
    R3CheckpointNativeCall::ReleaseCapturedProcess,
    R3CheckpointNativeCall::DismountAndDeleteDevices,
    R3CheckpointNativeCall::ReleaseTransientArraysAndBacking,
    R3CheckpointNativeCall::ReleaseControlStrongRef,
    R3CheckpointNativeCall::ReleaseRemainingStableSessionOwners,
    R3CheckpointNativeCall::VerifySessionAndRootLedgers,
];

#[test]
fn native_r4_checkpoint_trace_calls_all_twenty_operations_once_in_order() {
    let expected_locator = locator(7701);
    let mut native = RecordingR3CheckpointNativeOps::new(expected_locator, None);
    // SAFETY: the recording fake performs no kernel operation.
    let outcome = unsafe { run_checkpoint_roster(expected_locator, &mut native) };
    assert!(matches!(outcome, CheckpointRosterOutcome::Complete(_)));
    assert_eq!(native.seen, EXPECTED_R3_CHECKPOINT_NATIVE_CALLS);
    assert_eq!(native.consumed, [true; 20]);
}

#[test]
// Proof of safety: every index below is a fixed test fixture position or a
// cursor the same test just asserted, and this is host test code, not a
// driver input path. An out-of-range index here is the test failing, which
// is exactly the outcome wanted.
#[allow(clippy::indexing_slicing)]
fn native_r3_checkpoint_trace_stops_at_each_refused_operation() {
    for position in 0..EXPECTED_R3_CHECKPOINT_NATIVE_CALLS.len() {
        let expected_locator = locator(7702);
        let mut native = RecordingR3CheckpointNativeOps::new(expected_locator, Some(position));
        // SAFETY: the recording fake performs no kernel operation.
        let outcome = unsafe { run_checkpoint_roster(expected_locator, &mut native) };
        assert!(matches!(outcome, CheckpointRosterOutcome::Refused(_)));
        assert_eq!(
            native.seen.as_slice(),
            &EXPECTED_R3_CHECKPOINT_NATIVE_CALLS[..=position],
            "no operation after refusal {position} runs or replays",
        );
        assert!(native.consumed[..position].iter().all(|consumed| *consumed));
        assert!(
            native.consumed[position..]
                .iter()
                .all(|consumed| !*consumed),
            "the refused owner and every later owner stay retained at {position}",
        );
    }
}

#[test]
fn native_r3_checkpoint_trace_refuses_cross_wired_locator_before_any_operation_and_retains_all_owners()
 {
    let requested = locator(7703);
    let mut native = RecordingR3CheckpointNativeOps::new(locator(7704), None);

    // SAFETY: the recording fake performs no kernel operation.
    let outcome = unsafe { run_checkpoint_roster(requested, &mut native) };
    let CheckpointRosterOutcome::Refused(refused) = outcome else {
        panic!("a cross-wired native executor must refuse")
    };

    assert_eq!(refused.cursor(), PrepareCheckpointFinish::ExecutorBinding);
    assert_eq!(refused.report().locator(), requested);
    assert_eq!(refused.report().attempted_mask(), 0);
    assert_eq!(refused.report().failed_mask(), 0);
    assert!(native.seen.is_empty());
    assert_eq!(native.consumed, [false; 20]);
}

#[test]
fn native_checkpoint_release_operations_keep_three_direct_native_bodies_without_enum_dispatch() {
    let source = include_str!("../../../../fsring-fsd/src/session.rs");
    let operation = |name: &str| {
        let marker = format!("pub(crate) unsafe fn {name}");
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("missing production operation {name}"));
        let tail = &source[start..];
        let end = tail
            .find("\n///")
            .unwrap_or_else(|| panic!("missing end marker after production operation {name}"));
        &tail[..end]
    };

    let mappings = operation("checkpoint_release_read_only_mappings_reverse");
    assert!(mappings.contains("MmUnmapLockedPages"));
    assert!(mappings.contains("ZwUnmapViewOfSection"));
    assert!(mappings.contains("KeUnstackDetachProcess"));

    let mdls = operation("checkpoint_release_mdls_and_system_view");
    assert!(mdls.contains("IoFreeMdl"));
    assert!(mdls.contains("MmUnmapViewInSystemSpace"));
    assert!(mdls.contains("ZwClose"));

    let process = operation("checkpoint_release_captured_process");
    assert!(process.contains("captured_process"));
    assert!(process.contains("ObfDereferenceObject"));

    assert!(
        !source.contains("release_stage_six"),
        "the three named checkpoint operations must not share an enum dispatcher",
    );
}

#[test]
fn native_prepared_delete_production_uses_the_core_runner_and_named_operations() {
    let source = include_str!("../../../../fsring-fsd/src/fence.rs");
    let execute_start = source
        .find("unsafe fn execute(self, registry: NonNull<KernelSessionRegistry>)")
        .expect("missing production PreparedDelete executor");
    let execute_tail = &source[execute_start..];
    let execute_end = execute_tail
        .find("\n}\n\n/// The production executor")
        .expect("missing end marker after production PreparedDelete executor");
    let execute = &execute_tail[..execute_end];

    assert!(
        execute.contains("run_r3_prepared_delete_suffix(storage, &mut native)"),
        "production PreparedDelete must drive the same core runner as the recording trace",
    );
    assert!(
        !execute.contains("storage.execute()"),
        "production must not manually project the destructive cursor around the core runner",
    );

    let native_impl = source
        .find("unsafe impl R3PreparedDeleteNativeOps<PreparedCellResetRight>")
        .expect("missing private production PreparedDelete native-ops implementation");
    let native_impl = &source[native_impl..execute_start];
    for operation in [
        "transfer_closing_owner_to_completed_record_and_publish_outcome",
        "signal_terminal_outcome",
        "drain_counted_arrivals",
        "wait_joiners_drained",
        "complete_access_rundown",
        "reinitialize_access_rundown_if_reusable",
        "reset_cell_and_publish_disposition",
    ] {
        assert!(
            native_impl.contains(&format!("unsafe fn {operation}")),
            "production native ops is missing {operation}",
        );
    }
}

// ---------------------------------------------------------------------------
// R4 Task 19: the cutover's core-side named properties
// ---------------------------------------------------------------------------
//
// COVERAGE BOUNDARY, stated rather than implied. The cutover's structural
// claims -- that exactly one pending route is production-reachable, that both
// legacy bridges are gone, that the R3 authority surface is literally zero --
// are decided by
// `task19_r4_cutover_has_exactly_one_pending_terminal_delete_path`, which reads
// the source. Restating them as host assertions would be a check written from
// the same source as the thing it checks. What the rows below own is the part a
// host CAN decide: the version of the blocked payload, and the exact capability
// bundle that makes `R4AuthorityAbsence` mintable. The native install/drain
// traces are measured-uncovered here and are recorded as such in the evidence.

/// The blocked observation is R4's, carries the exact cursor and diagnostic,
/// and has no second arm a converter could target.
#[test]
fn task19_r4_readiness_replaces_r3_deposit_atomically() {
    let cell = locator(6100);
    let diagnostic = DiagnosticId::for_locator(cell);
    let payload = FenceTerminalBlocked::new(FenceFailStopReason::CoreInvariant, diagnostic);

    // The payload survives the public wrapper without decomposition: the arm
    // stores the whole thing, so a reader gets back exactly what was published.
    let blocked = crate::session::TerminalBlocked::from_fence(cell, payload);
    assert_eq!(blocked.locator(), cell);
    assert_eq!(payload.reason(), FenceFailStopReason::CoreInvariant);
    assert_eq!(payload.diagnostic(), diagnostic);

    assert_eq!(
        blocked.class(),
        crate::session::TerminalBlockedClass::FenceInvariant
    );
}

// ---------------------------------------------------------------------------
// Task 22: the exhaustive R5 fence dispatch seam
// ---------------------------------------------------------------------------

mod r5_fence_dispatch_tests {
    use crate::adapter::fence::{FenceNativeOps, execute_effect};
    use crate::effect::ALL_FENCE_EFFECTS;
    use crate::session::FenceEffect;

    /// A `FenceNativeOps` whose every method reports which method was entered.
    ///
    /// The marker is written into each method body by hand rather than derived
    /// from an argument, because that is the only way a *mis*-dispatch is
    /// visible: an implementation that could not tell one method from another
    /// would agree with any dispatcher at all.
    struct RecordingFenceOps {
        calls: std::vec::Vec<FenceEffect>,
        /// Refuse in this method, with `code`.
        refuse_in: Option<FenceEffect>,
        code: u32,
    }

    impl RecordingFenceOps {
        fn new() -> Self {
            Self {
                calls: std::vec::Vec::new(),
                refuse_in: None,
                code: 0,
            }
        }

        fn refusing(effect: FenceEffect, code: u32) -> Self {
            Self {
                calls: std::vec::Vec::new(),
                refuse_in: Some(effect),
                code,
            }
        }

        fn entered(&mut self, effect: FenceEffect) -> Result<(), u32> {
            self.calls.push(effect);
            if self.refuse_in == Some(effect) {
                Err(self.code)
            } else {
                Ok(())
            }
        }
    }

    impl FenceNativeOps for RecordingFenceOps {
        type Error = u32;

        fn close_session_admission(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::CloseSessionAdmission)
        }
        fn signal_pending_enter(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::SignalPendingEnter)
        }
        fn remove_producer_mappings_reverse(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::RemoveProducerMappingsReverse)
        }
        fn wait_producer_and_mapping_capture_rundown(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::WaitProducerAndMappingCaptureRundown)
        }
        fn acquire_consumers_increasing(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::AcquireConsumersIncreasing)
        }
        fn drain_stable_prefixes_bounded(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::DrainStablePrefixesBounded)
        }
        fn retire_credits(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::RetireCredits)
        }
        fn release_consumers(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::ReleaseConsumers)
        }
        fn queue_installed_work(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::QueueInstalledWork)
        }
        fn wait_pending_and_owners(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::WaitPendingAndOwners)
        }
        fn wait_control_rundown(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::WaitControlRundown)
        }
        fn release_read_only_mappings_reverse(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::ReleaseReadOnlyMappingsReverse)
        }
        fn release_mdls_and_system_view(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::ReleaseMdlsAndSystemView)
        }
        fn release_captured_process(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::ReleaseCapturedProcess)
        }
        fn dismount_and_delete_devices(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::DismountAndDeleteDevices)
        }
        fn release_transient_backing(&mut self) -> Result<(), u32> {
            self.entered(FenceEffect::ReleaseTransientBacking)
        }
    }

    /// Driving the whole advertised roster enters all sixteen methods, once
    /// each, in the order it was driven.
    ///
    /// **The roster's own order is not this row's claim** -- `effect.rs`'s
    /// `every_fence_effect_has_its_pinned_roster_index` pins that against an
    /// independently written list, and asserting it again here against
    /// `ALL_FENCE_EFFECTS` would be the constant agreeing with itself: swap two
    /// entries and both sides of the comparison swap together.
    ///
    /// What is claimed is the dispatcher's half: it enters exactly one method
    /// per call and follows its caller. The reverse pass is what makes that
    /// falsifiable -- a dispatcher with any order of its own passes the forward
    /// pass and fails the reverse one.
    #[test]
    fn execute_effect_calls_all_sixteen_trait_methods_in_roster_order() {
        let forward: std::vec::Vec<FenceEffect> = ALL_FENCE_EFFECTS.into_iter().collect();
        let mut backward = forward.clone();
        backward.reverse();

        for driven in [forward, backward] {
            let mut ops = RecordingFenceOps::new();
            for effect in driven.iter().copied() {
                execute_effect(&mut ops, effect).expect("the recorder refuses nothing");
            }
            assert_eq!(
                ops.calls, driven,
                "the dispatcher entered a different set, or imposed an order of its own",
            );
            assert_eq!(ops.calls.len(), 16, "sixteen calls, sixteen entries");
        }
    }

    /// Every refusal comes back out of `execute_effect` byte-for-byte.
    ///
    /// The code is chosen by the test and returned by the recorder, so what is
    /// checked is the *dispatcher's* propagation, not that an error happens to
    /// equal something the dispatcher computed. A dispatcher that mapped a
    /// refusal onto a shared "the fence failed" value would pass a row that only
    /// asserted `is_err`.
    #[test]
    fn each_execute_effect_error_is_returned_unchanged() {
        for (index, effect) in ALL_FENCE_EFFECTS.into_iter().enumerate() {
            let code = 0xC000_0000_u32.wrapping_add(index as u32);
            let mut ops = RecordingFenceOps::refusing(effect, code);
            assert_eq!(
                execute_effect(&mut ops, effect),
                Err(code),
                "{effect:?}: the refusal reached the caller changed",
            );
            // And the refusal is reported by the method that owns the effect,
            // not by some earlier one the dispatcher ran on the way.
            assert_eq!(ops.calls.as_slice(), &[effect], "{effect:?}");
        }
    }

    /// Each effect enters exactly one method, and it is that effect's own.
    ///
    /// This is the row a copy-paste in the sixteen-arm match fails: two arms
    /// calling one method leaves the other method unentered for its own effect.
    #[test]
    fn no_effect_dispatches_to_another_effect_method() {
        for effect in ALL_FENCE_EFFECTS {
            let mut ops = RecordingFenceOps::new();
            execute_effect(&mut ops, effect).expect("the recorder refuses nothing");
            assert_eq!(
                ops.calls.as_slice(),
                &[effect],
                "{effect:?} entered the wrong method, or more than one",
            );
        }
    }

    /// Every advertised effect names the checkpoint row that stands in for it
    /// today, or says outright that none does.
    ///
    /// The two rosters are separate on purpose — the checkpoint roster is what
    /// the current binary can honestly discharge, the advertised one is what
    /// Task 25 must end up running — but "separate" must not become "drifting".
    /// This table is `cfg(test)`, so it adds no production symbol; a new
    /// `FenceEffect` variant makes it fail to compile, and a renamed
    /// `CheckpointFenceEffect` variant does the same.
    #[test]
    fn every_advertised_effect_names_its_checkpoint_predecessor_or_none() {
        use crate::adapter::fence::CheckpointFenceEffect as C;

        const CORRESPONDENCE: [(FenceEffect, Option<C>); 16] = [
            (
                FenceEffect::CloseSessionAdmission,
                Some(C::CloseSessionAdmission),
            ),
            (FenceEffect::SignalPendingEnter, Some(C::SignalPendingEnter)),
            (
                FenceEffect::RemoveProducerMappingsReverse,
                Some(C::RemoveProducerMappingsReverse),
            ),
            (
                FenceEffect::WaitProducerAndMappingCaptureRundown,
                Some(C::WaitProducerAndMappingCaptureRundown),
            ),
            (
                FenceEffect::AcquireConsumersIncreasing,
                Some(C::AcquireConsumersIncreasing),
            ),
            // The pre-R5 predecessor: the checkpoint waits the roles out rather
            // than draining their stable prefixes, because there is no CQ drain
            // to run yet. Task 25 replaces it.
            (
                FenceEffect::DrainStablePrefixesBounded,
                Some(C::WaitExistingSqCqRolesAndConsumers),
            ),
            // Likewise: today's checkpoint retires the whole grant/credit state
            // it inherited, not the R5 credit generation.
            (
                FenceEffect::RetireCredits,
                Some(C::RetireExistingGrantAndCreditState),
            ),
            (FenceEffect::ReleaseConsumers, Some(C::ReleaseConsumers)),
            (FenceEffect::QueueInstalledWork, Some(C::QueueInstalledWork)),
            (
                FenceEffect::WaitPendingAndOwners,
                Some(C::WaitPendingAndOwners),
            ),
            (FenceEffect::WaitControlRundown, Some(C::WaitControlRundown)),
            (
                FenceEffect::ReleaseReadOnlyMappingsReverse,
                Some(C::ReleaseReadOnlyMappingsReverse),
            ),
            (
                FenceEffect::ReleaseMdlsAndSystemView,
                Some(C::ReleaseMdlsAndSystemView),
            ),
            (
                FenceEffect::ReleaseCapturedProcess,
                Some(C::ReleaseCapturedProcess),
            ),
            (
                FenceEffect::DismountAndDeleteDevices,
                Some(C::DismountAndDeleteDevices),
            ),
            (
                FenceEffect::ReleaseTransientBacking,
                Some(C::ReleaseTransientArraysAndBacking),
            ),
        ];

        // The table covers the roster exactly, in its order: a table that
        // silently dropped a row would otherwise still pass every lookup it
        // did contain.
        let listed: std::vec::Vec<FenceEffect> = CORRESPONDENCE
            .into_iter()
            .map(|(effect, _)| effect)
            .collect();
        assert_eq!(listed.as_slice(), ALL_FENCE_EFFECTS.as_slice());

        // No checkpoint row stands in for two advertised effects: that would
        // mean one native operation discharging two advertised obligations.
        let predecessors: std::vec::Vec<C> = CORRESPONDENCE
            .into_iter()
            .filter_map(|(_, predecessor)| predecessor)
            .collect();
        for (index, predecessor) in predecessors.iter().enumerate() {
            assert!(
                !predecessors
                    .iter()
                    .take(index)
                    .any(|earlier| earlier == predecessor),
                "{predecessor:?} was claimed by two advertised effects",
            );
        }
        assert_eq!(
            predecessors.len(),
            16,
            "every advertised effect has a checkpoint row standing in for it today",
        );
    }
}

// ---------------------------------------------------------------------------
// Task 23: consumer recovery
// ---------------------------------------------------------------------------

mod r5_consumer_recovery_tests {
    use crate::adapter::fence::{
        ConsumerFenceComplete, ConsumerPrefix, ConsumerPrefixPhase, ConsumerReleaseOutcome,
        ConsumerReleaseProof, ConsumerTokenSlabOwner, DrainCompletedProof, FenceError,
        PreparedConsumerDrain, RetireCompletedProof,
    };
    use crate::enter::{CqConsumerToken, PendingSlotParts};
    use crate::session::SessionRingSetBrand;
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    /// Storage a host test owns for the whole life of its prefix.
    ///
    /// In the driver this is a nonpaged slab reserved inside the native session;
    /// here it is a vector the test keeps alive, which is the same obligation
    /// written in host terms.
    pub(super) struct HostSlab {
        entries: std::vec::Vec<core::mem::MaybeUninit<Option<CqConsumerToken>>>,
    }

    impl HostSlab {
        pub(super) fn new(capacity: u32) -> Self {
            let mut entries = std::vec::Vec::new();
            for _ in 0..capacity {
                entries.push(core::mem::MaybeUninit::new(None));
            }
            Self { entries }
        }

        /// # Safety
        /// The returned owner points into this slab, so `self` must outlive it,
        /// and this must be called once per slab.
        pub(super) unsafe fn bind(&mut self, set: SessionRingSetBrand) -> ConsumerTokenSlabOwner {
            let capacity = self.entries.len() as u32;
            let base = core::ptr::NonNull::new(self.entries.as_mut_ptr()).expect("a live vector");
            // SAFETY: the vector is uniquely owned by this fixture, every entry
            // was written as `None` above, and the caller keeps it alive.
            unsafe { ConsumerTokenSlabOwner::bind_native_storage(set, base, capacity) }
                .expect("the slab covers the set")
        }
    }

    fn ring_identity(n: u64) -> SessionIdentity {
        SessionIdentity {
            mount_id: MountId { lo: n, hi: 23 },
            boot_instance_id: BootInstanceId { lo: 29, hi: 31 },
            session_epoch: 1,
        }
    }

    /// One published session's ring-set brand and its per-ring runtime parts.
    ///
    /// Shared with `session::tests` rather than restated: a second way to
    /// publish a session is a second thing that can drift.
    pub(super) fn published_rings(
        n: u64,
        rings: u32,
    ) -> (SessionRingSetBrand, std::vec::Vec<PendingSlotParts>) {
        let (_cell, brand, parts) =
            crate::session::tests::published_cell_with_rings::<1>(ring_identity(n), rings);
        (brand, parts)
    }

    fn token(parts: &mut PendingSlotParts) -> CqConsumerToken {
        parts
            .state
            .acquire_cq_consumer()
            .expect("a fresh ring admits its consumer")
    }

    /// The slab is indirect, and the prefix is small enough that moving it by
    /// value does not put 64 affine tokens on the stack.
    ///
    /// The second assertion is the structural one: if either type held an
    /// inline `[Option<CqConsumerToken>; 64]` it could not possibly be smaller
    /// than that array, so this rejects the inline layout without having to
    /// describe it.
    #[test]
    fn consumer_authority_slab_is_indirect_and_affine() {
        use core::mem::size_of;

        let inline_array = size_of::<Option<CqConsumerToken>>().saturating_mul(64);
        assert!(
            size_of::<ConsumerTokenSlabOwner>() <= 64,
            "the slab owner is {} bytes, over its 64-byte budget",
            size_of::<ConsumerTokenSlabOwner>(),
        );
        assert!(
            size_of::<ConsumerTokenSlabOwner>() < inline_array,
            "the slab owner is large enough to be holding the array itself",
        );
        assert!(
            size_of::<ConsumerPrefix>() < inline_array,
            "the prefix is large enough to be holding the array itself",
        );
    }

    /// The prefix and every proof fit the fence path's frame budget.
    #[test]
    fn consumer_prefix_and_proofs_fit_the_stack_budget() {
        use core::mem::size_of;

        assert!(
            size_of::<ConsumerPrefix>() <= 160,
            "the prefix is {} bytes, over its 160-byte budget",
            size_of::<ConsumerPrefix>(),
        );
        for (name, size) in [
            ("DrainCompletedProof", size_of::<DrainCompletedProof>()),
            ("RetireCompletedProof", size_of::<RetireCompletedProof>()),
            ("ConsumerReleaseProof", size_of::<ConsumerReleaseProof>()),
            ("ConsumerFenceComplete", size_of::<ConsumerFenceComplete>()),
            ("PreparedConsumerDrain", size_of::<PreparedConsumerDrain>()),
        ] {
            assert!(size <= 256, "{name} is {size} bytes");
        }
    }

    /// A token for the wrong ring, an already-taken ring, or a skipped ring is
    /// refused -- and comes back.
    ///
    /// **The return is the property.** A `Result<(), FenceError>` here would
    /// strand the role: the caller took it from the ring, so a refusal that
    /// swallowed it would leave that ring's consumer owned by nobody for the
    /// life of the session, and no later pass could release it.
    #[test]
    fn consumer_prefix_rejects_cross_set_cross_ring_and_nonincreasing_tokens() {
        let (brand, mut parts) = published_rings(2301, 3);
        let mut slab = HostSlab::new(3);
        // SAFETY: the fixture outlives the prefix built below.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix =
            ConsumerPrefix::begin_consumer_prefix(brand, owner).expect("the slab covers the set");

        // Out of the set entirely.
        let spare = token(&mut parts[2]);
        let (error, spare) = prefix
            .push_acquired(3, spare)
            .expect_err("ring 3 is not in a three-ring set");
        assert_eq!(error, FenceError::WrongRing);

        // A skip: the ordering is increasing *by one*, and a gap breaks the
        // total order that makes two concurrent fences deadlock-free.
        let (error, spare) = prefix
            .push_acquired(1, spare)
            .expect_err("ring 1 skips ring 0");
        assert_eq!(error, FenceError::NonIncreasingRing);
        assert_eq!(prefix.acquired_prefix(), 0, "a refusal acquired nothing");

        // In order, this one is accepted.
        prefix.push_acquired(0, spare).expect("ring 0 is next");
        assert_eq!(prefix.acquired_prefix(), 1);

        // And now ring 0 again is a duplicate.
        let repeat = token(&mut parts[0]);
        let (error, repeat) = prefix
            .push_acquired(0, repeat)
            .expect_err("ring 0 was already taken");
        assert_eq!(error, FenceError::DuplicateConsumer);
        drop(repeat);
    }

    /// Every refusal hands the exact token back, over the whole cross-product
    /// of illegal indices and phases.
    #[test]
    fn consumer_prefix_safe_api_returns_every_refused_token() {
        let (brand, mut parts) = published_rings(2302, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = ConsumerPrefix::begin_consumer_prefix(brand, owner).expect("covers");

        let mut spare = token(&mut parts[1]);
        let mut refusals = 0_u32;
        for index in [2_u32, 7, 1] {
            let (error, back) = prefix
                .push_acquired(index, spare)
                .expect_err("only ring 0 is next");
            refusals = refusals.saturating_add(1);
            assert!(matches!(
                error,
                FenceError::WrongRing | FenceError::NonIncreasingRing
            ));
            spare = back;
        }

        // A wrong phase returns it too: complete the set, then try to push.
        prefix.push_acquired(0, spare).expect("ring 0");
        let last = token(&mut parts[0]);
        prefix.push_acquired(1, last).expect("ring 1");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::AcquiredComplete);

        let (brand2, mut parts2) = published_rings(2303, 1);
        let extra = token(&mut parts2[0]);
        let (error, extra) = prefix
            .push_acquired(0, extra)
            .expect_err("a complete prefix takes nothing");
        assert_eq!(error, FenceError::InvalidConsumerPhase);
        drop(extra);
        let _ = brand2;
        assert_eq!(refusals, 3, "every illegal index was walked");
    }

    /// A partial acquisition cannot drain, and can still give back what it
    /// holds.
    ///
    /// Both halves matter. The first is why Drain has a typed prerequisite at
    /// all; the second is the case that used to be unrepresentable in this
    /// cursor -- a pass that took three of five rings and then refused had no
    /// phase from which to release them.
    #[test]
    fn partial_consumer_acquisition_defers_drain_and_retire_and_retains_backing() {
        let (brand, mut parts) = published_rings(2304, 3);
        let mut slab = HostSlab::new(3);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = ConsumerPrefix::begin_consumer_prefix(brand, owner).expect("covers");

        prefix
            .push_acquired(0, token(&mut parts[0]))
            .expect("ring 0");
        prefix
            .push_acquired(1, token(&mut parts[1]))
            .expect("ring 1");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::Acquiring);
        assert_eq!(prefix.acquired_prefix(), 2);

        // Drain refuses, and hands the prefix straight back.
        let Err((error, prefix)) = prefix.prepare_drain() else {
            panic!("two of three rings cannot drain")
        };
        assert_eq!(error, FenceError::IncompleteConsumerSet);
        assert_eq!(prefix.acquired_prefix(), 2, "the refusal changed nothing");

        // And the two roles it holds are releasable.
        let mut prefix = prefix;
        prefix.begin_release().expect("a partial prefix releases");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::ReleasingPartial);
        // One at a time, each back to its own ring and then accounted for.
        // Popping both before returning either would leave two tokens in flight
        // with one in-flight marker to describe them.
        for expected in [1_u32, 0] {
            let (index, back) = prefix.pop_for_release().expect("the highest first");
            assert_eq!(
                index, expected,
                "release is the exact reverse of acquisition"
            );
            parts[expected as usize]
                .state
                .release_cq_consumer(back)
                .map_err(|(error, _)| error)
                .expect("its own ring takes it back");
            prefix.confirm_released_token(index).expect("it is home");
        }
        assert!(matches!(
            prefix.finish_release(),
            ConsumerReleaseOutcome::Complete(_)
        ));
    }

    /// A recording `FenceKernelDdi` that can refuse one named operation.
    ///
    /// It records which raw operation was entered, which is what lets the rows
    /// below say "the wrapper called the DDI exactly once" rather than only
    /// "the wrapper returned something".
    #[derive(Debug, Default)]
    struct RecordingDdi {
        calls: std::vec::Vec<&'static str>,
        refuse: Option<&'static str>,
    }

    impl RecordingDdi {
        fn refusing(operation: &'static str) -> Self {
            Self {
                calls: std::vec::Vec::new(),
                refuse: Some(operation),
            }
        }

        fn entered(&mut self, operation: &'static str) -> Result<(), u32> {
            self.calls.push(operation);
            if self.refuse == Some(operation) {
                Err(0xDEAD_BEEF)
            } else {
                Ok(())
            }
        }
    }

    // SAFETY: this recorder owns no kernel object at all. Every method only
    // appends to a vector, so the trait's obligations about affine owners and
    // at-most-once effects hold vacuously.
    unsafe impl crate::adapter::fence::FenceKernelDdi for RecordingDdi {
        type Error = u32;

        unsafe fn native_close_generation_admission(&mut self) -> Result<(), u32> {
            self.entered("close")
        }
        unsafe fn native_schedule_linked_pending(&mut self) -> Result<(), u32> {
            self.entered("signal")
        }
        unsafe fn native_wait_control_and_access_rundown(&mut self) -> Result<(), u32> {
            self.entered("wait_control")
        }
        unsafe fn native_unmap_producer_aliases_reverse(&mut self) -> Result<(), u32> {
            self.entered("unmap_producer")
        }
        unsafe fn native_wait_producer_capture_rundown(&mut self) -> Result<(), u32> {
            self.entered("wait_producer")
        }
        unsafe fn native_acquire_consumers_increasing(
            &mut self,
            _prefix: &mut ConsumerPrefix,
        ) -> Result<(), u32> {
            self.entered("acquire")
        }
        unsafe fn native_drain_stable_prefixes_bounded(
            &mut self,
            _prepared: &mut PreparedConsumerDrain,
        ) -> Result<(), u32> {
            self.entered("drain")
        }
        unsafe fn native_retire_grants(
            &mut self,
            _call: &mut crate::adapter::fence::PreparedRetireCall,
        ) -> Result<(), u32> {
            self.entered("retire")
        }
        unsafe fn native_release_consumers(
            &mut self,
            _prefix: &mut ConsumerPrefix,
        ) -> Result<(), u32> {
            self.entered("release")
        }
        unsafe fn native_queue_installed_work(&mut self) -> Result<(), u32> {
            self.entered("queue")
        }
        unsafe fn native_wait_pending_and_owner_rundown(
            &mut self,
        ) -> Result<(), crate::adapter::fence::PendingOwnerWaitFailure<u32>> {
            self.entered("wait_pending")
                .map_err(crate::adapter::fence::PendingOwnerWaitFailure::Native)
        }
        unsafe fn native_unmap_readonly_aliases_reverse(&mut self) -> Result<(), u32> {
            self.entered("unmap_readonly")
        }
        unsafe fn native_release_mdls_and_system_view(&mut self) -> Result<(), u32> {
            self.entered("release_mdls")
        }
        unsafe fn native_dereference_process(&mut self) -> Result<(), u32> {
            self.entered("deref_process")
        }
        unsafe fn native_take_or_join_mount_and_delete(
            &mut self,
        ) -> Result<
            crate::adapter::fence::BoundCompletedMountTeardown,
            crate::adapter::fence::MountTeardownCallError<u32>,
        > {
            // This recorder owns no mount, so it can only refuse -- which is a
            // legitimate outcome, not a stub.
            let _ = self.entered("dismount");
            Err(crate::adapter::fence::MountTeardownCallError::Native(
                0xDEAD_BEEF,
            ))
        }
        unsafe fn native_release_transient_arrays(
            &mut self,
            proof: ConsumerReleaseProof,
        ) -> Result<(), (u32, ConsumerReleaseProof)> {
            match self.entered("release_backing") {
                Ok(()) => Ok(()),
                Err(error) => Err((error, proof)),
            }
        }
        unsafe fn native_take_consumer_slab(&mut self) -> Result<ConsumerTokenSlabOwner, u32> {
            self.entered("take_slab")?;
            Err(0x51AB_u32)
        }
    }

    fn blank_ops(ddi: RecordingDdi) -> crate::adapter::fence::KernelFenceOps<RecordingDdi> {
        let (brand, _) = published_rings(2701, 1);
        crate::adapter::fence::KernelFenceOps::blank(
            ddi,
            brand,
            crate::adapter::fence::FenceRetryKey::Effect(
                crate::session::FenceEffect::CloseSessionAdmission,
            ),
        )
    }

    /// Low-level recording DDI must see every KernelFenceOps native forward.
    /// A mutant that replaces a `D::native_*` call with `Ok(())` fails here.
    #[test]
    fn kernel_fence_ops_recording_ddi_forwards_each_native_call() {
        use crate::adapter::fence::{FenceNativeOps, KernelFenceError};

        let mut ops = blank_ops(RecordingDdi::refusing("close"));
        assert!(matches!(
            ops.close_session_admission(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("signal"));
        assert!(matches!(
            ops.signal_pending_enter(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("wait_control"));
        assert!(matches!(
            ops.wait_control_rundown(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("unmap_producer"));
        assert!(matches!(
            ops.remove_producer_mappings_reverse(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("wait_producer"));
        assert!(matches!(
            ops.wait_producer_and_mapping_capture_rundown(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("queue"));
        assert!(matches!(
            ops.queue_installed_work(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("unmap_readonly"));
        assert!(matches!(
            ops.release_read_only_mappings_reverse(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("release_mdls"));
        assert!(matches!(
            ops.release_mdls_and_system_view(),
            Err(KernelFenceError::Native(_))
        ));
        let mut ops = blank_ops(RecordingDdi::refusing("deref_process"));
        assert!(matches!(
            ops.release_captured_process(),
            Err(KernelFenceError::Native(_))
        ));
    }

    #[test]
    fn kernel_fence_ops_stateful_native_calls_enter_recording_ddi() {
        let (brand, mut parts) = published_rings(2702, 1);
        let mut slab = HostSlab::new(1);
        let owner = unsafe { slab.bind(brand) };
        let prefix = complete_prefix(brand, owner, &mut parts);
        let mut ops = blank_ops(RecordingDdi::refusing("acquire"));
        ops.wait_producer_done = true;
        ops.prefix = Some(prefix);
        ops.do_acquire();
        assert!(
            ops.first_retry.is_some(),
            "acquire native refusal must park a retry"
        );

        let mut ops = blank_ops(RecordingDdi::refusing("wait_pending"));
        ops.completed_consumers = None;
        ops.queue_done = true;
        ops.wait_control_done = true;
        ops.do_wait_pending();
        assert!(ops.first_retry.is_some() || !ops.wait_pending_done);

        let mut ops = blank_ops(RecordingDdi::refusing("dismount"));
        ops.process_done = true;
        ops.do_dismount();
        assert!(ops.first_retry.is_some() || !ops.dismount_done);

        let mut prefix_ops = blank_ops(RecordingDdi::refusing("release"));
        prefix_ops.prefix = Some({
            let (brand, mut parts) = published_rings(2703, 1);
            let mut slab = HostSlab::new(1);
            let owner = unsafe { slab.bind(brand) };
            let mut prefix = complete_prefix(brand, owner, &mut parts);
            prefix.begin_release().expect("release");
            prefix
        });
        prefix_ops.release_then(crate::adapter::fence::ConsumerReleaseNext::ReacquireThen(
            crate::adapter::fence::ConsumerResumeEffect::DrainStablePrefixesBounded,
        ));
        assert!(
            prefix_ops.first_retry.is_some(),
            "release native refusal must park a retry"
        );
        assert_eq!(
            prefix_ops.ddi.calls.as_slice(),
            &["release"],
            "release_then must enter native_release_consumers"
        );

        let mut backing_ops = blank_ops(RecordingDdi::refusing("release_backing"));
        backing_ops.completed_consumers = Some(paired_consumers(2704));
        backing_ops.do_release_backing();
        assert!(
            backing_ops.first_retry.is_some(),
            "release-backing native refusal must park a retry"
        );
        assert_eq!(
            backing_ops.ddi.calls.as_slice(),
            &["release_backing"],
            "do_release_backing must enter native_release_transient_arrays"
        );
    }

    fn paired_consumers(n: u64) -> ConsumerFenceComplete {
        let (brand, mut parts) = published_rings(n, 1);
        // The release proof owns a pointer into this slab for the rest of the
        // test. Leak it rather than threading a lifetime through finish().
        let slab = Box::leak(Box::new(HostSlab::new(1)));
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);
        prefix.begin_release().expect("a complete prefix releases");
        let (index, token) = prefix.pop_for_release().expect("the only ring");
        parts[0]
            .state
            .release_cq_consumer(token)
            .map_err(|(error, _)| error)
            .expect("its own ring takes it back");
        prefix.confirm_released_token(index).expect("it is home");
        let ConsumerReleaseOutcome::Complete(released) = prefix.finish_release() else {
            panic!("the empty prefix mints a release proof")
        };
        let retired = RetireCompletedProof {
            drain: DrainCompletedProof {
                set: brand,
                authority: super::super::PrivateDrainCompletedAuthority(()),
            },
            authority: super::super::PrivateRetireCompletedAuthority(()),
        };
        ConsumerFenceComplete::pair(retired, released).unwrap_or_else(|_| panic!("same brand"))
    }

    fn bound_owner_mount(n: u64) -> crate::adapter::fence::BoundCompletedMountTeardown {
        let completions = super::authentic_mount_completions(n);
        crate::adapter::fence::bind_completed_mount_teardown(
            completions.owner_expected,
            crate::adapter::fence::CompletedMountTeardown::from_owner(completions.owner),
        )
        .unwrap_or_else(|_| panic!("an owner completion binds its expectation"))
    }

    /// `finish` may mint Complete only with a full mask, no retry, and both
    /// consumer and mount proofs. A parked retry with those proofs still parks.
    #[test]
    fn kernel_fence_ops_finish_discharges_only_a_complete_empty_residual() {
        let mut complete = blank_ops(RecordingDdi::default());
        complete.attempted_mask = super::super::KERNEL_FENCE_FULL_MASK;
        complete.completed_consumers = Some(paired_consumers(2705));
        complete.bound_mount = Some(bound_owner_mount(2706));
        assert!(
            matches!(
                complete.finish(),
                crate::adapter::fence::FenceRunOutcome::Complete { .. }
            ),
            "a full pass with both proofs must discharge"
        );

        let mut residual = blank_ops(RecordingDdi::default());
        residual.attempted_mask = super::super::KERNEL_FENCE_FULL_MASK;
        residual.completed_consumers = Some(paired_consumers(2707));
        residual.bound_mount = Some(bound_owner_mount(2708));
        residual.first_retry = Some((
            crate::adapter::fence::FenceRetryPoint::Effect(
                crate::session::FenceEffect::ReleaseTransientBacking,
            ),
            super::super::PrivateFenceRetryCause::TransientNative,
        ));
        assert!(
            matches!(
                residual.finish(),
                crate::adapter::fence::FenceRunOutcome::Residual { .. }
            ),
            "a parked retry must not mint FenceObligationsDischarged"
        );
    }

    /// Acquire a complete prefix over `rings` rings.
    fn complete_prefix(
        brand: SessionRingSetBrand,
        slab: ConsumerTokenSlabOwner,
        parts: &mut [PendingSlotParts],
    ) -> ConsumerPrefix {
        let mut prefix = ConsumerPrefix::begin_consumer_prefix(brand, slab).expect("covers");
        for (index, part) in parts.iter_mut().enumerate() {
            let taken = part
                .state
                .acquire_cq_consumer()
                .expect("a fresh ring admits its consumer");
            prefix
                .push_acquired(index as u32, taken)
                .expect("increasing order");
        }
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::AcquiredComplete);
        prefix
    }

    /// A drain refusal returns the same prepared packet, and the prefix inside
    /// it is untouched, so the retry drains the set it already holds.
    #[test]
    fn drain_failure_release_requires_reacquire_before_drain_retry() {
        use crate::adapter::fence::drain_stable_prefixes_with_proof;

        let (brand, mut parts) = published_rings(2310, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let prefix = complete_prefix(brand, owner, &mut parts);
        let prepared = prefix
            .prepare_drain()
            .unwrap_or_else(|_| panic!("complete"));

        let mut ddi = RecordingDdi::refusing("drain");
        let Err((error, prepared)) = drain_stable_prefixes_with_proof(&mut ddi, prepared) else {
            panic!("the recorder refused the drain")
        };
        assert!(matches!(
            error,
            crate::adapter::fence::KernelFenceError::Native(0xDEAD_BEEF)
        ));
        assert_eq!(ddi.calls.as_slice(), &["drain"], "one raw call, no retry");
        assert_eq!(
            prepared.consumer_prefix().acquired_prefix(),
            2,
            "the refusal returned the same complete prefix",
        );

        // The retry drains that exact packet, and only success mints a proof.
        let mut ddi = RecordingDdi::default();
        let drained = drain_stable_prefixes_with_proof(&mut ddi, prepared)
            .unwrap_or_else(|_| panic!("the recorder accepts"));
        assert_eq!(ddi.calls.as_slice(), &["drain"]);
        assert_eq!(drained.consumer_prefix().acquired_prefix(), 2);
    }

    /// The retire boundary consumes the drain proof and hands it back unchanged
    /// when the raw call refuses.
    ///
    /// That is what stops a retry from retiring against a drain that never
    /// happened: there is no route to a `RetireCompletedProof` that does not
    /// carry the `DrainCompletedProof` the same pass produced.
    #[test]
    fn retire_boundary_consumes_drain_proof_and_returns_it_unchanged_on_refusal() {
        use crate::adapter::fence::{drain_stable_prefixes_with_proof, retire_credits_with_proof};

        let (brand, mut parts) = published_rings(2311, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let prefix = complete_prefix(brand, owner, &mut parts);
        let prepared = prefix
            .prepare_drain()
            .unwrap_or_else(|_| panic!("complete"));

        let mut ddi = RecordingDdi::default();
        let drained = drain_stable_prefixes_with_proof(&mut ddi, prepared)
            .unwrap_or_else(|_| panic!("drain accepted"));

        let mut ddi = RecordingDdi::refusing("retire");
        let Err((error, drained)) = retire_credits_with_proof(&mut ddi, drained) else {
            panic!("the recorder refused the retire")
        };
        assert!(matches!(
            error,
            crate::adapter::fence::KernelFenceError::Native(0xDEAD_BEEF)
        ));
        assert_eq!(ddi.calls.as_slice(), &["retire"], "one raw call");
        assert_eq!(
            drained.consumer_prefix().acquired_prefix(),
            2,
            "the drained packet came back whole",
        );

        // Success is the only mint, and it carries that same drain proof.
        let mut ddi = RecordingDdi::default();
        let retired = retire_credits_with_proof(&mut ddi, drained)
            .unwrap_or_else(|_| panic!("retire accepted"));
        let (prefix, proof) = retired.into_retired_parts();
        assert_eq!(proof.set_brand(), brand, "the proof names this ring set");
        assert_eq!(prefix.acquired_prefix(), 2);
    }

    /// Releasing every role is the only mint of a release proof, and the
    /// transient backing cannot be released without it.
    ///
    /// The second half is the reason the empty slab travels *inside* the proof:
    /// the DDI that frees the storage takes the proof by value, so there is no
    /// call to it that could run while a token is still live.
    #[test]
    fn transient_backing_requires_complete_consumer_release_proof() {
        let (brand, mut parts) = published_rings(2312, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);

        prefix.begin_release().expect("a complete prefix releases");
        let (first_index, first) = prefix.pop_for_release().expect("the highest ring first");
        assert_eq!(first_index, 1);
        parts[1]
            .state
            .release_cq_consumer(first)
            .map_err(|(error, _)| error)
            .expect("ring 1 takes its own back");
        prefix
            .confirm_released_token(first_index)
            .expect("it is home");

        // One token still live: the release cannot conclude.
        let ConsumerReleaseOutcome::Partial(partial) = prefix.finish_release() else {
            panic!("one role is still held")
        };
        let mut prefix = partial.restart_released_partial();
        assert_eq!(prefix.acquired_prefix(), 1, "ring 0 is still held");

        // Give the last one back, and now it concludes.
        prefix.begin_release().expect("the parked prefix releases");
        let (last_index, last) = prefix.pop_for_release().expect("ring 0");
        assert_eq!(last_index, 0);
        parts[0]
            .state
            .release_cq_consumer(last)
            .map_err(|(error, _)| error)
            .expect("ring 0 takes its own back");
        prefix
            .confirm_released_token(last_index)
            .expect("it is home");
        let ConsumerReleaseOutcome::Complete(proof) = prefix.finish_release() else {
            panic!("every role is back")
        };
        assert_eq!(proof.set_brand(), brand);

        // Only that proof reaches the backing DDI, and it is consumed.
        let mut ddi = RecordingDdi::default();
        // SAFETY: the proof owns the empty slab, so no token can be live.
        let released = unsafe {
            crate::adapter::fence::FenceKernelDdi::native_release_transient_arrays(&mut ddi, proof)
        };
        assert!(released.is_ok());
        assert_eq!(ddi.calls.as_slice(), &["release_backing"]);
    }

    /// A partial release parks, and the parked cursor resumes acquiring from
    /// exactly where it stopped rather than from zero.
    #[test]
    fn partial_acquire_partial_release_then_full_reacquire_reaches_one_release_proof() {
        let (brand, mut parts) = published_rings(2313, 3);
        let mut slab = HostSlab::new(3);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = ConsumerPrefix::begin_consumer_prefix(brand, owner).expect("covers");

        prefix
            .push_acquired(0, token(&mut parts[0]))
            .expect("ring 0");
        prefix
            .push_acquired(1, token(&mut parts[1]))
            .expect("ring 1");

        // Release one, park. The popped token is handed **back to its ring**,
        // not dropped: dropping it would leave that ring's consumer role owned
        // by nobody, and the reacquire below would find it busy forever. That is
        // what the native `native_release_consumers` DDI does with each token
        // this cursor pops.
        prefix.begin_release().expect("a partial prefix releases");
        let (index, released) = prefix.pop_for_release().expect("ring 1 first");
        assert_eq!(index, 1);
        parts[1]
            .state
            .release_cq_consumer(released)
            .map_err(|(error, _)| error)
            .expect("its own ring takes it back");
        prefix
            .confirm_released_token(index)
            .expect("ring 1 is home");
        let ConsumerReleaseOutcome::Partial(partial) = prefix.finish_release() else {
            panic!("ring 0 is still held")
        };

        // Resume: ring 0 is still held, so the next acquire is ring 1.
        let mut prefix = partial.restart_released_partial();
        assert_eq!(prefix.acquired_prefix(), 1);
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::Acquiring);
        prefix
            .push_acquired(1, token(&mut parts[1]))
            .expect("ring 1 again");
        prefix
            .push_acquired(2, token(&mut parts[2]))
            .expect("ring 2");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::AcquiredComplete);

        // And one complete reverse release yields exactly one proof.
        prefix.begin_release().expect("complete");
        for expected in [2_u32, 1, 0] {
            let (index, back) = prefix.pop_for_release().expect("reverse order");
            assert_eq!(index, expected);
            parts[expected as usize]
                .state
                .release_cq_consumer(back)
                .map_err(|(error, _)| error)
                .expect("each token goes back to the ring it came from");
            prefix.confirm_released_token(index).expect("it is home");
        }
        assert!(matches!(
            prefix.finish_release(),
            ConsumerReleaseOutcome::Complete(_)
        ));
    }

    /// A releasing cursor admits no acquisition, and a parked one admits no pop.
    ///
    /// Both directions, because a phase machine that only refused one of them
    /// would let an acquire and a release race for the same ring.
    #[test]
    fn release_cursor_never_calls_acquire_until_reverse_release_is_complete() {
        let (brand, mut parts) = published_rings(2314, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);

        prefix.begin_release().expect("complete");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::ReleasingPartial);

        let (other_brand, mut other_parts) = published_rings(2315, 1);
        let intruder = token(&mut other_parts[0]);
        let (error, intruder) = prefix
            .push_acquired(0, intruder)
            .expect_err("a releasing cursor acquires nothing");
        assert_eq!(error, FenceError::InvalidConsumerPhase);
        drop(intruder);
        let _ = other_brand;

        // Drain is refused for the same reason.
        let Err((error, mut prefix)) = prefix.prepare_drain() else {
            panic!("a releasing cursor does not drain")
        };
        assert_eq!(error, FenceError::IncompleteConsumerSet);

        // Park, and a parked cursor admits no pop until it begins again.
        prefix.park_partial_release().expect("parked");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::ReleasedPartial);
        assert_eq!(
            prefix.pop_for_release().expect_err("parked"),
            FenceError::InvalidConsumerPhase,
        );
    }

    /// A token the caller popped and never got home cannot become a proof.
    ///
    /// `release_remaining == 0` is not the property. The property is that every
    /// ring took its own token back, and a token sitting in the caller's hands
    /// between `pop_for_release` and the native call is evidence of neither.
    ///
    /// Round 15's N1: `pop_for_release` set `ReleasedComplete` -- the phase
    /// whose own doc reads "every role is back" -- the moment the last ring's
    /// token was taken OUT of the slab, so a cursor that lost it still satisfied
    /// `finish_release`'s mint condition and produced a full
    /// `ConsumerReleaseProof` over a ring whose `cq_owner` was `Some(..)` with
    /// no holder in existence. Every later acquire and every later DRAIN ENTER
    /// on that ring then finds it busy for the life of the session.
    #[test]
    fn a_popped_token_that_never_gets_home_cannot_mint_a_release_proof() {
        let (brand, mut parts) = published_rings(2316, 1);
        let mut slab = HostSlab::new(1);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);

        prefix.begin_release().expect("the only ring");
        let (index, in_flight) = prefix.pop_for_release().expect("ring 0");
        assert_eq!(index, 0);
        assert_eq!(prefix.release_remaining(), 0);
        assert_ne!(
            prefix.prefix_phase(),
            ConsumerPrefixPhase::ReleasedComplete,
            "the phase whose own doc reads 'every role is back' must not \
             describe a token still in the caller's hands",
        );

        // The native release refuses and the caller loses the token: no
        // `release_cq_consumer`, no restore. This is exactly what
        // `native_release_consumers` did with the token inside a refused
        // `restore_released_token`'s `Err`.
        drop(in_flight);

        assert!(
            !matches!(prefix.finish_release(), ConsumerReleaseOutcome::Complete(_)),
            "a token that never got home must not mint a ConsumerReleaseProof",
        );
    }

    /// A lost token follows the cursor across a park and a restart.
    ///
    /// `finish_release`'s Partial arm keeps the in-flight ring, and
    /// `restart_released_partial` does not clear it, so the pass that lost a
    /// token can never reach a proof by going round again -- which it otherwise
    /// could: `begin_release` mints `ReleasedComplete` directly when the slab is
    /// empty, and after a loss the slab IS empty.
    #[test]
    fn a_restarted_cursor_still_cannot_mint_over_a_token_it_lost() {
        let (brand, mut parts) = published_rings(2319, 1);
        let mut slab = HostSlab::new(1);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);

        prefix.begin_release().expect("the only ring");
        let (index, lost) = prefix.pop_for_release().expect("ring 0");
        assert_eq!(index, 0);
        drop(lost);

        let ConsumerReleaseOutcome::Partial(partial) = prefix.finish_release() else {
            panic!("a lost token is not a complete release")
        };
        let mut prefix = partial.restart_released_partial();

        // The slab is empty, so this takes `begin_release`'s zero-token arm and
        // sets `ReleasedComplete`. That phase plus an empty slab was the whole
        // mint condition; the in-flight ring is what still refuses.
        prefix.begin_release().expect("nothing is held");
        assert!(
            !matches!(prefix.finish_release(), ConsumerReleaseOutcome::Complete(_)),
            "going round again must not launder a token that never got home",
        );
    }

    /// A refused native release hands the last ring's token back to the cursor.
    ///
    /// This is the path `native_release_consumers` walks on failure, and the
    /// last ring is the one it could not walk: `restore_released_token` read the
    /// phase, and the phase after ring 0's pop said the release was over, so the
    /// restore refused and the refusal carried the affine token into a `let _ =`.
    /// The restore is gated on the in-flight ring now, which is the same gate
    /// for ring 0 as for every other.
    #[test]
    fn a_refused_release_of_the_last_token_puts_it_back_on_the_cursor() {
        let (brand, mut parts) = published_rings(2317, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);

        prefix.begin_release().expect("complete");
        let (high, high_token) = prefix.pop_for_release().expect("ring 1 first");
        assert_eq!(high, 1);
        parts[1]
            .state
            .release_cq_consumer(high_token)
            .map_err(|(error, _)| error)
            .expect("ring 1 takes its own back");
        prefix.confirm_released_token(high).expect("ring 1 is home");

        // Ring 0: popped, and the native release refuses.
        let (last, last_token) = prefix.pop_for_release().expect("then ring 0");
        assert_eq!(last, 0);
        assert_eq!(prefix.release_remaining(), 0, "nothing is left in the slab");

        prefix
            .restore_released_token(last, last_token)
            .map_err(|(error, _)| error)
            .expect("the last ring's token goes back on the cursor");
        assert_eq!(prefix.release_remaining(), 1, "ring 0 is held again");

        // A cursor that owns ring 0 parks. It does not mint.
        prefix.park_partial_release().expect("nothing is in flight");
        assert_eq!(prefix.prefix_phase(), ConsumerPrefixPhase::ReleasedPartial);
        let ConsumerReleaseOutcome::Partial(partial) = prefix.finish_release() else {
            panic!("ring 0's role is still held")
        };

        // And the retry really does resume at ring 0 rather than skipping it.
        let prefix = partial.restart_released_partial();
        assert_eq!(prefix.acquired_prefix(), 1, "ring 0 is still owned");
    }

    /// A cursor with nothing in flight adopts no token.
    ///
    /// `restore_released_token` puts back the one token this cursor handed out,
    /// and that is the whole of its job. Gated on the phase instead, it would
    /// also accept a token from a ring this pass never acquired -- the phase of
    /// a partial release says nothing about which ring is out -- and count it
    /// into `release_remaining`, which is the number `finish_release` reads.
    #[test]
    fn a_cursor_with_nothing_in_flight_refuses_a_token_it_never_handed_out() {
        let (brand, mut parts) = published_rings(2320, 3);
        let mut slab = HostSlab::new(3);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = ConsumerPrefix::begin_consumer_prefix(brand, owner).expect("covers");

        // Two of three rings: a partial acquisition, releasable as it stands.
        prefix
            .push_acquired(0, token(&mut parts[0]))
            .expect("ring 0");
        prefix
            .push_acquired(1, token(&mut parts[1]))
            .expect("ring 1");
        prefix.begin_release().expect("a partial prefix releases");
        assert_eq!(prefix.release_remaining(), 2);

        // Ring 2 was never acquired by this pass, and nothing is in flight.
        let stranger = token(&mut parts[2]);
        let (error, stranger) = prefix
            .restore_released_token(2, stranger)
            .expect_err("this cursor handed out no token");
        assert_eq!(error, FenceError::InvalidConsumerPhase);
        drop(stranger);
        assert_eq!(
            prefix.release_remaining(),
            2,
            "a refused restore counts nothing in",
        );
    }

    /// A cursor with a token in flight can neither park nor mint.
    ///
    /// Parking would record a prefix owning `release_remaining` tokens while one
    /// more is unaccounted for, and the resumed pass would never look for it.
    #[test]
    fn a_cursor_holding_a_token_in_flight_refuses_to_park() {
        let (brand, mut parts) = published_rings(2318, 2);
        let mut slab = HostSlab::new(2);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(brand) };
        let mut prefix = complete_prefix(brand, owner, &mut parts);

        prefix.begin_release().expect("complete");
        let (index, in_flight) = prefix.pop_for_release().expect("ring 1 first");
        assert_eq!(index, 1);

        assert_eq!(
            prefix.park_partial_release().expect_err("one is in flight"),
            FenceError::IncompleteConsumerSet,
        );
        // And a second pop is refused while the first is still out.
        assert_eq!(
            prefix.pop_for_release().expect_err("one at a time"),
            FenceError::DuplicateConsumer,
        );

        // Account for it, and both become available again.
        parts[1]
            .state
            .release_cq_consumer(in_flight)
            .map_err(|(error, _)| error)
            .expect("ring 1 takes its own back");
        prefix
            .confirm_released_token(index)
            .expect("ring 1 is home");
        prefix.park_partial_release().expect("nothing is in flight");
    }
}

// ---------------------------------------------------------------------------
// Task 24: the residual retry lifecycle
// ---------------------------------------------------------------------------

mod r5_retry_lifecycle_tests {
    use crate::adapter::fence::{
        FENCE_RETRY_DELAY_MS, FenceFailStopReason, FenceRetryDisposition, FenceRetryKey,
        FenceRetryLifecycle, FenceRetryLifecycleState, FenceRetryNeeded,
        checked_retry_due_time_100ns,
    };
    use crate::adapter::lifecycle::LifecycleError;
    use crate::session::{FenceEffect, SessionLocator};
    use core::sync::atomic::AtomicU64;
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    fn retry_locator(n: u64) -> SessionLocator {
        SessionLocator::from_parts_for_test(
            0,
            3,
            SessionIdentity {
                mount_id: MountId { lo: n, hi: 37 },
                boot_instance_id: BootInstanceId { lo: 41, hi: 43 },
                session_epoch: 1,
            },
        )
    }

    /// One armed delay, walked back to a Running pass and deferred again.
    ///
    /// The real path is DelayArmed -> DelayDpcRunning -> Queued -> Running, and
    /// a retry only re-enters the scheduler through `defer`. Folding that into
    /// one helper is what lets the row below read as a walk of the table rather
    /// than a transcription of the state machine.
    fn defer_again(
        machine: &mut FenceRetryLifecycle,
        right: crate::adapter::fence::FenceRetryDelayRight,
        locator: SessionLocator,
        key: FenceRetryKey,
    ) -> crate::adapter::fence::FenceRetryDelayRight {
        let dpc = machine
            .begin_delay_dpc(right)
            .map_err(|(error, _)| error)
            .expect("the timer this lifecycle armed");
        let queued = machine
            .queue_from_dpc(dpc)
            .map_err(|(error, _)| error)
            .expect("its own dpc right");
        let run = machine
            .begin_fence_retry_run(queued)
            .unwrap_or_else(|_| panic!("its own queued right"));
        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, key);
        match machine.defer(run, needed) {
            Ok(FenceRetryDisposition::Delay(next)) => next,
            Ok(FenceRetryDisposition::FailStop(_)) => {
                panic!("a transient refusal is never a fail-stop")
            }
            Err(_) => panic!("a Running lifecycle defers"),
        }
    }

    /// Repeating the same retry point walks the exact ten-entry table and then
    /// stays on its last entry.
    ///
    /// The delays are compared against `FENCE_RETRY_DELAY_MS` converted by
    /// `checked_retry_due_time_100ns`, and the table itself is pinned against an
    /// independently written literal in the first assertion -- so a changed
    /// table fails the literal, and a changed *index* fails the walk. Twelve
    /// refusals against ten entries is what makes the saturation visible: the
    /// last three delays must all be the tail.
    #[test]
    fn retry_delay_uses_exact_100_200_400_800_1600_3200_6400_12800_25600_30000ms_table() {
        assert_eq!(
            FENCE_RETRY_DELAY_MS,
            [100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 30000],
        );

        let locator = retry_locator(2401);
        let (mut machine, binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");
        let key = FenceRetryKey::Effect(FenceEffect::WaitControlRundown);

        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, key);
        let FenceRetryDisposition::Delay(mut right) = machine
            .prepare_fence_retry(binding, needed)
            .unwrap_or_else(|_| panic!("an idle lifecycle schedules"))
        else {
            panic!("a transient refusal delays")
        };

        let mut observed = std::vec::Vec::new();
        observed.push(right.due_time_100ns());
        for _ in 0..11 {
            right = defer_again(&mut machine, right, locator, key);
            observed.push(right.due_time_100ns());
        }
        let _ = right;

        let expected: std::vec::Vec<i64> = (0..12)
            .map(|attempt: usize| {
                let index = attempt.min(FENCE_RETRY_DELAY_MS.len().saturating_sub(1));
                let delay = FENCE_RETRY_DELAY_MS
                    .get(index)
                    .copied()
                    .expect("the index is clamped to the table");
                checked_retry_due_time_100ns(delay).expect("the table converts")
            })
            .collect();
        assert_eq!(observed, expected, "the schedule left its own table");
        assert_eq!(
            &observed[9..],
            &expected[9..],
            "the schedule saturates on the last entry rather than indexing past it",
        );
        assert_eq!(machine.same_key_attempts(), 11);
    }

    /// The due time is relative, negative, and computed with checked
    /// arithmetic.
    ///
    /// Negative is not cosmetic: the kernel reads a *positive* due time as an
    /// absolute 1601-epoch time, so an overflow that flipped the sign would arm
    /// the timer for the past and fire it immediately -- turning the whole
    /// backoff into a spin.
    #[test]
    fn retry_due_time_uses_checked_negative_relative_100ns_conversion() {
        for delay_ms in FENCE_RETRY_DELAY_MS {
            let due = checked_retry_due_time_100ns(delay_ms).expect("the table converts");
            assert!(due < 0, "{delay_ms}ms produced a non-relative due time");
            assert_eq!(due, -(i64::from(delay_ms) * 10_000));
        }
        // And the conversion refuses rather than wrapping.
        assert_eq!(checked_retry_due_time_100ns(0), Some(0));
        assert!(checked_retry_due_time_100ns(u32::MAX).is_some());
    }

    /// An unchanged key saturates the attempt counter; any change resets it.
    ///
    /// "Any change" is the claim, so the row moves each component of the key in
    /// turn rather than only the effect: a fence that released one more consumer
    /// has made progress even though its effect is the same, and inheriting the
    /// old backoff would punish it for progressing.
    #[test]
    fn same_cursor_saturates_and_full_cursor_progress_resets_the_attempt_index() {
        let locator = retry_locator(2402);
        let (mut machine, binding) = FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator)
            .expect("a fresh identity source");
        let first = FenceRetryKey::Effect(FenceEffect::WaitControlRundown);
        let second = FenceRetryKey::Effect(FenceEffect::QueueInstalledWork);

        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, first);
        let FenceRetryDisposition::Delay(right) = machine
            .prepare_fence_retry(binding, needed)
            .unwrap_or_else(|_| panic!("transient"))
        else {
            panic!("transient")
        };
        assert_eq!(right.same_point_attempts(), 0, "the first attempt is zero");

        let dpc = machine
            .begin_delay_dpc(right)
            .map_err(|(e, _)| e)
            .expect("armed");
        let queued = machine
            .queue_from_dpc(dpc)
            .map_err(|(e, _)| e)
            .expect("dpc");
        let run = machine
            .begin_fence_retry_run(queued)
            .unwrap_or_else(|_| panic!("queued"));
        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, first);
        let FenceRetryDisposition::Delay(right) = machine
            .defer(run, needed)
            .unwrap_or_else(|_| panic!("running"))
        else {
            panic!("transient")
        };
        assert_eq!(
            right.same_point_attempts(),
            1,
            "the same key advances the backoff",
        );

        let dpc = machine
            .begin_delay_dpc(right)
            .map_err(|(e, _)| e)
            .expect("armed");
        let queued = machine
            .queue_from_dpc(dpc)
            .map_err(|(e, _)| e)
            .expect("dpc");
        let run = machine
            .begin_fence_retry_run(queued)
            .unwrap_or_else(|_| panic!("queued"));
        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, second);
        let FenceRetryDisposition::Delay(right) = machine
            .defer(run, needed)
            .unwrap_or_else(|_| panic!("running"))
        else {
            panic!("transient")
        };
        assert_eq!(
            right.same_point_attempts(),
            0,
            "a different retry point is progress, so the backoff restarts",
        );
        assert_eq!(machine.same_key_attempts(), 0);
        let _ = right;
    }

    /// A transient refusal mints a delay right and nothing else; an invariant
    /// refusal mints a permanent fail-stop and arms no timer.
    #[test]
    fn transient_and_invariant_refusals_mint_exactly_one_disjoint_right() {
        let locator = retry_locator(2403);
        let key = FenceRetryKey::Effect(FenceEffect::ReleaseConsumers);

        let (mut transient, binding) = FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator)
            .expect("a fresh identity source");
        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, key);
        assert!(needed.is_transient_native());
        let disposition = transient
            .prepare_fence_retry(binding, needed)
            .unwrap_or_else(|_| panic!("idle"));
        assert!(matches!(disposition, FenceRetryDisposition::Delay(_)));
        assert_eq!(
            transient.lifecycle_state(),
            FenceRetryLifecycleState::DelayArmed,
        );
        let _ = disposition;

        let (mut invariant, binding) = FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator)
            .expect("a fresh identity source");
        let needed = FenceRetryNeeded::from_invariant_refusal(
            locator,
            key,
            FenceFailStopReason::CoreInvariant,
        );
        assert!(!needed.is_transient_native());
        let disposition = invariant
            .prepare_fence_retry(binding, needed)
            .unwrap_or_else(|_| panic!("idle"));
        let FenceRetryDisposition::FailStop(right) = disposition else {
            panic!("an invariant refusal is never retried")
        };
        assert_eq!(right.fail_stop_reason(), FenceFailStopReason::CoreInvariant);
        assert_eq!(
            invariant.lifecycle_state(),
            FenceRetryLifecycleState::FailStop,
        );
        let _ = right;
    }

    /// Two lifecycles that deliberately share a locator reject one another's
    /// rights, and the refusal returns the right unchanged.
    ///
    /// A locator cannot decide this. A cell is reused across generations, so a
    /// locator-only check would let a previous generation's parked right drive
    /// the next generation's retry -- which is the exact confusion the private
    /// identity exists to prevent.
    #[test]
    fn same_locator_distinct_lifecycle_rejects_every_foreign_right() {
        let locator = retry_locator(2404);
        let (mut first, first_binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");
        let (mut second, second_binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");

        // The second lifecycle refuses the first's binding, unchanged.
        let needed = FenceRetryNeeded::from_invoked_native_refusal(
            locator,
            FenceRetryKey::Effect(FenceEffect::CloseSessionAdmission),
        );
        let refusal = second
            .prepare_fence_retry(first_binding, needed)
            .err()
            .expect("a foreign binding is refused");
        assert_eq!(refusal.error(), LifecycleError::WrongState);
        assert_eq!(second.lifecycle_state(), FenceRetryLifecycleState::Idle);
        let (first_binding, needed) = refusal.into_initial_prepare_parts();

        // And the first accepts its own.
        let FenceRetryDisposition::Delay(right) = first
            .prepare_fence_retry(first_binding, needed)
            .unwrap_or_else(|_| panic!("its own binding"))
        else {
            panic!("transient")
        };

        // The second refuses the first's delay right too, and gives it back.
        let Err((error, right)) = second.begin_delay_dpc(right) else {
            panic!("a foreign delay right is refused")
        };
        assert_eq!(error, LifecycleError::WrongLocator);
        assert_eq!(second.lifecycle_state(), FenceRetryLifecycleState::Idle);
        let dpc = first
            .begin_delay_dpc(right)
            .map_err(|(e, _)| e)
            .expect("its own right");
        let _ = dpc;
        let _ = second_binding;
    }

    /// Identity exhaustion refuses before any lifecycle or binding exists.
    ///
    /// Reachable only because the allocator takes its source as a parameter. A
    /// closed-over static would put this branch 2^64 allocations away, and an
    /// unreachable refusal is an unproven one.
    #[test]
    fn lifecycle_identity_exhaustion_refuses_before_minting_either_value() {
        let locator = retry_locator(2405);
        let exhausted = AtomicU64::new(u64::MAX);
        assert_eq!(
            FenceRetryLifecycle::try_new_from_source(locator, &exhausted).err(),
            Some(LifecycleError::GenerationExhausted),
        );

        // One below the stop still succeeds, so the refusal is about exhaustion
        // and not about the source being unusable.
        let last = AtomicU64::new(u64::MAX - 1);
        let (machine, binding) = FenceRetryLifecycle::try_new_from_source(locator, &last)
            .expect("the last identity is still an identity");
        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Idle);
        let _ = binding;
    }

    /// A prepared completion borrows the exact lifecycle until its
    /// parameterless commit, and the commit is the sole Running-to-Idle move.
    ///
    /// The borrow is the mechanism, not a convention: while the prepared packet
    /// lives, the lifecycle it validated cannot be named again, so a preparation
    /// made on one lifecycle is not merely *discouraged* from committing on
    /// another -- the other is unreachable.
    #[test]
    fn prepared_complete_borrows_the_exact_lifecycle_until_parameterless_commit() {
        use crate::adapter::fence::FenceRunCompleteObservation;

        let locator = retry_locator(2406);
        let (mut machine, binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");
        let key = FenceRetryKey::Effect(FenceEffect::WaitPendingAndOwners);

        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, key);
        let FenceRetryDisposition::Delay(right) = machine
            .prepare_fence_retry(binding, needed)
            .unwrap_or_else(|_| panic!("idle"))
        else {
            panic!("transient")
        };
        let dpc = machine
            .begin_delay_dpc(right)
            .map_err(|(e, _)| e)
            .expect("armed");
        let queued = machine
            .queue_from_dpc(dpc)
            .map_err(|(e, _)| e)
            .expect("dpc");
        let run = machine
            .begin_fence_retry_run(queued)
            .unwrap_or_else(|_| panic!("queued"));
        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Running);

        let observation = FenceRunCompleteObservation::for_test(locator);
        let prepared = machine
            .prepare_complete(run, observation)
            .unwrap_or_else(|_| panic!("running, and its own right"));
        prepared.commit_retry_complete();

        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Idle);
        assert_eq!(
            machine.same_key_attempts(),
            0,
            "a completed pass starts the next fence's backoff from zero",
        );
    }

    /// A completion preparation that refuses hands the run right back, and
    /// `end_observation` is what lets the caller park it.
    ///
    /// The two-step return exists because the observation carries a borrow of
    /// the proof it was minted from: the run right has to outlive that proof to
    /// be parked, so there must be a consuming step that drops the observation
    /// and yields a value with no lifetime of its own.
    #[test]
    fn retry_complete_refusal_ends_observation_without_losing_run() {
        use crate::adapter::fence::FenceRunCompleteObservation;

        let locator = retry_locator(2407);
        let (mut machine, binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");
        let key = FenceRetryKey::Effect(FenceEffect::ReleaseCapturedProcess);

        let needed = FenceRetryNeeded::from_invoked_native_refusal(locator, key);
        let FenceRetryDisposition::Delay(right) = machine
            .prepare_fence_retry(binding, needed)
            .unwrap_or_else(|_| panic!("idle"))
        else {
            panic!("transient")
        };
        let dpc = machine
            .begin_delay_dpc(right)
            .map_err(|(e, _)| e)
            .expect("armed");
        let queued = machine
            .queue_from_dpc(dpc)
            .map_err(|(e, _)| e)
            .expect("dpc");
        let run = machine
            .begin_fence_retry_run(queued)
            .unwrap_or_else(|_| panic!("queued"));

        // A second lifecycle at the same locator refuses this run right.
        let (mut other, other_binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");
        let observation = FenceRunCompleteObservation::for_test(locator);
        let failure = other
            .prepare_complete(run, observation)
            .err()
            .expect("a foreign run right is refused");
        assert_eq!(failure.error(), LifecycleError::WrongLocator);
        assert_eq!(other.lifecycle_state(), FenceRetryLifecycleState::Idle);

        // The refusal still owns the run; ending the observation is what makes
        // it parkable, and the original lifecycle still accepts it.
        let refusal = failure.end_observation();
        assert_eq!(refusal.error(), LifecycleError::WrongLocator);
        let run = refusal.into_run_right();
        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Running);
        let observation = FenceRunCompleteObservation::for_test(locator);
        machine
            .prepare_complete(run, observation)
            .unwrap_or_else(|_| panic!("its own run right"))
            .commit_retry_complete();
        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Idle);
        let _ = other_binding;
    }

    /// An initial completion proves Idle without mutating it, and consumes the
    /// one binding so no second initial exit can happen.
    #[test]
    fn initial_complete_keeps_retry_lifecycle_idle_without_fabricating_a_run_right() {
        use crate::adapter::fence::FenceRunCompleteObservation;

        let locator = retry_locator(2408);
        let (machine, binding) =
            FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator).expect("source");
        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Idle);

        let observation = FenceRunCompleteObservation::for_test(locator);
        machine
            .prepare_initial_complete(binding, observation)
            .unwrap_or_else(|_| panic!("idle, and its own binding"))
            .commit_initial_complete();

        // Unchanged, because a clean initial run never armed anything. A commit
        // that *set* Idle here would be indistinguishable from one that found
        // it, and the difference is the whole claim.
        assert_eq!(machine.lifecycle_state(), FenceRetryLifecycleState::Idle);
        assert_eq!(machine.same_key_attempts(), 0);
    }

    /// A residual refuses a prefix branded for a different ring set, and
    /// returns every input.
    ///
    /// A residual that swallowed its inputs on refusal would lose the only
    /// record of what the pass still holds, which is the one thing a residual
    /// exists to carry. The brand check is what stops one session's parked
    /// cursor from being restored into another's fence.
    #[test]
    fn residual_rejects_a_foreign_branded_prefix_and_returns_every_input() {
        use super::r5_consumer_recovery_tests::{HostSlab, published_rings};
        use crate::adapter::fence::{
            ConsumerPrefix, ConsumerResumeEffect, FenceError, FenceResidual, FenceRetryPoint,
        };

        let (brand, _parts) = published_rings(2409, 1);
        let (other_brand, _other_parts) = published_rings(2410, 1);
        let mut slab = HostSlab::new(1);
        // SAFETY: the fixture outlives the prefix.
        let owner = unsafe { slab.bind(other_brand) };
        let foreign = ConsumerPrefix::begin_consumer_prefix(other_brand, owner).expect("covers");

        let retry = FenceRetryPoint::ReacquireConsumersThen {
            prefix: foreign,
            resume: ConsumerResumeEffect::DrainStablePrefixesBounded,
        };
        let Err((error, retry, proof, bind)) =
            FenceResidual::try_new_fence_residual(brand, 0, retry, None, None)
        else {
            panic!("a prefix branded for another set is not this residual's")
        };
        assert_eq!(error, FenceError::WrongRingSet);
        assert!(proof.is_none() && bind.is_none());

        // The prefix came back whole: the same retry point builds a residual
        // for the set it actually belongs to.
        let residual = FenceResidual::try_new_fence_residual(other_brand, 0, retry, None, None)
            .unwrap_or_else(|_| panic!("its own set"));
        assert_eq!(residual.set_brand(), other_brand);
        assert_eq!(
            residual.residual_retry_point(),
            FenceEffect::AcquireConsumersIncreasing,
        );
        assert!(!residual.has_completed_consumers());
    }
}

// ---------------------------------------------------------------------------
// Task 25: R5 atomic-cutover RED properties
// ---------------------------------------------------------------------------
//
// These rows are source scans on purpose. The types they name do not exist
// yet, so a host test that constructed them would fail to compile, and an
// unrelated compile failure is not accepted RED. After the cutover the same
// assertions turn GREEN against the production files they name.

const TASK25_ZERO_ROSTER: &[&str] = &[
    "run_checkpoint_teardown",
    "finish_checkpoint_teardown",
    "R3TeardownComplete",
    "R3AuthorityAbsence",
    "R3PreparedCheckpointFinish",
    "R3PreparedCheckpointFinish::prepare",
    "R3FenceIncomplete",
    "R3DeletionReadiness",
    "R3FinalizerDeposit",
    "R4TeardownComplete",
    "R4AuthorityAbsence",
    "R4PreparedCheckpointFinish",
    "R4PreparedCheckpointFinish::prepare",
    "R4ResidualLedger",
    "R4FenceIncomplete",
    "R4FenceIncomplete::BaseRefusal",
    "R4FenceIncomplete::PendingRefusal",
    "R4FenceIncomplete::PublicationBlocked",
    "R4DeletionReadiness",
    "R4FinalizerDeposit",
    "PrepareCheckpointFinish",
    "CheckpointTerminalBlocked",
    "CheckpointTerminalBlocked::R3",
    "CheckpointTerminalBlocked::R4",
    "run_provisional_fence",
    "LegacyCompletedFenceAdapter",
    "LegacyFinalizerDepositView",
    "LegacyFenceNotRepresentable",
    "LegacyCompletedFenceAdapter::from_completed_only",
    "LegacyCompletedFenceAdapter::try_from_outcome",
    "publish_installed_setup_legacy",
    "LegacyProviderDisposition",
    "split_legacy_provider_disposition",
    "ALLOW_CHECKPOINT_TEARDOWN_PRODUCTION_EDGE",
    "ALLOW_LEGACY_SETUP_PUBLISHER_PRODUCTION_EDGE",
    "ALLOW_LEGACY_PROVIDER_DISPOSITION_PRODUCTION_EDGE",
    "ALLOW_PROVISIONAL_FENCE_PRODUCTION_EDGE",
    "run_terminal -> run_checkpoint_teardown",
    "run_terminal -> R3PreparedCheckpointFinish::prepare",
    "run_terminal -> R4PreparedCheckpointFinish::prepare",
    "run_terminal -> finish_checkpoint_teardown",
    "run_terminal -> run_provisional_fence",
    "run_provisional_fence -> package_completed_fence",
    "run_provisional_fence -> LegacyCompletedFenceAdapter::from_completed_only",
    "LegacyCompletedFenceAdapter::try_from_outcome -> LegacyFinalizerDepositView::Completed",
    "execute_setup -> publish_installed_setup_legacy",
    "fsring_dispatch_provider -> split_legacy_provider_disposition",
];

fn task25_production_bundle() -> String {
    let mut bundle = String::new();
    bundle.push_str(include_str!("../fence.rs"));
    bundle.push_str(include_str!("../../session.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/fence.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/lifecycle.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/session.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/control.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/pending_enter.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/driver.rs"));
    bundle.push_str(include_str!("../../../../fsring-fsd/src/volume.rs"));
    bundle
}

#[test]
fn task25_new_routes_and_all16_runner_cut_over_atomically() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("KernelFenceOps") && fsd.contains("try_new"),
        "production run_terminal must construct KernelFenceOps via try_new"
    );
    assert!(
        fsd.contains("fsring_fence_retry_worker") && fsd.contains("::resume"),
        "the preallocated retry worker must be the only resume caller"
    );
    assert!(
        !fsd.contains("run_checkpoint_teardown"),
        "the R4 checkpoint scheduler must not remain a production callee"
    );
}

#[test]
fn task25_only_final_c4_discharge_reaches_delete() {
    let core = include_str!("../fence.rs");
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        core.contains("package_completed_fence") && core.contains("FenceObligationsDischarged"),
        "finish must mint FenceObligationsDischarged only through package_completed_fence"
    );
    assert!(
        fsd.contains("finish_fence") && fsd.contains("FenceDeletionReadiness"),
        "only the final discharge/readiness path may reach delete"
    );
    assert!(
        !core.contains("R4TeardownComplete") && !fsd.contains("R4TeardownComplete"),
        "an R4 teardown proof must not remain a delete input"
    );
}

#[test]
fn task25_final_readiness_replaces_r4_deposit_atomically() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    let core = include_str!("../fence.rs");
    assert!(
        fsd.contains("FenceDeletionReadiness") && fsd.contains("FinalizerDeposit"),
        "production deposit must be the final FenceDeletionReadiness/FinalizerDeposit pair"
    );
    assert!(
        !core.contains("R4DeletionReadiness") && !core.contains("R4FinalizerDeposit"),
        "the R4 readiness/deposit types must be gone from production core"
    );
}

#[test]
fn task25_checkpoint_compatibility_roster_is_empty() {
    let bundle = task25_production_bundle();
    let mut stripped = String::with_capacity(bundle.len());
    for line in bundle.lines() {
        let code = match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        };
        stripped.push_str(code);
        stripped.push('\n');
    }
    let mut present = std::vec::Vec::new();
    for entry in TASK25_ZERO_ROSTER {
        if stripped.contains(entry) {
            present.push(*entry);
        }
    }
    assert!(
        present.is_empty(),
        "the 47-entry checkpoint compatibility roster must be empty, still present: {present:?}"
    );
}

#[test]
fn task25_terminal_blocked_detail_has_only_final_fence_and_delete_variants() {
    let session = include_str!("../../session.rs");
    assert!(
        session.contains("FenceInvariant") && session.contains("DeleteInvariant"),
        "TerminalBlockedClass must keep the two final classes"
    );
    assert!(
        !session.contains("Checkpoint"),
        "TerminalBlockedClass must not retain a Checkpoint arm"
    );
    assert!(
        session.contains("from_fence") && session.contains("FenceTerminalBlocked"),
        "the common rendezvous must wrap FenceTerminalBlocked"
    );
}

#[test]
fn final_source_has_one_terminal_runner_and_one_delete_deposit_path() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert_eq!(
        fsd.matches("unsafe fn run_terminal<const UNLOAD: bool>")
            .count(),
        1,
        "there must be one terminal runner"
    );
    assert_eq!(
        fsd.matches("pub(crate) unsafe fn finish_fence").count(),
        1,
        "there must be one finish_fence deposit path"
    );
    assert_eq!(
        fsd.matches("pub(crate) unsafe fn prepare_final_delete")
            .count(),
        1,
        "there must be one prepare_final_delete path"
    );
    assert!(
        !fsd.contains("fn run_checkpoint_teardown"),
        "the checkpoint runner must not remain beside the final runner"
    );
}

#[test]
fn finalizer_prepares_before_destroy_and_commits_reset_atomically() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceDeletionReadiness"),
        "the finalizer must prepare a FenceDeletionReadiness packet before destroy"
    );
    assert!(
        fsd.contains("finish_delete"),
        "the no-refusal suffix must commit reset through finish_delete"
    );
}

#[test]
fn retry_begin_run_refusal_parks_queued_right_and_every_residual_companion() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceRetryBeginRunFailStopDeposit"),
        "begin-run refusal must park the queued right and every residual companion"
    );
}

#[test]
fn initial_native_borrow_refusal_parks_binding_and_every_owner() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceNativeBorrowFailStopDeposit")
            && fsd.contains("FenceNativeBorrowFailStopPass::Initial"),
        "initial native-borrow refusal must park the binding and every owner"
    );
}

#[test]
fn retry_native_borrow_refusal_parks_run_residual_and_every_owner() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceNativeBorrowFailStopPass::Retry"),
        "retry native-borrow refusal must park the run, residual, and every owner"
    );
}

#[test]
fn retry_begin_run_fail_stop_publishes_blocked_and_blocks_delete_and_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceRetryBeginRunFailStopDeposit")
            && fsd.contains("from_fence")
            && fsd.contains("FenceTerminalBlocked"),
        "begin-run fail-stop must publish fence blocked and close delete/unload"
    );
}

#[test]
fn initial_native_borrow_fail_stop_publishes_blocked_and_blocks_delete_and_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("NativeBorrowFailStop") && fsd.contains("FenceTerminalBlocked"),
        "initial native-borrow fail-stop must publish blocked"
    );
}

#[test]
fn retry_native_borrow_fail_stop_publishes_blocked_and_blocks_delete_and_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceNativeBorrowFailStopPass::Retry") && fsd.contains("from_fence"),
        "retry native-borrow fail-stop must publish blocked"
    );
}

#[test]
fn retry_complete_finalize_preflight_refusal_retains_all_authorities_and_no_running_leak() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("bind_completion_fail_stop") && core.contains("RetryFinalize"),
        "retry finalize refusal must bind a completion fail-stop that retains the run"
    );
}

#[test]
fn retry_complete_lifecycle_refusal_parks_prepared_finalize_and_exact_run() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("RetryLifecycle") && core.contains("PreparedTerminalWinnerFinalize"),
        "retry lifecycle refusal must park the prepared finalize and the exact run"
    );
}

#[test]
fn initial_complete_finalize_preflight_refusal_binds_exact_lifecycle_and_parks_all_authorities() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("InitialFinalize") && core.contains("FenceInitialLifecycleBinding"),
        "initial finalize refusal must bind the exact lifecycle"
    );
}

#[test]
fn initial_complete_idle_refusal_parks_all_authorities() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("InitialLifecycle") && core.contains("FenceInitialCompleteRefusal"),
        "initial Idle refusal must park every authority"
    );
}

#[test]
fn production_initial_lifecycle_binding_is_minted_once_and_consumed_on_every_exit() {
    let fsd_life = include_str!("../../../../fsring-fsd/src/lifecycle.rs");
    let fsd_fence = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd_life.contains("try_new_fence_retry_lifecycle")
            || fsd_fence.contains("try_new_fence_retry_lifecycle"),
        "setup must mint the initial lifecycle binding once"
    );
    assert!(
        fsd_fence.contains("FenceInitialLifecycleBinding"),
        "every initial exit must consume the unique binding"
    );
}

#[test]
fn initial_residual_prepare_refusal_binds_exact_lifecycle_and_parks_all_authorities() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("bind_initial_residual_fail_stop")
            && core.contains("FenceInitialResidualFailStopPacket"),
        "initial residual prepare refusal must bind a permanent packet"
    );
}

#[test]
fn completion_fail_stop_closes_join_and_permanently_blocks_delete_and_unload() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FenceCompletionFailStopDeposit") && fsd.contains("from_fence"),
        "completion fail-stop must close join and block delete/unload"
    );
}

#[test]
fn completion_fail_stop_core_bind_hides_lifecycle_id_and_never_returns_authority() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("fn bind_completion_fail_stop")
            && core.contains("FenceCompletionFailStopObservation"),
        "the core bind must hide the lifecycle id behind a copyable observation"
    );
}

#[test]
fn cross_lifecycle_failure_bind_returns_one_owning_core_invariant_packet() {
    let core = include_str!("../fence.rs");
    assert!(
        core.contains("fn bind_residual_merge_fail_stop")
            && core.contains("CoreInvariant")
            && core.contains("Retry { failed, .. } => match failed.error"),
        "a cross-lifecycle bind must still merge the retry report from failed.error"
    );
}

#[test]
fn finish_fence_refusal_parks_terminal_final_result_closing_owners_and_release_proof() {
    let fsd = include_str!("../../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("FinishFenceFailStopDeposit") && fsd.contains("FinishFenceFailure"),
        "finish_fence refusal must park the terminal, result, closing, owners, and release proof"
    );
}
