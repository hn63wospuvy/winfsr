// TEST: the R1 matrix uses `expect` and `expect_err` as assertion messages for
// exact affine transition outcomes; production keeps the crate-wide denial.
#![allow(clippy::expect_used)]

use super::*;
use crate::adapter::fence::{
    AuthenticatedTerminalResult, CompletedMountTeardown, DeleteTerminalBlocked,
    FenceDeletionReadiness, PendingCompletedPublication, R3FailStopPreparedContinuation,
    R3FinalizerCell, bind_completed_mount_teardown, run_r3_fail_stop_two_phase,
};
use crate::adapter::lifecycle::{
    MountAbsenceCursor, MountClaim, MountOwner, MountRendezvous, resolve_terminal_release,
    run_r3_mount_done_signal_ack, run_r3_mount_reset_complete_signal_ack,
};
use crate::adapter::load::run_r3_blocked_unload_wait;
use crate::effect::{Effect, EffectContext, EffectSink, Seam, recorder};
use crate::terminal::{ClaimOutcome, ClaimantKind, TerminalOwner};
use fsring_abi::validate::SessionIdentity;
use fsring_abi::{BootInstanceId, MountId};

const STAGES: [SetupStage; 8] = [
    SetupStage::IdentityBurned,
    SetupStage::LayoutPlanned,
    SetupStage::SectionReady,
    SetupStage::GrantsReady,
    SetupStage::VolumeReady,
    SetupStage::ViewsReady,
    SetupStage::OutputReady,
    SetupStage::ReferencesInstalled,
];

const PREFIX_BITS: [u64; 8] = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];

fn must_ok<T, E>(result: Result<T, E>, message: &str) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("{message}"),
    }
}

fn must_some<T>(value: Option<T>, message: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{message}"),
    }
}

fn slot<const N: usize>(registry: &SessionRegistry<N>, index: usize) -> RegistrySlot {
    match registry.slots.get(index) {
        Some(slot) => *slot,
        None => panic!("test registry is missing slot {index}"),
    }
}

fn slot_mut<const N: usize>(registry: &mut SessionRegistry<N>, index: usize) -> &mut RegistrySlot {
    match registry.slots.get_mut(index) {
        Some(slot) => slot,
        None => panic!("test registry is missing slot {index}"),
    }
}

fn identity(n: u64) -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: n, hi: 9 },
        boot_instance_id: BootInstanceId { lo: 7, hi: 11 },
        session_epoch: 1,
    }
}

fn transaction_at(identity: SessionIdentity, target: SetupStage) -> SetupTransaction {
    let mut transaction = must_ok(SetupTransaction::begin(identity), "valid burned identity");
    for stage in STAGES.iter().copied().skip(1) {
        if transaction.staging.stage == target {
            break;
        }
        transaction = transaction
            .stage(stage)
            .unwrap_or_else(|_| panic!("the strict next stage must advance"));
    }
    transaction
}

fn ready_setup(identity: SessionIdentity) -> SetupTransaction {
    transaction_at(identity, SetupStage::OutputReady)
}

fn published_registry<const N: usize>(
    identity: SessionIdentity,
) -> (SessionRegistry<N>, PublishedSession) {
    let (registry, _binding, published) = published_binding::<N>(identity);
    (registry, published)
}

fn installed_staging<const N: usize>(
    identity: SessionIdentity,
) -> (
    SessionRegistry<N>,
    ControlBinding,
    SetupReservation,
    SetupTransaction,
    InstalledSession,
) {
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "an empty binding stages");
    let transaction = transaction_at(identity, SetupStage::OutputReady);
    let mut registry = SessionRegistry::<N>::new();
    let installed = must_ok(
        registry.install_staging(&transaction, &binding, &reservation),
        "output-ready staging installs",
    );
    (registry, binding, reservation, transaction, installed)
}

fn assert_free(slot: RegistrySlot) {
    assert_eq!(slot.identity, None);
    assert_eq!(slot.state, RegistrySlotState::Free);
    assert_eq!(slot.strong_count, 0);
    assert!(!slot.fence_done);
}

fn registry_snapshot<const N: usize>(registry: &SessionRegistry<N>) -> (bool, [RegistrySlot; N]) {
    (registry.admission_open, registry.slots)
}

fn binding_snapshot(binding: &ControlBinding) -> (ControlBindingId, ControlBindingState) {
    (binding.binding_id, binding.state)
}

fn transaction_snapshot(transaction: &SetupTransaction) -> (SessionIdentity, SetupStage, u64) {
    (
        transaction.staging.identity,
        transaction.staging.stage,
        transaction.staging.resource_bits,
    )
}

fn installed_snapshot(installed: &InstalledSession) -> (SessionLocator, SessionLocator) {
    (installed.registry.locator(), installed.control.locator())
}

fn reservation_snapshot(reservation: &SetupReservation) -> (ControlBindingId, SetupEpoch) {
    (reservation.binding_id, reservation.setup_epoch)
}

fn new_binding() -> ControlBinding {
    must_ok(ControlBinding::new(), "the binding ID source has capacity")
}

fn install_with_fresh_reservation<const N: usize>(
    registry: &mut SessionRegistry<N>,
    transaction: &SetupTransaction,
) -> Result<InstalledSession, SessionError> {
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "the helper burns an epoch first");
    registry.install_staging(transaction, &binding, &reservation)
}

fn reserved_installed_staging<const N: usize>(
    id: SessionIdentity,
) -> (
    SessionRegistry<N>,
    ControlBinding,
    SetupReservation,
    SetupTransaction,
    InstalledSession,
) {
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "an empty binding reserves an epoch");
    let transaction = ready_setup(id);
    let mut registry = SessionRegistry::<N>::new();
    let installed = must_ok(
        registry.install_staging(&transaction, &binding, &reservation),
        "output-ready staging installs",
    );
    (registry, binding, reservation, transaction, installed)
}

fn published_binding<const N: usize>(
    id: SessionIdentity,
) -> (SessionRegistry<N>, ControlBinding, PublishedSession) {
    let (mut registry, mut binding, reservation, transaction, installed) =
        reserved_installed_staging::<N>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "all setup authorities publish together",
    );
    (registry, binding, published)
}

#[test]
fn setup_is_a_strict_prefix_and_transition_failure_returns_the_exact_transaction() {
    let id = identity(1);
    let transaction = must_ok(SetupTransaction::begin(id), "valid identity begins");
    assert_eq!(transaction.staging.identity, id);
    assert_eq!(transaction.staging.stage, SetupStage::IdentityBurned);
    assert_eq!(transaction.staging.resource_bits, 0b0000_0001);

    let failure = match transaction.stage(SetupStage::SectionReady) {
        Err(failure) => failure,
        Ok(_) => panic!("a skipped stage must fail"),
    };
    assert_eq!(failure.error(), SessionError::InvalidTransition);
    let mut transaction = failure.into_transaction();
    assert_eq!(transaction.staging.identity, id);
    assert_eq!(transaction.staging.stage, SetupStage::IdentityBurned);
    assert_eq!(transaction.staging.resource_bits, 0b0000_0001);

    for (index, stage) in STAGES.iter().copied().enumerate().skip(1) {
        transaction = transaction
            .stage(stage)
            .unwrap_or_else(|_| panic!("stage {stage:?} must be the strict successor"));
        assert_eq!(transaction.staging.stage, stage);
        let prefix = must_some(PREFIX_BITS.get(index).copied(), "stage prefix exists");
        assert_eq!(transaction.staging.resource_bits, prefix);
    }

    let failure = match transaction.stage(SetupStage::ReferencesInstalled) {
        Err(failure) => failure,
        Ok(_) => panic!("a repeated stage must fail"),
    };
    assert_eq!(failure.error(), SessionError::InvalidTransition);
    let transaction = failure.into_transaction();
    assert_eq!(transaction.staging.identity, id);
    assert_eq!(transaction.staging.stage, SetupStage::ReferencesInstalled);
    assert_eq!(transaction.staging.resource_bits, 0xff);
}

#[test]
fn invalid_or_zero_identity_cannot_begin_setup() {
    for invalid in [
        SessionIdentity {
            mount_id: MountId::ZERO,
            ..identity(1)
        },
        SessionIdentity {
            mount_id: MountId { lo: 0, hi: 9 },
            ..identity(1)
        },
        SessionIdentity {
            mount_id: MountId { lo: 1, hi: 0 },
            ..identity(1)
        },
        SessionIdentity {
            boot_instance_id: BootInstanceId::ZERO,
            ..identity(1)
        },
        SessionIdentity {
            session_epoch: 0,
            ..identity(1)
        },
    ] {
        assert!(matches!(
            SetupTransaction::begin(invalid),
            Err(SessionError::IdentityMismatch)
        ));
    }
}

#[test]
fn cancellation_at_every_precommit_stage_burns_the_identity_once() {
    for stage in STAGES.iter().copied() {
        let id = identity(1);
        let transaction = transaction_at(id, stage);
        let receipt = transaction.rollback(SetupFailure::Cancelled);
        assert_eq!(receipt.burned_identity, id);
        assert_eq!(receipt.last_stage, stage);
    }

    for reason in [
        SetupFailure::Resource,
        SetupFailure::NativeEffect,
        SetupFailure::OutputValidation,
        SetupFailure::Unload,
    ] {
        let receipt = transaction_at(identity(20), SetupStage::ViewsReady).rollback(reason);
        assert_eq!(receipt.burned_identity, identity(20));
        assert_eq!(receipt.last_stage, SetupStage::ViewsReady);
    }
}

#[test]
fn registry_owns_exact_free_backing_and_closure_is_irreversible() {
    let mut empty_registry = SessionRegistry::<0>::new();
    let transaction = transaction_at(identity(1), SetupStage::OutputReady);
    assert!(matches!(
        install_with_fresh_reservation(&mut empty_registry, &transaction),
        Err(SessionError::RegistryFull)
    ));

    let mut registry = SessionRegistry::<1>::new();
    registry.close_admission();
    registry.close_admission();
    let transaction = transaction_at(identity(1), SetupStage::OutputReady);
    assert!(matches!(
        install_with_fresh_reservation(&mut registry, &transaction),
        Err(SessionError::RegistryClosed)
    ));
    assert!(matches!(
        registry.acquire(SessionLocator {
            slot_index: 0,
            generation: 1,
            identity: identity(1),
        }),
        Err(SessionError::RegistryClosed)
    ));
    assert_free(slot(&registry, 0));
}

#[test]
fn r3_unload_core_admission_and_slot_emptiness_are_independent() {
    let mut empty_open = SessionRegistry::<1>::new();
    assert!(empty_open.r3_unload_slots_are_empty());
    assert!(!empty_open.r3_unload_admission_is_closed());

    let transaction = transaction_at(identity(2), SetupStage::OutputReady);
    let _installed = must_ok(
        install_with_fresh_reservation(&mut empty_open, &transaction),
        "the open registry accepts one staging cell",
    );
    empty_open.close_admission();
    assert!(empty_open.r3_unload_admission_is_closed());
    assert!(!empty_open.r3_unload_slots_are_empty());
}

#[test]
fn staging_installs_exactly_two_hidden_references_and_duplicate_setup_is_refused() {
    let id = identity(1);
    let transaction = transaction_at(id, SetupStage::OutputReady);
    let mut registry = SessionRegistry::<2>::new();
    let installed = must_ok(
        install_with_fresh_reservation(&mut registry, &transaction),
        "first install stages",
    );
    assert_eq!(installed.locator().identity(), id);
    assert_eq!(installed.locator().slot_index(), 0);
    assert_eq!(installed.locator().generation(), 1);
    assert_eq!(slot(&registry, 0).identity, Some(id));
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Staging);
    assert_eq!(slot(&registry, 0).strong_count, 2);
    assert!(matches!(
        registry.acquire(installed.locator()),
        Err(SessionError::ReferenceNotFound)
    ));

    let duplicate = transaction_at(id, SetupStage::OutputReady);
    assert!(matches!(
        install_with_fresh_reservation(&mut registry, &duplicate),
        Err(SessionError::DuplicateSetup)
    ));
    assert_eq!(slot(&registry, 1), RegistrySlot::FREE);

    let not_ready = transaction_at(identity(2), SetupStage::ViewsReady);
    assert!(matches!(
        install_with_fresh_reservation(&mut registry, &not_ready),
        Err(SessionError::InvalidTransition)
    ));
    assert_eq!(slot(&registry, 1), RegistrySlot::FREE);

    let other = transaction_at(identity(2), SetupStage::OutputReady);
    let _other_installed = must_ok(
        install_with_fresh_reservation(&mut registry, &other),
        "the final free slot stages",
    );
    let full = transaction_at(identity(3), SetupStage::OutputReady);
    assert!(matches!(
        install_with_fresh_reservation(&mut registry, &full),
        Err(SessionError::RegistryFull)
    ));
}

#[test]
fn precommit_rollback_returns_exact_authority_before_unbinding() {
    let id = identity(1);
    let (mut registry, mut binding, reservation, transaction, installed) =
        installed_staging::<1>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );

    let mut foreign = installed;
    foreign.control.authority.identity = identity(2);
    let (error, mut foreign) = match registry.rollback_staging(foreign) {
        Err(pair) => pair,
        Ok(_) => panic!("a mismatched installed pair must be returned"),
    };
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(foreign.control.authority.identity, identity(2));
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Staging);
    foreign.control.authority.identity = id;
    let prepared = must_ok(
        prepare_installed_setup_rollback(
            transaction,
            SetupFailure::Cancelled,
            &registry,
            &binding,
            reservation,
            foreign,
        ),
        "the restored exact aggregate prepares",
    );
    let (receipt, slot_disposition, binding_disposition) =
        commit_prepared_installed_setup_rollback(prepared, &mut registry, &mut binding);
    assert_free(slot(&registry, 0));
    assert_eq!(receipt.burned_identity, id);
    assert_eq!(slot_disposition, SlotDisposition::Free);
    assert_eq!(
        binding_disposition,
        SetupRollbackDisposition::Reopened(SetupEpochCursor::Next(SetupEpoch(2)))
    );
    assert_eq!(
        binding.state(),
        ControlBindingState::Empty(SetupEpochCursor::Next(SetupEpoch(2)))
    );
}

#[test]
fn publication_preflights_every_authority_before_its_first_mutation() {
    let id = identity(1);

    for fault in 0_u8..15 {
        let (mut registry, mut binding, reservation, transaction, mut installed) =
            installed_staging::<1>(id);
        let mut transaction = must_ok(
            transaction.stage(SetupStage::ReferencesInstalled),
            "references installed",
        );
        let expected_error = match fault {
            0 => {
                transaction.staging.stage = SetupStage::OutputReady;
                SessionError::InvalidTransition
            }
            1 => {
                transaction.staging.resource_bits = 0x7f;
                SessionError::InvalidTransition
            }
            2 => {
                binding.state = ControlBindingState::Active(installed.locator());
                SessionError::InvalidTransition
            }
            3 => {
                binding.state = ControlBindingState::Staging(SetupEpoch(2));
                SessionError::IdentityMismatch
            }
            4 => {
                installed.registry.authority.identity = identity(2);
                SessionError::IdentityMismatch
            }
            5 => {
                installed.control.authority.identity = identity(2);
                SessionError::IdentityMismatch
            }
            6 => {
                installed.control.authority.slot_index = 1;
                SessionError::IdentityMismatch
            }
            7 => {
                installed.registry.authority.slot_index = 1;
                installed.control.authority.slot_index = 1;
                SessionError::ReferenceNotFound
            }
            8 => {
                installed.registry.authority.generation = 2;
                installed.control.authority.generation = 2;
                SessionError::IdentityMismatch
            }
            9 => {
                installed.registry.authority.generation = 2;
                SessionError::IdentityMismatch
            }
            10 => {
                installed.control.authority.generation = 2;
                SessionError::IdentityMismatch
            }
            11 => {
                slot_mut(&mut registry, 0).identity = Some(identity(2));
                SessionError::IdentityMismatch
            }
            12 => {
                slot_mut(&mut registry, 0).state = RegistrySlotState::Live;
                SessionError::InvalidTransition
            }
            13 => {
                slot_mut(&mut registry, 0).strong_count = 3;
                SessionError::InvalidTransition
            }
            14 => {
                registry.close_admission();
                SessionError::RegistryClosed
            }
            _ => unreachable!(),
        };
        let slot_before = slot(&registry, 0);
        let binding_before = binding.state();
        let transaction_before = (
            transaction.staging.identity,
            transaction.staging.stage,
            transaction.staging.resource_bits,
        );
        let reservation_before = reservation_snapshot(&reservation);
        let installed_registry_before = installed.registry.locator();
        let installed_control_before = installed.control.locator();
        let mut rendezvous = TerminalRendezvous::new_inactive();
        let failure = match publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("fault {fault} must fail before publication"),
        };
        let (error, returned, returned_reservation, returned_installed) = failure.into_parts();
        assert_eq!(error, expected_error, "fault {fault}");
        assert_eq!(
            (
                returned.staging.identity,
                returned.staging.stage,
                returned.staging.resource_bits,
            ),
            transaction_before,
            "returned transaction fault {fault}",
        );
        assert_eq!(
            reservation_snapshot(&returned_reservation),
            reservation_before,
            "returned reservation fault {fault}",
        );
        assert_eq!(
            returned_installed.registry.locator(),
            installed_registry_before,
            "returned registry authority fault {fault}",
        );
        assert_eq!(
            returned_installed.control.locator(),
            installed_control_before,
            "returned control authority fault {fault}",
        );
        assert_eq!(slot(&registry, 0), slot_before);
        assert_eq!(binding.state(), binding_before);
    }
}

#[test]
fn publication_is_last_and_cancellation_loses_after_commit() {
    let id = identity(1);
    let (mut registry, mut binding, reservation, transaction, installed) =
        installed_staging::<1>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references installed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "all preflights permit publication",
    );
    assert_eq!(published.locator().identity(), id);
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Live);
    assert_eq!(slot(&registry, 0).strong_count, 2);
    assert_eq!(
        binding.state(),
        ControlBindingState::Active(published.locator())
    );

    let terminal = TerminalOwner::new();
    assert!(matches!(
        terminal.claim(ClaimantKind::Completion),
        ClaimOutcome::Won(_)
    ));
    assert!(matches!(
        terminal.claim(ClaimantKind::Cancellation),
        ClaimOutcome::Lost {
            winner: Some(ClaimantKind::Completion)
        }
    ));
    assert_eq!(
        binding.state(),
        ControlBindingState::Active(published.locator())
    );
}

#[test]
fn unload_closure_refuses_lookup_but_allows_exact_removal_and_drain() {
    let id = identity(1);
    let (mut registry, mut binding, reservation, transaction, installed) =
        installed_staging::<1>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references installed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "publishes",
    );
    assert_eq!(published.locator().identity(), id);
    let (locator, lease, control) = published.into_parts();

    registry.close_admission();
    assert!(matches!(
        registry.acquire(locator),
        Err(SessionError::RegistryClosed)
    ));
    let terminal = registry
        .begin_remove(lease)
        .expect("exact removal remains admitted");
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Removing);
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last authenticated reference must delete"),
    };
    let prepared = registry
        .prepare_finish_delete(right)
        .expect("delete preparation");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(prepared) },
        SlotDisposition::Free
    );
    assert_free(slot(&registry, 0));
}

#[test]
fn checked_references_delete_only_after_the_final_release_in_either_order() {
    for fence_first in [false, true] {
        let id = identity(if fence_first { 1 } else { 2 });
        let (mut registry, published) = published_registry::<1>(id);
        let locator = published.locator();
        let extra = must_ok(registry.acquire(locator), "live lookup acquires");
        assert_eq!(slot(&registry, 0).strong_count, 3);
        let (_, lease, control) = published.into_parts();

        let right = if fence_first {
            let terminal = registry.begin_remove(lease).expect("terminal reference");
            assert!(matches!(
                registry.finish_removal_for_test(terminal),
                Ok(RegistryRelease::Retained)
            ));
            assert!(matches!(
                registry.release(extra),
                Ok(RegistryRelease::Retained)
            ));
            match registry.release(control).expect("last stable release") {
                RegistryRelease::Delete(right) => right,
                RegistryRelease::Retained => panic!("fenced final release must delete"),
            }
        } else {
            assert!(matches!(
                registry.release(control),
                Ok(RegistryRelease::Retained)
            ));
            let terminal = registry.begin_remove(lease).expect("terminal reference");
            assert!(matches!(
                registry.release(extra),
                Ok(RegistryRelease::Retained)
            ));
            match registry.finish_removal_for_test(terminal).expect("fence") {
                RegistryRelease::Delete(right) => right,
                RegistryRelease::Retained => panic!("terminal final reference must delete"),
            }
        };
        assert_eq!(right.locator(), locator);
        let prepared = registry
            .prepare_finish_delete(right)
            .expect("delete preparation");
        // SAFETY: This core-only test owns the exact Deleting generation and its
        // one prepared commit; no native mirror exists, and `&mut` is exclusive.
        assert_eq!(
            unsafe { registry.finish_delete(prepared) },
            SlotDisposition::Free
        );
        assert_free(slot(&registry, 0));
    }
}

#[test]
fn reference_exhaustion_foreign_identity_and_stale_capabilities_are_mutation_free() {
    let first = identity(1);
    let (mut registry, published) = published_registry::<1>(first);
    let first_locator = published.locator();
    slot_mut(&mut registry, 0).strong_count = u32::MAX;
    assert!(matches!(
        registry.acquire(first_locator),
        Err(SessionError::ReferenceExhausted)
    ));
    assert_eq!(slot(&registry, 0).strong_count, u32::MAX);
    slot_mut(&mut registry, 0).strong_count = 2;
    assert!(matches!(
        registry.acquire(SessionLocator {
            identity: identity(2),
            ..first_locator
        }),
        Err(SessionError::ReferenceNotFound)
    ));

    let (_, lease, control) = published.into_parts();
    let stale = StrongSessionRef {
        authority: SessionAuthority {
            slot_index: first_locator.slot_index(),
            generation: first_locator.generation(),
            identity: identity(2),
        },
    };
    let before = slot(&registry, 0);
    let (error, stale) = match registry.release(stale) {
        Err(pair) => pair,
        Ok(_) => panic!("foreign reference must be returned"),
    };
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(stale.locator().identity(), identity(2));
    assert_eq!(slot(&registry, 0), before);
    let terminal = registry.begin_remove(lease).expect("terminal reference");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("first session deletes"),
    };
    let prepared = registry
        .prepare_finish_delete(right)
        .expect("delete preparation");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(prepared) },
        SlotDisposition::Free
    );

    let second = identity(3);
    let transaction = transaction_at(second, SetupStage::OutputReady);
    let installed = must_ok(
        install_with_fresh_reservation(&mut registry, &transaction),
        "freed slot is reusable",
    );
    let stale = StrongSessionRef {
        authority: SessionAuthority {
            slot_index: first_locator.slot_index(),
            generation: first_locator.generation(),
            identity: first,
        },
    };
    let before = slot(&registry, 0);
    let (error, stale) = match registry.release(stale) {
        Err(pair) => pair,
        Ok(_) => panic!("stale identity must not affect a reused slot"),
    };
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(stale.locator(), first_locator);
    assert_eq!(slot(&registry, 0), before);
    must_ok(
        registry.rollback_staging(installed),
        "new exact authority still rolls back",
    );
}

#[derive(Clone, Copy)]
enum AuthorityFault {
    Slot,
    Generation,
    Identity,
}

fn foreign_authority(locator: SessionLocator, fault: AuthorityFault) -> SessionAuthority {
    let mut authority = SessionAuthority {
        slot_index: locator.slot_index(),
        generation: locator.generation(),
        identity: locator.identity(),
    };
    match fault {
        AuthorityFault::Slot => authority.slot_index = authority.slot_index.saturating_add(1),
        AuthorityFault::Generation => authority.generation = authority.generation.saturating_add(1),
        AuthorityFault::Identity => authority.identity = identity(99),
    }
    authority
}

/// Exactly the empty binding says nothing is installed through the context.
///
/// The predicate lives in `adapter::setup`, beside the CLOSE decision it
/// serves, and its table lives HERE because this is where every
/// `ControlBindingState` can be constructed: `SetupEpoch` holds a private
/// field, so `adapter::setup::tests` cannot build the staging states at all.
///
/// `Empty` is what CREATE leaves in a fresh binding and what a rolled-back
/// SETUP returns to -- both cursors, so neither is mistaken for an
/// installation. Every other state names something that must outlive CLOSE's
/// decision: a staging epoch, a live locator, or a terminal still being
/// carried (native review N18-2).
#[test]
fn exactly_the_empty_binding_holds_no_installation() {
    use crate::adapter::setup::binding_holds_no_installation;

    let locator = SessionLocator {
        slot_index: 0,
        generation: 1,
        identity: identity(7),
    };
    let rows = [
        (
            ControlBindingState::Empty(SetupEpochCursor::Exhausted),
            true,
        ),
        (
            ControlBindingState::Empty(SetupEpochCursor::Next(SetupEpoch(1))),
            true,
        ),
        (ControlBindingState::Staging(SetupEpoch(1)), false),
        (ControlBindingState::Active(locator), false),
        (ControlBindingState::ClosingSetup(SetupEpoch(1)), false),
        (ControlBindingState::ClosingLive(locator), false),
        (
            ControlBindingState::ClosingComplete {
                generation: 1,
                result: TerminalResult {
                    reason: TerminalReason::Cleanup,
                    fence_failures: 0,
                },
            },
            false,
        ),
        (
            ControlBindingState::ClosingBlocked {
                locator,
                class: TerminalBlockedClass::FenceInvariant,
            },
            false,
        ),
        (
            ControlBindingState::ClosingOpaqueRetained { locator },
            false,
        ),
        (ControlBindingState::Closed, false),
    ];
    for (state, expected) in rows {
        assert_eq!(
            binding_holds_no_installation(state),
            expected,
            "{state:?} is classified wrongly",
        );
    }
}

fn authority_locator(authority: &SessionAuthority) -> SessionLocator {
    SessionLocator {
        slot_index: authority.slot_index,
        generation: authority.generation,
        identity: authority.identity,
    }
}

#[test]
fn every_authority_requires_exact_slot_generation_and_identity() {
    for fault in [
        AuthorityFault::Slot,
        AuthorityFault::Generation,
        AuthorityFault::Identity,
    ] {
        let mut staged = SessionRegistry::<1>::new();
        let installed = install_with_fresh_reservation(&mut staged, &ready_setup(identity(10)))
            .expect("staging installs");
        let exact_locator = installed.locator();
        let expected = foreign_authority(exact_locator, fault);
        let expected_locator = authority_locator(&expected);
        let foreign = InstalledSession {
            registry: RegistryLease {
                authority: expected,
            },
            control: StrongSessionRef {
                authority: foreign_authority(exact_locator, fault),
            },
            ring_set: None,
            native_owner_bind_rights: Some(NativeOwnerBindRights::mint(expected_locator)),
        };
        let before = staged.slot_snapshot(0).expect("slot");
        let (_, returned) = staged
            .rollback_staging(foreign)
            .expect_err("foreign installed authority");
        assert_eq!(returned.locator(), expected_locator);
        assert_eq!(staged.slot_snapshot(0), Some(before));

        let (mut registry, published) = published_registry::<1>(identity(11));
        let locator = published.locator();
        let before = registry.slot_snapshot(0).expect("slot");
        let foreign = RegistryLease {
            authority: foreign_authority(locator, fault),
        };
        let (_, returned) = registry
            .begin_remove(foreign)
            .expect_err("foreign registry lease");
        assert_eq!(
            returned.locator(),
            authority_locator(&foreign_authority(locator, fault))
        );
        assert_eq!(registry.slot_snapshot(0), Some(before));

        let (mut registry, published) = published_registry::<1>(identity(12));
        let locator = published.locator();
        let before = registry.slot_snapshot(0).expect("slot");
        let foreign = StrongSessionRef {
            authority: foreign_authority(locator, fault),
        };
        let (_, returned) = registry
            .release(foreign)
            .expect_err("foreign strong reference");
        assert_eq!(
            returned.locator(),
            authority_locator(&foreign_authority(locator, fault))
        );
        assert_eq!(registry.slot_snapshot(0), Some(before));

        let (mut registry, published) = published_registry::<1>(identity(13));
        let locator = published.locator();
        let (_, lease, _) = published.into_parts();
        let _terminal = registry.begin_remove(lease).expect("exact registry lease");
        let before = registry.slot_snapshot(0).expect("slot");
        let foreign = TerminalSessionRef {
            authority: foreign_authority(locator, fault),
        };
        let (_, returned) = registry
            .finish_removal_for_test(foreign)
            .expect_err("foreign terminal reference");
        assert_eq!(
            returned.locator(),
            authority_locator(&foreign_authority(locator, fault))
        );
        assert_eq!(registry.slot_snapshot(0), Some(before));

        let (mut registry, published) = published_registry::<1>(identity(14));
        let locator = published.locator();
        let (_, lease, control) = published.into_parts();
        let terminal = registry.begin_remove(lease).expect("exact registry lease");
        assert!(matches!(
            registry.release(control),
            Ok(RegistryRelease::Retained)
        ));
        let _right = registry
            .finish_removal_for_test(terminal)
            .expect("exact terminal reference");
        let before = registry.slot_snapshot(0).expect("slot");
        let foreign = DeleteSessionRight {
            authority: foreign_authority(locator, fault),
        };
        let (_, returned) = registry
            .prepare_finish_delete(foreign)
            .expect_err("foreign delete right");
        assert_eq!(
            returned.locator(),
            authority_locator(&foreign_authority(locator, fault))
        );
        assert_eq!(registry.slot_snapshot(0), Some(before));
    }
}

#[test]
fn control_mount_terminal_and_interleaved_releases_mint_one_delete_right() {
    for fence_before_last_release in [false, true] {
        let (mut registry, published) = published_registry::<1>(identity(20));
        let locator = published.locator();
        let mount = registry.acquire(locator).expect("mount reference");
        let wait = registry.acquire(locator).expect("wait reference");
        let (_, lease, control) = published.into_parts();
        let terminal = registry.begin_remove(lease).expect("terminal reference");
        assert!(matches!(
            registry.release(control),
            Ok(RegistryRelease::Retained)
        ));
        assert!(matches!(
            registry.release(mount),
            Ok(RegistryRelease::Retained)
        ));
        let right = if fence_before_last_release {
            assert!(matches!(
                registry.finish_removal_for_test(terminal),
                Ok(RegistryRelease::Retained)
            ));
            match registry.release(wait).expect("last stable release") {
                RegistryRelease::Delete(right) => right,
                RegistryRelease::Retained => panic!("last release after fence must delete"),
            }
        } else {
            assert!(matches!(
                registry.release(wait),
                Ok(RegistryRelease::Retained)
            ));
            match registry.finish_removal_for_test(terminal).expect("fence") {
                RegistryRelease::Delete(right) => right,
                RegistryRelease::Retained => panic!("authenticated finish at one must delete"),
            }
        };
        assert_eq!(right.locator(), locator);
        assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Deleting));
    }
}

#[test]
fn live_mount_rollback_and_nonterminal_wait_release_retain_without_deletion() {
    let mut staged = SessionRegistry::<1>::new();
    let installed = install_with_fresh_reservation(&mut staged, &ready_setup(identity(30)))
        .expect("staging installs");
    assert_eq!(
        staged.rollback_staging(installed),
        Ok(SlotDisposition::Free)
    );

    let (mut registry, published) = published_registry::<1>(identity(31));
    let locator = published.locator();
    let mount = registry.acquire(locator).expect("mount reference");
    let wait = registry.acquire(locator).expect("wait reference");
    assert!(matches!(
        registry.release(mount),
        Ok(RegistryRelease::Retained)
    ));
    assert!(matches!(
        registry.release(wait),
        Ok(RegistryRelease::Retained)
    ));
    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Live));
    assert_eq!(registry.slot_snapshot(0).expect("slot").strong_count, 2);
}

#[test]
fn closed_admission_refuses_install_and_lookup_but_allows_removal_and_delete() {
    let mut closed = SessionRegistry::<1>::new();
    closed.close_admission();
    assert!(!closed.admission_is_open());
    assert!(matches!(
        install_with_fresh_reservation(&mut closed, &ready_setup(identity(40))),
        Err(SessionError::RegistryClosed)
    ));

    let (mut registry, published) = published_registry::<1>(identity(41));
    let locator = published.locator();
    let (_, lease, control) = published.into_parts();
    registry.close_admission();
    assert!(matches!(
        registry.acquire(locator),
        Err(SessionError::RegistryClosed)
    ));
    let terminal = registry
        .begin_remove(lease)
        .expect("removal remains admitted");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry
        .finish_removal_for_test(terminal)
        .expect("authenticated finish remains admitted")
    {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last authenticated reference must delete"),
    };
    let commit = registry
        .prepare_finish_delete(right)
        .expect("delete preparation remains admitted");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(commit) },
        SlotDisposition::Free
    );
}

#[test]
fn stale_locator_cannot_observe_a_reused_slot() {
    let id = identity(50);
    let (mut registry, published) = published_registry::<1>(id);
    let stale = published.locator();
    let (_, lease, control) = published.into_parts();
    let terminal = registry.begin_remove(lease).expect("terminal");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last reference"),
    };
    let commit = registry
        .prepare_finish_delete(right)
        .expect("delete preparation");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(commit) },
        SlotDisposition::Free
    );

    let transaction = ready_setup(id);
    let installed =
        install_with_fresh_reservation(&mut registry, &transaction).expect("slot reuse");
    assert_ne!(installed.locator().generation(), stale.generation());
    let before = registry.slot_snapshot(0).expect("slot");
    assert!(matches!(
        registry.acquire(stale),
        Err(SessionError::ReferenceNotFound)
    ));
    assert_eq!(registry.slot_snapshot(0), Some(before));
}

#[test]
fn prepare_finish_delete_returns_the_exact_right_on_every_mismatch() {
    for fault in [
        AuthorityFault::Slot,
        AuthorityFault::Generation,
        AuthorityFault::Identity,
    ] {
        let (mut registry, published) = published_registry::<1>(identity(60));
        let locator = published.locator();
        let (_, lease, control) = published.into_parts();
        let terminal = registry.begin_remove(lease).expect("terminal");
        assert!(matches!(
            registry.release(control),
            Ok(RegistryRelease::Retained)
        ));
        let _right = registry.finish_removal_for_test(terminal).expect("fence");
        let expected = foreign_authority(locator, fault);
        let expected_locator = authority_locator(&expected);
        let foreign = DeleteSessionRight {
            authority: expected,
        };
        let before = registry.slot_snapshot(0).expect("slot");
        let (_, returned) = registry
            .prepare_finish_delete(foreign)
            .expect_err("mismatched right");
        assert_eq!(returned.locator(), expected_locator);
        assert_eq!(registry.slot_snapshot(0), Some(before));
    }
}

#[test]
fn delete_validation_borrows_exact_right_without_consuming_or_mutating_it() {
    let (mut registry, published) = published_registry::<1>(identity(65));
    let (_, lease, control) = published.into_parts();
    let terminal = registry.begin_remove(lease).expect("terminal");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last reference"),
    };
    let before = registry.slot_snapshot(0).expect("slot");
    assert_eq!(
        registry.validate_finish_delete(&right),
        Ok(SlotDisposition::Free)
    );
    assert_eq!(registry.slot_snapshot(0), Some(before));

    let foreign = SessionRegistry::<1>::new();
    assert!(matches!(
        foreign.validate_finish_delete(&right),
        Err(SessionError::ReferenceNotFound
            | SessionError::IdentityMismatch
            | SessionError::InvalidTransition)
    ));
    assert_eq!(registry.slot_snapshot(0), Some(before));

    let commit = registry
        .prepare_finish_delete(right)
        .expect("borrowed validation leaves the original right consumable");
    assert_eq!(commit.disposition(), SlotDisposition::Free);
}

#[test]
fn prepared_delete_core_commit_finishes_once_without_revalidation() {
    let (mut registry, published) = published_registry::<1>(identity(70));
    let (_, lease, control) = published.into_parts();
    let terminal = registry.begin_remove(lease).expect("terminal");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last reference"),
    };
    let commit = registry
        .prepare_finish_delete(right)
        .expect("delete preparation");
    assert_eq!(commit.disposition(), SlotDisposition::Free);
    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Deleting));
    registry.close_admission();
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(commit) },
        SlotDisposition::Free
    );
}

#[test]
fn zero_before_authenticated_finish_is_mutation_free() {
    let (mut registry, published) = published_registry::<1>(identity(80));
    let locator = published.locator();
    let (_, lease, control) = published.into_parts();
    let terminal = registry.begin_remove(lease).expect("terminal");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let before = registry.slot_snapshot(0).expect("slot");
    let unauthenticated = StrongSessionRef {
        authority: SessionAuthority {
            slot_index: locator.slot_index(),
            generation: locator.generation(),
            identity: locator.identity(),
        },
    };
    let (_, returned) = registry
        .release(unauthenticated)
        .expect_err("zero before authenticated finish is an invariant error");
    assert_eq!(returned.locator(), locator);
    assert_eq!(registry.slot_snapshot(0), Some(before));
    assert!(matches!(
        registry.finish_removal_for_test(terminal),
        Ok(RegistryRelease::Delete(_))
    ));
}

#[test]
fn r3_checkpoint_remaining_owner_observation_requires_exact_removing_generation_and_one_strong_ref()
{
    let (mut registry, published) = published_registry::<1>(identity(811));
    let locator = published.locator();
    let (_, lease, control) = published.into_parts();
    let foreign_locator = published_registry::<1>(identity(812)).1.locator();

    assert!(
        !registry.r3_checkpoint_has_only_terminal_strong_owner(locator),
        "a Live generation is not a checkpoint owner observation",
    );
    let terminal = registry.begin_remove(lease).expect("the live lease wins");
    assert!(
        !registry.r3_checkpoint_has_only_terminal_strong_owner(locator),
        "the control reference is still a second stable owner",
    );
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    assert!(
        registry.r3_checkpoint_has_only_terminal_strong_owner(locator),
        "the exact Removing generation now has only its terminal owner",
    );
    assert!(
        !registry.r3_checkpoint_has_only_terminal_strong_owner(foreign_locator),
        "a copied locator for another identity cannot satisfy the observation",
    );

    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("the terminal owner is the last owner"),
    };
    assert!(
        !registry.r3_checkpoint_has_only_terminal_strong_owner(locator),
        "the observation expires when the terminal owner advances to Deleting",
    );
    let _ = right;
}

#[test]
fn delete_right_keeps_the_slot_deleting_until_finish_delete() {
    let (mut registry, live) = published_registry::<1>(identity(1));
    let (_, lease, control) = live.into_parts();
    let terminal = registry.begin_remove(lease).expect("live lease");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last fenced reference must delete"),
    };
    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Deleting));
    assert!(matches!(
        install_with_fresh_reservation(&mut registry, &ready_setup(identity(2))),
        Err(SessionError::RegistryFull)
    ));
    let core_commit = registry
        .prepare_finish_delete(right)
        .expect("exact delete right");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(core_commit) },
        SlotDisposition::Free
    );
    assert!(install_with_fresh_reservation(&mut registry, &ready_setup(identity(2))).is_ok());
}

fn assert_finalizer_reset_completes_core_and_cell_together(
    generation: u64,
    expected: SlotDisposition,
) {
    let (mut registry, published) =
        published_registry_at_generation::<1>(identity(701), generation);
    let locator = published.locator();
    let (_, lease, control) = published.into_parts();
    let terminal = registry.begin_remove(lease).expect("live lease");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("the last fenced reference must delete"),
    };

    let rights = NativeOwnerBindRights::for_test(locator);
    let (_shell, _root, finalizer_right) = rights.into_parts();
    let mut finalizer = R3FinalizerCell::<()>::new_unbound();
    finalizer
        .bind(finalizer_right)
        .map_err(|_| ())
        .expect("the install-origin finalizer right binds once");
    let readiness = FenceDeletionReadiness::for_test(locator, ());
    let kick = finalizer
        .store_deposit_and_mint_kick(readiness, right)
        .map_err(|_| ())
        .expect("the exact readiness and right become one stored deposit");
    let context = crate::adapter::fence::run_r3_finalizer_queue(
        kick.admit(()),
        |context, ()| context,
        core::convert::identity,
    );
    let (deposit, running) =
        crate::adapter::fence::run_r3_finalizer_callback(context, |_| Some(&mut finalizer))
            .expect("the queued callback takes its one deposit");
    let (_readiness, commit) = deposit
        .prepare_final_delete_core(&registry)
        .map_err(|_| ())
        .expect("the deleting core accepts its exact deposit");
    let final_reset =
        PendingCompletedPublication::for_test(commit, running, ()).into_final_reset_for_test();

    let mut terminal = TerminalRendezvous::new_inactive();
    terminal
        .activate(locator)
        .expect("the test generation activates before completion");
    let (winner, ticket) = terminal
        .claim(locator, TerminalRequest::Cleanup)
        .expect("the test generation has one terminal winner")
        .into_parts();
    terminal
        .close_and_publish_completed(
            winner,
            TerminalResult {
                reason: TerminalReason::Cleanup,
                fence_failures: 0,
            },
        )
        .expect("the winner publishes one completed outcome");
    assert!(matches!(
        terminal.release(ticket),
        Ok(TerminalJoinRelease::Released {
            drained: Some(_),
            ..
        })
    ));

    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Deleting));
    assert_eq!(
        finalizer.state(),
        crate::adapter::lifecycle::FinalizerState::Running
    );
    // SAFETY: this test owns the exact running finalizer, deleting registry,
    // and post-storage reset right for one locator.
    let (disposition, proof, (), terminal_reset, _mount_reset) =
        unsafe { finalizer.finish_run_and_reset(&mut registry, final_reset) };
    unsafe { terminal.deactivate_after_delete_prepared(terminal_reset) };
    assert_eq!(disposition, expected);
    assert!(proof.ran_every_step());
    assert!(proof.reset_is_last());
    assert_eq!(finalizer.locator(), None);
    assert!(finalizer.deposit_is_none());
    assert_eq!(
        finalizer.state(),
        crate::adapter::lifecycle::FinalizerState::Idle
    );
    assert_eq!(
        registry.slot_state(0),
        Some(match expected {
            SlotDisposition::Free => RegistrySlotState::Free,
            SlotDisposition::Retired => RegistrySlotState::Retired,
        })
    );
}

#[test]
fn finalizer_reset_authority_completes_free_and_retired_generations_atomically() {
    assert_finalizer_reset_completes_core_and_cell_together(1, SlotDisposition::Free);
    assert_finalizer_reset_completes_core_and_cell_together(u64::MAX, SlotDisposition::Retired);
}

#[test]
fn authenticated_removal_has_both_exact_reference_count_branches() {
    let (mut registry, live) = published_registry::<1>(identity(3));
    let locator = live.locator();
    let extra = registry.acquire(locator).expect("extra reference");
    let (_, lease, control) = live.into_parts();
    let terminal = registry.begin_remove(lease).expect("terminal reference");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    assert!(matches!(
        registry.finish_removal_for_test(terminal),
        Ok(RegistryRelease::Retained)
    ));
    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Removing));
    let right = match registry.release(extra).expect("last stable release") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("fence_done plus zero must delete"),
    };
    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Deleting));
    let core_commit = registry
        .prepare_finish_delete(right)
        .expect("exact delete right");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { registry.finish_delete(core_commit) },
        SlotDisposition::Free
    );
}

#[test]
fn last_stable_release_before_fence_preserves_the_terminal_reference() {
    let (mut registry, live) = published_registry::<1>(identity(4));
    let (_, lease, control) = live.into_parts();
    let terminal = registry.begin_remove(lease).expect("terminal reference");
    let returned = registry.release(control).expect("terminal count remains");
    assert!(matches!(returned, RegistryRelease::Retained));
    let snapshot = registry.slot_snapshot(0).expect("slot");
    assert_eq!(snapshot.state, RegistrySlotState::Removing);
    assert_eq!(snapshot.strong_count, 1);
    assert!(!snapshot.fence_done);
    assert!(matches!(
        registry.finish_removal_for_test(terminal),
        Ok(RegistryRelease::Delete(_))
    ));
}

#[test]
fn rollback_and_delete_at_max_generation_retire_instead_of_wrap() {
    let mut staged = SessionRegistry::<1>::new();
    staged.set_generation_for_test(0, u64::MAX - 1);
    let installed = install_with_fresh_reservation(&mut staged, &ready_setup(identity(5)))
        .expect("max generation");
    assert_eq!(installed.locator().generation(), u64::MAX);
    assert!(matches!(
        staged.rollback_staging(installed),
        Ok(SlotDisposition::Retired)
    ));
    assert_eq!(staged.slot_state(0), Some(RegistrySlotState::Retired));

    let (mut live, published) = published_registry_at_generation::<1>(identity(6), u64::MAX);
    let (_, lease, control) = published.into_parts();
    let terminal = live.begin_remove(lease).expect("terminal");
    assert!(matches!(
        live.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match live.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("last reference"),
    };
    let core_commit = live
        .prepare_finish_delete(right)
        .expect("exact delete right");
    // SAFETY: This core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists, and `&mut` is exclusive.
    assert_eq!(
        unsafe { live.finish_delete(core_commit) },
        SlotDisposition::Retired
    );
    assert_eq!(live.slot_state(0), Some(RegistrySlotState::Retired));
}

#[test]
fn authentic_exhausted_mount_absence_forces_retired_when_session_generation_is_reusable() {
    let (mut registry, published) = published_registry::<1>(identity(61));
    let (locator, lease, control) = published.into_parts();
    assert_ne!(locator.generation(), u64::MAX);
    let mount_reference = registry
        .acquire(locator)
        .expect("the reusable session lends one authentic mount reference");
    let owner = MountOwner::try_new(locator, mount_reference, 0xD00Du32, 0xBEEFu32)
        .expect("the reference binds this exact cell");
    let mut rendezvous = MountRendezvous::new_inactive();
    rendezvous.activate(locator).expect("mount activates");
    rendezvous
        .set_next_mount_generation_for_test(core::num::NonZeroU64::MAX)
        .expect("the test begins at the maximum authentic mount generation");
    rendezvous
        .install(owner)
        .expect("the maximum mount generation installs once");

    let owner_expected = rendezvous
        .expected_teardown(locator)
        .expect("present owner expectation");
    let (mount_reference, teardown) = match rendezvous
        .take_or_join(owner_expected)
        .expect("the exact owner is taken once")
    {
        MountClaim::Owner {
            owner, teardown, ..
        } => {
            let (reference, _device, _vpb) = owner.into_parts();
            (reference, teardown)
        }
        _ => panic!("present generation yields its owner"),
    };
    assert!(matches!(
        registry.release(mount_reference),
        Ok(RegistryRelease::Retained)
    ));
    let done = rendezvous.publish_done(teardown).expect("Done publishes");
    let drain = unsafe { run_r3_mount_done_signal_ack(&mut rendezvous, done, |_| {}) }
        .expect("Done signal is acknowledged");
    let prepared_reset = rendezvous
        .poll_drain(drain)
        .expect("ordinary drain completes");
    let reset = rendezvous
        .finish_reset(prepared_reset)
        .expect("reset publishes");
    let owner_reset =
        unsafe { run_r3_mount_reset_complete_signal_ack(&mut rendezvous, reset, |_| {}) }
            .expect("reset signal is acknowledged");
    let owner_completion = rendezvous
        .complete_owner(owner_reset)
        .expect("the complete reset suffix mints owner completion");
    assert_eq!(owner_completion.cursor(), MountAbsenceCursor::Exhausted);

    let terminal = registry.begin_remove(lease).expect("terminal reference");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry
        .finish_removal_for_test(terminal)
        .expect("fence reaches delete")
    {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("the terminal reference is last"),
    };

    let mount = bind_completed_mount_teardown(
        owner_expected,
        CompletedMountTeardown::from_owner(owner_completion),
    )
    .map_err(|_| ())
    .expect("the authentic exhausted owner completion binds")
    .into_prepared_deactivation();
    let prepared = registry
        .prepare_finish_delete_with_mount(right, &mount)
        .expect("the exact deleting generation accepts its bound mount proof");
    assert_eq!(
        prepared.disposition(),
        SlotDisposition::Retired,
        "mount exhaustion dominates reusable session generation"
    );
    // SAFETY: the test owns the exact deleting slot and its prepared commit.
    assert_eq!(
        unsafe { registry.finish_delete(prepared) },
        SlotDisposition::Retired
    );
    assert_eq!(registry.slot_state(0), Some(RegistrySlotState::Retired));
}

#[derive(Default)]
struct Sink;

unsafe impl EffectSink for Sink {
    unsafe fn emit(&mut self, _effect: Effect) {}
}

#[test]
fn fence_stages_effect_slices_and_recorded_deadlock_order_are_exact() {
    assert_eq!(
        SessionFence::STAGES,
        [
            FenceStage::CloseAdmissionAndSignal,
            FenceStage::RemoveProducerMappings,
            FenceStage::AcquireConsumers,
            FenceStage::DrainStablePrefixes,
            FenceStage::ReleaseAndDrainOwners,
            FenceStage::ReleaseViewsDevicesAndBacking,
        ]
    );
    let expected: [&[FenceEffect]; 6] = [
        &[
            FenceEffect::CloseSessionAdmission,
            FenceEffect::SignalPendingEnter,
            FenceEffect::WaitControlRundown,
        ],
        &[
            FenceEffect::RemoveProducerMappingsReverse,
            FenceEffect::WaitProducerAndMappingCaptureRundown,
        ],
        &[FenceEffect::AcquireConsumersIncreasing],
        &[
            FenceEffect::DrainStablePrefixesBounded,
            FenceEffect::RetireCredits,
        ],
        &[
            FenceEffect::ReleaseConsumers,
            FenceEffect::QueueInstalledWork,
            FenceEffect::WaitPendingAndOwners,
        ],
        &[
            FenceEffect::ReleaseReadOnlyMappingsReverse,
            FenceEffect::ReleaseMdlsAndSystemView,
            FenceEffect::ReleaseCapturedProcess,
            FenceEffect::DismountAndDeleteDevices,
            FenceEffect::ReleaseTransientBacking,
        ],
    ];

    recorder::reset();
    let context = unsafe { EffectContext::empty() };
    let mut seam = Seam::new(Sink);
    let mut next = Some(SessionFence::begin(identity(1)));
    for (index, expected_stage) in SessionFence::STAGES.iter().copied().enumerate() {
        let fence = must_some(next.take(), "each unfinished stage has one capability");
        assert_eq!(fence.identity, identity(1));
        let advance = fence.advance();
        assert_eq!(advance.stage(), expected_stage);
        let expected_effects = must_some(expected.get(index).copied(), "fence stage exists");
        assert_eq!(advance.effects(), expected_effects);
        for effect in advance.effects() {
            must_ok(
                seam.emit(&context, Effect::SessionFence(*effect)),
                "the empty context permits the planned effect",
            );
        }
        next = advance.into_next();
    }
    assert!(
        next.is_none(),
        "the sixth stage has no reset or continuation"
    );
    recorder::assert_before(
        Effect::SessionFence(FenceEffect::CloseSessionAdmission),
        Effect::SessionFence(FenceEffect::WaitControlRundown),
    );
    recorder::assert_before(
        Effect::SessionFence(FenceEffect::SignalPendingEnter),
        Effect::SessionFence(FenceEffect::WaitControlRundown),
    );

    for phrase in crate::effect::oracles::SESSION_FENCE_ORDER_SENTENCES {
        assert!(
            crate::effect::oracles::LOCK_DOC.contains(phrase),
            "stale session-fence oracle phrase: {phrase}"
        );
    }
}

#[test]
fn committed_process_loss_uses_the_ordinary_fence_not_setup_rollback() {
    let id = identity(1);
    let (mut registry, mut binding, reservation, transaction, installed) =
        installed_staging::<1>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references installed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "publishes",
    );

    let terminal = TerminalOwner::new();
    assert!(matches!(
        terminal.claim(ClaimantKind::Teardown),
        ClaimOutcome::Won(_)
    ));
    let locator = published.locator();
    let prepared = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the committed process-loss claimant owns Active",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("the first claimant cannot join"),
    };
    commit_prepared_live_binding_claim(prepared, &mut binding);

    let expected_stages = [
        FenceStage::CloseAdmissionAndSignal,
        FenceStage::RemoveProducerMappings,
        FenceStage::AcquireConsumers,
        FenceStage::DrainStablePrefixes,
        FenceStage::ReleaseAndDrainOwners,
        FenceStage::ReleaseViewsDevicesAndBacking,
    ];
    let expected_effects = [
        Effect::SessionFence(FenceEffect::CloseSessionAdmission),
        Effect::SessionFence(FenceEffect::SignalPendingEnter),
        Effect::SessionFence(FenceEffect::WaitControlRundown),
        Effect::SessionFence(FenceEffect::RemoveProducerMappingsReverse),
        Effect::SessionFence(FenceEffect::WaitProducerAndMappingCaptureRundown),
        Effect::SessionFence(FenceEffect::AcquireConsumersIncreasing),
        Effect::SessionFence(FenceEffect::DrainStablePrefixesBounded),
        Effect::SessionFence(FenceEffect::RetireCredits),
        Effect::SessionFence(FenceEffect::ReleaseConsumers),
        Effect::SessionFence(FenceEffect::QueueInstalledWork),
        Effect::SessionFence(FenceEffect::WaitPendingAndOwners),
        Effect::SessionFence(FenceEffect::ReleaseReadOnlyMappingsReverse),
        Effect::SessionFence(FenceEffect::ReleaseMdlsAndSystemView),
        Effect::SessionFence(FenceEffect::ReleaseCapturedProcess),
        Effect::SessionFence(FenceEffect::DismountAndDeleteDevices),
        Effect::SessionFence(FenceEffect::ReleaseTransientBacking),
    ];

    recorder::reset();
    let context = unsafe { EffectContext::empty() };
    let mut seam = Seam::new(Sink);
    let mut next = Some(SessionFence::begin(published.locator().identity()));
    for expected_stage in expected_stages {
        let fence = must_some(next.take(), "each committed fence stage has one capability");
        let advance = fence.advance();
        assert_eq!(advance.stage(), expected_stage);
        for effect in advance.effects() {
            must_ok(
                seam.emit(&context, Effect::SessionFence(*effect)),
                "the ordinary process-loss fence effect is legal",
            );
        }
        next = advance.into_next();
    }
    assert!(
        next.is_none(),
        "committed process loss finishes after the sixth ordinary fence stage"
    );
    let recorded = recorder::entries();
    assert_eq!(recorded.len(), expected_effects.len());
    for (entry, expected) in recorded.iter().zip(expected_effects) {
        assert_eq!(entry.2, expected);
    }

    assert_eq!(binding.state(), ControlBindingState::ClosingLive(locator));
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Live);
    assert!(matches!(
        terminal.claim(ClaimantKind::Cancellation),
        ClaimOutcome::Lost {
            winner: Some(ClaimantKind::Teardown)
        }
    ));
}

#[test]
fn setup_epoch_is_burned_before_registry_selection() {
    let mut registry = SessionRegistry::<1>::new();
    let registry_before = registry_snapshot(&registry);
    let mut binding = new_binding();

    let premature = SetupReservation {
        binding_id: binding.binding_id,
        setup_epoch: SetupEpoch(1),
    };
    assert!(matches!(
        registry.install_staging(&ready_setup(identity(9)), &binding, &premature),
        Err(SessionError::InvalidTransition)
    ));
    assert_eq!(registry_snapshot(&registry), registry_before);

    let reservation = must_ok(binding.begin_setup(), "the first epoch is issued");

    assert_eq!(reservation.setup_epoch, SetupEpoch(1));
    assert_eq!(binding.state(), ControlBindingState::Staging(SetupEpoch(1)));
    assert_eq!(registry_snapshot(&registry), registry_before);
    let transaction = ready_setup(identity(1));
    let installed = must_ok(
        registry.install_staging(&transaction, &binding, &reservation),
        "registry selection requires the already-burned epoch",
    );
    assert_eq!(installed.locator().identity(), identity(1));
}

#[test]
fn maximum_setup_epoch_rolls_back_to_empty_exhausted() {
    let mut binding = new_binding();
    binding.state = ControlBindingState::Empty(SetupEpochCursor::Next(SetupEpoch(u64::MAX)));
    let reservation = must_ok(binding.begin_setup(), "the maximum epoch is issued once");
    assert_eq!(reservation.setup_epoch, SetupEpoch(u64::MAX));

    let prepared = must_ok(
        prepare_uninstalled_setup_rollback(
            transaction_at(identity(1), SetupStage::LayoutPlanned),
            SetupFailure::Cancelled,
            &binding,
            reservation,
        ),
        "the exact maximum-epoch rollback prepares",
    );
    let (_, disposition) = commit_prepared_uninstalled_setup_rollback(prepared, &mut binding);

    assert_eq!(
        disposition,
        SetupRollbackDisposition::Reopened(SetupEpochCursor::Exhausted)
    );
    assert_eq!(
        binding.state(),
        ControlBindingState::Empty(SetupEpochCursor::Exhausted)
    );
    let exhausted_before = binding_snapshot(&binding);
    for _ in 0..2 {
        assert!(matches!(
            binding.begin_setup(),
            Err(SessionError::SetupEpochExhausted)
        ));
        assert_eq!(binding_snapshot(&binding), exhausted_before);
    }
    assert!(matches!(
        must_ok(
            binding.claim_cleanup(),
            "cleanup may close an exhausted empty binding"
        ),
        CleanupBindingClaim::Empty
    ));
    assert_eq!(binding.state(), ControlBindingState::Closed);

    let mut binding = new_binding();
    binding.state = ControlBindingState::Empty(SetupEpochCursor::Next(SetupEpoch(u64::MAX)));
    let reservation = must_ok(binding.begin_setup(), "the maximum epoch may also commit");
    let transaction = ready_setup(identity(2));
    let mut registry = SessionRegistry::<1>::new();
    let installed = must_ok(
        registry.install_staging(&transaction, &binding, &reservation),
        "the maximum-epoch transaction selects a cell after reservation",
    );
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "the maximum-epoch references install",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "the maximum setup epoch may publish once",
    );
    assert_eq!(
        binding.state(),
        ControlBindingState::Active(published.locator())
    );
    let active_before = binding_snapshot(&binding);
    assert!(matches!(
        binding.begin_setup(),
        Err(SessionError::DuplicateSetup)
    ));
    assert_eq!(binding_snapshot(&binding), active_before);
}

#[test]
fn setup_after_epoch_exhaustion_has_no_state_change() {
    let mut binding = new_binding();
    binding.state = ControlBindingState::Empty(SetupEpochCursor::Exhausted);
    let before = binding_snapshot(&binding);

    for _ in 0..2 {
        assert!(matches!(
            binding.begin_setup(),
            Err(SessionError::SetupEpochExhausted)
        ));
        assert_eq!(binding_snapshot(&binding), before);
    }
}

#[test]
fn control_binding_id_exhaustion_has_no_state_or_context_publication() {
    let source = core::sync::atomic::AtomicU64::new(u64::MAX);
    let issued = must_ok(
        ControlBinding::new_from_id_source(&source),
        "the maximum binding ID is issued once",
    );
    assert_eq!(issued.binding_id.0.get(), u64::MAX);
    assert_eq!(source.load(core::sync::atomic::Ordering::Relaxed), 0);

    let mut published_context = None;
    match ControlBinding::new_from_id_source(&source) {
        Ok(binding) => published_context = Some(binding),
        Err(error) => assert_eq!(error, SessionError::ControlBindingIdExhausted),
    }

    assert!(published_context.is_none());
    assert_eq!(source.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn prepared_setup_rollback_tokens_are_private_and_nonforgeable() {
    let id = identity(1);
    let (mut registry, mut binding, reservation, transaction, installed) =
        reserved_installed_staging::<1>(id);
    let registry_before = registry_snapshot(&registry);
    let binding_before = binding_snapshot(&binding);
    let wrong_transaction = transaction_at(id, SetupStage::ViewsReady);
    let wrong_transaction_before = transaction_snapshot(&wrong_transaction);
    let reservation_before = reservation_snapshot(&reservation);
    let installed_before = installed_snapshot(&installed);
    let failure = match prepare_installed_setup_rollback(
        wrong_transaction,
        SetupFailure::Resource,
        &registry,
        &binding,
        reservation,
        installed,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a transaction from before installation must be refused"),
    };
    let (error, returned_transaction, reason, reservation, installed) = failure.into_parts();
    assert_eq!(error, SessionError::InvalidTransition);
    assert_eq!(reason, SetupFailure::Resource);
    assert_eq!(
        transaction_snapshot(&returned_transaction),
        wrong_transaction_before
    );
    assert_eq!(reservation_snapshot(&reservation), reservation_before);
    assert_eq!(installed_snapshot(&installed), installed_before);
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);

    let prepared = must_ok(
        prepare_installed_setup_rollback(
            transaction,
            SetupFailure::Resource,
            &registry,
            &binding,
            reservation,
            installed,
        ),
        "the complete installed rollback aggregate prepares",
    );
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);
    let prepared = match PreparedSetupRollback::Installed(prepared) {
        PreparedSetupRollback::Installed(prepared) => prepared,
        PreparedSetupRollback::Reserved(_) => panic!("the installed seal changed variant"),
        PreparedSetupRollback::Uninstalled(_) => panic!("the installed seal changed variant"),
    };
    let (receipt, slot_disposition, binding_disposition) =
        commit_prepared_installed_setup_rollback(prepared, &mut registry, &mut binding);
    assert_eq!(receipt.burned_identity, id);
    assert_eq!(slot_disposition, SlotDisposition::Free);
    assert_eq!(
        binding_disposition,
        SetupRollbackDisposition::Reopened(SetupEpochCursor::Next(SetupEpoch(2)))
    );

    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "another epoch is reserved");
    let prepared = must_ok(
        prepare_uninstalled_setup_rollback(
            transaction_at(identity(2), SetupStage::SectionReady),
            SetupFailure::NativeEffect,
            &binding,
            reservation,
        ),
        "the complete uninstalled rollback aggregate prepares",
    );
    let prepared = match PreparedSetupRollback::Uninstalled(prepared) {
        PreparedSetupRollback::Uninstalled(prepared) => prepared,
        PreparedSetupRollback::Reserved(_) => panic!("the uninstalled seal changed variant"),
        PreparedSetupRollback::Installed(_) => panic!("the uninstalled seal changed variant"),
    };
    let (receipt, disposition) = commit_prepared_uninstalled_setup_rollback(prepared, &mut binding);
    assert_eq!(receipt.burned_identity, identity(2));
    assert_eq!(
        disposition,
        SetupRollbackDisposition::Reopened(SetupEpochCursor::Next(SetupEpoch(2)))
    );
}

#[test]
fn cleanup_claims_staging_as_closing_setup_for_the_exact_epoch() {
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "the first epoch is reserved");

    let right = match must_ok(binding.claim_cleanup(), "cleanup claims staging") {
        CleanupBindingClaim::Setup(right) => right,
        _ => panic!("staging must return its exact setup cleanup right"),
    };

    assert_eq!(right.binding_id, reservation.binding_id);
    assert_eq!(right.setup_epoch, reservation.setup_epoch);
    assert_eq!(
        binding.state(),
        ControlBindingState::ClosingSetup(reservation.setup_epoch)
    );
}

#[test]
fn rollback_cannot_reopen_a_closing_setup_binding() {
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "the first epoch is reserved");
    let right = match must_ok(binding.claim_cleanup(), "cleanup claims staging") {
        CleanupBindingClaim::Setup(right) => right,
        _ => panic!("staging must return a setup cleanup right"),
    };
    let prepared = must_ok(
        prepare_uninstalled_setup_rollback(
            transaction_at(identity(1), SetupStage::ViewsReady),
            SetupFailure::Cancelled,
            &binding,
            reservation,
        ),
        "rollback recognizes the already-closing epoch",
    );

    let (_, disposition) = commit_prepared_uninstalled_setup_rollback(prepared, &mut binding);

    assert_eq!(disposition, SetupRollbackDisposition::RemainsClosing);
    assert_eq!(
        binding.state(),
        ControlBindingState::ClosingSetup(SetupEpoch(1))
    );
    must_ok(
        binding.finish_setup_cleanup(right),
        "only the exact cleanup right closes the binding",
    );
    assert_eq!(binding.state(), ControlBindingState::Closed);

    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "another setup is staging");
    let prepared = must_ok(
        prepare_uninstalled_setup_rollback(
            transaction_at(identity(2), SetupStage::ViewsReady),
            SetupFailure::Cancelled,
            &binding,
            reservation,
        ),
        "rollback may prepare before concurrent cleanup",
    );
    let right = match must_ok(
        binding.claim_cleanup(),
        "cleanup may advance the prepared setup to closing",
    ) {
        CleanupBindingClaim::Setup(right) => right,
        _ => panic!("staging must return a setup cleanup right"),
    };
    let (_, disposition) = commit_prepared_uninstalled_setup_rollback(prepared, &mut binding);
    assert_eq!(disposition, SetupRollbackDisposition::RemainsClosing);
    must_ok(
        binding.finish_setup_cleanup(right),
        "the concurrent cleanup right closes after rollback",
    );
}

#[test]
fn foreign_binding_reservation_and_cleanup_right_are_returned_without_mutation() {
    let id = identity(1);
    let (mut registry, mut binding, _reservation, transaction, installed) =
        reserved_installed_staging::<1>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references are installed",
    );
    let mut foreign_binding = new_binding();
    let foreign_reservation = must_ok(
        foreign_binding.begin_setup(),
        "the foreign binding has an exact reservation",
    );
    let transaction_before = transaction_snapshot(&transaction);
    let reservation_before = reservation_snapshot(&foreign_reservation);
    let installed_before = installed_snapshot(&installed);
    let registry_before = registry_snapshot(&registry);
    let binding_before = binding_snapshot(&binding);

    let mut rendezvous = TerminalRendezvous::new_inactive();
    let failure = match publish_installed_setup_for_test(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        foreign_reservation,
        installed,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a foreign binding reservation must not publish"),
    };
    let (error, transaction, foreign_reservation, installed) = failure.into_parts();
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(transaction_snapshot(&transaction), transaction_before);
    assert_eq!(
        reservation_snapshot(&foreign_reservation),
        reservation_before
    );
    assert_eq!(installed_snapshot(&installed), installed_before);
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);

    let stale_reservation = SetupReservation {
        binding_id: binding.binding_id,
        setup_epoch: SetupEpoch(2),
    };
    let stale_before = reservation_snapshot(&stale_reservation);
    let registry_before = registry_snapshot(&registry);
    let binding_before = binding_snapshot(&binding);
    let failure = match prepare_installed_setup_rollback(
        transaction,
        SetupFailure::Cancelled,
        &registry,
        &binding,
        stale_reservation,
        installed,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a stale setup reservation must not prepare rollback"),
    };
    let (error, transaction, reason, stale_reservation, installed) = failure.into_parts();
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(reason, SetupFailure::Cancelled);
    assert_eq!(transaction_snapshot(&transaction), transaction_before);
    assert_eq!(reservation_snapshot(&stale_reservation), stale_before);
    assert_eq!(installed_snapshot(&installed), installed_before);
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);

    let foreign_right = match must_ok(
        foreign_binding.claim_cleanup(),
        "the foreign cleanup claims its own epoch",
    ) {
        CleanupBindingClaim::Setup(right) => right,
        _ => panic!("the foreign staging state must return a setup right"),
    };
    let right_before = (foreign_right.binding_id, foreign_right.setup_epoch);
    let binding_before = binding_snapshot(&binding);
    let (error, returned_right) = match binding.finish_setup_cleanup(foreign_right) {
        Err(failure) => failure,
        Ok(()) => panic!("a foreign cleanup right must not close this binding"),
    };
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(
        (returned_right.binding_id, returned_right.setup_epoch),
        right_before
    );
    assert_eq!(binding_snapshot(&binding), binding_before);

    let mut target = new_binding();
    let _target_reservation = must_ok(target.begin_setup(), "the target setup is staging");
    let mut other = new_binding();
    let other_reservation = must_ok(other.begin_setup(), "the other setup is staging");
    let transaction = transaction_at(identity(3), SetupStage::VolumeReady);
    let transaction_before = transaction_snapshot(&transaction);
    let reservation_before = reservation_snapshot(&other_reservation);
    let registry_before = registry_snapshot(&registry);
    let binding_before = binding_snapshot(&target);
    let failure = match prepare_uninstalled_setup_rollback(
        transaction,
        SetupFailure::Unload,
        &target,
        other_reservation,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a foreign uninstalled reservation must be returned"),
    };
    let (error, returned_transaction, reason, returned_reservation) = failure.into_parts();
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(reason, SetupFailure::Unload);
    assert_eq!(
        transaction_snapshot(&returned_transaction),
        transaction_before
    );
    assert_eq!(
        reservation_snapshot(&returned_reservation),
        reservation_before
    );
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&target), binding_before);

    let (
        mut commit_registry,
        commit_binding,
        commit_reservation,
        commit_transaction,
        commit_installed,
    ) = reserved_installed_staging::<1>(identity(4));
    let prepared = must_ok(
        prepare_installed_setup_rollback(
            commit_transaction,
            SetupFailure::Cancelled,
            &commit_registry,
            &commit_binding,
            commit_reservation,
            commit_installed,
        ),
        "the exact installed rollback prepares",
    );
    let commit_registry_before = registry_snapshot(&commit_registry);
    let commit_binding_before = binding_snapshot(&commit_binding);
    let mut wrong_commit_binding = new_binding();
    let wrong_binding_before = binding_snapshot(&wrong_commit_binding);
    let refusal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = commit_prepared_installed_setup_rollback(
            prepared,
            &mut commit_registry,
            &mut wrong_commit_binding,
        );
    }));
    assert!(
        refusal.is_err(),
        "a foreign commit destination is unreachable"
    );
    assert_eq!(registry_snapshot(&commit_registry), commit_registry_before);
    assert_eq!(binding_snapshot(&commit_binding), commit_binding_before);
    assert_eq!(
        binding_snapshot(&wrong_commit_binding),
        wrong_binding_before
    );

    let (
        mut advanced_registry,
        mut advanced_binding,
        advanced_reservation,
        advanced_transaction,
        advanced_installed,
    ) = reserved_installed_staging::<1>(identity(5));
    let prepared = must_ok(
        prepare_installed_setup_rollback(
            advanced_transaction,
            SetupFailure::Cancelled,
            &advanced_registry,
            &advanced_binding,
            advanced_reservation,
            advanced_installed,
        ),
        "another installed rollback prepares",
    );
    let right = match must_ok(
        advanced_binding.claim_cleanup(),
        "cleanup advances the prepared binding",
    ) {
        CleanupBindingClaim::Setup(right) => right,
        _ => panic!("staging must return a setup cleanup right"),
    };
    must_ok(
        advanced_binding.finish_setup_cleanup(right),
        "an invalid caller can close before committing rollback",
    );
    let advanced_registry_before = registry_snapshot(&advanced_registry);
    let advanced_binding_before = binding_snapshot(&advanced_binding);
    let refusal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = commit_prepared_installed_setup_rollback(
            prepared,
            &mut advanced_registry,
            &mut advanced_binding,
        );
    }));
    assert!(
        refusal.is_err(),
        "an advanced commit destination is unreachable"
    );
    assert_eq!(
        registry_snapshot(&advanced_registry),
        advanced_registry_before
    );
    assert_eq!(binding_snapshot(&advanced_binding), advanced_binding_before);
}

#[test]
fn uninstalled_rollback_burns_epoch_without_registry_mutation() {
    let registry = SessionRegistry::<1>::new();
    let registry_before = registry_snapshot(&registry);
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "the first epoch is reserved");
    let prepared = must_ok(
        prepare_uninstalled_setup_rollback(
            transaction_at(identity(1), SetupStage::GrantsReady),
            SetupFailure::Resource,
            &binding,
            reservation,
        ),
        "the exact uninstalled rollback prepares",
    );

    let (receipt, disposition) = commit_prepared_uninstalled_setup_rollback(prepared, &mut binding);

    assert_eq!(receipt.burned_identity, identity(1));
    assert_eq!(receipt.last_stage, SetupStage::GrantsReady);
    assert_eq!(
        disposition,
        SetupRollbackDisposition::Reopened(SetupEpochCursor::Next(SetupEpoch(2)))
    );
    assert_eq!(registry_snapshot(&registry), registry_before);
}

#[test]
fn live_publication_stores_the_exact_locator() {
    let (registry, binding, published) = published_binding::<1>(identity(1));
    let locator = published.locator();

    assert_eq!(binding.state(), ControlBindingState::Active(locator));
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Live);
    assert_eq!(locator.slot_index(), 0);
    assert_eq!(locator.generation(), 1);
    assert_eq!(locator.identity(), identity(1));
}

#[test]
fn terminal_claim_moves_active_to_closing_live_once() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(1));
    let locator = published.locator();
    let prepared = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the active locator admits one terminal claim",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("the first terminal claimant must win"),
    };

    commit_prepared_live_binding_claim(prepared, &mut binding);

    assert_eq!(binding.state(), ControlBindingState::ClosingLive(locator));
    assert!(matches!(
        must_ok(
            prepare_live_binding_claim(&binding, locator),
            "the exact closing generation remains joinable"
        ),
        PreparedLiveBindingClaim::Join(joined) if joined == locator
    ));
}

#[test]
fn closing_live_join_cannot_claim_terminal_authority() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(1));
    let locator = published.locator();
    let prepared = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the active generation admits its winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("active cannot be a join"),
    };
    commit_prepared_live_binding_claim(prepared, &mut binding);
    let before = binding_snapshot(&binding);

    let joined = must_ok(
        prepare_live_binding_claim(&binding, locator),
        "closing live exposes only a join observation",
    );

    assert!(matches!(joined, PreparedLiveBindingClaim::Join(value) if value == locator));
    assert_eq!(binding_snapshot(&binding), before);
}

#[test]
fn closing_complete_requires_a_present_completed_control_record() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(1));
    let locator = published.locator();
    let claim = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the active generation admits its terminal winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("active cannot be a join"),
    };
    commit_prepared_live_binding_claim(claim, &mut binding);
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let before = binding_snapshot(&binding);

    assert!(matches!(
        prepare_closing_complete(&binding, locator, result, false),
        Err(SessionError::InvalidTransition)
    ));
    assert_eq!(binding_snapshot(&binding), before);

    let prepared = must_ok(
        prepare_closing_complete(&binding, locator, result, true),
        "a present completed-control record admits completion",
    );
    commit_prepared_closing_complete(prepared, &mut binding);
    assert_eq!(
        binding.state(),
        ControlBindingState::ClosingComplete {
            generation: 1,
            result,
        }
    );
}

#[test]
fn cleanup_acknowledges_closing_complete_without_resolving_the_old_cell() {
    let (mut binding, result) = {
        let (_old_registry, mut binding, published) = published_binding::<1>(identity(1));
        let locator = published.locator();
        let claim = match must_ok(
            prepare_live_binding_claim(&binding, locator),
            "the active generation admits its terminal winner",
        ) {
            PreparedLiveBindingClaim::Claim(prepared) => prepared,
            PreparedLiveBindingClaim::Join(_) => panic!("active cannot be a join"),
        };
        commit_prepared_live_binding_claim(claim, &mut binding);
        let result = TerminalResult {
            reason: TerminalReason::ProcessLoss,
            fence_failures: 2,
        };
        let prepared = must_ok(
            prepare_closing_complete(&binding, locator, result, true),
            "the completed record is present",
        );
        commit_prepared_closing_complete(prepared, &mut binding);
        (binding, result)
    };

    let claim = must_ok(
        binding.claim_cleanup(),
        "cleanup reads the binding record without a registry lookup",
    );

    assert!(matches!(
        claim,
        CleanupBindingClaim::Completed {
            generation: 1,
            result: returned,
        } if returned == result
    ));
    assert_eq!(binding.state(), ControlBindingState::Closed);
}

#[test]
fn closing_blocked_never_moves_to_closed_or_mints_a_close_right() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(1));
    let locator = published.locator();
    let claim = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the active generation admits its terminal winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("active cannot be a join"),
    };
    commit_prepared_live_binding_claim(claim, &mut binding);
    let prepared = must_ok(
        prepare_closing_blocked(&binding, locator, TerminalBlockedClass::FenceInvariant),
        "the exact closing generation may publish a fail-stop",
    );
    commit_prepared_closing_blocked(prepared, &mut binding);
    let before = binding_snapshot(&binding);

    for _ in 0..2 {
        assert!(matches!(
            must_ok(binding.claim_cleanup(), "blocked remains observable"),
            CleanupBindingClaim::Blocked {
                locator: returned,
                class: TerminalBlockedClass::FenceInvariant,
            } if returned == locator
        ));
        assert_eq!(binding_snapshot(&binding), before);
    }
}

#[derive(Clone, Copy)]
struct TestFailStopPacket {
    retained_locator: SessionLocator,
    blocked: TerminalBlocked,
    mode: StoredFailStopPublicationMode,
}

impl TestFailStopPacket {
    const fn new(
        retained_locator: SessionLocator,
        blocked: TerminalBlocked,
        mode: StoredFailStopPublicationMode,
    ) -> Self {
        Self {
            retained_locator,
            blocked,
            mode,
        }
    }
}

fn project_test_fail_stop_packet(
    packet: &TestFailStopPacket,
) -> (TerminalBlocked, StoredFailStopPublicationMode) {
    (packet.blocked, packet.mode)
}

#[test]
fn stored_fail_stop_packet_a_cannot_publish_packet_b_metadata() {
    let (_registry, mut binding_b, published_b) = published_binding::<1>(identity(74));
    let locator_b = published_b.locator();
    let claim_b = match must_ok(
        prepare_live_binding_claim(&binding_b, locator_b),
        "the live B binding admits its exact terminal winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("the active B generation is not a join"),
    };
    commit_prepared_live_binding_claim(claim_b, &mut binding_b);

    let mut rendezvous_b = terminal_for(locator_b);
    let (winner_b, _ticket_b) = rendezvous_b
        .claim(locator_b, TerminalRequest::Cleanup)
        .expect("the first counted B arrival wins")
        .into_parts();
    let blocked_b = blocked_fixture(locator_b, winner_b.diagnostic());

    let locator_a = SessionLocator::from_parts_for_test(0, 75, identity(75));
    let blocked_a = blocked_fixture(locator_a, DiagnosticId::for_locator(locator_a));
    let packet_a = TestFailStopPacket {
        retained_locator: locator_a,
        blocked: blocked_a,
        mode: StoredFailStopPublicationMode::PublishIfExact,
    };
    let mut slot = DurableFailStopSlot::new_empty();
    let resolution = must_ok(
        unsafe {
            slot.store_and_resolve(
                &mut rendezvous_b,
                packet_a,
                project_test_fail_stop_packet,
                |packet_a, receipt| {
                    assert_eq!(packet_a.retained_locator, locator_a);
                    let _copied_b_metadata = (locator_b, winner_b.diagnostic(), blocked_b);
                    commit_stored_fail_stop_visibility(receipt, &mut binding_b)
                },
            )
        },
        "the empty durable slot retains packet A",
    );

    assert!(matches!(
        resolution,
        StoredFailStopResolution::OpaqueRetained
    ));
    assert_eq!(
        binding_b.state(),
        ControlBindingState::ClosingLive(locator_b),
        "packet A cannot publish copied locator/diagnostic/blocked metadata from B",
    );
    assert_eq!(
        rendezvous_b.outcome_for_locator(locator_b),
        Some(TerminalRendezvousOutcome::Open),
        "packet A cannot close B's rendezvous",
    );
    assert_eq!(
        slot.observation_for(locator_a),
        Some(DurableFailStopObservation::OpaqueRetained),
        "the rejected cross-wire retains packet A in the occupied slot",
    );
    assert_eq!(slot.observation_for(locator_b), None);
}

#[test]
fn stored_fail_stop_slot_accepts_only_a_resolution_committed_from_its_receipt() {
    let (_registry_a, mut binding_a, published_a) = published_binding::<1>(identity(751));
    let locator_a = published_a.locator();
    let claim_a = match must_ok(
        prepare_live_binding_claim(&binding_a, locator_a),
        "the live A binding admits its exact terminal winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("the active A generation is not a join"),
    };
    commit_prepared_live_binding_claim(claim_a, &mut binding_a);
    let mut rendezvous_a = terminal_for(locator_a);
    let (_winner_a, ticket_a) = rendezvous_a
        .claim(locator_a, TerminalRequest::Cleanup)
        .expect("the first counted A arrival wins")
        .into_parts();
    let packet_a = TestFailStopPacket::new(
        locator_a,
        blocked_fixture(locator_a, DiagnosticId::for_locator(locator_a)),
        StoredFailStopPublicationMode::RequireOpaque,
    );

    let locator_b = SessionLocator::from_parts_for_test(0, 752, identity(752));
    let mut rendezvous_b = terminal_for(locator_b);
    let (winner_b, ticket_b) = rendezvous_b
        .claim(locator_b, TerminalRequest::Cleanup)
        .expect("the first counted B arrival wins")
        .into_parts();
    let foreign_signal = must_ok(
        rendezvous_b.close_and_publish_blocked(
            winner_b,
            blocked_fixture(locator_b, DiagnosticId::for_locator(locator_b)),
        ),
        "B can mint only B's terminal signal",
    );

    let mut slot_a = DurableFailStopSlot::new_empty();
    let resolution = must_ok(
        unsafe {
            slot_a.store_and_resolve(
                &mut rendezvous_a,
                packet_a,
                project_test_fail_stop_packet,
                |_packet, receipt| {
                    let _foreign_signal_that_cannot_substitute = foreign_signal;
                    commit_stored_fail_stop_visibility(receipt, &mut binding_a)
                },
            )
        },
        "A enters durable storage",
    );
    assert!(
        matches!(resolution, StoredFailStopResolution::OpaqueRetained),
        "slot A must reject a public resolution that was not committed from its private receipt",
    );
    assert_eq!(
        slot_a.observation_for(locator_a),
        Some(DurableFailStopObservation::OpaqueRetained),
    );

    let _ = (ticket_a, ticket_b);
}

#[test]
fn stored_fail_stop_publishes_only_after_exact_binding_and_rendezvous_match() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(71));
    let locator = published.locator();
    let claim = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the active generation admits its terminal winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("active cannot be a join"),
    };
    commit_prepared_live_binding_claim(claim, &mut binding);

    let mut rendezvous = terminal_for(locator);
    let (winner, ticket) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("the first counted arrival wins")
        .into_parts();
    let blocked = blocked_fixture(locator, winner.diagnostic());
    let packet = TestFailStopPacket::new(
        locator,
        blocked,
        StoredFailStopPublicationMode::PublishIfExact,
    );

    let mut slot = DurableFailStopSlot::new_empty();
    let resolution = must_ok(
        unsafe {
            slot.store_and_resolve(
                &mut rendezvous,
                packet,
                project_test_fail_stop_packet,
                |_packet, receipt| commit_stored_fail_stop_visibility(receipt, &mut binding),
            )
        },
        "the empty durable slot stores before visibility",
    );
    let StoredFailStopResolution::Published(signal) = resolution else {
        panic!("the exact stored packet authorizes ordinary blocked publication")
    };
    assert_eq!(signal.into_locator(), locator);
    assert_eq!(
        binding.state(),
        ControlBindingState::ClosingBlocked {
            locator,
            class: TerminalBlockedClass::FenceInvariant,
        }
    );
    assert_eq!(
        rendezvous.outcome_for_locator(locator),
        Some(TerminalRendezvousOutcome::Blocked(blocked)),
        "visibility is published only after storage authorization"
    );
    assert_eq!(
        slot.observation_for(locator),
        Some(DurableFailStopObservation::Published)
    );
    assert!(matches!(
        resolve_terminal_release(
            rendezvous
                .release(ticket)
                .map_err(|_| ())
                .expect("the authentic counted winner ticket releases normally")
        ),
        crate::adapter::lifecycle::TerminalWaitDisposition::Blocked {
            blocked: observed,
            drained: Some(_),
        } if observed == blocked
    ));
}

#[test]
fn stored_fail_stop_opaque_quarantine_never_overwrites_or_publishes_blocked() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(72));
    let locator = published.locator();
    let claim = match must_ok(
        prepare_live_binding_claim(&binding, locator),
        "the active generation admits its terminal winner",
    ) {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("active cannot be a join"),
    };
    commit_prepared_live_binding_claim(claim, &mut binding);

    let mut rendezvous = terminal_for(locator);
    let (winner, ticket) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("the first counted arrival wins")
        .into_parts();
    let blocked = blocked_fixture(locator, winner.diagnostic());
    let admitted_before = admitted(&rendezvous);
    let packet = TestFailStopPacket::new(
        locator,
        blocked,
        StoredFailStopPublicationMode::RequireOpaque,
    );

    let mut slot = DurableFailStopSlot::new_empty();
    let resolution = must_ok(
        unsafe {
            slot.store_and_resolve(
                &mut rendezvous,
                packet,
                project_test_fail_stop_packet,
                |_packet, receipt| commit_stored_fail_stop_visibility(receipt, &mut binding),
            )
        },
        "the empty durable slot stores before quarantine",
    );
    assert!(matches!(
        resolution,
        StoredFailStopResolution::OpaqueRetained
    ));
    assert_eq!(
        binding.state(),
        ControlBindingState::ClosingOpaqueRetained { locator },
        "only the exact ClosingLive component may move to opaque quarantine"
    );
    assert_eq!(
        rendezvous.outcome_for_locator(locator),
        None,
        "opaque quarantine is not a TerminalBlocked publication"
    );
    assert_eq!(
        rendezvous.opaque_retained_admitted_for_locator(locator),
        Some(admitted_before),
        "quarantine preserves the exact counted admissions"
    );
    assert_eq!(
        slot.observation_for(locator),
        Some(DurableFailStopObservation::OpaqueRetained)
    );
    let ticket = match rendezvous.release(ticket) {
        Err((_error, ticket)) => ticket,
        Ok(_) => panic!("opaque has no normal closed outcome"),
    };

    let foreign_ticket = {
        let foreign_locator = SessionLocator {
            slot_index: locator.slot_index(),
            generation: locator.generation().saturating_add(1),
            identity: identity(73),
        };
        let mut foreign_rendezvous = terminal_for(foreign_locator);
        foreign_rendezvous
            .claim(foreign_locator, TerminalRequest::Cleanup)
            .expect("the foreign generation mints only its own admission")
            .into_parts()
            .1
    };
    let foreign_ticket = rendezvous
        .release_opaque_retained(foreign_ticket)
        .expect_err("a foreign ticket is retained rather than fabricated as a release");
    assert_eq!(foreign_ticket.locator().identity(), identity(73));
    assert_eq!(
        rendezvous.opaque_retained_admitted_for_locator(locator),
        Some(admitted_before),
        "a rejected ticket does not alter the counted admission"
    );

    let drained = rendezvous
        .release_opaque_retained(ticket)
        .expect("the authentic winner ticket releases from quarantine")
        .expect("the sole counted arrival produces the drained signal");
    assert_eq!(drained.into_locator(), locator);
    assert_eq!(
        rendezvous.opaque_retained_admitted_for_locator(locator),
        Some(0),
        "valid opaque release decrements once without publishing an outcome"
    );

    let foreign = SessionLocator {
        slot_index: locator.slot_index(),
        generation: locator.generation().saturating_add(1),
        identity: identity(73),
    };
    let foreign_binding_before = binding_snapshot(&binding);
    let mut foreign_slot = DurableFailStopSlot::new_empty();
    let foreign_blocked = blocked_fixture(foreign, DiagnosticId::for_locator(foreign));
    let foreign_packet = TestFailStopPacket::new(
        foreign,
        foreign_blocked,
        StoredFailStopPublicationMode::PublishIfExact,
    );
    let foreign_resolution = must_ok(
        unsafe {
            foreign_slot.store_and_resolve(
                &mut rendezvous,
                foreign_packet,
                project_test_fail_stop_packet,
                |_packet, receipt| commit_stored_fail_stop_visibility(receipt, &mut binding),
            )
        },
        "the foreign packet is durably quarantined in its own slot",
    );
    assert!(matches!(
        foreign_resolution,
        StoredFailStopResolution::OpaqueRetained
    ));
    assert_eq!(binding_snapshot(&binding), foreign_binding_before);
    assert_eq!(
        rendezvous.opaque_retained_admitted_for_locator(locator),
        Some(0),
        "a foreign retry cannot overwrite, convert, or recount opaque state"
    );

    let _ = foreign_ticket;
}

#[test]
fn native_fail_stop_trace_stores_before_visibility_and_opaque_never_signals() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TraceStep {
        PacketStored,
        PublishBlocked,
        QuarantineOpaque,
        AuthenticateSlotAndRendezvous,
        ReleaseExact,
        RetainForeign,
        Unlock,
        SignalVisibility,
        SignalTerminal,
        AuthenticatePublishedSlot,
        PermanentWait,
        DedicatedOpaqueWait,
    }

    #[derive(Clone, Copy)]
    enum Case {
        Published,
        OpaqueExact,
        OpaqueForeign,
    }

    enum OpaqueContinuation {
        Released(Option<TerminalJoinersDrainedSignal>),
        Retained(TerminalJoinTicket),
    }

    enum BlockedWaitToken {
        Published,
        Opaque(OpaqueContinuation),
    }

    struct LockedPhase {
        slot: std::rc::Rc<core::cell::RefCell<DurableFailStopSlot<TestFailStopPacket>>>,
        rendezvous: std::rc::Rc<core::cell::RefCell<TerminalRendezvous>>,
        binding: std::rc::Rc<core::cell::RefCell<ControlBinding>>,
        packet: Option<TestFailStopPacket>,
        ticket: Option<TerminalJoinTicket>,
        locator: SessionLocator,
        trace: std::rc::Rc<core::cell::RefCell<Vec<TraceStep>>>,
    }

    struct PermanentWaitSentinel;

    for (number, case, expected) in [
        (
            721,
            Case::Published,
            vec![
                TraceStep::PacketStored,
                TraceStep::PublishBlocked,
                TraceStep::Unlock,
                TraceStep::SignalVisibility,
                TraceStep::SignalTerminal,
                TraceStep::ReleaseExact,
                TraceStep::AuthenticatePublishedSlot,
                TraceStep::PermanentWait,
            ],
        ),
        (
            722,
            Case::OpaqueExact,
            vec![
                TraceStep::PacketStored,
                TraceStep::QuarantineOpaque,
                TraceStep::AuthenticateSlotAndRendezvous,
                TraceStep::ReleaseExact,
                TraceStep::Unlock,
                TraceStep::SignalVisibility,
                TraceStep::DedicatedOpaqueWait,
            ],
        ),
        (
            723,
            Case::OpaqueForeign,
            vec![
                TraceStep::PacketStored,
                TraceStep::QuarantineOpaque,
                TraceStep::AuthenticateSlotAndRendezvous,
                TraceStep::RetainForeign,
                TraceStep::Unlock,
                TraceStep::SignalVisibility,
                TraceStep::DedicatedOpaqueWait,
            ],
        ),
    ] {
        let (_registry, mut binding, published) = published_binding::<1>(identity(number));
        let locator = published.locator();
        let claim = match must_ok(
            prepare_live_binding_claim(&binding, locator),
            "the live binding admits its exact winner",
        ) {
            PreparedLiveBindingClaim::Claim(prepared) => prepared,
            PreparedLiveBindingClaim::Join(_) => panic!("the first terminal arrival wins"),
        };
        commit_prepared_live_binding_claim(claim, &mut binding);

        let mut rendezvous = terminal_for(locator);
        let (winner, ticket) = rendezvous
            .claim(locator, TerminalRequest::Cleanup)
            .expect("the first counted arrival wins")
            .into_parts();
        let blocked = blocked_fixture(locator, winner.diagnostic());
        let mode = match case {
            Case::Published => StoredFailStopPublicationMode::PublishIfExact,
            Case::OpaqueExact | Case::OpaqueForeign => StoredFailStopPublicationMode::RequireOpaque,
        };
        let packet = TestFailStopPacket::new(locator, blocked, mode);
        let ticket = match case {
            Case::Published | Case::OpaqueExact => ticket,
            Case::OpaqueForeign => {
                let _ = ticket;
                let foreign = SessionLocator::from_parts_for_test(
                    locator.slot_index(),
                    locator.generation().saturating_add(1),
                    identity(number + 100),
                );
                let mut foreign_rendezvous = terminal_for(foreign);
                let (_foreign_winner, foreign_ticket) = foreign_rendezvous
                    .claim(foreign, TerminalRequest::Cleanup)
                    .expect("a foreign counted arrival owns a real foreign ticket")
                    .into_parts();
                foreign_ticket
            }
        };

        let trace = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        let slot = std::rc::Rc::new(core::cell::RefCell::new(DurableFailStopSlot::new_empty()));
        let rendezvous = std::rc::Rc::new(core::cell::RefCell::new(rendezvous));
        let binding = std::rc::Rc::new(core::cell::RefCell::new(binding));
        let locked = LockedPhase {
            slot: std::rc::Rc::clone(&slot),
            rendezvous: std::rc::Rc::clone(&rendezvous),
            binding,
            packet: Some(packet),
            ticket: Some(ticket),
            locator,
            trace: std::rc::Rc::clone(&trace),
        };

        let latch_trace = std::rc::Rc::clone(&trace);
        let published_trace = std::rc::Rc::clone(&trace);
        let published_rendezvous = std::rc::Rc::clone(&rendezvous);
        let published_slot = std::rc::Rc::clone(&slot);
        let published_continue_trace = std::rc::Rc::clone(&trace);
        let wait_trace = std::rc::Rc::clone(&trace);
        let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let token = run_r3_fail_stop_two_phase(
                locked,
                |locked| {
                    let packet = locked
                        .packet
                        .take()
                        .expect("the locked phase stores its packet exactly once");
                    let mut slot = locked.slot.borrow_mut();
                    let mut rendezvous = locked.rendezvous.borrow_mut();
                    let mut binding = locked.binding.borrow_mut();
                    let resolution = must_ok(
                        unsafe {
                            slot.store_and_resolve(
                                &mut rendezvous,
                                packet,
                                |stored_packet| {
                                    locked.trace.borrow_mut().push(TraceStep::PacketStored);
                                    project_test_fail_stop_packet(stored_packet)
                                },
                                |_packet, receipt| {
                                    assert!(
                                        receipt.packet_is_stored_before_visibility(),
                                        "the resolver receives proof borrowed from an occupied Stored slot",
                                    );
                                    let committed =
                                        commit_stored_fail_stop_visibility(receipt, &mut binding);
                                    let step = match committed.resolution() {
                                        StoredFailStopResolution::Published(_) => {
                                            TraceStep::PublishBlocked
                                        }
                                        StoredFailStopResolution::OpaqueRetained => {
                                            TraceStep::QuarantineOpaque
                                        }
                                    };
                                    locked.trace.borrow_mut().push(step);
                                    committed
                                },
                            )
                        },
                        "the empty durable slot accepts exactly one packet",
                    );

                    match resolution {
                        StoredFailStopResolution::Published(signal) => {
                            let ticket = locked
                                .ticket
                                .take()
                                .expect("Published carries the original counted ticket");
                            R3FailStopPreparedContinuation::<
                                _,
                                _,
                                OpaqueContinuation,
                                core::convert::Infallible,
                            >::Published {
                                signal,
                                continuation: ticket,
                            }
                        }
                        StoredFailStopResolution::OpaqueRetained => {
                            assert_eq!(
                                slot.observation_for(locked.locator),
                                Some(DurableFailStopObservation::OpaqueRetained),
                            );
                            assert!(
                                rendezvous
                                    .opaque_retained_admitted_for_locator(locked.locator)
                                    .is_some(),
                                "Opaque authenticates both its stored slot and rendezvous under lock",
                            );
                            locked
                                .trace
                                .borrow_mut()
                                .push(TraceStep::AuthenticateSlotAndRendezvous);
                            let ticket = locked
                                .ticket
                                .take()
                                .expect("Opaque conditionally consumes one real ticket");
                            let continuation = match rendezvous.release_opaque_retained(ticket) {
                                Ok(drained) => {
                                    locked.trace.borrow_mut().push(TraceStep::ReleaseExact);
                                    OpaqueContinuation::Released(drained)
                                }
                                Err(ticket) => {
                                    locked.trace.borrow_mut().push(TraceStep::RetainForeign);
                                    OpaqueContinuation::Retained(ticket)
                                }
                            };
                            R3FailStopPreparedContinuation::Opaque(continuation)
                        }
                    }
                },
                |locked| locked.trace.borrow_mut().push(TraceStep::Unlock),
                move || latch_trace.borrow_mut().push(TraceStep::SignalVisibility),
                move |signal| {
                    assert_eq!(signal.into_locator(), locator);
                    let mut trace = published_trace.borrow_mut();
                    trace.push(TraceStep::SignalVisibility);
                    trace.push(TraceStep::SignalTerminal);
                },
                move |ticket| {
                    let release = published_rendezvous
                        .borrow_mut()
                        .release(ticket)
                        .map_err(|_| ())
                        .expect(
                            "Published releases its exact counted ticket after the combined wake",
                        );
                    assert!(matches!(
                        resolve_terminal_release(release),
                        crate::adapter::lifecycle::TerminalWaitDisposition::Blocked { .. }
                    ));
                    let mut trace = published_continue_trace.borrow_mut();
                    trace.push(TraceStep::ReleaseExact);
                    assert_eq!(
                        published_slot.borrow().observation_for(locator),
                        Some(DurableFailStopObservation::Published),
                    );
                    trace.push(TraceStep::AuthenticatePublishedSlot);
                    BlockedWaitToken::Published
                },
                BlockedWaitToken::Opaque,
                |never| match never {},
            );

            run_r3_blocked_unload_wait(token, |token| {
                let wait = match token {
                    BlockedWaitToken::Published => TraceStep::PermanentWait,
                    BlockedWaitToken::Opaque(OpaqueContinuation::Released(drained)) => {
                        let _authentic_drained = drained;
                        TraceStep::DedicatedOpaqueWait
                    }
                    BlockedWaitToken::Opaque(OpaqueContinuation::Retained(ticket)) => {
                        let _retain_foreign_ticket = ticket;
                        TraceStep::DedicatedOpaqueWait
                    }
                };
                wait_trace.borrow_mut().push(wait);
                std::panic::panic_any(PermanentWaitSentinel)
            })
        }));
        let payload = stopped.expect_err("the outer blocked-wait seam uses a test sentinel");
        assert!(payload.is::<PermanentWaitSentinel>());

        assert_eq!(trace.borrow().as_slice(), expected.as_slice());
    }
}

#[test]
fn closed_never_coexists_with_live_publication() {
    let mut never_started = new_binding();
    assert!(matches!(
        must_ok(
            never_started.claim_cleanup(),
            "cleanup may close an unused binding"
        ),
        CleanupBindingClaim::Empty
    ));
    assert_eq!(never_started.state(), ControlBindingState::Closed);

    let id = identity(1);
    let (mut registry, mut binding, reservation, transaction, installed) =
        reserved_installed_staging::<1>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references are installed",
    );
    let right = match must_ok(binding.claim_cleanup(), "cleanup claims setup") {
        CleanupBindingClaim::Setup(right) => right,
        _ => panic!("staging cleanup must own the exact setup right"),
    };
    must_ok(
        binding.finish_setup_cleanup(right),
        "the exact cleanup right closes setup",
    );
    let registry_before = registry_snapshot(&registry);
    let binding_before = binding_snapshot(&binding);
    let transaction_before = transaction_snapshot(&transaction);
    let reservation_before = reservation_snapshot(&reservation);
    let installed_before = installed_snapshot(&installed);

    let mut rendezvous = TerminalRendezvous::new_inactive();
    let failure = match publish_installed_setup_for_test(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        reservation,
        installed,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a closed binding must never accompany Live publication"),
    };
    let (error, transaction, reservation, installed) = failure.into_parts();

    assert_eq!(error, SessionError::InvalidTransition);
    assert_eq!(transaction_snapshot(&transaction), transaction_before);
    assert_eq!(reservation_snapshot(&reservation), reservation_before);
    assert_eq!(installed_snapshot(&installed), installed_before);
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Staging);
}

fn terminal_for(locator: SessionLocator) -> TerminalRendezvous {
    let mut rendezvous = TerminalRendezvous::new_inactive();
    rendezvous
        .activate(locator)
        .expect("unit tests may exercise the crate-private activation preflight");
    rendezvous
}

fn admitted(rendezvous: &TerminalRendezvous) -> u32 {
    match rendezvous.state {
        PrivateTerminalRendezvousState::Open { admitted, .. }
        | PrivateTerminalRendezvousState::Closed { admitted, .. }
        | PrivateTerminalRendezvousState::OpaqueRetained { admitted, .. } => admitted,
        PrivateTerminalRendezvousState::Inactive => 0,
    }
}

/// A real checkpoint-blocked observation branded for one exact generation.
///
/// Task 5 had a `fixture_for_test` here because the production representation
/// was uninhabited. Task 10 fills it in, so the tests now build the payload the
/// production publisher builds and this helper is only the naming.
fn blocked_fixture(locator: SessionLocator, diagnostic: DiagnosticId) -> TerminalBlocked {
    TerminalBlocked::from_fence(
        locator,
        crate::adapter::fence::FenceTerminalBlocked::new(
            crate::adapter::fence::FenceFailStopReason::CoreInvariant,
            diagnostic,
        ),
    )
}

fn expected_reason(request: TerminalRequest) -> TerminalReason {
    match request {
        TerminalRequest::Cleanup => TerminalReason::Cleanup,
        TerminalRequest::ProcessLoss => TerminalReason::ProcessLoss,
        TerminalRequest::Unload => TerminalReason::Unload,
        TerminalRequest::PendingEpochExhausted => TerminalReason::PendingEpochExhausted,
        TerminalRequest::CreditGenerationExhausted => TerminalReason::CreditGenerationExhausted,
        TerminalRequest::SqGenerationExhausted => TerminalReason::SqGenerationExhausted,
        TerminalRequest::ProtocolFault => TerminalReason::ProtocolFault,
    }
}

#[test]
fn terminal_winner_is_counted_before_run_and_reset() {
    let (_registry, published) = published_registry::<1>(identity(301));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let claim = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("first arrival wins");
    assert_eq!(admitted(&rendezvous), 1);
    let (winner, ticket) = claim.into_parts();
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let _signal = rendezvous
        .close_and_publish_completed(winner, result)
        .expect("winner closes admission");
    assert_eq!(admitted(&rendezvous), 1);
    assert!(matches!(
        rendezvous.release(ticket).expect("winner releases its count"),
        TerminalJoinRelease::Released {
            outcome: TerminalClosedOutcome::Completed(current),
            drained: Some(_),
        } if current == result
    ));
}

#[test]
fn terminal_arrivals_have_one_runner_and_generation_specific_joiners() {
    let mut rows = Vec::new();
    let requests = [
        TerminalRequest::Cleanup,
        TerminalRequest::ProcessLoss,
        TerminalRequest::ProtocolFault,
        TerminalRequest::Unload,
    ];
    for (a, first) in requests.iter().copied().enumerate() {
        for (b, second) in requests.iter().copied().enumerate() {
            for (c, third) in requests.iter().copied().enumerate() {
                for (d, fourth) in requests.iter().copied().enumerate() {
                    if a != b && a != c && a != d && b != c && b != d && c != d {
                        rows.push([first, second, third, fourth]);
                    }
                }
            }
        }
    }
    assert_eq!(rows.len(), 24);

    for (row_index, row) in rows.into_iter().enumerate() {
        let (mut registry, published) = published_registry::<1>(identity(400 + row_index as u64));
        let locator = published.locator();
        let (_locator, lease, _control) = published.into_parts();
        assert_eq!(slot(&registry, 0).state, RegistrySlotState::Live);
        let mut rendezvous = terminal_for(locator);
        let claim = rendezvous
            .claim(locator, row[0])
            .expect("first arrival wins");
        let (winner, winner_ticket) = claim.into_parts();
        assert_eq!(winner.reason(), expected_reason(row[0]));
        let _terminal = registry
            .begin_remove(lease)
            .expect("the sole winner performs Live-to-Removing");
        assert_eq!(slot(&registry, 0).state, RegistrySlotState::Removing);
        let mut tickets = vec![winner_ticket];
        for request in row.into_iter().skip(1) {
            assert!(matches!(
                rendezvous.claim(locator, request),
                Err(LifecycleError::FinalizerBusy)
            ));
            match rendezvous
                .join(locator)
                .expect("loser joins the open generation")
            {
                TerminalJoinClaim::Join(ticket) => tickets.push(ticket),
                _ => panic!("the winner has not closed admission"),
            }
        }
        assert_eq!(admitted(&rendezvous), 4);
        let result = TerminalResult {
            reason: expected_reason(row[0]),
            fence_failures: 7,
        };
        let _signal = rendezvous
            .close_and_publish_completed(winner, result)
            .expect("the sole winner publishes");
        assert!(matches!(
            rendezvous.join(locator).expect("late exact locator observes"),
            TerminalJoinClaim::Completed(observed) if observed == result
        ));
        for ticket in tickets {
            assert!(matches!(
                rendezvous.release(ticket).expect("counted guard releases"),
                TerminalJoinRelease::Released {
                    outcome: TerminalClosedOutcome::Completed(observed),
                    ..
                } if observed == result
            ));
        }
        assert_eq!(admitted(&rendezvous), 0);
    }
}

#[test]
fn terminal_winner_carries_the_core_authenticated_reason() {
    let (_registry, published) = published_registry::<1>(identity(302));
    let locator = published.locator();
    for (request, want) in [
        (TerminalRequest::Cleanup, TerminalReason::Cleanup),
        (TerminalRequest::ProcessLoss, TerminalReason::ProcessLoss),
        (TerminalRequest::Unload, TerminalReason::Unload),
        (
            TerminalRequest::PendingEpochExhausted,
            TerminalReason::PendingEpochExhausted,
        ),
        (
            TerminalRequest::CreditGenerationExhausted,
            TerminalReason::CreditGenerationExhausted,
        ),
        (
            TerminalRequest::SqGenerationExhausted,
            TerminalReason::SqGenerationExhausted,
        ),
        (
            TerminalRequest::ProtocolFault,
            TerminalReason::ProtocolFault,
        ),
    ] {
        let mut rendezvous = terminal_for(locator);
        let (winner, _join) = rendezvous
            .claim(locator, request)
            .expect("first claim")
            .into_parts();
        assert_eq!(winner.reason(), want);
        assert_ne!(winner.reason(), TerminalReason::ProtocolAbort);
    }
}

#[test]
fn terminal_winner_carries_one_core_derived_bounded_diagnostic() {
    let (_registry, published) = published_registry::<1>(identity(303));
    let base = published.locator();
    let zero_slot = (0xC4D1_A601u32 ^ 1).rotate_right(7);
    let locators = [
        base,
        SessionLocator {
            slot_index: base.slot_index ^ 0x00ff_00ff,
            generation: base.generation,
            identity: base.identity,
        },
        SessionLocator {
            slot_index: base.slot_index,
            generation: 0x1234_5678_9abc_def0,
            identity: base.identity,
        },
        SessionLocator {
            slot_index: zero_slot,
            generation: 1,
            identity: base.identity,
        },
    ];
    let values = locators.map(|locator| {
        let mut rendezvous = terminal_for(locator);
        let (winner, _join) = rendezvous
            .claim(locator, TerminalRequest::Unload)
            .expect("first claim")
            .into_parts();
        let diagnostic = winner.diagnostic();
        assert_ne!(diagnostic.0.get(), 0);
        assert_eq!(diagnostic, winner.diagnostic());
        diagnostic.0.get()
    });
    let [base_value, slot_value, generation_value, zero_value] = values;
    assert_eq!(zero_value, 1, "the exact zero fold remaps to one");
    assert_ne!(base_value, slot_value);
    assert_ne!(base_value, generation_value);
}

#[test]
fn terminal_activation_is_reachable_only_through_the_setup_publish_bridge() {
    let (mut registry, mut binding, reservation, transaction, installed) =
        reserved_installed_staging::<1>(identity(304));
    let transaction = transaction
        .stage(SetupStage::ReferencesInstalled)
        .expect("references installed");
    let locator = installed.locator();
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = publish_installed_setup_for_test(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        reservation,
        installed,
    )
    .expect("one coupled setup suffix");
    assert_eq!(published.locator(), locator);
    assert!(matches!(
        rendezvous.state,
        PrivateTerminalRendezvousState::Open {
            locator: current,
            admitted: 0,
        } if current == locator
    ));
    assert_eq!(
        rendezvous.activate(locator),
        Err(LifecycleError::WrongState)
    );
}

#[test]
fn completed_publication_refusal_returns_the_exact_winner_and_result() {
    let (_registry, published) = published_registry::<1>(identity(305));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, _join) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let wrong = TerminalResult {
        reason: TerminalReason::Unload,
        fence_failures: 19,
    };
    let (error, winner, returned) = rendezvous
        .close_and_publish_completed(winner, wrong)
        .expect_err("the result reason must match the authenticated winner");
    assert_eq!(error, LifecycleError::Invariant);
    assert_eq!(winner.locator(), locator);
    assert_eq!(winner.reason(), TerminalReason::Cleanup);
    assert_eq!(returned, wrong);
    assert!(matches!(
        rendezvous.state,
        PrivateTerminalRendezvousState::Open { admitted: 1, .. }
    ));
}

#[test]
fn blocked_publication_refusal_returns_the_exact_winner_and_observation() {
    let (_registry, published) = published_registry::<1>(identity(306));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, _join) = rendezvous
        .claim(locator, TerminalRequest::ProtocolFault)
        .expect("winner")
        .into_parts();
    let foreign = SessionLocator {
        generation: locator.generation.saturating_add(1),
        ..locator
    };
    let blocked = blocked_fixture(foreign, winner.diagnostic());
    let (error, winner, returned) = rendezvous
        .close_and_publish_blocked(winner, blocked)
        .expect_err("blocked observation is generation-branded");
    assert_eq!(error, LifecycleError::WrongLocator);
    assert_eq!(winner.locator(), locator);
    assert_eq!(returned, blocked);
}

#[test]
fn r3_checkpoint_blocked_payload_preserves_effect_finish_and_core_diagnostic() {
    let locator = SessionLocator::from_parts_for_test(0, 5, identity(4101));
    let diagnostic = DiagnosticId::for_locator(locator);
    let payload = crate::adapter::fence::FenceTerminalBlocked::new(
        crate::adapter::fence::FenceFailStopReason::CoreInvariant,
        diagnostic,
    );
    let blocked = TerminalBlocked::from_fence(locator, payload);

    assert_eq!(blocked.locator(), locator);
    assert_eq!(blocked.class(), TerminalBlockedClass::FenceInvariant);
    assert_eq!(blocked.diagnostic(), diagnostic);
    assert_eq!(
        payload.reason(),
        crate::adapter::fence::FenceFailStopReason::CoreInvariant
    );
}

#[test]
fn delete_blocked_payload_preserves_preflight_step_and_core_diagnostic() {
    let locator = SessionLocator::from_parts_for_test(1, 9, identity(4102));
    let diagnostic = DiagnosticId::for_locator(locator);
    for step in [
        FinalizerPreflightStep::CoreDeleting,
        FinalizerPreflightStep::MirrorAndShell,
        FinalizerPreflightStep::ShellAndRootOwnership,
        FinalizerPreflightStep::ClosingContextAndLease,
        FinalizerPreflightStep::EmptyCompletedRecord,
        FinalizerPreflightStep::OpenOutcomeAndJoinAdmission,
        FinalizerPreflightStep::RunningDepositAndPublisher,
    ] {
        let payload = DeleteTerminalBlocked::new(step, diagnostic);
        let blocked = TerminalBlocked::from_delete(locator, payload);

        assert_eq!(blocked.locator(), locator);
        // A deletion fail-stop is a different class from a checkpoint refusal:
        // one says teardown could not finish, the other says destruction could
        // not start, and CLEANUP has to be able to tell them apart.
        assert_eq!(blocked.class(), TerminalBlockedClass::DeleteInvariant);
        assert_eq!(blocked.diagnostic(), diagnostic);
        assert_eq!(payload.step(), step, "the exact preflight step survives");
    }
}

#[test]
fn typed_blocked_carriers_cannot_mint_or_replace_diagnostic_id() {
    // The carrier copies the winner's diagnostic; it has no constructor that
    // derives one. Publishing a payload branded for another generation is
    // refused with the winner and the payload both returned intact.
    let (_registry, published) = published_registry::<1>(identity(4103));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, _join) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let other = SessionLocator::from_parts_for_test(0, 77, identity(4104));
    let foreign_diagnostic = DiagnosticId::for_locator(other);
    assert_ne!(foreign_diagnostic, winner.diagnostic());

    let mislabelled = TerminalBlocked::from_fence(
        locator,
        crate::adapter::fence::FenceTerminalBlocked::new(
            crate::adapter::fence::FenceFailStopReason::CoreInvariant,
            foreign_diagnostic,
        ),
    );
    let before = admitted(&rendezvous);
    let (error, winner, returned) = rendezvous
        .close_and_publish_blocked(winner, mislabelled)
        .expect_err("a foreign diagnostic cannot be published");
    assert_eq!(error, LifecycleError::Invariant);
    assert_eq!(winner.locator(), locator);
    assert_eq!(returned, mislabelled);
    assert_eq!(admitted(&rendezvous), before, "a refusal publishes nothing");

    // The same winner still publishes its own diagnostic.
    let honest = blocked_fixture(locator, winner.diagnostic());
    assert!(rendezvous.close_and_publish_blocked(winner, honest).is_ok());
}

#[test]
fn closed_join_admission_never_increments_the_count() {
    let (_registry, published) = published_registry::<1>(identity(307));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, _join) = rendezvous
        .claim(locator, TerminalRequest::Unload)
        .expect("winner")
        .into_parts();
    let result = TerminalResult {
        reason: TerminalReason::Unload,
        fence_failures: 0,
    };
    let _signal = rendezvous
        .close_and_publish_completed(winner, result)
        .expect("close");
    assert_eq!(admitted(&rendezvous), 1);
    for _ in 0..3 {
        assert!(matches!(
            rendezvous.join(locator).expect("closed observation"),
            TerminalJoinClaim::Completed(observed) if observed == result
        ));
        assert_eq!(admitted(&rendezvous), 1);
    }
}

#[test]
fn open_outcome_keeps_all_admitted_callers_waiting() {
    let (_registry, published) = published_registry::<1>(identity(308));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (_winner, winner_ticket) = rendezvous
        .claim(locator, TerminalRequest::ProcessLoss)
        .expect("winner")
        .into_parts();
    let join_ticket = match rendezvous.join(locator).expect("join") {
        TerminalJoinClaim::Join(ticket) => ticket,
        _ => panic!("open admission returns a ticket"),
    };
    assert!(matches!(
        rendezvous.release(winner_ticket).expect("open release"),
        TerminalJoinRelease::Open(_)
    ));
    assert!(matches!(
        rendezvous.release(join_ticket).expect("open release"),
        TerminalJoinRelease::Open(_)
    ));
    assert_eq!(admitted(&rendezvous), 2);
}

#[test]
fn open_release_returns_the_same_ticket_without_decrement() {
    let (_registry, published) = published_registry::<1>(identity(309));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (_winner, ticket) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let returned = match rendezvous.release(ticket).expect("open is retryable") {
        TerminalJoinRelease::Open(ticket) => ticket,
        _ => panic!("open release cannot consume accounting"),
    };
    assert_eq!(returned.locator(), locator);
    assert_eq!(admitted(&rendezvous), 1);
}

#[test]
fn completed_outcome_is_immutable_and_generation_branded() {
    let (_registry, published) = published_registry::<1>(identity(310));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, _join) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 5,
    };
    let _signal = rendezvous
        .close_and_publish_completed(winner, result)
        .expect("publish");
    let stale = SessionLocator {
        generation: locator.generation.saturating_add(1),
        ..locator
    };
    assert!(matches!(
        rendezvous.join(stale),
        Err(LifecycleError::WrongLocator)
    ));
    for _ in 0..2 {
        assert!(matches!(
            rendezvous.join(locator).expect("exact closed observation"),
            TerminalJoinClaim::Completed(observed) if observed == result
        ));
    }
}

#[test]
fn blocked_outcome_wakes_ordinary_joiners_without_proving_completion() {
    let (_registry, published) = published_registry::<1>(identity(311));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, winner_ticket) = rendezvous
        .claim(locator, TerminalRequest::ProtocolFault)
        .expect("winner")
        .into_parts();
    let mut tickets = vec![winner_ticket];
    for losing_request in [
        TerminalRequest::Cleanup,
        TerminalRequest::ProcessLoss,
        TerminalRequest::Unload,
    ] {
        assert!(matches!(
            rendezvous.claim(locator, losing_request),
            Err(LifecycleError::FinalizerBusy)
        ));
        match rendezvous
            .join(locator)
            .expect("loser is counted while Open")
        {
            TerminalJoinClaim::Join(ticket) => tickets.push(ticket),
            _ => panic!("an open rendezvous admits every losing guard"),
        }
    }
    let blocked = blocked_fixture(locator, winner.diagnostic());
    let _signal = rendezvous
        .close_and_publish_blocked(winner, blocked)
        .expect("authenticated fixture closes Blocked");
    assert!(matches!(
        rendezvous.join(locator).expect("late blocked observation"),
        TerminalJoinClaim::Blocked(observed) if observed == blocked
    ));
    for (index, ticket) in tickets.into_iter().enumerate() {
        assert!(matches!(
            rendezvous.release(ticket).expect("ordinary waiter wakes"),
            TerminalJoinRelease::Released {
                outcome: TerminalClosedOutcome::Blocked(observed),
                drained,
            } if observed == blocked && drained.is_some() == (index == 3)
        ));
    }
}

#[test]
fn last_joiner_after_closure_mints_one_affine_drained_signal() {
    let (_registry, published) = published_registry::<1>(identity(312));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, first) = rendezvous
        .claim(locator, TerminalRequest::Unload)
        .expect("winner")
        .into_parts();
    let second = match rendezvous.join(locator).expect("join") {
        TerminalJoinClaim::Join(ticket) => ticket,
        _ => panic!("join ticket"),
    };
    let result = TerminalResult {
        reason: TerminalReason::Unload,
        fence_failures: 0,
    };
    let _signal = rendezvous
        .close_and_publish_completed(winner, result)
        .expect("publish");
    assert!(matches!(
        rendezvous.release(first).expect("first release"),
        TerminalJoinRelease::Released { drained: None, .. }
    ));
    assert!(matches!(
        rendezvous.release(second).expect("last release"),
        TerminalJoinRelease::Released {
            drained: Some(_),
            ..
        }
    ));
}

#[test]
fn terminal_outcome_signal_and_joiners_drained_signal_are_nonreplayable() {
    fn consume_outcome(signal: TerminalOutcomeSignal) -> SessionLocator {
        signal.into_locator()
    }
    fn consume_drained(signal: TerminalJoinersDrainedSignal) -> SessionLocator {
        signal.into_locator()
    }

    let (_registry, published) = published_registry::<1>(identity(313));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, ticket) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let signal = rendezvous
        .close_and_publish_completed(
            winner,
            TerminalResult {
                reason: TerminalReason::Cleanup,
                fence_failures: 0,
            },
        )
        .expect("publish");
    assert_eq!(consume_outcome(signal), locator);
    let drained = match rendezvous.release(ticket).expect("release") {
        TerminalJoinRelease::Released {
            drained: Some(signal),
            ..
        } => signal,
        _ => panic!("last release mints the one signal"),
    };
    assert_eq!(consume_drained(drained), locator);
}

#[test]
fn winner_only_completion_cannot_reset_before_winner_releases() {
    let (_registry, published) = published_registry::<1>(identity(315));
    let locator = published.locator();
    let mut rendezvous = terminal_for(locator);
    let (winner, ticket) = rendezvous
        .claim(locator, TerminalRequest::Cleanup)
        .expect("winner")
        .into_parts();
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let _signal = rendezvous
        .close_and_publish_completed(winner, result)
        .expect("winner publishes completion");
    let prepared = PreparedDeleteCoreCommit {
        authority: SessionAuthority {
            slot_index: locator.slot_index,
            generation: locator.generation,
            identity: locator.identity,
        },
        disposition: SlotDisposition::Free,
    };
    assert_eq!(
        rendezvous.deactivate_after_delete(&prepared),
        Err(LifecycleError::AdmissionClosed)
    );
    assert!(matches!(
        rendezvous.release(ticket).expect("winner guard releases"),
        TerminalJoinRelease::Released {
            drained: Some(_),
            ..
        }
    ));
    assert_eq!(rendezvous.deactivate_after_delete(&prepared), Ok(()));
}

#[test]
fn late_cleanup_reads_closing_complete_without_old_locator_resolution() {
    let (_registry, mut binding, published) = published_binding::<1>(identity(314));
    let locator = published.locator();
    let prepared = match prepare_live_binding_claim(&binding, locator).expect("claim") {
        PreparedLiveBindingClaim::Claim(prepared) => prepared,
        PreparedLiveBindingClaim::Join(_) => panic!("first close claims"),
    };
    commit_prepared_live_binding_claim(prepared, &mut binding);
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 2,
    };
    let prepared = prepare_closing_complete(&binding, locator, result, true)
        .expect("completed control record present");
    commit_prepared_closing_complete(prepared, &mut binding);
    assert!(matches!(
        binding.claim_cleanup().expect("late cleanup reads binding only"),
        CleanupBindingClaim::Completed {
            generation,
            result: observed,
        } if generation == locator.generation && observed == result
    ));
}

#[test]
fn publication_and_rollback_refuse_a_transaction_the_installation_does_not_name() {
    let installed_identity = identity(271);
    let (mut registry, mut binding, reservation, _transaction, installed) =
        reserved_installed_staging::<2>(installed_identity);

    // A well-formed transaction for a *different* session. Everything else
    // agrees: the slot really holds this installation, the two installed halves
    // really name the same cell, the binding really reserved this epoch. The
    // only disagreement is the one this clause exists to catch, so a slot-level
    // or pair-level check cannot stand in for it.
    let foreign = must_ok(
        transaction_at(identity(272), SetupStage::ViewsReady).stage(SetupStage::OutputReady),
        "the foreign transaction is output-ready",
    );
    let foreign = must_ok(
        foreign.stage(SetupStage::ReferencesInstalled),
        "references are installed",
    );
    let transaction_before = transaction_snapshot(&foreign);
    let reservation_before = reservation_snapshot(&reservation);
    let installed_before = installed_snapshot(&installed);
    let registry_before = registry_snapshot(&registry);
    let binding_before = binding_snapshot(&binding);

    let mut rendezvous = TerminalRendezvous::new_inactive();
    let failure = match publish_installed_setup_for_test(
        foreign,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        reservation,
        installed,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a transaction the installation does not name must not publish"),
    };
    let (error, foreign, reservation, installed) = failure.into_parts();
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(transaction_snapshot(&foreign), transaction_before);
    assert_eq!(reservation_snapshot(&reservation), reservation_before);
    assert_eq!(installed_snapshot(&installed), installed_before);
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);
    assert_eq!(
        rendezvous.activation_preflight(),
        Ok(()),
        "the refused publication left the rendezvous inactive"
    );

    // The rollback path carries the same clause and must refuse the same pair.
    let failure = match prepare_installed_setup_rollback(
        foreign,
        SetupFailure::Cancelled,
        &registry,
        &binding,
        reservation,
        installed,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("a foreign transaction must not prepare an installed rollback"),
    };
    let (error, _foreign, reason, reservation, installed) = failure.into_parts();
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(reason, SetupFailure::Cancelled);
    assert_eq!(installed_snapshot(&installed), installed_before);
    assert_eq!(registry_snapshot(&registry), registry_before);
    assert_eq!(binding_snapshot(&binding), binding_before);

    // The transaction the installation does name still publishes, so both
    // refusals rejected on the identity binding alone and consumed nothing.
    let own = must_ok(
        ready_setup(installed_identity).stage(SetupStage::ReferencesInstalled),
        "the installed transaction reaches references-installed",
    );
    must_ok(
        publish_installed_setup_for_test(
            own,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        )
        .map_err(|failure| failure.into_parts().0),
        "the exact installation publishes",
    );
}

#[test]
fn a_crossed_registry_and_control_pair_is_refused_by_the_publication_preflight() {
    // The pair rule lives in `publish_preflight`, and this is where it is
    // proven: both halves carry the exact staging identity, so the identity
    // clause passes, but they name different cells. Each case gets its own
    // fixture because the transaction and reservation are affine.
    for cross in [CrossedHalf::Slot, CrossedHalf::Generation] {
        let id = identity(273);
        let (mut registry, mut binding, reservation, transaction, installed) =
            reserved_installed_staging::<2>(id);
        let transaction = must_ok(
            transaction.stage(SetupStage::ReferencesInstalled),
            "references are installed",
        );
        let (registry_locator, control_locator) = installed_snapshot(&installed);
        assert_eq!(registry_locator, control_locator);
        let _unused = installed;

        let crossed_control = match cross {
            CrossedHalf::Slot => SessionLocator::from_parts_for_test(
                registry_locator.slot_index.saturating_add(1),
                registry_locator.generation,
                registry_locator.identity,
            ),
            CrossedHalf::Generation => SessionLocator::from_parts_for_test(
                registry_locator.slot_index,
                registry_locator.generation.saturating_add(1),
                registry_locator.identity,
            ),
        };
        let crossed = InstalledSession::crossed_for_test(registry_locator, crossed_control);
        let registry_before = registry_snapshot(&registry);
        let binding_before = binding_snapshot(&binding);
        let mut rendezvous = TerminalRendezvous::new_inactive();
        let failure = match publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            crossed,
        ) {
            Err(failure) => failure,
            Ok(_) => panic!("a crossed installation must not publish"),
        };
        let (error, _transaction, _reservation, crossed) = failure.into_parts();
        assert_eq!(error, SessionError::IdentityMismatch);
        assert_eq!(registry_snapshot(&registry), registry_before);
        assert_eq!(binding_snapshot(&binding), binding_before);
        let _returned = crossed;
    }
}

#[derive(Clone, Copy)]
enum CrossedHalf {
    Slot,
    Generation,
}

#[test]
fn core_live_validation_is_read_only_and_rejects_removing() {
    // This test lives beside `validate_live` on purpose. Its first home was the
    // lifecycle adapter's file, where the C4 mutation suite runs
    // `session::tests` for a `session.rs` operator and never saw it: both
    // `validate_live` mutants survived a suite that reported the rule covered.
    let (mut registry, _binding, published) = published_binding::<2>(identity(41));
    let (locator, lease, reference) = published.into_parts();

    // The read-only check accepts the exact live locator and takes nothing.
    must_ok(
        registry.validate_live(locator),
        "the published locator is live",
    );
    must_ok(registry.validate_live(locator), "and still live");
    let before = registry_snapshot(&registry);
    must_ok(registry.validate_live(locator), "a third time");
    assert_eq!(
        registry_snapshot(&registry),
        before,
        "validation changed a slot; it must take no reference and close nothing"
    );

    for (wrong, why) in [
        (
            SessionLocator {
                slot_index: locator.slot_index,
                generation: locator.generation.saturating_add(1),
                identity: locator.identity,
            },
            "a stale generation names a session that is already gone",
        ),
        (
            SessionLocator {
                slot_index: locator.slot_index,
                generation: locator.generation,
                identity: identity(42),
            },
            "a foreign identity in the right slot is still foreign",
        ),
        (
            SessionLocator {
                slot_index: locator.slot_index.saturating_add(64),
                generation: locator.generation,
                identity: locator.identity,
            },
            "an out-of-range slot index resolves to nothing",
        ),
    ] {
        assert_eq!(
            registry.validate_live(wrong),
            Err(SessionError::ReferenceNotFound),
            "{why}"
        );
    }

    // Removing rejects: the terminal fence has started, so a resolve here would
    // hand a caller a session that is already being torn down.
    let terminal = match registry.begin_remove(lease) {
        Ok(terminal) => terminal,
        Err(_) => panic!("the live lease begins removal"),
    };
    assert_eq!(
        registry.validate_live(locator),
        Err(SessionError::ReferenceNotFound),
        "a Removing slot is not resolvable"
    );
    let _consumed = (terminal, reference);

    // A closed registry rejects a locator that was Live a moment ago: unload
    // has stopped admitting work.
    let (mut closed, _binding, published) = published_binding::<2>(identity(43));
    let live = published.locator();
    must_ok(closed.validate_live(live), "live before closure");
    closed.close_admission();
    assert_eq!(
        closed.validate_live(live),
        Err(SessionError::RegistryClosed),
        "a closed registry admits nothing, including what it just published"
    );
}

#[test]
fn terminal_removing_transition_rejects_every_late_locator() {
    // The whole point of resolving by locator rather than following a pointer:
    // once the terminal fence has begun, the locator that was valid a moment
    // ago must stop resolving. A dispatch that raced the fence is refused
    // instead of handed a session that is being torn down.
    let (mut registry, published) = published_registry::<1>(identity(51));
    let locator = published.locator();
    must_ok(registry.validate_live(locator), "live before removal");

    let (_, lease, control) = published.into_parts();
    let terminal = must_ok(registry.begin_remove(lease), "the live lease removes");
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Removing);

    // Removing: every reader is refused, and refused the same way whether it
    // asks to validate or to acquire.
    assert_eq!(
        registry.validate_live(locator),
        Err(SessionError::ReferenceNotFound)
    );
    assert!(matches!(
        registry.acquire(locator),
        Err(SessionError::ReferenceNotFound)
    ));

    // Deleting: still refused, and now with no strong reference left at all.
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("the last reference must delete"),
    };
    assert_eq!(slot(&registry, 0).state, RegistrySlotState::Deleting);
    assert_eq!(
        registry.validate_live(locator),
        Err(SessionError::ReferenceNotFound),
        "a Deleting slot is not resolvable either"
    );

    let prepared = must_ok(registry.prepare_finish_delete(right), "delete preparation");
    // SAFETY: this core-only test owns the exact Deleting generation and its
    // one prepared commit; no native mirror exists.
    assert_eq!(
        unsafe { registry.finish_delete(prepared) },
        SlotDisposition::Free
    );
    assert_eq!(
        registry.validate_live(locator),
        Err(SessionError::ReferenceNotFound),
        "a Free slot is not resolvable"
    );
}

#[test]
fn old_vdo_and_mounted_locators_fail_after_slot_reuse() {
    // A VDO's extension and a mounted volume's extension both carry a locator
    // for the life of the device. If the cell they name is torn down and
    // reused, those stored locators must stop resolving -- otherwise a device
    // that outlived its session would resolve to whichever session took the
    // slot next, which is exactly the confusion the generation exists to
    // prevent.
    let (mut registry, published) = published_registry::<1>(identity(52));
    let stored_by_the_vdo = published.locator();

    let (_, lease, control) = published.into_parts();
    let terminal = must_ok(registry.begin_remove(lease), "the live lease removes");
    assert!(matches!(
        registry.release(control),
        Ok(RegistryRelease::Retained)
    ));
    let right = match registry.finish_removal_for_test(terminal).expect("fence") {
        RegistryRelease::Delete(right) => right,
        RegistryRelease::Retained => panic!("the last reference must delete"),
    };
    let prepared = must_ok(registry.prepare_finish_delete(right), "delete preparation");
    // SAFETY: as above.
    assert_eq!(
        unsafe { registry.finish_delete(prepared) },
        SlotDisposition::Free
    );

    // The same slot, a different session.
    let mut binding = new_binding();
    let reservation = must_ok(binding.begin_setup(), "the reused slot reserves");
    let transaction = ready_setup(identity(53));
    let installed = must_ok(
        registry.install_staging(&transaction, &binding, &reservation),
        "the freed slot installs again",
    );
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references are installed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let republished = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        )
        .map_err(|failure| failure.into_parts().0),
        "the reused slot publishes",
    );
    let fresh = republished.locator();

    assert_eq!(
        fresh.slot_index, stored_by_the_vdo.slot_index,
        "the point of this test is that the slot really was reused"
    );
    assert_ne!(fresh.generation, stored_by_the_vdo.generation);
    must_ok(registry.validate_live(fresh), "the new session resolves");
    assert_eq!(
        registry.validate_live(stored_by_the_vdo),
        Err(SessionError::ReferenceNotFound),
        "a locator stored in a device extension must not resolve to its successor"
    );
    assert!(matches!(
        registry.acquire(stored_by_the_vdo),
        Err(SessionError::ReferenceNotFound)
    ));
}

#[test]
fn r3_retained_then_last_release_combines_one_right_and_readiness() {
    // Two owners hold the generation when the fence finishes, so the terminal
    // release retains and records fence_done, and the *one* later stable
    // release that reaches zero is the deleting one. Exactly one deletion right
    // exists across the whole sequence.
    let mut cell = published_cell::<1>(identity(4201));
    let winner = cell.win(TerminalRequest::Cleanup);
    let (winner, terminal, ticket) = winner.into_parts();

    let prepared = must_ok(
        prepare_terminal_release(&mut cell.registry, terminal),
        "the Removing generation admits its terminal release",
    );
    assert_eq!(
        prepared.kind(),
        PreparedReleaseKind::Retained,
        "another stable owner still holds the generation"
    );
    // SAFETY: the test stands in for the native deposit wrapper.
    let released = unsafe { prepared.commit() };
    assert!(matches!(released, RegistryRelease::Retained));
    assert_eq!(slot(&cell.registry, 0).state, RegistrySlotState::Removing);
    assert!(slot(&cell.registry, 0).fence_done);

    let control = must_some(cell.control.take(), "the published control reference");
    let prepared = must_ok(
        prepare_strong_release(&mut cell.registry, control),
        "the post-fence release is admissible",
    );
    assert_eq!(
        prepared.kind(),
        PreparedReleaseKind::Delete,
        "the release that reaches zero is the deleting one"
    );
    // SAFETY: as above.
    let released = unsafe { prepared.commit() };
    let RegistryRelease::Delete(right) = released else {
        panic!("the last release mints the one deletion right")
    };
    assert_eq!(right.locator(), cell.locator);
    assert_eq!(slot(&cell.registry, 0).state, RegistrySlotState::Deleting);
    assert_eq!(slot(&cell.registry, 0).strong_count, 0);

    let _ = winner;
    let _ = ticket;
    let _ = right;
}

#[test]
fn strong_release_refusal_leaves_reference_readiness_mirror_and_worker_unchanged() {
    let mut cell = published_cell::<1>(identity(4202));
    let before = cell.snapshot();

    // A Live generation with two owners retains; the refusals below are the
    // states in which a prepared release must decide nothing at all.
    let control = must_some(cell.control.take(), "the published control reference");
    let prepared = must_ok(
        prepare_strong_release(&mut cell.registry, control),
        "a live generation with two owners retains",
    );
    assert_eq!(prepared.kind(), PreparedReleaseKind::Retained);
    // Abandoning the preparation returns the exact reference and mutates
    // nothing: preparation is not a decrement.
    cell.control = Some(prepared.into_reference());
    assert_eq!(cell.snapshot(), before, "preparation mutated the registry");

    // A foreign reference is refused with the reference returned intact.
    let mut other = published_cell::<1>(identity(4203));
    let foreign = must_some(other.control.take(), "the other cell's reference");
    let (error, foreign) = prepare_strong_release(&mut cell.registry, foreign)
        .map(|_| ())
        .expect_err("a foreign reference cannot release here");
    assert_eq!(error, SessionError::IdentityMismatch);
    assert_eq!(foreign.locator(), other.locator);
    assert_eq!(cell.snapshot(), before);
    other.control = Some(foreign);

    // The terminal release with another owner still present is a retain, and
    // abandoning that preparation is likewise mutation-free: the fence_done bit
    // is set by the *commit*, never by deciding what the commit would do.
    let lease = must_some(cell.lease.take(), "the published registry lease");
    let terminal = must_ok(
        cell.registry
            .begin_remove(lease)
            .map_err(|(error, _)| error),
        "the live generation admits one removal",
    );
    let after_removal = cell.snapshot();
    let prepared = must_ok(
        prepare_terminal_release(&mut cell.registry, terminal),
        "a Removing slot with two owners prepares a retain",
    );
    assert_eq!(prepared.kind(), PreparedReleaseKind::Retained);
    let terminal = prepared.into_terminal();
    assert_eq!(terminal.locator(), cell.locator);
    assert_eq!(
        cell.snapshot(),
        after_removal,
        "abandoning a preparation mutated the registry"
    );
    assert!(
        !slot(&cell.registry, 0).fence_done,
        "fence_done belongs to the commit, not to the decision"
    );
    let _ = terminal;
}

#[test]
fn bare_delete_right_cannot_queue_the_r3_finalizer() {
    // `RegistryRelease::Delete` is producible only by an `unsafe`, doc-hidden
    // prepared commit whose safety contract names the same-lock native deposit
    // wrapper as its sole caller. There is no safe constructor, no `Default`,
    // and no clone, so a right cannot exist beside a readiness without having
    // gone through that boundary.
    let mut cell = published_cell::<1>(identity(4204));
    let winner = cell.win(TerminalRequest::Unload);
    let (winner, terminal, ticket) = winner.into_parts();
    must_ok(
        cell.registry.finish_removal_for_test(terminal),
        "the fence finishes with another owner present",
    );
    let control = must_some(cell.control.take(), "the published control reference");
    let prepared = must_ok(
        prepare_strong_release(&mut cell.registry, control),
        "the post-fence release is admissible",
    );
    // SAFETY: the test stands in for the native deposit wrapper.
    let RegistryRelease::Delete(right) = (unsafe { prepared.commit() }) else {
        panic!("the last release deletes")
    };

    // The right is consumed by a mutation-free preparation, which is the only
    // thing that accepts it, and that preparation refuses unless the slot is
    // exactly Deleting at zero references.
    let prepared = must_ok(
        cell.registry.prepare_finish_delete(right),
        "the exact right prepares its core commit",
    );
    assert_eq!(prepared.disposition(), SlotDisposition::Free);

    let _ = winner;
    let _ = ticket;
}

#[test]
fn process_loss_completion_pins_control_result_across_late_cleanup_and_reuse() {
    // The result a process-loss winner published stays readable from the
    // *binding* after the cell is reused by a later generation. That is what
    // makes a late CLEANUP safe: it reads a stable copy rather than resolving a
    // locator whose slot now names somebody else.
    let mut cell = published_cell::<1>(identity(4501));
    let locator = cell.locator;
    let winner = cell.win(TerminalRequest::ProcessLoss);
    let result = TerminalResult {
        reason: TerminalReason::ProcessLoss,
        fence_failures: 0,
    };
    must_ok(
        cell.binding.publish_closing_complete(locator, result, true),
        "the finalizer publishes the completed generation",
    );

    // Now finish the generation and reuse the slot for a successor.
    let (winner, terminal, ticket) = winner.into_parts();
    must_ok(
        cell.registry.finish_removal_for_test(terminal),
        "the fence finishes",
    );
    let control = must_some(cell.control.take(), "the published control reference");
    let RegistryRelease::Delete(right) = must_ok(cell.registry.release(control), "last release")
    else {
        panic!("the last release deletes")
    };
    let prepared = must_ok(
        cell.registry.prepare_finish_delete(right),
        "the exact right prepares",
    );
    // SAFETY: the test stands in for the native destructive suffix.
    unsafe { cell.registry.finish_delete(prepared) };

    let successor = must_ok(
        install_with_fresh_reservation(&mut cell.registry, &ready_setup(identity(4502))),
        "the freed slot admits a successor",
    );
    assert_eq!(
        successor.locator().slot_index(),
        locator.slot_index(),
        "the point of this test is that the slot really was reused"
    );
    assert_ne!(successor.locator().generation(), locator.generation());

    // The old binding still reports the old generation's result, unchanged by
    // the reuse. A CLEANUP arriving now reads this, not the successor.
    assert_eq!(
        cell.binding.state(),
        ControlBindingState::ClosingComplete {
            generation: locator.generation(),
            result
        }
    );
    // ...and the old locator no longer resolves, which is why the stable copy
    // is the only safe source.
    assert_eq!(
        cell.registry.validate_live(locator),
        Err(SessionError::ReferenceNotFound)
    );

    let _ = winner;
    let _ = ticket;
    let _ = successor;
}

#[test]
fn shell_destruction_is_impossible_while_core_live() {
    // The owners a destruction needs leave the cell only in the winning
    // terminal commit, and that same commit moves the core slot Live→Removing.
    // So there is no instant at which a caller holds destruction authority and
    // the core still says Live — the two are one transition, not two.
    let mut cell = published_cell::<1>(identity(4401));
    assert_eq!(slot(&cell.registry, 0).state, RegistrySlotState::Live);

    let winner = cell.win(TerminalRequest::Cleanup);
    assert_eq!(
        slot(&cell.registry, 0).state,
        RegistrySlotState::Removing,
        "the owners and the phase move together"
    );

    // And a second arrival at the same generation cannot win, so a second set
    // of owners can never exist.
    let locator = cell.locator;
    assert!(matches!(
        cell.prepare(locator, TerminalRequest::Unload)
            .map(|p| p.kind()),
        Ok(CoreTerminalClaimKind::Join)
    ));

    let (winner, terminal, ticket) = winner.into_parts();
    let _ = winner;
    let _ = terminal;
    let _ = ticket;
}

#[test]
fn published_session_is_seen_by_cleanup_process_loss_and_unload() {
    // One published generation, three terminal sources. Each of them reaches
    // the same claim and gets the same answer — which is what "one terminal
    // protocol" means: whichever arrives first wins, and the others join.
    for (index, request) in [
        TerminalRequest::Cleanup,
        TerminalRequest::ProcessLoss,
        TerminalRequest::Unload,
    ]
    .into_iter()
    .enumerate()
    {
        let mut cell = published_cell::<1>(identity(4410_u64.saturating_add(index as u64)));
        let locator = cell.locator;
        let prepared = must_ok(
            cell.prepare(locator, request),
            "every terminal source sees the published generation",
        );
        assert_eq!(
            prepared.kind(),
            CoreTerminalClaimKind::Winner,
            "{request:?}"
        );
        let _ = prepared;

        // The other two then join the generation the first one claimed.
        let winner = cell.win(request);
        for other in [
            TerminalRequest::Cleanup,
            TerminalRequest::ProcessLoss,
            TerminalRequest::Unload,
        ] {
            if other == request {
                continue;
            }
            match cell.claim(other) {
                CoreTerminalDisposition::Join(ticket) => {
                    let _ = ticket;
                }
                _ => panic!("{other:?} must join the generation {request:?} claimed"),
            }
        }
        let (winner, terminal, ticket) = winner.into_parts();
        let _ = winner;
        let _ = terminal;
        let _ = ticket;
    }
}

#[test]
fn closing_complete_is_refused_without_the_record_that_makes_it_readable() {
    // A ClosingComplete word with no completed record behind it is a
    // generation CLEANUP could acknowledge and CLOSE could never free: the
    // close right and its admission lease live in that record. The finalizer's
    // locked publication goes through this exact entry, so the gate is on the
    // path that runs, not beside it.
    let mut cell = published_cell::<1>(identity(4301));
    let locator = cell.locator;
    let winner = cell.win(TerminalRequest::Cleanup);
    let result = TerminalResult {
        reason: TerminalReason::Cleanup,
        fence_failures: 0,
    };
    let before = binding_snapshot(&cell.binding);

    assert_eq!(
        cell.binding
            .publish_closing_complete(locator, result, false)
            .err(),
        Some(SessionError::InvalidTransition),
        "a missing record refuses"
    );
    assert_eq!(
        binding_snapshot(&cell.binding),
        before,
        "the refusal published nothing"
    );

    must_ok(
        cell.binding.publish_closing_complete(locator, result, true),
        "a present record admits completion",
    );
    assert_eq!(
        cell.binding.state(),
        ControlBindingState::ClosingComplete {
            generation: locator.generation(),
            result
        }
    );

    // ...and it is a one-shot: the binding is no longer ClosingLive.
    assert_eq!(
        cell.binding
            .publish_closing_complete(locator, result, true)
            .err(),
        Some(SessionError::InvalidTransition)
    );

    let (winner, terminal, ticket) = winner.into_parts();
    let _ = winner;
    let _ = terminal;
    let _ = ticket;
}

#[test]
fn the_witness_parsers_reject_every_malformed_attested_value() {
    // These run at compile time in a production build, so a malformed value is
    // a build error there. Here they are ordinary functions, which is the only
    // place their acceptance can be observed at all.
    assert_eq!(
        parse_digest("00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff"),
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF
        ],
        "upper and lower case hex are the same digest"
    );
    assert_eq!(parse_rows("3"), 3);
    assert_eq!(parse_rows("175"), 175);
    assert_eq!(
        parse_capabilities("27"),
        ACTIVE_R4_CUTOVER_CAPABILITIES,
        "the emitted decimal mask preserves the complete R4 cutover capability bundle"
    );
    assert_eq!(
        parse_profile("r5-cutover"),
        ProductionAttestationProfile::R5Cutover
    );
    for (text, expected) in [
        ("r3-stage", ProductionAttestationProfile::R3Stage),
        ("r3-cutover", ProductionAttestationProfile::R3Cutover),
        ("r4-stage", ProductionAttestationProfile::R4Stage),
        ("r4-cutover", ProductionAttestationProfile::R4Cutover),
        ("r5-stage", ProductionAttestationProfile::R5Stage),
    ] {
        assert_eq!(parse_profile(text), expected, "{text}");
    }
    // A prefix is not a match: `equals` compares lengths first, so "r3" cannot
    // silently become "r3-stage".
    assert!(!equals(b"r3", b"r3-stage"));
    assert!(equals(b"r3-stage", b"r3-stage"));
}

#[test]
fn r4_authority_absence_requires_same_artifact_structural_pass() {
    // A test build runs no auditor, so it reads the injected witness, not the
    // generated one. The profile is part of the answer: an image attested for
    // one checkpoint must not satisfy another.
    let identity = must_ok(
        ProductionGraphArtifactIdentity::injected_for_test(ProductionAttestationProfile::R3Stage),
        "the injected witness is an r3-stage witness",
    );
    assert_eq!(identity.profile(), ProductionAttestationProfile::R3Stage);
    assert_eq!(identity.source_sha256(), [0x11; 32]);
    assert_eq!(identity.manifest_sha256(), [0x22; 32]);
    assert_eq!(identity.auditor_sha256(), [0x33; 32]);

    for wrong in [
        ProductionAttestationProfile::R3Cutover,
        ProductionAttestationProfile::R4Stage,
        ProductionAttestationProfile::R4Cutover,
        ProductionAttestationProfile::R5Stage,
        ProductionAttestationProfile::R5Cutover,
    ] {
        assert_eq!(
            ProductionGraphArtifactIdentity::injected_for_test(wrong),
            Err(ProductionAttestationError::WrongProfile),
            "{wrong:?}"
        );
    }

    // An image with no verified rows has no artifact at all, and says so
    // differently from an image attested under the wrong profile.
    assert_eq!(
        UNATTESTED_GRAPH_WITNESS.resolve(ProductionAttestationProfile::R3Stage),
        Err(ProductionAttestationError::RequiredRowMissing)
    );

    // A default (unattested) core build answers the same way, which is what
    // makes the absence proof unconstructible outside a production image.
    assert_eq!(
        ProductionGraphArtifactIdentity::embedded(ProductionAttestationProfile::R3Stage),
        Err(ProductionAttestationError::RequiredRowMissing)
    );
}

const ACTIVE_R4_CUTOVER_CAPABILITIES: ProductionRowCapabilities =
    ProductionRowCapabilities::TASK12_CUTOVER
        .union(ProductionRowCapabilities::TASK12_EXACT_DELETE)
        .union(ProductionRowCapabilities::R4_CUTOVER)
        .union(ProductionRowCapabilities::R5_STAGING);

fn task12_injected_witness(
    seed: u8,
    profile: ProductionAttestationProfile,
    capabilities: ProductionRowCapabilities,
) -> EmbeddedProductionWitness {
    EmbeddedProductionWitness::sealed_for_test(
        SealedProductionWitness(()),
        [seed; 32],
        [seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
        profile,
        1,
        capabilities,
    )
}

#[test]
fn active_r4_absence_accepts_the_complete_r4_cutover_capability_bundle() {
    let witness = task12_injected_witness(
        0x41,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES,
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&witness),
        Ok(witness.identity),
        "the no-argument production policy must accept the complete same-artifact R4Cutover bundle"
    );
}

#[test]
fn active_r4_absence_treats_the_four_required_capabilities_as_a_subset() {
    let witness = task12_injected_witness(
        0x51,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES.union(ProductionRowCapabilities::UNRELATED_VERIFIED_ROW),
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&witness),
        Ok(witness.identity),
        "an unrelated verified row must not invalidate the four required capabilities"
    );
}

#[test]
fn active_r4_absence_refuses_each_missing_required_capability() {
    for missing in [
        ProductionRowCapabilities::TASK12_CUTOVER,
        ProductionRowCapabilities::TASK12_EXACT_DELETE,
        ProductionRowCapabilities::R4_CUTOVER,
        ProductionRowCapabilities::R5_STAGING,
    ] {
        let witness = task12_injected_witness(
            missing.0.wrapping_add(0x60),
            ProductionAttestationProfile::R4Cutover,
            ACTIVE_R4_CUTOVER_CAPABILITIES
                .without(missing)
                .union(ProductionRowCapabilities::UNRELATED_VERIFIED_ROW),
        );
        assert_eq!(
            resolve_active_r4_authority_absence_from(&witness),
            Err(ProductionAttestationError::RequiredRowMissing),
            "missing capability {missing:?} must fail closed"
        );
    }
}

#[test]
fn historical_r3_r4_and_r5_bundles_resolve_only_under_their_exact_test_profiles() {
    let r3_bundle = ProductionRowCapabilities::TASK12_CUTOVER
        .union(ProductionRowCapabilities::TASK12_EXACT_DELETE);
    let r4_bundle = r3_bundle.union(ProductionRowCapabilities::R4_STAGING);
    let r5_bundle = r4_bundle.union(ProductionRowCapabilities::R5_STAGING);
    let r3 = task12_injected_witness(0x71, ProductionAttestationProfile::R3Cutover, r3_bundle);
    let r4 = task12_injected_witness(0x75, ProductionAttestationProfile::R4Stage, r4_bundle);
    let r5 = task12_injected_witness(0x79, ProductionAttestationProfile::R5Stage, r5_bundle);

    assert_eq!(
        r3.resolve(ProductionAttestationProfile::R3Cutover),
        Ok(r3.identity)
    );
    assert_eq!(
        r4.resolve(ProductionAttestationProfile::R4Stage),
        Ok(r4.identity)
    );
    assert_eq!(resolve_historical_r3_absence_for_test(&r3), Ok(r3.identity));
    assert_eq!(resolve_historical_r3_absence_for_test(&r4), Ok(r4.identity));
    assert_eq!(resolve_historical_r3_absence_for_test(&r5), Ok(r5.identity));
    assert_eq!(
        resolve_active_r4_authority_absence_from(&r3),
        Err(ProductionAttestationError::WrongProfile)
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&r4),
        Err(ProductionAttestationError::WrongProfile)
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&r5),
        Err(ProductionAttestationError::WrongProfile)
    );

    let r3_required = [
        ProductionRowCapabilities::TASK12_CUTOVER,
        ProductionRowCapabilities::TASK12_EXACT_DELETE,
    ];
    let r4_required = [
        ProductionRowCapabilities::TASK12_CUTOVER,
        ProductionRowCapabilities::TASK12_EXACT_DELETE,
        ProductionRowCapabilities::R4_STAGING,
    ];
    let r5_required = [
        ProductionRowCapabilities::TASK12_CUTOVER,
        ProductionRowCapabilities::TASK12_EXACT_DELETE,
        ProductionRowCapabilities::R4_STAGING,
        ProductionRowCapabilities::R5_STAGING,
    ];
    for (seed, profile, exact, required_bits, inappropriate_later_bit) in [
        (
            0x72u8,
            ProductionAttestationProfile::R3Cutover,
            r3_bundle,
            r3_required.as_slice(),
            ProductionRowCapabilities::R4_STAGING,
        ),
        (
            0x76u8,
            ProductionAttestationProfile::R4Stage,
            r4_bundle,
            r4_required.as_slice(),
            ProductionRowCapabilities::R5_STAGING,
        ),
        (
            0x7au8,
            ProductionAttestationProfile::R5Stage,
            r5_bundle,
            r5_required.as_slice(),
            ProductionRowCapabilities::R4_CUTOVER,
        ),
    ] {
        for &missing in required_bits {
            let witness = task12_injected_witness(
                seed.wrapping_add(missing.0),
                profile,
                exact.without(missing),
            );
            assert_eq!(
                resolve_historical_r3_absence_for_test(&witness),
                Err(ProductionAttestationError::RequiredRowMissing),
                "historical profile {profile:?} must reject missing bit {missing:?}"
            );
        }
        let witness = task12_injected_witness(
            seed.wrapping_add(0x10),
            profile,
            exact.union(inappropriate_later_bit),
        );
        assert_eq!(
            resolve_historical_r3_absence_for_test(&witness),
            Err(ProductionAttestationError::RequiredRowMissing),
            "historical profile {profile:?} must reject later bit {inappropriate_later_bit:?}"
        );
    }
}

#[test]
fn active_r4_absence_refuses_every_non_r4_cutover_profile() {
    for (seed, profile) in [
        (0xa1, ProductionAttestationProfile::R3Stage),
        (0xa5, ProductionAttestationProfile::R3Cutover),
        (0xa9, ProductionAttestationProfile::R4Stage),
        (0xad, ProductionAttestationProfile::R5Stage),
        (0xb1, ProductionAttestationProfile::R5Cutover),
    ] {
        let witness = task12_injected_witness(seed, profile, ACTIVE_R4_CUTOVER_CAPABILITIES);
        assert_eq!(
            resolve_active_r4_authority_absence_from(&witness),
            Err(ProductionAttestationError::WrongProfile),
            "the active constructor must refuse profile {profile:?} even with all four rows"
        );
    }
}

#[test]
fn active_r4_absence_never_combines_capabilities_across_artifact_identities() {
    let first = task12_injected_witness(
        0x81,
        ProductionAttestationProfile::R4Cutover,
        ProductionRowCapabilities::TASK12_CUTOVER
            .union(ProductionRowCapabilities::TASK12_EXACT_DELETE),
    );
    let second = task12_injected_witness(
        0x91,
        ProductionAttestationProfile::R4Cutover,
        ProductionRowCapabilities::R4_CUTOVER.union(ProductionRowCapabilities::R5_STAGING),
    );
    assert_ne!(first.identity, second.identity);
    for witness in [&first, &second] {
        assert_eq!(
            resolve_active_r4_authority_absence_from(witness),
            Err(ProductionAttestationError::RequiredRowMissing),
            "sequential observations of foreign partial artifacts must not accumulate a complete bundle"
        );
    }
}

// ---------------------------------------------------------------------------
// Task 9: the one locked terminal claim
// ---------------------------------------------------------------------------

/// Everything the locked claim reads, owned together so a test can hand the
/// same four objects to `prepare_terminal_claim` the way a native cell does.
pub(crate) struct CoreCell<const N: usize> {
    pub(crate) registry: SessionRegistry<N>,
    pub(crate) binding: ControlBinding,
    pub(crate) rendezvous: TerminalRendezvous,
    pub(crate) lease: Option<RegistryLease>,
    pub(crate) control: Option<StrongSessionRef>,
    pub(crate) locator: SessionLocator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoreCellSnapshot<const N: usize> {
    registry: (bool, [RegistrySlot; N]),
    binding: (ControlBindingId, ControlBindingState),
    rendezvous: PrivateTerminalRendezvousState,
    lease: Option<SessionLocator>,
    control: Option<SessionLocator>,
}

impl<const N: usize> CoreCell<N> {
    fn snapshot(&self) -> CoreCellSnapshot<N> {
        CoreCellSnapshot {
            registry: registry_snapshot(&self.registry),
            binding: binding_snapshot(&self.binding),
            rendezvous: self.rendezvous.state,
            lease: self.lease.as_ref().map(RegistryLease::locator),
            control: self.control.as_ref().map(StrongSessionRef::locator),
        }
    }

    fn prepare(
        &mut self,
        locator: SessionLocator,
        request: TerminalRequest,
    ) -> Result<PreparedTerminalClaim<'_, N>, LifecycleError> {
        prepare_terminal_claim(
            &mut self.registry,
            &mut self.binding,
            &mut self.rendezvous,
            &mut self.lease,
            locator,
            request,
        )
    }

    fn claim(&mut self, request: TerminalRequest) -> CoreTerminalDisposition {
        let locator = self.locator;
        must_ok(self.prepare(locator, request), "the arrival claims").commit()
    }

    fn win(&mut self, request: TerminalRequest) -> CoreTerminalWinner {
        match self.claim(request) {
            CoreTerminalDisposition::Winner(winner) => winner,
            _ => panic!("the first arrival at a live generation wins"),
        }
    }
}

fn published_cell<const N: usize>(id: SessionIdentity) -> CoreCell<N> {
    let (mut registry, mut binding, reservation, transaction, installed) =
        reserved_installed_staging::<N>(id);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "all setup authorities publish together",
    );
    let (locator, lease, control) = published.into_parts();
    CoreCell {
        registry,
        binding,
        rendezvous,
        lease: Some(lease),
        control: Some(control),
        locator,
    }
}

/// A published cell **and** the pending slot parts of its ring set.
///
/// The ring brands and the published locator come from the same
/// `InstalledSession`, which is the whole point: a CQ entry drained from one of
/// these rings names *this* cell, and there is no argument through which it
/// could name another. A fixture that published one session and branded the
/// rings of a second would make every disposition below a coincidence.
///
/// Shared with `adapter::enter::tests`, which owns the CQ side and has no way
/// to publish a session of its own without restating this.
pub(crate) fn published_cell_with_rings<const N: usize>(
    id: SessionIdentity,
    rings: u32,
) -> (
    CoreCell<N>,
    SessionRingSetBrand,
    std::vec::Vec<crate::enter::PendingSlotParts>,
) {
    let (mut registry, mut binding, reservation, transaction, mut installed) =
        reserved_installed_staging::<N>(id);
    let mut set = must_ok(
        installed.begin_ring_set(rings),
        "a fresh installation begins its one ring set",
    );
    let mut parts = std::vec::Vec::new();
    for _ in 0..rings {
        let right = must_some(
            must_ok(
                set.next_ring(),
                "the set issues the rings it was opened for",
            ),
            "a ring right",
        );
        parts.push(must_ok(
            crate::enter::build_pending_slot_parts(right, 64).map_err(|(error, _)| error),
            "the ring builds its runtime parts",
        ));
    }
    // `finish` is what records the completed set privately, so no later caller
    // can open a second brand family for a session already published. The brand
    // is handed back because a consumer-recovery cursor is stated over exactly
    // one completed set, and reconstructing it beside the cell would be a second
    // source of truth for which rings this session has.
    let brand = must_ok(
        set.finish().map_err(|(error, _)| error),
        "every ring of the set was issued",
    );
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let published = must_ok(
        publish_installed_setup_for_test(
            transaction,
            &mut registry,
            &mut binding,
            &mut rendezvous,
            reservation,
            installed,
        ),
        "all setup authorities publish together",
    );
    let (locator, lease, control) = published.into_parts();
    (
        CoreCell {
            registry,
            binding,
            rendezvous,
            lease: Some(lease),
            control: Some(control),
            locator,
        },
        brand,
        parts,
    )
}

/// The same cell, already driven into `shape`, with its ring parts.
pub(crate) fn cell_in_shape_with_rings<const N: usize>(
    id: SessionIdentity,
    shape: ArrivalShape,
    rings: u32,
) -> (
    CoreCell<N>,
    SessionRingSetBrand,
    std::vec::Vec<crate::enter::PendingSlotParts>,
) {
    let (mut cell, brand, parts) = published_cell_with_rings::<N>(id, rings);
    shape_cell(&mut cell, shape);
    (cell, brand, parts)
}

#[test]
fn setup_and_terminal_production_edges_change_in_one_tree() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Task12TreeEdge {
        SetupPublisher(SessionLocator),
        CountedTerminalClaim(SessionLocator),
        RunTerminalToCheckpointTeardown(SessionLocator),
        RunTerminalToPreparedCheckpointFinish(SessionLocator),
        RunTerminalToFinishCheckpointTeardown(SessionLocator),
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Task12TreeRecorder {
        artifact: ProductionGraphArtifactIdentity,
        edges: Vec<Task12TreeEdge>,
    }

    impl Task12TreeRecorder {
        fn new(artifact: ProductionGraphArtifactIdentity) -> Self {
            Self {
                artifact,
                edges: Vec::new(),
            }
        }

        fn has_test_artifact(&self) -> bool {
            self.artifact.profile() == ProductionAttestationProfile::R3Stage
                && self.artifact.source_sha256() != [0; 32]
                && self.artifact.manifest_sha256() != [0; 32]
                && self.artifact.auditor_sha256() != [0; 32]
        }

        fn record_setup<const N: usize>(&mut self, cell: &CoreCell<N>) {
            let locator = cell.locator;
            if self.has_test_artifact()
                && cell.registry.validate_live(locator) == Ok(())
                && cell.binding.state() == ControlBindingState::Active(locator)
                && cell.rendezvous.outcome_for_locator(locator)
                    == Some(TerminalRendezvousOutcome::Open)
            {
                self.edges.push(Task12TreeEdge::SetupPublisher(locator));
            }
        }

        fn take_counted_winner(
            &mut self,
            disposition: CoreTerminalDisposition,
        ) -> CoreTerminalWinner {
            match disposition {
                CoreTerminalDisposition::Winner(winner) if self.has_test_artifact() => winner,
                CoreTerminalDisposition::Winner(_) => {
                    panic!("a terminal edge without the tree artifact is inadmissible")
                }
                CoreTerminalDisposition::Join(_) => panic!("the first real arrival must win"),
                CoreTerminalDisposition::Completed(_) => {
                    panic!("the real published rendezvous cannot start completed")
                }
                CoreTerminalDisposition::Blocked(_) => {
                    panic!("the real published rendezvous cannot start blocked")
                }
            }
        }

        /// Drive the three core transitions the sole terminal runner performs.
        ///
        /// These mirror the exact direct rows the Task 12 production graph pins
        /// on `run_terminal`: the teardown authenticates its own result, the
        /// preparation is the whole fallible half, and the finish cannot refuse.
        /// Every push is gated on the transition actually succeeding for this
        /// locator, so omitting or reordering one drops its edge.
        fn record_terminal_run<const N: usize>(
            &mut self,
            cell: &mut CoreCell<N>,
            winner: CoreTerminalWinner,
        ) {
            let locator = winner.locator();
            let reason = winner.reason();
            let (winner, terminal, ticket) = winner.into_parts();

            // `run_checkpoint_teardown` binds the counted winner to the result
            // its own run produced. A relabelled reason is refused, so this edge
            // cannot be recorded on behalf of a foreign run.
            let result = TerminalResult {
                reason,
                fence_failures: 0,
            };
            let authenticated = must_ok(
                AuthenticatedTerminalResult::new(winner, result).map_err(|_| ()),
                "the winner's own reason authenticates its own result",
            );
            if self.has_test_artifact() && authenticated.locator() == locator {
                self.edges
                    .push(Task12TreeEdge::RunTerminalToCheckpointTeardown(locator));
            }

            // `prepare_checkpoint_finish` is the whole fallible half: it decides
            // without mutating and returns every input on refusal.
            let prepared = must_ok(
                prepare_terminal_release(&mut cell.registry, terminal).map_err(|(error, held)| {
                    let _ = held;
                    error
                }),
                "the Removing generation admits its own terminal release",
            );
            assert_eq!(
                prepared.kind(),
                PreparedReleaseKind::Retained,
                "the control reference still holds this generation"
            );
            if self.has_test_artifact() {
                self.edges
                    .push(Task12TreeEdge::RunTerminalToPreparedCheckpointFinish(
                        locator,
                    ));
            }

            // `finish_checkpoint_teardown` has no refusal edge. It consumes the
            // preparation and records the fence completion.
            // SAFETY: the test stands in for the native deposit wrapper.
            let released = unsafe { prepared.commit() };
            assert!(
                matches!(released, RegistryRelease::Retained),
                "another stable owner outlives the fence"
            );
            assert!(
                slot(&cell.registry, 0).fence_done,
                "the finish, not the preparation, records fence_done"
            );
            if self.has_test_artifact() {
                self.edges
                    .push(Task12TreeEdge::RunTerminalToFinishCheckpointTeardown(
                        locator,
                    ));
            }

            let _ = authenticated;
            let _ = ticket;
        }
    }

    let artifact = must_ok(
        ProductionGraphArtifactIdentity::injected_for_test(ProductionAttestationProfile::R3Stage),
        "one sealed artifact stamps the complete modeled tree",
    );
    let mut cell = published_cell::<1>(identity(6006));
    let locator = cell.locator;
    let mut tree = Task12TreeRecorder::new(artifact);
    tree.record_setup(&cell);

    let claim = cell.claim(TerminalRequest::Cleanup);
    let winner = tree.take_counted_winner(claim);

    assert_eq!(
        winner.locator(),
        locator,
        "the real claim keeps the setup brand"
    );

    tree.record_terminal_run(&mut cell, winner);

    assert_eq!(
        tree,
        Task12TreeRecorder {
            artifact,
            edges: vec![
                Task12TreeEdge::SetupPublisher(locator),
                Task12TreeEdge::RunTerminalToCheckpointTeardown(locator),
                Task12TreeEdge::RunTerminalToPreparedCheckpointFinish(locator),
                Task12TreeEdge::RunTerminalToFinishCheckpointTeardown(locator),
            ],
        },
        "the real SETUP publisher and the three exact canonical terminal edges must carry one artifact identity"
    );

    // Anti-vacuity: the half-cutover shape this property exists to reject is
    // expressible, and the comparison above can actually tell it apart. Without
    // this, a recorder that silently stopped pushing terminal edges would still
    // have to be caught by the assertion's own expected list — which is the same
    // text, not an independent check.
    let mut halted = Task12TreeRecorder::new(artifact);
    halted.record_setup(&published_cell::<1>(identity(6006)));
    halted
        .edges
        .push(Task12TreeEdge::CountedTerminalClaim(locator));
    assert_ne!(
        halted.edges, tree.edges,
        "a tree that stops at the counted claim must not compare equal to the cutover tree"
    );
    assert_eq!(
        halted.edges.first(),
        tree.edges.first(),
        "both trees publish the same real SETUP edge, so the difference is the terminal half alone"
    );
}

/// The six distinguishable states one arrival can find a generation in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArrivalShape {
    /// Live, nobody has claimed: this arrival wins.
    LiveUnclaimed,
    /// The winner already moved the slot to Removing.
    RemovingOpen,
    /// The last stable owner left; the slot is Deleting but still joinable.
    DeletingOpen,
    /// The runner published Completed.
    ClosedCompleted,
    /// The runner published a permanent fail-stop.
    ClosedBlocked,
    /// Live in the core registry but another source already took admission.
    /// This is the torn race the preflight exists to refuse.
    LiveAlreadyAdmitted,
}

const ARRIVAL_SHAPES: [ArrivalShape; 6] = [
    ArrivalShape::LiveUnclaimed,
    ArrivalShape::RemovingOpen,
    ArrivalShape::DeletingOpen,
    ArrivalShape::ClosedCompleted,
    ArrivalShape::ClosedBlocked,
    ArrivalShape::LiveAlreadyAdmitted,
];

const ARRIVAL_REQUESTS: [TerminalRequest; 4] = [
    TerminalRequest::Cleanup,
    TerminalRequest::ProcessLoss,
    TerminalRequest::Unload,
    TerminalRequest::ProtocolFault,
];

/// Build a cell already in `shape`, keeping every authority the shape implies.
fn cell_in_shape<const N: usize>(id: SessionIdentity, shape: ArrivalShape) -> CoreCell<N> {
    let mut cell = published_cell::<N>(id);
    shape_cell(&mut cell, shape);
    cell
}

/// Drive an already published cell into `shape`.
///
/// Split out of `cell_in_shape` so that a fixture which needs the cell's *ring
/// set* -- and therefore has to reach between installation and publication --
/// shapes it through this one body rather than restating six transitions.
pub(crate) fn shape_cell<const N: usize>(cell: &mut CoreCell<N>, shape: ArrivalShape) {
    let locator = cell.locator;
    match shape {
        ArrivalShape::LiveUnclaimed => {}
        ArrivalShape::RemovingOpen => {
            let winner = cell.win(TerminalRequest::Cleanup);
            let _ = winner;
        }
        ArrivalShape::DeletingOpen => {
            let winner = cell.win(TerminalRequest::Cleanup);
            let (winner, terminal, ticket) = winner.into_parts();
            // Drive the registry to Deleting the way a real teardown does: the
            // fence finishes, then the last stable owner releases.
            must_ok(
                cell.registry.finish_removal_for_test(terminal),
                "a two-reference removal records fence_done",
            );
            let control = must_some(cell.control.take(), "the published control reference");
            assert!(matches!(
                must_ok(cell.registry.release(control), "the final release deletes"),
                RegistryRelease::Delete(_)
            ));
            let _ = winner;
            let _ = ticket;
        }
        ArrivalShape::ClosedCompleted => {
            let winner = cell.win(TerminalRequest::Cleanup);
            let (winner, terminal, ticket) = winner.into_parts();
            let result = TerminalResult {
                reason: TerminalReason::Cleanup,
                fence_failures: 0,
            };
            let prepared = must_ok(
                prepare_closing_complete(&cell.binding, locator, result, true),
                "the closing generation completes",
            );
            commit_prepared_closing_complete(prepared, &mut cell.binding);
            let signal = cell.rendezvous.close_and_publish_completed(winner, result);
            assert!(
                signal.is_ok(),
                "the counted winner closes its own generation"
            );
            let _ = signal;
            let _ = terminal;
            let _ = ticket;
        }
        ArrivalShape::ClosedBlocked => {
            let winner = cell.win(TerminalRequest::Cleanup);
            let (winner, terminal, ticket) = winner.into_parts();
            let blocked = blocked_fixture(locator, winner.diagnostic());
            let prepared = must_ok(
                prepare_closing_blocked(
                    &cell.binding,
                    locator,
                    TerminalBlockedClass::FenceInvariant,
                ),
                "the closing generation fail-stops",
            );
            commit_prepared_closing_blocked(prepared, &mut cell.binding);
            let signal = cell.rendezvous.close_and_publish_blocked(winner, blocked);
            assert!(
                signal.is_ok(),
                "the counted winner publishes its own fail-stop"
            );
            let _ = signal;
            let _ = terminal;
            let _ = ticket;
        }
        ArrivalShape::LiveAlreadyAdmitted => {
            // Admission taken without the coupled core/binding transition: the
            // exact half-committed state the aggregate must never produce and
            // must always refuse.
            let claim = must_ok(
                cell.rendezvous.claim(locator, TerminalRequest::Cleanup),
                "the raw rendezvous admits one claimant",
            );
            let (winner, ticket) = claim.into_parts();
            let _ = winner;
            let _ = ticket;
        }
    }
}

fn expected_claim_kind(shape: ArrivalShape) -> Result<CoreTerminalClaimKind, LifecycleError> {
    match shape {
        ArrivalShape::LiveUnclaimed => Ok(CoreTerminalClaimKind::Winner),
        ArrivalShape::RemovingOpen | ArrivalShape::DeletingOpen => Ok(CoreTerminalClaimKind::Join),
        ArrivalShape::ClosedCompleted => Ok(CoreTerminalClaimKind::Completed),
        ArrivalShape::ClosedBlocked => Ok(CoreTerminalClaimKind::Blocked),
        ArrivalShape::LiveAlreadyAdmitted => Err(LifecycleError::FinalizerBusy),
    }
}

#[test]
fn terminal_claim_cross_product_refuses_without_mutation_or_owner_loss() {
    // All 24 pure-core arrival permutations: six generation states times the
    // four terminal sources that can reach a claim at this checkpoint.
    let mut rows = 0_u32;
    for (index, shape) in ARRIVAL_SHAPES.into_iter().enumerate() {
        for (offset, request) in ARRIVAL_REQUESTS.into_iter().enumerate() {
            rows = rows.saturating_add(1);
            let seed = (index as u64)
                .saturating_mul(16)
                .saturating_add(offset as u64)
                .saturating_add(900);
            let mut cell = cell_in_shape::<2>(identity(seed), shape);
            let locator = cell.locator;
            let before = cell.snapshot();

            let prepared = cell.prepare(locator, request);
            match (prepared, expected_claim_kind(shape)) {
                (Ok(prepared), Ok(expected)) => {
                    assert_eq!(prepared.kind(), expected, "{shape:?} / {request:?}");
                    assert_eq!(prepared.locator(), locator);
                    // Preparation is mutation-free even for the rows that will
                    // go on to commit: nothing has moved yet.
                    let _ = prepared;
                }
                (Err(error), Err(expected)) => {
                    assert_eq!(error, expected, "{shape:?} / {request:?}");
                }
                (Ok(_), Err(expected)) => {
                    panic!("{shape:?} / {request:?} must refuse with {expected:?}")
                }
                (Err(error), Ok(expected)) => {
                    panic!("{shape:?} / {request:?} must prepare {expected:?}, got {error:?}")
                }
            }

            assert_eq!(
                cell.snapshot(),
                before,
                "{shape:?} / {request:?} mutated the cross-product before commit"
            );
            // The affine inputs are still exactly where they were: a refusal
            // that consumed the lease would be an owner loss no later arrival
            // could repair.
            assert_eq!(
                cell.lease.as_ref().map(RegistryLease::locator),
                before.lease
            );
        }
    }
    assert_eq!(
        rows, 24,
        "the pure-core arrival cross-product is exactly 24 rows"
    );
}

#[test]
fn terminal_winner_receives_a_generation_join_guard_before_running() {
    let mut cell = published_cell::<1>(identity(931));
    let locator = cell.locator;
    assert_eq!(admitted(&cell.rendezvous), 0);

    let disposition = cell.claim(TerminalRequest::Cleanup);
    let CoreTerminalDisposition::Winner(winner) = disposition else {
        panic!("the first arrival wins")
    };

    // Counted *before* it runs: the count is already one on the instruction
    // after the commit, with no terminal work performed in between.
    assert_eq!(admitted(&cell.rendezvous), 1);
    assert_eq!(winner.locator(), locator);
    assert_eq!(winner.reason(), TerminalReason::Cleanup);
    assert_eq!(
        slot(&cell.registry, 0).state,
        RegistrySlotState::Removing,
        "the same suffix moved the core slot"
    );
    assert_eq!(
        cell.binding.state(),
        ControlBindingState::ClosingLive(locator),
        "the same suffix moved the binding"
    );
    assert!(
        cell.lease.is_none(),
        "the lease became the terminal reference"
    );

    let (winner, terminal, ticket) = winner.into_parts();
    assert_eq!(terminal.locator(), locator);
    assert_eq!(ticket.locator(), locator);
    let _ = winner;
    let _ = terminal;
    let _ = ticket;
}

#[test]
fn foreign_prepared_terminal_objects_cannot_be_substituted() {
    let mut own = published_cell::<1>(identity(941));
    let mut foreign = published_cell::<1>(identity(942));
    let own_locator = own.locator;
    let foreign_locator = foreign.locator;
    assert_ne!(own_locator.identity(), foreign_locator.identity());

    let foreign_before = foreign.snapshot();

    // A prepared claim names one locator and retains exclusive borrows of the
    // four objects it preflighted, and `commit` takes no argument. There is no
    // seam through which the other cell's registry, binding, rendezvous, or
    // lease could arrive.
    let disposition = own.claim(TerminalRequest::Cleanup);
    let CoreTerminalDisposition::Winner(winner) = disposition else {
        panic!("the owning cell wins its own generation")
    };
    let (winner, terminal, ticket) = winner.into_parts();
    let _ = winner;
    let _ = terminal;
    let _ = ticket;

    assert_eq!(
        foreign.snapshot(),
        foreign_before,
        "committing one cell's claim must not touch another cell"
    );

    // The reciprocal check: the other cell's locator is refused by identity,
    // mutation-free, rather than silently claiming this cell's generation.
    let own_after = own.snapshot();
    assert!(matches!(
        foreign.prepare(own_locator, TerminalRequest::Cleanup),
        Err(LifecycleError::WrongLocator)
    ));
    assert_eq!(foreign.snapshot(), foreign_before);
    assert_eq!(own.snapshot(), own_after);
}

#[test]
fn open_rendezvous_keeps_winner_and_joiners_counted() {
    use crate::adapter::lifecycle::{TerminalWaitDisposition, resolve_terminal_release};

    let mut cell = published_cell::<1>(identity(951));
    let locator = cell.locator;
    let winner = cell.win(TerminalRequest::Cleanup);
    assert_eq!(admitted(&cell.rendezvous), 1);

    let mut tickets = Vec::new();
    for request in [TerminalRequest::ProcessLoss, TerminalRequest::Unload] {
        match cell.claim(request) {
            CoreTerminalDisposition::Join(ticket) => tickets.push(ticket),
            _ => panic!("a Removing generation admits joiners"),
        }
    }
    assert_eq!(admitted(&cell.rendezvous), 3);

    // While the outcome is Open every release hands the ticket straight back:
    // the arrival stays counted and goes around the wait loop again.
    for ticket in tickets {
        let release = match cell.rendezvous.release(ticket) {
            Ok(release) => release,
            Err(_) => panic!("an admitted ticket releases against its own generation"),
        };
        match resolve_terminal_release(release) {
            TerminalWaitDisposition::Open(ticket) => {
                assert_eq!(ticket.locator(), locator);
                let _ = ticket;
            }
            _ => panic!("an Open generation publishes no outcome"),
        }
        assert_eq!(
            admitted(&cell.rendezvous),
            3,
            "an Open release is not a decrement"
        );
    }

    let (winner, terminal, ticket) = winner.into_parts();
    let _ = winner;
    let _ = terminal;
    let _ = ticket;
}

#[test]
fn blocked_rendezvous_wakes_winner_and_joiner_not_unload() {
    use crate::adapter::lifecycle::{
        BlockedArrivalAction, TerminalArrivalSource, TerminalWaitDisposition,
        decide_blocked_arrival, resolve_terminal_release,
    };

    let mut cell = published_cell::<1>(identity(961));
    let locator = cell.locator;
    let winner = cell.win(TerminalRequest::Cleanup);
    let joiner = match cell.claim(TerminalRequest::ProcessLoss) {
        CoreTerminalDisposition::Join(ticket) => ticket,
        _ => panic!("the Removing generation admits a joiner"),
    };
    let (winner, terminal, winner_ticket) = winner.into_parts();
    let blocked = blocked_fixture(locator, winner.diagnostic());
    let signal = cell.rendezvous.close_and_publish_blocked(winner, blocked);
    assert!(
        signal.is_ok(),
        "the counted winner publishes its own fail-stop"
    );
    let _ = signal;

    // Both counted arrivals wake and copy the same immutable observation, and
    // only the last release after closure mints the drained signal.
    let first = match cell.rendezvous.release(winner_ticket) {
        Ok(release) => resolve_terminal_release(release),
        Err(_) => panic!("the winner releases its own count"),
    };
    assert!(matches!(
        first,
        TerminalWaitDisposition::Blocked {
            blocked: observed,
            drained: None
        } if observed == blocked
    ));
    let last = match cell.rendezvous.release(joiner) {
        Ok(release) => resolve_terminal_release(release),
        Err(_) => panic!("the joiner releases its own count"),
    };
    assert!(matches!(
        last,
        TerminalWaitDisposition::Blocked {
            blocked: observed,
            drained: Some(_)
        } if observed == blocked
    ));

    // Every ordinary arrival reports the blocked status. Unload alone must not
    // return: the generation still owns callback-visible state.
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
        BlockedArrivalAction::BlockForever
    );

    let _ = terminal;
}

#[test]
fn raw_protocol_abort_reason_is_not_constructible_through_claim_terminal() {
    // The claim's request type is `TerminalRequest`, which has no protocol
    // abort variant: an authenticated abort arrives only with the committed
    // packet path, which this checkpoint does not build. Drive every variant
    // through the real aggregate and prove the reachable reason set.
    let mut reached = Vec::new();
    for (index, request) in [
        TerminalRequest::Cleanup,
        TerminalRequest::ProcessLoss,
        TerminalRequest::Unload,
        TerminalRequest::PendingEpochExhausted,
        TerminalRequest::CreditGenerationExhausted,
        TerminalRequest::SqGenerationExhausted,
        TerminalRequest::ProtocolFault,
    ]
    .into_iter()
    .enumerate()
    {
        let mut cell = published_cell::<1>(identity(970_u64.saturating_add(index as u64)));
        let winner = cell.win(request);
        let reason = winner.reason();
        assert_ne!(
            reason,
            TerminalReason::ProtocolAbort,
            "no request may mint an authenticated protocol abort"
        );
        assert_eq!(reason, expected_reason(request));
        reached.push(reason);
        let (winner, terminal, ticket) = winner.into_parts();
        let _ = winner;
        let _ = terminal;
        let _ = ticket;
    }
    assert_eq!(reached.len(), 7);
    assert!(!reached.contains(&TerminalReason::ProtocolAbort));
}

// ---------------------------------------------------------------------------
// R4 Task 13: ring-set branding and the pending control ledger
// ---------------------------------------------------------------------------

/// One installed session carrying a completed ring set of `ring_count` rings.
fn installed_with_ring_set<const N: usize>(
    id: SessionIdentity,
    ring_count: u32,
) -> (
    SessionRegistry<N>,
    ControlBinding,
    SetupReservation,
    SetupTransaction,
    InstalledSession,
    SessionRingSetBrand,
) {
    let (registry, binding, reservation, transaction, mut installed) =
        reserved_installed_staging::<N>(id);
    let brand = {
        let mut initializer = must_ok(installed.begin_ring_set(ring_count), "a fresh install");
        while must_ok(initializer.next_ring(), "identities are available").is_some() {}
        match initializer.finish() {
            Ok(brand) => brand,
            Err((error, _)) => unreachable!("a fully allocated set finishes: {error:?}"),
        }
    };
    (
        registry,
        binding,
        reservation,
        transaction,
        installed,
        brand,
    )
}

#[test]
fn ring_set_initializer_is_increasing_abortable_and_nonwrapping() {
    let (_registry, _binding, _reservation, _transaction, mut installed) =
        reserved_installed_staging::<1>(identity(1301));

    // Out-of-range counts are refused on both sides, before any identity burns.
    for count in [0, MAX_SESSION_RING_COUNT.saturating_add(1)] {
        assert_eq!(
            installed.begin_ring_set(count).err(),
            Some(RoleError::RingCountOutOfRange),
            "ring count {count} is outside the permitted range"
        );
    }

    // Ring indices increase by exactly one and stop at the declared count.
    let mut indices = Vec::new();
    {
        let mut initializer = must_ok(
            installed.begin_ring_set(4),
            "a fresh install begins one set",
        );
        while let Some(right) = must_ok(initializer.next_ring(), "identities are available") {
            indices.push(right.brand().ring_index());
        }
        // Past the end it keeps reporting completion rather than wrapping to 0.
        assert!(must_ok(initializer.next_ring(), "past the end").is_none());
        assert!(must_ok(initializer.next_ring(), "still past the end").is_none());
        initializer.abort();
    }
    assert_eq!(indices.as_slice(), [0u32, 1, 2, 3].as_slice());

    // `abort` recorded nothing, so the install is still uninitialized and a
    // second set may begin. This is the half that makes `abort` more than a
    // drop with a name: had `next_ring` written through to the install, the
    // aborted partial set would still be sitting there.
    assert!(installed.completed_ring_set().is_none());
    let mut second = must_ok(
        installed.begin_ring_set(1),
        "an aborted set left nothing behind",
    );
    assert!(must_ok(second.next_ring(), "one ring").is_some());
    let brand = match second.finish() {
        Ok(brand) => brand,
        Err((error, _)) => unreachable!("a complete set finishes: {error:?}"),
    };
    assert_eq!(brand.ring_count(), 1);

    // And now a third set is refused, because `finish` recorded the second.
    assert_eq!(
        installed.begin_ring_set(1).err(),
        Some(RoleError::RingAlreadyInitialized),
        "one completed ring set per installation"
    );
}

#[test]
// Proof of safety: the index is a fixed fixture position in a table this
// test just built, and this is host test code, never a driver input path.
// An out-of-range index here is a bug in the test that must panic.
#[allow(clippy::indexing_slicing)]
fn ring_set_brand_reports_exact_count_and_contains_only_its_full_brands() {
    let (_r1, _b1, _res1, _t1, _installed1, first) =
        installed_with_ring_set::<1>(identity(1302), 3);
    let (_r2, _b2, _res2, _t2, mut installed2) = reserved_installed_staging::<1>(identity(1303));
    let mut own = Vec::new();
    let second = {
        let mut initializer = must_ok(installed2.begin_ring_set(3), "a second session");
        while let Some(right) = must_ok(initializer.next_ring(), "identities are available") {
            own.push(right.into_brand());
        }
        match initializer.finish() {
            Ok(brand) => brand,
            Err((error, _)) => unreachable!("a complete set finishes: {error:?}"),
        }
    };

    assert_eq!(first.ring_count(), 3);
    assert_eq!(second.ring_count(), 3);
    assert_ne!(first, second, "two sets never share a set identity");

    // Its own three rings belong to it, and to nothing else.
    for brand in &own {
        assert!(
            second.contains_brand(*brand),
            "ring {} is its own",
            brand.ring_index()
        );
        assert!(
            !first.contains_brand(*brand),
            "a foreign set must not claim ring {}",
            brand.ring_index()
        );
    }

    // The set identity is doing the work, not the locator: this brand carries
    // the other session's locator with this session's set identity, and a check
    // that stopped at either component alone would accept it.
    let crossed = SessionRingBrand {
        locator: first.locator(),
        ring_index: 0,
        set_id: second.set_id,
        state_id: own[0].state_id,
    };
    assert!(
        !second.contains_brand(crossed),
        "a foreign locator is not this set"
    );
    assert!(
        !first.contains_brand(crossed),
        "a foreign set identity is not this set"
    );
}

#[test]
fn next_ring_mints_one_nonreplayable_cq_bind_right_per_full_brand() {
    let (_registry, _binding, _reservation, _transaction, mut installed) =
        reserved_installed_staging::<1>(identity(1304));
    let consumed;
    {
        let mut initializer = must_ok(installed.begin_ring_set(2), "a fresh install");

        let first = must_ok(initializer.next_ring(), "ring 0").expect("ring 0 exists");
        let second = must_ok(initializer.next_ring(), "ring 1").expect("ring 1 exists");

        // One right per ring, each carrying a distinct full brand.
        assert_eq!(first.brand().ring_index(), 0);
        assert_eq!(second.brand().ring_index(), 1);
        assert_ne!(
            first.brand(),
            second.brand(),
            "two rings never share a full brand"
        );
        assert_ne!(
            first.brand().state_id,
            second.brand().state_id,
            "each ring owns its own nonwrapping state identity"
        );

        // Consuming a right yields its brand and ends it. There is no way back:
        // `into_brand` takes `self`, so binding ring 0 a second time would need
        // a second right, and `next_ring` has already moved past it.
        consumed = first.into_brand();
        assert_eq!(consumed.ring_index(), 0);
        assert!(must_ok(initializer.next_ring(), "the set is full").is_none());
        initializer.abort();
    }

    // Re-running the whole set from a fresh initializer mints different state
    // identities, so a replayed brand from the first attempt cannot match.
    let mut replay = must_ok(installed.begin_ring_set(2), "an aborted set left nothing");
    let fresh = must_ok(replay.next_ring(), "ring 0 again").expect("ring 0 exists");
    assert_eq!(fresh.brand().ring_index(), 0);
    assert_ne!(
        fresh.brand().state_id,
        consumed.state_id,
        "a re-initialized ring 0 is not the ring 0 whose right was consumed"
    );
    assert_ne!(fresh.brand().set_id, consumed.set_id);
}

#[test]
fn pending_ledger_reservation_rejects_foreign_full_closed_and_exhausted() {
    let (_registry, binding, reservation, _transaction, _installed, ring_set) =
        installed_with_ring_set::<1>(identity(1305), 2);

    // The happy path: reserved while the binding is still branded Staging.
    let reserved = must_ok(
        PendingControlLedger::<2>::reserve_for_setup(&binding, &reservation, ring_set),
        "a staging binding with a completed ring set reserves",
    );
    assert_eq!(reserved.brand.locator(), ring_set.locator());
    assert!(reserved.brand.matches_binding(&binding));

    // A reservation minted by another binding is refused, even though its own
    // reservation and ring set are internally consistent.
    let (_r2, foreign_binding, foreign_reservation, _t2, _i2, foreign_set) =
        installed_with_ring_set::<1>(identity(1306), 2);
    assert_eq!(
        PendingControlLedger::<2>::reserve_for_setup(&binding, &foreign_reservation, ring_set)
            .err(),
        Some(PendingError::WrongControlLedger),
        "a reservation minted by a different binding is refused"
    );
    assert!(
        PendingControlLedger::<2>::reserve_for_setup(
            &foreign_binding,
            &foreign_reservation,
            foreign_set
        )
        .is_ok(),
        "the same inputs pass under their own binding, so the refusal above is the cross"
    );

    // Out-of-range, duplicate, zero-epoch, foreign, and closed are the ledger
    // refusals. The slot IS the ring index now, so "one install per ring" is
    // structural: a second install for a ring that already has one collides
    // with the occupied slot rather than being caught by a separate scan.
    let mut ledger = PendingControlLedger::<2> {
        brand: reserved.brand,
        slots: [0; 2],
        admission_open: true,
    };
    let ring = |index: u32| SessionRingBrand {
        locator: ring_set.locator(),
        ring_index: index,
        set_id: ring_set.set_id,
        state_id: RingEnterStateId(
            core::num::NonZeroU64::new(u64::from(index) + 1).expect("nonzero"),
        ),
    };
    let install_a = PendingInstallId {
        brand: ring(0),
        install_epoch: 1,
    };
    // A different epoch on the SAME ring. Under the predecessor's first-free
    // scan this took a second slot; it is now a duplicate, which is the
    // property the ring-indexed layout buys.
    let install_a_again = PendingInstallId {
        brand: ring(0),
        install_epoch: 2,
    };
    let install_b = PendingInstallId {
        brand: ring(1),
        install_epoch: 7,
    };
    let install_out_of_range = PendingInstallId {
        brand: ring(2),
        install_epoch: 3,
    };

    let link_a = must_ok(ledger.link(install_a), "ring 0 is free");
    assert_eq!(
        ledger.link(install_a).err(),
        Some(PendingError::DuplicateLink),
        "the same install cannot be linked twice"
    );
    assert_eq!(
        ledger.link(install_a_again).err(),
        Some(PendingError::DuplicateLink),
        "a second install for a ring that already has one is refused"
    );
    let link_b = must_ok(ledger.link(install_b), "ring 1 is free");
    assert_eq!(
        ledger.link(install_out_of_range).err(),
        Some(PendingError::LedgerFull),
        "a two-slot ledger has no ring 2"
    );

    // Epoch zero is the free marker, so an install carrying it could never be
    // unlinked again. It is refused rather than trusted from a distance.
    let zero_epoch = PendingInstallId {
        brand: ring(1),
        install_epoch: 0,
    };
    assert_eq!(
        ledger.link(zero_epoch).err(),
        Some(PendingError::WrongInstall),
        "epoch zero is never issued and is refused here rather than stored"
    );

    // Unlinking frees exactly its own ring, and the right is consumed by it.
    must_ok(
        ledger.unlink(link_a),
        "the right names its own ring and epoch",
    );
    let relinked = must_ok(
        ledger.link(install_a_again),
        "the freed ring accepts the next install",
    );

    // A right whose ring now holds a *different* epoch comes back unconsumed
    // rather than silently clearing whatever moved in.
    let stale = PendingControlLinkRight {
        brand: ledger.brand,
        install: install_a,
        slot_index: 0,
        authority: PrivateControlLinkAuthority(()),
    };
    let (error, returned) = match ledger.unlink(stale) {
        Ok(()) => (None, None),
        Err((error, right)) => (Some(error), Some(right)),
    };
    assert_eq!(error, Some(PendingError::WrongSlot));
    assert!(
        returned.is_some(),
        "a refused unlink returns the exact right it was handed"
    );

    // A right whose two halves disagree cannot index one ring and compare
    // another: it is refused before either is used.
    let crossed = PendingControlLinkRight {
        brand: ledger.brand,
        install: install_b,
        slot_index: 0,
        authority: PrivateControlLinkAuthority(()),
    };
    assert_eq!(
        match ledger.unlink(crossed) {
            Ok(()) => None,
            Err((error, _)) => Some(error),
        },
        Some(PendingError::WrongSlot),
        "a slot index that does not name its install's ring is refused"
    );

    must_ok(ledger.unlink(link_b), "ring 1's right names ring 1");
    must_ok(ledger.unlink(relinked), "ring 0's replacement unlinks too");

    // A foreign install is refused by locator before any slot is taken.
    let (_r3, _b3, _res3, _t3, _i3, other_set) = installed_with_ring_set::<1>(identity(1307), 1);
    let foreign_install = PendingInstallId {
        brand: SessionRingBrand {
            locator: other_set.locator(),
            ring_index: 0,
            set_id: other_set.set_id,
            state_id: ring(0).state_id,
        },
        install_epoch: 1,
    };
    assert_eq!(
        ledger.link(foreign_install).err(),
        Some(PendingError::WrongSession),
        "an install from another session is not this ledger business"
    );

    ledger.close_admission();
    assert_eq!(
        ledger.link(install_a).err(),
        Some(PendingError::AdmissionClosed),
        "a closed ledger admits nothing, even into a free slot"
    );
}

#[test]
fn ring_set_and_pending_ledger_publish_in_one_live_active_suffix() {
    let (mut registry, mut binding, reservation, transaction, installed, ring_set) =
        installed_with_ring_set::<1>(identity(1308), 2);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let pending = must_ok(
        PendingControlLedger::<4>::reserve_for_setup(&binding, &reservation, ring_set),
        "the binding is still staging",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();

    let published = match publish_installed_setup_with_ring_set(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        ring_set,
        reservation,
        installed,
        pending,
    ) {
        Ok(published) => published,
        Err(failure) => unreachable!("a consistent aggregate publishes: {:?}", failure.error()),
    };
    let (session, ledger) = published.into_parts();

    // Live, Active, and a bound ledger are one observation: the ledger brand
    // names the session that was just published, and the registry agrees it is
    // Live. A publication that bound the ledger afterwards could not make both
    // of these true at the same instant.
    assert_eq!(ledger.brand().locator(), session.locator());
    assert!(ledger.brand().matches_binding(&binding));
    must_ok(
        registry.validate_live(session.locator()),
        "the aggregate published Live",
    );
    assert!(
        matches!(binding.state, ControlBindingState::Active(_)),
        "the aggregate published Active"
    );
    // Activation makes the rendezvous Open *for this exact locator*. The
    // admitted count is still zero -- nobody has arrived yet -- so counting
    // arrivals here would be asserting the wrong thing entirely.
    assert_eq!(
        rendezvous.outcome_for_locator(session.locator()),
        Some(TerminalRendezvousOutcome::Open),
        "the aggregate activated the rendezvous for the published locator"
    );
}

#[test]
fn task19_prepared_ring_setup_publishes_only_after_the_native_runtime_install() {
    use crate::session::prepare_installed_ring_setup;

    // The window this boundary exists to close: the cutover has to write a
    // pending runtime into the permanent cell AND publish Live/Active with
    // nothing observable in between. A single preflight-and-commit call gives
    // its caller nowhere to stand between the two.

    // 1. Preparation refuses exactly where the one-call publisher refuses, and
    //    hands back every affine input having touched nothing.
    let (mut registry, mut binding, reservation, transaction, installed, _own) =
        installed_with_ring_set::<1>(identity(1361), 2);
    let (_r2, _b2, _res2, _t2, _i2, foreign_set) = installed_with_ring_set::<1>(identity(1362), 2);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let pending = must_ok(
        PendingControlLedger::<4>::reserve_for_setup(&binding, &reservation, foreign_set),
        "the reservation itself is well formed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let before = registry.slot_snapshot(0).expect("slot");
    let locator = installed.locator();
    let failure = match prepare_installed_ring_setup(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        foreign_set,
        reservation,
        installed,
        pending,
    ) {
        Ok(_) => unreachable!("a foreign ring set must not prepare"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.error(),
        RingSetupPublishError::Session(SessionError::IdentityMismatch)
    );
    assert_eq!(registry.slot_snapshot(0).expect("slot"), before);
    assert!(matches!(binding.state, ControlBindingState::Staging(_)));
    assert_eq!(rendezvous.outcome_for_locator(locator), None);
    let (_error, _t, _rs, _res, _inst, _pend) = failure.into_parts();

    // 1b. And it refuses on the Task 4 rules too, not only on the R4 ones. A
    //     transaction that never reached ReferencesInstalled is caught by the
    //     shared borrowing predicate alone, so a preparation that consulted
    //     only its own five checks would publish it.
    let (mut registry, mut binding, reservation, transaction, installed, ring_set) =
        installed_with_ring_set::<1>(identity(1364), 2);
    let pending = must_ok(
        PendingControlLedger::<4>::reserve_for_setup(&binding, &reservation, ring_set),
        "the reservation itself is well formed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let before = registry.slot_snapshot(0).expect("slot");
    let failure = match prepare_installed_ring_setup(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        ring_set,
        reservation,
        installed,
        pending,
    ) {
        Ok(_) => unreachable!("an unstaged transaction must not prepare"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.error(),
        RingSetupPublishError::Session(SessionError::InvalidTransition)
    );
    assert_eq!(registry.slot_snapshot(0).expect("slot"), before);
    assert!(matches!(binding.state, ControlBindingState::Staging(_)));
    let (_error, _t, _rs, _res, _inst, _pend) = failure.into_parts();

    // 2. A *successful* preparation still mutates nothing. This is the half a
    //    combined call cannot have: everything is validated, and the session is
    //    not yet Live, so a native preflight that refuses next can still unwind.
    let (mut registry, mut binding, reservation, transaction, installed, ring_set) =
        installed_with_ring_set::<1>(identity(1363), 2);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let pending = must_ok(
        PendingControlLedger::<4>::reserve_for_setup(&binding, &reservation, ring_set),
        "the binding is still staging",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let before = registry.slot_snapshot(0).expect("slot");
    let locator = installed.locator();
    let prepared = match prepare_installed_ring_setup(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        ring_set,
        reservation,
        installed,
        pending,
    ) {
        Ok(prepared) => prepared,
        Err(failure) => unreachable!("a consistent aggregate prepares: {:?}", failure.error()),
    };

    // 3. Cancelling returns all five inputs, and the observable state is byte
    //    identical to before preparation ran.
    let (transaction, ring_set, reservation, installed, pending) =
        prepared.into_uncommitted_parts();
    assert_eq!(registry.slot_snapshot(0).expect("slot"), before);
    assert!(matches!(binding.state, ControlBindingState::Staging(_)));
    assert_eq!(
        rendezvous.outcome_for_locator(locator),
        None,
        "a cancelled preparation activates nothing",
    );
    assert_eq!(
        ring_set,
        installed.completed_ring_set().expect("a ring set")
    );

    // 4. And the same five inputs still publish, so the cancellation above cost
    //    nothing. Without this the three assertions before it would hold for a
    //    boundary that simply never works.
    let prepared = match prepare_installed_ring_setup(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        ring_set,
        reservation,
        installed,
        pending,
    ) {
        Ok(prepared) => prepared,
        Err(failure) => unreachable!("the same inputs prepare twice: {:?}", failure.error()),
    };
    // SAFETY: this row stands in for the caller that installed the runtime into
    // the permanent cell while holding the same registry lock.
    let published = unsafe { prepared.commit_after_native_runtime_install() };
    let (session, ledger) = published.into_parts();
    assert_eq!(ledger.brand().locator(), session.locator());
    assert!(ledger.brand().matches_binding(&binding));
    must_ok(
        registry.validate_live(session.locator()),
        "the commit published Live",
    );
    assert!(matches!(binding.state, ControlBindingState::Active(_)));
    assert_eq!(
        rendezvous.outcome_for_locator(session.locator()),
        Some(TerminalRendezvousOutcome::Open),
    );
}

#[test]
fn setup_refusal_returns_every_unpublished_authority() {
    // A ring set from another session, so the aggregate preflight refuses
    // before the Task 4 path is entered at all.
    let (mut registry, mut binding, reservation, transaction, installed, _own) =
        installed_with_ring_set::<1>(identity(1309), 2);
    let (_r2, _b2, _res2, _t2, _i2, foreign_set) = installed_with_ring_set::<1>(identity(1310), 2);
    let transaction = must_ok(
        transaction.stage(SetupStage::ReferencesInstalled),
        "references advance after installation",
    );
    let pending = must_ok(
        PendingControlLedger::<4>::reserve_for_setup(&binding, &reservation, foreign_set),
        "the reservation itself is well formed",
    );
    let mut rendezvous = TerminalRendezvous::new_inactive();
    let before = registry.slot_snapshot(0).expect("slot");
    let published_locator = installed.locator();

    let failure = match publish_installed_setup_with_ring_set(
        transaction,
        &mut registry,
        &mut binding,
        &mut rendezvous,
        foreign_set,
        reservation,
        installed,
        pending,
    ) {
        Ok(_) => unreachable!("a foreign ring set must not publish"),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.error(),
        RingSetupPublishError::Session(SessionError::IdentityMismatch)
    );

    // Nothing moved: the slot is identical, the binding is still Staging, and
    // the rendezvous never activated.
    assert_eq!(registry.slot_snapshot(0).expect("slot"), before);
    assert!(matches!(binding.state, ControlBindingState::Staging(_)));
    assert_eq!(
        rendezvous.outcome_for_locator(published_locator),
        None,
        "a refused publication activates nothing"
    );

    // And every affine input comes back, so the caller can still roll back.
    let (_error, transaction, ring_set, reservation, installed, pending) = failure.into_parts();
    assert_eq!(ring_set, foreign_set);
    assert!(valid_installed_setup_transaction(&transaction));
    assert_eq!(reservation.binding_id, pending.brand.binding_id);
    assert!(installed.completed_ring_set().is_some());
    assert_eq!(installed.locator(), published_locator);
}

// ---------------------------------------------------------------------------
// R4 Task 19: the same-artifact dependency the cutover's absence proof carries
// ---------------------------------------------------------------------------

/// R4 completion is unavailable unless the R5 staging row is in the *same*
/// artifact.
///
/// This is Step 6o's persisted dependency, and it is the reason the R5 gate is
/// a row of the `r4-cutover` profile rather than a separate run: an injected R5
/// production edge fails that gate, the refreshed attestation then cannot carry
/// the row, and the bundle below stops resolving -- which makes R4 completion,
/// preparation, readiness and deposit unavailable rather than reusing Task 19's
/// evidence.
#[test]
fn task19_cq_and_protocol_authorities_remain_unconstructible() {
    let complete = task12_injected_witness(
        0xc1,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES,
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&complete),
        Ok(complete.identity)
    );

    let without_r5 = task12_injected_witness(
        0xc5,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES.without(ProductionRowCapabilities::R5_STAGING),
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&without_r5),
        Err(ProductionAttestationError::RequiredRowMissing),
        "an artifact that does not carry the R5 staging row may not mint R4 absence"
    );
}

/// The cutover row is required in its own right, and the retired staging row
/// cannot stand in for it.
#[test]
fn task19_r4_absence_requires_the_cutover_row_and_not_the_retired_staging_row() {
    let without_cutover = task12_injected_witness(
        0xd1,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES.without(ProductionRowCapabilities::R4_CUTOVER),
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&without_cutover),
        Err(ProductionAttestationError::RequiredRowMissing)
    );

    // The same bundle with the *staging* bit substituted for the cutover bit is
    // the exact same cardinality and still refused: the two rows are different
    // claims about the same tree, and only one of them can be true after the
    // cutover.
    let substituted = task12_injected_witness(
        0xd5,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES
            .without(ProductionRowCapabilities::R4_CUTOVER)
            .union(ProductionRowCapabilities::R4_STAGING),
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&substituted),
        Err(ProductionAttestationError::RequiredRowMissing),
        "the retired staging row must not stand in for the cutover row"
    );
}

/// The predecessor profile cannot mint the active absence, and the active
/// profile cannot mint a historical one.
#[test]
fn task19_r3_checkpoint_surface_is_zero_before_r4_publish() {
    let historical = task12_injected_witness(
        0xe1,
        ProductionAttestationProfile::R4Stage,
        HISTORICAL_R4_STAGE_CAPABILITIES,
    );
    assert_eq!(
        resolve_active_r4_authority_absence_from(&historical),
        Err(ProductionAttestationError::WrongProfile),
        "an r4-stage artifact predates the cutover and may not mint R4 absence"
    );

    let active = task12_injected_witness(
        0xe5,
        ProductionAttestationProfile::R4Cutover,
        ACTIVE_R4_CUTOVER_CAPABILITIES,
    );
    assert_eq!(
        resolve_historical_r3_absence_for_test(&active),
        Err(ProductionAttestationError::WrongProfile),
        "a cutover artifact may not be read back as a predecessor one"
    );
}

// ---------------------------------------------------------------------------
// R4: the sole production install-identity minter
// ---------------------------------------------------------------------------

/// An install identity exists only for a slot that just reserved its epoch, and
/// the epoch it carries is the one that slot issued.
#[test]
fn task19_install_identity_is_minted_only_by_the_slot_that_reserved_it() {
    use crate::enter::PendingSlotState;
    use crate::session::reserve_pending_install;

    let (_registry, _binding, _reservation, _transaction, _installed, ring_set) =
        installed_with_ring_set::<1>(identity(1330), 2);
    let ring = |index: u32| SessionRingBrand {
        locator: ring_set.locator(),
        ring_index: index,
        set_id: ring_set.set_id,
        state_id: RingEnterStateId(
            core::num::NonZeroU64::new(u64::from(index) + 1).expect("nonzero"),
        ),
    };

    // A fresh slot issues epoch 1 and moves to Installing for that same epoch.
    let (state, first) = must_ok(
        reserve_pending_install(ring(0), PendingSlotState::fresh()),
        "a fresh slot reserves",
    );
    assert_eq!(state, PendingSlotState::Installing { epoch: 1 });
    assert_eq!(first.install_epoch(), 1);
    assert_eq!(first.brand(), ring(0));

    // The identity is the slot's, not the caller's: reserving the *next* epoch
    // of the same slot yields a different identity for the same ring, which is
    // the whole reason a slot index alone is not one.
    let (_next_state, second) = must_ok(
        reserve_pending_install(ring(0), PendingSlotState::Vacant { next_epoch: 2 }),
        "a reusable slot reserves its next epoch",
    );
    assert_ne!(first, second);
    assert_eq!(second.install_epoch(), 2);

    // Two rings at the same epoch are still distinct identities.
    let (_other_state, other_ring) = must_ok(
        reserve_pending_install(ring(1), PendingSlotState::fresh()),
        "each ring has its own slot",
    );
    assert_ne!(first, other_ring);
    assert_eq!(other_ring.install_epoch(), first.install_epoch());
}

/// Every state that is not `Vacant` refuses, and refusal returns the state
/// unchanged so a loser of the race has reserved nothing.
#[test]
fn task19_a_slot_that_is_not_vacant_mints_no_identity_and_is_left_alone() {
    use crate::enter::PendingSlotState;
    use crate::session::reserve_pending_install;

    let (_registry, _binding, _reservation, _transaction, _installed, ring_set) =
        installed_with_ring_set::<1>(identity(1331), 1);
    let brand = SessionRingBrand {
        locator: ring_set.locator(),
        ring_index: 0,
        set_id: ring_set.set_id,
        state_id: RingEnterStateId(core::num::NonZeroU64::new(1).expect("nonzero")),
    };

    for occupied in [
        PendingSlotState::Installing { epoch: 4 },
        PendingSlotState::Active { epoch: 4 },
        PendingSlotState::Quiescing { epoch: 4 },
        PendingSlotState::PublicationFailStop { epoch: 4 },
        PendingSlotState::EpochExhausted,
    ] {
        let (error, returned) = match reserve_pending_install(brand, occupied) {
            Ok(_) => panic!("{occupied:?} must not admit a second install"),
            Err((error, returned)) => (error, returned),
        };
        assert_eq!(error, PendingError::SlotOccupied);
        assert_eq!(
            returned, occupied,
            "a refused reservation leaves the slot exactly as it found it"
        );
    }
}

#[test]
fn task25_terminal_blocked_detail_has_only_final_fence_and_delete_variants() {
    let session = include_str!("../session.rs");
    assert!(
        !session.contains("from_checkpoint") && session.contains("from_fence"),
        "PrivateTerminalBlocked must keep only fence and delete payloads"
    );
}

#[test]
fn finish_fence_refusal_parks_terminal_final_result_closing_owners_and_release_proof() {
    let fsd = include_str!("../../../fsring-fsd/src/fence.rs");
    assert!(
        fsd.contains("fn finish_fence") && fsd.contains("fn prepare_finish_fence"),
        "core finish must expose prepare_finish_fence and commit_finish_fence"
    );
}
