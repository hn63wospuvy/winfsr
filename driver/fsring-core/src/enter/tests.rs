// TEST: fixtures use host allocation and threads; production ENTER arbitration
// remains allocation-free, WDK-free, and governed by the crate-wide lints.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]

use super::*;

use std::sync::{Arc, Barrier};

use fsring_abi::{
    BootInstanceId, FeatureSet, MIN_CONTROL_SLOT_SIZE, MIN_K2U_PROGRESS_SLOTS_PER_RING,
    MIN_NOTIFICATION_CREDIT_SIZE, MIN_U2K_PROGRESS_SLOTS_PER_RING, MountId, SlotToken,
    codec::try_encode,
    control::{
        ENTER_REQUEST_V1_SIZE, ENTER_RESULT_V1_PREFIX_SIZE, EnterRequestV1,
        NOTIFICATION_CREDIT_V1_SIZE, NotificationCreditV1, SETUP_REQUEST_V1_SIZE, SetupRequestV1,
        SlotClassRequest, enter_request_flags, enter_result_flags,
    },
    features::PlatformProfile,
    layout::cq_kind,
    msgs::{CONTROL_VERSION_V1, ControlHeader},
    validate::{
        SessionIdentity, ValidatedEnterResult, ValidatedTopology, validate_enter_result_v1,
        validate_setup_request_v1,
    },
};

use crate::grant::{GrantEntry, GrantError, GrantState, GrantTable};
use crate::terminal::ClaimantKind;

const SECURITY_ONLY: FeatureSet = FeatureSet { words: [0x10, 0] };
const EMPTY_CLASS: SlotClassRequest = SlotClassRequest {
    slot_size: 0,
    slot_count: 0,
};

fn class(slot_size: u32, slot_count: u32) -> SlotClassRequest {
    SlotClassRequest {
        slot_size,
        slot_count,
    }
}

fn topology(ring_count: u32, credit_count: u32) -> ValidatedTopology {
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
            class(MIN_NOTIFICATION_CREDIT_SIZE * 2, credit_count),
            class(MIN_NOTIFICATION_CREDIT_SIZE * 4, 3),
            class(
                MIN_CONTROL_SLOT_SIZE,
                MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count,
            ),
        ],
        notification_credit_count: credit_count,
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
    .expect("ENTER test topology must validate")
    .topology()
}

fn identity() -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: 11, hi: 13 },
        boot_instance_id: BootInstanceId { lo: 17, hi: 19 },
        session_epoch: 23,
    }
}

fn request(
    identity: SessionIdentity,
    ring_index: u32,
    flags: u32,
    cq_budget: u32,
    timeout_ms: u32,
) -> EnterRequestV1 {
    EnterRequestV1 {
        header: ControlHeader {
            struct_size: ENTER_REQUEST_V1_SIZE,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        mount_id: identity.mount_id,
        session_epoch: identity.session_epoch,
        ring_index,
        flags,
        cq_budget,
        timeout_ms,
    }
}

fn free_backing(topology: &ValidatedTopology) -> Vec<GrantEntry> {
    let count = topology
        .u2k_slot_classes()
        .iter()
        .map(|request| request.slot_count as usize)
        .sum();
    vec![GrantEntry::FREE; count]
}

fn issue(table: &mut GrantTable<'_>, count: usize) -> Vec<NotificationCreditV1> {
    let mut output = vec![NotificationCreditV1::default(); count];
    assert_eq!(table.issue_notification_credits(&mut output), Ok(count));
    output
}

fn observation(sq_ready: bool, timeout_expired: bool, fenced: bool) -> EnterPollObservation {
    EnterPollObservation {
        sq_ready,
        timeout_expired,
        fenced,
    }
}

#[test]
fn request_classifier_covers_poll_finite_indefinite_and_drain_without_waiting() {
    let topology = topology(2, 2);
    let identity = identity();
    let state = RingEnterState::new(0);

    let poll = request(identity, 0, 0, 0, 0);
    assert_eq!(
        state.classify_request(&poll, identity, &topology, observation(false, false, false)),
        Ok((EnterRole::Sq, EnterDecision::Empty))
    );
    assert_eq!(
        state.classify_request(&poll, identity, &topology, observation(true, false, false)),
        Ok((EnterRole::Sq, EnterDecision::Ready))
    );

    let wait_poll = request(identity, 0, enter_request_flags::WAIT_SQ, 0, 0);
    assert_eq!(
        state.classify_request(
            &wait_poll,
            identity,
            &topology,
            observation(false, true, false),
        ),
        Ok((EnterRole::Sq, EnterDecision::Empty))
    );

    let finite = request(identity, 0, enter_request_flags::WAIT_SQ, 0, 37);
    assert_eq!(
        state.classify_request(
            &finite,
            identity,
            &topology,
            observation(false, false, false)
        ),
        Ok((EnterRole::Sq, EnterDecision::Pending))
    );
    assert_eq!(
        state.classify_request(
            &finite,
            identity,
            &topology,
            observation(false, true, false)
        ),
        Ok((EnterRole::Sq, EnterDecision::TimedOut))
    );
    assert_eq!(
        state.classify_request(&finite, identity, &topology, observation(true, true, false)),
        Ok((EnterRole::Sq, EnterDecision::Ready))
    );

    let indefinite = request(identity, 0, enter_request_flags::WAIT_SQ, 0, u32::MAX);
    assert_eq!(
        state.classify_request(
            &indefinite,
            identity,
            &topology,
            observation(false, true, false),
        ),
        Ok((EnterRole::Sq, EnterDecision::Pending))
    );
    assert_eq!(
        state.classify_request(
            &indefinite,
            identity,
            &topology,
            observation(true, true, false),
        ),
        Ok((EnterRole::Sq, EnterDecision::Ready))
    );

    let drain = request(identity, 0, enter_request_flags::DRAIN_CQ, 1, 0);
    assert_eq!(
        state.classify_request(&drain, identity, &topology, observation(false, true, false)),
        Ok((EnterRole::Cq, EnterDecision::Empty))
    );
    assert_eq!(
        state.classify_request(&drain, identity, &topology, observation(true, false, false)),
        Ok((EnterRole::Cq, EnterDecision::Ready))
    );
    let maximum_drain = request(identity, 0, enter_request_flags::DRAIN_CQ, 2, 0);
    assert_eq!(
        state.classify_request(
            &maximum_drain,
            identity,
            &topology,
            observation(false, false, false),
        ),
        Ok((EnterRole::Cq, EnterDecision::Empty))
    );
}

#[test]
fn request_classifier_enforces_flags_identity_budget_timeout_and_fence_precedence() {
    let topology = topology(2, 2);
    let identity = identity();
    let state = RingEnterState::new(0);
    let blocked = observation(false, false, true);

    let mut candidate = request(identity, 0, !enter_request_flags::KNOWN_MASK, 9, 9);
    candidate.mount_id = MountId::default();
    assert_eq!(
        state.classify_request(&candidate, identity, &topology, blocked),
        Err(EnterError::InvalidFlags)
    );

    candidate = request(
        identity,
        0,
        enter_request_flags::WAIT_SQ | enter_request_flags::DRAIN_CQ,
        1,
        0,
    );
    assert_eq!(
        state.classify_request(&candidate, identity, &topology, blocked),
        Err(EnterError::InvalidFlags)
    );

    candidate = request(identity, 1, enter_request_flags::DRAIN_CQ, 0, 7);
    assert_eq!(
        state.classify_request(&candidate, identity, &topology, blocked),
        Err(EnterError::InvalidIdentity)
    );

    candidate = request(identity, 0, enter_request_flags::DRAIN_CQ, 0, 7);
    assert_eq!(
        state.classify_request(&candidate, identity, &topology, blocked),
        Err(EnterError::InvalidBudget)
    );

    candidate = request(identity, 0, 0, 0, 7);
    assert_eq!(
        state.classify_request(&candidate, identity, &topology, blocked),
        Err(EnterError::InvalidTimeout)
    );

    candidate = request(identity, 0, enter_request_flags::WAIT_SQ, 0, 7);
    assert_eq!(
        state.classify_request(&candidate, identity, &topology, blocked),
        Err(EnterError::Fenced)
    );

    candidate = request(identity, 0, enter_request_flags::DRAIN_CQ, 3, 0);
    assert_eq!(
        state.classify_request(
            &candidate,
            identity,
            &topology,
            observation(false, false, false),
        ),
        Err(EnterError::InvalidBudget)
    );
}

#[test]
fn enter_error_surface_remains_the_frozen_task_six_set() {
    fn code(error: EnterError) -> u8 {
        match error {
            EnterError::DeviceBusy => 0,
            EnterError::InvalidFlags => 1,
            EnterError::InvalidIdentity => 2,
            EnterError::InvalidBudget => 3,
            EnterError::InvalidTimeout => 4,
            EnterError::GenerationExhausted => 5,
            EnterError::Fenced => 6,
        }
    }

    assert_eq!(
        [
            EnterError::DeviceBusy,
            EnterError::InvalidFlags,
            EnterError::InvalidIdentity,
            EnterError::InvalidBudget,
            EnterError::InvalidTimeout,
            EnterError::GenerationExhausted,
            EnterError::Fenced,
        ]
        .map(code),
        [0, 1, 2, 3, 4, 5, 6]
    );
}

#[test]
fn request_classifier_rechecks_mount_epoch_and_bounded_ring_identity_independently() {
    let topology = topology(2, 2);
    let identity = identity();
    let state = RingEnterState::new(0);
    let live = observation(false, false, false);

    let mut wrong_mount = request(identity, 0, 0, 0, 0);
    wrong_mount.mount_id = MountId { lo: 29, hi: 31 };
    assert_eq!(
        state.classify_request(&wrong_mount, identity, &topology, live),
        Err(EnterError::InvalidIdentity)
    );

    let mut wrong_epoch = request(identity, 0, 0, 0, 0);
    wrong_epoch.session_epoch = 29;
    assert_eq!(
        state.classify_request(&wrong_epoch, identity, &topology, live),
        Err(EnterError::InvalidIdentity)
    );

    let outside_topology = request(identity, topology.ring_count(), 0, 0, 0);
    assert_eq!(
        state.classify_request(&outside_topology, identity, &topology, live),
        Err(EnterError::InvalidIdentity)
    );

    let other_live_ring = request(identity, 1, 0, 0, 0);
    assert_eq!(
        state.classify_request(&other_live_ring, identity, &topology, live),
        Err(EnterError::InvalidIdentity)
    );
}

#[test]
fn sq_and_cq_roles_coexist_while_duplicate_roles_are_busy_and_leases_are_affine() {
    let mut state = RingEnterState::new(3);
    let sq = state
        .acquire_role(101, EnterRole::Sq)
        .expect("first SQ role");
    let cq = state
        .acquire_role(202, EnterRole::Cq)
        .expect("independent CQ role");

    assert!(matches!(
        state.acquire_role(303, EnterRole::Sq),
        Err(EnterError::DeviceBusy)
    ));
    assert!(matches!(
        state.acquire_role(404, EnterRole::Cq),
        Err(EnterError::DeviceBusy)
    ));

    let mut wrong_state = RingEnterState::new(3);
    let returned_sq = match wrong_state.release_role(sq) {
        Err((EnterError::InvalidIdentity, lease)) => lease,
        _ => panic!("foreign state accepted an SQ lease"),
    };
    assert!(matches!(
        state.acquire_role(707, EnterRole::Sq),
        Err(EnterError::DeviceBusy)
    ));
    state
        .release_role(returned_sq)
        .expect("SQ owner releases once");
    state.release_role(cq).expect("CQ owner releases once");
    assert!(state.acquire_role(505, EnterRole::Sq).is_ok());
    assert!(state.acquire_role(606, EnterRole::Cq).is_ok());
}

#[test]
fn r3_checkpoint_role_observation_requires_both_sq_and_cq_consumers_to_leave() {
    let mut state = RingEnterState::new(4);
    assert!(state.r3_checkpoint_roles_and_consumers_are_drained());

    let sq = state.acquire_role(101, EnterRole::Sq).expect("SQ role");
    assert!(!state.r3_checkpoint_roles_and_consumers_are_drained());
    let cq = state.acquire_role(202, EnterRole::Cq).expect("CQ role");
    assert!(!state.r3_checkpoint_roles_and_consumers_are_drained());

    state.release_role(sq).expect("SQ owner releases once");
    assert!(
        !state.r3_checkpoint_roles_and_consumers_are_drained(),
        "the remaining CQ consumer keeps the checkpoint closed",
    );
    state.release_role(cq).expect("CQ owner releases once");
    assert!(state.r3_checkpoint_roles_and_consumers_are_drained());
}

#[test]
fn a_parked_sq_wait_is_not_a_leftover_dispatch_role() {
    let mut state = RingEnterState::new(4);
    let sq = state.acquire_role(101, EnterRole::Sq).expect("SQ role");
    assert!(!state.r3_checkpoint_roles_and_consumers_are_drained());
    assert!(
        !state.leftover_dispatch_roles_are_absent(),
        "an unmarked SQ owner is still a leftover dispatch ENTER",
    );

    state
        .mark_sq_wait_pending(&sq)
        .expect("the parked WAIT still holds this lease");
    assert!(
        !state.r3_checkpoint_roles_and_consumers_are_drained(),
        "the pending context still occupies sq_owner until completion",
    );
    assert!(
        state.leftover_dispatch_roles_are_absent(),
        "fence WaitExistingSqCqRoles must not refuse a CSQ-parked WAIT",
    );

    let cq = state.acquire_role(202, EnterRole::Cq).expect("CQ role");
    assert!(
        !state.leftover_dispatch_roles_are_absent(),
        "a CQ consumer is still a leftover dispatch role",
    );
    state.release_role(cq).expect("CQ owner releases once");
    assert!(state.leftover_dispatch_roles_are_absent());

    state.release_role(sq).expect("SQ owner releases once");
    assert!(state.r3_checkpoint_roles_and_consumers_are_drained());
    assert!(state.leftover_dispatch_roles_are_absent());
}

#[test]
fn a_same_shape_lease_from_another_state_cannot_release_or_clear_this_state() {
    let mut first = RingEnterState::new(6);
    let mut second = RingEnterState::new(6);
    let first_lease = first
        .acquire_role(313, EnterRole::Sq)
        .expect("first state lease");
    let second_lease = second
        .acquire_role(313, EnterRole::Sq)
        .expect("same public lease shape on another state");

    first.publish_sq().expect("first state signal");
    let snapshot = first.observe_readiness(false);
    let signal_before = first.signaled_generation;
    assert_eq!(
        first.clear_event_after(&second_lease, snapshot),
        Err(EnterError::InvalidIdentity)
    );
    assert_eq!(first.signaled_generation, signal_before);

    let returned_second = match first.release_role(second_lease) {
        Err((EnterError::InvalidIdentity, lease)) => lease,
        _ => panic!("same-shape foreign lease released the first state"),
    };
    assert!(matches!(
        first.acquire_role(313, EnterRole::Sq),
        Err(EnterError::DeviceBusy)
    ));
    second
        .release_role(returned_second)
        .expect("foreign lease remained owned by its source state");
    first
        .release_role(first_lease)
        .expect("first lease remained live");
}

#[test]
fn only_the_current_sq_lease_can_clear_the_modeled_event() {
    let mut state = RingEnterState::new(4);
    let sq = state.acquire_role(11, EnterRole::Sq).expect("SQ lease");
    let cq = state.acquire_role(12, EnterRole::Cq).expect("CQ lease");
    state.publish_sq().expect("publication");
    let empty = state.observe_readiness(false);
    assert!(
        !empty.ready,
        "an event/generation signal is not an SQ readiness observation"
    );
    let signaled_before = state.signaled_generation;

    assert_eq!(
        state.clear_event_after(&cq, empty),
        Err(EnterError::InvalidIdentity)
    );
    assert_eq!(state.signaled_generation, signaled_before);

    let mut foreign = RingEnterState::new(4);
    let foreign_sq = foreign
        .acquire_role(99, EnterRole::Sq)
        .expect("foreign SQ lease");
    assert_eq!(
        state.clear_event_after(&foreign_sq, empty),
        Err(EnterError::InvalidIdentity)
    );
    assert_eq!(state.signaled_generation, signaled_before);

    assert_eq!(state.clear_event_after(&sq, empty), Ok(()));
    assert_eq!(state.signaled_generation, 0);

    state.publish_sq().expect("second publication");
    let ready = state.observe_readiness(true);
    let ready_signal = state.signaled_generation;
    assert_eq!(state.clear_event_after(&sq, ready), Ok(()));
    assert_eq!(state.signaled_generation, ready_signal);
}

#[test]
fn poll_clear_postclear_generation_recheck_closes_the_missed_wake_window() {
    let mut state = RingEnterState::new(0);
    let sq = state.acquire_role(7, EnterRole::Sq).expect("SQ lease");
    let first = state.observe_readiness(false);
    assert!(!first.ready);
    state
        .clear_event_after(&sq, first)
        .expect("current SQ owner clears");
    state.publish_sq().expect("generation advances");
    assert!(!state.observe_readiness(false).ready);
    assert!(state.observe_readiness(true).ready);
    assert_eq!(
        state.recheck_after_clear(first, false, false),
        Ok(EnterDecision::Ready)
    );

    let second = state.observe_readiness(false);
    assert_eq!(
        state.recheck_after_clear(second, false, false),
        Ok(EnterDecision::Pending)
    );
    assert_eq!(
        state.recheck_after_clear(second, true, false),
        Ok(EnterDecision::Ready)
    );
}

#[test]
fn fence_wins_before_clear_and_in_every_post_clear_race() {
    let topology = topology(1, 1);
    let identity = identity();
    let mut state = RingEnterState::new(0);
    let wait = request(identity, 0, enter_request_flags::WAIT_SQ, 0, 17);

    assert_eq!(
        state.classify_request(&wait, identity, &topology, observation(true, false, true),),
        Err(EnterError::Fenced),
        "an initial fence wins even over a ready SQ poll"
    );

    let lease = state.acquire_role(91, EnterRole::Sq).expect("SQ lease");
    let snapshot = state.observe_readiness(false);
    state
        .clear_event_after(&lease, snapshot)
        .expect("live SQ owner clears");
    assert_eq!(
        state.recheck_after_clear(snapshot, false, true),
        Err(EnterError::Fenced),
        "same generation and an empty second poll cannot repend after fence"
    );
    assert_eq!(
        state.recheck_after_clear(snapshot, true, true),
        Err(EnterError::Fenced),
        "post-clear fence wins over readiness"
    );
    state.publish_sq().expect("racing publication");
    assert_eq!(
        state.recheck_after_clear(snapshot, true, true),
        Err(EnterError::Fenced),
        "post-clear fence wins over both readiness and generation change"
    );
}

#[test]
fn clear_does_not_erase_a_post_snapshot_publication_and_generation_never_wraps() {
    let mut state = RingEnterState::new(0);
    let sq = state.acquire_role(8, EnterRole::Sq).expect("SQ lease");
    let before = state.observe_readiness(false);
    assert_eq!(state.publish_sq(), Ok(1));
    assert_eq!(state.clear_event_after(&sq, before), Ok(()));
    assert_eq!(state.signaled_generation, 1);

    state.sq_publish_generation = u64::MAX;
    state.signaled_generation = u64::MAX;
    assert_eq!(state.publish_sq(), Err(EnterError::GenerationExhausted));
    assert_eq!(state.sq_publish_generation, u64::MAX);
    assert_eq!(state.signaled_generation, u64::MAX);
}

#[test]
fn cq_empty_contention_and_kind_precedence_do_not_touch_grants() {
    let topology = topology(2, 2);
    let mut entries = free_backing(&topology);
    let mut grants = GrantTable::initialize(&mut entries, &topology, 23).expect("grant table");
    let credits = issue(&mut grants, 2);
    let token = SlotToken::from_raw(credits[0].buffer.token).expect("credit token");
    let before = grants.entry_snapshot(token);
    let state = RingEnterState::new(0);

    assert!(matches!(
        state.classify_cq(
            CqObservation {
                kind: u16::MAX,
                sequence_stable: true,
                record_ready: false,
                semantic: CqSemantic::Invalid,
                output_bytes_available: usize::MAX,
                credit: Some(token),
            },
            &grants,
        ),
        DrainPlan::Empty
    ));
    assert!(matches!(
        state.classify_cq(
            CqObservation {
                kind: u16::MAX,
                sequence_stable: false,
                record_ready: true,
                semantic: CqSemantic::Invalid,
                output_bytes_available: usize::MAX,
                credit: Some(token),
            },
            &grants,
        ),
        DrainPlan::Contended
    ));
    let stale = SlotToken::try_new(token.class(), token.index(), 2).expect("stale token shape");
    let cross = SlotToken::from_raw(credits[1].buffer.token).expect("cross-ring token");
    for credit in [None, Some(stale), Some(cross)] {
        assert!(matches!(
            state.classify_cq(
                CqObservation {
                    kind: cq_kind::COMPLETION,
                    sequence_stable: true,
                    record_ready: true,
                    semantic: CqSemantic::ProtocolAbort,
                    output_bytes_available: usize::MAX,
                    credit,
                },
                &grants,
            ),
            DrainPlan::CompletionFault
        ));
        assert!(matches!(
            state.classify_cq(
                CqObservation {
                    kind: cq_kind::PROTOCOL,
                    sequence_stable: true,
                    record_ready: true,
                    semantic: CqSemantic::ProtocolAbort,
                    output_bytes_available: 0,
                    credit,
                },
                &grants,
            ),
            DrainPlan::ProtocolAbort
        ));
    }
    assert!(matches!(
        state.classify_cq(
            CqObservation {
                kind: cq_kind::PROTOCOL,
                sequence_stable: true,
                record_ready: true,
                semantic: CqSemantic::Invalid,
                output_bytes_available: usize::MAX,
                credit: Some(token),
            },
            &grants,
        ),
        DrainPlan::ProtocolFault
    ));
    assert!(matches!(
        state.classify_cq(
            CqObservation {
                kind: u16::MAX,
                sequence_stable: true,
                record_ready: true,
                semantic: CqSemantic::Notify,
                output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
                credit: Some(token),
            },
            &grants,
        ),
        DrainPlan::ProtocolFault
    ));
    assert!(matches!(
        state.classify_cq(
            CqObservation {
                kind: cq_kind::NOTIFY,
                sequence_stable: true,
                record_ready: true,
                semantic: CqSemantic::Invalid,
                output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
                credit: Some(token),
            },
            &grants,
        ),
        DrainPlan::ProtocolFault
    ));
    assert_eq!(grants.entry_snapshot(token), before);
}

#[test]
fn notify_capacity_blocks_before_semantic_token_or_grant_validation() {
    let topology = topology(2, 2);
    let mut entries = free_backing(&topology);
    let mut grants = GrantTable::initialize(&mut entries, &topology, 23).expect("grant table");
    let credits = issue(&mut grants, 2);
    let token = SlotToken::from_raw(credits[0].buffer.token).expect("credit token");
    let stale = SlotToken::try_new(token.class(), token.index(), 2).expect("stale token shape");
    let cross = SlotToken::from_raw(credits[1].buffer.token).expect("cross-ring token");
    let before = grants.entry_snapshot(token);
    let cross_before = grants.entry_snapshot(cross);
    let state = RingEnterState::new(0);

    for (semantic, credit) in [
        (CqSemantic::Invalid, None),
        (CqSemantic::Notify, Some(stale)),
        (CqSemantic::Notify, Some(cross)),
    ] {
        assert!(matches!(
            state.classify_cq(
                CqObservation {
                    kind: cq_kind::NOTIFY,
                    sequence_stable: true,
                    record_ready: true,
                    semantic,
                    output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize - 1,
                    credit,
                },
                &grants,
            ),
            DrainPlan::NotifyBlocked
        ));
    }
    assert_eq!(grants.entry_snapshot(token), before);
    assert_eq!(grants.entry_snapshot(cross), cross_before);
}

#[test]
fn valid_notify_preflight_can_be_claimed_head_advanced_and_refreshed() {
    let topology = topology(1, 1);
    let mut entries = free_backing(&topology);
    let mut grants = GrantTable::initialize(&mut entries, &topology, 23).expect("grant table");
    let credits = issue(&mut grants, 1);
    let old = SlotToken::from_raw(credits[0].buffer.token).expect("credit token");
    let state = RingEnterState::new(0);

    let preflight = match state.classify_cq(
        CqObservation {
            kind: cq_kind::NOTIFY,
            sequence_stable: true,
            record_ready: true,
            semantic: CqSemantic::Notify,
            output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
            credit: Some(old),
        },
        &grants,
    ) {
        DrainPlan::Notify(preflight) => preflight,
        _ => panic!("valid notification was not preflighted"),
    };
    let claim = grants
        .claim_notify(preflight)
        .expect("claim checked credit");
    // SAFETY: this models the matching CQ-head Release store immediately
    // before consuming the claim.
    let advanced = unsafe { claim.after_release_head_advance() };
    let mut returned = NotificationCreditV1::default();
    let refreshed = advanced.refresh(&mut returned);
    let next = SlotToken::from_raw(returned.buffer.token).expect("refreshed token");
    assert_eq!(refreshed.old_generation, 1);
    assert_eq!(refreshed.new_generation, 2);
    assert_eq!(next.generation(), 2);
    assert_eq!(grants.entry_snapshot(old), None);
    assert_eq!(
        grants
            .entry_snapshot(next)
            .expect("live refreshed credit")
            .state,
        GrantState::Issued
    );
    assert!(matches!(
        state.classify_cq(
            CqObservation {
                kind: cq_kind::NOTIFY,
                sequence_stable: true,
                record_ready: true,
                semantic: CqSemantic::Notify,
                output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
                credit: Some(old),
            },
            &grants,
        ),
        DrainPlan::ProtocolFault
    ));
}

#[test]
fn stale_duplicate_concurrent_cross_ring_and_out_of_range_credits_fault() {
    let topology = topology(2, 4);
    let mut entries = free_backing(&topology);
    let mut grants = GrantTable::initialize(&mut entries, &topology, 23).expect("grant table");
    let credits = issue(&mut grants, 4);
    let ring_zero = RingEnterState::new(0);

    let first = SlotToken::from_raw(credits[0].buffer.token).expect("ring-zero credit");
    let stale = SlotToken::try_new(first.class(), first.index(), 2).expect("stale token shape");
    let cross = SlotToken::from_raw(credits[1].buffer.token).expect("ring-one credit");
    let out_of_range =
        SlotToken::try_new(first.class(), 99, first.generation()).expect("bounded raw token");
    for token in [stale, cross, out_of_range] {
        assert!(matches!(
            ring_zero.classify_cq(
                CqObservation {
                    kind: cq_kind::NOTIFY,
                    sequence_stable: true,
                    record_ready: true,
                    semantic: CqSemantic::Notify,
                    output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
                    credit: Some(token),
                },
                &grants,
            ),
            DrainPlan::ProtocolFault
        ));
    }

    let concurrent_preflight = match ring_zero.classify_cq(
        CqObservation {
            kind: cq_kind::NOTIFY,
            sequence_stable: true,
            record_ready: true,
            semantic: CqSemantic::Notify,
            output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
            credit: Some(first),
        },
        &grants,
    ) {
        DrainPlan::Notify(preflight) => preflight,
        _ => panic!("live credit did not preflight"),
    };
    {
        let _claim = grants
            .claim_notify(concurrent_preflight)
            .expect("first concurrent claimant");
    }
    assert!(matches!(
        ring_zero.classify_cq(
            CqObservation {
                kind: cq_kind::NOTIFY,
                sequence_stable: true,
                record_ready: true,
                semantic: CqSemantic::Notify,
                output_bytes_available: NOTIFICATION_CREDIT_V1_SIZE as usize,
                credit: Some(first),
            },
            &grants,
        ),
        DrainPlan::ProtocolFault
    ));

    assert!(matches!(
        classify_notify_preflight(Err(GrantError::GenerationExhausted)),
        DrainPlan::GenerationExhausted
    ));
}

fn assert_terminal_mapping(
    contender: EnterContender,
    expected_completion: PendingCompletion,
    expected_claimant: ClaimantKind,
) {
    let pending = PendingEnter::new(71);
    assert_eq!(pending.invocation(), 71);
    let right = match pending.contend(contender) {
        PendingOutcome::Won(right) => right,
        PendingOutcome::Lost { .. } => panic!("first contender lost"),
    };
    assert_eq!(right.finish(), expected_completion);
    match pending.contend(EnterContender::Cancel) {
        PendingOutcome::Lost { winner } => assert_eq!(winner, Some(expected_claimant)),
        PendingOutcome::Won(_) => panic!("a second terminal contender won"),
    }
}

#[test]
fn cancel_timeout_wake_fence_and_unload_each_finish_from_one_terminal_cas() {
    for (contender, completion, claimant) in [
        (
            EnterContender::Cancel,
            PendingCompletion::Cancelled,
            ClaimantKind::Cancellation,
        ),
        (
            EnterContender::Timeout,
            PendingCompletion::TimedOut,
            ClaimantKind::Timeout,
        ),
        (
            EnterContender::Wake,
            PendingCompletion::Ready,
            ClaimantKind::EnterContinuation,
        ),
        (
            EnterContender::Fence,
            PendingCompletion::Fenced,
            ClaimantKind::Fence,
        ),
        (
            EnterContender::Unload,
            PendingCompletion::Unloaded,
            ClaimantKind::Unload,
        ),
    ] {
        assert_terminal_mapping(contender, completion, claimant);
    }
}

#[test]
fn simultaneous_terminal_contenders_have_exactly_one_affine_right() {
    let pending = PendingEnter::new(73);
    let start = Arc::new(Barrier::new(5));
    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for contender in [
            EnterContender::Cancel,
            EnterContender::Timeout,
            EnterContender::Wake,
            EnterContender::Fence,
            EnterContender::Unload,
        ] {
            let start = Arc::clone(&start);
            let pending = &pending;
            handles.push(scope.spawn(move || {
                start.wait();
                pending.contend(contender)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("contender thread"))
            .collect::<Vec<_>>()
    });

    let mut winners = 0usize;
    let mut winning_claimant = None;
    let mut losing_claimants = Vec::new();
    for outcome in outcomes {
        match outcome {
            PendingOutcome::Won(right) => {
                winning_claimant = Some(right.claim.winner());
                let _completion = right.finish();
                winners += 1;
            }
            PendingOutcome::Lost { winner } => losing_claimants.push(winner),
        }
    }
    assert_eq!(winners, 1);
    assert!(winning_claimant.is_some());
    assert!(
        losing_claimants
            .iter()
            .all(|winner| *winner == winning_claimant)
    );
}

#[test]
fn cancellation_wins_before_commit_and_loses_after_first_commit() {
    let before_commit = PendingEnter::new(79);
    let cancelled = match before_commit.contend(EnterContender::Cancel) {
        PendingOutcome::Won(right) => right,
        PendingOutcome::Lost { .. } => panic!("cancellation should win first"),
    };
    assert_eq!(cancelled.finish(), PendingCompletion::Cancelled);
    match before_commit.claim_first_commit() {
        PendingOutcome::Lost { winner } => {
            assert_eq!(winner, Some(ClaimantKind::Cancellation));
        }
        PendingOutcome::Won(_) => panic!("commit won after cancellation"),
    }

    let after_commit = PendingEnter::new(83);
    let committed = match after_commit.claim_first_commit() {
        PendingOutcome::Won(right) => right,
        PendingOutcome::Lost { .. } => panic!("first commit should win"),
    };
    match after_commit.contend(EnterContender::Cancel) {
        PendingOutcome::Lost { winner } => {
            assert_eq!(winner, Some(ClaimantKind::EnterContinuation));
        }
        PendingOutcome::Won(_) => panic!("cancellation won after first commit"),
    }
    assert_eq!(committed.finish(), PendingCompletion::SuccessAfterCommit);
}

#[test]
fn cancellation_and_first_commit_race_on_the_same_terminal_owner() {
    for invocation in 100..228u64 {
        let pending = PendingEnter::new(invocation);
        let start = Arc::new(Barrier::new(2));
        let (cancel, commit) = std::thread::scope(|scope| {
            let cancel_start = Arc::clone(&start);
            let cancel_pending = &pending;
            let cancel = scope.spawn(move || {
                cancel_start.wait();
                cancel_pending.contend(EnterContender::Cancel)
            });
            let commit_start = Arc::clone(&start);
            let commit_pending = &pending;
            let commit = scope.spawn(move || {
                commit_start.wait();
                commit_pending.claim_first_commit()
            });
            (
                cancel.join().expect("cancel contender"),
                commit.join().expect("commit contender"),
            )
        });

        match (cancel, commit) {
            (PendingOutcome::Won(right), PendingOutcome::Lost { winner }) => {
                assert_eq!(right.claim.winner(), ClaimantKind::Cancellation);
                assert_eq!(winner, Some(ClaimantKind::Cancellation));
                assert_eq!(right.finish(), PendingCompletion::Cancelled);
            }
            (PendingOutcome::Lost { winner }, PendingOutcome::Won(right)) => {
                assert_eq!(right.claim.winner(), ClaimantKind::EnterContinuation);
                assert_eq!(winner, Some(ClaimantKind::EnterContinuation));
                assert_eq!(right.finish(), PendingCompletion::SuccessAfterCommit);
            }
            _ => panic!("cancel and first commit did not produce exactly one winner"),
        }
    }
}

#[test]
fn empty_and_timeout_results_round_trip_as_exact_forty_eight_byte_prefixes() {
    let topology = topology(1, 1);
    let identity = identity();
    for (request, decision, expected_flags) in [
        (request(identity, 0, 0, 0, 0), EnterDecision::Empty, 0),
        (
            request(identity, 0, enter_request_flags::WAIT_SQ, 0, 17),
            EnterDecision::TimedOut,
            enter_result_flags::TIMED_OUT,
        ),
        (
            request(identity, 0, 0, 0, 0),
            EnterDecision::Ready,
            enter_result_flags::SQ_READY,
        ),
    ] {
        let result = build_empty_result(&request, decision).expect("terminal empty result");
        assert_eq!(result.header.struct_size, ENTER_RESULT_V1_PREFIX_SIZE);
        assert_eq!(result.header.struct_version, CONTROL_VERSION_V1);
        assert_eq!(result.header.required_flags, 0);
        assert_eq!(result.session_epoch, request.session_epoch);
        assert_eq!(result.ring_index, request.ring_index);
        assert_eq!(result.flags, expected_flags);
        assert_eq!(result.cq_drained, 0);
        assert_eq!(result.sq_ready, u32::from(decision == EnterDecision::Ready));
        assert_eq!(result.notification_credit_count, 0);
        assert_eq!(
            result.notification_credit_desc_size,
            NOTIFICATION_CREDIT_V1_SIZE
        );
        assert_eq!(result.notification_credits_offset, 0);
        assert_eq!(result.reserved, 0);

        let mut bytes = [0u8; ENTER_RESULT_V1_PREFIX_SIZE as usize];
        assert_eq!(try_encode(&result, &mut bytes), Ok(bytes.len()));
        let validated: ValidatedEnterResult<'_> =
            validate_enter_result_v1(&bytes, &request, &topology).expect("exact result validates");
        assert_eq!(
            validated.bytes().len(),
            ENTER_RESULT_V1_PREFIX_SIZE as usize
        );
        assert_eq!(validated.prefix(), result);
    }

    let pending = request(identity, 0, enter_request_flags::WAIT_SQ, 0, u32::MAX);
    assert_eq!(
        build_empty_result(&pending, EnterDecision::Pending),
        Err(EnterError::InvalidTimeout)
    );
    assert_eq!(
        build_empty_result(&request(identity, 0, 0, 0, 0), EnterDecision::TimedOut),
        Err(EnterError::InvalidTimeout)
    );
    assert_eq!(
        build_empty_result(
            &request(identity, 0, enter_request_flags::DRAIN_CQ, 1, 0),
            EnterDecision::TimedOut,
        ),
        Err(EnterError::InvalidTimeout)
    );
    assert_eq!(
        build_empty_result(&pending, EnterDecision::TimedOut),
        Err(EnterError::InvalidTimeout)
    );
    assert_eq!(
        build_empty_result(
            &request(identity, 0, enter_request_flags::WAIT_SQ, 0, 17),
            EnterDecision::Empty,
        ),
        Err(EnterError::InvalidTimeout)
    );
    assert_eq!(
        build_empty_result(&pending, EnterDecision::Empty),
        Err(EnterError::InvalidTimeout)
    );
}

#[test]
fn encode_parked_empty_result_writes_a_valid_timed_out_prefix() {
    let topology = topology(1, 1);
    let request = request(identity(), 0, enter_request_flags::WAIT_SQ, 0, 17);
    let mut zeros = [0u8; ENTER_RESULT_V1_PREFIX_SIZE as usize];
    assert!(
        validate_enter_result_v1(&zeros, &request, &topology).is_err(),
        "an all-zero buffer is not a timed-out WAIT result",
    );
    let written = encode_parked_empty_result(&mut zeros, &request, EnterDecision::TimedOut)
        .expect("the prefix encodes");
    assert_eq!(written, ENTER_RESULT_V1_PREFIX_SIZE as usize);
    validate_enter_result_v1(&zeros, &request, &topology).expect("encoded prefix");
}

#[test]
fn result_flags_are_total_over_the_closed_role_decision_and_cq_product() {
    let remaining = enter_result_flags::CQ_REMAINING;
    let blocked = enter_result_flags::CQ_REMAINING | enter_result_flags::NOTIFY_BLOCKED;
    let contended = enter_result_flags::CQ_CONTENDED;
    let ready = enter_result_flags::SQ_READY;
    let timed_out = enter_result_flags::TIMED_OUT;

    for (role, decision, cq, expected) in [
        (
            EnterRole::Sq,
            EnterDecision::Ready,
            CqResultState::None,
            Some(ready),
        ),
        (
            EnterRole::Sq,
            EnterDecision::Pending,
            CqResultState::None,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::TimedOut,
            CqResultState::None,
            Some(timed_out),
        ),
        (
            EnterRole::Sq,
            EnterDecision::Empty,
            CqResultState::None,
            Some(0),
        ),
        (
            EnterRole::Sq,
            EnterDecision::Ready,
            CqResultState::Remaining,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Pending,
            CqResultState::Remaining,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::TimedOut,
            CqResultState::Remaining,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Empty,
            CqResultState::Remaining,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Ready,
            CqResultState::NotifyBlocked,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Pending,
            CqResultState::NotifyBlocked,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::TimedOut,
            CqResultState::NotifyBlocked,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Empty,
            CqResultState::NotifyBlocked,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Ready,
            CqResultState::Contended,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Pending,
            CqResultState::Contended,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::TimedOut,
            CqResultState::Contended,
            None,
        ),
        (
            EnterRole::Sq,
            EnterDecision::Empty,
            CqResultState::Contended,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::Ready,
            CqResultState::None,
            Some(ready),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Pending,
            CqResultState::None,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::TimedOut,
            CqResultState::None,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::Empty,
            CqResultState::None,
            Some(0),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Ready,
            CqResultState::Remaining,
            Some(ready | remaining),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Pending,
            CqResultState::Remaining,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::TimedOut,
            CqResultState::Remaining,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::Empty,
            CqResultState::Remaining,
            Some(remaining),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Ready,
            CqResultState::NotifyBlocked,
            Some(ready | blocked),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Pending,
            CqResultState::NotifyBlocked,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::TimedOut,
            CqResultState::NotifyBlocked,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::Empty,
            CqResultState::NotifyBlocked,
            Some(blocked),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Ready,
            CqResultState::Contended,
            Some(ready | contended),
        ),
        (
            EnterRole::Cq,
            EnterDecision::Pending,
            CqResultState::Contended,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::TimedOut,
            CqResultState::Contended,
            None,
        ),
        (
            EnterRole::Cq,
            EnterDecision::Empty,
            CqResultState::Contended,
            Some(contended),
        ),
    ] {
        assert_eq!(result_flags(role, decision, cq), expected);
    }
}

#[test]
fn drain_result_names_the_credit_tail() {
    let identity = identity();
    let drain = request(identity, 0, enter_request_flags::DRAIN_CQ, 2, 0);
    let result = build_enter_result(&drain, EnterDecision::Empty, 2, CqResultState::None)
        .expect("two-credit drain");
    assert_eq!(result.header.struct_size, 112);
    assert_eq!(result.notification_credit_count, 2);
    assert_eq!(
        result.notification_credits_offset,
        ENTER_RESULT_V1_PREFIX_SIZE
    );
    assert_eq!(result.cq_drained, 2);
    assert_eq!(
        result.notification_credit_desc_size,
        NOTIFICATION_CREDIT_V1_SIZE
    );
    assert!(build_enter_result(&drain, EnterDecision::Empty, 1, CqResultState::None).is_ok());
    let poll = request(identity, 0, 0, 0, 0);
    assert!(build_enter_result(&poll, EnterDecision::Empty, 1, CqResultState::None).is_err());
}

#[test]
fn standalone_cq_remaining_result_round_trips_through_the_abi_validator() {
    let topology = topology(1, 1);
    let identity = identity();
    let drain = request(identity, 0, enter_request_flags::DRAIN_CQ, 1, 0);
    let mut result = build_empty_result(&drain, EnterDecision::Empty).expect("empty result");
    result.flags = result_flags(
        EnterRole::Cq,
        EnterDecision::Empty,
        CqResultState::Remaining,
    )
    .expect("standalone CQ remaining is valid");

    let mut bytes = [0u8; ENTER_RESULT_V1_PREFIX_SIZE as usize];
    assert_eq!(try_encode(&result, &mut bytes), Ok(bytes.len()));
    let validated =
        validate_enter_result_v1(&bytes, &drain, &topology).expect("remaining result validates");
    assert_eq!(validated.prefix(), result);
}

#[test]
fn output_capacity_is_exact_and_a_forty_seven_byte_buffer_cannot_start_a_drain() {
    assert_eq!(notification_capacity(47), None);
    assert_eq!(notification_capacity(48), Some(0));
    assert_eq!(notification_capacity(79), Some(0));
    assert_eq!(notification_capacity(80), Some(1));
    assert_eq!(notification_capacity(112), Some(2));
    assert_eq!(enter_result_size(0), Some(48));
    assert_eq!(enter_result_size(1), Some(80));
    assert_eq!(enter_result_size(2), Some(112));
    assert_eq!(enter_result_size(u32::MAX), None);

    let topology = topology(1, 1);
    let mut entries = free_backing(&topology);
    let mut grants = GrantTable::initialize(&mut entries, &topology, 23).expect("grant table");
    let credits = issue(&mut grants, 1);
    let token = SlotToken::from_raw(credits[0].buffer.token).expect("credit token");
    let before = grants.entry_snapshot(token);
    let output_len = 47usize;
    assert_eq!(notification_capacity(output_len), None);
    assert_eq!(grants.entry_snapshot(token), before);
}

// ---------------------------------------------------------------------------
// R4 Task 14.1: the sealed ring-runtime factory
// ---------------------------------------------------------------------------

use crate::session::{
    ControlBinding, InstalledSession, SessionRegistry, SetupStage, SetupTransaction,
};

fn runtime_identity(n: u64) -> SessionIdentity {
    SessionIdentity {
        mount_id: MountId { lo: n, hi: 41 },
        boot_instance_id: BootInstanceId { lo: 43, hi: 47 },
        session_epoch: 1,
    }
}

/// One installed session, staged far enough to own a ring set.
///
/// Built through the ordinary public API rather than a fixture constructor: a
/// brand minted by a shortcut would not prove that the factory below accepts
/// the brands the real setup path produces.
fn installed_for_rings(n: u64) -> (SessionRegistry<1>, InstalledSession) {
    let mut binding = ControlBinding::new().expect("a fresh binding source has capacity");
    let reservation = binding
        .begin_setup()
        .expect("an empty binding reserves an epoch");
    let mut transaction = SetupTransaction::begin(runtime_identity(n)).expect("a valid identity");
    for stage in [
        SetupStage::LayoutPlanned,
        SetupStage::SectionReady,
        SetupStage::GrantsReady,
        SetupStage::VolumeReady,
        SetupStage::ViewsReady,
        SetupStage::OutputReady,
    ] {
        transaction = transaction
            .stage(stage)
            .expect("the staging order is the roster");
    }
    let mut registry = SessionRegistry::<1>::new();
    let installed = registry
        .install_staging(&transaction, &binding, &reservation)
        .expect("output-ready staging installs");
    (registry, installed)
}

/// Two bind rights from two different sessions, plus their brands.
fn two_rings() -> (
    CqStorageBindRight,
    SessionRingBrand,
    CqStorageBindRight,
    SessionRingBrand,
) {
    let (_r1, mut first) = installed_for_rings(1401);
    let (_r2, mut second) = installed_for_rings(1402);
    let mut a = first.begin_ring_set(1).expect("a fresh install");
    let right_a = a
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand_a = right_a.brand();
    let mut b = second.begin_ring_set(1).expect("a fresh install");
    let right_b = b
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand_b = right_b.brand();
    (right_a, brand_a, right_b, brand_b)
}

#[test]
fn task19_pending_slot_parts_consume_the_ring_bind_right_exactly_once() {
    use crate::enter::build_pending_slot_parts;

    // What `fsring-fsd` will call once per ring when SETUP installs the
    // pending runtime. It hands over the bind right and gets back the five
    // values a native slot stores — and never sees the brand, so there is no
    // path on which a native caller holds one it could pair with a wrong ring.
    let (right, brand, other_right, other_brand) = two_rings();

    // A refusal returns the right exactly as received, so the caller can still
    // abort the whole set. Capacity is what refuses here, and it is checked
    // before anything is built.
    let (error, right) = match build_pending_slot_parts(right, 0) {
        Ok(_) => unreachable!("a zero capacity builds nothing"),
        Err(returned) => returned,
    };
    assert_eq!(error, RingRuntimeBuildError::InvalidPendingResultCapacity);
    let (error, right) =
        match build_pending_slot_parts(right, MAX_PENDING_RESULT_CAPACITY.saturating_add(1)) {
            Ok(_) => unreachable!("a capacity past the bound builds nothing"),
            Err(returned) => returned,
        };
    assert_eq!(error, RingRuntimeBuildError::InvalidPendingResultCapacity);

    // The same right still works, which is what makes the two refusals above
    // about capacity rather than about the right being damaged.
    let mut parts = build_pending_slot_parts(right, 64)
        .unwrap_or_else(|(error, _)| unreachable!("the retained right builds: {error:?}"));

    // Every one of the five names the same ring. A bundle whose wake slot
    // named a different ring than its ledger is the state the shared brand
    // exists to make unrepresentable.
    assert_eq!(parts.result_slot.brand(), brand);
    assert_eq!(parts.result_slot.capacity(), 64);
    assert_eq!(parts.owners.brand(), brand);
    assert_eq!(parts.wake.brand(), brand);
    assert_eq!(parts.schedule.state(), WorkerScheduleState::Idle);
    assert_eq!(parts.schedule.axis(), InstallAxis::Installing);

    // And the schedule is bound to THIS ring: an install branded for the other
    // ring is refused, so the schedule cannot be paired with a foreign one.
    let foreign = PendingInstallId::for_test(other_brand, 1);
    assert_eq!(
        parts.schedule.begin_install(foreign).err(),
        Some(crate::session::PendingError::WrongRing),
    );
    let own = PendingInstallId::for_test(brand, 1);
    assert!(parts.schedule.begin_install(own).is_ok());

    // The other ring's right is untouched by any of the above.
    let other = build_pending_slot_parts(other_right, 64)
        .unwrap_or_else(|(error, _)| unreachable!("an independent ring builds: {error:?}"));
    assert_eq!(other.owners.brand(), other_brand);
}

#[test]
fn sealed_runtime_factory_is_the_only_component_constructor() {
    let (right, brand, _other, _other_brand) = two_rings();
    let parts = build_ring_runtime_parts(brand, 64, right).unwrap_or_else(|(error, _)| {
        unreachable!("a matching brand and valid capacity build: {error:?}")
    });
    assert_eq!(parts.brand(), brand);

    // The aggregate is the only source of the four components, and it hands
    // them out exactly once.
    let (state, result_slot, owners, wake, cq_bind) = parts.into_parts();
    assert_eq!(result_slot.brand(), brand);
    assert_eq!(result_slot.capacity(), 64);
    assert!(
        result_slot.install().is_none(),
        "a fresh slot holds no install"
    );
    assert_eq!(owners.brand(), brand);
    assert!(owners.is_empty(), "a fresh ledger owns nothing");
    assert_eq!(wake.brand(), brand);
    assert!(!wake.has_wake(), "a fresh slot holds no wake");
    assert!(
        wake.is_covered(),
        "nothing recorded means nothing outstanding"
    );

    // The state came from the brand, so its ring index cannot disagree with the
    // three components beside it. `classify_request` compares `self.ring_index`
    // against the request, so a state built with the wrong index would refuse
    // every ENTER for the ring it is supposed to serve.
    assert_eq!(state.brand_ring_index_for_test(), brand.ring_index());

    // And the CQ right is retained rather than consumed: it is the proof this
    // aggregate speaks for this ring's CQ storage.
    assert_eq!(cq_bind.brand(), brand);
}

#[test]
fn runtime_factory_rejects_cross_brand_cq_bind_without_consuming_right() {
    let (right_a, brand_a, right_b, brand_b) = two_rings();
    assert_ne!(brand_a, brand_b);

    // A right from session B against session A's brand is refused, and the
    // right comes back so B can still build its own runtime with it.
    let (error, returned) = match build_ring_runtime_parts(brand_a, 64, right_b) {
        Ok(_) => unreachable!("a cross-brand bind must not build"),
        Err(pair) => pair,
    };
    assert_eq!(error, RingRuntimeBuildError::Role(RoleError::WrongRing));
    assert_eq!(returned.brand(), brand_b, "the exact right came back");

    let parts = build_ring_runtime_parts(brand_b, 64, returned)
        .unwrap_or_else(|(error, _)| unreachable!("the returned right still works: {error:?}"));
    assert_eq!(parts.brand(), brand_b);
    let _ = build_ring_runtime_parts(brand_a, 64, right_a);
}

#[test]
fn direct_factory_invalid_capacity_returns_the_exact_cq_right() {
    let (right, brand, _other, _other_brand) = two_rings();

    // Zero and past-the-maximum are both invalid, and capacity is checked
    // before the brand, so neither builds anything.
    let (error, right) = match build_ring_runtime_parts(brand, 0, right) {
        Ok(_) => unreachable!("zero capacity must not build"),
        Err(pair) => pair,
    };
    assert_eq!(error, RingRuntimeBuildError::InvalidPendingResultCapacity);

    let (error, right) =
        match build_ring_runtime_parts(brand, MAX_PENDING_RESULT_CAPACITY.saturating_add(1), right)
        {
            Ok(_) => unreachable!("an oversized capacity must not build"),
            Err(pair) => pair,
        };
    assert_eq!(error, RingRuntimeBuildError::InvalidPendingResultCapacity);
    assert_eq!(right.brand(), brand, "the exact right came back both times");

    // The boundary itself is valid.
    let parts = build_ring_runtime_parts(brand, MAX_PENDING_RESULT_CAPACITY, right)
        .unwrap_or_else(|(error, _)| unreachable!("the maximum is valid: {error:?}"));
    let (_state, slot, _owners, _wake, _bind) = parts.into_parts();
    assert_eq!(slot.capacity(), MAX_PENDING_RESULT_CAPACITY);
}

#[test]
fn wrong_brand_and_invalid_capacity_are_distinct_build_errors() {
    let (right_a, brand_a, right_b, brand_b) = two_rings();

    // Both wrong at once: capacity is reported, because it is checked first and
    // a caller who passed a nonsense capacity has not yet been told anything
    // about brands. The two errors are never the same value.
    let (both, right_b) = match build_ring_runtime_parts(brand_a, 0, right_b) {
        Ok(_) => unreachable!("neither input is valid"),
        Err(pair) => pair,
    };
    assert_eq!(both, RingRuntimeBuildError::InvalidPendingResultCapacity);

    let (brand_only, _right_b) = match build_ring_runtime_parts(brand_a, 64, right_b) {
        Ok(_) => unreachable!("a cross-brand bind must not build"),
        Err(pair) => pair,
    };
    assert_eq!(
        brand_only,
        RingRuntimeBuildError::Role(RoleError::WrongRing)
    );
    assert_ne!(both, brand_only, "the two refusals are distinguishable");
    let _ = (right_a, brand_b);
}

#[test]
fn valid_retry_after_each_factory_refusal_succeeds_once() {
    let (right, brand, foreign_right, foreign_brand) = two_rings();

    // Walk every refusal in turn with the same right, then build with it.
    let (_e1, right) = build_ring_runtime_parts(brand, 0, right)
        .map_or_else(|pair| ((), pair.1), |_| unreachable!("zero capacity"));
    let (_e2, right) =
        build_ring_runtime_parts(brand, MAX_PENDING_RESULT_CAPACITY.saturating_add(1), right)
            .map_or_else(|pair| ((), pair.1), |_| unreachable!("oversized capacity"));
    let (_e3, right) = build_ring_runtime_parts(foreign_brand, 64, right)
        .map_or_else(|pair| ((), pair.1), |_| unreachable!("cross brand"));

    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("three refusals consumed nothing: {error:?}"));
    assert_eq!(parts.brand(), brand);

    // And exactly once: the right is inside the aggregate now, so a second
    // build for this ring would need a second right, which Task 13 never mints.
    let (_state, _slot, _owners, _wake, bind) = parts.into_parts();
    assert_eq!(bind.brand(), brand);
    let _ = foreign_right;
}

// ---------------------------------------------------------------------------
// R4 Task 14.1: the state-owned invocation source and two disjoint authorities
// ---------------------------------------------------------------------------

/// A branded R4 state, plus the brand it serves.
fn branded_state(n: u64) -> (RingEnterState, SessionRingBrand) {
    let (_registry, mut installed) = installed_for_rings(n);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("a matching brand builds: {error:?}"));
    let (state, _slot, _owners, _wake, _bind) = parts.into_parts();
    (state, brand)
}

#[test]
fn sq_wait_and_cq_consumer_authorities_are_type_disjoint() {
    let (mut state, brand) = branded_state(1410);

    let sq = state
        .acquire_sq_wait()
        .expect("a fresh ring has no SQ owner");
    let cq = state
        .acquire_cq_consumer()
        .expect("SQ and CQ are separate roles");

    // Both name the same ring, and differ only in domain -- which is the case a
    // single tagged type would represent with one field and let a caller pass
    // to the wrong consumer. Here they are different types, so the mistake is
    // not expressible: `release_sq_wait(cq)` does not compile, and no runtime
    // check is what stops it.
    assert_eq!(sq.execution().ring(), brand);
    assert_eq!(cq.execution().ring(), brand);
    assert_eq!(sq.execution().domain(), EnterExecutionDomain::SqWait);
    assert_eq!(cq.execution().domain(), EnterExecutionDomain::CqConsumer);
    assert_ne!(sq.execution(), cq.execution());
    assert_ne!(
        sq.execution().invocation(),
        cq.execution().invocation(),
        "two live authorities never share an invocation"
    );

    // Each role is exclusive while held, and each release frees only its own.
    assert_eq!(state.acquire_sq_wait().err(), Some(RoleError::DeviceBusy));
    assert_eq!(
        state.acquire_cq_consumer().err(),
        Some(RoleError::DeviceBusy)
    );
    state
        .release_sq_wait(sq)
        .unwrap_or_else(|(error, _)| unreachable!("the lease is this ring's: {error:?}"));
    assert!(
        state.acquire_sq_wait().is_ok(),
        "releasing SQ frees exactly SQ"
    );
    assert_eq!(
        state.acquire_cq_consumer().err(),
        Some(RoleError::DeviceBusy),
        "releasing SQ did not free CQ"
    );
    let _ = cq;
}

#[test]
fn caller_cannot_supply_invocation_irp_observation_or_execution_domain() {
    let (mut state, brand) = branded_state(1411);

    // The R4 acquisition API takes no arguments at all. Every component of the
    // resulting brand -- ring, invocation, domain -- comes from the state or
    // from the call site's choice of method, never from a caller-supplied
    // value. The predecessor `acquire_role(invocation, role)` took both.
    let _: fn(&mut RingEnterState) -> Result<SqWaitRoleLease, RoleError> =
        RingEnterState::acquire_sq_wait;
    let _: fn(&mut RingEnterState) -> Result<CqConsumerToken, RoleError> =
        RingEnterState::acquire_cq_consumer;

    let first = state.acquire_sq_wait().expect("a fresh ring");
    assert_eq!(first.execution().ring(), brand);
    // Invocations come from the state, so they are dense and increasing rather
    // than whatever a caller happened to pass.
    let first_id = first.execution().invocation();
    state
        .release_sq_wait(first)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let second = state.acquire_sq_wait().expect("released");
    assert!(
        second.execution().invocation() > first_id,
        "a re-acquired role never reuses the released invocation"
    );
    let _ = state.release_sq_wait(second);
}

#[test]
fn maximum_invocation_is_minted_once_then_exhausts_permanently() {
    let (mut state, _brand) = branded_state(1412);
    state.seed_last_invocation_for_test();

    // u64::MAX is issued exactly once...
    let last = state
        .acquire_sq_wait()
        .expect("the last identity is usable");
    assert_eq!(
        last.execution().invocation().get(),
        u64::MAX,
        "the final identity is issued, not discarded"
    );
    state
        .release_sq_wait(last)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    // ...and the source then latches shut. Not busy -- exhausted -- and it stays
    // exhausted, because wrapping to 1 would hand out an identity a live
    // authority may already carry.
    for _ in 0..3 {
        assert_eq!(
            state.acquire_sq_wait().err(),
            Some(RoleError::InvocationIdExhausted)
        );
        assert_eq!(
            state.acquire_cq_consumer().err(),
            Some(RoleError::InvocationIdExhausted),
            "both domains draw on the one exhausted source"
        );
    }
}

#[test]
fn failed_role_preflight_does_not_consume_an_invocation() {
    let (mut state, _brand) = branded_state(1413);

    let held = state.acquire_sq_wait().expect("a fresh ring");
    let held_id = held.execution().invocation();

    // Poll a busy ring repeatedly. Each refusal happens before the mint, so no
    // identity burns; minting first would spend one per poll, and a busy ring
    // is polled often.
    for _ in 0..8 {
        assert_eq!(state.acquire_sq_wait().err(), Some(RoleError::DeviceBusy));
    }
    state
        .release_sq_wait(held)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    let next = state.acquire_sq_wait().expect("released");
    assert_eq!(
        next.execution().invocation().get(),
        held_id.get().saturating_add(1),
        "eight refusals consumed no identity"
    );
    let _ = state.release_sq_wait(next);
}

#[test]
fn foreign_role_release_returns_the_exact_affine_value() {
    let (mut first, first_brand) = branded_state(1414);
    let (mut second, second_brand) = branded_state(1415);
    assert_ne!(first_brand, second_brand);

    let foreign = first.acquire_sq_wait().expect("a fresh ring");
    let foreign_id = foreign.execution().invocation();

    // Another ring's state refuses it by ring, and hands it straight back.
    let (error, foreign) = match second.release_sq_wait(foreign) {
        Ok(()) => unreachable!("a foreign lease must not release"),
        Err(pair) => pair,
    };
    assert_eq!(error, RoleError::WrongRing);
    assert_eq!(foreign.execution().ring(), first_brand);
    assert_eq!(foreign.execution().invocation(), foreign_id);

    // A predecessor state has no brand at all, and refuses on that.
    let mut unbranded = RingEnterState::new(0);
    let (error, foreign) = match unbranded.release_sq_wait(foreign) {
        Ok(()) => unreachable!("an unbranded state owns nothing"),
        Err(pair) => pair,
    };
    assert_eq!(error, RoleError::WrongState);
    assert_eq!(
        unbranded.acquire_sq_wait().err(),
        Some(RoleError::WrongState),
        "the R4 API refuses a predecessor state outright"
    );
    assert!(unbranded.brand().is_none());

    // And its own state still accepts it, so the two refusals above were about
    // the state and not about the lease having been damaged in transit.
    first
        .release_sq_wait(foreign)
        .unwrap_or_else(|(error, _)| unreachable!("its own state accepts it: {error:?}"));
    assert!(first.acquire_sq_wait().is_ok(), "the role really did free");

    // A stale invocation for the right ring is refused by invocation.
    let live = second.acquire_sq_wait().expect("a fresh ring");
    let live_id = live.execution().invocation();
    second
        .release_sq_wait(live)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let reacquired = second.acquire_sq_wait().expect("released");
    assert_ne!(reacquired.execution().invocation(), live_id);
    let _ = second.release_sq_wait(reacquired);
}

#[test]
fn brand_adoption_is_one_shot_index_checked_and_refused_once_a_role_is_live() {
    // The session shell's per-ring state is built by `new` before the ring set
    // exists, so `adopt_ring_brand` is the only way it can ever carry a brand
    // -- and an unbranded state answers `WrongState` to every R4 role request,
    // which is what made the fence unable to acquire a CQ consumer on any ring.
    //
    // Being the only way in is exactly why its refusals matter: without them it
    // is a way to re-identify a LIVE ring, under authorities its previous
    // identity already minted.
    let (_registry, mut installed) = installed_for_rings(1417);
    let mut set = installed.begin_ring_set(2).expect("a fresh install");
    let r0 = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0")
        .into_brand();
    let r1 = set
        .next_ring()
        .expect("identities available")
        .expect("ring 1")
        .into_brand();

    // An unbranded state refuses every R4 role, which is the defect itself.
    let mut shell = RingEnterState::new(r0.ring_index());
    assert_eq!(
        shell.acquire_cq_consumer().expect_err("no brand, no role"),
        RoleError::WrongState,
        "an unbranded shell state must refuse the fence's CQ consumer"
    );

    // A brand for another ring is refused: the index is checked, not assumed.
    assert_eq!(
        shell.adopt_ring_brand(r1).expect_err("wrong ring"),
        RoleError::WrongRing
    );

    // The right brand is adopted once, and the role it was blocking now works.
    shell.adopt_ring_brand(r0).expect("ring 0 adopts ring 0");
    let token = shell
        .acquire_cq_consumer()
        .expect("a branded shell state serves the fence");
    assert_eq!(token.execution().ring(), r0);

    // Not twice, and not while a role is live -- the outstanding token above
    // names the identity a second adoption would replace.
    assert_eq!(
        shell.adopt_ring_brand(r0).expect_err("already branded"),
        RoleError::WrongState
    );
    let _ = shell.release_cq_consumer(token);

    // Still refused after the release: one shot means one shot.
    assert_eq!(
        shell.adopt_ring_brand(r0).expect_err("still branded"),
        RoleError::WrongState
    );

    // And a state that has issued a role before being branded cannot be
    // branded either. `new` cannot issue an R4 role, so this is reached
    // through a state that already carries one.
    let mut live = RingEnterState::for_brand(r1);
    let held = live.acquire_cq_consumer().expect("a fresh ring");
    assert_eq!(
        live.adopt_ring_brand(r1)
            .expect_err("a live role blocks it"),
        RoleError::WrongState
    );
    let _ = live.release_cq_consumer(held);
}

#[test]
fn maximum_role_state_id_refuses_setup_without_aliasing_an_old_ring() {
    // Task 13's per-ring state identity draws on a nonwrapping source, and each
    // ring of each set gets its own. Two sets of the same session therefore
    // never share one, which is what stops a brand from an earlier set passing
    // a later set's check.
    let (_registry, mut installed) = installed_for_rings(1416);
    let mut first = installed.begin_ring_set(2).expect("a fresh install");
    let a0 = first
        .next_ring()
        .expect("identities available")
        .expect("ring 0")
        .into_brand();
    let a1 = first
        .next_ring()
        .expect("identities available")
        .expect("ring 1")
        .into_brand();
    first.abort();

    let mut second = installed
        .begin_ring_set(2)
        .expect("an aborted set left nothing");
    let b0 = second
        .next_ring()
        .expect("identities available")
        .expect("ring 0")
        .into_brand();

    // Same session, same ring index, different state identity -- so a state
    // built for one is not the state the other's authorities name.
    assert_eq!(a0.ring_index(), b0.ring_index());
    assert_ne!(a0, b0, "a re-initialized ring 0 is a different ring 0");
    assert_ne!(a0, a1, "two rings of one set never alias");

    let mut state = RingEnterState::for_brand(b0);
    let lease = state.acquire_sq_wait().expect("a fresh ring");
    assert_eq!(lease.execution().ring(), b0);
    assert_ne!(lease.execution().ring(), a0);

    let mut stale = RingEnterState::for_brand(a0);
    let (error, lease) = match stale.release_sq_wait(lease) {
        Ok(()) => unreachable!("the superseded ring must not release it"),
        Err(pair) => pair,
    };
    assert_eq!(error, RoleError::WrongRing);
    let _ = state.release_sq_wait(lease);
}

// ---------------------------------------------------------------------------
// R4 Task 14.3: owner kinds, coalescing wakes, and the worker schedule machine
// ---------------------------------------------------------------------------

/// A branded ring, one install id on it, and the three pending components.
///
/// Built through `build_ring_runtime_parts` rather than by hand: the components
/// have no other constructor, and a fixture that reached around the factory
/// would not be testing the values production actually gets.
fn pending_fixture(
    n: u64,
) -> (
    PendingInstallId,
    PendingOwnerLedger,
    PendingWakeSlot,
    PendingWorkerSchedule,
) {
    let (_registry, mut installed) = installed_for_rings(n);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("a matching brand builds: {error:?}"));
    let (_state, _slot, ledger, wake, _bind) = parts.into_parts();
    (
        PendingInstallId::for_test(brand, 1),
        ledger,
        wake,
        PendingWorkerSchedule::for_brand(brand),
    )
}

/// A wake batch belonging to an install this schedule does not serve.
///
/// It comes from a whole separate fixture, because a `CqStorageBindRight` is
/// minted once per ring and the caller has already spent theirs -- which is
/// itself the property Task 13 exists to give.
fn foreign_batch() -> WorkerWakeBatch {
    let (foreign_install, _ledger, mut wake, _schedule) = pending_fixture(9000);
    wake.record_wake(foreign_install, PendingReason::Readiness)
        .expect("its own slot owns it");
    wake.take_for_worker(foreign_install)
        .expect("a stored wake")
        .into_batch()
}

#[test]
fn idle_queued_running_and_completing_match_the_exact_worker_owner_slot() {
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1430);
    ledger
        .bind_install(install)
        .expect("a fresh ledger binds once");
    schedule
        .begin_install(install)
        .expect("a fresh schedule binds once");

    // Installing: nothing may be queued yet.
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);
    assert_eq!(schedule.axis(), InstallAxis::Installing);
    assert_eq!(
        schedule.queue_worker(install).err(),
        Some(PendingError::WrongRingState)
    );

    schedule
        .handoff_done(install)
        .expect("the installer published");
    assert_eq!(
        schedule.handoff_done(install).err(),
        Some(PendingError::WrongRingState),
        "handoff happens once"
    );

    // Idle -> Queued -> Running -> Completing, each step demanding the exact
    // Worker owner and the exact state.
    wake.record_wake(install, PendingReason::Readiness)
        .expect("this ring owns this install");
    schedule.queue_worker(install).expect("handoff is done");
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);

    let decision = wake.take_for_worker(install).expect("a stored wake");
    let batch = decision.into_batch();
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("no worker owns it yet");

    // A non-Worker token cannot begin a pass, and the refusal returns both.
    let installer = ledger
        .acquire_owner(install, PendingOwnerKind::Installer)
        .expect("installer is a distinct kind");
    let (error, installer, batch) = match schedule.begin_worker_pass(installer, batch) {
        Ok(_) => unreachable!("an installer token must not begin a worker pass"),
        Err(triple) => triple,
    };
    assert_eq!(error, PendingError::WrongOwnerKind);

    let (worker, batch) = schedule
        .begin_worker_pass(worker, batch)
        .unwrap_or_else(|(error, _, _)| unreachable!("the worker token is exact: {error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Running);
    assert!(batch.covers(PendingReason::Readiness));

    let (worker, rescheduled) = schedule
        .finish_worker_pass(worker)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert!(
        rescheduled.is_none(),
        "nothing arrived during the pass, so nothing is owed"
    );
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);

    // Completing needs Running, not Idle.
    let (error, worker) = match schedule.begin_worker_completion(worker) {
        Ok(_) => unreachable!("an idle schedule has no pass to complete"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRingState);

    ledger
        .release_owner(worker)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    ledger
        .release_owner(installer)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert!(ledger.owners_drained(), "every owner left");
}

#[test]
fn worker_begin_requires_queued_state_token_and_exact_wake_batch() {
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1431);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");
    schedule.handoff_done(install).expect("published");

    wake.record_wake(install, PendingReason::Timeout)
        .expect("owns it");
    let batch = wake.take_for_worker(install).expect("stored").into_batch();
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");

    // Idle is not Queued: the state, the token, and the batch are all required
    // and the refusal returns every one of them.
    let (error, worker, batch) = match schedule.begin_worker_pass(worker, batch) {
        Ok(_) => unreachable!("an idle schedule has no queued pass"),
        Err(triple) => triple,
    };
    assert_eq!(error, PendingError::WrongRingState);
    assert!(batch.covers(PendingReason::Timeout), "the batch is intact");

    // A batch for another install is refused even in the right state.
    schedule.queue_worker(install).expect("handoff is done");
    let (error, worker, _foreign) = match schedule.begin_worker_pass(worker, foreign_batch()) {
        Ok(_) => unreachable!("a foreign batch must not begin this pass"),
        Err(triple) => triple,
    };
    assert_eq!(error, PendingError::WrongInstall);

    let (worker, batch) = schedule
        .begin_worker_pass(worker, batch)
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Running);
    let _ = (worker, batch);
}

#[test]
fn worker_completion_requires_running_state_and_consumes_same_token() {
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1432);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");
    schedule.handoff_done(install).expect("published");
    wake.record_wake(install, PendingReason::Fence)
        .expect("owns it");
    schedule.queue_worker(install).expect("handoff is done");
    let batch = wake.take_for_worker(install).expect("stored").into_batch();
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");
    let (worker, _batch) = schedule
        .begin_worker_pass(worker, batch)
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));

    // A Cancel owner cannot complete a worker pass, and comes back intact.
    let cancel = ledger
        .acquire_owner(install, PendingOwnerKind::Cancel)
        .expect("cancel is a distinct kind");
    let (error, cancel) = match schedule.begin_worker_completion(cancel) {
        Ok(_) => unreachable!("only the worker completes its own pass"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongOwnerKind);
    assert_eq!(cancel.kind(), PendingOwnerKind::Cancel);

    let worker = schedule
        .begin_worker_completion(worker)
        .unwrap_or_else(|(error, _)| unreachable!("Running completes: {error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Completing);

    // Completing admits no further queueing.
    assert_eq!(
        schedule.queue_worker(install).err(),
        Some(PendingError::Closing)
    );
    ledger
        .release_owner(worker)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
    ledger
        .release_owner(cancel)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
}

#[test]
fn a_completing_pass_that_takes_no_irp_can_still_close_itself() {
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1433);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");
    schedule.handoff_done(install).expect("published");
    wake.record_wake(install, PendingReason::Fence)
        .expect("owns it");
    schedule.queue_worker(install).expect("handoff is done");
    let batch = wake.take_for_worker(install).expect("stored").into_batch();
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");
    let (worker, _batch) = schedule
        .begin_worker_pass(worker, batch)
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));

    // Running is not a completion to abandon.
    let (error, worker) = match schedule.abandon_worker_completion(worker) {
        Ok(_) => unreachable!("only a declared completion can be abandoned"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRingState);

    let worker = schedule
        .begin_worker_completion(worker)
        .unwrap_or_else(|(error, _)| unreachable!("Running completes: {error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Completing);

    // This is the wedge the pass would otherwise leave: `Completing` refuses
    // to finish and refuses to queue, so nothing could ever run here again.
    assert_eq!(
        schedule.queue_worker(install).err(),
        Some(PendingError::Closing)
    );

    let worker = schedule
        .abandon_worker_completion(worker)
        .unwrap_or_else(|(error, _)| unreachable!("a completion is abandonable: {error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Running);

    // And now the ordinary finish closes the pass, which is the whole point of
    // returning to `Running` rather than to `Idle`.
    let (worker, requeue) = schedule
        .finish_worker_pass(worker)
        .unwrap_or_else(|(error, _)| unreachable!("Running finishes: {error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);
    assert!(requeue.is_none());
    ledger
        .release_owner(worker)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
}

#[test]
fn a_queued_pass_that_cannot_begin_returns_the_ring_to_idle() {
    // The wedge this exists to prevent: a work item queued by the installer's
    // handoff can run before the parked plan is stored, so the pass never
    // begins and the schedule stays `Queued`. `Queued` refuses to queue again,
    // so without a way back to `Idle` every later wake is stored with nothing
    // scheduled to take it, while the IRP the worker already dequeued from the
    // CSQ sits uncancellable.
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1451);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");
    schedule.handoff_done(install).expect("published");
    wake.record_wake(install, PendingReason::Readiness)
        .expect("owns it");
    schedule.queue_worker(install).expect("queued");
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);

    // Only `Queued` is accepted, and the token comes back so the caller can
    // release it: leaving the Worker owner held would make the next wake refuse
    // with `DuplicateOwner`, which is the same wedge one state along.
    let worker = schedule
        .abandon_queued_pass(worker)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);
    ledger
        .release_owner(worker)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
    assert!(!ledger.holds(PendingOwnerKind::Worker));

    // And the ring really does accept work again: the reason the abandoned pass
    // never consumed is still in the slot, and the next wake queues a pass over
    // it rather than answering `Stored` forever.
    let mut owner = None;
    let outcome = record_and_schedule_pending(
        install,
        PendingReason::Unload,
        &mut schedule,
        &mut wake,
        &mut ledger,
        &mut owner,
    )
    .expect("an idle ring accepts a wake");
    let right = match outcome {
        PendingWakeOutcome::Queued(right) => right,
        other => unreachable!("an idle ring queues a pass, got {other:?}"),
    };
    // SAFETY: discharged exactly as the native worker discharges it.
    unsafe { right.commit_after_work_queued() };
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);
    let batch = wake.take_for_worker(install).expect("stored").into_batch();
    assert!(batch.covers(PendingReason::Readiness));
    assert!(batch.covers(PendingReason::Unload));
    let held = owner.take().expect("the queueing wake took the one token");
    ledger
        .release_owner(held)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
}

#[test]
fn abandoning_refuses_every_state_a_pass_actually_began_from() {
    // The refusal is the other half. `Running`, `RunningReschedule` and
    // `Completing` all belong to a pass that really did begin, and returning
    // any of them to `Idle` would drop a pass that is still driving.
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1452);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");
    schedule.handoff_done(install).expect("published");

    // `Idle`: nothing was queued, so there is nothing to put back.
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");
    let (error, worker) = match schedule.abandon_queued_pass(worker) {
        Ok(_) => unreachable!("an idle schedule has no queued pass to abandon"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRingState);

    // `Running`: a pass that began owns the state.
    wake.record_wake(install, PendingReason::Readiness)
        .expect("owns it");
    schedule.queue_worker(install).expect("queued");
    let batch = wake.take_for_worker(install).expect("stored").into_batch();
    let (worker, _batch) = schedule
        .begin_worker_pass(worker, batch)
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Running);
    let (error, worker) = match schedule.abandon_queued_pass(worker) {
        Ok(_) => unreachable!("a running pass may not be abandoned"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRingState);
    assert_eq!(schedule.state(), WorkerScheduleState::Running);

    // A foreign install never reaches the state test at all.
    let (other, mut other_ledger, _other_wake, _other_schedule) = pending_fixture(1453);
    other_ledger.bind_install(other).expect("binds");
    let foreign = other_ledger
        .acquire_owner(other, PendingOwnerKind::Worker)
        .expect("free");
    let (error, foreign) = match schedule.abandon_queued_pass(foreign) {
        Ok(_) => unreachable!("a foreign install owns nothing here"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongInstall);
    other_ledger
        .release_owner(foreign)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
    ledger
        .release_owner(worker)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
}

#[test]
fn running_reschedule_moves_the_next_batch_without_a_second_worker() {
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1433);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");
    schedule.handoff_done(install).expect("published");
    wake.record_wake(install, PendingReason::Readiness)
        .expect("owns it");
    schedule.queue_worker(install).expect("queued");
    let batch = wake.take_for_worker(install).expect("stored").into_batch();
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");
    let (worker, _batch) = schedule
        .begin_worker_pass(worker, batch)
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));

    // A wake during the pass reschedules the same worker rather than queuing a
    // second. The ledger would refuse a second Worker owner anyway; this is
    // where that refusal stops being needed.
    wake.record_wake(install, PendingReason::Unload)
        .expect("owns it");
    schedule
        .queue_worker(install)
        .expect("a running pass reschedules");
    assert_eq!(schedule.state(), WorkerScheduleState::RunningReschedule);
    assert_eq!(
        ledger
            .acquire_owner(install, PendingOwnerKind::Worker)
            .err(),
        Some(PendingError::DuplicateOwner),
        "one Worker owner at a time"
    );

    // A rescheduled pass may not complete: it still owes one pass over reasons
    // already recorded, and completing would drop them.
    let (error, worker) = match schedule.begin_worker_completion(worker) {
        Ok(_) => unreachable!("a rescheduled pass still owes work"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRingState);

    // Finishing atomically becomes the next Queued and reports it.
    let (worker, rescheduled) = schedule
        .finish_worker_pass(worker)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let right = rescheduled.expect("the reschedule was reported, not dropped");
    // SAFETY: discharged exactly as the native worker discharges it, after the
    // one queue call the right stands for.
    unsafe { right.commit_after_work_queued() };
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);

    // And the reasons deposited during the pass are still there.
    let next = wake
        .take_for_worker(install)
        .expect("the second wake survived");
    assert_eq!(next.reason(), PendingReason::Unload);
    ledger
        .release_owner(worker)
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
}

#[test]
fn noncancel_wake_priority_is_unload_fence_timeout_readiness() {
    let order = PendingReason::NONCANCEL_PRIORITY;
    assert_eq!(
        order,
        [
            PendingReason::Unload,
            PendingReason::Fence,
            PendingReason::Timeout,
            PendingReason::Readiness,
        ]
    );

    // Every ordered pair: the higher-priority reason is selected no matter
    // which arrived first, so the choice is the roster and not the order of
    // arrival.
    let mut checked = 0;
    for (high_index, high) in order.iter().copied().enumerate() {
        for low in order.iter().copied().skip(high_index.saturating_add(1)) {
            for (first, second) in [(high, low), (low, high)] {
                let (install, _ledger, mut wake, _schedule) =
                    pending_fixture(1440_u64.saturating_add(checked));
                wake.record_wake(install, first).expect("owns it");
                wake.record_wake(install, second).expect("coalesces");
                let decision = wake.take_for_worker(install).expect("a stored wake");
                assert_eq!(
                    decision.reason(),
                    high,
                    "{first:?} then {second:?} must select {high:?}"
                );
                // Coalescing keeps both: the loser is not discarded, it is
                // carried in the batch so the pass can see it happened.
                assert!(decision.batch().covers(first));
                assert!(decision.batch().covers(second));
                checked = checked.saturating_add(1);
            }
        }
    }
    assert_eq!(checked, 12, "four reasons make six unordered pairs, twice");
}

#[test]
fn worker_wake_priority_is_unload_fence_cancel_timeout_readiness() {
    let order = PendingReason::WORKER_PRIORITY;
    assert_eq!(
        order,
        [
            PendingReason::Unload,
            PendingReason::Fence,
            PendingReason::Cancel,
            PendingReason::Timeout,
            PendingReason::Readiness,
        ]
    );

    // Every ordered pair, including Cancel: a CSQ cancel callback cannot
    // complete at DISPATCH, so the PASSIVE worker must select Cancel above
    // Timeout/Readiness. Unload and Fence still outrank it.
    let mut checked = 0;
    for (high_index, high) in order.iter().copied().enumerate() {
        for low in order.iter().copied().skip(high_index.saturating_add(1)) {
            for (first, second) in [(high, low), (low, high)] {
                let (install, _ledger, mut wake, _schedule) =
                    pending_fixture(1480_u64.saturating_add(checked));
                wake.record_wake(install, first).expect("owns it");
                wake.record_wake(install, second).expect("coalesces");
                let decision = wake.take_for_worker(install).expect("a stored wake");
                assert_eq!(
                    decision.reason(),
                    high,
                    "{first:?} then {second:?} must select {high:?}"
                );
                assert!(decision.batch().covers(first));
                assert!(decision.batch().covers(second));
                checked = checked.saturating_add(1);
            }
        }
    }
    assert_eq!(checked, 20, "five reasons make ten unordered pairs, twice");

    let (install, _ledger, mut wake, _schedule) = pending_fixture(1510);
    wake.record_wake(install, PendingReason::Cancel)
        .expect("owns it");
    let decision = wake.take_for_worker(install).expect("Cancel is selectable");
    assert_eq!(decision.reason(), PendingReason::Cancel);
    assert!(decision.batch().covers(PendingReason::Cancel));
    assert!(!wake.has_wake(), "the selected cancel wake is taken");
}

#[test]
fn installing_wake_cannot_acquire_or_queue_a_worker() {
    let (install, mut ledger, mut wake, mut schedule) = pending_fixture(1471);
    ledger.bind_install(install).expect("binds");
    schedule.begin_install(install).expect("binds");

    // A wake arriving during Installing is recorded -- it must not be lost --
    // but it cannot schedule anything, because the installer is still
    // publishing the state a worker would read.
    wake.record_wake(install, PendingReason::Readiness)
        .expect("owns it");
    assert!(wake.has_wake());
    assert_eq!(
        schedule.queue_worker(install).err(),
        Some(PendingError::WrongRingState),
        "no worker is queued while installing"
    );
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);

    // After handoff the *same* stored wake queues a pass. Nothing was lost.
    schedule
        .handoff_done(install)
        .expect("the installer published");
    schedule.queue_worker(install).expect("handoff is done");
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);
    let decision = wake.take_for_worker(install).expect("the wake survived");
    assert_eq!(decision.reason(), PendingReason::Readiness);

    // A refused preflight restores the exact decision rather than dropping it.
    wake.restore(decision)
        .unwrap_or_else(|(error, _)| unreachable!("the slot is empty: {error:?}"));
    assert!(wake.stored_covers(PendingReason::Readiness));
    let _ = &mut ledger;
}

// ---------------------------------------------------------------------------
// R4 Task 14.2: owned parking, take-once dequeue receipts, and handoff
// ---------------------------------------------------------------------------

const FAKE_IRP: usize = 0xDEAD_BEEF;
const OTHER_IRP: usize = 0xFEED_FACE;

/// A branded ring with an SQ-wait lease, an arbiter bound to it, and an install.
fn arbiter_fixture(n: u64) -> (PendingInstallId, RingEnterState, PendingIrpArbiter) {
    let (mut state, brand) = branded_state(n);
    let lease = state.acquire_sq_wait().expect("a fresh ring");
    let arbiter = PendingIrpArbiter::bind(&lease);
    let _ = lease;
    (PendingInstallId::for_test(brand, 1), state, arbiter)
}

fn observed(raw: usize) -> IrpObservation {
    IrpObservation::from_raw(raw).expect("a nonzero literal is nonzero")
}

/// Park, hand off, and dequeue -- the ordinary route to a receipt.
fn parked_and_handed_off(n: u64) -> (PendingInstallId, RingEnterState, PendingIrpArbiter) {
    let (install, state, mut arbiter) = arbiter_fixture(n);
    arbiter
        .park(install, observed(FAKE_IRP), PendingEnter::new(1))
        .unwrap_or_else(|(error, _)| unreachable!("a fresh arbiter parks: {error:?}"));
    arbiter.handoff_done().expect("one handoff");
    (install, state, arbiter)
}

#[test]
fn parked_plan_is_owned_and_has_no_grant_borrow() {
    let (install, _state, mut arbiter) = arbiter_fixture(1420);

    // The parked plan is moved in, not borrowed: this compiles only because
    // `OwnedParkedEnter` has no lifetime parameter. A parked request outlives
    // the dispatch call that parked it, so a borrow would pin that frame or
    // dangle.
    let terminal = PendingEnter::new(11);
    arbiter
        .park(install, observed(FAKE_IRP), terminal)
        .unwrap_or_else(|(error, _)| unreachable!("a fresh arbiter parks: {error:?}"));
    assert!(arbiter.has_parked());

    // Parking twice is refused and the second plan comes back whole, because a
    // request that failed to install still has to be completed by somebody.
    let second = PendingEnter::new(12);
    let (error, returned) = match arbiter.park(install, observed(OTHER_IRP), second) {
        Ok(()) => unreachable!("one parked request per arbiter"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::SlotOccupied);
    assert_eq!(returned.invocation(), 12, "the exact plan came back");

    // A foreign ring is refused before the slot is touched.
    let (foreign, _s, _a) = arbiter_fixture(1421);
    let (error, _returned) = match arbiter.park(foreign, observed(OTHER_IRP), PendingEnter::new(13))
    {
        Ok(()) => unreachable!("a foreign ring must not park here"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRing);
}

#[test]
fn worker_dequeue_authority_refuses_a_slot_the_cancel_routine_owns() {
    let irp = observed(1423);

    // The race that used to bugcheck or complete an IRP the cancel routine
    // owns. The slot still names the IRP and the axis still reads `Queued`,
    // which is exactly `IoCsqRemoveIrp` having answered NULL.
    assert_eq!(
        classify_worker_dequeue(Some(IrpAxis::Queued), Some(irp)),
        WorkerDequeueAuthority::NoHandoffPublished,
        "a still-queued slot carries no handoff to complete from"
    );
    // The window between the framework's `CsqRemoveIrp` nulling the pointer
    // and its cancel completion publishing `Dequeued`.
    assert_eq!(
        classify_worker_dequeue(Some(IrpAxis::Queued), None),
        WorkerDequeueAuthority::NoHandoffPublished,
        "the mid-handoff window is the same answer"
    );

    // The two real handoffs -- a pass's own non-null return and the framework's
    // cancel completion -- are one answer, and it names the IRP.
    assert_eq!(
        classify_worker_dequeue(Some(IrpAxis::Dequeued), Some(irp)),
        WorkerDequeueAuthority::ReleasedToDriver(irp),
        "a published handoff releases exactly this IRP"
    );

    // Nothing parked, and a completion already under way, authorise nothing.
    assert_eq!(
        classify_worker_dequeue(None, Some(irp)),
        WorkerDequeueAuthority::NoParkedIrp
    );
    assert_eq!(
        classify_worker_dequeue(Some(IrpAxis::Dequeued), None),
        WorkerDequeueAuthority::NoParkedIrp
    );
    for axis in [IrpAxis::Completing, IrpAxis::Completed] {
        assert_eq!(
            classify_worker_dequeue(Some(axis), Some(irp)),
            WorkerDequeueAuthority::NoParkedIrp,
            "a completion under way is not a second authority"
        );
    }
}

#[test]
fn null_or_wrong_csq_return_never_mints_a_receipt() {
    let (install, _state, mut arbiter) = parked_and_handed_off(1422);

    // A null CSQ return cannot even become an observation, so it cannot reach
    // the receipt that authorises a terminal CAS.
    assert!(IrpObservation::from_raw(0).is_none());
    assert_eq!(
        arbiter.dequeue(install, 0, PendingReason::Cancel).err(),
        Some(PendingError::WrongIrp),
        "a null return mints nothing"
    );

    // A non-null return naming a different IRP is refused too.
    assert_eq!(
        arbiter
            .dequeue(install, OTHER_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::WrongIrp)
    );

    // And a different install on the right IRP.
    let other_install = PendingInstallId::for_test(install.brand(), 9);
    assert_eq!(
        arbiter
            .dequeue(other_install, FAKE_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::WrongInstall)
    );

    // None of the refusals consumed the parked plan, so the real dequeue works.
    let receipt = arbiter
        .dequeue(install, FAKE_IRP, PendingReason::Cancel)
        .expect("the exact install and IRP");
    assert_eq!(receipt.irp().get(), FAKE_IRP);
}

#[test]
fn dequeue_receipt_mints_and_retains_the_one_terminal_right() {
    let (install, _state, mut arbiter) = parked_and_handed_off(1423);
    let receipt = arbiter
        .dequeue(install, FAKE_IRP, PendingReason::Timeout)
        .expect("parked and handed off");
    assert_eq!(receipt.reason(), PendingReason::Timeout);
    assert_eq!(receipt.install(), install);

    let (right, irp) = arbiter
        .contend(receipt)
        .unwrap_or_else(|(error, _)| unreachable!("an authentic receipt wins: {error:?}"));
    assert_eq!(irp.get(), FAKE_IRP, "the winner takes the IRP");

    // The right is retained, not spent by contending, and finishing it names
    // the reason the receipt carried.
    assert_eq!(right.finish(), PendingCompletion::TimedOut);

    // The parked plan went with it, so there is nothing left to contend for.
    assert!(!arbiter.has_parked());
    assert_eq!(
        arbiter
            .dequeue(install, FAKE_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::NotDequeued)
    );
}

#[test]
fn terminal_cannot_contend_before_an_authentic_dequeue_receipt() {
    let (install, _state, mut arbiter) = arbiter_fixture(1424);
    arbiter
        .park(install, observed(FAKE_IRP), PendingEnter::new(21))
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    // Before handoff nothing is handed out at all: the receipt is stored and
    // the caller is told the install is still closing to it.
    assert_eq!(
        arbiter
            .dequeue(install, FAKE_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::Closing)
    );
    assert!(
        arbiter.take_early_receipt().is_none(),
        "not before handoff, either"
    );

    // `contend` takes a `DequeuedIrp` by value, and the only constructor is a
    // successful dequeue -- so a contender with no receipt cannot call it at
    // all. That is a compile-time fact, checked by the doctest on `DequeuedIrp`
    // rather than by anything expressible here; what this asserts is the
    // runtime half, that no receipt has yet escaped.
    assert!(arbiter.has_parked(), "the plan is still parked");
    assert!(!arbiter.handoff_is_done());
}

#[test]
fn fabricated_or_foreign_dequeue_receipt_is_unavailable() {
    let (install, _state, mut arbiter) = parked_and_handed_off(1425);
    let (foreign_install, _fs, mut foreign) = parked_and_handed_off(1426);

    // A receipt minted by another arbiter names another install, and contending
    // with it is refused -- and the receipt comes back so its real owner can
    // still use it.
    let foreign_receipt = foreign
        .dequeue(foreign_install, FAKE_IRP, PendingReason::Cancel)
        .expect("its own arbiter");
    let (error, foreign_receipt) = match arbiter.contend(foreign_receipt) {
        Ok(_) => unreachable!("a foreign receipt must not win this terminal"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongInstall);
    assert_eq!(foreign_receipt.install(), foreign_install);

    // Its own arbiter still accepts it, so the refusal was about provenance and
    // not about the receipt being damaged.
    let (right, _irp) = foreign
        .contend(foreign_receipt)
        .unwrap_or_else(|(error, _)| unreachable!("its own arbiter accepts it: {error:?}"));
    assert_eq!(right.finish(), PendingCompletion::Cancelled);

    // And this arbiter is untouched.
    let mine = arbiter
        .dequeue(install, FAKE_IRP, PendingReason::Fence)
        .expect("still parked");
    let (right, _irp) = arbiter
        .contend(mine)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert_eq!(right.finish(), PendingCompletion::Fenced);
}

#[test]
fn same_epoch_from_another_session_or_ring_cannot_contend() {
    // Two different sessions, each with its own ring, both using install epoch
    // 1 and the same raw IRP value. Only the full brand separates them, which
    // is the case a locator-or-epoch check would pass.
    let (mine, _s1, mut arbiter) = parked_and_handed_off(1427);
    let (theirs, _s2, mut other) = parked_and_handed_off(1428);
    assert_eq!(
        mine.install_epoch(),
        theirs.install_epoch(),
        "the epochs collide on purpose"
    );
    assert_ne!(mine.brand(), theirs.brand(), "only the ring brand differs");

    let theirs_receipt = other
        .dequeue(theirs, FAKE_IRP, PendingReason::Unload)
        .expect("its own arbiter");
    let (error, theirs_receipt) = match arbiter.contend(theirs_receipt) {
        Ok(_) => unreachable!("a same-epoch foreign receipt must not contend"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongInstall);

    // Parking their install here is refused by ring as well.
    let (error, _returned) = match arbiter.park(theirs, observed(OTHER_IRP), PendingEnter::new(31))
    {
        Ok(()) => unreachable!("a foreign ring must not park here"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::WrongRing);
    let _ = theirs_receipt;
    let _ = mine;
}

#[test]
fn early_dequeue_receipt_is_stored_and_taken_exactly_once() {
    let (install, _state, mut arbiter) = arbiter_fixture(1429);
    arbiter
        .park(install, observed(FAKE_IRP), PendingEnter::new(41))
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    // A dequeue before handoff stores the receipt rather than handing it out.
    assert_eq!(
        arbiter
            .dequeue(install, FAKE_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::Closing)
    );
    // A second early dequeue does not stack a second receipt.
    assert_eq!(
        arbiter
            .dequeue(install, FAKE_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::AlreadyDequeued)
    );

    arbiter.handoff_done().expect("one handoff");
    let receipt = arbiter
        .take_early_receipt()
        .expect("the stored receipt is due after handoff");
    assert_eq!(receipt.reason(), PendingReason::Cancel);

    // Exactly once: the slot is empty afterwards.
    assert!(
        arbiter.take_early_receipt().is_none(),
        "one stored receipt, taken once"
    );

    let (right, _irp) = arbiter
        .contend(receipt)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert_eq!(right.finish(), PendingCompletion::Cancelled);
}

#[test]
fn dequeue_before_handoff_releases_only_cancel_owner_not_installer_or_worker() {
    let (install, _state, mut arbiter) = arbiter_fixture(1450);
    // The ledger fixture brings its own brand and install, so the owner rules
    // below are about kinds rather than about crossed identities.
    let (ledger_install, mut ledger, _wake, _schedule) = pending_fixture(1451);
    ledger.bind_install(ledger_install).expect("binds");

    arbiter
        .park(install, observed(FAKE_IRP), PendingEnter::new(51))
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let installer = ledger
        .acquire_owner(ledger_install, PendingOwnerKind::Installer)
        .expect("free");
    let cancel = ledger
        .acquire_owner(ledger_install, PendingOwnerKind::Cancel)
        .expect("free");
    let worker = ledger
        .acquire_owner(ledger_install, PendingOwnerKind::Worker)
        .expect("free");

    assert_eq!(
        arbiter
            .dequeue(install, FAKE_IRP, PendingReason::Cancel)
            .err(),
        Some(PendingError::Closing)
    );
    assert_eq!(
        arbiter.early_disposition(),
        Some(EarlyDequeueDisposition::ReleaseCancelOwnerOnly),
        "only the cancel callback is finished at this point"
    );

    // Releasing the cancel owner is exactly what the disposition permits; the
    // installer is still mid-publication and the worker has not run, so both
    // keep their ownership.
    ledger
        .release_owner(cancel)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert!(ledger.holds(PendingOwnerKind::Installer), "installer stays");
    assert!(ledger.holds(PendingOwnerKind::Worker), "worker stays");
    assert!(!ledger.holds(PendingOwnerKind::Cancel));
    assert_eq!(ledger.owner_count(), 2);
    let _ = (installer, worker);
}

#[test]
fn handoff_done_reschedules_one_early_dequeue() {
    let (install, _state, mut arbiter) = arbiter_fixture(1452);
    arbiter
        .park(install, observed(FAKE_IRP), PendingEnter::new(61))
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    // Without an early dequeue, handoff reports nothing to reschedule.
    let (bare_install, _s, mut bare) = arbiter_fixture(1453);
    bare.park(bare_install, observed(FAKE_IRP), PendingEnter::new(62))
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert!(
        !bare.handoff_done().expect("one handoff"),
        "nothing arrived early"
    );

    // With one, handoff reports exactly one -- not two, and not zero.
    assert_eq!(
        arbiter
            .dequeue(install, FAKE_IRP, PendingReason::Readiness)
            .err(),
        Some(PendingError::Closing)
    );
    assert!(
        arbiter.handoff_done().expect("one handoff"),
        "the early dequeue is rescheduled"
    );
    assert_eq!(
        arbiter.handoff_done().err(),
        Some(PendingError::WrongRingState),
        "handoff happens once"
    );
    assert!(arbiter.take_early_receipt().is_some());
    assert!(arbiter.take_early_receipt().is_none(), "exactly one");
}

// ---------------------------------------------------------------------------
// R4 Task 14.5: the pending-completion typestate
// ---------------------------------------------------------------------------

/// One ring with everything a completion plan consumes, plus its components.
fn completion_fixture(
    n: u64,
) -> (
    PendingCompletionPlan,
    PendingResultSlot,
    PendingOwnerLedger,
    PendingWakeSlot,
    PendingInstallId,
) {
    let (_registry, mut installed) = installed_for_rings(n);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let (mut state, mut slot, mut ledger, wake, _bind) = parts.into_parts();

    let install = PendingInstallId::for_test(brand, 1);
    slot.occupy(install).expect("a fresh slot");
    ledger.bind_install(install).expect("binds");
    let worker = ledger
        .acquire_owner(install, PendingOwnerKind::Worker)
        .expect("free");
    let role = state.acquire_sq_wait().expect("a fresh ring");
    let link = control_link_for(install);

    let plan = PendingCompletionPlan::begin(install, observed(FAKE_IRP), role, link, worker)
        .unwrap_or_else(|(error, _, _, _)| unreachable!("every authority matches: {error:?}"));
    let _ = state;
    (plan, slot, ledger, wake, install)
}

/// A control link right for one install, through the real ledger API.
fn control_link_for(install: PendingInstallId) -> PendingControlLinkRight {
    use crate::session::PendingControlLedger;
    let mut ledger = PendingControlLedger::<2>::bound_for_test(install.brand().locator());
    ledger.link(install).expect("a fresh ledger links")
}

/// `UnlinkControlPending` must reach the session's ledger, not just drop the
/// local `Option`: a ring that never frees its ledger slot can serve exactly
/// one parked ENTER-WAIT for the life of the session. Unlike
/// `completion_fixture`/`control_link_for`, this test keeps its own
/// `PendingControlLedger` alive across the whole walk, so it can read the
/// slot back out after a real `PendingCompletionPlan` completion instead of
/// building the ledger fresh for the assertion.
#[test]
fn unlink_control_pending_frees_the_ledger_slot_for_the_next_install_on_the_same_ring() {
    use crate::session::PendingControlLedger;

    let (_registry, mut installed) = installed_for_rings(1463);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let (mut state, mut slot, mut owners, _wake, _bind) = parts.into_parts();

    let install_a = PendingInstallId::for_test(brand, 1);
    slot.occupy(install_a).expect("a fresh slot");
    owners.bind_install(install_a).expect("binds");
    let worker = owners
        .acquire_owner(install_a, PendingOwnerKind::Worker)
        .expect("free");
    let role = state.acquire_sq_wait().expect("a fresh ring");

    let mut ledger = PendingControlLedger::<2>::bound_for_test(install_a.brand().locator());
    let link = ledger.link(install_a).expect("a fresh ledger links");

    let plan = PendingCompletionPlan::begin(install_a, observed(FAKE_IRP), role, link, worker)
        .unwrap_or_else(|(error, _, _, _)| unreachable!("every authority matches: {error:?}"));

    let plan = advance_to(plan, PendingCompletionEffect::UnlinkControlPending);
    let (plan, taken) = plan.take_control_link();
    let taken = taken.expect("the stage hands back the exact right it was holding");
    ledger
        .unlink(taken)
        .unwrap_or_else(|(error, _)| unreachable!("the taken right matches this slot: {error:?}"));

    // The ledger slot is free again: a second install on the SAME ring links.
    // Before this fix, `run_next` alone dropped the right without reaching
    // the ledger, so this second `link` refused with `DuplicateLink`.
    let install_b = PendingInstallId::for_test(brand, 2);
    ledger.link(install_b).unwrap_or_else(|error| {
        unreachable!("a live ring must serve more than one parked WAIT: {error:?}")
    });
    let _ = plan;
}

/// `PendingResultSlot::vacate` is the closing half of `occupy`: a park attempt
/// that reserved a slot and then failed a later step must give it back, or
/// every later install on the same ring refuses at `SlotOccupied` forever
/// (round 7's verdict item 2, mirroring `PendingOwnerLedger::unbind_install`
/// and `PendingWorkerSchedule::end_install`, which already existed).
#[test]
fn result_slot_vacate_frees_the_reservation_for_the_next_install() {
    let (_registry, mut installed) = installed_for_rings(1464);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let (_state, mut slot, _owners, _wake, _bind) = parts.into_parts();

    let install_a = PendingInstallId::for_test(brand, 1);
    slot.occupy(install_a).expect("a fresh slot");
    assert_eq!(
        slot.occupy(PendingInstallId::for_test(brand, 2)).err(),
        Some(PendingError::SlotOccupied),
        "a second install cannot occupy a slot already reserved"
    );

    slot.vacate(install_a)
        .expect("the exact reserving install vacates its own slot");

    let install_b = PendingInstallId::for_test(brand, 2);
    slot.occupy(install_b)
        .expect("the slot is free again for the next install on this ring");
}

/// `PendingInstallId::locator` is the hidden-public accessor native uses to
/// reach an install's session ledger before it holds any right into it
/// (mirrors `PendingControlLinkRight::locator`, used for the same purpose
/// after linking).
#[test]
fn install_id_locator_matches_its_own_brand() {
    let (_registry, mut installed) = installed_for_rings(1465);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let install = PendingInstallId::for_test(brand, 1);
    assert_eq!(install.locator(), brand.locator());
}

/// Drive the plan to the given effect, committing the boundaries on the way.
fn advance_to(
    mut plan: PendingCompletionPlan,
    target: PendingCompletionEffect,
) -> PendingCompletionPlan {
    loop {
        if plan.stage() == Some(target) {
            return plan;
        }
        plan = match plan.run_next() {
            PendingCompletionStep::Advanced(next) => next,
            PendingCompletionStep::NeedResultWrite(write) => write.commit_result_write(0, 8),
            PendingCompletionStep::NeedIrpCompletion(complete) => complete.commit_irp_completion(),
            PendingCompletionStep::NeedFinalPublication(_) => {
                unreachable!("advance_to never passes the final stage")
            }
        };
    }
}

#[test]
fn pending_completion_typestate_exposes_all_eight_effects_in_exact_order() {
    assert_eq!(
        PENDING_COMPLETION_ORDER,
        [
            PendingCompletionEffect::CancelTimer,
            PendingCompletionEffect::WaitDpcExitIfRequired,
            PendingCompletionEffect::WriteExactResult,
            PendingCompletionEffect::ReleaseSqWaitRole,
            PendingCompletionEffect::UnlinkControlPending,
            PendingCompletionEffect::ReleaseStrongSessionRef,
            PendingCompletionEffect::CompleteIrpOnce,
            PendingCompletionEffect::PublishVacantOrEpochExhausted,
        ]
    );

    let (mut plan, _slot, _ledger, _wake, _install) = completion_fixture(1460);
    let mut seen = Vec::new();
    loop {
        let Some(stage) = plan.stage() else { break };
        seen.push(stage);
        plan = match plan.run_next() {
            PendingCompletionStep::Advanced(next) => next,
            PendingCompletionStep::NeedResultWrite(write) => write.commit_result_write(0, 8),
            PendingCompletionStep::NeedIrpCompletion(complete) => complete.commit_irp_completion(),
            PendingCompletionStep::NeedFinalPublication(_) => break,
        };
    }
    assert_eq!(
        seen.as_slice(),
        PENDING_COMPLETION_ORDER.as_slice(),
        "run_next walks the roster exactly, in order, with no skips"
    );

    // The ordering facts the roster encodes, stated as checks rather than as
    // positions: the write precedes the role release (or the next invocation
    // could reuse a slot still being copied into), and the IRP completes after
    // both (or the caller owns the buffer again while core is still writing).
    let position = |effect| {
        PENDING_COMPLETION_ORDER
            .iter()
            .position(|candidate| *candidate == effect)
            .expect("the roster contains every effect")
    };
    assert!(
        position(PendingCompletionEffect::WriteExactResult)
            < position(PendingCompletionEffect::ReleaseSqWaitRole)
    );
    assert!(
        position(PendingCompletionEffect::ReleaseSqWaitRole)
            < position(PendingCompletionEffect::CompleteIrpOnce)
    );
    assert!(
        position(PendingCompletionEffect::CompleteIrpOnce)
            < position(PendingCompletionEffect::PublishVacantOrEpochExhausted)
    );
}

#[test]
fn pending_completion_refusal_returns_the_plan_and_affine_authority_at_same_stage() {
    let (plan, mut slot, mut ledger, wake, install) = completion_fixture(1461);

    // Reach the final stage, then refuse it by leaving a wake outstanding.
    let plan = advance_to(plan, PendingCompletionEffect::PublishVacantOrEpochExhausted);
    let PendingCompletionStep::NeedFinalPublication(publication) = plan.run_next() else {
        unreachable!("the last stage is the final publication")
    };
    let mut dirty_wake = wake;
    dirty_wake
        .record_wake(install, PendingReason::Readiness)
        .expect("owns it");
    let failed =
        match publication.commit_final_publication(&mut slot, &mut ledger, &dirty_wake, false) {
            Ok(_) => unreachable!("an outstanding wake must refuse publication"),
            Err(fail) => fail,
        };
    assert_eq!(failed.reason(), PendingError::OwnersRemain);

    // Nothing was consumed: the slot is still occupied and the Worker owner is
    // still held, so the state the retry needs is exactly the state it left.
    assert!(
        !slot.is_reusable(),
        "the slot was not released by a refusal"
    );
    assert!(ledger.holds(PendingOwnerKind::Worker));
    assert_eq!(ledger.owner_count(), 1);

    // The witness reports the same refusal without consuming the packet.
    let witness = failed.witness();
    assert_eq!(witness.reason(), PendingError::OwnersRemain);
    assert_eq!(witness.install(), install);
    assert_eq!(failed.reason(), PendingError::OwnersRemain, "still intact");
}

#[test]
fn native_write_cannot_mint_written_receipt() {
    let (plan, _slot, _ledger, _wake, _install) = completion_fixture(1462);
    let plan = advance_to(plan, PendingCompletionEffect::WriteExactResult);
    assert!(!plan.has_written_result(), "nothing written yet");

    let PendingCompletionStep::NeedResultWrite(write) = plan.run_next() else {
        unreachable!("the third stage is the result write")
    };
    // The boundary exposes only the install and the IRP; there is no method on
    // it that returns a receipt, and `WrittenResultReceipt` has no public
    // constructor. The only route is `commit`, which is core minting it from
    // the status and information core was told.
    let (_install, _irp) = write.view();
    let plan = write.commit_result_write(0xC000_0001, 24);
    assert!(plan.has_written_result(), "core minted it, not native");
    assert_eq!(
        plan.stage(),
        Some(PendingCompletionEffect::ReleaseSqWaitRole)
    );
}

#[test]
fn take_sq_wait_role_returns_the_lease_and_advances_past_release() {
    let (plan, _slot, _ledger, _wake, _install) = completion_fixture(1464);
    let plan = advance_to(plan, PendingCompletionEffect::ReleaseSqWaitRole);
    let (plan, lease) = plan.take_sq_wait_role();
    assert!(lease.is_some(), "the write stage still held the SQ wait");
    assert_eq!(
        plan.stage(),
        Some(PendingCompletionEffect::UnlinkControlPending)
    );
    let (plan, again) = plan.take_sq_wait_role();
    assert!(again.is_none(), "the stage only yields the lease once");
    assert_eq!(
        plan.stage(),
        Some(PendingCompletionEffect::UnlinkControlPending)
    );
}

#[test]
fn native_complete_cannot_mint_completed_receipt() {
    let (plan, _slot, _ledger, _wake, _install) = completion_fixture(1463);
    let plan = advance_to(plan, PendingCompletionEffect::CompleteIrpOnce);
    assert!(!plan.has_completed_irp(), "nothing completed yet");
    assert!(plan.has_written_result(), "the write already happened");

    let PendingCompletionStep::NeedIrpCompletion(complete) = plan.run_next() else {
        unreachable!("the seventh stage is the IRP completion")
    };
    // The view carries forward exactly the status and information the write
    // recorded, so native cannot complete with values core never saw.
    let (irp, status, information) = complete.view().expect("the write receipt is held");
    assert_eq!(irp.get(), FAKE_IRP);
    assert_eq!((status, information), (0, 8));

    let plan = complete.commit_irp_completion();
    assert!(plan.has_completed_irp(), "core minted it, not native");
}

#[test]
fn result_slot_cannot_reuse_before_completed_irp_and_last_owner_publication() {
    let (plan, mut slot, mut ledger, wake, install) = completion_fixture(1464);

    // Mid-sequence the slot is still occupied, so a second install cannot take
    // it -- an IRP receipt alone, or a worker token alone, is not enough.
    let plan = advance_to(plan, PendingCompletionEffect::CompleteIrpOnce);
    assert!(!slot.is_reusable());
    let successor = PendingInstallId::for_test(install.brand(), 2);
    assert_eq!(
        slot.occupy(successor).err(),
        Some(PendingError::SlotOccupied)
    );

    // Even after the IRP completes, the slot is not free: the joint publication
    // has not run.
    let PendingCompletionStep::NeedIrpCompletion(complete) = plan.run_next() else {
        unreachable!("the seventh stage")
    };
    let plan = complete.commit_irp_completion();
    assert!(plan.has_completed_irp());
    assert!(!slot.is_reusable(), "a completed IRP alone frees nothing");
    assert_eq!(
        slot.occupy(successor).err(),
        Some(PendingError::SlotOccupied)
    );

    // And a second owner outstanding refuses the publication too.
    let extra = ledger
        .acquire_owner(install, PendingOwnerKind::Cancel)
        .expect("a distinct kind");
    let PendingCompletionStep::NeedFinalPublication(publication) = plan.run_next() else {
        unreachable!("the eighth stage")
    };
    let failed = match publication.commit_final_publication(&mut slot, &mut ledger, &wake, false) {
        Ok(_) => unreachable!("a second owner must refuse publication"),
        Err(fail) => fail,
    };
    assert_eq!(failed.reason(), PendingError::OwnersRemain);
    assert!(!slot.is_reusable());
    ledger
        .release_owner(extra)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
}

#[test]
fn exact_result_slot_reuses_after_coupled_final_publication() {
    let (plan, mut slot, mut ledger, wake, install) = completion_fixture(1465);
    let plan = advance_to(plan, PendingCompletionEffect::PublishVacantOrEpochExhausted);
    let PendingCompletionStep::NeedFinalPublication(publication) = plan.run_next() else {
        unreachable!("the eighth stage")
    };

    let result = publication
        .commit_final_publication(&mut slot, &mut ledger, &wake, false)
        .unwrap_or_else(|fail| unreachable!("everything matches: {:?}", fail.reason()));
    assert_eq!(result.install(), install);
    assert!(!result.exhausted());

    // One coupled commit released the slot and the last owner together.
    assert!(slot.is_reusable(), "the slot is free");
    assert!(ledger.owners_drained(), "the last owner left with it");

    // And the successor may now take it.
    let successor = PendingInstallId::for_test(install.brand(), 2);
    slot.occupy(successor).expect("the slot was published free");
}

#[test]
fn publication_fail_stop_packet_owns_the_refused_plan_without_decomposition() {
    let (plan, mut slot, mut ledger, wake, install) = completion_fixture(1466);
    let plan = advance_to(plan, PendingCompletionEffect::PublishVacantOrEpochExhausted);

    // Refuse by clearing the slot's occupancy underneath the plan.
    let mut foreign_slot = slot_for_other_install(install);
    let PendingCompletionStep::NeedFinalPublication(publication) = plan.run_next() else {
        unreachable!("the eighth stage")
    };
    let failed =
        match publication.commit_final_publication(&mut foreign_slot, &mut ledger, &wake, false) {
            Ok(_) => unreachable!("a slot holding another install must refuse"),
            Err(fail) => fail,
        };
    assert_eq!(failed.reason(), PendingError::WrongSlot);

    // The packet has no method that hands the plan back in pieces. A refusal at
    // the last stage leaves an IRP already completed and a result already
    // written, so decomposing it would let a caller reassemble a plan that
    // repeats both. `witness` reports; nothing extracts.
    let witness = failed.witness();
    assert_eq!(witness.install(), install);
    assert!(!slot.is_reusable(), "the real slot is untouched");
    let _ = &mut slot;
}

#[test]
fn publication_fail_stop_witness_is_typed_but_cannot_clear_or_retry_the_packet() {
    let (plan, _slot, mut ledger, wake, install) = completion_fixture(1467);
    let plan = advance_to(plan, PendingCompletionEffect::PublishVacantOrEpochExhausted);
    let mut foreign_slot = slot_for_other_install(install);
    let PendingCompletionStep::NeedFinalPublication(publication) = plan.run_next() else {
        unreachable!("the eighth stage")
    };
    let failed =
        match publication.commit_final_publication(&mut foreign_slot, &mut ledger, &wake, false) {
            Ok(_) => unreachable!("must refuse"),
            Err(fail) => fail,
        };

    // The witness is `Copy` and carries the typed reason, so a caller may log
    // it, compare it, and store it -- and it still cannot clear or retry
    // anything, because it holds no authority at all. Taking two of them
    // changes nothing about the packet.
    let first = failed.witness();
    let second = failed.witness();
    assert_eq!(first, second);
    assert_eq!(first.reason(), PendingError::WrongSlot);
    assert_eq!(failed.reason(), PendingError::WrongSlot, "packet unchanged");

    // The Worker owner is still held by the ledger: the refusal released
    // nothing, which is what makes a retry meaningful rather than a second
    // release.
    assert!(ledger.holds(PendingOwnerKind::Worker));
    assert_eq!(ledger.owner_count(), 1);
}

/// A result slot occupied by a *different* install on the same ring.
fn slot_for_other_install(install: PendingInstallId) -> PendingResultSlot {
    let (_registry, mut installed) = installed_for_rings(9500);
    let _ = &mut installed;
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set.next_ring().expect("available").expect("ring 0");
    let other_brand = right.brand();
    let parts = build_ring_runtime_parts(other_brand, 8, right)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let (_s, mut slot, _o, _w, _b) = parts.into_parts();
    slot.occupy(PendingInstallId::for_test(other_brand, 3))
        .expect("a fresh slot");
    let _ = install;
    slot
}

// ---------------------------------------------------------------------------
// R4 Task 14.1/14.4: acquisition aggregates and the SQ -> CQ resume bridge
// ---------------------------------------------------------------------------

#[test]
fn sq_acquisition_contains_exactly_one_lease_tracker_and_terminal() {
    let (mut state, brand) = branded_state(1480);
    let acquired = state
        .acquire_sq_wait_aggregate()
        .expect("a fresh ring acquires");
    assert_eq!(acquired.execution().ring(), brand);
    assert_eq!(acquired.execution().domain(), EnterExecutionDomain::SqWait);

    // The role is held: the aggregate is the acquisition, not a view of one.
    assert_eq!(state.acquire_sq_wait().err(), Some(RoleError::DeviceBusy));

    // Exactly one of each, and `into_plan_parts` is the only route to any of
    // them -- so a lease cannot exist beside a tracker for a different
    // invocation.
    let (lease, tracker, terminal) = acquired.into_plan_parts();
    assert_eq!(lease.execution(), tracker.execution());
    assert_eq!(
        terminal.invocation(),
        lease.execution().invocation().get(),
        "the terminal seed names the invocation that acquired the role"
    );
    assert!(
        !tracker.committed(),
        "a fresh execution has committed nothing"
    );
    let _ = state.release_sq_wait(lease);
}

#[test]
fn cq_acquisition_contains_exactly_one_token_and_tracker() {
    let (mut state, brand) = branded_state(1481);
    let acquired = state
        .acquire_cq_consumer_aggregate()
        .expect("a fresh ring acquires");
    assert_eq!(acquired.execution().ring(), brand);
    assert_eq!(
        acquired.execution().domain(),
        EnterExecutionDomain::CqConsumer
    );
    assert_eq!(
        state.acquire_cq_consumer().err(),
        Some(RoleError::DeviceBusy)
    );

    let (token, mut tracker) = acquired.into_plan_parts();
    assert_eq!(token.execution(), tracker.execution());
    assert_eq!(token.brand(), brand);
    assert!(!tracker.committed());

    // The tracker travels with the authority that could mutate, so recording a
    // commit is something only the holder can do.
    tracker.record_commit();
    assert!(tracker.committed());
    tracker.record_commit();
    assert!(tracker.committed(), "the question is whether, not how many");
    let _ = state.release_cq_consumer(token);
}

#[test]
fn readiness_resume_borrows_original_sq_lease_without_reacquisition() {
    let (mut state, brand) = branded_state(1482);
    let (lease, _tracker, _terminal) = state
        .acquire_sq_wait_aggregate()
        .expect("a fresh ring")
        .into_plan_parts();
    let parked = lease.execution();

    // The resume borrows the lease. The role is still held throughout -- there
    // is no window in which the ring looks free, which is what a
    // release-and-reacquire would create.
    let resume = state
        .authorize_resume(&lease)
        .expect("the state still owns this lease");
    assert_eq!(resume.execution(), parked);
    assert_eq!(state.acquire_sq_wait().err(), Some(RoleError::DeviceBusy));

    let cq = resume.bind_cq_consumer();
    assert_eq!(cq.ring(), brand);
    assert_eq!(state.acquire_sq_wait().err(), Some(RoleError::DeviceBusy));

    // And the lease is still usable afterwards, because it was only borrowed.
    state
        .release_sq_wait(lease)
        .unwrap_or_else(|(error, _)| unreachable!("the lease survived: {error:?}"));
    assert!(state.acquire_sq_wait().is_ok());
}

#[test]
fn resume_derives_one_cq_token_for_the_exact_sq_request() {
    let (mut state, brand) = branded_state(1483);
    let (lease, _tracker, _terminal) = state
        .acquire_sq_wait_aggregate()
        .expect("a fresh ring")
        .into_plan_parts();
    let parked = lease.execution();

    let cq = state
        .authorize_resume(&lease)
        .expect("owned")
        .bind_cq_consumer();

    // Same ring, same invocation, different domain -- the two halves of one
    // request, not two requests.
    assert_eq!(cq.execution().ring(), parked.ring());
    assert_eq!(cq.execution().invocation(), parked.invocation());
    assert_eq!(cq.execution().domain(), EnterExecutionDomain::CqConsumer);
    assert_ne!(cq.execution(), parked, "only the domain differs");
    assert_eq!(cq.ring(), brand);
    let _ = state.release_sq_wait(lease);
}

#[test]
fn sq_to_cq_bridge_does_not_consume_the_next_invocation() {
    let (mut state, _brand) = branded_state(1484);
    let (lease, _t, _p) = state
        .acquire_sq_wait_aggregate()
        .expect("a fresh ring")
        .into_plan_parts();
    let parked = lease.execution().invocation();

    // Bridge repeatedly. Each derivation reuses the parked invocation.
    for _ in 0..4 {
        let cq = state
            .authorize_resume(&lease)
            .expect("owned")
            .bind_cq_consumer();
        assert_eq!(cq.execution().invocation(), parked);
    }

    // The source is untouched: the next acquisition is exactly one past the
    // parked one, not five past it.
    state
        .release_sq_wait(lease)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let next = state.acquire_sq_wait().expect("released");
    assert_eq!(
        next.execution().invocation().get(),
        parked.get().saturating_add(1),
        "four bridges consumed no invocation"
    );
    let _ = state.release_sq_wait(next);
}

#[test]
fn foreign_state_cannot_authorize_readiness_resume() {
    let (mut mine, _b1) = branded_state(1485);
    let (mut theirs, _b2) = branded_state(1486);
    let (lease, _t, _p) = mine
        .acquire_sq_wait_aggregate()
        .expect("a fresh ring")
        .into_plan_parts();

    // Another ring refuses by ring.
    assert_eq!(
        theirs.authorize_resume(&lease).err(),
        Some(RoleError::WrongRing)
    );

    // A predecessor state has no brand at all.
    let unbranded = RingEnterState::new(0);
    assert_eq!(
        unbranded.authorize_resume(&lease).err(),
        Some(RoleError::WrongState)
    );

    // And its own state, after the lease is released, refuses by invocation --
    // a released lease is not a parked request.
    assert!(mine.authorize_resume(&lease).is_ok(), "still parked");
    mine.release_sq_wait(lease)
        .unwrap_or_else(|(error, _)| unreachable!("its own state releases it: {error:?}"));
    let (fresh, _t2, _p2) = mine
        .acquire_sq_wait_aggregate()
        .expect("released")
        .into_plan_parts();
    assert!(mine.authorize_resume(&fresh).is_ok());
    let _ = mine.release_sq_wait(fresh);
    let _ = &mut theirs;
}

#[test]
fn independent_plan_cannot_fabricate_an_authenticated_resume() {
    let (mut state, brand) = branded_state(1487);
    let (lease, _t, _p) = state
        .acquire_sq_wait_aggregate()
        .expect("a fresh ring")
        .into_plan_parts();

    // A stale lease for the same ring -- released, then a new one acquired --
    // cannot authorise a resume, because the state no longer names it.
    let stale_invocation = lease.execution().invocation();
    state
        .release_sq_wait(lease)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let (live, _t2, _p2) = state
        .acquire_sq_wait_aggregate()
        .expect("released")
        .into_plan_parts();
    assert_ne!(live.execution().invocation(), stale_invocation);

    // The only route to an `AuthenticatedCqResume` is `bind_cq_consumer` on an
    // `SqWaitResume`, whose only constructor is `authorize_resume` on the state
    // that owns the lease. There is no public constructor for either, and
    // `EnterExecutionBrand::for_resume` is module-private -- so a CQ-domain
    // brand carrying a parked invocation cannot be assembled from outside.
    let resume = state.authorize_resume(&live).expect("owned");
    let cq = resume.bind_cq_consumer();
    assert_eq!(cq.ring(), brand);
    assert_eq!(cq.execution().invocation(), live.execution().invocation());
    let _ = state.release_sq_wait(live);
}

// ---------------------------------------------------------------------------
// R4 Task 17 (core half): the pending slot epoch machine and the IRP axis
// ---------------------------------------------------------------------------

#[test]
fn pending_slot_epoch_never_repeats_across_reuse() {
    let mut slot = PendingSlotState::fresh();
    let mut issued = Vec::new();

    // Three full install cycles through the one reusable route.
    for _ in 0..3 {
        assert!(slot.admits_install());
        slot = slot
            .begin_install()
            .unwrap_or_else(|(error, _)| unreachable!("a vacant slot admits: {error:?}"));
        let epoch = slot.epoch().expect("installing carries its epoch");
        issued.push(epoch);
        assert!(!slot.admits_install(), "an installing slot admits nothing");

        slot = slot
            .handoff_done()
            .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
        assert_eq!(slot.epoch(), Some(epoch), "handoff keeps the epoch");
        slot = slot
            .begin_quiesce()
            .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
        assert_eq!(slot.epoch(), Some(epoch));
        slot = slot
            .publish_vacant()
            .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
    }

    assert_eq!(issued.as_slice(), [1, 2, 3].as_slice());
    let mut seen = issued.clone();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), issued.len(), "no epoch was ever reused");

    // Exhaustion latches: a slot whose next epoch is u64::MAX issues it once and
    // then refuses forever. Wrapping to 1 would reuse an epoch a live install
    // may still carry.
    let mut last = PendingSlotState::Quiescing { epoch: u64::MAX };
    last = last
        .publish_vacant()
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
    assert_eq!(last, PendingSlotState::EpochExhausted);
    assert!(!last.admits_install());
    assert_eq!(
        last.begin_install().err().map(|(error, _)| error),
        Some(PendingError::SlotOccupied)
    );
}

#[test]
fn pending_slot_reuse_requires_the_coupled_publication() {
    // `publish_vacant` is the only transition that produces a reusable slot,
    // and it is reachable only from `Quiescing`. Every other state refuses it
    // and comes back unchanged, so a caller cannot shortcut to a free slot from
    // the middle of an install.
    for state in [
        PendingSlotState::fresh(),
        PendingSlotState::Installing { epoch: 4 },
        PendingSlotState::Active { epoch: 4 },
        PendingSlotState::PublicationFailStop { epoch: 4 },
        PendingSlotState::EpochExhausted,
    ] {
        let (error, returned) = match state.publish_vacant() {
            Ok(next) => unreachable!("{state:?} must not publish vacant, got {next:?}"),
            Err(pair) => pair,
        };
        assert_eq!(error, PendingError::WrongRingState);
        assert_eq!(returned, state, "the refused state comes back unchanged");
    }

    // And a fail-stop is a dead end for reuse: it is not vacant, and it cannot
    // become vacant, because `publish_vacant` needs Quiescing.
    let stopped = PendingSlotState::Quiescing { epoch: 9 }
        .park_publication_fail_stop()
        .unwrap_or_else(|(e, _)| unreachable!("{e:?}"));
    assert_eq!(stopped, PendingSlotState::PublicationFailStop { epoch: 9 });
    assert!(!stopped.admits_install());
    assert!(stopped.publish_vacant().is_err());
    assert!(
        stopped.park_publication_fail_stop().is_err(),
        "one fail-stop, not two"
    );
}

#[test]
fn irp_axis_advances_one_way_and_never_returns() {
    // The axis is a successor function, not an allow-list of pairs: there is no
    // way to *express* Completed -> Queued, whereas an allow-list has to
    // remember to exclude it.
    let mut walked = Vec::new();
    let mut axis = Some(IrpAxis::Queued);
    while let Some(current) = axis {
        walked.push(current);
        axis = current.next();
    }
    assert_eq!(
        walked.as_slice(),
        [
            IrpAxis::Queued,
            IrpAxis::Dequeued,
            IrpAxis::Completing,
            IrpAxis::Completed
        ]
        .as_slice()
    );
    assert_eq!(IrpAxis::Completed.next(), None, "the end is the end");

    // The driver owns the completion until it has completed it -- which is what
    // says a `Completed` IRP must never be touched again.
    for axis in [IrpAxis::Queued, IrpAxis::Dequeued, IrpAxis::Completing] {
        assert!(axis.driver_owns_completion(), "{axis:?} is still ours");
    }
    assert!(!IrpAxis::Completed.driver_owns_completion());
}

// ---------------------------------------------------------------------------
// R4 Task 18 (core half): the counted initialization cursor
// ---------------------------------------------------------------------------

#[test]
fn runtime_readiness_requires_every_ring_not_merely_some() {
    // A zero-ring set is refused outright: it would satisfy `finish` vacuously,
    // and every later "is every ring initialized" check would pass with no ring
    // in existence.
    assert_eq!(
        PendingRuntimeInitCursor::begin(0).err(),
        Some(PendingError::InvalidCapacity)
    );
    assert_eq!(
        PendingRuntimeInitCursor::begin(MAX_SESSION_RING_COUNT.saturating_add(1)).err(),
        Some(PendingError::InvalidCapacity)
    );

    let mut cursor = PendingRuntimeInitCursor::begin(4).expect("four rings");
    assert_eq!(cursor.next_uninitialized_index(), Some(0));

    // Partial initialization is never ready, at every intermediate count.
    for expected in 0..4 {
        assert_eq!(cursor.initialized(), expected);
        assert_eq!(
            cursor.finish(4).err().map(|(error, _)| error),
            Some(PendingError::OwnersRemain),
            "{expected} of 4 rings is not ready"
        );
        assert_eq!(cursor.next_uninitialized_index(), Some(expected));
        cursor = cursor
            .record_initialized()
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    }

    // All four: ready, and the cursor reports the set is covered.
    assert_eq!(cursor.initialized(), 4);
    assert_eq!(cursor.next_uninitialized_index(), None);
    let ready = cursor
        .finish(4)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let _ = ready.ring_count();

    // Past the end is refused rather than saturating: a cursor that silently
    // stopped counting would make `finish` pass for a set whose later rings were
    // never constructed.
    let (error, returned) = match cursor.record_initialized() {
        Ok(next) => unreachable!("the set is covered, got {next:?}"),
        Err(pair) => pair,
    };
    assert_eq!(error, PendingError::SlotOccupied);
    assert_eq!(returned, cursor, "the refused cursor comes back unchanged");
}

#[test]
fn runtime_finish_requires_the_caller_to_agree_about_the_set() {
    let cursor = PendingRuntimeInitCursor::begin(3)
        .expect("three rings")
        .record_initialized()
        .and_then(PendingRuntimeInitCursor::record_initialized)
        .and_then(PendingRuntimeInitCursor::record_initialized)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    // Complete by its own count, but a caller naming a different set is
    // refused -- otherwise a caller passing a smaller count could declare a
    // partial arena ready, which is the exact confusion the second check exists
    // for.
    for wrong in [1_u32, 2, 4, 64] {
        assert_eq!(
            cursor.finish(wrong).err().map(|(error, _)| error),
            Some(PendingError::WrongRing),
            "a caller naming {wrong} rings does not speak for this set of 3"
        );
    }
    let ready = cursor
        .finish(3)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let _ = ready.ring_count();

    // And an *incomplete* cursor refuses on completeness, not on the count, so
    // the two failures stay distinguishable.
    let partial = PendingRuntimeInitCursor::begin(3)
        .expect("three rings")
        .record_initialized()
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert_eq!(
        partial.finish(3).err().map(|(error, _)| error),
        Some(PendingError::OwnersRemain)
    );
    assert_eq!(
        partial.finish(9).err().map(|(error, _)| error),
        Some(PendingError::WrongRing)
    );
}

#[test]
fn runtime_rollback_spans_exactly_the_initialized_prefix() {
    let mut cursor = PendingRuntimeInitCursor::begin(5).expect("five rings");
    assert!(
        cursor.rollback_span().is_empty(),
        "nothing built, nothing to undo"
    );

    // The span tracks the count exactly at every step. Guessing high would free
    // storage that was never constructed; guessing low would leak it.
    for expected in 1..=5 {
        cursor = cursor
            .record_initialized()
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        assert_eq!(cursor.rollback_span().len(), expected);
        assert!(!cursor.rollback_span().is_empty());
    }
    assert_eq!(cursor.rollback_span().len(), cursor.ring_count());

    // A cursor that refused past the end did not grow its span either, so a
    // failed step cannot inflate what a rollback tears down.
    let before = cursor.rollback_span();
    let (_error, unchanged) = match cursor.record_initialized() {
        Ok(_) => unreachable!("the set is covered"),
        Err(pair) => pair,
    };
    assert_eq!(unchanged.rollback_span(), before);
}

// ---------------------------------------------------------------------------
// R5 Task 21 (core half): the CQ release preflight
// ---------------------------------------------------------------------------

#[test]
fn cq_release_preflight_records_the_identity_without_releasing_the_role() {
    let (mut state, brand) = branded_state(2100);
    let token = state.acquire_cq_consumer().expect("a fresh ring");
    let invocation = token.execution().invocation();

    // The preflight takes `&self` and borrows the token: nothing is released.
    let preflight = state
        .prepare_cq_release(&token)
        .expect("the state owns this role");
    assert_eq!(preflight.brand(), brand);
    assert_eq!(preflight.invocation(), invocation);

    // The role is still held throughout, so a mutation running between the
    // preflight and the release is not running on a roleless ring -- and no
    // second consumer can slip in.
    assert_eq!(
        state.acquire_cq_consumer().err(),
        Some(RoleError::DeviceBusy),
        "the preflight released nothing"
    );

    // Preflighting twice is allowed and idempotent: it is a record, not a
    // consumption. What is affine is the *release*.
    let second = state.prepare_cq_release(&token).expect("still owned");
    assert_eq!(second.invocation(), invocation);

    let released = state
        .commit_cq_release(preflight, token)
        .unwrap_or_else(|(error, _, _)| unreachable!("the exact role: {error:?}"));
    assert_eq!(released.brand(), brand);
    assert_eq!(released.invocation(), invocation);
    assert!(
        state.acquire_cq_consumer().is_ok(),
        "the commit really did release"
    );
    let _ = second;
}

#[test]
fn cq_release_commit_cannot_release_a_later_invocation_of_the_same_ring() {
    let (mut state, _brand) = branded_state(2101);
    let first = state.acquire_cq_consumer().expect("a fresh ring");
    let stale = state.prepare_cq_release(&first).expect("owned");
    let stale_invocation = stale.invocation();
    state
        .release_cq_consumer(first)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));

    // A *later* invocation of the same ring. A release that re-looked-up the
    // consumer at commit time would find exactly this and credit the wrong
    // execution.
    let later = state.acquire_cq_consumer().expect("released");
    assert_ne!(later.execution().invocation(), stale_invocation);

    let (error, stale, later) = match state.commit_cq_release(stale, later) {
        Ok(_) => unreachable!("a stale preflight must not release a later role"),
        Err(triple) => triple,
    };
    assert_eq!(error, RoleError::WrongInvocation);
    assert_eq!(stale.invocation(), stale_invocation, "the record is intact");

    // The later role is untouched, so its own preflight still works.
    let matching = state.prepare_cq_release(&later).expect("owned");
    let _ = state
        .commit_cq_release(matching, later)
        .unwrap_or_else(|(error, _, _)| unreachable!("its own preflight: {error:?}"));
    assert!(state.acquire_cq_consumer().is_ok());
}

#[test]
fn cq_release_preflight_rejects_foreign_ring_and_sq_domain() {
    let (mut mine, _b1) = branded_state(2102);
    let (theirs, _b2) = branded_state(2103);
    let token = mine.acquire_cq_consumer().expect("a fresh ring");

    // Another ring does not own this role.
    assert_eq!(
        theirs.prepare_cq_release(&token).err(),
        Some(RoleError::WrongRing)
    );

    // A predecessor state has no brand at all.
    let unbranded = RingEnterState::new(0);
    assert_eq!(
        unbranded.prepare_cq_release(&token).err(),
        Some(RoleError::WrongState)
    );

    // And its own state accepts it, so both refusals are about the state and
    // not about the token being damaged.
    let preflight = mine.prepare_cq_release(&token).expect("owned");
    let _ = mine
        .commit_cq_release(preflight, token)
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));

    // A released role has no preflight either: the record is of a *held* role,
    // which is what makes "the role is still held during the mutation" true.
    let fresh = mine.acquire_cq_consumer().expect("released");
    mine.release_cq_consumer(fresh)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    let orphan = mine.acquire_cq_consumer().expect("released again");
    let orphan_preflight = mine.prepare_cq_release(&orphan).expect("owned");
    mine.release_cq_consumer(orphan)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    // The role is gone but the record remains; committing it needs the token,
    // which the release consumed -- so the record alone releases nothing.
    assert!(orphan_preflight.invocation().get() > 0);
}

#[test]
fn cq_release_preflight_rejects_sq_domain_and_wrong_invocation() {
    let (mut state, brand) = branded_state(2104);
    let token = state.acquire_cq_consumer().expect("a fresh ring");
    let invocation = token.execution().invocation();

    state.cq_owner = Some(u64::MAX);
    assert_eq!(
        state.prepare_cq_release(&token).err(),
        Some(RoleError::WrongInvocation),
        "a protocol commit cannot release a foreign invocation"
    );
    state.cq_owner = Some(invocation.get());

    let sq_shaped = CqConsumerToken {
        execution: EnterExecutionBrand {
            ring: brand,
            invocation,
            domain: EnterExecutionDomain::SqWait,
        },
    };
    assert_eq!(
        state.prepare_cq_release(&sq_shaped).err(),
        Some(RoleError::WrongState),
        "an SQ-domain authority is not a CQ consumer"
    );
    state
        .release_cq_consumer(token)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
}

// ---------------------------------------------------------------------------
// R4: the bounded drain wait `WaitPendingAndOwners` runs
// ---------------------------------------------------------------------------

/// An active context is re-observed, and the budget only ever goes down.
#[test]
fn task19_drain_wait_reobserves_an_active_context_within_its_bound() {
    use crate::enter::{PendingDrainStep, PendingDrainWait};

    let mut wait = PendingDrainWait::begin_drain_wait();
    assert_eq!(wait.remaining(), PendingDrainWait::MAX_OBSERVATIONS);

    // Each active observation costs exactly one, and never restores any.
    let mut seen = 0u32;
    loop {
        let before = wait.remaining();
        match wait.observed_active() {
            PendingDrainStep::Observe(next) => {
                assert_eq!(
                    next.remaining(),
                    before - 1,
                    "an active observation costs exactly one"
                );
                wait = next;
                seen = seen.saturating_add(1);
            }
            PendingDrainStep::Refused(reason) => {
                assert_eq!(reason, crate::enter::PendingDrainRefusal::StillActive);
                break;
            }
            PendingDrainStep::Drained => panic!("an active context is not drained"),
        }
        assert!(
            seen < PendingDrainWait::MAX_OBSERVATIONS,
            "the wait must be bounded"
        );
    }
    assert_eq!(
        seen,
        PendingDrainWait::MAX_OBSERVATIONS - 1,
        "the bound is the whole budget, spent once each"
    );
}

/// A drained context ends the wait immediately, at any point in the budget.
#[test]
fn task19_drain_wait_accepts_a_drained_context_at_any_point() {
    use crate::enter::{PendingDrainStep, PendingDrainWait};

    assert!(matches!(
        PendingDrainWait::begin_drain_wait().observed_drained(),
        PendingDrainStep::Drained
    ));

    // And after spending most of the budget.
    let mut wait = PendingDrainWait::begin_drain_wait();
    for _ in 0..16 {
        wait = match wait.observed_active() {
            PendingDrainStep::Observe(next) => next,
            other => panic!("still inside the budget: {other:?}"),
        };
    }
    assert!(matches!(wait.observed_drained(), PendingDrainStep::Drained));
}

/// A parked publication fail-stop refuses at once and can never be retried into
/// a drained proof.
#[test]
fn task19_drain_wait_never_retries_a_publication_fail_stop() {
    use crate::enter::{PendingDrainRefusal, PendingDrainStep, PendingDrainWait};

    // At the very start of the budget.
    let refusal = match PendingDrainWait::begin_drain_wait().observed_publication_fail_stop() {
        PendingDrainStep::Refused(reason) => reason,
        other => panic!("a fail-stop is not waitable: {other:?}"),
    };
    assert_eq!(refusal, PendingDrainRefusal::PublicationFailStop);

    // And with the whole budget still unspent, so the refusal is about the
    // fail-stop rather than about running out of observations. The two reasons
    // are distinct values precisely so a reader can tell them apart.
    let mut wait = PendingDrainWait::begin_drain_wait();
    for _ in 0..4 {
        wait = match wait.observed_active() {
            PendingDrainStep::Observe(next) => next,
            other => panic!("still inside the budget: {other:?}"),
        };
    }
    assert!(wait.remaining() > 0);
    let refusal = match wait.observed_publication_fail_stop() {
        PendingDrainStep::Refused(reason) => reason,
        other => panic!("a fail-stop is not waitable: {other:?}"),
    };
    assert_eq!(
        refusal,
        PendingDrainRefusal::PublicationFailStop,
        "a fail-stop refuses as a fail-stop, not as an exhausted budget"
    );
}

// ---------------------------------------------------------------------------
// R5 Task 20: the CQ stream brand
// ---------------------------------------------------------------------------

/// A stream brand exists only for a held CQ-consumer role, reports that exact
/// ring, and is the CQ domain rather than the SQ one.
#[test]
fn task20_cq_stream_brand_narrows_the_execution_to_the_cq_domain() {
    let (mut state, _brand) = branded_state(9200);
    let token = state
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("a free ring admits one consumer");

    let stream = token.cq_stream();
    assert!(
        stream.is_cq_domain(),
        "a stream minted from a consumer token is the CQ domain"
    );
    assert_eq!(stream.ring_brand(), token.brand());
    assert_eq!(stream.locator(), token.brand().locator());
    assert_eq!(stream.ring_index(), token.brand().ring_index());
    assert_eq!(stream.execution(), token.execution());

    // Borrowing the stream does not spend the role: a bind that refused would
    // otherwise have released the ring's consumer to nobody.
    let again = token.cq_stream();
    assert_eq!(again, stream, "the brand is a report, not a consumption");
    state
        .release_cq_consumer(token)
        .map_err(|_| ())
        .expect("the role is still held and releasable");
}

#[test]
fn cq_stream_brand_is_not_vacuously_the_cq_domain() {
    let (mut state, brand) = branded_state(9203);
    let token = state
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("a free ring admits one consumer");
    let sq_stream = CqStreamBrand {
        execution: EnterExecutionBrand {
            ring: brand,
            invocation: token.execution().invocation(),
            domain: EnterExecutionDomain::SqWait,
        },
    };
    assert!(
        !sq_stream.is_cq_domain(),
        "an SQ-domain execution must not report as a CQ stream"
    );
    state
        .release_cq_consumer(token)
        .map_err(|_| ())
        .expect("the acquired role is still held");
}

/// Two rings, and two invocations of one ring, are different streams.
#[test]
fn task20_cq_stream_brands_do_not_collide_across_rings_or_invocations() {
    let (mut first, _first_brand) = branded_state(9201);
    let (mut second, _second_brand) = branded_state(9202);

    let a = first
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("ring 0 admits");
    let b = second
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("ring 1 admits");
    assert_ne!(
        a.cq_stream(),
        b.cq_stream(),
        "two rings are two streams even at the same invocation ordinal"
    );

    let a_stream = a.cq_stream();
    first
        .release_cq_consumer(a)
        .map_err(|_| ())
        .expect("releasable");
    let a_again = first
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("the freed ring re-admits");
    assert_ne!(
        a_stream,
        a_again.cq_stream(),
        "a second invocation of the same ring is a different stream"
    );
    let _ = second.release_cq_consumer(b);
    let _ = first.release_cq_consumer(a_again);
}

// ---------------------------------------------------------------------------
// R5 Task 20: binding CQ storage to the ring that owns it
// ---------------------------------------------------------------------------

/// Backing for one CQ mapping, owned by the test for the whole borrow.
struct CqBacking {
    producer: fsring_abi::layout::ProducerPage,
    consumer: fsring_abi::layout::ConsumerPage,
    entries: std::vec::Vec<fsring_abi::layout::Cqe>,
}

impl CqBacking {
    fn new(capacity: usize) -> Self {
        Self {
            // SAFETY-FREE: both pages are plain POD wire structs, and a zeroed
            // page is the documented initial cursor state.
            producer: unsafe { core::mem::zeroed() },
            consumer: unsafe { core::mem::zeroed() },
            entries: std::vec![unsafe { core::mem::zeroed() }; capacity],
        }
    }

    fn descriptor(&mut self, capacity: usize) -> crate::enter::CqStorageDescriptor {
        // SAFETY: the three spans are distinct fields of this live value and
        // outlive every descriptor use below.
        unsafe {
            crate::enter::CqStorageDescriptor::from_raw_parts(
                core::ptr::NonNull::from(&mut self.producer),
                core::ptr::NonNull::from(&mut self.consumer),
                core::ptr::NonNull::from(&mut self.entries[0]),
                capacity,
            )
        }
        .expect("a power-of-two capacity binds")
    }
}

/// A descriptor exists only for a capacity the ABI's mask arithmetic accepts.
#[test]
fn task20_cq_storage_descriptor_refuses_a_capacity_the_cursor_cannot_mask() {
    use crate::enter::{CqBindError, CqStorageDescriptor};

    let mut backing = CqBacking::new(4);
    let producer = core::ptr::NonNull::from(&mut backing.producer);
    let consumer = core::ptr::NonNull::from(&mut backing.consumer);
    let entries = core::ptr::NonNull::from(&mut backing.entries[0]);

    // SAFETY: every call below uses the same live spans; only `capacity` varies.
    for (capacity, expected) in [
        (0usize, CqBindError::ZeroCapacity),
        (1, CqBindError::NonPowerOfTwoCapacity),
        (3, CqBindError::NonPowerOfTwoCapacity),
        (6, CqBindError::NonPowerOfTwoCapacity),
    ] {
        let error = match unsafe {
            CqStorageDescriptor::from_raw_parts(producer, consumer, entries, capacity)
        } {
            Ok(_) => panic!("capacity {capacity} must be refused"),
            Err(error) => error,
        };
        assert_eq!(error, expected, "capacity {capacity}");
    }

    // And the smallest capacity the ABI documents is accepted.
    let ok = unsafe { CqStorageDescriptor::from_raw_parts(producer, consumer, entries, 2) }
        .expect("two is a power of two");
    assert_eq!(ok.capacity(), 2);
    assert_eq!(
        ok.entry_bytes(),
        2 * core::mem::size_of::<fsring_abi::layout::Cqe>()
    );
}

/// Storage binds to the ring its ticket names, and a consumer borrowed from it
/// serves that ring and no other.
#[test]
fn task20_cq_storage_binds_to_the_ring_its_ticket_names() {
    use crate::enter::{BrandedCqStorage, build_pending_slot_parts};

    const CAPACITY: usize = 8;
    let (_registry, mut installed) = installed_for_rings(9210);
    let mut set = installed.begin_ring_set(2).expect("a fresh install");
    let first_right = set.next_ring().expect("ids").expect("ring 0");
    let second_right = set.next_ring().expect("ids").expect("ring 1");
    let first_brand = first_right.brand();
    let second_brand = second_right.brand();

    let mut first = build_pending_slot_parts(first_right, 64)
        .map_err(|_| ())
        .expect("ring 0 builds");
    let mut second = build_pending_slot_parts(second_right, 64)
        .map_err(|_| ())
        .expect("ring 1 builds");

    let mut backing = CqBacking::new(CAPACITY);
    let descriptor = backing.descriptor(CAPACITY);
    // SAFETY: the descriptor names this test's own live backing.
    let storage = unsafe { BrandedCqStorage::bind_storage(first.cq_storage, descriptor) };
    assert_eq!(storage.brand(), first_brand);

    let mut bytes = std::vec![0u8; CAPACITY * core::mem::size_of::<fsring_abi::layout::Cqe>()];
    // SAFETY: the slice is at least the entry span the descriptor claims.
    let scoped =
        unsafe { storage.borrow_consumer(&mut bytes) }.expect("the backing is long enough");
    let own = first
        .state
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("ring 0 admits its consumer");
    let other = second
        .state
        .acquire_cq_consumer()
        .map_err(|_| ())
        .expect("ring 1 admits its consumer");
    assert!(
        scoped.serves(own.cq_stream()),
        "the consumer serves the ring its storage was bound to"
    );
    assert!(
        !scoped.serves(other.cq_stream()),
        "and refuses another ring's stream, so the check above is not vacuous"
    );
    assert_ne!(first_brand, second_brand);
    let _ = first.state.release_cq_consumer(own);
    let _ = second.state.release_cq_consumer(other);
}

/// A backing shorter than the capacity claims is refused: the ABI is handed a
/// pointer and a count and cannot tell.
#[test]
fn task20_cq_consumer_refuses_a_backing_shorter_than_its_entry_span() {
    use crate::enter::{BrandedCqStorage, CqBindError, build_pending_slot_parts};

    const CAPACITY: usize = 8;
    let (_registry, mut installed) = installed_for_rings(9211);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set.next_ring().expect("ids").expect("ring 0");
    let parts = build_pending_slot_parts(right, 64)
        .map_err(|_| ())
        .expect("ring 0 builds");

    let mut backing = CqBacking::new(CAPACITY);
    let descriptor = backing.descriptor(CAPACITY);
    let span = descriptor.entry_bytes();
    // SAFETY: the descriptor names this test's own live backing.
    let storage = unsafe { BrandedCqStorage::bind_storage(parts.cq_storage, descriptor) };

    let mut short = std::vec![0u8; span - 1];
    // SAFETY: the call is expected to refuse before attaching anything.
    let error = match unsafe { storage.borrow_consumer(&mut short) } {
        Ok(_) => panic!("a short backing must be refused"),
        Err(error) => error,
    };
    assert_eq!(error, CqBindError::WrongStorage);

    // Exactly the span is enough, so the refusal above is about the shortfall.
    let mut exact = std::vec![0u8; span];
    // SAFETY: as above.
    assert!(unsafe { storage.borrow_consumer(&mut exact) }.is_ok());
}

// ---------------------------------------------------------------------------
// R6 recovery: a completed install releases its slot for reuse
// ---------------------------------------------------------------------------
//
// `begin_install` and `bind_install` each refuse a second install while one is
// bound, and nothing ever unbound them. A ring therefore served exactly one
// parked WAIT for the life of the session: the second park refused before it
// reached the CSQ. These pin the closing half of both pairs.

#[test]
fn a_finished_schedule_releases_its_install_for_the_next_park() {
    let (_state, brand) = branded_state(3101);
    let install = PendingInstallId::for_test(brand, 1);
    let successor = PendingInstallId::for_test(brand, 2);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    assert_eq!(
        schedule.begin_install(successor).err(),
        Some(PendingError::SlotOccupied),
        "one install at a time",
    );

    schedule
        .end_install(install)
        .expect("the install is finished");

    assert_eq!(schedule.axis(), InstallAxis::Installing, "reset for reuse");
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);
    schedule
        .begin_install(successor)
        .expect("the released schedule takes the next install");
}

#[test]
fn a_schedule_with_a_pass_still_running_keeps_its_install() {
    let (_state, brand) = branded_state(3102);
    let install = PendingInstallId::for_test(brand, 1);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    schedule
        .queue_worker(install)
        .expect("a wake queues one pass");

    assert_eq!(
        schedule.end_install(install).err(),
        Some(PendingError::WrongRingState),
        "a queued or running pass still names this install",
    );
}

#[test]
fn a_schedule_refuses_to_end_an_install_it_does_not_serve() {
    let (_state, brand) = branded_state(3103);
    let install = PendingInstallId::for_test(brand, 1);
    let other = PendingInstallId::for_test(brand, 2);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");

    assert_eq!(
        schedule.end_install(other).err(),
        Some(PendingError::WrongInstall),
    );
}

/// One ring's owner ledger and wake slot, built the way production builds them.
fn branded_owners(n: u64) -> (PendingOwnerLedger, SessionRingBrand) {
    let (owners, _wake, brand) = branded_owner_parts(n);
    (owners, brand)
}

fn branded_owner_parts(n: u64) -> (PendingOwnerLedger, PendingWakeSlot, SessionRingBrand) {
    let (_registry, mut installed) = installed_for_rings(n);
    let mut set = installed.begin_ring_set(1).expect("a fresh install");
    let right = set
        .next_ring()
        .expect("identities available")
        .expect("ring 0");
    let brand = right.brand();
    let parts = build_ring_runtime_parts(brand, 64, right)
        .unwrap_or_else(|(error, _)| unreachable!("a matching brand builds: {error:?}"));
    let (_state, _slot, owners, wake, _bind) = parts.into_parts();
    (owners, wake, brand)
}

#[test]
fn a_drained_ledger_releases_its_install_for_the_next_park() {
    let (mut owners, brand) = branded_owners(3104);
    let install = PendingInstallId::for_test(brand, 1);
    let successor = PendingInstallId::for_test(brand, 2);
    owners.bind_install(install).expect("a fresh ledger");
    assert_eq!(
        owners.bind_install(successor).err(),
        Some(PendingError::SlotOccupied),
    );

    owners
        .unbind_install(install)
        .expect("no owner is still held");

    owners
        .bind_install(successor)
        .expect("the released ledger takes the next install");
}

#[test]
fn a_ledger_with_an_owner_outstanding_keeps_its_install() {
    let (mut owners, brand) = branded_owners(3105);
    let install = PendingInstallId::for_test(brand, 1);
    owners.bind_install(install).expect("a fresh ledger");
    let installer = owners
        .acquire_owner(install, PendingOwnerKind::Installer)
        .expect("the first Installer");

    assert_eq!(
        owners.unbind_install(install).err(),
        Some(PendingError::OwnersRemain),
        "unbinding under a live owner would strand it",
    );

    owners.release_owner(installer).expect("release");
    owners.unbind_install(install).expect("now drained");
}

#[test]
fn a_completing_schedule_releases_its_install_for_the_next_park() {
    // The state a *finished* install is in. `Idle` covers one bound and torn
    // down without a pass ever running; a completed install arrives here
    // through `begin_worker_completion`, and it must release too or the ring
    // never serves a second WAIT.
    let (mut owners, mut wake, brand) = branded_owner_parts(3106);
    let install = PendingInstallId::for_test(brand, 1);
    let successor = PendingInstallId::for_test(brand, 2);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    owners.bind_install(install).expect("a fresh ledger");
    let mut worker = Some(
        owners
            .acquire_owner(install, PendingOwnerKind::Worker)
            .expect("the Worker owner"),
    );
    wake.record_wake(install, PendingReason::Cancel)
        .expect("a stored wake");
    schedule.queue_worker(install).expect("one pass is queued");
    begin_native_worker_pass(install, &mut schedule, &mut wake, &mut worker).expect("begins");

    let token = worker.take().expect("the token came back");
    let token = schedule
        .begin_worker_completion(token)
        .unwrap_or_else(|(error, _)| unreachable!("a Running pass completes: {error:?}"));
    assert_eq!(schedule.state(), WorkerScheduleState::Completing);
    owners
        .release_owner(token)
        .expect("the completion releases the Worker owner");

    schedule
        .end_install(install)
        .expect("a completing schedule releases its install");
    owners
        .unbind_install(install)
        .expect("the drained ledger releases too");

    schedule
        .begin_install(successor)
        .expect("the ring serves the next parked WAIT");
}

#[test]
fn beginning_a_native_pass_takes_the_arbitrated_reason_and_runs_the_schedule() {
    let (mut owners, mut wake, brand) = branded_owner_parts(3107);
    let install = PendingInstallId::for_test(brand, 1);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    owners.bind_install(install).expect("a fresh ledger");
    let mut worker = Some(
        owners
            .acquire_owner(install, PendingOwnerKind::Worker)
            .expect("the Worker owner"),
    );
    // Two coalesced reasons: WORKER_PRIORITY must pick Cancel over Readiness.
    wake.record_wake(install, PendingReason::Readiness)
        .expect("a stored wake");
    wake.record_wake(install, PendingReason::Cancel)
        .expect("a coalesced wake");
    schedule.queue_worker(install).expect("one pass is queued");

    let reason = begin_native_worker_pass(install, &mut schedule, &mut wake, &mut worker)
        .expect("a queued pass begins");

    assert_eq!(reason, PendingReason::Cancel, "the frozen priority order");
    assert_eq!(schedule.state(), WorkerScheduleState::Running);
    assert!(worker.is_some(), "the token comes back");
}

#[test]
fn a_native_pass_that_is_not_queued_keeps_the_wake_it_could_not_take() {
    let (mut owners, mut wake, brand) = branded_owner_parts(3108);
    let install = PendingInstallId::for_test(brand, 1);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    owners.bind_install(install).expect("a fresh ledger");
    let mut worker = Some(
        owners
            .acquire_owner(install, PendingOwnerKind::Worker)
            .expect("the Worker owner"),
    );
    wake.record_wake(install, PendingReason::Cancel)
        .expect("a stored wake");
    // Schedule left Idle: no pass was queued.

    let refused = begin_native_worker_pass(install, &mut schedule, &mut wake, &mut worker);

    assert_eq!(refused.err(), Some(PendingError::WrongRingState));
    assert!(
        wake.stored_covers(PendingReason::Cancel),
        "a refusal must not empty the wake slot it could not act on",
    );
    assert!(worker.is_some(), "the token comes back");
}

#[test]
fn finishing_a_native_pass_reports_whether_another_is_due() {
    let (mut owners, mut wake, brand) = branded_owner_parts(3109);
    let install = PendingInstallId::for_test(brand, 1);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    owners.bind_install(install).expect("a fresh ledger");
    let mut worker = Some(
        owners
            .acquire_owner(install, PendingOwnerKind::Worker)
            .expect("the Worker owner"),
    );
    wake.record_wake(install, PendingReason::Cancel)
        .expect("a stored wake");
    schedule.queue_worker(install).expect("one pass is queued");
    begin_native_worker_pass(install, &mut schedule, &mut wake, &mut worker).expect("begins");

    let again =
        finish_native_worker_pass(&mut schedule, &mut owners, &mut worker).expect("finishes");

    assert!(
        again.is_none(),
        "nothing was rescheduled, so nothing is owed"
    );
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);
    // The wedge this closes. An `Idle` schedule has no pass to inherit the
    // Worker token, and `record_and_schedule_pending` refuses any wake while
    // one is held -- so a token left here does not slow the ring down, it
    // ends it: no later wake, from cancel, timeout, readiness or the fence
    // sweep, can ever queue another pass for this install.
    assert!(
        worker.is_none(),
        "an Idle finish leaves no Worker owner behind",
    );
    assert!(
        !owners.holds(PendingOwnerKind::Worker),
        "and the ledger stops counting one",
    );
    let later = record_and_schedule_pending(
        install,
        PendingReason::Cancel,
        &mut schedule,
        &mut wake,
        &mut owners,
        &mut worker,
    )
    .expect("a wake after an Idle finish is accepted, not refused DuplicateOwner");
    let PendingWakeOutcome::Queued(right) = later else {
        panic!("a wake after an Idle finish must queue the pass the request is still owed");
    };
    // SAFETY: the obligation is discharged here the way the native caller
    // discharges it -- this test stands in for the queue DDI call.
    unsafe { right.commit_after_work_queued() };
    let token = schedule
        .abandon_queued_pass(worker.take().expect("the new pass owns a token"))
        .expect("the queued pass is put back");
    let _ = owners.release_owner(token);
    schedule
        .end_install(install)
        .expect("an idle schedule releases its install");
}

/// The window between the handoff and the plan store.
///
/// `commit_pending_handoff` answered `Ready` -- no wake was stored while the
/// install was `Installing` -- so the schedule reads `HandoffDone`/`Idle` and
/// the plan does not exist yet. A timeout DPC lands in exactly that instant:
/// the wake is recorded and a pass is queued, the pass runs before the plan is
/// stored, finds nothing to begin and abandons back to `Idle`, leaving its
/// reason in the slot with nothing scheduled. Nothing in the driver re-reads a
/// stored wake, so without the store asking this question the finite WAIT
/// never times out and a cancelled IRP is never completed.
#[test]
fn a_wake_stranded_before_the_plan_store_is_queued_by_the_store() {
    let (mut owners, mut wake, brand) = branded_owner_parts(3110);
    let install = PendingInstallId::for_test(brand, 1);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    owners.bind_install(install).expect("a fresh ledger");
    let mut worker: Option<PendingOwnerToken> = None;

    let queued = record_and_schedule_pending(
        install,
        PendingReason::Timeout,
        &mut schedule,
        &mut wake,
        &mut owners,
        &mut worker,
    )
    .expect("a wake in the window is accepted");
    let PendingWakeOutcome::Queued(right) = queued else {
        panic!("a wake at HandoffDone/Idle queues a pass");
    };
    // SAFETY: this test stands in for the queue DDI call the native caller
    // makes to discharge the obligation.
    unsafe { right.commit_after_work_queued() };

    // The pass runs before the plan exists, finds nothing, and abandons.
    let token = worker.take().expect("the queued pass owns the token");
    let token = match schedule.abandon_queued_pass(token) {
        Ok(token) => token,
        Err(_) => panic!("a queued pass that could not begin is put back"),
    };
    let _ = owners.release_owner(token);
    assert_eq!(schedule.state(), WorkerScheduleState::Idle);
    assert!(
        wake.stored_covers(PendingReason::Timeout),
        "the reason the pass could not act on stays in the slot",
    );

    // The store publishes the plan. This is the first instant a pass could do
    // anything with that reason, and the last instant anything will ask.
    let owed = schedule_stored_wake(install, &mut schedule, &wake, &mut owners, &mut worker)
        .expect("the store's question is legal here")
        .expect("a stored wake with nothing scheduled is owed a pass");
    // SAFETY: as above.
    unsafe { owed.commit_after_work_queued() };
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);
    assert!(
        worker.is_some(),
        "and that pass owns exactly one Worker token",
    );

    // Asking again must not mint a second obligation for one slot.
    let again = schedule_stored_wake(install, &mut schedule, &wake, &mut owners, &mut worker)
        .expect("a second ask is legal");
    assert!(again.is_none(), "a queued pass is not owed another");
}

/// A cancel that lands while a pass stands declared `Completing`.
///
/// `record_and_schedule_pending` refuses in `Completing` BEFORE it records,
/// so that wake is dropped, not stored -- correct while `Completing` meant a
/// terminal was on its way, and a hole once a completion can be abandoned.
/// The abandoned pass is the last thing that can notice, and this is the way
/// out it has to use: at `Running` the same reason is accepted, and the finish
/// then owes the queue call that serves the cancelled request.
#[test]
fn a_reason_refused_during_completing_is_accepted_once_the_completion_is_abandoned() {
    let (mut owners, mut wake, brand) = branded_owner_parts(3111);
    let install = PendingInstallId::for_test(brand, 1);
    let mut schedule = PendingWorkerSchedule::for_brand(brand);
    schedule.begin_install(install).expect("a fresh schedule");
    schedule.handoff_done(install).expect("the handoff");
    owners.bind_install(install).expect("a fresh ledger");
    let mut worker = Some(
        owners
            .acquire_owner(install, PendingOwnerKind::Worker)
            .expect("the Worker owner"),
    );
    // The readiness wake that queued this pass; `begin_native_worker_pass`
    // takes it out of the slot, which is why the slot is empty below.
    wake.record_wake(install, PendingReason::Readiness)
        .expect("a stored wake");
    schedule.queue_worker(install).expect("one pass is queued");
    begin_native_worker_pass(install, &mut schedule, &mut wake, &mut worker).expect("begins");
    let token = worker.take().expect("the running pass owns the token");
    let token = match schedule.begin_worker_completion(token) {
        Ok(token) => token,
        Err(_) => panic!("a running pass may declare its completion"),
    };
    worker = Some(token);

    // The cancel arrives here, and is dropped rather than stored.
    let refused = record_and_schedule_pending(
        install,
        PendingReason::Cancel,
        &mut schedule,
        &mut wake,
        &mut owners,
        &mut worker,
    );
    assert_eq!(refused.err(), Some(PendingError::Closing));
    assert!(
        !wake.stored_covers(PendingReason::Cancel),
        "the refusal happens before the record, so nothing holds this reason",
    );

    // The dequeue answered NULL, so the pass gives everything back.
    let token = worker.take().expect("the completing pass owns the token");
    let token = match schedule.abandon_worker_completion(token) {
        Ok(token) => token,
        Err(_) => panic!("an abandoned completion returns to Running"),
    };
    worker = Some(token);

    // The way out: the same reason, now accepted, and a pass owed for it.
    let accepted = record_and_schedule_pending(
        install,
        PendingReason::Cancel,
        &mut schedule,
        &mut wake,
        &mut owners,
        &mut worker,
    )
    .expect("Running accepts what Completing refused");
    assert!(
        matches!(accepted, PendingWakeOutcome::Rescheduled),
        "a running pass takes the reason as a reschedule",
    );
    let owed = finish_native_worker_pass(&mut schedule, &mut owners, &mut worker)
        .expect("the pass finishes")
        .expect("and owes the queue call the cancelled request is served by");
    // SAFETY: this test stands in for the queue DDI call.
    unsafe { owed.commit_after_work_queued() };
    assert_eq!(schedule.state(), WorkerScheduleState::Queued);
    assert!(
        wake.stored_covers(PendingReason::Cancel),
        "and the reason that pass will act on is in the slot",
    );
}

/// The framework's documented cancel order, end to end.
///
/// `CsqRemoveIrp` runs first and empties the slot; `CsqCompleteCanceledIrp`
/// runs second and must leave the slot naming the cancelled IRP, because the
/// slot is the only holder of that pointer. This is the sequence that
/// bugchecked from `079ec55` until the classification existed: the completion
/// callback demanded a pointer its predecessor had just cleared.
#[test]
fn a_cancel_after_the_remove_callback_leaves_the_slot_naming_the_irp() {
    let irp = IrpObservation::from_raw(0x4000).expect("non-null");

    // `csq_insert_irp`: the slot names the parked IRP.
    let mut slot = Some(irp);
    assert_eq!(slot, Some(irp), "the insert callback names the IRP");

    // `CsqRemoveIrp`: the slot stops naming an IRP the queue no longer holds.
    // The framework runs this FIRST on the cancel path, which is the fact the
    // completion callback used to contradict.
    slot = None;

    // `CsqCompleteCanceledIrp`, with the IRP the framework dequeued.
    match classify_csq_cancel_completion(slot, Some(irp)) {
        CsqCancelCompletion::AdoptRemoved => slot = Some(irp),
        other => panic!("cancel completion after a remove answered {other:?}"),
    }

    assert_eq!(
        slot,
        Some(irp),
        "the cancel path must end with the slot naming the cancelled IRP",
    );
}

#[test]
fn a_cancel_completion_on_a_slot_that_still_names_it_repairs_nothing() {
    let irp = IrpObservation::from_raw(0x4000).expect("non-null");
    assert_eq!(
        classify_csq_cancel_completion(Some(irp), Some(irp)),
        CsqCancelCompletion::AlreadyNamed,
    );
}

#[test]
fn a_cancel_completion_naming_a_different_irp_is_refused() {
    let parked = IrpObservation::from_raw(0x4000).expect("non-null");
    let other = IrpObservation::from_raw(0x8000).expect("non-null");
    assert_eq!(
        classify_csq_cancel_completion(Some(parked), Some(other)),
        CsqCancelCompletion::ForeignIrp,
        "a slot naming a different IRP is two installs on one slot",
    );
}

#[test]
fn a_cancel_completion_with_no_irp_adopts_and_refuses_nothing() {
    let parked = IrpObservation::from_raw(0x4000).expect("non-null");
    assert_eq!(
        classify_csq_cancel_completion(None, None),
        CsqCancelCompletion::NoIrp,
    );
    assert_eq!(
        classify_csq_cancel_completion(Some(parked), None),
        CsqCancelCompletion::NoIrp,
    );
}

/// The empty slot must be the ADOPT case and not the refusal case.
///
/// Stated separately from the sequence test because this is the single
/// discrimination the blocker got backwards: an empty slot at cancel completion
/// is the normal order, not a foreign IRP.
#[test]
fn an_empty_slot_at_cancel_completion_is_normal_and_never_a_refusal() {
    let irp = IrpObservation::from_raw(0x4000).expect("non-null");
    let decided = classify_csq_cancel_completion(None, Some(irp));
    assert_ne!(decided, CsqCancelCompletion::ForeignIrp);
    assert_eq!(decided, CsqCancelCompletion::AdoptRemoved);
}

/// A DPC-exit wait is sound only immediately after a cancel that bounds it.
///
/// The completion plan is where that pair lives, and the adjacency is the
/// property: a wait entered before anything asked the timer to stop is a wait
/// on an unfired deadline -- the client's whole `timeout_ms` on a system worker
/// thread. That was a shipped blocker, so the order is asserted rather than
/// assumed.
#[test]
fn the_dpc_exit_wait_runs_directly_after_the_cancel_that_bounds_it() {
    let cancel = PENDING_COMPLETION_ORDER
        .iter()
        .position(|effect| *effect == PendingCompletionEffect::CancelTimer)
        .expect("the completion plan cancels the timer");
    let wait = PENDING_COMPLETION_ORDER
        .iter()
        .position(|effect| *effect == PendingCompletionEffect::WaitDpcExitIfRequired)
        .expect("the completion plan waits for the DPC exit");
    assert_eq!(
        wait,
        cancel + 1,
        "the exit wait must be bounded by the cancel immediately before it",
    );
}

/// The worker roster holds no second DPC-exit rendezvous.
///
/// It held one for two rounds and it could not be made correct there: no cancel
/// precedes it, so it either waits on an unfired deadline or -- narrowed to
/// `Running`, a state only the DPC's own lock hold can contain -- never waits at
/// all. A rendezvous that cannot fire is worse than none, because it reads as a
/// protection. The roster is now six effects and observes first.
#[test]
fn the_worker_roster_holds_no_second_dpc_exit_rendezvous() {
    assert_eq!(
        PENDING_WORKER_PASS_ORDER.len(),
        6,
        "a seventh worker effect needs its own justification",
    );
    assert_eq!(
        PENDING_WORKER_PASS_ORDER[0],
        PendingCallbackAction::BeginWorkerPass,
    );
    assert_eq!(
        PENDING_WORKER_PASS_ORDER[1],
        PendingCallbackAction::PollAndRecheck,
        "the pass observes first now that nothing waits before it",
    );
    // No worker effect blocks any more: the three that remain forbidden at
    // DISPATCH_LEVEL are the ownership ones, and none of them waits.
    assert!(
        PENDING_WORKER_PASS_ORDER
            .iter()
            .filter(|effect| effect.forbidden_at_dispatch_level())
            .count()
            == 3,
        "the roster's DISPATCH-forbidden effects are exactly the ownership three",
    );
}
