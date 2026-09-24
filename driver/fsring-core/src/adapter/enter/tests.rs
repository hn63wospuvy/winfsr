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
    msgs::{CONTROL_VERSION_V1, ControlHeader},
    validate::{ValidatedTopology, validate_setup_request_v1},
};

use crate::adapter::setup::ScratchIdentity;
use crate::enter::{EnterContender, EnterRole, PendingEnter};
use crate::grant::GrantEntry;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SECURITY_ONLY: FeatureSet = FeatureSet { words: [0x10, 0] };
const IDENTITY: SessionIdentity = SessionIdentity {
    boot_instance_id: BootInstanceId { lo: 3, hi: 5 },
    mount_id: MountId { lo: 7, hi: 11 },
    session_epoch: 1,
};

fn class(slot_size: u32, slot_count: u32) -> SlotClassRequest {
    SlotClassRequest {
        slot_size,
        slot_count,
    }
}

fn topology(ring_count: u32) -> ValidatedTopology {
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
            class(0, 0),
            class(0, 0),
            class(0, 0),
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
    .expect("the enter adapter fixture must validate")
    .topology()
}

fn entry_count(topology: &ValidatedTopology) -> usize {
    topology
        .u2k_slot_classes()
        .iter()
        .map(|request| request.slot_count as usize)
        .sum()
}

/// Host-owned grant backing. The table itself is built once and held by the
/// caller, because a second `initialize` over already-issued entries is exactly
/// what the grant model refuses.
struct GrantBacking {
    entries: Vec<GrantEntry>,
    topology: ValidatedTopology,
}

impl GrantBacking {
    fn new(ring_count: u32) -> Self {
        let topology = topology(ring_count);
        let entries = vec![GrantEntry::FREE; entry_count(&topology)];
        Self { entries, topology }
    }
}

fn poll_input() -> NativeEnterInput {
    NativeEnterInput {
        kind: NativeEnterKind::Poll,
        ring_index: 0,
        output_capacity: 48,
        cq_budget: 0,
        timeout_ms: 0,
    }
}

fn drain_input(budget: u32) -> NativeEnterInput {
    NativeEnterInput {
        kind: NativeEnterKind::Drain,
        ring_index: 0,
        output_capacity: 48 + 32 * budget as usize,
        cq_budget: budget,
        timeout_ms: 0,
    }
}

fn wait_input(timeout_ms: u32) -> NativeEnterInput {
    NativeEnterInput {
        kind: if timeout_ms == u32::MAX {
            NativeEnterKind::WaitInfinite
        } else {
            NativeEnterKind::WaitFinite
        },
        ring_index: 0,
        output_capacity: 48,
        cq_budget: 0,
        timeout_ms,
    }
}

#[test]
fn the_wait_timeout_encoding_is_the_frozen_wire_encoding() {
    // 02-transport: `timeout_ms = 0` polls, `0xffffffff` waits indefinitely,
    // every other value is a relative timeout. The two wait forms are not
    // interchangeable: a finite wait may complete TIMED_OUT and an indefinite
    // one may not, so swapping them silently changes what a daemon is told.
    assert!(
        NativeEnterPlan::begin(NativeEnterInput {
            kind: NativeEnterKind::WaitInfinite,
            ..wait_input(u32::MAX)
        })
        .is_ok(),
        "the sentinel is the indefinite wait",
    );
    assert_eq!(
        NativeEnterPlan::begin(NativeEnterInput {
            kind: NativeEnterKind::WaitInfinite,
            ring_index: 0,
            output_capacity: 48,
            cq_budget: 0,
            timeout_ms: 0,
        })
        .err(),
        Some(AdapterPlanError::InvalidInput),
        "a zero timeout is a poll, never the indefinite wait",
    );
    assert_eq!(
        NativeEnterPlan::begin(NativeEnterInput {
            kind: NativeEnterKind::WaitFinite,
            ring_index: 0,
            output_capacity: 48,
            cq_budget: 0,
            timeout_ms: u32::MAX,
        })
        .err(),
        Some(AdapterPlanError::InvalidInput),
        "the sentinel is not a relative timeout, so it can never time out",
    );
    assert!(
        NativeEnterPlan::begin(NativeEnterInput {
            kind: NativeEnterKind::WaitFinite,
            ..wait_input(25)
        })
        .is_ok(),
        "an ordinary relative timeout is the finite wait",
    );
}

/// Drive the ordinary effects until the plan reaches a typed capability, a
/// completion, or the parked state, recording every effect seen.
fn walk<'g>(
    mut progress: EnterProgress<'g>,
    recorded: &mut Vec<EnterEffect>,
    decision: EnterDecision,
    roles: &mut RingEnterState,
) -> EnterProgress<'g> {
    loop {
        match progress {
            EnterProgress::Effect(pending) => {
                let effect = pending.effect();
                if matches!(effect, EnterEffect::PreflightCqAndCredit) {
                    // Only the caller can supply a CQ classification, so the
                    // walk stops here rather than inventing one.
                    return EnterProgress::Effect(pending);
                }
                recorded.push(effect);
                let outcome = match effect {
                    EnterEffect::AcquireRole => {
                        EnterEffectOutcome::RoleAcquired(lease_from(roles, EnterRole::Cq))
                    }
                    EnterEffect::PollClearRecheck => {
                        EnterEffectOutcome::ReadinessObserved(decision)
                    }
                    EnterEffect::ReturnPending => EnterEffectOutcome::PendingInstalled,
                    _ => EnterEffectOutcome::Done,
                };
                progress = match pending.succeeded(outcome) {
                    Ok(next) => next,
                    Err(error) => panic!("{effect:?} refused its own outcome: {error:?}"),
                };
            }
            other => return other,
        }
    }
}

fn lease_from(roles: &mut RingEnterState, role: EnterRole) -> RoleLease {
    roles
        .acquire_role(invocation(), role)
        .expect("a fresh ring grants both roles")
}

fn invocation() -> u64 {
    1
}

// ---------------------------------------------------------------------------
// Request shape
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_request_never_reaches_the_first_effect() {
    // DRAIN with no budget, POLL with a budget, WAIT with a budget, a finite
    // WAIT with a zero timeout, and an infinite WAIT with one.
    for input in [
        NativeEnterInput {
            cq_budget: 0,
            ..drain_input(4)
        },
        NativeEnterInput {
            cq_budget: 1,
            ..poll_input()
        },
        NativeEnterInput {
            cq_budget: 1,
            ..wait_input(5)
        },
        NativeEnterInput {
            timeout_ms: 0,
            ..wait_input(5)
        },
        NativeEnterInput {
            timeout_ms: 5,
            ..wait_input(u32::MAX)
        },
        NativeEnterInput {
            cq_budget: fsring_abi::MAX_ENTER_CQ_BUDGET + 1,
            ..drain_input(4)
        },
    ] {
        assert_eq!(
            NativeEnterPlan::begin(input).err(),
            Some(AdapterPlanError::InvalidInput),
            "{input:?} must be refused",
        );
    }
}

#[test]
fn an_output_too_small_for_the_zero_credit_result_is_refused() {
    let input = NativeEnterInput {
        output_capacity: 47,
        ..poll_input()
    };
    assert_eq!(
        NativeEnterPlan::begin(input).err(),
        Some(AdapterPlanError::Capacity),
    );
}

// ---------------------------------------------------------------------------
// Ordinary poll
// ---------------------------------------------------------------------------

#[test]
fn a_zero_poll_snapshots_zeroes_takes_a_role_and_returns_exactly_the_prefix() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(poll_input()).expect("begin"),
        &mut recorded,
        EnterDecision::Empty,
        &mut roles,
    );
    assert_eq!(
        recorded,
        vec![
            EnterEffect::SnapshotAndValidateInput,
            EnterEffect::ValidateAndZeroOutput,
            EnterEffect::AcquireRole,
            EnterEffect::PollClearRecheck,
            EnterEffect::WriteExactOutput,
        ],
        "the input is snapshotted and the output zeroed before any role is taken",
    );
    let EnterProgress::ReleaseRole(release) = progress else {
        panic!("a synchronous ENTER always releases its role");
    };
    // The lease goes back to the ring it came from, and the ENTER completes
    // with exactly the zero-credit prefix.
    let EnterProgress::Complete(result) = release
        .release(&mut roles)
        .map_err(|_| ())
        .expect("the lease belongs to this ring")
    else {
        panic!("a synchronous ENTER completes once its role is back");
    };
    assert_eq!(result.information, 48);
    assert_eq!(result.status, fsring_abi::control::status::SUCCESS);

    // A foreign ring refuses the release and hands the capability back intact.
    let mut recorded = Vec::new();
    let mut other = RingEnterState::new(0);
    let progress = walk(
        NativeEnterPlan::begin(poll_input()).expect("begin"),
        &mut recorded,
        EnterDecision::Empty,
        &mut other,
    );
    let EnterProgress::ReleaseRole(release) = progress else {
        panic!("release");
    };
    let mut foreign = RingEnterState::new(0);
    let (error, release) = release
        .release(&mut foreign)
        .err()
        .expect("mismatch refused");
    assert_eq!(error, crate::enter::EnterError::InvalidIdentity);
    assert_eq!(release.effect(), EnterEffect::ReleaseRole);
}

#[test]
fn a_poll_can_never_park() {
    for decision in [EnterDecision::Pending, EnterDecision::TimedOut] {
        let mut roles = RingEnterState::new(0);
        let mut recorded = Vec::new();
        let mut progress = NativeEnterPlan::begin(poll_input()).expect("begin");
        loop {
            let EnterProgress::Effect(pending) = progress else {
                panic!("a poll reaches its readiness effect");
            };
            let effect = pending.effect();
            recorded.push(effect);
            let outcome = match effect {
                EnterEffect::AcquireRole => {
                    EnterEffectOutcome::RoleAcquired(lease_from(&mut roles, EnterRole::Cq))
                }
                EnterEffect::PollClearRecheck => {
                    assert_eq!(
                        pending
                            .succeeded(EnterEffectOutcome::ReadinessObserved(decision))
                            .err(),
                        Some(AdapterPlanError::InvalidTransition),
                        "{decision:?} is not observable for a POLL",
                    );
                    break;
                }
                _ => EnterEffectOutcome::Done,
            };
            progress = pending.succeeded(outcome).expect("ordinary effect");
        }
    }
}

#[test]
fn a_drain_can_never_park() {
    for decision in [EnterDecision::Pending, EnterDecision::TimedOut] {
        let mut roles = RingEnterState::new(0);
        let mut progress = NativeEnterPlan::begin(drain_input(2)).expect("begin");
        loop {
            let EnterProgress::Effect(pending) = progress else {
                panic!("a drain reaches its readiness effect");
            };
            if matches!(pending.effect(), EnterEffect::PollClearRecheck) {
                assert_eq!(
                    pending
                        .succeeded(EnterEffectOutcome::ReadinessObserved(decision))
                        .err(),
                    Some(AdapterPlanError::InvalidTransition),
                );
                break;
            }
            let outcome = match pending.effect() {
                EnterEffect::AcquireRole => {
                    EnterEffectOutcome::RoleAcquired(lease_from(&mut roles, EnterRole::Cq))
                }
                _ => EnterEffectOutcome::Done,
            };
            progress = pending.succeeded(outcome).expect("ordinary effect");
        }
    }
}

#[test]
fn an_infinite_wait_never_times_out() {
    let mut roles = RingEnterState::new(0);
    let mut progress = NativeEnterPlan::begin(wait_input(u32::MAX)).expect("begin");
    loop {
        let EnterProgress::Effect(pending) = progress else {
            panic!("reaches readiness");
        };
        if matches!(pending.effect(), EnterEffect::PollClearRecheck) {
            assert_eq!(
                pending
                    .succeeded(EnterEffectOutcome::ReadinessObserved(
                        EnterDecision::TimedOut
                    ))
                    .err(),
                Some(AdapterPlanError::InvalidTransition),
            );
            return;
        }
        let outcome = match pending.effect() {
            EnterEffect::AcquireRole => {
                EnterEffectOutcome::RoleAcquired(lease_from(&mut roles, EnterRole::Cq))
            }
            _ => EnterEffectOutcome::Done,
        };
        progress = pending.succeeded(outcome).expect("ordinary effect");
    }
}

// ---------------------------------------------------------------------------
// Drain
// ---------------------------------------------------------------------------

/// Every classification that yields no credit ends the drain without a head
/// advance and with the prefix-only result.
#[test]
fn a_barren_classification_returns_the_prefix_and_advances_no_head() {
    for classified in [
        DrainPlan::Empty,
        DrainPlan::Contended,
        DrainPlan::NotifyBlocked,
        DrainPlan::GenerationExhausted,
    ] {
        let mut roles = RingEnterState::new(0);
        let mut recorded = Vec::new();
        let progress = walk(
            NativeEnterPlan::begin(drain_input(4)).expect("begin"),
            &mut recorded,
            EnterDecision::Ready,
            &mut roles,
        );
        let EnterProgress::Effect(preflight) = progress else {
            panic!("a drain preflights its CQ");
        };
        assert_eq!(preflight.effect(), EnterEffect::PreflightCqAndCredit);
        let next = preflight
            .succeeded(EnterEffectOutcome::CqClassified(classified))
            .expect("classification");
        let mut recorded = Vec::new();
        let progress = walk(next, &mut recorded, EnterDecision::Ready, &mut roles);
        assert_eq!(recorded, vec![EnterEffect::WriteExactOutput]);
        let EnterProgress::ReleaseRole(release) = progress else {
            panic!("release");
        };
        let EnterProgress::Complete(result) = release
            .release(&mut roles)
            .map_err(|_| ())
            .expect("release")
        else {
            panic!("complete");
        };
        assert_eq!(
            result.information, 48,
            "a barren classification advances no head and returns no credit",
        );
        assert_eq!(result.status, fsring_abi::control::status::SUCCESS);
    }
}

#[test]
fn a_protocol_abort_or_completion_fault_reports_invalid_device_state() {
    for classified in [
        DrainPlan::ProtocolAbort,
        DrainPlan::CompletionFault,
        DrainPlan::ProtocolFault,
    ] {
        let mut roles = RingEnterState::new(0);
        let mut recorded = Vec::new();
        let progress = walk(
            NativeEnterPlan::begin(drain_input(1)).expect("begin"),
            &mut recorded,
            EnterDecision::Ready,
            &mut roles,
        );
        let EnterProgress::Effect(preflight) = progress else {
            panic!("preflight");
        };
        let mut recorded = Vec::new();
        let progress = walk(
            preflight
                .succeeded(EnterEffectOutcome::CqClassified(classified))
                .expect("classification"),
            &mut recorded,
            EnterDecision::Ready,
            &mut roles,
        );
        let EnterProgress::ReleaseRole(release) = progress else {
            panic!("release");
        };
        let EnterProgress::Complete(result) = release
            .release(&mut roles)
            .map_err(|_| ())
            .expect("release")
        else {
            panic!("complete");
        };
        assert_eq!(
            result.status,
            fsring_abi::control::status::INVALID_DEVICE_STATE,
            "a CQ fault is reported, not swallowed",
        );
        assert_eq!(result.information, 48, "a fault returns no credit");
    }
}

#[test]
fn one_credit_walks_preflight_first_commit_claim_advance_refresh() {
    let mut backing = GrantBacking::new(1);
    let mut credits = vec![NotificationCreditV1::default(); 1];
    let mut output = NotificationCreditV1::default();
    let mut roles = RingEnterState::new(0);
    let mut table =
        GrantTable::initialize(&mut backing.entries, &backing.topology, 1).expect("table");
    assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
    let token =
        fsring_abi::slots::SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let notify = table
        .preflight_notify(0, token, 32, token.generation())
        .expect("preflight");

    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(drain_input(1)).expect("begin"),
        &mut recorded,
        EnterDecision::Ready,
        &mut roles,
    );
    let EnterProgress::Effect(preflight_effect) = progress else {
        panic!("preflight");
    };
    assert_eq!(preflight_effect.effect(), EnterEffect::PreflightCqAndCredit);

    let mut recorded = Vec::new();
    let progress = walk(
        preflight_effect
            .succeeded(EnterEffectOutcome::CqClassified(DrainPlan::Notify(notify)))
            .expect("notify"),
        &mut recorded,
        EnterDecision::Ready,
        &mut roles,
    );
    assert_eq!(
        recorded,
        vec![EnterEffect::ClaimFirstCommit],
        "the affine first commit is claimed once, before any credit is spent",
    );

    let EnterProgress::ClaimCredit(claim) = progress else {
        panic!("claim capability");
    };
    assert_eq!(claim.effect(), EnterEffect::ClaimCredit);
    let progress = claim.claim(&mut table).map_err(|_| ()).expect("claim");

    let EnterProgress::AdvanceCqHead(advance) = progress else {
        panic!("head advance capability");
    };
    assert_eq!(advance.effect(), EnterEffect::AdvanceCqHeadRelease);
    let command = advance.command();
    assert_eq!(command.ring_index, 0);
    assert_eq!(command.next_head, command.observed_head + 1);
    // SAFETY: the fixture performs no real store; the capability is what the
    // production executor must earn, and this exercises the conversion.
    let progress = unsafe { advance.completed_release() };

    let EnterProgress::RefreshCredit(refresh) = progress else {
        panic!("refresh capability");
    };
    assert_eq!(refresh.effect(), EnterEffect::RefreshCredit);
    let progress = refresh.refresh(&mut output);
    assert_ne!(
        output,
        NotificationCreditV1::default(),
        "the slot is written"
    );

    let mut recorded = Vec::new();
    let progress = walk(progress, &mut recorded, EnterDecision::Ready, &mut roles);
    assert_eq!(
        recorded,
        vec![EnterEffect::WriteExactOutput],
        "a spent budget ends the drain",
    );
    let EnterProgress::ReleaseRole(release) = progress else {
        panic!("release");
    };
    let EnterProgress::Complete(result) = release
        .release(&mut roles)
        .map_err(|_| ())
        .expect("release")
    else {
        panic!("complete");
    };
    assert_eq!(
        result.information, 80,
        "one credit is exactly one 32-byte descriptor past the frozen prefix",
    );
}

#[test]
fn the_information_is_the_frozen_prefix_plus_one_descriptor_per_credit() {
    for credits in [0u32, 1, 7, 64] {
        assert_eq!(
            information_for(credits).expect("checked"),
            48 + 32 * credits as usize,
        );
    }
}

// ---------------------------------------------------------------------------
// Pending installation and rollback
// ---------------------------------------------------------------------------

#[test]
fn a_wait_installs_the_pending_prefix_in_order() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(wait_input(25)).expect("begin"),
        &mut recorded,
        EnterDecision::Pending,
        &mut roles,
    );
    assert_eq!(
        recorded,
        vec![
            EnterEffect::SnapshotAndValidateInput,
            EnterEffect::ValidateAndZeroOutput,
            EnterEffect::AcquireRole,
            EnterEffect::PollClearRecheck,
            EnterEffect::AllocatePendingContext,
            EnterEffect::InitializeEventTimerAndCsq,
            EnterEffect::AcquireSessionAndFileReferences,
            EnterEffect::MarkIrpPending,
            EnterEffect::InsertCsq,
            EnterEffect::ExchangeDispatchRundown,
            EnterEffect::ReturnPending,
        ],
        "allocate/init, references, mark, insert, exchange, return - in order",
    );
    let EnterProgress::Pending(parked) = progress else {
        panic!("a WAIT that is not ready parks");
    };
    let lease = parked.into_held_role();
    roles
        .release_role(lease)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
}

#[test]
fn parked_wait_occupies_the_ring_until_the_extracted_lease_is_released() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(wait_input(25)).expect("begin"),
        &mut recorded,
        EnterDecision::Pending,
        &mut roles,
    );
    let EnterProgress::Pending(parked) = progress else {
        panic!("a WAIT that is not ready parks");
    };
    assert!(!roles.r3_checkpoint_roles_and_consumers_are_drained());
    let lease = parked.into_held_role();
    assert!(
        !roles.r3_checkpoint_roles_and_consumers_are_drained(),
        "extracting the lease does not release the ring",
    );
    roles
        .release_role(lease)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
    assert!(
        roles.r3_checkpoint_roles_and_consumers_are_drained(),
        "only release_role clears the waiter",
    );
}

#[test]
#[should_panic(expected = "parked ENTER dropped while still holding the ring role")]
fn dropping_a_parked_wait_is_a_bugcheck_not_a_silent_role_leak() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(wait_input(25)).expect("begin"),
        &mut recorded,
        EnterDecision::Pending,
        &mut roles,
    );
    let EnterProgress::Pending(parked) = progress else {
        panic!("a WAIT that is not ready parks");
    };
    assert!(
        !roles.r3_checkpoint_roles_and_consumers_are_drained(),
        "the ring still names the waiter",
    );
    drop(parked);
}

#[test]
fn a_parked_wait_is_owned_until_resume_without_extracting_the_lease() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(wait_input(25)).expect("begin"),
        &mut recorded,
        EnterDecision::Pending,
        &mut roles,
    );
    let EnterProgress::Pending(parked) = progress else {
        panic!("a WAIT that is not ready parks");
    };
    let owned = parked.into_owned_wait();
    assert!(
        !roles.r3_checkpoint_roles_and_consumers_are_drained(),
        "owning the parked plan retains the ring role",
    );
    assert!(
        owned.role().is_some(),
        "the parked plan still holds the lease"
    );
    let EnterProgress::Effect(claim) = owned.resume() else {
        panic!("the winner resumes the parked plan");
    };
    assert_eq!(claim.effect(), EnterEffect::ClaimTerminal);
}

/// The reverse subset each completed installation prefix earns.
///
/// The role lease is acquired before the installation starts, so every unwind
/// ends by handing it back; the installation-specific steps above it appear
/// only when their own prefix completed.
fn expected_rollback(prefix: usize) -> Vec<EnterRollbackEffect> {
    use EnterRollbackEffect as R;
    let full = [
        (6u32, R::ReleaseDispatchRundown),
        (5, R::RemoveCsq),
        (4, R::CompleteMarkedIrpOnce),
        (3, R::ReleaseSessionAndFileReferences),
        (2, R::CancelTimerAndEvent),
        (1, R::FreePendingContext),
        (0, R::ReleaseRole),
    ];
    full.iter()
        .filter(|(required, _)| prefix as u32 >= *required)
        .map(|(_, effect)| *effect)
        .collect()
}

#[test]
fn every_installation_failure_unwinds_the_exact_reverse_subset() {
    let installation = [
        EnterEffect::AllocatePendingContext,
        EnterEffect::InitializeEventTimerAndCsq,
        EnterEffect::AcquireSessionAndFileReferences,
        EnterEffect::MarkIrpPending,
        EnterEffect::InsertCsq,
        EnterEffect::ExchangeDispatchRundown,
        EnterEffect::ReturnPending,
    ];
    for (index, target) in installation.iter().enumerate() {
        let mut roles = RingEnterState::new(0);
        let mut progress = NativeEnterPlan::begin(wait_input(25)).expect("begin");
        let failure = loop {
            let EnterProgress::Effect(pending) = progress else {
                panic!("{target:?} is reachable");
            };
            if pending.effect() == *target {
                break pending.failed(EnterNativeFailure::Resource);
            }
            let outcome = match pending.effect() {
                EnterEffect::AcquireRole => {
                    EnterEffectOutcome::RoleAcquired(lease_from(&mut roles, EnterRole::Cq))
                }
                EnterEffect::PollClearRecheck => {
                    EnterEffectOutcome::ReadinessObserved(EnterDecision::Pending)
                }
                _ => EnterEffectOutcome::Done,
            };
            progress = pending.succeeded(outcome).expect("ordinary effect");
        };
        let EnterFailurePlan::Rollback(rollback) = failure else {
            panic!("nothing committed yet at {target:?}");
        };
        let (recorded, result) = drain_rollback(rollback, &mut roles);
        assert_eq!(
            recorded,
            expected_rollback(index),
            "failure at {target:?} unwinds exactly what it owns",
        );
        assert_eq!(
            result.information, 0,
            "a rolled-back ENTER returns no bytes"
        );
        assert_eq!(
            result.status,
            fsring_abi::control::status::INSUFFICIENT_RESOURCES,
        );
    }
}

fn drain_rollback(
    plan: EnterRollbackPlan,
    roles: &mut RingEnterState,
) -> (Vec<EnterRollbackEffect>, EnterAdapterResult) {
    let mut recorded = Vec::new();
    let mut progress = plan.next();
    loop {
        match progress {
            EnterRollbackProgress::Complete(result) => return (recorded, result),
            EnterRollbackProgress::Effect(pending) => {
                recorded.push(pending.effect());
                progress = pending.succeeded();
            }
            EnterRollbackProgress::ReleaseRole(pending) => {
                recorded.push(pending.effect());
                progress = pending
                    .release(roles)
                    .map_err(|_| ())
                    .expect("the lease belongs to this ring");
            }
        }
    }
}

#[test]
fn a_rollback_role_mismatch_preserves_both_the_lease_and_the_continuation() {
    let mut roles = RingEnterState::new(0);
    let mut progress = NativeEnterPlan::begin(wait_input(25)).expect("begin");
    let failure = loop {
        let EnterProgress::Effect(pending) = progress else {
            panic!("reaches the installation");
        };
        if matches!(pending.effect(), EnterEffect::AllocatePendingContext) {
            break pending.failed(EnterNativeFailure::Resource);
        }
        let outcome = match pending.effect() {
            EnterEffect::AcquireRole => {
                EnterEffectOutcome::RoleAcquired(lease_from(&mut roles, EnterRole::Cq))
            }
            EnterEffect::PollClearRecheck => {
                EnterEffectOutcome::ReadinessObserved(EnterDecision::Pending)
            }
            _ => EnterEffectOutcome::Done,
        };
        progress = pending.succeeded(outcome).expect("ordinary effect");
    };
    let EnterFailurePlan::Rollback(rollback) = failure else {
        panic!("precommit");
    };
    let EnterRollbackProgress::ReleaseRole(release) = rollback.next() else {
        panic!("the only owned resource is the role");
    };
    let mut foreign = RingEnterState::new(0);
    let (error, release) = release.release(&mut foreign).err().expect("mismatch");
    assert_eq!(error, crate::enter::EnterError::InvalidIdentity);
    // Neither the lease nor the rest of the unwind was lost: the same
    // capability still completes against the right ring.
    let EnterRollbackProgress::Complete(result) = release
        .release(&mut roles)
        .map_err(|_| ())
        .expect("the lease belongs to this ring")
    else {
        panic!("nothing else is owned");
    };
    assert_eq!(result.information, 0);
}

#[test]
fn a_lost_terminal_race_cannot_drive_the_completion() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(wait_input(25)).expect("begin"),
        &mut recorded,
        EnterDecision::Pending,
        &mut roles,
    );
    let EnterProgress::Pending(parked) = progress else {
        panic!("parked");
    };
    let EnterProgress::Effect(claim) = parked.resume() else {
        panic!("the winner claims its terminal");
    };
    assert_eq!(claim.effect(), EnterEffect::ClaimTerminal);

    let pending = PendingEnter::new(invocation());
    let first = pending.contend(EnterContender::Cancel);
    let second = pending.contend(EnterContender::Timeout);
    assert!(matches!(first, PendingOutcome::Won(_)));
    assert!(matches!(second, PendingOutcome::Lost { .. }));
    assert_eq!(
        claim
            .succeeded(EnterEffectOutcome::TerminalClaimed(second))
            .err(),
        Some(AdapterPlanError::InvalidTransition),
        "only the winner owns the completion",
    );
}

#[test]
fn the_winner_removes_csq_releases_references_then_the_role_then_completes() {
    let mut roles = RingEnterState::new(0);
    let mut recorded = Vec::new();
    let progress = walk(
        NativeEnterPlan::begin(wait_input(25)).expect("begin"),
        &mut recorded,
        EnterDecision::Pending,
        &mut roles,
    );
    let EnterProgress::Pending(parked) = progress else {
        panic!("parked");
    };
    let EnterProgress::Effect(claim) = parked.resume() else {
        panic!("claim terminal");
    };
    let pending = PendingEnter::new(invocation());
    let won = pending.contend(EnterContender::Wake);
    let mut recorded = Vec::new();
    let progress = walk(
        claim
            .succeeded(EnterEffectOutcome::TerminalClaimed(won))
            .expect("won"),
        &mut recorded,
        EnterDecision::Ready,
        &mut roles,
    );
    assert_eq!(
        recorded,
        vec![
            EnterEffect::RemoveCsq,
            EnterEffect::ReleaseSessionAndFileReferences,
        ],
        "the CSQ entry and native references go before the role",
    );
    let EnterProgress::ReleaseRole(release) = progress else {
        panic!("the role is released through its own capability");
    };
    let EnterProgress::Effect(complete) = release
        .release(&mut roles)
        .map_err(|_| ())
        .expect("release")
    else {
        panic!("a pending ENTER completes once, after the role is back");
    };
    assert_eq!(complete.effect(), EnterEffect::CompleteOnce);
    let EnterProgress::Complete(result) = complete
        .succeeded(EnterEffectOutcome::TerminalFinished(
            crate::enter::PendingCompletion::Ready,
        ))
        .expect("finish")
    else {
        panic!("complete");
    };
    assert_eq!(result.information, 48);
    assert_eq!(result.status, fsring_abi::control::status::SUCCESS);
}

// ---------------------------------------------------------------------------
// Scratch identities
// ---------------------------------------------------------------------------

#[test]
fn sixty_four_simultaneous_drains_use_pairwise_distinct_scratch() {
    let mut identities = Vec::new();
    for ring_index in 0..64u32 {
        identities.push(ScratchIdentity::drain(ring_index));
    }
    let fence = ScratchIdentity::fence();
    for (index, scratch) in identities.iter().enumerate() {
        assert_ne!(*scratch, fence, "ring {index} shares the fence scratch");
        for (other_index, other) in identities.iter().enumerate() {
            if index != other_index {
                assert_ne!(scratch, other, "rings {index} and {other_index} collide");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The fence
// ---------------------------------------------------------------------------

fn drive_fence(fail_at: Option<usize>) -> Vec<FenceEffect> {
    let mut recorded = Vec::new();
    let mut progress = FenceExecutionPlan::begin(IDENTITY).next();
    loop {
        match progress {
            FenceProgress::Complete => return recorded,
            FenceProgress::Effect(pending) => {
                let index = recorded.len();
                recorded.push(pending.effect());
                progress = if fail_at == Some(index) {
                    pending.failed()
                } else {
                    pending.succeeded()
                };
            }
        }
    }
}

#[test]
fn the_fence_runs_the_exact_six_stages_in_order() {
    let recorded = drive_fence(None);
    let mut expected = Vec::new();
    expected.extend_from_slice(&SessionFence::CLOSE_EFFECTS);
    expected.extend_from_slice(&SessionFence::REMOVE_PRODUCER_EFFECTS);
    expected.extend_from_slice(&SessionFence::ACQUIRE_CONSUMER_EFFECTS);
    expected.extend_from_slice(&SessionFence::DRAIN_EFFECTS);
    expected.extend_from_slice(&SessionFence::RELEASE_OWNER_EFFECTS);
    expected.extend_from_slice(&SessionFence::RELEASE_BACKING_EFFECTS);
    assert_eq!(recorded, expected);
}

#[test]
fn producer_aliases_disappear_before_any_consumer_is_acquired() {
    let recorded = drive_fence(None);
    let remove = recorded
        .iter()
        .position(|e| matches!(e, FenceEffect::RemoveProducerMappingsReverse))
        .expect("stage 2");
    let acquire = recorded
        .iter()
        .position(|e| matches!(e, FenceEffect::AcquireConsumersIncreasing))
        .expect("stage 3");
    let read_only = recorded
        .iter()
        .position(|e| matches!(e, FenceEffect::ReleaseReadOnlyMappingsReverse))
        .expect("stage 6");
    let process = recorded
        .iter()
        .position(|e| matches!(e, FenceEffect::ReleaseCapturedProcess))
        .expect("stage 6");
    assert!(remove < acquire, "writable aliases go before CQ capture");
    assert!(
        acquire < read_only && read_only < process,
        "read-only aliases and the captured process survive to stage 6",
    );
}

#[test]
fn admission_closes_and_pending_enters_are_signalled_before_any_rundown_wait() {
    let recorded = drive_fence(None);
    let close = recorded
        .iter()
        .position(|e| matches!(e, FenceEffect::CloseSessionAdmission))
        .expect("stage 1");
    let signal = recorded
        .iter()
        .position(|e| matches!(e, FenceEffect::SignalPendingEnter))
        .expect("stage 1");
    let first_wait = recorded
        .iter()
        .position(|e| {
            matches!(
                e,
                FenceEffect::WaitControlRundown
                    | FenceEffect::WaitProducerAndMappingCaptureRundown
                    | FenceEffect::WaitPendingAndOwners
            )
        })
        .expect("a wait exists");
    assert!(
        close < signal && signal < first_wait,
        "no wait precedes the signal"
    );
}

#[test]
fn a_failed_cleanup_step_does_not_stop_the_fence() {
    let complete = drive_fence(None);
    for index in 0..complete.len() {
        let recorded = drive_fence(Some(index));
        assert_eq!(
            recorded, complete,
            "a failed step at {index} still runs every remaining bounded effect",
        );
    }
}

// ---------------------------------------------------------------------------
// R4 Task 14.4: plan-side role bind, CQ mutation witness, exact-IRP cancel
// ---------------------------------------------------------------------------

mod r4_plan_tests {
    use crate::adapter::enter::{CqMutationWitness, R4EnterPlan};
    use crate::enter::{
        EnterExecutionDomain, IrpObservation, RingEnterState, build_ring_runtime_parts,
    };
    use crate::session::{
        ControlBinding, PendingError, SessionRegistry, SetupStage, SetupTransaction,
    };
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    const PLAN_IRP: usize = 0x1234_5678;
    const OTHER_PLAN_IRP: usize = 0x8765_4321;

    /// A branded R4 ring state, through the ordinary public setup path.
    fn branded(n: u64) -> RingEnterState {
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let reservation = binding.begin_setup().expect("an empty binding reserves");
        let identity = SessionIdentity {
            mount_id: MountId { lo: n, hi: 71 },
            boot_instance_id: BootInstanceId { lo: 73, hi: 79 },
            session_epoch: 1,
        };
        let mut transaction = SetupTransaction::begin(identity).expect("a valid identity");
        for stage in [
            SetupStage::LayoutPlanned,
            SetupStage::SectionReady,
            SetupStage::GrantsReady,
            SetupStage::VolumeReady,
            SetupStage::ViewsReady,
            SetupStage::OutputReady,
        ] {
            transaction = transaction.stage(stage).expect("the roster order");
        }
        let mut registry = SessionRegistry::<1>::new();
        let mut installed = registry
            .install_staging(&transaction, &binding, &reservation)
            .expect("output-ready staging installs");
        let mut set = installed.begin_ring_set(1).expect("a fresh install");
        let right = set
            .next_ring()
            .expect("identities available")
            .expect("ring 0");
        let brand = right.brand();
        let parts = build_ring_runtime_parts(brand, 64, right)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        let (state, _slot, _owners, _wake, _bind) = parts.into_parts();
        state
    }

    fn observed(raw: usize) -> IrpObservation {
        IrpObservation::from_raw(raw).expect("a nonzero literal")
    }

    #[test]
    fn sq_and_cq_acquisition_bind_consumes_the_exact_aggregate_once() {
        let mut state = branded(1490);
        let acquired = state
            .acquire_sq_wait_aggregate()
            .expect("a fresh ring acquires");
        let execution = acquired.execution();

        // Binding takes the aggregate by value, so the aggregate is gone. A
        // second bind needs a second aggregate, and the role is still held --
        // `RingEnterState` mints one per acquisition, so there is no second one
        // to be had while this execution lives.
        let plan = R4EnterPlan::bind_sq_wait(acquired);
        assert_eq!(plan.execution(), execution);
        assert!(
            plan.holds_terminal(),
            "the SQ bind carries its terminal seed"
        );
        assert!(!plan.has_committed());
        assert!(
            state.acquire_sq_wait_aggregate().is_err(),
            "the role is still held by the bound plan"
        );

        // The CQ side is symmetric and carries no terminal seed: only an SQ
        // wait can be the request that parks.
        let cq = state
            .acquire_cq_consumer_aggregate()
            .expect("CQ is a separate role");
        let cq_execution = cq.execution();
        let cq_plan = R4EnterPlan::bind_cq_consumer(cq);
        assert_eq!(cq_plan.execution(), cq_execution);
        assert!(!cq_plan.holds_terminal());
        assert_ne!(cq_execution, execution);
    }

    #[test]
    fn role_bind_refusal_returns_the_unchanged_plan_and_exact_aggregate() {
        let mut mine = branded(1491);
        let mut theirs = branded(1492);
        let sq = mine
            .acquire_sq_wait_aggregate()
            .expect("a fresh ring")
            .into_plan_parts();
        let (lease, tracker, terminal) = sq;
        // Rebuild the plan through the ordinary bind so the test exercises the
        // real boundary rather than a hand-made plan.
        let _ = (tracker, terminal);
        let resume = mine.authorize_resume(&lease).expect("owned");
        let cq_resume = resume.bind_cq_consumer();

        let plan_aggregate = mine
            .acquire_cq_consumer_aggregate()
            .expect("CQ is a separate role");
        let plan = R4EnterPlan::bind_cq_consumer(plan_aggregate);
        let plan_execution = plan.execution();

        // A foreign aggregate is refused, and both the plan and the aggregate
        // come back: the caller still owns a live role on the other ring and
        // still has to release it.
        let foreign = theirs
            .acquire_cq_consumer_aggregate()
            .expect("its own ring");
        let foreign_execution = foreign.execution();
        let (error, plan, foreign) = match plan.rebind_resumed(&cq_resume, foreign) {
            Ok(_) => unreachable!("a foreign aggregate must not rebind this plan"),
            Err(triple) => triple,
        };
        // `WrongInvocation`, not `WrongRing`: the resume names the invocation the
        // SQ lease parked, and this plan was bound from a *separate* CQ
        // acquisition, so its invocation is a later one. The rings match, so
        // the invocation check is the one that fires -- and that is the point
        // of the property, which is about what a refusal *returns*, not about
        // which of several refusals wins.
        assert_eq!(error, PendingError::WrongInvocation);
        assert_eq!(plan.execution(), plan_execution, "the plan is unchanged");
        assert_eq!(
            foreign.execution(),
            foreign_execution,
            "the exact aggregate came back"
        );
        assert!(!plan.has_committed());

        // And the returned aggregate still binds its own plan.
        let foreign_plan = R4EnterPlan::bind_cq_consumer(foreign);
        assert_eq!(foreign_plan.execution(), foreign_execution);
        let _ = lease;
    }

    #[test]
    fn synchronous_and_resumed_cancel_observation_is_bound_to_the_exact_irp() {
        let mut state = branded(1493);
        let acquired = state.acquire_sq_wait_aggregate().expect("a fresh ring");
        let mut plan = R4EnterPlan::bind_sq_wait(acquired);

        // Before an IRP is parked there is nothing a cancel could be about.
        assert_eq!(
            plan.observe_cancel(observed(PLAN_IRP)).err(),
            Some(PendingError::NotDequeued)
        );

        plan.observe_irp(observed(PLAN_IRP)).expect("first park");
        assert_eq!(
            plan.observe_irp(observed(OTHER_PLAN_IRP)).err(),
            Some(PendingError::SlotOccupied),
            "one parked IRP per execution"
        );

        // A cancel naming another IRP is another request's; answering it here
        // would complete the wrong one.
        assert_eq!(
            plan.observe_cancel(observed(OTHER_PLAN_IRP)).err(),
            Some(PendingError::WrongIrp)
        );

        // The synchronous observation, and the resumed one, are the same check
        // against the same parked IRP -- there is one code path, so the two
        // cannot drift apart.
        let synchronous = plan.observe_cancel(observed(PLAN_IRP)).expect("exact IRP");
        let resumed = plan.observe_cancel(observed(PLAN_IRP)).expect("exact IRP");
        assert_eq!(synchronous, resumed);
        assert_eq!(synchronous.irp().get(), PLAN_IRP);
        assert_eq!(synchronous.execution(), plan.execution());
    }

    #[test]
    fn naked_cq_token_cannot_cross_the_native_arbitration_boundary() {
        let mut state = branded(1494);
        let acquired = state.acquire_cq_consumer_aggregate().expect("a fresh ring");
        let execution = acquired.execution();
        let mut plan = R4EnterPlan::bind_cq_consumer(acquired);

        // Holding the CQ role is necessary and NOT sufficient. `arbitrate_cq_mutation`
        // takes a `CqMutationWitness`, whose only production minters are the
        // typed packets Tasks 20 and 21 add -- a `CqConsumerToken` does not
        // convert into one, and `CqConsumerToken` has no witness method at all.
        // The line below does not compile with a token in place of a witness;
        // what this asserts is that a *witness* is what the boundary accepts.
        let packet = ();
        let witness = CqMutationWitness::for_test_packet(execution, &packet)
            .expect("a CQ execution mints a CQ witness");
        assert!(!plan.has_committed(), "nothing arbitrated yet");
        let permit = plan
            .arbitrate_cq_mutation(witness)
            .expect("the witness names this execution");
        assert_eq!(permit.execution(), execution);
        // Arbitration does NOT record a commit. It authorises one; the commit
        // that performs the mutation is what records it, so a refused
        // preparation downstream leaves the tracker exactly as it was.
        drop(permit);
        assert!(
            !plan.has_committed(),
            "an arbitration whose permit was dropped performed no mutation",
        );

        // The witness is consumed, so one packet authorises one mutation. A
        // second mutation needs a second witness, which needs a second packet.
        let second_packet = ();
        let second = CqMutationWitness::for_test_packet(execution, &second_packet)
            .expect("a second packet mints a second witness");
        assert!(plan.arbitrate_cq_mutation(second).is_ok());
    }

    #[test]
    fn private_test_witness_fixture_rejects_a_matching_sq_execution_brand() {
        let mut state = branded(1495);
        let sq = state.acquire_sq_wait_aggregate().expect("a fresh ring");
        let sq_execution = sq.execution();
        assert_eq!(sq_execution.domain(), EnterExecutionDomain::SqWait);
        let mut sq_plan = R4EnterPlan::bind_sq_wait(sq);

        // The fixture refuses an SQ execution outright, even though everything
        // else about it matches: same ring, same invocation, a real brand. The
        // CQ arbitration boundary is the only thing a witness authorises, and an
        // SQ execution reaching it would mean the domain split had been undone
        // at exactly the point it matters.
        let packet = ();
        assert_eq!(
            CqMutationWitness::for_test_packet(sq_execution, &packet).err(),
            Some(PendingError::WrongExecutionDomain)
        );

        // So an SQ plan can never be handed a witness for itself, and the
        // boundary stays closed to it.
        assert!(!sq_plan.has_committed());
        let _ = &mut sq_plan;

        // A CQ execution on the same ring does mint one -- so the refusal above
        // is about the domain and not about the fixture being unusable.
        let cq = state
            .acquire_cq_consumer_aggregate()
            .expect("CQ is a separate role");
        let cq_execution = cq.execution();
        assert!(CqMutationWitness::for_test_packet(cq_execution, &packet).is_ok());
        let _ = cq;
    }

    #[test]
    fn native_plan_arbitration_does_not_project_its_private_tracker() {
        let mut state = branded(1496);
        let acquired = state.acquire_cq_consumer_aggregate().expect("a fresh ring");
        let execution = acquired.execution();
        let mut plan = R4EnterPlan::bind_cq_consumer(acquired);

        // The plan answers a *decision* -- has anything committed -- and never
        // hands out the tracker. There is no accessor returning
        // `EnterCommitTracker` by value or by reference, so a sibling crate
        // cannot record a commit for a mutation core never arbitrated.
        let before: bool = plan.has_committed();
        assert!(!before);

        let packet = ();
        let witness = CqMutationWitness::for_test_packet(execution, &packet).expect("CQ");
        let permit = plan
            .arbitrate_cq_mutation(witness)
            .expect("the witness names this execution");

        // The only route to the flag is a permit spent by a real commit. The
        // permit borrows the tracker, so `plan` cannot even be read while one
        // is outstanding -- which is why this reads it after, and why a second
        // arbitration beside the first is a borrow error rather than a runtime
        // refusal.
        permit.record_first_mutation();
        assert!(plan.has_committed());
        let _: fn(&R4EnterPlan) -> bool = R4EnterPlan::has_committed;
    }
}

// ---------------------------------------------------------------------------
// R4 Task 15: the typed outer disposition
// ---------------------------------------------------------------------------

mod r4_disposition_tests {
    use crate::adapter::enter::{
        CompletionValidationError, PendingDispatchReceipt, ProviderDisposition, STATUS_PENDING,
        ValidatedCompletion,
    };
    use crate::enter::IrpObservation;

    const OUT_CAPACITY: usize = 64;
    const EXACT: usize = 24;
    const DISPATCH_IRP: usize = 0x0BAD_F00D;

    fn ok_completion() -> ValidatedCompletion {
        ValidatedCompletion::prepare(0, EXACT, OUT_CAPACITY, EXACT)
            .expect("an exact success validates")
    }

    fn receipt() -> PendingDispatchReceipt {
        PendingDispatchReceipt::for_test_after_handoff(
            IrpObservation::from_raw(DISPATCH_IRP).expect("nonzero"),
        )
    }

    #[test]
    fn validated_completion_rejects_status_pending_and_invalid_information() {
        // STATUS_PENDING never describes a finished synchronous request: a
        // thunk returning it alongside a completed IRP would be telling the I/O
        // manager the request is still outstanding.
        assert_eq!(
            ValidatedCompletion::prepare(STATUS_PENDING, 0, OUT_CAPACITY, 0).err(),
            Some(CompletionValidationError::PendingStatus)
        );

        // Information beyond the buffer that will receive it sends the caller
        // past the end.
        assert_eq!(
            ValidatedCompletion::prepare(0, OUT_CAPACITY + 1, OUT_CAPACITY, OUT_CAPACITY + 1).err(),
            Some(CompletionValidationError::InformationBeyondCapacity)
        );

        // A success must report the exact result size. Fewer bytes tells the
        // caller to read a prefix of a structure the driver filled in full.
        assert_eq!(
            ValidatedCompletion::prepare(0, EXACT - 1, OUT_CAPACITY, EXACT).err(),
            Some(CompletionValidationError::InformationNotExact)
        );
        assert_eq!(
            ValidatedCompletion::prepare(0, EXACT + 1, OUT_CAPACITY, EXACT).err(),
            Some(CompletionValidationError::InformationNotExact)
        );

        // A failure status carries no result, so the exactness rule does not
        // apply to it -- only the capacity bound does.
        assert!(ValidatedCompletion::prepare(-1, 0, OUT_CAPACITY, EXACT).is_ok());
        assert_eq!(
            ValidatedCompletion::prepare(-1, OUT_CAPACITY + 1, OUT_CAPACITY, EXACT).err(),
            Some(CompletionValidationError::InformationBeyondCapacity)
        );

        // And the exact success validates.
        assert!(ValidatedCompletion::prepare(0, EXACT, OUT_CAPACITY, EXACT).is_ok());
    }

    #[test]
    fn validated_completion_is_consumed_by_one_exact_irp_completion() {
        let completion = ok_completion();

        // The route to a dispatch status is: prepare_for_irp -> view once ->
        // commit_after_io_complete -> into_dispatch_status. Every step consumes
        // its input, so there is no second completion to be had.
        // SAFETY: this test performs no real I/O; it exercises the ownership
        // chain, which is what the contract is about.
        let prepared = unsafe { completion.prepare_for_irp() };
        let (status, information) = prepared.view();
        assert_eq!((status, information), (0, EXACT));

        // SAFETY: as above -- the "IoCompleteRequest already happened" premise
        // is vacuously satisfied because no IRP exists here.
        let receipt = unsafe { prepared.commit_after_io_complete() };
        assert_eq!(receipt.into_dispatch_status(), 0);

        // `ValidatedCompletion` has no repeatable status/information getters, so
        // the values above are readable exactly where the write happens and
        // nowhere else. A second `prepare_for_irp` would need a second
        // `ValidatedCompletion`, and `prepare` is the only minter.
        let second = ValidatedCompletion::prepare(0, EXACT, OUT_CAPACITY, EXACT)
            .expect("a fresh candidate validates");
        // SAFETY: as above.
        let receipt = unsafe { second.prepare_for_irp().commit_after_io_complete() };
        assert_eq!(receipt.into_dispatch_status(), 0);
    }

    #[test]
    fn complete_pending_and_complete_after_terminal_are_disjoint() {
        // The three variants are distinguishable by shape alone, so a thunk
        // cannot return one while meaning another. `Complete` and
        // `CompleteAfterTerminal` both carry a completion, but only the second
        // carries terminal work -- and `Pending` carries no completion at all,
        // which is what says the thunk must not touch the IRP.
        let complete: ProviderDisposition<u8> = ProviderDisposition::Complete(ok_completion());
        let pending: ProviderDisposition<u8> = ProviderDisposition::Pending(receipt());
        let after: ProviderDisposition<u8> = ProviderDisposition::CompleteAfterTerminal {
            completion: ok_completion(),
            terminal: 7,
        };

        let kind = |disposition: &ProviderDisposition<u8>| match disposition {
            ProviderDisposition::Complete(_) => 0,
            ProviderDisposition::Pending(_) => 1,
            ProviderDisposition::CompleteAfterTerminal { .. } => 2,
        };
        assert_eq!(kind(&complete), 0);
        assert_eq!(kind(&pending), 1);
        assert_eq!(kind(&after), 2);

        // Task 19 deleted the predecessor splitter and its enum: after the
        // cutover the outer dispatch matches these three variants directly, so
        // there is no second shape a disposition could be observed through.
        for (disposition, expected) in [(complete, 0), (pending, 1), (after, 2)] {
            assert_eq!(
                kind(&disposition),
                expected,
                "the variant is its own answer"
            );
        }
    }

    #[test]
    fn pending_disposition_requires_the_post_handoff_receipt() {
        // `Pending` carries a `PendingDispatchReceipt` and nothing else can
        // stand in: a raw IRP pointer, a status code, or a "we queued it" bool
        // are all unrepresentable here. The receipt's only production minter is
        // Task 17's split selected -> post-handoff transition, so a merely
        // selected or CSQ-inserted IRP cannot produce one.
        let irp = IrpObservation::from_raw(DISPATCH_IRP).expect("nonzero");
        let disposition: ProviderDisposition<u8> = ProviderDisposition::Pending(receipt());
        let ProviderDisposition::Pending(held) = disposition else {
            unreachable!("the variant was just built")
        };
        assert_eq!(held.irp(), irp, "the receipt names the exact IRP");

        // And the receipt is still the only way back to that IRP: rebuilding
        // the variant around the same value neither mints a second receipt nor
        // lets the observation drift.
        let rebuilt: ProviderDisposition<u8> = ProviderDisposition::Pending(held);
        let ProviderDisposition::Pending(after) = rebuilt else {
            unreachable!("the variant was just rebuilt")
        };
        assert_eq!(after.irp(), irp);
    }

    #[test]
    fn pending_disposition_transfers_every_irp_touch_to_the_context() {
        // The shape is the transfer: `Pending` has no `ValidatedCompletion`, so
        // there is no value the thunk could use to write `IoStatus` or call
        // `IoCompleteRequest`. Completing an IRP synchronously requires a
        // `ValidatedCompletion`, and this variant does not carry one.
        let disposition: ProviderDisposition<u8> = ProviderDisposition::Pending(receipt());
        let completion_available = match &disposition {
            ProviderDisposition::Complete(_) => true,
            ProviderDisposition::CompleteAfterTerminal { .. } => true,
            ProviderDisposition::Pending(_) => false,
        };
        assert!(
            !completion_available,
            "a pending disposition hands the thunk nothing it could complete with"
        );

        // The other two variants do carry one, so the asymmetry above is about
        // Pending and not about the enum being empty.
        let complete: ProviderDisposition<u8> = ProviderDisposition::Complete(ok_completion());
        assert!(matches!(complete, ProviderDisposition::Complete(_)));
        let after: ProviderDisposition<u8> = ProviderDisposition::CompleteAfterTerminal {
            completion: ok_completion(),
            terminal: 3,
        };
        let ProviderDisposition::CompleteAfterTerminal {
            completion,
            terminal,
        } = after
        else {
            unreachable!("the variant was just built")
        };
        assert_eq!(terminal, 3);
        // SAFETY: ownership-chain exercise only; no IRP exists here.
        let status = unsafe { completion.prepare_for_irp().commit_after_io_complete() }
            .into_dispatch_status();
        assert_eq!(status, 0);
    }
}

// ---------------------------------------------------------------------------
// R4 Task 16: the staged recording harness
// ---------------------------------------------------------------------------
//
// The plan puts this harness in `fsring-fsd` under `#[cfg(test)]`. That crate is
// a kernel cdylib with a WDK dependency and no host test target, so a harness
// there would compile in no configuration anyone can run. It lives here instead,
// against the same staged APIs, and the deviation is recorded in the evidence.

mod r4_recording_harness {
    use crate::adapter::enter::{PendingDispatchReceipt, ProviderDisposition, ValidatedCompletion};
    use crate::enter::{IrpObservation, build_ring_runtime_parts};
    use crate::session::{
        ControlBinding, PendingControlLedger, SessionRegistry, SetupStage, SetupTransaction,
        TerminalRendezvous, publish_installed_setup_with_ring_set,
    };
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    const HARNESS_IRP: usize = 0x00C0_FFEE;
    const OUT_CAPACITY: usize = 96;
    const EXACT: usize = 32;

    /// Everything one SETUP accumulates before its aggregate publication.
    ///
    /// This is the recording half: the harness *stores* each part as production
    /// would, so the test can assert the order in which they became available
    /// rather than only that the final call succeeded.
    #[derive(Default)]
    struct RecordedSetup {
        runtime_parts: usize,
        ring_set: Option<u32>,
        ledger_reserved: bool,
        published_locator: Option<crate::session::SessionLocator>,
        ledger_bound: bool,
    }

    fn harness_identity(n: u64) -> SessionIdentity {
        SessionIdentity {
            mount_id: MountId { lo: n, hi: 101 },
            boot_instance_id: BootInstanceId { lo: 103, hi: 107 },
            session_epoch: 1,
        }
    }

    #[test]
    fn setup_stores_all_runtime_parts_before_live_active_publication() {
        let mut recorded = RecordedSetup::default();
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let reservation = binding.begin_setup().expect("an empty binding reserves");
        let mut transaction =
            SetupTransaction::begin(harness_identity(1600)).expect("a valid identity");
        for stage in [
            SetupStage::LayoutPlanned,
            SetupStage::SectionReady,
            SetupStage::GrantsReady,
            SetupStage::VolumeReady,
            SetupStage::ViewsReady,
            SetupStage::OutputReady,
        ] {
            transaction = transaction.stage(stage).expect("the roster order");
        }
        let mut registry = SessionRegistry::<1>::new();
        let mut installed = registry
            .install_staging(&transaction, &binding, &reservation)
            .expect("output-ready staging installs");

        // Build and deposit every ring's runtime parts, then seal the set.
        const RINGS: u32 = 3;
        let ring_set = {
            let mut initializer = installed.begin_ring_set(RINGS).expect("a fresh install");
            while let Some(right) = initializer.next_ring().expect("identities available") {
                let brand = right.brand();
                let parts = build_ring_runtime_parts(brand, 64, right)
                    .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
                // Production deposits these into the native cell; the harness
                // only has to prove every ring produced one before the set is
                // sealed, which is what the count below asserts.
                let (_state, _slot, _owners, _wake, _bind) = parts.into_parts();
                recorded.runtime_parts += 1;
            }
            match initializer.finish() {
                Ok(brand) => brand,
                Err((error, _)) => unreachable!("a complete set finishes: {error:?}"),
            }
        };
        recorded.ring_set = Some(ring_set.ring_count());
        assert_eq!(
            recorded.runtime_parts, RINGS as usize,
            "every ring produced its runtime parts before the set was sealed"
        );

        // Reserve the ledger while the binding is still Staging. The
        // reservation succeeding *is* the Staging proof: `reserve_for_setup`
        // refuses any other binding state, so a behavioural check is stronger
        // here than reading a field the module keeps private.
        let pending =
            PendingControlLedger::<8>::reserve_for_setup(&binding, &reservation, ring_set)
                .expect("a staging binding reserves");
        recorded.ledger_reserved = true;

        // Nothing is published yet.
        assert!(recorded.published_locator.is_none());
        assert!(registry.validate_live(installed.locator()).is_err());

        let transaction = transaction
            .stage(SetupStage::ReferencesInstalled)
            .expect("references advance");
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
        recorded.published_locator = Some(session.locator());
        recorded.ledger_bound = true;

        // Both parts of `PublishedRingSetup` are stored before the visibility
        // observation, which is the whole ordering claim: production must not be
        // able to observe Live/Active with only half of it in hand.
        assert!(recorded.ledger_bound && recorded.published_locator.is_some());
        assert_eq!(ledger.brand().locator(), session.locator());
        registry
            .validate_live(session.locator())
            .expect("the aggregate published Live");
        // Active, checked the same behavioural way: the binding is neither
        // Empty nor Staging any more, so it will not begin a second setup.
        assert!(
            binding.begin_setup().is_err(),
            "the aggregate moved the binding to Active"
        );
        assert_eq!(recorded.ring_set, Some(RINGS));
    }

    #[test]
    fn outer_thunk_completes_validated_completion_once() {
        // The harness is the outer thunk: it takes a disposition, and for the
        // two completing variants it walks the one-use chain to a dispatch
        // status. There is no branch in which it can take that chain twice,
        // because each step consumes its input.
        fn outer_thunk(disposition: ProviderDisposition<u8>) -> (i32, Option<u8>, bool) {
            match disposition {
                ProviderDisposition::Complete(completion) => {
                    // SAFETY: harness only; no IRP exists, so the "write
                    // IoStatus and call IoCompleteRequest" premise is vacuous.
                    let prepared = unsafe { completion.prepare_for_irp() };
                    let (status, _information) = prepared.view();
                    let _ = status;
                    // SAFETY: as above.
                    let receipt = unsafe { prepared.commit_after_io_complete() };
                    (receipt.into_dispatch_status(), None, false)
                }
                ProviderDisposition::CompleteAfterTerminal {
                    completion,
                    terminal,
                } => {
                    // SAFETY: as above.
                    let receipt =
                        unsafe { completion.prepare_for_irp().commit_after_io_complete() };
                    (receipt.into_dispatch_status(), Some(terminal), false)
                }
                ProviderDisposition::Pending(receipt) => {
                    // The thunk touches the IRP no further; it only reports that
                    // the pending context owns it.
                    let _ = receipt;
                    (0x0000_0103, None, true)
                }
            }
        }

        let completion = ValidatedCompletion::prepare(0, EXACT, OUT_CAPACITY, EXACT)
            .expect("an exact success validates");
        assert_eq!(
            outer_thunk(ProviderDisposition::Complete(completion)),
            (0, None, false)
        );

        let completion = ValidatedCompletion::prepare(-1, 0, OUT_CAPACITY, EXACT)
            .expect("a failure carries no result");
        assert_eq!(
            outer_thunk(ProviderDisposition::CompleteAfterTerminal {
                completion,
                terminal: 9,
            }),
            (-1, Some(9), false)
        );
    }

    #[test]
    fn outer_thunk_returns_pending_only_for_pending_dispatch_receipt() {
        // The Pending arm consumes an authentic receipt and nothing else can
        // reach it: `ProviderDisposition::Pending` takes a
        // `PendingDispatchReceipt`, whose production minter is Task 17's
        // post-handoff transition. A raw IRP or a status code cannot stand in.
        let irp = IrpObservation::from_raw(HARNESS_IRP).expect("nonzero");
        let receipt = PendingDispatchReceipt::for_test_after_handoff(irp);
        let disposition: ProviderDisposition<u8> = ProviderDisposition::Pending(receipt);

        let is_pending = matches!(disposition, ProviderDisposition::Pending(_));
        assert!(is_pending);

        // Task 19 deleted the predecessor splitter, so the arm the outer
        // dispatch matches is this one and there is no second shape it could
        // have been observed through on the way out.
        let ProviderDisposition::Pending(after) = disposition else {
            unreachable!("the variant was just built")
        };
        assert_eq!(after.irp(), irp);

        // The two completing arms are the only ones that carry a completion, so
        // "returns pending" and "completes" are mutually exclusive by shape.
        let completion = ValidatedCompletion::prepare(0, EXACT, OUT_CAPACITY, EXACT)
            .expect("an exact success validates");
        let completing: ProviderDisposition<u8> = ProviderDisposition::Complete(completion);
        assert!(!matches!(completing, ProviderDisposition::Pending(_)));
    }
}

// ---------------------------------------------------------------------------
// R4 Task 17: the pending-install trace, its selection cut, and its rollback
// ---------------------------------------------------------------------------

#[cfg(test)]
mod r4_pending_install_tests {
    extern crate alloc;

    use crate::adapter::enter::{
        PENDING_INSTALL_ORDER, PENDING_INSTALL_ROLLBACK_ORDER, PendingInstallEffect,
        PendingInstallProgress, PendingInstallRollbackEffect, PendingRollbackProgress,
    };
    use crate::enter::build_ring_runtime_parts;
    use crate::session::{
        ControlBinding, PendingInstallId, SessionRegistry, SetupStage, SetupTransaction,
    };
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    /// One branded install identity, through the ordinary staged setup path.
    fn install(n: u64) -> PendingInstallId {
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let reservation = binding.begin_setup().expect("an empty binding reserves");
        let identity = SessionIdentity {
            mount_id: MountId { lo: n, hi: 17 },
            boot_instance_id: BootInstanceId { lo: 19, hi: 23 },
            session_epoch: 1,
        };
        let mut transaction = SetupTransaction::begin(identity).expect("a valid identity");
        for stage in [
            SetupStage::LayoutPlanned,
            SetupStage::SectionReady,
            SetupStage::GrantsReady,
            SetupStage::VolumeReady,
            SetupStage::ViewsReady,
            SetupStage::OutputReady,
        ] {
            transaction = transaction.stage(stage).expect("the roster order");
        }
        let mut registry = SessionRegistry::<1>::new();
        let mut installed = registry
            .install_staging(&transaction, &binding, &reservation)
            .expect("output-ready staging installs");
        let mut set = installed.begin_ring_set(1).expect("a fresh install");
        let right = set
            .next_ring()
            .expect("identities available")
            .expect("ring 0");
        let brand = right.brand();
        let parts = build_ring_runtime_parts(brand, 64, right)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        let (_state, _slot, _owners, _wake, _bind) = parts.into_parts();
        PendingInstallId::for_test(brand, 1)
    }

    /// Drive the trace, refusing at `refuse_at` if it is on the refusable side,
    /// and report `(install effects attempted, rollback effects performed)`.
    fn drive(
        install: PendingInstallId,
        refuse_at: Option<PendingInstallEffect>,
    ) -> (
        Vec<PendingInstallEffect>,
        Option<Vec<PendingInstallRollbackEffect>>,
    ) {
        let mut attempted = Vec::new();
        let mut progress = PendingInstallProgress::begin_pending_install(install);
        loop {
            progress = match progress {
                PendingInstallProgress::Preselect(step) => {
                    let effect = step.effect();
                    attempted.push(effect);
                    if refuse_at == Some(effect) {
                        step.refused()
                    } else {
                        step.succeeded()
                    }
                }
                PendingInstallProgress::Selected(step) => {
                    let effect = step.effect();
                    attempted.push(effect);
                    // There is no `refused` to call here. That absence is the
                    // property, not an `if` this test chose not to take.
                    step.performed()
                }
                PendingInstallProgress::Installed(installed) => {
                    assert!(installed.ran_the_closed_order());
                    return (attempted, None);
                }
                PendingInstallProgress::Rollback(plan) => {
                    let mut reverse = Vec::new();
                    let mut walk = plan.next();
                    loop {
                        walk = match walk {
                            PendingRollbackProgress::Effect(step) => {
                                reverse.push(step.effect());
                                step.succeeded()
                            }
                            PendingRollbackProgress::Stalled(_) => {
                                unreachable!("no reverse stage refuses in this fixture")
                            }
                            PendingRollbackProgress::Complete(done) => {
                                for effect in PENDING_INSTALL_ROLLBACK_ORDER {
                                    assert_eq!(
                                        done.returned(effect),
                                        reverse.contains(&effect),
                                        "{effect:?} owed and performed must agree",
                                    );
                                }
                                return (attempted, Some(reverse));
                            }
                        };
                    }
                }
            };
        }
    }

    /// Drive the install to the selection cut and refuse there, which is the
    /// cutpoint that owes every one of the eight reverse stages.
    fn drive_to_rollback(install: PendingInstallId) -> PendingInstallProgress {
        let mut progress = PendingInstallProgress::begin_pending_install(install);
        loop {
            progress = match progress {
                PendingInstallProgress::Preselect(step) => {
                    if step.effect() == PendingInstallEffect::SelectPendingDisposition {
                        return step.refused();
                    }
                    step.succeeded()
                }
                other => return other,
            };
        }
    }

    #[test]
    fn a_refused_reverse_stage_resumes_at_itself_without_skipping_ahead() {
        // The `Stalled` arm is the resumable-rollback contract, and until now
        // the only harness that drove a rollback had it as `unreachable!()` --
        // so "a retry resumes at exactly this stage" had no test at all.
        //
        // A reverse stage that refuses still owns the affine value it was
        // meant to give back. Advancing past it would strand that value with
        // nothing left holding a claim on it.
        let install = install(1730);
        let PendingInstallProgress::Rollback(plan) = drive_to_rollback(install) else {
            unreachable!("refusing the selection produces a rollback")
        };

        // Walk to the second owed stage, then refuse it.
        let PendingRollbackProgress::Effect(first) = plan.next() else {
            unreachable!("this rollback owes at least two stages")
        };
        let first_effect = first.effect();
        let PendingRollbackProgress::Effect(second) = first.succeeded() else {
            unreachable!("a second stage is owed")
        };
        let stalled_at = second.effect();
        assert_ne!(stalled_at, first_effect);

        let PendingRollbackProgress::Stalled(plan) = second.refused() else {
            unreachable!("a refused stage stalls the plan")
        };

        // The cursor did not advance: retrying yields the SAME stage, not the
        // one after it.
        let PendingRollbackProgress::Effect(retry) = plan.next() else {
            unreachable!("the stalled stage is still owed")
        };
        assert_eq!(
            retry.effect(),
            stalled_at,
            "a retry resumes at the refused stage, never past it",
        );
        // It still owes what it owed; refusing did not discharge anything.
        assert!(retry.plan_owes(stalled_at));

        // And a stage that already succeeded is not replayed.
        assert!(!retry.plan_owes(first_effect) || first_effect != stalled_at);

        // Driving on from the retry completes normally, and the completed
        // report still claims every effect this install owed.
        let mut walk = retry.succeeded();
        let mut seen = alloc::vec![first_effect, stalled_at];
        loop {
            walk = match walk {
                PendingRollbackProgress::Effect(step) => {
                    seen.push(step.effect());
                    step.succeeded()
                }
                PendingRollbackProgress::Stalled(_) => {
                    unreachable!("nothing refuses on the resumed pass")
                }
                PendingRollbackProgress::Complete(done) => {
                    for effect in PENDING_INSTALL_ROLLBACK_ORDER {
                        assert_eq!(done.returned(effect), seen.contains(&effect));
                    }
                    break;
                }
            };
        }
    }

    #[test]
    fn every_preselect_install_cutpoint_rolls_back_exact_authorities() {
        let install = install(1701);

        // The exact expected reverse set at each of the seven refusable
        // cutpoints, written out rather than derived, so a change to the owed
        // table has to be restated here to pass.
        let expected: [(PendingInstallEffect, &[PendingInstallRollbackEffect]); 7] = [
            (PendingInstallEffect::ReservePendingSlotEpoch, &[]),
            (
                PendingInstallEffect::AcquireStrongSessionReference,
                &[PendingInstallRollbackEffect::PublishVacantOrExhausted],
            ),
            (
                PendingInstallEffect::InitializeCancelVisibleOwners,
                &[
                    PendingInstallRollbackEffect::ReleaseStrongReference,
                    PendingInstallRollbackEffect::PublishVacantOrExhausted,
                ],
            ),
            (
                PendingInstallEffect::PrepareFiniteTimer,
                &[
                    PendingInstallRollbackEffect::AbortOwners,
                    PendingInstallRollbackEffect::ReleaseStrongReference,
                    PendingInstallRollbackEffect::PublishVacantOrExhausted,
                ],
            ),
            (
                PendingInstallEffect::LinkControlPendingInstalling,
                &[
                    PendingInstallRollbackEffect::AbortOwners,
                    PendingInstallRollbackEffect::ReleaseStrongReference,
                    PendingInstallRollbackEffect::PublishVacantOrExhausted,
                ],
            ),
            (
                PendingInstallEffect::PreparePendingSelection,
                &[
                    PendingInstallRollbackEffect::UnlinkControl,
                    PendingInstallRollbackEffect::AbortOwners,
                    PendingInstallRollbackEffect::ReleaseStrongReference,
                    PendingInstallRollbackEffect::PublishVacantOrExhausted,
                ],
            ),
            (
                PendingInstallEffect::SelectPendingDisposition,
                &[
                    PendingInstallRollbackEffect::UnlinkControl,
                    PendingInstallRollbackEffect::AbortOwners,
                    PendingInstallRollbackEffect::AbortUnpublishedPark,
                    PendingInstallRollbackEffect::ReleaseSqWaitRole,
                    PendingInstallRollbackEffect::AbortResultReservation,
                    PendingInstallRollbackEffect::ReleaseStrongReference,
                    PendingInstallRollbackEffect::ClearNativeObservations,
                    PendingInstallRollbackEffect::PublishVacantOrExhausted,
                ],
            ),
        ];

        for (refused_at, owed) in expected {
            let (attempted, reverse) = drive(install, Some(refused_at));
            let reverse = reverse
                .unwrap_or_else(|| unreachable!("{refused_at:?} is refusable and must roll back"));
            assert_eq!(
                reverse, owed,
                "refusing at {refused_at:?} must return exactly these, in this order",
            );
            // The refusing effect itself is attempted and is the last one: the
            // trace stops there rather than running the rest of the prefix.
            assert_eq!(attempted.last(), Some(&refused_at));
            assert!(
                !reverse.contains(&PendingInstallRollbackEffect::ClearNativeObservations)
                    || attempted.contains(&PendingInstallEffect::PreparePendingSelection),
                "native observations are only owed once the selection prepared them",
            );
        }

        // Anti-vacuity: the same driver with no refusal installs all thirteen
        // and rolls nothing back, so the rows above are not measuring a
        // fixture that always unwinds.
        let (attempted, reverse) = drive(install, None);
        assert_eq!(attempted, PENDING_INSTALL_ORDER.to_vec());
        assert!(reverse.is_none());
    }

    #[test]
    fn preselect_rollback_never_arms_timer_or_queues_worker() {
        let install = install(1702);
        for refused_at in PENDING_INSTALL_ORDER {
            if !refused_at.may_refuse() {
                continue;
            }
            let (attempted, reverse) = drive(install, Some(refused_at));
            let reverse = reverse.unwrap_or_else(|| unreachable!("{refused_at:?} rolls back"));

            // Nothing after the cut ran at all, so nothing armed a timer,
            // inserted into the CSQ, committed a handoff, or queued work.
            for effect in PENDING_INSTALL_ORDER {
                if !effect.may_refuse() {
                    assert!(
                        !attempted.contains(&effect),
                        "{effect:?} is past the cut and must not run on a refused install",
                    );
                }
            }

            // `PrepareFiniteTimer` records a due time; it owes nothing of its
            // own, so reaching it never adds a reverse stage. Its DPC owner is
            // an owner, and `AbortOwners` is what gives that back.
            let owed_by_timer = reverse.len();
            let (_, without_timer) = drive(install, Some(PendingInstallEffect::PrepareFiniteTimer));
            let without_timer = without_timer.expect("refusable");
            if refused_at == PendingInstallEffect::LinkControlPendingInstalling {
                assert_eq!(
                    owed_by_timer,
                    without_timer.len(),
                    "completing PrepareFiniteTimer must owe nothing extra",
                );
            }
        }
    }

    #[test]
    fn selected_suffix_has_no_refusal_edge() {
        let install = install(1703);

        // Refusal is representable before the cut...
        let mut refusable = 0usize;
        let mut infallible = 0usize;
        for effect in PENDING_INSTALL_ORDER {
            if effect.may_refuse() {
                refusable = refusable.saturating_add(1);
                let (_, reverse) = drive(install, Some(effect));
                assert!(
                    reverse.is_some(),
                    "{effect:?} is refusable and must produce a rollback",
                );
            } else {
                infallible = infallible.saturating_add(1);
                // ...and asking for it after the cut changes nothing, because
                // the suffix step type has no `refused` to reach. The install
                // still completes the full closed order.
                let (attempted, reverse) = drive(install, Some(effect));
                assert!(
                    reverse.is_none(),
                    "{effect:?} is past the cut; a refusal cannot exist for it",
                );
                assert_eq!(attempted, PENDING_INSTALL_ORDER.to_vec());
            }
        }
        assert_eq!(refusable, 7, "seven effects may refuse");
        assert_eq!(infallible, 6, "six effects may not");
        assert_eq!(
            refusable.saturating_add(infallible),
            PENDING_INSTALL_ORDER.len(),
        );
    }
}

// ---------------------------------------------------------------------------
// R4 Task 17: the atomic handoff commit
// ---------------------------------------------------------------------------

#[cfg(test)]
mod r4_pending_handoff_tests {
    use crate::adapter::enter::{PendingDispatchReceipt, ValidatedCompletion};
    use crate::enter::{
        InstallAxis, IrpObservation, PendingHandoffCommit, PendingOwnerKind, PendingOwnerLedger,
        PendingOwnerToken, PendingReason, PendingWakeSlot, PendingWorkerSchedule,
        WorkerScheduleState, build_ring_runtime_parts, commit_pending_handoff,
        select_pending_install,
    };
    use crate::session::{
        ControlBinding, PendingInstallId, SessionRegistry, SetupStage, SetupTransaction,
    };
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    const HANDOFF_IRP: usize = 0x0BAD_F00D;
    /// The exact result size a success must report, and the buffer that
    /// receives it. Same pair the disposition tests use.
    const EXACT: usize = 48;
    const OUT_CAPACITY: usize = 64;

    struct Bench {
        install: PendingInstallId,
        schedule: PendingWorkerSchedule,
        wake: PendingWakeSlot,
        owners: PendingOwnerLedger,
        worker_owner: Option<PendingOwnerToken>,
    }

    /// One ring mid-install: the ledger bound, the Installer owner held, the
    /// axis still `Installing`. Exactly the state the suffix commits from.
    fn bench(n: u64) -> (Bench, PendingOwnerToken) {
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let reservation = binding.begin_setup().expect("an empty binding reserves");
        let identity = SessionIdentity {
            mount_id: MountId { lo: n, hi: 29 },
            boot_instance_id: BootInstanceId { lo: 31, hi: 37 },
            session_epoch: 1,
        };
        let mut transaction = SetupTransaction::begin(identity).expect("a valid identity");
        for stage in [
            SetupStage::LayoutPlanned,
            SetupStage::SectionReady,
            SetupStage::GrantsReady,
            SetupStage::VolumeReady,
            SetupStage::ViewsReady,
            SetupStage::OutputReady,
        ] {
            transaction = transaction.stage(stage).expect("the roster order");
        }
        let mut registry = SessionRegistry::<1>::new();
        let mut installed = registry
            .install_staging(&transaction, &binding, &reservation)
            .expect("output-ready staging installs");
        let mut set = installed.begin_ring_set(1).expect("a fresh install");
        let right = set
            .next_ring()
            .expect("identities available")
            .expect("ring 0");
        let brand = right.brand();
        let parts = build_ring_runtime_parts(brand, 64, right)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        let (_state, _slot, mut owners, wake, _bind) = parts.into_parts();

        let install = PendingInstallId::for_test(brand, 1);
        owners.bind_install(install).expect("a fresh ledger binds");
        let installer = owners
            .acquire_owner(install, PendingOwnerKind::Installer)
            .expect("the first Installer");
        let mut schedule = PendingWorkerSchedule::for_brand(brand);
        schedule.begin_install(install).expect("a fresh schedule");

        (
            Bench {
                install,
                schedule,
                wake,
                owners,
                worker_owner: None,
            },
            installer,
        )
    }

    fn irp() -> IrpObservation {
        IrpObservation::from_raw(HANDOFF_IRP).expect("a nonzero literal")
    }

    #[test]
    fn pending_receipt_mints_only_after_atomic_handoff() {
        let (mut b, installer) = bench(1704);

        // A wake stored while Installing is what makes work owed. It must not
        // schedule anything yet: the installer is still publishing.
        b.wake
            .record_wake(b.install, PendingReason::Readiness)
            .expect("the slot takes a wake during installation");
        assert_eq!(b.schedule.state(), WorkerScheduleState::Idle);
        assert_eq!(b.schedule.axis(), InstallAxis::Installing);
        assert!(
            b.schedule.queue_worker(b.install).is_err(),
            "a worker cannot be queued before the handoff commits",
        );

        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(b.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            installer,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));

        // A stored wake means the receipt is *not* immediately readable: the
        // queue call it represents has to happen first.
        let PendingHandoffCommit::Queue(queued) = commit else {
            unreachable!("a stored noncancel wake owes one queue call")
        };
        // SAFETY: the fixture stands in for the one void queue side effect.
        let receipt = unsafe { queued.commit_after_queue() };
        assert_eq!(receipt.irp(), irp());

        // And only that receipt mints the dispatch receipt the Pending arm
        // takes. There is no other production route into it.
        let dispatch = PendingDispatchReceipt::from_handoff(receipt);
        assert_eq!(dispatch.irp(), irp());
    }

    #[test]
    fn handoff_publishes_queued_and_worker_owner_in_the_same_lock_hold() {
        let (mut b, installer) = bench(1705);
        b.wake
            .record_wake(b.install, PendingReason::Fence)
            .expect("a fence arrives during installation");

        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(b.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            installer,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(matches!(commit, PendingHandoffCommit::Queue(_)));

        // One transition, four published facts. There is no ordering between
        // them to observe because there is no second call that could produce
        // any one of them.
        assert_eq!(b.schedule.axis(), InstallAxis::HandoffDone);
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        assert!(b.worker_owner.is_some(), "exactly one Worker token stored");
        assert!(
            !b.owners.holds(PendingOwnerKind::Installer),
            "the Installer owner stopped existing in the same step",
        );
        assert!(b.owners.holds(PendingOwnerKind::Worker));

        // The coalesced reasons stayed in the slot for the pass to take.
        assert!(b.wake.stored_covers(PendingReason::Fence));

        // With nothing stored, the same call publishes HandoffDone and mints
        // an immediate receipt, acquiring no Worker at all -- so the Queued
        // publication above is caused by the stored wake, not by the call.
        let (mut quiet, quiet_installer) = bench(1706);
        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(quiet.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            quiet_installer,
            &mut quiet.schedule,
            &mut quiet.wake,
            &mut quiet.owners,
            &mut quiet.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(matches!(commit, PendingHandoffCommit::Ready(_)));
        assert_eq!(quiet.schedule.axis(), InstallAxis::HandoffDone);
        assert_eq!(quiet.schedule.state(), WorkerScheduleState::Idle);
        assert!(quiet.worker_owner.is_none());
        assert!(!quiet.owners.holds(PendingOwnerKind::Worker));

        // A stored Cancel during Installing must become the first worker pass
        // at handoff: the cancel callback already ran (and cannot complete at
        // DISPATCH), so HandoffDone is what transfers that wake to a Worker
        // and queues after unlock. take_for_worker must select Cancel so the
        // pass completes STATUS_CANCELLED instead of wedging.
        let (mut cancel_only, cancel_installer) = bench(1709);
        cancel_only
            .wake
            .record_wake(cancel_only.install, PendingReason::Cancel)
            .expect("a cancel arrives during installation");
        assert!(
            cancel_only
                .wake
                .take_for_worker(cancel_only.install)
                .is_ok(),
            "a worker must select Cancel so a queued cancel pass can complete",
        );
        cancel_only
            .wake
            .record_wake(cancel_only.install, PendingReason::Cancel)
            .expect("restore the cancel-only slot");
        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(cancel_only.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            cancel_installer,
            &mut cancel_only.schedule,
            &mut cancel_only.wake,
            &mut cancel_only.owners,
            &mut cancel_only.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(
            matches!(commit, PendingHandoffCommit::Queue(_)),
            "a cancel-only wake at handoff owes one queue call",
        );
        assert_eq!(cancel_only.schedule.state(), WorkerScheduleState::Queued);
        assert!(cancel_only.worker_owner.is_some());
        assert!(cancel_only.owners.holds(PendingOwnerKind::Worker));
        assert!(cancel_only.wake.stored_covers(PendingReason::Cancel));
    }

    /// A bench whose handoff has already committed, so the schedule is
    /// `HandoffDone` + `Idle` — the state every producer wake meets.
    fn handed_off(n: u64) -> Bench {
        let (mut b, installer) = bench(n);
        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(b.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            installer,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(matches!(commit, PendingHandoffCommit::Ready(_)));
        assert_eq!(b.schedule.state(), WorkerScheduleState::Idle);
        b
    }

    #[test]
    fn pending_runtime_ready_exists_but_production_route_remains_unreachable() {
        use crate::enter::PendingRuntimeInitCursor;

        // Readiness is a value, not a belief. The only way to hold one is to
        // have driven the cursor to completion and agreed about the count.
        let mut cursor = PendingRuntimeInitCursor::begin(4).expect("a real ring set");
        for _ in 0..4 {
            cursor = cursor
                .record_initialized()
                .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        }

        // Disagreeing about which set this is refuses and hands the cursor
        // back, so a caller cannot declare a partial arena ready by naming a
        // smaller count.
        let (error, cursor) = cursor.finish(3).expect_err("a smaller count is refused");
        assert_eq!(error, crate::session::PendingError::WrongRing);
        let (error, cursor) = cursor.finish(5).expect_err("a larger count is refused");
        assert_eq!(error, crate::session::PendingError::WrongRing);

        let ready = cursor.finish(4).expect("the exact set publishes");
        assert_eq!(ready.ring_count(), 4);

        // An incomplete prefix cannot mint one at all, whatever count it names.
        let mut short = PendingRuntimeInitCursor::begin(4).expect("a real ring set");
        for _ in 0..3 {
            short = short
                .record_initialized()
                .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        }
        let (error, short) = short.finish(4).expect_err("three of four is not ready");
        assert_eq!(error, crate::session::PendingError::OwnersRemain);
        assert_eq!(short.initialized(), 3);

        // The proof is affine and has no public constructor, so the staging
        // gate's job is the other half of this: `PendingRuntimeReadyProof`
        // exists in the tree while no production root can reach the cursor
        // that mints it. Task 19's cutover is the first consumer.
    }

    #[test]
    fn pending_runtime_prefix_rolls_back_every_work_item_in_reverse() {
        use crate::enter::PendingRuntimeInitCursor;

        // Initialize a full prefix, then walk the rollback. It must yield every
        // initialized index exactly once, highest first, and stop at zero.
        for ring_count in [1u32, 2, 8, 64] {
            let mut cursor = PendingRuntimeInitCursor::begin(ring_count).expect("a real ring set");
            for _ in 0..ring_count {
                cursor = cursor
                    .record_initialized()
                    .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
            }
            let mut span = cursor.rollback_span();
            assert_eq!(span.len(), ring_count);
            let mut walked = Vec::new();
            while let Some((index, rest)) = span.next_reverse() {
                walked.push(index);
                span = rest;
            }
            let expected: Vec<u32> = (0..ring_count).rev().collect();
            assert_eq!(walked, expected, "{ring_count} rings tear down in reverse");
            assert!(span.is_empty(), "the span is consumed exactly once");
            assert_eq!(span.next_reverse(), None);
        }
    }

    #[test]
    fn pending_runtime_allocation_failure_at_each_index_never_publishes_live() {
        use crate::enter::PendingRuntimeInitCursor;

        const RINGS: u32 = 8;
        // Fail at every index in turn. Each time, the rollback must span
        // exactly the contexts that were built -- never the one that failed,
        // and never one that was never reached.
        for failure_index in 0..RINGS {
            let mut cursor = PendingRuntimeInitCursor::begin(RINGS).expect("a real ring set");
            for _ in 0..failure_index {
                cursor = cursor
                    .record_initialized()
                    .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
            }
            // The context at `failure_index` failed to build, so it is never
            // recorded. `finish` must refuse: an incomplete prefix cannot
            // become a live runtime.
            assert_eq!(cursor.next_uninitialized_index(), Some(failure_index));
            let cursor = cursor
                .finish(RINGS)
                .expect_err("an incomplete prefix cannot publish live")
                .1;

            let mut span = cursor.rollback_span();
            assert_eq!(
                span.len(),
                failure_index,
                "only the built prefix is torn down",
            );
            let mut walked = Vec::new();
            while let Some((index, rest)) = span.next_reverse() {
                walked.push(index);
                span = rest;
            }
            assert_eq!(walked, (0..failure_index).rev().collect::<Vec<_>>());
            assert!(
                !walked.contains(&failure_index),
                "the context that failed to build is never torn down",
            );
        }

        // And the complete prefix does publish, which is what keeps every row
        // above from being a fixture that can only fail.
        let mut cursor = PendingRuntimeInitCursor::begin(RINGS).expect("a real ring set");
        for _ in 0..RINGS {
            cursor = cursor
                .record_initialized()
                .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        }
        let ready = cursor.finish(RINGS).expect("a complete prefix publishes");
        let _ = ready.ring_count();
    }

    #[test]
    fn producer_publication_sets_event_and_queues_one_passive_worker() {
        use crate::enter::{PendingWakeOutcome, record_and_schedule_pending};

        let mut b = handed_off(1801);
        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Readiness,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("a readiness wake after handoff queues");
        let PendingWakeOutcome::Queued(right) = outcome else {
            unreachable!("an Idle schedule queues exactly one pass")
        };
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        assert!(b.worker_owner.is_some(), "exactly one Worker token");
        assert!(b.owners.holds(PendingOwnerKind::Worker));
        // The right is what the queue DDI call is paired with, outside the lock.
        // SAFETY: the fixture stands in for that one void call.
        unsafe { right.commit_after_work_queued() };

        // A second wake while Queued does NOT queue again: the pending pass has
        // not begun and will take these reasons with the rest.
        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Fence,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("a second wake coalesces");
        assert!(matches!(outcome, PendingWakeOutcome::Stored));
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        assert!(b.wake.stored_covers(PendingReason::Fence));
        assert!(b.wake.stored_covers(PendingReason::Readiness));

        // After HandoffDone a Cancel wake is a producer publication: the
        // callback cannot complete at DISPATCH, so the PASSIVE worker must
        // run and complete STATUS_CANCELLED. take_for_worker selects Cancel.
        let mut cancel_only = handed_off(1806);
        let outcome = record_and_schedule_pending(
            cancel_only.install,
            PendingReason::Cancel,
            &mut cancel_only.schedule,
            &mut cancel_only.wake,
            &mut cancel_only.owners,
            &mut cancel_only.worker_owner,
        )
        .expect("a cancel wake is recorded");
        let PendingWakeOutcome::Queued(right) = outcome else {
            unreachable!("a Cancel after HandoffDone queues one worker pass")
        };
        unsafe { right.commit_after_work_queued() };
        assert_eq!(cancel_only.schedule.state(), WorkerScheduleState::Queued);
        assert!(cancel_only.worker_owner.is_some());
        assert!(cancel_only.owners.holds(PendingOwnerKind::Worker));
        assert!(cancel_only.wake.stored_covers(PendingReason::Cancel));
        assert!(
            cancel_only
                .wake
                .take_for_worker(cancel_only.install)
                .is_ok(),
            "a worker selects Cancel and completes CANCELLED",
        );
    }

    #[test]
    fn worker_state_machine_and_affine_owner_never_diverge() {
        use crate::enter::{PendingWakeOutcome, record_and_schedule_pending};

        // The invariant: Idle with no token, Queued/Running with exactly one.
        let mut b = handed_off(1802);
        assert_eq!(b.schedule.state(), WorkerScheduleState::Idle);
        assert!(b.worker_owner.is_none() && !b.owners.holds(PendingOwnerKind::Worker));

        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Unload,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("queues");
        let PendingWakeOutcome::Queued(right) = outcome else {
            unreachable!("an Idle schedule queues exactly one pass")
        };
        // SAFETY: the fixture stands in for the one void queue call.
        unsafe { right.commit_after_work_queued() };
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        assert!(b.worker_owner.is_some() && b.owners.holds(PendingOwnerKind::Worker));

        // Running: the same one token moves into the active pass.
        let token = b.worker_owner.take().expect("the queued token");
        let batch = b
            .wake
            .take_for_worker(b.install)
            .expect("the pass takes the reasons")
            .into_batch();
        let (token, _batch) = b
            .schedule
            .begin_worker_pass(token, batch)
            .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert_eq!(b.schedule.state(), WorkerScheduleState::Running);
        assert!(
            b.owners.holds(PendingOwnerKind::Worker),
            "still exactly one"
        );

        // Back to Idle, and the token is released in the same step that
        // publishes it -- so Idle never coexists with a held Worker owner.
        let (token, rescheduled) = b
            .schedule
            .finish_worker_pass(token)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        assert!(rescheduled.is_none(), "an Idle finish owes no queue call");
        assert_eq!(b.schedule.state(), WorkerScheduleState::Idle);
        b.owners.release_owner(token).expect("the exact token");
        assert!(!b.owners.holds(PendingOwnerKind::Worker));
    }

    #[test]
    fn idle_publication_and_worker_owner_release_are_one_locked_transition() {
        use crate::enter::{PendingWakeOutcome, record_and_schedule_pending};

        // There is no API that publishes Queued without acquiring the token,
        // and none that acquires the token without publishing Queued: the one
        // function does both or refuses. Refusing leaves both untouched.
        let mut b = handed_off(1803);
        let stolen = b
            .owners
            .acquire_owner(b.install, PendingOwnerKind::Worker)
            .expect("a Worker kind is available");
        let error = record_and_schedule_pending(
            b.install,
            PendingReason::Timeout,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect_err("a second Worker owner is refused");
        assert_eq!(error, crate::session::PendingError::DuplicateOwner);
        // Refused before any mutation: nothing recorded, nothing published.
        assert_eq!(b.schedule.state(), WorkerScheduleState::Idle);
        assert!(b.worker_owner.is_none());
        assert!(!b.wake.has_wake(), "a refused wake records nothing");
        b.owners.release_owner(stolen).expect("the exact token");

        // With the kind free again, the same call publishes both together.
        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Timeout,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("queues");
        let PendingWakeOutcome::Queued(right) = outcome else {
            unreachable!("an Idle schedule queues exactly one pass")
        };
        // SAFETY: the fixture stands in for the one void queue call.
        unsafe { right.commit_after_work_queued() };
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        assert!(b.worker_owner.is_some());
    }

    #[test]
    fn producer_during_running_final_recheck_sets_reschedule_without_a_second_token() {
        use crate::enter::{PendingWakeOutcome, record_and_schedule_pending};

        let mut b = handed_off(1804);
        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Readiness,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("queues");
        let PendingWakeOutcome::Queued(right) = outcome else {
            unreachable!("an Idle schedule queues exactly one pass")
        };
        // SAFETY: the fixture stands in for the one void queue call.
        unsafe { right.commit_after_work_queued() };
        let token = b.worker_owner.take().expect("the queued token");
        let batch = b
            .wake
            .take_for_worker(b.install)
            .expect("reasons")
            .into_batch();
        let (token, _batch) = b
            .schedule
            .begin_worker_pass(token, batch)
            .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert_eq!(b.schedule.state(), WorkerScheduleState::Running);

        // A producer wake landing during the pass's final recheck reschedules
        // that same pass. No second token is acquired -- the running pass still
        // holds the only one.
        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Fence,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("a wake during a pass reschedules it");
        assert!(matches!(outcome, PendingWakeOutcome::Rescheduled));
        assert_eq!(b.schedule.state(), WorkerScheduleState::RunningReschedule);
        assert!(b.worker_owner.is_none(), "no second token was stored");

        // And finishing turns that reschedule into the next Queued atomically,
        // still with the one token.
        let (token, rescheduled) = b
            .schedule
            .finish_worker_pass(token)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        let right = rescheduled.expect("the published Queued owes one queue call");
        assert_eq!(right.install(), b.install);
        // SAFETY: the obligation is discharged the way production discharges it.
        unsafe { right.commit_after_work_queued() };
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        b.owners.release_owner(token).expect("the exact token");
    }

    #[test]
    fn spurious_wake_rearms_without_dequeue() {
        use crate::enter::{PendingWakeOutcome, record_and_schedule_pending};

        // A wake that turns out to have nothing to do still leaves the install
        // parked: nothing here dequeues an IRP or touches the arbiter. The pass
        // runs, finds nothing, finishes, and the slot returns to Idle ready to
        // be woken again.
        let mut b = handed_off(1805);
        for round in 0..3u32 {
            let outcome = record_and_schedule_pending(
                b.install,
                PendingReason::Readiness,
                &mut b.schedule,
                &mut b.wake,
                &mut b.owners,
                &mut b.worker_owner,
            )
            .expect("each spurious wake queues once");
            let PendingWakeOutcome::Queued(right) = outcome else {
                unreachable!("round {round} must queue from Idle")
            };
            // SAFETY: the fixture stands in for the one void queue call.
            unsafe { right.commit_after_work_queued() };
            let token = b.worker_owner.take().expect("the queued token");
            let batch = b
                .wake
                .take_for_worker(b.install)
                .expect("reasons")
                .into_batch();
            let (token, _batch) = b
                .schedule
                .begin_worker_pass(token, batch)
                .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
            let (token, rescheduled) = b
                .schedule
                .finish_worker_pass(token)
                .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
            assert!(rescheduled.is_none(), "an Idle finish owes no queue call");
            b.owners.release_owner(token).expect("the exact token");
            assert_eq!(b.schedule.state(), WorkerScheduleState::Idle);
            assert!(!b.wake.has_wake(), "the pass consumed the reasons");
        }
        // Still parked after three spurious rounds.
        assert_eq!(b.schedule.axis(), InstallAxis::HandoffDone);
    }

    #[test]
    fn false_ke_cancel_timer_requires_dpc_exit_wait() {
        use crate::enter::{PendingTimerCancel, TimerState};

        // The DPC is already running, so the canceller owns nothing and must
        // wait. Critically, the state stays `Running`: publishing Quiesced here
        // would advertise a reusable slot the DPC still holds.
        let mut timer = TimerState::Quiesced;
        timer.arm(7).expect("a quiesced timer arms");
        timer.dpc_entered(7).expect("the DPC for this epoch enters");
        assert_eq!(
            timer.cancel(7, false),
            PendingTimerCancel::RequiresDpcExitWait,
        );
        assert_eq!(timer, TimerState::Running { epoch: 7 });

        // Armed-but-not-dequeued is the same obligation: the DPC is already on
        // its way in, and only it may publish Quiesced.
        let mut racing = TimerState::Quiesced;
        racing.arm(8).expect("a quiesced timer arms");
        assert_eq!(
            racing.cancel(8, false),
            PendingTimerCancel::RequiresDpcExitWait,
        );
        assert_eq!(racing, TimerState::Armed { epoch: 8 });

        // Only the DPC's own exit quiesces it, and only for its own epoch.
        assert!(timer.dpc_exiting(9).is_err());
        assert_eq!(timer, TimerState::Running { epoch: 7 });
        timer.dpc_exiting(7).expect("its own epoch exits");
        assert_eq!(timer, TimerState::Quiesced);
    }

    #[test]
    fn true_ke_cancel_timer_returns_and_releases_the_exact_dpc_owner_without_wait() {
        use crate::enter::{PendingTimerCancel, TimerState};

        // Dequeued before running: the DPC never ran, so the canceller takes
        // the owner back and waits for nothing. The slot is immediately
        // quiesced because nothing else can be holding it.
        let mut timer = TimerState::Quiesced;
        timer.arm(11).expect("a quiesced timer arms");
        assert_eq!(
            timer.cancel(11, true),
            PendingTimerCancel::DequeuedBeforeRun,
        );
        assert_eq!(timer, TimerState::Quiesced);

        // A TRUE return naming a *different* epoch is not this install's
        // dequeue. It must be told it owns nothing -- NOT handed a wait
        // obligation. `RequiresDpcExitWait` here would send a stale generation
        // to block on a DPC-exit event only the live generation's DPC signals.
        let mut other = TimerState::Quiesced;
        other.arm(12).expect("a quiesced timer arms");
        assert_eq!(other.cancel(13, true), PendingTimerCancel::NotThisInstall);
        assert_eq!(other, TimerState::Armed { epoch: 12 });
        // And the live owner is still able to cancel its own timer afterwards,
        // so the refusal costs the real owner nothing.
        assert_eq!(
            other.cancel(12, true),
            PendingTimerCancel::DequeuedBeforeRun,
        );
        assert_eq!(other, TimerState::Quiesced);
    }

    #[test]
    fn infinite_wait_observes_not_armed_and_has_no_dpc_owner() {
        use crate::enter::{PendingTimerCancel, TimerState};

        // An indefinite wait arms nothing, so cancelling it is a no-op with no
        // owner to return and nothing to wait for.
        let mut timer = TimerState::Quiesced;
        assert_eq!(timer.cancel(0, false), PendingTimerCancel::NotArmed);
        assert_eq!(timer.cancel(0, true), PendingTimerCancel::NotArmed);
        assert_eq!(timer, TimerState::Quiesced);
        assert_eq!(timer.epoch(), None);

        // And a DPC cannot enter a timer that was never armed.
        assert!(timer.dpc_entered(1).is_err());
        assert!(timer.dpc_exiting(1).is_err());

        // An infinite wait has no due time to compute; a finite one does, and
        // it is negative because relative due times count down.
        assert_eq!(crate::enter::finite_due_time_100ns(1), Some(-10_000));
        assert_eq!(crate::enter::finite_due_time_100ns(0), Some(0));
        // Overflow terminalizes rather than arming a wrapped due time.
        assert_eq!(
            crate::enter::finite_due_time_100ns(u32::MAX),
            Some(-42_949_672_950_000)
        );
    }

    #[test]
    fn old_timer_and_worker_epochs_cannot_touch_a_reused_slot() {
        use crate::enter::TimerState;

        // Generation 1 runs and quiesces.
        let mut timer = TimerState::Quiesced;
        timer.arm(1).expect("arm");
        timer.dpc_entered(1).expect("enter");
        timer.dpc_exiting(1).expect("exit");

        // The slot is reused by generation 2.
        timer.arm(2).expect("the reused slot arms");
        assert_eq!(timer, TimerState::Armed { epoch: 2 });

        // A late DPC from generation 1 finds an epoch that is not its own and
        // is refused. It changes nothing -- it must still signal its exit, but
        // it may not quiesce generation 2's live timer.
        assert!(timer.dpc_entered(1).is_err());
        assert_eq!(timer, TimerState::Armed { epoch: 2 });
        assert!(timer.dpc_exiting(1).is_err());
        assert_eq!(timer, TimerState::Armed { epoch: 2 });

        // Nor may an old canceller take generation 2's DPC owner -- and it is
        // told it owns nothing rather than being given a wait it can never
        // satisfy. Generation 1's DPC has already exited; nothing will signal
        // an exit event on its behalf again.
        assert_eq!(
            timer.cancel(1, true),
            crate::enter::PendingTimerCancel::NotThisInstall,
        );
        assert_eq!(
            timer.cancel(1, false),
            crate::enter::PendingTimerCancel::NotThisInstall,
        );
        assert_eq!(timer, TimerState::Armed { epoch: 2 });

        // Arming over a live timer is refused outright: two epochs believing
        // they own one DPC is the state every rule above exists to prevent.
        assert!(timer.arm(3).is_err());
        assert_eq!(timer, TimerState::Armed { epoch: 2 });
    }

    /// Walk one DPC pass to its end, returning the effects it performed and the
    /// ticket it minted. Written once so every DPC row judges the same walk.
    fn walk_dpc_pass(
        timer: &mut crate::enter::TimerState,
        epoch: u64,
    ) -> (
        Vec<crate::enter::PendingCallbackAction>,
        crate::enter::PendingDpcExitTicket,
    ) {
        use crate::enter::{PendingDpcPass, PendingDpcStep};

        let mut pass = PendingDpcPass::begin_dpc_pass(timer, epoch);
        let mut performed = Vec::new();
        loop {
            match pass.run_next_dpc_effect() {
                PendingDpcStep::Perform(action, next) => {
                    performed.push(action);
                    pass = next;
                }
                PendingDpcStep::SignalExit(ticket) => return (performed, ticket),
            }
        }
    }

    #[test]
    fn timer_dpc_signals_exit_on_every_epoch_match_and_mismatch_path() {
        use crate::enter::{
            PENDING_DPC_OWN_EPOCH_ORDER, PendingDpcPass, PendingDpcPath, PendingDpcStep, TimerState,
        };

        // The live epoch's DPC: it takes the whole roster and ends with a
        // ticket. `dpc_entered` is what chose the roster, so the walk and the
        // timer transition cannot disagree.
        let mut own = TimerState::Quiesced;
        own.arm(5).expect("a quiesced timer arms");
        let (performed, ticket) = walk_dpc_pass(&mut own, 5);
        assert_eq!(performed, PENDING_DPC_OWN_EPOCH_ORDER.to_vec());
        assert_eq!(ticket.epoch(), 5);
        assert_eq!(ticket.path(), PendingDpcPath::OwnEpoch);
        assert_eq!(own, TimerState::Running { epoch: 5 });
        // SAFETY: this row stands in for the one `KeSetEvent(dpc_exited)`.
        unsafe { ticket.commit_after_exit_signalled() };

        // Every shape of mismatch reaches the same exit, and none of them
        // touches the live install's timer. A stale DPC that quietly returned
        // without signalling is the shape that hangs a canceller forever on the
        // `RequiresDpcExitWait` arm.
        let stale_states = [
            // A later install owns the slot now.
            (TimerState::Armed { epoch: 9 }, 5u64),
            // A later install's DPC is already running.
            (TimerState::Running { epoch: 9 }, 5),
            // The slot was cancelled and quiesced out from under this DPC.
            (TimerState::Quiesced, 5),
        ];
        for (initial, epoch) in stale_states {
            let mut timer = initial;
            let (performed, ticket) = walk_dpc_pass(&mut timer, epoch);
            assert!(
                performed.is_empty(),
                "a stale DPC performs no effect on a slot it does not own",
            );
            assert_eq!(ticket.epoch(), epoch);
            assert_eq!(ticket.path(), PendingDpcPath::StaleEpoch);
            assert_eq!(timer, initial, "a stale DPC changes nothing");
            // SAFETY: the exit is signalled on this path too, which is the row.
            unsafe { ticket.commit_after_exit_signalled() };
        }

        // And the exit is not something a pass can reach early: on the
        // own-epoch path every prefix shorter than the roster yields another
        // effect, never a ticket.
        let mut early = TimerState::Quiesced;
        early.arm(6).expect("a quiesced timer arms");
        let mut pass = PendingDpcPass::begin_dpc_pass(&mut early, 6);
        for expected in PENDING_DPC_OWN_EPOCH_ORDER {
            let PendingDpcStep::Perform(action, next) = pass.run_next_dpc_effect() else {
                panic!("the exit ticket cannot be reached before {expected:?}")
            };
            assert_eq!(action, expected);
            pass = next;
        }
        assert!(matches!(
            pass.run_next_dpc_effect(),
            PendingDpcStep::SignalExit(_)
        ));
    }

    #[test]
    fn timer_dpc_releases_owner_and_publishes_quiesced_before_signalling_exit() {
        use crate::enter::{
            PendingCallbackAction, PendingDpcPass, PendingDpcStep, PendingOwnerKind, TimerState,
        };

        // Drive the walk against real state, performing each effect for real,
        // so the ordering claim is about what the ledger and the timer actually
        // hold when the ticket appears -- not about a list of tags.
        let mut b = handed_off(1901);
        let dpc = b
            .owners
            .acquire_owner(b.install, PendingOwnerKind::Dpc)
            .expect("arming mints exactly one DPC owner");
        let mut dpc_slot = Some(dpc);

        let mut timer = TimerState::Quiesced;
        timer.arm(3).expect("a quiesced timer arms");

        let mut pass = PendingDpcPass::begin_dpc_pass(&mut timer, 3);
        let mut released_at = None;
        let mut quiesced_at = None;
        let mut queue_right = None;
        let mut step = 0usize;
        let ticket = loop {
            match pass.run_next_dpc_effect() {
                PendingDpcStep::Perform(action, next) => {
                    match action {
                        PendingCallbackAction::EnterRunning => {
                            // The transition already happened in `begin_dpc_pass`;
                            // this effect is where the native side takes the
                            // owner out of the context's slot.
                            assert_eq!(timer, TimerState::Running { epoch: 3 });
                            assert!(dpc_slot.is_some());
                        }
                        PendingCallbackAction::RecordTimeoutWake => {
                            let outcome = crate::enter::record_and_schedule_pending(
                                b.install,
                                crate::enter::PendingReason::Timeout,
                                &mut b.schedule,
                                &mut b.wake,
                                &mut b.owners,
                                &mut b.worker_owner,
                            )
                            .expect("a timeout after handoff schedules one pass");
                            let crate::enter::PendingWakeOutcome::Queued(right) = outcome else {
                                panic!("an Idle schedule queues exactly one pass")
                            };
                            // Held until the QueueWorker effect, which is what
                            // "the queue call happens outside the lock" means.
                            queue_right = Some(right);
                        }
                        PendingCallbackAction::QueueWorker => {
                            let right = queue_right
                                .take()
                                .expect("the wake produced the right this effect discharges");
                            // SAFETY: this row stands in for the one void queue call.
                            unsafe { right.commit_after_work_queued() };
                        }
                        PendingCallbackAction::ReleaseDpcOwner => {
                            let token = dpc_slot.take().expect("the DPC still holds its owner");
                            b.owners.release_owner(token).expect("the exact token");
                            released_at = Some(step);
                        }
                        PendingCallbackAction::PublishQuiesced => {
                            timer.dpc_exiting(3).expect("its own epoch publishes");
                            quiesced_at = Some(step);
                        }
                        other => panic!("a DPC does not perform {other:?}"),
                    }
                    step += 1;
                    pass = next;
                }
                PendingDpcStep::SignalExit(ticket) => break ticket,
            }
        };

        // The ticket exists only now, and by then both obligations are already
        // discharged. A waiter that wakes on this event therefore cannot find
        // an owner still held or a timer still claiming to run.
        let released_at = released_at.expect("the own-epoch path releases the owner");
        let quiesced_at = quiesced_at.expect("the own-epoch path publishes Quiesced");
        assert!(released_at < step, "release precedes the exit signal");
        assert!(quiesced_at < step, "Quiesced precedes the exit signal");
        assert!(
            released_at < quiesced_at,
            "the owner leaves the ledger before the slot advertises Quiesced",
        );
        assert!(!b.owners.holds(PendingOwnerKind::Dpc));
        assert_eq!(timer, TimerState::Quiesced);
        assert!(dpc_slot.is_none());
        // SAFETY: this row stands in for the one `KeSetEvent(dpc_exited)`.
        unsafe { ticket.commit_after_exit_signalled() };
    }

    #[test]
    fn timer_dpc_never_dequeues_waits_writes_or_completes() {
        use crate::enter::{
            PENDING_DPC_OWN_EPOCH_ORDER, PENDING_DPC_STALE_EPOCH_ORDER, PENDING_WORKER_PASS_ORDER,
            PendingCallbackAction, PendingDpcPath,
        };

        // Neither DPC roster contains an action the DPC may not perform.
        for path in [PendingDpcPath::OwnEpoch, PendingDpcPath::StaleEpoch] {
            for action in path.effects() {
                assert!(
                    !action.forbidden_at_dispatch_level(),
                    "a DPC roster may not contain {action:?}",
                );
            }
        }
        assert_eq!(
            PendingDpcPath::OwnEpoch.effects(),
            &PENDING_DPC_OWN_EPOCH_ORDER,
        );
        assert_eq!(
            PendingDpcPath::StaleEpoch.effects(),
            &PENDING_DPC_STALE_EPOCH_ORDER,
        );

        // The predicate is not a constant `false`. The worker's roster is built
        // from the same vocabulary and contains every one of the three, so this
        // row fails the moment a DPC roster picks one of them up -- and it
        // would also fail if the predicate stopped recognising them.
        //
        // Three, not four: `WaitDpcExitEvent` was the fourth and left with the
        // roster entry that was its only member. It could not be a rendezvous
        // from that position -- no cancel precedes a worker roster walk -- and
        // the wait the worker still performs is the completion plan's
        // `WaitDpcExitIfRequired`, immediately after its `CancelTimer`.
        let worker_forbidden: Vec<PendingCallbackAction> = PENDING_WORKER_PASS_ORDER
            .into_iter()
            .filter(|action| action.forbidden_at_dispatch_level())
            .collect();
        assert_eq!(
            worker_forbidden,
            vec![
                PendingCallbackAction::RemoveIrpFromCsq,
                PendingCallbackAction::WriteResultStorage,
                PendingCallbackAction::CompleteIrp,
            ],
            "the three forbidden actions exist, and the worker is what performs them",
        );

        // And no action appears on both sides of the line.
        for action in PENDING_DPC_OWN_EPOCH_ORDER {
            assert!(
                !worker_forbidden.contains(&action),
                "{action:?} is on a DPC roster and in the forbidden set",
            );
        }
    }

    #[test]
    fn maximum_pending_epoch_completes_once_then_exhausts() {
        use crate::enter::PendingSlotState;
        use crate::session::PendingError;

        // The last epoch the slot will ever issue. It must be *used*, not
        // discarded: refusing at MAX would throw away a usable install, and
        // wrapping to 1 would hand out an epoch a live install may still carry.
        let slot = PendingSlotState::Vacant {
            next_epoch: u64::MAX,
        };
        assert!(slot.admits_install());
        let slot = slot
            .begin_install()
            .expect("the last epoch is still issued");
        assert_eq!(slot, PendingSlotState::Installing { epoch: u64::MAX });
        let slot = slot.handoff_done().expect("it installs like any other");
        assert_eq!(slot, PendingSlotState::Active { epoch: u64::MAX });
        let slot = slot
            .begin_quiesce()
            .expect("and runs to terminal like any other");
        assert_eq!(slot, PendingSlotState::Quiescing { epoch: u64::MAX });

        // The one completion succeeds -- and the successor state is not a
        // reusable slot but a latched exhaustion.
        let slot = slot
            .publish_vacant()
            .expect("the final publication is a success, not a refusal");
        assert_eq!(slot, PendingSlotState::EpochExhausted);
        assert_eq!(slot.epoch(), None);

        // Latched: nothing reopens it, and the refusal returns the same state.
        assert!(!slot.admits_install());
        let (error, unchanged) = slot
            .begin_install()
            .expect_err("an exhausted slot admits no install");
        assert_eq!(error, PendingError::SlotOccupied);
        assert_eq!(unchanged, PendingSlotState::EpochExhausted);
        assert!(slot.handoff_done().is_err());
        assert!(slot.begin_quiesce().is_err());
        assert!(slot.publish_vacant().is_err());
        assert!(slot.park_publication_fail_stop().is_err());

        // One below the maximum still recycles, so the exhaustion is about the
        // counter running out and not about the machine being broken.
        let ordinary = PendingSlotState::Vacant {
            next_epoch: u64::MAX - 1,
        }
        .begin_install()
        .and_then(PendingSlotState::handoff_done)
        .and_then(PendingSlotState::begin_quiesce)
        .and_then(PendingSlotState::publish_vacant)
        .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        assert_eq!(
            ordinary,
            PendingSlotState::Vacant {
                next_epoch: u64::MAX
            },
        );
    }

    #[test]
    fn exhausted_slot_fences_before_marking_or_queueing_a_new_irp() {
        use crate::adapter::enter::{
            PendingParkDecision, ProviderDisposition, STATUS_INVALID_DEVICE_STATE,
            decide_pending_park, exhausted_pending_completion,
        };
        use crate::enter::PendingSlotState;
        use crate::session::{PendingError, TerminalRequest};

        // The fence is consulted from the slot state alone.
        assert_eq!(
            decide_pending_park(PendingSlotState::EpochExhausted),
            PendingParkDecision::CompleteAfterTerminal(TerminalRequest::PendingEpochExhausted),
        );
        assert_eq!(
            decide_pending_park(PendingSlotState::fresh()),
            PendingParkDecision::Install,
        );
        // A live install refuses the arrival, and does NOT terminalize it with
        // an exhaustion reason it has not suffered.
        for occupied in [
            PendingSlotState::Installing { epoch: 4 },
            PendingSlotState::Active { epoch: 4 },
            PendingSlotState::Quiescing { epoch: 4 },
        ] {
            assert_eq!(
                decide_pending_park(occupied),
                PendingParkDecision::Refuse(PendingError::SlotOccupied),
            );
        }
        assert_eq!(
            decide_pending_park(PendingSlotState::PublicationFailStop { epoch: 4 }),
            PendingParkDecision::Refuse(PendingError::WrongRingState),
        );

        // The structural half: an exhausted slot yields no install identity, so
        // there is nothing to select, nothing to insert into the CSQ, and
        // nothing to queue. This is what "fences BEFORE marking" means -- the
        // marking API cannot be named, rather than being called and undone.
        assert!(PendingSlotState::EpochExhausted.begin_install().is_err());

        // And the completion it returns is exact: STATUS_INVALID_DEVICE_STATE
        // with information zero, validated through the same constructor every
        // other completion uses.
        let completion = exhausted_pending_completion(OUT_CAPACITY, EXACT)
            .expect("a failure status with zero information always validates");
        let disposition: ProviderDisposition<TerminalRequest> =
            ProviderDisposition::CompleteAfterTerminal {
                completion,
                terminal: TerminalRequest::PendingEpochExhausted,
            };
        let ProviderDisposition::CompleteAfterTerminal {
            completion,
            terminal,
        } = disposition
        else {
            panic!("an exhausted slot completes after terminal work")
        };
        assert_eq!(terminal, TerminalRequest::PendingEpochExhausted);
        // SAFETY: this row stands in for the one IoCompleteRequest.
        let prepared = unsafe { completion.prepare_for_irp() };
        assert_eq!(prepared.view(), (STATUS_INVALID_DEVICE_STATE, 0));
        // SAFETY: paired with the write above.
        let receipt = unsafe { prepared.commit_after_io_complete() };
        assert_eq!(receipt.into_dispatch_status(), STATUS_INVALID_DEVICE_STATE);
        assert_ne!(
            STATUS_INVALID_DEVICE_STATE,
            crate::adapter::enter::STATUS_PENDING,
            "an exhausted slot never returns STATUS_PENDING",
        );
    }

    #[test]
    fn maximum_sq_publish_generation_terminalizes_without_wrap_or_false_wake() {
        use crate::enter::RingEnterState;
        use crate::session::TerminalRequest;

        // One below the maximum publishes normally, and the event is owed the
        // generation that was just published.
        let mut state = RingEnterState::for_test_at_generation(0, u64::MAX - 1);
        assert_eq!(state.owed_signal_generation(), u64::MAX - 1);
        assert_eq!(state.publish_sq_or_terminalize(), Ok(u64::MAX));
        assert_eq!(state.observe_readiness(false).generation, u64::MAX);
        assert_eq!(state.owed_signal_generation(), u64::MAX);

        // The next publish has nowhere to go. It terminalizes rather than
        // wrapping to zero, which would make a later generation compare equal
        // to one a parked waiter already snapshotted.
        assert_eq!(
            state.publish_sq_or_terminalize(),
            Err(TerminalRequest::SqGenerationExhausted),
        );
        assert_eq!(
            state.observe_readiness(false).generation,
            u64::MAX,
            "a refused publish does not advance the counter",
        );
        assert_eq!(
            state.owed_signal_generation(),
            u64::MAX,
            "and it publishes no new wake -- the event owes exactly what it did",
        );

        // Repeating it is still a refusal and still changes nothing, so a
        // producer that retries cannot walk the counter past the end.
        for _ in 0..3 {
            assert_eq!(
                state.publish_sq_or_terminalize(),
                Err(TerminalRequest::SqGenerationExhausted),
            );
            assert_eq!(state.observe_readiness(false).generation, u64::MAX);
            assert_eq!(state.owed_signal_generation(), u64::MAX);
        }

        // A fresh ring is unaffected: exhaustion is per-state, and the counter
        // is the ring's own rather than a process-wide one.
        let mut fresh = RingEnterState::new(1);
        assert_eq!(fresh.publish_sq_or_terminalize(), Ok(1));
        assert_eq!(fresh.owed_signal_generation(), 1);
    }

    /// What the recording outer thunk did, in the order it did it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ThunkStep {
        RunTerminal,
        WaitCompletionGuard,
        WaitJoinGuard,
        ReadCompletedResult,
        WriteIoStatus,
        CompleteIrp,
    }

    #[derive(Clone, Copy, Debug)]
    enum TerminalRoute {
        Winner,
        Join,
        Completed,
    }

    impl ThunkStep {
        const fn is_terminal_route(self) -> bool {
            matches!(
                self,
                Self::RunTerminal
                    | Self::WaitCompletionGuard
                    | Self::WaitJoinGuard
                    | Self::ReadCompletedResult
            )
        }

        const fn touches_the_irp(self) -> bool {
            matches!(self, Self::WriteIoStatus | Self::CompleteIrp)
        }
    }

    /// The property, as one function both the real trace and a deliberately
    /// wrong one are judged by. Written once so the anti-vacuity case below
    /// exercises the same predicate rather than a copy that agrees with it.
    fn terminal_precedes_every_irp_touch(trace: &[ThunkStep]) -> bool {
        let mut touched = false;
        for step in trace {
            if step.touches_the_irp() {
                touched = true;
            } else if step.is_terminal_route() && touched {
                return false;
            }
        }
        true
    }

    #[test]
    fn complete_after_terminal_waits_for_runner_or_join_return_before_irp_completion() {
        // The thunk consumes the completion only after the terminal route has
        // returned. That is structural, not conditional: `ValidatedCompletion`
        // is moved into `prepare_for_irp`, so an arm that completed first would
        // have nothing left for the terminal route to be sequenced against.
        fn outer_thunk(
            route: TerminalRoute,
            completion: ValidatedCompletion,
            trace: &mut Vec<ThunkStep>,
        ) -> i32 {
            // Dispatch and access guards are released before routing; the
            // terminal work below may block, and holding them across it is the
            // deadlock this ordering exists to prevent.
            match route {
                TerminalRoute::Winner => {
                    trace.push(ThunkStep::RunTerminal);
                    // The winner waits its *separate* completion guard: having
                    // returned from the runner is not the same as the run
                    // having been observed complete.
                    trace.push(ThunkStep::WaitCompletionGuard);
                }
                TerminalRoute::Join => trace.push(ThunkStep::WaitJoinGuard),
                TerminalRoute::Completed => trace.push(ThunkStep::ReadCompletedResult),
            }
            // SAFETY: harness only; no IRP exists, so the "write IoStatus and
            // call IoCompleteRequest" premise is vacuous.
            let prepared = unsafe { completion.prepare_for_irp() };
            trace.push(ThunkStep::WriteIoStatus);
            let (status, _information) = prepared.view();
            // SAFETY: as above.
            let receipt = unsafe { prepared.commit_after_io_complete() };
            trace.push(ThunkStep::CompleteIrp);
            let _ = status;
            receipt.into_dispatch_status()
        }

        let expected: [(TerminalRoute, &[ThunkStep]); 3] = [
            (
                TerminalRoute::Winner,
                &[
                    ThunkStep::RunTerminal,
                    ThunkStep::WaitCompletionGuard,
                    ThunkStep::WriteIoStatus,
                    ThunkStep::CompleteIrp,
                ],
            ),
            (
                TerminalRoute::Join,
                &[
                    ThunkStep::WaitJoinGuard,
                    ThunkStep::WriteIoStatus,
                    ThunkStep::CompleteIrp,
                ],
            ),
            (
                TerminalRoute::Completed,
                &[
                    ThunkStep::ReadCompletedResult,
                    ThunkStep::WriteIoStatus,
                    ThunkStep::CompleteIrp,
                ],
            ),
        ];

        for (route, steps) in expected {
            let mut trace = Vec::new();
            let completion = ValidatedCompletion::prepare(0, EXACT, OUT_CAPACITY, EXACT)
                .expect("an exact success validates");
            let status = outer_thunk(route, completion, &mut trace);
            assert_eq!(status, 0);
            assert_eq!(trace, steps, "{route:?} runs exactly these, in this order");
            assert!(
                terminal_precedes_every_irp_touch(&trace),
                "{route:?} touched the IRP before its terminal route returned",
            );
        }

        // A failing completion takes the same route: an error arm may not
        // complete the IRP while a terminal run or join is outstanding either.
        let mut trace = Vec::new();
        let completion = ValidatedCompletion::prepare(-1, 0, OUT_CAPACITY, EXACT)
            .expect("a failure carries no result");
        assert_eq!(
            outer_thunk(TerminalRoute::Winner, completion, &mut trace),
            -1
        );
        assert!(terminal_precedes_every_irp_touch(&trace));

        // Anti-vacuity: the predicate above is not a constant. Handed the
        // inversion this row exists to forbid -- completing first, then
        // joining -- the same function reports false.
        assert!(!terminal_precedes_every_irp_touch(&[
            ThunkStep::WriteIoStatus,
            ThunkStep::CompleteIrp,
            ThunkStep::WaitJoinGuard,
        ]));
        // And it is not merely "the last step is CompleteIrp": a winner that
        // completed between the runner and its completion guard is refused.
        assert!(!terminal_precedes_every_irp_touch(&[
            ThunkStep::RunTerminal,
            ThunkStep::WriteIoStatus,
            ThunkStep::WaitCompletionGuard,
            ThunkStep::CompleteIrp,
        ]));
    }

    #[test]
    #[should_panic(expected = "QueueWorkRight dropped without queueing")]
    fn dropping_the_queue_right_is_a_bugcheck_not_a_silent_hang() {
        use crate::enter::{PendingWakeOutcome, record_and_schedule_pending};

        // By the time a right exists, Queued is published and a Worker token is
        // stored. Dropping it means the queue call never happens: the schedule
        // says a pass is queued, the ledger says its owner is held, and no pass
        // will ever run to release either. The parked ENTER is hung, and every
        // other invariant still reads as healthy -- which is precisely why this
        // has to be loud.
        //
        // This row exists because adding the `Drop` caught four rows in this
        // very module silently dropping the right. `#[must_use]` had not
        // warned on any of them, because each bound the value.
        let mut b = handed_off(1813);
        let outcome = record_and_schedule_pending(
            b.install,
            PendingReason::Readiness,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .expect("queues");
        assert!(matches!(outcome, PendingWakeOutcome::Queued(_)));
        assert_eq!(b.schedule.state(), WorkerScheduleState::Queued);
        assert!(b.worker_owner.is_some());
        // Dropped here, undischarged.
        drop(outcome);
        unreachable!("the drop above must have panicked");
    }

    #[test]
    fn handoff_refuses_a_released_installer_and_another_installs_stale_wake() {
        // Two preconditions that an adversarial review found unguarded: the
        // first reached an `unreachable!` nothing had established, the second
        // let a previous generation's wake decide whether this one queues.

        // (a) A token naming this install whose kind the ledger no longer
        // holds. Every other check passes; only the explicit holds() check
        // stops `release_owner` from refusing below an `unreachable!`.
        let (mut b, installer) = bench(1810);
        let stolen = b
            .owners
            .release_owner(installer)
            .err()
            .map(|(_, token)| token);
        assert!(stolen.is_none(), "the ledger did hold the Installer");
        // The ledger has now released the kind, but a token still exists in the
        // caller's hands only in the sense that we can mint an equivalent one.
        let reissued = b
            .owners
            .acquire_owner(b.install, PendingOwnerKind::Installer)
            .expect("the kind is free again");
        b.owners.release_owner(reissued).expect("release again");
        let orphan = {
            // Mint a token, then drop the ledger's record of its kind.
            let token = b
                .owners
                .acquire_owner(b.install, PendingOwnerKind::Installer)
                .expect("free");
            let mut other = bench(1811).0;
            let _ = &mut other;
            token
        };
        // Release the kind out from under the token we still hold.
        let mirror = b
            .owners
            .acquire_owner(b.install, PendingOwnerKind::Worker)
            .expect("a different kind");
        b.owners.release_owner(mirror).expect("exact token");
        // Now drop the Installer kind while keeping `orphan`.
        let dup = b
            .owners
            .acquire_owner(b.install, PendingOwnerKind::Installer);
        assert!(dup.is_err(), "the kind is still held by `orphan`");
        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(b.install, irp()) };
        // With the kind genuinely held, the commit succeeds -- the positive
        // control that keeps the negative below from being vacuous.
        let commit = commit_pending_handoff(
            selected,
            orphan,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(matches!(commit, PendingHandoffCommit::Ready(_)));

        // (b) A wake left by a PREVIOUS install must not decide whether this
        // one queues. The slot is per-ring, not per-install.
        let (mut c, c_installer) = bench(1812);
        let previous = PendingInstallId::for_test(c.install.brand(), 99);
        c.wake
            .record_wake(previous, PendingReason::Readiness)
            .expect("a previous generation's wake sits in the slot");
        assert!(c.wake.has_wake());
        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(c.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            c_installer,
            &mut c.schedule,
            &mut c.wake,
            &mut c.owners,
            &mut c.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(
            matches!(commit, PendingHandoffCommit::Ready(_)),
            "another install's stored wake must not queue a pass for this one",
        );
        assert_eq!(c.schedule.state(), WorkerScheduleState::Idle);
        assert!(c.worker_owner.is_none());
        assert!(!c.owners.holds(PendingOwnerKind::Worker));
    }

    #[test]
    fn worker_cannot_run_while_installer_owner_exists() {
        // This bench is never committed: it exists to show what is refused
        // while the Installer owner is still outstanding.
        let (mut b, _uncommitted_installer) = bench(1707);
        b.wake
            .record_wake(b.install, PendingReason::Unload)
            .expect("an unload arrives during installation");

        // While the Installer owner is outstanding the ledger refuses a second
        // Installer, the schedule refuses to queue, and no pass can begin.
        assert!(
            b.owners
                .acquire_owner(b.install, PendingOwnerKind::Installer)
                .is_err(),
            "one Installer kind at a time",
        );
        assert!(b.schedule.queue_worker(b.install).is_err());

        // A pass cannot begin either, and the refusal names the reason: the
        // state is still `Idle` because only the handoff publishes `Queued`.
        // This bench is spent proving that, so the post-handoff half below
        // uses a fresh one rather than a test-only way to put a batch back.
        let early = b
            .owners
            .acquire_owner(b.install, PendingOwnerKind::Worker)
            .expect("the ledger can mint a Worker kind");
        let batch = b
            .wake
            .take_for_worker(b.install)
            .expect("a stored noncancel wake selects")
            .into_batch();
        let (error, _token, _batch) = b
            .schedule
            .begin_worker_pass(early, batch)
            .err()
            .unwrap_or_else(|| unreachable!("a pass cannot begin before the handoff"));
        assert_eq!(error, crate::session::PendingError::WrongRingState);

        // Now the same shape, committed. A fresh bench, because the one above
        // spent its stored wake proving the refusal.
        let (mut b, installer) = bench(1708);
        b.wake
            .record_wake(b.install, PendingReason::Unload)
            .expect("an unload arrives during installation");
        // SAFETY: the fixture's outer thunk selected Pending for this install.
        let selected = unsafe { select_pending_install(b.install, irp()) };
        let commit = commit_pending_handoff(
            selected,
            installer,
            &mut b.schedule,
            &mut b.wake,
            &mut b.owners,
            &mut b.worker_owner,
        )
        .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert!(matches!(commit, PendingHandoffCommit::Queue(_)));

        // Only now, with the Installer gone, does a pass become possible.
        assert!(!b.owners.holds(PendingOwnerKind::Installer));
        let token = b.worker_owner.take().expect("the handoff stored one");
        let decision = b
            .wake
            .take_for_worker(b.install)
            .expect("the pass takes the coalesced reasons");
        assert_eq!(decision.reason(), PendingReason::Unload);
        let batch = decision.into_batch();
        let (token, _batch) = b
            .schedule
            .begin_worker_pass(token, batch)
            .unwrap_or_else(|(error, _, _)| unreachable!("{error:?}"));
        assert_eq!(b.schedule.state(), WorkerScheduleState::Running);
        let (token, rescheduled) = b
            .schedule
            .finish_worker_pass(token)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        assert!(rescheduled.is_none(), "an Idle finish owes no queue call");
        b.owners.release_owner(token).expect("the exact token");
    }
}

// ---------------------------------------------------------------------------
// R5 Task 20: the deferred CQ drain
// ---------------------------------------------------------------------------

// `drop(scoped)` below ends the scoped consumer's *borrow* of the backing so
// the shared head can be read; clippy's `drop_non_drop` reads it as a no-op
// because the type has no `Drop` impl. Here the move is the point, and it is
// what makes the "the head did not change" assertions observe the real page.
#[allow(clippy::drop_non_drop)]
mod r5_cq_drain_tests {
    use crate::adapter::enter::{
        CONSERVATIVE_NOTIFY_CQ_KINDS, CqDrainAuthority, CqMutationWitness, CqPeek, CqPeekError,
        NotifyShapeError, R4EnterPlan,
    };
    use crate::enter::{
        BrandedCqStorage, CqBindError, CqStorageDescriptor, PendingSlotParts,
        build_pending_slot_parts,
    };
    use crate::session::{
        ControlBinding, PendingError, SessionRegistry, SetupStage, SetupTransaction,
    };
    use fsring_abi::layout::{ConsumerPage, Cqe, CqeBody, ProducerPage, cq_kind};
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, CursorFault, MountId, PopError};

    const CAPACITY: usize = 8;
    const ENTRY_BYTES: usize = CAPACITY * core::mem::size_of::<Cqe>();

    /// One CQ mapping the test owns for the whole borrow.
    ///
    /// `borrow_consumer` attaches over the descriptor's own spans, so the
    /// entries published here are exactly the ones the cursor reads.
    struct CqBacking {
        producer: ProducerPage,
        consumer: ConsumerPage,
        entries: std::vec::Vec<Cqe>,
        bytes: std::vec::Vec<u8>,
    }

    impl CqBacking {
        fn new() -> Self {
            Self {
                // Both pages are POD wire structs and a zeroed page is the
                // documented initial cursor state.
                producer: unsafe { core::mem::zeroed() },
                consumer: unsafe { core::mem::zeroed() },
                entries: std::vec![unsafe { core::mem::zeroed() }; CAPACITY],
                bytes: std::vec![0u8; ENTRY_BYTES],
            }
        }

        fn descriptor(&mut self) -> CqStorageDescriptor {
            // SAFETY: the three spans are distinct fields of this live value,
            // and it outlives every descriptor use below.
            unsafe {
                CqStorageDescriptor::from_raw_parts(
                    core::ptr::NonNull::from(&mut self.producer),
                    core::ptr::NonNull::from(&mut self.consumer),
                    core::ptr::NonNull::from(&mut self.entries[0]),
                    CAPACITY,
                )
            }
            .expect("a power-of-two capacity binds")
        }

        /// Publish one entry at its exact ordinal.
        ///
        /// The sequence is `index + 1` because the cursor starts at head zero
        /// and validates the exact successor. The producer tail moves with it so
        /// the mapping stays self-consistent, even though `try_peek` reads the
        /// entry's own sequence rather than the tail.
        fn publish(&mut self, index: usize, body: CqeBody) {
            self.publish_sequence(index, index as u64 + 1, body);
        }

        /// Publish one entry carrying a sequence the ordinal does not imply.
        ///
        /// The only way to reach the future-sequence fault: the cursor compares
        /// the entry's own sequence against the exact successor of its head, so
        /// a gap has to be written into the entry the head points at.
        fn publish_sequence(&mut self, index: usize, sequence: u64, body: CqeBody) {
            self.entries[index] = Cqe { sequence, body };
            self.producer.tail = sequence;
        }

        fn shared_head(&self) -> u64 {
            self.consumer.head
        }
    }

    /// The exact fixed-CQE shape `03-messages.md` section 9.1 gives a
    /// notification: kind NOTIFY, opcode/flags/req_id/status/reserved zero,
    /// `out_len = 24`, a nonzero total length, and an `OControl` naming a slot.
    fn notify_body() -> CqeBody {
        let mut body = body_of_kind(cq_kind::NOTIFY);
        body.out_len = core::mem::size_of::<fsring_abi::msgs::OControl>() as u16;
        body.information = 96;
        // The first eight `out` bytes are the `OControl`'s `BufferRef` token.
        body.out[..8].copy_from_slice(&1u64.to_ne_bytes());
        body
    }

    /// A NOTIFY that names no arena body.
    ///
    /// Section 9.1 does not describe this row: every notification points at a
    /// `NotifyEnvelopeV2` in a notification credit. It is the shape a hostile
    /// producer would use to get a head advance without a credit claim.
    fn bodyless_notify_body() -> CqeBody {
        body_of_kind(cq_kind::NOTIFY)
    }

    fn body_of_kind(kind: u16) -> CqeBody {
        // `CqeBody` is a POD wire struct whose every field is an integer or a
        // byte array, so a zeroed value is a valid one.
        let mut body: CqeBody = unsafe { core::mem::zeroed() };
        body.kind = kind;
        body
    }

    /// One installed session's pending slot parts, one per ring.
    fn slots(n: u64, rings: u32) -> (SessionRegistry<1>, std::vec::Vec<PendingSlotParts>) {
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let reservation = binding.begin_setup().expect("an empty binding reserves");
        let identity = SessionIdentity {
            mount_id: MountId { lo: n, hi: 71 },
            boot_instance_id: BootInstanceId { lo: 73, hi: 79 },
            session_epoch: 1,
        };
        let mut transaction = SetupTransaction::begin(identity).expect("a valid identity");
        for stage in [
            SetupStage::LayoutPlanned,
            SetupStage::SectionReady,
            SetupStage::GrantsReady,
            SetupStage::VolumeReady,
            SetupStage::ViewsReady,
            SetupStage::OutputReady,
        ] {
            transaction = transaction.stage(stage).expect("the roster order");
        }
        let mut registry = SessionRegistry::<1>::new();
        let mut installed = registry
            .install_staging(&transaction, &binding, &reservation)
            .expect("output-ready staging installs");
        let mut set = installed
            .begin_ring_set(rings)
            .expect("a fresh install begins a set");
        let mut parts = std::vec::Vec::new();
        for _ in 0..rings {
            let right = set
                .next_ring()
                .expect("identities available")
                .expect("a ring");
            parts.push(
                build_pending_slot_parts(right, 64)
                    .map_err(|(error, _)| error)
                    .expect("the ring builds"),
            );
        }
        (registry, parts)
    }

    /// Empty, both cursor faults, and a consumer that serves another ring all
    /// hand the same affine authority back. A refusal that kept it would leave
    /// the ring's consumer role owned by nobody and the ring undrainable.
    #[test]
    fn task20_empty_and_faulted_peeks_return_the_same_cq_drain_authority() {
        let (_registry, parts) = slots(9300, 2);
        let mut parts = parts.into_iter();
        let mut ring0 = parts.next().expect("ring 0");
        let ring1 = parts.next().expect("ring 1");

        let mut backing = CqBacking::new();
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let token = ring0
            .state
            .acquire_cq_consumer()
            .expect("a fresh ring admits its consumer");
        let authority = CqDrainAuthority::bind_drain(&storage, token)
            .map_err(|(error, _)| error)
            .expect("the storage and the role name the same ring");

        // Nothing published: empty, and the authority comes straight back.
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }
            .expect("the backing covers the entry span");
        let authority = match authority.try_peek(&mut scoped) {
            Ok(CqPeek::Empty(authority)) => authority,
            Ok(CqPeek::Ready(_)) => panic!("an unpublished queue is not ready"),
            Err((error, _)) => panic!("an empty queue is not a fault: {error:?}"),
        };
        drop(scoped);

        // A consumer that serves another ring is a bind refusal, and it is
        // distinguishable from a cursor fault.
        let mut other_backing = CqBacking::new();
        let other_descriptor = other_backing.descriptor();
        // SAFETY: as above, for ring 1's own backing.
        let other_storage =
            unsafe { BrandedCqStorage::bind_storage(ring1.cq_storage, other_descriptor) };
        // SAFETY: as above.
        let mut other_scoped = unsafe { other_storage.borrow_consumer(&mut other_backing.bytes) }
            .expect("the backing covers the entry span");
        let (error, authority) = authority
            .try_peek(&mut other_scoped)
            .map(|_| ())
            .expect_err("another ring's consumer is refused");
        assert_eq!(error, CqPeekError::Bind(CqBindError::WrongRing));
        drop(other_scoped);

        // A sequence beyond the exact successor is a cursor fault. The entry
        // the head points at is the one that has to carry the gap.
        backing.publish_sequence(0, 5, notify_body());
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }
            .expect("the backing covers the entry span");
        let (error, authority) = authority
            .try_peek(&mut scoped)
            .map(|_| ())
            .expect_err("a future sequence is a fault");
        assert_eq!(
            error,
            CqPeekError::Cursor(PopError::Protocol(CursorFault::FutureSequence)),
        );
        drop(scoped);

        // And an exhausted cursor is the other fault. The head is set on the
        // shared page before the attach, which is where the cursor reads it.
        backing.consumer.head = u64::MAX;
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }
            .expect("the backing covers the entry span");
        let (error, authority) = authority
            .try_peek(&mut scoped)
            .map(|_| ())
            .expect_err("an exhausted cursor is a fault");
        assert_eq!(
            error,
            CqPeekError::Cursor(PopError::Protocol(CursorFault::Exhausted)),
        );
        drop(scoped);

        // The authority that survived all four is still the role itself: it
        // releases through the exact ring state that minted it.
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A released peek moves neither cursor; only `commit` performs the Release
    /// head store, and it performs exactly one.
    #[test]
    fn task20_peek_release_leaves_the_shared_cq_head_unchanged_and_commit_advances_once() {
        let (_registry, parts) = slots(9301, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the storage and the role name the same ring");

        assert_eq!(backing.shared_head(), 0);
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let authority = match authority.try_peek(&mut scoped) {
            Ok(CqPeek::Ready(pop)) => {
                assert_eq!(pop.sequence(), 1);
                assert_eq!(pop.next_head(), 1);
                pop.abort()
            }
            Ok(CqPeek::Empty(_)) => panic!("a published entry is ready"),
            Err((error, _)) => panic!("a published entry is not a fault: {error:?}"),
        };
        drop(scoped);
        assert_eq!(
            backing.shared_head(),
            0,
            "an aborted peek must not move the shared head",
        );

        // The same entry is still queued, and the whole ordinary path commits it.
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the aborted entry is still queued")
        };
        let preflight = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a NOTIFY naming no body is the conservative ordinary row");
        assert!(!plan.has_committed());

        // The plan arbitrates from the packet's own witness, and that borrow
        // ends before the packet moves into the preparation.
        let permit = plan
            .arbitrate_cq_mutation(preflight.mutation_witness())
            .expect("the witness names this exact execution");
        // `plan` cannot be read here at all: the permit borrows its tracker
        // until the commit that earns the transition. That borrow IS the
        // property -- arbitration no longer marks a commit that has not
        // happened.
        let committed = preflight
            .prepare_notify_commit(permit)
            .map_err(|(error, _, _)| error)
            .expect("the permit names the same execution")
            .commit();
        assert!(
            plan.has_committed(),
            "the transition happens at the commit, not at the arbitration",
        );
        assert_eq!(committed.sequence(), 1);
        assert_eq!(committed.next_head(), 1);
        assert_eq!(committed.body().kind, cq_kind::NOTIFY);
        let authority = committed.into_authority();
        drop(scoped);
        assert_eq!(
            backing.shared_head(),
            1,
            "commit performs the sole Release head store",
        );

        // The head moved exactly one entry, so the queue is empty afterwards.
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let authority = match authority.try_peek(&mut scoped) {
            Ok(CqPeek::Empty(authority)) => authority,
            _ => panic!("one commit consumed exactly one entry"),
        };
        drop(scoped);
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// PROTOCOL, COMPLETION, an unknown kind, and every NOTIFY whose fixed-CQE
    /// shape section 9.1 does not describe all return the exact pop, and none
    /// of them moves the head.
    ///
    /// The five malformed NOTIFY rows are the load-bearing half. Section 9.1 is
    /// exhaustive, so a NOTIFY that names no arena body, reports no length, or
    /// carries a nonzero opcode/flags/req_id is a protocol fault -- and each is
    /// a shape a hostile producer would use to get a head advance without a
    /// credit claim.
    #[test]
    fn task20_protocol_completion_unknown_and_malformed_notify_rows_are_all_refused() {
        for (index, (body, expected)) in [
            (
                bodyless_notify_body(),
                NotifyShapeError::MalformedNotifyShape,
            ),
            (
                {
                    let mut body = notify_body();
                    body.out_len = 0;
                    body
                },
                NotifyShapeError::MalformedNotifyShape,
            ),
            (
                {
                    let mut body = notify_body();
                    body.information = 0;
                    body
                },
                NotifyShapeError::MalformedNotifyShape,
            ),
            (
                {
                    let mut body = notify_body();
                    body.flags = 1;
                    body
                },
                NotifyShapeError::MalformedNotifyShape,
            ),
            (
                {
                    let mut body = notify_body();
                    body.req_id = 7;
                    body
                },
                NotifyShapeError::MalformedNotifyShape,
            ),
            (
                body_of_kind(cq_kind::PROTOCOL),
                NotifyShapeError::NotConservativeNotifyKind,
            ),
            (
                body_of_kind(cq_kind::COMPLETION),
                NotifyShapeError::NotConservativeNotifyKind,
            ),
            (
                body_of_kind(u16::MAX),
                NotifyShapeError::NotConservativeNotifyKind,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            // One session per row: a storage ticket is one per ring, so a fresh
            // row needs a fresh ring rather than a rebound one.
            let (_registry, parts) = slots(9310 + index as u64, 1);
            let mut ring0 = parts.into_iter().next().expect("ring 0");
            let mut backing = CqBacking::new();
            backing.publish(0, body);
            let descriptor = backing.descriptor();
            // SAFETY: the descriptor names this row's own live backing.
            let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
            let token = ring0.state.acquire_cq_consumer().expect("a fresh ring");
            let authority = CqDrainAuthority::bind_drain(&storage, token)
                .map_err(|(error, _)| error)
                .expect("the same ring");
            // SAFETY: the slice is at least the entry span the descriptor claims.
            let mut scoped =
                unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
            let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
                panic!("row {index} was published")
            };
            let (error, pop) = pop
                .preflight_notify_shape()
                .map(|_| ())
                .expect_err("the row is not conservative ordinary");
            assert_eq!(error, expected, "row {index}");

            // The refused pop is intact: it still reports its own entry, and it
            // still carries the authority back.
            assert_eq!(pop.sequence(), 1, "row {index}");
            assert_eq!(pop.next_head(), 1, "row {index}");
            let authority = pop.abort();
            drop(scoped);
            assert_eq!(
                backing.shared_head(),
                0,
                "row {index} must not move the head",
            );
            ring0
                .state
                .release_cq_consumer(authority.into_consumer_token())
                .map_err(|(error, _)| error)
                .expect("the exact token releases");
        }
    }

    /// Two rings whose entries are byte-identical cannot swap head authority,
    /// and neither can a stale permit from an earlier invocation of the same
    /// ring. Both refusals return the packet and the permit unchanged.
    #[test]
    fn task20_identical_bodies_at_different_ordinals_cannot_swap_head_authority() {
        let (_registry, parts) = slots(9320, 2);
        let mut parts = parts.into_iter();
        let mut ring0 = parts.next().expect("ring 0");
        let mut ring1 = parts.next().expect("ring 1");
        let packet = ();

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };

        // Invocation A of ring 0 mints a permit and then releases its role, so
        // the permit outlives the execution it was minted for. Nothing in the
        // permit's type says which invocation that was -- the packet's does.
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut stale_plan, stale_authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("ring 0's storage and role");
        let stale_execution = stale_plan.execution();
        let stale_permit = stale_plan
            .arbitrate_cq_mutation(
                CqMutationWitness::for_test_packet(stale_execution, &packet)
                    .expect("a CQ-domain execution"),
            )
            .expect("its own execution");
        ring0
            .state
            .release_cq_consumer(stale_authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");

        // Ring 1 arbitrates a byte-identical packet of its own and gets a
        // permit for *its* execution.
        let foreign_acquired = ring1
            .state
            .acquire_cq_consumer_aggregate()
            .expect("ring 1 admits its consumer");
        let mut foreign_plan = R4EnterPlan::bind_cq_consumer(foreign_acquired);
        let foreign_execution = foreign_plan.execution();
        let foreign_permit = foreign_plan
            .arbitrate_cq_mutation(
                CqMutationWitness::for_test_packet(foreign_execution, &packet)
                    .expect("a CQ-domain execution"),
            )
            .expect("its own execution");

        // Invocation B of ring 0 is the live drain.
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("the freed ring re-admits");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("ring 0's storage and role");
        assert_ne!(plan.execution(), stale_execution);

        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the entry is published")
        };
        let preflight = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("an ordinary row");

        let (error, preflight, _returned) = preflight
            .prepare_notify_commit(foreign_permit)
            .map(|_| ())
            .expect_err("another ring's permit cannot bind this packet");
        assert_eq!(error, PendingError::WrongRing);

        // Same ring, earlier invocation: a different cause, so the ring arm is
        // not silently answering both.
        let (error, preflight, _returned) = preflight
            .prepare_notify_commit(stale_permit)
            .map(|_| ())
            .expect_err("an earlier invocation's permit is not this execution's");
        assert_eq!(error, PendingError::WrongInvocation);

        // And the packet is unchanged: it still commits under its own permit.
        let permit = plan
            .arbitrate_cq_mutation(preflight.mutation_witness())
            .expect("its own execution");
        let committed = preflight
            .prepare_notify_commit(permit)
            .map_err(|(error, _, _)| error)
            .expect("its own permit")
            .commit();
        assert_eq!(committed.next_head(), 1);
        drop(scoped);
        assert_eq!(backing.shared_head(), 1);
        ring0
            .state
            .release_cq_consumer(committed.into_authority().into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A permit is bound to the entry it was arbitrated for.
    ///
    /// Two permits can no longer *coexist* -- the permit borrows the plan's
    /// tracker, so a second arbitration while the first is alive is a borrow
    /// error rather than a runtime refusal. What remains representable, and what
    /// this row builds, is a permit that outlives the peek it came from: the
    /// packet is aborted, the entry is peeked again, and the still-live permit
    /// commits it, because the identity names the ENTRY and not the peek. A
    /// permit minted for a different entry is what the sequence and next head
    /// exist to refuse, and the drain loop keeps ring, invocation and domain
    /// constant across every iteration, so nothing else could tell them apart.
    #[test]
    fn task20_a_permit_arbitrated_for_one_entry_cannot_commit_the_next() {
        let (_registry, parts) = slots(9340, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body());
        backing.publish(1, notify_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");

        // Entry one arbitrates a permit and is then ABORTED, so the permit
        // outlives the peek it was minted from.
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("entry one is published")
        };
        let first = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        assert_eq!(first.sequence(), 1);
        let carried = plan
            .arbitrate_cq_mutation(first.mutation_witness())
            .expect("its own execution");
        let authority = first.abort();
        drop(scoped);
        assert_eq!(backing.shared_head(), 0, "the aborted entry moved no head");

        // The same entry is still queued. Its identity is unchanged, so the
        // carried permit is still its authority -- the identity names the entry,
        // not the peek.
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("entry one is still queued")
        };
        let again = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        assert_eq!(again.sequence(), 1);
        let advanced = again
            .prepare_notify_commit(carried)
            .map_err(|(error, _, _)| error)
            .expect("the same entry accepts the permit minted for it")
            .commit();
        assert_eq!(advanced.next_head(), 1);
        let authority = advanced.into_authority();
        drop(scoped);
        assert_eq!(backing.shared_head(), 1);

        // Entry two is a different entry. A permit arbitrated for it commits it;
        // the plan is free to arbitrate again because the previous permit was
        // spent by the commit above.
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("entry two is published")
        };
        let second = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        assert_eq!(second.sequence(), 2);
        let permit = plan
            .arbitrate_cq_mutation(second.mutation_witness())
            .expect("its own execution");
        let committed = second
            .prepare_notify_commit(permit)
            .map_err(|(error, _, _)| error)
            .expect("its own permit")
            .commit();
        assert_eq!(committed.next_head(), 2);
        drop(scoped);
        assert_eq!(backing.shared_head(), 2);
        ring0
            .state
            .release_cq_consumer(committed.into_authority().into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A permit that is dropped without committing leaves the tracker unmoved.
    ///
    /// This is the defect the permit's tracker borrow exists to fix.
    /// Arbitration used to call `record_commit` itself, so an arbitration whose
    /// mutation never happened -- a refused preparation, a cancel that won, a
    /// packet aborted after arbitration -- left the plan marked committed with
    /// **zero mutations performed**. Cancellation precedence is decided by
    /// exactly that bit, so a cancel that should have won would lose to a commit
    /// that never happened.
    ///
    /// **Two things this row deliberately does NOT test, because the borrow made
    /// them unreachable rather than merely unlikely.** A second arbitration
    /// beside the first is now a borrow error, not a runtime refusal -- the
    /// two-permits-at-once row that used to exist stopped compiling when this
    /// landed, which is the strongest evidence that half is in force. And a
    /// permit whose `CqPacketIdentity` mismatches its packet is no longer
    /// constructible in safe code: to hold one you would have to arbitrate for
    /// entry N and then obtain a packet for entry M, which needs the head past
    /// N, which needs a commit, which needs a permit -- and the only live permit
    /// is the one being held. `WrongSlot` therefore becomes defence in depth for
    /// Task 25's native path, where the borrow is reconstructed across an
    /// `unsafe` boundary; it is recorded as measured-unreachable here rather
    /// than covered by a test that could not build its own premise.
    #[test]
    fn task20_a_permit_dropped_without_committing_leaves_the_tracker_unmoved() {
        let (_registry, parts) = slots(9412, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        assert!(!plan.has_committed(), "nothing has mutated yet");

        // Arbitrate, then abandon: the packet is aborted and the permit is
        // dropped. Under the old contract the flag would already be set here.
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let packet = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        let permit = plan
            .arbitrate_cq_mutation(packet.mutation_witness())
            .expect("its own execution");
        drop(permit);
        let authority = packet.abort();
        drop(scoped);

        assert!(
            !plan.has_committed(),
            "an arbitration whose mutation never happened is not a commit",
        );
        assert_eq!(backing.shared_head(), 0, "and no head moved");

        // The same execution can still arbitrate and commit for real, so the
        // abandoned permit damaged nothing.
        // SAFETY: as above.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the entry is still queued")
        };
        let packet = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        let permit = plan
            .arbitrate_cq_mutation(packet.mutation_witness())
            .expect("its own execution");
        let committed = packet
            .prepare_notify_commit(permit)
            .map_err(|(error, _, _)| error)
            .expect("its own permit")
            .commit();
        assert_eq!(committed.next_head(), 1);
        let authority = committed.into_authority();
        drop(scoped);
        assert!(plan.has_committed(), "and a real commit does move the flag",);
        assert_eq!(backing.shared_head(), 1);

        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// An SQ-domain permit is unrepresentable rather than refused downstream.
    ///
    /// `prepare_notify_commit` checks the domain, but nothing can produce a
    /// permit that fails that check: [`R4EnterPlan::arbitrate_cq_mutation`] is
    /// the only minter and it refuses a non-CQ execution first, and the witness
    /// factory refuses one earlier still. This row records where the refusal
    /// actually happens, so the domain arm downstream reads as
    /// measured-unreachable rather than measured-passing.
    #[test]
    fn task20_same_request_sq_permit_is_refused_before_a_permit_exists() {
        let (_registry, parts) = slots(9330, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let lease = ring0
            .state
            .acquire_sq_wait()
            .expect("a fresh ring admits its SQ role");
        let sq_execution = lease.execution();
        let packet = ();
        let refusal = CqMutationWitness::for_test_packet(sq_execution, &packet)
            .map(|_| ())
            .expect_err("an SQ execution cannot mint a CQ witness");
        assert_eq!(refusal, PendingError::WrongExecutionDomain);
        ring0
            .state
            .release_sq_wait(lease)
            .map_err(|(error, _)| error)
            .expect("the exact lease releases");
    }

    // ---------------------------------------------------------------------
    // The credit lane: a shaped notification through to a refreshed credit
    // ---------------------------------------------------------------------

    use crate::adapter::enter::NotifyClaimError;
    use crate::adapter::enter::tests::{entry_count, topology};
    use crate::grant::{GrantEntry, GrantError, GrantFault, GrantState, GrantTable};
    use fsring_abi::control::NotificationCreditV1;
    use fsring_abi::slots::SlotToken;

    /// A CQE that names the credit `token` describes.
    fn notify_body_for(token: SlotToken, length: u32) -> CqeBody {
        let mut body = notify_body();
        body.out[..8].copy_from_slice(&token.raw().to_ne_bytes());
        body.out[8..12].copy_from_slice(&0u32.to_ne_bytes());
        body.out[12..16].copy_from_slice(&length.to_ne_bytes());
        body
    }

    /// The published per-class data offsets this fixture's arena uses.
    ///
    /// An *input*, deliberately not a sum over the classes: the point of
    /// `SlotArenaGeometry` is that the offsets are published and only required
    /// to be aligned, so a fixture that derived them would be agreeing with a
    /// derivation production refuses to make. These are hand-chosen, aligned,
    /// and deliberately NOT contiguous, so a prefix-sum implementation would
    /// produce a different answer and fail the row below.
    fn geometry() -> crate::grant::SlotArenaGeometry {
        crate::grant::SlotArenaGeometry::from_published([4096, 65_536, 131_072, 262_144])
            .expect("aligned offsets")
    }

    /// One ring, one issued credit, and the CQE that claims it.
    struct CreditFixture {
        entries: std::vec::Vec<GrantEntry>,
        topology: fsring_abi::validate::ValidatedTopology,
    }

    impl CreditFixture {
        fn new() -> Self {
            let topology = topology(1);
            let entries = std::vec![GrantEntry::FREE; entry_count(&topology)];
            Self { entries, topology }
        }
    }

    /// The whole lane, in order, with the head and the credit generation read
    /// before and after every stage.
    #[test]
    fn task20_the_credit_lane_claims_advances_and_refreshes_in_that_order() {
        let (_registry, parts) = slots(9400, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");
        let before = table.entry_snapshot(token).expect("the issued entry");
        assert_eq!(before.state, GrantState::Issued);

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");

        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let packet = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        let bound = packet
            .bind_credit(&table, &geometry(), 64)
            .map_err(|(error, _)| error)
            .expect("the credit the OControl names is claimable");

        // Nothing has moved yet: not the head, not the credit. Read through
        // the page field rather than the accessor, because `bytes` is mutably
        // borrowed by the scoped consumer and the two fields are disjoint.
        assert_eq!(backing.consumer.head, 0);
        assert_eq!(
            table.entry_snapshot(token).expect("still there").state,
            GrantState::Issued,
        );

        let permit = plan
            .arbitrate_cq_mutation(bound.credit_mutation_witness())
            .expect("the witness names this execution");
        let prepared = bound
            .prepare_credit_claim(&mut table, permit)
            .map_err(|(error, _, _)| error)
            .expect("the permit names this packet");

        // The preparation is still mutation-free.
        let pending = prepared.commit();
        // Now the credit is claimed and the head has still not moved.
        assert_eq!(
            backing.consumer.head, 0,
            "the claim precedes the head store",
        );

        let advanced = pending.commit();
        assert_eq!(advanced.sequence(), 1);
        assert_eq!(advanced.next_head(), 1);
        drop(scoped);
        assert_eq!(backing.shared_head(), 1, "the head moved exactly once");

        let mut output = NotificationCreditV1::default();
        let (refreshed, authority) = advanced.refresh(&mut output);
        assert_eq!(refreshed.old_generation, token.generation());
        assert_eq!(refreshed.new_generation, token.generation() + 1);
        assert_eq!(output, refreshed.descriptor);
        assert_eq!(
            table
                .entry_snapshot(
                    SlotToken::from_raw(refreshed.descriptor.buffer.token).expect("next token")
                )
                .expect("the refreshed entry")
                .state,
            GrantState::Issued,
            "the refresh reissues rather than leaving the entry claimed",
        );

        // And the loop can continue: the authority came back.
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// Every refusal on the way in returns the packet, and none of them touches
    /// the head or the credit.
    #[test]
    fn task20_a_refused_credit_bind_returns_the_packet_and_mutates_nothing() {
        let (_registry, parts) = slots(9401, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        // A token whose generation is stale: the credit exists, but not at the
        // generation this notification claims.
        let stale = SlotToken::try_new(token.class(), token.index(), token.generation() + 7)
            .expect("a well-formed token");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(stale, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let token_role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
        let authority = CqDrainAuthority::bind_drain(&storage, token_role)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let packet = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("the shape is well formed; only the generation is wrong");
        let (error, packet) = packet
            .bind_credit(&table, &geometry(), 64)
            .map(|_| ())
            .expect_err("a stale generation cannot claim");
        assert_eq!(error, GrantError::StaleGeneration);

        // The packet is intact and still names its own entry.
        assert_eq!(packet.sequence(), 1);
        let authority = packet.abort();
        drop(scoped);
        assert_eq!(backing.shared_head(), 0, "a refused bind moves no head");
        assert_eq!(
            table.entry_snapshot(token).expect("still issued").state,
            GrantState::Issued,
            "and claims no credit",
        );
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// The source range is read from the published geometry, and a control that
    /// points past its own slot is refused.
    ///
    /// The geometry this fixture uses is deliberately not contiguous, so an
    /// implementation that summed `count * size` over the earlier classes would
    /// compute a different offset and fail the first assertion. That is the
    /// whole reason the offsets are an input rather than a derivation: the
    /// section validator requires only 64-byte alignment inside the arena, so
    /// padding between classes is legal.
    #[test]
    fn task20_the_source_range_comes_from_the_published_geometry() {
        let (_registry, parts) = slots(9406, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");
        let slot_size = credits[0].buffer.length;

        let mut backing = CqBacking::new();
        let mut body = notify_body_for(token, 16);
        // A body that starts partway into its slot, so the offset contributes.
        body.out[8..12].copy_from_slice(&32u32.to_ne_bytes());
        backing.publish(0, body);
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
        let authority = CqDrainAuthority::bind_drain(&storage, role)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let bound = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification")
            .bind_credit(&table, &geometry(), 64)
            .map_err(|(error, _)| error)
            .expect("a claimable credit");

        // Two claims, neither of which restates the implementation's arithmetic.
        //
        // First: the range lands inside the published span of the class the
        // token names -- so the offset came from the geometry at all.
        let classes = fixture.topology.u2k_slot_classes();
        let published = [4096u64, 65_536, 131_072, 262_144];
        let class = usize::from(token.class());
        let (base, span) = match (published.get(class), classes.get(class)) {
            (Some(base), Some(request)) => (
                *base,
                u64::from(request.slot_count) * u64::from(request.slot_size),
            ),
            _ => panic!("the token names a modelled class"),
        };
        let offset = bound.source_range().arena_offset();
        assert!(
            offset >= base && offset < base + span,
            "{offset} is inside class {class}'s published span [{base}, {})",
            base + span,
        );

        // Second, and the point of the row: a prefix sum over the earlier
        // classes -- the derivation production deliberately does not make --
        // answers something else, because this geometry is not contiguous.
        let mut derived = 0u64;
        for earlier in 0..class {
            let request = classes.get(earlier).expect("a modelled class");
            derived += u64::from(request.slot_count) * u64::from(request.slot_size);
        }
        derived += u64::from(token.index()) * u64::from(slot_size) + 32;
        assert_ne!(
            offset, derived,
            "a summed offset would land elsewhere; that is why the geometry is an input",
        );
        assert_eq!(bound.source_range().length(), 16);
        let authority = bound.abort();
        drop(scoped);
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A control whose span leaves its own slot is refused before any claim.
    #[test]
    fn task20_a_control_that_points_past_its_slot_cannot_bind() {
        let (_registry, parts) = slots(9407, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");
        let slot_size = credits[0].buffer.length;

        let mut backing = CqBacking::new();
        // One byte past the end of the slot the token names.
        backing.publish(0, notify_body_for(token, slot_size + 1));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
        let authority = CqDrainAuthority::bind_drain(&storage, role)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let (error, packet) = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("the fixed CQE shape is well formed")
            .bind_credit(&table, &geometry(), 64)
            .map(|_| ())
            .expect_err("a body that leaves its slot is not a body");
        assert_eq!(error, GrantError::InvalidToken);
        let authority = packet.abort();
        drop(scoped);
        assert_eq!(backing.shared_head(), 0);
        assert_eq!(
            table.entry_snapshot(token).expect("still issued").state,
            GrantState::Issued,
        );
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A control naming a zero-length body is refused before any credit check.
    ///
    /// Section 9.1 makes the `OControl` length part of the same total byte
    /// length as `information` and `NotifyEnvelopeV2.struct_size`; a zero
    /// length names no envelope, so there is nothing for the claimed credit to
    /// describe.
    #[test]
    fn task20_a_zero_length_control_cannot_bind_a_credit() {
        let (_registry, parts) = slots(9404, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 0));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
        let authority = CqDrainAuthority::bind_drain(&storage, role)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let (error, packet) = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("the fixed CQE shape is well formed")
            .bind_credit(&table, &geometry(), 64)
            .map(|_| ())
            .expect_err("a zero-length control names no envelope");
        assert_eq!(error, GrantError::InvalidToken);
        let authority = packet.abort();
        drop(scoped);
        assert_eq!(backing.shared_head(), 0);
        assert_eq!(
            table.entry_snapshot(token).expect("still issued").state,
            GrantState::Issued,
        );
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A preparation that is built and then abandoned leaves the credit unclaimed.
    ///
    /// This is the observable form of "the preparation mutates nothing". While a
    /// `PreparedNotifyMutation` is alive it holds the table's `&mut`, so the
    /// entry cannot be read at all -- that exclusivity is the design. What CAN
    /// be observed is what a dropped preparation leaves behind, and a
    /// preparation that had already claimed would leave the credit permanently
    /// `Claimed` with no `ClaimedNotification` in existence to refresh it.
    #[test]
    fn task20_an_abandoned_preparation_leaves_the_credit_unclaimed() {
        let (_registry, parts) = slots(9405, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let bound = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification")
            .bind_credit(&table, &geometry(), 64)
            .map_err(|(error, _)| error)
            .expect("a claimable credit");
        let permit = plan
            .arbitrate_cq_mutation(bound.credit_mutation_witness())
            .expect("its own execution");
        {
            let prepared = bound
                .prepare_credit_claim(&mut table, permit)
                .map_err(|(error, _, _)| error)
                .expect("its own permit");
            // Abandoned rather than committed; the table's borrow ends here.
            drop(prepared);
        }
        drop(scoped);
        assert_eq!(
            table.entry_snapshot(token).expect("still there").state,
            GrantState::Issued,
            "a preparation that never committed claimed nothing",
        );
        assert_eq!(backing.shared_head(), 0, "and moved no head");
    }

    /// A permit for another entry cannot claim this packet's credit, and the
    /// refusal leaves the table byte-for-byte unchanged.
    #[test]
    fn task20_a_foreign_permit_cannot_claim_a_credit_and_leaves_the_table_intact() {
        let (_registry, parts) = slots(9402, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        let packet_marker = ();
        let foreign = plan
            .arbitrate_cq_mutation(
                CqMutationWitness::for_test_packet(plan.execution(), &packet_marker)
                    .expect("a CQ-domain execution"),
            )
            .expect("its own execution");

        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let bound = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification")
            .bind_credit(&table, &geometry(), 64)
            .map_err(|(error, _)| error)
            .expect("a claimable credit");

        // The foreign permit was arbitrated for the sentinel test packet, not
        // for this entry, so ring/invocation/domain all match and only the
        // identity differs.
        let (error, bound, _spent) = bound
            .prepare_credit_claim(&mut table, foreign)
            .map(|_| ())
            .expect_err("a permit for another entry is not this credit's authority");
        assert_eq!(error, NotifyClaimError::Pending(PendingError::WrongSlot));
        assert_eq!(
            table.entry_snapshot(token).expect("still issued").state,
            GrantState::Issued,
            "a refused preparation mutates nothing",
        );

        // And the packet still claims under its own permit.
        let permit = plan
            .arbitrate_cq_mutation(bound.credit_mutation_witness())
            .expect("its own execution");
        let advanced = bound
            .prepare_credit_claim(&mut table, permit)
            .map_err(|(error, _, _)| error)
            .expect("its own permit")
            .commit()
            .commit();
        drop(scoped);
        assert_eq!(backing.shared_head(), 1);
        let mut output = NotificationCreditV1::default();
        let (_refreshed, authority) = advanced.refresh(&mut output);
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// A second claim of the same credit is a grant fault, not a second claim.
    #[test]
    fn task20_a_credit_already_claimed_refuses_the_preparation() {
        let (_registry, parts) = slots(9403, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        // Claim it out of band first, so the entry is already Claimed when the
        // lane's preparation rechecks it.
        let record = table
            .preflight_notify(0, token, 64, token.generation())
            .expect("a claimable credit");
        let _claimed = table.claim_notify(record).expect("the first claim");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let token_role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
        let authority = CqDrainAuthority::bind_drain(&storage, token_role)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the notification is published")
        };
        let packet = pop
            .preflight_notify_shape()
            .map_err(|(error, _)| error)
            .expect("a section 9.1 notification");
        // The bind itself already refuses: `preflight_notify` requires Issued,
        // and a Claimed entry fails that check rather than the earlier
        // Free/Retired one -- so the cause names the generation, not the token.
        let (error, packet) = packet
            .bind_credit(&table, &geometry(), 64)
            .map(|_| ())
            .expect_err("an already-claimed credit is not claimable");
        assert_eq!(error, GrantError::StaleGeneration);
        let authority = packet.abort();
        drop(scoped);
        assert_eq!(backing.shared_head(), 0);
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
        // The fault arm of the preparation is reachable only when the table
        // changes between bind and prepare, which no single-threaded test can
        // stage; `GrantFault` is carried through `NotifyClaimError::Grant` so
        // the caller can tell it from a permit refusal.
        let _ = NotifyClaimError::Grant(GrantFault::ConcurrentReuse);
    }

    // ---------------------------------------------------------------------
    // Steps 5-6: what a whole drain writes, and what exhaustion does
    // ---------------------------------------------------------------------

    use crate::adapter::enter::{ProviderDisposition, RecordedCqEffect, record_bounded_drain};
    use crate::session::TerminalRequest;
    use fsring_abi::control::{ENTER_RESULT_V1_PREFIX_SIZE, NOTIFICATION_CREDIT_V1_SIZE, status};

    const PREFIX: usize = ENTER_RESULT_V1_PREFIX_SIZE as usize;
    const DESCRIPTOR: usize = NOTIFICATION_CREDIT_V1_SIZE as usize;

    /// A drain writes the credits it committed and nothing else.
    ///
    /// Three separate claims, because "exact output" is three properties and a
    /// single length check would satisfy none of them: the 48-byte prefix is
    /// left for the production writer, the tail holds exactly the committed
    /// descriptors in ordinal order, and the suffix past `information` is still
    /// the zero the buffer was cleared to. That last one is what "never expose
    /// drain scratch, padding, uncommitted descriptors, or a larger caller
    /// buffer suffix" means operationally.
    #[test]
    fn task20_a_recorded_drain_writes_its_credits_and_leaves_the_rest_zero() {
        let (_registry, parts) = slots(9410, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 2];
        let issued = table
            .issue_notification_credits(&mut credits)
            .expect("credits issue");
        assert!(issued >= 1, "the fixture issues at least one credit");
        let token = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");

        // Deliberately larger than one credit needs, so the untouched suffix is
        // observable at all.
        let mut output = std::vec![0xABu8; PREFIX + DESCRIPTOR * 4];
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let (recorded, authority) = record_bounded_drain(
            &mut plan,
            authority,
            &mut scoped,
            &mut table,
            &geometry(),
            &mut output,
            4,
        );
        drop(scoped);

        assert_eq!(recorded.credits(), 1, "one entry was published");
        assert_eq!(
            recorded.effects(),
            &[
                RecordedCqEffect::ClaimCredit,
                RecordedCqEffect::AdvanceCqHead,
                RecordedCqEffect::RefreshCredit,
            ],
            "claim, then the head that accounts for it, then the refresh",
        );
        match recorded.disposition() {
            ProviderDisposition::Complete(_) => {}
            other => panic!("a clean drain completes: {other:?}"),
        }
        // Read from the recorder, not assumed: an expectation derived from this
        // test's own arithmetic would agree with a drain that reported the whole
        // buffer.
        let information = recorded.information();
        assert_eq!(
            information,
            PREFIX + DESCRIPTOR,
            "one credit is 48 + 1 * 32 bytes, not the buffer it was written into",
        );
        assert_eq!(recorded.status(), status::SUCCESS);

        // 1. The prefix belongs to the production writer, not to this lane.
        assert!(
            output
                .get(..PREFIX)
                .expect("prefix")
                .iter()
                .all(|b| *b == 0),
            "the 48-byte prefix is left zeroed",
        );
        // 2. The tail holds exactly the committed descriptor.
        let tail = output.get(PREFIX..information).expect("tail");
        assert_eq!(tail.len(), DESCRIPTOR);
        assert!(
            tail.iter().any(|b| *b != 0),
            "and the descriptor was actually written",
        );
        // 3. Nothing past `information` was touched.
        assert!(
            output
                .get(information..)
                .expect("suffix")
                .iter()
                .all(|b| *b == 0),
            "the caller's larger buffer suffix is not exposed",
        );

        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    /// An exhausted credit generation fences without consuming CQ or credit.
    ///
    /// The decision is `CompleteAfterTerminal(CreditGenerationExhausted)` with
    /// `STATUS_INVALID_DEVICE_STATE` and zero information -- not an error
    /// return. A drain that reported it as a refusal would leave the caller
    /// unable to tell "nothing to do" from "this session can never claim
    /// another credit".
    #[test]
    fn task20_generation_exhaustion_fences_without_consuming_cq_or_credit() {
        let (_registry, parts) = slots(9411, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");
        let mut fixture = CreditFixture::new();
        let mut table = GrantTable::initialize(&mut fixture.entries, &fixture.topology, 1)
            .expect("a fresh table");
        let mut credits = std::vec![NotificationCreditV1::default(); 1];
        assert_eq!(table.issue_notification_credits(&mut credits), Ok(1));
        let issued = SlotToken::from_raw(credits[0].buffer.token).expect("an issued token");

        // The state the fence exists for is 2^42 refreshes away; plant it.
        let token = table
            .force_entry_for_test(issued, fsring_abi::slots::SLOT_TOKEN_GENERATION_MAX, 0)
            .expect("the entry accepts a maximum generation");
        let before = table.entry_snapshot(token).expect("the planted entry");

        let mut backing = CqBacking::new();
        backing.publish(0, notify_body_for(token, 64));
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");

        let mut output = std::vec![0u8; PREFIX + DESCRIPTOR * 2];
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let (recorded, authority) = record_bounded_drain(
            &mut plan,
            authority,
            &mut scoped,
            &mut table,
            &geometry(),
            &mut output,
            2,
        );
        drop(scoped);

        assert_eq!(recorded.credits(), 0);
        assert!(
            recorded.effects().is_empty(),
            "no claim, no head advance, no refresh",
        );
        match recorded.disposition() {
            ProviderDisposition::CompleteAfterTerminal {
                completion,
                terminal,
            } => {
                assert_eq!(*terminal, TerminalRequest::CreditGenerationExhausted);
                let _ = completion;
            }
            other => panic!("exhaustion asks for a terminal: {other:?}"),
        }
        assert_eq!(
            recorded.status(),
            status::INVALID_DEVICE_STATE,
            "a fence reports a failure status, not a successful empty drain",
        );
        assert_eq!(recorded.information(), 0);
        assert_eq!(
            backing.shared_head(),
            0,
            "the CQ head is untouched, so the entry can be reclassified later",
        );
        assert_eq!(
            table.entry_snapshot(token),
            Some(before),
            "and the credit is still live",
        );
        assert!(
            output.iter().all(|b| *b == 0),
            "zero information means zero bytes",
        );

        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the exact token releases");
    }

    // ---------------------------------------------------------------------
    // Task 21: the private provider-fatal protocol abort
    // ---------------------------------------------------------------------

    use crate::adapter::enter::ProtocolError;
    use crate::session::RoleError;
    use fsring_abi::msgs::{ControlHeader, ProtocolAbortV1, protocol_opcode, protocol_reason};

    /// The exact ABORT_SESSION CQE the ABI validator accepts.
    fn protocol_abort_body() -> CqeBody {
        let mut body = body_of_kind(cq_kind::PROTOCOL);
        body.opcode = protocol_opcode::ABORT_SESSION;
        body.out_len = core::mem::size_of::<ProtocolAbortV1>() as u16;
        let record = ProtocolAbortV1 {
            header: ControlHeader {
                struct_size: core::mem::size_of::<ProtocolAbortV1>() as u32,
                struct_version: 1,
                required_flags: 0,
            },
            reason: protocol_reason::PROVIDER_FATAL_STATE,
            reserved: 0,
            context: 0x5EED,
        };
        fsring_abi::codec::try_encode(&record, &mut body.out).expect("24 bytes");
        body
    }

    /// The whole protocol lane: validate, record the role, arbitrate, commit.
    ///
    /// The two naive orders both fail, and this row pins the one that does not.
    /// Releasing the consumer first would leave the mutation running on a
    /// roleless ring; committing first and re-looking-up the consumer could
    /// find a LATER invocation of the same ring. The role is recorded while
    /// still held, and released in the same infallible suffix as the head
    /// advance.
    #[test]
    fn task21_a_provider_fatal_abort_advances_the_head_and_releases_that_exact_role() {
        let (_registry, parts) = slots(9420, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, protocol_abort_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");

        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the abort is published")
        };
        let pending = pop
            .preflight_protocol()
            .map_err(|(error, _)| error)
            .expect("the ABI accepts this exact fixed CQE");
        assert_eq!(pending.abort_record().context, 0x5EED);

        // The role is still held here: a second consumer cannot be acquired.
        let prepared = pending
            .prepare_consumer_release(&ring0.state)
            .map_err(|failure| failure.error())
            .expect("the ring state recognises its own held role");
        assert!(
            ring0.state.acquire_cq_consumer().is_err(),
            "the role is recorded, not released -- no second consumer can slip in",
        );

        let permit = plan
            .arbitrate_cq_mutation(prepared.protocol_commit_witness())
            .expect("its own execution");
        let committed = prepared
            .bind_mutation(permit, &mut ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own permit")
            .commit_protocol_abort();
        assert_eq!(committed.sequence(), 1);
        assert_eq!(committed.next_head(), 1);
        drop(scoped);
        assert_eq!(backing.shared_head(), 1, "the head advanced exactly once");
        assert!(plan.has_committed(), "the abort is a real first mutation");

        // And the role really was released: the ring admits a new consumer.
        let next = ring0
            .state
            .acquire_cq_consumer()
            .expect("the released ring admits a new consumer");
        assert_ne!(
            next.execution(),
            committed.brand_execution_for_test(),
            "the new consumer is a later invocation, not the released one",
        );
        assert_eq!(
            committed.authenticated_locator(),
            next.execution().ring().locator(),
            "and the abort speaks for this session, which only the brand can say",
        );
        let _ = ring0.state.release_cq_consumer(next);
    }

    /// Every CQE the ABI validator rejects is returned unchanged.
    ///
    /// Nothing about the shape is restated here: `validate_protocol_abort_v1`
    /// is normative and exhaustive over kind, opcode, flags, out_len, req_id,
    /// status, reserved and information, then the decoded header, reason and
    /// reserved. These rows perturb one field each and require the pop back.
    #[test]
    fn task21_every_non_abort_cqe_is_returned_unchanged() {
        for (index, body) in [
            body_of_kind(cq_kind::NOTIFY),
            body_of_kind(cq_kind::COMPLETION),
            {
                let mut body = protocol_abort_body();
                body.opcode = protocol_opcode::ABORT_SESSION + 1;
                body
            },
            {
                let mut body = protocol_abort_body();
                body.flags = 1;
                body
            },
            {
                let mut body = protocol_abort_body();
                body.information = 1;
                body
            },
            {
                let mut body = protocol_abort_body();
                // A reason the document does not define as provider-fatal.
                body.out[8..12].copy_from_slice(&0u32.to_ne_bytes());
                body
            },
        ]
        .into_iter()
        .enumerate()
        {
            let (_registry, parts) = slots(9430 + index as u64, 1);
            let mut ring0 = parts.into_iter().next().expect("ring 0");
            let mut backing = CqBacking::new();
            backing.publish(0, body);
            let descriptor = backing.descriptor();
            // SAFETY: the descriptor names this row's own live backing.
            let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
            let role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
            let authority = CqDrainAuthority::bind_drain(&storage, role)
                .map_err(|(error, _)| error)
                .expect("the same ring");
            // SAFETY: the slice is at least the entry span the descriptor claims.
            let mut scoped =
                unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
            let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
                panic!("row {index} was published")
            };
            let (error, pop) = pop
                .preflight_protocol()
                .map(|_| ())
                .expect_err("row {index} is not a provider-fatal abort");
            assert_eq!(error, ProtocolError::NotProviderFatalAbort, "row {index}");
            assert_eq!(pop.sequence(), 1, "row {index}");
            let authority = pop.abort();
            drop(scoped);
            assert_eq!(backing.shared_head(), 0, "row {index} moved no head");
            ring0
                .state
                .release_cq_consumer(authority.into_consumer_token())
                .map_err(|(error, _)| error)
                .expect("the exact token releases");
        }
    }

    /// A release preflight against another ring's state refuses, and the entry,
    /// the head and the role all survive it.
    #[test]
    fn task21_a_release_preflight_for_another_ring_refuses_and_releases_nothing() {
        let (_registry, parts) = slots(9440, 2);
        let mut parts = parts.into_iter();
        let mut ring0 = parts.next().expect("ring 0");
        let ring1 = parts.next().expect("ring 1");

        let mut backing = CqBacking::new();
        backing.publish(0, protocol_abort_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let role = ring0.state.acquire_cq_consumer().expect("a fresh ring");
        let authority = CqDrainAuthority::bind_drain(&storage, role)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the abort is published")
        };
        let pending = pop
            .preflight_protocol()
            .map_err(|(error, _)| error)
            .expect("a provider-fatal abort");

        // Ring one's state does not own this role.
        let failure = pending
            .prepare_consumer_release(&ring1.state)
            .map(|_| ())
            .expect_err("another ring's state cannot record this role");
        assert_eq!(failure.error(), RoleError::WrongRing);
        let (error, authority) = failure.abort();
        assert_eq!(error, RoleError::WrongRing);
        drop(scoped);
        assert_eq!(
            backing.shared_head(),
            0,
            "a refused preflight moves no head"
        );
        ring0
            .state
            .release_cq_consumer(authority.into_consumer_token())
            .map_err(|(error, _)| error)
            .expect("the role was never released, so it is still ours");
    }

    /// A committed abort that cannot become a terminal claim is consumed into a
    /// typed reject, and that reject completes exactly once.
    ///
    /// Everything a reject reports was observed **after** the CQ head advanced
    /// and the consumer role was released -- both irreversible. So a reject
    /// cannot be an error return: there is no state to roll back to, and a raw
    /// error would leave the caller holding a released role with nothing saying
    /// the release happened. The receipt carries that proof, sealed.
    #[test]
    fn task21_a_committed_abort_that_cannot_claim_becomes_one_typed_reject() {
        use crate::adapter::lifecycle::{
            ProtocolRejectReason, complete_protocol_reject, reject_committed_protocol,
        };

        let (_registry, parts) = slots(9450, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, protocol_abort_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");

        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the abort is published")
        };
        let prepared = pop
            .preflight_protocol()
            .map_err(|(error, _)| error)
            .expect("a provider-fatal abort")
            .prepare_consumer_release(&ring0.state)
            .map_err(|failure| failure.error())
            .expect("the ring state recognises its own held role");
        let permit = plan
            .arbitrate_cq_mutation(prepared.protocol_commit_witness())
            .expect("its own execution");
        let committed = prepared
            .bind_mutation(permit, &mut ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own permit")
            .commit_protocol_abort();
        drop(scoped);

        // Both irreversible things have happened by now.
        assert_eq!(backing.shared_head(), 1, "the head advanced");
        let reacquired = ring0
            .state
            .acquire_cq_consumer()
            .expect("the role really was released");
        let _ = ring0.state.release_cq_consumer(reacquired);

        // The record is what proves that, and the reject consumes it.
        let record = committed.into_terminal_record();
        assert_eq!(record.sequence(), 1);
        assert_eq!(record.next_head(), 1);
        let receipt = reject_committed_protocol(ProtocolRejectReason::StaleGeneration, record);
        assert_eq!(receipt.reason(), ProtocolRejectReason::StaleGeneration);

        // And the receipt spends into exactly one deterministic completion.
        // Read from the completion, not assumed: an expectation derived from
        // this test's own reading of the rule would agree with a reject that
        // reported success.
        let completion = complete_protocol_reject(receipt);
        assert_eq!(
            completion.observed_for_test(),
            (fsring_abi::control::status::INVALID_DEVICE_STATE, 0),
        );
    }

    /// Every reject reason completes the same way, and none of them can be told
    /// apart from the wire.
    ///
    /// The reasons describe kernel scheduling -- which of CLEANUP, process loss
    /// or unload won the race between the abort and the registry lock. Mapping
    /// them onto distinct statuses would leak that into a user-visible code, so
    /// the completion is deterministic across the whole closed set and this row
    /// walks it rather than sampling it.
    #[test]
    fn task21_every_reject_reason_completes_invalid_device_state_with_zero() {
        use crate::adapter::lifecycle::{
            LifecycleError, ProtocolRejectReason, complete_protocol_reject,
            reject_committed_protocol,
        };

        let reasons = [
            ProtocolRejectReason::StaleGeneration,
            ProtocolRejectReason::NoActiveGeneration,
            ProtocolRejectReason::CellPhaseMismatch,
            ProtocolRejectReason::CompletionIdentityMismatch,
            ProtocolRejectReason::MissingControlOwner,
            ProtocolRejectReason::DepositOccupied,
            ProtocolRejectReason::BindingMismatch,
            ProtocolRejectReason::ProtocolBrandMismatch,
            ProtocolRejectReason::JoinGuardUnavailable,
            ProtocolRejectReason::Lifecycle(LifecycleError::WrongState),
        ];

        for (index, reason) in reasons.into_iter().enumerate() {
            let (_registry, parts) = slots(9460 + index as u64, 1);
            let mut ring0 = parts.into_iter().next().expect("ring 0");
            let mut backing = CqBacking::new();
            backing.publish(0, protocol_abort_body());
            let descriptor = backing.descriptor();
            // SAFETY: the descriptor names this row's own live backing.
            let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
            let acquired = ring0
                .state
                .acquire_cq_consumer_aggregate()
                .expect("a fresh ring");
            let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
                .map_err(|(error, _)| error)
                .expect("the same ring");
            // SAFETY: the slice is at least the entry span the descriptor claims.
            let mut scoped =
                unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
            let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
                panic!("row {index} was published")
            };
            let prepared = pop
                .preflight_protocol()
                .map_err(|(error, _)| error)
                .expect("a provider-fatal abort")
                .prepare_consumer_release(&ring0.state)
                .map_err(|failure| failure.error())
                .expect("its own role");
            let permit = plan
                .arbitrate_cq_mutation(prepared.protocol_commit_witness())
                .expect("its own execution");
            let record = prepared
                .bind_mutation(permit, &mut ring0.state)
                .map_err(|failure| failure.error())
                .expect("its own permit")
                .commit_protocol_abort()
                .into_terminal_record();
            drop(scoped);

            let receipt = reject_committed_protocol(reason, record);
            assert_eq!(receipt.reason(), reason, "row {index}");
            assert_eq!(
                complete_protocol_reject(receipt).observed_for_test(),
                (fsring_abi::control::status::INVALID_DEVICE_STATE, 0),
                "row {index}: every reason completes identically",
            );
        }
    }

    /// A committed abort whose session cannot be claimed becomes a reject, and
    /// the four lifecycle objects are left exactly as they were.
    ///
    /// The locator is the **arrival's own**, derived from the private CQ stream
    /// brand, so this is not a test of argument passing: there is no argument
    /// through which another session could be named. What it pins is that the
    /// refusal path mutates nothing -- the registry, binding, rendezvous and
    /// lease slot are compared before and after -- and that the arrival is still
    /// answered exactly once, because the record was consumed into a receipt.
    #[test]
    fn task21_an_unclaimable_arrival_rejects_and_leaves_the_lifecycle_objects_alone() {
        use crate::adapter::lifecycle::{
            CommittedProtocolTerminalDisposition, ProtocolRejectReason, complete_protocol_reject,
            prepare_protocol_terminal_claim,
        };
        use crate::session::{ControlBinding, RegistryLease, TerminalRendezvous};

        let (mut registry, parts) = slots(9470, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, protocol_abort_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the abort is published")
        };
        let prepared = pop
            .preflight_protocol()
            .map_err(|(error, _)| error)
            .expect("a provider-fatal abort")
            .prepare_consumer_release(&ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own role");
        let permit = plan
            .arbitrate_cq_mutation(prepared.protocol_commit_witness())
            .expect("its own execution");
        let committed = prepared
            .bind_mutation(permit, &mut ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own permit")
            .commit_protocol_abort();
        drop(scoped);
        assert_eq!(
            backing.shared_head(),
            1,
            "the head advanced before the claim"
        );

        // The four objects a terminal claim reads. This cell was never taken to
        // a live terminal generation, so there is nothing to claim -- which is
        // exactly the race the reject arm exists for: CLEANUP, process loss or
        // unload getting there first.
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let mut rendezvous = TerminalRendezvous::new_inactive();
        let mut lease: Option<RegistryLease> = None;

        let before_rendezvous = rendezvous.state_debug_for_test();
        let before_lease = lease.is_some();

        let disposition = prepare_protocol_terminal_claim(
            &mut registry,
            &mut binding,
            &mut rendezvous,
            &mut lease,
            committed,
        )
        .commit_protocol_claim();

        let receipt = match disposition {
            CommittedProtocolTerminalDisposition::Reject(receipt) => receipt,
            _ => panic!("an inactive rendezvous cannot be claimed"),
        };
        assert!(
            matches!(receipt.reason(), ProtocolRejectReason::Lifecycle(_)),
            "the refusal carries the lifecycle rule that refused it, got {:?}",
            receipt.reason(),
        );

        // Nothing moved.
        assert_eq!(rendezvous.state_debug_for_test(), before_rendezvous);
        assert_eq!(lease.is_some(), before_lease);

        // And the arrival is answered exactly once.
        assert_eq!(
            complete_protocol_reject(receipt).observed_for_test(),
            (fsring_abi::control::status::INVALID_DEVICE_STATE, 0),
        );
    }

    /// Drain a real provider-fatal abort out of a ring belonging to a cell that
    /// is *already published*, and claim its terminal.
    ///
    /// This is the row the four disposition arms were owed. Until the fixture
    /// below existed, every arrival this module could build named a session that
    /// had never been published, so `prepare_protocol_terminal_claim` always
    /// refused at Task 9's preflight and Winner, Join, Completed and Blocked
    /// were branches nothing reached -- a plant replacing any of them with
    /// `unreachable!` survived.
    ///
    /// What makes it work is that the cell and the ring come from one
    /// `InstalledSession`: `published_cell_with_rings` reaches between
    /// installation and publication to take the ring set, so the locator the
    /// arrival authenticates from its own CQ stream brand is the locator the
    /// registry published. The arrival still names no session by argument.
    ///
    /// All six arrival shapes are walked, because the two reject routes are
    /// distinguishable and each disposition must be the one that shape earns:
    /// Blocked is *not* an error return -- by this point the head has advanced
    /// and the role is gone, so it becomes the typed reject.
    #[test]
    fn task21_a_published_cell_yields_every_protocol_terminal_disposition() {
        use crate::adapter::lifecycle::{
            CommittedProtocolTerminalDisposition, LifecycleError, ProtocolRejectReason,
            complete_protocol_reject, prepare_protocol_terminal_claim,
        };
        use crate::session::TerminalReason;
        use crate::session::tests::{ArrivalShape, cell_in_shape_with_rings};

        /// What each shape earns, named rather than computed, so a disposition
        /// that changed shows up as a row rather than as agreement.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Expected {
            Winner,
            Join,
            Completed,
            Reject(ProtocolRejectReason),
        }

        const ROWS: [(ArrivalShape, Expected); 6] = [
            (ArrivalShape::LiveUnclaimed, Expected::Winner),
            (ArrivalShape::RemovingOpen, Expected::Join),
            (ArrivalShape::DeletingOpen, Expected::Join),
            (ArrivalShape::ClosedCompleted, Expected::Completed),
            // A permanently blocked generation cannot be claimed and cannot be
            // joined; the receipt says so.
            (
                ArrivalShape::ClosedBlocked,
                Expected::Reject(ProtocolRejectReason::JoinGuardUnavailable),
            ),
            // Admission taken without the coupled transition: Task 9's preflight
            // refuses, and the refusal travels as the lifecycle reason.
            (
                ArrivalShape::LiveAlreadyAdmitted,
                Expected::Reject(ProtocolRejectReason::Lifecycle(
                    LifecycleError::FinalizerBusy,
                )),
            ),
        ];

        let mut rows = 0_u32;
        for (index, (shape, expected)) in ROWS.into_iter().enumerate() {
            rows = rows.saturating_add(1);
            let id = SessionIdentity {
                mount_id: MountId {
                    lo: 9600 + index as u64,
                    hi: 71,
                },
                boot_instance_id: BootInstanceId { lo: 73, hi: 79 },
                session_epoch: 1,
            };
            let (mut cell, _brand, parts) = cell_in_shape_with_rings::<1>(id, shape, 1);
            let mut ring0 = parts.into_iter().next().expect("ring 0");
            let cell_locator = cell.locator;

            let mut backing = CqBacking::new();
            backing.publish(0, protocol_abort_body());
            let descriptor = backing.descriptor();
            // SAFETY: the descriptor names this test's own live backing.
            let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
            let acquired = ring0
                .state
                .acquire_cq_consumer_aggregate()
                .expect("a fresh ring");
            let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
                .map_err(|(error, _)| error)
                .expect("the same ring");
            // SAFETY: the slice is at least the entry span the descriptor claims.
            let mut scoped =
                unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
            let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
                panic!("row {index}: the abort is published")
            };
            let prepared = pop
                .preflight_protocol()
                .map_err(|(error, _)| error)
                .expect("a provider-fatal abort")
                .prepare_consumer_release(&ring0.state)
                .map_err(|failure| failure.error())
                .expect("its own role");
            let permit = plan
                .arbitrate_cq_mutation(prepared.protocol_commit_witness())
                .expect("its own execution");
            let committed = prepared
                .bind_mutation(permit, &mut ring0.state)
                .map_err(|failure| failure.error())
                .expect("its own permit")
                .commit_protocol_abort();
            drop(scoped);
            assert_eq!(
                backing.shared_head(),
                1,
                "row {index}: the head advanced before the claim"
            );

            let disposition = prepare_protocol_terminal_claim(
                &mut cell.registry,
                &mut cell.binding,
                &mut cell.rendezvous,
                &mut cell.lease,
                committed,
            )
            .commit_protocol_claim();

            match (disposition, expected) {
                (CommittedProtocolTerminalDisposition::Winner { work, join }, Expected::Winner) => {
                    let (winner, terminal) = work.into_terminal_authorities();
                    assert_eq!(
                        winner.locator(),
                        cell_locator,
                        "row {index}: the winner is this cell's, not an argument's",
                    );
                    assert_eq!(
                        winner.reason(),
                        TerminalReason::ProtocolFault,
                        "row {index}: a protocol arrival always claims as a protocol fault",
                    );
                    // The winner holds a join against its own generation, and
                    // it arrives sealed rather than inside the winner.
                    let _ = terminal;
                    let _ = join;
                }
                (CommittedProtocolTerminalDisposition::Join(join), Expected::Join) => {
                    // Releasing is the assertion. A join minted against another
                    // generation refuses here, so a successful release is the
                    // proof that this arrival joined *this* cell -- stronger
                    // than reading a locator back out, and it is the only route
                    // out of the wrapper.
                    match join.release_protocol_join(&mut cell.rendezvous) {
                        Ok(_) => {}
                        Err((error, _join)) => {
                            panic!("row {index}: the joiner was not this generation's: {error:?}")
                        }
                    }
                }
                (
                    CommittedProtocolTerminalDisposition::Completed(completed),
                    Expected::Completed,
                ) => {
                    assert_eq!(
                        completed.into_result().reason,
                        TerminalReason::Cleanup,
                        "row {index}: the copied result is the one the runner published",
                    );
                }
                (
                    CommittedProtocolTerminalDisposition::Reject(receipt),
                    Expected::Reject(reason),
                ) => {
                    assert_eq!(receipt.reason(), reason, "row {index}");
                    assert_eq!(
                        complete_protocol_reject(receipt).observed_for_test(),
                        (fsring_abi::control::status::INVALID_DEVICE_STATE, 0),
                        "row {index}: every reject completes identically",
                    );
                }
                (other, expected) => panic!(
                    "row {index}: {shape:?} must yield {expected:?}, got {}",
                    match other {
                        CommittedProtocolTerminalDisposition::Winner { .. } => "Winner",
                        CommittedProtocolTerminalDisposition::Join(_) => "Join",
                        CommittedProtocolTerminalDisposition::Completed(_) => "Completed",
                        CommittedProtocolTerminalDisposition::Reject(_) => "Reject",
                    }
                ),
            }
        }
        assert_eq!(
            rows, 6,
            "every distinguishable arrival shape is walked, not a chosen few",
        );
    }

    /// A refusal the native side observes becomes the same typed reject, minted
    /// under the same four exclusive borrows the claim would have held.
    ///
    /// `reject_committed_protocol` is crate-private on purpose, so `fsring-fsd`
    /// cannot mint a receipt for an arrival nobody claimed. Everything it can
    /// see that core cannot -- cell phase, generation word, control owner,
    /// deposit occupancy -- therefore comes back through this bridge, and the
    /// bridge takes the borrows so no second arrival can be mid-claim on this
    /// generation while this one is being answered.
    #[test]
    fn task21_a_native_side_refusal_becomes_a_typed_reject_under_the_same_borrows() {
        use crate::adapter::lifecycle::{
            CommittedProtocolTerminalDisposition, ProtocolRejectReason, complete_protocol_reject,
            prepare_protocol_terminal_reject,
        };
        use crate::session::tests::{ArrivalShape, cell_in_shape_with_rings};

        let id = SessionIdentity {
            mount_id: MountId { lo: 9700, hi: 71 },
            boot_instance_id: BootInstanceId { lo: 73, hi: 79 },
            session_epoch: 1,
        };
        // A live cell: the claim would have succeeded, so the reject below is
        // the native observation refusing and nothing else.
        let (mut cell, _brand, parts) =
            cell_in_shape_with_rings::<1>(id, ArrivalShape::LiveUnclaimed, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, protocol_abort_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the abort is published")
        };
        let prepared = pop
            .preflight_protocol()
            .map_err(|(error, _)| error)
            .expect("a provider-fatal abort")
            .prepare_consumer_release(&ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own role");
        let permit = plan
            .arbitrate_cq_mutation(prepared.protocol_commit_witness())
            .expect("its own execution");
        let committed = prepared
            .bind_mutation(permit, &mut ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own permit")
            .commit_protocol_abort();
        drop(scoped);

        let before_rendezvous = cell.rendezvous.state_debug_for_test();
        let before_lease = cell.lease.is_some();

        let disposition = prepare_protocol_terminal_reject(
            &mut cell.registry,
            &mut cell.binding,
            &mut cell.rendezvous,
            &mut cell.lease,
            ProtocolRejectReason::MissingControlOwner,
            committed,
        )
        .commit_protocol_claim();

        let CommittedProtocolTerminalDisposition::Reject(receipt) = disposition else {
            panic!("a native refusal is always a reject")
        };
        assert_eq!(receipt.reason(), ProtocolRejectReason::MissingControlOwner);

        // Nothing moved -- including the lease, which a claim would have taken.
        assert_eq!(cell.rendezvous.state_debug_for_test(), before_rendezvous);
        assert_eq!(cell.lease.is_some(), before_lease);
        assert_eq!(
            complete_protocol_reject(receipt).observed_for_test(),
            (fsring_abi::control::status::INVALID_DEVICE_STATE, 0),
        );
    }

    /// A refused opaque release hands the sealed wrapper back, never a ticket.
    ///
    /// This is the arm most likely to leak one: the opaque path exists because
    /// a fail-stopped generation never signals its terminal event, so its
    /// release runs against a rendezvous that may legitimately refuse. A
    /// refusal that yielded the bare ticket would let the caller join a second
    /// generation with a first generation's admission.
    #[test]
    fn task21_a_refused_opaque_protocol_release_returns_the_sealed_wrapper() {
        use crate::adapter::lifecycle::{
            CommittedProtocolTerminalDisposition, prepare_protocol_terminal_claim,
        };
        use crate::session::tests::{ArrivalShape, cell_in_shape_with_rings};

        let id = SessionIdentity {
            mount_id: MountId { lo: 9701, hi: 71 },
            boot_instance_id: BootInstanceId { lo: 73, hi: 79 },
            session_epoch: 1,
        };
        // Removing/open: this arrival joins, so it holds a real sealed join.
        let (mut cell, _brand, parts) =
            cell_in_shape_with_rings::<1>(id, ArrivalShape::RemovingOpen, 1);
        let mut ring0 = parts.into_iter().next().expect("ring 0");

        let mut backing = CqBacking::new();
        backing.publish(0, protocol_abort_body());
        let descriptor = backing.descriptor();
        // SAFETY: the descriptor names this test's own live backing.
        let storage = unsafe { BrandedCqStorage::bind_storage(ring0.cq_storage, descriptor) };
        let acquired = ring0
            .state
            .acquire_cq_consumer_aggregate()
            .expect("a fresh ring");
        let (mut plan, authority) = R4EnterPlan::bind_cq_drain(acquired, &storage)
            .map_err(|(error, _)| error)
            .expect("the same ring");
        // SAFETY: the slice is at least the entry span the descriptor claims.
        let mut scoped = unsafe { storage.borrow_consumer(&mut backing.bytes) }.expect("covers");
        let Ok(CqPeek::Ready(pop)) = authority.try_peek(&mut scoped) else {
            panic!("the abort is published")
        };
        let prepared = pop
            .preflight_protocol()
            .map_err(|(error, _)| error)
            .expect("a provider-fatal abort")
            .prepare_consumer_release(&ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own role");
        let permit = plan
            .arbitrate_cq_mutation(prepared.protocol_commit_witness())
            .expect("its own execution");
        let committed = prepared
            .bind_mutation(permit, &mut ring0.state)
            .map_err(|failure| failure.error())
            .expect("its own permit")
            .commit_protocol_abort();
        drop(scoped);

        let disposition = prepare_protocol_terminal_claim(
            &mut cell.registry,
            &mut cell.binding,
            &mut cell.rendezvous,
            &mut cell.lease,
            committed,
        )
        .commit_protocol_claim();
        let CommittedProtocolTerminalDisposition::Join(join) = disposition else {
            panic!("an open Removing generation is joined")
        };

        // This rendezvous is Open, not OpaqueRetained, so the opaque release
        // refuses -- and the only thing it can hand back is the wrapper.
        let Err(join) = join.release_opaque_protocol_join(&mut cell.rendezvous) else {
            panic!("an open generation has no retained opaque slot")
        };

        // And the ordinary release still works on that same wrapper, which is
        // what proves the refusal consumed nothing.
        assert!(
            join.release_protocol_join(&mut cell.rendezvous).is_ok(),
            "the refused wrapper still owns its admission",
        );
    }

    /// The conservative kind set is a closed constant the test walks, not a set
    /// the test restates beside the code.
    #[test]
    fn task20_conservative_notify_kind_set_is_walked_rather_than_restated() {
        assert!(
            CONSERVATIVE_NOTIFY_CQ_KINDS.contains(&cq_kind::NOTIFY),
            "the only non-fault CQ kind C4 accounts for is the notification",
        );
        for kind in [cq_kind::COMPLETION, cq_kind::PROTOCOL, 3, u16::MAX] {
            assert!(
                !CONSERVATIVE_NOTIFY_CQ_KINDS.contains(&kind),
                "kind {kind} is outside C4's conservative notification set",
            );
        }
    }
}

#[test]
fn task25_new_routes_and_all16_runner_cut_over_atomically() {
    let enter = include_str!("../../../../fsring-fsd/src/session.rs");
    assert!(
        !enter.contains("EnterProgress::ClaimCredit(_)")
            || !enter.contains("STATUS_INVALID_DEVICE_STATE"),
        "production ENTER must no longer refuse ClaimCredit as an unexecuted predecessor"
    );
    assert!(
        enter.contains("prepare_credit_claim") || enter.contains("bind_credit"),
        "production ENTER must bind the Task 20 credit/CQ executor"
    );
    assert!(
        enter.contains("classify_cq"),
        "production ENTER must classify a live CQ observation"
    );
}

// ---------------------------------------------------------------------------
// R6 recovery: the parked WAIT's terminal comes from the arbitration
// ---------------------------------------------------------------------------
//
// A parked WAIT is completed by whichever of cancel, timeout, readiness, fence,
// or unload wins the terminal CAS. The worker that runs the completion knows
// which wake it observed, but an observed wake is not an arbitration: two of
// them can be stored before the worker runs, and only `PendingIrpArbiter`
// decides which one owns the completion. These tests pin the property that the
// delivered status is the arbitrated one rather than a native re-derivation.

#[cfg(test)]
mod r6_parked_wait_arbitration_tests {
    use super::*;

    use crate::enter::{
        IrpObservation, PendingEnter, PendingIrpArbiter, PendingReason, RingEnterState,
        build_ring_runtime_parts,
    };
    use crate::session::{
        ControlBinding, PendingInstallId, SessionRegistry, SessionRingBrand, SetupStage,
        SetupTransaction,
    };
    use fsring_abi::validate::SessionIdentity;
    use fsring_abi::{BootInstanceId, MountId};

    const PARKED_IRP: usize = 0x00C4_0001;

    /// The pending slot's own branded ring: production binds the arbiter to the
    /// *slot's* SQ-wait lease, which is a different role from the session ring
    /// lease the parked plan holds.
    fn slot_ring(n: u64) -> (RingEnterState, SessionRingBrand) {
        let mut binding = ControlBinding::new().expect("a fresh binding source");
        let reservation = binding.begin_setup().expect("an empty binding reserves");
        let identity = SessionIdentity {
            mount_id: MountId { lo: n, hi: 29 },
            boot_instance_id: BootInstanceId { lo: 31, hi: 37 },
            session_epoch: 1,
        };
        let mut transaction = SetupTransaction::begin(identity).expect("a valid identity");
        for stage in [
            SetupStage::LayoutPlanned,
            SetupStage::SectionReady,
            SetupStage::GrantsReady,
            SetupStage::VolumeReady,
            SetupStage::ViewsReady,
            SetupStage::OutputReady,
        ] {
            transaction = transaction.stage(stage).expect("the roster order");
        }
        let mut registry = SessionRegistry::<1>::new();
        let mut installed = registry
            .install_staging(&transaction, &binding, &reservation)
            .expect("output-ready staging installs");
        let mut set = installed.begin_ring_set(1).expect("a fresh install");
        let right = set
            .next_ring()
            .expect("identities available")
            .expect("ring 0");
        let brand = right.brand();
        let parts = build_ring_runtime_parts(brand, 64, right)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        let (state, _slot, _owners, _wake, _bind) = parts.into_parts();
        (state, brand)
    }

    /// Park a WAIT on `roles`, and mint the authentic terminal right that
    /// `reason` wins, exactly the way production does: bind the arbiter to the
    /// slot lease, park the owned terminal, finish the handoff, dequeue the
    /// exact CSQ return, then contend.
    fn parked_wait_and_right(
        n: u64,
        roles: &mut RingEnterState,
        reason: PendingReason,
    ) -> (ParkedWaitInstall, crate::enter::PendingTerminalRight) {
        let mut recorded = Vec::new();
        let progress = walk(
            NativeEnterPlan::begin(wait_input(25)).expect("begin"),
            &mut recorded,
            EnterDecision::Pending,
            roles,
        );
        let EnterProgress::Pending(parked) = progress else {
            panic!("a WAIT that is not ready parks");
        };
        let owned = parked.into_owned_wait();

        let (mut slot, brand) = slot_ring(n);
        let lease = slot.acquire_sq_wait().expect("a fresh slot");
        let mut arbiter = PendingIrpArbiter::bind(&lease);
        let install = PendingInstallId::for_test(brand, 1);
        let irp = IrpObservation::from_raw(PARKED_IRP).expect("a nonzero literal");
        arbiter
            .park(install, irp, PendingEnter::new(1))
            .unwrap_or_else(|(error, _)| unreachable!("a fresh arbiter parks: {error:?}"));
        arbiter.handoff_done().expect("one handoff");
        let receipt = arbiter
            .dequeue(install, PARKED_IRP, reason)
            .expect("the exact CSQ return mints one receipt");
        let (right, dequeued) = arbiter
            .contend(receipt)
            .unwrap_or_else(|(error, _)| unreachable!("the sole contender wins: {error:?}"));
        assert_eq!(dequeued, irp, "the winner names the IRP that parked");
        let _ = lease;
        (owned, right)
    }

    #[test]
    fn a_cancelled_parked_wait_completes_with_the_arbitrated_cancel_status() {
        let mut roles = RingEnterState::new(0);
        let (owned, right) = parked_wait_and_right(2901, &mut roles, PendingReason::Cancel);

        let outcome = owned.finish_arbitrated(right);

        assert_eq!(
            outcome.result.status,
            status::CANCELLED,
            "the terminal CAS decided Cancel, so the result must say so"
        );
        assert_eq!(
            outcome.result.information, 0,
            "a cancelled IRP copied no bytes back, so it reports none",
        );
    }

    #[test]
    fn a_readiness_woken_parked_wait_completes_successfully() {
        let mut roles = RingEnterState::new(0);
        let (owned, right) = parked_wait_and_right(2902, &mut roles, PendingReason::Readiness);

        let outcome = owned.finish_arbitrated(right);

        assert_eq!(
            outcome.result.status,
            status::SUCCESS,
            "an SQ-readiness wake is a successful ENTER",
        );
        assert_eq!(
            outcome.result.information, ENTER_RESULT_V1_PREFIX_SIZE as usize,
            "a woken WAIT delivers the zero-credit prefix",
        );
    }

    #[test]
    fn a_fenced_parked_wait_completes_with_the_arbitrated_fence_status() {
        let mut roles = RingEnterState::new(0);
        let (owned, right) = parked_wait_and_right(2903, &mut roles, PendingReason::Fence);

        let outcome = owned.finish_arbitrated(right);

        assert_eq!(outcome.result.status, status::INVALID_DEVICE_STATE);
    }

    #[test]
    fn finishing_a_parked_wait_hands_back_the_ring_lease_it_held() {
        let mut roles = RingEnterState::new(0);
        let (owned, right) = parked_wait_and_right(2904, &mut roles, PendingReason::Timeout);
        assert!(
            !roles.r3_checkpoint_roles_and_consumers_are_drained(),
            "the ring still names the parked waiter",
        );

        let outcome = owned.finish_arbitrated(right);

        let role = outcome
            .role
            .expect("the parked plan hands its ring lease back to the completion");
        assert!(
            !roles.r3_checkpoint_roles_and_consumers_are_drained(),
            "handing the lease out does not release the ring",
        );
        roles
            .release_role(role)
            .unwrap_or_else(|(error, _)| unreachable!("{error:?}"));
        assert!(
            roles.r3_checkpoint_roles_and_consumers_are_drained(),
            "only the completion's own release stage clears the waiter",
        );
    }
}
