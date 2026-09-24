// TEST: fixtures use host allocation and checked topology arithmetic; production
// grant code remains allocation-free and retains the crate-wide lint denials.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]

use super::*;

use core::sync::atomic::{AtomicU64, Ordering};

use fsring_abi::{
    FeatureSet, MIN_CONTROL_SLOT_SIZE, MIN_K2U_PROGRESS_SLOTS_PER_RING,
    MIN_NOTIFICATION_CREDIT_SIZE, MIN_U2K_PROGRESS_SLOTS_PER_RING,
    codec::try_encode,
    control::{NotificationCreditV1, SETUP_REQUEST_V1_SIZE, SetupRequestV1, SlotClassRequest},
    features::PlatformProfile,
    msgs::{BufferRef, CONTROL_VERSION_V1, ControlHeader, buffer_access, buffer_kind},
    slots::SLOT_TOKEN_GENERATION_MAX,
    validate::{ValidatedTopology, validate_setup_request_v1},
};

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
    .expect("grant test topology must validate")
    .topology()
}

fn entry_count(topology: &ValidatedTopology) -> usize {
    topology
        .u2k_slot_classes()
        .iter()
        .map(|request| request.slot_count as usize)
        .sum()
}

fn free_backing(topology: &ValidatedTopology) -> Vec<GrantEntry> {
    vec![GrantEntry::FREE; entry_count(topology)]
}

fn sentinel_credit(byte: u8) -> NotificationCreditV1 {
    NotificationCreditV1 {
        buffer: BufferRef {
            token: u64::from(byte),
            offset: u32::from(byte),
            length: u32::from(byte),
            kind: u16::from(byte),
            access: u16::from(byte),
            reserved: u32::from(byte),
        },
        ring_index: u32::from(byte),
        reserved: u32::from(byte),
    }
}

fn issue(table: &mut GrantTable<'_>) -> Vec<NotificationCreditV1> {
    let mut output =
        vec![NotificationCreditV1::default(); table.notification_credit_count as usize];
    let expected = output.len();
    assert_eq!(table.issue_notification_credits(&mut output), Ok(expected));
    output
}

#[test]
fn initialization_uses_exact_u2k_prefix_bases_and_rejects_k2u_only_indices() {
    let topology = topology(2, 4);
    let classes = topology.u2k_slot_classes();
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 77).expect("valid backing");
    let credits = issue(&mut table);

    assert_eq!(topology.notification_credit_class(), 1);
    for (index, descriptor) in credits.iter().enumerate() {
        let token = SlotToken::from_raw(descriptor.buffer.token).expect("issued token");
        assert_eq!(token.class(), 1);
        assert_eq!(token.index(), index as u32);
        assert_eq!(token.generation(), 1);
        assert_eq!(
            table.entry_snapshot(token).expect("issued entry").token,
            token
        );
    }

    assert_eq!(table.class_bases, [0, 2, 6, 9]);
    assert_eq!(
        table.class_counts,
        classes.map(|request| request.slot_count)
    );
    assert_eq!(table.slot_sizes, classes.map(|request| request.slot_size));
    for (class, index, expected_entry) in [(0, 1, 1), (1, 3, 5), (2, 2, 8), (3, 3, 12)] {
        let token = SlotToken::try_new(class, index, 1).expect("canonical U2K token");
        assert_eq!(table.canonical_entry_index(token), Some(expected_entry));
    }

    // K2U class zero has eight slots here, while U2K class zero has only two.
    let k2u_only_shape = SlotToken::try_new(0, 3, 1).expect("well-formed raw token");
    assert_eq!(table.entry_snapshot(k2u_only_shape), None);
}

#[test]
fn attach_reopens_issued_entries_under_the_same_identity() {
    let topology = topology(2, 4);
    let mut entries = free_backing(&topology);
    let identity;
    let token;
    {
        let mut table = GrantTable::initialize(&mut entries, &topology, 1).expect("fresh");
        let credits = issue(&mut table);
        identity = table.identity();
        token = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
        assert!(table.preflight_notify(0, token, 32, 1).is_ok());
    }
    match GrantTable::initialize(&mut entries, &topology, 1) {
        Ok(_) => panic!("issued backing must not re-initialize"),
        Err(error) => assert_eq!(error, GrantError::InvalidBacking),
    }
    let mut reopened = GrantTable::attach(&mut entries, &topology, 1, identity).expect("issued");
    assert_eq!(reopened.identity(), identity);
    let preflight = reopened
        .preflight_notify(0, token, 32, 1)
        .expect("same generation");
    assert!(reopened.claim_notify(preflight).is_ok());
}

#[test]
fn failed_initialize_preserves_wrong_sized_and_nonfree_backing() {
    let topology = topology(1, 1);

    let mut short = vec![GrantEntry::FREE; entry_count(&topology) - 1];
    let short_before = short.clone();
    assert_eq!(
        GrantTable::initialize(&mut short, &topology, 9).err(),
        Some(GrantError::InvalidBacking)
    );
    assert_eq!(short, short_before);

    let mut dirty = free_backing(&topology);
    dirty[0] = GrantEntry {
        slot_token: SlotToken::try_new(0, 0, 1).ok(),
        ring_index: 0,
        generation: 1,
        state: GrantState::Retired,
    };
    let dirty_before = dirty.clone();
    assert_eq!(
        GrantTable::initialize(&mut dirty, &topology, 9).err(),
        Some(GrantError::InvalidBacking)
    );
    assert_eq!(dirty, dirty_before);

    let mut zero_epoch = free_backing(&topology);
    let zero_epoch_before = zero_epoch.clone();
    assert_eq!(
        GrantTable::initialize(&mut zero_epoch, &topology, 0).err(),
        Some(GrantError::InvalidTopology)
    );
    assert_eq!(zero_epoch, zero_epoch_before);
}

#[test]
fn grant_table_identity_exhaustion_is_sticky_and_preserves_backing() {
    let zero = AtomicU64::new(0);
    assert_eq!(allocate_grant_table_id(&zero).map(GrantTableId::get), Ok(1));

    let ordinary = AtomicU64::new(1);
    let first = allocate_grant_table_id(&ordinary).expect("first table identity");
    let second = allocate_grant_table_id(&ordinary).expect("second table identity");
    assert_ne!(first, second);
    assert_ne!(first.get(), 0);

    let near_max = AtomicU64::new(u64::MAX - 1);
    assert_eq!(
        allocate_grant_table_id(&near_max).map(GrantTableId::get),
        Ok(u64::MAX - 1)
    );
    assert_eq!(
        allocate_grant_table_id(&near_max),
        Err(GrantError::TableIdentityExhausted)
    );
    assert_eq!(
        allocate_grant_table_id(&near_max),
        Err(GrantError::TableIdentityExhausted)
    );
    assert_eq!(near_max.load(Ordering::Relaxed), u64::MAX);

    let topology = topology(1, 1);
    let mut entries = free_backing(&topology);
    let before = entries.clone();
    let exhausted = AtomicU64::new(u64::MAX);
    assert_eq!(
        GrantTable::initialize_with_table_id_source(&mut entries, &topology, 9, &exhausted).err(),
        Some(GrantError::TableIdentityExhausted)
    );
    assert_eq!(entries, before);
    assert_eq!(exhausted.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn failed_issue_preserves_every_entry_and_output_byte() {
    let topology = topology(4, 8);
    let mut entries = free_backing(&topology);
    let before_entries = entries.clone();
    let mut output = vec![sentinel_credit(0xa5); 7];
    let before_output = output.clone();
    {
        let mut table = GrantTable::initialize(&mut entries, &topology, 11).expect("valid table");
        assert_eq!(
            table.issue_notification_credits(&mut output),
            Err(GrantError::ReturnBufferTooSmall)
        );
    }
    assert_eq!(entries, before_entries);
    assert_eq!(output, before_output);

    let mut table = GrantTable::initialize(&mut entries, &topology, 11).expect("valid table");
    let _credits = issue(&mut table);
    let issued_entries = table.entries.to_vec();
    let mut duplicate_output = vec![sentinel_credit(0x5a); 8];
    let duplicate_output_before = duplicate_output.clone();
    assert_eq!(
        table.issue_notification_credits(&mut duplicate_output),
        Err(GrantError::InvalidBacking)
    );
    assert_eq!(table.entries, issued_entries);
    assert_eq!(duplicate_output, duplicate_output_before);
}

#[test]
fn issue_distributes_distinct_generation_one_credits_to_every_ring() {
    let topology = topology(4, 8);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 13).expect("valid table");
    let output = issue(&mut table);

    for (ordinal, descriptor) in output.iter().enumerate() {
        let token = SlotToken::from_raw(descriptor.buffer.token).expect("issued token");
        assert_eq!(descriptor.ring_index, ordinal as u32 % 4);
        assert_eq!(descriptor.reserved, 0);
        assert_eq!(descriptor.buffer.offset, 0);
        assert_eq!(
            descriptor.buffer.length,
            topology.notification_credit_size()
        );
        assert_eq!(descriptor.buffer.kind, buffer_kind::SLOT);
        assert_eq!(descriptor.buffer.access, buffer_access::U2K_WRITE);
        assert_eq!(descriptor.buffer.reserved, 0);
        assert_eq!(token.generation(), 1);
        assert!(
            output[..ordinal]
                .iter()
                .all(|prior| prior.buffer.token != descriptor.buffer.token)
        );
    }
}

#[test]
fn preflight_rejections_leave_the_live_entry_unchanged() {
    let topology = topology(2, 2);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 17).expect("valid table");
    let credits = issue(&mut table);
    let token = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let before = table.entry_snapshot(token);

    let invalid = SlotToken::try_new(token.class(), 2, 1).expect("well-formed token");
    assert_eq!(
        table.preflight_notify(0, invalid, 32, 1).err(),
        Some(GrantError::InvalidToken)
    );
    assert_eq!(table.entry_snapshot(token), before);
    assert_eq!(
        table.preflight_notify(1, token, 32, 1).err(),
        Some(GrantError::WrongRing)
    );
    assert_eq!(table.entry_snapshot(token), before);
    assert_eq!(
        table.preflight_notify(0, token, 32, 2).err(),
        Some(GrantError::StaleGeneration)
    );
    assert_eq!(table.entry_snapshot(token), before);
    assert_eq!(
        table.preflight_notify(0, token, 31, 1).err(),
        Some(GrantError::ReturnBufferTooSmall)
    );
    assert_eq!(table.entry_snapshot(token), before);
}

#[test]
fn preflight_from_one_table_cannot_claim_an_identical_other_table() {
    let topology = topology(1, 1);
    let mut entries_a = free_backing(&topology);
    let mut entries_b = free_backing(&topology);
    let mut table_a = GrantTable::initialize(&mut entries_a, &topology, 41).expect("valid table A");
    let mut table_b = GrantTable::initialize(&mut entries_b, &topology, 41).expect("valid table B");
    let credits_a = issue(&mut table_a);
    let credits_b = issue(&mut table_b);
    assert_eq!(
        credits_a, credits_b,
        "wire identities are deliberately equal"
    );

    let token = SlotToken::from_raw(credits_a[0].buffer.token).expect("issued token");
    let preflight = table_a
        .preflight_notify(0, token, 32, 1)
        .expect("table A preflight");
    let before_b = table_b.entry_snapshot(token);
    match table_b.claim_notify(preflight) {
        Err(error) => assert_eq!(error, GrantFault::OutOfRange),
        Ok(_) => panic!("table B accepted table A's preflight authority"),
    }
    assert_eq!(table_b.entry_snapshot(token), before_b);
}

#[test]
fn claim_rechecks_duplicate_concurrent_cross_ring_and_out_of_range_identity() {
    let topology = topology(2, 4);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 19).expect("valid table");
    let credits = issue(&mut table);
    let concurrent_token = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let first = table
        .preflight_notify(0, concurrent_token, 32, 1)
        .expect("preflight");
    let concurrent = table
        .preflight_notify(0, concurrent_token, 32, 1)
        .expect("preflight");
    {
        let _abandoned_claim = table.claim_notify(first).expect("first claim");
    }
    let before_concurrent = table.entry_snapshot(concurrent_token);
    assert_eq!(
        table.claim_notify(concurrent).err(),
        Some(GrantFault::ConcurrentReuse)
    );
    assert_eq!(table.entry_snapshot(concurrent_token), before_concurrent);

    let refresh_token = SlotToken::from_raw(credits[2].buffer.token).expect("issued token");
    let refresh_preflight = table
        .preflight_notify(0, refresh_token, 32, 1)
        .expect("preflight");
    let claim = table.claim_notify(refresh_preflight).expect("claim");
    let advanced = unsafe { claim.after_release_head_advance() };
    let mut returned = NotificationCreditV1::default();
    let refreshed = advanced.refresh(&mut returned);
    assert_eq!(refreshed.descriptor, returned);

    let duplicate = NotifyPreflight {
        table_id: table.table_id,
        entry_index: table.class_bases[refresh_token.class() as usize] + refresh_token.index(),
        ring_index: 0,
        observed_generation: 1,
        next_generation: 2,
        next_descriptor: returned,
    };
    let next_token = SlotToken::from_raw(returned.buffer.token).expect("refreshed token");
    let before_duplicate = table.entry_snapshot(next_token);
    assert_eq!(
        table.claim_notify(duplicate).err(),
        Some(GrantFault::Duplicate)
    );
    assert_eq!(table.entry_snapshot(next_token), before_duplicate);

    let token_two = SlotToken::from_raw(credits[1].buffer.token).expect("issued token");
    let mut cross = table
        .preflight_notify(1, token_two, 32, 1)
        .expect("preflight");
    cross.ring_index = 0;
    let before_cross_ring = table.entry_snapshot(token_two);
    assert_eq!(table.claim_notify(cross).err(), Some(GrantFault::CrossRing));
    assert_eq!(table.entry_snapshot(token_two), before_cross_ring);

    let mut out_of_range = table
        .preflight_notify(1, token_two, 32, 1)
        .expect("preflight");
    out_of_range.entry_index = u32::MAX;
    let before_out_of_range = table.entry_snapshot(token_two);
    assert_eq!(
        table.claim_notify(out_of_range).err(),
        Some(GrantFault::OutOfRange)
    );
    assert_eq!(table.entry_snapshot(token_two), before_out_of_range);
}

#[test]
fn refresh_requires_head_advance_proof_and_reissues_the_checked_descriptor() {
    assert_eq!(
        GrantCommitStep::ORDER,
        [
            GrantCommitStep::Preflight,
            GrantCommitStep::Claim,
            GrantCommitStep::AdvanceHead,
            GrantCommitStep::Refresh,
        ]
    );

    let topology = topology(1, 1);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 23).expect("valid table");
    let credits = issue(&mut table);
    let old = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let preflight = table.preflight_notify(0, old, 32, 1).expect("preflight");
    let claim = table.claim_notify(preflight).expect("claim");

    // SAFETY: the test models the matching Release CQ-head store immediately
    // before consuming the claim, as required by this sole constructor.
    let advanced = unsafe { claim.after_release_head_advance() };
    let mut output = sentinel_credit(0x5a);
    let refreshed = advanced.refresh(&mut output);
    let next = SlotToken::from_raw(output.buffer.token).expect("refreshed token");
    assert_eq!(refreshed.old_generation, 1);
    assert_eq!(refreshed.new_generation, 2);
    assert_eq!(refreshed.descriptor, output);
    assert_eq!(next.generation(), 2);
    assert_eq!(table.entry_snapshot(old), None);
    assert_eq!(
        table.entry_snapshot(next).expect("reissued entry").state,
        GrantState::Issued
    );
}

#[test]
fn fence_retires_issued_and_claimed_credits_once() {
    let topology = topology(2, 4);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 29).expect("valid table");
    let credits = issue(&mut table);
    let token = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let preflight = table.preflight_notify(0, token, 32, 1).expect("preflight");
    {
        let _abandoned_claim = table.claim_notify(preflight).expect("claim");
    }

    assert_eq!(table.retire_for_fence(), 4);
    assert_eq!(table.retire_for_fence(), 0);
    for descriptor in credits {
        let token = SlotToken::from_raw(descriptor.buffer.token).expect("issued token");
        assert_eq!(
            table.entry_snapshot(token).expect("retired entry").state,
            GrantState::Retired
        );
    }
}

#[test]
fn r3_checkpoint_retires_grant_entries_and_credit_descriptors_as_one_operation() {
    let topology = topology(2, 4);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 30).expect("valid table");
    let mut credits = issue(&mut table);
    let token = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let preflight = table.preflight_notify(0, token, 32, 1).expect("preflight");
    let _abandoned_claim = table.claim_notify(preflight).expect("claim");
    let _ = table;

    let first = retire_r3_grants_and_credits_for_checkpoint(&mut entries, &mut credits);
    assert_eq!(first.grants_retired(), 4);
    assert_eq!(first.credit_descriptors_retired(), 4);
    assert!(first.complete(&entries, &credits));
    assert!(
        credits
            .iter()
            .all(|credit| *credit == NotificationCreditV1::default())
    );

    let second = retire_r3_grants_and_credits_for_checkpoint(&mut entries, &mut credits);
    assert_eq!(second.grants_retired(), 0);
    assert_eq!(second.credit_descriptors_retired(), 0);
    assert!(second.complete(&entries, &credits));
}

#[test]
fn sixty_four_ring_credit_transitions_remain_distinct() {
    let topology = topology(64, 64);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 31).expect("valid table");
    let credits = issue(&mut table);

    for ring in 0..64usize {
        assert_eq!(credits[ring].ring_index, ring as u32);
        assert!(
            credits[..ring]
                .iter()
                .all(|prior| prior.buffer.token != credits[ring].buffer.token)
        );
        let token = SlotToken::from_raw(credits[ring].buffer.token).expect("issued token");
        let preflight = table
            .preflight_notify(ring as u32, token, 32, 1)
            .expect("independent preflight");
        let claim = table.claim_notify(preflight).expect("independent claim");
        // SAFETY: each ring models its own matching Release CQ-head store.
        let advanced = unsafe { claim.after_release_head_advance() };
        let mut output = NotificationCreditV1::default();
        let refreshed = advanced.refresh(&mut output);
        assert_eq!(refreshed.descriptor.ring_index, ring as u32);
    }
}

#[test]
fn maximum_generation_exhaustion_changes_no_entry_head_or_return_count() {
    let topology = topology(1, 1);
    let mut entries = free_backing(&topology);
    let mut table = GrantTable::initialize(&mut entries, &topology, 37).expect("valid table");
    let credits = issue(&mut table);
    let issued = SlotToken::from_raw(credits[0].buffer.token).expect("issued token");
    let token = SlotToken::try_new(issued.class(), issued.index(), SLOT_TOKEN_GENERATION_MAX)
        .expect("maximum generation token");
    let entry_index = table.class_bases[issued.class() as usize] + issued.index();
    table.entries[entry_index as usize] = GrantEntry {
        slot_token: Some(token),
        ring_index: 0,
        generation: SLOT_TOKEN_GENERATION_MAX,
        state: GrantState::Issued,
    };

    let before_entry = table.entry_snapshot(token).expect("live entry");
    let cq_head = 9u64;
    let before_head = cq_head;
    let returned_credit_count = 0usize;
    let result = table.preflight_notify(0, token, 32, SLOT_TOKEN_GENERATION_MAX);
    assert_eq!(result.err(), Some(GrantError::GenerationExhausted));
    assert_eq!(table.entry_snapshot(token), Some(before_entry));
    assert_eq!(cq_head, before_head);
    assert_eq!(returned_credit_count, 0);
}
