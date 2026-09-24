use super::*;

use fsring_abi::{
    BootInstanceId, FeatureSet, MountId,
    codec::try_encode,
    control::{
        BOOT_CONTEXT_HEADER_BYTES, BOOT_CONTEXT_INITIAL_SEQUENCE, BOOT_CONTEXT_MAGIC,
        BOOT_CONTEXT_SECTION_BYTES, BOOT_CONTEXT_SLOT_BYTES, BOOT_CONTEXT_SLOT_COUNT,
        BOOT_CONTEXT_VERSION, BootContextHeaderV1, BootContextSlotV1, BootCounterError,
        BootIdentityError, BootSequenceError, boot_context_init_state, boot_context_slot_state,
    },
    digest::{boot_context_header_digest_v1, boot_context_slot_digest_v1},
    validate::{BootContextValidationError, validate_boot_context_header_v1},
};

const BOOT: BootInstanceId = BootInstanceId {
    lo: 0x0123_4567_89ab_cdef,
    hi: 0xfedc_ba98_7654_3210,
};
const KEY: [u8; 32] = [0xa5; 32];
const RANDOM_HIGH: u64 = 0xa5a5_a5a5_a5a5_a5a5;
const SERVICE_SID: [u8; 32] = [
    1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0,
];

fn header_as_bytes(header: &BootContextHeaderV1) -> [u8; 256] {
    let mut bytes = [0u8; 256];
    assert_eq!(try_encode(header, &mut bytes), Ok(256));
    bytes
}

fn slots_as_bytes(slots: &[BootContextSlotV1]) -> Vec<u8> {
    let mut bytes = vec![0u8; slots.len().saturating_mul(256)];
    for (slot, output) in slots.iter().zip(bytes.chunks_exact_mut(256)) {
        assert_eq!(try_encode(slot, output), Ok(256));
    }
    bytes
}

fn resign_header(header: &mut BootContextHeaderV1) {
    header.digest = [0; 32];
    header.digest = boot_context_header_digest_v1(header);
}

fn ready_header() -> BootContextHeaderV1 {
    let mut header = BootContextHeaderV1 {
        magic: BOOT_CONTEXT_MAGIC,
        format_version: BOOT_CONTEXT_VERSION,
        header_size: BOOT_CONTEXT_HEADER_BYTES,
        context_size: BOOT_CONTEXT_SECTION_BYTES,
        slot_size: BOOT_CONTEXT_SLOT_BYTES,
        slot_count: BOOT_CONTEXT_SLOT_COUNT,
        init_state: boot_context_init_state::READY,
        flags: 0,
        reserved0: 0,
        header_sequence: BOOT_CONTEXT_INITIAL_SEQUENCE,
        mount_sequence: 9,
        mount_sequence_complement: 9 ^ u64::MAX,
        load_generation: 7,
        load_generation_complement: 7 ^ u64::MAX,
        boot_instance_id: BOOT,
        per_boot_retire_key: KEY,
        digest: [0; 32],
        reserved: [0; 96],
    };
    resign_header(&mut header);
    header
}

fn free_slot(index: u32) -> BootContextSlotV1 {
    let mut slot = BootContextSlotV1 {
        sequence: BOOT_CONTEXT_INITIAL_SEQUENCE,
        state: boot_context_slot_state::FREE,
        service_sid_length: 0,
        load_generation: 0,
        mount_sequence: 0,
        mount_id: MountId::ZERO,
        boot_instance_id: BootInstanceId::ZERO,
        latest_session_epoch: 0,
        selected_features: FeatureSet { words: [0, 0] },
        journal_version: 0,
        flags: 0,
        service_sid: [0; 68],
        reserved: [0; 60],
        digest: [0; 32],
    };
    let Some(digest) = boot_context_slot_digest_v1(index, &slot) else {
        panic!("test slot index must be in range")
    };
    slot.digest = digest;
    slot
}

fn free_slots() -> [BootContextSlotV1; BOOT_CONTEXT_SLOT_COUNT as usize] {
    core::array::from_fn(|index| free_slot(index as u32))
}

fn non_free_slot(index: u32, state: u32) -> BootContextSlotV1 {
    let mut service_sid = [0u8; 68];
    let Some(service_sid_prefix) = service_sid.get_mut(..SERVICE_SID.len()) else {
        panic!("service SID fixture must fit")
    };
    service_sid_prefix.copy_from_slice(&SERVICE_SID);
    let (sequence, load_generation, latest_session_epoch) = match state {
        boot_context_slot_state::STAGING => (4, 7, 1),
        boot_context_slot_state::LIVE => (6, 5, 3),
        boot_context_slot_state::TERMINALIZING | boot_context_slot_state::TERMINAL => (8, 5, 3),
        _ => panic!("test requires a non-FREE state"),
    };
    let mut slot = BootContextSlotV1 {
        sequence,
        state,
        service_sid_length: 32,
        load_generation,
        mount_sequence: 8,
        mount_id: MountId {
            lo: 8,
            hi: 0x2122_2324_2526_2728,
        },
        boot_instance_id: BOOT,
        latest_session_epoch,
        selected_features: FeatureSet { words: [0x1c, 0] },
        journal_version: 1,
        flags: 0,
        service_sid,
        reserved: [0; 60],
        digest: [0; 32],
    };
    let Some(digest) = boot_context_slot_digest_v1(index, &slot) else {
        panic!("test slot index must be in range")
    };
    slot.digest = digest;
    slot
}

fn assert_header_error(header: BootContextHeaderV1, expected: BootContextValidationError) {
    assert_load_error(
        plan_existing_context(header, &free_slots()),
        BootPlanError::Validation(expected),
    );
}

fn assert_load_error(result: Result<BootLoadPlan, BootPlanError>, expected: BootPlanError) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("load plan unexpectedly succeeded; expected {expected:?}"),
    }
}

fn assert_burn_error(result: Result<MountBurnPlan, BootPlanError>, expected: BootPlanError) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("mount burn unexpectedly succeeded; expected {expected:?}"),
    }
}

fn assert_valid_header(header: &BootContextHeaderV1) {
    let validated = match validate_boot_context_header_v1(&header_as_bytes(header)) {
        Ok(validated) => validated,
        Err(error) => panic!("committed header did not validate: {error:?}"),
    };
    assert_eq!(header_as_bytes(&validated), header_as_bytes(header));
}

#[test]
fn a_new_zeroed_context_gets_canonical_initializing_and_ready_publications() {
    let Ok(BootLoadPlan::Initialize(publication)) = plan_new_context(BOOT, KEY) else {
        panic!("new context must initialize")
    };

    assert_eq!(
        publication.initial.init_state,
        boot_context_init_state::INITIALIZING
    );
    assert_eq!(publication.initial.header_sequence, 1);
    assert_eq!(
        publication.committed.init_state,
        boot_context_init_state::READY
    );
    assert_eq!(
        publication.committed.header_sequence,
        BOOT_CONTEXT_INITIAL_SEQUENCE
    );
    assert_eq!(publication.committed.mount_sequence, 0);
    assert_eq!(publication.committed.mount_sequence_complement, u64::MAX);
    assert_eq!(publication.committed.load_generation, 1);
    assert_eq!(
        publication.committed.load_generation_complement,
        u64::MAX - 1
    );
    assert_eq!(publication.committed.boot_instance_id, BOOT);
    assert_eq!(publication.committed.per_boot_retire_key, KEY);
    assert_eq!(publication.committed.flags, 0);
    assert_eq!(publication.committed.reserved0, 0);
    assert_eq!(publication.committed.reserved, [0; 96]);
    assert_eq!(
        publication.committed.digest,
        boot_context_header_digest_v1(&publication.committed),
    );
    assert_valid_header(&publication.committed);
}

#[test]
fn new_context_rejects_zero_boot_identity_and_retire_key() {
    assert_load_error(
        plan_new_context(BootInstanceId::ZERO, KEY),
        BootPlanError::Validation(BootContextValidationError::HeaderBootInstanceId),
    );
    assert_load_error(
        plan_new_context(BOOT, [0; 32]),
        BootPlanError::Validation(BootContextValidationError::HeaderRetireKey),
    );
}

#[test]
fn valid_ready_reload_advances_generation_with_sequence_only_in_progress_image() {
    let header = ready_header();
    let slots = free_slots();
    let before_slots = slots;
    let Ok(BootLoadPlan::Adopt(publication)) = plan_existing_context(header, &slots) else {
        panic!("valid READY context must be adopted")
    };

    let mut expected_initial = header;
    expected_initial.header_sequence = 3;
    assert_eq!(
        header_as_bytes(&publication.initial),
        header_as_bytes(&expected_initial),
        "the odd publication changes only the sequence word",
    );
    assert_eq!(publication.committed.header_sequence, 4);
    assert_eq!(publication.committed.load_generation, 8);
    assert_eq!(
        publication.committed.load_generation_complement,
        8 ^ u64::MAX
    );
    assert_eq!(publication.committed.mount_sequence, header.mount_sequence);
    assert_eq!(
        publication.committed.mount_sequence_complement,
        header.mount_sequence_complement,
    );
    assert_valid_header(&publication.committed);
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));
}

#[test]
fn every_invalid_header_shape_is_preserved_as_a_validation_error() {
    let mut header = ready_header();
    header.magic ^= 1;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderFormat);

    let mut header = ready_header();
    header.init_state = boot_context_init_state::INITIALIZING;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderInitState);

    let mut header = ready_header();
    header.header_sequence = 3;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderSequence);

    let mut header = ready_header();
    header.mount_sequence = 10;
    assert_header_error(header, BootContextValidationError::HeaderDigest);

    let mut header = ready_header();
    header.flags = 1;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderFlagsOrReserved);

    let mut header = ready_header();
    header.mount_sequence_complement ^= 1;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderComplement);

    let mut header = ready_header();
    header.load_generation_complement ^= 1;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderComplement);

    let mut header = ready_header();
    header.boot_instance_id = BootInstanceId::ZERO;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderBootInstanceId);

    let mut header = ready_header();
    header.per_boot_retire_key = [0; 32];
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderRetireKey);

    let mut header = ready_header();
    header.load_generation = 0;
    header.load_generation_complement = u64::MAX;
    resign_header(&mut header);
    assert_header_error(header, BootContextValidationError::HeaderLoadGeneration);
}

#[test]
fn torn_or_malformed_free_slots_fail_validation_without_mutation() {
    let header = ready_header();
    let mut slots = free_slots();
    slots[0].sequence = 3;
    slots[0].digest = boot_context_slot_digest_v1(0, &slots[0]).unwrap_or([0; 32]);
    let before_slots = slots;
    assert_load_error(
        plan_existing_context(header, &slots),
        BootPlanError::Validation(BootContextValidationError::SlotSequence),
    );
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));

    let mut slots = free_slots();
    slots[0].digest[0] ^= 1;
    let before_slots = slots;
    assert_load_error(
        plan_existing_context(header, &slots),
        BootPlanError::Validation(BootContextValidationError::SlotDigest),
    );
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));

    let mut slots = free_slots();
    slots[0].mount_sequence = 1;
    slots[0].digest = boot_context_slot_digest_v1(0, &slots[0]).unwrap_or([0; 32]);
    let before_slots = slots;
    assert_load_error(
        plan_existing_context(header, &slots),
        BootPlanError::Validation(BootContextValidationError::SlotFreeShape),
    );
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));
}

#[test]
fn an_existing_context_requires_the_complete_permanent_slot_array() {
    let slots = free_slots();
    assert_load_error(
        plan_existing_context(ready_header(), &slots[..63]),
        BootPlanError::Validation(BootContextValidationError::InvalidLength),
    );
}

#[test]
fn every_valid_non_free_state_refuses_downgrade_without_changing_slots() {
    for state in [
        boot_context_slot_state::STAGING,
        boot_context_slot_state::LIVE,
        boot_context_slot_state::TERMINALIZING,
        boot_context_slot_state::TERMINAL,
    ] {
        let mut slots = free_slots();
        slots[0] = non_free_slot(0, state);
        let before_slots = slots;
        assert_load_error(
            plan_existing_context(ready_header(), &slots),
            BootPlanError::ActivePermanentSlot,
        );
        assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));
    }
}

#[test]
fn a_valid_non_free_slot_does_not_hide_later_snapshot_corruption() {
    let mut slots = free_slots();
    slots[0] = non_free_slot(0, boot_context_slot_state::LIVE);
    slots[1].digest[0] ^= 1;
    let before_slots = slots;

    assert_load_error(
        plan_existing_context(ready_header(), &slots),
        BootPlanError::Validation(BootContextValidationError::SlotDigest),
    );
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));
}

#[test]
fn duplicate_mount_sequence_in_slots_zero_and_sixty_three_is_corruption() {
    let mut slots = free_slots();
    slots[0] = non_free_slot(0, boot_context_slot_state::LIVE);
    slots[63] = non_free_slot(63, boot_context_slot_state::TERMINAL);
    let before_slots = slots;

    assert_load_error(
        plan_existing_context(ready_header(), &slots),
        BootPlanError::Validation(BootContextValidationError::DuplicateMountSequence),
    );
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));
}

#[test]
fn existing_reload_maps_load_generation_and_publication_exhaustion() {
    let mut header = ready_header();
    header.load_generation = u64::MAX;
    header.load_generation_complement = 0;
    resign_header(&mut header);
    assert_load_error(
        plan_existing_context(header, &free_slots()),
        BootPlanError::Counter(BootCounterError::Exhausted),
    );

    let mut header = ready_header();
    header.header_sequence = u64::MAX - 1;
    resign_header(&mut header);
    assert_load_error(
        plan_existing_context(header, &free_slots()),
        BootPlanError::Publication(BootSequenceError::Exhausted),
    );
}

#[test]
fn mount_burn_maps_counter_publication_and_identity_failures() {
    let mut header = ready_header();
    header.mount_sequence = u64::MAX;
    header.mount_sequence_complement = 0;
    resign_header(&mut header);
    assert_burn_error(
        plan_mount_burn(&header, RANDOM_HIGH),
        BootPlanError::Counter(BootCounterError::Exhausted),
    );

    let mut header = ready_header();
    header.header_sequence = u64::MAX - 1;
    resign_header(&mut header);
    assert_burn_error(
        plan_mount_burn(&header, RANDOM_HIGH),
        BootPlanError::Publication(BootSequenceError::Exhausted),
    );

    assert_burn_error(
        plan_mount_burn(&ready_header(), 0),
        BootPlanError::Identity(BootIdentityError::ZeroRandomHigh),
    );
}

#[test]
fn two_consecutive_mount_burns_are_unique_checked_publications() {
    let header = ready_header();
    let first = match plan_mount_burn(&header, RANDOM_HIGH) {
        Ok(plan) => plan,
        Err(error) => panic!("first burn failed: {error:?}"),
    };
    let second = match plan_mount_burn(&first.committed(), 0xa5a5_a5a5_a5a5_a5a6) {
        Ok(plan) => plan,
        Err(error) => panic!("second burn failed: {error:?}"),
    };

    assert_eq!(
        first.mount_id(),
        MountId {
            lo: 10,
            hi: RANDOM_HIGH
        }
    );
    assert_eq!(
        second.mount_id(),
        MountId {
            lo: 11,
            hi: 0xa5a5_a5a5_a5a5_a5a6,
        },
    );
    assert_eq!(first.committed().header_sequence, 4);
    assert_eq!(second.committed().header_sequence, 6);
    assert_valid_header(&second.committed());
}

#[test]
fn volatile_mount_burn_preserves_header_before_image_and_all_permanent_slot_bytes() {
    let header = ready_header();
    let slots = free_slots();
    let before_slots = slots;
    let burn = match plan_mount_burn(&header, RANDOM_HIGH) {
        Ok(plan) => plan,
        Err(error) => panic!("burn failed: {error:?}"),
    };

    assert_eq!(burn.mount_id().lo, header.mount_sequence + 1);
    assert_eq!(burn.mount_id().hi, RANDOM_HIGH);
    assert_eq!(header_as_bytes(&burn.before()), header_as_bytes(&header));
    assert_eq!(slots_as_bytes(&slots), slots_as_bytes(&before_slots));
}
