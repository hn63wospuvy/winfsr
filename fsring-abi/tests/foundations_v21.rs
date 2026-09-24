use core::mem::{align_of, size_of};

use fsring_abi::{
    features::{
        os_cap, protocol_feature, BASE_REQUIRED_PROTOCOL_MASK, UNSELECTABLE_PROTOCOL_MASK,
        WIN10_ARM64_OS_CAPABILITIES, WIN10_ARM64_PROTOCOL_MASK, WIN10_X64_OS_CAPABILITIES,
        WIN10_X64_PROTOCOL_MASK, WIN7_X64_OS_CAPABILITIES, WIN7_X64_PROTOCOL_MASK,
    },
    ids::REQ_INDEX_MAX,
    limits::{
        classify_req_index, validate_file_range, RangeError, ReqIndexClass, ReqIndexError,
        CONTROL_SQ_RESERVE_PER_RING, GLOBAL_EXTERNAL_CHANGE_ACK_REQID, MAX_CQ_CAPACITY,
        MAX_FILE_SIZE, MAX_INFLIGHT, MAX_PENDING_ASYNC_IRPS_GLOBAL,
        MAX_PENDING_ASYNC_IRPS_PER_IO_OWNER, MAX_PENDING_ASYNC_IRPS_PER_MOUNT,
        MAX_PENDING_ASYNC_MDL_BYTES_GLOBAL, MAX_PENDING_ASYNC_MDL_BYTES_PER_IO_OWNER,
        MAX_PENDING_ASYNC_MDL_BYTES_PER_MOUNT, MAX_RETAINED_OPENS_GLOBAL,
        MAX_RETAINED_OPENS_PER_MOUNT, MAX_RETAINED_OPENS_PER_RING, MAX_RING_COUNT,
        MAX_SECTION_BYTES, MAX_SLOT_COUNT, MAX_SLOT_SIZE, MAX_SQ_CAPACITY, MIN_CQ_CAPACITY,
        MIN_RING_COUNT, MIN_SLOT_COUNT, MIN_SLOT_SIZE, MIN_SQ_CAPACITY, SLOT_ALIGNMENT,
        SYSTEM_REQID_BASE, SYSTEM_REQUEST_SLOTS_PER_RING, USER_VIEW_OFFSET_ALIGNMENT,
    },
    slots::{
        SlotToken, SlotTokenError, SLOT_TOKEN_CLASS_MAX, SLOT_TOKEN_GENERATION_MAX,
        SLOT_TOKEN_INDEX_MAX,
    },
    FSRING_ABI_MAJOR, FSRING_ABI_MINOR, FSRING_ABI_MIN_COMPAT_MINOR,
};

#[test]
fn feature_and_profile_registry_is_closed_for_abi_21() {
    assert_eq!(protocol_feature::CASE_SENSITIVE_NAMES, 9);
    assert_eq!(BASE_REQUIRED_PROTOCOL_MASK.words, [0x10, 0]);
    assert_eq!(UNSELECTABLE_PROTOCOL_MASK.words, [0x360, 0]);
    assert_eq!(WIN10_X64_PROTOCOL_MASK.words, [0x9f, 0]);
    assert_eq!(WIN10_ARM64_PROTOCOL_MASK.words, [0x9f, 0]);
    assert_eq!(WIN7_X64_PROTOCOL_MASK.words, [0x1f, 0]);
    assert_eq!(WIN10_X64_OS_CAPABILITIES.words, [0x3, 0]);
    assert_eq!(WIN10_ARM64_OS_CAPABILITIES.words, [0xb, 0]);
    assert_eq!(WIN7_X64_OS_CAPABILITIES.words, [0, 0]);
    assert_eq!(os_cap::MDL_NO_WRITE, 0);
    assert_eq!(os_cap::MDL_NO_EXECUTE, 1);
    assert_eq!(os_cap::MODERN_COHERENCY, 2);
    assert_eq!(os_cap::ARM64, 3);
}

#[test]
fn slot_token_uses_all_42_generation_bits_and_rejects_invalid_fields() {
    assert_eq!(size_of::<SlotToken>(), 8);
    assert_eq!(align_of::<SlotToken>(), 8);
    assert_eq!(SLOT_TOKEN_CLASS_MAX, 3);
    assert_eq!(SLOT_TOKEN_INDEX_MAX, 0x0f_ffff);
    assert_eq!(SLOT_TOKEN_GENERATION_MAX, (1u64 << 42) - 1);

    let generation = (1u64 << 41) | 7;
    let token = SlotToken::try_new(3, 0x0f_ffff, generation).unwrap();
    const GOLDEN_RAW: u64 = 0x8000_0000_01ff_ffff;
    assert_eq!(token.raw(), GOLDEN_RAW);
    assert_eq!(SlotToken::from_raw(GOLDEN_RAW), Ok(token));
    assert_eq!(token.class(), 3);
    assert_eq!(token.index(), 0x0f_ffff);
    assert_eq!(token.generation(), generation);
    assert_eq!(SlotToken::from_raw(token.raw()), Ok(token));

    let max = SlotToken::try_new(3, SLOT_TOKEN_INDEX_MAX, SLOT_TOKEN_GENERATION_MAX).unwrap();
    assert_eq!(max.raw(), u64::MAX);
    assert_eq!(max.generation(), SLOT_TOKEN_GENERATION_MAX);
    assert_eq!(
        SlotToken::try_new(4, 0, 1),
        Err(SlotTokenError::ClassOutOfRange)
    );
    assert_eq!(
        SlotToken::try_new(0, SLOT_TOKEN_INDEX_MAX + 1, 1),
        Err(SlotTokenError::IndexOutOfRange)
    );
    assert_eq!(
        SlotToken::try_new(0, 0, 0),
        Err(SlotTokenError::ZeroGeneration)
    );
    assert_eq!(SlotToken::from_raw(0), Err(SlotTokenError::ZeroGeneration));
    assert_eq!(
        SlotToken::try_new(0, 0, SLOT_TOKEN_GENERATION_MAX + 1),
        Err(SlotTokenError::GenerationOutOfRange)
    );
}

#[test]
fn shared_scalar_limits_are_exact() {
    assert_eq!(SLOT_ALIGNMENT, 64);
    assert_eq!(USER_VIEW_OFFSET_ALIGNMENT, 65_536);
    assert_eq!(MIN_SLOT_SIZE, 256);
    assert_eq!(MAX_SLOT_SIZE, 16 * 1024 * 1024);
    assert_eq!(MIN_SLOT_COUNT, 1);
    assert_eq!(MAX_SLOT_COUNT, 1 << 20);
    assert_eq!(MIN_RING_COUNT, 1);
    assert_eq!(MAX_RING_COUNT, 64);
    assert_eq!(MIN_SQ_CAPACITY, 8);
    assert_eq!(MIN_CQ_CAPACITY, 2);
    assert_eq!(MAX_SQ_CAPACITY, 65_536);
    assert_eq!(MAX_CQ_CAPACITY, 65_536);
    assert_eq!(MAX_INFLIGHT, 16_777_023);
    assert_eq!(CONTROL_SQ_RESERVE_PER_RING, 4);
    assert_eq!(SYSTEM_REQUEST_SLOTS_PER_RING, 3);
    assert_eq!(SYSTEM_REQID_BASE, 16_777_023);
    assert_eq!(GLOBAL_EXTERNAL_CHANGE_ACK_REQID, 16_777_215);
    assert_eq!(GLOBAL_EXTERNAL_CHANGE_ACK_REQID, REQ_INDEX_MAX);
    assert_eq!(MAX_SECTION_BYTES, 1_073_741_824);
    assert_eq!(MAX_RETAINED_OPENS_PER_RING, 4_096);
    assert_eq!(MAX_RETAINED_OPENS_PER_MOUNT, 262_144);
    assert_eq!(MAX_RETAINED_OPENS_GLOBAL, 1_048_576);
    assert_eq!(MAX_PENDING_ASYNC_IRPS_PER_IO_OWNER, 1_024);
    assert_eq!(MAX_PENDING_ASYNC_IRPS_PER_MOUNT, 16_384);
    assert_eq!(MAX_PENDING_ASYNC_IRPS_GLOBAL, 65_536);
    assert_eq!(MAX_PENDING_ASYNC_MDL_BYTES_PER_IO_OWNER, 67_108_864);
    assert_eq!(MAX_PENDING_ASYNC_MDL_BYTES_PER_MOUNT, 268_435_456);
    assert_eq!(MAX_PENDING_ASYNC_MDL_BYTES_GLOBAL, 1_073_741_824);
    assert_eq!(MAX_FILE_SIZE, i64::MAX as u64);
    // Wave 10 activates ABI 2.1: minor 1, min-compatible minor 1, major stays 2.
    assert_eq!(FSRING_ABI_MAJOR, 2);
    assert_eq!(FSRING_ABI_MINOR, 1, "Wave 10 owns the ABI minor cutover");
    assert_eq!(FSRING_ABI_MIN_COMPAT_MINOR, 1);
}

#[test]
fn file_ranges_are_checked_without_wrap() {
    assert_eq!(validate_file_range(0, 0, true), Ok(()));
    assert_eq!(
        validate_file_range(1, 0, true),
        Err(RangeError::WholeStreamOffsetNonZero)
    );
    assert_eq!(
        validate_file_range(0, 0, false),
        Err(RangeError::ZeroLength)
    );
    assert_eq!(validate_file_range(MAX_FILE_SIZE - 1, 1, false), Ok(()));
    assert_eq!(
        validate_file_range(MAX_FILE_SIZE - 1, 2, false),
        Err(RangeError::EndOutOfRange)
    );
    assert_eq!(
        validate_file_range(MAX_FILE_SIZE, 1, false),
        Err(RangeError::OffsetOutOfRange)
    );
    assert_eq!(
        validate_file_range(0, MAX_FILE_SIZE + 1, false),
        Err(RangeError::LengthOutOfRange)
    );
    assert_eq!(
        validate_file_range(u64::MAX - 1, u64::MAX, false),
        Err(RangeError::OffsetOutOfRange)
    );
}

#[test]
fn request_index_partitions_are_disjoint_and_exhaustive() {
    assert_eq!(
        classify_req_index(0, 1, 1),
        Ok(ReqIndexClass::Application { index: 0 })
    );
    assert_eq!(classify_req_index(1, 1, 1), Err(ReqIndexError::Unassigned));
    assert_eq!(
        classify_req_index(SYSTEM_REQID_BASE, 1, 1),
        Ok(ReqIndexClass::OpenLifecycle { ring_index: 0 })
    );
    assert_eq!(
        classify_req_index(SYSTEM_REQID_BASE + 1, 1, 1),
        Ok(ReqIndexClass::PtRouteAck { ring_index: 0 })
    );
    assert_eq!(
        classify_req_index(SYSTEM_REQID_BASE + 2, 1, 1),
        Ok(ReqIndexClass::PtExternalSafeAck { ring_index: 0 })
    );
    assert_eq!(
        classify_req_index(SYSTEM_REQID_BASE + 3, 1, 1),
        Err(ReqIndexError::Unassigned)
    );
    assert_eq!(
        classify_req_index(GLOBAL_EXTERNAL_CHANGE_ACK_REQID, 1, 1),
        Ok(ReqIndexClass::ExternalChangeAck)
    );

    let last_ring_base = SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING * 63;
    assert_eq!(
        classify_req_index(MAX_INFLIGHT - 1, 64, MAX_INFLIGHT),
        Ok(ReqIndexClass::Application {
            index: MAX_INFLIGHT - 1,
        })
    );
    assert_eq!(
        classify_req_index(last_ring_base, 64, MAX_INFLIGHT),
        Ok(ReqIndexClass::OpenLifecycle { ring_index: 63 })
    );
    assert_eq!(
        classify_req_index(last_ring_base + 2, 64, MAX_INFLIGHT),
        Ok(ReqIndexClass::PtExternalSafeAck { ring_index: 63 })
    );
    assert_eq!(last_ring_base + 3, GLOBAL_EXTERNAL_CHANGE_ACK_REQID);
    assert_eq!(
        classify_req_index(GLOBAL_EXTERNAL_CHANGE_ACK_REQID - 1, 1, 1),
        Err(ReqIndexError::Unassigned)
    );
    assert_eq!(
        classify_req_index(REQ_INDEX_MAX + 1, 64, MAX_INFLIGHT),
        Err(ReqIndexError::IndexOutOfRange)
    );
}

#[test]
fn request_index_classification_rejects_invalid_configuration() {
    assert_eq!(
        classify_req_index(0, 0, 1),
        Err(ReqIndexError::RingCountOutOfRange)
    );
    assert_eq!(
        classify_req_index(0, MAX_RING_COUNT + 1, 1),
        Err(ReqIndexError::RingCountOutOfRange)
    );
    assert_eq!(
        classify_req_index(0, 1, 0),
        Err(ReqIndexError::MaxInflightOutOfRange)
    );
    assert_eq!(
        classify_req_index(0, 1, MAX_INFLIGHT + 1),
        Err(ReqIndexError::MaxInflightOutOfRange)
    );
}

fn audit_entire_req_index_domain(ring_count: u32, max_inflight: u32) {
    let mut application_count = 0u64;
    let mut open_lifecycle_count = 0u64;
    let mut pt_route_ack_count = 0u64;
    let mut pt_external_safe_ack_count = 0u64;
    let mut external_change_ack_count = 0u64;
    let mut unassigned_count = 0u64;

    for index in 0..=REQ_INDEX_MAX {
        match classify_req_index(index, ring_count, max_inflight) {
            Ok(ReqIndexClass::Application { index: classified }) => {
                assert_eq!(classified, index);
                assert!(index < max_inflight);
                application_count += 1;
            }
            Ok(ReqIndexClass::OpenLifecycle { ring_index }) => {
                assert!(ring_index < ring_count);
                assert_eq!(
                    index,
                    SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING * ring_index
                );
                open_lifecycle_count += 1;
            }
            Ok(ReqIndexClass::PtRouteAck { ring_index }) => {
                assert!(ring_index < ring_count);
                assert_eq!(
                    index,
                    SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING * ring_index + 1
                );
                pt_route_ack_count += 1;
            }
            Ok(ReqIndexClass::PtExternalSafeAck { ring_index }) => {
                assert!(ring_index < ring_count);
                assert_eq!(
                    index,
                    SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING * ring_index + 2
                );
                pt_external_safe_ack_count += 1;
            }
            Ok(ReqIndexClass::ExternalChangeAck) => {
                assert_eq!(index, GLOBAL_EXTERNAL_CHANGE_ACK_REQID);
                external_change_ack_count += 1;
            }
            Err(ReqIndexError::Unassigned) => {
                assert!(index >= max_inflight);
                assert!(
                    index < SYSTEM_REQID_BASE
                        || index >= SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING * ring_count
                );
                assert_ne!(index, GLOBAL_EXTERNAL_CHANGE_ACK_REQID);
                unassigned_count += 1;
            }
            Err(error) => panic!("valid 24-bit index rejected with {error:?}"),
        }
    }

    assert_eq!(application_count, u64::from(max_inflight));
    assert_eq!(open_lifecycle_count, u64::from(ring_count));
    assert_eq!(pt_route_ack_count, u64::from(ring_count));
    assert_eq!(pt_external_safe_ack_count, u64::from(ring_count));
    assert_eq!(external_change_ack_count, 1);
    assert_eq!(
        unassigned_count,
        u64::from(REQ_INDEX_MAX) + 1
            - u64::from(max_inflight)
            - u64::from(SYSTEM_REQUEST_SLOTS_PER_RING) * u64::from(ring_count)
            - 1
    );
}

#[test]
fn request_index_partition_is_exhaustive_over_the_24_bit_domain() {
    audit_entire_req_index_domain(MIN_RING_COUNT, 1);
    audit_entire_req_index_domain(MAX_RING_COUNT, MAX_INFLIGHT);
}
