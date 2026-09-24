use core::mem::{offset_of, size_of};

use fsring_abi::codec::try_encode;
use fsring_abi::control::{SetupRequestV1, SlotClassRequest, SETUP_REQUEST_V1_SIZE};
use fsring_abi::features::{FeatureSet, PlatformProfile};
use fsring_abi::layout::{ConsumerPage, GlobalHeader, ProducerPage, RingDesc, FSRING_MAGIC};
use fsring_abi::limits::{
    MAX_CQ_CAPACITY, MAX_SQ_CAPACITY, MIN_CONTROL_SLOT_SIZE, MIN_CQ_CAPACITY,
    MIN_K2U_PROGRESS_SLOTS_PER_RING, MIN_NOTIFICATION_CREDIT_SIZE, MIN_SQ_CAPACITY,
    MIN_U2K_PROGRESS_SLOTS_PER_RING,
};
use fsring_abi::msgs::ControlHeader;
use fsring_abi::section_layout::{
    validate_finished_section_v21, validate_header_directory_v21, SectionLayoutError,
    SectionLayoutPlan,
};
use fsring_abi::validate::{validate_setup_request_v1, ValidatedSetupRequest};

const SECURITY: FeatureSet = FeatureSet { words: [0x10, 0] };
const ZERO_CLASS: SlotClassRequest = SlotClassRequest {
    slot_size: 0,
    slot_count: 0,
};

const _: () = assert!(core::mem::size_of::<SectionLayoutPlan>() <= 512);

fn setup(ring_count: u32, sq_capacity: u32, cq_capacity: u32) -> ValidatedSetupRequest {
    let request = SetupRequestV1 {
        header: ControlHeader {
            struct_size: SETUP_REQUEST_V1_SIZE,
            struct_version: 1,
            required_flags: 0,
        },
        abi_major: 2,
        min_abi_minor: 1,
        max_abi_minor: 1,
        reserved0: 0,
        offered_features: SECURITY,
        required_features: SECURITY,
        required_os_capabilities: FeatureSet { words: [0, 0] },
        ring_count,
        sq_capacity,
        cq_capacity,
        max_inflight: 1,
        k2u_slot_classes: [
            SlotClassRequest {
                slot_size: MIN_CONTROL_SLOT_SIZE,
                slot_count: MIN_K2U_PROGRESS_SLOTS_PER_RING * ring_count,
            },
            ZERO_CLASS,
            ZERO_CLASS,
            ZERO_CLASS,
        ],
        u2k_slot_classes: [
            SlotClassRequest {
                slot_size: MIN_NOTIFICATION_CREDIT_SIZE,
                slot_count: ring_count,
            },
            SlotClassRequest {
                slot_size: MIN_CONTROL_SLOT_SIZE,
                slot_count: MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count,
            },
            ZERO_CLASS,
            ZERO_CLASS,
        ],
        notification_credit_count: ring_count,
        notification_credit_size: MIN_NOTIFICATION_CREDIT_SIZE,
        flags: 0,
        reserved1: 0,
    };
    let mut bytes = [0u8; SETUP_REQUEST_V1_SIZE as usize];
    try_encode(&request, &mut bytes).expect("SETUP encodes");
    validate_setup_request_v1(
        &bytes,
        PlatformProfile::Win10X64,
        SECURITY,
        FeatureSet { words: [0x3, 0] },
        true,
    )
    .expect("test SETUP validates")
}

#[test]
fn compact_plan_has_literal_geometry_and_lazy_ring_iteration() {
    // Mutation caught: storing a 64-element ring array, changing placement order,
    // or making ring()/rings() disagree.
    let setup = setup(1, MIN_SQ_CAPACITY, MIN_CQ_CAPACITY);
    let plan = SectionLayoutPlan::compute(&setup, 4096).expect("valid plan");

    assert_eq!(plan.rings().count(), setup.topology().ring_count() as usize);
    assert_eq!(plan.ring(0), plan.rings().next());
    assert!(plan.ring(setup.topology().ring_count()).is_none());
    assert_eq!(plan.ring_directory().offset, 65_536);
    assert_eq!(plan.ring_directory().length, 4_096);
    let ring = plan.ring(0).expect("ring zero");
    assert_eq!(ring.sq_producer.offset, 131_072);
    assert_eq!(ring.sq_consumer.offset, 196_608);
    assert_eq!(ring.sq_entries.offset, 262_144);
    assert_eq!(ring.cq_producer.offset, 327_680);
    assert_eq!(ring.cq_consumer.offset, 393_216);
    assert_eq!(ring.cq_entries.offset, 458_752);
    assert_eq!(plan.k2u_slots().offset, 524_288);
    assert_eq!(plan.k2u_slots().length, 524_288);
    assert_eq!(plan.u2k_slots().offset, 1_048_576);
    assert_eq!(plan.u2k_slots().length, 327_680);
    assert_eq!(plan.notify_names().offset, 1_376_256);
    assert_eq!(plan.section_size(), 1_441_792);
    assert_eq!(plan.protocol_features(), SECURITY);
    assert_eq!(plan.os_capabilities(), FeatureSet { words: [0x3, 0] });
}

#[test]
fn ring_count_capacity_and_page_boundaries_are_checked() {
    // Mutation caught: accepting non-power-of-two pages/capacities, overflowing
    // geometry, or indexing only the first/smallest topology.
    for ring_count in [1, 16, 64] {
        for (sq, cq) in [
            (MIN_SQ_CAPACITY, MIN_CQ_CAPACITY),
            (MAX_SQ_CAPACITY, MAX_CQ_CAPACITY),
        ] {
            let setup = setup(ring_count, sq, cq);
            let plan = SectionLayoutPlan::compute(&setup, 4096).expect("boundary plan");
            assert_eq!(plan.ring_count(), ring_count);
            assert_eq!(plan.sq_capacity(), sq);
            assert_eq!(plan.cq_capacity(), cq);
            assert_eq!(plan.rings().count(), ring_count as usize);
            assert_eq!(plan.section_size() % 65_536, 0);
        }
    }

    let setup = setup(1, MIN_SQ_CAPACITY, MIN_CQ_CAPACITY);
    for exponent in 0..=26 {
        SectionLayoutPlan::compute(&setup, 1u32 << exponent).expect("valid page boundary");
    }
    for page in [0, 3, u32::MAX] {
        assert_eq!(
            SectionLayoutPlan::compute(&setup, page).err(),
            Some(SectionLayoutError::InvalidPageSize)
        );
    }
    for exponent in 27..=31 {
        assert_eq!(
            SectionLayoutPlan::compute(&setup, 1u32 << exponent).err(),
            Some(SectionLayoutError::SectionTooLarge)
        );
    }
}

#[test]
fn generated_valid_topologies_keep_every_ring_in_canonical_order() {
    // Mutation caught: a capacity-dependent stride, a non-power-of-two ring
    // count, or a late ring derives from an earlier ring's descriptor.
    for ring_count in [1, 2, 3, 16, 31, 64] {
        for exponent in 0..=13 {
            let sq = MIN_SQ_CAPACITY << exponent;
            let cq = MIN_CQ_CAPACITY << exponent.min(15);
            let setup = setup(ring_count, sq, cq);
            let plan = SectionLayoutPlan::compute(&setup, 4096).expect("generated topology");
            let mut previous_end = plan.ring_directory().offset + plan.ring_directory().length;
            for (expected_index, ring) in plan.rings().enumerate() {
                assert_eq!(ring.ring_index, expected_index as u32);
                assert!(ring.sq_producer.offset >= previous_end);
                assert!(ring.sq_producer.offset < ring.sq_consumer.offset);
                assert!(ring.sq_consumer.offset < ring.sq_entries.offset);
                assert!(ring.sq_entries.offset < ring.cq_producer.offset);
                assert!(ring.cq_producer.offset < ring.cq_consumer.offset);
                assert!(ring.cq_consumer.offset < ring.cq_entries.offset);
                previous_end = ring.cq_entries.offset + ring.cq_entries.length;
            }
            assert!(plan.k2u_slots().offset >= previous_end);
        }
    }
}

fn constructed(setup: &ValidatedSetupRequest) -> (SectionLayoutPlan, Vec<u8>) {
    let plan = SectionLayoutPlan::compute(setup, 4096).expect("compute");
    let mut bytes = vec![0u8; plan.section_size() as usize];
    plan.construct(&mut bytes).expect("construct");
    (plan, bytes)
}

#[test]
fn construct_requires_zero_output_and_writes_only_header_directory() {
    // Mutation caught: accepting dirty output, truncating output, or initializing
    // a cursor/arena byte to a non-zero value.
    let setup = setup(1, MIN_SQ_CAPACITY, MIN_CQ_CAPACITY);
    let plan = SectionLayoutPlan::compute(&setup, 4096).expect("compute");
    let mut short = vec![0u8; plan.section_size() as usize - 1];
    assert_eq!(
        plan.construct(&mut short),
        Err(SectionLayoutError::BufferTooSmall)
    );
    let mut dirty = vec![0u8; plan.section_size() as usize];
    dirty[plan.section_size() as usize - 1] = 1;
    assert_eq!(
        plan.construct(&mut dirty),
        Err(SectionLayoutError::OutputNotZero)
    );

    let (_, bytes) = constructed(&setup);
    let ring = plan.ring(0).unwrap();
    for offset in [
        ring.sq_producer.offset,
        ring.sq_consumer.offset,
        ring.cq_producer.offset,
        ring.cq_consumer.offset,
        plan.k2u_slots().offset,
        plan.u2k_slots().offset,
        plan.notify_names().offset,
    ] {
        assert_eq!(bytes[offset as usize], 0);
    }
}

#[test]
fn split_snapshot_parser_recomputes_identity_order_and_descriptors() {
    // Mutation caught: trusting header-produced placement, descriptor order, or
    // reserved bytes instead of independently comparing canonical values.
    let setup = setup(16, MIN_SQ_CAPACITY, MIN_CQ_CAPACITY);
    let (plan, bytes) = constructed(&setup);
    let header = bytes[..size_of::<GlobalHeader>()].to_vec();
    let directory = bytes[plan.ring_directory().offset as usize
        ..(plan.ring_directory().offset + plan.ring_directory().length) as usize]
        .to_vec();
    let parsed =
        validate_header_directory_v21(&header, &directory, &setup, 1).expect("canonical snapshots");
    assert_eq!(parsed.plan(), &plan);

    let mut bad_header = header.clone();
    bad_header[offset_of!(GlobalHeader, magic)] ^= 1;
    assert_eq!(
        validate_header_directory_v21(&bad_header, &directory, &setup, 1).err(),
        Some(SectionLayoutError::InvalidIdentity)
    );
    let mut bad_directory = directory.clone();
    bad_directory[offset_of!(RingDesc, ring_index)] ^= 1;
    assert_eq!(
        validate_header_directory_v21(&header, &bad_directory, &setup, 1).err(),
        Some(SectionLayoutError::InvalidDescriptor)
    );
    let mut bad_reserved = directory;
    bad_reserved[offset_of!(RingDesc, reserved)] = 1;
    assert_eq!(
        validate_header_directory_v21(&header, &bad_reserved, &setup, 1).err(),
        Some(SectionLayoutError::InvalidDescriptor)
    );
}

#[test]
fn every_header_and_directory_field_class_is_single_byte_hostile() {
    // Mutation caught: omitting any identity, region, feature, class, flag,
    // reserved, descriptor, or directory-padding comparison.
    let setup = setup(1, MIN_SQ_CAPACITY, MIN_CQ_CAPACITY);
    let (plan, bytes) = constructed(&setup);
    let header = bytes[..size_of::<GlobalHeader>()].to_vec();
    let directory = bytes[plan.ring_directory().offset as usize
        ..(plan.ring_directory().offset + plan.ring_directory().length) as usize]
        .to_vec();

    let header_offsets = [
        offset_of!(GlobalHeader, magic),
        offset_of!(GlobalHeader, header_size),
        offset_of!(GlobalHeader, abi_major),
        offset_of!(GlobalHeader, abi_minor),
        offset_of!(GlobalHeader, byte_order),
        offset_of!(GlobalHeader, header_flags),
        offset_of!(GlobalHeader, page_size),
        offset_of!(GlobalHeader, session_epoch),
        offset_of!(GlobalHeader, section_size),
        offset_of!(GlobalHeader, ring_count),
        offset_of!(GlobalHeader, ring_desc_size),
        offset_of!(GlobalHeader, ring_directory),
        offset_of!(GlobalHeader, k2u_slots),
        offset_of!(GlobalHeader, u2k_slots),
        offset_of!(GlobalHeader, notify_names),
        offset_of!(GlobalHeader, protocol_features),
        offset_of!(GlobalHeader, os_capabilities),
        offset_of!(GlobalHeader, max_inflight),
        offset_of!(GlobalHeader, flags),
        offset_of!(GlobalHeader, k2u_slot_classes),
        offset_of!(GlobalHeader, u2k_slot_classes),
        offset_of!(GlobalHeader, reserved),
    ];
    for offset in header_offsets {
        let mut corrupted = header.clone();
        corrupted[offset] ^= 1;
        assert!(
            validate_header_directory_v21(&corrupted, &directory, &setup, 1).is_err(),
            "header corruption at {offset} accepted"
        );
    }

    let directory_offsets = [
        offset_of!(RingDesc, magic),
        offset_of!(RingDesc, desc_size),
        offset_of!(RingDesc, desc_version),
        offset_of!(RingDesc, ring_index),
        offset_of!(RingDesc, flags),
        offset_of!(RingDesc, sq_capacity),
        offset_of!(RingDesc, cq_capacity),
        offset_of!(RingDesc, sq_entries),
        offset_of!(RingDesc, sq_producer),
        offset_of!(RingDesc, sq_consumer),
        offset_of!(RingDesc, cq_entries),
        offset_of!(RingDesc, cq_producer),
        offset_of!(RingDesc, cq_consumer),
        offset_of!(RingDesc, reserved),
        size_of::<RingDesc>(),
    ];
    for offset in directory_offsets {
        let mut corrupted = directory.clone();
        corrupted[offset] ^= 1;
        assert!(
            validate_header_directory_v21(&header, &corrupted, &setup, 1).is_err(),
            "directory corruption at {offset} accepted"
        );
    }
}

#[test]
fn full_parser_rejects_one_byte_in_each_image_class() {
    // Mutation caught: skipping header, directory, cursor, arena, padding, or
    // complete-image bound validation.
    let setup = setup(1, MIN_SQ_CAPACITY, MIN_CQ_CAPACITY);
    let (plan, bytes) = constructed(&setup);
    validate_finished_section_v21(&bytes, &setup, 1).expect("canonical image");
    assert_eq!(
        validate_finished_section_v21(&bytes[..bytes.len() - 1], &setup, 1).err(),
        Some(SectionLayoutError::BufferTooSmall)
    );

    let ring = plan.ring(0).unwrap();
    let k2u_classes = plan.k2u_slot_classes();
    let u2k_classes = plan.u2k_slot_classes();
    let cases = [
        0usize,
        plan.ring_directory().offset as usize + offset_of!(RingDesc, sq_entries),
        (plan.ring_directory().offset + size_of::<RingDesc>() as u64) as usize,
        ring.sq_producer.offset as usize,
        ring.sq_consumer.offset as usize,
        ring.sq_entries.offset as usize,
        ring.cq_producer.offset as usize,
        ring.cq_consumer.offset as usize,
        ring.cq_entries.offset as usize,
        k2u_classes[0].data_offset as usize,
        (plan.k2u_slots().offset + plan.k2u_slots().length - 1) as usize,
        u2k_classes[0].data_offset as usize,
        u2k_classes[1].data_offset as usize,
        (plan.u2k_slots().offset + plan.u2k_slots().length - 1) as usize,
        plan.notify_names().offset as usize,
        (plan.notify_names().offset + plan.notify_names().length - 1) as usize,
    ];
    for offset in cases {
        let mut corrupted = bytes.clone();
        corrupted[offset] ^= 1;
        assert!(
            validate_finished_section_v21(&corrupted, &setup, 1).is_err(),
            "corruption at {offset} accepted"
        );
    }

    let mut wrong_epoch = bytes;
    assert_eq!(
        validate_finished_section_v21(&wrong_epoch, &setup, 2).err(),
        Some(SectionLayoutError::InvalidIdentity)
    );
    wrong_epoch[offset_of!(GlobalHeader, session_epoch)] = 2;
    assert_eq!(
        validate_finished_section_v21(&wrong_epoch, &setup, 1).err(),
        Some(SectionLayoutError::InvalidIdentity)
    );
}

#[test]
fn frozen_wire_sizes_remain_the_geometry_basis() {
    // Mutation caught: silently using a different record/page size in placement.
    assert_eq!(size_of::<GlobalHeader>(), 4096);
    assert_eq!(size_of::<RingDesc>(), 128);
    assert_eq!(size_of::<ProducerPage>(), 4096);
    assert_eq!(size_of::<ConsumerPage>(), 4096);
    assert_eq!(FSRING_MAGIC, 0x4752_5346);
}
