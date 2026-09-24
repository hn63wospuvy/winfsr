use core::mem::{align_of, offset_of, size_of};

use fsring_abi::{
    codec::Pod, ConsumerPage, Cqe, CqeBody, FeatureSet, GlobalHeader, ProducerPage, RegionDesc,
    RingDesc, SlotClassDesc, SlotRef, SlotRefError, Sqe, SqeBody, FSRING_ABI_MAJOR, SLOT_INDEX_MAX,
    SLOT_LENGTH_MAX, SLOT_OFFSET_MAX,
};

fn assert_pod<T: Pod>() {}

macro_rules! assert_wire_layout {
    ($ty:ty, $size:expr, $align:expr; $($field:ident : $field_ty:ty => $offset:expr),+ $(,)?) => {{
        assert_eq!(size_of::<$ty>(), $size, "{} size", stringify!($ty));
        assert_eq!(align_of::<$ty>(), $align, "{} alignment", stringify!($ty));
        let mut next = 0usize;
        $(
            let _: fn(&$ty) -> $field_ty = |value| value.$field;
            let expected_offset: usize = $offset;
            assert_eq!(
                offset_of!($ty, $field),
                expected_offset,
                "{}.{} offset",
                stringify!($ty),
                stringify!($field)
            );
            assert_eq!(
                expected_offset,
                next,
                "implicit gap before {}.{}",
                stringify!($ty),
                stringify!($field)
            );
            next += size_of::<$field_ty>();
        )+
        assert_eq!(next, size_of::<$ty>(), "{} tail padding", stringify!($ty));
        assert_pod::<$ty>();
    }};
}

#[test]
fn physical_layout_sizes_and_alignments_are_byte_exact() {
    assert_eq!(FSRING_ABI_MAJOR, 2);
    assert_eq!(size_of::<FeatureSet>(), 16);
    assert_eq!(size_of::<RegionDesc>(), 16);
    assert_eq!(size_of::<SlotClassDesc>(), 16);

    assert_eq!(
        (size_of::<GlobalHeader>(), align_of::<GlobalHeader>()),
        (4096, 4096)
    );
    assert_eq!((size_of::<RingDesc>(), align_of::<RingDesc>()), (128, 64));
    assert_eq!(
        (size_of::<ProducerPage>(), align_of::<ProducerPage>()),
        (4096, 4096)
    );
    assert_eq!(
        (size_of::<ConsumerPage>(), align_of::<ConsumerPage>()),
        (4096, 4096)
    );
    assert_eq!((size_of::<Sqe>(), align_of::<Sqe>()), (128, 64));
    assert_eq!((size_of::<Cqe>(), align_of::<Cqe>()), (64, 64));
}

#[test]
fn physical_layout_field_offsets_are_byte_exact() {
    assert_eq!(offset_of!(GlobalHeader, session_epoch), 16);
    assert_eq!(offset_of!(GlobalHeader, protocol_features), 104);
    assert_eq!(offset_of!(GlobalHeader, k2u_slot_classes), 144);

    assert_eq!(offset_of!(SqeBody, req_id), 8);
    assert_eq!(offset_of!(SqeBody, payload), 32);
    assert_eq!(offset_of!(Sqe, body) + offset_of!(SqeBody, req_id), 16);
    assert_eq!(offset_of!(Sqe, body) + offset_of!(SqeBody, payload), 40);

    assert_eq!(offset_of!(CqeBody, req_id), 8);
    assert_eq!(offset_of!(CqeBody, out), 32);
    assert_eq!(offset_of!(Cqe, body) + offset_of!(CqeBody, req_id), 16);
    assert_eq!(offset_of!(Cqe, body) + offset_of!(CqeBody, out), 40);
}

#[test]
fn descriptor_widths_and_shared_cursor_fields_are_exact_wire_integers() {
    let _: fn(&GlobalHeader) -> u32 = |header| header.ring_desc_size;
    let _: fn(&RingDesc) -> u16 = |desc| desc.desc_size;
    let _: fn(&ProducerPage) -> u64 = |page| page.tail;
    let _: fn(&ProducerPage) -> u64 = |page| page.wake_sequence;
    let _: fn(&ConsumerPage) -> u64 = |page| page.head;
    let _: fn(&Sqe) -> u64 = |entry| entry.sequence;
    let _: fn(&Cqe) -> u64 = |entry| entry.sequence;
}

#[test]
fn every_physical_wire_field_has_an_exact_type_and_gapless_offset() {
    assert_wire_layout!(RegionDesc, 16, 8;
        offset: u64 => 0,
        length: u64 => 8,
    );
    assert_wire_layout!(SlotClassDesc, 16, 8;
        slot_size: u32 => 0,
        slot_count: u32 => 4,
        data_offset: u64 => 8,
    );
    assert_wire_layout!(GlobalHeader, 4096, 4096;
        magic: u32 => 0,
        header_size: u16 => 4,
        abi_major: u16 => 6,
        abi_minor: u16 => 8,
        byte_order: u8 => 10,
        header_flags: u8 => 11,
        page_size: u32 => 12,
        session_epoch: u64 => 16,
        section_size: u64 => 24,
        ring_count: u32 => 32,
        ring_desc_size: u32 => 36,
        ring_directory: RegionDesc => 40,
        k2u_slots: RegionDesc => 56,
        u2k_slots: RegionDesc => 72,
        notify_names: RegionDesc => 88,
        protocol_features: FeatureSet => 104,
        os_capabilities: FeatureSet => 120,
        max_inflight: u32 => 136,
        flags: u32 => 140,
        k2u_slot_classes: [SlotClassDesc; 4] => 144,
        u2k_slot_classes: [SlotClassDesc; 4] => 208,
        reserved: [u8; 3824] => 272,
    );
    assert_wire_layout!(RingDesc, 128, 64;
        magic: u32 => 0,
        desc_size: u16 => 4,
        desc_version: u16 => 6,
        ring_index: u32 => 8,
        flags: u32 => 12,
        sq_capacity: u32 => 16,
        cq_capacity: u32 => 20,
        sq_entries: RegionDesc => 24,
        sq_producer: RegionDesc => 40,
        sq_consumer: RegionDesc => 56,
        cq_entries: RegionDesc => 72,
        cq_producer: RegionDesc => 88,
        cq_consumer: RegionDesc => 104,
        reserved: [u8; 8] => 120,
    );
    assert_wire_layout!(ProducerPage, 4096, 4096;
        tail: u64 => 0,
        wake_sequence: u64 => 8,
        flags: u32 => 16,
        reserved0: [u8; 4] => 20,
        reserved: [u8; 4072] => 24,
    );
    assert_wire_layout!(ConsumerPage, 4096, 4096;
        head: u64 => 0,
        park_state: u32 => 8,
        flags: u32 => 12,
        heartbeat: u64 => 16,
        reserved: [u8; 4072] => 24,
    );
    assert_wire_layout!(SqeBody, 120, 8;
        opcode: u16 => 0,
        flags: u16 => 2,
        payload_len: u16 => 4,
        reserved: u16 => 6,
        req_id: u64 => 8,
        kernel_open_id: u64 => 16,
        ccb_sequence: u64 => 24,
        payload: [u8; 88] => 32,
    );
    assert_wire_layout!(Sqe, 128, 64;
        sequence: u64 => 0,
        body: SqeBody => 8,
    );
    assert_wire_layout!(CqeBody, 56, 8;
        kind: u16 => 0,
        opcode: u16 => 2,
        flags: u16 => 4,
        out_len: u16 => 6,
        req_id: u64 => 8,
        status: i32 => 16,
        reserved: u32 => 20,
        information: u64 => 24,
        out: [u8; 24] => 32,
    );
    assert_wire_layout!(Cqe, 64, 64;
        sequence: u64 => 0,
        body: CqeBody => 8,
    );

    assert_eq!(size_of::<SlotRef>(), 8);
    assert_eq!(align_of::<SlotRef>(), 8);
    assert_pod::<SlotRef>();
}

#[test]
fn slot_ref_round_trips_every_field() {
    let slot = SlotRef::try_new(3, 0x0f_edcb, 0x1e_dcba, 0x1d_cba9).unwrap();

    assert_eq!(slot.class(), 3);
    assert_eq!(slot.index(), 0x0f_edcb);
    assert_eq!(slot.offset(), 0x1e_dcba);
    assert_eq!(slot.len(), 0x1d_cba9);
    assert_eq!(
        slot.raw(),
        3 | (0x0f_edcb_u64 << 2) | (0x1e_dcba_u64 << 22) | (0x1d_cba9_u64 << 43)
    );
}

#[test]
fn slot_ref_rejects_each_out_of_range_field() {
    assert_eq!(
        SlotRef::try_new(4, 0, 0, 0),
        Err(SlotRefError::ClassOutOfRange)
    );
    assert_eq!(
        SlotRef::try_new(0, 1 << 20, 0, 0),
        Err(SlotRefError::IndexOutOfRange)
    );
    assert_eq!(
        SlotRef::try_new(0, 0, 1 << 21, 0),
        Err(SlotRefError::OffsetOutOfRange)
    );
    assert_eq!(
        SlotRef::try_new(0, 0, 0, 1 << 21),
        Err(SlotRefError::LengthOutOfRange)
    );
}

#[test]
fn slot_ref_accepts_zero_and_every_maximum_field() {
    let zero = SlotRef::try_new(0, 0, 0, 0).unwrap();
    assert_eq!(zero.raw(), 0);
    assert!(zero.is_empty());

    let maximum = SlotRef::try_new(3, SLOT_INDEX_MAX, SLOT_OFFSET_MAX, SLOT_LENGTH_MAX).unwrap();
    assert_eq!(maximum.raw(), u64::MAX);
    assert_eq!(maximum.class(), 3);
    assert_eq!(maximum.index(), SLOT_INDEX_MAX);
    assert_eq!(maximum.offset(), SLOT_OFFSET_MAX);
    assert_eq!(maximum.len(), SLOT_LENGTH_MAX);
    assert!(!maximum.is_empty());
}
