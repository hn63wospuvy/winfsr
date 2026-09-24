use core::mem::{align_of, offset_of, size_of};

use fsring_abi::{
    codec::{try_decode, try_encode, Pod},
    cq_kind,
    ids::{AckToken, FileId, LinkId, MountId, OpId, ReqId, TransactionId},
    msgs::{
        buffer_access, buffer_kind, rw_flags, AbortOpenV1, AckResultV1, AttachV1, BufferRef,
        CommitOpenResultV1, CommitOpenV1, ControlHeader, DonateBackingV1, DonateSecurityContextV1,
        MutationResultV1, MutationV1, NotifyEnvelopeV1, OControl, ORw, PBarrier, PCancel, PControl,
        PNotifyAck, PRw, PrepareOpenResultV1, PrepareOpenV1, QueryOpResultV1, QueryOpV1,
        ReplayOpenResultV1, ReplayOpenV1, SizeState,
    },
    notify, op, sqe_flags, CqeBody, FeatureSet, CQE_OUT_LEN, SQE_PAYLOAD_LEN,
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
fn message_sizes_are_byte_exact() {
    assert_eq!(size_of::<ControlHeader>(), 8);
    assert_eq!(size_of::<BufferRef>(), 24);
    assert_eq!(size_of::<SizeState>(), 32);
    assert_eq!(size_of::<PControl>(), 24);
    assert_eq!(size_of::<OControl>(), 24);
    assert_eq!(size_of::<PBarrier>(), 24);
    assert_eq!(size_of::<PCancel>(), 16);
    assert_eq!(size_of::<PNotifyAck>(), 24);
    assert_eq!(size_of::<PRw>(), 80);
    assert_eq!(size_of::<ORw>(), 24);
    assert_eq!(size_of::<PrepareOpenV1>(), 96);
    assert_eq!(size_of::<PrepareOpenResultV1>(), 136);
    assert_eq!(size_of::<CommitOpenV1>(), 72);
    assert_eq!(size_of::<CommitOpenResultV1>(), 104);
    assert_eq!(size_of::<AbortOpenV1>(), 24);
    assert_eq!(size_of::<ReplayOpenV1>(), 80);
    assert_eq!(size_of::<ReplayOpenResultV1>(), 16);
    assert_eq!(size_of::<MutationV1>(), 72);
    assert_eq!(size_of::<MutationResultV1>(), 80);
    assert_eq!(size_of::<AttachV1>(), 56);
    assert_eq!(size_of::<QueryOpV1>(), 56);
    assert_eq!(size_of::<QueryOpResultV1>(), 56);
    assert_eq!(size_of::<AckResultV1>(), 24);
    assert_eq!(size_of::<NotifyEnvelopeV1>(), 72);
    assert_eq!(size_of::<DonateBackingV1>(), 48);
    assert_eq!(size_of::<DonateSecurityContextV1>(), 32);
}

#[test]
fn common_and_fixed_io_fields_have_exact_types_and_gapless_offsets() {
    assert_wire_layout!(ControlHeader, 8, 4;
        struct_size: u32 => 0,
        struct_version: u16 => 4,
        required_flags: u16 => 6,
    );
    assert_wire_layout!(BufferRef, 24, 8;
        token: u64 => 0,
        offset: u32 => 8,
        length: u32 => 12,
        kind: u16 => 16,
        access: u16 => 18,
        reserved: u32 => 20,
    );
    assert_wire_layout!(SizeState, 32, 8;
        allocation_size: u64 => 0,
        file_size: u64 => 8,
        valid_data_length: u64 => 16,
        size_epoch: u64 => 24,
    );
    assert_wire_layout!(PControl, 24, 8; body: BufferRef => 0);
    assert_wire_layout!(OControl, 24, 8; body: BufferRef => 0);
    assert_wire_layout!(PBarrier, 24, 8;
        op_id: OpId => 0,
        flags: u32 => 16,
        reserved: u32 => 20,
    );
    assert_wire_layout!(PCancel, 16, 8;
        target_req_id: u64 => 0,
        target_session_epoch: u64 => 8,
    );
    assert_wire_layout!(PNotifyAck, 24, 8;
        token: AckToken => 0,
        epoch: u64 => 16,
    );
    assert_wire_layout!(PRw, 80, 8;
        op_id: OpId => 0,
        offset: u64 => 16,
        size_epoch: u64 => 24,
        initialized_offset: u64 => 32,
        data: BufferRef => 40,
        length: u32 => 64,
        initialized_length: u32 => 68,
        rw_flags: u32 => 72,
        reserved: u32 => 76,
    );
    assert_wire_layout!(ORw, 24, 8;
        file_size: u64 => 0,
        valid_data_length: u64 => 8,
        size_epoch: u64 => 16,
    );
}

#[test]
fn every_mapped_fixed_payload_fits_its_ring_area() {
    assert!(size_of::<PControl>() <= SQE_PAYLOAD_LEN);
    assert!(size_of::<PBarrier>() <= SQE_PAYLOAD_LEN);
    assert!(size_of::<PRw>() <= SQE_PAYLOAD_LEN);
    assert!(size_of::<PCancel>() <= SQE_PAYLOAD_LEN);
    assert!(size_of::<PNotifyAck>() <= SQE_PAYLOAD_LEN);
    assert!(size_of::<OControl>() <= CQE_OUT_LEN);
    assert!(size_of::<ORw>() <= CQE_OUT_LEN);
}

#[test]
fn open_control_fields_have_exact_types_and_gapless_offsets() {
    assert_wire_layout!(PrepareOpenV1, 96, 8;
        header: ControlHeader => 0,
        op_id: OpId => 8,
        parent_id: FileId => 24,
        name: BufferRef => 40,
        security_context_id: u64 => 64,
        desired_access: u32 => 72,
        share_access: u32 => 76,
        disposition: u32 => 80,
        create_options: u32 => 84,
        file_attributes: u32 => 88,
        open_flags: u32 => 92,
    );
    assert_wire_layout!(PrepareOpenResultV1, 136, 8;
        header: ControlHeader => 0,
        transaction_id: TransactionId => 8,
        file_id: FileId => 24,
        link_id: LinkId => 40,
        security_descriptor: BufferRef => 56,
        sizes: SizeState => 80,
        namespace_generation: u64 => 112,
        security_generation: u64 => 120,
        object_flags: u32 => 128,
        reserved: u32 => 132,
    );
    assert_wire_layout!(CommitOpenV1, 72, 8;
        header: ControlHeader => 0,
        op_id: OpId => 8,
        transaction_id: TransactionId => 24,
        expected_namespace_generation: u64 => 40,
        expected_security_generation: u64 => 48,
        kernel_open_id: u64 => 56,
        commit_flags: u32 => 64,
        reserved: u32 => 68,
    );
    assert_wire_layout!(CommitOpenResultV1, 104, 8;
        header: ControlHeader => 0,
        provider_open_cookie: u64 => 8,
        file_id: FileId => 16,
        link_id: LinkId => 32,
        sizes: SizeState => 48,
        namespace_generation: u64 => 80,
        security_generation: u64 => 88,
        create_result: u32 => 96,
        result_flags: u32 => 100,
    );
    assert_wire_layout!(AbortOpenV1, 24, 8;
        header: ControlHeader => 0,
        transaction_id: TransactionId => 8,
    );
}

#[test]
fn mutation_and_recovery_fields_have_exact_types_and_gapless_offsets() {
    assert_wire_layout!(MutationV1, 72, 8;
        header: ControlHeader => 0,
        op_id: OpId => 8,
        mutation_kind: u16 => 24,
        mutation_flags: u16 => 26,
        reserved: u32 => 28,
        expected_namespace_generation: u64 => 32,
        expected_size_epoch: u64 => 40,
        body: BufferRef => 48,
    );
    assert_wire_layout!(MutationResultV1, 80, 8;
        header: ControlHeader => 0,
        op_id: OpId => 8,
        volume_commit_sequence: u64 => 24,
        sizes: SizeState => 32,
        namespace_generation: u64 => 64,
        result_flags: u32 => 72,
        reserved: u32 => 76,
    );
    assert_wire_layout!(ReplayOpenV1, 80, 8;
        header: ControlHeader => 0,
        kernel_open_id: u64 => 8,
        file_id: FileId => 16,
        link_id: LinkId => 32,
        desired_access: u32 => 48,
        share_access: u32 => 52,
        create_options: u32 => 56,
        disposition: u32 => 60,
        ccb_sequence: u64 => 64,
        state_flags: u64 => 72,
    );
    assert_wire_layout!(ReplayOpenResultV1, 16, 8;
        header: ControlHeader => 0,
        provider_open_cookie: u64 => 8,
    );
    assert_wire_layout!(AttachV1, 56, 8;
        header: ControlHeader => 0,
        prior_session_epoch: u64 => 8,
        requested_features: FeatureSet => 16,
        mount_id: MountId => 32,
        journal_version: u32 => 48,
        flags: u32 => 52,
    );
    assert_wire_layout!(QueryOpV1, 56, 8;
        header: ControlHeader => 0,
        op_id: OpId => 8,
        operation_digest: [u8; 32] => 24,
    );
    assert_wire_layout!(QueryOpResultV1, 56, 8;
        header: ControlHeader => 0,
        state: u16 => 8,
        flags: u16 => 10,
        reserved: u32 => 12,
        op_id: OpId => 16,
        result: BufferRef => 32,
    );
    assert_wire_layout!(AckResultV1, 24, 8;
        header: ControlHeader => 0,
        op_id: OpId => 8,
    );
}

#[test]
fn notification_and_donation_fields_have_exact_types_and_gapless_offsets() {
    assert_wire_layout!(NotifyEnvelopeV1, 72, 8;
        header: ControlHeader => 0,
        notify_code: u16 => 8,
        notify_flags: u16 => 10,
        reserved: u32 => 12,
        token: AckToken => 16,
        file_id: FileId => 32,
        body: BufferRef => 48,
    );
    assert_wire_layout!(DonateBackingV1, 48, 8;
        header: ControlHeader => 0,
        file_id: FileId => 8,
        pt_epoch: u64 => 24,
        daemon_handle: u64 => 32,
        sector_size: u32 => 40,
        flags: u32 => 44,
    );
    assert_wire_layout!(DonateSecurityContextV1, 32, 8;
        header: ControlHeader => 0,
        security_context_id: u64 => 8,
        daemon_handle: u64 => 16,
        flags: u32 => 24,
        reserved: u32 => 28,
    );
}

#[test]
fn control_header_has_golden_little_endian_bytes() {
    let header = ControlHeader {
        struct_size: 0x1234_5678,
        struct_version: 0x9abc,
        required_flags: 0xdef0,
    };
    let mut bytes = [0xa5; 8];

    assert_eq!(try_encode(&header, &mut bytes), Ok(8));
    assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde]);
}

#[test]
fn prw_has_golden_bytes_including_all_of_op_id() {
    let request = PRw {
        op_id: OpId {
            lo: 0x0807_0605_0403_0201,
            hi: 0x100f_0e0d_0c0b_0a09,
        },
        offset: 0x1817_1615_1413_1211,
        size_epoch: 0x201f_1e1d_1c1b_1a19,
        initialized_offset: 0x2827_2625_2423_2221,
        data: BufferRef {
            token: 0x302f_2e2d_2c2b_2a29,
            offset: 0x3433_3231,
            length: 0x3837_3635,
            kind: 0x3a39,
            access: 0x3c3b,
            reserved: 0,
        },
        length: 0x4443_4241,
        initialized_length: 0x4847_4645,
        rw_flags: 0x4c4b_4a49,
        reserved: 0,
    };
    let mut bytes = [0xa5; 80];

    assert_eq!(try_encode(&request, &mut bytes), Ok(80));
    assert_eq!(
        bytes,
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
            0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x00, 0x00, 0x00, 0x00,
        ]
    );
}

#[test]
fn completion_kind_is_independent_of_all_req_id_generation_bits() {
    let generation = (1u64 << 39) | 0x1234;
    let req_id = ReqId::try_new(generation, 0x00ab_cdef).unwrap();
    assert_ne!(req_id.raw() & (1u64 << 63), 0);

    let completion = CqeBody {
        kind: cq_kind::COMPLETION,
        opcode: op::WRITE,
        flags: 0,
        out_len: CQE_OUT_LEN as u16,
        req_id: req_id.raw(),
        status: 0,
        reserved: 0,
        information: 0x0102_0304_0506_0708,
        out: [0; CQE_OUT_LEN],
    };
    let mut bytes = [0xa5; size_of::<CqeBody>()];

    assert_eq!(
        try_encode(&completion, &mut bytes),
        Ok(size_of::<CqeBody>())
    );
    assert_eq!(&bytes[0..2], &cq_kind::COMPLETION.to_le_bytes());
    assert_eq!(&bytes[8..16], &req_id.raw().to_le_bytes());

    let decoded = try_decode::<CqeBody>(&bytes).unwrap();
    assert_eq!(decoded.kind, cq_kind::COMPLETION);
    assert_eq!(ReqId::from_raw(decoded.req_id).generation(), generation);
}

#[test]
fn registry_values_and_fixed_payload_flags_are_stable() {
    fn assert_u16(_: u16) {}
    fn assert_u32(_: u32) {}

    assert_eq!(
        [
            op::PREPARE_OPEN,
            op::COMMIT_OPEN,
            op::ABORT_OPEN,
            op::CLEANUP,
            op::CLOSE,
            op::READ,
            op::WRITE,
            op::FLUSH,
            op::QUERY_INFO,
            op::MUTATE,
            op::QUERY_DIR,
            op::QUERY_VOLUME,
            op::QUERY_SECURITY,
            op::FSCTL,
            op::CANCEL,
            op::ATTACH,
            op::REPLAY_OPEN,
            op::QUERY_OP,
            op::ACK_RESULT,
            op::PT_ROUTE_ACK,
            op::PT_EXTERNAL_SAFE_ACK,
        ],
        [
            0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0010, 0x0011, 0x0012, 0x0020, 0x0021, 0x0022,
            0x0023, 0x0024, 0x0025, 0x0030, 0x0040, 0x0041, 0x0042, 0x0043, 0x0050, 0x0051,
        ]
    );
    assert_eq!(
        [cq_kind::COMPLETION, cq_kind::NOTIFY, cq_kind::PROTOCOL],
        [0, 1, 2]
    );
    assert_eq!(
        [
            notify::INVALIDATE_FILE,
            notify::INVALIDATE_ENTRY,
            notify::PT_GRANT,
            notify::PT_REVOKE_ROUTE,
            notify::PT_EXTERNAL_MUTATION_SAFE,
            notify::RESIZE,
            notify::DIR_CHANGE,
        ],
        [1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(
        [buffer_kind::NONE, buffer_kind::SLOT, buffer_kind::MAPPING],
        [0, 1, 2]
    );
    assert_eq!(
        [buffer_access::K2U_READ_ONLY, buffer_access::U2K_WRITE],
        [1, 2]
    );
    assert_eq!(
        [
            rw_flags::PAGING,
            rw_flags::NOCACHE,
            rw_flags::WRITE_THROUGH,
            rw_flags::MAPPED,
            rw_flags::SYNC_PAGING,
            rw_flags::EXTENDING,
            rw_flags::ZERO_RANGE_VALID,
        ],
        [1, 2, 4, 8, 16, 32, 64]
    );
    assert_ne!(sqe_flags::NO_COMPLETION, 0);

    assert_u16(op::PREPARE_OPEN);
    assert_u16(cq_kind::COMPLETION);
    assert_u16(notify::INVALIDATE_FILE);
    assert_u16(buffer_kind::NONE);
    assert_u16(buffer_access::K2U_READ_ONLY);
    assert_u32(rw_flags::PAGING);

    let _: fn(&PBarrier) -> u32 = |payload| payload.flags;
    let _: fn(&PrepareOpenV1) -> u32 = |payload| payload.open_flags;
    let _: fn(&CommitOpenV1) -> u32 = |payload| payload.commit_flags;
    assert_u16(sqe_flags::NO_COMPLETION);
}
