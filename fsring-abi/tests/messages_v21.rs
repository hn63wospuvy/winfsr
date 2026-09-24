use core::mem::{align_of, offset_of, size_of};

use fsring_abi::{
    codec::{try_encode, Pod},
    cq_kind,
    msgs::{
        basic_info_set_mask, buffer_access, buffer_kind, create_result, file_attributes,
        journal_version, link_flags, mutation_kind, protocol_opcode, protocol_reason,
        query_op_required_flags, query_op_state, rename_flags, security_information,
        validate_protocol_abort_v1, AckResultV1, AckResultV2, BlobSlice, BufferRef,
        CommitOpenResultV1, CommitOpenResultV2, CommitOpenV1, CommitOpenV2, ControlHeader,
        DeleteReparseV1, LinkResultV2, LinkV1, MutationResultV2, MutationV2, OControl,
        PrepareOpenResultV1, PrepareOpenV1, PrepareOpenV2, ProtocolAbortV1, QueryOpV1, QueryOpV2,
        RenameResultV2, RenameV1, ReplayOpenResultV1, ReplayOpenV1, ReplayOpenV2, SetBasicInfoV1,
        SetReparseV1, SetSecurityV1, SetSizeV1, SetSparseV1, SizeState, UnlinkResultV1, UnlinkV1,
        WriteResultV2, WriteV2, CONTROL_VERSION_V1, CONTROL_VERSION_V2,
    },
    op,
    validate::{
        classify_rw_submission_v21, mutation_kind_of_body_v21, mutation_kind_result_length_v21,
        validate_ack_result_v2, validate_commit_open_success_v2, validate_commit_open_v2,
        validate_create_phase_identity_v21, validate_mutation_body_v21,
        validate_mutation_success_v2, validate_mutation_v2, validate_notification_version_v21,
        validate_prepare_open_success_v21, validate_prepare_open_v2, validate_query_op_v2,
        validate_read_success_v21, validate_read_v21, validate_replay_open_success_v21,
        validate_replay_open_v2, validate_request_version_v21, validate_request_wire_form_v21,
        validate_result_wire_form_v21, validate_size_state_v21, validate_stored_component_utf16,
        validate_write_success_v2, validate_write_v2, CheckedRange64, ControlError,
        CreatePhaseCandidateV21, CreatePhaseExpectationV21, CreatePhaseV21, GrantBindingV21,
        MessageValidationError, MutationBodyRefV21, MutationKindResultRefV21, MutationV2Context,
        PrepareOpenV2Context, QueryOpV2Context, RwRequestWireFormV21, RwResultWireFormV21,
        RwSubmissionV21, WriteV2Context,
    },
    CqeBody, FileId, LinkId, OpId, RegionDesc, ReqId, SlotClassDesc, SlotToken, TransactionId,
    MAX_CANONICAL_DIR_ENTRY_BYTES, MAX_COMPONENT_UTF16_CODE_UNITS, MAX_CONTROL_BLOB, MAX_FILE_SIZE,
    MAX_INFLIGHT, MAX_REPARSE_DATA_BYTES, MAX_SECURITY_DESCRIPTOR_BYTES,
    MIN_SECURITY_DESCRIPTOR_BYTES,
};

use fsring_abi::slots::{
    resolve_slot, validate_slot_arena, BufferRefError, GrantCapability, GrantMetadata, GrantOwner,
    GrantState, SlotDirection, ValidatedBuffer,
};

type MutationRow<T, E> = (fn(&mut T), E);
type ExpectationRow<T> = (u16, fn(&mut T));

fn assert_pod<T: Pod>() {}

macro_rules! assert_wire_layout {
    ($ty:ty, $size:expr, $align:expr; $($field:ident : $field_ty:ty => $offset:expr),+ $(,)?) => {{
        assert_eq!(size_of::<$ty>(), $size, "{} size", stringify!($ty));
        assert_eq!(align_of::<$ty>(), $align, "{} alignment", stringify!($ty));
        let mut next = 0usize;
        $(
            let _: fn(&$ty) -> $field_ty = |value| value.$field;
            assert_eq!(offset_of!($ty, $field), $offset, "{}.{}", stringify!($ty), stringify!($field));
            assert_eq!($offset, next, "gap before {}.{}", stringify!($ty), stringify!($field));
            next += size_of::<$field_ty>();
        )+
        assert_eq!(next, size_of::<$ty>(), "{} tail padding", stringify!($ty));
        assert_pod::<$ty>();
    }};
}

fn sentinel_header() -> ControlHeader {
    ControlHeader {
        struct_size: 0x0403_0201,
        struct_version: 0x0605,
        required_flags: 0x0807,
    }
}

fn sentinel_buffer(seed: u64) -> BufferRef {
    BufferRef {
        token: seed,
        offset: seed as u32 ^ 0xa5a5_a5a5,
        length: seed as u32 ^ 0x5a5a_5a5a,
        kind: (seed as u16) ^ 0x1357,
        access: (seed as u16) ^ 0x2468,
        reserved: seed as u32 ^ 0x55aa_aa55,
    }
}

fn sentinel_op(seed: u64) -> OpId {
    OpId {
        lo: seed,
        hi: seed ^ u64::MAX,
    }
}

fn sentinel_file(seed: u64) -> FileId {
    FileId {
        lo: seed,
        hi: seed ^ u64::MAX,
    }
}

fn sentinel_link(seed: u64) -> LinkId {
    LinkId {
        lo: seed,
        hi: seed ^ u64::MAX,
    }
}

fn sentinel_transaction(seed: u64) -> TransactionId {
    TransactionId {
        lo: seed,
        hi: seed ^ u64::MAX,
    }
}

fn encode_exact<T: Pod, const N: usize>(value: &T) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(try_encode(value, &mut out).unwrap(), N);
    out
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_header(out: &mut [u8], offset: usize, value: ControlHeader) {
    put_u32(out, offset, value.struct_size);
    put_u16(out, offset + 4, value.struct_version);
    put_u16(out, offset + 6, value.required_flags);
}

fn put_pair(out: &mut [u8], offset: usize, lo: u64, hi: u64) {
    put_u64(out, offset, lo);
    put_u64(out, offset + 8, hi);
}

fn put_buffer(out: &mut [u8], offset: usize, value: BufferRef) {
    put_u64(out, offset, value.token);
    put_u32(out, offset + 8, value.offset);
    put_u32(out, offset + 12, value.length);
    put_u16(out, offset + 16, value.kind);
    put_u16(out, offset + 18, value.access);
    put_u32(out, offset + 20, value.reserved);
}

fn put_sizes(out: &mut [u8], offset: usize, value: SizeState) {
    put_u64(out, offset, value.allocation_size);
    put_u64(out, offset + 8, value.file_size);
    put_u64(out, offset + 16, value.valid_data_length);
    put_u64(out, offset + 24, value.size_epoch);
}

fn sentinel_prepare_v2() -> PrepareOpenV2 {
    PrepareOpenV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0x1112_1314_1516_1718),
        parent_id: sentinel_file(0x2122_2324_2526_2728),
        name: sentinel_buffer(0x3132_3334_3536_3738),
        security_context_id: 0x4142_4344_4546_4748,
        desired_access: 0x5152_5354,
        share_access: 0x6162_6364,
        disposition: 0x7172_7374,
        create_options: 0x8182_8384,
        file_attributes: 0x9192_9394,
        open_flags: 0xa1a2_a3a4,
        requested_security_descriptor: sentinel_buffer(0xb1b2_b3b4_b5b6_b7b8),
        extended_attributes: sentinel_buffer(0xc1c2_c3c4_c5c6_c7c8),
        reply: sentinel_buffer(0xd1d2_d3d4_d5d6_d7d8),
        result_security_descriptor: sentinel_buffer(0xe1e2_e3e4_e5e6_e7e8),
    }
}

fn sentinel_prepare_v1() -> PrepareOpenV1 {
    let value = sentinel_prepare_v2();
    PrepareOpenV1 {
        header: value.header,
        op_id: value.op_id,
        parent_id: value.parent_id,
        name: value.name,
        security_context_id: value.security_context_id,
        desired_access: value.desired_access,
        share_access: value.share_access,
        disposition: value.disposition,
        create_options: value.create_options,
        file_attributes: value.file_attributes,
        open_flags: value.open_flags,
    }
}

fn sentinel_commit_v2() -> CommitOpenV2 {
    CommitOpenV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0x1111_2222_3333_4444),
        transaction_id: sentinel_transaction(0x5555_6666_7777_8888),
        expected_namespace_generation: 0x9999_aaaa_bbbb_cccc,
        expected_security_generation: 0xdddd_eeee_ffff_0001,
        kernel_open_id: 0x1234_5678_9abc_def0,
        commit_flags: 0x1357_9bdf,
        reserved: 0x2468_ace0,
        granted_access: 0x55aa_33cc,
        reserved2: 0xaa55_cc33,
        reply: sentinel_buffer(0x1020_3040_5060_7080),
    }
}

fn sentinel_commit_v1() -> CommitOpenV1 {
    let value = sentinel_commit_v2();
    CommitOpenV1 {
        header: value.header,
        op_id: value.op_id,
        transaction_id: value.transaction_id,
        expected_namespace_generation: value.expected_namespace_generation,
        expected_security_generation: value.expected_security_generation,
        kernel_open_id: value.kernel_open_id,
        commit_flags: value.commit_flags,
        reserved: value.reserved,
    }
}

fn sentinel_commit_result_v2() -> CommitOpenResultV2 {
    CommitOpenResultV2 {
        header: sentinel_header(),
        provider_open_cookie: 0x1111_1111_2222_2222,
        file_id: sentinel_file(0x3333_3333_4444_4444),
        link_id: sentinel_link(0x5555_5555_6666_6666),
        sizes: SizeState {
            allocation_size: 0x7777_7777_8888_8888,
            file_size: 0x9999_9999_aaaa_aaaa,
            valid_data_length: 0xbbbb_bbbb_cccc_cccc,
            size_epoch: 0xdddd_dddd_eeee_eeee,
        },
        namespace_generation: 0x0102_0304_0506_0708,
        security_generation: 0x1112_1314_1516_1718,
        create_result: 0x2122_2324,
        result_flags: 0x3132_3334,
        volume_commit_sequence: 0x4142_4344_4546_4748,
    }
}

fn sentinel_commit_result_v1() -> CommitOpenResultV1 {
    let value = sentinel_commit_result_v2();
    CommitOpenResultV1 {
        header: value.header,
        provider_open_cookie: value.provider_open_cookie,
        file_id: value.file_id,
        link_id: value.link_id,
        sizes: value.sizes,
        namespace_generation: value.namespace_generation,
        security_generation: value.security_generation,
        create_result: value.create_result,
        result_flags: value.result_flags,
    }
}

fn sentinel_write_v2() -> WriteV2 {
    WriteV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0x1112_1314_1516_1718),
        offset: 0x2122_2324_2526_2728,
        expected_size_epoch: 0x3132_3334_3536_3738,
        initialized_offset: 0x4142_4344_4546_4748,
        data: sentinel_buffer(0x5152_5354_5556_5758),
        length: 0x6162_6364,
        initialized_length: 0x7172_7374,
        rw_flags: 0x8182_8384,
        reserved: 0x9192_9394,
        reply: sentinel_buffer(0xa1a2_a3a4_a5a6_a7a8),
    }
}

fn sentinel_write_result_v2() -> WriteResultV2 {
    WriteResultV2 {
        header: sentinel_header(),
        sizes: SizeState {
            allocation_size: 0x1112_1314_1516_1718,
            file_size: 0x2122_2324_2526_2728,
            valid_data_length: 0x3132_3334_3536_3738,
            size_epoch: 0x4142_4344_4546_4748,
        },
        volume_commit_sequence: 0x5152_5354_5556_5758,
        flags: 0x6162_6364,
        reserved: 0x7172_7374,
    }
}

fn sentinel_replay_v2() -> ReplayOpenV2 {
    ReplayOpenV2 {
        header: sentinel_header(),
        kernel_open_id: 0x1112_1314_1516_1718,
        file_id: sentinel_file(0x2122_2324_2526_2728),
        link_id: sentinel_link(0x3132_3334_3536_3738),
        desired_access: 0x4142_4344,
        share_access: 0x5152_5354,
        create_options: 0x6162_6364,
        disposition: 0x7172_7374,
        ccb_sequence: 0x8182_8384_8586_8788,
        state_flags: 0x9192_9394_9596_9798,
        reply: sentinel_buffer(0xa1a2_a3a4_a5a6_a7a8),
    }
}

fn sentinel_replay_v1() -> ReplayOpenV1 {
    let value = sentinel_replay_v2();
    ReplayOpenV1 {
        header: value.header,
        kernel_open_id: value.kernel_open_id,
        file_id: value.file_id,
        link_id: value.link_id,
        desired_access: value.desired_access,
        share_access: value.share_access,
        create_options: value.create_options,
        disposition: value.disposition,
        ccb_sequence: value.ccb_sequence,
        state_flags: value.state_flags,
    }
}

fn sentinel_query_v2() -> QueryOpV2 {
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = 0x40 + index as u8;
    }
    QueryOpV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0x1112_1314_1516_1718),
        operation_digest: digest,
        reply: sentinel_buffer(0x2122_2324_2526_2728),
        committed_result: sentinel_buffer(0x3132_3334_3536_3738),
    }
}

fn sentinel_query_v1() -> QueryOpV1 {
    let value = sentinel_query_v2();
    QueryOpV1 {
        header: value.header,
        op_id: value.op_id,
        operation_digest: value.operation_digest,
    }
}

fn sentinel_ack_v2() -> AckResultV2 {
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = 0x80 + index as u8;
    }
    AckResultV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0x1112_1314_1516_1718),
        operation_digest: digest,
    }
}

fn sentinel_ack_v1() -> AckResultV1 {
    let value = sentinel_ack_v2();
    AckResultV1 {
        header: value.header,
        op_id: value.op_id,
    }
}

const ZERO_CLASS: SlotClassDesc = SlotClassDesc {
    slot_size: 0,
    slot_count: 0,
    data_offset: 0,
};

fn request_owner() -> GrantOwner {
    GrantOwner::Request(ReqId::try_new(7, 3).unwrap())
}

fn mapping_grant(token: u64, access: u16, length: u32) -> GrantMetadata {
    GrantMetadata {
        capability: GrantCapability::Mapping {
            token,
            length: u64::from(length),
        },
        session_epoch: 9,
        owner: request_owner(),
        access,
        maximum: CheckedRange64 {
            start: 0,
            end: u64::from(length),
        },
        state: GrantState::Live,
        issued: BufferRef {
            token,
            offset: 0,
            length,
            kind: buffer_kind::MAPPING,
            access,
            reserved: 0,
        },
    }
}

fn slot_grant(direction: SlotDirection, length: u32, generation: u64) -> GrantMetadata {
    let access = match direction {
        SlotDirection::K2u => buffer_access::K2U_READ_ONLY,
        SlotDirection::U2k => buffer_access::U2K_WRITE,
    };
    let arena = validate_slot_arena(
        direction,
        65_536,
        RegionDesc {
            offset: 0,
            length: 65_536,
        },
        [
            SlotClassDesc {
                slot_size: 65_536,
                slot_count: 1,
                data_offset: 0,
            },
            ZERO_CLASS,
            ZERO_CLASS,
            ZERO_CLASS,
        ],
    )
    .unwrap();
    let slot = resolve_slot(&arena, SlotToken::try_new(0, 0, generation).unwrap()).unwrap();
    GrantMetadata {
        capability: GrantCapability::Slot(slot),
        session_epoch: 9,
        owner: request_owner(),
        access,
        maximum: CheckedRange64 {
            start: 0,
            end: 65_536,
        },
        state: GrantState::Live,
        issued: BufferRef {
            token: slot.token().raw(),
            offset: 0,
            length,
            kind: buffer_kind::SLOT,
            access,
            reserved: 0,
        },
    }
}

fn binding(grant: &GrantMetadata) -> GrantBindingV21<'_> {
    GrantBindingV21 {
        grant,
        expected_session_epoch: grant.session_epoch,
        expected_owner: grant.owner,
    }
}

fn validated_length(value: ValidatedBuffer) -> u64 {
    value
        .mapping_range()
        .or_else(|| value.section_range())
        .unwrap()
        .checked_len()
        .unwrap()
}

fn control_header(size: u32) -> ControlHeader {
    ControlHeader {
        struct_size: size,
        struct_version: CONTROL_VERSION_V2,
        required_flags: 0,
    }
}

fn canonical_prepare(
    name: BufferRef,
    requested_security_descriptor: BufferRef,
    extended_attributes: BufferRef,
    reply: BufferRef,
    result_security_descriptor: BufferRef,
) -> PrepareOpenV2 {
    PrepareOpenV2 {
        header: control_header(192),
        op_id: OpId { lo: 1, hi: 2 },
        parent_id: FileId { lo: 3, hi: 4 },
        name,
        security_context_id: 0,
        desired_access: 0x0012_0089,
        share_access: 7,
        disposition: 1,
        create_options: 0,
        file_attributes: 0x80,
        open_flags: 0,
        requested_security_descriptor,
        extended_attributes,
        reply,
        result_security_descriptor,
    }
}

fn canonical_commit(reply: BufferRef) -> CommitOpenV2 {
    CommitOpenV2 {
        header: control_header(104),
        op_id: OpId { lo: 1, hi: 2 },
        transaction_id: TransactionId { lo: 3, hi: 4 },
        expected_namespace_generation: 5,
        expected_security_generation: 6,
        kernel_open_id: 7,
        commit_flags: 0,
        reserved: 0,
        granted_access: 0x0012_0089,
        reserved2: 0,
        reply,
    }
}

fn canonical_read(data: BufferRef) -> fsring_abi::msgs::PRw {
    fsring_abi::msgs::PRw {
        op_id: OpId::ZERO,
        offset: 100,
        size_epoch: 7,
        initialized_offset: 100,
        data,
        length: 4,
        initialized_length: 2,
        rw_flags: 0,
        reserved: 0,
    }
}

fn canonical_write(data: BufferRef, reply: BufferRef) -> WriteV2 {
    WriteV2 {
        header: control_header(112),
        op_id: OpId { lo: 1, hi: 2 },
        offset: 100,
        expected_size_epoch: 7,
        initialized_offset: 100,
        data,
        length: 4,
        initialized_length: 2,
        rw_flags: 0,
        reserved: 0,
        reply,
    }
}

fn canonical_replay(reply: BufferRef) -> ReplayOpenV2 {
    ReplayOpenV2 {
        header: control_header(104),
        kernel_open_id: 1,
        file_id: FileId { lo: 2, hi: 3 },
        link_id: LinkId { lo: 4, hi: 5 },
        desired_access: 0x0012_0089,
        share_access: 7,
        create_options: 0,
        disposition: 1,
        ccb_sequence: 6,
        state_flags: 0,
        reply,
    }
}

fn canonical_query(reply: BufferRef, committed_result: BufferRef) -> QueryOpV2 {
    QueryOpV2 {
        header: control_header(104),
        op_id: OpId { lo: 1, hi: 2 },
        operation_digest: [0xa5; 32],
        reply,
        committed_result,
    }
}

fn canonical_ack() -> AckResultV2 {
    AckResultV2 {
        header: control_header(56),
        op_id: OpId { lo: 1, hi: 2 },
        operation_digest: [0x5a; 32],
    }
}

#[test]
fn wave6_v2_layouts_are_exact_gapless_and_prefix_compatible() {
    assert_eq!(CONTROL_VERSION_V2, 2);
    assert_wire_layout!(PrepareOpenV2, 192, 8;
        header: ControlHeader => 0, op_id: OpId => 8, parent_id: FileId => 24,
        name: BufferRef => 40, security_context_id: u64 => 64,
        desired_access: u32 => 72, share_access: u32 => 76,
        disposition: u32 => 80, create_options: u32 => 84,
        file_attributes: u32 => 88, open_flags: u32 => 92,
        requested_security_descriptor: BufferRef => 96,
        extended_attributes: BufferRef => 120, reply: BufferRef => 144,
        result_security_descriptor: BufferRef => 168,
    );
    assert_wire_layout!(CommitOpenV2, 104, 8;
        header: ControlHeader => 0, op_id: OpId => 8,
        transaction_id: TransactionId => 24,
        expected_namespace_generation: u64 => 40,
        expected_security_generation: u64 => 48, kernel_open_id: u64 => 56,
        commit_flags: u32 => 64, reserved: u32 => 68,
        granted_access: u32 => 72, reserved2: u32 => 76,
        reply: BufferRef => 80,
    );
    assert_wire_layout!(CommitOpenResultV2, 112, 8;
        header: ControlHeader => 0, provider_open_cookie: u64 => 8,
        file_id: FileId => 16, link_id: LinkId => 32, sizes: SizeState => 48,
        namespace_generation: u64 => 80, security_generation: u64 => 88,
        create_result: u32 => 96, result_flags: u32 => 100,
        volume_commit_sequence: u64 => 104,
    );
    assert_wire_layout!(WriteV2, 112, 8;
        header: ControlHeader => 0, op_id: OpId => 8, offset: u64 => 24,
        expected_size_epoch: u64 => 32, initialized_offset: u64 => 40,
        data: BufferRef => 48, length: u32 => 72,
        initialized_length: u32 => 76, rw_flags: u32 => 80,
        reserved: u32 => 84, reply: BufferRef => 88,
    );
    assert_wire_layout!(WriteResultV2, 56, 8;
        header: ControlHeader => 0, sizes: SizeState => 8,
        volume_commit_sequence: u64 => 40, flags: u32 => 48,
        reserved: u32 => 52,
    );
    assert_wire_layout!(ReplayOpenV2, 104, 8;
        header: ControlHeader => 0, kernel_open_id: u64 => 8,
        file_id: FileId => 16, link_id: LinkId => 32,
        desired_access: u32 => 48, share_access: u32 => 52,
        create_options: u32 => 56, disposition: u32 => 60,
        ccb_sequence: u64 => 64, state_flags: u64 => 72,
        reply: BufferRef => 80,
    );
    assert_wire_layout!(QueryOpV2, 104, 8;
        header: ControlHeader => 0, op_id: OpId => 8,
        operation_digest: [u8; 32] => 24, reply: BufferRef => 56,
        committed_result: BufferRef => 80,
    );
    assert_wire_layout!(AckResultV2, 56, 8;
        header: ControlHeader => 0, op_id: OpId => 8,
        operation_digest: [u8; 32] => 24,
    );
}

#[test]
fn wave6_v2_prefixes_match_their_v1_physical_prefixes() {
    assert_eq!(
        &encode_exact::<_, 192>(&sentinel_prepare_v2())[..96],
        &encode_exact::<_, 96>(&sentinel_prepare_v1())
    );
    assert_eq!(
        &encode_exact::<_, 104>(&sentinel_commit_v2())[..72],
        &encode_exact::<_, 72>(&sentinel_commit_v1())
    );
    assert_eq!(
        &encode_exact::<_, 112>(&sentinel_commit_result_v2())[..104],
        &encode_exact::<_, 104>(&sentinel_commit_result_v1())
    );
    assert_eq!(
        &encode_exact::<_, 104>(&sentinel_replay_v2())[..80],
        &encode_exact::<_, 80>(&sentinel_replay_v1())
    );
    assert_eq!(
        &encode_exact::<_, 104>(&sentinel_query_v2())[..56],
        &encode_exact::<_, 56>(&sentinel_query_v1())
    );
    assert_eq!(
        &encode_exact::<_, 56>(&sentinel_ack_v2())[..24],
        &encode_exact::<_, 24>(&sentinel_ack_v1())
    );
}

#[test]
fn wave6_v2_headers_and_grant_directions_have_canonical_examples() {
    let prepare = PrepareOpenV2 {
        header: ControlHeader {
            struct_size: 192,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        op_id: sentinel_op(1),
        parent_id: sentinel_file(2),
        name: BufferRef {
            token: 3,
            offset: 0,
            length: 4,
            kind: buffer_kind::SLOT,
            access: buffer_access::K2U_READ_ONLY,
            reserved: 0,
        },
        security_context_id: 0,
        desired_access: 0,
        share_access: 0,
        disposition: 0,
        create_options: 0,
        file_attributes: 0,
        open_flags: 0,
        requested_security_descriptor: BufferRef::default(),
        extended_attributes: BufferRef::default(),
        reply: BufferRef {
            token: 5,
            offset: 0,
            length: 136,
            kind: buffer_kind::MAPPING,
            access: buffer_access::U2K_WRITE,
            reserved: 0,
        },
        result_security_descriptor: BufferRef {
            token: 6,
            offset: 0,
            length: 65_536,
            kind: buffer_kind::MAPPING,
            access: buffer_access::U2K_WRITE,
            reserved: 0,
        },
    };
    assert_eq!(
        encode_exact::<_, 192>(&prepare)[..8],
        [192, 0, 0, 0, 2, 0, 0, 0]
    );
    assert_eq!(prepare.name.access, buffer_access::K2U_READ_ONLY);
    assert_eq!(prepare.reply.access, buffer_access::U2K_WRITE);
    assert_eq!(prepare.result_security_descriptor.length, 65_536);
}

#[test]
fn prepare_open_v2_has_a_complete_literal_little_endian_image() {
    let value = sentinel_prepare_v2();
    let mut expected = [0u8; 192];
    put_header(&mut expected, 0, value.header);
    put_pair(&mut expected, 8, value.op_id.lo, value.op_id.hi);
    put_pair(&mut expected, 24, value.parent_id.lo, value.parent_id.hi);
    put_buffer(&mut expected, 40, value.name);
    put_u64(&mut expected, 64, value.security_context_id);
    put_u32(&mut expected, 72, value.desired_access);
    put_u32(&mut expected, 76, value.share_access);
    put_u32(&mut expected, 80, value.disposition);
    put_u32(&mut expected, 84, value.create_options);
    put_u32(&mut expected, 88, value.file_attributes);
    put_u32(&mut expected, 92, value.open_flags);
    put_buffer(&mut expected, 96, value.requested_security_descriptor);
    put_buffer(&mut expected, 120, value.extended_attributes);
    put_buffer(&mut expected, 144, value.reply);
    put_buffer(&mut expected, 168, value.result_security_descriptor);
    assert_eq!(encode_exact::<_, 192>(&value), expected);
}

#[test]
fn commit_open_v2_family_has_complete_literal_little_endian_images() {
    let request = sentinel_commit_v2();
    let mut request_expected = [0u8; 104];
    put_header(&mut request_expected, 0, request.header);
    put_pair(&mut request_expected, 8, request.op_id.lo, request.op_id.hi);
    put_pair(
        &mut request_expected,
        24,
        request.transaction_id.lo,
        request.transaction_id.hi,
    );
    put_u64(
        &mut request_expected,
        40,
        request.expected_namespace_generation,
    );
    put_u64(
        &mut request_expected,
        48,
        request.expected_security_generation,
    );
    put_u64(&mut request_expected, 56, request.kernel_open_id);
    put_u32(&mut request_expected, 64, request.commit_flags);
    put_u32(&mut request_expected, 68, request.reserved);
    put_u32(&mut request_expected, 72, request.granted_access);
    put_u32(&mut request_expected, 76, request.reserved2);
    put_buffer(&mut request_expected, 80, request.reply);
    assert_eq!(encode_exact::<_, 104>(&request), request_expected);

    let result = sentinel_commit_result_v2();
    let mut result_expected = [0u8; 112];
    put_header(&mut result_expected, 0, result.header);
    put_u64(&mut result_expected, 8, result.provider_open_cookie);
    put_pair(
        &mut result_expected,
        16,
        result.file_id.lo,
        result.file_id.hi,
    );
    put_pair(
        &mut result_expected,
        32,
        result.link_id.lo,
        result.link_id.hi,
    );
    put_sizes(&mut result_expected, 48, result.sizes);
    put_u64(&mut result_expected, 80, result.namespace_generation);
    put_u64(&mut result_expected, 88, result.security_generation);
    put_u32(&mut result_expected, 96, result.create_result);
    put_u32(&mut result_expected, 100, result.result_flags);
    put_u64(&mut result_expected, 104, result.volume_commit_sequence);
    assert_eq!(encode_exact::<_, 112>(&result), result_expected);
}

#[test]
fn write_v2_family_has_complete_literal_little_endian_images() {
    let request = sentinel_write_v2();
    let mut request_expected = [0u8; 112];
    put_header(&mut request_expected, 0, request.header);
    put_pair(&mut request_expected, 8, request.op_id.lo, request.op_id.hi);
    put_u64(&mut request_expected, 24, request.offset);
    put_u64(&mut request_expected, 32, request.expected_size_epoch);
    put_u64(&mut request_expected, 40, request.initialized_offset);
    put_buffer(&mut request_expected, 48, request.data);
    put_u32(&mut request_expected, 72, request.length);
    put_u32(&mut request_expected, 76, request.initialized_length);
    put_u32(&mut request_expected, 80, request.rw_flags);
    put_u32(&mut request_expected, 84, request.reserved);
    put_buffer(&mut request_expected, 88, request.reply);
    assert_eq!(encode_exact::<_, 112>(&request), request_expected);

    let result = sentinel_write_result_v2();
    let mut result_expected = [0u8; 56];
    put_header(&mut result_expected, 0, result.header);
    put_sizes(&mut result_expected, 8, result.sizes);
    put_u64(&mut result_expected, 40, result.volume_commit_sequence);
    put_u32(&mut result_expected, 48, result.flags);
    put_u32(&mut result_expected, 52, result.reserved);
    assert_eq!(encode_exact::<_, 56>(&result), result_expected);
}

#[test]
fn recovery_v2_family_has_complete_literal_little_endian_images() {
    let replay = sentinel_replay_v2();
    let mut replay_expected = [0u8; 104];
    put_header(&mut replay_expected, 0, replay.header);
    put_u64(&mut replay_expected, 8, replay.kernel_open_id);
    put_pair(
        &mut replay_expected,
        16,
        replay.file_id.lo,
        replay.file_id.hi,
    );
    put_pair(
        &mut replay_expected,
        32,
        replay.link_id.lo,
        replay.link_id.hi,
    );
    put_u32(&mut replay_expected, 48, replay.desired_access);
    put_u32(&mut replay_expected, 52, replay.share_access);
    put_u32(&mut replay_expected, 56, replay.create_options);
    put_u32(&mut replay_expected, 60, replay.disposition);
    put_u64(&mut replay_expected, 64, replay.ccb_sequence);
    put_u64(&mut replay_expected, 72, replay.state_flags);
    put_buffer(&mut replay_expected, 80, replay.reply);
    assert_eq!(encode_exact::<_, 104>(&replay), replay_expected);

    let query = sentinel_query_v2();
    let mut query_expected = [0u8; 104];
    put_header(&mut query_expected, 0, query.header);
    put_pair(&mut query_expected, 8, query.op_id.lo, query.op_id.hi);
    query_expected[24..56].copy_from_slice(&query.operation_digest);
    put_buffer(&mut query_expected, 56, query.reply);
    put_buffer(&mut query_expected, 80, query.committed_result);
    assert_eq!(encode_exact::<_, 104>(&query), query_expected);

    let ack = sentinel_ack_v2();
    let mut ack_expected = [0u8; 56];
    put_header(&mut ack_expected, 0, ack.header);
    put_pair(&mut ack_expected, 8, ack.op_id.lo, ack.op_id.hi);
    ack_expected[24..56].copy_from_slice(&ack.operation_digest);
    assert_eq!(encode_exact::<_, 56>(&ack), ack_expected);
}

#[test]
fn abi21_control_versions_and_rw_forms_are_closed() {
    let v2 = [
        op::PREPARE_OPEN,
        op::COMMIT_OPEN,
        op::WRITE,
        op::MUTATE,
        op::QUERY_DIR,
        op::REPLAY_OPEN,
        op::QUERY_OP,
        op::ACK_RESULT,
    ];
    let v1 = [
        op::ABORT_OPEN,
        op::QUERY_INFO,
        op::QUERY_VOLUME,
        op::QUERY_SECURITY,
        op::FSCTL,
    ];
    for opcode in u16::MIN..=u16::MAX {
        for version in [0, 1, 2, 3, u16::MAX] {
            let expected = if v2.contains(&opcode) {
                version == 2
            } else if v1.contains(&opcode) {
                version == 1
            } else {
                false
            };
            assert_eq!(
                validate_request_version_v21(opcode, version).is_ok(),
                expected,
                "opcode={opcode:#06x} version={version}"
            );
        }
    }
    for version in u16::MIN..=u16::MAX {
        assert_eq!(
            validate_notification_version_v21(version).is_ok(),
            version == 2
        );
    }
    assert_eq!(
        validate_request_wire_form_v21(op::READ, RwRequestWireFormV21::InlinePrw),
        Ok(())
    );
    assert_eq!(
        validate_request_wire_form_v21(op::READ, RwRequestWireFormV21::Control),
        Err(MessageValidationError::IllegalWireForm)
    );
    assert_eq!(
        validate_request_wire_form_v21(op::WRITE, RwRequestWireFormV21::Control),
        Ok(())
    );
    assert_eq!(
        validate_request_wire_form_v21(op::WRITE, RwRequestWireFormV21::InlinePrw),
        Err(MessageValidationError::IllegalWireForm)
    );
    for opcode in [op::READ, op::WRITE] {
        assert_eq!(
            validate_result_wire_form_v21(opcode, RwResultWireFormV21::OControl),
            Ok(())
        );
        assert_eq!(
            validate_result_wire_form_v21(opcode, RwResultWireFormV21::Orw),
            Err(MessageValidationError::IllegalWireForm)
        );
    }
}

#[test]
fn rw_submission_and_size_state_boundaries_are_closed() {
    assert_eq!(
        classify_rw_submission_v21(0, 0),
        Ok(RwSubmissionV21::CompleteLocally)
    );
    assert_eq!(
        classify_rw_submission_v21(MAX_FILE_SIZE - 1, 1),
        Ok(RwSubmissionV21::Emit)
    );
    assert_eq!(
        classify_rw_submission_v21(MAX_FILE_SIZE, 1),
        Err(MessageValidationError::Range(
            fsring_abi::RangeError::OffsetOutOfRange
        ))
    );

    for sizes in [
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        },
        SizeState {
            allocation_size: MAX_FILE_SIZE,
            file_size: MAX_FILE_SIZE,
            valid_data_length: MAX_FILE_SIZE,
            size_epoch: u64::MAX,
        },
    ] {
        assert_eq!(validate_size_state_v21(sizes), Ok(()));
    }

    let invalid_scalars = [
        SizeState {
            allocation_size: MAX_FILE_SIZE + 1,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        },
        SizeState {
            allocation_size: MAX_FILE_SIZE,
            file_size: MAX_FILE_SIZE + 1,
            valid_data_length: 0,
            size_epoch: 1,
        },
        SizeState {
            allocation_size: MAX_FILE_SIZE,
            file_size: MAX_FILE_SIZE,
            valid_data_length: MAX_FILE_SIZE + 1,
            size_epoch: 1,
        },
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 0,
        },
    ];
    for sizes in invalid_scalars {
        assert_eq!(
            validate_size_state_v21(sizes),
            Err(MessageValidationError::SizeState)
        );
    }

    for sizes in [
        SizeState {
            allocation_size: 1,
            file_size: 2,
            valid_data_length: 0,
            size_epoch: 1,
        },
        SizeState {
            allocation_size: 2,
            file_size: 1,
            valid_data_length: 2,
            size_epoch: 1,
        },
    ] {
        assert_eq!(
            validate_size_state_v21(sizes),
            Err(MessageValidationError::Relationship)
        );
    }
}

#[test]
fn every_wave6_request_accepts_canonical_mapping_grants() {
    let name = mapping_grant(1, buffer_access::K2U_READ_ONLY, 10);
    let requested_sd = mapping_grant(2, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(3, buffer_access::K2U_READ_ONLY, 1);
    let prepare_reply = mapping_grant(4, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(5, buffer_access::U2K_WRITE, 65_536);
    let prepare = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        prepare_reply.issued,
        result_sd.issued,
    );
    let prepare_context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: Some(binding(&requested_sd)),
        extended_attributes: Some(binding(&ea)),
        reply: binding(&prepare_reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: Some(20),
        validated_ea_length: Some(1),
    };
    let prepare_proof = validate_prepare_open_v2(&prepare, &prepare_context).unwrap();
    assert_eq!(validated_length(prepare_proof.name()), 10);
    assert_eq!(
        validated_length(prepare_proof.requested_security_descriptor().unwrap()),
        20
    );
    assert_eq!(
        validated_length(prepare_proof.extended_attributes().unwrap()),
        1
    );
    assert_eq!(validated_length(prepare_proof.reply()), 136);
    assert_eq!(
        validated_length(prepare_proof.result_security_descriptor()),
        65_536
    );

    let commit_reply = mapping_grant(6, buffer_access::U2K_WRITE, 112);
    let commit = canonical_commit(commit_reply.issued);
    assert_eq!(
        validated_length(
            validate_commit_open_v2(&commit, binding(&commit_reply))
                .unwrap()
                .reply()
        ),
        112
    );

    let read_data = mapping_grant(7, buffer_access::U2K_WRITE, 4);
    let read = canonical_read(read_data.issued);
    assert_eq!(
        validated_length(
            validate_read_v21(&read, binding(&read_data))
                .unwrap()
                .data()
        ),
        4
    );

    let write_data = mapping_grant(8, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(9, buffer_access::U2K_WRITE, 56);
    let write = canonical_write(write_data.issued, write_reply.issued);
    let write_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    let write_proof = validate_write_v2(&write, &write_context).unwrap();
    assert_eq!(validated_length(write_proof.data()), 4);
    assert_eq!(validated_length(write_proof.reply()), 56);

    let replay_reply = mapping_grant(10, buffer_access::U2K_WRITE, 16);
    let replay = canonical_replay(replay_reply.issued);
    assert_eq!(
        validated_length(
            validate_replay_open_v2(&replay, binding(&replay_reply))
                .unwrap()
                .reply()
        ),
        16
    );

    let query_reply = mapping_grant(11, buffer_access::U2K_WRITE, 56);
    let committed_result = mapping_grant(12, buffer_access::U2K_WRITE, 224);
    let query = canonical_query(query_reply.issued, committed_result.issued);
    let query_context = QueryOpV2Context {
        reply: binding(&query_reply),
        committed_result: binding(&committed_result),
        retained_cancelled_no_candidate: false,
    };
    let query_proof = validate_query_op_v2(&query, &query_context).unwrap();
    assert_eq!(validated_length(query_proof.reply()), 56);
    assert_eq!(validated_length(query_proof.committed_result()), 224);

    assert_eq!(validate_ack_result_v2(&canonical_ack()), Ok(()));
}

#[test]
fn every_wave6_request_accepts_canonical_slot_grants() {
    let name = slot_grant(SlotDirection::K2u, 10, 1);
    let requested_sd = slot_grant(SlotDirection::K2u, 20, 2);
    let ea = slot_grant(SlotDirection::K2u, 1, 3);
    let prepare_reply = slot_grant(SlotDirection::U2k, 136, 4);
    let result_sd = slot_grant(SlotDirection::U2k, 65_536, 5);
    let prepare = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        prepare_reply.issued,
        result_sd.issued,
    );
    let prepare_context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: Some(binding(&requested_sd)),
        extended_attributes: Some(binding(&ea)),
        reply: binding(&prepare_reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: Some(20),
        validated_ea_length: Some(1),
    };
    assert!(validate_prepare_open_v2(&prepare, &prepare_context).is_ok());

    let commit_reply = slot_grant(SlotDirection::U2k, 112, 6);
    assert!(validate_commit_open_v2(
        &canonical_commit(commit_reply.issued),
        binding(&commit_reply)
    )
    .is_ok());

    let read_data = slot_grant(SlotDirection::U2k, 4, 7);
    assert!(validate_read_v21(&canonical_read(read_data.issued), binding(&read_data)).is_ok());

    let write_data = slot_grant(SlotDirection::K2u, 4, 8);
    let write_reply = slot_grant(SlotDirection::U2k, 56, 9);
    assert!(validate_write_v2(
        &canonical_write(write_data.issued, write_reply.issued),
        &WriteV2Context {
            data: binding(&write_data),
            reply: binding(&write_reply),
        },
    )
    .is_ok());

    let replay_reply = slot_grant(SlotDirection::U2k, 16, 10);
    assert!(validate_replay_open_v2(
        &canonical_replay(replay_reply.issued),
        binding(&replay_reply)
    )
    .is_ok());

    let query_reply = slot_grant(SlotDirection::U2k, 56, 11);
    let committed_result = slot_grant(SlotDirection::U2k, 224, 12);
    assert!(validate_query_op_v2(
        &canonical_query(query_reply.issued, committed_result.issued),
        &QueryOpV2Context {
            reply: binding(&query_reply),
            committed_result: binding(&committed_result),
            retained_cancelled_no_candidate: false,
        },
    )
    .is_ok());

    assert_eq!(validate_ack_result_v2(&canonical_ack()), Ok(()));
}

#[test]
fn prepare_optional_inputs_and_capacity_boundaries_are_exact() {
    let name = mapping_grant(101, buffer_access::K2U_READ_ONLY, 10);
    let reply = mapping_grant(102, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(103, buffer_access::U2K_WRITE, 65_536);
    let absent = canonical_prepare(
        name.issued,
        BufferRef::default(),
        BufferRef::default(),
        reply.issued,
        result_sd.issued,
    );
    let absent_context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: None,
        extended_attributes: None,
        reply: binding(&reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: None,
        validated_ea_length: None,
    };
    let proof = validate_prepare_open_v2(&absent, &absent_context).unwrap();
    assert_eq!(proof.requested_security_descriptor(), None);
    assert_eq!(proof.extended_attributes(), None);

    let requested_sd = mapping_grant(104, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(105, buffer_access::K2U_READ_ONLY, 1);
    let present = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        reply.issued,
        result_sd.issued,
    );
    for context in [
        PrepareOpenV2Context {
            name: binding(&name),
            requested_security_descriptor: None,
            extended_attributes: Some(binding(&ea)),
            reply: binding(&reply),
            result_security_descriptor: binding(&result_sd),
            validated_name_length: 10,
            validated_security_descriptor_length: Some(20),
            validated_ea_length: Some(1),
        },
        PrepareOpenV2Context {
            name: binding(&name),
            requested_security_descriptor: Some(binding(&requested_sd)),
            extended_attributes: None,
            reply: binding(&reply),
            result_security_descriptor: binding(&result_sd),
            validated_name_length: 10,
            validated_security_descriptor_length: Some(20),
            validated_ea_length: Some(1),
        },
    ] {
        assert_eq!(
            validate_prepare_open_v2(&present, &context),
            Err(MessageValidationError::Relationship)
        );
    }

    for length in [19, 20, 65_536, 65_537] {
        let sd = mapping_grant(
            200 + u64::from(length),
            buffer_access::K2U_READ_ONLY,
            length,
        );
        let request = canonical_prepare(
            name.issued,
            sd.issued,
            BufferRef::default(),
            reply.issued,
            result_sd.issued,
        );
        let context = PrepareOpenV2Context {
            name: binding(&name),
            requested_security_descriptor: Some(binding(&sd)),
            extended_attributes: None,
            reply: binding(&reply),
            result_security_descriptor: binding(&result_sd),
            validated_name_length: 10,
            validated_security_descriptor_length: Some(length),
            validated_ea_length: None,
        };
        assert_eq!(
            validate_prepare_open_v2(&request, &context).is_ok(),
            matches!(length, 20 | 65_536),
            "requested SD length={length}"
        );
    }

    for length in [1, 65_536, 65_537] {
        let ea = mapping_grant(
            300 + u64::from(length),
            buffer_access::K2U_READ_ONLY,
            length,
        );
        let request = canonical_prepare(
            name.issued,
            BufferRef::default(),
            ea.issued,
            reply.issued,
            result_sd.issued,
        );
        let context = PrepareOpenV2Context {
            name: binding(&name),
            requested_security_descriptor: None,
            extended_attributes: Some(binding(&ea)),
            reply: binding(&reply),
            result_security_descriptor: binding(&result_sd),
            validated_name_length: 10,
            validated_security_descriptor_length: None,
            validated_ea_length: Some(length),
        };
        assert_eq!(
            validate_prepare_open_v2(&request, &context).is_ok(),
            matches!(length, 1 | 65_536),
            "EA length={length}"
        );
    }

    let mut zero_ea = mapping_grant(106, buffer_access::K2U_READ_ONLY, 1);
    zero_ea.issued.length = 0;
    let zero_ea_request = canonical_prepare(
        name.issued,
        BufferRef::default(),
        zero_ea.issued,
        reply.issued,
        result_sd.issued,
    );
    let zero_ea_context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: None,
        extended_attributes: Some(binding(&zero_ea)),
        reply: binding(&reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: None,
        validated_ea_length: Some(0),
    };
    assert_eq!(
        validate_prepare_open_v2(&zero_ea_request, &zero_ea_context),
        Err(MessageValidationError::InvalidScalar)
    );
}

#[test]
fn every_required_output_capacity_is_closed_at_its_boundary() {
    let name = mapping_grant(401, buffer_access::K2U_READ_ONLY, 10);
    let result_sd = mapping_grant(402, buffer_access::U2K_WRITE, 65_536);
    for (length, expected) in [(135, false), (136, true), (137, true)] {
        let reply = mapping_grant(403 + u64::from(length), buffer_access::U2K_WRITE, length);
        let request = canonical_prepare(
            name.issued,
            BufferRef::default(),
            BufferRef::default(),
            reply.issued,
            result_sd.issued,
        );
        let context = PrepareOpenV2Context {
            name: binding(&name),
            requested_security_descriptor: None,
            extended_attributes: None,
            reply: binding(&reply),
            result_security_descriptor: binding(&result_sd),
            validated_name_length: 10,
            validated_security_descriptor_length: None,
            validated_ea_length: None,
        };
        assert_eq!(
            validate_prepare_open_v2(&request, &context).is_ok(),
            expected
        );
    }

    for (length, expected) in [(111, false), (112, true), (113, true)] {
        let reply = mapping_grant(500 + u64::from(length), buffer_access::U2K_WRITE, length);
        assert_eq!(
            validate_commit_open_v2(&canonical_commit(reply.issued), binding(&reply)).is_ok(),
            expected
        );
    }

    for (length, expected) in [(15, false), (16, true), (17, true)] {
        let reply = mapping_grant(600 + u64::from(length), buffer_access::U2K_WRITE, length);
        assert_eq!(
            validate_replay_open_v2(&canonical_replay(reply.issued), binding(&reply)).is_ok(),
            expected
        );
    }

    for (length, expected) in [(55, false), (56, true), (57, true)] {
        let reply = mapping_grant(700 + u64::from(length), buffer_access::U2K_WRITE, length);
        let committed = mapping_grant(800, buffer_access::U2K_WRITE, 224);
        assert_eq!(
            validate_query_op_v2(
                &canonical_query(reply.issued, committed.issued),
                &QueryOpV2Context {
                    reply: binding(&reply),
                    committed_result: binding(&committed),
                    retained_cancelled_no_candidate: false,
                },
            )
            .is_ok(),
            expected
        );
    }

    for (length, expected) in [(223, false), (224, true), (225, false)] {
        let reply = mapping_grant(900, buffer_access::U2K_WRITE, 56);
        let committed = mapping_grant(901 + u64::from(length), buffer_access::U2K_WRITE, length);
        assert_eq!(
            validate_query_op_v2(
                &canonical_query(reply.issued, committed.issued),
                &QueryOpV2Context {
                    reply: binding(&reply),
                    committed_result: binding(&committed),
                    retained_cancelled_no_candidate: false,
                },
            )
            .is_ok(),
            expected,
            "committed result length={length}"
        );
    }
}

#[test]
fn rw_request_scalars_relationships_and_directions_are_closed() {
    let read_data = mapping_grant(1_001, buffer_access::U2K_WRITE, 4);
    let mut read = canonical_read(read_data.issued);
    read.length = 0;
    assert_eq!(
        validate_read_v21(&read, binding(&read_data)),
        Err(MessageValidationError::LocalOnlyWireForm)
    );
    read = canonical_read(read_data.issued);
    read.initialized_length = 5;
    assert_eq!(
        validate_read_v21(&read, binding(&read_data)),
        Err(MessageValidationError::Relationship)
    );
    read = canonical_read(read_data.issued);
    read.offset = MAX_FILE_SIZE;
    assert_eq!(
        validate_read_v21(&read, binding(&read_data)),
        Err(MessageValidationError::Range(
            fsring_abi::RangeError::OffsetOutOfRange
        ))
    );
    read = canonical_read(read_data.issued);
    read.rw_flags = 0x80;
    assert_eq!(
        validate_read_v21(&read, binding(&read_data)),
        Err(MessageValidationError::FlagsOrReserved)
    );
    read = canonical_read(read_data.issued);
    read.reserved = 1;
    assert_eq!(
        validate_read_v21(&read, binding(&read_data)),
        Err(MessageValidationError::FlagsOrReserved)
    );

    let wrong_read_data = mapping_grant(1_002, buffer_access::K2U_READ_ONLY, 4);
    assert_eq!(
        validate_read_v21(
            &canonical_read(wrong_read_data.issued),
            binding(&wrong_read_data)
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let write_data = mapping_grant(1_003, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(1_004, buffer_access::U2K_WRITE, 56);
    let context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    let mut write = canonical_write(write_data.issued, write_reply.issued);
    write.length = 0;
    assert_eq!(
        validate_write_v2(&write, &context),
        Err(MessageValidationError::LocalOnlyWireForm)
    );
    write = canonical_write(write_data.issued, write_reply.issued);
    write.initialized_length = 5;
    assert_eq!(
        validate_write_v2(&write, &context),
        Err(MessageValidationError::Relationship)
    );
    write = canonical_write(write_data.issued, write_reply.issued);
    write.offset = MAX_FILE_SIZE;
    assert_eq!(
        validate_write_v2(&write, &context),
        Err(MessageValidationError::Range(
            fsring_abi::RangeError::OffsetOutOfRange
        ))
    );
    write = canonical_write(write_data.issued, write_reply.issued);
    write.rw_flags = 0x80;
    assert_eq!(
        validate_write_v2(&write, &context),
        Err(MessageValidationError::FlagsOrReserved)
    );
    write = canonical_write(write_data.issued, write_reply.issued);
    write.reserved = 1;
    assert_eq!(
        validate_write_v2(&write, &context),
        Err(MessageValidationError::FlagsOrReserved)
    );

    let short_data = mapping_grant(1_005, buffer_access::K2U_READ_ONLY, 3);
    let short_context = WriteV2Context {
        data: binding(&short_data),
        reply: binding(&write_reply),
    };
    assert_eq!(
        validate_write_v2(
            &canonical_write(short_data.issued, write_reply.issued),
            &short_context,
        ),
        Err(MessageValidationError::Relationship)
    );

    let short_reply = mapping_grant(1_006, buffer_access::U2K_WRITE, 55);
    let short_reply_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&short_reply),
    };
    assert_eq!(
        validate_write_v2(
            &canonical_write(write_data.issued, short_reply.issued),
            &short_reply_context,
        ),
        Err(MessageValidationError::InvalidScalar)
    );

    let wrong_write_data = mapping_grant(1_007, buffer_access::U2K_WRITE, 4);
    let wrong_direction_context = WriteV2Context {
        data: binding(&wrong_write_data),
        reply: binding(&write_reply),
    };
    assert_eq!(
        validate_write_v2(
            &canonical_write(wrong_write_data.issued, write_reply.issued),
            &wrong_direction_context,
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );
}

#[test]
fn contextual_grant_faults_keep_their_exact_causes() {
    let data = mapping_grant(1_101, buffer_access::K2U_READ_ONLY, 4);
    let reply = mapping_grant(1_102, buffer_access::U2K_WRITE, 56);
    let canonical = canonical_write(data.issued, reply.issued);

    let wrong_epoch = GrantBindingV21 {
        grant: &data,
        expected_session_epoch: 10,
        expected_owner: data.owner,
    };
    assert_eq!(
        validate_write_v2(
            &canonical,
            &WriteV2Context {
                data: wrong_epoch,
                reply: binding(&reply),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::SessionEpochMismatch
        ))
    );

    let wrong_owner = GrantBindingV21 {
        grant: &data,
        expected_session_epoch: data.session_epoch,
        expected_owner: GrantOwner::Request(ReqId::try_new(8, 3).unwrap()),
    };
    assert_eq!(
        validate_write_v2(
            &canonical,
            &WriteV2Context {
                data: wrong_owner,
                reply: binding(&reply),
            },
        ),
        Err(MessageValidationError::Grant(BufferRefError::OwnerMismatch))
    );

    let mut rundown = data;
    rundown.state = GrantState::Rundown;
    let rundown_request = canonical_write(rundown.issued, reply.issued);
    assert_eq!(
        validate_write_v2(
            &rundown_request,
            &WriteV2Context {
                data: binding(&rundown),
                reply: binding(&reply),
            },
        ),
        Err(MessageValidationError::Grant(BufferRefError::GrantNotLive))
    );

    let mutations: [MutationRow<BufferRef, BufferRefError>; 6] = [
        (
            |reference| reference.token ^= 1,
            BufferRefError::CapabilityMismatch,
        ),
        (
            |reference| reference.kind = buffer_kind::SLOT,
            BufferRefError::KindMismatch,
        ),
        (
            |reference| reference.access = buffer_access::U2K_WRITE,
            BufferRefError::AccessMismatch,
        ),
        (
            |reference| reference.offset = 1,
            BufferRefError::RangeOutOfBounds,
        ),
        (
            |reference| reference.length = 3,
            BufferRefError::EchoMismatch,
        ),
        (
            |reference| reference.reserved = 1,
            BufferRefError::NonZeroReserved,
        ),
    ];
    for (mutate, expected) in mutations {
        let mut request = canonical;
        mutate(&mut request.data);
        assert_eq!(
            validate_write_v2(
                &request,
                &WriteV2Context {
                    data: binding(&data),
                    reply: binding(&reply),
                },
            ),
            Err(MessageValidationError::Grant(expected))
        );
    }
}

#[test]
fn request_error_precedence_is_header_flags_identity_scalar_then_grant() {
    let data = mapping_grant(1_201, buffer_access::K2U_READ_ONLY, 4);
    let reply = mapping_grant(1_202, buffer_access::U2K_WRITE, 56);
    let context = WriteV2Context {
        data: binding(&data),
        reply: binding(&reply),
    };

    let mut request = canonical_write(data.issued, reply.issued);
    request.header.struct_version = 1;
    request.reserved = 1;
    request.op_id = OpId::ZERO;
    request.length = 0;
    request.data.token ^= 1;
    assert_eq!(
        validate_write_v2(&request, &context),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );

    request.header = control_header(112);
    assert_eq!(
        validate_write_v2(&request, &context),
        Err(MessageValidationError::FlagsOrReserved)
    );
    request.reserved = 0;
    assert_eq!(
        validate_write_v2(&request, &context),
        Err(MessageValidationError::Identity)
    );
    request.op_id = OpId { lo: 1, hi: 2 };
    assert_eq!(
        validate_write_v2(&request, &context),
        Err(MessageValidationError::LocalOnlyWireForm)
    );
    request.length = 4;
    assert_eq!(
        validate_write_v2(&request, &context),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );

    let mut ack = canonical_ack();
    ack.header.required_flags = 1;
    ack.op_id = OpId::ZERO;
    assert_eq!(
        validate_ack_result_v2(&ack),
        Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags
        ))
    );
    ack.header.required_flags = 0;
    assert_eq!(
        validate_ack_result_v2(&ack),
        Err(MessageValidationError::Identity)
    );
}

#[test]
fn every_request_header_and_identity_rule_is_independently_enforced() {
    let name = mapping_grant(1_301, buffer_access::K2U_READ_ONLY, 10);
    let prepare_reply = mapping_grant(1_302, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(1_303, buffer_access::U2K_WRITE, 65_536);
    let prepare_context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: None,
        extended_attributes: None,
        reply: binding(&prepare_reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: None,
        validated_ea_length: None,
    };
    for (mutate, expected) in [
        (
            (|value: &mut PrepareOpenV2| value.header.struct_version = 1) as fn(&mut PrepareOpenV2),
            ControlError::RevisionMismatch,
        ),
        (
            |value: &mut PrepareOpenV2| value.header.required_flags = 1,
            ControlError::UnsupportedRequiredFlags,
        ),
        (
            |value: &mut PrepareOpenV2| value.header.struct_size = 191,
            ControlError::InvalidSize,
        ),
    ] {
        let mut request = canonical_prepare(
            name.issued,
            BufferRef::default(),
            BufferRef::default(),
            prepare_reply.issued,
            result_sd.issued,
        );
        mutate(&mut request);
        assert_eq!(
            validate_prepare_open_v2(&request, &prepare_context),
            Err(MessageValidationError::Control(expected))
        );
    }
    let mut prepare = canonical_prepare(
        name.issued,
        BufferRef::default(),
        BufferRef::default(),
        prepare_reply.issued,
        result_sd.issued,
    );
    prepare.op_id = OpId::ZERO;
    assert_eq!(
        validate_prepare_open_v2(&prepare, &prepare_context),
        Err(MessageValidationError::Identity)
    );

    let commit_reply = mapping_grant(1_304, buffer_access::U2K_WRITE, 112);
    for (mutate, expected) in [
        (
            (|value: &mut CommitOpenV2| value.header.struct_version = 1) as fn(&mut CommitOpenV2),
            ControlError::RevisionMismatch,
        ),
        (
            |value: &mut CommitOpenV2| value.header.required_flags = 1,
            ControlError::UnsupportedRequiredFlags,
        ),
        (
            |value: &mut CommitOpenV2| value.header.struct_size = 103,
            ControlError::InvalidSize,
        ),
    ] {
        let mut request = canonical_commit(commit_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_commit_open_v2(&request, binding(&commit_reply)),
            Err(MessageValidationError::Control(expected))
        );
    }
    for mutate in [
        (|value: &mut CommitOpenV2| value.op_id = OpId::ZERO) as fn(&mut CommitOpenV2),
        |value: &mut CommitOpenV2| value.transaction_id = TransactionId::ZERO,
        |value: &mut CommitOpenV2| value.expected_namespace_generation = 0,
        |value: &mut CommitOpenV2| value.expected_security_generation = 0,
        |value: &mut CommitOpenV2| value.kernel_open_id = 0,
    ] {
        let mut request = canonical_commit(commit_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_commit_open_v2(&request, binding(&commit_reply)),
            Err(MessageValidationError::Identity)
        );
    }
    for mutate in [
        (|value: &mut CommitOpenV2| value.reserved = 1) as fn(&mut CommitOpenV2),
        |value: &mut CommitOpenV2| value.reserved2 = 1,
    ] {
        let mut request = canonical_commit(commit_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_commit_open_v2(&request, binding(&commit_reply)),
            Err(MessageValidationError::FlagsOrReserved)
        );
    }

    let read_data = mapping_grant(1_305, buffer_access::U2K_WRITE, 4);
    let mut read = canonical_read(read_data.issued);
    read.op_id = OpId { lo: 1, hi: 0 };
    assert_eq!(
        validate_read_v21(&read, binding(&read_data)),
        Err(MessageValidationError::Identity)
    );

    let write_data = mapping_grant(1_306, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(1_307, buffer_access::U2K_WRITE, 56);
    let write_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    for (mutate, expected) in [
        (
            (|value: &mut WriteV2| value.header.struct_version = 1) as fn(&mut WriteV2),
            ControlError::RevisionMismatch,
        ),
        (
            |value: &mut WriteV2| value.header.required_flags = 1,
            ControlError::UnsupportedRequiredFlags,
        ),
        (
            |value: &mut WriteV2| value.header.struct_size = 111,
            ControlError::InvalidSize,
        ),
    ] {
        let mut request = canonical_write(write_data.issued, write_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_write_v2(&request, &write_context),
            Err(MessageValidationError::Control(expected))
        );
    }
    for mutate in [
        (|value: &mut WriteV2| value.op_id = OpId::ZERO) as fn(&mut WriteV2),
        |value: &mut WriteV2| value.expected_size_epoch = 0,
    ] {
        let mut request = canonical_write(write_data.issued, write_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_write_v2(&request, &write_context),
            Err(MessageValidationError::Identity)
        );
    }

    let replay_reply = mapping_grant(1_308, buffer_access::U2K_WRITE, 16);
    for (mutate, expected) in [
        (
            (|value: &mut ReplayOpenV2| value.header.struct_version = 1) as fn(&mut ReplayOpenV2),
            ControlError::RevisionMismatch,
        ),
        (
            |value: &mut ReplayOpenV2| value.header.required_flags = 1,
            ControlError::UnsupportedRequiredFlags,
        ),
        (
            |value: &mut ReplayOpenV2| value.header.struct_size = 103,
            ControlError::InvalidSize,
        ),
    ] {
        let mut request = canonical_replay(replay_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_replay_open_v2(&request, binding(&replay_reply)),
            Err(MessageValidationError::Control(expected))
        );
    }
    for mutate in [
        (|value: &mut ReplayOpenV2| value.kernel_open_id = 0) as fn(&mut ReplayOpenV2),
        |value: &mut ReplayOpenV2| value.file_id = FileId::ZERO,
        |value: &mut ReplayOpenV2| value.link_id = LinkId::ZERO,
    ] {
        let mut request = canonical_replay(replay_reply.issued);
        mutate(&mut request);
        assert_eq!(
            validate_replay_open_v2(&request, binding(&replay_reply)),
            Err(MessageValidationError::Identity)
        );
    }

    let query_reply = mapping_grant(1_309, buffer_access::U2K_WRITE, 56);
    let committed = mapping_grant(1_310, buffer_access::U2K_WRITE, 224);
    let query_context = QueryOpV2Context {
        reply: binding(&query_reply),
        committed_result: binding(&committed),
        retained_cancelled_no_candidate: false,
    };
    for (mutate, expected) in [
        (
            (|value: &mut QueryOpV2| value.header.struct_version = 1) as fn(&mut QueryOpV2),
            ControlError::RevisionMismatch,
        ),
        (
            |value: &mut QueryOpV2| value.header.required_flags = 1,
            ControlError::UnsupportedRequiredFlags,
        ),
        (
            |value: &mut QueryOpV2| value.header.struct_size = 103,
            ControlError::InvalidSize,
        ),
    ] {
        let mut request = canonical_query(query_reply.issued, committed.issued);
        mutate(&mut request);
        assert_eq!(
            validate_query_op_v2(&request, &query_context),
            Err(MessageValidationError::Control(expected))
        );
    }
    let mut query = canonical_query(query_reply.issued, committed.issued);
    query.op_id = OpId::ZERO;
    assert_eq!(
        validate_query_op_v2(&query, &query_context),
        Err(MessageValidationError::Identity)
    );

    for (mutate, expected) in [
        (
            (|value: &mut AckResultV2| value.header.struct_version = 1) as fn(&mut AckResultV2),
            ControlError::RevisionMismatch,
        ),
        (
            |value: &mut AckResultV2| value.header.required_flags = 1,
            ControlError::UnsupportedRequiredFlags,
        ),
        (
            |value: &mut AckResultV2| value.header.struct_size = 55,
            ControlError::InvalidSize,
        ),
    ] {
        let mut request = canonical_ack();
        mutate(&mut request);
        assert_eq!(
            validate_ack_result_v2(&request),
            Err(MessageValidationError::Control(expected))
        );
    }
}

#[test]
fn every_grant_role_rejects_reversed_access_and_required_none() {
    let name = mapping_grant(1_401, buffer_access::K2U_READ_ONLY, 10);
    let requested_sd = mapping_grant(1_402, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(1_403, buffer_access::K2U_READ_ONLY, 1);
    let reply = mapping_grant(1_404, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(1_405, buffer_access::U2K_WRITE, 65_536);

    let wrong_name = mapping_grant(1_406, buffer_access::U2K_WRITE, 10);
    let request = canonical_prepare(
        wrong_name.issued,
        requested_sd.issued,
        ea.issued,
        reply.issued,
        result_sd.issued,
    );
    assert_eq!(
        validate_prepare_open_v2(
            &request,
            &PrepareOpenV2Context {
                name: binding(&wrong_name),
                requested_security_descriptor: Some(binding(&requested_sd)),
                extended_attributes: Some(binding(&ea)),
                reply: binding(&reply),
                result_security_descriptor: binding(&result_sd),
                validated_name_length: 10,
                validated_security_descriptor_length: Some(20),
                validated_ea_length: Some(1),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let wrong_requested_sd = mapping_grant(1_407, buffer_access::U2K_WRITE, 20);
    let request = canonical_prepare(
        name.issued,
        wrong_requested_sd.issued,
        ea.issued,
        reply.issued,
        result_sd.issued,
    );
    assert_eq!(
        validate_prepare_open_v2(
            &request,
            &PrepareOpenV2Context {
                name: binding(&name),
                requested_security_descriptor: Some(binding(&wrong_requested_sd)),
                extended_attributes: Some(binding(&ea)),
                reply: binding(&reply),
                result_security_descriptor: binding(&result_sd),
                validated_name_length: 10,
                validated_security_descriptor_length: Some(20),
                validated_ea_length: Some(1),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let wrong_ea = mapping_grant(1_408, buffer_access::U2K_WRITE, 1);
    let request = canonical_prepare(
        name.issued,
        requested_sd.issued,
        wrong_ea.issued,
        reply.issued,
        result_sd.issued,
    );
    assert_eq!(
        validate_prepare_open_v2(
            &request,
            &PrepareOpenV2Context {
                name: binding(&name),
                requested_security_descriptor: Some(binding(&requested_sd)),
                extended_attributes: Some(binding(&wrong_ea)),
                reply: binding(&reply),
                result_security_descriptor: binding(&result_sd),
                validated_name_length: 10,
                validated_security_descriptor_length: Some(20),
                validated_ea_length: Some(1),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let wrong_reply = mapping_grant(1_409, buffer_access::K2U_READ_ONLY, 136);
    let request = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        wrong_reply.issued,
        result_sd.issued,
    );
    assert_eq!(
        validate_prepare_open_v2(
            &request,
            &PrepareOpenV2Context {
                name: binding(&name),
                requested_security_descriptor: Some(binding(&requested_sd)),
                extended_attributes: Some(binding(&ea)),
                reply: binding(&wrong_reply),
                result_security_descriptor: binding(&result_sd),
                validated_name_length: 10,
                validated_security_descriptor_length: Some(20),
                validated_ea_length: Some(1),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let wrong_result_sd = mapping_grant(1_410, buffer_access::K2U_READ_ONLY, 65_536);
    let request = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        reply.issued,
        wrong_result_sd.issued,
    );
    assert_eq!(
        validate_prepare_open_v2(
            &request,
            &PrepareOpenV2Context {
                name: binding(&name),
                requested_security_descriptor: Some(binding(&requested_sd)),
                extended_attributes: Some(binding(&ea)),
                reply: binding(&reply),
                result_security_descriptor: binding(&wrong_result_sd),
                validated_name_length: 10,
                validated_security_descriptor_length: Some(20),
                validated_ea_length: Some(1),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let commit_reply = mapping_grant(1_411, buffer_access::K2U_READ_ONLY, 112);
    assert_eq!(
        validate_commit_open_v2(
            &canonical_commit(commit_reply.issued),
            binding(&commit_reply)
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let write_data = mapping_grant(1_412, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(1_413, buffer_access::K2U_READ_ONLY, 56);
    assert_eq!(
        validate_write_v2(
            &canonical_write(write_data.issued, write_reply.issued),
            &WriteV2Context {
                data: binding(&write_data),
                reply: binding(&write_reply),
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let replay_reply = mapping_grant(1_414, buffer_access::K2U_READ_ONLY, 16);
    assert_eq!(
        validate_replay_open_v2(
            &canonical_replay(replay_reply.issued),
            binding(&replay_reply)
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let query_reply = mapping_grant(1_415, buffer_access::K2U_READ_ONLY, 56);
    let committed = mapping_grant(1_416, buffer_access::U2K_WRITE, 224);
    assert_eq!(
        validate_query_op_v2(
            &canonical_query(query_reply.issued, committed.issued),
            &QueryOpV2Context {
                reply: binding(&query_reply),
                committed_result: binding(&committed),
                retained_cancelled_no_candidate: false,
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let query_reply = mapping_grant(1_417, buffer_access::U2K_WRITE, 56);
    let committed = mapping_grant(1_418, buffer_access::K2U_READ_ONLY, 224);
    assert_eq!(
        validate_query_op_v2(
            &canonical_query(query_reply.issued, committed.issued),
            &QueryOpV2Context {
                reply: binding(&query_reply),
                committed_result: binding(&committed),
                retained_cancelled_no_candidate: false,
            },
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let mut required_none = canonical_commit(reply.issued);
    required_none.reply = BufferRef::default();
    assert_eq!(
        validate_commit_open_v2(&required_none, binding(&reply)),
        Err(MessageValidationError::Grant(BufferRefError::UnknownAccess))
    );
}

fn abort_record(context: u64) -> ProtocolAbortV1 {
    ProtocolAbortV1 {
        header: ControlHeader {
            struct_size: 24,
            struct_version: 1,
            required_flags: 0,
        },
        reason: 1,
        reserved: 0,
        context,
    }
}

fn protocol_cqe(record: ProtocolAbortV1) -> CqeBody {
    let mut out = [0u8; 24];
    assert_eq!(try_encode(&record, &mut out).unwrap(), 24);
    CqeBody {
        kind: 2,
        opcode: 1,
        flags: 0,
        out_len: 24,
        req_id: 0,
        status: 0,
        reserved: 0,
        information: 0,
        out,
    }
}

#[test]
fn protocol_abort_v1_layout_and_literal_bytes_are_exact() {
    assert_pod::<ProtocolAbortV1>();
    assert_eq!(protocol_opcode::ABORT_SESSION, 1u16);
    assert_eq!(protocol_reason::PROVIDER_FATAL_STATE, 1u32);
    assert_eq!(size_of::<ProtocolAbortV1>(), 24);
    assert_eq!(align_of::<ProtocolAbortV1>(), 8);
    assert_eq!(offset_of!(ProtocolAbortV1, header), 0);
    assert_eq!(offset_of!(ProtocolAbortV1, reason), 8);
    assert_eq!(offset_of!(ProtocolAbortV1, reserved), 12);
    assert_eq!(offset_of!(ProtocolAbortV1, context), 16);
    assert_eq!(offset_of!(ProtocolAbortV1, context) + size_of::<u64>(), 24);

    let record = ProtocolAbortV1 {
        header: ControlHeader {
            struct_size: 0x1817_1615,
            struct_version: 0x1a19,
            required_flags: 0x1c1b,
        },
        reason: 0x2322_2120,
        reserved: 0x2726_2524,
        context: 0x2f2e_2d2c_2b2a_2928,
    };
    let mut actual = [0u8; 24];
    assert_eq!(try_encode(&record, &mut actual).unwrap(), 24);
    assert_eq!(
        actual,
        [
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        ]
    );
}

#[test]
fn exact_protocol_abort_cqe_accepts_every_context_boundary() {
    for context in [0, 0x0123_4567_89ab_cdef, u64::MAX] {
        let expected = abort_record(context);
        assert_eq!(
            validate_protocol_abort_v1(&protocol_cqe(expected)),
            Some(expected)
        );
    }
}

#[test]
fn protocol_abort_cqe_registries_are_literal_and_closed() {
    assert_eq!(cq_kind::PROTOCOL, 2);
    let valid = protocol_cqe(abort_record(0x0123_4567_89ab_cdef));

    for kind in u16::MIN..=u16::MAX {
        let mut candidate = valid;
        candidate.kind = kind;
        assert_eq!(
            validate_protocol_abort_v1(&candidate).is_some(),
            kind == 2,
            "kind {kind}"
        );
    }
    for opcode in u16::MIN..=u16::MAX {
        let mut candidate = valid;
        candidate.opcode = opcode;
        assert_eq!(
            validate_protocol_abort_v1(&candidate).is_some(),
            opcode == 1,
            "opcode {opcode}"
        );
    }
    for flags in u16::MIN..=u16::MAX {
        let mut candidate = valid;
        candidate.flags = flags;
        assert_eq!(
            validate_protocol_abort_v1(&candidate).is_some(),
            flags == 0,
            "flags {flags}"
        );
    }
    for out_len in u16::MIN..=u16::MAX {
        let mut candidate = valid;
        candidate.out_len = out_len;
        assert_eq!(
            validate_protocol_abort_v1(&candidate).is_some(),
            out_len == 24,
            "out_len {out_len}"
        );
    }
    for req_id in [1, u64::MAX] {
        let mut candidate = valid;
        candidate.req_id = req_id;
        assert_eq!(validate_protocol_abort_v1(&candidate), None);
    }
    for status in [i32::MIN, -65_536, -1, 1, 65_536, i32::MAX] {
        let mut candidate = valid;
        candidate.status = status;
        assert_eq!(validate_protocol_abort_v1(&candidate), None);
    }
    for reserved in [1, u32::MAX] {
        let mut candidate = valid;
        candidate.reserved = reserved;
        assert_eq!(validate_protocol_abort_v1(&candidate), None);
    }
    for information in [1, u64::MAX] {
        let mut candidate = valid;
        candidate.information = information;
        assert_eq!(validate_protocol_abort_v1(&candidate), None);
    }
}

#[test]
fn every_noncanonical_protocol_cqe_field_is_rejected() {
    let mutations: [fn(&mut CqeBody); 10] = [
        |cqe| cqe.kind = cq_kind::COMPLETION,
        |cqe| cqe.opcode = 2,
        |cqe| cqe.flags = 1,
        |cqe| cqe.out_len = 23,
        |cqe| cqe.out_len = 25,
        |cqe| cqe.out_len = u16::MAX,
        |cqe| cqe.req_id = 1,
        |cqe| cqe.status = 1,
        |cqe| cqe.reserved = 1,
        |cqe| cqe.information = 1,
    ];
    for mutate in mutations {
        let mut cqe = protocol_cqe(abort_record(0x0123_4567_89ab_cdef));
        mutate(&mut cqe);
        assert_eq!(validate_protocol_abort_v1(&cqe), None);
    }
}

#[test]
fn every_noncanonical_protocol_record_field_is_rejected() {
    let mutations: [fn(&mut ProtocolAbortV1); 8] = [
        |record| record.header.struct_size = 23,
        |record| record.header.struct_size = 25,
        |record| record.header.struct_version = 0,
        |record| record.header.struct_version = 2,
        |record| record.header.required_flags = 1,
        |record| record.reason = 0,
        |record| record.reason = 2,
        |record| record.reserved = 1,
    ];
    for mutate in mutations {
        let mut record = abort_record(0xfedc_ba98_7654_3210);
        mutate(&mut record);
        assert_eq!(validate_protocol_abort_v1(&protocol_cqe(record)), None);
    }
}

fn v1_result_header(size: u32) -> ControlHeader {
    ControlHeader {
        struct_size: size,
        struct_version: CONTROL_VERSION_V1,
        required_flags: 0,
    }
}

fn canonical_result_sizes() -> SizeState {
    SizeState {
        allocation_size: 4_096,
        file_size: 200,
        valid_data_length: 104,
        size_epoch: 8,
    }
}

fn echo_output(grant: &GrantMetadata, length: u32) -> OControl {
    let mut body = grant.issued;
    body.length = length;
    OControl { body }
}

fn shrunk_reference(grant: &GrantMetadata, length: u32) -> BufferRef {
    let mut reference = grant.issued;
    reference.length = length;
    reference
}

fn canonical_prepare_result(security_descriptor: BufferRef) -> PrepareOpenResultV1 {
    PrepareOpenResultV1 {
        header: v1_result_header(136),
        transaction_id: TransactionId { lo: 21, hi: 22 },
        file_id: FileId { lo: 23, hi: 24 },
        link_id: LinkId { lo: 25, hi: 26 },
        security_descriptor,
        sizes: canonical_result_sizes(),
        namespace_generation: 27,
        security_generation: 28,
        object_flags: 0,
        reserved: 0,
    }
}

fn canonical_commit_result() -> CommitOpenResultV2 {
    CommitOpenResultV2 {
        header: control_header(112),
        provider_open_cookie: 31,
        file_id: FileId { lo: 32, hi: 33 },
        link_id: LinkId { lo: 34, hi: 35 },
        sizes: canonical_result_sizes(),
        namespace_generation: 36,
        security_generation: 37,
        create_result: 0,
        result_flags: 0,
        volume_commit_sequence: 38,
    }
}

fn canonical_write_result() -> WriteResultV2 {
    WriteResultV2 {
        header: control_header(56),
        sizes: canonical_result_sizes(),
        volume_commit_sequence: 41,
        flags: 0,
        reserved: 0,
    }
}

fn canonical_replay_result() -> ReplayOpenResultV1 {
    ReplayOpenResultV1 {
        header: v1_result_header(16),
        provider_open_cookie: 51,
    }
}

#[test]
fn rw_success_information_boundaries_are_closed() {
    let read_data = mapping_grant(2_001, buffer_access::U2K_WRITE, 4);
    let read = canonical_read(read_data.issued);
    let request_length = read.length;
    for information in [1, u64::from(request_length)] {
        let read_output = echo_output(&read_data, information as u32);
        assert_eq!(
            validated_length(
                validate_read_success_v21(&read, binding(&read_data), &read_output, information)
                    .unwrap()
                    .data()
            ),
            information
        );
    }
    let read_output = echo_output(&read_data, request_length);
    for information in [0, u64::from(request_length) + 1, u64::MAX] {
        assert_eq!(
            validate_read_success_v21(&read, binding(&read_data), &read_output, information),
            Err(MessageValidationError::Completion)
        );
    }
    let short_echo = echo_output(&read_data, 1);
    assert_eq!(
        validate_read_success_v21(&read, binding(&read_data), &short_echo, 2),
        Err(MessageValidationError::Completion)
    );
    let mut reserved_defect = read;
    reserved_defect.reserved = 1;
    assert_eq!(
        validate_read_success_v21(
            &reserved_defect,
            binding(&read_data),
            &echo_output(&read_data, 4),
            4
        ),
        Err(MessageValidationError::FlagsOrReserved)
    );

    let write_data = mapping_grant(2_002, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(2_003, buffer_access::U2K_WRITE, 56);
    let write = canonical_write(write_data.issued, write_reply.issued);
    let write_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    let write_output = echo_output(&write_reply, 56);
    for information in [1, u64::from(write.length)] {
        assert_eq!(
            validated_length(
                validate_write_success_v2(
                    &write,
                    &write_context,
                    &write_output,
                    information,
                    &canonical_write_result(),
                )
                .unwrap()
                .reply()
            ),
            56
        );
    }
    for information in [0, u64::from(write.length) + 1, u64::MAX] {
        assert_eq!(
            validate_write_success_v2(
                &write,
                &write_context,
                &write_output,
                information,
                &canonical_write_result(),
            ),
            Err(MessageValidationError::Completion)
        );
    }
    let mut version_defect = write;
    version_defect.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_write_success_v2(
            &version_defect,
            &write_context,
            &write_output,
            4,
            &canonical_write_result(),
        ),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
}

#[test]
fn rw_success_output_echoes_keep_exact_causes() {
    let read_data = mapping_grant(2_011, buffer_access::U2K_WRITE, 4);
    let read = canonical_read(read_data.issued);
    let mut wrong_token = echo_output(&read_data, 4);
    wrong_token.body.token ^= 1;
    assert_eq!(
        validate_read_success_v21(&read, binding(&read_data), &wrong_token, 4),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );

    let write_data = mapping_grant(2_012, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(2_013, buffer_access::U2K_WRITE, 56);
    let write = canonical_write(write_data.issued, write_reply.issued);
    let write_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    let result = canonical_write_result();
    let mutations: [MutationRow<BufferRef, MessageValidationError>; 6] = [
        (
            |body| body.token ^= 1,
            MessageValidationError::Grant(BufferRefError::CapabilityMismatch),
        ),
        (
            |body| body.kind = buffer_kind::SLOT,
            MessageValidationError::Grant(BufferRefError::KindMismatch),
        ),
        (
            |body| body.access = buffer_access::K2U_READ_ONLY,
            MessageValidationError::Grant(BufferRefError::AccessMismatch),
        ),
        (
            |body| body.offset = 1,
            MessageValidationError::Grant(BufferRefError::RangeOutOfBounds),
        ),
        (|body| body.length = 55, MessageValidationError::Completion),
        (
            |body| body.length = 57,
            MessageValidationError::Grant(BufferRefError::RangeOutOfBounds),
        ),
    ];
    for (mutate, expected) in mutations {
        let mut output = echo_output(&write_reply, 56);
        mutate(&mut output.body);
        assert_eq!(
            validate_write_success_v2(&write, &write_context, &output, 4, &result),
            Err(expected)
        );
    }

    let mut roomy_reply = mapping_grant(2_014, buffer_access::U2K_WRITE, 60);
    roomy_reply.issued.length = 56;
    let roomy_write = canonical_write(write_data.issued, roomy_reply.issued);
    let roomy_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&roomy_reply),
    };
    assert!(validate_write_success_v2(
        &roomy_write,
        &roomy_context,
        &echo_output(&roomy_reply, 56),
        4,
        &result,
    )
    .is_ok());
    assert_eq!(
        validate_write_success_v2(
            &roomy_write,
            &roomy_context,
            &echo_output(&roomy_reply, 57),
            4,
            &result,
        ),
        Err(MessageValidationError::Grant(BufferRefError::LengthGrowth))
    );
}

#[test]
fn write_result_scalars_sizes_and_coverage_are_closed() {
    let write_data = mapping_grant(2_021, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(2_022, buffer_access::U2K_WRITE, 56);
    let write = canonical_write(write_data.issued, write_reply.issued);
    let context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    let output = echo_output(&write_reply, 56);

    let mutations: [MutationRow<WriteResultV2, MessageValidationError>; 8] = [
        (
            |result| result.header.struct_version = CONTROL_VERSION_V1,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |result| result.header.struct_size = 55,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |result| result.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
        (
            |result| result.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |result| result.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |result| result.volume_commit_sequence = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |result| result.sizes.size_epoch = 0,
            MessageValidationError::SizeState,
        ),
        (
            |result| result.sizes.file_size = 4_097,
            MessageValidationError::Relationship,
        ),
    ];
    for (mutate, expected) in mutations {
        let mut result = canonical_write_result();
        mutate(&mut result);
        assert_eq!(
            validate_write_success_v2(&write, &context, &output, 4, &result),
            Err(expected)
        );
    }

    let mut uncovered_vdl = canonical_write_result();
    uncovered_vdl.sizes.valid_data_length = 103;
    assert_eq!(
        validate_write_success_v2(&write, &context, &output, 4, &uncovered_vdl),
        Err(MessageValidationError::Relationship)
    );
    let mut uncovered_eof = canonical_write_result();
    uncovered_eof.sizes.file_size = 103;
    uncovered_eof.sizes.valid_data_length = 103;
    assert_eq!(
        validate_write_success_v2(&write, &context, &output, 4, &uncovered_eof),
        Err(MessageValidationError::Relationship)
    );
    let mut exact_cover = canonical_write_result();
    exact_cover.sizes.file_size = 104;
    exact_cover.sizes.valid_data_length = 104;
    assert!(validate_write_success_v2(&write, &context, &output, 4, &exact_cover).is_ok());
}

#[test]
fn prepare_success_echo_result_and_sd_shrink_are_exact() {
    let name = mapping_grant(2_031, buffer_access::K2U_READ_ONLY, 10);
    let requested_sd = mapping_grant(2_032, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(2_033, buffer_access::K2U_READ_ONLY, 1);
    let reply = mapping_grant(2_034, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(2_035, buffer_access::U2K_WRITE, 65_536);
    let request = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        reply.issued,
        result_sd.issued,
    );
    let context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: Some(binding(&requested_sd)),
        extended_attributes: Some(binding(&ea)),
        reply: binding(&reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: Some(20),
        validated_ea_length: Some(1),
    };
    let output = echo_output(&reply, 136);

    let proof = validate_prepare_open_success_v21(
        &request,
        &context,
        &output,
        &canonical_prepare_result(shrunk_reference(&result_sd, 64)),
    )
    .unwrap();
    assert_eq!(validated_length(proof.reply()), 136);
    assert_eq!(validated_length(proof.security_descriptor()), 64);

    for length in [20, 65_536] {
        assert!(validate_prepare_open_success_v21(
            &request,
            &context,
            &output,
            &canonical_prepare_result(shrunk_reference(&result_sd, length)),
        )
        .is_ok());
    }
    for length in [19, 65_537] {
        assert_eq!(
            validate_prepare_open_success_v21(
                &request,
                &context,
                &output,
                &canonical_prepare_result(shrunk_reference(&result_sd, length)),
            ),
            Err(MessageValidationError::InvalidScalar)
        );
    }

    assert_eq!(
        validate_prepare_open_success_v21(
            &request,
            &context,
            &echo_output(&reply, 135),
            &canonical_prepare_result(shrunk_reference(&result_sd, 64)),
        ),
        Err(MessageValidationError::Completion)
    );
    assert_eq!(
        validate_prepare_open_success_v21(
            &request,
            &context,
            &echo_output(&reply, 137),
            &canonical_prepare_result(shrunk_reference(&result_sd, 64)),
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::RangeOutOfBounds
        ))
    );

    let result_mutations: [MutationRow<PrepareOpenResultV1, MessageValidationError>; 6] = [
        (
            |result| result.header.struct_version = CONTROL_VERSION_V2,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |result| result.header.struct_size = 135,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |result| result.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
        (
            |result| result.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |result| result.transaction_id = TransactionId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |result| result.sizes.size_epoch = 0,
            MessageValidationError::SizeState,
        ),
    ];
    for (mutate, expected) in result_mutations {
        let mut result = canonical_prepare_result(shrunk_reference(&result_sd, 64));
        mutate(&mut result);
        assert_eq!(
            validate_prepare_open_success_v21(&request, &context, &output, &result),
            Err(expected)
        );
    }

    let mut sd_wrong_token = shrunk_reference(&result_sd, 64);
    sd_wrong_token.token ^= 1;
    assert_eq!(
        validate_prepare_open_success_v21(
            &request,
            &context,
            &output,
            &canonical_prepare_result(sd_wrong_token),
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
    let mut sd_moved = shrunk_reference(&result_sd, 64);
    sd_moved.offset = 1;
    assert_eq!(
        validate_prepare_open_success_v21(
            &request,
            &context,
            &output,
            &canonical_prepare_result(sd_moved),
        ),
        Err(MessageValidationError::Grant(BufferRefError::EchoMismatch))
    );

    let mut version_defect = request;
    version_defect.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_prepare_open_success_v21(
            &version_defect,
            &context,
            &output,
            &canonical_prepare_result(shrunk_reference(&result_sd, 64)),
        ),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
}

#[test]
fn commit_success_echo_and_result_scalars_are_exact() {
    let reply = mapping_grant(2_041, buffer_access::U2K_WRITE, 112);
    let request = canonical_commit(reply.issued);
    let output = echo_output(&reply, 112);

    let proof = validate_commit_open_success_v2(
        &request,
        binding(&reply),
        &output,
        &canonical_commit_result(),
    )
    .unwrap();
    assert_eq!(validated_length(proof.reply()), 112);

    assert_eq!(
        validate_commit_open_success_v2(
            &request,
            binding(&reply),
            &echo_output(&reply, 111),
            &canonical_commit_result(),
        ),
        Err(MessageValidationError::Completion)
    );
    assert_eq!(
        validate_commit_open_success_v2(
            &request,
            binding(&reply),
            &echo_output(&reply, 113),
            &canonical_commit_result(),
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::RangeOutOfBounds
        ))
    );

    let mutations: [MutationRow<CommitOpenResultV2, MessageValidationError>; 7] = [
        (
            |result| result.header.struct_version = CONTROL_VERSION_V1,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |result| result.header.struct_size = 111,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |result| result.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
        (
            |result| result.provider_open_cookie = 0,
            MessageValidationError::Identity,
        ),
        (
            |result| result.volume_commit_sequence = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |result| result.sizes.size_epoch = 0,
            MessageValidationError::SizeState,
        ),
        (
            |result| result.sizes.valid_data_length = 201,
            MessageValidationError::Relationship,
        ),
    ];
    for (mutate, expected) in mutations {
        let mut result = canonical_commit_result();
        mutate(&mut result);
        assert_eq!(
            validate_commit_open_success_v2(&request, binding(&reply), &output, &result),
            Err(expected)
        );
    }

    let mut version_defect = request;
    version_defect.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_commit_open_success_v2(
            &version_defect,
            binding(&reply),
            &output,
            &canonical_commit_result(),
        ),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
}

#[test]
fn replay_success_echo_and_cookie_are_exact() {
    let reply = mapping_grant(2_051, buffer_access::U2K_WRITE, 16);
    let request = canonical_replay(reply.issued);
    let output = echo_output(&reply, 16);

    let proof = validate_replay_open_success_v21(
        &request,
        binding(&reply),
        &output,
        &canonical_replay_result(),
    )
    .unwrap();
    assert_eq!(validated_length(proof.reply()), 16);

    assert_eq!(
        validate_replay_open_success_v21(
            &request,
            binding(&reply),
            &echo_output(&reply, 15),
            &canonical_replay_result(),
        ),
        Err(MessageValidationError::Completion)
    );
    assert_eq!(
        validate_replay_open_success_v21(
            &request,
            binding(&reply),
            &echo_output(&reply, 17),
            &canonical_replay_result(),
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::RangeOutOfBounds
        ))
    );

    let mutations: [MutationRow<ReplayOpenResultV1, MessageValidationError>; 4] = [
        (
            |result| result.header.struct_version = CONTROL_VERSION_V2,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |result| result.header.struct_size = 15,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |result| result.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
        (
            |result| result.provider_open_cookie = 0,
            MessageValidationError::Identity,
        ),
    ];
    for (mutate, expected) in mutations {
        let mut result = canonical_replay_result();
        mutate(&mut result);
        assert_eq!(
            validate_replay_open_success_v21(&request, binding(&reply), &output, &result),
            Err(expected)
        );
    }

    let mut version_defect = request;
    version_defect.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_replay_open_success_v21(
            &version_defect,
            binding(&reply),
            &output,
            &canonical_replay_result(),
        ),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
}

#[test]
fn create_phases_reuse_one_slot_with_fresh_generations() {
    let op_id = OpId { lo: 1, hi: 2 };
    let tx = TransactionId { lo: 3, hi: 4 };
    let expectation = CreatePhaseExpectationV21 {
        op_id,
        transaction_id: Some(tx),
        slot_index: 0,
        max_inflight: 1,
        prior_generation: Some(7),
    };
    let cases = [
        (CreatePhaseV21::Prepare, Some(op_id), None),
        (CreatePhaseV21::Commit, Some(op_id), Some(tx)),
        (CreatePhaseV21::AbortOpen, None, Some(tx)),
        (CreatePhaseV21::QueryOp, Some(op_id), None),
        (CreatePhaseV21::AckResult, Some(op_id), None),
    ];
    for (phase, phase_op_id, transaction_id) in cases {
        let candidate = CreatePhaseCandidateV21 {
            phase,
            req_id: ReqId::try_new(8, 0).unwrap(),
            op_id: phase_op_id,
            transaction_id,
        };
        let proof = validate_create_phase_identity_v21(&expectation, &candidate).unwrap();
        assert_eq!(proof.phase(), phase);
        assert_eq!(proof.req_id(), candidate.req_id);
    }
}

#[test]
fn create_phase_identity_rejections_are_closed() {
    let op_id = OpId { lo: 1, hi: 2 };
    let tx = TransactionId { lo: 3, hi: 4 };
    let expectation = CreatePhaseExpectationV21 {
        op_id,
        transaction_id: Some(tx),
        slot_index: 0,
        max_inflight: 1,
        prior_generation: Some(7),
    };
    let commit_candidate = CreatePhaseCandidateV21 {
        phase: CreatePhaseV21::Commit,
        req_id: ReqId::try_new(8, 0).unwrap(),
        op_id: Some(op_id),
        transaction_id: Some(tx),
    };
    assert!(validate_create_phase_identity_v21(&expectation, &commit_candidate).is_ok());

    let first_expectation = CreatePhaseExpectationV21 {
        op_id,
        transaction_id: None,
        slot_index: 0,
        max_inflight: 1,
        prior_generation: None,
    };
    let first_prepare = CreatePhaseCandidateV21 {
        phase: CreatePhaseV21::Prepare,
        req_id: ReqId::try_new(1, 0).unwrap(),
        op_id: Some(op_id),
        transaction_id: None,
    };
    assert!(validate_create_phase_identity_v21(&first_expectation, &first_prepare).is_ok());

    let expectation_rows: [fn(&mut CreatePhaseExpectationV21); 6] = [
        |expectation| expectation.max_inflight = 0,
        |expectation| expectation.max_inflight = MAX_INFLIGHT + 1,
        |expectation| expectation.slot_index = 1,
        |expectation| expectation.op_id = OpId::ZERO,
        |expectation| expectation.prior_generation = Some(0),
        |expectation| expectation.transaction_id = Some(TransactionId { lo: 0, hi: 0 }),
    ];
    for mutate in expectation_rows {
        let mut defective = expectation;
        mutate(&mut defective);
        assert_eq!(
            validate_create_phase_identity_v21(&defective, &commit_candidate),
            Err(MessageValidationError::Identity)
        );
    }

    let candidate_rows: [fn(&mut CreatePhaseCandidateV21); 7] = [
        |candidate| candidate.req_id = ReqId::try_new(0, 0).unwrap(),
        |candidate| candidate.req_id = ReqId::try_new(8, 1).unwrap(),
        |candidate| candidate.req_id = ReqId::try_new(7, 0).unwrap(),
        |candidate| candidate.op_id = Some(OpId { lo: 9, hi: 9 }),
        |candidate| candidate.op_id = None,
        |candidate| candidate.transaction_id = None,
        |candidate| candidate.transaction_id = Some(TransactionId { lo: 9, hi: 9 }),
    ];
    for mutate in candidate_rows {
        let mut defective = commit_candidate;
        mutate(&mut defective);
        assert_eq!(
            validate_create_phase_identity_v21(&expectation, &defective),
            Err(MessageValidationError::Identity)
        );
    }

    let abort = CreatePhaseCandidateV21 {
        phase: CreatePhaseV21::AbortOpen,
        req_id: ReqId::try_new(9, 0).unwrap(),
        op_id: None,
        transaction_id: Some(tx),
    };
    assert!(validate_create_phase_identity_v21(&expectation, &abort).is_ok());

    let abort_with_op = CreatePhaseCandidateV21 {
        op_id: Some(op_id),
        ..abort
    };
    assert_eq!(
        validate_create_phase_identity_v21(&expectation, &abort_with_op),
        Err(MessageValidationError::Identity)
    );
    let prepare_with_tx = CreatePhaseCandidateV21 {
        phase: CreatePhaseV21::Prepare,
        req_id: ReqId::try_new(8, 0).unwrap(),
        op_id: Some(op_id),
        transaction_id: Some(tx),
    };
    assert_eq!(
        validate_create_phase_identity_v21(&expectation, &prepare_with_tx),
        Err(MessageValidationError::Identity)
    );
    let query_with_tx = CreatePhaseCandidateV21 {
        phase: CreatePhaseV21::QueryOp,
        req_id: ReqId::try_new(8, 0).unwrap(),
        op_id: Some(op_id),
        transaction_id: Some(tx),
    };
    assert_eq!(
        validate_create_phase_identity_v21(&expectation, &query_with_tx),
        Err(MessageValidationError::Identity)
    );
    let abort_missing_tx = CreatePhaseCandidateV21 {
        transaction_id: None,
        ..abort
    };
    assert_eq!(
        validate_create_phase_identity_v21(&expectation, &abort_missing_tx),
        Err(MessageValidationError::Identity)
    );
}

fn put_blob(out: &mut [u8], offset: usize, value: BlobSlice) {
    put_u32(out, offset, value.offset);
    put_u32(out, offset + 4, value.length);
}

fn sentinel_blob(seed: u32) -> BlobSlice {
    BlobSlice {
        offset: seed,
        length: seed ^ 0xffff_ffff,
    }
}

#[test]
fn wave7a_registries_and_limits_are_closed_and_literal() {
    assert_eq!(MAX_COMPONENT_UTF16_CODE_UNITS, 255);
    assert_eq!(MIN_SECURITY_DESCRIPTOR_BYTES, 20);
    assert_eq!(MAX_SECURITY_DESCRIPTOR_BYTES, 65_536);
    assert_eq!(MAX_REPARSE_DATA_BYTES, 16_384);
    assert_eq!(MAX_CONTROL_BLOB, 16_777_216);
    assert_eq!(MAX_CANONICAL_DIR_ENTRY_BYTES, 648);

    assert_eq!(file_attributes::READONLY, 0x0000_0001);
    assert_eq!(file_attributes::HIDDEN, 0x0000_0002);
    assert_eq!(file_attributes::SYSTEM, 0x0000_0004);
    assert_eq!(file_attributes::DIRECTORY, 0x0000_0010);
    assert_eq!(file_attributes::ARCHIVE, 0x0000_0020);
    assert_eq!(file_attributes::NORMAL, 0x0000_0080);
    assert_eq!(file_attributes::TEMPORARY, 0x0000_0100);
    assert_eq!(file_attributes::SPARSE_FILE, 0x0000_0200);
    assert_eq!(file_attributes::REPARSE_POINT, 0x0000_0400);
    assert_eq!(file_attributes::COMPRESSED, 0x0000_0800);
    assert_eq!(file_attributes::OFFLINE, 0x0000_1000);
    assert_eq!(file_attributes::NOT_CONTENT_INDEXED, 0x0000_2000);
    assert_eq!(file_attributes::ENCRYPTED, 0x0000_4000);
    assert_eq!(file_attributes::REGISTRY_MASK, 0x0000_7fb7);
    assert_eq!(file_attributes::ACCEPTED_MASK_V21, 0x0000_7bb7);
    assert_eq!(file_attributes::SETTABLE_BASIC_MASK, 0x0000_31a7);
    assert_eq!(
        file_attributes::REGISTRY_MASK & !file_attributes::REPARSE_POINT,
        file_attributes::ACCEPTED_MASK_V21
    );

    assert_eq!(create_result::SUPERSEDED, 0);
    assert_eq!(create_result::OPENED, 1);
    assert_eq!(create_result::CREATED, 2);
    assert_eq!(create_result::OVERWRITTEN, 3);
    assert_eq!(create_result::EXISTS, 4);
    assert_eq!(create_result::DOES_NOT_EXIST, 5);

    assert_eq!(query_op_state::INVALID, 0);
    assert_eq!(query_op_state::NOT_FOUND, 1);
    assert_eq!(query_op_state::PREPARED, 2);
    assert_eq!(query_op_state::COMMITTED, 3);
    assert_eq!(journal_version::NONE, 0);
    assert_eq!(journal_version::V1, 1);
    assert_eq!(query_op_required_flags::ABORT_IF_PREPARED, 0x0001);

    assert_eq!(mutation_kind::INVALID, 0);
    assert_eq!(mutation_kind::SET_BASIC_INFO, 1);
    assert_eq!(mutation_kind::SET_ALLOCATION_SIZE, 2);
    assert_eq!(mutation_kind::SET_END_OF_FILE, 3);
    assert_eq!(mutation_kind::SET_VALID_DATA_LENGTH, 4);
    assert_eq!(mutation_kind::RENAME, 5);
    assert_eq!(mutation_kind::LINK, 6);
    assert_eq!(mutation_kind::UNLINK, 7);
    assert_eq!(mutation_kind::SET_SECURITY, 8);
    assert_eq!(mutation_kind::SET_REPARSE, 9);
    assert_eq!(mutation_kind::DELETE_REPARSE, 10);
    assert_eq!(mutation_kind::SET_SPARSE, 11);

    assert_eq!(basic_info_set_mask::CREATION_TIME, 0x0000_0001);
    assert_eq!(basic_info_set_mask::LAST_ACCESS_TIME, 0x0000_0002);
    assert_eq!(basic_info_set_mask::LAST_WRITE_TIME, 0x0000_0004);
    assert_eq!(basic_info_set_mask::CHANGE_TIME, 0x0000_0008);
    assert_eq!(basic_info_set_mask::FILE_ATTRIBUTES, 0x0000_0010);
    assert_eq!(basic_info_set_mask::ALL, 0x0000_001f);
    assert_eq!(rename_flags::REPLACE_IF_EXISTS, 0x0000_0001);
    assert_eq!(link_flags::REPLACE_IF_EXISTS, 0x0000_0001);

    assert_eq!(security_information::OWNER, 0x0000_0001);
    assert_eq!(security_information::GROUP, 0x0000_0002);
    assert_eq!(security_information::DACL, 0x0000_0004);
    assert_eq!(security_information::SACL, 0x0000_0008);
    assert_eq!(security_information::LABEL, 0x0000_0010);
    assert_eq!(security_information::ATTRIBUTE, 0x0000_0020);
    assert_eq!(security_information::SCOPE, 0x0000_0040);
    assert_eq!(security_information::BACKUP, 0x0001_0000);
    assert_eq!(security_information::UNPROTECTED_SACL, 0x1000_0000);
    assert_eq!(security_information::UNPROTECTED_DACL, 0x2000_0000);
    assert_eq!(security_information::PROTECTED_SACL, 0x4000_0000);
    assert_eq!(security_information::PROTECTED_DACL, 0x8000_0000);
    assert_eq!(security_information::SET_MASK, 0xf001_007f);
    assert_eq!(security_information::QUERY_ACCEPTED_MASK, 0x0000_000f);
    assert_eq!(
        security_information::OWNER
            | security_information::GROUP
            | security_information::DACL
            | security_information::SACL,
        security_information::QUERY_ACCEPTED_MASK
    );
}

#[test]
fn wave7a_mutation_layouts_are_exact_and_gapless() {
    assert_wire_layout!(SetBasicInfoV1, 48, 8;
        header: ControlHeader => 0, creation_time: i64 => 8,
        last_access_time: i64 => 16, last_write_time: i64 => 24,
        change_time: i64 => 32, attributes: u32 => 40, set_mask: u32 => 44,
    );
    assert_wire_layout!(SetSizeV1, 24, 8;
        header: ControlHeader => 0, new_size: u64 => 8, flags: u32 => 16,
        reserved: u32 => 20,
    );
    assert_wire_layout!(RenameV1, 72, 8;
        header: ControlHeader => 0, source_link_id: LinkId => 8,
        target_parent_id: FileId => 24,
        expected_source_parent_generation: u64 => 40,
        expected_target_parent_generation: u64 => 48, name: BlobSlice => 56,
        flags: u32 => 64, reserved: u32 => 68,
    );
    assert_wire_layout!(LinkV1, 64, 8;
        header: ControlHeader => 0, source_file_id: FileId => 8,
        target_parent_id: FileId => 24,
        expected_target_parent_generation: u64 => 40, name: BlobSlice => 48,
        flags: u32 => 56, reserved: u32 => 60,
    );
    assert_wire_layout!(UnlinkV1, 56, 8;
        header: ControlHeader => 0, link_id: LinkId => 8,
        parent_id: FileId => 24, expected_parent_generation: u64 => 40,
        flags: u32 => 48, reserved: u32 => 52,
    );
    assert_wire_layout!(SetSecurityV1, 24, 4;
        header: ControlHeader => 0, security_information: u32 => 8,
        flags: u32 => 12, security_descriptor: BlobSlice => 16,
    );
    assert_wire_layout!(SetReparseV1, 24, 4;
        header: ControlHeader => 0, tag: u32 => 8, flags: u32 => 12,
        reparse_data: BlobSlice => 16,
    );
    assert_wire_layout!(DeleteReparseV1, 16, 4;
        header: ControlHeader => 0, tag: u32 => 8, flags: u32 => 12,
    );
    assert_wire_layout!(SetSparseV1, 16, 4;
        header: ControlHeader => 0, sparse: u32 => 8, flags: u32 => 12,
    );
    assert_wire_layout!(MutationV2, 128, 8;
        header: ControlHeader => 0, op_id: OpId => 8, mutation_kind: u16 => 24,
        mutation_flags: u16 => 26, reserved: u32 => 28,
        expected_namespace_generation: u64 => 32, expected_size_epoch: u64 => 40,
        expected_security_generation: u64 => 48, body: BufferRef => 56,
        reply: BufferRef => 80, kind_result: BufferRef => 104,
    );
    assert_wire_layout!(MutationResultV2, 112, 8;
        header: ControlHeader => 0, op_id: OpId => 8,
        volume_commit_sequence: u64 => 24, mutation_kind: u16 => 32,
        result_flags: u16 => 34, reserved: u32 => 36, sizes: SizeState => 40,
        namespace_generation: u64 => 72, security_generation: u64 => 80,
        kind_result: BufferRef => 88,
    );
    assert_wire_layout!(RenameResultV2, 112, 8;
        header: ControlHeader => 0, file_id: FileId => 8, link_id: LinkId => 24,
        replaced_file_id: FileId => 40, replaced_link_id: LinkId => 56,
        source_parent_generation: u64 => 72, target_parent_generation: u64 => 80,
        replaced_namespace_generation: u64 => 88, link_count: u32 => 96,
        replaced_link_count: u32 => 100, flags: u32 => 104, reserved: u32 => 108,
    );
    assert_wire_layout!(LinkResultV2, 104, 8;
        header: ControlHeader => 0, file_id: FileId => 8,
        new_link_id: LinkId => 24, replaced_file_id: FileId => 40,
        replaced_link_id: LinkId => 56, target_parent_generation: u64 => 72,
        replaced_namespace_generation: u64 => 80, link_count: u32 => 88,
        replaced_link_count: u32 => 92, flags: u32 => 96, reserved: u32 => 100,
    );
    assert_wire_layout!(UnlinkResultV1, 56, 8;
        header: ControlHeader => 0, file_id: FileId => 8,
        removed_link_id: LinkId => 24, parent_generation: u64 => 40,
        remaining_link_count: u32 => 48, flags: u32 => 52,
    );
}

#[test]
fn wave7a_mutation_family_has_complete_literal_little_endian_images() {
    let mutation = MutationV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0x1112_1314_1516_1718),
        mutation_kind: 0x2122,
        mutation_flags: 0x3132,
        reserved: 0x4142_4344,
        expected_namespace_generation: 0x5152_5354_5556_5758,
        expected_size_epoch: 0x6162_6364_6566_6768,
        expected_security_generation: 0x7172_7374_7576_7778,
        body: sentinel_buffer(0x8182_8384_8586_8788),
        reply: sentinel_buffer(0x9192_9394_9596_9798),
        kind_result: sentinel_buffer(0xa1a2_a3a4_a5a6_a7a8),
    };
    let bytes: [u8; 128] = encode_exact(&mutation);
    let mut expected = [0u8; 128];
    put_header(&mut expected, 0, mutation.header);
    put_pair(&mut expected, 8, mutation.op_id.lo, mutation.op_id.hi);
    put_u16(&mut expected, 24, mutation.mutation_kind);
    put_u16(&mut expected, 26, mutation.mutation_flags);
    put_u32(&mut expected, 28, mutation.reserved);
    put_u64(&mut expected, 32, mutation.expected_namespace_generation);
    put_u64(&mut expected, 40, mutation.expected_size_epoch);
    put_u64(&mut expected, 48, mutation.expected_security_generation);
    put_buffer(&mut expected, 56, mutation.body);
    put_buffer(&mut expected, 80, mutation.reply);
    put_buffer(&mut expected, 104, mutation.kind_result);
    assert_eq!(bytes, expected);

    let result = MutationResultV2 {
        header: sentinel_header(),
        op_id: sentinel_op(0xb1b2_b3b4_b5b6_b7b8),
        volume_commit_sequence: 0xc1c2_c3c4_c5c6_c7c8,
        mutation_kind: 0xd1d2,
        result_flags: 0xe1e2,
        reserved: 0xf1f2_f3f4,
        sizes: SizeState {
            allocation_size: 0x0102_0304_0506_0708,
            file_size: 0x1112_1314_1516_1718,
            valid_data_length: 0x2122_2324_2526_2728,
            size_epoch: 0x3132_3334_3536_3738,
        },
        namespace_generation: 0x4142_4344_4546_4748,
        security_generation: 0x5152_5354_5556_5758,
        kind_result: sentinel_buffer(0x6162_6364_6566_6768),
    };
    let bytes: [u8; 112] = encode_exact(&result);
    let mut expected = [0u8; 112];
    put_header(&mut expected, 0, result.header);
    put_pair(&mut expected, 8, result.op_id.lo, result.op_id.hi);
    put_u64(&mut expected, 24, result.volume_commit_sequence);
    put_u16(&mut expected, 32, result.mutation_kind);
    put_u16(&mut expected, 34, result.result_flags);
    put_u32(&mut expected, 36, result.reserved);
    put_sizes(&mut expected, 40, result.sizes);
    put_u64(&mut expected, 72, result.namespace_generation);
    put_u64(&mut expected, 80, result.security_generation);
    put_buffer(&mut expected, 88, result.kind_result);
    assert_eq!(bytes, expected);

    let basic = SetBasicInfoV1 {
        header: sentinel_header(),
        creation_time: 0x0102_0304_0506_0708,
        last_access_time: 0x1112_1314_1516_1718,
        last_write_time: 0x2122_2324_2526_2728,
        change_time: 0x3132_3334_3536_3738,
        attributes: 0x4142_4344,
        set_mask: 0x5152_5354,
    };
    let bytes: [u8; 48] = encode_exact(&basic);
    let mut expected = [0u8; 48];
    put_header(&mut expected, 0, basic.header);
    put_u64(&mut expected, 8, basic.creation_time as u64);
    put_u64(&mut expected, 16, basic.last_access_time as u64);
    put_u64(&mut expected, 24, basic.last_write_time as u64);
    put_u64(&mut expected, 32, basic.change_time as u64);
    put_u32(&mut expected, 40, basic.attributes);
    put_u32(&mut expected, 44, basic.set_mask);
    assert_eq!(bytes, expected);

    let rename = RenameV1 {
        header: sentinel_header(),
        source_link_id: sentinel_link(0x1112_1314_1516_1718),
        target_parent_id: sentinel_file(0x2122_2324_2526_2728),
        expected_source_parent_generation: 0x3132_3334_3536_3738,
        expected_target_parent_generation: 0x4142_4344_4546_4748,
        name: sentinel_blob(0x5152_5354),
        flags: 0x6162_6364,
        reserved: 0x7172_7374,
    };
    let bytes: [u8; 72] = encode_exact(&rename);
    let mut expected = [0u8; 72];
    put_header(&mut expected, 0, rename.header);
    put_pair(
        &mut expected,
        8,
        rename.source_link_id.lo,
        rename.source_link_id.hi,
    );
    put_pair(
        &mut expected,
        24,
        rename.target_parent_id.lo,
        rename.target_parent_id.hi,
    );
    put_u64(&mut expected, 40, rename.expected_source_parent_generation);
    put_u64(&mut expected, 48, rename.expected_target_parent_generation);
    put_blob(&mut expected, 56, rename.name);
    put_u32(&mut expected, 64, rename.flags);
    put_u32(&mut expected, 68, rename.reserved);
    assert_eq!(bytes, expected);

    let rename_result = RenameResultV2 {
        header: sentinel_header(),
        file_id: sentinel_file(0x1112_1314_1516_1718),
        link_id: sentinel_link(0x2122_2324_2526_2728),
        replaced_file_id: sentinel_file(0x3132_3334_3536_3738),
        replaced_link_id: sentinel_link(0x4142_4344_4546_4748),
        source_parent_generation: 0x5152_5354_5556_5758,
        target_parent_generation: 0x6162_6364_6566_6768,
        replaced_namespace_generation: 0x7172_7374_7576_7778,
        link_count: 0x8182_8384,
        replaced_link_count: 0x9192_9394,
        flags: 0xa1a2_a3a4,
        reserved: 0xb1b2_b3b4,
    };
    let bytes: [u8; 112] = encode_exact(&rename_result);
    let mut expected = [0u8; 112];
    put_header(&mut expected, 0, rename_result.header);
    put_pair(
        &mut expected,
        8,
        rename_result.file_id.lo,
        rename_result.file_id.hi,
    );
    put_pair(
        &mut expected,
        24,
        rename_result.link_id.lo,
        rename_result.link_id.hi,
    );
    put_pair(
        &mut expected,
        40,
        rename_result.replaced_file_id.lo,
        rename_result.replaced_file_id.hi,
    );
    put_pair(
        &mut expected,
        56,
        rename_result.replaced_link_id.lo,
        rename_result.replaced_link_id.hi,
    );
    put_u64(&mut expected, 72, rename_result.source_parent_generation);
    put_u64(&mut expected, 80, rename_result.target_parent_generation);
    put_u64(
        &mut expected,
        88,
        rename_result.replaced_namespace_generation,
    );
    put_u32(&mut expected, 96, rename_result.link_count);
    put_u32(&mut expected, 100, rename_result.replaced_link_count);
    put_u32(&mut expected, 104, rename_result.flags);
    put_u32(&mut expected, 108, rename_result.reserved);
    assert_eq!(bytes, expected);

    let link_result = LinkResultV2 {
        header: sentinel_header(),
        file_id: sentinel_file(0x1112_1314_1516_1718),
        new_link_id: sentinel_link(0x2122_2324_2526_2728),
        replaced_file_id: sentinel_file(0x3132_3334_3536_3738),
        replaced_link_id: sentinel_link(0x4142_4344_4546_4748),
        target_parent_generation: 0x5152_5354_5556_5758,
        replaced_namespace_generation: 0x6162_6364_6566_6768,
        link_count: 0x7172_7374,
        replaced_link_count: 0x8182_8384,
        flags: 0x9192_9394,
        reserved: 0xa1a2_a3a4,
    };
    let bytes: [u8; 104] = encode_exact(&link_result);
    let mut expected = [0u8; 104];
    put_header(&mut expected, 0, link_result.header);
    put_pair(
        &mut expected,
        8,
        link_result.file_id.lo,
        link_result.file_id.hi,
    );
    put_pair(
        &mut expected,
        24,
        link_result.new_link_id.lo,
        link_result.new_link_id.hi,
    );
    put_pair(
        &mut expected,
        40,
        link_result.replaced_file_id.lo,
        link_result.replaced_file_id.hi,
    );
    put_pair(
        &mut expected,
        56,
        link_result.replaced_link_id.lo,
        link_result.replaced_link_id.hi,
    );
    put_u64(&mut expected, 72, link_result.target_parent_generation);
    put_u64(&mut expected, 80, link_result.replaced_namespace_generation);
    put_u32(&mut expected, 88, link_result.link_count);
    put_u32(&mut expected, 92, link_result.replaced_link_count);
    put_u32(&mut expected, 96, link_result.flags);
    put_u32(&mut expected, 100, link_result.reserved);
    assert_eq!(bytes, expected);

    let unlink_result = UnlinkResultV1 {
        header: sentinel_header(),
        file_id: sentinel_file(0x1112_1314_1516_1718),
        removed_link_id: sentinel_link(0x2122_2324_2526_2728),
        parent_generation: 0x3132_3334_3536_3738,
        remaining_link_count: 0x4142_4344,
        flags: 0x5152_5354,
    };
    let bytes: [u8; 56] = encode_exact(&unlink_result);
    let mut expected = [0u8; 56];
    put_header(&mut expected, 0, unlink_result.header);
    put_pair(
        &mut expected,
        8,
        unlink_result.file_id.lo,
        unlink_result.file_id.hi,
    );
    put_pair(
        &mut expected,
        24,
        unlink_result.removed_link_id.lo,
        unlink_result.removed_link_id.hi,
    );
    put_u64(&mut expected, 40, unlink_result.parent_generation);
    put_u32(&mut expected, 48, unlink_result.remaining_link_count);
    put_u32(&mut expected, 52, unlink_result.flags);
    assert_eq!(bytes, expected);
}

#[test]
fn wave6_review_hardening_closes_uncovered_rejections() {
    let name = mapping_grant(3_001, buffer_access::K2U_READ_ONLY, 10);
    let requested_sd = mapping_grant(3_002, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(3_003, buffer_access::K2U_READ_ONLY, 1);
    let reply = mapping_grant(3_004, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(3_005, buffer_access::U2K_WRITE, 65_536);
    let request = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        reply.issued,
        result_sd.issued,
    );
    let context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: Some(binding(&requested_sd)),
        extended_attributes: Some(binding(&ea)),
        reply: binding(&reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: Some(20),
        validated_ea_length: Some(1),
    };
    assert!(validate_prepare_open_v2(&request, &context).is_ok());

    let mut zero_name = context;
    zero_name.validated_name_length = 0;
    assert_eq!(
        validate_prepare_open_v2(&request, &zero_name),
        Err(MessageValidationError::InvalidScalar)
    );

    let mut short_name = context;
    short_name.validated_name_length = 9;
    assert_eq!(
        validate_prepare_open_v2(&request, &short_name),
        Err(MessageValidationError::Relationship)
    );

    let mut absent_sd = context;
    absent_sd.requested_security_descriptor = None;
    absent_sd.validated_security_descriptor_length = None;
    assert_eq!(
        validate_prepare_open_v2(&request, &absent_sd),
        Err(MessageValidationError::Grant(BufferRefError::InvalidNone))
    );

    let mut absent_ea = context;
    absent_ea.extended_attributes = None;
    absent_ea.validated_ea_length = None;
    assert_eq!(
        validate_prepare_open_v2(&request, &absent_ea),
        Err(MessageValidationError::Grant(BufferRefError::InvalidNone))
    );

    for capacity in [65_535u32, 65_537] {
        let wrong_result_sd = mapping_grant(3_006, buffer_access::U2K_WRITE, capacity);
        let wrong_request = canonical_prepare(
            name.issued,
            requested_sd.issued,
            ea.issued,
            reply.issued,
            wrong_result_sd.issued,
        );
        let mut wrong_context = context;
        wrong_context.result_security_descriptor = binding(&wrong_result_sd);
        assert_eq!(
            validate_prepare_open_v2(&wrong_request, &wrong_context),
            Err(MessageValidationError::InvalidScalar),
            "result SD capacity={capacity}"
        );
    }

    let oversized_read_data = mapping_grant(3_007, buffer_access::U2K_WRITE, 5);
    let oversized_read = canonical_read(oversized_read_data.issued);
    assert_eq!(
        validate_read_v21(&oversized_read, binding(&oversized_read_data)),
        Err(MessageValidationError::Relationship)
    );

    let read_data = mapping_grant(3_008, buffer_access::U2K_WRITE, 4);
    let mut init_read = canonical_read(read_data.issued);
    init_read.initialized_offset = MAX_FILE_SIZE;
    assert_eq!(
        validate_read_v21(&init_read, binding(&read_data)),
        Err(MessageValidationError::Range(
            fsring_abi::RangeError::OffsetOutOfRange
        ))
    );

    let write_data = mapping_grant(3_009, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(3_010, buffer_access::U2K_WRITE, 56);
    let mut init_write = canonical_write(write_data.issued, write_reply.issued);
    init_write.initialized_offset = MAX_FILE_SIZE;
    assert_eq!(
        validate_write_v2(
            &init_write,
            &WriteV2Context {
                data: binding(&write_data),
                reply: binding(&write_reply),
            },
        ),
        Err(MessageValidationError::Range(
            fsring_abi::RangeError::OffsetOutOfRange
        ))
    );
}

#[test]
fn prepare_scalars_precede_optional_grant_binding() {
    let name = mapping_grant(3_041, buffer_access::K2U_READ_ONLY, 10);
    let requested_sd = mapping_grant(3_042, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(3_043, buffer_access::K2U_READ_ONLY, 1);
    let reply = mapping_grant(3_044, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(3_045, buffer_access::U2K_WRITE, 65_536);
    let context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: Some(binding(&requested_sd)),
        extended_attributes: Some(binding(&ea)),
        reply: binding(&reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: Some(20),
        validated_ea_length: Some(1),
    };

    let mut sd_grant_defect = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        reply.issued,
        result_sd.issued,
    );
    sd_grant_defect.requested_security_descriptor.token ^= 1;
    let mut ea_scalar_defect = context;
    ea_scalar_defect.validated_ea_length = Some(65_537);
    assert_eq!(
        validate_prepare_open_v2(&sd_grant_defect, &ea_scalar_defect),
        Err(MessageValidationError::InvalidScalar)
    );
}

#[test]
fn success_stage_precedence_is_information_echo_then_result() {
    let write_data = mapping_grant(3_021, buffer_access::K2U_READ_ONLY, 4);
    let write_reply = mapping_grant(3_022, buffer_access::U2K_WRITE, 56);
    let write = canonical_write(write_data.issued, write_reply.issued);
    let write_context = WriteV2Context {
        data: binding(&write_data),
        reply: binding(&write_reply),
    };
    let mut bad_write_echo = echo_output(&write_reply, 56);
    bad_write_echo.body.token ^= 1;
    assert_eq!(
        validate_write_success_v2(
            &write,
            &write_context,
            &bad_write_echo,
            0,
            &canonical_write_result(),
        ),
        Err(MessageValidationError::Completion)
    );
    let mut bad_write_result = canonical_write_result();
    bad_write_result.header.struct_version = CONTROL_VERSION_V1;
    bad_write_result.volume_commit_sequence = 0;
    assert_eq!(
        validate_write_success_v2(
            &write,
            &write_context,
            &bad_write_echo,
            4,
            &bad_write_result
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );

    let read_data = mapping_grant(3_023, buffer_access::U2K_WRITE, 4);
    let read = canonical_read(read_data.issued);
    let mut bad_read_echo = echo_output(&read_data, 4);
    bad_read_echo.body.token ^= 1;
    assert_eq!(
        validate_read_success_v21(&read, binding(&read_data), &bad_read_echo, 5),
        Err(MessageValidationError::Completion)
    );

    let name = mapping_grant(3_024, buffer_access::K2U_READ_ONLY, 10);
    let requested_sd = mapping_grant(3_025, buffer_access::K2U_READ_ONLY, 20);
    let ea = mapping_grant(3_026, buffer_access::K2U_READ_ONLY, 1);
    let prepare_reply = mapping_grant(3_027, buffer_access::U2K_WRITE, 136);
    let result_sd = mapping_grant(3_028, buffer_access::U2K_WRITE, 65_536);
    let prepare = canonical_prepare(
        name.issued,
        requested_sd.issued,
        ea.issued,
        prepare_reply.issued,
        result_sd.issued,
    );
    let prepare_context = PrepareOpenV2Context {
        name: binding(&name),
        requested_security_descriptor: Some(binding(&requested_sd)),
        extended_attributes: Some(binding(&ea)),
        reply: binding(&prepare_reply),
        result_security_descriptor: binding(&result_sd),
        validated_name_length: 10,
        validated_security_descriptor_length: Some(20),
        validated_ea_length: Some(1),
    };
    let mut zero_tx_result = canonical_prepare_result(shrunk_reference(&result_sd, 64));
    zero_tx_result.transaction_id = TransactionId { lo: 0, hi: 0 };
    assert_eq!(
        validate_prepare_open_success_v21(
            &prepare,
            &prepare_context,
            &echo_output(&prepare_reply, 135),
            &zero_tx_result,
        ),
        Err(MessageValidationError::Completion)
    );

    let commit_reply = mapping_grant(3_029, buffer_access::U2K_WRITE, 112);
    let commit = canonical_commit(commit_reply.issued);
    let mut zero_cookie_commit = canonical_commit_result();
    zero_cookie_commit.provider_open_cookie = 0;
    assert_eq!(
        validate_commit_open_success_v2(
            &commit,
            binding(&commit_reply),
            &echo_output(&commit_reply, 111),
            &zero_cookie_commit,
        ),
        Err(MessageValidationError::Completion)
    );

    let replay_reply = mapping_grant(3_030, buffer_access::U2K_WRITE, 16);
    let replay = canonical_replay(replay_reply.issued);
    let mut zero_cookie_replay = canonical_replay_result();
    zero_cookie_replay.provider_open_cookie = 0;
    assert_eq!(
        validate_replay_open_success_v21(
            &replay,
            binding(&replay_reply),
            &echo_output(&replay_reply, 15),
            &zero_cookie_replay,
        ),
        Err(MessageValidationError::Completion)
    );
}

fn v1_body_header(size: u32) -> ControlHeader {
    ControlHeader {
        struct_size: size,
        struct_version: 1,
        required_flags: 0,
    }
}

fn canonical_mutation(
    kind: u16,
    body: BufferRef,
    reply: BufferRef,
    kind_result: BufferRef,
) -> MutationV2 {
    let (namespace, epoch, security) = match kind {
        1 | 5 | 6 | 7 | 9 | 10 => (11, 0, 0),
        2..=4 => (0, 7, 0),
        8 => (0, 0, 13),
        _ => (0, 0, 0),
    };
    MutationV2 {
        header: control_header(128),
        op_id: OpId { lo: 1, hi: 2 },
        mutation_kind: kind,
        mutation_flags: 0,
        reserved: 0,
        expected_namespace_generation: namespace,
        expected_size_epoch: epoch,
        expected_security_generation: security,
        body,
        reply,
        kind_result,
    }
}

fn mutation_context<'a>(
    body: &'a GrantMetadata,
    reply: &'a GrantMetadata,
    kind_result: Option<&'a GrantMetadata>,
) -> MutationV2Context<'a> {
    MutationV2Context {
        body: binding(body),
        reply: binding(reply),
        kind_result: kind_result.map(binding),
        reparse_selected: false,
        same_parent_rename: false,
    }
}

fn body_blob<T: Pod>(record: &T, tail: &[u8]) -> Vec<u8> {
    let fixed = size_of::<T>();
    let unpadded = fixed + tail.len();
    let padded = unpadded.div_ceil(8) * 8;
    let mut out = vec![0u8; padded];
    assert_eq!(try_encode(record, &mut out[..fixed]).unwrap(), fixed);
    out[fixed..unpadded].copy_from_slice(tail);
    out
}

const NAME_AB: [u8; 4] = [0x61, 0x00, 0x62, 0x00];

fn canonical_basic_body() -> SetBasicInfoV1 {
    SetBasicInfoV1 {
        header: v1_body_header(48),
        creation_time: 100,
        last_access_time: 0,
        last_write_time: 200,
        change_time: 0,
        attributes: file_attributes::READONLY | file_attributes::ARCHIVE,
        set_mask: basic_info_set_mask::CREATION_TIME
            | basic_info_set_mask::LAST_WRITE_TIME
            | basic_info_set_mask::FILE_ATTRIBUTES,
    }
}

fn canonical_size_body() -> SetSizeV1 {
    SetSizeV1 {
        header: v1_body_header(24),
        new_size: 1_024,
        flags: 0,
        reserved: 0,
    }
}

fn canonical_rename_body() -> RenameV1 {
    RenameV1 {
        header: v1_body_header(80),
        source_link_id: LinkId { lo: 21, hi: 22 },
        target_parent_id: FileId { lo: 23, hi: 24 },
        expected_source_parent_generation: 31,
        expected_target_parent_generation: 32,
        name: BlobSlice {
            offset: 72,
            length: 4,
        },
        flags: 0,
        reserved: 0,
    }
}

fn canonical_link_body() -> LinkV1 {
    LinkV1 {
        header: v1_body_header(72),
        source_file_id: FileId { lo: 41, hi: 42 },
        target_parent_id: FileId { lo: 43, hi: 44 },
        expected_target_parent_generation: 45,
        name: BlobSlice {
            offset: 64,
            length: 4,
        },
        flags: 0,
        reserved: 0,
    }
}

fn canonical_unlink_body() -> UnlinkV1 {
    UnlinkV1 {
        header: v1_body_header(56),
        link_id: LinkId { lo: 51, hi: 52 },
        parent_id: FileId { lo: 53, hi: 54 },
        expected_parent_generation: 55,
        flags: 0,
        reserved: 0,
    }
}

fn canonical_security_body() -> SetSecurityV1 {
    SetSecurityV1 {
        header: v1_body_header(48),
        security_information: security_information::OWNER | security_information::DACL,
        flags: 0,
        security_descriptor: BlobSlice {
            offset: 24,
            length: 20,
        },
    }
}

#[test]
fn every_mutation_envelope_accepts_canonical_kinds() {
    let reply = mapping_grant(4_001, buffer_access::U2K_WRITE, 112);
    let rows: [(u16, u32, Option<u32>); 8] = [
        (mutation_kind::SET_BASIC_INFO, 48, None),
        (mutation_kind::SET_ALLOCATION_SIZE, 24, None),
        (mutation_kind::SET_END_OF_FILE, 24, None),
        (mutation_kind::SET_VALID_DATA_LENGTH, 24, None),
        (mutation_kind::RENAME, 80, Some(112)),
        (mutation_kind::LINK, 72, Some(104)),
        (mutation_kind::UNLINK, 56, Some(56)),
        (mutation_kind::SET_SECURITY, 48, None),
    ];
    for (kind, body_len, kind_result_len) in rows {
        let body = mapping_grant(
            4_100 + u64::from(kind),
            buffer_access::K2U_READ_ONLY,
            body_len,
        );
        let kind_result_grant = kind_result_len
            .map(|length| mapping_grant(4_200 + u64::from(kind), buffer_access::U2K_WRITE, length));
        let request = canonical_mutation(
            kind,
            body.issued,
            reply.issued,
            kind_result_grant
                .as_ref()
                .map(|grant| grant.issued)
                .unwrap_or_default(),
        );
        let context = mutation_context(&body, &reply, kind_result_grant.as_ref());
        let proof = validate_mutation_v2(&request, &context).unwrap();
        assert_eq!(validated_length(proof.body()), u64::from(body_len));
        assert_eq!(validated_length(proof.reply()), 112);
        assert_eq!(proof.kind_result().is_some(), kind_result_len.is_some());
    }

    let slot_body = slot_grant(SlotDirection::K2u, 48, 21);
    let slot_reply = slot_grant(SlotDirection::U2k, 112, 22);
    let request = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        slot_body.issued,
        slot_reply.issued,
        BufferRef::default(),
    );
    assert!(
        validate_mutation_v2(&request, &mutation_context(&slot_body, &slot_reply, None)).is_ok()
    );

    let reparse_body = mapping_grant(4_301, buffer_access::K2U_READ_ONLY, 32);
    let request = canonical_mutation(
        mutation_kind::SET_REPARSE,
        reparse_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    let mut context = mutation_context(&reparse_body, &reply, None);
    context.reparse_selected = true;
    assert!(validate_mutation_v2(&request, &context).is_ok());
    context.reparse_selected = false;
    assert_eq!(
        validate_mutation_v2(&request, &context),
        Err(MessageValidationError::InvalidScalar)
    );
    let delete_request = canonical_mutation(
        mutation_kind::DELETE_REPARSE,
        reparse_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    assert_eq!(
        validate_mutation_v2(&delete_request, &context),
        Err(MessageValidationError::InvalidScalar)
    );
}

#[test]
fn mutation_envelope_headers_kinds_and_expectations_are_closed() {
    let body = mapping_grant(4_401, buffer_access::K2U_READ_ONLY, 48);
    let reply = mapping_grant(4_402, buffer_access::U2K_WRITE, 112);
    let context = mutation_context(&body, &reply, None);
    let canonical = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        body.issued,
        reply.issued,
        BufferRef::default(),
    );

    let header_rows: [MutationRow<MutationV2, MessageValidationError>; 6] = [
        (
            |request| request.header.struct_version = CONTROL_VERSION_V1,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |request| request.header.struct_size = 127,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |request| request.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
        (
            |request| request.mutation_flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |request| request.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |request| request.op_id = OpId::ZERO,
            MessageValidationError::Identity,
        ),
    ];
    for (mutate, expected) in header_rows {
        let mut request = canonical;
        mutate(&mut request);
        assert_eq!(validate_mutation_v2(&request, &context), Err(expected));
    }

    for kind in [
        mutation_kind::INVALID,
        mutation_kind::SET_SPARSE,
        12,
        u16::MAX,
    ] {
        let mut request = canonical;
        request.mutation_kind = kind;
        assert_eq!(
            validate_mutation_v2(&request, &context),
            Err(MessageValidationError::InvalidScalar),
            "kind={kind}"
        );
    }

    let expectation_rows: [ExpectationRow<MutationV2>; 8] = [
        (mutation_kind::SET_BASIC_INFO, |request| {
            request.expected_namespace_generation = 0
        }),
        (mutation_kind::SET_BASIC_INFO, |request| {
            request.expected_size_epoch = 7
        }),
        (mutation_kind::SET_BASIC_INFO, |request| {
            request.expected_security_generation = 13
        }),
        (mutation_kind::SET_END_OF_FILE, |request| {
            request.expected_size_epoch = 0
        }),
        (mutation_kind::SET_END_OF_FILE, |request| {
            request.expected_namespace_generation = 11
        }),
        (mutation_kind::RENAME, |request| {
            request.expected_namespace_generation = 0
        }),
        (mutation_kind::SET_SECURITY, |request| {
            request.expected_security_generation = 0
        }),
        (mutation_kind::SET_SECURITY, |request| {
            request.expected_namespace_generation = 11
        }),
    ];
    for (kind, mutate) in expectation_rows {
        let body_len: u32 = match kind {
            1 => 48,
            2..=4 => 24,
            5 => 80,
            8 => 48,
            _ => unreachable!(),
        };
        let kind_body = mapping_grant(
            4_500 + u64::from(kind),
            buffer_access::K2U_READ_ONLY,
            body_len,
        );
        let kind_result_grant = (kind == mutation_kind::RENAME)
            .then(|| mapping_grant(4_600, buffer_access::U2K_WRITE, 112));
        let mut request = canonical_mutation(
            kind,
            kind_body.issued,
            reply.issued,
            kind_result_grant
                .as_ref()
                .map(|grant| grant.issued)
                .unwrap_or_default(),
        );
        mutate(&mut request);
        assert_eq!(
            validate_mutation_v2(
                &request,
                &mutation_context(&kind_body, &reply, kind_result_grant.as_ref()),
            ),
            Err(MessageValidationError::Identity)
        );
    }

    let short_body = mapping_grant(4_701, buffer_access::K2U_READ_ONLY, 47);
    let request = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        short_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    assert_eq!(
        validate_mutation_v2(&request, &mutation_context(&short_body, &reply, None)),
        Err(MessageValidationError::InvalidScalar)
    );
    let huge_body = mapping_grant(4_702, buffer_access::K2U_READ_ONLY, 65_561);
    let request = canonical_mutation(
        mutation_kind::SET_SECURITY,
        huge_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    let mut security_request = request;
    security_request.expected_namespace_generation = 0;
    security_request.expected_security_generation = 13;
    assert_eq!(
        validate_mutation_v2(
            &security_request,
            &mutation_context(&huge_body, &reply, None)
        ),
        Err(MessageValidationError::InvalidScalar)
    );
    let max_body = mapping_grant(4_703, buffer_access::K2U_READ_ONLY, 65_560);
    let request = canonical_mutation(
        mutation_kind::SET_SECURITY,
        max_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    assert!(validate_mutation_v2(&request, &mutation_context(&max_body, &reply, None)).is_ok());

    let small_reply = mapping_grant(4_704, buffer_access::U2K_WRITE, 111);
    let request = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        body.issued,
        small_reply.issued,
        BufferRef::default(),
    );
    assert_eq!(
        validate_mutation_v2(&request, &mutation_context(&body, &small_reply, None)),
        Err(MessageValidationError::InvalidScalar)
    );

    for kind_result_len in [111u32, 113] {
        let rename_body = mapping_grant(4_705, buffer_access::K2U_READ_ONLY, 80);
        let kind_result_grant = mapping_grant(
            4_706 + u64::from(kind_result_len),
            buffer_access::U2K_WRITE,
            kind_result_len,
        );
        let request = canonical_mutation(
            mutation_kind::RENAME,
            rename_body.issued,
            reply.issued,
            kind_result_grant.issued,
        );
        assert_eq!(
            validate_mutation_v2(
                &request,
                &mutation_context(&rename_body, &reply, Some(&kind_result_grant)),
            ),
            Err(MessageValidationError::InvalidScalar),
            "kind result length={kind_result_len}"
        );
    }

    let rename_body = mapping_grant(4_710, buffer_access::K2U_READ_ONLY, 80);
    let request = canonical_mutation(
        mutation_kind::RENAME,
        rename_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    assert_eq!(
        validate_mutation_v2(&request, &mutation_context(&rename_body, &reply, None)),
        Err(MessageValidationError::Relationship)
    );

    let stray_kind_result = mapping_grant(4_711, buffer_access::U2K_WRITE, 112);
    let request = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        body.issued,
        reply.issued,
        stray_kind_result.issued,
    );
    assert_eq!(
        validate_mutation_v2(
            &request,
            &mutation_context(&body, &reply, Some(&stray_kind_result)),
        ),
        Err(MessageValidationError::Relationship)
    );
    assert_eq!(
        validate_mutation_v2(&request, &mutation_context(&body, &reply, None)),
        Err(MessageValidationError::Grant(BufferRefError::InvalidNone))
    );

    let mut wrong_token = canonical;
    wrong_token.body.token ^= 1;
    assert_eq!(
        validate_mutation_v2(&wrong_token, &context),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
}

#[test]
fn mutation_bodies_have_one_accepted_byte_representation() {
    let basic = canonical_basic_body();
    let basic_blob = body_blob(&basic, &[]);
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_BASIC_INFO,
            MutationBodyRefV21::SetBasicInfo(&basic),
            &basic_blob,
            false,
        ),
        Ok(())
    );
    assert_eq!(
        mutation_kind_of_body_v21(MutationBodyRefV21::SetBasicInfo(&basic)),
        mutation_kind::SET_BASIC_INFO
    );
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_END_OF_FILE,
            MutationBodyRefV21::SetBasicInfo(&basic),
            &basic_blob,
            false,
        ),
        Err(MessageValidationError::Relationship)
    );

    let basic_rows: [MutationRow<SetBasicInfoV1, MessageValidationError>; 9] = [
        (
            |body| body.header.struct_version = 2,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |body| body.header.struct_size = 47,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |body| body.set_mask = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.set_mask = 0x20,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.attributes = file_attributes::NORMAL | file_attributes::READONLY,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.attributes = file_attributes::REPARSE_POINT,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.attributes = 0,
            MessageValidationError::Relationship,
        ),
        (
            |body| body.creation_time = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.creation_time = -1,
            MessageValidationError::InvalidScalar,
        ),
    ];
    for (index, (mutate, expected)) in basic_rows.into_iter().enumerate() {
        let mut body = canonical_basic_body();
        mutate(&mut body);
        let blob = body_blob(&body, &[]);
        assert_eq!(
            validate_mutation_body_v21(
                mutation_kind::SET_BASIC_INFO,
                MutationBodyRefV21::SetBasicInfo(&body),
                &blob,
                false,
            ),
            Err(expected),
            "basic row {index}"
        );
    }
    let mut unselected_time = canonical_basic_body();
    unselected_time.last_access_time = 5;
    let blob = body_blob(&unselected_time, &[]);
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_BASIC_INFO,
            MutationBodyRefV21::SetBasicInfo(&unselected_time),
            &blob,
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );
    let mut attrs_without_bit = canonical_basic_body();
    attrs_without_bit.set_mask =
        basic_info_set_mask::CREATION_TIME | basic_info_set_mask::LAST_WRITE_TIME;
    let blob = body_blob(&attrs_without_bit, &[]);
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_BASIC_INFO,
            MutationBodyRefV21::SetBasicInfo(&attrs_without_bit),
            &blob,
            false,
        ),
        Err(MessageValidationError::Relationship)
    );

    let size = canonical_size_body();
    for kind in [
        mutation_kind::SET_ALLOCATION_SIZE,
        mutation_kind::SET_END_OF_FILE,
        mutation_kind::SET_VALID_DATA_LENGTH,
    ] {
        let body_ref = match kind {
            2 => MutationBodyRefV21::SetAllocationSize(&size),
            3 => MutationBodyRefV21::SetEndOfFile(&size),
            _ => MutationBodyRefV21::SetValidDataLength(&size),
        };
        assert_eq!(
            validate_mutation_body_v21(kind, body_ref, &body_blob(&size, &[]), false),
            Ok(())
        );
    }
    let mut max_size = canonical_size_body();
    max_size.new_size = MAX_FILE_SIZE;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_END_OF_FILE,
            MutationBodyRefV21::SetEndOfFile(&max_size),
            &body_blob(&max_size, &[]),
            false,
        ),
        Ok(())
    );
    let size_rows: [MutationRow<SetSizeV1, MessageValidationError>; 3] = [
        (
            |body| body.new_size = MAX_FILE_SIZE + 1,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |body| body.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
    ];
    for (mutate, expected) in size_rows {
        let mut body = canonical_size_body();
        mutate(&mut body);
        assert_eq!(
            validate_mutation_body_v21(
                mutation_kind::SET_VALID_DATA_LENGTH,
                MutationBodyRefV21::SetValidDataLength(&body),
                &body_blob(&body, &[]),
                false,
            ),
            Err(expected)
        );
    }

    let rename = canonical_rename_body();
    let rename_blob = body_blob(&rename, &NAME_AB);
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::RENAME,
            MutationBodyRefV21::Rename(&rename),
            &rename_blob,
            false,
        ),
        Ok(())
    );
    let mut same_parent = canonical_rename_body();
    same_parent.expected_target_parent_generation = 31;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::RENAME,
            MutationBodyRefV21::Rename(&same_parent),
            &body_blob(&same_parent, &NAME_AB),
            true,
        ),
        Ok(())
    );
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::RENAME,
            MutationBodyRefV21::Rename(&rename),
            &rename_blob,
            true,
        ),
        Err(MessageValidationError::Relationship)
    );
    let rename_rows: [MutationRow<RenameV1, MessageValidationError>; 8] = [
        (
            |body| body.source_link_id = LinkId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |body| body.target_parent_id = FileId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |body| body.expected_source_parent_generation = 0,
            MessageValidationError::Identity,
        ),
        (
            |body| body.expected_target_parent_generation = 0,
            MessageValidationError::Identity,
        ),
        (
            |body| body.flags = 2,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |body| body.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |body| body.name.offset = 71,
            MessageValidationError::Relationship,
        ),
        (
            |body| body.name.length = 0,
            MessageValidationError::Relationship,
        ),
    ];
    for (index, (mutate, expected)) in rename_rows.into_iter().enumerate() {
        let mut body = canonical_rename_body();
        mutate(&mut body);
        assert_eq!(
            validate_mutation_body_v21(
                mutation_kind::RENAME,
                MutationBodyRefV21::Rename(&body),
                &body_blob(&body, &NAME_AB),
                false,
            ),
            Err(expected),
            "rename row {index}"
        );
    }
    let mut padded = body_blob(&rename, &NAME_AB);
    padded[77] = 1;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::RENAME,
            MutationBodyRefV21::Rename(&rename),
            &padded,
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );

    let link = canonical_link_body();
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::LINK,
            MutationBodyRefV21::Link(&link),
            &body_blob(&link, &NAME_AB),
            false,
        ),
        Ok(())
    );
    let mut zero_link_source = canonical_link_body();
    zero_link_source.source_file_id = FileId { lo: 0, hi: 0 };
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::LINK,
            MutationBodyRefV21::Link(&zero_link_source),
            &body_blob(&zero_link_source, &NAME_AB),
            false,
        ),
        Err(MessageValidationError::Identity)
    );

    let unlink = canonical_unlink_body();
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::UNLINK,
            MutationBodyRefV21::Unlink(&unlink),
            &body_blob(&unlink, &[]),
            false,
        ),
        Ok(())
    );
    let mut zero_unlink = canonical_unlink_body();
    zero_unlink.expected_parent_generation = 0;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::UNLINK,
            MutationBodyRefV21::Unlink(&zero_unlink),
            &body_blob(&zero_unlink, &[]),
            false,
        ),
        Err(MessageValidationError::Identity)
    );

    let security = canonical_security_body();
    let descriptor = [0x11u8; 20];
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_SECURITY,
            MutationBodyRefV21::SetSecurity(&security),
            &body_blob(&security, &descriptor),
            false,
        ),
        Ok(())
    );
    let security_rows: [MutationRow<SetSecurityV1, MessageValidationError>; 3] = [
        (
            |body| body.security_information = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.security_information = 0x80,
            MessageValidationError::InvalidScalar,
        ),
        (
            |body| body.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
    ];
    for (index, (mutate, expected)) in security_rows.into_iter().enumerate() {
        let mut body = canonical_security_body();
        mutate(&mut body);
        assert_eq!(
            validate_mutation_body_v21(
                mutation_kind::SET_SECURITY,
                MutationBodyRefV21::SetSecurity(&body),
                &body_blob(&body, &descriptor),
                false,
            ),
            Err(expected),
            "security row {index}"
        );
    }
    let mut short_descriptor = canonical_security_body();
    short_descriptor.security_descriptor.length = 19;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_SECURITY,
            MutationBodyRefV21::SetSecurity(&short_descriptor),
            &body_blob(&short_descriptor, &descriptor[..19]),
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );

    assert_eq!(validate_stored_component_utf16(&NAME_AB), Ok(()));
    let component_rows: [&[u8]; 9] = [
        &[],
        &[0x61],
        &[0x00, 0x00],
        &[0x2f, 0x00],
        &[0x5c, 0x00],
        &[0x3a, 0x00],
        &[0x2a, 0x00],
        &[0x00, 0xd8],
        &[0x2e, 0x00],
    ];
    for (index, bytes) in component_rows.into_iter().enumerate() {
        assert_eq!(
            validate_stored_component_utf16(bytes),
            Err(MessageValidationError::InvalidScalar),
            "component row {index}"
        );
    }
    let dotdot: [u8; 4] = [0x2e, 0x00, 0x2e, 0x00];
    assert_eq!(
        validate_stored_component_utf16(&dotdot),
        Err(MessageValidationError::InvalidScalar)
    );
    let surrogate_pair: [u8; 4] = [0x00, 0xd8, 0x00, 0xdc];
    assert_eq!(validate_stored_component_utf16(&surrogate_pair), Ok(()));
    let max_name = [0x61u8, 0x00].repeat(255);
    assert_eq!(validate_stored_component_utf16(&max_name), Ok(()));
    let over_name = [0x61u8, 0x00].repeat(256);
    assert_eq!(
        validate_stored_component_utf16(&over_name),
        Err(MessageValidationError::InvalidScalar)
    );
}

fn retained_sizes_v21() -> SizeState {
    SizeState {
        allocation_size: 4_096,
        file_size: 200,
        valid_data_length: 104,
        size_epoch: 7,
    }
}

fn canonical_mutation_result(kind: u16, kind_result: BufferRef) -> MutationResultV2 {
    let (namespace, security) = match kind {
        1 | 5 | 6 | 7 | 9 | 10 => (12, 0),
        8 => (0, 14),
        _ => (0, 0),
    };
    MutationResultV2 {
        header: control_header(112),
        op_id: OpId { lo: 1, hi: 2 },
        volume_commit_sequence: 91,
        mutation_kind: kind,
        result_flags: 0,
        reserved: 0,
        sizes: SizeState {
            allocation_size: 4_096,
            file_size: 200,
            valid_data_length: 104,
            size_epoch: 8,
        },
        namespace_generation: namespace,
        security_generation: security,
        kind_result,
    }
}

fn canonical_rename_result() -> RenameResultV2 {
    RenameResultV2 {
        header: control_header(112),
        file_id: FileId { lo: 61, hi: 62 },
        link_id: LinkId { lo: 21, hi: 22 },
        replaced_file_id: FileId { lo: 0, hi: 0 },
        replaced_link_id: LinkId { lo: 0, hi: 0 },
        source_parent_generation: 33,
        target_parent_generation: 34,
        replaced_namespace_generation: 0,
        link_count: 1,
        replaced_link_count: 0,
        flags: 0,
        reserved: 0,
    }
}

#[test]
fn mutation_success_results_and_kind_results_are_exact() {
    let retained = retained_sizes_v21();

    let body_grant = mapping_grant(5_001, buffer_access::K2U_READ_ONLY, 80);
    let reply = mapping_grant(5_002, buffer_access::U2K_WRITE, 112);
    let kind_result_grant = mapping_grant(5_003, buffer_access::U2K_WRITE, 112);
    let request = canonical_mutation(
        mutation_kind::RENAME,
        body_grant.issued,
        reply.issued,
        kind_result_grant.issued,
    );
    request_context_check(&request);
    let context = mutation_context(&body_grant, &reply, Some(&kind_result_grant));
    let body = canonical_rename_body();
    let output = echo_output(&reply, 112);
    let result = canonical_mutation_result(
        mutation_kind::RENAME,
        shrunk_reference(&kind_result_grant, 112),
    );
    let rename_result = canonical_rename_result();
    let proof = validate_mutation_success_v2(
        &request,
        &context,
        MutationBodyRefV21::Rename(&body),
        &output,
        &result,
        MutationKindResultRefV21::Rename(&rename_result),
        retained,
    )
    .unwrap();
    assert_eq!(validated_length(proof.reply()), 112);
    assert_eq!(validated_length(proof.kind_result().unwrap()), 112);

    let mut replaced = canonical_rename_result();
    replaced.replaced_file_id = FileId { lo: 63, hi: 64 };
    replaced.replaced_link_id = LinkId { lo: 65, hi: 66 };
    replaced.replaced_namespace_generation = 40;
    assert!(validate_mutation_success_v2(
        &request,
        &context,
        MutationBodyRefV21::Rename(&body),
        &output,
        &result,
        MutationKindResultRefV21::Rename(&replaced),
        retained,
    )
    .is_ok());
    let mut alias = canonical_rename_result();
    alias.replaced_file_id = alias.file_id;
    alias.replaced_link_id = LinkId { lo: 65, hi: 66 };
    alias.replaced_namespace_generation = 12;
    alias.replaced_link_count = alias.link_count;
    assert!(validate_mutation_success_v2(
        &request,
        &context,
        MutationBodyRefV21::Rename(&body),
        &output,
        &result,
        MutationKindResultRefV21::Rename(&alias),
        retained,
    )
    .is_ok());

    assert_eq!(
        validate_mutation_success_v2(
            &request,
            &context,
            MutationBodyRefV21::Rename(&body),
            &echo_output(&reply, 111),
            &result,
            MutationKindResultRefV21::Rename(&rename_result),
            retained,
        ),
        Err(MessageValidationError::Completion)
    );
    let result_rows: [MutationRow<MutationResultV2, MessageValidationError>; 8] = [
        (
            |result| result.header.struct_version = 1,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |result| result.header.struct_size = 111,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |result| result.result_flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |result| result.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |result| result.op_id = OpId { lo: 9, hi: 9 },
            MessageValidationError::Identity,
        ),
        (
            |result| result.mutation_kind = mutation_kind::LINK,
            MessageValidationError::Identity,
        ),
        (
            |result| result.volume_commit_sequence = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |result| result.sizes.size_epoch = 0,
            MessageValidationError::SizeState,
        ),
    ];
    for (index, (mutate, expected)) in result_rows.into_iter().enumerate() {
        let mut defective = canonical_mutation_result(
            mutation_kind::RENAME,
            shrunk_reference(&kind_result_grant, 112),
        );
        mutate(&mut defective);
        assert_eq!(
            validate_mutation_success_v2(
                &request,
                &context,
                MutationBodyRefV21::Rename(&body),
                &output,
                &defective,
                MutationKindResultRefV21::Rename(&rename_result),
                retained,
            ),
            Err(expected),
            "result row {index}"
        );
    }
    for (index, (namespace, security, expected)) in [
        (0u64, 0u64, MessageValidationError::Identity),
        (11, 0, MessageValidationError::Identity),
        (12, 14, MessageValidationError::InvalidScalar),
    ]
    .into_iter()
    .enumerate()
    {
        let mut defective = canonical_mutation_result(
            mutation_kind::RENAME,
            shrunk_reference(&kind_result_grant, 112),
        );
        defective.namespace_generation = namespace;
        defective.security_generation = security;
        assert_eq!(
            validate_mutation_success_v2(
                &request,
                &context,
                MutationBodyRefV21::Rename(&body),
                &output,
                &defective,
                MutationKindResultRefV21::Rename(&rename_result),
                retained,
            ),
            Err(expected),
            "generation row {index}"
        );
    }
    let mut regressed = canonical_mutation_result(
        mutation_kind::RENAME,
        shrunk_reference(&kind_result_grant, 112),
    );
    regressed.sizes.size_epoch = 6;
    assert_eq!(
        validate_mutation_success_v2(
            &request,
            &context,
            MutationBodyRefV21::Rename(&body),
            &output,
            &regressed,
            MutationKindResultRefV21::Rename(&rename_result),
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );

    let short_echo = canonical_mutation_result(
        mutation_kind::RENAME,
        shrunk_reference(&kind_result_grant, 111),
    );
    assert_eq!(
        validate_mutation_success_v2(
            &request,
            &context,
            MutationBodyRefV21::Rename(&body),
            &output,
            &short_echo,
            MutationKindResultRefV21::Rename(&rename_result),
            retained,
        ),
        Err(MessageValidationError::Completion)
    );
    let link_record = LinkResultV2 {
        header: control_header(104),
        file_id: FileId { lo: 71, hi: 72 },
        new_link_id: LinkId { lo: 73, hi: 74 },
        replaced_file_id: FileId { lo: 0, hi: 0 },
        replaced_link_id: LinkId { lo: 0, hi: 0 },
        target_parent_generation: 46,
        replaced_namespace_generation: 0,
        link_count: 2,
        replaced_link_count: 0,
        flags: 0,
        reserved: 0,
    };
    assert_eq!(
        validate_mutation_success_v2(
            &request,
            &context,
            MutationBodyRefV21::Rename(&body),
            &output,
            &result,
            MutationKindResultRefV21::Link(&link_record),
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );

    let rename_record_rows: [MutationRow<RenameResultV2, MessageValidationError>; 8] = [
        (
            |record| record.header.struct_version = 1,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |record| record.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |record| record.file_id = FileId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |record| record.link_id = LinkId { lo: 98, hi: 99 },
            MessageValidationError::Identity,
        ),
        (
            |record| record.source_parent_generation = 31,
            MessageValidationError::Identity,
        ),
        (
            |record| record.target_parent_generation = 0,
            MessageValidationError::Identity,
        ),
        (
            |record| record.replaced_file_id = FileId { lo: 63, hi: 64 },
            MessageValidationError::Relationship,
        ),
        (
            |record| {
                record.replaced_file_id = FileId { lo: 63, hi: 64 };
                record.replaced_link_id = record.link_id;
                record.replaced_namespace_generation = 40;
            },
            MessageValidationError::Relationship,
        ),
    ];
    for (index, (mutate, expected)) in rename_record_rows.into_iter().enumerate() {
        let mut record = canonical_rename_result();
        mutate(&mut record);
        assert_eq!(
            validate_mutation_success_v2(
                &request,
                &context,
                MutationBodyRefV21::Rename(&body),
                &output,
                &result,
                MutationKindResultRefV21::Rename(&record),
                retained,
            ),
            Err(expected),
            "rename record row {index}"
        );
    }
    let mut bad_alias = canonical_rename_result();
    bad_alias.replaced_file_id = bad_alias.file_id;
    bad_alias.replaced_link_id = LinkId { lo: 65, hi: 66 };
    bad_alias.replaced_namespace_generation = 40;
    bad_alias.replaced_link_count = bad_alias.link_count;
    assert_eq!(
        validate_mutation_success_v2(
            &request,
            &context,
            MutationBodyRefV21::Rename(&body),
            &output,
            &result,
            MutationKindResultRefV21::Rename(&bad_alias),
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );

    let svdl_body_grant = mapping_grant(5_011, buffer_access::K2U_READ_ONLY, 24);
    let svdl_request = canonical_mutation(
        mutation_kind::SET_VALID_DATA_LENGTH,
        svdl_body_grant.issued,
        reply.issued,
        BufferRef::default(),
    );
    let svdl_context = mutation_context(&svdl_body_grant, &reply, None);
    let mut svdl_body = canonical_size_body();
    svdl_body.new_size = 150;
    let mut svdl_result =
        canonical_mutation_result(mutation_kind::SET_VALID_DATA_LENGTH, BufferRef::default());
    svdl_result.op_id = svdl_request.op_id;
    svdl_result.sizes.valid_data_length = 150;
    assert!(validate_mutation_success_v2(
        &svdl_request,
        &svdl_context,
        MutationBodyRefV21::SetValidDataLength(&svdl_body),
        &output,
        &svdl_result,
        MutationKindResultRefV21::None,
        retained,
    )
    .is_ok());
    let svdl_rows: [MutationRow<MutationResultV2, MessageValidationError>; 4] = [
        (
            |result| result.sizes.size_epoch = 7,
            MessageValidationError::InvalidScalar,
        ),
        (
            |result| result.sizes.valid_data_length = 149,
            MessageValidationError::Relationship,
        ),
        (
            |result| result.sizes.allocation_size = 4_097,
            MessageValidationError::Relationship,
        ),
        (
            |result| result.sizes.file_size = 199,
            MessageValidationError::Relationship,
        ),
    ];
    for (index, (mutate, expected)) in svdl_rows.into_iter().enumerate() {
        let mut defective =
            canonical_mutation_result(mutation_kind::SET_VALID_DATA_LENGTH, BufferRef::default());
        defective.sizes.valid_data_length = 150;
        mutate(&mut defective);
        assert_eq!(
            validate_mutation_success_v2(
                &svdl_request,
                &svdl_context,
                MutationBodyRefV21::SetValidDataLength(&svdl_body),
                &output,
                &defective,
                MutationKindResultRefV21::None,
                retained,
            ),
            Err(expected),
            "svdl row {index}"
        );
    }

    let eof_body_grant = mapping_grant(5_021, buffer_access::K2U_READ_ONLY, 24);
    let eof_request = canonical_mutation(
        mutation_kind::SET_END_OF_FILE,
        eof_body_grant.issued,
        reply.issued,
        BufferRef::default(),
    );
    let eof_body = canonical_size_body();
    let mut eof_result =
        canonical_mutation_result(mutation_kind::SET_END_OF_FILE, BufferRef::default());
    eof_result.sizes.file_size = 1_024;
    assert!(validate_mutation_success_v2(
        &eof_request,
        &mutation_context(&eof_body_grant, &reply, None),
        MutationBodyRefV21::SetEndOfFile(&eof_body),
        &output,
        &eof_result,
        MutationKindResultRefV21::None,
        retained,
    )
    .is_ok());
    let mut eof_mismatch =
        canonical_mutation_result(mutation_kind::SET_END_OF_FILE, BufferRef::default());
    eof_mismatch.sizes.file_size = 1_023;
    assert_eq!(
        validate_mutation_success_v2(
            &eof_request,
            &mutation_context(&eof_body_grant, &reply, None),
            MutationBodyRefV21::SetEndOfFile(&eof_body),
            &output,
            &eof_mismatch,
            MutationKindResultRefV21::None,
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );

    let alloc_body_grant = mapping_grant(5_031, buffer_access::K2U_READ_ONLY, 24);
    let alloc_request = canonical_mutation(
        mutation_kind::SET_ALLOCATION_SIZE,
        alloc_body_grant.issued,
        reply.issued,
        BufferRef::default(),
    );
    let alloc_body = canonical_size_body();
    let alloc_result =
        canonical_mutation_result(mutation_kind::SET_ALLOCATION_SIZE, BufferRef::default());
    assert!(validate_mutation_success_v2(
        &alloc_request,
        &mutation_context(&alloc_body_grant, &reply, None),
        MutationBodyRefV21::SetAllocationSize(&alloc_body),
        &output,
        &alloc_result,
        MutationKindResultRefV21::None,
        retained,
    )
    .is_ok());
    let mut alloc_short =
        canonical_mutation_result(mutation_kind::SET_ALLOCATION_SIZE, BufferRef::default());
    alloc_short.sizes.allocation_size = 1_023;
    alloc_short.sizes.file_size = 200;
    assert_eq!(
        validate_mutation_success_v2(
            &alloc_request,
            &mutation_context(&alloc_body_grant, &reply, None),
            MutationBodyRefV21::SetAllocationSize(&alloc_body),
            &output,
            &alloc_short,
            MutationKindResultRefV21::None,
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );

    let unlink_body_grant = mapping_grant(5_041, buffer_access::K2U_READ_ONLY, 56);
    let unlink_kind_result = mapping_grant(5_042, buffer_access::U2K_WRITE, 56);
    let unlink_request = canonical_mutation(
        mutation_kind::UNLINK,
        unlink_body_grant.issued,
        reply.issued,
        unlink_kind_result.issued,
    );
    let unlink_body = canonical_unlink_body();
    let unlink_result = canonical_mutation_result(
        mutation_kind::UNLINK,
        shrunk_reference(&unlink_kind_result, 56),
    );
    let unlink_record = UnlinkResultV1 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: 1,
            required_flags: 0,
        },
        file_id: FileId { lo: 67, hi: 68 },
        removed_link_id: LinkId { lo: 51, hi: 52 },
        parent_generation: 56,
        remaining_link_count: 1,
        flags: 0,
    };
    assert!(validate_mutation_success_v2(
        &unlink_request,
        &mutation_context(&unlink_body_grant, &reply, Some(&unlink_kind_result)),
        MutationBodyRefV21::Unlink(&unlink_body),
        &output,
        &unlink_result,
        MutationKindResultRefV21::Unlink(&unlink_record),
        retained,
    )
    .is_ok());
    let mut wrong_removed = unlink_record;
    wrong_removed.removed_link_id = LinkId { lo: 98, hi: 99 };
    assert_eq!(
        validate_mutation_success_v2(
            &unlink_request,
            &mutation_context(&unlink_body_grant, &reply, Some(&unlink_kind_result)),
            MutationBodyRefV21::Unlink(&unlink_body),
            &output,
            &unlink_result,
            MutationKindResultRefV21::Unlink(&wrong_removed),
            retained,
        ),
        Err(MessageValidationError::Identity)
    );
    let mut stale_parent = unlink_record;
    stale_parent.parent_generation = 55;
    assert_eq!(
        validate_mutation_success_v2(
            &unlink_request,
            &mutation_context(&unlink_body_grant, &reply, Some(&unlink_kind_result)),
            MutationBodyRefV21::Unlink(&unlink_body),
            &output,
            &unlink_result,
            MutationKindResultRefV21::Unlink(&stale_parent),
            retained,
        ),
        Err(MessageValidationError::Identity)
    );

    let basic_body_grant = mapping_grant(5_051, buffer_access::K2U_READ_ONLY, 48);
    let basic_request = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        basic_body_grant.issued,
        reply.issued,
        BufferRef::default(),
    );
    let basic_body = canonical_basic_body();
    let basic_result =
        canonical_mutation_result(mutation_kind::SET_BASIC_INFO, BufferRef::default());
    assert!(validate_mutation_success_v2(
        &basic_request,
        &mutation_context(&basic_body_grant, &reply, None),
        MutationBodyRefV21::SetBasicInfo(&basic_body),
        &output,
        &basic_result,
        MutationKindResultRefV21::None,
        retained,
    )
    .is_ok());
    assert_eq!(
        validate_mutation_success_v2(
            &basic_request,
            &mutation_context(&basic_body_grant, &reply, None),
            MutationBodyRefV21::SetBasicInfo(&basic_body),
            &output,
            &basic_result,
            MutationKindResultRefV21::Rename(&rename_result),
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );
    let mut live_kind_result =
        canonical_mutation_result(mutation_kind::SET_BASIC_INFO, BufferRef::default());
    live_kind_result.kind_result = reply.issued;
    assert_eq!(
        validate_mutation_success_v2(
            &basic_request,
            &mutation_context(&basic_body_grant, &reply, None),
            MutationBodyRefV21::SetBasicInfo(&basic_body),
            &output,
            &live_kind_result,
            MutationKindResultRefV21::None,
            retained,
        ),
        Err(MessageValidationError::Grant(BufferRefError::InvalidNone))
    );
    assert_eq!(
        mutation_kind_result_length_v21(mutation_kind::RENAME),
        Some(112)
    );
    assert_eq!(
        mutation_kind_result_length_v21(mutation_kind::LINK),
        Some(104)
    );
    assert_eq!(
        mutation_kind_result_length_v21(mutation_kind::UNLINK),
        Some(56)
    );
    assert_eq!(
        mutation_kind_result_length_v21(mutation_kind::SET_BASIC_INFO),
        None
    );
}

fn request_context_check(request: &MutationV2) {
    assert_eq!(request.header.struct_size, 128);
}

#[test]
fn wave7a_review_hardening_closes_uncovered_rows() {
    let wildcard_rows: [[u8; 2]; 5] = [
        [0x3f, 0x00],
        [0x3c, 0x00],
        [0x3e, 0x00],
        [0x22, 0x00],
        [0x00, 0xdc],
    ];
    for (index, bytes) in wildcard_rows.into_iter().enumerate() {
        assert_eq!(
            validate_stored_component_utf16(&bytes),
            Err(MessageValidationError::InvalidScalar),
            "wildcard/surrogate row {index}"
        );
    }
    let high_then_nonlow: [u8; 4] = [0x00, 0xd8, 0x61, 0x00];
    assert_eq!(
        validate_stored_component_utf16(&high_then_nonlow),
        Err(MessageValidationError::InvalidScalar)
    );

    let mut star_rename = canonical_rename_body();
    star_rename.name.length = 4;
    let star_name: [u8; 4] = [0x2a, 0x00, 0x62, 0x00];
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::RENAME,
            MutationBodyRefV21::Rename(&star_rename),
            &body_blob(&star_rename, &star_name),
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );
    let mut long_link = canonical_link_body();
    long_link.name.length = 512;
    long_link.header.struct_size = 576;
    let long_name = [0x61u8; 512];
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::LINK,
            MutationBodyRefV21::Link(&long_link),
            &body_blob(&long_link, &long_name),
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );

    let mut flagged_basic = canonical_basic_body();
    flagged_basic.header.required_flags = 1;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_BASIC_INFO,
            MutationBodyRefV21::SetBasicInfo(&flagged_basic),
            &body_blob(&flagged_basic, &[]),
            false,
        ),
        Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags
        ))
    );

    let mut flagged_rename = canonical_rename_body();
    flagged_rename.flags = 2;
    let mut padded_and_flagged = body_blob(&flagged_rename, &NAME_AB);
    padded_and_flagged[77] = 1;
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::RENAME,
            MutationBodyRefV21::Rename(&flagged_rename),
            &padded_and_flagged,
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );

    let link_body_rows: [MutationRow<LinkV1, MessageValidationError>; 4] = [
        (
            |body| body.target_parent_id = FileId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |body| body.expected_target_parent_generation = 0,
            MessageValidationError::Identity,
        ),
        (
            |body| body.flags = 2,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |body| body.reserved = 1,
            MessageValidationError::FlagsOrReserved,
        ),
    ];
    for (index, (mutate, expected)) in link_body_rows.into_iter().enumerate() {
        let mut body = canonical_link_body();
        mutate(&mut body);
        assert_eq!(
            validate_mutation_body_v21(
                mutation_kind::LINK,
                MutationBodyRefV21::Link(&body),
                &body_blob(&body, &NAME_AB),
                false,
            ),
            Err(expected),
            "link body row {index}"
        );
    }
    let unlink_body_rows: [fn(&mut UnlinkV1); 2] = [
        |body| body.link_id = LinkId { lo: 0, hi: 0 },
        |body| body.parent_id = FileId { lo: 0, hi: 0 },
    ];
    for (index, mutate) in unlink_body_rows.into_iter().enumerate() {
        let mut body = canonical_unlink_body();
        mutate(&mut body);
        assert_eq!(
            validate_mutation_body_v21(
                mutation_kind::UNLINK,
                MutationBodyRefV21::Unlink(&body),
                &body_blob(&body, &[]),
                false,
            ),
            Err(MessageValidationError::Identity),
            "unlink body row {index}"
        );
    }

    let security = canonical_security_body();
    let mut max_sd = security;
    max_sd.security_descriptor.length = 65_536;
    max_sd.header.struct_size = 65_560;
    let max_tail = vec![0x11u8; 65_536];
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_SECURITY,
            MutationBodyRefV21::SetSecurity(&max_sd),
            &body_blob(&max_sd, &max_tail),
            false,
        ),
        Ok(())
    );
    let mut over_sd = security;
    over_sd.security_descriptor.length = 65_537;
    over_sd.header.struct_size = 65_568;
    let over_tail = vec![0x11u8; 65_537];
    assert_eq!(
        validate_mutation_body_v21(
            mutation_kind::SET_SECURITY,
            MutationBodyRefV21::SetSecurity(&over_sd),
            &body_blob(&over_sd, &over_tail),
            false,
        ),
        Err(MessageValidationError::InvalidScalar)
    );

    let reply = mapping_grant(6_001, buffer_access::U2K_WRITE, 112);
    for (kind, body_len, kind_result_len, expected_ok) in [
        (mutation_kind::SET_REPARSE, 23u32, None::<u32>, false),
        (mutation_kind::DELETE_REPARSE, 15, None, false),
        (mutation_kind::DELETE_REPARSE, 16, None, true),
    ] {
        let body = mapping_grant(
            6_010 + u64::from(body_len),
            buffer_access::K2U_READ_ONLY,
            body_len,
        );
        let request = canonical_mutation(kind, body.issued, reply.issued, BufferRef::default());
        let mut context = mutation_context(&body, &reply, None);
        context.reparse_selected = true;
        let _ = kind_result_len;
        let outcome = validate_mutation_v2(&request, &context);
        if expected_ok {
            assert!(outcome.is_ok(), "kind={kind} len={body_len}");
        } else {
            assert_eq!(
                outcome,
                Err(MessageValidationError::InvalidScalar),
                "kind={kind} len={body_len}"
            );
        }
    }

    for (kind, body_len, kind_result_len) in [
        (mutation_kind::LINK, 72u32, 103u32),
        (mutation_kind::UNLINK, 56, 55),
    ] {
        let body = mapping_grant(
            6_100 + u64::from(kind),
            buffer_access::K2U_READ_ONLY,
            body_len,
        );
        let kind_result_grant = mapping_grant(
            6_200 + u64::from(kind),
            buffer_access::U2K_WRITE,
            kind_result_len,
        );
        let request = canonical_mutation(kind, body.issued, reply.issued, kind_result_grant.issued);
        assert_eq!(
            validate_mutation_v2(
                &request,
                &mutation_context(&body, &reply, Some(&kind_result_grant)),
            ),
            Err(MessageValidationError::InvalidScalar),
            "kind={kind} kind_result={kind_result_len}"
        );
    }

    let stacked_body = mapping_grant(6_301, buffer_access::K2U_READ_ONLY, 48);
    let context = mutation_context(&stacked_body, &reply, None);
    let mut stacked = canonical_mutation(
        mutation_kind::SET_BASIC_INFO,
        stacked_body.issued,
        reply.issued,
        BufferRef::default(),
    );
    stacked.header.struct_version = CONTROL_VERSION_V1;
    stacked.mutation_flags = 1;
    stacked.op_id = OpId::ZERO;
    stacked.mutation_kind = mutation_kind::SET_SPARSE;
    stacked.expected_size_epoch = 7;
    stacked.body.token ^= 1;
    assert_eq!(
        validate_mutation_v2(&stacked, &context),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
    stacked.header.struct_version = CONTROL_VERSION_V2;
    assert_eq!(
        validate_mutation_v2(&stacked, &context),
        Err(MessageValidationError::FlagsOrReserved)
    );
    stacked.mutation_flags = 0;
    assert_eq!(
        validate_mutation_v2(&stacked, &context),
        Err(MessageValidationError::Identity)
    );
    stacked.op_id = OpId { lo: 1, hi: 2 };
    assert_eq!(
        validate_mutation_v2(&stacked, &context),
        Err(MessageValidationError::InvalidScalar)
    );
    stacked.mutation_kind = mutation_kind::SET_BASIC_INFO;
    assert_eq!(
        validate_mutation_v2(&stacked, &context),
        Err(MessageValidationError::Identity)
    );
    stacked.expected_size_epoch = 0;
    assert_eq!(
        validate_mutation_v2(&stacked, &context),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
    stacked.body.token ^= 1;
    assert!(validate_mutation_v2(&stacked, &context).is_ok());
}

#[test]
fn wave7a_link_security_success_and_paired_precedence_are_closed() {
    let retained = retained_sizes_v21();
    let reply = mapping_grant(6_401, buffer_access::U2K_WRITE, 112);
    let output = echo_output(&reply, 112);

    let link_body_grant = mapping_grant(6_402, buffer_access::K2U_READ_ONLY, 72);
    let link_kind_result = mapping_grant(6_403, buffer_access::U2K_WRITE, 104);
    let link_request = canonical_mutation(
        mutation_kind::LINK,
        link_body_grant.issued,
        reply.issued,
        link_kind_result.issued,
    );
    let link_context = mutation_context(&link_body_grant, &reply, Some(&link_kind_result));
    let link_body = canonical_link_body();
    let link_result_env = canonical_mutation_result(
        mutation_kind::LINK,
        shrunk_reference(&link_kind_result, 104),
    );
    let link_record = LinkResultV2 {
        header: control_header(104),
        file_id: FileId { lo: 71, hi: 72 },
        new_link_id: LinkId { lo: 73, hi: 74 },
        replaced_file_id: FileId { lo: 0, hi: 0 },
        replaced_link_id: LinkId { lo: 0, hi: 0 },
        target_parent_generation: 46,
        replaced_namespace_generation: 0,
        link_count: 2,
        replaced_link_count: 0,
        flags: 0,
        reserved: 0,
    };
    let proof = validate_mutation_success_v2(
        &link_request,
        &link_context,
        MutationBodyRefV21::Link(&link_body),
        &output,
        &link_result_env,
        MutationKindResultRefV21::Link(&link_record),
        retained,
    )
    .unwrap();
    assert_eq!(validated_length(proof.kind_result().unwrap()), 104);

    let mut link_alias = link_record;
    link_alias.replaced_file_id = link_alias.file_id;
    link_alias.replaced_link_id = LinkId { lo: 75, hi: 76 };
    link_alias.replaced_namespace_generation = 12;
    link_alias.replaced_link_count = link_alias.link_count;
    assert!(validate_mutation_success_v2(
        &link_request,
        &link_context,
        MutationBodyRefV21::Link(&link_body),
        &output,
        &link_result_env,
        MutationKindResultRefV21::Link(&link_alias),
        retained,
    )
    .is_ok());

    let link_record_rows: [MutationRow<LinkResultV2, MessageValidationError>; 8] = [
        (
            |record| record.header.struct_version = 1,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |record| record.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |record| record.file_id = FileId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |record| record.new_link_id = LinkId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
        (
            |record| record.target_parent_generation = 45,
            MessageValidationError::Identity,
        ),
        (
            |record| record.replaced_file_id = FileId { lo: 81, hi: 82 },
            MessageValidationError::Relationship,
        ),
        (
            |record| {
                record.replaced_file_id = FileId { lo: 81, hi: 82 };
                record.replaced_link_id = record.new_link_id;
                record.replaced_namespace_generation = 40;
            },
            MessageValidationError::Relationship,
        ),
        (
            |record| {
                record.replaced_file_id = record.file_id;
                record.replaced_link_id = LinkId { lo: 75, hi: 76 };
                record.replaced_namespace_generation = 40;
                record.replaced_link_count = record.link_count;
            },
            MessageValidationError::Relationship,
        ),
    ];
    for (index, (mutate, expected)) in link_record_rows.into_iter().enumerate() {
        let mut record = link_record;
        mutate(&mut record);
        assert_eq!(
            validate_mutation_success_v2(
                &link_request,
                &link_context,
                MutationBodyRefV21::Link(&link_body),
                &output,
                &link_result_env,
                MutationKindResultRefV21::Link(&record),
                retained,
            ),
            Err(expected),
            "link record row {index}"
        );
    }
    let short_link_echo = canonical_mutation_result(
        mutation_kind::LINK,
        shrunk_reference(&link_kind_result, 103),
    );
    assert_eq!(
        validate_mutation_success_v2(
            &link_request,
            &link_context,
            MutationBodyRefV21::Link(&link_body),
            &output,
            &short_link_echo,
            MutationKindResultRefV21::Link(&link_record),
            retained,
        ),
        Err(MessageValidationError::Completion)
    );

    let mut bad_request = link_request;
    bad_request.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_mutation_success_v2(
            &bad_request,
            &link_context,
            MutationBodyRefV21::Link(&link_body),
            &output,
            &link_result_env,
            MutationKindResultRefV21::Link(&link_record),
            retained,
        ),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
    let size_body = canonical_size_body();
    assert_eq!(
        validate_mutation_success_v2(
            &link_request,
            &link_context,
            MutationBodyRefV21::SetValidDataLength(&size_body),
            &output,
            &link_result_env,
            MutationKindResultRefV21::Link(&link_record),
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );
    let alloc_pairing_grant = mapping_grant(6_451, buffer_access::K2U_READ_ONLY, 24);
    let alloc_pairing_request = canonical_mutation(
        mutation_kind::SET_ALLOCATION_SIZE,
        alloc_pairing_grant.issued,
        reply.issued,
        BufferRef::default(),
    );
    let mismatched_basic = canonical_basic_body();
    assert_eq!(
        validate_mutation_success_v2(
            &alloc_pairing_request,
            &mutation_context(&alloc_pairing_grant, &reply, None),
            MutationBodyRefV21::SetBasicInfo(&mismatched_basic),
            &output,
            &canonical_mutation_result(mutation_kind::SET_ALLOCATION_SIZE, BufferRef::default()),
            MutationKindResultRefV21::None,
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );
    let mut bad_echo = echo_output(&reply, 112);
    bad_echo.body.token ^= 1;
    let mut bad_link_result = link_result_env;
    bad_link_result.header.struct_version = 1;
    assert_eq!(
        validate_mutation_success_v2(
            &link_request,
            &link_context,
            MutationBodyRefV21::Link(&link_body),
            &bad_echo,
            &bad_link_result,
            MutationKindResultRefV21::Link(&link_record),
            retained,
        ),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
    let mut broken_record = link_record;
    broken_record.flags = 1;
    assert_eq!(
        validate_mutation_success_v2(
            &link_request,
            &link_context,
            MutationBodyRefV21::Link(&link_body),
            &echo_output(&reply, 111),
            &link_result_env,
            MutationKindResultRefV21::Link(&broken_record),
            retained,
        ),
        Err(MessageValidationError::Completion)
    );

    let security_body_grant = mapping_grant(6_411, buffer_access::K2U_READ_ONLY, 48);
    let security_request = canonical_mutation(
        mutation_kind::SET_SECURITY,
        security_body_grant.issued,
        reply.issued,
        BufferRef::default(),
    );
    let security_context = mutation_context(&security_body_grant, &reply, None);
    let security_body = canonical_security_body();
    let security_result =
        canonical_mutation_result(mutation_kind::SET_SECURITY, BufferRef::default());
    assert!(validate_mutation_success_v2(
        &security_request,
        &security_context,
        MutationBodyRefV21::SetSecurity(&security_body),
        &output,
        &security_result,
        MutationKindResultRefV21::None,
        retained,
    )
    .is_ok());
    let mut stale_security =
        canonical_mutation_result(mutation_kind::SET_SECURITY, BufferRef::default());
    stale_security.security_generation = 13;
    assert_eq!(
        validate_mutation_success_v2(
            &security_request,
            &security_context,
            MutationBodyRefV21::SetSecurity(&security_body),
            &output,
            &stale_security,
            MutationKindResultRefV21::None,
            retained,
        ),
        Err(MessageValidationError::Identity)
    );

    let rename_body_grant = mapping_grant(6_421, buffer_access::K2U_READ_ONLY, 80);
    let rename_kind_result = mapping_grant(6_422, buffer_access::U2K_WRITE, 112);
    let rename_request = canonical_mutation(
        mutation_kind::RENAME,
        rename_body_grant.issued,
        reply.issued,
        rename_kind_result.issued,
    );
    let mut same_parent_context =
        mutation_context(&rename_body_grant, &reply, Some(&rename_kind_result));
    same_parent_context.same_parent_rename = true;
    let mut same_parent_body = canonical_rename_body();
    same_parent_body.expected_target_parent_generation = 31;
    let rename_result_env = canonical_mutation_result(
        mutation_kind::RENAME,
        shrunk_reference(&rename_kind_result, 112),
    );
    let mut equal_record = canonical_rename_result();
    equal_record.source_parent_generation = 33;
    equal_record.target_parent_generation = 33;
    assert!(validate_mutation_success_v2(
        &rename_request,
        &same_parent_context,
        MutationBodyRefV21::Rename(&same_parent_body),
        &output,
        &rename_result_env,
        MutationKindResultRefV21::Rename(&equal_record),
        retained,
    )
    .is_ok());
    let mut unequal_record = canonical_rename_result();
    unequal_record.source_parent_generation = 33;
    unequal_record.target_parent_generation = 34;
    assert_eq!(
        validate_mutation_success_v2(
            &rename_request,
            &same_parent_context,
            MutationBodyRefV21::Rename(&same_parent_body),
            &output,
            &rename_result_env,
            MutationKindResultRefV21::Rename(&unequal_record),
            retained,
        ),
        Err(MessageValidationError::Relationship)
    );

    let unlink_record_rows_grant = mapping_grant(6_431, buffer_access::K2U_READ_ONLY, 56);
    let unlink_kind_result = mapping_grant(6_432, buffer_access::U2K_WRITE, 56);
    let unlink_request = canonical_mutation(
        mutation_kind::UNLINK,
        unlink_record_rows_grant.issued,
        reply.issued,
        unlink_kind_result.issued,
    );
    let unlink_context =
        mutation_context(&unlink_record_rows_grant, &reply, Some(&unlink_kind_result));
    let unlink_body = canonical_unlink_body();
    let unlink_result_env = canonical_mutation_result(
        mutation_kind::UNLINK,
        shrunk_reference(&unlink_kind_result, 56),
    );
    let canonical_unlink_record = UnlinkResultV1 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: 1,
            required_flags: 0,
        },
        file_id: FileId { lo: 67, hi: 68 },
        removed_link_id: LinkId { lo: 51, hi: 52 },
        parent_generation: 56,
        remaining_link_count: 1,
        flags: 0,
    };
    let zero_link_body_grant = mapping_grant(6_441, buffer_access::K2U_READ_ONLY, 80);
    let zero_link_kind_result = mapping_grant(6_442, buffer_access::U2K_WRITE, 112);
    let zero_link_request = canonical_mutation(
        mutation_kind::RENAME,
        zero_link_body_grant.issued,
        reply.issued,
        zero_link_kind_result.issued,
    );
    let mut zero_link_body = canonical_rename_body();
    zero_link_body.source_link_id = LinkId { lo: 0, hi: 0 };
    let mut zero_link_record = canonical_rename_result();
    zero_link_record.link_id = LinkId { lo: 0, hi: 0 };
    assert_eq!(
        validate_mutation_success_v2(
            &zero_link_request,
            &mutation_context(&zero_link_body_grant, &reply, Some(&zero_link_kind_result)),
            MutationBodyRefV21::Rename(&zero_link_body),
            &output,
            &canonical_mutation_result(
                mutation_kind::RENAME,
                shrunk_reference(&zero_link_kind_result, 112),
            ),
            MutationKindResultRefV21::Rename(&zero_link_record),
            retained,
        ),
        Err(MessageValidationError::Identity)
    );

    let unlink_record_rows: [MutationRow<UnlinkResultV1, MessageValidationError>; 3] = [
        (
            |record| record.header.struct_version = 2,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |record| record.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |record| record.file_id = FileId { lo: 0, hi: 0 },
            MessageValidationError::Identity,
        ),
    ];
    for (index, (mutate, expected)) in unlink_record_rows.into_iter().enumerate() {
        let mut record = canonical_unlink_record;
        mutate(&mut record);
        assert_eq!(
            validate_mutation_success_v2(
                &unlink_request,
                &unlink_context,
                MutationBodyRefV21::Unlink(&unlink_body),
                &output,
                &unlink_result_env,
                MutationKindResultRefV21::Unlink(&record),
                retained,
            ),
            Err(expected),
            "unlink record row {index}"
        );
    }
}

#[test]
fn commit_create_result_and_query_op_flags_are_closed() {
    let reply = mapping_grant(4_801, buffer_access::U2K_WRITE, 112);
    let request = canonical_commit(reply.issued);
    let output = echo_output(&reply, 112);
    for value in [
        create_result::SUPERSEDED,
        create_result::OPENED,
        create_result::CREATED,
        create_result::OVERWRITTEN,
    ] {
        let mut result = canonical_commit_result();
        result.create_result = value;
        assert!(
            validate_commit_open_success_v2(&request, binding(&reply), &output, &result).is_ok(),
            "create_result={value}"
        );
    }
    for value in [
        create_result::EXISTS,
        create_result::DOES_NOT_EXIST,
        6,
        u32::MAX,
    ] {
        let mut result = canonical_commit_result();
        result.create_result = value;
        assert_eq!(
            validate_commit_open_success_v2(&request, binding(&reply), &output, &result),
            Err(MessageValidationError::InvalidScalar),
            "create_result={value}"
        );
    }
    let mut flagged = canonical_commit_result();
    flagged.result_flags = 1;
    assert_eq!(
        validate_commit_open_success_v2(&request, binding(&reply), &output, &flagged),
        Err(MessageValidationError::FlagsOrReserved)
    );

    let query_reply = mapping_grant(4_802, buffer_access::U2K_WRITE, 56);
    let committed = mapping_grant(4_803, buffer_access::U2K_WRITE, 224);
    let query = canonical_query(query_reply.issued, committed.issued);
    let mut context = QueryOpV2Context {
        reply: binding(&query_reply),
        committed_result: binding(&committed),
        retained_cancelled_no_candidate: false,
    };
    assert!(validate_query_op_v2(&query, &context).is_ok());
    let mut abort_query = query;
    abort_query.header.required_flags = query_op_required_flags::ABORT_IF_PREPARED;
    assert_eq!(
        validate_query_op_v2(&abort_query, &context),
        Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags
        ))
    );
    context.retained_cancelled_no_candidate = true;
    assert!(validate_query_op_v2(&abort_query, &context).is_ok());
    assert!(validate_query_op_v2(&query, &context).is_ok());
    for flags in [0x0002u16, 0x0003, u16::MAX] {
        let mut unknown = query;
        unknown.header.required_flags = flags;
        assert_eq!(
            validate_query_op_v2(&unknown, &context),
            Err(MessageValidationError::Control(
                ControlError::UnsupportedRequiredFlags
            )),
            "flags={flags:#06x}"
        );
    }
}
