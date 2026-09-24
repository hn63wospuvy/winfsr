use core::mem::{align_of, offset_of, size_of};
use std::{
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
};

use fsring_abi::{
    codec::{try_decode, try_encode, Pod},
    durable::{
        durable_child_kind, durable_committed_result_state, durable_immutable_request_state,
        durable_journal_state, durable_key_digest_v1, durable_open_state,
        durable_payload_digest_v1, durable_prepare_state, durable_pt_epoch_intent_state,
        durable_pt_lane_state, durable_query_dir_attempt_state, durable_query_dir_cookie_state,
        durable_query_dir_snapshot_state, durable_record_charge_v1, encode_durable_key_v1,
        encoded_durable_key_len_v1, DurableChildValueV1, DurableKeyIdentityV1, DurableKeyV1,
        DurableNamespaceV1, JournalStateV1, OpenRecoveryPayloadV1, PrepareRecoveryPayloadV1,
        PtEpochIntentPayloadV1, PtLanePayloadV1, QueryDirCookiePayloadV1,
        QueryDirSnapshotPayloadV1, DURABLE_CHILD_VALUE_PREFIX_BYTES,
        IMMUTABLE_REQUEST_DIGEST_BYTES, JOURNAL_STATE_V1_BYTES,
        OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES, PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES,
        PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES, PT_LANE_PAYLOAD_V1_PREFIX_BYTES,
        QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES, QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES,
    },
    ids::{AckToken, BootInstanceId, FileId, LinkId, MountId, OpId, TransactionId},
    msgs::{BlobSlice, ControlHeader, SizeState},
    validate::{
        validate_durable_payload_v1, DurableMetadataError, DurablePayloadError,
        ValidatedDurablePayloadV1,
    },
    FSRING_ABI_MAJOR, FSRING_ABI_MINOR, MAX_FILE_SIZE,
};

const RING_COUNT: u32 = 4;
const FILE: FileId = FileId {
    lo: 0x1111,
    hi: 0x2222,
};
const LINK: LinkId = LinkId {
    lo: 0x3333,
    hi: 0x4444,
};
const PARENT: FileId = FileId {
    lo: 0x5555,
    hi: 0x6666,
};
const OP: OpId = OpId {
    lo: 0x7777,
    hi: 0x8888,
};
const TX: TransactionId = TransactionId {
    lo: 0x9999,
    hi: 0xaaaa,
};
const TOKEN: AckToken = AckToken {
    lo: 0xbbbb,
    hi: 0xcccc,
};

fn namespace() -> DurableNamespaceV1 {
    DurableNamespaceV1 {
        mount_id: MountId { lo: 1, hi: 2 },
        boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
    }
}

fn control(size: u32) -> ControlHeader {
    ControlHeader {
        struct_size: size,
        struct_version: 1,
        required_flags: 0,
    }
}

fn sizes() -> SizeState {
    SizeState {
        allocation_size: 30,
        file_size: 20,
        valid_data_length: 10,
        size_epoch: 1,
    }
}

fn encode_pod<T: Pod>(value: &T) -> Vec<u8> {
    let mut output = vec![0u8; size_of::<T>()];
    assert_eq!(try_encode(value, &mut output).unwrap(), output.len());
    output
}

fn encode_key(identity: DurableKeyIdentityV1) -> Vec<u8> {
    let key = DurableKeyV1 {
        namespace: namespace(),
        identity,
    };
    let needed = usize::try_from(encoded_durable_key_len_v1(&identity)).unwrap();
    let mut output = vec![0xa5; needed + 7];
    assert_eq!(encode_durable_key_v1(&key, &mut output).unwrap(), needed);
    assert!(output[needed..].iter().all(|byte| *byte == 0));
    output.truncate(needed);
    output
}

fn wrap(
    identity: DurableKeyIdentityV1,
    value_kind: u16,
    state: u16,
    payload_bytes: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let key = encode_key(identity);
    let unaligned = DURABLE_CHILD_VALUE_PREFIX_BYTES as usize + payload_bytes.len();
    let struct_size = (unaligned + 7) & !7;
    let payload = if payload_bytes.is_empty() {
        BlobSlice {
            offset: 0,
            length: 0,
        }
    } else {
        BlobSlice {
            offset: DURABLE_CHILD_VALUE_PREFIX_BYTES,
            length: payload_bytes.len().try_into().unwrap(),
        }
    };
    let prefix = DurableChildValueV1 {
        header: control(struct_size.try_into().unwrap()),
        value_kind,
        state,
        flags: 0,
        identity_digest: durable_key_digest_v1(&key, RING_COUNT).unwrap(),
        payload_digest: durable_payload_digest_v1(payload_bytes),
        payload,
    };
    let mut value = vec![0u8; struct_size];
    assert_eq!(
        try_encode(
            &prefix,
            &mut value[..DURABLE_CHILD_VALUE_PREFIX_BYTES as usize]
        )
        .unwrap(),
        DURABLE_CHILD_VALUE_PREFIX_BYTES as usize
    );
    value[DURABLE_CHILD_VALUE_PREFIX_BYTES as usize
        ..DURABLE_CHILD_VALUE_PREFIX_BYTES as usize + payload_bytes.len()]
        .copy_from_slice(payload_bytes);
    (key, value)
}

fn reseal_payload(value: &mut [u8]) {
    let prefix_bytes = DURABLE_CHILD_VALUE_PREFIX_BYTES as usize;
    let mut wrapper: DurableChildValueV1 = try_decode(&value[..prefix_bytes]).unwrap();
    let start = usize::try_from(wrapper.payload.offset).unwrap();
    let end = start + usize::try_from(wrapper.payload.length).unwrap();
    wrapper.payload_digest = durable_payload_digest_v1(&value[start..end]);
    assert_eq!(
        try_encode(&wrapper, &mut value[..prefix_bytes]).unwrap(),
        prefix_bytes
    );
}

fn nested_range(value: &[u8]) -> core::ops::Range<usize> {
    let wrapper: DurableChildValueV1 = try_decode(value).unwrap();
    let start = usize::try_from(wrapper.payload.offset).unwrap();
    let end = start + usize::try_from(wrapper.payload.length).unwrap();
    start..end
}

fn put_nested_u16(value: &mut [u8], offset: usize, field: u16) {
    let start = nested_range(value).start + offset;
    value[start..start + 2].copy_from_slice(&field.to_le_bytes());
}

fn put_nested_u32(value: &mut [u8], offset: usize, field: u32) {
    let start = nested_range(value).start + offset;
    value[start..start + 4].copy_from_slice(&field.to_le_bytes());
}

fn put_nested_u64(value: &mut [u8], offset: usize, field: u64) {
    let start = nested_range(value).start + offset;
    value[start..start + 8].copy_from_slice(&field.to_le_bytes());
}

fn tail_layout<const N: usize>(prefix: u32, segments: [&[u8]; N]) -> ([BlobSlice; N], u32) {
    let mut descriptors = [BlobSlice {
        offset: 0,
        length: 0,
    }; N];
    let mut next = prefix;
    for (index, segment) in segments.iter().enumerate() {
        if !segment.is_empty() {
            let length = u32::try_from(segment.len()).unwrap();
            descriptors[index] = BlobSlice {
                offset: next,
                length,
            };
            next = next.checked_add(length).unwrap();
        }
    }
    (descriptors, next.checked_add(7).unwrap() & !7)
}

fn encode_payload<T: Pod, const N: usize>(
    prefix: &T,
    total: u32,
    descriptors: [BlobSlice; N],
    segments: [&[u8]; N],
) -> Vec<u8> {
    let mut output = vec![0u8; usize::try_from(total).unwrap()];
    assert_eq!(try_encode(prefix, &mut output).unwrap(), size_of::<T>());
    for (descriptor, segment) in descriptors.into_iter().zip(segments) {
        if descriptor.length != 0 {
            let start = usize::try_from(descriptor.offset).unwrap();
            let end = start + usize::try_from(descriptor.length).unwrap();
            output[start..end].copy_from_slice(segment);
        }
    }
    output
}

fn open_payload(name: &[u8], security_descriptor: &[u8]) -> Vec<u8> {
    let segments = [name, security_descriptor];
    let (descriptors, total) = tail_layout(OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES, segments);
    let prefix = OpenRecoveryPayloadV1 {
        header: control(total),
        file_id: FILE,
        link_id: LINK,
        parent_id: PARENT,
        sizes: sizes(),
        namespace_generation: 2,
        security_generation: 3,
        kernel_open_id: 4,
        desired_access: 0x1111_1111,
        granted_access: 0x2222_2222,
        share_access: 0x3333_3333,
        create_options: 0x4444_4444,
        file_attributes: 0x5555_5555,
        disposition: 0x6666_6666,
        name: descriptors[0],
        security_descriptor: descriptors[1],
    };
    encode_payload(&prefix, total, descriptors, segments)
}

fn prepare_payload(name: &[u8], requested_sd: &[u8], ea: &[u8], result_sd: &[u8]) -> Vec<u8> {
    let segments = [name, requested_sd, ea, result_sd];
    let (descriptors, total) = tail_layout(PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES, segments);
    let prefix = PrepareRecoveryPayloadV1 {
        header: control(total),
        parent_id: PARENT,
        transaction_id: TX,
        result_file_id: FILE,
        result_link_id: LINK,
        result_sizes: sizes(),
        result_namespace_generation: 2,
        result_security_generation: 3,
        desired_access: 0x1111_1111,
        share_access: 0x2222_2222,
        disposition: 0x3333_3333,
        create_options: 0x4444_4444,
        file_attributes: 0x5555_5555,
        open_flags: 0,
        result_object_flags: 0,
        reserved: 0,
        name: descriptors[0],
        requested_security_descriptor: descriptors[1],
        ea: descriptors[2],
        result_security_descriptor: descriptors[3],
    };
    encode_payload(&prefix, total, descriptors, segments)
}

fn journal_payload(state: u16) -> Vec<u8> {
    encode_pod(&JournalStateV1 {
        header: control(JOURNAL_STATE_V1_BYTES),
        op_id: OP,
        opcode: 0x1111,
        mutation_kind: 0x2222,
        state: u32::from(state),
        operation_digest: [0x33; 32],
    })
}

fn generic_blob(body: &[u8]) -> Vec<u8> {
    assert_eq!(body.len() % 8, 0);
    let total = 8 + body.len();
    let mut output = vec![0u8; total];
    assert_eq!(
        try_encode(&control(total.try_into().unwrap()), &mut output[..8]).unwrap(),
        8
    );
    output[8..].copy_from_slice(body);
    output
}

fn snapshot_payload(entries: &[u8], entry_count: u64) -> Vec<u8> {
    let segments = [entries];
    let (descriptors, total) = tail_layout(QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES, segments);
    let prefix = QueryDirSnapshotPayloadV1 {
        header: control(total),
        pattern_digest: [0x44; 32],
        entry_count,
        entries: descriptors[0],
    };
    encode_payload(&prefix, total, descriptors, segments)
}

fn cookie_payload(next_cookie: u64) -> Vec<u8> {
    encode_pod(&QueryDirCookiePayloadV1 {
        header: control(QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES),
        next_cookie,
        result_flags: 0,
        reserved: 0,
        attempt_digest: [0x55; 32],
    })
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

fn pt_intent_payload(path: &[u8], sector_size: u32, pt_epoch: u64) -> Vec<u8> {
    let segments = [path];
    let (descriptors, total) = tail_layout(PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES, segments);
    let prefix = PtEpochIntentPayloadV1 {
        header: control(total),
        pt_epoch,
        sector_size,
        flags: 0,
        backing_path: descriptors[0],
    };
    encode_payload(&prefix, total, descriptors, segments)
}

fn pt_lane_payload(high_watermark: u64, tuple_is_zero: bool, pending: &[u8]) -> Vec<u8> {
    let segments = [pending];
    let (descriptors, total) = tail_layout(PT_LANE_PAYLOAD_V1_PREFIX_BYTES, segments);
    let prefix = PtLanePayloadV1 {
        header: control(total),
        high_watermark,
        latest_token: if tuple_is_zero { AckToken::ZERO } else { TOKEN },
        latest_file_id: if tuple_is_zero { FileId::ZERO } else { FILE },
        latest_pt_epoch: if tuple_is_zero { 0 } else { 7 },
        latest_notify_code: if tuple_is_zero { 0 } else { 8 },
        flags: 0,
        reserved: 0,
        pending_envelope: descriptors[0],
    };
    encode_payload(&prefix, total, descriptors, segments)
}

fn expect_error(key: &[u8], value: &[u8], expected: DurablePayloadError) {
    match validate_durable_payload_v1(key, value, RING_COUNT) {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("malformed durable payload unexpectedly validated"),
    }
}

fn assert_borrowed_from(owner: &[u8], borrowed: &[u8]) {
    let owner_start = owner.as_ptr() as usize;
    let owner_end = owner_start + owner.len();
    let borrowed_start = borrowed.as_ptr() as usize;
    let borrowed_end = borrowed_start + borrowed.len();
    assert!(borrowed_start >= owner_start);
    assert!(borrowed_end <= owner_end);
}

fn assert_pod<T: Pod>() {}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_pair(output: &mut [u8], offset: usize, lo: u64, hi: u64) {
    put_u64(output, offset, lo);
    put_u64(output, offset + 8, hi);
}

#[test]
fn public_surface_constants_layouts_and_pod_are_exact() {
    assert_eq!(OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES, 152);
    assert_eq!(PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES, 184);
    assert_eq!(JOURNAL_STATE_V1_BYTES, 64);
    assert_eq!(QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES, 56);
    assert_eq!(QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES, 56);
    assert_eq!(PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES, 32);
    assert_eq!(PT_LANE_PAYLOAD_V1_PREFIX_BYTES, 72);
    assert_eq!(IMMUTABLE_REQUEST_DIGEST_BYTES, 32);

    assert_pod::<OpenRecoveryPayloadV1>();
    assert_pod::<PrepareRecoveryPayloadV1>();
    assert_pod::<JournalStateV1>();
    assert_pod::<QueryDirSnapshotPayloadV1>();
    assert_pod::<QueryDirCookiePayloadV1>();
    assert_pod::<PtEpochIntentPayloadV1>();
    assert_pod::<PtLanePayloadV1>();

    assert_eq!(
        (
            size_of::<OpenRecoveryPayloadV1>(),
            align_of::<OpenRecoveryPayloadV1>()
        ),
        (152, 8)
    );
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, header), 0);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, file_id), 8);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, link_id), 24);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, parent_id), 40);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, sizes), 56);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, namespace_generation), 88);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, security_generation), 96);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, kernel_open_id), 104);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, desired_access), 112);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, granted_access), 116);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, share_access), 120);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, create_options), 124);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, file_attributes), 128);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, disposition), 132);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, name), 136);
    assert_eq!(offset_of!(OpenRecoveryPayloadV1, security_descriptor), 144);

    assert_eq!(
        (
            size_of::<PrepareRecoveryPayloadV1>(),
            align_of::<PrepareRecoveryPayloadV1>()
        ),
        (184, 8)
    );
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, header), 0);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, parent_id), 8);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, transaction_id), 24);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, result_file_id), 40);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, result_link_id), 56);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, result_sizes), 72);
    assert_eq!(
        offset_of!(PrepareRecoveryPayloadV1, result_namespace_generation),
        104
    );
    assert_eq!(
        offset_of!(PrepareRecoveryPayloadV1, result_security_generation),
        112
    );
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, desired_access), 120);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, share_access), 124);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, disposition), 128);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, create_options), 132);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, file_attributes), 136);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, open_flags), 140);
    assert_eq!(
        offset_of!(PrepareRecoveryPayloadV1, result_object_flags),
        144
    );
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, reserved), 148);
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, name), 152);
    assert_eq!(
        offset_of!(PrepareRecoveryPayloadV1, requested_security_descriptor),
        160
    );
    assert_eq!(offset_of!(PrepareRecoveryPayloadV1, ea), 168);
    assert_eq!(
        offset_of!(PrepareRecoveryPayloadV1, result_security_descriptor),
        176
    );

    assert_eq!(
        (size_of::<JournalStateV1>(), align_of::<JournalStateV1>()),
        (64, 8)
    );
    assert_eq!(offset_of!(JournalStateV1, header), 0);
    assert_eq!(offset_of!(JournalStateV1, op_id), 8);
    assert_eq!(offset_of!(JournalStateV1, opcode), 24);
    assert_eq!(offset_of!(JournalStateV1, mutation_kind), 26);
    assert_eq!(offset_of!(JournalStateV1, state), 28);
    assert_eq!(offset_of!(JournalStateV1, operation_digest), 32);

    assert_eq!(
        (
            size_of::<QueryDirSnapshotPayloadV1>(),
            align_of::<QueryDirSnapshotPayloadV1>()
        ),
        (56, 8)
    );
    assert_eq!(offset_of!(QueryDirSnapshotPayloadV1, header), 0);
    assert_eq!(offset_of!(QueryDirSnapshotPayloadV1, pattern_digest), 8);
    assert_eq!(offset_of!(QueryDirSnapshotPayloadV1, entry_count), 40);
    assert_eq!(offset_of!(QueryDirSnapshotPayloadV1, entries), 48);

    assert_eq!(
        (
            size_of::<QueryDirCookiePayloadV1>(),
            align_of::<QueryDirCookiePayloadV1>()
        ),
        (56, 8)
    );
    assert_eq!(offset_of!(QueryDirCookiePayloadV1, header), 0);
    assert_eq!(offset_of!(QueryDirCookiePayloadV1, next_cookie), 8);
    assert_eq!(offset_of!(QueryDirCookiePayloadV1, result_flags), 16);
    assert_eq!(offset_of!(QueryDirCookiePayloadV1, reserved), 20);
    assert_eq!(offset_of!(QueryDirCookiePayloadV1, attempt_digest), 24);

    assert_eq!(
        (
            size_of::<PtEpochIntentPayloadV1>(),
            align_of::<PtEpochIntentPayloadV1>()
        ),
        (32, 8)
    );
    assert_eq!(offset_of!(PtEpochIntentPayloadV1, header), 0);
    assert_eq!(offset_of!(PtEpochIntentPayloadV1, pt_epoch), 8);
    assert_eq!(offset_of!(PtEpochIntentPayloadV1, sector_size), 16);
    assert_eq!(offset_of!(PtEpochIntentPayloadV1, flags), 20);
    assert_eq!(offset_of!(PtEpochIntentPayloadV1, backing_path), 24);

    assert_eq!(
        (size_of::<PtLanePayloadV1>(), align_of::<PtLanePayloadV1>()),
        (72, 8)
    );
    assert_eq!(offset_of!(PtLanePayloadV1, header), 0);
    assert_eq!(offset_of!(PtLanePayloadV1, high_watermark), 8);
    assert_eq!(offset_of!(PtLanePayloadV1, latest_token), 16);
    assert_eq!(offset_of!(PtLanePayloadV1, latest_file_id), 32);
    assert_eq!(offset_of!(PtLanePayloadV1, latest_pt_epoch), 48);
    assert_eq!(offset_of!(PtLanePayloadV1, latest_notify_code), 56);
    assert_eq!(offset_of!(PtLanePayloadV1, flags), 58);
    assert_eq!(offset_of!(PtLanePayloadV1, reserved), 60);
    assert_eq!(offset_of!(PtLanePayloadV1, pending_envelope), 64);
}

#[test]
fn all_seven_prefixes_have_independent_little_endian_goldens() {
    let open = OpenRecoveryPayloadV1 {
        header: ControlHeader {
            struct_size: 0x0403_0201,
            struct_version: 0x0605,
            required_flags: 0x0807,
        },
        file_id: FileId {
            lo: 0x1817_1615_1413_1211,
            hi: 0x2827_2625_2423_2221,
        },
        link_id: LinkId {
            lo: 0x3837_3635_3433_3231,
            hi: 0x4847_4645_4443_4241,
        },
        parent_id: FileId {
            lo: 0x5857_5655_5453_5251,
            hi: 0x6867_6665_6463_6261,
        },
        sizes: SizeState {
            allocation_size: 0x7877_7675_7473_7271,
            file_size: 0x8887_8685_8483_8281,
            valid_data_length: 0x9897_9695_9493_9291,
            size_epoch: 0xa8a7_a6a5_a4a3_a2a1,
        },
        namespace_generation: 0xb8b7_b6b5_b4b3_b2b1,
        security_generation: 0xc8c7_c6c5_c4c3_c2c1,
        kernel_open_id: 0xd8d7_d6d5_d4d3_d2d1,
        desired_access: 0xe4e3_e2e1,
        granted_access: 0xf4f3_f2f1,
        share_access: 0x1413_1211,
        create_options: 0x2423_2221,
        file_attributes: 0x3433_3231,
        disposition: 0x4443_4241,
        name: BlobSlice {
            offset: 0x5453_5251,
            length: 0x6463_6261,
        },
        security_descriptor: BlobSlice {
            offset: 0x7473_7271,
            length: 0x8483_8281,
        },
    };
    let actual = encode_pod(&open);
    let mut expected = vec![0u8; 152];
    put_u32(&mut expected, 0, 0x0403_0201);
    put_u16(&mut expected, 4, 0x0605);
    put_u16(&mut expected, 6, 0x0807);
    put_pair(
        &mut expected,
        8,
        0x1817_1615_1413_1211,
        0x2827_2625_2423_2221,
    );
    put_pair(
        &mut expected,
        24,
        0x3837_3635_3433_3231,
        0x4847_4645_4443_4241,
    );
    put_pair(
        &mut expected,
        40,
        0x5857_5655_5453_5251,
        0x6867_6665_6463_6261,
    );
    put_u64(&mut expected, 56, 0x7877_7675_7473_7271);
    put_u64(&mut expected, 64, 0x8887_8685_8483_8281);
    put_u64(&mut expected, 72, 0x9897_9695_9493_9291);
    put_u64(&mut expected, 80, 0xa8a7_a6a5_a4a3_a2a1);
    put_u64(&mut expected, 88, 0xb8b7_b6b5_b4b3_b2b1);
    put_u64(&mut expected, 96, 0xc8c7_c6c5_c4c3_c2c1);
    put_u64(&mut expected, 104, 0xd8d7_d6d5_d4d3_d2d1);
    put_u32(&mut expected, 112, 0xe4e3_e2e1);
    put_u32(&mut expected, 116, 0xf4f3_f2f1);
    put_u32(&mut expected, 120, 0x1413_1211);
    put_u32(&mut expected, 124, 0x2423_2221);
    put_u32(&mut expected, 128, 0x3433_3231);
    put_u32(&mut expected, 132, 0x4443_4241);
    put_u32(&mut expected, 136, 0x5453_5251);
    put_u32(&mut expected, 140, 0x6463_6261);
    put_u32(&mut expected, 144, 0x7473_7271);
    put_u32(&mut expected, 148, 0x8483_8281);
    assert_eq!(actual, expected);

    let prepare = PrepareRecoveryPayloadV1 {
        header: ControlHeader {
            struct_size: 0x0c0b_0a09,
            struct_version: 0x0e0d,
            required_flags: 0x100f,
        },
        parent_id: FileId {
            lo: 0x201f_1e1d_1c1b_1a19,
            hi: 0x302f_2e2d_2c2b_2a29,
        },
        transaction_id: TransactionId {
            lo: 0x403f_3e3d_3c3b_3a39,
            hi: 0x504f_4e4d_4c4b_4a49,
        },
        result_file_id: FileId {
            lo: 0x605f_5e5d_5c5b_5a59,
            hi: 0x706f_6e6d_6c6b_6a69,
        },
        result_link_id: LinkId {
            lo: 0x807f_7e7d_7c7b_7a79,
            hi: 0x908f_8e8d_8c8b_8a89,
        },
        result_sizes: SizeState {
            allocation_size: 0xa09f_9e9d_9c9b_9a99,
            file_size: 0xb0af_aead_acab_aaa9,
            valid_data_length: 0xc0bf_bebd_bcbb_bab9,
            size_epoch: 0xd0cf_cecd_cccb_cac9,
        },
        result_namespace_generation: 0xe0df_dedd_dcdb_dad9,
        result_security_generation: 0xf0ef_eeed_eceb_eae9,
        desired_access: 0x201f_1e1d,
        share_access: 0x302f_2e2d,
        disposition: 0x403f_3e3d,
        create_options: 0x504f_4e4d,
        file_attributes: 0x605f_5e5d,
        open_flags: 0x706f_6e6d,
        result_object_flags: 0x807f_7e7d,
        reserved: 0x908f_8e8d,
        name: BlobSlice {
            offset: 0xa09f_9e9d,
            length: 0xb0af_aead,
        },
        requested_security_descriptor: BlobSlice {
            offset: 0xc0bf_bebd,
            length: 0xd0cf_cecd,
        },
        ea: BlobSlice {
            offset: 0xe0df_dedd,
            length: 0xf0ef_eeed,
        },
        result_security_descriptor: BlobSlice {
            offset: 0x1817_1615,
            length: 0x2827_2625,
        },
    };
    let actual = encode_pod(&prepare);
    let mut expected = vec![0u8; 184];
    put_u32(&mut expected, 0, 0x0c0b_0a09);
    put_u16(&mut expected, 4, 0x0e0d);
    put_u16(&mut expected, 6, 0x100f);
    put_pair(
        &mut expected,
        8,
        0x201f_1e1d_1c1b_1a19,
        0x302f_2e2d_2c2b_2a29,
    );
    put_pair(
        &mut expected,
        24,
        0x403f_3e3d_3c3b_3a39,
        0x504f_4e4d_4c4b_4a49,
    );
    put_pair(
        &mut expected,
        40,
        0x605f_5e5d_5c5b_5a59,
        0x706f_6e6d_6c6b_6a69,
    );
    put_pair(
        &mut expected,
        56,
        0x807f_7e7d_7c7b_7a79,
        0x908f_8e8d_8c8b_8a89,
    );
    put_u64(&mut expected, 72, 0xa09f_9e9d_9c9b_9a99);
    put_u64(&mut expected, 80, 0xb0af_aead_acab_aaa9);
    put_u64(&mut expected, 88, 0xc0bf_bebd_bcbb_bab9);
    put_u64(&mut expected, 96, 0xd0cf_cecd_cccb_cac9);
    put_u64(&mut expected, 104, 0xe0df_dedd_dcdb_dad9);
    put_u64(&mut expected, 112, 0xf0ef_eeed_eceb_eae9);
    put_u32(&mut expected, 120, 0x201f_1e1d);
    put_u32(&mut expected, 124, 0x302f_2e2d);
    put_u32(&mut expected, 128, 0x403f_3e3d);
    put_u32(&mut expected, 132, 0x504f_4e4d);
    put_u32(&mut expected, 136, 0x605f_5e5d);
    put_u32(&mut expected, 140, 0x706f_6e6d);
    put_u32(&mut expected, 144, 0x807f_7e7d);
    put_u32(&mut expected, 148, 0x908f_8e8d);
    put_u32(&mut expected, 152, 0xa09f_9e9d);
    put_u32(&mut expected, 156, 0xb0af_aead);
    put_u32(&mut expected, 160, 0xc0bf_bebd);
    put_u32(&mut expected, 164, 0xd0cf_cecd);
    put_u32(&mut expected, 168, 0xe0df_dedd);
    put_u32(&mut expected, 172, 0xf0ef_eeed);
    put_u32(&mut expected, 176, 0x1817_1615);
    put_u32(&mut expected, 180, 0x2827_2625);
    assert_eq!(actual, expected);

    let journal = JournalStateV1 {
        header: ControlHeader {
            struct_size: 0x3433_3231,
            struct_version: 0x3635,
            required_flags: 0x3837,
        },
        op_id: OpId {
            lo: 0x4847_4645_4443_4241,
            hi: 0x5857_5655_5453_5251,
        },
        opcode: 0x6261,
        mutation_kind: 0x6463,
        state: 0x6867_6665,
        operation_digest: [0x79; 32],
    };
    let actual = encode_pod(&journal);
    let mut expected = vec![0u8; 64];
    put_u32(&mut expected, 0, 0x3433_3231);
    put_u16(&mut expected, 4, 0x3635);
    put_u16(&mut expected, 6, 0x3837);
    put_pair(
        &mut expected,
        8,
        0x4847_4645_4443_4241,
        0x5857_5655_5453_5251,
    );
    put_u16(&mut expected, 24, 0x6261);
    put_u16(&mut expected, 26, 0x6463);
    put_u32(&mut expected, 28, 0x6867_6665);
    expected[32..64].fill(0x79);
    assert_eq!(actual, expected);

    let snapshot = QueryDirSnapshotPayloadV1 {
        header: ControlHeader {
            struct_size: 0x7473_7271,
            struct_version: 0x7675,
            required_flags: 0x7877,
        },
        pattern_digest: [0x89; 32],
        entry_count: 0x9897_9695_9493_9291,
        entries: BlobSlice {
            offset: 0xa4a3_a2a1,
            length: 0xb4b3_b2b1,
        },
    };
    let actual = encode_pod(&snapshot);
    let mut expected = vec![0u8; 56];
    put_u32(&mut expected, 0, 0x7473_7271);
    put_u16(&mut expected, 4, 0x7675);
    put_u16(&mut expected, 6, 0x7877);
    expected[8..40].fill(0x89);
    put_u64(&mut expected, 40, 0x9897_9695_9493_9291);
    put_u32(&mut expected, 48, 0xa4a3_a2a1);
    put_u32(&mut expected, 52, 0xb4b3_b2b1);
    assert_eq!(actual, expected);

    let cookie = QueryDirCookiePayloadV1 {
        header: ControlHeader {
            struct_size: 0xc4c3_c2c1,
            struct_version: 0xc6c5,
            required_flags: 0xc8c7,
        },
        next_cookie: 0xd8d7_d6d5_d4d3_d2d1,
        result_flags: 0xe4e3_e2e1,
        reserved: 0xf4f3_f2f1,
        attempt_digest: [0x5a; 32],
    };
    let actual = encode_pod(&cookie);
    let mut expected = vec![0u8; 56];
    put_u32(&mut expected, 0, 0xc4c3_c2c1);
    put_u16(&mut expected, 4, 0xc6c5);
    put_u16(&mut expected, 6, 0xc8c7);
    put_u64(&mut expected, 8, 0xd8d7_d6d5_d4d3_d2d1);
    put_u32(&mut expected, 16, 0xe4e3_e2e1);
    put_u32(&mut expected, 20, 0xf4f3_f2f1);
    expected[24..56].fill(0x5a);
    assert_eq!(actual, expected);

    let intent = PtEpochIntentPayloadV1 {
        header: ControlHeader {
            struct_size: 0x1413_1211,
            struct_version: 0x1615,
            required_flags: 0x1817,
        },
        pt_epoch: 0x2827_2625_2423_2221,
        sector_size: 0x3433_3231,
        flags: 0x4443_4241,
        backing_path: BlobSlice {
            offset: 0x5453_5251,
            length: 0x6463_6261,
        },
    };
    let actual = encode_pod(&intent);
    let mut expected = vec![0u8; 32];
    put_u32(&mut expected, 0, 0x1413_1211);
    put_u16(&mut expected, 4, 0x1615);
    put_u16(&mut expected, 6, 0x1817);
    put_u64(&mut expected, 8, 0x2827_2625_2423_2221);
    put_u32(&mut expected, 16, 0x3433_3231);
    put_u32(&mut expected, 20, 0x4443_4241);
    put_u32(&mut expected, 24, 0x5453_5251);
    put_u32(&mut expected, 28, 0x6463_6261);
    assert_eq!(actual, expected);

    let lane = PtLanePayloadV1 {
        header: ControlHeader {
            struct_size: 0x7473_7271,
            struct_version: 0x7675,
            required_flags: 0x7877,
        },
        high_watermark: 0x8887_8685_8483_8281,
        latest_token: AckToken {
            lo: 0x9897_9695_9493_9291,
            hi: 0xa8a7_a6a5_a4a3_a2a1,
        },
        latest_file_id: FileId {
            lo: 0xb8b7_b6b5_b4b3_b2b1,
            hi: 0xc8c7_c6c5_c4c3_c2c1,
        },
        latest_pt_epoch: 0xd8d7_d6d5_d4d3_d2d1,
        latest_notify_code: 0xe2e1,
        flags: 0xe4e3,
        reserved: 0xf4f3_f2f1,
        pending_envelope: BlobSlice {
            offset: 0x1413_1211,
            length: 0x2423_2221,
        },
    };
    let actual = encode_pod(&lane);
    let mut expected = vec![0u8; 72];
    put_u32(&mut expected, 0, 0x7473_7271);
    put_u16(&mut expected, 4, 0x7675);
    put_u16(&mut expected, 6, 0x7877);
    put_u64(&mut expected, 8, 0x8887_8685_8483_8281);
    put_pair(
        &mut expected,
        16,
        0x9897_9695_9493_9291,
        0xa8a7_a6a5_a4a3_a2a1,
    );
    put_pair(
        &mut expected,
        32,
        0xb8b7_b6b5_b4b3_b2b1,
        0xc8c7_c6c5_c4c3_c2c1,
    );
    put_u64(&mut expected, 48, 0xd8d7_d6d5_d4d3_d2d1);
    put_u16(&mut expected, 56, 0xe2e1);
    put_u16(&mut expected, 58, 0xe4e3);
    put_u32(&mut expected, 60, 0xf4f3_f2f1);
    put_u32(&mut expected, 64, 0x1413_1211);
    put_u32(&mut expected, 68, 0x2423_2221);
    assert_eq!(actual, expected);
}

#[test]
fn open_valid_states_and_borrowed_tails_are_exact() {
    for state in [durable_open_state::LIVE, durable_open_state::CLEANED] {
        let payload = open_payload(b"name", b"sd");
        let (key, value) = wrap(
            DurableKeyIdentityV1::Open { kernel_open_id: 4 },
            durable_child_kind::OPEN,
            state,
            &payload,
        );
        match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
            ValidatedDurablePayloadV1::Open {
                prefix,
                name,
                security_descriptor,
            } => {
                assert_eq!(prefix.kernel_open_id, 4);
                assert_eq!(name, b"name");
                assert_eq!(security_descriptor, b"sd");
                assert_borrowed_from(&value, name);
                assert_borrowed_from(&value, security_descriptor);
            }
            _ => panic!("wrong Open view"),
        }
    }

    let payload = open_payload(&[], b"sd");
    let (key, value) = wrap(
        DurableKeyIdentityV1::Open { kernel_open_id: 4 },
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::Open {
            name,
            security_descriptor,
            ..
        } => {
            assert!(name.is_empty());
            assert_eq!(security_descriptor, b"sd");
            assert_borrowed_from(&value, name);
            assert_borrowed_from(&value, security_descriptor);
        }
        _ => panic!("wrong Open view"),
    }
}

#[test]
fn prepare_valid_view_tails_and_charge_are_exact() {
    let payload = prepare_payload(b"n", b"requested", b"ea", b"result");
    let (key, value) = wrap(
        DurableKeyIdentityV1::Prepare { op_id: OP },
        durable_child_kind::PREPARE,
        durable_prepare_state::PREPARED,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::Prepare {
            name,
            requested_security_descriptor,
            ea,
            result_security_descriptor,
            ..
        } => {
            assert_eq!(name, b"n");
            assert_eq!(requested_security_descriptor, b"requested");
            assert_eq!(ea, b"ea");
            assert_eq!(result_security_descriptor, b"result");
            for borrowed in [
                name,
                requested_security_descriptor,
                ea,
                result_security_descriptor,
            ] {
                assert_borrowed_from(&value, borrowed);
            }
        }
        _ => panic!("wrong Prepare view"),
    }

    let payload = prepare_payload(&[], &[], &[], &[]);
    let (key, value) = wrap(
        DurableKeyIdentityV1::Prepare { op_id: OP },
        durable_child_kind::PREPARE,
        durable_prepare_state::PREPARED,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::Prepare {
            name,
            requested_security_descriptor,
            ea,
            result_security_descriptor,
            ..
        } => {
            for borrowed in [
                name,
                requested_security_descriptor,
                ea,
                result_security_descriptor,
            ] {
                assert!(borrowed.is_empty());
                assert_borrowed_from(&value, borrowed);
            }
        }
        _ => panic!("wrong Prepare view"),
    }

    assert_eq!(durable_record_charge_v1(50, 272), Ok(392));
    for lengths in [[1u64, 2, 3, 4], [0, 7, 8, 9], [15, 0, 1, 0]] {
        let tail_sum = lengths.into_iter().sum::<u64>();
        let aligned_tail = tail_sum.checked_add(7).unwrap() & !7;
        assert_eq!(
            durable_record_charge_v1(50, 272 + aligned_tail),
            Ok(392 + aligned_tail)
        );
    }
}

#[test]
fn immutable_and_committed_future_bytes_are_borrowed_and_opaque() {
    for semantic in [&[][..], &[1, 2, 3, 4, 5][..]] {
        let mut payload = vec![0x77; 32];
        payload.extend_from_slice(semantic);
        let (key, value) = wrap(
            DurableKeyIdentityV1::ImmutableRequest { op_id: OP },
            durable_child_kind::IMMUTABLE_REQUEST,
            durable_immutable_request_state::RETAINED,
            &payload,
        );
        match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
            ValidatedDurablePayloadV1::ImmutableRequest {
                operation_digest,
                semantic_bytes,
            } => {
                assert_eq!(operation_digest, [0x77; 32]);
                assert_eq!(semantic_bytes, semantic);
                assert_borrowed_from(&value, semantic_bytes);
            }
            _ => panic!("wrong immutable view"),
        }
    }

    let payload = generic_blob(&[0xa5; 8]);
    let (key, value) = wrap(
        DurableKeyIdentityV1::CommittedResult { op_id: OP },
        durable_child_kind::COMMITTED_RESULT,
        durable_committed_result_state::COMMITTED,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::CommittedResult { bytes } => {
            assert_eq!(bytes, payload);
            assert_borrowed_from(&value, bytes);
        }
        _ => panic!("wrong committed-result view"),
    }
}

#[test]
fn journal_valid_states_and_identity_are_exact() {
    for state in [
        durable_journal_state::PREPARED,
        durable_journal_state::COMMITTED,
    ] {
        let payload = journal_payload(state);
        let (key, value) = wrap(
            DurableKeyIdentityV1::Journal { op_id: OP },
            durable_child_kind::JOURNAL,
            state,
            &payload,
        );
        match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
            ValidatedDurablePayloadV1::Journal { record } => {
                assert_eq!(record.op_id, OP);
                assert_eq!(record.state, u32::from(state));
                assert_eq!(record.opcode, 0x1111);
            }
            _ => panic!("wrong Journal view"),
        }
    }
}

#[test]
fn query_dir_snapshot_attempt_and_cookie_views_are_exact() {
    let payload = snapshot_payload(b"opaque-entries", 2);
    let (key, value) = wrap(
        DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id: 4,
            generation: 5,
        },
        durable_child_kind::QUERY_DIR_SNAPSHOT,
        durable_query_dir_snapshot_state::ACTIVE,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::QueryDirSnapshot { prefix, entries } => {
            assert_eq!(prefix.entry_count, 2);
            assert_eq!(entries, b"opaque-entries");
            assert_borrowed_from(&value, entries);
        }
        _ => panic!("wrong QueryDir snapshot view"),
    }

    let payload = snapshot_payload(&[], 0);
    let (key, value) = wrap(
        DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id: 4,
            generation: 5,
        },
        durable_child_kind::QUERY_DIR_SNAPSHOT,
        durable_query_dir_snapshot_state::ACTIVE,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::QueryDirSnapshot { entries, .. } => {
            assert!(entries.is_empty());
            assert_borrowed_from(&value, entries);
        }
        _ => panic!("wrong QueryDir snapshot view"),
    }

    let payload = generic_blob(&[0xc3; 16]);
    let (key, value) = wrap(
        DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id: 4,
            generation: 5,
            input_cookie: 6,
            attempt_digest: [0x66; 32],
        },
        durable_child_kind::QUERY_DIR_ATTEMPT,
        durable_query_dir_attempt_state::ACCEPTED,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::QueryDirAttempt { bytes } => {
            assert_eq!(bytes, payload);
            assert_borrowed_from(&value, bytes);
        }
        _ => panic!("wrong QueryDir attempt view"),
    }

    for next_cookie in [0, u64::MAX] {
        let payload = cookie_payload(next_cookie);
        let (key, value) = wrap(
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 4,
                generation: 5,
                cookie: 6,
            },
            durable_child_kind::QUERY_DIR_COOKIE,
            durable_query_dir_cookie_state::ACTIVE,
            &payload,
        );
        match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
            ValidatedDurablePayloadV1::QueryDirCookie { record } => {
                assert_eq!(record.next_cookie, next_cookie);
            }
            _ => panic!("wrong QueryDir cookie view"),
        }
    }
}

#[test]
fn pt_epoch_all_states_sector_boundaries_and_backing_path_are_exact() {
    for state in [
        durable_pt_epoch_intent_state::PENDING,
        durable_pt_epoch_intent_state::ACCEPTED,
        durable_pt_epoch_intent_state::REVOKED,
    ] {
        for sector_size in [512, 65_536] {
            let path = utf16le("\\dEvIcE\\HarddiskVolume1\\winfsr.dat");
            let payload = pt_intent_payload(&path, sector_size, 7);
            let (key, value) = wrap(
                DurableKeyIdentityV1::PtEpochIntent {
                    file_id: FILE,
                    pt_epoch: 7,
                },
                durable_child_kind::PT_EPOCH_INTENT,
                state,
                &payload,
            );
            match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
                ValidatedDurablePayloadV1::PtEpochIntent {
                    prefix,
                    backing_path,
                } => {
                    assert_eq!(prefix.sector_size, sector_size);
                    assert_eq!(backing_path, path);
                    assert_borrowed_from(&value, backing_path);
                }
                _ => panic!("wrong PT epoch-intent view"),
            }
        }
    }

    let surrogate_path = utf16le("\\Device\\disk😀");
    let payload = pt_intent_payload(&surrogate_path, 4096, 7);
    let (key, value) = wrap(
        DurableKeyIdentityV1::PtEpochIntent {
            file_id: FILE,
            pt_epoch: 7,
        },
        durable_child_kind::PT_EPOCH_INTENT,
        durable_pt_epoch_intent_state::PENDING,
        &payload,
    );
    assert!(validate_durable_payload_v1(&key, &value, RING_COUNT).is_ok());
}

#[test]
fn pt_lane_zero_and_nonzero_watermarks_are_exact() {
    let payload = pt_lane_payload(0, true, &[]);
    let (key, value) = wrap(
        DurableKeyIdentityV1::PtLane {
            ring_index: 1,
            kind_ordinal: 2,
        },
        durable_child_kind::PT_LANE,
        durable_pt_lane_state::PRESENT,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::PtLane {
            prefix,
            pending_envelope,
        } => {
            assert_eq!(prefix.high_watermark, 0);
            assert!(pending_envelope.is_none());
        }
        _ => panic!("wrong PT lane view"),
    }

    let pending = generic_blob(&[0x91; 8]);
    let payload = pt_lane_payload(9, false, &pending);
    let (key, value) = wrap(
        DurableKeyIdentityV1::PtLane {
            ring_index: 1,
            kind_ordinal: 2,
        },
        durable_child_kind::PT_LANE,
        durable_pt_lane_state::PRESENT,
        &payload,
    );
    match validate_durable_payload_v1(&key, &value, RING_COUNT).unwrap() {
        ValidatedDurablePayloadV1::PtLane {
            pending_envelope, ..
        } => {
            let pending_envelope = pending_envelope.unwrap();
            assert_eq!(pending_envelope, pending);
            assert_borrowed_from(&value, pending_envelope);
        }
        _ => panic!("wrong PT lane view"),
    }
}

#[test]
fn generic_future_blob_framing_is_closed_but_semantics_are_opaque() {
    for length in 0..8 {
        let payload = vec![0u8; length];
        let (key, value) = wrap(
            DurableKeyIdentityV1::CommittedResult { op_id: OP },
            durable_child_kind::COMMITTED_RESULT,
            durable_committed_result_state::COMMITTED,
            &payload,
        );
        expect_error(&key, &value, DurablePayloadError::InvalidLength);
    }

    for (offset, bytes) in [(4usize, 2u16.to_le_bytes()), (6, 1u16.to_le_bytes())] {
        let payload = generic_blob(&[]);
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::CommittedResult { op_id: OP },
            durable_child_kind::COMMITTED_RESULT,
            durable_committed_result_state::COMMITTED,
            &payload,
        );
        let start = nested_range(&value).start + offset;
        value[start..start + 2].copy_from_slice(&bytes);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::Header);
    }

    let mut wrong_size = generic_blob(&[]);
    wrong_size[0..4].copy_from_slice(&16u32.to_le_bytes());
    let (key, value) = wrap(
        DurableKeyIdentityV1::CommittedResult { op_id: OP },
        durable_child_kind::COMMITTED_RESULT,
        durable_committed_result_state::COMMITTED,
        &wrong_size,
    );
    expect_error(&key, &value, DurablePayloadError::Header);

    let mut unaligned = generic_blob(&[]);
    unaligned.extend_from_slice(&[1]);
    unaligned[0..4].copy_from_slice(&9u32.to_le_bytes());
    let (key, value) = wrap(
        DurableKeyIdentityV1::CommittedResult { op_id: OP },
        durable_child_kind::COMMITTED_RESULT,
        durable_committed_result_state::COMMITTED,
        &unaligned,
    );
    expect_error(&key, &value, DurablePayloadError::Header);
}

#[test]
fn query_dir_attempt_accepts_opaque_future_semantics() {
    for body in [&[][..], &[0xff; 8][..], &[0xa5; 24][..]] {
        let payload = generic_blob(body);
        let (key, value) = wrap(
            DurableKeyIdentityV1::QueryDirAttempt {
                kernel_open_id: 4,
                generation: 5,
                input_cookie: 6,
                attempt_digest: [0; 32],
            },
            durable_child_kind::QUERY_DIR_ATTEMPT,
            durable_query_dir_attempt_state::ACCEPTED,
            &payload,
        );
        assert!(validate_durable_payload_v1(&key, &value, RING_COUNT).is_ok());
    }
}

#[test]
fn scalar_identity_flag_and_relationship_errors_are_exact() {
    let open_identity = DurableKeyIdentityV1::Open { kernel_open_id: 4 };

    let (key, mut value) = wrap(
        open_identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    put_nested_u64(&mut value, 104, 5);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::Identity);

    for pair_offset in [8usize, 24, 40] {
        let (key, mut value) = wrap(
            open_identity,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            &open_payload(&[], &[]),
        );
        put_nested_u64(&mut value, pair_offset, 0);
        put_nested_u64(&mut value, pair_offset + 8, 0);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    for scalar_offset in [80usize, 88, 96, 104] {
        let (key, mut value) = wrap(
            open_identity,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            &open_payload(&[], &[]),
        );
        put_nested_u64(&mut value, scalar_offset, 0);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    for size_offset in [56usize, 64, 72] {
        let (key, mut value) = wrap(
            open_identity,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            &open_payload(&[], &[]),
        );
        put_nested_u64(&mut value, size_offset, MAX_FILE_SIZE + 1);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    let (key, mut value) = wrap(
        open_identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    put_nested_u64(&mut value, 56, 10);
    put_nested_u64(&mut value, 64, 20);
    put_nested_u64(&mut value, 72, 5);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::Relationship);

    for flag_offset in [140, 144, 148] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            durable_prepare_state::PREPARED,
            &prepare_payload(&[], &[], &[], &[]),
        );
        put_nested_u32(&mut value, flag_offset, 1);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::FlagsOrReserved);
    }

    for flag_offset in [16, 20] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 4,
                generation: 5,
                cookie: 6,
            },
            durable_child_kind::QUERY_DIR_COOKIE,
            durable_query_dir_cookie_state::ACTIVE,
            &cookie_payload(0),
        );
        put_nested_u32(&mut value, flag_offset, 1);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::FlagsOrReserved);
    }
}

#[test]
fn journal_relationship_error_is_exact() {
    let (key, mut value) = wrap(
        DurableKeyIdentityV1::Journal { op_id: OP },
        durable_child_kind::JOURNAL,
        durable_journal_state::PREPARED,
        &journal_payload(durable_journal_state::PREPARED),
    );
    put_nested_u32(&mut value, 28, u32::from(durable_journal_state::COMMITTED));
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::Relationship);
}

#[test]
fn query_dir_snapshot_relationship_errors_are_exact() {
    for (entries, count) in [(&[][..], 1), (&[1][..], 0)] {
        let (key, value) = wrap(
            DurableKeyIdentityV1::QueryDirSnapshot {
                kernel_open_id: 4,
                generation: 5,
            },
            durable_child_kind::QUERY_DIR_SNAPSHOT,
            durable_query_dir_snapshot_state::ACTIVE,
            &snapshot_payload(entries, count),
        );
        expect_error(&key, &value, DurablePayloadError::Relationship);
    }
}

#[test]
fn pt_lane_relationship_errors_are_exact() {
    for payload in [
        pt_lane_payload(0, false, &[]),
        pt_lane_payload(0, true, &generic_blob(&[])),
        pt_lane_payload(1, true, &[]),
    ] {
        let (key, value) = wrap(
            DurableKeyIdentityV1::PtLane {
                ring_index: 1,
                kind_ordinal: 2,
            },
            durable_child_kind::PT_LANE,
            durable_pt_lane_state::PRESENT,
            &payload,
        );
        expect_error(&key, &value, DurablePayloadError::Relationship);
    }
}

#[test]
fn open_and_prepare_tail_shape_matrix_is_exhaustive() {
    let identity = DurableKeyIdentityV1::Open { kernel_open_id: 4 };
    let valid = open_payload(b"abc", b"defgh");
    let mutations = [
        (136usize, 0u32, 3u32),
        (136, 152, 0),
        (136, 153, 3),
        (144, 154, 5),
        (144, 151, 5),
        (136, u32::MAX - 2, 8),
    ];
    for (descriptor_offset, offset, length) in mutations {
        let (key, mut value) = wrap(
            identity,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            &valid,
        );
        put_nested_u32(&mut value, descriptor_offset, offset);
        put_nested_u32(&mut value, descriptor_offset + 4, length);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::SliceShape);
    }

    let mut gapped = open_payload(&[], b"sd");
    gapped[144..148].copy_from_slice(&160u32.to_le_bytes());
    let (key, value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &gapped,
    );
    expect_error(&key, &value, DurablePayloadError::SliceShape);

    let mut padded = open_payload(b"x", &[]);
    *padded.last_mut().unwrap() = 1;
    let (key, value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &padded,
    );
    expect_error(&key, &value, DurablePayloadError::SliceShape);

    let mut extra = open_payload(&[], &[]);
    extra.extend_from_slice(&[0; 8]);
    extra[0..4].copy_from_slice(&160u32.to_le_bytes());
    let (key, value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &extra,
    );
    expect_error(&key, &value, DurablePayloadError::SliceShape);

    let prepare = prepare_payload(b"a", b"b", b"c", b"d");
    for (left, right) in [(152, 160), (160, 168), (168, 176)] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            durable_prepare_state::PREPARED,
            &prepare,
        );
        let left_offset = nested_range(&value).start + left;
        let right_offset = nested_range(&value).start + right;
        let left_descriptor = value[left_offset..left_offset + 8].to_vec();
        let right_descriptor = value[right_offset..right_offset + 8].to_vec();
        value[left_offset..left_offset + 8].copy_from_slice(&right_descriptor);
        value[right_offset..right_offset + 8].copy_from_slice(&left_descriptor);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::SliceShape);
    }
}

#[test]
fn pt_sector_and_backing_path_rejection_corpus_is_exact() {
    let identity = DurableKeyIdentityV1::PtEpochIntent {
        file_id: FILE,
        pt_epoch: 7,
    };
    let valid_path = utf16le("\\Device\\disk");

    for sector in [0, 511, 513, 65_535, 65_537] {
        let (key, value) = wrap(
            identity,
            durable_child_kind::PT_EPOCH_INTENT,
            durable_pt_epoch_intent_state::PENDING,
            &pt_intent_payload(&valid_path, sector, 7),
        );
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    let invalid_paths = [
        Vec::new(),
        vec![b'\\'],
        utf16le("Device\\disk"),
        utf16le("\\Device"),
        utf16le("\\Device\\"),
        utf16le("\\Device\\a\\\\b"),
        utf16le("\\Device\\."),
        utf16le("\\Device\\.."),
        utf16le("\\Device\\a/b"),
        utf16le("\\Device\\a:b"),
        utf16le("\\??\\disk"),
        vec![b'\\', 0, b'D', 0, 0, 0, b'x', 0],
        vec![b'\\', 0, b'D', 0, 0x00, 0xd8, b'x', 0],
        vec![b'\\', 0, b'D', 0, 0x00, 0xdc, b'x', 0],
    ];
    for path in invalid_paths {
        let (key, value) = wrap(
            identity,
            durable_child_kind::PT_EPOCH_INTENT,
            durable_pt_epoch_intent_state::PENDING,
            &pt_intent_payload(&path, 4096, 7),
        );
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    let mut max_path = utf16le("\\Device\\");
    max_path.extend((0..16_372).flat_map(|_| (b'a' as u16).to_le_bytes()));
    assert_eq!(max_path.len(), 32_760);
    let (key, value) = wrap(
        identity,
        durable_child_kind::PT_EPOCH_INTENT,
        durable_pt_epoch_intent_state::PENDING,
        &pt_intent_payload(&max_path, 4096, 7),
    );
    assert!(validate_durable_payload_v1(&key, &value, RING_COUNT).is_ok());

    max_path.extend_from_slice(&(b'a' as u16).to_le_bytes());
    let (key, value) = wrap(
        identity,
        durable_child_kind::PT_EPOCH_INTENT,
        durable_pt_epoch_intent_state::PENDING,
        &pt_intent_payload(&max_path, 4096, 7),
    );
    expect_error(&key, &value, DurablePayloadError::InvalidScalar);
}

#[test]
fn error_precedence_is_exact_for_adjacent_and_outer_defects() {
    let identity = DurableKeyIdentityV1::Open { kernel_open_id: 4 };
    let (key, mut value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    value[16] ^= 1;
    value.truncate(DURABLE_CHILD_VALUE_PREFIX_BYTES as usize);
    expect_error(
        &key,
        &value,
        DurablePayloadError::Envelope(DurableMetadataError::Header),
    );

    let (key, mut value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    put_nested_u16(&mut value, 4, 2);
    expect_error(
        &key,
        &value,
        DurablePayloadError::Envelope(DurableMetadataError::PayloadDigest),
    );

    let (key, value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &[0; 7],
    );
    expect_error(&key, &value, DurablePayloadError::InvalidLength);

    let (key, mut value) = wrap(
        DurableKeyIdentityV1::Prepare { op_id: OP },
        durable_child_kind::PREPARE,
        durable_prepare_state::PREPARED,
        &prepare_payload(&[], &[], &[], &[]),
    );
    put_nested_u16(&mut value, 4, 2);
    put_nested_u32(&mut value, 140, 1);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::Header);

    let (key, mut value) = wrap(
        DurableKeyIdentityV1::PtEpochIntent {
            file_id: FILE,
            pt_epoch: 7,
        },
        durable_child_kind::PT_EPOCH_INTENT,
        durable_pt_epoch_intent_state::PENDING,
        &pt_intent_payload(&utf16le("\\Device\\disk"), 4096, 7),
    );
    put_nested_u32(&mut value, 20, 1);
    put_nested_u64(&mut value, 8, 8);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::FlagsOrReserved);

    let (key, mut value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    put_nested_u64(&mut value, 104, 5);
    put_nested_u64(&mut value, 8, 0);
    put_nested_u64(&mut value, 16, 0);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::Identity);

    let (key, mut value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    put_nested_u64(&mut value, 8, 0);
    put_nested_u64(&mut value, 16, 0);
    put_nested_u32(&mut value, 136, 152);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::InvalidScalar);

    let (key, mut value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &open_payload(&[], &[]),
    );
    put_nested_u32(&mut value, 136, 152);
    put_nested_u64(&mut value, 56, 10);
    put_nested_u64(&mut value, 64, 20);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::SliceShape);
}

#[test]
fn truncation_extension_and_descriptor_mutations_never_panic() {
    let identity = DurableKeyIdentityV1::Open { kernel_open_id: 4 };
    let payload = open_payload(b"abc", b"sd");
    let (key, value) = wrap(
        identity,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        &payload,
    );

    for length in 0..value.len() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            validate_durable_payload_v1(&key, &value[..length], RING_COUNT).is_err()
        }));
        assert!(matches!(result, Ok(true)));
    }

    for extension in 1..=15 {
        let mut extended = value.clone();
        extended.resize(extended.len() + extension, 0);
        let result = catch_unwind(AssertUnwindSafe(|| {
            validate_durable_payload_v1(&key, &extended, RING_COUNT).is_err()
        }));
        assert!(matches!(result, Ok(true)));
    }

    let nested_cases = vec![
        (
            identity,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES as usize,
            open_payload(b"abc", b"sd"),
        ),
        (
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            durable_prepare_state::PREPARED,
            PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES as usize,
            prepare_payload(b"n", b"requested", b"ea", b"result"),
        ),
        (
            DurableKeyIdentityV1::ImmutableRequest { op_id: OP },
            durable_child_kind::IMMUTABLE_REQUEST,
            durable_immutable_request_state::RETAINED,
            IMMUTABLE_REQUEST_DIGEST_BYTES as usize,
            vec![0x77; IMMUTABLE_REQUEST_DIGEST_BYTES as usize],
        ),
        (
            DurableKeyIdentityV1::CommittedResult { op_id: OP },
            durable_child_kind::COMMITTED_RESULT,
            durable_committed_result_state::COMMITTED,
            size_of::<ControlHeader>(),
            generic_blob(&[]),
        ),
        (
            DurableKeyIdentityV1::Journal { op_id: OP },
            durable_child_kind::JOURNAL,
            durable_journal_state::PREPARED,
            JOURNAL_STATE_V1_BYTES as usize,
            journal_payload(durable_journal_state::PREPARED),
        ),
        (
            DurableKeyIdentityV1::QueryDirSnapshot {
                kernel_open_id: 4,
                generation: 5,
            },
            durable_child_kind::QUERY_DIR_SNAPSHOT,
            durable_query_dir_snapshot_state::ACTIVE,
            QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES as usize,
            snapshot_payload(b"entry", 1),
        ),
        (
            DurableKeyIdentityV1::QueryDirAttempt {
                kernel_open_id: 4,
                generation: 5,
                input_cookie: 6,
                attempt_digest: [0x66; 32],
            },
            durable_child_kind::QUERY_DIR_ATTEMPT,
            durable_query_dir_attempt_state::ACCEPTED,
            size_of::<ControlHeader>(),
            generic_blob(&[]),
        ),
        (
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 4,
                generation: 5,
                cookie: 6,
            },
            durable_child_kind::QUERY_DIR_COOKIE,
            durable_query_dir_cookie_state::ACTIVE,
            QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES as usize,
            cookie_payload(7),
        ),
        (
            DurableKeyIdentityV1::PtEpochIntent {
                file_id: FILE,
                pt_epoch: 7,
            },
            durable_child_kind::PT_EPOCH_INTENT,
            durable_pt_epoch_intent_state::PENDING,
            PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES as usize,
            pt_intent_payload(&utf16le("\\Device\\disk"), 4096, 7),
        ),
        (
            DurableKeyIdentityV1::PtLane {
                ring_index: 1,
                kind_ordinal: 2,
            },
            durable_child_kind::PT_LANE,
            durable_pt_lane_state::PRESENT,
            PT_LANE_PAYLOAD_V1_PREFIX_BYTES as usize,
            pt_lane_payload(1, false, &generic_blob(&[])),
        ),
    ];

    for (identity, kind, state, fixed_prefix, payload) in nested_cases {
        for length in 0..=fixed_prefix + 1 {
            let nested = if length <= payload.len() {
                payload[..length].to_vec()
            } else {
                let mut bytes = payload.clone();
                bytes.resize(length, 0);
                bytes
            };
            let (key, value) = wrap(identity, kind, state, &nested);
            let result = catch_unwind(AssertUnwindSafe(|| {
                validate_durable_payload_v1(&key, &value, RING_COUNT)
            }))
            .expect("nested truncation must not panic");
            assert!(!matches!(result, Err(DurablePayloadError::Envelope(_))));
            if length < fixed_prefix {
                assert!(matches!(result, Err(DurablePayloadError::InvalidLength)));
            }
        }

        for extension in 1..=15 {
            let mut nested = payload.clone();
            nested.resize(nested.len() + extension, 0);
            let (key, value) = wrap(identity, kind, state, &nested);
            let result = catch_unwind(AssertUnwindSafe(|| {
                validate_durable_payload_v1(&key, &value, RING_COUNT)
            }))
            .expect("nested extension must not panic");
            assert!(!matches!(result, Err(DurablePayloadError::Envelope(_))));
        }
    }

    for (offset, length) in [(u32::MAX, 1), (u32::MAX - 3, 8), (152, u32::MAX), (1, 1)] {
        let (key, mut malformed) = wrap(
            identity,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            &payload,
        );
        put_nested_u32(&mut malformed, 136, offset);
        put_nested_u32(&mut malformed, 140, length);
        reseal_payload(&mut malformed);
        let result = catch_unwind(AssertUnwindSafe(|| {
            validate_durable_payload_v1(&key, &malformed, RING_COUNT).is_err()
        }));
        assert!(matches!(result, Ok(true)));
    }
}

#[test]
fn prepare_scalar_and_relationship_boundaries_are_closed() {
    for pair_offset in [8usize, 24, 40, 56] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            durable_prepare_state::PREPARED,
            &prepare_payload(&[], &[], &[], &[]),
        );
        put_nested_u64(&mut value, pair_offset, 0);
        put_nested_u64(&mut value, pair_offset + 8, 0);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    for scalar_offset in [96usize, 104, 112] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            durable_prepare_state::PREPARED,
            &prepare_payload(&[], &[], &[], &[]),
        );
        put_nested_u64(&mut value, scalar_offset, 0);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    for size_offset in [72usize, 80, 88] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            durable_prepare_state::PREPARED,
            &prepare_payload(&[], &[], &[], &[]),
        );
        put_nested_u64(&mut value, size_offset, MAX_FILE_SIZE + 1);
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::InvalidScalar);
    }

    let (key, mut value) = wrap(
        DurableKeyIdentityV1::Prepare { op_id: OP },
        durable_child_kind::PREPARE,
        durable_prepare_state::PREPARED,
        &prepare_payload(&[], &[], &[], &[]),
    );
    put_nested_u64(&mut value, 72, 10);
    put_nested_u64(&mut value, 80, 20);
    put_nested_u64(&mut value, 88, 5);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::Relationship);
}

#[test]
fn immutable_and_fixed_record_lengths_and_journal_identity_are_closed() {
    for length in [0usize, 1, 31] {
        let payload = vec![0u8; length];
        let (key, value) = wrap(
            DurableKeyIdentityV1::ImmutableRequest { op_id: OP },
            durable_child_kind::IMMUTABLE_REQUEST,
            durable_immutable_request_state::RETAINED,
            &payload,
        );
        expect_error(&key, &value, DurablePayloadError::InvalidLength);
    }

    for (lo, hi, expected) in [
        (0, 0, DurablePayloadError::InvalidScalar),
        (OP.lo + 1, OP.hi, DurablePayloadError::Identity),
    ] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::Journal { op_id: OP },
            durable_child_kind::JOURNAL,
            durable_journal_state::PREPARED,
            &journal_payload(durable_journal_state::PREPARED),
        );
        put_nested_u64(&mut value, 8, lo);
        put_nested_u64(&mut value, 16, hi);
        reseal_payload(&mut value);
        expect_error(&key, &value, expected);
    }

    let mut long_journal = journal_payload(durable_journal_state::PREPARED);
    long_journal.extend_from_slice(&[0; 8]);
    long_journal[0..4].copy_from_slice(&72u32.to_le_bytes());
    let (key, value) = wrap(
        DurableKeyIdentityV1::Journal { op_id: OP },
        durable_child_kind::JOURNAL,
        durable_journal_state::PREPARED,
        &long_journal,
    );
    expect_error(&key, &value, DurablePayloadError::InvalidLength);

    for payload in [cookie_payload(0)[..55].to_vec(), {
        let mut bytes = cookie_payload(0);
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }] {
        let (key, value) = wrap(
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 4,
                generation: 5,
                cookie: 6,
            },
            durable_child_kind::QUERY_DIR_COOKIE,
            durable_query_dir_cookie_state::ACTIVE,
            &payload,
        );
        expect_error(&key, &value, DurablePayloadError::InvalidLength);
    }
}

#[test]
fn pt_flags_identity_tail_and_pending_framing_are_closed() {
    let identity = DurableKeyIdentityV1::PtEpochIntent {
        file_id: FILE,
        pt_epoch: 7,
    };
    let path = utf16le("\\Device\\disk");

    let (key, mut value) = wrap(
        identity,
        durable_child_kind::PT_EPOCH_INTENT,
        durable_pt_epoch_intent_state::PENDING,
        &pt_intent_payload(&path, 4096, 7),
    );
    put_nested_u32(&mut value, 20, 1);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::FlagsOrReserved);

    for (epoch, expected) in [
        (0, DurablePayloadError::InvalidScalar),
        (8, DurablePayloadError::Identity),
    ] {
        let (key, mut value) = wrap(
            identity,
            durable_child_kind::PT_EPOCH_INTENT,
            durable_pt_epoch_intent_state::PENDING,
            &pt_intent_payload(&path, 4096, 7),
        );
        put_nested_u64(&mut value, 8, epoch);
        reseal_payload(&mut value);
        expect_error(&key, &value, expected);
    }

    let (key, mut value) = wrap(
        identity,
        durable_child_kind::PT_EPOCH_INTENT,
        durable_pt_epoch_intent_state::PENDING,
        &pt_intent_payload(&path, 4096, 7),
    );
    put_nested_u32(&mut value, 24, u32::MAX - 1);
    reseal_payload(&mut value);
    expect_error(&key, &value, DurablePayloadError::SliceShape);

    for (offset, width) in [(58usize, 2usize), (60, 4)] {
        let (key, mut value) = wrap(
            DurableKeyIdentityV1::PtLane {
                ring_index: 1,
                kind_ordinal: 2,
            },
            durable_child_kind::PT_LANE,
            durable_pt_lane_state::PRESENT,
            &pt_lane_payload(1, false, &[]),
        );
        if width == 2 {
            put_nested_u16(&mut value, offset, 1);
        } else {
            put_nested_u32(&mut value, offset, 1);
        }
        reseal_payload(&mut value);
        expect_error(&key, &value, DurablePayloadError::FlagsOrReserved);
    }

    let mut malformed_pending = generic_blob(&[]);
    malformed_pending[4..6].copy_from_slice(&2u16.to_le_bytes());
    let (key, value) = wrap(
        DurableKeyIdentityV1::PtLane {
            ring_index: 1,
            kind_ordinal: 2,
        },
        durable_child_kind::PT_LANE,
        durable_pt_lane_state::PRESENT,
        &pt_lane_payload(1, false, &malformed_pending),
    );
    expect_error(&key, &value, DurablePayloadError::Header);
}

#[test]
fn durable_envelope_hashes_the_already_validated_key_once() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/validate/durable.rs"))
            .unwrap();
    let start = source
        .find("pub(super) fn validate_durable_envelope_v1")
        .unwrap();
    let end = source[start..]
        .find("pub fn validate_durable_child_value_v1")
        .map(|relative| start + relative)
        .unwrap();
    let body = &source[start..end];

    assert_eq!(body.matches("validate_durable_key_v1(").count(), 1);
    assert!(!body.contains("durable_key_digest_v1("));
    assert_eq!(body.matches("crate::digest::sha256_bytes(key)").count(), 1);
}

#[test]
fn wave4c_keeps_abi_identity_artifacts_dependencies_and_surface_frozen() {
    // Wave 10 activation rebaseline + Wave 15 ZIP rebaseline: identity is 2.1,
    // the header/Cargo.lock/lib.rs baselines stay frozen, and the crate still
    // exposes no re-exports of the durable/validate namespaces. The two ZIPs are
    // regenerated in Wave 15 (freeze lifted); their SHA-256s are recorded in the
    // durable ledger, not pinned here — fsring-abi.zip's hash cannot be
    // self-asserted because this test file is a member of that archive.
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.1");
    assert_eq!(FSRING_ABI_MAJOR, 2);
    assert_eq!(FSRING_ABI_MINOR, 1);
    assert_eq!(
        durable_payload_digest_v1(include_bytes!("../include/fsring_abi.h")),
        hex32("7bc16346475e8bd786306368ef90d80e6f3009b8cc44adc11ca6dfd60509ab2d")
    );
    assert_eq!(
        durable_payload_digest_v1(include_bytes!("../Cargo.lock")),
        hex32("0c662af3fadb2e635e7b004943ad1102a3451b87218ef7a236d48f7e6926b017")
    );
    // Wave 15 ZIP rebaseline: the two ZIP-hash freeze assertions are retired
    // (the archives are regenerated and their SHA-256s recorded in the durable
    // ledger; fsring-abi.zip's hash cannot be self-asserted here because this
    // test file is a member of that archive). C4 adds the reviewed public,
    // non-wire compact section-layout module; the header/Cargo.lock freezes and
    // the rebaselined lib.rs surface remain guarded.
    assert_eq!(
        durable_payload_digest_v1(include_bytes!("../src/lib.rs")),
        hex32("dc2fba3fa6a39ba1cd899ca1fcdda60626c0f96a8e62e4a1de2d07427cab4aa9")
    );

    let crate_root = include_str!("../src/lib.rs");
    assert!(!crate_root.contains("/// cbindgen:ignore\npub mod durable;"));
    assert!(!crate_root.contains("pub use durable"));
    assert!(!crate_root.contains("pub use validate"));

    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("version = \"0.2.1\""));
    let direct_dependencies = manifest
        .lines()
        .skip_while(|line| *line != "[dependencies]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .count();
    assert_eq!(direct_dependencies, 0);

    let payload_source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/durable/payloads.rs"))
            .unwrap();
    // Wave 4c froze this surface at seven records; Wave 8 adds the four
    // committed-result records defined by corrective-design section 12.
    assert_eq!(payload_source.matches("unsafe impl Pod for ").count(), 11);
    assert_eq!(payload_source.matches("#[derive(Clone, Copy)]").count(), 11);

    let validator_source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/validate/durable_payloads.rs"),
    )
    .unwrap();
    assert!(validator_source
        .contains("#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum DurablePayloadError"));
    assert!(!validator_source.contains("pub use crate::"));
}

fn hex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    let mut output = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid lowercase hex literal"),
            }
        }
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}
