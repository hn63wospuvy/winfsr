use core::mem::{align_of, offset_of, size_of};

use fsring_abi::{
    codec::{try_encode, Pod},
    digest::{
        commit_open_operation_digest_v1, encode_commit_open_digest_prefix_v1,
        encode_mutation_digest_prefix_v1, encode_write_digest_prefix_v1,
        mutation_operation_digest_v1, operation_digest_eq, sha256_bytes,
        write_operation_digest_begin_v1, write_operation_digest_v1, CommitOpenDigestV1,
        MutationDigestV1, OpDigestBuilder, OpDigestError, WriteDigestV1,
        COMMIT_OPEN_DIGEST_V1_PREFIX_BYTES, MAX_IMMUTABLE_WRITE_BYTES_PER_MOUNT,
        MAX_JOURNALED_WRITE_BYTES_PER_REQUEST, MUTATION_DIGEST_V1_PREFIX_BYTES, OP_DIGEST_DOMAIN,
        OP_DIGEST_FORMAT_V1, OP_DIGEST_PREFIX_BYTES, WRITE_DIGEST_V1_PREFIX_BYTES,
    },
    durable::{
        committed_result_kind, CommittedMutationResultV1, CommittedOpenResultV1, CommittedResultV1,
        CommittedWriteResultV1, COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES,
        COMMITTED_OPEN_RESULT_V1_BYTES, COMMITTED_RESULT_V1_PREFIX_BYTES,
        COMMITTED_WRITE_RESULT_V1_BYTES, MAX_COMMITTED_RESULT_BYTES,
    },
    msgs::{mutation_kind, rw_flags, BlobSlice, ControlHeader, SizeState},
    op, FileId, LinkId, MountId, OpId, TransactionId,
};

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

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut out = [0u8; N];
    let mut index = 0usize;
    while index < N {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("non-lowercase-hex test literal"),
            }
        }
        out[index] =
            (nibble(text.as_bytes()[index * 2]) << 4) | nibble(text.as_bytes()[index * 2 + 1]);
        index += 1;
    }
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

fn put_pair(out: &mut [u8], offset: usize, lo: u64, hi: u64) {
    put_u64(out, offset, lo);
    put_u64(out, offset + 8, hi);
}

fn put_blob(out: &mut [u8], offset: usize, value: BlobSlice) {
    put_u32(out, offset, value.offset);
    put_u32(out, offset + 4, value.length);
}

fn put_header(out: &mut [u8], offset: usize, value: ControlHeader) {
    put_u32(out, offset, value.struct_size);
    put_u16(out, offset + 4, value.struct_version);
    put_u16(out, offset + 6, value.required_flags);
}

fn put_sizes(out: &mut [u8], offset: usize, value: SizeState) {
    put_u64(out, offset, value.allocation_size);
    put_u64(out, offset + 8, value.file_size);
    put_u64(out, offset + 16, value.valid_data_length);
    put_u64(out, offset + 24, value.size_epoch);
}

fn encode_exact<T: Pod, const N: usize>(value: &T) -> [u8; N] {
    let mut out = [0u8; N];
    assert_eq!(try_encode(value, &mut out).unwrap(), N);
    out
}

const MOUNT: MountId = MountId {
    lo: 0x1111_2222_3333_4444,
    hi: 0x5555_6666_7777_8888,
};
const OP: OpId = OpId {
    lo: 0x9999_aaaa_bbbb_cccc,
    hi: 0xdddd_eeee_ffff_0102,
};

fn expected_prefix(opcode: u16, kind: u16, semantic_length: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..16].copy_from_slice(b"FSRING-OP-DIGEST");
    put_u16(&mut out, 16, 1);
    put_u16(&mut out, 18, 2);
    put_u32(&mut out, 20, 1);
    put_pair(&mut out, 24, MOUNT.lo, MOUNT.hi);
    put_pair(&mut out, 40, OP.lo, OP.hi);
    put_u16(&mut out, 56, opcode);
    put_u16(&mut out, 58, kind);
    put_u32(&mut out, 60, semantic_length);
    out
}

fn expected_digest(opcode: u16, kind: u16, semantic: &[u8]) -> [u8; 32] {
    let mut image = [0u8; 64 + 66_000];
    let semantic_length = u32::try_from(semantic.len()).unwrap();
    image[..64].copy_from_slice(&expected_prefix(opcode, kind, semantic_length));
    image[64..64 + semantic.len()].copy_from_slice(semantic);
    sha256_bytes(&image[..64 + semantic.len()])
}

fn commit_transcript(name_len: u32, sd_len: u32, ea_len: u32) -> CommitOpenDigestV1 {
    let sd = if sd_len == 0 {
        BlobSlice::default()
    } else {
        BlobSlice {
            offset: 112 + name_len,
            length: sd_len,
        }
    };
    let ea = if ea_len == 0 {
        BlobSlice::default()
    } else {
        BlobSlice {
            offset: 112 + name_len + sd_len,
            length: ea_len,
        }
    };
    CommitOpenDigestV1 {
        parent_id: FileId { lo: 3, hi: 4 },
        transaction_id: TransactionId { lo: 5, hi: 6 },
        kernel_open_id: 7,
        expected_namespace_generation: 8,
        expected_security_generation: 9,
        desired_access: 0x0012_0089,
        share_access: 0x0000_0007,
        disposition: 2,
        create_options: 0x0000_0044,
        file_attributes: 0x0000_0080,
        open_flags: 0,
        granted_access: 0x0012_0089,
        commit_flags: 0,
        name: BlobSlice {
            offset: 112,
            length: name_len,
        },
        requested_security_descriptor: sd,
        ea,
    }
}

fn encode_commit_prefix(transcript: &CommitOpenDigestV1) -> [u8; 112] {
    let mut out = [0u8; 112];
    put_pair(
        &mut out,
        0,
        transcript.parent_id.lo,
        transcript.parent_id.hi,
    );
    put_pair(
        &mut out,
        16,
        transcript.transaction_id.lo,
        transcript.transaction_id.hi,
    );
    put_u64(&mut out, 32, transcript.kernel_open_id);
    put_u64(&mut out, 40, transcript.expected_namespace_generation);
    put_u64(&mut out, 48, transcript.expected_security_generation);
    put_u32(&mut out, 56, transcript.desired_access);
    put_u32(&mut out, 60, transcript.share_access);
    put_u32(&mut out, 64, transcript.disposition);
    put_u32(&mut out, 68, transcript.create_options);
    put_u32(&mut out, 72, transcript.file_attributes);
    put_u32(&mut out, 76, transcript.open_flags);
    put_u32(&mut out, 80, transcript.granted_access);
    put_u32(&mut out, 84, transcript.commit_flags);
    put_blob(&mut out, 88, transcript.name);
    put_blob(&mut out, 96, transcript.requested_security_descriptor);
    put_blob(&mut out, 104, transcript.ea);
    out
}

fn write_transcript(length: u32) -> WriteDigestV1 {
    WriteDigestV1 {
        file_id: FileId { lo: 21, hi: 22 },
        kernel_open_id: 23,
        offset: 4_096,
        size_epoch: 3,
        initialized_offset: 4_096,
        length,
        initialized_length: length,
        rw_flags: rw_flags::WRITE_THROUGH,
        reserved: 0,
        data: BlobSlice { offset: 72, length },
    }
}

fn encode_write_prefix(transcript: &WriteDigestV1) -> [u8; 72] {
    let mut out = [0u8; 72];
    put_pair(&mut out, 0, transcript.file_id.lo, transcript.file_id.hi);
    put_u64(&mut out, 16, transcript.kernel_open_id);
    put_u64(&mut out, 24, transcript.offset);
    put_u64(&mut out, 32, transcript.size_epoch);
    put_u64(&mut out, 40, transcript.initialized_offset);
    put_u32(&mut out, 48, transcript.length);
    put_u32(&mut out, 52, transcript.initialized_length);
    put_u32(&mut out, 56, transcript.rw_flags);
    put_u32(&mut out, 60, transcript.reserved);
    put_blob(&mut out, 64, transcript.data);
    out
}

fn mutation_transcript(kind: u16, body_length: u32) -> MutationDigestV1 {
    let namespace = matches!(
        kind,
        mutation_kind::SET_BASIC_INFO
            | mutation_kind::RENAME
            | mutation_kind::LINK
            | mutation_kind::UNLINK
    );
    let epoch = matches!(
        kind,
        mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH
    );
    let security = kind == mutation_kind::SET_SECURITY;
    MutationDigestV1 {
        file_id: FileId { lo: 31, hi: 32 },
        kernel_open_id: 33,
        expected_namespace_generation: if namespace { 11 } else { 0 },
        expected_size_epoch: if epoch { 12 } else { 0 },
        expected_security_generation: if security { 13 } else { 0 },
        mutation_kind: kind,
        mutation_flags: 0,
        body_length,
        body: BlobSlice {
            offset: 64,
            length: body_length,
        },
    }
}

fn encode_mutation_prefix(transcript: &MutationDigestV1) -> [u8; 64] {
    let mut out = [0u8; 64];
    put_pair(&mut out, 0, transcript.file_id.lo, transcript.file_id.hi);
    put_u64(&mut out, 16, transcript.kernel_open_id);
    put_u64(&mut out, 24, transcript.expected_namespace_generation);
    put_u64(&mut out, 32, transcript.expected_size_epoch);
    put_u64(&mut out, 40, transcript.expected_security_generation);
    put_u16(&mut out, 48, transcript.mutation_kind);
    put_u16(&mut out, 50, transcript.mutation_flags);
    put_u32(&mut out, 52, transcript.body_length);
    put_blob(&mut out, 56, transcript.body);
    out
}

/// A structurally canonical mutation body: leading struct_size, version 1,
/// zero required flags, zero-filled remainder.
fn mutation_body(struct_size: u32) -> Vec<u8> {
    let mut body = vec![0u8; struct_size as usize];
    put_header(
        &mut body,
        0,
        ControlHeader {
            struct_size,
            struct_version: 1,
            required_flags: 0,
        },
    );
    body
}

fn mutation_body_size(kind: u16) -> u32 {
    match kind {
        mutation_kind::SET_BASIC_INFO => 48,
        mutation_kind::SET_ALLOCATION_SIZE
        | mutation_kind::SET_END_OF_FILE
        | mutation_kind::SET_VALID_DATA_LENGTH => 24,
        mutation_kind::RENAME => 80,
        mutation_kind::LINK => 72,
        mutation_kind::UNLINK => 56,
        mutation_kind::SET_SECURITY => 48,
        _ => panic!("no canonical body for kind {kind}"),
    }
}

#[test]
fn digest_constants_match_binding_design() {
    assert_eq!(OP_DIGEST_DOMAIN, b"FSRING-OP-DIGEST");
    assert_eq!(OP_DIGEST_FORMAT_V1, 1);
    assert_eq!(OP_DIGEST_PREFIX_BYTES, 64);
    assert_eq!(COMMIT_OPEN_DIGEST_V1_PREFIX_BYTES, 112);
    assert_eq!(WRITE_DIGEST_V1_PREFIX_BYTES, 72);
    assert_eq!(MUTATION_DIGEST_V1_PREFIX_BYTES, 64);
    assert_eq!(MAX_JOURNALED_WRITE_BYTES_PER_REQUEST, 16_777_216);
    assert_eq!(MAX_IMMUTABLE_WRITE_BYTES_PER_MOUNT, 268_435_456);
}

#[test]
fn sha256_matches_standard_vectors() {
    assert_eq!(
        sha256_bytes(b""),
        decode_hex::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    );
    assert_eq!(
        sha256_bytes(b"abc"),
        decode_hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );
}

#[test]
fn committed_result_layouts_are_exact() {
    assert_wire_layout!(CommittedResultV1, 40, 8;
        header: ControlHeader => 0,
        opcode: u16 => 8,
        result_kind: u16 => 10,
        status: i32 => 12,
        information: u64 => 16,
        payload: BlobSlice => 24,
        volume_commit_sequence: u64 => 32,
    );
    assert_wire_layout!(CommittedOpenResultV1, 96, 8;
        header: ControlHeader => 0,
        file_id: FileId => 8,
        link_id: LinkId => 24,
        sizes: SizeState => 40,
        namespace_generation: u64 => 72,
        security_generation: u64 => 80,
        create_result: u32 => 88,
        flags: u32 => 92,
    );
    assert_wire_layout!(CommittedWriteResultV1, 40, 8;
        header: ControlHeader => 0,
        sizes: SizeState => 8,
    );
    assert_wire_layout!(CommittedMutationResultV1, 72, 8;
        header: ControlHeader => 0,
        mutation_kind: u16 => 8,
        flags: u16 => 10,
        reserved: u32 => 12,
        sizes: SizeState => 16,
        namespace_generation: u64 => 48,
        security_generation: u64 => 56,
        kind_payload: BlobSlice => 64,
    );
}

#[test]
fn committed_result_constants_and_totals_are_exact() {
    assert_eq!(committed_result_kind::INVALID, 0);
    assert_eq!(committed_result_kind::EMPTY, 1);
    assert_eq!(committed_result_kind::COMMIT_OPEN, 2);
    assert_eq!(committed_result_kind::WRITE, 3);
    assert_eq!(committed_result_kind::MUTATION, 4);

    assert_eq!(COMMITTED_RESULT_V1_PREFIX_BYTES, 40);
    assert_eq!(COMMITTED_OPEN_RESULT_V1_BYTES, 96);
    assert_eq!(COMMITTED_WRITE_RESULT_V1_BYTES, 40);
    assert_eq!(COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES, 72);
    assert_eq!(MAX_COMMITTED_RESULT_BYTES, 224);

    // Derived totals from section 12: WRITE, base mutation, COMMIT_OPEN,
    // UNLINK, LINK, RENAME.
    assert_eq!(
        COMMITTED_RESULT_V1_PREFIX_BYTES + COMMITTED_WRITE_RESULT_V1_BYTES,
        80
    );
    assert_eq!(
        COMMITTED_RESULT_V1_PREFIX_BYTES + COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES,
        112
    );
    assert_eq!(
        COMMITTED_RESULT_V1_PREFIX_BYTES + COMMITTED_OPEN_RESULT_V1_BYTES,
        136
    );
    assert_eq!(
        COMMITTED_RESULT_V1_PREFIX_BYTES + COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES + 56,
        168
    );
    assert_eq!(
        COMMITTED_RESULT_V1_PREFIX_BYTES + COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES + 104,
        216
    );
    assert_eq!(
        COMMITTED_RESULT_V1_PREFIX_BYTES + COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES + 112,
        MAX_COMMITTED_RESULT_BYTES
    );
}

#[test]
fn committed_result_byte_images_are_literal() {
    let outer = CommittedResultV1 {
        header: ControlHeader {
            struct_size: 0x0403_0201,
            struct_version: 0x0605,
            required_flags: 0x0807,
        },
        opcode: 0x1112,
        result_kind: 0x1314,
        status: 0x2122_2324,
        information: 0x3132_3334_3536_3738,
        payload: BlobSlice {
            offset: 0x4142_4344,
            length: 0x4546_4748,
        },
        volume_commit_sequence: 0x5152_5354_5556_5758,
    };
    let mut expected = [0u8; 40];
    put_header(&mut expected, 0, outer.header);
    put_u16(&mut expected, 8, outer.opcode);
    put_u16(&mut expected, 10, outer.result_kind);
    put_u32(&mut expected, 12, outer.status as u32);
    put_u64(&mut expected, 16, outer.information);
    put_blob(&mut expected, 24, outer.payload);
    put_u64(&mut expected, 32, outer.volume_commit_sequence);
    assert_eq!(encode_exact::<_, 40>(&outer), expected);

    let open = CommittedOpenResultV1 {
        header: ControlHeader {
            struct_size: 96,
            struct_version: 1,
            required_flags: 0,
        },
        file_id: FileId { lo: 1, hi: 2 },
        link_id: LinkId { lo: 3, hi: 4 },
        sizes: SizeState {
            allocation_size: 5,
            file_size: 6,
            valid_data_length: 7,
            size_epoch: 8,
        },
        namespace_generation: 9,
        security_generation: 10,
        create_result: 11,
        flags: 12,
    };
    let mut expected = [0u8; 96];
    put_header(&mut expected, 0, open.header);
    put_pair(&mut expected, 8, 1, 2);
    put_pair(&mut expected, 24, 3, 4);
    put_sizes(&mut expected, 40, open.sizes);
    put_u64(&mut expected, 72, 9);
    put_u64(&mut expected, 80, 10);
    put_u32(&mut expected, 88, 11);
    put_u32(&mut expected, 92, 12);
    assert_eq!(encode_exact::<_, 96>(&open), expected);

    let write = CommittedWriteResultV1 {
        header: ControlHeader {
            struct_size: 40,
            struct_version: 1,
            required_flags: 0,
        },
        sizes: SizeState {
            allocation_size: 13,
            file_size: 14,
            valid_data_length: 15,
            size_epoch: 16,
        },
    };
    let mut expected = [0u8; 40];
    put_header(&mut expected, 0, write.header);
    put_sizes(&mut expected, 8, write.sizes);
    assert_eq!(encode_exact::<_, 40>(&write), expected);

    let mutation = CommittedMutationResultV1 {
        header: ControlHeader {
            struct_size: 72,
            struct_version: 1,
            required_flags: 0,
        },
        mutation_kind: 17,
        flags: 18,
        reserved: 19,
        sizes: SizeState {
            allocation_size: 20,
            file_size: 21,
            valid_data_length: 22,
            size_epoch: 23,
        },
        namespace_generation: 24,
        security_generation: 25,
        kind_payload: BlobSlice {
            offset: 26,
            length: 27,
        },
    };
    let mut expected = [0u8; 72];
    put_header(&mut expected, 0, mutation.header);
    put_u16(&mut expected, 8, 17);
    put_u16(&mut expected, 10, 18);
    put_u32(&mut expected, 12, 19);
    put_sizes(&mut expected, 16, mutation.sizes);
    put_u64(&mut expected, 48, 24);
    put_u64(&mut expected, 56, 25);
    put_blob(&mut expected, 64, mutation.kind_payload);
    assert_eq!(encode_exact::<_, 72>(&mutation), expected);
}

#[test]
fn transcript_prefix_encodings_are_literal() {
    let commit = commit_transcript(6, 20, 4);
    assert_eq!(
        encode_commit_open_digest_prefix_v1(&commit),
        encode_commit_prefix(&commit)
    );
    let write = write_transcript(16);
    assert_eq!(
        encode_write_digest_prefix_v1(&write),
        encode_write_prefix(&write)
    );
    let mutation = mutation_transcript(mutation_kind::UNLINK, 56);
    assert_eq!(
        encode_mutation_digest_prefix_v1(&mutation),
        encode_mutation_prefix(&mutation)
    );
}

#[test]
fn builder_digest_matches_independent_assembly() {
    let semantic = *b"semantic-bytes\x00\x01";
    let mut builder = OpDigestBuilder::new(MOUNT, OP, op::WRITE, 0, 16).unwrap();
    builder.update(&semantic).unwrap();
    assert_eq!(
        builder.finalize().unwrap(),
        expected_digest(op::WRITE, 0, &semantic)
    );
}

#[test]
fn commit_open_digest_covers_prefix_and_ordered_tails() {
    let name = [0x61u8, 0x00, 0x62, 0x00, 0x63, 0x00];
    let sd = [0x51u8; 20];
    let ea = [0x45u8; 4];
    let transcript = commit_transcript(6, 20, 4);
    let digest = commit_open_operation_digest_v1(MOUNT, OP, &transcript, &name, &sd, &ea).unwrap();

    let mut semantic = Vec::new();
    semantic.extend_from_slice(&encode_commit_prefix(&transcript));
    semantic.extend_from_slice(&name);
    semantic.extend_from_slice(&sd);
    semantic.extend_from_slice(&ea);
    assert_eq!(digest, expected_digest(op::COMMIT_OPEN, 0, &semantic));

    // Name-only form: absent SD/EA are {0,0} and create no gap.
    let transcript = commit_transcript(6, 0, 0);
    let digest = commit_open_operation_digest_v1(MOUNT, OP, &transcript, &name, &[], &[]).unwrap();
    let mut semantic = Vec::new();
    semantic.extend_from_slice(&encode_commit_prefix(&transcript));
    semantic.extend_from_slice(&name);
    assert_eq!(digest, expected_digest(op::COMMIT_OPEN, 0, &semantic));
}

#[test]
fn write_digest_covers_prefix_and_data() {
    let data = [0xd7u8; 16];
    let transcript = write_transcript(16);
    let digest = write_operation_digest_v1(MOUNT, OP, &transcript, &data).unwrap();

    let mut semantic = Vec::new();
    semantic.extend_from_slice(&encode_write_prefix(&transcript));
    semantic.extend_from_slice(&data);
    assert_eq!(digest, expected_digest(op::WRITE, 0, &semantic));
}

#[test]
fn write_digest_is_chunking_invariant() {
    let mut data = [0u8; 300];
    let mut index = 0usize;
    while index < data.len() {
        data[index] = index as u8;
        index += 1;
    }
    let transcript = write_transcript(300);
    let expected = write_operation_digest_v1(MOUNT, OP, &transcript, &data).unwrap();

    for split in [0usize, 1, 63, 64, 65, 150, 299, 300] {
        let mut builder = write_operation_digest_begin_v1(MOUNT, OP, &transcript).unwrap();
        builder.update(&data[..split]).unwrap();
        builder.update(&data[split..]).unwrap();
        assert_eq!(builder.finalize().unwrap(), expected, "split {split}");
    }
    for width in [1usize, 7, 64, 128] {
        let mut builder = write_operation_digest_begin_v1(MOUNT, OP, &transcript).unwrap();
        for chunk in data.chunks(width) {
            builder.update(chunk).unwrap();
        }
        assert_eq!(builder.finalize().unwrap(), expected, "width {width}");
    }
}

#[test]
fn mutation_digest_covers_every_base_kind() {
    for kind in [
        mutation_kind::SET_BASIC_INFO,
        mutation_kind::SET_ALLOCATION_SIZE,
        mutation_kind::SET_END_OF_FILE,
        mutation_kind::SET_VALID_DATA_LENGTH,
        mutation_kind::RENAME,
        mutation_kind::LINK,
        mutation_kind::UNLINK,
        mutation_kind::SET_SECURITY,
    ] {
        let size = mutation_body_size(kind);
        let body = mutation_body(size);
        let transcript = mutation_transcript(kind, size);
        let digest = mutation_operation_digest_v1(MOUNT, OP, &transcript, &body).unwrap();

        let mut semantic = Vec::new();
        semantic.extend_from_slice(&encode_mutation_prefix(&transcript));
        semantic.extend_from_slice(&body);
        assert_eq!(
            digest,
            expected_digest(op::MUTATE, kind, &semantic),
            "kind {kind}"
        );
    }
}

#[test]
fn digest_is_sensitive_to_every_prefix_field_and_semantic_byte() {
    let data = [0xd7u8; 16];
    let transcript = write_transcript(16);
    let baseline = write_operation_digest_v1(MOUNT, OP, &transcript, &data).unwrap();

    let mut other_mount = MOUNT;
    other_mount.lo ^= 1;
    assert_ne!(
        write_operation_digest_v1(other_mount, OP, &transcript, &data).unwrap(),
        baseline
    );
    let mut other_mount = MOUNT;
    other_mount.hi ^= 1;
    assert_ne!(
        write_operation_digest_v1(other_mount, OP, &transcript, &data).unwrap(),
        baseline
    );
    let mut other_op = OP;
    other_op.lo ^= 1;
    assert_ne!(
        write_operation_digest_v1(MOUNT, other_op, &transcript, &data).unwrap(),
        baseline
    );
    let mut other_op = OP;
    other_op.hi ^= 1;
    assert_ne!(
        write_operation_digest_v1(MOUNT, other_op, &transcript, &data).unwrap(),
        baseline
    );

    let mut other_data = data;
    other_data[7] ^= 0x80;
    assert_ne!(
        write_operation_digest_v1(MOUNT, OP, &transcript, &other_data).unwrap(),
        baseline
    );

    let mut other_transcript = transcript;
    other_transcript.offset ^= 1;
    assert_ne!(
        write_operation_digest_v1(MOUNT, OP, &other_transcript, &data).unwrap(),
        baseline
    );

    // Same semantic bytes under a different opcode/kind prefix digest
    // differently.
    let body = mutation_body(56);
    let unlink = mutation_transcript(mutation_kind::UNLINK, 56);
    let mut sneaky = unlink;
    sneaky.mutation_kind = mutation_kind::RENAME;
    sneaky.body_length = 56;
    let unlink_digest = mutation_operation_digest_v1(MOUNT, OP, &unlink, &body).unwrap();
    let rename_digest = mutation_operation_digest_v1(MOUNT, OP, &sneaky, &body).unwrap();
    assert_ne!(rename_digest, unlink_digest);
}

#[test]
fn builder_rejects_illegal_identity_and_length() {
    assert!(OpDigestBuilder::new(MOUNT, OP, op::WRITE, 0, 16).is_ok());
    assert_eq!(
        OpDigestBuilder::new(MOUNT, OP, op::READ, 0, 16).unwrap_err(),
        OpDigestError::UnsupportedOpcode
    );
    assert_eq!(
        OpDigestBuilder::new(MOUNT, OP, op::QUERY_OP, 0, 16).unwrap_err(),
        OpDigestError::UnsupportedOpcode
    );
    assert_eq!(
        OpDigestBuilder::new(MOUNT, OP, op::MUTATE, 0, 64).unwrap_err(),
        OpDigestError::MutationKindPairing
    );
    assert_eq!(
        OpDigestBuilder::new(MOUNT, OP, op::WRITE, mutation_kind::RENAME, 16).unwrap_err(),
        OpDigestError::MutationKindPairing
    );
    // The builder itself pins the closed journaled mutation-kind set.
    for kind in [
        mutation_kind::SET_REPARSE,
        mutation_kind::DELETE_REPARSE,
        mutation_kind::SET_SPARSE,
        12,
    ] {
        assert_eq!(
            OpDigestBuilder::new(MOUNT, OP, op::MUTATE, kind, 64).unwrap_err(),
            OpDigestError::InvalidScalar,
            "kind {kind}"
        );
    }
    assert!(OpDigestBuilder::new(MOUNT, OP, op::MUTATE, mutation_kind::UNLINK, 64).is_ok());
    assert_eq!(
        OpDigestBuilder::new(MOUNT, OpId::ZERO, op::WRITE, 0, 16).unwrap_err(),
        OpDigestError::ZeroIdentity
    );
    assert_eq!(
        OpDigestBuilder::new(MountId { lo: 0, hi: 1 }, OP, op::WRITE, 0, 16).unwrap_err(),
        OpDigestError::ZeroIdentity
    );
    assert_eq!(
        OpDigestBuilder::new(MountId { lo: 1, hi: 0 }, OP, op::WRITE, 0, 16).unwrap_err(),
        OpDigestError::ZeroIdentity
    );

    let mut builder = OpDigestBuilder::new(MOUNT, OP, op::WRITE, 0, 4).unwrap();
    assert_eq!(
        builder.update(&[0u8; 5]).unwrap_err(),
        OpDigestError::LengthMismatch
    );
    let mut builder = OpDigestBuilder::new(MOUNT, OP, op::WRITE, 0, 4).unwrap();
    builder.update(&[0u8; 3]).unwrap();
    assert_eq!(
        builder.finalize().unwrap_err(),
        OpDigestError::LengthMismatch
    );
}

#[test]
fn commit_open_projection_rejects_geometry_and_identity_faults() {
    let name = [0x61u8, 0x00, 0x62, 0x00, 0x63, 0x00];
    let sd = [0x51u8; 20];
    let ea = [0x45u8; 4];
    let good = commit_transcript(6, 20, 4);
    assert!(commit_open_operation_digest_v1(MOUNT, OP, &good, &name, &sd, &ea).is_ok());

    // Mandatory nonempty name.
    let mut bad = good;
    bad.name = BlobSlice::default();
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &bad, &[], &sd, &ea).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    // Name must start the tail at byte 112.
    let mut bad = good;
    bad.name.offset = 113;
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &bad, &name, &sd, &ea).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    // Odd name length is not a stored component.
    let mut bad = commit_transcript(5, 0, 0);
    bad.requested_security_descriptor = BlobSlice::default();
    bad.ea = BlobSlice::default();
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &bad, &name[..5], &[], &[]).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    // Oversized name (256 units = 512 bytes); 255 units = 510 bytes is the
    // stored-component maximum.
    let long_name = vec![0x61u8; 512];
    let bad = commit_transcript(512, 0, 0);
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &bad, &long_name, &[], &[]).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    let edge = commit_transcript(510, 0, 0);
    assert!(commit_open_operation_digest_v1(MOUNT, OP, &edge, &long_name[..510], &[], &[]).is_ok());
    // SD below the 20-byte descriptor minimum.
    let mut bad = commit_transcript(6, 19, 0);
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &bad, &name, &sd[..19], &[]).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    bad.requested_security_descriptor.length = 20;
    assert!(commit_open_operation_digest_v1(MOUNT, OP, &bad, &name, &sd, &[]).is_ok());
    // EA slice creating a gap after the SD.
    let mut bad = commit_transcript(6, 20, 4);
    bad.ea.offset += 1;
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &bad, &name, &sd, &ea).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    // Caller bytes must match the slice lengths exactly.
    assert_eq!(
        commit_open_operation_digest_v1(MOUNT, OP, &good, &name, &sd[..19], &ea).unwrap_err(),
        OpDigestError::LengthMismatch
    );
    // Zero identity scalars.
    for wreck in [
        |t: &mut CommitOpenDigestV1| t.parent_id = FileId::ZERO,
        |t: &mut CommitOpenDigestV1| t.transaction_id = TransactionId::ZERO,
        |t: &mut CommitOpenDigestV1| t.kernel_open_id = 0,
        |t: &mut CommitOpenDigestV1| t.expected_namespace_generation = 0,
        |t: &mut CommitOpenDigestV1| t.expected_security_generation = 0,
    ] {
        let mut bad = good;
        wreck(&mut bad);
        assert_eq!(
            commit_open_operation_digest_v1(MOUNT, OP, &bad, &name, &sd, &ea).unwrap_err(),
            OpDigestError::ZeroIdentity
        );
    }
}

#[test]
fn write_projection_rejects_scalar_flag_and_geometry_faults() {
    let data = [0xd7u8; 16];
    let good = write_transcript(16);
    assert!(write_operation_digest_v1(MOUNT, OP, &good, &data).is_ok());

    let mut bad = good;
    bad.length = 0;
    bad.data.length = 0;
    bad.initialized_length = 0;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &[]).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    let mut bad = good;
    bad.rw_flags = 1 << 30;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
        OpDigestError::FlagsOrReserved
    );
    let mut bad = good;
    bad.reserved = 1;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
        OpDigestError::FlagsOrReserved
    );
    let mut bad = good;
    bad.initialized_length = 17;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    let mut bad = good;
    bad.offset = u64::MAX - 8;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
        OpDigestError::Range
    );
    let mut bad = good;
    bad.data.offset = 73;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    let mut bad = good;
    bad.data.length = 15;
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    assert_eq!(
        write_operation_digest_v1(MOUNT, OP, &good, &data[..15]).unwrap_err(),
        OpDigestError::LengthMismatch
    );
    for wreck in [
        |t: &mut WriteDigestV1| t.file_id = FileId::ZERO,
        |t: &mut WriteDigestV1| t.kernel_open_id = 0,
        |t: &mut WriteDigestV1| t.size_epoch = 0,
    ] {
        let mut bad = good;
        wreck(&mut bad);
        assert_eq!(
            write_operation_digest_v1(MOUNT, OP, &bad, &data).unwrap_err(),
            OpDigestError::ZeroIdentity
        );
    }
    // The per-request journaled chunk bound is enforced without allocating.
    let mut bad = good;
    bad.length = MAX_JOURNALED_WRITE_BYTES_PER_REQUEST + 1;
    bad.data.length = bad.length;
    bad.initialized_length = 0;
    assert_eq!(
        write_operation_digest_begin_v1(MOUNT, OP, &bad).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    let mut edge = good;
    edge.length = MAX_JOURNALED_WRITE_BYTES_PER_REQUEST;
    edge.data.length = edge.length;
    edge.initialized_length = 0;
    assert!(write_operation_digest_begin_v1(MOUNT, OP, &edge).is_ok());
}

#[test]
fn mutation_projection_rejects_kind_pairing_and_body_faults() {
    let body = mutation_body(56);
    let good = mutation_transcript(mutation_kind::UNLINK, 56);
    assert!(mutation_operation_digest_v1(MOUNT, OP, &good, &body).is_ok());

    for kind in [
        mutation_kind::INVALID,
        mutation_kind::SET_REPARSE,
        mutation_kind::DELETE_REPARSE,
        mutation_kind::SET_SPARSE,
        12,
    ] {
        let mut bad = good;
        bad.mutation_kind = kind;
        assert_eq!(
            mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
            OpDigestError::InvalidScalar,
            "kind {kind}"
        );
    }
    let mut bad = good;
    bad.mutation_flags = 1;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
        OpDigestError::FlagsOrReserved
    );
    let mut bad = good;
    bad.body.offset = 65;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    let mut bad = good;
    bad.body.length = 48;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
        OpDigestError::SliceGeometry
    );
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &good, &body[..48]).unwrap_err(),
        OpDigestError::LengthMismatch
    );
    // The body's leading struct_size must match body_length.
    let mut lying = mutation_body(56);
    put_u32(&mut lying, 0, 48);
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &good, &lying).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    // Below the 8-byte header minimum and non-multiple-of-8 shapes.
    let mut bad = good;
    bad.body_length = 4;
    bad.body.length = 4;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &mutation_body(8)[..4]).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    let mut bad = good;
    bad.body_length = 60;
    bad.body.length = 60;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &mutation_body(60)).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    // Above the 65,560-byte mutation body cap.
    let mut bad = good;
    bad.body_length = 65_568;
    bad.body.length = 65_568;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &mutation_body(65_568)).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    // Expected-generation pairing per kind.
    let mut bad = good;
    bad.expected_namespace_generation = 0;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
        OpDigestError::ZeroIdentity
    );
    let mut bad = good;
    bad.expected_size_epoch = 7;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
        OpDigestError::InvalidScalar
    );
    let mut bad = mutation_transcript(mutation_kind::SET_SECURITY, 48);
    bad.expected_security_generation = 0;
    assert_eq!(
        mutation_operation_digest_v1(MOUNT, OP, &bad, &mutation_body(48)).unwrap_err(),
        OpDigestError::ZeroIdentity
    );
    for wreck in [
        |t: &mut MutationDigestV1| t.file_id = FileId::ZERO,
        |t: &mut MutationDigestV1| t.kernel_open_id = 0,
    ] {
        let mut bad = good;
        wreck(&mut bad);
        assert_eq!(
            mutation_operation_digest_v1(MOUNT, OP, &bad, &body).unwrap_err(),
            OpDigestError::ZeroIdentity
        );
    }
}

#[test]
fn operation_digest_comparison_is_exact() {
    let data = [0xd7u8; 16];
    let transcript = write_transcript(16);
    let digest = write_operation_digest_v1(MOUNT, OP, &transcript, &data).unwrap();
    assert!(operation_digest_eq(&digest, &digest));
    for bit in [0usize, 1, 127, 255] {
        let mut other = digest;
        other[bit / 8] ^= 1 << (bit % 8);
        assert!(!operation_digest_eq(&digest, &other), "bit {bit}");
    }
}
