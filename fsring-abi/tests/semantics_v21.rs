use core::mem::{align_of, offset_of, size_of};

use fsring_abi::{
    codec::{try_encode, Pod},
    features::protocol_feature,
    msgs::{
        buffer_access, buffer_kind, file_attributes, query_dir_flags, query_dir_result_flags,
        query_info_class, query_volume_class, security_information, BlobSlice, BufferRef,
        ControlHeader, DirEntryV1, FileInfoV1, FsctlV1, QueryDirResultV1, QueryDirV1, QueryDirV2,
        QueryInfoV1, QuerySecurityV1, QueryVolumeV1, SizeState, VolumeSizeInfoV1,
        CONTROL_VERSION_V1, CONTROL_VERSION_V2,
    },
    slots::{
        resolve_slot, validate_slot_arena, BufferRefError, GrantCapability, GrantMetadata,
        GrantOwner, GrantState, SlotDirection, ValidatedBuffer,
    },
    validate::{
        validate_dir_pattern_utf16, validate_feature_wire_legality_v21, validate_file_info_v1,
        validate_fsctl_emission_v21, validate_query_dir_result_v1, validate_query_dir_v2,
        validate_query_info_v1, validate_query_security_v1, validate_query_volume_v1,
        validate_volume_size_info_v1, CheckedRange64, ControlError, GrantBindingV21,
        MessageValidationError, QueryDirFormV21, QueryValidationError, WireFormV21,
    },
    FeatureSet, FileId, LinkId, RegionDesc, ReqId, SlotClassDesc, SlotToken, MAX_CONTROL_BLOB,
};

type MutationRow<T, E> = (fn(&mut T), E);

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

fn put_blob(out: &mut [u8], offset: usize, value: BlobSlice) {
    put_u32(out, offset, value.offset);
    put_u32(out, offset + 4, value.length);
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

fn sentinel_blob(seed: u32) -> BlobSlice {
    BlobSlice {
        offset: seed,
        length: seed ^ 0xffff_ffff,
    }
}

fn sentinel_sizes() -> SizeState {
    SizeState {
        allocation_size: 0x1112_1314_1516_1718,
        file_size: 0x2122_2324_2526_2728,
        valid_data_length: 0x3132_3334_3536_3738,
        size_epoch: 0x4142_4344_4546_4748,
    }
}

#[test]
fn wave7b_query_registries_are_closed_and_literal() {
    assert_eq!(query_info_class::INVALID, 0);
    assert_eq!(query_info_class::CANONICAL, 1);
    assert_eq!(query_volume_class::INVALID, 0);
    assert_eq!(query_volume_class::SIZE, 1);
    assert_eq!(query_dir_flags::RESTART, 0x0000_0001);
    assert_eq!(query_dir_flags::SINGLE, 0x0000_0002);
    assert_eq!(query_dir_flags::EXACT_PATTERN, 0x0000_0004);
    assert_eq!(query_dir_flags::ALL, 0x0000_0007);
    assert_eq!(
        query_dir_flags::RESTART | query_dir_flags::SINGLE | query_dir_flags::EXACT_PATTERN,
        query_dir_flags::ALL
    );
    assert_eq!(query_dir_result_flags::EOF, 0x0000_0001);
}

#[test]
fn wave7b_query_layouts_are_exact_and_gapless() {
    assert_wire_layout!(QueryInfoV1, 40, 8;
        header: ControlHeader => 0, info_class: u16 => 8, flags: u16 => 10,
        reserved: u32 => 12, output: BufferRef => 16,
    );
    assert_wire_layout!(FileInfoV1, 104, 8;
        header: ControlHeader => 0, creation_time: i64 => 8,
        last_access_time: i64 => 16, last_write_time: i64 => 24,
        change_time: i64 => 32, sizes: SizeState => 40,
        namespace_generation: u64 => 72, security_generation: u64 => 80,
        attributes: u32 => 88, link_count: u32 => 92, reparse_tag: u32 => 96,
        flags: u32 => 100,
    );
    assert_wire_layout!(QueryDirV1, 56, 8;
        header: ControlHeader => 0, enumeration_cookie: u64 => 8,
        flags: u32 => 16, reserved: u32 => 20, pattern: BlobSlice => 24,
        output: BufferRef => 32,
    );
    assert_wire_layout!(QueryDirV2, 64, 8;
        header: ControlHeader => 0, enumeration_cookie: u64 => 8,
        flags: u32 => 16, reserved: u32 => 20, pattern: BlobSlice => 24,
        output: BufferRef => 32, enumeration_generation: u64 => 56,
    );
    assert_wire_layout!(QueryDirResultV1, 40, 8;
        header: ControlHeader => 0, next_cookie: u64 => 8, flags: u32 => 16,
        entry_count: u32 => 20, entries: BlobSlice => 24,
        required_length: u32 => 32, reserved: u32 => 36,
    );
    assert_wire_layout!(DirEntryV1, 136, 8;
        header: ControlHeader => 0, file_id: FileId => 8, link_id: LinkId => 24,
        sizes: SizeState => 40, creation_time: i64 => 72,
        last_access_time: i64 => 80, last_write_time: i64 => 88,
        change_time: i64 => 96, namespace_generation: u64 => 104,
        attributes: u32 => 112, reparse_tag: u32 => 116, flags: u32 => 120,
        reserved: u32 => 124, name: BlobSlice => 128,
    );
    assert_wire_layout!(QueryVolumeV1, 40, 8;
        header: ControlHeader => 0, info_class: u16 => 8, flags: u16 => 10,
        reserved: u32 => 12, output: BufferRef => 16,
    );
    assert_wire_layout!(VolumeSizeInfoV1, 40, 8;
        header: ControlHeader => 0, total_allocation_units: u64 => 8,
        available_allocation_units: u64 => 16,
        sectors_per_allocation_unit: u32 => 24, bytes_per_sector: u32 => 28,
        flags: u32 => 32, reserved: u32 => 36,
    );
    assert_wire_layout!(QuerySecurityV1, 40, 8;
        header: ControlHeader => 0, security_information: u32 => 8,
        flags: u32 => 12, output: BufferRef => 16,
    );
    assert_wire_layout!(FsctlV1, 64, 8;
        header: ControlHeader => 0, code: u32 => 8, flags: u32 => 12,
        input: BufferRef => 16, output: BufferRef => 40,
    );

    let v2 = QueryDirV2 {
        header: sentinel_header(),
        enumeration_cookie: 0x1112_1314_1516_1718,
        flags: 0x2122_2324,
        reserved: 0x3132_3334,
        pattern: sentinel_blob(0x4142_4344),
        output: sentinel_buffer(0x5152_5354_5556_5758),
        enumeration_generation: 0x6162_6364_6566_6768,
    };
    let v1 = QueryDirV1 {
        header: v2.header,
        enumeration_cookie: v2.enumeration_cookie,
        flags: v2.flags,
        reserved: v2.reserved,
        pattern: v2.pattern,
        output: v2.output,
    };
    let v2_bytes: [u8; 64] = encode_exact(&v2);
    let v1_bytes: [u8; 56] = encode_exact(&v1);
    assert_eq!(&v2_bytes[..56], &v1_bytes);
}

#[test]
fn wave7b_query_family_has_complete_literal_little_endian_images() {
    let query_dir = QueryDirV2 {
        header: sentinel_header(),
        enumeration_cookie: 0x1112_1314_1516_1718,
        flags: 0x2122_2324,
        reserved: 0x3132_3334,
        pattern: sentinel_blob(0x4142_4344),
        output: sentinel_buffer(0x5152_5354_5556_5758),
        enumeration_generation: 0x6162_6364_6566_6768,
    };
    let bytes: [u8; 64] = encode_exact(&query_dir);
    let mut expected = [0u8; 64];
    put_header(&mut expected, 0, query_dir.header);
    put_u64(&mut expected, 8, query_dir.enumeration_cookie);
    put_u32(&mut expected, 16, query_dir.flags);
    put_u32(&mut expected, 20, query_dir.reserved);
    put_blob(&mut expected, 24, query_dir.pattern);
    put_buffer(&mut expected, 32, query_dir.output);
    put_u64(&mut expected, 56, query_dir.enumeration_generation);
    assert_eq!(bytes, expected);

    let result = QueryDirResultV1 {
        header: sentinel_header(),
        next_cookie: 0x7172_7374_7576_7778,
        flags: 0x8182_8384,
        entry_count: 0x9192_9394,
        entries: sentinel_blob(0xa1a2_a3a4),
        required_length: 0xb1b2_b3b4,
        reserved: 0xc1c2_c3c4,
    };
    let bytes: [u8; 40] = encode_exact(&result);
    let mut expected = [0u8; 40];
    put_header(&mut expected, 0, result.header);
    put_u64(&mut expected, 8, result.next_cookie);
    put_u32(&mut expected, 16, result.flags);
    put_u32(&mut expected, 20, result.entry_count);
    put_blob(&mut expected, 24, result.entries);
    put_u32(&mut expected, 32, result.required_length);
    put_u32(&mut expected, 36, result.reserved);
    assert_eq!(bytes, expected);

    let entry = DirEntryV1 {
        header: sentinel_header(),
        file_id: FileId {
            lo: 0x1112_1314_1516_1718,
            hi: 0x2122_2324_2526_2728,
        },
        link_id: LinkId {
            lo: 0x3132_3334_3536_3738,
            hi: 0x4142_4344_4546_4748,
        },
        sizes: sentinel_sizes(),
        creation_time: 0x5152_5354_5556_5758,
        last_access_time: 0x6162_6364_6566_6768,
        last_write_time: 0x7172_7374_7576_7778,
        change_time: 0x0102_0304_0506_0708,
        namespace_generation: 0x8182_8384_8586_8788,
        attributes: 0x9192_9394,
        reparse_tag: 0xa1a2_a3a4,
        flags: 0xb1b2_b3b4,
        reserved: 0xc1c2_c3c4,
        name: sentinel_blob(0xd1d2_d3d4),
    };
    let bytes: [u8; 136] = encode_exact(&entry);
    let mut expected = [0u8; 136];
    put_header(&mut expected, 0, entry.header);
    put_pair(&mut expected, 8, entry.file_id.lo, entry.file_id.hi);
    put_pair(&mut expected, 24, entry.link_id.lo, entry.link_id.hi);
    put_sizes(&mut expected, 40, entry.sizes);
    put_u64(&mut expected, 72, entry.creation_time as u64);
    put_u64(&mut expected, 80, entry.last_access_time as u64);
    put_u64(&mut expected, 88, entry.last_write_time as u64);
    put_u64(&mut expected, 96, entry.change_time as u64);
    put_u64(&mut expected, 104, entry.namespace_generation);
    put_u32(&mut expected, 112, entry.attributes);
    put_u32(&mut expected, 116, entry.reparse_tag);
    put_u32(&mut expected, 120, entry.flags);
    put_u32(&mut expected, 124, entry.reserved);
    put_blob(&mut expected, 128, entry.name);
    assert_eq!(bytes, expected);

    let info = FileInfoV1 {
        header: sentinel_header(),
        creation_time: 0x1112_1314_1516_1718,
        last_access_time: 0x2122_2324_2526_2728,
        last_write_time: 0x3132_3334_3536_3738,
        change_time: 0x4142_4344_4546_4748,
        sizes: sentinel_sizes(),
        namespace_generation: 0x5152_5354_5556_5758,
        security_generation: 0x6162_6364_6566_6768,
        attributes: 0x7172_7374,
        link_count: 0x8182_8384,
        reparse_tag: 0x9192_9394,
        flags: 0xa1a2_a3a4,
    };
    let bytes: [u8; 104] = encode_exact(&info);
    let mut expected = [0u8; 104];
    put_header(&mut expected, 0, info.header);
    put_u64(&mut expected, 8, info.creation_time as u64);
    put_u64(&mut expected, 16, info.last_access_time as u64);
    put_u64(&mut expected, 24, info.last_write_time as u64);
    put_u64(&mut expected, 32, info.change_time as u64);
    put_sizes(&mut expected, 40, info.sizes);
    put_u64(&mut expected, 72, info.namespace_generation);
    put_u64(&mut expected, 80, info.security_generation);
    put_u32(&mut expected, 88, info.attributes);
    put_u32(&mut expected, 92, info.link_count);
    put_u32(&mut expected, 96, info.reparse_tag);
    put_u32(&mut expected, 100, info.flags);
    assert_eq!(bytes, expected);

    let volume = VolumeSizeInfoV1 {
        header: sentinel_header(),
        total_allocation_units: 0x1112_1314_1516_1718,
        available_allocation_units: 0x2122_2324_2526_2728,
        sectors_per_allocation_unit: 0x3132_3334,
        bytes_per_sector: 0x4142_4344,
        flags: 0x5152_5354,
        reserved: 0x6162_6364,
    };
    let bytes: [u8; 40] = encode_exact(&volume);
    let mut expected = [0u8; 40];
    put_header(&mut expected, 0, volume.header);
    put_u64(&mut expected, 8, volume.total_allocation_units);
    put_u64(&mut expected, 16, volume.available_allocation_units);
    put_u32(&mut expected, 24, volume.sectors_per_allocation_unit);
    put_u32(&mut expected, 28, volume.bytes_per_sector);
    put_u32(&mut expected, 32, volume.flags);
    put_u32(&mut expected, 36, volume.reserved);
    assert_eq!(bytes, expected);
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
        131_072,
        RegionDesc {
            offset: 0,
            length: 131_072,
        },
        [
            SlotClassDesc {
                slot_size: 131_072,
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
            end: 131_072,
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

fn v1_request_header(size: u32) -> ControlHeader {
    ControlHeader {
        struct_size: size,
        struct_version: CONTROL_VERSION_V1,
        required_flags: 0,
    }
}

fn v2_request_header(size: u32) -> ControlHeader {
    ControlHeader {
        struct_size: size,
        struct_version: CONTROL_VERSION_V2,
        required_flags: 0,
    }
}

fn canonical_query_info(output: BufferRef) -> QueryInfoV1 {
    QueryInfoV1 {
        header: v1_request_header(40),
        info_class: query_info_class::CANONICAL,
        flags: 0,
        reserved: 0,
        output,
    }
}

fn canonical_query_volume(output: BufferRef) -> QueryVolumeV1 {
    QueryVolumeV1 {
        header: v1_request_header(40),
        info_class: query_volume_class::SIZE,
        flags: 0,
        reserved: 0,
        output,
    }
}

fn canonical_query_security(output: BufferRef) -> QuerySecurityV1 {
    QuerySecurityV1 {
        header: v1_request_header(40),
        security_information: security_information::OWNER | security_information::DACL,
        flags: 0,
        output,
    }
}

fn canonical_query_dir_match_all(output: BufferRef) -> QueryDirV2 {
    QueryDirV2 {
        header: v2_request_header(64),
        enumeration_cookie: 0,
        flags: query_dir_flags::RESTART,
        reserved: 0,
        pattern: BlobSlice {
            offset: 0,
            length: 0,
        },
        output,
        enumeration_generation: 5,
    }
}

fn query_dir_blob(request: &QueryDirV2, pattern: &[u8]) -> Vec<u8> {
    let unpadded = 64 + pattern.len();
    let padded = unpadded.div_ceil(8) * 8;
    let mut out = vec![0u8; padded];
    assert_eq!(try_encode(request, &mut out[..64]).unwrap(), 64);
    out[64..unpadded].copy_from_slice(pattern);
    out
}

const PATTERN_STAR_AB: [u8; 6] = [0x2a, 0x00, 0x61, 0x00, 0x62, 0x00];
const PATTERN_AB: [u8; 4] = [0x61, 0x00, 0x62, 0x00];

#[test]
fn wave7b_query_requests_accept_canonical_grants() {
    let info_output = mapping_grant(7_001, buffer_access::U2K_WRITE, 104);
    let info = canonical_query_info(info_output.issued);
    assert_eq!(
        validated_length(validate_query_info_v1(&info, binding(&info_output)).unwrap()),
        104
    );
    let volume_output = mapping_grant(7_002, buffer_access::U2K_WRITE, 40);
    let volume = canonical_query_volume(volume_output.issued);
    assert_eq!(
        validated_length(validate_query_volume_v1(&volume, binding(&volume_output)).unwrap()),
        40
    );
    let security_output = mapping_grant(7_003, buffer_access::U2K_WRITE, 65_536);
    let security = canonical_query_security(security_output.issued);
    assert_eq!(
        validated_length(validate_query_security_v1(&security, binding(&security_output)).unwrap()),
        65_536
    );
    let dir_output = mapping_grant(7_004, buffer_access::U2K_WRITE, 40);
    let dir = canonical_query_dir_match_all(dir_output.issued);
    let proof =
        validate_query_dir_v2(&dir, &query_dir_blob(&dir, &[]), binding(&dir_output)).unwrap();
    assert_eq!(validated_length(proof.output()), 40);
    assert_eq!(proof.form(), QueryDirFormV21::InitialMatchAll);

    let slot_info_output = slot_grant(SlotDirection::U2k, 104, 31);
    let slot_info = canonical_query_info(slot_info_output.issued);
    assert!(validate_query_info_v1(&slot_info, binding(&slot_info_output)).is_ok());
    let slot_dir_output = slot_grant(SlotDirection::U2k, 131_072, 32);
    let slot_dir = canonical_query_dir_match_all(slot_dir_output.issued);
    assert!(validate_query_dir_v2(
        &slot_dir,
        &query_dir_blob(&slot_dir, &[]),
        binding(&slot_dir_output),
    )
    .is_ok());
}

#[test]
fn wave7b_query_request_rules_are_closed() {
    let output = mapping_grant(7_101, buffer_access::U2K_WRITE, 104);
    let canonical = canonical_query_info(output.issued);

    let mut wrong_version = canonical;
    wrong_version.header.struct_version = CONTROL_VERSION_V2;
    assert_eq!(
        validate_query_info_v1(&wrong_version, binding(&output)),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
    let mut wrong_size = canonical;
    wrong_size.header.struct_size = 39;
    assert_eq!(
        validate_query_info_v1(&wrong_size, binding(&output)),
        Err(MessageValidationError::Control(ControlError::InvalidSize))
    );
    let mut flagged = canonical;
    flagged.header.required_flags = 1;
    assert_eq!(
        validate_query_info_v1(&flagged, binding(&output)),
        Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags
        ))
    );
    for class in [query_info_class::INVALID, 2, u16::MAX] {
        let mut request = canonical;
        request.info_class = class;
        assert_eq!(
            validate_query_info_v1(&request, binding(&output)),
            Err(MessageValidationError::InvalidScalar),
            "info class {class}"
        );
    }
    let mut soft_flags = canonical;
    soft_flags.flags = 1;
    assert_eq!(
        validate_query_info_v1(&soft_flags, binding(&output)),
        Err(MessageValidationError::FlagsOrReserved)
    );
    let mut reserved = canonical;
    reserved.reserved = 1;
    assert_eq!(
        validate_query_info_v1(&reserved, binding(&output)),
        Err(MessageValidationError::FlagsOrReserved)
    );
    let short_output = mapping_grant(7_102, buffer_access::U2K_WRITE, 103);
    let short = canonical_query_info(short_output.issued);
    assert_eq!(
        validate_query_info_v1(&short, binding(&short_output)),
        Err(MessageValidationError::InvalidScalar)
    );

    for class in [query_volume_class::INVALID, 2, u16::MAX] {
        let volume_output = mapping_grant(7_103, buffer_access::U2K_WRITE, 40);
        let mut request = canonical_query_volume(volume_output.issued);
        request.info_class = class;
        assert_eq!(
            validate_query_volume_v1(&request, binding(&volume_output)),
            Err(MessageValidationError::InvalidScalar),
            "volume class {class}"
        );
    }
    let short_volume_output = mapping_grant(7_104, buffer_access::U2K_WRITE, 39);
    let short_volume = canonical_query_volume(short_volume_output.issued);
    assert_eq!(
        validate_query_volume_v1(&short_volume, binding(&short_volume_output)),
        Err(MessageValidationError::InvalidScalar)
    );

    let security_output = mapping_grant(7_105, buffer_access::U2K_WRITE, 65_536);
    for mask in [
        security_information::OWNER,
        security_information::GROUP,
        security_information::DACL,
        security_information::SACL,
        security_information::QUERY_ACCEPTED_MASK,
    ] {
        let mut request = canonical_query_security(security_output.issued);
        request.security_information = mask;
        assert!(
            validate_query_security_v1(&request, binding(&security_output)).is_ok(),
            "mask {mask:#x}"
        );
    }
    for mask in [
        0u32,
        security_information::LABEL,
        0x1f,
        security_information::SET_MASK,
    ] {
        let mut request = canonical_query_security(security_output.issued);
        request.security_information = mask;
        assert_eq!(
            validate_query_security_v1(&request, binding(&security_output)),
            Err(MessageValidationError::InvalidScalar),
            "mask {mask:#x}"
        );
    }
    for length in [65_535u32, 65_537] {
        let wrong_output =
            mapping_grant(7_106 + u64::from(length), buffer_access::U2K_WRITE, length);
        let request = canonical_query_security(wrong_output.issued);
        assert_eq!(
            validate_query_security_v1(&request, binding(&wrong_output)),
            Err(MessageValidationError::InvalidScalar),
            "security capacity {length}"
        );
    }

    let mut stacked = canonical;
    stacked.header.struct_version = CONTROL_VERSION_V2;
    stacked.flags = 1;
    stacked.info_class = query_info_class::INVALID;
    stacked.output.token ^= 1;
    assert_eq!(
        validate_query_info_v1(&stacked, binding(&output)),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
    stacked.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_query_info_v1(&stacked, binding(&output)),
        Err(MessageValidationError::FlagsOrReserved)
    );
    stacked.flags = 0;
    assert_eq!(
        validate_query_info_v1(&stacked, binding(&output)),
        Err(MessageValidationError::InvalidScalar)
    );
    stacked.info_class = query_info_class::CANONICAL;
    assert_eq!(
        validate_query_info_v1(&stacked, binding(&output)),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
    stacked.output.token ^= 1;
    assert!(validate_query_info_v1(&stacked, binding(&output)).is_ok());
}

#[test]
fn wave7b_query_dir_wire_forms_are_closed() {
    let output = mapping_grant(7_201, buffer_access::U2K_WRITE, 4_096);
    let base = canonical_query_dir_match_all(output.issued);

    let mut expression = base;
    expression.header.struct_size = 72;
    expression.pattern = BlobSlice {
        offset: 64,
        length: 6,
    };
    let star_blob = query_dir_blob(&expression, &PATTERN_STAR_AB);
    let proof = validate_query_dir_v2(&expression, &star_blob, binding(&output)).unwrap();
    assert_eq!(
        proof.form(),
        QueryDirFormV21::InitialExpression {
            exact_pattern: false
        }
    );

    let mut exact = base;
    exact.header.struct_size = 72;
    exact.flags = query_dir_flags::RESTART | query_dir_flags::EXACT_PATTERN;
    exact.pattern = BlobSlice {
        offset: 64,
        length: 4,
    };
    let exact_blob = query_dir_blob(&exact, &PATTERN_AB);
    let proof = validate_query_dir_v2(&exact, &exact_blob, binding(&output)).unwrap();
    assert_eq!(
        proof.form(),
        QueryDirFormV21::InitialExpression {
            exact_pattern: true
        }
    );

    let mut mismatched_exact = expression;
    mismatched_exact.flags = query_dir_flags::RESTART | query_dir_flags::EXACT_PATTERN;
    assert_eq!(
        validate_query_dir_v2(&mismatched_exact, &star_blob, binding(&output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Relationship
        ))
    );
    let mut missing_exact = exact;
    missing_exact.flags = query_dir_flags::RESTART;
    assert_eq!(
        validate_query_dir_v2(&missing_exact, &exact_blob, binding(&output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Relationship
        ))
    );

    let mut continuation = base;
    continuation.enumeration_cookie = 9;
    continuation.flags = 0;
    let continuation_blob = query_dir_blob(&continuation, &[]);
    let proof = validate_query_dir_v2(&continuation, &continuation_blob, binding(&output)).unwrap();
    assert_eq!(proof.form(), QueryDirFormV21::Continuation);
    let mut single_continuation = continuation;
    single_continuation.flags = query_dir_flags::SINGLE;
    assert!(validate_query_dir_v2(
        &single_continuation,
        &query_dir_blob(&single_continuation, &[]),
        binding(&output),
    )
    .is_ok());
    let mut single_initial = base;
    single_initial.flags = query_dir_flags::RESTART | query_dir_flags::SINGLE;
    assert!(validate_query_dir_v2(
        &single_initial,
        &query_dir_blob(&single_initial, &[]),
        binding(&output),
    )
    .is_ok());

    let mut zero_cookie_continuation = continuation;
    zero_cookie_continuation.enumeration_cookie = 0;
    assert_eq!(
        validate_query_dir_v2(
            &zero_cookie_continuation,
            &query_dir_blob(&zero_cookie_continuation, &[]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Identity
        ))
    );
    let mut restart_with_cookie = base;
    restart_with_cookie.enumeration_cookie = 9;
    assert_eq!(
        validate_query_dir_v2(
            &restart_with_cookie,
            &query_dir_blob(&restart_with_cookie, &[]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Relationship
        ))
    );
    let mut continuation_exact = continuation;
    continuation_exact.flags = query_dir_flags::EXACT_PATTERN;
    assert_eq!(
        validate_query_dir_v2(
            &continuation_exact,
            &query_dir_blob(&continuation_exact, &[]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved
        ))
    );
    let mut continuation_pattern = continuation;
    continuation_pattern.header.struct_size = 72;
    continuation_pattern.pattern = BlobSlice {
        offset: 64,
        length: 4,
    };
    assert_eq!(
        validate_query_dir_v2(
            &continuation_pattern,
            &query_dir_blob(&continuation_pattern, &PATTERN_AB),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Relationship
        ))
    );

    let mut unknown_flag = base;
    unknown_flag.flags = query_dir_flags::RESTART | 0x8;
    assert_eq!(
        validate_query_dir_v2(
            &unknown_flag,
            &query_dir_blob(&unknown_flag, &[]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved
        ))
    );
    let mut reserved_set = base;
    reserved_set.reserved = 1;
    assert_eq!(
        validate_query_dir_v2(
            &reserved_set,
            &query_dir_blob(&reserved_set, &[]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved
        ))
    );
    let mut zero_generation = base;
    zero_generation.enumeration_generation = 0;
    assert_eq!(
        validate_query_dir_v2(
            &zero_generation,
            &query_dir_blob(&zero_generation, &[]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Identity
        ))
    );

    let mut wrong_offset = exact;
    wrong_offset.pattern.offset = 63;
    assert_eq!(
        validate_query_dir_v2(&wrong_offset, &exact_blob, binding(&output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Relationship
        ))
    );
    let mut odd_length = exact;
    odd_length.pattern.length = 3;
    assert_eq!(
        validate_query_dir_v2(
            &odd_length,
            &query_dir_blob(&odd_length, &PATTERN_AB[..3]),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );
    let long_pattern = [0x61u8; 512];
    let mut over_length = exact;
    over_length.header.struct_size = 576;
    over_length.pattern.length = 512;
    assert_eq!(
        validate_query_dir_v2(
            &over_length,
            &query_dir_blob(&over_length, &long_pattern),
            binding(&output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );
    let mut padded_blob = query_dir_blob(&exact, &PATTERN_AB);
    padded_blob[69] = 1;
    assert_eq!(
        validate_query_dir_v2(&exact, &padded_blob, binding(&output)),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );

    let small_output = mapping_grant(7_202, buffer_access::U2K_WRITE, 39);
    let small = canonical_query_dir_match_all(small_output.issued);
    assert_eq!(
        validate_query_dir_v2(&small, &query_dir_blob(&small, &[]), binding(&small_output)),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );

    assert_eq!(validate_dir_pattern_utf16(&PATTERN_AB), Ok(true));
    assert_eq!(validate_dir_pattern_utf16(&PATTERN_STAR_AB), Ok(false));
    for wildcard in [0x2au8, 0x3f, 0x3c, 0x3e, 0x22] {
        let bytes = [wildcard, 0x00];
        assert_eq!(
            validate_dir_pattern_utf16(&bytes),
            Ok(false),
            "wildcard {wildcard:#x}"
        );
    }
    for forbidden in [[0x00u8, 0x00], [0x2f, 0x00], [0x5c, 0x00], [0x3a, 0x00]] {
        assert_eq!(
            validate_dir_pattern_utf16(&forbidden),
            Err(MessageValidationError::InvalidScalar)
        );
    }
    assert_eq!(
        validate_dir_pattern_utf16(&[]),
        Err(MessageValidationError::InvalidScalar)
    );
    assert_eq!(
        validate_dir_pattern_utf16(&[0x00, 0xd8]),
        Err(MessageValidationError::InvalidScalar)
    );
    assert_eq!(
        validate_dir_pattern_utf16(&[0x00, 0xd8, 0x00, 0xdc]),
        Ok(true)
    );
}

fn canonical_dir_entry(name_len: u32, seed: u64) -> DirEntryV1 {
    let padded = (136 + name_len).div_ceil(8) * 8;
    DirEntryV1 {
        header: ControlHeader {
            struct_size: padded,
            struct_version: 1,
            required_flags: 0,
        },
        file_id: FileId {
            lo: seed,
            hi: seed + 1,
        },
        link_id: LinkId {
            lo: seed + 2,
            hi: seed + 3,
        },
        sizes: SizeState {
            allocation_size: 4_096,
            file_size: 200,
            valid_data_length: 104,
            size_epoch: 8,
        },
        creation_time: 100,
        last_access_time: 0,
        last_write_time: 200,
        change_time: 300,
        namespace_generation: seed + 4,
        attributes: file_attributes::ARCHIVE,
        reparse_tag: 0,
        flags: 0,
        reserved: 0,
        name: BlobSlice {
            offset: 136,
            length: name_len,
        },
    }
}

fn entry_bytes(entry: &DirEntryV1, name: &[u8]) -> Vec<u8> {
    let padded = entry.header.struct_size as usize;
    let mut out = vec![0u8; padded.max(136)];
    assert_eq!(try_encode(entry, &mut out[..136]).unwrap(), 136);
    let end = (136 + name.len()).min(out.len());
    out[136..end].copy_from_slice(&name[..end - 136]);
    out.truncate(padded.max(136));
    out
}

fn result_blob(entries: &[Vec<u8>], input_cookie: u64, eof: bool) -> (QueryDirResultV1, Vec<u8>) {
    let entries_len: usize = entries.iter().map(Vec::len).sum();
    let total = 40 + entries_len;
    let count = entries.len() as u32;
    let prefix = QueryDirResultV1 {
        header: ControlHeader {
            struct_size: total as u32,
            struct_version: 1,
            required_flags: 0,
        },
        next_cookie: if eof {
            0
        } else {
            input_cookie.wrapping_add(u64::from(count))
        },
        flags: if eof { query_dir_result_flags::EOF } else { 0 },
        entry_count: count,
        entries: if entries_len == 0 {
            BlobSlice {
                offset: 0,
                length: 0,
            }
        } else {
            BlobSlice {
                offset: 40,
                length: entries_len as u32,
            }
        },
        required_length: 0,
        reserved: 0,
    };
    let mut blob = vec![0u8; 40];
    assert_eq!(try_encode(&prefix, &mut blob[..40]).unwrap(), 40);
    for entry in entries {
        blob.extend_from_slice(entry);
    }
    (prefix, blob)
}

fn rebuild_prefix(prefix: &QueryDirResultV1, blob: &mut [u8]) {
    let mut head = [0u8; 40];
    assert_eq!(try_encode(prefix, &mut head).unwrap(), 40);
    blob[..40].copy_from_slice(&head);
}

const NAME_AB16: [u8; 4] = [0x61, 0x00, 0x62, 0x00];
const NAME_A16: [u8; 2] = [0x61, 0x00];

#[test]
fn wave7b_dir_entry_chains_have_one_accepted_representation() {
    let single = entry_bytes(&canonical_dir_entry(4, 100), &NAME_AB16);
    let (prefix, blob) = result_blob(std::slice::from_ref(&single), 7, false);
    let proof = validate_query_dir_result_v1(&prefix, &blob, 7).unwrap();
    assert_eq!(proof.entry_count(), 1);
    assert_eq!(proof.next_cookie(), 8);
    assert!(!proof.eof());

    let three = [
        entry_bytes(&canonical_dir_entry(4, 200), &NAME_AB16),
        entry_bytes(&canonical_dir_entry(2, 300), &NAME_A16),
        entry_bytes(&canonical_dir_entry(4, 400), &NAME_AB16),
    ];
    let (prefix, blob) = result_blob(&three, 10, true);
    let proof = validate_query_dir_result_v1(&prefix, &blob, 10).unwrap();
    assert_eq!(proof.entry_count(), 3);
    assert_eq!(proof.next_cookie(), 0);
    assert!(proof.eof());

    let (prefix, blob) = result_blob(&[], 0, true);
    let proof = validate_query_dir_result_v1(&prefix, &blob, 0).unwrap();
    assert_eq!(proof.entry_count(), 0);
    assert!(proof.eof());
    let (mut no_eof_prefix, mut no_eof_blob) = result_blob(&[], 0, true);
    no_eof_prefix.flags = 0;
    no_eof_prefix.next_cookie = 0;
    rebuild_prefix(&no_eof_prefix, &mut no_eof_blob);
    assert_eq!(
        validate_query_dir_result_v1(&no_eof_prefix, &no_eof_blob, 0),
        Err(QueryValidationError::EntryCount)
    );

    let prefix_rows: [MutationRow<QueryDirResultV1, QueryValidationError>; 5] = [
        (
            |prefix| prefix.header.struct_version = 2,
            QueryValidationError::Message(MessageValidationError::Control(
                ControlError::RevisionMismatch,
            )),
        ),
        (
            |prefix| prefix.header.required_flags = 1,
            QueryValidationError::Message(MessageValidationError::Control(
                ControlError::UnsupportedRequiredFlags,
            )),
        ),
        (
            |prefix| prefix.flags = 2,
            QueryValidationError::Message(MessageValidationError::FlagsOrReserved),
        ),
        (
            |prefix| prefix.required_length = 1,
            QueryValidationError::Message(MessageValidationError::FlagsOrReserved),
        ),
        (
            |prefix| prefix.reserved = 1,
            QueryValidationError::Message(MessageValidationError::FlagsOrReserved),
        ),
    ];
    for (index, (mutate, expected)) in prefix_rows.into_iter().enumerate() {
        let (mut prefix, mut blob) = result_blob(std::slice::from_ref(&single), 7, false);
        mutate(&mut prefix);
        rebuild_prefix(&prefix, &mut blob);
        assert_eq!(
            validate_query_dir_result_v1(&prefix, &blob, 7),
            Err(expected),
            "prefix row {index}"
        );
    }
    let (mut short_prefix, mut short_blob) = result_blob(std::slice::from_ref(&single), 7, false);
    short_prefix.header.struct_size = 40;
    rebuild_prefix(&short_prefix, &mut short_blob);
    assert_eq!(
        validate_query_dir_result_v1(&short_prefix, &short_blob, 7),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::InvalidSize)
        ))
    );
    let (mut moved_prefix, mut moved_blob) = result_blob(std::slice::from_ref(&single), 7, false);
    moved_prefix.entries.offset = 41;
    rebuild_prefix(&moved_prefix, &mut moved_blob);
    assert_eq!(
        validate_query_dir_result_v1(&moved_prefix, &moved_blob, 7),
        Err(QueryValidationError::EntryOverrun)
    );
    let (mut short_entries_prefix, mut short_entries_blob) =
        result_blob(std::slice::from_ref(&single), 7, false);
    short_entries_prefix.entries.length = 100;
    rebuild_prefix(&short_entries_prefix, &mut short_entries_blob);
    assert_eq!(
        validate_query_dir_result_v1(&short_entries_prefix, &short_entries_blob, 7),
        Err(QueryValidationError::EntryOverrun)
    );
    let (mut over_count_prefix, mut over_count_blob) =
        result_blob(std::slice::from_ref(&single), 7, false);
    over_count_prefix.entry_count = 2;
    over_count_prefix.next_cookie = 9;
    rebuild_prefix(&over_count_prefix, &mut over_count_blob);
    assert_eq!(
        validate_query_dir_result_v1(&over_count_prefix, &over_count_blob, 7),
        Err(QueryValidationError::EntryCount)
    );
    let (mut under_count_prefix, mut under_count_blob) = result_blob(&three, 10, true);
    under_count_prefix.entry_count = 2;
    rebuild_prefix(&under_count_prefix, &mut under_count_blob);
    assert_eq!(
        validate_query_dir_result_v1(&under_count_prefix, &under_count_blob, 10),
        Err(QueryValidationError::EntryCount)
    );
    let (zero_count_prefix, mut zero_count_blob) =
        result_blob(std::slice::from_ref(&single), 7, false);
    let mut zero_count_prefix = zero_count_prefix;
    zero_count_prefix.entry_count = 0;
    zero_count_prefix.next_cookie = 7;
    rebuild_prefix(&zero_count_prefix, &mut zero_count_blob);
    assert_eq!(
        validate_query_dir_result_v1(&zero_count_prefix, &zero_count_blob, 7),
        Err(QueryValidationError::EntryCount)
    );

    let entry_rows: [MutationRow<DirEntryV1, QueryValidationError>; 12] = [
        (
            |entry| entry.header.struct_version = 2,
            QueryValidationError::Message(MessageValidationError::Control(
                ControlError::RevisionMismatch,
            )),
        ),
        (
            |entry| entry.header.required_flags = 1,
            QueryValidationError::Message(MessageValidationError::Control(
                ControlError::UnsupportedRequiredFlags,
            )),
        ),
        (
            |entry| entry.header.struct_size = 142,
            QueryValidationError::EntryAlignment,
        ),
        (
            |entry| entry.header.struct_size = 152,
            QueryValidationError::NameBounds,
        ),
        (
            |entry| entry.name.offset = 135,
            QueryValidationError::NameBounds,
        ),
        (
            |entry| entry.name.length = 0,
            QueryValidationError::NameBounds,
        ),
        (
            |entry| entry.flags = 1,
            QueryValidationError::Message(MessageValidationError::FlagsOrReserved),
        ),
        (
            |entry| entry.reserved = 1,
            QueryValidationError::Message(MessageValidationError::FlagsOrReserved),
        ),
        (
            |entry| entry.file_id = FileId { lo: 0, hi: 0 },
            QueryValidationError::Message(MessageValidationError::Identity),
        ),
        (
            |entry| entry.namespace_generation = 0,
            QueryValidationError::Message(MessageValidationError::Identity),
        ),
        (
            |entry| entry.attributes = file_attributes::REPARSE_POINT,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
        (
            |entry| entry.reparse_tag = 1,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
    ];
    for (index, (mutate, expected)) in entry_rows.into_iter().enumerate() {
        let mut entry = canonical_dir_entry(4, 500);
        mutate(&mut entry);
        let bytes = entry_bytes(&entry, &NAME_AB16);
        let entries_len = bytes.len();
        let (mut prefix, mut blob) = result_blob(&[bytes], 7, false);
        prefix.entries.length = entries_len as u32;
        prefix.header.struct_size = (40 + entries_len) as u32;
        rebuild_prefix(&prefix, &mut blob);
        assert_eq!(
            validate_query_dir_result_v1(&prefix, &blob, 7),
            Err(expected),
            "entry row {index}"
        );
    }
    let wildcard_entry = canonical_dir_entry(4, 600);
    let wildcard_name: [u8; 4] = [0x2a, 0x00, 0x62, 0x00];
    let bytes = entry_bytes(&wildcard_entry, &wildcard_name);
    let (prefix, blob) = result_blob(&[bytes], 7, false);
    assert_eq!(
        validate_query_dir_result_v1(&prefix, &blob, 7),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );
    let mut padded_entry_bytes = entry_bytes(&canonical_dir_entry(4, 800), &NAME_AB16);
    padded_entry_bytes[141] = 1;
    let (prefix, blob) = result_blob(&[padded_entry_bytes], 7, false);
    assert_eq!(
        validate_query_dir_result_v1(&prefix, &blob, 7),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );
    let mut big_entry = canonical_dir_entry(514, 900);
    big_entry.header.struct_size = 656;
    let big_name = [0x61u8; 514];
    let bytes = entry_bytes(&big_entry, &big_name);
    let (prefix, blob) = result_blob(&[bytes], 7, false);
    assert_eq!(
        validate_query_dir_result_v1(&prefix, &blob, 7),
        Err(QueryValidationError::NameBounds)
    );

    let (mut eof_bad_cookie_prefix, mut eof_bad_cookie_blob) =
        result_blob(std::slice::from_ref(&single), 7, true);
    eof_bad_cookie_prefix.next_cookie = 1;
    rebuild_prefix(&eof_bad_cookie_prefix, &mut eof_bad_cookie_blob);
    assert_eq!(
        validate_query_dir_result_v1(&eof_bad_cookie_prefix, &eof_bad_cookie_blob, 7),
        Err(QueryValidationError::CookieSuccessor)
    );
    let (mut skipped_prefix, mut skipped_blob) =
        result_blob(std::slice::from_ref(&single), 7, false);
    skipped_prefix.next_cookie = 9;
    rebuild_prefix(&skipped_prefix, &mut skipped_blob);
    assert_eq!(
        validate_query_dir_result_v1(&skipped_prefix, &skipped_blob, 7),
        Err(QueryValidationError::CookieSuccessor)
    );
    let (overflow_prefix, blob) = result_blob(std::slice::from_ref(&single), u64::MAX, false);
    assert_eq!(
        validate_query_dir_result_v1(&overflow_prefix, &blob, u64::MAX),
        Err(QueryValidationError::CookieSuccessor)
    );
}

#[test]
fn wave7b_info_volume_fsctl_and_feature_map_are_closed() {
    let info = FileInfoV1 {
        header: sentinel_header(),
        creation_time: 100,
        last_access_time: 0,
        last_write_time: 200,
        change_time: 300,
        sizes: SizeState {
            allocation_size: 4_096,
            file_size: 200,
            valid_data_length: 104,
            size_epoch: 8,
        },
        namespace_generation: 5,
        security_generation: 6,
        attributes: file_attributes::ARCHIVE,
        link_count: 0,
        reparse_tag: 0,
        flags: 0,
    };
    assert_eq!(validate_file_info_v1(&info), Ok(()));
    let info_rows: [MutationRow<FileInfoV1, MessageValidationError>; 7] = [
        (
            |info| info.namespace_generation = 0,
            MessageValidationError::Identity,
        ),
        (
            |info| info.security_generation = 0,
            MessageValidationError::Identity,
        ),
        (
            |info| info.attributes = file_attributes::REPARSE_POINT,
            MessageValidationError::InvalidScalar,
        ),
        (
            |info| info.attributes = file_attributes::NORMAL | file_attributes::READONLY,
            MessageValidationError::InvalidScalar,
        ),
        (
            |info| info.reparse_tag = 1,
            MessageValidationError::InvalidScalar,
        ),
        (
            |info| info.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
        (
            |info| info.creation_time = -1,
            MessageValidationError::InvalidScalar,
        ),
    ];
    for (index, (mutate, expected)) in info_rows.into_iter().enumerate() {
        let mut defective = info;
        mutate(&mut defective);
        assert_eq!(
            validate_file_info_v1(&defective),
            Err(expected),
            "info row {index}"
        );
    }
    let mut bad_sizes = info;
    bad_sizes.sizes.size_epoch = 0;
    assert_eq!(
        validate_file_info_v1(&bad_sizes),
        Err(MessageValidationError::SizeState)
    );

    let volume = VolumeSizeInfoV1 {
        header: sentinel_header(),
        total_allocation_units: 1_000,
        available_allocation_units: 500,
        sectors_per_allocation_unit: 8,
        bytes_per_sector: 512,
        flags: 0,
        reserved: 0,
    };
    assert_eq!(validate_volume_size_info_v1(&volume), Ok(()));
    let mut max_cluster = volume;
    max_cluster.bytes_per_sector = 65_536;
    max_cluster.sectors_per_allocation_unit = 256;
    assert_eq!(validate_volume_size_info_v1(&max_cluster), Ok(()));
    let volume_rows: [MutationRow<VolumeSizeInfoV1, MessageValidationError>; 8] = [
        (
            |volume| volume.available_allocation_units = 1_001,
            MessageValidationError::Relationship,
        ),
        (
            |volume| volume.bytes_per_sector = 511,
            MessageValidationError::InvalidScalar,
        ),
        (
            |volume| volume.bytes_per_sector = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |volume| volume.bytes_per_sector = 131_072,
            MessageValidationError::InvalidScalar,
        ),
        (
            |volume| volume.sectors_per_allocation_unit = 0,
            MessageValidationError::InvalidScalar,
        ),
        (
            |volume| volume.sectors_per_allocation_unit = 3,
            MessageValidationError::InvalidScalar,
        ),
        (
            |volume| {
                volume.bytes_per_sector = 65_536;
                volume.sectors_per_allocation_unit = 512;
            },
            MessageValidationError::InvalidScalar,
        ),
        (
            |volume| volume.flags = 1,
            MessageValidationError::FlagsOrReserved,
        ),
    ];
    for (index, (mutate, expected)) in volume_rows.into_iter().enumerate() {
        let mut defective = volume;
        mutate(&mut defective);
        assert_eq!(
            validate_volume_size_info_v1(&defective),
            Err(expected),
            "volume row {index}"
        );
    }

    let fsctl = FsctlV1 {
        header: sentinel_header(),
        code: 0,
        flags: 0,
        input: BufferRef::default(),
        output: BufferRef::default(),
    };
    assert_eq!(
        validate_fsctl_emission_v21(&fsctl),
        Err(MessageValidationError::IllegalWireForm)
    );

    fn features(bits: &[u8]) -> FeatureSet {
        let mut set = FeatureSet::default();
        for bit in bits {
            set.insert(*bit).unwrap();
        }
        set
    }
    let empty = FeatureSet::default();
    let rows: [(WireFormV21, &[u8], &[u8]); 10] = [
        (
            WireFormV21::RecoveryRequest,
            &[
                protocol_feature::HOT_RESTART,
                protocol_feature::EXACTLY_ONCE,
            ],
            &[protocol_feature::HOT_RESTART],
        ),
        (
            WireFormV21::JournalV1Attach,
            &[
                protocol_feature::HOT_RESTART,
                protocol_feature::EXACTLY_ONCE,
            ],
            &[protocol_feature::EXACTLY_ONCE],
        ),
        (
            WireFormV21::MappedRwFlag,
            &[protocol_feature::MMAP],
            &[protocol_feature::MAPPED_IO],
        ),
        (
            WireFormV21::MappingBufferKind,
            &[protocol_feature::MAPPED_IO],
            &[protocol_feature::MMAP],
        ),
        (
            WireFormV21::ReparseMutation,
            &[protocol_feature::REPARSE],
            &[protocol_feature::SECURITY],
        ),
        (
            WireFormV21::ReparseAttribute,
            &[protocol_feature::REPARSE],
            &[],
        ),
        (
            WireFormV21::PtDonation,
            &[protocol_feature::PT],
            &[protocol_feature::MMAP],
        ),
        (WireFormV21::PtNotification, &[protocol_feature::PT], &[]),
        (
            WireFormV21::QuerySecurityRequest,
            &[protocol_feature::SECURITY],
            &[],
        ),
        (
            WireFormV21::SetSecurityMutation,
            &[protocol_feature::SECURITY],
            &[protocol_feature::REPARSE],
        ),
    ];
    for (form, enough, missing) in rows {
        assert_eq!(
            validate_feature_wire_legality_v21(features(enough), form),
            Ok(()),
            "{form:?} with required features"
        );
        assert_eq!(
            validate_feature_wire_legality_v21(features(missing), form),
            Err(MessageValidationError::IllegalWireForm),
            "{form:?} with missing features"
        );
        assert_eq!(
            validate_feature_wire_legality_v21(empty, form),
            Err(MessageValidationError::IllegalWireForm),
            "{form:?} with empty features"
        );
    }
    let everything = features(&[
        protocol_feature::PT,
        protocol_feature::MMAP,
        protocol_feature::HOT_RESTART,
        protocol_feature::EXACTLY_ONCE,
        protocol_feature::SECURITY,
        protocol_feature::REPARSE,
        protocol_feature::MAPPED_IO,
    ]);
    assert_eq!(
        validate_feature_wire_legality_v21(everything, WireFormV21::SparseMutation),
        Err(MessageValidationError::IllegalWireForm)
    );
    assert_eq!(
        validate_feature_wire_legality_v21(everything, WireFormV21::RecoveryRequest),
        Ok(())
    );
}

#[test]
fn wave7b_review_hardening_closes_uncovered_rows() {
    let max_output = mapping_grant(8_001, buffer_access::U2K_WRITE, MAX_CONTROL_BLOB);
    let max_dir = canonical_query_dir_match_all(max_output.issued);
    assert!(validate_query_dir_v2(
        &max_dir,
        &query_dir_blob(&max_dir, &[]),
        binding(&max_output)
    )
    .is_ok());
    let over_output = mapping_grant(8_002, buffer_access::U2K_WRITE, MAX_CONTROL_BLOB + 1);
    let over_dir = canonical_query_dir_match_all(over_output.issued);
    assert_eq!(
        validate_query_dir_v2(
            &over_dir,
            &query_dir_blob(&over_dir, &[]),
            binding(&over_output)
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );

    let volume_output = mapping_grant(8_003, buffer_access::U2K_WRITE, 40);
    let volume_header_rows: [MutationRow<QueryVolumeV1, MessageValidationError>; 3] = [
        (
            |request| request.header.struct_version = CONTROL_VERSION_V2,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |request| request.header.struct_size = 39,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |request| request.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
    ];
    for (index, (mutate, expected)) in volume_header_rows.into_iter().enumerate() {
        let mut request = canonical_query_volume(volume_output.issued);
        mutate(&mut request);
        assert_eq!(
            validate_query_volume_v1(&request, binding(&volume_output)),
            Err(expected),
            "volume header row {index}"
        );
    }
    let security_output = mapping_grant(8_004, buffer_access::U2K_WRITE, 65_536);
    let security_header_rows: [MutationRow<QuerySecurityV1, MessageValidationError>; 3] = [
        (
            |request| request.header.struct_version = CONTROL_VERSION_V2,
            MessageValidationError::Control(ControlError::RevisionMismatch),
        ),
        (
            |request| request.header.struct_size = 39,
            MessageValidationError::Control(ControlError::InvalidSize),
        ),
        (
            |request| request.header.required_flags = 1,
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags),
        ),
    ];
    for (index, (mutate, expected)) in security_header_rows.into_iter().enumerate() {
        let mut request = canonical_query_security(security_output.issued);
        mutate(&mut request);
        assert_eq!(
            validate_query_security_v1(&request, binding(&security_output)),
            Err(expected),
            "security header row {index}"
        );
    }
    let dir_output = mapping_grant(8_005, buffer_access::U2K_WRITE, 4_096);
    let dir_base = canonical_query_dir_match_all(dir_output.issued);
    let mut dir_wrong_version = dir_base;
    dir_wrong_version.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_query_dir_v2(
            &dir_wrong_version,
            &query_dir_blob(&dir_wrong_version, &[]),
            binding(&dir_output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::RevisionMismatch)
        ))
    );
    let mut dir_flagged = dir_base;
    dir_flagged.header.required_flags = 1;
    assert_eq!(
        validate_query_dir_v2(
            &dir_flagged,
            &query_dir_blob(&dir_flagged, &[]),
            binding(&dir_output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::UnsupportedRequiredFlags)
        ))
    );
    let mut dir_wrong_size = dir_base;
    dir_wrong_size.header.struct_size = 63;
    assert_eq!(
        validate_query_dir_v2(
            &dir_wrong_size,
            &query_dir_blob(&dir_wrong_size, &[]),
            binding(&dir_output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::InvalidSize)
        ))
    );
    let mut dir_short_blob = dir_base;
    dir_short_blob.header.struct_size = 56;
    let mut short_blob = query_dir_blob(&dir_short_blob, &[]);
    short_blob.truncate(56);
    assert_eq!(
        validate_query_dir_v2(&dir_short_blob, &short_blob, binding(&dir_output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::InvalidSize)
        ))
    );

    let k2u_output = mapping_grant(8_006, buffer_access::K2U_READ_ONLY, 104);
    let k2u_request = canonical_query_info(k2u_output.issued);
    assert_eq!(
        validate_query_info_v1(&k2u_request, binding(&k2u_output)),
        Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch
        ))
    );

    let slot_volume_output = slot_grant(SlotDirection::U2k, 40, 41);
    assert!(validate_query_volume_v1(
        &canonical_query_volume(slot_volume_output.issued),
        binding(&slot_volume_output),
    )
    .is_ok());
    let slot_security_output = slot_grant(SlotDirection::U2k, 65_536, 42);
    assert!(validate_query_security_v1(
        &canonical_query_security(slot_security_output.issued),
        binding(&slot_security_output),
    )
    .is_ok());

    let mut offset_65 = dir_base;
    offset_65.header.struct_size = 72;
    offset_65.pattern = BlobSlice {
        offset: 65,
        length: 4,
    };
    assert_eq!(
        validate_query_dir_v2(
            &offset_65,
            &query_dir_blob(&offset_65, &PATTERN_AB),
            binding(&dir_output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Relationship
        ))
    );
    let mut single_expression = dir_base;
    single_expression.header.struct_size = 72;
    single_expression.flags =
        query_dir_flags::RESTART | query_dir_flags::SINGLE | query_dir_flags::EXACT_PATTERN;
    single_expression.pattern = BlobSlice {
        offset: 64,
        length: 4,
    };
    assert!(validate_query_dir_v2(
        &single_expression,
        &query_dir_blob(&single_expression, &PATTERN_AB),
        binding(&dir_output),
    )
    .is_ok());

    let mut volume_stacked = canonical_query_volume(volume_output.issued);
    volume_stacked.header.struct_version = CONTROL_VERSION_V2;
    volume_stacked.flags = 1;
    volume_stacked.info_class = query_volume_class::INVALID;
    volume_stacked.output.token ^= 1;
    assert_eq!(
        validate_query_volume_v1(&volume_stacked, binding(&volume_output)),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
    volume_stacked.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_query_volume_v1(&volume_stacked, binding(&volume_output)),
        Err(MessageValidationError::FlagsOrReserved)
    );
    volume_stacked.flags = 0;
    assert_eq!(
        validate_query_volume_v1(&volume_stacked, binding(&volume_output)),
        Err(MessageValidationError::InvalidScalar)
    );
    volume_stacked.info_class = query_volume_class::SIZE;
    assert_eq!(
        validate_query_volume_v1(&volume_stacked, binding(&volume_output)),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
    volume_stacked.output.token ^= 1;
    assert!(validate_query_volume_v1(&volume_stacked, binding(&volume_output)).is_ok());

    let mut security_stacked = canonical_query_security(security_output.issued);
    security_stacked.header.struct_version = CONTROL_VERSION_V2;
    security_stacked.flags = 1;
    security_stacked.security_information = 0;
    security_stacked.output.token ^= 1;
    assert_eq!(
        validate_query_security_v1(&security_stacked, binding(&security_output)),
        Err(MessageValidationError::Control(
            ControlError::RevisionMismatch
        ))
    );
    security_stacked.header.struct_version = CONTROL_VERSION_V1;
    assert_eq!(
        validate_query_security_v1(&security_stacked, binding(&security_output)),
        Err(MessageValidationError::FlagsOrReserved)
    );
    security_stacked.flags = 0;
    assert_eq!(
        validate_query_security_v1(&security_stacked, binding(&security_output)),
        Err(MessageValidationError::InvalidScalar)
    );
    security_stacked.security_information = security_information::OWNER;
    assert_eq!(
        validate_query_security_v1(&security_stacked, binding(&security_output)),
        Err(MessageValidationError::Grant(
            BufferRefError::CapabilityMismatch
        ))
    );
    security_stacked.output.token ^= 1;
    assert!(validate_query_security_v1(&security_stacked, binding(&security_output)).is_ok());

    let mut dir_stacked = dir_base;
    dir_stacked.header.struct_version = CONTROL_VERSION_V1;
    dir_stacked.flags = query_dir_flags::RESTART | 0x8;
    dir_stacked.enumeration_generation = 0;
    dir_stacked.output.token ^= 1;
    let stacked_blob = query_dir_blob(&dir_stacked, &[]);
    assert_eq!(
        validate_query_dir_v2(&dir_stacked, &stacked_blob, binding(&dir_output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::RevisionMismatch)
        ))
    );
    dir_stacked.header.struct_version = CONTROL_VERSION_V2;
    let stacked_blob = query_dir_blob(&dir_stacked, &[]);
    assert_eq!(
        validate_query_dir_v2(&dir_stacked, &stacked_blob, binding(&dir_output)),
        Err(QueryValidationError::Message(
            MessageValidationError::FlagsOrReserved
        ))
    );
    dir_stacked.flags = query_dir_flags::RESTART;
    let stacked_blob = query_dir_blob(&dir_stacked, &[]);
    assert_eq!(
        validate_query_dir_v2(&dir_stacked, &stacked_blob, binding(&dir_output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Identity
        ))
    );
    dir_stacked.enumeration_generation = 5;
    let stacked_blob = query_dir_blob(&dir_stacked, &[]);
    assert_eq!(
        validate_query_dir_v2(&dir_stacked, &stacked_blob, binding(&dir_output)),
        Err(QueryValidationError::Message(
            MessageValidationError::Grant(BufferRefError::CapabilityMismatch)
        ))
    );
    dir_stacked.output.token ^= 1;
    let stacked_blob = query_dir_blob(&dir_stacked, &[]);
    assert!(validate_query_dir_v2(&dir_stacked, &stacked_blob, binding(&dir_output)).is_ok());

    let chain_entry_rows: [MutationRow<DirEntryV1, QueryValidationError>; 8] = [
        (
            |entry| entry.link_id = LinkId { lo: 0, hi: 0 },
            QueryValidationError::Message(MessageValidationError::Identity),
        ),
        (
            |entry| entry.sizes.size_epoch = 0,
            QueryValidationError::Message(MessageValidationError::SizeState),
        ),
        (
            |entry| entry.creation_time = -1,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
        (
            |entry| entry.last_access_time = -1,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
        (
            |entry| entry.last_write_time = -1,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
        (
            |entry| entry.change_time = -1,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
        (
            |entry| entry.attributes = file_attributes::NORMAL | file_attributes::READONLY,
            QueryValidationError::Message(MessageValidationError::InvalidScalar),
        ),
        (
            |entry| entry.name.offset = 137,
            QueryValidationError::NameBounds,
        ),
    ];
    for (index, (mutate, expected)) in chain_entry_rows.into_iter().enumerate() {
        let mut entry = canonical_dir_entry(4, 8_100 + index as u64 * 10);
        mutate(&mut entry);
        let bytes = entry_bytes(&entry, &NAME_AB16);
        let (prefix, blob) = result_blob(&[bytes], 7, false);
        assert_eq!(
            validate_query_dir_result_v1(&prefix, &blob, 7),
            Err(expected),
            "chain entry row {index}"
        );
    }
    let long_name_entry = canonical_dir_entry(512, 8_200);
    let long_name = [0x61u8; 512];
    let bytes = entry_bytes(&long_name_entry, &long_name);
    let (prefix, blob) = result_blob(&[bytes], 7, false);
    assert_eq!(
        validate_query_dir_result_v1(&prefix, &blob, 7),
        Err(QueryValidationError::Message(
            MessageValidationError::InvalidScalar
        ))
    );
    let overrun_bytes = entry_bytes(&canonical_dir_entry(4, 8_300), &NAME_AB16);
    let (prefix, mut blob) = result_blob(&[overrun_bytes], 7, false);
    blob[40..44].copy_from_slice(&152u32.to_le_bytes());
    assert_eq!(
        validate_query_dir_result_v1(&prefix, &blob, 7),
        Err(QueryValidationError::EntryOverrun)
    );
    let (mut padded_empty_prefix, _) = result_blob(&[], 0, true);
    padded_empty_prefix.header.struct_size = 48;
    let mut padded_empty_blob = vec![0u8; 48];
    rebuild_prefix(&padded_empty_prefix, &mut padded_empty_blob);
    assert_eq!(
        validate_query_dir_result_v1(&padded_empty_prefix, &padded_empty_blob, 0),
        Err(QueryValidationError::EntryOverrun)
    );

    let canonical_info = FileInfoV1 {
        header: sentinel_header(),
        creation_time: 100,
        last_access_time: 0,
        last_write_time: 200,
        change_time: 300,
        sizes: SizeState {
            allocation_size: 4_096,
            file_size: 200,
            valid_data_length: 104,
            size_epoch: 8,
        },
        namespace_generation: 5,
        security_generation: 6,
        attributes: file_attributes::ARCHIVE,
        link_count: 0,
        reparse_tag: 0,
        flags: 0,
    };
    for (index, mutate) in [
        (|info: &mut FileInfoV1| info.last_access_time = -1) as fn(&mut FileInfoV1),
        |info| info.last_write_time = -1,
        |info| info.change_time = -1,
    ]
    .into_iter()
    .enumerate()
    {
        let mut defective = canonical_info;
        mutate(&mut defective);
        assert_eq!(
            validate_file_info_v1(&defective),
            Err(MessageValidationError::InvalidScalar),
            "file info time row {index}"
        );
    }

    let canonical_volume_info = VolumeSizeInfoV1 {
        header: sentinel_header(),
        total_allocation_units: 1_000,
        available_allocation_units: 500,
        sectors_per_allocation_unit: 8,
        bytes_per_sector: 512,
        flags: 0,
        reserved: 0,
    };
    let mut reserved_volume = canonical_volume_info;
    reserved_volume.reserved = 1;
    assert_eq!(
        validate_volume_size_info_v1(&reserved_volume),
        Err(MessageValidationError::FlagsOrReserved)
    );
    let mut small_sector = canonical_volume_info;
    small_sector.bytes_per_sector = 256;
    assert_eq!(
        validate_volume_size_info_v1(&small_sector),
        Err(MessageValidationError::InvalidScalar)
    );

    let adversarial_output = mapping_grant(8_020, buffer_access::U2K_WRITE, 4_096);
    let mut adversarial_pattern = canonical_query_dir_match_all(adversarial_output.issued);
    adversarial_pattern.header.struct_size = 64;
    adversarial_pattern.pattern = BlobSlice {
        offset: 64,
        length: u32::MAX - 6,
    };
    assert_eq!(
        validate_query_dir_v2(
            &adversarial_pattern,
            &query_dir_blob(&adversarial_pattern, &[]),
            binding(&adversarial_output),
        ),
        Err(QueryValidationError::Message(
            MessageValidationError::Control(ControlError::InvalidSize)
        ))
    );
    let mut adversarial_entry = canonical_dir_entry(4, 8_400);
    adversarial_entry.name.length = u32::MAX - 5;
    let bytes = entry_bytes(&adversarial_entry, &NAME_AB16);
    let (prefix, blob) = result_blob(&[bytes], 7, false);
    assert_eq!(
        validate_query_dir_result_v1(&prefix, &blob, 7),
        Err(QueryValidationError::NameBounds)
    );
}

mod wave8_disposition {
    use fsring_abi::{
        layout::cq_kind,
        msgs::protocol_opcode,
        op,
        validate::{
            classify_completion_v21, completion_status as cs, is_registered_completion_status_v21,
            validate_completion_output_v21, CompletionDispositionV21, CompletionOutputContextV21,
            MessageValidationError, FLUSH_FAILURES, MUTATE_FAILURES, OPEN_FAILURES, QUERY_FAILURES,
            READ_FAILURES, WRITE_FAILURES,
        },
    };

    /// Section 13 names DIR_CHANGE_ACK in the SUCCESS-only row; the opcode
    /// value is assigned by section 14 and lands as a wire type in Wave 9.
    const DIR_CHANGE_ACK: u16 = 0x0052;
    const UNREGISTERED: i32 = 0xc000_0001u32 as i32; // STATUS_UNSUCCESSFUL

    #[test]
    fn wave8_status_registry_values_are_exact() {
        assert_eq!(cs::SUCCESS, 0);
        assert_eq!(cs::NO_MORE_FILES, 0x8000_0006u32 as i32);
        assert_eq!(cs::BUFFER_OVERFLOW, 0x8000_0005u32 as i32);
        assert_eq!(cs::PENDING, 0x0000_0103);
        assert_eq!(cs::NO_SUCH_FILE, 0xc000_000fu32 as i32);
        assert_eq!(cs::END_OF_FILE, 0xc000_0011u32 as i32);
        assert_eq!(cs::BUFFER_TOO_SMALL, 0xc000_0023u32 as i32);
        assert_eq!(cs::ACCESS_DENIED, 0xc000_0022u32 as i32);
        assert_eq!(cs::OBJECT_NAME_NOT_FOUND, 0xc000_0034u32 as i32);
        assert_eq!(cs::OBJECT_NAME_COLLISION, 0xc000_0035u32 as i32);
        assert_eq!(cs::OBJECT_PATH_NOT_FOUND, 0xc000_003au32 as i32);
        assert_eq!(cs::DATA_ERROR, 0xc000_003eu32 as i32);
        assert_eq!(cs::SHARING_VIOLATION, 0xc000_0043u32 as i32);
        assert_eq!(cs::FILE_LOCK_CONFLICT, 0xc000_0054u32 as i32);
        assert_eq!(cs::DELETE_PENDING, 0xc000_0056u32 as i32);
        assert_eq!(cs::PRIVILEGE_NOT_HELD, 0xc000_0061u32 as i32);
        assert_eq!(cs::INVALID_SECURITY_DESCR, 0xc000_0079u32 as i32);
        assert_eq!(cs::DISK_FULL, 0xc000_007fu32 as i32);
        assert_eq!(cs::INTEGER_OVERFLOW, 0xc000_0095u32 as i32);
        assert_eq!(cs::INSUFFICIENT_RESOURCES, 0xc000_009au32 as i32);
        assert_eq!(cs::MEDIA_WRITE_PROTECTED, 0xc000_00a2u32 as i32);
        assert_eq!(cs::DEVICE_NOT_READY, 0xc000_00a3u32 as i32);
        assert_eq!(cs::IO_TIMEOUT, 0xc000_00b5u32 as i32);
        assert_eq!(cs::FILE_IS_A_DIRECTORY, 0xc000_00bau32 as i32);
        assert_eq!(cs::NOT_SUPPORTED, 0xc000_00bbu32 as i32);
        assert_eq!(cs::DIRECTORY_NOT_EMPTY, 0xc000_0101u32 as i32);
        assert_eq!(cs::FILE_CORRUPT_ERROR, 0xc000_0102u32 as i32);
        assert_eq!(cs::NOT_A_DIRECTORY, 0xc000_0103u32 as i32);
        assert_eq!(cs::CANCELLED, 0xc000_0120u32 as i32);
        assert_eq!(cs::CANNOT_DELETE, 0xc000_0121u32 as i32);
        assert_eq!(cs::IO_DEVICE_ERROR, 0xc000_0185u32 as i32);
        assert_eq!(cs::RETRY, 0xc000_022du32 as i32);
        assert_eq!(cs::USER_MAPPED_FILE, 0xc000_0243u32 as i32);
    }

    fn assert_sorted_unsigned(values: &[i32]) {
        for pair in values.windows(2) {
            assert!((pair[0] as u32) < (pair[1] as u32), "unsorted at {pair:?}");
        }
    }

    #[test]
    fn wave8_failure_arrays_are_sorted_and_exact() {
        assert_eq!(
            OPEN_FAILURES,
            [
                cs::ACCESS_DENIED,
                cs::OBJECT_NAME_NOT_FOUND,
                cs::OBJECT_NAME_COLLISION,
                cs::OBJECT_PATH_NOT_FOUND,
                cs::DATA_ERROR,
                cs::SHARING_VIOLATION,
                cs::DELETE_PENDING,
                cs::DISK_FULL,
                cs::INSUFFICIENT_RESOURCES,
                cs::MEDIA_WRITE_PROTECTED,
                cs::DEVICE_NOT_READY,
                cs::IO_TIMEOUT,
                cs::FILE_IS_A_DIRECTORY,
                cs::NOT_SUPPORTED,
                cs::FILE_CORRUPT_ERROR,
                cs::NOT_A_DIRECTORY,
                cs::CANCELLED,
            ]
        );
        assert_eq!(
            READ_FAILURES,
            [
                cs::ACCESS_DENIED,
                cs::DATA_ERROR,
                cs::FILE_LOCK_CONFLICT,
                cs::INSUFFICIENT_RESOURCES,
                cs::DEVICE_NOT_READY,
                cs::IO_TIMEOUT,
                cs::FILE_CORRUPT_ERROR,
                cs::CANCELLED,
            ]
        );
        assert_eq!(
            WRITE_FAILURES,
            [
                cs::ACCESS_DENIED,
                cs::DATA_ERROR,
                cs::FILE_LOCK_CONFLICT,
                cs::DISK_FULL,
                cs::INSUFFICIENT_RESOURCES,
                cs::MEDIA_WRITE_PROTECTED,
                cs::DEVICE_NOT_READY,
                cs::IO_TIMEOUT,
                cs::FILE_CORRUPT_ERROR,
                cs::CANCELLED,
                cs::RETRY,
            ]
        );
        assert_eq!(
            FLUSH_FAILURES,
            [
                cs::DATA_ERROR,
                cs::INSUFFICIENT_RESOURCES,
                cs::MEDIA_WRITE_PROTECTED,
                cs::DEVICE_NOT_READY,
                cs::IO_TIMEOUT,
                cs::FILE_CORRUPT_ERROR,
                cs::CANCELLED,
            ]
        );
        assert_eq!(
            QUERY_FAILURES,
            [
                cs::ACCESS_DENIED,
                cs::DATA_ERROR,
                cs::INSUFFICIENT_RESOURCES,
                cs::DEVICE_NOT_READY,
                cs::IO_TIMEOUT,
                cs::NOT_SUPPORTED,
                cs::FILE_CORRUPT_ERROR,
                cs::CANCELLED,
            ]
        );
        assert_eq!(
            MUTATE_FAILURES,
            [
                cs::ACCESS_DENIED,
                cs::OBJECT_NAME_NOT_FOUND,
                cs::OBJECT_NAME_COLLISION,
                cs::OBJECT_PATH_NOT_FOUND,
                cs::DATA_ERROR,
                cs::SHARING_VIOLATION,
                cs::DELETE_PENDING,
                cs::PRIVILEGE_NOT_HELD,
                cs::INVALID_SECURITY_DESCR,
                cs::DISK_FULL,
                cs::INSUFFICIENT_RESOURCES,
                cs::MEDIA_WRITE_PROTECTED,
                cs::DEVICE_NOT_READY,
                cs::IO_TIMEOUT,
                cs::NOT_SUPPORTED,
                cs::DIRECTORY_NOT_EMPTY,
                cs::FILE_CORRUPT_ERROR,
                cs::NOT_A_DIRECTORY,
                cs::CANCELLED,
                cs::CANNOT_DELETE,
                cs::RETRY,
                cs::USER_MAPPED_FILE,
            ]
        );
        assert_sorted_unsigned(&OPEN_FAILURES);
        assert_sorted_unsigned(&READ_FAILURES);
        assert_sorted_unsigned(&WRITE_FAILURES);
        assert_sorted_unsigned(&FLUSH_FAILURES);
        assert_sorted_unsigned(&QUERY_FAILURES);
        assert_sorted_unsigned(&MUTATE_FAILURES);
    }

    fn status_universe() -> Vec<i32> {
        let mut universe = vec![
            cs::SUCCESS,
            cs::NO_MORE_FILES,
            cs::BUFFER_OVERFLOW,
            cs::PENDING,
            cs::NO_SUCH_FILE,
            cs::END_OF_FILE,
            cs::BUFFER_TOO_SMALL,
            cs::INTEGER_OVERFLOW,
            cs::IO_DEVICE_ERROR,
            cs::RETRY,
            UNREGISTERED,
        ];
        universe.extend_from_slice(&OPEN_FAILURES);
        universe.extend_from_slice(&READ_FAILURES);
        universe.extend_from_slice(&WRITE_FAILURES);
        universe.extend_from_slice(&FLUSH_FAILURES);
        universe.extend_from_slice(&QUERY_FAILURES);
        universe.extend_from_slice(&MUTATE_FAILURES);
        universe.sort_unstable();
        universe.dedup();
        universe
    }

    fn assert_registered_set(opcode: u16, expected: &[i32]) {
        for status in status_universe() {
            assert_eq!(
                is_registered_completion_status_v21(opcode, status),
                expected.contains(&status),
                "opcode {opcode:#06x} status {status:#010x}"
            );
        }
    }

    #[test]
    fn wave8_opcode_status_sets_are_closed() {
        let mut prepare = vec![cs::SUCCESS];
        prepare.extend_from_slice(&OPEN_FAILURES);
        assert_registered_set(op::PREPARE_OPEN, &prepare);
        assert!(!is_registered_completion_status_v21(
            op::PREPARE_OPEN,
            cs::RETRY
        ));

        let mut commit = vec![cs::SUCCESS, cs::RETRY];
        commit.extend_from_slice(&OPEN_FAILURES);
        assert_registered_set(op::COMMIT_OPEN, &commit);

        for opcode in [op::ABORT_OPEN, op::CLEANUP, op::CLOSE] {
            assert_registered_set(opcode, &[cs::SUCCESS]);
        }

        let mut read = vec![cs::SUCCESS, cs::END_OF_FILE];
        read.extend_from_slice(&READ_FAILURES);
        assert_registered_set(op::READ, &read);

        let mut write = vec![cs::SUCCESS];
        write.extend_from_slice(&WRITE_FAILURES);
        assert_registered_set(op::WRITE, &write);

        let mut flush = vec![cs::SUCCESS];
        flush.extend_from_slice(&FLUSH_FAILURES);
        assert_registered_set(op::FLUSH, &flush);

        let mut query = vec![cs::SUCCESS];
        query.extend_from_slice(&QUERY_FAILURES);
        assert_registered_set(op::QUERY_INFO, &query);
        assert_registered_set(op::QUERY_VOLUME, &query);
        assert_registered_set(op::QUERY_SECURITY, &query);

        let mut query_dir = vec![cs::SUCCESS, cs::NO_MORE_FILES, cs::NO_SUCH_FILE];
        query_dir.extend_from_slice(&QUERY_FAILURES);
        assert_registered_set(op::QUERY_DIR, &query_dir);
        assert!(!is_registered_completion_status_v21(
            op::QUERY_DIR,
            cs::INTEGER_OVERFLOW
        ));

        let mut mutate = vec![cs::SUCCESS];
        mutate.extend_from_slice(&MUTATE_FAILURES);
        assert_registered_set(op::MUTATE, &mutate);

        for opcode in [
            op::REPLAY_OPEN,
            op::ACK_RESULT,
            op::PT_ROUTE_ACK,
            op::PT_EXTERNAL_SAFE_ACK,
            DIR_CHANGE_ACK,
        ] {
            assert_registered_set(opcode, &[cs::SUCCESS]);
        }

        assert_registered_set(op::QUERY_OP, &[cs::SUCCESS, cs::BUFFER_TOO_SMALL]);

        // CANCEL has no CQE; ATTACH is control-only; FSCTL has no legal
        // completion; unknown opcodes are closed out.
        for opcode in [op::CANCEL, op::ATTACH, op::FSCTL, 0x0777] {
            assert_registered_set(opcode, &[]);
        }
    }

    #[test]
    fn wave8_completion_classification_rows_are_closed() {
        use CompletionDispositionV21 as d;
        let completion = cq_kind::COMPLETION;

        for (opcode, status) in [
            (op::PREPARE_OPEN, cs::SUCCESS),
            (op::COMMIT_OPEN, cs::RETRY),
            (op::READ, cs::END_OF_FILE),
            (op::QUERY_DIR, cs::NO_MORE_FILES),
            (op::QUERY_OP, cs::BUFFER_TOO_SMALL),
            (op::MUTATE, cs::USER_MAPPED_FILE),
        ] {
            assert_eq!(
                classify_completion_v21(completion, opcode, status, true),
                d::Registered
            );
        }

        // Structurally empty unregistered observational results normalize.
        for (opcode, status) in [
            (op::READ, UNREGISTERED),
            (op::QUERY_INFO, cs::PENDING),
            (op::QUERY_DIR, cs::INTEGER_OVERFLOW),
            (op::QUERY_VOLUME, cs::BUFFER_OVERFLOW),
            (op::QUERY_SECURITY, cs::BUFFER_TOO_SMALL),
        ] {
            assert_eq!(
                classify_completion_v21(completion, opcode, status, true),
                d::NormalizeObservational
            );
            assert_eq!(
                classify_completion_v21(completion, opcode, status, false),
                d::SessionProtocolFault
            );
        }

        // Journaled opcodes resolve through the recovery rule instead.
        for (opcode, status) in [
            (op::COMMIT_OPEN, UNREGISTERED),
            (op::WRITE, cs::PENDING),
            (op::MUTATE, cs::BUFFER_OVERFLOW),
        ] {
            assert_eq!(
                classify_completion_v21(completion, opcode, status, true),
                d::JournaledCandidateFault
            );
            assert_eq!(
                classify_completion_v21(completion, opcode, status, false),
                d::JournaledCandidateFault
            );
        }

        // Every other unregistered completion faults the session.
        for (opcode, status) in [
            (op::PREPARE_OPEN, cs::RETRY),
            (op::ABORT_OPEN, cs::CANCELLED),
            (op::FLUSH, cs::RETRY),
            (op::REPLAY_OPEN, cs::CANCELLED),
            (op::ACK_RESULT, cs::CANCELLED),
            (op::QUERY_OP, cs::CANCELLED),
            (op::CANCEL, cs::SUCCESS),
            (op::ATTACH, cs::SUCCESS),
            (op::FSCTL, cs::SUCCESS),
            (0x0777, cs::SUCCESS),
        ] {
            assert_eq!(
                classify_completion_v21(completion, opcode, status, true),
                d::SessionProtocolFault,
                "opcode {opcode:#06x}"
            );
        }

        // NOTIFY requires opcode zero and success; PROTOCOL follows the
        // section 7 record identity.
        assert_eq!(
            classify_completion_v21(cq_kind::NOTIFY, 0, cs::SUCCESS, false),
            d::Registered
        );
        assert_eq!(
            classify_completion_v21(cq_kind::NOTIFY, 1, cs::SUCCESS, false),
            d::SessionProtocolFault
        );
        assert_eq!(
            classify_completion_v21(cq_kind::NOTIFY, 0, cs::CANCELLED, false),
            d::SessionProtocolFault
        );
        assert_eq!(
            classify_completion_v21(
                cq_kind::PROTOCOL,
                protocol_opcode::ABORT_SESSION,
                cs::SUCCESS,
                false
            ),
            d::Registered
        );
        assert_eq!(
            classify_completion_v21(cq_kind::PROTOCOL, 0, cs::SUCCESS, false),
            d::SessionProtocolFault
        );
        assert_eq!(
            classify_completion_v21(3, 0, cs::SUCCESS, true),
            d::SessionProtocolFault
        );
    }

    #[test]
    fn wave8_output_matrix_ocontrol_success_rows_are_exact() {
        use CompletionOutputContextV21 as ctx;
        for (opcode, information) in [
            (op::PREPARE_OPEN, 136u64),
            (op::COMMIT_OPEN, 112),
            (op::MUTATE, 112),
            (op::REPLAY_OPEN, 16),
            (op::QUERY_OP, 56),
        ] {
            assert_eq!(
                validate_completion_output_v21(opcode, cs::SUCCESS, 24, information, ctx::None),
                Ok(())
            );
            assert_eq!(
                validate_completion_output_v21(opcode, cs::SUCCESS, 24, information + 1, ctx::None),
                Err(MessageValidationError::Completion)
            );
            assert_eq!(
                validate_completion_output_v21(opcode, cs::SUCCESS, 0, information, ctx::None),
                Err(MessageValidationError::Completion)
            );
        }

        for opcode in [op::READ, op::WRITE] {
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    1,
                    ctx::RequestLength(4_096)
                ),
                Ok(())
            );
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    4_096,
                    ctx::RequestLength(4_096)
                ),
                Ok(())
            );
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    0,
                    ctx::RequestLength(4_096)
                ),
                Err(MessageValidationError::Completion)
            );
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    4_097,
                    ctx::RequestLength(4_096)
                ),
                Err(MessageValidationError::Completion)
            );
            assert_eq!(
                validate_completion_output_v21(opcode, cs::SUCCESS, 24, 1, ctx::None),
                Err(MessageValidationError::Relationship)
            );
        }

        for opcode in [op::QUERY_INFO, op::QUERY_VOLUME, op::QUERY_DIR] {
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    88,
                    ctx::CanonicalBlobLength(88)
                ),
                Ok(())
            );
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    89,
                    ctx::CanonicalBlobLength(88)
                ),
                Err(MessageValidationError::Completion)
            );
            assert_eq!(
                validate_completion_output_v21(
                    opcode,
                    cs::SUCCESS,
                    24,
                    0,
                    ctx::CanonicalBlobLength(0)
                ),
                Err(MessageValidationError::Completion)
            );
            assert_eq!(
                validate_completion_output_v21(opcode, cs::SUCCESS, 24, 88, ctx::None),
                Err(MessageValidationError::Relationship)
            );
        }

        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_SECURITY,
                cs::SUCCESS,
                24,
                20,
                ctx::DescriptorLength(20)
            ),
            Ok(())
        );
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_SECURITY,
                cs::SUCCESS,
                24,
                65_536,
                ctx::DescriptorLength(65_536)
            ),
            Ok(())
        );
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_SECURITY,
                cs::SUCCESS,
                24,
                19,
                ctx::DescriptorLength(19)
            ),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_SECURITY,
                cs::SUCCESS,
                24,
                65_537,
                ctx::DescriptorLength(65_537)
            ),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_SECURITY,
                cs::SUCCESS,
                24,
                21,
                ctx::DescriptorLength(20)
            ),
            Err(MessageValidationError::Completion)
        );
    }

    #[test]
    fn wave8_output_matrix_zero_rows_are_exact() {
        use CompletionOutputContextV21 as ctx;
        for (opcode, status) in [
            (op::COMMIT_OPEN, cs::RETRY),
            (op::WRITE, cs::RETRY),
            (op::READ, cs::END_OF_FILE),
            (op::QUERY_DIR, cs::NO_MORE_FILES),
            (op::QUERY_DIR, cs::NO_SUCH_FILE),
            (op::READ, cs::ACCESS_DENIED),
            (op::MUTATE, cs::SHARING_VIOLATION),
            (op::PREPARE_OPEN, cs::CANCELLED),
            (op::ABORT_OPEN, cs::SUCCESS),
            (op::CLEANUP, cs::SUCCESS),
            (op::CLOSE, cs::SUCCESS),
            (op::FLUSH, cs::SUCCESS),
            (op::ACK_RESULT, cs::SUCCESS),
            (op::PT_ROUTE_ACK, cs::SUCCESS),
            (op::PT_EXTERNAL_SAFE_ACK, cs::SUCCESS),
            (DIR_CHANGE_ACK, cs::SUCCESS),
        ] {
            assert_eq!(
                validate_completion_output_v21(opcode, status, 0, 0, ctx::None),
                Ok(()),
                "opcode {opcode:#06x} status {status:#010x}"
            );
            assert_eq!(
                validate_completion_output_v21(opcode, status, 0, 1, ctx::None),
                Err(MessageValidationError::Completion)
            );
            assert_eq!(
                validate_completion_output_v21(opcode, status, 24, 0, ctx::None),
                Err(MessageValidationError::Completion)
            );
        }
    }

    #[test]
    fn wave8_output_matrix_query_op_bts_shape_is_bounded() {
        use CompletionOutputContextV21 as ctx;
        for derived in [80u32, 112, 136, 168, 216, 224] {
            assert_eq!(
                validate_completion_output_v21(
                    op::QUERY_OP,
                    cs::BUFFER_TOO_SMALL,
                    0,
                    u64::from(derived),
                    ctx::QueryOpRetained {
                        derived_size: derived,
                        current_capacity: 40,
                    }
                ),
                Ok(()),
                "derived {derived}"
            );
        }
        // Information must exceed the current grant capacity.
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_OP,
                cs::BUFFER_TOO_SMALL,
                0,
                136,
                ctx::QueryOpRetained {
                    derived_size: 136,
                    current_capacity: 136,
                }
            ),
            Err(MessageValidationError::Completion)
        );
        // Information must equal the retained derived size.
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_OP,
                cs::BUFFER_TOO_SMALL,
                0,
                112,
                ctx::QueryOpRetained {
                    derived_size: 136,
                    current_capacity: 40,
                }
            ),
            Err(MessageValidationError::Completion)
        );
        // Values outside the closed set are rejected even when consistent.
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_OP,
                cs::BUFFER_TOO_SMALL,
                0,
                104,
                ctx::QueryOpRetained {
                    derived_size: 104,
                    current_capacity: 40,
                }
            ),
            Err(MessageValidationError::Completion)
        );
        // BTS carries no result blob.
        assert_eq!(
            validate_completion_output_v21(
                op::QUERY_OP,
                cs::BUFFER_TOO_SMALL,
                24,
                136,
                ctx::QueryOpRetained {
                    derived_size: 136,
                    current_capacity: 40,
                }
            ),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(op::QUERY_OP, cs::BUFFER_TOO_SMALL, 0, 136, ctx::None),
            Err(MessageValidationError::Relationship)
        );
    }

    #[test]
    fn wave8_output_matrix_rejects_unregistered_pairs_and_odd_lengths() {
        use CompletionOutputContextV21 as ctx;
        assert_eq!(
            validate_completion_output_v21(op::READ, cs::PENDING, 0, 0, ctx::None),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(op::PREPARE_OPEN, cs::RETRY, 0, 0, ctx::None),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(op::CANCEL, cs::SUCCESS, 0, 0, ctx::None),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(op::FSCTL, cs::SUCCESS, 0, 0, ctx::None),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_completion_output_v21(op::READ, cs::SUCCESS, 7, 1, ctx::None),
            Err(MessageValidationError::Completion)
        );
    }
}

mod wave8_recovery {
    use super::*;
    use fsring_abi::{
        durable::{
            committed_result_kind, CommittedMutationResultV1, CommittedOpenResultV1,
            CommittedResultV1, CommittedWriteResultV1,
        },
        ids::REQ_GENERATION_MAX,
        msgs::{
            query_op_state, AckResultV2, CommitOpenResultV2, MutationResultV2, QueryOpV2,
            RenameResultV2, RenameV1, SetSizeV1, UnlinkResultV1, UnlinkV1, WriteResultV2,
        },
        op,
        validate::{
            apply_domain_kind, apply_domain_reservation_v21, apply_lock_order_less_v21,
            classify_ack_pruning_v21, classify_volume_sequence_merge_v21,
            committed_result_total_size_v21, compare_committed_mutation_v21,
            compare_committed_open_v21, compare_committed_write_v21, next_req_generation_v21,
            query_op_table_action_v21, validate_ack_result_binding_v21,
            validate_committed_result_v1, validate_query_op_bts_retry_v21,
            validate_query_op_result_v1, AckBundleObservationV21, AckPruningActionV21,
            ApplyDomainCountsV21, ApplyLockEntryV21, MutationBodyRefV21, QueryOpAnswerContextV21,
            QueryOpBtsContextV21, QueryOpTableActionV21, RetainedCommittedContextV21,
            RetainedOpPhaseV21, SequenceMergeV21, ValidatedCommittedResultV1,
            MAX_APPLY_DOMAINS_PER_OPERATION, MAX_QUERY_OP_BTS_RETRIES,
        },
        OpId, TransactionId,
    };

    use fsring_abi::msgs::mutation_kind;

    fn canonical_sizes() -> SizeState {
        SizeState {
            allocation_size: 4_096,
            file_size: 100,
            valid_data_length: 60,
            size_epoch: 5,
        }
    }

    fn outer_for(opcode: u16, result_kind: u16, information: u64, total: u32) -> CommittedResultV1 {
        CommittedResultV1 {
            header: ControlHeader {
                struct_size: total,
                struct_version: 1,
                required_flags: 0,
            },
            opcode,
            result_kind,
            status: 0,
            information,
            payload: BlobSlice {
                offset: 40,
                length: total - 40,
            },
            volume_commit_sequence: 9,
        }
    }

    fn assemble(outer: &CommittedResultV1, inner: &[u8]) -> Vec<u8> {
        let mut blob = encode_exact::<_, 40>(outer).to_vec();
        blob.extend_from_slice(inner);
        blob
    }

    fn open_context() -> RetainedCommittedContextV21<'static> {
        RetainedCommittedContextV21 {
            opcode: op::COMMIT_OPEN,
            mutation_kind: 0,
            write_request_length: 0,
            mutation_body: None,
            same_parent_rename: false,
        }
    }

    fn open_inner() -> CommittedOpenResultV1 {
        CommittedOpenResultV1 {
            header: ControlHeader {
                struct_size: 96,
                struct_version: 1,
                required_flags: 0,
            },
            file_id: FileId { lo: 1, hi: 2 },
            link_id: LinkId { lo: 3, hi: 4 },
            sizes: canonical_sizes(),
            namespace_generation: 6,
            security_generation: 7,
            create_result: 1,
            flags: 0,
        }
    }

    fn open_blob(outer: &CommittedResultV1, inner: &CommittedOpenResultV1) -> Vec<u8> {
        assemble(outer, &encode_exact::<_, 96>(inner))
    }

    fn write_context() -> RetainedCommittedContextV21<'static> {
        RetainedCommittedContextV21 {
            opcode: op::WRITE,
            mutation_kind: 0,
            write_request_length: 100,
            mutation_body: None,
            same_parent_rename: false,
        }
    }

    fn write_inner() -> CommittedWriteResultV1 {
        CommittedWriteResultV1 {
            header: ControlHeader {
                struct_size: 40,
                struct_version: 1,
                required_flags: 0,
            },
            sizes: canonical_sizes(),
        }
    }

    fn mutation_inner(
        kind: u16,
        tail: u32,
        namespace: u64,
        security: u64,
    ) -> CommittedMutationResultV1 {
        CommittedMutationResultV1 {
            header: ControlHeader {
                struct_size: 72 + tail,
                struct_version: 1,
                required_flags: 0,
            },
            mutation_kind: kind,
            flags: 0,
            reserved: 0,
            sizes: canonical_sizes(),
            namespace_generation: namespace,
            security_generation: security,
            kind_payload: if tail == 0 {
                BlobSlice::default()
            } else {
                BlobSlice {
                    offset: 72,
                    length: tail,
                }
            },
        }
    }

    fn set_size_body() -> SetSizeV1 {
        SetSizeV1 {
            header: ControlHeader {
                struct_size: 24,
                struct_version: 1,
                required_flags: 0,
            },
            new_size: 100,
            flags: 0,
            reserved: 0,
        }
    }

    fn unlink_body() -> UnlinkV1 {
        UnlinkV1 {
            header: ControlHeader {
                struct_size: 56,
                struct_version: 1,
                required_flags: 0,
            },
            link_id: LinkId { lo: 21, hi: 22 },
            parent_id: FileId { lo: 23, hi: 24 },
            expected_parent_generation: 3,
            flags: 0,
            reserved: 0,
        }
    }

    fn unlink_record() -> UnlinkResultV1 {
        UnlinkResultV1 {
            header: ControlHeader {
                struct_size: 56,
                struct_version: 1,
                required_flags: 0,
            },
            file_id: FileId { lo: 1, hi: 2 },
            removed_link_id: LinkId { lo: 21, hi: 22 },
            parent_generation: 4,
            remaining_link_count: 0,
            flags: 0,
        }
    }

    fn rename_body() -> RenameV1 {
        RenameV1 {
            header: ControlHeader {
                struct_size: 80,
                struct_version: 1,
                required_flags: 0,
            },
            source_link_id: LinkId { lo: 31, hi: 32 },
            target_parent_id: FileId { lo: 33, hi: 34 },
            expected_source_parent_generation: 5,
            expected_target_parent_generation: 6,
            name: BlobSlice {
                offset: 72,
                length: 4,
            },
            flags: 0,
            reserved: 0,
        }
    }

    fn rename_record() -> RenameResultV2 {
        RenameResultV2 {
            header: ControlHeader {
                struct_size: 112,
                struct_version: 2,
                required_flags: 0,
            },
            file_id: FileId { lo: 1, hi: 2 },
            link_id: LinkId { lo: 31, hi: 32 },
            replaced_file_id: FileId::ZERO,
            replaced_link_id: LinkId::ZERO,
            source_parent_generation: 7,
            target_parent_generation: 8,
            replaced_namespace_generation: 0,
            link_count: 1,
            replaced_link_count: 0,
            flags: 0,
            reserved: 0,
        }
    }

    #[test]
    fn wave8_committed_result_totals_are_the_closed_set() {
        assert_eq!(committed_result_total_size_v21(op::WRITE, 0), Some(80));
        assert_eq!(
            committed_result_total_size_v21(op::COMMIT_OPEN, 0),
            Some(136)
        );
        for kind in [
            mutation_kind::SET_BASIC_INFO,
            mutation_kind::SET_ALLOCATION_SIZE,
            mutation_kind::SET_END_OF_FILE,
            mutation_kind::SET_VALID_DATA_LENGTH,
            mutation_kind::SET_SECURITY,
        ] {
            assert_eq!(
                committed_result_total_size_v21(op::MUTATE, kind),
                Some(112),
                "kind {kind}"
            );
        }
        assert_eq!(
            committed_result_total_size_v21(op::MUTATE, mutation_kind::UNLINK),
            Some(168)
        );
        assert_eq!(
            committed_result_total_size_v21(op::MUTATE, mutation_kind::LINK),
            Some(216)
        );
        assert_eq!(
            committed_result_total_size_v21(op::MUTATE, mutation_kind::RENAME),
            Some(224)
        );
        for illegal in [
            (op::READ, 0),
            (op::QUERY_OP, 0),
            (op::MUTATE, mutation_kind::INVALID),
            (op::MUTATE, mutation_kind::SET_REPARSE),
            (op::MUTATE, mutation_kind::DELETE_REPARSE),
            (op::MUTATE, mutation_kind::SET_SPARSE),
            (op::WRITE, mutation_kind::RENAME),
            (op::COMMIT_OPEN, mutation_kind::UNLINK),
        ] {
            assert_eq!(
                committed_result_total_size_v21(illegal.0, illegal.1),
                None,
                "{illegal:?}"
            );
        }
    }

    #[test]
    fn wave8_committed_open_result_accepts_and_pins_every_field_rule() {
        let blob = open_blob(&outer_for(op::COMMIT_OPEN, 2, 0, 136), &open_inner());
        match validate_committed_result_v1(&blob, &open_context()) {
            Ok(ValidatedCommittedResultV1::Open { outer, inner }) => {
                assert_eq!(outer.volume_commit_sequence, 9);
                assert_eq!(inner.create_result, 1);
                assert_eq!(inner.namespace_generation, 6);
            }
            Ok(_) => panic!("wrong committed variant"),
            Err(error) => panic!("unexpected rejection {error:?}"),
        }

        // Context sanity is checked before any byte is trusted.
        let mut bad_context = open_context();
        bad_context.mutation_kind = mutation_kind::RENAME;
        assert_eq!(
            validate_committed_result_v1(&blob, &bad_context).unwrap_err(),
            MessageValidationError::Relationship
        );
        let mut bad_context = write_context();
        bad_context.write_request_length = 0;
        assert_eq!(
            validate_committed_result_v1(&blob, &bad_context).unwrap_err(),
            MessageValidationError::Relationship
        );

        // Total size and outer header discipline.
        let mut oversize = blob.clone();
        oversize.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            validate_committed_result_v1(&oversize, &open_context()).unwrap_err(),
            MessageValidationError::InvalidScalar
        );
        let mut lying_header = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        lying_header.header.struct_size = 128;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&lying_header, &open_inner()), &open_context())
                .unwrap_err(),
            MessageValidationError::Control(ControlError::InvalidSize)
        );
        let mut wrong_version = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        wrong_version.header.struct_version = 2;
        assert_eq!(
            validate_committed_result_v1(
                &open_blob(&wrong_version, &open_inner()),
                &open_context()
            )
            .unwrap_err(),
            MessageValidationError::Control(ControlError::RevisionMismatch)
        );

        // Outer identity, kind, status, information, sequence, framing.
        let wrong_opcode = outer_for(op::WRITE, 2, 0, 136);
        assert_eq!(
            validate_committed_result_v1(&open_blob(&wrong_opcode, &open_inner()), &open_context())
                .unwrap_err(),
            MessageValidationError::Identity
        );
        for kind in [
            committed_result_kind::INVALID,
            committed_result_kind::EMPTY,
            committed_result_kind::WRITE,
            5,
        ] {
            let bad = outer_for(op::COMMIT_OPEN, kind, 0, 136);
            assert_eq!(
                validate_committed_result_v1(&open_blob(&bad, &open_inner()), &open_context())
                    .unwrap_err(),
                MessageValidationError::InvalidScalar,
                "kind {kind}"
            );
        }
        let mut bad_status = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        bad_status.status = 0xc000_0120u32 as i32;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&bad_status, &open_inner()), &open_context())
                .unwrap_err(),
            MessageValidationError::Completion
        );
        let nonzero_information = outer_for(op::COMMIT_OPEN, 2, 1, 136);
        assert_eq!(
            validate_committed_result_v1(
                &open_blob(&nonzero_information, &open_inner()),
                &open_context()
            )
            .unwrap_err(),
            MessageValidationError::Completion
        );
        let mut zero_sequence = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        zero_sequence.volume_commit_sequence = 0;
        assert_eq!(
            validate_committed_result_v1(
                &open_blob(&zero_sequence, &open_inner()),
                &open_context()
            )
            .unwrap_err(),
            MessageValidationError::InvalidScalar
        );
        let mut bad_payload = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        bad_payload.payload.offset = 39;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&bad_payload, &open_inner()), &open_context())
                .unwrap_err(),
            MessageValidationError::Relationship
        );
        let mut short_payload = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        short_payload.payload.length = 88;
        assert_eq!(
            validate_committed_result_v1(
                &open_blob(&short_payload, &open_inner()),
                &open_context()
            )
            .unwrap_err(),
            MessageValidationError::Relationship
        );

        // Inner record rules.
        let outer = outer_for(op::COMMIT_OPEN, 2, 0, 136);
        let mut inner = open_inner();
        inner.header.struct_size = 88;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&outer, &inner), &open_context()).unwrap_err(),
            MessageValidationError::Control(ControlError::InvalidSize)
        );
        let mut inner = open_inner();
        inner.flags = 1;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&outer, &inner), &open_context()).unwrap_err(),
            MessageValidationError::FlagsOrReserved
        );
        let mut inner = open_inner();
        inner.file_id = FileId::ZERO;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&outer, &inner), &open_context()).unwrap_err(),
            MessageValidationError::Identity
        );
        let mut inner = open_inner();
        inner.security_generation = 0;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&outer, &inner), &open_context()).unwrap_err(),
            MessageValidationError::Identity
        );
        let mut inner = open_inner();
        inner.create_result = 4;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&outer, &inner), &open_context()).unwrap_err(),
            MessageValidationError::InvalidScalar
        );
        let mut inner = open_inner();
        inner.sizes.file_size = 5_000;
        assert_eq!(
            validate_committed_result_v1(&open_blob(&outer, &inner), &open_context()).unwrap_err(),
            MessageValidationError::Relationship
        );
    }

    #[test]
    fn wave8_committed_write_result_binds_information_to_the_request() {
        let blob = assemble(
            &outer_for(op::WRITE, 3, 42, 80),
            &encode_exact::<_, 40>(&write_inner()),
        );
        match validate_committed_result_v1(&blob, &write_context()) {
            Ok(ValidatedCommittedResultV1::Write { outer, inner }) => {
                assert_eq!(outer.information, 42);
                assert_eq!(inner.sizes.size_epoch, 5);
            }
            Ok(_) => panic!("wrong committed variant"),
            Err(error) => panic!("unexpected rejection {error:?}"),
        }

        for information in [0u64, 101, 4_096] {
            let blob = assemble(
                &outer_for(op::WRITE, 3, information, 80),
                &encode_exact::<_, 40>(&write_inner()),
            );
            assert_eq!(
                validate_committed_result_v1(&blob, &write_context()).unwrap_err(),
                MessageValidationError::Completion,
                "information {information}"
            );
        }
        let mut inner = write_inner();
        inner.sizes.size_epoch = 0;
        let blob = assemble(
            &outer_for(op::WRITE, 3, 42, 80),
            &encode_exact::<_, 40>(&inner),
        );
        assert_eq!(
            validate_committed_result_v1(&blob, &write_context()).unwrap_err(),
            MessageValidationError::SizeState
        );
    }

    #[test]
    fn wave8_committed_mutation_results_close_kind_generation_and_payload_rules() {
        let body = set_size_body();
        let context = RetainedCommittedContextV21 {
            opcode: op::MUTATE,
            mutation_kind: mutation_kind::SET_END_OF_FILE,
            write_request_length: 0,
            mutation_body: Some(MutationBodyRefV21::SetEndOfFile(&body)),
            same_parent_rename: false,
        };
        let inner = mutation_inner(mutation_kind::SET_END_OF_FILE, 0, 0, 0);
        let blob = assemble(
            &outer_for(op::MUTATE, 4, 0, 112),
            &encode_exact::<_, 72>(&inner),
        );
        match validate_committed_result_v1(&blob, &context) {
            Ok(ValidatedCommittedResultV1::Mutation {
                inner,
                kind_payload,
                ..
            }) => {
                assert_eq!(inner.mutation_kind, mutation_kind::SET_END_OF_FILE);
                assert!(kind_payload.is_empty());
            }
            Ok(_) => panic!("wrong committed variant"),
            Err(error) => panic!("unexpected rejection {error:?}"),
        }

        // MUTATE context demands a matching retained body.
        let mut orphan = context;
        orphan.mutation_body = None;
        assert_eq!(
            validate_committed_result_v1(&blob, &orphan).unwrap_err(),
            MessageValidationError::Relationship
        );
        let mut mismatched = context;
        mismatched.mutation_kind = mutation_kind::SET_ALLOCATION_SIZE;
        assert_eq!(
            validate_committed_result_v1(&blob, &mismatched).unwrap_err(),
            MessageValidationError::Relationship
        );

        // Inner kind echo, generation pattern, and payload closure.
        let wrong_kind = mutation_inner(mutation_kind::SET_ALLOCATION_SIZE, 0, 0, 0);
        let blob2 = assemble(
            &outer_for(op::MUTATE, 4, 0, 112),
            &encode_exact::<_, 72>(&wrong_kind),
        );
        assert_eq!(
            validate_committed_result_v1(&blob2, &context).unwrap_err(),
            MessageValidationError::Identity
        );
        let stray_namespace = mutation_inner(mutation_kind::SET_END_OF_FILE, 0, 6, 0);
        let blob2 = assemble(
            &outer_for(op::MUTATE, 4, 0, 112),
            &encode_exact::<_, 72>(&stray_namespace),
        );
        assert_eq!(
            validate_committed_result_v1(&blob2, &context).unwrap_err(),
            MessageValidationError::InvalidScalar
        );
        let mut stray_payload = mutation_inner(mutation_kind::SET_END_OF_FILE, 0, 0, 0);
        stray_payload.kind_payload = BlobSlice {
            offset: 72,
            length: 8,
        };
        let blob2 = assemble(
            &outer_for(op::MUTATE, 4, 0, 112),
            &encode_exact::<_, 72>(&stray_payload),
        );
        assert_eq!(
            validate_committed_result_v1(&blob2, &context).unwrap_err(),
            MessageValidationError::Relationship
        );
        let nonzero_information = assemble(
            &outer_for(op::MUTATE, 4, 1, 112),
            &encode_exact::<_, 72>(&inner),
        );
        assert_eq!(
            validate_committed_result_v1(&nonzero_information, &context).unwrap_err(),
            MessageValidationError::Completion
        );
    }

    #[test]
    fn wave8_committed_unlink_and_rename_validate_their_inline_records() {
        let unlink = unlink_body();
        let unlink_context = RetainedCommittedContextV21 {
            opcode: op::MUTATE,
            mutation_kind: mutation_kind::UNLINK,
            write_request_length: 0,
            mutation_body: Some(MutationBodyRefV21::Unlink(&unlink)),
            same_parent_rename: false,
        };
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::UNLINK, 56, 8, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 56>(&unlink_record()));
        let blob = assemble(&outer_for(op::MUTATE, 4, 0, 168), &inner_bytes);
        match validate_committed_result_v1(&blob, &unlink_context) {
            Ok(ValidatedCommittedResultV1::Mutation { kind_payload, .. }) => {
                assert_eq!(kind_payload.len(), 56);
            }
            Ok(_) => panic!("wrong committed variant"),
            Err(error) => panic!("unexpected rejection {error:?}"),
        }

        // The inline record must echo the retained request identity.
        let mut treacherous = unlink_record();
        treacherous.removed_link_id = LinkId { lo: 99, hi: 98 };
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::UNLINK, 56, 8, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 56>(&treacherous));
        assert_eq!(
            validate_committed_result_v1(
                &assemble(&outer_for(op::MUTATE, 4, 0, 168), &inner_bytes),
                &unlink_context
            )
            .unwrap_err(),
            MessageValidationError::Identity
        );
        // A stale parent generation is rejected by the record rule.
        let mut stale = unlink_record();
        stale.parent_generation = 3;
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::UNLINK, 56, 8, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 56>(&stale));
        assert_eq!(
            validate_committed_result_v1(
                &assemble(&outer_for(op::MUTATE, 4, 0, 168), &inner_bytes),
                &unlink_context
            )
            .unwrap_err(),
            MessageValidationError::Identity
        );
        // UNLINK requires a nonzero result namespace generation.
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::UNLINK, 56, 0, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 56>(&unlink_record()));
        assert_eq!(
            validate_committed_result_v1(
                &assemble(&outer_for(op::MUTATE, 4, 0, 168), &inner_bytes),
                &unlink_context
            )
            .unwrap_err(),
            MessageValidationError::Identity
        );
        // The payload slice must cover exactly the record.
        let mut short_slice = mutation_inner(mutation_kind::UNLINK, 56, 8, 0);
        short_slice.kind_payload.length = 48;
        let mut inner_bytes = encode_exact::<_, 72>(&short_slice).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 56>(&unlink_record()));
        assert_eq!(
            validate_committed_result_v1(
                &assemble(&outer_for(op::MUTATE, 4, 0, 168), &inner_bytes),
                &unlink_context
            )
            .unwrap_err(),
            MessageValidationError::Relationship
        );

        let rename = rename_body();
        let rename_context = RetainedCommittedContextV21 {
            opcode: op::MUTATE,
            mutation_kind: mutation_kind::RENAME,
            write_request_length: 0,
            mutation_body: Some(MutationBodyRefV21::Rename(&rename)),
            same_parent_rename: false,
        };
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::RENAME, 112, 9, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 112>(&rename_record()));
        let blob = assemble(&outer_for(op::MUTATE, 4, 0, 224), &inner_bytes);
        assert!(validate_committed_result_v1(&blob, &rename_context).is_ok());

        // A non-advancing source parent generation is rejected.
        let mut stale = rename_record();
        stale.source_parent_generation = 5;
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::RENAME, 112, 9, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 112>(&stale));
        assert_eq!(
            validate_committed_result_v1(
                &assemble(&outer_for(op::MUTATE, 4, 0, 224), &inner_bytes),
                &rename_context
            )
            .unwrap_err(),
            MessageValidationError::Identity
        );
        // Same-parent renames demand equal parent generations.
        let mut same_parent = rename_context;
        same_parent.same_parent_rename = true;
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::RENAME, 112, 9, 0)).to_vec();
        inner_bytes.extend_from_slice(&encode_exact::<_, 112>(&rename_record()));
        assert_eq!(
            validate_committed_result_v1(
                &assemble(&outer_for(op::MUTATE, 4, 0, 224), &inner_bytes),
                &same_parent
            )
            .unwrap_err(),
            MessageValidationError::Relationship
        );
    }

    fn candidate_open() -> CommitOpenResultV2 {
        CommitOpenResultV2 {
            header: ControlHeader {
                struct_size: 112,
                struct_version: 2,
                required_flags: 0,
            },
            provider_open_cookie: 0xdead_beef,
            file_id: FileId { lo: 1, hi: 2 },
            link_id: LinkId { lo: 3, hi: 4 },
            sizes: canonical_sizes(),
            namespace_generation: 6,
            security_generation: 7,
            create_result: 1,
            result_flags: 0,
            volume_commit_sequence: 9,
        }
    }

    #[test]
    fn wave8_candidate_to_durable_open_comparison_excludes_only_the_cookie() {
        let blob = open_blob(&outer_for(op::COMMIT_OPEN, 2, 0, 136), &open_inner());
        let durable = validate_committed_result_v1(&blob, &open_context()).unwrap();

        let mut candidate = candidate_open();
        assert_eq!(compare_committed_open_v21(&durable, &candidate), Ok(()));
        // The provider-open cookie is session-local and excluded.
        candidate.provider_open_cookie = 1;
        assert_eq!(compare_committed_open_v21(&durable, &candidate), Ok(()));

        for wreck in [
            |c: &mut CommitOpenResultV2| c.volume_commit_sequence = 10,
            |c: &mut CommitOpenResultV2| c.file_id = FileId { lo: 9, hi: 2 },
            |c: &mut CommitOpenResultV2| c.link_id = LinkId { lo: 9, hi: 4 },
            |c: &mut CommitOpenResultV2| c.sizes.size_epoch = 6,
            |c: &mut CommitOpenResultV2| c.namespace_generation = 7,
            |c: &mut CommitOpenResultV2| c.security_generation = 8,
            |c: &mut CommitOpenResultV2| c.create_result = 2,
        ] {
            let mut candidate = candidate_open();
            wreck(&mut candidate);
            assert_eq!(
                compare_committed_open_v21(&durable, &candidate),
                Err(MessageValidationError::Relationship)
            );
        }

        let write_blob = assemble(
            &outer_for(op::WRITE, 3, 42, 80),
            &encode_exact::<_, 40>(&write_inner()),
        );
        let wrong_shape = validate_committed_result_v1(&write_blob, &write_context()).unwrap();
        assert_eq!(
            compare_committed_open_v21(&wrong_shape, &candidate_open()),
            Err(MessageValidationError::Relationship)
        );
    }

    #[test]
    fn wave8_candidate_to_durable_write_comparison_binds_information() {
        let blob = assemble(
            &outer_for(op::WRITE, 3, 42, 80),
            &encode_exact::<_, 40>(&write_inner()),
        );
        let durable = validate_committed_result_v1(&blob, &write_context()).unwrap();
        let candidate = WriteResultV2 {
            header: ControlHeader {
                struct_size: 56,
                struct_version: 2,
                required_flags: 0,
            },
            sizes: canonical_sizes(),
            volume_commit_sequence: 9,
            flags: 0,
            reserved: 0,
        };
        assert_eq!(
            compare_committed_write_v21(&durable, &candidate, 42),
            Ok(())
        );
        assert_eq!(
            compare_committed_write_v21(&durable, &candidate, 41),
            Err(MessageValidationError::Relationship)
        );
        let mut skewed = candidate;
        skewed.volume_commit_sequence = 10;
        assert_eq!(
            compare_committed_write_v21(&durable, &skewed, 42),
            Err(MessageValidationError::Relationship)
        );
        let mut skewed = candidate;
        skewed.sizes.valid_data_length = 61;
        assert_eq!(
            compare_committed_write_v21(&durable, &skewed, 42),
            Err(MessageValidationError::Relationship)
        );
    }

    #[test]
    fn wave8_candidate_to_durable_mutation_comparison_includes_kind_payload_bytes() {
        let unlink = unlink_body();
        let unlink_context = RetainedCommittedContextV21 {
            opcode: op::MUTATE,
            mutation_kind: mutation_kind::UNLINK,
            write_request_length: 0,
            mutation_body: Some(MutationBodyRefV21::Unlink(&unlink)),
            same_parent_rename: false,
        };
        let record_bytes = encode_exact::<_, 56>(&unlink_record());
        let mut inner_bytes =
            encode_exact::<_, 72>(&mutation_inner(mutation_kind::UNLINK, 56, 8, 0)).to_vec();
        inner_bytes.extend_from_slice(&record_bytes);
        let blob = assemble(&outer_for(op::MUTATE, 4, 0, 168), &inner_bytes);
        let durable = validate_committed_result_v1(&blob, &unlink_context).unwrap();

        let candidate = MutationResultV2 {
            header: ControlHeader {
                struct_size: 112,
                struct_version: 2,
                required_flags: 0,
            },
            op_id: OpId { lo: 5, hi: 6 },
            volume_commit_sequence: 9,
            mutation_kind: mutation_kind::UNLINK,
            result_flags: 0,
            reserved: 0,
            sizes: canonical_sizes(),
            namespace_generation: 8,
            security_generation: 0,
            kind_result: BufferRef {
                token: 1,
                offset: 0,
                length: 56,
                kind: buffer_kind::MAPPING,
                access: buffer_access::U2K_WRITE,
                reserved: 0,
            },
        };
        assert_eq!(
            compare_committed_mutation_v21(&durable, &candidate, &record_bytes),
            Ok(())
        );

        let mut flipped = record_bytes;
        flipped[40] ^= 1;
        assert_eq!(
            compare_committed_mutation_v21(&durable, &candidate, &flipped),
            Err(MessageValidationError::Relationship)
        );
        let mut skewed = candidate;
        skewed.namespace_generation = 9;
        assert_eq!(
            compare_committed_mutation_v21(&durable, &skewed, &record_bytes),
            Err(MessageValidationError::Relationship)
        );
        let mut skewed = candidate;
        skewed.mutation_kind = mutation_kind::RENAME;
        assert_eq!(
            compare_committed_mutation_v21(&durable, &skewed, &record_bytes),
            Err(MessageValidationError::Relationship)
        );
    }

    fn committed_grant() -> GrantMetadata {
        GrantMetadata {
            capability: GrantCapability::Mapping {
                token: 0x51,
                length: 224,
            },
            session_epoch: 9,
            owner: GrantOwner::Request(ReqId::try_new(7, 3).unwrap()),
            access: buffer_access::U2K_WRITE,
            maximum: CheckedRange64 { start: 0, end: 224 },
            state: GrantState::Live,
            issued: BufferRef {
                token: 0x51,
                offset: 0,
                length: 224,
                kind: buffer_kind::MAPPING,
                access: buffer_access::U2K_WRITE,
                reserved: 0,
            },
        }
    }

    fn query_op_request() -> QueryOpV2 {
        QueryOpV2 {
            header: ControlHeader {
                struct_size: 104,
                struct_version: 2,
                required_flags: 0,
            },
            op_id: OpId { lo: 5, hi: 6 },
            operation_digest: [7u8; 32],
            reply: BufferRef::default(),
            committed_result: BufferRef::default(),
        }
    }

    fn query_op_answer(state: u16, result: BufferRef) -> fsring_abi::msgs::QueryOpResultV1 {
        fsring_abi::msgs::QueryOpResultV1 {
            header: ControlHeader {
                struct_size: 56,
                struct_version: 1,
                required_flags: 0,
            },
            state,
            flags: 0,
            reserved: 0,
            op_id: OpId { lo: 5, hi: 6 },
            result,
        }
    }

    fn committed_echo(length: u32) -> BufferRef {
        BufferRef {
            token: 0x51,
            offset: 0,
            length,
            kind: buffer_kind::MAPPING,
            access: buffer_access::U2K_WRITE,
            reserved: 0,
        }
    }

    #[test]
    fn wave8_query_op_answer_shape_is_closed() {
        let grant = committed_grant();
        let request = query_op_request();
        let bind = GrantBindingV21 {
            grant: &grant,
            expected_session_epoch: 9,
            expected_owner: grant.owner,
        };

        let answer = query_op_answer(query_op_state::NOT_FOUND, BufferRef::default());
        let validated = validate_query_op_result_v1(&answer, &request, bind, 136, false).unwrap();
        assert_eq!(validated.state(), query_op_state::NOT_FOUND);
        assert!(validated.committed_result().is_none());

        let answer = query_op_answer(query_op_state::PREPARED, BufferRef::default());
        assert!(validate_query_op_result_v1(&answer, &request, bind, 136, false).is_ok());

        let answer = query_op_answer(query_op_state::COMMITTED, committed_echo(136));
        let validated = validate_query_op_result_v1(&answer, &request, bind, 136, false).unwrap();
        assert_eq!(validated.state(), query_op_state::COMMITTED);
        assert!(validated.committed_result().is_some());

        // Abort mode can never observe PREPARED.
        let answer = query_op_answer(query_op_state::PREPARED, BufferRef::default());
        assert_eq!(
            validate_query_op_result_v1(&answer, &request, bind, 136, true),
            Err(MessageValidationError::Completion)
        );
        // Wire-shape rules.
        let mut answer = query_op_answer(query_op_state::NOT_FOUND, BufferRef::default());
        answer.header.struct_version = 2;
        assert_eq!(
            validate_query_op_result_v1(&answer, &request, bind, 136, false),
            Err(MessageValidationError::Control(
                ControlError::RevisionMismatch
            ))
        );
        let mut answer = query_op_answer(query_op_state::NOT_FOUND, BufferRef::default());
        answer.flags = 1;
        assert_eq!(
            validate_query_op_result_v1(&answer, &request, bind, 136, false),
            Err(MessageValidationError::FlagsOrReserved)
        );
        let mut answer = query_op_answer(query_op_state::NOT_FOUND, BufferRef::default());
        answer.reserved = 1;
        assert_eq!(
            validate_query_op_result_v1(&answer, &request, bind, 136, false),
            Err(MessageValidationError::FlagsOrReserved)
        );
        let mut answer = query_op_answer(query_op_state::NOT_FOUND, BufferRef::default());
        answer.op_id = OpId { lo: 5, hi: 7 };
        assert_eq!(
            validate_query_op_result_v1(&answer, &request, bind, 136, false),
            Err(MessageValidationError::Identity)
        );
        for state in [query_op_state::INVALID, 4] {
            let answer = query_op_answer(state, BufferRef::default());
            assert_eq!(
                validate_query_op_result_v1(&answer, &request, bind, 136, false),
                Err(MessageValidationError::InvalidScalar),
                "state {state}"
            );
        }
        // NOT_FOUND and PREPARED forbid a result reference.
        let answer = query_op_answer(query_op_state::NOT_FOUND, committed_echo(136));
        assert!(matches!(
            validate_query_op_result_v1(&answer, &request, bind, 136, false),
            Err(MessageValidationError::Grant(_))
        ));
        // COMMITTED must shrink the echo to the exact derived size.
        let answer = query_op_answer(query_op_state::COMMITTED, committed_echo(224));
        assert_eq!(
            validate_query_op_result_v1(&answer, &request, bind, 136, false),
            Err(MessageValidationError::Completion)
        );
    }

    fn table_context(cancel: bool, abort: bool, commit_open: bool) -> QueryOpAnswerContextV21 {
        QueryOpAnswerContextV21 {
            exactly_once_selected: true,
            cancel_requested: cancel,
            abort_mode: abort,
            is_commit_open: commit_open,
        }
    }

    #[test]
    fn wave8_query_op_phase_table_is_total_and_closed() {
        use QueryOpTableActionV21 as a;
        use RetainedOpPhaseV21 as p;
        let nf = query_op_state::NOT_FOUND;
        let pr = query_op_state::PREPARED;
        let co = query_op_state::COMMITTED;
        let plain = table_context(false, false, false);

        // EXACTLY_ONCE gates every emission.
        let mut off = plain;
        off.exactly_once_selected = false;
        assert_eq!(
            query_op_table_action_v21(p::NoCandidate, nf, off),
            Ok(a::ExactlyOnceProtocolFault)
        );
        // Abort mode resolves atomically and can never observe PREPARED.
        assert_eq!(
            query_op_table_action_v21(p::NoCandidate, pr, table_context(true, true, false)),
            Ok(a::AbortModePreparedFault)
        );
        assert_eq!(
            query_op_table_action_v21(p::NoCandidate, nf, table_context(true, true, false)),
            Ok(a::CompleteCancelled)
        );
        assert_eq!(
            query_op_table_action_v21(p::NoCandidate, co, table_context(true, true, false)),
            Ok(a::ValidateDurableThenCommittedVerified)
        );

        let rows: [(
            RetainedOpPhaseV21,
            u16,
            QueryOpAnswerContextV21,
            QueryOpTableActionV21,
        ); 34] = [
            (p::NoCandidate, nf, plain, a::ResubmitSameOperation),
            (
                p::NoCandidate,
                nf,
                table_context(true, false, false),
                a::CompleteCancelled,
            ),
            (
                p::NoCandidate,
                nf,
                table_context(true, false, true),
                a::EnterAbortOpenSubprotocol,
            ),
            (p::NoCandidate, pr, plain, a::ResumeTransaction),
            (
                p::NoCandidate,
                pr,
                table_context(true, false, false),
                a::IssueAbortIfPrepared,
            ),
            (
                p::NoCandidate,
                co,
                plain,
                a::ValidateDurableThenCommittedVerified,
            ),
            (p::FailureCandidate, nf, plain, a::CompleteSavedFailure),
            (
                p::FailureCandidate,
                nf,
                table_context(false, false, true),
                a::AbortOpenThenSavedFailure,
            ),
            (p::FailureCandidate, pr, plain, a::Indeterminate),
            (
                p::FailureCandidate,
                co,
                plain,
                a::DurableWinsRecordViolation,
            ),
            (p::SuccessCandidate, nf, plain, a::Indeterminate),
            (p::SuccessCandidate, pr, plain, a::Indeterminate),
            (
                p::SuccessCandidate,
                co,
                plain,
                a::RequireExactCandidateEquality,
            ),
            (p::InvalidCandidate, nf, plain, a::Indeterminate),
            (p::InvalidCandidate, pr, plain, a::Indeterminate),
            (
                p::InvalidCandidate,
                co,
                plain,
                a::IgnoreCandidateValidateDurable,
            ),
            (p::CommittedVerified, nf, plain, a::Indeterminate),
            (p::CommittedVerified, pr, plain, a::Indeterminate),
            (p::CommittedVerified, co, plain, a::ApplyOnce),
            (p::AppliedNotifyPending, nf, plain, a::Indeterminate),
            (p::AppliedNotifyPending, pr, plain, a::Indeterminate),
            (
                p::AppliedNotifyPending,
                co,
                plain,
                a::DeliverOrCoverNotification,
            ),
            (p::AppliedAckUnsent, nf, plain, a::Indeterminate),
            (p::AppliedAckUnsent, pr, plain, a::Indeterminate),
            (p::AppliedAckUnsent, co, plain, a::PrepareAndPublishAck),
            (p::AppliedAckSent, nf, plain, a::InferAcknowledged),
            (p::AppliedAckSent, pr, plain, a::Indeterminate),
            (p::AppliedAckSent, co, plain, a::RetryIdenticalAck),
            (p::Acknowledged, nf, plain, a::NoQueryOpEmitted),
            (p::Acknowledged, pr, plain, a::NoQueryOpEmitted),
            (p::Acknowledged, co, plain, a::NoQueryOpEmitted),
            (p::Indeterminate, nf, plain, a::AdministrativeTeardownOnly),
            (p::Indeterminate, pr, plain, a::AdministrativeTeardownOnly),
            (p::Indeterminate, co, plain, a::AdministrativeTeardownOnly),
        ];
        for (phase, answer, context, expected) in rows {
            assert_eq!(
                query_op_table_action_v21(phase, answer, context),
                Ok(expected),
                "{phase:?} answer {answer}"
            );
        }
        assert_eq!(
            query_op_table_action_v21(p::NoCandidate, 0, plain),
            Err(MessageValidationError::InvalidScalar)
        );
        assert_eq!(
            query_op_table_action_v21(p::NoCandidate, 4, plain),
            Err(MessageValidationError::InvalidScalar)
        );
    }

    #[test]
    fn wave8_bts_retry_is_single_and_exact() {
        assert_eq!(MAX_QUERY_OP_BTS_RETRIES, 1);
        let recovery = QueryOpBtsContextV21 {
            opcode: op::WRITE,
            mutation_kind: 0,
            current_capacity: 40,
            prior_bts_retries: 0,
            ordinary_confirmation: false,
        };
        assert_eq!(validate_query_op_bts_retry_v21(&recovery, 80), Ok(80));

        // The ordinary confirmation grant is complete; BTS against it is
        // always a protocol fault.
        let mut ordinary = recovery;
        ordinary.ordinary_confirmation = true;
        ordinary.current_capacity = 224;
        assert_eq!(
            validate_query_op_bts_retry_v21(&ordinary, 80),
            Err(MessageValidationError::Completion)
        );
        // Only one retry ever.
        let mut second = recovery;
        second.prior_bts_retries = 1;
        assert_eq!(
            validate_query_op_bts_retry_v21(&second, 80),
            Err(MessageValidationError::Completion)
        );
        // The reported size must equal the exact derived size.
        assert_eq!(
            validate_query_op_bts_retry_v21(&recovery, 79),
            Err(MessageValidationError::Completion)
        );
        assert_eq!(
            validate_query_op_bts_retry_v21(&recovery, 224),
            Err(MessageValidationError::Completion)
        );
        // Equal or decreasing capacity is illegal.
        let mut saturated = recovery;
        saturated.current_capacity = 80;
        assert_eq!(
            validate_query_op_bts_retry_v21(&saturated, 80),
            Err(MessageValidationError::Completion)
        );
        let mut oversupplied = recovery;
        oversupplied.current_capacity = 96;
        assert_eq!(
            validate_query_op_bts_retry_v21(&oversupplied, 80),
            Err(MessageValidationError::Completion)
        );
        // A context with no derived size cannot retry.
        let mut alien = recovery;
        alien.opcode = op::READ;
        assert_eq!(
            validate_query_op_bts_retry_v21(&alien, 80),
            Err(MessageValidationError::Relationship)
        );
    }

    #[test]
    fn wave8_ack_binding_authenticates_op_id_and_digest() {
        let retained_digest = [0x2au8; 32];
        let request = AckResultV2 {
            header: ControlHeader {
                struct_size: 56,
                struct_version: 2,
                required_flags: 0,
            },
            op_id: OpId { lo: 5, hi: 6 },
            operation_digest: retained_digest,
        };
        assert_eq!(
            validate_ack_result_binding_v21(&request, OpId { lo: 5, hi: 6 }, &retained_digest),
            Ok(())
        );
        assert_eq!(
            validate_ack_result_binding_v21(&request, OpId { lo: 5, hi: 7 }, &retained_digest),
            Err(MessageValidationError::Identity)
        );
        let mut drifted = retained_digest;
        drifted[13] ^= 4;
        assert_eq!(
            validate_ack_result_binding_v21(&request, OpId { lo: 5, hi: 6 }, &drifted),
            Err(MessageValidationError::Identity)
        );
        assert_eq!(
            validate_ack_result_binding_v21(&request, OpId { lo: 5, hi: 6 }, &[0u8; 32]),
            Err(MessageValidationError::InvalidScalar)
        );
        let mut malformed = request;
        malformed.header.struct_version = 1;
        assert_eq!(
            validate_ack_result_binding_v21(&malformed, OpId { lo: 5, hi: 6 }, &retained_digest),
            Err(MessageValidationError::Control(
                ControlError::RevisionMismatch
            ))
        );
    }

    #[test]
    fn wave8_ack_pruning_classification_is_closed() {
        use AckBundleObservationV21 as o;
        use AckPruningActionV21 as act;
        assert_eq!(
            classify_ack_pruning_v21(o::CommittedExact),
            act::DeleteAndSucceed
        );
        assert_eq!(classify_ack_pruning_v21(o::Absent), act::IdempotentSuccess);
        assert_eq!(
            classify_ack_pruning_v21(o::PreparedPresent),
            act::Corruption
        );
        assert_eq!(classify_ack_pruning_v21(o::PartialBundle), act::Corruption);
        assert_eq!(classify_ack_pruning_v21(o::DigestMismatch), act::Corruption);
    }

    #[test]
    fn wave8_apply_domain_registry_is_exact_and_bounded() {
        assert_eq!(apply_domain_kind::FILE_STATE, 1);
        assert_eq!(apply_domain_kind::DIRECTORY_NAMESPACE, 2);
        assert_eq!(apply_domain_kind::LINK_STATE, 3);
        assert_eq!(apply_domain_kind::OPEN_STATE, 4);
        assert_eq!(MAX_APPLY_DOMAINS_PER_OPERATION, 6);

        let expect = |file, directory_namespace, link, open| ApplyDomainCountsV21 {
            file,
            directory_namespace,
            link,
            open,
        };
        assert_eq!(
            apply_domain_reservation_v21(op::COMMIT_OPEN, 0, false),
            Some(expect(1, 1, 1, 1))
        );
        assert_eq!(
            apply_domain_reservation_v21(op::WRITE, 0, false),
            Some(expect(1, 0, 0, 0))
        );
        assert_eq!(
            apply_domain_reservation_v21(op::MUTATE, mutation_kind::SET_BASIC_INFO, false),
            Some(expect(1, 0, 0, 1))
        );
        for kind in [
            mutation_kind::SET_ALLOCATION_SIZE,
            mutation_kind::SET_END_OF_FILE,
            mutation_kind::SET_VALID_DATA_LENGTH,
            mutation_kind::SET_SECURITY,
        ] {
            assert_eq!(
                apply_domain_reservation_v21(op::MUTATE, kind, false),
                Some(expect(1, 0, 0, 0)),
                "kind {kind}"
            );
        }
        assert_eq!(
            apply_domain_reservation_v21(op::MUTATE, mutation_kind::RENAME, false),
            Some(expect(1, 2, 1, 0))
        );
        assert_eq!(
            apply_domain_reservation_v21(op::MUTATE, mutation_kind::RENAME, true),
            Some(expect(2, 2, 2, 0))
        );
        assert_eq!(
            apply_domain_reservation_v21(op::MUTATE, mutation_kind::LINK, false),
            Some(expect(1, 1, 1, 0))
        );
        assert_eq!(
            apply_domain_reservation_v21(op::MUTATE, mutation_kind::LINK, true),
            Some(expect(2, 1, 2, 0))
        );
        assert_eq!(
            apply_domain_reservation_v21(op::MUTATE, mutation_kind::UNLINK, false),
            Some(expect(1, 1, 1, 0))
        );
        // Replacement is a RENAME/LINK-only input; every other row demands
        // false, unselectable kinds and foreign opcodes have no row.
        for (opcode, kind) in [
            (op::COMMIT_OPEN, 0),
            (op::WRITE, 0),
            (op::MUTATE, mutation_kind::SET_BASIC_INFO),
            (op::MUTATE, mutation_kind::SET_SECURITY),
            (op::MUTATE, mutation_kind::UNLINK),
        ] {
            assert_eq!(
                apply_domain_reservation_v21(opcode, kind, true),
                None,
                "{opcode:#06x}/{kind}"
            );
        }
        for (opcode, kind) in [
            (op::MUTATE, mutation_kind::INVALID),
            (op::MUTATE, mutation_kind::SET_REPARSE),
            (op::MUTATE, mutation_kind::DELETE_REPARSE),
            (op::MUTATE, mutation_kind::SET_SPARSE),
            (op::READ, 0),
            (op::PREPARE_OPEN, 0),
            (op::WRITE, mutation_kind::RENAME),
        ] {
            assert_eq!(
                apply_domain_reservation_v21(opcode, kind, false),
                None,
                "{opcode:#06x}/{kind}"
            );
        }
        // Every legal row fits the prepublication reservation bound and the
        // worst case saturates it exactly.
        let mut worst = 0;
        for (opcode, kind, with_replacement) in [
            (op::COMMIT_OPEN, 0, false),
            (op::WRITE, 0, false),
            (op::MUTATE, mutation_kind::SET_BASIC_INFO, false),
            (op::MUTATE, mutation_kind::SET_ALLOCATION_SIZE, false),
            (op::MUTATE, mutation_kind::SET_END_OF_FILE, false),
            (op::MUTATE, mutation_kind::SET_VALID_DATA_LENGTH, false),
            (op::MUTATE, mutation_kind::SET_SECURITY, false),
            (op::MUTATE, mutation_kind::RENAME, false),
            (op::MUTATE, mutation_kind::RENAME, true),
            (op::MUTATE, mutation_kind::LINK, false),
            (op::MUTATE, mutation_kind::LINK, true),
            (op::MUTATE, mutation_kind::UNLINK, false),
        ] {
            let counts = apply_domain_reservation_v21(opcode, kind, with_replacement).unwrap();
            assert!(counts.total() <= MAX_APPLY_DOMAINS_PER_OPERATION);
            if counts.total() > worst {
                worst = counts.total();
            }
        }
        assert_eq!(worst, MAX_APPLY_DOMAINS_PER_OPERATION);
    }

    #[test]
    fn wave8_apply_lock_order_is_file_then_domain_then_link() {
        let entry = |fhi, flo, kind, lhi, llo| ApplyLockEntryV21 {
            file_id: FileId { lo: flo, hi: fhi },
            domain_kind: kind,
            link_id: LinkId { lo: llo, hi: lhi },
        };
        let canonical = [
            entry(1, 5, apply_domain_kind::FILE_STATE, 0, 0),
            entry(1, 5, apply_domain_kind::DIRECTORY_NAMESPACE, 0, 0),
            entry(1, 5, apply_domain_kind::LINK_STATE, 2, 1),
            entry(1, 5, apply_domain_kind::LINK_STATE, 2, 2),
            entry(1, 5, apply_domain_kind::LINK_STATE, 3, 0),
            entry(1, 6, apply_domain_kind::FILE_STATE, 0, 0),
            entry(2, 0, apply_domain_kind::FILE_STATE, 0, 0),
        ];
        for window in canonical.windows(2) {
            assert!(apply_lock_order_less_v21(&window[0], &window[1]));
            assert!(!apply_lock_order_less_v21(&window[1], &window[0]));
        }
        let same = entry(1, 5, apply_domain_kind::LINK_STATE, 2, 1);
        assert!(!apply_lock_order_less_v21(&same, &same));

        let mut shuffled = [
            canonical[4],
            canonical[0],
            canonical[6],
            canonical[2],
            canonical[1],
            canonical[5],
            canonical[3],
        ];
        shuffled.sort_by(|left, right| {
            if apply_lock_order_less_v21(left, right) {
                core::cmp::Ordering::Less
            } else if apply_lock_order_less_v21(right, left) {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        });
        assert_eq!(shuffled, canonical);
    }

    #[test]
    fn wave8_sequence_and_generation_merges_never_wrap() {
        use SequenceMergeV21 as m;
        assert_eq!(
            classify_volume_sequence_merge_v21(0, 0, true),
            Err(MessageValidationError::InvalidScalar)
        );
        assert_eq!(
            classify_volume_sequence_merge_v21(0, 1, false),
            Ok(m::Fresh)
        );
        assert_eq!(
            classify_volume_sequence_merge_v21(9, 10, false),
            Ok(m::Fresh)
        );
        assert_eq!(
            classify_volume_sequence_merge_v21(9, 9, true),
            Ok(m::ExactRepeat)
        );
        assert_eq!(
            classify_volume_sequence_merge_v21(9, 9, false),
            Err(MessageValidationError::Relationship)
        );
        assert_eq!(
            classify_volume_sequence_merge_v21(9, 8, false),
            Ok(m::StaleSuppressed)
        );

        assert_eq!(next_req_generation_v21(0), Ok(1));
        assert_eq!(next_req_generation_v21(5), Ok(6));
        assert_eq!(
            next_req_generation_v21(REQ_GENERATION_MAX - 1),
            Ok(REQ_GENERATION_MAX)
        );
        assert_eq!(
            next_req_generation_v21(REQ_GENERATION_MAX),
            Err(MessageValidationError::InvalidScalar)
        );
        assert_eq!(
            next_req_generation_v21(u64::MAX),
            Err(MessageValidationError::InvalidScalar)
        );
    }

    #[test]
    fn wave8_recovery_identity_scalars_stay_pinned() {
        // TransactionId participates in the ABORT_OPEN subprotocol identity;
        // its zero form is never a legal retained transaction.
        assert_eq!(TransactionId::ZERO, TransactionId { lo: 0, hi: 0 });
    }
}
