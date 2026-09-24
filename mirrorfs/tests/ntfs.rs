#![cfg(windows)]

mod support;

use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::process::Command;
use std::time::{Duration, SystemTime};

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::ids::{FileId, LinkId, OpId, ReqId, TransactionId};
use fsring_abi::layout::{
    op, RegionDesc, SlotClassDesc, SqeBody, SLOT_CLASS_COUNT, SQE_PAYLOAD_LEN,
};
use fsring_abi::msgs::{
    basic_info_set_mask, buffer_kind, create_result, file_attributes, link_flags, mutation_kind,
    rename_flags, security_information, BlobSlice, BufferRef, CommitOpenV2, ControlHeader,
    DirEntryV1, LinkResultV2, LinkV1, MutationV2, PControl, PrepareOpenV2, QueryDirResultV1,
    RenameResultV2, RenameV1, SetBasicInfoV1, SetSizeV1, SizeState, UnlinkResultV1, UnlinkV1,
    CONTROL_VERSION_V1, CONTROL_VERSION_V2,
};
use fsring_abi::slots::{
    validate_slot_arena, BufferRefPolicy, GrantOwner, SlotDirection, SlotToken, ValidatedSlotArena,
};
use fsring_abi::validate::{completion_status, validate_query_dir_result_v1, QueryDirFormV21};
use fsring_user::{
    build_file_info, build_mutation_result, build_volume_size_info, decode_mutation,
    revalidate_context, write_body, CommitRequest, DecodedBody, DirCandidate, DirEnumerator,
    GrantTable, HeapSection, MutationContext, MutationRequest, PreparedRequest, ProviderError,
    QueryDirRequest,
};
use mirrorfs::{MirrorFs, MirrorFsError};

use support::TempRoot;

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const MUTATION_TEST_SECTION_SIZE: u64 = 2 * 65_536;
const MUTATION_TEST_REQ_ID: u64 = 0x000d_0000_0001;

struct DecodedMutationFixture {
    _section: HeapSection,
    table: GrantTable,
    owner: GrantOwner,
    request: MutationRequest,
}

fn mutation_test_arena(direction: SlotDirection, offset: u64) -> ValidatedSlotArena {
    let classes = [
        SlotClassDesc {
            slot_size: 4096,
            slot_count: 8,
            data_offset: offset,
        },
        SlotClassDesc {
            slot_size: 8192,
            slot_count: 4,
            data_offset: offset + 32_768,
        },
        SlotClassDesc {
            slot_size: 0,
            slot_count: 0,
            data_offset: 0,
        },
        SlotClassDesc {
            slot_size: 0,
            slot_count: 0,
            data_offset: 0,
        },
    ];
    assert_eq!(classes.len(), SLOT_CLASS_COUNT);
    validate_slot_arena(
        direction,
        MUTATION_TEST_SECTION_SIZE,
        RegionDesc {
            offset,
            length: 65_536,
        },
        classes,
    )
    .expect("compact mutation test arena is valid")
}

fn write_granted_blob(
    section: &HeapSection,
    table: &GrantTable,
    owner: GrantOwner,
    reference: &BufferRef,
    bytes: &[u8],
) {
    let validated = table
        .resolve(reference, owner, BufferRefPolicy::Exact)
        .expect("resolve fixture grant");
    write_body(section, &validated, bytes).expect("write fixture grant");
}

fn decoded_mutation(
    kind: u16,
    expected_namespace_generation: u64,
    expected_size_epoch: u64,
    expected_security_generation: u64,
    body_bytes: &[u8],
    same_parent_rename: bool,
) -> DecodedMutationFixture {
    let section = HeapSection::with_len(MUTATION_TEST_SECTION_SIZE as usize, 65_536);
    let k2u = mutation_test_arena(SlotDirection::K2u, 0);
    let u2k = mutation_test_arena(SlotDirection::U2k, 65_536);
    let owner = GrantOwner::Request(ReqId::from_raw(MUTATION_TEST_REQ_ID));
    let mut table = GrantTable::new(1);
    let env_token = SlotToken::try_new(0, 0, 1).unwrap();
    let body_token = SlotToken::try_new(0, 1, 1).unwrap();
    let reply_token = SlotToken::try_new(1, 0, 1).unwrap();
    let kind_token = SlotToken::try_new(0, 2, 1).unwrap();
    let body_ref = table
        .issue_k2u(&k2u, owner, body_token, body_bytes.len() as u32)
        .expect("issue mutation body");
    write_granted_blob(&section, &table, owner, &body_ref, body_bytes);
    let reply_ref = table
        .issue_u2k(&u2k, owner, reply_token, 112)
        .expect("issue mutation reply");
    let kind_result_len = match kind {
        mutation_kind::RENAME => 112,
        mutation_kind::LINK => 104,
        mutation_kind::UNLINK => 56,
        _ => 0,
    };
    let kind_result = if kind_result_len == 0 {
        BufferRef {
            token: 0,
            offset: 0,
            length: 0,
            kind: buffer_kind::NONE,
            access: 0,
            reserved: 0,
        }
    } else {
        table
            .issue_u2k(&u2k, owner, kind_token, kind_result_len)
            .expect("issue mutation kind result")
    };
    let envelope = MutationV2 {
        header: ControlHeader {
            struct_size: 128,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        op_id: OpId {
            lo: u64::from(kind),
            hi: 1,
        },
        mutation_kind: kind,
        mutation_flags: 0,
        reserved: 0,
        expected_namespace_generation,
        expected_size_epoch,
        expected_security_generation,
        body: body_ref,
        reply: reply_ref,
        kind_result,
    };
    let mut envelope_bytes = [0_u8; 128];
    try_encode(&envelope, &mut envelope_bytes).expect("encode mutation envelope");
    let env_ref = table
        .issue_k2u(&k2u, owner, env_token, envelope_bytes.len() as u32)
        .expect("issue mutation envelope");
    write_granted_blob(&section, &table, owner, &env_ref, &envelope_bytes);
    let pcontrol = PControl { body: env_ref };
    let mut payload = [0_u8; SQE_PAYLOAD_LEN];
    try_encode(&pcontrol, &mut payload[..24]).expect("encode PControl");
    let sqe = SqeBody {
        opcode: op::MUTATE,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id: MUTATION_TEST_REQ_ID,
        kernel_open_id: 0,
        ccb_sequence: 0,
        payload,
    };
    let request = decode_mutation(&sqe, &table, &section, owner, same_parent_rename)
        .expect("decode mutation");
    DecodedMutationFixture {
        _section: section,
        table,
        owner,
        request,
    }
}

fn decoded_task13_mutation(
    kind: u16,
    expected_namespace_generation: u64,
    expected_size_epoch: u64,
    body_bytes: &[u8],
) -> DecodedMutationFixture {
    decoded_mutation(
        kind,
        expected_namespace_generation,
        expected_size_epoch,
        0,
        body_bytes,
        false,
    )
}

fn utf16le_name(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn rename_body(
    source_link_id: LinkId,
    target_parent_id: FileId,
    expected_source_parent_generation: u64,
    expected_target_parent_generation: u64,
    name: &str,
    replace: bool,
) -> Vec<u8> {
    let name = utf16le_name(name);
    let body_len = (72 + name.len()).div_ceil(8) * 8;
    let raw = RenameV1 {
        header: ControlHeader {
            struct_size: body_len as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        source_link_id,
        target_parent_id,
        expected_source_parent_generation,
        expected_target_parent_generation,
        name: BlobSlice {
            offset: 72,
            length: name.len() as u32,
        },
        flags: if replace {
            rename_flags::REPLACE_IF_EXISTS
        } else {
            0
        },
        reserved: 0,
    };
    let mut bytes = vec![0; body_len];
    try_encode(&raw, &mut bytes[..72]).expect("encode rename body");
    bytes[72..72 + name.len()].copy_from_slice(&name);
    bytes
}

fn link_body(
    source_file_id: FileId,
    target_parent_id: FileId,
    expected_target_parent_generation: u64,
    name: &str,
    replace: bool,
) -> Vec<u8> {
    let name = utf16le_name(name);
    let body_len = (64 + name.len()).div_ceil(8) * 8;
    let raw = LinkV1 {
        header: ControlHeader {
            struct_size: body_len as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        source_file_id,
        target_parent_id,
        expected_target_parent_generation,
        name: BlobSlice {
            offset: 64,
            length: name.len() as u32,
        },
        flags: if replace {
            link_flags::REPLACE_IF_EXISTS
        } else {
            0
        },
        reserved: 0,
    };
    let mut bytes = vec![0; body_len];
    try_encode(&raw, &mut bytes[..64]).expect("encode link body");
    bytes[64..64 + name.len()].copy_from_slice(&name);
    bytes
}

fn unlink_body(link_id: LinkId, parent_id: FileId, expected_parent_generation: u64) -> [u8; 56] {
    let raw = UnlinkV1 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        link_id,
        parent_id,
        expected_parent_generation,
        flags: 0,
        reserved: 0,
    };
    let mut bytes = [0; 56];
    try_encode(&raw, &mut bytes).expect("encode unlink body");
    bytes
}

#[derive(Clone, Copy)]
struct PrepareCase<'a> {
    op: u64,
    parent: FileId,
    name: &'a str,
    disposition: u32,
    create_options: u32,
    attributes: u32,
    share_access: u32,
}

fn prepare_request(case: PrepareCase<'_>) -> PreparedRequest {
    prepare_request_with_access(case, FILE_GENERIC_READ | FILE_GENERIC_WRITE)
}

fn prepare_request_with_access(case: PrepareCase<'_>, desired_access: u32) -> PreparedRequest {
    let mut raw: PrepareOpenV2 = try_decode(&[0_u8; 192]).expect("zeroed prepare body");
    raw.op_id = OpId { lo: case.op, hi: 0 };
    raw.parent_id = case.parent;
    raw.desired_access = desired_access;
    raw.share_access = case.share_access;
    raw.disposition = case.disposition;
    raw.create_options = case.create_options;
    raw.file_attributes = case.attributes;
    let name = case
        .name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    PreparedRequest::from_raw(raw, name, None, None)
}

fn commit_request(
    request: &PreparedRequest,
    transaction: u64,
    kernel_open_id: u64,
    namespace_generation: u64,
    security_generation: u64,
) -> CommitRequest {
    let mut raw: CommitOpenV2 = try_decode(&[0_u8; 104]).expect("zeroed commit body");
    raw.op_id = request.op_id;
    raw.transaction_id = TransactionId {
        lo: transaction,
        hi: 0,
    };
    raw.expected_namespace_generation = namespace_generation;
    raw.expected_security_generation = security_generation;
    raw.kernel_open_id = kernel_open_id;
    raw.granted_access = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    CommitRequest::from_raw(raw)
}

fn commit_request_with_access(
    request: &PreparedRequest,
    transaction: u64,
    kernel_open_id: u64,
    namespace_generation: u64,
    security_generation: u64,
    granted_access: u32,
) -> CommitRequest {
    let mut raw: CommitOpenV2 = try_decode(&[0_u8; 104]).expect("zeroed commit body");
    raw.op_id = request.op_id;
    raw.transaction_id = TransactionId {
        lo: transaction,
        hi: 0,
    };
    raw.expected_namespace_generation = namespace_generation;
    raw.expected_security_generation = security_generation;
    raw.kernel_open_id = kernel_open_id;
    raw.granted_access = granted_access;
    CommitRequest::from_raw(raw)
}

fn expect_status<T>(result: Result<T, ProviderError>, expected: i32) {
    match result {
        Ok(_) => panic!("expected provider status {expected:#010x}"),
        Err(error) => assert_eq!(error.status(), expected),
    }
}

fn all_shares() -> u32 {
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
}

fn grant_current_user_full_control(path: &std::path::Path) {
    let domain = std::env::var_os("USERDOMAIN").expect("Windows USERDOMAIN");
    let username = std::env::var_os("USERNAME").expect("Windows USERNAME");
    let mut principal = domain;
    principal.push("\\");
    principal.push(username);
    principal.push(":(F)");
    let output = Command::new("icacls.exe")
        .arg(path)
        .arg("/grant:r")
        .arg(principal)
        .output()
        .expect("launch Windows ACL utility");
    assert!(
        output.status.success(),
        "grant full control on owned test object: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn normalized_native_security_descriptor(descriptor: &[u8]) -> Vec<u8> {
    let mut normalized = descriptor.to_vec();
    let control = u16::from_le_bytes([normalized[2], normalized[3]]);
    // Windows may canonicalize DEFAULTED/AUTO_INHERIT/PROTECTED control
    // metadata when the same selected owner/group/DACL is reapplied. Preserve
    // only the component-presence and self-relative semantics for comparison.
    let semantic_control = control & (0x0010 | 0x0004 | 0x8000);
    normalized[2..4].copy_from_slice(&semantic_control.to_le_bytes());
    normalized
}

fn basic_info_body(
    set_mask: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
) -> SetBasicInfoV1 {
    SetBasicInfoV1 {
        header: ControlHeader {
            struct_size: 48,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
        attributes,
        set_mask,
    }
}

fn size_state_tuple(sizes: SizeState) -> (u64, u64, u64, u64) {
    (
        sizes.allocation_size,
        sizes.file_size,
        sizes.valid_data_length,
        sizes.size_epoch,
    )
}

fn candidate_name(candidate: &DirCandidate) -> String {
    let units: Vec<u16> = candidate
        .name
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&units).expect("provider emitted canonical UTF-16LE")
}

fn query_dir_request(
    form: QueryDirFormV21,
    generation: u64,
    cookie: u64,
    single: bool,
    pattern: Option<&str>,
) -> QueryDirRequest {
    const OUTPUT_CAPACITY: u32 = 64 * 1024;
    QueryDirRequest {
        form,
        enumeration_generation: generation,
        enumeration_cookie: cookie,
        single,
        output_capacity: OUTPUT_CAPACITY,
        output: BufferRef {
            length: OUTPUT_CAPACITY,
            ..Default::default()
        },
        pattern: pattern.map(|value| value.encode_utf16().collect::<Vec<_>>().into_boxed_slice()),
    }
}

fn query_dir_batch_names(blob: &[u8], input_cookie: u64) -> Vec<String> {
    let result: QueryDirResultV1 = try_decode(blob).expect("decode query-dir result");
    let validated = validate_query_dir_result_v1(&result, blob, input_cookie)
        .expect("provider candidates encode canonically");
    let mut cursor = result.entries.offset as usize;
    let mut names = Vec::with_capacity(validated.entry_count() as usize);
    for _ in 0..validated.entry_count() {
        let entry: DirEntryV1 = try_decode(&blob[cursor..]).expect("decode directory entry");
        let name_start = cursor + entry.name.offset as usize;
        let name_end = name_start + entry.name.length as usize;
        let units: Vec<u16> = blob[name_start..name_end]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        names.push(String::from_utf16(&units).expect("encoded entry name is valid UTF-16"));
        cursor += entry.header.struct_size as usize;
    }
    names
}

#[test]
fn d_temp_is_a_fixed_ntfs_backing_volume() {
    let provider = MirrorFs::open(r"D:\temp").expect("D:/temp must be a fixed NTFS directory");
    assert_ne!(provider.root_file_id(), FileId::ZERO);
}

#[test]
fn opens_an_owned_root_and_installs_its_native_identity() {
    let root = TempRoot::new("open-root");

    let provider = MirrorFs::open(root.path()).expect("open owned fixed NTFS root");

    assert_ne!(provider.root_file_id(), FileId::ZERO);
}

#[test]
fn rejects_missing_and_nondirectory_roots_exactly() {
    let root = TempRoot::new("invalid-roots");
    let missing = root.child("missing");
    let file = root.child("plain-file");
    std::fs::write(&file, b"not a directory").expect("create test file");

    match MirrorFs::open(&missing).unwrap_err() {
        MirrorFsError::Io(error) => assert_eq!(error.kind(), ErrorKind::NotFound),
        other => panic!("missing root returned {other:?}"),
    }
    assert!(matches!(
        MirrorFs::open(&file).unwrap_err(),
        MirrorFsError::NotDirectory
    ));
}

#[test]
fn rejects_a_root_reparse_point_before_canonicalization() {
    let mut root = TempRoot::new("reparse-root");
    let target = root.child("target");
    let reparse = root.child("junction");
    std::fs::create_dir(&target).expect("create junction target");
    std::os::windows::fs::symlink_dir(&target, &reparse)
        .expect("creating a directory reparse point is required for this test");
    root.track_reparse_point(reparse.clone());

    assert!(matches!(
        MirrorFs::open(reparse).unwrap_err(),
        MirrorFsError::ReparsePoint
    ));
}

#[test]
fn open_existing_prepare_and_commit_return_native_identity_and_one_sequence() {
    let root = TempRoot::new("open-existing");
    let path = root.child("existing.txt");
    std::fs::write(&path, b"preserved").expect("seed existing file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 100,
        parent: provider.root_file_id(),
        name: "existing.txt",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });

    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1000, hi: 0 })
        .expect("prepare existing open");
    assert_ne!(prepared.file_id, FileId::ZERO);
    assert_ne!(prepared.link_id, fsring_abi::ids::LinkId::ZERO);
    assert_eq!(prepared.sizes.file_size, 9);
    assert_eq!(prepared.sizes.valid_data_length, 9);
    assert_eq!(prepared.object_flags, 0);

    let commit = commit_request(
        &request,
        1000,
        5000,
        prepared.namespace_generation,
        prepared.security_generation,
    );
    let effect = provider.commit_open(&commit).expect("commit existing open");
    assert_eq!(effect.create_result, create_result::OPENED);
    assert_eq!(effect.file_id, prepared.file_id);
    assert_eq!(effect.link_id, prepared.link_id);
    assert_eq!(effect.volume_commit_sequence, 1);
    assert_eq!(std::fs::read(&path).unwrap(), b"preserved");

    provider.cleanup_open(5000);
    provider.close_open(5000);
}

#[test]
fn create_open_if_overwrite_and_collision_have_exact_disk_results() {
    let root = TempRoot::new("create-dispositions");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();

    let create = prepare_request(PrepareCase {
        op: 110,
        parent,
        name: "created.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let create_prepared = provider
        .prepare_open(&create, TransactionId { lo: 1010, hi: 0 })
        .expect("prepare create");
    assert_eq!(create_prepared.link_id, fsring_abi::ids::LinkId::ZERO);
    assert!(
        !root.child("created.txt").exists(),
        "PREPARE is backing-nonmutating"
    );
    let create_effect = provider
        .commit_open(&commit_request(
            &create,
            1010,
            5010,
            create_prepared.namespace_generation,
            create_prepared.security_generation,
        ))
        .expect("commit create");
    assert_eq!(create_effect.create_result, create_result::CREATED);
    assert_ne!(create_effect.link_id, fsring_abi::ids::LinkId::ZERO);
    assert_ne!(
        std::fs::metadata(root.child("created.txt"))
            .unwrap()
            .file_attributes()
            & file_attributes::HIDDEN,
        0
    );

    let collision = prepare_request(PrepareCase {
        op: 111,
        parent,
        name: "created.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    expect_status(
        provider.prepare_open(&collision, TransactionId { lo: 1011, hi: 0 }),
        completion_status::OBJECT_NAME_COLLISION,
    );

    let open_if = prepare_request(PrepareCase {
        op: 112,
        parent,
        name: "created.txt",
        disposition: FILE_OPEN_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let open_if_prepared = provider
        .prepare_open(&open_if, TransactionId { lo: 1012, hi: 0 })
        .expect("prepare OPEN_IF existing");
    let open_if_effect = provider
        .commit_open(&commit_request(
            &open_if,
            1012,
            5012,
            open_if_prepared.namespace_generation,
            open_if_prepared.security_generation,
        ))
        .expect("commit OPEN_IF existing");
    assert_eq!(open_if_effect.create_result, create_result::OPENED);

    let open_if_new = prepare_request(PrepareCase {
        op: 114,
        parent,
        name: "open-if-new.txt",
        disposition: FILE_OPEN_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let open_if_new_prepared = provider
        .prepare_open(&open_if_new, TransactionId { lo: 1014, hi: 0 })
        .expect("prepare OPEN_IF absent");
    let open_if_new_effect = provider
        .commit_open(&commit_request(
            &open_if_new,
            1014,
            5014,
            open_if_new_prepared.namespace_generation,
            open_if_new_prepared.security_generation,
        ))
        .expect("commit OPEN_IF absent");
    assert_eq!(open_if_new_effect.create_result, create_result::CREATED);

    std::fs::write(root.child("overwrite.txt"), b"remove me").unwrap();
    let overwrite = prepare_request(PrepareCase {
        op: 113,
        parent,
        name: "overwrite.txt",
        disposition: FILE_OVERWRITE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let overwrite_prepared = provider
        .prepare_open(&overwrite, TransactionId { lo: 1013, hi: 0 })
        .expect("prepare overwrite");
    let overwrite_effect = provider
        .commit_open(&commit_request(
            &overwrite,
            1013,
            5013,
            overwrite_prepared.namespace_generation,
            overwrite_prepared.security_generation,
        ))
        .expect("commit overwrite");
    assert_eq!(overwrite_effect.create_result, create_result::OVERWRITTEN);
    assert!(std::fs::read(root.child("overwrite.txt"))
        .unwrap()
        .is_empty());

    std::fs::write(root.child("overwrite-if.txt"), b"overwrite-if").unwrap();
    let overwrite_if = prepare_request(PrepareCase {
        op: 115,
        parent,
        name: "overwrite-if.txt",
        disposition: FILE_OVERWRITE_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let overwrite_if_prepared = provider
        .prepare_open(&overwrite_if, TransactionId { lo: 1015, hi: 0 })
        .expect("prepare OVERWRITE_IF");
    let overwrite_if_effect = provider
        .commit_open(&commit_request(
            &overwrite_if,
            1015,
            5015,
            overwrite_if_prepared.namespace_generation,
            overwrite_if_prepared.security_generation,
        ))
        .expect("commit OVERWRITE_IF");
    assert_eq!(
        overwrite_if_effect.create_result,
        create_result::OVERWRITTEN
    );
    assert!(std::fs::read(root.child("overwrite-if.txt"))
        .unwrap()
        .is_empty());

    std::fs::write(root.child("supersede.txt"), b"supersede").unwrap();
    let supersede = prepare_request(PrepareCase {
        op: 116,
        parent,
        name: "supersede.txt",
        disposition: FILE_SUPERSEDE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let supersede_prepared = provider
        .prepare_open(&supersede, TransactionId { lo: 1016, hi: 0 })
        .expect("prepare SUPERSEDE");
    let supersede_effect = provider
        .commit_open(&commit_request(
            &supersede,
            1016,
            5016,
            supersede_prepared.namespace_generation,
            supersede_prepared.security_generation,
        ))
        .expect("commit SUPERSEDE");
    assert_eq!(supersede_effect.create_result, create_result::SUPERSEDED);
    assert!(std::fs::read(root.child("supersede.txt"))
        .unwrap()
        .is_empty());

    for (op, transaction, disposition) in [(117, 1017, FILE_OPEN), (118, 1018, FILE_OVERWRITE)] {
        let missing = prepare_request(PrepareCase {
            op,
            parent,
            name: "missing-disposition.txt",
            disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        });
        expect_status(
            provider.prepare_open(
                &missing,
                TransactionId {
                    lo: transaction,
                    hi: 0,
                },
            ),
            completion_status::OBJECT_NAME_NOT_FOUND,
        );
    }

    for kernel_open_id in [5010, 5012, 5013, 5014, 5015, 5016] {
        provider.cleanup_open(kernel_open_id);
        provider.close_open(kernel_open_id);
    }
}

#[test]
fn directory_creation_type_mismatches_and_ea_reject_before_backing_effect() {
    let root = TempRoot::new("open-types");
    std::fs::write(root.child("file.bin"), b"file").unwrap();
    std::fs::create_dir(root.child("directory")).unwrap();
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();

    let directory_as_file = prepare_request(PrepareCase {
        op: 120,
        parent,
        name: "directory",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    expect_status(
        provider.prepare_open(&directory_as_file, TransactionId { lo: 1020, hi: 0 }),
        completion_status::FILE_IS_A_DIRECTORY,
    );

    let file_as_directory = prepare_request(PrepareCase {
        op: 121,
        parent,
        name: "file.bin",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    expect_status(
        provider.prepare_open(&file_as_directory, TransactionId { lo: 1021, hi: 0 }),
        completion_status::NOT_A_DIRECTORY,
    );

    let create_directory = prepare_request(PrepareCase {
        op: 122,
        parent,
        name: "new-directory",
        disposition: FILE_CREATE,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let directory_prepared = provider
        .prepare_open(&create_directory, TransactionId { lo: 1022, hi: 0 })
        .expect("prepare directory create");
    assert!(!root.child("new-directory").exists());
    let directory_effect = provider
        .commit_open(&commit_request(
            &create_directory,
            1022,
            5022,
            directory_prepared.namespace_generation,
            directory_prepared.security_generation,
        ))
        .expect("commit directory create");
    assert_eq!(directory_effect.create_result, create_result::CREATED);
    assert!(root.child("new-directory").is_dir());

    let mut with_ea = prepare_request(PrepareCase {
        op: 123,
        parent,
        name: "ea-must-not-exist",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    with_ea.extended_attributes = Some(vec![1_u8].into_boxed_slice());
    expect_status(
        provider.prepare_open(&with_ea, TransactionId { lo: 1023, hi: 0 }),
        completion_status::NOT_SUPPORTED,
    );
    assert!(!root.child("ea-must-not-exist").exists());

    let mut reparse_attribute = prepare_request(PrepareCase {
        op: 124,
        parent,
        name: "reparse-attribute",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    reparse_attribute.file_attributes = file_attributes::REPARSE_POINT;
    expect_status(
        provider.prepare_open(&reparse_attribute, TransactionId { lo: 1024, hi: 0 }),
        completion_status::NOT_SUPPORTED,
    );

    let reparse_option = prepare_request(PrepareCase {
        op: 125,
        parent,
        name: "reparse-option",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    expect_status(
        provider.prepare_open(&reparse_option, TransactionId { lo: 1025, hi: 0 }),
        completion_status::NOT_SUPPORTED,
    );

    let invalid_disposition = prepare_request(PrepareCase {
        op: 126,
        parent,
        name: "invalid-disposition",
        disposition: 6,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    expect_status(
        provider.prepare_open(&invalid_disposition, TransactionId { lo: 1026, hi: 0 }),
        completion_status::DATA_ERROR,
    );

    provider.cleanup_open(5022);
    provider.close_open(5022);
}

#[test]
fn prepare_validates_requested_security_descriptor_before_state_installation() {
    let root = TempRoot::new("prepare-security-descriptor");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();
    let mut request = prepare_request(PrepareCase {
        op: 127,
        parent,
        name: "descriptor.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    request.requested_security_descriptor = Some(vec![0_u8; 20].into_boxed_slice());
    let transaction = TransactionId { lo: 1027, hi: 0 };

    expect_status(
        provider.prepare_open(&request, transaction),
        completion_status::DATA_ERROR,
    );
    assert!(!root.child("descriptor.txt").exists());

    request.requested_security_descriptor = None;
    let fallback = provider
        .prepare_open(&request, transaction)
        .expect("failed PREPARE did not consume transaction or prospective identity");
    assert_eq!(fallback.file_id.lo, parent.lo + 1);
    provider.abort_open(transaction);

    let mut explicit = prepare_request(PrepareCase {
        op: 128,
        parent,
        name: "explicit-descriptor.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    explicit.requested_security_descriptor = Some(fallback.security_descriptor.clone());
    provider
        .prepare_open(&explicit, TransactionId { lo: 1028, hi: 0 })
        .expect("valid self-relative requested descriptor");
    provider.abort_open(TransactionId { lo: 1028, hi: 0 });
}

#[test]
fn prepare_replay_abort_generation_and_pre_effect_failure_preserve_exact_transaction() {
    let root = TempRoot::new("prepare-replay");
    let path = root.child("blocked.txt");
    std::fs::write(&path, b"blocked").unwrap();
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();
    let request = prepare_request(PrepareCase {
        op: 130,
        parent,
        name: "blocked.txt",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let first = provider
        .prepare_open(&request, TransactionId { lo: 1030, hi: 0 })
        .expect("first prepare");
    let replay = provider
        .prepare_open(&request, TransactionId { lo: 9999, hi: 0 })
        .expect("identical replay");
    assert_eq!(replay.file_id, first.file_id);
    assert_eq!(replay.link_id, first.link_id);
    assert_eq!(replay.security_descriptor, first.security_descriptor);
    provider.abort_open(TransactionId { lo: 9999, hi: 0 });

    let mut mismatch = request.clone();
    mismatch.file_attributes = file_attributes::HIDDEN;
    expect_status(
        provider.prepare_open(&mismatch, TransactionId { lo: 1031, hi: 0 }),
        completion_status::DATA_ERROR,
    );

    let stale = commit_request(
        &request,
        1030,
        5030,
        first.namespace_generation + 1,
        first.security_generation,
    );
    expect_status(provider.commit_open(&stale), completion_status::RETRY);

    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .expect("open exclusive blocker");
    let commit = commit_request(
        &request,
        1030,
        5030,
        first.namespace_generation,
        first.security_generation,
    );
    expect_status(
        provider.commit_open(&commit),
        completion_status::SHARING_VIOLATION,
    );
    drop(blocker);
    let effect = provider
        .commit_open(&commit)
        .expect("registered pre-effect failure retained pending transaction");
    assert_eq!(effect.create_result, create_result::OPENED);

    let abort = prepare_request(PrepareCase {
        op: 131,
        parent,
        name: "aborted.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let aborted = provider
        .prepare_open(&abort, TransactionId { lo: 1032, hi: 0 })
        .expect("prepare abort case");
    provider.abort_open(TransactionId { lo: 1032, hi: 0 });
    provider.abort_open(TransactionId { lo: 1032, hi: 0 });
    expect_status(
        provider.commit_open(&commit_request(
            &abort,
            1032,
            5032,
            aborted.namespace_generation,
            aborted.security_generation,
        )),
        completion_status::DATA_ERROR,
    );
    assert!(!root.child("aborted.txt").exists());

    provider.cleanup_open(5030);
    provider.close_open(5030);
}

#[test]
fn cleanup_and_close_retain_then_drop_exactly_one_native_handle() {
    let root = TempRoot::new("open-lifecycle");
    let path = root.child("retained.txt");
    std::fs::write(&path, b"retained").unwrap();
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 140,
        parent: provider.root_file_id(),
        name: "retained.txt",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: FILE_SHARE_READ | FILE_SHARE_WRITE,
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1040, hi: 0 })
        .expect("prepare retained open");
    provider
        .commit_open(&commit_request(
            &request,
            1040,
            5040,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit retained open");

    assert_eq!(
        std::fs::remove_file(&path).unwrap_err().raw_os_error(),
        Some(32)
    );
    provider.cleanup_open(5040);
    provider.cleanup_open(5040);
    assert_eq!(
        std::fs::remove_file(&path).unwrap_err().raw_os_error(),
        Some(32)
    );
    provider.close_open(5040);
    provider.close_open(5040);
    std::fs::remove_file(&path).expect("CLOSE dropped the retained native handle");
}

#[test]
fn prepared_existing_open_if_reports_internal_after_actual_recreation() {
    let root = TempRoot::new("open-if-existing-race");
    let path = root.child("raced.txt");
    std::fs::write(&path, b"prepared identity").unwrap();
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 150,
        parent: provider.root_file_id(),
        name: "raced.txt",
        disposition: FILE_OPEN_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: 0,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1050, hi: 0 })
        .expect("prepare existing OPEN_IF");
    std::fs::remove_file(&path).expect("delete prepared target before commit");

    let commit = commit_request(
        &request,
        1050,
        5050,
        prepared.namespace_generation,
        prepared.security_generation,
    );
    expect_status(
        provider.commit_open(&commit),
        completion_status::IO_DEVICE_ERROR,
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"",
        "OPEN_ALWAYS created a new object before the identity mismatch was classified"
    );
    expect_status(provider.commit_open(&commit), completion_status::RETRY);
    provider.abort_open(TransactionId { lo: 1050, hi: 0 });
}

#[test]
fn prepared_existing_create_always_paths_stop_after_actual_recreation() {
    for (index, disposition) in [FILE_SUPERSEDE, FILE_OVERWRITE_IF].into_iter().enumerate() {
        let root = TempRoot::new("create-always-existing-race");
        let path = root.child("raced.txt");
        std::fs::write(&path, b"prepared identity").unwrap();
        let mut provider = MirrorFs::open(root.path()).expect("open provider");
        let request = prepare_request(PrepareCase {
            op: 154 + index as u64,
            parent: provider.root_file_id(),
            name: "raced.txt",
            disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        });
        let transaction = 1054 + index as u64;
        let prepared = provider
            .prepare_open(
                &request,
                TransactionId {
                    lo: transaction,
                    hi: 0,
                },
            )
            .expect("prepare existing CREATE_ALWAYS disposition");
        std::fs::remove_file(&path).expect("delete prepared target before commit");

        expect_status(
            provider.commit_open(&commit_request(
                &request,
                transaction,
                5054 + index as u64,
                prepared.namespace_generation,
                prepared.security_generation,
            )),
            completion_status::IO_DEVICE_ERROR,
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"",
            "CREATE_ALWAYS visibly recreated the target before internal-stop"
        );
        provider.abort_open(TransactionId {
            lo: transaction,
            hi: 0,
        });
    }
}

#[test]
fn prospective_open_if_retries_after_actual_open_without_touching_bytes() {
    let root = TempRoot::new("open-if-prospective-race");
    let path = root.child("raced.txt");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 151,
        parent: provider.root_file_id(),
        name: "raced.txt",
        disposition: FILE_OPEN_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1051, hi: 0 })
        .expect("prepare absent OPEN_IF");
    std::fs::write(&path, b"external content").expect("race in an external target");

    let commit = commit_request(
        &request,
        1051,
        5051,
        prepared.namespace_generation,
        prepared.security_generation,
    );
    expect_status(provider.commit_open(&commit), completion_status::RETRY);
    assert_eq!(std::fs::read(&path).unwrap(), b"external content");

    std::fs::remove_file(&path).expect("remove external target for retained retry");
    let effect = provider
        .commit_open(&commit)
        .expect("no-effect RETRY retained the pending transaction");
    assert_eq!(effect.create_result, create_result::CREATED);
    provider.cleanup_open(5051);
    provider.close_open(5051);
}

#[test]
fn prospective_replacing_dispositions_stop_after_actual_external_truncation() {
    for (index, disposition) in [FILE_SUPERSEDE, FILE_OVERWRITE_IF].into_iter().enumerate() {
        let root = TempRoot::new("replace-prospective-race");
        let path = root.child("raced.txt");
        let mut provider = MirrorFs::open(root.path()).expect("open provider");
        let request = prepare_request(PrepareCase {
            op: 152 + index as u64,
            parent: provider.root_file_id(),
            name: "raced.txt",
            disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        });
        let transaction = 1052 + index as u64;
        let prepared = provider
            .prepare_open(
                &request,
                TransactionId {
                    lo: transaction,
                    hi: 0,
                },
            )
            .expect("prepare absent replacing disposition");
        std::fs::write(&path, b"external content").expect("race in an external target");

        let commit = commit_request(
            &request,
            transaction,
            5052 + index as u64,
            prepared.namespace_generation,
            prepared.security_generation,
        );
        expect_status(
            provider.commit_open(&commit),
            completion_status::IO_DEVICE_ERROR,
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"",
            "CREATE_ALWAYS truncated the raced-in object before internal-stop"
        );

        std::fs::remove_file(&path).expect("remove raced target for retained retry");
        let effect = provider
            .commit_open(&commit)
            .expect("post-effect internal-stop retained the pending transaction");
        assert_eq!(effect.create_result, create_result::CREATED);
        provider.cleanup_open(5052 + index as u64);
        provider.close_open(5052 + index as u64);
    }
}

#[test]
fn nontruncating_existing_open_preserves_tracked_vdl_and_size_epoch() {
    for (index, disposition) in [FILE_OPEN, FILE_OPEN_IF].into_iter().enumerate() {
        let root = TempRoot::new("existing-open-size-preserve");
        let path = root.child("tracked.txt");
        std::fs::write(&path, b"tracked!").unwrap();
        let mut provider = MirrorFs::open(root.path()).expect("open provider");
        let request = prepare_request(PrepareCase {
            op: 160 + index as u64,
            parent: provider.root_file_id(),
            name: "tracked.txt",
            disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        });
        let transaction = 1060 + index as u64;
        let prepared = provider
            .prepare_open(
                &request,
                TransactionId {
                    lo: transaction,
                    hi: 0,
                },
            )
            .expect("prepare existing nontruncating open");
        assert_eq!(prepared.sizes.file_size, 8);
        assert_eq!(prepared.sizes.valid_data_length, 8);
        std::fs::write(&path, b"externally enlarged").unwrap();

        let kernel_open_id = 5060 + index as u64;
        let effect = provider
            .commit_open(&commit_request(
                &request,
                transaction,
                kernel_open_id,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .expect("commit nontruncating open");
        assert_eq!(effect.sizes.file_size, 19);
        assert_eq!(effect.sizes.valid_data_length, 8);
        assert_eq!(effect.sizes.size_epoch, prepared.sizes.size_epoch);
        assert_eq!(effect.volume_commit_sequence, 1);
        provider.cleanup_open(kernel_open_id);
        provider.close_open(kernel_open_id);
    }
}

#[test]
fn nontruncating_open_retries_before_finalization_when_native_eof_is_below_vdl() {
    let root = TempRoot::new("existing-open-vdl-race");
    let path = root.child("tracked.txt");
    std::fs::write(&path, b"tracked!").unwrap();
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 166,
        parent: provider.root_file_id(),
        name: "tracked.txt",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: 0,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1066, hi: 0 })
        .expect("prepare existing open");
    std::fs::write(&path, b"").expect("externally shrink below tracked VDL");
    let commit = commit_request(
        &request,
        1066,
        5066,
        prepared.namespace_generation,
        prepared.security_generation,
    );

    expect_status(provider.commit_open(&commit), completion_status::RETRY);
    std::fs::write(&path, b"restored").expect("restore tracked size for retained retry");
    let effect = provider
        .commit_open(&commit)
        .expect("no-effect size RETRY retained reservation-free pending state");
    assert_eq!(effect.volume_commit_sequence, 1);
    assert_eq!(effect.sizes.valid_data_length, 8);
    assert_eq!(effect.sizes.size_epoch, prepared.sizes.size_epoch);
    provider.cleanup_open(5066);
    provider.close_open(5066);
}

#[test]
fn replacing_existing_open_zeros_vdl_and_advances_one_size_epoch() {
    for (index, disposition) in [FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF]
        .into_iter()
        .enumerate()
    {
        let root = TempRoot::new("existing-open-size-truncate");
        let path = root.child("tracked.txt");
        std::fs::write(&path, b"nonzero tracked bytes").unwrap();
        let mut provider = MirrorFs::open(root.path()).expect("open provider");
        let request = prepare_request(PrepareCase {
            op: 162 + index as u64,
            parent: provider.root_file_id(),
            name: "tracked.txt",
            disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        });
        let transaction = 1062 + index as u64;
        let prepared = provider
            .prepare_open(
                &request,
                TransactionId {
                    lo: transaction,
                    hi: 0,
                },
            )
            .expect("prepare existing replacing open");
        assert_ne!(prepared.sizes.valid_data_length, 0);

        let kernel_open_id = 5062 + index as u64;
        let effect = provider
            .commit_open(&commit_request(
                &request,
                transaction,
                kernel_open_id,
                prepared.namespace_generation,
                prepared.security_generation,
            ))
            .expect("commit replacing open");
        assert_eq!(effect.sizes.file_size, 0);
        assert_eq!(effect.sizes.valid_data_length, 0);
        assert_eq!(
            effect.sizes.size_epoch,
            prepared.sizes.size_epoch + 1,
            "exactly one size generation is allocated"
        );
        assert_eq!(effect.volume_commit_sequence, 1);
        provider.cleanup_open(kernel_open_id);
        provider.close_open(kernel_open_id);
    }
}

#[test]
fn prepare_rejects_every_unsupported_open_attribute_before_allocating_identity() {
    const FILE_ATTRIBUTE_DEVICE: u32 = 0x0000_0040;
    const UNKNOWN_ATTRIBUTE: u32 = 0x8000_0000;

    let root = TempRoot::new("unsupported-open-attributes");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();
    for (index, attributes) in [
        file_attributes::SPARSE_FILE,
        file_attributes::COMPRESSED,
        file_attributes::ENCRYPTED,
        file_attributes::REPARSE_POINT,
        FILE_ATTRIBUTE_DEVICE,
        UNKNOWN_ATTRIBUTE,
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("rejected-{index}.txt");
        let request = prepare_request(PrepareCase {
            op: 170 + index as u64,
            parent,
            name: &name,
            disposition: FILE_CREATE,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes,
            share_access: all_shares(),
        });
        expect_status(
            provider.prepare_open(
                &request,
                TransactionId {
                    lo: 1070 + index as u64,
                    hi: 0,
                },
            ),
            completion_status::NOT_SUPPORTED,
        );
        assert!(!root.child(&name).exists());
    }

    let mismatched_directory = prepare_request(PrepareCase {
        op: 176,
        parent,
        name: "mismatched-directory.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    expect_status(
        provider.prepare_open(&mismatched_directory, TransactionId { lo: 1076, hi: 0 }),
        completion_status::DATA_ERROR,
    );

    let valid = prepare_request(PrepareCase {
        op: 177,
        parent,
        name: "valid.txt",
        disposition: FILE_CREATE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::HIDDEN | file_attributes::ARCHIVE,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&valid, TransactionId { lo: 1077, hi: 0 })
        .expect("rejections did not allocate a prospective identity");
    assert_eq!(prepared.file_id.lo, parent.lo + 1);
    provider.abort_open(TransactionId { lo: 1077, hi: 0 });
}

#[test]
fn replacing_existing_file_post_applies_attributes_and_refreshes_time() {
    let root = TempRoot::new("existing-open-basic-info");
    let path = root.child("refresh.txt");
    std::fs::write(&path, b"truncate and refresh").unwrap();
    let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(old_time)
            .set_modified(old_time),
    )
    .unwrap();
    drop(file);

    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 178,
        parent: provider.root_file_id(),
        name: "refresh.txt",
        disposition: FILE_OVERWRITE,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1078, hi: 0 })
        .expect("prepare overwrite with supported basic attributes");
    let effect = provider
        .commit_open(&commit_request(
            &request,
            1078,
            5078,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit overwrite and basic-info update");
    assert_eq!(effect.sizes.file_size, 0);
    assert_ne!(
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::HIDDEN,
        0,
        "CreateFileW flags alone do not update an existing object's attributes"
    );
    provider.cleanup_open(5078);
    provider.close_open(5078);
    assert!(std::fs::metadata(&path).unwrap().modified().unwrap() > old_time);
}

#[test]
fn nonreplacing_existing_file_opens_preserve_hidden_against_requested_normal() {
    for (index, disposition) in [FILE_OPEN, FILE_OPEN_IF].into_iter().enumerate() {
        let root = TempRoot::new("existing-open-preserves-attributes");
        let path = root.child("hidden.txt");
        let mut provider = MirrorFs::open(root.path()).expect("open provider");
        let parent = provider.root_file_id();
        let create = prepare_request(PrepareCase {
            op: 180 + index as u64 * 2,
            parent,
            name: "hidden.txt",
            disposition: FILE_CREATE,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::HIDDEN,
            share_access: all_shares(),
        });
        let create_prepared = provider
            .prepare_open(
                &create,
                TransactionId {
                    lo: 1080 + index as u64 * 2,
                    hi: 0,
                },
            )
            .expect("prepare hidden seed file");
        let create_kernel_id = 5080 + index as u64 * 2;
        provider
            .commit_open(&commit_request(
                &create,
                1080 + index as u64 * 2,
                create_kernel_id,
                create_prepared.namespace_generation,
                create_prepared.security_generation,
            ))
            .expect("create hidden seed file");
        provider.cleanup_open(create_kernel_id);
        provider.close_open(create_kernel_id);
        assert_ne!(
            std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::HIDDEN,
            0
        );

        let open = prepare_request(PrepareCase {
            op: 181 + index as u64 * 2,
            parent,
            name: "hidden.txt",
            disposition,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        });
        let open_transaction = 1081 + index as u64 * 2;
        let open_prepared = provider
            .prepare_open(
                &open,
                TransactionId {
                    lo: open_transaction,
                    hi: 0,
                },
            )
            .expect("prepare nonreplacing existing open");
        let open_kernel_id = 5081 + index as u64 * 2;
        provider
            .commit_open(&commit_request(
                &open,
                open_transaction,
                open_kernel_id,
                open_prepared.namespace_generation,
                open_prepared.security_generation,
            ))
            .expect("commit nonreplacing existing open");
        assert_ne!(
            std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::HIDDEN,
            0,
            "nonreplacing OPEN must not apply requested creation attributes"
        );
        provider.cleanup_open(open_kernel_id);
        provider.close_open(open_kernel_id);
    }
}

#[test]
fn nonreplacing_existing_directory_open_preserves_hidden_attribute() {
    let root = TempRoot::new("existing-directory-preserves-attributes");
    let path = root.child("hidden-directory");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();
    let create = prepare_request(PrepareCase {
        op: 184,
        parent,
        name: "hidden-directory",
        disposition: FILE_CREATE,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY | file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let create_prepared = provider
        .prepare_open(&create, TransactionId { lo: 1084, hi: 0 })
        .expect("prepare hidden directory");
    provider
        .commit_open(&commit_request(
            &create,
            1084,
            5084,
            create_prepared.namespace_generation,
            create_prepared.security_generation,
        ))
        .expect("create hidden directory");
    provider.cleanup_open(5084);
    provider.close_open(5084);

    let open = prepare_request(PrepareCase {
        op: 185,
        parent,
        name: "hidden-directory",
        disposition: FILE_OPEN,
        create_options: 0,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let open_prepared = provider
        .prepare_open(&open, TransactionId { lo: 1085, hi: 0 })
        .expect("prepare directory open");
    provider
        .commit_open(&commit_request(
            &open,
            1085,
            5085,
            open_prepared.namespace_generation,
            open_prepared.security_generation,
        ))
        .expect("commit directory open");
    assert_ne!(
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::HIDDEN,
        0
    );
    provider.cleanup_open(5085);
    provider.close_open(5085);

    let open_if = prepare_request(PrepareCase {
        op: 193,
        parent,
        name: "hidden-directory",
        disposition: FILE_OPEN_IF,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let open_if_prepared = provider
        .prepare_open(&open_if, TransactionId { lo: 1093, hi: 0 })
        .expect("prepare stable directory OPEN_IF");
    provider
        .commit_open(&commit_request(
            &open_if,
            1093,
            5093,
            open_if_prepared.namespace_generation,
            open_if_prepared.security_generation,
        ))
        .expect("commit stable directory OPEN_IF");
    assert_ne!(
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::HIDDEN,
        0,
        "stable directory OPEN_IF must retain existing basic attributes"
    );
    provider.cleanup_open(5093);
    provider.close_open(5093);
}

#[test]
fn replacing_attribute_changes_advance_namespace_once_while_noop_preserves_it() {
    let root = TempRoot::new("replacing-open-namespace-generation");
    let path = root.child("metadata.txt");
    std::fs::write(&path, b"first replacement").unwrap();
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let parent = provider.root_file_id();

    let first = prepare_request(PrepareCase {
        op: 186,
        parent,
        name: "metadata.txt",
        disposition: FILE_OVERWRITE_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let first_prepared = provider
        .prepare_open(&first, TransactionId { lo: 1086, hi: 0 })
        .expect("prepare first attribute-changing replacement");
    let first_effect = provider
        .commit_open(&commit_request(
            &first,
            1086,
            5086,
            first_prepared.namespace_generation,
            first_prepared.security_generation,
        ))
        .expect("commit first attribute-changing replacement");
    assert_ne!(
        first_effect.namespace_generation,
        first_prepared.namespace_generation
    );
    assert_eq!(first_effect.volume_commit_sequence, 1);
    provider.cleanup_open(5086);
    provider.close_open(5086);

    let current_basic_attributes =
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::SETTABLE_BASIC_MASK;
    assert_ne!(current_basic_attributes, 0);
    let noop = prepare_request(PrepareCase {
        op: 187,
        parent,
        name: "metadata.txt",
        disposition: FILE_OVERWRITE_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: current_basic_attributes,
        share_access: all_shares(),
    });
    let noop_prepared = provider
        .prepare_open(&noop, TransactionId { lo: 1087, hi: 0 })
        .expect("prepare no-op attribute replacement");
    let noop_effect = provider
        .commit_open(&commit_request(
            &noop,
            1087,
            5087,
            noop_prepared.namespace_generation,
            noop_prepared.security_generation,
        ))
        .expect("commit no-op attribute replacement");
    assert_eq!(
        noop_effect.namespace_generation,
        first_effect.namespace_generation
    );
    assert_eq!(noop_effect.volume_commit_sequence, 2);
    provider.cleanup_open(5087);
    provider.close_open(5087);
    assert_eq!(
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::SETTABLE_BASIC_MASK,
        current_basic_attributes,
        "a no-op replacement must restore the requested attributes after truncation"
    );

    let changed_attributes = if current_basic_attributes == file_attributes::SYSTEM {
        file_attributes::HIDDEN
    } else {
        file_attributes::SYSTEM
    };
    let changed = prepare_request(PrepareCase {
        op: 188,
        parent,
        name: "metadata.txt",
        disposition: FILE_OVERWRITE_IF,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: changed_attributes,
        share_access: all_shares(),
    });
    let changed_prepared = provider
        .prepare_open(&changed, TransactionId { lo: 1088, hi: 0 })
        .expect("prepare second attribute-changing replacement");
    let changed_effect = provider
        .commit_open(&commit_request(
            &changed,
            1088,
            5088,
            changed_prepared.namespace_generation,
            changed_prepared.security_generation,
        ))
        .expect("commit second attribute-changing replacement");
    assert_eq!(
        changed_effect.namespace_generation,
        first_effect.namespace_generation + 1,
        "the no-op replacement did not consume the intervening namespace generation"
    );
    assert_eq!(changed_effect.volume_commit_sequence, 3);
    provider.cleanup_open(5088);
    provider.close_open(5088);
}

#[test]
fn prepared_existing_directory_open_if_internal_stops_after_actual_recreation() {
    let root = TempRoot::new("directory-open-if-existing-race");
    let path = root.child("raced-directory");
    std::fs::create_dir(&path).expect("create prepared directory");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 189,
        parent: provider.root_file_id(),
        name: "raced-directory",
        disposition: FILE_OPEN_IF,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let transaction = TransactionId { lo: 1089, hi: 0 };
    let prepared = provider
        .prepare_open(&request, transaction)
        .expect("prepare existing directory OPEN_IF");
    std::fs::remove_dir(&path).expect("delete prepared directory before commit");
    let commit = commit_request(
        &request,
        transaction.lo,
        5089,
        prepared.namespace_generation,
        prepared.security_generation,
    );

    expect_status(
        provider.commit_open(&commit),
        completion_status::IO_DEVICE_ERROR,
    );
    assert!(
        path.is_dir(),
        "OPEN_IF visibly recreated the directory before the identity mismatch stopped commit"
    );
    expect_status(provider.commit_open(&commit), completion_status::RETRY);
    provider.abort_open(transaction);
    expect_status(provider.commit_open(&commit), completion_status::DATA_ERROR);
}

#[test]
fn prospective_directory_open_if_retries_collision_without_mutation_then_reuses_pending() {
    let root = TempRoot::new("directory-open-if-prospective-race");
    let path = root.child("raced-directory");
    let marker = path.join("external.txt");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 190,
        parent: provider.root_file_id(),
        name: "raced-directory",
        disposition: FILE_OPEN_IF,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY | file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let transaction = TransactionId { lo: 1090, hi: 0 };
    let prepared = provider
        .prepare_open(&request, transaction)
        .expect("prepare absent directory OPEN_IF");
    std::fs::create_dir(&path).expect("race in external directory");
    std::fs::write(&marker, b"external content").expect("write external marker");
    let raced_attributes = std::fs::metadata(&path).unwrap().file_attributes();
    let commit = commit_request(
        &request,
        transaction.lo,
        5090,
        prepared.namespace_generation,
        prepared.security_generation,
    );

    expect_status(provider.commit_open(&commit), completion_status::RETRY);
    assert_eq!(std::fs::read(&marker).unwrap(), b"external content");
    assert_eq!(
        std::fs::metadata(&path).unwrap().file_attributes(),
        raced_attributes,
        "a no-effect OPEN_IF collision must not apply requested directory attributes"
    );

    std::fs::remove_file(&marker).expect("remove external marker");
    std::fs::remove_dir(&path).expect("remove external directory for retained retry");
    let effect = provider
        .commit_open(&commit)
        .expect("no-effect RETRY retained the pending directory transaction");
    assert_eq!(effect.create_result, create_result::CREATED);
    assert!(path.is_dir());
    assert_ne!(
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::HIDDEN,
        0,
        "successful directory creation applied requested basic attributes"
    );
    provider.cleanup_open(5090);
    provider.close_open(5090);
}

#[test]
fn directory_file_open_and_create_keep_race_error_semantics() {
    let root = TempRoot::new("directory-race-control-dispositions");
    let open_path = root.child("open-directory");
    std::fs::create_dir(&open_path).expect("create prepared OPEN directory");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");

    let open_request = prepare_request(PrepareCase {
        op: 191,
        parent: provider.root_file_id(),
        name: "open-directory",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let open_transaction = TransactionId { lo: 1091, hi: 0 };
    let open_prepared = provider
        .prepare_open(&open_request, open_transaction)
        .expect("prepare existing directory FILE_OPEN");
    std::fs::remove_dir(&open_path).expect("delete prepared FILE_OPEN directory");
    expect_status(
        provider.commit_open(&commit_request(
            &open_request,
            open_transaction.lo,
            5091,
            open_prepared.namespace_generation,
            open_prepared.security_generation,
        )),
        completion_status::OBJECT_NAME_NOT_FOUND,
    );
    assert!(
        !open_path.exists(),
        "FILE_OPEN must not recreate a directory"
    );
    provider.abort_open(open_transaction);

    let create_path = root.child("create-directory");
    let create_request = prepare_request(PrepareCase {
        op: 192,
        parent: provider.root_file_id(),
        name: "create-directory",
        disposition: FILE_CREATE,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY | file_attributes::HIDDEN,
        share_access: all_shares(),
    });
    let create_transaction = TransactionId { lo: 1092, hi: 0 };
    let create_prepared = provider
        .prepare_open(&create_request, create_transaction)
        .expect("prepare absent directory FILE_CREATE");
    std::fs::create_dir(&create_path).expect("race in FILE_CREATE collision");
    let raced_attributes = std::fs::metadata(&create_path).unwrap().file_attributes();
    expect_status(
        provider.commit_open(&commit_request(
            &create_request,
            create_transaction.lo,
            5092,
            create_prepared.namespace_generation,
            create_prepared.security_generation,
        )),
        completion_status::OBJECT_NAME_COLLISION,
    );
    assert_eq!(
        std::fs::metadata(&create_path).unwrap().file_attributes(),
        raced_attributes,
        "FILE_CREATE collision must not apply requested attributes"
    );
    provider.abort_open(create_transaction);
}

#[test]
fn committed_data_operations_are_positional_partial_and_stateful() {
    let root = TempRoot::new("data-operations");
    let path = root.child("data.bin");
    std::fs::write(&path, b"0123456789").expect("seed file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 200,
        parent: provider.root_file_id(),
        name: "data.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1200, hi: 0 })
        .expect("prepare data open");
    let committed = provider
        .commit_open(&commit_request(
            &request,
            1200,
            5200,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit data open");

    let in_place = provider
        .write(5200, 3, committed.sizes.size_epoch, b"ABCDE")
        .expect("in-place write");
    assert_eq!(in_place.information, 5);
    assert_eq!(in_place.effect.volume_commit_sequence, 2);
    assert_eq!(in_place.effect.sizes.file_size, 10);
    assert_eq!(in_place.effect.sizes.valid_data_length, 10);
    assert_eq!(
        in_place.effect.sizes.size_epoch, committed.sizes.size_epoch,
        "an in-place write must not invent a size transition"
    );
    provider.flush(5200).expect("flush committed handle");

    let mut exact = [0_u8; 5];
    assert_eq!(provider.read(5200, 3, &mut exact).expect("exact read"), 5);
    assert_eq!(&exact, b"ABCDE");

    let mut short = [0xcc_u8; 8];
    assert_eq!(provider.read(5200, 8, &mut short).expect("short read"), 2);
    assert_eq!(&short[..2], b"89");
    assert_eq!(&short[2..], &[0xcc; 6]);
    assert_eq!(
        provider
            .read(5200, 10, &mut short)
            .expect("zero-at-EOF read"),
        0
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"012ABCDE89");

    let before_stale = std::fs::read(&path).unwrap();
    expect_status(
        provider.write(
            5200,
            u64::MAX,
            in_place.effect.sizes.size_epoch,
            b"overflow",
        ),
        completion_status::DATA_ERROR,
    );
    expect_status(
        provider.write(5200, 0, in_place.effect.sizes.size_epoch, b""),
        completion_status::DATA_ERROR,
    );
    expect_status(
        provider.write(5200, 0, in_place.effect.sizes.size_epoch + 1, b"stale"),
        completion_status::RETRY,
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before_stale,
        "stale epoch must reject before native I/O"
    );

    let growth = provider
        .write(5200, 12, in_place.effect.sizes.size_epoch, b"xyz")
        .expect("growing write");
    assert_eq!(growth.information, 3);
    assert_eq!(growth.effect.volume_commit_sequence, 3);
    assert_eq!(growth.effect.sizes.file_size, 15);
    assert_eq!(growth.effect.sizes.valid_data_length, 15);
    assert_ne!(
        growth.effect.sizes.size_epoch,
        in_place.effect.sizes.size_epoch
    );
    provider.flush(5200).expect("flush growth");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"012ABCDE89\0\0xyz",
        "the retained handle uses positional writes without stream coupling"
    );
    let refreshed = provider.query_info(5200).expect("refresh info after write");
    assert_eq!(refreshed.sizes.file_size, growth.effect.sizes.file_size);
    assert_eq!(
        refreshed.sizes.valid_data_length,
        growth.effect.sizes.valid_data_length
    );
    assert_eq!(refreshed.sizes.size_epoch, growth.effect.sizes.size_epoch);
    build_file_info(&refreshed).expect("post-write file info builds");

    provider.cleanup_open(5200);
    provider.close_open(5200);
}

#[test]
fn canonical_info_and_volume_queries_self_validate_against_native_state() {
    let root = TempRoot::new("canonical-queries");
    let path = root.child("query.bin");
    std::fs::write(&path, b"query bytes").expect("seed query file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 201,
        parent: provider.root_file_id(),
        name: "query.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1201, hi: 0 })
        .expect("prepare query open");
    let committed = provider
        .commit_open(&commit_request(
            &request,
            1201,
            5201,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit query open");

    let fields = provider.query_info(5201).expect("query canonical info");
    assert_eq!(fields.sizes.file_size, 11);
    assert_eq!(fields.sizes.valid_data_length, 11);
    assert_eq!(fields.sizes.size_epoch, committed.sizes.size_epoch);
    assert_eq!(fields.namespace_generation, committed.namespace_generation);
    assert_eq!(fields.security_generation, committed.security_generation);
    assert_eq!(
        fields.attributes,
        std::fs::metadata(&path).unwrap().file_attributes() & file_attributes::ACCEPTED_MASK_V21
    );
    assert!(fields.link_count >= 1);
    let encoded_info = build_file_info(&fields).expect("canonical file info builds");
    assert_eq!(encoded_info.len(), 104);

    let volume = provider.query_volume().expect("query canonical volume");
    assert!(volume.total_allocation_units > 0);
    assert!(volume.available_allocation_units <= volume.total_allocation_units);
    assert!(volume.sectors_per_allocation_unit.is_power_of_two());
    assert!(volume.bytes_per_sector.is_power_of_two());
    let encoded_volume =
        build_volume_size_info(&volume).expect("canonical volume size info builds");
    assert_eq!(encoded_volume.len(), 40);

    provider.cleanup_open(5201);
    provider.close_open(5201);
}

#[test]
fn query_dir_preserves_native_spelling_identity_and_enumerator_order() {
    let root = TempRoot::new("query-dir-native-identities");
    let listed = root.child("LiStEd");
    std::fs::create_dir(&listed).expect("create enumerated directory");
    let mixed_name = "MiXeD-\u{732b}.TXT";
    let shared_name = "shared.bin";
    let alias_name = "SHARED-\u{5225}\u{540d}.bin";
    let subdir_name = "SubDir";
    std::fs::write(listed.join(mixed_name), b"unicode content").expect("seed unicode file");
    std::fs::write(listed.join(shared_name), b"hard-link stream").expect("seed hard-link file");
    std::fs::hard_link(listed.join(shared_name), listed.join(alias_name))
        .expect("create second hard-link name");
    std::fs::create_dir(listed.join(subdir_name)).expect("create child directory");

    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let directory_open = prepare_request(PrepareCase {
        op: 210,
        parent: provider.root_file_id(),
        name: "LiStEd",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&directory_open, TransactionId { lo: 1210, hi: 0 })
        .expect("prepare directory open");
    provider
        .commit_open(&commit_request(
            &directory_open,
            1210,
            5210,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit directory open");

    let first = provider
        .query_dir(5210)
        .expect("enumerate native directory");
    let provider_order: Vec<String> = first.iter().map(candidate_name).collect();
    assert_eq!(provider_order.len(), 4);
    assert!(!provider_order
        .iter()
        .any(|name| name == "." || name == ".."));
    for exact in [mixed_name, shared_name, alias_name, subdir_name] {
        assert_eq!(
            provider_order.iter().filter(|name| *name == exact).count(),
            1,
            "preserve each actual on-disk UTF-16 spelling"
        );
    }

    let mixed = first
        .iter()
        .find(|candidate| candidate_name(candidate) == mixed_name)
        .expect("mixed-case candidate");
    let mixed_native = std::fs::metadata(listed.join(mixed_name)).expect("native mixed metadata");
    assert_eq!(mixed.fields.sizes.file_size, mixed_native.file_size());
    assert_eq!(
        mixed.fields.sizes.valid_data_length,
        mixed_native.file_size()
    );
    assert_eq!(
        mixed.fields.attributes,
        mixed_native.file_attributes() & file_attributes::ACCEPTED_MASK_V21
    );
    assert_eq!(
        mixed.fields.creation_time,
        i64::try_from(mixed_native.creation_time()).expect("representable creation time")
    );
    assert_eq!(
        mixed.fields.last_access_time,
        i64::try_from(mixed_native.last_access_time()).expect("representable access time")
    );
    assert_eq!(
        mixed.fields.last_write_time,
        i64::try_from(mixed_native.last_write_time()).expect("representable write time")
    );
    assert!(mixed.fields.sizes.allocation_size >= mixed.fields.sizes.file_size);
    assert_ne!(mixed.fields.sizes.size_epoch, 0);
    assert_ne!(mixed.fields.namespace_generation, 0);

    let shared = first
        .iter()
        .find(|candidate| candidate_name(candidate) == shared_name)
        .expect("first hard-link candidate");
    let alias = first
        .iter()
        .find(|candidate| candidate_name(candidate) == alias_name)
        .expect("second hard-link candidate");
    assert_eq!(shared.fields.file_id, alias.fields.file_id);
    assert_ne!(shared.fields.link_id, alias.fields.link_id);
    assert_eq!(
        (
            shared.fields.sizes.allocation_size,
            shared.fields.sizes.file_size,
            shared.fields.sizes.valid_data_length,
            shared.fields.sizes.size_epoch,
        ),
        (
            alias.fields.sizes.allocation_size,
            alias.fields.sizes.file_size,
            alias.fields.sizes.valid_data_length,
            alias.fields.sizes.size_epoch,
        )
    );
    let replay = provider.query_dir(5210).expect("replay native directory");
    assert_eq!(
        replay.iter().map(candidate_name).collect::<Vec<_>>(),
        provider_order
    );
    for candidate in &first {
        let name = candidate_name(candidate);
        let repeated = replay
            .iter()
            .find(|entry| candidate_name(entry) == name)
            .expect("replayed candidate");
        assert_eq!(repeated.fields.file_id, candidate.fields.file_id);
        assert_eq!(repeated.fields.link_id, candidate.fields.link_id);
        assert_eq!(
            repeated.fields.namespace_generation,
            candidate.fields.namespace_generation
        );
        assert_eq!(
            repeated.fields.sizes.size_epoch,
            candidate.fields.sizes.size_epoch
        );
    }

    let mut enumerator = DirEnumerator::new();
    let initial = query_dir_request(QueryDirFormV21::InitialMatchAll, 71, 0, true, None);
    let first_page = enumerator
        .open(5210, &initial, first.clone())
        .expect("initial provider-order page");
    assert_eq!(first_page.entry_count, 1);
    assert_eq!(first_page.next_cookie, 1);
    assert_eq!(
        query_dir_batch_names(&first_page.blob, 0),
        provider_order[..1]
    );
    let continuation = query_dir_request(
        QueryDirFormV21::Continuation,
        71,
        first_page.next_cookie,
        false,
        None,
    );
    let second_page = enumerator
        .continue_(5210, &continuation)
        .expect("continuation provider-order page");
    assert!(second_page.eof);
    assert_eq!(second_page.next_cookie, 0);
    assert_eq!(
        query_dir_batch_names(&second_page.blob, first_page.next_cookie),
        provider_order[1..]
    );

    let exact_request = query_dir_request(
        QueryDirFormV21::InitialExpression {
            exact_pattern: true,
        },
        72,
        0,
        false,
        Some(mixed_name),
    );
    let exact_page = enumerator
        .open(5210, &exact_request, first.clone())
        .expect("DirEnumerator owns exact-pattern filtering");
    assert!(exact_page.eof);
    assert_eq!(
        query_dir_batch_names(&exact_page.blob, 0),
        vec![mixed_name.to_owned()]
    );

    let hard_open = prepare_request(PrepareCase {
        op: 211,
        parent: prepared.file_id,
        name: shared_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let hard_prepared = provider
        .prepare_open(&hard_open, TransactionId { lo: 1211, hi: 0 })
        .expect("prepare retained hard-link identity");
    assert_eq!(hard_prepared.file_id, shared.fields.file_id);
    provider
        .commit_open(&commit_request(
            &hard_open,
            1211,
            5211,
            hard_prepared.namespace_generation,
            hard_prepared.security_generation,
        ))
        .expect("commit hard-link open");
    assert_eq!(
        provider
            .query_info(5211)
            .expect("query native hard-link count")
            .link_count,
        2
    );
    provider.cleanup_open(5211);
    provider.close_open(5211);
    provider.cleanup_open(5210);
    provider.close_open(5210);
}

#[test]
fn query_dir_rejects_reparse_before_publishing_candidates() {
    let root = TempRoot::new("query-dir-reparse");
    let listed = root.child("listed");
    let target = root.child("target");
    std::fs::create_dir(&listed).expect("create enumerated directory");
    std::fs::create_dir(&target).expect("create reparse target");
    std::fs::write(listed.join("ordinary.txt"), b"ordinary").expect("seed ordinary entry");
    let junction = listed.join("blocked-link");
    std::os::windows::fs::symlink_dir(&target, &junction)
        .expect("create owned directory reparse entry");

    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 212,
        parent: provider.root_file_id(),
        name: "listed",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1212, hi: 0 })
        .expect("prepare directory open");
    provider
        .commit_open(&commit_request(
            &request,
            1212,
            5212,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit directory open");

    let rejected = provider.query_dir(5212);
    std::fs::remove_dir(&junction).expect("clean owned reparse entry");
    expect_status(rejected, completion_status::NOT_SUPPORTED);
    let after_cleanup = provider
        .query_dir(5212)
        .expect("enumerate only after removing reparse");
    assert_eq!(
        after_cleanup.iter().map(candidate_name).collect::<Vec<_>>(),
        vec!["ordinary.txt".to_owned()]
    );

    provider.cleanup_open(5212);
    provider.close_open(5212);
}

#[test]
fn query_dir_requires_a_live_directory_open_with_list_access() {
    let root = TempRoot::new("query-dir-open-contract");
    let listed = root.child("listed");
    std::fs::create_dir(&listed).expect("create enumerated directory");
    std::fs::write(root.child("plain.txt"), b"plain").expect("seed plain file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");

    let directory_request = prepare_request(PrepareCase {
        op: 213,
        parent: provider.root_file_id(),
        name: "listed",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let directory_prepared = provider
        .prepare_open(&directory_request, TransactionId { lo: 1213, hi: 0 })
        .expect("prepare no-access directory");
    provider
        .commit_open(&commit_request_with_access(
            &directory_request,
            1213,
            5213,
            directory_prepared.namespace_generation,
            directory_prepared.security_generation,
            0,
        ))
        .expect("commit no-access directory");
    expect_status(provider.query_dir(5213), completion_status::ACCESS_DENIED);

    let file_request = prepare_request(PrepareCase {
        op: 214,
        parent: provider.root_file_id(),
        name: "plain.txt",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let file_prepared = provider
        .prepare_open(&file_request, TransactionId { lo: 1214, hi: 0 })
        .expect("prepare file open");
    provider
        .commit_open(&commit_request(
            &file_request,
            1214,
            5214,
            file_prepared.namespace_generation,
            file_prepared.security_generation,
        ))
        .expect("commit file open");
    expect_status(provider.query_dir(5214), completion_status::DATA_ERROR);

    provider.cleanup_open(5214);
    provider.close_open(5214);
    provider.cleanup_open(5213);
    provider.close_open(5213);
    match provider.query_dir(5213) {
        Err(error) => assert_eq!(error, ProviderError::internal()),
        Ok(_) => panic!("a missing retained open is provider-state corruption"),
    }
}

#[test]
fn query_dir_returns_data_error_for_abi_illegal_native_name_without_identity_leak() {
    let root = TempRoot::new("query-dir-invalid-native-name");
    let listed = root.child("listed");
    std::fs::create_dir(&listed).expect("create enumerated directory");
    std::fs::write(listed.join("ordinary.txt"), b"ordinary").expect("seed ordinary entry");
    let invalid_name = OsString::from_wide(&[
        u16::from(b'i'),
        u16::from(b'l'),
        u16::from(b'l'),
        u16::from(b'-'),
        0xd800,
        u16::from(b'.'),
        u16::from(b'b'),
        u16::from(b'i'),
        u16::from(b'n'),
    ]);
    let invalid_path = listed.join(&invalid_name);
    std::fs::write(&invalid_path, b"ill-formed UTF-16")
        .expect("NTFS accepts an owned unpaired-surrogate spelling");

    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 215,
        parent: provider.root_file_id(),
        name: "listed",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1215, hi: 0 })
        .expect("prepare directory open");
    provider
        .commit_open(&commit_request(
            &request,
            1215,
            5215,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit directory open");

    let rejected = provider.query_dir(5215);
    std::fs::remove_file(&invalid_path).expect("remove exact invalid-name path");
    expect_status(rejected, completion_status::DATA_ERROR);

    let candidates = provider
        .query_dir(5215)
        .expect("enumerate valid entry after invalid-name cleanup");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidate_name(&candidates[0]), "ordinary.txt");
    assert_eq!(candidates[0].fields.file_id, FileId { lo: 3, hi: 0 });
    assert_eq!(
        candidates[0].fields.link_id,
        fsring_abi::ids::LinkId { lo: 2, hi: 0 }
    );
    assert_eq!(
        candidates[0].fields.namespace_generation, 5,
        "failed enumeration must not consume a namespace generation"
    );
    assert_eq!(
        candidates[0].fields.sizes.size_epoch, 3,
        "failed enumeration must not consume a size epoch"
    );

    provider.cleanup_open(5215);
    provider.close_open(5215);
}

#[test]
fn security_owner_group_dacl_round_trip_advances_only_security_lane() {
    let root = TempRoot::new("security-round-trip");
    let file_name = "secured.txt";
    let file_path = root.child(file_name);
    std::fs::write(&file_path, b"security bytes").expect("seed owned file");
    grant_current_user_full_control(&file_path);
    let directory_name = "secured-dir";
    std::fs::create_dir(root.child(directory_name)).expect("seed owned directory");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let security_access =
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | READ_CONTROL;

    let file_request = prepare_request_with_access(
        PrepareCase {
            op: 216,
            parent: provider.root_file_id(),
            name: file_name,
            disposition: FILE_OPEN,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        },
        security_access,
    );
    let file_prepared = provider
        .prepare_open(&file_request, TransactionId { lo: 1216, hi: 0 })
        .expect("prepare secured file");
    let committed = provider
        .commit_open(&commit_request_with_access(
            &file_request,
            1216,
            5216,
            file_prepared.namespace_generation,
            file_prepared.security_generation,
            security_access,
        ))
        .expect("commit secured file");

    let information =
        security_information::OWNER | security_information::GROUP | security_information::DACL;
    let descriptor = provider
        .query_security(5216, information)
        .expect("query owner/group/DACL");
    assert!((20..=65_536).contains(&descriptor.len()));
    assert_eq!(descriptor[0], 1, "security descriptor revision");
    assert_ne!(
        u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8000,
        0,
        "descriptor must be self-relative"
    );
    let before = provider.query_info(5216).expect("query generations");
    let effect = provider
        .set_security(5216, before.security_generation, information, &descriptor)
        .expect("set the same owner/group/DACL descriptor");
    let after = provider.query_info(5216).expect("refresh generations");
    let round_trip = provider
        .query_security(5216, information)
        .expect("query applied owner/group/DACL");

    assert_eq!(
        normalized_native_security_descriptor(&round_trip),
        normalized_native_security_descriptor(&descriptor)
    );
    assert_eq!(effect.file_id, file_prepared.file_id);
    assert_eq!(effect.link_count, after.link_count);
    assert_eq!(effect.security_generation, after.security_generation);
    assert_ne!(after.security_generation, before.security_generation);
    assert_eq!(after.namespace_generation, before.namespace_generation);
    assert_eq!(after.sizes.size_epoch, before.sizes.size_epoch);
    assert_eq!(effect.namespace_generation, 0);
    assert_eq!(effect.source_parent_generation, 0);
    assert_eq!(effect.target_parent_generation, 0);
    assert_eq!(effect.parent_generation, 0);
    assert_eq!(
        (
            effect.sizes.allocation_size,
            effect.sizes.file_size,
            effect.sizes.valid_data_length,
            effect.sizes.size_epoch,
        ),
        (
            after.sizes.allocation_size,
            after.sizes.file_size,
            after.sizes.valid_data_length,
            after.sizes.size_epoch,
        )
    );
    assert_eq!(
        (
            effect.retained_sizes.allocation_size,
            effect.retained_sizes.file_size,
            effect.retained_sizes.valid_data_length,
            effect.retained_sizes.size_epoch,
        ),
        (
            after.sizes.allocation_size,
            after.sizes.file_size,
            after.sizes.valid_data_length,
            after.sizes.size_epoch,
        )
    );
    assert_eq!(
        effect.volume_commit_sequence,
        committed.volume_commit_sequence + 1
    );

    let directory_request = prepare_request(PrepareCase {
        op: 217,
        parent: provider.root_file_id(),
        name: directory_name,
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let directory_prepared = provider
        .prepare_open(&directory_request, TransactionId { lo: 1217, hi: 0 })
        .expect("prepare secured directory");
    provider
        .commit_open(&commit_request_with_access(
            &directory_request,
            1217,
            5217,
            directory_prepared.namespace_generation,
            directory_prepared.security_generation,
            READ_CONTROL,
        ))
        .expect("commit secured directory");
    let directory_descriptor = provider
        .query_security(5217, information)
        .expect("query directory owner/group/DACL");
    assert!((20..=65_536).contains(&directory_descriptor.len()));
    assert_ne!(
        u16::from_le_bytes([directory_descriptor[2], directory_descriptor[3]]) & 0x8000,
        0
    );

    provider.cleanup_open(5217);
    provider.close_open(5217);
    provider.cleanup_open(5216);
    provider.close_open(5216);
}

#[test]
fn security_rejects_masks_descriptors_stale_generations_and_missing_access_pre_effect() {
    let root = TempRoot::new("security-preflight");
    let file_name = "secured.txt";
    let path = root.child(file_name);
    std::fs::write(&path, b"unchanged backing bytes").expect("seed owned file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let security_access = FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC | READ_CONTROL;
    let full_request = prepare_request_with_access(
        PrepareCase {
            op: 218,
            parent: provider.root_file_id(),
            name: file_name,
            disposition: FILE_OPEN,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        },
        security_access,
    );
    let full_prepared = provider
        .prepare_open(&full_request, TransactionId { lo: 1218, hi: 0 })
        .expect("prepare security-capable open");
    provider
        .commit_open(&commit_request_with_access(
            &full_request,
            1218,
            5218,
            full_prepared.namespace_generation,
            full_prepared.security_generation,
            security_access,
        ))
        .expect("commit security-capable open");
    let information =
        security_information::OWNER | security_information::GROUP | security_information::DACL;
    let descriptor = provider
        .query_security(5218, information)
        .expect("query reference descriptor");
    let before = provider.query_info(5218).expect("query before failures");
    let bytes_before = std::fs::read(&path).expect("read backing before failures");

    for invalid_mask in [0, security_information::LABEL] {
        expect_status(
            provider.query_security(5218, invalid_mask),
            completion_status::DATA_ERROR,
        );
    }
    for invalid_mask in [0, security_information::SET_MASK | 0x80] {
        expect_status(
            provider.set_security(5218, before.security_generation, invalid_mask, &descriptor),
            completion_status::DATA_ERROR,
        );
    }

    let truncated = descriptor[..19].to_vec();
    let mut wrong_revision = descriptor.clone();
    wrong_revision[0] = 2;
    let mut absolute = descriptor.clone();
    let control = u16::from_le_bytes([absolute[2], absolute[3]]) & !0x8000;
    absolute[2..4].copy_from_slice(&control.to_le_bytes());
    for malformed in [&truncated, &wrong_revision, &absolute] {
        expect_status(
            provider.set_security(
                5218,
                before.security_generation,
                security_information::DACL,
                malformed,
            ),
            completion_status::INVALID_SECURITY_DESCR,
        );
    }
    expect_status(
        provider.set_security(
            u64::MAX,
            before.security_generation,
            security_information::DACL,
            &truncated,
        ),
        completion_status::INVALID_SECURITY_DESCR,
    );
    expect_status(
        provider.set_security(
            5218,
            before.security_generation + 1,
            security_information::DACL,
            &descriptor,
        ),
        completion_status::RETRY,
    );

    let denied_request = prepare_request(PrepareCase {
        op: 219,
        parent: provider.root_file_id(),
        name: file_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let denied_prepared = provider
        .prepare_open(&denied_request, TransactionId { lo: 1219, hi: 0 })
        .expect("prepare restricted open");
    provider
        .commit_open(&commit_request_with_access(
            &denied_request,
            1219,
            5219,
            denied_prepared.namespace_generation,
            denied_prepared.security_generation,
            0,
        ))
        .expect("commit restricted open");
    expect_status(
        provider.query_security(5219, information),
        completion_status::ACCESS_DENIED,
    );
    for information_bit in [
        security_information::OWNER,
        security_information::GROUP,
        security_information::DACL,
        security_information::SACL,
        security_information::LABEL,
        security_information::ATTRIBUTE,
        security_information::SCOPE,
        security_information::BACKUP,
        security_information::PROTECTED_DACL,
        security_information::UNPROTECTED_DACL,
        security_information::PROTECTED_SACL,
        security_information::UNPROTECTED_SACL,
    ] {
        expect_status(
            provider.set_security(
                5219,
                before.security_generation,
                information_bit,
                &descriptor,
            ),
            completion_status::ACCESS_DENIED,
        );
    }

    let after = provider.query_info(5218).expect("query after failures");
    assert_eq!(after.security_generation, before.security_generation);
    assert_eq!(after.namespace_generation, before.namespace_generation);
    assert_eq!(after.sizes.size_epoch, before.sizes.size_epoch);
    assert_eq!(
        provider
            .query_security(5218, information)
            .expect("descriptor unchanged"),
        descriptor
    );
    assert_eq!(
        std::fs::read(&path).expect("read backing after failures"),
        bytes_before
    );

    provider.cleanup_open(5219);
    provider.close_open(5219);
    provider.cleanup_open(5218);
    assert_eq!(
        provider.query_security(5218, information),
        Err(ProviderError::internal())
    );
    provider.close_open(5218);
}

#[test]
fn sacl_security_requires_retained_system_security_access_without_state_change() {
    let root = TempRoot::new("security-sacl-privilege");
    let file_name = "secured.txt";
    std::fs::write(root.child(file_name), b"sacl bytes").expect("seed owned file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 220,
        parent: provider.root_file_id(),
        name: file_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1220, hi: 0 })
        .expect("prepare ordinary open");
    provider
        .commit_open(&commit_request_with_access(
            &request,
            1220,
            5220,
            prepared.namespace_generation,
            prepared.security_generation,
            READ_CONTROL,
        ))
        .expect("commit without ACCESS_SYSTEM_SECURITY");

    let before_descriptor = provider
        .query_security(
            5220,
            security_information::OWNER | security_information::GROUP | security_information::DACL,
        )
        .expect("query unprivileged baseline");
    expect_status(
        provider.query_security(5220, security_information::SACL),
        completion_status::ACCESS_DENIED,
    );
    expect_status(
        provider.set_security(
            5220,
            prepared.security_generation,
            security_information::SACL,
            &before_descriptor,
        ),
        completion_status::ACCESS_DENIED,
    );
    assert_eq!(
        provider
            .query_security(
                5220,
                security_information::OWNER
                    | security_information::GROUP
                    | security_information::DACL,
            )
            .expect("query baseline after denied SACL"),
        before_descriptor
    );

    provider.cleanup_open(5220);
    provider.close_open(5220);
}

#[test]
fn basic_info_applies_each_mask_bit_and_advances_only_metadata_lane() {
    let root = TempRoot::new("basic-info-mask-bits");
    let file_name = "basic.txt";
    let path = root.child(file_name);
    std::fs::write(&path, b"basic-info bytes").expect("seed owned file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let access = FILE_GENERIC_READ | FILE_WRITE_ATTRIBUTES;
    let request = prepare_request_with_access(
        PrepareCase {
            op: 221,
            parent: provider.root_file_id(),
            name: file_name,
            disposition: FILE_OPEN,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        },
        access,
    );
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1221, hi: 0 })
        .expect("prepare metadata-capable open");
    let committed = provider
        .commit_open(&commit_request_with_access(
            &request,
            1221,
            5221,
            prepared.namespace_generation,
            prepared.security_generation,
            access,
        ))
        .expect("commit metadata-capable open");

    let mut expected_sequence = committed.volume_commit_sequence;
    for (index, mask) in [
        basic_info_set_mask::CREATION_TIME,
        basic_info_set_mask::LAST_ACCESS_TIME,
        basic_info_set_mask::LAST_WRITE_TIME,
        basic_info_set_mask::CHANGE_TIME,
        basic_info_set_mask::FILE_ATTRIBUTES,
    ]
    .into_iter()
    .enumerate()
    {
        let before = provider.query_info(5221).expect("query pre-basic state");
        let timestamp = before
            .creation_time
            .checked_sub(10_000_000 * i64::try_from(index + 1).unwrap())
            .filter(|value| *value > 0)
            .unwrap_or(before.creation_time + 10_000_000 * i64::try_from(index + 1).unwrap());
        let body = basic_info_body(
            mask,
            if mask == basic_info_set_mask::CREATION_TIME {
                timestamp
            } else {
                0
            },
            if mask == basic_info_set_mask::LAST_ACCESS_TIME {
                timestamp
            } else {
                0
            },
            if mask == basic_info_set_mask::LAST_WRITE_TIME {
                timestamp
            } else {
                0
            },
            if mask == basic_info_set_mask::CHANGE_TIME {
                timestamp
            } else {
                0
            },
            if mask == basic_info_set_mask::FILE_ATTRIBUTES {
                file_attributes::HIDDEN
            } else {
                0
            },
        );

        let effect = provider
            .set_basic_info(5221, before.namespace_generation, &body)
            .expect("apply one selected basic-info field");
        let after = provider.query_info(5221).expect("refresh basic state");
        expected_sequence += 1;

        match mask {
            basic_info_set_mask::CREATION_TIME => assert_eq!(after.creation_time, timestamp),
            basic_info_set_mask::LAST_ACCESS_TIME => assert_eq!(after.last_access_time, timestamp),
            basic_info_set_mask::LAST_WRITE_TIME => assert_eq!(after.last_write_time, timestamp),
            basic_info_set_mask::CHANGE_TIME => assert_eq!(after.change_time, timestamp),
            basic_info_set_mask::FILE_ATTRIBUTES => {
                assert_ne!(after.attributes & file_attributes::HIDDEN, 0)
            }
            _ => unreachable!(),
        }
        if mask != basic_info_set_mask::CREATION_TIME {
            assert_eq!(after.creation_time, before.creation_time);
        }
        if mask != basic_info_set_mask::LAST_ACCESS_TIME {
            assert_eq!(after.last_access_time, before.last_access_time);
        }
        if mask != basic_info_set_mask::LAST_WRITE_TIME {
            assert_eq!(after.last_write_time, before.last_write_time);
        }
        if mask != basic_info_set_mask::CHANGE_TIME {
            assert_eq!(after.change_time, before.change_time);
        }
        if mask != basic_info_set_mask::FILE_ATTRIBUTES {
            assert_eq!(after.attributes, before.attributes);
        }
        assert!(after.namespace_generation > before.namespace_generation);
        assert_eq!(after.security_generation, before.security_generation);
        assert_eq!(after.sizes.size_epoch, before.sizes.size_epoch);
        assert_eq!(
            after.sizes.valid_data_length,
            before.sizes.valid_data_length
        );
        assert_eq!(effect.file_id, prepared.file_id);
        assert_eq!(effect.namespace_generation, after.namespace_generation);
        assert_eq!(effect.security_generation, 0);
        assert_eq!(effect.source_parent_generation, 0);
        assert_eq!(effect.target_parent_generation, 0);
        assert_eq!(effect.parent_generation, 0);
        assert_eq!(effect.volume_commit_sequence, expected_sequence);
        assert_eq!(
            (
                effect.sizes.allocation_size,
                effect.sizes.file_size,
                effect.sizes.valid_data_length,
                effect.sizes.size_epoch,
            ),
            (
                before.sizes.allocation_size,
                before.sizes.file_size,
                before.sizes.valid_data_length,
                before.sizes.size_epoch,
            )
        );
        assert_eq!(
            (
                effect.retained_sizes.allocation_size,
                effect.retained_sizes.file_size,
                effect.retained_sizes.valid_data_length,
                effect.retained_sizes.size_epoch,
            ),
            (
                before.sizes.allocation_size,
                before.sizes.file_size,
                before.sizes.valid_data_length,
                before.sizes.size_epoch,
            )
        );
    }

    provider.cleanup_open(5221);
    provider.close_open(5221);
}

#[test]
fn allocation_eof_and_vdl_mutations_commit_exact_size_state() {
    let root = TempRoot::new("size-mutations");
    let file_name = "sizes.bin";
    let path = root.child(file_name);
    let original_bytes = b"0123456789abcdef";
    std::fs::write(&path, original_bytes).expect("seed owned file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 222,
        parent: provider.root_file_id(),
        name: file_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1222, hi: 0 })
        .expect("prepare size-capable open");
    let committed = provider
        .commit_open(&commit_request(
            &request,
            1222,
            5222,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit size-capable open");
    let initial = provider.query_info(5222).expect("query initial sizes");

    let allocation = provider
        .set_allocation_size(5222, initial.sizes.size_epoch, 64 * 1024)
        .expect("reserve native allocation");
    let after_allocation = provider.query_info(5222).expect("query allocation");
    assert!(after_allocation.sizes.allocation_size >= 64 * 1024);
    assert_eq!(after_allocation.sizes.file_size, initial.sizes.file_size);
    assert_eq!(
        after_allocation.sizes.valid_data_length,
        initial.sizes.valid_data_length
    );
    assert!(after_allocation.sizes.size_epoch > initial.sizes.size_epoch);
    assert_eq!(
        after_allocation.namespace_generation,
        initial.namespace_generation
    );
    assert_eq!(
        after_allocation.security_generation,
        initial.security_generation
    );
    assert_eq!(
        allocation.volume_commit_sequence,
        committed.volume_commit_sequence + 1
    );
    assert_eq!(
        size_state_tuple(allocation.sizes),
        size_state_tuple(after_allocation.sizes)
    );
    assert_eq!(
        size_state_tuple(allocation.retained_sizes),
        size_state_tuple(initial.sizes)
    );
    assert_eq!(allocation.namespace_generation, 0);
    assert_eq!(allocation.security_generation, 0);
    assert_eq!(
        (
            allocation.retained_sizes.file_size,
            allocation.retained_sizes.valid_data_length,
            allocation.retained_sizes.size_epoch,
        ),
        (
            initial.sizes.file_size,
            initial.sizes.valid_data_length,
            initial.sizes.size_epoch,
        )
    );

    let shrink = provider
        .set_end_of_file(5222, after_allocation.sizes.size_epoch, 8)
        .expect("shrink EOF");
    let after_shrink = provider.query_info(5222).expect("query shrink");
    assert_eq!(
        std::fs::read(&path).expect("read shrunk bytes"),
        &original_bytes[..8]
    );
    assert_eq!(after_shrink.sizes.file_size, 8);
    assert_eq!(after_shrink.sizes.valid_data_length, 8);
    assert!(after_shrink.sizes.size_epoch > after_allocation.sizes.size_epoch);
    assert_eq!(
        shrink.volume_commit_sequence,
        allocation.volume_commit_sequence + 1
    );
    assert_eq!(
        size_state_tuple(shrink.sizes),
        size_state_tuple(after_shrink.sizes)
    );
    assert_eq!(
        size_state_tuple(shrink.retained_sizes),
        size_state_tuple(after_allocation.sizes)
    );
    assert_eq!(shrink.namespace_generation, 0);
    assert_eq!(shrink.security_generation, 0);

    let extend = provider
        .set_end_of_file(5222, after_shrink.sizes.size_epoch, 32)
        .expect("extend EOF");
    let after_extend = provider.query_info(5222).expect("query extension");
    assert_eq!(after_extend.sizes.file_size, 32);
    assert_eq!(
        after_extend.sizes.valid_data_length, after_shrink.sizes.valid_data_length,
        "EOF extension preserves the tracked VDL"
    );
    assert!(after_extend.sizes.size_epoch > after_shrink.sizes.size_epoch);
    assert_eq!(
        extend.volume_commit_sequence,
        shrink.volume_commit_sequence + 1
    );
    assert_eq!(
        size_state_tuple(extend.sizes),
        size_state_tuple(after_extend.sizes)
    );
    assert_eq!(
        size_state_tuple(extend.retained_sizes),
        size_state_tuple(after_shrink.sizes)
    );

    let bytes_before_vdl = std::fs::read(&path).expect("read before VDL");
    let vdl_before = provider.query_info(5222).expect("query before VDL");
    match provider.set_valid_data_length(5222, vdl_before.sizes.size_epoch, 16) {
        Ok(vdl) => {
            eprintln!(
                "Task 15 privilege-path outcome: SET_VALID_DATA_LENGTH succeeded on this host"
            );
            let after_vdl = provider.query_info(5222).expect("query successful VDL");
            assert_eq!(after_vdl.sizes.file_size, vdl_before.sizes.file_size);
            assert_eq!(
                after_vdl.sizes.allocation_size,
                vdl_before.sizes.allocation_size
            );
            assert_eq!(after_vdl.sizes.valid_data_length, 16);
            assert!(after_vdl.sizes.size_epoch > vdl_before.sizes.size_epoch);
            assert_eq!(
                vdl.volume_commit_sequence,
                extend.volume_commit_sequence + 1
            );
            assert_eq!(
                size_state_tuple(vdl.sizes),
                size_state_tuple(after_vdl.sizes)
            );
            assert_eq!(
                size_state_tuple(vdl.retained_sizes),
                size_state_tuple(vdl_before.sizes)
            );
            assert_eq!(vdl.namespace_generation, 0);
            assert_eq!(vdl.security_generation, 0);
        }
        Err(error) => {
            eprintln!(
                "Task 15 privilege-path outcome: SET_VALID_DATA_LENGTH returned {:#010x}",
                error.status()
            );
            assert!(
                matches!(
                    error.status(),
                    completion_status::PRIVILEGE_NOT_HELD | completion_status::ACCESS_DENIED
                ),
                "VDL failure must be the registered privilege/access path, got {:#010x}",
                error.status()
            );
            let after_vdl = provider.query_info(5222).expect("query rejected VDL");
            assert_eq!(after_vdl.sizes.file_size, vdl_before.sizes.file_size);
            assert_eq!(
                after_vdl.sizes.allocation_size,
                vdl_before.sizes.allocation_size
            );
            assert_eq!(
                after_vdl.sizes.valid_data_length,
                vdl_before.sizes.valid_data_length
            );
            assert_eq!(after_vdl.sizes.size_epoch, vdl_before.sizes.size_epoch);
            assert_eq!(
                std::fs::read(&path).expect("read after rejected VDL"),
                bytes_before_vdl
            );
        }
    }

    provider.cleanup_open(5222);
    provider.close_open(5222);
}

#[test]
fn metadata_and_size_preflights_reject_stale_invalid_denied_and_directory_requests() {
    let root = TempRoot::new("mutation-preflight");
    let file_name = "guarded.bin";
    let path = root.child(file_name);
    std::fs::write(&path, b"unchanged payload").expect("seed owned file");
    std::fs::create_dir(root.child("directory")).expect("seed owned directory");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let denied_request = prepare_request_with_access(
        PrepareCase {
            op: 223,
            parent: provider.root_file_id(),
            name: file_name,
            disposition: FILE_OPEN,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        },
        FILE_GENERIC_READ,
    );
    let denied_prepared = provider
        .prepare_open(&denied_request, TransactionId { lo: 1223, hi: 0 })
        .expect("prepare denied open");
    provider
        .commit_open(&commit_request_with_access(
            &denied_request,
            1223,
            5223,
            denied_prepared.namespace_generation,
            denied_prepared.security_generation,
            FILE_GENERIC_READ,
        ))
        .expect("commit denied open");
    let before = provider.query_info(5223).expect("query baseline");
    let bytes_before = std::fs::read(&path).expect("read baseline");
    let valid_basic = basic_info_body(
        basic_info_set_mask::LAST_WRITE_TIME,
        0,
        0,
        before.last_write_time.saturating_sub(10_000_000).max(1),
        0,
        0,
    );

    expect_status(
        provider.set_basic_info(5223, before.namespace_generation, &valid_basic),
        completion_status::ACCESS_DENIED,
    );
    expect_status(
        provider.set_allocation_size(5223, before.sizes.size_epoch, 4096),
        completion_status::ACCESS_DENIED,
    );
    expect_status(
        provider.set_end_of_file(5223, before.sizes.size_epoch, 4),
        completion_status::ACCESS_DENIED,
    );
    expect_status(
        provider.set_valid_data_length(5223, before.sizes.size_epoch, 4),
        completion_status::ACCESS_DENIED,
    );

    let allowed_request = prepare_request(PrepareCase {
        op: 224,
        parent: provider.root_file_id(),
        name: file_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let allowed_prepared = provider
        .prepare_open(&allowed_request, TransactionId { lo: 1224, hi: 0 })
        .expect("prepare allowed open");
    provider
        .commit_open(&commit_request(
            &allowed_request,
            1224,
            5224,
            allowed_prepared.namespace_generation,
            allowed_prepared.security_generation,
        ))
        .expect("commit allowed open");
    let allowed_before = provider.query_info(5224).expect("query allowed baseline");

    expect_status(
        provider.set_basic_info(5224, allowed_before.namespace_generation + 1, &valid_basic),
        completion_status::RETRY,
    );
    expect_status(
        provider.set_end_of_file(5224, allowed_before.sizes.size_epoch + 1, 4),
        completion_status::RETRY,
    );
    expect_status(
        provider.set_allocation_size(5224, allowed_before.sizes.size_epoch + 1, 4096),
        completion_status::RETRY,
    );
    expect_status(
        provider.set_valid_data_length(5224, allowed_before.sizes.size_epoch + 1, 4),
        completion_status::RETRY,
    );
    for invalid in [
        basic_info_body(0, 0, 0, 0, 0, 0),
        basic_info_body(basic_info_set_mask::ALL | 0x20, 1, 1, 1, 1, 0),
        basic_info_body(basic_info_set_mask::CREATION_TIME, 0, 0, 0, 0, 0),
        basic_info_body(basic_info_set_mask::CREATION_TIME, 1, 2, 0, 0, 0),
        basic_info_body(basic_info_set_mask::CREATION_TIME, 1, -1, 0, 0, 0),
        basic_info_body(
            basic_info_set_mask::CREATION_TIME,
            1,
            0,
            0,
            0,
            file_attributes::HIDDEN,
        ),
        basic_info_body(basic_info_set_mask::FILE_ATTRIBUTES, 0, 0, 0, 0, 0),
        basic_info_body(
            basic_info_set_mask::FILE_ATTRIBUTES,
            0,
            0,
            0,
            0,
            file_attributes::DIRECTORY,
        ),
        basic_info_body(
            basic_info_set_mask::FILE_ATTRIBUTES,
            0,
            0,
            0,
            0,
            file_attributes::NORMAL | file_attributes::HIDDEN,
        ),
    ] {
        expect_status(
            provider.set_basic_info(5224, allowed_before.namespace_generation, &invalid),
            completion_status::DATA_ERROR,
        );
    }
    for operation in [
        provider.set_allocation_size(5224, allowed_before.sizes.size_epoch, i64::MAX as u64 + 1),
        provider.set_end_of_file(5224, allowed_before.sizes.size_epoch, i64::MAX as u64 + 1),
        provider.set_valid_data_length(
            5224,
            allowed_before.sizes.size_epoch,
            allowed_before.sizes.file_size + 1,
        ),
        provider.set_valid_data_length(
            5224,
            allowed_before.sizes.size_epoch,
            allowed_before.sizes.valid_data_length - 1,
        ),
    ] {
        expect_status(operation, completion_status::DATA_ERROR);
    }

    let directory_request = prepare_request(PrepareCase {
        op: 225,
        parent: provider.root_file_id(),
        name: "directory",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let directory_prepared = provider
        .prepare_open(&directory_request, TransactionId { lo: 1225, hi: 0 })
        .expect("prepare directory");
    provider
        .commit_open(&commit_request(
            &directory_request,
            1225,
            5225,
            directory_prepared.namespace_generation,
            directory_prepared.security_generation,
        ))
        .expect("commit directory");
    let directory_before = provider.query_info(5225).expect("query directory");
    expect_status(
        provider.set_allocation_size(5225, directory_before.sizes.size_epoch, 4096),
        completion_status::DATA_ERROR,
    );
    expect_status(
        provider.set_end_of_file(5225, directory_before.sizes.size_epoch, 0),
        completion_status::DATA_ERROR,
    );
    expect_status(
        provider.set_valid_data_length(5225, directory_before.sizes.size_epoch, 0),
        completion_status::DATA_ERROR,
    );

    let allowed_after = provider.query_info(5224).expect("query after rejections");
    assert_eq!(
        (
            allowed_after.namespace_generation,
            allowed_after.security_generation,
            allowed_after.sizes.size_epoch,
            allowed_after.sizes.file_size,
            allowed_after.sizes.valid_data_length,
        ),
        (
            allowed_before.namespace_generation,
            allowed_before.security_generation,
            allowed_before.sizes.size_epoch,
            allowed_before.sizes.file_size,
            allowed_before.sizes.valid_data_length,
        )
    );
    assert_eq!(
        std::fs::read(&path).expect("read unchanged bytes"),
        bytes_before
    );

    for kernel_open_id in [5225, 5224, 5223] {
        provider.cleanup_open(kernel_open_id);
        provider.close_open(kernel_open_id);
    }
}

#[test]
fn basic_info_rejects_malformed_headers_before_open_lookup_or_native_effect() {
    let root = TempRoot::new("basic-info-header");
    let file_name = "header.txt";
    let path = root.child(file_name);
    std::fs::write(&path, b"header bytes").expect("seed owned file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 226,
        parent: provider.root_file_id(),
        name: file_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1226, hi: 0 })
        .expect("prepare metadata open");
    let committed = provider
        .commit_open(&commit_request(
            &request,
            1226,
            5226,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit metadata open");
    let bytes_before = std::fs::read(&path).expect("read baseline");
    let before = provider.query_info(5226).expect("query baseline");
    let requested_time = before.last_write_time.saturating_sub(10_000_000).max(1);
    let canonical = basic_info_body(
        basic_info_set_mask::LAST_WRITE_TIME,
        0,
        0,
        requested_time,
        0,
        0,
    );
    let mut malformed_size = canonical;
    malformed_size.header.struct_size = 47;
    let mut malformed_version = canonical;
    malformed_version.header.struct_version = CONTROL_VERSION_V1 + 1;
    let mut malformed_flags = canonical;
    malformed_flags.header.required_flags = 1;

    for malformed in [malformed_size, malformed_version, malformed_flags] {
        expect_status(
            provider.set_basic_info(5226, before.namespace_generation, &malformed),
            completion_status::DATA_ERROR,
        );
        expect_status(
            provider.set_basic_info(u64::MAX, before.namespace_generation, &malformed),
            completion_status::DATA_ERROR,
        );
        let after = provider.query_info(5226).expect("query rejected header");
        assert_eq!(after.creation_time, before.creation_time);
        assert_eq!(after.last_access_time, before.last_access_time);
        assert_eq!(after.last_write_time, before.last_write_time);
        assert_eq!(after.change_time, before.change_time);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.namespace_generation, before.namespace_generation);
        assert_eq!(after.security_generation, before.security_generation);
        assert_eq!(
            size_state_tuple(after.sizes),
            size_state_tuple(before.sizes)
        );
    }
    assert_eq!(
        std::fs::read(&path).expect("read unchanged bytes"),
        bytes_before
    );

    let effect = provider
        .set_basic_info(5226, before.namespace_generation, &canonical)
        .expect("valid header still mutates");
    assert_eq!(
        effect.volume_commit_sequence,
        committed.volume_commit_sequence + 1,
        "malformed headers must not consume the volume sequence"
    );
    assert_eq!(
        provider
            .query_info(5226)
            .expect("query valid mutation")
            .last_write_time,
        requested_time
    );

    provider.cleanup_open(5226);
    provider.close_open(5226);
}

#[test]
fn decoded_task13_mutations_dispatch_and_build_frozen_results() {
    let root = TempRoot::new("decoded-task13-mutations");
    let file_name = "decoded.bin";
    let path = root.child(file_name);
    std::fs::write(&path, b"0123456789abcdef").expect("seed owned file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let request = prepare_request(PrepareCase {
        op: 227,
        parent: provider.root_file_id(),
        name: file_name,
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let prepared = provider
        .prepare_open(&request, TransactionId { lo: 1227, hi: 0 })
        .expect("prepare mutation open");
    provider
        .commit_open(&commit_request(
            &request,
            1227,
            5227,
            prepared.namespace_generation,
            prepared.security_generation,
        ))
        .expect("commit mutation open");

    let before_basic = provider.query_info(5227).expect("query before basic");
    let requested_write_time = before_basic
        .last_write_time
        .saturating_sub(10_000_000)
        .max(1);
    let basic = basic_info_body(
        basic_info_set_mask::LAST_WRITE_TIME,
        0,
        0,
        requested_write_time,
        0,
        0,
    );
    let mut basic_bytes = [0_u8; 48];
    try_encode(&basic, &mut basic_bytes).expect("encode basic body");
    let basic_fixture = decoded_task13_mutation(
        mutation_kind::SET_BASIC_INFO,
        before_basic.namespace_generation,
        0,
        &basic_bytes,
    );
    assert_eq!(
        basic_fixture.request.expected_namespace_generation(),
        before_basic.namespace_generation
    );
    assert_eq!(basic_fixture.request.expected_size_epoch(), 0);
    match basic_fixture.request.body() {
        DecodedBody::SetBasicInfo { raw } => {
            assert_eq!(raw.set_mask, basic_info_set_mask::LAST_WRITE_TIME);
            assert_eq!(raw.last_write_time, requested_write_time);
        }
        _ => panic!("decoder retained wrong basic body"),
    }
    let basic_effect = provider
        .mutate_open(5227, &basic_fixture.request)
        .expect("dispatch decoded basic mutation");
    let basic_result = build_mutation_result(
        &basic_fixture.request,
        &basic_effect,
        &basic_fixture.table,
        basic_fixture.owner,
    )
    .expect("build validated basic result");
    assert_eq!(basic_result.result.len(), 112);
    assert!(basic_result.kind_result.is_empty());
    assert_eq!(
        provider
            .query_info(5227)
            .expect("query decoded basic")
            .last_write_time,
        requested_write_time
    );

    let before_allocation = provider.query_info(5227).expect("query before allocation");
    let allocation_body = SetSizeV1 {
        header: ControlHeader {
            struct_size: 24,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        new_size: 65_536,
        flags: 0,
        reserved: 0,
    };
    let mut allocation_bytes = [0_u8; 24];
    try_encode(&allocation_body, &mut allocation_bytes).expect("encode allocation body");
    let allocation_fixture = decoded_task13_mutation(
        mutation_kind::SET_ALLOCATION_SIZE,
        0,
        before_allocation.sizes.size_epoch,
        &allocation_bytes,
    );
    assert_eq!(
        allocation_fixture.request.expected_size_epoch(),
        before_allocation.sizes.size_epoch
    );
    match allocation_fixture.request.body() {
        DecodedBody::SetAllocationSize { raw } => assert_eq!(raw.new_size, 65_536),
        _ => panic!("decoder retained wrong allocation body"),
    }
    let allocation_effect = provider
        .mutate_open(5227, &allocation_fixture.request)
        .expect("dispatch decoded allocation mutation");
    let allocation_result = build_mutation_result(
        &allocation_fixture.request,
        &allocation_effect,
        &allocation_fixture.table,
        allocation_fixture.owner,
    )
    .expect("build validated allocation result");
    assert_eq!(allocation_result.result.len(), 112);
    assert!(allocation_result.kind_result.is_empty());

    let before_eof = provider.query_info(5227).expect("query before EOF");
    let eof_body = SetSizeV1 {
        new_size: 32,
        ..allocation_body
    };
    let mut eof_bytes = [0_u8; 24];
    try_encode(&eof_body, &mut eof_bytes).expect("encode EOF body");
    let eof_fixture = decoded_task13_mutation(
        mutation_kind::SET_END_OF_FILE,
        0,
        before_eof.sizes.size_epoch,
        &eof_bytes,
    );
    assert_eq!(
        eof_fixture.request.expected_size_epoch(),
        before_eof.sizes.size_epoch
    );
    match eof_fixture.request.body() {
        DecodedBody::SetEndOfFile { raw } => assert_eq!(raw.new_size, 32),
        _ => panic!("decoder retained wrong EOF body"),
    }
    let eof_effect = provider
        .mutate_open(5227, &eof_fixture.request)
        .expect("dispatch decoded EOF mutation");
    let eof_result = build_mutation_result(
        &eof_fixture.request,
        &eof_effect,
        &eof_fixture.table,
        eof_fixture.owner,
    )
    .expect("build validated EOF result");
    assert_eq!(eof_result.result.len(), 112);
    assert!(eof_result.kind_result.is_empty());

    let bytes_before_vdl = std::fs::read(&path).expect("read before decoded VDL");
    let before_vdl = provider.query_info(5227).expect("query before VDL");
    let vdl_body = SetSizeV1 {
        new_size: 24,
        ..allocation_body
    };
    let mut vdl_bytes = [0_u8; 24];
    try_encode(&vdl_body, &mut vdl_bytes).expect("encode VDL body");
    let vdl_fixture = decoded_task13_mutation(
        mutation_kind::SET_VALID_DATA_LENGTH,
        0,
        before_vdl.sizes.size_epoch,
        &vdl_bytes,
    );
    assert_eq!(
        vdl_fixture.request.expected_size_epoch(),
        before_vdl.sizes.size_epoch
    );
    match vdl_fixture.request.body() {
        DecodedBody::SetValidDataLength { raw } => assert_eq!(raw.new_size, 24),
        _ => panic!("decoder retained wrong VDL body"),
    }
    match provider.mutate_open(5227, &vdl_fixture.request) {
        Ok(vdl_effect) => {
            let vdl_result = build_mutation_result(
                &vdl_fixture.request,
                &vdl_effect,
                &vdl_fixture.table,
                vdl_fixture.owner,
            )
            .expect("build validated VDL result");
            assert_eq!(vdl_result.result.len(), 112);
            assert!(vdl_result.kind_result.is_empty());
            let after_vdl = provider.query_info(5227).expect("query decoded VDL");
            assert_eq!(after_vdl.sizes.valid_data_length, 24);
            assert_eq!(after_vdl.sizes.file_size, before_vdl.sizes.file_size);
            assert_eq!(
                after_vdl.sizes.allocation_size,
                before_vdl.sizes.allocation_size
            );
        }
        Err(error) => {
            assert!(
                matches!(
                    error.status(),
                    completion_status::PRIVILEGE_NOT_HELD | completion_status::ACCESS_DENIED
                ),
                "decoded VDL exact privilege/access failure: {:#010x}",
                error.status()
            );
            let after_vdl = provider
                .query_info(5227)
                .expect("query rejected decoded VDL");
            assert_eq!(
                size_state_tuple(after_vdl.sizes),
                size_state_tuple(before_vdl.sizes)
            );
            assert_eq!(
                after_vdl.namespace_generation,
                before_vdl.namespace_generation
            );
            assert_eq!(
                after_vdl.security_generation,
                before_vdl.security_generation
            );
            assert_eq!(
                std::fs::read(&path).expect("read after rejected decoded VDL"),
                bytes_before_vdl
            );
        }
    }

    provider.cleanup_open(5227);
    provider.close_open(5227);
}

#[test]
fn decoded_namespace_mutations_preserve_identity_and_build_kind_results() {
    let root = TempRoot::new("decoded-namespace-mutations");
    let source_path = root.child("source.bin");
    let target_path = root.child("target");
    std::fs::write(&source_path, b"namespace bytes").expect("seed source");
    std::fs::create_dir(&target_path).expect("seed target directory");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");

    let source_request = prepare_request(PrepareCase {
        op: 228,
        parent: provider.root_file_id(),
        name: "source.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let source = provider
        .prepare_open(&source_request, TransactionId { lo: 1228, hi: 0 })
        .expect("prepare source");
    provider
        .commit_open(&commit_request(
            &source_request,
            1228,
            5228,
            source.namespace_generation,
            source.security_generation,
        ))
        .expect("commit source");

    let target_request = prepare_request(PrepareCase {
        op: 229,
        parent: provider.root_file_id(),
        name: "target",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let target = provider
        .prepare_open(&target_request, TransactionId { lo: 1229, hi: 0 })
        .expect("prepare target");
    provider
        .commit_open(&commit_request(
            &target_request,
            1229,
            5229,
            target.namespace_generation,
            target.security_generation,
        ))
        .expect("commit target");

    let rename_bytes = rename_body(
        source.link_id,
        provider.root_file_id(),
        1,
        1,
        "SOURCE.BIN",
        false,
    );
    let rename_fixture = decoded_mutation(
        mutation_kind::RENAME,
        source.namespace_generation,
        0,
        0,
        &rename_bytes,
        false,
    );
    let context = provider
        .mutation_context(&rename_fixture.request)
        .expect("same-parent rename context");
    assert_eq!(
        context,
        MutationContext {
            same_parent_rename: true
        }
    );
    let rename_request = revalidate_context(
        rename_fixture.request,
        &rename_fixture.table,
        rename_fixture.owner,
        context,
    )
    .expect("revalidate same-parent rename");
    let rename_effect = provider
        .mutate_open(5228, &rename_request)
        .expect("rename source");
    assert_eq!(rename_effect.file_id, source.file_id);
    assert_eq!(
        rename_effect.source_parent_generation,
        rename_effect.target_parent_generation
    );
    assert_eq!(rename_effect.link_count, 1);
    let rename_result = build_mutation_result(
        &rename_request,
        &rename_effect,
        &rename_fixture.table,
        rename_fixture.owner,
    )
    .expect("build rename result");
    let rename_kind: RenameResultV2 =
        try_decode(&rename_result.kind_result).expect("decode rename kind result");
    assert_eq!(rename_kind.file_id, source.file_id);
    assert_eq!(rename_kind.link_id, source.link_id);
    assert_eq!(
        provider
            .query_info(5228)
            .expect("query renamed open")
            .namespace_generation,
        rename_effect.namespace_generation
    );
    assert!(root.child("SOURCE.BIN").exists());

    let unicode_bytes = rename_body(
        source.link_id,
        provider.root_file_id(),
        rename_effect.source_parent_generation,
        rename_effect.target_parent_generation,
        "Renamed-\u{732b}.bin",
        false,
    );
    let unicode_fixture = decoded_mutation(
        mutation_kind::RENAME,
        rename_effect.namespace_generation,
        0,
        0,
        &unicode_bytes,
        false,
    );
    let unicode_context = provider
        .mutation_context(&unicode_fixture.request)
        .expect("Unicode rename context");
    let unicode_request = revalidate_context(
        unicode_fixture.request,
        &unicode_fixture.table,
        unicode_fixture.owner,
        unicode_context,
    )
    .expect("revalidate Unicode rename");
    let rename_effect = provider
        .mutate_open(5228, &unicode_request)
        .expect("Unicode rename source");
    build_mutation_result(
        &unicode_request,
        &rename_effect,
        &unicode_fixture.table,
        unicode_fixture.owner,
    )
    .expect("build Unicode rename result");
    assert!(root.child("Renamed-\u{732b}.bin").exists());

    let link_bytes = link_body(
        source.file_id,
        target.file_id,
        target.namespace_generation,
        "alias.bin",
        false,
    );
    let link_fixture = decoded_mutation(
        mutation_kind::LINK,
        rename_effect.namespace_generation,
        0,
        0,
        &link_bytes,
        false,
    );
    assert_eq!(
        provider
            .mutation_context(&link_fixture.request)
            .expect("link context"),
        MutationContext {
            same_parent_rename: false
        }
    );
    let link_effect = provider
        .mutate_open(5228, &link_fixture.request)
        .expect("create hard link");
    assert_eq!(link_effect.file_id, source.file_id);
    assert_ne!(link_effect.new_link_id, LinkId::ZERO);
    assert_ne!(link_effect.new_link_id, source.link_id);
    assert_eq!(link_effect.link_count, 2);
    let link_result = build_mutation_result(
        &link_fixture.request,
        &link_effect,
        &link_fixture.table,
        link_fixture.owner,
    )
    .expect("build link result");
    let link_kind: LinkResultV2 =
        try_decode(&link_result.kind_result).expect("decode link kind result");
    assert_eq!(link_kind.new_link_id, link_effect.new_link_id);
    assert_eq!(
        std::fs::read(target_path.join("alias.bin")).expect("hard-link bytes"),
        b"namespace bytes"
    );

    let cross_bytes = rename_body(
        source.link_id,
        target.file_id,
        rename_effect.source_parent_generation,
        link_effect.target_parent_generation,
        "moved.bin",
        false,
    );
    let cross_fixture = decoded_mutation(
        mutation_kind::RENAME,
        link_effect.namespace_generation,
        0,
        0,
        &cross_bytes,
        false,
    );
    let cross_context = provider
        .mutation_context(&cross_fixture.request)
        .expect("cross-parent context");
    assert!(!cross_context.same_parent_rename);
    let cross_request = revalidate_context(
        cross_fixture.request,
        &cross_fixture.table,
        cross_fixture.owner,
        cross_context,
    )
    .expect("revalidate cross-parent rename");
    let cross_effect = provider
        .mutate_open(5228, &cross_request)
        .expect("cross-parent rename");
    assert_eq!(cross_effect.file_id, source.file_id);
    assert_ne!(
        cross_effect.source_parent_generation,
        cross_effect.target_parent_generation
    );
    build_mutation_result(
        &cross_request,
        &cross_effect,
        &cross_fixture.table,
        cross_fixture.owner,
    )
    .expect("build cross-parent result");
    assert_eq!(
        provider
            .query_info(5228)
            .expect("query cross-parent renamed open")
            .namespace_generation,
        cross_effect.namespace_generation
    );

    let unlink_bytes = unlink_body(
        link_effect.new_link_id,
        target.file_id,
        cross_effect.target_parent_generation,
    );
    let unlink_fixture = decoded_mutation(
        mutation_kind::UNLINK,
        cross_effect.namespace_generation,
        0,
        0,
        &unlink_bytes,
        false,
    );
    let unlink_effect = provider
        .mutate_open(5228, &unlink_fixture.request)
        .expect("unlink alias");
    assert_eq!(unlink_effect.file_id, source.file_id);
    assert_eq!(unlink_effect.link_count, 1);
    let unlink_result = build_mutation_result(
        &unlink_fixture.request,
        &unlink_effect,
        &unlink_fixture.table,
        unlink_fixture.owner,
    )
    .expect("build unlink result");
    let unlink_kind: UnlinkResultV1 =
        try_decode(&unlink_result.kind_result).expect("decode unlink kind result");
    assert_eq!(unlink_kind.removed_link_id, link_effect.new_link_id);
    assert!(!target_path.join("alias.bin").exists());
    assert_eq!(
        std::fs::read(target_path.join("moved.bin")).expect("retained source"),
        b"namespace bytes"
    );

    provider.cleanup_open(5228);
    provider.close_open(5228);
    provider.cleanup_open(5229);
    provider.close_open(5229);
}

#[test]
fn namespace_collisions_replacement_and_stale_requests_are_preeffect() {
    let root = TempRoot::new("namespace-replacement");
    std::fs::write(root.child("source.bin"), b"source").expect("seed source");
    std::fs::write(root.child("victim.bin"), b"victim").expect("seed victim");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");

    let source_request = prepare_request(PrepareCase {
        op: 230,
        parent: provider.root_file_id(),
        name: "source.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let source = provider
        .prepare_open(&source_request, TransactionId { lo: 1230, hi: 0 })
        .expect("prepare source");
    provider
        .commit_open(&commit_request(
            &source_request,
            1230,
            5230,
            source.namespace_generation,
            source.security_generation,
        ))
        .expect("commit source");
    let victim_request = prepare_request(PrepareCase {
        op: 231,
        parent: provider.root_file_id(),
        name: "victim.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let victim = provider
        .prepare_open(&victim_request, TransactionId { lo: 1231, hi: 0 })
        .expect("prepare victim");
    provider
        .commit_open(&commit_request(
            &victim_request,
            1231,
            5231,
            victim.namespace_generation,
            victim.security_generation,
        ))
        .expect("commit victim");

    let collision_body = rename_body(
        source.link_id,
        provider.root_file_id(),
        1,
        1,
        "victim.bin",
        false,
    );
    let collision = decoded_mutation(
        mutation_kind::RENAME,
        source.namespace_generation,
        0,
        0,
        &collision_body,
        false,
    );
    expect_status(
        provider.mutate_open(5230, &collision.request),
        completion_status::OBJECT_NAME_COLLISION,
    );
    assert_eq!(std::fs::read(root.child("source.bin")).unwrap(), b"source");
    assert_eq!(std::fs::read(root.child("victim.bin")).unwrap(), b"victim");

    let stale = decoded_mutation(
        mutation_kind::RENAME,
        source.namespace_generation + 1,
        0,
        0,
        &rename_body(
            source.link_id,
            provider.root_file_id(),
            1,
            1,
            "stale.bin",
            false,
        ),
        false,
    );
    expect_status(
        provider.mutate_open(5230, &stale.request),
        completion_status::RETRY,
    );
    assert!(!root.child("stale.bin").exists());

    provider.cleanup_open(5231);
    provider.close_open(5231);
    let replace_body = rename_body(
        source.link_id,
        provider.root_file_id(),
        1,
        1,
        "victim.bin",
        true,
    );
    let replace_fixture = decoded_mutation(
        mutation_kind::RENAME,
        source.namespace_generation,
        0,
        0,
        &replace_body,
        false,
    );
    let context = provider
        .mutation_context(&replace_fixture.request)
        .expect("replacement context");
    let replace_request = revalidate_context(
        replace_fixture.request,
        &replace_fixture.table,
        replace_fixture.owner,
        context,
    )
    .expect("revalidate replacement");
    let replaced = provider
        .mutate_open(5230, &replace_request)
        .expect("replace rename");
    let replaced_tuple = replaced.replaced.expect("replacement tuple");
    assert_eq!(replaced_tuple.file_id, victim.file_id);
    assert_eq!(replaced_tuple.link_id, victim.link_id);
    assert_eq!(replaced_tuple.link_count, 0);
    build_mutation_result(
        &replace_request,
        &replaced,
        &replace_fixture.table,
        replace_fixture.owner,
    )
    .expect("build replacement result");
    assert_eq!(std::fs::read(root.child("victim.bin")).unwrap(), b"source");
    assert!(!root.child("source.bin").exists());

    let create_alias = decoded_mutation(
        mutation_kind::LINK,
        replaced.namespace_generation,
        0,
        0,
        &link_body(
            source.file_id,
            provider.root_file_id(),
            replaced.target_parent_generation,
            "alias.bin",
            false,
        ),
        false,
    );
    let alias_effect = provider
        .mutate_open(5230, &create_alias.request)
        .expect("create alias");
    assert_eq!(alias_effect.link_count, 2);

    let stale_parent = decoded_mutation(
        mutation_kind::LINK,
        alias_effect.namespace_generation,
        0,
        0,
        &link_body(
            source.file_id,
            provider.root_file_id(),
            alias_effect.target_parent_generation + 1,
            "never.bin",
            false,
        ),
        false,
    );
    expect_status(
        provider.mutate_open(5230, &stale_parent.request),
        completion_status::RETRY,
    );
    assert!(!root.child("never.bin").exists());

    let same_file_replace = decoded_mutation(
        mutation_kind::LINK,
        alias_effect.namespace_generation,
        0,
        0,
        &link_body(
            source.file_id,
            provider.root_file_id(),
            alias_effect.target_parent_generation,
            "alias.bin",
            true,
        ),
        false,
    );
    let same_file_effect = provider
        .mutate_open(5230, &same_file_replace.request)
        .expect("replace same-file alias");
    let alias_replaced = same_file_effect.replaced.expect("same-file tuple");
    assert_eq!(alias_replaced.file_id, source.file_id);
    assert_eq!(alias_replaced.link_id, alias_effect.new_link_id);
    assert_eq!(
        alias_replaced.namespace_generation,
        same_file_effect.namespace_generation
    );
    assert_eq!(alias_replaced.link_count, same_file_effect.link_count);
    assert_ne!(same_file_effect.new_link_id, alias_effect.new_link_id);
    build_mutation_result(
        &same_file_replace.request,
        &same_file_effect,
        &same_file_replace.table,
        same_file_replace.owner,
    )
    .expect("build same-file replacement result");

    provider.cleanup_open(5230);
    provider.close_open(5230);
}

#[test]
fn rename_replace_reconciles_an_unseen_native_target() {
    let root = TempRoot::new("rename-unseen-replacement");
    std::fs::write(root.child("source.bin"), b"source").expect("seed source");
    std::fs::write(root.child("unseen.bin"), b"unseen").expect("seed unseen target");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let source_request = prepare_request(PrepareCase {
        op: 236,
        parent: provider.root_file_id(),
        name: "source.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let source = provider
        .prepare_open(&source_request, TransactionId { lo: 1236, hi: 0 })
        .expect("prepare only source");
    let committed = provider
        .commit_open(&commit_request(
            &source_request,
            1236,
            5236,
            source.namespace_generation,
            source.security_generation,
        ))
        .expect("commit only source");

    let fixture = decoded_mutation(
        mutation_kind::RENAME,
        source.namespace_generation,
        0,
        0,
        &rename_body(
            source.link_id,
            provider.root_file_id(),
            1,
            1,
            "unseen.bin",
            true,
        ),
        false,
    );
    let context = provider
        .mutation_context(&fixture.request)
        .expect("replacement context");
    let request = revalidate_context(fixture.request, &fixture.table, fixture.owner, context)
        .expect("revalidate replacement");
    let effect = provider
        .mutate_open(5236, &request)
        .expect("replace unseen target");
    assert_eq!(
        effect.volume_commit_sequence,
        committed.volume_commit_sequence + 1
    );
    let replaced = effect.replaced.expect("unseen replacement tuple");
    assert_ne!(replaced.file_id, FileId::ZERO);
    assert_ne!(replaced.file_id, source.file_id);
    assert_ne!(replaced.link_id, LinkId::ZERO);
    assert_eq!(replaced.link_count, 0);
    build_mutation_result(&request, &effect, &fixture.table, fixture.owner)
        .expect("build unseen rename replacement");
    assert_eq!(std::fs::read(root.child("unseen.bin")).unwrap(), b"source");
    assert!(!root.child("source.bin").exists());

    provider.cleanup_open(5236);
    provider.close_open(5236);
}

#[test]
fn link_replace_reconciles_an_unseen_native_target() {
    let root = TempRoot::new("link-unseen-replacement");
    std::fs::write(root.child("source.bin"), b"source").expect("seed source");
    std::fs::write(root.child("unseen.bin"), b"unseen").expect("seed unseen target");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let source_request = prepare_request(PrepareCase {
        op: 237,
        parent: provider.root_file_id(),
        name: "source.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let source = provider
        .prepare_open(&source_request, TransactionId { lo: 1237, hi: 0 })
        .expect("prepare only source");
    let committed = provider
        .commit_open(&commit_request(
            &source_request,
            1237,
            5237,
            source.namespace_generation,
            source.security_generation,
        ))
        .expect("commit only source");

    let fixture = decoded_mutation(
        mutation_kind::LINK,
        source.namespace_generation,
        0,
        0,
        &link_body(
            source.file_id,
            provider.root_file_id(),
            1,
            "unseen.bin",
            true,
        ),
        false,
    );
    let effect = provider
        .mutate_open(5237, &fixture.request)
        .expect("replace unseen target with hard link");
    assert_eq!(
        effect.volume_commit_sequence,
        committed.volume_commit_sequence + 1
    );
    let replaced = effect.replaced.expect("unseen replacement tuple");
    assert_ne!(replaced.file_id, FileId::ZERO);
    assert_ne!(replaced.file_id, source.file_id);
    assert_ne!(replaced.link_id, LinkId::ZERO);
    assert_eq!(replaced.link_count, 0);
    assert_eq!(effect.link_count, 2);
    build_mutation_result(&fixture.request, &effect, &fixture.table, fixture.owner)
        .expect("build unseen link replacement");
    assert_eq!(std::fs::read(root.child("unseen.bin")).unwrap(), b"source");

    provider.cleanup_open(5237);
    provider.close_open(5237);
}

#[test]
fn link_replace_reconciles_an_unseen_same_native_alias() {
    let root = TempRoot::new("link-unseen-same-native");
    std::fs::write(root.child("source.bin"), b"source").expect("seed source");
    std::fs::hard_link(root.child("source.bin"), root.child("unseen-alias.bin"))
        .expect("seed unseen same-native alias");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let source_request = prepare_request(PrepareCase {
        op: 238,
        parent: provider.root_file_id(),
        name: "source.bin",
        disposition: FILE_OPEN,
        create_options: FILE_NON_DIRECTORY_FILE,
        attributes: file_attributes::NORMAL,
        share_access: all_shares(),
    });
    let source = provider
        .prepare_open(&source_request, TransactionId { lo: 1238, hi: 0 })
        .expect("prepare only source");
    let committed = provider
        .commit_open(&commit_request(
            &source_request,
            1238,
            5238,
            source.namespace_generation,
            source.security_generation,
        ))
        .expect("commit only source");
    let fixture = decoded_mutation(
        mutation_kind::LINK,
        source.namespace_generation,
        0,
        0,
        &link_body(
            source.file_id,
            provider.root_file_id(),
            1,
            "unseen-alias.bin",
            true,
        ),
        false,
    );
    let effect = provider
        .mutate_open(5238, &fixture.request)
        .expect("replace unseen same-native alias");
    assert_eq!(
        effect.volume_commit_sequence,
        committed.volume_commit_sequence + 1
    );
    let replaced = effect.replaced.expect("same-native replacement tuple");
    assert_eq!(replaced.file_id, source.file_id);
    assert_eq!(replaced.namespace_generation, effect.namespace_generation);
    assert_eq!(replaced.link_count, effect.link_count);
    assert_eq!(effect.link_count, 2);
    assert_ne!(replaced.link_id, effect.new_link_id);
    build_mutation_result(&fixture.request, &effect, &fixture.table, fixture.owner)
        .expect("build unseen same-native replacement");

    provider.cleanup_open(5238);
    provider.close_open(5238);
}

#[test]
fn directory_rename_rebases_live_descendant_opens_and_nonempty_unlink_is_clean() {
    let root = TempRoot::new("directory-rename-rebase");
    let tree = root.child("tree");
    std::fs::create_dir(&tree).expect("seed tree");
    std::fs::write(tree.join("child.bin"), b"child bytes").expect("seed child");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");

    let tree_request = prepare_request(PrepareCase {
        op: 232,
        parent: provider.root_file_id(),
        name: "tree",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let tree_open = provider
        .prepare_open(&tree_request, TransactionId { lo: 1232, hi: 0 })
        .expect("prepare tree");
    provider
        .commit_open(&commit_request(
            &tree_request,
            1232,
            5232,
            tree_open.namespace_generation,
            tree_open.security_generation,
        ))
        .expect("commit tree");
    let child_request = prepare_request_with_access(
        PrepareCase {
            op: 233,
            parent: tree_open.file_id,
            name: "child.bin",
            disposition: FILE_OPEN,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        },
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
    );
    let child_open = provider
        .prepare_open(&child_request, TransactionId { lo: 1233, hi: 0 })
        .expect("prepare child");
    provider
        .commit_open(&commit_request_with_access(
            &child_request,
            1233,
            5233,
            child_open.namespace_generation,
            child_open.security_generation,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        ))
        .expect("commit child");
    let rename_fixture = decoded_mutation(
        mutation_kind::RENAME,
        tree_open.namespace_generation,
        0,
        0,
        &rename_body(
            tree_open.link_id,
            provider.root_file_id(),
            1,
            1,
            "moved-tree",
            false,
        ),
        false,
    );
    let context = provider
        .mutation_context(&rename_fixture.request)
        .expect("directory rename context");
    let rename_request = revalidate_context(
        rename_fixture.request,
        &rename_fixture.table,
        rename_fixture.owner,
        context,
    )
    .expect("revalidate directory rename");
    let effect = provider
        .mutate_open(5232, &rename_request)
        .expect("rename directory");
    assert!(root.child("moved-tree").join("child.bin").exists());
    assert_eq!(
        provider
            .query_dir(5232)
            .expect("query renamed directory")
            .len(),
        1
    );
    let descriptor = provider
        .query_security(
            5233,
            security_information::OWNER | security_information::GROUP | security_information::DACL,
        )
        .expect("query security through rebased child path");
    assert!(descriptor.len() >= 20);
    let mut bytes = [0; 16];
    assert_eq!(
        provider
            .read(5233, 0, &mut bytes)
            .expect("read through retained child handle"),
        b"child bytes".len()
    );

    let nonempty = decoded_mutation(
        mutation_kind::UNLINK,
        effect.namespace_generation,
        0,
        0,
        &unlink_body(
            tree_open.link_id,
            provider.root_file_id(),
            effect.target_parent_generation,
        ),
        false,
    );
    expect_status(
        provider.mutate_open(5232, &nonempty.request),
        completion_status::DIRECTORY_NOT_EMPTY,
    );
    assert!(root.child("moved-tree").join("child.bin").exists());
    assert_eq!(
        provider
            .query_info(5232)
            .expect("directory generation unchanged")
            .namespace_generation,
        effect.namespace_generation
    );

    provider.cleanup_open(5233);
    provider.close_open(5233);
    provider.cleanup_open(5232);
    provider.close_open(5232);
}

#[test]
fn full_direct_provider_flow_preserves_every_identity_and_generation_lane() {
    let root = TempRoot::new("full-direct-provider-flow");
    let owned_root = root.path().to_path_buf();
    let directory_path = root.child("stateful");
    let original_path = directory_path.join("stream.bin");
    let renamed_path = directory_path.join("renamed.bin");
    let alias_path = directory_path.join("alias.bin");
    assert_eq!(owned_root.parent(), Some(std::path::Path::new(r"D:\temp")));
    for path in [&directory_path, &original_path, &renamed_path, &alias_path] {
        assert!(
            path.starts_with(&owned_root),
            "every backing object must remain below the owned test root"
        );
    }

    std::fs::create_dir(&directory_path).expect("seed stateful directory");
    std::fs::write(&original_path, b"wave-2-seed").expect("seed stateful stream");
    grant_current_user_full_control(&original_path);
    let mut provider = MirrorFs::open(root.path()).expect("open stateful provider");

    // Retain the parent directory before the measured chain so QUERY_DIR can
    // observe the same file/link identity without inserting another OPEN.
    let directory_request = prepare_request(PrepareCase {
        op: 240,
        parent: provider.root_file_id(),
        name: "stateful",
        disposition: FILE_OPEN,
        create_options: FILE_DIRECTORY_FILE,
        attributes: file_attributes::DIRECTORY,
        share_access: all_shares(),
    });
    let directory_prepared = provider
        .prepare_open(&directory_request, TransactionId { lo: 1240, hi: 0 })
        .expect("prepare parent directory");
    assert_ne!(directory_prepared.file_id, FileId::ZERO);
    assert_ne!(directory_prepared.link_id, LinkId::ZERO);
    let directory_committed = provider
        .commit_open(&commit_request(
            &directory_request,
            1240,
            5240,
            directory_prepared.namespace_generation,
            directory_prepared.security_generation,
        ))
        .expect("commit parent directory");
    assert_eq!(directory_committed.volume_commit_sequence, 1);

    let access = FILE_GENERIC_READ
        | FILE_GENERIC_WRITE
        | FILE_WRITE_ATTRIBUTES
        | READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | DELETE;

    // PREPARE.
    let file_request = prepare_request_with_access(
        PrepareCase {
            op: 241,
            parent: directory_prepared.file_id,
            name: "stream.bin",
            disposition: FILE_OPEN,
            create_options: FILE_NON_DIRECTORY_FILE,
            attributes: file_attributes::NORMAL,
            share_access: all_shares(),
        },
        access,
    );
    let prepared = provider
        .prepare_open(&file_request, TransactionId { lo: 1241, hi: 0 })
        .expect("prepare stateful stream");
    assert_ne!(prepared.file_id, FileId::ZERO);
    assert_ne!(prepared.link_id, LinkId::ZERO);
    assert_ne!(prepared.file_id, directory_prepared.file_id);
    assert_ne!(prepared.link_id, directory_prepared.link_id);
    assert_ne!(prepared.namespace_generation, 0);
    assert_ne!(prepared.security_generation, 0);
    assert_ne!(prepared.sizes.size_epoch, 0);
    assert_eq!(prepared.sizes.file_size, 11);
    assert_eq!(prepared.sizes.valid_data_length, 11);

    // COMMIT.
    let committed = provider
        .commit_open(&commit_request_with_access(
            &file_request,
            1241,
            5241,
            prepared.namespace_generation,
            prepared.security_generation,
            access,
        ))
        .expect("commit stateful stream");
    assert_eq!(committed.file_id, prepared.file_id);
    assert_eq!(committed.link_id, prepared.link_id);
    assert_eq!(
        committed.volume_commit_sequence,
        directory_committed.volume_commit_sequence + 1
    );
    let mut expected_sequence = committed.volume_commit_sequence;

    // WRITE.
    let written = provider
        .write(
            5241,
            committed.sizes.file_size,
            committed.sizes.size_epoch,
            b"-written",
        )
        .expect("grow stateful stream");
    expected_sequence += 1;
    assert_eq!(written.information, 8);
    assert_eq!(written.effect.volume_commit_sequence, expected_sequence);
    assert_eq!(written.effect.sizes.file_size, 19);
    assert_eq!(written.effect.sizes.valid_data_length, 19);
    assert!(written.effect.sizes.size_epoch > committed.sizes.size_epoch);

    // FLUSH.
    provider.flush(5241).expect("flush stateful stream");

    // READ.
    let mut read_back = [0_u8; 19];
    assert_eq!(
        provider
            .read(5241, 0, &mut read_back)
            .expect("read stateful stream"),
        read_back.len()
    );
    assert_eq!(&read_back, b"wave-2-seed-written");
    assert_eq!(std::fs::read(&original_path).unwrap(), read_back);

    // QUERY_INFO.
    let queried = provider.query_info(5241).expect("query stateful info");
    assert_eq!(queried.link_count, 1);
    assert_eq!(queried.namespace_generation, prepared.namespace_generation);
    assert_eq!(queried.security_generation, prepared.security_generation);
    assert_eq!(
        size_state_tuple(queried.sizes),
        size_state_tuple(written.effect.sizes)
    );
    build_file_info(&queried).expect("stateful file info builds");

    // QUERY_DIR.
    let candidates = provider.query_dir(5240).expect("enumerate stateful parent");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidate_name(&candidates[0]), "stream.bin");
    assert_eq!(candidates[0].fields.file_id, prepared.file_id);
    assert_eq!(candidates[0].fields.link_id, prepared.link_id);
    assert_ne!(
        candidates[0].fields.namespace_generation, queried.namespace_generation,
        "the per-link namespace generation is independent from the file lane"
    );
    assert!(candidates[0].fields.namespace_generation > queried.namespace_generation);
    assert_eq!(
        size_state_tuple(candidates[0].fields.sizes),
        size_state_tuple(queried.sizes)
    );
    let parent_before_rename = provider
        .query_info(5240)
        .expect("query parent generation after enumeration");

    // QUERY_VOLUME.
    let volume = provider.query_volume().expect("query stateful volume");
    assert!(volume.total_allocation_units > 0);
    assert!(volume.available_allocation_units <= volume.total_allocation_units);
    assert!(volume.sectors_per_allocation_unit.is_power_of_two());
    assert!(volume.bytes_per_sector.is_power_of_two());
    build_volume_size_info(&volume).expect("stateful volume info builds");

    // QUERY_SECURITY.
    let information =
        security_information::OWNER | security_information::GROUP | security_information::DACL;
    let descriptor = provider
        .query_security(5241, information)
        .expect("query stateful security");
    assert!((20..=65_536).contains(&descriptor.len()));
    assert_eq!(descriptor[0], 1);
    assert_ne!(
        u16::from_le_bytes([descriptor[2], descriptor[3]]) & 0x8000,
        0,
        "security descriptor must be self-relative"
    );
    let target_descriptor = provider
        .query_security(5240, information)
        .expect("query distinct parent security target");
    assert!((20..=65_536).contains(&target_descriptor.len()));
    assert_ne!(
        normalized_native_security_descriptor(&descriptor),
        normalized_native_security_descriptor(&target_descriptor),
        "the SET_SECURITY target must differ from the stream's native pre-effect descriptor"
    );

    // SET_BASIC_INFO.
    let basic = basic_info_body(
        basic_info_set_mask::FILE_ATTRIBUTES,
        0,
        0,
        0,
        0,
        file_attributes::HIDDEN,
    );
    let basic_effect = provider
        .set_basic_info(5241, queried.namespace_generation, &basic)
        .expect("set one stateful basic-info field");
    expected_sequence += 1;
    assert_eq!(basic_effect.file_id, prepared.file_id);
    assert_eq!(basic_effect.volume_commit_sequence, expected_sequence);
    assert!(basic_effect.namespace_generation > queried.namespace_generation);
    assert_eq!(basic_effect.security_generation, 0);
    assert_eq!(
        size_state_tuple(basic_effect.sizes),
        size_state_tuple(queried.sizes)
    );
    let after_basic = provider
        .query_info(5241)
        .expect("query state after basic info");
    assert_ne!(after_basic.attributes & file_attributes::HIDDEN, 0);
    assert_eq!(
        after_basic.namespace_generation,
        basic_effect.namespace_generation
    );
    assert_eq!(after_basic.security_generation, queried.security_generation);
    assert_eq!(
        size_state_tuple(after_basic.sizes),
        size_state_tuple(queried.sizes)
    );

    // SET_SIZE.
    let size_effect = provider
        .set_end_of_file(5241, after_basic.sizes.size_epoch, 12)
        .expect("shrink stateful EOF");
    expected_sequence += 1;
    assert_eq!(size_effect.file_id, prepared.file_id);
    assert_eq!(size_effect.volume_commit_sequence, expected_sequence);
    assert_eq!(size_effect.namespace_generation, 0);
    assert_eq!(size_effect.security_generation, 0);
    assert_eq!(size_effect.sizes.file_size, 12);
    assert_eq!(size_effect.sizes.valid_data_length, 12);
    assert!(size_effect.sizes.size_epoch > after_basic.sizes.size_epoch);
    assert_eq!(std::fs::read(&original_path).unwrap(), b"wave-2-seed-");
    let after_size = provider.query_info(5241).expect("query state after size");
    assert_eq!(
        after_size.namespace_generation,
        after_basic.namespace_generation
    );
    assert_eq!(
        after_size.security_generation,
        after_basic.security_generation
    );
    assert_eq!(
        size_state_tuple(after_size.sizes),
        size_state_tuple(size_effect.sizes)
    );

    // RENAME.
    let rename_fixture = decoded_mutation(
        mutation_kind::RENAME,
        after_size.namespace_generation,
        0,
        0,
        &rename_body(
            prepared.link_id,
            directory_prepared.file_id,
            parent_before_rename.namespace_generation,
            parent_before_rename.namespace_generation,
            "renamed.bin",
            false,
        ),
        false,
    );
    let rename_context = provider
        .mutation_context(&rename_fixture.request)
        .expect("resolve stateful rename context");
    assert!(rename_context.same_parent_rename);
    let rename_request = revalidate_context(
        rename_fixture.request,
        &rename_fixture.table,
        rename_fixture.owner,
        rename_context,
    )
    .expect("revalidate stateful rename");
    let rename_effect = provider
        .mutate_open(5241, &rename_request)
        .expect("rename stateful stream");
    expected_sequence += 1;
    assert_eq!(rename_effect.file_id, prepared.file_id);
    assert_eq!(rename_effect.new_link_id, LinkId::ZERO);
    assert_eq!(rename_effect.link_count, 1);
    assert_eq!(
        rename_effect.source_parent_generation,
        rename_effect.target_parent_generation
    );
    assert_eq!(rename_effect.volume_commit_sequence, expected_sequence);
    assert!(rename_effect.namespace_generation > after_size.namespace_generation);
    assert_eq!(
        size_state_tuple(rename_effect.sizes),
        size_state_tuple(after_size.sizes)
    );
    let rename_result = build_mutation_result(
        &rename_request,
        &rename_effect,
        &rename_fixture.table,
        rename_fixture.owner,
    )
    .expect("build stateful rename result");
    let rename_kind: RenameResultV2 =
        try_decode(&rename_result.kind_result).expect("decode stateful rename result");
    assert_eq!(rename_kind.file_id, prepared.file_id);
    assert_eq!(rename_kind.link_id, prepared.link_id);
    assert!(!original_path.exists());
    assert_eq!(std::fs::read(&renamed_path).unwrap(), b"wave-2-seed-");
    let entries_after_rename = provider
        .query_dir(5240)
        .expect("re-observe native directory after rename");
    assert_eq!(entries_after_rename.len(), 1);
    assert_eq!(candidate_name(&entries_after_rename[0]), "renamed.bin");
    assert_eq!(entries_after_rename[0].fields.file_id, prepared.file_id);
    assert_eq!(entries_after_rename[0].fields.link_id, prepared.link_id);
    let after_rename = provider.query_info(5241).expect("query renamed identity");
    assert_eq!(after_rename.link_count, 1);
    assert_eq!(
        after_rename.namespace_generation,
        rename_effect.namespace_generation
    );
    assert_eq!(
        after_rename.security_generation,
        after_size.security_generation
    );
    assert_eq!(
        size_state_tuple(after_rename.sizes),
        size_state_tuple(after_size.sizes)
    );

    // LINK.
    let link_fixture = decoded_mutation(
        mutation_kind::LINK,
        after_rename.namespace_generation,
        0,
        0,
        &link_body(
            prepared.file_id,
            directory_prepared.file_id,
            rename_effect.target_parent_generation,
            "alias.bin",
            false,
        ),
        false,
    );
    let link_effect = provider
        .mutate_open(5241, &link_fixture.request)
        .expect("link stateful stream");
    expected_sequence += 1;
    assert_eq!(link_effect.file_id, prepared.file_id);
    assert_ne!(link_effect.new_link_id, LinkId::ZERO);
    assert_ne!(link_effect.new_link_id, prepared.link_id);
    assert_eq!(link_effect.link_count, 2);
    assert_eq!(link_effect.volume_commit_sequence, expected_sequence);
    assert!(link_effect.namespace_generation > after_rename.namespace_generation);
    assert_eq!(
        size_state_tuple(link_effect.sizes),
        size_state_tuple(after_rename.sizes)
    );
    let link_result = build_mutation_result(
        &link_fixture.request,
        &link_effect,
        &link_fixture.table,
        link_fixture.owner,
    )
    .expect("build stateful link result");
    let link_kind: LinkResultV2 =
        try_decode(&link_result.kind_result).expect("decode stateful link result");
    assert_eq!(link_kind.new_link_id, link_effect.new_link_id);
    assert_eq!(std::fs::read(&alias_path).unwrap(), b"wave-2-seed-");
    assert_eq!(std::fs::read(&renamed_path).unwrap(), b"wave-2-seed-");
    let entries_after_link = provider
        .query_dir(5240)
        .expect("re-observe native directory after hard link");
    assert_eq!(entries_after_link.len(), 2);
    let renamed_entry = entries_after_link
        .iter()
        .find(|entry| candidate_name(entry) == "renamed.bin")
        .expect("renamed binding remains after hard link");
    let alias_entry = entries_after_link
        .iter()
        .find(|entry| candidate_name(entry) == "alias.bin")
        .expect("new alias is natively discoverable");
    assert_eq!(renamed_entry.fields.file_id, prepared.file_id);
    assert_eq!(alias_entry.fields.file_id, prepared.file_id);
    assert_eq!(renamed_entry.fields.file_id, alias_entry.fields.file_id);
    assert_eq!(renamed_entry.fields.link_id, prepared.link_id);
    assert_eq!(alias_entry.fields.link_id, link_effect.new_link_id);
    assert_ne!(renamed_entry.fields.link_id, alias_entry.fields.link_id);
    let after_link_info = provider
        .query_info(5241)
        .expect("query native link count after hard link");
    assert_eq!(after_link_info.link_count, 2);
    assert_eq!(
        after_link_info.namespace_generation,
        link_effect.namespace_generation
    );
    assert_eq!(
        after_link_info.security_generation,
        after_rename.security_generation
    );
    assert_eq!(
        size_state_tuple(after_link_info.sizes),
        size_state_tuple(after_rename.sizes)
    );

    // UNLINK.
    let unlink_fixture = decoded_mutation(
        mutation_kind::UNLINK,
        link_effect.namespace_generation,
        0,
        0,
        &unlink_body(
            link_effect.new_link_id,
            directory_prepared.file_id,
            link_effect.target_parent_generation,
        ),
        false,
    );
    let unlink_effect = provider
        .mutate_open(5241, &unlink_fixture.request)
        .expect("unlink stateful alias");
    expected_sequence += 1;
    assert_eq!(unlink_effect.file_id, prepared.file_id);
    assert_eq!(unlink_effect.link_count, 1);
    assert_eq!(unlink_effect.volume_commit_sequence, expected_sequence);
    assert!(unlink_effect.namespace_generation > link_effect.namespace_generation);
    assert_eq!(
        size_state_tuple(unlink_effect.sizes),
        size_state_tuple(link_effect.sizes)
    );
    let unlink_result = build_mutation_result(
        &unlink_fixture.request,
        &unlink_effect,
        &unlink_fixture.table,
        unlink_fixture.owner,
    )
    .expect("build stateful unlink result");
    let unlink_kind: UnlinkResultV1 =
        try_decode(&unlink_result.kind_result).expect("decode stateful unlink result");
    assert_eq!(unlink_kind.removed_link_id, link_effect.new_link_id);
    assert!(!alias_path.exists());
    assert_eq!(std::fs::read(&renamed_path).unwrap(), b"wave-2-seed-");
    let entries_after_unlink = provider
        .query_dir(5240)
        .expect("re-observe native directory after unlink");
    assert_eq!(entries_after_unlink.len(), 1);
    assert_eq!(candidate_name(&entries_after_unlink[0]), "renamed.bin");
    assert_eq!(entries_after_unlink[0].fields.file_id, prepared.file_id);
    assert_eq!(entries_after_unlink[0].fields.link_id, prepared.link_id);

    // SET_SECURITY.
    let before_security = provider
        .query_info(5241)
        .expect("query state before security");
    assert_eq!(
        before_security.namespace_generation,
        unlink_effect.namespace_generation
    );
    assert_eq!(before_security.link_count, 1);
    assert_eq!(
        before_security.security_generation,
        prepared.security_generation
    );
    let security_effect = provider
        .set_security(
            5241,
            before_security.security_generation,
            information,
            &target_descriptor,
        )
        .expect("set distinct parent owner/group/DACL");
    expected_sequence += 1;
    assert_eq!(security_effect.file_id, prepared.file_id);
    assert_eq!(security_effect.link_count, 1);
    assert_eq!(security_effect.namespace_generation, 0);
    assert!(security_effect.security_generation > before_security.security_generation);
    assert_eq!(security_effect.volume_commit_sequence, expected_sequence);
    assert_eq!(
        size_state_tuple(security_effect.sizes),
        size_state_tuple(before_security.sizes)
    );
    let round_trip = provider
        .query_security(5241, information)
        .expect("query stateful applied security");
    assert_eq!(
        normalized_native_security_descriptor(&round_trip),
        normalized_native_security_descriptor(&target_descriptor)
    );
    assert_ne!(
        normalized_native_security_descriptor(&round_trip),
        normalized_native_security_descriptor(&descriptor),
        "native security must change from the pre-effect descriptor"
    );
    let final_info = provider.query_info(5241).expect("query final state");
    assert_eq!(final_info.link_count, 1);
    assert_eq!(
        final_info.namespace_generation,
        before_security.namespace_generation
    );
    assert_eq!(
        final_info.security_generation,
        security_effect.security_generation
    );
    assert_eq!(
        size_state_tuple(final_info.sizes),
        size_state_tuple(before_security.sizes)
    );

    // CLEANUP then CLOSE.
    provider.cleanup_open(5241);
    provider.close_open(5241);
    provider.cleanup_open(5240);
    provider.close_open(5240);
    drop(provider);

    assert!(!original_path.exists());
    assert!(!alias_path.exists());
    assert_eq!(std::fs::read(&renamed_path).unwrap(), b"wave-2-seed-");
    std::fs::remove_file(&renamed_path).expect("remove final owned stream");
    std::fs::remove_dir(&directory_path).expect("remove final owned directory");
    assert!(
        std::fs::read_dir(&owned_root)
            .expect("read cleaned owned root")
            .next()
            .is_none(),
        "the stateful scenario must leave no object in its owned root"
    );
    drop(root);
    assert!(
        !owned_root.exists(),
        "TempRoot cleanup must remove the unique owned root itself"
    );
}
