#![cfg(windows)]

#[allow(dead_code)]
mod support;

use std::os::windows::fs::MetadataExt;

use fsring_abi::codec::try_decode;
use fsring_abi::ids::{FileId, OpId, TransactionId};
use fsring_abi::layout::{op, CqeBody, SqeBody, SQE_PAYLOAD_LEN};
use fsring_abi::msgs::{
    basic_info_set_mask, create_result, file_attributes, mutation_kind, security_information,
    BufferRef, CommitOpenResultV2, FileInfoV1, LinkResultV2, MutationResultV2, OControl,
    PrepareOpenResultV1, QueryDirResultV1, RenameResultV2, SizeState, UnlinkResultV1,
    VolumeSizeInfoV1, WriteResultV2, CONTROL_VERSION_V1, CONTROL_VERSION_V2,
};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    completion_status, validate_completion_output_v21, CompletionOutputContextV21,
};
use fsring_user::testkit::{
    CommitFixture, Harness, MutationFixture, PrepareFixture, ProviderMutation, QueryDirFixture,
    QueryInfoFixture, QuerySecurityFixture, QueryVolumeFixture, ReadFixture, WriteFixture,
};
use fsring_user::{
    decode_commit, decode_mutation, decode_prepare, decode_query_dir, decode_query_info,
    decode_query_security, decode_query_volume, decode_read, decode_write, resolve_body, Daemon,
    FileSystem, GrantTable, MutationRequest, PrepareResult, PreparedRequest,
};
use mirrorfs::MirrorFs;

use support::TempRoot;

const FILE_OPEN: u32 = 1;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_GENERIC_READ: u32 = 0x0012_0089;
const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const ALL_SHARES: u32 = 0x7;
const OPEN_ACCESS: u32 = FILE_GENERIC_READ
    | FILE_GENERIC_WRITE
    | READ_CONTROL
    | WRITE_DAC
    | FILE_WRITE_ATTRIBUTES
    | DELETE;

struct DirectOpen {
    prepared_request: PreparedRequest,
    prepared: PrepareResult,
    committed: fsring_user::CommitEffect,
    transaction_id: TransactionId,
    kernel_open_id: u64,
}

fn direct_open(
    provider: &mut MirrorFs,
    parent_id: FileId,
    name: &str,
    directory: bool,
    sequence: u64,
    kernel_open_id: u64,
) -> DirectOpen {
    let op_id = OpId {
        lo: sequence,
        hi: 0xE2,
    };
    let prepare = PrepareFixture::provider(
        parent_id,
        name,
        op_id,
        OPEN_ACCESS,
        ALL_SHARES,
        FILE_OPEN,
        if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        },
        if directory {
            file_attributes::DIRECTORY
        } else {
            file_attributes::NORMAL
        },
        0,
    );
    let prepared_request = decode_prepare(
        &prepare.sqe,
        &prepare.table,
        prepare.section(),
        prepare.owner,
    )
    .expect("provider PREPARE fixture decodes");
    let transaction_id = TransactionId {
        lo: 0x1000 + sequence,
        hi: 0,
    };
    let prepared = FileSystem::prepare(provider, &prepared_request, transaction_id)
        .expect("direct setup PREPARE");

    let commit = CommitFixture::provider(
        op_id,
        transaction_id,
        kernel_open_id,
        prepared.namespace_generation,
        prepared.security_generation,
        OPEN_ACCESS,
    );
    let request = decode_commit(&commit.sqe, &commit.table, commit.section(), commit.owner)
        .expect("provider COMMIT fixture decodes");
    let committed = FileSystem::commit(provider, &request).expect("direct setup COMMIT");
    DirectOpen {
        prepared_request,
        prepared,
        committed,
        transaction_id,
        kernel_open_id,
    }
}

fn read_grant(
    harness: &Harness,
    table: &GrantTable,
    owner: GrantOwner,
    grant: BufferRef,
    length: u32,
) -> Vec<u8> {
    let shrunk = BufferRef {
        token: grant.token,
        offset: 0,
        length,
        kind: grant.kind,
        access: grant.access,
        reserved: 0,
    };
    let validated = table
        .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
        .expect("resolve exact output prefix");
    resolve_body(harness.section(), &validated)
        .expect("read output grant")
        .as_slice()
        .to_vec()
}

fn assert_size_state(actual: SizeState, expected: SizeState) {
    assert_eq!(actual.allocation_size, expected.allocation_size);
    assert_eq!(actual.file_size, expected.file_size);
    assert_eq!(actual.valid_data_length, expected.valid_data_length);
    assert_eq!(actual.size_epoch, expected.size_epoch);
}

fn prepare_result_from_wire(wire: &PrepareOpenResultV1, descriptor: Vec<u8>) -> PrepareResult {
    PrepareResult {
        file_id: wire.file_id,
        link_id: wire.link_id,
        sizes: wire.sizes,
        namespace_generation: wire.namespace_generation,
        security_generation: wire.security_generation,
        security_descriptor: descriptor.into_boxed_slice(),
        object_flags: wire.object_flags,
    }
}

fn assert_cqe(cqe: &CqeBody, opcode: u16, status: i32, context: CompletionOutputContextV21) {
    assert_eq!(cqe.opcode, opcode);
    assert_eq!(cqe.status, status);
    assert_eq!(cqe.reserved, 0);
    validate_completion_output_v21(
        opcode,
        status,
        u32::from(cqe.out_len),
        cqe.information,
        context,
    )
    .expect("frozen completion registry/output matrix");
    if cqe.out_len == 0 {
        assert!(cqe.out.iter().all(|byte| *byte == 0));
    } else {
        let echo: OControl = try_decode(&cqe.out).expect("CQE carries OControl");
        assert_ne!(echo.body.token, 0);
    }
}

fn barrier_sqe(opcode: u16, req_id: u64, kernel_open_id: u64) -> SqeBody {
    SqeBody {
        opcode,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id,
        kernel_open_id,
        ccb_sequence: 0,
        payload: [0; SQE_PAYLOAD_LEN],
    }
}

fn drive_mutation(
    provider: &mut MirrorFs,
    fixture: MutationFixture,
) -> (MutationRequest, MutationResultV2, Vec<u8>) {
    let (harness, table, sqe, owner) = fixture.into_parts();
    let request =
        decode_mutation(&sqe, &table, harness.section(), owner, false).expect("decode mutation");
    assert_eq!(request.kernel_open_id(), sqe.kernel_open_id);
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit mutation");
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, provider);
    let stats = daemon.pump_once().expect("pump mutation");
    assert_eq!((stats.handled, stats.posted), (1, 1));
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("mutation CQE");
    assert_cqe(
        &cqe,
        op::MUTATE,
        completion_status::SUCCESS,
        CompletionOutputContextV21::None,
    );
    let result_bytes = read_grant(
        &harness,
        daemon.table(),
        owner,
        request.reply(),
        cqe.information as u32,
    );
    let result: MutationResultV2 = try_decode(&result_bytes).expect("MutationResultV2");
    assert_eq!(result.mutation_kind, request.mutation_kind());
    let kind = if request.kind_result().token == 0 {
        Vec::new()
    } else {
        read_grant(
            &harness,
            daemon.table(),
            owner,
            request.kind_result(),
            request.kind_result().length,
        )
    };
    (request, result, kind)
}

#[test]
fn open_success_and_registered_failure() {
    let root = TempRoot::new("daemon-open");
    let path = root.child("open.bin");
    std::fs::write(&path, b"daemon open bytes").expect("seed file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let op_id = OpId { lo: 1, hi: 16 };
    let fixture = PrepareFixture::provider(
        provider.root_file_id(),
        "open.bin",
        op_id,
        OPEN_ACCESS,
        ALL_SHARES,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        file_attributes::NORMAL,
        0,
    );
    let (harness, table, sqe, owner) = fixture.into_parts();
    let prepared_request =
        decode_prepare(&sqe, &table, harness.section(), owner).expect("decode prepare");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit prepare");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump prepare");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("prepare CQE");
    assert_cqe(
        &cqe,
        op::PREPARE_OPEN,
        completion_status::SUCCESS,
        CompletionOutputContextV21::None,
    );
    let bytes = read_grant(
        &harness,
        daemon.table(),
        owner,
        prepared_request.reply(),
        136,
    );
    let prepared_wire: PrepareOpenResultV1 = try_decode(&bytes).expect("prepare result");
    let descriptor = read_grant(
        &harness,
        daemon.table(),
        owner,
        prepared_request.result_security_descriptor(),
        prepared_wire.security_descriptor.length,
    );
    assert!(descriptor.len() >= 20);
    assert_eq!(prepared_wire.header.struct_size, 136);
    assert_eq!(prepared_wire.header.struct_version, CONTROL_VERSION_V1);
    assert_eq!(prepared_wire.header.required_flags, 0);
    assert!(
        prepared_wire.transaction_id.lo != 0 || prepared_wire.transaction_id.hi != 0,
        "wire transaction id is nonzero"
    );
    assert_ne!(prepared_wire.file_id, FileId::ZERO);
    assert_eq!(prepared_wire.object_flags, 0);
    assert_eq!(prepared_request.create_options, FILE_NON_DIRECTORY_FILE);
    assert_eq!(prepared_request.file_attributes, file_attributes::NORMAL);
    assert_eq!(prepared_request.open_flags, 0);
    let descriptor_ref = prepared_request.result_security_descriptor();
    assert_eq!(
        prepared_wire.security_descriptor.token,
        descriptor_ref.token
    );
    assert_eq!(
        prepared_wire.security_descriptor.offset,
        descriptor_ref.offset
    );
    assert_eq!(
        prepared_wire.security_descriptor.length as usize,
        descriptor.len()
    );
    assert_eq!(prepared_wire.security_descriptor.kind, descriptor_ref.kind);
    assert_eq!(
        prepared_wire.security_descriptor.access,
        descriptor_ref.access
    );
    assert_eq!(prepared_wire.security_descriptor.reserved, 0);
    let prepared = prepare_result_from_wire(&prepared_wire, descriptor.clone());
    assert_eq!(prepared.file_id, prepared_wire.file_id);
    assert_eq!(prepared.link_id, prepared_wire.link_id);
    assert_size_state(prepared.sizes, prepared_wire.sizes);
    assert_eq!(
        prepared.namespace_generation,
        prepared_wire.namespace_generation
    );
    assert_eq!(
        prepared.security_generation,
        prepared_wire.security_generation
    );
    assert_eq!(prepared.security_descriptor.as_ref(), descriptor.as_slice());
    assert_eq!(prepared.object_flags, prepared_wire.object_flags);
    drop(daemon);

    let mut tampered_wire = prepared_wire;
    tampered_wire.namespace_generation = tampered_wire
        .namespace_generation
        .checked_add(1)
        .expect("bounded generation");
    let tampered = prepare_result_from_wire(&tampered_wire, descriptor.clone());
    let mismatch_fixture = CommitFixture::provider(
        op_id,
        tampered_wire.transaction_id,
        0x1601,
        tampered_wire.namespace_generation,
        tampered_wire.security_generation,
        OPEN_ACCESS,
    );
    let (mismatch_harness, mismatch_table, mismatch_sqe, _) = mismatch_fixture.into_parts();
    let mismatch_kernel = mismatch_harness.kernel_ring();
    let _ = mismatch_kernel
        .submit(mismatch_sqe)
        .expect("submit wire-mismatch commit");
    let mut mismatch_daemon = Daemon::new(
        mismatch_harness.daemon_ring(),
        mismatch_harness.section(),
        mismatch_table,
        &mut provider,
    );
    mismatch_daemon
        .lifecycle_mut()
        .prepare(
            prepared_request.clone(),
            tampered,
            0,
            tampered_wire.transaction_id,
        )
        .expect("seed lifecycle from deliberately tampered wire result");
    mismatch_daemon
        .pump_once()
        .expect("wire-mismatch commit pumps");
    let mut mismatch_kernel = mismatch_kernel;
    let mismatch_cqe = mismatch_kernel
        .reap()
        .expect("reap")
        .expect("wire-mismatch CQE");
    assert_cqe(
        &mismatch_cqe,
        op::COMMIT_OPEN,
        completion_status::RETRY,
        CompletionOutputContextV21::None,
    );
    drop(mismatch_daemon);

    let commit_fixture = CommitFixture::provider(
        op_id,
        prepared_wire.transaction_id,
        0x1601,
        prepared_wire.namespace_generation,
        prepared_wire.security_generation,
        OPEN_ACCESS,
    );
    let (harness, table, sqe, owner) = commit_fixture.into_parts();
    let commit_request =
        decode_commit(&sqe, &table, harness.section(), owner).expect("decode commit");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit commit");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon
        .lifecycle_mut()
        .prepare(prepared_request, prepared, 0, prepared_wire.transaction_id)
        .expect("seed lifecycle solely from prior PREPARE wire values");
    daemon.pump_once().expect("pump commit");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("commit CQE");
    assert_cqe(
        &cqe,
        op::COMMIT_OPEN,
        completion_status::SUCCESS,
        CompletionOutputContextV21::None,
    );
    let bytes = read_grant(&harness, daemon.table(), owner, commit_request.reply(), 112);
    let committed: CommitOpenResultV2 = try_decode(&bytes).expect("commit result");
    assert_eq!(committed.header.struct_size, 112);
    assert_eq!(committed.header.struct_version, CONTROL_VERSION_V2);
    assert_eq!(committed.header.required_flags, 0);
    assert_ne!(committed.provider_open_cookie, 0);
    assert_eq!(committed.file_id, prepared_wire.file_id);
    assert_eq!(committed.link_id, prepared_wire.link_id);
    assert_size_state(committed.sizes, prepared_wire.sizes);
    assert_eq!(
        committed.namespace_generation,
        prepared_wire.namespace_generation
    );
    assert_eq!(
        committed.security_generation,
        prepared_wire.security_generation
    );
    assert_eq!(committed.create_result, create_result::OPENED);
    assert_eq!(committed.result_flags, 0);
    assert_ne!(committed.volume_commit_sequence, 0);
    let native = std::fs::metadata(&path).expect("native committed metadata");
    assert_eq!(native.file_size(), committed.sizes.file_size);
    assert_eq!(
        native.file_attributes() & !file_attributes::ACCEPTED_MASK_V21,
        0
    );
    assert_eq!(native.file_attributes() & file_attributes::DIRECTORY, 0);
    assert_eq!(std::fs::read(&path).unwrap(), b"daemon open bytes");
    drop(daemon);
    let projected =
        FileSystem::query_info(&mut provider, 0x1601).expect("committed native projection");
    assert_size_state(projected.sizes, committed.sizes);
    assert_eq!(
        projected.namespace_generation,
        committed.namespace_generation
    );
    assert_eq!(projected.security_generation, committed.security_generation);
    assert_eq!(projected.attributes, native.file_attributes());
    assert_eq!(projected.link_count, 1);

    let missing = PrepareFixture::provider(
        provider.root_file_id(),
        "missing.bin",
        OpId { lo: 2, hi: 16 },
        OPEN_ACCESS,
        ALL_SHARES,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        file_attributes::NORMAL,
        0,
    );
    let (harness, table, sqe, _) = missing.into_parts();
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit missing open");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("registered open failure pumps");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("failure CQE");
    assert_cqe(
        &cqe,
        op::PREPARE_OPEN,
        completion_status::OBJECT_NAME_NOT_FOUND,
        CompletionOutputContextV21::None,
    );
    drop(daemon);
    FileSystem::cleanup(&mut provider, 0x1601);
    FileSystem::close(&mut provider, 0x1601);
}

#[test]
fn data_round_trip_and_flush() {
    let root = TempRoot::new("daemon-data");
    let path = root.child("data.bin");
    std::fs::write(&path, b"0123456789").expect("seed data");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let root_id = provider.root_file_id();
    let opened = direct_open(&mut provider, root_id, "data.bin", false, 20, 0x2001);
    let payload = b"daemon-write".to_vec();
    let fixture = WriteFixture::provider(
        opened.kernel_open_id,
        OpId { lo: 21, hi: 16 },
        3,
        opened.committed.sizes.size_epoch,
        payload.clone(),
    );
    let (harness, table, sqe, owner) = fixture.into_parts();
    let request =
        decode_write(&sqe, &table, harness.section(), owner).expect("decode write request");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit write");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump write");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("write CQE");
    assert_cqe(
        &cqe,
        op::WRITE,
        completion_status::SUCCESS,
        CompletionOutputContextV21::RequestLength(payload.len() as u32),
    );
    let bytes = read_grant(&harness, daemon.table(), owner, request.reply(), 56);
    let write: WriteResultV2 = try_decode(&bytes).expect("write result");
    assert_eq!(cqe.information, payload.len() as u64);
    drop(daemon);

    let read_fixture = ReadFixture::provider(
        opened.kernel_open_id,
        3,
        write.sizes.size_epoch,
        payload.len() as u32,
    );
    let (harness, table, sqe, owner) = read_fixture.into_parts();
    let request = decode_read(&sqe, &table, owner).expect("decode read");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit read");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump read");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("read CQE");
    assert_cqe(
        &cqe,
        op::READ,
        completion_status::SUCCESS,
        CompletionOutputContextV21::RequestLength(payload.len() as u32),
    );
    let bytes = read_grant(
        &harness,
        daemon.table(),
        owner,
        request.data,
        request.length,
    );
    assert_eq!(&bytes[..payload.len()], payload.as_slice());
    drop(daemon);

    let harness = Harness::new_single_ring();
    let table = GrantTable::new(harness.session_epoch());
    let kernel = harness.kernel_ring();
    let _ = kernel
        .submit(barrier_sqe(op::FLUSH, 0x2002, opened.kernel_open_id))
        .expect("submit flush");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump flush");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("flush CQE");
    assert_cqe(
        &cqe,
        op::FLUSH,
        completion_status::SUCCESS,
        CompletionOutputContextV21::None,
    );
    drop(daemon);
    assert_eq!(
        &std::fs::read(&path).expect("native bytes")[3..3 + payload.len()],
        payload.as_slice()
    );
    FileSystem::cleanup(&mut provider, opened.kernel_open_id);
    FileSystem::close(&mut provider, opened.kernel_open_id);
}

#[test]
fn canonical_queries_write_back_native_values() {
    let root = TempRoot::new("daemon-queries");
    let path = root.child("query.bin");
    std::fs::write(&path, b"canonical query bytes").expect("seed query file");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let root_id = provider.root_file_id();
    let opened = direct_open(&mut provider, root_id, "query.bin", false, 30, 0x3001);

    let fixture = QueryInfoFixture::provider(opened.kernel_open_id);
    let (harness, table, sqe, owner) = fixture.into_parts();
    let request = decode_query_info(&sqe, &table, harness.section(), owner).expect("decode info");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit info");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump info");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("info CQE");
    assert_cqe(
        &cqe,
        op::QUERY_INFO,
        completion_status::SUCCESS,
        CompletionOutputContextV21::CanonicalBlobLength(104),
    );
    let bytes = read_grant(&harness, daemon.table(), owner, request.output, 104);
    let info: FileInfoV1 = try_decode(&bytes).expect("FileInfoV1");
    assert_eq!(
        info.sizes.file_size,
        std::fs::metadata(&path).unwrap().file_size()
    );
    assert_eq!(
        info.namespace_generation,
        opened.committed.namespace_generation
    );
    drop(daemon);

    let fixture = QueryVolumeFixture::provider();
    let (harness, table, sqe, owner) = fixture.into_parts();
    let request =
        decode_query_volume(&sqe, &table, harness.section(), owner).expect("decode volume");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit volume");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump volume");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("volume CQE");
    assert_cqe(
        &cqe,
        op::QUERY_VOLUME,
        completion_status::SUCCESS,
        CompletionOutputContextV21::CanonicalBlobLength(40),
    );
    let bytes = read_grant(&harness, daemon.table(), owner, request.output, 40);
    let volume: VolumeSizeInfoV1 = try_decode(&bytes).expect("VolumeSizeInfoV1");
    assert!(volume.total_allocation_units >= volume.available_allocation_units);
    assert!(volume.bytes_per_sector.is_power_of_two());
    drop(daemon);

    let expected_descriptor = FileSystem::query_security(
        &mut provider,
        opened.kernel_open_id,
        security_information::DACL,
    )
    .expect("native descriptor");
    let fixture = QuerySecurityFixture::provider(opened.kernel_open_id, security_information::DACL);
    let (harness, table, sqe, owner) = fixture.into_parts();
    let request =
        decode_query_security(&sqe, &table, harness.section(), owner).expect("decode security");
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit security");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump security");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("security CQE");
    assert_cqe(
        &cqe,
        op::QUERY_SECURITY,
        completion_status::SUCCESS,
        CompletionOutputContextV21::DescriptorLength(cqe.information as u32),
    );
    let bytes = read_grant(
        &harness,
        daemon.table(),
        owner,
        request.output,
        cqe.information as u32,
    );
    assert_eq!(bytes, expected_descriptor);
    drop(daemon);

    let moved = root.child("query-moved.bin");
    std::fs::rename(&path, &moved).expect("externally rename retained path");
    let fixture = QuerySecurityFixture::provider(opened.kernel_open_id, security_information::DACL);
    let (harness, table, sqe, _) = fixture.into_parts();
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit failing security query");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("mapped query failure pumps");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("query failure CQE");
    assert_cqe(
        &cqe,
        op::QUERY_SECURITY,
        completion_status::DATA_ERROR,
        CompletionOutputContextV21::None,
    );
    drop(daemon);
    std::fs::rename(&moved, &path).expect("restore retained path");
    FileSystem::cleanup(&mut provider, opened.kernel_open_id);
    FileSystem::close(&mut provider, opened.kernel_open_id);
}

#[test]
fn directory_pages_and_terminal_statuses() {
    let root = TempRoot::new("daemon-directory");
    let directory = root.child("entries");
    std::fs::create_dir(&directory).expect("create directory");
    for index in 0..48 {
        let name = format!("{index:02}-{}.bin", "x".repeat(80));
        std::fs::write(directory.join(name), [index as u8]).expect("seed entry");
    }
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let root_id = provider.root_file_id();
    let opened = direct_open(&mut provider, root_id, "entries", true, 40, 0x4001);
    let fixture = QueryDirFixture::provider_match_all(opened.kernel_open_id, 1, 4096);
    let (harness, table, mut sqe, owner) = fixture.into_parts();
    let initial =
        decode_query_dir(&sqe, &table, harness.section(), owner).expect("decode initial page");
    let output = initial.output;
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit first directory page");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump first page");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("first page CQE");
    assert_cqe(
        &cqe,
        op::QUERY_DIR,
        completion_status::SUCCESS,
        CompletionOutputContextV21::CanonicalBlobLength(cqe.information),
    );
    let bytes = read_grant(
        &harness,
        daemon.table(),
        owner,
        output,
        cqe.information as u32,
    );
    let first: QueryDirResultV1 = try_decode(&bytes).expect("directory page prefix");
    assert!(first.entry_count > 0);
    assert_ne!(first.next_cookie, 0);

    let mut cookie = first.next_cookie;
    loop {
        harness.rewrite_query_dir_page(&mut sqe, output, opened.kernel_open_id, 0, cookie, 1);
        let decoded = decode_query_dir(&sqe, daemon.table(), harness.section(), owner)
            .expect("rewritten continuation decodes before submission");
        assert_eq!(decoded.enumeration_cookie, cookie);
        assert_eq!(decoded.enumeration_generation, 1);
        let _ = kernel.submit(sqe).expect("submit continuation");
        let submitted = decode_query_dir(&sqe, daemon.table(), harness.section(), owner)
            .expect("submitted SQE PControl still decodes");
        assert_eq!(submitted.enumeration_cookie, cookie);
        assert_eq!(submitted.enumeration_generation, 1);
        daemon.pump_once().expect("pump continuation");
        let cqe = kernel.reap().expect("reap").expect("continuation CQE");
        if cqe.status == completion_status::NO_MORE_FILES {
            assert_cqe(
                &cqe,
                op::QUERY_DIR,
                completion_status::NO_MORE_FILES,
                CompletionOutputContextV21::None,
            );
            break;
        }
        assert_cqe(
            &cqe,
            op::QUERY_DIR,
            completion_status::SUCCESS,
            CompletionOutputContextV21::CanonicalBlobLength(cqe.information),
        );
        let bytes = read_grant(
            &harness,
            daemon.table(),
            owner,
            output,
            cqe.information as u32,
        );
        let page: QueryDirResultV1 = try_decode(&bytes).expect("continuation prefix");
        cookie = if page.next_cookie == 0 {
            cookie + u64::from(page.entry_count)
        } else {
            page.next_cookie
        };
    }
    drop(daemon);

    for entry in std::fs::read_dir(&directory).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let fixture = QueryDirFixture::provider_match_all(opened.kernel_open_id, 2, 4096);
    let (harness, table, sqe, _) = fixture.into_parts();
    let kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit empty initial");
    let mut daemon = Daemon::new(
        harness.daemon_ring(),
        harness.section(),
        table,
        &mut provider,
    );
    daemon.pump_once().expect("pump empty initial");
    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("empty CQE");
    assert_cqe(
        &cqe,
        op::QUERY_DIR,
        completion_status::NO_SUCH_FILE,
        CompletionOutputContextV21::None,
    );
    drop(daemon);
    FileSystem::cleanup(&mut provider, opened.kernel_open_id);
    FileSystem::close(&mut provider, opened.kernel_open_id);
}

#[test]
fn mutations_write_back_real_effects() {
    let root = TempRoot::new("daemon-mutations");
    let directory = root.child("box");
    std::fs::create_dir(&directory).expect("create box");
    std::fs::write(directory.join("source.bin"), b"mutation bytes").expect("seed source");
    let mut provider = MirrorFs::open(root.path()).expect("open provider");
    let root_id = provider.root_file_id();
    let parent = direct_open(&mut provider, root_id, "box", true, 50, 0x5001);
    let source = direct_open(
        &mut provider,
        parent.committed.file_id,
        "source.bin",
        false,
        51,
        0x5002,
    );
    FileSystem::cleanup(&mut provider, parent.kernel_open_id);
    FileSystem::close(&mut provider, parent.kernel_open_id);
    let descriptor = FileSystem::query_security(
        &mut provider,
        source.kernel_open_id,
        security_information::DACL,
    )
    .expect("query source DACL");
    let (_, security_result, kind) = drive_mutation(
        &mut provider,
        MutationFixture::provider(
            source.kernel_open_id,
            OpId { lo: 52, hi: 16 },
            0,
            0,
            source.committed.security_generation,
            ProviderMutation::SetSecurity {
                security_information: security_information::DACL,
                descriptor,
            },
        ),
    );
    assert_eq!(security_result.mutation_kind, mutation_kind::SET_SECURITY);
    assert!(security_result.security_generation > source.committed.security_generation);
    assert!(kind.is_empty());

    let timestamp = source
        .prepared
        .sizes
        .file_size
        .checked_add(1)
        .map(|_| 0x01D9_0000_0000_0001_i64)
        .unwrap();
    let (_, basic_result, kind) = drive_mutation(
        &mut provider,
        MutationFixture::provider(
            source.kernel_open_id,
            OpId { lo: 53, hi: 16 },
            source.committed.namespace_generation,
            0,
            0,
            ProviderMutation::SetBasicInfo {
                creation_time: timestamp,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                attributes: 0,
                set_mask: basic_info_set_mask::CREATION_TIME,
            },
        ),
    );
    assert!(basic_result.namespace_generation > source.committed.namespace_generation);
    assert!(kind.is_empty());

    let (_, rename_result, kind) = drive_mutation(
        &mut provider,
        MutationFixture::provider(
            source.kernel_open_id,
            OpId { lo: 54, hi: 16 },
            basic_result.namespace_generation,
            0,
            0,
            ProviderMutation::Rename {
                source_link_id: source.committed.link_id,
                target_parent_id: parent.committed.file_id,
                expected_source_parent_generation: parent.committed.namespace_generation,
                expected_target_parent_generation: parent.committed.namespace_generation,
                name: "renamed.bin".into(),
                flags: 0,
            },
        ),
    );
    let renamed: RenameResultV2 = try_decode(&kind).expect("rename kind result");
    assert_eq!(renamed.file_id, source.committed.file_id);
    assert!(directory.join("renamed.bin").exists());
    assert!(!directory.join("source.bin").exists());

    let (_, link_result, kind) = drive_mutation(
        &mut provider,
        MutationFixture::provider(
            source.kernel_open_id,
            OpId { lo: 55, hi: 16 },
            rename_result.namespace_generation,
            0,
            0,
            ProviderMutation::Link {
                source_file_id: source.committed.file_id,
                target_parent_id: parent.committed.file_id,
                expected_target_parent_generation: renamed.target_parent_generation,
                name: "linked.bin".into(),
                flags: 0,
            },
        ),
    );
    let linked: LinkResultV2 = try_decode(&kind).expect("link kind result");
    assert_eq!(linked.file_id, source.committed.file_id);
    assert_eq!(
        std::fs::read(directory.join("linked.bin")).unwrap(),
        b"mutation bytes"
    );

    let (_, unlink_result, kind) = drive_mutation(
        &mut provider,
        MutationFixture::provider(
            source.kernel_open_id,
            OpId { lo: 56, hi: 16 },
            link_result.namespace_generation,
            0,
            0,
            ProviderMutation::Unlink {
                link_id: linked.new_link_id,
                parent_id: parent.committed.file_id,
                expected_parent_generation: linked.target_parent_generation,
                flags: 0,
            },
        ),
    );
    let unlinked: UnlinkResultV1 = try_decode(&kind).expect("unlink kind result");
    assert_eq!(unlinked.removed_link_id, linked.new_link_id);
    assert!(!directory.join("linked.bin").exists());
    assert!(directory.join("renamed.bin").exists());
    assert_eq!(unlink_result.mutation_kind, mutation_kind::UNLINK);

    FileSystem::cleanup(&mut provider, source.kernel_open_id);
    FileSystem::close(&mut provider, source.kernel_open_id);
    let _ = (
        source.prepared_request,
        source.transaction_id,
        parent.prepared_request,
        parent.transaction_id,
    );
}
