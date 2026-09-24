//! Task 13: an end-to-end integration test driving a COHERENT stateful
//! sequence through the public `Daemon` API against the `StubFileSystem`,
//! proving the pieces compose across ops on ONE open, from an external
//! consumer of the crate (this file uses only `fsring_user`'s public surface,
//! never a `crate::`-internal path).
//!
//! Task 11 (`fsring-user/src/testkit.rs`) already proved every opcode
//! individually — each fixture builds its OWN `Harness`/section. This test
//! instead builds ONE `Harness` + `GrantTable` + `Daemon` + `StubFileSystem`,
//! seeds a LIVE open row directly through the engine (`Daemon::lifecycle_mut`,
//! mirroring the Task-10 CLEANUP test), and drives multiple opcodes against
//! that ONE seeded open in sequence — submit on the kernel ring, `pump_once`,
//! reap — asserting each reaped CQE is wire-legal and, for the write-back
//! ops, that the U2K grant holds the expected bytes read back via
//! `resolve_body`.
//!
//! A single 9-op chain (WRITE, READ, QUERY_DIR, QUERY_INFO, QUERY_VOLUME,
//! QUERY_SECURITY, MUTATE, CLEANUP, CLOSE) on one section turns out to be
//! physically infeasible: `Daemon::new` consumes the `GrantTable` by value
//! and exposes only a read-only `table()` accessor afterward, so *every*
//! grant the whole sequence will ever need must be issued into disjoint
//! physical slots *before* the `Daemon` is built (`GrantTable::resolve` finds
//! the *first* matching entry for a reused token, so reusing a slot for two
//! different grants silently resolves to the stale one — not merely
//! wasteful, actually wrong). The canonical single-ring SETUP
//! (`Harness::new_single_ring`) only carves out 4 K2U slots (class 0) and 2
//! U2K slots (class 1) per section (`MIN_K2U_PROGRESS_SLOTS_PER_RING` /
//! `MIN_U2K_PROGRESS_SLOTS_PER_RING` in `fsring-abi::limits`, ring_count=1).
//! Every write-back opcode needs exactly one U2K grant except MUTATE, which
//! needs two (`reply` + `kind_result`) — so MUTATE alone consumes the whole
//! U2K budget, and no other write-back op can join it in the same section.
//! This is why Task 11's own per-op fixtures each build a fresh `Harness`.
//!
//! Given that ceiling, this file drives the two largest coherent sequences
//! that DO fit in one section's grant budget:
//! - `daemon_drives_write_then_read_then_teardown_on_one_open`: WRITE, READ,
//!   CLEANUP, CLOSE (2 K2U + 2 U2K grants — exactly the U2K budget).
//! - `daemon_drives_a_mutate_rename_then_teardown_on_one_open`: MUTATE
//!   (rename), CLEANUP, CLOSE (2 K2U + 2 U2K grants — MUTATE's own pair).
//!
//! QUERY_DIR/QUERY_INFO/QUERY_VOLUME/QUERY_SECURITY/PREPARE/COMMIT/ABORT/
//! FLUSH stay Task-11-only coverage (each already proven individually there).
//!
//! Requires the `testkit` feature:
//! `cargo test -p fsring-user --features testkit --test daemon`.

#![cfg(feature = "testkit")]

use std::collections::HashMap;

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::ids::{FileId, LinkId, OpId, ReqId, TransactionId};
use fsring_abi::layout::{op, CqeBody, SqeBody, CQE_OUT_LEN, SQE_PAYLOAD_LEN};
use fsring_abi::msgs::{
    create_result, BlobSlice, BufferRef, CommitOpenV2, ControlHeader, MutationV2, PRw,
    PrepareOpenResultV1, PrepareOpenV2, QueryDirV2, RenameV1, SizeState, WriteResultV2, WriteV2,
    CONTROL_VERSION_V1, CONTROL_VERSION_V2,
};
use fsring_abi::msgs::{mutation_kind, query_dir_flags};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner, SlotToken};
use fsring_abi::validate::completion_status;

use fsring_user::testkit::{
    CommitFixture, Harness, MutationFixture, PrepareFixture, QueryDirFixture, QueryInfoFixture,
    QuerySecurityFixture, QueryVolumeFixture, ReadFixture, StubFileSystem, WriteFixture,
};
use fsring_user::{
    build_mutation_result, build_write_result, decode_mutation, decode_prepare, decode_read,
    decode_write, resolve_body, CommitEffect, CommitRequest, Daemon, DaemonError, FileInfoFields,
    FileSystem, FileSystemResult, GrantTable, LifecycleFault, MutationContext, MutationEffect,
    MutationRequest, OpenLifecycle, PrepareResult, PreparedRequest, ProviderError,
    ProviderViolation, PumpStats, QueryDirRequest, RowState, VolumeSizeFields, WriteOutcome,
    WriteRequest,
};

/// A generation-1 slot token in `class`/`index` (mirrors `testkit.rs`'s own
/// private `tok` helper — not re-exported, so this file rebuilds the one line
/// it needs from the public `SlotToken::try_new`).
fn tok(class: u8, index: u32) -> SlotToken {
    SlotToken::try_new(class, index, 1).expect("valid slot token")
}

/// A `PControl` SQE (`payload_len = 24`) whose 24-byte payload echoes
/// `body_ref`, carrying `kernel_open_id` (mirrors `testkit.rs`'s private
/// `pcontrol_sqe`, extended with the open id so every step in a sequence
/// targets the same seeded open).
fn pcontrol_sqe(opcode: u16, req_id: u64, kernel_open_id: u64, body_ref: &BufferRef) -> SqeBody {
    let mut payload = [0u8; SQE_PAYLOAD_LEN];
    payload[0..8].copy_from_slice(&body_ref.token.to_le_bytes());
    payload[8..12].copy_from_slice(&body_ref.offset.to_le_bytes());
    payload[12..16].copy_from_slice(&body_ref.length.to_le_bytes());
    payload[16..18].copy_from_slice(&body_ref.kind.to_le_bytes());
    payload[18..20].copy_from_slice(&body_ref.access.to_le_bytes());
    payload[20..24].copy_from_slice(&body_ref.reserved.to_le_bytes());
    SqeBody {
        opcode,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id,
        kernel_open_id,
        ccb_sequence: 0,
        payload,
    }
}

/// A zeroed-tail `PBarrier` SQE for a barrier opcode (CLEANUP/CLOSE):
/// `payload_len = 24`, an all-zero payload, carrying the `kernel_open_id` the
/// barrier targets (mirrors `daemon.rs`'s/`testkit.rs`'s own `barrier_sqe`).
fn barrier_sqe(opcode: u16, req_id: u64, kernel_open_id: u64) -> SqeBody {
    SqeBody {
        opcode,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id,
        kernel_open_id,
        ccb_sequence: 0,
        payload: [0u8; SQE_PAYLOAD_LEN],
    }
}

struct QueryDirSqeSpec {
    req_id: u64,
    body_token: SlotToken,
    output_token: SlotToken,
    flags: u32,
    enumeration_cookie: u64,
}

fn query_dir_sqe(
    harness: &Harness,
    table: &mut GrantTable,
    owner: GrantOwner,
    spec: QueryDirSqeSpec,
) -> SqeBody {
    let output = table
        .issue_u2k(&harness.u2k_arena(), owner, spec.output_token, 4096)
        .expect("query output grant");
    let query = QueryDirV2 {
        header: ControlHeader {
            struct_size: 64,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        enumeration_cookie: spec.enumeration_cookie,
        flags: spec.flags,
        reserved: 0,
        pattern: BlobSlice {
            offset: 0,
            length: 0,
        },
        output,
        enumeration_generation: 5,
    };
    let mut body = [0u8; 64];
    try_encode(&query, &mut body).expect("QueryDirV2 fits its body");
    let body_ref = table
        .issue_k2u(
            &harness.k2u_arena(),
            owner,
            spec.body_token,
            body.len() as u32,
        )
        .expect("query body grant");
    harness.write_slot(&harness.k2u_arena(), spec.body_token, &body);
    pcontrol_sqe(op::QUERY_DIR, spec.req_id, 0, &body_ref)
}

fn ok_sizes() -> SizeState {
    SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    }
}

/// Seed a live OPEN row at `kernel_open_id` by driving the engine's public
/// prepare+commit path directly (mirrors `daemon.rs`'s/`testkit.rs`'s own
/// `seed_open`/`seed_live_open`), so a CLEANUP/CLOSE for that open finds a
/// LIVE row instead of a `RowCorruption` fault. This is the workable
/// alternative to a real wire PREPARE_OPEN + COMMIT_OPEN round trip, which
/// would alone exhaust the section's entire grant budget (PREPARE needs four
/// K2U grants and two U2K grants; COMMIT needs one more of each) and leave
/// nothing for any following op.
fn seed_live_open(lifecycle: &mut OpenLifecycle, kernel_open_id: u64, op_lo: u64, tx_lo: u64) {
    let mut prepare_raw: PrepareOpenV2 =
        try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
    prepare_raw.op_id = OpId { lo: op_lo, hi: 0 };
    let prepared = PreparedRequest::from_raw(
        prepare_raw,
        b"a.txt".to_vec().into_boxed_slice(),
        None,
        None,
    );
    let result = PrepareResult {
        file_id: FileId { lo: 9, hi: 0 },
        link_id: LinkId { lo: 9, hi: 0 },
        sizes: ok_sizes(),
        namespace_generation: 1,
        security_generation: 1,
        security_descriptor: vec![0u8; 20].into_boxed_slice(),
        object_flags: 0,
    };
    let transaction_id = TransactionId { lo: tx_lo, hi: 0 };
    lifecycle
        .prepare(prepared, result, 0, transaction_id)
        .expect("seed prepare");

    let mut commit_raw: CommitOpenV2 =
        try_decode(&[0u8; 104]).expect("zeroed CommitOpenV2 decodes");
    commit_raw.op_id = OpId { lo: op_lo, hi: 0 };
    commit_raw.transaction_id = transaction_id;
    commit_raw.expected_namespace_generation = 1;
    commit_raw.expected_security_generation = 1;
    commit_raw.kernel_open_id = kernel_open_id;
    commit_raw.granted_access = 1;
    let commit = CommitRequest::from_raw(commit_raw);
    let effect = CommitEffect {
        create_result: create_result::CREATED,
        file_id: FileId { lo: 9, hi: 0 },
        link_id: LinkId { lo: 9, hi: 0 },
        sizes: ok_sizes(),
        namespace_generation: 1,
        security_generation: 1,
        volume_commit_sequence: 5,
    };
    lifecycle.commit(&commit, effect).expect("seed commit");
}

/// A shrunk echo of `grant` (offset 0, `length` bytes) for a `ShrinkOnly`
/// resolve of a U2K write-back destination (mirrors the pattern every Task-11
/// drive test uses to read a result back).
fn shrunk(grant: BufferRef, length: u32) -> BufferRef {
    BufferRef {
        token: grant.token,
        offset: 0,
        length,
        kind: grant.kind,
        access: grant.access,
        reserved: 0,
    }
}

struct FailureFileSystem {
    error: ProviderError,
}

impl FileSystem for FailureFileSystem {
    fn prepare(
        &mut self,
        _request: &PreparedRequest,
        _transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult> {
        Err(self.error)
    }

    fn commit(&mut self, _request: &CommitRequest) -> FileSystemResult<CommitEffect> {
        Err(self.error)
    }

    fn abort(&mut self, _transaction_id: TransactionId) {}

    fn cleanup(&mut self, _kernel_open_id: u64) {}

    fn close(&mut self, _kernel_open_id: u64) {}

    fn read(
        &mut self,
        _kernel_open_id: u64,
        _offset: u64,
        _buf: &mut [u8],
    ) -> FileSystemResult<usize> {
        Err(self.error)
    }

    fn write(
        &mut self,
        _kernel_open_id: u64,
        _request: &fsring_user::WriteRequest,
    ) -> FileSystemResult<fsring_user::WriteOutcome> {
        Err(self.error)
    }

    fn flush(&mut self, _kernel_open_id: u64) -> FileSystemResult<()> {
        Err(self.error)
    }

    fn query_dir(
        &mut self,
        _kernel_open_id: u64,
        _request: &fsring_user::QueryDirRequest,
    ) -> FileSystemResult<Vec<fsring_user::DirCandidate>> {
        Err(self.error)
    }

    fn query_info(
        &mut self,
        _kernel_open_id: u64,
    ) -> FileSystemResult<fsring_user::FileInfoFields> {
        Err(self.error)
    }

    fn query_volume(&mut self) -> FileSystemResult<fsring_user::VolumeSizeFields> {
        Err(self.error)
    }

    fn query_security(
        &mut self,
        _kernel_open_id: u64,
        _security_information: u32,
    ) -> FileSystemResult<Vec<u8>> {
        Err(self.error)
    }

    fn mutation_context(
        &mut self,
        _request: &fsring_user::MutationRequest,
    ) -> FileSystemResult<MutationContext> {
        Err(self.error)
    }

    fn mutate(
        &mut self,
        _request: &fsring_user::MutationRequest,
    ) -> FileSystemResult<fsring_user::MutationEffect> {
        Err(self.error)
    }
}

fn drive_provider_failure(opcode: u16, error: ProviderError) -> Result<CqeBody, DaemonError> {
    let (harness, table, sqe) = match opcode {
        op::PREPARE_OPEN => {
            let (harness, table, sqe, _) = PrepareFixture::build().into_parts();
            (harness, table, sqe)
        }
        op::COMMIT_OPEN => {
            let (harness, table, sqe, _) = CommitFixture::build().into_parts();
            (harness, table, sqe)
        }
        op::READ => {
            let (harness, table, sqe, _) = ReadFixture::valid().into_parts();
            (harness, table, sqe)
        }
        op::WRITE => {
            let (harness, table, sqe, _) = WriteFixture::valid().into_parts();
            (harness, table, sqe)
        }
        op::QUERY_DIR => {
            let (harness, table, sqe, _) = QueryDirFixture::match_all().into_parts();
            (harness, table, sqe)
        }
        op::QUERY_INFO => {
            let (harness, table, sqe, _) = QueryInfoFixture::valid().into_parts();
            (harness, table, sqe)
        }
        op::QUERY_VOLUME => {
            let (harness, table, sqe, _) = QueryVolumeFixture::valid().into_parts();
            (harness, table, sqe)
        }
        op::QUERY_SECURITY => {
            let (harness, table, sqe, _) = QuerySecurityFixture::valid().into_parts();
            (harness, table, sqe)
        }
        op::MUTATE => {
            let (harness, table, sqe, _) = MutationFixture::rename().into_parts();
            (harness, table, sqe)
        }
        op::FLUSH => {
            let harness = Harness::new_single_ring();
            let table = GrantTable::new(harness.session_epoch());
            (harness, table, barrier_sqe(op::FLUSH, 0xF1, 0xF1))
        }
        _ => panic!("unsupported fallible opcode: {opcode:#x}"),
    };

    let mut kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit");
    let mut fs = FailureFileSystem { error };
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    if opcode == op::COMMIT_OPEN {
        seed_pending_open(daemon.lifecycle_mut(), 0x11, 0x22, 1);
    }
    let result = daemon.pump_once();
    let cqe = kernel.reap().expect("reap");
    match result {
        Ok(stats) => {
            assert_eq!(
                stats,
                PumpStats {
                    handled: 1,
                    posted: 1,
                    suppressed: 0
                }
            );
            Ok(cqe.expect("provider failure completion"))
        }
        Err(error) => {
            assert!(
                cqe.is_none(),
                "illegal provider failure must not post a CQE"
            );
            Err(error)
        }
    }
}

#[test]
fn provider_failure_posts_registered_statuses_with_empty_cqes() {
    for (opcode, status) in [
        (op::PREPARE_OPEN, completion_status::DATA_ERROR),
        (op::COMMIT_OPEN, completion_status::RETRY),
        (op::READ, completion_status::DATA_ERROR),
        (op::WRITE, completion_status::DISK_FULL),
        (op::FLUSH, completion_status::IO_TIMEOUT),
        (op::QUERY_DIR, completion_status::NOT_SUPPORTED),
        (op::QUERY_INFO, completion_status::DATA_ERROR),
        (op::QUERY_VOLUME, completion_status::DEVICE_NOT_READY),
        (op::QUERY_SECURITY, completion_status::ACCESS_DENIED),
        (op::MUTATE, completion_status::RETRY),
    ] {
        let cqe = drive_provider_failure(opcode, ProviderError::terminal(status))
            .expect("registered provider failure completes");
        assert_eq!(cqe.status, status);
        assert_eq!(cqe.information, 0);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.out, [0; CQE_OUT_LEN]);
    }
}

#[test]
fn provider_failure_rejects_illegal_statuses_without_posting() {
    for status in [
        completion_status::SUCCESS,
        completion_status::PENDING,
        0xDEAD_BEEFu32 as i32,
        ProviderError::internal().status(),
    ] {
        match drive_provider_failure(op::FLUSH, ProviderError::terminal(status)) {
            Err(DaemonError::Provider(ProviderViolation::IllegalFailureStatus {
                opcode: op::FLUSH,
                status: actual,
            })) if actual == status => {}
            Err(other) => panic!("wrong provider failure: {other:?}"),
            Ok(_) => panic!("illegal provider failure unexpectedly completed"),
        }
    }
}

#[test]
fn partial_write_preserves_the_provider_prefix_and_rejects_illegal_counts() {
    for (reported, should_succeed) in [(3u32, true), (0, false), (9, false)] {
        let (harness, table, sqe, owner) =
            WriteFixture::with_data_bytes((0u8..8).collect()).into_parts();
        let request = decode_write(&sqe, &table, harness.section(), owner).expect("decode write");
        let mut fs = StubFileSystem {
            write_information: Some(reported),
            ..Default::default()
        };
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let mut kernel = harness.kernel_ring();
        let _ = kernel.submit(sqe).expect("submit write");

        match (daemon.pump_once(), should_succeed) {
            (Ok(_), true) => {
                let cqe = kernel.reap().expect("reap").expect("write completion");
                assert_eq!(cqe.status, 0);
                assert_eq!(cqe.information, 3);
                let reply = daemon
                    .table()
                    .resolve(
                        &shrunk(request.reply(), 56),
                        owner,
                        BufferRefPolicy::ShrinkOnly,
                    )
                    .expect("resolve write reply");
                let bytes = resolve_body(harness.section(), &reply).expect("read write reply");
                let result: WriteResultV2 = try_decode(bytes.as_slice()).expect("decode result");
                assert_eq!(result.sizes.file_size, 3);
                assert_eq!(result.sizes.valid_data_length, 3);
            }
            (Err(DaemonError::Result(_)), false) => {
                assert!(
                    kernel.reap().expect("reap").is_none(),
                    "invalid count posts no CQE"
                );
                let reply = daemon
                    .table()
                    .resolve(&request.reply(), owner, BufferRefPolicy::Exact)
                    .expect("resolve untouched reply");
                assert!(
                    resolve_body(harness.section(), &reply)
                        .expect("read untouched reply")
                        .as_slice()
                        .iter()
                        .all(|&byte| byte == 0),
                    "invalid count must stop before reply write-back"
                );
            }
            (other, _) => panic!("unexpected partial write result: {other:?}"),
        }
    }
}

#[test]
fn query_dir_terminal_reports_empty_initial_and_exhausted_continuation() {
    let (empty_harness, empty_table, empty_sqe, _) = QueryDirFixture::match_all().into_parts();
    let mut empty_fs = StubFileSystem::default();
    let mut empty_daemon = Daemon::new(
        empty_harness.daemon_ring(),
        empty_harness.section(),
        empty_table,
        &mut empty_fs,
    );
    let mut empty_kernel = empty_harness.kernel_ring();
    let _ = empty_kernel
        .submit(empty_sqe)
        .expect("submit empty initial");
    empty_daemon.pump_once().expect("pump empty initial");
    let initial_empty = empty_kernel
        .reap()
        .expect("reap")
        .expect("empty initial completion");

    const INITIAL_REQ_ID: u64 = 0x7701;
    const CONTINUATION_REQ_ID: u64 = 0x7702;
    let harness = Harness::new_single_ring();
    let mut table = GrantTable::new(harness.session_epoch());
    let initial_sqe = query_dir_sqe(
        &harness,
        &mut table,
        GrantOwner::Request(ReqId::from_raw(INITIAL_REQ_ID)),
        QueryDirSqeSpec {
            req_id: INITIAL_REQ_ID,
            body_token: tok(0, 0),
            output_token: tok(1, 0),
            flags: query_dir_flags::RESTART,
            enumeration_cookie: 0,
        },
    );
    let continuation_sqe = query_dir_sqe(
        &harness,
        &mut table,
        GrantOwner::Request(ReqId::from_raw(CONTINUATION_REQ_ID)),
        QueryDirSqeSpec {
            req_id: CONTINUATION_REQ_ID,
            body_token: tok(0, 1),
            output_token: tok(1, 1),
            flags: 0,
            enumeration_cookie: 1,
        },
    );
    let mut fs = StubFileSystem {
        query_dir_candidates: vec![fsring_user::DirCandidate {
            name: "one".encode_utf16().flat_map(u16::to_le_bytes).collect(),
            fields: fsring_user::DirEntryFields {
                file_id: FileId { lo: 1, hi: 0 },
                link_id: LinkId { lo: 1, hi: 0 },
                sizes: ok_sizes(),
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                namespace_generation: 1,
                attributes: 0,
            },
        }],
        ..Default::default()
    };
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    let mut kernel = harness.kernel_ring();
    let _ = kernel.submit(initial_sqe).expect("submit initial");
    daemon.pump_once().expect("pump initial");
    kernel
        .reap()
        .expect("reap initial")
        .expect("initial completion");
    let _ = kernel
        .submit(continuation_sqe)
        .expect("submit continuation");
    daemon.pump_once().expect("pump continuation");
    let continuation_end = kernel
        .reap()
        .expect("reap")
        .expect("continuation completion");

    assert_eq!(initial_empty.status, completion_status::NO_SUCH_FILE);
    assert_eq!(continuation_end.status, completion_status::NO_MORE_FILES);
    for cqe in [initial_empty, continuation_end] {
        assert_eq!(cqe.information, 0);
        assert_eq!(cqe.out_len, 0);
    }
}

#[test]
fn daemon_drives_write_then_read_then_teardown_on_one_open() {
    const REQ_ID: u64 = 0x0770_0000_0001;
    const KERNEL_OPEN_ID: u64 = 0x77;

    let harness = Harness::new_single_ring();
    let mut table = GrantTable::new(harness.session_epoch());
    let owner = GrantOwner::Request(ReqId::from_raw(REQ_ID));
    let k2u = harness.k2u_arena();
    let u2k = harness.u2k_arena();

    // ---- WRITE: K2U envelope (0,0) + K2U data (0,1); U2K reply (1,0). ----
    let write_data: Vec<u8> = (0..256u32).map(|i| (i % 256) as u8).collect();
    let write_data_ref = table
        .issue_k2u(&k2u, owner, tok(0, 1), write_data.len() as u32)
        .expect("write data grant");
    harness.write_slot(&k2u, tok(0, 1), &write_data);
    let write_reply_ref = table
        .issue_u2k(&u2k, owner, tok(1, 0), 56)
        .expect("write reply grant");
    let write_envelope = WriteV2 {
        header: ControlHeader {
            struct_size: 112,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        op_id: OpId { lo: 0x11, hi: 0 },
        offset: 0,
        expected_size_epoch: 1,
        initialized_offset: 0,
        data: write_data_ref,
        length: write_data.len() as u32,
        initialized_length: 0,
        rw_flags: 0,
        reserved: 0,
        reply: write_reply_ref,
    };
    let mut write_envelope_bytes = [0u8; 112];
    try_encode(&write_envelope, &mut write_envelope_bytes).expect("WriteV2 fits its 112 bytes");
    let write_env_ref = table
        .issue_k2u(&k2u, owner, tok(0, 0), 112)
        .expect("write envelope grant");
    harness.write_slot(&k2u, tok(0, 0), &write_envelope_bytes);
    let write_sqe = pcontrol_sqe(op::WRITE, REQ_ID, KERNEL_OPEN_ID, &write_env_ref);

    // ---- READ: U2K data (1,1); the PRw travels inline, no K2U needed. ----
    const READ_LEN: u32 = 512;
    let read_data_ref = table
        .issue_u2k(&u2k, owner, tok(1, 1), READ_LEN)
        .expect("read data grant");
    let read_request = PRw {
        op_id: OpId { lo: 0, hi: 0 },
        offset: 0,
        size_epoch: 1,
        initialized_offset: 0,
        data: read_data_ref,
        length: READ_LEN,
        initialized_length: 0,
        rw_flags: 0,
        reserved: 0,
    };
    let prw_len = core::mem::size_of::<PRw>();
    let mut read_payload = [0u8; SQE_PAYLOAD_LEN];
    try_encode(&read_request, &mut read_payload[..prw_len]).expect("PRw fits its 80 bytes");
    let read_sqe = SqeBody {
        opcode: op::READ,
        flags: 0,
        payload_len: prw_len as u16,
        reserved: 0,
        req_id: REQ_ID,
        kernel_open_id: KERNEL_OPEN_ID,
        ccb_sequence: 0,
        payload: read_payload,
    };

    // Independently decode + compute the expected write-back bytes for both
    // ops before any dispatch happens (the same pattern Task 11 uses): a
    // fresh decode of the very SQEs about to be submitted, plus the stub's
    // own effect, fed into the same public `build_*` encoder the Daemon
    // itself calls. A mismatch here is a real behavioral regression, not a
    // copy/paste coincidence.
    let write_request = decode_write(&write_sqe, &table, harness.section(), owner)
        .expect("decode write independently");
    let read_request_decoded =
        decode_read(&read_sqe, &table, owner).expect("decode read independently");

    let mut fs = StubFileSystem::default();
    let write_outcome = fs
        .write(KERNEL_OPEN_ID, &write_request)
        .expect("stub write succeeds");
    let write_information = u64::from(write_outcome.information);
    let expected_write_bytes = build_write_result(
        &write_request,
        &write_outcome.effect,
        write_information,
        &table,
        owner,
    )
    .expect("expected write result builds");

    fs.read_returns = read_request_decoded.length as usize;
    let expected_read_bytes: Vec<u8> = (0..read_request_decoded.length as usize)
        .map(|i| (i % 251) as u8)
        .collect();

    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    seed_live_open(daemon.lifecycle_mut(), KERNEL_OPEN_ID, 0x01, 0x1001);

    let mut kernel = harness.kernel_ring();

    // Step 1: WRITE on the seeded open.
    let _receipt = kernel.submit(write_sqe).expect("submit write");
    let stats = daemon.pump_once().expect("pump write");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    let cqe = kernel.reap().expect("reap").expect("write completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);
    assert_eq!(cqe.out_len, 24);
    assert_eq!(cqe.information, write_information);
    let write_reply_shrunk = shrunk(write_request.reply(), expected_write_bytes.len() as u32);
    let write_reply_validated = daemon
        .table()
        .resolve(&write_reply_shrunk, owner, BufferRefPolicy::ShrinkOnly)
        .expect("resolve write reply");
    let write_reply_view =
        resolve_body(harness.section(), &write_reply_validated).expect("read back write reply");
    assert_eq!(write_reply_view.as_slice(), expected_write_bytes.as_slice());

    // Step 2: READ on the same seeded open.
    let _receipt = kernel.submit(read_sqe).expect("submit read");
    let stats = daemon.pump_once().expect("pump read");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    let cqe = kernel.reap().expect("reap").expect("read completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);
    assert_eq!(cqe.out_len, 24);
    assert_eq!(cqe.information, read_request_decoded.length as u64);
    let read_data_validated = daemon
        .table()
        .resolve(&read_request_decoded.data, owner, BufferRefPolicy::Exact)
        .expect("resolve read data");
    let read_data_view =
        resolve_body(harness.section(), &read_data_validated).expect("read back read data");
    assert_eq!(read_data_view.as_slice(), expected_read_bytes.as_slice());

    // Step 3: CLEANUP drives the durable row LIVE -> CLEANED.
    let _receipt = kernel
        .submit(barrier_sqe(op::CLEANUP, REQ_ID, KERNEL_OPEN_ID))
        .expect("submit cleanup");
    let stats = daemon.pump_once().expect("pump cleanup");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    assert_eq!(
        daemon.lifecycle_mut().row_state(KERNEL_OPEN_ID),
        Some(RowState::Cleaned)
    );
    let cqe = kernel.reap().expect("reap").expect("cleanup completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);
    assert_eq!(cqe.out_len, 0);
    assert_eq!(cqe.information, 0);

    // Step 4: CLOSE retires the row entirely.
    let _receipt = kernel
        .submit(barrier_sqe(op::CLOSE, REQ_ID, KERNEL_OPEN_ID))
        .expect("submit close");
    let stats = daemon.pump_once().expect("pump close");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    assert_eq!(daemon.lifecycle_mut().row_state(KERNEL_OPEN_ID), None);
    let cqe = kernel.reap().expect("reap").expect("close completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);
    assert_eq!(cqe.out_len, 0);
    assert_eq!(cqe.information, 0);
}

#[test]
fn daemon_drives_a_mutate_rename_then_teardown_on_one_open() {
    const REQ_ID: u64 = 0x0880_0000_0001;
    const KERNEL_OPEN_ID: u64 = 0x88;
    const MUT_GEN: u64 = 1;

    let harness = Harness::new_single_ring();
    let mut table = GrantTable::new(harness.session_epoch());
    let owner = GrantOwner::Request(ReqId::from_raw(REQ_ID));
    let k2u = harness.k2u_arena();
    let u2k = harness.u2k_arena();

    // ---- MUTATE (rename): K2U envelope (0,0) + K2U body (0,1);
    // U2K reply (1,0) + U2K kind_result (1,1) — MUTATE's own pair of U2K
    // grants exactly exhausts the section's 2-slot U2K budget, so this
    // sequence cannot also carry a WRITE/READ/QUERY_DIR alongside it. ----
    let name: Vec<u8> = "b.txt"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let body_len = (72 + name.len() + 7) & !7;
    let rename_record = RenameV1 {
        header: ControlHeader {
            struct_size: body_len as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        source_link_id: LinkId { lo: 0x22, hi: 0 },
        target_parent_id: FileId { lo: 0x33, hi: 0 },
        expected_source_parent_generation: MUT_GEN,
        expected_target_parent_generation: MUT_GEN,
        name: BlobSlice {
            offset: 72,
            length: name.len() as u32,
        },
        flags: 0,
        reserved: 0,
    };
    let mut body_bytes = vec![0u8; body_len];
    try_encode(&rename_record, &mut body_bytes[..72]).expect("RenameV1 fits its 72 bytes");
    body_bytes[72..72 + name.len()].copy_from_slice(&name);

    let body_ref = table
        .issue_k2u(&k2u, owner, tok(0, 1), body_bytes.len() as u32)
        .expect("mutate body grant");
    harness.write_slot(&k2u, tok(0, 1), &body_bytes);
    let reply_ref = table
        .issue_u2k(&u2k, owner, tok(1, 0), 112)
        .expect("mutate reply grant");
    let kind_result_ref = table
        .issue_u2k(&u2k, owner, tok(1, 1), 112)
        .expect("mutate kind_result grant");

    let envelope = MutationV2 {
        header: ControlHeader {
            struct_size: 128,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        op_id: OpId { lo: 0x11, hi: 0 },
        mutation_kind: mutation_kind::RENAME,
        mutation_flags: 0,
        reserved: 0,
        expected_namespace_generation: MUT_GEN,
        expected_size_epoch: 0,
        expected_security_generation: 0,
        body: body_ref,
        reply: reply_ref,
        kind_result: kind_result_ref,
    };
    let mut envelope_bytes = [0u8; 128];
    try_encode(&envelope, &mut envelope_bytes).expect("MutationV2 fits its 128 bytes");
    let env_ref = table
        .issue_k2u(&k2u, owner, tok(0, 0), 128)
        .expect("mutate envelope grant");
    harness.write_slot(&k2u, tok(0, 0), &envelope_bytes);

    let mutate_sqe = pcontrol_sqe(op::MUTATE, REQ_ID, KERNEL_OPEN_ID, &env_ref);

    // Independently decode + compute the expected result bytes before any
    // dispatch, exactly as the WRITE/READ test above does.
    let request = decode_mutation(&mutate_sqe, &table, harness.section(), owner, false)
        .expect("decode mutate independently");
    let mut fs = StubFileSystem::default();
    let effect = fs.mutate(&request).expect("stub mutation succeeds");
    let expected = build_mutation_result(&request, &effect, &table, owner)
        .expect("expected mutation result builds");

    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    seed_live_open(daemon.lifecycle_mut(), KERNEL_OPEN_ID, 0x02, 0x2002);

    let mut kernel = harness.kernel_ring();

    // Step 1: MUTATE (rename) on the seeded open.
    let _receipt = kernel.submit(mutate_sqe).expect("submit mutate");
    let stats = daemon.pump_once().expect("pump mutate");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    let cqe = kernel.reap().expect("reap").expect("mutate completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);
    assert_eq!(cqe.out_len, 24);
    assert_eq!(cqe.information, 112);

    let reply_shrunk = shrunk(request.reply(), expected.result.len() as u32);
    let reply_validated = daemon
        .table()
        .resolve(&reply_shrunk, owner, BufferRefPolicy::ShrinkOnly)
        .expect("resolve mutate reply");
    let reply_view =
        resolve_body(harness.section(), &reply_validated).expect("read back mutate reply");
    assert_eq!(reply_view.as_slice(), expected.result.as_slice());

    let kind_result_shrunk = shrunk(request.kind_result(), expected.kind_result.len() as u32);
    let kind_result_validated = daemon
        .table()
        .resolve(&kind_result_shrunk, owner, BufferRefPolicy::ShrinkOnly)
        .expect("resolve mutate kind_result");
    let kind_result_view = resolve_body(harness.section(), &kind_result_validated)
        .expect("read back mutate kind_result");
    assert_eq!(kind_result_view.as_slice(), expected.kind_result.as_slice());

    // Step 2: CLEANUP drives the durable row LIVE -> CLEANED.
    let _receipt = kernel
        .submit(barrier_sqe(op::CLEANUP, REQ_ID, KERNEL_OPEN_ID))
        .expect("submit cleanup");
    let stats = daemon.pump_once().expect("pump cleanup");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    assert_eq!(
        daemon.lifecycle_mut().row_state(KERNEL_OPEN_ID),
        Some(RowState::Cleaned)
    );
    let cqe = kernel.reap().expect("reap").expect("cleanup completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);

    // Step 3: CLOSE retires the row entirely.
    let _receipt = kernel
        .submit(barrier_sqe(op::CLOSE, REQ_ID, KERNEL_OPEN_ID))
        .expect("submit close");
    let stats = daemon.pump_once().expect("pump close");
    assert_eq!(
        stats,
        PumpStats {
            handled: 1,
            posted: 1,
            suppressed: 0
        }
    );
    assert_eq!(daemon.lifecycle_mut().row_state(KERNEL_OPEN_ID), None);
    let cqe = kernel.reap().expect("reap").expect("close completion");
    assert_eq!(cqe.req_id, REQ_ID);
    assert_eq!(cqe.status, 0);
}

fn lifecycle_prepare_result(namespace_generation: u64) -> PrepareResult {
    PrepareResult {
        file_id: FileId { lo: 9, hi: 0 },
        link_id: LinkId { lo: 9, hi: 0 },
        sizes: ok_sizes(),
        namespace_generation,
        security_generation: namespace_generation,
        security_descriptor: vec![0xAB; 20].into_boxed_slice(),
        object_flags: 0,
    }
}

fn seed_pending_open(
    lifecycle: &mut OpenLifecycle,
    op_lo: u64,
    tx_lo: u64,
    namespace_generation: u64,
) {
    let mut prepare_raw: PrepareOpenV2 =
        try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
    prepare_raw.op_id = OpId { lo: op_lo, hi: 0 };
    let prepared = PreparedRequest::from_raw(
        prepare_raw,
        b"a.txt".to_vec().into_boxed_slice(),
        None,
        None,
    );
    lifecycle
        .prepare(
            prepared,
            lifecycle_prepare_result(namespace_generation),
            0,
            TransactionId { lo: tx_lo, hi: 0 },
        )
        .expect("seed pending open");
}

struct PipelineSpyFileSystem {
    prepare_candidates: Vec<TransactionId>,
    prepare_results: HashMap<OpId, PrepareResult>,
    aborted: Vec<TransactionId>,
    commit_calls: usize,
    mutation_context: MutationContext,
    mutation_context_calls: usize,
    mutate_same_parent_flags: Vec<bool>,
}

impl PipelineSpyFileSystem {
    fn new(mutation_context: MutationContext) -> Self {
        Self {
            prepare_candidates: Vec::new(),
            prepare_results: HashMap::new(),
            aborted: Vec::new(),
            commit_calls: 0,
            mutation_context,
            mutation_context_calls: 0,
            mutate_same_parent_flags: Vec::new(),
        }
    }
}

impl FileSystem for PipelineSpyFileSystem {
    fn prepare(
        &mut self,
        request: &PreparedRequest,
        transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult> {
        self.prepare_candidates.push(transaction_id);
        if let Some(stored) = self.prepare_results.get(&request.op_id) {
            return Ok(stored.clone());
        }
        let result = lifecycle_prepare_result(2);
        self.prepare_results.insert(request.op_id, result.clone());
        Ok(result)
    }

    fn commit(&mut self, _request: &CommitRequest) -> FileSystemResult<CommitEffect> {
        self.commit_calls += 1;
        Ok(CommitEffect {
            create_result: create_result::CREATED,
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 2,
            security_generation: 2,
            volume_commit_sequence: 5,
        })
    }

    fn abort(&mut self, transaction_id: TransactionId) {
        self.aborted.push(transaction_id);
    }

    fn cleanup(&mut self, _kernel_open_id: u64) {}

    fn close(&mut self, _kernel_open_id: u64) {}

    fn read(
        &mut self,
        _kernel_open_id: u64,
        _offset: u64,
        _buf: &mut [u8],
    ) -> FileSystemResult<usize> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn write(
        &mut self,
        _kernel_open_id: u64,
        _request: &WriteRequest,
    ) -> FileSystemResult<WriteOutcome> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn flush(&mut self, _kernel_open_id: u64) -> FileSystemResult<()> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn query_dir(
        &mut self,
        _kernel_open_id: u64,
        _request: &QueryDirRequest,
    ) -> FileSystemResult<Vec<fsring_user::DirCandidate>> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn query_info(&mut self, _kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn query_security(
        &mut self,
        _kernel_open_id: u64,
        _security_information: u32,
    ) -> FileSystemResult<Vec<u8>> {
        unimplemented!("not used by lifecycle or mutation pipeline tests")
    }

    fn mutation_context(
        &mut self,
        _request: &MutationRequest,
    ) -> FileSystemResult<MutationContext> {
        self.mutation_context_calls += 1;
        Ok(self.mutation_context)
    }

    fn mutate(&mut self, request: &MutationRequest) -> FileSystemResult<MutationEffect> {
        self.mutate_same_parent_flags
            .push(request.same_parent_rename());
        Ok(MutationEffect {
            file_id: FileId { lo: 0x100, hi: 0 },
            new_link_id: LinkId { lo: 0x101, hi: 0 },
            replaced: None,
            link_count: 1,
            namespace_generation: 2,
            source_parent_generation: 2,
            target_parent_generation: 2,
            parent_generation: 2,
            sizes: ok_sizes(),
            retained_sizes: ok_sizes(),
            volume_commit_sequence: 5,
            security_generation: 0,
        })
    }
}

fn read_prepare_reply(
    daemon: &Daemon<'_, '_, fsring_user::HeapSection, PipelineSpyFileSystem>,
    harness: &Harness,
    request: &PreparedRequest,
    owner: GrantOwner,
) -> PrepareOpenResultV1 {
    let validated = daemon
        .table()
        .resolve(&request.reply(), owner, BufferRefPolicy::Exact)
        .expect("resolve prepare reply");
    let bytes = resolve_body(harness.section(), &validated).expect("read prepare reply");
    try_decode(bytes.as_slice()).expect("decode prepare reply")
}

#[test]
fn open_lifecycle_prepare_provider_sees_candidates_and_replay_keeps_stored_result() {
    let fixture = PrepareFixture::build();
    let request = decode_prepare(
        &fixture.sqe,
        &fixture.table,
        fixture.section(),
        fixture.owner,
    )
    .expect("decode prepare");
    let owner = fixture.owner;
    let (harness, table, sqe, _) = fixture.into_parts();
    let mut fs = PipelineSpyFileSystem::new(MutationContext::default());
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    let mut kernel = harness.kernel_ring();

    let _ = kernel.submit(sqe).expect("submit first prepare");
    daemon.pump_once().expect("pump first prepare");
    kernel.reap().expect("reap").expect("first completion");
    let first = read_prepare_reply(&daemon, &harness, &request, owner);

    let _ = kernel.submit(sqe).expect("submit replay prepare");
    daemon.pump_once().expect("pump replay prepare");
    kernel.reap().expect("reap").expect("replay completion");
    let replay = read_prepare_reply(&daemon, &harness, &request, owner);

    assert_eq!(first.transaction_id, TransactionId { lo: 1, hi: 0 });
    assert_eq!(replay.transaction_id, first.transaction_id);
    assert_eq!(replay.file_id, first.file_id);
    assert_eq!(replay.link_id, first.link_id);
    assert_eq!(
        replay.namespace_generation, first.namespace_generation,
        "provider-owned stored result is replayed"
    );
    drop(daemon);
    assert_eq!(
        fs.prepare_candidates,
        [
            TransactionId { lo: 1, hi: 0 },
            TransactionId { lo: 2, hi: 0 }
        ]
    );
    assert!(fs.aborted.is_empty());
}

#[test]
fn open_lifecycle_prepare_rejection_aborts_the_fresh_candidate_once() {
    let fixture = PrepareFixture::build();
    let (harness, table, sqe, _) = fixture.into_parts();
    let mut fs = PipelineSpyFileSystem::new(MutationContext::default());
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    let mut kernel = harness.kernel_ring();

    let _ = kernel.submit(sqe).expect("submit first prepare");
    daemon.pump_once().expect("pump first prepare");
    kernel.reap().expect("reap").expect("first completion");

    harness.write_slot(&harness.k2u_arena(), tok(0, 1), b"b.txt");
    let _ = kernel.submit(sqe).expect("submit changed replay");
    assert_eq!(
        daemon.pump_once(),
        Err(DaemonError::Lifecycle(LifecycleFault::PrepareBytesMismatch))
    );
    drop(daemon);

    assert_eq!(
        fs.prepare_candidates,
        [
            TransactionId { lo: 1, hi: 0 },
            TransactionId { lo: 2, hi: 0 }
        ]
    );
    assert_eq!(fs.aborted, [TransactionId { lo: 2, hi: 0 }]);
}

#[test]
fn open_lifecycle_commit_preflight_blocks_provider_for_every_state_fault() {
    let scenarios = [
        LifecycleFault::UnknownTransaction,
        LifecycleFault::OpIdMismatch,
        LifecycleFault::SemanticMismatch,
        LifecycleFault::RowCorruption,
        LifecycleFault::OpenQuota,
    ];

    for expected in scenarios {
        let fixture = CommitFixture::build();
        let (harness, table, sqe, _) = fixture.into_parts();
        let mut fs = PipelineSpyFileSystem::new(MutationContext::default());
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);

        match expected {
            LifecycleFault::UnknownTransaction => {}
            LifecycleFault::OpIdMismatch => {
                seed_pending_open(daemon.lifecycle_mut(), 0x12, 0x22, 1);
            }
            LifecycleFault::SemanticMismatch => {
                seed_pending_open(daemon.lifecycle_mut(), 0x11, 0x22, 2);
            }
            LifecycleFault::RowCorruption => {
                seed_live_open(daemon.lifecycle_mut(), 0x33, 0x90, 0x9000);
                seed_pending_open(daemon.lifecycle_mut(), 0x11, 0x22, 1);
            }
            LifecycleFault::OpenQuota => {
                for index in 0..4096u64 {
                    seed_live_open(
                        daemon.lifecycle_mut(),
                        0x10_000 + index,
                        0x20_000 + index,
                        0x30_000 + index,
                    );
                }
                seed_pending_open(daemon.lifecycle_mut(), 0x11, 0x22, 1);
            }
            _ => unreachable!("scenario list is exhaustive"),
        }

        let retained = daemon.lifecycle_mut().retained_prepare_bytes();
        let live = daemon.lifecycle_mut().live_opens();
        let kernel = harness.kernel_ring();
        let _ = kernel.submit(sqe).expect("submit invalid commit");
        assert_eq!(daemon.pump_once(), Err(DaemonError::Lifecycle(expected)));
        assert_eq!(daemon.lifecycle_mut().retained_prepare_bytes(), retained);
        assert_eq!(daemon.lifecycle_mut().live_opens(), live);
        drop(daemon);
        assert_eq!(
            fs.commit_calls, 0,
            "provider COMMIT must not run for {expected:?}"
        );
    }
}

#[test]
fn mutation_context_is_revalidated_before_mutate_and_reaches_result_building() {
    let fixture = MutationFixture::rename();
    let (harness, table, sqe, _) = fixture.into_parts();
    let mut fs = PipelineSpyFileSystem::new(MutationContext {
        same_parent_rename: true,
    });
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    let mut kernel = harness.kernel_ring();
    let _ = kernel.submit(sqe).expect("submit rename");
    daemon.pump_once().expect("pump rename");
    kernel.reap().expect("reap").expect("rename completion");
    drop(daemon);

    assert_eq!(fs.mutation_context_calls, 1);
    assert_eq!(fs.mutate_same_parent_flags, [true]);
}
