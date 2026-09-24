//! End-to-end open lifecycle: decode a granted `PREPARE_OPEN`/`COMMIT_OPEN` body
//! through the A2 grant layer, drive the volatile `OpenLifecycle` engine through
//! `PREPARE -> COMMIT -> CLEANUP -> CLOSE`, and exercise the `ABORT` paths.
//!
//! Gated on `testkit` (the kernel-role fixtures live there).
#![cfg(feature = "testkit")]

use fsring_abi::codec::try_decode;
use fsring_abi::ids::{FileId, LinkId, OpId, TransactionId};
use fsring_abi::limits::MAX_RETAINED_OPENS_PER_RING;
use fsring_abi::msgs::{create_result, CommitOpenV2, PrepareOpenV2, SizeState};

use fsring_user::testkit::{CommitFixture, PrepareFixture};
use fsring_user::{
    decode_commit, decode_prepare, CommitEffect, OpenLifecycle, PrepareResult, RowState,
};

/// The `TransactionId` the provider allocates at PREPARE — matched by the
/// `CommitFixture`'s default (`0x22`).
const TX: TransactionId = TransactionId { lo: 0x22, hi: 0 };
/// The `CommitFixture`'s default `kernel_open_id`.
const KOID: u64 = 0x33;

fn sizes() -> SizeState {
    SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    }
}

/// A prepare result whose generations (1, 1) match the `CommitFixture`'s
/// expected generations.
fn prepare_result() -> PrepareResult {
    PrepareResult {
        file_id: FileId { lo: 9, hi: 0 },
        link_id: LinkId { lo: 9, hi: 0 },
        sizes: sizes(),
        namespace_generation: 1,
        security_generation: 1,
        security_descriptor: vec![0u8; 20].into_boxed_slice(),
        object_flags: 0,
    }
}

fn commit_effect() -> CommitEffect {
    CommitEffect {
        create_result: create_result::CREATED,
        file_id: FileId { lo: 9, hi: 0 },
        link_id: LinkId { lo: 9, hi: 0 },
        sizes: sizes(),
        namespace_generation: 1,
        security_generation: 1,
        volume_commit_sequence: 5,
    }
}

/// Decode the prepare fixture and admit it into `eng`, returning the op id.
fn admit_prepare(eng: &mut OpenLifecycle) -> fsring_abi::ids::OpId {
    let pf = PrepareFixture::build();
    let op_id = pf.op_id;
    let prepared =
        decode_prepare(&pf.sqe, &pf.table, pf.section(), pf.owner).expect("decode prepare");
    let got = eng
        .prepare(prepared, prepare_result(), 0, TX)
        .expect("prepare");
    assert_eq!(
        got.lo, TX.lo,
        "prepare returns the allocated transaction id"
    );
    op_id
}

/// Decode the commit fixture and commit it into `eng`.
fn commit(eng: &mut OpenLifecycle) {
    let cf = CommitFixture::build();
    let request = decode_commit(&cf.sqe, &cf.table, cf.section(), cf.owner).expect("decode commit");
    let out = eng.commit(&request, commit_effect()).expect("commit");
    assert_ne!(out.provider_open_cookie, 0);
    assert_eq!(out.create_result, create_result::CREATED);
}

#[test]
fn prepare_commit_cleanup_close_walk() {
    let mut eng = OpenLifecycle::new(1);

    let op_id = admit_prepare(&mut eng);
    assert!(eng.has_prepare(op_id));

    commit(&mut eng);
    assert_eq!(eng.row_state(KOID), Some(RowState::Live));
    assert_eq!(eng.live_opens(), 1);
    assert!(
        !eng.has_prepare(op_id),
        "commit retires the open-prepare record"
    );
    assert_eq!(eng.retained_prepare_bytes(), 0);
    eng.assert_invariants();

    eng.cleanup(KOID).expect("cleanup");
    assert_eq!(eng.row_state(KOID), Some(RowState::Cleaned));

    eng.close(KOID).expect("close");
    assert_eq!(eng.row_state(KOID), None);
    assert_eq!(
        eng.live_opens(),
        0,
        "close refunds the retained-open ticket"
    );
    eng.assert_invariants();
}

#[test]
fn prepare_then_abort_removes_the_pair() {
    let mut eng = OpenLifecycle::new(1);
    let op_id = admit_prepare(&mut eng);
    eng.abort(TX).expect("abort");
    assert!(!eng.has_prepare(op_id));
    assert_eq!(eng.retained_prepare_bytes(), 0);
}

#[test]
fn abort_after_commit_is_idempotent() {
    let mut eng = OpenLifecycle::new(1);
    admit_prepare(&mut eng);
    commit(&mut eng);
    // Commit already retired the record + index; abort finds joint absence.
    assert_eq!(eng.abort(TX), Ok(()));
    assert_eq!(
        eng.row_state(KOID),
        Some(RowState::Live),
        "the row is untouched"
    );
}

fn synthetic_prepare(op_lo: u64) -> fsring_user::PreparedRequest {
    let mut raw: PrepareOpenV2 = try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
    raw.op_id = OpId { lo: op_lo, hi: 0 };
    fsring_user::PreparedRequest::from_raw(raw, b"a.txt".to_vec().into_boxed_slice(), None, None)
}

fn synthetic_commit(
    op_lo: u64,
    tx_lo: u64,
    kernel_open_id: u64,
    namespace_generation: u64,
    security_generation: u64,
) -> fsring_user::CommitRequest {
    let mut raw: CommitOpenV2 = try_decode(&[0u8; 104]).expect("zeroed CommitOpenV2 decodes");
    raw.op_id = OpId { lo: op_lo, hi: 0 };
    raw.transaction_id = TransactionId { lo: tx_lo, hi: 0 };
    raw.expected_namespace_generation = namespace_generation;
    raw.expected_security_generation = security_generation;
    raw.kernel_open_id = kernel_open_id;
    raw.granted_access = 1;
    fsring_user::CommitRequest::from_raw(raw)
}

fn seed_prepare(
    eng: &mut OpenLifecycle,
    op_lo: u64,
    tx_lo: u64,
    namespace_generation: u64,
    security_generation: u64,
) {
    let mut result = prepare_result();
    result.namespace_generation = namespace_generation;
    result.security_generation = security_generation;
    eng.prepare(
        synthetic_prepare(op_lo),
        result,
        0,
        TransactionId { lo: tx_lo, hi: 0 },
    )
    .expect("seed prepare");
}

fn seed_commit(eng: &mut OpenLifecycle, op_lo: u64, tx_lo: u64, kernel_open_id: u64) {
    seed_prepare(eng, op_lo, tx_lo, 1, 1);
    eng.commit(
        &synthetic_commit(op_lo, tx_lo, kernel_open_id, 1, 1),
        commit_effect(),
    )
    .expect("seed commit");
}

#[test]
fn open_lifecycle_commit_preflight_rejects_request_row_and_quota_faults() {
    let unknown = OpenLifecycle::new(1);
    assert_eq!(
        unknown.preflight_commit(&synthetic_commit(1, 100, 0x33, 1, 1)),
        Err(fsring_user::LifecycleFault::UnknownTransaction)
    );

    let mut wrong_op = OpenLifecycle::new(1);
    seed_prepare(&mut wrong_op, 1, 100, 1, 1);
    assert_eq!(
        wrong_op.preflight_commit(&synthetic_commit(2, 100, 0x33, 1, 1)),
        Err(fsring_user::LifecycleFault::OpIdMismatch)
    );

    let mut wrong_generation = OpenLifecycle::new(1);
    seed_prepare(&mut wrong_generation, 1, 100, 1, 1);
    assert_eq!(
        wrong_generation.preflight_commit(&synthetic_commit(1, 100, 0x33, 2, 1)),
        Err(fsring_user::LifecycleFault::SemanticMismatch)
    );

    let mut occupied = OpenLifecycle::new(1);
    seed_commit(&mut occupied, 1, 100, 0x33);
    seed_prepare(&mut occupied, 2, 101, 1, 1);
    assert_eq!(
        occupied.preflight_commit(&synthetic_commit(2, 101, 0x33, 1, 1)),
        Err(fsring_user::LifecycleFault::RowCorruption)
    );

    let mut full = OpenLifecycle::new(1);
    for index in 0..u64::from(MAX_RETAINED_OPENS_PER_RING) {
        let op_lo = 10_000 + index;
        let tx_lo = 20_000 + index;
        seed_commit(&mut full, op_lo, tx_lo, 30_000 + index);
    }
    seed_prepare(&mut full, 99_000, 99_001, 1, 1);
    let retained = full.retained_prepare_bytes();
    assert_eq!(
        full.preflight_commit(&synthetic_commit(99_000, 99_001, 99_002, 1, 1)),
        Err(fsring_user::LifecycleFault::OpenQuota)
    );
    assert_eq!(full.live_opens(), MAX_RETAINED_OPENS_PER_RING);
    assert_eq!(full.retained_prepare_bytes(), retained);
    assert!(full.has_prepare(OpId { lo: 99_000, hi: 0 }));
}
