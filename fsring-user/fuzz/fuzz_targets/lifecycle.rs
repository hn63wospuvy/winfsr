#![no_main]
//! Fuzz the volatile open-lifecycle engine: an arbitrary sequence of
//! prepare/commit/cleanup/close/abort operations over a tiny id domain (so
//! collisions, idempotent replays, and retries actually occur) must never panic
//! and must preserve the engine's cross-field invariants after every step
//! (index/record bijection, one retained-open ticket per live row across all
//! three counters, retained-prepare bytes == sum of live charges).

use libfuzzer_sys::fuzz_target;

use fsring_abi::codec::try_decode;
use fsring_abi::ids::{FileId, LinkId, OpId, TransactionId};
use fsring_abi::msgs::{CommitOpenV2, PrepareOpenV2, SizeState};
use fsring_user::{CommitEffect, CommitRequest, OpenLifecycle, PrepareResult, PreparedRequest};

fn sizes() -> SizeState {
    SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    }
}

fn prepared(id: u64, name_byte: u8) -> PreparedRequest {
    // A zeroed raw with just `op_id` set: the engine keys/compares on the
    // semantic fields only, so this is a faithful synthetic request.
    let mut raw: PrepareOpenV2 = try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2");
    raw.op_id = OpId { lo: id, hi: 0 };
    PreparedRequest::from_raw(raw, vec![name_byte].into_boxed_slice(), None, None)
}

fn result() -> PrepareResult {
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

fn commit_req(op: u64, tx: u64, koid: u64, gen: u64) -> CommitRequest {
    let mut raw: CommitOpenV2 = try_decode(&[0u8; 104]).expect("zeroed CommitOpenV2");
    raw.op_id = OpId { lo: op, hi: 0 };
    raw.transaction_id = TransactionId { lo: tx, hi: 0 };
    raw.expected_namespace_generation = gen;
    raw.expected_security_generation = 1;
    raw.kernel_open_id = koid;
    raw.granted_access = 1;
    CommitRequest::from_raw(raw)
}

fn effect(create_result: u32) -> CommitEffect {
    CommitEffect {
        create_result,
        file_id: FileId { lo: 9, hi: 0 },
        link_id: LinkId { lo: 9, hi: 0 },
        sizes: sizes(),
        namespace_generation: 1,
        security_generation: 1,
        volume_commit_sequence: 5,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut eng = OpenLifecycle::new(1);
    for chunk in data.chunks(2) {
        let selector = chunk[0];
        let arg = chunk.get(1).copied().unwrap_or(0);
        let id = (selector & 0x07) as u64; // 0..7 domain -> collisions/retries
        let koid = id + 1; // kernel_open_id domain (nonzero)
        match selector >> 5 {
            0 => {
                let _ = eng.prepare(
                    prepared(id, arg),
                    result(),
                    (arg & 1) as u16,
                    TransactionId { lo: id, hi: 0 },
                );
            }
            // Draw the commit's op_id / tx / generation from offset slices of
            // `arg` so OpIdMismatch (op != tx's record) and generation-driven
            // SemanticMismatch (gen != 1) are reachable, alongside the
            // create_result > OVERWRITTEN(3) -> IllegalCreateResult path.
            1 => {
                let op = (arg & 0x07) as u64;
                let gen = ((arg >> 3) & 0x01) as u64; // 0 or 1
                let _ = eng.commit(
                    &commit_req(op, id, koid, gen),
                    effect((arg >> 4) as u32 & 0x07),
                );
            }
            2 => {
                let _ = eng.cleanup(koid);
            }
            3 => {
                let _ = eng.close(koid);
            }
            4 => {
                let _ = eng.abort(TransactionId { lo: id, hi: 0 });
            }
            _ => {}
        }
        eng.assert_invariants();
    }
    eng.assert_invariants();
});
