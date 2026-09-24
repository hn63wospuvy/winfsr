//! End-to-end heap round-trip: a request submitted by the kernel role is echoed
//! by the daemon and reaped as a matching completion, in FIFO order.
//!
//! Requires the `testkit` feature: `cargo test -p fsring-user --features testkit`.

#![cfg(feature = "testkit")]

use fsring_abi::layout::{cq_kind, SqeBody, SQE_PAYLOAD_LEN};
use fsring_user::testkit::Harness;
use fsring_user::{pump_once, BarrierRequest, EchoProvider};

/// A CLEANUP request carrying a wire-legal `PBarrier`: `payload_len = 24`, a
/// zero `op_id` (which `03-messages.md` permits), zero flags/reserved, and a
/// zero-filled 64-byte tail.
fn request(opcode: u16, req_id: u64) -> SqeBody {
    SqeBody {
        opcode,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id,
        kernel_open_id: 0,
        ccb_sequence: 0,
        payload: [0u8; SQE_PAYLOAD_LEN],
    }
}

#[test]
fn the_round_trip_fixture_is_a_decodable_barrier() {
    // Ties A1's two halves together: the request the round-trips below submit is
    // itself a legal PBarrier, so the payload decoder and the output contract
    // agree on one and the same request.
    let decoded = BarrierRequest::decode(&request(CLEANUP, 1)).expect("wire-legal PBarrier");
    assert_eq!(decoded.op_id.lo, 0);
    assert_eq!(decoded.op_id.hi, 0);
}

const CLEANUP: u16 = 0x0004;

#[test]
fn single_sqe_round_trips_to_matching_cqe() {
    let harness = Harness::new_single_ring();
    let kernel = harness.kernel_ring();
    let mut daemon = harness.daemon_ring();

    let mut provider = EchoProvider;
    let _receipt = kernel.submit(request(CLEANUP, 7)).expect("submit");
    assert_eq!(
        pump_once(&mut daemon, &mut provider).expect("pump").posted,
        1,
        "daemon posted one completion"
    );

    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("a completion is ready");
    assert_eq!(cqe.req_id, 7);
    assert_eq!(cqe.opcode, CLEANUP);
    assert_eq!(cqe.kind, cq_kind::COMPLETION);
    assert_eq!(cqe.status, 0);
    assert!(
        kernel.reap().expect("reap").is_none(),
        "exactly one completion"
    );
}

#[test]
fn multiple_sqes_round_trip_in_fifo_order() {
    let harness = Harness::new_single_ring();
    let kernel = harness.kernel_ring();
    let mut daemon = harness.daemon_ring();
    let mut kernel = kernel;
    let mut provider = EchoProvider;

    // Interleave one at a time so the small CQ (capacity 2) never overflows,
    // while proving the ring preserves submission order across many requests.
    for req_id in 1..=5u64 {
        let _receipt = kernel.submit(request(CLEANUP, req_id)).expect("submit");
        assert_eq!(
            pump_once(&mut daemon, &mut provider).expect("pump").posted,
            1
        );
        let cqe = kernel.reap().expect("reap").expect("a completion is ready");
        assert_eq!(cqe.req_id, req_id, "completions arrive in FIFO order");
    }
    assert!(kernel.reap().expect("reap").is_none());
}
