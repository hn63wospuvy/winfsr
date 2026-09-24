//! Provider dispatch over the real transport: non-echo completions round-trip
//! intact, the guardrail rejects an illegal completion without corrupting the
//! ring, and fire-and-forget requests post nothing.
//!
//! Requires the `testkit` feature.
#![cfg(feature = "testkit")]

use fsring_abi::layout::{op, sqe_flags, SqeBody, SQE_PAYLOAD_LEN};
use fsring_abi::validate::completion_status;
use fsring_user::testkit::Harness;
use fsring_user::{pump_once, EchoProvider, OutBuf, ProviderViolation, PumpError, StatusProvider};

fn req(opcode: u16, flags: u16, req_id: u64) -> SqeBody {
    SqeBody {
        opcode,
        flags,
        payload_len: 0,
        reserved: 0,
        req_id,
        kernel_open_id: 0,
        ccb_sequence: 0,
        payload: [0u8; SQE_PAYLOAD_LEN],
    }
}

#[test]
fn exact_information_completion_round_trips_with_output() {
    // PREPARE_OPEN success is the matrix's exact-information shape: out_len 24
    // and information exactly 136. (A registered *failure* must carry zero
    // output, so the old READ+END_OF_FILE+4-byte shape is now illegal.)
    let harness = Harness::new_single_ring();
    let kernel = harness.kernel_ring();
    let mut daemon = harness.daemon_ring();
    let payload = [7u8; 24];
    let mut provider = StatusProvider {
        status: completion_status::SUCCESS,
        information: 136,
        out: OutBuf::new(&payload).unwrap(),
    };

    let _receipt = kernel.submit(req(op::PREPARE_OPEN, 0, 11)).expect("submit");
    assert_eq!(
        pump_once(&mut daemon, &mut provider).expect("pump").posted,
        1
    );

    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("completion ready");
    assert_eq!(cqe.req_id, 11);
    assert_eq!(cqe.status, completion_status::SUCCESS);
    assert_eq!(cqe.information, 136);
    assert_eq!(cqe.out_len, 24);
    assert_eq!(&cqe.out[..], &payload[..]);
}

#[test]
fn registered_failure_round_trips_with_zero_output() {
    let harness = Harness::new_single_ring();
    let kernel = harness.kernel_ring();
    let mut daemon = harness.daemon_ring();
    let mut provider = StatusProvider {
        status: completion_status::ACCESS_DENIED,
        information: 0,
        out: OutBuf::empty(),
    };

    let _receipt = kernel.submit(req(op::READ, 0, 21)).expect("submit");
    assert_eq!(
        pump_once(&mut daemon, &mut provider).expect("pump").posted,
        1
    );

    let mut kernel = kernel;
    let cqe = kernel.reap().expect("reap").expect("completion");
    assert_eq!(cqe.status, completion_status::ACCESS_DENIED);
    assert_eq!(cqe.out_len, 0);
    assert_eq!(cqe.information, 0);
}

#[test]
fn unregistered_completion_is_rejected_and_ring_stays_coherent() {
    let harness = Harness::new_single_ring();
    let kernel = harness.kernel_ring();
    let mut daemon = harness.daemon_ring();

    // A provider that returns a status the ABI does not register for READ.
    let mut bad = StatusProvider {
        status: 0x0000_1234,
        information: 0,
        out: OutBuf::empty(),
    };
    let _receipt = kernel.submit(req(op::READ, 0, 1)).expect("submit");
    assert_eq!(
        pump_once(&mut daemon, &mut bad),
        Err(PumpError::Provider(ProviderViolation::UnregisteredStatus {
            opcode: op::READ,
            status: 0x0000_1234,
        }))
    );

    // Nothing was posted; the ring still works for a subsequent legal request.
    let mut kernel = kernel;
    assert!(
        kernel.reap().expect("reap").is_none(),
        "illegal CQE not posted"
    );

    let mut good = EchoProvider;
    // A wire-legal PBarrier (payload_len 24, zero op_id/flags/reserved).
    let mut barrier = req(op::CLEANUP, 0, 2);
    barrier.payload_len = 24;
    let _receipt = kernel.submit(barrier).expect("submit");
    assert_eq!(pump_once(&mut daemon, &mut good).expect("pump").posted, 1);
    let cqe = kernel.reap().expect("reap").expect("completion ready");
    assert_eq!(cqe.req_id, 2);
}

#[test]
fn fire_and_forget_request_posts_nothing() {
    let harness = Harness::new_single_ring();
    let kernel = harness.kernel_ring();
    let mut daemon = harness.daemon_ring();
    let mut provider = EchoProvider;

    let _receipt = kernel
        .submit(req(op::CANCEL, sqe_flags::NO_COMPLETION, 3))
        .expect("submit");
    let stats = pump_once(&mut daemon, &mut provider).expect("pump");
    assert_eq!(stats.suppressed, 1);
    assert_eq!(stats.posted, 0);

    let mut kernel = kernel;
    assert!(kernel.reap().expect("reap").is_none());
}
