//! End-to-end granted-body round trip: the harness (kernel role) grants an
//! `AbortOpenV1` into a k2u slot and submits an `ABORT_OPEN` SQE whose
//! `PControl` echoes the grant; the daemon resolves the grant, single-fetches
//! the body, and decodes it.
//!
//! Requires the `testkit` feature.
#![cfg(feature = "testkit")]

use fsring_abi::ids::ReqId;
use fsring_abi::slots::{BufferRefPolicy, GrantOwner, SlotToken};
use fsring_user::control::{pcontrol_body_ref, AbortRequest};
use fsring_user::testkit::Harness;
use fsring_user::{resolve_body, GrantTable};

#[test]
fn granted_abort_open_round_trips_and_decodes() {
    let harness = Harness::new_single_ring();
    let arena = harness.k2u_arena();

    let req_id: u64 = 0x0001_0000_0001;
    let owner = GrantOwner::Request(ReqId::from_raw(req_id));
    let token = SlotToken::try_new(0, 0, 1).unwrap();

    // Harness (kernel role): write the AbortOpenV1 into the slot, grant it, and
    // build the ABORT_OPEN SQE whose PControl echoes the grant.
    let mut body = [0u8; 24];
    body[0..4].copy_from_slice(&24u32.to_le_bytes()); // struct_size
    body[4..6].copy_from_slice(&1u16.to_le_bytes()); // CONTROL_VERSION_V1
    body[8..16].copy_from_slice(&0x99u64.to_le_bytes()); // transaction_id.lo
    harness.write_slot(&arena, token, &body);

    let mut table = GrantTable::new(harness.session_epoch());
    let sqe = harness.grant_abort_sqe(&mut table, owner, token, req_id, &body);

    let kernel = harness.kernel_ring();
    let _receipt = kernel.submit(sqe).expect("submit");

    // Daemon role: pop the request, resolve the grant, fetch and decode.
    let mut daemon = harness.daemon_ring();
    let popped = daemon.poll_sqe().expect("poll").expect("a request");

    let reference = pcontrol_body_ref(&popped).expect("pcontrol");
    let owner = GrantOwner::Request(ReqId::from_raw(popped.req_id));
    let validated = table
        .resolve(&reference, owner, BufferRefPolicy::Exact)
        .expect("resolve");
    let view = resolve_body(harness.section(), &validated).expect("resolve_body");
    let abort = AbortRequest::decode(view.as_slice()).expect("decode");
    assert_eq!(abort.transaction_id_lo, 0x99);
    assert_eq!(abort.transaction_id_hi, 0);
}
