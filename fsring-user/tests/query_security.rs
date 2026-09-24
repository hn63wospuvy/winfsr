//! End-to-end `QUERY_SECURITY`: decode a granted request through the A2 grant
//! layer, build its success completion, resolve it against the SQE, and
//! confirm the produced CQE fields agree with the completion.
//!
//! Gated on `testkit` (the kernel-role fixtures live there).
#![cfg(feature = "testkit")]

use fsring_user::testkit::QuerySecurityFixture;
use fsring_user::{build_query_security_completion, decode_query_security, resolve_completion};

#[test]
fn query_security_end_to_end() {
    let fx = QuerySecurityFixture::valid();
    let req = decode_query_security(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
    let completion = build_query_security_completion(&req, 64).expect("completion builds");

    let cqe = resolve_completion(&fx.sqe, completion)
        .expect("legal")
        .expect("a completion");
    assert_eq!(cqe.out_len, 24);
    assert_eq!(cqe.information, 64);
}
