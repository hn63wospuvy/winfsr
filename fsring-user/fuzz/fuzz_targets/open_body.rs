#![no_main]
//! Fuzz the open-lifecycle body decoders: an attacker-chosen `PrepareOpenV2` /
//! `CommitOpenV2` body sitting behind a valid grant must be decoded or rejected
//! without panicking or reading out of bounds. The outer `BufferRef` and the
//! single-fetch bounds are fuzzed by A2's `grant_resolve`; here the outer grant
//! is valid, so decode reaches `try_decode` + the inner-grant resolution over
//! arbitrary body bytes.

use libfuzzer_sys::fuzz_target;

use fsring_user::testkit::{CommitFixture, PrepareFixture};
use fsring_user::{decode_commit, decode_prepare};

fuzz_target!(|data: &[u8]| {
    let pf = PrepareFixture::build();
    pf.overwrite_body(data);
    let _ = decode_prepare(&pf.sqe, &pf.table, pf.section(), pf.owner);

    let cf = CommitFixture::build();
    cf.overwrite_body(data);
    let _ = decode_commit(&cf.sqe, &cf.table, cf.section(), cf.owner);
});
