#![no_main]
//! Fuzz the U2K write-back trust boundary: `grant::write_body` must never
//! OOB/UB on any input. Against a fresh U2K grant of a fuzz-varied length `L`
//! (1..=2048, the u2k class-0 slot size), resolved to a `ValidatedBuffer`, the
//! remaining fuzz bytes are written through `write_body` at their own
//! arbitrary length. Most inputs (length != L) hit `GrantError::LengthMismatch`;
//! an L-length input hits the guarded copy path -- the host soak for
//! `write_body`'s single `unsafe` write, mirroring `grant_resolve.rs`'s soak of
//! the read side (`resolve_body`).

use fsring_abi::ids::ReqId;
use fsring_abi::slots::{BufferRefPolicy, GrantOwner, SlotToken};
use fsring_user::testkit::Harness;
use fsring_user::{write_body, GrantTable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Fresh section + arena + one U2K grant per input.
    let harness = Harness::new_single_ring();
    let arena = harness.u2k_arena();
    let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
    let token = SlotToken::try_new(0, 0, 1).unwrap();

    // `L`, the grant's length, is fuzz-varied over [1, 2048] (the u2k class-0
    // slot size) from up to the first two fuzz bytes, so both the
    // LengthMismatch and copy paths are reached for varied grant sizes, not
    // just a single fixed L.
    let raw = u16::from_le_bytes([data[0], data.get(1).copied().unwrap_or(0)]);
    let length = 1 + (u32::from(raw) % 2048);
    let mut table = GrantTable::new(harness.session_epoch());
    let issued = table
        .issue_u2k(&arena, owner, token, length)
        .expect("length in [1, 2048] is always a valid u2k grant");
    let validated = table
        .resolve(&issued, owner, BufferRefPolicy::Exact)
        .expect("the just-issued reference always resolves");

    // The rest of the fuzz bytes are the write source, at its own arbitrary
    // length: write_body must reject anything != `length` and, on a match,
    // copy exactly `length` bytes without OOB/UB.
    let source = &data[data.len().min(2)..];
    let _ = write_body(harness.section(), &validated, source);
});
