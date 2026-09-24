#![no_main]
//! Fuzz the grant-resolution trust boundary: against a fixed section holding one
//! real k2u grant, an arbitrary peer `BufferRef` fed through
//! `GrantTable::resolve` + `resolve_body` must never panic or read out of
//! bounds, and any body it returns must lie within the section. This is the
//! host soak for the single most safety-critical operation in the SDK.

use fsring_abi::ids::ReqId;
use fsring_abi::msgs::BufferRef;
use fsring_abi::slots::{BufferRefPolicy, GrantOwner, SlotToken};
use fsring_user::testkit::Harness;
use fsring_user::{resolve_body, GrantTable, SharedSection};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fixed section + arena + one real grant; only the peer's BufferRef is fuzzed.
    let harness = Harness::new_single_ring();
    let arena = harness.k2u_arena();
    let owner = GrantOwner::Request(ReqId::from_raw(0x0001_0000_0001));
    let token = SlotToken::try_new(0, 0, 1).unwrap();
    harness.write_slot(&arena, token, &[0u8; 24]);
    let mut table = GrantTable::new(harness.session_epoch());
    let _issued = table.issue_k2u(&arena, owner, token, 24).unwrap();

    // Carve an arbitrary BufferRef from the fuzz bytes (short input zero-fills).
    let mut b = [0u8; 24];
    let n = data.len().min(b.len());
    b[..n].copy_from_slice(&data[..n]);
    let reference = BufferRef {
        token: u64::from_le_bytes(b[0..8].try_into().unwrap()),
        offset: u32::from_le_bytes(b[8..12].try_into().unwrap()),
        length: u32::from_le_bytes(b[12..16].try_into().unwrap()),
        kind: u16::from_le_bytes(b[16..18].try_into().unwrap()),
        access: u16::from_le_bytes(b[18..20].try_into().unwrap()),
        reserved: u32::from_le_bytes(b[20..24].try_into().unwrap()),
    };

    for policy in [
        BufferRefPolicy::Exact,
        BufferRefPolicy::ShrinkOnly,
        BufferRefPolicy::DerivedSubrange,
    ] {
        if let Ok(validated) = table.resolve(&reference, owner, policy) {
            let range = validated.section_range().expect("a resolved slot has a range");
            // Load-bearing: the validated range stays inside the section, and the
            // fetched body is exactly the range's length (catches a mis-sized copy,
            // not merely a non-panic).
            assert!(range.end <= harness.section().len() as u64);
            if let Ok(view) = resolve_body(harness.section(), &validated) {
                assert_eq!(view.len() as u64, range.end - range.start);
            }
        }
    }
});
