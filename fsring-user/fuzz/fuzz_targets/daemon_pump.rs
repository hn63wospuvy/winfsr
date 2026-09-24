#![no_main]
//! Fuzz `Daemon::pump_once` against an arbitrary SQE. `pump_once` composes
//! every E1 layer -- decode, grant resolve, open-lifecycle, dir enumeration,
//! result build, `write_body` -- each already soaked by its own fuzz target
//! (`grant_resolve`, `mutation_decode`, `query_security_decode`, ...); this
//! target is the integration proof over the one entry point a hostile kernel
//! role drives: a malformed opcode/payload must classify to a `DaemonError`
//! (or, if it happens to decode as a legal request, post a legal completion)
//! -- never panic, never touch memory outside the section.

use fsring_abi::layout::{SqeBody, SQE_PAYLOAD_LEN};
use fsring_user::testkit::{Harness, StubFileSystem};
use fsring_user::{Daemon, GrantTable};
use libfuzzer_sys::fuzz_target;

/// Header bytes preceding the payload: opcode(2) + flags(2) + payload_len(2)
/// + reserved(2) + req_id(8) + kernel_open_id(8) + ccb_sequence(8).
const HEADER_LEN: usize = 32;
const TOTAL_LEN: usize = HEADER_LEN + SQE_PAYLOAD_LEN;

fuzz_target!(|data: &[u8]| {
    // Fresh harness + table + stub filesystem + daemon per input: `Daemon::new`
    // consumes the `GrantTable` by value, and a live grant from one input must
    // never leak into another input's resolution.
    let harness = Harness::new_single_ring();
    let table = GrantTable::new(harness.session_epoch());
    let mut fs = StubFileSystem::default();

    // Carve one whole SqeBody out of the fuzz bytes (short input zero-fills);
    // opcode, every other header field, and the full payload are all
    // fuzz-driven, so the decode + grant-resolve error paths run over
    // arbitrary bytes, not just a fixed shape's opcode.
    let mut b = [0u8; TOTAL_LEN];
    let n = data.len().min(b.len());
    b[..n].copy_from_slice(&data[..n]);

    let mut payload = [0u8; SQE_PAYLOAD_LEN];
    payload.copy_from_slice(&b[HEADER_LEN..TOTAL_LEN]);
    let sqe = SqeBody {
        opcode: u16::from_le_bytes(b[0..2].try_into().unwrap()),
        flags: u16::from_le_bytes(b[2..4].try_into().unwrap()),
        payload_len: u16::from_le_bytes(b[4..6].try_into().unwrap()),
        reserved: u16::from_le_bytes(b[6..8].try_into().unwrap()),
        req_id: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        kernel_open_id: u64::from_le_bytes(b[16..24].try_into().unwrap()),
        ccb_sequence: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        payload,
    };

    let kernel = harness.kernel_ring();
    let _receipt = kernel
        .submit(sqe)
        .expect("an empty single-ring SQ always has room for one request");
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    // Never panics/UB: a malformed request classifies to a `DaemonError`; a
    // well-formed-enough one posts a legal completion.
    let _ = daemon.pump_once();
});
