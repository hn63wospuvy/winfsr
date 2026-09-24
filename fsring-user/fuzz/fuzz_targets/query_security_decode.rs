#![no_main]
//! Fuzz the QUERY_SECURITY decoder: an attacker-chosen `QuerySecurityV1`
//! control blob behind a valid grant must be decoded or rejected without
//! panicking or reading out of bounds. Two paths per input:
//!
//! - Path A (`overwrite_blob`): the full 40-byte blob, including the `output`
//!   `BufferRef`, is attacker-chosen. This exercises memory safety over
//!   arbitrary bytes, but the fuzzed `output.token` almost never matches an
//!   issued grant, so `decode_query_security` usually bails at `grant_for`
//!   (`UnknownToken`) before ever reaching `validate_query_security_v1`.
//! - Path B (`overwrite_scalars`): only the 16-byte scalar prefix (`header` +
//!   `security_information` + `flags`) is attacker-chosen; the `output`
//!   `BufferRef` is re-encoded from the fixture's real issued grant. This
//!   reliably reaches `validate_query_security_v1`'s mask/flags/version/length
//!   gates instead of bailing early on an unknown token.

use libfuzzer_sys::fuzz_target;

use fsring_user::decode_query_security;
use fsring_user::testkit::QuerySecurityFixture;

fuzz_target!(|data: &[u8]| {
    let fx = QuerySecurityFixture::valid();
    fx.overwrite_blob(data);
    let _ = decode_query_security(&fx.sqe, &fx.table, fx.section(), fx.owner);

    let fx2 = QuerySecurityFixture::valid();
    fx2.overwrite_scalars(data);
    let _ = decode_query_security(&fx2.sqe, &fx2.table, fx2.section(), fx2.owner);
});
