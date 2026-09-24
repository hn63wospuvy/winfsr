#![no_main]
//! Fuzz the QUERY_DIR decoder: an attacker-chosen `QueryDirV2` control blob
//! behind a valid grant must be decoded or rejected without panicking or reading
//! out of bounds. The outer grant + SQE stay valid, so decode reaches
//! `try_decode` + `validate_query_dir_v2` over arbitrary blob bytes.

use libfuzzer_sys::fuzz_target;

use fsring_user::decode_query_dir;
use fsring_user::testkit::QueryDirFixture;

fuzz_target!(|data: &[u8]| {
    // A 64-byte MatchAll blob overwritten with arbitrary bytes.
    let fx = QueryDirFixture::match_all();
    fx.overwrite_blob(data);
    let _ = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner);

    // A larger (> 64-byte) Expression blob, so a fuzzed blob can classify as
    // InitialExpression and drive the pattern-tail extraction path too.
    let pattern: Vec<u16> = "*.txt".encode_utf16().collect();
    let ex = QueryDirFixture::expression(&pattern, false);
    ex.overwrite_blob(data);
    let _ = decode_query_dir(&ex.sqe, &ex.table, ex.section(), ex.owner);
});
