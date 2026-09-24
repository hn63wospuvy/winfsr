//! End-to-end QUERY_DIR: decode a granted `QueryDirV2` through the A2 grant
//! layer and enumerate a directory through the volatile `DirEnumerator`,
//! including the initial batch, a cookie continuation, and (on Windows, outside
//! Miri) an OS-backed name-match vector via the slice-3 predicate.
//!
//! Gated on `testkit` (the kernel-role fixtures live there).
#![cfg(feature = "testkit")]

use fsring_abi::codec::try_decode;
use fsring_abi::ids::{FileId, LinkId};
use fsring_abi::msgs::{file_attributes, QueryDirResultV1, SizeState};
use fsring_abi::validate::validate_query_dir_result_v1;

use fsring_user::testkit::QueryDirFixture;
use fsring_user::{decode_query_dir, DirCandidate, DirEntryFields, DirEnumerator};

const KOID: u64 = 0x33;

fn cand(name: &str) -> DirCandidate {
    let bytes: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    DirCandidate {
        name: bytes.into_boxed_slice(),
        fields: DirEntryFields {
            file_id: FileId { lo: 1, hi: 0 },
            link_id: LinkId { lo: 1, hi: 0 },
            sizes: SizeState {
                allocation_size: 0,
                file_size: 0,
                valid_data_length: 0,
                size_epoch: 1,
            },
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            namespace_generation: 1,
            attributes: file_attributes::NORMAL,
        },
    }
}

/// Re-validate an emitted batch blob for its input cookie.
fn validates(blob: &[u8], input_cookie: u64) {
    let result: QueryDirResultV1 = try_decode(blob).expect("decode result");
    validate_query_dir_result_v1(&result, blob, input_cookie).expect("batch validates");
}

#[test]
fn match_all_enumerate_then_continue() {
    let mut eng = DirEnumerator::new();

    // Initial: decode a granted MatchAll query and enumerate all three entries.
    let fx = QueryDirFixture::match_all();
    let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode initial");
    let candidates = vec![cand("a.txt"), cand("b.txt"), cand("c.txt")];
    let first = eng.open(KOID, &req, candidates).expect("open");
    assert_eq!(first.entry_count, 3);
    assert!(first.eof);
    validates(&first.blob, 0);

    // Continuation: decode a granted continuation (cookie 1) and re-batch from
    // position 1 of the immutable snapshot (a stable ordinal, not a cursor).
    let cf = QueryDirFixture::continuation(1);
    let creq = decode_query_dir(&cf.sqe, &cf.table, cf.section(), cf.owner).expect("decode cont");
    let second = eng.continue_(KOID, &creq).expect("continue");
    assert_eq!(second.entry_count, 2);
    assert!(second.eof);
    assert_eq!(second.next_cookie, 0);
    validates(&second.blob, 1);
}

// The expression path compiles the pattern through the OS-backed slice-3 name
// matcher, so this vector only runs on Windows outside Miri.
#[cfg(all(windows, not(miri)))]
#[test]
fn expression_filters_via_the_os_predicate() {
    let mut eng = DirEnumerator::new();
    let pattern: Vec<u16> = "*.txt".encode_utf16().collect();
    let fx = QueryDirFixture::expression(&pattern, false);
    let req = decode_query_dir(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
    // `*.txt` matches `FILE.TXT` (the slice-3 upcase case) but not `a.bin`.
    let candidates = vec![cand("FILE.TXT"), cand("a.bin")];
    let batch = eng.open(KOID, &req, candidates).expect("open");
    assert_eq!(batch.entry_count, 1, "only FILE.TXT matches *.txt");
    assert!(batch.eof);
    validates(&batch.blob, 0);
}
