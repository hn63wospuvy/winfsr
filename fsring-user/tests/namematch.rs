//! Canonical `FsRtlIsNameInExpression` vectors: proves the SDK matcher is wired
//! to the OS routine (five wildcards + case-insensitivity via the OS upcase
//! table). The match itself is the OS's contract; these lock in that our FFI
//! calls it correctly. Windows-only, non-Miri (foreign calls).
#![cfg(all(windows, not(miri)))]

use fsring_user::{name_in_expression, NameMatcher};

fn u16s(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn matches(pattern: &str, name: &str) -> bool {
    name_in_expression(&u16s(pattern), &u16s(name)).expect("compile ok on windows")
}

#[test]
fn literal_and_case_insensitivity() {
    assert!(matches("foo.txt", "foo.txt"));
    assert!(matches("foo.txt", "FOO.TXT"));
    // The killer case: the expression is lowercase and the NAME is uppercase.
    // RtlIsNameInExpression upcases only the name, so this passes ONLY if the
    // expression was pre-upcased by RtlUpcaseUnicodeString at compile time.
    assert!(matches("*.txt", "FILE.TXT"));
    assert!(!matches("foo.txt", "bar.txt"));
}

#[test]
fn non_ascii_case_folding_uses_the_os_table() {
    // ä (U+00E4) in the pattern must match Ä (U+00C4) in the name — a case fold
    // a naive ASCII-only matcher would miss, which is why §12.11 uses the OS.
    assert!(matches("\u{00e4}.txt", "\u{00c4}.TXT"));
}

#[test]
fn star_and_question() {
    assert!(matches("*", "anything"));
    assert!(matches("*.txt", "foo.txt"));
    assert!(!matches("*.txt", "foo.doc"));
    assert!(matches("a?c", "abc"));
    assert!(!matches("a?c", "ac")); // ? requires exactly one character
    assert!(matches("foo*", "foobar"));
    assert!(matches("*bar", "foobar"));
}

#[test]
fn dos_meta_characters_are_wildcards() {
    // DOS_STAR '<' spans up to the final dot; DOS_QM '>' a single char; DOS_DOT
    // '"' a period or end-of-name. Expected values are the authoritative OS
    // results (reconciled at GREEN if an assumption is off — the OS wins per
    // §12.11); the point is they are treated as wildcards, not literals.
    assert!(matches("<.txt", "foo.txt")); // DOS_STAR
    assert!(matches("a>c", "abc")); // DOS_QM matches the single 'b'
    assert!(matches("foo\"", "foo")); // DOS_DOT matches end-of-name
}

#[test]
fn match_all_from_empty_pattern() {
    let m = NameMatcher::compile(&[]).expect("compile");
    assert!(m.matches(&u16s("literally.anything")));
}

#[test]
fn empty_candidate_name_against_expression() {
    // The empty candidate name through the OS routine against a non-empty
    // Expression (distinct from MatchAll, which short-circuits before FFI).
    // Per §12.11 the OS result is authoritative — and it reports that an empty
    // candidate name matches NOTHING, not even '*' (verified against ntdll;
    // production names are never empty per validate_stored_component_utf16).
    assert!(!matches("*", ""));
    assert!(!matches("foo.txt", ""));
}
