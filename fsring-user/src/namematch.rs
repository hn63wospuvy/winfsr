//! The daemon-SDK name-match helper: a `NameMatcher` that decides whether a
//! directory entry satisfies a `QUERY_DIR` search pattern, byte-identical to the
//! kernel's `FsRtlIsNameInExpression` because it calls the same OS routine
//! (`RtlIsNameInExpression`, `IgnoreCase=TRUE`, null table) over an OS-upcased
//! expression. See `05-irp-dispatch.md` §12.11 and the slice-3 design. The ABI
//! bounds a pattern/name to `fsring_abi::limits::MAX_COMPONENT_UTF16_CODE_UNITS`
//! (255); this helper additionally guards `MAX_MATCH_UNITS` for its own safety.

/// Reject a pattern/name longer than this many UTF-16 code units so a
/// `UNICODE_STRING` byte `Length` (`len*2`) never overflows `u16`.
const MAX_MATCH_UNITS: usize = 0x7FFF;

/// A compiled `QUERY_DIR` search pattern.
pub enum NameMatcher {
    /// The `InitialMatchAll` form (empty pattern): matches every name, no FFI.
    MatchAll,
    /// A literal/wildcard expression, upcased once through the OS table.
    ///
    /// Invariant (established by [`NameMatcher::compile`]): the buffer is
    /// OS-upcased and at most `MAX_MATCH_UNITS` code units. Constructing this
    /// variant directly bypasses `compile`: `matches` still defends memory
    /// safety (an over-long buffer is a non-match, never an out-of-bounds read),
    /// but a non-upcased buffer yields case-wrong results that diverge from the
    /// OS routine — prefer `compile`.
    Expression(Box<[u16]>),
}

/// Why compiling a pattern failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameMatchError {
    /// Pattern exceeds `MAX_MATCH_UNITS` (would overflow a `UNICODE_STRING`).
    TooLong,
    /// The OS `RtlUpcaseUnicodeString` returned a failure status.
    UpcaseFailed,
    /// Non-Windows target or Miri: only `MatchAll` (empty pattern) is available.
    Unsupported,
}

impl NameMatcher {
    /// Compile a validated pattern. Upcases a non-empty expression once.
    pub fn compile(pattern: &[u16]) -> Result<NameMatcher, NameMatchError> {
        if pattern.len() > MAX_MATCH_UNITS {
            return Err(NameMatchError::TooLong);
        }
        if pattern.is_empty() {
            return Ok(NameMatcher::MatchAll);
        }
        upcase(pattern).map(NameMatcher::Expression)
    }

    /// Whether `name` matches this pattern. Infallible; an over-long name is a
    /// non-match rather than an error.
    pub fn matches(&self, name: &[u16]) -> bool {
        match self {
            NameMatcher::MatchAll => true,
            NameMatcher::Expression(upcased) => matches_expression(upcased, name),
        }
    }
}

/// Compile `pattern` then test `name` in one call.
pub fn name_in_expression(pattern: &[u16], name: &[u16]) -> Result<bool, NameMatchError> {
    Ok(NameMatcher::compile(pattern)?.matches(name))
}

#[cfg(all(windows, not(miri)))]
mod sys {
    pub type NtStatus = i32;
    pub type Boolean = u8;
    pub const TRUE: Boolean = 1;
    pub const STATUS_SUCCESS: NtStatus = 0;

    #[repr(C)]
    pub struct UnicodeString {
        pub length: u16,
        pub maximum_length: u16,
        pub buffer: *mut u16,
    }

    #[link(name = "ntdll")]
    extern "system" {
        pub fn RtlUpcaseUnicodeString(
            dst: *mut UnicodeString,
            src: *const UnicodeString,
            allocate: Boolean,
        ) -> NtStatus;
        pub fn RtlIsNameInExpression(
            expression: *const UnicodeString,
            name: *const UnicodeString,
            ignore_case: Boolean,
            upcase_table: *mut u16,
        ) -> Boolean;
    }
}

#[cfg(all(windows, not(miri)))]
fn upcase(pattern: &[u16]) -> Result<Box<[u16]>, NameMatchError> {
    let mut upcased = vec![0u16; pattern.len()];
    let bytes = (pattern.len() * 2) as u16; // guarded <= 0xFFFE
    let src = sys::UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: pattern.as_ptr() as *mut u16,
    };
    let mut dst = sys::UnicodeString {
        length: 0,
        maximum_length: bytes,
        buffer: upcased.as_mut_ptr(),
    };
    // SAFETY: `src.buffer`/`dst.buffer` reference `pattern` and `upcased`, each
    // `pattern.len()` live u16s, for the duration of this call; the byte lengths
    // come from a guarded `len*2 <= 0xFFFE`; `allocate = 0` (FALSE) and
    // `dst.maximum_length == src.length`, so the routine writes at most that many
    // bytes into `upcased`.
    let status = unsafe { sys::RtlUpcaseUnicodeString(&mut dst, &src, 0) };
    if status != sys::STATUS_SUCCESS {
        return Err(NameMatchError::UpcaseFailed);
    }
    Ok(upcased.into_boxed_slice())
}

#[cfg(not(all(windows, not(miri))))]
fn upcase(_pattern: &[u16]) -> Result<Box<[u16]>, NameMatchError> {
    Err(NameMatchError::Unsupported)
}

#[cfg(all(windows, not(miri)))]
fn matches_expression(upcased: &[u16], name: &[u16]) -> bool {
    // Guard BOTH lengths: `name` is caller input, and `upcased` may come from an
    // `Expression` constructed directly (bypassing `compile`'s guard). An
    // over-long side is a non-match, never a truncated `UNICODE_STRING` length.
    if upcased.len() > MAX_MATCH_UNITS || name.len() > MAX_MATCH_UNITS {
        return false;
    }
    let expr = sys::UnicodeString {
        length: (upcased.len() * 2) as u16,
        maximum_length: (upcased.len() * 2) as u16,
        buffer: upcased.as_ptr() as *mut u16,
    };
    let name = sys::UnicodeString {
        length: (name.len() * 2) as u16,
        maximum_length: (name.len() * 2) as u16,
        buffer: name.as_ptr() as *mut u16,
    };
    // SAFETY: both buffers reference live u16 slices for the duration of this
    // call; the byte lengths come from guarded `len*2 <= 0xFFFE`. With
    // `ignore_case = TRUE` and `upcase_table = null`, the routine upcases the
    // name internally via the OS table and does not write through either buffer.
    unsafe { sys::RtlIsNameInExpression(&expr, &name, sys::TRUE, core::ptr::null_mut()) != 0 }
}

#[cfg(not(all(windows, not(miri))))]
fn matches_expression(_upcased: &[u16], _name: &[u16]) -> bool {
    // Unreachable in practice: `Expression` is only built on windows+non-miri
    // (compile returns `Unsupported` elsewhere). The arm must type-check anyway.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16s(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn empty_pattern_compiles_to_match_all() {
        assert!(matches!(
            NameMatcher::compile(&[]),
            Ok(NameMatcher::MatchAll)
        ));
    }

    #[test]
    fn match_all_matches_every_name() {
        let m = NameMatcher::MatchAll;
        assert!(m.matches(&[]));
        assert!(m.matches(&u16s("anything.txt")));
        assert!(m.matches(&u16s("\u{00c4}\u{4e2d}")));
    }

    #[test]
    fn overlong_pattern_is_too_long() {
        let pattern = vec![0x41u16; MAX_MATCH_UNITS + 1];
        assert!(matches!(
            NameMatcher::compile(&pattern),
            Err(NameMatchError::TooLong)
        ));
    }

    #[test]
    fn overlong_name_never_matches() {
        // Directly construct an `Expression` (bypassing `compile`) to reach the
        // name length guard. On windows+non-miri this exercises the real guard
        // in `matches_expression`; off-windows/miri it hits the
        // unconditional-false stub. Either way an over-long name is a non-match
        // (success criterion §3.3 #4).
        let m = NameMatcher::Expression(vec![0x41u16; 1].into_boxed_slice());
        assert!(!m.matches(&vec![0x41u16; MAX_MATCH_UNITS + 1]));
    }

    #[test]
    fn overlong_expression_never_matches() {
        // A directly-constructed over-long `Expression` (bypassing `compile`'s
        // guard) is a non-match rather than a truncated-length wrong match.
        let m = NameMatcher::Expression(vec![0x41u16; MAX_MATCH_UNITS + 1].into_boxed_slice());
        assert!(!m.matches(&[0x41u16]));
    }
}
