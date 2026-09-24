//! Fail-closed randomness (`11-rust-implementation.md` section 4).
//!
//! All kernel randomness comes from `BCryptGenRandom` with the system-preferred
//! RNG, at PASSIVE_LEVEL. Time, counters, PIDs, `RtlRandom*` and daemon-supplied
//! bytes are **never** entropy, and there is **no weaker fallback**: a failure
//! fails the operation.
//!
//! `RtlRandom` and `RtlRandomEx` are bound by `wdk-sys` and forbidden here, so
//! `driver/fsring-core/tests/extern_quarantine.rs` asserts no driver source
//! mentions them. A rule that is only written down is not a rule.
//!
//! A required nonzero field is drawn into a private zeroed buffer and retried at
//! most eight times if the complete sampled integer is zero; eight consecutive
//! zero samples fail closed.

/// The maximum number of draws before failing closed. Section 4 fixes it at 8.
pub const MAX_DRAWS: u32 = 8;

/// Why a draw produced nothing. There is no "degraded" outcome by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    /// The source failed. There is no weaker fallback.
    SourceFailed,
    /// Eight consecutive samples were zero.
    ExhaustedRetries,
}

/// A fallible byte source. The kernel implementation wraps `BCryptGenRandom`.
pub trait RandomSource {
    /// Fill the buffer with cryptographically strong bytes, or fail.
    fn fill(&mut self, out: &mut [u8; 8]) -> Result<(), RandomError>;
}

/// Draw a nonzero `u64`, or fail closed.
pub fn draw_nonzero<S: RandomSource>(source: &mut S) -> Result<u64, RandomError> {
    let mut attempt = 0u32;
    while attempt < MAX_DRAWS {
        // A private buffer, zeroed each round: no sample leaks into the next.
        let mut buf = [0u8; 8];
        source.fill(&mut buf)?;
        let value = u64::from_le_bytes(buf);
        if value != 0 {
            return Ok(value);
        }
        attempt = attempt.saturating_add(1);
    }
    Err(RandomError::ExhaustedRetries)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scripted {
        values: [u64; 9],
        at: usize,
        fail_at: Option<usize>,
    }

    impl RandomSource for Scripted {
        fn fill(&mut self, out: &mut [u8; 8]) -> Result<(), RandomError> {
            if self.fail_at == Some(self.at) {
                return Err(RandomError::SourceFailed);
            }
            let v = self.values.get(self.at).copied().unwrap_or(0);
            self.at = self.at.saturating_add(1);
            *out = v.to_le_bytes();
            Ok(())
        }
    }

    fn scripted(values: [u64; 9], fail_at: Option<usize>) -> Scripted {
        Scripted {
            values,
            at: 0,
            fail_at,
        }
    }

    #[test]
    fn the_first_nonzero_sample_is_returned() {
        let mut s = scripted([7, 0, 0, 0, 0, 0, 0, 0, 0], None);
        assert_eq!(draw_nonzero(&mut s), Ok(7));
        assert_eq!(s.at, 1, "a good first sample must not cost a second draw");
    }

    #[test]
    fn seven_zeros_then_a_value_still_succeeds() {
        let mut s = scripted([0, 0, 0, 0, 0, 0, 0, 42, 0], None);
        assert_eq!(draw_nonzero(&mut s), Ok(42));
    }

    #[test]
    fn eight_consecutive_zeros_fail_closed() {
        let mut s = scripted([0; 9], None);
        assert_eq!(draw_nonzero(&mut s), Err(RandomError::ExhaustedRetries));
    }

    #[test]
    fn a_source_error_fails_closed_immediately() {
        let mut s = scripted([0; 9], Some(0));
        assert_eq!(draw_nonzero(&mut s), Err(RandomError::SourceFailed));
        assert_eq!(s.at, 0, "an error must not be retried into a weaker answer");
    }

    #[test]
    fn a_source_error_after_some_zeros_still_fails_closed() {
        let mut s = scripted([0; 9], Some(3));
        assert_eq!(draw_nonzero(&mut s), Err(RandomError::SourceFailed));
    }

    #[test]
    fn the_draw_never_exceeds_the_mandated_retry_count() {
        let mut s = scripted([0; 9], None);
        let _ = draw_nonzero(&mut s);
        assert_eq!(
            u32::try_from(s.at).unwrap_or(u32::MAX),
            MAX_DRAWS,
            "section 4 fixes the count at eight"
        );
    }
}
