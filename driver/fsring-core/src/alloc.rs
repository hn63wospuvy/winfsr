//! Fallible kernel allocation (`11-rust-implementation.md` sections 4 and 5).
//!
//! No `#[global_allocator]` exists in this driver. One exists to make `alloc`'s
//! infallible APIs work, which is precisely the path section 5 forbids: every
//! allocation goes through [`try_alloc`] and returns a `Result`.
//!
//! The pool choice is a total function over the profile. `ExAllocatePool2` — the
//! modern "stronger allocator" section 4 permits — is **not** used as a static
//! import: it is `NTDDI_WIN10_VB` (Windows 10 2004), newer than the modern
//! profile's Windows 10 1507 floor, so `00-INDEX.md` section 5 requires it to be
//! runtime-resolved. See [`crate::resolver`].

use fsring_abi::features::PlatformProfile;

/// `NonPagedPool` — the Win7 legacy pool, no NX guarantee on that baseline.
pub const POOL_NON_PAGED: i32 = 0;
/// `NonPagedPoolNx` — non-paged, no-execute. Present since Windows 8, so it is
/// available at the modern profile's Windows 10 1507 floor.
pub const POOL_NON_PAGED_NX: i32 = 512;

/// Which allocator to call.
///
/// `11-rust-implementation.md` section 4 permits "a dynamically resolved
/// stronger allocator obtained through the `MmGetSystemRoutineAddress` rule".
/// That is `ExAllocatePool2`, and it is only reachable when
/// [`crate::resolver`] latched its address, so the choice is a function of the
/// resolution outcome and not of the profile alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allocator {
    /// The baseline path: `ExAllocatePoolWithTag`, present at every supported
    /// baseline, taking a `POOL_TYPE`.
    PoolWithTag,
    /// The stronger path: `ExAllocatePool2`, taking `POOL_FLAGS`. Selected only
    /// when the optional DDI resolved.
    Pool2,
}

/// `POOL_FLAG_NON_PAGED` — non-paged NX pool, for the `ExAllocatePool2` path.
/// Hand-ported by `wdk-sys` in its own `src/constants.rs`; mirrored here
/// because `fsring-core` is WDK-free.
pub const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;

/// Which pool the profile allocates from, and what it owes afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolPolicy {
    /// Which allocator to call.
    pub allocator: Allocator,
    /// The `POOL_FLAGS` word for the [`Allocator::Pool2`] path.
    pub pool_flags: u64,
    /// The `POOL_TYPE` discriminant to pass to `ExAllocatePoolWithTag`.
    pub pool_type: i32,
    /// Whether the caller must zero the block before publishing it.
    ///
    /// The Win7 baseline has no `NonPagedPoolNx` and no zeroing guarantee, so
    /// the legacy profile owes an explicit zeroing (section 4). The modern
    /// profile does not, because it allocates from the NX pool and publishes
    /// nothing before initialising it.
    pub must_zero: bool,
}

/// The allocator decision for a profile and a resolution outcome. Total over
/// both inputs: three profiles times two outcomes.
///
/// The legacy profile never takes the stronger path even when the address
/// resolves, because a Win7 kernel does not export `ExAllocatePool2` at all —
/// a resolution success there would mean the probe answered about a different
/// symbol, and trusting it would be worse than ignoring it.
pub const fn pool_policy(profile: PlatformProfile, pool2_available: bool) -> PoolPolicy {
    match profile {
        PlatformProfile::Win7X64 => PoolPolicy {
            allocator: Allocator::PoolWithTag,
            pool_flags: POOL_FLAG_NON_PAGED,
            pool_type: POOL_NON_PAGED,
            must_zero: true,
        },
        PlatformProfile::Win10X64 | PlatformProfile::Win10Arm64 => PoolPolicy {
            allocator: if pool2_available {
                Allocator::Pool2
            } else {
                Allocator::PoolWithTag
            },
            pool_flags: POOL_FLAG_NON_PAGED,
            pool_type: POOL_NON_PAGED_NX,
            must_zero: false,
        },
    }
}

/// Why an allocation did not happen. Never a panic, never an abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// The kernel returned no memory.
    OutOfMemory,
    /// A zero-byte request, which is a caller bug rather than memory pressure.
    ZeroSized,
}

/// The raw pool, behind a seam so the host can inject failure.
pub trait RawPool {
    /// Returns a null pointer on failure, exactly as `ExAllocatePoolWithTag`
    /// does.
    fn allocate(&mut self, policy: PoolPolicy, bytes: usize) -> *mut u8;
}

/// Allocate, or fail. The only allocation entry point in the driver.
pub fn try_alloc<P: RawPool>(
    pool: &mut P,
    policy: PoolPolicy,
    bytes: usize,
) -> Result<*mut u8, AllocError> {
    if bytes == 0 {
        return Err(AllocError::ZeroSized);
    }
    let raw = pool.allocate(policy, bytes);
    if raw.is_null() {
        return Err(AllocError::OutOfMemory);
    }
    if policy.must_zero {
        // The obligation lives HERE, not in the `RawPool` implementation, so a
        // second implementation - a lookaside, a per-mount pool - cannot forget
        // it. `11-rust-implementation.md` section 4 makes zeroing before
        // publication normative for the legacy allocator.
        // SAFETY: the allocation succeeded, so `raw` is valid for `bytes`.
        unsafe { core::ptr::write_bytes(raw, 0, bytes) };
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::features::PlatformProfile::{Win7X64, Win10Arm64, Win10X64};

    struct NullPool;
    impl RawPool for NullPool {
        fn allocate(&mut self, _policy: PoolPolicy, _bytes: usize) -> *mut u8 {
            core::ptr::null_mut()
        }
    }

    /// Hands back a buffer pre-filled with 0xAA, so a test can tell whether the
    /// zeroing obligation was actually discharged.
    struct PoisonedPool {
        buf: [u8; 16],
        asked: Option<(PoolPolicy, usize)>,
    }
    impl PoisonedPool {
        fn new() -> Self {
            Self {
                buf: [0xAA; 16],
                asked: None,
            }
        }
    }
    impl RawPool for PoisonedPool {
        fn allocate(&mut self, policy: PoolPolicy, bytes: usize) -> *mut u8 {
            self.asked = Some((policy, bytes));
            self.buf.as_mut_ptr()
        }
    }

    #[test]
    fn a_null_return_is_an_error_not_a_panic() {
        let r = try_alloc(&mut NullPool, pool_policy(Win10X64, false), 16);
        assert_eq!(r, Err(AllocError::OutOfMemory));
    }

    #[test]
    fn zero_sized_requests_are_rejected_before_the_kernel_is_asked() {
        assert_eq!(
            try_alloc(&mut NullPool, pool_policy(Win10X64, true), 0),
            Err(AllocError::ZeroSized)
        );
    }

    #[test]
    fn a_successful_allocation_passes_the_policy_through() {
        let mut p = PoisonedPool::new();
        let policy = pool_policy(Win10X64, false);
        assert!(try_alloc(&mut p, policy, 8).is_ok());
        assert_eq!(p.asked, Some((policy, 8)));
    }

    #[test]
    fn the_seam_zeroes_for_the_legacy_profile() {
        // The obligation is discharged by try_alloc, not by the RawPool
        // implementation, so a future pool cannot forget it.
        let mut p = PoisonedPool::new();
        assert!(try_alloc(&mut p, pool_policy(Win7X64, false), 16).is_ok());
        assert_eq!(
            p.buf, [0u8; 16],
            "the legacy profile owes an explicit zeroing"
        );
    }

    #[test]
    fn the_seam_does_not_zero_for_the_modern_profile() {
        // Modern allocates from the NX pool and publishes nothing before
        // initialising it; zeroing here would be wasted work on every request.
        let mut p = PoisonedPool::new();
        assert!(try_alloc(&mut p, pool_policy(Win10X64, false), 16).is_ok());
        assert_eq!(p.buf, [0xAAu8; 16]);
    }

    #[test]
    fn the_legacy_profile_owes_zeroing_and_uses_the_non_nx_pool() {
        for available in [false, true] {
            let p = pool_policy(Win7X64, available);
            assert_eq!(p.pool_type, POOL_NON_PAGED);
            assert!(
                p.must_zero,
                "the Win7 baseline has no NX pool and no zeroing guarantee"
            );
            assert_eq!(
                p.allocator,
                Allocator::PoolWithTag,
                "a Win7 kernel does not export ExAllocatePool2 at all, so a                  resolution success there must not be trusted"
            );
        }
    }

    #[test]
    fn the_modern_profiles_use_the_nx_pool_and_owe_no_zeroing() {
        for profile in [Win10X64, Win10Arm64] {
            for available in [false, true] {
                let p = pool_policy(profile, available);
                assert_eq!(p.pool_type, POOL_NON_PAGED_NX);
                assert!(!p.must_zero);
            }
        }
    }

    #[test]
    fn the_resolved_capability_actually_changes_the_selected_allocator() {
        // Without this the resolver would be decoration: both branches of the
        // resolution would behave identically and nothing would notice.
        for profile in [Win10X64, Win10Arm64] {
            assert_eq!(pool_policy(profile, true).allocator, Allocator::Pool2);
            assert_eq!(
                pool_policy(profile, false).allocator,
                Allocator::PoolWithTag
            );
        }
    }

    #[test]
    fn the_pool_discriminants_match_the_kernel_values() {
        // Cross-checked against the generated wdk-sys POOL_TYPE enum and
        // wdk-sys's hand-ported POOL_FLAG_NON_PAGED; fsring-core is WDK-free,
        // so these are pinned rather than imported.
        assert_eq!(POOL_NON_PAGED, 0);
        assert_eq!(POOL_NON_PAGED_NX, 512);
        assert_eq!(POOL_FLAG_NON_PAGED, 0x40);
    }
}
