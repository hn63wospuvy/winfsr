//! WDK-free ordered effect plans executed by the native driver adapters.
//!
//! Every module here states one native choreography as pure data: which effect
//! comes next, which outcome that effect may report, and — when an effect fails
//! — exactly which of the resources already acquired must be released, in which
//! order. `fsring-fsd` translates one typed effect into exactly one native call
//! and reports the matching outcome; it never restates the transition order.
//!
//! A plan is an *ordering and ownership model*, not a resource owner. It never
//! claims that a handle, mapping, device, or registration exists: only the
//! native executor can supply that evidence, and the executor keeps the real
//! handles in its own affine wrappers. That split is what lets the host test
//! binary prove the order and the unwind on a machine that cannot load a
//! driver.

pub mod enter;
pub mod fence;
pub mod lifecycle;
pub mod load;
pub mod setup;
pub mod stackexpand;
pub mod volume;

/// Widen ASCII source text into the exact UTF-16 code units of a counted
/// Windows name.
///
/// `UNICODE_STRING` is counted rather than NUL terminated, so the result holds
/// exactly the name and nothing else. Every Object Manager and device name the
/// driver uses is built here from one `&str`, so no call site retypes a name
/// as a hand-written code-unit array.
pub const fn ascii_utf16_name<const N: usize>(text: &str) -> [u16; N] {
    let bytes = text.as_bytes();
    assert!(
        bytes.len() == N,
        "the declared name length must match the literal"
    );
    let mut units = [0u16; N];
    let mut i = 0usize;
    while i < N {
        // PROOF: `i < N` is the loop condition and `N == bytes.len()` is
        // asserted above, so both accesses are in range on every iteration.
        // `<[T]>::get` is not available in a const context, which is why these
        // are indexes rather than checked accesses. The ASCII assertion keeps
        // the widening cast lossless.
        #[allow(clippy::indexing_slicing)]
        {
            assert!(bytes[i] < 0x80, "Windows object names here are ASCII");
            units[i] = bytes[i] as u16;
        }
        // PROOF: `i` is bounded by `N`, the length of a name literal, so this
        // cannot overflow a `usize`.
        #[allow(clippy::arithmetic_side_effects)]
        {
            i += 1;
        }
    }
    units
}

/// The closed refusal vocabulary shared by every adapter plan.
///
/// These are contract violations by the trusted in-crate executor, not user
/// input: a released driver reaches none of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterPlanError {
    /// The reported outcome is not the variant this effect can produce.
    InvalidInput,
    /// The outcome is well-formed but contradicts state an earlier effect
    /// already established.
    InvalidTransition,
    /// A caller-owned fixed-capacity table cannot hold another entry.
    Capacity,
    /// A checked counter would wrap.
    ArithmeticOverflow,
}
