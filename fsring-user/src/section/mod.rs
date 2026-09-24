//! The `SharedSection` + `Waiter` seam.
//!
//! A [`SharedSection`] is a contiguous, peer-shared memory region plus a
//! [`Waiter`] park/wake primitive. The daemon-side transport is written once
//! over this seam; a backend supplies the memory (a heap allocation or a real
//! Windows section) and the wake primitive (a condvar or an event object). The
//! ABI ring algorithm runs over the region's pages; this crate never re-derives
//! it.

pub mod heap;

// The mapped backend calls real kernel32 FFI, which Miri cannot execute, so it
// is excluded under Miri (the heap backend exists precisely to give Miri a
// portable path to check the pointer/atomic code).
#[cfg(all(windows, not(miri)))]
pub mod mapped;

pub use heap::{CondvarWaiter, HeapSection};

#[cfg(all(windows, not(miri)))]
pub use mapped::{EventWaiter, MappedSection, PeerView};

/// A contiguous, peer-shared memory region plus its park/wake primitive.
///
/// # Safety
///
/// An implementor MUST guarantee that:
///
/// - [`base`](SharedSection::base) points to [`len`](SharedSection::len)
///   contiguous bytes that are readable and writable and stay live at a fixed
///   address for as long as the `SharedSection` value exists;
/// - the same underlying section MAY be mapped by a peer (or by this process
///   again) at a *different* base address, so all addressing into the region is
///   section-relative and no absolute pointer read out of the region is trusted;
/// - the returned [`Waiter`](SharedSection::Waiter) is bound to this section
///   instance and is the only wake object routed the ring's wake decisions.
#[allow(clippy::len_without_is_empty)] // len() is a fixed mapping size, never "empty"
pub unsafe trait SharedSection {
    /// Base address of this mapping. Two mappings of one section may differ.
    fn base(&self) -> *mut u8;

    /// Byte length of the mapping. Every ABI offset is validated against this.
    fn len(&self) -> usize;

    /// The park/wake primitive bound to this section.
    type Waiter: Waiter;

    /// Borrow the section's park/wake primitive.
    fn waiter(&self) -> &Self::Waiter;
}

/// Park/wake with **auto-reset-event semantics** — one saturating pending wake.
///
/// This is the primitive Windows auto-reset events already provide and that the
/// [`CondvarWaiter`](heap::CondvarWaiter) emulates, so the ring's park/wake is
/// backend-uniform:
///
/// - [`wake`](Waiter::wake) sets a single pending-wake bit (saturating: two
///   wakes with no intervening wait leave exactly one pending) and releases a
///   blocked waiter;
/// - [`wait`](Waiter::wait) consumes a pending wake and returns immediately if
///   one is set, otherwise blocks until the next `wake`, then consumes it.
///
/// The saturating pending bit is what makes a `wake` delivered *between* a
/// consumer's park declaration and its `wait` impossible to lose — the ABI
/// `ParkProtocol` recheck relies on exactly this to avoid a missed wakeup.
pub trait Waiter {
    /// Consume a pending wake, or block until the next [`wake`](Waiter::wake).
    fn wait(&self);

    /// Set the pending wake and release a blocked [`wait`](Waiter::wait).
    fn wake(&self);
}
