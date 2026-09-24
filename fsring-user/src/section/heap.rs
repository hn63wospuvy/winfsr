//! Heap-backed [`SharedSection`] and a lost-wakeup-safe [`CondvarWaiter`].
//!
//! `HeapSection` owns a single page-aligned, zeroed heap allocation shared
//! in-process by both transport roles. It is portable and Miri-friendly (no OS
//! calls), which is why it exists alongside the real Windows-section backend.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::{Condvar, Mutex};

use super::{SharedSection, Waiter};

/// A lost-wakeup-safe [`Waiter`] emulating a Windows auto-reset event with a
/// `Condvar` and a single saturating pending-wake flag.
#[derive(Default)]
pub struct CondvarWaiter {
    pending: Mutex<bool>,
    cond: Condvar,
}

impl Waiter for CondvarWaiter {
    fn wait(&self) {
        let mut pending = self.pending.lock().expect("waiter mutex poisoned");
        while !*pending {
            pending = self.cond.wait(pending).expect("waiter mutex poisoned");
        }
        *pending = false;
    }

    fn wake(&self) {
        let mut pending = self.pending.lock().expect("waiter mutex poisoned");
        *pending = true;
        drop(pending);
        self.cond.notify_one();
    }
}

/// A [`SharedSection`] backed by one page-aligned, zeroed heap allocation.
pub struct HeapSection {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
    waiter: CondvarWaiter,
}

impl HeapSection {
    /// Allocate a zeroed section of `len` bytes aligned to `page_size`.
    ///
    /// # Panics
    /// Panics if `len == 0`, if `page_size` is not a power of two, or if the
    /// allocation fails — construction is a host-side setup step, not a
    /// hostile-input path.
    pub fn with_len(len: usize, page_size: usize) -> Self {
        assert!(len > 0, "section length must be non-zero");
        assert!(
            page_size.is_power_of_two(),
            "page_size must be a power of two"
        );
        let layout = Layout::from_size_align(len, page_size).expect("valid section layout");
        // SAFETY: `layout` has a non-zero size (asserted above).
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "section allocation failed");
        Self {
            ptr,
            len,
            layout,
            waiter: CondvarWaiter::default(),
        }
    }
}

// SAFETY: `HeapSection` owns a unique heap allocation of `len` bytes that stays
// live at a fixed address until `Drop`. Both in-process transport roles address
// it through section-relative offsets derived from `base()`; concurrent access
// to ring cursor/entry fields goes through the ABI's atomic/volatile operations,
// never through a `&`/`&mut` to those cells. The waiter is bound to this value.
unsafe impl SharedSection for HeapSection {
    fn base(&self) -> *mut u8 {
        self.ptr
    }

    fn len(&self) -> usize {
        self.len
    }

    type Waiter = CondvarWaiter;

    fn waiter(&self) -> &CondvarWaiter {
        &self.waiter
    }
}

impl Drop for HeapSection {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`layout` came from `alloc_zeroed` with this exact layout
        // and are freed exactly once here.
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn wake_before_wait_is_not_lost() {
        let waiter = Arc::new(CondvarWaiter::default());
        waiter.wake(); // wake arrives BEFORE any wait
        let peer = Arc::clone(&waiter);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            peer.wait(); // must consume the pending wake and return
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(TIMEOUT).is_ok(),
            "wait() hung: a wake delivered before wait was lost"
        );
    }

    #[test]
    fn wake_releases_a_blocked_waiter() {
        let waiter = Arc::new(CondvarWaiter::default());
        let peer = Arc::clone(&waiter);
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            peer.wait();
            let _ = tx.send(());
        });
        thread::sleep(Duration::from_millis(50)); // let the waiter block
        waiter.wake();
        assert!(
            rx.recv_timeout(TIMEOUT).is_ok(),
            "blocked waiter was not woken"
        );
        handle.join().unwrap();
    }

    #[test]
    fn two_wakes_saturate_to_one_pending() {
        let waiter = CondvarWaiter::default();
        waiter.wake();
        waiter.wake(); // saturates: still exactly one pending
        waiter.wait(); // consumes the single pending wake, returns immediately
                       // a second wait must now block; prove it does not have a
                       // second pending wake by checking it would time out.
        let waiter = Arc::new(waiter);
        let peer = Arc::clone(&waiter);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            peer.wait();
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "two saturating wakes left more than one pending"
        );
        waiter.wake(); // release the parked test thread so it can exit
    }

    #[test]
    fn heap_section_is_zeroed_page_aligned_and_correct_length() {
        let section = HeapSection::with_len(8192, 4096);
        assert_eq!(section.len(), 8192);
        assert_eq!(section.base() as usize % 4096, 0, "base not page-aligned");
        // SAFETY: `base()` covers `len()` readable bytes just allocated zeroed.
        let bytes = unsafe { std::slice::from_raw_parts(section.base(), section.len()) };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "section not zero-initialized"
        );
    }
}
