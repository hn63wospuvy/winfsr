//! Loom model of the [`CondvarWaiter`](crate::section::heap::CondvarWaiter)
//! **wake/wait primitive** (not the full ring park handoff, which the ABI
//! already Loom-checks).
//!
//! Mirrors the waiter's algorithm — a condvar plus one saturating pending-wake
//! flag — with loom primitives and exhaustively checks, across every thread
//! interleaving, that a wake is never lost (`wait` always returns). Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p fsring-user --offline loom
//! ```

use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

/// The auto-reset-event emulation under test, rebuilt on loom primitives so
/// loom can explore its interleavings (the shipping type uses `std` directly).
struct LoomWaiter {
    pending: Mutex<bool>,
    cond: Condvar,
}

impl LoomWaiter {
    fn new() -> Self {
        Self {
            pending: Mutex::new(false),
            cond: Condvar::new(),
        }
    }

    fn wait(&self) {
        let mut pending = self.pending.lock().unwrap();
        while !*pending {
            pending = self.cond.wait(pending).unwrap();
        }
        *pending = false;
    }

    fn wake(&self) {
        let mut pending = self.pending.lock().unwrap();
        *pending = true;
        drop(pending);
        self.cond.notify_one();
    }
}

#[test]
fn a_wake_is_never_lost_across_interleavings() {
    loom::model(|| {
        let waiter = Arc::new(LoomWaiter::new());
        let waker = {
            let waiter = Arc::clone(&waiter);
            thread::spawn(move || waiter.wake())
        };
        // Whether wake() runs before, during, or after wait(), wait() must
        // observe the pending flag and return: no lost wakeup, no deadlock.
        waiter.wait();
        waker.join().unwrap();
    });
}
