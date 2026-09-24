// External callers must not recover an owner from a pending token.
use fsring_core::typestate::{CompletionSink, PendingToken};

struct NullSink;

unsafe impl CompletionSink for NullSink {
    unsafe fn complete(
        &mut self,
        _cleared: fsring_core::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
    }
    unsafe fn mark_pending(&mut self) {}
}

pub fn pending_token_sink_recovery() {
    // This is never run: it provides a typed PendingToken so the probe reaches
    // the real recovery method without relying on the separate private pending
    // transition. Both fields are zero-sized in this fixture.
    let token = unsafe { core::mem::zeroed::<PendingToken<NullSink>>() };
    let _owner = token.into_owner();
}
