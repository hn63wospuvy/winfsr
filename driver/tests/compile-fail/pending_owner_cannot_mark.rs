// External callers must not be able to consume an owner into a pending token.
use fsring_core::typestate::{CompletionOwner, CompletionSink};

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

pub fn pending_owner_cannot_mark() {
    let owner = CompletionOwner::new(NullSink);
    let _token = owner.pending();
}
