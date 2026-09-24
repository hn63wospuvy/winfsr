// C2 / 06-locking.md section 6: no IoCompleteRequest under a ring token,
// domain/FCB/CCB lock, notification gate or mount rundown.
//
// Rev 4 constructs CompletionClearance in the reviewed, byte-frozen
// effect/clearance.rs trusted boundary. The raw CompletionSink::complete method
// requires it; unsafe fabrication remains possible as an explicit invariant
// violation.
use fsring_core::typestate::{CompletionOwner, CompletionSink};

pub struct NullSink;
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

pub fn complete_without_asking() {
    CompletionOwner::new(NullSink).complete(0, 0);
}
