// C2 rev 4: the lowest fsring-core completion seam requires a clearance.
use fsring_core::typestate::CompletionSink;

pub struct OldSink;

unsafe impl CompletionSink for OldSink {
    unsafe fn complete(&mut self, _status: i32, _information: usize) {}
    unsafe fn mark_pending(&mut self) {}
}
