use fsring_core::{reqtab::ApplicationSlot, typestate::CompletionSink};

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

pub fn application_slot_private() -> ApplicationSlot<NullSink> {
    ApplicationSlot {
        state: unsafe { core::mem::zeroed() },
    }
}
