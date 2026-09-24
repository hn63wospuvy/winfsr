use fsring_core::{
    reqtab::TerminalApplication,
    typestate::CompletionSink,
};

#[derive(Clone)]
struct CloneSink;

unsafe impl CompletionSink for CloneSink {
    unsafe fn complete(
        &mut self,
        _cleared: fsring_core::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
    }
    unsafe fn mark_pending(&mut self) {}
}

fn requires_clone<T: Clone>() {}

pub fn terminal_application_clone() {
    requires_clone::<TerminalApplication<CloneSink>>();
}
