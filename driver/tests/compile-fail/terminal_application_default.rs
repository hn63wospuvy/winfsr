use fsring_core::{
    reqtab::TerminalApplication,
    typestate::CompletionSink,
};

#[derive(Default)]
struct DefaultSink;

unsafe impl CompletionSink for DefaultSink {
    unsafe fn complete(
        &mut self,
        _cleared: fsring_core::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
    }
    unsafe fn mark_pending(&mut self) {}
}

fn requires_default<T: Default>() {}

pub fn terminal_application_default() {
    requires_default::<TerminalApplication<DefaultSink>>();
}
