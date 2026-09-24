use fsring_core::{
    reqtab::TerminalApplication,
    typestate::CompletionSink,
};

pub fn forged_terminal_application<S: CompletionSink>(value: TerminalApplication<S>) {
    let TerminalApplication {
        table_id: _,
        slot_index: _,
        birth_session_epoch: _,
        birth_generation: _,
        terminal_wire_session_epoch: _,
        terminal_req_id: _,
        pending: _,
    } = value;
}
