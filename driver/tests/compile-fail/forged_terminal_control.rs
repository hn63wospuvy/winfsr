use fsring_core::reqtab::TerminalControl;

pub fn forged_terminal_control<C>(value: TerminalControl<C>) {
    let TerminalControl {
        table_id: _,
        slot_index: _,
        lane: _,
        birth_session_epoch: _,
        birth_generation: _,
        terminal_wire_session_epoch: _,
        terminal_req_id: _,
        terminal_kind: _,
        continuation: _,
    } = value;
}
