use fsring_core::reqtab::ControlRelease;

pub fn forged_control_release(value: ControlRelease) {
    let ControlRelease {
        table_id: _,
        slot_index: _,
        lane: _,
        birth_session_epoch: _,
        birth_generation: _,
        terminal_wire_session_epoch: _,
        terminal_req_id: _,
        terminal_kind: _,
    } = value;
}
