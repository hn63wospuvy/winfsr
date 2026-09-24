use fsring_core::reqtab::CompletionReceipt;

pub fn forged_completion_receipt(value: CompletionReceipt) {
    let CompletionReceipt {
        table_id: _,
        slot_index: _,
        birth_session_epoch: _,
        birth_generation: _,
        terminal_wire_session_epoch: _,
        terminal_req_id: _,
    } = value;
}
