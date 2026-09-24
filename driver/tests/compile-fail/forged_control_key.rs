use fsring_core::reqtab::ControlKey;

pub fn forged_control_key(key: ControlKey) {
    let ControlKey {
        table_id: _,
        slot_index: _,
        lane: _,
        birth_session_epoch: _,
        birth_generation: _,
    } = key;
}
