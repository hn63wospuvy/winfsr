use fsring_core::reqtab::ApplicationKey;

pub fn forged_application_key(key: ApplicationKey) {
    let ApplicationKey {
        table_id: _,
        slot_index: _,
        birth_session_epoch: _,
        birth_generation: _,
    } = key;
}
