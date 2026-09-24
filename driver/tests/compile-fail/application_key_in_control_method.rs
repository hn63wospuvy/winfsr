use fsring_core::reqtab::{ApplicationKey, ControlKey};

pub fn application_key_in_control_method(key: ApplicationKey) {
    control_method(key);
}

fn control_method(_key: ControlKey) {}
