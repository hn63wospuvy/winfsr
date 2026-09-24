use fsring_core::reqtab::{ApplicationKey, ControlKey};

pub fn control_key_in_application_method(key: ControlKey) {
    application_method(key);
}

fn application_method(_key: ApplicationKey) {}
