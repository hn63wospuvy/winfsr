use fsring_core::reqtab::ControlRelease;

fn requires_default<T: Default>() {}

pub fn control_release_default() {
    requires_default::<ControlRelease>();
}
