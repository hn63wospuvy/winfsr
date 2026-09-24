use fsring_core::reqtab::ControlRelease;

fn requires_clone<T: Clone>() {}

pub fn control_release_clone() {
    requires_clone::<ControlRelease>();
}
