use fsring_core::reqtab::TerminalControl;

fn requires_clone<T: Clone>() {}

pub fn terminal_control_clone() {
    requires_clone::<TerminalControl<u32>>();
}
