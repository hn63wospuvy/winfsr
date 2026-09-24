use fsring_core::reqtab::TerminalControl;

fn requires_default<T: Default>() {}

pub fn terminal_control_default() {
    requires_default::<TerminalControl<u32>>();
}
