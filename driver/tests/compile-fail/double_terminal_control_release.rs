use fsring_core::reqtab::TerminalControl;

pub fn double_terminal_control_release<C>(terminal: TerminalControl<C>) {
    let _first = terminal.release();
    let _second = terminal.release();
}
