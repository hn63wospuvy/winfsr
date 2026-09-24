use fsring_core::enter::PendingTerminalRight;

pub fn enter_terminal_twice(right: PendingTerminalRight) {
    let _first = right.finish();
    let _second = right.finish();
}
