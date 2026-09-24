use fsring_core::session::TerminalSessionRef;

pub fn consume_twice(consume: fn(TerminalSessionRef), terminal: TerminalSessionRef) {
    consume(terminal);
    consume(terminal);
}
