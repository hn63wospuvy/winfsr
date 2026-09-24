// A refund receipt anyone can write is not evidence that a refund happened.
// Refund's fields are private, so the only way to hold one is to have performed
// a refund through the ledger.
use fsring_core::terminal::{
    ClaimOutcome, ClaimantKind, QuotaTicket, RefundGate, TerminalOwner, TicketOwners,
};

fn owners() -> TicketOwners {
    TicketOwners { global: 1, mount: 2, io_owner: 3, class_budget: None }
}

pub fn write_a_receipt_without_refunding() {
    let _ = fsring_core::terminal::Refund { charge: 1 << 40, owners: owners() };
}
