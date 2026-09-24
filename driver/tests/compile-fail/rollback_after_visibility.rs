// 06-locking.md section 5.1 begins "Once the IRP may be visible to
// cancellation or a queue" -- from that moment the CAS governs the ticket. The
// section 11 no-arbitration rollback belongs only to the never-visible path, so
// it must not exist on a published ticket.
use fsring_core::terminal::{
    ClaimOutcome, ClaimantKind, QuotaTicket, RefundGate, TerminalOwner, TicketOwners,
};

fn owners() -> TicketOwners {
    TicketOwners { global: 1, mount: 2, io_owner: 3, class_budget: None }
}

pub fn rollback_a_published_ticket() {
    let owner = TerminalOwner::new();
    let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&owner);
    let _ = ticket.rollback_before_visibility();
}
