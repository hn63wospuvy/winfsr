// 06-locking.md section 5.1: the terminal owner refunds EXACTLY ONCE. `refund`
// consumes the gate, so a second refund is a use-after-move.
use fsring_core::terminal::{
    ClaimOutcome, ClaimantKind, QuotaTicket, RefundGate, TerminalOwner, TicketOwners,
};

fn owners() -> TicketOwners {
    TicketOwners { global: 1, mount: 2, io_owner: 3, class_budget: None }
}

pub fn refund_twice() {
    let owner = TerminalOwner::new();
    let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&owner);
    let ClaimOutcome::Won(claim) = owner.claim(ClaimantKind::Completion) else {
        return;
    };
    let Ok(gate) = RefundGate::new(claim, ticket) else { return };
    let gate = gate.last_access_done().completion_returned();
    let _first = gate.refund();
    let _second = gate.refund();
}
