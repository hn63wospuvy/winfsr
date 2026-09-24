// 06-locking.md section 5.1: the terminal owner refunds "only after the last
// driver MDL/system-VA access and after IoCompleteRequest returns". Refunding
// while still in the Charged state must not compile.
use fsring_core::terminal::{
    ClaimOutcome, ClaimantKind, QuotaTicket, RefundGate, TerminalOwner, TicketOwners,
};

fn owners() -> TicketOwners {
    TicketOwners { global: 1, mount: 2, io_owner: 3, class_budget: None }
}

pub fn refund_too_early() {
    let owner = TerminalOwner::new();
    let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&owner);
    let ClaimOutcome::Won(claim) = owner.claim(ClaimantKind::Completion) else {
        return;
    };
    let Ok(gate) = RefundGate::new(claim, ticket) else { return };
    // Neither precondition has been asserted; `refund` does not exist here.
    let _ = gate.refund();
}
