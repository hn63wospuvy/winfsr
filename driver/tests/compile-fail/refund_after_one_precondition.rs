// The half of the ordering the first revision left unfixtured: section 5.1
// names TWO preconditions, and asserting only the first must not be enough.
// A mutation adding `impl RefundGate<LastAccessDone> { fn refund }` would have
// passed every test and every other fixture.
use fsring_core::terminal::{
    ClaimOutcome, ClaimantKind, QuotaTicket, RefundGate, TerminalOwner, TicketOwners,
};

fn owners() -> TicketOwners {
    TicketOwners { global: 1, mount: 2, io_owner: 3, class_budget: None }
}

pub fn refund_after_only_the_last_access() {
    let owner = TerminalOwner::new();
    let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&owner);
    let ClaimOutcome::Won(claim) = owner.claim(ClaimantKind::Completion) else {
        return;
    };
    let Ok(gate) = RefundGate::new(claim, ticket) else { return };
    // IoCompleteRequest has not returned; `refund` does not exist here either.
    let _ = gate.last_access_done().refund();
}
