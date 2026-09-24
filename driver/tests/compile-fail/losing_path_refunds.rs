// 06-locking.md section 5.1: "losing paths never refund it". A loser holds no
// TerminalClaim, and TerminalClaim's fields are private, so it cannot forge one
// to build a RefundGate with.
use fsring_core::terminal::{
    ClaimOutcome, ClaimantKind, QuotaTicket, RefundGate, TerminalOwner, TicketOwners,
};

fn owners() -> TicketOwners {
    TicketOwners { global: 1, mount: 2, io_owner: 3, class_budget: None }
}

pub fn a_loser_tries_to_refund() {
    let owner = TerminalOwner::new();
    let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&owner);
    let _winner = owner.claim(ClaimantKind::Completion);
    let ClaimOutcome::Lost { winner } = owner.claim(ClaimantKind::Cancellation) else {
        return;
    };
    // The loser has only the winner's identity. Forging the proof is the only
    // way to reach a RefundGate through this arbitration, and the private
    // fields forbid it.
    let forged = fsring_core::terminal::TerminalClaim {
        winner: winner.unwrap_or(ClaimantKind::Teardown),
        arbitration: owner.id(),
    };
    let _ = RefundGate::new(forged, ticket);
}
