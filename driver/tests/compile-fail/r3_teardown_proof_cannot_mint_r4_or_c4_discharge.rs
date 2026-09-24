// Task 19 deleted the R3 checkpoint authority surface. Task 25 keeps that
// absence and also deletes the R4 replacement names, so this fixture can no
// longer name `R4TeardownComplete` either: that name's absence is the
// sibling `r4_pending_teardown_proof_cannot_mint_c4_discharge`. What remains
// here is the original R3 half, as a singular unresolved import.
use fsring_core::adapter::fence::R3TeardownComplete;

pub fn r3_surface_is_gone(proof: R3TeardownComplete) -> R3TeardownComplete {
    proof
}
