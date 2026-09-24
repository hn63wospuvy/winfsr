use fsring_core::{pagingledger::*, size::{self, SizeTrio}};
pub fn pass_success_as_failure() {
    let initial = size::validate(SizeTrio::new(10, 10, 0), 1).unwrap();
    let mut state = SequencerState::try_new(initial).unwrap();
    let snapshot = state.bind_size(initial);
    let claim = state.bind_claim(ContextClaimResult::Acquired);
    let extracted = PagingWrite::extract(0, 10).unwrap();
    let write = match state.admit(extracted, snapshot, claim) {
        AdmissionOutcome::InFlight(write) => write,
        _ => panic!("fixture admission must be in flight"),
    };
    let budget = NodeBudget::preclaim(0).unwrap();
    let _ = state.terminalize(
        write,
        snapshot,
        budget,
        Reservation::Granted,
        0_i32,
    );
}
