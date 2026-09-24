use fsring_core::{pagingledger::*, size::{self, SizeTrio}};

pub fn forge() {
    let initial = size::validate(SizeTrio::new(10, 10, 0), 1).unwrap();
    let state = SequencerState::try_new(initial).unwrap();
    let _ = ContextClaim {
        owner: state.id(),
        result: ContextClaimResult::Acquired,
    };
}
