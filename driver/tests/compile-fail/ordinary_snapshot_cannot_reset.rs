use fsring_core::{pagingledger::SequencerState, size::{self, SizeTrio}};

pub fn reset_with_ordinary_snapshot() {
    let initial = size::validate(SizeTrio::new(10, 10, 0), 1).unwrap();
    let mut state = SequencerState::try_new(initial).unwrap();
    let snapshot = state.bind_size(initial);
    let _ = state.truncate_reset(snapshot);
}
