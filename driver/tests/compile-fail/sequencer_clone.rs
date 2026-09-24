use fsring_core::{pagingledger::SequencerState, size::{self, SizeTrio}};

pub fn duplicate() {
    let initial = size::validate(SizeTrio::new(10, 10, 0), 1).unwrap();
    let state = SequencerState::try_new(initial).unwrap();
    let _copy = state.clone();
}
