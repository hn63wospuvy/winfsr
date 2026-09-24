use fsring_core::pagingledger::*;

pub fn construct_separate_components() {
    let _ = IssueCounter::new();
    let _ = ActiveSet::new();
    let _ = Ledger::new();
}
