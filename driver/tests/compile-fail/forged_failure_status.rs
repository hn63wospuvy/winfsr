use fsring_core::pagingledger::FailureStatus;
pub fn forge_success_as_failure() {
    let _ = FailureStatus(0_i32);
}
