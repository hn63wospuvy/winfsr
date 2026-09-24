// The result-write boundary has no way back. Once native has copied into the
// slot, the only route onward is the core commit that mints the receipt --
// aborting would leave the slot written and the plan claiming it was not.
use fsring_core::enter::PendingResultWrite;

pub fn prove(write: PendingResultWrite) {
    // There is no abort, and no way to recover the plan without committing.
    let _plan = write.abort();
    let _back = write.into_plan();
}
