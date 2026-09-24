// The IRP-completion boundary has no way back either. After IoCompleteRequest
// the caller no longer owns the IRP, so a plan that could be recovered
// unchanged would be a plan that can complete it twice.
use fsring_core::enter::PendingIrpCompletion;

pub fn prove(completion: PendingIrpCompletion) {
    let _plan = completion.abort();
    let _back = completion.into_plan();
}
