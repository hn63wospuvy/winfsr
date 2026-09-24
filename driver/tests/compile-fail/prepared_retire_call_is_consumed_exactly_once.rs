// `retire_credits_with_proof` takes its drained packet **by value**, and returns
// it only inside the refusal. So a caller that retired once cannot retire the
// same drained pass again: the packet is gone.
//
// This is the affine half of the same property the unforgeable prepared call
// gives structurally — together they say a successful native retire happens at
// most once per drain, without anyone having to remember it.
use fsring_core::adapter::fence::{DrainedConsumerPrefix, FenceKernelDdi, retire_credits_with_proof};

pub fn prove<D: FenceKernelDdi>(ddi: &mut D, drained: DrainedConsumerPrefix) {
    let _first = retire_credits_with_proof(ddi, drained);

    // The packet moved into the first call; there is nothing left to retire.
    let _second = retire_credits_with_proof(ddi, drained);
}
