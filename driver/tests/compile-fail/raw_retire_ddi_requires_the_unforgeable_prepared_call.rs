// `native_retire_grants` takes a `PreparedRetireCall`, and that packet is minted
// only inside `retire_credits_with_proof` — the one safe wrapper — from a
// `DrainedConsumerPrefix` that a successful drain produced.
//
// That is what makes "a successful native retire happened at most once" a
// property of the type system rather than of the caller's discipline: safe code
// cannot build the argument, so it cannot replay the raw call.
use fsring_core::adapter::fence::{DrainedConsumerPrefix, PreparedRetireCall};

pub fn prove(drained: DrainedConsumerPrefix) {
    // No public constructor from the drained packet...
    let _forged = PreparedRetireCall::new(drained);

    // ...and no conversion on the packet either.
    let _converted = drained.into_prepared_retire_call();
}
