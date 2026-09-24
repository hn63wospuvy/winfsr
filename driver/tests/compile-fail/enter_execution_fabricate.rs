// Every R4 execution identity is minted by the state that owns the ring, and
// none of them has a caller-side constructor. A caller who could build one
// could name an execution that never acquired a role.
use fsring_core::adapter::enter::CqMutationWitness;
use fsring_core::enter::{
    CqConsumerToken, EnterCommitTracker, EnterExecutionBrand, IrpObservation, RingEnterState,
};

pub fn prove(mut state: RingEnterState, token: CqConsumerToken) {
    // A raw pointer value is not an observation: the field is private.
    let _observation = IrpObservation(1);

    // Neither brand nor tracker has a public constructor.
    let _brand = EnterExecutionBrand::new();
    let _tracker = EnterCommitTracker::new();

    // The R4 acquisition takes no invocation from its caller.
    let _lease = state.acquire_sq_wait(7);

    // And a naked CQ token does not convert into a mutation witness.
    let _witness = CqMutationWitness::from_token(token);
}
