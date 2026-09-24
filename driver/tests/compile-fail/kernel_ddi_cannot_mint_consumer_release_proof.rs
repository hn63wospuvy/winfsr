// A `ConsumerReleaseProof` says every consumer role is back in its ring and the
// token slab is empty. Only a complete reverse release mints one, and it carries
// the empty slab inside it — so the DDI that frees the transient backing cannot
// run while a token is still live.
//
// A kernel DDI implementor is exactly the code that would benefit from forging
// one: it is handed the proof by value and could otherwise claim the release
// happened. There is no public constructor and no conversion into one.
use fsring_core::adapter::fence::{ConsumerReleaseProof, ConsumerTokenSlabOwner};

pub fn prove(slab: ConsumerTokenSlabOwner) {
    // No constructor: a proof cannot be assembled from the slab it would own.
    let _forged = ConsumerReleaseProof::new(slab);

    // ...and the slab offers no route of its own.
    let _from_slab = slab.into_release_proof();
}
