// CcPublication is the evidence that section 3's three preconditions were met
// -- PASSIVE_LEVEL, a non-paging origin, and a held-set that permits the wait.
// Forging it would let the paging path publish sizes to Cc.
use fsring_core::size::*;

pub fn forge_the_evidence() -> CcPublication {
    CcPublication { change: SizeChange::Extend }
}
