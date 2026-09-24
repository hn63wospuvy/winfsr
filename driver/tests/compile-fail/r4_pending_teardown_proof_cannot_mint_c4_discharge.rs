// After Task 25 the R4 checkpoint proof is not nameable. The fixture keeps the
// same identity and now proves absence plus the surviving nonconversion: a
// fence discharge still has no public constructor.
use fsring_core::adapter::fence::{FenceObligationsDischarged, R4TeardownComplete};

pub fn r4_surface_is_gone(proof: R4TeardownComplete) -> R4TeardownComplete {
    proof
}

pub fn discharge_still_has_no_constructor(locator: fsring_core::session::SessionLocator) {
    let _forged = FenceObligationsDischarged::new(locator);
}
