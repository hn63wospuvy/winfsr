// A DISPATCH_LEVEL token must not satisfy a PASSIVE_LEVEL requirement.
use fsring_core::typestate::{Dispatch, Passive};

fn needs_passive(_p: &Passive) {}

pub fn wrong_token(d: &Dispatch) {
    needs_passive(d);
}
