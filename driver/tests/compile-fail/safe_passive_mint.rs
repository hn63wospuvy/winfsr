// The one minting point must be unsafe: safe code outside the crate must not be
// able to manufacture a PASSIVE_LEVEL capability.
use fsring_core::typestate::{passive_at_driver_entry, Passive};

pub fn mint_without_unsafe() -> Passive {
    passive_at_driver_entry()
}
