// Passive must not be constructible by literal outside the crate. The other
// route, the unsafe mint, is covered by safe_passive_mint.rs.
use fsring_core::typestate::Passive;

pub fn forge() -> Passive {
    Passive(())
}
