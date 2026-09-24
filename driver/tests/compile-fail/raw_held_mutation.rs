// C1: a modelled position is recordable as held only through a guard that
// consulted the checker, OR through the `unsafe` escape hatch that makes the
// assertion explicit. Safe external code has neither route.
//
// Round 1 of C1's review found the earlier version of this fixture asserting
// "external code cannot install a position directly" while measuring only
// E0616 field privacy -- and itself calling the then-public safe
// `EffectContext::new`, which could install any position at all. The property
// the header claimed and the property the fixture measured were different.
use fsring_core::effect::{EffectContext, TopLevelContext};
use fsring_core::lockrank::{HeldLocks, LockRank};

pub fn forge() -> EffectContext {
    // Safe code cannot call the unsafe constructor.
    EffectContext::assume_held(
        HeldLocks::none().acquire(LockRank::Sequencer),
        TopLevelContext::Ordinary,
    )
}
