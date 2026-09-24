// C1 / 07-cache-mm.md section 10: a guard releases only what it acquired. The
// `acquired` flag is private, so external code cannot flip a conditional guard
// into releasing a position it never took -- which would reintroduce exactly
// the self-deadlock section 10 avoids, inverted.
use fsring_core::effect::EffectContext;
use fsring_core::lockrank::LockRank;

pub fn release_what_we_did_not_take() {
    let mut ctx = unsafe { EffectContext::empty() };
    let mut guard = ctx.acquire_if_unheld(LockRank::FcbPaging).unwrap();
    guard.acquired = true;
}
