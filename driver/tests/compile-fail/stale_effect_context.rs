// C1 / review round 3: a context is a claim about NOW, so it cannot be copied
// and re-presented later.
//
// While EffectContext was Copy, safe code could snapshot a context, acquire a
// spin lock through a guard, and hand the stale copy to the seam -- which
// approved IoCompleteRequest while the lock was still held, with no unsafe
// anywhere. Making the constructors unsafe in round 2 did not help: a caller
// never had to forge a context, only to keep an old one.
use fsring_core::effect::EffectContext;

pub fn snapshot_and_reuse() {
    // SAFETY: this fixture never runs; it exists to be rejected by the
    // compiler, and the constructor's obligation is vacuous in dead code.
    let ctx = unsafe { EffectContext::empty() };
    let stale = ctx;
    let _also = ctx;
    let _ = stale;
}
