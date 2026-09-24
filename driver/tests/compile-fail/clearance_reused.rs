// C2: a clearance authorises ONE completion. It is move-only and consumed by
// value, so a second completion cannot reuse the first one's permission --
// the same discipline B5 applies to the owner capability itself.
use fsring_core::effect::{Effect, EffectContext, EffectSink, Seam};
use fsring_core::typestate::{CompletionOwner, CompletionSink};

pub struct NullSink;
unsafe impl CompletionSink for NullSink {
    unsafe fn complete(
        &mut self,
        _cleared: fsring_core::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
    }
    unsafe fn mark_pending(&mut self) {}
}
pub struct NullEffects;
unsafe impl EffectSink for NullEffects {
    unsafe fn emit(&mut self, _effect: Effect) {}
}

pub fn reuse_one_clearance() {
    let mut seam = Seam::new(NullEffects);
    let ctx = unsafe { EffectContext::empty() };
    let cleared = seam.clear_completion(&ctx).unwrap();
    CompletionOwner::new(NullSink).complete(cleared, 0, 0);
    CompletionOwner::new(NullSink).complete(cleared, 0, 0);
}
