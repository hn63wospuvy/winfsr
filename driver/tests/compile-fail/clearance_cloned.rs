// C2 round 2: a clearance cannot be duplicated.
//
// `clearance_reused` proves it cannot be USED twice. This proves it cannot be
// COPIED, which is a different property with a different failure mode: adding
// `#[derive(Clone)]` to the token leaves `clearance_reused` failing exactly as
// before, so without this fixture the no-`Clone` half of the claim had no
// signal at all. C2's first review round found that gap.
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

pub fn duplicate_one_clearance() {
    let mut seam = Seam::new(NullEffects);
    let ctx = unsafe { EffectContext::empty() };
    let cleared = seam.clear_completion(&ctx).unwrap();
    let duplicate = cleared.clone();
    CompletionOwner::new(NullSink).complete(cleared, 0, 0);
    CompletionOwner::new(NullSink).complete(duplicate, 0, 0);
}
