// A second completion of one request must not compile.
//
// C2 note: `complete` now also consumes a `CompletionClearance`, so this
// fixture mints TWO of them. Passing one would make the file fail on the
// clearance's move instead of the owner's, which is a different property --
// `clearance_reused` is the fixture for that one. compile_fail.sh's own header
// warns that the right error code for the wrong reason passes silently.
use fsring_core::effect::{Effect, EffectContext, EffectSink, Seam};
use fsring_core::typestate::{CompletionOwner, CompletionSink};

struct NullSink;
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
struct NullEffects;
unsafe impl EffectSink for NullEffects {
    unsafe fn emit(&mut self, _effect: Effect) {}
}

pub fn double_complete() {
    let mut seam = Seam::new(NullEffects);
    let ctx = unsafe { EffectContext::empty() };
    let first = seam.clear_completion(&ctx).unwrap();
    let second = seam.clear_completion(&ctx).unwrap();

    let owner = CompletionOwner::new(NullSink);
    owner.complete(first, 0, 0);
    owner.complete(second, 0, 0);
}
