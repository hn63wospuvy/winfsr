// C2 round 3: a clearance cannot survive a lock taken on THE SAME context.
//
// The scope in that first line is the whole point, and rev 2 did not have it.
// Round 2 of C2's review cleared against one `EffectContext`, acquired
// `LockRank::Sequencer` on a SECOND ordinary one, and completed under it -- in
// three lines, with no `static` and no more unsafe than this fixture uses. The
// tie is per-VALUE, not per-thread: nothing here connects an `EffectContext` to
// the caller's real held-set, and a caller may hold several.
//
// This fixture is unchanged and still measures something real -- the review was
// explicit that the gap must not be closed by editing it. What changed is the
// claim around it, in this header, in `clear_completion`'s rustdoc and in the
// design. Closing the gap itself needs a witness the caller cannot swap (a
// thread or IRQL token), which this slice does not have.
//
// History: C2's first review round found the token had no lifetime tie at all,
// so this fixture compiled. The clearance now borrows its `EffectContext` and
// acquiring needs `&mut`, so the borrow checker refuses -- for this context.
use fsring_core::effect::{Effect, EffectContext, EffectSink, Seam};
use fsring_core::lockrank::LockRank;
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

pub fn complete_under_a_lock_taken_after_clearing() {
    let mut seam = Seam::new(NullEffects);
    let mut ctx = unsafe { EffectContext::empty() };
    let cleared = seam.clear_completion(&ctx).unwrap();
    let _guard = ctx.acquire(LockRank::Sequencer);
    CompletionOwner::new(NullSink).complete(cleared, 0, 0);
}
