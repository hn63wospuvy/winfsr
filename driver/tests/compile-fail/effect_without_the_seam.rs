// C1: an effect routed through `Seam` cannot bypass that checked boundary.
// `Seam`'s sink field is private, so external code cannot reach this sink and
// perform an effect the checker never evaluated. This fixture makes no claim
// about completion/pending paths outside `effect.rs`.
use fsring_core::effect::{Effect, EffectSink, Seam};

pub struct NullSink;
unsafe impl EffectSink for NullSink {
    unsafe fn emit(&mut self, _effect: Effect) {}
}

pub fn bypass(seam: &mut Seam<NullSink>) {
    unsafe { seam.sink.emit(Effect::CompleteIrp) };
}
