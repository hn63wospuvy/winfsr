// A second terminal completion of one application request must not compile.
//
// C2 note: two clearances are minted for the same reason as in
// `double_complete` -- so the double move under test is the TERMINAL's, not the
// clearance's.
use fsring_core::effect::{Effect, EffectContext, EffectSink, Seam};
use fsring_core::{reqtab::TerminalApplication, typestate::CompletionSink};

struct NullEffects;
unsafe impl EffectSink for NullEffects {
    unsafe fn emit(&mut self, _effect: Effect) {}
}

pub fn double_terminal_application_complete<S: CompletionSink>(
    terminal: TerminalApplication<S>,
) {
    let mut seam = Seam::new(NullEffects);
    let ctx = unsafe { EffectContext::empty() };
    let first = seam.clear_completion(&ctx).unwrap();
    let second = seam.clear_completion(&ctx).unwrap();

    let _first = terminal.complete(first, 0, 0);
    let _second = terminal.complete(second, 0, 0);
}
