// C2 rev 4: safe code outside the trusted construction file cannot construct a
// clearance through normal Rust construction.
//
// C2's first review round found the token documented as unforgeable with no
// fixture behind the word, while a probe inside module `effect` could write the
// literal -- Rust field privacy is module-scoped. The complete trusted boundary
// now lives in reviewed, byte-frozen `effect/clearance.rs`, and the raw
// `CompletionSink::complete` signature carries the clearance. This fixture
// holds the safe external-construction half. Unsafe fabrication remains an
// explicit, unmeasured invariant violation; the tracked ledger contains no
// unsafe-forge plant command, source state, or grade.
use fsring_core::effect::CompletionClearance;

pub fn forge() -> CompletionClearance<'static> {
    CompletionClearance(core::marker::PhantomData)
}
