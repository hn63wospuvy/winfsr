//! Slice C1: **within `effect.rs`**, a kernel effect reaches the effect sink
//! through exactly one boundary, that boundary checks before it forwards, and
//! the recorder does not exist in a non-test build.
//!
//! **The boundary is not crate-wide, and saying so is the point.** C1's review
//! exhibited the design's earlier, overbroad falsifier 3 with shipped code,
//! twice; the current falsifier is scoped to effects routed through
//! `effect.rs`.
//! `typestate::CompletionOwner::complete` performs `IoCompleteRequest` and
//! `CompletionOwner::pending` performs `IoMarkIrpPending`, both through
//! `CompletionSink` — safe, public, in-crate, both live-called from
//! `reqtab.rs` — with no `may_emit`, no recorder, and in `pending`'s case no
//! `Effect` variant at all.
//!
//! Round 1 found `complete`; round 2 found that the fix for it named `complete`
//! as "the only" such path while `pending` sat beside it. Both are now measured
//! below, which is the difference between a boundary and a sentence about one.
//!
//! **C2 closed the `complete` half at the lowest Rust seam.** The unsafe
//! [`fsring_core::typestate::CompletionSink::complete`] signature consumes a
//! [`fsring_core::effect::CompletionClearance`].
//! `completion_sink_without_clearance` rejects an old sink implementation, and
//! `completion_sink_call_without_clearance` rejects a raw call without the
//! token. `completion_clearance_reaches_raw_sink_once` then exercises the
//! normal-library production path from [`fsring_core::effect::Seam::clear_completion`]
//! through [`fsring_core::typestate::CompletionOwner`] to that raw sink.
//! `Seam::clear_completion` still has **zero non-test callers** on this SHA —
//! the crate has no dispatch entry and C2 creates no device object — while
//! production `Guard::emit` calls `Seam::emit`. This establishes the required
//! completion integration path, not a live driver completion path. `pending`
//! remains unchecked and the gate still carries its PENDING.
//!
//! The remaining source checks are syntactic by construction. Each predicate is
//! paired with a case in `the_scanners_discriminate` showing it rejects a
//! lookalike — the idiom `extern_quarantine.rs` established, and the reason a
//! scan is evidence rather than decoration.

const EFFECT_SRC: &str = include_str!("../src/effect.rs");

/// A line that actually performs an effect through the wrapped sink.
///
/// Comment lines do not count: prose describing the call is not the call, and a
/// scanner that cannot tell them apart would be satisfied by documentation.
fn is_sink_call(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.starts_with("//") && trimmed.contains("self.sink.emit(")
}

/// Does `needle` occur on a line that is not a `//` comment?
///
/// Round 2 of C2's review removed the clearance from the production API
/// entirely -- `complete` back to `(status, information)`, `reqtab` updated, 27
/// test call sites updated -- left the two literals behind as `//` comments, and
/// the retired completion-path scan stayed green. This file had defined the
/// discipline two functions above since C1; the C2 predicates simply did not use
/// it.
fn contains_in_code(src: &str, needle: &str) -> bool {
    src.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//") && line.contains(needle)
    })
}

/// A line that consults the checker.
fn is_check_call(line: &str) -> bool {
    let trimmed = line.trim_start();
    !trimmed.starts_with("//") && trimmed.contains("may_emit(ctx, effect)")
}

#[test]
fn exactly_one_boundary_in_effect_rs_reaches_the_sink() {
    let calls: Vec<(usize, &str)> = EFFECT_SRC
        .lines()
        .enumerate()
        .filter(|(_, l)| is_sink_call(l))
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "within effect.rs, an effect must reach the sink through exactly one \
         boundary; found {calls:?}"
    );
}

/// The boundary checks before it forwards.
///
/// Order in the source, not merely presence of both: a `Seam::emit` that called
/// the sink first and the checker afterwards would contain both lines and
/// perform every forbidden effect exactly once before refusing it.
#[test]
fn the_boundary_checks_before_it_forwards() {
    let Some(check) = EFFECT_SRC.lines().position(is_check_call) else {
        panic!("no line in effect.rs consults may_emit(ctx, effect)")
    };
    let Some(call) = EFFECT_SRC.lines().position(is_sink_call) else {
        panic!("no line in effect.rs reaches the sink")
    };
    assert!(
        check < call,
        "may_emit is at line {check} and the sink call at line {call}; the check \
         must precede the effect or every forbidden effect happens once before \
         being refused"
    );
}

/// The recorder is `#[cfg(test)]` and stays that way.
///
/// `fsring-core` carries no `[features]` section by design, so the recorder has
/// no other gate available to it. A `pub mod recorder` that lost its attribute
/// would ship a test observer into the kernel image.
///
/// **This scan is the second line of defence, and the measurement says so.**
/// Deleting the attribute today does not reach this test: the recorder uses
/// `std::cell::RefCell` and `std::vec::Vec`, which do not resolve in the crate's
/// `no_std` build, so the compiler rejects it first — measured 2026-07-28, the
/// falsification attempt produced a build failure rather than a red test. The
/// scan covers the case the compiler would not catch: a recorder rewritten to be
/// `no_std`-compatible, where losing the attribute compiles cleanly and ships
/// the observer.
#[test]
fn the_recorder_is_test_only() {
    let Some(idx) = EFFECT_SRC.find("pub mod recorder") else {
        panic!("effect.rs must declare the recorder module")
    };
    let Some(preceding) = EFFECT_SRC.get(..idx) else {
        panic!("the recorder declaration has no preceding text")
    };
    assert!(
        preceding.trim_end().ends_with("#[cfg(test)]"),
        "the recorder module must be immediately preceded by #[cfg(test)]"
    );
}

/// Anti-vacuity: each scan must reject a lookalike, not merely accept the real
/// thing. A scanner that cannot tell the difference is not a scanner.
#[test]
fn the_scanners_discriminate() {
    // The real call, at its real indentation.
    assert!(is_sink_call("        unsafe { self.sink.emit(effect) };"));
    // Prose about the call is not the call. Without this, the one-boundary
    // count could be satisfied by a comment and violated by real code.
    assert!(!is_sink_call(
        "        // unsafe { self.sink.emit(effect) };"
    ));
    assert!(!is_sink_call(
        "    /// forwards through self.sink.emit(effect)"
    ));
    // The scan is keyed to the literal `self.sink.emit(`. Renaming the field
    // does not disable it silently: the count drops to zero and
    // `exactly_one_boundary_in_effect_rs_reaches_the_sink` fails on `0 != 1` rather
    // passing vacuously. That is the direction that matters here.
    assert!(!is_sink_call(
        "        unsafe { self.channel.emit(effect) };"
    ));

    assert!(is_check_call("        may_emit(ctx, effect)?;"));
    assert!(!is_check_call("        // may_emit(ctx, effect)?;"));
    assert!(!is_check_call(
        "/// See may_emit(ctx, effect) for the rules."
    ));

    // The surviving C2 predicate supports the pending-path test below.
    assert!(contains_in_code(
        "    fn pending(mut self) -> PendingToken<S>",
        "fn pending(mut self) -> PendingToken<S>"
    ));
    assert!(!contains_in_code(
        "    // fn pending(mut self) -> PendingToken<S>",
        "fn pending(mut self) -> PendingToken<S>"
    ));
    assert!(!contains_in_code(
        "    /// See fn pending(mut self) -> PendingToken<S>",
        "fn pending(mut self) -> PendingToken<S>"
    ));

    // The recorder check is a suffix test, so a declaration without the
    // attribute must fail it.
    assert!(!"pub mod recorder { }".trim_end().ends_with("#[cfg(test)]"));
    assert!("#[cfg(test)]".trim_end().ends_with("#[cfg(test)]"));
}

/// `pending` still bypasses the seam, and that is a decision, not an omission.
///
/// `IoMarkIrpPending` occurs exactly twice in `06-locking.md`, at lines 331 and
/// 338, and **both are permissive** — 331 records that it *has run* under the
/// sequencer. No sentence forbids it under a hold, so no `Effect` variant is
/// licensed for it; adding one would fail
/// `every_forbidden_effect_is_representable` or force someone to weaken that
/// manually enumerated corpus check. That check covers only its curated
/// transcriptions; it is not a document-wide derivation or discovery
/// mechanism.
///
/// **This test is the surviving half of a split, and why it was split matters.**
/// C1's `b5s_completion_path_still_bypasses_the_seam` carried three assertions.
/// C2 routed `complete` through the seam — and **not one of the three flipped**,
/// because all three were source scans for text C2 left in place. The old test
/// would have stayed green across the entire change it existed to notice.
///
/// C2's first review round found this header claiming instead that the routing
/// "flips the second and third", which was never measured and is false. The
/// split's real justification is the blindness: one test that could not see the
/// transition was replaced by two that each name a mechanism, and the
/// assertion below was rewritten to pin `pending`'s **signature** for the same
/// reason. `self.sink.mark_pending()` alone survives seam routing — it is what
/// `complete`'s body still says today — so scanning for it could not have
/// detected the change either.
#[test]
fn b5s_pending_path_still_bypasses_the_seam() {
    const TYPESTATE_SRC: &str = include_str!("../src/typestate.rs");
    assert!(
        contains_in_code(TYPESTATE_SRC, "fn pending(mut self) -> PendingToken<S>"),
        "CompletionOwner::pending's signature has changed. If it now takes a \
         clearance, `pending` no longer bypasses the seam: delete this test AND \
         its PENDING entry together."
    );
    assert!(
        contains_in_code(TYPESTATE_SRC, "self.sink.mark_pending()"),
        "CompletionOwner::pending no longer calls its sink directly."
    );
}

#[test]
fn completion_clearance_reaches_raw_sink_once() {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use fsring_core::{
        effect::{CompletionClearance, Effect, EffectContext, EffectSink, Seam},
        typestate::{CompletionOwner, CompletionSink},
    };

    struct NullEffectSink;

    unsafe impl EffectSink for NullEffectSink {
        unsafe fn emit(&mut self, _effect: Effect) {}
    }

    struct CountingCompletionSink(Arc<AtomicU32>);

    unsafe impl CompletionSink for CountingCompletionSink {
        unsafe fn complete(
            &mut self,
            _cleared: CompletionClearance<'_>,
            _status: i32,
            _information: usize,
        ) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        unsafe fn mark_pending(&mut self) {}
    }

    let completed = Arc::new(AtomicU32::new(0));
    let mut seam = Seam::new(NullEffectSink);
    // SAFETY: this host integration test owns no kernel lock.
    let context = unsafe { EffectContext::empty() };
    let clearance = seam
        .clear_completion(&context)
        .expect("completion is permitted with no held locks");

    CompletionOwner::new(CountingCompletionSink(Arc::clone(&completed))).complete(clearance, 0, 0);

    assert_eq!(completed.load(Ordering::Relaxed), 1);
}
