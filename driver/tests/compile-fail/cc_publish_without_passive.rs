// 07-cache-mm.md section 3: "CcSetFileSizes MUST be called at PASSIVE_LEVEL."
// A dispatch-level token must not satisfy the seam.
//
// The context argument is deliberately WELL-TYPED. C1 changed this parameter
// from HeldLocks to EffectContext, and leaving the old type here would make the
// fixture fail on an argument-type mismatch as well -- still E0308, still
// "passing", but no longer isolating the IRQL property it exists to prove.
use fsring_core::effect::EffectContext;
use fsring_core::size::{publish_sizes_to_cc, IoOrigin, SizeChange};
use fsring_core::typestate::Dispatch;

pub fn publish_at_dispatch(irql: &Dispatch) {
    let _ = publish_sizes_to_cc(irql, unsafe { EffectContext::empty() }, IoOrigin::Cached, SizeChange::Extend);
}
