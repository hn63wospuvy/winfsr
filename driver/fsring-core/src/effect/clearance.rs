use core::marker::PhantomData;

use super::{Effect, EffectContext, LockOrderError, may_emit};

/// Reviewed proof that this context permitted completion.
///
/// Rust privacy prevents safe code outside this trusted file from constructing
/// the private field. This file is itself a reviewed trusted boundary, not a
/// language proof that its own runtime check remains present.
#[derive(Debug)]
pub struct CompletionClearance<'a>(PhantomData<&'a EffectContext>);

pub(super) fn checked(ctx: &EffectContext) -> Result<CompletionClearance<'_>, LockOrderError> {
    may_emit(ctx, Effect::CompleteIrp)?;
    Ok(CompletionClearance(PhantomData))
}
