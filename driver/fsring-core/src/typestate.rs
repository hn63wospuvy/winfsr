//! Compile-time safety typestates (`11-rust-implementation.md` section 7).
//!
//! Two kernel-safety properties the C driver model can only assert at runtime
//! are made compile-time facts here: IRQL discipline and completion ownership.
//!
//! Both types are WDK-free. [`CompletionOwner`] reaches the kernel through the
//! [`CompletionSink`] seam, whose real implementation (calling
//! `IoCompleteRequest` / `IoMarkIrpPending`) arrives with `fsring-sys`; the host
//! substitutes a counting stub, which makes at-most-once use through one owner
//! capability testable today. Binding each sink value uniquely to one native
//! request, and performing effects only for that request, remains the unsafe
//! sink implementation's obligation.
//!
//! **What this module proves, and what it does not.** A second `complete` on
//! one owner capability does not compile. That is all. It does not prove a
//! completion occurs, that the first completion is correct, or that two
//! duplicable sink values do not alias one native request. The current request
//! table consumes the private pending/recovery seam and preserves the same
//! at-most-once-per-capability boundary; dropping or forgetting an affine value
//! can still lose progress conservatively.

/// Capability token for PASSIVE_LEVEL.
///
/// Zero-sized, not `Copy`, not `Clone`, and sealed by a private field, so it
/// cannot be constructed by literal outside this crate. A routine that requires
/// PASSIVE_LEVEL takes `&Passive`, so calling it from a raised-IRQL context
/// does not type-check.
///
/// The crate exposes exactly one minting point,
/// [`passive_at_driver_entry`], and it is `unsafe`. That is the honest form of
/// the property: `Passive` is unforgeable in **safe** code outside the crate,
/// and every mint is a reviewable `unsafe` site rather than an ordinary call.
/// The general raise/lower pair arrives with `fsring-sys`.
#[derive(Debug)]
pub struct Passive(());

/// Capability token for DISPATCH_LEVEL. Same sealing rules as [`Passive`].
///
/// A2 left this with no minting point at all, noting that `Dispatch` tokens are
/// produced by the lock guards of `06-locking.md` §1, which were a later slice's.
/// Slice C1 is that slice: [`crate::effect::Guard::dispatch_token`] is the
/// producer, and it is `unsafe` for the same reason
/// [`passive_at_driver_entry`] is — nothing here inspects the running IRQL.
#[derive(Debug)]
pub struct Dispatch(());

impl Passive {
    /// Mint a token. Crate-private: see the type documentation.
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

impl Dispatch {
    /// Mint a token. Crate-private: see the type documentation.
    ///
    /// A2 gated this `#[cfg(test)]` because it had no kernel-build caller and
    /// would have been dead code. Slice C1 added that caller —
    /// [`crate::effect::Guard::dispatch_token`], the spin-lock guard §1 names —
    /// so the gate is removed as A2 said it would be.
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

/// Mint a [`Passive`] token at `DriverEntry`, which the kernel guarantees runs
/// at PASSIVE_LEVEL.
///
/// This is the only minting point in this slice, and it is `unsafe` on purpose:
/// nothing here checks the running IRQL, so an unchecked safe mint would let
/// any caller manufacture the very capability the token exists to prove. A
/// token minted in the wrong context is caught by Driver Verifier's IRQL
/// checks, not by `rustc`.
///
/// # Safety
///
/// The caller must actually be running at PASSIVE_LEVEL. `DriverEntry` is such
/// a context by the kernel's own contract; a dispatch routine is not, unless it
/// has established it.
pub const unsafe fn passive_at_driver_entry() -> Passive {
    Passive::new()
}

/// The kernel operations [`CompletionOwner`] performs, behind a seam so the
/// core stays WDK-free and the host can count them.
///
/// **Implementors MUST NOT be `Copy` or `Clone`, and MUST be constructible only
/// where ownership of the request is transferred.** The at-most-once property
/// holds only over one owner *capability*: `CompletionOwner::new` accepts any
/// sink, so duplicable sink values (a `Copy` wrapper around a raw `IRP` pointer,
/// say) could build two owners over one request and complete it twice, with no
/// compile error and no fixture to catch it. The type system prevents a second
/// completion through one owner capability; keeping exactly one nonduplicable
/// sink value per native request is this trait's obligation.
///
/// # Safety
///
/// Each sink value must represent one unique native request, must not be
/// duplicated, and must perform pending/completion effects only for that
/// request. The raw completion signature itself requires proof that the
/// held-context checker approved completion when the clearance came from the
/// safe API. Its trusted construction lives in the reviewed, byte-frozen
/// `effect/clearance.rs`. Fabricating a clearance with `MaybeUninit`,
/// `transmute`, or equivalent unsafe code violates that invariant, just as
/// duplicating a native request violates this unsafe implementor contract.
/// Native request identity remains the unsafe implementor's obligation. These
/// obligations are what lift the type system's at-most-once-per-owner-capability
/// property to the real request.
pub unsafe trait CompletionSink {
    /// Invoke the completion effect through this sink value.
    ///
    /// # Safety
    ///
    /// The effect must target the unique native request represented by this
    /// sink value, and `cleared` must be a genuine clearance obtained from the
    /// safe API.
    unsafe fn complete(
        &mut self,
        cleared: crate::effect::CompletionClearance<'_>,
        status: i32,
        information: usize,
    );
    /// Invoke the pending effect through this sink value.
    ///
    /// # Safety
    ///
    /// The effect must target the unique native request represented by this
    /// sink value.
    unsafe fn mark_pending(&mut self);
}

/// Move-only capability for invoking at most one terminal effect through its
/// contained sink value.
///
/// [`complete`](Self::complete) consumes `self`, so a second use through the
/// same owner capability is a compile error. This does not prove that another
/// sink value cannot name the same native request; uniqueness remains the
/// unsafe [`CompletionSink`] implementation's obligation. The capability is
/// not `Copy` or `Clone` and deliberately has no `Drop` effect: dropping it
/// performs no completion, which this slice does not attempt to detect (see
/// the module documentation).
#[derive(Debug)]
pub struct CompletionOwner<S: CompletionSink> {
    sink: S,
}

/// Move-only token retaining one pending owner capability.
///
/// For this token and its contained capability,
/// [`into_owner`](Self::into_owner) is the sole request-table recovery route
/// back to a completing capability. The token exposes no completion method
/// itself, and safe external code cannot invoke the crate-private recovery
/// transition. Native request uniqueness remains the unsafe
/// [`CompletionSink`] implementation's obligation.
///
/// [`crate::reqtab::RequestTable`] admission consumes a [`CompletionOwner`]
/// through the private [`CompletionOwner::pending`] seam and stores this token.
/// Its terminal application path recovers the owner through the private seam
/// above. Safe external code can call neither transition.
#[derive(Debug)]
pub struct PendingToken<S: CompletionSink> {
    #[allow(dead_code)] // Consumed by the request-table slice.
    sink: S,
}

impl<S: CompletionSink> CompletionOwner<S> {
    /// Create an owner capability from one sink value.
    pub const fn new(sink: S) -> Self {
        Self { sink }
    }

    /// Consume this owner capability and invoke its sink's completion effect.
    ///
    /// **Requires a [`crate::effect::CompletionClearance`]** and passes it to
    /// the clearance-bearing raw [`CompletionSink::complete`] method. The safe
    /// API obtains that proof through
    /// [`crate::effect::Seam::clear_completion`] after the reviewed,
    /// byte-frozen `effect/clearance.rs` construction boundary checks
    /// `Effect::CompleteIrp` for the caller's held context.
    /// Slice C1 modelled `06-locking.md` §6's no-completion-under-a-lock rule
    /// and left this path unchecked, with a standing test measuring the gap;
    /// C2 closes it, and the compiler is what holds it closed.
    pub fn complete(
        mut self,
        cleared: crate::effect::CompletionClearance<'_>,
        status: i32,
        information: usize,
    ) {
        // SAFETY: this capability contains this sink value, and consuming
        // `self` prevents a second completion effect through the same owner
        // capability. Native request identity and uniqueness remain the
        // `CompletionSink` implementation's obligation.
        unsafe { self.sink.complete(cleared, status, information) };
    }

    /// Consume this owner capability, invoke its pending effect, and yield the
    /// corresponding pending token.
    #[allow(dead_code)] // Called by the request-table slice.
    pub(crate) fn pending(mut self) -> PendingToken<S> {
        // SAFETY: this capability contains this sink value, and consuming
        // `self` moves that value into the corresponding pending token. Native
        // request identity and uniqueness remain the `CompletionSink`
        // implementation's obligation.
        unsafe { self.sink.mark_pending() };
        PendingToken { sink: self.sink }
    }
}

impl<S: CompletionSink> PendingToken<S> {
    /// Recover this token's owner capability for the request table's terminal
    /// path.
    #[allow(dead_code)] // Called by the request-table slice.
    pub(crate) fn into_owner(self) -> CompletionOwner<S> {
        CompletionOwner { sink: self.sink }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CountingSink {
        completed: u32,
        pended: u32,
        last: Option<(i32, usize)>,
    }

    unsafe impl CompletionSink for &mut CountingSink {
        unsafe fn complete(
            &mut self,
            _cleared: crate::effect::CompletionClearance<'_>,
            status: i32,
            information: usize,
        ) {
            self.completed = self.completed.saturating_add(1);
            self.last = Some((status, information));
        }
        unsafe fn mark_pending(&mut self) {
            self.pended = self.pended.saturating_add(1);
        }
    }

    #[test]
    fn complete_calls_the_sink_exactly_once() {
        let mut sink = CountingSink::default();
        // A real clearance from the seam: §6 permits completion with nothing
        // held, so an empty context yields one. Minting it rather than
        // fabricating keeps this test on the production path.
        struct NullSink;
        // SAFETY: performs no kernel effect.
        unsafe impl crate::effect::EffectSink for NullSink {
            unsafe fn emit(&mut self, _effect: crate::effect::Effect) {}
        }
        let mut seam = crate::effect::Seam::new(NullSink);
        // SAFETY: a host test owns no kernel lock.
        let ctx = unsafe { crate::effect::EffectContext::empty() };
        let Ok(cleared) = seam.clear_completion(&ctx) else {
            panic!("§6 permits completion with nothing held")
        };
        CompletionOwner::new(&mut sink).complete(cleared, 0, 7);
        assert_eq!(sink.completed, 1);
        assert_eq!(sink.pended, 0);
        assert_eq!(sink.last, Some((0, 7)));
    }

    #[test]
    fn pending_marks_and_yields_a_receipt_without_completing() {
        let mut sink = CountingSink::default();
        let token = CompletionOwner::new(&mut sink).pending();
        let _owner_back = token.into_owner();
        assert_eq!(sink.pended, 1);
        assert_eq!(sink.completed, 0);
    }

    #[test]
    fn a_passive_only_routine_accepts_the_passive_token() {
        const fn needs_passive(_p: &Passive) -> u32 {
            1
        }
        // SAFETY: a host unit test is not a kernel context at all; the token's
        // meaning is exercised here, not its IRQL claim.
        let p = unsafe { passive_at_driver_entry() };
        assert_eq!(needs_passive(&p), 1);
    }

    #[test]
    fn a_dispatch_token_can_be_minted_inside_the_crate() {
        // This unit test pins the crate-private constructor directly. The
        // public unsafe Guard::dispatch_token is the production mint path
        // after its caller has acquired the spin lock.
        let d = Dispatch::new();
        assert_eq!(core::mem::size_of_val(&d), 0);
    }

    #[test]
    fn tokens_are_zero_sized() {
        assert_eq!(core::mem::size_of::<Passive>(), 0);
        assert_eq!(core::mem::size_of::<Dispatch>(), 0);
    }
}
