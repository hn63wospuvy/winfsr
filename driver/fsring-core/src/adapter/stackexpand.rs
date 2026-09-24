//! The result contract of an expanded-stack callout.
//!
//! `KeExpandKernelStackAndCallout` returns `VOID` from the callout, so a result
//! can only travel in the parameter block, and the DDI's own NTSTATUS is a
//! second, independent answer. Two answers admit three outcomes and only one of
//! them is success; this module is where that is decided, in the WDK-free crate,
//! because no test on a machine that cannot load a driver can execute the
//! kernel code that consumes it.
//!
//! SETUP folds every refusal into one answer ([`resolve`]) because it refuses
//! on any of them and reports the DDI's status itself. CLEANUP cannot: an
//! arrival it completes unclaimed loses its context, so it reads the status
//! ([`resolve_cleanup`]) to tell the one refusal a wait can clear from the
//! ones it cannot, and waits for that one only as long as its budget lasts.
//!
//! Per `11-rust-implementation.md` section 1: `fsring-core` owns call-site
//! sequencing, `fsring-fsd` is the marshalling adapter.

/// Why an expanded-stack callout produced no result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandFault {
    /// The kernel refused the expansion. The callout never ran, and whatever
    /// the slot holds was not put there by it.
    Refused,
    /// The kernel reported success and the callout left its slot unwritten,
    /// which means it did not run to completion.
    SlotUnwritten,
}

/// Resolve the DDI's status and the callout's outcome slot into one answer.
///
/// `expanded` is the DDI's own success, tested against `STATUS_SUCCESS` exactly
/// rather than by sign: this is the fail-closed reading of a
/// `_Must_inspect_result_` return.
pub fn resolve<T>(expanded: bool, slot: Option<T>) -> Result<T, ExpandFault> {
    match (expanded, slot) {
        (false, _) => Err(ExpandFault::Refused),
        (true, None) => Err(ExpandFault::SlotUnwritten),
        (true, Some(value)) => Ok(value),
    }
}

/// `STATUS_SUCCESS`, the one status a CLEANUP expansion reads as success.
const STATUS_SUCCESS: i32 = 0;

/// `STATUS_NO_MEMORY`, which `ntstatus.h` defines as `((NTSTATUS)0xC0000017L)`.
///
/// A literal because this crate is WDK-free. `fsring-fsd`'s `control.rs`
/// asserts it equal to `wdk_sys::STATUS_NO_MEMORY` at build time, as `boot.rs`
/// does for `adapter::load`'s status literals.
pub const STATUS_NO_MEMORY: i32 = 0xC000_0017_u32 as i32;

/// How many expansions one CLEANUP arrival asks for before it gives up.
///
/// Every refused attempt but the last is followed by one 10 ms wait, so 100
/// attempts wait about a second, and up to about three at the default timer
/// resolution, where a 10 ms relative wait can take two 15.6 ms ticks.
/// Bounded because the waiting thread is the one closing the handle, often a
/// terminating process's own, and a non-alertable `KernelMode` wait is one
/// `TerminateProcess` cannot break (round-20 native review, N1). The crate's
/// other delay, `delay_one_drain_interval`, is bounded for the same reason.
pub const CLEANUP_EXPANSION_ATTEMPTS: u32 = 100;

/// Why a CLEANUP expansion produced no result, read from the DDI's status.
///
/// SETUP's [`resolve`] folds every refusal into one `Refused`, which is right
/// for a caller that refuses on any fault. A CLEANUP that completes unclaimed
/// loses its context, so it has to know which refusals a wait can clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupExpandFault {
    /// `STATUS_NO_MEMORY` with the slot empty: the kernel could not allocate
    /// the stack and the callout never ran. The one refusal a wait can clear.
    ShortOfMemory,
    /// Any other failure with the slot empty. Microsoft's reference for
    /// `KeExpandKernelStackAndCalloutEx` lists `STATUS_STACK_OVERFLOW` -- the
    /// stack "would exceed the operating system's internal limits" -- and two
    /// parameter errors. None clears with time, and a status no document
    /// lists is not assumed to.
    Refused,
    /// A failure status beside a WRITTEN slot. The two answers disagree, and
    /// the callout may have run and taken its counted claim, so running it
    /// again could take a second claim for one arrival (round-20 native
    /// review, N5).
    Contradicted,
    /// `STATUS_SUCCESS` with the slot empty: the callout ran and returned
    /// before writing it.
    SlotUnwritten,
}

/// Read a CLEANUP expansion's status and slot into one answer.
///
/// Success is `STATUS_SUCCESS` exactly, as in [`resolve`]: the fail-closed
/// reading of a `_Must_inspect_result_` return.
pub fn resolve_cleanup<T>(status: i32, slot: Option<T>) -> Result<T, CleanupExpandFault> {
    match (status, slot) {
        (STATUS_SUCCESS, Some(value)) => Ok(value),
        (STATUS_SUCCESS, None) => Err(CleanupExpandFault::SlotUnwritten),
        (_, Some(_)) => Err(CleanupExpandFault::Contradicted),
        (STATUS_NO_MEMORY, None) => Err(CleanupExpandFault::ShortOfMemory),
        (_, None) => Err(CleanupExpandFault::Refused),
    }
}

/// What a CLEANUP does after one refused expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupExpansionRecourse {
    /// Wait one interval, then ask for the expansion again.
    DelayAndRetry,
    /// The kernel was short of memory for the whole budget. Give up.
    Exhausted,
    /// Asking again cannot change the answer. Give up.
    Surrender,
}

/// The expansions one CLEANUP arrival may ask for.
///
/// One per arrival, made before the first attempt. A budget made inside the
/// retry loop would start again on every attempt and bound nothing.
///
/// Giving up completes the arrival unclaimed, which strands the context: the
/// generation stays live, CLOSE may free nothing, and unload waits on an
/// admission nothing releases. That leak is disclosed and chosen over a
/// closing thread that never returns; `close_choreography` walks it and
/// asserts it is reached only by giving up.
#[derive(Debug)]
pub struct CleanupExpansionBudget {
    attempts: u32,
    limit: u32,
}

impl CleanupExpansionBudget {
    /// A full budget of [`CLEANUP_EXPANSION_ATTEMPTS`].
    pub const fn per_arrival() -> Self {
        Self::with_limit(CLEANUP_EXPANSION_ATTEMPTS)
    }

    /// A budget of `limit` attempts: the walk's, kept small enough to explore.
    pub(crate) const fn with_limit(limit: u32) -> Self {
        Self { attempts: 0, limit }
    }

    /// Count one refused attempt and decide what follows it.
    ///
    /// No catch-all: a fault added without a decision here is an E0004, not a
    /// silent retry of something that will never succeed.
    pub fn answer_refusal(&mut self, fault: CleanupExpandFault) -> CleanupExpansionRecourse {
        self.attempts = self.attempts.saturating_add(1);
        match fault {
            CleanupExpandFault::ShortOfMemory if self.attempts < self.limit => {
                CleanupExpansionRecourse::DelayAndRetry
            }
            CleanupExpandFault::ShortOfMemory => CleanupExpansionRecourse::Exhausted,
            CleanupExpandFault::Refused
            | CleanupExpandFault::Contradicted
            | CleanupExpandFault::SlotUnwritten => CleanupExpansionRecourse::Surrender,
        }
    }
}

#[cfg(test)]
mod tests;
