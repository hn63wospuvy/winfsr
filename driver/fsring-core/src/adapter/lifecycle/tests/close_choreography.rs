//! The close choreography, walked over every interleaving that can reach it.
//!
//! `fsring-fsd` implements CLEANUP, CLOSE, the finalizer and the two scans that
//! dereference a cell's recorded control context, and it has no host test
//! target. Round 17 freed a context the process-loss and unload scans still
//! named and let CLOSE rewrite the lifetime slot with no lock, and nothing in
//! the repository could run either path. This walk drives the REAL core
//! decisions those paths make -- `ControlBinding::claim_cleanup`,
//! `decide_cleanup_route`, `prepare_terminal_claim`, `PrecommitCleanupPlan::begin`,
//! `continue_cleanup` and `ControlContextCloseOwnership::for_lifetime` --
//! through every interleaving of its actors and checks the design's invariants
//! at every state it reaches.
//!
//! What core cannot decide enters as the boolean fields of [`Policy`]. Each is
//! pinned in `fsring-fsd` by `audit_c4_lifetime.py`, and each has a retained
//! plant below that makes this walk fail without it.
//!
//! BOUNDARY. Modelled: one published generation; one CLEANUP, arriving with or
//! without the dispatch rundown, whose stack expansion the kernel may refuse
//! for memory -- which the dispatch answers by asking again until core's
//! budget is spent -- or for a reason no wait clears, which it gives up on at
//! once; one CLOSE; one external terminal source (process loss or unload) that
//! reaches the context through the recorded pointer; one later scan. Not
//! modelled: a `Blocked` or opaque-retained outcome, whose context stays
//! cell-owned and is never freed by design; a second concurrent scan;
//! protocol-fault arrivals, whose native entries `claim_committed_protocol`,
//! `run_terminal_arrival` and `run_terminal_for_process` have no production
//! caller on this tree.
//!
//! Giving up is modelled, and it strands the context: the arrival completes
//! unclaimed, CLOSE may free nothing, and unload waits on an admission nothing
//! releases. That leak is disclosed rather than closed -- chosen over a closing
//! thread that never returns (round-20 native review, N1) -- and the design
//! test asserts it is reached, and reached only by giving up.
//!
//! Three exclusions are worth naming, because each is a path `fsring-fsd`
//! still has and this walk says nothing about directly:
//!
//! * The callout's own early return, `stackexpand::CleanupExpandFault::SlotUnwritten`:
//!   it ran and returned before claiming anything, which only its
//!   null-parameter check does. Core surrenders on it, so it leaves the state
//!   `Actor::CleanupExpansionImpossible` leaves, and core's `stackexpand` tests
//!   hold its classification.
//! * `CleanupExpandFault::Contradicted`, a failure status beside a written
//!   slot. It needs the DDI to report failure after running the callout,
//!   which its documented contract does not do. Core surrenders on it so that
//!   it can never cause a second counted claim for one arrival.
//! * A CLOSE with no CLEANUP before it. `enabled(Actor::Close)` requires
//!   `CleanupPc::Done`, so no state here has the I/O manager's teardown of a
//!   file object that never reached a handle. That path finds the CREATE
//!   admission lease in the slot, which CLOSE adopts when the binding holds no
//!   installation (native review N18-2's repair); its table is
//!   `adapter::setup::tests::only_an_uninstalled_lease_is_adopted`.

use super::publish_with_binding;
use crate::adapter::lifecycle::{
    CleanupContinuation, CleanupPass, CleanupRoute, CleanupRouteResult, TerminalOutcomeKind,
    continue_cleanup, decide_cleanup_route,
};
use crate::adapter::setup::{
    ControlContextCloseOwnership, ControlContextLifetimeKind, PrecommitCleanupPlan,
};
use crate::adapter::stackexpand::{
    CleanupExpandFault, CleanupExpansionBudget, CleanupExpansionRecourse, STATUS_NO_MEMORY,
    resolve_cleanup,
};
use crate::session::{
    CleanupBindingClaim, ControlBinding, ControlBindingState, CoreTerminalDisposition,
    RegistryLease, SessionLocator, SessionRegistry, StrongSessionRef, TerminalReason,
    TerminalRendezvous, TerminalRequest, TerminalResult, prepare_terminal_claim,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Actor {
    External,
    Cleanup,
    /// The kernel refused CLEANUP's stack expansion for memory.
    CleanupExpansionShort,
    /// The kernel refused it for a reason no wait clears.
    CleanupExpansionImpossible,
    Close,
    Scan,
}

const ACTORS: [Actor; 6] = [
    Actor::External,
    Actor::Cleanup,
    Actor::CleanupExpansionShort,
    Actor::CleanupExpansionImpossible,
    Actor::Close,
    Actor::Scan,
];

const SOURCES: [TerminalRequest; 2] = [TerminalRequest::ProcessLoss, TerminalRequest::Unload];

/// The walk's budget: one retry that recovers and one that is spent fit in it.
/// Core's own tests hold the production budget.
const WALK_EXPANSION_ATTEMPTS: u32 = 3;

/// `STATUS_STACK_OVERFLOW` (`ntstatus.h`): the listed refusal no wait clears.
const STATUS_STACK_OVERFLOW: i32 = 0xC000_00FD_u32 as i32;

/// How a CLEANUP that gave up its expansion got there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GaveUp {
    fault: CleanupExpandFault,
    attempts: u32,
}

/// The decisions under test. Core's are function pointers so a retained plant
/// can put the defective one back; the driver's are booleans.
#[derive(Clone, Copy)]
struct Policy {
    close_decision: fn(ControlContextLifetimeKind) -> ControlContextCloseOwnership,
    continuation: fn(CleanupPass, CleanupRouteResult) -> CleanupContinuation,
    /// `fsring_dispatch_cleanup`: a refused rundown acquisition still takes the
    /// committed route.
    late_cleanup_takes_the_committed_route: bool,
    /// `RegistryLockGuard::publish_completed_generation`: the store hold retires
    /// the cell's recorded context pointer.
    finalizer_retires_the_recorded_pointer: bool,
    /// `run_close_plan`: `take_close_ownership` runs under the registry lock.
    close_takes_the_registry_lock: bool,
    /// `fsring_dispatch_cleanup`: `release_outer` precedes the committed route.
    cleanup_releases_the_rundown_before_the_route: bool,
    /// `fsring_dispatch_cleanup`: a `DelayAndRetry` from the budget is followed
    /// by another expansion, not by completing the arrival unclaimed.
    cleanup_follows_the_expansion_budget: bool,
}

const DESIGN: Policy = Policy {
    close_decision: ControlContextCloseOwnership::for_lifetime,
    continuation: continue_cleanup,
    late_cleanup_takes_the_committed_route: true,
    finalizer_retires_the_recorded_pointer: true,
    close_takes_the_registry_lock: true,
    cleanup_releases_the_rundown_before_the_route: true,
    cleanup_follows_the_expansion_budget: true,
};

/// What `f78cda8` shipped.
const ROUND_17: Policy = Policy {
    close_decision: round_17_close_decision,
    continuation: never_reclaim,
    late_cleanup_takes_the_committed_route: false,
    finalizer_retires_the_recorded_pointer: false,
    close_takes_the_registry_lock: false,
    cleanup_releases_the_rundown_before_the_route: true,
    cleanup_follows_the_expansion_budget: false,
};

/// Round 17's `for_lifetime`: an unacknowledged `Completed` record is freeable.
const fn round_17_close_decision(kind: ControlContextLifetimeKind) -> ControlContextCloseOwnership {
    match kind {
        ControlContextLifetimeKind::Close | ControlContextLifetimeKind::Completed => {
            ControlContextCloseOwnership::CloseRight
        }
        ControlContextLifetimeKind::Lease => ControlContextCloseOwnership::Lease,
        ControlContextLifetimeKind::LiveCellOwned
        | ControlContextLifetimeKind::BlockedCellOwned => ControlContextCloseOwnership::CellOwned,
    }
}

/// Rounds 16 and 17: a completed terminal is where CLEANUP stops.
const fn never_reclaim(_pass: CleanupPass, result: CleanupRouteResult) -> CleanupContinuation {
    match result {
        CleanupRouteResult::Terminal(TerminalOutcomeKind::Blocked)
        | CleanupRouteResult::Blocked
        | CleanupRouteResult::OpaqueRetained => CleanupContinuation::Refuse,
        _ => CleanupContinuation::Proceed,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalPc {
    WaitControlRundown,
    StoreRecord,
    PublishClosingComplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalPc {
    NotArrived,
    Winner(TerminalPc),
    Joining,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanupPc {
    NotArrived,
    /// Holding the dispatch rundown, about to take the precommit look.
    PrecommitClaim,
    /// About to claim the committed route under the registry lock.
    Route(CleanupPass),
    Winner(CleanupPass, TerminalPc),
    Joining(CleanupPass),
    Continue(CleanupPass, CleanupRouteResult),
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClosePc {
    NotArrived,
    /// Unlocked only: the slot was emptied, and this is what the restore writes.
    Restore(ControlContextLifetimeKind),
    Free,
    Done,
}

/// Everything that decides the future of a state. The affine core objects are
/// not part of it: the only transitions that move them (`commit` of a terminal
/// claim, `publish_closing_complete`, `claim_cleanup`) are all reflected in
/// `binding` and the program counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Signature {
    binding: ControlBindingState,
    lifetime: ControlContextLifetimeKind,
    recorded_pointer: bool,
    cleanup_holds_the_rundown: bool,
    rundown_run_down: bool,
    outcome_visible: bool,
    finalizer_holds_the_lock: bool,
    close_holds_a_right: bool,
    frees: u8,
    external: ExternalPc,
    cleanup: CleanupPc,
    close: ClosePc,
    scanned: bool,
    expansion_attempts: u32,
    cleanup_gave_up: Option<GaveUp>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Report {
    states: usize,
    use_after_free: bool,
    freed_unacknowledged: bool,
    record_lost: bool,
    finalizer_preflight_refused: bool,
    precommit_consumed_a_completion: bool,
    unbounded_reclaim: bool,
    deadlock: bool,
    stranded: bool,
    /// A run that gave up its expansion and freed nothing: the disclosed leak.
    /// The design must reach it, which is what keeps the disclosure true.
    stranded_after_giving_up: bool,
    /// A run that gave up on a memory refusal before its budget was spent.
    stranded_before_the_budget: bool,
    /// A completed run refused for memory at least once that still freed its
    /// context. Not a violation: the witness that the retry recovers, without
    /// which the assertions about giving up hold of a walk that never retries.
    retried_then_freed: bool,
    /// Both ways of giving up were walked.
    exhaustion_walked: bool,
    impossible_refusal_walked: bool,
}

impl Report {
    fn absorb(&mut self, seen: Self) {
        self.use_after_free |= seen.use_after_free;
        self.freed_unacknowledged |= seen.freed_unacknowledged;
        self.record_lost |= seen.record_lost;
        self.finalizer_preflight_refused |= seen.finalizer_preflight_refused;
        self.precommit_consumed_a_completion |= seen.precommit_consumed_a_completion;
        self.unbounded_reclaim |= seen.unbounded_reclaim;
    }
}

struct World {
    policy: Policy,
    request: TerminalRequest,
    registry: SessionRegistry<2>,
    rendezvous: TerminalRendezvous,
    binding: ControlBinding,
    lease: Option<RegistryLease>,
    locator: SessionLocator,
    _control: StrongSessionRef,
    lifetime: ControlContextLifetimeKind,
    recorded_pointer: bool,
    cleanup_holds_the_rundown: bool,
    rundown_run_down: bool,
    outcome_visible: bool,
    finalizer_holds_the_lock: bool,
    close_holds_a_right: bool,
    frees: u8,
    external: ExternalPc,
    cleanup: CleanupPc,
    close: ClosePc,
    scanned: bool,
    /// Not in the signature: `expansion_attempts` determines it.
    expansion_budget: CleanupExpansionBudget,
    expansion_attempts: u32,
    cleanup_gave_up: Option<GaveUp>,
    violations: Report,
}

impl World {
    fn start(policy: Policy, request: TerminalRequest) -> Self {
        let mut registry = SessionRegistry::<2>::new();
        let (published, rendezvous, binding) = publish_with_binding(&mut registry, 9201);
        let (locator, lease, control) = published.into_parts();
        Self {
            policy,
            request,
            registry,
            rendezvous,
            binding,
            lease: Some(lease),
            locator,
            _control: control,
            // `take_lease_for_live` moved the CREATE lease into the cell.
            lifetime: ControlContextLifetimeKind::LiveCellOwned,
            recorded_pointer: true,
            cleanup_holds_the_rundown: false,
            rundown_run_down: false,
            outcome_visible: false,
            finalizer_holds_the_lock: false,
            close_holds_a_right: false,
            frees: 0,
            external: ExternalPc::NotArrived,
            cleanup: CleanupPc::NotArrived,
            close: ClosePc::NotArrived,
            scanned: false,
            expansion_budget: CleanupExpansionBudget::with_limit(WALK_EXPANSION_ATTEMPTS),
            expansion_attempts: 0,
            cleanup_gave_up: None,
            violations: Report::default(),
        }
    }

    fn signature(&self) -> Signature {
        Signature {
            binding: self.binding.state(),
            lifetime: self.lifetime,
            recorded_pointer: self.recorded_pointer,
            cleanup_holds_the_rundown: self.cleanup_holds_the_rundown,
            rundown_run_down: self.rundown_run_down,
            outcome_visible: self.outcome_visible,
            finalizer_holds_the_lock: self.finalizer_holds_the_lock,
            close_holds_a_right: self.close_holds_a_right,
            frees: self.frees,
            external: self.external,
            cleanup: self.cleanup,
            close: self.close,
            scanned: self.scanned,
            expansion_attempts: self.expansion_attempts,
            cleanup_gave_up: self.cleanup_gave_up,
        }
    }

    fn all_done(&self) -> bool {
        self.external == ExternalPc::Done
            && self.cleanup == CleanupPc::Done
            && self.close == ClosePc::Done
            && self.scanned
    }

    /// A dereference of the control context.
    fn touch(&mut self) {
        if self.frees > 0 {
            self.violations.use_after_free = true;
        }
    }

    fn enabled(&self, actor: Actor) -> bool {
        // Every registry-lock step waits for the finalizer's store hold to end.
        let lock_free = !self.finalizer_holds_the_lock;
        match actor {
            Actor::External => match self.external {
                ExternalPc::NotArrived => lock_free,
                ExternalPc::Winner(pc) => self.terminal_step_enabled(pc),
                ExternalPc::Joining => self.outcome_visible,
                ExternalPc::Done => false,
            },
            Actor::Cleanup => match self.cleanup {
                CleanupPc::NotArrived | CleanupPc::Continue(..) => true,
                CleanupPc::PrecommitClaim | CleanupPc::Route(_) => lock_free,
                CleanupPc::Winner(_, pc) => self.terminal_step_enabled(pc),
                CleanupPc::Joining(_) => self.outcome_visible,
                CleanupPc::Done => false,
            },
            // Before the first pass's callout: the refusal comes before
            // anything is claimed, and a retried attempt re-enters this same
            // state. The attempt count bounds it: the budget ends the retry.
            Actor::CleanupExpansionShort | Actor::CleanupExpansionImpossible => {
                matches!(self.cleanup, CleanupPc::Route(CleanupPass::First))
            }
            Actor::Close => match self.close {
                // IRP_MJ_CLEANUP completes before IRP_MJ_CLOSE for one file object.
                ClosePc::NotArrived => {
                    self.cleanup == CleanupPc::Done
                        && (lock_free || !self.policy.close_takes_the_registry_lock)
                }
                ClosePc::Restore(_) | ClosePc::Free => true,
                ClosePc::Done => false,
            },
            Actor::Scan => !self.scanned && lock_free,
        }
    }

    const fn terminal_step_enabled(&self, pc: TerminalPc) -> bool {
        match pc {
            // `ExWaitForRundownProtectionRelease` holds no lock and waits for
            // every holder of the dispatch rundown.
            TerminalPc::WaitControlRundown => !self.cleanup_holds_the_rundown,
            TerminalPc::StoreRecord => !self.finalizer_holds_the_lock,
            TerminalPc::PublishClosingComplete => self.finalizer_holds_the_lock,
        }
    }

    fn step(&mut self, actor: Actor) {
        assert!(
            self.enabled(actor),
            "{actor:?} was replayed while it could not move"
        );
        match actor {
            Actor::External => self.step_external(),
            Actor::Cleanup => self.step_cleanup(),
            Actor::CleanupExpansionShort => self.refuse_expansion(STATUS_NO_MEMORY),
            Actor::CleanupExpansionImpossible => self.refuse_expansion(STATUS_STACK_OVERFLOW),
            Actor::Close => self.step_close(),
            Actor::Scan => {
                // The process-loss or unload scan, under the registry lock: a
                // set pointer is dereferenced to prepare a claim.
                if self.recorded_pointer {
                    self.touch();
                }
                self.scanned = true;
            }
        }
    }

    /// `KeExpandKernelStackAndCallout` refused with `status`: the callout never
    /// ran, so the slot is empty and nothing was claimed. Core reads the pair,
    /// the budget answers, and the dispatch asks again or gives up.
    fn refuse_expansion(&mut self, status: i32) {
        let fault = resolve_cleanup::<()>(status, None)
            .expect_err("a refused expansion never carries a result");
        self.expansion_attempts = self.expansion_attempts.saturating_add(1);
        let gives_up = match self.expansion_budget.answer_refusal(fault) {
            CleanupExpansionRecourse::DelayAndRetry => {
                !self.policy.cleanup_follows_the_expansion_budget
            }
            CleanupExpansionRecourse::Exhausted | CleanupExpansionRecourse::Surrender => true,
        };
        if gives_up {
            // Round 18 did this on every refusal. The design does it only once
            // core says asking again cannot help: the arrival completes
            // unclaimed.
            self.cleanup_gave_up = Some(GaveUp {
                fault,
                attempts: self.expansion_attempts,
            });
            self.finish_cleanup();
        }
        // Otherwise the wait elapses and the next `Actor::Cleanup` step is the
        // re-entered expansion's callout. The program counter stays at
        // `Route(First)`; the attempt count, which is in the signature, is what
        // makes the second attempt a state of its own.
    }

    /// `prepare_terminal_claim` then `commit`, as `prepare_native_terminal_claim`
    /// does under the registry lock. `Some(true)` won, `Some(false)` joined.
    fn claim_terminal(&mut self, request: TerminalRequest) -> Option<bool> {
        let prepared = prepare_terminal_claim(
            &mut self.registry,
            &mut self.binding,
            &mut self.rendezvous,
            &mut self.lease,
            self.locator,
            request,
        )
        .ok()?;
        match prepared.commit() {
            CoreTerminalDisposition::Winner(_winner) => Some(true),
            CoreTerminalDisposition::Join(_ticket) => Some(false),
            CoreTerminalDisposition::Completed(_) | CoreTerminalDisposition::Blocked(_) => None,
        }
    }

    /// One step of a winner's terminal; `None` once its outcome is published.
    fn run_terminal_step(&mut self, pc: TerminalPc) -> Option<TerminalPc> {
        match pc {
            TerminalPc::WaitControlRundown => {
                // The fence's `WaitControlRundown`: no dispatch acquires it again.
                self.rundown_run_down = true;
                Some(TerminalPc::StoreRecord)
            }
            TerminalPc::StoreRecord => {
                // The deletion preflight requires a still cell-owned slot, then
                // `store_completed_control_record_prepared` fills it.
                self.finalizer_holds_the_lock = true;
                self.touch();
                if self.lifetime != ControlContextLifetimeKind::LiveCellOwned {
                    self.violations.finalizer_preflight_refused = true;
                }
                self.lifetime = ControlContextLifetimeKind::Completed;
                Some(TerminalPc::PublishClosingComplete)
            }
            TerminalPc::PublishClosingComplete => {
                // Same hold: `publish_closing_complete_prepared` dereferences
                // the context, the pointer is retired, the rendezvous closes.
                self.touch();
                let result = TerminalResult {
                    reason: TerminalReason::ProcessLoss,
                    fence_failures: 0,
                };
                self.binding
                    .publish_closing_complete(self.locator, result, true)
                    .expect("the claimed generation publishes its completion");
                if self.policy.finalizer_retires_the_recorded_pointer {
                    self.recorded_pointer = false;
                }
                self.outcome_visible = true;
                self.finalizer_holds_the_lock = false;
                None
            }
        }
    }

    fn step_external(&mut self) {
        let pc = self.external;
        self.external = match pc {
            ExternalPc::NotArrived if !self.recorded_pointer => {
                // The rendezvous route answers from the cell; no context.
                ExternalPc::Done
            }
            ExternalPc::NotArrived => {
                self.touch();
                match self.binding.state() {
                    ControlBindingState::Active(_) => match self.claim_terminal(self.request) {
                        Some(true) => ExternalPc::Winner(TerminalPc::WaitControlRundown),
                        Some(false) => ExternalPc::Joining,
                        None => ExternalPc::Done,
                    },
                    ControlBindingState::ClosingLive(_) => ExternalPc::Joining,
                    _ => ExternalPc::Done,
                }
            }
            ExternalPc::Winner(pc) => match self.run_terminal_step(pc) {
                Some(next) => ExternalPc::Winner(next),
                None => ExternalPc::Done,
            },
            // `join_terminal_outcome` copies the cell's outcome; no context.
            ExternalPc::Joining => ExternalPc::Done,
            ExternalPc::Done => unreachable!("a finished actor is never enabled"),
        };
    }

    fn step_cleanup(&mut self) {
        let pc = self.cleanup;
        match pc {
            CleanupPc::NotArrived => {
                // `ControlDispatchRundownGuard::acquire`.
                self.cleanup = if !self.rundown_run_down {
                    self.cleanup_holds_the_rundown = true;
                    CleanupPc::PrecommitClaim
                } else if self.policy.late_cleanup_takes_the_committed_route {
                    CleanupPc::Route(CleanupPass::First)
                } else {
                    CleanupPc::Done
                };
            }
            CleanupPc::PrecommitClaim => {
                // `fsring_dispatch_cleanup`'s own hold.
                self.touch();
                let claim = self
                    .binding
                    .claim_cleanup()
                    .expect("a published binding admits CLEANUP");
                if matches!(claim, CleanupBindingClaim::Completed { .. }) {
                    self.violations.precommit_consumed_a_completion = true;
                }
                assert!(
                    PrecommitCleanupPlan::begin(claim).is_err(),
                    "a published binding took the precommit route"
                );
                if self.policy.cleanup_releases_the_rundown_before_the_route {
                    self.cleanup_holds_the_rundown = false;
                }
                self.cleanup = CleanupPc::Route(CleanupPass::First);
            }
            CleanupPc::Route(pass) => {
                // `claim_native_cleanup_route`.
                self.touch();
                let claim = self
                    .binding
                    .claim_cleanup()
                    .expect("CLEANUP's committed route claims");
                self.cleanup = match decide_cleanup_route(&claim) {
                    CleanupRoute::ClaimTerminal(_) => {
                        match self.claim_terminal(TerminalRequest::Cleanup) {
                            Some(true) => CleanupPc::Winner(pass, TerminalPc::WaitControlRundown),
                            Some(false) => CleanupPc::Joining(pass),
                            None => CleanupPc::Continue(pass, CleanupRouteResult::Refused),
                        }
                    }
                    CleanupRoute::JoinTerminal(_) => CleanupPc::Joining(pass),
                    CleanupRoute::CompletedRecord { .. } => {
                        // `take_completed_record` and
                        // `acknowledge_completed_control`, same hold.
                        if self.lifetime == ControlContextLifetimeKind::Completed {
                            self.lifetime = ControlContextLifetimeKind::Close;
                            CleanupPc::Continue(pass, CleanupRouteResult::CompletedAcknowledged)
                        } else {
                            CleanupPc::Continue(pass, CleanupRouteResult::Refused)
                        }
                    }
                    CleanupRoute::Blocked(_) => {
                        CleanupPc::Continue(pass, CleanupRouteResult::Blocked)
                    }
                    CleanupRoute::OpaqueRetained(_) => {
                        CleanupPc::Continue(pass, CleanupRouteResult::OpaqueRetained)
                    }
                    CleanupRoute::AlreadyClosed => {
                        CleanupPc::Continue(pass, CleanupRouteResult::AlreadyClosed)
                    }
                    CleanupRoute::Empty => CleanupPc::Continue(pass, CleanupRouteResult::Empty),
                    CleanupRoute::Setup => CleanupPc::Continue(pass, CleanupRouteResult::Setup),
                };
            }
            CleanupPc::Winner(pass, terminal) => {
                self.cleanup = match self.run_terminal_step(terminal) {
                    Some(next) => CleanupPc::Winner(pass, next),
                    None => CleanupPc::Continue(
                        pass,
                        CleanupRouteResult::Terminal(TerminalOutcomeKind::Completed),
                    ),
                };
            }
            CleanupPc::Joining(pass) => {
                self.cleanup = CleanupPc::Continue(
                    pass,
                    CleanupRouteResult::Terminal(TerminalOutcomeKind::Completed),
                );
            }
            CleanupPc::Continue(pass, result) => {
                match ((self.policy.continuation)(pass, result), pass) {
                    (CleanupContinuation::ReclaimOnce, CleanupPass::First) => {
                        self.cleanup = CleanupPc::Route(CleanupPass::Reclaim);
                    }
                    (CleanupContinuation::ReclaimOnce, CleanupPass::Reclaim) => {
                        self.violations.unbounded_reclaim = true;
                        self.finish_cleanup();
                    }
                    (CleanupContinuation::Proceed | CleanupContinuation::Refuse, _) => {
                        self.finish_cleanup();
                    }
                }
            }
            CleanupPc::Done => unreachable!("a finished actor is never enabled"),
        }
    }

    /// `wait_and_release_requestor`, then the IRP's completion.
    fn finish_cleanup(&mut self) {
        self.cleanup_holds_the_rundown = false;
        self.rundown_run_down = true;
        self.cleanup = CleanupPc::Done;
    }

    fn step_close(&mut self) {
        let pc = self.close;
        match pc {
            ClosePc::NotArrived => {
                // `take_close_ownership` empties the slot before it classifies.
                self.touch();
                let previous = core::mem::replace(
                    &mut self.lifetime,
                    ControlContextLifetimeKind::BlockedCellOwned,
                );
                if self.policy.close_takes_the_registry_lock {
                    self.decide_close(previous);
                } else {
                    // Unlocked, the restore is a second write another hold can
                    // precede.
                    self.close = ClosePc::Restore(previous);
                }
            }
            ClosePc::Restore(previous) => self.decide_close(previous),
            ClosePc::Free => {
                // `ExFreePoolWithTag`, outside any lock.
                if self.close_holds_a_right {
                    self.frees = self.frees.saturating_add(1);
                }
                self.close = ClosePc::Done;
            }
            ClosePc::Done => unreachable!("a finished actor is never enabled"),
        }
    }

    fn decide_close(&mut self, previous: ControlContextLifetimeKind) {
        if (self.policy.close_decision)(previous).may_free() {
            if previous != ControlContextLifetimeKind::Close {
                self.violations.freed_unacknowledged = true;
            }
            self.close_holds_a_right = true;
        } else {
            if matches!(
                self.lifetime,
                ControlContextLifetimeKind::Completed | ControlContextLifetimeKind::Close
            ) {
                // The restore overwrites a record stored since the slot emptied.
                self.violations.record_lost = true;
            }
            self.lifetime = previous;
        }
        self.close = ClosePc::Free;
    }
}

fn replay(policy: Policy, request: TerminalRequest, schedule: &[Actor]) -> World {
    let mut world = World::start(policy, request);
    for actor in schedule {
        world.step(*actor);
    }
    world
}

/// Every state reachable under `policy`, each visited once.
///
/// The affine core objects cannot be cloned, so a state is rebuilt by replaying
/// the schedule that first reached it. Violations are absorbed BEFORE the
/// visited check, so a state reached a second time by a violating schedule
/// still reports.
fn explore(policy: Policy, request: TerminalRequest) -> Report {
    let mut report = Report::default();
    let mut seen: Vec<Signature> = Vec::new();
    let mut pending: Vec<Vec<Actor>> = vec![Vec::new()];
    while let Some(schedule) = pending.pop() {
        let world = replay(policy, request, &schedule);
        report.absorb(world.violations);
        let signature = world.signature();
        if seen.contains(&signature) {
            continue;
        }
        seen.push(signature);
        let enabled: Vec<Actor> = ACTORS
            .into_iter()
            .filter(|actor| world.enabled(*actor))
            .collect();
        if enabled.is_empty() {
            if !world.all_done() {
                report.deadlock = true;
            } else {
                match world.cleanup_gave_up {
                    None if world.frees == 0 => report.stranded = true,
                    None => report.retried_then_freed |= world.expansion_attempts > 0,
                    Some(gave_up) => {
                        report.exhaustion_walked |= gave_up.fault
                            == CleanupExpandFault::ShortOfMemory
                            && gave_up.attempts == WALK_EXPANSION_ATTEMPTS;
                        report.impossible_refusal_walked |=
                            gave_up.fault == CleanupExpandFault::Refused;
                        if world.frees == 0 {
                            report.stranded_after_giving_up = true;
                            report.stranded_before_the_budget |= gave_up.fault
                                == CleanupExpandFault::ShortOfMemory
                                && gave_up.attempts < WALK_EXPANSION_ATTEMPTS;
                        }
                    }
                }
            }
        }
        for actor in enabled {
            let mut next = schedule.clone();
            next.push(actor);
            pending.push(next);
        }
    }
    report.states = seen.len();
    report
}

/// The approved design, as round 18 wires it, holds in every interleaving.
#[test]
fn design_close_choreography_holds_in_every_interleaving() {
    for request in SOURCES {
        let report = explore(DESIGN, request);
        assert!(report.states > 0, "{request:?}: the walk explored nothing");
        assert!(
            !report.use_after_free,
            "{request:?}: context touched after its free: {report:?}"
        );
        assert!(
            !report.freed_unacknowledged,
            "{request:?}: CLOSE freed an unacknowledged record: {report:?}"
        );
        assert!(
            !report.record_lost,
            "{request:?}: CLOSE's restore overwrote a stored record: {report:?}"
        );
        assert!(
            !report.finalizer_preflight_refused,
            "{request:?}: the finalizer saw CLOSE's emptied slot: {report:?}"
        );
        assert!(
            !report.precommit_consumed_a_completion,
            "{request:?}: the dispatch's precommit look consumed a completion: {report:?}"
        );
        assert!(
            !report.unbounded_reclaim,
            "{request:?}: CLEANUP asked for a third pass: {report:?}"
        );
        assert!(
            !report.deadlock,
            "{request:?}: an interleaving stops with work left: {report:?}"
        );
        assert!(
            !report.stranded,
            "{request:?}: a completed context was never freed: {report:?}"
        );
        assert!(
            !report.stranded_before_the_budget,
            "{request:?}: a CLEANUP gave up a memory refusal before its budget was spent: {report:?}"
        );
        assert!(
            report.retried_then_freed,
            "{request:?}: no run recovered from a refused expansion: {report:?}"
        );
        // The disclosed leak. Round 20 asserted it unreachable, and the
        // dispatch hung the closing thread for ever to make that true (round-20
        // native review, N1). The design gives up instead, so the leak is
        // reachable, but only by giving up, and both ways of giving up are
        // walked.
        assert!(
            report.exhaustion_walked
                && report.impossible_refusal_walked
                && report.stranded_after_giving_up,
            "{request:?}: giving up an expansion was not walked to its strand: {report:?}"
        );
    }
}

/// What `f78cda8` shipped is observed failing. Without this, a green DESIGN run
/// would only say the walk passes, not that it can see anything.
#[test]
fn round_17_close_choreography_is_observed_to_use_after_free() {
    for request in SOURCES {
        let report = explore(ROUND_17, request);
        assert!(report.use_after_free, "{request:?}: {report:?}");
        assert!(report.freed_unacknowledged, "{request:?}: {report:?}");
    }
}

/// Each driver fact the design depends on is load-bearing on its own. These
/// plants are retained on purpose: reverting one repair later fails here rather
/// than passing silently.
#[test]
fn each_choreography_repair_is_load_bearing() {
    for request in SOURCES {
        let never_reclaims = Policy {
            continuation: never_reclaim,
            ..DESIGN
        };
        assert!(
            explore(never_reclaims, request).stranded,
            "{request:?}: a CLEANUP that stops at its terminal must strand the context"
        );

        let late_cleanup_returns = Policy {
            late_cleanup_takes_the_committed_route: false,
            ..DESIGN
        };
        assert!(
            explore(late_cleanup_returns, request).stranded,
            "{request:?}: a late CLEANUP that returns at once must strand the context (N17-2)"
        );

        let keeps_pointer = Policy {
            finalizer_retires_the_recorded_pointer: false,
            ..DESIGN
        };
        assert!(
            explore(keeps_pointer, request).use_after_free,
            "{request:?}: a recorded pointer that outlives the free must be dereferenced (N17-1)"
        );

        // The race needs a CLEANUP that completes while the generation is
        // still live, so the external terminal can still win and store its
        // record beside an unlocked CLOSE. Giving up an expansion is such a
        // completion and the design reaches it, so this plant needs no second
        // deviation (round-20 native review, N3).
        let unlocked_close = Policy {
            close_takes_the_registry_lock: false,
            ..DESIGN
        };
        let report = explore(unlocked_close, request);
        assert!(
            report.record_lost || report.finalizer_preflight_refused,
            "{request:?}: an unlocked CLOSE must be seen racing the finalizer: {report:?}"
        );

        let holds_rundown = Policy {
            cleanup_releases_the_rundown_before_the_route: false,
            ..DESIGN
        };
        assert!(
            explore(holds_rundown, request).deadlock,
            "{request:?}: a CLEANUP holding the dispatch rundown into its route must deadlock"
        );

        let gives_up_at_once = Policy {
            cleanup_follows_the_expansion_budget: false,
            ..DESIGN
        };
        assert!(
            explore(gives_up_at_once, request).stranded_before_the_budget,
            "{request:?}: a CLEANUP that completes after one refused expansion must strand the context (N18-1)"
        );
    }
}
