//! Pending-ENTER slots: one exclusive CSQ per ring.
//!
//! A WAIT that must park calls `park_wait_enter`, which publishes owners and
//! then the void `IoCsqInsertIrp`. The PASSIVE worker is the sole non-cancel
//! `IoCsqRemoveIrp` path. The outer DEVICE_CONTROL thunk returns
//! `STATUS_PENDING` without completing that IRP.
//!
//! This module is PRODUCTION. Task 19's cutover made it reachable and Task 25
//! left it so; `task19_r4_cutover_has_exactly_one_pending_terminal_delete_path`
//! is the live gate over that route, and it proves the route exists rather than
//! that it does not.
//!
//! This header used to read "`task13_18_r4_staging_is_production_unreachable`
//! is what proves the module unreachable until then". That gate is one of the
//! RETIRED staging gates: it FAILs by design, no profile carries it, and the
//! module it claimed to prove unreachable is on the dispatch path. Its
//! `stagedTargets` listing is retained in the manifest as the predecessor
//! contract, not as a live proof of anything about this file.
//!
//! Task 17 initialized **only** the context/CSQ/lock surface, and deliberately
//! left timer, DPC, DPC-exit event and work item *absent* rather than present
//! and uninitialized: a `MaybeUninit<KTIMER>` sitting in the context is a field
//! a callback can reach, and Task 17 had no callback with any business reaching
//! one. Task 18 adds all four **together with** the two callbacks that own them
//! and the arena that initializes them, which is the only order in which none
//! of them is ever reachable while uninitialized.
//!
//! # Why the non-Ex CSQ
//!
//! The slot is exclusive — one parked ENTER per ring — so insertion cannot fail
//! for want of room, and `IoCsqInsertIrp` returns `void`. The `Ex` form returns
//! an `NTSTATUS` that this shape would have nothing to do with, and an ignored
//! status is exactly the kind of edge the R4 rewrite exists to delete. The DDI
//! itself marks the IRP pending and routes an already-cancelled IRP to the
//! cancel callback, so there is no separate inline mark and no post-insertion
//! rollback branch either.
//!
//! This is a choice about the shape being built, not a migration away from an
//! `Ex` route that exists. `driver/fsring-core/src/lockrank.rs` quotes a
//! normative document describing dispatch calling `IoCsqInsertIrpEx`; that
//! describes the intended end state, and no code implements it.

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use fsring_abi::control::ENTER_RESULT_V1_PREFIX_SIZE;
use fsring_abi::control::EnterRequestV1;
use fsring_core::adapter::enter::{ParkedWaitInstall, PendingParkDecision, decide_pending_park};
use fsring_core::enter::{
    CqStorageBindTicket, CsqCancelCompletion, DequeuedIrp, EnterDecision, InstallAxis, IrpAxis,
    IrpObservation, PendingCallbackAction, PendingCompletionEffect, PendingCompletionPlan,
    PendingCompletionResult, PendingCompletionStep, PendingDpcPass, PendingDpcStep,
    PendingDrainStep, PendingDrainWait, PendingEnter, PendingFinalPublication,
    PendingHandoffCommit, PendingHandoffQueue, PendingIrpArbiter, PendingOwnerKind,
    PendingOwnerLedger, PendingOwnerToken, PendingReason, PendingResultSlot,
    PendingRuntimeInitCursor, PendingRuntimeReadyProof, PendingSlotParts, PendingSlotState,
    PendingTerminalRight, PendingTimerCancel, PendingWakeOutcome, PendingWakeSlot,
    PendingWorkerSchedule, PublicationFailStop, PublicationFailStopWitness, QueueWorkRight,
    RingEnterState, RoleLease, SqWaitRoleLease, TimerState, WorkerDequeueAuthority,
    begin_native_worker_pass, build_pending_slot_parts, classify_csq_cancel_completion,
    classify_worker_dequeue, commit_pending_handoff, encode_parked_empty_result,
    finish_native_worker_pass, record_and_schedule_pending, schedule_stored_wake,
    select_pending_install,
};
use fsring_core::session::{
    CqStorageBindRight, PendingControlLinkRight, PendingError, PendingInstallId, SessionRingBrand,
    SessionRingSetBrand, StrongSessionRef, reserve_pending_install,
};
use fsring_sys::c4::{
    BOOLEAN, DelayedWorkQueue, IO_CSQ, IO_CSQ_IRP_CONTEXT, IoAllocateWorkItem, IoCsqInitialize,
    IoCsqInsertIrp, IoCsqRemoveIrp, IoFreeWorkItem, IoQueueWorkItem, KDPC, KEVENT, KIRQL,
    KSPIN_LOCK, KTIMER, KeAcquireSpinLockRaiseToDpc, KeInitializeDpc, KeInitializeEvent,
    KeInitializeSpinLock, KeInitializeTimer, KeReleaseSpinLock, KeSetEvent, KeSetTimer,
    LARGE_INTEGER, NTSTATUS, NotificationEvent, PDEVICE_OBJECT, PIO_CSQ, PIO_CSQ_ACQUIRE_LOCK,
    PIO_CSQ_COMPLETE_CANCELED_IRP, PIO_CSQ_INSERT_IRP, PIO_CSQ_IRP_CONTEXT, PIO_CSQ_PEEK_NEXT_IRP,
    PIO_CSQ_RELEASE_LOCK, PIO_CSQ_REMOVE_IRP, PIO_WORKITEM, PIO_WORKITEM_ROUTINE, PIRP,
    PKDEFERRED_ROUTINE, PKDPC, PKIRQL, PKTIMER, PVOID,
};

use crate::lifecycle::NonPagedAllocationOwner;

// The generated declarations, named exactly. These are drift checks on every
// x64/ARM64/profile build, in the same form `lib.rs` uses for Task 6's and
// Task 7's DDIs: a hand-written declaration cannot satisfy them.
const _: unsafe extern "C" fn(
    PIO_CSQ,
    PIO_CSQ_INSERT_IRP,
    PIO_CSQ_REMOVE_IRP,
    PIO_CSQ_PEEK_NEXT_IRP,
    PIO_CSQ_ACQUIRE_LOCK,
    PIO_CSQ_RELEASE_LOCK,
    PIO_CSQ_COMPLETE_CANCELED_IRP,
) -> NTSTATUS = IoCsqInitialize;
const _: unsafe extern "C" fn(PIO_CSQ, PIRP, PIO_CSQ_IRP_CONTEXT) = IoCsqInsertIrp;
const _: unsafe extern "C" fn(PIO_CSQ, PIO_CSQ_IRP_CONTEXT) -> PIRP = IoCsqRemoveIrp;

/// Which of the two closed outcomes an insertion produced.
///
/// There is no third state. Either the queue holds the IRP, or the framework
/// routed an already-cancelled one to the cancel callback, which now owns it.
/// Both retain the same install and owner authority and both proceed to
/// handoff, so neither is an error and neither has a rollback branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CsqInsertOutcome {
    Inserted,
    CancelCallbackOwns,
}

/// The core runtime one pending slot drives.
///
/// Every value here is `fsring-core`'s and is minted only by
/// `build_pending_slot_parts`, which consumes the ring's one-shot bind right.
/// The slot stores them rather than reaching for them, because the rules that
/// govern them -- one Worker token, one owner per kind, a wake that is recorded
/// before it can schedule -- are core's and are already host-tested there. This
/// struct adds no rule; it is where the values live.
pub(crate) struct PendingSlotRuntime {
    state: RingEnterState,
    result_slot: PendingResultSlot,
    owners: PendingOwnerLedger,
    wake: PendingWakeSlot,
    schedule: PendingWorkerSchedule,
    /// The one stored Worker token, present exactly while the schedule says
    /// `Queued`. `WorkerScheduleState` is the sole publication and this is the
    /// slot it is coupled to; there is no second boolean.
    worker_owner: Option<PendingOwnerToken>,
    /// The DPC's owner while a finite timer is armed, always of the Dpc kind.
    /// The DPC takes it on entry and the pass releases it before minting its
    /// exit ticket.
    dpc_owner: Option<PendingOwnerToken>,
    /// Which install this runtime currently serves, or `None` between installs.
    install: Option<PendingInstallId>,
    /// Which ring this runtime was built for, copied out of the parts before
    /// they were destructured. It is a report, not an authority: the one-shot
    /// right that produced it is already consumed, so nothing can rebind it.
    brand: SessionRingBrand,
    /// The obligation `SignalPendingEnter` produced and `QueueInstalledWork`
    /// discharges.
    ///
    /// The two are separate roster entries precisely because the deposit
    /// happens under this slot's lock and the queue DDI must not, so the right
    /// has to survive between them. It lives here rather than on the walking
    /// frame because a 64-ring set would otherwise need a 64-entry array of
    /// affine rights on a kernel stack.
    queue_right: Option<QueueWorkRight>,
    /// The installer's handoff obligation, parked until the parked plan is
    /// stored. Queueing it any earlier races `store_parked_wait`, and a
    /// worker that wins that race wedges the ring at `Queued`.
    handoff_queue: Option<PendingHandoffQueue>,
    /// This ring's one authority to bind its CQ storage.
    ///
    /// Held, not spent: it is minted where the ring's one-shot
    /// `CqStorageBindRight` is consumed, and `BrandedCqStorage::bind_storage`
    /// is the only thing that consumes it in turn. The slot is where the
    /// one-per-ring authority lives, because dropping it would leave the
    /// ring's CQ permanently unbindable.
    ///
    /// NOT CLAIMED: nothing spends this ticket. An earlier revision of this
    /// comment said Task 25's cutover would bind the storage; Task 25 closed
    /// without doing so, and `BrandedCqStorage` still has no production
    /// constructor on any path -- `bind_storage`, `borrow_consumer`,
    /// `R4EnterPlan::bind_cq_drain` and `CqDrainAuthority::bind_drain` are
    /// reached only from `fsring-core`'s own tests. Production drains the CQ
    /// through `NativeSession`'s own cursor accessors instead (`cq_cursors`,
    /// `read_cqe`, `store_cq_head` in `session.rs`, reached through the
    /// `lifecycle.rs` access forwarder), so the typed one-consumer-per-ring
    /// guard those four functions implement is not on the production path. The
    /// ticket is retained rather than dropped so that binding stays possible;
    /// the `allow` records that possession, not use, is what this field is
    /// for today.
    #[allow(dead_code)]
    cq_storage: Option<CqStorageBindTicket>,
    /// The parked ENTER's SQ-wait lease, held from the install until the
    /// worker's completion plan consumes it.
    parked_role: Option<SqWaitRoleLease>,
    /// This install's link into the session's pending control ledger, likewise
    /// held until the plan unlinks it.
    control_link: Option<PendingControlLinkRight>,
    /// The session-ring SQ `RoleLease` taken by `NativeEnterPlan`. Distinct
    /// from `parked_role`: fence existing-role observes this ring, and
    /// dropping the parked plan without storing this lease leaks `sq_owner`.
    session_role: Option<RoleLease>,
    /// The ring slot that owns `session_role`. Used only under that slot's
    /// spin lock, after the pending-context lock is released.
    session_ring: *const crate::session::NativeRingSlot,
    /// Snapshot of the METHOD_BUFFERED request, for the parked result encode.
    parked_request: Option<EnterRequestV1>,
    /// Owned parked WAIT plan, retained until the worker resumes it.
    parked_plan: Option<ParkedWaitInstall>,
    /// The lease-bound arbiter that owns this slot's parked IRP. It holds the
    /// unclaimed terminal from install until a CSQ dequeue receipt mints the
    /// authentic right, which is the only thing that decides which of several
    /// coalesced wakes actually completes the request.
    arbiter: Option<PendingIrpArbiter>,
    /// Stable session reference, not the fence-waited access/control rundown.
    parked_strong: Option<StrongSessionRef>,
    /// Registry that issued `parked_strong`, for the matching release.
    parked_strong_registry: *mut crate::lifecycle::KernelSessionRegistry,
    /// Published session, for SQ cursor re-poll at completion.
    session: *const crate::session::NativeSession,
    /// Last `PollAndRecheck` observation. Readiness is never inferred from a
    /// wake reason alone.
    polled_sq_ready: bool,
}

/// Proof that a worker pass could begin on this slot at the instant it was
/// minted.
///
/// `PendingSlotRuntime::pass_admission` is the only mint, and
/// `queue_wake_still_owed` takes one BY VALUE, so no caller can queue a pass
/// for a slot that would refuse it. The two questions -- may a pass begin,
/// and should one be queued -- were separate conditions once, they drifted,
/// and the drift was a work item requeueing itself for ever.
struct PassAdmission(());

impl PendingSlotRuntime {
    /// Take ownership of one ring's freshly built parts.
    pub(crate) fn from_parts(parts: PendingSlotParts) -> Self {
        let brand = parts.ring_brand();
        let PendingSlotParts {
            state,
            result_slot,
            owners,
            wake,
            schedule,
            cq_storage,
        } = parts;
        Self {
            state,
            result_slot,
            owners,
            wake,
            schedule,
            worker_owner: None,
            dpc_owner: None,
            install: None,
            brand,
            cq_storage: Some(cq_storage),
            queue_right: None,
            handoff_queue: None,
            parked_role: None,
            control_link: None,
            session_role: None,
            session_ring: core::ptr::null(),
            parked_request: None,
            parked_plan: None,
            arbiter: None,
            parked_strong: None,
            parked_strong_registry: core::ptr::null_mut(),
            session: core::ptr::null(),
            polled_sq_ready: false,
        }
    }

    /// Which install this runtime serves right now.
    ///
    /// Named `serving_install`, not `install`: the graph auditor models an edge
    /// as a bare-name mention and merges a method with a field of the same
    /// name, so a method called `install` on the struct that HAS an `install`
    /// field makes every reader of the field look like a caller of the method.
    pub(crate) const fn serving_install(&self) -> Option<PendingInstallId> {
        self.install
    }

    /// Which ring this runtime was built for.
    ///
    /// Readiness compares it against the sealed set brand; nothing can rebind
    /// it, because the one-shot right that produced it is already consumed.
    pub(crate) const fn ring_brand(&self) -> SessionRingBrand {
        self.brand
    }

    /// Coalesce one wake under the caller's slot lock and park any obligation.
    ///
    /// A slot serving no install has nothing to wake and answers `true`: the
    /// checkpoint's deposit is over every context, and a ring nobody parked on
    /// is not a refusal.
    ///
    /// Neither is `PendingError::Closing`, and separating the two is what makes
    /// the `false` worth reporting. `record_and_schedule_pending` returns
    /// `Closing` for a schedule already in `Completing` and for a ledger
    /// already closing -- an install whose terminal is being delivered right
    /// now, which needs no further wake and will not be helped by one. Treating
    /// that as a refusal made refusals routine, and a routine refusal is one
    /// nobody can act on. What remains -- `WrongInstall`, `WrongRing`,
    /// `DuplicateOwner`, `OwnerOverflow` -- means the wake slot, the schedule
    /// and the owner ledger disagree about who owns this ring, which no later
    /// wake repairs.
    fn deposit_locked_wake(&mut self, reason: PendingReason) -> bool {
        let Some(install) = self.install else {
            return true;
        };
        if self.queue_right.is_some() {
            // This slot's one obligation is already parked and `QueueInstalledWork`
            // has not discharged it yet. A second wake still coalesces into the
            // slot below, but it can never owe a second queue call.
            return Self::wake_deposit_accepted(record_and_schedule_pending(
                install,
                reason,
                &mut self.schedule,
                &mut self.wake,
                &mut self.owners,
                &mut self.worker_owner,
            ));
        }
        match record_and_schedule_pending(
            install,
            reason,
            &mut self.schedule,
            &mut self.wake,
            &mut self.owners,
            &mut self.worker_owner,
        ) {
            Ok(PendingWakeOutcome::Queued(right)) => {
                self.queue_right = Some(right);
                true
            }
            Ok(PendingWakeOutcome::Stored | PendingWakeOutcome::Rescheduled) => true,
            other => Self::wake_deposit_accepted(other),
        }
    }

    /// Whether one `record_and_schedule_pending` answer leaves this ring in a
    /// state a sweep may call clean.
    ///
    /// The whole classification lives here rather than at the two sweeps, so
    /// they cannot drift apart about which refusals mean something.
    fn wake_deposit_accepted(outcome: Result<PendingWakeOutcome, PendingError>) -> bool {
        match outcome {
            Ok(_) => true,
            // The terminal for this install is already being delivered. There
            // is nothing this wake could add and nothing a caller could do.
            Err(PendingError::Closing) => true,
            Err(_) => false,
        }
    }

    /// Queue the pass a stored wake is still owed, at every instant where one
    /// could newly become owed.
    ///
    /// Nothing in this driver re-reads a stored wake, so a reason left in the
    /// slot with the schedule `Idle` is a request nobody will ever serve: the
    /// finite WAIT stops timing out, the cancelled IRP is never completed.
    /// Two instants can leave that state, and both ask here.
    ///
    /// The store: a wake landing between `commit_pending_handoff` and the plan
    /// store queues a pass that finds no plan.
    ///
    /// The abandon: that pass refuses in `begin_pass` BEFORE it touches the
    /// schedule, so the schedule still reads `Queued` while the store runs --
    /// the store's own ask answers `Ok(None)` -- and only `abandon_queued_pass`
    /// afterwards returns it to `Idle`. Asking only at the store would leave
    /// exactly that interleaving wedged.
    fn queue_wake_still_owed(&mut self, admission: PassAdmission) -> Option<QueueWorkRight> {
        // Taken by value so this cannot be called without one. A queue call
        // for a slot no pass could begin on is not a slower repair, it is a
        // worker thread spinning until the machine is rebooted.
        let PassAdmission(()) = admission;
        let install = self.install?;
        if self.queue_right.is_some() || self.handoff_queue.is_some() {
            // An obligation is already parked for this slot. A second queue
            // call is what the one-token rule exists to forbid.
            return None;
        }
        // A refusal is a slot that already owes or is running a pass; both
        // re-read the slot themselves, so there is nothing owed here.
        schedule_stored_wake(
            install,
            &mut self.schedule,
            &self.wake,
            &mut self.owners,
            &mut self.worker_owner,
        )
        .unwrap_or_default()
    }

    /// Take the SQ-wait role *and* the unclaimed terminal that goes with it.
    ///
    /// The aggregate is the only source of a `PendingEnter`: minting one beside
    /// the lease would let this slot arbitrate a terminal the ring never issued.
    fn acquire_park_role(
        &mut self,
    ) -> Result<(SqWaitRoleLease, PendingEnter), fsring_core::session::RoleError> {
        let acquired = self.state.acquire_sq_wait_aggregate()?;
        let (lease, _tracker, terminal) = acquired.into_plan_parts();
        Ok((lease, terminal))
    }

    fn release_park_role(&mut self, lease: SqWaitRoleLease) {
        let _ = self.state.release_sq_wait(lease);
    }

    /// Mint the one dequeue receipt this completion is authorised by.
    ///
    /// `csq_return` is the address of the IRP the slot's AXIS says was
    /// released to this driver, decided by `classify_worker_dequeue` from one
    /// locked observation -- not a bare read of the slot pointer, which is
    /// still set while the cancel routine owns the request. A null or
    /// mismatched value mints nothing, which is what stops a worker completing
    /// an IRP this install never parked.
    fn mint_worker_receipt(
        &mut self,
        csq_return: usize,
        reason: PendingReason,
    ) -> Option<DequeuedIrp> {
        let install = self.install?;
        let arbiter = self.arbiter.as_mut()?;
        arbiter.dequeue(install, csq_return, reason).ok()
    }

    /// Take everything one worker pass needs, or nothing at all.
    ///
    /// All five are taken together because `PendingCompletionPlan::begin` needs
    /// all five: taking four and finding the fifth absent would leave a slot
    /// that has lost its lease with no plan to release it.
    fn take_completion_authorities(
        &mut self,
    ) -> Option<(
        PendingInstallId,
        SqWaitRoleLease,
        PendingControlLinkRight,
        PendingOwnerToken,
    )> {
        let install = self.install?;
        if self.parked_role.is_none() || self.control_link.is_none() || self.worker_owner.is_none()
        {
            return None;
        }
        let (Some(role), Some(link), Some(worker)) = (
            self.parked_role.take(),
            self.control_link.take(),
            self.worker_owner.take(),
        ) else {
            unreachable!("all three were just observed present")
        };
        Some((install, role, link, worker))
    }

    /// Begin one worker pass and select the reason it is completing.
    ///
    /// This is what moves the schedule out of `Queued`. Without it the state
    /// machine never advanced, so a pass that completed nothing could never
    /// queue another and a request whose wake landed before its plan was
    /// published stayed stranded.
    /// Whether a worker pass could begin on this slot right now.
    ///
    /// ONE predicate, consulted by everything that either begins a pass or
    /// queues one. It exists as a value rather than as a repeated condition
    /// because the two questions drifted apart once and the cost was a
    /// livelock: `queue_wake_still_owed` queued a pass for a slot whose
    /// `parked_plan` was `None`, `begin_pass` refused it for exactly that
    /// reason without emptying the wake slot, the abandon queued another, and
    /// `fail_unstored_parked_wait` leaves `parked_plan` `None` for the life of
    /// the slot -- a `DelayedWorkQueue` item requeueing itself for ever on a
    /// system worker thread.
    ///
    /// `PassAdmission` is what makes that unrepeatable: a caller cannot queue
    /// a pass without holding one, and the only way to hold one is to have
    /// asked here.
    fn pass_admission(&self) -> Option<PassAdmission> {
        // The plan is published by `store_parked_wait` after `IoCsqInsertIrp`
        // returns, and a cancel or timer wake can land inside that window; the
        // reasons must survive for the pass that finds the plan present.
        if self.parked_plan.is_none() || self.arbiter.is_none() {
            return None;
        }
        if self.parked_role.is_none() || self.control_link.is_none() {
            return None;
        }
        Some(PassAdmission(()))
    }

    fn begin_pass(&mut self) -> Option<PendingReason> {
        let install = self.install?;
        // Refuse before `begin_native_worker_pass` empties the wake slot.
        let PassAdmission(()) = self.pass_admission()?;
        begin_native_worker_pass(
            install,
            &mut self.schedule,
            &mut self.wake,
            &mut self.worker_owner,
        )
        .ok()
    }

    /// Close a pass that completed nothing, yielding the obligation to queue
    /// the next one when the schedule published a `Queued` for it.
    ///
    /// A refusal is NOT "no `Queued` was published". That claim stood here and
    /// was wrong about the one refusal that actually occurs: a pass queued by
    /// the installer's handoff that could not begin leaves the schedule at
    /// `Queued`, which `finish_worker_pass` has no arm for, and its queue call
    /// has already been spent by the work item running this very code. That
    /// refusal is handled by `abandon_queued_pass` below rather than swallowed.
    ///
    /// What a refusal does mean is that no NEW `Queued` was published, so no
    /// new queue call is owed, which is why `None` is the right answer to this
    /// caller either way.
    fn finish_pass(&mut self) -> Option<QueueWorkRight> {
        match finish_native_worker_pass(
            &mut self.schedule,
            &mut self.owners,
            &mut self.worker_owner,
        ) {
            Ok(right) => right,
            Err(_) => self.abandon_queued_pass(),
        }
    }

    /// Put back a `Queued` a pass could not begin from, and release the Worker
    /// owner the wake that queued it acquired.
    ///
    /// This is the wedge half that `finish_worker_pass` cannot express. A pass
    /// queued by the installer's handoff can run before `store_parked_wait`
    /// publishes the plan; `begin_pass` then refuses, the schedule stays
    /// `Queued`, and `Queued` refuses to queue again -- so every later wake is
    /// stored with nothing scheduled to take it while the IRP this pass already
    /// dequeued from the CSQ sits uncancellable. Returning to `Idle` lets the
    /// next wake queue another pass over the reasons still in the slot.
    ///
    /// A refusal from either half is left alone: `Completing` and `Running`
    /// belong to a pass that really did begin, and this is not that.
    fn abandon_queued_pass(&mut self) -> Option<QueueWorkRight> {
        let token = self.worker_owner.take()?;
        match self.schedule.abandon_queued_pass(token) {
            Ok(token) => {
                let _ = self.owners.release_owner(token);
                // `Idle` again, with the reasons this pass could not act on
                // still in the slot. This is the instant a pass newly becomes
                // owed, and nothing else will notice it -- but only if a pass
                // could actually begin, which is why the admission is asked
                // for here and not assumed.
                let admission = self.pass_admission()?;
                self.queue_wake_still_owed(admission)
            }
            Err((_, token)) => {
                self.worker_owner = Some(token);
                None
            }
        }
    }

    /// Undo `begin_completion` for a pass that turned out to have nothing to
    /// complete. Without it the schedule stays `Completing`, which refuses to
    /// finish and refuses to queue: the slot would never run again.
    ///
    /// The return to `Running` is also what makes the Cancel its caller
    /// deposits acceptable: `record_and_schedule_pending` refuses every wake
    /// while the schedule reads `Completing`.
    fn abandon_completion(&mut self) {
        let Some(token) = self.worker_owner.take() else {
            return;
        };
        match self.schedule.abandon_worker_completion(token) {
            Ok(token) => self.worker_owner = Some(token),
            Err((_, token)) => self.worker_owner = Some(token),
        }
    }

    /// Move this pass into `Completing` before its authorities are consumed.
    ///
    /// `begin_worker_completion` is the transition that forbids completing a
    /// `RunningReschedule`, which still owes a pass over reasons already
    /// recorded. The token goes straight back so `take_completion_authorities`
    /// can hand it to the completion plan.
    fn begin_completion(&mut self) -> bool {
        let Some(token) = self.worker_owner.take() else {
            return false;
        };
        match self.schedule.begin_worker_completion(token) {
            Ok(token) => {
                self.worker_owner = Some(token);
                true
            }
            Err((_, token)) => {
                self.worker_owner = Some(token);
                false
            }
        }
    }

    /// Release everything this install bound, so the ring can serve another.
    ///
    /// The closing half of `begin_install` / `bind_install` / `occupy`. The
    /// final publication has already released the last owner and cleared the
    /// result slot, so both unbinds are due here and refuse if anything is
    /// still outstanding.
    ///
    /// Reports whether the release happened, and clears the per-install values
    /// as well as the two ledgers. Both were missing: the closing halves were
    /// discarded, and a `parked_plan` left behind made `store_session_wait`
    /// refuse every later park -- the ring then served exactly one WAIT for the
    /// life of the session, and a completion pass could reach `begin_pass` on
    /// the strength of a plan the previous install had abandoned.
    ///
    /// It refuses BEFORE it takes anything, and that is the whole shape of the
    /// answer. A refusal leaves this runtime exactly as it was found, so the
    /// caller can decline to republish the slot instead of being handed a half
    /// released one; the slot then stays `Quiescing` and still names its
    /// install, which is what `observe_pending_for_unload` reports as Active
    /// and what makes the drain refuse into blocked-safe unload. Bugchecking
    /// here instead would be an assert on a state this function is the only
    /// thing able to describe.
    fn release_install(&mut self) -> bool {
        let Some(install) = self.install else {
            return true;
        };
        // Nothing may still be bound. `commit_final_publication` proved the
        // owner count was one, `take_arbitrated_completion` took the plan, and
        // `ReleaseSqWaitRole` released the session role -- so anything still
        // here means this slot's ledgers disagree with the publication that
        // just succeeded, and the next install would inherit the disagreement
        // as a park it can never store.
        if self.parked_plan.is_some() || self.session_role.is_some() || self.dpc_owner.is_some() {
            return false;
        }
        if self.schedule.end_install(install).is_err() {
            return false;
        }
        if self.owners.unbind_install(install).is_err() {
            return false;
        }
        self.session = core::ptr::null();
        self.arbiter = None;
        self.parked_request = None;
        self.session_ring = core::ptr::null();
        self.polled_sq_ready = false;
        self.install = None;
        true
    }

    /// Select this pass's winner and mint the right that completes it.
    ///
    /// The three steps are one call so they cannot disagree: `take_for_worker`
    /// applies the frozen `WORKER_PRIORITY` order to the coalesced wakes, the
    /// dequeue receipt is minted for exactly that reason against exactly the
    /// IRP the CSQ handed back, and `contend` turns the pair into the affine
    /// right. A worker holding this right cannot deliver the status of a wake
    /// that lost, because the losing reason never reached the terminal.
    fn take_arbitrated_completion(
        &mut self,
        csq_return: usize,
        reason: PendingReason,
    ) -> Option<(ParkedWaitInstall, PendingTerminalRight, PendingReason)> {
        // The plan comes out FIRST. It used to be taken last, behind an
        // `unreachable!` whose stated justification was a `begin_pass` check
        // performed in a *different* lock hold -- and by the time that arm
        // could be reached the receipt had been minted and the one-shot
        // terminal contended, so a plan that had gone would have stranded the
        // IRP with its terminal already spent and no way to deliver it.
        //
        // Taking it first turns an absence into an ordinary refusal before
        // anything is spent, and a refusal below puts it back exactly as found.
        let plan = self.parked_plan.take()?;
        match self.arbitrate_completion(csq_return, reason) {
            Some(right) => Some((plan, right, reason)),
            None => {
                self.parked_plan = Some(plan);
                None
            }
        }
    }

    /// Mint this pass's dequeue receipt and turn it into the affine right.
    ///
    /// Split out so `take_arbitrated_completion` can hold the plan across it
    /// without holding a borrow of `self` at the same time. `begin_pass`
    /// already refused unless the arbiter is present, and it is what selected
    /// `reason` out of the coalesced wakes.
    fn arbitrate_completion(
        &mut self,
        csq_return: usize,
        reason: PendingReason,
    ) -> Option<PendingTerminalRight> {
        let receipt = self.mint_worker_receipt(csq_return, reason)?;
        let arbiter = self.arbiter.as_mut()?;
        let (right, _irp) = arbiter.contend(receipt).ok()?;
        Some(right)
    }

    /// Store the owned parked WAIT plan, or hand it back unconsumed.
    ///
    /// The refusal condition should be unreachable in the ordinary sequence:
    /// `park_wait_enter`'s `InsertCsq` effect already committed
    /// `slot_state = Installing` before this call is ever reached, so
    /// `decide_pending_park` refuses any second concurrent park on this same
    /// ring before it could reach a second `store_session_wait`. It is kept
    /// as a refusal, not an `unreachable!`, because a kernel invariant this
    /// call cannot itself reverify is not a fact this call may bet a bugcheck
    /// on -- and a caller that refuses instead still owes `owned` back whole
    /// (see [`store_parked_session_wait_inner`]).
    #[allow(clippy::result_large_err)]
    fn store_session_wait(
        &mut self,
        owned: ParkedWaitInstall,
        ring: *const crate::session::NativeRingSlot,
        request: EnterRequestV1,
        session: *const crate::session::NativeSession,
    ) -> Result<(), ParkedWaitInstall> {
        if self.parked_plan.is_some() || self.session_role.is_some() {
            return Err(owned);
        }
        self.parked_plan = Some(owned);
        self.session_ring = ring;
        self.parked_request = Some(request);
        self.session = session;
        Ok(())
    }

    fn take_session_wait(
        &mut self,
    ) -> (
        Option<RoleLease>,
        *const crate::session::NativeRingSlot,
        Option<EnterRequestV1>,
        *const crate::session::NativeSession,
    ) {
        let lease = self
            .parked_plan
            .as_mut()
            .and_then(ParkedWaitInstall::take_role)
            .or_else(|| self.session_role.take());
        (
            lease,
            self.session_ring,
            self.parked_request.take(),
            self.session,
        )
    }
}

/// One ring's exclusive pending-ENTER slot.
///
/// `#[repr(C)]` because the CSQ callbacks recover it from the address of its
/// `csq` field, which is only sound with a fixed layout.
#[repr(C)]
pub(crate) struct PendingEnterContext {
    /// Must stay first: the callbacks are handed `PIO_CSQ` and recover the
    /// context by casting that pointer back. Keeping the offset zero makes the
    /// recovery a cast rather than arithmetic nobody can check.
    csq: IO_CSQ,
    csq_irp_context: IO_CSQ_IRP_CONTEXT,
    lock: KSPIN_LOCK,
    slot_state: PendingSlotState,
    install_axis: Option<InstallAxis>,
    irp_axis: Option<IrpAxis>,
    /// The parked IRP, or null. Written only under `lock`.
    irp: PIRP,
    /// The dispatch-owned control context this install belongs to.
    ///
    /// MEASURED, round 16: this field has no reader anywhere in the crate, and
    /// its only two writes -- in `initialize_staged_pending_slot` and in the
    /// slot reset -- both store null. It is dead storage.
    ///
    /// The doc used to read "Task 19 gives it a production writer; here it is
    /// always null." Task 19 closed without adding one. What replaced the
    /// per-install pointer is the registry's own recorded context, reached
    /// through `ControlFileCell::recorded_control_context` in `fence.rs`, so
    /// nothing needs this field and nothing asks for it. It is
    /// recorded rather than deleted here because removing it moves
    /// `PendingEnterContext`'s layout and the censuses frozen over this file;
    /// that is a decision of its own, not a side effect of a documentation
    /// sweep.
    control_context: *mut c_void,

    // -- Task 18 --------------------------------------------------------
    //
    // These four were deliberately ABSENT from Task 17's shape rather than
    // present-and-uninitialized: a `MaybeUninit<KTIMER>` in the context is a
    // field a callback can reach, and Task 17 had no callback with any
    // business reaching one. Task 18 adds them together WITH the callbacks
    // that own them and the initialization that makes them live, which is the
    // only order in which none of them is ever reachable while uninitialized.
    /// Armed only for a finite WAIT. Initialized before the CSQ is published.
    timer: KTIMER,
    /// The one DPC `timer` fires, naming [`fsring_pending_enter_timer_dpc`].
    dpc: KDPC,
    /// Nonsignaled `NotificationEvent`, set by the DPC as its final action.
    ///
    /// It is proof that the DPC owner slot and its occupied-kind bit are
    /// already clear, because [`fsring_core::enter::PendingDpcExitTicket`] --
    /// the only thing that authorizes the `KeSetEvent` -- does not exist until
    /// the pass has released the owner and published `Quiesced`.
    dpc_exited: KEVENT,
    /// This slot's out-of-line result backing, or null before the runtime is
    /// built and after rollback.
    ///
    /// A pointer into the arena rather than an inline array: the context has no
    /// byte-array field at all, which is what
    /// `pending_context_contains_no_inline_result_storage` asserts from the core
    /// side and `PENDING_SHAPE_BODIES` freezes from the auditor's.
    result_view: *mut u8,
    /// The one provider-associated work item this slot queues its PASSIVE
    /// worker with, or null before allocation and after rollback.
    ///
    /// Null-is-absent rather than the plan's `Option<NonNull<IO_WORKITEM>>`:
    /// `wdk-sys` re-exports the pointer alias but not the opaque body type, so
    /// a `NonNull` of it is not nameable. Ownership is unaffected -- the
    /// prefix below is the sole owner and its reverse rollback the sole free.
    work_item: PIO_WORKITEM,
    /// The one refused final publication this slot is parked on.
    ///
    /// The invariant is exact and goes both ways:
    /// `slot_state == PublicationFailStop { epoch }` **iff** this is
    /// `Some(packet)` for that same epoch. Every other slot state requires it to
    /// be `None`. That is why the store happens *before* the state is published
    /// and the state is cleared *never*: a reader that saw the parked state with
    /// an empty slot would have no way to tell a fail-stop from a bug.
    ///
    /// It is the sole authority location. There is no decomposition, reset or
    /// retry API -- it can emit a witness, and nothing else.
    publication_fail_stop: Option<PublicationFailStop>,
    /// This ring's core runtime, once SETUP has built it.
    ///
    /// `None` on a slot that has been initialized but not yet given its parts.
    /// It is an `Option` rather than a `MaybeUninit` for the same reason the
    /// timer was absent from Task 17's shape: an uninitialized value a callback
    /// can reach is a value a callback will eventually read, and `None` is a
    /// state every reader has to handle.
    runtime: Option<PendingSlotRuntime>,
    /// Where this slot's timer is in its life. The whole quiescence rule.
    timer_state: TimerState,
    /// Whether any DPC has ever entered on this slot. A latch, never cleared.
    ///
    /// `timer_state` alone cannot answer this at teardown. `dpc_exiting`
    /// publishes `Quiesced` INSIDE the slot lock and the DPC's last act --
    /// `KeSetEvent(dpc_exited)` -- happens after it releases, so a frame that
    /// observes `Quiesced` may still be racing a store into this arena. This
    /// says whether there is such a store to wait for; without it, waiting
    /// unconditionally would block forever on a slot no DPC ever ran for.
    ///
    /// It is a LATCH and not a per-generation flag, which is the whole of the
    /// N3 repair's own repair. Clearing it when a new generation armed raced
    /// exactly the store it exists to guard: an install that armed between a
    /// DPC's release and that DPC's `KeSetEvent` erased an obligation still
    /// owed, and the teardown wait then returned at once. Latched, the reading
    /// is weaker and sound -- "a DPC has run, so the exit event is the proof of
    /// its last store" -- and because `dpc_exited` is a NotificationEvent, a
    /// set left standing by the last DPC satisfies the wait immediately. The
    /// only thing this must still distinguish is a slot whose timer was never
    /// armed at all, and a latch distinguishes exactly that.
    dpc_entered: bool,
    /// The SQ publish generation this install snapshotted when it parked.
    observed_generation: u64,
}

// The result backing is out of line by construction: this context has no byte
// array field at all, which is what
// `pending_context_contains_no_inline_result_storage` asserts from the core
// side. The bound below is the plan's, and it is checked rather than asserted
// in prose -- a field added later that pushes past it stops the build.
const _: () = {
    // Raised from 1024 when the slot took ownership of its core runtime, again
    // when it took the parked fail-stop packet -- which holds a whole
    // `PendingCompletionPlan`, and is the single largest field here -- and again
    // at the cutover, when the runtime took the parked SQ lease, the control
    // link, the queue obligation and the out-of-line result view. Raised from
    // 3072 when the runtime stopped dropping the parked plan and started owning
    // it (`Option<ParkedWaitInstall>`, 272 bytes) together with the arbiter that
    // holds its unclaimed terminal (`Option<PendingIrpArbiter>`, 328). Both are
    // what make a parked WAIT completable by its own arbitrated winner rather
    // than by a native re-derivation. The shape measures **3448 bytes** on x64
    // today (measured with a `[u8; 0]` mismatch, not guessed); the bound leaves
    // deliberate headroom and 4096 * 64 is 256 KiB of nonpaged backing for a
    // whole ring set.
    //
    // The bound is a bound, not the property: what actually forbids inline
    // result storage is `PENDING_SHAPE_BODIES` in `audit_c4_lifetime.py`, which
    // freezes the exact field grammar and would refuse an added `[u8; N]` at
    // any size. This number exists only so a slot cannot quietly grow past what
    // 64 of them fit in.
    assert!(core::mem::size_of::<PendingEnterContext>() <= 4096);
    // The recovery cast in every callback depends on this being zero.
    assert!(core::mem::offset_of!(PendingEnterContext, csq) == 0);
};

impl PendingEnterContext {
    /// Recover the containing context from the pointer a callback was handed.
    ///
    /// # Safety
    /// `csq` must have the *provenance* of a live, initialized
    /// `PendingEnterContext`'s `csq` field -- not merely the right address.
    /// The zero-offset assertion above makes the cast correct for layout; it
    /// says nothing about which allocation the pointer came from, and only the
    /// caller can know that. In practice the framework hands back exactly the
    /// pointer this module passed to `IoCsqInitialize`, which is the whole of
    /// why the contract is satisfiable.
    ///
    /// A null `csq` is refused rather than cast: the framework never passes
    /// one, so reaching that arm means the queue is not ours.
    unsafe fn from_csq(csq: PIO_CSQ) -> NonNull<Self> {
        assert!(!csq.is_null(), "CSQ callback invoked with a null queue");
        // SAFETY: the caller's provenance contract, plus the zero-offset
        // assertion above for the layout half.
        unsafe { NonNull::new_unchecked(csq.cast::<Self>()) }
    }
}

// ---------------------------------------------------------------------------
// The six callbacks
// ---------------------------------------------------------------------------
//
// The lock discipline is the whole content of this block, so it is stated once
// here rather than repeated six times:
//
//   * `CsqAcquireLock` is the ONLY one that acquires.
//   * `CsqReleaseLock` is the ONLY one that releases, and it releases with the
//     IRQL the framework hands back -- which is the value `CsqAcquireLock`
//     returned through its out parameter. The context deliberately does NOT
//     keep a copy: a stored IRQL would be a second source of truth that no
//     code reads, and a release judged against it would be judged against
//     whichever acquire wrote last rather than against its own partner.
//   * insert / remove / peek run under the hold the framework already took
//     through those two. Reacquiring there is a deadlock at DISPATCH_LEVEL,
//     not a style preference.
//   * `CsqCompleteCanceledIrp` runs AFTER the framework released the queue
//     lock. It is the one callback that may acquire on its own, and it must
//     release before doing anything that could block.
//
// None of them waits, fences, writes output, or completes an IRP.

/// Take the slot lock and report the IRQL the framework must release with.
///
/// # Safety
/// Invoked by the CSQ framework with a `csq` this module initialized.
unsafe extern "C" fn csq_acquire_lock(csq: PIO_CSQ, irql: PKIRQL) {
    // SAFETY: the framework's contract, forwarded.
    let context = unsafe { PendingEnterContext::from_csq(csq) };
    // SAFETY: `lock` is initialized by the staged constructor before the CSQ
    // that names these callbacks is published.
    let raised =
        unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*context.as_ptr()).lock)) };
    // SAFETY: the framework supplies a valid out parameter. The raised IRQL
    // leaves through it and is not stored: the framework is what carries it to
    // the matching release.
    unsafe {
        *irql = raised;
    }
}

/// Release the slot lock with the exact IRQL its acquire saved.
///
/// # Safety
/// Invoked by the CSQ framework, paired with [`csq_acquire_lock`].
unsafe extern "C" fn csq_release_lock(csq: PIO_CSQ, irql: KIRQL) {
    // SAFETY: the framework's contract, forwarded.
    let context = unsafe { PendingEnterContext::from_csq(csq) };
    // SAFETY: paired with the acquire above; the framework returns the exact
    // IRQL that acquire reported through its out parameter.
    unsafe {
        KeReleaseSpinLock(core::ptr::addr_of_mut!((*context.as_ptr()).lock), irql);
    }
}

/// Store the IRP into the exclusive slot.
///
/// Void, and structurally infallible: the slot holds one IRP and the caller
/// reserved it before reaching here.
///
/// # Safety
/// Invoked by the CSQ framework with the slot lock already held.
unsafe extern "C" fn csq_insert_irp(csq: PIO_CSQ, irp: PIRP) {
    // SAFETY: the framework's contract, forwarded. The lock is already held by
    // `csq_acquire_lock`; this must not reacquire it.
    let context = unsafe { PendingEnterContext::from_csq(csq) };
    // The slot is exclusive, so an occupied one here means two ENTERs were
    // installed against one ring -- and overwriting would drop an IRP that is
    // already marked pending, which nothing would ever complete. There is no
    // return value to refuse with and no recovery, so this is a bugcheck for
    // the same reason a dropped `QueueWorkRight` is.
    //
    // SAFETY: read and written under the framework's hold.
    unsafe {
        assert!(
            (*context.as_ptr()).irp.is_null(),
            "CSQ insert into an occupied exclusive slot would strand a pending IRP",
        );
        assert!(
            (*context.as_ptr()).irp_axis.is_none(),
            "CSQ insert onto a live IRP axis; only a fresh install may queue",
        );
        (*context.as_ptr()).irp = irp;
        (*context.as_ptr()).irp_axis = Some(IrpAxis::Queued);
    }
}

/// Clear the exclusive slot for an IRP the framework is taking back.
///
/// # Safety
/// Invoked by the CSQ framework with the slot lock already held.
unsafe extern "C" fn csq_remove_irp(csq: PIO_CSQ, _irp: PIRP) {
    // SAFETY: the framework's contract, forwarded.
    let context = unsafe { PendingEnterContext::from_csq(csq) };
    // SAFETY: written under the framework's hold. The axis is advanced by the
    // winner that consumes the removal, not here: this callback only stops the
    // slot from naming an IRP the queue no longer holds.
    unsafe {
        (*context.as_ptr()).irp = core::ptr::null_mut();
    }
}

/// Report the one IRP this exclusive slot holds.
///
/// The peek contract is "the entry after `irp`", and an exclusive slot has no
/// entry after anything, so a non-null `irp` yields null.
///
/// # Safety
/// Invoked by the CSQ framework with the slot lock already held.
unsafe extern "C" fn csq_peek_next_irp(csq: PIO_CSQ, irp: PIRP, _context: PVOID) -> PIRP {
    if !irp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the framework's contract, forwarded.
    let context = unsafe { PendingEnterContext::from_csq(csq) };
    // SAFETY: read under the framework's hold.
    unsafe { (*context.as_ptr()).irp }
}

/// Publish that the cancel path now owns the dequeued IRP.
///
/// Runs after the framework released the queue lock, so this is the one
/// callback that takes the slot lock itself — and it releases before returning,
/// because everything a cancelled install still owes happens outside the hold.
///
/// # Safety
/// Invoked by the CSQ framework with an IRP it has already dequeued.
unsafe extern "C" fn csq_complete_canceled_irp(csq: PIO_CSQ, irp: PIRP) {
    // SAFETY: the framework's contract, forwarded.
    let context = unsafe { PendingEnterContext::from_csq(csq) };
    let raw = context.as_ptr();
    // SAFETY: the queue lock is NOT held here, so this acquire is correct and
    // the matching release below is unconditional.
    let raised = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // The slot ENDS UP NAMING the IRP. This callback is handed ownership of an
    // IRP the framework has already dequeued, and the slot is the only place
    // that pointer is kept -- leaving it null here would leave a cancelled IRP
    // that nothing holds, nothing completes, and nothing can find again.
    //
    // Publishing `Dequeued` is what changes: it says the cancel path owns the
    // request now, which is exactly what `observe_insert_outcome` reads to
    // report `CancelCallbackOwns`. Completion is the pending machinery's
    // business on the terminal path, not this callback's -- it runs at
    // DISPATCH_LEVEL and may not block. After HandoffDone the PASSIVE worker
    // is queued; during Installing the stored Cancel wake is transferred at
    // handoff.
    //
    // `csq_remove_irp` clears the slot on BOTH its callers: the worker's
    // explicit `IoCsqRemoveIrp`, which restores the non-null return itself, and
    // the framework's cancel path, which runs it immediately before this
    // callback. The comment that stood here said the clear belonged to the
    // explicit caller alone, and that reading is what made this callback assert
    // on a pointer that is null every time it is reached.
    //
    // SAFETY: read and written under the hold just taken.
    let queue_right = unsafe {
        // `csq_remove_irp` ran before this callback and cleared the slot -- the
        // framework removes before it completes -- so the normal state here is
        // an EMPTY slot, and the pointer must be restored rather than asserted.
        // `classify_csq_cancel_completion` owns that discrimination in the core,
        // where `driver-core-test` can watch it get it wrong; this file runs no
        // host test and cannot, so a decision left here is graded only by a
        // source auditor reading text.
        match classify_csq_cancel_completion(
            IrpObservation::from_raw((*raw).irp as usize),
            IrpObservation::from_raw(irp as usize),
        ) {
            CsqCancelCompletion::AdoptRemoved => (*raw).irp = irp,
            CsqCancelCompletion::AlreadyNamed | CsqCancelCompletion::NoIrp => {}
            CsqCancelCompletion::ForeignIrp => {
                // Release before panicking: a bugcheck holding a spin lock
                // hangs every other processor that touches this ring.
                KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);
                panic!("cancel completion named an IRP this slot never parked");
            }
        }
        (*raw).irp_axis = Some(IrpAxis::Dequeued);
        match (*raw).runtime.as_mut() {
            Some(runtime) => {
                let _ = runtime.deposit_locked_wake(PendingReason::Cancel);
                runtime.queue_right.take()
            }
            None => None,
        }
    };
    // SAFETY: paired with the acquire above; nothing between them can block.
    unsafe {
        KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);
    }
    if let Some(right) = queue_right {
        let work_item = unsafe { (*raw).work_item };
        if !work_item.is_null() {
            unsafe {
                IoQueueWorkItem(
                    work_item,
                    Some(fsring_pending_enter_worker),
                    DelayedWorkQueue,
                    raw.cast::<c_void>(),
                );
            }
        }
        unsafe { right.commit_after_work_queued() };
    }
}

/// Read, under the slot lock, which of the two closed outcomes an insertion
/// produced.
///
/// This is the "locked observation after the call" the insert boundary owes.
/// It is a read, not a decision: the framework has already either queued the
/// IRP or routed an already-cancelled one to the cancel callback, and both
/// leave the same install and owner authority in place. Whichever it reports,
/// the suffix proceeds to handoff — there is no third state and no branch that
/// unwinds.
///
/// # Safety
/// `context` is a live initialized slot, and the caller holds no lock and runs
/// at or below DISPATCH_LEVEL.
unsafe fn observe_insert_outcome(context: NonNull<PendingEnterContext>) -> CsqInsertOutcome {
    let raw = context.as_ptr();
    // SAFETY: the caller's contract; this acquire is paired unconditionally.
    let raised = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // The AXIS decides, not the pointer. Reading null-ness alone reported
    // `Inserted` for a slot that was never filled, because "not dequeued" and
    // "never inserted" are the same shape through that lens. The axis tells
    // them apart, and a slot with no axis at all is neither outcome -- the
    // insert boundary was never crossed, so there is nothing to observe.
    //
    // SAFETY: read under the hold just taken.
    let outcome = unsafe {
        match (*raw).irp_axis {
            Some(IrpAxis::Queued) => CsqInsertOutcome::Inserted,
            Some(IrpAxis::Dequeued) => CsqInsertOutcome::CancelCallbackOwns,
            other => {
                // Release before panicking: a bugcheck holding a spin lock
                // hangs every other processor that touches this ring.
                KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);
                panic!("insert outcome observed on a slot with axis {other:?}");
            }
        }
    };
    // SAFETY: paired with the acquire above; nothing between them can block.
    unsafe {
        KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);
    }
    outcome
}

// Bind each callback to its generated alias. A shape that drifted -- a
// returned status where the DDI returns void, a missing parameter -- fails
// here rather than against a live queue.
const _: PIO_CSQ_INSERT_IRP = Some(csq_insert_irp);
const _: PIO_CSQ_REMOVE_IRP = Some(csq_remove_irp);
const _: PIO_CSQ_PEEK_NEXT_IRP = Some(csq_peek_next_irp);
const _: PIO_CSQ_ACQUIRE_LOCK = Some(csq_acquire_lock);
const _: PIO_CSQ_RELEASE_LOCK = Some(csq_release_lock);
const _: PIO_CSQ_COMPLETE_CANCELED_IRP = Some(csq_complete_canceled_irp);

/// Initialize one ring's staged pending slot in place.
///
/// Called from `build_pending_runtime`, which is on the SETUP path, so this is
/// production code and not staged surface.
///
/// This doc used to read "Not called from any dispatch path in this checkpoint.
/// Task 19 is the commit that first reaches it, and until then the staging gate
/// is what proves it." Both halves were false: the call above exists, and
/// `task13_18_r4_staging_is_production_unreachable` is one of the RETIRED
/// staging gates that FAIL by design, so it proved nothing about anything.
///
/// # Safety
/// `slot` points at writable, nonpaged, suitably aligned storage for one
/// `PendingEnterContext` that no other thread can observe yet, and the caller
/// runs at PASSIVE_LEVEL.
pub(crate) unsafe fn initialize_staged_pending_slot(
    slot: NonNull<PendingEnterContext>,
) -> Result<(), NTSTATUS> {
    let raw = slot.as_ptr();
    // Every per-install authority starts absent. `Vacant { next_epoch: 1 }` is
    // the only state from which an epoch may be reserved, and epoch 0 is never
    // issued, so a zeroed slot cannot pass for a reserved one.
    // SAFETY: the caller's contract: exclusive, writable, correctly aligned.
    unsafe {
        (*raw).slot_state = PendingSlotState::Vacant { next_epoch: 1 };
        (*raw).install_axis = None;
        (*raw).irp_axis = None;
        (*raw).irp = core::ptr::null_mut();
        (*raw).control_context = core::ptr::null_mut();
        (*raw).csq_irp_context = core::mem::zeroed();
        KeInitializeSpinLock(core::ptr::addr_of_mut!((*raw).lock));
    }
    // Task 18's four resources, live before anything can reach them. The DPC
    // is bound to the timer here and armed only by a finite WAIT, so a slot
    // that is never waited on carries a quiesced timer and an unqueued DPC.
    //
    // SAFETY: same exclusive, writable, correctly aligned storage; all four
    // initializers are PASSIVE-callable and none of them can fail.
    unsafe {
        KeInitializeTimer(core::ptr::addr_of_mut!((*raw).timer));
        KeInitializeDpc(
            core::ptr::addr_of_mut!((*raw).dpc),
            Some(fsring_pending_enter_timer_dpc),
            raw.cast::<c_void>(),
        );
        // Nonsignaled: nothing has exited yet, and a signaled exit event on a
        // fresh slot would let the first canceller skip the wait it owes.
        KeInitializeEvent(
            core::ptr::addr_of_mut!((*raw).dpc_exited),
            NotificationEvent,
            0,
        );
        (*raw).work_item = core::ptr::null_mut();
        (*raw).result_view = core::ptr::null_mut();
        core::ptr::write(core::ptr::addr_of_mut!((*raw).publication_fail_stop), None);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).runtime), None);
        (*raw).timer_state = TimerState::Quiesced;
        (*raw).observed_generation = 0;
        (*raw).dpc_entered = false;
    }
    // The lock is live before the CSQ that names the callbacks exists, so the
    // framework can never hand a callback a lock it has not initialized.
    // SAFETY: `csq` is the zero-offset field of the storage above, and all six
    // callbacks are this module's.
    let status = unsafe {
        IoCsqInitialize(
            core::ptr::addr_of_mut!((*raw).csq),
            Some(csq_insert_irp),
            Some(csq_remove_irp),
            Some(csq_peek_next_irp),
            Some(csq_acquire_lock),
            Some(csq_release_lock),
            Some(csq_complete_canceled_irp),
        )
    };
    if status < 0 { Err(status) } else { Ok(()) }
}

// ---------------------------------------------------------------------------
// R4 Task 18: the two callbacks, and what they are allowed to do
// ---------------------------------------------------------------------------
//
// The ORDER is `fsring-core`'s -- `PENDING_DPC_OWN_EPOCH_ORDER`,
// `PENDING_DPC_STALE_EPOCH_ORDER` and `PENDING_WORKER_PASS_ORDER`, all host
// tested there. This module supplies the WDK-typed body that performs one
// effect at a time, exactly as `NativeCheckpointExecutor` does for the R3
// roster. Nothing about which effect comes next, or whether a path performs any
// at all, is decidable here.
//
// BOTH callbacks are registered, and both fire. `IoQueueWorkItem` is called
// with `Some(fsring_pending_enter_worker)` from the CSQ cancel callback
// `csq_complete_canceled_irp`, from `StagedSlotEffects::perform_pending_effect`'s
// `QueueWorker` and `FinishWorkerPass` arms, and from `queue_pending_worker`;
// the DPC is installed by `KeInitializeDpc` in `initialize_staged_pending_slot`
// and armed by `KeSetTimer` in `park_wait_enter`, inside the hold that
// published `Armed`.
//
// Round 17 wrote this paragraph to replace bare line numbers, and wrote it
// from memory: it named `arm_pending_timer_locked`, which has never existed,
// called the cancel callback "the arena initializer", and omitted the
// `FinishWorkerPass` site (round-17 evidence E2). Every name above was
// grepped before it was written.
//
// This comment used to assert the opposite -- "Neither callback is registered
// ... and `task13_18_r4_staging_is_production_unreachable` is what proves it".
// The gate is retired and FAILs by design, so it proved nothing, and the claim
// it was cited for is the reverse of what this module does.

/// Perform one pending-callback effect natively.
///
/// A trait rather than a match arm so Task 19's cutover replaces the *impl* and
/// leaves both trampolines and both roster walks untouched. The effects that
/// need the per-install core runtime (`PendingWorkerSchedule`,
/// `PendingWakeSlot`, `PendingOwnerLedger`) are the ones Task 19 fills in:
/// `build_ring_runtime_parts` and `PendingWorkerSchedule::for_brand` are
/// `pub(crate)` to `fsring-core` today, so this crate cannot hold those values
/// at all yet -- which puts the staging boundary in the type system rather than
/// in a comment.
pub(crate) trait PendingCallbackEffects {
    /// Perform `action` for the slot at `context`, under whatever lock
    /// discipline that action's core documentation states.
    ///
    /// # Safety
    /// `context` is a live initialized slot and the caller is the callback the
    /// action belongs to.
    unsafe fn perform_pending_effect(
        &mut self,
        context: NonNull<PendingEnterContext>,
        action: PendingCallbackAction,
    );
}

/// The production executor for both the timer DPC and the PASSIVE worker. It
/// performs every effect on core's roster, and the walk visits every entry.
///
/// The runtime-dependent effects ACT: `RecordTimeoutWake` drives
/// `record_and_schedule_pending` over the real `runtime.schedule`/`wake`/
/// `owners`, `QueueWorker` calls `IoQueueWorkItem`, and `ReleaseDpcOwner`
/// releases the real token. Each is a no-op only when the slot has no runtime
/// or no install, which is a state and not a checkpoint.
///
/// This doc used to read "it performs the effects this crate can express today
/// and no others. The runtime-dependent effects are inert rather than a
/// bugcheck, because a bugcheck here would be a trap Task 19 has to remember to
/// remove ... What is missing is the *value* they act on, and this crate cannot
/// name it yet." Every clause of that is false on this tree, and the one that
/// mattered is the first: a reader who believed it believed the timer path
/// could not queue work, which is the opposite of what it does.
pub(crate) struct StagedSlotEffects {
    /// Held between `RecordTimeoutWake` and `QueueWorker`, which is the whole
    /// reason those are two roster entries: the wake is recorded under the slot
    /// lock and the queue DDI is called outside it. The right has a `Drop` that
    /// bugchecks, so a pass that recorded a wake and never reached `QueueWorker`
    /// cannot leave the install queued with nothing to run it.
    queue_right: Option<QueueWorkRight>,
}

impl StagedSlotEffects {
    pub(crate) const fn new() -> Self {
        Self { queue_right: None }
    }
}

impl PendingCallbackEffects for StagedSlotEffects {
    unsafe fn perform_pending_effect(
        &mut self,
        context: NonNull<PendingEnterContext>,
        action: PendingCallbackAction,
    ) {
        let raw = context.as_ptr();
        match action {
            // The Armed -> Running transition already happened inside
            // `begin_dpc_pass`, which is what chose the roster.
            //
            // The DPC owner is NOT taken here, and that is deliberate. This
            // whole roster runs inside one slot-lock hold, and the only reader
            // of `owner_count` -- `commit_final_publication` -- takes the same
            // lock, so an owner acquired and released in this scope is
            // invisible to every observer: the two can never be inside the lock
            // at once. Making an in-flight DPC visible needs the owner held
            // from the moment the timer is ARMED until the DPC exits, which is
            // where `park_wait_enter` takes it. `ReleaseDpcOwner` below is the
            // matching release, and `cancel_pending_timer` releases it for a
            // timer dequeued before it ever ran.
            PendingCallbackAction::EnterRunning => {}
            PendingCallbackAction::PublishQuiesced => {
                // SAFETY: the DPC holds the slot lock across this effect, and
                // `timer_state` is initialized before the CSQ is published. A
                // stale pass never reaches this effect: its roster is empty.
                let epoch = unsafe { (*raw).timer_state.epoch() };
                if let Some(epoch) = epoch {
                    // SAFETY: as above. `dpc_exiting` refuses any state that is
                    // not this pass's own `Running`, so a slot re-armed by a
                    // later install is left exactly as it is.
                    let _ = unsafe { (*raw).timer_state.dpc_exiting(epoch) };
                }
            }
            PendingCallbackAction::RecordTimeoutWake => {
                // SAFETY: the DPC holds the slot lock across this effect.
                let runtime = unsafe { (*raw).runtime.as_mut() };
                if let Some(runtime) = runtime {
                    if let Some(install) = runtime.install {
                        // The shared helper, not a second scheduling path.
                        // `WorkerScheduleState` is the sole publication and this
                        // is the only thing allowed to move it, so a DPC cannot
                        // queue a pass the installer has not handed off.
                        let outcome = record_and_schedule_pending(
                            install,
                            PendingReason::Timeout,
                            &mut runtime.schedule,
                            &mut runtime.wake,
                            &mut runtime.owners,
                            &mut runtime.worker_owner,
                        );
                        if let Ok(PendingWakeOutcome::Queued(right)) = outcome {
                            self.queue_right = Some(right);
                        }
                    }
                }
            }
            PendingCallbackAction::QueueWorker => {
                if let Some(right) = self.queue_right.take() {
                    // SAFETY: the work item was allocated at SETUP and is this
                    // slot's; IoQueueWorkItem is callable at DISPATCH_LEVEL.
                    let work_item = unsafe { (*raw).work_item };
                    if !work_item.is_null() {
                        unsafe {
                            IoQueueWorkItem(
                                work_item,
                                Some(fsring_pending_enter_worker),
                                DelayedWorkQueue,
                                raw.cast::<c_void>(),
                            );
                        }
                    }
                    // SAFETY: the one void queue DDI for this right just ran.
                    unsafe { right.commit_after_work_queued() };
                }
            }
            PendingCallbackAction::ReleaseDpcOwner => {
                // SAFETY: the DPC holds the slot lock across this effect.
                let runtime = unsafe { (*raw).runtime.as_mut() };
                if let Some(runtime) = runtime {
                    if let Some(token) = runtime.dpc_owner.take() {
                        // The exact token this DPC took on entry. A ledger that
                        // accepted any Dpc-kind token would let a stale pass
                        // release a live install's owner.
                        let _ = runtime.owners.release_owner(token);
                    }
                }
            }
            // The worker's remaining effects are mediated by
            // `PendingCompletionPlan::run_next`, which owns their order and
            // takes itself by value so a stage cannot be skipped. Driving them
            // from this roster too would be two orders for one sequence.
            // `RemoveIrpFromCsq` is no longer walked from here. The dequeue is
            // performed by `run_pending_completion_pass` itself, once the pass
            // holds the completion authorities, so a pass that cannot run
            // leaves the request queued and cancellable. Keeping the arm as a
            // no-op would let a future roster walk it silently, so it is
            // simply gone: `PendingCallbackAction` is exhaustive here and a
            // reinstated walk fails to compile.
            PendingCallbackAction::PollAndRecheck => {
                // SAFETY: PASSIVE worker; the session pointer is stored before
                // the thunk returns STATUS_PENDING and is not taken until the
                // completion pass below.
                //
                // Reaches `(*raw).runtime` under this slot's own lock: an
                // unguarded `&mut` here would alias the DPC's hold of the same
                // lock over the same context, the identical shape as
                // `RemoveIrpFromCsq` above.
                let old_irql =
                    unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
                let unlock = unsafe {
                    PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
                };
                let runtime = unsafe { (*raw).runtime.as_mut() };
                if let Some(runtime) = runtime {
                    let ring_index = runtime.ring_brand().ring_index();
                    runtime.polled_sq_ready = !runtime.session.is_null()
                        && unsafe { (*runtime.session).sq_cursors(ring_index) }
                            .is_some_and(|(produced, consumed)| produced != consumed);
                }
                unlock.release();
            }
            PendingCallbackAction::FinishWorkerPass => {
                // Performed here, in the roster, rather than inside the
                // completion pass: the frozen order names this action, so this
                // is where it has to happen, and having exactly one close means
                // a pass can never be finished twice.
                //
                // `finish_worker_pass` yields a `QueueWorkRight` when a wake
                // landed while this pass was running -- it moves
                // `RunningReschedule` to `Queued`, and a `Queued` schedule
                // refuses to queue again. That answer used to be a `bool` and
                // it was discarded, which did not merely lose one wake: it
                // wedged the ring, with every later wake stored and nothing
                // scheduled to act on any of them, and the parked WAIT then
                // waiting for a fence or unload it should never have needed.
                //
                // SAFETY: the lock is initialized before the CSQ is published,
                // and this arm is only ever reached by the PASSIVE worker,
                // holding nothing.
                let old_irql =
                    unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
                // SAFETY: paired with the acquire; released on every path.
                let unlock = unsafe {
                    PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
                };
                // SAFETY: exclusive under the hold. A pass that never began
                // holds no Worker token, so this refuses and owes nothing
                // rather than closing a pass that does not exist.
                let due = match unsafe { (*raw).runtime.as_mut() } {
                    Some(runtime) => runtime.finish_pass(),
                    None => None,
                };
                // SAFETY: read under the hold; every slot of a ready runtime
                // carries its work item.
                let work_item = unsafe { (*raw).work_item };
                unlock.release();
                if let Some(right) = due {
                    // The right is the obligation the schedule minted when it
                    // published `Queued`, and it is discharged by the one queue
                    // call it stands for -- the same discipline every other
                    // queue site in this module follows. Its `Drop` is what
                    // would make a missing queue loud rather than silent.
                    if work_item.is_null() {
                        // Nothing to queue against: the arena has been rolled
                        // back under this slot. Nothing can run again here, so
                        // the obligation is reported rather than discharged.
                        panic!("a rescheduled pass has no work item to queue");
                    }
                    // SAFETY: the lock is released, this item is this slot's
                    // own and is no longer queued -- the I/O manager dequeued
                    // it to run this very callback -- and the schedule above
                    // published the `Queued` this call discharges.
                    unsafe {
                        IoQueueWorkItem(
                            work_item,
                            Some(fsring_pending_enter_worker),
                            DelayedWorkQueue,
                            raw.cast::<c_void>(),
                        );
                        right.commit_after_work_queued();
                    }
                }
            }
            PendingCallbackAction::BeginWorkerPass
            | PendingCallbackAction::WriteResultStorage
            | PendingCallbackAction::CompleteIrp
            | PendingCallbackAction::RemoveIrpFromCsq => {}
        }
    }
}

/// The timer DPC for one pending slot.
///
/// Runs at DISPATCH_LEVEL, so it never dequeues, waits, writes output, or
/// completes -- and that is not a promise made here, it is
/// `PendingCallbackAction::forbidden_at_dispatch_level` holding over the two
/// rosters `PendingDpcPath::effects` can return.
///
/// # Safety
/// Invoked by the kernel with the `DeferredContext` this module passed to
/// `KeInitializeDpc`: the address of the containing slot.
unsafe extern "C" fn fsring_pending_enter_timer_dpc(
    _dpc: PKDPC,
    deferred_context: PVOID,
    _argument1: PVOID,
    _argument2: PVOID,
) {
    let Some(context) = NonNull::new(deferred_context.cast::<PendingEnterContext>()) else {
        // The DPC this module initializes always carries its slot. A null one
        // is another driver's DPC arriving on our routine, which is not a
        // condition any recovery can improve.
        panic!("pending-ENTER timer DPC invoked without its slot");
    };
    let raw = context.as_ptr();
    // SAFETY: `lock` is initialized before the DPC is bound to a timer, and a
    // DPC already runs at DISPATCH_LEVEL so the raise is a no-op.
    let raised = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: read under the hold just taken. A quiesced slot reports no epoch
    // and takes the stale roster, which performs nothing.
    let epoch = unsafe { (*raw).timer_state.epoch() }.unwrap_or_default();
    // The roster is chosen by the timer transition, so a DPC that arrived for
    // an install the slot no longer runs performs nothing at all.
    // SAFETY: exclusive under the hold.
    // Clear the exit event at DPC ENTRY, not when the next install arms. This
    // event is a NotificationEvent: it stays signalled until cleared, and it
    // used to be cleared nowhere at all, so every exit wait after the first was
    // unconditional success. Clearing it here rather than at arm time keeps the
    // clear and the set inside one generation: no thread ever clears an event a
    // different generation's DPC is about to signal.
    // SAFETY: exclusive under the hold; `dpc_exited` is initialized before the
    // DPC can be bound to a timer.
    unsafe { fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!((*raw).dpc_exited)) };
    // This generation now has a DPC that will store into the arena once more,
    // after this hold is released. Teardown reads it to know whether the
    // `KeSetEvent` below is still owed.
    // SAFETY: exclusive under the hold.
    unsafe { (*raw).dpc_entered = true };
    let mut pass = unsafe { PendingDpcPass::begin_dpc_pass(&mut (*raw).timer_state, epoch) };
    let mut effects = StagedSlotEffects::new();
    let ticket = loop {
        match pass.run_next_dpc_effect() {
            PendingDpcStep::Perform(action, next) => {
                // SAFETY: this is the callback each DPC action belongs to, and
                // the slot lock is held for every one of them.
                unsafe { effects.perform_pending_effect(context, action) };
                pass = next;
            }
            PendingDpcStep::SignalExit(ticket) => break ticket,
        }
    };
    // Unlock BEFORE the event: a waiter released by `KeSetEvent` immediately
    // takes this same lock, and signalling under the hold would make every
    // wakeup spin for the rest of this critical section. The named c4 mutant
    // `pending-dpc-exit-signal-before-owner-release` plants the reverse and
    // must stay killable.
    // SAFETY: paired with the acquire above.
    unsafe {
        KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);
    }
    // The final action, and the ticket is the only authority for it. By the
    // time one exists the owner is released and `Quiesced` is published, so a
    // waiter that wakes here cannot observe a timer still claiming to run.
    //
    // A stale signal cannot leak into the next install, and the reason is NOT
    // that "a waiter only waits while `TimerState::Running`" -- that sentence
    // stood here and was false: `TimerState::cancel` answers
    // `RequiresDpcExitWait` from `Armed` too, and a waiter entitled to that
    // state waits before this DPC's successor has entered or cleared anything.
    //
    // What actually holds is that `wait_pending_dpc_exit` clears the event
    // itself, under the slot lock, whenever the state still owes it a wait. A
    // set published after this unlock is therefore erased by the waiter before
    // it waits, and no waiter can be satisfied by a generation that has already
    // finished. This DPC's own entry clear is the second line, not the first.
    // SAFETY: `dpc_exited` is initialized before the DPC can be armed; no lock
    // is held and `KeSetEvent` is callable at DISPATCH_LEVEL with wait FALSE.
    unsafe {
        KeSetEvent(core::ptr::addr_of_mut!((*raw).dpc_exited), 0, 0 as BOOLEAN);
    }
    // SAFETY: the one `KeSetEvent(dpc_exited)` for this pass just happened.
    unsafe { ticket.commit_after_exit_signalled() };
}

/// The PASSIVE worker pass for one pending slot.
///
/// # Safety
/// Invoked by the I/O manager with the context this module passed to
/// `IoQueueWorkItem`: the address of the containing slot.
unsafe extern "C" fn fsring_pending_enter_worker(_device: PDEVICE_OBJECT, context: PVOID) {
    let Some(context) = NonNull::new(context.cast::<PendingEnterContext>()) else {
        panic!("pending-ENTER worker invoked without its slot");
    };
    let mut effects = StagedSlotEffects::new();
    // The two roster rows this callback owns outright, in
    // `PENDING_WORKER_PASS_ORDER`. The remaining four are NOT walked here:
    // `WriteResultStorage`, `CompleteIrp` and the final publication are
    // mediated by `PendingCompletionPlan`, which owns their order and takes
    // itself by value so a stage cannot be skipped. Driving them from the
    // roster too would be two orders for one sequence.
    //
    // `RemoveIrpFromCsq` joined them. Walking it here dequeued the IRP -- and
    // cleared its cancel routine -- BEFORE `begin_pass` had decided the pass
    // may run at all. A pass that then refused (the plan is published by
    // `store_parked_wait` after `IoCsqInsertIrp` returns, and a wake can land
    // inside that window) left the request out of the queue, uncancellable,
    // with nothing scheduled: an indefinite WAIT arms no timer, readiness
    // needs another ENTER, and teardown is what the wedge blocks. The dequeue
    // now happens inside the completion pass, after the authorities are in
    // hand, so a refusal leaves the IRP queued and cancellable.
    //
    // There is no DPC-exit rendezvous here any more. One stood second, and it
    // could not do that job from this position: nothing has cancelled the timer
    // when this walk runs, so it either waited on an unfired deadline -- the
    // client's whole `timeout_ms` on this very `DelayedWorkQueue` thread -- or,
    // narrowed to `Running`, waited never, because `Running` exists only inside
    // the DPC's own hold of the slot lock. The rendezvous the worker still
    // performs is `PendingCompletionPlan`'s `WaitDpcExitIfRequired`, directly
    // after the `CancelTimer` that bounds it.
    for action in [
        PendingCallbackAction::BeginWorkerPass,
        PendingCallbackAction::PollAndRecheck,
    ] {
        // SAFETY: this is the callback each worker action belongs to.
        unsafe { effects.perform_pending_effect(context, action) };
    }
    // SAFETY: PASSIVE_LEVEL on the work-item thread; the slot is live.
    let started = unsafe { run_pending_completion_pass(context) };
    if started {
        // The total publication already released the last owner, published the
        // reusable state, and unlocked. Nothing may touch the context after it.
        return;
    }
    // SAFETY: as above. Nothing was completed, so the pass closes normally and
    // the slot's schedule decides whether another pass follows.
    unsafe {
        effects.perform_pending_effect(context, PendingCallbackAction::FinishWorkerPass);
    }
}

/// Run one parked install's completion, if this slot has one to run.
///
/// Returns whether a completion ran. `false` means the pass found no install
/// authorities -- a wake that coalesced, or a slot whose install is still
/// publishing -- and the caller closes the pass instead.
///
/// # Safety
/// PASSIVE_LEVEL on the work-item thread; `context` is a live initialized slot.
unsafe fn run_pending_completion_pass(context: NonNull<PendingEnterContext>) -> bool {
    let raw = context.as_ptr();
    // SAFETY: the lock is initialized before the CSQ is published.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire; released on every path below.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: exclusive under the hold. Session wait stays until this pass
    // actually begins: taking it on a coalesced wake would drop `RoleLease`.
    // SAFETY: both fields are read under the hold and are written only under
    // it. The AXIS decides, not the pointer: a pointer that is still there
    // says nothing about who may complete the request. A published handoff --
    // this slot's own earlier dequeue, or the framework's cancel completion --
    // is the only thing this pass may complete from without going to the CSQ
    // itself, and that trip happens below, after the authorities are in hand.
    let handed = unsafe {
        classify_worker_dequeue(
            (*raw).irp_axis,
            IrpObservation::from_raw((*raw).irp as usize),
        )
    };
    let (taken, pass_reason, ring_index, session_wait, polled_sq_ready) =
        match unsafe { (*raw).runtime.as_mut() } {
            Some(runtime) => {
                // One transaction under the slot lock. The pass begins first,
                // because that is what takes the coalesced wakes and moves the
                // schedule to `Running`; then it declares itself a completing
                // pass, and only then are the authorities the plan consumes
                // taken. A pass that cannot begin takes nothing at all.
                //
                // A pass that begins but cannot declare completion is NOT
                // finished here. It returns `false` and the caller performs the
                // roster's `FinishWorkerPass`, which is the one close and the
                // one place that acts on "another pass is due". Finishing here
                // as well would either close the pass twice or -- as it did --
                // close it in the one place whose answer nobody reads.
                //
                // The release is part of the same condition as the pass and
                // the completion declaration, and the observation is zipped
                // onto the authorities in one expression, so the two cannot
                // desynchronise: there is no way to hold authorities without
                // the IRP the CSQ actually released.
                let reason = runtime.begin_pass();
                let taken = if reason.is_some()
                    && !matches!(handed, WorkerDequeueAuthority::NoParkedIrp)
                    && runtime.begin_completion()
                {
                    let taken = runtime.take_completion_authorities();
                    if taken.is_none() {
                        // `begin_completion` has already declared `Completing`,
                        // and the authorities did not come. Undone HERE, inside
                        // the hold that made the declaration, rather than at the
                        // `taken` refusal below: that one runs after
                        // `unlock.release()`, so it would have to re-take the
                        // lock to undo something this frame never should have
                        // let out of it.
                        //
                        // Without this the schedule stays `Completing`, which
                        // refuses to finish, refuses to abandon and refuses to
                        // queue -- for the life of the slot. The round-14 review
                        // found this third exit and could not reach it, because
                        // `pass_admission` and `begin_completion` between them
                        // establish everything `take_completion_authorities`
                        // asks for under this same hold. It is closed anyway:
                        // the two arms below undo the same declaration, and a
                        // refusal path whose safety rests on another predicate
                        // agreeing with it is one edit away from being wrong.
                        runtime.abandon_completion();
                    }
                    taken
                } else {
                    None
                };
                let session_wait = if taken.is_some() {
                    runtime.take_session_wait()
                } else {
                    (None, core::ptr::null(), None, core::ptr::null())
                };
                (
                    taken,
                    reason,
                    runtime.ring_brand().ring_index(),
                    session_wait,
                    runtime.polled_sq_ready,
                )
            }
            None => (
                None,
                None,
                0,
                (None, core::ptr::null(), None, core::ptr::null()),
                false,
            ),
        };
    // SAFETY: as above; the view is fixed for the life of the runtime.
    let result_view = NonNull::new(unsafe { (*raw).result_view });
    unlock.release();
    let (mut session_role, session_ring, parked_request, session) = session_wait;

    // The bugcheck that used to stand here -- `a pending install without its
    // dequeued IRP` -- was reachable exactly when the cancel routine owned the
    // request, and it is deleted rather than guarded: that state refuses.
    let Some((install, role, control_link, worker)) = taken else {
        return false;
    };
    let Some(result_view) = result_view else {
        panic!("a pending install on a slot with no result backing")
    };

    // Only now, holding the authorities, does this pass go to the CSQ. Doing
    // it in the unconditional roster prefix dequeued the IRP and cleared its
    // cancel routine before `begin_pass` had decided anything, so a refused
    // pass stranded a request nothing could cancel and nothing was scheduled
    // to complete.
    //
    // SAFETY: PASSIVE worker; the CSQ was initialized before any insert and
    // this is the sole non-cancel dequeue. `IoCsqRemoveIrp` takes and releases
    // this slot's own lock itself, so it is called with no hold outstanding,
    // and the publication below takes its own separate acquire.
    let irp = match handed {
        // The framework's cancel completion, or an earlier pass, already
        // published the handoff. The request is out of the queue and this slot
        // names it; going to the CSQ again would answer NULL.
        WorkerDequeueAuthority::ReleasedToDriver(irp) => Some(irp),
        WorkerDequeueAuthority::NoHandoffPublished => {
            let removed = unsafe {
                IoCsqRemoveIrp(
                    core::ptr::addr_of_mut!((*raw).csq),
                    core::ptr::addr_of_mut!((*raw).csq_irp_context),
                )
            };
            match IrpObservation::from_raw(removed as usize) {
                Some(observed) => {
                    // SAFETY: publish the handoff under this slot's own lock,
                    // never aliasing the DPC roster's hold of the same lock.
                    let old_irql = unsafe {
                        KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock))
                    };
                    let unlock = unsafe {
                        PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
                    };
                    unsafe {
                        (*raw).irp = removed;
                        (*raw).irp_axis = Some(IrpAxis::Dequeued);
                    }
                    unlock.release();
                    Some(observed)
                }
                // NULL means `IoSetCancelRoutine` handed the routine out: the
                // framework owns this request and will publish its own
                // handoff. Complete nothing.
                None => None,
            }
        }
        WorkerDequeueAuthority::NoParkedIrp => None,
    };

    let Some(irp) = irp else {
        // Give back everything this pass took, including the completion
        // declaration itself: `Completing` refuses both to finish and to
        // queue, so leaving it there would wedge the slot for good. The
        // caller's `FinishWorkerPass` then closes the pass the ordinary way.
        // SAFETY: re-taking the same lock to put back what was taken.
        let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
        // SAFETY: paired with the acquire.
        let unlock =
            unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
        // Ask the same question of the same two fields the pass asked before it
        // went to the CSQ. A different answer now means the framework's cancel
        // completion published the handoff while this pass held `Completing`.
        //
        // SAFETY: exclusive under the hold, and read before the runtime borrow.
        let adopted = unsafe {
            classify_worker_dequeue(
                (*raw).irp_axis,
                IrpObservation::from_raw((*raw).irp as usize),
            )
        };
        // SAFETY: exclusive under the hold.
        if let Some(runtime) = unsafe { (*raw).runtime.as_mut() } {
            runtime.parked_role = Some(role);
            runtime.control_link = Some(control_link);
            runtime.worker_owner = Some(worker);
            if let Some(lease) = session_role {
                runtime.session_role = Some(lease);
                runtime.session_ring = session_ring;
                runtime.parked_request = parked_request;
                runtime.session = session;
            }
            runtime.abandon_completion();
            // The framework's cancel path can adopt this request while the
            // pass stands declared `Completing`, and `record_and_schedule_pending`
            // refuses every wake in that state BEFORE it records one -- so the
            // Cancel that arrived was dropped rather than stored, and the
            // cancel routine that delivered it is spent. `abandon_completion`
            // has just put the schedule back to `Running`, the first state
            // that can take that reason, and this is the only point that has
            // seen both halves: the NULL dequeue answer and the adopted slot.
            //
            // Without this the request is dequeued, adopted, no longer
            // cancellable and owed by nobody -- there is no later wake to
            // rescue it, because the one wake that would have existed is the
            // one that was just refused.
            if matches!(adopted, WorkerDequeueAuthority::ReleasedToDriver(_)) {
                let _ = runtime.deposit_locked_wake(PendingReason::Cancel);
            }
        }
        unlock.release();
        return false;
    };
    let plan = match PendingCompletionPlan::begin(install, irp, role, control_link, worker) {
        Ok(plan) => plan,
        // The three authorities come back intact, which is exactly why they are
        // returned: they belong to a slot that is still installed, and losing
        // them would strand the parked IRP with nothing able to complete it.
        Err((_, role, control_link, worker)) => {
            // SAFETY: re-taking the same lock to put back what was taken.
            let old_irql =
                unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
            // SAFETY: paired with the acquire.
            let unlock = unsafe {
                PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
            };
            // SAFETY: exclusive under the hold.
            if let Some(runtime) = unsafe { (*raw).runtime.as_mut() } {
                runtime.parked_role = Some(role);
                runtime.control_link = Some(control_link);
                runtime.worker_owner = Some(worker);
                if let Some(lease) = session_role {
                    runtime.session_role = Some(lease);
                    runtime.session_ring = session_ring;
                    runtime.parked_request = parked_request;
                    runtime.session = session;
                }
                // Returning the authorities is not the whole undo. This frame
                // declared `Completing` in `begin_completion` before taking
                // them, and a schedule left at `Completing` refuses to finish
                // AND refuses to queue -- the slot never runs again, with the
                // IRP already dequeued and its cancel routine spent, so no
                // later wake can rescue it either. The NULL-dequeue arm above
                // undoes the declaration for exactly this reason; this arm is
                // the same shape and owes the same undo.
                runtime.abandon_completion();
            }
            unlock.release();
            return false;
        }
    };

    // Only now, with the completion plan in hand, may this pass arbitrate.
    // `PendingIrpArbiter::contend` is one-shot and `PendingCompletionPlan::begin`
    // above can still refuse and hand every authority back; arbitrating before
    // that cut would spend the terminal on a pass that then returns without
    // completing, stranding the parked IRP with nothing able to finish it.
    //
    // SAFETY: re-taking the same slot lock this frame released above.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: exclusive under the hold.
    let mut arbitrated = match unsafe { (*raw).runtime.as_mut() } {
        Some(runtime) => match pass_reason {
            Some(reason) => runtime.take_arbitrated_completion(irp.observed_address(), reason),
            None => None,
        },
        None => None,
    };
    unlock.release();

    // Drive the plan up to -- but not into -- the final publication. The last
    // effect is the total operation's, which takes the lock itself; running it
    // here would consume the plan into a boundary this frame cannot unlock.
    let mut plan = plan;
    while !matches!(
        plan.stage(),
        None | Some(PendingCompletionEffect::PublishVacantOrEpochExhausted)
    ) {
        if matches!(plan.stage(), Some(PendingCompletionEffect::CancelTimer)) {
            // The DDI, not bookkeeping. A finite WAIT arms `KeSetTimer`, and
            // without this call an armed timer stays queued while the pool
            // holding its KTIMER and KDPC is freed underneath it. The BOOLEAN
            // is what decides who owns the DPC: dequeued means this frame took
            // it off the queue, and not-dequeued while armed or running means
            // the DPC owns it and only `dpc_exiting` may publish Quiesced.
            // SAFETY: PASSIVE worker; the timer and DPC live in the slot until
            // the arena is freed, which the completion has not reached.
            // `CancelledAndQueued`: the DDI has already answered FALSE for
            // this timer, so `Armed` here means a DPC that is queued and
            // imminent rather than a deadline that has not fired.
            if unsafe { cancel_pending_timer(context, install) } {
                unsafe { wait_pending_dpc_exit(context) };
            }
            plan = match plan.run_next() {
                PendingCompletionStep::Advanced(next) => next,
                other => {
                    let _ = other;
                    panic!("timer cancellation is a bookkeeping stage")
                }
            };
            continue;
        }
        if matches!(
            plan.stage(),
            Some(PendingCompletionEffect::ReleaseSqWaitRole)
        ) {
            let (next, slot_lease) = plan.take_sq_wait_role();
            plan = next;
            if let Some(slot_lease) = slot_lease {
                unsafe { release_slot_sq_wait(context, slot_lease) };
            }
            if let Some(lease) = session_role.take() {
                if !session_ring.is_null() {
                    unsafe { (*session_ring).release_parked_session_role(lease) };
                }
            }
            continue;
        }
        if matches!(
            plan.stage(),
            Some(PendingCompletionEffect::UnlinkControlPending)
        ) {
            let (next, link) = plan.take_control_link();
            plan = next;
            if let Some(link) = link {
                unsafe { unlink_parked_control_link(context, link) };
            }
            continue;
        }
        if matches!(
            plan.stage(),
            Some(PendingCompletionEffect::ReleaseStrongSessionRef)
        ) {
            plan = match plan.run_next() {
                PendingCompletionStep::Advanced(next) => next,
                other => {
                    let _ = other;
                    panic!("strong-ref release is a bookkeeping stage")
                }
            };
            unsafe { release_parked_strong_refs(context) };
            continue;
        }
        match plan.run_next() {
            PendingCompletionStep::Advanced(next) => plan = next,
            PendingCompletionStep::NeedResultWrite(write) => {
                let (_install, observed) = write.view();
                let sq_ready = polled_sq_ready
                    || (!session.is_null()
                        && unsafe { (*session).sq_cursors(ring_index) }
                            .is_some_and(|(produced, consumed)| produced != consumed));
                // The status is the arbitration's. `finish_arbitrated` consumes
                // the parked plan and the terminal right together, so the only
                // reachable status here is the one the terminal CAS decided --
                // this frame cannot re-derive it from the raw wake flags, and a
                // slot with no authentic right completes fail-stop instead.
                let (status, information) = match arbitrated.take() {
                    Some((parked, right, reason)) => {
                        let outcome = parked.finish_arbitrated(right);
                        if session_role.is_none() {
                            session_role = outcome.role;
                        }
                        let status = outcome.result.status as u32;
                        match (status, parked_request.as_ref()) {
                            (0, Some(request)) => {
                                // The body says what the daemon should do next.
                                // `PollAndRecheck` is what upgrades a WAIT that
                                // timed out with work already queued.
                                let decision = if reason == PendingReason::Timeout && !sq_ready {
                                    EnterDecision::TimedOut
                                } else {
                                    EnterDecision::Ready
                                };
                                match unsafe {
                                    encode_parked_result_into_irp(observed, request, decision)
                                } {
                                    Some(written) => {
                                        let _ = unsafe { write_parked_enter_result(result_view) };
                                        (0, written)
                                    }
                                    None => (
                                        fsring_abi::control::status::INVALID_DEVICE_STATE as u32,
                                        0,
                                    ),
                                }
                            }
                            (0, None) => {
                                (fsring_abi::control::status::INVALID_DEVICE_STATE as u32, 0)
                            }
                            (status, _) => (status, outcome.result.information),
                        }
                    }
                    None => (fsring_abi::control::status::INVALID_DEVICE_STATE as u32, 0),
                };
                plan = write.commit_result_write(status, information);
            }
            PendingCompletionStep::NeedIrpCompletion(completion) => {
                let Some((observed, status, information)) = completion.view() else {
                    panic!("the IRP completion boundary was reached with no written result")
                };
                // SAFETY: the receipt names the exact dequeued IRP, this frame
                // owns it, and this is its one completion.
                unsafe { complete_parked_irp(observed, status, information) };
                plan = completion.commit_irp_completion();
            }
            // Unreachable: the loop condition stops before this stage.
            PendingCompletionStep::NeedFinalPublication(_) => {
                panic!("the worker reached the final publication boundary itself")
            }
        }
    }
    if let Some(lease) = session_role.take() {
        if !session_ring.is_null() {
            unsafe { (*session_ring).release_parked_session_role(lease) };
        }
    }
    // The one total call: it acquires the lock, commits or fail-stops, and
    // unlocks exactly once.
    // SAFETY: the IRP was completed once above and this frame touches the
    // context no further.
    let _outcome = unsafe { finalize_native_pending_publication(context, plan) };
    true
}

/// Cancel this slot's timer, reporting whether the DPC must be waited out.
///
/// `KeCancelTimer`'s BOOLEAN is the only thing that says who owns the DPC, so
/// the return is fed straight into `TimerState::cancel` rather than inferred.
/// A slot whose timer was never armed answers `NotArmed` and needs no wait.
///
/// # Safety
/// PASSIVE_LEVEL on the worker thread; `context` is a live initialized slot
/// whose timer and DPC outlive this call.
unsafe fn cancel_pending_timer(
    context: NonNull<PendingEnterContext>,
    install: PendingInstallId,
) -> bool {
    let raw = context.as_ptr();
    // SAFETY: the lock is initialized before the timer can be armed.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: read under the hold. The epoch is only consulted to learn whether
    // a timer was ever armed; the epoch this frame CLAIMS comes from its own
    // install, below.
    let armed_at_all = unsafe { (*raw).timer_state }.epoch().is_some();
    unlock.release();
    if !armed_at_all {
        return false;
    }
    // The install's epoch, not the timer's. Reading the epoch out of the field
    // `TimerState::cancel` validates it against made `NotThisInstall`
    // unreachable, and that arm is the only thing stopping a stale generation
    // being handed an obligation to wait on a DPC-exit event that only the live
    // generation's DPC will ever signal.
    let epoch = install.install_epoch();
    // SAFETY: the DDI is callable at or below DISPATCH_LEVEL and the timer
    // object is this slot's own. Outside the lock: it may synchronise with a
    // DPC that takes the same lock.
    let dequeued = unsafe { fsring_sys::c4::KeCancelTimer(core::ptr::addr_of_mut!((*raw).timer)) };
    // SAFETY: re-taking the same lock to record the one interpretation.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: exclusive under the hold.
    let outcome = unsafe { (*raw).timer_state.cancel(epoch, dequeued != 0) };
    // A timer this frame dequeued means the DPC will never run, so nothing will
    // ever reach `ReleaseDpcOwner`. The owner taken at arm time is released
    // here instead, or the slot could never publish again. A cancel that did
    // NOT dequeue leaves it held: that DPC is still in flight and the wait
    // below is what rendezvous with it.
    if matches!(outcome, PendingTimerCancel::DequeuedBeforeRun) {
        if let Some(runtime) = unsafe { (*raw).runtime.as_mut() } {
            if let Some(token) = runtime.dpc_owner.take() {
                let _ = runtime.owners.release_owner(token);
            }
        }
    }
    unlock.release();
    matches!(outcome, PendingTimerCancel::RequiresDpcExitWait)
}

/// Wait until this slot's timer DPC has provably exited.
///
/// The event is only the wakeup. `timer_state` is the truth, it is read under
/// the slot lock, and this function returns exactly when it has *observed* a
/// state that owes it nothing -- so the rendezvous is generation-specific
/// rather than "somebody's DPC signalled at some point".
///
/// One `KeWaitForSingleObject` was not enough, and the reason is
/// [`TimerState::cancel`]: it answers `RequiresDpcExitWait` from `Armed` as
/// well as from `Running`, because a queued-but-not-yet-entered DPC must be
/// waited for too. Such a DPC has not run its own entry `KeClearEvent` yet, so
/// a set left standing by the *previous* install's DPC -- which publishes
/// `Quiesced` inside the lock and signals after releasing it, a gap in which
/// the whole install can complete and the slot be reused -- satisfied the wait
/// immediately and the pass went on to free an arena a live KDPC still names.
///
/// The stale set is erased here, under the lock, because that is the one place
/// it can be told apart from a live one: a DPC is never between its own entry
/// clear and its own exit set while this hold is held, so a signal standing
/// while the state owes a wait was published by a generation that has already
/// finished.
///
/// # Safety
/// PASSIVE_LEVEL on the worker thread with the slot lock NOT held. A DPC may
/// never reach this: waiting on its own exit event is a deadlock.
unsafe fn wait_pending_dpc_exit(context: NonNull<PendingEnterContext>) {
    let raw = context.as_ptr();
    loop {
        // SAFETY: the lock is initialized before the timer can be armed.
        let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
        // SAFETY: paired with the acquire; released on every path below.
        let unlock =
            unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
        // SAFETY: read under the hold. `dpc_exiting` publishes `Quiesced` in
        // this same critical section, so this is the DPC's own report of
        // having left rather than an inference from a dispatcher object.
        //
        // Every caller of this function has already had a `KeCancelTimer`
        // answer FALSE, so `Armed` here is a DPC queued and imminent, never an
        // unfired deadline -- the state that made this wait park a system
        // worker thread for a client's whole timeout belonged to the roster arm
        // that no longer exists. Anything but `Quiesced` therefore owes a wait,
        // and no state is tested that an observer could not reach: `Running`
        // exists only inside the DPC's own hold of this lock, so the arm that
        // used to name it could never be taken.
        let owes_wait = !matches!(unsafe { (*raw).timer_state }, TimerState::Quiesced);
        if owes_wait {
            // SAFETY: under the hold, and `dpc_exited` is initialized before
            // the DPC can be bound to a timer. See the paragraph above for why
            // clearing here cannot erase the set this frame is waiting for.
            unsafe { fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!((*raw).dpc_exited)) };
        }
        unlock.release();
        if !owes_wait {
            return;
        }
        // NULL Timeout, not a pointer to zero. A non-null Timeout of zero means
        // "do not wait, return STATUS_TIMEOUT now", which is what this
        // rendezvous did until the R6 repair: `KeCancelTimer` returning FALSE
        // obliged a wait for the DPC, and the wait returned instantly, so the
        // pass completed the IRP and republished the slot while the KDPC was
        // still queued against it. Every other indefinite wait in this driver
        // passes NULL; the one bounded wait, in boot.rs, passes a negative
        // relative time.
        //
        // The returned status is deliberately not asserted on. A `KernelMode`,
        // non-alertable wait with a NULL Timeout on a live dispatcher object
        // has exactly one outcome, and a bogus object does not return a status
        // at all -- it bugchecks inside the DDI. An assert here would be dead
        // code claiming a detection it cannot perform. The loop's re-read under
        // the lock is this function's real postcondition.
        //
        // SAFETY: `dpc_exited` is initialized before the DPC can be armed, no
        // lock is held, and the caller is PASSIVE. The wait is bounded by the
        // exit signal of a DPC the state above proved is still in flight.
        let _status = unsafe {
            fsring_sys::c4::KeWaitForSingleObject(
                core::ptr::addr_of_mut!((*raw).dpc_exited).cast(),
                0,
                0,
                0 as BOOLEAN,
                core::ptr::null_mut(),
            )
        };
    }
}

/// Encode the parked WAIT prefix into the METHOD_BUFFERED SystemBuffer.
///
/// # Safety
/// `observed` names the dequeued IRP this pass still owns; the I/O manager has
/// not completed it, so SystemBuffer remains the ENTER output.
unsafe fn encode_parked_result_into_irp(
    observed: IrpObservation,
    request: &EnterRequestV1,
    decision: EnterDecision,
) -> Option<usize> {
    let irp = observed.observed_address() as PIRP;
    if irp.is_null() {
        return None;
    }
    // SAFETY: ENTER is METHOD_BUFFERED; SystemBuffer is the active member
    // until IoCompleteRequest.
    let system_buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer }.cast::<u8>();
    if system_buffer.is_null() {
        return None;
    }
    let stack = unsafe { fsring_sys::io_get_current_irp_stack_location(irp) };
    if stack.is_null() {
        return None;
    }
    let output_length = unsafe { (*stack).Parameters.DeviceIoControl }.OutputBufferLength as usize;
    let prefix = ENTER_RESULT_V1_PREFIX_SIZE as usize;
    if output_length < prefix {
        return None;
    }
    // SAFETY: METHOD_BUFFERED guarantees `output_length` writable bytes.
    let dst = unsafe { core::slice::from_raw_parts_mut(system_buffer, output_length) };
    encode_parked_empty_result(dst, request, decision).ok()
}

/// Copy the parked ENTER's exact result into this slot's out-of-line backing.
///
/// The backing is the arena's, not the caller's buffer: the daemon's output
/// buffer belongs to an IRP that is completed *after* this, and writing it here
/// would be writing memory the I/O manager has not yet handed back.
///
/// # Safety
/// `view` is this slot's own result storage, written only by the pass that owns
/// the completion plan.
unsafe fn write_parked_enter_result(view: NonNull<u8>) -> usize {
    // The zero-credit result is the only shape a parked ENTER produces on this
    // tree: this function writes the prefix and nothing else, so no CQ entry
    // reaches a parked completion. Zeroing is the write: it is what stops a
    // reused slot handing back a previous install's bytes.
    //
    // This comment used to read "Task 20 is what adds CQ entries to it." Task
    // 20 closed without adding them, and the CQ storage lane it would have come
    // through has no production caller at all -- the same lane the gate
    // document's section 11 entry records as unbound.
    let prefix = ENTER_RESULT_V1_PREFIX_SIZE as usize;
    // SAFETY: the arena reserved at least the prefix for every slot, checked
    // when the runtime was built.
    unsafe { core::ptr::write_bytes(view.as_ptr(), 0, prefix) };
    prefix
}

/// Complete the one dequeued IRP this install parked.
///
/// # Safety
/// `observed` is the exact IRP this plan dequeued, it has not been completed,
/// and this frame owns it.
unsafe fn complete_parked_irp(observed: IrpObservation, status: u32, information: usize) {
    let irp = observed.observed_address() as PIRP;
    // SAFETY: the caller's ownership contract. Both output fields are written
    // before the single completion call, in the same shape every other dispatch
    // path in this driver uses, and the IRP is never touched afterwards.
    unsafe {
        core::ptr::addr_of_mut!((*irp).IoStatus.__bindgen_anon_1.Status).write(status as NTSTATUS);
        core::ptr::addr_of_mut!((*irp).IoStatus.Information).write(information as u64);
        crate::kernel::complete_request(irp, 0);
    }
}

/// Take back and fail a WAIT whose parked plan was never stored.
///
/// A refused `store_parked_wait` leaves the IRP in the CSQ with no plan behind
/// it, so nothing in this driver will ever complete it: the worker's
/// `begin_pass` refuses forever on a `parked_plan` that stays `None`. Rather
/// than leave the client waiting on a request the driver already knows it
/// cannot serve, the dispatch takes the IRP back out of the queue and fails it
/// once, here.
///
/// Returns false when `IoCsqRemoveIrp` answers NULL: `IoSetCancelRoutine`
/// handed the routine out and the framework owns the request, so this path
/// must not complete it.
///
/// Do not read that as "the cancel path completes it" -- it does not. This
/// driver's `csq_complete_canceled_irp` deliberately completes nothing; it
/// adopts the request into the slot and deposits a Cancel wake for a worker
/// pass to act on. With no plan stored there is no pass that can, so on this
/// branch the request is answered by nothing until the session's fence or
/// process-loss teardown reaches it. That is owed work, not a covered case,
/// and it is sound only for as long as every `ParkedStoreRefusal` arm stays
/// unreachable. The next reader who needs a completion here should add it to
/// the teardown that owns the slot, not to this branch, which holds no plan,
/// no role and no terminal to complete with.
///
/// What this does NOT do, deliberately: end the reserved install or restore
/// `slot_state`. Those inputs were consumed into the slot runtime before
/// `IoCsqInsertIrp`, and reversing them after the fact would have to unwind an
/// arbiter that is already parked and a handoff that may already have queued a
/// worker. A partial unwind there buys a second wedge -- a ring whose next
/// `park` is refused for the life of the session -- in exchange for the one it
/// removes. The slot therefore still reports `Active` to
/// `observe_pending_for_unload`, which is the driver's designed blocked-safe
/// unload path rather than a request nobody can answer.
///
/// # Safety
/// PASSIVE_LEVEL with no slot lock held, on a slot whose CSQ was initialized.
pub(crate) unsafe fn fail_unstored_parked_wait(
    runtime: &PendingRuntimeReady,
    ring_index: u32,
) -> bool {
    if ring_index >= runtime.ring_count() {
        return false;
    }
    // SAFETY: the index is in range, so the slot exists for this runtime.
    let context = unsafe { runtime.slot_context(ring_index) };
    // SAFETY: forwarded contract.
    unsafe {
        fail_unstored_parked_wait_at(
            context,
            fsring_abi::control::status::INVALID_DEVICE_STATE as u32,
        )
    }
}

unsafe fn fail_unstored_parked_wait_at(context: NonNull<PendingEnterContext>, status: u32) -> bool {
    let raw = context.as_ptr();
    // SAFETY: the CSQ takes and releases this slot's own lock itself, so it is
    // called with no hold outstanding.
    let removed = unsafe {
        IoCsqRemoveIrp(
            core::ptr::addr_of_mut!((*raw).csq),
            core::ptr::addr_of_mut!((*raw).csq_irp_context),
        )
    };
    let Some(observed) = IrpObservation::from_raw(removed as usize) else {
        return false;
    };
    // SAFETY: the queue released this IRP to this thread and nothing else can
    // reach it: no plan exists, so no completion pass can name it.
    unsafe { complete_parked_irp(observed, status, 0) };
    true
}

unsafe fn release_slot_sq_wait(context: NonNull<PendingEnterContext>, lease: SqWaitRoleLease) {
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    if let Some(runtime) = unsafe { (*raw).runtime.as_mut() } {
        runtime.release_park_role(lease);
    }
    unlock.release();
}

/// Reach the session's `PendingControlLedger` and unlink one completed install.
///
/// Mirrors `release_parked_strong_refs`: a brief hold of this slot's own lock
/// reads the session's registry pointer this install parked with, then the
/// actual mutation runs entirely under that registry's lock (never nested
/// with any per-ring lock, per 06-locking.md section 5.3's fixed order). If
/// the registry, cell, or ledger is gone -- the session is already tearing
/// down -- the affine right is simply dropped; it has no `Drop`, so the worst
/// case is the degenerate one a dying session already accepts elsewhere in
/// this file.
unsafe fn unlink_parked_control_link(
    context: NonNull<PendingEnterContext>,
    link: PendingControlLinkRight,
) {
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let registry = match unsafe { (*raw).runtime.as_ref() } {
        Some(runtime) => runtime.parked_strong_registry,
        None => core::ptr::null_mut(),
    };
    unlock.release();
    let Some(registry) = NonNull::new(registry) else {
        return;
    };
    let index = link.locator().slot_index();
    let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
    if let Some(cell) = unsafe { lock.cell_mut(index) } {
        if let Some(ledger) = cell.pending_ledger_mut() {
            let _ = ledger.unlink(link);
        }
    }
    unsafe { lock.release() };
}

/// Reach the session's `PendingControlLedger` and link one reserved install.
///
/// Mirrors [`unlink_parked_control_link`]: the caller must NOT hold this
/// slot's own lock -- this briefly takes it itself to read the session's
/// registry pointer, then the actual `link` call runs entirely under that
/// registry's lock alone, never nested with the per-ring lock, per
/// `06-locking.md` section 5.3's fixed order. This is the fix for the race
/// that same order forbids: the previous call site held only the per-ring
/// lock across `ledger.link()`, letting two concurrent parks on different
/// rings of one session alias the ledger's `&mut` with no synchronization.
unsafe fn link_parked_control(
    context: NonNull<PendingEnterContext>,
    install: PendingInstallId,
) -> Result<PendingControlLinkRight, PendingError> {
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let registry = match unsafe { (*raw).runtime.as_ref() } {
        Some(runtime) => runtime.parked_strong_registry,
        None => core::ptr::null_mut(),
    };
    unlock.release();
    let Some(registry) = NonNull::new(registry) else {
        return Err(PendingError::WrongSession);
    };
    let index = install.locator().slot_index();
    let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
    let result = match unsafe { lock.cell_mut(index) } {
        Some(cell) => match cell.pending_ledger_mut() {
            Some(ledger) => ledger.link(install),
            None => Err(PendingError::WrongSession),
        },
        None => Err(PendingError::WrongSession),
    };
    unsafe { lock.release() };
    result
}

/// Undo everything Phase A of `park_wait_enter` bound to `install`, after a
/// later phase refused. Acquires this slot's own lock itself; the caller
/// must not be holding it. Does not touch the control ledger -- callers that
/// reached Phase B successfully must call [`unlink_parked_control_link`]
/// separately, since that mutation has its own lock discipline.
///
/// By the time any caller reaches this, `schedule`/`owners`/`result_slot`
/// are all known bound: Phase A's own combined check already reversed a
/// partial failure among those three before ever calling this.
unsafe fn unwind_reserved_install(
    context: NonNull<PendingEnterContext>,
    install: PendingInstallId,
    lease: SqWaitRoleLease,
    installer: PendingOwnerToken,
    original_slot_state: PendingSlotState,
) {
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    if let Some(slot_runtime) = unsafe { (*raw).runtime.as_mut() } {
        let _ = slot_runtime.owners.release_owner(installer);
        let _ = slot_runtime.result_slot.vacate(install);
        let _ = slot_runtime.owners.unbind_install(install);
        let _ = slot_runtime.schedule.end_install(install);
        slot_runtime.release_park_role(lease);
        slot_runtime.install = None;
    }
    unsafe { (*raw).slot_state = original_slot_state };
    unsafe { (*raw).install_axis = None };
    unlock.release();
}

unsafe fn release_parked_strong_refs(context: NonNull<PendingEnterContext>) {
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let (reference, registry) = match unsafe { (*raw).runtime.as_mut() } {
        Some(runtime) => (runtime.parked_strong.take(), runtime.parked_strong_registry),
        None => (None, core::ptr::null_mut()),
    };
    unlock.release();
    let Some(reference) = reference else {
        return;
    };
    let Some(registry) = NonNull::new(registry) else {
        return;
    };
    let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };
    let _ = unsafe { lock.core_mut().release(reference) };
    unsafe { lock.release() };
}

// Bind both entry points to their generated callback aliases, in the same form
// the six CSQ callbacks above use. A shape that drifted fails here.
const _: PKDEFERRED_ROUTINE = Some(fsring_pending_enter_timer_dpc);
const _: PIO_WORKITEM_ROUTINE = Some(fsring_pending_enter_worker);

// The two timer DDIs this module binds, checked against the generated
// declarations rather than hand-declared. The event and work-item DDIs are
// already checked this way in `lib.rs`.
const _: unsafe extern "C" fn(PKTIMER) = KeInitializeTimer;
const _: unsafe extern "C" fn(PKDPC, PKDEFERRED_ROUTINE, PVOID) = KeInitializeDpc;

// ---------------------------------------------------------------------------
// R4 Task 18: the arena, and the prefix that is reversed over exactly what it
// built
// ---------------------------------------------------------------------------

/// The largest ring set a pending runtime is built for.
pub(crate) const MAX_PENDING_SLOTS: u32 = 64;

/// One nonpaged allocation backing a whole ring set's pending slots.
///
/// Allocated once, before any context is initialized. Neither the arena, one
/// context, nor the 64-context roster is ever returned by value on a kernel
/// stack: every accessor below hands out a pointer into the allocation this
/// owner holds.
pub(crate) struct PendingContextArenaOwner {
    base: NonNull<MaybeUninit<PendingEnterContext>>,
    result_storage: NonNull<u8>,
    result_stride: usize,
    capacity: u32,
    allocation: NonPagedAllocationOwner,
}

impl PendingContextArenaOwner {
    /// Allocate backing for `capacity` slots and their out-of-line results.
    ///
    /// # Safety
    /// PASSIVE setup, before any context exists.
    pub(crate) unsafe fn allocate_pending_arena(
        capacity: u32,
        result_stride: usize,
    ) -> Result<Self, NTSTATUS> {
        const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000D_u32 as NTSTATUS;
        if capacity == 0 || capacity > MAX_PENDING_SLOTS || result_stride == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let slots = capacity as usize;
        let Some(context_bytes) = core::mem::size_of::<PendingEnterContext>().checked_mul(slots)
        else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let Some(result_bytes) = result_stride.checked_mul(slots) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let Some(total) = context_bytes.checked_add(result_bytes) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        // SAFETY: PASSIVE setup with the fixed C4 pool tag and a checked size.
        let allocation =
            unsafe { NonPagedAllocationOwner::allocate(total, crate::kernel::POOL_TAG) }?;
        let (base, _bytes) = allocation.region();
        // SAFETY: `context_bytes` is inside the region just allocated, and the
        // contexts occupy exactly its first half by construction.
        let result_storage = unsafe { NonNull::new_unchecked(base.as_ptr().add(context_bytes)) };
        Ok(Self {
            base: base.cast::<MaybeUninit<PendingEnterContext>>(),
            result_storage,
            result_stride,
            capacity,
            allocation,
        })
    }

    pub(crate) const fn capacity(&self) -> u32 {
        self.capacity
    }

    /// The storage for one slot.
    ///
    /// # Safety
    /// `index < self.capacity`.
    unsafe fn slot_storage(&self, index: u32) -> NonNull<MaybeUninit<PendingEnterContext>> {
        // SAFETY: the caller's bound, and the allocation covers `capacity`
        // contexts by construction.
        unsafe { NonNull::new_unchecked(self.base.as_ptr().add(index as usize)) }
    }

    /// The out-of-line result backing for one slot.
    ///
    /// # Safety
    /// `index < self.capacity`.
    unsafe fn slot_result_storage(&self, index: u32) -> NonNull<u8> {
        // `saturating_mul` only ever runs under the caller's `index <
        // capacity` bound, and `allocate_pending_arena` already proved
        // `capacity * result_stride` does not overflow -- so this product is
        // strictly smaller than one the allocation was sized for.
        let offset = (index as usize).saturating_mul(self.result_stride);
        // SAFETY: as above, over the second half of the same allocation.
        unsafe { NonNull::new_unchecked(self.result_storage.as_ptr().add(offset)) }
    }

    /// # Safety
    /// Every context built in this arena has already been torn down and no
    /// pointer into the region remains.
    pub(crate) unsafe fn release_arena(self) {
        let Self {
            base: _,
            result_storage: _,
            result_stride: _,
            capacity: _,
            allocation,
        } = self;
        // SAFETY: the caller's contract, forwarded to the owner that allocated.
        unsafe { allocation.release() };
    }
}

/// Free the work items a rollback must reverse.
///
/// A trait so the free is the caller's DDI rather than this module reaching for
/// one directly, which is what lets a rollback be driven without a live I/O
/// manager.
pub(crate) trait PendingRuntimeDdi {
    /// # Safety
    /// `work_item` is one prefix-owned item allocated for the permanent
    /// provider and has not been freed or queued after rollback began.
    unsafe fn free_pending_work_item(&mut self, work_item: PIO_WORKITEM);
}

/// The production free.
pub(crate) struct NativePendingRuntimeDdi;

impl PendingRuntimeDdi for NativePendingRuntimeDdi {
    unsafe fn free_pending_work_item(&mut self, work_item: PIO_WORKITEM) {
        // SAFETY: the trait's contract: an allocated, unqueued item.
        unsafe { IoFreeWorkItem(work_item) };
    }
}

/// A partially built pending runtime: the arena, and exactly how much of it is
/// live.
///
/// The cursor is `fsring-core`'s, which is where the two rules that matter
/// live: readiness requires *every* ring and the caller agreeing which set it
/// is, and a rollback reverses the exact initialized prefix, highest index
/// first. A forward rollback would free the arena's first work item while later
/// contexts still referenced it.
/// The prefix deliberately does **not** carry the set brand.
///
/// Task 13's `SessionRingSetInitializer` mints every ring's one-shot bind right
/// *before* `finish` seals the set, so a builder that needed the sealed brand up
/// front would have nowhere to put the rights it was already holding. Moving the
/// brand to `finish_pending_runtime` is what removes the cycle, and it does not
/// weaken anything: readiness now proves *both* that the initialized prefix is
/// complete for the caller's ring count **and** that every slot it built belongs
/// to the exact set the caller is about to publish under.
pub(crate) struct PendingRuntimePrefix {
    arena: PendingContextArenaOwner,
    cursor: PendingRuntimeInitCursor,
    provider: PDEVICE_OBJECT,
}

/// The one exclusive borrow that initializes one slot.
///
/// It retains the prefix borrow, so a caller commits through this guard rather
/// than borrowing the prefix again; every refusal returns the still-owning
/// guard with the prefix unmutated.
pub(crate) struct PendingContextInit<'prefix> {
    prefix: &'prefix mut PendingRuntimePrefix,
    index: u32,
}

/// A complete pending runtime, and the proof that made it one.
pub(crate) struct PendingRuntimeReady {
    prefix: PendingRuntimePrefix,
    ring_set: SessionRingSetBrand,
    proof: PendingRuntimeReadyProof,
}

// The plan's bounds, checked rather than asserted in prose. A field added later
// that pushes any of them past its limit stops the build.
const _: () = {
    assert!(core::mem::size_of::<PendingRuntimePrefix>() <= 256);
    assert!(core::mem::size_of::<PendingRuntimeReady>() <= 256);
    assert!(core::mem::size_of::<PendingContextInit<'static>>() <= 64);
    // The arena hands out `PendingEnterContext` storage at the pool's
    // guaranteed alignment, so the type must not need more than that.
    assert!(core::mem::align_of::<PendingEnterContext>() <= 16);
};

impl PendingRuntimePrefix {
    /// Begin one initialization over an already allocated arena.
    ///
    /// A refusal returns the arena, because the caller then has to free
    /// something this function did not consume.
    pub(crate) fn begin_pending_runtime(
        arena: PendingContextArenaOwner,
        provider: PDEVICE_OBJECT,
    ) -> Result<Self, (PendingError, PendingContextArenaOwner)> {
        match PendingRuntimeInitCursor::begin(arena.capacity()) {
            Ok(cursor) => Ok(Self {
                arena,
                cursor,
                provider,
            }),
            Err(error) => Err((error, arena)),
        }
    }

    /// Take the guard for the next uninitialized slot, or `None` once covered.
    pub(crate) fn next_uninitialized(&mut self) -> Option<PendingContextInit<'_>> {
        let index = self.cursor.next_uninitialized_index()?;
        Some(PendingContextInit {
            prefix: self,
            index,
        })
    }

    /// Readiness requires every ring, the caller agreeing which set it is, and
    /// every built slot belonging to that exact set.
    ///
    /// The third check is the one the brand move bought. The cursor can only
    /// count; it cannot tell a slot built from *this* set's rights from one
    /// built from a predecessor set of the same session, and a runtime whose
    /// slots named a retired set would be addressed by installs that never
    /// reach them.
    pub(crate) fn finish_pending_runtime(
        self,
        ring_set: SessionRingSetBrand,
    ) -> Result<PendingRuntimeReady, (PendingError, Self)> {
        let proof = match self.cursor.finish(ring_set.ring_count()) {
            Ok(proof) => proof,
            Err((error, _)) => return Err((error, self)),
        };
        let mut index = 0u32;
        while index < ring_set.ring_count() {
            // SAFETY: the cursor just proved every index below `ring_count` was
            // initialized through this prefix's own guard.
            let slot = unsafe { self.arena.slot_storage(index) };
            let raw = slot.as_ptr().cast::<PendingEnterContext>();
            // SAFETY: as above; the borrow ends inside this iteration.
            let brand = unsafe { (*raw).runtime.as_ref() }.map(PendingSlotRuntime::ring_brand);
            let Some(brand) = brand else {
                return Err((PendingError::WrongSession, self));
            };
            if !ring_set.contains_brand(brand) {
                return Err((PendingError::WrongSession, self));
            }
            index = index.saturating_add(1);
        }
        Ok(PendingRuntimeReady {
            prefix: self,
            ring_set,
            proof,
        })
    }

    /// Reverse exactly the initialized prefix, then free the arena.
    ///
    /// Each context is invalidated before its work item is freed, so a stale
    /// queue attempt cannot reach a freed item through a field this walk has
    /// already passed.
    ///
    /// # Safety
    /// No callback of any slot in this prefix is running or can be started:
    /// none was ever registered and no timer was ever armed.
    pub(crate) unsafe fn rollback_pending_runtime(self, ddi: &mut impl PendingRuntimeDdi) {
        let Self {
            arena,
            cursor,
            provider: _,
        } = self;
        let mut span = cursor.rollback_span();
        while let Some((index, rest)) = span.next_reverse() {
            // SAFETY: the span yields only indices this prefix initialized, and
            // every one of those is below the arena's capacity.
            let slot = unsafe { arena.slot_storage(index) };
            let raw = slot.as_ptr().cast::<PendingEnterContext>();
            // SAFETY: the slot was fully initialized before it was counted.
            let work_item = unsafe { (*raw).work_item };
            // Invalidate first: after this the context names no work item, so
            // the free below cannot be repeated through the field.
            //
            // `runtime` is deliberately NOT cleared, and that is not an
            // omission. Clearing it would drop the `PendingSlotRuntime`, and a
            // runtime holding a parked `QueueWorkRight` bugchecks on drop by
            // design — the right exists to make "queued but never queued" loud.
            // The slot's values own no allocation, so leaving them unrun in pool
            // memory that is about to be freed costs nothing and cannot fire a
            // destructor whose whole purpose is to be unreachable here.
            // SAFETY: as above, and no callback can observe this slot.
            unsafe {
                (*raw).work_item = core::ptr::null_mut();
                (*raw).result_view = core::ptr::null_mut();
                (*raw).timer_state = TimerState::Quiesced;
                (*raw).irp = core::ptr::null_mut();
                (*raw).irp_axis = None;
                (*raw).install_axis = None;
                (*raw).control_context = core::ptr::null_mut();
            }
            if !work_item.is_null() {
                // SAFETY: the item was allocated for the permanent provider,
                // was never queued, and this is its only free.
                unsafe { ddi.free_pending_work_item(work_item) };
            }
            span = rest;
        }
        // SAFETY: every context built here has just been torn down, and the
        // loop retained no pointer into the region.
        unsafe { arena.release_arena() };
    }
}

impl PendingContextInit<'_> {
    /// The out-of-line result backing for this slot.
    ///
    /// # Safety
    /// Used only to write this slot's result storage in place.
    pub(crate) unsafe fn slot_result_view(&self) -> NonNull<u8> {
        // SAFETY: `index` came from the cursor, so it is below capacity.
        unsafe { self.prefix.arena.slot_result_storage(self.index) }
    }

    /// Initialize this slot in place, allocating its one work item and giving
    /// it the core runtime built from this ring's one-shot bind right.
    ///
    /// The right is consumed only on the success path: every refusal hands it
    /// straight back, because a caller that lost it could neither retry this
    /// ring nor abort the set cleanly -- the right is the only thing that
    /// speaks for the ring.
    ///
    /// # Safety
    /// PASSIVE setup. No other thread can observe this slot yet.
    pub(crate) unsafe fn initialize_pending_context(
        &mut self,
        cq_bind: CqStorageBindRight,
        result_capacity: usize,
    ) -> Result<(), (NTSTATUS, CqStorageBindRight)> {
        const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000_009A_u32 as NTSTATUS;
        const STATUS_INVALID_DEVICE_STATE: NTSTATUS = 0xC000_0184_u32 as NTSTATUS;
        // The two native steps run first *because* they can refuse without
        // touching the right at all. Building the core runtime first would put
        // the right beyond reach of the two refusals most likely to happen.
        // SAFETY: `index` came from the cursor, so it is below capacity, and
        // the arena's storage for it is uninitialized and exclusively ours.
        let slot = unsafe { self.prefix.arena.slot_storage(self.index) };
        let raw = slot.as_ptr().cast::<PendingEnterContext>();
        // SAFETY: the caller's contract, forwarded. This publishes the CSQ, so
        // it happens before the work item is attached to the same slot.
        if let Err(status) = unsafe { initialize_staged_pending_slot(NonNull::new_unchecked(raw)) }
        {
            return Err((status, cq_bind));
        }
        // SAFETY: the permanent provider outlives every session's runtime.
        let work_item = unsafe { IoAllocateWorkItem(self.prefix.provider) };
        if work_item.is_null() {
            return Err((STATUS_INSUFFICIENT_RESOURCES, cq_bind));
        }
        // SAFETY: exclusive, initialized storage; nothing observes it yet, and
        // `index` came from the cursor so the arena reserved this slot's share
        // of the out-of-line result region for it.
        unsafe {
            (*raw).work_item = work_item;
            (*raw).result_view = self.slot_result_view().as_ptr();
        }
        // The last fallible step. A refusal here owns the one thing this frame
        // allocated, so it frees the work item and clears the field before
        // handing the right back: the slot is not counted yet, so the prefix
        // rollback would never reach it, and a leak here is a permanent one.
        let parts = match build_pending_slot_parts(cq_bind, result_capacity) {
            Ok(parts) => parts,
            Err((_, cq_bind)) => {
                // SAFETY: exclusive storage that nothing observes, and the item
                // was allocated by this frame and never queued.
                unsafe {
                    (*raw).work_item = core::ptr::null_mut();
                    NativePendingRuntimeDdi.free_pending_work_item(work_item);
                }
                return Err((STATUS_INVALID_DEVICE_STATE, cq_bind));
            }
        };
        // SAFETY: as above; the slot is still exclusively this frame's.
        unsafe {
            (*raw).runtime = Some(PendingSlotRuntime::from_parts(parts));
        }
        Ok(())
    }

    /// Record that this slot is live.
    ///
    /// # Safety
    /// The exact slot and its out-of-line result storage were fully initialized
    /// in place through this guard, and no reference to either remains.
    /// Validation happens before the cursor moves; a refusal returns this same
    /// guard with the prefix unchanged.
    pub(crate) unsafe fn commit_pending_context(self) -> Result<(), (PendingError, Self)> {
        match self.prefix.cursor.record_initialized() {
            Ok(cursor) => {
                self.prefix.cursor = cursor;
                Ok(())
            }
            Err((error, _)) => Err((error, self)),
        }
    }
}

impl PendingRuntimeReady {
    pub(crate) const fn ring_count(&self) -> u32 {
        self.proof.ring_count()
    }

    pub(crate) const fn staged_ring_set(&self) -> SessionRingSetBrand {
        self.ring_set
    }

    /// Queue one slot's PASSIVE worker.
    ///
    /// Present so the work item this runtime allocated has exactly one queue
    /// site, with the `DelayedWorkQueue` value the plan fixes. It has six
    /// callers on this tree -- the two completion-loop sites and the four
    /// rearm/retry sites in the worker -- so the single queue site is a
    /// property of this function, not of the count of its callers.
    ///
    /// This doc used to read "Task 19 gives it a caller; today the staging gate
    /// proves it has none." Task 19 closed, the callers arrived, and the gate it
    /// named is retired and FAILs by design.
    ///
    /// # Safety
    /// `index < self.ring_count()`, the caller holds a
    /// `fsring_core::enter::QueueWorkRight` for this slot's install, and it has
    /// already left the slot lock.
    pub(crate) unsafe fn queue_pending_worker(&self, index: u32) {
        // SAFETY: the caller's bound.
        let slot = unsafe { self.prefix.arena.slot_storage(index) };
        let raw = slot.as_ptr().cast::<PendingEnterContext>();
        // SAFETY: every slot of a ready runtime carries its work item.
        let work_item = unsafe { (*raw).work_item };
        // SAFETY: the item is this slot's, is not queued, and the routine is
        // this module's own.
        unsafe {
            IoQueueWorkItem(
                work_item,
                Some(fsring_pending_enter_worker),
                DelayedWorkQueue,
                raw.cast::<c_void>(),
            );
        }
    }

    /// The permanent address of one slot's context.
    ///
    /// # Safety
    /// `index < self.ring_count()`.
    pub(crate) unsafe fn slot_context(&self, index: u32) -> NonNull<PendingEnterContext> {
        // SAFETY: the caller's bound, and every slot below the ring count was
        // initialized before readiness was minted.
        let slot = unsafe { self.prefix.arena.slot_storage(index) };
        // SAFETY: the storage is initialized, so the cast is to a live context.
        unsafe { NonNull::new_unchecked(slot.as_ptr().cast::<PendingEnterContext>()) }
    }

    /// Deposit one Fence wake in every installed context.
    ///
    /// The roster's `SignalPendingEnter`. A context that is still `Installing`
    /// stores the reason and cannot schedule; an installed one produces the one
    /// `QueueWorkRight` this slot owes, which is parked in the slot until
    /// `QueueInstalledWork` performs the queue DDI outside the lock.
    ///
    /// Every ring is offered its wake before the refusal is reported: returning
    /// at the first one left every higher ring with no Fence wake at all, which
    /// is the same shape the readiness sweep was repaired for and one function
    /// away from it.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held; the runtime is still installed.
    pub(crate) unsafe fn deposit_fence_wakes(&self) -> bool {
        let mut refused = false;
        let mut index = 0u32;
        while index < self.ring_count() {
            // SAFETY: the loop bound is the ring count.
            let context = unsafe { self.slot_context(index) };
            let raw = context.as_ptr();
            // SAFETY: the lock is initialized before the CSQ is published.
            let old_irql =
                unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
            // SAFETY: paired with the acquire; released on every path below.
            let unlock = unsafe {
                PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
            };
            // SAFETY: exclusive under the hold.
            let deposited = match unsafe { (*raw).runtime.as_mut() } {
                Some(runtime) => runtime.deposit_locked_wake(PendingReason::Fence),
                // A ready runtime gave every slot below the ring count its
                // parts, so this arm is a shape violation rather than an
                // ordinary absence.
                None => false,
            };
            unlock.release();
            if !deposited {
                refused = true;
            }
            index = index.saturating_add(1);
        }
        !refused
    }

    /// Deposit a Readiness wake into every parked WAIT whose SQ is ready, and
    /// queue the PASSIVE worker immediately. This is the producer doorbell:
    /// mapped SQ writes are visible on the next session ENTER, which polls
    /// cursors here.
    ///
    /// # Safety
    /// PASSIVE_LEVEL; `session` is the published shell this runtime belongs to.
    pub(crate) unsafe fn deposit_readiness_wakes(
        &self,
        session: *const crate::session::NativeSession,
    ) -> bool {
        if session.is_null() {
            return false;
        }
        let mut refused = false;
        let mut index = 0u32;
        while index < self.ring_count() {
            let ready = unsafe { (*session).sq_cursors(index) }
                .is_some_and(|(produced, consumed)| produced != consumed);
            if ready {
                let context = unsafe { self.slot_context(index) };
                let raw = context.as_ptr();
                let old_irql =
                    unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
                let unlock = unsafe {
                    PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
                };
                // A refused deposit is this ring's problem, not the sweep's.
                // Returning here abandoned every higher ring, and since this is
                // the only readiness producer, those rings then had no path to
                // a readiness wake at all. The refusal is carried out as a
                // false result after every ring has been offered its wake.
                let right = match unsafe { (*raw).runtime.as_mut() } {
                    Some(runtime) => {
                        if runtime.deposit_locked_wake(PendingReason::Readiness) {
                            runtime.queue_right.take()
                        } else {
                            refused = true;
                            None
                        }
                    }
                    None => None,
                };
                unlock.release();
                if let Some(right) = right {
                    unsafe {
                        self.queue_pending_worker(index);
                        right.commit_after_work_queued();
                    }
                }
            }
            index = index.saturating_add(1);
        }
        !refused
    }

    /// Turn each parked obligation into at most one queued worker pass.
    ///
    /// The queue DDI runs *outside* the slot lock, which is the whole reason
    /// the deposit and the queue are two roster entries.
    ///
    /// # Safety
    /// As `deposit_fence_wakes`.
    pub(crate) unsafe fn queue_installed_work(&self) -> bool {
        let mut index = 0u32;
        while index < self.ring_count() {
            // SAFETY: the loop bound is the ring count.
            let context = unsafe { self.slot_context(index) };
            let raw = context.as_ptr();
            // SAFETY: as above.
            let old_irql =
                unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
            // SAFETY: paired with the acquire.
            let unlock = unsafe {
                PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql)
            };
            // SAFETY: exclusive under the hold.
            let right = match unsafe { (*raw).runtime.as_mut() } {
                Some(runtime) => runtime.queue_right.take(),
                None => return false,
            };
            unlock.release();
            if let Some(right) = right {
                // SAFETY: the lock is released, `index` is below the ring
                // count, and this is the one queue call the right stands for.
                unsafe {
                    self.queue_pending_worker(index);
                    right.commit_after_work_queued();
                }
            }
            index = index.saturating_add(1);
        }
        true
    }

    /// Observe every context, and refuse rather than call anything drained that
    /// is not.
    ///
    /// `WaitPendingAndOwners`. Observation alone cannot mint success: a context
    /// that reports `Active` or a parked publication refuses the whole roster
    /// entry, and a refused checkpoint parks instead of deleting the session
    /// underneath its own still-parked IRP.
    ///
    /// It *waits*: the Fence wake is deposited and the worker queued two roster
    /// rows earlier, so a context can be legitimately Active with a pass queued
    /// and not yet running, and refusing that would park a session whose worker
    /// was about to complete it. `PendingDrainWait` owns how many times and what
    /// may never be retried; this body owns only the delay between looks.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no registry lock held; this row blocks.
    pub(crate) unsafe fn wait_contexts_drained(&self) -> bool {
        let mut index = 0u32;
        while index < self.ring_count() {
            // SAFETY: the loop bound is the ring count.
            let context = unsafe { self.slot_context(index) };
            let mut wait = PendingDrainWait::begin_drain_wait();
            loop {
                // SAFETY: the session is still resident: the checkpoint that is
                // asking has not released its backing.
                let step = match unsafe { observe_pending_for_unload(context) } {
                    PendingUnloadObservation::Drained => wait.observed_drained(),
                    PendingUnloadObservation::Active(_) => wait.observed_active(),
                    PendingUnloadObservation::PublicationFailStop(_) => {
                        wait.observed_publication_fail_stop()
                    }
                };
                match step {
                    PendingDrainStep::Drained => break,
                    // A fail-stop refuses as a fail-stop and an exhausted budget
                    // as an exhausted budget; both park the generation, and
                    // neither can become a drained proof.
                    PendingDrainStep::Refused(_) => return false,
                    PendingDrainStep::Observe(next) => {
                        wait = next;
                        // SAFETY: PASSIVE_LEVEL, no lock held, and the interval
                        // is a relative one on this frame. This is the only
                        // thing this body decides; the budget is core's.
                        unsafe { delay_one_drain_interval() };
                    }
                }
            }
            index = index.saturating_add(1);
        }
        true
    }

    /// Reverse the whole runtime after every context is drained.
    ///
    /// Every timer is cancelled and every in-flight DPC waited out FIRST, and
    /// that is not belt over brace. `wait_contexts_drained` proves no *install*
    /// is outstanding by reading `slot_state`, which says nothing at all about
    /// `timer_state`: a `Vacant` or `EpochExhausted` slot reports `Drained`
    /// whether or not a KDPC is queued against it. The arena freed below is
    /// exactly where that KDPC, its KTIMER and its exit event live, and neither
    /// `KeRemoveQueueDpc` nor `KeFlushQueuedDpcs` exists anywhere in this image
    /// to catch it afterwards. `rollback_pending_runtime` even *assigns*
    /// `TimerState::Quiesced` -- bookkeeping on memory it is about to free --
    /// and its safety contract ("no timer was ever armed") is written for the
    /// setup-rollback caller, where it is true, and was forwarded verbatim to
    /// this one, where it is not.
    ///
    /// # Safety
    /// PASSIVE_LEVEL with no lock held. No install of any slot is outstanding:
    /// the checkpoint's `WaitPendingAndOwners` reported every context drained,
    /// and admission is closed.
    pub(crate) unsafe fn release_pending_runtime(self, ddi: &mut impl PendingRuntimeDdi) {
        let mut index = 0u32;
        while index < self.ring_count() {
            // SAFETY: the loop bound is the ring count, and the arena is still
            // resident -- this runs before the rollback below.
            let context = unsafe { self.slot_context(index) };
            // SAFETY: PASSIVE_LEVEL with no lock held, per this function's own
            // contract.
            unsafe { quiesce_pending_timer_for_teardown(context) };
            index = index.saturating_add(1);
        }
        let Self {
            prefix,
            ring_set: _,
            proof: _,
        } = self;
        // SAFETY: the loop above made this call's contract true rather than
        // assuming it: no timer of any slot is armed and no DPC is in flight.
        unsafe { prefix.rollback_pending_runtime(ddi) };
    }
}

/// Cancel one slot's timer and rendezvous with a DPC it has already queued.
///
/// Unload's last chance to make "no callback is running or can be started" a
/// fact rather than a comment. The epoch is read out of the state here, and
/// that is deliberately not the self-authentication `cancel_pending_timer` was
/// repaired for: admission is closed and every install is drained, so this
/// frame is the only generation there is and there is no other epoch it could
/// be confused with. A `NotThisInstall` refusal here would be a frame declining
/// to clean up the only timer in existence.
///
/// A dequeued timer leaves its Dpc owner held, and that is deliberate: unlike
/// `cancel_pending_timer`, nothing after this will read the ledger. The runtime
/// is not dropped by the rollback below -- see its own comment on why -- and
/// the arena that holds both is freed whole.
///
/// # Safety
/// PASSIVE_LEVEL with no lock held; `context` is a live initialized slot whose
/// arena has not been released.
unsafe fn quiesce_pending_timer_for_teardown(context: NonNull<PendingEnterContext>) {
    let raw = context.as_ptr();
    // SAFETY: the lock is initialized before the timer can be armed.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: read under the hold.
    let epoch = unsafe { (*raw).timer_state }.epoch();
    unlock.release();
    let Some(epoch) = epoch else {
        // Already `Quiesced`, which is NOT the same as "no DPC is touching this
        // arena". `dpc_exiting` publishes `Quiesced` inside the lock and the
        // DPC stores into `dpc_exited` after releasing it, so a teardown that
        // stopped here could free the event out from under that store.
        // SAFETY: PASSIVE_LEVEL with no lock held.
        unsafe { wait_pending_dpc_exit_signal(context) };
        return;
    };
    // SAFETY: the DDI is callable at or below DISPATCH_LEVEL and the timer
    // object is this slot's own. Outside the lock: it may synchronise with a
    // DPC that takes the same lock.
    let dequeued = unsafe { fsring_sys::c4::KeCancelTimer(core::ptr::addr_of_mut!((*raw).timer)) };
    // SAFETY: as above.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: exclusive under the hold.
    let outcome = unsafe { (*raw).timer_state.cancel(epoch, dequeued != 0) };
    unlock.release();
    if matches!(outcome, PendingTimerCancel::RequiresDpcExitWait) {
        // SAFETY: PASSIVE_LEVEL with no lock held. The DPC signals its exit and
        // publishes `Quiesced`, which is what this returns on. The cancel
        // above answered FALSE, so this frame is entitled to wait on `Armed`.
        unsafe { wait_pending_dpc_exit(context) };
    }
    // The rendezvous returns on an observed `Quiesced`, which the DPC publishes
    // one store before it is finished with this arena. Only the signal itself
    // proves that store has happened.
    // SAFETY: PASSIVE_LEVEL with no lock held.
    unsafe { wait_pending_dpc_exit_signal(context) };
}

/// Wait for a DPC that has already published `Quiesced` to make its last store.
///
/// The rendezvous above returns on the state, and the state goes to `Quiesced`
/// inside the lock while `KeSetEvent(dpc_exited)` happens after the release.
/// Between those two the DPC still owns one store into an arena unload is about
/// to free. `dpc_entered` says whether such a store is owed at all: waiting
/// unconditionally would block forever on a slot whose timer was never armed,
/// because nothing would ever set the event.
///
/// `dpc_exited` is a NotificationEvent, so if the store already happened this
/// returns at once.
///
/// # Safety
/// PASSIVE_LEVEL with no lock held; `context` is a live initialized slot whose
/// arena has not been released.
unsafe fn wait_pending_dpc_exit_signal(context: NonNull<PendingEnterContext>) {
    let raw = context.as_ptr();
    // SAFETY: the lock is initialized before the timer can be armed.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: read under the hold.
    let owed = unsafe { (*raw).dpc_entered };
    unlock.release();
    if !owed {
        return;
    }
    // SAFETY: `dpc_exited` is initialized before the DPC can be armed, no lock
    // is held, and the caller is PASSIVE. A DPC that entered always reaches its
    // `KeSetEvent`, so this is bounded by that store.
    let _status = unsafe {
        fsring_sys::c4::KeWaitForSingleObject(
            core::ptr::addr_of_mut!((*raw).dpc_exited).cast(),
            0,
            0,
            0 as BOOLEAN,
            core::ptr::null_mut(),
        )
    };
}

/// Sleep one drain-observation interval.
///
/// The only thing `wait_contexts_drained` decides for itself. How many times to
/// look, and what may never be looked at twice, is `PendingDrainWait`'s and is
/// host-tested; this is the part that needs a kernel and cannot be.
///
/// A relative 100-microsecond interval: negative means relative in the DDI's
/// units, and 100 us against a 1024-observation budget bounds the whole wait at
/// about a tenth of a second per context — long enough for a queued worker pass
/// to be scheduled and run, short enough that a stuck context does not hold the
/// terminal thread while unload waits behind it.
///
/// # Safety
/// PASSIVE_LEVEL with no lock held: this blocks the calling thread.
unsafe fn delay_one_drain_interval() {
    let mut interval = LARGE_INTEGER {
        QuadPart: -1_000_i64,
    };
    // The returned status is deliberately discarded and the DDI is `must_use`,
    // so the discard is explicit. A non-alertable `KernelMode` delay has exactly
    // one outcome — the interval elapsed — and there is nothing a caller could
    // decide differently on it. `STATUS_ALERTED`/`STATUS_USER_APC` are the two
    // statuses that would carry information, and both require `Alertable`, which
    // this call passes `FALSE` for.
    //
    // SAFETY: the caller's contract. `KernelMode`/non-alertable is the only
    // shape a driver worker may sleep in, and the interval lives on this frame
    // for the whole synchronous call.
    let _elapsed = unsafe {
        fsring_sys::c4::KeDelayExecutionThread(0, 0 as BOOLEAN, core::ptr::addr_of_mut!(interval))
    };
}

/// Convert a finite WAIT timeout into the exact due time, or refuse.
///
/// The conversion is core's `finite_due_time_100ns`; this only wraps it in the
/// `LARGE_INTEGER` the DDI takes. Overflow returns `None` so the caller
/// terminalizes BEFORE arming: a wrapped due time is a timer that fires
/// immediately or never.
pub(crate) fn finite_due_time(milliseconds: u32) -> Option<LARGE_INTEGER> {
    let hundred_ns = fsring_core::enter::finite_due_time_100ns(milliseconds)?;
    Some(LARGE_INTEGER {
        QuadPart: hundred_ns,
    })
}

/// Park one WAIT ENTER on this ring's exclusive CSQ.
///
/// Every refusal happens before `IoCsqInsertIrp`. After insert the IRP belongs
/// to the queue (or to the cancel callback) and this function returns success
/// so the outer thunk will not complete it.
///
/// Three phases, not one critical section, because the control-ledger link
/// may not run under this slot's own lock (see [`link_parked_control`]):
///
/// - **Phase A** (this slot's lock): reserve the install, bind
///   schedule/owners/result-slot to it, and publish `slot_state`,
///   `install_axis` and `slot_runtime.install` -- together, because
///   `observe_pending_for_unload` panics on an `Installing` slot naming no
///   install. Publishing here rather than at the end is what keeps "at most
///   one install per ring" true while this slot's lock is released below:
///   a concurrent second park on this exact ring now reads `Installing` at
///   `decide_pending_park` and refuses before it could reach
///   `reserve_pending_install` itself.
/// - **Phase B** (no lock held here; the registry lock alone, inside
///   [`link_parked_control`]): link into the session's control ledger.
/// - **Phase C** (this slot's lock, re-acquired): arbitrate the park and
///   store the authorities Phase A deliberately left absent (`arbiter`,
///   `control_link`, `parked_role`) -- every reader of them
///   (`begin_pass`, `take_completion_authorities`) already checks each
///   independently and defers rather than assumes, so the gap between
///   Phase A's publish and Phase C's store is not a new race, it is the
///   ordinary "wake before the plan is fully installed" deferral this file
///   already relies on elsewhere.
///
/// # Safety
/// PASSIVE_LEVEL. `runtime` is this session's published pending runtime,
/// `ring_index` is inside the topology, and `irp` is the live METHOD_BUFFERED
/// ENTER that this dispatch has not completed.
pub(crate) unsafe fn park_wait_enter(
    runtime: &PendingRuntimeReady,
    ring_index: u32,
    irp: PIRP,
    timeout_ms: u32,
) -> Result<(), NTSTATUS> {
    const STATUS_INVALID_DEVICE_STATE: NTSTATUS = 0xC000_0184_u32 as NTSTATUS;
    const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000D_u32 as NTSTATUS;

    if ring_index >= runtime.ring_count() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let Some(observed) = IrpObservation::from_raw(irp as usize) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let due = if timeout_ms == 0 || timeout_ms == u32::MAX {
        None
    } else {
        Some(finite_due_time(timeout_ms).ok_or(STATUS_INVALID_PARAMETER)?)
    };

    // SAFETY: `ring_index` was just bounded by `ring_count`.
    let context = unsafe { runtime.slot_context(ring_index) };
    let raw = context.as_ptr();

    // ---- Phase A ----
    // SAFETY: the lock is initialized before the CSQ is published.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire; released on every path below.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };

    // SAFETY: exclusive under the hold.
    let original_slot_state = unsafe { (*raw).slot_state };
    if !matches!(
        decide_pending_park(original_slot_state),
        PendingParkDecision::Install
    ) {
        unlock.release();
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    let Some(slot_runtime) = (unsafe { (*raw).runtime.as_mut() }) else {
        unlock.release();
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let brand = slot_runtime.ring_brand();
    let (reserved, install) = match reserve_pending_install(brand, original_slot_state) {
        Ok(pair) => pair,
        Err(_) => {
            unlock.release();
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
    };
    let Some(epoch) = reserved.epoch() else {
        unlock.release();
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    let (lease, terminal) = match slot_runtime.acquire_park_role() {
        Ok(pair) => pair,
        Err(_) => {
            unlock.release();
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
    };
    // Bound to the lease before it moves into the slot: the arbiter carries the
    // lease's execution brand, so one minted here cannot serve a later
    // invocation of the same ring.
    let arbiter = PendingIrpArbiter::bind(&lease);
    // The result slot is claimed for this install here, with the schedule and
    // the owner ledger, because `commit_final_publication` refuses unless the
    // slot names the install it is completing. Without this claim every parked
    // WAIT completes its IRP and then parks a permanent refusal packet, which
    // blocks drain, delete and unload for the whole session. The commit clears
    // `install` again on success, so this is the only half that was missing.
    //
    // Attempted in order rather than short-circuited on a combined `||`: the
    // original combined check left whichever of the three succeeded before
    // the first failure bound to this install forever, so the *next* park on
    // this ring refused at `SlotOccupied` permanently. Each `_ok` tracks
    // exactly what this attempt actually bound, so the failure branch below
    // reverses only that -- never a step this attempt never reached.
    let schedule_ok = slot_runtime.schedule.begin_install(install).is_ok();
    let owners_ok = schedule_ok && slot_runtime.owners.bind_install(install).is_ok();
    let occupy_ok = owners_ok && slot_runtime.result_slot.occupy(install).is_ok();
    if !occupy_ok {
        if owners_ok {
            let _ = slot_runtime.owners.unbind_install(install);
        }
        if schedule_ok {
            let _ = slot_runtime.schedule.end_install(install);
        }
        slot_runtime.release_park_role(lease);
        unlock.release();
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    let installer = match slot_runtime
        .owners
        .acquire_owner(install, PendingOwnerKind::Installer)
    {
        Ok(token) => token,
        Err(_) => {
            let _ = slot_runtime.result_slot.vacate(install);
            let _ = slot_runtime.owners.unbind_install(install);
            let _ = slot_runtime.schedule.end_install(install);
            slot_runtime.release_park_role(lease);
            unlock.release();
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
    };
    slot_runtime.install = Some(install);
    unsafe { (*raw).slot_state = reserved };
    unsafe { (*raw).install_axis = Some(InstallAxis::Installing) };
    unlock.release();

    // ---- Phase B ----
    // SAFETY: no per-ring lock is held here; the caller's contract, forwarded.
    let link = match unsafe { link_parked_control(context, install) } {
        Ok(link) => link,
        Err(_) => {
            // SAFETY: `install` was reserved by this call and nothing else
            // has raced its epoch (Phase A published `Installing` before
            // releasing the lock above), so it is still this call's alone
            // to unwind.
            unsafe {
                unwind_reserved_install(context, install, lease, installer, original_slot_state)
            };
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
    };

    // ---- Phase C ----
    // SAFETY: as Phase A's acquire; nothing wrote `slot_state` between the
    // release above and here, because `decide_pending_park` refuses a second
    // park while it reads `Installing` and no other path writes it.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let Some(slot_runtime) = (unsafe { (*raw).runtime.as_mut() }) else {
        unlock.release();
        // SAFETY: no per-ring lock is held here.
        unsafe { unlink_parked_control_link(context, link) };
        unsafe { unwind_reserved_install(context, install, lease, installer, original_slot_state) };
        return Err(STATUS_INVALID_DEVICE_STATE);
    };
    // Park BEFORE the insert. The cancel callback can run the instant
    // `IoCsqInsertIrp` returns, and it mints its receipt through this arbiter;
    // parking afterwards would leave that callback contending with an arbiter
    // that has nothing parked.
    let mut arbiter = arbiter;
    if arbiter.park(install, observed, terminal).is_err() {
        unlock.release();
        // SAFETY: no per-ring lock is held here.
        unsafe { unlink_parked_control_link(context, link) };
        unsafe { unwind_reserved_install(context, install, lease, installer, original_slot_state) };
        return Err(STATUS_INVALID_DEVICE_STATE);
    }
    slot_runtime.parked_role = Some(lease);
    slot_runtime.arbiter = Some(arbiter);
    slot_runtime.control_link = Some(link);
    unlock.release();

    // SAFETY: every owner is published; the DDI marks the IRP pending.
    unsafe {
        IoCsqInsertIrp(
            core::ptr::addr_of_mut!((*raw).csq),
            irp,
            core::ptr::addr_of_mut!((*raw).csq_irp_context),
        );
    }
    let _outcome = unsafe { observe_insert_outcome(context) };

    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let Some(slot_runtime) = (unsafe { (*raw).runtime.as_mut() }) else {
        unlock.release();
        return Ok(());
    };
    // SAFETY: the outer thunk selected Pending for this exact install and IRP.
    let selected = unsafe { select_pending_install(install, observed) };
    let queue = match commit_pending_handoff(
        selected,
        installer,
        &mut slot_runtime.schedule,
        &mut slot_runtime.wake,
        &mut slot_runtime.owners,
        &mut slot_runtime.worker_owner,
    ) {
        Ok(PendingHandoffCommit::Queue(queued)) => Some(queued),
        Ok(PendingHandoffCommit::Ready(_)) => None,
        // Round-16 N16-3. This arm was collapsed with `Ready`, which is the one
        // outcome it is not: `Ready` means the handoff COMMITTED and owes no
        // queue call, while `Err` means it did not happen at all. Collapsed, the
        // refusal dropped the `PendingOwnerToken` it hands back and then fell
        // through to publish `handoff_done()` and `InstallAxis::HandoffDone` --
        // announcing a transition that never occurred, on a slot whose IRP is
        // already in the CSQ.
        //
        // None of `commit_pending_handoff`'s refusals can fire here -- but not,
        // as this comment used to say, because every precondition is
        // established "under this same hold": this function releases the slot
        // lock between minting the Installer token and this call. They cannot
        // fire because nothing that could falsify them runs in between. The
        // Installer token is minted for this install and held only by this
        // frame. The axis this frame set to `Installing` moves to `HandoffDone`
        // in production only inside this commit, and
        // `PendingWorkerSchedule::queue_worker` refuses unless it is
        // `HandoffDone` -- so a wake deposited meanwhile records its reason,
        // queues no worker, and leaves the schedule `Idle` and `worker_owner`
        // empty, which only a queued worker pass could change. A refusal is
        // therefore an invariant violation, not a condition, and it is fatal
        // like the other invariant violations in this file. (Native review
        // observation on N16-3, round 17.)
        //
        // Out of the hold first: a bugcheck holding this slot's spin lock hangs
        // every other processor that touches the ring.
        Err((error, _selected, installer)) => {
            drop(installer);
            unlock.release();
            panic!("pending handoff refused on a slot this frame owns: {error:?}");
        }
    };
    // The arbiter's own handoff. Until it runs, a dequeue mints nothing: the
    // installer is still publishing, and no claimant may act on this request
    // while that is true.
    if let Some(arbiter) = slot_runtime.arbiter.as_mut() {
        let _ = arbiter.handoff_done();
    }
    unsafe { (*raw).install_axis = Some(InstallAxis::HandoffDone) };
    if let Some(due_time) = due {
        // `arm` refuses unless the timer is quiesced, and that refusal is the
        // only thing standing between two epochs believing they own the same
        // DPC. Discarding it and calling `KeSetTimer` anyway is how a stale DPC
        // reaches the *next* install and completes a fresh finite WAIT early.
        // SAFETY: written under the hold taken above.
        //
        // A refusal must NOT return an error here: `IoCsqInsertIrp` has already
        // transferred this IRP, and a non-PENDING status would make the thunk
        // complete one it no longer owns. The timer is simply not armed. The
        // request stays cancellable and fence, unload and readiness still reach
        // it; only its deadline is lost, which is strictly better than arming a
        // second epoch onto a DPC somebody else still owns.
        let armed = unsafe { (*raw).timer_state.arm(epoch) }.is_ok();
        // `dpc_entered` is deliberately NOT cleared here. It was, and the clear
        // raced the store it guards: a DPC publishes `Quiesced` and releases
        // this lock BEFORE its `KeSetEvent`, so an install arming inside that
        // window erased an obligation the previous generation still owed, and
        // unload's exit-signal wait then returned at once and freed the arena
        // that set was about to write into. Nothing may clear this flag; see
        // its declaration for why a latch is the sound reading.
        // Take the Dpc owner HERE, not inside the DPC. The DPC's whole roster
        // runs under this same slot lock, and so does the only reader of
        // `owner_count`, so an owner taken in there can never be observed. Held
        // from arm until the DPC exits, it is exactly the window in which an
        // in-flight DPC exists, and any worker that takes the lock in that
        // window sees it and refuses to publish the slot reusable.
        if armed {
            if let Some(runtime) = unsafe { (*raw).runtime.as_mut() } {
                if runtime.dpc_owner.is_none() {
                    if let Ok(token) = runtime.owners.acquire_owner(install, PendingOwnerKind::Dpc)
                    {
                        runtime.dpc_owner = Some(token);
                    }
                }
            }
            // `KeSetTimer` INSIDE the hold that published `Armed`, so the two
            // cannot disagree. With the insertion outside it there was a window
            // in which the state said `Armed { epoch }` and the timer was not
            // in the queue yet: a completion pass racing that window got FALSE
            // from `KeCancelTimer`, `cancel` read `Armed`-not-dequeued as "the
            // DPC is already on its way in", and the worker then blocked on an
            // exit event no DPC had been queued to signal -- for as long as the
            // client's own `timeout_ms`, on a system worker thread.
            //
            // `Armed` now means "in the timer queue", which is the fact
            // `KeCancelTimer`'s BOOLEAN is interpreted against.
            //
            // SAFETY: `KeSetTimer` is callable at or below DISPATCH_LEVEL and
            // takes no lock this slot holds. Its DPC contends for this same
            // spin lock, so an already-expired due time costs that DPC the
            // remainder of this critical section -- three stores -- and nothing
            // else.
            unsafe {
                KeSetTimer(
                    core::ptr::addr_of_mut!((*raw).timer),
                    due_time,
                    core::ptr::addr_of_mut!((*raw).dpc),
                );
            }
        }
        unlock.release();
    } else {
        unlock.release();
    }
    // The queue call is NOT made here. `commit_pending_handoff` has published
    // `Queued`, but the parked plan is stored by `store_parked_wait` after this
    // function returns -- so a worker queued now can run first, find no plan,
    // and leave the ring wedged at `Queued` with the IRP already dequeued from
    // the CSQ. The obligation is parked in the slot and discharged by
    // `store_parked_session_wait`, which is the first moment a pass could
    // usefully run.
    //
    // Nothing is lost if that store never happens: the token stays in the slot
    // and `abandon_queued_pass` returns the schedule to `Idle` on the pass that
    // does eventually run, and cancel, fence, timer and unload all still reach
    // this request.
    if let Some(queued) = queue {
        // SAFETY: the lock is initialized before the CSQ is published.
        let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
        // SAFETY: paired with the acquire.
        let unlock =
            unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
        // SAFETY: exclusive under the hold.
        if let Some(slot_runtime) = unsafe { (*raw).runtime.as_mut() } {
            slot_runtime.handoff_queue = Some(queued);
            unlock.release();
        } else {
            unlock.release();
            // No runtime to park it in and nothing that could ever run the
            // pass, so the obligation is discharged against the queue call it
            // stands for rather than dropped.
            unsafe {
                runtime.queue_pending_worker(ring_index);
                let _ = queued.commit_after_queue();
            }
        }
    }
    Ok(())
}

/// Store the owned parked WAIT plan. Marks the ring SQ owner as a pending
/// waiter so fence role observation does not refuse it.
///
/// A refusal returns `owned` whole, for the same reason
/// [`store_parked_session_wait_inner`] does: it privately holds a `RoleLease`
/// with no `Drop`, and dropping it here would leak the ring's sole SQ-wait
/// role forever.
///
/// # Safety
/// PASSIVE_LEVEL. `runtime` is this session's published pending runtime, and
/// `ring` / `session` outlive the parked install.
#[allow(clippy::result_large_err)]
pub(crate) unsafe fn store_parked_session_wait(
    runtime: &PendingRuntimeReady,
    ring_index: u32,
    owned: ParkedWaitInstall,
    ring: *const crate::session::NativeRingSlot,
    request: fsring_abi::control::EnterRequestV1,
    session: *const crate::session::NativeSession,
) -> Result<(), ParkedWaitInstall> {
    // One exit, and the discharge is on it. `park_wait_enter` parks a handoff
    // obligation that only this call can discharge: the schedule already says
    // `Queued`, and if no work item is ever queued then no pass runs, so the
    // `abandon_queued_pass` recovery has nothing to run on and the ring is
    // wedged forever with its IRP already dequeued.
    //
    // The inner call still discharges under the same lock that publishes the
    // plan -- the first instant a pass could find it, which is the ordering the
    // previous round established and this does not disturb. `take()` is
    // idempotent, so this second discharge is a no-op on that path and covers
    // every path where the inner call returned `false` before reaching it.
    // Written as a shape rather than as three more calls at three more early
    // returns, because "every path discharges" is what was missed the first
    // time and a shape cannot forget it.
    // SAFETY: the caller's contract, forwarded unchanged.
    let stored = unsafe {
        store_parked_session_wait_inner(runtime, ring_index, owned, ring, request, session)
    };
    // SAFETY: PASSIVE_LEVEL with no lock held, and `ring_index` was the
    // caller's; a ring index out of range discharges nothing.
    unsafe { discharge_parked_handoff(runtime, ring_index) };
    stored
}

/// Discharge a parked handoff obligation that no plan publication took.
///
/// Idempotent by construction: the obligation is an `Option` taken under the
/// slot lock, so a second call finds `None` and queues nothing. Queuing the
/// worker is the one act the obligation stands for, and it is safe even with no
/// plan stored -- the pass finds nothing to begin and `abandon_queued_pass`
/// returns the schedule to `Idle`, which is the state a later wake can queue
/// from.
///
/// # Safety
/// PASSIVE_LEVEL with no slot lock held.
unsafe fn discharge_parked_handoff(runtime: &PendingRuntimeReady, ring_index: u32) {
    if ring_index >= runtime.ring_count() {
        return;
    }
    // SAFETY: the index is in range, so the slot exists for this runtime.
    let context = unsafe { runtime.slot_context(ring_index) };
    let raw = context.as_ptr();
    // SAFETY: the lock is initialized before the CSQ is published.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // SAFETY: exclusive under the hold.
    let queued = match unsafe { (*raw).runtime.as_mut() } {
        Some(slot_runtime) => slot_runtime.handoff_queue.take(),
        None => None,
    };
    unlock.release();
    if let Some(queued) = queued {
        // SAFETY: the lock is released, the index is in range, and this is the
        // one queue call the obligation stands for.
        unsafe {
            runtime.queue_pending_worker(ring_index);
            let _ = queued.commit_after_queue();
        }
    }
}

/// The store itself. Every refusal here leaves the handoff obligation for
/// [`store_parked_session_wait`] to discharge; none of them may discharge it
/// twice, and none of them can, because the take is what discharges.
///
/// A refusal hands `owned` back rather than dropping it: it privately carries
/// the ring-wide `RoleLease` `EnterEffect::AcquireRole` minted for this WAIT,
/// and that lease has no `Drop`. Dropping `owned` would leak the session-
/// ring's sole SQ-wait-owner bit forever, permanently refusing every later
/// WAIT on this ring with `DEVICE_BUSY` -- the same "losing a role silently
/// is worse than reporting the fault" property `EnterProgress::ReleaseRole`'s
/// caller already states and enforces for the plan's own unwind path.
///
/// # Safety
/// As [`store_parked_session_wait`].
#[allow(clippy::result_large_err)]
unsafe fn store_parked_session_wait_inner(
    runtime: &PendingRuntimeReady,
    ring_index: u32,
    owned: ParkedWaitInstall,
    ring: *const crate::session::NativeRingSlot,
    request: fsring_abi::control::EnterRequestV1,
    session: *const crate::session::NativeSession,
) -> Result<(), ParkedWaitInstall> {
    if ring_index >= runtime.ring_count() || ring.is_null() || session.is_null() {
        return Err(owned);
    }
    // `role()` peeks rather than takes, so `owned` still holds its lease
    // whole on every refusal below.
    let marked = match owned.role() {
        Some(lease) => unsafe { (*ring).mark_parked_sq_wait(lease) },
        None => return Err(owned),
    };
    if !marked {
        return Err(owned);
    }
    let context = unsafe { runtime.slot_context(ring_index) };
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let Some(slot_runtime) = (unsafe { (*raw).runtime.as_mut() }) else {
        unlock.release();
        return Err(owned);
    };
    let stored = slot_runtime.store_session_wait(owned, ring, request, session);
    // The installer's handoff obligation, discharged HERE rather than in
    // `park_wait_enter`: this is the first instant a worker pass could find the
    // plan. It is taken whether or not the store succeeded, because
    // `commit_pending_handoff` already published `Queued` and a schedule that
    // says queued with no work item queued is the state the right exists to
    // make impossible. A pass that runs against a failed store finds no plan
    // and `abandon_queued_pass` returns the schedule to `Idle`.
    let queued = slot_runtime.handoff_queue.take();
    // The plan now exists, so a wake that arrived while it did not -- and whose
    // pass therefore found nothing and abandoned -- is owed the pass nothing
    // else will ever queue. Asked only when the store succeeded and only when
    // the handoff did not already publish a `Queued`, so this slot still owes
    // exactly one queue call in total.
    let owed = if stored.is_ok() && queued.is_none() {
        slot_runtime
            .pass_admission()
            .and_then(|admission| slot_runtime.queue_wake_still_owed(admission))
    } else {
        None
    };
    unlock.release();
    if let Some(queued) = queued {
        // SAFETY: the lock is released, `ring_index` is below the ring count,
        // and this is the one queue call the obligation stands for.
        unsafe {
            runtime.queue_pending_worker(ring_index);
            let _ = queued.commit_after_queue();
        }
    }
    if let Some(owed) = owed {
        // SAFETY: as above, and `owed` is only `Some` when `queued` was `None`,
        // so this is still exactly one queue call for this slot.
        unsafe {
            runtime.queue_pending_worker(ring_index);
            owed.commit_after_work_queued();
        }
    }
    stored
}

/// Store the stable session reference acquired before CSQ insert.
///
/// # Safety
/// PASSIVE_LEVEL. `reference` is not stored anywhere else.
pub(crate) unsafe fn store_parked_strong_session(
    runtime: &PendingRuntimeReady,
    ring_index: u32,
    reference: StrongSessionRef,
    registry: *mut crate::lifecycle::KernelSessionRegistry,
) -> Result<(), StrongSessionRef> {
    if ring_index >= runtime.ring_count() || registry.is_null() {
        return Err(reference);
    }
    let context = unsafe { runtime.slot_context(ring_index) };
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let result = match unsafe { (*raw).runtime.as_mut() } {
        Some(slot_runtime) if slot_runtime.parked_strong.is_none() => {
            slot_runtime.parked_strong = Some(reference);
            slot_runtime.parked_strong_registry = registry;
            Ok(())
        }
        _ => Err(reference),
    };
    unlock.release();
    result
}

/// Take the parked strong session reference so a refused install can release it.
///
/// # Safety
/// PASSIVE_LEVEL. The caller releases the reference exactly once.
pub(crate) unsafe fn take_parked_strong_session(
    runtime: &PendingRuntimeReady,
    ring_index: u32,
) -> Option<StrongSessionRef> {
    if ring_index >= runtime.ring_count() {
        return None;
    }
    let context = unsafe { runtime.slot_context(ring_index) };
    let raw = context.as_ptr();
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    let taken = match unsafe { (*raw).runtime.as_mut() } {
        Some(slot_runtime) => slot_runtime.parked_strong.take(),
        None => None,
    };
    unlock.release();
    taken
}

// ---------------------------------------------------------------------------
// R4 Task 19: the two total operations the worker and unload call
// ---------------------------------------------------------------------------
//
// Both acquire the slot lock themselves and both release it on every path. That
// is why they are the only two things visible outside this module for the
// publication surface: a function that handed a caller a locked context, a
// prepared packet, or a field projection would make the release somebody else's
// problem, and a missed release at DISPATCH_LEVEL wedges every processor that
// touches the ring.

/// The one authority to release a slot lock, and a `Drop` that means it happens.
///
/// `armed` is not belt-and-braces: the interesting paths here are the ones that
/// RETURN EARLY between acquire and release, and on those the explicit call
/// never runs. Releasing twice would be worse than not releasing at all, so the
/// flag is what makes the destructor idempotent with the explicit call.
///
/// **It does not cover a panic, and never did.** `driver/Cargo.toml` sets
/// `panic = "abort"` in both profiles and `lib.rs` installs a `#[panic_handler]`
/// that calls `KeBugCheckEx`, so nothing unwinds and this `Drop` does not run.
/// A panic between acquire and release bugchecks with the spin lock held, which
/// hangs every other processor that touches the ring. Every panic on a held path
/// therefore has to release explicitly first -- see the sweep recorded above
/// `finalize_native_pending_publication`. The doc used to name "panic" as one of
/// the cases this guard covers, which is the one case it cannot.
struct PendingContextUnlock {
    lock: *mut KSPIN_LOCK,
    old_irql: KIRQL,
    armed: bool,
}

impl PendingContextUnlock {
    /// # Safety
    /// `lock` is an initialized slot lock this frame has just acquired, and
    /// `old_irql` is exactly what that acquire returned.
    const unsafe fn armed(lock: *mut KSPIN_LOCK, old_irql: KIRQL) -> Self {
        Self {
            lock,
            old_irql,
            armed: true,
        }
    }

    fn release(mut self) {
        if self.armed {
            // SAFETY: the constructor's contract: this exact lock, this exact
            // saved IRQL, released once.
            unsafe { KeReleaseSpinLock(self.lock, self.old_irql) };
            self.armed = false;
        }
    }
}

impl Drop for PendingContextUnlock {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: as above. Reached only when an early return or an unwind
            // skipped the explicit release.
            unsafe { KeReleaseSpinLock(self.lock, self.old_irql) };
            self.armed = false;
        }
    }
}

/// What the one total final publication produced.
///
/// Two closed outcomes and nothing else: no lock, no plan, no packet, no field
/// projection crosses this boundary. The worker returns immediately after
/// receiving it and never touches the context again.
///
/// Both payloads are carried but unread, and that is deliberate rather than an
/// omission: the worker's single caller binds the whole value to `_outcome`
/// and returns, because a refused publication is already parked IN the context
/// by `finalize_native_pending_publication` itself. The durable state, not
/// this value, is what `observe_pending_for_unload` later reads and what
/// `wait_contexts_drained` refuses on. The payloads stay so the boundary is
/// total and `#[must_use]` still forces the caller to name the result.
#[must_use]
#[allow(dead_code)]
pub(crate) enum NativeFinalPublicationOutcome {
    Published(PendingCompletionResult),
    FailStopped(PublicationFailStopWitness),
}

/// What unload saw when it looked at one slot.
///
/// `wait_contexts_drained` decides on the discriminant alone -- drained,
/// active, or fail-stopped -- and the two payloads are carried unread. They
/// are kept because each names the exact thing that refused, which is what a
/// crash dump needs; the `allow` records that no code path reads them.
#[must_use]
#[allow(dead_code)]
pub(crate) enum PendingUnloadObservation {
    /// Vacant or exhausted, with an empty fail-stop slot.
    Drained,
    /// A live install still owns the slot.
    Active(PendingInstallId),
    /// A refused publication is parked here. The packet stays in the context;
    /// this is only its witness.
    ///
    /// DEVIATION: the plan asks for a non-`Clone`/non-`Copy` witness.
    /// `fsring-core`'s `PublicationFailStopWitness` derives both, and it is the
    /// only witness type there is. What the plan is protecting -- that the
    /// *packet* is unique and stays put -- holds regardless: `witness()` borrows
    /// and copies two scalars, and there is no API that takes, clears, resets or
    /// retries the packet at all.
    PublicationFailStop(PublicationFailStopWitness),
}

/// Publish one completed pending install, or park it.
///
/// Total: it acquires the slot lock, drives the plan's remaining stages to the
/// core-mediated final boundary, and releases the lock on both outcomes. On
/// success the reusable slot state is the **last** thing written, so no observer
/// can see a vacant slot whose owners are still held. On refusal the packet is
/// stored **first** and the parked state published after it, so the exact
/// invariant on `publication_fail_stop` holds at every instant a reader could
/// look.
///
/// # The panic-inside-a-hold population, swept
///
/// Round 15's N2 found the two bugchecks below firing with the slot lock held,
/// one commit after `a56eedb` moved three other sites out of exactly that. That
/// repair produced the construct at the three sites it was given and did not
/// generalise, so the population is stated here with its boundary.
///
/// COVERED -- every `panic!`/`assert!`/`unreachable!` lexically inside this
/// file. There are 23. Five are inside a lock hold:
///
///   * the two below, released before the bugcheck by this commit;
///   * `csq_complete_canceled_irp`'s `ForeignIrp` arm, which already releases
///     the raw lock first and says why;
///   * `csq_insert_irp`'s two `assert!`s, which are NOT fixed -- see below.
///
/// The other eighteen are outside any hold: `run_pending_completion_pass` and
/// `perform_pending_effect` each call `unlock.release()` before every panic they
/// contain, the `size_of`/`offset_of` assertions run at init, and the two
/// trampolines panic before taking anything.
///
/// UNCOVERED, and measured rather than assumed:
///
///   * `csq_insert_irp`'s two assertions run under the CSQ framework's hold.
///     The callback did not take that lock -- `csq_acquire_lock` did, and
///     `csq_release_lock` will -- so it cannot release it without breaking the
///     framework's pairing, and it has no return value to refuse with. They stay
///     fatal-in-hold. Moving them needs the check to happen before the insert,
///     in a caller that owns the pairing, which is a design change and not a
///     sweep.
///   * A panic in a function CALLED from inside a hold is not visible to a
///     lexical sweep of this file. That set is unmeasured.
///
/// # Safety
/// `context` is the permanent context matching `plan`; its exact IRP was
/// completed once, and the caller performs no later context touch.
pub(crate) unsafe fn finalize_native_pending_publication(
    context: NonNull<PendingEnterContext>,
    plan: PendingCompletionPlan,
) -> NativeFinalPublicationOutcome {
    let raw = context.as_ptr();
    // SAFETY: `lock` is initialized before the CSQ that names the callbacks is
    // published, so any context reachable here has a live lock.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire above; released on every path below,
    // including an unwind.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };

    // Drive the plan to the one boundary core has to mediate. `run_next` takes
    // the plan by value, so there is no way to reach the final stage without
    // having gone through every earlier one.
    let mut plan = plan;
    let final_publication: Result<PendingFinalPublication, &'static str> = loop {
        match plan.run_next() {
            PendingCompletionStep::NeedFinalPublication(publication) => break Ok(publication),
            PendingCompletionStep::Advanced(next) => plan = next,
            // The result write and the IRP completion belong to the worker and
            // happened before it called this. Reaching either here means the
            // plan handed over is at the wrong stage, which is a bug in the
            // caller rather than a condition to recover from.
            PendingCompletionStep::NeedResultWrite(_)
            | PendingCompletionStep::NeedIrpCompletion(_) => {
                break Err("final publication was handed a plan that has not written or completed");
            }
        }
    };
    // Out of the hold before the bugcheck, for the reason `a56eedb` wrote into
    // this file for three other sites: a bugcheck holding this spin lock hangs
    // every other processor that touches this ring. `PendingContextUnlock`'s
    // `Drop` cannot cover it -- `panic = "abort"` plus the crate's
    // `#[panic_handler]` means no unwind ever runs -- so the release has to be
    // an explicit statement on the path to the panic.
    //
    // The invariant is unchanged and still fatal. Only where it fires moved.
    let final_publication = match final_publication {
        Ok(publication) => publication,
        Err(reason) => {
            unlock.release();
            panic!("{reason}");
        }
    };

    // SAFETY: the lock is held, and the runtime is present on any slot a worker
    // pass could have been queued for.
    let runtime = unsafe { (*raw).runtime.as_mut() };
    let Some(runtime) = runtime else {
        // Same boundary as the stage check above: release, then bugcheck.
        unlock.release();
        panic!("final publication on a slot with no runtime")
    };
    // SAFETY: read under the hold.
    let slot_state = unsafe { (*raw).slot_state };
    let exhausted = matches!(
        slot_state.publish_vacant(),
        Ok(PendingSlotState::EpochExhausted)
    );

    match final_publication.commit_final_publication(
        &mut runtime.result_slot,
        &mut runtime.owners,
        &runtime.wake,
        exhausted,
    ) {
        Ok(result) => {
            let next = match slot_state.publish_vacant() {
                Ok(next) => next,
                // Unreachable in practice: the commit above validated the
                // Quiescing epoch this transition needs. Parking rather than
                // publishing is the safe direction if it ever is not.
                Err((_, unchanged)) => unchanged,
            };
            // The reusable state is the LAST write, and the lock is still held,
            // so no observer sees a vacant slot with owners outstanding.
            // The ring must stop naming this install, or it serves exactly one
            // parked WAIT for the life of the session: `begin_install` and
            // `bind_install` both refuse while one is bound, and the CSQ insert
            // asserts the slot names no IRP. This happens whatever the closing
            // half answers below -- the IRP was completed by the pass above, so
            // a slot still naming it names freed memory.
            // SAFETY: written under the hold.
            unsafe {
                (*raw).irp = core::ptr::null_mut();
                (*raw).irp_axis = None;
            }
            // The closing half is checked, not discarded, and it is what
            // decides whether the slot may be republished. It refuses without
            // taking anything, so a refusal leaves this slot exactly as the
            // publication found it: still `Quiescing`, still naming its
            // install, which `observe_pending_for_unload` reports as Active and
            // which makes the drain refuse into blocked-safe unload rather than
            // hand the next install a ring whose ledgers disagree with its
            // state. The request itself is unaffected -- it was completed
            // above -- so a refusal costs this ring, not the caller.
            //
            // The reusable state is the LAST write, and the lock is still held,
            // so no observer sees a vacant slot with owners outstanding.
            if runtime.release_install() {
                // SAFETY: written under the hold.
                unsafe {
                    (*raw).slot_state = next;
                }
            }
            unlock.release();
            NativeFinalPublicationOutcome::Published(result)
        }
        Err(packet) => {
            let witness = packet.witness();
            // Store FIRST, publish the parked state after. The reverse order
            // would leave an instant in which the state claims a fail-stop no
            // packet backs.
            // SAFETY: written under the hold; the slot was `None` because every
            // non-parked state requires it to be.
            unsafe {
                (*raw).publication_fail_stop = Some(packet);
            }
            if let Ok(parked) = slot_state.park_publication_fail_stop() {
                // SAFETY: written under the hold.
                unsafe {
                    (*raw).slot_state = parked;
                }
            }
            unlock.release();
            NativeFinalPublicationOutcome::FailStopped(witness)
        }
    }
}

/// Look at one slot for unload, without disturbing it.
///
/// It acquires and releases the lock itself and never takes, clears, resets,
/// retries or projects the packet -- it borrows it under the hold, copies the
/// witness out, and leaves the unique packet where it is. A fail-stop therefore
/// cannot satisfy the drain: the caller gets a third answer that is neither
/// Drained nor an install it could wait for.
///
/// # Safety
/// `context` belongs to a still-resident session.
pub(crate) unsafe fn observe_pending_for_unload(
    context: NonNull<PendingEnterContext>,
) -> PendingUnloadObservation {
    let raw = context.as_ptr();
    // SAFETY: as above.
    let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock)) };
    // SAFETY: paired with the acquire; released on every path.
    let unlock =
        unsafe { PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock), old_irql) };
    // Classify under the hold, and carry a broken invariant OUT of it as a
    // value rather than panicking inside it. This driver builds
    // `panic = "abort"` in both profiles, so `Drop` never runs and the guard
    // above would not release: a bugcheck holding this spin lock hangs every
    // other processor that touches this ring, which is exactly what
    // `observe_insert_outcome` and `csq_complete_canceled_irp` release early to
    // avoid and say so. They release the lock raw because they hold it raw;
    // this frame holds a guard, so it keeps its single release path and moves
    // the panic past it instead.
    //
    // The invariants are unchanged and still fatal. Only where they fire moved.
    //
    // SAFETY: read under the hold.
    let observed: Result<PendingUnloadObservation, &'static str> = unsafe {
        match (*raw).slot_state {
            PendingSlotState::PublicationFailStop { .. } => {
                match (*raw).publication_fail_stop.as_ref() {
                    Some(packet) => Ok(PendingUnloadObservation::PublicationFailStop(
                        packet.witness(),
                    )),
                    // The exact invariant, enforced rather than assumed: a
                    // parked state with no packet is the one cross-product this
                    // module exists to make impossible.
                    None => Err("a parked slot with no fail-stop packet"),
                }
            }
            PendingSlotState::Vacant { .. } | PendingSlotState::EpochExhausted => {
                if (*raw).publication_fail_stop.is_some() {
                    Err("a drained slot holding a fail-stop packet")
                } else {
                    Ok(PendingUnloadObservation::Drained)
                }
            }
            PendingSlotState::Installing { .. }
            | PendingSlotState::Active { .. }
            | PendingSlotState::Quiescing { .. } => {
                match (*raw)
                    .runtime
                    .as_ref()
                    .and_then(PendingSlotRuntime::serving_install)
                {
                    Some(install) => Ok(PendingUnloadObservation::Active(install)),
                    None => Err("an occupied slot naming no install"),
                }
            }
        }
    };
    unlock.release();
    match observed {
        Ok(observation) => observation,
        Err(reason) => panic!("{reason}"),
    }
}
