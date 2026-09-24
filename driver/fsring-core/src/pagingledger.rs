//! The paging-write issue ledger (`07-cache-mm.md` §6).
//!
//! §6 says what it is for: *"It is this document's centerpiece because it is
//! what makes sections 3 and 7's zero-fill and VDL-advance guarantees actually
//! hold under concurrency rather than only in the single-writer case."*
//!
//! Slice B3 shipped `must_zero_fill` and `vdl_after_cached_write` and named them
//! the single-writer halves. This is the other half, and its failure mode is the
//! worst one in the driver: a VDL advanced over a range nothing proved was
//! written, so a reader observes provider storage the daemon never accounted
//! for.
//!
//! **What is decided here and what is not.** No spin lock is taken, no node is
//! allocated, no IRP or MDL exists. §6 assigns the sequencer lock to
//! `06-locking.md` in as many words, and this module states what the sequencer
//! *tracks*, not how its lock is acquired. The node budget is modelled as an
//! **input** rather than observed.
//!
//! *"Never allocates while the sequencer lock is held"* remains a property of
//! code this crate does not contain, and slice C1 did **not** retire it.
//!
//! C1 tried, and its own review round 1 showed the attempt was vacuous: no
//! production path here — `terminalize`, `record_failure`, `subtract_proven` —
//! takes an `effect::Seam` or reaches the recorder, so a test that ran this
//! module's terminal cycle "through the seam" observed nothing about it. A
//! planted heap allocation in `record_failure` left that test green. The test
//! is deleted rather than re-worded; a measurement that cannot fail is not
//! weaker evidence, it is none.
//!
//! Retiring this PENDING needs the ledger's fallible steps routed through the
//! seam, which is a call-site change and belongs to the slice that builds the
//! call sites.
//!
//! **[`ActiveSet`] is a host stand-in, and the deviation is named here rather
//! than discovered.** `07:360-363` denies *"a 1024-entry table embedded in every
//! FCB"* — the real driver threads an *intrusive* ordered set through the
//! `WriteIrpContext` nodes that already exist, so the set costs nothing extra.
//! This crate has no allocator and no nodes, so its stand-in does reserve its
//! bound as an inline array. What is modelled and checked is the **rule**: the
//! set holds bare issue numbers and nothing else (signal 8's scan), and the
//! per-FCB limit is *enforced* on every insertion. The storage shape is the
//! host's, not the document's.

use crate::size::{SizeTrio, Truncation, ValidatedSizeState, VdlClamped};
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use fsring_abi::limits::{MAX_FILE_SIZE, RangeError, validate_file_range};
use fsring_abi::validate::completion_status;

/// `07-cache-mm.md` §6's bounded adapter constants, in the document's order.
///
/// Filled from the parser's own printed output, not typed. A hand-copy checked
/// against a hand-written count is what slice B2 had to correct twice.
pub const LIMITS: [(&str, u64); 8] = [
    ("MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_FCB", 1024),
    ("MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_MOUNT", 16384),
    ("MAX_ACTIVE_PAGING_WRITE_CONTEXTS_GLOBAL", 65536),
    ("INLINE_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB", 2),
    ("MAX_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB", 64),
    ("PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES", 2),
    ("MAX_PAGING_WRITE_FAILURE_OVERFLOW_NODES_PER_MOUNT", 16384),
    ("MAX_PAGING_WRITE_FAILURE_OVERFLOW_NODES_GLOBAL", 65536),
];

/// Look one of §6's constants up by name.
///
/// Panic-free: an unknown name is `None`, so a typo is a test failure rather
/// than a silent zero.
pub fn limit(name: &str) -> Option<u64> {
    let mut i = 0;
    while i < LIMITS.len() {
        match LIMITS.get(i) {
            Some((n, v)) if *n == name => return Some(*v),
            _ => {}
        }
        i = i.saturating_add(1);
    }
    None
}

/// §6's closed list of events that must never clear evidence, transcribed
/// verbatim and compared positionally against the document.
pub const NEVER_CLEARING_SENTENCE: &str = "Waiter absence, timeout, CLEANUP, a \
session fence, or ATTACH never discards or normalizes a recorded failure.";

/// §7's formula, parsed out of its fenced block rather than typed.
/// [`target_vdl`] computes exactly this.
pub const TARGET_VDL_FORMULA: &str = "target_vdl = min(EndOfFile, current file_size)";

/// §7's `AdvanceOnly` precondition, transcribed verbatim.
///
/// [`SequencerState::advance_only_barrier`] is this sentence as a function, down to the
/// candidate being the lowest-issue interval rather than a bool.
pub const TARGET_VDL_SENTENCE: &str = "and only advances VDL to `target_vdl` \
once the ledger shows no unresolved or `UNKNOWN` evidence intersecting \
`[current VDL, target_vdl)`; if such evidence exists, the lowest-issue \
unresolved interval becomes the local failure candidate instead.";

/// One of §6's five never-clearing events.
///
/// A closed list, in the document's order. `06-locking.md` §3.4 states the same
/// rule in shorter words — *"Waiter absence, timeout, CLEANUP, fence, and
/// ATTACH never discard or normalize a failure"* — and the transcription test
/// checks both documents, so a list that drifted from either is caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerEvent {
    /// No waiter is present for a completion.
    WaiterAbsence,
    /// A wait expired.
    Timeout,
    /// `IRP_MJ_CLEANUP` on the file object.
    Cleanup,
    /// A session fence.
    SessionFence,
    /// A filter `ATTACH`.
    Attach,
}

/// §6's five, in the document's order.
pub const ALL_LEDGER_EVENTS: [LedgerEvent; 5] = [
    LedgerEvent::WaiterAbsence,
    LedgerEvent::Timeout,
    LedgerEvent::Cleanup,
    LedgerEvent::SessionFence,
    LedgerEvent::Attach,
];

impl LedgerEvent {
    /// The document's own phrase for this event, as it appears in §6's
    /// sentence.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::WaiterAbsence => "Waiter absence",
            Self::Timeout => "timeout",
            Self::Cleanup => "CLEANUP",
            Self::SessionFence => "a session fence",
            Self::Attach => "ATTACH",
        }
    }
}

/// `MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_FCB`, as a `usize` so it can size the
/// host stand-in's storage.
///
/// Written out rather than read from [`LIMITS`] because an array length must be
/// a `const` and `&str` equality is not available in a `const fn`. The link to
/// the document is not lost: [`LIMITS`] is compared against §6's fenced block,
/// and `the_per_fcb_bound_is_the_documents_constant` compares this against
/// [`LIMITS`]. Drifting it reddens that test.
const ACTIVE_CAPACITY: usize = 1024;

/// `INLINE_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB`. §6: *"Each FCB embeds
/// exactly two ordinary interval slots inline plus one allocation-free inline
/// UNKNOWN accumulator"*. Beyond this an update needs an overflow node.
const INLINE_INTERVALS: usize = 2;

/// `MAX_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB` — the **total** ordinary bound:
/// two inline plus at most 62 overflow, not 2 + 64. The UNKNOWN accumulator is
/// counted separately, as §6 counts it.
const MAX_INTERVALS: usize = 64;

/// `PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES`. §6: *"A terminal update may
/// preclaim at most … nodes before entering the size gate/sequencer pair; any
/// update that needs more takes the inline UNKNOWN fallback instead of
/// allocating under the lock."*
const PRECLAIM_NODES: u64 = 2;

/// Everything the ledger refuses to do, as a value.
///
/// Every one of these is a *refusal*, never a silent adjustment: §6's whole
/// premise is that pressure makes the proof more conservative, so a path that
/// cannot do the safe thing says so rather than doing the unsafe one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    /// `last_issued` cannot advance without wrapping. §6 calls the counter
    /// *"checked"*; wrapping would reissue a live number.
    IssuesExhausted,
    /// The per-FCB active-context bound is full. §6 routes this to the
    /// claim-failure path, not to an unnumbered failure.
    ActiveContextsExhausted,
    /// The aggregate's internal counter is behind its active ordering. Safe
    /// callers enter only through [`SequencerState::admit`], which keeps those
    /// components paired.
    IssueOutOfOrder,
    /// A terminal record named an issue the set does not hold.
    NotActive,
    /// A byte range `04 §8.1`'s domain rejects, carrying `fsring-abi`'s own
    /// reason. An empty or inverted range lands here: it carries no evidence.
    Range(RangeError),
    /// A preclaim above `PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES`.
    BudgetTooLarge,
    /// A returned VDL below the baseline the caller verified. `07:323-326`
    /// preconditions the input as *"a verified, monotonically increasing
    /// returned VDL"*; a truncate uses [`Ledger::truncate_reset`] instead.
    VdlRegressed,
    /// A completion claimed coverage that is not a prefix of what it requested.
    /// §6 knows one shape of partial success — the *"short `SUCCESS`"* — and a
    /// provider claiming anything else is refused rather than interpreted.
    CoverageOutsideRequest,
}

/// A checked, nonzero paging-WRITE issue number.
///
/// §6: *"a checked monotonically increasing nonzero counter"*. Nonzero is a
/// **type** fact rather than an asserted one, so no code path can produce issue
/// 0 and no test has to remember to look for it.
///
/// `Copy`, because an issue is an identifier and the ledger's intervals must be
/// able to name one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Issue(NonZeroU64);

impl Issue {
    /// The issue number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Wrap a raw number, if it is a legal issue.
    ///
    /// Module-private: outside this module the only route to an [`Issue`] is
    /// [`ActiveSet::allocate`] (or the claim-failure path), which is what
    /// signal 35 exists to keep true.
    const fn from_raw(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(nz) => Some(Self(nz)),
            None => None,
        }
    }
}

/// §6's `last_issued`.
///
/// Its [`next`](Self::next) is **module-private**: an issue that is allocated
/// and never inserted is invisible to the prefix formula, and the formula's
/// soundness depends on every allocated issue being either active or terminal.
/// [`ActiveSet::allocate`] mints and inserts in one call for that reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IssueCounter {
    last_issued: u64,
}

impl IssueCounter {
    /// A counter that has issued nothing. The first issue it mints is 1.
    #[must_use]
    const fn new() -> Self {
        Self { last_issued: 0 }
    }

    /// The highest issue minted so far; 0 when none has been.
    ///
    /// `07:306-308` reads this to compute the terminal prefix of an empty set.
    #[must_use]
    const fn last_issued(&self) -> u64 {
        self.last_issued
    }

    /// Mint the next issue, or refuse.
    ///
    /// Module-private; see the type documentation. The counter is advanced
    /// **only** on success, so an exhausted counter stays exhausted: a wrapping
    /// increment would leave `last_issued` at 0 and reissue 1 on the next call,
    /// handing two live paging WRITEs the same number.
    fn next(&mut self) -> Result<Issue, LedgerError> {
        let Some(raw) = self.last_issued.checked_add(1) else {
            return Err(LedgerError::IssuesExhausted);
        };
        let Some(issue) = Issue::from_raw(raw) else {
            return Err(LedgerError::IssuesExhausted);
        };
        self.last_issued = raw;
        Ok(issue)
    }
}

/// Private proof that preflight found exactly one active entry.
///
/// The index is minted only after owner and coverage validation. The terminal
/// paths consume it immediately after recording, so the removal is exact and
/// has no fallible exit after ledger mutation begins.
#[derive(Debug)]
struct ActiveEntry {
    issue: Issue,
    index: usize,
}

/// §6's *"ordered set containing exactly the nonterminal (still in-flight)
/// issues"*.
///
/// Kept sorted ascending, which is what makes [`minimum`](Self::minimum) — and
/// therefore §6's *"computable in O(1) under the lock"* prefix — a read of the
/// first element rather than a search. Sortedness is not assumed: insertion is
/// append-only and [`allocate`](Self::allocate) refuses when the counter is
/// behind the set.
///
/// See the module documentation for why the storage is an inline array here and
/// must not be one in an FCB.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSet {
    /// Issue numbers, ascending, valid for the first `len` entries. A bare
    /// number and nothing else: §6 says out-of-order completion *"needs no
    /// retained terminal-issue table"*, and signal 8's scan reads this
    /// declaration to check that no status or coverage range has crept in.
    entries: [u64; ACTIVE_CAPACITY],
    /// How many of `entries` are live.
    len: usize,
}

impl Default for ActiveSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl ActiveSet {
    /// An empty set.
    #[must_use]
    const fn new() -> Self {
        Self {
            entries: [0; ACTIVE_CAPACITY],
            len: 0,
        }
    }

    /// How many issues are still in flight.
    #[must_use]
    const fn len(&self) -> usize {
        self.len
    }

    /// Whether any issue is still in flight.
    #[must_use]
    const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mint the next issue **and insert it**, or refuse.
    ///
    /// `07:302-304` puts the two in one critical section: *"the same critical
    /// section allocates the issue and links the context into the intrusive
    /// ordered active set"*. They are one call here for a sharper reason — the
    /// prefix formula reads only the set, so an issue minted and not inserted
    /// is covered by a prefix that proves nothing about it. Active set `{5}`,
    /// mint 6 without inserting, remove 5: the set is empty, the prefix is
    /// `last_issued` = 6, and issue 6 recorded nothing.
    ///
    /// **Nothing is minted on a refusal.** Both checks run before
    /// [`IssueCounter::next`], because a burnt issue that is neither active nor
    /// terminal is a hole in exactly the same invariant. A full set is §6's
    /// failed context claim: the caller's answer is the claim-failure path,
    /// which numbers and records an issue of its own.
    ///
    /// # Errors
    ///
    /// [`LedgerError::ActiveContextsExhausted`] when the per-FCB bound is
    /// reached; [`LedgerError::IssuesExhausted`] when the counter cannot
    /// advance; [`LedgerError::IssueOutOfOrder`] when `counter` is not this
    /// set's counter — the design pairs the two by convention, so the pairing
    /// is checked rather than trusted.
    fn allocate(&mut self, counter: &mut IssueCounter) -> Result<Issue, LedgerError> {
        if self.len >= ACTIVE_CAPACITY {
            return Err(LedgerError::ActiveContextsExhausted);
        }
        // `next` yields `last_issued + 1`, so it out-ranks every entry exactly
        // when the greatest entry does not out-rank `last_issued`. Testing it
        // here rather than after minting keeps the refusal free of side effects.
        let greatest = self.live().last().copied().unwrap_or(0);
        if greatest > counter.last_issued() {
            return Err(LedgerError::IssueOutOfOrder);
        }

        let issue = counter.next()?;
        let Some(slot) = self.entries.get_mut(self.len) else {
            return Err(LedgerError::ActiveContextsExhausted);
        };
        *slot = issue.get();
        self.len = self.len.saturating_add(1);
        Ok(issue)
    }

    /// Find the exact active entry without mutating it.
    fn preflight(&self, issue: Issue) -> Option<ActiveEntry> {
        self.live()
            .iter()
            .position(|entry| *entry == issue.get())
            .map(|index| ActiveEntry { issue, index })
    }

    /// Retire exactly the entry which [`Self::preflight`] found.
    ///
    /// There is deliberately no `Result`: terminal paths create this private
    /// token only after every rejection condition has passed, and consume it
    /// without touching the active set in between.
    fn remove_preflighted(&mut self, entry: ActiveEntry) {
        let (_, from_entry) = self.entries.split_at_mut(entry.index);
        let (tail, _) = from_entry.split_at_mut(self.len.saturating_sub(entry.index));
        debug_assert_eq!(tail.first().copied(), Some(entry.issue.get()));
        tail.rotate_left(1);
        self.len = self.len.saturating_sub(1);
    }

    /// The lowest still-open issue, if any.
    #[must_use]
    fn minimum(&self) -> Option<Issue> {
        self.live().first().copied().and_then(Issue::from_raw)
    }

    /// §6's contiguous terminal prefix: *"`last_issued` when the active set is
    /// empty, or `minimum_active_issue - 1` otherwise"*.
    ///
    /// Takes the counter rather than a bare `u64`. The document's `last_issued`
    /// is the sequencer's own, and a hand-passed number is a number a caller can
    /// get wrong — `06 §3.5` releases BARRIER_WAIT fences on prefix coverage, so
    /// an overstated prefix releases a waiter over bytes nothing has proven.
    #[must_use]
    fn terminal_prefix(&self, counter: &IssueCounter) -> u64 {
        match self.minimum() {
            None => counter.last_issued(),
            Some(min) => min.get().saturating_sub(1),
        }
    }

    /// The live prefix of `entries`, ascending. Empty when the set is.
    fn live(&self) -> &[u64] {
        self.entries.get(..self.len).unwrap_or(&[])
    }
}

// ======================================== aggregate provenance and admission

/// The process-unique identity of one per-FCB paging-write sequencer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SequencerId(NonZeroU64);

impl SequencerId {
    /// The nonzero process-unique identity value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Why a sequencer could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequencerInitError {
    /// The process identity space is permanently exhausted.
    IdsExhausted,
}

/// Why a verified VDL update could not change this sequencer's baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VdlRejection {
    /// The proof was captured by a different per-FCB sequencer.
    WrongSequencer,
    /// An ordinary returned-size snapshot would lower the verified baseline.
    Regressed,
}

/// Why a VDL advance barrier could not inspect this sequencer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarrierRejection {
    /// The returned-size snapshot belongs to a different per-FCB sequencer.
    WrongSequencer,
}

/// A validated size state branded to the sequencer that captured it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeSnapshot {
    owner: SequencerId,
    trio: SizeTrio,
    size_epoch: u64,
}

impl SizeSnapshot {
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.owner
    }

    #[must_use]
    pub const fn trio(&self) -> SizeTrio {
        self.trio
    }

    #[must_use]
    pub const fn size_epoch(&self) -> u64 {
        self.size_epoch
    }
}

/// A completed truncation proof branded to its sequencer.
#[derive(Debug, PartialEq, Eq)]
pub struct TruncateSnapshot {
    owner: SequencerId,
    trio: SizeTrio,
}

impl TruncateSnapshot {
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.owner
    }

    #[must_use]
    pub const fn trio(&self) -> SizeTrio {
        self.trio
    }
}

/// The context-claim answer supplied to one admission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextClaimResult {
    Acquired,
    Failed,
}

/// An affine context-claim answer branded to its sequencer.
#[derive(Debug, PartialEq, Eq)]
pub struct ContextClaim {
    owner: SequencerId,
    result: ContextClaimResult,
}

impl ContextClaim {
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.owner
    }

    #[must_use]
    pub const fn result(&self) -> ContextClaimResult {
        self.result
    }
}

/// Why a capability could not be admitted by this sequencer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRejectionReason {
    WrongSizeOwner,
    WrongClaimOwner,
}

/// The untouched capabilities returned after ownership preflight rejects them.
pub struct AdmissionRejection {
    reason: AdmissionRejectionReason,
    write: PagingWrite<Extracted>,
    snapshot: SizeSnapshot,
    claim: ContextClaim,
}

impl AdmissionRejection {
    #[must_use]
    pub const fn reason(&self) -> AdmissionRejectionReason {
        self.reason
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        AdmissionRejectionReason,
        PagingWrite<Extracted>,
        SizeSnapshot,
        ContextClaim,
    ) {
        (self.reason, self.write, self.snapshot, self.claim)
    }
}

/// The fatal failure returned after the issue counter can no longer advance.
pub struct IssueExhaustion {
    owner: SequencerId,
    range: Coverage,
}

impl IssueExhaustion {
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.owner
    }

    #[must_use]
    pub const fn range(&self) -> Coverage {
        self.range
    }
}

/// The receipt for a numbered, immediately-terminal claim rejection.
pub struct ClaimRejectedReceipt {
    owner: SequencerId,
    issue: Issue,
    prefix: u64,
    outcome: RecordOutcome,
}

/// A status suitable for a terminal failed paging WRITE.
///
/// NTSTATUS failures have the sign bit set. Restricting construction to that
/// class keeps `SUCCESS`, `PENDING`, and all informational/success values out
/// of registered terminal evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureStatus(i32);

/// A raw completion status was not a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureStatusError;

impl FailureStatus {
    /// Validate that `status` belongs to the negative failure class.
    pub const fn new(status: i32) -> Result<Self, FailureStatusError> {
        if status < 0 {
            Ok(Self(status))
        } else {
            Err(FailureStatusError)
        }
    }

    /// The validated raw NTSTATUS.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl TryFrom<i32> for FailureStatus {
    type Error = FailureStatusError;

    fn try_from(status: i32) -> Result<Self, Self::Error> {
        Self::new(status)
    }
}

/// Which terminal exit produced a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalKind {
    Completed,
    Failed,
}

/// Why the aggregate refused a terminal operation before mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteRejectionReason {
    WrongSequencer,
    WrongSizeOwner,
    NotActive,
    CoverageOutsideRequest,
}

/// A rejected terminal operation returns the original live write unchanged.
#[derive(Debug)]
pub struct WriteRejection {
    reason: WriteRejectionReason,
    write: PagingWrite<Linearized>,
}

impl WriteRejection {
    #[must_use]
    pub const fn reason(&self) -> WriteRejectionReason {
        self.reason
    }

    #[must_use]
    pub fn into_write(self) -> PagingWrite<Linearized> {
        self.write
    }
}

/// Evidence and retirement receipt for an active paging WRITE.
#[derive(Debug)]
pub struct ActiveTerminalReceipt {
    owner: SequencerId,
    issue: Issue,
    prefix: u64,
    outcome: RecordOutcome,
    terminal_kind: TerminalKind,
}

impl ActiveTerminalReceipt {
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.owner
    }

    #[must_use]
    pub const fn issue(&self) -> Issue {
        self.issue
    }

    #[must_use]
    pub const fn prefix(&self) -> u64 {
        self.prefix
    }

    #[must_use]
    pub const fn outcome(&self) -> RecordOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn terminal_kind(&self) -> TerminalKind {
        self.terminal_kind
    }
}

impl ClaimRejectedReceipt {
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.owner
    }

    #[must_use]
    pub const fn issue(&self) -> Issue {
        self.issue
    }

    #[must_use]
    pub const fn prefix(&self) -> u64 {
        self.prefix
    }

    #[must_use]
    pub const fn outcome(&self) -> RecordOutcome {
        self.outcome
    }
}

/// The result of admitting an extracted paging write exactly once.
pub enum AdmissionOutcome {
    InFlight(PagingWrite<Linearized>),
    ClaimRejected {
        receipt: ClaimRejectedReceipt,
        claim: ContextClaim,
    },
    MountFatal {
        failure: IssueExhaustion,
        claim: ContextClaim,
    },
    Rejected(AdmissionRejection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionState {
    Open,
    IssuesExhausted,
}

static NEXT_SEQUENCER_ID: AtomicU64 = AtomicU64::new(1);

/// The only owner of one FCB's paging-write issuance, active set, and ledger.
pub struct SequencerState {
    id: SequencerId,
    counter: IssueCounter,
    active: ActiveSet,
    ledger: Ledger,
    admission: AdmissionState,
    verified_vdl_baseline: u64,
}

fn allocate_sequencer_id(next_id: &AtomicU64) -> Result<SequencerId, SequencerInitError> {
    let mut current = next_id.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return Err(SequencerInitError::IdsExhausted);
        }
        if current == 0 {
            match next_id.compare_exchange_weak(0, 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => current = 1,
                Err(observed) => current = observed,
            }
            continue;
        }
        let next = current.checked_add(1).unwrap_or(u64::MAX);
        match next_id.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                let Some(id) = NonZeroU64::new(current) else {
                    return Err(SequencerInitError::IdsExhausted);
                };
                return Ok(SequencerId(id));
            }
            Err(observed) => current = observed,
        }
    }
}

impl SequencerState {
    /// Construct one private paging-write component set for an FCB.
    pub fn try_new(initial: ValidatedSizeState) -> Result<Self, SequencerInitError> {
        Ok(Self {
            id: allocate_sequencer_id(&NEXT_SEQUENCER_ID)?,
            counter: IssueCounter::new(),
            active: ActiveSet::new(),
            ledger: Ledger::new(),
            admission: AdmissionState::Open,
            verified_vdl_baseline: initial.trio().valid_data_length,
        })
    }

    #[must_use]
    pub const fn id(&self) -> SequencerId {
        self.id
    }

    #[must_use]
    pub const fn last_issued(&self) -> u64 {
        self.counter.last_issued()
    }

    #[must_use]
    pub const fn active_count(&self) -> usize {
        self.active.len()
    }

    #[must_use]
    pub fn minimum_active(&self) -> Option<Issue> {
        self.active.minimum()
    }

    #[must_use]
    pub fn terminal_prefix(&self) -> u64 {
        self.active.terminal_prefix(&self.counter)
    }

    #[must_use]
    pub const fn verified_vdl_baseline(&self) -> u64 {
        self.verified_vdl_baseline
    }

    pub fn intervals(&self) -> impl Iterator<Item = &Interval> + '_ {
        self.ledger.intervals()
    }

    #[must_use]
    pub const fn unknown(&self) -> Option<Interval> {
        self.ledger.unknown()
    }

    #[must_use]
    pub const fn bind_size(&self, state: ValidatedSizeState) -> SizeSnapshot {
        SizeSnapshot {
            owner: self.id,
            trio: state.trio(),
            size_epoch: state.size_epoch(),
        }
    }

    #[must_use]
    pub const fn bind_truncation(&self, proof: Truncation<VdlClamped>) -> TruncateSnapshot {
        TruncateSnapshot {
            owner: self.id,
            trio: proof.trio(),
        }
    }

    #[must_use]
    pub const fn bind_claim(&self, result: ContextClaimResult) -> ContextClaim {
        ContextClaim {
            owner: self.id,
            result,
        }
    }

    /// Apply one same-owner, verified monotonically nondecreasing returned VDL.
    ///
    /// A normal returned-size snapshot may only advance this sequencer's
    /// baseline. The B3 truncation sequence has the separate
    /// [`truncate_reset`](Self::truncate_reset) entry point because its
    /// `VdlClamped` proof is the one authorized lower-reset capability.
    pub fn apply_verified_vdl(&mut self, snapshot: SizeSnapshot) -> Result<(), VdlRejection> {
        if snapshot.owner != self.id {
            return Err(VdlRejection::WrongSequencer);
        }
        let vdl = snapshot.trio.valid_data_length;
        if vdl < self.verified_vdl_baseline {
            return Err(VdlRejection::Regressed);
        }
        let Ok(()) = self.ledger.trim_to_vdl(self.verified_vdl_baseline, vdl) else {
            unreachable!("a validated same-owner monotonic VDL is in the ledger domain")
        };
        self.verified_vdl_baseline = vdl;
        Ok(())
    }

    /// Reset the VDL baseline after B3's fully committed and clamped truncate.
    ///
    /// Only [`TruncateSnapshot`] carries the consumed `Truncation<VdlClamped>`
    /// proof, so an ordinary [`SizeSnapshot`] cannot use this lower-reset path.
    pub fn truncate_reset(&mut self, snapshot: TruncateSnapshot) -> Result<(), VdlRejection> {
        if snapshot.owner != self.id {
            return Err(VdlRejection::WrongSequencer);
        }
        let vdl = snapshot.trio.valid_data_length;
        let Ok(()) = self.ledger.truncate_reset(vdl) else {
            unreachable!("a clamped truncation VDL is in the ledger domain")
        };
        self.verified_vdl_baseline = vdl;
        Ok(())
    }

    /// Observe one of the five never-clearing ledger events through the owner.
    pub fn observe_event(&mut self, event: LedgerEvent) {
        self.ledger.observe(event);
    }

    /// Decide whether this same-owner snapshot's VDL may advance to its target.
    ///
    /// Ownership is checked before reading admission or any other aggregate
    /// state, so an alien snapshot cannot learn whether this FCB is exhausted.
    pub fn advance_only_barrier(
        &self,
        snapshot: SizeSnapshot,
        end_of_file: u64,
    ) -> Result<Barrier, BarrierRejection> {
        if snapshot.owner != self.id {
            return Err(BarrierRejection::WrongSequencer);
        }
        if matches!(self.admission, AdmissionState::IssuesExhausted) {
            return Ok(Barrier::IssuesExhausted);
        }
        let target = target_vdl(end_of_file, snapshot.trio.file_size);
        Ok(self
            .ledger
            .advance_only_barrier(snapshot.trio.valid_data_length, target))
    }
}

// ============================================================ the evidence ledger

/// The failure status an unresolved interval carries.
///
/// §6: each interval *"carries the lowest issue that touched it and that
/// issue's registered failure status"*. Both of the statuses §6 names by name
/// come from `fsring-abi`, never from a literal here — `the_statuses_are_fsring_abis`
/// reads this module's own source to keep that true.
///
/// *"Registered"* is descriptive: `fsring-abi`'s registry
/// (`is_registered_completion_status_v21`) is keyed by **opcode**, and a paging
/// WRITE's failure status may come from the kernel rather than from a daemon
/// completion, so there is no opcode to key on. The status is taken as the
/// terminal path reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntervalStatus(i32);

impl IntervalStatus {
    /// §6's fail-closed status: *"an unproven suffix following a short
    /// `SUCCESS` carries the fail-closed `IO_DEVICE_ERROR` status rather than
    /// being assumed committed"*.
    #[must_use]
    const fn io_device_error() -> Self {
        Self(completion_status::IO_DEVICE_ERROR)
    }

    /// `07:294-299`'s status for a failed `WriteIrpContext` claim.
    #[must_use]
    const fn insufficient_resources() -> Self {
        Self(completion_status::INSUFFICIENT_RESOURCES)
    }

    /// The status a terminal path registered for its issue.
    #[must_use]
    const fn registered(status: FailureStatus) -> Self {
        Self(status.get())
    }

    /// The NTSTATUS value.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// One unresolved byte range and the evidence attached to it.
///
/// Private fields behind a checked constructor, so **every** range in the
/// ledger has passed `04 §8.1`'s domain — there is exactly one place that
/// builds one, and it calls `fsring_abi::limits::validate_file_range` first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    start: u64,
    end: u64,
    lowest_issue: Issue,
    status: IntervalStatus,
}

impl Interval {
    /// A range `[start, end)` carrying `lowest_issue`'s failure status.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Range`] with `fsring-abi`'s own reason. An empty or
    /// inverted range is [`RangeError::ZeroLength`]: it carries no evidence, so
    /// the interval algebra reads `Err` as *"this piece vanished"* rather than
    /// as a fault. That is why trimming and splitting can be written as
    /// constructor calls whose failures mean deletion.
    pub fn new(
        start: u64,
        end: u64,
        lowest_issue: Issue,
        status: IntervalStatus,
    ) -> Result<Self, LedgerError> {
        // Saturating, so an inverted range becomes a zero length and is refused
        // by the frozen validator rather than by a rule restated here.
        let length = end.saturating_sub(start);
        match validate_file_range(start, length, false) {
            Ok(()) => Ok(Self {
                start,
                end,
                lowest_issue,
                status,
            }),
            Err(reason) => Err(LedgerError::Range(reason)),
        }
    }

    /// First byte.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// One past the last byte.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// The lowest issue that touched this range.
    #[must_use]
    pub const fn lowest_issue(&self) -> Issue {
        self.lowest_issue
    }

    /// That issue's failure status.
    #[must_use]
    pub const fn status(&self) -> IntervalStatus {
        self.status
    }

    /// Whether `byte` lies in this range.
    #[must_use]
    pub const fn covers(&self, byte: u64) -> bool {
        self.start <= byte && byte < self.end
    }

    /// Whether the two ranges overlap **or abut**. Abutting counts: the live
    /// intervals are kept strictly separated, so two that touch are one.
    const fn touches(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// The two ranges as one, carrying the **lower** issue and that issue's
    /// status — `07:334-335`'s *"preserving the lowest issue and its status"*.
    ///
    /// Returns `None` only if the union leaves `04 §8.1`'s domain, which it
    /// cannot: a union of two in-domain ranges is in domain.
    fn fused(&self, other: &Self) -> Option<Self> {
        let (issue, status) = if self.lowest_issue <= other.lowest_issue {
            (self.lowest_issue, self.status)
        } else {
            (other.lowest_issue, other.status)
        };
        Self::new(
            self.start.min(other.start),
            self.end.max(other.end),
            issue,
            status,
        )
        .ok()
    }

    /// What is left of this interval once `[from, to)` is proven committed:
    /// the piece below and the piece above, each `None` when empty.
    ///
    /// No special case for "no overlap" — the formula already returns the
    /// interval unchanged as exactly one of the two pieces.
    #[cfg_attr(not(test), allow(dead_code))]
    fn minus(&self, from: u64, to: u64) -> [Option<Self>; 2] {
        let below = Self::new(
            self.start,
            self.end.min(from),
            self.lowest_issue,
            self.status,
        )
        .ok();
        let above = Self::new(self.start.max(to), self.end, self.lowest_issue, self.status).ok();
        [below, above]
    }
}

/// A byte range proven committed by the provider. No issue, no status: it is
/// the absence of evidence, not evidence.
///
/// Non-empty by construction, through the same funnel as [`Interval`]. A
/// terminal path that proved *nothing* passes `None` rather than an empty
/// range, so there is no degenerate range anywhere in the algebra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    start: u64,
    end: u64,
}

impl Coverage {
    /// Proven coverage over `[start, end)`.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Range`], with `fsring-abi`'s reason, including for an
    /// empty range.
    pub fn new(start: u64, end: u64) -> Result<Self, LedgerError> {
        let length = end.saturating_sub(start);
        match validate_file_range(start, length, false) {
            Ok(()) => Ok(Self { start, end }),
            Err(reason) => Err(LedgerError::Range(reason)),
        }
    }

    /// First proven byte.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// One past the last proven byte.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }
}

/// Whether the overflow-node reservation this update needs actually succeeded.
///
/// An **explicit parameter** rather than a field of [`NodeBudget`]: a budget
/// says how many nodes the update was allowed to preclaim, and a reservation
/// says whether the pools gave them. Folding the two together made
/// [`MergeTrigger::ReservationFailed`] and [`MergeTrigger::BudgetExhausted`]
/// indistinguishable from their inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// The overflow nodes this update needs are reserved.
    Granted,
    /// The reservation failed. §6 routes this to the inline UNKNOWN fallback.
    Failed,
}

/// How many overflow nodes a terminal update preclaimed before entering the
/// size gate/sequencer pair.
///
/// Behind a checked constructor for the same reason [`Interval`] is: §6 caps
/// the preclaim, and a budget constructible above its own cap would let an
/// update allocate under the sequencer lock — the thing §6's fallback exists to
/// prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeBudget {
    preclaimed: u64,
}

impl NodeBudget {
    /// Preclaim `nodes` overflow nodes.
    ///
    /// # Errors
    ///
    /// [`LedgerError::BudgetTooLarge`] above
    /// `PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES`.
    pub const fn preclaim(nodes: u64) -> Result<Self, LedgerError> {
        if nodes > PRECLAIM_NODES {
            return Err(LedgerError::BudgetTooLarge);
        }
        Ok(Self { preclaimed: nodes })
    }

    /// How many nodes were preclaimed.
    #[must_use]
    pub const fn preclaimed(&self) -> u64 {
        self.preclaimed
    }

    /// What is left of this preclaim after an update took the ordinary count
    /// from `before` to `after`.
    ///
    /// A completion makes two ledger updates under **one** preclaim, so the
    /// second must not be handed the first's nodes again. Without this a
    /// preclaim of 1 would fund a split and then a fresh interval — one node
    /// more than §6 permits to be allocated under the lock.
    #[cfg_attr(not(test), allow(dead_code))]
    fn after_spending(self, before: usize, after: usize) -> Self {
        let spent = Ledger::overflow_nodes(after).saturating_sub(Ledger::overflow_nodes(before));
        Self {
            preclaimed: self.preclaimed.saturating_sub(spent),
        }
    }
}

/// Why the ledger fell back to the inline UNKNOWN span.
///
/// The four §6 gives, and no more. Each is returned so a test can name **which**
/// one fired rather than only that something did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeTrigger {
    /// *"If a split would exceed the per-FCB interval bound"*.
    IntervalBound,
    /// *"an overflow-node reservation fails"*.
    ReservationFailed,
    /// *"or exact checked representation cannot be maintained"*.
    ///
    /// **No host path produces this**, and that is stated rather than hidden:
    /// every range here is pre-validated at or below `MAX_FILE_SIZE`, and
    /// subrange arithmetic on `u64` cannot lose exactness. The variant exists
    /// because the document names it; the gate's PENDING block carries it.
    Inexact,
    /// *"any update that needs more takes the inline UNKNOWN fallback instead
    /// of allocating under the lock"*.
    BudgetExhausted,
}

/// What one mutating operation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Held exactly, as ordinary intervals.
    Recorded,
    /// Nothing to do: the range lies wholly below the current VDL. §6:
    /// *"Coverage intersection starts at the current VDL, so bytes already
    /// below VDL never block a future prefix advance."*
    BelowVdl,
    /// Everything unresolved was merged into the inline UNKNOWN span.
    Merged(MergeTrigger),
}

/// §6's evidence ledger: the ordinary unresolved intervals plus the one inline
/// UNKNOWN accumulator.
///
/// **Invariant, and every operation preserves it:** the live ordinary intervals
/// are ascending and *strictly* separated — `prev.end < next.start`. Two that
/// would touch are one, fused under the lower issue. That is what makes the
/// touching set of any range a contiguous run, so a single pass finds it.
///
/// **The host stand-in, named.** §6's *"bounded nonpaged overflow nodes"* are
/// allocations this crate cannot make, so the slots beyond
/// `INLINE_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB` are modelled as inline array
/// slots whose *availability* is an input ([`NodeBudget`], [`Reservation`])
/// rather than an allocation. What is checked is the decision, not the malloc.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ledger {
    ordinary: [Option<Interval>; MAX_INTERVALS],
    len: usize,
    unknown: Option<Interval>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum UnknownOrientation {
    LowerInline,
    UpperInline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
struct SubtractProjection {
    ordinary: [Option<Interval>; MAX_INTERVALS],
    len: usize,
    unknown: Option<Interval>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SubtractProjection {
    fn overflow_nodes(&self) -> u64 {
        u64::try_from(self.len.saturating_sub(INLINE_INTERVALS)).unwrap_or(u64::MAX)
    }

    fn new_nodes(&self, before_len: usize) -> u64 {
        let before = u64::try_from(before_len.saturating_sub(INLINE_INTERVALS)).unwrap_or(u64::MAX);
        self.overflow_nodes().saturating_sub(before)
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl Ledger {
    /// A ledger with no evidence.
    #[must_use]
    const fn new() -> Self {
        Self {
            ordinary: [None; MAX_INTERVALS],
            len: 0,
            unknown: None,
        }
    }

    /// How many ordinary intervals are held. The UNKNOWN span is not one.
    #[must_use]
    const fn len(&self) -> usize {
        self.len
    }

    /// Whether any evidence at all is held.
    #[must_use]
    const fn is_empty(&self) -> bool {
        self.len == 0 && self.unknown.is_none()
    }

    /// The inline UNKNOWN accumulator, if it holds anything.
    #[must_use]
    const fn unknown(&self) -> Option<Interval> {
        self.unknown
    }

    /// The ordinary intervals, ascending and strictly separated.
    fn intervals(&self) -> impl Iterator<Item = &Interval> + '_ {
        self.ordinary
            .get(..self.len)
            .unwrap_or(&[])
            .iter()
            .flatten()
    }

    /// Every piece of evidence, ordinary and UNKNOWN alike.
    ///
    /// The barrier reads this: `06:336-338` makes the UNKNOWN span a blocking
    /// candidate exactly as an ordinary interval is.
    fn evidence(&self) -> impl Iterator<Item = &Interval> + '_ {
        self.intervals().chain(self.unknown.iter())
    }

    /// Record a terminal path's unproven range.
    ///
    /// `07:314-317`: *"each terminal (failed) path records every requested byte
    /// range it cannot prove committed"*. The range is first intersected with
    /// `[vdl, …)`; if nothing is left, there is nothing to record.
    ///
    /// If the exact representation does not fit — §6's three triggers plus the
    /// preclaim budget — everything unresolved merges into the inline UNKNOWN
    /// span instead. Nothing is ever dropped.
    fn record_failure(
        &mut self,
        range: Interval,
        vdl: u64,
        budget: NodeBudget,
        reservation: Reservation,
    ) -> RecordOutcome {
        let Ok(clamped) = Interval::new(
            range.start.max(vdl),
            range.end,
            range.lowest_issue,
            range.status,
        ) else {
            return RecordOutcome::BelowVdl;
        };

        let touching = self.intervals().filter(|e| e.touches(&clamped)).count();
        let projected = self.len.saturating_sub(touching).saturating_add(1);
        if let Some(trigger) = Self::degradation(self.len, projected, budget, reservation) {
            return self.merge_to_unknown(Some(clamped), trigger);
        }
        self.insert_fusing(clamped)
    }

    /// Credit a verified commit against the outstanding evidence.
    ///
    /// §6: *"A later verified WRITE commit subtracts exactly its proven coverage
    /// from the outstanding intervals."* Carries the **same** seam as
    /// [`record_failure`](Self::record_failure), because subtracting from the
    /// middle of an interval *splits* it — and `07:331` starts its degradation
    /// rule with *"If a **split** would exceed the per-FCB interval bound"*.
    ///
    /// When the split does not fit, the ledger merges rather than subtracting:
    /// the credit is simply not taken. Keeping evidence that could have been
    /// discharged is the conservative direction.
    fn subtract_proven(
        &mut self,
        range: Coverage,
        vdl: u64,
        budget: NodeBudget,
        reservation: Reservation,
    ) -> RecordOutcome {
        // Clamped like a recording, and for the same reason. Subtracting less
        // keeps more evidence, so the clamp errs safely in any case.
        let from = range.start.max(vdl);
        if from >= range.end {
            return RecordOutcome::BelowVdl;
        }

        let lower = self.project_subtraction(from, range.end, UnknownOrientation::LowerInline);
        let projection = match self.unknown {
            Some(span) if matches!(span.minus(from, range.end), [Some(_), Some(_)]) => {
                let upper =
                    self.project_subtraction(from, range.end, UnknownOrientation::UpperInline);
                if upper.new_nodes(self.len) < lower.new_nodes(self.len) {
                    upper
                } else {
                    lower
                }
            }
            _ => lower,
        };
        if let Some(trigger) = Self::degradation(self.len, projection.len, budget, reservation) {
            return self.merge_to_unknown(None, trigger);
        }

        let SubtractProjection {
            ordinary,
            len,
            unknown,
        } = projection;
        self.ordinary = ordinary;
        self.len = len;
        self.unknown = unknown;
        RecordOutcome::Recorded
    }

    /// Build an exact subtraction result without changing the live ledger.
    ///
    /// A middle UNKNOWN split keeps one residual inline and moves the other
    /// into ordinary evidence. The caller compares both complete candidates
    /// against the live count before selecting the inline side.
    fn project_subtraction(
        &self,
        from: u64,
        to: u64,
        orientation: UnknownOrientation,
    ) -> SubtractProjection {
        // A contiguous proof can add only one ordinary split piece, and a
        // middle UNKNOWN split can add one more. Keep every exact piece until
        // the MAX_INTERVALS gate decides whether it can become live state.
        let mut pieces: [Option<Interval>; MAX_INTERVALS + 2] = [None; MAX_INTERVALS + 2];
        let mut pieces_len = 0usize;
        let mut push_piece = |piece: Interval| {
            if let Some(slot) = pieces.get_mut(pieces_len) {
                *slot = Some(piece);
                pieces_len = pieces_len.saturating_add(1);
            }
        };

        for existing in self.intervals() {
            for piece in existing.minus(from, to).into_iter().flatten() {
                push_piece(piece);
            }
        }

        let mut unknown = None;
        if let Some(span) = self.unknown {
            let [lower, upper] = span.minus(from, to);
            match (lower, upper) {
                (Some(lower), Some(upper)) => match orientation {
                    UnknownOrientation::LowerInline => {
                        unknown = Some(lower);
                        push_piece(upper);
                    }
                    UnknownOrientation::UpperInline => {
                        unknown = Some(upper);
                        push_piece(lower);
                    }
                },
                (Some(only), None) | (None, Some(only)) => unknown = Some(only),
                (None, None) => {}
            }
        }

        let mut at = 1usize;
        while at < pieces_len {
            let Some(previous) = pieces.get(at.saturating_sub(1)).copied().flatten() else {
                break;
            };
            let Some(current) = pieces.get(at).copied().flatten() else {
                break;
            };
            if previous.start <= current.start {
                at = at.saturating_add(1);
            } else {
                pieces.swap(at.saturating_sub(1), at);
                at = at.saturating_sub(1);
            }
        }

        let mut fused: [Option<Interval>; MAX_INTERVALS + 2] = [None; MAX_INTERVALS + 2];
        let mut fused_len = 0usize;
        for piece in pieces.get(..pieces_len).unwrap_or(&[]).iter().flatten() {
            if let Some(Some(last)) = fused.get_mut(fused_len.saturating_sub(1)) {
                if last.touches(piece) {
                    let Some(merged) = last.fused(piece) else {
                        unreachable!("a union of checked intervals remains checked");
                    };
                    *last = merged;
                    continue;
                }
            }
            if let Some(slot) = fused.get_mut(fused_len) {
                *slot = Some(*piece);
                fused_len = fused_len.saturating_add(1);
            }
        }

        let mut ordinary = [None; MAX_INTERVALS];
        for (slot, piece) in ordinary.iter_mut().zip(fused.iter().flatten()) {
            *slot = Some(*piece);
        }
        SubtractProjection {
            ordinary,
            len: fused_len,
            unknown,
        }
    }

    /// Apply a verified, monotonically increasing returned VDL.
    ///
    /// §6: *"a verified, monotonically increasing returned VDL trims each
    /// interval to the portion above that VDL and deletes any interval that
    /// falls entirely below it."*
    ///
    /// The baseline is a **parameter**, not an internal high-water mark:
    /// `07 §5` step 5 sets `valid_data_length = min(VDL, EOF)` after a truncate
    /// commit, so VDL legitimately regresses outside the returned-VDL stream.
    /// Against an internal mark every post-truncate trim would be rejected
    /// forever, stale intervals would never trim, and `07:341-343`'s clear
    /// conditions would become unreachable — a permanent liveness failure no
    /// document sanctions. [`truncate_reset`](Self::truncate_reset) is the
    /// truncate path's entry point.
    ///
    /// **No seam, and that is deliberate:** a trim is a prefix cut and can only
    /// shrink or delete, never split, so it can never need a node.
    ///
    /// # Errors
    ///
    /// [`LedgerError::VdlRegressed`] when `vdl < previous_verified`;
    /// [`LedgerError::Range`] when `vdl` leaves `04 §8.1`'s domain.
    fn trim_to_vdl(&mut self, previous_verified: u64, vdl: u64) -> Result<(), LedgerError> {
        if vdl < previous_verified {
            return Err(LedgerError::VdlRegressed);
        }
        if vdl > MAX_FILE_SIZE {
            return Err(LedgerError::Range(RangeError::OffsetOutOfRange));
        }
        self.apply_vdl(vdl);
        Ok(())
    }

    /// Reset the trim baseline to a truncate's new VDL.
    ///
    /// What B3's `Truncation` sequence produces at its step 5. Identical to
    /// [`trim_to_vdl`](Self::trim_to_vdl) except that it accepts a **lower**
    /// VDL, because a truncate is exactly the case `07:323-326`'s monotonicity
    /// precondition does not cover.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Range`] when `new_vdl` leaves `04 §8.1`'s domain.
    fn truncate_reset(&mut self, new_vdl: u64) -> Result<(), LedgerError> {
        if new_vdl > MAX_FILE_SIZE {
            return Err(LedgerError::Range(RangeError::OffsetOutOfRange));
        }
        self.apply_vdl(new_vdl);
        Ok(())
    }

    /// Observe one of §6's five never-clearing events.
    ///
    /// §6: *"Waiter absence, timeout, CLEANUP, a session fence, or ATTACH never
    /// discards or normalizes a recorded failure."*
    ///
    /// **It does nothing, and that is the deliverable.** The events themselves
    /// are dispatched elsewhere; what this fixes is that the slice wiring
    /// `IRP_MJ_CLEANUP` has one obvious place to call, and that place is empty
    /// on purpose.
    ///
    /// It takes `&mut self` **deliberately**, though it never writes. A `&self`
    /// signature would make the prohibition structurally unbreakable and the
    /// five named tests simultaneously vacuous — a guard that cannot see the
    /// thing it guards. A prohibition can only be checked somewhere the
    /// forbidden write is expressible, so this is that somewhere: each event
    /// has a test asserting the ledger is unchanged afterwards, and a mutation
    /// that lets one of them clear reddens that event's test alone.
    fn observe(&mut self, event: LedgerEvent) {
        // Deliberately empty; see above. `07:343-345` and `06:295-296`.
        let _ = event;
    }

    /// Which of §6's triggers fires, if any, for an update taking the ordinary
    /// count from `before` to `projected`.
    ///
    /// Tested in the document's own order: the interval bound, then the
    /// reservation, then exactness, then the preclaim budget — which is the
    /// order §6 lists them in, the last one coming from its own sentence.
    fn degradation(
        before: usize,
        projected: usize,
        budget: NodeBudget,
        reservation: Reservation,
    ) -> Option<MergeTrigger> {
        if projected > MAX_INTERVALS {
            return Some(MergeTrigger::IntervalBound);
        }
        let needed = Self::overflow_nodes(projected).saturating_sub(Self::overflow_nodes(before));
        if needed > 0 && reservation == Reservation::Failed {
            return Some(MergeTrigger::ReservationFailed);
        }
        // MergeTrigger::Inexact would be tested here. Nothing on the host can
        // produce it; see the variant's documentation.
        if needed > budget.preclaimed() {
            return Some(MergeTrigger::BudgetExhausted);
        }
        None
    }

    /// How many overflow nodes an ordinary count of `n` needs.
    fn overflow_nodes(n: usize) -> u64 {
        u64::try_from(n.saturating_sub(INLINE_INTERVALS)).unwrap_or(u64::MAX)
    }

    /// §6's fallback: *"merges all affected evidence into the inline UNKNOWN
    /// span covering the minimum unresolved start through the maximum
    /// unresolved end, preserving the lowest issue and its status."*
    ///
    /// `extra` is the range the failed update was trying to record, which is
    /// affected evidence too. A failed *subtraction* passes `None`: the credit
    /// is not taken, so nothing is added.
    fn merge_to_unknown(
        &mut self,
        extra: Option<Interval>,
        trigger: MergeTrigger,
    ) -> RecordOutcome {
        let mut span = match (extra, self.unknown) {
            (Some(a), Some(b)) => a.fused(&b),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };
        for existing in self.intervals() {
            span = match span {
                Some(s) => s.fused(existing),
                None => Some(*existing),
            };
        }
        self.ordinary = [None; MAX_INTERVALS];
        self.len = 0;
        self.unknown = span;
        RecordOutcome::Merged(trigger)
    }

    /// Insert `iv`, fusing it with every interval it overlaps or abuts.
    ///
    /// The touching set is computed against `iv` as given, not against the
    /// growing union: because the live intervals are strictly separated, an
    /// interval that does not touch `iv` cannot touch the union either, so one
    /// pass is exact.
    ///
    /// **The overflow arm cannot fire, and it is here anyway.**
    /// [`Self::degradation`] has already refused anything projecting past
    /// `MAX_INTERVALS`, and this loop emits exactly that projection, so no slot
    /// write can miss. If that arithmetic were ever wrong the alternative was a
    /// piece falling silently on the floor — which is *this module's worst
    /// failure mode reached through its own back door*. It merges instead, so
    /// the wrong answer is conservative rather than lost.
    fn insert_fusing(&mut self, iv: Interval) -> RecordOutcome {
        let mut merged = iv;
        for existing in self.intervals() {
            if existing.touches(&iv) {
                if let Some(f) = merged.fused(existing) {
                    merged = f;
                }
            }
        }

        let mut kept: [Option<Interval>; MAX_INTERVALS] = [None; MAX_INTERVALS];
        let mut n = 0usize;
        let mut placed = false;
        let mut overflowed = false;
        {
            let mut push =
                |value: Interval, n: &mut usize, overflowed: &mut bool| match kept.get_mut(*n) {
                    Some(slot) => {
                        *slot = Some(value);
                        *n = n.saturating_add(1);
                    }
                    None => *overflowed = true,
                };
            for existing in self
                .ordinary
                .get(..self.len)
                .unwrap_or(&[])
                .iter()
                .flatten()
            {
                if existing.touches(&iv) {
                    continue;
                }
                if !placed && merged.start < existing.start {
                    push(merged, &mut n, &mut overflowed);
                    placed = true;
                }
                push(*existing, &mut n, &mut overflowed);
            }
            if !placed {
                push(merged, &mut n, &mut overflowed);
            }
        }

        if overflowed {
            return self.merge_to_unknown(Some(iv), MergeTrigger::IntervalBound);
        }
        self.ordinary = kept;
        self.len = n;
        RecordOutcome::Recorded
    }

    /// Trim every interval to the portion above `vdl` and delete those wholly
    /// below it. Shared by the two VDL entry points.
    fn apply_vdl(&mut self, vdl: u64) {
        let mut kept: [Option<Interval>; MAX_INTERVALS] = [None; MAX_INTERVALS];
        let mut n = 0usize;
        for existing in self.intervals() {
            // A constructor failure IS the deletion: an interval wholly below
            // `vdl` trims to an empty range, which `Interval::new` refuses.
            if let Ok(trimmed) = Interval::new(
                existing.start.max(vdl),
                existing.end,
                existing.lowest_issue,
                existing.status,
            ) {
                if let Some(slot) = kept.get_mut(n) {
                    *slot = Some(trimmed);
                    n = n.saturating_add(1);
                }
            }
        }
        self.ordinary = kept;
        self.len = n;
        self.unknown = self.unknown.and_then(|span| {
            Interval::new(
                span.start.max(vdl),
                span.end,
                span.lowest_issue,
                span.status,
            )
            .ok()
        });
    }

    /// §7's `AdvanceOnly` precondition, as a query on the evidence.
    ///
    /// §7 permits the advance *"only … once the ledger shows no unresolved or
    /// `UNKNOWN` evidence intersecting `[current VDL, target_vdl)`; if such
    /// evidence exists, the lowest-issue unresolved interval becomes the local
    /// failure candidate"*. So the answer is not a bool — a blocked barrier
    /// names who blocked it.
    ///
    /// A target at or below `vdl` is [`Barrier::Clear`] **even with evidence
    /// above it** (`06:334-336`, `05:926-928`): there is nothing to advance
    /// over, so no evidence can be intersecting.
    ///
    /// The UNKNOWN span is a candidate exactly as an ordinary interval is
    /// (`06:336-338`). On a tie in issue number the ordinary interval is named,
    /// because it is the more precise description of the same blockage.
    ///
    /// **What this does not do:** it does not perform the advance, and nothing
    /// here ties an advance to a `Clear` the way a terminal receipt ties removal
    /// to recording. §7 says the barrier *"MUST precede the VDL advance"*; that
    /// weld belongs to the `AdvanceOnly` slice and is carried in the gate's
    /// PENDING block rather than quietly assumed.
    #[must_use]
    fn advance_only_barrier(&self, vdl: u64, target: u64) -> Barrier {
        if target <= vdl {
            return Barrier::Clear;
        }
        let blocking = |i: &&Interval| i.end > vdl && i.start < target;
        let ordinary = self.intervals().filter(blocking).map(|i| Candidate {
            interval: *i,
            kind: CandidateKind::Ordinary,
        });
        let unknown = self.unknown.iter().filter(blocking).map(|i| Candidate {
            interval: *i,
            kind: CandidateKind::Unknown,
        });
        match ordinary
            .chain(unknown)
            .min_by_key(|c| c.interval.lowest_issue)
        {
            None => Barrier::Clear,
            Some(candidate) => Barrier::Blocked(candidate),
        }
    }
}

/// §7's VDL advance target: *"advance to `target_vdl = min(EndOfFile, current
/// file_size)`"*.
///
/// The **minimum**. A maximum would advance the VDL past the end of the file,
/// publishing storage the daemon never accounted for — the failure this whole
/// module exists to prevent, reachable by one wrong function name.
#[must_use]
pub const fn target_vdl(end_of_file: u64, file_size: u64) -> u64 {
    if end_of_file < file_size {
        end_of_file
    } else {
        file_size
    }
}

/// Which slot a blocking [`Candidate`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// One of the ordinary unresolved intervals.
    Ordinary,
    /// The inline UNKNOWN accumulator. `06:336-338` makes it a candidate too.
    Unknown,
}

/// The evidence that blocked an `AdvanceOnly`, and where it lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    interval: Interval,
    kind: CandidateKind,
}

impl Candidate {
    /// The blocking evidence.
    #[must_use]
    pub const fn interval(&self) -> Interval {
        self.interval
    }

    /// Ordinary interval or UNKNOWN span.
    #[must_use]
    pub const fn kind(&self) -> CandidateKind {
        self.kind
    }

    /// The issue that becomes §7's local failure candidate.
    #[must_use]
    pub const fn issue(&self) -> Issue {
        self.interval.lowest_issue
    }
}

/// Whether the ordered write barrier permits a VDL advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Barrier {
    /// No unresolved or UNKNOWN evidence intersects the range.
    Clear,
    /// Evidence intersects it, and this is the lowest-issue piece.
    Blocked(Candidate),
    /// Issuance is permanently closed, so no VDL advance may be admitted.
    IssuesExhausted,
}

// ================================= the linearization order, as a typestate

/// The range is extracted; no issue exists yet.
///
/// `07:296-302` puts checked extraction first, the bounded context claim
/// second, and the issue allocation third — *"only after that linearization may
/// dispatch validate the MDL, reserve the common admission quota ticket, map
/// pages, or take any further fallible step."*
#[derive(Debug)]
pub struct Extracted(());

/// The issue is allocated and the context is linked into the active set.
#[derive(Debug)]
pub struct Linearized {
    owner: SequencerId,
    issue: Issue,
}

/// One paging WRITE, in one of the two states §6's ordering distinguishes.
///
/// The fallible steps exist on [`Linearized`] and on nothing else, so taking
/// one before linearization does not type-check. Three compile-fail fixtures
/// prove it for the three §6 names; *"or take any further fallible step"* is an
/// open class no fixture count can close, and that is said rather than implied.
#[derive(Debug)]
pub struct PagingWrite<S> {
    range: Coverage,
    state: S,
}

impl<S> PagingWrite<S> {
    /// The extracted native `[offset, end)` range.
    #[must_use]
    pub const fn range(&self) -> Coverage {
        self.range
    }
}

impl PagingWrite<Extracted> {
    /// `07:296-297`'s *"checked extraction of the immutable native `[offset,
    /// end)` range"*, through [`Coverage`]'s funnel.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Range`] with `fsring-abi`'s reason.
    pub fn extract(offset: u64, end: u64) -> Result<Self, LedgerError> {
        Ok(Self {
            range: Coverage::new(offset, end)?,
            state: Extracted(()),
        })
    }
}

impl PagingWrite<Linearized> {
    /// The sequencer that admitted this affine write.
    #[must_use]
    pub const fn owner(&self) -> SequencerId {
        self.state.owner
    }

    /// The issue this write was linearized under.
    #[must_use]
    pub const fn issue(&self) -> Issue {
        self.state.issue
    }

    /// Validate the MDL — the first of §6's three named post-linearization
    /// steps.
    ///
    /// Returns the issue the step is charged to, which is the whole point of
    /// the ordering: after linearization every fallible step has a number, so
    /// *"no paging WRITE with a valid extracted range ever returns an
    /// unnumbered failure"*. The MDL itself belongs to `fsring-sys`; what is
    /// modelled here is **where** the step may be taken.
    #[must_use]
    pub const fn validate_mdl(&self) -> Issue {
        self.state.issue
    }

    /// Reserve the common admission quota ticket — §6's second named step.
    /// `06 §5.1` owns the ticket itself.
    #[must_use]
    pub const fn reserve_ticket(&self) -> Issue {
        self.state.issue
    }

    /// Map pages — §6's third named step.
    #[must_use]
    pub const fn map_pages(&self) -> Issue {
        self.state.issue
    }
}

impl SequencerState {
    /// Complete an active write after all ownership, liveness, and coverage
    /// checks have passed. Rejection returns the untouched affine write.
    pub fn complete(
        &mut self,
        write: PagingWrite<Linearized>,
        snapshot: SizeSnapshot,
        budget: NodeBudget,
        reservation: Reservation,
        proven: Option<Coverage>,
    ) -> Result<ActiveTerminalReceipt, WriteRejection> {
        if write.owner() != self.id {
            return Err(WriteRejection {
                reason: WriteRejectionReason::WrongSequencer,
                write,
            });
        }
        if snapshot.owner != self.id {
            return Err(WriteRejection {
                reason: WriteRejectionReason::WrongSizeOwner,
                write,
            });
        }
        let Some(active) = self.active.preflight(write.issue()) else {
            return Err(WriteRejection {
                reason: WriteRejectionReason::NotActive,
                write,
            });
        };
        let proven_end = match proven {
            Some(committed)
                if committed.start != write.range.start || committed.end > write.range.end =>
            {
                return Err(WriteRejection {
                    reason: WriteRejectionReason::CoverageOutsideRequest,
                    write,
                });
            }
            Some(committed) => committed.end,
            None => write.range.start,
        };

        let issue = write.issue();
        let mut outcome = RecordOutcome::BelowVdl;
        let mut remaining = budget;
        if let Some(committed) = proven {
            let before = self.ledger.len();
            outcome = worse(
                outcome,
                self.ledger.subtract_proven(
                    committed,
                    snapshot.trio.valid_data_length,
                    remaining,
                    reservation,
                ),
            );
            remaining = remaining.after_spending(before, self.ledger.len());
        }
        if proven_end < write.range.end {
            let suffix = Interval {
                start: proven_end,
                end: write.range.end,
                lowest_issue: issue,
                status: IntervalStatus::io_device_error(),
            };
            outcome = worse(
                outcome,
                self.ledger.record_failure(
                    suffix,
                    snapshot.trio.valid_data_length,
                    remaining,
                    reservation,
                ),
            );
        }
        self.active.remove_preflighted(active);
        let prefix = self.active.terminal_prefix(&self.counter);
        Ok(ActiveTerminalReceipt {
            owner: self.id,
            issue,
            prefix,
            outcome,
            terminal_kind: TerminalKind::Completed,
        })
    }

    /// Terminalize an active failed write after ownership and liveness checks.
    /// Rejection returns the untouched affine write.
    pub fn terminalize(
        &mut self,
        write: PagingWrite<Linearized>,
        snapshot: SizeSnapshot,
        budget: NodeBudget,
        reservation: Reservation,
        status: FailureStatus,
    ) -> Result<ActiveTerminalReceipt, WriteRejection> {
        if write.owner() != self.id {
            return Err(WriteRejection {
                reason: WriteRejectionReason::WrongSequencer,
                write,
            });
        }
        if snapshot.owner != self.id {
            return Err(WriteRejection {
                reason: WriteRejectionReason::WrongSizeOwner,
                write,
            });
        }
        let Some(active) = self.active.preflight(write.issue()) else {
            return Err(WriteRejection {
                reason: WriteRejectionReason::NotActive,
                write,
            });
        };

        let issue = write.issue();
        let range = Interval {
            start: write.range.start,
            end: write.range.end,
            lowest_issue: issue,
            status: IntervalStatus::registered(status),
        };
        let outcome =
            self.ledger
                .record_failure(range, snapshot.trio.valid_data_length, budget, reservation);
        self.active.remove_preflighted(active);
        let prefix = self.active.terminal_prefix(&self.counter);
        Ok(ActiveTerminalReceipt {
            owner: self.id,
            issue,
            prefix,
            outcome,
            terminal_kind: TerminalKind::Failed,
        })
    }

    /// Preflight owner brands and consume one context claim in the owning FCB.
    pub fn admit(
        &mut self,
        write: PagingWrite<Extracted>,
        snapshot: SizeSnapshot,
        claim: ContextClaim,
    ) -> AdmissionOutcome {
        if snapshot.owner != self.id {
            return AdmissionOutcome::Rejected(AdmissionRejection {
                reason: AdmissionRejectionReason::WrongSizeOwner,
                write,
                snapshot,
                claim,
            });
        }
        if claim.owner != self.id {
            return AdmissionOutcome::Rejected(AdmissionRejection {
                reason: AdmissionRejectionReason::WrongClaimOwner,
                write,
                snapshot,
                claim,
            });
        }
        if matches!(self.admission, AdmissionState::IssuesExhausted) {
            return self.mount_fatal(write.range, claim);
        }

        match claim.result {
            ContextClaimResult::Failed => self.claim_rejected(write, claim),
            ContextClaimResult::Acquired => match self.active.allocate(&mut self.counter) {
                Ok(issue) => AdmissionOutcome::InFlight(PagingWrite {
                    range: write.range,
                    state: Linearized {
                        owner: self.id,
                        issue,
                    },
                }),
                Err(LedgerError::ActiveContextsExhausted) => self.claim_rejected(write, claim),
                Err(LedgerError::IssuesExhausted | LedgerError::IssueOutOfOrder) => {
                    self.mount_fatal(write.range, claim)
                }
                Err(
                    LedgerError::NotActive
                    | LedgerError::Range(_)
                    | LedgerError::BudgetTooLarge
                    | LedgerError::VdlRegressed
                    | LedgerError::CoverageOutsideRequest,
                ) => self.mount_fatal(write.range, claim),
            },
        }
    }

    fn claim_rejected(
        &mut self,
        write: PagingWrite<Extracted>,
        claim: ContextClaim,
    ) -> AdmissionOutcome {
        let issue = match self.counter.next() {
            Ok(issue) => issue,
            Err(_) => return self.mount_fatal(write.range, claim),
        };
        let range = match Interval::new(
            write.range.start,
            write.range.end,
            issue,
            IntervalStatus::insufficient_resources(),
        ) {
            Ok(range) => range,
            Err(_) => return self.mount_fatal(write.range, claim),
        };
        let budget = match NodeBudget::preclaim(0) {
            Ok(budget) => budget,
            Err(_) => return self.mount_fatal(write.range, claim),
        };
        let outcome = self.ledger.record_failure(
            range,
            self.verified_vdl_baseline,
            budget,
            Reservation::Failed,
        );
        AdmissionOutcome::ClaimRejected {
            receipt: ClaimRejectedReceipt {
                owner: self.id,
                issue,
                prefix: self.active.terminal_prefix(&self.counter),
                outcome,
            },
            claim,
        }
    }

    fn mount_fatal(&mut self, range: Coverage, claim: ContextClaim) -> AdmissionOutcome {
        self.admission = AdmissionState::IssuesExhausted;
        AdmissionOutcome::MountFatal {
            failure: IssueExhaustion {
                owner: self.id,
                range,
            },
            claim,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
const fn worse(a: RecordOutcome, b: RecordOutcome) -> RecordOutcome {
    match (a, b) {
        (RecordOutcome::Merged(t), _) => RecordOutcome::Merged(t),
        (_, RecordOutcome::Merged(t)) => RecordOutcome::Merged(t),
        (RecordOutcome::Recorded, _) | (_, RecordOutcome::Recorded) => RecordOutcome::Recorded,
        _ => RecordOutcome::BelowVdl,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        size::{
            self, EpochCapture, IoOrigin, MmVerdict, SizeChange, SizeTrio, Truncation,
            ValidatedSizeState, VdlClamped, publish_sizes_to_cc,
        },
        typestate::passive_at_driver_entry,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    const CACHE_DOC: &str = include_str!("../../../docs/design/07-cache-mm.md");

    fn unique_line_start(text: &str, expected: &str, name: &str) -> usize {
        let mut found = None;
        let mut at = 0usize;
        for raw_line in text.split_inclusive('\n') {
            let without_lf = raw_line.strip_suffix('\n').unwrap_or(raw_line);
            let line = without_lf.strip_suffix('\r').unwrap_or(without_lf);
            if line == expected {
                if found.is_some() {
                    panic!("{name} appears as an exact line more than once")
                }
                found = Some(at);
            }
            at = at.saturating_add(raw_line.len());
        }
        let Some(at) = found else {
            panic!("{name} is not present as an exact line")
        };
        at
    }

    fn unique_substring_start(text: &str, expected: &str, name: &str) -> usize {
        let mut matches = text.match_indices(expected);
        let Some((at, _)) = matches.next() else {
            panic!("{name} is gone")
        };
        if matches.next().is_some() {
            panic!("{name} appears more than once")
        }
        at
    }

    fn scoped_section<'a>(doc: &'a str, heading: &str, next_heading: &str, name: &str) -> &'a str {
        let at = unique_line_start(doc, heading, &format!("{name}'s heading"));
        let end = unique_line_start(doc, next_heading, &format!("{name}'s following heading"));
        if end <= at {
            panic!("{name}'s following heading precedes its intended heading")
        }
        doc.get(at..end).unwrap_or("")
    }

    fn fenced_text_between<'a>(section: &'a str, before: &str, after: &str, name: &str) -> &'a str {
        let before_at =
            unique_substring_start(section, before, &format!("{name}'s preceding anchor"));
        let after_at =
            unique_substring_start(section, after, &format!("{name}'s following anchor"));
        let window_start = before_at.saturating_add(before.len());
        if after_at <= window_start {
            panic!("{name}'s following anchor precedes its fenced content")
        }
        let window = section.get(window_start..after_at).unwrap_or("");

        let mut fence_count = 0usize;
        let mut open_end = None;
        let mut close_at = None;
        let mut at = 0usize;
        for raw_line in window.split_inclusive('\n') {
            let without_lf = raw_line.strip_suffix('\n').unwrap_or(raw_line);
            let line = without_lf.strip_suffix('\r').unwrap_or(without_lf);
            if line.starts_with("```") {
                fence_count = fence_count.saturating_add(1);
                match (fence_count, line) {
                    (1, "```text") => open_end = Some(at.saturating_add(line.len())),
                    (2, "```") => close_at = Some(at),
                    _ => panic!("{name} contains a duplicate or decoy fenced block"),
                }
            }
            at = at.saturating_add(raw_line.len());
        }
        if fence_count != 2 {
            panic!("{name} must contain exactly one fenced text block")
        }
        let Some(open_end) = open_end else {
            panic!("{name}'s fenced text block is gone")
        };
        let Some(close_at) = close_at else {
            panic!("{name}'s fenced text block is unterminated")
        };
        if close_at <= open_end {
            panic!("{name}'s fenced text block closes before its body")
        }
        window.get(open_end..close_at).unwrap_or("")
    }

    fn exact_sentence(section: &str, start: &str, end: &str, name: &str) -> String {
        let normalized = flat(section);
        let at = unique_substring_start(&normalized, start, &format!("{name}'s sentence start"));
        let end_at = unique_substring_start(&normalized, end, &format!("{name}'s sentence ending"));
        let end_at = end_at.saturating_add(end.len());
        if end_at <= at.saturating_add(start.len()) {
            panic!("{name}'s sentence ending precedes its start")
        }
        normalized.get(at..end_at).unwrap_or("").to_owned()
    }

    /// §6's fenced `text` block, as (name, value) pairs in document order.
    fn doc_limits() -> Vec<(String, u64)> {
        let body = fenced_text_between(
            section_six(),
            "The bounded adapter state (corrective design section 10) is:",
            "There is no 1024-entry table embedded in every FCB:",
            "section 6 constants",
        );

        let mut out = Vec::new();
        for line in body.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let Some((name, value)) = t.split_once('=') else {
                panic!("constants line without `=`: {t:?}")
            };
            let Ok(v) = value.trim().parse::<u64>() else {
                panic!("constants line whose value is not a u64: {t:?}")
            };
            out.push((String::from(name.trim()), v));
        }
        out
    }

    #[test]
    fn the_parsed_constants_are_not_empty() {
        // The anti-vacuity guard, and it comes first because everything below
        // compares against this parse. A parser that silently matched nothing
        // would otherwise certify an empty comparison as passing.
        let parsed = doc_limits();
        assert_eq!(parsed.len(), 8, "section 6's block has eight constants");
        for (name, value) in &parsed {
            assert!(!name.is_empty(), "a constant parsed with no name");
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()),
                "{name} is not SCREAMING_SNAKE"
            );
            assert!(*value > 0, "{name} parsed as zero");
        }
    }

    #[test]
    fn the_limits_match_the_document() {
        let parsed = doc_limits();
        assert_eq!(
            parsed.len(),
            8,
            "section 6 must contain exactly eight adapter constants"
        );
        assert_eq!(LIMITS.len(), 8, "the shipped table must contain all eight");
        for (i, ((stored_name, stored_value), (doc_name, doc_value))) in
            LIMITS.iter().zip(parsed.iter()).enumerate()
        {
            assert_eq!(stored_name, doc_name, "LIMITS[{i}]: name");
            assert_eq!(stored_value, doc_value, "LIMITS[{i}] ({doc_name}): value");
        }
    }

    #[test]
    fn every_limit_is_reachable_by_name() {
        for (name, value) in LIMITS {
            assert_eq!(limit(name), Some(value));
        }
        assert_eq!(limit("NOT_A_LIMIT"), None, "a typo must not read as zero");
    }

    // ------------------------------------ 4.3: the other two transcriptions

    const LOCK_DOC: &str = include_str!("../../../docs/design/06-locking.md");

    /// Whitespace-normalized, because the documents hard-wrap their prose and a
    /// sentence that spans a line break is one sentence.
    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The text of `07-cache-mm.md` §7, bounded by both headings.
    fn section_seven() -> &'static str {
        scoped_section(
            CACHE_DOC,
            "## 7. `AdvanceOnly` -- the trusted fast path",
            "## 8. Purge and coherency recipe",
            "section 7",
        )
    }

    /// The text of `07-cache-mm.md` §6, bounded by both headings.
    fn section_six() -> &'static str {
        scoped_section(
            CACHE_DOC,
            "## 6. The paging-write issue ledger",
            "## 7. `AdvanceOnly` -- the trusted fast path",
            "section 6",
        )
    }

    /// The text of `06-locking.md` §3.4, bounded by both headings.
    fn locking_paging_sequencer_section() -> &'static str {
        scoped_section(
            LOCK_DOC,
            "### 3.4 The paging sequencer",
            "### 3.5 The AdvanceOnly CSQ",
            "06-locking.md section 3.4",
        )
    }

    fn cache_never_clearing_sentence() -> String {
        exact_sentence(
            section_six(),
            "Waiter absence",
            "normalizes a recorded failure.",
            "section 6 never-clearing",
        )
    }

    fn locking_never_clearing_sentence() -> String {
        exact_sentence(
            locking_paging_sequencer_section(),
            "Waiter absence",
            "normalize a failure.",
            "06-locking.md section 3.4 never-clearing",
        )
    }

    fn target_vdl_formula_block() -> String {
        flat(fenced_text_between(
            section_seven(),
            "Concretely, the worker computes",
            "and only advances VDL to `target_vdl`",
            "section 7 target_vdl formula",
        ))
    }

    fn target_vdl_barrier_sentence() -> String {
        exact_sentence(
            section_seven(),
            "and only advances VDL to `target_vdl`",
            "candidate instead.",
            "section 7 target_vdl barrier",
        )
    }

    const CACHE_NEVER_CLEARING_EVENTS: [&str; 5] = [
        "Waiter absence",
        "timeout",
        "CLEANUP",
        "a session fence",
        "ATTACH",
    ];

    const LOCK_NEVER_CLEARING_EVENTS: [&str; 5] =
        ["Waiter absence", "timeout", "CLEANUP", "fence", "ATTACH"];

    const LOCK_NEVER_CLEARING_SENTENCE: &str =
        "Waiter absence, timeout, CLEANUP, fence, and ATTACH never discard or normalize a failure.";

    fn assert_exact_five_events(sentence: &str, expected: &[&str; 5], source: &str) {
        let mut at = 0usize;
        for phrase in expected {
            assert_eq!(
                sentence.matches(phrase).count(),
                1,
                "{source} does not contain exactly one {phrase:?} phrase"
            );
            let Some(rest) = sentence.get(at..) else {
                panic!("ran off {source} before {phrase}")
            };
            let Some(found) = rest.find(phrase) else {
                panic!("{source} does not name {phrase} in order")
            };
            at = at.saturating_add(found).saturating_add(phrase.len());
        }
    }

    #[test]
    fn transcription_selector_rejects_duplicate_exact_heading_lines() {
        let doc = "## 6. Intended\nfirst\n## 6. Intended\nsecond\n## 7. Next\n";
        assert!(
            std::panic::catch_unwind(|| {
                scoped_section(doc, "## 6. Intended", "## 7. Next", "synthetic section")
            })
            .is_err(),
            "a duplicate intended heading must make the section ambiguous"
        );
    }

    #[test]
    fn transcription_selector_rejects_duplicate_next_heading_lines() {
        let doc = "## 6. Intended\nbody\n## 7. Next\nnoise\n## 7. Next\n";
        assert!(
            std::panic::catch_unwind(|| {
                scoped_section(doc, "## 6. Intended", "## 7. Next", "synthetic section")
            })
            .is_err(),
            "a duplicate following heading must make the section boundary ambiguous"
        );
    }

    #[test]
    fn transcription_selector_ignores_an_inline_quoted_heading() {
        let doc = "The phrase `## 6. Intended` is quoted.\n\
                   ## 6. Intended\nbody\n## 7. Next\n";
        assert_eq!(
            scoped_section(doc, "## 6. Intended", "## 7. Next", "synthetic section"),
            "## 6. Intended\nbody\n",
            "only an exact heading line may begin the section"
        );
    }

    #[test]
    fn transcription_selector_rejects_duplicate_fence_anchors() {
        let section = "Formula follows:\n```text\ndecoy\n```\n\
                       Formula follows:\n```text\nwanted\n```\nFormula terminates.\n";
        assert!(
            std::panic::catch_unwind(|| {
                fenced_text_between(
                    section,
                    "Formula follows:",
                    "Formula terminates.",
                    "synthetic formula",
                )
            })
            .is_err(),
            "a duplicate fence anchor must not select its first formula"
        );
    }

    #[test]
    fn transcription_selector_rejects_duplicate_fenced_formula_blocks() {
        let section =
            "Formula follows:\n```text\ndecoy\n```\n```text\nwanted\n```\nFormula terminates.\n";
        assert!(
            std::panic::catch_unwind(|| {
                fenced_text_between(
                    section,
                    "Formula follows:",
                    "Formula terminates.",
                    "synthetic formula",
                )
            })
            .is_err(),
            "two fenced formulas after one anchor are ambiguous"
        );
    }

    #[test]
    fn transcription_selector_rejects_duplicate_sentence_starts() {
        let section = "Rule starts with a decoy. Rule starts with the answer and ends here.";
        assert!(
            std::panic::catch_unwind(|| {
                exact_sentence(section, "Rule starts", "ends here.", "synthetic sentence")
            })
            .is_err(),
            "a duplicate sentence start must not select its first occurrence"
        );
    }

    #[test]
    fn transcription_selector_rejects_duplicate_sentence_ends() {
        let section = "Rule starts and ends here. A decoy also says ends here.";
        assert!(
            std::panic::catch_unwind(|| {
                exact_sentence(section, "Rule starts", "ends here.", "synthetic sentence")
            })
            .is_err(),
            "a duplicate sentence end must not select its first occurrence"
        );
    }

    #[test]
    fn transcription_selector_accepts_one_unambiguous_scope() {
        let doc = "## 6. Intended\nFormula follows:\n```text\nvalue\n```\n\
                   Rule starts and ends here.\n## 7. Next\n";
        let section = scoped_section(doc, "## 6. Intended", "## 7. Next", "synthetic section");
        assert_eq!(
            fenced_text_between(
                section,
                "Formula follows:",
                "Rule starts",
                "synthetic formula",
            )
            .trim(),
            "value"
        );
        assert_eq!(
            exact_sentence(section, "Rule starts", "ends here.", "synthetic sentence"),
            "Rule starts and ends here."
        );
    }

    #[test]
    fn the_never_clearing_sentence_matches_the_document() {
        assert_eq!(
            cache_never_clearing_sentence(),
            flat(NEVER_CLEARING_SENTENCE),
            "section 6's never-clearing sentence drifted from the transcription"
        );
        assert_eq!(
            locking_never_clearing_sentence(),
            flat(LOCK_NEVER_CLEARING_SENTENCE),
            "06-locking.md section 3.4's never-clearing sentence drifted"
        );
    }

    #[test]
    fn the_five_events_are_the_documents_five_in_its_order() {
        // Positional, not "each appears somewhere": a list that named the right
        // five in the wrong order would still be a drifted transcription, and
        // both documents have to agree.
        assert_eq!(ALL_LEDGER_EVENTS.len(), 5);
        for (event, phrase) in ALL_LEDGER_EVENTS.iter().zip(CACHE_NEVER_CLEARING_EVENTS) {
            assert_eq!(
                event.phrase(),
                phrase,
                "adapter event list drifted from section 6"
            );
        }
        assert_exact_five_events(
            &cache_never_clearing_sentence(),
            &CACHE_NEVER_CLEARING_EVENTS,
            "section 6",
        );
        assert_exact_five_events(
            &locking_never_clearing_sentence(),
            &LOCK_NEVER_CLEARING_EVENTS,
            "06-locking.md section 3.4",
        );
    }

    #[test]
    fn the_target_vdl_formula_and_sentence_match_the_document() {
        assert_eq!(
            target_vdl_formula_block(),
            flat(TARGET_VDL_FORMULA),
            "the formula drifted from section 7's block"
        );
        assert_eq!(
            target_vdl_barrier_sentence(),
            flat(TARGET_VDL_SENTENCE),
            "section 7's AdvanceOnly precondition drifted from the transcription"
        );
    }

    #[test]
    fn the_per_fcb_bound_is_the_documents_constant() {
        // `ACTIVE_CAPACITY` is written out because an array length must be a
        // `const`. This is the link back: `LIMITS` is checked against §6's
        // fenced block above, and the stand-in's storage is checked against
        // `LIMITS` here, so drifting either end reddens something.
        assert_eq!(
            limit("MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_FCB"),
            u64::try_from(ACTIVE_CAPACITY).ok(),
            "the active-set bound is not §6's per-FCB constant"
        );
    }

    // ------------------------------------------------ the counter and the set

    /// `n` issues, allocated in order, from a fresh pair.
    fn seeded(n: u64) -> (ActiveSet, IssueCounter) {
        let mut set = ActiveSet::new();
        let mut counter = IssueCounter::new();
        for expected in 1..=n {
            let Ok(issue) = set.allocate(&mut counter) else {
                panic!("seeding was refused at issue {expected}")
            };
            assert_eq!(issue.get(), expected);
        }
        (set, counter)
    }

    /// The still-open issues, in order, as an owned list the asserts can name.
    fn live_of(set: &ActiveSet) -> Vec<u64> {
        set.live().to_vec()
    }

    /// Retire `issue` from `set`, failing the test if it was not active.
    fn retire(set: &mut ActiveSet, issue: u64) {
        let Some(i) = Issue::from_raw(issue) else {
            panic!("{issue} is not a legal issue number")
        };
        let Some(entry) = set.preflight(i) else {
            panic!("issue {issue} was not active")
        };
        set.remove_preflighted(entry);
    }

    #[test]
    fn issues_start_at_one_and_increase() {
        let (set, counter) = seeded(2);
        // The first issue is 1. §6 calls the counter nonzero, and `Issue` makes
        // that a type fact -- a counter that handed out 0 could not build one.
        assert_eq!(live_of(&set), vec![1, 2]);
        assert_eq!(counter.last_issued(), 2);
    }

    #[test]
    fn an_exhausted_counter_errors_and_stays_exhausted() {
        let mut set = ActiveSet::new();
        let mut counter = IssueCounter {
            last_issued: u64::MAX,
        };

        assert_eq!(
            set.allocate(&mut counter),
            Err(LedgerError::IssuesExhausted),
            "the counter must refuse rather than wrap"
        );
        // The second call is the one that matters. A wrapping increment errors
        // on the nonzero check too -- and leaves `last_issued` at 0, so the
        // next call hands out issue 1 again while issue 1 may still be live.
        assert_eq!(
            counter.last_issued(),
            u64::MAX,
            "the counter advanced anyway"
        );
        assert_eq!(
            set.allocate(&mut counter),
            Err(LedgerError::IssuesExhausted),
            "an exhausted counter reissued a live number"
        );
        assert!(set.is_empty());
    }

    #[test]
    fn an_allocated_issue_is_always_in_the_active_set() {
        // The prefix formula reads only the set, so an issue minted outside it
        // is covered by a prefix that proves nothing about it. The reviewer's
        // walk was: hold {5}, mint 6 without inserting, remove 5 -- empty set,
        // prefix = last_issued = 6, and issue 6 recorded nothing. There is no
        // such call to make: `allocate` is the only public route to an `Issue`.
        let (set, counter) = seeded(5);
        assert_eq!(set.len(), 5);
        assert_eq!(counter.last_issued(), 5);
        for issue in 1..=5 {
            assert!(
                set.live().contains(&issue),
                "issue {issue} was minted but not inserted"
            );
        }
    }

    #[test]
    fn a_full_set_refuses_without_minting_an_issue() {
        // §6's failed context claim. The caller's answer is the claim-failure
        // path, which numbers an issue of its own; a number burnt here would
        // belong to neither the active set nor any terminal record, and the
        // prefix formula's soundness rests on there being no such number.
        let mut set = ActiveSet::new();
        let mut counter = IssueCounter::new();
        for _ in 0..ACTIVE_CAPACITY {
            let Ok(_issue) = set.allocate(&mut counter) else {
                panic!("the set refused below its own bound")
            };
        }
        assert_eq!(set.len(), ACTIVE_CAPACITY);
        let before = counter.last_issued();

        assert_eq!(
            set.allocate(&mut counter),
            Err(LedgerError::ActiveContextsExhausted),
            "the per-FCB bound was not enforced"
        );
        assert_eq!(counter.last_issued(), before, "a refusal burnt an issue");
        assert_eq!(set.len(), ACTIVE_CAPACITY);
    }

    #[test]
    fn a_counter_behind_the_set_is_refused() {
        // The design pairs a set with a counter by convention, and nothing in
        // the type system holds them together. Appending an issue that does not
        // out-rank the greatest entry would break the ascending order the O(1)
        // minimum depends on, so the pairing is checked rather than trusted.
        let (mut set, _counter) = seeded(3);
        let mut fresh = IssueCounter::new();
        assert_eq!(
            set.allocate(&mut fresh),
            Err(LedgerError::IssueOutOfOrder),
            "a mispaired counter would have inserted 1 after 3"
        );
        assert_eq!(fresh.last_issued(), 0, "a refusal burnt an issue");
        assert_eq!(live_of(&set), vec![1, 2, 3]);
    }

    #[test]
    fn the_set_stays_ordered_so_the_minimum_is_the_first_entry() {
        let (mut set, _counter) = seeded(6);
        retire(&mut set, 3);
        retire(&mut set, 1);
        retire(&mut set, 6);
        assert_eq!(
            live_of(&set),
            vec![2, 4, 5],
            "removal must not disturb the order"
        );
        assert_eq!(set.minimum().map(Issue::get), Some(2));
    }

    #[test]
    fn a_preflight_token_retires_its_issue_exactly_once() {
        let (mut set, _counter) = seeded(2);
        retire(&mut set, 1);
        let Some(one) = Issue::from_raw(1) else {
            panic!("1 is a legal issue number")
        };
        assert!(set.preflight(one).is_none());
        assert_eq!(live_of(&set), vec![2]);
    }

    #[test]
    fn an_issue_the_set_does_not_hold_cannot_be_removed() {
        // `07:294-299`'s claim-failure issue is absent from the set by design.
        let (set, _counter) = seeded(2);
        let Some(nine) = Issue::from_raw(9) else {
            panic!("9 is a legal issue number")
        };
        assert!(set.preflight(nine).is_none());
        assert_eq!(live_of(&set), vec![1, 2]);
    }

    // ------------------------------------------------------------ the prefix

    #[test]
    fn the_prefix_is_last_issued_when_the_set_is_empty() {
        let fresh = ActiveSet::new();
        assert_eq!(
            fresh.terminal_prefix(&IssueCounter::new()),
            0,
            "nothing issued is nothing proven"
        );

        let (mut set, counter) = seeded(3);
        for issue in 1..=3 {
            retire(&mut set, issue);
        }
        assert!(set.is_empty());
        // `last_issued`, not `last_issued + 1`: `06 §3.5` releases BARRIER_WAIT
        // fences on prefix coverage, so an overstated prefix releases a waiter
        // over bytes nothing has proven.
        assert_eq!(set.terminal_prefix(&counter), 3);
    }

    #[test]
    fn the_prefix_is_the_minimum_minus_one_when_the_set_is_not_empty() {
        let (mut set, counter) = seeded(4);
        retire(&mut set, 1);
        retire(&mut set, 2);
        assert_eq!(set.minimum().map(Issue::get), Some(3));
        // The minimum, not the maximum: with {3, 4} still open, a prefix of 3
        // would claim issue 3 terminal while it is in flight.
        assert_eq!(set.terminal_prefix(&counter), 2);
    }

    #[test]
    fn issue_nine_completing_before_seven_leaves_the_prefix_at_six() {
        // `07:308-312` verbatim: "a paging WRITE with issue 7 can complete after
        // issue 9 without the ledger ever materializing a sparse history of
        // completed issues, because only the *lowest* still-open issue
        // determines how far the prefix has actually advanced."
        let (mut set, counter) = seeded(9);
        for issue in [1, 2, 3, 4, 5, 6, 8] {
            retire(&mut set, issue);
        }
        assert_eq!(
            live_of(&set),
            vec![7, 9],
            "issues 7 and 9 are the ones left open"
        );
        assert_eq!(set.terminal_prefix(&counter), 6);

        // Nine completes first. The prefix does NOT move: seven is still open.
        retire(&mut set, 9);
        assert_eq!(live_of(&set), vec![7]);
        assert_eq!(
            set.terminal_prefix(&counter),
            6,
            "the prefix advanced past an issue that is still in flight"
        );

        // Seven completes. Now the whole range is contiguous, and the answer
        // comes from `last_issued` -- no sparse history was ever materialized.
        retire(&mut set, 7);
        assert!(set.is_empty());
        assert_eq!(set.terminal_prefix(&counter), 9);
    }

    // ------------------------------------- signal 8: no retained history, structurally

    /// This module's own source. A behavioural test cannot see a field that is
    /// present and merely unused, so the check is structural.
    const OWN_SOURCE: &str = include_str!("pagingledger.rs");

    /// The SHIPPED half — everything before the test module marker. The rule is
    /// about what an FCB would carry, not about test scaffolding.
    fn shipped_source() -> &'static str {
        match OWN_SOURCE.find("#[cfg(test)]") {
            Some(at) => OWN_SOURCE.get(..at).unwrap_or(OWN_SOURCE),
            None => panic!("the test module marker is gone; the scan would cover everything"),
        }
    }

    /// What `07:308-312` forbids the set to retain: a status, or a coverage
    /// range keyed by issue. **Not** "any collection" — the active set is one.
    ///
    /// `i32` is in the list because an NTSTATUS is an `i32` throughout this
    /// driver, so `[(u64, i32); N]` is precisely the retained terminal-issue
    /// table the document says is unnecessary.
    const HISTORY_NEEDLES: [&str; 6] = ["status", "interval", "coverage", "range", "record", "i32"];

    /// The one predicate. Both the scan and its anti-vacuity guard call it, so
    /// switching the scan off cannot leave the guard green.
    fn carries_status_or_range(field_type: &str) -> bool {
        let lowered = field_type.to_lowercase();
        HISTORY_NEEDLES.iter().any(|n| lowered.contains(n))
    }

    /// The body of `pub struct <name> {` … `\n}` in `src`.
    fn struct_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
        let decl = format!("struct {name} {{");
        let at = src.find(&decl)?;
        let rest = src.get(at.saturating_add(decl.len())..)?;
        let close = rest.find("\n}")?;
        rest.get(..close)
    }

    /// `(field, type)` for each declaration in a struct body.
    fn struct_fields(body: &str) -> Vec<(String, String)> {
        body.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("//") && !l.starts_with("#["))
            .filter_map(|l| {
                let decl = l.strip_suffix(',').unwrap_or(l);
                let (name, ty) = decl.split_once(':')?;
                Some((name.trim().to_string(), ty.trim().to_string()))
            })
            .collect()
    }

    /// The element type of an array type, or the type itself.
    fn element_type(ty: &str) -> &str {
        let inner = ty
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(ty);
        inner.split(';').next().unwrap_or(inner).trim()
    }

    #[test]
    fn the_active_set_retains_no_completed_issue_history() {
        let Some(body) = struct_body(shipped_source(), "ActiveSet") else {
            panic!("`struct ActiveSet {{` is gone; the scan has nothing to read")
        };
        let fields = struct_fields(body);
        assert!(
            !fields.is_empty(),
            "no fields parsed out of ActiveSet; the comparison below would be vacuous"
        );

        let mut issue_storage = 0usize;
        for (name, ty) in &fields {
            assert!(
                !carries_status_or_range(ty),
                "ActiveSet::{name}: `{ty}` is the retained terminal-issue table \
                 `07:308-312` says out-of-order completion does not need"
            );
            let element = element_type(ty);
            assert!(
                matches!(element, "u64" | "Issue" | "usize"),
                "ActiveSet::{name}: element type `{element}` is not a bare issue number"
            );
            if matches!(element, "u64" | "Issue") {
                issue_storage = issue_storage.saturating_add(1);
            }
        }
        assert!(
            issue_storage > 0,
            "ActiveSet stores no issue numbers at all; the scan would pass on an empty type"
        );
    }

    #[test]
    fn the_history_scan_fires_on_the_shapes_it_exists_to_reject() {
        // Anti-vacuity in both directions, and it calls the SAME predicate the
        // scan calls. A guard that reimplemented the needle list could not see
        // the real scan being switched off -- which is how B3 stayed green while
        // its own scan was disabled.
        for rejected in [
            "[(u64, i32); ACTIVE_CAPACITY]",
            "[(u64, IntervalStatus); 8]",
            "[Interval; 4]",
            "[Coverage; 2]",
            "[RecordStatus; 4]",
            "[Range<u64>; 4]",
        ] {
            assert!(
                carries_status_or_range(rejected),
                "the scan misses a retained history: {rejected}"
            );
        }
        for accepted in ["[u64; ACTIVE_CAPACITY]", "usize", "u64"] {
            assert!(
                !carries_status_or_range(accepted),
                "the scan false-positives on a bare issue number: {accepted}"
            );
        }

        // The extraction has to work too: a `struct_body` that found nothing
        // would make the scan above pass on zero fields.
        let Some(body) = struct_body(shipped_source(), "ActiveSet") else {
            panic!("the struct-body extractor found nothing to read")
        };
        assert_eq!(
            struct_fields(body).len(),
            2,
            "ActiveSet's field count changed; the scan's assumptions need rereading"
        );
        assert_eq!(element_type("[u64; ACTIVE_CAPACITY]"), "u64");
        assert_eq!(element_type("usize"), "usize");
    }

    // ============================================================ the ledger

    /// Lossless on every target this crate builds for; all three are 64-bit.
    fn u(n: usize) -> u64 {
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    fn s(n: u64) -> usize {
        usize::try_from(n).unwrap_or(usize::MAX)
    }

    fn iss(n: u64) -> Issue {
        let Some(i) = Issue::from_raw(n) else {
            panic!("{n} is not a legal issue number")
        };
        i
    }

    /// The status this test suite registers for issue `n`, so the property test
    /// can check that a surviving interval carries **its own** issue's status.
    fn status_for(n: u64) -> i32 {
        match n.checked_rem(3) {
            Some(0) => IntervalStatus::io_device_error().get(),
            Some(1) => IntervalStatus::insufficient_resources().get(),
            _ => completion_status::DEVICE_NOT_READY,
        }
    }

    fn iv(start: u64, end: u64, issue: u64) -> Interval {
        let Ok(v) = Interval::new(
            start,
            end,
            iss(issue),
            IntervalStatus::registered(failure(status_for(issue))),
        ) else {
            panic!("[{start}, {end}) is not a legal interval")
        };
        v
    }

    fn cov(start: u64, end: u64) -> Coverage {
        let Ok(c) = Coverage::new(start, end) else {
            panic!("[{start}, {end}) is not legal coverage")
        };
        c
    }

    fn nodes(n: u64) -> NodeBudget {
        let Ok(b) = NodeBudget::preclaim(n) else {
            panic!("{n} is above the preclaim cap")
        };
        b
    }

    /// The ordinary intervals as `(start, end, issue)` triples.
    fn spans(l: &Ledger) -> Vec<(u64, u64, u64)> {
        l.intervals()
            .map(|i| (i.start(), i.end(), i.lowest_issue().get()))
            .collect()
    }

    fn ledger_with_unknown(start: u64, end: u64, issue: u64) -> Ledger {
        let mut ledger = Ledger::new();
        ledger.unknown = Some(iv(start, end, issue));
        ledger
    }

    /// A ledger holding `n` separated ordinary intervals, `[10i, 10i+5)`.
    fn filled(n: usize) -> Ledger {
        let mut l = Ledger::new();
        for k in 0..n {
            let base = u(k).saturating_mul(10);
            let out = l.record_failure(
                iv(base, base.saturating_add(5), u(k).saturating_add(1)),
                0,
                nodes(2),
                Reservation::Granted,
            );
            assert_eq!(out, RecordOutcome::Recorded, "seeding interval {k}");
        }
        assert_eq!(l.len(), n, "seeding produced the wrong count");
        l
    }

    #[test]
    fn the_interval_constants_are_the_documents() {
        assert_eq!(
            limit("INLINE_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB"),
            u64::try_from(INLINE_INTERVALS).ok()
        );
        assert_eq!(
            limit("MAX_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB"),
            u64::try_from(MAX_INTERVALS).ok()
        );
        assert_eq!(
            limit("PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES"),
            Some(PRECLAIM_NODES)
        );
    }

    // ------------------------------------------------- the domain, one funnel

    #[test]
    fn an_empty_or_inverted_range_carries_no_evidence() {
        assert_eq!(
            Interval::new(10, 10, iss(1), IntervalStatus::io_device_error()),
            Err(LedgerError::Range(RangeError::ZeroLength))
        );
        assert_eq!(
            Interval::new(30, 10, iss(1), IntervalStatus::io_device_error()),
            Err(LedgerError::Range(RangeError::ZeroLength)),
            "an inverted range is a zero length, refused by the frozen validator"
        );
        assert_eq!(
            Coverage::new(10, 10),
            Err(LedgerError::Range(RangeError::ZeroLength))
        );
    }

    #[test]
    fn a_range_outside_the_domain_is_refused_with_fsring_abis_reason() {
        // 04 section 8.1's domain is fsring-abi's, and so is the reason.
        assert_eq!(
            Interval::new(
                MAX_FILE_SIZE,
                MAX_FILE_SIZE.saturating_add(1),
                iss(1),
                IntervalStatus::io_device_error()
            ),
            Err(LedgerError::Range(RangeError::OffsetOutOfRange))
        );
        assert_eq!(
            Coverage::new(
                MAX_FILE_SIZE.saturating_sub(1),
                MAX_FILE_SIZE.saturating_add(4)
            ),
            Err(LedgerError::Range(RangeError::EndOutOfRange))
        );
    }

    #[test]
    fn every_range_is_minted_behind_the_frozen_validator() {
        // Structural, because a behavioural test cannot tell a delegation from
        // a faithful local copy of the same bounds.
        let src = shipped_source();
        let mut mints = 0usize;
        for (at, _) in src.match_indices("Self {") {
            let Some(rest) = src.get(at..) else { continue };
            let Some(close) = rest.find('}') else {
                continue;
            };
            let Some(body) = rest.get(..close) else {
                continue;
            };
            if !(body.contains("start") && body.contains("end")) {
                continue;
            }
            mints = mints.saturating_add(1);
            let Some(before) = src.get(..at) else {
                continue;
            };
            let Some(fn_at) = before.rfind("pub fn ") else {
                panic!("a range is minted outside any public constructor")
            };
            let Some(head) = before.get(fn_at..) else {
                continue;
            };
            assert!(
                head.contains("validate_file_range"),
                "a range is minted without passing 04 section 8.1's domain: {}",
                head.lines().next().unwrap_or("")
            );
        }
        assert_eq!(
            mints, 2,
            "expected exactly two range mints -- Interval and Coverage -- found {mints}"
        );
    }

    #[test]
    fn the_statuses_are_fsring_abis_not_literals() {
        assert_eq!(
            IntervalStatus::io_device_error().get(),
            completion_status::IO_DEVICE_ERROR
        );
        assert_eq!(
            IntervalStatus::insufficient_resources().get(),
            completion_status::INSUFFICIENT_RESOURCES
        );
        let src = shipped_source();
        assert!(src.contains("completion_status::IO_DEVICE_ERROR"));
        assert!(src.contains("completion_status::INSUFFICIENT_RESOURCES"));
        // The comparison above reads the same constant the code reads, so it
        // cannot catch a correct literal -- only drift. This can: the value
        // belongs to fsring-abi/src/validate/messages.rs, never to this file.
        for spelled_out in ["0xc000_0185", "0xc0000185", "0xc000_009a", "0xc000009a"] {
            assert!(
                !src.to_lowercase().contains(spelled_out),
                "an NTSTATUS value is spelled out here: {spelled_out}"
            );
        }
    }

    #[test]
    fn a_budget_above_the_preclaim_cap_is_refused() {
        assert!(NodeBudget::preclaim(0).is_ok());
        assert!(NodeBudget::preclaim(PRECLAIM_NODES).is_ok());
        assert_eq!(
            NodeBudget::preclaim(PRECLAIM_NODES.saturating_add(1)),
            Err(LedgerError::BudgetTooLarge),
            "a budget above its own cap would allocate under the sequencer lock"
        );
    }

    // ------------------------------------------------- recording and the VDL

    #[test]
    fn a_record_wholly_below_vdl_records_nothing() {
        // "bytes already below VDL never block a future prefix advance"
        let mut l = Ledger::new();
        let out = l.record_failure(iv(10, 40, 1), 40, nodes(2), Reservation::Granted);
        assert_eq!(out, RecordOutcome::BelowVdl);
        assert!(l.is_empty());
    }

    #[test]
    fn a_record_straddling_vdl_starts_at_vdl() {
        // Starting ABOVE the VDL would lose the bytes between; starting at 0
        // would keep bytes 07:317-319 says never block. The document says VDL.
        let mut l = Ledger::new();
        assert_eq!(
            l.record_failure(iv(10, 40, 1), 25, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(spans(&l), vec![(25, 40, 1)]);
    }

    #[test]
    fn two_touching_records_become_one_under_the_lower_issue() {
        let mut l = Ledger::new();
        assert_eq!(
            l.record_failure(iv(10, 20, 7), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            l.record_failure(iv(15, 30, 3), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            spans(&l),
            vec![(10, 30, 3)],
            "the union carries the lowest issue that touched it"
        );
        let Some(only) = l.intervals().next() else {
            panic!("one interval")
        };
        assert_eq!(
            only.status().get(),
            status_for(3),
            "and that issue's status, not the other's"
        );
    }

    #[test]
    fn separated_records_stay_separate_and_ascending() {
        let mut l = Ledger::new();
        for (start, end, issue) in [(40u64, 50u64, 4u64), (10, 20, 2), (25, 30, 9)] {
            assert_eq!(
                l.record_failure(iv(start, end, issue), 0, nodes(2), Reservation::Granted),
                RecordOutcome::Recorded
            );
        }
        assert_eq!(spans(&l), vec![(10, 20, 2), (25, 30, 9), (40, 50, 4)]);
    }

    // --------------------------------------------------------- subtraction

    #[test]
    fn a_commit_subtracts_exactly_its_coverage() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(10, 40, 5), 0, nodes(2), Reservation::Granted);
        assert_eq!(
            l.subtract_proven(cov(10, 20), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            spans(&l),
            vec![(20, 40, 5)],
            "exactly its coverage -- no more, no less"
        );
    }

    #[test]
    fn a_commit_inside_an_interval_splits_it() {
        // 07:331's degradation rule opens with "If a SPLIT would exceed the
        // per-FCB interval bound", and this is the operation that splits.
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(10, 40, 5), 0, nodes(2), Reservation::Granted);
        assert_eq!(
            l.subtract_proven(cov(20, 25), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(spans(&l), vec![(10, 20, 5), (25, 40, 5)]);
    }

    #[test]
    fn a_split_that_cannot_be_represented_merges_rather_than_dropping() {
        // The seam that rev 2 of the design gave to record_failure alone.
        let mut l = filled(MAX_INTERVALS);
        assert_eq!(l.len(), MAX_INTERVALS);
        // Splitting the first interval would need a 65th slot.
        let out = l.subtract_proven(cov(2, 3), 0, nodes(2), Reservation::Granted);
        assert_eq!(out, RecordOutcome::Merged(MergeTrigger::IntervalBound));
        assert_eq!(l.len(), 0);
        let Some(span) = l.unknown() else {
            panic!("the evidence must be in the UNKNOWN span")
        };
        assert_eq!(
            (span.start(), span.end()),
            (0, u(MAX_INTERVALS).saturating_mul(10).saturating_sub(5))
        );
        assert_eq!(
            span.lowest_issue().get(),
            1,
            "the lowest issue is preserved"
        );
    }

    #[test]
    fn unknown_middle_split_retains_both_residuals_with_granted_resources() {
        let mut ledger = ledger_with_unknown(0, 100, 7);
        let outcome = ledger.subtract_proven(cov(40, 60), 0, nodes(0), Reservation::Granted);
        assert_eq!(outcome, RecordOutcome::Recorded);
        assert_eq!(ledger.unknown(), Some(iv(0, 40, 7)));
        assert_eq!(spans(&ledger), vec![(60, 100, 7)]);
    }

    #[test]
    fn unknown_middle_split_ignores_failed_reservation_without_a_new_node() {
        let mut ledger = ledger_with_unknown(0, 100, 7);
        let outcome = ledger.subtract_proven(cov(40, 60), 0, nodes(0), Reservation::Failed);
        assert_eq!(outcome, RecordOutcome::Recorded);
        assert_eq!(ledger.unknown(), Some(iv(0, 40, 7)));
        assert_eq!(spans(&ledger), vec![(60, 100, 7)]);
    }

    #[test]
    fn unknown_middle_split_chooses_upper_inline_when_it_needs_fewer_new_nodes() {
        let mut ledger = ledger_with_unknown(100, 200, 7);
        assert_eq!(
            ledger.record_failure(iv(80, 100, 8), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.record_failure(iv(300, 310, 9), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.subtract_proven(cov(140, 160), 0, nodes(0), Reservation::Failed),
            RecordOutcome::Recorded
        );
        assert_eq!(ledger.unknown(), Some(iv(160, 200, 7)));
        assert_eq!(spans(&ledger), vec![(80, 140, 7), (300, 310, 9)]);
    }

    #[test]
    fn unknown_middle_split_chooses_lower_inline_when_it_needs_fewer_new_nodes() {
        let mut ledger = ledger_with_unknown(100, 200, 7);
        assert_eq!(
            ledger.record_failure(iv(200, 220, 8), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.record_failure(iv(300, 310, 9), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.subtract_proven(cov(140, 160), 0, nodes(0), Reservation::Failed),
            RecordOutcome::Recorded
        );
        assert_eq!(ledger.unknown(), Some(iv(100, 140, 7)));
        assert_eq!(spans(&ledger), vec![(160, 220, 7), (300, 310, 9)]);
    }

    #[test]
    fn unknown_middle_split_degrades_only_when_a_required_reservation_fails() {
        let mut ledger = ledger_with_unknown(0, 100, 7);
        assert_eq!(
            ledger.record_failure(iv(200, 210, 8), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.record_failure(iv(300, 310, 9), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.subtract_proven(cov(40, 60), 0, nodes(1), Reservation::Failed),
            RecordOutcome::Merged(MergeTrigger::ReservationFailed)
        );
        assert_eq!(ledger.unknown(), Some(iv(0, 310, 7)));
        assert!(spans(&ledger).is_empty());
    }

    #[test]
    fn unknown_middle_split_reports_budget_exhaustion_without_losing_evidence() {
        let mut ledger = ledger_with_unknown(0, 100, 7);
        assert_eq!(
            ledger.record_failure(iv(200, 210, 8), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.record_failure(iv(300, 310, 9), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(
            ledger.subtract_proven(cov(40, 60), 0, nodes(0), Reservation::Granted),
            RecordOutcome::Merged(MergeTrigger::BudgetExhausted)
        );
        assert_eq!(ledger.unknown(), Some(iv(0, 310, 7)));
    }

    #[test]
    fn unknown_orientation_ties_on_new_nodes_not_total_nodes() {
        let mut ledger = ledger_with_unknown(100, 200, 7);
        for interval in [
            iv(80, 100, 8),
            iv(140, 145, 9),
            iv(150, 155, 10),
            iv(300, 310, 11),
        ] {
            assert_eq!(
                ledger.record_failure(interval, 0, nodes(1), Reservation::Granted),
                RecordOutcome::Recorded
            );
        }
        assert_eq!(
            ledger.subtract_proven(cov(140, 160), 0, nodes(0), Reservation::Failed),
            RecordOutcome::Recorded
        );
        assert_eq!(ledger.unknown(), Some(iv(100, 140, 7)));
        assert_eq!(
            spans(&ledger),
            vec![(80, 100, 8), (160, 200, 7), (300, 310, 11)]
        );
    }

    #[test]
    fn unknown_middle_split_has_the_same_exact_state_in_either_commit_order() {
        let mut forward = ledger_with_unknown(0, 100, 7);
        let mut reverse = ledger_with_unknown(0, 100, 7);

        for range in [cov(20, 40), cov(60, 80)] {
            assert_eq!(
                forward.subtract_proven(range, 0, nodes(0), Reservation::Granted),
                RecordOutcome::Recorded
            );
        }
        for range in [cov(60, 80), cov(20, 40)] {
            assert_eq!(
                reverse.subtract_proven(range, 0, nodes(0), Reservation::Granted),
                RecordOutcome::Recorded
            );
        }

        for ledger in [&forward, &reverse] {
            assert_eq!(ledger.unknown(), Some(iv(0, 20, 7)));
            assert_eq!(spans(ledger), vec![(40, 60, 7), (80, 100, 7)]);
        }
    }

    #[test]
    fn unknown_middle_split_at_the_interval_bound_merges_before_either_orientation() {
        let mut ledger = filled(MAX_INTERVALS);
        ledger.unknown = Some(iv(1_000, 1_100, 65));

        let lower = ledger.project_subtraction(1_040, 1_060, UnknownOrientation::LowerInline);
        let upper = ledger.project_subtraction(1_040, 1_060, UnknownOrientation::UpperInline);
        assert_eq!(lower.len, MAX_INTERVALS + 1);
        assert_eq!(upper.len, MAX_INTERVALS + 1);

        assert_eq!(
            ledger.subtract_proven(cov(1_040, 1_060), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Merged(MergeTrigger::IntervalBound)
        );
        assert!(spans(&ledger).is_empty());
        assert_eq!(ledger.unknown(), Some(iv(0, 1_100, 1)));
    }

    // ------------------------------------------------------------- the VDL

    #[test]
    fn a_verified_vdl_trims_and_deletes() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(10, 20, 1), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(30, 50, 2), 0, nodes(2), Reservation::Granted);
        assert_eq!(l.trim_to_vdl(0, 40), Ok(()));
        assert_eq!(
            spans(&l),
            vec![(40, 50, 2)],
            "wholly below is deleted; straddling is trimmed to the portion above"
        );
    }

    #[test]
    fn a_regressing_vdl_is_rejected_and_changes_nothing() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(10, 50, 1), 0, nodes(2), Reservation::Granted);
        assert_eq!(l.trim_to_vdl(30, 20), Err(LedgerError::VdlRegressed));
        assert_eq!(spans(&l), vec![(10, 50, 1)]);
    }

    #[test]
    fn a_truncate_resets_the_baseline_a_trim_would_have_refused() {
        // 07 section 5 step 5 sets valid_data_length = min(VDL, EOF) after a
        // truncate commit, so VDL legitimately regresses OUTSIDE the
        // returned-VDL stream. Without this entry point the ledger would refuse
        // every post-truncate trim forever and AdvanceOnly would never clear.
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(10, 100, 1), 0, nodes(2), Reservation::Granted);
        assert_eq!(
            l.trim_to_vdl(60, 30),
            Err(LedgerError::VdlRegressed),
            "the returned-VDL stream is monotone, so a trim refuses this"
        );
        assert_eq!(spans(&l), vec![(10, 100, 1)], "and changes nothing");

        // The truncate path is not that stream, and it does the same work.
        assert_eq!(l.truncate_reset(30), Ok(()));
        assert_eq!(
            spans(&l),
            vec![(30, 100, 1)],
            "truncate_reset must apply its VDL, not merely be accepted"
        );

        // The baseline has moved with it: a trim the old baseline refused now
        // passes on the new one, so AdvanceOnly is not blocked forever.
        assert_eq!(l.trim_to_vdl(30, 40), Ok(()));
        assert_eq!(spans(&l), vec![(40, 100, 1)]);
    }

    // ----------------------------------------------------- the UNKNOWN span

    #[test]
    fn a_failed_reservation_merges_to_unknown() {
        let mut l = filled(INLINE_INTERVALS);
        let base = u(INLINE_INTERVALS).saturating_mul(10);
        let out = l.record_failure(
            iv(base, base.saturating_add(5), 9),
            0,
            nodes(2),
            Reservation::Failed,
        );
        assert_eq!(out, RecordOutcome::Merged(MergeTrigger::ReservationFailed));
        assert_eq!(l.len(), 0);
        assert!(l.unknown().is_some());
    }

    #[test]
    fn exceeding_the_preclaim_budget_merges_to_unknown() {
        // "any update that needs more takes the inline UNKNOWN fallback instead
        // of allocating under the lock"
        let mut l = filled(INLINE_INTERVALS);
        let base = u(INLINE_INTERVALS).saturating_mul(10);
        let out = l.record_failure(
            iv(base, base.saturating_add(5), 9),
            0,
            nodes(0),
            Reservation::Granted,
        );
        assert_eq!(out, RecordOutcome::Merged(MergeTrigger::BudgetExhausted));
        assert!(l.unknown().is_some());
    }

    #[test]
    fn a_record_needing_no_new_node_ignores_the_budget_and_the_reservation() {
        // Anti-vacuity for the two triggers above: below the inline count they
        // must NOT fire, or every recording would degrade.
        let mut l = Ledger::new();
        assert_eq!(
            l.record_failure(iv(10, 20, 1), 0, nodes(0), Reservation::Failed),
            RecordOutcome::Recorded
        );
        assert_eq!(
            l.record_failure(iv(30, 40, 2), 0, nodes(0), Reservation::Failed),
            RecordOutcome::Recorded,
            "the two inline slots need no overflow node"
        );
        assert_eq!(l.len(), INLINE_INTERVALS);
    }

    #[test]
    fn the_bound_is_sixty_four_in_total_not_sixty_six() {
        // Rev 1 of the design read the 64 as an overflow bound and would have
        // merged at 66 -- two inline plus sixty-four nodes.
        let mut at_62 = filled(62);
        assert_eq!(
            at_62.record_failure(iv(620, 625, 63), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded
        );
        assert_eq!(at_62.len(), 63);

        let mut at_63 = filled(63);
        assert_eq!(
            at_63.record_failure(iv(630, 635, 64), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Recorded,
            "the 64th ordinary interval still fits"
        );
        assert_eq!(at_63.len(), MAX_INTERVALS);

        let mut at_64 = filled(MAX_INTERVALS);
        assert_eq!(
            at_64.record_failure(iv(640, 645, 65), 0, nodes(2), Reservation::Granted),
            RecordOutcome::Merged(MergeTrigger::IntervalBound),
            "the 65th does not"
        );
        assert_eq!(at_64.len(), 0);
        assert!(at_64.unknown().is_some(), "and nothing was dropped");
    }

    #[test]
    fn the_merge_preserves_the_lowest_issue_and_its_status() {
        let mut l = Ledger::new();
        for (start, end, issue) in [(100u64, 110u64, 9u64), (200, 210, 4), (300, 310, 7)] {
            let _ = l.record_failure(iv(start, end, issue), 0, nodes(2), Reservation::Granted);
        }
        // Force the merge with a reservation failure rather than by volume.
        let out = l.record_failure(iv(400, 410, 8), 0, nodes(2), Reservation::Failed);
        assert_eq!(out, RecordOutcome::Merged(MergeTrigger::ReservationFailed));

        let Some(span) = l.unknown() else {
            panic!("the merge must produce an UNKNOWN span")
        };
        assert_eq!(
            (span.start(), span.end()),
            (100, 410),
            "the minimum unresolved start through the maximum unresolved end"
        );
        assert_eq!(
            span.lowest_issue().get(),
            4,
            "the LOWEST issue, not the first"
        );
        assert_eq!(
            span.status().get(),
            status_for(4),
            "and THAT issue's status, not another's"
        );
    }

    #[test]
    fn unknown_clears_when_a_verified_vdl_reaches_its_end() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(100, 110, 9), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(200, 210, 4), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(300, 310, 7), 0, nodes(0), Reservation::Granted);
        assert!(l.unknown().is_some());

        l.apply_vdl(200);
        let Some(span) = l.unknown() else {
            panic!("a VDL short of the end only trims UNKNOWN evidence")
        };
        assert_eq!((span.start(), span.end()), (200, 310));
        l.apply_vdl(310);
        assert!(l.unknown().is_none());
        assert!(l.is_empty());
    }

    #[test]
    fn unknown_shrinks_on_a_prefix_commit_and_projects_a_hole() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(100, 200, 3), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(300, 400, 5), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(500, 600, 7), 0, nodes(0), Reservation::Granted);
        let Some(span) = l.unknown() else {
            panic!("merged")
        };
        assert_eq!((span.start(), span.end()), (100, 600));

        // A prefix commit shrinks it exactly.
        let _ = l.subtract_proven(cov(100, 150), 0, nodes(2), Reservation::Granted);
        let Some(span) = l.unknown() else {
            panic!("still there")
        };
        assert_eq!((span.start(), span.end()), (150, 600));

        // A commit in the middle keeps the lower residual inline on the tie
        // and projects the upper residual into ordinary evidence.
        let _ = l.subtract_proven(cov(300, 320), 0, nodes(2), Reservation::Granted);
        let Some(span) = l.unknown() else {
            panic!("still there")
        };
        assert_eq!((span.start(), span.end()), (150, 300));
        assert_eq!(spans(&l), vec![(320, 600, 3)]);
    }

    #[test]
    fn inexact_has_no_host_producer() {
        // 07:331 names "exact checked representation cannot be maintained" as a
        // trigger. Every range here is pre-validated at or below MAX_FILE_SIZE
        // and subrange arithmetic on u64 cannot lose exactness, so nothing on
        // the host reaches it. The variant exists because the document does;
        // the gate's PENDING block carries it rather than the code pretending.
        assert!(
            !shipped_source().contains("MergeTrigger::Inexact)"),
            "if something now returns Inexact, this test and the PENDING block are both stale"
        );
        // It is still a real value, so a later slice can produce it.
        assert_ne!(MergeTrigger::Inexact, MergeTrigger::IntervalBound);
    }

    #[test]
    fn the_ledger_never_holds_touching_or_unordered_intervals() {
        let l = filled(10);
        let mut previous_end: Option<u64> = None;
        for interval in l.intervals() {
            if let Some(end) = previous_end {
                assert!(
                    end < interval.start(),
                    "intervals must be strictly separated: {end} then {}",
                    interval.start()
                );
            }
            previous_end = Some(interval.end());
        }
        assert_eq!(l.len(), 10);
    }

    // ------------------------------------------ the five never-clearing events

    /// A ledger holding one ordinary interval and one UNKNOWN span, so an event
    /// that discarded *either* kind of evidence would show.
    fn with_both_kinds() -> Ledger {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(100, 110, 3), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(200, 210, 5), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(300, 310, 7), 0, nodes(0), Reservation::Granted);
        assert!(l.unknown().is_some(), "the fixture needs an UNKNOWN span");
        let _ = l.record_failure(iv(500, 510, 9), 0, nodes(2), Reservation::Granted);
        assert_eq!(l.len(), 1, "and an ordinary interval beside it");
        l
    }

    /// One event, one assertion. Named per event on purpose: a mutation that
    /// let a single one of the five clear must redden a test that says which.
    fn assert_event_changes_nothing(event: LedgerEvent) {
        let before = with_both_kinds();
        let mut after = seq(1_000, 0, 1);
        after.ledger = before.clone();
        after.observe_event(event);
        assert_eq!(
            after.ledger,
            before,
            "{} discarded or normalized a recorded failure",
            event.phrase()
        );
    }

    #[test]
    fn waiter_absence_never_discards_a_recorded_failure() {
        assert_event_changes_nothing(LedgerEvent::WaiterAbsence);
    }

    #[test]
    fn a_timeout_never_discards_a_recorded_failure() {
        assert_event_changes_nothing(LedgerEvent::Timeout);
    }

    #[test]
    fn cleanup_never_discards_a_recorded_failure() {
        assert_event_changes_nothing(LedgerEvent::Cleanup);
    }

    #[test]
    fn a_session_fence_never_discards_a_recorded_failure() {
        assert_event_changes_nothing(LedgerEvent::SessionFence);
    }

    #[test]
    fn attach_never_discards_a_recorded_failure() {
        assert_event_changes_nothing(LedgerEvent::Attach);
    }

    #[test]
    fn aggregate_observe_event_preserves_each_never_clearing_event() {
        for event in ALL_LEDGER_EVENTS {
            assert_event_changes_nothing(event);
        }
    }

    #[test]
    fn the_fixture_those_five_tests_share_can_actually_show_a_loss() {
        // Anti-vacuity: if `with_both_kinds` produced an empty ledger, all five
        // tests above would pass against any implementation at all.
        let l = with_both_kinds();
        assert!(!l.is_empty());
        assert_eq!(l.len(), 1);
        assert!(l.unknown().is_some());
        let mut cleared = with_both_kinds();
        cleared.ordinary = [None; MAX_INTERVALS];
        cleared.len = 0;
        cleared.unknown = None;
        assert_ne!(
            cleared,
            with_both_kinds(),
            "the comparison can detect a loss"
        );
    }

    // ------------------------------- 5.2: the property over operation sequences

    /// A deterministic LCG. `fsring-core` depends on `fsring-abi` and nothing
    /// else, so there is no `rand` to reach for -- and a fixed sequence is what
    /// makes a failure reproducible anyway.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        /// A value in `[0, n)`, read from the **high** bits.
        ///
        /// An LCG's low bits have period `2^k` for the low `k` of them, so
        /// `next() % 4` cycles with period 4 and is not a coin at all. The
        /// first run of this test produced zero regressing VDLs because of it,
        /// and the anti-vacuity counter is what said so.
        fn below(&mut self, n: u64) -> u64 {
            self.next().wrapping_shr(33).checked_rem(n).unwrap_or(0)
        }
    }

    /// The byte universe the property runs over.
    const ORACLE_BYTES: usize = 512;
    const ORACLE_INLINE_RUNS: usize = 2;
    const ORACLE_MAX_RUNS: usize = 64;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct OracleLabel {
        issue: u64,
        status: i32,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TruthOracle {
        unresolved: [bool; ORACLE_BYTES],
    }

    impl TruthOracle {
        const fn new() -> Self {
            Self {
                unresolved: [false; ORACLE_BYTES],
            }
        }

        fn record(&mut self, start: usize, end: usize) {
            for slot in self.unresolved.get_mut(start..end).unwrap_or(&mut []) {
                *slot = true;
            }
        }

        fn prove(&mut self, start: usize, end: usize) {
            for slot in self.unresolved.get_mut(start..end).unwrap_or(&mut []) {
                *slot = false;
            }
        }

        fn apply_vdl(&mut self, vdl: usize) {
            self.prove(0, vdl.min(ORACLE_BYTES));
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ConservativeOracle {
        ordinary: [Option<OracleLabel>; ORACLE_BYTES],
        unknown: Option<(usize, usize, OracleLabel)>,
    }

    type OracleRunTuple = (usize, usize, OracleLabel);

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OracleRunProjection {
        runs: [Option<OracleRunTuple>; ORACLE_MAX_RUNS],
        len: usize,
        overflowed: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum OracleOrdinaryMismatch {
        OracleRunOverflow {
            run_count: usize,
        },
        Count {
            sut: usize,
            oracle: usize,
        },
        OutOfDomain {
            index: usize,
            start: u64,
            end: u64,
        },
        Run {
            index: usize,
            sut: Option<OracleRunTuple>,
            oracle: Option<OracleRunTuple>,
        },
    }

    #[derive(Default)]
    struct PathCounts {
        exact: usize,
        exact_after_degradation: usize,
        middle_split: usize,
        lower_inline_wins: usize,
        upper_inline_wins: usize,
        orientation_delta_tie: usize,
        interval_bound: usize,
        reservation_failed: usize,
        budget_exhausted: usize,
        failed_reservation_without_need: usize,
        vdl_rejection: usize,
        boundary_64_to_65: usize,
    }

    #[derive(Clone, Copy)]
    enum OracleOperation {
        Record {
            start: usize,
            end: usize,
            label: OracleLabel,
            vdl: usize,
            budget: u64,
            reservation: Reservation,
        },
        Subtract {
            start: usize,
            end: usize,
            vdl: usize,
            budget: u64,
            reservation: Reservation,
        },
        Trim {
            target: usize,
        },
        Reset {
            target: usize,
        },
    }

    fn oracle_label(issue: u64) -> OracleLabel {
        OracleLabel {
            issue,
            status: status_for(issue),
        }
    }

    fn lower_label(left: OracleLabel, right: OracleLabel) -> OracleLabel {
        if left.issue <= right.issue {
            left
        } else {
            right
        }
    }

    fn canonicalize_oracle_runs(ordinary: &mut [Option<OracleLabel>; ORACLE_BYTES]) {
        let mut at = 0usize;
        while at < ORACLE_BYTES {
            let Some(mut lowest) = ordinary.get(at).copied().flatten() else {
                at = at.saturating_add(1);
                continue;
            };
            let start = at;
            at = at.saturating_add(1);
            while at < ORACLE_BYTES {
                let Some(label) = ordinary.get(at).copied().flatten() else {
                    break;
                };
                lowest = lower_label(lowest, label);
                at = at.saturating_add(1);
            }
            for slot in ordinary.get_mut(start..at).unwrap_or(&mut []) {
                *slot = Some(lowest);
            }
        }
    }

    fn oracle_run_count(ordinary: &[Option<OracleLabel>; ORACLE_BYTES]) -> usize {
        let mut runs = 0usize;
        let mut previous_was_set = false;
        for slot in ordinary {
            if slot.is_some() && !previous_was_set {
                runs = runs.saturating_add(1);
            }
            previous_was_set = slot.is_some();
        }
        runs
    }

    fn project_oracle_runs(ordinary: &[Option<OracleLabel>; ORACLE_BYTES]) -> OracleRunProjection {
        let mut projection = OracleRunProjection {
            runs: [None; ORACLE_MAX_RUNS],
            len: 0,
            overflowed: false,
        };
        let mut cursor = 0usize;
        while cursor < ORACLE_BYTES {
            let Some(mut lowest) = ordinary.get(cursor).copied().flatten() else {
                cursor = cursor.saturating_add(1);
                continue;
            };
            let start = cursor;
            cursor = cursor.saturating_add(1);
            while cursor < ORACLE_BYTES {
                let Some(label) = ordinary.get(cursor).copied().flatten() else {
                    break;
                };
                lowest = lower_label(lowest, label);
                cursor = cursor.saturating_add(1);
            }

            if let Some(slot) = projection.runs.get_mut(projection.len) {
                *slot = Some((start, cursor, lowest));
            } else {
                projection.overflowed = true;
            }
            projection.len = projection.len.saturating_add(1);
        }
        projection
    }

    fn compare_ledger_ordinary_to_oracle(
        ledger: &Ledger,
        oracle: &ConservativeOracle,
    ) -> Result<(), OracleOrdinaryMismatch> {
        let projection = project_oracle_runs(&oracle.ordinary);
        if projection.overflowed {
            return Err(OracleOrdinaryMismatch::OracleRunOverflow {
                run_count: projection.len,
            });
        }
        if ledger.len != projection.len {
            return Err(OracleOrdinaryMismatch::Count {
                sut: ledger.len,
                oracle: projection.len,
            });
        }

        for index in 0..projection.len {
            let oracle_run = projection.runs.get(index).copied().flatten();
            let sut_interval = ledger.ordinary.get(index).copied().flatten();
            let sut_run = match sut_interval {
                Some(interval)
                    if interval.start > u(ORACLE_BYTES) || interval.end > u(ORACLE_BYTES) =>
                {
                    return Err(OracleOrdinaryMismatch::OutOfDomain {
                        index,
                        start: interval.start,
                        end: interval.end,
                    });
                }
                Some(interval) => Some((
                    s(interval.start),
                    s(interval.end),
                    OracleLabel {
                        issue: interval.lowest_issue.get(),
                        status: interval.status.get(),
                    },
                )),
                None => None,
            };
            if sut_run != oracle_run {
                return Err(OracleOrdinaryMismatch::Run {
                    index,
                    sut: sut_run,
                    oracle: oracle_run,
                });
            }
        }
        Ok(())
    }

    fn oracle_overflow(run_count: usize) -> usize {
        run_count.saturating_sub(ORACLE_INLINE_RUNS)
    }

    fn oracle_insert(
        ordinary: &mut [Option<OracleLabel>; ORACLE_BYTES],
        start: usize,
        end: usize,
        label: OracleLabel,
    ) {
        for slot in ordinary.get_mut(start..end).unwrap_or(&mut []) {
            *slot = Some(match *slot {
                Some(existing) => lower_label(existing, label),
                None => label,
            });
        }
        canonicalize_oracle_runs(ordinary);
    }

    fn oracle_trigger(
        before_runs: usize,
        projected_runs: usize,
        budget: u64,
        reservation: Reservation,
    ) -> (Option<MergeTrigger>, usize) {
        let needed = oracle_overflow(projected_runs).saturating_sub(oracle_overflow(before_runs));
        if projected_runs > ORACLE_MAX_RUNS {
            return (Some(MergeTrigger::IntervalBound), needed);
        }
        if needed > 0 && reservation == Reservation::Failed {
            return (Some(MergeTrigger::ReservationFailed), needed);
        }
        if u64::try_from(needed).unwrap_or(u64::MAX) > budget {
            return (Some(MergeTrigger::BudgetExhausted), needed);
        }
        (None, needed)
    }

    impl ConservativeOracle {
        const fn new() -> Self {
            Self {
                ordinary: [None; ORACLE_BYTES],
                unknown: None,
            }
        }

        fn widen(&mut self, extra: Option<(usize, usize, OracleLabel)>) {
            let mut span = extra;
            if let Some(unknown) = self.unknown {
                span = Some(match span {
                    Some((start, end, label)) => (
                        start.min(unknown.0),
                        end.max(unknown.1),
                        lower_label(label, unknown.2),
                    ),
                    None => unknown,
                });
            }
            for (byte, label) in self.ordinary.iter().copied().enumerate() {
                let Some(label) = label else {
                    continue;
                };
                span = Some(match span {
                    Some((start, end, lowest)) => (
                        start.min(byte),
                        end.max(byte.saturating_add(1)),
                        lower_label(lowest, label),
                    ),
                    None => (byte, byte.saturating_add(1), label),
                });
            }
            self.ordinary = [None; ORACLE_BYTES];
            self.unknown = span;
        }

        fn note_exact(counts: &mut PathCounts, had_unknown: bool) {
            counts.exact = counts.exact.saturating_add(1);
            if had_unknown {
                counts.exact_after_degradation = counts.exact_after_degradation.saturating_add(1);
            }
        }

        fn note_trigger(counts: &mut PathCounts, trigger: MergeTrigger) {
            match trigger {
                MergeTrigger::IntervalBound => {
                    counts.interval_bound = counts.interval_bound.saturating_add(1);
                }
                MergeTrigger::ReservationFailed => {
                    counts.reservation_failed = counts.reservation_failed.saturating_add(1);
                }
                MergeTrigger::BudgetExhausted => {
                    counts.budget_exhausted = counts.budget_exhausted.saturating_add(1);
                }
                MergeTrigger::Inexact => {
                    panic!("Inexact is unreachable under valid host arithmetic")
                }
            }
        }

        fn record_failure(
            &mut self,
            range: core::ops::Range<usize>,
            label: OracleLabel,
            vdl: usize,
            budget: u64,
            reservation: Reservation,
            counts: &mut PathCounts,
        ) -> RecordOutcome {
            let start = range.start.max(vdl);
            let end = range.end;
            if start >= end {
                return RecordOutcome::BelowVdl;
            }
            let had_unknown = self.unknown.is_some();
            let before_runs = oracle_run_count(&self.ordinary);
            let mut projected = self.clone();
            oracle_insert(&mut projected.ordinary, start, end, label);
            let projected_runs = oracle_run_count(&projected.ordinary);
            let (trigger, needed) =
                oracle_trigger(before_runs, projected_runs, budget, reservation);
            if before_runs == ORACLE_MAX_RUNS && projected_runs == ORACLE_MAX_RUNS + 1 {
                counts.boundary_64_to_65 = counts.boundary_64_to_65.saturating_add(1);
            }
            if trigger.is_none() && reservation == Reservation::Failed && needed == 0 {
                counts.failed_reservation_without_need =
                    counts.failed_reservation_without_need.saturating_add(1);
            }
            if let Some(trigger) = trigger {
                Self::note_trigger(counts, trigger);
                self.widen(Some((start, end, label)));
                return RecordOutcome::Merged(trigger);
            }
            Self::note_exact(counts, had_unknown);
            *self = projected;
            RecordOutcome::Recorded
        }

        fn project_subtraction(&self, start: usize, end: usize, lower_inline: bool) -> Self {
            let mut projected = self.clone();
            for slot in projected.ordinary.get_mut(start..end).unwrap_or(&mut []) {
                *slot = None;
            }
            canonicalize_oracle_runs(&mut projected.ordinary);

            let Some((unknown_start, unknown_end, label)) = self.unknown else {
                return projected;
            };
            if end <= unknown_start || start >= unknown_end {
                return projected;
            }
            let lower =
                (unknown_start < start).then_some((unknown_start, start.min(unknown_end), label));
            let upper = (end < unknown_end).then_some((end.max(unknown_start), unknown_end, label));
            match (lower, upper) {
                (Some(lower), Some(upper)) => {
                    let (inline, ordinary) = if lower_inline {
                        (lower, upper)
                    } else {
                        (upper, lower)
                    };
                    projected.unknown = Some(inline);
                    oracle_insert(&mut projected.ordinary, ordinary.0, ordinary.1, ordinary.2);
                }
                (Some(only), None) | (None, Some(only)) => {
                    projected.unknown = Some(only);
                }
                (None, None) => {
                    projected.unknown = None;
                }
            }
            projected
        }

        fn subtract_proven(
            &mut self,
            start: usize,
            end: usize,
            vdl: usize,
            budget: u64,
            reservation: Reservation,
            counts: &mut PathCounts,
        ) -> RecordOutcome {
            let start = start.max(vdl);
            if start >= end {
                return RecordOutcome::BelowVdl;
            }
            let had_unknown = self.unknown.is_some();
            let before_runs = oracle_run_count(&self.ordinary);
            let lower = self.project_subtraction(start, end, true);
            let mut selected = lower.clone();
            if let Some((unknown_start, unknown_end, _)) = self.unknown {
                if unknown_start < start && end < unknown_end {
                    counts.middle_split = counts.middle_split.saturating_add(1);
                    let upper = self.project_subtraction(start, end, false);
                    let lower_runs = oracle_run_count(&lower.ordinary);
                    let upper_runs = oracle_run_count(&upper.ordinary);
                    let before_overflow = oracle_overflow(before_runs);
                    let lower_new = oracle_overflow(lower_runs).saturating_sub(before_overflow);
                    let upper_new = oracle_overflow(upper_runs).saturating_sub(before_overflow);
                    if upper_new < lower_new {
                        counts.upper_inline_wins = counts.upper_inline_wins.saturating_add(1);
                        selected = upper;
                    } else {
                        if lower_new < upper_new {
                            counts.lower_inline_wins = counts.lower_inline_wins.saturating_add(1);
                        } else if lower_new == 0 && upper_new == 0 && lower_runs != upper_runs {
                            counts.orientation_delta_tie =
                                counts.orientation_delta_tie.saturating_add(1);
                        }
                        selected = lower;
                    }
                }
            }
            let projected_runs = oracle_run_count(&selected.ordinary);
            let (trigger, needed) =
                oracle_trigger(before_runs, projected_runs, budget, reservation);
            if before_runs == ORACLE_MAX_RUNS && projected_runs == ORACLE_MAX_RUNS + 1 {
                counts.boundary_64_to_65 = counts.boundary_64_to_65.saturating_add(1);
            }
            if trigger.is_none() && reservation == Reservation::Failed && needed == 0 {
                counts.failed_reservation_without_need =
                    counts.failed_reservation_without_need.saturating_add(1);
            }
            if let Some(trigger) = trigger {
                Self::note_trigger(counts, trigger);
                self.widen(None);
                return RecordOutcome::Merged(trigger);
            }
            Self::note_exact(counts, had_unknown);
            *self = selected;
            RecordOutcome::Recorded
        }

        fn apply_vdl(&mut self, vdl: usize) {
            for slot in self
                .ordinary
                .get_mut(0..vdl.min(ORACLE_BYTES))
                .unwrap_or(&mut [])
            {
                *slot = None;
            }
            self.unknown = self.unknown.and_then(|(start, end, label)| {
                let start = start.max(vdl);
                (start < end).then_some((start, end, label))
            });
        }
    }

    fn explicit_operation(seed_index: usize, step: usize) -> Option<OracleOperation> {
        let record = |start, end, issue, budget, reservation| OracleOperation::Record {
            start,
            end,
            label: oracle_label(issue),
            vdl: 0,
            budget,
            reservation,
        };
        let subtract = |start, end, budget, reservation| OracleOperation::Subtract {
            start,
            end,
            vdl: 0,
            budget,
            reservation,
        };

        match seed_index {
            0 => match step {
                0 => Some(record(100, 200, 7, 0, Reservation::Granted)),
                1 => Some(record(400, 410, 12, 0, Reservation::Granted)),
                2 => Some(record(500, 510, 13, 1, Reservation::Failed)),
                3 => Some(subtract(200, 510, 0, Reservation::Failed)),
                4 => Some(record(200, 220, 8, 0, Reservation::Granted)),
                5 => Some(record(300, 310, 9, 0, Reservation::Granted)),
                6 => Some(subtract(140, 160, 0, Reservation::Failed)),
                _ => None,
            },
            1 => match step {
                0 => Some(record(100, 200, 7, 0, Reservation::Granted)),
                1 => Some(record(400, 410, 12, 0, Reservation::Granted)),
                2 => Some(record(500, 510, 13, 1, Reservation::Failed)),
                3 => Some(subtract(200, 510, 0, Reservation::Failed)),
                4 => Some(record(80, 100, 8, 0, Reservation::Granted)),
                5 => Some(record(300, 310, 9, 0, Reservation::Granted)),
                6 => Some(subtract(140, 160, 0, Reservation::Failed)),
                _ => None,
            },
            2 => match step {
                0 => Some(record(100, 200, 7, 0, Reservation::Granted)),
                1 => Some(record(400, 410, 12, 0, Reservation::Granted)),
                2 => Some(record(500, 510, 13, 1, Reservation::Failed)),
                3 => Some(subtract(200, 510, 0, Reservation::Failed)),
                4 => Some(record(80, 100, 8, 0, Reservation::Granted)),
                5 => Some(record(140, 145, 9, 0, Reservation::Granted)),
                6 => Some(record(150, 155, 10, 1, Reservation::Granted)),
                7 => Some(record(300, 310, 11, 1, Reservation::Granted)),
                8 => Some(subtract(140, 160, 0, Reservation::Failed)),
                _ => None,
            },
            3 => match step {
                0 => Some(record(10, 20, 1, 0, Reservation::Failed)),
                1 => Some(record(30, 40, 2, 0, Reservation::Failed)),
                // Reservation failure precedes the simultaneously exhausted
                // zero-node budget.
                2 => Some(record(50, 60, 3, 0, Reservation::Failed)),
                _ => None,
            },
            4 => match step {
                0 => Some(record(10, 20, 1, 0, Reservation::Granted)),
                1 => Some(record(30, 40, 2, 0, Reservation::Granted)),
                2 => Some(record(50, 60, 3, 0, Reservation::Granted)),
                _ => None,
            },
            5 => match step {
                0 => Some(record(0, 100, 1, 0, Reservation::Granted)),
                1 => Some(OracleOperation::Trim { target: 32 }),
                2 => Some(OracleOperation::Trim { target: 31 }),
                _ => None,
            },
            6 if step <= ORACLE_MAX_RUNS => {
                let start = step.saturating_mul(2);
                let boundary = step == ORACLE_MAX_RUNS;
                let budget = if boundary {
                    0
                } else if step < ORACLE_INLINE_RUNS {
                    u64::try_from(step).unwrap_or(0)
                } else if step % 2 == 0 {
                    1
                } else {
                    2
                };
                Some(record(
                    start,
                    start.saturating_add(1),
                    u64::try_from(step).unwrap_or(0).saturating_add(1),
                    budget,
                    if boundary {
                        Reservation::Failed
                    } else {
                        Reservation::Granted
                    },
                ))
            }
            _ => None,
        }
    }

    fn generated_operation(
        seed_index: usize,
        step: usize,
        verified: usize,
        rng: &mut Lcg,
    ) -> OracleOperation {
        if let Some(operation) = explicit_operation(seed_index, step) {
            return operation;
        }
        let start = s(rng.below(u(ORACLE_BYTES.saturating_sub(1))));
        let end = start
            .saturating_add(1)
            .saturating_add(s(rng.below(24)))
            .min(ORACLE_BYTES);
        let vdl = s(rng.below(u(ORACLE_BYTES / 4)));
        let budget = u64::try_from(seed_index.saturating_add(step) % 3).unwrap_or(0);
        let reservation = if (seed_index.saturating_add(step / 4)) % 2 == 0 {
            Reservation::Granted
        } else {
            Reservation::Failed
        };
        match seed_index.saturating_add(step) % 4 {
            0 => OracleOperation::Record {
                start,
                end,
                label: oracle_label(
                    10_000u64
                        .saturating_add(u(seed_index).saturating_mul(256))
                        .saturating_add(u(step)),
                ),
                vdl,
                budget,
                reservation,
            },
            1 => OracleOperation::Subtract {
                start,
                end,
                vdl,
                budget,
                reservation,
            },
            2 => {
                let target = if verified > 0 && seed_index.saturating_add(step) % 3 == 0 {
                    verified
                        .saturating_sub(1)
                        .saturating_sub(s(rng.below(u(verified.min(16)))))
                } else {
                    verified.saturating_add(s(rng.below(9))).min(ORACLE_BYTES)
                };
                OracleOperation::Trim { target }
            }
            _ => OracleOperation::Reset {
                target: s(rng.below(u(verified.saturating_add(1)))),
            },
        }
    }

    fn sut_ordinary_label_at(ledger: &Ledger, byte: usize) -> Option<OracleLabel> {
        let byte = u(byte);
        ledger
            .ordinary
            .get(..ledger.len)
            .unwrap_or(&[])
            .iter()
            .flatten()
            .find(|interval| interval.start <= byte && byte < interval.end)
            .map(|interval| OracleLabel {
                issue: interval.lowest_issue.get(),
                status: interval.status.get(),
            })
    }

    fn assert_truth_unresolved_is_subset_of_ledger_coverage(
        ledger: &Ledger,
        truth: &TruthOracle,
        seed: u64,
        step: usize,
    ) {
        for (byte, unresolved) in truth.unresolved.iter().copied().enumerate() {
            if !unresolved {
                continue;
            }
            let covered = ledger.evidence().any(|interval| interval.covers(u(byte)));
            assert!(
                covered,
                "truth_unresolved_is_subset_of_ledger_coverage: seed {seed}, op {step}, byte {byte}"
            );
        }
    }

    fn assert_ledger_ordinary_and_unknown_equal_conservative_oracle(
        ledger: &Ledger,
        oracle: &ConservativeOracle,
        seed: u64,
        step: usize,
    ) {
        assert_eq!(
            compare_ledger_ordinary_to_oracle(ledger, oracle),
            Ok(()),
            "ledger_ordinary_and_unknown_equal_conservative_oracle: seed {seed}, op {step}, exact ordered ordinary tuples"
        );
        assert_eq!(
            ledger.len,
            oracle_run_count(&oracle.ordinary),
            "ledger_ordinary_and_unknown_equal_conservative_oracle: seed {seed}, op {step}, run count"
        );
        for byte in 0..ORACLE_BYTES {
            assert_eq!(
                sut_ordinary_label_at(ledger, byte),
                oracle.ordinary.get(byte).copied().flatten(),
                "ledger_ordinary_and_unknown_equal_conservative_oracle: seed {seed}, op {step}, byte {byte}"
            );
        }
        let sut_unknown = ledger.unknown.map(|span| {
            (
                s(span.start),
                s(span.end),
                OracleLabel {
                    issue: span.lowest_issue.get(),
                    status: span.status.get(),
                },
            )
        });
        assert_eq!(
            sut_unknown, oracle.unknown,
            "ledger_ordinary_and_unknown_equal_conservative_oracle: seed {seed}, op {step}, UNKNOWN"
        );
    }

    #[test]
    fn exact_oracle_comparison_rejects_an_ordinary_end_beyond_its_domain() {
        let label = oracle_label(1);
        let mut oracle = ConservativeOracle::new();
        oracle_insert(&mut oracle.ordinary, 500, ORACLE_BYTES, label);

        let mut ledger = Ledger::new();
        let Some(slot) = ledger.ordinary.get_mut(0) else {
            panic!("the SUT has no first ordinary slot")
        };
        *slot = Some(iv(500, 513, label.issue));
        ledger.len = 1;

        // Anti-vacuity: these are the old checks. They both pass because byte
        // 512 lies just outside the model loop even though the SUT run reaches
        // it.
        assert_eq!(ledger.len, oracle_run_count(&oracle.ordinary));
        for byte in 0..ORACLE_BYTES {
            assert_eq!(
                sut_ordinary_label_at(&ledger, byte),
                oracle.ordinary.get(byte).copied().flatten()
            );
        }

        assert_eq!(
            compare_ledger_ordinary_to_oracle(&ledger, &oracle),
            Err(OracleOrdinaryMismatch::OutOfDomain {
                index: 0,
                start: 500,
                end: 513,
            })
        );
    }

    fn assert_lowest_issue_and_its_status_are_preserved(
        ledger: &Ledger,
        oracle: &ConservativeOracle,
        seed: u64,
        step: usize,
    ) {
        for label in oracle.ordinary.iter().flatten() {
            assert_eq!(
                label.status,
                status_for(label.issue),
                "lowest_issue_and_its_status_are_preserved: seed {seed}, op {step}, oracle issue {}",
                label.issue
            );
        }
        if let Some((_, _, label)) = oracle.unknown {
            assert_eq!(
                label.status,
                status_for(label.issue),
                "lowest_issue_and_its_status_are_preserved: seed {seed}, op {step}, oracle UNKNOWN"
            );
        }
        for interval in ledger
            .ordinary
            .get(..ledger.len)
            .unwrap_or(&[])
            .iter()
            .flatten()
            .chain(ledger.unknown.iter())
        {
            assert_eq!(
                interval.status.get(),
                status_for(interval.lowest_issue.get()),
                "lowest_issue_and_its_status_are_preserved: seed {seed}, op {step}, SUT issue {}",
                interval.lowest_issue.get()
            );
        }
    }

    #[test]
    fn degradation_never_drops_evidence_over_operation_sequences() {
        const SEEDS: [u64; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        const OPERATIONS_PER_SEED: usize = 256;
        let mut counts = PathCounts::default();
        for (seed_index, seed) in SEEDS.into_iter().enumerate() {
            let mut rng = Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
            let mut ledger = Ledger::new();
            let mut truth = TruthOracle::new();
            let mut conservative = ConservativeOracle::new();
            let mut verified = 0usize;

            for step in 0..OPERATIONS_PER_SEED {
                let operation = generated_operation(seed_index, step, verified, &mut rng);
                match operation {
                    OracleOperation::Record {
                        start,
                        end,
                        label,
                        vdl,
                        budget,
                        reservation,
                    } => {
                        let expected = conservative.record_failure(
                            start..end,
                            label,
                            vdl,
                            budget,
                            reservation,
                            &mut counts,
                        );
                        if start.max(vdl) < end {
                            truth.record(start.max(vdl), end);
                        }
                        let actual = ledger.record_failure(
                            iv(u(start), u(end), label.issue),
                            u(vdl),
                            nodes(budget),
                            reservation,
                        );
                        assert!(
                            !matches!(actual, RecordOutcome::Merged(MergeTrigger::Inexact)),
                            "Inexact became reachable under valid host arithmetic: seed {seed}, op {step}"
                        );
                        assert_eq!(
                            actual, expected,
                            "record_outcome_equals_independently_predicted_outcome: seed {seed}, op {step}"
                        );
                    }
                    OracleOperation::Subtract {
                        start,
                        end,
                        vdl,
                        budget,
                        reservation,
                    } => {
                        let expected = conservative.subtract_proven(
                            start,
                            end,
                            vdl,
                            budget,
                            reservation,
                            &mut counts,
                        );
                        truth.prove(start.max(vdl), end);
                        let actual = ledger.subtract_proven(
                            cov(u(start), u(end)),
                            u(vdl),
                            nodes(budget),
                            reservation,
                        );
                        assert!(
                            !matches!(actual, RecordOutcome::Merged(MergeTrigger::Inexact)),
                            "Inexact became reachable under valid host arithmetic: seed {seed}, op {step}"
                        );
                        assert_eq!(
                            actual, expected,
                            "record_outcome_equals_independently_predicted_outcome: seed {seed}, op {step}"
                        );
                    }
                    OracleOperation::Trim { target } => {
                        let before_ledger = ledger.clone();
                        let before_truth = truth.clone();
                        let before_conservative = conservative.clone();
                        let actual = ledger.trim_to_vdl(u(verified), u(target));
                        if target < verified {
                            counts.vdl_rejection = counts.vdl_rejection.saturating_add(1);
                            assert_eq!(
                                actual,
                                Err(LedgerError::VdlRegressed),
                                "record_outcome_equals_independently_predicted_outcome: seed {seed}, op {step}"
                            );
                            assert_eq!(
                                ledger, before_ledger,
                                "regressed VDL mutated the SUT: seed {seed}, op {step}"
                            );
                            assert_eq!(truth, before_truth);
                            assert_eq!(conservative, before_conservative);
                        } else {
                            assert_eq!(
                                actual,
                                Ok(()),
                                "record_outcome_equals_independently_predicted_outcome: seed {seed}, op {step}"
                            );
                            verified = target;
                            truth.apply_vdl(target);
                            conservative.apply_vdl(target);
                        }
                    }
                    OracleOperation::Reset { target } => {
                        let actual = ledger.truncate_reset(u(target));
                        assert_eq!(
                            actual,
                            Ok(()),
                            "record_outcome_equals_independently_predicted_outcome: seed {seed}, op {step}"
                        );
                        verified = target;
                        truth.apply_vdl(target);
                        conservative.apply_vdl(target);
                    }
                }

                assert_truth_unresolved_is_subset_of_ledger_coverage(&ledger, &truth, seed, step);
                assert_ledger_ordinary_and_unknown_equal_conservative_oracle(
                    &ledger,
                    &conservative,
                    seed,
                    step,
                );
                assert!(
                    ledger.len <= ORACLE_MAX_RUNS,
                    "ordinary_count_is_at_most_64: seed {seed}, op {step}, count {}",
                    ledger.len
                );
                assert_lowest_issue_and_its_status_are_preserved(
                    &ledger,
                    &conservative,
                    seed,
                    step,
                );
            }
        }

        assert!(counts.exact > 0, "exact was not exercised");
        assert!(
            counts.exact_after_degradation > 0,
            "exact-after-degradation was not exercised"
        );
        assert!(counts.middle_split > 0, "middle split was not exercised");
        assert!(
            counts.lower_inline_wins > 0,
            "true lower-inline win was not exercised"
        );
        assert!(
            counts.upper_inline_wins > 0,
            "true upper-inline win was not exercised"
        );
        assert!(
            counts.orientation_delta_tie > 0,
            "new-node delta tie was not exercised"
        );
        assert!(
            counts.interval_bound > 0,
            "interval bound was not exercised"
        );
        assert!(
            counts.reservation_failed > 0,
            "reservation failure was not exercised"
        );
        assert!(
            counts.budget_exhausted > 0,
            "budget exhaustion was not exercised"
        );
        assert!(
            counts.failed_reservation_without_need > 0,
            "failed reservation without need was not exercised"
        );
        assert!(counts.vdl_rejection > 0, "VDL rejection was not exercised");
        assert!(
            counts.boundary_64_to_65 > 0,
            "the 64-to-65 boundary was not exercised"
        );
    }

    // ================================ the linearization order and the barrier

    fn validated(file_size: u64, vdl: u64, epoch: u64) -> ValidatedSizeState {
        let Ok(state) = size::validate(SizeTrio::new(file_size, file_size, vdl), epoch) else {
            panic!("the test size trio must be valid")
        };
        state
    }

    fn clamped_truncation(
        current: SizeTrio,
        returned: SizeTrio,
        old_epoch: u64,
        new_epoch: u64,
    ) -> Truncation<VdlClamped> {
        // SAFETY: this is a host unit test with no kernel IRQL; it exercises the
        // existing B3 capability seam rather than minting a production token.
        let passive = unsafe { passive_at_driver_entry() };
        let Ok(publication) = publish_sizes_to_cc(
            &passive,
            &unsafe { crate::effect::EffectContext::empty() },
            IoOrigin::Cached,
            SizeChange::Reduce,
        ) else {
            panic!("unlocked cached reduction publication must be permitted")
        };
        let Ok(returned_state) = size::validate(returned, new_epoch) else {
            panic!("returned test state must be valid")
        };
        let Ok(started) = Truncation::mm_veto(current, returned, MmVerdict::CanTruncate) else {
            panic!("the fixture must be a reduction with a cleared veto")
        };
        let committed = started
            .publish_sizes(publication)
            .purge_tail()
            .commit(EpochCapture::new(old_epoch), returned_state);
        let Ok(committed) = committed else {
            panic!("the returned epoch must advance")
        };
        committed.clamp_vdl()
    }

    fn seq(file_size: u64, vdl: u64, epoch: u64) -> SequencerState {
        let Ok(state) = SequencerState::try_new(validated(file_size, vdl, epoch)) else {
            panic!("the production ID allocator must not be exhausted in ordinary tests")
        };
        state
    }

    fn write(start: u64, end: u64) -> PagingWrite<Extracted> {
        let Ok(write) = PagingWrite::extract(start, end) else {
            panic!("the test paging range must be valid")
        };
        write
    }

    #[test]
    fn sequencer_ids_are_nonzero_unique_and_move_stable() {
        fn move_it(s: SequencerState) -> SequencerState {
            s
        }

        let first = seq(100, 0, 1);
        let second = seq(100, 0, 1);
        assert_ne!(first.id().get(), 0);
        assert_ne!(second.id().get(), 0);
        assert_ne!(first.id(), second.id());
        let id = first.id();
        let moved = move_it(first);
        assert_eq!(moved.id(), id);
    }

    #[test]
    fn sequencer_ids_near_max_become_sticky_exhausted() {
        let ordinary = AtomicU64::new(1);
        assert_eq!(allocate_sequencer_id(&ordinary).map(|id| id.get()), Ok(1));

        let near_max = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            allocate_sequencer_id(&near_max).map(|id| id.get()),
            Ok(u64::MAX - 1)
        );
        assert_eq!(near_max.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            allocate_sequencer_id(&near_max),
            Err(SequencerInitError::IdsExhausted)
        );
        assert_eq!(
            allocate_sequencer_id(&near_max),
            Err(SequencerInitError::IdsExhausted)
        );

        let exhausted = AtomicU64::new(u64::MAX);
        assert_eq!(
            allocate_sequencer_id(&exhausted),
            Err(SequencerInitError::IdsExhausted)
        );
        assert_eq!(exhausted.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn sequencer_ids_are_unique_under_concurrent_allocation() {
        let ids = AtomicU64::new(1);
        let mut allocated = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..16 {
                handles.push(scope.spawn(|| {
                    let Ok(id) = allocate_sequencer_id(&ids) else {
                        panic!("a fresh local allocator must not exhaust")
                    };
                    id.get()
                }));
            }
            handles
                .into_iter()
                .map(|handle| match handle.join() {
                    Ok(id) => id,
                    Err(_) => panic!("allocation thread panicked"),
                })
                .collect::<Vec<_>>()
        });
        allocated.sort_unstable();
        allocated.dedup();
        assert_eq!(allocated.len(), 16);
    }

    fn in_flight(outcome: &AdmissionOutcome) -> &PagingWrite<Linearized> {
        let AdmissionOutcome::InFlight(write) = outcome else {
            panic!("the fixture must contain an in-flight write")
        };
        write
    }

    #[test]
    fn separate_owners_may_issue_one_without_interchangeable_capabilities() {
        let mut a = seq(100, 0, 1);
        let mut b = seq(100, 0, 1);
        let a_size = a.bind_size(validated(100, 0, 2));
        let a_claim = a.bind_claim(ContextClaimResult::Acquired);
        let b_size = b.bind_size(validated(100, 0, 2));
        let b_claim = b.bind_claim(ContextClaimResult::Acquired);
        let a_out = a.admit(write(0, 10), a_size, a_claim);
        let b_out = b.admit(write(20, 30), b_size, b_claim);
        assert_eq!(in_flight(&a_out).issue().get(), 1);
        assert_eq!(in_flight(&b_out).issue().get(), 1);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn foreign_size_owner_rejects_claim_admission_without_mutation() {
        let mut owner = seq(100, 0, 1);
        let foreign = seq(100, 0, 1);
        let snapshot = foreign.bind_size(validated(100, 0, 2));
        let outcome = owner.admit(
            write(10, 20),
            snapshot,
            owner.bind_claim(ContextClaimResult::Acquired),
        );
        let AdmissionOutcome::Rejected(rejection) = outcome else {
            panic!("a foreign size snapshot must be returned without mutation")
        };
        let (reason, returned_write, returned_snapshot, returned_claim) = rejection.into_parts();
        assert_eq!(reason, AdmissionRejectionReason::WrongSizeOwner);
        assert_eq!(
            (returned_write.range().start(), returned_write.range().end()),
            (10, 20)
        );
        assert_eq!(returned_snapshot, snapshot);
        assert_eq!(returned_claim.owner(), owner.id());
        assert_eq!(returned_claim.result(), ContextClaimResult::Acquired);
        assert_eq!(owner.last_issued(), 0);
        assert_eq!(owner.active_count(), 0);
        assert_eq!(owner.intervals().count(), 0);
    }

    #[test]
    fn foreign_claim_owner_rejects_claim_admission_without_mutation() {
        let mut owner = seq(100, 0, 1);
        let foreign = seq(100, 0, 1);
        let snapshot = owner.bind_size(validated(100, 0, 2));
        let foreign_claim = foreign.bind_claim(ContextClaimResult::Acquired);
        let outcome = owner.admit(write(10, 20), snapshot, foreign_claim);
        let AdmissionOutcome::Rejected(rejection) = outcome else {
            panic!("a foreign claim must be returned without mutation")
        };
        let (reason, returned_write, returned_snapshot, returned_claim) = rejection.into_parts();
        assert_eq!(reason, AdmissionRejectionReason::WrongClaimOwner);
        assert_eq!(
            (returned_write.range().start(), returned_write.range().end()),
            (10, 20)
        );
        assert_eq!(returned_snapshot, snapshot);
        assert_eq!(returned_claim.owner(), foreign.id());
        assert_eq!(returned_claim.result(), ContextClaimResult::Acquired);
        assert_eq!(owner.last_issued(), 0);
        assert_eq!(owner.active_count(), 0);
        assert_eq!(owner.intervals().count(), 0);
    }

    #[test]
    fn failed_claim_admission_numbers_records_and_returns_claim() {
        let mut state = seq(100, 0, 1);
        let snapshot = state.bind_size(validated(100, 0, 2));
        let outcome = state.admit(
            write(10, 20),
            snapshot,
            state.bind_claim(ContextClaimResult::Failed),
        );
        let AdmissionOutcome::ClaimRejected { receipt, claim } = outcome else {
            panic!("a failed claim must number and terminalize the extracted write")
        };
        assert_eq!(receipt.owner(), state.id());
        assert_eq!(receipt.issue().get(), 1);
        assert_eq!(receipt.prefix(), 1);
        assert_eq!(receipt.outcome(), RecordOutcome::Recorded);
        assert_eq!(claim.owner(), state.id());
        assert_eq!(claim.result(), ContextClaimResult::Failed);
        assert_eq!(state.last_issued(), 1);
        assert_eq!(state.active_count(), 0);
        let Some(only) = state.intervals().next() else {
            panic!("the entire rejected range must be recorded")
        };
        assert_eq!((only.start(), only.end()), (10, 20));
        assert_eq!(
            only.status().get(),
            completion_status::INSUFFICIENT_RESOURCES
        );
    }

    #[test]
    fn full_claim_admission_numbers_records_and_returns_acquired_claim() {
        let mut state = seq(600, 0, 1);
        let snapshot = state.bind_size(validated(600, 0, 2));
        for _ in 0..ACTIVE_CAPACITY {
            let claim = state.bind_claim(ContextClaimResult::Acquired);
            let outcome = state.admit(write(0, 1), snapshot, claim);
            let AdmissionOutcome::InFlight(_) = outcome else {
                panic!("the active set must admit entries below its own capacity")
            };
        }
        let outcome = state.admit(
            write(500, 600),
            snapshot,
            state.bind_claim(ContextClaimResult::Acquired),
        );
        let AdmissionOutcome::ClaimRejected { receipt, claim } = outcome else {
            panic!("a full context claim must be immediately terminal")
        };
        assert_eq!(receipt.owner(), state.id());
        assert_eq!(receipt.issue().get(), u(ACTIVE_CAPACITY).saturating_add(1));
        assert_eq!(receipt.prefix(), 0);
        assert_eq!(claim.owner(), state.id());
        assert_eq!(claim.result(), ContextClaimResult::Acquired);
        assert_eq!(state.active_count(), ACTIVE_CAPACITY);
        let Some(only) = state.intervals().next() else {
            panic!("the full-claim rejection must record its whole range")
        };
        assert_eq!((only.start(), only.end()), (500, 600));
        assert_eq!(
            only.status().get(),
            completion_status::INSUFFICIENT_RESOURCES
        );
    }

    #[test]
    fn issue_exhaustion_closes_admission_without_retry() {
        let mut state = seq(100, 0, 1);
        state.counter.last_issued = u64::MAX;
        let snapshot = state.bind_size(validated(100, 0, 2));
        let outcome = state.admit(
            write(10, 20),
            snapshot,
            state.bind_claim(ContextClaimResult::Acquired),
        );
        let AdmissionOutcome::MountFatal { failure, claim } = outcome else {
            panic!("issue exhaustion must close the mount admission lane")
        };
        assert_eq!(failure.owner(), state.id());
        assert_eq!((failure.range().start(), failure.range().end()), (10, 20));
        assert_eq!(claim.result(), ContextClaimResult::Acquired);
        assert_eq!(state.last_issued(), u64::MAX);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.intervals().count(), 0);

        let retry = state.admit(
            write(30, 40),
            snapshot,
            state.bind_claim(ContextClaimResult::Failed),
        );
        let AdmissionOutcome::MountFatal {
            failure: retry_failure,
            claim: retry_claim,
        } = retry
        else {
            panic!("a closed admission lane must not retry issue allocation")
        };
        assert_eq!(
            (retry_failure.range().start(), retry_failure.range().end()),
            (30, 40)
        );
        assert_eq!(retry_claim.result(), ContextClaimResult::Failed);
        assert_eq!(state.last_issued(), u64::MAX);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.intervals().count(), 0);
    }

    #[test]
    fn a_preexisting_active_write_remains_active_after_issue_exhaustion_closure() {
        let mut state = seq(100, 0, 1);
        let snapshot = state.bind_size(validated(100, 0, 2));
        let claim = state.bind_claim(ContextClaimResult::Acquired);
        let first = state.admit(write(0, 10), snapshot, claim);
        let AdmissionOutcome::InFlight(_) = first else {
            panic!("the fixture must first create an active write")
        };
        state.counter.last_issued = u64::MAX;
        let fatal = state.admit(
            write(20, 30),
            snapshot,
            state.bind_claim(ContextClaimResult::Acquired),
        );
        let AdmissionOutcome::MountFatal { .. } = fatal else {
            panic!("the later exhausted issue must close admission")
        };
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.minimum_active().map(Issue::get), Some(1));
        assert_eq!(state.terminal_prefix(), 0);
    }

    fn admitted(start: u64, end: u64) -> (SequencerState, PagingWrite<Linearized>, SizeSnapshot) {
        let mut state = seq(end, 0, 1);
        let snapshot = state.bind_size(validated(end, 0, 2));
        let claim = state.bind_claim(ContextClaimResult::Acquired);
        let outcome = state.admit(write(start, end), snapshot, claim);
        let AdmissionOutcome::InFlight(write) = outcome else {
            panic!("the fixture must admit one in-flight write")
        };
        (state, write, snapshot)
    }

    fn failure(raw: i32) -> FailureStatus {
        let Ok(status) = FailureStatus::new(raw) else {
            panic!("the fixture must use a negative failure status")
        };
        status
    }

    fn admit_acquired(
        state: &mut SequencerState,
        start: u64,
        end: u64,
        epoch: u64,
    ) -> PagingWrite<Linearized> {
        let snapshot = state.bind_size(validated(end, 0, epoch));
        let claim = state.bind_claim(ContextClaimResult::Acquired);
        match state.admit(write(start, end), snapshot, claim) {
            AdmissionOutcome::InFlight(write) => write,
            _ => panic!("the fixture admission must be in flight"),
        }
    }

    type StateSnapshot = (
        SequencerId,
        IssueCounter,
        ActiveSet,
        Ledger,
        AdmissionState,
        u64,
    );

    fn snapshot_state(state: &SequencerState) -> StateSnapshot {
        (
            state.id,
            state.counter.clone(),
            state.active.clone(),
            state.ledger.clone(),
            state.admission,
            state.verified_vdl_baseline(),
        )
    }

    #[test]
    fn failure_status_rejects_every_nonfailure_class_used_by_the_contract() {
        assert_eq!(
            FailureStatus::new(completion_status::SUCCESS),
            Err(FailureStatusError)
        );
        assert_eq!(
            FailureStatus::new(completion_status::PENDING),
            Err(FailureStatusError)
        );
        assert_eq!(FailureStatus::new(1), Err(FailureStatusError));
        assert_eq!(
            FailureStatus::new(completion_status::IO_TIMEOUT).map(FailureStatus::get),
            Ok(completion_status::IO_TIMEOUT)
        );
    }

    #[test]
    fn foreign_sequencer_rejects_a_live_write_and_the_owner_can_retry_it() {
        let mut a = seq(100, 0, 1);
        let mut b = seq(100, 0, 1);
        let write_a = admit_acquired(&mut a, 0, 100, 2);
        let write_b = admit_acquired(&mut b, 0, 100, 2);
        assert_eq!(write_a.issue(), write_b.issue());
        assert_eq!(write_a.issue().get(), 1);
        let before_a = snapshot_state(&a);
        let before_b = snapshot_state(&b);
        let b_size = b.bind_size(validated(100, 0, 2));
        let result = b.terminalize(
            write_a,
            b_size,
            nodes(0),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        );
        let Err(rejection) = result else {
            panic!("owner B must reject owner A's write")
        };
        assert_eq!(rejection.reason(), WriteRejectionReason::WrongSequencer);
        assert_eq!(snapshot_state(&a), before_a);
        assert_eq!(snapshot_state(&b), before_b);
        assert_eq!(write_b.issue().get(), 1);
        assert_eq!(b.minimum_active().map(Issue::get), Some(1));
        let a_size = a.bind_size(validated(100, 0, 2));
        let result = a.terminalize(
            rejection.into_write(),
            a_size,
            nodes(0),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        );
        let Ok(receipt) = result else {
            panic!("the original owner must retain a live capability")
        };
        assert_eq!(receipt.prefix(), 1);
        assert_eq!(
            a.intervals()
                .map(|iv| (iv.start(), iv.end()))
                .collect::<Vec<_>>(),
            vec![(0, 100)]
        );
        assert_eq!(a.unknown(), None);
    }

    #[test]
    fn foreign_size_snapshot_rejects_a_live_write_without_mutation() {
        let mut a = seq(100, 0, 1);
        let b = seq(100, 0, 1);
        let write_a = admit_acquired(&mut a, 0, 100, 2);
        let foreign_size = b.bind_size(validated(100, 0, 2));
        let before_a = snapshot_state(&a);
        let before_b = snapshot_state(&b);
        let result = a.terminalize(
            write_a,
            foreign_size,
            nodes(0),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        );
        let Err(rejection) = result else {
            panic!("a foreign size snapshot must be rejected")
        };
        assert_eq!(rejection.reason(), WriteRejectionReason::WrongSizeOwner);
        assert_eq!(snapshot_state(&a), before_a);
        assert_eq!(snapshot_state(&b), before_b);

        let own_size = a.bind_size(validated(100, 0, 2));
        assert!(
            a.terminalize(
                rejection.into_write(),
                own_size,
                nodes(0),
                Reservation::Granted,
                failure(completion_status::IO_TIMEOUT),
            )
            .is_ok()
        );
    }

    #[test]
    fn invalid_completion_coverage_returns_the_live_write_without_mutation() {
        let mut state = seq(100, 0, 1);
        let write = admit_acquired(&mut state, 10, 100, 2);
        let before = snapshot_state(&state);
        let snapshot = state.bind_size(validated(100, 0, 2));
        let result = state.complete(
            write,
            snapshot,
            nodes(0),
            Reservation::Granted,
            Some(cov(11, 100)),
        );
        let Err(rejection) = result else {
            panic!("a non-prefix coverage claim must be rejected")
        };
        assert_eq!(
            rejection.reason(),
            WriteRejectionReason::CoverageOutsideRequest
        );
        assert_eq!(snapshot_state(&state), before);
        let snapshot = state.bind_size(validated(100, 0, 2));
        assert!(
            state
                .complete(
                    rejection.into_write(),
                    snapshot,
                    nodes(0),
                    Reservation::Granted,
                    Some(cov(10, 100)),
                )
                .is_ok()
        );

        let write = admit_acquired(&mut state, 10, 100, 3);
        let before = snapshot_state(&state);
        let snapshot = state.bind_size(validated(100, 0, 3));
        let result = state.complete(
            write,
            snapshot,
            nodes(0),
            Reservation::Granted,
            Some(cov(10, 101)),
        );
        let Err(rejection) = result else {
            panic!("coverage beyond the request must be rejected")
        };
        assert_eq!(
            rejection.reason(),
            WriteRejectionReason::CoverageOutsideRequest
        );
        assert_eq!(snapshot_state(&state), before);
    }

    #[test]
    fn inactive_write_is_rejected_before_evidence_mutates() {
        let mut state = seq(100, 0, 1);
        let live_write = admit_acquired(&mut state, 0, 100, 2);
        state.active.len = 0;
        let before = snapshot_state(&state);
        let snapshot = state.bind_size(validated(100, 0, 2));
        let result = state.terminalize(
            live_write,
            snapshot,
            nodes(0),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        );
        let Err(rejection) = result else {
            panic!("an inactive write must be rejected")
        };
        assert_eq!(rejection.reason(), WriteRejectionReason::NotActive);
        assert_eq!(snapshot_state(&state), before);
        let _returned = rejection.into_write();
    }

    #[test]
    fn dropping_a_live_write_leaves_its_issue_active() {
        let mut state = seq(100, 0, 1);
        {
            let write = admit_acquired(&mut state, 0, 100, 2);
            assert_eq!(write.issue().get(), 1);
        }
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.terminal_prefix(), 0);
    }

    #[test]
    fn short_success_subtracts_its_exact_prefix_then_records_only_the_suffix() {
        let mut state = seq(200, 0, 1);
        let failed = admit_acquired(&mut state, 100, 150, 2);
        let snapshot = state.bind_size(validated(200, 0, 2));
        assert!(
            state
                .terminalize(
                    failed,
                    snapshot,
                    nodes(2),
                    Reservation::Granted,
                    failure(completion_status::IO_TIMEOUT),
                )
                .is_ok()
        );
        let retry = admit_acquired(&mut state, 100, 200, 3);
        let snapshot = state.bind_size(validated(200, 0, 3));
        let Ok(receipt) = state.complete(
            retry,
            snapshot,
            nodes(2),
            Reservation::Granted,
            Some(cov(100, 150)),
        ) else {
            panic!("a short success must complete")
        };
        assert_eq!(receipt.prefix(), 2);
        let Some(only) = state.intervals().next() else {
            panic!("the suffix must remain unresolved")
        };
        assert_eq!((only.start(), only.end()), (150, 200));
        assert_eq!(only.status().get(), completion_status::IO_DEVICE_ERROR);
    }

    /// A sink for the measurement below. It performs nothing; the recorder is
    /// what the test reads.
    struct NullSink;
    // SAFETY: performs no kernel effect at all, so `EffectSink`'s obligations
    // about performing exactly the requested effect are vacuous for it.
    unsafe impl crate::effect::EffectSink for NullSink {
        unsafe fn emit(&mut self, _effect: crate::effect::Effect) {}
    }

    /// The recorder's `assert_none_between` fires on an allocation recorded
    /// under the sequencer.
    ///
    /// **This tests the recorder, not this module.** C1's review round 1
    /// established that no production path here reaches the seam, so nothing in
    /// `pagingledger` can be observed by it; the companion test that claimed
    /// otherwise is deleted. What survives is a check that the assertion itself
    /// works, kept next to the rule it is about so a future slice wiring these
    /// paths through the seam finds it already here.
    ///
    /// The effect is recorded directly rather than emitted because the seam
    /// would refuse it — that refusal is
    /// `effect::tests::an_allocation_under_the_sequencer_names_07_section_6`'s
    /// job.
    #[test]
    #[should_panic(expected = "to be absent between")]
    fn a_planted_allocation_under_the_sequencer_is_caught() {
        use crate::effect::{AllocTarget, Effect, EffectContext, Seam, recorder};
        use crate::lockrank::LockRank;

        recorder::reset();
        let mut seam = Seam::new(NullSink);
        let mut ctx = unsafe { EffectContext::empty() };
        assert_eq!(seam.emit(&ctx, Effect::PrivilegeOrAccessCheck), Ok(()));
        {
            let Ok(guard) = ctx.acquire(LockRank::Sequencer) else {
                panic!("legal from an empty context")
            };
            recorder::record(guard.context(), Effect::Allocate(AllocTarget::Pool));
        }
        assert_eq!(seam.emit(&ctx, Effect::NotificationCallback), Ok(()));
        recorder::assert_none_between(
            |e| matches!(e, Effect::Allocate(_)),
            Effect::PrivilegeOrAccessCheck,
            Effect::NotificationCallback,
        );
    }

    #[test]
    fn terminal_failure_records_the_full_range_removes_its_exact_issue_then_advances_prefix() {
        let mut state = seq(100, 0, 1);
        let write = admit_acquired(&mut state, 0, 100, 2);
        let snapshot = state.bind_size(validated(100, 0, 2));
        let Ok(receipt) = state.terminalize(
            write,
            snapshot,
            nodes(0),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        ) else {
            panic!("terminal failure must complete")
        };
        assert_eq!(receipt.owner(), state.id());
        assert_eq!(receipt.issue().get(), 1);
        assert_eq!(receipt.outcome(), RecordOutcome::Recorded);
        assert_eq!(receipt.terminal_kind(), TerminalKind::Failed);
        assert_eq!(state.active_count(), 0);
        assert_eq!(receipt.prefix(), 1);
        let Some(only) = state.intervals().next() else {
            panic!("the full failed range must be recorded")
        };
        assert_eq!((only.start(), only.end()), (0, 100));
    }

    #[test]
    fn active_write_can_terminalize_after_admission_closes() {
        let mut state = seq(100, 0, 1);
        let live_write = admit_acquired(&mut state, 0, 100, 2);
        state.counter.last_issued = u64::MAX;
        let snapshot = state.bind_size(validated(100, 0, 2));
        let fatal = state.admit(
            write(10, 20),
            snapshot,
            state.bind_claim(ContextClaimResult::Acquired),
        );
        assert!(matches!(fatal, AdmissionOutcome::MountFatal { .. }));
        let snapshot = state.bind_size(validated(100, 0, 2));
        let Ok(receipt) = state.terminalize(
            live_write,
            snapshot,
            nodes(0),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        ) else {
            panic!("an already active write must terminalize after closure")
        };
        assert_eq!(receipt.issue().get(), 1);
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn active_terminal_receipts_report_terminal_kind_and_claim_rejections_do_not_remove_active_issues()
     {
        let mut state = seq(100, 0, 1);
        let live_write = admit_acquired(&mut state, 0, 100, 2);
        let snapshot = state.bind_size(validated(100, 0, 2));
        let Ok(completed) =
            state.complete(live_write, snapshot, nodes(0), Reservation::Granted, None)
        else {
            panic!("completion must return a receipt")
        };
        assert_eq!(completed.owner(), state.id());
        assert_eq!(completed.issue().get(), 1);
        assert_eq!(completed.prefix(), 1);
        assert_eq!(completed.outcome(), RecordOutcome::Recorded);
        assert_eq!(completed.terminal_kind(), TerminalKind::Completed);

        let _active = admit_acquired(&mut state, 10, 20, 3);
        assert_eq!(_active.issue().get(), 2);
        let rejected = state.admit(
            write(30, 40),
            state.bind_size(validated(100, 0, 3)),
            state.bind_claim(ContextClaimResult::Failed),
        );
        let AdmissionOutcome::ClaimRejected { receipt, .. } = rejected else {
            panic!("a failed claim must use its distinct receipt")
        };
        assert_eq!(receipt.owner(), state.id());
        assert_eq!(receipt.issue().get(), 3);
        assert_eq!(receipt.prefix(), 1);
        assert_eq!(receipt.outcome(), RecordOutcome::Recorded);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.minimum_active().map(Issue::get), Some(2));
    }

    #[test]
    fn an_exit_records_before_it_retires_the_active_entry() {
        let (mut state, write, snapshot) = admitted(100, 200);
        assert_eq!(state.intervals().count(), 0, "nothing is recorded yet");

        let Ok(receipt) = state.terminalize(
            write,
            snapshot,
            nodes(2),
            Reservation::Granted,
            failure(completion_status::DEVICE_NOT_READY),
        ) else {
            panic!("terminalize refused")
        };
        assert_eq!(receipt.outcome(), RecordOutcome::Recorded);
        assert_eq!(state.active_count(), 0);
        assert_eq!(
            state
                .intervals()
                .map(|iv| (iv.start(), iv.end(), iv.lowest_issue().get()))
                .collect::<Vec<_>>(),
            vec![(100, 200, 1)],
            "the receipt exists because the ledger changed before retirement"
        );
    }

    #[test]
    fn a_post_linearization_failure_terminalizes_the_whole_requested_range() {
        // 07:314-317: "a synchronous early failure MAY conservatively record its
        // full requested range."
        let (mut state, write, snapshot) = admitted(100, 200);
        let _ = write.validate_mdl();
        let Ok(receipt) = state.terminalize(
            write,
            snapshot,
            nodes(2),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        ) else {
            panic!("terminalize refused")
        };
        assert_eq!(receipt.issue().get(), 1);
        let Some(only) = state.intervals().next() else {
            panic!("one interval")
        };
        assert_eq!((only.start(), only.end()), (100, 200));
        assert_eq!(
            only.status().get(),
            completion_status::IO_TIMEOUT,
            "the terminal path's own registered status"
        );
    }

    #[test]
    fn a_short_success_records_its_unproven_suffix_as_io_device_error() {
        // 07:320-322: the suffix "carries the fail-closed IO_DEVICE_ERROR status
        // rather than being assumed committed". Assuming it committed is the
        // unsafe direction and the reason this module exists.
        let (mut state, write, snapshot) = admitted(100, 200);
        let Ok(receipt) = state.complete(
            write,
            snapshot,
            nodes(2),
            Reservation::Granted,
            Some(cov(100, 150)),
        ) else {
            panic!("complete refused")
        };
        assert_eq!(receipt.outcome(), RecordOutcome::Recorded);
        let Some(only) = state.intervals().next() else {
            panic!("the unproven suffix must be recorded")
        };
        assert_eq!((only.start(), only.end()), (150, 200));
        assert_eq!(only.status().get(), completion_status::IO_DEVICE_ERROR);
    }

    #[test]
    fn a_completion_that_proved_nothing_records_its_whole_range() {
        let (mut state, write, snapshot) = admitted(100, 200);
        let Ok(_receipt) = state.complete(write, snapshot, nodes(2), Reservation::Granted, None)
        else {
            panic!("complete refused")
        };
        assert_eq!(
            state
                .intervals()
                .map(|iv| (iv.start(), iv.end(), iv.lowest_issue().get()))
                .collect::<Vec<_>>(),
            vec![(100, 200, 1)]
        );
    }

    #[test]
    fn a_full_success_records_nothing_and_still_retires_the_issue() {
        let (mut state, write, snapshot) = admitted(100, 200);
        assert_eq!(state.terminal_prefix(), 0, "issue 1 is in flight");

        let Ok(_receipt) = state.complete(
            write,
            snapshot,
            nodes(2),
            Reservation::Granted,
            Some(cov(100, 200)),
        ) else {
            panic!("complete refused")
        };
        assert_eq!(state.intervals().count(), 0, "nothing was left unproven");
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.terminal_prefix(), 1);
    }

    #[test]
    fn a_completion_credits_its_proven_coverage_against_existing_evidence() {
        // 07:314-315: "each completed child paging WRITE records its exact
        // provider-committed byte coverage". Recording proven bytes IS
        // subtracting them -- an exit that only recorded the unproven suffix
        // would leave an earlier issue's evidence standing over bytes a later
        // one has since proven, and AdvanceOnly would block on them forever.
        let (mut state, earlier, snapshot) = admitted(100, 200);
        let Ok(_failed) = state.terminalize(
            earlier,
            snapshot,
            nodes(2),
            Reservation::Granted,
            failure(completion_status::IO_TIMEOUT),
        ) else {
            panic!("terminalize refused")
        };
        assert_eq!(
            state
                .intervals()
                .map(|iv| (iv.start(), iv.end(), iv.lowest_issue().get()))
                .collect::<Vec<_>>(),
            vec![(100, 200, 1)]
        );

        let claim = state.bind_claim(ContextClaimResult::Acquired);
        let retry = match state.admit(write(100, 150), snapshot, claim) {
            AdmissionOutcome::InFlight(write) => write,
            _ => panic!("the retry must be admitted"),
        };
        let Ok(_receipt) = state.complete(
            retry,
            snapshot,
            nodes(2),
            Reservation::Granted,
            Some(cov(100, 150)),
        ) else {
            panic!("complete refused")
        };
        assert_eq!(
            state
                .intervals()
                .map(|iv| (iv.start(), iv.end(), iv.lowest_issue().get()))
                .collect::<Vec<_>>(),
            vec![(150, 200, 1)],
            "the proven bytes were credited against the standing evidence"
        );
    }

    #[test]
    fn coverage_outside_the_request_is_refused() {
        // A provider claiming more than it was asked, or claiming a
        // non-prefix, is refused rather than interpreted.
        let (mut state, first_write, snapshot) = admitted(100, 200);
        let Err(first_rejection) = state.complete(
            first_write,
            snapshot,
            nodes(2),
            Reservation::Granted,
            Some(cov(100, 300)),
        ) else {
            panic!("a provider may not claim more than it was asked")
        };
        assert_eq!(
            first_rejection.reason(),
            WriteRejectionReason::CoverageOutsideRequest
        );
        let _first_write = first_rejection.into_write();

        let claim = state.bind_claim(ContextClaimResult::Acquired);
        let retry = match state.admit(write(100, 200), snapshot, claim) {
            AdmissionOutcome::InFlight(write) => write,
            _ => panic!("a fresh retry must be admitted"),
        };
        let Err(rejection) = state.complete(
            retry,
            snapshot,
            nodes(2),
            Reservation::Granted,
            Some(cov(120, 180)),
        ) else {
            panic!("section 6 knows one shape of partial success: the short SUCCESS")
        };
        assert_eq!(
            rejection.reason(),
            WriteRejectionReason::CoverageOutsideRequest
        );
        assert_eq!(state.intervals().count(), 0, "a refusal records nothing");
    }

    #[test]
    fn a_completion_advances_the_prefix_only_once_the_record_exists() {
        // A terminal receipt is returned only after it has recorded and retired
        // exactly its preflighted active issue.
        let mut state = seq(300, 0, 1);
        let snapshot = state.bind_size(validated(300, 0, 2));
        let first_claim = state.bind_claim(ContextClaimResult::Acquired);
        let one = match state.admit(write(0, 100), snapshot, first_claim) {
            AdmissionOutcome::InFlight(write) => write,
            _ => panic!("issue 1"),
        };
        let second_claim = state.bind_claim(ContextClaimResult::Acquired);
        let two = state.admit(write(200, 300), snapshot, second_claim);
        let AdmissionOutcome::InFlight(_) = two else {
            panic!("issue 2")
        };
        assert_eq!(state.terminal_prefix(), 0);

        let Ok(receipt) = state.complete(one, snapshot, nodes(2), Reservation::Granted, None)
        else {
            panic!("complete refused")
        };
        assert_eq!(
            state
                .intervals()
                .map(|iv| (iv.start(), iv.end(), iv.lowest_issue().get()))
                .collect::<Vec<_>>(),
            vec![(0, 100, 1)],
            "the recording happened inside the exit"
        );
        assert_eq!(
            state.terminal_prefix(),
            1,
            "the remaining active issue keeps the prefix at one"
        );
        assert_eq!(receipt.prefix(), 1);
    }

    // ---------------------------------------------- the numbered claim failure

    // ------------------------------------------ sequencer-owned VDL baseline

    #[test]
    fn vdl_baseline_initially_matches_the_validated_size_state() {
        let state = seq(100, 40, 1);
        assert_eq!(state.verified_vdl_baseline(), 40);
    }

    #[test]
    fn vdl_baseline_same_owner_snapshot_trims_evidence_and_advances() {
        let mut state = seq(100, 10, 1);
        let _ = state
            .ledger
            .record_failure(iv(20, 80, 1), 10, nodes(2), Reservation::Granted);
        state.ledger.unknown = Some(iv(20, 35, 2));
        let snapshot = state.bind_size(validated(100, 40, 2));

        assert_eq!(state.apply_verified_vdl(snapshot), Ok(()));
        assert_eq!(state.verified_vdl_baseline(), 40);
        assert_eq!(spans(&state.ledger), vec![(40, 80, 1)]);
        assert_eq!(
            state.unknown(),
            None,
            "covered UNKNOWN evidence must trim away"
        );
    }

    #[test]
    fn vdl_baseline_rejects_a_lower_ordinary_snapshot_without_mutation() {
        let mut state = seq(100, 40, 1);
        let _ = state
            .ledger
            .record_failure(iv(40, 80, 1), 40, nodes(2), Reservation::Granted);
        let before = snapshot_state(&state);
        let lower = state.bind_size(validated(100, 30, 2));

        assert_eq!(
            state.apply_verified_vdl(lower),
            Err(VdlRejection::Regressed)
        );
        assert_eq!(snapshot_state(&state), before);
    }

    #[test]
    fn vdl_baseline_rejects_a_foreign_snapshot_before_inspecting_regression() {
        let mut owner = seq(100, 40, 1);
        let foreign = seq(100, 0, 1);
        let before_owner = snapshot_state(&owner);
        let before_foreign = snapshot_state(&foreign);
        let stale_foreign = foreign.bind_size(validated(100, 0, 2));

        assert_eq!(
            owner.apply_verified_vdl(stale_foreign),
            Err(VdlRejection::WrongSequencer)
        );
        assert_eq!(snapshot_state(&owner), before_owner);
        assert_eq!(snapshot_state(&foreign), before_foreign);
    }

    #[test]
    fn vdl_baseline_only_a_clamped_truncation_can_reset_lower() {
        let mut state = seq(100, 80, 1);
        let proof =
            clamped_truncation(SizeTrio::new(100, 100, 80), SizeTrio::new(60, 50, 30), 1, 2);
        let snapshot = state.bind_truncation(proof);

        assert_eq!(state.truncate_reset(snapshot), Ok(()));
        assert_eq!(state.verified_vdl_baseline(), 30);
    }

    #[test]
    fn vdl_baseline_rejects_a_foreign_truncate_without_mutation() {
        let owner = seq(100, 80, 1);
        let mut foreign = seq(100, 80, 1);
        let proof =
            clamped_truncation(SizeTrio::new(100, 100, 80), SizeTrio::new(60, 50, 30), 1, 2);
        let snapshot = owner.bind_truncation(proof);
        let before_owner = snapshot_state(&owner);
        let before_foreign = snapshot_state(&foreign);

        assert_eq!(
            foreign.truncate_reset(snapshot),
            Err(VdlRejection::WrongSequencer)
        );
        assert_eq!(snapshot_state(&owner), before_owner);
        assert_eq!(snapshot_state(&foreign), before_foreign);
    }

    // ------------------------------------------------------------ the barrier

    #[test]
    fn barrier_same_owner_uses_the_minimum_of_eof_and_snapshot_file_size() {
        let mut state = seq(80, 0, 1);
        let _ = state
            .ledger
            .record_failure(iv(85, 90, 1), 0, nodes(2), Reservation::Granted);
        let snapshot = state.bind_size(validated(80, 0, 2));

        assert_eq!(
            state.advance_only_barrier(snapshot, 100),
            Ok(Barrier::Clear)
        );
    }

    #[test]
    fn barrier_selects_the_lowest_issue_across_ordinary_and_unknown_evidence() {
        let mut state = seq(100, 0, 1);
        let _ = state
            .ledger
            .record_failure(iv(10, 20, 9), 0, nodes(2), Reservation::Granted);
        state.ledger.unknown = Some(iv(30, 40, 4));
        let snapshot = state.bind_size(validated(100, 0, 2));

        let Ok(Barrier::Blocked(candidate)) = state.advance_only_barrier(snapshot, 100) else {
            panic!("the lower-issue UNKNOWN span must block")
        };
        assert_eq!(candidate.kind(), CandidateKind::Unknown);
        assert_eq!(candidate.issue().get(), 4);
    }

    #[test]
    fn barrier_target_at_or_below_the_snapshot_vdl_is_clear() {
        let mut state = seq(100, 50, 1);
        let _ = state
            .ledger
            .record_failure(iv(50, 80, 1), 50, nodes(2), Reservation::Granted);
        let snapshot = state.bind_size(validated(100, 50, 2));

        assert_eq!(state.advance_only_barrier(snapshot, 30), Ok(Barrier::Clear));
    }

    #[test]
    fn barrier_exhausted_admission_returns_issues_exhausted_never_clear() {
        let mut state = seq(100, 0, 1);
        let snapshot = state.bind_size(validated(100, 0, 2));
        state.counter.last_issued = u64::MAX;
        let outcome = state.admit(
            write(0, 10),
            snapshot,
            state.bind_claim(ContextClaimResult::Acquired),
        );
        assert!(matches!(outcome, AdmissionOutcome::MountFatal { .. }));

        assert_eq!(
            state.advance_only_barrier(snapshot, 100),
            Ok(Barrier::IssuesExhausted)
        );
    }

    #[test]
    fn barrier_rejects_a_foreign_snapshot_against_an_open_sequencer() {
        let owner = seq(100, 0, 1);
        let foreign = seq(100, 0, 1);
        let snapshot = foreign.bind_size(validated(100, 0, 2));
        let before_owner = snapshot_state(&owner);
        let before_foreign = snapshot_state(&foreign);

        assert_eq!(
            owner.advance_only_barrier(snapshot, 100),
            Err(BarrierRejection::WrongSequencer)
        );
        assert_eq!(snapshot_state(&owner), before_owner);
        assert_eq!(snapshot_state(&foreign), before_foreign);
    }

    #[test]
    fn barrier_rejects_a_foreign_snapshot_before_observing_exhaustion() {
        let mut exhausted = seq(100, 0, 1);
        let foreign = seq(100, 0, 1);
        let owned = exhausted.bind_size(validated(100, 0, 2));
        exhausted.counter.last_issued = u64::MAX;
        let outcome = exhausted.admit(
            write(0, 10),
            owned,
            exhausted.bind_claim(ContextClaimResult::Acquired),
        );
        assert!(matches!(outcome, AdmissionOutcome::MountFatal { .. }));
        let snapshot = foreign.bind_size(validated(100, 0, 2));
        let before_exhausted = snapshot_state(&exhausted);
        let before_foreign = snapshot_state(&foreign);

        assert_eq!(
            exhausted.advance_only_barrier(snapshot, 100),
            Err(BarrierRejection::WrongSequencer)
        );
        assert_eq!(snapshot_state(&exhausted), before_exhausted);
        assert_eq!(snapshot_state(&foreign), before_foreign);
    }

    #[test]
    fn barrier_queries_leave_both_sequencers_unchanged() {
        let mut first = seq(100, 0, 1);
        let second = seq(100, 0, 1);
        let _ = first
            .ledger
            .record_failure(iv(20, 30, 1), 0, nodes(2), Reservation::Granted);
        let own = first.bind_size(validated(100, 0, 2));
        let foreign = second.bind_size(validated(100, 0, 2));
        let before_first = snapshot_state(&first);
        let before_second = snapshot_state(&second);

        assert!(matches!(
            first.advance_only_barrier(own, 100),
            Ok(Barrier::Blocked(_))
        ));
        assert_eq!(snapshot_state(&first), before_first);
        assert_eq!(snapshot_state(&second), before_second);
        assert_eq!(
            first.advance_only_barrier(foreign, 100),
            Err(BarrierRejection::WrongSequencer)
        );
        assert_eq!(snapshot_state(&first), before_first);
        assert_eq!(snapshot_state(&second), before_second);
    }

    #[test]
    fn target_vdl_is_the_minimum_of_end_of_file_and_file_size() {
        // The maximum would advance the VDL past the end of the file.
        assert_eq!(target_vdl(100, 200), 100);
        assert_eq!(target_vdl(300, 200), 200);
        assert_eq!(target_vdl(150, 150), 150);
    }

    #[test]
    fn the_barrier_clears_when_nothing_intersects_the_range() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(500, 600, 1), 0, nodes(2), Reservation::Granted);
        assert_eq!(l.advance_only_barrier(0, 100), Barrier::Clear);
    }

    #[test]
    fn a_target_at_or_below_the_vdl_is_clear_even_with_evidence_above_it() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(100, 200, 1), 0, nodes(2), Reservation::Granted);
        assert_eq!(
            l.advance_only_barrier(100, 100),
            Barrier::Clear,
            "there is nothing to advance over"
        );
        assert_eq!(l.advance_only_barrier(150, 120), Barrier::Clear);
        // And the same ledger DOES block a real advance, so the two clears
        // above are not the ledger simply being empty.
        assert!(matches!(
            l.advance_only_barrier(100, 300),
            Barrier::Blocked(_)
        ));
    }

    #[test]
    fn the_barrier_blocks_on_the_unknown_span_too() {
        // 06:336-338 makes the accumulator a candidate exactly as an ordinary
        // interval is. Ignoring it would advance the VDL over a span whose
        // contents are, by construction, unknown.
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(100, 110, 3), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(200, 210, 5), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(300, 310, 7), 0, nodes(0), Reservation::Granted);
        assert_eq!(l.len(), 0, "everything degraded into the span");
        assert!(l.unknown().is_some());

        let Barrier::Blocked(candidate) = l.advance_only_barrier(0, 1000) else {
            panic!("the UNKNOWN span must block")
        };
        assert_eq!(candidate.kind(), CandidateKind::Unknown);
        assert_eq!(candidate.issue().get(), 3);
    }

    #[test]
    fn the_candidate_is_the_lowest_issue_one() {
        let mut l = Ledger::new();
        for (start, end, issue) in [(100u64, 110u64, 9u64), (200, 210, 4), (300, 310, 7)] {
            let _ = l.record_failure(iv(start, end, issue), 0, nodes(2), Reservation::Granted);
        }
        let Barrier::Blocked(candidate) = l.advance_only_barrier(0, 1000) else {
            panic!("three intervals intersect")
        };
        assert_eq!(candidate.kind(), CandidateKind::Ordinary);
        assert_eq!(
            candidate.issue().get(),
            4,
            "section 7 makes the LOWEST-issue interval the local failure candidate"
        );
        assert_eq!(
            (candidate.interval().start(), candidate.interval().end()),
            (200, 210)
        );
    }

    #[test]
    fn the_barrier_ignores_evidence_wholly_below_the_vdl() {
        let mut l = Ledger::new();
        let _ = l.record_failure(iv(10, 20, 1), 0, nodes(2), Reservation::Granted);
        let _ = l.record_failure(iv(400, 410, 2), 0, nodes(2), Reservation::Granted);
        let Barrier::Blocked(candidate) = l.advance_only_barrier(100, 500) else {
            panic!("the interval at 400 intersects")
        };
        assert_eq!(
            candidate.issue().get(),
            2,
            "issue 1's range is below the VDL and 07:317-319 says it never blocks"
        );
    }

    // ------------------------------------------------ the shared preclaim

    #[test]
    fn a_completions_two_updates_share_one_preclaim() {
        // A completion enters the size gate/sequencer pair ONCE, so section 6's
        // preclaim bounds the pair of updates, not each of them.
        let spent_one = nodes(2).after_spending(INLINE_INTERVALS, INLINE_INTERVALS + 1);
        assert_eq!(spent_one.preclaimed(), 1, "one overflow node was taken");
        let spent_none = nodes(2).after_spending(0, INLINE_INTERVALS);
        assert_eq!(
            spent_none.preclaimed(),
            2,
            "filling the inline slots takes no node"
        );
        let freed = nodes(1).after_spending(INLINE_INTERVALS + 3, INLINE_INTERVALS);
        assert_eq!(freed.preclaimed(), 1, "a shrink never over-refunds");

        // Honest limit, stated rather than implied: no completion currently
        // reaches the second spend. A subtraction grows the count only by
        // splitting an interval around the proven range, and the unproven
        // suffix begins exactly where that range ends -- so it abuts the upper
        // split piece and fuses with it. If the split did not happen there is
        // no upper piece and nothing was spent. The guard is insurance against
        // the algebra changing, and it is tested directly because no scenario
        // can reach it.
        assert_eq!(nodes(0).after_spending(0, 60).preclaimed(), 0);
    }
}
