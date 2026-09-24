//! The checked size domain: `SizeState` transitions and the truncate order.
//!
//! `04-object-model.md` §8.1 fixes the domain, `07-cache-mm.md` §3 the trio and
//! the epoch, and `07 §5` with `06-locking.md` §3.3 the order a reduction must
//! follow. This module holds the decisions; it calls no kernel API, so
//! `CcSetFileSizes`, `CcPurgeCacheSection`, `MmCanFileBeTruncated` and
//! `CcCopyWrite` are *decided about* here and never invoked.
//!
//! **The transcriptions below are checked against the documents at test time.**
//! `07 §5`'s five numbered steps, `07 §3`'s three `CcSetFileSizes` obligations,
//! `06 §3.3`'s three reduction-only obligations and `07 §3`'s extending-write
//! sentence are parsed out of the normative files and compared positionally and
//! exactly. Slice B2 shipped a table that asserted its own row count as a fact
//! about a document that said otherwise; a stored copy checked against a
//! hand-written number is not a check.

/// `07-cache-mm.md` §5's reduction sequence, in the document's order.
///
/// Filled from parsed output, not typed by hand.
pub const TRUNCATION_STEPS: [&str; 5] = [
    "MM veto.",
    "Publish the smaller size to Cc.",
    "Purge the truncated tail.",
    "Commit.",
    "Post-commit VDL clamp.",
];

/// `07-cache-mm.md` §3's `CcSetFileSizes` obligations, verbatim.
pub const CC_OBLIGATIONS: [&str; 3] = [
    "when EOF increases (extend) -- **before** the corresponding `CcCopyWrite` runs, so Cc does not reject a write past the old EOF;",
    "when EOF decreases (truncate) -- as part of the Cache-Manager/MM truncate sequence in section 5, before the truncated tail is purged;",
    "when AllocationSize increases without an EOF change.",
];

/// `06-locking.md` §3.3's reduction-only obligations, verbatim.
pub const TRUNCATING_WORK: [&str; 3] = [
    "it blocks new section creation for the stream;",
    "it performs byte-range-lock arbitration and the MM truncation vetoes, `MmCanFileBeTruncated` and the mapped/image-section vetoes;",
    "it completes every fallible flush/purge step before SQ publication.",
];

/// `07-cache-mm.md` §3's extending-write sentence, verbatim.
pub const EXTENDING_WRITE: &str = "**Extending write.** Reserve/commit the new EOF with the daemon first, update the FCB header and call `CcSetFileSizes`, then run `CcCopyWrite` into the newly visible range.";

use crate::effect::{Effect, EffectContext, WaitTarget, may_emit};
use crate::lockrank::LockOrderError;
use crate::typestate::Passive;
use fsring_abi::limits::MAX_FILE_SIZE;
use fsring_abi::msgs::common::SizeState;
use fsring_abi::validate::validate_size_state_v21;

/// The three ordered sizes of `07-cache-mm.md` §3's trio.
///
/// `AllocationSize >= FileSize (EOF) >= ValidDataLength (VDL)`. The epoch is
/// deliberately NOT a field: it orders transitions, and the trio is a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeTrio {
    pub allocation_size: u64,
    pub file_size: u64,
    pub valid_data_length: u64,
}

/// A trio that `fsring-abi` rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeError;

/// A `SizeState` that `fsring-abi` accepted.
///
/// `06-locking.md` §3.3: *"Terminal reentry installs the **already-validated**
/// SizeState and performs only nonfailing cache-size update and gate-release
/// work."* "Already-validated" is a property of the value, so it is carried by
/// the type: the only way to obtain one is [`validate`], and the two sequences'
/// commit steps accept nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct ValidatedSizeState {
    trio: SizeTrio,
    size_epoch: u64,
}

impl ValidatedSizeState {
    pub const fn trio(&self) -> SizeTrio {
        self.trio
    }
    pub const fn size_epoch(&self) -> u64 {
        self.size_epoch
    }
}

impl SizeTrio {
    pub const fn new(allocation_size: u64, file_size: u64, valid_data_length: u64) -> Self {
        Self {
            allocation_size,
            file_size,
            valid_data_length,
        }
    }
}

/// Validate a trio and its epoch.
///
/// **Delegates** to `fsring_abi::validate::validate_size_state_v21`, which owns
/// the bounds against `MAX_FILE_SIZE`, the `A >= F >= V` ordering, and the
/// `size_epoch != 0` rule. This crate does not restate any of them; the source
/// scan of signal 21 is what keeps that true.
///
/// The epoch is a **parameter** rather than synthesized: a fabricated nonzero
/// epoch would make the `size_epoch != 0` leg unreachable through the
/// delegation, and the delegation claim untestable.
pub fn validate(trio: SizeTrio, size_epoch: u64) -> Result<ValidatedSizeState, SizeError> {
    let state = SizeState {
        allocation_size: trio.allocation_size,
        file_size: trio.file_size,
        valid_data_length: trio.valid_data_length,
        size_epoch,
    };
    match validate_size_state_v21(state) {
        Ok(()) => Ok(ValidatedSizeState { trio, size_epoch }),
        Err(_) => Err(SizeError),
    }
}

/// Why a size-changing response's epoch was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochError {
    /// The response repeated the expected epoch. §3 calls this stale too; it is
    /// named apart so a caller can log *which* failure it saw.
    NoAdvance,
    /// The response went backwards.
    Stale,
}

/// `07-cache-mm.md` §3's **size-changing-response** lane, and no other.
///
/// *"A successful size-changing response MUST return a `size_epoch` strictly
/// greater than the expected input epoch -- gaps are legal, so an epoch that
/// advances by more than one is not itself an error. A stale (equal or lower)
/// epoch is a protocol/state error and triggers reconciliation, never silent
/// acceptance."*
///
/// **`size_epoch` has at least three documented comparison regimes.** Using the
/// wrong one is the B1 defect of collapsing two distinct things into one
/// position, so the lane is in the name:
///
/// | Lane | Rule | Source |
/// |---|---|---|
/// | size-changing **response** (this one) | only strictly greater accepted; gaps legal | `07 §3` |
/// | `volume_commit_sequence` **merge** | lower = stale, equal = full state must match, **higher = protocol fault** | `04 §8.3` |
/// | **non-size** mutation snapshot | equal allowed, lower faults | frozen at `messages.rs:1656-1658` |
///
/// The merge lane gives the **opposite** verdict on both `equal` and `higher`.
/// And the **resync** refresh path of §3 is a fourth context this does not
/// govern: a resync may legitimately install an unchanged epoch.
///
/// This restates the frozen `result.sizes.size_epoch <=
/// request.expected_size_epoch` of `validate_mutation_success_v2`
/// (`messages.rs:1622`) at finer grain, because the size gate must decide before
/// it has a whole validated result message. Being a restatement of a frozen
/// rule, it carries an equivalence guard in the tests.
pub const fn accept_size_response_epoch(expected: u64, returned: u64) -> Result<(), EpochError> {
    if returned == expected {
        return Err(EpochError::NoAdvance);
    }
    if returned < expected {
        return Err(EpochError::Stale);
    }
    Ok(())
}

/// A size epoch captured under the gate, still good for a decision.
///
/// `06-locking.md` §3.3: *"A wait or resource drop invalidates the captured size
/// epoch and repeats the size decision if state changed."*
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct EpochCapture(u64);

/// A capture that a wait or resource drop invalidated. There is no path back:
/// the size decision must be repeated against freshly read state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct InvalidatedCapture;

impl EpochCapture {
    pub const fn new(size_epoch: u64) -> Self {
        Self(size_epoch)
    }
    /// The epoch, usable only while the capture is still valid.
    ///
    /// Takes `&self` so a commit can read it without destroying the capture,
    /// while `wait_occurred` still consumes it.
    pub const fn epoch(&self) -> u64 {
        self.0
    }
    /// A wait happened, or a resource was dropped. **Consumes** the capture.
    ///
    /// This type is deliberately neither `Copy` nor `Clone`. An earlier
    /// revision derived both, so `wait_occurred(self)` copied and the original
    /// stayed usable — an adversarial review compiled and RAN a probe that read
    /// the epoch after the wait and fed it to a decision. Three places in this
    /// module claimed "there is no path back" while there was one.
    pub fn wait_occurred(self) -> InvalidatedCapture {
        InvalidatedCapture
    }
}

/// The VDL a cached write **targets** once its bytes are durable.
///
/// §3: *"the kernel advances `valid_data_length = max(VDL, offset + length)`
/// once the written bytes are durable"*.
///
/// This computes a **target, not a licence**. Durability is `07 §6`'s ledger,
/// and advancing VDL before it is what §3's zero-fill guarantee exists to
/// prevent — a reader would observe provider bytes the daemon never accounted
/// for.
pub const fn vdl_after_cached_write(vdl: u64, offset: u64, length: u64) -> Result<u64, SizeError> {
    let Some(end) = offset.checked_add(length) else {
        return Err(SizeError);
    };
    if end > MAX_FILE_SIZE {
        return Err(SizeError);
    }
    Ok(if end > vdl { end } else { vdl })
}

/// The post-commit VDL clamp. `07 §5` step 5: *"After the completion queue entry
/// confirms the commit, the kernel sets `valid_data_length = min(VDL, EOF)`."*
pub const fn vdl_after_commit(vdl: u64, eof: u64) -> u64 {
    if vdl < eof { vdl } else { eof }
}

/// Whether a read of `[offset, offset+length)` touches bytes at or above VDL,
/// which the paging-READ handler must return as zeros.
///
/// §3: *"every byte at or above VDL that a reader observes is either data this
/// driver wrote or an explicit zero, never provider storage the daemon has not
/// accounted for."*
///
/// This is the **single-writer half** of that guarantee. §6 states that the
/// paging-write issue ledger is what makes it hold *"under concurrency rather
/// than only in the single-writer case"*, and no ledger exists here.
pub const fn must_zero_fill(trio: SizeTrio, offset: u64, length: u64) -> bool {
    if length == 0 {
        return false;
    }
    let Some(end) = offset.checked_add(length) else {
        return true;
    };
    end > trio.valid_data_length
}

// ============================================================================
// The size-change classifier
// ============================================================================

/// What a requested size change is, for the purpose of deciding what work runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeChange {
    NoChange,
    /// `allocation_size` or `file_size` went down. `07 §5`: *"Shrinking
    /// `FileSize` or `AllocationSize` enters `06-locking.md`'s `TRUNCATING`
    /// substate"* — the disjunction is the document's, not a conservative
    /// reading chosen here.
    Reduce,
    /// `file_size` went up and nothing went down.
    Extend,
    /// `allocation_size` went up, EOF unchanged, nothing down.
    AllocationIncrease,
    /// Only `valid_data_length` went up.
    VdlAdvance,
}

/// A requested transition the size lane does not accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeTransitionError {
    /// A `valid_data_length` **increase** rode a change to another field.
    ///
    /// `05-irp-dispatch.md` §9.4: *"For SET_VALID_DATA_LENGTH, success
    /// additionally requires `allocation_size == retained allocation_size`,
    /// `file_size == retained file_size` … any different successful state is a
    /// protocol fault before cache/FCB installation or native completion."* So a
    /// VDL advance is legitimate only when both other fields stand still.
    VdlRiderOnSizeChange,
    /// A reduction carried a `valid_data_length` above what the documents allow
    /// it to end at.
    ///
    /// §9.4: a combined allocation shrink *"sets the resulting EOF to the
    /// requested value and resulting VDL to `min(old VDL, new EOF)`"*, and on an
    /// EOF shrink the provider *"returns allocation at least the new EOF and VDL
    /// no greater than it"*. VDL never rises here, so the ceiling is
    /// `min(current VDL, new EOF)`.
    VdlAboveReductionCeiling,
    /// `valid_data_length` decreased without `allocation_size` or `file_size`
    /// decreasing.
    ///
    /// `05-irp-dispatch.md` §9.5 requires *"`0 <= current VDL < new VDL <=
    /// current EOF`; zero and equality are not no-ops. Violation completes
    /// locally with INVALID_PARAMETER, zero information, and no ReqId, grant,
    /// or SQE"*, and `07 §7`'s AdvanceOnly *"never reduces VDL"*.
    ///
    /// A VDL decrease reaches state only through `07 §5` step 5's post-commit
    /// clamp, which [`vdl_after_commit`] computes rather than accepts.
    VdlRegression,
}

/// Classify a **requested** size change.
///
/// The precedence, total over all 27 (down/same/up)³ transitions:
///
/// 1. `allocation_size` **or** `file_size` decreased → [`SizeChange::Reduce`];
/// 2. else `file_size` increased → [`SizeChange::Extend`];
/// 3. else `allocation_size` increased → [`SizeChange::AllocationIncrease`];
/// 4. else `valid_data_length` increased → [`SizeChange::VdlAdvance`];
/// 5. else [`SizeChange::NoChange`].
///
/// A `valid_data_length` decrease that step 1 does not absorb is
/// [`SizeTransitionError::VdlRegression`] rather than a classification. An
/// earlier revision made this function total and returned a plain
/// `SizeChange`; the four cells where VDL alone decreased then got answers, and
/// `(same, same, down)` fell through to `NoChange` — a regression reported as
/// no change at all.
///
/// **Requested, not installed.** `07 §3`'s other refresh path — *"or a
/// resync"* — may legitimately deliver a lower VDL against a stale mirror, and
/// this function does not govern it.
pub const fn classify_request(
    current: SizeTrio,
    requested: SizeTrio,
) -> Result<SizeChange, SizeTransitionError> {
    let alloc_down = requested.allocation_size < current.allocation_size;
    let file_down = requested.file_size < current.file_size;
    let vdl_down = requested.valid_data_length < current.valid_data_length;

    let alloc_moved = requested.allocation_size != current.allocation_size;
    let file_moved = requested.file_size != current.file_size;
    let vdl_up = requested.valid_data_length > current.valid_data_length;

    // §9.4: a VDL advance requires BOTH other fields unchanged, so an advance
    // riding any other movement has no producer and is a protocol fault.
    if vdl_up && (alloc_moved || file_moved) {
        return Err(SizeTransitionError::VdlRiderOnSizeChange);
    }

    if alloc_down || file_down {
        // A reduction's VDL is computed, not requested: it may only end at or
        // below min(current VDL, new EOF).
        let ceiling = if current.valid_data_length < requested.file_size {
            current.valid_data_length
        } else {
            requested.file_size
        };
        if requested.valid_data_length > ceiling {
            return Err(SizeTransitionError::VdlAboveReductionCeiling);
        }
        return Ok(SizeChange::Reduce);
    }
    if vdl_down {
        return Err(SizeTransitionError::VdlRegression);
    }
    if requested.file_size > current.file_size {
        return Ok(SizeChange::Extend);
    }
    if requested.allocation_size > current.allocation_size {
        return Ok(SizeChange::AllocationIncrease);
    }
    if requested.valid_data_length > current.valid_data_length {
        return Ok(SizeChange::VdlAdvance);
    }
    Ok(SizeChange::NoChange)
}

/// Whether the change enters `06-locking.md` §3.3's `TRUNCATING` substate.
///
/// §3.3: *"Only a reduction enters TRUNCATING"*, and *"Extensions and VDL
/// advances use the common gate and size epoch but skip all reduction-only MM
/// and flush/purge work."*
pub const fn enters_truncating(change: SizeChange) -> bool {
    matches!(change, SizeChange::Reduce)
}

/// Whether §3.3's reduction-only MM and flush/purge work runs. Identical to
/// [`enters_truncating`] by construction: the substate *is* where that work
/// lives, and two functions that could disagree would be two rules.
pub const fn reduction_only_work(change: SizeChange) -> bool {
    enters_truncating(change)
}

/// `06-locking.md` §3.3: *"Only the documented reduction prerequisites below may
/// be discovered under the gate; **no request-table/grant/allocator admission
/// is allowed there**."*
pub const fn admission_allowed_under_size_gate() -> bool {
    false
}

// ============================================================================
// The `CcSetFileSizes` obligation
// ============================================================================

/// Where the I/O came from, for `07 §3`'s paging prohibition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOrigin {
    Cached,
    NonCached,
    /// §3: *"The paging-I/O path MUST NOT call it: paging dispatch updates the
    /// FCB header fields directly under the size gate … rather than re-entering
    /// Cc from a context where PASSIVE_LEVEL is not guaranteed."*
    Paging,
}

/// Why a `CcSetFileSizes` publication was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcError {
    /// `07 §3`'s paging prohibition.
    PagingPathForbidden,
    /// The change is not one of the four cases that obliges the call.
    NotRequired,
    /// `06 §6` forbids a wait under the locks currently held, and
    /// `CcSetFileSizes` at PASSIVE_LEVEL may block.
    LockOrder(LockOrderError),
}

/// Evidence that a `CcSetFileSizes` call is obliged and permitted here.
///
/// Neither `Copy` nor `Clone`: the three preconditions were checked for **this**
/// call, under **this** held-set. A copyable receipt could be minted once with
/// no locks held and replayed under any later one.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CcPublication {
    change: SizeChange,
}

impl CcPublication {
    pub const fn change(&self) -> SizeChange {
        self.change
    }
}

/// Whether `CcSetFileSizes` must be called for this change.
///
/// **Four arms, and the fourth is in a different section from the other three.**
/// `07 §3` enumerates three cases and has **no case for an AllocationSize
/// decrease**, while `07 §5` routes an allocation shrink through the sequence
/// whose step 2 *is* the `CcSetFileSizes` call. That is not a conflict to
/// escalate: §5 step 2 is an obligation stated elsewhere, and `CcSetFileSizes`
/// publishes the whole trio (`07 §4` confirms Cc's view is
/// `{AllocationSize, FileSize, VDL}`), so an allocation shrink genuinely changes
/// what Cc holds.
///
/// | Case | Source |
/// |---|---|
/// | EOF increases | `07 §3` bullet 1 — before the corresponding `CcCopyWrite` |
/// | EOF decreases | `07 §3` bullet 2 — before the truncated tail is purged |
/// | AllocationSize increases, EOF unchanged | `07 §3` bullet 3 |
/// | any reduction, including an allocation-only shrink | `07 §5` step 2 |
///
/// `VdlAdvance` is **false**, which is §3's closed trigger list rather than a
/// dropped obligation: VDL reaches Cc through the FCB header Cc already holds a
/// pointer to (§3's own mechanism for the paging path).
pub const fn cc_set_file_sizes_required(change: SizeChange) -> bool {
    match change {
        SizeChange::Extend | SizeChange::Reduce | SizeChange::AllocationIncrease => true,
        SizeChange::VdlAdvance | SizeChange::NoChange => false,
    }
}

/// Decide whether this context may publish sizes to Cc.
///
/// Three preconditions, each from a sentence:
///
/// - the `Passive` token, because §3 says `CcSetFileSizes` *"MUST be called at
///   PASSIVE_LEVEL"* and A2's token cannot be minted at dispatch level;
/// - the origin, because §3 says *"The paging-I/O path MUST NOT call it"*;
/// - the effect context, because the call may block: `06 §6` forbids a wait
///   under the notification-state push lock or a CSQ spin lock, and `07 §4`
///   forbids one under the FSRTL cache sentinel **regardless of what is held**.
///   B1's table is consulted rather than cited — a table nothing consults is
///   what B1's own gate warned about.
///
/// The wait target is [`WaitTarget::BlockingResource`]: `CcSetFileSizes` can
/// block, and it is an ordinary blocking resource rather than one of §2
/// corollary 2's admission resources. Naming the target is what lets the two
/// corollaries land differently on this call than on a provider round trip.
pub fn publish_sizes_to_cc(
    _irql: &Passive,
    ctx: &EffectContext,
    origin: IoOrigin,
    change: SizeChange,
) -> Result<CcPublication, CcError> {
    if matches!(origin, IoOrigin::Paging) {
        return Err(CcError::PagingPathForbidden);
    }
    if !cc_set_file_sizes_required(change) {
        return Err(CcError::NotRequired);
    }
    match may_emit(ctx, Effect::Wait(WaitTarget::BlockingResource)) {
        Ok(()) => Ok(CcPublication { change }),
        Err(e) => Err(CcError::LockOrder(e)),
    }
}

// ============================================================================
// `07 §5`'s reduction sequence, as an order that cannot be expressed wrongly
// ============================================================================

/// One position in `07-cache-mm.md` §5's numbered reduction sequence.
///
/// `LABEL` is the document's own bold label, and
/// `the_truncation_typestate_walks_the_documents_steps` walks the transitions
/// and compares the labels it collects against the parsed document. Storing a
/// transcription and checking only *that* is what slice B2 had to correct
/// twice: the document-check must check the code.
pub trait TruncationStep {
    /// 1-based position in §5's list.
    const STEP: usize;
    /// §5's verbatim bold label for that step.
    const LABEL: &'static str;
}

/// Step 1 has passed: `MmCanFileBeTruncated` did not veto.
#[derive(Debug)]
pub struct VetoCleared(());
/// Step 2: the smaller sizes are published to Cc.
#[derive(Debug)]
pub struct SizePublished(());
/// Step 3: the truncated tail is purged.
#[derive(Debug)]
pub struct TailPurged(());
/// Step 4: the daemon transaction committed. **Nothing after this may fail.**
#[derive(Debug)]
pub struct Committed(());
/// Step 5: `valid_data_length = min(VDL, EOF)`.
#[derive(Debug)]
pub struct VdlClamped(());

impl TruncationStep for VetoCleared {
    const STEP: usize = 1;
    const LABEL: &'static str = TRUNCATION_STEPS[0];
}
impl TruncationStep for SizePublished {
    const STEP: usize = 2;
    const LABEL: &'static str = TRUNCATION_STEPS[1];
}
impl TruncationStep for TailPurged {
    const STEP: usize = 3;
    const LABEL: &'static str = TRUNCATION_STEPS[2];
}
impl TruncationStep for Committed {
    const STEP: usize = 4;
    const LABEL: &'static str = TRUNCATION_STEPS[3];
}
impl TruncationStep for VdlClamped {
    const STEP: usize = 5;
    const LABEL: &'static str = TRUNCATION_STEPS[4];
}

/// A step that **cannot fail**.
///
/// `06-locking.md` §3.3: *"Terminal reentry installs the already-validated
/// SizeState and performs only nonfailing cache-size update and gate-release
/// work. The kernel never discovers a new fallible prerequisite after an
/// irreversible provider size change."*
///
/// A transition that gained a `Result` would return `Result<_, _>`, which does
/// not implement this, so the assertion in the tests stops compiling. The rule
/// is declared rather than left to whoever reads the signature.
pub trait Nonfailing {}

/// What `MmCanFileBeTruncated` answered. The call itself belongs to
/// `fsring-fsd`; this crate decides what its answer means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmVerdict {
    CanTruncate,
    /// An incompatible active mapping exists over the region being cut away.
    Vetoed,
}

/// `07 §5` step 1's veto outcome.
///
/// *"the request completes **locally**, immediately, with
/// `STATUS_USER_MAPPED_FILE` … with no ReqId, grant, digest, or SQE ever
/// allocated."* The status is read from `fsring-abi`, never written here, and
/// this value is produced only where no request resource can yet exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct MappedFileVeto {
    status: i32,
}

impl MappedFileVeto {
    /// `USER_MAPPED_FILE`, from the frozen crate.
    pub const fn status(&self) -> i32 {
        self.status
    }
}

/// Why a reduction could not enter `07 §5`'s sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TruncationEntryError {
    /// The request is not a transition the size lane accepts at all.
    Transition(SizeTransitionError),
    /// `06 §3.3`: *"Only a reduction enters TRUNCATING"*.
    NotAReduction(SizeChange),
    /// `MmCanFileBeTruncated` said no.
    Vetoed(MappedFileVeto),
}

/// Why an extension could not begin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionEntryError {
    Transition(SizeTransitionError),
    /// A reduction must go through [`Truncation::mm_veto`], which runs the MM
    /// veto and the purge that `07 §5` requires and this sequence has neither.
    NotAnExtension(SizeChange),
    Epoch(EpochError),
}

/// A reduction, positioned in `07 §5`'s sequence.
#[derive(Debug)]
pub struct Truncation<S> {
    trio: SizeTrio,
    step: core::marker::PhantomData<S>,
}

impl<S: TruncationStep> Truncation<S> {
    /// The document's label for the step this reduction has reached.
    pub const fn label(&self) -> &'static str {
        S::LABEL
    }
    /// Its 1-based position in §5.
    pub const fn step(&self) -> usize {
        S::STEP
    }
    pub const fn trio(&self) -> SizeTrio {
        self.trio
    }
}

impl Truncation<VetoCleared> {
    /// §5 step 1, and the only way into the sequence.
    ///
    /// *"`MmCanFileBeTruncated` … is the truncation veto … `CcPurgeCacheSection`
    /// does **not** itself invalidate active mappings and MUST NOT be treated as
    /// proof that mapped views have gone away — `MmCanFileBeTruncated` is the
    /// actual veto, and it MUST run before any other reduction-only step."*
    ///
    /// Takes `current` and **classifies the change itself**, so only a
    /// [`SizeChange::Reduce`] can enter. An earlier revision took the requested
    /// trio alone: a review then compiled an *extension* through this entry and
    /// a *shrink* through the extension entry, which is rev-1's own defect —
    /// an allocation shrink routed around the veto and the purge — reappearing
    /// one level above the classifier that was fixed to prevent it.
    pub fn mm_veto(
        current: SizeTrio,
        requested: SizeTrio,
        verdict: MmVerdict,
    ) -> Result<Self, TruncationEntryError> {
        match classify_request(current, requested) {
            Err(e) => return Err(TruncationEntryError::Transition(e)),
            Ok(change) if !enters_truncating(change) => {
                return Err(TruncationEntryError::NotAReduction(change));
            }
            Ok(_) => {}
        }
        match verdict {
            MmVerdict::Vetoed => Err(TruncationEntryError::Vetoed(MappedFileVeto {
                status: fsring_abi::validate::completion_status::USER_MAPPED_FILE,
            })),
            MmVerdict::CanTruncate => Ok(Self {
                trio: requested,
                step: core::marker::PhantomData,
            }),
        }
    }

    /// §5 step 2. Takes the [`CcPublication`] evidence, so a reduction cannot
    /// publish from the paging path, at the wrong IRQL, or under a lock that
    /// forbids the wait.
    pub fn publish_sizes(self, publication: CcPublication) -> Truncation<SizePublished> {
        let _ = publication;
        Truncation {
            trio: self.trio,
            step: core::marker::PhantomData,
        }
    }
}

impl Truncation<SizePublished> {
    /// §5 step 3, after publication so Cc already knows the new EOF when it
    /// discards pages.
    pub fn purge_tail(self) -> Truncation<TailPurged> {
        Truncation {
            trio: self.trio,
            step: core::marker::PhantomData,
        }
    }
}

impl Truncation<TailPurged> {
    /// §5 step 4 — the last fallible step. The provider size change is
    /// irreversible from here, so nothing after it may fail.
    ///
    /// **The returned state is what gets installed, not the requested one.**
    /// `05-irp-dispatch.md` §9.4: *"The returned allocation is at least the
    /// resulting EOF and **at least the requested allocation**, and the complete
    /// returned SizeState is committed"*, and on an EOF shrink the provider
    /// *"returns allocation at least the new EOF and VDL no greater than it"* —
    /// both legally different from what was asked for. `07 §3` makes the daemon
    /// the durable authority; `06 §3.3` installs the already-validated
    /// SizeState at terminal reentry. An earlier revision carried the requested
    /// trio through the whole sequence and clamped that.
    ///
    /// The epoch comes from the [`EpochCapture`] taken under the gate, so an
    /// epoch that survived a wait cannot reach here: `06 §3.3` invalidates it.
    pub fn commit(
        self,
        expected: EpochCapture,
        returned: ValidatedSizeState,
    ) -> Result<Truncation<Committed>, EpochError> {
        match accept_size_response_epoch(expected.epoch(), returned.size_epoch()) {
            Ok(()) => Ok(Truncation {
                trio: returned.trio(),
                step: core::marker::PhantomData,
            }),
            Err(e) => Err(e),
        }
    }
}

impl Truncation<Committed> {
    /// §5 step 5: *"After the completion queue entry confirms the commit, the
    /// kernel sets `valid_data_length = min(VDL, EOF)`."*
    ///
    /// Infallible by signature — see [`Nonfailing`].
    pub fn clamp_vdl(self) -> Truncation<VdlClamped> {
        Truncation {
            trio: SizeTrio {
                allocation_size: self.trio.allocation_size,
                file_size: self.trio.file_size,
                valid_data_length: vdl_after_commit(
                    self.trio.valid_data_length,
                    self.trio.file_size,
                ),
            },
            step: core::marker::PhantomData,
        }
    }
}

impl Nonfailing for Truncation<VdlClamped> {}

// ============================================================================
// `07 §3`'s extending-write order
// ============================================================================

/// One clause of `07 §3`'s extending-write sentence.
pub trait ExtensionStep {
    const STEP: usize;
    /// The clause text, as it appears in [`EXTENDING_WRITE`].
    const CLAUSE: &'static str;
}

/// The daemon has reserved **and committed** the new EOF.
///
/// Named for the whole step. §3 says *"Reserve/**commit** the new EOF with the
/// daemon first"*, and `06:237` uses "reserves" for a different thing entirely —
/// the pre-gate fallible-resource reservation. A state called `Reserved` invites
/// putting the commit after publication, which is the order this sequence exists
/// to fix.
#[derive(Debug)]
pub struct ProviderCommitted(());
/// `CcSetFileSizes` has published the larger sizes.
#[derive(Debug)]
pub struct SizesPublished(());
/// `CcCopyWrite` may run into the newly visible range.
#[derive(Debug)]
pub struct CopyWritePermitted(());

impl ExtensionStep for ProviderCommitted {
    const STEP: usize = 1;
    const CLAUSE: &'static str = "Reserve/commit the new EOF with the daemon first";
}
impl ExtensionStep for SizesPublished {
    const STEP: usize = 2;
    const CLAUSE: &'static str = "call `CcSetFileSizes`";
}
impl ExtensionStep for CopyWritePermitted {
    const STEP: usize = 3;
    const CLAUSE: &'static str = "then run `CcCopyWrite`";
}

/// An extension, positioned in `07 §3`'s order.
///
/// No veto and no purge: §5 says *"Extending `FileSize`/`AllocationSize`
/// publishes the larger sizes to Cc first and does **not** purge; no MM veto
/// applies to an extension because no existing mapped range is being cut away."*
/// That "first" contrasts with the reduction's veto→publish→purge shape; it is
/// not a licence to publish before the provider, which §3 settles.
#[derive(Debug)]
pub struct Extension<S> {
    trio: SizeTrio,
    step: core::marker::PhantomData<S>,
}

impl<S: ExtensionStep> Extension<S> {
    pub const fn clause(&self) -> &'static str {
        S::CLAUSE
    }
    pub const fn step(&self) -> usize {
        S::STEP
    }
    pub const fn trio(&self) -> SizeTrio {
        self.trio
    }
}

impl Extension<ProviderCommitted> {
    /// The daemon reserved and committed the new EOF. The last fallible step:
    /// the size change is irreversible from here.
    /// The state installed is the provider's, not the request's — see
    /// [`Truncation::commit`] for the sentences.
    ///
    /// Classifies against `current` and refuses anything that
    /// [`enters_truncating`], so a shrink cannot take the path with no veto and
    /// no purge.
    pub fn provider_committed(
        current: SizeTrio,
        expected: EpochCapture,
        returned: ValidatedSizeState,
    ) -> Result<Self, ExtensionEntryError> {
        match classify_request(current, returned.trio()) {
            Err(e) => return Err(ExtensionEntryError::Transition(e)),
            Ok(change) if enters_truncating(change) => {
                return Err(ExtensionEntryError::NotAnExtension(change));
            }
            Ok(_) => {}
        }
        match accept_size_response_epoch(expected.epoch(), returned.size_epoch()) {
            Ok(()) => Ok(Self {
                trio: returned.trio(),
                step: core::marker::PhantomData,
            }),
            Err(e) => Err(ExtensionEntryError::Epoch(e)),
        }
    }

    /// Publish the larger sizes. Infallible: `06 §3.3`'s terminal reentry
    /// installs the *already-validated* SizeState.
    pub fn publish_sizes(self, publication: CcPublication) -> Extension<SizesPublished> {
        let _ = publication;
        Extension {
            trio: self.trio,
            step: core::marker::PhantomData,
        }
    }
}

impl Extension<SizesPublished> {
    /// Cc now knows the new EOF, so `CcCopyWrite` cannot be rejected for
    /// writing past the old one.
    pub fn permit_copy_write(self) -> Extension<CopyWritePermitted> {
        Extension {
            trio: self.trio,
            step: core::marker::PhantomData,
        }
    }
}

impl Nonfailing for Extension<SizesPublished> {}
impl Nonfailing for Extension<CopyWritePermitted> {}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::lockrank::LockRank;
    use crate::typestate::passive_at_driver_entry;

    const CACHE_DOC: &str = include_str!("../../../docs/design/07-cache-mm.md");
    const LOCK_DOC: &str = include_str!("../../../docs/design/06-locking.md");

    /// The text from `start` up to the next `end` marker.
    fn section<'a>(doc: &'a str, start: &str, end: &str) -> &'a str {
        let Some(s) = doc.find(start) else {
            panic!("heading {start:?} not found -- the document was reorganised")
        };
        let rest = doc.get(s..).unwrap_or("");
        match rest.find(end) {
            Some(e) => rest.get(..e).unwrap_or(""),
            None => rest,
        }
    }

    /// The first contiguous run of `- ` items, continuation lines joined with a
    /// single space. The run ends at the first blank line *after* it has begun,
    /// so a blank line between the lead-in and the list is tolerated.
    fn collect_bullets(text: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut started = false;
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("- ") {
                started = true;
                out.push(String::from(rest));
            } else if started {
                if t.is_empty() {
                    break;
                }
                if let Some(last) = out.last_mut() {
                    last.push(' ');
                    last.push_str(t);
                }
            }
        }
        out
    }

    /// `07 §5`'s numbered reduction steps, as (ordinal, bold label).
    fn doc_truncation_steps() -> Vec<(usize, String)> {
        let sec = section(CACHE_DOC, "## 5. Truncation", "\n## 6.");
        let mut out = Vec::new();
        for line in sec.lines() {
            let Some((num, rest)) = line.split_once(". **") else {
                continue;
            };
            let Ok(n) = num.trim().parse::<usize>() else {
                continue;
            };
            let Some((label, _)) = rest.split_once("**") else {
                continue;
            };
            out.push((n, String::from(label)));
        }
        out
    }

    /// `07 §3`'s `CcSetFileSizes` obligation bullets, verbatim.
    fn doc_cc_obligations() -> Vec<String> {
        let sec = section(CACHE_DOC, "## 3. Size trio", "\n## 4.");
        let Some(i) = sec.find("MUST be called:") else {
            panic!("07 section 3's `MUST be called:` lead-in is gone")
        };
        collect_bullets(sec.get(i..).unwrap_or(""))
    }

    /// `06 §3.3`'s reduction-only obligations, verbatim.
    fn doc_truncating_work() -> Vec<String> {
        let sec = section(LOCK_DOC, "### 3.3 The per-FCB size gate", "\n### 3.4");
        let Some(i) = sec.find("Only a reduction enters TRUNCATING:") else {
            panic!("06 section 3.3's TRUNCATING lead-in is gone")
        };
        collect_bullets(sec.get(i..).unwrap_or(""))
    }

    /// `07 §3`'s extending-write sentence, and the offsets of its three ordered
    /// clauses so their ORDER can be asserted rather than merely their presence.
    fn doc_extension_clauses() -> (String, [usize; 3]) {
        let sec = section(CACHE_DOC, "## 3. Size trio", "\n## 4.");
        let Some(i) = sec.find("- **Extending write.**") else {
            panic!("07 section 3's extending-write bullet is gone")
        };
        let Some(bullet) = collect_bullets(sec.get(i..).unwrap_or(""))
            .into_iter()
            .next()
        else {
            panic!("the extending-write bullet parsed to nothing")
        };
        let clauses = [
            "Reserve/commit the new EOF with the daemon first",
            "call `CcSetFileSizes`",
            "then run `CcCopyWrite`",
        ];
        let mut at = [0usize; 3];
        for (k, c) in clauses.iter().enumerate() {
            let Some(pos) = bullet.find(c) else {
                panic!("clause {c:?} is not in the parsed sentence {bullet:?}")
            };
            if let Some(slot) = at.get_mut(k) {
                *slot = pos;
            }
        }
        (bullet, at)
    }

    // ------------------------------------------------- the anti-vacuity guard

    #[test]
    fn the_parsed_documents_are_not_empty() {
        // A parser that silently matches nothing would certify every comparison
        // below as passing. B2 needed this guard and only got it on the second
        // correction, so it comes FIRST here and depends on nothing else.
        let steps = doc_truncation_steps();
        assert_eq!(steps.len(), 5, "07 section 5 has five numbered steps");
        assert_eq!(
            doc_cc_obligations().len(),
            3,
            "07 section 3 lists three CcSetFileSizes cases"
        );
        assert_eq!(
            doc_truncating_work().len(),
            3,
            "06 section 3.3 lists three reduction-only obligations"
        );
        for (i, (ordinal, label)) in steps.iter().enumerate() {
            assert_eq!(
                *ordinal,
                i.saturating_add(1),
                "section 5's steps must be numbered consecutively from 1"
            );
            assert!(
                !label.is_empty(),
                "step {ordinal} parsed with an empty label"
            );
        }
        let (sentence, _) = doc_extension_clauses();
        assert!(!sentence.is_empty());
    }

    // ------------------------------- the transcription, against the documents

    #[test]
    fn the_truncation_steps_match_the_document() {
        let parsed = doc_truncation_steps();
        assert_eq!(TRUNCATION_STEPS.len(), parsed.len());
        for (i, (stored, (ordinal, label))) in
            TRUNCATION_STEPS.iter().zip(parsed.iter()).enumerate()
        {
            assert_eq!(
                stored, label,
                "step {ordinal}: TRUNCATION_STEPS[{i}] is not 07 section 5's wording"
            );
        }
    }

    #[test]
    fn the_cc_obligations_match_the_document() {
        let parsed = doc_cc_obligations();
        assert_eq!(CC_OBLIGATIONS.len(), parsed.len());
        for (i, (stored, doc)) in CC_OBLIGATIONS.iter().zip(parsed.iter()).enumerate() {
            assert_eq!(
                stored, doc,
                "CC_OBLIGATIONS[{i}] is not 07 section 3's wording"
            );
        }
    }

    #[test]
    fn the_truncating_work_matches_the_document() {
        let parsed = doc_truncating_work();
        assert_eq!(TRUNCATING_WORK.len(), parsed.len());
        for (i, (stored, doc)) in TRUNCATING_WORK.iter().zip(parsed.iter()).enumerate() {
            assert_eq!(
                stored, doc,
                "TRUNCATING_WORK[{i}] is not 06 section 3.3's wording"
            );
        }
    }

    #[test]
    fn the_extending_write_sentence_matches_the_document() {
        let (sentence, _) = doc_extension_clauses();
        assert_eq!(EXTENDING_WRITE, sentence);
    }

    #[test]
    fn the_extending_write_clauses_are_in_the_documents_order() {
        // Presence is not order. The daemon commit must precede the
        // CcSetFileSizes call, which must precede CcCopyWrite -- design rev 2
        // named a state `Reserved` and asserted the wrong order in its own
        // contract, and nothing in rev 2 could have noticed.
        let (_, at) = doc_extension_clauses();
        let [reserve, publish, copy] = at;
        assert!(
            reserve < publish,
            "07 section 3 puts the daemon reserve/commit before CcSetFileSizes"
        );
        assert!(
            publish < copy,
            "07 section 3 puts CcSetFileSizes before CcCopyWrite"
        );
    }

    // ------------------------------------------------- the domain delegation

    #[test]
    fn a_valid_trio_and_epoch_are_accepted() {
        let Ok(v) = validate(SizeTrio::new(100, 50, 10), 1) else {
            panic!("a well-ordered trio with a nonzero epoch must validate")
        };
        assert_eq!(v.trio(), SizeTrio::new(100, 50, 10));
        assert_eq!(v.size_epoch(), 1);
        assert!(validate(SizeTrio::new(0, 0, 0), 1).is_ok());
    }

    #[test]
    fn the_delegation_rejects_exactly_what_fsring_abi_rejects() {
        // Not a restatement of the rules -- a check that our answer IS its
        // answer, on cases that distinguish them.
        let cases = [
            (SizeTrio::new(100, 50, 10), 1u64),
            (SizeTrio::new(100, 50, 10), 0),
            (SizeTrio::new(50, 100, 10), 1),
            (SizeTrio::new(100, 10, 50), 1),
            (SizeTrio::new(MAX_FILE_SIZE.saturating_add(1), 0, 0), 1),
            (SizeTrio::new(u64::MAX, u64::MAX, u64::MAX), u64::MAX),
            (
                SizeTrio::new(MAX_FILE_SIZE, MAX_FILE_SIZE, MAX_FILE_SIZE),
                1,
            ),
        ];
        let mut seen_ok = 0usize;
        let mut seen_err = 0usize;
        for (trio, epoch) in cases {
            let state = SizeState {
                allocation_size: trio.allocation_size,
                file_size: trio.file_size,
                valid_data_length: trio.valid_data_length,
                size_epoch: epoch,
            };
            let theirs = validate_size_state_v21(state).is_ok();
            let ours = validate(trio, epoch).is_ok();
            assert_eq!(ours, theirs, "disagreed on {trio:?} epoch {epoch}");
            if theirs {
                seen_ok = seen_ok.saturating_add(1);
            } else {
                seen_err = seen_err.saturating_add(1);
            }
        }
        // Anti-vacuity: the case set must have exercised both verdicts.
        assert!(seen_ok > 0 && seen_err > 0, "the case set proves nothing");
    }

    #[test]
    fn a_zero_epoch_is_rejected_through_the_delegation() {
        // The leg a synthesized epoch would have made unreachable.
        assert_eq!(
            validate(SizeTrio::new(100, 50, 10), 0).err(),
            Some(SizeError)
        );
    }

    // -------------------------------------------------------- the epoch lane

    #[test]
    fn only_a_strictly_greater_response_epoch_is_accepted() {
        assert_eq!(accept_size_response_epoch(7, 8), Ok(()));
        assert_eq!(accept_size_response_epoch(7, 7), Err(EpochError::NoAdvance));
        assert_eq!(accept_size_response_epoch(7, 6), Err(EpochError::Stale));
        assert_eq!(accept_size_response_epoch(7, 0), Err(EpochError::Stale));
    }

    #[test]
    fn a_gap_is_legal_and_is_not_an_error() {
        // "gaps are legal, so an epoch that advances by more than one is not
        // itself an error" -- the sentence that stops `expected + 1`.
        assert_eq!(accept_size_response_epoch(7, 9), Ok(()));
        assert_eq!(accept_size_response_epoch(7, 1_000_000), Ok(()));
        assert_eq!(accept_size_response_epoch(0, u64::MAX), Ok(()));
    }

    #[test]
    fn no_advance_and_stale_stay_distinct() {
        assert_ne!(
            accept_size_response_epoch(7, 7),
            accept_size_response_epoch(7, 6)
        );
    }

    #[test]
    fn the_epoch_rule_agrees_with_the_frozen_validator() {
        // fsring-abi's validate_mutation_success_v2 rejects
        //   result.sizes.size_epoch <= request.expected_size_epoch
        // (messages.rs:1622) for every size-kind mutation. This function is a
        // finer-grained RESTATEMENT of that, so it gets a drift guard rather
        // than a claim -- the design's own prohibition on second copies of a
        // frozen rule would otherwise apply to it.
        let interesting = [0u64, 1, 2, 7, 8, u64::MAX.saturating_sub(1), u64::MAX];
        let mut compared = 0usize;
        for expected in interesting {
            for returned in interesting {
                let frozen_rejects = returned <= expected;
                let ours_rejects = accept_size_response_epoch(expected, returned).is_err();
                assert_eq!(
                    ours_rejects, frozen_rejects,
                    "disagreed with the frozen rule at expected={expected} returned={returned}"
                );
                compared = compared.saturating_add(1);
            }
        }
        assert_eq!(
            compared,
            interesting.len().saturating_mul(interesting.len())
        );
    }

    #[test]
    fn a_waited_capture_is_consumed() {
        // 06 section 3.3: "A wait or resource drop invalidates the captured size
        // epoch". wait_occurred consumes the capture; the compile-fail fixture
        // proves there is no path back.
        let capture = EpochCapture::new(42);
        assert_eq!(capture.epoch(), 42);
        // Not Copy: this MOVES the capture, so nothing can read the epoch after
        // it. An earlier revision derived Copy and a probe read it anyway.
        assert_eq!(capture.wait_occurred(), InvalidatedCapture);
    }

    // ----------------------------------------------------- the VDL arithmetic

    #[test]
    fn a_cached_write_targets_the_max_of_vdl_and_its_end() {
        assert_eq!(vdl_after_cached_write(100, 0, 50), Ok(100));
        assert_eq!(vdl_after_cached_write(100, 90, 50), Ok(140));
        assert_eq!(vdl_after_cached_write(0, 0, 1), Ok(1));
        assert_eq!(vdl_after_cached_write(100, 100, 0), Ok(100));
    }

    #[test]
    fn the_cached_write_target_never_wraps_or_leaves_the_domain() {
        // 04 section 8.1: "No opcode may fall back to unsigned wrap or an
        // implementation-defined volume maximum."
        assert_eq!(vdl_after_cached_write(0, u64::MAX, 1), Err(SizeError));
        assert_eq!(vdl_after_cached_write(0, MAX_FILE_SIZE, 1), Err(SizeError));
        assert_eq!(
            vdl_after_cached_write(0, MAX_FILE_SIZE.saturating_sub(1), 1),
            Ok(MAX_FILE_SIZE)
        );
    }

    #[test]
    fn the_post_commit_clamp_is_the_min() {
        // 07 section 5 step 5. It is the MIN: a truncation must not leave VDL
        // above the new EOF.
        assert_eq!(vdl_after_commit(100, 50), 50);
        assert_eq!(vdl_after_commit(50, 100), 50);
        assert_eq!(vdl_after_commit(50, 50), 50);
    }

    #[test]
    fn the_two_vdl_formulas_are_not_interchangeable() {
        // One is a max and one is a min. Swapping them is silent corruption in
        // both directions: a write that never advances VDL, or a truncation
        // that leaves VDL above EOF.
        assert_eq!(vdl_after_cached_write(100, 90, 50), Ok(140));
        assert_eq!(vdl_after_commit(100, 140), 100);
        assert_ne!(
            vdl_after_cached_write(100, 0, 140),
            Ok(vdl_after_commit(100, 140))
        );
    }

    // ---------------------------------------------------- the zero-fill rule

    #[test]
    fn a_read_wholly_below_vdl_needs_no_zero_fill() {
        let t = SizeTrio::new(1000, 500, 200);
        assert!(!must_zero_fill(t, 0, 200));
        assert!(!must_zero_fill(t, 100, 100));
    }

    #[test]
    fn a_read_touching_or_passing_vdl_needs_zero_fill() {
        // "every byte AT OR ABOVE VDL" -- the byte at exactly VDL counts, so
        // the boundary is `end > VDL`, not `end >= VDL`.
        let t = SizeTrio::new(1000, 500, 200);
        assert!(must_zero_fill(t, 200, 1), "the byte AT VDL must be zeroed");
        assert!(must_zero_fill(t, 199, 2));
        assert!(!must_zero_fill(t, 199, 1), "the byte below VDL must not be");
        assert!(must_zero_fill(t, 400, 100));
    }

    #[test]
    fn an_empty_read_never_needs_zero_fill() {
        assert!(!must_zero_fill(SizeTrio::new(1000, 500, 0), 0, 0));
    }

    // -------------------------------------------------------- the classifier

    /// The 27 transitions, as (alloc, file, vdl) deltas.
    const DELTAS: [i8; 3] = [-1, 0, 1];

    fn apply(base: u64, delta: i8) -> u64 {
        match delta {
            -1 => base.saturating_sub(10),
            1 => base.saturating_add(10),
            _ => base,
        }
    }

    /// The expected verdict, written from design decision 5's five sentences
    /// rather than from `classify_request`'s body. A different shape on purpose:
    /// this restates each precedence step as its own predicate.
    fn oracle(a: i8, f: i8, v: i8) -> Result<SizeChange, SizeTransitionError> {
        if v > 0 && (a != 0 || f != 0) {
            return Err(SizeTransitionError::VdlRiderOnSizeChange);
        }
        if a < 0 || f < 0 {
            // The sweep moves each field by a fixed step from a base whose VDL
            // sits below both the current and the new EOF, so every swept
            // reduction is at or below its ceiling; the dedicated tests cover
            // the ceiling itself.
            return Ok(SizeChange::Reduce);
        }
        if v < 0 {
            return Err(SizeTransitionError::VdlRegression);
        }
        if f > 0 {
            return Ok(SizeChange::Extend);
        }
        if a > 0 {
            return Ok(SizeChange::AllocationIncrease);
        }
        if v > 0 {
            return Ok(SizeChange::VdlAdvance);
        }
        Ok(SizeChange::NoChange)
    }

    #[test]
    fn the_classifier_is_total_over_all_27_transitions() {
        // A base with room to move in both directions on every field.
        let current = SizeTrio::new(1000, 500, 200);
        let mut seen: Vec<(i8, i8, i8)> = Vec::new();
        for a in DELTAS {
            for f in DELTAS {
                for v in DELTAS {
                    let requested = SizeTrio::new(
                        apply(current.allocation_size, a),
                        apply(current.file_size, f),
                        apply(current.valid_data_length, v),
                    );
                    assert_eq!(
                        classify_request(current, requested),
                        oracle(a, f, v),
                        "transition (alloc {a}, file {f}, vdl {v})"
                    );
                    assert!(!seen.contains(&(a, f, v)), "cell visited twice");
                    seen.push((a, f, v));
                }
            }
        }
        // Coverage, not iteration count: B1's lesson.
        assert_eq!(seen.len(), 27, "the sweep must visit 27 DISTINCT cells");
    }

    #[test]
    fn an_allocation_only_shrink_is_a_reduction() {
        // 07 section 5: "Shrinking FileSize OR AllocationSize enters TRUNCATING".
        // An earlier design had a direction-blind AllocationOnly variant that
        // would have routed this around MmCanFileBeTruncated and the purge.
        let current = SizeTrio::new(1000, 500, 200);
        let requested = SizeTrio::new(600, 500, 200);
        assert_eq!(classify_request(current, requested), Ok(SizeChange::Reduce));
        assert!(enters_truncating(SizeChange::Reduce));
        assert!(cc_set_file_sizes_required(SizeChange::Reduce));
    }

    #[test]
    fn a_mixed_extend_and_shrink_is_a_reduction() {
        // EOF up, allocation down. Step 1 of the precedence fires first, and it
        // must: the shrink is what needs the veto.
        let current = SizeTrio::new(1000, 500, 200);
        let requested = SizeTrio::new(900, 600, 200);
        assert_eq!(classify_request(current, requested), Ok(SizeChange::Reduce));
    }

    #[test]
    fn a_vdl_regression_is_an_error_not_a_classification() {
        // The four cells where VDL alone decreases. A total classifier gave
        // these answers -- (same, same, down) fell through to NoChange.
        let current = SizeTrio::new(1000, 500, 200);
        for (a, f) in [(0i8, 0i8), (0, 1), (1, 0), (1, 1)] {
            let requested = SizeTrio::new(
                apply(current.allocation_size, a),
                apply(current.file_size, f),
                150,
            );
            assert_eq!(
                classify_request(current, requested),
                Err(SizeTransitionError::VdlRegression),
                "alloc {a}, file {f}, vdl down"
            );
        }
    }

    #[test]
    fn a_reduction_may_carry_a_vdl_at_or_below_its_ceiling() {
        // A reduction's VDL is COMPUTED, not requested. 05 section 9.4: a
        // combined allocation shrink sets "resulting VDL to min(old VDL, new
        // EOF)", and on an EOF shrink the provider "returns allocation at least
        // the new EOF and VDL no greater than it". So the ceiling is
        // min(current VDL, new EOF) -- a bound, not an equality, because the
        // EOF-shrink form only bounds it.
        //
        // An earlier version of this test justified a requested VDL of 150 with
        // "section 5 step 5's clamp", which computes 200 for this input. The
        // cell is legal; the reasoning was not, and a review said so.
        let current = SizeTrio::new(1000, 500, 200);
        let ceiling = 200u64; // min(current VDL 200, new EOF 300)
        assert_eq!(
            classify_request(current, SizeTrio::new(1000, 300, ceiling)),
            Ok(SizeChange::Reduce),
            "at the ceiling"
        );
        assert_eq!(
            classify_request(current, SizeTrio::new(1000, 300, 150)),
            Ok(SizeChange::Reduce),
            "below it, which the EOF-shrink form permits"
        );
    }

    #[test]
    fn a_reduction_may_not_carry_a_vdl_above_its_ceiling() {
        // The ceiling only bites when VDL comes DOWN but not far enough: a VDL
        // that goes UP during a reduction is a rider, caught earlier. The first
        // version of this test used two VDL-increase cases and was measuring the
        // rider rule while claiming to measure the ceiling.
        let current = SizeTrio::new(1000, 500, 400);
        assert_eq!(
            classify_request(current, SizeTrio::new(1000, 200, 300)),
            Err(SizeTransitionError::VdlAboveReductionCeiling),
            "VDL 300 exceeds the new EOF of 200"
        );
        assert_eq!(
            classify_request(current, SizeTrio::new(1000, 200, 200)),
            Ok(SizeChange::Reduce),
            "exactly at the new EOF is the clamp value itself"
        );
        assert_eq!(
            classify_request(current, SizeTrio::new(600, 500, 450)),
            Err(SizeTransitionError::VdlRiderOnSizeChange),
            "an allocation-only shrink cannot raise VDL either"
        );
    }

    #[test]
    fn a_vdl_advance_may_not_ride_another_size_change() {
        // 05 section 9.4: "For SET_VALID_DATA_LENGTH, success additionally
        // requires allocation_size == retained allocation_size, file_size ==
        // retained file_size ... any different successful state is a protocol
        // fault." So an advance riding any other movement has no producer.
        let current = SizeTrio::new(1000, 500, 200);
        for requested in [
            SizeTrio::new(1000, 600, 300),
            SizeTrio::new(1100, 500, 300),
            SizeTrio::new(1100, 600, 300),
        ] {
            assert_eq!(
                classify_request(current, requested),
                Err(SizeTransitionError::VdlRiderOnSizeChange),
                "{requested:?}"
            );
        }
        // And the legitimate shape still classifies.
        assert_eq!(
            classify_request(current, SizeTrio::new(1000, 500, 300)),
            Ok(SizeChange::VdlAdvance)
        );
    }

    #[test]
    fn each_precedence_step_is_reachable_and_distinct() {
        let c = SizeTrio::new(1000, 500, 200);
        assert_eq!(
            classify_request(c, SizeTrio::new(900, 500, 200)),
            Ok(SizeChange::Reduce)
        );
        assert_eq!(
            classify_request(c, SizeTrio::new(1000, 600, 200)),
            Ok(SizeChange::Extend)
        );
        assert_eq!(
            classify_request(c, SizeTrio::new(1100, 500, 200)),
            Ok(SizeChange::AllocationIncrease)
        );
        assert_eq!(
            classify_request(c, SizeTrio::new(1000, 500, 300)),
            Ok(SizeChange::VdlAdvance)
        );
        assert_eq!(classify_request(c, c), Ok(SizeChange::NoChange));
    }

    #[test]
    fn the_sweeps_reductions_stay_under_their_ceiling() {
        // The 27-cell sweep's base must not accidentally exercise the ceiling
        // rule, or the oracle's simplification above would be a lie. VDL 200
        // against a worst-case new EOF of 490 leaves headroom in every cell.
        let current = SizeTrio::new(1000, 500, 200);
        let worst_new_eof = apply(current.file_size, -1);
        assert!(
            current.valid_data_length <= worst_new_eof,
            "the sweep base would collide with the reduction ceiling"
        );
    }

    #[test]
    fn allocation_growth_outranks_a_vdl_advance() {
        // The one pair the other named cases cannot separate: when BOTH
        // allocation and VDL rise, precedence step 3 must fire before step 4.
        // Swapping those two arms reddened only the 27-cell sweep, and B1's rule
        // is that a mutation which reddens only a sweep means the named cases
        // are too weak.
        // 05 section 9.4 forbids a VDL advance riding another change, so the
        // pair is separated by the ERROR rather than by a precedence win -- and
        // that is a stronger answer than the one this test originally asserted.
        let c = SizeTrio::new(1000, 500, 200);
        assert_eq!(
            classify_request(c, SizeTrio::new(1100, 500, 300)),
            Err(SizeTransitionError::VdlRiderOnSizeChange),
            "a VDL advance may not ride an allocation increase"
        );
        assert_eq!(
            classify_request(c, SizeTrio::new(1100, 500, 200)),
            Ok(SizeChange::AllocationIncrease)
        );
        // The precedence still matters: the two answers oblige different Cc work.
        assert!(cc_set_file_sizes_required(SizeChange::AllocationIncrease));
        assert!(!cc_set_file_sizes_required(SizeChange::VdlAdvance));
    }

    #[test]
    fn only_a_reduction_enters_truncating() {
        assert!(enters_truncating(SizeChange::Reduce));
        for other in [
            SizeChange::NoChange,
            SizeChange::Extend,
            SizeChange::AllocationIncrease,
            SizeChange::VdlAdvance,
        ] {
            assert!(!enters_truncating(other), "{other:?} must skip TRUNCATING");
            assert!(!reduction_only_work(other));
        }
    }

    #[test]
    fn no_admission_is_allowed_under_the_size_gate() {
        assert!(!admission_allowed_under_size_gate());
    }

    // -------------------------------------------- the CcSetFileSizes seam

    #[test]
    fn the_four_cc_obligation_arms() {
        assert!(cc_set_file_sizes_required(SizeChange::Extend));
        assert!(cc_set_file_sizes_required(SizeChange::Reduce));
        assert!(cc_set_file_sizes_required(SizeChange::AllocationIncrease));
        assert!(!cc_set_file_sizes_required(SizeChange::VdlAdvance));
        assert!(!cc_set_file_sizes_required(SizeChange::NoChange));
    }

    #[test]
    fn the_fourth_arm_covers_the_allocation_shrink_section_3_omits() {
        // 07 section 3's three bullets have no allocation-DECREASE case; section
        // 5 step 2 supplies it. Assert the omission is real, so this arm cannot
        // be mistaken for an invention.
        for obligation in CC_OBLIGATIONS {
            assert!(
                !obligation.contains("AllocationSize decreases"),
                "section 3 gained an allocation-decrease case: {obligation}"
            );
        }
        assert!(
            CC_OBLIGATIONS
                .iter()
                .any(|o| o.contains("AllocationSize increases")),
            "section 3's allocation-INCREASE bullet is gone"
        );
        assert!(cc_set_file_sizes_required(SizeChange::Reduce));
    }

    fn passive() -> Passive {
        // SAFETY: a host test is not a kernel dispatch routine; there is no IRQL
        // here to be wrong about. The token's contract is about kernel context,
        // and this call exists so the seam can be exercised at all.
        unsafe { passive_at_driver_entry() }
    }

    #[test]
    fn the_paging_path_may_not_publish_sizes_to_cc() {
        let p = passive();
        assert_eq!(
            publish_sizes_to_cc(
                &p,
                &unsafe { EffectContext::empty() },
                IoOrigin::Paging,
                SizeChange::Extend
            ),
            Err(CcError::PagingPathForbidden)
        );
    }

    #[test]
    fn a_change_that_obliges_no_call_is_refused() {
        let p = passive();
        assert_eq!(
            publish_sizes_to_cc(
                &p,
                &unsafe { EffectContext::empty() },
                IoOrigin::Cached,
                SizeChange::VdlAdvance
            ),
            Err(CcError::NotRequired)
        );
    }

    #[test]
    fn publication_consults_b1s_lock_table() {
        // CcSetFileSizes at PASSIVE_LEVEL may block, and 06 section 6 forbids a
        // wait under the notification-state push lock or a CSQ spin lock. The
        // seam asks the table rather than citing it.
        let p = passive();
        let held = crate::lockrank::HeldLocks::none().acquire(LockRank::NotificationState);
        // SAFETY: a host test holds no kernel lock, so `held` describes exactly
        // the (empty) set of real resources owned; it is the test's hypothesis
        // about a call site, which is what this test evaluates.
        let ctx =
            unsafe { EffectContext::assume_held(held, crate::effect::TopLevelContext::Ordinary) };
        let refused = publish_sizes_to_cc(&p, &ctx, IoOrigin::Cached, SizeChange::Extend);
        assert!(
            matches!(refused, Err(CcError::LockOrder(_))),
            "a wait under the notification-state push lock must be refused, got {refused:?}"
        );
        assert_eq!(
            may_emit(&ctx, Effect::Wait(WaitTarget::BlockingResource)).is_err(),
            refused.is_err(),
            "the seam's verdict must BE the checker's verdict"
        );
    }

    /// `07-cache-mm.md` §4, and the case that could not be written before C1:
    /// publishing from inside a Cc callback holds **nothing**, and is still
    /// forbidden, because the thread's top-level context is the cache sentinel.
    #[test]
    fn publishing_under_the_cache_sentinel_is_refused() {
        let p = passive();
        let ctx = unsafe { EffectContext::empty_under_cache_sentinel() };
        assert!(ctx.held().is_empty(), "the point is that nothing is held");
        assert_eq!(
            publish_sizes_to_cc(&p, &ctx, IoOrigin::Cached, SizeChange::Extend),
            Err(CcError::LockOrder(
                LockOrderError::SyncWaitUnderCacheSentinel
            )),
            "07 §4: no synchronous wait while the top-level context is the \
             cache sentinel"
        );
    }

    #[test]
    fn a_permitted_publication_carries_its_change() {
        let p = passive();
        let ok = publish_sizes_to_cc(
            &p,
            &unsafe { EffectContext::empty() },
            IoOrigin::Cached,
            SizeChange::Reduce,
        );
        match ok {
            Ok(pubn) => assert_eq!(pubn.change(), SizeChange::Reduce),
            Err(e) => panic!("an unlocked cached reduction must be permitted, got {e:?}"),
        }
    }

    // ------------------------------------------- the reduction sequence

    fn cc_publication(change: SizeChange) -> CcPublication {
        let p = passive();
        match publish_sizes_to_cc(
            &p,
            &unsafe { EffectContext::empty() },
            IoOrigin::Cached,
            change,
        ) {
            Ok(pubn) => pubn,
            Err(e) => panic!("an unlocked cached publication must be permitted: {e:?}"),
        }
    }

    /// Walk the whole sequence, collecting the label at each state. This is what
    /// binds the CODE's order to the document, rather than binding a stored
    /// array to it.
    /// The provider's answer: allocation ABOVE what was requested, which
    /// 05 section 9.4 explicitly permits.
    fn returned_state(trio: SizeTrio, epoch: u64) -> ValidatedSizeState {
        match validate(trio, epoch) {
            Ok(v) => v,
            Err(_) => panic!("the test's returned state must itself be valid"),
        }
    }

    /// A current state every reduction in these tests shrinks from.
    fn current() -> SizeTrio {
        SizeTrio::new(4096, 500, 200)
    }

    fn walk_truncation() -> Vec<(usize, &'static str)> {
        let requested = SizeTrio::new(4096, 300, 200);
        let Ok(t) = Truncation::mm_veto(current(), requested, MmVerdict::CanTruncate) else {
            panic!("an uncontested truncation must clear the veto")
        };
        let mut out = alloc_vec(&t);
        let t = t.publish_sizes(cc_publication(SizeChange::Reduce));
        out.push((t.step(), t.label()));
        let t = t.purge_tail();
        out.push((t.step(), t.label()));
        let Ok(t) = t.commit(
            EpochCapture::new(7),
            returned_state(SizeTrio::new(1200, 300, 200), 8),
        ) else {
            panic!("a strictly greater epoch must be accepted")
        };
        out.push((t.step(), t.label()));
        let t = t.clamp_vdl();
        assert_nonfailing(&t);
        out.push((t.step(), t.label()));
        out
    }

    fn alloc_vec<S: TruncationStep>(t: &Truncation<S>) -> Vec<(usize, &'static str)> {
        alloc::vec![(t.step(), t.label())]
    }

    /// Compiles only for a type that declares itself infallible. If a
    /// post-commit transition gained a `Result`, this call would not compile.
    fn assert_nonfailing<T: Nonfailing>(_t: &T) {}

    #[test]
    fn the_truncation_typestate_walks_the_documents_steps() {
        let walked = walk_truncation();
        let parsed = doc_truncation_steps();
        assert_eq!(walked.len(), parsed.len(), "the walk must visit every step");
        for (i, ((step, label), (ordinal, doc_label))) in
            walked.iter().zip(parsed.iter()).enumerate()
        {
            assert_eq!(step, ordinal, "position {i}: the typestate's step number");
            assert_eq!(label, doc_label, "position {i}: 07 section 5's wording");
        }
    }

    #[test]
    fn the_veto_terminates_with_fsring_abis_status() {
        let requested = SizeTrio::new(4096, 300, 200);
        match Truncation::mm_veto(current(), requested, MmVerdict::Vetoed) {
            Err(TruncationEntryError::Vetoed(veto)) => assert_eq!(
                veto.status(),
                fsring_abi::validate::completion_status::USER_MAPPED_FILE,
                "the status must be the frozen constant, not a literal"
            ),
            other => panic!("a vetoed truncation must not proceed, got {other:?}"),
        }
    }

    #[test]
    fn the_veto_status_is_the_documented_value() {
        // Read from fsring-abi, but pinned here too: 07 section 5 names
        // USER_MAPPED_FILE = 0xc000_0243 explicitly.
        assert_eq!(
            fsring_abi::validate::completion_status::USER_MAPPED_FILE,
            0xc000_0243_u32 as i32
        );
    }

    #[test]
    fn a_stale_commit_epoch_stops_the_sequence() {
        let requested = SizeTrio::new(4096, 300, 200);
        let Ok(t) = Truncation::mm_veto(current(), requested, MmVerdict::CanTruncate) else {
            panic!("veto cleared")
        };
        let t = t
            .publish_sizes(cc_publication(SizeChange::Reduce))
            .purge_tail();
        assert_eq!(
            t.commit(
                EpochCapture::new(7),
                returned_state(SizeTrio::new(4096, 300, 200), 7)
            )
            .err(),
            Some(EpochError::NoAdvance)
        );
    }

    #[test]
    fn the_clamp_applies_section_5_step_5() {
        let requested = SizeTrio::new(4096, 300, 200);
        let Ok(t) = Truncation::mm_veto(current(), requested, MmVerdict::CanTruncate) else {
            panic!("veto cleared")
        };
        // A provider answer whose VDL still exceeds the new EOF: step 5 exists
        // to clamp it, so the test must supply one that needs clamping.
        let Ok(t) = t
            .publish_sizes(cc_publication(SizeChange::Reduce))
            .purge_tail()
            .commit(
                EpochCapture::new(7),
                returned_state(SizeTrio::new(4096, 300, 250), 8),
            )
        else {
            panic!("commit accepted")
        };
        assert_eq!(t.trio().valid_data_length, 250);
        let done = t.clamp_vdl();
        // **The clamp is IDENTITY here, and that is worth stating rather than
        // hiding.** Once the installed state is a ValidatedSizeState, fsring-abi
        // has already guaranteed A >= F >= V, so min(VDL, EOF) cannot move it.
        // Section 5 step 5 still has work to do on the path this slice does not
        // model -- a kernel mirror whose stale VDL sits above the new EOF -- and
        // `vdl_after_commit`'s own tests cover the case where it bites.
        assert_eq!(done.trio().valid_data_length, 250);
        assert_eq!(done.trio().file_size, 300);
        assert_eq!(
            vdl_after_commit(400, 300),
            300,
            "the formula itself does clamp; it is the validated INPUT that makes              it a no-op in this sequence"
        );
    }

    #[test]
    fn the_commit_installs_the_providers_state_not_the_request() {
        // 05 section 9.4: "The returned allocation is at least the resulting EOF
        // and AT LEAST THE REQUESTED ALLOCATION, and the complete returned
        // SizeState is committed." An earlier revision carried the REQUESTED
        // trio through the whole sequence, so a provider that rounded the
        // allocation up would have been silently overwritten by the request.
        let requested = SizeTrio::new(1000, 300, 200);
        let Ok(t) = Truncation::mm_veto(current(), requested, MmVerdict::CanTruncate) else {
            panic!("veto cleared")
        };
        let provider_answer = SizeTrio::new(8192, 300, 200);
        let Ok(t) = t
            .publish_sizes(cc_publication(SizeChange::Reduce))
            .purge_tail()
            .commit(EpochCapture::new(7), returned_state(provider_answer, 8))
        else {
            panic!("commit accepted")
        };
        assert_eq!(
            t.trio().allocation_size,
            8192,
            "the provider's allocation must survive, not the requested 1000"
        );
        assert_eq!(t.clamp_vdl().trio().allocation_size, 8192);
    }

    // ------------------------------------------- the extension sequence

    fn walk_extension() -> Vec<(usize, &'static str)> {
        let Ok(e) = Extension::provider_committed(
            SizeTrio::new(1000, 500, 200),
            EpochCapture::new(7),
            returned_state(SizeTrio::new(1000, 800, 200), 8),
        ) else {
            panic!("a strictly greater epoch must be accepted")
        };
        let mut out = alloc::vec![(e.step(), e.clause())];
        let e = e.publish_sizes(cc_publication(SizeChange::Extend));
        assert_nonfailing(&e);
        out.push((e.step(), e.clause()));
        let e = e.permit_copy_write();
        assert_nonfailing(&e);
        out.push((e.step(), e.clause()));
        out
    }

    #[test]
    fn the_extension_typestate_walks_the_documents_clause_order() {
        // Presence is not order. Each walked clause must appear in the parsed
        // sentence, and their offsets must increase in the order walked.
        let walked = walk_extension();
        let (sentence, _) = doc_extension_clauses();
        assert_eq!(walked.len(), 3);
        let mut previous = 0usize;
        for (i, (step, clause)) in walked.iter().enumerate() {
            assert_eq!(*step, i.saturating_add(1), "clause {i} is out of position");
            let Some(at) = sentence.find(clause) else {
                panic!("clause {clause:?} is not in 07 section 3's sentence")
            };
            if i > 0 {
                assert!(
                    at > previous,
                    "clause {i} ({clause:?}) precedes its predecessor in the document"
                );
            }
            previous = at;
        }
    }

    #[test]
    fn an_extension_commits_with_the_daemon_before_publishing() {
        // The whole point of ProviderCommitted being first: 07 section 3 says
        // "Reserve/commit the new EOF with the daemon FIRST, update the FCB
        // header and call CcSetFileSizes, then run CcCopyWrite."
        assert_eq!(
            <ProviderCommitted as ExtensionStep>::STEP,
            1,
            "the daemon commit is the extension's first step"
        );
        assert!(
            Extension::provider_committed(
                SizeTrio::new(1000, 500, 200),
                EpochCapture::new(7),
                returned_state(SizeTrio::new(1000, 800, 200), 7)
            )
            .is_err(),
            "an extension cannot commit on a stale epoch"
        );
    }

    #[test]
    fn a_shrink_cannot_take_the_extension_path() {
        // The hole an adversarial review compiled: Extension::provider_committed
        // took no `current`, so a SHRINK went through the sequence that has no
        // MM veto and no purge -- rev-1's own Critical, one level above the
        // classifier that was fixed to stop it.
        let shrunk = SizeTrio::new(100, 50, 10);
        match Extension::provider_committed(
            SizeTrio::new(1000, 500, 10),
            EpochCapture::new(7),
            returned_state(shrunk, 8),
        ) {
            Err(ExtensionEntryError::NotAnExtension(SizeChange::Reduce)) => {}
            other => panic!("a shrink must be refused by the extension entry, got {other:?}"),
        }
    }

    #[test]
    fn an_extension_cannot_take_the_truncation_path() {
        let grown = SizeTrio::new(4096, 900, 200);
        match Truncation::mm_veto(current(), grown, MmVerdict::CanTruncate) {
            Err(TruncationEntryError::NotAReduction(SizeChange::Extend)) => {}
            other => panic!("an extension must be refused by the veto entry, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_transition_cannot_enter_either_sequence() {
        let bad = SizeTrio::new(4096, 500, 300); // a VDL advance riding nothing else is fine,
        let riding = SizeTrio::new(8192, 500, 300); // but riding an allocation increase is not.
        assert!(matches!(
            Truncation::mm_veto(current(), riding, MmVerdict::CanTruncate),
            Err(TruncationEntryError::Transition(
                SizeTransitionError::VdlRiderOnSizeChange
            ))
        ));
        assert!(matches!(
            Extension::provider_committed(
                current(),
                EpochCapture::new(7),
                returned_state(riding, 8)
            ),
            Err(ExtensionEntryError::Transition(
                SizeTransitionError::VdlRiderOnSizeChange
            ))
        ));
        // The well-formed advance still classifies, so this is not vacuous.
        assert_eq!(classify_request(current(), bad), Ok(SizeChange::VdlAdvance));
    }

    #[test]
    fn noncached_io_may_publish_sizes_to_cc() {
        // 07 section 3 forbids only the PAGING path. Forbidding NonCached too
        // would be a narrowing no document asks for, and nothing caught it.
        let p = passive();
        assert!(
            publish_sizes_to_cc(
                &p,
                &unsafe { EffectContext::empty() },
                IoOrigin::NonCached,
                SizeChange::Extend
            )
            .is_ok(),
            "only the paging path is prohibited"
        );
    }

    #[test]
    fn the_paging_prohibition_is_unconditional() {
        // "The paging-I/O path MUST NOT call it" -- not "unless the change would
        // not have obliged a call anyway". The order of the two checks matters,
        // and nothing caught it being reversed.
        let p = passive();
        assert_eq!(
            publish_sizes_to_cc(
                &p,
                &unsafe { EffectContext::empty() },
                IoOrigin::Paging,
                SizeChange::VdlAdvance
            ),
            Err(CcError::PagingPathForbidden),
            "the paging refusal must precede the not-required refusal"
        );
    }

    #[test]
    fn an_overflowing_read_range_is_treated_as_needing_zero_fill() {
        // 04 section 8.1: "No opcode may fall back to unsigned wrap." The
        // overflow arm must fail CLOSED -- its sibling vdl_after_cached_write
        // has this tested; must_zero_fill did not, and flipping it passed.
        let t = SizeTrio::new(1000, 500, 200);
        assert!(
            must_zero_fill(t, u64::MAX, 2),
            "an overflowing range must be treated as reaching past VDL"
        );
    }

    #[test]
    fn an_extension_has_no_veto_and_no_purge() {
        // 07 section 5: "no MM veto applies to an extension because no existing
        // mapped range is being cut away", and it "does not purge".
        // Structural: Extension exposes neither, and Truncation's entry point
        // is the only mm_veto in the module.
        let Ok(e) = Extension::provider_committed(
            SizeTrio::new(1000, 500, 200),
            EpochCapture::new(7),
            returned_state(SizeTrio::new(1000, 800, 200), 8),
        ) else {
            panic!("committed")
        };
        let e = e.publish_sizes(cc_publication(SizeChange::Extend));
        let e = e.permit_copy_write();
        assert_eq!(e.trio().file_size, 800);
    }

    // ------------------------------------------ the delegation, structurally

    /// This module's own source. A behavioural test cannot distinguish a
    /// faithful local copy of a frozen validator from a delegation to it: both
    /// answer identically until one drifts. So the check is structural.
    const OWN_SOURCE: &str = include_str!("size.rs");

    /// The SHIPPED half of this module -- everything before `#[cfg(test)]`.
    ///
    /// The rule is about the code compiled into the kernel image, not about
    /// test scaffolding. On its first run the scan flagged its own anti-vacuity
    /// fixture, which is the scan working correctly on the wrong text.
    fn shipped_source() -> &'static str {
        match OWN_SOURCE.find("#[cfg(test)]") {
            Some(at) => OWN_SOURCE.get(..at).unwrap_or(OWN_SOURCE),
            None => panic!("the test module marker is gone; the scan would cover everything"),
        }
    }

    /// The three field names of the trio, for the cross-field scan.
    const TRIO_FIELDS: [&str; 3] = ["allocation_size", "file_size", "valid_data_length"];

    /// The receiver a `<recv>.<field>` access reads from, if any.
    ///
    /// The rule is "two different fields of **one** state". A comparison of two
    /// different fields across two DIFFERENT states is the classifier's whole
    /// job -- `current.valid_data_length` against `requested.file_size` is how
    /// the reduction ceiling is computed -- and an earlier version of this scan
    /// ignored the receiver and flagged exactly that. The scan was right about
    /// the shape and wrong about the rule.
    fn receiver_of(side: &str, field: &str) -> Option<&'static str> {
        let at = side.rfind(field)?;
        let before = side.get(..at)?;
        let stripped = before.strip_suffix('.')?;
        let start = stripped
            .rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map_or(0, |i| i.saturating_add(1));
        let name = stripped.get(start..)?;
        if name.is_empty() {
            return None;
        }
        // Leaked as 'static by comparing against a fixed set instead of
        // allocating: only equality between the two sides matters.
        Some(match name {
            "trio" => "trio",
            "current" => "current",
            "requested" => "requested",
            "sizes" => "sizes",
            "self" => "self",
            _ => "other",
        })
    }

    /// Every position at which a comparison operator begins.
    ///
    /// An earlier version used `line.find(op)` and inspected only the FIRST
    /// occurrence, so any line with two comparisons was half-examined -- and
    /// ordinary code produces those by accident. It also required spaces around
    /// `<` and `>`, so `a<b` slipped past. An adversarial review compiled both
    /// evasions into the shipped half and they passed.
    fn comparison_splits(line: &str) -> Vec<usize> {
        let bytes = line.as_bytes();
        let mut out = Vec::new();
        for (i, c) in line.char_indices() {
            if c != '<' && c != '>' {
                continue;
            }
            // Skip `->`, `=>`, `<<`, `>>`, and the `<` of a turbofish/generic
            // that is immediately preceded by an identifier character.
            let prev = i.checked_sub(1).and_then(|j| bytes.get(j)).copied();
            let next = line
                .get(i.saturating_add(1)..)
                .and_then(|r| r.chars().next());
            if matches!(prev, Some(b'-') | Some(b'=') | Some(b'<') | Some(b'>')) {
                continue;
            }
            if matches!(next, Some('<') | Some('>')) {
                continue;
            }
            out.push(i);
        }
        out
    }

    /// True when the line compares two DIFFERENT trio fields of the SAME state
    /// -- the `A >= F >= V` shape `validate_size_state_v21` owns.
    ///
    /// Cross-*state* comparisons of different fields are the classifier's job
    /// (the reduction ceiling reads `current.valid_data_length` against
    /// `requested.file_size`), and same-field cross-state comparisons are its
    /// whole purpose. Neither is a restatement.
    ///
    /// **What this cannot see**, stated because a review demonstrated it: a copy
    /// that rebinds the fields to locals first (`let a = t.allocation_size; …
    /// a >= f`) names no trio field on the comparison line, and one split across
    /// two lines is invisible to a line scanner. The scan is a hygiene check,
    /// not the guarantee -- see `the_evidence_type_is_the_real_guard`.
    fn is_cross_field_same_state(line: &str) -> bool {
        !cross_field_hits(line).is_empty()
    }

    /// The offending (receiver, lhs field, rhs field) triples on one line.
    fn cross_field_hits(line: &str) -> Vec<(&'static str, &'static str, &'static str)> {
        let mut hits = Vec::new();
        for at in comparison_splits(line) {
            let (Some(lhs), Some(rhs)) = (line.get(..at), line.get(at..)) else {
                continue;
            };
            for a in TRIO_FIELDS {
                for b in TRIO_FIELDS {
                    if a == b || !lhs.contains(a) || !rhs.contains(b) {
                        continue;
                    }
                    let (Some(l), Some(r)) = (receiver_of(lhs, a), receiver_of(rhs, b)) else {
                        continue;
                    };
                    if l == r {
                        hits.push((l, a, b));
                    }
                }
            }
        }
        hits
    }

    #[test]
    fn the_trio_ordering_is_never_restated_here() {
        // 07 section 3 states the ordering; 04 section 8.1 states the bounds;
        // fsring-abi enforces both. A second copy here would agree today and
        // drift tomorrow, and nothing would notice until it mattered.
        //
        // The scan and its anti-vacuity guard call the SAME predicate. An
        // earlier version had the guard reimplement the needle over a planted
        // string, so switching the real scan's operator list off left every test
        // green -- B2's own defect, a copy checked against itself, reproduced
        // inside the guard that exists to prevent it.
        let mut offences: Vec<String> = Vec::new();
        for (n, raw) in shipped_source().lines().enumerate() {
            let line = raw.trim();
            if line.starts_with("//") {
                continue;
            }
            for (recv, a, b) in cross_field_hits(line) {
                offences.push(alloc::format!(
                    "line {}: `{recv}.{a}` compared with `{recv}.{b}` -- {line}",
                    n.saturating_add(1)
                ));
            }
        }
        assert!(
            offences.is_empty(),
            "the trio ordering belongs to fsring-abi's validate_size_state_v21, \
             not to this module:\n{}",
            offences.join("\n")
        );
    }

    #[test]
    fn the_scan_fires_on_every_shape_a_review_got_past_it() {
        // Anti-vacuity in both directions, over the SAME code the scan runs.
        for restatement in [
            "if trio.allocation_size >= trio.file_size { }",
            "self.trio.file_size >= self.trio.valid_data_length",
            "if trio.allocation_size<trio.file_size { }",
            "let ok = 1 >= 0 && trio.allocation_size >= trio.file_size;",
            "assert!(x > y && trio.file_size > trio.valid_data_length)",
        ] {
            assert!(
                is_cross_field_same_state(restatement),
                "the scan misses: {restatement}"
            );
        }
        for legitimate in [
            "let ceiling = if current.valid_data_length < requested.file_size { }",
            "if requested.file_size > current.file_size { }",
            "fn f(x: Vec<SizeTrio>) -> Option<u64> { }",
            "let a = requested.allocation_size;",
        ] {
            assert!(
                !is_cross_field_same_state(legitimate),
                "the scan false-positives on: {legitimate}"
            );
        }
    }

    #[test]
    fn the_evidence_type_is_the_real_guard() {
        // The scan is a hygiene check with demonstrated blind spots. The
        // STRUCTURAL guarantee is narrower and stronger: `ValidatedSizeState`
        // has private fields and exactly one construction site, inside
        // `validate`, which calls the frozen validator. A local restatement may
        // exist somewhere a line scanner cannot see it -- but it cannot mint the
        // evidence the two sequences require, so it cannot install anything.
        let src = shipped_source();
        // A CONSTRUCTION site, not the declaration or the impl block: a struct
        // literal is `ValidatedSizeState {` not preceded by `struct ` or
        // `impl `. The first version of this test counted all three and failed
        // -- correctly, on a needle that meant something else.
        let sites: Vec<usize> = src
            .match_indices("ValidatedSizeState {")
            .filter(|(at, _)| {
                let Some(before) = src.get(..*at) else {
                    return false;
                };
                !before.ends_with("struct ") && !before.ends_with("impl ")
            })
            .map(|(at, _)| at)
            .collect();
        assert_eq!(
            sites.len(),
            1,
            "ValidatedSizeState must have exactly one construction site; found {}",
            sites.len()
        );
        let Some(&at) = sites.first() else {
            panic!("no construction site at all")
        };
        let Some(before) = src.get(..at) else {
            panic!("slice")
        };
        assert!(
            before.ends_with("Ok("),
            "the only mint must sit in an Ok arm"
        );
        let Some(guard) = before.rfind("validate_size_state_v21(state)") else {
            panic!("the mint is not guarded by the frozen validator")
        };
        assert!(guard < at, "the frozen call must precede the mint");
    }

    #[test]
    fn the_max_file_size_bound_is_never_restated_here() {
        // 04 section 8.1's domain is fsring-abi's MAX_FILE_SIZE. This module
        // may USE it; it may not spell the value out.
        assert!(
            !shipped_source().contains("0x7fffffffffffffff"),
            "MAX_FILE_SIZE's value belongs to fsring-abi/src/limits.rs:204"
        );
        assert!(
            !shipped_source().contains("i64::MAX as u64"),
            "use fsring_abi::limits::MAX_FILE_SIZE rather than recomputing it"
        );
    }
}
