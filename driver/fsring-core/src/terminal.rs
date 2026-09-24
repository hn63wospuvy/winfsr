//! The one-terminal-owner CAS and the refund-exactly-once ledger
//! (`06-locking.md` §5).
//!
//! §5.1: *"Once the IRP may be visible to cancellation or a queue, that ticket
//! follows the one terminal-owner CAS; losing paths never refund it. … The
//! terminal owner refunds exactly once only after the last driver MDL/system-VA
//! access and after `IoCompleteRequest` returns."*
//!
//! Five things are made structural here rather than left to discipline:
//!
//! 1. **One winner.** [`TerminalOwner::claim`] is a real `compare_exchange`, and
//!    only the winner receives a [`TerminalClaim`] — which is sealed, so a loser
//!    cannot manufacture one.
//! 2. **The CAS governs only once the IRP may be visible.** §5.1 opens with
//!    *"Once the IRP may be visible to cancellation or a queue"*, and §11's
//!    *"cancel, never visible"* row refunds with no arbitration at all:
//!    *"nothing was visible, so no ticket transfer occurred"*. So the ticket
//!    carries that boundary in its type: [`QuotaTicket<NotYetVisible>`] refunds
//!    by rollback and cannot enter a ledger; [`QuotaTicket<MayBeVisible>`] is
//!    bound to the arbitration that will govern it.
//! 3. **Losing paths never refund *this* ticket.** A [`RefundGate`] needs a
//!    [`TerminalClaim`] **from the arbitration the ticket was published under**.
//!    Winning some *other* arbitration buys nothing — see
//!    [`MismatchedArbitration`].
//! 4. **Refund exactly once, and not early.** The gate is a typestate that must
//!    pass through both §5.1 preconditions before `refund` exists, and `refund`
//!    consumes the gate.
//! 5. **A refund receipt is minted, never written.** [`Refund`]'s fields are
//!    private, so the only way to produce one is to actually perform a refund.
//!
//! **What is not proven here.** No IRP, MDL, budget object or rundown reference
//! exists in this crate, so nothing verifies that a caller's assertions —
//! visibility, last access, completion returned — are *true*; the typestates
//! prove only that the code cannot reach a refund without asserting them. The
//! race test is empirical evidence on one machine, not a statement about the
//! memory model. And the guarantees above are guarantees about **safe** code:
//! `transmute` and `ptr::read` defeat any of them, as they defeat every
//! typestate in Rust.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Who is competing for a terminal arbitration.
///
/// One variant per claimant `06-locking.md` §5.2 distinguishes. Distinctions the
/// document draws are kept: `CSQ_CANCEL` is not "cancellation", "stream close"
/// is not "CCB CLEANUP", "unload" is not "irreversible teardown", and "clean
/// DETACH" is not a completion. Collapsing two distinct things into one position
/// was the shipped defect in slice B1, and it is not repeated.
///
/// **The transcription is not this enum** — it is the verbatim `segment` on each
/// [`Claimant`], which `every_registry_row_matches_the_document` compares to the
/// parsed document positionally and exactly. A `ClaimantKind` is the *label* on
/// a quoted segment, and [`phrase`] is only the text used to check that the
/// label is the best available reading of it. Where the document adds a
/// qualifier the label does not repeat — "session fence" and "the fence" are both
/// `Fence`, "irreversible teardown" is `Teardown` — the quoted segment is what
/// carries the difference, and no §5.2 row pairs a qualified form with its bare
/// form, so no discrimination is lost.
///
/// [`phrase`]: ClaimantKind::phrase
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClaimantKind {
    Completion = 1,
    Cancellation = 2,
    Fence = 3,
    Teardown = 4,
    CqCandidate = 5,
    ProviderCancelled = 6,
    CqConsumer = 7,
    Timeout = 8,
    NormalDrain = 9,
    DetachedHandler = 10,
    CcbCleanup = 11,
    NormalEvent = 12,
    Overflow = 13,
    BarrierWake = 14,
    ResourceHandoff = 15,
    CsqCancel = 16,
    Rejection = 17,
    StreamClose = 18,
    StructuralFailure = 19,
    CleanDetach = 20,
    GraceExpiry = 21,
    ProtocolAbort = 22,
    Unload = 23,
    AckPublication = 24,
    EnterContinuation = 25,
    DetachedOwner = 26,
    LateCqCandidate = 27,
}

/// Every claimant, in discriminant order, for exhaustive iteration.
pub const ALL_CLAIMANTS: [ClaimantKind; 27] = {
    use ClaimantKind as K;
    [
        K::Completion,
        K::Cancellation,
        K::Fence,
        K::Teardown,
        K::CqCandidate,
        K::ProviderCancelled,
        K::CqConsumer,
        K::Timeout,
        K::NormalDrain,
        K::DetachedHandler,
        K::CcbCleanup,
        K::NormalEvent,
        K::Overflow,
        K::BarrierWake,
        K::ResourceHandoff,
        K::CsqCancel,
        K::Rejection,
        K::StreamClose,
        K::StructuralFailure,
        K::CleanDetach,
        K::GraceExpiry,
        K::ProtocolAbort,
        K::Unload,
        K::AckPublication,
        K::EnterContinuation,
        K::DetachedOwner,
        K::LateCqCandidate,
    ]
};

impl ClaimantKind {
    const fn code(self) -> u8 {
        self as u8
    }

    /// The shortest text that identifies this claimant in `06-locking.md` §5.2.
    ///
    /// Used to check a label, never to find a segment:
    /// `each_claimant_is_the_longest_match_for_its_own_segment` requires this to
    /// occur in the claimant's quoted segment and requires no other variant to
    /// match that segment with a **longer** phrase.
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::Cancellation => "cancellation",
            Self::Fence => "fence",
            Self::Teardown => "teardown",
            Self::CqCandidate => "CQ candidate",
            Self::ProviderCancelled => "provider CANCELLED",
            Self::CqConsumer => "CQ consumer",
            Self::Timeout => "timeout",
            Self::NormalDrain => "normal drain",
            Self::DetachedHandler => "DETACHED_HANDLER",
            Self::CcbCleanup => "CCB CLEANUP",
            Self::NormalEvent => "normal event",
            Self::Overflow => "overflow",
            Self::BarrierWake => "barrier wake",
            Self::ResourceHandoff => "resource handoff",
            Self::CsqCancel => "CSQ_CANCEL",
            Self::Rejection => "rejection",
            Self::StreamClose => "stream close",
            Self::StructuralFailure => "structural failure",
            Self::CleanDetach => "clean DETACH",
            Self::GraceExpiry => "grace expiry",
            Self::ProtocolAbort => "protocol abort",
            Self::Unload => "unload",
            Self::AckPublication => "ack publication",
            Self::EnterContinuation => "ENTER continuations",
            Self::DetachedOwner => "detached owners",
            Self::LateCqCandidate => "late CQ candidates",
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Completion,
            2 => Self::Cancellation,
            3 => Self::Fence,
            4 => Self::Teardown,
            5 => Self::CqCandidate,
            6 => Self::ProviderCancelled,
            7 => Self::CqConsumer,
            8 => Self::Timeout,
            9 => Self::NormalDrain,
            10 => Self::DetachedHandler,
            11 => Self::CcbCleanup,
            12 => Self::NormalEvent,
            13 => Self::Overflow,
            14 => Self::BarrierWake,
            15 => Self::ResourceHandoff,
            16 => Self::CsqCancel,
            17 => Self::Rejection,
            18 => Self::StreamClose,
            19 => Self::StructuralFailure,
            20 => Self::CleanDetach,
            21 => Self::GraceExpiry,
            22 => Self::ProtocolAbort,
            23 => Self::Unload,
            24 => Self::AckPublication,
            25 => Self::EnterContinuation,
            26 => Self::DetachedOwner,
            27 => Self::LateCqCandidate,
            _ => return None,
        })
    }
}

/// Which arbitration a claim or a ticket belongs to.
///
/// Drawn from a monotonic counter at [`TerminalOwner::new`], so it is
/// **provenance**, not identity: it survives the owner being moved, and a later
/// arbitration never inherits an earlier one's id.
///
/// The first attempt used the owner's address instead. That stopped the attack
/// it was built for, but it broke the honest path: publishing a ticket and then
/// moving the arbitration — `Box::new(owner)`, pushing it into a collection —
/// changed the address, so the real winner's claim was rejected and the charged
/// ticket came back inside a [`MismatchedArbitration`] for the caller to drop.
/// A fix that introduces the leak §5.1 exists to prevent is not a fix. A probe
/// compiled against the real crate confirmed it before this replacement.
///
/// The counter wraps after 2^64 arbitrations. One per direct-I/O admission puts
/// that beyond any uptime this driver will see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArbitrationId(u64);

/// The source of [`ArbitrationId`]s. Starts at 1 so a zero id is never valid.
static NEXT_ARBITRATION: AtomicU64 = AtomicU64::new(1);

/// Proof that this path won a terminal arbitration.
///
/// Sealed by private fields: outside this module it cannot be constructed, and
/// [`TerminalOwner::claim`] is the only thing that mints one. It records *which*
/// arbitration it won, so it cannot be spent on another one's ticket.
#[derive(Debug)]
pub struct TerminalClaim {
    winner: ClaimantKind,
    arbitration: ArbitrationId,
}

impl TerminalClaim {
    /// Which claimant this proof belongs to.
    pub const fn winner(&self) -> ClaimantKind {
        self.winner
    }
    /// Which arbitration this proof was won in.
    pub const fn arbitration(&self) -> ArbitrationId {
        self.arbitration
    }
}

/// The result of competing for a terminal arbitration.
#[derive(Debug)]
pub enum ClaimOutcome {
    /// This path is the single terminal owner.
    Won(TerminalClaim),
    /// Another path already won.
    ///
    /// `winner` is `None` only if the owner byte held a value [`claim`] cannot
    /// write — memory corruption, not a lost race. It is reported rather than
    /// papered over with a plausible-looking claimant, because a loser that
    /// logs the wrong winner is worse than one that says it does not know.
    ///
    /// [`claim`]: TerminalOwner::claim
    Lost { winner: Option<ClaimantKind> },
}

/// One terminal arbitration: one CAS, one owner, forever.
///
/// `06-locking.md` §5.2: *"Every terminal arbitration in the driver is one CAS
/// with one owner."*
///
/// "Forever" is a property of one *value*. There is deliberately no `Default`
/// and no `reset`, so no safe call re-arms a decided arbitration through a
/// shared reference. A holder of `&mut TerminalOwner` can still overwrite it
/// with a fresh one — that is true of every Rust type and requires exclusive
/// access, which the deployment shape (an arbitration shared inside a request
/// context) never grants.
#[derive(Debug)]
pub struct TerminalOwner {
    state: AtomicU8,
    id: ArbitrationId,
}

impl TerminalOwner {
    // PROOF: `Default` is withheld deliberately, not forgotten. `Default` is
    // what makes `core::mem::take(&mut owner)` compile, and that call re-arms a
    // decided arbitration -- it leaves a fresh unclaimed owner behind, so a
    // second path can win what was already won and refund a second time. That
    // is the exact failure section 5.1 forbids. `new()` is the constructor; a
    // caller that genuinely wants a fresh arbitration writes one.
    #[allow(clippy::new_without_default)]
    /// A fresh, unclaimed arbitration, with an id no other arbitration shares.
    ///
    /// Not `const`: the id comes from a counter, which is what makes the
    /// binding survive a move. See [`ArbitrationId`].
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            id: ArbitrationId(NEXT_ARBITRATION.fetch_add(1, Ordering::Relaxed)),
        }
    }

    /// This arbitration's provenance, for binding tickets and claims to it.
    pub const fn id(&self) -> ArbitrationId {
        self.id
    }

    /// Compete. Exactly one call across all threads returns [`ClaimOutcome::Won`].
    ///
    /// A second claim by the *same* claimant still loses: the arbitration is
    /// over, and pretending otherwise would let one path refund twice.
    pub fn claim(&self, who: ClaimantKind) -> ClaimOutcome {
        match self.state.compare_exchange(
            0,
            who.code(),
            // Acquire-Release: the winner's subsequent work must be ordered
            // after the claim, and a loser must observe the winner's prior
            // publication.
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => ClaimOutcome::Won(TerminalClaim {
                winner: who,
                arbitration: self.id,
            }),
            Err(existing) => ClaimOutcome::Lost {
                winner: ClaimantKind::from_code(existing),
            },
        }
    }

    /// The winner, if the arbitration has been decided.
    pub fn winner(&self) -> Option<ClaimantKind> {
        ClaimantKind::from_code(self.state.load(Ordering::Acquire))
    }
}

/// The budget owners a ticket references.
///
/// §5.1: *"the exact charge and the referenced global/mount/I/O-owner and
/// optional class-budget owners"*. Ticket references keep these alive through
/// the refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TicketOwners {
    pub global: u64,
    pub mount: u64,
    pub io_owner: u64,
    /// Optional per-class budget owner.
    pub class_budget: Option<u64>,
}

/// The IRP cannot yet be seen by cancellation or a queue.
#[derive(Debug)]
pub struct NotYetVisible(());
/// The IRP may be visible, so §5.1's CAS governs the ticket from here on.
#[derive(Debug)]
pub struct MayBeVisible(());

/// One nonpaged quota ticket, carrying §5.1's visibility boundary in its type.
///
/// Deliberately neither `Copy` nor `Clone`: a duplicable ticket is a double
/// refund waiting to happen. `#[must_use]` because dropping one silently is the
/// leak §5.1 exists to prevent.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct QuotaTicket<V> {
    charge: u64,
    owners: TicketOwners,
    /// Set at publication; `None` before the IRP may be visible.
    arbitration: Option<ArbitrationId>,
    visibility: PhantomData<V>,
}

impl QuotaTicket<NotYetVisible> {
    /// Charge a ticket at admission. §5.1: *"Every direct-I/O admission produces
    /// one nonpaged quota ticket"*.
    pub const fn charge_at_admission(charge: u64, owners: TicketOwners) -> Self {
        Self {
            charge,
            owners,
            arbitration: None,
            visibility: PhantomData,
        }
    }

    /// Refund a ticket the IRP never made visible, with **no arbitration**.
    ///
    /// `06-locking.md` §11, the *"cancel, never visible"* row: *"local
    /// completion after full reservation rollback; nothing was visible, so no
    /// ticket transfer occurred."* §5.1's CAS begins at visibility, so requiring
    /// a [`TerminalClaim`] here would force a path to win an arbitration the
    /// document says does not yet govern it.
    pub fn rollback_before_visibility(self) -> Refund {
        Refund {
            charge: self.charge,
            owners: self.owners,
        }
    }

    /// The IRP may now be seen by cancellation or a queue, and `owner` is the
    /// arbitration that governs this ticket from here on. Only that
    /// arbitration's winner can refund it.
    pub fn may_be_visible(self, owner: &TerminalOwner) -> QuotaTicket<MayBeVisible> {
        QuotaTicket {
            charge: self.charge,
            owners: self.owners,
            arbitration: Some(owner.id()),
            visibility: PhantomData,
        }
    }
}

impl QuotaTicket<MayBeVisible> {
    /// The arbitration this ticket was published under.
    pub const fn arbitration(&self) -> Option<ArbitrationId> {
        self.arbitration
    }
}

impl<V> QuotaTicket<V> {
    pub const fn charge(&self) -> u64 {
        self.charge
    }
    pub const fn owners(&self) -> TicketOwners {
        self.owners
    }
}

/// A claim from one arbitration was offered for a ticket published under
/// another. Both are handed back, because dropping a charged ticket would leak
/// the charge — the failure §5.1 exists to prevent.
#[derive(Debug)]
pub struct MismatchedArbitration {
    pub claim: TerminalClaim,
    pub ticket: QuotaTicket<MayBeVisible>,
}

/// What a refund released.
///
/// Fields are private and there is no public constructor: the only way to hold
/// one is to have performed a refund. A receipt anyone can write is not
/// evidence that a refund happened.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct Refund {
    charge: u64,
    owners: TicketOwners,
}

impl Refund {
    pub const fn charge(&self) -> u64 {
        self.charge
    }
    pub const fn owners(&self) -> TicketOwners {
        self.owners
    }
}

/// The ticket is charged; neither §5.1 precondition has been met.
///
/// The three state markers are only ever used as type parameters — the gate
/// holds a `PhantomData`, never a value — so they are never constructed at all.
#[derive(Debug)]
pub struct Charged(());
/// The last driver MDL/system-VA access is done.
#[derive(Debug)]
pub struct LastAccessDone(());
/// `IoCompleteRequest` has **returned**.
#[derive(Debug)]
pub struct CompletionReturned(());

/// The refund ledger, as a typestate over §5.1's two preconditions.
///
/// Built only from a [`TerminalClaim`] won in the very arbitration the ticket
/// was published under. `refund` exists only in the final state and consumes the
/// gate, so a second refund does not type-check.
#[derive(Debug)]
pub struct RefundGate<S> {
    claim: TerminalClaim,
    ticket: QuotaTicket<MayBeVisible>,
    state: PhantomData<S>,
}

impl RefundGate<Charged> {
    /// Take the ticket into the ledger.
    ///
    /// Fails if the claim was won in a different arbitration than the one the
    /// ticket was published under — the loophole that makes "only the winner
    /// refunds" a statement about *this* request rather than about winning
    /// something, anything.
    pub fn new(
        claim: TerminalClaim,
        ticket: QuotaTicket<MayBeVisible>,
    ) -> Result<Self, MismatchedArbitration> {
        if ticket.arbitration != Some(claim.arbitration) {
            return Err(MismatchedArbitration { claim, ticket });
        }
        Ok(Self {
            claim,
            ticket,
            state: PhantomData,
        })
    }

    /// Record that the last driver MDL/system-VA access has happened.
    pub fn last_access_done(self) -> RefundGate<LastAccessDone> {
        RefundGate {
            claim: self.claim,
            ticket: self.ticket,
            state: PhantomData,
        }
    }
}

impl RefundGate<LastAccessDone> {
    /// Record that `IoCompleteRequest` has **returned** — not merely been
    /// called. §5.1 is specific about that.
    pub fn completion_returned(self) -> RefundGate<CompletionReturned> {
        RefundGate {
            claim: self.claim,
            ticket: self.ticket,
            state: PhantomData,
        }
    }
}

impl RefundGate<CompletionReturned> {
    /// Refund, exactly once. Consumes the gate, so there is no second refund to
    /// write.
    pub fn refund(self) -> Refund {
        Refund {
            charge: self.ticket.charge(),
            owners: self.ticket.owners(),
        }
    }
}

impl<S> RefundGate<S> {
    /// Which claimant owns this ledger.
    pub const fn winner(&self) -> ClaimantKind {
        self.claim.winner()
    }
}

/// Something that happens to a charged request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeEvent {
    ReadWriteChunking,
    QuerySecurityRecovery,
    InternalQueryDirBatch,
    RecoverableGraceAttach,
    NotificationFanout,
    DeferredCompletion,
    /// A notification fence. §5.1: terminal, and it refunds.
    NotificationFence,
    /// A restart-eligible QueryDir/READ/WRITE/QUERY_SECURITY fence. §5.1: the
    /// ticket is **retained** through reissue.
    RestartEligibleFence,
}

/// Every charge event, for exhaustive iteration.
pub const ALL_CHARGE_EVENTS: [ChargeEvent; 8] = [
    ChargeEvent::ReadWriteChunking,
    ChargeEvent::QuerySecurityRecovery,
    ChargeEvent::InternalQueryDirBatch,
    ChargeEvent::RecoverableGraceAttach,
    ChargeEvent::NotificationFanout,
    ChargeEvent::DeferredCompletion,
    ChargeEvent::NotificationFence,
    ChargeEvent::RestartEligibleFence,
];

/// What happens to the charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// The charge survives; the ticket stays with the request.
    Survives,
    /// Terminal: the owner refunds.
    TerminalRefund,
    /// Retained through reissue — neither refunded nor re-charged.
    RetainThroughReissue,
}

/// `06-locking.md` §5.1's charge-survival rule, total over [`ChargeEvent`].
pub const fn charge_disposition(event: ChargeEvent) -> Disposition {
    match event {
        ChargeEvent::ReadWriteChunking
        | ChargeEvent::QuerySecurityRecovery
        | ChargeEvent::InternalQueryDirBatch
        | ChargeEvent::RecoverableGraceAttach
        | ChargeEvent::NotificationFanout
        | ChargeEvent::DeferredCompletion => Disposition::Survives,
        ChargeEvent::NotificationFence => Disposition::TerminalRefund,
        ChargeEvent::RestartEligibleFence => Disposition::RetainThroughReissue,
    }
}

/// One row of `06-locking.md` §5.2's closed registry.
///
/// The document's table has four columns; this carries two. "CAS owner state"
/// and "Exact rundown/refund point" name kernel objects that do not exist in
/// this crate — `sq_wait_owner`, `IoCsqRemoveIrp`, MDLs, rundown — so storing
/// their prose would add a second, unchecked copy of the document with no
/// consumer. Row 1's refund point is the one this slice does model, and it is
/// modelled as [`RefundGate`] rather than as a string.
#[derive(Clone, Copy, Debug)]
pub struct Arbitration {
    /// The arbitration's name, matching §5.2's first column with its
    /// `(section N)` reference stripped.
    pub name: &'static str,
    /// The claimants that compete for it, in the document's order.
    pub claimants: &'static [Claimant],
}

/// One claimant of one arbitration, carrying `06-locking.md` §5.2's **verbatim**
/// wording for it in that row.
///
/// The segment is quoted rather than paraphrased for two reasons. The test
/// compares it to the parsed document **positionally and exactly**, so drift in
/// either direction fails; and a reader sees the document's own words beside the
/// label, which is what makes a mislabel visible at all.
///
/// An earlier revision matched claimant to segment by substring search, and a
/// reviewer demonstrated the consequence: `Completion`'s phrase "completion" is
/// a substring of "a registered provider CANCELLED completion", so a
/// transcription collapsing the two passed every test. Search finds *a* match;
/// it cannot tell you the match was the right one.
#[derive(Clone, Copy, Debug)]
pub struct Claimant {
    pub kind: ClaimantKind,
    /// §5.2's exact text for this claimant, between the commas.
    pub segment: &'static str,
}

const fn c(kind: ClaimantKind, segment: &'static str) -> Claimant {
    Claimant { kind, segment }
}

use ClaimantKind as C;

/// `06-locking.md` §5.2's registry. **Closed**: exactly these eleven.
///
/// Checked against the document itself by
/// `every_registry_row_matches_the_document`, which parses §5.2's table out of
/// `06-locking.md` — so an added row, a dropped row, a dropped claimant or an
/// invented one fails against the normative source, not against a hand-copied
/// expectation. The first revision of this slice asserted "exactly ten" and was
/// wrong about the document; nothing in it could have noticed.
pub const REGISTRY: [Arbitration; 11] = [
    Arbitration {
        name: "direct-I/O quota ticket",
        claimants: &[
            c(C::Completion, "completion"),
            c(C::Cancellation, "cancellation"),
            c(C::Fence, "fence"),
            c(C::Teardown, "teardown"),
        ],
    },
    Arbitration {
        name: "per-request semantic state",
        claimants: &[
            c(C::CqCandidate, "a stable matching CQ candidate"),
            c(
                C::ProviderCancelled,
                "a registered provider CANCELLED completion",
            ),
            c(C::Fence, "a session fence after its stable-prefix drain"),
        ],
    },
    Arbitration {
        name: "journaled candidate capture",
        claimants: &[
            c(C::CqConsumer, "CQ consumer"),
            c(
                C::Fence,
                "session fence (which waits for any capture in progress)",
            ),
        ],
    },
    Arbitration {
        name: "ENTER SQ wait",
        claimants: &[
            c(C::Cancellation, "cancellation"),
            c(C::Timeout, "timeout"),
            c(C::Fence, "fence -- each arbitrates the bit exactly once"),
        ],
    },
    Arbitration {
        name: "ENTER CQ role",
        claimants: &[
            c(C::NormalDrain, "the normal drain"),
            c(C::DetachedHandler, "the `DETACHED_HANDLER` continuation"),
            c(C::Fence, "the fence"),
        ],
    },
    Arbitration {
        name: "change-notify CSQ IRP",
        claimants: &[
            c(C::Cancellation, "cancellation"),
            c(C::CcbCleanup, "CCB CLEANUP"),
            c(C::NormalEvent, "a normal event"),
            c(C::Overflow, "overflow"),
            c(C::Fence, "the session fence"),
        ],
    },
    Arbitration {
        name: "AdvanceOnly context",
        claimants: &[
            c(C::BarrierWake, "barrier wake"),
            c(C::ResourceHandoff, "resource handoff"),
            c(C::CsqCancel, "CSQ_CANCEL"),
            c(C::Rejection, "rejection"),
            c(C::StreamClose, "stream close"),
            c(C::Teardown, "teardown"),
        ],
    },
    Arbitration {
        name: "paging-WRITE active context",
        claimants: &[
            c(C::Completion, "completion"),
            c(C::StructuralFailure, "structural failure"),
            c(C::Cancellation, "cancellation"),
            c(C::Teardown, "teardown"),
        ],
    },
    Arbitration {
        name: "DETACH / mount-lifecycle terminal",
        claimants: &[
            c(C::CleanDetach, "clean DETACH"),
            c(C::GraceExpiry, "grace expiry"),
            c(C::ProtocolAbort, "protocol abort"),
            c(C::Teardown, "irreversible teardown"),
            c(C::Unload, "unload"),
        ],
    },
    Arbitration {
        name: "PT acknowledgement",
        claimants: &[
            c(C::AckPublication, "ack publication"),
            c(C::Fence, "session fence"),
            c(C::Teardown, "teardown"),
        ],
    },
    Arbitration {
        name: "session fence",
        claimants: &[
            c(C::EnterContinuation, "in-flight ENTER continuations"),
            c(C::DetachedOwner, "detached owners"),
            c(C::LateCqCandidate, "late CQ candidates"),
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The normative document itself. Compiled into the TEST binary only.
    const DOC: &str = include_str!("../../../docs/design/06-locking.md");

    fn owners() -> TicketOwners {
        TicketOwners {
            global: 1,
            mount: 2,
            io_owner: 3,
            class_budget: Some(4),
        }
    }

    fn won(owner: &TerminalOwner, who: ClaimantKind) -> TerminalClaim {
        match owner.claim(who) {
            ClaimOutcome::Won(claim) => claim,
            ClaimOutcome::Lost { .. } => panic!("the first claim must win"),
        }
    }

    fn ledger(owner: &TerminalOwner, who: ClaimantKind, charge: u64) -> RefundGate<Charged> {
        let ticket = QuotaTicket::charge_at_admission(charge, owners()).may_be_visible(owner);
        match RefundGate::new(won(owner, who), ticket) {
            Ok(gate) => gate,
            Err(_) => panic!("a claim from this arbitration must be accepted"),
        }
    }

    // ---------------------------------------------------------------- the CAS

    #[test]
    fn exactly_one_claim_wins() {
        let owner = TerminalOwner::new();
        let claim = won(&owner, C::Completion);
        assert_eq!(claim.winner(), C::Completion);
        assert!(matches!(
            owner.claim(C::Cancellation),
            ClaimOutcome::Lost {
                winner: Some(C::Completion)
            }
        ));
    }

    #[test]
    fn the_same_claimant_still_loses_the_second_time() {
        // The arbitration is over. Letting the winner claim again would let one
        // path build two RefundGates and refund twice.
        let owner = TerminalOwner::new();
        let _first = won(&owner, C::Fence);
        assert!(matches!(
            owner.claim(C::Fence),
            ClaimOutcome::Lost {
                winner: Some(C::Fence)
            }
        ));
    }

    #[test]
    fn a_loser_learns_the_actual_winner() {
        for winner in [C::Teardown, C::Timeout, C::Overflow, C::Unload] {
            let owner = TerminalOwner::new();
            let _claim = won(&owner, winner);
            match owner.claim(C::Cancellation) {
                ClaimOutcome::Lost { winner: w } => assert_eq!(w, Some(winner)),
                ClaimOutcome::Won(_) => panic!("a second claim must not win"),
            }
            assert_eq!(owner.winner(), Some(winner));
        }
    }

    #[test]
    fn an_unclaimed_arbitration_has_no_winner() {
        assert_eq!(TerminalOwner::new().winner(), None);
    }

    #[test]
    fn racing_threads_produce_exactly_one_winner() {
        // EMPIRICAL evidence on one machine, not a statement about the memory
        // model: it exercises the interleavings this host happens to produce.
        // The real gate is Driver Verifier, which cannot run here.
        use std::sync::Arc;
        const THREADS: usize = 8;
        const ROUNDS: usize = 200;

        let mut observed_wins = 0usize;
        let mut observed_losses = 0usize;
        for round in 0..ROUNDS {
            let owner = Arc::new(TerminalOwner::new());
            let barrier = Arc::new(std::sync::Barrier::new(THREADS));
            let mut handles = Vec::new();
            for i in 0..THREADS {
                let owner = Arc::clone(&owner);
                let barrier = Arc::clone(&barrier);
                let who = ALL_CLAIMANTS.get(i).copied().unwrap_or(C::Completion);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    match owner.claim(who) {
                        ClaimOutcome::Won(claim) => (true, Some(claim.winner())),
                        ClaimOutcome::Lost { winner } => (false, winner),
                    }
                }));
            }
            let mut wins = 0usize;
            let mut losses = 0usize;
            let mut named: Vec<ClaimantKind> = Vec::new();
            for h in handles {
                let Ok((did_win, seen)) = h.join() else {
                    panic!("a racing thread panicked")
                };
                if did_win {
                    wins = wins.saturating_add(1);
                } else {
                    losses = losses.saturating_add(1);
                }
                let Some(s) = seen else {
                    panic!(
                        "a thread could not name a winner: the owner byte held a code claim cannot write"
                    )
                };
                named.push(s);
            }
            assert_eq!(wins, 1, "round {round}: exactly one thread must win");

            // Winner and losers alike must name the SAME winner.
            let actual = owner.winner();
            assert!(
                actual.is_some(),
                "round {round}: the arbitration is decided"
            );
            for s in named {
                assert_eq!(
                    Some(s),
                    actual,
                    "round {round}: a thread named the wrong winner"
                );
            }
            observed_wins = observed_wins.saturating_add(wins);
            observed_losses = observed_losses.saturating_add(losses);
        }

        // Anti-vacuity, counted from what the THREADS RETURNED. The first
        // revision incremented this by a constant each round and then compared
        // it to that same constant times ROUNDS -- arithmetic that cannot fail
        // for any THREADS value, including THREADS = 1, which is precisely the
        // no-contention case it claimed to exclude. Same defect B1 found in a
        // cell counter that counted iterations instead of coverage.
        assert_eq!(observed_wins, ROUNDS, "one winner per round");
        assert_eq!(
            observed_losses,
            ROUNDS.saturating_mul(THREADS.saturating_sub(1)),
            "every non-winning thread must have reported a loss"
        );
        assert!(observed_losses > 0, "the race produced no losers at all");
    }

    // ------------------------------------------------------------- the ledger

    #[test]
    fn the_winner_refunds_exactly_once_after_both_preconditions() {
        let owner = TerminalOwner::new();
        let gate = ledger(&owner, C::Completion, 4096);
        assert_eq!(gate.winner(), C::Completion);
        let refund = gate.last_access_done().completion_returned().refund();
        assert_eq!(refund.charge(), 4096);
        assert_eq!(refund.owners(), owners());
        // A second refund does not type-check: `refund` consumed the gate. The
        // compile-fail fixtures assert that, since a test cannot.
    }

    #[test]
    fn winning_a_different_arbitration_buys_nothing() {
        // The attack an adversarial review compiled against the first revision:
        // lose the real arbitration, then mint a fresh TerminalOwner, win it
        // trivially, and spend THAT claim on the real ticket. `RefundGate::new`
        // took any claim with any ticket, so it type-checked and refunded.
        let real = TerminalOwner::new();
        let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&real);
        let _winner = won(&real, C::Completion);
        assert!(matches!(
            real.claim(C::Cancellation),
            ClaimOutcome::Lost { .. }
        ));

        let side = TerminalOwner::new();
        let side_claim = won(&side, C::Cancellation);
        assert_ne!(
            side_claim.arbitration(),
            ticket.arbitration().unwrap_or(side.id())
        );

        match RefundGate::new(side_claim, ticket) {
            Err(back) => {
                // Both come back: dropping a charged ticket would leak the
                // charge, which is the failure section 5.1 exists to prevent.
                assert_eq!(back.ticket.charge(), 4096);
                assert_eq!(back.claim.winner(), C::Cancellation);
            }
            Ok(_) => panic!("a claim from another arbitration must not open this ledger"),
        }
    }

    #[test]
    fn the_real_winner_is_accepted_for_its_own_ticket() {
        // The other half of the binding: the check must not reject the path it
        // exists to permit.
        let owner = TerminalOwner::new();
        let refund = ledger(&owner, C::Completion, 512)
            .last_access_done()
            .completion_returned()
            .refund();
        assert_eq!(refund.charge(), 512);
    }

    #[test]
    fn a_never_visible_ticket_refunds_without_any_arbitration() {
        // 06-locking.md section 11, "cancel, never visible": "local completion
        // after full reservation rollback; nothing was visible, so no ticket
        // transfer occurred." No TerminalOwner is constructed here AT ALL --
        // that is the point. Section 5.1's CAS begins at visibility.
        let ticket = QuotaTicket::charge_at_admission(8192, owners());
        let refund = ticket.rollback_before_visibility();
        assert_eq!(refund.charge(), 8192);
        assert_eq!(refund.owners(), owners());
    }

    #[test]
    fn publication_binds_the_ticket_to_one_arbitration() {
        let a = TerminalOwner::new();
        let b = TerminalOwner::new();
        assert_ne!(a.id(), b.id(), "distinct arbitrations differ");
        let ticket = QuotaTicket::charge_at_admission(64, owners()).may_be_visible(&a);
        assert_eq!(ticket.arbitration(), Some(a.id()));
        assert_ne!(ticket.arbitration(), Some(b.id()));
    }

    #[test]
    fn moving_the_arbitration_does_not_orphan_its_ticket() {
        // The defect the FIRST attempt at this binding introduced. ArbitrationId
        // was the owner's address, so publishing a ticket and then moving the
        // arbitration -- Box::new(owner), pushing it into a collection -- made
        // the real winner's claim mismatch. The charged ticket then came back
        // inside a MismatchedArbitration for the caller to drop: the very leak
        // section 5.1 exists to prevent, introduced by the fix for something
        // else. A compiled downstream probe demonstrated it.
        let owner = TerminalOwner::new();
        let before = owner.id();
        let ticket = QuotaTicket::charge_at_admission(4096, owners()).may_be_visible(&owner);

        let moved = Box::new(owner);
        assert_eq!(moved.id(), before, "an id must survive a move");

        let ClaimOutcome::Won(claim) = moved.claim(C::Completion) else {
            panic!("the first claim must win")
        };
        match RefundGate::new(claim, ticket) {
            Ok(gate) => {
                let refund = gate.last_access_done().completion_returned().refund();
                assert_eq!(refund.charge(), 4096);
            }
            Err(_) => panic!("the legitimate winner was rejected after a move"),
        }
    }

    #[test]
    fn arbitration_ids_are_never_reused() {
        // Provenance, not identity: an id is not inherited by a later
        // arbitration even if the earlier one is gone. An address-based id
        // could be.
        let first = {
            let owner = TerminalOwner::new();
            owner.id()
        };
        let mut seen = Vec::new();
        for _ in 0..64 {
            let owner = TerminalOwner::new();
            let id = owner.id();
            assert_ne!(id, first, "a dropped arbitration's id came back");
            assert!(!seen.contains(&id), "an id was issued twice");
            seen.push(id);
        }
    }

    // ------------------------------------------------- the charge disposition

    #[test]
    fn the_charge_survival_table_is_total_and_correct() {
        let mut seen = 0usize;
        for e in ALL_CHARGE_EVENTS {
            let d = charge_disposition(e);
            let expected = match e {
                ChargeEvent::NotificationFence => Disposition::TerminalRefund,
                ChargeEvent::RestartEligibleFence => Disposition::RetainThroughReissue,
                _ => Disposition::Survives,
            };
            assert_eq!(d, expected, "{e:?}");
            seen = seen.saturating_add(1);
        }
        assert_eq!(seen, ALL_CHARGE_EVENTS.len());
    }

    #[test]
    fn the_two_fences_mean_opposite_things() {
        // Both rows say "fence"; section 5.1 gives them opposite dispositions,
        // which is exactly the pair a reader skims past.
        assert_eq!(
            charge_disposition(ChargeEvent::NotificationFence),
            Disposition::TerminalRefund
        );
        assert_eq!(
            charge_disposition(ChargeEvent::RestartEligibleFence),
            Disposition::RetainThroughReissue
        );
        assert_ne!(
            charge_disposition(ChargeEvent::NotificationFence),
            charge_disposition(ChargeEvent::RestartEligibleFence)
        );
    }

    // ------------------------------------- the registry, checked against §5.2

    /// §5.2's table, parsed out of the normative document: one entry per data
    /// row, as (arbitration name, claimant-cell segments).
    fn doc_rows() -> Vec<(String, Vec<String>)> {
        let mut rows = Vec::new();
        let mut inside = false;
        for line in DOC.lines() {
            if line.starts_with("### 5.2") {
                inside = true;
                continue;
            }
            if inside && line.starts_with("### ") {
                break;
            }
            if !inside || !line.starts_with('|') {
                continue;
            }
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let (Some(name), Some(claimants)) = (cells.get(1), cells.get(3)) else {
                continue;
            };
            if name.starts_with("Terminal arbitration") || name.starts_with("---") {
                continue;
            }
            let name = name.split(" (section").next().unwrap_or(name).trim();
            let segments: Vec<String> = claimants
                .split(',')
                .map(|s| String::from(s.trim()))
                .collect();
            rows.push((String::from(name), segments));
        }
        rows
    }

    #[test]
    fn the_document_table_was_actually_found() {
        // Guard against the registry test passing vacuously because the parser
        // silently matched nothing. If 06-locking.md is reorganised this fails
        // loudly instead of certifying an empty comparison.
        let rows = doc_rows();
        assert!(
            rows.len() >= 5,
            "parsed {} rows out of section 5.2; the parser or the document moved",
            rows.len()
        );
        for (name, segments) in &rows {
            assert!(!name.is_empty(), "a parsed row has no arbitration name");
            assert!(
                segments.len() >= 2,
                "row {name} parsed with fewer than two claimants: {segments:?}"
            );
        }
    }

    #[test]
    fn every_registry_row_matches_the_document() {
        let rows = doc_rows();

        assert_eq!(
            REGISTRY.len(),
            rows.len(),
            "06-locking.md section 5.2 has {} rows; REGISTRY has {}. The registry \
             is declared CLOSED, so this is a contract break, not a formatting \
             difference.",
            rows.len(),
            REGISTRY.len()
        );

        for (i, (arb, (doc_name, segments))) in REGISTRY.iter().zip(rows.iter()).enumerate() {
            assert_eq!(
                arb.name, doc_name,
                "row {i}: REGISTRY is in document order; name mismatch"
            );
            assert_eq!(
                arb.claimants.len(),
                segments.len(),
                "row {i} ({doc_name}): the document lists {} claimants, REGISTRY has {} -- {segments:?}",
                segments.len(),
                arb.claimants.len()
            );

            // Positional and EXACT. No search, so no chance of a claimant
            // binding to a segment that merely contains its phrase.
            for (j, (claimant, segment)) in arb.claimants.iter().zip(segments.iter()).enumerate() {
                assert_eq!(
                    claimant.segment, segment,
                    "row {i} claimant {j} ({doc_name}): REGISTRY quotes {:?}, \
                     06-locking.md says {segment:?}",
                    claimant.segment
                );
            }
        }
    }

    #[test]
    fn each_claimant_is_the_longest_match_for_its_own_segment() {
        // The label must be the BEST available reading of the quoted segment,
        // not merely a possible one. A reviewer showed the difference by
        // transcribing "a registered provider CANCELLED completion" as
        // `Completion`: its phrase "completion" really is a substring, so a
        // containment check accepted it. `ProviderCancelled`'s phrase is longer
        // and also matches, so this test rejects it.
        //
        // Stated narrowly, because it is not a closure: this catches a mislabel
        // whenever a BETTER-matching variant exists. A coordinated edit that
        // deletes the better variant first still passes -- what stops that is
        // the verbatim quote sitting next to the label, which is a reader's
        // defence, not a machine's.
        for (i, arb) in REGISTRY.iter().enumerate() {
            for claimant in arb.claimants {
                let own = claimant.kind.phrase();
                assert!(
                    claimant.segment.contains(own),
                    "row {i} ({}): {:?} does not contain its claimant's phrase {own:?}",
                    arb.name,
                    claimant.segment
                );
                for other in ALL_CLAIMANTS {
                    if other == claimant.kind {
                        continue;
                    }
                    let alt = other.phrase();
                    assert!(
                        !(claimant.segment.contains(alt) && alt.len() > own.len()),
                        "row {i} ({}): segment {:?} is labelled {:?} (phrase {own:?}) \
                         but {other:?} matches it with the longer phrase {alt:?}",
                        arb.name,
                        claimant.segment,
                        claimant.kind
                    );
                }
            }
        }
    }

    #[test]
    fn the_registry_is_well_formed() {
        for (i, a) in REGISTRY.iter().enumerate() {
            assert!(!a.name.is_empty());
            assert!(
                a.claimants.len() >= 2,
                "{}: an arbitration with one claimant is not an arbitration",
                a.name
            );
            for b in REGISTRY.iter().skip(i.saturating_add(1)) {
                assert_ne!(a.name, b.name, "duplicate registry row");
            }
            for c in a.claimants {
                assert_eq!(ClaimantKind::from_code(c.kind.code()), Some(c.kind));
            }
        }
    }

    #[test]
    fn every_claimant_is_used_by_some_arbitration() {
        // A variant no row references is either an invention or a transcription
        // that lost its row -- both are the failure this slice exists to catch.
        for k in ALL_CLAIMANTS {
            assert!(
                REGISTRY
                    .iter()
                    .any(|a| a.claimants.iter().any(|c| c.kind == k)),
                "{k:?} is named by no arbitration"
            );
        }
    }

    #[test]
    fn claimant_codes_round_trip_and_reject_the_unknown() {
        let mut seen = 0usize;
        for (i, k) in ALL_CLAIMANTS.iter().enumerate() {
            let expected = u8::try_from(i.saturating_add(1)).unwrap_or(0);
            assert_eq!(k.code(), expected, "{k:?} has a non-contiguous code");
            assert_eq!(ClaimantKind::from_code(k.code()), Some(*k));
            seen = seen.saturating_add(1);
        }
        assert_eq!(seen, ALL_CLAIMANTS.len());
        assert_eq!(ClaimantKind::from_code(0), None, "0 means unclaimed");
        let past_end = u8::try_from(ALL_CLAIMANTS.len().saturating_add(1)).unwrap_or(u8::MAX);
        assert_eq!(ClaimantKind::from_code(past_end), None);
        assert_eq!(ClaimantKind::from_code(u8::MAX), None);
    }

    #[test]
    fn every_claimant_phrase_appears_in_the_document() {
        // Catches a phrase that is a plausible paraphrase rather than the
        // document's own words. The bijection test alone would still pass if a
        // phrase matched its segment by accident of a shared substring.
        for k in ALL_CLAIMANTS {
            assert!(
                DOC.contains(k.phrase()),
                "{k:?}: phrase {:?} does not occur in 06-locking.md",
                k.phrase()
            );
        }
    }

    #[test]
    fn a_ticket_is_not_duplicable() {
        // A compile-time property expressed as a reminder: QuotaTicket derives
        // neither Copy nor Clone, so the only way to have two is to charge two.
        let t = QuotaTicket::charge_at_admission(8, owners());
        let moved = t;
        assert_eq!(moved.charge(), 8);
    }
}
