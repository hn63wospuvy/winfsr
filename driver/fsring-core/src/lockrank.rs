//! The universal lock order (`06-locking.md` §1), the change-notify nesting
//! (§8), and the no-completion-under-a-lock rule (§6), as total functions.
//!
//! `06-locking.md` §1 opens: *"The driver has exactly one blocking-acquisition
//! order."* This module is that order, checkable. Every future acquisition site
//! calls [`may_acquire`] before taking a lock and [`may_perform`] before doing
//! something a held lock forbids.
//!
//! **What this is not.** It does not prevent a deadlock. It checks the orders
//! this document names, at sites that call it; the real gate is Driver
//! Verifier's deadlock detection, which is an environment gate
//! (`12-test-plan.md`), and `11-rust-implementation.md` §5 already calls the
//! static lock-order lint a "best-effort supplement" to it. No kernel lock is
//! acquired here — this module holds the rule, not the mechanism — so **a call
//! site that does not consult it is not protected by it**.
//!
//! **What is modelled.** Twenty-four positions, listed in [`LockRank`]. That is
//! **not** every position `06-locking.md` names as something a path can hold,
//! and the earlier version of this sentence said it was. C1's review round 1
//! falsified that by finding *FCB rundown* inside a sentence C1 itself quotes
//! verbatim. `KNOWN_UNMODELLED_POSITIONS_IN_C1` records reviewed examples —
//! FCB rundown, the session/ring/mount-control locks, the namespace lock, the
//! registration rundown — and a test
//! pins each listed entry. It is not an exhaustive document scan.
//!
//! Two distinctions matter and are kept apart:
//!
//! - **The legacy ordinal ordering** applies to §1's five ordered positions.
//!   [`LockRank::in_universal_order`] is the predicate, and it is a positive
//!   match on those five so a position added later cannot join the order by
//!   accident. §1 is explicit that the operation-state lock (§9), the domain
//!   locks (§4) and the per-ring sole-consumer token (§7) are *"outside and
//!   below the five-position order"*.
//!   C4 adds two separately enumerated R2 paths; they never join the legacy
//!   order by ordinal comparison.
//! - **Membership** applies to all twenty-six. This is what §6's no-completion
//!   rule and §1's no-work-under-a-spin-lock rule are stated in terms of.
//!
//! Before slice C1 this set was seven, and the four classes §6's opening
//! sentence forbids completion under — ring token, domain/FCB/CCB lock,
//! notification gate, mount rundown — were unrepresentable, so an empty
//! held-set could not mean what that sentence means. It now can, over those
//! four classes; see [`may_perform`] for what that does and does not certify.

/// A position in the acquisition order.
///
/// Ranks 1–5 are `06-locking.md` §1's five ordered positions, in its order.
/// Ranks 6–7 are the change-notify side, which §1 and §8 give its own nesting:
/// [`LockRank::NotificationState`] → [`LockRank::NotifyCsq`] and nothing else.
/// Their discriminants remain outside 1–5, so an ordinal comparison can never
/// place them between two of the legacy five. Ranks 16–26 are C4's separate R2
/// graph and membership positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LockRank {
    /// Mount-scope admission against DETACH, teardown and ACTIVE publication.
    LifecycleAdmission = 1,
    /// One open (`kernel_open_id`): REPLAY_OPEN, CLEANUP, CLOSE.
    PerOpenLifecycle = 2,
    /// Per-FCB: every allocation, EOF and VDL mutation; the `TRUNCATING` substate.
    SizeGate = 3,
    /// Per-FCB **spin lock**: paging-WRITE issue order, the failure ledger,
    /// the AdvanceOnly FIFOs.
    Sequencer = 4,
    /// The AdvanceOnly `IO_CSQ` **spin lock**, per FCB (§3.5): queue links and
    /// IRP ownership only.
    AdvanceOnlyCsq = 5,
    /// The change-notify side's **push lock**. Outside the five-position order.
    NotificationState = 6,
    /// The change-notify `IO_CSQ` **spin lock** (§5.4: the driver owns every
    /// `IRP_MN_NOTIFY_CHANGE_DIRECTORY(_EX)` IRP in its own `IO_CSQ`), drained
    /// per §8 as a mount queue. A separate queue from [`Self::AdvanceOnlyCsq`],
    /// and modelled separately so a cross-side nesting cannot pass.
    NotifyCsq = 7,
    /// The FCB main resource. `06-locking.md` §1 row 3: the size gate is
    /// *"entered while the FCB main/paging resources are owned"* (§1 row 3's Kind
    /// column). Membership
    /// only — §1's ordinal order does not contain it.
    FcbMain = 8,
    /// The FCB paging resource. The same §1 row 3 sentence as [`Self::FcbMain`],
    /// and the resource `07-cache-mm.md` §10's conditional acquisition names.
    FcbPaging = 9,
    /// The per-request operation-state lock (`06-locking.md` §9). §1: acquired
    /// *"with no session, ring, mount-control, or operation-state lock owned"*
    /// and *"therefore outside and below the five-position order"*.
    OperationState = 10,
    /// An APPLYING domain lock (`06-locking.md` §4), outside the order by the
    /// same §1 bullet. One position for the class: the per-instance layer —
    /// comparator, dedup, and §4.3's six simultaneous holds — is C9's.
    DomainLock = 11,
    /// The per-ring sole-consumer token (`06-locking.md` §7.2). §1 calls it
    /// *"a physical cursor/credit token, not a lock tier"*; §6 forbids
    /// completion under it, which is why it is a member here.
    ///
    /// **One bit for what §7.1 step 3 calls "every per-ring sole-consumer
    /// token"**, acquired in increasing ring-index order and, per step 4, all
    /// retained together. The model cannot express holding two, and a second
    /// acquisition answers [`LockOrderError::AlreadyHeld`]. Recorded here
    /// rather than discovered, as [`Self::DomainLock`] already does for its own
    /// instance layer; both belong to C9.
    SoleConsumerToken = 12,
    /// Mount rundown, named by `06-locking.md` §6's no-completion rule.
    MountRundown = 13,
    /// The stream-admission gate (`06-locking.md` §3.6).
    StreamAdmissionGate = 14,
    /// A CCB lock. `06-locking.md` §6 names *"domain/FCB/CCB lock"* as three
    /// things; the domain and FCB members are above.
    CcbLock = 15,
    /// The permanent session-registry spin lock.
    RegistrySpin = 16,
    /// The affine SQ polling/wait role. It is a no-completion membership guard.
    SqWaitRole = 17,
    /// The global IRP cancel spin lock.
    CancelSpin = 18,
    /// The VPB spin lock.
    VpbSpin = 19,
    /// The synchronous CQ consumer role. It never authorizes a wait.
    CqConsumerToken = 20,
    /// Control-object rundown held while a control operation is admitted.
    ControlRundown = 21,
    /// Exact session-generation access rundown.
    SessionAccessRundown = 22,
    /// Driver-wide SETUP admission rundown.
    SetupAdmissionRundown = 23,
    /// Driver-wide control-context admission rundown.
    ControlContextAdmissionRundown = 24,
    /// The C4 per-ring native spin lock: one ring's slot, its CQ storage, and
    /// the cursor borrowed from it.
    ///
    /// Entered only by a path that already holds one of ENTER's two affine
    /// roles, which is what makes "this ring" answerable at all — a spin lock
    /// taken without a role names a ring nobody is speaking for.
    RingSpin = 25,
    /// The C4 session-wide grant spin lock, guarding the grant table and its
    /// entry array.
    ///
    /// One per session, not one per ring, so two rings claiming credits cannot
    /// form overlapping mutable slices over the same entries. Reachable for an
    /// ENTER only through an already-held [`Self::RingSpin`], which is what
    /// fixes `RingSpin < GrantSpin`.
    GrantSpin = 26,
}

/// Whether a position blocks or is a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// A logical gate. `06-locking.md` §3.1 is explicit that the lifecycle gate
    /// is "a logical admission gate, not a thread-owned blocking resource", and
    /// §2 keeps the size gate across the provider round trip, so a gate does not
    /// by itself forbid waiting.
    Gate,
    /// A thread-owned push lock. Not a leaf in the queue sense, but §6 forbids
    /// allocation, waits, copies and completion under it.
    PushLock,
    /// A spin lock. `06-locking.md` §1: "Spin locks are leaves."
    SpinLock,
}

/// Every rank, for exhaustive iteration and sweeps.
pub const ALL_RANKS: [LockRank; 26] = [
    LockRank::LifecycleAdmission,
    LockRank::PerOpenLifecycle,
    LockRank::SizeGate,
    LockRank::Sequencer,
    LockRank::AdvanceOnlyCsq,
    LockRank::NotificationState,
    LockRank::NotifyCsq,
    LockRank::FcbMain,
    LockRank::FcbPaging,
    LockRank::OperationState,
    LockRank::DomainLock,
    LockRank::SoleConsumerToken,
    LockRank::MountRundown,
    LockRank::StreamAdmissionGate,
    LockRank::CcbLock,
    LockRank::RegistrySpin,
    LockRank::SqWaitRole,
    LockRank::CancelSpin,
    LockRank::VpbSpin,
    LockRank::CqConsumerToken,
    LockRank::ControlRundown,
    LockRank::SessionAccessRundown,
    LockRank::SetupAdmissionRundown,
    LockRank::ControlContextAdmissionRundown,
    LockRank::RingSpin,
    LockRank::GrantSpin,
];

impl LockRank {
    /// The document's kind for this position.
    ///
    /// The membership positions added by C1 are `Gate` because none of them is
    /// a spin lock or the change-notify push lock, which are the two kinds the
    /// rules key off. Calling them gates does not claim they are logical rather
    /// than blocking — `FcbMain`/`FcbPaging` are ERESOURCEs — only that they do
    /// not trip the leaf rule.
    pub const fn kind(self) -> LockKind {
        match self {
            Self::Sequencer
            | Self::AdvanceOnlyCsq
            | Self::NotifyCsq
            | Self::RegistrySpin
            | Self::CancelSpin
            | Self::VpbSpin
            | Self::RingSpin
            | Self::GrantSpin => LockKind::SpinLock,
            Self::NotificationState => LockKind::PushLock,
            Self::LifecycleAdmission
            | Self::PerOpenLifecycle
            | Self::SizeGate
            | Self::FcbMain
            | Self::FcbPaging
            | Self::OperationState
            | Self::DomainLock
            | Self::SoleConsumerToken
            | Self::MountRundown
            | Self::StreamAdmissionGate
            | Self::CcbLock
            | Self::SqWaitRole
            | Self::CqConsumerToken
            | Self::ControlRundown
            | Self::SessionAccessRundown
            | Self::SetupAdmissionRundown
            | Self::ControlContextAdmissionRundown => LockKind::Gate,
        }
    }

    /// True for the five positions that participate in the ordinal order.
    ///
    /// Stated as a positive match on the five, not as *"everything except the
    /// change-notify pair"*. Under the negative form every position added later
    /// would join the ordinal order silently, which is the opposite of what
    /// `06-locking.md` §1's last two bullets say about them: the operation-state
    /// lock, the domain locks and the sole-consumer token are *"outside and
    /// below the five-position order"*.
    pub const fn in_universal_order(self) -> bool {
        matches!(
            self,
            Self::LifecycleAdmission
                | Self::PerOpenLifecycle
                | Self::SizeGate
                | Self::Sequencer
                | Self::AdvanceOnlyCsq
        )
    }

    /// This rank's bit in a [`HeldLocks`] set.
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32).saturating_sub(1)
    }
}

/// Bits of the five positions that participate in the ordinal order.
/// Derived from the ranks rather than written as a literal, so adding a rank
/// cannot leave a stale mask behind.
const UNIVERSAL_MASK: u32 = LockRank::LifecycleAdmission.bit()
    | LockRank::PerOpenLifecycle.bit()
    | LockRank::SizeGate.bit()
    | LockRank::Sequencer.bit()
    | LockRank::AdvanceOnlyCsq.bit();

/// Bits of every position whose [`LockKind`] is [`LockKind::SpinLock`].
///
/// Folded over [`ALL_RANKS`] through `kind()`, so a position cannot be a spin
/// lock for the kind census and not a spin lock for the leaf rule.
const SPIN_LOCK_MASK: u32 = {
    let mut bits = 0u32;
    let mut i = 0;
    while i < ALL_RANKS.len() {
        // PROOF: `i < ALL_RANKS.len()` is the loop condition immediately above,
        // so the index is in range on every iteration; `<[T]>::get` is not
        // const, which is why this is an index.
        #[allow(clippy::indexing_slicing)]
        let rank = ALL_RANKS[i];
        if matches!(rank.kind(), LockKind::SpinLock) {
            bits |= rank.bit();
        }
        i += 1;
    }
    bits
};

/// Every representable bit.
///
/// Folded over [`ALL_RANKS`] rather than written as a union of named ranks: the
/// hand-written form had to be edited every time a rank was added, and a rank
/// left out of it would be silently unrepresentable — [`HeldLocks::from_bits`]
/// masks with this constant, so the missing rank's bit would be dropped rather
/// than rejected.
const ALL_BITS: u32 = {
    let mut bits = 0u32;
    let mut i = 0;
    while i < ALL_RANKS.len() {
        // PROOF: `i < ALL_RANKS.len()` is the loop condition immediately above,
        // so the index is in range on every iteration. `<[T]>::get` is not
        // available in a const context, which is why this is an index rather
        // than a checked access.
        #[allow(clippy::indexing_slicing)]
        let bit = ALL_RANKS[i].bit();
        bits |= bit;
        // PROOF: `i` is bounded by `ALL_RANKS.len()` = 24, so this cannot
        // overflow a `usize`.
        #[allow(clippy::arithmetic_side_effects)]
        {
            i += 1;
        }
    }
    bits
};

/// The set of locks a path currently owns. `Copy`, allocation-free.
///
/// `u32` rather than `u8`: the legacy model already exceeded eight positions,
/// and C4's nine R2 positions bring the closed roster to twenty-four.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeldLocks(u32);

impl HeldLocks {
    /// Own nothing.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Record `rank` as held. Does not check legality — [`may_acquire`] does.
    pub const fn acquire(self, rank: LockRank) -> Self {
        Self(self.0 | rank.bit())
    }

    /// Record `rank` as released.
    pub const fn release(self, rank: LockRank) -> Self {
        Self(self.0 & !rank.bit())
    }

    /// Is `rank` held?
    pub const fn holds(self, rank: LockRank) -> bool {
        self.0 & rank.bit() != 0
    }

    /// Is none of the modelled positions held?
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Is any spin lock held? `06-locking.md` §1's leaf rule keys off this.
    pub const fn holds_any_spin_lock(self) -> bool {
        // Folded from `kind()` rather than enumerated by name. The
        // hand-written form named six ranks and did not grow when Task 20
        // added the C4 ring and grant spin locks, so the leaf rule and the
        // no-work rule -- both stated over "a spin lock is held" -- would have
        // stopped seeing the two newest spin locks while every existing test
        // stayed green. `kind()` is the one place a position's kind is
        // decided; this reads it.
        self.bits() & SPIN_LOCK_MASK != 0
    }

    /// Is the change-notify push lock held? §6 forbids work under it.
    pub const fn holds_push_lock(self) -> bool {
        self.holds(LockRank::NotificationState)
    }

    /// The raw bits, for exhaustive test enumeration.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Reconstruct from raw bits, for exhaustive test enumeration. Bits outside
    /// the modelled ranks are dropped.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & ALL_BITS)
    }
}

/// Something a path may want to do while holding locks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Block on anything.
    Wait,
    /// Allocate or free kernel storage.
    Allocate,
    /// Map memory, or copy to or from a user buffer.
    MapMemory,
    /// Call the daemon across the ring.
    CallProvider,
    /// `IoCompleteRequest`.
    CompleteIrp,
}

/// Every action, for exhaustive iteration.
pub const ALL_ACTIONS: [Action; 5] = [
    Action::Wait,
    Action::Allocate,
    Action::MapMemory,
    Action::CallProvider,
    Action::CompleteIrp,
];

/// Which rule a request broke. Named after the rule, not the symptom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockOrderError {
    /// The rank is already held; re-acquisition is not modelled as legal.
    AlreadyHeld,
    /// A later position is held, so this earlier one may not be taken.
    /// "No path acquires any earlier lock from the sequencer."
    OutOfOrder,
    /// A spin lock is held and this acquisition is not the one fixed nesting
    /// out of it. "Spin locks are leaves."
    SpinLockNotLeaf,
    /// The change-notify push lock is held and this is not [`LockRank::NotifyCsq`].
    /// §1: notification state → CSQ is "the only nested queue order on that side".
    PushLockNesting,
    /// The reverse of a fixed nesting: a CSQ taking the lock that may nest into
    /// it. "No path takes the reverse order."
    ReversedNesting,
    /// A wait, allocation, mapping, copy or provider call under a spin lock or
    /// the change-notify push lock.
    ActionUnderLock,
    /// `IoCompleteRequest` with a modelled position held (§6).
    CompletionUnderLock,
    /// A wait for an admission resource, or an allocation, while the logical
    /// size gate is owned. `06-locking.md` §2 corollary 2: *"no size path waits
    /// for an application slot, ApplyReserve, allocation, grant, or other
    /// admission resource while it owns the logical gate."* Corollary 1's
    /// provider round trip under that same gate is legal and is not this error.
    AdmissionUnderSizeGate,
    /// An allocation while the sequencer is held. `07-cache-mm.md` §6: the
    /// ledger *"never allocates while the sequencer lock is held"*. More
    /// specific than [`Self::ActionUnderLock`], which the sequencer would also
    /// trip as a spin lock.
    AllocationUnderSequencer,
    /// A synchronous wait while the thread's top-level context is the FSRTL
    /// cache sentinel. `07-cache-mm.md` §4: *"a second synchronous wait on that
    /// same thread, stacked under the first, is a self-deadlock, not merely
    /// slow."* Depends on the thread, not on the held set.
    SyncWaitUnderCacheSentinel,
    /// A rundown drain while the per-open lifecycle gate is owned.
    /// `06-locking.md` §3.2: *"The lifecycle gate is released while any
    /// predecessor waits; a retained count plus per-operation references, not a
    /// held gate or a table scan, detects the zero transition."*
    ///
    /// **Deliberately narrow.** The sentence describes the predecessor drain,
    /// which waits on operation rundown, and that is the only wait target this
    /// rule covers. §2's opening — a waiting thread owns *"no gate that a
    /// completion, fence, or rundown path can require"* — reads wider, but §2
    /// corollary 1 then keeps the **size** gate held across a provider round
    /// trip on purpose, so "every wait under every gate" is not what the
    /// document says. Whether a provider round trip under the *per-open* gate is
    /// legal is not settled by either sentence, and C1 does not decide it.
    DrainUnderLifecycleGate,
    /// Blocking work, an access check, or a notification callback while the
    /// per-ring sole-consumer token is held. `06-locking.md` §7.2: *"It is never
    /// held while acquiring an FCB/CCB/namespace/domain lock, running an access
    /// check or notification callback, waiting for SQ, or completing an IRP."*
    /// §7.1 states the same rule for the fence walk.
    WorkUnderSoleConsumerToken,
    /// A lock acquisition while the sole-consumer token is held. Same two
    /// sentences; §1 bullet 5 adds *"nothing blocking is ever acquired under
    /// it"*.
    AcquisitionUnderSoleConsumerToken,
    /// The C4 R2 graph contains no edge between the requested positions.
    UnlistedR2Nesting,
    /// A lifecycle event wait retained a rundown, role, or C4 spin guard.
    LifecycleWaitUnderGuard,
    /// The CQ consumer role is synchronous and grants no wait authority.
    WaitUnderNoWaitRole,
}

const R2_POSITION_MASK: u32 = LockRank::RegistrySpin.bit()
    | LockRank::SqWaitRole.bit()
    | LockRank::CancelSpin.bit()
    | LockRank::VpbSpin.bit()
    | LockRank::CqConsumerToken.bit()
    | LockRank::ControlRundown.bit()
    | LockRank::SessionAccessRundown.bit()
    | LockRank::SetupAdmissionRundown.bit()
    | LockRank::ControlContextAdmissionRundown.bit()
    | LockRank::RingSpin.bit()
    | LockRank::GrantSpin.bit();

const R2_SQ_PREFIX_MASK: u32 =
    LockRank::RegistrySpin.bit() | LockRank::SqWaitRole.bit() | LockRank::CancelSpin.bit();
const R2_CQ_PREFIX_MASK: u32 = LockRank::RegistrySpin.bit() | LockRank::CqConsumerToken.bit();

/// The two affine ENTER roles. `R` in the C4 ring/grant graph is a nonempty
/// subset of exactly this set: `{SqWait}` for a poll or wait, `{CqConsumer}`
/// for a synchronous CQ-only drain, or both for an authenticated readiness
/// resume.
const R2_ENTER_ROLE_MASK: u32 = LockRank::SqWaitRole.bit() | LockRank::CqConsumerToken.bit();
/// `R` plus the per-ring spin lock.
///
/// The registry spin lock is deliberately **not** here. The C4 ENTER path reads
/// the locator under the registry lock and drops it before touching a ring, so
/// admitting it would model a three-deep spin nest the driver does not perform
/// and the plan does not list.
const R2_C4_RING_PREFIX_MASK: u32 = R2_ENTER_ROLE_MASK | LockRank::RingSpin.bit();
/// The same, once the grant lock is nested inside it.
const R2_C4_GRANT_PREFIX_MASK: u32 = R2_C4_RING_PREFIX_MASK | LockRank::GrantSpin.bit();
const R2_RUNDOWN_MASK: u32 = LockRank::ControlRundown.bit()
    | LockRank::SessionAccessRundown.bit()
    | LockRank::SetupAdmissionRundown.bit()
    | LockRank::ControlContextAdmissionRundown.bit();

const fn is_r2_position(rank: LockRank) -> bool {
    rank.bit() & R2_POSITION_MASK != 0
}

const fn r2_acquisition_allowed(held: HeldLocks, next: LockRank) -> bool {
    let bits = held.bits();
    if bits & !R2_POSITION_MASK != 0 || bits & R2_RUNDOWN_MASK != 0 {
        return false;
    }
    match next {
        LockRank::RegistrySpin => bits == 0,
        LockRank::SqWaitRole => bits & !LockRank::RegistrySpin.bit() == 0,
        LockRank::CancelSpin => {
            // Task 5's CSQ edge, unchanged: the SQ prefix alone reaches Cancel.
            bits & !R2_SQ_PREFIX_MASK == 0
                // C4 adds Cancel under the ring lock, with or without the grant
                // lock nested in it. The `RingSpin` conjunct is not redundant
                // with the mask: it states that a grant-only hold can never
                // reach Cancel, rather than leaving that to the fact that
                // `GrantSpin` happens to be unreachable without `RingSpin`.
                // The role conjunct is not decoration. A held set of the ring
                // lock ALONE is unreachable through legal acquisitions, but a
                // rule that answers Ok for an unreachable state is a rule that
                // stops being a check the moment the state becomes reachable.
                || (bits & R2_ENTER_ROLE_MASK != 0
                    && bits & LockRank::RingSpin.bit() != 0
                    && bits & !R2_C4_GRANT_PREFIX_MASK == 0)
        }
        // Widened for C4: the authenticated readiness resume holds the SQ lease
        // and derives a CQ token for the same request, so the pairing the
        // authority model already produces has to be expressible here.
        LockRank::CqConsumerToken => {
            bits & !(LockRank::RegistrySpin.bit() | LockRank::SqWaitRole.bit()) == 0
        }
        // A ring spin lock without a role names a ring nobody is speaking for,
        // so the held set must be a NONEMPTY subset of the two roles -- exactly
        // the plan's `R`.
        LockRank::RingSpin => bits != 0 && bits & !R2_ENTER_ROLE_MASK == 0,
        // `RingSpin < GrantSpin` is the whole point: the only ENTER route to the
        // session-wide grant lock is through the exact ring's guard.
        LockRank::GrantSpin => {
            bits & R2_ENTER_ROLE_MASK != 0
                && bits & LockRank::RingSpin.bit() != 0
                && bits & !R2_C4_RING_PREFIX_MASK == 0
        }
        LockRank::VpbSpin => bits & !R2_SQ_PREFIX_MASK == 0 || bits & !R2_CQ_PREFIX_MASK == 0,
        LockRank::ControlRundown
        | LockRank::SessionAccessRundown
        | LockRank::SetupAdmissionRundown
        | LockRank::ControlContextAdmissionRundown => bits == 0,
        LockRank::LifecycleAdmission
        | LockRank::PerOpenLifecycle
        | LockRank::SizeGate
        | LockRank::Sequencer
        | LockRank::AdvanceOnlyCsq
        | LockRank::NotificationState
        | LockRank::NotifyCsq
        | LockRank::FcbMain
        | LockRank::FcbPaging
        | LockRank::OperationState
        | LockRank::DomainLock
        | LockRank::SoleConsumerToken
        | LockRank::MountRundown
        | LockRank::StreamAdmissionGate
        | LockRank::CcbLock => false,
    }
}

/// May a path holding `held` acquire `next`?
///
/// The rules, in the order they are checked, so the error names the *first*
/// rule broken:
///
/// 1. already held → [`LockOrderError::AlreadyHeld`];
/// 2. a spin lock is held → the only legal acquisition is
///    `Sequencer -> AdvanceOnlyCsq`; taking the lock that nests *into* a held
///    CSQ is [`LockOrderError::ReversedNesting`], anything else is
///    [`LockOrderError::SpinLockNotLeaf`];
/// 3. the change-notify push lock is held → the only legal acquisition is
///    [`LockRank::NotifyCsq`] (§1's "only nested queue order on that side");
///    anything else is [`LockOrderError::PushLockNesting`];
/// 4. `next` is in the universal order and some held position in that order is
///    at or after it → [`LockOrderError::OutOfOrder`];
/// 5. otherwise legal.
pub const fn may_acquire(held: HeldLocks, next: LockRank) -> Result<(), LockOrderError> {
    if held.holds(next) {
        return Err(LockOrderError::AlreadyHeld);
    }

    if held.bits() & R2_POSITION_MASK != 0 || is_r2_position(next) {
        return if r2_acquisition_allowed(held, next) {
            Ok(())
        } else {
            Err(LockOrderError::UnlistedR2Nesting)
        };
    }

    // Rule 1b: the four lock classes §7 names are not acquired under the
    // sole-consumer token.
    //
    // **Exactly those four, and review round 2 is why.** The first version of
    // this rule refused EVERY rank under the token, reading §1 bullet 5's
    // "nothing blocking is ever acquired under it" as a blanket. That makes
    // §7.1 step 4 unimplementable: the token owner "retains all tokens while
    // it ... [assigns each stable completion its] preallocated semantic
    // terminal owner **under the normal state gate**". Refusing
    // `OperationState` under the token forbids the sequence the document
    // requires. §7.1 and §7.2 enumerate what is forbidden — domain, FCB, CCB
    // and namespace locks — and this rule is that enumeration, not a
    // generalization of it.
    //
    // Checked before the spin-lock rule, and the order is a decision: §7.2's
    // rule is categorical for the ranks it names, while §1's leaf rule carries
    // a documented exception (the sequencer's own CSQ). `oracle_acquire`
    // states the same order independently.
    if held.holds(LockRank::SoleConsumerToken)
        && matches!(
            next,
            LockRank::DomainLock | LockRank::FcbMain | LockRank::FcbPaging | LockRank::CcbLock
        )
    {
        return Err(LockOrderError::AcquisitionUnderSoleConsumerToken);
    }

    // Rule 2: spin locks are leaves, with one fixed nesting out of the sequencer.
    if held.holds_any_spin_lock() {
        if held.holds(LockRank::AdvanceOnlyCsq) || held.holds(LockRank::NotifyCsq) {
            // A CSQ is a terminal leaf. Naming the two reverses specifically
            // makes the diagnostic point at the rule the caller inverted.
            return match next {
                LockRank::Sequencer | LockRank::NotificationState => {
                    Err(LockOrderError::ReversedNesting)
                }
                _ => Err(LockOrderError::SpinLockNotLeaf),
            };
        }
        // Holding the sequencer, the only legal acquisition is its own CSQ.
        return match next {
            LockRank::AdvanceOnlyCsq => Ok(()),
            _ => Err(LockOrderError::SpinLockNotLeaf),
        };
    }

    // Rule 3: the change-notify side nests exactly one way.
    if held.holds_push_lock() {
        return match next {
            LockRank::NotifyCsq => Ok(()),
            _ => Err(LockOrderError::PushLockNesting),
        };
    }

    // Rule 4: within the five-position order, acquisitions strictly ascend.
    //
    // Expressed as one bitmask test rather than a loop over `ALL_RANKS`:
    // indexing an array is denied crate-wide, and `<[T]>::get` is not const. The
    // held-set's bit k is rank k+1, so clearing the low `next-1` bits of the
    // universal mask leaves exactly the positions at or after `next`. The
    // exhaustive sweep validates this form against an oracle that does iterate.
    if next.in_universal_order() {
        let shift = (next as u8).saturating_sub(1);
        let at_or_after = (UNIVERSAL_MASK >> shift) << shift;
        if held.bits() & at_or_after != 0 {
            return Err(LockOrderError::OutOfOrder);
        }
    }

    Ok(())
}

/// May a path holding `held` perform `action`?
///
/// `06-locking.md` §1: no spin lock is retained across a wait, an allocation, a
/// mapping, a provider call, or an IRP completion. §6 adds the change-notify
/// side: *"privilege and access checks, allocation and free, waits, user-buffer
/// copies, and `IoCompleteRequest` occur under neither the notification-state
/// push lock nor the CSQ spin lock."* So the four working actions are forbidden
/// under a spin lock **or** the push lock.
///
/// Completion is stricter still: §6 forbids `IoCompleteRequest` under a ring
/// token, domain/FCB/CCB lock, notification gate or mount rundown, so it
/// requires an empty held-set.
///
/// **This rule is deliberately permissive elsewhere, and C1 refined it.** With
/// only a logical gate held it returns `Ok` for every working action, which
/// `06-locking.md` §2 corollary 2 and `07-cache-mm.md` §6 both contradict for
/// specific targets. Expressing that needs the target, which [`Action`] does not
/// carry — see [`crate::effect::may_emit`].
///
/// **What an empty set now means, and what it does not.** Through B5 this doc
/// said to read the completion verdict narrowly, because the ring token, the
/// domain locks, the operation-state lock and mount rundown were outside the
/// seven modelled positions. Slice C1 models the four classes named in §6's
/// **opening sentence**, so an empty [`HeldLocks`] is a certificate over ring
/// token, domain/FCB/CCB lock, notification gate and mount rundown.
///
/// It is **not** a certificate over all of §6. That section's per-subsystem
/// bullets name further things a completing path must have released — detached
/// rundown, `cq_enter_owner`, ring/session/mount rundown, the embedded work
/// owner — and C1 models only mount rundown among them. The verdict is bounded
/// to the opening sentence's four classes, which is what it is named for.
///
/// It is still not a certificate that the *call site* passed a truthful context.
/// The checker proves refusal given a context; C1's guards make the context
/// structural rather than asserted, but a call site outside `fsring-core` can
/// still hand over a set that does not describe what it holds.
///
/// **Superseded for new code.** This function is B1's rule over B1's
/// five-variant [`Action`]. Production code calls [`crate::effect::may_emit`],
/// which takes the effect's target and the thread's top-level context and so can
/// state the rules this signature cannot. `may_perform` is retained because
/// nothing about it became wrong — only incomplete.
pub const fn may_perform(held: HeldLocks, action: Action) -> Result<(), LockOrderError> {
    match action {
        Action::CompleteIrp => {
            if held.is_empty() {
                Ok(())
            } else {
                Err(LockOrderError::CompletionUnderLock)
            }
        }
        Action::Wait | Action::Allocate | Action::MapMemory | Action::CallProvider => {
            if held.holds_any_spin_lock() || held.holds_push_lock() {
                Err(LockOrderError::ActionUnderLock)
            } else {
                Ok(())
            }
        }
    }
}

/// [`ALL_BITS`], for the effect module's exhaustive sweep.
#[cfg(test)]
pub const ALL_BITS_FOR_TEST: u32 = ALL_BITS;

/// A bounded but structurally broad held-set corpus for host sweeps. The C1
/// domain remains exhaustive; the R2 domain includes every subset plus every
/// legacy/R2 cross-family pair without turning tests into a 2^24 walk.
#[cfg(test)]
pub fn held_sets_for_test() -> std::vec::Vec<HeldLocks> {
    let mut sets = std::vec::Vec::new();
    for bits in 0..(1u32 << 15) {
        sets.push(HeldLocks::from_bits(bits));
    }
    for subset in 0..(1u32 << 11) {
        sets.push(HeldLocks::from_bits(subset << 15));
    }
    for legacy in ALL_RANKS.iter().copied().take(15) {
        for r2 in ALL_RANKS.iter().copied().skip(15) {
            sets.push(HeldLocks::none().acquire(legacy).acquire(r2));
        }
    }
    sets.sort_by_key(|held| held.bits());
    sets.dedup_by_key(|held| held.bits());
    sets
}

/// B1's rule, restated over C1's effect vocabulary and nothing else.
///
/// This exists so [`crate::effect::may_emit`] can be compared against the rule
/// it refines, cell by cell, and every divergence made to name a sentence. It
/// is `#[cfg(test)]`: production code calls `may_emit`.
///
/// Deliberately a transcription of [`may_perform`]'s two arms rather than a call
/// to it — `may_perform` takes an [`Action`], and mapping `Effect` onto `Action`
/// to reuse it would put the mapping inside the thing being compared.
#[cfg(test)]
pub fn may_perform_legacy_shape(
    held: HeldLocks,
    effect: crate::effect::Effect,
) -> Result<(), LockOrderError> {
    if matches!(effect, crate::effect::Effect::CompleteIrp) {
        return if held.is_empty() {
            Ok(())
        } else {
            Err(LockOrderError::CompletionUnderLock)
        };
    }
    if held.holds_any_spin_lock() || held.holds_push_lock() {
        Err(LockOrderError::ActionUnderLock)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use LockRank::{
        AdvanceOnlyCsq, LifecycleAdmission, NotificationState, NotifyCsq, PerOpenLifecycle,
        Sequencer, SizeGate,
    };

    fn is_r2(rank: LockRank) -> bool {
        matches!(
            rank,
            LockRank::RegistrySpin
                | LockRank::SqWaitRole
                | LockRank::CancelSpin
                | LockRank::VpbSpin
                | LockRank::CqConsumerToken
                | LockRank::ControlRundown
                | LockRank::SessionAccessRundown
                | LockRank::SetupAdmissionRundown
                | LockRank::ControlContextAdmissionRundown
                | LockRank::RingSpin
                | LockRank::GrantSpin
        )
    }

    fn oracle_r2_acquire(held: HeldLocks, next: LockRank) -> bool {
        crate::effect::oracles::r2_acquisition_is_listed(held, next)
    }

    /// The expected verdict, derived from `06-locking.md`'s RULES rather than
    /// from [`may_acquire`].
    ///
    /// Deliberately a different shape: the implementation short-circuits with
    /// early returns and decides the ordinal rule with a bitmask, this states
    /// each rule as an independent predicate and iterates. **The sweep proves
    /// agreement between two restatements, not correctness** — both read the
    /// same discriminants and the same `bit()`, so a wrong idea about the
    /// document reaches both. The named cases below, each carrying the sentence
    /// it enforces, are what check the content.
    fn oracle_acquire(held: HeldLocks, next: LockRank) -> Result<(), LockOrderError> {
        if held.holds(next) {
            return Err(LockOrderError::AlreadyHeld);
        }
        let holds_r2 = ALL_RANKS
            .iter()
            .copied()
            .any(|rank| is_r2(rank) && held.holds(rank));
        if holds_r2 || is_r2(next) {
            return if oracle_r2_acquire(held, next) {
                Ok(())
            } else {
                Err(LockOrderError::UnlistedR2Nesting)
            };
        }
        let holds_a_csq = held.holds(AdvanceOnlyCsq) || held.holds(NotifyCsq);
        let holds_seq = held.holds(Sequencer);
        let reversing = holds_a_csq && matches!(next, Sequencer | NotificationState);
        let sequencer_to_own_csq = holds_seq && !holds_a_csq && next == AdvanceOnlyCsq;
        let under_spin = holds_a_csq || holds_seq;
        let ascends = !ALL_RANKS.iter().any(|r| {
            r.in_universal_order()
                && held.holds(*r)
                && next.in_universal_order()
                && (*r as u8) >= (next as u8)
        });

        // 06 §7.1 / §7.2 name four lock classes, not every rank. See
        // `may_acquire`'s rule 1b for why this is an enumeration.
        let under_token = held.holds(LockRank::SoleConsumerToken)
            && matches!(
                next,
                LockRank::DomainLock | LockRank::FcbMain | LockRank::FcbPaging | LockRank::CcbLock
            );

        if under_token {
            Err(LockOrderError::AcquisitionUnderSoleConsumerToken)
        } else if reversing {
            Err(LockOrderError::ReversedNesting)
        } else if under_spin && !sequencer_to_own_csq {
            Err(LockOrderError::SpinLockNotLeaf)
        } else if under_spin {
            Ok(())
        } else if held.holds_push_lock() && next != NotifyCsq {
            Err(LockOrderError::PushLockNesting)
        } else if !ascends {
            Err(LockOrderError::OutOfOrder)
        } else {
            Ok(())
        }
    }

    /// Same idea for actions: §1's sentence plus §6's change-notify bullet.
    fn oracle_perform(held: HeldLocks, action: Action) -> Result<(), LockOrderError> {
        let completing = action == Action::CompleteIrp;
        if completing && !held.is_empty() {
            Err(LockOrderError::CompletionUnderLock)
        } else if !completing && (held.holds_any_spin_lock() || held.holds_push_lock()) {
            Err(LockOrderError::ActionUnderLock)
        } else {
            Ok(())
        }
    }

    /// `06-locking.md` §1's last two bullets put the operation-state lock, the
    /// domain locks and the sole-consumer token *"outside and below the
    /// five-position order"*. A membership position must therefore never
    /// produce an ordinal verdict, from any held set.
    ///
    /// This is not covered by `acquisition_is_exhaustively_correct`: that sweep
    /// compares [`may_acquire`] against `oracle_acquire`, and both read
    /// `in_universal_order`, so a wrong idea about which positions are ordered
    /// reaches both and the sweep stays green. This test states the property
    /// directly instead of comparing two restatements of it.
    #[test]
    fn membership_positions_never_produce_an_ordinal_verdict() {
        let membership: Vec<LockRank> = ALL_RANKS
            .iter()
            .copied()
            .filter(|r| !r.in_universal_order())
            .collect();
        assert_eq!(
            membership.len(),
            21,
            "expected the change-notify pair, C1's eight, and C4's ring/grant              spin locks; got {membership:?}"
        );
        for position in membership {
            for held in held_sets_for_test() {
                // No `continue` for an already-held position: `may_acquire`
                // answers `AlreadyHeld` there, which is not `OutOfOrder`, so the
                // assertion below holds either way. The C1 sweep showed a
                // `continue` here could be removed with nothing noticing, which
                // is what a branch that changes no outcome looks like.
                assert_ne!(
                    may_acquire(held, position),
                    Err(LockOrderError::OutOfOrder),
                    "{position:?} is outside §1's order and must never be OutOfOrder, \
                     but {held:?} produced it"
                );
            }
        }
    }

    /// Every position's [`LockKind`] classification, checked.
    ///
    /// The C1 mutation sweep found this unwatched: eight `kind()` or-pattern
    /// alternatives could be moved to a sibling arm with nothing noticing.
    /// It is not cosmetic — [`crate::effect::Guard::dispatch_token`] mints a
    /// `DISPATCH_LEVEL` capability for exactly the positions `kind()` calls
    /// `SpinLock`, so a misclassified `FcbMain` would hand out a token
    /// asserting an IRQL an ERESOURCE never raises.
    ///
    /// The five ordered positions are read from `06-locking.md` §1's table
    /// rather than restated: its Kind column says "spin lock" for rows 4 and 5
    /// and "gate" for rows 1-3.
    #[test]
    fn every_position_carries_the_kind_the_document_gives_it() {
        // §1's table, parsed: (order, kind-cell).
        let mut rows: Vec<(u8, &str)> = Vec::new();
        for line in crate::effect::oracles::LOCK_DOC.lines() {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let (Some(order_cell), Some(kind_cell)) = (cells.get(1), cells.get(3)) else {
                continue;
            };
            // No length guard: `cells.get(3)` above already rejects a row too
            // short to have a Kind column, and `assert_eq!(rows.len(), 5)`
            // below is what catches structural drift in the table. The C1
            // sweep showed a `cells.len() <= 4` check here could be disabled
            // with nothing noticing -- dead against this document, and the
            // assertion is the guard that actually has a signal.
            let Ok(order) = order_cell.parse::<u8>() else {
                continue;
            };
            if (1..=5).contains(&order) {
                rows.push((order, *kind_cell));
            }
        }
        assert_eq!(
            rows.len(),
            5,
            "§1's table must still have five rows: {rows:?}"
        );
        let ordered = [
            LifecycleAdmission,
            PerOpenLifecycle,
            SizeGate,
            Sequencer,
            AdvanceOnlyCsq,
        ];
        for (order, kind_cell) in rows {
            let Some(rank) = ordered.get(usize::from(order).saturating_sub(1)) else {
                panic!("row {order} has no modelled rank")
            };
            let expected = if kind_cell.contains("spin lock") {
                LockKind::SpinLock
            } else {
                LockKind::Gate
            };
            assert_eq!(
                rank.kind(),
                expected,
                "§1 row {order} calls {rank:?} a {kind_cell:?}"
            );
        }

        // The remaining nineteen, each with the rule behind its classification.
        // `SpinLock` and `PushLock` are the two kinds the rules key off, so
        // these are the classifications that decide whether the leaf rule and
        // the DISPATCH minting point apply.
        assert_eq!(NotificationState.kind(), LockKind::PushLock);
        assert_eq!(NotifyCsq.kind(), LockKind::SpinLock);
        for rank in [
            LockRank::FcbMain,
            LockRank::FcbPaging,
            LockRank::OperationState,
            LockRank::DomainLock,
            LockRank::SoleConsumerToken,
            LockRank::MountRundown,
            LockRank::StreamAdmissionGate,
            LockRank::CcbLock,
            LockRank::SqWaitRole,
            LockRank::CqConsumerToken,
            LockRank::ControlRundown,
            LockRank::SessionAccessRundown,
            LockRank::SetupAdmissionRundown,
            LockRank::ControlContextAdmissionRundown,
        ] {
            assert_eq!(
                rank.kind(),
                LockKind::Gate,
                "{rank:?} is neither a spin lock nor the change-notify push \
                 lock, so it must not trip the leaf rule or mint DISPATCH"
            );
        }

        // Exactly six spin locks, exactly one push lock, over the whole set.
        let spin = ALL_RANKS
            .iter()
            .filter(|r| matches!(r.kind(), LockKind::SpinLock))
            .count();
        let push = ALL_RANKS
            .iter()
            .filter(|r| matches!(r.kind(), LockKind::PushLock))
            .count();
        assert_eq!(
            (spin, push),
            (8, 1),
            "the kind census changed -- C4 adds the ring and grant spin locks",
        );
    }

    /// Is `name` the `Debug` name of a modelled position?
    ///
    /// Round 2 replaced a morphological guess with this: each uncovered entry
    /// states the identifier a future slice would add, and the check is a plain
    /// name comparison. The guess could not match any multi-word phrase, which
    /// made those entries' assertions unconditionally true — the shape of a
    /// guard that cannot see what it guards.
    fn is_modelled_name(name: &str) -> bool {
        ALL_RANKS.iter().any(|r| format!("{r:?}") == name)
    }

    /// The check above must answer `true` for names that ARE modelled, or the
    /// curated known-unmodelled list would pass whatever it contained.
    #[test]
    fn the_unmodelled_check_can_see_a_modelled_position() {
        for modelled in [
            "MountRundown",
            "SoleConsumerToken",
            "FcbMain",
            "FcbPaging",
            "CancelSpin",
        ] {
            assert!(is_modelled_name(modelled), "{modelled} is a LockRank");
        }
        for absent in [
            "FcbRundown",
            "NamespaceLock",
            "SessionLock",
            "RegistrationRundown",
        ] {
            assert!(!is_modelled_name(absent), "{absent} is not a LockRank");
        }
    }

    /// Each known-unmodelled position listed by C1 is still unmodelled.
    ///
    /// Both directions for the curated list: each phrase must still occur in
    /// the document, and none of the identifiers that would model it may exist
    /// — so modelling one without removing its entry fails here. A document
    /// position nobody added to the list remains review-bound.
    #[test]
    fn every_listed_unmodelled_position_is_still_unmodelled() {
        use crate::effect::oracles::{KNOWN_UNMODELLED_POSITIONS_IN_C1 as UNCOVERED, LOCK_DOC};
        for entry in UNCOVERED {
            assert!(
                LOCK_DOC.contains(entry.phrase),
                "06-locking.md no longer contains {:?}; the known-unmodelled                  entry is stale ({})",
                entry.phrase,
                entry.why
            );
            assert!(
                !entry.would_be_named.is_empty(),
                "{:?} names no identifier, so its assertion would be vacuous",
                entry.phrase
            );
            for name in entry.would_be_named {
                assert!(
                    !is_modelled_name(name),
                    "{:?} is listed as unmodelled but {name} is a LockRank;                      model it and remove the entry, or the boundary lies",
                    entry.phrase
                );
            }
        }
    }

    /// Anti-vacuity for the curated roster: every phrase already transcribed by
    /// the oracle must still occur in the document. This detects stale entries;
    /// it does not discover a phrase nobody added to the corpus.
    #[test]
    fn every_named_position_string_occurs_in_the_document() {
        use crate::effect::oracles::{LOCK_DOC, curated_positions_from_06};
        let named = curated_positions_from_06();
        assert!(
            named.len() >= 14,
            "the roster collapsed to {} entries",
            named.len()
        );
        for phrase in named {
            assert!(
                LOCK_DOC.contains(phrase),
                "06-locking.md no longer contains {phrase:?}; the roster is stale"
            );
        }
    }

    /// Every position in the **curated roster** maps to a `LockRank`.
    ///
    /// **Not "every position `06-locking.md` names"** — that sentence is the
    /// totality claim round 1 falsified with FCB rundown, and round 3 found it
    /// restated here verbatim on a test that only walks the fourteen phrases
    /// the roster carries. `KNOWN_UNMODELLED_POSITIONS_IN_C1` records and pins
    /// reviewed examples outside that roster, but is not exhaustive. This test
    /// checks only that nothing in the curated roster is unmapped.
    ///
    /// The mapping from a document phrase to the modelled positions it names is
    /// stated here, in one place. A phrase with no mapping is a failure, not an
    /// omission nobody notices. One phrase may name more than one position:
    /// *"FCB main/paging resources"* is two.
    #[test]
    fn every_curated_position_is_representable() {
        let mapped: &[(&str, &[LockRank])] = &[
            ("lifecycle-admission gate", &[LockRank::LifecycleAdmission]),
            ("per-open lifecycle gate", &[LockRank::PerOpenLifecycle]),
            ("size gate", &[LockRank::SizeGate]),
            ("sequencer", &[LockRank::Sequencer]),
            ("AdvanceOnly CSQ", &[LockRank::AdvanceOnlyCsq]),
            (
                "notification-state push lock",
                &[LockRank::NotificationState],
            ),
            (
                "CSQ spin lock",
                &[LockRank::AdvanceOnlyCsq, LockRank::NotifyCsq],
            ),
            (
                "FCB main/paging resources",
                &[LockRank::FcbMain, LockRank::FcbPaging],
            ),
            ("operation state lock", &[LockRank::OperationState]),
            ("domain locks", &[LockRank::DomainLock]),
            ("sole-consumer token", &[LockRank::SoleConsumerToken]),
            ("mount rundown", &[LockRank::MountRundown]),
            ("stream-admission gate", &[LockRank::StreamAdmissionGate]),
            (
                "domain/FCB/CCB lock",
                &[LockRank::DomainLock, LockRank::FcbMain, LockRank::CcbLock],
            ),
        ];
        for position in crate::effect::oracles::curated_positions_from_06() {
            assert!(
                mapped.iter().any(|(name, _)| *name == position),
                "the curated C1 corpus names {position:?} and no LockRank maps to it"
            );
        }
        // …and every curated mapping phrase still occurs in the source.
        for (phrase, _) in mapped {
            assert!(
                crate::effect::oracles::LOCK_DOC.contains(phrase),
                "the mapping claims 06-locking.md says {phrase:?}, and it does not"
            );
        }
    }

    /// Coverage, not cell count. A cell counter cannot notice that two ranks
    /// collide on one bit, which would silently halve the state space.
    #[test]
    fn every_rank_has_a_distinct_bit_and_the_masks_are_derived() {
        for (i, a) in ALL_RANKS.iter().enumerate() {
            assert_ne!(a.bit(), 0, "{a:?} has no bit");
            for b in ALL_RANKS.iter().skip(i.saturating_add(1)) {
                assert_ne!(a.bit(), b.bit(), "{a:?} and {b:?} collide on one bit");
            }
        }
        let union = ALL_RANKS.iter().fold(0u32, |acc, r| acc | r.bit());
        assert_eq!(
            union, ALL_BITS,
            "from_bits must admit exactly the modelled ranks"
        );
        let universal = ALL_RANKS
            .iter()
            .filter(|r| r.in_universal_order())
            .fold(0u32, |acc, r| acc | r.bit());
        assert_eq!(
            universal, UNIVERSAL_MASK,
            "the ordinal mask must match the ranks"
        );
    }

    #[test]
    fn acquisition_is_exhaustively_correct() {
        let mut seen_states = 0usize;
        for held in held_sets_for_test() {
            seen_states = seen_states.saturating_add(1);
            for next in ALL_RANKS {
                assert_eq!(
                    may_acquire(held, next),
                    oracle_acquire(held, next),
                    "held={:07b} next={next:?}",
                    held.bits()
                );
            }
        }
        assert!(seen_states >= (1 << 15) + (1 << 11) - 1);
    }

    #[test]
    fn actions_are_exhaustively_correct() {
        let mut seen_states = 0usize;
        for held in held_sets_for_test() {
            seen_states = seen_states.saturating_add(1);
            for action in ALL_ACTIONS {
                assert_eq!(
                    may_perform(held, action),
                    oracle_perform(held, action),
                    "held={:07b} action={action:?}",
                    held.bits()
                );
            }
        }
        assert!(seen_states >= (1 << 15) + (1 << 11) - 1);
    }

    #[test]
    fn r2_spin_paths_are_exact_and_cross_family_edges_are_refused() {
        for subset in 0..(1u32 << 11) {
            let held = HeldLocks::from_bits(subset << 15);
            for next in ALL_RANKS.iter().copied().filter(|rank| is_r2(*rank)) {
                let want = if held.holds(next) {
                    Err(LockOrderError::AlreadyHeld)
                } else if oracle_r2_acquire(held, next) {
                    Ok(())
                } else {
                    Err(LockOrderError::UnlistedR2Nesting)
                };
                assert_eq!(may_acquire(held, next), want, "{held:?} -> {next:?}");
            }
        }
        for legacy in ALL_RANKS.iter().copied().take(15) {
            for r2 in ALL_RANKS.iter().copied().skip(15) {
                assert_eq!(
                    may_acquire(HeldLocks::none().acquire(legacy), r2),
                    Err(LockOrderError::UnlistedR2Nesting)
                );
                assert_eq!(
                    may_acquire(HeldLocks::none().acquire(r2), legacy),
                    Err(LockOrderError::UnlistedR2Nesting)
                );
            }
        }
    }

    // --- Named cases: each carries the sentence it enforces ---

    #[test]
    fn the_sequencer_may_take_its_own_csq() {
        // §1: "dispatch calls IoCsqInsertIrpEx and IoCsqRemoveIrp while it owns
        // the sequencer".
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(Sequencer), AdvanceOnlyCsq),
            Ok(())
        );
    }

    #[test]
    fn the_sequencer_may_not_take_the_notify_csq() {
        // The two nestings are per side; §1 names the AdvanceOnly CSQ for the
        // sequencer and §5.4 gives change-notify its own separate IO_CSQ.
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(Sequencer), NotifyCsq),
            Err(LockOrderError::SpinLockNotLeaf)
        );
    }

    #[test]
    fn the_csq_may_not_take_the_sequencer() {
        // §1: "no CSQ callback acquires the sequencer".
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(AdvanceOnlyCsq), Sequencer),
            Err(LockOrderError::ReversedNesting)
        );
    }

    #[test]
    fn notification_state_may_take_the_notify_csq_and_nothing_else() {
        // §1: notification-state push lock followed by the CSQ spin lock is
        // "the only nested queue order on that side".
        let held = HeldLocks::none().acquire(NotificationState);
        assert_eq!(may_acquire(held, NotifyCsq), Ok(()));
        for other in [
            LifecycleAdmission,
            PerOpenLifecycle,
            SizeGate,
            Sequencer,
            AdvanceOnlyCsq,
        ] {
            assert_eq!(
                may_acquire(held, other),
                Err(LockOrderError::PushLockNesting),
                "{other:?} must not be acquired under the notification push lock"
            );
        }
    }

    #[test]
    fn a_csq_may_not_take_notification_state() {
        // §1: "cancellation/CSQ callbacks never take notification state".
        for csq in [AdvanceOnlyCsq, NotifyCsq] {
            assert_eq!(
                may_acquire(HeldLocks::none().acquire(csq), NotificationState),
                Err(LockOrderError::ReversedNesting)
            );
        }
    }

    #[test]
    fn nothing_may_be_acquired_while_a_csq_is_held() {
        for csq in [AdvanceOnlyCsq, NotifyCsq] {
            let held = HeldLocks::none().acquire(csq);
            for next in ALL_RANKS {
                assert!(
                    may_acquire(held, next).is_err(),
                    "a CSQ is a terminal leaf, but {next:?} was allowed under {csq:?}"
                );
            }
        }
    }

    #[test]
    fn no_earlier_position_may_be_taken_from_the_sequencer() {
        // §1: "No path acquires any earlier lock from the sequencer."
        let held = HeldLocks::none().acquire(Sequencer);
        for earlier in [LifecycleAdmission, PerOpenLifecycle, SizeGate] {
            assert_eq!(
                may_acquire(held, earlier),
                Err(LockOrderError::SpinLockNotLeaf)
            );
        }
    }

    #[test]
    fn the_universal_order_ascends_strictly() {
        let held = HeldLocks::none().acquire(SizeGate);
        assert_eq!(
            may_acquire(held, PerOpenLifecycle),
            Err(LockOrderError::OutOfOrder)
        );
        assert_eq!(may_acquire(held, Sequencer), Ok(()));
        assert_eq!(
            may_acquire(held, SizeGate),
            Err(LockOrderError::AlreadyHeld)
        );
    }

    #[test]
    fn a_path_may_omit_locks_it_does_not_need() {
        // §1: "omitting locks a path does not need".
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(LifecycleAdmission), Sequencer),
            Ok(())
        );
    }

    #[test]
    fn completion_requires_holding_no_modelled_position() {
        // §6, and note this is stricter than the working-action rule: a mere
        // gate also forbids completion.
        assert_eq!(may_perform(HeldLocks::none(), Action::CompleteIrp), Ok(()));
        for rank in ALL_RANKS {
            assert_eq!(
                may_perform(HeldLocks::none().acquire(rank), Action::CompleteIrp),
                Err(LockOrderError::CompletionUnderLock),
                "completion under {rank:?} must be rejected"
            );
        }
    }

    #[test]
    fn no_work_under_a_spin_lock() {
        // §1: "no spin lock is retained across a wait, an allocation, a
        // mapping, a provider call, or an IRP completion".
        for spin in [Sequencer, AdvanceOnlyCsq, NotifyCsq] {
            let held = HeldLocks::none().acquire(spin);
            for action in [
                Action::Wait,
                Action::Allocate,
                Action::MapMemory,
                Action::CallProvider,
            ] {
                assert_eq!(
                    may_perform(held, action),
                    Err(LockOrderError::ActionUnderLock),
                    "{action:?} under {spin:?}"
                );
            }
        }
    }

    #[test]
    fn no_work_under_the_notification_push_lock() {
        // §6: "privilege and access checks, allocation and free, waits,
        // user-buffer copies, and IoCompleteRequest occur under neither the
        // notification-state push lock nor the CSQ spin lock." The first draft
        // of this module allowed all four here, because its only guard was the
        // spin-lock predicate.
        let held = HeldLocks::none().acquire(NotificationState);
        for action in [
            Action::Wait,
            Action::Allocate,
            Action::MapMemory,
            Action::CallProvider,
        ] {
            assert_eq!(
                may_perform(held, action),
                Err(LockOrderError::ActionUnderLock),
                "{action:?} under the notification-state push lock"
            );
        }
    }

    #[test]
    fn work_is_allowed_under_a_logical_gate() {
        // The rule is about spin locks and the push lock. §3.1 calls the
        // lifecycle gate "a logical admission gate, not a thread-owned blocking
        // resource", and §2 keeps the size gate across the provider round trip.
        for gate in [LifecycleAdmission, PerOpenLifecycle, SizeGate] {
            let held = HeldLocks::none().acquire(gate);
            for action in [
                Action::Wait,
                Action::Allocate,
                Action::MapMemory,
                Action::CallProvider,
            ] {
                assert_eq!(
                    may_perform(held, action),
                    Ok(()),
                    "{action:?} under {gate:?}"
                );
            }
        }
    }

    #[test]
    fn the_kinds_match_the_document() {
        assert_eq!(LifecycleAdmission.kind(), LockKind::Gate);
        assert_eq!(PerOpenLifecycle.kind(), LockKind::Gate);
        assert_eq!(SizeGate.kind(), LockKind::Gate);
        assert_eq!(Sequencer.kind(), LockKind::SpinLock);
        assert_eq!(AdvanceOnlyCsq.kind(), LockKind::SpinLock);
        assert_eq!(NotificationState.kind(), LockKind::PushLock);
        assert_eq!(NotifyCsq.kind(), LockKind::SpinLock);
    }

    #[test]
    fn the_discriminants_are_pinned_to_the_documents_table() {
        assert_eq!(LifecycleAdmission as u8, 1);
        assert_eq!(PerOpenLifecycle as u8, 2);
        assert_eq!(SizeGate as u8, 3);
        assert_eq!(Sequencer as u8, 4);
        assert_eq!(AdvanceOnlyCsq as u8, 5);
        // The change-notify side sits above the five so an ordinal comparison
        // can never place it between two of them.
        assert_eq!(NotificationState as u8, 6);
        assert_eq!(NotifyCsq as u8, 7);
        for r in [
            LifecycleAdmission,
            PerOpenLifecycle,
            SizeGate,
            Sequencer,
            AdvanceOnlyCsq,
        ] {
            assert!(r.in_universal_order());
        }
        assert!(!NotificationState.in_universal_order());
        assert!(!NotifyCsq.in_universal_order());
    }

    #[test]
    fn held_set_operations_are_exact() {
        let h = HeldLocks::none();
        assert!(h.is_empty());
        let h = h.acquire(SizeGate);
        assert!(h.holds(SizeGate) && !h.holds(Sequencer) && !h.is_empty());
        assert!(!h.holds_any_spin_lock() && !h.holds_push_lock());
        let h = h.acquire(Sequencer);
        assert!(h.holds_any_spin_lock());
        let h = h.release(Sequencer).acquire(NotificationState);
        assert!(!h.holds_any_spin_lock() && h.holds_push_lock() && h.holds(SizeGate));
        // `from_bits` drops bits outside the modelled ranks. The literal was
        // `0xFF` while the set was a `u8` with seven ranks; under a `u32` with
        // fifteen at that checkpoint, `0xFF` no longer had a bit outside
        // `ALL_BITS` and the
        // assertion would pass without testing anything. `u32::MAX` is the
        // faithful form and does not go stale when a rank is added.
        assert_eq!(HeldLocks::from_bits(u32::MAX).bits(), ALL_BITS);
        assert_ne!(u32::MAX, ALL_BITS, "the input must have droppable bits");
    }

    // ---------------------------------------------------------------------
    // R5 Task 20: the C4 ring and grant spin edges
    // ---------------------------------------------------------------------
    //
    // The sweep above proves `may_acquire` and the oracle agree. These say what
    // the graph IS, one sentence at a time, so a wrong idea that reached both
    // restatements still has to get past a row that names the rule.

    use LockRank::{CancelSpin, CqConsumerToken, GrantSpin, RegistrySpin, RingSpin, SqWaitRole};

    /// `R` is a nonempty subset of the two ENTER roles, and nothing else.
    const ROLE_SETS: [&[LockRank]; 3] = [
        &[SqWaitRole],
        &[CqConsumerToken],
        &[SqWaitRole, CqConsumerToken],
    ];

    fn holding(ranks: &[LockRank]) -> HeldLocks {
        ranks
            .iter()
            .fold(HeldLocks::none(), |held, rank| held.acquire(*rank))
    }

    /// A ring spin lock is reachable from each of the three exact role sets --
    /// and from nothing else.
    ///
    /// The negative half is the load-bearing one: a per-ring spin lock taken
    /// with no role names a ring nobody is speaking for, so "which ring is this"
    /// has no answer and the lock guards an object the caller cannot name.
    #[test]
    fn task20_only_a_held_enter_role_reaches_the_per_ring_spin_lock() {
        for roles in ROLE_SETS {
            assert_eq!(
                may_acquire(holding(roles), RingSpin),
                Ok(()),
                "{roles:?} is one of the three exact role sets"
            );
            // The registry lock is read and dropped before a ring is touched,
            // so it is not part of any C4 prefix.
            let mut under_registry = roles.to_vec();
            under_registry.push(RegistrySpin);
            assert_eq!(
                may_acquire(holding(&under_registry), RingSpin),
                Err(LockOrderError::UnlistedR2Nesting),
                "the registry lock is dropped before the ring is touched"
            );
        }
        assert_eq!(
            may_acquire(HeldLocks::none(), RingSpin),
            Err(LockOrderError::UnlistedR2Nesting),
            "a ring lock with no role names a ring nobody is speaking for"
        );
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(RegistrySpin), RingSpin),
            Err(LockOrderError::UnlistedR2Nesting)
        );
    }

    /// `RingSpin < GrantSpin`, and the grant lock has no other ENTER route.
    ///
    /// One grant lock serves the whole session, so two rings claiming credits
    /// would form overlapping mutable slices over the same entry array unless
    /// every claim arrives through the exact ring's guard.
    #[test]
    fn task20_the_grant_lock_is_reachable_only_through_the_exact_ring_guard() {
        for roles in ROLE_SETS {
            let mut with_ring = roles.to_vec();
            with_ring.push(RingSpin);
            assert_eq!(may_acquire(holding(&with_ring), GrantSpin), Ok(()));

            // Without the ring guard the grant lock is unreachable, whichever
            // role is held.
            assert_eq!(
                may_acquire(holding(roles), GrantSpin),
                Err(LockOrderError::UnlistedR2Nesting),
                "the ring guard is the only ENTER route to the grant lock"
            );

            // And the reverse order is refused, which is what makes this an
            // ORDER rather than a pair of memberships.
            let mut with_grant = roles.to_vec();
            with_grant.push(GrantSpin);
            assert_eq!(
                may_acquire(holding(&with_grant), RingSpin),
                Err(LockOrderError::UnlistedR2Nesting),
                "GrantSpin -> RingSpin is the inversion this order forbids"
            );
        }
        // A ring lock with no role cannot launder itself into the grant lock.
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(RingSpin), GrantSpin),
            Err(LockOrderError::UnlistedR2Nesting)
        );
    }

    /// Cancel is a terminal leaf reachable under the ring hold with or without
    /// the grant lock -- and never from a grant-only hold.
    ///
    /// The grant-only row is unreachable through legal acquisitions today. It is
    /// still stated, because a rule that answers `Ok` for an unreachable state
    /// stops being a check the moment the state becomes reachable.
    #[test]
    fn task20_cancel_is_reachable_under_ring_and_grant_but_never_grant_only() {
        for roles in ROLE_SETS {
            let mut with_ring = roles.to_vec();
            with_ring.push(RingSpin);
            assert_eq!(may_acquire(holding(&with_ring), CancelSpin), Ok(()));

            let mut with_grant = with_ring.clone();
            with_grant.push(GrantSpin);
            assert_eq!(may_acquire(holding(&with_grant), CancelSpin), Ok(()));

            let mut grant_only = roles.to_vec();
            grant_only.push(GrantSpin);
            assert_eq!(
                may_acquire(holding(&grant_only), CancelSpin),
                Err(LockOrderError::UnlistedR2Nesting),
                "a grant hold with no ring guard may never reach Cancel"
            );
        }
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(GrantSpin), CancelSpin),
            Err(LockOrderError::UnlistedR2Nesting)
        );
        // Task 5's SQ edge is untouched: the SQ prefix alone still reaches
        // Cancel, so the C4 arm was added beside it rather than over it.
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(SqWaitRole), CancelSpin),
            Ok(())
        );
    }

    /// The authenticated readiness resume derives its CQ role while the SQ
    /// lease is held; the reverse pairing is not a listed edge.
    ///
    /// Before Task 20 the CQ role was reachable only from an empty or
    /// registry-only hold, which made the third role set -- the one Task 14.4's
    /// `authorize_resume` already builds in the type system -- unrepresentable
    /// in the lock model.
    #[test]
    fn task20_the_readiness_resume_derives_its_cq_role_under_the_sq_lease() {
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(SqWaitRole), CqConsumerToken),
            Ok(())
        );
        assert_eq!(
            may_acquire(holding(&[RegistrySpin, SqWaitRole]), CqConsumerToken),
            Ok(())
        );
        assert_eq!(
            may_acquire(HeldLocks::none().acquire(CqConsumerToken), SqWaitRole),
            Err(LockOrderError::UnlistedR2Nesting),
            "the resume goes SQ -> CQ; the reverse is not a listed edge"
        );
    }

    /// Neither C4 spin lock admits the VPB lock, any legacy position, or a
    /// second acquisition of itself.
    #[test]
    fn task20_the_c4_spin_locks_admit_no_cross_family_or_repeat_edge() {
        for roles in ROLE_SETS {
            let mut with_ring = roles.to_vec();
            with_ring.push(RingSpin);
            let held = holding(&with_ring);
            assert_eq!(
                may_acquire(held, LockRank::VpbSpin),
                Err(LockOrderError::UnlistedR2Nesting),
                "the VPB lock is on neither C4 path"
            );
            assert_eq!(
                may_acquire(held, RingSpin),
                Err(LockOrderError::AlreadyHeld)
            );
            for legacy in ALL_RANKS.iter().copied().take(15) {
                assert_eq!(
                    may_acquire(held, legacy),
                    Err(LockOrderError::UnlistedR2Nesting),
                    "{legacy:?} under the ring guard"
                );
            }
        }
        let grant_held = holding(&[SqWaitRole, RingSpin, GrantSpin]);
        assert_eq!(
            may_acquire(grant_held, GrantSpin),
            Err(LockOrderError::AlreadyHeld)
        );
        assert_eq!(
            may_acquire(grant_held, RegistrySpin),
            Err(LockOrderError::UnlistedR2Nesting)
        );
    }

    /// No work, wait, allocation or completion happens under either C4 spin
    /// lock: both are `SpinLock` kind, and the leaf rule is stated over kinds.
    #[test]
    fn task20_no_work_or_completion_is_permitted_under_the_c4_spin_locks() {
        for position in [RingSpin, GrantSpin] {
            assert_eq!(position.kind(), LockKind::SpinLock);
            let held = HeldLocks::none().acquire(SqWaitRole).acquire(position);
            assert!(held.holds_any_spin_lock());
            assert_eq!(
                may_perform(held, Action::CompleteIrp),
                Err(LockOrderError::CompletionUnderLock)
            );
            assert_eq!(
                may_perform(held, Action::Allocate),
                Err(LockOrderError::ActionUnderLock)
            );
        }
    }
}
