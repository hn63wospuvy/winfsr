//! One parsed roster plus curated normative-document transcriptions, for tests.
//!
//! **What is parsed and what is transcribed, stated exactly.** Only
//! `06-locking.md` §1's five-row table is *parsed* — read structurally, so a row
//! added, removed or renamed changes the result.
//!
//! Everything else here is a **transcribed phrase** checked for occurrence:
//! [`POSITION_PHRASES_OUTSIDE_THE_TABLE`], [`FORBIDDEN_EFFECT_SENTENCES`],
//! [`PROVIDER_ROUND_TRIP_IS_LEGAL`], [`ALLOC_TARGET_SENTENCE`]. An occurrence
//! check is weaker than a parse: it catches a document reworded out from under
//! the roster, and it does **not** catch a sentence the roster never
//! transcribed. C1's review round 1 found the design describing all of this as
//! "parsed", which overstated it, and found the consequence — *FCB rundown*,
//! named by a transcribed sentence, modelled by nothing.
//!
//! A hand-written list checked by a hand-written test is the same source twice;
//! an occurrence check is one step better than that and two steps short of a
//! parse. The known-unmodelled list below records reviewed examples; it is not
//! a document-wide discovery mechanism.
//!
//! Every phrase below is paired with an anti-vacuity test that requires it to
//! occur in the document it claims to come from. Without that test, a stale
//! transcription could keep feeding every downstream check even after its
//! source text changed.

use crate::effect::{Effect, WaitTarget};
use crate::lockrank::{HeldLocks, LockOrderError, LockRank};
use crate::session::FenceEffect;

/// The C4 R2 positions, transcribed independently from the production masks.
pub const R2_POSITIONS: [LockRank; 11] = [
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

/// The three exact held-role sets Task 20's C4 ring/grant graph is stated over.
///
/// `{SqWait}` is a poll or wait, `{CqConsumer}` a synchronous CQ-only drain, and
/// both together the authenticated readiness resume, whose SQ lease and derived
/// CQ token belong to one request. Nothing else is an `R`.
pub const C4_ENTER_ROLE_SETS: [&[LockRank]; 3] = [
    &[LockRank::SqWaitRole],
    &[LockRank::CqConsumerToken],
    &[LockRank::SqWaitRole, LockRank::CqConsumerToken],
];

/// The lifecycle-event waits introduced by the C4 decision seam.
pub const R2_LIFECYCLE_WAITS: [WaitTarget; 7] = [
    WaitTarget::TerminalOutcomeEvent,
    WaitTarget::JoinerDrainedEvent,
    WaitTarget::PendingDpcExitEvent,
    WaitTarget::MountCompletionEvent,
    WaitTarget::MountWaitersDrainedEvent,
    WaitTarget::MountResetCompleteEvent,
    WaitTarget::MountResetWaitersDrainedEvent,
];

/// Every modelled rundown, role, or spin guard that terminal work must outlive.
pub const TERMINAL_WAIT_GUARDS: [LockRank; 15] = [
    LockRank::MountRundown,
    LockRank::ControlRundown,
    LockRank::SessionAccessRundown,
    LockRank::SetupAdmissionRundown,
    LockRank::ControlContextAdmissionRundown,
    LockRank::SqWaitRole,
    LockRank::CqConsumerToken,
    LockRank::Sequencer,
    LockRank::AdvanceOnlyCsq,
    LockRank::NotifyCsq,
    LockRank::RegistrySpin,
    LockRank::CancelSpin,
    LockRank::VpbSpin,
    LockRank::RingSpin,
    LockRank::GrantSpin,
];

/// The pre-C4 terminal waits embedded in the session-fence effect vocabulary.
pub const SESSION_FENCE_TERMINAL_WAITS: [FenceEffect; 3] = [
    FenceEffect::WaitProducerAndMappingCaptureRundown,
    FenceEffect::WaitPendingAndOwners,
    FenceEffect::WaitControlRundown,
];

/// The independent terminal-wait verdict for one held set and effect.
pub fn terminal_wait_verdict(held: HeldLocks, effect: Effect) -> Option<LockOrderError> {
    let terminal_wait = matches!(effect, Effect::Wait(target) if R2_LIFECYCLE_WAITS.contains(&target))
        || matches!(effect, Effect::SessionFence(wait) if SESSION_FENCE_TERMINAL_WAITS.contains(&wait));
    (terminal_wait && TERMINAL_WAIT_GUARDS.iter().any(|rank| held.holds(*rank)))
        .then_some(LockOrderError::LifecycleWaitUnderGuard)
}

/// Is an R2 acquisition one of the two listed spin paths, or an isolated
/// rundown acquired from an empty context?
///
/// This deliberately uses ordered arrays and search rather than the production
/// bit masks. Agreement therefore checks two different representations of the
/// same graph.
pub fn r2_acquisition_is_listed(held: HeldLocks, next: LockRank) -> bool {
    let held_ranks: Vec<LockRank> = R2_POSITIONS
        .iter()
        .copied()
        .filter(|rank| held.holds(*rank))
        .collect();
    let contains_non_r2 = crate::lockrank::ALL_RANKS
        .iter()
        .copied()
        .any(|rank| !R2_POSITIONS.contains(&rank) && held.holds(rank));
    if contains_non_r2 {
        return false;
    }

    let isolated = [
        LockRank::ControlRundown,
        LockRank::SessionAccessRundown,
        LockRank::SetupAdmissionRundown,
        LockRank::ControlContextAdmissionRundown,
    ];
    if isolated.contains(&next) {
        return held_ranks.is_empty();
    }

    if c4_ring_graph_lists(&held_ranks, next) {
        return true;
    }

    let sq_path = [
        LockRank::RegistrySpin,
        LockRank::SqWaitRole,
        LockRank::CancelSpin,
        LockRank::VpbSpin,
    ];
    let cq_path = [
        LockRank::RegistrySpin,
        LockRank::CqConsumerToken,
        LockRank::VpbSpin,
    ];
    [sq_path.as_slice(), cq_path.as_slice()].iter().any(|path| {
        let Some(next_index) = path.iter().position(|rank| *rank == next) else {
            return false;
        };
        held_ranks.iter().all(|held_rank| {
            path.iter()
                .position(|rank| rank == held_rank)
                .is_some_and(|held_index| held_index < next_index)
        })
    })
}

/// Task 20's C4 ring/grant graph, as the exact rows the plan enumerates.
///
/// Stated as *rows* rather than as another linear path, because the graph is not
/// linear: `R` is any nonempty subset of the two ENTER roles, so the three role
/// sets are three different starting points that converge on the same ring and
/// grant positions. A path model would have to admit an empty prefix, which is
/// precisely the case this graph forbids -- a per-ring spin lock taken with no
/// role names a ring nobody is speaking for.
///
/// The four shapes, from the plan: `R -> RingSpin`,
/// `{R, RingSpin} -> GrantSpin`, `{R, RingSpin} -> CancelSpin`, and
/// `{R, RingSpin, GrantSpin} -> CancelSpin`. The fifth row is the readiness
/// resume deriving its CQ role while the SQ lease is held, which is what makes
/// the third `R` reachable at all.
fn c4_ring_graph_lists(held: &[LockRank], next: LockRank) -> bool {
    fn same_set(left: &[LockRank], right: &[LockRank]) -> bool {
        left.len() == right.len() && right.iter().all(|rank| left.contains(rank))
    }

    if next == LockRank::CqConsumerToken {
        // The resume holds the SQ lease, optionally under the registry lock it
        // read the locator through.
        let without_registry: Vec<LockRank> = held
            .iter()
            .copied()
            .filter(|rank| *rank != LockRank::RegistrySpin)
            .collect();
        return same_set(&without_registry, &[LockRank::SqWaitRole]);
    }

    for roles in C4_ENTER_ROLE_SETS {
        let mut with_ring: Vec<LockRank> = roles.to_vec();
        with_ring.push(LockRank::RingSpin);
        let mut with_grant = with_ring.clone();
        with_grant.push(LockRank::GrantSpin);

        let listed = match next {
            LockRank::RingSpin => same_set(held, roles),
            LockRank::GrantSpin => same_set(held, &with_ring),
            LockRank::CancelSpin => same_set(held, &with_ring) || same_set(held, &with_grant),
            _ => false,
        };
        if listed {
            return true;
        }
    }
    false
}

/// The expected C4 effect verdict for a held set made exclusively of R2
/// positions.
///
/// `None` means no R2 rule decides the effect. The production function still
/// applies the pre-existing C1 rules in that case.
pub fn r2_effect_verdict(held: HeldLocks, effect: Effect) -> Option<LockOrderError> {
    if matches!(effect, Effect::CompleteIrp) && !held.is_empty() {
        return Some(LockOrderError::CompletionUnderLock);
    }
    if let Some(verdict) = terminal_wait_verdict(held, effect) {
        return Some(verdict);
    }
    let waits = matches!(effect, Effect::Wait(_))
        || matches!(
            effect,
            Effect::SessionFence(
                FenceEffect::WaitProducerAndMappingCaptureRundown
                    | FenceEffect::WaitPendingAndOwners
                    | FenceEffect::WaitControlRundown
            )
        );
    if waits && held.holds(LockRank::CqConsumerToken) {
        return Some(LockOrderError::WaitUnderNoWaitRole);
    }
    if [
        LockRank::RegistrySpin,
        LockRank::CancelSpin,
        LockRank::VpbSpin,
        LockRank::RingSpin,
        LockRank::GrantSpin,
    ]
    .iter()
    .any(|rank| held.holds(*rank))
    {
        return Some(LockOrderError::ActionUnderLock);
    }
    None
}

/// `06-locking.md`, the concurrency contract.
pub const LOCK_DOC: &str = include_str!("../../../../docs/design/06-locking.md");

/// `07-cache-mm.md`, the Cache-Manager/MM contract.
pub const CACHE_DOC: &str = include_str!("../../../../docs/design/07-cache-mm.md");

/// Verbatim anchors for all six ordered session-fence stages in `06` section
/// 7.1. The session tests pin the finer-grained immutable effect slices.
pub const SESSION_FENCE_ORDER_SENTENCES: &[&str] = &[
    "signals every outstanding ENTER to\n   leave its wait",
    "removes the old daemon's writable producer mappings and waits only\n   the producer publication/mapping-capture rundown",
    "acquires every per-ring sole-consumer token in increasing ring-index\n   order",
    "walks each ring's stable CQ prefix in order, at most `cq_capacity`\n   cells",
    "Only after every stable prefix has been owned and all tokens have been\n   released does the fence queue the newly installed work and wait for",
    "completes the remaining session/mapping rundown and\n   discards the old views",
];

/// The phrases naming positions that live outside `06-locking.md` §1's table.
///
/// Sources, each a sentence rather than a judgement:
///
/// | phrase | where |
/// |---|---|
/// | `FCB main/paging resources` | §1 row 3's Kind column, §2 corollary 1 |
/// | `notification-state push lock` | §1 bullet 3, §6 |
/// | `CSQ spin lock` | §1 bullet 3, §6 |
/// | `operation state lock` | §1 bullet 4 (§9 owns it) |
/// | `domain locks` | §1 bullet 4 (§4 owns them) |
/// | `sole-consumer token` | §1 bullet 5 (§7.2 owns it) |
/// | `mount rundown` | §6's opening sentence |
/// | `stream-admission gate` | §3.6 |
/// | `domain/FCB/CCB lock` | §6's opening sentence |
pub const POSITION_PHRASES_OUTSIDE_THE_TABLE: &[&str] = &[
    "FCB main/paging resources",
    "notification-state push lock",
    "CSQ spin lock",
    "operation state lock",
    "domain locks",
    "sole-consumer token",
    "mount rundown",
    "stream-admission gate",
    "domain/FCB/CCB lock",
];

/// The five ordered positions, read out of `06-locking.md` §1's table.
///
/// The table's rows are `| <order> | <name> | <kind> | <scope> | <serializes> |`.
/// Reading them rather than restating them is what makes "the table names a
/// position the enum omits" a test failure. Measured against the shipped
/// document: this returns exactly five rows and no other table in `06` has a
/// numeric first cell in 1..=5.
///
/// The scope is **this table**. Positions named in prose elsewhere are reached
/// by transcription, not by this parse — see the module documentation.
pub fn ordered_positions_named_by_06() -> Vec<&'static str> {
    let mut found = Vec::new();
    for line in LOCK_DOC.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // A table row is `| order | name | kind | scope | serializes |`, which
        // splits to seven cells with empty ends. Read positionally through
        // `get` rather than by index: `clippy::indexing_slicing` is denied
        // crate-wide, and a row shorter than expected must be skipped rather
        // than panic the test suite.
        let (Some(order_cell), Some(name_cell)) = (cells.get(1), cells.get(2)) else {
            continue;
        };
        if cells.len() <= 3 {
            continue;
        }
        let Ok(order) = order_cell.parse::<u8>() else {
            continue;
        };
        if (1..=5).contains(&order) && !name_cell.is_empty() {
            found.push(*name_cell);
        }
    }
    found
}

/// The curated roster: the five ordered positions parsed from §1's table, then
/// the nine transcribed phrases outside it.
///
/// **Not every position `06-locking.md` names.** That was the totality claim
/// round 1 falsified and round 3 found still standing here, eleven lines above
/// this file's own quotation of it as "the earlier totality claim". What the
/// known document positions that C1 does not model are recorded in
/// [`KNOWN_UNMODELLED_POSITIONS_IN_C1`]. That list is deliberately described as
/// known examples, not as a complete scan of the document.
pub fn curated_positions_from_06() -> Vec<&'static str> {
    let mut found = ordered_positions_named_by_06();
    found.extend_from_slice(POSITION_PHRASES_OUTSIDE_THE_TABLE);
    found
}

/// Known positions `06-locking.md` names that C1 does **not** model.
///
/// This is a curated, non-exhaustive list. Each entry is pinned in both
/// directions, but an unlisted document phrase cannot make the test fail.
///
/// C1's review round 1 falsified the earlier totality claim — *"every position
/// `06-locking.md` names as something a path can hold"* — by finding **FCB
/// rundown** inside a sentence C1 itself quotes verbatim
/// ([`PROVIDER_ROUND_TRIP_IS_LEGAL`]). The claim named its own boundary and
/// then a counterexample turned up inside it, which is the same failure B5 lost
/// two rounds to one level up.
///
/// So known examples are enumerated and pinned.
/// `every_listed_unmodelled_position_is_still_unmodelled` requires each phrase
/// to occur in the document (so a listed entry cannot go stale) **and** requires
/// `LockRank` to have no variant whose name matches (so modelling one without
/// removing it from here fails). Discovery of additional examples remains a
/// review obligation.
pub const KNOWN_UNMODELLED_POSITIONS_IN_C1: &[UncoveredPosition] = &[
    UncoveredPosition {
        phrase: "FCB rundown",
        why: "§2 corollary 1 and the §2 wait table hold it alongside the size               gate across a provider round trip; C1 models the gate, not the               rundown",
        would_be_named: &["FcbRundown"],
    },
    UncoveredPosition {
        phrase: "session, ring, mount-control",
        why: "§1 bullet 4 names three more locks a path may own; C1 models none",
        would_be_named: &["SessionLock", "RingLock", "MountControlLock"],
    },
    UncoveredPosition {
        phrase: "namespace lock",
        why: "§7.1 forbids taking it under the token; C1 folds no namespace               position into its roster",
        would_be_named: &["NamespaceLock"],
    },
    UncoveredPosition {
        phrase: "registration rundown",
        why: "§8's notify side names it; C1 models mount rundown only",
        would_be_named: &["RegistrationRundown"],
    },
];

/// One known position the documents name and C1 does not model.
///
/// `would_be_named` is the identifier a future slice would add to `LockRank`.
/// The boundary test asserts no such variant exists — an explicit name rather
/// than a morphological guess, because round 2 found the guess unable to match
/// any multi-word phrase, which made those entries' assertions unconditionally
/// true.
pub struct UncoveredPosition {
    /// The phrase as `06-locking.md` writes it.
    pub phrase: &'static str,
    /// Which sentence names it, and what C1 models instead.
    pub why: &'static str,
    /// The `LockRank` identifier(s) that would model it.
    pub would_be_named: &'static [&'static str],
}

/// The sentences that forbid an effect under a hold.
///
/// The C1 effect vocabulary is closed over these curated sentences and nothing
/// else; this is not a claim that the corpus contains every relevant document
/// sentence. Each entry is `(document, phrase)` and the phrase is quoted
/// **verbatim**, line wrapping included, so
/// `every_forbidding_sentence_still_occurs` fails if the document is reworded
/// rather than passing on a paraphrase.
pub const FORBIDDEN_EFFECT_SENTENCES: &[(&str, &str)] = &[
    // 06 §1, first completing bullet: the spin-lock leaf rule, which is where
    // Wait / Allocate / CopyUserBuffer / CallProvider / CompleteIrp come from.
    (
        "06",
        "no spin lock is retained across a wait, an\n  allocation, a mapping, a provider call, or an IRP completion",
    ),
    // 06 §6, the change-notify bullet: adds PrivilegeOrAccessCheck and Free.
    (
        "06",
        "privilege and access checks, allocation and\n  free, waits, user-buffer copies, and `IoCompleteRequest` occur under",
    ),
    // 06 §2 corollary 2: the sentence that makes WaitTarget necessary.
    (
        "06",
        "no size\n   path waits for an application slot, ApplyReserve, allocation, grant, or\n   other admission resource while it owns the logical gate",
    ),
    // 07 §6: allocation under the sequencer.
    ("07", "never allocates while the sequencer lock is held"),
    // 07 §4: the rule no held-set can express, which is why TopLevelContext
    // exists.
    (
        "07",
        "MUST NOT synchronously wait on anything else while the\ntop-level context is the cache sentinel",
    ),
    // 06 §3.2: the per-open lifecycle gate is not held across a predecessor
    // drain. This is the sentence behind the fourth named case.
    (
        "06",
        "The lifecycle\ngate is released while any predecessor waits",
    ),
    // 06 §7.2: the sole-consumer token. This is the source of
    // Effect::NotificationCallback and of the token rules -- the earlier
    // citation to §6's change-notify bullet was wrong, since that bullet names
    // no callback.
    (
        "06",
        "It is never held while\nacquiring an FCB/CCB/namespace/domain lock, running an access check or\nnotification callback, waiting for SQ, or completing an IRP.",
    ),
    // 06 §7.1, the same rule stated for the fence walk.
    (
        "06",
        "No domain/FCB/CCB/namespace lock, access check, callback, or blocking action runs while a token is held.",
    ),
    // 07 §10: the conditional acquisition, which is why there are two guards.
    (
        "07",
        "only if the calling thread does not\nalready own it, and release only what they acquired",
    ),
];

/// `06-locking.md` §2 corollary 1, which makes the provider round trip under
/// the size gate **legal**. Quoted so the refinement derived from corollary 2
/// cannot be widened into a blanket ban without this sentence going missing.
pub const PROVIDER_ROUND_TRIP_IS_LEGAL: &str = "Blocking resources are released before provider execution while the\n   logical size gate and FCB rundown remain held";

/// The allocation targets `07-cache-mm.md` §5 enumerates by name.
pub const ALLOC_TARGET_SENTENCE: &str = "ReqId, grant, digest, or SQE";
