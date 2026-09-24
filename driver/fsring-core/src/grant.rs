//! Caller-backed O(1) U2K grant and notification-credit transitions.

use core::{
    convert::TryFrom,
    mem::size_of,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

use fsring_abi::{
    SLOT_CLASS_COUNT, SlotToken,
    control::NotificationCreditV1,
    msgs::{BufferRef, buffer_access, buffer_kind},
    validate::ValidatedTopology,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantEntry {
    slot_token: Option<SlotToken>,
    ring_index: u32,
    generation: u64,
    state: GrantState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GrantTableId(NonZeroU64);

impl GrantTableId {
    #[cfg(test)]
    const fn get(self) -> u64 {
        self.0.get()
    }
}

/// The identity one `GrantTable::initialize` minted. SETUP stores it; ENTER
/// drain reopens the issued backing with [`GrantTable::attach`] so preflight
/// and claim still see the same table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantTableIdentity(NonZeroU64);

static NEXT_GRANT_TABLE_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_grant_table_id(next_id: &AtomicU64) -> Result<GrantTableId, GrantError> {
    let mut current = next_id.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return Err(GrantError::TableIdentityExhausted);
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
                let Some(identity) = NonZeroU64::new(current) else {
                    return Err(GrantError::TableIdentityExhausted);
                };
                return Ok(GrantTableId(identity));
            }
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantState {
    Free,
    Issued,
    Claimed,
    Retired,
}

impl GrantEntry {
    pub const FREE: Self = Self {
        slot_token: None,
        ring_index: 0,
        generation: 0,
        state: GrantState::Free,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct NotifyPreflight {
    table_id: GrantTableId,
    entry_index: u32,
    ring_index: u32,
    observed_generation: u64,
    next_generation: u64,
    next_descriptor: NotificationCreditV1,
}

/// Where each U2K slot class's data actually starts.
///
/// **Given, never derived.** `SlotClassDesc.data_offset` is a published field
/// the section validator checks only for 64-byte alignment and containment in
/// its arena, so padding between classes is legal and summing `count * size`
/// over the earlier classes produces a plausible number that is quietly wrong.
/// A `GrantTable` is built from the topology *request*, which carries sizes and
/// counts and no offsets at all, so the geometry has to arrive separately from
/// whoever validated the layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotArenaGeometry {
    class_data_offsets: [u64; SLOT_CLASS_COUNT],
}

impl SlotArenaGeometry {
    /// Adopt the published per-class data offsets.
    ///
    /// Alignment is checked here rather than trusted: the validator that
    /// accepted the section is a different artifact from this one, and a
    /// geometry that disagreed with it would produce ranges pointing between
    /// slots.
    pub fn from_published(class_data_offsets: [u64; SLOT_CLASS_COUNT]) -> Result<Self, GrantError> {
        for offset in class_data_offsets {
            if offset % SLOT_ALIGNMENT != 0 {
                return Err(GrantError::InvalidTopology);
            }
        }
        Ok(Self { class_data_offsets })
    }

    fn base_of(&self, class: usize) -> Option<u64> {
        self.class_data_offsets.get(class).copied()
    }
}

/// The `SLOT_ALIGNMENT` `06`/`07` and the section validator both name.
const SLOT_ALIGNMENT: u64 = 64;

/// Where in the U2K arena one notification body lives.
///
/// Two numbers copied out of the validated descriptor, not a borrow of the
/// entry that produced them: holding a range cannot keep a grant entry alive or
/// make it look claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRange {
    arena_offset: u64,
    length: u32,
}

impl GrantRange {
    pub const fn arena_offset(&self) -> u64 {
        self.arena_offset
    }

    pub const fn length(&self) -> u32 {
        self.length
    }
}

/// A validated credit claim that has not mutated anything yet.
///
/// It retains the exact `&mut GrantEntry` the claim will write, so no lookup,
/// no index and no fallible bind sits between the arbitration that authorised
/// the mutation and the mutation itself. There is exactly one way out and it
/// cannot fail.
#[derive(Debug)]
#[must_use]
pub struct PreparedCreditClaim<'claim> {
    entry: &'claim mut GrantEntry,
    ring_index: u32,
    old_generation: u64,
    next_generation: u64,
    next_descriptor: NotificationCreditV1,
}

impl<'claim> PreparedCreditClaim<'claim> {
    /// Perform the one credit mutation. Parameterless and infallible.
    ///
    /// **MEASURED-UNCOVERED: the `Claimed` write itself.** Removing it leaves
    /// every core test green, and that is a property of the borrow rather than
    /// a gap in the tests: while a `ClaimedNotification` is alive the table is
    /// exclusively borrowed, so no safe caller can observe the intermediate
    /// state, and `refresh` overwrites the entry wholesale, so the endpoint is
    /// the same either way. The write is what makes a *concurrently reached*
    /// table -- `retire_for_fence` on the fence side, or the native executor
    /// holding a raw pointer -- see the entry as spoken for. Task 25's native
    /// integration is where that becomes observable; it is recorded here rather
    /// than covered by a test that could only agree with this comment.
    pub fn commit(self) -> ClaimedNotification<'claim> {
        let Self {
            entry,
            ring_index,
            old_generation,
            next_generation,
            next_descriptor,
        } = self;
        entry.state = GrantState::Claimed;
        ClaimedNotification {
            entry,
            ring_index,
            old_generation,
            next_generation,
            next_descriptor,
        }
    }

    /// Which ring this claim belongs to, for a sibling's cross-check.
    #[allow(dead_code)]
    pub(crate) const fn ring_index(&self) -> u32 {
        self.ring_index
    }
}

/// Exclusive authority over one claimed notification credit.
///
/// A claim must prevent the table-wide fence transition from retiring its
/// entry before the matching refresh. The old, arbitrary-table refresh trace
/// is therefore intentionally unrepresentable:
///
/// ```compile_fail,E0499
/// use fsring_abi::control::NotificationCreditV1;
/// use fsring_core::grant::{GrantTable, NotifyPreflight};
///
/// fn cannot_retire_then_resurrect(
///     table: &mut GrantTable<'_>,
///     preflight: NotifyPreflight,
///     output: &mut NotificationCreditV1,
/// ) {
///     let Ok(claim) = table.claim_notify(preflight) else { return };
///     table.retire_for_fence();
///     // SAFETY: illustrative only; safe code still cannot overlap the table.
///     let advanced = unsafe { claim.after_release_head_advance() };
///     let _ = advanced.refresh(output);
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct ClaimedNotification<'claim> {
    entry: &'claim mut GrantEntry,
    ring_index: u32,
    old_generation: u64,
    next_generation: u64,
    next_descriptor: NotificationCreditV1,
}

/// Proof that one claimed credit's matching CQ-head Release store occurred.
///
/// A bare claim cannot perform refresh:
///
/// ```compile_fail,E0599
/// use fsring_abi::control::NotificationCreditV1;
/// use fsring_core::grant::ClaimedNotification;
///
/// fn bare_claim_cannot_refresh(
///     claim: ClaimedNotification<'_>,
///     output: &mut NotificationCreditV1,
/// ) {
///     let _ = claim.refresh(output);
/// }
/// ```
///
/// Safe external code also cannot fabricate the proof:
///
/// ```compile_fail,E0451
/// use fsring_core::grant::{ClaimedNotification, HeadAdvancedNotification};
///
/// fn safe_code_cannot_fabricate(
///     claim: ClaimedNotification<'_>,
/// ) -> HeadAdvancedNotification<'_> {
///     HeadAdvancedNotification { claim }
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct HeadAdvancedNotification<'claim> {
    claim: ClaimedNotification<'claim>,
}

impl<'claim> ClaimedNotification<'claim> {
    /// Convert a claimed credit into proof that its consuming CQ commit occurred.
    ///
    /// # Safety
    /// The caller completed the matching CQ-head atomic store with Release
    /// ordering exactly once immediately before this transition.
    pub unsafe fn after_release_head_advance(self) -> HeadAdvancedNotification<'claim> {
        HeadAdvancedNotification { claim: self }
    }
}

impl HeadAdvancedNotification<'_> {
    /// Publish the already-preflighted generation and return descriptor.
    pub fn refresh(self, output: &mut NotificationCreditV1) -> RefreshedCredit {
        let ClaimedNotification {
            entry,
            ring_index,
            old_generation,
            next_generation,
            next_descriptor,
        } = self.claim;
        let next_token = match SlotToken::from_raw(next_descriptor.buffer.token) {
            Ok(token) => token,
            Err(_) => unreachable!("claimed notification descriptor was prevalidated"),
        };
        *entry = GrantEntry {
            slot_token: Some(next_token),
            ring_index,
            generation: next_generation,
            state: GrantState::Issued,
        };
        *output = next_descriptor;
        RefreshedCredit {
            descriptor: next_descriptor,
            old_generation,
            new_generation: next_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshedCredit {
    pub descriptor: NotificationCreditV1,
    pub old_generation: u64,
    pub new_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantEntrySnapshot {
    pub token: SlotToken,
    pub ring_index: u32,
    pub generation: u64,
    pub state: GrantState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    InvalidBacking,
    InvalidTopology,
    TableIdentityExhausted,
    InvalidToken,
    WrongRing,
    StaleGeneration,
    ReturnBufferTooSmall,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantFault {
    Duplicate,
    ConcurrentReuse,
    CrossRing,
    OutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantCommitStep {
    Preflight,
    Claim,
    AdvanceHead,
    Refresh,
}

impl GrantCommitStep {
    pub const ORDER: [Self; 4] = [
        GrantCommitStep::Preflight,
        GrantCommitStep::Claim,
        GrantCommitStep::AdvanceHead,
        GrantCommitStep::Refresh,
    ];
}

struct GrantTableLayout {
    class_bases: [u32; SLOT_CLASS_COUNT],
    class_counts: [u32; SLOT_CLASS_COUNT],
    slot_sizes: [u32; SLOT_CLASS_COUNT],
    notification_credit_class: u8,
    notification_credit_count: u32,
    notification_credit_size: u32,
    ring_count: u32,
    required: usize,
}

fn grant_table_layout(
    topology: &ValidatedTopology,
    session_epoch: u64,
) -> Result<GrantTableLayout, GrantError> {
    if session_epoch == 0 {
        return Err(GrantError::InvalidTopology);
    }

    let classes = topology.u2k_slot_classes();
    let mut class_bases = [0u32; SLOT_CLASS_COUNT];
    let mut class_counts = [0u32; SLOT_CLASS_COUNT];
    let mut slot_sizes = [0u32; SLOT_CLASS_COUNT];
    let mut total = 0u32;
    for (class_index, request) in classes.iter().enumerate() {
        let Some(base) = class_bases.get_mut(class_index) else {
            return Err(GrantError::InvalidTopology);
        };
        let Some(count) = class_counts.get_mut(class_index) else {
            return Err(GrantError::InvalidTopology);
        };
        let Some(size) = slot_sizes.get_mut(class_index) else {
            return Err(GrantError::InvalidTopology);
        };
        if (request.slot_size == 0) != (request.slot_count == 0) {
            return Err(GrantError::InvalidTopology);
        }
        *base = total;
        *count = request.slot_count;
        *size = request.slot_size;
        total = total
            .checked_add(request.slot_count)
            .ok_or(GrantError::InvalidTopology)?;
    }

    let notification_class = usize::from(topology.notification_credit_class());
    let Some(&notification_count_capacity) = class_counts.get(notification_class) else {
        return Err(GrantError::InvalidTopology);
    };
    let Some(&notification_slot_size) = slot_sizes.get(notification_class) else {
        return Err(GrantError::InvalidTopology);
    };
    if topology.ring_count() == 0
        || topology.notification_credit_count() < topology.ring_count()
        || topology.notification_credit_count() > notification_count_capacity
        || topology.notification_credit_size() == 0
        || topology.notification_credit_size() > notification_slot_size
    {
        return Err(GrantError::InvalidTopology);
    }

    let required = usize::try_from(total).map_err(|_| GrantError::InvalidTopology)?;
    Ok(GrantTableLayout {
        class_bases,
        class_counts,
        slot_sizes,
        notification_credit_class: topology.notification_credit_class(),
        notification_credit_count: topology.notification_credit_count(),
        notification_credit_size: topology.notification_credit_size(),
        ring_count: topology.ring_count(),
        required,
    })
}

pub struct GrantTable<'a> {
    entries: &'a mut [GrantEntry],
    table_id: GrantTableId,
    session_epoch: u64,
    class_bases: [u32; SLOT_CLASS_COUNT],
    class_counts: [u32; SLOT_CLASS_COUNT],
    slot_sizes: [u32; SLOT_CLASS_COUNT],
    notification_credit_class: u8,
    notification_credit_count: u32,
    notification_credit_size: u32,
    ring_count: u32,
}

impl<'a> GrantTable<'a> {
    pub fn initialize(
        entries: &'a mut [GrantEntry],
        topology: &ValidatedTopology,
        session_epoch: u64,
    ) -> Result<Self, GrantError> {
        Self::initialize_with_table_id_source(
            entries,
            topology,
            session_epoch,
            &NEXT_GRANT_TABLE_ID,
        )
    }

    /// The identity SETUP stored after issue. ENTER drain must reopen with it.
    pub const fn identity(&self) -> GrantTableIdentity {
        GrantTableIdentity(self.table_id.0)
    }

    /// Reopen an already-issued table. Does not mint a new identity and does
    /// not require FREE entries; a second `initialize` on that backing is
    /// `InvalidBacking`.
    pub fn attach(
        entries: &'a mut [GrantEntry],
        topology: &ValidatedTopology,
        session_epoch: u64,
        identity: GrantTableIdentity,
    ) -> Result<Self, GrantError> {
        let layout = grant_table_layout(topology, session_epoch)?;
        if entries.len() != layout.required {
            return Err(GrantError::InvalidBacking);
        }
        Ok(Self::from_layout(
            entries,
            GrantTableId(identity.0),
            session_epoch,
            layout,
        ))
    }

    fn initialize_with_table_id_source(
        entries: &'a mut [GrantEntry],
        topology: &ValidatedTopology,
        session_epoch: u64,
        next_table_id: &AtomicU64,
    ) -> Result<Self, GrantError> {
        let layout = grant_table_layout(topology, session_epoch)?;
        if entries.len() != layout.required
            || entries.iter().any(|entry| *entry != GrantEntry::FREE)
        {
            return Err(GrantError::InvalidBacking);
        }

        let table_id = allocate_grant_table_id(next_table_id)?;
        Ok(Self::from_layout(entries, table_id, session_epoch, layout))
    }

    fn from_layout(
        entries: &'a mut [GrantEntry],
        table_id: GrantTableId,
        session_epoch: u64,
        layout: GrantTableLayout,
    ) -> Self {
        Self {
            entries,
            table_id,
            session_epoch,
            class_bases: layout.class_bases,
            class_counts: layout.class_counts,
            slot_sizes: layout.slot_sizes,
            notification_credit_class: layout.notification_credit_class,
            notification_credit_count: layout.notification_credit_count,
            notification_credit_size: layout.notification_credit_size,
            ring_count: layout.ring_count,
        }
    }

    pub fn issue_notification_credits(
        &mut self,
        output: &mut [NotificationCreditV1],
    ) -> Result<usize, GrantError> {
        let class = usize::from(self.notification_credit_class);
        if self.session_epoch == 0
            || self
                .slot_sizes
                .get(class)
                .is_none_or(|size| *size < self.notification_credit_size)
        {
            return Err(GrantError::InvalidTopology);
        }
        let count = usize::try_from(self.notification_credit_count)
            .map_err(|_| GrantError::InvalidTopology)?;
        if output.len() < count {
            return Err(GrantError::ReturnBufferTooSmall);
        }

        let base = *self
            .class_bases
            .get(class)
            .ok_or(GrantError::InvalidTopology)?;
        let end = base
            .checked_add(self.notification_credit_count)
            .ok_or(GrantError::InvalidTopology)?;
        let base = usize::try_from(base).map_err(|_| GrantError::InvalidTopology)?;
        let end = usize::try_from(end).map_err(|_| GrantError::InvalidTopology)?;
        let targets = self
            .entries
            .get(base..end)
            .ok_or(GrantError::InvalidTopology)?;
        if targets.iter().any(|entry| *entry != GrantEntry::FREE) {
            return Err(GrantError::InvalidBacking);
        }
        let Some(last_credit_index) = self.notification_credit_count.checked_sub(1) else {
            return Err(GrantError::InvalidTopology);
        };
        if SlotToken::try_new(self.notification_credit_class, last_credit_index, 1).is_err() {
            return Err(GrantError::InvalidTopology);
        }

        let targets = match self.entries.get_mut(base..end) {
            Some(targets) => targets,
            None => unreachable!("validated notification-credit entry range disappeared"),
        };
        let output = match output.get_mut(..count) {
            Some(output) => output,
            None => unreachable!("validated notification-credit output range disappeared"),
        };
        for ((entry, descriptor), ordinal) in targets
            .iter_mut()
            .zip(output.iter_mut())
            .zip(0..self.notification_credit_count)
        {
            let token = match SlotToken::try_new(self.notification_credit_class, ordinal, 1) {
                Ok(token) => token,
                Err(_) => unreachable!("validated notification-credit token became invalid"),
            };
            let ring_index = match ordinal.checked_rem(self.ring_count) {
                Some(ring_index) => ring_index,
                None => unreachable!("validated ring count became zero"),
            };
            let next_descriptor =
                credit_descriptor(token, ring_index, self.notification_credit_size);
            *entry = GrantEntry {
                slot_token: Some(token),
                ring_index,
                generation: 1,
                state: GrantState::Issued,
            };
            *descriptor = next_descriptor;
        }
        Ok(count)
    }

    pub fn preflight_notify(
        &self,
        ring_index: u32,
        token: SlotToken,
        return_bytes_available: usize,
        observed_generation: u64,
    ) -> Result<NotifyPreflight, GrantError> {
        let entry_index = self
            .canonical_entry_index(token)
            .ok_or(GrantError::InvalidToken)?;
        let index = usize::try_from(entry_index).map_err(|_| GrantError::InvalidToken)?;
        let entry = self.entries.get(index).ok_or(GrantError::InvalidToken)?;
        if matches!(entry.state, GrantState::Free | GrantState::Retired)
            || entry.slot_token.is_none()
        {
            return Err(GrantError::InvalidToken);
        }
        if ring_index >= self.ring_count || entry.ring_index != ring_index {
            return Err(GrantError::WrongRing);
        }
        if entry.state != GrantState::Issued
            || entry.slot_token != Some(token)
            || token.generation() != observed_generation
            || entry.generation != observed_generation
        {
            return Err(GrantError::StaleGeneration);
        }

        let next_generation = observed_generation.checked_add(1);
        let next_generation = next_generation.ok_or(GrantError::GenerationExhausted)?;
        let next_token = SlotToken::try_new(token.class(), token.index(), next_generation)
            .map_err(|_| GrantError::GenerationExhausted)?;
        if return_bytes_available < size_of::<NotificationCreditV1>() {
            return Err(GrantError::ReturnBufferTooSmall);
        }
        let next_descriptor =
            credit_descriptor(next_token, ring_index, self.notification_credit_size);
        Ok(NotifyPreflight {
            table_id: self.table_id,
            entry_index,
            ring_index,
            observed_generation,
            next_generation,
            next_descriptor,
        })
    }

    /// Claim one preflighted credit: validate, then perform the one mutation.
    ///
    /// Kept as the composition of the two halves below rather than as a second
    /// copy of the checks, so the predecessor path and the R5 branded path
    /// cannot drift into disagreeing about what a claim requires.
    pub fn claim_notify(
        &mut self,
        preflight: NotifyPreflight,
    ) -> Result<ClaimedNotification<'_>, GrantFault> {
        self.prepare_claim_notify(preflight)
            .map(PreparedCreditClaim::commit)
    }

    /// Every check `claim_notify` makes, with the exact entry borrow retained
    /// and **nothing mutated**.
    ///
    /// The split exists because Task 20's ordering rule needs a boundary the
    /// composed form cannot express: the CQ mutation permit is arbitrated under
    /// the cancel spin lock, and the credit mutation must be the *first* thing
    /// that happens after it, with no fallible step in between. A refusal here
    /// leaves the table byte-for-byte unchanged, so the caller still owns an
    /// intact preflight and can abort.
    pub fn prepare_claim_notify(
        &mut self,
        preflight: NotifyPreflight,
    ) -> Result<PreparedCreditClaim<'_>, GrantFault> {
        if preflight.table_id != self.table_id {
            return Err(GrantFault::OutOfRange);
        }
        let index = usize::try_from(preflight.entry_index).map_err(|_| GrantFault::OutOfRange)?;
        let next_token = SlotToken::from_raw(preflight.next_descriptor.buffer.token)
            .map_err(|_| GrantFault::OutOfRange)?;
        if self.canonical_entry_index(next_token) != Some(preflight.entry_index)
            || next_token.generation() != preflight.next_generation
        {
            return Err(GrantFault::OutOfRange);
        }
        let entry = self.entries.get_mut(index).ok_or(GrantFault::OutOfRange)?;
        if preflight.ring_index >= self.ring_count
            || entry.ring_index != preflight.ring_index
            || preflight.next_descriptor.ring_index != preflight.ring_index
        {
            return Err(GrantFault::CrossRing);
        }
        if preflight.next_descriptor
            != credit_descriptor(
                next_token,
                preflight.ring_index,
                self.notification_credit_size,
            )
        {
            return Err(GrantFault::OutOfRange);
        }
        match entry.state {
            GrantState::Claimed => return Err(GrantFault::ConcurrentReuse),
            GrantState::Free | GrantState::Retired => return Err(GrantFault::OutOfRange),
            GrantState::Issued => {}
        }
        let old_token = entry.slot_token.ok_or(GrantFault::OutOfRange)?;
        if entry.generation != preflight.observed_generation
            || old_token.generation() != preflight.observed_generation
        {
            return Err(GrantFault::Duplicate);
        }
        if old_token.class() != next_token.class()
            || old_token.index() != next_token.index()
            || preflight.observed_generation.checked_add(1) != Some(preflight.next_generation)
        {
            return Err(GrantFault::OutOfRange);
        }

        Ok(PreparedCreditClaim {
            entry,
            ring_index: preflight.ring_index,
            old_generation: preflight.observed_generation,
            next_generation: preflight.next_generation,
            next_descriptor: preflight.next_descriptor,
        })
    }

    /// Where the body a notification's `OControl` names actually lives.
    ///
    /// Checked, not computed: the control's own offset and length must lie
    /// inside the slot its token names, so a control that pointed past its slot
    /// -- into the next class, or off the end of the arena -- is a refusal
    /// rather than a range the caller would later copy from.
    /// Named `grant_source_range` rather than `source_range` so the production
    /// graph can carry a row for it. Three packet types expose a `source_range`
    /// accessor, and a bare-identifier model makes four definitions one node --
    /// which cannot be staged at all. The accessors keep the short name because
    /// their only callers are the staged lane; this one does the work.
    pub fn grant_source_range(
        &self,
        geometry: &SlotArenaGeometry,
        token: SlotToken,
        control: &BufferRef,
    ) -> Result<GrantRange, GrantError> {
        let class = usize::from(token.class());
        let slot_size = *self.slot_sizes.get(class).ok_or(GrantError::InvalidToken)?;
        let count = *self
            .class_counts
            .get(class)
            .ok_or(GrantError::InvalidToken)?;
        if token.index() >= count || slot_size == 0 {
            return Err(GrantError::InvalidToken);
        }
        if control.length == 0 {
            return Err(GrantError::InvalidToken);
        }
        let end = control
            .offset
            .checked_add(control.length)
            .ok_or(GrantError::InvalidToken)?;
        if end > slot_size {
            return Err(GrantError::InvalidToken);
        }
        let base = geometry.base_of(class).ok_or(GrantError::InvalidTopology)?;
        let slot_start = u64::from(token.index())
            .checked_mul(u64::from(slot_size))
            .and_then(|within| base.checked_add(within))
            .ok_or(GrantError::InvalidTopology)?;
        let arena_offset = slot_start
            .checked_add(u64::from(control.offset))
            .ok_or(GrantError::InvalidTopology)?;
        Ok(GrantRange {
            arena_offset,
            length: control.length,
        })
    }

    /// Plant one entry at an exact generation.
    ///
    /// `#[cfg(test)]`, and it exists because the state Step 6 fences on -- a
    /// credit whose generation has no successor -- is 2^64 refreshes away
    /// through the ordinary issue/refresh cycle. `grant::tests` reaches the
    /// fields directly because it is a child module; the adapter's drain tests
    /// are not, and a test that cannot build the state it fences on would be
    /// asserting about a branch nothing reaches.
    #[cfg(test)]
    pub(crate) fn force_entry_for_test(
        &mut self,
        token: SlotToken,
        generation: u64,
        ring_index: u32,
    ) -> Option<SlotToken> {
        let planted = SlotToken::try_new(token.class(), token.index(), generation).ok()?;
        let index = usize::try_from(self.canonical_entry_index(planted)?).ok()?;
        let entry = self.entries.get_mut(index)?;
        *entry = GrantEntry {
            slot_token: Some(planted),
            ring_index,
            generation,
            state: GrantState::Issued,
        };
        Some(planted)
    }

    pub fn retire_for_fence(&mut self) -> usize {
        let mut retired = 0usize;
        for entry in self.entries.iter_mut() {
            if matches!(entry.state, GrantState::Issued | GrantState::Claimed) {
                entry.state = GrantState::Retired;
                retired = match retired.checked_add(1) {
                    Some(next) => next,
                    None => unreachable!("entry slice length fits usize"),
                };
            }
        }
        retired
    }

    pub fn entry_snapshot(&self, token: SlotToken) -> Option<GrantEntrySnapshot> {
        let index = usize::try_from(self.canonical_entry_index(token)?).ok()?;
        let entry = self.entries.get(index)?;
        if entry.slot_token != Some(token) || entry.state == GrantState::Free {
            return None;
        }
        Some(GrantEntrySnapshot {
            token,
            ring_index: entry.ring_index,
            generation: entry.generation,
            state: entry.state,
        })
    }

    fn canonical_entry_index(&self, token: SlotToken) -> Option<u32> {
        let class = usize::from(token.class());
        let count = *self.class_counts.get(class)?;
        if token.index() >= count {
            return None;
        }
        self.class_bases.get(class)?.checked_add(token.index())
    }
}

fn credit_descriptor(
    token: SlotToken,
    ring_index: u32,
    notification_credit_size: u32,
) -> NotificationCreditV1 {
    NotificationCreditV1 {
        buffer: BufferRef {
            token: token.raw(),
            offset: 0,
            length: notification_credit_size,
            kind: buffer_kind::SLOT,
            access: buffer_access::U2K_WRITE,
            reserved: 0,
        },
        ring_index,
        reserved: 0,
    }
}

#[cfg(test)]
mod tests;

/// Retire every live entry of a table whose owner is gone.
///
/// A session fence must retire the credits of a table it did not just build,
/// and [`GrantTable::initialize`] deliberately refuses non-FREE backing, so a
/// fence cannot go back through it. This is the same transition
/// [`GrantTable::retire_for_fence`] performs, expressed over the backing alone:
/// no table identity is minted, so no preflight can be produced from it, and a
/// retired entry can never be claimed or refreshed again.
///
/// Idempotent, which is what lets a second fence attempt run without a second
/// count.
pub fn retire_entries_for_fence(entries: &mut [GrantEntry]) -> usize {
    let mut retired = 0usize;
    for entry in entries.iter_mut() {
        if matches!(entry.state, GrantState::Issued | GrantState::Claimed) {
            entry.state = GrantState::Retired;
            retired = retired.saturating_add(1);
        }
    }
    retired
}

/// Result of the one R3 checkpoint operation that retires both halves of the
/// predecessor notification-credit ledger.
///
/// Grant entries are the mutable issue/claim authority. The descriptor array
/// is the separately allocated native record handed to SETUP output. Keeping
/// the counts together makes it observable if production retires one half and
/// silently leaves the other populated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct R3CheckpointGrantCreditRetirement {
    grants_retired: usize,
    credit_descriptors_retired: usize,
}

impl R3CheckpointGrantCreditRetirement {
    pub const fn grants_retired(self) -> usize {
        self.grants_retired
    }

    pub const fn credit_descriptors_retired(self) -> usize {
        self.credit_descriptors_retired
    }

    /// Re-observe both exact ledgers after the consuming operation.
    pub fn complete(self, entries: &[GrantEntry], credits: &[NotificationCreditV1]) -> bool {
        let _ = self;
        entries
            .iter()
            .all(|entry| matches!(entry.state, GrantState::Free | GrantState::Retired))
            && credits
                .iter()
                .all(|credit| *credit == NotificationCreditV1::default())
    }
}

/// Retire the complete R3 grant/notification-credit state in one named native
/// operation.
///
/// This is idempotent for an already-retired checkpoint retry, but it is not a
/// no-op: every live grant becomes permanently `Retired` and every issued
/// descriptor is cleared from its separately owned backing.
pub fn retire_r3_grants_and_credits_for_checkpoint(
    entries: &mut [GrantEntry],
    credits: &mut [NotificationCreditV1],
) -> R3CheckpointGrantCreditRetirement {
    let grants_retired = retire_entries_for_fence(entries);
    let mut credit_descriptors_retired = 0usize;
    for credit in credits.iter_mut() {
        if *credit != NotificationCreditV1::default() {
            *credit = NotificationCreditV1::default();
            credit_descriptors_retired = credit_descriptors_retired
                .checked_add(1)
                .unwrap_or_else(|| unreachable!("a slice count fits usize"));
        }
    }
    R3CheckpointGrantCreditRetirement {
        grants_retired,
        credit_descriptors_retired,
    }
}
