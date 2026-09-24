//! ABI 2.1 generation-stamped slot capability tokens and checked slot arenas.
//!
//! crate::layout::SlotRef remains a byte-stable published helper, but it is
//! not the meaning of BufferRef.token in ABI 2.1.

use core::convert::TryFrom;

use crate::{
    ids::ReqId,
    layout::{RegionDesc, SlotClassDesc, SLOT_CLASS_COUNT},
    limits::{
        MAX_SECTION_BYTES, MAX_SLOT_COUNT, MAX_SLOT_SIZE, MIN_SLOT_COUNT, MIN_SLOT_SIZE,
        SLOT_ALIGNMENT, USER_VIEW_OFFSET_ALIGNMENT,
    },
    msgs::{buffer_access, buffer_kind, BufferRef},
    validate::CheckedRange64,
};

pub const SLOT_TOKEN_CLASS_MAX: u8 = 3;
pub const SLOT_TOKEN_INDEX_MAX: u32 = (1u32 << 20) - 1;
pub const SLOT_TOKEN_GENERATION_MAX: u64 = (1u64 << 42) - 1;

const SLOT_TOKEN_INDEX_SHIFT: u32 = 2;
const SLOT_TOKEN_GENERATION_SHIFT: u32 = 22;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotTokenError {
    ClassOutOfRange,
    IndexOutOfRange,
    ZeroGeneration,
    GenerationOutOfRange,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SlotToken(u64);

impl SlotToken {
    pub const fn try_new(class: u8, index: u32, generation: u64) -> Result<Self, SlotTokenError> {
        if class > SLOT_TOKEN_CLASS_MAX {
            return Err(SlotTokenError::ClassOutOfRange);
        }
        if index > SLOT_TOKEN_INDEX_MAX {
            return Err(SlotTokenError::IndexOutOfRange);
        }
        if generation == 0 {
            return Err(SlotTokenError::ZeroGeneration);
        }
        if generation > SLOT_TOKEN_GENERATION_MAX {
            return Err(SlotTokenError::GenerationOutOfRange);
        }
        Ok(Self(
            class as u64
                | (index as u64) << SLOT_TOKEN_INDEX_SHIFT
                | generation << SLOT_TOKEN_GENERATION_SHIFT,
        ))
    }

    pub const fn from_raw(raw: u64) -> Result<Self, SlotTokenError> {
        Self::try_new(
            (raw & SLOT_TOKEN_CLASS_MAX as u64) as u8,
            ((raw >> SLOT_TOKEN_INDEX_SHIFT) & SLOT_TOKEN_INDEX_MAX as u64) as u32,
            raw >> SLOT_TOKEN_GENERATION_SHIFT,
        )
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn class(self) -> u8 {
        (self.0 & SLOT_TOKEN_CLASS_MAX as u64) as u8
    }

    pub const fn index(self) -> u32 {
        ((self.0 >> SLOT_TOKEN_INDEX_SHIFT) & SLOT_TOKEN_INDEX_MAX as u64) as u32
    }

    pub const fn generation(self) -> u64 {
        self.0 >> SLOT_TOKEN_GENERATION_SHIFT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotLayoutError {
    InvalidSectionSize,
    InvalidArenaAlignment,
    ArenaOutOfBounds,
    InvalidInactiveClass,
    ActiveAfterInactive,
    InvalidSlotSize,
    InvalidSlotCount,
    InvalidClassAlignment,
    NonIncreasingSlotSize,
    PackingMismatch,
    ArithmeticOverflow,
    ArenaLengthMismatch,
    PaddingLengthMismatch,
    NonZeroPadding,
    NoActiveClasses,
    ClassOutOfRange,
    IndexOutOfRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotDirection {
    K2u,
    U2k,
}

/// Opaque proof that one copied arena descriptor set is exactly packed.
#[derive(Clone, Copy)]
pub struct ValidatedSlotArena {
    direction: SlotDirection,
    section_size: u64,
    arena: RegionDesc,
    classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    active_class_count: u8,
    final_padding: CheckedRange64,
}

impl ValidatedSlotArena {
    pub const fn direction(&self) -> SlotDirection {
        self.direction
    }

    pub const fn section_size(&self) -> u64 {
        self.section_size
    }

    pub const fn arena(&self) -> RegionDesc {
        self.arena
    }

    pub const fn active_class_count(&self) -> u8 {
        self.active_class_count
    }

    pub const fn final_padding(&self) -> CheckedRange64 {
        self.final_padding
    }
}

/// Opaque full-slot range resolved from a validated arena and SlotToken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedSlot {
    token: SlotToken,
    direction: SlotDirection,
    slot_size: u32,
    section_range: CheckedRange64,
}

impl ResolvedSlot {
    pub const fn token(self) -> SlotToken {
        self.token
    }

    pub const fn direction(self) -> SlotDirection {
        self.direction
    }

    pub const fn slot_size(self) -> u32 {
        self.slot_size
    }

    pub const fn section_range(self) -> CheckedRange64 {
        self.section_range
    }
}

fn checked_align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;
    let with_mask = value.checked_add(mask)?;
    Some(with_mask & !mask)
}

/// Validate one private numeric snapshot of exactly four slot-class descriptors.
pub fn validate_slot_arena(
    direction: SlotDirection,
    section_size: u64,
    arena: RegionDesc,
    classes: [SlotClassDesc; SLOT_CLASS_COUNT],
) -> Result<ValidatedSlotArena, SlotLayoutError> {
    if section_size == 0 || section_size > MAX_SECTION_BYTES {
        return Err(SlotLayoutError::InvalidSectionSize);
    }
    if arena.offset % USER_VIEW_OFFSET_ALIGNMENT != 0
        || arena.length == 0
        || arena.length % USER_VIEW_OFFSET_ALIGNMENT != 0
    {
        return Err(SlotLayoutError::InvalidArenaAlignment);
    }
    let arena_end = arena
        .offset
        .checked_add(arena.length)
        .ok_or(SlotLayoutError::ArithmeticOverflow)?;
    if arena_end > section_size {
        return Err(SlotLayoutError::ArenaOutOfBounds);
    }

    let mut cursor = arena.offset;
    let mut previous_slot_size = None;
    let mut active_class_count = 0u8;
    let mut saw_inactive = false;

    for class in &classes {
        if class.slot_size == 0 || class.slot_count == 0 {
            if class.slot_size != 0 || class.slot_count != 0 || class.data_offset != 0 {
                return Err(SlotLayoutError::InvalidInactiveClass);
            }
            saw_inactive = true;
            continue;
        }
        if saw_inactive {
            return Err(SlotLayoutError::ActiveAfterInactive);
        }
        if class.slot_size < MIN_SLOT_SIZE
            || class.slot_size > MAX_SLOT_SIZE
            || !class.slot_size.is_power_of_two()
        {
            return Err(SlotLayoutError::InvalidSlotSize);
        }
        if class.slot_count < MIN_SLOT_COUNT || class.slot_count > MAX_SLOT_COUNT {
            return Err(SlotLayoutError::InvalidSlotCount);
        }
        if class.data_offset % SLOT_ALIGNMENT != 0 {
            return Err(SlotLayoutError::InvalidClassAlignment);
        }
        if previous_slot_size
            .map(|previous| class.slot_size <= previous)
            .unwrap_or(false)
        {
            return Err(SlotLayoutError::NonIncreasingSlotSize);
        }

        let expected_offset =
            checked_align_up(cursor, SLOT_ALIGNMENT).ok_or(SlotLayoutError::ArithmeticOverflow)?;
        if class.data_offset != expected_offset {
            return Err(SlotLayoutError::PackingMismatch);
        }
        let class_length = u64::from(class.slot_size)
            .checked_mul(u64::from(class.slot_count))
            .ok_or(SlotLayoutError::ArithmeticOverflow)?;
        cursor = class
            .data_offset
            .checked_add(class_length)
            .ok_or(SlotLayoutError::ArithmeticOverflow)?;
        previous_slot_size = Some(class.slot_size);
        active_class_count = active_class_count
            .checked_add(1)
            .ok_or(SlotLayoutError::ArithmeticOverflow)?;
    }

    if active_class_count == 0 {
        return Err(SlotLayoutError::NoActiveClasses);
    }
    let aligned_end = checked_align_up(cursor, USER_VIEW_OFFSET_ALIGNMENT)
        .ok_or(SlotLayoutError::ArithmeticOverflow)?;
    if aligned_end != arena_end {
        return Err(SlotLayoutError::ArenaLengthMismatch);
    }

    Ok(ValidatedSlotArena {
        direction,
        section_size,
        arena,
        classes,
        active_class_count,
        final_padding: CheckedRange64 {
            start: cursor,
            end: arena_end,
        },
    })
}

/// Resolve a full slot. Grant validation owns generation equality and subranges.
pub fn resolve_slot(
    arena: &ValidatedSlotArena,
    token: SlotToken,
) -> Result<ResolvedSlot, SlotLayoutError> {
    let class = token.class();
    if class >= arena.active_class_count {
        return Err(SlotLayoutError::ClassOutOfRange);
    }
    let class_index = usize::from(class);
    let descriptor = arena.classes[class_index];

    let index = token.index();
    if index >= descriptor.slot_count {
        return Err(SlotLayoutError::IndexOutOfRange);
    }
    let relative = u64::from(index)
        .checked_mul(u64::from(descriptor.slot_size))
        .ok_or(SlotLayoutError::ArithmeticOverflow)?;
    let start = descriptor
        .data_offset
        .checked_add(relative)
        .ok_or(SlotLayoutError::ArithmeticOverflow)?;
    let end = start
        .checked_add(u64::from(descriptor.slot_size))
        .ok_or(SlotLayoutError::ArithmeticOverflow)?;

    Ok(ResolvedSlot {
        token,
        direction: arena.direction,
        slot_size: descriptor.slot_size,
        section_range: CheckedRange64 { start, end },
    })
}

/// Validate a private copy of exactly the final padding range.
pub fn validate_zeroed_padding(
    private_padding_snapshot: &[u8],
    expected_range: CheckedRange64,
) -> Result<(), SlotLayoutError> {
    let expected_length = expected_range
        .checked_len()
        .ok_or(SlotLayoutError::ArithmeticOverflow)?;
    let expected_length =
        usize::try_from(expected_length).map_err(|_| SlotLayoutError::ArithmeticOverflow)?;
    if private_padding_snapshot.len() != expected_length {
        return Err(SlotLayoutError::PaddingLengthMismatch);
    }
    if private_padding_snapshot.iter().any(|byte| *byte != 0) {
        return Err(SlotLayoutError::NonZeroPadding);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantOwner {
    /// Request-table identity. Raw `ReqId` zero is not allocatable.
    Request(ReqId),
    /// Prevalidated table identity; negotiated ring-count validation is external.
    NotificationCredit { ring_index: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantState {
    Live,
    Rundown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantCapability {
    Slot(ResolvedSlot),
    Mapping {
        /// Opaque mapping-table capability token; never decode it as a slot
        /// token or interpret it as a pointer.
        ///
        /// Selecting this variant presupposes that the caller already enforced
        /// the MAPPED_IO feature and the guarded mapping-table direction.
        token: u64,
        /// Mapping-relative capacity in bytes.
        length: u64,
    },
}

/// Immutable numeric snapshot of one live-table grant entry.
///
/// The caller must hold the real kernel grant- or mapping-table rundown/state
/// guard from the time this snapshot is taken through the last use of every
/// validation result derived from it. [`GrantState::Live`] is only a checked
/// snapshot field and does not replace that external guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantMetadata {
    pub capability: GrantCapability,
    pub session_epoch: u64,
    pub owner: GrantOwner,
    pub access: u16,
    /// Capability-relative live grant interval; end is exclusive.
    ///
    /// `CheckedRange64` is the checked numeric carrier here; these coordinates
    /// are not necessarily section-relative.
    pub maximum: CheckedRange64,
    pub state: GrantState,
    pub issued: BufferRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferRefPolicy {
    Exact,
    ShrinkOnly,
    DerivedSubrange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyBufferRule {
    Forbidden,
    Allowed,
}

/// Context required to validate a `BufferRef`.
///
/// For [`BufferRefRule::Grant`], the caller must keep the real external
/// rundown/state guard held from the grant snapshot through the last use of
/// the returned [`ValidatedBuffer`]. Copying this rule does not extend that
/// guard's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferRefRule<'a> {
    None,
    Grant {
        grant: &'a GrantMetadata,
        expected_session_epoch: u64,
        expected_owner: GrantOwner,
        policy: BufferRefPolicy,
        empty: EmptyBufferRule,
    },
}

/// Opaque contextual proof of a checked numeric buffer range.
///
/// A SLOT result stores an absolute section-relative range. A MAPPING result
/// stores a mapping-relative range. No pointer or borrow into shared memory is
/// retained. For a result produced from [`BufferRefRule::Grant`], the caller
/// must not use this value, including a copied value, after releasing the real
/// external rundown/state guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedBuffer {
    kind: u16,
    token: u64,
    range: CheckedRange64,
}

impl ValidatedBuffer {
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    pub const fn is_none(&self) -> bool {
        self.kind == buffer_kind::NONE
    }

    pub const fn slot_token(&self) -> Option<SlotToken> {
        if self.kind != buffer_kind::SLOT {
            return None;
        }
        match SlotToken::from_raw(self.token) {
            Ok(token) => Some(token),
            Err(_) => None,
        }
    }

    pub const fn mapping_token(&self) -> Option<u64> {
        if self.kind == buffer_kind::MAPPING {
            Some(self.token)
        } else {
            None
        }
    }

    /// Absolute section-relative range for a validated SLOT reference.
    pub const fn section_range(&self) -> Option<CheckedRange64> {
        if self.kind == buffer_kind::SLOT {
            Some(self.range)
        } else {
            None
        }
    }

    /// Mapping-relative range for a validated MAPPING reference.
    ///
    /// `CheckedRange64` is the checked numeric carrier here; these coordinates
    /// are not section-relative.
    pub const fn mapping_range(&self) -> Option<CheckedRange64> {
        if self.kind == buffer_kind::MAPPING {
            Some(self.range)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferRefError {
    InvalidNone,
    UnknownKind,
    UnknownAccess,
    NonZeroReserved,
    InvalidSlotToken,
    InvalidGrantMetadata,
    GrantNotLive,
    SessionEpochMismatch,
    OwnerMismatch,
    KindMismatch,
    CapabilityMismatch,
    AccessMismatch,
    EmptyNotAllowed,
    RangeOutOfBounds,
    EchoMismatch,
    LengthGrowth,
}

const fn is_known_buffer_kind(kind: u16) -> bool {
    matches!(
        kind,
        buffer_kind::NONE | buffer_kind::SLOT | buffer_kind::MAPPING
    )
}

const fn is_known_buffer_access(access: u16) -> bool {
    matches!(
        access,
        buffer_access::K2U_READ_ONLY | buffer_access::U2K_WRITE
    )
}

fn checked_buffer_range(reference: &BufferRef) -> Option<CheckedRange64> {
    let start = u64::from(reference.offset);
    let end = start.checked_add(u64::from(reference.length))?;
    Some(CheckedRange64 { start, end })
}

pub fn validate_grant_metadata(grant: &GrantMetadata) -> Result<(), BufferRefError> {
    if grant.session_epoch == 0 {
        return Err(BufferRefError::InvalidGrantMetadata);
    }
    if let GrantOwner::Request(request_id) = grant.owner {
        if request_id.raw() == 0 {
            return Err(BufferRefError::InvalidGrantMetadata);
        }
    }
    if !is_known_buffer_access(grant.access) {
        return Err(BufferRefError::InvalidGrantMetadata);
    }

    let (capability_kind, capability_token, capability_length) = match grant.capability {
        GrantCapability::Slot(slot) => {
            let required_access = match slot.direction() {
                SlotDirection::K2u => buffer_access::K2U_READ_ONLY,
                SlotDirection::U2k => buffer_access::U2K_WRITE,
            };
            if grant.access != required_access {
                return Err(BufferRefError::InvalidGrantMetadata);
            }
            (
                buffer_kind::SLOT,
                slot.token().raw(),
                u64::from(slot.slot_size()),
            )
        }
        GrantCapability::Mapping { token, length } => {
            if token == 0 || length == 0 {
                return Err(BufferRefError::InvalidGrantMetadata);
            }
            (buffer_kind::MAPPING, token, length)
        }
    };

    let capacity = CheckedRange64 {
        start: 0,
        end: capability_length,
    };
    if grant.maximum.start >= grant.maximum.end || !capacity.contains(grant.maximum) {
        return Err(BufferRefError::InvalidGrantMetadata);
    }

    let issued = &grant.issued;
    if issued.reserved != 0
        || !is_known_buffer_access(issued.access)
        || issued.access != grant.access
        || issued.kind != capability_kind
        || issued.token != capability_token
        || issued.length == 0
    {
        return Err(BufferRefError::InvalidGrantMetadata);
    }
    let issued_range = checked_buffer_range(issued).ok_or(BufferRefError::InvalidGrantMetadata)?;
    if !capacity.contains(issued_range) || !grant.maximum.contains(issued_range) {
        return Err(BufferRefError::InvalidGrantMetadata);
    }

    Ok(())
}

pub fn validate_buffer_ref(
    reference: &BufferRef,
    rule: &BufferRefRule<'_>,
) -> Result<ValidatedBuffer, BufferRefError> {
    match *rule {
        BufferRefRule::None => {
            if reference.token != 0
                || reference.offset != 0
                || reference.length != 0
                || reference.kind != buffer_kind::NONE
                || reference.access != 0
                || reference.reserved != 0
            {
                return Err(BufferRefError::InvalidNone);
            }
            Ok(ValidatedBuffer {
                kind: buffer_kind::NONE,
                token: 0,
                range: CheckedRange64 { start: 0, end: 0 },
            })
        }
        BufferRefRule::Grant {
            grant,
            expected_session_epoch,
            expected_owner,
            policy,
            empty,
        } => {
            validate_grant_metadata(grant)?;
            let issued_range =
                checked_buffer_range(&grant.issued).ok_or(BufferRefError::InvalidGrantMetadata)?;

            if reference.reserved != 0 {
                return Err(BufferRefError::NonZeroReserved);
            }
            if !is_known_buffer_kind(reference.kind) {
                return Err(BufferRefError::UnknownKind);
            }
            if !is_known_buffer_access(reference.access) {
                return Err(BufferRefError::UnknownAccess);
            }

            if grant.state != GrantState::Live {
                return Err(BufferRefError::GrantNotLive);
            }
            if grant.session_epoch != expected_session_epoch {
                return Err(BufferRefError::SessionEpochMismatch);
            }
            if grant.owner != expected_owner {
                return Err(BufferRefError::OwnerMismatch);
            }

            let capability_kind = match grant.capability {
                GrantCapability::Slot(_) => buffer_kind::SLOT,
                GrantCapability::Mapping { .. } => buffer_kind::MAPPING,
            };
            if reference.kind != capability_kind {
                return Err(BufferRefError::KindMismatch);
            }

            match grant.capability {
                GrantCapability::Slot(slot) => {
                    let candidate_token = SlotToken::from_raw(reference.token)
                        .map_err(|_| BufferRefError::InvalidSlotToken)?;
                    if candidate_token != slot.token() {
                        return Err(BufferRefError::CapabilityMismatch);
                    }
                }
                GrantCapability::Mapping { token, .. } => {
                    if reference.token != token {
                        return Err(BufferRefError::CapabilityMismatch);
                    }
                }
            }

            if reference.access != grant.access {
                return Err(BufferRefError::AccessMismatch);
            }
            if reference.length == 0 && empty == EmptyBufferRule::Forbidden {
                return Err(BufferRefError::EmptyNotAllowed);
            }

            let candidate_range =
                checked_buffer_range(reference).ok_or(BufferRefError::RangeOutOfBounds)?;
            let capability_length = match grant.capability {
                GrantCapability::Slot(slot) => u64::from(slot.slot_size()),
                GrantCapability::Mapping { length, .. } => length,
            };
            let capacity = CheckedRange64 {
                start: 0,
                end: capability_length,
            };
            if !capacity.contains(candidate_range) || !grant.maximum.contains(candidate_range) {
                return Err(BufferRefError::RangeOutOfBounds);
            }

            match policy {
                BufferRefPolicy::Exact => {
                    if reference.offset != grant.issued.offset
                        || reference.length != grant.issued.length
                    {
                        return Err(BufferRefError::EchoMismatch);
                    }
                }
                BufferRefPolicy::ShrinkOnly => {
                    if reference.offset != grant.issued.offset {
                        return Err(BufferRefError::EchoMismatch);
                    }
                    if reference.length > grant.issued.length {
                        return Err(BufferRefError::LengthGrowth);
                    }
                }
                BufferRefPolicy::DerivedSubrange => {
                    if !issued_range.contains(candidate_range) {
                        return Err(BufferRefError::RangeOutOfBounds);
                    }
                }
            }

            let range = match grant.capability {
                GrantCapability::Slot(slot) => {
                    let section_range = slot.section_range();
                    let start = section_range
                        .start
                        .checked_add(candidate_range.start)
                        .ok_or(BufferRefError::RangeOutOfBounds)?;
                    let end = section_range
                        .start
                        .checked_add(candidate_range.end)
                        .ok_or(BufferRefError::RangeOutOfBounds)?;
                    let absolute_range = CheckedRange64 { start, end };
                    if !section_range.contains(absolute_range) {
                        return Err(BufferRefError::RangeOutOfBounds);
                    }
                    absolute_range
                }
                GrantCapability::Mapping { .. } => candidate_range,
            };

            Ok(ValidatedBuffer {
                kind: reference.kind,
                token: reference.token,
                range,
            })
        }
    }
}
