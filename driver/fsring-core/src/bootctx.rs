//! Pure BootContext load and volatile mount-identity publication plans.
//!
//! Every input is a caller-owned private snapshot captured under the native
//! BootContext mutant. This module validates and plans byte images only; it
//! owns no mapping, mutant, permanent slot, or native side effect.

use fsring_abi::{
    BootInstanceId, MountId,
    codec::try_encode,
    control::{
        BOOT_CONTEXT_HEADER_BYTES, BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS,
        BOOT_CONTEXT_INITIAL_SEQUENCE, BOOT_CONTEXT_MAGIC, BOOT_CONTEXT_SECTION_BYTES,
        BOOT_CONTEXT_SLOT_BYTES, BOOT_CONTEXT_SLOT_COUNT, BOOT_CONTEXT_VERSION,
        BootContextHeaderV1, BootContextSlotV1, BootCounterError, BootIdentityError,
        BootSequenceError, boot_context_init_state, boot_context_slot_state,
        checked_boot_context_publication_sequence, checked_next_load_generation,
        checked_next_mount_sequence, mount_id_from_burned_sequence,
    },
    digest::boot_context_header_digest_v1,
    validate::{
        BootContextValidationError, validate_boot_context_header_v1, validate_boot_context_slot_v1,
    },
};

pub enum BootLoadPlan {
    Initialize(BootHeaderPublication),
    Adopt(BootHeaderPublication),
}

pub struct BootHeaderPublication {
    pub initial: BootContextHeaderV1,
    pub committed: BootContextHeaderV1,
}

pub struct MountBurnPlan {
    before: BootContextHeaderV1,
    committed: BootContextHeaderV1,
    mount_id: MountId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootPlanError {
    Validation(BootContextValidationError),
    ActivePermanentSlot,
    Publication(BootSequenceError),
    Counter(BootCounterError),
    Identity(BootIdentityError),
}

impl MountBurnPlan {
    pub const fn before(&self) -> BootContextHeaderV1 {
        self.before
    }

    pub const fn committed(&self) -> BootContextHeaderV1 {
        self.committed
    }

    pub const fn mount_id(&self) -> MountId {
        self.mount_id
    }
}

fn header_bytes(header: &BootContextHeaderV1) -> [u8; BOOT_CONTEXT_HEADER_BYTES as usize] {
    let mut bytes = [0u8; BOOT_CONTEXT_HEADER_BYTES as usize];
    let _ = try_encode(header, &mut bytes);
    bytes
}

fn slot_bytes(slot: &BootContextSlotV1) -> [u8; BOOT_CONTEXT_SLOT_BYTES as usize] {
    let mut bytes = [0u8; BOOT_CONTEXT_SLOT_BYTES as usize];
    let _ = try_encode(slot, &mut bytes);
    bytes
}

fn validate_header(header: &BootContextHeaderV1) -> Result<BootContextHeaderV1, BootPlanError> {
    validate_boot_context_header_v1(&header_bytes(header)).map_err(BootPlanError::Validation)
}

fn seal_header(header: &mut BootContextHeaderV1) {
    header.digest = [0; 32];
    header.digest = boot_context_header_digest_v1(header);
}

pub fn plan_new_context(
    boot_instance_id: BootInstanceId,
    per_boot_retire_key: [u8; 32],
) -> Result<BootLoadPlan, BootPlanError> {
    let mut committed = BootContextHeaderV1 {
        magic: BOOT_CONTEXT_MAGIC,
        format_version: BOOT_CONTEXT_VERSION,
        header_size: BOOT_CONTEXT_HEADER_BYTES,
        context_size: BOOT_CONTEXT_SECTION_BYTES,
        slot_size: BOOT_CONTEXT_SLOT_BYTES,
        slot_count: BOOT_CONTEXT_SLOT_COUNT,
        init_state: boot_context_init_state::READY,
        flags: 0,
        reserved0: 0,
        header_sequence: BOOT_CONTEXT_INITIAL_SEQUENCE,
        mount_sequence: 0,
        mount_sequence_complement: u64::MAX,
        load_generation: 1,
        load_generation_complement: 1 ^ u64::MAX,
        boot_instance_id,
        per_boot_retire_key,
        digest: [0; 32],
        reserved: [0; 96],
    };
    seal_header(&mut committed);
    validate_header(&committed)?;

    // A new all-zero section has no preceding stable image. The initializer
    // writes this odd/INITIALIZING image before filling the FREE slot records,
    // then Release-publishes the independently sealed READY image.
    let mut initial = committed;
    initial.init_state = boot_context_init_state::INITIALIZING;
    initial.header_sequence = 1;
    seal_header(&mut initial);

    Ok(BootLoadPlan::Initialize(BootHeaderPublication {
        initial,
        committed,
    }))
}

pub fn plan_existing_context(
    header: BootContextHeaderV1,
    slots: &[BootContextSlotV1],
) -> Result<BootLoadPlan, BootPlanError> {
    let header = validate_header(&header)?;
    if slots.len() != BOOT_CONTEXT_SLOT_COUNT as usize {
        return Err(BootPlanError::Validation(
            BootContextValidationError::InvalidLength,
        ));
    }

    let mut has_active_permanent_slot = false;
    for (index, slot) in slots.iter().enumerate() {
        let index = match u32::try_from(index) {
            Ok(index) => index,
            Err(_) => {
                return Err(BootPlanError::Validation(
                    BootContextValidationError::SlotIndex,
                ));
            }
        };
        let validated = validate_boot_context_slot_v1(&header, index, &slot_bytes(slot))
            .map_err(BootPlanError::Validation)?;
        if validated.state != boot_context_slot_state::FREE {
            has_active_permanent_slot = true;
        }
    }
    for (index, slot) in slots.iter().enumerate() {
        if slot.state != boot_context_slot_state::FREE
            && slots.iter().skip(index.saturating_add(1)).any(|other| {
                other.state != boot_context_slot_state::FREE
                    && other.mount_sequence == slot.mount_sequence
            })
        {
            return Err(BootPlanError::Validation(
                BootContextValidationError::DuplicateMountSequence,
            ));
        }
    }
    if has_active_permanent_slot {
        return Err(BootPlanError::ActivePermanentSlot);
    }

    let next_generation =
        checked_next_load_generation(header.load_generation).map_err(BootPlanError::Counter)?;
    let committed_sequence = checked_boot_context_publication_sequence(
        header.header_sequence,
        BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS,
    )
    .map_err(BootPlanError::Publication)?;

    // The in-progress publication is a sequence-only store. All other bytes
    // remain the previously validated stable image until the native adapter
    // writes the committed non-sequence words and finally the even sequence.
    let mut initial = header;
    initial.header_sequence |= 1;

    let mut committed = header;
    committed.header_sequence = committed_sequence;
    committed.load_generation = next_generation;
    committed.load_generation_complement = next_generation ^ u64::MAX;
    seal_header(&mut committed);

    Ok(BootLoadPlan::Adopt(BootHeaderPublication {
        initial,
        committed,
    }))
}

#[rustfmt::skip]
pub fn plan_mount_burn(
    header: &BootContextHeaderV1,
    random_high: u64,
) -> Result<MountBurnPlan, BootPlanError> {
    let header = validate_header(header)?;
    let next = checked_next_mount_sequence(header.mount_sequence).map_err(BootPlanError::Counter)?;
    let committed_sequence = checked_boot_context_publication_sequence(
        header.header_sequence,
        BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS,
    )
    .map_err(BootPlanError::Publication)?;
    let mount_id =
        mount_id_from_burned_sequence(next, random_high).map_err(BootPlanError::Identity)?;

    let mut committed = header;
    committed.header_sequence = committed_sequence;
    committed.mount_sequence = next;
    committed.mount_sequence_complement = next ^ u64::MAX;
    seal_header(&mut committed);

    Ok(MountBurnPlan {
        before: header,
        committed,
        mount_id,
    })
}

#[cfg(test)]
mod tests;
