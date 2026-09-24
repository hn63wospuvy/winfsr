use crate::{
    codec::{try_decode, Pod},
    control::{
        boot_context_init_state, boot_context_slot_offset_v1, boot_context_slot_state,
        checked_boot_context_publication_sequence, BootContextHeaderV1, BootContextSlotV1,
        BOOT_CONTEXT_HEADER_BYTES, BOOT_CONTEXT_MAGIC, BOOT_CONTEXT_SECTION_BYTES,
        BOOT_CONTEXT_SERVICE_SID_BYTES, BOOT_CONTEXT_SLOT_BYTES, BOOT_CONTEXT_SLOT_COUNT,
        BOOT_CONTEXT_USED_BYTES, BOOT_CONTEXT_VERSION,
    },
    digest::{boot_context_header_digest_v1, boot_context_slot_digest_v1},
};

/// Errors reported while validating a coherent, caller-owned private BootContext snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootContextValidationError {
    InvalidLength,
    SlotIndex,
    HeaderFormat,
    HeaderInitState,
    HeaderSequence,
    HeaderDigest,
    HeaderFlagsOrReserved,
    HeaderComplement,
    HeaderBootInstanceId,
    HeaderRetireKey,
    HeaderLoadGeneration,
    SlotState,
    SlotSequence,
    SlotDigest,
    SlotFlagsOrReserved,
    SlotFreeShape,
    SlotServiceSid,
    SlotBootInstanceId,
    SlotMountSequence,
    SlotMountId,
    SlotLoadGeneration,
    SlotSessionEpoch,
    SlotFeatures,
    SlotJournalVersion,
    DuplicateMountSequence,
    ImmutableTail,
}

fn decode_exact<T: Pod>(input: &[u8], expected: usize) -> Result<T, BootContextValidationError> {
    if input.len() != expected {
        return Err(BootContextValidationError::InvalidLength);
    }
    try_decode(input).map_err(|_| BootContextValidationError::InvalidLength)
}

fn fixed_or_reduce(bytes: &[u8; 32]) -> u8 {
    let mut aggregate = 0u8;
    let mut index = 0usize;
    while index < bytes.len() {
        aggregate |= bytes[index];
        index += 1;
    }
    aggregate
}

fn validate_header_record(header: &BootContextHeaderV1) -> Result<(), BootContextValidationError> {
    if header.magic != BOOT_CONTEXT_MAGIC
        || header.format_version != BOOT_CONTEXT_VERSION
        || header.header_size != BOOT_CONTEXT_HEADER_BYTES
        || header.context_size != BOOT_CONTEXT_SECTION_BYTES
        || header.slot_size != BOOT_CONTEXT_SLOT_BYTES
        || header.slot_count != BOOT_CONTEXT_SLOT_COUNT
    {
        return Err(BootContextValidationError::HeaderFormat);
    }
    if header.init_state != boot_context_init_state::READY {
        return Err(BootContextValidationError::HeaderInitState);
    }
    if header.header_sequence == 0 || header.header_sequence & 1 != 0 {
        return Err(BootContextValidationError::HeaderSequence);
    }
    if boot_context_header_digest_v1(header) != header.digest {
        return Err(BootContextValidationError::HeaderDigest);
    }
    if header.flags != 0 || header.reserved0 != 0 || header.reserved.iter().any(|byte| *byte != 0) {
        return Err(BootContextValidationError::HeaderFlagsOrReserved);
    }
    if header.mount_sequence_complement != (header.mount_sequence ^ u64::MAX)
        || header.load_generation_complement != (header.load_generation ^ u64::MAX)
    {
        return Err(BootContextValidationError::HeaderComplement);
    }
    if header.boot_instance_id.lo == 0 && header.boot_instance_id.hi == 0 {
        return Err(BootContextValidationError::HeaderBootInstanceId);
    }
    if fixed_or_reduce(&header.per_boot_retire_key) == 0 {
        return Err(BootContextValidationError::HeaderRetireKey);
    }
    if header.load_generation == 0 {
        return Err(BootContextValidationError::HeaderLoadGeneration);
    }
    Ok(())
}

/// Validates an exact privately captured stable BootContext header image.
///
/// `input` must be a caller-owned private copy, never a direct view, cast, or
/// borrow of a live mapped record. Runtime code must first complete the binding
/// seqlock/barrier capture protocol.
pub fn validate_boot_context_header_v1(
    input: &[u8],
) -> Result<BootContextHeaderV1, BootContextValidationError> {
    let header = decode_exact(input, BOOT_CONTEXT_HEADER_BYTES as usize)?;
    validate_header_record(&header)?;
    Ok(header)
}

fn validate_non_free_slot_common(
    header: &BootContextHeaderV1,
    slot: &BootContextSlotV1,
) -> Result<(), BootContextValidationError> {
    let sid_bytes = BOOT_CONTEXT_SERVICE_SID_BYTES as usize;
    if slot.service_sid_length != BOOT_CONTEXT_SERVICE_SID_BYTES
        || !is_dedicated_service_sid_v1(&slot.service_sid[..sid_bytes])
        || slot.service_sid[sid_bytes..].iter().any(|byte| *byte != 0)
    {
        return Err(BootContextValidationError::SlotServiceSid);
    }
    if slot.boot_instance_id.lo != header.boot_instance_id.lo
        || slot.boot_instance_id.hi != header.boot_instance_id.hi
    {
        return Err(BootContextValidationError::SlotBootInstanceId);
    }
    if slot.mount_sequence == 0
        || slot.mount_sequence > header.mount_sequence
        || slot.mount_id.lo != slot.mount_sequence
    {
        return Err(BootContextValidationError::SlotMountSequence);
    }
    if slot.mount_id.hi == 0 {
        return Err(BootContextValidationError::SlotMountId);
    }
    if slot.load_generation == 0 || slot.load_generation > header.load_generation {
        return Err(BootContextValidationError::SlotLoadGeneration);
    }
    if slot.latest_session_epoch == 0 {
        return Err(BootContextValidationError::SlotSessionEpoch);
    }
    if slot.selected_features.words[0] & !0x9f != 0
        || slot.selected_features.words[1] != 0
        || slot.selected_features.words[0] & 0x1c != 0x1c
    {
        return Err(BootContextValidationError::SlotFeatures);
    }
    if slot.journal_version != 1 {
        return Err(BootContextValidationError::SlotJournalVersion);
    }
    Ok(())
}

fn validate_slot_record(
    header: &BootContextHeaderV1,
    slot_index: u32,
    input: &[u8],
) -> Result<BootContextSlotV1, BootContextValidationError> {
    let slot: BootContextSlotV1 = decode_exact(input, BOOT_CONTEXT_SLOT_BYTES as usize)?;
    match slot.state {
        boot_context_slot_state::FREE
        | boot_context_slot_state::STAGING
        | boot_context_slot_state::LIVE
        | boot_context_slot_state::TERMINALIZING
        | boot_context_slot_state::TERMINAL => {}
        _ => return Err(BootContextValidationError::SlotState),
    }
    if slot.sequence == 0 || slot.sequence & 1 != 0 {
        return Err(BootContextValidationError::SlotSequence);
    }
    if boot_context_slot_digest_v1(slot_index, &slot) != Some(slot.digest) {
        return Err(BootContextValidationError::SlotDigest);
    }
    if slot.flags != 0 || slot.reserved.iter().any(|byte| *byte != 0) {
        return Err(BootContextValidationError::SlotFlagsOrReserved);
    }
    if slot.state == boot_context_slot_state::FREE {
        if input[8..224].iter().any(|byte| *byte != 0) {
            return Err(BootContextValidationError::SlotFreeShape);
        }
        return Ok(slot);
    }

    validate_non_free_slot_common(header, &slot)?;

    let (minimum_sequence, remaining_publications) = match slot.state {
        boot_context_slot_state::STAGING => (4, 4),
        boot_context_slot_state::LIVE => (6, 3),
        boot_context_slot_state::TERMINALIZING => (8, 2),
        boot_context_slot_state::TERMINAL => (8, 1),
        _ => return Err(BootContextValidationError::SlotState),
    };
    if slot.sequence < minimum_sequence
        || checked_boot_context_publication_sequence(slot.sequence, remaining_publications).is_err()
    {
        return Err(BootContextValidationError::SlotSequence);
    }
    if slot.state == boot_context_slot_state::STAGING {
        if slot.load_generation != header.load_generation {
            return Err(BootContextValidationError::SlotLoadGeneration);
        }
        if slot.latest_session_epoch != 1 {
            return Err(BootContextValidationError::SlotSessionEpoch);
        }
    }
    Ok(slot)
}

/// Validates an exact privately captured stable BootContext slot image.
///
/// Both `header` and `input` must come from caller-owned private copies, never
/// from direct views, casts, or borrows of a live mapped BootContext. Runtime
/// code must first complete the binding seqlock/barrier capture protocol.
pub fn validate_boot_context_slot_v1(
    header: &BootContextHeaderV1,
    slot_index: u32,
    input: &[u8],
) -> Result<BootContextSlotV1, BootContextValidationError> {
    if input.len() != BOOT_CONTEXT_SLOT_BYTES as usize {
        return Err(BootContextValidationError::InvalidLength);
    }
    if slot_index >= BOOT_CONTEXT_SLOT_COUNT {
        return Err(BootContextValidationError::SlotIndex);
    }
    validate_header_record(header)?;
    validate_slot_record(header, slot_index, input)
}

/// Validates an exact coherent, caller-owned private BootContext section image.
///
/// `snapshot` must be an offline frozen image, or an image assembled while the
/// runtime holds the named BootContext mutant/quiescence guarantee and captures
/// every record through the accepted seqlock/barrier protocol. A direct live
/// mapping view, flat `memcpy` from a live mapping, or unlocked set of records
/// captured across different publication times is forbidden.
pub fn validate_boot_context_section_v1(
    snapshot: &[u8],
) -> Result<BootContextHeaderV1, BootContextValidationError> {
    if snapshot.len() != BOOT_CONTEXT_SECTION_BYTES as usize {
        return Err(BootContextValidationError::InvalidLength);
    }
    let header = validate_boot_context_header_v1(&snapshot[..BOOT_CONTEXT_HEADER_BYTES as usize])?;
    let mut seen = [0u64; BOOT_CONTEXT_SLOT_COUNT as usize];
    let mut seen_len = 0usize;
    let mut index = 0u32;
    while index < BOOT_CONTEXT_SLOT_COUNT {
        let start = match boot_context_slot_offset_v1(index) {
            Some(value) => value as usize,
            None => return Err(BootContextValidationError::SlotIndex),
        };
        let end = match start.checked_add(BOOT_CONTEXT_SLOT_BYTES as usize) {
            Some(value) => value,
            None => return Err(BootContextValidationError::SlotIndex),
        };
        let slot = validate_slot_record(&header, index, &snapshot[start..end])?;
        if slot.state != boot_context_slot_state::FREE {
            if seen[..seen_len].contains(&slot.mount_sequence) {
                return Err(BootContextValidationError::DuplicateMountSequence);
            }
            seen[seen_len] = slot.mount_sequence;
            seen_len += 1;
        }
        index += 1;
    }
    if snapshot[BOOT_CONTEXT_USED_BYTES as usize..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(BootContextValidationError::ImmutableTail);
    }
    Ok(header)
}

/// Returns whether `service_sid` is the exact dedicated-service SID byte shape.
pub fn is_dedicated_service_sid_v1(service_sid: &[u8]) -> bool {
    service_sid.len() == 32
        && service_sid[0] == 1
        && service_sid[1] == 6
        && service_sid[2..8] == [0, 0, 0, 0, 0, 5]
        && u32::from_le_bytes([
            service_sid[8],
            service_sid[9],
            service_sid[10],
            service_sid[11],
        ]) == 80
}

#[cfg(test)]
mod tests {
    use super::is_dedicated_service_sid_v1;

    const SERVICE_SID: [u8; 32] = [
        1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0,
        0, 0,
    ];

    #[test]
    fn dedicated_service_sid_shape_is_exact() {
        assert!(is_dedicated_service_sid_v1(&SERVICE_SID));

        let mut zero_suffix = SERVICE_SID;
        zero_suffix[12..].fill(0);
        assert!(is_dedicated_service_sid_v1(&zero_suffix));

        let mut sized = [0u8; 69];
        sized[..SERVICE_SID.len()].copy_from_slice(&SERVICE_SID);
        for length in 0..=31 {
            assert!(!is_dedicated_service_sid_v1(&sized[..length]));
        }
        for length in 33..=69 {
            assert!(!is_dedicated_service_sid_v1(&sized[..length]));
        }

        for revision in [0, 2] {
            let mut malformed = SERVICE_SID;
            malformed[0] = revision;
            assert!(!is_dedicated_service_sid_v1(&malformed));
        }
        for count in [2, 5, 7] {
            let mut malformed = SERVICE_SID;
            malformed[1] = count;
            assert!(!is_dedicated_service_sid_v1(&malformed));
        }
        for authority_index in 2..8 {
            let mut malformed = SERVICE_SID;
            malformed[authority_index] ^= 1;
            assert!(!is_dedicated_service_sid_v1(&malformed));
        }
        for first_rid in [79u32, 81] {
            let mut malformed = SERVICE_SID;
            malformed[8..12].copy_from_slice(&first_rid.to_le_bytes());
            assert!(!is_dedicated_service_sid_v1(&malformed));
        }

        let mut generic_service_sid = [0u8; 16];
        generic_service_sid[..8].copy_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5]);
        generic_service_sid[8..12].copy_from_slice(&80u32.to_le_bytes());
        assert!(!is_dedicated_service_sid_v1(&generic_service_sid));
    }
}
