use core::mem::size_of;

use crate::{
    codec::{try_decode, Pod},
    durable::{
        durable_child_kind, durable_committed_result_state, durable_immutable_request_state,
        durable_journal_state, durable_key_child_kind_v1, durable_key_digest_v1,
        durable_open_state, durable_prepare_state, durable_pt_epoch_intent_state,
        durable_pt_lane_state, durable_query_dir_attempt_state, durable_query_dir_cookie_state,
        durable_query_dir_snapshot_state, durable_record_charge_v1, provider_mount_root_state,
        retire_receipt_state, validate_durable_key_v1, validate_retire_receipt_key_v1,
        AccountingReservationV1, DurableChildValueV1, DurableKeyError, DurableKeyIdentityV1,
        DurableKeyV1, LatestProcessedV1, PrepareTxIndexValueV1, ProviderMountRootV1,
        RetireReceiptV1, DURABLE_ACCOUNTING_RESERVATION_BYTES, DURABLE_CHILD_VALUE_PREFIX_BYTES,
        DURABLE_LATEST_PROCESSED_BYTES, DURABLE_PREPARE_TX_INDEX_BYTES,
        DURABLE_PROVIDER_ROOT_BYTES, DURABLE_RETIRE_RECEIPT_KEY_BYTES,
        DURABLE_RETIRE_RECEIPT_VALUE_BYTES, PROVIDER_MOUNT_ROOT_VERSION,
    },
};

use super::is_dedicated_service_sid_v1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedDurableChildV1 {
    pub struct_size: u32,
    pub value_kind: u16,
    pub state: u16,
    pub identity_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub payload_offset: u32,
    pub payload_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableMetadataError {
    InvalidLength,
    Header,
    FlagsOrReserved,
    InvalidNamespace,
    InvalidKind,
    InvalidState,
    InvalidIdentity,
    InvalidServiceSid,
    InvalidPayloadShape,
    IdentityDigest,
    PayloadDigest,
    TailPadding,
    ChargeMismatch,
}

#[derive(Clone, Copy)]
pub(super) struct ValidatedDurableEnvelopeV1<'a> {
    pub(super) key: DurableKeyV1,
    pub(super) record: DurableChildValueV1,
    pub(super) payload: &'a [u8],
}

fn decode_exact<T: Pod>(input: &[u8], expected: usize) -> Result<T, DurableMetadataError> {
    if input.len() != expected {
        return Err(DurableMetadataError::InvalidLength);
    }
    try_decode(input).map_err(|_| DurableMetadataError::InvalidLength)
}

fn map_key_error(error: DurableKeyError) -> DurableMetadataError {
    match error {
        DurableKeyError::InvalidLength | DurableKeyError::InvalidTail => {
            DurableMetadataError::InvalidLength
        }
        DurableKeyError::InvalidNamespace => DurableMetadataError::InvalidNamespace,
        DurableKeyError::UnknownChildKind | DurableKeyError::UnknownExternalSubkind => {
            DurableMetadataError::InvalidKind
        }
        DurableKeyError::ZeroIdentity | DurableKeyError::InvalidLane => {
            DurableMetadataError::InvalidIdentity
        }
        DurableKeyError::BufferTooSmall => DurableMetadataError::InvalidLength,
    }
}

fn wrapped_state_is_valid(kind: u16, state: u16) -> bool {
    match kind {
        durable_child_kind::OPEN => {
            state == durable_open_state::LIVE || state == durable_open_state::CLEANED
        }
        durable_child_kind::PREPARE => state == durable_prepare_state::PREPARED,
        durable_child_kind::IMMUTABLE_REQUEST => state == durable_immutable_request_state::RETAINED,
        durable_child_kind::COMMITTED_RESULT => state == durable_committed_result_state::COMMITTED,
        durable_child_kind::JOURNAL => {
            state == durable_journal_state::PREPARED || state == durable_journal_state::COMMITTED
        }
        durable_child_kind::QUERY_DIR_SNAPSHOT => state == durable_query_dir_snapshot_state::ACTIVE,
        durable_child_kind::QUERY_DIR_ATTEMPT => state == durable_query_dir_attempt_state::ACCEPTED,
        durable_child_kind::QUERY_DIR_COOKIE => state == durable_query_dir_cookie_state::ACTIVE,
        durable_child_kind::PT_EPOCH_INTENT => {
            state == durable_pt_epoch_intent_state::PENDING
                || state == durable_pt_epoch_intent_state::ACCEPTED
                || state == durable_pt_epoch_intent_state::REVOKED
        }
        durable_child_kind::PT_LANE => state == durable_pt_lane_state::PRESENT,
        _ => false,
    }
}

fn wrapped_kind_is_supported(kind: u16) -> bool {
    matches!(
        kind,
        durable_child_kind::OPEN
            | durable_child_kind::PREPARE
            | durable_child_kind::IMMUTABLE_REQUEST
            | durable_child_kind::COMMITTED_RESULT
            | durable_child_kind::JOURNAL
            | durable_child_kind::QUERY_DIR_SNAPSHOT
            | durable_child_kind::QUERY_DIR_ATTEMPT
            | durable_child_kind::QUERY_DIR_COOKIE
            | durable_child_kind::PT_EPOCH_INTENT
            | durable_child_kind::PT_LANE
    )
}

fn checked_payload_range(
    value: &[u8],
    record: &DurableChildValueV1,
) -> Result<(usize, usize, usize), DurableMetadataError> {
    let prefix = DURABLE_CHILD_VALUE_PREFIX_BYTES as usize;
    let struct_size =
        usize::try_from(record.header.struct_size).map_err(|_| DurableMetadataError::Header)?;
    if struct_size != value.len() {
        return Err(DurableMetadataError::Header);
    }
    if record.payload.offset == 0 && record.payload.length == 0 {
        if struct_size != prefix {
            return Err(DurableMetadataError::InvalidPayloadShape);
        }
        return Ok((prefix, prefix, prefix));
    }
    if record.payload.offset != DURABLE_CHILD_VALUE_PREFIX_BYTES || record.payload.length == 0 {
        return Err(DurableMetadataError::InvalidPayloadShape);
    }
    let start = usize::try_from(record.payload.offset)
        .map_err(|_| DurableMetadataError::InvalidPayloadShape)?;
    let length = usize::try_from(record.payload.length)
        .map_err(|_| DurableMetadataError::InvalidPayloadShape)?;
    let end = start
        .checked_add(length)
        .ok_or(DurableMetadataError::InvalidPayloadShape)?;
    let rounded = end
        .checked_add(7)
        .ok_or(DurableMetadataError::InvalidPayloadShape)?;
    let aligned_end = rounded & !7;
    if aligned_end != struct_size || end > value.len() {
        return Err(DurableMetadataError::InvalidPayloadShape);
    }
    Ok((start, end, aligned_end))
}

pub fn validate_provider_mount_root_v1(
    key: &[u8],
    value: &[u8],
    ring_count: u32,
) -> Result<ProviderMountRootV1, DurableMetadataError> {
    if value.len() != DURABLE_PROVIDER_ROOT_BYTES as usize {
        return Err(DurableMetadataError::InvalidLength);
    }
    let parsed_key = validate_durable_key_v1(key, ring_count).map_err(map_key_error)?;
    if parsed_key.identity != DurableKeyIdentityV1::Root {
        return Err(DurableMetadataError::InvalidKind);
    }
    let record: ProviderMountRootV1 = decode_exact(value, DURABLE_PROVIDER_ROOT_BYTES as usize)?;
    if record.reserved.iter().any(|byte| *byte != 0) {
        return Err(DurableMetadataError::FlagsOrReserved);
    }
    if record.boot_instance_id == crate::BootInstanceId::ZERO
        || record.mount_id == crate::MountId::ZERO
        || record.latest_session_epoch == 0
    {
        return Err(DurableMetadataError::InvalidIdentity);
    }
    if record.boot_instance_id != parsed_key.namespace.boot_instance_id
        || record.mount_id != parsed_key.namespace.mount_id
    {
        return Err(DurableMetadataError::InvalidNamespace);
    }
    if record.service_sid_length != 32
        || !is_dedicated_service_sid_v1(
            record
                .service_sid
                .get(..32)
                .ok_or(DurableMetadataError::InvalidServiceSid)?,
        )
        || record
            .service_sid
            .get(32..)
            .ok_or(DurableMetadataError::InvalidServiceSid)?
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(DurableMetadataError::InvalidServiceSid);
    }
    if record.selected_features.words[1] != 0 || (record.selected_features.words[0] & !0x9f) != 0 {
        return Err(DurableMetadataError::FlagsOrReserved);
    }
    if record.version != PROVIDER_MOUNT_ROOT_VERSION {
        return Err(DurableMetadataError::InvalidState);
    }
    if record.state != provider_mount_root_state::ACTIVE
        && record.state != provider_mount_root_state::RECOVERING
        && record.state != provider_mount_root_state::RETIRING
    {
        return Err(DurableMetadataError::InvalidState);
    }
    if (record.selected_features.words[0] & 0x1c) != 0x1c || record.journal_version != 1 {
        return Err(DurableMetadataError::InvalidState);
    }
    Ok(record)
}

pub(super) fn validate_durable_envelope_v1<'a>(
    key: &[u8],
    value: &'a [u8],
    ring_count: u32,
) -> Result<ValidatedDurableEnvelopeV1<'a>, DurableMetadataError> {
    let prefix = DURABLE_CHILD_VALUE_PREFIX_BYTES as usize;
    if value.len() < prefix {
        return Err(DurableMetadataError::InvalidLength);
    }
    let parsed_key = validate_durable_key_v1(key, ring_count).map_err(map_key_error)?;
    let record: DurableChildValueV1 = try_decode(
        value
            .get(..prefix)
            .ok_or(DurableMetadataError::InvalidLength)?,
    )
    .map_err(|_| DurableMetadataError::InvalidLength)?;
    if record.header.struct_version != 1
        || record.header.required_flags != 0
        || usize::try_from(record.header.struct_size).map_err(|_| DurableMetadataError::Header)?
            != value.len()
    {
        return Err(DurableMetadataError::Header);
    }
    if record.flags != 0 {
        return Err(DurableMetadataError::FlagsOrReserved);
    }
    let key_kind = durable_key_child_kind_v1(parsed_key.identity);
    if record.value_kind != key_kind || !wrapped_kind_is_supported(key_kind) {
        return Err(DurableMetadataError::InvalidKind);
    }
    if !wrapped_state_is_valid(key_kind, record.state) {
        return Err(DurableMetadataError::InvalidState);
    }
    let (payload_start, payload_end, aligned_end) = checked_payload_range(value, &record)?;
    let expected_identity_digest = crate::digest::sha256_bytes(key);
    if record.identity_digest != expected_identity_digest {
        return Err(DurableMetadataError::IdentityDigest);
    }
    let payload = value
        .get(payload_start..payload_end)
        .ok_or(DurableMetadataError::InvalidPayloadShape)?;
    if record.payload_digest != crate::durable::durable_payload_digest_v1(payload) {
        return Err(DurableMetadataError::PayloadDigest);
    }
    if value
        .get(payload_end..aligned_end)
        .ok_or(DurableMetadataError::InvalidPayloadShape)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(DurableMetadataError::TailPadding);
    }
    Ok(ValidatedDurableEnvelopeV1 {
        key: parsed_key,
        record,
        payload,
    })
}

pub fn validate_durable_child_value_v1(
    key: &[u8],
    value: &[u8],
    ring_count: u32,
) -> Result<ValidatedDurableChildV1, DurableMetadataError> {
    let validated = validate_durable_envelope_v1(key, value, ring_count)?;
    Ok(ValidatedDurableChildV1 {
        struct_size: validated.record.header.struct_size,
        value_kind: validated.record.value_kind,
        state: validated.record.state,
        identity_digest: validated.record.identity_digest,
        payload_digest: validated.record.payload_digest,
        payload_offset: validated.record.payload.offset,
        payload_length: validated.record.payload.length,
    })
}

pub fn validate_accounting_reservation_v1(
    reservation_key: &[u8],
    reservation_value: &[u8],
    target_key: &[u8],
    target_value_bytes: u64,
    ring_count: u32,
) -> Result<AccountingReservationV1, DurableMetadataError> {
    if reservation_value.len() != DURABLE_ACCOUNTING_RESERVATION_BYTES as usize
        || reservation_key.len() != 66
        || target_key.len() < 34
        || target_key.len() > crate::durable::DURABLE_KEY_MAX_BYTES as usize
    {
        return Err(DurableMetadataError::InvalidLength);
    }
    let parsed_reservation =
        validate_durable_key_v1(reservation_key, ring_count).map_err(map_key_error)?;
    let reservation_digest = match parsed_reservation.identity {
        DurableKeyIdentityV1::AccountingReservation { target_key_digest } => target_key_digest,
        _ => return Err(DurableMetadataError::InvalidKind),
    };
    let parsed_target = validate_durable_key_v1(target_key, ring_count).map_err(map_key_error)?;
    if matches!(
        parsed_target.identity,
        DurableKeyIdentityV1::AccountingReservation { .. }
    ) {
        return Err(DurableMetadataError::InvalidKind);
    }
    if parsed_reservation.namespace != parsed_target.namespace {
        return Err(DurableMetadataError::InvalidNamespace);
    }
    let record: AccountingReservationV1 = decode_exact(
        reservation_value,
        DURABLE_ACCOUNTING_RESERVATION_BYTES as usize,
    )?;
    if record.flags != 0 {
        return Err(DurableMetadataError::FlagsOrReserved);
    }
    let target_kind = durable_key_child_kind_v1(parsed_target.identity);
    if record.target_child_kind != target_kind {
        return Err(DurableMetadataError::InvalidKind);
    }
    if usize::try_from(record.target_key_length).map_err(|_| DurableMetadataError::InvalidLength)?
        != target_key.len()
    {
        return Err(DurableMetadataError::InvalidLength);
    }
    let target_digest = durable_key_digest_v1(target_key, ring_count).map_err(map_key_error)?;
    if reservation_digest != record.target_key_digest || record.target_key_digest != target_digest {
        return Err(DurableMetadataError::IdentityDigest);
    }
    let target_key_bytes =
        u64::try_from(target_key.len()).map_err(|_| DurableMetadataError::ChargeMismatch)?;
    let expected_charge = durable_record_charge_v1(target_key_bytes, target_value_bytes)
        .map_err(|_| DurableMetadataError::ChargeMismatch)?;
    if record.charged_bytes != expected_charge {
        return Err(DurableMetadataError::ChargeMismatch);
    }
    Ok(record)
}

pub fn validate_prepare_tx_index_value_v1(
    key: &[u8],
    value: &[u8],
    ring_count: u32,
) -> Result<PrepareTxIndexValueV1, DurableMetadataError> {
    if value.len() != DURABLE_PREPARE_TX_INDEX_BYTES as usize {
        return Err(DurableMetadataError::InvalidLength);
    }
    let parsed_key = validate_durable_key_v1(key, ring_count).map_err(map_key_error)?;
    if !matches!(
        parsed_key.identity,
        DurableKeyIdentityV1::PrepareTxIndex { .. }
    ) {
        return Err(DurableMetadataError::InvalidKind);
    }
    let record: PrepareTxIndexValueV1 =
        decode_exact(value, DURABLE_PREPARE_TX_INDEX_BYTES as usize)?;
    if record.op_id == crate::OpId::ZERO {
        return Err(DurableMetadataError::InvalidIdentity);
    }
    let expected_digest = durable_key_digest_v1(key, ring_count).map_err(map_key_error)?;
    if record.identity_digest != expected_digest {
        return Err(DurableMetadataError::IdentityDigest);
    }
    Ok(record)
}

pub fn validate_latest_processed_v1(
    key: &[u8],
    value: &[u8],
    ring_count: u32,
) -> Result<LatestProcessedV1, DurableMetadataError> {
    if value.len() != DURABLE_LATEST_PROCESSED_BYTES as usize {
        return Err(DurableMetadataError::InvalidLength);
    }
    let parsed_key = validate_durable_key_v1(key, ring_count).map_err(map_key_error)?;
    if parsed_key.identity
        != (DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: crate::durable::ExternalNotifyKeyIdentityV1::LatestProcessed,
        })
    {
        return Err(DurableMetadataError::InvalidKind);
    }
    decode_exact(value, DURABLE_LATEST_PROCESSED_BYTES as usize)
}

/// Validate a durable external OUTBOX_ROW value: the stored canonical
/// `NotifyEnvelopeV2` DIR_CHANGE row whose first ordinal matches its key.
pub fn validate_external_outbox_row_v1(
    key: &[u8],
    value: &[u8],
    ring_count: u32,
) -> Result<(), DurableMetadataError> {
    let parsed_key = validate_durable_key_v1(key, ring_count).map_err(map_key_error)?;
    let first_ordinal = match parsed_key.identity {
        DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: crate::durable::ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal },
        } => first_ordinal,
        _ => return Err(DurableMetadataError::InvalidKind),
    };
    let validated = super::validate_notify_envelope_v2(value)
        .map_err(|_| DurableMetadataError::InvalidPayloadShape)?;
    match validated.body {
        super::ValidatedNotifyBodyV2::ExternalDirChange { body, .. } => {
            if body.first_ordinal != first_ordinal {
                return Err(DurableMetadataError::InvalidIdentity);
            }
            Ok(())
        }
        _ => Err(DurableMetadataError::InvalidKind),
    }
}

pub fn validate_durable_u64_value_v1(
    key: &[u8],
    value: &[u8],
    ring_count: u32,
) -> Result<u64, DurableMetadataError> {
    if value.len() != size_of::<u64>() {
        return Err(DurableMetadataError::InvalidLength);
    }
    let parsed_key = validate_durable_key_v1(key, ring_count).map_err(map_key_error)?;
    let valid_kind = matches!(
        parsed_key.identity,
        DurableKeyIdentityV1::PtEpochCounter { .. }
            | DurableKeyIdentityV1::VolumeCommitCounter
            | DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: crate::durable::ExternalNotifyKeyIdentityV1::OrdinalCounter,
            }
            | DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: crate::durable::ExternalNotifyKeyIdentityV1::AttachCut { .. },
            }
    );
    if !valid_kind {
        return Err(DurableMetadataError::InvalidKind);
    }
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| DurableMetadataError::InvalidLength)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn validate_retire_receipt_v1(
    key: &[u8],
    value: &[u8],
) -> Result<RetireReceiptV1, DurableMetadataError> {
    if key.len() != DURABLE_RETIRE_RECEIPT_KEY_BYTES as usize
        || value.len() != DURABLE_RETIRE_RECEIPT_VALUE_BYTES as usize
    {
        return Err(DurableMetadataError::InvalidLength);
    }
    validate_retire_receipt_key_v1(key).map_err(map_key_error)?;
    let record: RetireReceiptV1 = decode_exact(value, DURABLE_RETIRE_RECEIPT_VALUE_BYTES as usize)?;
    if record.reserved.iter().any(|byte| *byte != 0) {
        return Err(DurableMetadataError::FlagsOrReserved);
    }
    if record.state != retire_receipt_state::RECEIPT_PENDING_ACK {
        return Err(DurableMetadataError::InvalidState);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::{
        validate_accounting_reservation_v1, validate_durable_child_value_v1,
        validate_durable_u64_value_v1, validate_latest_processed_v1,
        validate_prepare_tx_index_value_v1, validate_provider_mount_root_v1,
        validate_retire_receipt_v1, DurableMetadataError,
    };

    #[test]
    fn every_validator_rejects_empty_slices() {
        let empty = &[];
        assert!(matches!(
            validate_provider_mount_root_v1(empty, empty, 1),
            Err(DurableMetadataError::InvalidLength)
        ));
        assert!(matches!(
            validate_durable_child_value_v1(empty, empty, 1),
            Err(DurableMetadataError::InvalidLength)
        ));
        assert!(matches!(
            validate_accounting_reservation_v1(empty, empty, empty, 0, 1),
            Err(DurableMetadataError::InvalidLength)
        ));
        assert!(matches!(
            validate_prepare_tx_index_value_v1(empty, empty, 1),
            Err(DurableMetadataError::InvalidLength)
        ));
        assert!(matches!(
            validate_latest_processed_v1(empty, empty, 1),
            Err(DurableMetadataError::InvalidLength)
        ));
        assert!(matches!(
            validate_durable_u64_value_v1(empty, empty, 1),
            Err(DurableMetadataError::InvalidLength)
        ));
        assert!(matches!(
            validate_retire_receipt_v1(empty, empty),
            Err(DurableMetadataError::InvalidLength)
        ));
    }
}
