use core::{convert::TryFrom, mem::size_of};

use crate::{
    codec::{try_decode, Pod},
    durable::{
        DurableKeyIdentityV1, JournalStateV1, OpenRecoveryPayloadV1, PrepareRecoveryPayloadV1,
        PtEpochIntentPayloadV1, PtLanePayloadV1, QueryDirCookiePayloadV1,
        QueryDirSnapshotPayloadV1, IMMUTABLE_REQUEST_DIGEST_BYTES, JOURNAL_STATE_V1_BYTES,
        OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES, PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES,
        PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES, PT_LANE_PAYLOAD_V1_PREFIX_BYTES,
        QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES, QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES,
    },
    limits::{
        MAX_BACKING_PATH_BYTES, MAX_BACKING_SECTOR_SIZE, MAX_FILE_SIZE, MIN_BACKING_PATH_BYTES,
        MIN_BACKING_SECTOR_SIZE,
    },
    msgs::{BlobSlice, ControlHeader, SizeState},
    AckToken, FileId,
};

use super::{
    durable::{validate_durable_envelope_v1, ValidatedDurableEnvelopeV1},
    is_canonical_backing_device_path, DurableMetadataError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurablePayloadError {
    Envelope(DurableMetadataError),
    InvalidLength,
    Header,
    FlagsOrReserved,
    Identity,
    InvalidScalar,
    SliceShape,
    Relationship,
}

pub enum ValidatedDurablePayloadV1<'a> {
    Open {
        prefix: OpenRecoveryPayloadV1,
        name: &'a [u8],
        security_descriptor: &'a [u8],
    },
    Prepare {
        prefix: PrepareRecoveryPayloadV1,
        name: &'a [u8],
        requested_security_descriptor: &'a [u8],
        ea: &'a [u8],
        result_security_descriptor: &'a [u8],
    },
    ImmutableRequest {
        operation_digest: [u8; 32],
        semantic_bytes: &'a [u8],
    },
    CommittedResult {
        bytes: &'a [u8],
    },
    Journal {
        record: JournalStateV1,
    },
    QueryDirSnapshot {
        prefix: QueryDirSnapshotPayloadV1,
        entries: &'a [u8],
    },
    QueryDirAttempt {
        bytes: &'a [u8],
    },
    QueryDirCookie {
        record: QueryDirCookiePayloadV1,
    },
    PtEpochIntent {
        prefix: PtEpochIntentPayloadV1,
        backing_path: &'a [u8],
    },
    PtLane {
        prefix: PtLanePayloadV1,
        pending_envelope: Option<&'a [u8]>,
    },
}

struct TailCursor<'a> {
    bytes: &'a [u8],
    next: u32,
}

impl<'a> TailCursor<'a> {
    fn new(bytes: &'a [u8], prefix: u32) -> Self {
        Self {
            bytes,
            next: prefix,
        }
    }

    fn take(&mut self, slice: BlobSlice, required: bool) -> Result<&'a [u8], DurablePayloadError> {
        if slice.offset == 0 && slice.length == 0 {
            return if required {
                Err(DurablePayloadError::SliceShape)
            } else {
                let empty =
                    usize::try_from(self.next).map_err(|_| DurablePayloadError::SliceShape)?;
                self.bytes
                    .get(empty..empty)
                    .ok_or(DurablePayloadError::SliceShape)
            };
        }
        if slice.offset != self.next || slice.length == 0 {
            return Err(DurablePayloadError::SliceShape);
        }
        let end = slice
            .offset
            .checked_add(slice.length)
            .ok_or(DurablePayloadError::SliceShape)?;
        let start = usize::try_from(slice.offset).map_err(|_| DurablePayloadError::SliceShape)?;
        let end_usize = usize::try_from(end).map_err(|_| DurablePayloadError::SliceShape)?;
        let result = self
            .bytes
            .get(start..end_usize)
            .ok_or(DurablePayloadError::SliceShape)?;
        self.next = end;
        Ok(result)
    }

    fn finish(self) -> Result<(), DurablePayloadError> {
        let aligned = self
            .next
            .checked_add(7)
            .map(|end| end & !7)
            .ok_or(DurablePayloadError::SliceShape)?;
        let aligned_usize =
            usize::try_from(aligned).map_err(|_| DurablePayloadError::SliceShape)?;
        if aligned_usize != self.bytes.len() {
            return Err(DurablePayloadError::SliceShape);
        }
        let end = usize::try_from(self.next).map_err(|_| DurablePayloadError::SliceShape)?;
        if self
            .bytes
            .get(end..aligned_usize)
            .ok_or(DurablePayloadError::SliceShape)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(DurablePayloadError::SliceShape);
        }
        Ok(())
    }
}

fn decode_prefix<T: Pod>(payload: &[u8], prefix_bytes: u32) -> Result<T, DurablePayloadError> {
    let prefix = usize::try_from(prefix_bytes).map_err(|_| DurablePayloadError::InvalidLength)?;
    if payload.len() < prefix {
        return Err(DurablePayloadError::InvalidLength);
    }
    let header: ControlHeader = try_decode(
        payload
            .get(..size_of::<ControlHeader>())
            .ok_or(DurablePayloadError::InvalidLength)?,
    )
    .map_err(|_| DurablePayloadError::InvalidLength)?;
    if header.struct_version != 1
        || header.required_flags != 0
        || usize::try_from(header.struct_size).map_err(|_| DurablePayloadError::Header)?
            != payload.len()
        || header.struct_size % 8 != 0
    {
        return Err(DurablePayloadError::Header);
    }
    try_decode(
        payload
            .get(..prefix)
            .ok_or(DurablePayloadError::InvalidLength)?,
    )
    .map_err(|_| DurablePayloadError::InvalidLength)
}

fn decode_exact<T: Pod>(payload: &[u8], exact_bytes: u32) -> Result<T, DurablePayloadError> {
    if payload.len()
        != usize::try_from(exact_bytes).map_err(|_| DurablePayloadError::InvalidLength)?
    {
        return Err(DurablePayloadError::InvalidLength);
    }
    decode_prefix(payload, exact_bytes)
}

fn validate_generic_control_blob(bytes: &[u8]) -> Result<(), DurablePayloadError> {
    if bytes.len() < size_of::<ControlHeader>() {
        return Err(DurablePayloadError::InvalidLength);
    }
    let header: ControlHeader = try_decode(
        bytes
            .get(..size_of::<ControlHeader>())
            .ok_or(DurablePayloadError::InvalidLength)?,
    )
    .map_err(|_| DurablePayloadError::InvalidLength)?;
    if header.struct_version != 1
        || header.required_flags != 0
        || usize::try_from(header.struct_size).map_err(|_| DurablePayloadError::Header)?
            != bytes.len()
        || header.struct_size < 8
        || header.struct_size % 8 != 0
    {
        return Err(DurablePayloadError::Header);
    }
    Ok(())
}

fn pair_nonzero(lo: u64, hi: u64) -> bool {
    lo != 0 || hi != 0
}

fn sizes_have_valid_scalars(value: SizeState) -> bool {
    value.allocation_size <= MAX_FILE_SIZE
        && value.file_size <= MAX_FILE_SIZE
        && value.valid_data_length <= MAX_FILE_SIZE
        && value.size_epoch != 0
}

fn sizes_are_ordered(value: SizeState) -> bool {
    value.allocation_size >= value.file_size && value.file_size >= value.valid_data_length
}

fn validate_open<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
    key_kernel_open_id: u64,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let prefix: OpenRecoveryPayloadV1 =
        decode_prefix(envelope.payload, OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES)?;
    if prefix.kernel_open_id != 0 && prefix.kernel_open_id != key_kernel_open_id {
        return Err(DurablePayloadError::Identity);
    }
    if prefix.kernel_open_id == 0
        || !pair_nonzero(prefix.file_id.lo, prefix.file_id.hi)
        || !pair_nonzero(prefix.link_id.lo, prefix.link_id.hi)
        || !pair_nonzero(prefix.parent_id.lo, prefix.parent_id.hi)
        || prefix.namespace_generation == 0
        || prefix.security_generation == 0
        || !sizes_have_valid_scalars(prefix.sizes)
    {
        return Err(DurablePayloadError::InvalidScalar);
    }
    let mut cursor = TailCursor::new(envelope.payload, OPEN_RECOVERY_PAYLOAD_V1_PREFIX_BYTES);
    let name = cursor.take(prefix.name, false)?;
    let security_descriptor = cursor.take(prefix.security_descriptor, false)?;
    cursor.finish()?;
    if !sizes_are_ordered(prefix.sizes) {
        return Err(DurablePayloadError::Relationship);
    }
    Ok(ValidatedDurablePayloadV1::Open {
        prefix,
        name,
        security_descriptor,
    })
}

fn validate_prepare<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let prefix: PrepareRecoveryPayloadV1 =
        decode_prefix(envelope.payload, PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES)?;
    if prefix.open_flags != 0 || prefix.result_object_flags != 0 || prefix.reserved != 0 {
        return Err(DurablePayloadError::FlagsOrReserved);
    }
    if !pair_nonzero(prefix.parent_id.lo, prefix.parent_id.hi)
        || !pair_nonzero(prefix.transaction_id.lo, prefix.transaction_id.hi)
        || !pair_nonzero(prefix.result_file_id.lo, prefix.result_file_id.hi)
        || !pair_nonzero(prefix.result_link_id.lo, prefix.result_link_id.hi)
        || prefix.result_namespace_generation == 0
        || prefix.result_security_generation == 0
        || !sizes_have_valid_scalars(prefix.result_sizes)
    {
        return Err(DurablePayloadError::InvalidScalar);
    }
    let mut cursor = TailCursor::new(envelope.payload, PREPARE_RECOVERY_PAYLOAD_V1_PREFIX_BYTES);
    let name = cursor.take(prefix.name, false)?;
    let requested_security_descriptor = cursor.take(prefix.requested_security_descriptor, false)?;
    let ea = cursor.take(prefix.ea, false)?;
    let result_security_descriptor = cursor.take(prefix.result_security_descriptor, false)?;
    cursor.finish()?;
    if !sizes_are_ordered(prefix.result_sizes) {
        return Err(DurablePayloadError::Relationship);
    }
    Ok(ValidatedDurablePayloadV1::Prepare {
        prefix,
        name,
        requested_security_descriptor,
        ea,
        result_security_descriptor,
    })
}

fn validate_immutable_request<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let digest_bytes = usize::try_from(IMMUTABLE_REQUEST_DIGEST_BYTES)
        .map_err(|_| DurablePayloadError::InvalidLength)?;
    if envelope.payload.len() < digest_bytes {
        return Err(DurablePayloadError::InvalidLength);
    }
    let mut operation_digest = [0u8; 32];
    operation_digest.copy_from_slice(
        envelope
            .payload
            .get(..digest_bytes)
            .ok_or(DurablePayloadError::InvalidLength)?,
    );
    let semantic_bytes = envelope
        .payload
        .get(digest_bytes..)
        .ok_or(DurablePayloadError::InvalidLength)?;
    Ok(ValidatedDurablePayloadV1::ImmutableRequest {
        operation_digest,
        semantic_bytes,
    })
}

fn validate_committed_result<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    validate_generic_control_blob(envelope.payload)?;
    Ok(ValidatedDurablePayloadV1::CommittedResult {
        bytes: envelope.payload,
    })
}

fn validate_journal<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
    key_op_id: crate::OpId,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let record: JournalStateV1 = decode_exact(envelope.payload, JOURNAL_STATE_V1_BYTES)?;
    if record.op_id != crate::OpId::ZERO && record.op_id != key_op_id {
        return Err(DurablePayloadError::Identity);
    }
    if record.op_id == crate::OpId::ZERO {
        return Err(DurablePayloadError::InvalidScalar);
    }
    if record.state != u32::from(envelope.record.state) {
        return Err(DurablePayloadError::Relationship);
    }
    Ok(ValidatedDurablePayloadV1::Journal { record })
}

fn validate_query_dir_snapshot<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let prefix: QueryDirSnapshotPayloadV1 =
        decode_prefix(envelope.payload, QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES)?;
    let mut cursor = TailCursor::new(envelope.payload, QUERY_DIR_SNAPSHOT_PAYLOAD_V1_PREFIX_BYTES);
    let entries = cursor.take(prefix.entries, false)?;
    cursor.finish()?;
    if (prefix.entry_count == 0) != entries.is_empty() {
        return Err(DurablePayloadError::Relationship);
    }
    Ok(ValidatedDurablePayloadV1::QueryDirSnapshot { prefix, entries })
}

fn validate_query_dir_attempt<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    validate_generic_control_blob(envelope.payload)?;
    Ok(ValidatedDurablePayloadV1::QueryDirAttempt {
        bytes: envelope.payload,
    })
}

fn validate_query_dir_cookie<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let record: QueryDirCookiePayloadV1 =
        decode_exact(envelope.payload, QUERY_DIR_COOKIE_PAYLOAD_V1_BYTES)?;
    if record.result_flags != 0 || record.reserved != 0 {
        return Err(DurablePayloadError::FlagsOrReserved);
    }
    Ok(ValidatedDurablePayloadV1::QueryDirCookie { record })
}

fn validate_pt_epoch_intent<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
    key_pt_epoch: u64,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let prefix: PtEpochIntentPayloadV1 =
        decode_prefix(envelope.payload, PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES)?;
    if prefix.flags != 0 {
        return Err(DurablePayloadError::FlagsOrReserved);
    }
    if prefix.pt_epoch != 0 && prefix.pt_epoch != key_pt_epoch {
        return Err(DurablePayloadError::Identity);
    }
    if prefix.pt_epoch == 0
        || !(MIN_BACKING_SECTOR_SIZE..=MAX_BACKING_SECTOR_SIZE).contains(&prefix.sector_size)
        || !prefix.sector_size.is_power_of_two()
        || !(MIN_BACKING_PATH_BYTES..=MAX_BACKING_PATH_BYTES).contains(&prefix.backing_path.length)
        || prefix.backing_path.length % 2 != 0
    {
        return Err(DurablePayloadError::InvalidScalar);
    }
    let candidate_end = prefix
        .backing_path
        .offset
        .checked_add(prefix.backing_path.length)
        .ok_or(DurablePayloadError::SliceShape)?;
    let candidate_start =
        usize::try_from(prefix.backing_path.offset).map_err(|_| DurablePayloadError::SliceShape)?;
    let candidate_end =
        usize::try_from(candidate_end).map_err(|_| DurablePayloadError::SliceShape)?;
    let candidate = envelope
        .payload
        .get(candidate_start..candidate_end)
        .ok_or(DurablePayloadError::SliceShape)?;
    if !is_canonical_backing_device_path(candidate) {
        return Err(DurablePayloadError::InvalidScalar);
    }
    let mut cursor = TailCursor::new(envelope.payload, PT_EPOCH_INTENT_PAYLOAD_V1_PREFIX_BYTES);
    let backing_path = cursor.take(prefix.backing_path, true)?;
    cursor.finish()?;
    Ok(ValidatedDurablePayloadV1::PtEpochIntent {
        prefix,
        backing_path,
    })
}

fn validate_pt_lane<'a>(
    envelope: ValidatedDurableEnvelopeV1<'a>,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let prefix: PtLanePayloadV1 = decode_prefix(envelope.payload, PT_LANE_PAYLOAD_V1_PREFIX_BYTES)?;
    if prefix.flags != 0 || prefix.reserved != 0 {
        return Err(DurablePayloadError::FlagsOrReserved);
    }
    let mut cursor = TailCursor::new(envelope.payload, PT_LANE_PAYLOAD_V1_PREFIX_BYTES);
    let pending = cursor.take(prefix.pending_envelope, false)?;
    cursor.finish()?;
    let pending_envelope = if prefix.pending_envelope.length == 0 {
        None
    } else {
        validate_generic_control_blob(pending)?;
        Some(pending)
    };
    let latest_tuple_is_zero = prefix.latest_token == AckToken::ZERO
        && prefix.latest_file_id == FileId::ZERO
        && prefix.latest_pt_epoch == 0
        && prefix.latest_notify_code == 0;
    if (prefix.high_watermark == 0 && (!latest_tuple_is_zero || pending_envelope.is_some()))
        || (prefix.high_watermark != 0 && latest_tuple_is_zero)
    {
        return Err(DurablePayloadError::Relationship);
    }
    Ok(ValidatedDurablePayloadV1::PtLane {
        prefix,
        pending_envelope,
    })
}

pub fn validate_durable_payload_v1<'a>(
    key: &[u8],
    value: &'a [u8],
    ring_count: u32,
) -> Result<ValidatedDurablePayloadV1<'a>, DurablePayloadError> {
    let envelope = validate_durable_envelope_v1(key, value, ring_count)
        .map_err(DurablePayloadError::Envelope)?;
    match envelope.key.identity {
        DurableKeyIdentityV1::Open { kernel_open_id } => validate_open(envelope, kernel_open_id),
        DurableKeyIdentityV1::Prepare { .. } => validate_prepare(envelope),
        DurableKeyIdentityV1::ImmutableRequest { .. } => validate_immutable_request(envelope),
        DurableKeyIdentityV1::CommittedResult { .. } => validate_committed_result(envelope),
        DurableKeyIdentityV1::Journal { op_id } => validate_journal(envelope, op_id),
        DurableKeyIdentityV1::QueryDirSnapshot { .. } => validate_query_dir_snapshot(envelope),
        DurableKeyIdentityV1::QueryDirAttempt { .. } => validate_query_dir_attempt(envelope),
        DurableKeyIdentityV1::QueryDirCookie { .. } => validate_query_dir_cookie(envelope),
        DurableKeyIdentityV1::PtEpochIntent { pt_epoch, .. } => {
            validate_pt_epoch_intent(envelope, pt_epoch)
        }
        DurableKeyIdentityV1::PtLane { .. } => validate_pt_lane(envelope),
        _ => Err(DurablePayloadError::Envelope(
            DurableMetadataError::InvalidKind,
        )),
    }
}
