use crate::{BootInstanceId, FileId, MountId, OpId, TransactionId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableNamespaceV1 {
    pub mount_id: MountId,
    pub boot_instance_id: BootInstanceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalNotifyKeyIdentityV1 {
    OutboxRow { first_ordinal: u64 },
    LatestProcessed,
    OrdinalCounter,
    AttachCut { session_epoch: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableKeyIdentityV1 {
    Root,
    AccountingReservation {
        target_key_digest: [u8; 32],
    },
    Open {
        kernel_open_id: u64,
    },
    Prepare {
        op_id: OpId,
    },
    ImmutableRequest {
        op_id: OpId,
    },
    CommittedResult {
        op_id: OpId,
    },
    Journal {
        op_id: OpId,
    },
    QueryDirSnapshot {
        kernel_open_id: u64,
        generation: u64,
    },
    QueryDirAttempt {
        kernel_open_id: u64,
        generation: u64,
        input_cookie: u64,
        attempt_digest: [u8; 32],
    },
    QueryDirCookie {
        kernel_open_id: u64,
        generation: u64,
        cookie: u64,
    },
    PtEpochIntent {
        file_id: FileId,
        pt_epoch: u64,
    },
    PtEpochCounter {
        file_id: FileId,
    },
    PtLane {
        ring_index: u8,
        kind_ordinal: u8,
    },
    ExternalNotifyOutbox {
        identity: ExternalNotifyKeyIdentityV1,
    },
    VolumeCommitCounter,
    PrepareTxIndex {
        transaction_id: TransactionId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableKeyV1 {
    pub namespace: DurableNamespaceV1,
    pub identity: DurableKeyIdentityV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableKeyError {
    BufferTooSmall,
    InvalidLength,
    InvalidNamespace,
    UnknownChildKind,
    InvalidTail,
    ZeroIdentity,
    InvalidLane,
    UnknownExternalSubkind,
}

pub const fn encoded_durable_key_len_v1(identity: &DurableKeyIdentityV1) -> u32 {
    match identity {
        DurableKeyIdentityV1::Root | DurableKeyIdentityV1::VolumeCommitCounter => 34,
        DurableKeyIdentityV1::AccountingReservation { .. } => 66,
        DurableKeyIdentityV1::Open { .. } => 42,
        DurableKeyIdentityV1::Prepare { .. }
        | DurableKeyIdentityV1::ImmutableRequest { .. }
        | DurableKeyIdentityV1::CommittedResult { .. }
        | DurableKeyIdentityV1::Journal { .. }
        | DurableKeyIdentityV1::QueryDirSnapshot { .. }
        | DurableKeyIdentityV1::PtEpochCounter { .. }
        | DurableKeyIdentityV1::PrepareTxIndex { .. } => 50,
        DurableKeyIdentityV1::QueryDirAttempt { .. } => 90,
        DurableKeyIdentityV1::QueryDirCookie { .. }
        | DurableKeyIdentityV1::PtEpochIntent { .. } => 58,
        DurableKeyIdentityV1::PtLane { .. } => 36,
        DurableKeyIdentityV1::ExternalNotifyOutbox { identity } => match identity {
            ExternalNotifyKeyIdentityV1::OutboxRow { .. }
            | ExternalNotifyKeyIdentityV1::AttachCut { .. } => 44,
            ExternalNotifyKeyIdentityV1::LatestProcessed
            | ExternalNotifyKeyIdentityV1::OrdinalCounter => 36,
        },
    }
}

pub const fn max_durable_pt_lane_records_per_mount(ring_count: u32) -> Option<u32> {
    if ring_count == 0 || ring_count > 64 {
        None
    } else {
        ring_count.checked_mul(4)
    }
}

fn pair_is_nonzero(lo: u64, hi: u64) -> bool {
    lo != 0 || hi != 0
}

fn namespace_is_valid(namespace: DurableNamespaceV1) -> bool {
    pair_is_nonzero(namespace.mount_id.lo, namespace.mount_id.hi)
        && pair_is_nonzero(namespace.boot_instance_id.lo, namespace.boot_instance_id.hi)
}

fn validate_identity_for_encoding(identity: DurableKeyIdentityV1) -> Result<(), DurableKeyError> {
    match identity {
        DurableKeyIdentityV1::Root
        | DurableKeyIdentityV1::AccountingReservation { .. }
        | DurableKeyIdentityV1::VolumeCommitCounter => {}
        DurableKeyIdentityV1::Open { kernel_open_id } => {
            if kernel_open_id == 0 {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::Prepare { op_id }
        | DurableKeyIdentityV1::ImmutableRequest { op_id }
        | DurableKeyIdentityV1::CommittedResult { op_id }
        | DurableKeyIdentityV1::Journal { op_id } => {
            if !pair_is_nonzero(op_id.lo, op_id.hi) {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id,
            generation,
        } => {
            if kernel_open_id == 0 || generation == 0 {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id,
            generation,
            input_cookie,
            ..
        } => {
            if kernel_open_id == 0 || generation == 0 || input_cookie == 0 {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::QueryDirCookie {
            kernel_open_id,
            generation,
            cookie,
        } => {
            if kernel_open_id == 0 || generation == 0 || cookie == 0 {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::PtEpochIntent { file_id, pt_epoch } => {
            if !pair_is_nonzero(file_id.lo, file_id.hi) || pt_epoch == 0 {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::PtEpochCounter { file_id } => {
            if !pair_is_nonzero(file_id.lo, file_id.hi) {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
        DurableKeyIdentityV1::PtLane {
            ring_index,
            kind_ordinal,
        } => {
            if ring_index >= 64 || !(1..=2).contains(&kind_ordinal) {
                return Err(DurableKeyError::InvalidLane);
            }
        }
        DurableKeyIdentityV1::ExternalNotifyOutbox { identity } => match identity {
            ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal } => {
                if first_ordinal == 0 {
                    return Err(DurableKeyError::ZeroIdentity);
                }
            }
            ExternalNotifyKeyIdentityV1::LatestProcessed
            | ExternalNotifyKeyIdentityV1::OrdinalCounter => {}
            ExternalNotifyKeyIdentityV1::AttachCut { session_epoch } => {
                if session_epoch == 0 {
                    return Err(DurableKeyError::ZeroIdentity);
                }
            }
        },
        DurableKeyIdentityV1::PrepareTxIndex { transaction_id } => {
            if !pair_is_nonzero(transaction_id.lo, transaction_id.hi) {
                return Err(DurableKeyError::ZeroIdentity);
            }
        }
    }
    Ok(())
}

fn put_bytes(output: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), DurableKeyError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(DurableKeyError::BufferTooSmall)?;
    let destination = output
        .get_mut(offset..end)
        .ok_or(DurableKeyError::BufferTooSmall)?;
    destination.copy_from_slice(bytes);
    Ok(())
}

fn put_u8(output: &mut [u8], offset: usize, value: u8) -> Result<(), DurableKeyError> {
    put_bytes(output, offset, &[value])
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), DurableKeyError> {
    put_bytes(output, offset, &value.to_le_bytes())
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), DurableKeyError> {
    put_bytes(output, offset, &value.to_le_bytes())
}

fn put_pair(output: &mut [u8], offset: usize, lo: u64, hi: u64) -> Result<(), DurableKeyError> {
    put_u64(output, offset, lo)?;
    let high_offset = offset
        .checked_add(8)
        .ok_or(DurableKeyError::BufferTooSmall)?;
    put_u64(output, high_offset, hi)
}

fn put_namespace(output: &mut [u8], namespace: DurableNamespaceV1) -> Result<(), DurableKeyError> {
    put_pair(output, 0, namespace.mount_id.lo, namespace.mount_id.hi)?;
    put_pair(
        output,
        16,
        namespace.boot_instance_id.lo,
        namespace.boot_instance_id.hi,
    )
}

pub(crate) fn durable_key_child_kind_v1(identity: DurableKeyIdentityV1) -> u16 {
    use super::durable_child_kind;

    match identity {
        DurableKeyIdentityV1::Root => durable_child_kind::ROOT,
        DurableKeyIdentityV1::AccountingReservation { .. } => {
            durable_child_kind::ACCOUNTING_RESERVATION
        }
        DurableKeyIdentityV1::Open { .. } => durable_child_kind::OPEN,
        DurableKeyIdentityV1::Prepare { .. } => durable_child_kind::PREPARE,
        DurableKeyIdentityV1::ImmutableRequest { .. } => durable_child_kind::IMMUTABLE_REQUEST,
        DurableKeyIdentityV1::CommittedResult { .. } => durable_child_kind::COMMITTED_RESULT,
        DurableKeyIdentityV1::Journal { .. } => durable_child_kind::JOURNAL,
        DurableKeyIdentityV1::QueryDirSnapshot { .. } => durable_child_kind::QUERY_DIR_SNAPSHOT,
        DurableKeyIdentityV1::QueryDirAttempt { .. } => durable_child_kind::QUERY_DIR_ATTEMPT,
        DurableKeyIdentityV1::QueryDirCookie { .. } => durable_child_kind::QUERY_DIR_COOKIE,
        DurableKeyIdentityV1::PtEpochIntent { .. } => durable_child_kind::PT_EPOCH_INTENT,
        DurableKeyIdentityV1::PtEpochCounter { .. } => durable_child_kind::PT_EPOCH_COUNTER,
        DurableKeyIdentityV1::PtLane { .. } => durable_child_kind::PT_LANE,
        DurableKeyIdentityV1::ExternalNotifyOutbox { .. } => {
            durable_child_kind::EXTERNAL_NOTIFY_OUTBOX
        }
        DurableKeyIdentityV1::VolumeCommitCounter => durable_child_kind::VOLUME_COMMIT_COUNTER,
        DurableKeyIdentityV1::PrepareTxIndex { .. } => durable_child_kind::PREPARE_TX_INDEX,
    }
}

pub fn encode_durable_key_v1(
    key: &DurableKeyV1,
    output: &mut [u8],
) -> Result<usize, DurableKeyError> {
    let needed = encoded_durable_key_len_v1(&key.identity) as usize;
    if output.len() < needed {
        return Err(DurableKeyError::BufferTooSmall);
    }
    if !namespace_is_valid(key.namespace) {
        return Err(DurableKeyError::InvalidNamespace);
    }
    validate_identity_for_encoding(key.identity)?;

    let mut scratch = [0u8; super::DURABLE_KEY_MAX_BYTES as usize];
    put_namespace(&mut scratch, key.namespace)?;
    put_u16(&mut scratch, 32, durable_key_child_kind_v1(key.identity))?;
    match key.identity {
        DurableKeyIdentityV1::Root | DurableKeyIdentityV1::VolumeCommitCounter => {}
        DurableKeyIdentityV1::AccountingReservation { target_key_digest } => {
            put_bytes(&mut scratch, 34, &target_key_digest)?;
        }
        DurableKeyIdentityV1::Open { kernel_open_id } => {
            put_u64(&mut scratch, 34, kernel_open_id)?;
        }
        DurableKeyIdentityV1::Prepare { op_id }
        | DurableKeyIdentityV1::ImmutableRequest { op_id }
        | DurableKeyIdentityV1::CommittedResult { op_id }
        | DurableKeyIdentityV1::Journal { op_id } => {
            put_pair(&mut scratch, 34, op_id.lo, op_id.hi)?;
        }
        DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id,
            generation,
        } => {
            put_u64(&mut scratch, 34, kernel_open_id)?;
            put_u64(&mut scratch, 42, generation)?;
        }
        DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id,
            generation,
            input_cookie,
            attempt_digest,
        } => {
            put_u64(&mut scratch, 34, kernel_open_id)?;
            put_u64(&mut scratch, 42, generation)?;
            put_u64(&mut scratch, 50, input_cookie)?;
            put_bytes(&mut scratch, 58, &attempt_digest)?;
        }
        DurableKeyIdentityV1::QueryDirCookie {
            kernel_open_id,
            generation,
            cookie,
        } => {
            put_u64(&mut scratch, 34, kernel_open_id)?;
            put_u64(&mut scratch, 42, generation)?;
            put_u64(&mut scratch, 50, cookie)?;
        }
        DurableKeyIdentityV1::PtEpochIntent { file_id, pt_epoch } => {
            put_pair(&mut scratch, 34, file_id.lo, file_id.hi)?;
            put_u64(&mut scratch, 50, pt_epoch)?;
        }
        DurableKeyIdentityV1::PtEpochCounter { file_id } => {
            put_pair(&mut scratch, 34, file_id.lo, file_id.hi)?;
        }
        DurableKeyIdentityV1::PtLane {
            ring_index,
            kind_ordinal,
        } => {
            put_u8(&mut scratch, 34, ring_index)?;
            put_u8(&mut scratch, 35, kind_ordinal)?;
        }
        DurableKeyIdentityV1::ExternalNotifyOutbox { identity } => {
            use super::external_notify_subkind;
            match identity {
                ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal } => {
                    put_u16(&mut scratch, 34, external_notify_subkind::OUTBOX_ROW)?;
                    put_u64(&mut scratch, 36, first_ordinal)?;
                }
                ExternalNotifyKeyIdentityV1::LatestProcessed => {
                    put_u16(&mut scratch, 34, external_notify_subkind::LATEST_PROCESSED)?;
                }
                ExternalNotifyKeyIdentityV1::OrdinalCounter => {
                    put_u16(&mut scratch, 34, external_notify_subkind::ORDINAL_COUNTER)?;
                }
                ExternalNotifyKeyIdentityV1::AttachCut { session_epoch } => {
                    put_u16(&mut scratch, 34, external_notify_subkind::ATTACH_CUT)?;
                    put_u64(&mut scratch, 36, session_epoch)?;
                }
            }
        }
        DurableKeyIdentityV1::PrepareTxIndex { transaction_id } => {
            put_pair(&mut scratch, 34, transaction_id.lo, transaction_id.hi)?;
        }
    }

    let prefix = output
        .get_mut(..needed)
        .ok_or(DurableKeyError::BufferTooSmall)?;
    prefix.copy_from_slice(
        scratch
            .get(..needed)
            .ok_or(DurableKeyError::BufferTooSmall)?,
    );
    output
        .get_mut(needed..)
        .ok_or(DurableKeyError::BufferTooSmall)?
        .fill(0);
    Ok(needed)
}

pub fn encode_retire_receipt_key_v1(
    namespace: DurableNamespaceV1,
    output: &mut [u8],
) -> Result<usize, DurableKeyError> {
    let needed = super::DURABLE_RETIRE_RECEIPT_KEY_BYTES as usize;
    if output.len() < needed {
        return Err(DurableKeyError::BufferTooSmall);
    }
    if !namespace_is_valid(namespace) {
        return Err(DurableKeyError::InvalidNamespace);
    }

    let mut scratch = [0u8; super::DURABLE_RETIRE_RECEIPT_KEY_BYTES as usize];
    put_namespace(&mut scratch, namespace)?;
    output
        .get_mut(..needed)
        .ok_or(DurableKeyError::BufferTooSmall)?
        .copy_from_slice(&scratch);
    output
        .get_mut(needed..)
        .ok_or(DurableKeyError::BufferTooSmall)?
        .fill(0);
    Ok(needed)
}

fn read_bytes<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], DurableKeyError> {
    let end = offset.checked_add(N).ok_or(DurableKeyError::InvalidTail)?;
    let source = input.get(offset..end).ok_or(DurableKeyError::InvalidTail)?;
    let mut output = [0u8; N];
    output.copy_from_slice(source);
    Ok(output)
}

fn read_u8(input: &[u8], offset: usize) -> Result<u8, DurableKeyError> {
    input
        .get(offset)
        .copied()
        .ok_or(DurableKeyError::InvalidTail)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, DurableKeyError> {
    Ok(u16::from_le_bytes(read_bytes(input, offset)?))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, DurableKeyError> {
    Ok(u64::from_le_bytes(read_bytes(input, offset)?))
}

fn read_namespace(input: &[u8]) -> Result<DurableNamespaceV1, DurableKeyError> {
    Ok(DurableNamespaceV1 {
        mount_id: MountId {
            lo: read_u64(input, 0)?,
            hi: read_u64(input, 8)?,
        },
        boot_instance_id: BootInstanceId {
            lo: read_u64(input, 16)?,
            hi: read_u64(input, 24)?,
        },
    })
}

pub fn validate_durable_key_v1(
    input: &[u8],
    ring_count: u32,
) -> Result<DurableKeyV1, DurableKeyError> {
    use super::{durable_child_kind, external_notify_subkind};

    if input.len() < super::DURABLE_KEY_HEADER_BYTES as usize {
        return Err(DurableKeyError::InvalidLength);
    }
    let namespace = read_namespace(input)?;
    if !namespace_is_valid(namespace) {
        return Err(DurableKeyError::InvalidNamespace);
    }
    let kind = read_u16(input, 32)?;
    let expected_length = match kind {
        durable_child_kind::ROOT | durable_child_kind::VOLUME_COMMIT_COUNTER => 34,
        durable_child_kind::ACCOUNTING_RESERVATION => 66,
        durable_child_kind::OPEN => 42,
        durable_child_kind::PREPARE
        | durable_child_kind::IMMUTABLE_REQUEST
        | durable_child_kind::COMMITTED_RESULT
        | durable_child_kind::JOURNAL
        | durable_child_kind::QUERY_DIR_SNAPSHOT
        | durable_child_kind::PT_EPOCH_COUNTER
        | durable_child_kind::PREPARE_TX_INDEX => 50,
        durable_child_kind::QUERY_DIR_ATTEMPT => 90,
        durable_child_kind::QUERY_DIR_COOKIE | durable_child_kind::PT_EPOCH_INTENT => 58,
        durable_child_kind::PT_LANE => 36,
        durable_child_kind::EXTERNAL_NOTIFY_OUTBOX => {
            if input.len() != 36 && input.len() != 44 {
                return Err(DurableKeyError::InvalidTail);
            }
            match read_u16(input, 34)? {
                external_notify_subkind::OUTBOX_ROW | external_notify_subkind::ATTACH_CUT => 44,
                external_notify_subkind::LATEST_PROCESSED
                | external_notify_subkind::ORDINAL_COUNTER => 36,
                _ => return Err(DurableKeyError::UnknownExternalSubkind),
            }
        }
        _ => return Err(DurableKeyError::UnknownChildKind),
    };
    if input.len() != expected_length {
        return Err(DurableKeyError::InvalidTail);
    }

    let identity = match kind {
        durable_child_kind::ROOT => DurableKeyIdentityV1::Root,
        durable_child_kind::ACCOUNTING_RESERVATION => DurableKeyIdentityV1::AccountingReservation {
            target_key_digest: read_bytes(input, 34)?,
        },
        durable_child_kind::OPEN => DurableKeyIdentityV1::Open {
            kernel_open_id: read_u64(input, 34)?,
        },
        durable_child_kind::PREPARE => DurableKeyIdentityV1::Prepare {
            op_id: OpId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
        },
        durable_child_kind::IMMUTABLE_REQUEST => DurableKeyIdentityV1::ImmutableRequest {
            op_id: OpId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
        },
        durable_child_kind::COMMITTED_RESULT => DurableKeyIdentityV1::CommittedResult {
            op_id: OpId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
        },
        durable_child_kind::JOURNAL => DurableKeyIdentityV1::Journal {
            op_id: OpId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
        },
        durable_child_kind::QUERY_DIR_SNAPSHOT => DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id: read_u64(input, 34)?,
            generation: read_u64(input, 42)?,
        },
        durable_child_kind::QUERY_DIR_ATTEMPT => DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id: read_u64(input, 34)?,
            generation: read_u64(input, 42)?,
            input_cookie: read_u64(input, 50)?,
            attempt_digest: read_bytes(input, 58)?,
        },
        durable_child_kind::QUERY_DIR_COOKIE => DurableKeyIdentityV1::QueryDirCookie {
            kernel_open_id: read_u64(input, 34)?,
            generation: read_u64(input, 42)?,
            cookie: read_u64(input, 50)?,
        },
        durable_child_kind::PT_EPOCH_INTENT => DurableKeyIdentityV1::PtEpochIntent {
            file_id: FileId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
            pt_epoch: read_u64(input, 50)?,
        },
        durable_child_kind::PT_EPOCH_COUNTER => DurableKeyIdentityV1::PtEpochCounter {
            file_id: FileId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
        },
        durable_child_kind::PT_LANE => DurableKeyIdentityV1::PtLane {
            ring_index: read_u8(input, 34)?,
            kind_ordinal: read_u8(input, 35)?,
        },
        durable_child_kind::EXTERNAL_NOTIFY_OUTBOX => {
            let identity = match read_u16(input, 34)? {
                external_notify_subkind::OUTBOX_ROW => ExternalNotifyKeyIdentityV1::OutboxRow {
                    first_ordinal: read_u64(input, 36)?,
                },
                external_notify_subkind::LATEST_PROCESSED => {
                    ExternalNotifyKeyIdentityV1::LatestProcessed
                }
                external_notify_subkind::ORDINAL_COUNTER => {
                    ExternalNotifyKeyIdentityV1::OrdinalCounter
                }
                external_notify_subkind::ATTACH_CUT => ExternalNotifyKeyIdentityV1::AttachCut {
                    session_epoch: read_u64(input, 36)?,
                },
                _ => return Err(DurableKeyError::UnknownExternalSubkind),
            };
            DurableKeyIdentityV1::ExternalNotifyOutbox { identity }
        }
        durable_child_kind::VOLUME_COMMIT_COUNTER => DurableKeyIdentityV1::VolumeCommitCounter,
        durable_child_kind::PREPARE_TX_INDEX => DurableKeyIdentityV1::PrepareTxIndex {
            transaction_id: TransactionId {
                lo: read_u64(input, 34)?,
                hi: read_u64(input, 42)?,
            },
        },
        _ => return Err(DurableKeyError::UnknownChildKind),
    };
    validate_identity_for_encoding(identity)?;
    if ring_count == 0 || ring_count > 64 {
        return Err(DurableKeyError::InvalidLane);
    }
    if let DurableKeyIdentityV1::PtLane { ring_index, .. } = identity {
        if u32::from(ring_index) >= ring_count {
            return Err(DurableKeyError::InvalidLane);
        }
    }
    Ok(DurableKeyV1 {
        namespace,
        identity,
    })
}

pub fn validate_retire_receipt_key_v1(input: &[u8]) -> Result<DurableNamespaceV1, DurableKeyError> {
    if input.len() != super::DURABLE_RETIRE_RECEIPT_KEY_BYTES as usize {
        return Err(DurableKeyError::InvalidLength);
    }
    let namespace = read_namespace(input)?;
    if !namespace_is_valid(namespace) {
        return Err(DurableKeyError::InvalidNamespace);
    }
    Ok(namespace)
}

pub fn durable_key_digest_v1(input: &[u8], ring_count: u32) -> Result<[u8; 32], DurableKeyError> {
    validate_durable_key_v1(input, ring_count)?;
    Ok(crate::digest::sha256_bytes(input))
}

#[cfg(test)]
mod tests {
    use super::{
        encode_durable_key_v1, encode_retire_receipt_key_v1, encoded_durable_key_len_v1,
        max_durable_pt_lane_records_per_mount, validate_durable_key_v1,
        validate_retire_receipt_key_v1, DurableKeyError, DurableKeyIdentityV1, DurableKeyV1,
        DurableNamespaceV1, ExternalNotifyKeyIdentityV1,
    };
    use crate::{BootInstanceId, FileId, MountId, OpId, TransactionId};

    const NAMESPACE: DurableNamespaceV1 = DurableNamespaceV1 {
        mount_id: MountId { lo: 1, hi: 2 },
        boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
    };

    fn registered_identities() -> [DurableKeyIdentityV1; 19] {
        let op_id = OpId { lo: 1, hi: 2 };
        let file_id = FileId { lo: 3, hi: 4 };
        let transaction_id = TransactionId { lo: 5, hi: 6 };
        [
            DurableKeyIdentityV1::Root,
            DurableKeyIdentityV1::AccountingReservation {
                target_key_digest: [0; 32],
            },
            DurableKeyIdentityV1::Open { kernel_open_id: 1 },
            DurableKeyIdentityV1::Prepare { op_id },
            DurableKeyIdentityV1::ImmutableRequest { op_id },
            DurableKeyIdentityV1::CommittedResult { op_id },
            DurableKeyIdentityV1::Journal { op_id },
            DurableKeyIdentityV1::QueryDirSnapshot {
                kernel_open_id: 1,
                generation: 2,
            },
            DurableKeyIdentityV1::QueryDirAttempt {
                kernel_open_id: 1,
                generation: 2,
                input_cookie: 3,
                attempt_digest: [0; 32],
            },
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 1,
                generation: 2,
                cookie: 3,
            },
            DurableKeyIdentityV1::PtEpochIntent {
                file_id,
                pt_epoch: 1,
            },
            DurableKeyIdentityV1::PtEpochCounter { file_id },
            DurableKeyIdentityV1::PtLane {
                ring_index: 0,
                kind_ordinal: 1,
            },
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal: 1 },
            },
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::LatestProcessed,
            },
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::OrdinalCounter,
            },
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::AttachCut { session_epoch: 1 },
            },
            DurableKeyIdentityV1::VolumeCommitCounter,
            DurableKeyIdentityV1::PrepareTxIndex { transaction_id },
        ]
    }

    #[test]
    fn all_registered_key_lengths_are_exact() {
        let expected = [
            34, 66, 42, 50, 50, 50, 50, 50, 90, 58, 58, 50, 36, 44, 36, 36, 44, 34, 50,
        ];

        for (identity, expected) in registered_identities().into_iter().zip(expected) {
            assert_eq!(encoded_durable_key_len_v1(&identity), expected);
        }
    }

    #[test]
    fn pt_lane_bound_is_closed() {
        assert_eq!(max_durable_pt_lane_records_per_mount(0), None);
        assert_eq!(max_durable_pt_lane_records_per_mount(1), Some(4));
        assert_eq!(max_durable_pt_lane_records_per_mount(64), Some(256));
        assert_eq!(max_durable_pt_lane_records_per_mount(65), None);
    }

    #[test]
    fn all_registered_keys_round_trip_and_zero_output_tail() {
        for identity in registered_identities() {
            let key = DurableKeyV1 {
                namespace: NAMESPACE,
                identity,
            };
            let mut output = [0xa5; 128];
            let length = encode_durable_key_v1(&key, &mut output).unwrap();
            assert_eq!(length, encoded_durable_key_len_v1(&identity) as usize);
            assert!(output[length..].iter().all(|byte| *byte == 0));
            assert_eq!(validate_durable_key_v1(&output[..length], 64), Ok(key));
        }
    }

    #[test]
    fn encoder_failures_preserve_output() {
        let root = DurableKeyV1 {
            namespace: NAMESPACE,
            identity: DurableKeyIdentityV1::Root,
        };
        let mut short = [0xa5; 33];
        assert_eq!(
            encode_durable_key_v1(&root, &mut short),
            Err(DurableKeyError::BufferTooSmall)
        );
        assert_eq!(short, [0xa5; 33]);

        let mut invalid_lane = [0xa5; 128];
        assert_eq!(
            encode_durable_key_v1(
                &DurableKeyV1 {
                    namespace: NAMESPACE,
                    identity: DurableKeyIdentityV1::PtLane {
                        ring_index: 64,
                        kind_ordinal: 1,
                    },
                },
                &mut invalid_lane,
            ),
            Err(DurableKeyError::InvalidLane)
        );
        assert_eq!(invalid_lane, [0xa5; 128]);
    }

    #[test]
    fn receipt_key_is_the_exact_namespace() {
        let mut output = [0xa5; 64];
        assert_eq!(encode_retire_receipt_key_v1(NAMESPACE, &mut output), Ok(32));
        assert!(output[32..].iter().all(|byte| *byte == 0));
        assert_eq!(validate_retire_receipt_key_v1(&output[..32]), Ok(NAMESPACE));
    }
}
