//! Cross-protocol ABI 2.1 scalar bounds and request-index partitioning.

use crate::ids::REQ_INDEX_MAX;

/// cbindgen:ignore
pub const SLOT_ALIGNMENT: u64 = 64;
/// cbindgen:ignore
pub const USER_VIEW_OFFSET_ALIGNMENT: u64 = 65_536;
/// cbindgen:ignore
pub const MIN_SLOT_SIZE: u32 = 256;
/// cbindgen:ignore
pub const MAX_SLOT_SIZE: u32 = 16 * 1024 * 1024;
/// cbindgen:ignore
pub const MIN_SLOT_COUNT: u32 = 1;
/// cbindgen:ignore
pub const MAX_SLOT_COUNT: u32 = 1 << 20;

/// cbindgen:ignore
pub const MIN_RING_COUNT: u32 = 1;
/// cbindgen:ignore
pub const MAX_RING_COUNT: u32 = 64;
/// cbindgen:ignore
pub const MIN_SQ_CAPACITY: u32 = 8;
/// cbindgen:ignore
pub const MIN_CQ_CAPACITY: u32 = 2;
/// cbindgen:ignore
pub const MAX_SQ_CAPACITY: u32 = 65_536;
/// cbindgen:ignore
pub const MAX_CQ_CAPACITY: u32 = 65_536;
/// cbindgen:ignore
pub const MAX_INFLIGHT: u32 = 16_777_023;
pub const CONTROL_SQ_RESERVE_PER_RING: u32 = 4;
pub const SYSTEM_REQUEST_SLOTS_PER_RING: u32 = 3;
pub const SYSTEM_REQID_BASE: u32 = 16_777_023;
pub const GLOBAL_EXTERNAL_CHANGE_ACK_REQID: u32 = 16_777_215;

/// cbindgen:ignore
pub const MIN_NOTIFICATION_CREDIT_SIZE: u32 = 2_048;
/// cbindgen:ignore
pub const MAX_NOTIFICATION_CREDIT_SIZE: u32 = 65_536;
/// cbindgen:ignore
pub const MAX_NOTIFICATION_CREDITS_PER_RING: u32 = 64;
/// cbindgen:ignore
pub const MAX_NOTIFICATION_CREDITS_PER_SESSION: u32 = 1_024;
/// cbindgen:ignore
pub const MAX_NOTIFICATION_CREDIT_BYTES: u64 = 16 * 1024 * 1024;

/// cbindgen:ignore
pub const MIN_CONTROL_SLOT_SIZE: u32 = 131_072;
/// cbindgen:ignore
pub const MIN_K2U_PROGRESS_SLOTS_PER_RING: u32 = 4;
/// cbindgen:ignore
pub const MIN_U2K_PROGRESS_SLOTS_PER_RING: u32 = 2;

/// cbindgen:ignore
pub const MAX_ENTER_CQ_BUDGET: u32 = 4_096;
/// cbindgen:ignore
pub const MIN_BACKING_PATH_BYTES: u32 = 2;
/// cbindgen:ignore
pub const MAX_BACKING_PATH_BYTES: u32 = 32_760;
/// cbindgen:ignore
pub const MIN_BACKING_SECTOR_SIZE: u32 = 512;
/// cbindgen:ignore
pub const MAX_BACKING_SECTOR_SIZE: u32 = 65_536;
/// cbindgen:ignore
pub const RESTART_GRACE_TIMEOUT_MS: u32 = 30_000;

// ---- Wave 9 notification and external-change bounds (section 14) ------------

/// OR of every legal directory-notify completion filter bit (section 14.1).
/// cbindgen:ignore
pub const VALID_NOTIFY_FILTER_MASK: u32 = 0x0000_0fff;

/// The twelve directory-notify completion filter bits.
/// cbindgen:ignore
pub mod notify_filter {
    pub const FILE_NAME: u32 = 0x0000_0001;
    pub const DIR_NAME: u32 = 0x0000_0002;
    pub const ATTRIBUTES: u32 = 0x0000_0004;
    pub const SIZE: u32 = 0x0000_0008;
    pub const LAST_WRITE: u32 = 0x0000_0010;
    pub const LAST_ACCESS: u32 = 0x0000_0020;
    pub const CREATION: u32 = 0x0000_0040;
    pub const EA: u32 = 0x0000_0080;
    pub const SECURITY: u32 = 0x0000_0100;
    pub const STREAM_NAME: u32 = 0x0000_0200;
    pub const STREAM_SIZE: u32 = 0x0000_0400;
    pub const STREAM_WRITE: u32 = 0x0000_0800;
}

/// The five `FILE_NOTIFY_INFORMATION.Action` codes synthesized in base 2.1.
/// cbindgen:ignore
pub mod file_action {
    pub const ADDED: u32 = 1;
    pub const REMOVED: u32 = 2;
    pub const MODIFIED: u32 = 3;
    pub const RENAMED_OLD_NAME: u32 = 4;
    pub const RENAMED_NEW_NAME: u32 = 5;
}

/// Filter subset legal for an external MODIFY: no FILE_NAME/DIR_NAME name bit.
/// cbindgen:ignore
pub const EXTERNAL_MODIFY_FILTER_MASK: u32 = 0x0000_01fc;

/// External-change name bounds (2..=510 bytes, i.e. 1..=255 UTF-16 units).
/// cbindgen:ignore
pub const MIN_EXTERNAL_CHANGE_NAME_BYTES: u32 = 2;
/// cbindgen:ignore
pub const MAX_EXTERNAL_CHANGE_NAME_BYTES: u32 = 510;

/// One outstanding external-change record and one PT acknowledgement per lane.
/// cbindgen:ignore
pub const MAX_OUTSTANDING_EXTERNAL_CHANGE: u32 = 1;
/// cbindgen:ignore
pub const MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING: u32 = 1;

/// Precise external-outbox rows admit all but one reserved overflow slot and
/// all but the reserved overflow bytes of `MAX_DURABLE_EXTERNAL_OUTBOX_*`.
/// cbindgen:ignore
pub const MAX_PRECISE_EXTERNAL_OUTBOX_RECORDS: u32 = 4_095;
/// cbindgen:ignore
pub const EXTERNAL_OUTBOX_OVERFLOW_RESERVE_BYTES: u64 = 2_048;

/// Section 14.1 driver-owned Windows change-notify reference caps.
/// cbindgen:ignore
pub const MAX_NOTIFY_BUFFER_BYTES_PER_CCB: u32 = 1_048_576;
/// cbindgen:ignore
pub const MAX_NOTIFY_BUFFER_BYTES_PER_MOUNT: u64 = 67_108_864;
/// cbindgen:ignore
pub const MAX_NOTIFY_REGISTRATIONS_PER_MOUNT: u32 = 4_096;
/// cbindgen:ignore
pub const MAX_PENDING_NOTIFY_IRPS_PER_CCB: u32 = 64;
/// cbindgen:ignore
pub const MAX_PENDING_NOTIFY_IRPS_PER_MOUNT: u32 = 16_384;
/// cbindgen:ignore
pub const MAX_PENDING_NOTIFY_MDL_BYTES_PER_CCB: u32 = 4_194_304;
/// cbindgen:ignore
pub const MAX_PENDING_NOTIFY_MDL_BYTES_PER_MOUNT: u64 = 67_108_864;
/// cbindgen:ignore
pub const MAX_NOTIFY_PATH_COMPONENTS: u32 = 1_024;
/// cbindgen:ignore
pub const MAX_NOTIFY_RELATIVE_PATH_BYTES: u32 = 65_520;
/// cbindgen:ignore
pub const MAX_PRECISE_NOTIFY_LINKS_PER_LOCAL_OPERATION: u32 = 64;

/// Native `FILE_NOTIFY_INFORMATION` record shape (section 14.1). This is a
/// semantic reference helper, never a shared-memory wire type.
/// cbindgen:ignore
pub mod file_notify_information {
    pub const NEXT_ENTRY_OFFSET: u32 = 0;
    pub const ACTION: u32 = 4;
    pub const FILE_NAME_LENGTH: u32 = 8;
    pub const FILE_NAME: u32 = 12;
    pub const FIXED_PREFIX_BYTES: u32 = 12;
}

/// The `align4(12 + FileNameLength)` size of one non-final
/// `FILE_NOTIFY_INFORMATION` record; `None` on 32-bit overflow.
pub const fn file_notify_information_entry_len(file_name_length: u32) -> Option<u32> {
    match file_name_length.checked_add(file_notify_information::FIXED_PREFIX_BYTES) {
        Some(unaligned) => match unaligned.checked_add(3) {
            Some(padded) => Some(padded & !3),
            None => None,
        },
        None => None,
    }
}

/// cbindgen:ignore
pub const MAX_COMPONENT_UTF16_CODE_UNITS: u32 = 255;
/// cbindgen:ignore
pub const MIN_SECURITY_DESCRIPTOR_BYTES: u32 = 20;
/// cbindgen:ignore
pub const MAX_SECURITY_DESCRIPTOR_BYTES: u32 = 65_536;
/// cbindgen:ignore
pub const MAX_REPARSE_DATA_BYTES: u32 = 16_384;
/// cbindgen:ignore
pub const MAX_CONTROL_BLOB: u32 = 16_777_216;
/// cbindgen:ignore
pub const MAX_CANONICAL_DIR_ENTRY_BYTES: u32 = 648;

/// cbindgen:ignore
pub const MAX_SECTION_BYTES: u64 = 1_073_741_824;
/// cbindgen:ignore
pub const MAX_RETAINED_OPENS_PER_RING: u32 = 4_096;
/// cbindgen:ignore
pub const MAX_RETAINED_OPENS_PER_MOUNT: u32 = 262_144;
/// cbindgen:ignore
pub const MAX_RETAINED_OPENS_GLOBAL: u32 = 1_048_576;
/// cbindgen:ignore
pub const MAX_PENDING_ASYNC_IRPS_PER_IO_OWNER: u32 = 1_024;
/// cbindgen:ignore
pub const MAX_PENDING_ASYNC_IRPS_PER_MOUNT: u32 = 16_384;
/// cbindgen:ignore
pub const MAX_PENDING_ASYNC_IRPS_GLOBAL: u32 = 65_536;
/// cbindgen:ignore
pub const MAX_PENDING_ASYNC_MDL_BYTES_PER_IO_OWNER: u64 = 67_108_864;
/// cbindgen:ignore
pub const MAX_PENDING_ASYNC_MDL_BYTES_PER_MOUNT: u64 = 268_435_456;
/// cbindgen:ignore
pub const MAX_PENDING_ASYNC_MDL_BYTES_GLOBAL: u64 = 1_073_741_824;

/// Largest nonnegative value that can be represented by a Windows LARGE_INTEGER.
pub const MAX_FILE_SIZE: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    ZeroLength,
    WholeStreamOffsetNonZero,
    OffsetOutOfRange,
    LengthOutOfRange,
    Overflow,
    EndOutOfRange,
}

/// Validate an unsigned wire file range before conversion to native signed sizes.
pub const fn validate_file_range(
    offset: u64,
    length: u64,
    zero_means_whole: bool,
) -> Result<(), RangeError> {
    if length == 0 {
        if !zero_means_whole {
            return Err(RangeError::ZeroLength);
        }
        return if offset == 0 {
            Ok(())
        } else {
            Err(RangeError::WholeStreamOffsetNonZero)
        };
    }
    if offset >= MAX_FILE_SIZE {
        return Err(RangeError::OffsetOutOfRange);
    }
    if length > MAX_FILE_SIZE {
        return Err(RangeError::LengthOutOfRange);
    }
    let end = match offset.checked_add(length) {
        Some(end) => end,
        None => return Err(RangeError::Overflow),
    };
    if end > MAX_FILE_SIZE {
        return Err(RangeError::EndOutOfRange);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqIndexClass {
    Application { index: u32 },
    OpenLifecycle { ring_index: u32 },
    PtRouteAck { ring_index: u32 },
    PtExternalSafeAck { ring_index: u32 },
    ExternalChangeAck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqIndexError {
    RingCountOutOfRange,
    MaxInflightOutOfRange,
    IndexOutOfRange,
    Overflow,
    Unassigned,
}

/// Classify one 24-bit request-table index under the negotiated topology.
pub const fn classify_req_index(
    index: u32,
    ring_count: u32,
    max_inflight: u32,
) -> Result<ReqIndexClass, ReqIndexError> {
    if ring_count < MIN_RING_COUNT || ring_count > MAX_RING_COUNT {
        return Err(ReqIndexError::RingCountOutOfRange);
    }
    if max_inflight == 0 || max_inflight > MAX_INFLIGHT {
        return Err(ReqIndexError::MaxInflightOutOfRange);
    }
    if index > REQ_INDEX_MAX {
        return Err(ReqIndexError::IndexOutOfRange);
    }
    if index < max_inflight {
        return Ok(ReqIndexClass::Application { index });
    }
    if index == GLOBAL_EXTERNAL_CHANGE_ACK_REQID {
        return Ok(ReqIndexClass::ExternalChangeAck);
    }

    let system_count = match ring_count.checked_mul(SYSTEM_REQUEST_SLOTS_PER_RING) {
        Some(count) => count,
        None => return Err(ReqIndexError::Overflow),
    };
    let system_end = match SYSTEM_REQID_BASE.checked_add(system_count) {
        Some(end) => end,
        None => return Err(ReqIndexError::Overflow),
    };
    if index < SYSTEM_REQID_BASE || index >= system_end {
        return Err(ReqIndexError::Unassigned);
    }

    let ordinal = index - SYSTEM_REQID_BASE;
    let ring_index = ordinal / SYSTEM_REQUEST_SLOTS_PER_RING;
    match ordinal % SYSTEM_REQUEST_SLOTS_PER_RING {
        0 => Ok(ReqIndexClass::OpenLifecycle { ring_index }),
        1 => Ok(ReqIndexClass::PtRouteAck { ring_index }),
        2 => Ok(ReqIndexClass::PtExternalSafeAck { ring_index }),
        _ => Err(ReqIndexError::Unassigned),
    }
}
