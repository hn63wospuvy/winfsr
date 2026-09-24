//! Allocation-free durable namespace and private-snapshot metadata helpers.

mod accounting;
mod key;
mod metadata;
mod payloads;

pub use accounting::*;
pub(crate) use key::durable_key_child_kind_v1;
pub use key::*;
pub use metadata::*;
pub use payloads::*;

/// cbindgen:ignore
pub const PROVIDER_MOUNT_ROOT_VERSION: u32 = 1;
/// cbindgen:ignore
pub const DURABLE_ALIGNMENT: u64 = 8;
/// cbindgen:ignore
pub const DURABLE_NAMESPACE_PREFIX_BYTES: u32 = 32;
/// cbindgen:ignore
pub const DURABLE_KEY_HEADER_BYTES: u32 = 34;
/// cbindgen:ignore
pub const DURABLE_KEY_MAX_BYTES: u32 = 90;
/// cbindgen:ignore
pub const DURABLE_CHILD_VALUE_PREFIX_BYTES: u32 = 88;
/// cbindgen:ignore
pub const DURABLE_PROVIDER_ROOT_BYTES: u32 = 160;
/// cbindgen:ignore
pub const DURABLE_ACCOUNTING_RESERVATION_BYTES: u32 = 48;
/// cbindgen:ignore
pub const DURABLE_PREPARE_TX_INDEX_BYTES: u32 = 48;
/// cbindgen:ignore
pub const DURABLE_LATEST_PROCESSED_BYTES: u32 = 56;
/// cbindgen:ignore
pub const DURABLE_RETIRE_RECEIPT_KEY_BYTES: u32 = 32;
/// cbindgen:ignore
pub const DURABLE_RETIRE_RECEIPT_VALUE_BYTES: u32 = 32;

/// cbindgen:ignore
pub const MAX_DURABLE_QUERY_DIR_SNAPSHOTS_PER_OPEN: u32 = 1;
/// cbindgen:ignore
pub const MAX_DURABLE_QUERY_DIR_SNAPSHOT_BYTES_PER_OPEN: u64 = 67_108_864;
/// cbindgen:ignore
pub const MAX_DURABLE_QUERY_DIR_BYTES_PER_MOUNT: u64 = 268_435_456;
/// cbindgen:ignore
pub const MAX_RETAINED_PREPARE_BYTES_PER_MOUNT: u64 = 67_108_864;
/// cbindgen:ignore
pub const MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS: u32 = 4_096;
/// cbindgen:ignore
pub const MAX_DURABLE_EXTERNAL_OUTBOX_BYTES: u64 = 8_388_608;

/// cbindgen:ignore
pub mod durable_child_kind {
    pub const ROOT: u16 = 1;
    pub const ACCOUNTING_RESERVATION: u16 = 2;
    pub const OPEN: u16 = 3;
    pub const PREPARE: u16 = 4;
    pub const IMMUTABLE_REQUEST: u16 = 6;
    pub const COMMITTED_RESULT: u16 = 7;
    pub const JOURNAL: u16 = 8;
    pub const QUERY_DIR_SNAPSHOT: u16 = 9;
    pub const QUERY_DIR_ATTEMPT: u16 = 10;
    pub const QUERY_DIR_COOKIE: u16 = 11;
    pub const PT_EPOCH_INTENT: u16 = 12;
    pub const PT_EPOCH_COUNTER: u16 = 13;
    pub const PT_LANE: u16 = 14;
    pub const EXTERNAL_NOTIFY_OUTBOX: u16 = 15;
    pub const VOLUME_COMMIT_COUNTER: u16 = 16;
    pub const PREPARE_TX_INDEX: u16 = 17;
}

/// cbindgen:ignore
pub mod external_notify_subkind {
    pub const OUTBOX_ROW: u16 = 1;
    pub const LATEST_PROCESSED: u16 = 2;
    pub const ORDINAL_COUNTER: u16 = 3;
    pub const ATTACH_CUT: u16 = 4;
}

/// cbindgen:ignore
pub mod provider_mount_root_state {
    pub const ACTIVE: u32 = 1;
    pub const RECOVERING: u32 = 2;
    pub const RETIRING: u32 = 3;
}

/// cbindgen:ignore
pub mod durable_open_state {
    pub const LIVE: u16 = 1;
    pub const CLEANED: u16 = 2;
}

/// cbindgen:ignore
pub mod durable_prepare_state {
    pub const PREPARED: u16 = 1;
}

/// cbindgen:ignore
pub mod durable_immutable_request_state {
    pub const RETAINED: u16 = 1;
}

/// cbindgen:ignore
pub mod durable_committed_result_state {
    pub const COMMITTED: u16 = 1;
}

/// cbindgen:ignore
pub mod durable_journal_state {
    pub const PREPARED: u16 = 1;
    pub const COMMITTED: u16 = 2;
}

/// cbindgen:ignore
pub mod durable_query_dir_snapshot_state {
    pub const ACTIVE: u16 = 1;
}

/// cbindgen:ignore
pub mod durable_query_dir_attempt_state {
    pub const ACCEPTED: u16 = 1;
}

/// cbindgen:ignore
pub mod durable_query_dir_cookie_state {
    pub const ACTIVE: u16 = 1;
}

/// cbindgen:ignore
pub mod durable_pt_epoch_intent_state {
    pub const PENDING: u16 = 1;
    pub const ACCEPTED: u16 = 2;
    pub const REVOKED: u16 = 3;
}

/// cbindgen:ignore
pub mod durable_pt_lane_state {
    pub const PRESENT: u16 = 1;
}

/// cbindgen:ignore
pub mod retire_receipt_state {
    pub const RECEIPT_PENDING_ACK: u32 = 1;
}
