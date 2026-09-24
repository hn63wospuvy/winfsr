//! Byte-exact FSRING ABI v2 shared-memory layout.
//!
//! These types contain plain wire integers only. In particular, shared cursor
//! and entry-sequence fields are `u64`; later transport code accesses them
//! atomically through aligned raw-pointer views without changing this ABI.

use core::mem::{align_of, size_of};

use crate::{codec::Pod, features::FeatureSet};

/// Little-endian integer representation of the ASCII bytes `FSRG`.
///
/// Keep this as a literal so the pinned C header generator can emit the same
/// value without evaluating a Rust-only `const fn` call.
pub const FSRING_MAGIC: u32 = 0x4752_5346;
pub const FSRING_ABI_MAJOR: u16 = 2;
pub const FSRING_ABI_MINOR: u16 = 1;
/// The oldest ABI minor this build interoperates with. ABI 2.0 is a
/// non-interoperable pre-release; minor 0 is never negotiated, so the minimum
/// compatible minor equals the active minor.
pub const FSRING_ABI_MIN_COMPAT_MINOR: u16 = 1;
pub const FSRING_ENDIAN_LITTLE: u8 = 1;
pub const SLOT_CLASS_COUNT: usize = 4;
pub const SQE_PAYLOAD_LEN: usize = 88;
pub const CQE_OUT_LEN: usize = 24;

/// Consumer-owned park-state wire values used by the v2 wake protocol.
pub const PARK_STATE_ACTIVE: u32 = 0;
pub const PARK_STATE_POLLING: u32 = 1;
pub const PARK_STATE_PARKED: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionDesc {
    pub offset: u64,
    pub length: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotClassDesc {
    pub slot_size: u32,
    pub slot_count: u32,
    pub data_offset: u64,
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct GlobalHeader {
    pub magic: u32,
    pub header_size: u16,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub byte_order: u8,
    pub header_flags: u8,
    pub page_size: u32,
    pub session_epoch: u64,
    pub section_size: u64,
    pub ring_count: u32,
    pub ring_desc_size: u32,
    pub ring_directory: RegionDesc,
    pub k2u_slots: RegionDesc,
    pub u2k_slots: RegionDesc,
    pub notify_names: RegionDesc,
    pub protocol_features: FeatureSet,
    pub os_capabilities: FeatureSet,
    pub max_inflight: u32,
    pub flags: u32,
    pub k2u_slot_classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    pub u2k_slot_classes: [SlotClassDesc; SLOT_CLASS_COUNT],
    /// Reserved ABI bytes: senders write zero; receivers validate zero.
    pub reserved: [u8; 3824],
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct RingDesc {
    pub magic: u32,
    pub desc_size: u16,
    pub desc_version: u16,
    pub ring_index: u32,
    pub flags: u32,
    pub sq_capacity: u32,
    pub cq_capacity: u32,
    pub sq_entries: RegionDesc,
    pub sq_producer: RegionDesc,
    pub sq_consumer: RegionDesc,
    pub cq_entries: RegionDesc,
    pub cq_producer: RegionDesc,
    pub cq_consumer: RegionDesc,
    /// Reserved ABI bytes: senders write zero; receivers validate zero.
    pub reserved: [u8; 8],
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct ProducerPage {
    pub tail: u64,
    pub wake_sequence: u64,
    pub flags: u32,
    /// Explicit alignment bytes: senders write zero; receivers validate zero.
    pub reserved0: [u8; 4],
    /// Reserved ABI bytes: senders write zero; receivers validate zero.
    pub reserved: [u8; 4072],
}

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
pub struct ConsumerPage {
    pub head: u64,
    pub park_state: u32,
    pub flags: u32,
    pub heartbeat: u64,
    /// Reserved ABI bytes: senders write zero; receivers validate zero.
    pub reserved: [u8; 4072],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SqeBody {
    pub opcode: u16,
    pub flags: u16,
    pub payload_len: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u16,
    pub req_id: u64,
    pub kernel_open_id: u64,
    pub ccb_sequence: u64,
    pub payload: [u8; SQE_PAYLOAD_LEN],
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct Sqe {
    pub sequence: u64,
    pub body: SqeBody,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CqeBody {
    pub kind: u16,
    pub opcode: u16,
    pub flags: u16,
    pub out_len: u16,
    pub req_id: u64,
    pub status: i32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub information: u64,
    pub out: [u8; CQE_OUT_LEN],
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct Cqe {
    pub sequence: u64,
    pub body: CqeBody,
}

pub const SLOT_INDEX_MAX: u32 = (1u32 << 20) - 1;
pub const SLOT_OFFSET_MAX: u32 = (1u32 << 21) - 1;
pub const SLOT_LENGTH_MAX: u32 = (1u32 << 21) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotRefError {
    ClassOutOfRange,
    IndexOutOfRange,
    OffsetOutOfRange,
    LengthOutOfRange,
}

/// Packed slot reference: `class:2 | index:20 | offset:21 | len:21`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SlotRef(u64);

impl SlotRef {
    pub const fn try_new(
        class: u8,
        index: u32,
        offset: u32,
        len: u32,
    ) -> Result<Self, SlotRefError> {
        if class >= 4 {
            return Err(SlotRefError::ClassOutOfRange);
        }
        if index > SLOT_INDEX_MAX {
            return Err(SlotRefError::IndexOutOfRange);
        }
        if offset > SLOT_OFFSET_MAX {
            return Err(SlotRefError::OffsetOutOfRange);
        }
        if len > SLOT_LENGTH_MAX {
            return Err(SlotRefError::LengthOutOfRange);
        }
        Ok(Self(
            class as u64 | ((index as u64) << 2) | ((offset as u64) << 22) | ((len as u64) << 43),
        ))
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn class(self) -> u8 {
        (self.0 & 0b11) as u8
    }

    pub const fn index(self) -> u32 {
        ((self.0 >> 2) & SLOT_INDEX_MAX as u64) as u32
    }

    pub const fn offset(self) -> u32 {
        ((self.0 >> 22) & SLOT_OFFSET_MAX as u64) as u32
    }

    pub const fn len(self) -> u32 {
        ((self.0 >> 43) & SLOT_LENGTH_MAX as u64) as u32
    }

    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// SQE flags. `NO_COMPLETION` is required for fire-and-forget CANCEL requests.
pub mod sqe_flags {
    pub const NO_COMPLETION: u16 = 1 << 0;
}

pub mod op {
    pub const PREPARE_OPEN: u16 = 0x0001;
    pub const COMMIT_OPEN: u16 = 0x0002;
    pub const ABORT_OPEN: u16 = 0x0003;
    pub const CLEANUP: u16 = 0x0004;
    pub const CLOSE: u16 = 0x0005;
    pub const READ: u16 = 0x0010;
    pub const WRITE: u16 = 0x0011;
    pub const FLUSH: u16 = 0x0012;
    pub const QUERY_INFO: u16 = 0x0020;
    pub const MUTATE: u16 = 0x0021;
    pub const QUERY_DIR: u16 = 0x0022;
    pub const QUERY_VOLUME: u16 = 0x0023;
    pub const QUERY_SECURITY: u16 = 0x0024;
    pub const FSCTL: u16 = 0x0025;
    pub const CANCEL: u16 = 0x0030;
    pub const ATTACH: u16 = 0x0040;
    pub const REPLAY_OPEN: u16 = 0x0041;
    pub const QUERY_OP: u16 = 0x0042;
    pub const ACK_RESULT: u16 = 0x0043;
    pub const PT_ROUTE_ACK: u16 = 0x0050;
    pub const PT_EXTERNAL_SAFE_ACK: u16 = 0x0051;
    pub const DIR_CHANGE_ACK: u16 = 0x0052;
}

pub mod cq_kind {
    pub const COMPLETION: u16 = 0;
    pub const NOTIFY: u16 = 1;
    pub const PROTOCOL: u16 = 2;
}

pub mod notify {
    pub const INVALIDATE_FILE: u16 = 1;
    pub const INVALIDATE_ENTRY: u16 = 2;
    pub const PT_GRANT: u16 = 3;
    pub const PT_REVOKE_ROUTE: u16 = 4;
    pub const PT_EXTERNAL_MUTATION_SAFE: u16 = 5;
    pub const RESIZE: u16 = 6;
    pub const DIR_CHANGE: u16 = 7;
    pub const PT_LANE_READY: u16 = 8;
    pub const EXTERNAL_CHANGE_READY: u16 = 9;
    pub const EXTERNAL_CHANGE_CUT: u16 = 10;
}

unsafe impl Pod for RegionDesc {}
unsafe impl Pod for SlotClassDesc {}
unsafe impl Pod for GlobalHeader {}
unsafe impl Pod for RingDesc {}
unsafe impl Pod for ProducerPage {}
unsafe impl Pod for ConsumerPage {}
unsafe impl Pod for SqeBody {}
unsafe impl Pod for Sqe {}
unsafe impl Pod for CqeBody {}
unsafe impl Pod for Cqe {}
unsafe impl Pod for SlotRef {}

const _: () = assert!(size_of::<FeatureSet>() == 16);
const _: () = assert!(align_of::<FeatureSet>() == 8);
const _: () = assert!(size_of::<RegionDesc>() == 16);
const _: () = assert!(align_of::<RegionDesc>() == 8);
const _: () = assert!(size_of::<SlotClassDesc>() == 16);
const _: () = assert!(align_of::<SlotClassDesc>() == 8);
const _: () = assert!(size_of::<GlobalHeader>() == 4096);
const _: () = assert!(align_of::<GlobalHeader>() == 4096);
const _: () = assert!(size_of::<RingDesc>() == 128);
const _: () = assert!(align_of::<RingDesc>() == 64);
const _: () = assert!(size_of::<ProducerPage>() == 4096);
const _: () = assert!(align_of::<ProducerPage>() == 4096);
const _: () = assert!(size_of::<ConsumerPage>() == 4096);
const _: () = assert!(align_of::<ConsumerPage>() == 4096);
const _: () = assert!(size_of::<SqeBody>() == 120);
const _: () = assert!(align_of::<SqeBody>() == 8);
const _: () = assert!(size_of::<Sqe>() == 128);
const _: () = assert!(align_of::<Sqe>() == 64);
const _: () = assert!(size_of::<CqeBody>() == 56);
const _: () = assert!(align_of::<CqeBody>() == 8);
const _: () = assert!(size_of::<Cqe>() == 64);
const _: () = assert!(align_of::<Cqe>() == 64);
const _: () = assert!(size_of::<SlotRef>() == 8);
const _: () = assert!(align_of::<SlotRef>() == 8);
