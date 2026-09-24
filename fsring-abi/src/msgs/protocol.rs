//! Exact ABI 2.1 PROTOCOL completion record.

use core::mem::{align_of, offset_of, size_of};

use crate::{
    codec::{try_decode, Pod},
    layout::{cq_kind, CqeBody, CQE_OUT_LEN},
};

use super::{ControlHeader, CONTROL_VERSION_V1};

/// cbindgen:ignore
pub mod protocol_opcode {
    pub const ABORT_SESSION: u16 = 1;
}

/// cbindgen:ignore
pub mod protocol_reason {
    pub const PROVIDER_FATAL_STATE: u32 = 1;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProtocolAbortV1 {
    pub header: ControlHeader,
    pub reason: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    /// Diagnostic data only; never an address, handle, token, or authority.
    pub context: u64,
}

// SAFETY: repr(C) plus the assertions below prove a stable, gapless integer
// image; every bit pattern is valid and every object byte is initialized.
unsafe impl Pod for ProtocolAbortV1 {}

pub fn validate_protocol_abort_v1(cqe: &CqeBody) -> Option<ProtocolAbortV1> {
    if cqe.kind != cq_kind::PROTOCOL
        || cqe.opcode != protocol_opcode::ABORT_SESSION
        || cqe.flags != 0
        || usize::from(cqe.out_len) != size_of::<ProtocolAbortV1>()
        || cqe.req_id != 0
        || cqe.status != 0
        || cqe.reserved != 0
        || cqe.information != 0
    {
        return None;
    }

    let record = try_decode::<ProtocolAbortV1>(&cqe.out).ok()?;
    if usize::try_from(record.header.struct_size).ok()? != size_of::<ProtocolAbortV1>()
        || record.header.struct_version != CONTROL_VERSION_V1
        || record.header.required_flags != 0
        || record.reason != protocol_reason::PROVIDER_FATAL_STATE
        || record.reserved != 0
    {
        return None;
    }
    Some(record)
}

const _: () = assert!(size_of::<ProtocolAbortV1>() == CQE_OUT_LEN);
const _: () = assert!(align_of::<ProtocolAbortV1>() == 8);
const _: () = assert!(offset_of!(ProtocolAbortV1, header) == 0);
const _: () = assert!(offset_of!(ProtocolAbortV1, reason) == 8);
const _: () = assert!(offset_of!(ProtocolAbortV1, reserved) == 12);
const _: () = assert!(offset_of!(ProtocolAbortV1, context) == 16);
const _: () = assert!(offset_of!(ProtocolAbortV1, context) + size_of::<u64>() == 24);
