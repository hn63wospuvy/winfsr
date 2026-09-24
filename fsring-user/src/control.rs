//! Typed decode of granted control bodies (the first: `AbortOpenV1`).
//!
//! An `ABORT_OPEN` request's SQ payload is a `PControl` whose `body: BufferRef`
//! points at a granted slot holding an `AbortOpenV1`. [`pcontrol_body_ref`]
//! reads the `BufferRef` (the grant layer validates it); after
//! `grant::resolve_body` single-fetches the body, [`AbortRequest::decode`]
//! validates and decodes it.
//!
//! The frozen ABI ships no `validate_abort_open_v1` (as it ships no `PBarrier`
//! validator), so the `03-messages.md` §4.1 rules are transcribed here.
//! `AbortOpenV1` is `24/8`: a `ControlHeader` (`struct_size:u32 @0`,
//! `struct_version:u16 @4`, `required_flags:u16 @6`) then `transaction_id`
//! (`lo:u64 @8`, `hi:u64 @16`). The doc states no explicit header version for
//! this row; per the ABI's `V1`-suffix convention (matching how it validates
//! other `V1` structs) it carries `CONTROL_VERSION_V1` — a documented inference.

use fsring_abi::layout::{SqeBody, SQE_PAYLOAD_LEN};
use fsring_abi::msgs::{BufferRef, CONTROL_VERSION_V1};

/// Wire size of an `AbortOpenV1` body, bound to the frozen ABI type (which
/// const-asserts `size_of == 24`) rather than re-deriving the literal, per the
/// slice's "never re-derive a wire value" rule.
pub const ABORT_OPEN_V1_SIZE: usize = core::mem::size_of::<fsring_abi::msgs::AbortOpenV1>();
/// Wire size of a `PControl` SQ payload, bound to the frozen ABI type.
pub const PCONTROL_SIZE: u16 = core::mem::size_of::<fsring_abi::msgs::PControl>() as u16;

/// A decoded `AbortOpenV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortRequest {
    pub transaction_id_lo: u64,
    pub transaction_id_hi: u64,
}

/// Why a granted control body (or its `PControl`) was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlBodyError {
    /// The body/payload was not the exact expected wire size.
    WrongLength,
    /// A byte past the `PControl` payload inside the 88-byte array was non-zero.
    /// Also reused for the inline-`PRw` READ tail: `dataio::decode_read` applies
    /// the same zero-tail rule to the SQE payload bytes past the 80-byte record.
    NonZeroTail,
    /// `ControlHeader.struct_size` did not match the body's wire size.
    BadSize,
    /// `ControlHeader.struct_version` was not the expected control version.
    BadVersion,
    /// `ControlHeader.required_flags` (mask zero in ABI 2.1) was non-zero.
    FlagsNonZero,
    /// The `transaction_id` pair was zero (an `ABORT_OPEN` carries a live one).
    ZeroTransactionId,
}

impl AbortRequest {
    /// Decode and validate a single-fetched `AbortOpenV1` body.
    pub fn decode(body: &[u8]) -> Result<AbortRequest, ControlBodyError> {
        if body.len() != ABORT_OPEN_V1_SIZE {
            return Err(ControlBodyError::WrongLength);
        }
        // ControlHeader: struct_size:u32 @0, struct_version:u16 @4, required_flags:u16 @6.
        let struct_size = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let struct_version = u16::from_le_bytes([body[4], body[5]]);
        let required_flags = u16::from_le_bytes([body[6], body[7]]);
        let transaction_id_lo = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let transaction_id_hi = u64::from_le_bytes(body[16..24].try_into().unwrap());
        if struct_size as usize != ABORT_OPEN_V1_SIZE {
            return Err(ControlBodyError::BadSize);
        }
        if struct_version != CONTROL_VERSION_V1 {
            return Err(ControlBodyError::BadVersion);
        }
        if required_flags != 0 {
            return Err(ControlBodyError::FlagsNonZero);
        }
        if transaction_id_lo == 0 && transaction_id_hi == 0 {
            return Err(ControlBodyError::ZeroTransactionId);
        }
        Ok(AbortRequest {
            transaction_id_lo,
            transaction_id_hi,
        })
    }
}

/// Read the `BufferRef` from an SQE's `PControl` payload. The `BufferRef`'s own
/// field legality (kind/access/token/reserved/range) is the grant layer's job
/// (`validate_buffer_ref`); this enforces only the `PControl` wire shape.
pub fn pcontrol_body_ref(sqe: &SqeBody) -> Result<BufferRef, ControlBodyError> {
    if sqe.payload_len != PCONTROL_SIZE {
        return Err(ControlBodyError::WrongLength);
    }
    let used = PCONTROL_SIZE as usize;
    if sqe.payload[used..SQE_PAYLOAD_LEN].iter().any(|&b| b != 0) {
        return Err(ControlBodyError::NonZeroTail);
    }
    // BufferRef: token:u64 @0, offset:u32 @8, length:u32 @12, kind:u16 @16,
    // access:u16 @18, reserved:u32 @20.
    let p = &sqe.payload;
    Ok(BufferRef {
        token: u64::from_le_bytes(p[0..8].try_into().unwrap()),
        offset: u32::from_le_bytes(p[8..12].try_into().unwrap()),
        length: u32::from_le_bytes(p[12..16].try_into().unwrap()),
        kind: u16::from_le_bytes(p[16..18].try_into().unwrap()),
        access: u16::from_le_bytes(p[18..20].try_into().unwrap()),
        reserved: u32::from_le_bytes(p[20..24].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::layout::{op, SqeBody, SQE_PAYLOAD_LEN};
    use fsring_abi::msgs::{buffer_access, buffer_kind};

    fn abort_body(struct_size: u32, version: u16, flags: u16, tx_lo: u64, tx_hi: u64) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&struct_size.to_le_bytes());
        b[4..6].copy_from_slice(&version.to_le_bytes());
        b[6..8].copy_from_slice(&flags.to_le_bytes());
        b[8..16].copy_from_slice(&tx_lo.to_le_bytes());
        b[16..24].copy_from_slice(&tx_hi.to_le_bytes());
        b
    }

    #[test]
    fn decodes_a_well_formed_abort() {
        let body = abort_body(24, 1, 0, 7, 0);
        let decoded = AbortRequest::decode(&body).expect("well formed");
        assert_eq!(decoded.transaction_id_lo, 7);
        assert_eq!(decoded.transaction_id_hi, 0);
    }

    #[test]
    fn abort_field_matrix_is_rejected() {
        assert_eq!(
            AbortRequest::decode(&[0u8; 23]),
            Err(ControlBodyError::WrongLength)
        );
        assert_eq!(
            AbortRequest::decode(&abort_body(25, 1, 0, 1, 0)),
            Err(ControlBodyError::BadSize)
        );
        assert_eq!(
            AbortRequest::decode(&abort_body(24, 2, 0, 1, 0)),
            Err(ControlBodyError::BadVersion)
        );
        assert_eq!(
            AbortRequest::decode(&abort_body(24, 1, 1, 1, 0)),
            Err(ControlBodyError::FlagsNonZero)
        );
        assert_eq!(
            AbortRequest::decode(&abort_body(24, 1, 0, 0, 0)),
            Err(ControlBodyError::ZeroTransactionId)
        );
    }

    fn pcontrol_sqe(payload_len: u16, token: u64, tail_byte: Option<usize>) -> SqeBody {
        let mut payload = [0u8; SQE_PAYLOAD_LEN];
        payload[0..8].copy_from_slice(&token.to_le_bytes());
        payload[8..12].copy_from_slice(&0u32.to_le_bytes()); // offset
        payload[12..16].copy_from_slice(&24u32.to_le_bytes()); // length
        payload[16..18].copy_from_slice(&buffer_kind::SLOT.to_le_bytes());
        payload[18..20].copy_from_slice(&buffer_access::K2U_READ_ONLY.to_le_bytes());
        if let Some(index) = tail_byte {
            payload[index] = 1;
        }
        SqeBody {
            opcode: op::ABORT_OPEN,
            flags: 0,
            payload_len,
            reserved: 0,
            req_id: 1,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload,
        }
    }

    #[test]
    fn pcontrol_body_ref_reads_the_buffer_ref() {
        let sqe = pcontrol_sqe(24, 0xdead, None);
        let reference = pcontrol_body_ref(&sqe).expect("decodes");
        assert_eq!(reference.token, 0xdead);
        assert_eq!(reference.length, 24);
        assert_eq!(reference.kind, buffer_kind::SLOT);
    }

    #[test]
    fn pcontrol_body_ref_rejects_bad_shape() {
        assert_eq!(
            pcontrol_body_ref(&pcontrol_sqe(23, 1, None)),
            Err(ControlBodyError::WrongLength)
        );
        assert_eq!(
            pcontrol_body_ref(&pcontrol_sqe(24, 1, Some(24))),
            Err(ControlBodyError::NonZeroTail)
        );
    }
}
