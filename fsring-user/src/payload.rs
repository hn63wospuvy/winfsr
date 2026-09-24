//! Typed decode of the fixed SQ payloads that need no grant.
//!
//! `03-messages.md` §4.1 fixes `PBarrier` at `24/8` — `+0 op_id:OpId`,
//! `+16 flags:u32`, `+20 reserved:u32` — with `reserved = 0` and a zero flags
//! mask, `payload_len = 24`, and the remaining 64 bytes of the 88-byte payload
//! array zero-filled. The frozen ABI ships **no** validator for this (there is
//! no `validate_abort_open_v1` and no CLEANUP/CLOSE/`PBarrier` validator
//! anywhere in `fsring-abi/src/validate/`), so the rules are transcribed here.
//!
//! `op_id` is deliberately **unconstrained**: the document constrains `op_id`
//! explicitly where it means to (`PRw`: "READ requires `PRw.op_id ==
//! OpId::ZERO`. WRITE requires a nonzero `op_id`") and does not here. Inventing
//! a nonzero rule would reject legal traffic.

use fsring_abi::ids::OpId;
use fsring_abi::layout::{SqeBody, SQE_PAYLOAD_LEN};

/// Wire size of a `PBarrier` payload.
pub const BARRIER_PAYLOAD_LEN: u16 = 24;

// The decode below slices `payload[BARRIER_PAYLOAD_LEN..SQE_PAYLOAD_LEN]`, which
// is in bounds only while this holds. Asserted so the "cannot panic" contract
// rests on a checked relation rather than on two constants happening to agree.
const _: () = assert!(BARRIER_PAYLOAD_LEN as usize <= SQE_PAYLOAD_LEN);

/// A decoded `PBarrier` payload (CLEANUP / CLOSE / FLUSH).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarrierRequest {
    /// The barrier's operation id, reusing the frozen ABI's `OpId` rather than
    /// re-deriving its `lo`/`hi` split.
    pub op_id: OpId,
}

/// Why a fixed SQ payload was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    /// `payload_len` is not the payload's exact wire size.
    WrongLength,
    /// A byte past the payload inside the 88-byte array was non-zero.
    NonZeroTail,
    /// A reserved field that must be zero was non-zero.
    ReservedNonZero,
    /// A flags field whose ABI 2.1 mask is zero was non-zero.
    FlagsNonZero,
}

fn le_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

fn le_u32(bytes: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    u32::from_le_bytes(buf)
}

impl BarrierRequest {
    /// Decode and validate the `PBarrier` payload of a barrier-opcode request.
    ///
    /// Enforces the `03-messages.md` §4.1 rules: exact `payload_len`, a
    /// zero-filled tail, `reserved == 0`, and a zero `flags` mask. `op_id` is
    /// intentionally unconstrained (see the module doc). Reads only within the
    /// fixed 88-byte payload array, so no input can panic or read out of bounds.
    ///
    /// **Precondition — the caller dispatches by opcode.** This decodes the
    /// `PBarrier` *shape*; it does not inspect `sqe.opcode`. `PControl` and
    /// `PNotifyAck` share the same 24-byte payload with a 64-byte zero tail, so
    /// a request carrying one of those would also decode "successfully" here.
    /// Call this only for the barrier opcodes (`CLEANUP`, `CLOSE`, `FLUSH`).
    pub fn decode(sqe: &SqeBody) -> Result<BarrierRequest, PayloadError> {
        if sqe.payload_len != BARRIER_PAYLOAD_LEN {
            return Err(PayloadError::WrongLength);
        }
        let used = BARRIER_PAYLOAD_LEN as usize;
        if sqe.payload[used..SQE_PAYLOAD_LEN].iter().any(|&b| b != 0) {
            return Err(PayloadError::NonZeroTail);
        }
        if le_u32(&sqe.payload[16..20]) != 0 {
            return Err(PayloadError::FlagsNonZero);
        }
        if le_u32(&sqe.payload[20..24]) != 0 {
            return Err(PayloadError::ReservedNonZero);
        }
        Ok(BarrierRequest {
            op_id: OpId {
                lo: le_u64(&sqe.payload[0..8]),
                hi: le_u64(&sqe.payload[8..16]),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsring_abi::layout::{op, SqeBody, SQE_PAYLOAD_LEN};

    fn barrier_sqe(op_id_lo: u64, op_id_hi: u64, flags: u32, reserved: u32) -> SqeBody {
        let mut payload = [0u8; SQE_PAYLOAD_LEN];
        payload[0..8].copy_from_slice(&op_id_lo.to_le_bytes());
        payload[8..16].copy_from_slice(&op_id_hi.to_le_bytes());
        payload[16..20].copy_from_slice(&flags.to_le_bytes());
        payload[20..24].copy_from_slice(&reserved.to_le_bytes());
        SqeBody {
            opcode: op::CLEANUP,
            flags: 0,
            payload_len: BARRIER_PAYLOAD_LEN,
            reserved: 0,
            req_id: 1,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload,
        }
    }

    #[test]
    fn decodes_a_well_formed_barrier() {
        let sqe = barrier_sqe(0xdead, 0xbeef, 0, 0);
        let decoded = BarrierRequest::decode(&sqe).expect("well formed");
        assert_eq!(
            decoded.op_id,
            OpId {
                lo: 0xdead,
                hi: 0xbeef
            }
        );
    }

    #[test]
    fn zero_op_id_is_accepted() {
        // 03-messages.md does NOT constrain PBarrier.op_id (contrast PRw).
        let sqe = barrier_sqe(0, 0, 0, 0);
        let decoded = BarrierRequest::decode(&sqe).expect("zero op_id is legal");
        assert_eq!(decoded.op_id, OpId { lo: 0, hi: 0 });
    }

    #[test]
    fn wrong_payload_len_is_rejected() {
        let mut sqe = barrier_sqe(1, 1, 0, 0);
        sqe.payload_len = 23;
        assert_eq!(BarrierRequest::decode(&sqe), Err(PayloadError::WrongLength));
    }

    #[test]
    fn non_zero_tail_is_rejected() {
        let mut sqe = barrier_sqe(1, 1, 0, 0);
        sqe.payload[BARRIER_PAYLOAD_LEN as usize] = 1; // first tail byte
        assert_eq!(BarrierRequest::decode(&sqe), Err(PayloadError::NonZeroTail));

        let mut sqe = barrier_sqe(1, 1, 0, 0);
        sqe.payload[SQE_PAYLOAD_LEN - 1] = 1; // last tail byte
        assert_eq!(BarrierRequest::decode(&sqe), Err(PayloadError::NonZeroTail));
    }

    #[test]
    fn non_zero_flags_or_reserved_is_rejected() {
        assert_eq!(
            BarrierRequest::decode(&barrier_sqe(1, 1, 1, 0)),
            Err(PayloadError::FlagsNonZero)
        );
        assert_eq!(
            BarrierRequest::decode(&barrier_sqe(1, 1, 0, 1)),
            Err(PayloadError::ReservedNonZero)
        );
    }
}
