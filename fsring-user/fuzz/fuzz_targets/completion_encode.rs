#![no_main]
//! Fuzz the dispatch guardrail: for arbitrary provider output on an arbitrary
//! request, `resolve_completion` must never panic, and any CQE it returns must
//! satisfy the frozen ABI's **full output matrix** — not merely the registry —
//! plus kind `COMPLETION` and `out_len <= CQE_OUT_LEN`.

use fsring_abi::layout::{cq_kind, SqeBody, CQE_OUT_LEN, SQE_PAYLOAD_LEN};
use fsring_abi::validate::{validate_completion_output_v21, CompletionOutputContextV21};
use fsring_user::{resolve_completion, Completion, OutBuf};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Carve request + provider-output fields from the fuzzer bytes. Short input
    // is fine — missing bytes default to zero. The buffer holds the 17-byte
    // scalar header plus up to `CQE_OUT_LEN` output bytes read from offset 17.
    let mut b = [0u8; 17 + CQE_OUT_LEN];
    let n = data.len().min(b.len());
    b[..n].copy_from_slice(&data[..n]);

    let opcode = u16::from_le_bytes([b[0], b[1]]);
    let flags = u16::from_le_bytes([b[2], b[3]]);
    let status = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let information = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    let out_len = (b[16] as usize) % (CQE_OUT_LEN + 1);
    let out = OutBuf::new(&b[17..17 + out_len]).expect("out_len <= CQE_OUT_LEN by construction");

    let req = SqeBody {
        opcode,
        flags,
        payload_len: 0,
        reserved: 0,
        req_id: information, // arbitrary; only echoed
        kernel_open_id: 0,
        ccb_sequence: 0,
        payload: [0u8; SQE_PAYLOAD_LEN],
    };

    if let Ok(Some(cqe)) = resolve_completion(&req, Completion::complete(status, information, out))
    {
        // Anything posted must satisfy the full ABI output matrix. The seam
        // built this completion with the `None` context, so the same context is
        // the one the matrix must accept.
        assert!(
            validate_completion_output_v21(
                cqe.opcode,
                cqe.status,
                u32::from(cqe.out_len),
                cqe.information,
                CompletionOutputContextV21::None,
            )
            .is_ok(),
            "posted a completion the ABI output matrix rejects"
        );
        assert_eq!(cqe.kind, cq_kind::COMPLETION);
        assert!(cqe.out_len as usize <= CQE_OUT_LEN);
    }
});
