//! The `Provider` seam: the daemon-side handler abstraction and the guardrail
//! that keeps a provider from publishing a completion the frozen ABI rejects.
//!
//! Slice 2 checked only that the `(opcode, status)` pair was registered; slice 4
//! upgrades the guardrail to the ABI's full output matrix
//! (`validate_completion_output_v21`), which subsumes the registry check and
//! additionally fixes `out_len ∈ {0, 24}`, the per-opcode `information`, and the
//! zero-output rules. Still transport-level: no grant resolution and no
//! filesystem semantics.

use fsring_abi::layout::{cq_kind, sqe_flags, CqeBody, SqeBody, CQE_OUT_LEN};
use fsring_abi::validate::{
    is_registered_completion_status_v21, validate_completion_output_v21, CompletionOutputContextV21,
};

use crate::error::ProviderViolation;

/// Output bytes for a completion, length-bounded to `CQE_OUT_LEN` at
/// construction so an over-long provider output is unrepresentable rather than
/// a runtime reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutBuf {
    len: u16,
    bytes: [u8; CQE_OUT_LEN],
}

impl OutBuf {
    /// An empty output (`len == 0`).
    pub const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0u8; CQE_OUT_LEN],
        }
    }

    /// Build from `bytes`, or `None` if it exceeds `CQE_OUT_LEN`.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > CQE_OUT_LEN {
            return None;
        }
        let mut buf = [0u8; CQE_OUT_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            len: bytes.len() as u16,
            bytes: buf,
        })
    }

    /// Content length in bytes (`<= CQE_OUT_LEN`).
    pub fn len(&self) -> u16 {
        self.len
    }

    /// True when there are no content bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `len`-bounded content slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The full `CqeBody.out` array, zero-padded past `len`.
    pub fn to_cqe_out(&self) -> [u8; CQE_OUT_LEN] {
        self.bytes
    }
}

/// A daemon-side handler: turns one popped request into its completion.
///
/// Synchronous by contract in this slice — the completion is decided in the
/// call. The provider owns the decision only; it never touches the ring, the
/// section, or the CQE encoding.
pub trait Provider {
    fn dispatch(&mut self, req: &SqeBody) -> Completion;
}

/// The two legal outcomes of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Produce a `COMPLETION` CQE. The `(status, information, out.len(),
    /// context)` tuple must satisfy the ABI output matrix
    /// (`validate_completion_output_v21`), enforced by [`resolve_completion`];
    /// `out` is `<= CQE_OUT_LEN` bytes by construction.
    Complete {
        status: i32,
        information: u64,
        out: OutBuf,
        context: CompletionOutputContextV21,
    },
    /// Produce no CQE. Legal only for a request whose SQE set
    /// `sqe_flags::NO_COMPLETION`.
    None,
}

impl Completion {
    /// `SUCCESS` with no output — the shape every zero-output opcode
    /// (`ABORT_OPEN`/`CLEANUP`/`CLOSE`/`FLUSH`/`ACK_RESULT`) requires.
    pub fn success_empty() -> Self {
        Completion::Complete {
            status: 0,
            information: 0,
            out: OutBuf::empty(),
            context: CompletionOutputContextV21::None,
        }
    }

    /// A registered *ordinary failure* status, which the matrix requires to
    /// carry zero output and zero information. Not for `QUERY_OP` +
    /// `BUFFER_TOO_SMALL`, whose row needs the `QueryOpRetained` context — use
    /// [`Completion::complete_with`] for that.
    pub fn failure(status: i32) -> Self {
        Completion::Complete {
            status,
            information: 0,
            out: OutBuf::empty(),
            context: CompletionOutputContextV21::None,
        }
    }

    /// A completion with the `None` output context — correct for every
    /// exact-information opcode (`PREPARE_OPEN` 136, `COMMIT_OPEN`/`MUTATE` 112,
    /// `REPLAY_OPEN` 16, `QUERY_OP` 56), every zero-output opcode, and every
    /// registered ordinary failure. The request-derived rows (`READ`/`WRITE`,
    /// `QUERY_INFO`/`QUERY_VOLUME`/`QUERY_DIR`, `QUERY_SECURITY`) and
    /// `QUERY_OP` + `BUFFER_TOO_SMALL` need [`Completion::complete_with`].
    pub fn complete(status: i32, information: u64, out: OutBuf) -> Self {
        Completion::Complete {
            status,
            information,
            out,
            context: CompletionOutputContextV21::None,
        }
    }

    /// A completion with an explicit request-derived output context
    /// (`READ`/`WRITE`, `QUERY_INFO`/`QUERY_VOLUME`/`QUERY_DIR`,
    /// `QUERY_SECURITY`). Deriving those contexts needs a resolved grant, which
    /// is sub-project A2; this constructor exists so the seam is already shaped
    /// for it.
    pub fn complete_with(
        status: i32,
        information: u64,
        out: OutBuf,
        context: CompletionOutputContextV21,
    ) -> Self {
        Completion::Complete {
            status,
            information,
            out,
            context,
        }
    }
}

/// Reconcile a provider outcome with the request and, for a completion-bearing
/// request, encode a **matrix-validated** `CqeBody`.
///
/// `Ok(Some(cqe))` → post it; `Ok(None)` → fire-and-forget, post nothing;
/// `Err(_)` → a provider contract violation, nothing is posted.
///
/// This is the whole guardrail: the completion must satisfy the frozen ABI's
/// `validate_completion_output_v21` matrix — a registered `(opcode, status)`
/// pair, `out_len ∈ {0, 24}`, the exact per-opcode `information`, and zero
/// output wherever the opcode or status forbids it — before it is allowed onto
/// the ring. It is pure (no ring, no section) so it is directly unit- and
/// fuzz-testable.
pub fn resolve_completion(
    req: &SqeBody,
    outcome: Completion,
) -> Result<Option<CqeBody>, ProviderViolation> {
    let no_completion = req.flags & sqe_flags::NO_COMPLETION != 0;
    match (no_completion, outcome) {
        (true, Completion::None) => Ok(None),
        (true, Completion::Complete { .. }) => Err(ProviderViolation::UnexpectedCompletion),
        (false, Completion::None) => Err(ProviderViolation::MissingCompletion),
        (
            false,
            Completion::Complete {
                status,
                information,
                out,
                context,
            },
        ) => {
            let out_len = u32::from(out.len());
            // The full ABI output matrix subsumes the registry check. On failure
            // the registry is re-tested only to classify the violation
            // precisely; the happy path calls the matrix once.
            if validate_completion_output_v21(req.opcode, status, out_len, information, context)
                .is_err()
            {
                return Err(
                    if !is_registered_completion_status_v21(req.opcode, status) {
                        ProviderViolation::UnregisteredStatus {
                            opcode: req.opcode,
                            status,
                        }
                    } else {
                        ProviderViolation::IllegalCompletionOutput {
                            opcode: req.opcode,
                            status,
                            out_len,
                            information,
                            context,
                        }
                    },
                );
            }
            Ok(Some(CqeBody {
                kind: cq_kind::COMPLETION,
                opcode: req.opcode,
                flags: 0,
                out_len: out.len(),
                req_id: req.req_id,
                status,
                reserved: 0,
                information,
                out: out.to_cqe_out(),
            }))
        }
    }
}

/// The trivial provider: completes every completion-required request with
/// `SUCCESS` and no output, honoring `NO_COMPLETION`. Reproduces slice 1's echo
/// behavior through the seam.
///
/// Valid only for opcodes whose `SUCCESS` is **zero-output**
/// (`ABORT_OPEN`/`CLEANUP`/`CLOSE`/`FLUSH`/`ACK_RESULT`). An exact-information
/// opcode (`PREPARE_OPEN`/`COMMIT_OPEN`/`REPLAY_OPEN`/`QUERY_OP`) requires a
/// matching `information` and 24 output bytes, so this provider's completion
/// would be rejected by the output matrix there.
#[derive(Clone, Copy, Debug, Default)]
pub struct EchoProvider;

impl Provider for EchoProvider {
    fn dispatch(&mut self, req: &SqeBody) -> Completion {
        if req.flags & sqe_flags::NO_COMPLETION != 0 {
            Completion::None
        } else {
            Completion::success_empty()
        }
    }
}

/// A provider that returns one fixed completion for every completion-required
/// request (and `None` for a fire-and-forget one). For dispatch tests: pick a
/// `status` the ABI registers for the opcode under test to exercise the accept
/// path, or an unregistered one to exercise the guardrail's reject path.
#[derive(Clone, Copy, Debug)]
pub struct StatusProvider {
    pub status: i32,
    pub information: u64,
    pub out: OutBuf,
}

impl Provider for StatusProvider {
    fn dispatch(&mut self, req: &SqeBody) -> Completion {
        if req.flags & sqe_flags::NO_COMPLETION != 0 {
            Completion::None
        } else {
            Completion::complete(self.status, self.information, self.out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProviderViolation;
    use fsring_abi::layout::{cq_kind, op, sqe_flags, SqeBody, SQE_PAYLOAD_LEN};
    use fsring_abi::validate::completion_status;

    const UNREGISTERED: i32 = 0x0000_1234;

    fn req(opcode: u16, flags: u16, req_id: u64) -> SqeBody {
        SqeBody {
            opcode,
            flags,
            payload_len: 0,
            reserved: 0,
            req_id,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload: [0u8; SQE_PAYLOAD_LEN],
        }
    }

    #[test]
    fn empty_outbuf_has_zero_len() {
        let out = OutBuf::empty();
        assert_eq!(out.len(), 0);
        assert!(out.is_empty());
        assert_eq!(out.as_slice(), &[] as &[u8]);
        assert_eq!(out.to_cqe_out(), [0u8; CQE_OUT_LEN]);
    }

    #[test]
    fn new_outbuf_within_bound_keeps_bytes() {
        let out = OutBuf::new(&[1, 2, 3]).expect("3 <= CQE_OUT_LEN");
        assert_eq!(out.len(), 3);
        assert_eq!(out.as_slice(), &[1, 2, 3]);
        let mut expected = [0u8; CQE_OUT_LEN];
        expected[..3].copy_from_slice(&[1, 2, 3]);
        assert_eq!(out.to_cqe_out(), expected);
    }

    #[test]
    fn new_outbuf_at_capacity_is_accepted() {
        let full = [7u8; CQE_OUT_LEN];
        let out = OutBuf::new(&full).expect("CQE_OUT_LEN is the exact bound");
        assert_eq!(out.len() as usize, CQE_OUT_LEN);
        assert_eq!(out.as_slice(), &full);
    }

    #[test]
    fn new_outbuf_over_capacity_is_rejected() {
        let too_long = [0u8; CQE_OUT_LEN + 1];
        assert!(OutBuf::new(&too_long).is_none());
    }

    #[test]
    fn resolve_exact_information_success_encodes_cqe() {
        // PREPARE_OPEN success: out_len 24, information 136, context None.
        let request = req(op::PREPARE_OPEN, 0, 42);
        let out = OutBuf::new(&[9u8; CQE_OUT_LEN]).unwrap();
        let cqe = resolve_completion(&request, Completion::complete(0, 136, out))
            .expect("legal")
            .expect("a completion is produced");
        assert_eq!(cqe.kind, cq_kind::COMPLETION);
        assert_eq!(cqe.opcode, op::PREPARE_OPEN);
        assert_eq!(cqe.req_id, 42);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 136);
        assert_eq!(cqe.flags, 0);
        assert_eq!(cqe.reserved, 0);
    }

    #[test]
    fn resolve_wrong_information_is_illegal_output() {
        // PREPARE_OPEN success with information != 136.
        let request = req(op::PREPARE_OPEN, 0, 1);
        let out = OutBuf::new(&[0u8; CQE_OUT_LEN]).unwrap();
        match resolve_completion(&request, Completion::complete(0, 999, out)) {
            Err(ProviderViolation::IllegalCompletionOutput {
                opcode,
                information,
                ..
            }) => {
                assert_eq!(opcode, op::PREPARE_OPEN);
                assert_eq!(information, 999);
            }
            _ => panic!("expected IllegalCompletionOutput"),
        }
    }

    #[test]
    fn resolve_zero_output_opcode_success_is_legal() {
        // CLEANUP/CLOSE success: out_len 0, information 0.
        for opcode in [op::CLEANUP, op::CLOSE] {
            let request = req(opcode, 0, 7);
            let cqe = resolve_completion(&request, Completion::success_empty())
                .expect("legal")
                .expect("a completion");
            assert_eq!(cqe.out_len, 0);
            assert_eq!(cqe.information, 0);
            assert_eq!(cqe.status, 0);
        }
    }

    #[test]
    fn resolve_output_on_zero_output_opcode_is_illegal() {
        let request = req(op::CLEANUP, 0, 7);
        let out = OutBuf::new(&[1u8; CQE_OUT_LEN]).unwrap();
        assert!(matches!(
            resolve_completion(&request, Completion::complete(0, 0, out)),
            Err(ProviderViolation::IllegalCompletionOutput { .. })
        ));
    }

    #[test]
    fn resolve_registered_failure_requires_zero_output() {
        // READ + ACCESS_DENIED is registered; failures must carry zero output.
        let request = req(op::READ, 0, 3);
        let ok = resolve_completion(
            &request,
            Completion::failure(completion_status::ACCESS_DENIED),
        )
        .expect("legal")
        .expect("a completion");
        assert_eq!(ok.status, completion_status::ACCESS_DENIED);
        assert_eq!(ok.out_len, 0);
        assert_eq!(ok.information, 0);

        // Use a *legal* out_len (24) so this exercises the failure/zero-output
        // rule itself rather than short-circuiting on the `out_len ∈ {0,24}`
        // gate that precedes it.
        let out = OutBuf::new(&[1u8; CQE_OUT_LEN]).unwrap();
        assert!(matches!(
            resolve_completion(
                &request,
                Completion::complete(completion_status::ACCESS_DENIED, 24, out)
            ),
            Err(ProviderViolation::IllegalCompletionOutput { .. })
        ));
    }

    #[test]
    fn resolve_every_exact_information_row_is_accepted() {
        // The full set of exact-information rows A1 covers, per the matrix.
        for (opcode, information) in [
            (op::PREPARE_OPEN, 136u64),
            (op::COMMIT_OPEN, 112),
            (op::MUTATE, 112),
            (op::REPLAY_OPEN, 16),
            (op::QUERY_OP, 56),
        ] {
            let request = req(opcode, 0, 5);
            let out = OutBuf::new(&[0u8; CQE_OUT_LEN]).unwrap();
            let cqe = resolve_completion(&request, Completion::complete(0, information, out))
                .unwrap_or_else(|_| panic!("opcode {opcode:#06x} must accept {information}"))
                .expect("a completion");
            assert_eq!(cqe.out_len, 24);
            assert_eq!(cqe.information, information);
        }
    }

    #[test]
    fn forbidden_context_on_a_none_context_row_is_illegal() {
        // CLEANUP success requires the `None` context; any other context is a
        // Relationship fault inside the matrix.
        let request = req(op::CLEANUP, 0, 7);
        match resolve_completion(
            &request,
            Completion::complete_with(
                0,
                0,
                OutBuf::empty(),
                CompletionOutputContextV21::RequestLength(8),
            ),
        ) {
            Err(ProviderViolation::IllegalCompletionOutput { context, .. }) => {
                assert_eq!(context, CompletionOutputContextV21::RequestLength(8));
            }
            _ => panic!("expected IllegalCompletionOutput for a forbidden context"),
        }
    }

    #[test]
    fn request_derived_context_reaches_the_matrix() {
        // READ success is judged against the caller-supplied RequestLength. The
        // accept/reject pair below differs ONLY in that context value, so it
        // fails if `resolve_completion` ever stops forwarding the field.
        let request = req(op::READ, 0, 9);
        let out = OutBuf::new(&[0u8; CQE_OUT_LEN]).unwrap();

        let cqe = resolve_completion(
            &request,
            Completion::complete_with(0, 8, out, CompletionOutputContextV21::RequestLength(8)),
        )
        .expect("information 8 <= request_length 8 is legal")
        .expect("a completion");
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 8);

        assert!(
            matches!(
                resolve_completion(
                    &request,
                    Completion::complete_with(
                        0,
                        8,
                        out,
                        CompletionOutputContextV21::RequestLength(4)
                    ),
                ),
                Err(ProviderViolation::IllegalCompletionOutput { .. })
            ),
            "information 8 > request_length 4 must be rejected"
        );
    }

    #[test]
    fn resolve_unregistered_status_is_rejected_not_posted() {
        let request = req(op::READ, 0, 1);
        let outcome = Completion::failure(UNREGISTERED);
        // `CqeBody` derives neither `Debug` nor `PartialEq`, so the `Ok` side of
        // this `Result` cannot be compared with `assert_eq!`; match instead.
        match resolve_completion(&request, outcome) {
            Err(ProviderViolation::UnregisteredStatus { opcode, status }) => {
                assert_eq!(opcode, op::READ);
                assert_eq!(status, UNREGISTERED);
            }
            _ => panic!("expected UnregisteredStatus"),
        }
    }

    #[test]
    fn resolve_no_completion_flag_with_none_suppresses() {
        let request = req(op::READ, sqe_flags::NO_COMPLETION, 5);
        assert!(matches!(
            resolve_completion(&request, Completion::None),
            Ok(None)
        ));
    }

    #[test]
    fn resolve_no_completion_flag_with_complete_is_unexpected() {
        let request = req(op::READ, sqe_flags::NO_COMPLETION, 5);
        assert!(matches!(
            resolve_completion(&request, Completion::success_empty()),
            Err(ProviderViolation::UnexpectedCompletion)
        ));
    }

    #[test]
    fn resolve_completion_required_with_none_is_missing() {
        let request = req(op::READ, 0, 5);
        assert!(matches!(
            resolve_completion(&request, Completion::None),
            Err(ProviderViolation::MissingCompletion)
        ));
    }

    #[test]
    fn echo_provider_succeeds_on_registered_opcode() {
        let mut provider = EchoProvider;
        match provider.dispatch(&req(op::CLEANUP, 0, 1)) {
            Completion::Complete {
                status,
                information,
                out,
                ..
            } => {
                assert_eq!(status, completion_status::SUCCESS);
                assert_eq!(information, 0);
                assert!(out.is_empty());
            }
            Completion::None => panic!("echo must complete a completion-required request"),
        }
    }

    #[test]
    fn echo_provider_honors_no_completion_flag() {
        let mut provider = EchoProvider;
        assert!(matches!(
            provider.dispatch(&req(op::READ, sqe_flags::NO_COMPLETION, 1)),
            Completion::None
        ));
    }

    #[test]
    fn status_provider_returns_its_fixed_completion() {
        let out = OutBuf::new(&[0xaa, 0xbb]).unwrap();
        let mut provider = StatusProvider {
            status: completion_status::ACCESS_DENIED,
            information: 2,
            out,
        };
        match provider.dispatch(&req(op::READ, 0, 1)) {
            Completion::Complete {
                status,
                information,
                out,
                ..
            } => {
                assert_eq!(status, completion_status::ACCESS_DENIED);
                assert_eq!(information, 2);
                assert_eq!(out.as_slice(), &[0xaa, 0xbb]);
            }
            Completion::None => panic!("completion required"),
        }
        assert!(matches!(
            provider.dispatch(&req(op::READ, sqe_flags::NO_COMPLETION, 2)),
            Completion::None
        ));
    }
}
