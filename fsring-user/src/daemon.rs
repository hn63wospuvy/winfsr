//! The daemon-role ENTER loop.
//!
//! Two dispatchers share the ring plumbing (slice 1's `DaemonRing`, unchanged):
//!
//! * The free-fn [`pump_once`] is the transport-level seam — it drains the SQ,
//!   hands each request to a [`Provider`], and posts whatever
//!   [`resolve_completion`] validates. It knows nothing of decode/lifecycle/
//!   result semantics.
//! * The stateful [`Daemon`] is the E1 finale: it composes every earlier layer
//!   (grant table, decoders, the open-lifecycle engine, the dir enumerator, the
//!   result encoders, `write_body`) into one loop that drives a [`FileSystem`]
//!   provider end-to-end. Per SQE it decodes the request, resolves its grants,
//!   calls the trait, builds the wire result, writes it back into the U2K
//!   grant(s), and posts the matrix-validated completion.

use crate::control::{pcontrol_body_ref, AbortRequest};
use crate::dataio::{build_read_completion, build_write_result, decode_read, decode_write};
use crate::direnum::DirEnumerator;
use crate::error::{
    DaemonError, EnumError, LifecycleFault, ProviderViolation, PumpError, ResultError, RingFault,
    TransportError, WriteResultError,
};
use crate::filesystem::{FileSystem, ProviderError};
use crate::grant::{resolve_body, write_body, GrantTable};
use crate::lifecycle::OpenLifecycle;
use crate::mutation::{
    build_mutate_completion, build_mutation_result, decode_mutation, revalidate_context,
};
use crate::openbody::{
    build_commit_completion, build_commit_result, build_prepare_completion, build_prepare_result,
    decode_commit, decode_prepare,
};
use crate::payload::BarrierRequest;
use crate::provider::{resolve_completion, Completion, OutBuf, Provider};
use crate::querydir::{build_query_dir_completion, decode_query_dir};
use crate::queryinfo::{build_file_info, decode_query_info};
use crate::querysecurity::{build_query_security_completion, decode_query_security};
use crate::queryvolume::{build_volume_size_info, decode_query_volume};
use crate::ring::DaemonRing;
use crate::section::SharedSection;

use fsring_abi::codec::try_encode;
use fsring_abi::ids::{ReqId, TransactionId};
use fsring_abi::layout::{op, SqeBody};
use fsring_abi::msgs::{BufferRef, OControl};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    completion_status, is_registered_completion_status_v21, CompletionOutputContextV21,
    MessageValidationError, QueryDirFormV21,
};

/// One-pass dispatch tally.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PumpStats {
    /// Requests popped and dispatched.
    pub handled: u32,
    /// Completions posted to the CQ.
    pub posted: u32,
    /// Fire-and-forget requests that produced no CQE.
    pub suppressed: u32,
}

/// Turn a provider's semantic failure into the only legal zero-output failure
/// completion for `opcode`, rejecting statuses a provider is not permitted to
/// use as failures.
fn provider_failure(opcode: u16, error: ProviderError) -> Result<Completion, DaemonError> {
    let status = error.status();
    if status == completion_status::SUCCESS
        || status == completion_status::PENDING
        || !is_registered_completion_status_v21(opcode, status)
    {
        return Err(DaemonError::Provider(
            ProviderViolation::IllegalFailureStatus { opcode, status },
        ));
    }
    Ok(Completion::failure(status))
}

fn invalid_write_outcome() -> DaemonError {
    DaemonError::Result(ResultError::Write(WriteResultError::Message(
        MessageValidationError::InvalidScalar,
    )))
}

/// Drain every ready request in one pass, dispatching each to `provider`.
///
/// Stops at the first fault: a
/// [`ProviderViolation`](crate::error::ProviderViolation) (a buggy local
/// provider) or a transport fault (a hostile peer / full CQ), both surfaced
/// through [`PumpError`]. A rejected completion is never posted, leaving the
/// ring coherent for the next pass.
pub fn pump_once<P: Provider>(
    ring: &mut DaemonRing,
    provider: &mut P,
) -> Result<PumpStats, PumpError> {
    ring.set_polling();
    let mut stats = PumpStats::default();
    while let Some(sqe) = ring.poll_sqe().map_err(PumpError::Transport)? {
        stats.handled += 1;
        let outcome = provider.dispatch(&sqe);
        match resolve_completion(&sqe, outcome).map_err(PumpError::Provider)? {
            Some(cqe) => {
                // The receipt's `should_wake` is intentionally ignored: as in
                // slice 1 the kernel role polls the CQ, so the CQ-producer park
                // path is not driven here (deferred to a later slice).
                let _receipt = ring.post_cqe(cqe).map_err(|error| {
                    PumpError::Transport(TransportError::Ring(RingFault::from(error)))
                })?;
                stats.posted += 1;
            }
            None => stats.suppressed += 1,
        }
    }
    Ok(stats)
}

/// The stateful daemon dispatcher: one loop driving a [`FileSystem`] provider
/// end-to-end over one ring.
///
/// Owns everything the composed pipeline needs — the ring, the grant table, the
/// volatile open-lifecycle engine, the dir enumerator, a monotone
/// transaction-id source — and borrows the shared section (for the guarded
/// grant read/write) and the provider (`&mut F`). Per SQE the [`pump_once`]
/// method decodes → resolves grants → calls the trait → builds the wire result
/// → writes it into the U2K grant(s) → posts the matrix-validated completion.
///
/// The per-request grant owner is derived from the SQE's `req_id`
/// (`GrantOwner::Request(ReqId::from_raw(sqe.req_id))`): each request owns the
/// grants it submitted, so resolution keys on the current SQE's identity rather
/// than a daemon-wide owner.
pub struct Daemon<'sec, 'fs, S: SharedSection, F: FileSystem> {
    ring: DaemonRing<'sec>,
    section: &'sec S,
    table: GrantTable,
    lifecycle: OpenLifecycle,
    enumerator: DirEnumerator,
    fs: &'fs mut F,
    next_transaction_id: u64,
}

impl<'sec, 'fs, S: SharedSection, F: FileSystem> Daemon<'sec, 'fs, S, F> {
    /// The single ring index this daemon owns. Multi-ring routing (deriving the
    /// owning ring from the SQE's source ring) is a later sub-project; a
    /// single-section daemon owns ring 0.
    const OWNING_RING: u16 = 0;

    /// Compose a daemon over `ring`/`section`/`table` driving `fs`. The
    /// lifecycle engine and dir enumerator start empty, bound to the table's
    /// session epoch; the transaction-id counter starts at 1 (never the zero
    /// pair the lifecycle rejects).
    pub fn new(
        ring: DaemonRing<'sec>,
        section: &'sec S,
        table: GrantTable,
        fs: &'fs mut F,
    ) -> Self {
        let session_epoch = table.session_epoch();
        Self {
            ring,
            section,
            table,
            lifecycle: OpenLifecycle::new(session_epoch),
            enumerator: DirEnumerator::new(),
            fs,
            next_transaction_id: 1,
        }
    }

    /// The grant table (for read-back / inspection).
    pub fn table(&self) -> &GrantTable {
        &self.table
    }

    /// The open-lifecycle engine, mutable — for seeding/inspecting durable OPEN
    /// rows an embedder (or a test) recovers or asserts on.
    pub fn lifecycle_mut(&mut self) -> &mut OpenLifecycle {
        &mut self.lifecycle
    }

    /// Drain every ready request in one pass, driving each to completion through
    /// the full semantic pipeline. Stops at the first fault (any layer's), which
    /// is surfaced as a [`DaemonError`]; a rejected completion is never posted,
    /// leaving the ring coherent.
    pub fn pump_once(&mut self) -> Result<PumpStats, DaemonError> {
        self.ring.set_polling();
        let mut stats = PumpStats::default();
        while let Some(sqe) = self.ring.poll_sqe()? {
            stats.handled += 1;
            let completion = self.dispatch(&sqe)?;
            match resolve_completion(&sqe, completion)? {
                Some(cqe) => {
                    // The receipt's `should_wake` is ignored for the same reason
                    // as the free-fn `pump_once`: the kernel role polls the CQ.
                    let _receipt = self.ring.post_cqe(cqe).map_err(|error| {
                        DaemonError::Transport(TransportError::Ring(RingFault::from(error)))
                    })?;
                    stats.posted += 1;
                }
                None => stats.suppressed += 1,
            }
        }
        Ok(stats)
    }

    /// The next monotone, nonzero `TransactionId` to offer the lifecycle engine
    /// at `PREPARE_OPEN`. On an idempotent replay the engine returns its stored
    /// id and this candidate is discarded — harmless, since the counter is
    /// strictly increasing and every value is handed out at most once, so no two
    /// live records can ever collide on it.
    fn next_transaction(&mut self) -> Result<TransactionId, LifecycleFault> {
        let next = self
            .next_transaction_id
            .checked_add(1)
            .ok_or(LifecycleFault::CounterExhausted)?;
        let id = TransactionId {
            lo: self.next_transaction_id,
            hi: 0,
        };
        self.next_transaction_id = next;
        Ok(id)
    }

    /// Decode one popped SQE, drive it through its provider + engine + result
    /// pipeline, and return the completion [`pump_once`](Self::pump_once) posts.
    fn dispatch(&mut self, sqe: &SqeBody) -> Result<Completion, DaemonError> {
        let owner = GrantOwner::Request(ReqId::from_raw(sqe.req_id));
        let completion = match sqe.opcode {
            op::PREPARE_OPEN => {
                let request = decode_prepare(sqe, &self.table, self.section, owner)?;
                let candidate = self.next_transaction()?;
                let effect = match self.fs.prepare(&request, candidate) {
                    Ok(effect) => effect,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                // The engine returns the effective id (this candidate for a new
                // open, or the stored id on an idempotent replay); the result is
                // always built from the current SQE's fresh decode, never a
                // stored record.
                let transaction_id = match self.lifecycle.prepare(
                    request.clone(),
                    effect.clone(),
                    Self::OWNING_RING,
                    candidate,
                ) {
                    Ok(transaction_id) => transaction_id,
                    Err(error) => {
                        self.fs.abort(candidate);
                        return Err(error.into());
                    }
                };
                let bytes =
                    build_prepare_result(&request, &effect, transaction_id, &self.table, owner)?;
                self.write_output(&request.reply(), &bytes, owner)?;
                // `PrepareOpenResultV1.security_descriptor` is a BufferRef into
                // the SECOND U2K output grant; the reply write-back above only
                // wrote the 136-byte result, so the SD bytes must be written into
                // that result-SD grant too (guarded on a non-empty descriptor).
                if !effect.security_descriptor.is_empty() {
                    self.write_output(
                        &request.result_security_descriptor(),
                        &effect.security_descriptor,
                        owner,
                    )?;
                }
                build_prepare_completion(&request)?
            }
            op::COMMIT_OPEN => {
                let request = decode_commit(sqe, &self.table, self.section, owner)?;
                self.lifecycle.preflight_commit(&request)?;
                let effect = match self.fs.commit(&request) {
                    Ok(effect) => effect,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                let committed = self.lifecycle.commit(&request, effect)?;
                let bytes = build_commit_result(&request, &committed, &self.table, owner)?;
                self.write_output(&request.reply(), &bytes, owner)?;
                build_commit_completion(&request)?
            }
            op::ABORT_OPEN => {
                let reference = pcontrol_body_ref(sqe)?;
                let validated = self
                    .table
                    .resolve(&reference, owner, BufferRefPolicy::Exact)?;
                let body = resolve_body(self.section, &validated)?;
                let abort = AbortRequest::decode(body.as_slice())?;
                let transaction_id = TransactionId {
                    lo: abort.transaction_id_lo,
                    hi: abort.transaction_id_hi,
                };
                self.lifecycle.abort(transaction_id)?;
                self.fs.abort(transaction_id);
                Completion::success_empty()
            }
            op::CLEANUP => {
                let _barrier = BarrierRequest::decode(sqe)?;
                self.lifecycle.cleanup(sqe.kernel_open_id)?;
                self.fs.cleanup(sqe.kernel_open_id);
                Completion::success_empty()
            }
            op::CLOSE => {
                let _barrier = BarrierRequest::decode(sqe)?;
                self.lifecycle.close(sqe.kernel_open_id)?;
                self.fs.close(sqe.kernel_open_id);
                Completion::success_empty()
            }
            op::FLUSH => {
                // FLUSH carries a `PBarrier` shape but drives no lifecycle
                // transition — a pure provider durability barrier.
                let _barrier = BarrierRequest::decode(sqe)?;
                match self.fs.flush(sqe.kernel_open_id) {
                    Ok(()) => {}
                    Err(error) => return provider_failure(sqe.opcode, error),
                }
                Completion::success_empty()
            }
            op::READ => {
                let request = decode_read(sqe, &self.table, owner)?;
                let mut buf = vec![0u8; request.length as usize];
                let read = match self.fs.read(sqe.kernel_open_id, request.offset, &mut buf) {
                    Ok(read) => read,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                if read == 0 {
                    // Short of the first byte: EOF completes with zero output.
                    Completion::failure(completion_status::END_OF_FILE)
                } else {
                    // Build + self-validate the completion via the frozen
                    // `validate_read_success_v21` (the raw PRw + data grant +
                    // echo) BEFORE the write-back, mirroring how the WRITE arm
                    // self-validates through `build_write_result`. The full
                    // `length`-sized buffer is written (any tail beyond `read`
                    // stays zero); the completion reports `read` valid.
                    let completion =
                        build_read_completion(&request, read as u64, &self.table, owner)?;
                    self.write_output(&request.data, &buf, owner)?;
                    completion
                }
            }
            op::WRITE => {
                let request = decode_write(sqe, &self.table, self.section, owner)?;
                let outcome = match self.fs.write(sqe.kernel_open_id, &request) {
                    Ok(outcome) => outcome,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                let information = u64::from(outcome.information);
                let request_len =
                    u64::try_from(request.data().len()).map_err(|_| invalid_write_outcome())?;
                let information_usize =
                    usize::try_from(information).map_err(|_| invalid_write_outcome())?;
                if information == 0
                    || information > request_len
                    || information_usize > request.data().len()
                {
                    return Err(invalid_write_outcome());
                }
                let bytes =
                    build_write_result(&request, &outcome.effect, information, &self.table, owner)?;
                self.write_output(&request.reply(), &bytes, owner)?;
                let out = ocontrol_out(&request.reply(), bytes.len() as u32);
                Completion::complete_with(
                    0,
                    information,
                    out,
                    CompletionOutputContextV21::RequestLength(request.length()),
                )
            }
            op::QUERY_DIR => {
                let request = decode_query_dir(sqe, &self.table, self.section, owner)?;
                let result = match request.form {
                    QueryDirFormV21::Continuation => {
                        self.enumerator.continue_(sqe.kernel_open_id, &request)
                    }
                    QueryDirFormV21::InitialMatchAll
                    | QueryDirFormV21::InitialExpression { .. } => {
                        let candidates = match self.fs.query_dir(sqe.kernel_open_id, &request) {
                            Ok(candidates) => candidates,
                            Err(error) => return provider_failure(sqe.opcode, error),
                        };
                        self.enumerator
                            .open(sqe.kernel_open_id, &request, candidates)
                    }
                };
                match result {
                    Ok(batch) => {
                        self.write_output(&request.output, &batch.blob, owner)?;
                        build_query_dir_completion(&request, batch.blob.len() as u32)?
                    }
                    Err(EnumError::NoMoreEntries) => {
                        let status = match request.form {
                            QueryDirFormV21::InitialMatchAll
                            | QueryDirFormV21::InitialExpression { .. } => {
                                completion_status::NO_SUCH_FILE
                            }
                            QueryDirFormV21::Continuation => completion_status::NO_MORE_FILES,
                        };
                        Completion::failure(status)
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            op::QUERY_INFO => {
                let request = decode_query_info(sqe, &self.table, self.section, owner)?;
                let fields = match self.fs.query_info(sqe.kernel_open_id) {
                    Ok(fields) => fields,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                let bytes = build_file_info(&fields)?;
                self.write_output(&request.output, &bytes, owner)?;
                let out = ocontrol_out(&request.output, bytes.len() as u32);
                Completion::complete_with(
                    0,
                    bytes.len() as u64,
                    out,
                    CompletionOutputContextV21::CanonicalBlobLength(bytes.len() as u64),
                )
            }
            op::QUERY_VOLUME => {
                let request = decode_query_volume(sqe, &self.table, self.section, owner)?;
                let fields = match self.fs.query_volume() {
                    Ok(fields) => fields,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                let bytes = build_volume_size_info(&fields)?;
                self.write_output(&request.output, &bytes, owner)?;
                let out = ocontrol_out(&request.output, bytes.len() as u32);
                Completion::complete_with(
                    0,
                    bytes.len() as u64,
                    out,
                    CompletionOutputContextV21::CanonicalBlobLength(bytes.len() as u64),
                )
            }
            op::QUERY_SECURITY => {
                let request = decode_query_security(sqe, &self.table, self.section, owner)?;
                let descriptor = match self
                    .fs
                    .query_security(sqe.kernel_open_id, request.security_information)
                {
                    Ok(descriptor) => descriptor,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                // Validate-then-write (matching the other arms): build + self-
                // validate the completion before the descriptor write-back.
                let completion =
                    build_query_security_completion(&request, descriptor.len() as u32)?;
                self.write_output(&request.output, &descriptor, owner)?;
                completion
            }
            op::MUTATE => {
                let request = decode_mutation(sqe, &self.table, self.section, owner, false)?;
                let context = match self.fs.mutation_context(&request) {
                    Ok(context) => context,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                let request = revalidate_context(request, &self.table, owner, context)?;
                let effect = match self.fs.mutate(&request) {
                    Ok(effect) => effect,
                    Err(error) => return provider_failure(sqe.opcode, error),
                };
                let result = build_mutation_result(&request, &effect, &self.table, owner)?;
                self.write_output(&request.reply(), &result.result, owner)?;
                // The kind result is a real echo only for rename/link/unlink; the
                // metadata/size/security kinds produce an empty vec (a NONE
                // kind_result grant), which has nothing to write back.
                if !result.kind_result.is_empty() {
                    self.write_output(&request.kind_result(), &result.kind_result, owner)?;
                }
                build_mutate_completion(&request)?
            }
            other => return Err(DaemonError::UnhandledOpcode { opcode: other }),
        };
        Ok(completion)
    }

    /// Write `bytes` back into the U2K output `grant` (a `reply` / `output` /
    /// `kind_result` echo), single-writing exactly `bytes.len()` bytes into the
    /// front of the granted slot. The destination echo is shrunk to the produced
    /// length and validated `ShrinkOnly`, so a result shorter than the issued
    /// grant (a small enumeration batch, a short security descriptor) is legal.
    fn write_output(
        &self,
        grant: &BufferRef,
        bytes: &[u8],
        owner: GrantOwner,
    ) -> Result<(), DaemonError> {
        let destination = BufferRef {
            token: grant.token,
            offset: 0,
            length: bytes.len() as u32,
            kind: grant.kind,
            access: grant.access,
            reserved: 0,
        };
        let validated = self
            .table
            .resolve(&destination, owner, BufferRefPolicy::ShrinkOnly)?;
        write_body(self.section, &validated, bytes)?;
        Ok(())
    }
}

/// Build the 24-byte `OControl` echo output for a request-derived completion
/// (`READ`/`WRITE`, `QUERY_INFO`/`QUERY_VOLUME`): the destination `grant` shrunk
/// to `length` valid bytes, encoded into an [`OutBuf`]. The frozen output matrix
/// (applied by [`resolve_completion`]) only fixes `out_len == 24`; the echoed
/// length is informational.
fn ocontrol_out(grant: &BufferRef, length: u32) -> OutBuf {
    let echo = OControl {
        body: BufferRef {
            token: grant.token,
            offset: 0,
            length,
            kind: grant.kind,
            access: grant.access,
            reserved: 0,
        },
    };
    let mut bytes = vec![0u8; core::mem::size_of::<OControl>()];
    try_encode(&echo, &mut bytes).expect("OControl encodes into its own size");
    OutBuf::new(&bytes).expect("size_of::<OControl>() (24) <= CQE_OUT_LEN")
}

// The dispatch-loop tests drive a real ring via the kernel-role `Harness`, which
// is `testkit`-gated; so is this module (mirrors `tests/roundtrip.rs`).
#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::provider::EchoProvider;
    use crate::testkit::Harness;
    use fsring_abi::layout::{cq_kind, op, sqe_flags, SqeBody, SQE_PAYLOAD_LEN};

    fn req(opcode: u16, flags: u16, req_id: u64) -> SqeBody {
        SqeBody {
            opcode,
            flags,
            payload_len: 24,
            reserved: 0,
            req_id,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload: [0u8; SQE_PAYLOAD_LEN],
        }
    }

    #[test]
    fn pump_echoes_a_registered_request_and_counts_it() {
        let harness = Harness::new_single_ring();
        let kernel = harness.kernel_ring();
        let mut daemon = harness.daemon_ring();
        let mut provider = EchoProvider;

        let _receipt = kernel.submit(req(op::CLEANUP, 0, 7)).expect("submit");
        let stats = pump_once(&mut daemon, &mut provider).expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);
        assert_eq!(stats.suppressed, 0);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("completion ready");
        assert_eq!(cqe.req_id, 7);
        assert_eq!(cqe.kind, cq_kind::COMPLETION);
        assert_eq!(cqe.status, 0);
    }

    #[test]
    fn pump_suppresses_a_fire_and_forget_request() {
        let harness = Harness::new_single_ring();
        let kernel = harness.kernel_ring();
        let mut daemon = harness.daemon_ring();
        let mut provider = EchoProvider;

        let _receipt = kernel
            .submit(req(op::CLEANUP, sqe_flags::NO_COMPLETION, 9))
            .expect("submit");
        let stats = pump_once(&mut daemon, &mut provider).expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 0);
        assert_eq!(stats.suppressed, 1);

        let mut kernel = kernel;
        assert!(kernel.reap().expect("reap").is_none(), "no CQE posted");
    }

    #[test]
    fn pump_empty_sq_is_no_work() {
        let harness = Harness::new_single_ring();
        let mut daemon = harness.daemon_ring();
        let mut provider = EchoProvider;
        let stats = pump_once(&mut daemon, &mut provider).expect("pump");
        assert_eq!(stats, PumpStats::default());
    }
}

// The stateful-dispatcher tests drive a grant-backed SQE through a full `Daemon`
// round-trip: submit on the kernel ring, `pump_once`, reap, and read the U2K
// write-back back out of the section. An inline stub `FileSystem` supplies canned
// effects (the full testkit provider stub + broad per-op coverage is Task 11).
#[cfg(all(test, feature = "testkit"))]
mod stateful_tests {
    use super::Daemon;
    use crate::dataio::{decode_read, WriteOutcome, WriteRequest};
    use crate::direnum::{DirCandidate, DirEntryFields, DirEnumerator};
    use crate::filesystem::{FileSystem, FileSystemResult};
    use crate::grant::{resolve_body, GrantTable};
    use crate::lifecycle::{CommitEffect, OpenLifecycle, PrepareResult, RowState};
    use crate::mutation::{MutationEffect, MutationRequest};
    use crate::openbody::{CommitRequest, PreparedRequest};
    use crate::querydir::{decode_query_dir, QueryDirRequest};
    use crate::queryinfo::FileInfoFields;
    use crate::queryvolume::VolumeSizeFields;
    use crate::testkit::{CommitFixture, Harness, PrepareFixture, QueryDirFixture, ReadFixture};
    use crate::MutationContext;

    use fsring_abi::codec::try_decode;
    use fsring_abi::ids::{FileId, LinkId, OpId, TransactionId};
    use fsring_abi::layout::{op, SqeBody, SQE_PAYLOAD_LEN};
    use fsring_abi::msgs::{
        create_result, file_attributes, BufferRef, CommitOpenV2, PrepareOpenV2, SizeState,
    };
    use fsring_abi::slots::BufferRefPolicy;
    use fsring_abi::validate::completion_status;

    /// An inline `FileSystem` stub with canned effects: enough for the CLEANUP,
    /// QUERY_DIR, and READ round-trips exercised here. The unexercised open/write/
    /// mutate/query-info/query-volume/query-security methods are
    /// `unimplemented!()` (Task 11 supplies the full behavioral stub).
    #[derive(Default)]
    struct StubFs {
        candidates: Vec<DirCandidate>,
        read_returns: usize,
        cleanups: Vec<u64>,
        prepare_candidates: Vec<TransactionId>,
        commit_calls: usize,
    }

    impl FileSystem for StubFs {
        fn prepare(
            &mut self,
            _request: &PreparedRequest,
            transaction_id: TransactionId,
        ) -> FileSystemResult<PrepareResult> {
            self.prepare_candidates.push(transaction_id);
            unimplemented!("open lifecycle is compile-checked, not exercised here")
        }
        fn commit(&mut self, _request: &CommitRequest) -> FileSystemResult<CommitEffect> {
            self.commit_calls += 1;
            unimplemented!("open lifecycle is compile-checked, not exercised here")
        }
        fn abort(&mut self, _transaction_id: TransactionId) {}
        fn cleanup(&mut self, kernel_open_id: u64) {
            self.cleanups.push(kernel_open_id);
        }
        fn close(&mut self, _kernel_open_id: u64) {}
        fn read(
            &mut self,
            _kernel_open_id: u64,
            _offset: u64,
            buf: &mut [u8],
        ) -> FileSystemResult<usize> {
            let read = self.read_returns.min(buf.len());
            for (index, byte) in buf[..read].iter_mut().enumerate() {
                *byte = (index % 251) as u8;
            }
            Ok(read)
        }
        fn write(
            &mut self,
            _kernel_open_id: u64,
            _request: &WriteRequest,
        ) -> FileSystemResult<WriteOutcome> {
            unimplemented!("WRITE is compile-checked, not exercised here")
        }
        fn flush(&mut self, _kernel_open_id: u64) -> FileSystemResult<()> {
            Ok(())
        }
        fn query_dir(
            &mut self,
            _kernel_open_id: u64,
            _request: &QueryDirRequest,
        ) -> FileSystemResult<Vec<DirCandidate>> {
            Ok(self.candidates.clone())
        }
        fn query_info(&mut self, _kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
            unimplemented!("QUERY_INFO is compile-checked, not exercised here")
        }
        fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
            unimplemented!("QUERY_VOLUME is compile-checked, not exercised here")
        }
        fn query_security(
            &mut self,
            _kernel_open_id: u64,
            _security_information: u32,
        ) -> FileSystemResult<Vec<u8>> {
            unimplemented!("QUERY_SECURITY is compile-checked, not exercised here")
        }
        fn mutation_context(
            &mut self,
            _request: &MutationRequest,
        ) -> FileSystemResult<MutationContext> {
            unimplemented!("MUTATE is compile-checked, not exercised here")
        }
        fn mutate(&mut self, _request: &MutationRequest) -> FileSystemResult<MutationEffect> {
            unimplemented!("MUTATE is compile-checked, not exercised here")
        }
    }

    fn ok_sizes() -> SizeState {
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        }
    }

    fn candidate(name: &str) -> DirCandidate {
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        DirCandidate {
            name: utf16.into_boxed_slice(),
            fields: DirEntryFields {
                file_id: FileId { lo: 1, hi: 0 },
                link_id: LinkId { lo: 1, hi: 0 },
                sizes: ok_sizes(),
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                namespace_generation: 1,
                attributes: file_attributes::NORMAL,
            },
        }
    }

    /// A zeroed-tail `PBarrier` SQE for a barrier opcode (CLEANUP/CLOSE/FLUSH):
    /// `payload_len = 24`, an all-zero payload (`op_id`/`flags`/`reserved` zero),
    /// carrying the `kernel_open_id` the barrier targets.
    fn barrier_sqe(opcode: u16, req_id: u64, kernel_open_id: u64) -> SqeBody {
        SqeBody {
            opcode,
            flags: 0,
            payload_len: 24,
            reserved: 0,
            req_id,
            kernel_open_id,
            ccb_sequence: 0,
            payload: [0u8; SQE_PAYLOAD_LEN],
        }
    }

    /// Seed a live OPEN row at `kernel_open_id` by driving the engine's public
    /// prepare+commit path (mirrors `lifecycle.rs`'s test seeding), so a CLEANUP
    /// for that open finds a LIVE row instead of a `RowCorruption` fault.
    fn seed_open(lifecycle: &mut OpenLifecycle, kernel_open_id: u64) {
        let mut prepare_raw: PrepareOpenV2 =
            try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
        prepare_raw.op_id = OpId { lo: 1, hi: 0 };
        let prepared = PreparedRequest::from_raw(
            prepare_raw,
            b"a.txt".to_vec().into_boxed_slice(),
            None,
            None,
        );
        let result = PrepareResult {
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            security_descriptor: vec![0u8; 20].into_boxed_slice(),
            object_flags: 0,
        };
        lifecycle
            .prepare(prepared, result, 0, TransactionId { lo: 0x22, hi: 0 })
            .expect("seed prepare");

        let mut commit_raw: CommitOpenV2 =
            try_decode(&[0u8; 104]).expect("zeroed CommitOpenV2 decodes");
        commit_raw.op_id = OpId { lo: 1, hi: 0 };
        commit_raw.transaction_id = TransactionId { lo: 0x22, hi: 0 };
        commit_raw.expected_namespace_generation = 1;
        commit_raw.expected_security_generation = 1;
        commit_raw.kernel_open_id = kernel_open_id;
        commit_raw.granted_access = 1;
        let commit = CommitRequest::from_raw(commit_raw);
        let effect = CommitEffect {
            create_result: create_result::CREATED,
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            volume_commit_sequence: 5,
        };
        lifecycle.commit(&commit, effect).expect("seed commit");
    }

    #[test]
    fn cleanup_round_trips_a_live_open() {
        let harness = Harness::new_single_ring();
        let table = GrantTable::new(harness.session_epoch());
        let mut fs = StubFs::default();
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        seed_open(daemon.lifecycle_mut(), 0x33);

        let kernel = harness.kernel_ring();
        let _receipt = kernel
            .submit(barrier_sqe(op::CLEANUP, 7, 0x33))
            .expect("submit");
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);
        assert_eq!(stats.suppressed, 0);

        // The barrier drove the durable row LIVE -> CLEANED.
        assert_eq!(
            daemon.lifecycle_mut().row_state(0x33),
            Some(RowState::Cleaned)
        );

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.req_id, 7);
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.information, 0);
    }

    #[test]
    fn query_dir_round_trips_and_writes_the_batch_back() {
        let candidates = vec![candidate("a.txt"), candidate("b.txt")];
        let (harness, table, sqe, owner) = QueryDirFixture::match_all().into_parts();

        // Reference batch: decode the same request and run a fresh enumerator
        // over the same candidates the stub returns.
        let request = decode_query_dir(&sqe, &table, harness.section(), owner).expect("decode");
        let mut reference = DirEnumerator::new();
        let expected = reference
            .open(sqe.kernel_open_id, &request, candidates.clone())
            .expect("reference batch");

        let mut fs = StubFs {
            candidates,
            ..Default::default()
        };
        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected.blob.len() as u64);

        // The U2K output grant holds exactly the enumerator's batch bytes.
        let shrunk = BufferRef {
            token: request.output.token,
            offset: 0,
            length: expected.blob.len() as u32,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve output");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected.blob.as_slice());
    }

    #[test]
    fn read_round_trips_and_writes_the_fetched_bytes() {
        let (harness, table, sqe, owner) = ReadFixture::valid().into_parts();
        let request = decode_read(&sqe, &table, owner).expect("decode");

        let mut fs = StubFs {
            read_returns: request.length as usize,
            ..Default::default()
        };
        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        daemon.pump_once().expect("pump");

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, request.length as u64);

        // The U2K data grant holds the provider's fetched pattern.
        let validated = daemon
            .table()
            .resolve(&request.data, owner, BufferRefPolicy::Exact)
            .expect("resolve data");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        let expected: Vec<u8> = (0..request.length as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(view.as_slice(), expected.as_slice());
    }

    #[test]
    fn read_at_eof_completes_with_end_of_file_and_no_output() {
        let (harness, table, sqe, _owner) = ReadFixture::valid().into_parts();
        let mut fs = StubFs {
            read_returns: 0,
            ..Default::default()
        };
        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        daemon.pump_once().expect("pump");

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, completion_status::END_OF_FILE);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.information, 0);
    }

    #[test]
    fn open_lifecycle_transaction_counter_exhaustion_skips_provider_and_state() {
        let fixture = PrepareFixture::build();
        let op_id = fixture.op_id;
        let (harness, table, sqe, _) = fixture.into_parts();
        let mut fs = StubFs::default();
        let kernel = harness.kernel_ring();
        let _ = kernel.submit(sqe).expect("submit prepare");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        daemon.next_transaction_id = u64::MAX;

        assert_eq!(
            daemon.pump_once(),
            Err(crate::error::DaemonError::Lifecycle(
                crate::error::LifecycleFault::CounterExhausted
            ))
        );
        assert_eq!(daemon.next_transaction_id, u64::MAX);
        assert!(!daemon.lifecycle.has_prepare(op_id));
        assert_eq!(daemon.lifecycle.retained_prepare_bytes(), 0);
        drop(daemon);
        assert!(fs.prepare_candidates.is_empty());
    }

    #[test]
    fn open_lifecycle_cookie_counter_exhaustion_skips_provider_and_state() {
        let fixture = CommitFixture::build();
        let op_id = fixture.op_id;
        let transaction_id = fixture.transaction_id;
        let kernel_open_id = fixture.kernel_open_id;
        let (harness, table, sqe, _) = fixture.into_parts();
        let mut fs = StubFs::default();
        let kernel = harness.kernel_ring();
        let _ = kernel.submit(sqe).expect("submit commit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);

        let mut raw: PrepareOpenV2 = try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
        raw.op_id = op_id;
        let prepared =
            PreparedRequest::from_raw(raw, b"a.txt".to_vec().into_boxed_slice(), None, None);
        daemon
            .lifecycle
            .prepare(
                prepared,
                PrepareResult {
                    file_id: FileId { lo: 9, hi: 0 },
                    link_id: LinkId { lo: 9, hi: 0 },
                    sizes: ok_sizes(),
                    namespace_generation: 1,
                    security_generation: 1,
                    security_descriptor: vec![0u8; 20].into_boxed_slice(),
                    object_flags: 0,
                },
                0,
                transaction_id,
            )
            .expect("seed prepare");
        let retained = daemon.lifecycle.retained_prepare_bytes();
        daemon.lifecycle.exhaust_cookie_counter_for_test();

        assert_eq!(
            daemon.pump_once(),
            Err(crate::error::DaemonError::Lifecycle(
                crate::error::LifecycleFault::CounterExhausted
            ))
        );
        assert!(daemon.lifecycle.has_prepare(op_id));
        assert_eq!(daemon.lifecycle.row_state(kernel_open_id), None);
        assert_eq!(daemon.lifecycle.retained_prepare_bytes(), retained);
        drop(daemon);
        assert_eq!(fs.commit_calls, 0);
    }
}
