#![no_main]
//! Fuzz the `FileSystem` failure-status seam through the stateful daemon. For
//! an arbitrary `ProviderError::terminal(i32)` on a valid FLUSH, the only legal
//! outcomes are a registered, zero-output failure CQE or the exact matching
//! `IllegalFailureStatus` provider violation with no CQE posted.

use fsring_abi::ids::TransactionId;
use fsring_abi::layout::{op, SqeBody, CQE_OUT_LEN, SQE_PAYLOAD_LEN};
use fsring_abi::validate::{completion_status, is_registered_completion_status_v21};
use fsring_user::testkit::Harness;
use fsring_user::{
    CommitEffect, CommitRequest, Daemon, DaemonError, DirCandidate, FileInfoFields, FileSystem,
    FileSystemResult, GrantTable, MutationContext, MutationEffect, MutationRequest, PrepareResult,
    PreparedRequest, ProviderError, ProviderViolation, QueryDirRequest, VolumeSizeFields,
    WriteOutcome, WriteRequest,
};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy)]
struct FlushFailure(ProviderError);

impl FileSystem for FlushFailure {
    fn prepare(
        &mut self,
        _request: &PreparedRequest,
        _transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult> {
        unreachable!("the target submits only FLUSH")
    }

    fn commit(&mut self, _request: &CommitRequest) -> FileSystemResult<CommitEffect> {
        unreachable!("the target submits only FLUSH")
    }

    fn abort(&mut self, _transaction_id: TransactionId) {
        unreachable!("the target submits only FLUSH")
    }

    fn cleanup(&mut self, _kernel_open_id: u64) {
        unreachable!("the target submits only FLUSH")
    }

    fn close(&mut self, _kernel_open_id: u64) {
        unreachable!("the target submits only FLUSH")
    }

    fn read(
        &mut self,
        _kernel_open_id: u64,
        _offset: u64,
        _buf: &mut [u8],
    ) -> FileSystemResult<usize> {
        unreachable!("the target submits only FLUSH")
    }

    fn write(
        &mut self,
        _kernel_open_id: u64,
        _request: &WriteRequest,
    ) -> FileSystemResult<WriteOutcome> {
        unreachable!("the target submits only FLUSH")
    }

    fn flush(&mut self, _kernel_open_id: u64) -> FileSystemResult<()> {
        Err(self.0)
    }

    fn query_dir(
        &mut self,
        _kernel_open_id: u64,
        _request: &QueryDirRequest,
    ) -> FileSystemResult<Vec<DirCandidate>> {
        unreachable!("the target submits only FLUSH")
    }

    fn query_info(&mut self, _kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
        unreachable!("the target submits only FLUSH")
    }

    fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
        unreachable!("the target submits only FLUSH")
    }

    fn query_security(
        &mut self,
        _kernel_open_id: u64,
        _security_information: u32,
    ) -> FileSystemResult<Vec<u8>> {
        unreachable!("the target submits only FLUSH")
    }

    fn mutation_context(
        &mut self,
        _request: &MutationRequest,
    ) -> FileSystemResult<MutationContext> {
        unreachable!("the target submits only FLUSH")
    }

    fn mutate(&mut self, _request: &MutationRequest) -> FileSystemResult<MutationEffect> {
        unreachable!("the target submits only FLUSH")
    }
}

fn flush_sqe() -> SqeBody {
    SqeBody {
        opcode: op::FLUSH,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id: 1,
        kernel_open_id: 1,
        ccb_sequence: 0,
        payload: [0; SQE_PAYLOAD_LEN],
    }
}

fn accepts_provider_rejection(error: &DaemonError, status: i32) -> bool {
    match error {
        DaemonError::Provider(ProviderViolation::IllegalFailureStatus {
            opcode,
            status: observed,
        }) => *opcode == op::FLUSH && *observed == status,
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    assert!(
        !accepts_provider_rejection(
            &DaemonError::Provider(ProviderViolation::UnexpectedCompletion),
            completion_status::SUCCESS,
        ),
        "a non-status ProviderViolation must not satisfy the illegal-status oracle",
    );
    assert!(
        !accepts_provider_rejection(
            &DaemonError::Provider(ProviderViolation::IllegalFailureStatus {
                opcode: op::FLUSH,
                status: completion_status::PENDING,
            }),
            completion_status::SUCCESS,
        ),
        "the observed illegal status must equal the provider's status",
    );
    assert!(
        !accepts_provider_rejection(
            &DaemonError::Provider(ProviderViolation::IllegalFailureStatus {
                opcode: op::READ,
                status: completion_status::SUCCESS,
            }),
            completion_status::SUCCESS,
        ),
        "the illegal-status violation must belong to FLUSH",
    );

    let mut bytes = [0u8; 4];
    let len = data.len().min(bytes.len());
    bytes[..len].copy_from_slice(&data[..len]);
    let status = i32::from_le_bytes(bytes);
    let legal_failure = status != completion_status::SUCCESS
        && status != completion_status::PENDING
        && is_registered_completion_status_v21(op::FLUSH, status);

    let harness = Harness::new_single_ring();
    let table = GrantTable::new(harness.session_epoch());
    let mut kernel = harness.kernel_ring();
    let _receipt = kernel
        .submit(flush_sqe())
        .expect("an empty single-ring SQ accepts one FLUSH");
    let mut fs = FlushFailure(ProviderError::terminal(status));
    let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
    let result = daemon.pump_once();
    let posted = kernel.reap().expect("reap must not fault");

    match result {
        Ok(stats) => {
            assert!(legal_failure, "an illegal provider status was posted");
            assert_eq!(stats.handled, 1);
            assert_eq!(stats.posted, 1);
            assert_eq!(stats.suppressed, 0);
            let cqe = posted.expect("a legal provider failure posts one CQE");
            assert_eq!(cqe.opcode, op::FLUSH);
            assert_eq!(cqe.status, status);
            assert_eq!(cqe.information, 0);
            assert_eq!(cqe.out_len, 0);
            assert_eq!(cqe.out, [0; CQE_OUT_LEN]);
            assert!(is_registered_completion_status_v21(cqe.opcode, cqe.status));
        }
        Err(error) if accepts_provider_rejection(&error, status) => {
            assert!(!legal_failure, "a legal provider failure was rejected");
            assert!(posted.is_none(), "a rejected provider status posted a CQE");
        }
        Err(other) => panic!("provider status escaped as a non-provider error: {other:?}"),
    }
});
