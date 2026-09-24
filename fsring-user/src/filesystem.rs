//! The semantic `FileSystem` trait: the seam a real filesystem provider plugs
//! into (design `2026-07-22-fsring-user-daemon-sdk-completion-design.md` §7.1).
//!
//! Every method is **request-in, effect-out**: it takes a decoded,
//! ABI-validated request (or the bare scalars a lifecycle/barrier opcode
//! carries) and returns a semantic effect value — never a wire type, never a
//! grant, never a `BufferRef`. The existing effect types the earlier decode
//! modules already defined are reused as-is (`PrepareResult`/`CommitEffect`
//! from [`crate::lifecycle`], `MutationEffect` from [`crate::mutation`],
//! `DirCandidate` from [`crate::direnum`], `WriteOutcome` from
//! [`crate::dataio`], `FileInfoFields` from [`crate::queryinfo`],
//! `VolumeSizeFields` from [`crate::queryvolume`]) — this module adds nothing
//! new but the trait itself. The `Daemon` dispatcher (a later task) is the
//! only caller: decode -> resolve grants -> call the trait -> build the wire
//! result -> write back -> complete.

use fsring_abi::ids::TransactionId;
use fsring_abi::validate::completion_status;

use crate::dataio::{WriteOutcome, WriteRequest};
use crate::direnum::DirCandidate;
use crate::lifecycle::{CommitEffect, PrepareResult};
use crate::mutation::{MutationEffect, MutationRequest};
use crate::openbody::{CommitRequest, PreparedRequest};
use crate::querydir::QueryDirRequest;
use crate::queryinfo::FileInfoFields;
use crate::queryvolume::VolumeSizeFields;

/// A semantic failure reported by a filesystem provider.
///
/// The daemon validates its status against the frozen completion registry for
/// the current opcode before publishing the resulting zero-output completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderError {
    status: i32,
}

impl ProviderError {
    /// Construct a provider failure with a completion status to be validated by
    /// the daemon for the operation being completed.
    pub const fn terminal(status: i32) -> Self {
        Self { status }
    }

    /// Construct the canonical failure for an internal provider failure.
    pub const fn internal() -> Self {
        Self {
            status: completion_status::IO_DEVICE_ERROR,
        }
    }

    /// The requested completion status.
    pub const fn status(self) -> i32 {
        self.status
    }
}

/// The result returned by a fallible filesystem provider operation.
pub type FileSystemResult<T> = Result<T, ProviderError>;

/// Backing-filesystem facts needed to finish validating an owned mutation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MutationContext {
    pub same_parent_rename: bool,
}

/// The provider seam: every filesystem operation the `Daemon` dispatcher
/// drives, as one request-in/effect-out method. No wire type, grant, or
/// `BufferRef` ever crosses this boundary — decoding/grant-resolution happens
/// before the call, and result-building/write-back happens after it.
pub trait FileSystem {
    // --- open lifecycle ---
    /// `PREPARE_OPEN`: validate/resolve the open against namespace state and
    /// return the values [`crate::lifecycle::OpenLifecycle::prepare`] retains
    /// for idempotent replay and the eventual `PrepareOpenResultV1`. On an
    /// identical replay, ignore the fresh `transaction_id` candidate and return
    /// the provider's stored [`PrepareResult`]; the lifecycle supplies the
    /// effective stored [`TransactionId`] used in the completion.
    fn prepare(
        &mut self,
        request: &PreparedRequest,
        transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult>;
    /// `COMMIT_OPEN`: durably materialize the prepared open and return its
    /// committed outcome (`create_result`, identity, sizes, generations, the
    /// mount-wide commit sequence).
    fn commit(&mut self, request: &CommitRequest) -> FileSystemResult<CommitEffect>;
    /// `ABORT_OPEN`/cancellation: discard a prepared-but-uncommitted open.
    fn abort(&mut self, transaction_id: TransactionId);
    /// Transition a committed open `LIVE -> CLEANED` (the provider's own
    /// last-handle bookkeeping; the durable row transition is the engine's).
    fn cleanup(&mut self, kernel_open_id: u64);
    /// Release the provider's last resources for a `CLEANED` open.
    fn close(&mut self, kernel_open_id: u64);

    // --- data ---
    /// Fill `buf` from `offset` and return the number of bytes actually read
    /// (`<= buf.len()`; short of EOF).
    fn read(&mut self, kernel_open_id: u64, offset: u64, buf: &mut [u8])
        -> FileSystemResult<usize>;
    /// Write the decoded request and return the exact committed byte count plus
    /// the post-write size state and mount-wide commit sequence.
    fn write(
        &mut self,
        kernel_open_id: u64,
        request: &WriteRequest,
    ) -> FileSystemResult<WriteOutcome>;
    /// Durably persist any buffered writes for the open.
    fn flush(&mut self, kernel_open_id: u64) -> FileSystemResult<()>;

    // --- query ---
    /// `QUERY_DIR`: the matched candidates for one enumeration request, in
    /// provider order (the `DirEnumerator` applies the name filter/paging).
    fn query_dir(
        &mut self,
        kernel_open_id: u64,
        request: &QueryDirRequest,
    ) -> FileSystemResult<Vec<DirCandidate>>;
    /// `QUERY_INFO`: the current file-information fields.
    fn query_info(&mut self, kernel_open_id: u64) -> FileSystemResult<FileInfoFields>;
    /// `QUERY_VOLUME`: the current volume-size fields (not per-open).
    fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields>;
    /// `QUERY_SECURITY`: the self-relative security-descriptor bytes selected
    /// by `security_information`.
    fn query_security(
        &mut self,
        kernel_open_id: u64,
        security_information: u32,
    ) -> FileSystemResult<Vec<u8>>;

    // --- mutate ---
    /// Return backing-state facts needed to finish validating `request`.
    fn mutation_context(&mut self, request: &MutationRequest) -> FileSystemResult<MutationContext>;
    /// Apply the fully revalidated mutation and return its committed effect.
    fn mutate(&mut self, request: &MutationRequest) -> FileSystemResult<MutationEffect>;
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use fsring_abi::ids::TransactionId;
    use fsring_abi::msgs::{file_attributes, SizeState};

    use crate::dataio::{WriteOutcome, WriteRequest};
    use crate::direnum::DirCandidate;
    use crate::lifecycle::{CommitEffect, PrepareResult};
    use crate::mutation::{MutationEffect, MutationRequest};
    use crate::openbody::{CommitRequest, PreparedRequest};
    use crate::querydir::QueryDirRequest;
    use crate::queryinfo::FileInfoFields;
    use crate::queryvolume::VolumeSizeFields;

    use super::{FileSystem, FileSystemResult, MutationContext};

    /// A trivial stub proving the trait is object-safe/usable: every method
    /// compiles with a canned/`unimplemented!()` body. Never invoked (this is
    /// a compile-level contract, not a behavioral one).
    struct NullFs;

    impl FileSystem for NullFs {
        fn prepare(
            &mut self,
            _request: &PreparedRequest,
            _transaction_id: TransactionId,
        ) -> FileSystemResult<PrepareResult> {
            unimplemented!()
        }

        fn commit(&mut self, _request: &CommitRequest) -> FileSystemResult<CommitEffect> {
            unimplemented!()
        }

        fn abort(&mut self, _transaction_id: TransactionId) {
            unimplemented!()
        }

        fn cleanup(&mut self, _kernel_open_id: u64) {
            unimplemented!()
        }

        fn close(&mut self, _kernel_open_id: u64) {
            unimplemented!()
        }

        fn read(
            &mut self,
            _kernel_open_id: u64,
            _offset: u64,
            _buf: &mut [u8],
        ) -> FileSystemResult<usize> {
            unimplemented!()
        }

        fn write(
            &mut self,
            _kernel_open_id: u64,
            _request: &WriteRequest,
        ) -> FileSystemResult<WriteOutcome> {
            unimplemented!()
        }

        fn flush(&mut self, _kernel_open_id: u64) -> FileSystemResult<()> {
            unimplemented!()
        }

        fn query_dir(
            &mut self,
            _kernel_open_id: u64,
            _request: &QueryDirRequest,
        ) -> FileSystemResult<Vec<DirCandidate>> {
            unimplemented!()
        }

        fn query_info(&mut self, _kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
            unimplemented!()
        }

        fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
            unimplemented!()
        }

        fn query_security(
            &mut self,
            _kernel_open_id: u64,
            _security_information: u32,
        ) -> FileSystemResult<Vec<u8>> {
            unimplemented!()
        }

        fn mutation_context(
            &mut self,
            _request: &MutationRequest,
        ) -> FileSystemResult<MutationContext> {
            unimplemented!()
        }

        fn mutate(&mut self, _request: &MutationRequest) -> FileSystemResult<MutationEffect> {
            unimplemented!()
        }
    }

    #[test]
    fn null_fs_implements_the_trait_and_is_object_usable() {
        let mut fs = NullFs;
        // Object-safety: a `NullFs` must coerce to `&mut dyn FileSystem`.
        let _: &mut dyn FileSystem = &mut fs;
    }

    /// A valid `SizeState` (monotone, nonzero epoch) shared by the fixtures
    /// below.
    fn ok_sizes() -> SizeState {
        SizeState {
            allocation_size: 8192,
            file_size: 4096,
            valid_data_length: 4096,
            size_epoch: 1,
        }
    }

    #[test]
    fn write_outcome_constructs() {
        let _ = WriteOutcome {
            information: 1,
            effect: crate::dataio::WriteEffect {
                sizes: ok_sizes(),
                volume_commit_sequence: 1,
            },
        };
    }

    #[test]
    fn file_info_fields_constructs() {
        let _ = FileInfoFields {
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            attributes: file_attributes::ARCHIVE,
            link_count: 1,
        };
    }

    #[test]
    fn volume_size_fields_constructs() {
        let _ = VolumeSizeFields {
            total_allocation_units: 1000,
            available_allocation_units: 500,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        };
    }
}
