//! Error types for the `fsring-user` transport layer.
//!
//! [`SectionError`] classifies faults found while validating a peer-constructed
//! section as hostile input. [`RingFault`] surfaces the ABI ring core's protocol
//! faults. [`TransportError`] is their union at the daemon API boundary.

use fsring_abi::ring::{CursorFault, PopError, PushError};
use fsring_abi::slots::{BufferRefError, SlotLayoutError};
use fsring_abi::validate::{
    CompletionOutputContextV21, MessageValidationError, QueryValidationError,
};

use crate::control::ControlBodyError;
use crate::namematch::NameMatchError;
use crate::payload::PayloadError;

/// A fault detected while validating a peer-constructed section.
///
/// Every variant is a classified rejection; none is ever produced by a
/// dereference of an unvalidated offset (validation single-fetches the header
/// into a local copy and checks bounds before use).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionError {
    /// The `GlobalHeader.magic` field is not `FSRING_MAGIC`.
    BadMagic,
    /// The header size or version fields are outside the supported ABI.
    UnsupportedHeaderSize,
    /// The ABI major/minor is not a supported/compatible 2.1 identity.
    RevisionMismatch,
    /// `byte_order` is not the little-endian marker.
    BadByteOrder,
    /// `page_size` is zero or not a power of two.
    BadPageSize,
    /// `section_size` exceeds the mapping length, or the mapping is too small
    /// to hold the header/descriptor set.
    SectionTooSmall,
    /// A region descriptor points outside the section.
    RegionOutOfBounds,
    /// A region descriptor is not aligned as the ABI requires.
    RegionMisaligned,
    /// Two writable regions overlap.
    RegionOverlap,
    /// A `RingDesc` magic/version/shape is invalid.
    BadRingDesc,
    /// A ring capacity is zero, one, or not a power of two.
    BadCapacity,
    /// A reserved field that must be zero was non-zero.
    ReservedNonZero,
    /// A slot arena (its class descriptors or final padding) is invalid per the
    /// ABI `validate_slot_arena` / `validate_zeroed_padding` rules.
    BadSlotArena,
    /// A length/offset computation overflowed.
    Arithmetic,
}

/// A ring-level transport fault surfaced from the ABI ring core.
///
/// The producer-side value carried by [`PushError`] is dropped here; callers
/// that must retry the exact body keep the ABI [`PushError`] instead of
/// converting to `RingFault`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingFault {
    /// A hostile or incoherent cursor was observed.
    Cursor(CursorFault),
    /// The ring is full.
    Full,
    /// Reservation lost the bounded contention retry budget.
    Contended,
}

impl<T> From<PushError<T>> for RingFault {
    fn from(error: PushError<T>) -> Self {
        match error {
            PushError::Full(_) => RingFault::Full,
            PushError::Contended(_) => RingFault::Contended,
            PushError::Protocol(fault, _) => RingFault::Cursor(fault),
        }
    }
}

impl From<PopError> for RingFault {
    fn from(error: PopError) -> Self {
        match error {
            PopError::Protocol(fault) => RingFault::Cursor(fault),
        }
    }
}

/// Any error crossing the `fsring-user` transport boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// A section validation fault.
    Section(SectionError),
    /// A ring protocol fault.
    Ring(RingFault),
}

impl From<SectionError> for TransportError {
    fn from(error: SectionError) -> Self {
        TransportError::Section(error)
    }
}

impl From<RingFault> for TransportError {
    fn from(error: RingFault) -> Self {
        TransportError::Ring(error)
    }
}

impl From<PopError> for TransportError {
    fn from(error: PopError) -> Self {
        TransportError::Ring(error.into())
    }
}

/// A daemon-side provider fault: the local provider returned an outcome the
/// dispatch seam refuses to publish. Categorically distinct from the hostile-
/// peer transport faults ([`SectionError`], [`RingFault`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderViolation {
    /// The provider returned a `(opcode, status)` pair the frozen ABI does not
    /// register (`is_registered_completion_status_v21` is false). Never posted.
    UnregisteredStatus { opcode: u16, status: i32 },
    /// A `FileSystem` provider reported a semantic failure using `SUCCESS`,
    /// `PENDING`, or a status not registered for the dispatched opcode. Never
    /// posted.
    IllegalFailureStatus { opcode: u16, status: i32 },
    /// The provider produced a completion for a request whose SQE set
    /// `sqe_flags::NO_COMPLETION` (fire-and-forget).
    UnexpectedCompletion,
    /// The provider produced no completion for a completion-required request.
    MissingCompletion,
    /// The provider's completion violated the ABI output matrix
    /// (`validate_completion_output_v21`): a wrong `information` for an
    /// exact-information opcode, an illegal `out_len`, output on a zero-output
    /// opcode or on a registered failure, or a context the opcode forbids.
    ///
    /// `context` is carried because it is part of what the matrix judges: the
    /// same `(opcode, status, out_len, information)` tuple can be legal with one
    /// context and illegal with another, so without it the payload could
    /// describe a perfectly legal completion.
    IllegalCompletionOutput {
        opcode: u16,
        status: i32,
        out_len: u32,
        information: u64,
        context: CompletionOutputContextV21,
    },
}

/// Any error surfaced by the daemon ENTER loop: a hostile-peer transport fault
/// or a local provider fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PumpError {
    /// A section- or ring-level transport fault (slice 1).
    Transport(TransportError),
    /// A local provider contract violation (slice 2).
    Provider(ProviderViolation),
}

impl From<TransportError> for PumpError {
    fn from(error: TransportError) -> Self {
        PumpError::Transport(error)
    }
}

impl From<ProviderViolation> for PumpError {
    fn from(error: ProviderViolation) -> Self {
        PumpError::Provider(error)
    }
}

/// A fault resolving a peer `BufferRef` against the grant table into a body.
///
/// The ABI faults ([`BufferRefError`], [`SlotLayoutError`]) are the peer-input
/// rejections; the SDK's own variants guard the single-fetch read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// No live grant matches the `BufferRef`'s token.
    UnknownToken,
    /// The validated buffer is not a slot reference (nothing to fetch here).
    NotASlot,
    /// The validated section range does not fit the daemon's mapping length.
    OutOfBounds,
    /// A range/length computation overflowed `usize`.
    Arithmetic,
    /// The produced bytes are not exactly the validated grant length.
    LengthMismatch,
    /// The ABI `validate_buffer_ref`/`validate_grant_metadata` rejected the peer
    /// reference or the grant snapshot.
    BufferRef(BufferRefError),
    /// The ABI `resolve_slot` rejected the token against the arena.
    Layout(SlotLayoutError),
}

impl From<BufferRefError> for GrantError {
    fn from(error: BufferRefError) -> Self {
        GrantError::BufferRef(error)
    }
}

impl From<SlotLayoutError> for GrantError {
    fn from(error: SlotLayoutError) -> Self {
        GrantError::Layout(error)
    }
}

/// A fault decoding a granted open-lifecycle control body (`PrepareOpenV2` /
/// `CommitOpenV2`) into an SDK request value.
///
/// Layered over the A2 grant faults ([`GrantError`]) and the frozen ABI's
/// [`MessageValidationError`]: the enclosing `PControl` shape, the grant
/// lookups, the single-fetch length, and the ABI body validator each surface a
/// distinct variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenBodyError {
    /// The enclosing `PControl` wire shape was rejected
    /// (`control::pcontrol_body_ref`).
    Control(ControlBodyError),
    /// A grant lookup or resolution failed (unknown token, out-of-bounds fetch).
    Grant(GrantError),
    /// The single-fetched body was shorter than the target struct.
    Truncated,
    /// The frozen ABI body validator (`validate_prepare_open_v2` /
    /// `validate_commit_open_v2`) rejected the request.
    Message(MessageValidationError),
}

impl From<ControlBodyError> for OpenBodyError {
    fn from(error: ControlBodyError) -> Self {
        OpenBodyError::Control(error)
    }
}

impl From<GrantError> for OpenBodyError {
    fn from(error: GrantError) -> Self {
        OpenBodyError::Grant(error)
    }
}

impl From<MessageValidationError> for OpenBodyError {
    fn from(error: MessageValidationError) -> Self {
        OpenBodyError::Message(error)
    }
}

/// A fault decoding a granted `QueryDirV2` control blob into an SDK request, or
/// building its `QUERY_DIR` completion.
///
/// Layered over the A2 grant faults and the frozen ABI's
/// [`QueryValidationError`]: the enclosing `PControl` shape, the grant lookups,
/// the single-fetch length, and the ABI query validator each surface a variant.
/// `Completion` is distinct from `Query`: `validate_query_dir_v2` (decode)
/// returns the dir-specific [`QueryValidationError`], but
/// `validate_completion_output_v21` (`build_query_dir_completion`'s
/// self-validation) returns the shared [`MessageValidationError`] — the two
/// frozen validators disagree on error type, so `QueryDirError` carries both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryDirError {
    /// The enclosing `PControl` wire shape was rejected.
    Control(ControlBodyError),
    /// A grant lookup or resolution failed.
    Grant(GrantError),
    /// The single-fetched control blob was shorter than `QueryDirV2` (64 bytes).
    Truncated,
    /// The frozen ABI `validate_query_dir_v2` rejected the request.
    Query(QueryValidationError),
    /// `build_query_dir_completion`'s self-validation
    /// (`validate_completion_output_v21`) rejected the built completion.
    Completion(MessageValidationError),
}

impl From<ControlBodyError> for QueryDirError {
    fn from(error: ControlBodyError) -> Self {
        QueryDirError::Control(error)
    }
}

impl From<GrantError> for QueryDirError {
    fn from(error: GrantError) -> Self {
        QueryDirError::Grant(error)
    }
}

impl From<QueryValidationError> for QueryDirError {
    fn from(error: QueryValidationError) -> Self {
        QueryDirError::Query(error)
    }
}

/// A fault decoding a granted `QuerySecurityV1` security-descriptor query.
///
/// Layered over the A2 grant faults and the frozen ABI's
/// [`MessageValidationError`]: the enclosing `PControl` shape, the grant
/// lookups, the single-fetch length, and the ABI query validator each surface a
/// variant. Unlike [`QueryDirError`], the frozen validator here
/// (`validate_query_security_v1`) returns `MessageValidationError` directly —
/// `QuerySecurityV1` is a fixed 40-byte struct with no variable tail to
/// misclassify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuerySecurityError {
    /// The enclosing `PControl` wire shape was rejected.
    Control(ControlBodyError),
    /// A grant lookup or resolution failed.
    Grant(GrantError),
    /// The single-fetched control blob was shorter than `QuerySecurityV1` (40 bytes).
    Truncated,
    /// The frozen ABI `validate_query_security_v1` rejected the request.
    Message(MessageValidationError),
}

impl From<ControlBodyError> for QuerySecurityError {
    fn from(error: ControlBodyError) -> Self {
        QuerySecurityError::Control(error)
    }
}

impl From<GrantError> for QuerySecurityError {
    fn from(error: GrantError) -> Self {
        QuerySecurityError::Grant(error)
    }
}

impl From<MessageValidationError> for QuerySecurityError {
    fn from(error: MessageValidationError) -> Self {
        QuerySecurityError::Message(error)
    }
}

/// A fault decoding a granted `MutationV2` namespace-mutation request.
///
/// Layered over the A2 grant faults and the frozen ABI's
/// [`MessageValidationError`]. `NotInScope` is now unreachable via
/// `decode_mutation`: it has a decode arm for each of `SET_BASIC_INFO`,
/// `SET_ALLOCATION_SIZE`, `SET_END_OF_FILE`, `SET_VALID_DATA_LENGTH`, `RENAME`,
/// `LINK`, `UNLINK`, and `SET_SECURITY` (kinds 1-8); kinds `INVALID`/
/// `SET_REPARSE`/`DELETE_REPARSE`/`SET_SPARSE` (0, 9, 10, 11) are rejected by
/// `validate_mutation_v2` itself (`Message`), never reaching the scope
/// dispatch. The variant is kept for match exhaustiveness (a future mutation
/// kind added to the registry without a decode arm falls through to it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationError {
    /// The enclosing `PControl` wire shape was rejected.
    Control(ControlBodyError),
    /// A grant lookup or resolution failed.
    Grant(GrantError),
    /// A single-fetched body was shorter than its target struct.
    Truncated,
    /// The frozen ABI (`validate_mutation_v2` / `validate_mutation_body_v21`)
    /// rejected the request.
    Message(MessageValidationError),
    /// A valid mutation kind with no decode arm (currently unreachable; kept
    /// for match exhaustiveness).
    NotInScope { kind: u16 },
}

impl From<ControlBodyError> for MutationError {
    fn from(error: ControlBodyError) -> Self {
        MutationError::Control(error)
    }
}

impl From<GrantError> for MutationError {
    fn from(error: GrantError) -> Self {
        MutationError::Grant(error)
    }
}

impl From<MessageValidationError> for MutationError {
    fn from(error: MessageValidationError) -> Self {
        MutationError::Message(error)
    }
}

/// A fault building/validating a namespace-mutation result.
///
/// The provider-supplied effect produced a `MutationResultV2` + kind result that
/// `validate_mutation_success_v2` rejected (a §9.7 inconsistency), or a grant
/// lookup for the reply/kind_result echo failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationResultError {
    /// The built result failed the frozen ABI success validator.
    Message(MessageValidationError),
    /// A grant lookup for the reply/kind_result echo failed.
    Grant(GrantError),
}

impl From<GrantError> for MutationResultError {
    fn from(error: GrantError) -> Self {
        MutationResultError::Grant(error)
    }
}

/// A fault building/validating an open-lifecycle result (`CommitOpenResultV2` /
/// `PrepareOpenResultV1`).
///
/// Mirrors [`MutationResultError`]: the provider-supplied effect produced a
/// result the frozen success validator (`validate_commit_open_success_v2` /
/// `validate_prepare_open_success_v21`, each of which re-runs the request
/// validator over the retained raw request) rejected, or a grant lookup for the
/// reply / result-security-descriptor echo failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenResultError {
    /// The built result failed the frozen ABI success validator.
    Message(MessageValidationError),
    /// A grant lookup for the reply / result-SD echo failed.
    Grant(GrantError),
}

impl From<GrantError> for OpenResultError {
    fn from(error: GrantError) -> Self {
        OpenResultError::Grant(error)
    }
}

/// A fault decoding a granted `PRw` (READ) or `WriteV2` (WRITE) request.
///
/// READ's `PRw` travels inline in the SQE payload (never a `PControl`
/// indirection); WRITE's `WriteV2` is a granted `PControl` body, mirroring
/// [`MutationError`]'s shape. `Control` covers both the inline-`PRw` wire-shape
/// rejection (the `payload_len`/tail check `decode_read` performs itself,
/// mirroring `control::pcontrol_body_ref`'s framing rule) and, for WRITE, the
/// enclosing `PControl` wire shape rejected by `control::pcontrol_body_ref`
/// itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataIoError {
    /// The enclosing wire shape was rejected: for READ, the inline `PRw`
    /// framing; for WRITE, the `PControl` wire shape.
    Control(ControlBodyError),
    /// A grant lookup or resolution failed.
    Grant(GrantError),
    /// A single-fetched body was shorter than its target struct.
    Truncated,
    /// The frozen ABI (`validate_read_v21` / `validate_write_v2`) rejected the
    /// request.
    Message(MessageValidationError),
}

impl From<ControlBodyError> for DataIoError {
    fn from(error: ControlBodyError) -> Self {
        DataIoError::Control(error)
    }
}

impl From<GrantError> for DataIoError {
    fn from(error: GrantError) -> Self {
        DataIoError::Grant(error)
    }
}

impl From<MessageValidationError> for DataIoError {
    fn from(error: MessageValidationError) -> Self {
        DataIoError::Message(error)
    }
}

/// A fault building/validating a WRITE result.
///
/// Mirrors [`MutationResultError`]: the provider-supplied
/// [`crate::dataio::WriteEffect`] plus `information` produced a `WriteResultV2`
/// that `validate_write_success_v2` rejected, or a grant lookup for the reply
/// echo failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteResultError {
    /// The built result failed the frozen ABI success validator.
    Message(MessageValidationError),
    /// A grant lookup for the reply echo failed.
    Grant(GrantError),
}

impl From<GrantError> for WriteResultError {
    fn from(error: GrantError) -> Self {
        WriteResultError::Grant(error)
    }
}

/// A fault decoding a granted `QueryInfoV1` file-information query.
///
/// Layered over the A2 grant faults and the frozen ABI's
/// [`MessageValidationError`]: the enclosing `PControl` shape, the grant
/// lookups, the single-fetch length, and the ABI query validator each surface a
/// variant. Mirrors [`QuerySecurityError`]: the frozen validator here
/// (`validate_query_info_v1`) returns `MessageValidationError` directly —
/// `QueryInfoV1` is a fixed 40-byte struct with no variable tail to
/// misclassify. Also covers `queryinfo::build_file_info`'s self-validation
/// (`validate_file_info_v1`), which is grant-free and only ever produces the
/// `Message` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryInfoError {
    /// The enclosing `PControl` wire shape was rejected.
    Control(ControlBodyError),
    /// A grant lookup or resolution failed.
    Grant(GrantError),
    /// The single-fetched control blob was shorter than `QueryInfoV1` (40 bytes).
    Truncated,
    /// The frozen ABI `validate_query_info_v1` (decode) / `validate_file_info_v1`
    /// (result self-validation) rejected the request/result.
    Message(MessageValidationError),
}

impl From<ControlBodyError> for QueryInfoError {
    fn from(error: ControlBodyError) -> Self {
        QueryInfoError::Control(error)
    }
}

impl From<GrantError> for QueryInfoError {
    fn from(error: GrantError) -> Self {
        QueryInfoError::Grant(error)
    }
}

impl From<MessageValidationError> for QueryInfoError {
    fn from(error: MessageValidationError) -> Self {
        QueryInfoError::Message(error)
    }
}

/// A fault decoding a granted `QueryVolumeV1` volume-information query.
///
/// Layered exactly like [`QueryInfoError`] (same fixed 40-byte shape, same
/// frozen `MessageValidationError` surface). Also covers
/// `queryvolume::build_volume_size_info`'s self-validation
/// (`validate_volume_size_info_v1`), which is grant-free and only ever
/// produces the `Message` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryVolumeError {
    /// The enclosing `PControl` wire shape was rejected.
    Control(ControlBodyError),
    /// A grant lookup or resolution failed.
    Grant(GrantError),
    /// The single-fetched control blob was shorter than `QueryVolumeV1` (40 bytes).
    Truncated,
    /// The frozen ABI `validate_query_volume_v1` (decode) /
    /// `validate_volume_size_info_v1` (result self-validation) rejected the
    /// request/result.
    Message(MessageValidationError),
}

impl From<ControlBodyError> for QueryVolumeError {
    fn from(error: ControlBodyError) -> Self {
        QueryVolumeError::Control(error)
    }
}

impl From<GrantError> for QueryVolumeError {
    fn from(error: GrantError) -> Self {
        QueryVolumeError::Grant(error)
    }
}

impl From<MessageValidationError> for QueryVolumeError {
    fn from(error: MessageValidationError) -> Self {
        QueryVolumeError::Message(error)
    }
}

/// A fault in the volatile directory-enumeration engine (`direnum.rs`).
///
/// A produced batch always carries at least one entry (`05` §12.10); the
/// empty/exhausted case is [`EnumError::NoMoreEntries`], never an empty-success
/// batch. `NoMoreEntries` is not a hard error — the provider maps it to the
/// NO_SUCH_FILE / NO_MORE_FILES completion status, which is the (PENDING)
/// completion-layer decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnumError {
    /// The expression pattern failed to compile via the slice-3 matcher.
    Pattern(NameMatchError),
    /// A continuation referenced a `(kernel_open_id, generation)` with no snapshot.
    UnknownGeneration,
    /// The input cookie is past the end of the match sequence.
    CookieOutOfRange,
    /// The sequence is empty or fully consumed at the input cookie.
    NoMoreEntries,
    /// The output grant cannot hold even one maximum canonical entry (the kernel
    /// guarantees it can, so this is a defensive guard).
    OutputTooSmall,
    /// A candidate name exceeds `MAX_COMPONENT_UTF16_CODE_UNITS`.
    NameTooLong,
    /// The produced batch failed the frozen ABI self-validation
    /// (`validate_query_dir_result_v1`) — a malformed candidate (empty/odd name,
    /// zero identity, illegal attributes) that cannot be encoded as a legal entry.
    Encode(QueryValidationError),
}

impl From<NameMatchError> for EnumError {
    fn from(error: NameMatchError) -> Self {
        EnumError::Pattern(error)
    }
}

/// A fault in the volatile open-lifecycle state machine (`lifecycle.rs`).
///
/// These are the *stateful* rules the frozen ABI does not model — transitions,
/// idempotence, caps, and corruption — transcribed from `04-object-model.md` §3
/// and `05-irp-dispatch.md` §4/§7/§8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleFault {
    /// A repeat `PREPARE_OPEN` with a live `OpId` but different semantic bytes
    /// (`05` §4.4: "reuse with different bytes is a protocol fault").
    PrepareBytesMismatch,
    /// The retained-prepare byte cap would be exceeded; nonmutating (no record).
    PrepareQuota,
    /// The supplied `TransactionId` is the zero pair, or already indexes another
    /// `OpId` within the mount (`04` §2.1: a collision is corruption).
    TransactionIdCollision,
    /// A transaction or provider-cookie counter cannot advance without wrap.
    CounterExhausted,
    /// `COMMIT_OPEN`/`ABORT_OPEN` referenced a `TransactionId` with no live index.
    UnknownTransaction,
    /// `COMMIT_OPEN`'s `OpId` does not equal the record's `OpId`.
    OpIdMismatch,
    /// `COMMIT_OPEN`'s expected generations do not match the retained prepare
    /// result (a kernel-request-versus-record mismatch).
    SemanticMismatch,
    /// `COMMIT_OPEN`'s provider effect carried a `create_result` outside the
    /// registry (`> OVERWRITTEN`) — a provider-effect fault, distinct from a
    /// request/record `SemanticMismatch`.
    IllegalCreateResult,
    /// The retained-open (ring/mount/global) reservation would be exceeded;
    /// nonmutating (no row created, `04` §3.2).
    OpenQuota,
    /// A row transition observed an illegal, one-sided, or absent state
    /// (`04` §3.4 / `05` §7.4 / §8: "ABSENT, an unknown state, or a mismatched
    /// payload is corruption").
    RowCorruption,
}

/// A fault decoding one request into its SDK request value, unifying every
/// per-opcode decode-family error so [`DaemonError`] can absorb them through a
/// single `Decode` arm (the decoders never share an error type — each names its
/// own `PControl`/grant/ABI faults — so this enum is their least-upper-bound at
/// the dispatch boundary).
///
/// `QueryDir` and `QuerySecurity` additionally carry the completion-build
/// self-validation faults of `build_query_dir_completion` /
/// `build_query_security_completion`, which reuse those same error types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// An inline/`PControl` wire-shape fault (`ABORT_OPEN`'s `AbortOpenV1`).
    Control(ControlBodyError),
    /// A fixed SQ payload fault (`CLEANUP`/`CLOSE`/`FLUSH`'s `PBarrier`).
    Payload(PayloadError),
    /// A `PREPARE_OPEN`/`COMMIT_OPEN` control-body fault.
    OpenBody(OpenBodyError),
    /// A `READ`/`WRITE` data-io fault.
    DataIo(DataIoError),
    /// A `QUERY_DIR` decode or completion-build fault.
    QueryDir(QueryDirError),
    /// A `QUERY_INFO` decode fault.
    QueryInfo(QueryInfoError),
    /// A `QUERY_VOLUME` decode fault.
    QueryVolume(QueryVolumeError),
    /// A `QUERY_SECURITY` decode or completion-build fault.
    QuerySecurity(QuerySecurityError),
    /// A `MUTATE` (`SET_INFORMATION`) decode fault.
    Mutation(MutationError),
}

/// A fault building + host-validating one request's wire result, unifying the
/// per-opcode result-encoder errors so [`DaemonError`] can absorb them through a
/// single `Result` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultError {
    /// A `PREPARE_OPEN`/`COMMIT_OPEN` result-build fault.
    Open(OpenResultError),
    /// A `WRITE` result-build fault.
    Write(WriteResultError),
    /// A `MUTATE` result-build fault.
    Mutation(MutationResultError),
}

/// Any error surfaced by the stateful [`crate::daemon::Daemon`] dispatcher: a
/// hostile-peer transport fault, a request-decode fault, a grant-resolution
/// fault, a provider outcome the ABI output matrix rejects, a lifecycle-state
/// fault, an enumeration-engine fault, a result-build fault, or an opcode the
/// dispatcher does not handle.
///
/// Distinct from [`PumpError`] (the transport-level `pump_once<P: Provider>`
/// seam, which knows nothing of decode/lifecycle/result semantics): the stateful
/// dispatcher composes every E1 layer, so its error carries every layer's fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonError {
    /// A section- or ring-level transport fault.
    Transport(TransportError),
    /// A grant lookup / `BufferRef` resolution / write-back fault.
    Grant(GrantError),
    /// A request-decode fault (per-opcode, unified through [`DecodeError`]).
    Decode(DecodeError),
    /// A provider outcome the ABI output matrix refuses to publish.
    Provider(ProviderViolation),
    /// A volatile open-lifecycle state-machine fault.
    Lifecycle(LifecycleFault),
    /// A volatile directory-enumeration engine fault.
    Enumerate(EnumError),
    /// A result-build / host-validation fault (unified through [`ResultError`]).
    Result(ResultError),
    /// An opcode the dispatcher has no arm for (defensive; the transport layer
    /// admits only the frozen opcode set, so this is a corruption guard).
    UnhandledOpcode { opcode: u16 },
}

impl From<TransportError> for DaemonError {
    fn from(error: TransportError) -> Self {
        DaemonError::Transport(error)
    }
}

impl From<GrantError> for DaemonError {
    fn from(error: GrantError) -> Self {
        DaemonError::Grant(error)
    }
}

impl From<ProviderViolation> for DaemonError {
    fn from(error: ProviderViolation) -> Self {
        DaemonError::Provider(error)
    }
}

impl From<LifecycleFault> for DaemonError {
    fn from(error: LifecycleFault) -> Self {
        DaemonError::Lifecycle(error)
    }
}

impl From<EnumError> for DaemonError {
    fn from(error: EnumError) -> Self {
        DaemonError::Enumerate(error)
    }
}

impl From<ControlBodyError> for DaemonError {
    fn from(error: ControlBodyError) -> Self {
        DaemonError::Decode(DecodeError::Control(error))
    }
}

impl From<PayloadError> for DaemonError {
    fn from(error: PayloadError) -> Self {
        DaemonError::Decode(DecodeError::Payload(error))
    }
}

impl From<OpenBodyError> for DaemonError {
    fn from(error: OpenBodyError) -> Self {
        DaemonError::Decode(DecodeError::OpenBody(error))
    }
}

impl From<DataIoError> for DaemonError {
    fn from(error: DataIoError) -> Self {
        DaemonError::Decode(DecodeError::DataIo(error))
    }
}

impl From<QueryDirError> for DaemonError {
    fn from(error: QueryDirError) -> Self {
        DaemonError::Decode(DecodeError::QueryDir(error))
    }
}

impl From<QueryInfoError> for DaemonError {
    fn from(error: QueryInfoError) -> Self {
        DaemonError::Decode(DecodeError::QueryInfo(error))
    }
}

impl From<QueryVolumeError> for DaemonError {
    fn from(error: QueryVolumeError) -> Self {
        DaemonError::Decode(DecodeError::QueryVolume(error))
    }
}

impl From<QuerySecurityError> for DaemonError {
    fn from(error: QuerySecurityError) -> Self {
        DaemonError::Decode(DecodeError::QuerySecurity(error))
    }
}

impl From<MutationError> for DaemonError {
    fn from(error: MutationError) -> Self {
        DaemonError::Decode(DecodeError::Mutation(error))
    }
}

impl From<OpenResultError> for DaemonError {
    fn from(error: OpenResultError) -> Self {
        DaemonError::Result(ResultError::Open(error))
    }
}

impl From<WriteResultError> for DaemonError {
    fn from(error: WriteResultError) -> Self {
        DaemonError::Result(ResultError::Write(error))
    }
}

impl From<MutationResultError> for DaemonError {
    fn from(error: MutationResultError) -> Self {
        DaemonError::Result(ResultError::Mutation(error))
    }
}
