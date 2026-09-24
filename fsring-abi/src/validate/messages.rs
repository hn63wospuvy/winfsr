use core::{convert::TryFrom, mem::size_of};

use crate::{
    codec::try_decode,
    cq_kind,
    digest::operation_digest_eq,
    durable::{
        committed_result_kind, CommittedMutationResultV1, CommittedOpenResultV1, CommittedResultV1,
        CommittedWriteResultV1, COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES,
        COMMITTED_RESULT_V1_PREFIX_BYTES,
    },
    ids::REQ_GENERATION_MAX,
    limits::{
        notify_filter, validate_file_range, RangeError, EXTERNAL_MODIFY_FILTER_MASK,
        MAX_BACKING_SECTOR_SIZE, MAX_COMPONENT_UTF16_CODE_UNITS, MAX_FILE_SIZE, MAX_INFLIGHT,
        MAX_RING_COUNT, MAX_SECURITY_DESCRIPTOR_BYTES, MIN_BACKING_SECTOR_SIZE,
        MIN_SECURITY_DESCRIPTOR_BYTES,
    },
    msgs::{
        basic_info_set_mask, buffer_access, create_result, external_change_kind,
        external_object_kind, file_attributes, link_flags, mutation_kind, notify_ack_kind,
        protocol_opcode, query_op_required_flags, query_op_state, rename_flags, rw_flags,
        security_information, AckResultV2, BlobSlice, BufferRef, CommitOpenResultV2, CommitOpenV2,
        ControlHeader, ExternalChangeCutV1, ExternalChangeReadyV1, ExternalDirChangeV1,
        InvalidateEntryV1, InvalidateFileV1, LinkResultV2, LinkV1, MutationResultV2, MutationV2,
        NotifyEnvelopeV2, OControl, PDirChangeAckV1, PNotifyAck, PRw, PrepareOpenResultV1,
        PrepareOpenV2, PtEpochV1, PtGrantV1, PtLaneReadyV1, QueryOpResultV1, QueryOpV2,
        RenameResultV2, RenameV1, ReplayOpenResultV1, ReplayOpenV2, ResizeV1, SetBasicInfoV1,
        SetSecurityV1, SetSizeV1, SizeState, UnlinkResultV1, UnlinkV1, WriteResultV2, WriteV2,
        ACK_TOKEN_HI_MASK, ACK_TOKEN_HI_TAG, CONTROL_VERSION_V1, CONTROL_VERSION_V2,
    },
    notify, op,
    slots::{
        validate_buffer_ref, BufferRefError, BufferRefPolicy, BufferRefRule, EmptyBufferRule,
        GrantMetadata, GrantOwner, ValidatedBuffer,
    },
    AckToken, FileId, LinkId, OpId, ReqId, TransactionId,
};

use super::control::ControlError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageValidationError {
    IllegalWireForm,
    IllegalVersion,
    Control(ControlError),
    FlagsOrReserved,
    Identity,
    InvalidScalar,
    SizeState,
    Relationship,
    LocalOnlyWireForm,
    Completion,
    Grant(BufferRefError),
    Range(RangeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RwRequestWireFormV21 {
    InlinePrw,
    Control,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RwResultWireFormV21 {
    OControl,
    Orw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RwSubmissionV21 {
    CompleteLocally,
    Emit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantBindingV21<'a> {
    pub grant: &'a GrantMetadata,
    pub expected_session_epoch: u64,
    pub expected_owner: GrantOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrepareOpenV2Context<'a> {
    pub name: GrantBindingV21<'a>,
    pub requested_security_descriptor: Option<GrantBindingV21<'a>>,
    pub extended_attributes: Option<GrantBindingV21<'a>>,
    pub reply: GrantBindingV21<'a>,
    pub result_security_descriptor: GrantBindingV21<'a>,
    pub validated_name_length: u32,
    pub validated_security_descriptor_length: Option<u32>,
    pub validated_ea_length: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteV2Context<'a> {
    pub data: GrantBindingV21<'a>,
    pub reply: GrantBindingV21<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryOpV2Context<'a> {
    pub reply: GrantBindingV21<'a>,
    pub committed_result: GrantBindingV21<'a>,
    pub retained_cancelled_no_candidate: bool,
}

#[derive(Clone, Copy)]
pub enum MutationBodyRefV21<'a> {
    SetBasicInfo(&'a SetBasicInfoV1),
    SetAllocationSize(&'a SetSizeV1),
    SetEndOfFile(&'a SetSizeV1),
    SetValidDataLength(&'a SetSizeV1),
    Rename(&'a RenameV1),
    Link(&'a LinkV1),
    Unlink(&'a UnlinkV1),
    SetSecurity(&'a SetSecurityV1),
}

#[derive(Clone, Copy)]
pub enum MutationKindResultRefV21<'a> {
    None,
    Rename(&'a RenameResultV2),
    Link(&'a LinkResultV2),
    Unlink(&'a UnlinkResultV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedMutationSuccessV2 {
    reply: ValidatedBuffer,
    kind_result: Option<ValidatedBuffer>,
}

impl ValidatedMutationSuccessV2 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }

    pub const fn kind_result(&self) -> Option<ValidatedBuffer> {
        self.kind_result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MutationV2Context<'a> {
    pub body: GrantBindingV21<'a>,
    pub reply: GrantBindingV21<'a>,
    pub kind_result: Option<GrantBindingV21<'a>>,
    pub reparse_selected: bool,
    pub same_parent_rename: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedMutationV2 {
    body: ValidatedBuffer,
    reply: ValidatedBuffer,
    kind_result: Option<ValidatedBuffer>,
}

impl ValidatedMutationV2 {
    pub const fn body(&self) -> ValidatedBuffer {
        self.body
    }

    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }

    pub const fn kind_result(&self) -> Option<ValidatedBuffer> {
        self.kind_result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedPrepareOpenV2 {
    name: ValidatedBuffer,
    requested_security_descriptor: Option<ValidatedBuffer>,
    extended_attributes: Option<ValidatedBuffer>,
    reply: ValidatedBuffer,
    result_security_descriptor: ValidatedBuffer,
}

impl ValidatedPrepareOpenV2 {
    pub const fn name(&self) -> ValidatedBuffer {
        self.name
    }

    pub const fn requested_security_descriptor(&self) -> Option<ValidatedBuffer> {
        self.requested_security_descriptor
    }

    pub const fn extended_attributes(&self) -> Option<ValidatedBuffer> {
        self.extended_attributes
    }

    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }

    pub const fn result_security_descriptor(&self) -> ValidatedBuffer {
        self.result_security_descriptor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedCommitOpenV2 {
    reply: ValidatedBuffer,
}

impl ValidatedCommitOpenV2 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedReadV21 {
    data: ValidatedBuffer,
}

impl ValidatedReadV21 {
    pub const fn data(&self) -> ValidatedBuffer {
        self.data
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedWriteV2 {
    data: ValidatedBuffer,
    reply: ValidatedBuffer,
}

impl ValidatedWriteV2 {
    pub const fn data(&self) -> ValidatedBuffer {
        self.data
    }

    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedReplayOpenV2 {
    reply: ValidatedBuffer,
}

impl ValidatedReplayOpenV2 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedQueryOpV2 {
    reply: ValidatedBuffer,
    committed_result: ValidatedBuffer,
}

impl ValidatedQueryOpV2 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }

    pub const fn committed_result(&self) -> ValidatedBuffer {
        self.committed_result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreatePhaseV21 {
    Prepare,
    Commit,
    AbortOpen,
    QueryOp,
    AckResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePhaseExpectationV21 {
    pub op_id: OpId,
    pub transaction_id: Option<TransactionId>,
    pub slot_index: u32,
    pub max_inflight: u32,
    pub prior_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatePhaseCandidateV21 {
    pub phase: CreatePhaseV21,
    pub req_id: ReqId,
    pub op_id: Option<OpId>,
    pub transaction_id: Option<TransactionId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedPrepareOpenSuccessV21 {
    reply: ValidatedBuffer,
    security_descriptor: ValidatedBuffer,
}

impl ValidatedPrepareOpenSuccessV21 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }

    pub const fn security_descriptor(&self) -> ValidatedBuffer {
        self.security_descriptor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedCommitOpenSuccessV2 {
    reply: ValidatedBuffer,
}

impl ValidatedCommitOpenSuccessV2 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedReadSuccessV21 {
    data: ValidatedBuffer,
}

impl ValidatedReadSuccessV21 {
    pub const fn data(&self) -> ValidatedBuffer {
        self.data
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedWriteSuccessV2 {
    reply: ValidatedBuffer,
}

impl ValidatedWriteSuccessV2 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedReplayOpenSuccessV21 {
    reply: ValidatedBuffer,
}

impl ValidatedReplayOpenSuccessV21 {
    pub const fn reply(&self) -> ValidatedBuffer {
        self.reply
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedCreatePhaseIdentityV21 {
    phase: CreatePhaseV21,
    req_id: ReqId,
}

impl ValidatedCreatePhaseIdentityV21 {
    pub const fn phase(&self) -> CreatePhaseV21 {
        self.phase
    }

    pub const fn req_id(&self) -> ReqId {
        self.req_id
    }
}

const V2_REQUESTS: [u16; 8] = [
    op::PREPARE_OPEN,
    op::COMMIT_OPEN,
    op::WRITE,
    op::MUTATE,
    op::QUERY_DIR,
    op::REPLAY_OPEN,
    op::QUERY_OP,
    op::ACK_RESULT,
];

const V1_REQUESTS: [u16; 5] = [
    op::ABORT_OPEN,
    op::QUERY_INFO,
    op::QUERY_VOLUME,
    op::QUERY_SECURITY,
    op::FSCTL,
];

pub const fn validate_request_version_v21(
    opcode: u16,
    version: u16,
) -> Result<(), MessageValidationError> {
    let mut index = 0;
    while index < V2_REQUESTS.len() {
        if opcode == V2_REQUESTS[index] {
            return if version == CONTROL_VERSION_V2 {
                Ok(())
            } else {
                Err(MessageValidationError::IllegalVersion)
            };
        }
        index += 1;
    }

    index = 0;
    while index < V1_REQUESTS.len() {
        if opcode == V1_REQUESTS[index] {
            return if version == CONTROL_VERSION_V1 {
                Ok(())
            } else {
                Err(MessageValidationError::IllegalVersion)
            };
        }
        index += 1;
    }

    Err(MessageValidationError::IllegalWireForm)
}

pub const fn validate_notification_version_v21(version: u16) -> Result<(), MessageValidationError> {
    if version == CONTROL_VERSION_V2 {
        Ok(())
    } else {
        Err(MessageValidationError::IllegalVersion)
    }
}

pub const fn validate_request_wire_form_v21(
    opcode: u16,
    form: RwRequestWireFormV21,
) -> Result<(), MessageValidationError> {
    if matches!(
        (opcode, form),
        (op::READ, RwRequestWireFormV21::InlinePrw) | (op::WRITE, RwRequestWireFormV21::Control)
    ) {
        Ok(())
    } else {
        Err(MessageValidationError::IllegalWireForm)
    }
}

pub const fn validate_result_wire_form_v21(
    opcode: u16,
    form: RwResultWireFormV21,
) -> Result<(), MessageValidationError> {
    if matches!(opcode, op::READ | op::WRITE) && matches!(form, RwResultWireFormV21::OControl) {
        Ok(())
    } else {
        Err(MessageValidationError::IllegalWireForm)
    }
}

const RW_FLAGS_V21: u32 = rw_flags::PAGING
    | rw_flags::NOCACHE
    | rw_flags::WRITE_THROUGH
    | rw_flags::MAPPED
    | rw_flags::SYNC_PAGING
    | rw_flags::EXTENDING
    | rw_flags::ZERO_RANGE_VALID;

fn validate_header_with_flags(
    header: ControlHeader,
    version: u16,
    size: usize,
    accepted_required_flags: u16,
) -> Result<(), MessageValidationError> {
    if header.struct_version != version {
        return Err(MessageValidationError::Control(
            ControlError::RevisionMismatch,
        ));
    }
    if header.required_flags & !accepted_required_flags != 0 {
        return Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags,
        ));
    }
    if usize::try_from(header.struct_size).ok() != Some(size) {
        return Err(MessageValidationError::Control(ControlError::InvalidSize));
    }
    Ok(())
}

fn validate_header(
    header: ControlHeader,
    version: u16,
    size: usize,
) -> Result<(), MessageValidationError> {
    validate_header_with_flags(header, version, size, 0)
}

const fn pair_nonzero(lo: u64, hi: u64) -> bool {
    lo != 0 || hi != 0
}

fn validate_bound(
    reference: &BufferRef,
    binding: GrantBindingV21<'_>,
    access: u16,
    policy: BufferRefPolicy,
) -> Result<ValidatedBuffer, MessageValidationError> {
    let value = validate_buffer_ref(
        reference,
        &BufferRefRule::Grant {
            grant: binding.grant,
            expected_session_epoch: binding.expected_session_epoch,
            expected_owner: binding.expected_owner,
            policy,
            empty: EmptyBufferRule::Forbidden,
        },
    )
    .map_err(MessageValidationError::Grant)?;
    if reference.access != access {
        return Err(MessageValidationError::Grant(
            BufferRefError::AccessMismatch,
        ));
    }
    Ok(value)
}

fn validate_optional_input_scalars(
    reference: &BufferRef,
    binding_present: bool,
    validated_length: Option<u32>,
    minimum_length: u32,
) -> Result<(), MessageValidationError> {
    match (binding_present, validated_length) {
        (false, None) => Ok(()),
        (true, Some(validated_length)) => {
            if validated_length < minimum_length || validated_length > 65_536 {
                return Err(MessageValidationError::InvalidScalar);
            }
            if reference.length != validated_length {
                return Err(MessageValidationError::Relationship);
            }
            Ok(())
        }
        _ => Err(MessageValidationError::Relationship),
    }
}

fn validate_optional_input_grant(
    reference: &BufferRef,
    binding: Option<GrantBindingV21<'_>>,
) -> Result<Option<ValidatedBuffer>, MessageValidationError> {
    match binding {
        None => {
            validate_buffer_ref(reference, &BufferRefRule::None)
                .map_err(MessageValidationError::Grant)?;
            Ok(None)
        }
        Some(binding) => validate_bound(
            reference,
            binding,
            buffer_access::K2U_READ_ONLY,
            BufferRefPolicy::Exact,
        )
        .map(Some),
    }
}

pub const fn classify_rw_submission_v21(
    offset: u64,
    length: u32,
) -> Result<RwSubmissionV21, MessageValidationError> {
    if length == 0 {
        return Ok(RwSubmissionV21::CompleteLocally);
    }
    match validate_file_range(offset, length as u64, false) {
        Ok(()) => Ok(RwSubmissionV21::Emit),
        Err(error) => Err(MessageValidationError::Range(error)),
    }
}

pub const fn validate_size_state_v21(sizes: SizeState) -> Result<(), MessageValidationError> {
    if sizes.allocation_size > MAX_FILE_SIZE
        || sizes.file_size > MAX_FILE_SIZE
        || sizes.valid_data_length > MAX_FILE_SIZE
        || sizes.size_epoch == 0
    {
        return Err(MessageValidationError::SizeState);
    }
    if sizes.allocation_size < sizes.file_size || sizes.file_size < sizes.valid_data_length {
        return Err(MessageValidationError::Relationship);
    }
    Ok(())
}

pub fn validate_prepare_open_v2(
    request: &PrepareOpenV2,
    context: &PrepareOpenV2Context<'_>,
) -> Result<ValidatedPrepareOpenV2, MessageValidationError> {
    validate_header(
        request.header,
        CONTROL_VERSION_V2,
        size_of::<PrepareOpenV2>(),
    )?;
    if !pair_nonzero(request.op_id.lo, request.op_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    if context.validated_name_length == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if request.name.length != context.validated_name_length {
        return Err(MessageValidationError::Relationship);
    }
    validate_optional_input_scalars(
        &request.requested_security_descriptor,
        context.requested_security_descriptor.is_some(),
        context.validated_security_descriptor_length,
        20,
    )?;
    validate_optional_input_scalars(
        &request.extended_attributes,
        context.extended_attributes.is_some(),
        context.validated_ea_length,
        1,
    )?;

    let name = validate_bound(
        &request.name,
        context.name,
        buffer_access::K2U_READ_ONLY,
        BufferRefPolicy::Exact,
    )?;
    let requested_security_descriptor = validate_optional_input_grant(
        &request.requested_security_descriptor,
        context.requested_security_descriptor,
    )?;
    let extended_attributes =
        validate_optional_input_grant(&request.extended_attributes, context.extended_attributes)?;
    let reply = validate_bound(
        &request.reply,
        context.reply,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.reply.length < 136 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let result_security_descriptor = validate_bound(
        &request.result_security_descriptor,
        context.result_security_descriptor,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.result_security_descriptor.length != 65_536 {
        return Err(MessageValidationError::InvalidScalar);
    }

    Ok(ValidatedPrepareOpenV2 {
        name,
        requested_security_descriptor,
        extended_attributes,
        reply,
        result_security_descriptor,
    })
}

pub fn validate_commit_open_v2(
    request: &CommitOpenV2,
    reply: GrantBindingV21<'_>,
) -> Result<ValidatedCommitOpenV2, MessageValidationError> {
    validate_header(
        request.header,
        CONTROL_VERSION_V2,
        size_of::<CommitOpenV2>(),
    )?;
    if request.reserved != 0 || request.reserved2 != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(request.op_id.lo, request.op_id.hi)
        || !pair_nonzero(request.transaction_id.lo, request.transaction_id.hi)
        || request.expected_namespace_generation == 0
        || request.expected_security_generation == 0
        || request.kernel_open_id == 0
    {
        return Err(MessageValidationError::Identity);
    }
    let reply = validate_bound(
        &request.reply,
        reply,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.reply.length < 112 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(ValidatedCommitOpenV2 { reply })
}

fn validate_rw_scalars(
    offset: u64,
    length: u32,
    initialized_offset: u64,
    initialized_length: u32,
) -> Result<(), MessageValidationError> {
    if classify_rw_submission_v21(offset, length)? == RwSubmissionV21::CompleteLocally {
        return Err(MessageValidationError::LocalOnlyWireForm);
    }
    if initialized_length > length {
        return Err(MessageValidationError::Relationship);
    }
    if initialized_length != 0 {
        validate_file_range(initialized_offset, u64::from(initialized_length), false)
            .map_err(MessageValidationError::Range)?;
    }
    Ok(())
}

pub fn validate_read_v21(
    request: &PRw,
    data: GrantBindingV21<'_>,
) -> Result<ValidatedReadV21, MessageValidationError> {
    if request.rw_flags & !RW_FLAGS_V21 != 0 || request.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if pair_nonzero(request.op_id.lo, request.op_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    validate_rw_scalars(
        request.offset,
        request.length,
        request.initialized_offset,
        request.initialized_length,
    )?;
    let data = validate_bound(
        &request.data,
        data,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.data.length != request.length {
        return Err(MessageValidationError::Relationship);
    }
    Ok(ValidatedReadV21 { data })
}

pub fn validate_write_v2(
    request: &WriteV2,
    context: &WriteV2Context<'_>,
) -> Result<ValidatedWriteV2, MessageValidationError> {
    validate_header(request.header, CONTROL_VERSION_V2, size_of::<WriteV2>())?;
    if request.rw_flags & !RW_FLAGS_V21 != 0 || request.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(request.op_id.lo, request.op_id.hi) || request.expected_size_epoch == 0 {
        return Err(MessageValidationError::Identity);
    }
    validate_rw_scalars(
        request.offset,
        request.length,
        request.initialized_offset,
        request.initialized_length,
    )?;
    let data = validate_bound(
        &request.data,
        context.data,
        buffer_access::K2U_READ_ONLY,
        BufferRefPolicy::Exact,
    )?;
    if request.data.length != request.length {
        return Err(MessageValidationError::Relationship);
    }
    let reply = validate_bound(
        &request.reply,
        context.reply,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.reply.length < 56 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(ValidatedWriteV2 { data, reply })
}

pub fn validate_replay_open_v2(
    request: &ReplayOpenV2,
    reply: GrantBindingV21<'_>,
) -> Result<ValidatedReplayOpenV2, MessageValidationError> {
    validate_header(
        request.header,
        CONTROL_VERSION_V2,
        size_of::<ReplayOpenV2>(),
    )?;
    if request.kernel_open_id == 0
        || !pair_nonzero(request.file_id.lo, request.file_id.hi)
        || !pair_nonzero(request.link_id.lo, request.link_id.hi)
    {
        return Err(MessageValidationError::Identity);
    }
    let reply = validate_bound(
        &request.reply,
        reply,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.reply.length < 16 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(ValidatedReplayOpenV2 { reply })
}

pub fn validate_query_op_v2(
    request: &QueryOpV2,
    context: &QueryOpV2Context<'_>,
) -> Result<ValidatedQueryOpV2, MessageValidationError> {
    let accepted_required_flags = if context.retained_cancelled_no_candidate {
        query_op_required_flags::ABORT_IF_PREPARED
    } else {
        0
    };
    validate_header_with_flags(
        request.header,
        CONTROL_VERSION_V2,
        size_of::<QueryOpV2>(),
        accepted_required_flags,
    )?;
    if !pair_nonzero(request.op_id.lo, request.op_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    let reply = validate_bound(
        &request.reply,
        context.reply,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.reply.length < 56 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let committed_result = validate_bound(
        &request.committed_result,
        context.committed_result,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.committed_result.length != 224 {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(ValidatedQueryOpV2 {
        reply,
        committed_result,
    })
}

pub fn validate_ack_result_v2(request: &AckResultV2) -> Result<(), MessageValidationError> {
    validate_header(request.header, CONTROL_VERSION_V2, size_of::<AckResultV2>())?;
    if !pair_nonzero(request.op_id.lo, request.op_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

fn validate_shrunk_echo(
    reference: &BufferRef,
    binding: GrantBindingV21<'_>,
) -> Result<ValidatedBuffer, MessageValidationError> {
    validate_buffer_ref(
        reference,
        &BufferRefRule::Grant {
            grant: binding.grant,
            expected_session_epoch: binding.expected_session_epoch,
            expected_owner: binding.expected_owner,
            policy: BufferRefPolicy::ShrinkOnly,
            empty: EmptyBufferRule::Forbidden,
        },
    )
    .map_err(MessageValidationError::Grant)
}

fn validate_output_echo(
    output: &OControl,
    binding: GrantBindingV21<'_>,
    exact_length: u32,
) -> Result<ValidatedBuffer, MessageValidationError> {
    let value = validate_shrunk_echo(&output.body, binding)?;
    if output.body.length != exact_length {
        return Err(MessageValidationError::Completion);
    }
    Ok(value)
}

fn validate_information(
    information: u64,
    request_length: u32,
) -> Result<u32, MessageValidationError> {
    if information == 0 || information > u64::from(request_length) {
        return Err(MessageValidationError::Completion);
    }
    u32::try_from(information).map_err(|_| MessageValidationError::Completion)
}

fn validate_write_coverage(
    request: &WriteV2,
    information: u64,
    sizes: SizeState,
) -> Result<(), MessageValidationError> {
    let end = request
        .offset
        .checked_add(information)
        .ok_or(MessageValidationError::Relationship)?;
    if end > sizes.file_size || end > sizes.valid_data_length {
        return Err(MessageValidationError::Relationship);
    }
    Ok(())
}

pub fn validate_prepare_open_success_v21(
    request: &PrepareOpenV2,
    context: &PrepareOpenV2Context<'_>,
    output: &OControl,
    result: &PrepareOpenResultV1,
) -> Result<ValidatedPrepareOpenSuccessV21, MessageValidationError> {
    validate_prepare_open_v2(request, context)?;
    let reply = validate_output_echo(output, context.reply, 136)?;
    validate_header(
        result.header,
        CONTROL_VERSION_V1,
        size_of::<PrepareOpenResultV1>(),
    )?;
    if result.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(result.transaction_id.lo, result.transaction_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    validate_size_state_v21(result.sizes)?;
    if result.security_descriptor.length < 20 || result.security_descriptor.length > 65_536 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let security_descriptor = validate_shrunk_echo(
        &result.security_descriptor,
        context.result_security_descriptor,
    )?;
    Ok(ValidatedPrepareOpenSuccessV21 {
        reply,
        security_descriptor,
    })
}

pub fn validate_commit_open_success_v2(
    request: &CommitOpenV2,
    reply: GrantBindingV21<'_>,
    output: &OControl,
    result: &CommitOpenResultV2,
) -> Result<ValidatedCommitOpenSuccessV2, MessageValidationError> {
    validate_commit_open_v2(request, reply)?;
    let reply = validate_output_echo(output, reply, 112)?;
    validate_header(
        result.header,
        CONTROL_VERSION_V2,
        size_of::<CommitOpenResultV2>(),
    )?;
    if result.result_flags != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if result.provider_open_cookie == 0 {
        return Err(MessageValidationError::Identity);
    }
    if result.volume_commit_sequence == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if result.create_result > create_result::OVERWRITTEN {
        return Err(MessageValidationError::InvalidScalar);
    }
    validate_size_state_v21(result.sizes)?;
    Ok(ValidatedCommitOpenSuccessV2 { reply })
}

pub fn validate_read_success_v21(
    request: &PRw,
    data: GrantBindingV21<'_>,
    output: &OControl,
    information: u64,
) -> Result<ValidatedReadSuccessV21, MessageValidationError> {
    validate_read_v21(request, data)?;
    let transferred = validate_information(information, request.length)?;
    let data = validate_output_echo(output, data, transferred)?;
    Ok(ValidatedReadSuccessV21 { data })
}

pub fn validate_write_success_v2(
    request: &WriteV2,
    context: &WriteV2Context<'_>,
    output: &OControl,
    information: u64,
    result: &WriteResultV2,
) -> Result<ValidatedWriteSuccessV2, MessageValidationError> {
    validate_write_v2(request, context)?;
    validate_information(information, request.length)?;
    let reply = validate_output_echo(output, context.reply, 56)?;
    validate_header(
        result.header,
        CONTROL_VERSION_V2,
        size_of::<WriteResultV2>(),
    )?;
    if result.flags != 0 || result.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if result.volume_commit_sequence == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    validate_size_state_v21(result.sizes)?;
    validate_write_coverage(request, information, result.sizes)?;
    Ok(ValidatedWriteSuccessV2 { reply })
}

pub fn validate_replay_open_success_v21(
    request: &ReplayOpenV2,
    reply: GrantBindingV21<'_>,
    output: &OControl,
    result: &ReplayOpenResultV1,
) -> Result<ValidatedReplayOpenSuccessV21, MessageValidationError> {
    validate_replay_open_v2(request, reply)?;
    let reply = validate_output_echo(output, reply, 16)?;
    validate_header(
        result.header,
        CONTROL_VERSION_V1,
        size_of::<ReplayOpenResultV1>(),
    )?;
    if result.provider_open_cookie == 0 {
        return Err(MessageValidationError::Identity);
    }
    Ok(ValidatedReplayOpenSuccessV21 { reply })
}

pub const fn validate_create_phase_identity_v21(
    expectation: &CreatePhaseExpectationV21,
    candidate: &CreatePhaseCandidateV21,
) -> Result<ValidatedCreatePhaseIdentityV21, MessageValidationError> {
    if expectation.max_inflight == 0
        || expectation.max_inflight > MAX_INFLIGHT
        || expectation.slot_index >= expectation.max_inflight
        || (expectation.op_id.lo == 0 && expectation.op_id.hi == 0)
        || matches!(expectation.prior_generation, Some(0))
        || matches!(expectation.transaction_id, Some(value) if value.lo == 0 && value.hi == 0)
    {
        return Err(MessageValidationError::Identity);
    }
    if candidate.req_id.generation() == 0
        || candidate.req_id.slot_index() != expectation.slot_index
        || matches!(expectation.prior_generation, Some(value) if value == candidate.req_id.generation())
    {
        return Err(MessageValidationError::Identity);
    }
    let op_matches = matches!(
        candidate.op_id,
        Some(value) if value.lo == expectation.op_id.lo && value.hi == expectation.op_id.hi
    );
    let tx_matches = match (expectation.transaction_id, candidate.transaction_id) {
        (Some(expected), Some(actual)) => {
            (expected.lo != 0 || expected.hi != 0)
                && expected.lo == actual.lo
                && expected.hi == actual.hi
        }
        _ => false,
    };
    let shape_ok = match candidate.phase {
        CreatePhaseV21::Prepare | CreatePhaseV21::QueryOp | CreatePhaseV21::AckResult => {
            op_matches && candidate.transaction_id.is_none()
        }
        CreatePhaseV21::Commit => op_matches && tx_matches,
        CreatePhaseV21::AbortOpen => candidate.op_id.is_none() && tx_matches,
    };
    if !shape_ok {
        return Err(MessageValidationError::Identity);
    }
    Ok(ValidatedCreatePhaseIdentityV21 {
        phase: candidate.phase,
        req_id: candidate.req_id,
    })
}

pub const fn mutation_kind_of_body_v21(body: MutationBodyRefV21<'_>) -> u16 {
    match body {
        MutationBodyRefV21::SetBasicInfo(_) => mutation_kind::SET_BASIC_INFO,
        MutationBodyRefV21::SetAllocationSize(_) => mutation_kind::SET_ALLOCATION_SIZE,
        MutationBodyRefV21::SetEndOfFile(_) => mutation_kind::SET_END_OF_FILE,
        MutationBodyRefV21::SetValidDataLength(_) => mutation_kind::SET_VALID_DATA_LENGTH,
        MutationBodyRefV21::Rename(_) => mutation_kind::RENAME,
        MutationBodyRefV21::Link(_) => mutation_kind::LINK,
        MutationBodyRefV21::Unlink(_) => mutation_kind::UNLINK,
        MutationBodyRefV21::SetSecurity(_) => mutation_kind::SET_SECURITY,
    }
}

pub const fn mutation_kind_result_length_v21(kind: u16) -> Option<u32> {
    match kind {
        mutation_kind::RENAME => Some(112),
        mutation_kind::LINK => Some(104),
        mutation_kind::UNLINK => Some(56),
        _ => None,
    }
}

const fn mutation_fixed_size_v21(kind: u16) -> u32 {
    match kind {
        mutation_kind::SET_BASIC_INFO => 48,
        mutation_kind::SET_ALLOCATION_SIZE
        | mutation_kind::SET_END_OF_FILE
        | mutation_kind::SET_VALID_DATA_LENGTH => 24,
        mutation_kind::RENAME => 72,
        mutation_kind::LINK => 64,
        mutation_kind::UNLINK => 56,
        mutation_kind::SET_SECURITY => 24,
        mutation_kind::SET_REPARSE => 24,
        mutation_kind::DELETE_REPARSE => 16,
        _ => 0,
    }
}

pub fn validate_stored_component_utf16(bytes: &[u8]) -> Result<(), MessageValidationError> {
    if bytes.is_empty()
        || bytes.len() % 2 != 0
        || bytes.len() > (MAX_COMPONENT_UTF16_CODE_UNITS as usize) * 2
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    let count = bytes.len() / 2;
    let mut index = 0;
    while index < count {
        let unit = u16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]);
        match unit {
            0x0000 | 0x0022 | 0x002a | 0x002f | 0x003a | 0x003c | 0x003e | 0x003f | 0x005c => {
                return Err(MessageValidationError::InvalidScalar);
            }
            0xd800..=0xdbff => {
                if index + 1 >= count {
                    return Err(MessageValidationError::InvalidScalar);
                }
                let low = u16::from_le_bytes([bytes[2 * (index + 1)], bytes[2 * (index + 1) + 1]]);
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Err(MessageValidationError::InvalidScalar);
                }
                index += 1;
            }
            0xdc00..=0xdfff => {
                return Err(MessageValidationError::InvalidScalar);
            }
            _ => {}
        }
        index += 1;
    }
    let first = u16::from_le_bytes([bytes[0], bytes[1]]);
    if first == 0x002e {
        if count == 1 {
            return Err(MessageValidationError::InvalidScalar);
        }
        if count == 2 && u16::from_le_bytes([bytes[2], bytes[3]]) == 0x002e {
            return Err(MessageValidationError::InvalidScalar);
        }
    }
    Ok(())
}

pub fn validate_mutation_v2(
    request: &MutationV2,
    context: &MutationV2Context<'_>,
) -> Result<ValidatedMutationV2, MessageValidationError> {
    validate_header(request.header, CONTROL_VERSION_V2, size_of::<MutationV2>())?;
    if request.mutation_flags != 0 || request.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(request.op_id.lo, request.op_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    let kind = request.mutation_kind;
    if kind == mutation_kind::INVALID || kind > mutation_kind::DELETE_REPARSE {
        return Err(MessageValidationError::InvalidScalar);
    }
    if matches!(
        kind,
        mutation_kind::SET_REPARSE | mutation_kind::DELETE_REPARSE
    ) && !context.reparse_selected
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    let requires_namespace = matches!(
        kind,
        mutation_kind::SET_BASIC_INFO
            | mutation_kind::RENAME
            | mutation_kind::LINK
            | mutation_kind::UNLINK
            | mutation_kind::SET_REPARSE
            | mutation_kind::DELETE_REPARSE
    );
    let requires_epoch = matches!(
        kind,
        mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH
    );
    let requires_security = kind == mutation_kind::SET_SECURITY;
    if (request.expected_namespace_generation != 0) != requires_namespace
        || (request.expected_size_epoch != 0) != requires_epoch
        || (request.expected_security_generation != 0) != requires_security
    {
        return Err(MessageValidationError::Identity);
    }

    let body = validate_bound(
        &request.body,
        context.body,
        buffer_access::K2U_READ_ONLY,
        BufferRefPolicy::Exact,
    )?;
    if request.body.length < mutation_fixed_size_v21(kind) || request.body.length > 65_560 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let reply = validate_bound(
        &request.reply,
        context.reply,
        buffer_access::U2K_WRITE,
        BufferRefPolicy::Exact,
    )?;
    if request.reply.length < 112 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let kind_result = match (mutation_kind_result_length_v21(kind), context.kind_result) {
        (Some(length), Some(binding)) => {
            let value = validate_bound(
                &request.kind_result,
                binding,
                buffer_access::U2K_WRITE,
                BufferRefPolicy::Exact,
            )?;
            if request.kind_result.length != length {
                return Err(MessageValidationError::InvalidScalar);
            }
            Some(value)
        }
        (None, None) => {
            validate_buffer_ref(&request.kind_result, &BufferRefRule::None)
                .map_err(MessageValidationError::Grant)?;
            None
        }
        _ => return Err(MessageValidationError::Relationship),
    };
    Ok(ValidatedMutationV2 {
        body,
        reply,
        kind_result,
    })
}

fn validate_body_prefix(
    header: ControlHeader,
    fixed: u32,
    blob: &[u8],
    tail: Option<BlobSlice>,
) -> Result<(), MessageValidationError> {
    if header.struct_version != 1 {
        return Err(MessageValidationError::Control(
            ControlError::RevisionMismatch,
        ));
    }
    if header.required_flags != 0 {
        return Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags,
        ));
    }
    match tail {
        None => {
            if header.struct_size != fixed {
                return Err(MessageValidationError::Control(ControlError::InvalidSize));
            }
        }
        Some(slice) => {
            if slice.offset != fixed || slice.length == 0 {
                return Err(MessageValidationError::Relationship);
            }
            let end = u64::from(fixed) + u64::from(slice.length);
            let padded = end.div_ceil(8) * 8;
            if u64::from(header.struct_size) != padded {
                return Err(MessageValidationError::Control(ControlError::InvalidSize));
            }
        }
    }
    if blob.len() as u64 != u64::from(header.struct_size) {
        return Err(MessageValidationError::Control(ControlError::InvalidSize));
    }
    if let Some(slice) = tail {
        let mut index = (fixed as usize) + (slice.length as usize);
        while index < blob.len() {
            if blob[index] != 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            index += 1;
        }
    }
    Ok(())
}

pub fn validate_mutation_body_v21(
    kind: u16,
    body: MutationBodyRefV21<'_>,
    blob: &[u8],
    same_parent_rename: bool,
) -> Result<(), MessageValidationError> {
    if mutation_kind_of_body_v21(body) != kind {
        return Err(MessageValidationError::Relationship);
    }
    match body {
        MutationBodyRefV21::SetBasicInfo(record) => {
            validate_body_prefix(record.header, 48, blob, None)?;
            if record.set_mask == 0 || record.set_mask & !basic_info_set_mask::ALL != 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            if record.attributes != 0 {
                if record.attributes & !file_attributes::SETTABLE_BASIC_MASK != 0 {
                    return Err(MessageValidationError::InvalidScalar);
                }
                if record.attributes & file_attributes::NORMAL != 0
                    && record.attributes != file_attributes::NORMAL
                {
                    return Err(MessageValidationError::InvalidScalar);
                }
            }
            let selects_attributes = record.set_mask & basic_info_set_mask::FILE_ATTRIBUTES != 0;
            if selects_attributes != (record.attributes != 0) {
                return Err(MessageValidationError::Relationship);
            }
            let times: [(i64, u32); 4] = [
                (record.creation_time, basic_info_set_mask::CREATION_TIME),
                (
                    record.last_access_time,
                    basic_info_set_mask::LAST_ACCESS_TIME,
                ),
                (record.last_write_time, basic_info_set_mask::LAST_WRITE_TIME),
                (record.change_time, basic_info_set_mask::CHANGE_TIME),
            ];
            for (time, bit) in times {
                if record.set_mask & bit != 0 {
                    if time <= 0 {
                        return Err(MessageValidationError::InvalidScalar);
                    }
                } else if time != 0 {
                    return Err(MessageValidationError::InvalidScalar);
                }
            }
            Ok(())
        }
        MutationBodyRefV21::SetAllocationSize(record)
        | MutationBodyRefV21::SetEndOfFile(record)
        | MutationBodyRefV21::SetValidDataLength(record) => {
            validate_body_prefix(record.header, 24, blob, None)?;
            if record.flags != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if record.new_size > MAX_FILE_SIZE {
                return Err(MessageValidationError::InvalidScalar);
            }
            Ok(())
        }
        MutationBodyRefV21::Rename(record) => {
            validate_body_prefix(record.header, 72, blob, Some(record.name))?;
            if record.flags & !rename_flags::REPLACE_IF_EXISTS != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if !pair_nonzero(record.source_link_id.lo, record.source_link_id.hi)
                || !pair_nonzero(record.target_parent_id.lo, record.target_parent_id.hi)
                || record.expected_source_parent_generation == 0
                || record.expected_target_parent_generation == 0
            {
                return Err(MessageValidationError::Identity);
            }
            if same_parent_rename
                && record.expected_source_parent_generation
                    != record.expected_target_parent_generation
            {
                return Err(MessageValidationError::Relationship);
            }
            let start = 72usize;
            let end = start + record.name.length as usize;
            validate_stored_component_utf16(&blob[start..end])
        }
        MutationBodyRefV21::Link(record) => {
            validate_body_prefix(record.header, 64, blob, Some(record.name))?;
            if record.flags & !link_flags::REPLACE_IF_EXISTS != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if !pair_nonzero(record.source_file_id.lo, record.source_file_id.hi)
                || !pair_nonzero(record.target_parent_id.lo, record.target_parent_id.hi)
                || record.expected_target_parent_generation == 0
            {
                return Err(MessageValidationError::Identity);
            }
            let start = 64usize;
            let end = start + record.name.length as usize;
            validate_stored_component_utf16(&blob[start..end])
        }
        MutationBodyRefV21::Unlink(record) => {
            validate_body_prefix(record.header, 56, blob, None)?;
            if record.flags != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if !pair_nonzero(record.link_id.lo, record.link_id.hi)
                || !pair_nonzero(record.parent_id.lo, record.parent_id.hi)
                || record.expected_parent_generation == 0
            {
                return Err(MessageValidationError::Identity);
            }
            Ok(())
        }
        MutationBodyRefV21::SetSecurity(record) => {
            validate_body_prefix(record.header, 24, blob, Some(record.security_descriptor))?;
            if record.flags != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if record.security_information == 0
                || record.security_information & !security_information::SET_MASK != 0
            {
                return Err(MessageValidationError::InvalidScalar);
            }
            if record.security_descriptor.length < MIN_SECURITY_DESCRIPTOR_BYTES
                || record.security_descriptor.length > MAX_SECURITY_DESCRIPTOR_BYTES
            {
                return Err(MessageValidationError::InvalidScalar);
            }
            Ok(())
        }
    }
}

fn validate_replacement_tuple(
    replaced_file_nonzero: bool,
    replaced_link_nonzero: bool,
    replaced_generation: u64,
    replaced_link_count: u32,
) -> Result<bool, MessageValidationError> {
    let replaced_generation_nonzero = replaced_generation != 0;
    if replaced_file_nonzero != replaced_link_nonzero
        || replaced_file_nonzero != replaced_generation_nonzero
    {
        return Err(MessageValidationError::Relationship);
    }
    if !replaced_file_nonzero && replaced_link_count != 0 {
        return Err(MessageValidationError::Relationship);
    }
    Ok(replaced_file_nonzero)
}

fn validate_rename_result_record(
    body: &RenameV1,
    record: &RenameResultV2,
    same_parent_rename: bool,
    result_namespace_generation: u64,
) -> Result<(), MessageValidationError> {
    validate_header(
        record.header,
        CONTROL_VERSION_V2,
        size_of::<RenameResultV2>(),
    )?;
    if record.flags != 0 || record.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(record.file_id.lo, record.file_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    if !pair_nonzero(record.link_id.lo, record.link_id.hi) || record.link_id != body.source_link_id
    {
        return Err(MessageValidationError::Identity);
    }
    if record.source_parent_generation <= body.expected_source_parent_generation
        || record.target_parent_generation <= body.expected_target_parent_generation
    {
        return Err(MessageValidationError::Identity);
    }
    if same_parent_rename && record.source_parent_generation != record.target_parent_generation {
        return Err(MessageValidationError::Relationship);
    }
    let replaced = validate_replacement_tuple(
        pair_nonzero(record.replaced_file_id.lo, record.replaced_file_id.hi),
        pair_nonzero(record.replaced_link_id.lo, record.replaced_link_id.hi),
        record.replaced_namespace_generation,
        record.replaced_link_count,
    )?;
    if replaced {
        if record.replaced_link_id == record.link_id {
            return Err(MessageValidationError::Relationship);
        }
        if record.replaced_file_id == record.file_id
            && (record.replaced_namespace_generation != result_namespace_generation
                || record.replaced_link_count != record.link_count)
        {
            return Err(MessageValidationError::Relationship);
        }
    }
    Ok(())
}

fn validate_link_result_record(
    body: &LinkV1,
    record: &LinkResultV2,
    result_namespace_generation: u64,
) -> Result<(), MessageValidationError> {
    validate_header(record.header, CONTROL_VERSION_V2, size_of::<LinkResultV2>())?;
    if record.flags != 0 || record.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(record.file_id.lo, record.file_id.hi)
        || !pair_nonzero(record.new_link_id.lo, record.new_link_id.hi)
    {
        return Err(MessageValidationError::Identity);
    }
    if record.target_parent_generation <= body.expected_target_parent_generation {
        return Err(MessageValidationError::Identity);
    }
    let replaced = validate_replacement_tuple(
        pair_nonzero(record.replaced_file_id.lo, record.replaced_file_id.hi),
        pair_nonzero(record.replaced_link_id.lo, record.replaced_link_id.hi),
        record.replaced_namespace_generation,
        record.replaced_link_count,
    )?;
    if replaced {
        if record.replaced_link_id == record.new_link_id {
            return Err(MessageValidationError::Relationship);
        }
        if record.replaced_file_id == record.file_id
            && (record.replaced_namespace_generation != result_namespace_generation
                || record.replaced_link_count != record.link_count)
        {
            return Err(MessageValidationError::Relationship);
        }
    }
    Ok(())
}

fn validate_unlink_result_record(
    body: &UnlinkV1,
    record: &UnlinkResultV1,
) -> Result<(), MessageValidationError> {
    validate_header(
        record.header,
        CONTROL_VERSION_V1,
        size_of::<UnlinkResultV1>(),
    )?;
    if record.flags != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if !pair_nonzero(record.file_id.lo, record.file_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    if !pair_nonzero(record.removed_link_id.lo, record.removed_link_id.hi)
        || record.removed_link_id != body.link_id
    {
        return Err(MessageValidationError::Identity);
    }
    if record.parent_generation <= body.expected_parent_generation {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_mutation_success_v2(
    request: &MutationV2,
    context: &MutationV2Context<'_>,
    body: MutationBodyRefV21<'_>,
    output: &OControl,
    result: &MutationResultV2,
    kind_result: MutationKindResultRefV21<'_>,
    retained_sizes: SizeState,
) -> Result<ValidatedMutationSuccessV2, MessageValidationError> {
    validate_mutation_v2(request, context)?;
    if mutation_kind_of_body_v21(body) != request.mutation_kind {
        return Err(MessageValidationError::Relationship);
    }
    let reply = validate_output_echo(output, context.reply, 112)?;
    validate_header(
        result.header,
        CONTROL_VERSION_V2,
        size_of::<MutationResultV2>(),
    )?;
    if result.result_flags != 0 || result.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if result.op_id.lo != request.op_id.lo
        || result.op_id.hi != request.op_id.hi
        || result.mutation_kind != request.mutation_kind
    {
        return Err(MessageValidationError::Identity);
    }
    if result.volume_commit_sequence == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    validate_size_state_v21(result.sizes)?;

    let kind = request.mutation_kind;
    let requires_namespace = matches!(
        kind,
        mutation_kind::SET_BASIC_INFO
            | mutation_kind::RENAME
            | mutation_kind::LINK
            | mutation_kind::UNLINK
            | mutation_kind::SET_REPARSE
            | mutation_kind::DELETE_REPARSE
    );
    if requires_namespace {
        if result.namespace_generation <= request.expected_namespace_generation {
            return Err(MessageValidationError::Identity);
        }
    } else if result.namespace_generation != 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if kind == mutation_kind::SET_SECURITY {
        if result.security_generation <= request.expected_security_generation {
            return Err(MessageValidationError::Identity);
        }
    } else if result.security_generation != 0 {
        return Err(MessageValidationError::InvalidScalar);
    }

    let is_size_kind = matches!(
        kind,
        mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH
    );
    if is_size_kind {
        if result.sizes.size_epoch <= request.expected_size_epoch {
            return Err(MessageValidationError::InvalidScalar);
        }
        let new_size = match body {
            MutationBodyRefV21::SetAllocationSize(record)
            | MutationBodyRefV21::SetEndOfFile(record)
            | MutationBodyRefV21::SetValidDataLength(record) => record.new_size,
            _ => 0,
        };
        match kind {
            mutation_kind::SET_VALID_DATA_LENGTH => {
                if result.sizes.allocation_size != retained_sizes.allocation_size
                    || result.sizes.file_size != retained_sizes.file_size
                    || result.sizes.valid_data_length != new_size
                {
                    return Err(MessageValidationError::Relationship);
                }
            }
            mutation_kind::SET_END_OF_FILE => {
                if result.sizes.file_size != new_size {
                    return Err(MessageValidationError::Relationship);
                }
            }
            _ => {
                let floor = if new_size > result.sizes.file_size {
                    new_size
                } else {
                    result.sizes.file_size
                };
                if result.sizes.allocation_size < floor {
                    return Err(MessageValidationError::Relationship);
                }
            }
        }
    } else if result.sizes.size_epoch < retained_sizes.size_epoch {
        return Err(MessageValidationError::Relationship);
    }

    let kind_result_value = match kind_result {
        MutationKindResultRefV21::None => {
            if mutation_kind_result_length_v21(kind).is_some() {
                return Err(MessageValidationError::Relationship);
            }
            validate_buffer_ref(&result.kind_result, &BufferRefRule::None)
                .map_err(MessageValidationError::Grant)?;
            None
        }
        MutationKindResultRefV21::Rename(record) => {
            if kind != mutation_kind::RENAME {
                return Err(MessageValidationError::Relationship);
            }
            let binding = match context.kind_result {
                Some(binding) => binding,
                None => return Err(MessageValidationError::Relationship),
            };
            let value = validate_shrunk_echo(&result.kind_result, binding)?;
            if result.kind_result.length != 112 {
                return Err(MessageValidationError::Completion);
            }
            let rename_body = match body {
                MutationBodyRefV21::Rename(rename_body) => rename_body,
                _ => return Err(MessageValidationError::Relationship),
            };
            validate_rename_result_record(
                rename_body,
                record,
                context.same_parent_rename,
                result.namespace_generation,
            )?;
            Some(value)
        }
        MutationKindResultRefV21::Link(record) => {
            if kind != mutation_kind::LINK {
                return Err(MessageValidationError::Relationship);
            }
            let binding = match context.kind_result {
                Some(binding) => binding,
                None => return Err(MessageValidationError::Relationship),
            };
            let value = validate_shrunk_echo(&result.kind_result, binding)?;
            if result.kind_result.length != 104 {
                return Err(MessageValidationError::Completion);
            }
            let link_body = match body {
                MutationBodyRefV21::Link(link_body) => link_body,
                _ => return Err(MessageValidationError::Relationship),
            };
            validate_link_result_record(link_body, record, result.namespace_generation)?;
            Some(value)
        }
        MutationKindResultRefV21::Unlink(record) => {
            if kind != mutation_kind::UNLINK {
                return Err(MessageValidationError::Relationship);
            }
            let binding = match context.kind_result {
                Some(binding) => binding,
                None => return Err(MessageValidationError::Relationship),
            };
            let value = validate_shrunk_echo(&result.kind_result, binding)?;
            if result.kind_result.length != 56 {
                return Err(MessageValidationError::Completion);
            }
            let unlink_body = match body {
                MutationBodyRefV21::Unlink(unlink_body) => unlink_body,
                _ => return Err(MessageValidationError::Relationship),
            };
            validate_unlink_result_record(unlink_body, record)?;
            Some(value)
        }
    };
    Ok(ValidatedMutationSuccessV2 {
        reply,
        kind_result: kind_result_value,
    })
}

/// Section 13 completion status registry. Every value that may legally
/// appear in an ABI 2.1 provider completion, plus the named values the
/// normalization rules reference.
/// cbindgen:ignore
pub mod completion_status {
    pub const SUCCESS: i32 = 0x0000_0000;
    pub const PENDING: i32 = 0x0000_0103;
    pub const BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
    pub const NO_MORE_FILES: i32 = 0x8000_0006u32 as i32;
    pub const NO_SUCH_FILE: i32 = 0xc000_000fu32 as i32;
    pub const END_OF_FILE: i32 = 0xc000_0011u32 as i32;
    pub const ACCESS_DENIED: i32 = 0xc000_0022u32 as i32;
    pub const BUFFER_TOO_SMALL: i32 = 0xc000_0023u32 as i32;
    pub const OBJECT_NAME_NOT_FOUND: i32 = 0xc000_0034u32 as i32;
    pub const OBJECT_NAME_COLLISION: i32 = 0xc000_0035u32 as i32;
    pub const OBJECT_PATH_NOT_FOUND: i32 = 0xc000_003au32 as i32;
    pub const DATA_ERROR: i32 = 0xc000_003eu32 as i32;
    pub const SHARING_VIOLATION: i32 = 0xc000_0043u32 as i32;
    pub const FILE_LOCK_CONFLICT: i32 = 0xc000_0054u32 as i32;
    pub const DELETE_PENDING: i32 = 0xc000_0056u32 as i32;
    pub const PRIVILEGE_NOT_HELD: i32 = 0xc000_0061u32 as i32;
    pub const INVALID_SECURITY_DESCR: i32 = 0xc000_0079u32 as i32;
    pub const DISK_FULL: i32 = 0xc000_007fu32 as i32;
    pub const INTEGER_OVERFLOW: i32 = 0xc000_0095u32 as i32;
    pub const INSUFFICIENT_RESOURCES: i32 = 0xc000_009au32 as i32;
    pub const MEDIA_WRITE_PROTECTED: i32 = 0xc000_00a2u32 as i32;
    pub const DEVICE_NOT_READY: i32 = 0xc000_00a3u32 as i32;
    pub const IO_TIMEOUT: i32 = 0xc000_00b5u32 as i32;
    pub const FILE_IS_A_DIRECTORY: i32 = 0xc000_00bau32 as i32;
    pub const NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;
    pub const DIRECTORY_NOT_EMPTY: i32 = 0xc000_0101u32 as i32;
    pub const FILE_CORRUPT_ERROR: i32 = 0xc000_0102u32 as i32;
    pub const NOT_A_DIRECTORY: i32 = 0xc000_0103u32 as i32;
    pub const CANCELLED: i32 = 0xc000_0120u32 as i32;
    pub const CANNOT_DELETE: i32 = 0xc000_0121u32 as i32;
    pub const IO_DEVICE_ERROR: i32 = 0xc000_0185u32 as i32;
    pub const RETRY: i32 = 0xc000_022du32 as i32;
    pub const USER_MAPPED_FILE: i32 = 0xc000_0243u32 as i32;
}

/// cbindgen:ignore
pub const OPEN_FAILURES: [i32; 17] = [
    completion_status::ACCESS_DENIED,
    completion_status::OBJECT_NAME_NOT_FOUND,
    completion_status::OBJECT_NAME_COLLISION,
    completion_status::OBJECT_PATH_NOT_FOUND,
    completion_status::DATA_ERROR,
    completion_status::SHARING_VIOLATION,
    completion_status::DELETE_PENDING,
    completion_status::DISK_FULL,
    completion_status::INSUFFICIENT_RESOURCES,
    completion_status::MEDIA_WRITE_PROTECTED,
    completion_status::DEVICE_NOT_READY,
    completion_status::IO_TIMEOUT,
    completion_status::FILE_IS_A_DIRECTORY,
    completion_status::NOT_SUPPORTED,
    completion_status::FILE_CORRUPT_ERROR,
    completion_status::NOT_A_DIRECTORY,
    completion_status::CANCELLED,
];

/// cbindgen:ignore
pub const READ_FAILURES: [i32; 8] = [
    completion_status::ACCESS_DENIED,
    completion_status::DATA_ERROR,
    completion_status::FILE_LOCK_CONFLICT,
    completion_status::INSUFFICIENT_RESOURCES,
    completion_status::DEVICE_NOT_READY,
    completion_status::IO_TIMEOUT,
    completion_status::FILE_CORRUPT_ERROR,
    completion_status::CANCELLED,
];

/// cbindgen:ignore
pub const WRITE_FAILURES: [i32; 11] = [
    completion_status::ACCESS_DENIED,
    completion_status::DATA_ERROR,
    completion_status::FILE_LOCK_CONFLICT,
    completion_status::DISK_FULL,
    completion_status::INSUFFICIENT_RESOURCES,
    completion_status::MEDIA_WRITE_PROTECTED,
    completion_status::DEVICE_NOT_READY,
    completion_status::IO_TIMEOUT,
    completion_status::FILE_CORRUPT_ERROR,
    completion_status::CANCELLED,
    completion_status::RETRY,
];

/// cbindgen:ignore
pub const FLUSH_FAILURES: [i32; 7] = [
    completion_status::DATA_ERROR,
    completion_status::INSUFFICIENT_RESOURCES,
    completion_status::MEDIA_WRITE_PROTECTED,
    completion_status::DEVICE_NOT_READY,
    completion_status::IO_TIMEOUT,
    completion_status::FILE_CORRUPT_ERROR,
    completion_status::CANCELLED,
];

/// cbindgen:ignore
pub const QUERY_FAILURES: [i32; 8] = [
    completion_status::ACCESS_DENIED,
    completion_status::DATA_ERROR,
    completion_status::INSUFFICIENT_RESOURCES,
    completion_status::DEVICE_NOT_READY,
    completion_status::IO_TIMEOUT,
    completion_status::NOT_SUPPORTED,
    completion_status::FILE_CORRUPT_ERROR,
    completion_status::CANCELLED,
];

/// cbindgen:ignore
pub const MUTATE_FAILURES: [i32; 22] = [
    completion_status::ACCESS_DENIED,
    completion_status::OBJECT_NAME_NOT_FOUND,
    completion_status::OBJECT_NAME_COLLISION,
    completion_status::OBJECT_PATH_NOT_FOUND,
    completion_status::DATA_ERROR,
    completion_status::SHARING_VIOLATION,
    completion_status::DELETE_PENDING,
    completion_status::PRIVILEGE_NOT_HELD,
    completion_status::INVALID_SECURITY_DESCR,
    completion_status::DISK_FULL,
    completion_status::INSUFFICIENT_RESOURCES,
    completion_status::MEDIA_WRITE_PROTECTED,
    completion_status::DEVICE_NOT_READY,
    completion_status::IO_TIMEOUT,
    completion_status::NOT_SUPPORTED,
    completion_status::DIRECTORY_NOT_EMPTY,
    completion_status::FILE_CORRUPT_ERROR,
    completion_status::NOT_A_DIRECTORY,
    completion_status::CANCELLED,
    completion_status::CANNOT_DELETE,
    completion_status::RETRY,
    completion_status::USER_MAPPED_FILE,
];

const SUCCESS_ONLY: &[i32] = &[completion_status::SUCCESS];

/// One closed section 13 opcode row: the registered set is exactly
/// `extra` union `failures` and union adds no other value.
struct OpcodeStatusRow {
    opcode: u16,
    extra: &'static [i32],
    failures: &'static [i32],
}

/// CANCEL (no CQE), ATTACH (control IOCTL only), FSCTL (no legal request or
/// completion), and unknown opcodes have no row: nothing is registered.
const OPCODE_STATUS_TABLE: &[OpcodeStatusRow] = &[
    OpcodeStatusRow {
        opcode: op::PREPARE_OPEN,
        extra: SUCCESS_ONLY,
        failures: &OPEN_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::COMMIT_OPEN,
        extra: &[completion_status::SUCCESS, completion_status::RETRY],
        failures: &OPEN_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::ABORT_OPEN,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::CLEANUP,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::CLOSE,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::READ,
        extra: &[completion_status::SUCCESS, completion_status::END_OF_FILE],
        failures: &READ_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::WRITE,
        extra: SUCCESS_ONLY,
        failures: &WRITE_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::FLUSH,
        extra: SUCCESS_ONLY,
        failures: &FLUSH_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::QUERY_INFO,
        extra: SUCCESS_ONLY,
        failures: &QUERY_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::MUTATE,
        extra: SUCCESS_ONLY,
        failures: &MUTATE_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::QUERY_DIR,
        extra: &[
            completion_status::SUCCESS,
            completion_status::NO_MORE_FILES,
            completion_status::NO_SUCH_FILE,
        ],
        failures: &QUERY_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::QUERY_VOLUME,
        extra: SUCCESS_ONLY,
        failures: &QUERY_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::QUERY_SECURITY,
        extra: SUCCESS_ONLY,
        failures: &QUERY_FAILURES,
    },
    OpcodeStatusRow {
        opcode: op::REPLAY_OPEN,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::QUERY_OP,
        extra: &[
            completion_status::SUCCESS,
            completion_status::BUFFER_TOO_SMALL,
        ],
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::ACK_RESULT,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::PT_ROUTE_ACK,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::PT_EXTERNAL_SAFE_ACK,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
    OpcodeStatusRow {
        opcode: op::DIR_CHANGE_ACK,
        extra: SUCCESS_ONLY,
        failures: &[],
    },
];

const fn status_slice_contains(values: &[i32], status: i32) -> bool {
    let mut index = 0;
    while index < values.len() {
        if values[index] == status {
            return true;
        }
        index += 1;
    }
    false
}

/// True exactly when `(COMPLETION, opcode, status)` is a registered
/// section 13 pair. There is no severity-based catch-all.
pub const fn is_registered_completion_status_v21(opcode: u16, status: i32) -> bool {
    let mut index = 0;
    while index < OPCODE_STATUS_TABLE.len() {
        let row = &OPCODE_STATUS_TABLE[index];
        if row.opcode == opcode {
            return status_slice_contains(row.extra, status)
                || status_slice_contains(row.failures, status);
        }
        index += 1;
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionDispositionV21 {
    /// The `(kind, opcode, status)` triple is registered and may proceed to
    /// shape/output validation.
    Registered,
    /// Structurally empty unregistered observational result: normalize to
    /// IO_DEVICE_ERROR, record a provider violation, discard the result.
    NormalizeObservational,
    /// Unregistered status on a journaled opcode: the section 12 recovery
    /// rule (INVALID_CANDIDATE row / quarantine without EXACTLY_ONCE) takes
    /// precedence; never normalized, never replayed via NO_CANDIDATE.
    JournaledCandidateFault,
    /// Every remaining shape is a session protocol fault.
    SessionProtocolFault,
}

/// Classify one completion under the section 13 registry. A structurally
/// empty result has zero `out_len`, zero information, and all-zero output
/// bytes; the caller asserts that predicate before passing it.
pub const fn classify_completion_v21(
    kind: u16,
    opcode: u16,
    status: i32,
    structurally_empty: bool,
) -> CompletionDispositionV21 {
    match kind {
        cq_kind::COMPLETION => {
            if is_registered_completion_status_v21(opcode, status) {
                return CompletionDispositionV21::Registered;
            }
            if matches!(opcode, op::COMMIT_OPEN | op::WRITE | op::MUTATE) {
                return CompletionDispositionV21::JournaledCandidateFault;
            }
            if structurally_empty
                && matches!(
                    opcode,
                    op::READ
                        | op::QUERY_INFO
                        | op::QUERY_DIR
                        | op::QUERY_VOLUME
                        | op::QUERY_SECURITY
                )
            {
                return CompletionDispositionV21::NormalizeObservational;
            }
            CompletionDispositionV21::SessionProtocolFault
        }
        cq_kind::NOTIFY => {
            if opcode == 0 && status == completion_status::SUCCESS {
                CompletionDispositionV21::Registered
            } else {
                CompletionDispositionV21::SessionProtocolFault
            }
        }
        cq_kind::PROTOCOL => {
            if opcode == protocol_opcode::ABORT_SESSION && status == completion_status::SUCCESS {
                CompletionDispositionV21::Registered
            } else {
                CompletionDispositionV21::SessionProtocolFault
            }
        }
        _ => CompletionDispositionV21::SessionProtocolFault,
    }
}

/// Request-derived scalars a section 13 output row needs; `None` for rows
/// that are fully determined by `(opcode, status)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOutputContextV21 {
    None,
    RequestLength(u32),
    CanonicalBlobLength(u64),
    DescriptorLength(u32),
    QueryOpRetained {
        derived_size: u32,
        current_capacity: u32,
    },
}

const fn require_zero_output(
    out_len: u32,
    information: u64,
    context: CompletionOutputContextV21,
) -> Result<(), MessageValidationError> {
    if !matches!(context, CompletionOutputContextV21::None) {
        return Err(MessageValidationError::Relationship);
    }
    if out_len != 0 || information != 0 {
        return Err(MessageValidationError::Completion);
    }
    Ok(())
}

const fn require_ocontrol_exact(
    out_len: u32,
    information: u64,
    expected_information: u64,
    context: CompletionOutputContextV21,
) -> Result<(), MessageValidationError> {
    if !matches!(context, CompletionOutputContextV21::None) {
        return Err(MessageValidationError::Relationship);
    }
    if out_len != 24 || information != expected_information {
        return Err(MessageValidationError::Completion);
    }
    Ok(())
}

/// The exact section 13 `out_len`/information/output matrix. Only 0 or 24
/// is a legal `out_len`; when it is zero the caller separately asserts all
/// 24 output bytes are zero, and grant-echo validation stays with the
/// per-opcode success validators.
pub const fn validate_completion_output_v21(
    opcode: u16,
    status: i32,
    out_len: u32,
    information: u64,
    context: CompletionOutputContextV21,
) -> Result<(), MessageValidationError> {
    if !is_registered_completion_status_v21(opcode, status) {
        return Err(MessageValidationError::Completion);
    }
    if out_len != 0 && out_len != 24 {
        return Err(MessageValidationError::Completion);
    }

    if status == completion_status::SUCCESS {
        return match opcode {
            op::PREPARE_OPEN => require_ocontrol_exact(out_len, information, 136, context),
            op::COMMIT_OPEN | op::MUTATE => {
                require_ocontrol_exact(out_len, information, 112, context)
            }
            op::REPLAY_OPEN => require_ocontrol_exact(out_len, information, 16, context),
            op::QUERY_OP => require_ocontrol_exact(out_len, information, 56, context),
            op::READ | op::WRITE => match context {
                CompletionOutputContextV21::RequestLength(request_length) => {
                    if out_len != 24 || information == 0 || information > request_length as u64 {
                        Err(MessageValidationError::Completion)
                    } else {
                        Ok(())
                    }
                }
                _ => Err(MessageValidationError::Relationship),
            },
            op::QUERY_INFO | op::QUERY_VOLUME | op::QUERY_DIR => match context {
                CompletionOutputContextV21::CanonicalBlobLength(blob_length) => {
                    if out_len != 24 || blob_length == 0 || information != blob_length {
                        Err(MessageValidationError::Completion)
                    } else {
                        Ok(())
                    }
                }
                _ => Err(MessageValidationError::Relationship),
            },
            op::QUERY_SECURITY => match context {
                CompletionOutputContextV21::DescriptorLength(descriptor_length) => {
                    if out_len != 24
                        || descriptor_length < 20
                        || descriptor_length > 65_536
                        || information != descriptor_length as u64
                    {
                        Err(MessageValidationError::Completion)
                    } else {
                        Ok(())
                    }
                }
                _ => Err(MessageValidationError::Relationship),
            },
            // ABORT/CLEANUP/CLOSE/FLUSH/ACK/PT/external-change ACK success.
            _ => require_zero_output(out_len, information, context),
        };
    }

    if opcode == op::QUERY_OP && status == completion_status::BUFFER_TOO_SMALL {
        return match context {
            CompletionOutputContextV21::QueryOpRetained {
                derived_size,
                current_capacity,
            } => {
                if out_len != 0
                    || !matches!(derived_size, 80 | 112 | 136 | 168 | 216 | 224)
                    || information != derived_size as u64
                    || information <= current_capacity as u64
                {
                    Err(MessageValidationError::Completion)
                } else {
                    Ok(())
                }
            }
            _ => Err(MessageValidationError::Relationship),
        };
    }

    // RETRY, END_OF_FILE, NO_MORE_FILES, NO_SUCH_FILE, and every registered
    // ordinary failure complete with zero output and zero information.
    require_zero_output(out_len, information, context)
}

/// Apply-domain kinds in canonical lock order position.
/// cbindgen:ignore
pub mod apply_domain_kind {
    pub const FILE_STATE: u16 = 1;
    pub const DIRECTORY_NAMESPACE: u16 = 2;
    pub const LINK_STATE: u16 = 3;
    pub const OPEN_STATE: u16 = 4;
}

/// cbindgen:ignore
pub const MAX_APPLY_DOMAINS_PER_OPERATION: u32 = 6;
/// cbindgen:ignore
pub const MAX_QUERY_OP_BTS_RETRIES: u32 = 1;

/// The exact derived committed-result size for one retained journaled
/// operation: outer prefix plus the matching inner blob and inline kind
/// payload. `None` for every pair outside the closed journaled set.
pub const fn committed_result_total_size_v21(opcode: u16, mutation_kind_value: u16) -> Option<u32> {
    match (opcode, mutation_kind_value) {
        (op::WRITE, 0) => Some(80),
        (op::COMMIT_OPEN, 0) => Some(136),
        (op::MUTATE, kind) => match kind {
            mutation_kind::SET_BASIC_INFO
            | mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH
            | mutation_kind::SET_SECURITY => Some(112),
            mutation_kind::UNLINK => Some(168),
            mutation_kind::LINK => Some(216),
            mutation_kind::RENAME => Some(224),
            _ => None,
        },
        _ => None,
    }
}

/// The retained journaled operation a durable committed result is validated
/// against. `mutation_body` is the canonical validated request body and is
/// present exactly for MUTATE.
#[derive(Clone, Copy)]
pub struct RetainedCommittedContextV21<'a> {
    pub opcode: u16,
    pub mutation_kind: u16,
    pub write_request_length: u32,
    pub mutation_body: Option<MutationBodyRefV21<'a>>,
    pub same_parent_rename: bool,
}

pub enum ValidatedCommittedResultV1<'a> {
    Open {
        outer: CommittedResultV1,
        inner: CommittedOpenResultV1,
    },
    Write {
        outer: CommittedResultV1,
        inner: CommittedWriteResultV1,
    },
    Mutation {
        outer: CommittedResultV1,
        inner: CommittedMutationResultV1,
        kind_payload: &'a [u8],
    },
}

impl core::fmt::Debug for ValidatedCommittedResultV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Open { .. } => "ValidatedCommittedResultV1::Open",
            Self::Write { .. } => "ValidatedCommittedResultV1::Write",
            Self::Mutation { .. } => "ValidatedCommittedResultV1::Mutation",
        })
    }
}

fn committed_context_total(
    context: &RetainedCommittedContextV21<'_>,
) -> Result<u32, MessageValidationError> {
    let pairing_ok = match context.opcode {
        op::MUTATE => {
            context.write_request_length == 0
                && matches!(
                    context.mutation_body,
                    Some(body) if mutation_kind_of_body_v21(body) == context.mutation_kind
                )
        }
        op::WRITE => {
            context.mutation_kind == 0
                && context.mutation_body.is_none()
                && context.write_request_length != 0
        }
        op::COMMIT_OPEN => {
            context.mutation_kind == 0
                && context.mutation_body.is_none()
                && context.write_request_length == 0
        }
        _ => false,
    };
    if !pairing_ok {
        return Err(MessageValidationError::Relationship);
    }
    committed_result_total_size_v21(context.opcode, context.mutation_kind)
        .ok_or(MessageValidationError::Relationship)
}

fn decode_committed<T: crate::codec::Pod>(
    bytes: &[u8],
    start: usize,
    length: usize,
) -> Result<T, MessageValidationError> {
    let end = start
        .checked_add(length)
        .ok_or(MessageValidationError::InvalidScalar)?;
    let window = bytes
        .get(start..end)
        .ok_or(MessageValidationError::InvalidScalar)?;
    try_decode(window).map_err(|_| MessageValidationError::InvalidScalar)
}

fn validate_committed_prefix_header(
    header: ControlHeader,
    expected_size: u32,
) -> Result<(), MessageValidationError> {
    if header.struct_version != CONTROL_VERSION_V1 {
        return Err(MessageValidationError::Control(
            ControlError::RevisionMismatch,
        ));
    }
    if header.required_flags != 0 {
        return Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags,
        ));
    }
    if header.struct_size != expected_size {
        return Err(MessageValidationError::Control(ControlError::InvalidSize));
    }
    Ok(())
}

const fn expected_committed_result_kind(opcode: u16) -> u16 {
    match opcode {
        op::COMMIT_OPEN => committed_result_kind::COMMIT_OPEN,
        op::WRITE => committed_result_kind::WRITE,
        _ => committed_result_kind::MUTATION,
    }
}

/// Validate one complete durable committed-result blob against the retained
/// operation per section 12. The caller owns `bytes` as a private snapshot.
pub fn validate_committed_result_v1<'a>(
    bytes: &'a [u8],
    context: &RetainedCommittedContextV21<'_>,
) -> Result<ValidatedCommittedResultV1<'a>, MessageValidationError> {
    let total = committed_context_total(context)?;
    if bytes.len() != total as usize {
        return Err(MessageValidationError::InvalidScalar);
    }

    let outer: CommittedResultV1 =
        decode_committed(bytes, 0, COMMITTED_RESULT_V1_PREFIX_BYTES as usize)?;
    validate_committed_prefix_header(outer.header, total)?;
    if outer.opcode != context.opcode {
        return Err(MessageValidationError::Identity);
    }
    if outer.result_kind != expected_committed_result_kind(context.opcode) {
        return Err(MessageValidationError::InvalidScalar);
    }
    if outer.volume_commit_sequence == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if outer.payload.offset != COMMITTED_RESULT_V1_PREFIX_BYTES
        || outer.payload.length != total - COMMITTED_RESULT_V1_PREFIX_BYTES
    {
        return Err(MessageValidationError::Relationship);
    }
    if outer.status != completion_status::SUCCESS {
        return Err(MessageValidationError::Completion);
    }
    let information_ok = if context.opcode == op::WRITE {
        outer.information != 0 && outer.information <= u64::from(context.write_request_length)
    } else {
        outer.information == 0
    };
    if !information_ok {
        return Err(MessageValidationError::Completion);
    }

    match context.opcode {
        op::COMMIT_OPEN => {
            let inner: CommittedOpenResultV1 = decode_committed(bytes, 40, 96)?;
            validate_committed_prefix_header(inner.header, 96)?;
            if inner.flags != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if !pair_nonzero(inner.file_id.lo, inner.file_id.hi)
                || !pair_nonzero(inner.link_id.lo, inner.link_id.hi)
                || inner.namespace_generation == 0
                || inner.security_generation == 0
            {
                return Err(MessageValidationError::Identity);
            }
            if inner.create_result > create_result::OVERWRITTEN {
                return Err(MessageValidationError::InvalidScalar);
            }
            validate_size_state_v21(inner.sizes)?;
            Ok(ValidatedCommittedResultV1::Open { outer, inner })
        }
        op::WRITE => {
            let inner: CommittedWriteResultV1 = decode_committed(bytes, 40, 40)?;
            validate_committed_prefix_header(inner.header, 40)?;
            validate_size_state_v21(inner.sizes)?;
            Ok(ValidatedCommittedResultV1::Write { outer, inner })
        }
        _ => {
            let inner: CommittedMutationResultV1 = decode_committed(
                bytes,
                40,
                COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES as usize,
            )?;
            let tail_length = total - 112;
            validate_committed_prefix_header(
                inner.header,
                COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES + tail_length,
            )?;
            if inner.mutation_kind != context.mutation_kind {
                return Err(MessageValidationError::Identity);
            }
            if inner.flags != 0 || inner.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            let requires_namespace = matches!(
                context.mutation_kind,
                mutation_kind::SET_BASIC_INFO
                    | mutation_kind::RENAME
                    | mutation_kind::LINK
                    | mutation_kind::UNLINK
            );
            let requires_security = context.mutation_kind == mutation_kind::SET_SECURITY;
            if (requires_namespace && inner.namespace_generation == 0)
                || (requires_security && inner.security_generation == 0)
            {
                return Err(MessageValidationError::Identity);
            }
            if (!requires_namespace && inner.namespace_generation != 0)
                || (!requires_security && inner.security_generation != 0)
            {
                return Err(MessageValidationError::InvalidScalar);
            }
            validate_size_state_v21(inner.sizes)?;

            let kind_payload = match mutation_kind_result_length_v21(context.mutation_kind) {
                None => {
                    if inner.kind_payload.offset != 0 || inner.kind_payload.length != 0 {
                        return Err(MessageValidationError::Relationship);
                    }
                    bytes.get(total as usize..).unwrap_or(&[])
                }
                Some(record_length) => {
                    if inner.kind_payload.offset != COMMITTED_MUTATION_RESULT_V1_PREFIX_BYTES
                        || inner.kind_payload.length != record_length
                    {
                        return Err(MessageValidationError::Relationship);
                    }
                    let record_bytes = bytes
                        .get(112..total as usize)
                        .ok_or(MessageValidationError::InvalidScalar)?;
                    match context.mutation_body {
                        Some(MutationBodyRefV21::Rename(body)) => {
                            let record: RenameResultV2 = decode_committed(bytes, 112, 112)?;
                            validate_rename_result_record(
                                body,
                                &record,
                                context.same_parent_rename,
                                inner.namespace_generation,
                            )?;
                        }
                        Some(MutationBodyRefV21::Link(body)) => {
                            let record: LinkResultV2 = decode_committed(bytes, 112, 104)?;
                            validate_link_result_record(body, &record, inner.namespace_generation)?;
                        }
                        Some(MutationBodyRefV21::Unlink(body)) => {
                            let record: UnlinkResultV1 = decode_committed(bytes, 112, 56)?;
                            validate_unlink_result_record(body, &record)?;
                        }
                        _ => return Err(MessageValidationError::Relationship),
                    }
                    record_bytes
                }
            };
            Ok(ValidatedCommittedResultV1::Mutation {
                outer,
                inner,
                kind_payload,
            })
        }
    }
}

const fn size_state_fields_equal(left: SizeState, right: SizeState) -> bool {
    left.allocation_size == right.allocation_size
        && left.file_size == right.file_size
        && left.valid_data_length == right.valid_data_length
        && left.size_epoch == right.size_epoch
}

/// Candidate-to-durable equality for COMMIT_OPEN, excluding only the
/// session-local `provider_open_cookie`.
pub fn compare_committed_open_v21(
    durable: &ValidatedCommittedResultV1<'_>,
    candidate: &CommitOpenResultV2,
) -> Result<(), MessageValidationError> {
    let (outer, inner) = match durable {
        ValidatedCommittedResultV1::Open { outer, inner } => (outer, inner),
        _ => return Err(MessageValidationError::Relationship),
    };
    if outer.volume_commit_sequence != candidate.volume_commit_sequence
        || inner.file_id != candidate.file_id
        || inner.link_id != candidate.link_id
        || !size_state_fields_equal(inner.sizes, candidate.sizes)
        || inner.namespace_generation != candidate.namespace_generation
        || inner.security_generation != candidate.security_generation
        || inner.create_result != candidate.create_result
        || inner.flags != candidate.result_flags
    {
        return Err(MessageValidationError::Relationship);
    }
    Ok(())
}

/// Candidate-to-durable equality for WRITE: volume sequence, CQ
/// information, and the complete SizeState.
pub fn compare_committed_write_v21(
    durable: &ValidatedCommittedResultV1<'_>,
    candidate: &WriteResultV2,
    cq_information: u64,
) -> Result<(), MessageValidationError> {
    let (outer, inner) = match durable {
        ValidatedCommittedResultV1::Write { outer, inner } => (outer, inner),
        _ => return Err(MessageValidationError::Relationship),
    };
    if outer.volume_commit_sequence != candidate.volume_commit_sequence
        || outer.information != cq_information
        || !size_state_fields_equal(inner.sizes, candidate.sizes)
    {
        return Err(MessageValidationError::Relationship);
    }
    Ok(())
}

/// Candidate-to-durable equality for MUTATE, including byte-exact inline
/// kind-payload comparison against the validated candidate kind result.
pub fn compare_committed_mutation_v21(
    durable: &ValidatedCommittedResultV1<'_>,
    candidate: &MutationResultV2,
    candidate_kind_blob: &[u8],
) -> Result<(), MessageValidationError> {
    let (outer, inner, kind_payload) = match durable {
        ValidatedCommittedResultV1::Mutation {
            outer,
            inner,
            kind_payload,
        } => (outer, inner, *kind_payload),
        _ => return Err(MessageValidationError::Relationship),
    };
    if outer.volume_commit_sequence != candidate.volume_commit_sequence
        || inner.mutation_kind != candidate.mutation_kind
        || inner.flags != candidate.result_flags
        || !size_state_fields_equal(inner.sizes, candidate.sizes)
        || inner.namespace_generation != candidate.namespace_generation
        || inner.security_generation != candidate.security_generation
        || kind_payload != candidate_kind_blob
    {
        return Err(MessageValidationError::Relationship);
    }
    Ok(())
}

/// One validated QueryOp answer: the reported durable state plus the
/// committed-result echo when the state is COMMITTED.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedQueryOpAnswerV21 {
    state: u16,
    committed_result: Option<ValidatedBuffer>,
}

impl ValidatedQueryOpAnswerV21 {
    pub const fn state(&self) -> u16 {
        self.state
    }

    pub const fn committed_result(&self) -> Option<ValidatedBuffer> {
        self.committed_result
    }
}

/// Section 12 QueryOp wire-shape rules: zero flags/reserved, exact OpId
/// echo, NONE result for NOT_FOUND/PREPARED, and the committed grant echo
/// shrunk to the exact derived size for COMMITTED. PREPARED is illegal in
/// abort mode.
pub fn validate_query_op_result_v1(
    result: &QueryOpResultV1,
    request: &QueryOpV2,
    committed_grant: GrantBindingV21<'_>,
    derived_size: u32,
    abort_mode: bool,
) -> Result<ValidatedQueryOpAnswerV21, MessageValidationError> {
    validate_header(
        result.header,
        CONTROL_VERSION_V1,
        size_of::<QueryOpResultV1>(),
    )?;
    if result.flags != 0 || result.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if result.op_id.lo != request.op_id.lo || result.op_id.hi != request.op_id.hi {
        return Err(MessageValidationError::Identity);
    }
    match result.state {
        query_op_state::NOT_FOUND | query_op_state::PREPARED => {
            if result.state == query_op_state::PREPARED && abort_mode {
                return Err(MessageValidationError::Completion);
            }
            validate_buffer_ref(&result.result, &BufferRefRule::None)
                .map_err(MessageValidationError::Grant)?;
            Ok(ValidatedQueryOpAnswerV21 {
                state: result.state,
                committed_result: None,
            })
        }
        query_op_state::COMMITTED => {
            let value = validate_shrunk_echo(&result.result, committed_grant)?;
            if result.result.length != derived_size {
                return Err(MessageValidationError::Completion);
            }
            Ok(ValidatedQueryOpAnswerV21 {
                state: result.state,
                committed_result: Some(value),
            })
        }
        _ => Err(MessageValidationError::InvalidScalar),
    }
}

/// Retained journaled-operation phases; the QueryOp table below is keyed by
/// this phase and the validated durable answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedOpPhaseV21 {
    NoCandidate,
    FailureCandidate,
    SuccessCandidate,
    InvalidCandidate,
    CommittedVerified,
    AppliedNotifyPending,
    AppliedAckUnsent,
    AppliedAckSent,
    Acknowledged,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryOpAnswerContextV21 {
    pub exactly_once_selected: bool,
    pub cancel_requested: bool,
    pub abort_mode: bool,
    pub is_commit_open: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOpTableActionV21 {
    CompleteCancelled,
    EnterAbortOpenSubprotocol,
    ResubmitSameOperation,
    IssueAbortIfPrepared,
    ResumeTransaction,
    ValidateDurableThenCommittedVerified,
    CompleteSavedFailure,
    AbortOpenThenSavedFailure,
    DurableWinsRecordViolation,
    RequireExactCandidateEquality,
    IgnoreCandidateValidateDurable,
    ApplyOnce,
    DeliverOrCoverNotification,
    PrepareAndPublishAck,
    RetryIdenticalAck,
    InferAcknowledged,
    NoQueryOpEmitted,
    AdministrativeTeardownOnly,
    Indeterminate,
    ExactlyOnceProtocolFault,
    AbortModePreparedFault,
}

/// One table cell: either a fixed action or one of the three
/// context-conditional cells of section 12.
#[derive(Clone, Copy)]
enum QueryOpCellV21 {
    Fixed(QueryOpTableActionV21),
    NoCandidateNotFound,
    NoCandidatePrepared,
    FailureNotFound,
}

/// Rows follow `RetainedOpPhaseV21` order; columns are
/// NOT_FOUND/PREPARED/COMMITTED.
const QUERY_OP_TABLE: [[QueryOpCellV21; 3]; 10] = [
    [
        QueryOpCellV21::NoCandidateNotFound,
        QueryOpCellV21::NoCandidatePrepared,
        QueryOpCellV21::Fixed(QueryOpTableActionV21::ValidateDurableThenCommittedVerified),
    ],
    [
        QueryOpCellV21::FailureNotFound,
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::DurableWinsRecordViolation),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::RequireExactCandidateEquality),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::IgnoreCandidateValidateDurable),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::ApplyOnce),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::DeliverOrCoverNotification),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::PrepareAndPublishAck),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::InferAcknowledged),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::Indeterminate),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::RetryIdenticalAck),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::NoQueryOpEmitted),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::NoQueryOpEmitted),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::NoQueryOpEmitted),
    ],
    [
        QueryOpCellV21::Fixed(QueryOpTableActionV21::AdministrativeTeardownOnly),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::AdministrativeTeardownOnly),
        QueryOpCellV21::Fixed(QueryOpTableActionV21::AdministrativeTeardownOnly),
    ],
];

/// The total section 12 retained-phase table. QueryOp phases exist only
/// with EXACTLY_ONCE; abort mode accepts only the atomic NOT_FOUND or
/// COMMITTED outcome.
pub const fn query_op_table_action_v21(
    phase: RetainedOpPhaseV21,
    answer_state: u16,
    context: QueryOpAnswerContextV21,
) -> Result<QueryOpTableActionV21, MessageValidationError> {
    let column = match answer_state {
        query_op_state::NOT_FOUND => 0,
        query_op_state::PREPARED => 1,
        query_op_state::COMMITTED => 2,
        _ => return Err(MessageValidationError::InvalidScalar),
    };
    if !context.exactly_once_selected {
        return Ok(QueryOpTableActionV21::ExactlyOnceProtocolFault);
    }
    if context.abort_mode {
        return Ok(match column {
            1 => QueryOpTableActionV21::AbortModePreparedFault,
            0 => QueryOpTableActionV21::CompleteCancelled,
            _ => QueryOpTableActionV21::ValidateDurableThenCommittedVerified,
        });
    }
    Ok(match QUERY_OP_TABLE[phase as usize][column] {
        QueryOpCellV21::Fixed(action) => action,
        QueryOpCellV21::NoCandidateNotFound => {
            if context.cancel_requested {
                if context.is_commit_open {
                    QueryOpTableActionV21::EnterAbortOpenSubprotocol
                } else {
                    QueryOpTableActionV21::CompleteCancelled
                }
            } else {
                QueryOpTableActionV21::ResubmitSameOperation
            }
        }
        QueryOpCellV21::NoCandidatePrepared => {
            if context.cancel_requested {
                QueryOpTableActionV21::IssueAbortIfPrepared
            } else {
                QueryOpTableActionV21::ResumeTransaction
            }
        }
        QueryOpCellV21::FailureNotFound => {
            if context.is_commit_open {
                QueryOpTableActionV21::AbortOpenThenSavedFailure
            } else {
                QueryOpTableActionV21::CompleteSavedFailure
            }
        }
    })
}

/// One retained recovery grant considered for a BUFFER_TOO_SMALL retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryOpBtsContextV21 {
    pub opcode: u16,
    pub mutation_kind: u16,
    pub current_capacity: u32,
    pub prior_bts_retries: u32,
    pub ordinary_confirmation: bool,
}

/// The bounded BTS retry rule: at most one retry, never against the
/// ordinary 224-byte confirmation grant, and only for the exact derived
/// size strictly above the current capacity. Returns the single legal new
/// capacity.
pub const fn validate_query_op_bts_retry_v21(
    context: &QueryOpBtsContextV21,
    information: u64,
) -> Result<u32, MessageValidationError> {
    if context.ordinary_confirmation {
        return Err(MessageValidationError::Completion);
    }
    if context.prior_bts_retries >= MAX_QUERY_OP_BTS_RETRIES {
        return Err(MessageValidationError::Completion);
    }
    let derived = match committed_result_total_size_v21(context.opcode, context.mutation_kind) {
        Some(value) => value,
        None => return Err(MessageValidationError::Relationship),
    };
    if information != derived as u64 {
        return Err(MessageValidationError::Completion);
    }
    if derived <= context.current_capacity {
        return Err(MessageValidationError::Completion);
    }
    Ok(derived)
}

/// ACK pruning authentication: the published `AckResultV2` must carry the
/// retained OpId and operation digest exactly; the digest comparison is
/// constant-time and an all-zero retained digest is never a valid binding.
pub fn validate_ack_result_binding_v21(
    request: &AckResultV2,
    retained_op_id: OpId,
    retained_digest: &[u8; 32],
) -> Result<(), MessageValidationError> {
    validate_ack_result_v2(request)?;
    let mut aggregate = 0u8;
    let mut index = 0usize;
    while index < retained_digest.len() {
        aggregate |= retained_digest[index];
        index += 1;
    }
    if aggregate == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if request.op_id != retained_op_id {
        return Err(MessageValidationError::Identity);
    }
    if !operation_digest_eq(&request.operation_digest, retained_digest) {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

/// What the provider finds for `(OpId, operation_digest)` while handling
/// ACK_RESULT, observed atomically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckBundleObservationV21 {
    CommittedExact,
    Absent,
    PreparedPresent,
    PartialBundle,
    DigestMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckPruningActionV21 {
    DeleteAndSucceed,
    IdempotentSuccess,
    Corruption,
}

/// ACK_RESULT is idempotent only when the complete bundle and all of its
/// reservations are absent; a partial bundle or any present row with the
/// same OpId and a different digest is corruption.
pub const fn classify_ack_pruning_v21(observation: AckBundleObservationV21) -> AckPruningActionV21 {
    match observation {
        AckBundleObservationV21::CommittedExact => AckPruningActionV21::DeleteAndSucceed,
        AckBundleObservationV21::Absent => AckPruningActionV21::IdempotentSuccess,
        AckBundleObservationV21::PreparedPresent
        | AckBundleObservationV21::PartialBundle
        | AckBundleObservationV21::DigestMismatch => AckPruningActionV21::Corruption,
    }
}

/// One worst-case prepublication ApplyReserve row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyDomainCountsV21 {
    pub file: u8,
    pub directory_namespace: u8,
    pub link: u8,
    pub open: u8,
}

impl ApplyDomainCountsV21 {
    pub const fn total(&self) -> u32 {
        self.file as u32 + self.directory_namespace as u32 + self.link as u32 + self.open as u32
    }
}

const fn domain_counts(
    file: u8,
    directory_namespace: u8,
    link: u8,
    open: u8,
) -> ApplyDomainCountsV21 {
    ApplyDomainCountsV21 {
        file,
        directory_namespace,
        link,
        open,
    }
}

/// The closed section 12 worst-case apply-domain table. `with_replacement`
/// is meaningful only for RENAME and LINK; every other row demands `false`,
/// and unselectable kinds or foreign opcodes have no row.
pub const fn apply_domain_reservation_v21(
    opcode: u16,
    mutation_kind_value: u16,
    with_replacement: bool,
) -> Option<ApplyDomainCountsV21> {
    match (opcode, mutation_kind_value) {
        (op::COMMIT_OPEN, 0) if !with_replacement => Some(domain_counts(1, 1, 1, 1)),
        (op::WRITE, 0) if !with_replacement => Some(domain_counts(1, 0, 0, 0)),
        (op::MUTATE, mutation_kind::SET_BASIC_INFO) if !with_replacement => {
            Some(domain_counts(1, 0, 0, 1))
        }
        (
            op::MUTATE,
            mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH
            | mutation_kind::SET_SECURITY,
        ) if !with_replacement => Some(domain_counts(1, 0, 0, 0)),
        (op::MUTATE, mutation_kind::RENAME) => Some(if with_replacement {
            domain_counts(2, 2, 2, 0)
        } else {
            domain_counts(1, 2, 1, 0)
        }),
        (op::MUTATE, mutation_kind::LINK) => Some(if with_replacement {
            domain_counts(2, 1, 2, 0)
        } else {
            domain_counts(1, 1, 1, 0)
        }),
        (op::MUTATE, mutation_kind::UNLINK) if !with_replacement => Some(domain_counts(1, 1, 1, 0)),
        _ => None,
    }
}

// RENAME with replacement is the exact worst case and saturates the bound.
const _: () = {
    assert!(domain_counts(2, 2, 2, 0).total() == MAX_APPLY_DOMAINS_PER_OPERATION);
};

/// One entry of the deduplicated canonical lock vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyLockEntryV21 {
    pub file_id: FileId,
    pub domain_kind: u16,
    pub link_id: LinkId,
}

/// Strict canonical lock order:
/// `(FileId.hi, FileId.lo, domain_kind, LinkId.hi, LinkId.lo)`.
pub const fn apply_lock_order_less_v21(
    left: &ApplyLockEntryV21,
    right: &ApplyLockEntryV21,
) -> bool {
    if left.file_id.hi != right.file_id.hi {
        return left.file_id.hi < right.file_id.hi;
    }
    if left.file_id.lo != right.file_id.lo {
        return left.file_id.lo < right.file_id.lo;
    }
    if left.domain_kind != right.domain_kind {
        return left.domain_kind < right.domain_kind;
    }
    if left.link_id.hi != right.link_id.hi {
        return left.link_id.hi < right.link_id.hi;
    }
    left.link_id.lo < right.link_id.lo
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceMergeV21 {
    Fresh,
    ExactRepeat,
    StaleSuppressed,
}

/// Volume-commit-sequence merge classification: sequences are nonzero and
/// non-wrapping; a greater value is fresh, a smaller one is suppressed as
/// stale, and an equal value is legal only as an exact same-provenance
/// repeat.
pub const fn classify_volume_sequence_merge_v21(
    retained: u64,
    incoming: u64,
    same_provenance: bool,
) -> Result<SequenceMergeV21, MessageValidationError> {
    if incoming == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if retained == 0 || incoming > retained {
        return Ok(SequenceMergeV21::Fresh);
    }
    if incoming == retained {
        return if same_provenance {
            Ok(SequenceMergeV21::ExactRepeat)
        } else {
            Err(MessageValidationError::Relationship)
        };
    }
    Ok(SequenceMergeV21::StaleSuppressed)
}

/// The next request-table generation for the same slot index. Generation
/// exhaustion retires the slot/session rather than wrapping.
pub const fn next_req_generation_v21(current: u64) -> Result<u64, MessageValidationError> {
    if current >= REQ_GENERATION_MAX {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(current + 1)
}

// ---- Wave 9 notification envelope, body, and acknowledgement validators -----

/// Decoded mount-scoped `AckToken` lane coordinates (section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckTokenPartsV21 {
    pub kind_ordinal: u16,
    pub ring_index: u32,
    pub ordinal: u64,
}

const fn ack_token_hi(kind_ordinal: u16, ring_index: u32) -> u64 {
    ACK_TOKEN_HI_TAG | ((kind_ordinal as u64) << 8) | (ring_index as u64)
}

/// The ring-zero external DIR_CHANGE token whose ordinal is the first ordinal.
pub const fn external_dir_change_ack_token(first_ordinal: u64) -> AckToken {
    AckToken {
        lo: first_ordinal,
        hi: ack_token_hi(notify_ack_kind::DIR_CHANGE, 0),
    }
}

/// A PT acknowledgement token; `None` unless the kind is a PT lane, the ring is
/// in range, and the ordinal is nonzero.
pub const fn pt_ack_token(kind_ordinal: u16, ring_index: u32, ordinal: u64) -> Option<AckToken> {
    if kind_ordinal != notify_ack_kind::PT_REVOKE_ROUTE
        && kind_ordinal != notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE
    {
        return None;
    }
    if ring_index >= MAX_RING_COUNT || ordinal == 0 {
        return None;
    }
    Some(AckToken {
        lo: ordinal,
        hi: ack_token_hi(kind_ordinal, ring_index),
    })
}

/// Decode and validate a mount-scoped `AckToken` under the closed lane rules.
pub const fn decode_ack_token(token: AckToken) -> Result<AckTokenPartsV21, MessageValidationError> {
    if token.hi & ACK_TOKEN_HI_MASK != ACK_TOKEN_HI_TAG {
        return Err(MessageValidationError::Identity);
    }
    let low = token.hi & !ACK_TOKEN_HI_MASK;
    let kind_ordinal = ((low >> 8) & 0xff) as u16;
    let ring_byte = (low & 0xff) as u32;
    if ring_byte & 0xc0 != 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let ring_index = ring_byte & 0x3f;
    match kind_ordinal {
        notify_ack_kind::PT_REVOKE_ROUTE | notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE => {}
        notify_ack_kind::DIR_CHANGE => {
            if ring_index != 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
        }
        _ => return Err(MessageValidationError::InvalidScalar),
    }
    if token.lo == 0 {
        return Err(MessageValidationError::Identity);
    }
    Ok(AckTokenPartsV21 {
        kind_ordinal,
        ring_index,
        ordinal: token.lo,
    })
}

/// The external-change record ordinal interval class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalOrdinalIntervalV21 {
    Precise,
    Overflow,
}

/// A precise record spans one nonzero ordinal; an overflow spans a nonzero,
/// non-decreasing range.
pub const fn classify_external_ordinal_interval_v21(
    first: u64,
    through: u64,
    is_overflow: bool,
) -> Result<ExternalOrdinalIntervalV21, MessageValidationError> {
    if first == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    if is_overflow {
        if first > through {
            return Err(MessageValidationError::Relationship);
        }
        Ok(ExternalOrdinalIntervalV21::Overflow)
    } else {
        if first != through {
            return Err(MessageValidationError::Relationship);
        }
        Ok(ExternalOrdinalIntervalV21::Precise)
    }
}

/// The retained canonical external-change event tuple the kernel keeps until
/// mount retirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedExternalTupleV21 {
    pub first_ordinal: u64,
    pub through_ordinal: u64,
    pub volume_commit_sequence: u64,
    pub semantic_digest: [u8; 32],
}

/// A validated notification body borrowed from the envelope bytes.
#[derive(Clone, Copy)]
pub enum ValidatedNotifyBodyV2<'a> {
    InvalidateFile(InvalidateFileV1),
    InvalidateEntry {
        body: InvalidateEntryV1,
        name: &'a [u8],
    },
    PtGrant(PtGrantV1),
    PtRevokeRoute(PtEpochV1),
    PtExternalMutationSafe(PtEpochV1),
    Resize(ResizeV1),
    ExternalDirChange {
        body: ExternalDirChangeV1,
        interval: ExternalOrdinalIntervalV21,
        old_name: &'a [u8],
        new_name: &'a [u8],
    },
    PtLaneReady(PtLaneReadyV1),
    ExternalChangeReady(ExternalChangeReadyV1),
    ExternalChangeCut(ExternalChangeCutV1),
}

/// A fully validated `NotifyEnvelopeV2` and its dispatched body.
pub struct ValidatedNotifyEnvelopeV2<'a> {
    pub envelope: NotifyEnvelopeV2,
    pub body: ValidatedNotifyBodyV2<'a>,
}

fn require_zero_token(envelope: &NotifyEnvelopeV2) -> Result<(), MessageValidationError> {
    if envelope.token != AckToken::ZERO {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

fn require_zero_file_id(envelope: &NotifyEnvelopeV2) -> Result<(), MessageValidationError> {
    if pair_nonzero(envelope.file_id.lo, envelope.file_id.hi) {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

fn decode_fixed_body<T: crate::codec::Pod>(body: &[u8]) -> Result<T, MessageValidationError> {
    if body.len() != size_of::<T>() {
        return Err(MessageValidationError::IllegalWireForm);
    }
    try_decode(body).map_err(|_| MessageValidationError::IllegalWireForm)
}

fn decode_prefix_body<T: crate::codec::Pod>(
    body: &[u8],
    prefix: usize,
) -> Result<T, MessageValidationError> {
    let head = body
        .get(..prefix)
        .ok_or(MessageValidationError::IllegalWireForm)?;
    try_decode(head).map_err(|_| MessageValidationError::IllegalWireForm)
}

/// Cursor over minimally packed body-relative stored-component name slices.
struct NameCursor<'a> {
    body: &'a [u8],
    next: u32,
}

impl<'a> NameCursor<'a> {
    fn new(body: &'a [u8], prefix: u32) -> Self {
        Self { body, next: prefix }
    }

    fn take(
        &mut self,
        slice: BlobSlice,
        required: bool,
    ) -> Result<&'a [u8], MessageValidationError> {
        if slice.offset == 0 && slice.length == 0 {
            if required {
                return Err(MessageValidationError::InvalidScalar);
            }
            let at =
                usize::try_from(self.next).map_err(|_| MessageValidationError::IllegalWireForm)?;
            return self
                .body
                .get(at..at)
                .ok_or(MessageValidationError::IllegalWireForm);
        }
        if slice.offset != self.next {
            return Err(MessageValidationError::Relationship);
        }
        let end = slice
            .offset
            .checked_add(slice.length)
            .ok_or(MessageValidationError::IllegalWireForm)?;
        let start =
            usize::try_from(slice.offset).map_err(|_| MessageValidationError::IllegalWireForm)?;
        let end_usize =
            usize::try_from(end).map_err(|_| MessageValidationError::IllegalWireForm)?;
        let bytes = self
            .body
            .get(start..end_usize)
            .ok_or(MessageValidationError::IllegalWireForm)?;
        validate_stored_component_utf16(bytes)?;
        self.next = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), MessageValidationError> {
        let aligned = self
            .next
            .checked_add(7)
            .map(|end| end & !7)
            .ok_or(MessageValidationError::IllegalWireForm)?;
        let aligned_usize =
            usize::try_from(aligned).map_err(|_| MessageValidationError::IllegalWireForm)?;
        if aligned_usize != self.body.len() {
            return Err(MessageValidationError::Relationship);
        }
        let end =
            usize::try_from(self.next).map_err(|_| MessageValidationError::IllegalWireForm)?;
        if self
            .body
            .get(end..aligned_usize)
            .ok_or(MessageValidationError::IllegalWireForm)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(MessageValidationError::InvalidScalar);
        }
        Ok(())
    }
}

fn nonzero_or(pair_lo: u64, pair_hi: u64, present: bool) -> Result<(), MessageValidationError> {
    if pair_nonzero(pair_lo, pair_hi) != present {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

fn validate_external_dir_change<'a>(
    envelope: &NotifyEnvelopeV2,
    body: &'a [u8],
) -> Result<ValidatedNotifyBodyV2<'a>, MessageValidationError> {
    let prefix = size_of::<ExternalDirChangeV1>();
    let record: ExternalDirChangeV1 = decode_prefix_body(body, prefix)?;
    if record.flags != 0 || record.reserved0 != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    let parts = decode_ack_token(envelope.token)?;
    if parts.kind_ordinal != notify_ack_kind::DIR_CHANGE {
        return Err(MessageValidationError::Identity);
    }
    if parts.ordinal != record.first_ordinal {
        return Err(MessageValidationError::Relationship);
    }
    let is_overflow = record.change_kind == external_change_kind::OVERFLOW;
    let interval = classify_external_ordinal_interval_v21(
        record.first_ordinal,
        record.through_ordinal,
        is_overflow,
    )?;
    let mut cursor = NameCursor::new(body, prefix as u32);

    if is_overflow {
        if record.object_kind != 0
            || record.filter_match != 0
            || record.volume_commit_sequence == 0
            || pair_nonzero(envelope.file_id.lo, envelope.file_id.hi)
            || pair_nonzero(record.target_link_id.lo, record.target_link_id.hi)
            || pair_nonzero(record.replaced_file_id.lo, record.replaced_file_id.hi)
            || pair_nonzero(record.replaced_link_id.lo, record.replaced_link_id.hi)
            || pair_nonzero(record.old_parent_id.lo, record.old_parent_id.hi)
            || pair_nonzero(record.new_parent_id.lo, record.new_parent_id.hi)
            || record.old_parent_generation != 0
            || record.new_parent_generation != 0
            || record.target_namespace_generation != 0
            || record.replaced_namespace_generation != 0
            || record.old_name.offset != 0
            || record.old_name.length != 0
            || record.new_name.offset != 0
            || record.new_name.length != 0
        {
            return Err(MessageValidationError::Relationship);
        }
        let old_name = cursor.take(record.old_name, false)?;
        let new_name = cursor.take(record.new_name, false)?;
        cursor.finish()?;
        return Ok(ValidatedNotifyBodyV2::ExternalDirChange {
            body: record,
            interval,
            old_name,
            new_name,
        });
    }

    // Precise: nonzero target identity, volume sequence, and namespace generation.
    if !pair_nonzero(envelope.file_id.lo, envelope.file_id.hi)
        || !pair_nonzero(record.target_link_id.lo, record.target_link_id.hi)
    {
        return Err(MessageValidationError::Identity);
    }
    if record.volume_commit_sequence == 0 || record.target_namespace_generation == 0 {
        return Err(MessageValidationError::InvalidScalar);
    }
    let name_bit = match record.object_kind {
        external_object_kind::FILE => notify_filter::FILE_NAME,
        external_object_kind::DIRECTORY => notify_filter::DIR_NAME,
        _ => return Err(MessageValidationError::InvalidScalar),
    };

    let replacement_any = pair_nonzero(record.replaced_file_id.lo, record.replaced_file_id.hi)
        || pair_nonzero(record.replaced_link_id.lo, record.replaced_link_id.hi)
        || record.replaced_namespace_generation != 0;
    let replacement_all = pair_nonzero(record.replaced_file_id.lo, record.replaced_file_id.hi)
        && pair_nonzero(record.replaced_link_id.lo, record.replaced_link_id.hi)
        && record.replaced_namespace_generation != 0;
    if replacement_any && !replacement_all {
        return Err(MessageValidationError::Relationship);
    }

    let (old_side, new_side, replacement_allowed) = match record.change_kind {
        external_change_kind::ADD => (false, true, true),
        external_change_kind::REMOVE => (true, false, false),
        external_change_kind::MODIFY => (false, true, false),
        external_change_kind::RENAME => (true, true, true),
        _ => return Err(MessageValidationError::InvalidScalar),
    };
    if replacement_any && !replacement_allowed {
        return Err(MessageValidationError::Relationship);
    }
    if record.change_kind == external_change_kind::MODIFY {
        if record.filter_match == 0 || record.filter_match & !EXTERNAL_MODIFY_FILTER_MASK != 0 {
            return Err(MessageValidationError::InvalidScalar);
        }
    } else if record.filter_match != name_bit {
        return Err(MessageValidationError::InvalidScalar);
    }

    nonzero_or(record.old_parent_id.lo, record.old_parent_id.hi, old_side)?;
    nonzero_or(record.new_parent_id.lo, record.new_parent_id.hi, new_side)?;
    if (record.old_parent_generation != 0) != old_side
        || (record.new_parent_generation != 0) != new_side
    {
        return Err(MessageValidationError::InvalidScalar);
    }
    if !old_side && (record.old_name.offset != 0 || record.old_name.length != 0) {
        return Err(MessageValidationError::Relationship);
    }
    if !new_side && (record.new_name.offset != 0 || record.new_name.length != 0) {
        return Err(MessageValidationError::Relationship);
    }

    let old_name = cursor.take(record.old_name, old_side)?;
    let new_name = cursor.take(record.new_name, new_side)?;
    cursor.finish()?;

    if record.change_kind == external_change_kind::RENAME
        && record.old_parent_id == record.new_parent_id
    {
        if record.old_parent_generation != record.new_parent_generation {
            return Err(MessageValidationError::Relationship);
        }
        if old_name == new_name {
            return Err(MessageValidationError::Relationship);
        }
    }

    Ok(ValidatedNotifyBodyV2::ExternalDirChange {
        body: record,
        interval,
        old_name,
        new_name,
    })
}

fn validate_notify_body<'a>(
    envelope: &NotifyEnvelopeV2,
    body: &'a [u8],
) -> Result<ValidatedNotifyBodyV2<'a>, MessageValidationError> {
    match envelope.notify_code {
        notify::INVALIDATE_FILE => {
            require_zero_token(envelope)?;
            let record: InvalidateFileV1 = decode_fixed_body(body)?;
            if record.flags != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            validate_file_range(record.offset, record.length, true)
                .map_err(MessageValidationError::Range)?;
            if record.content_epoch == 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            Ok(ValidatedNotifyBodyV2::InvalidateFile(record))
        }
        notify::INVALIDATE_ENTRY => {
            require_zero_token(envelope)?;
            if !pair_nonzero(envelope.file_id.lo, envelope.file_id.hi) {
                return Err(MessageValidationError::Identity);
            }
            let record: InvalidateEntryV1 =
                decode_prefix_body(body, size_of::<InvalidateEntryV1>())?;
            if record.flags != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if record.namespace_generation == 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            let mut cursor = NameCursor::new(body, size_of::<InvalidateEntryV1>() as u32);
            let name = cursor.take(record.name, true)?;
            cursor.finish()?;
            Ok(ValidatedNotifyBodyV2::InvalidateEntry { body: record, name })
        }
        notify::PT_GRANT => {
            require_zero_token(envelope)?;
            let record: PtGrantV1 = decode_fixed_body(body)?;
            if record.flags != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if record.pt_epoch == 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            if !(MIN_BACKING_SECTOR_SIZE..=MAX_BACKING_SECTOR_SIZE).contains(&record.sector_size)
                || !record.sector_size.is_power_of_two()
            {
                return Err(MessageValidationError::InvalidScalar);
            }
            Ok(ValidatedNotifyBodyV2::PtGrant(record))
        }
        notify::PT_REVOKE_ROUTE | notify::PT_EXTERNAL_MUTATION_SAFE => {
            let expected_kind = if envelope.notify_code == notify::PT_REVOKE_ROUTE {
                notify_ack_kind::PT_REVOKE_ROUTE
            } else {
                notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE
            };
            let parts = decode_ack_token(envelope.token)?;
            if parts.kind_ordinal != expected_kind {
                return Err(MessageValidationError::Identity);
            }
            let record: PtEpochV1 = decode_fixed_body(body)?;
            if record.pt_epoch == 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            if envelope.notify_code == notify::PT_REVOKE_ROUTE {
                Ok(ValidatedNotifyBodyV2::PtRevokeRoute(record))
            } else {
                Ok(ValidatedNotifyBodyV2::PtExternalMutationSafe(record))
            }
        }
        notify::RESIZE => {
            require_zero_token(envelope)?;
            let record: ResizeV1 = decode_fixed_body(body)?;
            validate_size_state_v21(record.sizes)?;
            if record.volume_commit_sequence == 0 {
                return Err(MessageValidationError::InvalidScalar);
            }
            Ok(ValidatedNotifyBodyV2::Resize(record))
        }
        notify::DIR_CHANGE => validate_external_dir_change(envelope, body),
        notify::PT_LANE_READY => {
            require_zero_token(envelope)?;
            require_zero_file_id(envelope)?;
            let record: PtLaneReadyV1 = decode_fixed_body(body)?;
            if record.reserved0 != 0 || record.flags != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            if record.kind_ordinal != notify_ack_kind::PT_REVOKE_ROUTE
                && record.kind_ordinal != notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE
            {
                return Err(MessageValidationError::InvalidScalar);
            }
            Ok(ValidatedNotifyBodyV2::PtLaneReady(record))
        }
        notify::EXTERNAL_CHANGE_READY => {
            require_zero_token(envelope)?;
            require_zero_file_id(envelope)?;
            let record: ExternalChangeReadyV1 = decode_fixed_body(body)?;
            if record.flags != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            Ok(ValidatedNotifyBodyV2::ExternalChangeReady(record))
        }
        notify::EXTERNAL_CHANGE_CUT => {
            require_zero_token(envelope)?;
            require_zero_file_id(envelope)?;
            let record: ExternalChangeCutV1 = decode_fixed_body(body)?;
            if record.flags != 0 || record.reserved != 0 {
                return Err(MessageValidationError::FlagsOrReserved);
            }
            Ok(ValidatedNotifyBodyV2::ExternalChangeCut(record))
        }
        _ => Err(MessageValidationError::IllegalWireForm),
    }
}

/// Validate a `NotifyEnvelopeV2` and its inline body against section 14.2.
pub fn validate_notify_envelope_v2(
    bytes: &[u8],
) -> Result<ValidatedNotifyEnvelopeV2<'_>, MessageValidationError> {
    let env_size = size_of::<NotifyEnvelopeV2>();
    let head = bytes
        .get(..env_size)
        .ok_or(MessageValidationError::IllegalWireForm)?;
    let envelope: NotifyEnvelopeV2 =
        try_decode(head).map_err(|_| MessageValidationError::IllegalWireForm)?;
    if envelope.header.struct_version != CONTROL_VERSION_V2 {
        return Err(MessageValidationError::Control(
            ControlError::RevisionMismatch,
        ));
    }
    if envelope.header.required_flags != 0 {
        return Err(MessageValidationError::Control(
            ControlError::UnsupportedRequiredFlags,
        ));
    }
    if envelope.notify_flags != 0 || envelope.reserved != 0 {
        return Err(MessageValidationError::FlagsOrReserved);
    }
    if envelope.body.offset != env_size as u32 {
        return Err(MessageValidationError::Control(ControlError::InvalidRange));
    }
    let total = (env_size as u32)
        .checked_add(envelope.body.length)
        .ok_or(MessageValidationError::Control(ControlError::InvalidRange))?;
    if envelope.header.struct_size != total || total % 8 != 0 {
        return Err(MessageValidationError::Control(ControlError::InvalidSize));
    }
    let total_usize =
        usize::try_from(total).map_err(|_| MessageValidationError::IllegalWireForm)?;
    if bytes.len() != total_usize {
        return Err(MessageValidationError::IllegalWireForm);
    }
    let body = bytes
        .get(env_size..total_usize)
        .ok_or(MessageValidationError::IllegalWireForm)?;
    // Every body carries a version-1 ControlHeader whose struct_size covers it.
    let body_header: ControlHeader = try_decode(
        body.get(..size_of::<ControlHeader>())
            .ok_or(MessageValidationError::IllegalWireForm)?,
    )
    .map_err(|_| MessageValidationError::IllegalWireForm)?;
    validate_header(body_header, CONTROL_VERSION_V1, body.len())?;
    let validated = validate_notify_body(&envelope, body)?;
    Ok(ValidatedNotifyEnvelopeV2 {
        envelope,
        body: validated,
    })
}

/// Validate a `DIR_CHANGE_ACK` inline payload against the retained tuple.
pub fn validate_pdir_change_ack_v1(
    payload: &[u8],
    retained: &RetainedExternalTupleV21,
) -> Result<(), MessageValidationError> {
    if payload.len() != size_of::<PDirChangeAckV1>() {
        return Err(MessageValidationError::IllegalWireForm);
    }
    let ack: PDirChangeAckV1 =
        try_decode(payload).map_err(|_| MessageValidationError::IllegalWireForm)?;
    let parts = decode_ack_token(ack.token)?;
    if parts.kind_ordinal != notify_ack_kind::DIR_CHANGE {
        return Err(MessageValidationError::Identity);
    }
    if parts.ordinal != retained.first_ordinal {
        return Err(MessageValidationError::Identity);
    }
    if ack.through_ordinal != retained.through_ordinal
        || ack.volume_commit_sequence != retained.volume_commit_sequence
    {
        return Err(MessageValidationError::Relationship);
    }
    if !operation_digest_eq(&ack.semantic_digest, &retained.semantic_digest) {
        return Err(MessageValidationError::Identity);
    }
    Ok(())
}

// ---- Wave 9 PT-lane acknowledgement machine --------------------------------

/// The bounded per-lane `{latest_processed?, pending?}` acknowledgement state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtLaneStateV21 {
    pub high_watermark: u64,
    pub pending_ordinal: Option<u64>,
    pub processed_ordinal: Option<u64>,
}

/// The action a PT acknowledgement provokes on its lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtLaneAckActionV21 {
    Apply,
    IdempotentSuccess,
    ProtocolFault,
}

/// Classify an incoming PT acknowledgement ordinal against the lane state.
pub fn classify_pt_ack_v21(state: &PtLaneStateV21, incoming_ordinal: u64) -> PtLaneAckActionV21 {
    if state.pending_ordinal == Some(incoming_ordinal) {
        return PtLaneAckActionV21::Apply;
    }
    if state.processed_ordinal == Some(incoming_ordinal) {
        return PtLaneAckActionV21::IdempotentSuccess;
    }
    PtLaneAckActionV21::ProtocolFault
}

/// The next PT lane ordinal is exactly the retained high-watermark plus one;
/// exhaustion retires the lane rather than wrapping.
pub const fn next_pt_lane_ordinal_v21(high_watermark: u64) -> Result<u64, MessageValidationError> {
    if high_watermark == u64::MAX {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(high_watermark + 1)
}

/// One outstanding acknowledgement-required notification per lane: a second
/// distinct notification while PENDING, or a non-successor ordinal, is illegal.
pub fn pt_lane_can_publish_v21(
    state: &PtLaneStateV21,
    new_ordinal: u64,
) -> Result<(), MessageValidationError> {
    if state.pending_ordinal.is_some() {
        return Err(MessageValidationError::Relationship);
    }
    if new_ordinal != next_pt_lane_ordinal_v21(state.high_watermark)? {
        return Err(MessageValidationError::Relationship);
    }
    Ok(())
}

/// Validate a `PNotifyAck` (24/8) against its lane kind, ring, and PT epoch.
pub fn validate_pnotify_ack_v21(
    payload: &[u8],
    expected_kind: u16,
    ring_index: u32,
    pt_epoch: u64,
) -> Result<AckTokenPartsV21, MessageValidationError> {
    if payload.len() != size_of::<PNotifyAck>() {
        return Err(MessageValidationError::IllegalWireForm);
    }
    if expected_kind != notify_ack_kind::PT_REVOKE_ROUTE
        && expected_kind != notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE
    {
        return Err(MessageValidationError::Identity);
    }
    let ack: PNotifyAck =
        try_decode(payload).map_err(|_| MessageValidationError::IllegalWireForm)?;
    let parts = decode_ack_token(ack.token)?;
    if parts.kind_ordinal != expected_kind || parts.ring_index != ring_index {
        return Err(MessageValidationError::Identity);
    }
    if pt_epoch == 0 || ack.epoch != pt_epoch {
        return Err(MessageValidationError::InvalidScalar);
    }
    Ok(parts)
}

// ---- Wave 9 attach reconciliation barriers ---------------------------------

/// The barrier verdict for an attach-time CUT/READY/LANE_READY record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachBarrierV21 {
    Accept,
    IdempotentDuplicate,
    ProtocolFault,
}

/// Retained state for the external-change CUT barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachCutContextV21 {
    pub kernel_high_watermark: u64,
    pub ordinal_counter: u64,
    pub stored_cut: Option<u64>,
    pub progressed: bool,
}

/// Classify an `ExternalChangeCutV1` against the attach reconciliation state.
pub fn classify_external_change_cut_v21(
    cut: &ExternalChangeCutV1,
    ctx: &AttachCutContextV21,
) -> AttachBarrierV21 {
    let value = cut.reconcile_cut;
    if ctx.kernel_high_watermark > value {
        return AttachBarrierV21::ProtocolFault;
    }
    match ctx.stored_cut {
        Some(stored) => {
            if ctx.progressed || stored != value || stored > ctx.ordinal_counter {
                AttachBarrierV21::ProtocolFault
            } else {
                AttachBarrierV21::IdempotentDuplicate
            }
        }
        None => {
            if value != ctx.ordinal_counter {
                AttachBarrierV21::ProtocolFault
            } else {
                AttachBarrierV21::Accept
            }
        }
    }
}

/// Retained state for the external-change READY barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachReadyContextV21 {
    pub stored_cut: u64,
    pub kernel_high_watermark: u64,
    pub ordinal_counter: u64,
    pub already_ready: bool,
    pub active: bool,
}

/// Classify an `ExternalChangeReadyV1` against the reconciliation state: the
/// reconcile cut, processed high-watermark, stored cut, and kernel high-watermark
/// must all be equal, and may be zero only when the counter is also zero.
pub fn classify_external_change_ready_v21(
    ready: &ExternalChangeReadyV1,
    ctx: &AttachReadyContextV21,
) -> AttachBarrierV21 {
    if ctx.active {
        return AttachBarrierV21::ProtocolFault;
    }
    if ready.reconcile_cut != ready.processed_high_watermark
        || ready.reconcile_cut != ctx.stored_cut
        || ctx.stored_cut != ctx.kernel_high_watermark
    {
        return AttachBarrierV21::ProtocolFault;
    }
    if ready.reconcile_cut == 0 && ctx.ordinal_counter != 0 {
        return AttachBarrierV21::ProtocolFault;
    }
    if ctx.already_ready {
        AttachBarrierV21::IdempotentDuplicate
    } else {
        AttachBarrierV21::Accept
    }
}

/// Classify a `PtLaneReadyV1` against the kernel's retained lane high-watermark.
pub fn classify_pt_lane_ready_v21(
    ready: &PtLaneReadyV1,
    kernel_high_watermark: u64,
    already_ready: bool,
    active: bool,
) -> AttachBarrierV21 {
    if active {
        return AttachBarrierV21::ProtocolFault;
    }
    if ready.kind_ordinal != notify_ack_kind::PT_REVOKE_ROUTE
        && ready.kind_ordinal != notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE
    {
        return AttachBarrierV21::ProtocolFault;
    }
    if ready.high_watermark != kernel_high_watermark {
        return AttachBarrierV21::ProtocolFault;
    }
    if already_ready {
        AttachBarrierV21::IdempotentDuplicate
    } else {
        AttachBarrierV21::Accept
    }
}

// ---- Wave 9 notification-credit ownership ----------------------------------

/// A notification credit's owning coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationCreditRefV21 {
    pub ring_index: u32,
    pub index: u32,
    pub generation: u64,
}

/// The closed credit ownership/reuse classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationCreditClassV21 {
    Fresh,
    DuplicateReuse,
    StaleCrossRing,
    WrongRing,
}

/// Classify an incoming notification credit against the retained owner.
/// DIR_CHANGE credits are pinned to ring zero.
pub const fn classify_notification_credit_v21(
    retained: NotificationCreditRefV21,
    incoming: NotificationCreditRefV21,
    dir_change: bool,
) -> NotificationCreditClassV21 {
    if dir_change && incoming.ring_index != 0 {
        return NotificationCreditClassV21::WrongRing;
    }
    if incoming.ring_index != retained.ring_index {
        return NotificationCreditClassV21::StaleCrossRing;
    }
    if incoming.index != retained.index {
        return NotificationCreditClassV21::WrongRing;
    }
    if incoming.generation <= retained.generation {
        NotificationCreditClassV21::DuplicateReuse
    } else {
        NotificationCreditClassV21::Fresh
    }
}
