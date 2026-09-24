//! Checked, allocation-free validation helpers for caller-owned private snapshots.

mod backing_path;
mod boot;
mod control;
mod durable;
mod durable_payloads;
mod messages;
mod queries;
mod session;

pub(super) use backing_path::is_canonical_backing_device_path;

pub use boot::{
    is_dedicated_service_sid_v1, validate_boot_context_header_v1, validate_boot_context_section_v1,
    validate_boot_context_slot_v1, BootContextValidationError,
};
pub use control::{
    resolve_blob_slice, validate_control_prefix, validate_control_prefix_with_schemas,
    validate_tail_coverage, BlobSliceRule, ControlError, ControlVersionSchema, EmptySliceRule,
    TailSegment, TailSegmentKind, ValidatedControlPrefix,
};
pub use durable::{
    validate_accounting_reservation_v1, validate_durable_child_value_v1,
    validate_durable_u64_value_v1, validate_external_outbox_row_v1, validate_latest_processed_v1,
    validate_prepare_tx_index_value_v1, validate_provider_mount_root_v1,
    validate_retire_receipt_v1, DurableMetadataError, ValidatedDurableChildV1,
};
pub use durable_payloads::{
    validate_durable_payload_v1, DurablePayloadError, ValidatedDurablePayloadV1,
};
pub use messages::{
    apply_domain_kind, apply_domain_reservation_v21, apply_lock_order_less_v21,
    classify_ack_pruning_v21, classify_completion_v21, classify_external_ordinal_interval_v21,
    classify_rw_submission_v21, classify_volume_sequence_merge_v21,
    committed_result_total_size_v21, compare_committed_mutation_v21, compare_committed_open_v21,
    compare_committed_write_v21, completion_status, decode_ack_token,
    external_dir_change_ack_token, is_registered_completion_status_v21, mutation_kind_of_body_v21,
    mutation_kind_result_length_v21, next_req_generation_v21, pt_ack_token,
    query_op_table_action_v21, validate_ack_result_binding_v21, validate_ack_result_v2,
    validate_commit_open_success_v2, validate_commit_open_v2, validate_committed_result_v1,
    validate_completion_output_v21, validate_create_phase_identity_v21, validate_mutation_body_v21,
    validate_mutation_success_v2, validate_mutation_v2, validate_notification_version_v21,
    validate_notify_envelope_v2, validate_pdir_change_ack_v1, validate_prepare_open_success_v21,
    validate_prepare_open_v2, validate_query_op_bts_retry_v21, validate_query_op_result_v1,
    validate_query_op_v2, validate_read_success_v21, validate_read_v21,
    validate_replay_open_success_v21, validate_replay_open_v2, validate_request_version_v21,
    validate_request_wire_form_v21, validate_result_wire_form_v21, validate_size_state_v21,
    validate_stored_component_utf16, validate_write_success_v2, validate_write_v2,
    AckBundleObservationV21, AckPruningActionV21, AckTokenPartsV21, ApplyDomainCountsV21,
    ApplyLockEntryV21, CompletionDispositionV21, CompletionOutputContextV21,
    CreatePhaseCandidateV21, CreatePhaseExpectationV21, CreatePhaseV21, ExternalOrdinalIntervalV21,
    GrantBindingV21, MessageValidationError, MutationBodyRefV21, MutationKindResultRefV21,
    MutationV2Context, PrepareOpenV2Context, QueryOpAnswerContextV21, QueryOpBtsContextV21,
    QueryOpTableActionV21, QueryOpV2Context, RetainedCommittedContextV21, RetainedExternalTupleV21,
    RetainedOpPhaseV21, RwRequestWireFormV21, RwResultWireFormV21, RwSubmissionV21,
    SequenceMergeV21, ValidatedCommitOpenSuccessV2, ValidatedCommitOpenV2,
    ValidatedCommittedResultV1, ValidatedCreatePhaseIdentityV21, ValidatedMutationSuccessV2,
    ValidatedMutationV2, ValidatedNotifyBodyV2, ValidatedNotifyEnvelopeV2,
    ValidatedPrepareOpenSuccessV21, ValidatedPrepareOpenV2, ValidatedQueryOpAnswerV21,
    ValidatedQueryOpV2, ValidatedReadSuccessV21, ValidatedReadV21, ValidatedReplayOpenSuccessV21,
    ValidatedReplayOpenV2, ValidatedWriteSuccessV2, ValidatedWriteV2, WriteV2Context,
    FLUSH_FAILURES, MAX_APPLY_DOMAINS_PER_OPERATION, MAX_QUERY_OP_BTS_RETRIES, MUTATE_FAILURES,
    OPEN_FAILURES, QUERY_FAILURES, READ_FAILURES, WRITE_FAILURES,
};
pub use messages::{
    classify_external_change_cut_v21, classify_external_change_ready_v21,
    classify_notification_credit_v21, classify_pt_ack_v21, classify_pt_lane_ready_v21,
    next_pt_lane_ordinal_v21, pt_lane_can_publish_v21, validate_pnotify_ack_v21, AttachBarrierV21,
    AttachCutContextV21, AttachReadyContextV21, NotificationCreditClassV21,
    NotificationCreditRefV21, PtLaneAckActionV21, PtLaneStateV21,
};
pub use queries::{
    validate_dir_pattern_utf16, validate_feature_wire_legality_v21, validate_file_info_v1,
    validate_fsctl_emission_v21, validate_query_dir_result_v1, validate_query_dir_v2,
    validate_query_info_v1, validate_query_security_v1, validate_query_volume_v1,
    validate_volume_size_info_v1, QueryDirFormV21, QueryValidationError, ValidatedQueryDirResultV1,
    ValidatedQueryDirV2, WireFormV21,
};
pub use session::{
    enter_result_size_v1, session_result_size_v1, validate_attach_v1, validate_detach_request_v1,
    validate_donate_backing_v2, validate_donate_security_context_v1, validate_enter_request_v1,
    validate_enter_result_v1, validate_retire_mount_result_v1, validate_retire_mount_v1,
    validate_section_size_v21, validate_session_result_v1, validate_setup_request_v1,
    AttachExpectation, RingViewLayout, SessionContextError, SessionIdentity,
    SessionValidationError, SessionViewLayout, ValidatedDonateBacking, ValidatedEnterResult,
    ValidatedSessionResult, ValidatedSetupRequest, ValidatedTopology,
};

/// Exclusive checked range inside a versioned control blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedRange32 {
    pub start: u32,
    pub end: u32,
}

/// Exclusive checked numeric range.
///
/// The containing API defines the coordinate space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedRange64 {
    pub start: u64,
    pub end: u64,
}

impl CheckedRange64 {
    pub const fn checked_len(self) -> Option<u64> {
        self.end.checked_sub(self.start)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.start <= self.end
            && other.start <= other.end
            && self.start <= other.start
            && other.end <= self.end
    }
}
