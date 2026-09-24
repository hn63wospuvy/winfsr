#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "fsring_abi.h"

#ifdef MAX_RESERVE_RETRIES
#error "ring implementation constants must not be exported by the wire ABI header"
#endif

#define ASSERT_LAYOUT(type_, size_, alignment_)                                  \
    _Static_assert(sizeof(type_) == (size_), #type_ " size");                  \
    _Static_assert(_Alignof(type_) == (alignment_), #type_ " alignment")

#define ASSERT_OFFSET(type_, field_, offset_)                                    \
    _Static_assert(offsetof(type_, field_) == (offset_),                         \
                   #type_ "." #field_ " offset")

/* ABI identity and every pinned public integer registry value. */
_Static_assert(FSRING_MAGIC == UINT32_C(0x47525346), "FSRING magic");
_Static_assert(FSRING_ABI_MAJOR == 2, "ABI major");
_Static_assert(FSRING_ABI_MINOR == 1, "ABI minor");
_Static_assert(FSRING_ABI_MIN_COMPAT_MINOR == 1, "ABI min-compatible minor");
_Static_assert(FSRING_ENDIAN_LITTLE == 1, "little-endian tag");
_Static_assert(FSRING_SLOT_CLASS_COUNT == 4, "slot class count");
_Static_assert(FSRING_SQE_PAYLOAD_LEN == 88, "SQE payload length");
_Static_assert(FSRING_CQE_OUT_LEN == 24, "CQE output length");

_Static_assert(FSRING_REQ_INDEX_BITS == 24, "request index bits");
_Static_assert(FSRING_REQ_GENERATION_BITS == 40, "request generation bits");
_Static_assert(FSRING_REQ_INDEX_MAX == UINT32_C(0x00ffffff),
               "request index maximum");
_Static_assert(FSRING_REQ_GENERATION_MAX == UINT64_C(0x000000ffffffffff),
               "request generation maximum");

_Static_assert(FSRING_SLOT_INDEX_MAX == UINT32_C(0x000fffff),
               "slot index maximum");
_Static_assert(FSRING_SLOT_OFFSET_MAX == UINT32_C(0x001fffff),
               "slot offset maximum");
_Static_assert(FSRING_SLOT_LENGTH_MAX == UINT32_C(0x001fffff),
               "slot length maximum");

_Static_assert(FSRING_PARK_STATE_ACTIVE == 0, "active park state");
_Static_assert(FSRING_PARK_STATE_POLLING == 1, "polling park state");
_Static_assert(FSRING_PARK_STATE_PARKED == 2, "parked park state");

_Static_assert(FSRING_PROTOCOL_FEATURE_PT == 0, "PT feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_MMAP == 1, "mmap feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_HOT_RESTART == 2,
               "hot-restart feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_EXACTLY_ONCE == 3,
               "exactly-once feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_SECURITY == 4, "security feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_REPARSE == 5, "reparse feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_TOKEN_DONATION == 6,
               "token-donation feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_MAPPED_IO == 7,
               "mapped-I/O feature bit");
_Static_assert(FSRING_PROTOCOL_FEATURE_NOTIFY_NAMES == 8,
               "notify-names feature bit");

_Static_assert(FSRING_OS_CAP_MDL_NO_WRITE == 0, "MDL no-write OS bit");
_Static_assert(FSRING_OS_CAP_MDL_NO_EXECUTE == 1, "MDL no-execute OS bit");
_Static_assert(FSRING_OS_CAP_MODERN_COHERENCY == 2,
               "modern coherency OS bit");
_Static_assert(FSRING_OS_CAP_ARM64 == 3, "ARM64 OS bit");

_Static_assert(FSRING_SQE_FLAG_NO_COMPLETION == UINT16_C(1),
               "no-completion SQE flag");

_Static_assert(FSRING_OP_PREPARE_OPEN == UINT16_C(0x0001), "PREPARE_OPEN");
_Static_assert(FSRING_OP_COMMIT_OPEN == UINT16_C(0x0002), "COMMIT_OPEN");
_Static_assert(FSRING_OP_ABORT_OPEN == UINT16_C(0x0003), "ABORT_OPEN");
_Static_assert(FSRING_OP_CLEANUP == UINT16_C(0x0004), "CLEANUP");
_Static_assert(FSRING_OP_CLOSE == UINT16_C(0x0005), "CLOSE");
_Static_assert(FSRING_OP_READ == UINT16_C(0x0010), "READ");
_Static_assert(FSRING_OP_WRITE == UINT16_C(0x0011), "WRITE");
_Static_assert(FSRING_OP_FLUSH == UINT16_C(0x0012), "FLUSH");
_Static_assert(FSRING_OP_QUERY_INFO == UINT16_C(0x0020), "QUERY_INFO");
_Static_assert(FSRING_OP_MUTATE == UINT16_C(0x0021), "MUTATE");
_Static_assert(FSRING_OP_QUERY_DIR == UINT16_C(0x0022), "QUERY_DIR");
_Static_assert(FSRING_OP_QUERY_VOLUME == UINT16_C(0x0023), "QUERY_VOLUME");
_Static_assert(FSRING_OP_QUERY_SECURITY == UINT16_C(0x0024), "QUERY_SECURITY");
_Static_assert(FSRING_OP_FSCTL == UINT16_C(0x0025), "FSCTL");
_Static_assert(FSRING_OP_CANCEL == UINT16_C(0x0030), "CANCEL");
_Static_assert(FSRING_OP_ATTACH == UINT16_C(0x0040), "ATTACH");
_Static_assert(FSRING_OP_REPLAY_OPEN == UINT16_C(0x0041), "REPLAY_OPEN");
_Static_assert(FSRING_OP_QUERY_OP == UINT16_C(0x0042), "QUERY_OP");
_Static_assert(FSRING_OP_ACK_RESULT == UINT16_C(0x0043), "ACK_RESULT");
_Static_assert(FSRING_OP_PT_ROUTE_ACK == UINT16_C(0x0050), "PT_ROUTE_ACK");
_Static_assert(FSRING_OP_PT_EXTERNAL_SAFE_ACK == UINT16_C(0x0051),
               "PT_EXTERNAL_SAFE_ACK");

_Static_assert(FSRING_CQ_KIND_COMPLETION == 0, "completion kind");
_Static_assert(FSRING_CQ_KIND_NOTIFY == 1, "notification kind");
_Static_assert(FSRING_CQ_KIND_PROTOCOL == 2, "protocol kind");

_Static_assert(FSRING_NOTIFY_INVALIDATE_FILE == 1, "INVALIDATE_FILE");
_Static_assert(FSRING_NOTIFY_INVALIDATE_ENTRY == 2, "INVALIDATE_ENTRY");
_Static_assert(FSRING_NOTIFY_PT_GRANT == 3, "PT_GRANT");
_Static_assert(FSRING_NOTIFY_PT_REVOKE_ROUTE == 4, "PT_REVOKE_ROUTE");
_Static_assert(FSRING_NOTIFY_PT_EXTERNAL_MUTATION_SAFE == 5,
               "PT_EXTERNAL_MUTATION_SAFE");
_Static_assert(FSRING_NOTIFY_RESIZE == 6, "RESIZE");
_Static_assert(FSRING_NOTIFY_DIR_CHANGE == 7, "DIR_CHANGE");

_Static_assert(FSRING_CONTROL_VERSION_V1 == 1, "control version");
_Static_assert(FSRING_BUFFER_KIND_NONE == 0, "no buffer");
_Static_assert(FSRING_BUFFER_KIND_SLOT == 1, "slot buffer");
_Static_assert(FSRING_BUFFER_KIND_MAPPING == 2, "mapped buffer");
_Static_assert(FSRING_BUFFER_ACCESS_K2U_READ_ONLY == 1,
               "kernel-to-user read-only access");
_Static_assert(FSRING_BUFFER_ACCESS_U2K_WRITE == 2,
               "user-to-kernel write access");
_Static_assert(FSRING_RW_FLAG_PAGING == UINT32_C(1), "paging flag");
_Static_assert(FSRING_RW_FLAG_NOCACHE == UINT32_C(2), "noncached flag");
_Static_assert(FSRING_RW_FLAG_WRITE_THROUGH == UINT32_C(4),
               "write-through flag");
_Static_assert(FSRING_RW_FLAG_MAPPED == UINT32_C(8), "mapped flag");
_Static_assert(FSRING_RW_FLAG_SYNC_PAGING == UINT32_C(16),
               "synchronous paging flag");
_Static_assert(FSRING_RW_FLAG_EXTENDING == UINT32_C(32), "extending flag");
_Static_assert(FSRING_RW_FLAG_ZERO_RANGE_VALID == UINT32_C(64),
               "valid zero-range flag");

/* ABI 2.1 flat wire-code additions and section-15 scalars. */
_Static_assert(FSRING_PROTOCOL_FEATURE_CASE_SENSITIVE_NAMES == 9,
               "case-sensitive-names feature bit");
_Static_assert(FSRING_OP_DIR_CHANGE_ACK == UINT16_C(0x0052), "DIR_CHANGE_ACK");
_Static_assert(FSRING_NOTIFY_PT_LANE_READY == 8, "PT_LANE_READY");
_Static_assert(FSRING_NOTIFY_EXTERNAL_CHANGE_READY == 9, "EXTERNAL_CHANGE_READY");
_Static_assert(FSRING_NOTIFY_EXTERNAL_CHANGE_CUT == 10, "EXTERNAL_CHANGE_CUT");
_Static_assert(FSRING_CONTROL_VERSION_V2 == 2, "control version V2");
_Static_assert(FSRING_SLOT_TOKEN_CLASS_MAX == 3, "slot-token class maximum");
_Static_assert(FSRING_SLOT_TOKEN_INDEX_MAX == UINT32_C(0x000fffff),
               "slot-token index maximum");
_Static_assert(FSRING_SLOT_TOKEN_GENERATION_MAX == UINT64_C(0x000003ffffffffff),
               "slot-token generation maximum");
_Static_assert(FSRING_MAX_FILE_SIZE == (uint64_t)INT64_MAX, "maximum file size");
_Static_assert(FSRING_SYSTEM_REQID_BASE == UINT32_C(16777023), "system ReqId base");
_Static_assert(FSRING_GLOBAL_EXTERNAL_CHANGE_ACK_REQID == UINT32_C(16777215),
               "global external-change ack ReqId");
_Static_assert(FSRING_SYSTEM_REQUEST_SLOTS_PER_RING == 3,
               "system request slots per ring");
_Static_assert(FSRING_CONTROL_SQ_RESERVE_PER_RING == 4, "control SQ reserve per ring");

/* Foundational wire types. */
ASSERT_LAYOUT(FeatureSet, 16, 8);
ASSERT_OFFSET(FeatureSet, words, 0);

ASSERT_LAYOUT(ReqId, 8, 8);

#define ASSERT_ID128(type_)                                                      \
    ASSERT_LAYOUT(type_, 16, 8);                                                 \
    ASSERT_OFFSET(type_, lo, 0);                                                 \
    ASSERT_OFFSET(type_, hi, 8)

ASSERT_ID128(OpId);
ASSERT_ID128(FileId);
ASSERT_ID128(LinkId);
ASSERT_ID128(MountId);
ASSERT_ID128(TransactionId);
ASSERT_ID128(AckToken);

ASSERT_LAYOUT(SlotRef, 8, 8);

/* Physical transport layout: every struct and every physical field. */
ASSERT_LAYOUT(RegionDesc, 16, 8);
ASSERT_OFFSET(RegionDesc, offset, 0);
ASSERT_OFFSET(RegionDesc, length, 8);

ASSERT_LAYOUT(SlotClassDesc, 16, 8);
ASSERT_OFFSET(SlotClassDesc, slot_size, 0);
ASSERT_OFFSET(SlotClassDesc, slot_count, 4);
ASSERT_OFFSET(SlotClassDesc, data_offset, 8);

ASSERT_LAYOUT(GlobalHeader, 4096, 4096);
ASSERT_OFFSET(GlobalHeader, magic, 0);
ASSERT_OFFSET(GlobalHeader, header_size, 4);
ASSERT_OFFSET(GlobalHeader, abi_major, 6);
ASSERT_OFFSET(GlobalHeader, abi_minor, 8);
ASSERT_OFFSET(GlobalHeader, byte_order, 10);
ASSERT_OFFSET(GlobalHeader, header_flags, 11);
ASSERT_OFFSET(GlobalHeader, page_size, 12);
ASSERT_OFFSET(GlobalHeader, session_epoch, 16);
ASSERT_OFFSET(GlobalHeader, section_size, 24);
ASSERT_OFFSET(GlobalHeader, ring_count, 32);
ASSERT_OFFSET(GlobalHeader, ring_desc_size, 36);
ASSERT_OFFSET(GlobalHeader, ring_directory, 40);
ASSERT_OFFSET(GlobalHeader, k2u_slots, 56);
ASSERT_OFFSET(GlobalHeader, u2k_slots, 72);
ASSERT_OFFSET(GlobalHeader, notify_names, 88);
ASSERT_OFFSET(GlobalHeader, protocol_features, 104);
ASSERT_OFFSET(GlobalHeader, os_capabilities, 120);
ASSERT_OFFSET(GlobalHeader, max_inflight, 136);
ASSERT_OFFSET(GlobalHeader, flags, 140);
ASSERT_OFFSET(GlobalHeader, k2u_slot_classes, 144);
ASSERT_OFFSET(GlobalHeader, u2k_slot_classes, 208);
ASSERT_OFFSET(GlobalHeader, reserved, 272);

ASSERT_LAYOUT(RingDesc, 128, 64);
ASSERT_OFFSET(RingDesc, magic, 0);
ASSERT_OFFSET(RingDesc, desc_size, 4);
ASSERT_OFFSET(RingDesc, desc_version, 6);
ASSERT_OFFSET(RingDesc, ring_index, 8);
ASSERT_OFFSET(RingDesc, flags, 12);
ASSERT_OFFSET(RingDesc, sq_capacity, 16);
ASSERT_OFFSET(RingDesc, cq_capacity, 20);
ASSERT_OFFSET(RingDesc, sq_entries, 24);
ASSERT_OFFSET(RingDesc, sq_producer, 40);
ASSERT_OFFSET(RingDesc, sq_consumer, 56);
ASSERT_OFFSET(RingDesc, cq_entries, 72);
ASSERT_OFFSET(RingDesc, cq_producer, 88);
ASSERT_OFFSET(RingDesc, cq_consumer, 104);
ASSERT_OFFSET(RingDesc, reserved, 120);

ASSERT_LAYOUT(ProducerPage, 4096, 4096);
ASSERT_OFFSET(ProducerPage, tail, 0);
ASSERT_OFFSET(ProducerPage, wake_sequence, 8);
ASSERT_OFFSET(ProducerPage, flags, 16);
ASSERT_OFFSET(ProducerPage, reserved0, 20);
ASSERT_OFFSET(ProducerPage, reserved, 24);

ASSERT_LAYOUT(ConsumerPage, 4096, 4096);
ASSERT_OFFSET(ConsumerPage, head, 0);
ASSERT_OFFSET(ConsumerPage, park_state, 8);
ASSERT_OFFSET(ConsumerPage, flags, 12);
ASSERT_OFFSET(ConsumerPage, heartbeat, 16);
ASSERT_OFFSET(ConsumerPage, reserved, 24);

ASSERT_LAYOUT(SqeBody, 120, 8);
ASSERT_OFFSET(SqeBody, opcode, 0);
ASSERT_OFFSET(SqeBody, flags, 2);
ASSERT_OFFSET(SqeBody, payload_len, 4);
ASSERT_OFFSET(SqeBody, reserved, 6);
ASSERT_OFFSET(SqeBody, req_id, 8);
ASSERT_OFFSET(SqeBody, kernel_open_id, 16);
ASSERT_OFFSET(SqeBody, ccb_sequence, 24);
ASSERT_OFFSET(SqeBody, payload, 32);

ASSERT_LAYOUT(Sqe, 128, 64);
ASSERT_OFFSET(Sqe, sequence, 0);
ASSERT_OFFSET(Sqe, body, 8);

ASSERT_LAYOUT(CqeBody, 56, 8);
ASSERT_OFFSET(CqeBody, kind, 0);
ASSERT_OFFSET(CqeBody, opcode, 2);
ASSERT_OFFSET(CqeBody, flags, 4);
ASSERT_OFFSET(CqeBody, out_len, 6);
ASSERT_OFFSET(CqeBody, req_id, 8);
ASSERT_OFFSET(CqeBody, status, 16);
ASSERT_OFFSET(CqeBody, reserved, 20);
ASSERT_OFFSET(CqeBody, information, 24);
ASSERT_OFFSET(CqeBody, out, 32);

ASSERT_LAYOUT(Cqe, 64, 64);
ASSERT_OFFSET(Cqe, sequence, 0);
ASSERT_OFFSET(Cqe, body, 8);

/* Common/fixed I/O payloads: every struct and field. */
ASSERT_LAYOUT(ControlHeader, 8, 4);
ASSERT_OFFSET(ControlHeader, struct_size, 0);
ASSERT_OFFSET(ControlHeader, struct_version, 4);
ASSERT_OFFSET(ControlHeader, required_flags, 6);

ASSERT_LAYOUT(BufferRef, 24, 8);
ASSERT_OFFSET(BufferRef, token, 0);
ASSERT_OFFSET(BufferRef, offset, 8);
ASSERT_OFFSET(BufferRef, length, 12);
ASSERT_OFFSET(BufferRef, kind, 16);
ASSERT_OFFSET(BufferRef, access, 18);
ASSERT_OFFSET(BufferRef, reserved, 20);

ASSERT_LAYOUT(SizeState, 32, 8);
ASSERT_OFFSET(SizeState, allocation_size, 0);
ASSERT_OFFSET(SizeState, file_size, 8);
ASSERT_OFFSET(SizeState, valid_data_length, 16);
ASSERT_OFFSET(SizeState, size_epoch, 24);

ASSERT_LAYOUT(PControl, 24, 8);
ASSERT_OFFSET(PControl, body, 0);

ASSERT_LAYOUT(OControl, 24, 8);
ASSERT_OFFSET(OControl, body, 0);

ASSERT_LAYOUT(PBarrier, 24, 8);
ASSERT_OFFSET(PBarrier, op_id, 0);
ASSERT_OFFSET(PBarrier, flags, 16);
ASSERT_OFFSET(PBarrier, reserved, 20);

ASSERT_LAYOUT(PCancel, 16, 8);
ASSERT_OFFSET(PCancel, target_req_id, 0);
ASSERT_OFFSET(PCancel, target_session_epoch, 8);

ASSERT_LAYOUT(PNotifyAck, 24, 8);
ASSERT_OFFSET(PNotifyAck, token, 0);
ASSERT_OFFSET(PNotifyAck, epoch, 16);

ASSERT_LAYOUT(PRw, 80, 8);
ASSERT_OFFSET(PRw, op_id, 0);
ASSERT_OFFSET(PRw, offset, 16);
ASSERT_OFFSET(PRw, size_epoch, 24);
ASSERT_OFFSET(PRw, initialized_offset, 32);
ASSERT_OFFSET(PRw, data, 40);
ASSERT_OFFSET(PRw, length, 64);
ASSERT_OFFSET(PRw, initialized_length, 68);
ASSERT_OFFSET(PRw, rw_flags, 72);
ASSERT_OFFSET(PRw, reserved, 76);

ASSERT_LAYOUT(ORw, 24, 8);
ASSERT_OFFSET(ORw, file_size, 0);
ASSERT_OFFSET(ORw, valid_data_length, 8);
ASSERT_OFFSET(ORw, size_epoch, 16);

/* Transactional OPEN payloads. */
ASSERT_LAYOUT(PrepareOpenV1, 96, 8);
ASSERT_OFFSET(PrepareOpenV1, header, 0);
ASSERT_OFFSET(PrepareOpenV1, op_id, 8);
ASSERT_OFFSET(PrepareOpenV1, parent_id, 24);
ASSERT_OFFSET(PrepareOpenV1, name, 40);
ASSERT_OFFSET(PrepareOpenV1, security_context_id, 64);
ASSERT_OFFSET(PrepareOpenV1, desired_access, 72);
ASSERT_OFFSET(PrepareOpenV1, share_access, 76);
ASSERT_OFFSET(PrepareOpenV1, disposition, 80);
ASSERT_OFFSET(PrepareOpenV1, create_options, 84);
ASSERT_OFFSET(PrepareOpenV1, file_attributes, 88);
ASSERT_OFFSET(PrepareOpenV1, open_flags, 92);

ASSERT_LAYOUT(PrepareOpenResultV1, 136, 8);
ASSERT_OFFSET(PrepareOpenResultV1, header, 0);
ASSERT_OFFSET(PrepareOpenResultV1, transaction_id, 8);
ASSERT_OFFSET(PrepareOpenResultV1, file_id, 24);
ASSERT_OFFSET(PrepareOpenResultV1, link_id, 40);
ASSERT_OFFSET(PrepareOpenResultV1, security_descriptor, 56);
ASSERT_OFFSET(PrepareOpenResultV1, sizes, 80);
ASSERT_OFFSET(PrepareOpenResultV1, namespace_generation, 112);
ASSERT_OFFSET(PrepareOpenResultV1, security_generation, 120);
ASSERT_OFFSET(PrepareOpenResultV1, object_flags, 128);
ASSERT_OFFSET(PrepareOpenResultV1, reserved, 132);

ASSERT_LAYOUT(CommitOpenV1, 72, 8);
ASSERT_OFFSET(CommitOpenV1, header, 0);
ASSERT_OFFSET(CommitOpenV1, op_id, 8);
ASSERT_OFFSET(CommitOpenV1, transaction_id, 24);
ASSERT_OFFSET(CommitOpenV1, expected_namespace_generation, 40);
ASSERT_OFFSET(CommitOpenV1, expected_security_generation, 48);
ASSERT_OFFSET(CommitOpenV1, kernel_open_id, 56);
ASSERT_OFFSET(CommitOpenV1, commit_flags, 64);
ASSERT_OFFSET(CommitOpenV1, reserved, 68);

ASSERT_LAYOUT(CommitOpenResultV1, 104, 8);
ASSERT_OFFSET(CommitOpenResultV1, header, 0);
ASSERT_OFFSET(CommitOpenResultV1, provider_open_cookie, 8);
ASSERT_OFFSET(CommitOpenResultV1, file_id, 16);
ASSERT_OFFSET(CommitOpenResultV1, link_id, 32);
ASSERT_OFFSET(CommitOpenResultV1, sizes, 48);
ASSERT_OFFSET(CommitOpenResultV1, namespace_generation, 80);
ASSERT_OFFSET(CommitOpenResultV1, security_generation, 88);
ASSERT_OFFSET(CommitOpenResultV1, create_result, 96);
ASSERT_OFFSET(CommitOpenResultV1, result_flags, 100);

ASSERT_LAYOUT(AbortOpenV1, 24, 8);
ASSERT_OFFSET(AbortOpenV1, header, 0);
ASSERT_OFFSET(AbortOpenV1, transaction_id, 8);

/* Exactly-once mutation payloads. */
ASSERT_LAYOUT(MutationV1, 72, 8);
ASSERT_OFFSET(MutationV1, header, 0);
ASSERT_OFFSET(MutationV1, op_id, 8);
ASSERT_OFFSET(MutationV1, mutation_kind, 24);
ASSERT_OFFSET(MutationV1, mutation_flags, 26);
ASSERT_OFFSET(MutationV1, reserved, 28);
ASSERT_OFFSET(MutationV1, expected_namespace_generation, 32);
ASSERT_OFFSET(MutationV1, expected_size_epoch, 40);
ASSERT_OFFSET(MutationV1, body, 48);

ASSERT_LAYOUT(MutationResultV1, 80, 8);
ASSERT_OFFSET(MutationResultV1, header, 0);
ASSERT_OFFSET(MutationResultV1, op_id, 8);
ASSERT_OFFSET(MutationResultV1, volume_commit_sequence, 24);
ASSERT_OFFSET(MutationResultV1, sizes, 32);
ASSERT_OFFSET(MutationResultV1, namespace_generation, 64);
ASSERT_OFFSET(MutationResultV1, result_flags, 72);
ASSERT_OFFSET(MutationResultV1, reserved, 76);

/* Attach/replay/exactly-once recovery payloads. */
ASSERT_LAYOUT(ReplayOpenV1, 80, 8);
ASSERT_OFFSET(ReplayOpenV1, header, 0);
ASSERT_OFFSET(ReplayOpenV1, kernel_open_id, 8);
ASSERT_OFFSET(ReplayOpenV1, file_id, 16);
ASSERT_OFFSET(ReplayOpenV1, link_id, 32);
ASSERT_OFFSET(ReplayOpenV1, desired_access, 48);
ASSERT_OFFSET(ReplayOpenV1, share_access, 52);
ASSERT_OFFSET(ReplayOpenV1, create_options, 56);
ASSERT_OFFSET(ReplayOpenV1, disposition, 60);
ASSERT_OFFSET(ReplayOpenV1, ccb_sequence, 64);
ASSERT_OFFSET(ReplayOpenV1, state_flags, 72);

ASSERT_LAYOUT(ReplayOpenResultV1, 16, 8);
ASSERT_OFFSET(ReplayOpenResultV1, header, 0);
ASSERT_OFFSET(ReplayOpenResultV1, provider_open_cookie, 8);

ASSERT_LAYOUT(AttachV1, 56, 8);
ASSERT_OFFSET(AttachV1, header, 0);
ASSERT_OFFSET(AttachV1, prior_session_epoch, 8);
ASSERT_OFFSET(AttachV1, requested_features, 16);
ASSERT_OFFSET(AttachV1, mount_id, 32);
ASSERT_OFFSET(AttachV1, journal_version, 48);
ASSERT_OFFSET(AttachV1, flags, 52);

ASSERT_LAYOUT(QueryOpV1, 56, 8);
ASSERT_OFFSET(QueryOpV1, header, 0);
ASSERT_OFFSET(QueryOpV1, op_id, 8);
ASSERT_OFFSET(QueryOpV1, operation_digest, 24);

ASSERT_LAYOUT(QueryOpResultV1, 56, 8);
ASSERT_OFFSET(QueryOpResultV1, header, 0);
ASSERT_OFFSET(QueryOpResultV1, state, 8);
ASSERT_OFFSET(QueryOpResultV1, flags, 10);
ASSERT_OFFSET(QueryOpResultV1, reserved, 12);
ASSERT_OFFSET(QueryOpResultV1, op_id, 16);
ASSERT_OFFSET(QueryOpResultV1, result, 32);

ASSERT_LAYOUT(AckResultV1, 24, 8);
ASSERT_OFFSET(AckResultV1, header, 0);
ASSERT_OFFSET(AckResultV1, op_id, 8);

/* Notifications and authenticated handle donation payloads. */
ASSERT_LAYOUT(NotifyEnvelopeV1, 72, 8);
ASSERT_OFFSET(NotifyEnvelopeV1, header, 0);
ASSERT_OFFSET(NotifyEnvelopeV1, notify_code, 8);
ASSERT_OFFSET(NotifyEnvelopeV1, notify_flags, 10);
ASSERT_OFFSET(NotifyEnvelopeV1, reserved, 12);
ASSERT_OFFSET(NotifyEnvelopeV1, token, 16);
ASSERT_OFFSET(NotifyEnvelopeV1, file_id, 32);
ASSERT_OFFSET(NotifyEnvelopeV1, body, 48);

ASSERT_LAYOUT(DonateBackingV1, 48, 8);
ASSERT_OFFSET(DonateBackingV1, header, 0);
ASSERT_OFFSET(DonateBackingV1, file_id, 8);
ASSERT_OFFSET(DonateBackingV1, pt_epoch, 24);
ASSERT_OFFSET(DonateBackingV1, daemon_handle, 32);
ASSERT_OFFSET(DonateBackingV1, sector_size, 40);
ASSERT_OFFSET(DonateBackingV1, flags, 44);

ASSERT_LAYOUT(DonateSecurityContextV1, 32, 8);
ASSERT_OFFSET(DonateSecurityContextV1, header, 0);
ASSERT_OFFSET(DonateSecurityContextV1, security_context_id, 8);
ASSERT_OFFSET(DonateSecurityContextV1, daemon_handle, 16);
ASSERT_OFFSET(DonateSecurityContextV1, flags, 24);
ASSERT_OFFSET(DonateSecurityContextV1, reserved, 28);

/* ============================================================
 * ABI 2.1 wire types activated by Wave 10.
 * ============================================================ */
/* 128-bit identities. */
ASSERT_ID128(BootInstanceId);
ASSERT_ID128(RetireToken);

/* Slot token / blob slice. */
ASSERT_LAYOUT(SlotToken, 8, 8);
ASSERT_LAYOUT(BlobSlice, 8, 4);
ASSERT_OFFSET(BlobSlice, offset, 0);
ASSERT_OFFSET(BlobSlice, length, 4);

/* Control / session. */
ASSERT_LAYOUT(SlotClassRequest, 8, 4);
ASSERT_OFFSET(SlotClassRequest, slot_size, 0);
ASSERT_OFFSET(SlotClassRequest, slot_count, 4);
ASSERT_LAYOUT(SetupRequestV1, 160, 8);
ASSERT_OFFSET(SetupRequestV1, header, 0);
ASSERT_OFFSET(SetupRequestV1, abi_major, 8);
ASSERT_OFFSET(SetupRequestV1, min_abi_minor, 10);
ASSERT_OFFSET(SetupRequestV1, max_abi_minor, 12);
ASSERT_OFFSET(SetupRequestV1, reserved0, 14);
ASSERT_OFFSET(SetupRequestV1, offered_features, 16);
ASSERT_OFFSET(SetupRequestV1, required_features, 32);
ASSERT_OFFSET(SetupRequestV1, required_os_capabilities, 48);
ASSERT_OFFSET(SetupRequestV1, ring_count, 64);
ASSERT_OFFSET(SetupRequestV1, sq_capacity, 68);
ASSERT_OFFSET(SetupRequestV1, cq_capacity, 72);
ASSERT_OFFSET(SetupRequestV1, max_inflight, 76);
ASSERT_OFFSET(SetupRequestV1, k2u_slot_classes, 80);
ASSERT_OFFSET(SetupRequestV1, u2k_slot_classes, 112);
ASSERT_OFFSET(SetupRequestV1, notification_credit_count, 144);
ASSERT_OFFSET(SetupRequestV1, notification_credit_size, 148);
ASSERT_OFFSET(SetupRequestV1, flags, 152);
ASSERT_OFFSET(SetupRequestV1, reserved1, 156);
ASSERT_LAYOUT(UserViewDesc, 32, 8);
ASSERT_OFFSET(UserViewDesc, section_offset, 0);
ASSERT_OFFSET(UserViewDesc, length, 8);
ASSERT_OFFSET(UserViewDesc, user_address, 16);
ASSERT_OFFSET(UserViewDesc, ring_index, 24);
ASSERT_OFFSET(UserViewDesc, kind, 28);
ASSERT_OFFSET(UserViewDesc, access, 30);
ASSERT_LAYOUT(NotificationCreditV1, 32, 8);
ASSERT_OFFSET(NotificationCreditV1, buffer, 0);
ASSERT_OFFSET(NotificationCreditV1, ring_index, 24);
ASSERT_OFFSET(NotificationCreditV1, reserved, 28);
ASSERT_LAYOUT(SessionResultV1, 136, 8);
ASSERT_OFFSET(SessionResultV1, header, 0);
ASSERT_OFFSET(SessionResultV1, abi_major, 8);
ASSERT_OFFSET(SessionResultV1, abi_minor, 10);
ASSERT_OFFSET(SessionResultV1, reserved0, 12);
ASSERT_OFFSET(SessionResultV1, mount_id, 16);
ASSERT_OFFSET(SessionResultV1, boot_instance_id, 32);
ASSERT_OFFSET(SessionResultV1, session_epoch, 48);
ASSERT_OFFSET(SessionResultV1, section_size, 56);
ASSERT_OFFSET(SessionResultV1, selected_features, 64);
ASSERT_OFFSET(SessionResultV1, os_capabilities, 80);
ASSERT_OFFSET(SessionResultV1, view_count, 96);
ASSERT_OFFSET(SessionResultV1, view_desc_size, 100);
ASSERT_OFFSET(SessionResultV1, views_offset, 104);
ASSERT_OFFSET(SessionResultV1, notification_credit_count, 108);
ASSERT_OFFSET(SessionResultV1, notification_credit_desc_size, 112);
ASSERT_OFFSET(SessionResultV1, notification_credits_offset, 116);
ASSERT_OFFSET(SessionResultV1, ring_count, 120);
ASSERT_OFFSET(SessionResultV1, max_inflight, 124);
ASSERT_OFFSET(SessionResultV1, flags, 128);
ASSERT_OFFSET(SessionResultV1, reserved1, 132);
ASSERT_LAYOUT(EnterRequestV1, 48, 8);
ASSERT_OFFSET(EnterRequestV1, header, 0);
ASSERT_OFFSET(EnterRequestV1, mount_id, 8);
ASSERT_OFFSET(EnterRequestV1, session_epoch, 24);
ASSERT_OFFSET(EnterRequestV1, ring_index, 32);
ASSERT_OFFSET(EnterRequestV1, flags, 36);
ASSERT_OFFSET(EnterRequestV1, cq_budget, 40);
ASSERT_OFFSET(EnterRequestV1, timeout_ms, 44);
ASSERT_LAYOUT(EnterResultV1, 48, 8);
ASSERT_OFFSET(EnterResultV1, header, 0);
ASSERT_OFFSET(EnterResultV1, session_epoch, 8);
ASSERT_OFFSET(EnterResultV1, ring_index, 16);
ASSERT_OFFSET(EnterResultV1, flags, 20);
ASSERT_OFFSET(EnterResultV1, cq_drained, 24);
ASSERT_OFFSET(EnterResultV1, sq_ready, 28);
ASSERT_OFFSET(EnterResultV1, notification_credit_count, 32);
ASSERT_OFFSET(EnterResultV1, notification_credit_desc_size, 36);
ASSERT_OFFSET(EnterResultV1, notification_credits_offset, 40);
ASSERT_OFFSET(EnterResultV1, reserved, 44);
ASSERT_LAYOUT(DetachRequestV1, 40, 8);
ASSERT_OFFSET(DetachRequestV1, header, 0);
ASSERT_OFFSET(DetachRequestV1, mount_id, 8);
ASSERT_OFFSET(DetachRequestV1, session_epoch, 24);
ASSERT_OFFSET(DetachRequestV1, flags, 32);
ASSERT_OFFSET(DetachRequestV1, reserved, 36);
ASSERT_LAYOUT(DonateBackingV2, 48, 8);
ASSERT_OFFSET(DonateBackingV2, header, 0);
ASSERT_OFFSET(DonateBackingV2, file_id, 8);
ASSERT_OFFSET(DonateBackingV2, pt_epoch, 24);
ASSERT_OFFSET(DonateBackingV2, sector_size, 32);
ASSERT_OFFSET(DonateBackingV2, flags, 36);
ASSERT_OFFSET(DonateBackingV2, backing_path, 40);
ASSERT_LAYOUT(RetireMountV1, 48, 8);
ASSERT_OFFSET(RetireMountV1, header, 0);
ASSERT_OFFSET(RetireMountV1, mount_id, 8);
ASSERT_OFFSET(RetireMountV1, token, 24);
ASSERT_OFFSET(RetireMountV1, action, 40);
ASSERT_OFFSET(RetireMountV1, reserved, 44);
ASSERT_LAYOUT(RetireMountResultV1, 96, 8);
ASSERT_OFFSET(RetireMountResultV1, header, 0);
ASSERT_OFFSET(RetireMountResultV1, mount_id, 8);
ASSERT_OFFSET(RetireMountResultV1, boot_instance_id, 24);
ASSERT_OFFSET(RetireMountResultV1, proof_token, 40);
ASSERT_OFFSET(RetireMountResultV1, latest_session_epoch, 56);
ASSERT_OFFSET(RetireMountResultV1, selected_features, 64);
ASSERT_OFFSET(RetireMountResultV1, journal_version, 80);
ASSERT_OFFSET(RetireMountResultV1, mount_state, 84);
ASSERT_OFFSET(RetireMountResultV1, flags, 86);
ASSERT_OFFSET(RetireMountResultV1, reserved, 88);

/* Boot context. */
ASSERT_LAYOUT(BootContextHeaderV1, 256, 64);
ASSERT_OFFSET(BootContextHeaderV1, magic, 0);
ASSERT_OFFSET(BootContextHeaderV1, format_version, 8);
ASSERT_OFFSET(BootContextHeaderV1, header_size, 12);
ASSERT_OFFSET(BootContextHeaderV1, context_size, 16);
ASSERT_OFFSET(BootContextHeaderV1, slot_size, 20);
ASSERT_OFFSET(BootContextHeaderV1, slot_count, 24);
ASSERT_OFFSET(BootContextHeaderV1, init_state, 28);
ASSERT_OFFSET(BootContextHeaderV1, flags, 32);
ASSERT_OFFSET(BootContextHeaderV1, reserved0, 36);
ASSERT_OFFSET(BootContextHeaderV1, header_sequence, 40);
ASSERT_OFFSET(BootContextHeaderV1, mount_sequence, 48);
ASSERT_OFFSET(BootContextHeaderV1, mount_sequence_complement, 56);
ASSERT_OFFSET(BootContextHeaderV1, load_generation, 64);
ASSERT_OFFSET(BootContextHeaderV1, load_generation_complement, 72);
ASSERT_OFFSET(BootContextHeaderV1, boot_instance_id, 80);
ASSERT_OFFSET(BootContextHeaderV1, per_boot_retire_key, 96);
ASSERT_OFFSET(BootContextHeaderV1, digest, 128);
ASSERT_OFFSET(BootContextHeaderV1, reserved, 160);
ASSERT_LAYOUT(BootContextSlotV1, 256, 64);
ASSERT_OFFSET(BootContextSlotV1, sequence, 0);
ASSERT_OFFSET(BootContextSlotV1, state, 8);
ASSERT_OFFSET(BootContextSlotV1, service_sid_length, 12);
ASSERT_OFFSET(BootContextSlotV1, load_generation, 16);
ASSERT_OFFSET(BootContextSlotV1, mount_sequence, 24);
ASSERT_OFFSET(BootContextSlotV1, mount_id, 32);
ASSERT_OFFSET(BootContextSlotV1, boot_instance_id, 48);
ASSERT_OFFSET(BootContextSlotV1, latest_session_epoch, 64);
ASSERT_OFFSET(BootContextSlotV1, selected_features, 72);
ASSERT_OFFSET(BootContextSlotV1, journal_version, 88);
ASSERT_OFFSET(BootContextSlotV1, flags, 92);
ASSERT_OFFSET(BootContextSlotV1, service_sid, 96);
ASSERT_OFFSET(BootContextSlotV1, reserved, 164);
ASSERT_OFFSET(BootContextSlotV1, digest, 224);

/* Durable metadata. */
ASSERT_LAYOUT(ProviderMountRootV1, 160, 8);
ASSERT_OFFSET(ProviderMountRootV1, version, 0);
ASSERT_OFFSET(ProviderMountRootV1, state, 4);
ASSERT_OFFSET(ProviderMountRootV1, boot_instance_id, 8);
ASSERT_OFFSET(ProviderMountRootV1, mount_id, 24);
ASSERT_OFFSET(ProviderMountRootV1, latest_session_epoch, 40);
ASSERT_OFFSET(ProviderMountRootV1, selected_features, 48);
ASSERT_OFFSET(ProviderMountRootV1, journal_version, 64);
ASSERT_OFFSET(ProviderMountRootV1, service_sid_length, 68);
ASSERT_OFFSET(ProviderMountRootV1, service_sid, 72);
ASSERT_OFFSET(ProviderMountRootV1, reserved, 140);
ASSERT_OFFSET(ProviderMountRootV1, latest_proof_token, 144);
ASSERT_LAYOUT(DurableChildValueV1, 88, 8);
ASSERT_OFFSET(DurableChildValueV1, header, 0);
ASSERT_OFFSET(DurableChildValueV1, value_kind, 8);
ASSERT_OFFSET(DurableChildValueV1, state, 10);
ASSERT_OFFSET(DurableChildValueV1, flags, 12);
ASSERT_OFFSET(DurableChildValueV1, identity_digest, 16);
ASSERT_OFFSET(DurableChildValueV1, payload_digest, 48);
ASSERT_OFFSET(DurableChildValueV1, payload, 80);
ASSERT_LAYOUT(AccountingReservationV1, 48, 8);
ASSERT_OFFSET(AccountingReservationV1, target_child_kind, 0);
ASSERT_OFFSET(AccountingReservationV1, flags, 2);
ASSERT_OFFSET(AccountingReservationV1, target_key_length, 4);
ASSERT_OFFSET(AccountingReservationV1, charged_bytes, 8);
ASSERT_OFFSET(AccountingReservationV1, target_key_digest, 16);
ASSERT_LAYOUT(PrepareTxIndexValueV1, 48, 8);
ASSERT_OFFSET(PrepareTxIndexValueV1, op_id, 0);
ASSERT_OFFSET(PrepareTxIndexValueV1, identity_digest, 16);
ASSERT_LAYOUT(LatestProcessedV1, 56, 8);
ASSERT_OFFSET(LatestProcessedV1, first_ordinal, 0);
ASSERT_OFFSET(LatestProcessedV1, through_ordinal, 8);
ASSERT_OFFSET(LatestProcessedV1, volume_commit_sequence, 16);
ASSERT_OFFSET(LatestProcessedV1, semantic_digest, 24);
ASSERT_LAYOUT(RetireReceiptV1, 32, 8);
ASSERT_OFFSET(RetireReceiptV1, retire_token, 0);
ASSERT_OFFSET(RetireReceiptV1, state, 16);
ASSERT_OFFSET(RetireReceiptV1, reserved, 20);

/* Durable payloads. */
ASSERT_LAYOUT(OpenRecoveryPayloadV1, 152, 8);
ASSERT_OFFSET(OpenRecoveryPayloadV1, header, 0);
ASSERT_OFFSET(OpenRecoveryPayloadV1, file_id, 8);
ASSERT_OFFSET(OpenRecoveryPayloadV1, link_id, 24);
ASSERT_OFFSET(OpenRecoveryPayloadV1, parent_id, 40);
ASSERT_OFFSET(OpenRecoveryPayloadV1, sizes, 56);
ASSERT_OFFSET(OpenRecoveryPayloadV1, namespace_generation, 88);
ASSERT_OFFSET(OpenRecoveryPayloadV1, security_generation, 96);
ASSERT_OFFSET(OpenRecoveryPayloadV1, kernel_open_id, 104);
ASSERT_OFFSET(OpenRecoveryPayloadV1, desired_access, 112);
ASSERT_OFFSET(OpenRecoveryPayloadV1, granted_access, 116);
ASSERT_OFFSET(OpenRecoveryPayloadV1, share_access, 120);
ASSERT_OFFSET(OpenRecoveryPayloadV1, create_options, 124);
ASSERT_OFFSET(OpenRecoveryPayloadV1, file_attributes, 128);
ASSERT_OFFSET(OpenRecoveryPayloadV1, disposition, 132);
ASSERT_OFFSET(OpenRecoveryPayloadV1, name, 136);
ASSERT_OFFSET(OpenRecoveryPayloadV1, security_descriptor, 144);
ASSERT_LAYOUT(PrepareRecoveryPayloadV1, 184, 8);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, header, 0);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, parent_id, 8);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, transaction_id, 24);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_file_id, 40);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_link_id, 56);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_sizes, 72);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_namespace_generation, 104);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_security_generation, 112);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, desired_access, 120);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, share_access, 124);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, disposition, 128);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, create_options, 132);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, file_attributes, 136);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, open_flags, 140);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_object_flags, 144);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, reserved, 148);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, name, 152);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, requested_security_descriptor, 160);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, ea, 168);
ASSERT_OFFSET(PrepareRecoveryPayloadV1, result_security_descriptor, 176);
ASSERT_LAYOUT(JournalStateV1, 64, 8);
ASSERT_OFFSET(JournalStateV1, header, 0);
ASSERT_OFFSET(JournalStateV1, op_id, 8);
ASSERT_OFFSET(JournalStateV1, opcode, 24);
ASSERT_OFFSET(JournalStateV1, mutation_kind, 26);
ASSERT_OFFSET(JournalStateV1, state, 28);
ASSERT_OFFSET(JournalStateV1, operation_digest, 32);
ASSERT_LAYOUT(QueryDirSnapshotPayloadV1, 56, 8);
ASSERT_OFFSET(QueryDirSnapshotPayloadV1, header, 0);
ASSERT_OFFSET(QueryDirSnapshotPayloadV1, pattern_digest, 8);
ASSERT_OFFSET(QueryDirSnapshotPayloadV1, entry_count, 40);
ASSERT_OFFSET(QueryDirSnapshotPayloadV1, entries, 48);
ASSERT_LAYOUT(QueryDirCookiePayloadV1, 56, 8);
ASSERT_OFFSET(QueryDirCookiePayloadV1, header, 0);
ASSERT_OFFSET(QueryDirCookiePayloadV1, next_cookie, 8);
ASSERT_OFFSET(QueryDirCookiePayloadV1, result_flags, 16);
ASSERT_OFFSET(QueryDirCookiePayloadV1, reserved, 20);
ASSERT_OFFSET(QueryDirCookiePayloadV1, attempt_digest, 24);
ASSERT_LAYOUT(PtEpochIntentPayloadV1, 32, 8);
ASSERT_OFFSET(PtEpochIntentPayloadV1, header, 0);
ASSERT_OFFSET(PtEpochIntentPayloadV1, pt_epoch, 8);
ASSERT_OFFSET(PtEpochIntentPayloadV1, sector_size, 16);
ASSERT_OFFSET(PtEpochIntentPayloadV1, flags, 20);
ASSERT_OFFSET(PtEpochIntentPayloadV1, backing_path, 24);
ASSERT_LAYOUT(PtLanePayloadV1, 72, 8);
ASSERT_OFFSET(PtLanePayloadV1, header, 0);
ASSERT_OFFSET(PtLanePayloadV1, high_watermark, 8);
ASSERT_OFFSET(PtLanePayloadV1, latest_token, 16);
ASSERT_OFFSET(PtLanePayloadV1, latest_file_id, 32);
ASSERT_OFFSET(PtLanePayloadV1, latest_pt_epoch, 48);
ASSERT_OFFSET(PtLanePayloadV1, latest_notify_code, 56);
ASSERT_OFFSET(PtLanePayloadV1, flags, 58);
ASSERT_OFFSET(PtLanePayloadV1, reserved, 60);
ASSERT_OFFSET(PtLanePayloadV1, pending_envelope, 64);
ASSERT_LAYOUT(CommittedResultV1, 40, 8);
ASSERT_OFFSET(CommittedResultV1, header, 0);
ASSERT_OFFSET(CommittedResultV1, opcode, 8);
ASSERT_OFFSET(CommittedResultV1, result_kind, 10);
ASSERT_OFFSET(CommittedResultV1, status, 12);
ASSERT_OFFSET(CommittedResultV1, information, 16);
ASSERT_OFFSET(CommittedResultV1, payload, 24);
ASSERT_OFFSET(CommittedResultV1, volume_commit_sequence, 32);
ASSERT_LAYOUT(CommittedOpenResultV1, 96, 8);
ASSERT_OFFSET(CommittedOpenResultV1, header, 0);
ASSERT_OFFSET(CommittedOpenResultV1, file_id, 8);
ASSERT_OFFSET(CommittedOpenResultV1, link_id, 24);
ASSERT_OFFSET(CommittedOpenResultV1, sizes, 40);
ASSERT_OFFSET(CommittedOpenResultV1, namespace_generation, 72);
ASSERT_OFFSET(CommittedOpenResultV1, security_generation, 80);
ASSERT_OFFSET(CommittedOpenResultV1, create_result, 88);
ASSERT_OFFSET(CommittedOpenResultV1, flags, 92);
ASSERT_LAYOUT(CommittedWriteResultV1, 40, 8);
ASSERT_OFFSET(CommittedWriteResultV1, header, 0);
ASSERT_OFFSET(CommittedWriteResultV1, sizes, 8);
ASSERT_LAYOUT(CommittedMutationResultV1, 72, 8);
ASSERT_OFFSET(CommittedMutationResultV1, header, 0);
ASSERT_OFFSET(CommittedMutationResultV1, mutation_kind, 8);
ASSERT_OFFSET(CommittedMutationResultV1, flags, 10);
ASSERT_OFFSET(CommittedMutationResultV1, reserved, 12);
ASSERT_OFFSET(CommittedMutationResultV1, sizes, 16);
ASSERT_OFFSET(CommittedMutationResultV1, namespace_generation, 48);
ASSERT_OFFSET(CommittedMutationResultV1, security_generation, 56);
ASSERT_OFFSET(CommittedMutationResultV1, kind_payload, 64);

/* Message V2: I/O and OPEN. */
ASSERT_LAYOUT(WriteV2, 112, 8);
ASSERT_OFFSET(WriteV2, header, 0);
ASSERT_OFFSET(WriteV2, op_id, 8);
ASSERT_OFFSET(WriteV2, offset, 24);
ASSERT_OFFSET(WriteV2, expected_size_epoch, 32);
ASSERT_OFFSET(WriteV2, initialized_offset, 40);
ASSERT_OFFSET(WriteV2, data, 48);
ASSERT_OFFSET(WriteV2, length, 72);
ASSERT_OFFSET(WriteV2, initialized_length, 76);
ASSERT_OFFSET(WriteV2, rw_flags, 80);
ASSERT_OFFSET(WriteV2, reserved, 84);
ASSERT_OFFSET(WriteV2, reply, 88);
ASSERT_LAYOUT(WriteResultV2, 56, 8);
ASSERT_OFFSET(WriteResultV2, header, 0);
ASSERT_OFFSET(WriteResultV2, sizes, 8);
ASSERT_OFFSET(WriteResultV2, volume_commit_sequence, 40);
ASSERT_OFFSET(WriteResultV2, flags, 48);
ASSERT_OFFSET(WriteResultV2, reserved, 52);
ASSERT_LAYOUT(PrepareOpenV2, 192, 8);
ASSERT_OFFSET(PrepareOpenV2, header, 0);
ASSERT_OFFSET(PrepareOpenV2, op_id, 8);
ASSERT_OFFSET(PrepareOpenV2, parent_id, 24);
ASSERT_OFFSET(PrepareOpenV2, name, 40);
ASSERT_OFFSET(PrepareOpenV2, security_context_id, 64);
ASSERT_OFFSET(PrepareOpenV2, desired_access, 72);
ASSERT_OFFSET(PrepareOpenV2, share_access, 76);
ASSERT_OFFSET(PrepareOpenV2, disposition, 80);
ASSERT_OFFSET(PrepareOpenV2, create_options, 84);
ASSERT_OFFSET(PrepareOpenV2, file_attributes, 88);
ASSERT_OFFSET(PrepareOpenV2, open_flags, 92);
ASSERT_OFFSET(PrepareOpenV2, requested_security_descriptor, 96);
ASSERT_OFFSET(PrepareOpenV2, extended_attributes, 120);
ASSERT_OFFSET(PrepareOpenV2, reply, 144);
ASSERT_OFFSET(PrepareOpenV2, result_security_descriptor, 168);
ASSERT_LAYOUT(CommitOpenV2, 104, 8);
ASSERT_OFFSET(CommitOpenV2, header, 0);
ASSERT_OFFSET(CommitOpenV2, op_id, 8);
ASSERT_OFFSET(CommitOpenV2, transaction_id, 24);
ASSERT_OFFSET(CommitOpenV2, expected_namespace_generation, 40);
ASSERT_OFFSET(CommitOpenV2, expected_security_generation, 48);
ASSERT_OFFSET(CommitOpenV2, kernel_open_id, 56);
ASSERT_OFFSET(CommitOpenV2, commit_flags, 64);
ASSERT_OFFSET(CommitOpenV2, reserved, 68);
ASSERT_OFFSET(CommitOpenV2, granted_access, 72);
ASSERT_OFFSET(CommitOpenV2, reserved2, 76);
ASSERT_OFFSET(CommitOpenV2, reply, 80);
ASSERT_LAYOUT(CommitOpenResultV2, 112, 8);
ASSERT_OFFSET(CommitOpenResultV2, header, 0);
ASSERT_OFFSET(CommitOpenResultV2, provider_open_cookie, 8);
ASSERT_OFFSET(CommitOpenResultV2, file_id, 16);
ASSERT_OFFSET(CommitOpenResultV2, link_id, 32);
ASSERT_OFFSET(CommitOpenResultV2, sizes, 48);
ASSERT_OFFSET(CommitOpenResultV2, namespace_generation, 80);
ASSERT_OFFSET(CommitOpenResultV2, security_generation, 88);
ASSERT_OFFSET(CommitOpenResultV2, create_result, 96);
ASSERT_OFFSET(CommitOpenResultV2, result_flags, 100);
ASSERT_OFFSET(CommitOpenResultV2, volume_commit_sequence, 104);

/* Mutation bodies and results. */
ASSERT_LAYOUT(SetBasicInfoV1, 48, 8);
ASSERT_OFFSET(SetBasicInfoV1, header, 0);
ASSERT_OFFSET(SetBasicInfoV1, creation_time, 8);
ASSERT_OFFSET(SetBasicInfoV1, last_access_time, 16);
ASSERT_OFFSET(SetBasicInfoV1, last_write_time, 24);
ASSERT_OFFSET(SetBasicInfoV1, change_time, 32);
ASSERT_OFFSET(SetBasicInfoV1, attributes, 40);
ASSERT_OFFSET(SetBasicInfoV1, set_mask, 44);
ASSERT_LAYOUT(SetSizeV1, 24, 8);
ASSERT_OFFSET(SetSizeV1, header, 0);
ASSERT_OFFSET(SetSizeV1, new_size, 8);
ASSERT_OFFSET(SetSizeV1, flags, 16);
ASSERT_OFFSET(SetSizeV1, reserved, 20);
ASSERT_LAYOUT(RenameV1, 72, 8);
ASSERT_OFFSET(RenameV1, header, 0);
ASSERT_OFFSET(RenameV1, source_link_id, 8);
ASSERT_OFFSET(RenameV1, target_parent_id, 24);
ASSERT_OFFSET(RenameV1, expected_source_parent_generation, 40);
ASSERT_OFFSET(RenameV1, expected_target_parent_generation, 48);
ASSERT_OFFSET(RenameV1, name, 56);
ASSERT_OFFSET(RenameV1, flags, 64);
ASSERT_OFFSET(RenameV1, reserved, 68);
ASSERT_LAYOUT(LinkV1, 64, 8);
ASSERT_OFFSET(LinkV1, header, 0);
ASSERT_OFFSET(LinkV1, source_file_id, 8);
ASSERT_OFFSET(LinkV1, target_parent_id, 24);
ASSERT_OFFSET(LinkV1, expected_target_parent_generation, 40);
ASSERT_OFFSET(LinkV1, name, 48);
ASSERT_OFFSET(LinkV1, flags, 56);
ASSERT_OFFSET(LinkV1, reserved, 60);
ASSERT_LAYOUT(UnlinkV1, 56, 8);
ASSERT_OFFSET(UnlinkV1, header, 0);
ASSERT_OFFSET(UnlinkV1, link_id, 8);
ASSERT_OFFSET(UnlinkV1, parent_id, 24);
ASSERT_OFFSET(UnlinkV1, expected_parent_generation, 40);
ASSERT_OFFSET(UnlinkV1, flags, 48);
ASSERT_OFFSET(UnlinkV1, reserved, 52);
ASSERT_LAYOUT(SetSecurityV1, 24, 4);
ASSERT_OFFSET(SetSecurityV1, header, 0);
ASSERT_OFFSET(SetSecurityV1, security_information, 8);
ASSERT_OFFSET(SetSecurityV1, flags, 12);
ASSERT_OFFSET(SetSecurityV1, security_descriptor, 16);
ASSERT_LAYOUT(SetReparseV1, 24, 4);
ASSERT_OFFSET(SetReparseV1, header, 0);
ASSERT_OFFSET(SetReparseV1, tag, 8);
ASSERT_OFFSET(SetReparseV1, flags, 12);
ASSERT_OFFSET(SetReparseV1, reparse_data, 16);
ASSERT_LAYOUT(DeleteReparseV1, 16, 4);
ASSERT_OFFSET(DeleteReparseV1, header, 0);
ASSERT_OFFSET(DeleteReparseV1, tag, 8);
ASSERT_OFFSET(DeleteReparseV1, flags, 12);
ASSERT_LAYOUT(SetSparseV1, 16, 4);
ASSERT_OFFSET(SetSparseV1, header, 0);
ASSERT_OFFSET(SetSparseV1, sparse, 8);
ASSERT_OFFSET(SetSparseV1, flags, 12);
ASSERT_LAYOUT(MutationV2, 128, 8);
ASSERT_OFFSET(MutationV2, header, 0);
ASSERT_OFFSET(MutationV2, op_id, 8);
ASSERT_OFFSET(MutationV2, mutation_kind, 24);
ASSERT_OFFSET(MutationV2, mutation_flags, 26);
ASSERT_OFFSET(MutationV2, reserved, 28);
ASSERT_OFFSET(MutationV2, expected_namespace_generation, 32);
ASSERT_OFFSET(MutationV2, expected_size_epoch, 40);
ASSERT_OFFSET(MutationV2, expected_security_generation, 48);
ASSERT_OFFSET(MutationV2, body, 56);
ASSERT_OFFSET(MutationV2, reply, 80);
ASSERT_OFFSET(MutationV2, kind_result, 104);
ASSERT_LAYOUT(MutationResultV2, 112, 8);
ASSERT_OFFSET(MutationResultV2, header, 0);
ASSERT_OFFSET(MutationResultV2, op_id, 8);
ASSERT_OFFSET(MutationResultV2, volume_commit_sequence, 24);
ASSERT_OFFSET(MutationResultV2, mutation_kind, 32);
ASSERT_OFFSET(MutationResultV2, result_flags, 34);
ASSERT_OFFSET(MutationResultV2, reserved, 36);
ASSERT_OFFSET(MutationResultV2, sizes, 40);
ASSERT_OFFSET(MutationResultV2, namespace_generation, 72);
ASSERT_OFFSET(MutationResultV2, security_generation, 80);
ASSERT_OFFSET(MutationResultV2, kind_result, 88);
ASSERT_LAYOUT(RenameResultV2, 112, 8);
ASSERT_OFFSET(RenameResultV2, header, 0);
ASSERT_OFFSET(RenameResultV2, file_id, 8);
ASSERT_OFFSET(RenameResultV2, link_id, 24);
ASSERT_OFFSET(RenameResultV2, replaced_file_id, 40);
ASSERT_OFFSET(RenameResultV2, replaced_link_id, 56);
ASSERT_OFFSET(RenameResultV2, source_parent_generation, 72);
ASSERT_OFFSET(RenameResultV2, target_parent_generation, 80);
ASSERT_OFFSET(RenameResultV2, replaced_namespace_generation, 88);
ASSERT_OFFSET(RenameResultV2, link_count, 96);
ASSERT_OFFSET(RenameResultV2, replaced_link_count, 100);
ASSERT_OFFSET(RenameResultV2, flags, 104);
ASSERT_OFFSET(RenameResultV2, reserved, 108);
ASSERT_LAYOUT(LinkResultV2, 104, 8);
ASSERT_OFFSET(LinkResultV2, header, 0);
ASSERT_OFFSET(LinkResultV2, file_id, 8);
ASSERT_OFFSET(LinkResultV2, new_link_id, 24);
ASSERT_OFFSET(LinkResultV2, replaced_file_id, 40);
ASSERT_OFFSET(LinkResultV2, replaced_link_id, 56);
ASSERT_OFFSET(LinkResultV2, target_parent_generation, 72);
ASSERT_OFFSET(LinkResultV2, replaced_namespace_generation, 80);
ASSERT_OFFSET(LinkResultV2, link_count, 88);
ASSERT_OFFSET(LinkResultV2, replaced_link_count, 92);
ASSERT_OFFSET(LinkResultV2, flags, 96);
ASSERT_OFFSET(LinkResultV2, reserved, 100);
ASSERT_LAYOUT(UnlinkResultV1, 56, 8);
ASSERT_OFFSET(UnlinkResultV1, header, 0);
ASSERT_OFFSET(UnlinkResultV1, file_id, 8);
ASSERT_OFFSET(UnlinkResultV1, removed_link_id, 24);
ASSERT_OFFSET(UnlinkResultV1, parent_generation, 40);
ASSERT_OFFSET(UnlinkResultV1, remaining_link_count, 48);
ASSERT_OFFSET(UnlinkResultV1, flags, 52);

/* Query schemas. */
ASSERT_LAYOUT(QueryInfoV1, 40, 8);
ASSERT_OFFSET(QueryInfoV1, header, 0);
ASSERT_OFFSET(QueryInfoV1, info_class, 8);
ASSERT_OFFSET(QueryInfoV1, flags, 10);
ASSERT_OFFSET(QueryInfoV1, reserved, 12);
ASSERT_OFFSET(QueryInfoV1, output, 16);
ASSERT_LAYOUT(FileInfoV1, 104, 8);
ASSERT_OFFSET(FileInfoV1, header, 0);
ASSERT_OFFSET(FileInfoV1, creation_time, 8);
ASSERT_OFFSET(FileInfoV1, last_access_time, 16);
ASSERT_OFFSET(FileInfoV1, last_write_time, 24);
ASSERT_OFFSET(FileInfoV1, change_time, 32);
ASSERT_OFFSET(FileInfoV1, sizes, 40);
ASSERT_OFFSET(FileInfoV1, namespace_generation, 72);
ASSERT_OFFSET(FileInfoV1, security_generation, 80);
ASSERT_OFFSET(FileInfoV1, attributes, 88);
ASSERT_OFFSET(FileInfoV1, link_count, 92);
ASSERT_OFFSET(FileInfoV1, reparse_tag, 96);
ASSERT_OFFSET(FileInfoV1, flags, 100);
ASSERT_LAYOUT(QueryDirV1, 56, 8);
ASSERT_OFFSET(QueryDirV1, header, 0);
ASSERT_OFFSET(QueryDirV1, enumeration_cookie, 8);
ASSERT_OFFSET(QueryDirV1, flags, 16);
ASSERT_OFFSET(QueryDirV1, reserved, 20);
ASSERT_OFFSET(QueryDirV1, pattern, 24);
ASSERT_OFFSET(QueryDirV1, output, 32);
ASSERT_LAYOUT(QueryDirV2, 64, 8);
ASSERT_OFFSET(QueryDirV2, header, 0);
ASSERT_OFFSET(QueryDirV2, enumeration_cookie, 8);
ASSERT_OFFSET(QueryDirV2, flags, 16);
ASSERT_OFFSET(QueryDirV2, reserved, 20);
ASSERT_OFFSET(QueryDirV2, pattern, 24);
ASSERT_OFFSET(QueryDirV2, output, 32);
ASSERT_OFFSET(QueryDirV2, enumeration_generation, 56);
ASSERT_LAYOUT(QueryDirResultV1, 40, 8);
ASSERT_OFFSET(QueryDirResultV1, header, 0);
ASSERT_OFFSET(QueryDirResultV1, next_cookie, 8);
ASSERT_OFFSET(QueryDirResultV1, flags, 16);
ASSERT_OFFSET(QueryDirResultV1, entry_count, 20);
ASSERT_OFFSET(QueryDirResultV1, entries, 24);
ASSERT_OFFSET(QueryDirResultV1, required_length, 32);
ASSERT_OFFSET(QueryDirResultV1, reserved, 36);
ASSERT_LAYOUT(DirEntryV1, 136, 8);
ASSERT_OFFSET(DirEntryV1, header, 0);
ASSERT_OFFSET(DirEntryV1, file_id, 8);
ASSERT_OFFSET(DirEntryV1, link_id, 24);
ASSERT_OFFSET(DirEntryV1, sizes, 40);
ASSERT_OFFSET(DirEntryV1, creation_time, 72);
ASSERT_OFFSET(DirEntryV1, last_access_time, 80);
ASSERT_OFFSET(DirEntryV1, last_write_time, 88);
ASSERT_OFFSET(DirEntryV1, change_time, 96);
ASSERT_OFFSET(DirEntryV1, namespace_generation, 104);
ASSERT_OFFSET(DirEntryV1, attributes, 112);
ASSERT_OFFSET(DirEntryV1, reparse_tag, 116);
ASSERT_OFFSET(DirEntryV1, flags, 120);
ASSERT_OFFSET(DirEntryV1, reserved, 124);
ASSERT_OFFSET(DirEntryV1, name, 128);
ASSERT_LAYOUT(QueryVolumeV1, 40, 8);
ASSERT_OFFSET(QueryVolumeV1, header, 0);
ASSERT_OFFSET(QueryVolumeV1, info_class, 8);
ASSERT_OFFSET(QueryVolumeV1, flags, 10);
ASSERT_OFFSET(QueryVolumeV1, reserved, 12);
ASSERT_OFFSET(QueryVolumeV1, output, 16);
ASSERT_LAYOUT(VolumeSizeInfoV1, 40, 8);
ASSERT_OFFSET(VolumeSizeInfoV1, header, 0);
ASSERT_OFFSET(VolumeSizeInfoV1, total_allocation_units, 8);
ASSERT_OFFSET(VolumeSizeInfoV1, available_allocation_units, 16);
ASSERT_OFFSET(VolumeSizeInfoV1, sectors_per_allocation_unit, 24);
ASSERT_OFFSET(VolumeSizeInfoV1, bytes_per_sector, 28);
ASSERT_OFFSET(VolumeSizeInfoV1, flags, 32);
ASSERT_OFFSET(VolumeSizeInfoV1, reserved, 36);
ASSERT_LAYOUT(QuerySecurityV1, 40, 8);
ASSERT_OFFSET(QuerySecurityV1, header, 0);
ASSERT_OFFSET(QuerySecurityV1, security_information, 8);
ASSERT_OFFSET(QuerySecurityV1, flags, 12);
ASSERT_OFFSET(QuerySecurityV1, output, 16);
ASSERT_LAYOUT(FsctlV1, 64, 8);
ASSERT_OFFSET(FsctlV1, header, 0);
ASSERT_OFFSET(FsctlV1, code, 8);
ASSERT_OFFSET(FsctlV1, flags, 12);
ASSERT_OFFSET(FsctlV1, input, 16);
ASSERT_OFFSET(FsctlV1, output, 40);

/* Notification bodies. */
ASSERT_LAYOUT(NotifyEnvelopeV2, 56, 8);
ASSERT_OFFSET(NotifyEnvelopeV2, header, 0);
ASSERT_OFFSET(NotifyEnvelopeV2, notify_code, 8);
ASSERT_OFFSET(NotifyEnvelopeV2, notify_flags, 10);
ASSERT_OFFSET(NotifyEnvelopeV2, reserved, 12);
ASSERT_OFFSET(NotifyEnvelopeV2, token, 16);
ASSERT_OFFSET(NotifyEnvelopeV2, file_id, 32);
ASSERT_OFFSET(NotifyEnvelopeV2, body, 48);
ASSERT_LAYOUT(InvalidateFileV1, 40, 8);
ASSERT_OFFSET(InvalidateFileV1, header, 0);
ASSERT_OFFSET(InvalidateFileV1, offset, 8);
ASSERT_OFFSET(InvalidateFileV1, length, 16);
ASSERT_OFFSET(InvalidateFileV1, content_epoch, 24);
ASSERT_OFFSET(InvalidateFileV1, flags, 32);
ASSERT_OFFSET(InvalidateFileV1, reserved, 36);
ASSERT_LAYOUT(InvalidateEntryV1, 32, 8);
ASSERT_OFFSET(InvalidateEntryV1, header, 0);
ASSERT_OFFSET(InvalidateEntryV1, namespace_generation, 8);
ASSERT_OFFSET(InvalidateEntryV1, name, 16);
ASSERT_OFFSET(InvalidateEntryV1, flags, 24);
ASSERT_OFFSET(InvalidateEntryV1, reserved, 28);
ASSERT_LAYOUT(PtGrantV1, 24, 8);
ASSERT_OFFSET(PtGrantV1, header, 0);
ASSERT_OFFSET(PtGrantV1, pt_epoch, 8);
ASSERT_OFFSET(PtGrantV1, sector_size, 16);
ASSERT_OFFSET(PtGrantV1, flags, 20);
ASSERT_LAYOUT(PtEpochV1, 16, 8);
ASSERT_OFFSET(PtEpochV1, header, 0);
ASSERT_OFFSET(PtEpochV1, pt_epoch, 8);
ASSERT_LAYOUT(ResizeV1, 48, 8);
ASSERT_OFFSET(ResizeV1, header, 0);
ASSERT_OFFSET(ResizeV1, sizes, 8);
ASSERT_OFFSET(ResizeV1, volume_commit_sequence, 40);
ASSERT_LAYOUT(ExternalDirChangeV1, 176, 8);
ASSERT_OFFSET(ExternalDirChangeV1, header, 0);
ASSERT_OFFSET(ExternalDirChangeV1, first_ordinal, 8);
ASSERT_OFFSET(ExternalDirChangeV1, through_ordinal, 16);
ASSERT_OFFSET(ExternalDirChangeV1, volume_commit_sequence, 24);
ASSERT_OFFSET(ExternalDirChangeV1, change_kind, 32);
ASSERT_OFFSET(ExternalDirChangeV1, object_kind, 34);
ASSERT_OFFSET(ExternalDirChangeV1, filter_match, 36);
ASSERT_OFFSET(ExternalDirChangeV1, flags, 40);
ASSERT_OFFSET(ExternalDirChangeV1, reserved0, 44);
ASSERT_OFFSET(ExternalDirChangeV1, target_link_id, 48);
ASSERT_OFFSET(ExternalDirChangeV1, replaced_file_id, 64);
ASSERT_OFFSET(ExternalDirChangeV1, replaced_link_id, 80);
ASSERT_OFFSET(ExternalDirChangeV1, old_parent_id, 96);
ASSERT_OFFSET(ExternalDirChangeV1, new_parent_id, 112);
ASSERT_OFFSET(ExternalDirChangeV1, old_parent_generation, 128);
ASSERT_OFFSET(ExternalDirChangeV1, new_parent_generation, 136);
ASSERT_OFFSET(ExternalDirChangeV1, target_namespace_generation, 144);
ASSERT_OFFSET(ExternalDirChangeV1, replaced_namespace_generation, 152);
ASSERT_OFFSET(ExternalDirChangeV1, old_name, 160);
ASSERT_OFFSET(ExternalDirChangeV1, new_name, 168);
ASSERT_LAYOUT(PtLaneReadyV1, 24, 8);
ASSERT_OFFSET(PtLaneReadyV1, header, 0);
ASSERT_OFFSET(PtLaneReadyV1, kind_ordinal, 8);
ASSERT_OFFSET(PtLaneReadyV1, reserved0, 10);
ASSERT_OFFSET(PtLaneReadyV1, flags, 12);
ASSERT_OFFSET(PtLaneReadyV1, high_watermark, 16);
ASSERT_LAYOUT(ExternalChangeReadyV1, 32, 8);
ASSERT_OFFSET(ExternalChangeReadyV1, header, 0);
ASSERT_OFFSET(ExternalChangeReadyV1, reconcile_cut, 8);
ASSERT_OFFSET(ExternalChangeReadyV1, processed_high_watermark, 16);
ASSERT_OFFSET(ExternalChangeReadyV1, flags, 24);
ASSERT_OFFSET(ExternalChangeReadyV1, reserved, 28);
ASSERT_LAYOUT(ExternalChangeCutV1, 24, 8);
ASSERT_OFFSET(ExternalChangeCutV1, header, 0);
ASSERT_OFFSET(ExternalChangeCutV1, reconcile_cut, 8);
ASSERT_OFFSET(ExternalChangeCutV1, flags, 16);
ASSERT_OFFSET(ExternalChangeCutV1, reserved, 20);
ASSERT_LAYOUT(PDirChangeAckV1, 64, 8);
ASSERT_OFFSET(PDirChangeAckV1, token, 0);
ASSERT_OFFSET(PDirChangeAckV1, through_ordinal, 16);
ASSERT_OFFSET(PDirChangeAckV1, volume_commit_sequence, 24);
ASSERT_OFFSET(PDirChangeAckV1, semantic_digest, 32);

/* Protocol abort. */
ASSERT_LAYOUT(ProtocolAbortV1, 24, 8);
ASSERT_OFFSET(ProtocolAbortV1, header, 0);
ASSERT_OFFSET(ProtocolAbortV1, reason, 8);
ASSERT_OFFSET(ProtocolAbortV1, reserved, 12);
ASSERT_OFFSET(ProtocolAbortV1, context, 16);

/* Recovery V2. */
ASSERT_LAYOUT(ReplayOpenV2, 104, 8);
ASSERT_OFFSET(ReplayOpenV2, header, 0);
ASSERT_OFFSET(ReplayOpenV2, kernel_open_id, 8);
ASSERT_OFFSET(ReplayOpenV2, file_id, 16);
ASSERT_OFFSET(ReplayOpenV2, link_id, 32);
ASSERT_OFFSET(ReplayOpenV2, desired_access, 48);
ASSERT_OFFSET(ReplayOpenV2, share_access, 52);
ASSERT_OFFSET(ReplayOpenV2, create_options, 56);
ASSERT_OFFSET(ReplayOpenV2, disposition, 60);
ASSERT_OFFSET(ReplayOpenV2, ccb_sequence, 64);
ASSERT_OFFSET(ReplayOpenV2, state_flags, 72);
ASSERT_OFFSET(ReplayOpenV2, reply, 80);
ASSERT_LAYOUT(QueryOpV2, 104, 8);
ASSERT_OFFSET(QueryOpV2, header, 0);
ASSERT_OFFSET(QueryOpV2, op_id, 8);
ASSERT_OFFSET(QueryOpV2, operation_digest, 24);
ASSERT_OFFSET(QueryOpV2, reply, 56);
ASSERT_OFFSET(QueryOpV2, committed_result, 80);
ASSERT_LAYOUT(AckResultV2, 56, 8);
ASSERT_OFFSET(AckResultV2, header, 0);
ASSERT_OFFSET(AckResultV2, op_id, 8);
ASSERT_OFFSET(AckResultV2, operation_digest, 24);
