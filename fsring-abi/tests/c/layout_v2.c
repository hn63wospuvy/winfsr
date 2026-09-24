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
_Static_assert(FSRING_ABI_MINOR == 0, "ABI minor");
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
