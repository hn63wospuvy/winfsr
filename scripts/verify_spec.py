#!/usr/bin/env python3
"""Verify the FSRING normative document set.

Wave 11 contract: documents 00-03 must present the ABI 2.1 identity, the
byte-exact transport/control/durable tables, and the closed
message/status/notification maps (REQUIRED tokens), and must not carry the
superseded ABI 2.0 claims (per-document FORBIDDEN_BY_DOC tokens beside the
global FORBIDDEN list). Strict UTF-8 throughout; stdlib only.

Wave 12 contract: documents 04-06 must present the kernel-side ABI 2.1
contract (object/open identities, the direct-I/O admission and two-phase
CREATE dispatch machines, and the universal lock/rundown order with daemon
waits as state-machine boundaries) and must not carry the superseded 2.0
kernel model (STABLE labels, 2.0 opcode/payload names, ERESOURCE lock-order
member names, "doc NN §" cross-references).
"""
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
DESIGN_ROOT = REPO_ROOT / "docs" / "design"
EXPECTED = [
    "00-INDEX.md",
    "01-principles-architecture.md",
    "02-transport.md",
    "03-messages.md",
    "04-object-model.md",
    "05-irp-dispatch.md",
    "06-locking.md",
    "07-cache-mm.md",
    "08-passthrough.md",
    "09-security.md",
    "10-lifecycle.md",
    "11-rust-implementation.md",
    "12-test-plan.md",
]
REQUIRED = {
    "00-INDEX.md": [
        "ABI 2.1", "FSRING_ABI_MINOR", "FSRING_ABI_MIN_COMPAT_MINOR", "0.2.1",
        "Windows 10 1507", "Windows 7 SP1", "ARM64", "fsring-abi/",
        "verify_v21_registry.py", "chuyển tiếp",
    ],
    "01-principles-architecture.md": [
        "protocol_features", "os_capabilities", "op_id", "session_epoch",
        "SlotToken", "BootInstanceId", "volume_commit_sequence",
        "kernel_open_id", "BCryptGenRandom", "HOT_RESTART", "EXACTLY_ONCE",
    ],
    "02-transport.md": [
        "generation:40", "slot_index:24", "MPSC", "SPSC", "K2U", "U2K",
        "PROTOCOL_FAULT", "FSRING_ABI_MIN_COMPAT_MINOR", "SlotToken",
        "generation:42", "ControlHeader", "CONTROL_VERSION_V2",
        "IOCTL_FSRING_SETUP", "0x0022e000", "IOCTL_FSRING_RETIRE_MOUNT",
        "SetupRequestV1", "SessionResultV1", "UserViewDesc",
        "NotificationCreditV1", "EnterRequestV1", "EnterResultV1", "AttachV1",
        "DetachRequestV1", "DonateBackingV2", "RetireMountV1",
        "RetireMountResultV1", "BootContextHeaderV1", "BootContextSlotV1",
        "BOOT_CONTEXT_MAGIC", "RESTART_GRACE_TIMEOUT_MS", "BOUND_RECONCILING",
        "SYSTEM_REQID_BASE", "16777023", "GLOBAL_EXTERNAL_CHANGE_ACK_REQID",
        "16777215", "DurableChildValueV1", "ProviderMountRootV1",
        "OpenRecoveryPayloadV1", "PrepareRecoveryPayloadV1", "JournalStateV1",
        "AccountingReservationV1", "VOLUME_COMMIT_COUNTER",
        "EXTERNAL_NOTIFY_OUTBOX", "DRAIN_CQ", "WAIT_SQ", "CQ_CONTENDED",
        "MAX_FILE_SIZE", "MAX_RESERVE_RETRIES = 64",
        "DonateBackingV1 MUST NOT appear on the ABI 2.1 wire",
    ],
    "03-messages.md": [
        "ControlHeader", "PREPARE_OPEN", "COMMIT_OPEN", "QUERY_OP",
        "ACK_RESULT", "NotifyEnvelopeV2", "PrepareOpenV2", "CommitOpenV2",
        "CommitOpenResultV2", "WriteV2", "WriteResultV2", "MutationV2",
        "MutationResultV2", "RenameResultV2", "LinkResultV2", "QueryDirV2",
        "QueryOpV2", "ReplayOpenV2", "AckResultV2", "AbortOpenV1",
        "operation_digest", "enumeration_generation", "DIR_CHANGE_ACK",
        "0x0052", "PT_LANE_READY", "EXTERNAL_CHANGE_READY",
        "EXTERNAL_CHANGE_CUT", "ExternalDirChangeV1", "PDirChangeAckV1",
        "PtLaneReadyV1", "ExternalChangeReadyV1", "ExternalChangeCutV1",
        "ProtocolAbortV1", "ABORT_SESSION", "CommittedResultV1",
        "FSRING-OP-DIGEST", "ABORT_IF_PREPARED", "OPEN_FAILURES",
        "MUTATE_FAILURES", "volume_commit_sequence", "CASE_SENSITIVE_NAMES",
        "NotifyEnvelopeV1 MUST NOT appear on the ABI 2.1 wire",
        "AckResultV1 MUST NOT appear on the ABI 2.1 wire",
        "QueryDirV1 MUST NOT appear on the ABI 2.1 wire",
        "MutationV1 MUST NOT appear on the ABI 2.1 wire",
    ],
    "04-object-model.md": [
        "FileId", "LinkId", "kernel_open_id", "provider_open_cookie",
        "namespace_generation", "volume_commit_sequence", "BOUND_RECONCILING",
        "ccb_sequence", "security_generation", "size_epoch", "session_epoch",
        "TransactionId", "REPLAY_STATE_PAGING_ONLY", "LCB",
        "stream-admission gate", "MAX_RETAINED_OPENS_PER_RING",
        "MAX_RETAINED_OPENS_PER_MOUNT", "MAX_RETAINED_OPENS_GLOBAL",
        "retire_mount_state", "CLEANED never admits ordinary CCB work",
    ],
    "05-irp-dispatch.md": [
        "PrepareOpenV2", "CommitOpenV2", "WriteV2", "MutationV2",
        "QueryDirV2", "CLEANUP barrier", "STATUS_INVALID_USER_BUFFER",
        "DO_DIRECT_IO", "PREPARE_MAY_BE_VISIBLE", "PREPARE_SUCCEEDED",
        "AbortOpenV1", "ABORT_IF_PREPARED", "REPLAY_OPEN", "QUERY_OP",
        "CANDIDATE_CAPTURE", "COMMITTED_VERIFIED", "APPLIED_NOTIFY_PENDING",
        "ACKNOWLEDGED", "INDETERMINATE", "CLEANUP_PENDING",
        "POST_CLEANUP_HELD", "DRAIN_REPLAY", "CLOSE_PENDING",
        "MAX_PENDING_ASYNC_IRPS_PER_IO_OWNER",
        "MAX_PENDING_ASYNC_MDL_BYTES_GLOBAL", "MmGetSystemAddressForMdlSafe",
        "MdlMappingNoExecute", "IoMarkIrpPending", "enumeration_generation",
        "ACTIVE_AT_START", "MAX_QUERY_DIR_IRPS_PER_CCB",
        "STATUS_NOTIFY_ENUM_DIR", "IoCsqInsertIrpEx", "NotifyIrpContext",
        "STATUS_IO_DEVICE_ERROR", "0xc0000185", "OPEN_FAILURES", "PCancel",
        "MUST NOT emit FSCTL", "SL_INDEX_SPECIFIED",
        "FsRtlIsNameInExpression",
    ],
    "06-locking.md": [
        "no ERESOURCE", "daemon wait", "ccb_sequence", "TRUNCATING",
        "one terminal-owner CAS", "PT rundown", "BOUND_RECONCILING",
        "lifecycle-admission", "size gate", "AdvanceOnly CSQ",
        "sole-consumer token", "DETACHED_HANDLER", "semantic_may_be_visible",
        "cancel_requested", "APPLYING", "ApplyReserve",
        "MAX_APPLY_DOMAINS_PER_OPERATION", "DIRECTORY_NAMESPACE",
        "OPEN_STATE", "notify_fence_generation", "sq_wait_owner",
        "CSQ spin lock",
    ],
    "07-cache-mm.md": [
        "MAX_FILE_SIZE", "AllocationSize", "ValidDataLength", "size_epoch",
        "CcSetFileSizes", "CcInitializeCacheMap", "CcCopyRead", "CcCopyWrite",
        "CcPurgeCacheSection", "CcFlushCache", "MmFlushImageSection",
        "MmCanFileBeTruncated", "STATUS_USER_MAPPED_FILE", "TRUNCATING",
        "paging-write issue", "WriteIrpContext", "last_issued", "AdvanceOnly",
        "target_vdl", "MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_FCB",
        "MAX_PENDING_ADVANCE_ONLY_IRPS_PER_FCB", "SectionObjectPointers",
        "INVALIDATE_FILE", "INVALIDATE_ENTRY", "CcUninitializeCacheMap",
        "MmForceSectionClosed", "AcquireFileForNtCreateSection",
    ],
    "08-passthrough.md": [
        "DonateBackingV2", "IO_STOP_ON_SYMLINK", "FILE_OPEN_REQUIRING_OPLOCK",
        "PT_LANE_READY", "pt_epoch", "BOUND_RECONCILING", "OBJ_KERNEL_HANDLE",
        "MmDoesFileHaveUserWritableReferences", "MmCanFileBeTruncated",
        "FSCTL_REQUEST_OPLOCK", "STOPPED_ON_SYMLINK",
        "MAX_OPENING_BACKING_ATTEMPTS_PER_MOUNT", "OPENING", "ISOLATING",
        "BREAKING_CLOSED", "REVOKED", "CANCEL_DRAINING", "RING", "GRANTING",
        "PT_ACTIVE", "REVOKING", "PT_GRANT", "PT_REVOKE_ROUTE",
        "PT_EXTERNAL_MUTATION_SAFE", "PT_ROUTE_ACK", "PT_EXTERNAL_SAFE_ACK",
        "PtGrantV1", "PtEpochV1", "PtComplete", "IoFreeIrp",
    ],
    "09-security.md": [
        "SlotToken", "K2U_READ_ONLY", "U2K_WRITE", "RequestorMode", "EPROCESS",
        "checked arithmetic", "MdlMappingNoExecute", "quarantine",
        "protocol fault", "SeAccessCheck", "QuerySecurityV1", "SetSecurityV1",
        "DonateSecurityContextV1", "TOKEN_DONATION is unselectable",
        "security_information", "RtlValidRelativeSecurityDescriptor",
        "SessionProtocolFault",
    ],
    "10-lifecycle.md": [
        "ReplayOpenV2", "QueryOpV2", "AckResultV2", "BootContextHeaderV1",
        "BOOT_CONTEXT_MAGIC", "RESTART_GRACE_TIMEOUT_MS", "RetireMountV1",
        "RetireMountResultV1", "RetireToken", "StateToken", "BOUND_RECONCILING",
        "MountId", "BootInstanceId", "session_epoch", "volume_commit_sequence",
        "fresh rings", "ProviderMountRootV1", "DurableChildValueV1",
        "OpenRecoveryPayloadV1", "PrepareRecoveryPayloadV1", "EXACTLY_ONCE",
        "service SID", "TEARDOWN", "operation_digest",
        "REPLAY_STATE_PAGING_ONLY", "CLEANUP_PENDING", "AttachV1",
    ],
    "11-rust-implementation.md": [
        "platform-win10", "platform-win7", "Windows 10 1507",
        "Windows 10 1709", "Windows 7 SP1", "MmGetSystemRoutineAddress",
        "Rust 1.82", "no_std", "panic=abort", "SEH", "BCryptGenRandom",
        "NonPagedPoolNx", "ExAllocatePoolWithTag", "MdlMappingNoExecute",
        "MdlMappingNoWrite", "ZwMapViewOfSection", "PAGE_READONLY",
        "PAGE_READWRITE", "HVCI", "Static Driver Verifier", "llvm-readobj",
        "checked arithmetic", "fallible", "fsring-abi/", "IoCompleteRequest",
    ],
    "12-test-plan.md": [
        "Rust 1.82", "MSVC x64", "clang-cl ARM64", "Win7 SP1 x64",
        "Windows 10 1507", "Windows 11 ARM64", "Driver Verifier",
        "Special Pool", "deadlock detection", "low-resource", "HLK", "10,000",
        "24-hour", "p99.9", "90%", "80%", "5%", "10%", "differential", "Loom",
        "Miri", "cargo fuzz", "allowlist", "winfsp-tests",
    ],
}
FORBIDDEN = ["gen:16", "idx:48", "NOTIFY_BIT", "bounded MPMC", "v1.0-draft"]
FORBIDDEN_BY_DOC = {
    "02-transport.md": [
        "normative for FSRING ABI v2.0",
        "MAX_RESERVE_RETRIES = 16",
        "at most 16 reservation attempts",
        "used all 16 reservation attempts",
        "authoritative-registry gap",
        "addressing MUST remain unnegotiated",
        "optional notification-name arena",
        "negotiated notification-name region",
        "validates ABI 2.0",
    ],
    "03-messages.md": [
        "PControl → PrepareOpenV1",
        "PControl → CommitOpenV1",
        "PControl → MutationV1",
        "PControl → QueryOpV1",
        "PControl → AckResultV1",
        "NotifyEnvelopeV1.notify_code",
        "Returned for READ and WRITE",
        "the ABI v2.0 source registry",
        "A v2.0 sender",
        "- 21 opcodes;",
        "- 7 notification codes;",
        "- 9 protocol-feature bits and 4 OS-capability bits;",
    ],
    "04-object-model.md": [
        "Trạng thái: STABLE", "OP_CREATE", "OP_CLOSE", "FSS_DISPO",
        "FcbTableLock", "NT_INVALIDATE_FILE", "FSQ_CANON", "PCreate",
        "FEAT_CASE_SENSITIVE", "doc 03 §",
    ],
    "05-irp-dispatch.md": [
        "Trạng thái: STABLE", "OP_READ", "OP_WRITE", "OP_QUERY_DIR",
        "OP_CLEANUP", "FSS_RENAME", "FSS_EOF", "NT_DIR_CHANGE",
        "FEAT_NOTIFY_NAMES", "FEAT_REPARSE", "NOTIFY_SYNC", "doc 03 §",
    ],
    "06-locking.md": [
        "Trạng thái: STABLE", "FCB.MainResource", "FCB.PagingIoResource",
        "FcbTableLock", "sync-wait", "ORw", "FSS_RENAME", "doc 03 §",
    ],
    "07-cache-mm.md": [
        "Trạng thái: STABLE", "doc 05 §", "doc 03 §", "doc 02 §", "doc 04 §",
        "doc 08 §", "NT_INVALIDATE_FILE",
    ],
    "08-passthrough.md": [
        "Trạng thái: STABLE", "OP_CREATE", "OP_CLEANUP", "OP_CLOSE",
        "NT_GRANT_PT", "NT_REVOKE_PT", "OP_REVOKE_ACK", "FSQ_CANON",
        "doc 03 §", "doc 05 §", "doc 07 §", "doc 01 §",
    ],
    "09-security.md": [
        "Trạng thái: STABLE", "PCreate.token", "FEAT_TOKEN_DONATION",
        "OP_QUERY_SECURITY", "FEAT_SECURITY", "PSec", "doc 02 §", "doc 04 §",
        "doc 03 §",
    ],
    "10-lifecycle.md": [
        "Trạng thái: STABLE", "ENTER_REPLAY", "OP_REPLAY_OPEN", "PReplayOpen",
        "OCreate", "FEAT_HOT_RESTART", "volume_guid", "grace_ms",
        "48-bit idx", "doc 01 §", "doc 02 §", "doc 03 §", "doc 05 §",
        "doc 08 §", "doc 09 §",
    ],
    "11-rust-implementation.md": [
        "Trạng thái: STABLE", "ERESOURCE", "PSetInfo", "grace_ms", "doc 02 §",
        "doc 03 §", "doc 06 §", "doc 09 §", "doc 12 §",
    ],
    "12-test-plan.md": [
        "Trạng thái: STABLE", "NT_INVALIDATE_FILE", "FEAT_SECURITY",
        "doc 02 §", "doc 06 §", "doc 08 §", "doc 10 §", "doc 11 §",
    ],
}


# --- C4 source-complete contract ------------------------------------------
#
# Required tokens name behavior a local gate actually proves. Stale tokens are
# the C3-era claims the same documents used to make: a document that still says
# SETUP is unsupported, or that one device serves both roles, is describing an
# image that no longer exists.
C4_REQUIRED = {
    "01-principles-architecture.md": [
        "IMPLEMENTED_PROTOCOL_MASK", "four native object roles",
        "FILE_DEVICE_VIRTUAL_DISK", "device-kind tag",
    ],
    "02-transport.md": [
        "twenty-three effects", "PublishActive", "PreserveBurnedMountId",
        "view_count = 2 + 3 * ring_count", "48 + credit_count * 32",
        "MAX_NOTIFICATION_CREDIT_SIZE",
    ],
    "04-object-model.md": [
        "owning generation registry",
        "SessionLocator",
        "access rundown",
        "ClosingSetup",
        "ClosingLive",
        "state-minted request identity",
        "EnterExecutionDomain",
        "PublicationFailStopWitness",
        "MountOwner",
        "FenceTerminalBlocked",
        "DeleteTerminalBlocked",
    ],
    "06-locking.md": [
        "HandoffDoneReceipt",
        "CSQ dequeue receipt",
        "PendingTimerCancel",
        "TimerState",
        "dpc_exited",
        "no-lock-bearing",
        "TerminalJoinersDrainedSignal",
        "queue_cell_finalizer",
    ],
    "05-irp-dispatch.md": [
        "fsring_dispatch_provider", "fsring_dispatch_mount",
        "fsring_dispatch_verify", "closed `match`", "VPB_MOUNTED",
        "STATUS_VOLUME_DISMOUNTED",
    ],
    "09-security.md": [
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)", "{92AC3ED3-4505-42D5-A81C-901212229852}",
        "{201DC259-6F66-4682-A3CD-04CCEBE3D8B2}", "FsRingVolume-",
        "validate_header_directory_v21", "never authority",
    ],
    "10-lifecycle.md": [
        "six-stage fence", "fsring_session_fence", "producer-writable",
        "survive to stage 6", "process-exit callback",
        "publication fail-stop",
        "fence fail-stop",
        "delete fail-stop",
    ],
    "11-rust-implementation.md": [
        "adapter::setup", "adapter::enter", "adapter::volume",
        "PendingCqHeadAdvance", "audit_c4_imports.py", "audit_c4_stack.py",
        "permission is not presence",
        "KeExpandKernelStackAndCallout", "expansion root",
        "KernelFenceOps",
        "FenceKernelDdi",
    ],
    "12-test-plan.md": [
        "C4_SOURCE_COMPLETE", "C4_NATIVE_VERIFIED", "fsring-control-smoke/v2",
        "27-probe roster", "unload-transients", "pending",
        "c4-recovery-logs",
        "c4-recovery-native",
    ],
}

C4_STALE = {
    "01-principles-architecture.md": [
        "a single control device object serves",
    ],
    "02-transport.md": [
        "SETUP returns NOT_SUPPORTED",
        "ENTER returns NOT_SUPPORTED",
    ],
    "04-object-model.md": [
        "a raw session pointer is published",
        "caller-supplied invocation",
    ],
    "06-locking.md": [
        "the installer performs the noncancel dequeue",
        "final publication returns a lock",
        "terminal CAS before the dequeue",
    ],
    "05-irp-dispatch.md": [
        "no VDO can exist",
        "mount and verify are refused",
    ],
    "10-lifecycle.md": [
        "no session can exist",
        "the fence wait is a no-op",
        "a fail-stop counts as drained",
    ],
    "12-test-plan.md": [
        "C4_NATIVE_VERIFIED is established by the local gates",
        "a live verify has been performed",
        "the harness emits the public v2 report",
        "native verification passed",
    ],
}

# --- C4 recovery contract (Task 28) ---------------------------------------
#
# The documents above describe behaviour. This section checks the *recovery*
# claims: that the normative set names what the recovered source actually does,
# that the two parent review gates were superseded rather than rewritten, and
# that the machine-readable surfaces the Task 29 battery executes are the ones
# verifier independently expects.
#
# Every roster below is a literal maintained here on purpose. A verifier that
# derived them from the manifest or the auditor would agree with whatever those
# files said, which is not a check.

REVIEW_ROOT = REPO_ROOT / "docs" / "superpowers" / "reviews"
RECOVERY_GATE = REVIEW_ROOT / "2026-08-08-driver-c4-recovery-gate.md"

# The profile a final source state must select, and the three imports manifests
# whose direct count the gate document states. Spelled here rather than derived
# from the document, so the document cannot be its own oracle.
C4_FINAL_PROFILE = "r5-cutover"
C4_IMPORT_MANIFESTS = (
    "c4-imports-win10-x64.json",
    "c4-imports-win10-arm64.json",
    "c4-imports-win7-x64.json",
)
# Prose states a count in words; this is the mapping the check compares through.
# Only the counts this gate could legitimately reach are listed: a profile that
# grew past four gates would fail the lookup rather than silently pass.
C4_LIVE_GATE_WORDS = {
    1: "**One** is live at the final",
    2: "**Two** are live at the final",
    3: "**Three** are live at the final",
    4: "**Four** are live at the final",
}
DESIGN_SPEC_ROOT = REPO_ROOT / "docs" / "superpowers" / "specs"
PARENT_GATES = (
    REVIEW_ROOT / "2026-08-07-driver-c4-1a-gate.md",
    REVIEW_ROOT / "2026-08-08-driver-c4-2-gate.md",
)
# Task 28 never edits or stages the approved design; it is the read-only oracle
# every other document is reconciled against.
APPROVED_DESIGN = (
    REPO_ROOT / "docs" / "superpowers" / "specs"
    / "2026-08-08-fsring-driver-c4-recovery-design.md"
)
SOURCE_GATES = REPO_ROOT / "driver" / "audit" / "c4-source-gates.json"
PRODUCTION_GRAPH = REPO_ROOT / "driver" / "audit" / "c4-production-graph.json"
GITATTRIBUTES = REPO_ROOT / ".gitattributes"
GITIGNORE = REPO_ROOT / ".gitignore"

# The six cutover gate names, in checkpoint order.
C4_GATE_NAMES = (
    "task09_11_r3_staging_is_production_unreachable",
    "task12_r3_cutover_has_exactly_one_terminal_delete_path",
    "task13_18_r4_staging_is_production_unreachable",
    "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path",
    "task20_24_r5_staging_is_production_unreachable",
    "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path",
)
# The two mandatory auditor self-test cases the graph gate must carry.
C4_AUDITOR_SELF_TESTS = (
    "production_graph_auditor_rejects_duplicate_and_bypass_edges",
    "production_graph_auditor_rejects_primary_staged_route_edges",
)

# The approved design's section 16 zero-result table, in its own order. It is 53
# entries, not 47: the six-entry superseded R2/R3 predecessor ownership row was
# missing from the final gate until Task 28, and six plants proved the final
# gate could not see any of them. `DriverState.mounts` is carried as the
# substring `.mounts`, which is how the Task 12 gate has always implemented that
# same design entry.
C4_ZERO_ROSTER = (
    "run_checkpoint_teardown",
    "finish_checkpoint_teardown",
    "R3TeardownComplete",
    "R3AuthorityAbsence",
    "R3PreparedCheckpointFinish",
    "R3PreparedCheckpointFinish::prepare",
    "R3FenceIncomplete",
    "R3DeletionReadiness",
    "R3FinalizerDeposit",
    "R4TeardownComplete",
    "R4AuthorityAbsence",
    "R4PreparedCheckpointFinish",
    "R4PreparedCheckpointFinish::prepare",
    "R4ResidualLedger",
    "R4FenceIncomplete",
    "R4FenceIncomplete::BaseRefusal",
    "R4FenceIncomplete::PendingRefusal",
    "R4FenceIncomplete::PublicationBlocked",
    "R4DeletionReadiness",
    "R4FinalizerDeposit",
    "PrepareCheckpointFinish",
    "CheckpointTerminalBlocked",
    "CheckpointTerminalBlocked::R3",
    "CheckpointTerminalBlocked::R4",
    "MountRegistry",
    ".mounts",
    "claim_by_process",
    "fence_all",
    "live_count",
    "fence_bound_session",
    "run_provisional_fence",
    "LegacyCompletedFenceAdapter",
    "LegacyFinalizerDepositView",
    "LegacyFenceNotRepresentable",
    "LegacyCompletedFenceAdapter::from_completed_only",
    "LegacyCompletedFenceAdapter::try_from_outcome",
    "publish_installed_setup_legacy",
    "LegacyProviderDisposition",
    "split_legacy_provider_disposition",
    "ALLOW_CHECKPOINT_TEARDOWN_PRODUCTION_EDGE",
    "ALLOW_LEGACY_SETUP_PUBLISHER_PRODUCTION_EDGE",
    "ALLOW_LEGACY_PROVIDER_DISPOSITION_PRODUCTION_EDGE",
    "ALLOW_PROVISIONAL_FENCE_PRODUCTION_EDGE",
    "run_terminal -> run_checkpoint_teardown",
    "run_terminal -> R3PreparedCheckpointFinish::prepare",
    "run_terminal -> R4PreparedCheckpointFinish::prepare",
    "run_terminal -> finish_checkpoint_teardown",
    "run_terminal -> run_provisional_fence",
    "run_provisional_fence -> package_completed_fence",
    "run_provisional_fence -> LegacyCompletedFenceAdapter::from_completed_only",
    "LegacyCompletedFenceAdapter::try_from_outcome -> LegacyFinalizerDepositView::Completed",
    "execute_setup -> publish_installed_setup_legacy",
    "fsring_dispatch_provider -> split_legacy_provider_disposition",
)

# The twenty frozen executable roles, in the order the runner resolves them.
C4_TOOL_ROLES = (
    "powershell", "python", "git", "git-bash", "cmd",
    "cargo-1.82.0", "rustc-1.82.0", "rustdoc-1.82.0",
    "cargo-fmt-1.82.0", "rustfmt-1.82.0",
    "cargo-1.85.0", "rustc-1.85.0", "rustdoc-1.85.0",
    "cargo-fmt-1.85.0", "rustfmt-1.85.0",
    "cargo-clippy-1.85.0", "clippy-driver-1.85.0",
    "cargo-wdk-0.1.1", "infverif", "signtool",
)
C4_NATIVE_MODES = (
    "Inspect", "Authorize", "Run", "SealNotRun", "CleanupOnly", "SelfTest",
)
C4_RECORDER_MODES = (
    "RecordSourceAttempt", "FinalizeSourceReview", "WithdrawSourceCandidate",
    "RecordNativeAttempt", "SelfTest",
)
C4_EVIDENCE_TEXT_ATTRIBUTES = (
    "docs/superpowers/reviews/evidence/c4-recovery-logs/** -text",
    "docs/superpowers/reviews/evidence/c4-recovery-native/** -text",
)
C4_ZIP_NEGATIONS = (
    "!docs/superpowers/reviews/evidence/c4-recovery-logs/attempt-*/artifacts/archives/fsring-abi.zip",
    "!docs/superpowers/reviews/evidence/c4-recovery-logs/attempt-*/artifacts/archives/fsring-spec.zip",
)

# The 21 ordered verdict-table row IDs: parent C4 section 13 items 1-10, then
# recovery section 16 items 1-11, with nothing between them.
C4_VERDICT_ROW_IDS = tuple(
    ["P%02d" % n for n in range(1, 11)] + ["R%02d" % n for n in range(1, 12)]
)
C4_VERDICT_HEADING = "| rowId | requirementSha256 | proofRefs | verdict | residual |"


def _canonical_gate_row(row):
    """The exact record the runner and this verifier both hash."""
    import json as _json

    ordered = {key: row[key] for key in C4_SOURCE_GATE_KEYS}
    return _json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# The 38 ordered source-battery rows and the SHA-256 of each canonical
# (id,argv,cwd,toolchain,expectedExit,timeout,stdout,stderr,exit) record,
# maintained here independently of the manifest that carries them.
EXPECTED_C4_SOURCE_GATE_ROWS = (
    ("source-runner-selftest", "7ac05d27367ac0763c7bf162c02590e34bf385db62fe99e2d44b06784d798058"),
    ("capture-helper-selftest", "1ae836766a3070ca1a9c7ba99beaf6408220085c1720098cc45fb57c7adb3702"),
    ("root-fmt", "f865765a60aa8cb51cc5429b0d28ac0c1e35ed1f1e2059c86750ba4274ee402d"),
    ("root-check", "94f4c79a5c3732e301b240073c9486bd7d7b19b0054e5f18de2477e4aac9881d"),
    ("root-test", "3cd679894863bce8c9370b78e49e47b42958be663a99c9a64ed667dd6adc3586"),
    ("driver-fmt", "10b096641c2a5425867d7b8ef6dbba50190d482d9adf015066d981b537c50581"),
    ("driver-core-clippy", "7bff44c650f5ca439d0967f7d5a2fcef905b524fac5624abea0780bde545c8f1"),
    ("driver-core-test", "b2619beb4bb05ffbb7a7f39580734529b16c41715d9d7a7ebe45c7ea51121e0d"),
    ("c2-boundary", "6749582576f598091e25dddd72a8d51e8fb23a273b5ca03be193a600ff0db598"),
    ("b5-manifest", "75d4349113fbe83fc6ff81a183a2caea18175eea2b72622f1a9a8ee28c57a237"),
    ("compile-fail", "762f1e0f95fe9469a727e133f3a7bb16103c33719d534a144f97af75504fedb3"),
    # `--no-resume` added 2026-08-30: an interrupted battery left a journal
    # keyed to this exact tree, and the next attempt's row 12 replayed all 369
    # verdicts in seconds and still sealed PASS. Row 14 already carried the flag
    # for the same reason; this row had the identical exposure one row over.
    ("mutation-default", "5a6ae023685fda4f4c22f226e3e2ff862a50e380a84ef7c289cd9908648188b8"),
    ("mutation-c4-list", "4a6d0ed0b70bdb0c3b2c9cbb0ce58ab47715f1f4c32bdfed132ab55bbb76af3b"),
    ("mutation-c4", "7089b0fa98324ff9a237cd5840fec81b001144d86e88d2168a90d3171397a0a1"),
    ("lifetime-selftest", "651d02dfc29a0d0878899253f7df43021cf8ae6eab842a809992168991957ffb"),
    ("lifetime-source", "3d447fbe75f258e10d8a23774b5aaa3486e0858bbf4f6b8bba5c8be4f3c46343"),
    ("imports-selftest", "0e83be237402e1c2cdebc0761239acdb8b4384e33403af646bdc3409b620b9b2"),
    ("stack-selftest", "e51ea0df21b4dda7d506760bb50002d66e0446f968324400ad96352ade04cca2"),
    ("matrix-selftest", "b9759bc3e7930a9392255dcb41d2dde8a7bcb3965e3fe5811f50a04b5add96fd"),
    ("matrix-three-profile", "7c5d10bef26d965fb8e89718655e69459a27c72adf11688692da8e55dcc757b0"),
    ("package-win10-x64", "3a2a109537f4c6ee7037591b7a83ba26aa6772823310001dc2ca5dc62139897a"),
    ("package-selftest", "6aa557c73dafbb88396c52ab943304c9fa9afe3516b1fc749feee786c0afa540"),
    ("smoke-selftest", "9b84d97a65b093f2b3d1c292d79759dc22f42c2acfadc8ee47935fa38ab7d88d"),
    ("native-session-test", "4dc3dd158dadf39ba55d511b975abe02a7f49e78bdfd8ab656c51d1a0a0de87b"),
    ("smoke-v2-test", "effc4dc6f2f8a531f0ab28fc3351a463e6bd2cbb4e7ff00eb8a9f667e32634da"),
    ("smoke-live-test", "c44f947637d47d4cb17680bf23733c3c03ad015d55a691445a6b934143d0dd4f"),
    ("harness-win10-x64-release", "4dd9bd4682415827ef405e3dcf2d3ef857f128f1a7dc9b3154e2a16f9724e24e"),
    ("verify-spec", "b5592f23ce17299742ff1c308da24469b2c267871a0e471e276e51c586e0f43f"),
    ("verify-registry", "bd17401bf990f0973fe73642c8bcd486923a09411a278b18e4f1a5be329412a1"),
    ("archives-generate", "ddbefe20d7c7c00487c247056c37faffe0e5167b7b34b837f5eff72e07e50bfd"),
    ("archives-selftest", "ead94ca2a25796de27c0a006725d848ff4dfbad4aa22c235bb8790d9bc1f0f04"),
    ("archives-verify", "5362095b981b397f741d3482b4d08432a15f7985bc59922b312b9ee839c0b4b2"),
    ("production-graph-selftest", "56097bc5e240f0a2f9ca98d3e5dc3a4a0f7a024261b3d0e9f785d92d619a2406"),
    ("production-graph-final", "9595e8246d6b9794b50c5e09167a3fc6cda910a7062e9186ef3588e3507ccaca"),
    ("diff-check", "a2cbe231199ac182495cfd876e4f6b4409eafc7f595b50461b13212675989249"),
    ("clean-close", "2583d608783dd12d4eba910f514bf1d05fccd5eaf8498d71fb62ea01a86d381f"),
    ("head-close", "f681e4d855dc40c7b9ff70e96662c917154ec2626a2fdb1003912701f3d632a9"),
    ("tree-close", "c455e1ea99495dc81d3001b78b8c408cf58f68d53c742242e466cb130e40aa6e"),
)

C4_SOURCE_GATE_KEYS = (
    "id", "argv", "cwd", "toolchain", "expectedExit",
    "timeoutSeconds", "stdout", "stderr", "exit",
)


# The parent C4 section 13 and recovery section 16 requirements, hashed from
# their canonical text. These literals are maintained here; the recovery gate
# document carries its own independent copy; and the function below recomputes
# both from the two approved designs. Three copies have to agree, so editing a
# design, the gate, or this tuple alone turns the check red.
APPROVED_REQUIREMENT_SOURCES = (
    (DESIGN_SPEC_ROOT /
     "2026-08-04-fsring-driver-c4-native-session-transport-foundation-design.md",
     "## 13. Definition of done", "P", 10),
    (DESIGN_SPEC_ROOT / "2026-08-08-fsring-driver-c4-recovery-design.md",
     "## 16. Definition of done", "R", 11),
)

EXPECTED_C4_REQUIREMENT_HASHES = (
    ("P01", "97fb718e0123e75bc7fa455c288e82acd26e5b0ec1fe330b7306ad107f20f8df"),
    ("P02", "971e6d439f8dca8287f8ed8770dcddb0feb49a92de0a315d3052f70b860ba660"),
    ("P03", "4d39c92b3cb39c9f4c1697fc5b36e66e0688aad5560c636d5e00a669be664c25"),
    ("P04", "817798804c8bb4544a708fd3a9c9d2b65d26085764336bd1bba72abbbeff49cc"),
    ("P05", "c3ad0dac90a9b6125ee98536f10d83de1bed13b7c27ec95c732e78046f25c9bd"),
    ("P06", "5fc2020dfb78c3c56b8a433a553dd18c45c2582b5461965814a53a7ec687d527"),
    ("P07", "ffa1a797081f95c5d2d615474d2d34fda354ef2e862b9c337a12eb0379ba0923"),
    ("P08", "ae4abf357b33860dfa83cfd5770a0e944b624686ffb863b2434e756317e93031"),
    ("P09", "0691db316d11630fa7580d45e017c6c30ac7dd32bce58a9bd5580bdbcfa2be72"),
    ("P10", "5ab34b2ae12e56b2024f7122c12bbdf058e3e103607d5751668eee5e9d45c7ca"),
    ("R01", "11420d81400792baef4cfa0222eeeecea191bbb050284c6b278a5ce2a6f5c911"),
    ("R02", "1953055a61198c444c74d5480c273f933fa2765d2d949395ad4f4ee39627320e"),
    ("R03", "c3cfc38de3f372df2929da5c365d39bff31a852f0c87f54a427aae50de068f8a"),
    ("R04", "283883db6b33c2e4f58795f9d7b96970dec28966acb30e31b0afabfeb2a53876"),
    ("R05", "241c3af721eccd44d6e84df34b580a63b347a6e1dce7e3eeabc349cb85bcca7f"),
    ("R06", "05fbccda1695d59e3a6a62481d574836c91c9077688425e6c464b938d980f7c3"),
    ("R07", "75b6c8d85f0f016a123dae86a02257e46519773935794e668a6848a3bb0be288"),
    ("R08", "b3e07c90255cbc38e192951ebd2b9ee3a9cb7f74221f26c732c671e5cf9d1e99"),
    ("R09", "d8c0170f6fb7d0d576d3af4795cd3be297f4d70000242ff0f9f25c67c40c097f"),
    ("R10", "ae385734ef533a7ca6edb0deeea13c79af6e056c2775cc588f1aee0451fd0660"),
    ("R11", "3c69a090c2b011132600a5e85d31744f9095aedfcca8b6ac34d72edbf5738538"),
)


def _canonical_requirement(text: str) -> str:
    """A requirement's canonical text.

    The list marker is dropped and every whitespace run -- including the
    newlines the design wraps at -- collapses to one space. Rewrapping a design
    must not move the hash; changing a word must.
    """
    return re.sub(r"\s+", " ", text).strip()


def _extract_requirements(path, heading: str, count: int) -> "list[str]":
    lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")
    start = None
    for index, line in enumerate(lines):
        if line.strip() == heading:
            start = index + 1
            break
    if start is None:
        raise ValueError("%s: heading %r not found" % (path.name, heading))
    items: list[str] = []
    current = None
    expected = 1
    for line in lines[start:]:
        if line.startswith("## ") and current is None and items:
            break
        marker = re.match(r"^(\d+)\.\s+(.*)$", line)
        if marker and int(marker.group(1)) == expected:
            if current is not None:
                items.append(current)
            current = marker.group(2)
            expected += 1
            if len(items) == count:
                break
            continue
        if current is not None:
            if line.strip() == "":
                items.append(current)
                current = None
                if len(items) == count:
                    break
                continue
            current += " " + line.strip()
    if current is not None and len(items) < count:
        items.append(current)
    if len(items) != count:
        raise ValueError(
            "%s: found %d requirements under %r, expected %d"
            % (path.name, len(items), heading, count))
    return items


def requirement_hash_errors(gate_text) -> "list[str]":
    """Recompute the 21 requirement hashes and hold three copies to agreement."""
    import hashlib

    errors: list[str] = []
    computed: list[tuple] = []
    for path, heading, prefix, count in APPROVED_REQUIREMENT_SOURCES:
        if not path.is_file():
            errors.append("%s: missing approved design" % path.name)
            return errors
        try:
            items = _extract_requirements(path, heading, count)
        except ValueError as error:
            errors.append(str(error))
            return errors
        for index, text in enumerate(items, start=1):
            canonical = _canonical_requirement(text)
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            computed.append(("%s%02d" % (prefix, index), digest))

    if len(computed) != len(EXPECTED_C4_REQUIREMENT_HASHES):
        errors.append(
            "recomputed %d requirement hashes, expected %d"
            % (len(computed), len(EXPECTED_C4_REQUIREMENT_HASHES)))
        return errors
    for (row_id, digest), (expected_id, expected_digest) in zip(
            computed, EXPECTED_C4_REQUIREMENT_HASHES):
        if row_id != expected_id:
            errors.append("requirement row %s is out of order (expected %s)"
                          % (row_id, expected_id))
            continue
        if digest != expected_digest:
            errors.append(
                "%s: the approved requirement text no longer hashes to the frozen "
                "value; the design changed, or this literal is stale" % row_id)
    if gate_text is None:
        return errors
    # The gate document's own literal must agree with the recomputed value on
    # the same row. A row present with a different hash is the interesting
    # failure; a missing row is already caught by the row-ID check.
    for row_id, digest in computed:
        marker = "| %s | " % row_id
        position = gate_text.find(marker)
        if position < 0:
            continue
        claimed = gate_text[position + len(marker):position + len(marker) + 64]
        if claimed != digest:
            errors.append(
                "%s: the recovery gate's requirementSha256 does not match the "
                "approved requirement text" % row_id)
    return errors

def recovery_errors() -> "list[str]":
    """Task 28's recovery contract, checked against independent literals."""
    import hashlib
    import json

    errors: list[str] = []

    def read(path):
        try:
            return path.read_text(encoding="utf-8", errors="strict")
        except OSError:
            errors.append("%s: missing file" % path.name)
            return None

    # 1. The approved design is a read-only oracle. Task 28 has no output path
    #    into it, so its absence -- or a `## Task 28` heading written into it --
    #    is a refusal rather than a silent edit.
    design = read(APPROVED_DESIGN)
    if design is not None and "\n## Task 28" in design:
        errors.append(
            "%s: the approved recovery design is a read-only oracle and must not "
            "carry Task 28 output" % APPROVED_DESIGN.name
        )

    # 2. The two parent review gates keep their original verdict and gain only a
    #    dated supersession cross-reference. A rewritten verdict is the failure
    #    this check exists for.
    for path in PARENT_GATES:
        text = read(path)
        if text is None:
            continue
        if "## 1. Verdict" not in text:
            errors.append("%s: the historical verdict section was removed" % path.name)
        if "2026-08-08-driver-c4-recovery-gate.md" not in text:
            errors.append(
                "%s: missing the dated supersession cross-reference to the "
                "recovery gate" % path.name
            )
        if "Superseded" not in text:
            errors.append("%s: missing the 'Superseded' cross-reference" % path.name)

    # 3. The recovery gate document: 21 ordered rows, both rosters, and the six
    #    gate names.
    gate = read(RECOVERY_GATE)
    if gate is not None:
        if C4_VERDICT_HEADING not in gate:
            errors.append(
                "%s: missing the exact verdict table heading" % RECOVERY_GATE.name
            )
        seen = [row for row in C4_VERDICT_ROW_IDS if ("| %s |" % row) in gate]
        if len(seen) != len(C4_VERDICT_ROW_IDS):
            missing = [row for row in C4_VERDICT_ROW_IDS if row not in seen]
            errors.append(
                "%s: verdict table is not the 21 ordered rows; missing %r"
                % (RECOVERY_GATE.name, missing)
            )
        for name in C4_GATE_NAMES:
            if name not in gate:
                errors.append("%s: missing gate name %r" % (RECOVERY_GATE.name, name))
        for name in C4_AUDITOR_SELF_TESTS:
            if name not in gate:
                errors.append(
                    "%s: missing mandatory auditor self-test %r"
                    % (RECOVERY_GATE.name, name)
                )
        for entry in C4_ZERO_ROSTER:
            if entry not in gate:
                errors.append(
                    "%s: missing zero-roster entry %r" % (RECOVERY_GATE.name, entry)
                )
        if "47-entry" in gate:
            errors.append(
                "%s: the final zero roster is the design's 53 entries, not 47"
                % RECOVERY_GATE.name
            )

        # The two numbers this document states about other artifacts, checked
        # against those artifacts rather than trusted. Both drifted: the live
        # gate count was cut to two by `c235564`, three days before this file
        # was frozen saying three, and the import census moved 99 -> 101 -> 102
        # inside this recovery. Neither was read by anything until now, which is
        # the whole reason both survived to a sealed review.
        graph_for_gate = read(PRODUCTION_GRAPH)
        if graph_for_gate is not None:
            try:
                parsed = json.loads(graph_for_gate)
            except ValueError:
                parsed = None
            if parsed is not None:
                profile = parsed.get("profiles", {}).get(C4_FINAL_PROFILE)
                live = len(profile.get("gates", ())) if isinstance(profile, dict) else None
                if live is None:
                    errors.append(
                        "%s: declares no %s profile to count live gates from"
                        % (PRODUCTION_GRAPH.name, C4_FINAL_PROFILE)
                    )
                else:
                    stated = C4_LIVE_GATE_WORDS.get(live)
                    if stated is None or stated not in gate:
                        errors.append(
                            "%s: the %s profile declares %d live gates and the "
                            "gate document does not say so"
                            % (RECOVERY_GATE.name, C4_FINAL_PROFILE, live)
                        )
        counts = set()
        for name in C4_IMPORT_MANIFESTS:
            manifest_text = read(REPO_ROOT / "driver" / "audit" / name)
            if manifest_text is None:
                continue
            try:
                counts.add(len(json.loads(manifest_text).get("direct", ())))
            except ValueError:
                errors.append("%s: is not valid JSON" % name)
        if len(counts) > 1:
            errors.append(
                "the three imports manifests disagree on their direct count: %r"
                % (sorted(counts),)
            )
        elif len(counts) == 1:
            direct = counts.pop()
            if ("carries **%d** direct imports" % direct) not in gate:
                errors.append(
                    "%s: the imports manifests carry %d direct imports and the "
                    "gate document does not say so" % (RECOVERY_GATE.name, direct)
                )

    errors.extend(requirement_hash_errors(gate))

    # 4. The tracked production graph must carry the same 53-entry roster and
    #    all six gate names. This verifier is the third party: the auditor and
    #    the manifest already agree with each other by construction.
    graph_text = read(PRODUCTION_GRAPH)
    if graph_text is not None:
        try:
            graph = json.loads(graph_text)
        except ValueError as error:
            errors.append("%s: is not valid JSON (%s)" % (PRODUCTION_GRAPH.name, error))
            graph = None
        if graph is not None:
            declared = tuple(graph.get("gates", {}))
            for name in C4_GATE_NAMES:
                if name not in declared:
                    errors.append(
                        "%s: does not declare gate %r" % (PRODUCTION_GRAPH.name, name)
                    )
            final = graph.get("gates", {}).get(C4_GATE_NAMES[5], {})
            roster = tuple(final.get("zeroRoster", ()))
            if roster != C4_ZERO_ROSTER:
                errors.append(
                    "%s: the final zeroRoster is not the approved 53-entry table "
                    "(%d entries)" % (PRODUCTION_GRAPH.name, len(roster))
                )

    # 5. The 38-row source battery, checked row by row against independent
    #    canonical-record hashes rather than against the file it is describing.
    gates_text = read(SOURCE_GATES)
    if gates_text is not None:
        try:
            document = json.loads(gates_text)
        except ValueError as error:
            errors.append("%s: is not valid JSON (%s)" % (SOURCE_GATES.name, error))
            document = None
        if document is not None:
            if list(document) != ["schema", "workingDirectory", "commands"]:
                errors.append(
                    "%s: root keys must be exactly schema, workingDirectory, commands"
                    % SOURCE_GATES.name
                )
            if document.get("schema") != "fsring-c4-source-gates/v1":
                errors.append("%s: wrong schema" % SOURCE_GATES.name)
            if document.get("workingDirectory") != ".":
                errors.append("%s: workingDirectory must be '.'" % SOURCE_GATES.name)
            rows = document.get("commands", [])
            if len(rows) != len(EXPECTED_C4_SOURCE_GATE_ROWS):
                errors.append(
                    "%s: expected %d command rows, found %d"
                    % (SOURCE_GATES.name, len(EXPECTED_C4_SOURCE_GATE_ROWS), len(rows))
                )
            for index, (expected_id, expected_hash) in enumerate(
                EXPECTED_C4_SOURCE_GATE_ROWS
            ):
                if index >= len(rows):
                    break
                row = rows[index]
                if list(row) != list(C4_SOURCE_GATE_KEYS):
                    errors.append(
                        "%s: row %02d keys are not the exact closed set"
                        % (SOURCE_GATES.name, index + 1)
                    )
                    continue
                if row["id"] != expected_id:
                    errors.append(
                        "%s: row %02d is %r, expected %r"
                        % (SOURCE_GATES.name, index + 1, row["id"], expected_id)
                    )
                    continue
                actual = hashlib.sha256(_canonical_gate_row(row)).hexdigest()
                if actual != expected_hash:
                    errors.append(
                        "%s: row %02d %s drifted from its frozen record hash"
                        % (SOURCE_GATES.name, index + 1, expected_id)
                    )

    # 6. Evidence bytes are stageable and only the two source archives escape the
    #    broad ZIP ignore.
    attributes = read(GITATTRIBUTES)
    if attributes is not None:
        for rule in C4_EVIDENCE_TEXT_ATTRIBUTES:
            if rule not in attributes:
                errors.append(".gitattributes: missing evidence rule %r" % rule)
    ignore = read(GITIGNORE)
    if ignore is not None:
        negations = [
            line.strip()
            for line in ignore.splitlines()
            if line.strip().startswith("!") and line.strip().endswith(".zip")
        ]
        if tuple(negations) != C4_ZIP_NEGATIONS:
            errors.append(
                ".gitignore: ZIP negations must be exactly the two attempt-local "
                "source archives, found %r" % (negations,)
            )

    # 7. The committed orchestrators own closed mode rosters and keep scratch
    #    outside the sealed attempt.
    for name, modes in (
        ("run_c4_native_attempt.ps1", C4_NATIVE_MODES),
        ("record_c4_evidence.ps1", C4_RECORDER_MODES),
    ):
        path = REPO_ROOT / "driver" / "scripts" / name
        text = read(path)
        if text is None:
            continue
        for mode in modes:
            if mode not in text:
                errors.append("%s: missing mode %r" % (name, mode))
    runner = REPO_ROOT / "driver" / "scripts" / "run_c4_recovery_gates.ps1"
    runner_text = read(runner)
    if runner_text is not None:
        for role in C4_TOOL_ROLES:
            if role not in runner_text:
                errors.append("%s: missing frozen tool role %r" % (runner.name, role))
        if "-ScratchDirectory" not in runner_text:
            errors.append(
                "%s: missing the external scratch parameter; scratch must be a "
                "sibling of the attempt, never inside it" % runner.name
            )
    return errors


def main() -> int:
    errors: list[str] = []
    actual = sorted(path.name for path in DESIGN_ROOT.glob("[0-9][0-9]-*.md"))
    if actual != EXPECTED:
        errors.append(f"design document set differs: expected={EXPECTED!r} actual={actual!r}")
    for name in EXPECTED:
        path = DESIGN_ROOT / name
        if not path.is_file():
            errors.append(f"{name}: missing file")
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        for token in REQUIRED.get(name, []):
            if token not in text:
                errors.append(f"{name}: missing token {token!r}")
        for token in FORBIDDEN:
            if token in text:
                errors.append(f"{name}: forbidden token {token!r}")
        for token in FORBIDDEN_BY_DOC.get(name, []):
            if token in text:
                errors.append(f"{name}: forbidden stale token {token!r}")
        if name in C4_REQUIRED:
            # Scope the C4 requirement to the C4 section. A file-wide search
            # would let a token that C2 or C3 already wrote elsewhere satisfy a
            # C4 requirement, so the gate would still pass with the C4 section
            # deleted. Anchoring it means each token attests to C4 text.
            marker = text.find("\n## C4 ")
            if marker < 0:
                errors.append(f"{name}: missing the '## C4 ...' section entirely")
            else:
                section = text[marker:]
                for token in C4_REQUIRED[name]:
                    if token not in section:
                        errors.append(f"{name}: missing C4 token {token!r}")
        # Stale claims are matched case-insensitively: the same false statement
        # at the start of a sentence is the same false statement.
        folded = text.casefold()
        for token in C4_STALE.get(name, []):
            if token.casefold() in folded:
                errors.append(f"{name}: stale C3-era claim {token!r}")
    errors.extend(recovery_errors())

    if errors:
        print("\n".join(errors), file=sys.stderr)
        print(f"FAILED: {len(errors)} document error(s)", file=sys.stderr)
        return 1
    required_count = (sum(len(tokens) for tokens in REQUIRED.values())
                      + sum(len(tokens) for tokens in C4_REQUIRED.values()))
    print(
        f"verified {len(EXPECTED)} FSRING documents: ABI 2.1 token gate "
        f"({required_count} required tokens present, "
        f"{sum(len(t) for t in FORBIDDEN_BY_DOC.values())} stale 2.0 sequences absent)"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
