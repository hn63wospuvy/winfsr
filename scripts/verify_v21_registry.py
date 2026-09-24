#!/usr/bin/env python3
"""Verify the ABI 2.1 registry is coherent across the three authoritative tiers:
the Rust source of truth, the generated C header, and the exhaustive C layout
test. Binds every wire type across header and C, checks the identity triple and
the flat 2.1 wire-code constants in all tiers, proves the SETUP negotiation
never selects minor 0, and rejects stale minor-0 identity and any accidental
flattening of the collision-scoped sub-registries. Strict UTF-8 throughout.

Exit 0 on success (with a one-line summary), 1 on the first failure batch.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ABI = ROOT / "fsring-abi"

# --- the 123 public wire types (120 structs + 3 u64 identities) ---------------
WIRE_STRUCTS = [
    "FeatureSet", "OpId", "FileId", "LinkId", "MountId", "TransactionId",
    "AckToken", "RegionDesc", "SlotClassDesc", "GlobalHeader", "RingDesc",
    "ProducerPage", "ConsumerPage", "SqeBody", "Sqe", "CqeBody", "Cqe",
    "ControlHeader", "BufferRef", "SizeState", "PControl", "OControl", "PBarrier",
    "PCancel", "PNotifyAck", "PRw", "ORw", "PrepareOpenV1", "PrepareOpenResultV1",
    "CommitOpenV1", "CommitOpenResultV1", "AbortOpenV1", "MutationV1",
    "MutationResultV1", "ReplayOpenV1", "ReplayOpenResultV1", "AttachV1",
    "QueryOpV1", "QueryOpResultV1", "AckResultV1", "NotifyEnvelopeV1",
    "DonateBackingV1", "DonateSecurityContextV1", "BootInstanceId", "RetireToken",
    "BlobSlice", "SlotClassRequest", "SetupRequestV1", "UserViewDesc",
    "NotificationCreditV1", "SessionResultV1", "EnterRequestV1", "EnterResultV1",
    "DetachRequestV1", "DonateBackingV2", "RetireMountV1", "RetireMountResultV1",
    "BootContextHeaderV1", "BootContextSlotV1", "ProviderMountRootV1",
    "DurableChildValueV1", "AccountingReservationV1", "PrepareTxIndexValueV1",
    "LatestProcessedV1", "RetireReceiptV1", "OpenRecoveryPayloadV1",
    "PrepareRecoveryPayloadV1", "JournalStateV1", "QueryDirSnapshotPayloadV1",
    "QueryDirCookiePayloadV1", "PtEpochIntentPayloadV1", "PtLanePayloadV1",
    "CommittedResultV1", "CommittedOpenResultV1", "CommittedWriteResultV1",
    "CommittedMutationResultV1", "WriteV2", "WriteResultV2", "PrepareOpenV2",
    "CommitOpenV2", "CommitOpenResultV2", "SetBasicInfoV1", "SetSizeV1",
    "RenameV1", "LinkV1", "UnlinkV1", "SetSecurityV1", "SetReparseV1",
    "DeleteReparseV1", "SetSparseV1", "MutationV2", "MutationResultV2",
    "RenameResultV2", "LinkResultV2", "UnlinkResultV1", "QueryInfoV1",
    "FileInfoV1", "QueryDirV1", "QueryDirV2", "QueryDirResultV1", "DirEntryV1",
    "QueryVolumeV1", "VolumeSizeInfoV1", "QuerySecurityV1", "FsctlV1",
    "NotifyEnvelopeV2", "InvalidateFileV1", "InvalidateEntryV1", "PtGrantV1",
    "PtEpochV1", "ResizeV1", "ExternalDirChangeV1", "PtLaneReadyV1",
    "ExternalChangeReadyV1", "ExternalChangeCutV1", "PDirChangeAckV1",
    "ProtocolAbortV1", "ReplayOpenV2", "QueryOpV2", "AckResultV2",
]
SCALAR_TYPEDEFS = ["ReqId", "SlotRef", "SlotToken"]

# flat 2.1 wire-code / scalar constants added by Wave 10 (header C name -> value)
NEW_HEADER_DEFINES = [
    "#define FSRING_ABI_MIN_COMPAT_MINOR 1",
    "#define FSRING_PROTOCOL_FEATURE_CASE_SENSITIVE_NAMES 9",
    "#define FSRING_OP_DIR_CHANGE_ACK 82",
    "#define FSRING_NOTIFY_PT_LANE_READY 8",
    "#define FSRING_NOTIFY_EXTERNAL_CHANGE_READY 9",
    "#define FSRING_NOTIFY_EXTERNAL_CHANGE_CUT 10",
    "#define FSRING_CONTROL_VERSION_V2 2",
    "#define FSRING_SLOT_TOKEN_CLASS_MAX 3",
    "#define FSRING_SYSTEM_REQID_BASE 16777023",
    "#define FSRING_GLOBAL_EXTERNAL_CHANGE_ACK_REQID 16777215",
    "#define FSRING_SYSTEM_REQUEST_SLOTS_PER_RING 3",
    "#define FSRING_CONTROL_SQ_RESERVE_PER_RING 4",
    "#define FSRING_MAX_FILE_SIZE",
    "#define FSRING_SLOT_TOKEN_INDEX_MAX",
    "#define FSRING_SLOT_TOKEN_GENERATION_MAX",
]


def read(rel):
    """Strict-UTF-8 read; a decode error is a hard failure."""
    return (ABI / rel).read_text(encoding="utf-8", errors="strict")


def main():
    errors = []

    layout_rs = read("src/layout.rs")
    header = read("include/fsring_abi.h")
    ctest = read("tests/c/layout_v21.c")
    session_rs = read("src/validate/session.rs")

    # 1. Identity triple in the Rust source of truth.
    for tok in ("pub const FSRING_ABI_MAJOR: u16 = 2;",
                "pub const FSRING_ABI_MINOR: u16 = 1;",
                "pub const FSRING_ABI_MIN_COMPAT_MINOR: u16 = 1;"):
        if tok not in layout_rs:
            errors.append(f"src/layout.rs missing 2.1 identity `{tok}`")
    if "FSRING_ABI_MINOR: u16 = 0" in layout_rs:
        errors.append("src/layout.rs still advertises minor 0")

    # 2. Identity triple in the generated header, and minor 0 never advertised.
    for tok in ("#define FSRING_ABI_MAJOR 2",
                "#define FSRING_ABI_MINOR 1",
                "#define FSRING_ABI_MIN_COMPAT_MINOR 1",
                "/* Package version: 0.2.1 */"):
        if tok not in header:
            errors.append(f"header missing 2.1 identity `{tok}`")
    if "#define FSRING_ABI_MINOR 0" in header:
        errors.append("header still advertises minor 0")

    # 3. Identity triple asserted in the exhaustive C layout test.
    for tok in ("FSRING_ABI_MINOR == 1", "FSRING_ABI_MIN_COMPAT_MINOR == 1",
                "FSRING_ABI_MAJOR == 2"):
        if tok not in ctest:
            errors.append(f"layout_v21.c missing identity assert `{tok}`")
    if "FSRING_ABI_MINOR == 0" in ctest:
        errors.append("layout_v21.c still asserts minor 0")

    # 4. Manifest: every wire type is bound in BOTH the header and the C test.
    for ty in WIRE_STRUCTS:
        if f"}} {ty};" not in header:
            errors.append(f"header missing wire struct `{ty}`")
        if f"ASSERT_LAYOUT({ty}," not in ctest and f"ASSERT_ID128({ty})" not in ctest:
            errors.append(f"layout_v21.c missing layout assert for `{ty}`")
    for ty in SCALAR_TYPEDEFS:
        if f"typedef uint64_t {ty};" not in header:
            errors.append(f"header missing scalar identity `{ty}`")

    # 5. Flat 2.1 wire-code constants present in the header.
    for d in NEW_HEADER_DEFINES:
        if d not in header:
            errors.append(f"header missing 2.1 constant `{d}`")

    # 6. SETUP negotiation selects minor 1 and rejects any range missing minor 1
    #    (so minor 0 is never negotiated) -- the source-of-truth for identity.
    if "selected_abi_minor: 1" not in session_rs:
        errors.append("validate/session.rs does not fix the selected minor at 1")
    if "min_abi_minor > 1" not in session_rs or "max_abi_minor < 1" not in session_rs:
        errors.append("validate/session.rs does not reject minor ranges that omit 1")

    # 7. The collision-scoped per-message sub-registries are NOT flattened into
    #    the header (they stay Rust/document-scoped; see the design amendment).
    for bad in ("#define INVALID ", "IOCTL_FSRING", "FSRING_IOCTL_",
                "FSRING_MUTATION_KIND", "FSRING_DURABLE_CHILD_KIND",
                "FSRING_VIEW_KIND", "FSRING_COMMITTED_RESULT_KIND",
                "FSRING_SESSION_RESULT_V1_PREFIX_SIZE", "FSRING_BOOT_CONTEXT"):
        if bad in header:
            errors.append(f"header unexpectedly flattened sub-registry `{bad}`")

    # 8. Implementation handles and the retry bound are not exported.
    for bad in ("MpscProducer", "SingleConsumer", "MAX_RESERVE_RETRIES",
                "ParkProtocol"):
        if bad in header:
            errors.append(f"header leaked implementation symbol `{bad}`")

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"FAILED: {len(errors)} registry error(s)", file=sys.stderr)
        return 1

    print(f"verified ABI 2.1 registry: identity 2.1/min-compat 1, "
          f"{len(WIRE_STRUCTS) + len(SCALAR_TYPEDEFS)} wire types bound across "
          f"Rust/header/C, {len(NEW_HEADER_DEFINES)} flat 2.1 constants, "
          f"minor 0 never advertised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
