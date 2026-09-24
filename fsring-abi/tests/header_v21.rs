//! Wave 10 activation contract: the generated C header is the exhaustive,
//! byte-frozen ABI 2.1 wire contract.
//!
//! These tests read `include/fsring_abi.h` verbatim and prove (a) the 2.1
//! identity triple and package version, (b) the pinned post-cutover SHA-256,
//! (c) that every one of the 123 public wire types is exported, (d) that the
//! flat 2.1 wire-code constants and the section-15 scalars are exported with
//! their `FSRING_`-prefixed names, and (e) that implementation handles, error
//! enums, validators, feature-selection policy masks, and the collision-scoped
//! per-message sub-registries are all absent. The exhaustive per-type
//! size/alignment/offset proof lives in `tests/c/layout_v21.c`.

use fsring_abi::digest::sha256_bytes;

const HEADER: &str = include_str!("../include/fsring_abi.h");

/// SHA-256 of the frozen ABI 2.1 header. Wave 10 is the only wave that changes
/// the header; Waves 11-14 rewrite documents only and must not touch it, so this
/// pins the post-cutover baseline.
const HEADER_SHA256_HEX: &str = "7bc16346475e8bd786306368ef90d80e6f3009b8cc44adc11ca6dfd60509ab2d";

/// Every public `#[repr(C)]` wire struct emitted to the header (120).
const WIRE_STRUCTS: &[&str] = &[
    "FeatureSet",
    "OpId",
    "FileId",
    "LinkId",
    "MountId",
    "TransactionId",
    "AckToken",
    "RegionDesc",
    "SlotClassDesc",
    "GlobalHeader",
    "RingDesc",
    "ProducerPage",
    "ConsumerPage",
    "SqeBody",
    "Sqe",
    "CqeBody",
    "Cqe",
    "ControlHeader",
    "BufferRef",
    "SizeState",
    "PControl",
    "OControl",
    "PBarrier",
    "PCancel",
    "PNotifyAck",
    "PRw",
    "ORw",
    "PrepareOpenV1",
    "PrepareOpenResultV1",
    "CommitOpenV1",
    "CommitOpenResultV1",
    "AbortOpenV1",
    "MutationV1",
    "MutationResultV1",
    "ReplayOpenV1",
    "ReplayOpenResultV1",
    "AttachV1",
    "QueryOpV1",
    "QueryOpResultV1",
    "AckResultV1",
    "NotifyEnvelopeV1",
    "DonateBackingV1",
    "DonateSecurityContextV1",
    "BootInstanceId",
    "RetireToken",
    "BlobSlice",
    "SlotClassRequest",
    "SetupRequestV1",
    "UserViewDesc",
    "NotificationCreditV1",
    "SessionResultV1",
    "EnterRequestV1",
    "EnterResultV1",
    "DetachRequestV1",
    "DonateBackingV2",
    "RetireMountV1",
    "RetireMountResultV1",
    "BootContextHeaderV1",
    "BootContextSlotV1",
    "ProviderMountRootV1",
    "DurableChildValueV1",
    "AccountingReservationV1",
    "PrepareTxIndexValueV1",
    "LatestProcessedV1",
    "RetireReceiptV1",
    "OpenRecoveryPayloadV1",
    "PrepareRecoveryPayloadV1",
    "JournalStateV1",
    "QueryDirSnapshotPayloadV1",
    "QueryDirCookiePayloadV1",
    "PtEpochIntentPayloadV1",
    "PtLanePayloadV1",
    "CommittedResultV1",
    "CommittedOpenResultV1",
    "CommittedWriteResultV1",
    "CommittedMutationResultV1",
    "WriteV2",
    "WriteResultV2",
    "PrepareOpenV2",
    "CommitOpenV2",
    "CommitOpenResultV2",
    "SetBasicInfoV1",
    "SetSizeV1",
    "RenameV1",
    "LinkV1",
    "UnlinkV1",
    "SetSecurityV1",
    "SetReparseV1",
    "DeleteReparseV1",
    "SetSparseV1",
    "MutationV2",
    "MutationResultV2",
    "RenameResultV2",
    "LinkResultV2",
    "UnlinkResultV1",
    "QueryInfoV1",
    "FileInfoV1",
    "QueryDirV1",
    "QueryDirV2",
    "QueryDirResultV1",
    "DirEntryV1",
    "QueryVolumeV1",
    "VolumeSizeInfoV1",
    "QuerySecurityV1",
    "FsctlV1",
    "NotifyEnvelopeV2",
    "InvalidateFileV1",
    "InvalidateEntryV1",
    "PtGrantV1",
    "PtEpochV1",
    "ResizeV1",
    "ExternalDirChangeV1",
    "PtLaneReadyV1",
    "ExternalChangeReadyV1",
    "ExternalChangeCutV1",
    "PDirChangeAckV1",
    "ProtocolAbortV1",
    "ReplayOpenV2",
    "QueryOpV2",
    "AckResultV2",
];

/// The three `#[repr(transparent)]` u64 wire identities (uint64_t typedefs).
const SCALAR_TYPEDEFS: &[&str] = &["ReqId", "SlotRef", "SlotToken"];

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[test]
fn header_advertises_abi_2_1_identity() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.1");
    assert!(HEADER.contains("/* Package version: 0.2.1 */"));
    assert!(HEADER.contains("#define FSRING_ABI_MAJOR 2"));
    assert!(HEADER.contains("#define FSRING_ABI_MINOR 1"));
    assert!(HEADER.contains("#define FSRING_ABI_MIN_COMPAT_MINOR 1"));
    // Minor 0 is a non-interoperable pre-release and is never advertised.
    assert!(!HEADER.contains("#define FSRING_ABI_MINOR 0"));
}

#[test]
fn header_pins_the_frozen_2_1_sha256() {
    assert_eq!(hex(&sha256_bytes(HEADER.as_bytes())), HEADER_SHA256_HEX);
}

#[test]
fn header_records_the_pinned_generator_and_guard() {
    assert!(HEADER.contains("Generated with cbindgen:0.29.4"));
    assert!(HEADER.contains("#ifndef FSRING_ABI_H"));
    assert!(HEADER.contains("#define FSRING_ABI_H"));
    assert!(HEADER.contains("#include <stdint.h>"));
}

#[test]
fn header_exports_every_public_wire_type() {
    for ty in WIRE_STRUCTS {
        assert!(
            HEADER.contains(&format!("}} {ty};")),
            "generated header is missing wire struct `{ty}`",
        );
    }
    for ty in SCALAR_TYPEDEFS {
        assert!(
            HEADER.contains(&format!("typedef uint64_t {ty};")),
            "generated header is missing scalar identity `{ty}`",
        );
    }
    assert_eq!(WIRE_STRUCTS.len() + SCALAR_TYPEDEFS.len(), 123);
}

#[test]
fn header_exports_the_flat_2_1_wire_codes_and_section_15_scalars() {
    for line in [
        "#define FSRING_ABI_MIN_COMPAT_MINOR 1",
        "#define FSRING_PROTOCOL_FEATURE_CASE_SENSITIVE_NAMES 9",
        "#define FSRING_OP_DIR_CHANGE_ACK 82",
        "#define FSRING_NOTIFY_PT_LANE_READY 8",
        "#define FSRING_NOTIFY_EXTERNAL_CHANGE_READY 9",
        "#define FSRING_NOTIFY_EXTERNAL_CHANGE_CUT 10",
        "#define FSRING_CONTROL_VERSION_V2 2",
        "#define FSRING_SLOT_TOKEN_CLASS_MAX 3",
        "#define FSRING_SLOT_TOKEN_INDEX_MAX",
        "#define FSRING_SLOT_TOKEN_GENERATION_MAX",
        "#define FSRING_MAX_FILE_SIZE",
        "#define FSRING_SYSTEM_REQID_BASE 16777023",
        "#define FSRING_GLOBAL_EXTERNAL_CHANGE_ACK_REQID 16777215",
        "#define FSRING_SYSTEM_REQUEST_SLOTS_PER_RING 3",
        "#define FSRING_CONTROL_SQ_RESERVE_PER_RING 4",
    ] {
        assert!(
            HEADER.contains(line),
            "generated header is missing `{line}`"
        );
    }
}

#[test]
fn header_excludes_handles_errors_validators_and_policy_masks() {
    for bad in [
        // ring implementation handles and the retry bound
        "MpscProducer",
        "SpscProducer",
        "SingleConsumer",
        "ConsumerPark",
        "ProducerPark",
        "ParkProtocol",
        "NativeReservation",
        "PushReceipt",
        "MAX_RESERVE_RETRIES",
        // error enums, validated/builder types, feature-selection policy
        "Error",
        "Validated",
        "Builder",
        "Selection",
        "PROTOCOL_MASK",
        "WIN10_X64",
        "WIN7_X64",
        "OS_CAPABILITIES",
    ] {
        assert!(
            !HEADER.contains(bad),
            "generated header leaked excluded symbol `{bad}`",
        );
    }
}

#[test]
fn header_does_not_flatten_the_colliding_sub_registries() {
    // Per the design's cbindgen bare-name collision amendment, the per-message /
    // session / durable enum-like sub-registries stay Rust/document-scoped.
    for bad in [
        "#define INVALID",
        "IOCTL_FSRING",
        "FSRING_IOCTL_",
        "FSRING_STATUS_",
        "FSRING_VIEW_KIND",
        "FSRING_VIEW_ACCESS",
        "FSRING_MUTATION_KIND",
        "FSRING_QUERY_INFO_CLASS",
        "FSRING_DURABLE_CHILD_KIND",
        "FSRING_COMMITTED_RESULT_KIND",
        "FSRING_BOOT_CONTEXT",
        "FSRING_RETIRE_MOUNT_STATE",
        "FSRING_NOTIFY_ACK_KIND",
        "FSRING_EXTERNAL_CHANGE_KIND",
        "FSRING_FILE_ATTRIBUTE",
        "FSRING_NOTIFY_FILTER",
        "FSRING_SESSION_RESULT_V1_PREFIX_SIZE",
    ] {
        assert!(
            !HEADER.contains(bad),
            "unexpectedly flattened sub-registry constant `{bad}`",
        );
    }
}
