use core::mem::{align_of, offset_of, size_of};
use std::{
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
};

use fsring_abi::{
    codec::{try_encode, Pod},
    durable::{
        self, checked_add_ordinary_charge_v1, checked_add_retire_receipt_v1,
        checked_remove_ordinary_charge_v1, checked_remove_retire_receipt_v1, durable_child_kind,
        durable_committed_result_state, durable_immutable_request_state, durable_journal_state,
        durable_key_digest_v1, durable_open_state, durable_payload_digest_v1,
        durable_prepare_state, durable_pt_epoch_intent_state, durable_pt_lane_state,
        durable_query_dir_attempt_state, durable_query_dir_cookie_state,
        durable_query_dir_snapshot_state, durable_record_charge_v1, encode_durable_key_v1,
        encode_retire_receipt_key_v1, encoded_durable_key_len_v1, external_notify_subkind,
        max_durable_pt_lane_records_per_mount, provider_mount_root_state, retire_receipt_state,
        validate_durable_accounting_v1, validate_durable_key_v1, validate_retire_receipt_key_v1,
        AccountingReservationV1, DurableAccountingError, DurableAccountingV1, DurableChildValueV1,
        DurableKeyError, DurableKeyIdentityV1, DurableKeyV1, DurableNamespaceV1,
        ExternalNotifyKeyIdentityV1, LatestProcessedV1, PrepareTxIndexValueV1, ProviderMountRootV1,
        RetireReceiptV1, DURABLE_ACCOUNTING_RESERVATION_BYTES, DURABLE_ALIGNMENT,
        DURABLE_CHILD_VALUE_PREFIX_BYTES, DURABLE_KEY_HEADER_BYTES, DURABLE_KEY_MAX_BYTES,
        DURABLE_LATEST_PROCESSED_BYTES, DURABLE_NAMESPACE_PREFIX_BYTES,
        DURABLE_PREPARE_TX_INDEX_BYTES, DURABLE_PROVIDER_ROOT_BYTES,
        DURABLE_RECORD_ACCOUNTING_OVERHEAD, DURABLE_RETIRE_RECEIPT_KEY_BYTES,
        DURABLE_RETIRE_RECEIPT_VALUE_BYTES, MAX_DURABLE_EXTERNAL_OUTBOX_BYTES,
        MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS, MAX_DURABLE_ORDINARY_BYTES_GLOBAL,
        MAX_DURABLE_QUERY_DIR_BYTES_PER_MOUNT, MAX_DURABLE_QUERY_DIR_SNAPSHOTS_PER_OPEN,
        MAX_DURABLE_QUERY_DIR_SNAPSHOT_BYTES_PER_OPEN, MAX_DURABLE_RECOVERY_BYTES_GLOBAL,
        MAX_DURABLE_RETIRE_RECEIPTS, MAX_RETAINED_PREPARE_BYTES_PER_MOUNT,
        PROVIDER_MOUNT_ROOT_VERSION, RETIRE_RECEIPT_CHARGE_BYTES, RETIRE_RECEIPT_RESERVED_BYTES,
    },
    msgs::{BlobSlice, ControlHeader},
    validate::{
        validate_accounting_reservation_v1, validate_durable_child_value_v1,
        validate_durable_u64_value_v1, validate_latest_processed_v1,
        validate_prepare_tx_index_value_v1, validate_provider_mount_root_v1,
        validate_retire_receipt_v1, DurableMetadataError, ValidatedDurableChildV1,
    },
    BootInstanceId, FeatureSet, FileId, MountId, OpId, RetireToken, TransactionId,
    FSRING_ABI_MINOR,
};

type MetadataValidator<T> = fn(&[u8], &[u8], u32) -> Result<T, DurableMetadataError>;
type AccountingReservationValidator =
    fn(&[u8], &[u8], &[u8], u64, u32) -> Result<AccountingReservationV1, DurableMetadataError>;

macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<Marker> {
                fn marker() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct ForbiddenImpl;
            impl<T: ?Sized + $trait> AmbiguousIfImpl<ForbiddenImpl> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::marker;
        };
    };
}

assert_not_impl!(DurableNamespaceV1: Pod);
assert_not_impl!(ExternalNotifyKeyIdentityV1: Pod);
assert_not_impl!(DurableKeyIdentityV1: Pod);
assert_not_impl!(DurableKeyV1: Pod);
assert_not_impl!(ValidatedDurableChildV1: Pod);
assert_not_impl!(DurableAccountingV1: Pod);
assert_not_impl!(DurableKeyError: Pod);
assert_not_impl!(DurableMetadataError: Pod);
assert_not_impl!(DurableAccountingError: Pod);

assert_not_impl!(ProviderMountRootV1: Default);
assert_not_impl!(ProviderMountRootV1: core::fmt::Debug);
assert_not_impl!(ProviderMountRootV1: PartialEq);
assert_not_impl!(ProviderMountRootV1: Eq);
assert_not_impl!(DurableChildValueV1: Default);
assert_not_impl!(DurableChildValueV1: core::fmt::Debug);
assert_not_impl!(DurableChildValueV1: PartialEq);
assert_not_impl!(DurableChildValueV1: Eq);
assert_not_impl!(AccountingReservationV1: Default);
assert_not_impl!(AccountingReservationV1: core::fmt::Debug);
assert_not_impl!(AccountingReservationV1: PartialEq);
assert_not_impl!(AccountingReservationV1: Eq);
assert_not_impl!(PrepareTxIndexValueV1: Default);
assert_not_impl!(PrepareTxIndexValueV1: core::fmt::Debug);
assert_not_impl!(PrepareTxIndexValueV1: PartialEq);
assert_not_impl!(PrepareTxIndexValueV1: Eq);
assert_not_impl!(LatestProcessedV1: Default);
assert_not_impl!(LatestProcessedV1: core::fmt::Debug);
assert_not_impl!(LatestProcessedV1: PartialEq);
assert_not_impl!(LatestProcessedV1: Eq);
assert_not_impl!(RetireReceiptV1: Default);
assert_not_impl!(RetireReceiptV1: core::fmt::Debug);
assert_not_impl!(RetireReceiptV1: PartialEq);
assert_not_impl!(RetireReceiptV1: Eq);

const MOUNT: MountId = MountId {
    lo: 0x0102_0304_0506_0708,
    hi: 0x1112_1314_1516_1718,
};
const BOOT: BootInstanceId = BootInstanceId {
    lo: 0x2122_2324_2526_2728,
    hi: 0x3132_3334_3536_3738,
};
const NS: DurableNamespaceV1 = DurableNamespaceV1 {
    mount_id: MOUNT,
    boot_instance_id: BOOT,
};
const OP: OpId = OpId { lo: 1, hi: 2 };
const FILE: FileId = FileId { lo: 3, hi: 4 };
const TX: TransactionId = TransactionId { lo: 5, hi: 6 };
const SID: [u8; 32] = [
    1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0,
];
const ROOT_KEY_HEX: &str = "08070605040302011817161514131211282726252423222138373635343332310100";
const ROOT_KEY_DIGEST_HEX: &str =
    "52e877a3bf001f128b205cc6ca57f9a69aefe8b1189e23d180fccc39a8a8bdf9";
const OPEN_KEY_DIGEST_HEX: &str =
    "cf0377043ee5df8a373976f44913f3d83b0bfa515af4d38aebcb109de2ccb0ed";
const EMPTY_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_SHA256_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const RECEIPT_KEY_HEX: &str = "0807060504030201181716151413121128272625242322213837363534333231";
const ROOT_VALUE_HEX: &str = "0100000001000000282726252423222138373635343332310807060504030201181716151413121101000000000000001c000000000000000000000000000000010000002000000001060000000000055000000001000000020000000300000004000000050000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000800000000000000";
const ACCOUNTING_RESERVATION_VALUE_HEX: &str = concat!(
    "01000000220000000801000000000000",
    "52e877a3bf001f128b205cc6ca57f9a69aefe8b1189e23d180fccc39a8a8bdf9",
);
const PREPARE_TX_INDEX_VALUE_HEX: &str = concat!(
    "01000000000000000200000000000000",
    "fd668df86ae5336ded869c6399c27cb7e4ad1692fee1612ec885274af1407d31",
);
const LATEST_PROCESSED_VALUE_HEX: &str = concat!(
    "0000000000000000ffffffffffffffff0000000000000080",
    "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
);
const RETIRE_RECEIPT_VALUE_HEX: &str =
    "0000000000000000ffffffffffffffff01000000000000000000000000000000";
const OPEN_LIVE_VALUE_HEX: &str = concat!(
    "60000000010000000300010000000000",
    "cf0377043ee5df8a373976f44913f3d83b0bfa515af4d38aebcb109de2ccb0ed",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "58000000030000006162630000000000",
);
const OPEN_CLEANED_VALUE_HEX: &str = concat!(
    "58000000010000000300020000000000",
    "cf0377043ee5df8a373976f44913f3d83b0bfa515af4d38aebcb109de2ccb0ed",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "0000000000000000",
);
const CONST_RECORD_CHARGE: Result<u64, DurableAccountingError> = durable_record_charge_v1(34, 160);
const CONST_ACCOUNTING_VALID: Result<(), DurableAccountingError> =
    validate_durable_accounting_v1(DurableAccountingV1 {
        ordinary_charged_bytes: 0,
        receipt_count: 0,
        receipt_actual_bytes: 0,
    });
const CONST_ADD_ORDINARY: Result<DurableAccountingV1, DurableAccountingError> =
    checked_add_ordinary_charge_v1(
        DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 0,
            receipt_actual_bytes: 0,
        },
        1,
    );
const CONST_REMOVE_ORDINARY: Result<DurableAccountingV1, DurableAccountingError> =
    checked_remove_ordinary_charge_v1(
        DurableAccountingV1 {
            ordinary_charged_bytes: 1,
            receipt_count: 0,
            receipt_actual_bytes: 0,
        },
        1,
    );
const CONST_ADD_RECEIPT: Result<DurableAccountingV1, DurableAccountingError> =
    checked_add_retire_receipt_v1(DurableAccountingV1 {
        ordinary_charged_bytes: 0,
        receipt_count: 0,
        receipt_actual_bytes: 0,
    });
const CONST_REMOVE_RECEIPT: Result<DurableAccountingV1, DurableAccountingError> =
    checked_remove_retire_receipt_v1(DurableAccountingV1 {
        ordinary_charged_bytes: 0,
        receipt_count: 1,
        receipt_actual_bytes: 128,
    });

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    decode_hex_vec(text).try_into().unwrap()
}

fn decode_hex_vec(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    let mut out = vec![0u8; text.len() / 2];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("non-lowercase-hex test literal"),
            }
        }
        out[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    out
}

fn canonical_key_cases() -> [(DurableKeyIdentityV1, &'static str); 19] {
    [
        (DurableKeyIdentityV1::Root, ROOT_KEY_HEX),
        (
            DurableKeyIdentityV1::AccountingReservation {
                target_key_digest: [0; 32],
            },
            concat!(
                "08070605040302011817161514131211282726252423222138373635343332310200",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            DurableKeyIdentityV1::Open { kernel_open_id: 1 },
            "080706050403020118171615141312112827262524232221383736353433323103000100000000000000",
        ),
        (
            DurableKeyIdentityV1::Prepare { op_id: OP },
            "0807060504030201181716151413121128272625242322213837363534333231040001000000000000000200000000000000",
        ),
        (
            DurableKeyIdentityV1::ImmutableRequest { op_id: OP },
            "0807060504030201181716151413121128272625242322213837363534333231060001000000000000000200000000000000",
        ),
        (
            DurableKeyIdentityV1::CommittedResult { op_id: OP },
            "0807060504030201181716151413121128272625242322213837363534333231070001000000000000000200000000000000",
        ),
        (
            DurableKeyIdentityV1::Journal { op_id: OP },
            "0807060504030201181716151413121128272625242322213837363534333231080001000000000000000200000000000000",
        ),
        (
            DurableKeyIdentityV1::QueryDirSnapshot {
                kernel_open_id: 1,
                generation: 2,
            },
            "0807060504030201181716151413121128272625242322213837363534333231090001000000000000000200000000000000",
        ),
        (
            DurableKeyIdentityV1::QueryDirAttempt {
                kernel_open_id: 1,
                generation: 2,
                input_cookie: 3,
                attempt_digest: [0; 32],
            },
            concat!(
                "08070605040302011817161514131211282726252423222138373635343332310a00",
                "010000000000000002000000000000000300000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 1,
                generation: 2,
                cookie: 3,
            },
            "08070605040302011817161514131211282726252423222138373635343332310b00010000000000000002000000000000000300000000000000",
        ),
        (
            DurableKeyIdentityV1::PtEpochIntent {
                file_id: FILE,
                pt_epoch: 1,
            },
            "08070605040302011817161514131211282726252423222138373635343332310c00030000000000000004000000000000000100000000000000",
        ),
        (
            DurableKeyIdentityV1::PtEpochCounter { file_id: FILE },
            "08070605040302011817161514131211282726252423222138373635343332310d0003000000000000000400000000000000",
        ),
        (
            DurableKeyIdentityV1::PtLane {
                ring_index: 1,
                kind_ordinal: 2,
            },
            "08070605040302011817161514131211282726252423222138373635343332310e000102",
        ),
        (
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal: 1 },
            },
            "08070605040302011817161514131211282726252423222138373635343332310f0001000100000000000000",
        ),
        (
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::LatestProcessed,
            },
            "08070605040302011817161514131211282726252423222138373635343332310f000200",
        ),
        (
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::OrdinalCounter,
            },
            "08070605040302011817161514131211282726252423222138373635343332310f000300",
        ),
        (
            DurableKeyIdentityV1::ExternalNotifyOutbox {
                identity: ExternalNotifyKeyIdentityV1::AttachCut { session_epoch: 1 },
            },
            "08070605040302011817161514131211282726252423222138373635343332310f0004000100000000000000",
        ),
        (
            DurableKeyIdentityV1::VolumeCommitCounter,
            "08070605040302011817161514131211282726252423222138373635343332311000",
        ),
        (
            DurableKeyIdentityV1::PrepareTxIndex { transaction_id: TX },
            "0807060504030201181716151413121128272625242322213837363534333231110005000000000000000600000000000000",
        ),
    ]
}

fn encode_pod<T: Pod>(value: &T) -> Vec<u8> {
    let mut output = vec![0u8; size_of::<T>()];
    assert_eq!(try_encode(value, &mut output).unwrap(), output.len());
    output
}

fn durable_key(identity: DurableKeyIdentityV1) -> DurableKeyV1 {
    DurableKeyV1 {
        namespace: NS,
        identity,
    }
}

fn encode_key(identity: DurableKeyIdentityV1) -> Vec<u8> {
    let mut output = [0xa5; 128];
    let needed = encode_durable_key_v1(&durable_key(identity), &mut output).unwrap();
    assert!(output[needed..].iter().all(|byte| *byte == 0));
    output[..needed].to_vec()
}

fn root_record() -> ProviderMountRootV1 {
    let mut service_sid = [0u8; 68];
    service_sid[..SID.len()].copy_from_slice(&SID);
    ProviderMountRootV1 {
        version: PROVIDER_MOUNT_ROOT_VERSION,
        state: provider_mount_root_state::ACTIVE,
        boot_instance_id: BOOT,
        mount_id: MOUNT,
        latest_session_epoch: 1,
        selected_features: FeatureSet { words: [0x1c, 0] },
        journal_version: 1,
        service_sid_length: SID.len() as u32,
        service_sid,
        reserved: [0; 4],
        latest_proof_token: RetireToken { lo: 7, hi: 8 },
    }
}

fn child_value(key: &[u8], value_kind: u16, state: u16, payload_bytes: &[u8]) -> Vec<u8> {
    let unaligned = DURABLE_CHILD_VALUE_PREFIX_BYTES as usize + payload_bytes.len();
    let struct_size = (unaligned + 7) & !7;
    let payload = if payload_bytes.is_empty() {
        BlobSlice {
            offset: 0,
            length: 0,
        }
    } else {
        BlobSlice {
            offset: DURABLE_CHILD_VALUE_PREFIX_BYTES,
            length: payload_bytes.len().try_into().unwrap(),
        }
    };
    let prefix = DurableChildValueV1 {
        header: ControlHeader {
            struct_size: struct_size.try_into().unwrap(),
            struct_version: 1,
            required_flags: 0,
        },
        value_kind,
        state,
        flags: 0,
        identity_digest: durable_key_digest_v1(key, 64).unwrap(),
        payload_digest: durable_payload_digest_v1(payload_bytes),
        payload,
    };
    let mut output = vec![0u8; struct_size];
    assert_eq!(
        try_encode(
            &prefix,
            &mut output[..DURABLE_CHILD_VALUE_PREFIX_BYTES as usize]
        )
        .unwrap(),
        DURABLE_CHILD_VALUE_PREFIX_BYTES as usize
    );
    output[DURABLE_CHILD_VALUE_PREFIX_BYTES as usize
        ..DURABLE_CHILD_VALUE_PREFIX_BYTES as usize + payload_bytes.len()]
        .copy_from_slice(payload_bytes);
    output
}

fn assert_exact_derive_line(
    relative_path: &str,
    declaration: &str,
    expected_derive: &str,
    expected_repr: Option<&str>,
) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let source = fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = source.lines().collect();
    let declaration_index = lines
        .iter()
        .position(|line| line.trim() == declaration)
        .unwrap_or_else(|| panic!("missing declaration {declaration}"));
    assert_eq!(
        lines[..declaration_index]
            .iter()
            .filter(|line| line.trim() == declaration)
            .count(),
        0
    );
    assert_eq!(lines[declaration_index - 1].trim(), expected_derive);
    match expected_repr {
        Some(repr) => assert_eq!(lines[declaration_index - 2].trim(), repr),
        None => {
            assert!(!lines[declaration_index - 2].trim().starts_with("#[derive("))
        }
    }
}

fn assert_metadata_error<T>(
    result: Result<T, DurableMetadataError>,
    expected: DurableMetadataError,
) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("expected {expected:?}"),
    }
}

#[test]
fn wave4b_public_surface_and_constants_are_exact() {
    assert_eq!(durable::DURABLE_ALIGNMENT, DURABLE_ALIGNMENT);
    let _: fn(&DurableKeyIdentityV1) -> u32 = encoded_durable_key_len_v1;
    let _: fn(&DurableKeyV1, &mut [u8]) -> Result<usize, DurableKeyError> = encode_durable_key_v1;
    let _: fn(&[u8], u32) -> Result<DurableKeyV1, DurableKeyError> = validate_durable_key_v1;
    let _: fn(&[u8], u32) -> Result<[u8; 32], DurableKeyError> = durable_key_digest_v1;
    let _: fn(DurableNamespaceV1, &mut [u8]) -> Result<usize, DurableKeyError> =
        encode_retire_receipt_key_v1;
    let _: fn(&[u8]) -> Result<DurableNamespaceV1, DurableKeyError> =
        validate_retire_receipt_key_v1;
    let _: fn(&[u8]) -> [u8; 32] = durable_payload_digest_v1;
    let _: fn(u32) -> Option<u32> = max_durable_pt_lane_records_per_mount;
    let _: MetadataValidator<ProviderMountRootV1> = validate_provider_mount_root_v1;
    let _: MetadataValidator<ValidatedDurableChildV1> = validate_durable_child_value_v1;
    let _: AccountingReservationValidator = validate_accounting_reservation_v1;
    let _: MetadataValidator<PrepareTxIndexValueV1> = validate_prepare_tx_index_value_v1;
    let _: MetadataValidator<LatestProcessedV1> = validate_latest_processed_v1;
    let _: MetadataValidator<u64> = validate_durable_u64_value_v1;
    let _: fn(&[u8], &[u8]) -> Result<RetireReceiptV1, DurableMetadataError> =
        validate_retire_receipt_v1;
    let _: fn(u64, u64) -> Result<u64, DurableAccountingError> = durable_record_charge_v1;
    let _: fn(DurableAccountingV1) -> Result<(), DurableAccountingError> =
        validate_durable_accounting_v1;

    assert_eq!(PROVIDER_MOUNT_ROOT_VERSION, 1);
    assert_eq!(
        [
            DURABLE_ALIGNMENT,
            DURABLE_NAMESPACE_PREFIX_BYTES as u64,
            DURABLE_KEY_HEADER_BYTES as u64,
            DURABLE_KEY_MAX_BYTES as u64,
            DURABLE_CHILD_VALUE_PREFIX_BYTES as u64,
            DURABLE_PROVIDER_ROOT_BYTES as u64,
            DURABLE_ACCOUNTING_RESERVATION_BYTES as u64,
            DURABLE_PREPARE_TX_INDEX_BYTES as u64,
            DURABLE_LATEST_PROCESSED_BYTES as u64,
            DURABLE_RETIRE_RECEIPT_KEY_BYTES as u64,
            DURABLE_RETIRE_RECEIPT_VALUE_BYTES as u64,
        ],
        [8, 32, 34, 90, 88, 160, 48, 48, 56, 32, 32],
    );
    assert_eq!(MAX_DURABLE_RECOVERY_BYTES_GLOBAL, 4_294_967_296);
    assert_eq!(DURABLE_RECORD_ACCOUNTING_OVERHEAD, 64);
    assert_eq!(RETIRE_RECEIPT_CHARGE_BYTES, 128);
    assert_eq!(RETIRE_RECEIPT_RESERVED_BYTES, 8_192);
    assert_eq!(MAX_DURABLE_RETIRE_RECEIPTS, 64);
    assert_eq!(MAX_DURABLE_ORDINARY_BYTES_GLOBAL, 4_294_959_104);
    assert_eq!(MAX_DURABLE_QUERY_DIR_SNAPSHOTS_PER_OPEN, 1);
    assert_eq!(MAX_DURABLE_QUERY_DIR_SNAPSHOT_BYTES_PER_OPEN, 67_108_864);
    assert_eq!(MAX_DURABLE_QUERY_DIR_BYTES_PER_MOUNT, 268_435_456);
    assert_eq!(MAX_RETAINED_PREPARE_BYTES_PER_MOUNT, 67_108_864);
    assert_eq!(MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS, 4_096);
    assert_eq!(MAX_DURABLE_EXTERNAL_OUTBOX_BYTES, 8_388_608);
    assert_eq!(
        [
            durable_child_kind::ROOT,
            durable_child_kind::ACCOUNTING_RESERVATION,
            durable_child_kind::OPEN,
            durable_child_kind::PREPARE,
            durable_child_kind::IMMUTABLE_REQUEST,
            durable_child_kind::COMMITTED_RESULT,
            durable_child_kind::JOURNAL,
            durable_child_kind::QUERY_DIR_SNAPSHOT,
            durable_child_kind::QUERY_DIR_ATTEMPT,
            durable_child_kind::QUERY_DIR_COOKIE,
            durable_child_kind::PT_EPOCH_INTENT,
            durable_child_kind::PT_EPOCH_COUNTER,
            durable_child_kind::PT_LANE,
            durable_child_kind::EXTERNAL_NOTIFY_OUTBOX,
            durable_child_kind::VOLUME_COMMIT_COUNTER,
            durable_child_kind::PREPARE_TX_INDEX,
        ],
        [1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
    );
    assert_eq!(
        [
            external_notify_subkind::OUTBOX_ROW,
            external_notify_subkind::LATEST_PROCESSED,
            external_notify_subkind::ORDINAL_COUNTER,
            external_notify_subkind::ATTACH_CUT,
        ],
        [1, 2, 3, 4],
    );
    assert_eq!(
        [
            provider_mount_root_state::ACTIVE as u16,
            provider_mount_root_state::RECOVERING as u16,
            provider_mount_root_state::RETIRING as u16,
            durable_open_state::LIVE,
            durable_open_state::CLEANED,
            durable_prepare_state::PREPARED,
            durable_immutable_request_state::RETAINED,
            durable_committed_result_state::COMMITTED,
            durable_journal_state::PREPARED,
            durable_journal_state::COMMITTED,
            durable_query_dir_snapshot_state::ACTIVE,
            durable_query_dir_attempt_state::ACCEPTED,
            durable_query_dir_cookie_state::ACTIVE,
            durable_pt_epoch_intent_state::PENDING,
            durable_pt_epoch_intent_state::ACCEPTED,
            durable_pt_epoch_intent_state::REVOKED,
            durable_pt_lane_state::PRESENT,
            retire_receipt_state::RECEIPT_PENDING_ACK as u16,
        ],
        [1, 2, 3, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 3, 1, 1],
    );
    assert_eq!(max_durable_pt_lane_records_per_mount(0), None);
    assert_eq!(max_durable_pt_lane_records_per_mount(1), Some(4));
    assert_eq!(max_durable_pt_lane_records_per_mount(64), Some(256));
    assert_eq!(max_durable_pt_lane_records_per_mount(65), None);
}

#[test]
fn fixed_metadata_layouts_are_exact_and_gapless() {
    assert_eq!(
        (
            size_of::<ProviderMountRootV1>(),
            align_of::<ProviderMountRootV1>()
        ),
        (160, 8)
    );
    assert_eq!(offset_of!(ProviderMountRootV1, version), 0);
    assert_eq!(offset_of!(ProviderMountRootV1, state), 4);
    assert_eq!(offset_of!(ProviderMountRootV1, boot_instance_id), 8);
    assert_eq!(offset_of!(ProviderMountRootV1, mount_id), 24);
    assert_eq!(offset_of!(ProviderMountRootV1, latest_session_epoch), 40);
    assert_eq!(offset_of!(ProviderMountRootV1, selected_features), 48);
    assert_eq!(offset_of!(ProviderMountRootV1, journal_version), 64);
    assert_eq!(offset_of!(ProviderMountRootV1, service_sid_length), 68);
    assert_eq!(offset_of!(ProviderMountRootV1, service_sid), 72);
    assert_eq!(offset_of!(ProviderMountRootV1, reserved), 140);
    assert_eq!(offset_of!(ProviderMountRootV1, latest_proof_token), 144);
    assert_eq!(
        offset_of!(ProviderMountRootV1, latest_proof_token) + size_of::<RetireToken>(),
        size_of::<ProviderMountRootV1>()
    );

    assert_eq!(
        (
            size_of::<DurableChildValueV1>(),
            align_of::<DurableChildValueV1>()
        ),
        (88, 8)
    );
    assert_eq!(offset_of!(DurableChildValueV1, header), 0);
    assert_eq!(offset_of!(DurableChildValueV1, value_kind), 8);
    assert_eq!(offset_of!(DurableChildValueV1, state), 10);
    assert_eq!(offset_of!(DurableChildValueV1, flags), 12);
    assert_eq!(offset_of!(DurableChildValueV1, identity_digest), 16);
    assert_eq!(offset_of!(DurableChildValueV1, payload_digest), 48);
    assert_eq!(offset_of!(DurableChildValueV1, payload), 80);
    assert_eq!(
        offset_of!(DurableChildValueV1, payload) + size_of::<BlobSlice>(),
        size_of::<DurableChildValueV1>()
    );

    assert_eq!(
        (
            size_of::<AccountingReservationV1>(),
            align_of::<AccountingReservationV1>()
        ),
        (48, 8)
    );
    assert_eq!(offset_of!(AccountingReservationV1, target_child_kind), 0);
    assert_eq!(offset_of!(AccountingReservationV1, flags), 2);
    assert_eq!(offset_of!(AccountingReservationV1, target_key_length), 4);
    assert_eq!(offset_of!(AccountingReservationV1, charged_bytes), 8);
    assert_eq!(offset_of!(AccountingReservationV1, target_key_digest), 16);
    assert_eq!(
        offset_of!(AccountingReservationV1, target_key_digest) + 32,
        size_of::<AccountingReservationV1>()
    );

    assert_eq!(
        (
            size_of::<PrepareTxIndexValueV1>(),
            align_of::<PrepareTxIndexValueV1>()
        ),
        (48, 8)
    );
    assert_eq!(offset_of!(PrepareTxIndexValueV1, op_id), 0);
    assert_eq!(offset_of!(PrepareTxIndexValueV1, identity_digest), 16);
    assert_eq!(
        offset_of!(PrepareTxIndexValueV1, identity_digest) + 32,
        size_of::<PrepareTxIndexValueV1>()
    );

    assert_eq!(
        (
            size_of::<LatestProcessedV1>(),
            align_of::<LatestProcessedV1>()
        ),
        (56, 8)
    );
    assert_eq!(offset_of!(LatestProcessedV1, first_ordinal), 0);
    assert_eq!(offset_of!(LatestProcessedV1, through_ordinal), 8);
    assert_eq!(offset_of!(LatestProcessedV1, volume_commit_sequence), 16);
    assert_eq!(offset_of!(LatestProcessedV1, semantic_digest), 24);
    assert_eq!(
        offset_of!(LatestProcessedV1, semantic_digest) + 32,
        size_of::<LatestProcessedV1>()
    );

    assert_eq!(
        (size_of::<RetireReceiptV1>(), align_of::<RetireReceiptV1>()),
        (32, 8)
    );
    assert_eq!(offset_of!(RetireReceiptV1, retire_token), 0);
    assert_eq!(offset_of!(RetireReceiptV1, state), 16);
    assert_eq!(offset_of!(RetireReceiptV1, reserved), 20);
    assert_eq!(
        offset_of!(RetireReceiptV1, reserved) + 12,
        size_of::<RetireReceiptV1>()
    );
}

#[test]
fn all_canonical_keys_round_trip_with_exact_lengths() {
    for (identity, literal_hex) in canonical_key_cases() {
        let literal = decode_hex_vec(literal_hex);
        let expected_length = literal.len();
        assert_eq!(
            encoded_durable_key_len_v1(&identity) as usize,
            expected_length
        );
        let key = durable_key(identity);
        let encoded = encode_key(identity);
        assert_eq!(encoded, literal);
        assert_eq!(validate_durable_key_v1(&literal, 64).unwrap(), key);
    }
}

#[test]
fn key_validation_is_closed_nonzero_and_nonmutating() {
    let root = encode_key(DurableKeyIdentityV1::Root);
    for length in 0..DURABLE_KEY_HEADER_BYTES as usize {
        assert_eq!(
            validate_durable_key_v1(&root[..length], 1),
            Err(DurableKeyError::InvalidLength),
            "length {length}"
        );
    }

    let mut invalid_namespace = root.clone();
    invalid_namespace[..16].fill(0);
    assert_eq!(
        validate_durable_key_v1(&invalid_namespace, 1),
        Err(DurableKeyError::InvalidNamespace)
    );
    let mut invalid_boot_namespace = root.clone();
    invalid_boot_namespace[16..32].fill(0);
    assert_eq!(
        validate_durable_key_v1(&invalid_boot_namespace, 1),
        Err(DurableKeyError::InvalidNamespace)
    );

    for kind in 0u16..=u16::MAX {
        if matches!(kind, 1..=4 | 6..=17) {
            continue;
        }
        let mut unknown = root.clone();
        unknown[32..34].copy_from_slice(&kind.to_le_bytes());
        assert_eq!(
            validate_durable_key_v1(&unknown, 1),
            Err(DurableKeyError::UnknownChildKind)
        );
    }

    let mut long_root = root.clone();
    long_root.push(0);
    assert_eq!(
        validate_durable_key_v1(&long_root, 1),
        Err(DurableKeyError::InvalidTail)
    );

    let mut unknown_external = decode_hex_vec(canonical_key_cases()[14].1);
    for subkind in 0u16..=u16::MAX {
        if matches!(subkind, 1..=4) {
            continue;
        }
        unknown_external[34..36].copy_from_slice(&subkind.to_le_bytes());
        assert_eq!(
            validate_durable_key_v1(&unknown_external, 1),
            Err(DurableKeyError::UnknownExternalSubkind),
            "external subkind {subkind}",
        );
    }
    unknown_external[34..36].copy_from_slice(&5u16.to_le_bytes());
    for invalid_length in [37usize, 38, 39, 40, 41, 42, 43, 45, 90] {
        let mut invalid_tail = unknown_external.clone();
        invalid_tail.resize(invalid_length, 0);
        assert_eq!(
            validate_durable_key_v1(&invalid_tail, 1),
            Err(DurableKeyError::InvalidTail),
            "external length {invalid_length}",
        );
    }

    for (_, literal_hex) in canonical_key_cases() {
        let literal = decode_hex_vec(literal_hex);
        let mut short = literal.clone();
        short.pop();
        assert_eq!(
            validate_durable_key_v1(&short, 64),
            Err(if short.len() < DURABLE_KEY_HEADER_BYTES as usize {
                DurableKeyError::InvalidLength
            } else {
                DurableKeyError::InvalidTail
            }),
            "short literal {literal_hex}",
        );
        let mut long = literal;
        long.push(0);
        assert_eq!(
            validate_durable_key_v1(&long, 64),
            Err(DurableKeyError::InvalidTail),
            "long literal {literal_hex}",
        );
    }

    let zero_identities = [
        DurableKeyIdentityV1::Open { kernel_open_id: 0 },
        DurableKeyIdentityV1::Prepare { op_id: OpId::ZERO },
        DurableKeyIdentityV1::ImmutableRequest { op_id: OpId::ZERO },
        DurableKeyIdentityV1::CommittedResult { op_id: OpId::ZERO },
        DurableKeyIdentityV1::Journal { op_id: OpId::ZERO },
        DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id: 0,
            generation: 1,
        },
        DurableKeyIdentityV1::QueryDirSnapshot {
            kernel_open_id: 1,
            generation: 0,
        },
        DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id: 0,
            generation: 1,
            input_cookie: 1,
            attempt_digest: [0; 32],
        },
        DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id: 1,
            generation: 0,
            input_cookie: 1,
            attempt_digest: [0; 32],
        },
        DurableKeyIdentityV1::QueryDirAttempt {
            kernel_open_id: 1,
            generation: 1,
            input_cookie: 0,
            attempt_digest: [0; 32],
        },
        DurableKeyIdentityV1::QueryDirCookie {
            kernel_open_id: 0,
            generation: 1,
            cookie: 1,
        },
        DurableKeyIdentityV1::QueryDirCookie {
            kernel_open_id: 1,
            generation: 0,
            cookie: 1,
        },
        DurableKeyIdentityV1::QueryDirCookie {
            kernel_open_id: 1,
            generation: 1,
            cookie: 0,
        },
        DurableKeyIdentityV1::PtEpochIntent {
            file_id: FileId::ZERO,
            pt_epoch: 1,
        },
        DurableKeyIdentityV1::PtEpochIntent {
            file_id: FILE,
            pt_epoch: 0,
        },
        DurableKeyIdentityV1::PtEpochCounter {
            file_id: FileId::ZERO,
        },
        DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal: 0 },
        },
        DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: ExternalNotifyKeyIdentityV1::AttachCut { session_epoch: 0 },
        },
        DurableKeyIdentityV1::PrepareTxIndex {
            transaction_id: TransactionId::ZERO,
        },
    ];
    for identity in zero_identities {
        let mut output = [0xa5; 128];
        assert_eq!(
            encode_durable_key_v1(&durable_key(identity), &mut output),
            Err(DurableKeyError::ZeroIdentity)
        );
        assert_eq!(output, [0xa5; 128]);
    }

    for (case_index, offset, width) in [
        (2usize, 34usize, 8usize),
        (3, 34, 16),
        (4, 34, 16),
        (5, 34, 16),
        (6, 34, 16),
        (7, 34, 8),
        (7, 42, 8),
        (8, 34, 8),
        (8, 42, 8),
        (8, 50, 8),
        (9, 34, 8),
        (9, 42, 8),
        (9, 50, 8),
        (10, 34, 16),
        (10, 50, 8),
        (11, 34, 16),
        (13, 36, 8),
        (16, 36, 8),
        (18, 34, 16),
    ] {
        let mut literal = decode_hex_vec(canonical_key_cases()[case_index].1);
        literal[offset..offset + width].fill(0);
        assert_eq!(
            validate_durable_key_v1(&literal, 64),
            Err(DurableKeyError::ZeroIdentity),
            "zero parser identity case {case_index} offset {offset}",
        );
    }

    for identity in [
        DurableKeyIdentityV1::PtLane {
            ring_index: 64,
            kind_ordinal: 1,
        },
        DurableKeyIdentityV1::PtLane {
            ring_index: 0,
            kind_ordinal: 0,
        },
        DurableKeyIdentityV1::PtLane {
            ring_index: 0,
            kind_ordinal: 3,
        },
    ] {
        let mut output = [0xa5; 128];
        assert_eq!(
            encode_durable_key_v1(&durable_key(identity), &mut output),
            Err(DurableKeyError::InvalidLane)
        );
        assert_eq!(output, [0xa5; 128]);
    }

    let lane_zero = encode_key(DurableKeyIdentityV1::PtLane {
        ring_index: 0,
        kind_ordinal: 1,
    });
    assert_eq!(
        validate_durable_key_v1(&lane_zero, 0),
        Err(DurableKeyError::InvalidLane)
    );
    assert_eq!(
        validate_durable_key_v1(&lane_zero, 65),
        Err(DurableKeyError::InvalidLane)
    );
    let lane_one = encode_key(DurableKeyIdentityV1::PtLane {
        ring_index: 1,
        kind_ordinal: 2,
    });
    assert_eq!(
        validate_durable_key_v1(&lane_one, 1),
        Err(DurableKeyError::InvalidLane)
    );

    let mut short = [0xa5; 33];
    assert_eq!(
        encode_durable_key_v1(&durable_key(DurableKeyIdentityV1::Root), &mut short),
        Err(DurableKeyError::BufferTooSmall)
    );
    assert_eq!(short, [0xa5; 33]);

    let invalid_ns = DurableNamespaceV1 {
        mount_id: MountId::ZERO,
        boot_instance_id: BOOT,
    };
    let mut ordinary_output = [0xa5; 128];
    assert_eq!(
        encode_durable_key_v1(
            &DurableKeyV1 {
                namespace: invalid_ns,
                identity: DurableKeyIdentityV1::Root,
            },
            &mut ordinary_output,
        ),
        Err(DurableKeyError::InvalidNamespace)
    );
    assert_eq!(ordinary_output, [0xa5; 128]);

    let mut receipt_output = [0xa5; 64];
    assert_eq!(
        encode_retire_receipt_key_v1(invalid_ns, &mut receipt_output),
        Err(DurableKeyError::InvalidNamespace)
    );
    assert_eq!(receipt_output, [0xa5; 64]);

    let invalid_boot_ns = DurableNamespaceV1 {
        mount_id: MOUNT,
        boot_instance_id: BootInstanceId::ZERO,
    };
    let mut invalid_boot_ordinary_output = [0xa5; 128];
    assert_eq!(
        encode_durable_key_v1(
            &DurableKeyV1 {
                namespace: invalid_boot_ns,
                identity: DurableKeyIdentityV1::Root,
            },
            &mut invalid_boot_ordinary_output,
        ),
        Err(DurableKeyError::InvalidNamespace)
    );
    assert_eq!(invalid_boot_ordinary_output, [0xa5; 128]);
    let mut invalid_boot_receipt_output = [0xa5; 64];
    assert_eq!(
        encode_retire_receipt_key_v1(invalid_boot_ns, &mut invalid_boot_receipt_output),
        Err(DurableKeyError::InvalidNamespace)
    );
    assert_eq!(invalid_boot_receipt_output, [0xa5; 64]);

    let mut zero_mount_receipt = decode_hex::<32>(RECEIPT_KEY_HEX);
    zero_mount_receipt[..16].fill(0);
    assert_eq!(
        validate_retire_receipt_key_v1(&zero_mount_receipt),
        Err(DurableKeyError::InvalidNamespace)
    );
    let mut zero_boot_receipt = decode_hex::<32>(RECEIPT_KEY_HEX);
    zero_boot_receipt[16..32].fill(0);
    assert_eq!(
        validate_retire_receipt_key_v1(&zero_boot_receipt),
        Err(DurableKeyError::InvalidNamespace)
    );

    let mut short_receipt_output = [0xa5; 31];
    assert_eq!(
        encode_retire_receipt_key_v1(NS, &mut short_receipt_output),
        Err(DurableKeyError::BufferTooSmall)
    );
    assert_eq!(short_receipt_output, [0xa5; 31]);
    assert_eq!(
        validate_retire_receipt_key_v1(&root[..31]),
        Err(DurableKeyError::InvalidLength)
    );
    assert_eq!(
        validate_retire_receipt_key_v1(&root[..33]),
        Err(DurableKeyError::InvalidLength)
    );
}

#[test]
fn receipt_key_and_digest_facades_have_literal_goldens() {
    let root = encode_key(DurableKeyIdentityV1::Root);
    let mut receipt_output = [0xa5; 64];
    let literal_receipt_key = decode_hex::<32>(RECEIPT_KEY_HEX);
    assert_eq!(
        encode_retire_receipt_key_v1(NS, &mut receipt_output),
        Ok(DURABLE_RETIRE_RECEIPT_KEY_BYTES as usize)
    );
    assert_eq!(receipt_output[..32], literal_receipt_key);
    assert!(receipt_output[32..].iter().all(|byte| *byte == 0));
    assert_eq!(validate_retire_receipt_key_v1(&literal_receipt_key), Ok(NS));

    assert_eq!(
        durable_key_digest_v1(&root, 1),
        Ok(decode_hex::<32>(ROOT_KEY_DIGEST_HEX))
    );
    assert_eq!(
        durable_payload_digest_v1(b""),
        decode_hex::<32>(EMPTY_SHA256_HEX)
    );
    assert_eq!(
        durable_payload_digest_v1(b"abc"),
        decode_hex::<32>(ABC_SHA256_HEX)
    );
    let mut one_bit_key = root.clone();
    one_bit_key[0] ^= 1;
    assert_ne!(
        durable_key_digest_v1(&one_bit_key, 1).unwrap(),
        durable_key_digest_v1(&root, 1).unwrap()
    );
    let mut one_bit_payload = *b"abc";
    one_bit_payload[0] ^= 1;
    assert_ne!(
        durable_payload_digest_v1(&one_bit_payload),
        durable_payload_digest_v1(b"abc")
    );
}

#[test]
fn fixed_and_wrapped_metadata_validate_exact_private_images() {
    let root_key = encode_key(DurableKeyIdentityV1::Root);
    let root_bytes = decode_hex_vec(ROOT_VALUE_HEX);
    assert_eq!(encode_pod(&root_record()), root_bytes);
    let parsed_root = validate_provider_mount_root_v1(&root_key, &root_bytes, 1).unwrap();
    assert_eq!(parsed_root.version, 1);
    assert_eq!(parsed_root.state, provider_mount_root_state::ACTIVE);
    assert_eq!(parsed_root.boot_instance_id, BOOT);
    assert_eq!(parsed_root.mount_id, MOUNT);
    assert_eq!(parsed_root.latest_session_epoch, 1);
    assert_eq!(parsed_root.selected_features.words, [0x1c, 0]);
    assert_eq!(parsed_root.journal_version, 1);
    assert_eq!(parsed_root.service_sid_length, 32);
    assert_eq!(&parsed_root.service_sid[..32], &SID);
    assert_eq!(parsed_root.service_sid[32..], [0; 36]);
    assert_eq!(parsed_root.reserved, [0; 4]);
    assert_eq!(parsed_root.latest_proof_token, RetireToken { lo: 7, hi: 8 });

    let open_key = encode_key(DurableKeyIdentityV1::Open { kernel_open_id: 1 });
    let live = decode_hex_vec(OPEN_LIVE_VALUE_HEX);
    assert_eq!(
        child_value(
            &open_key,
            durable_child_kind::OPEN,
            durable_open_state::LIVE,
            b"abc",
        ),
        live,
    );
    assert_eq!(
        validate_durable_child_value_v1(&open_key, &live, 1),
        Ok(ValidatedDurableChildV1 {
            struct_size: 96,
            value_kind: durable_child_kind::OPEN,
            state: durable_open_state::LIVE,
            identity_digest: decode_hex::<32>(OPEN_KEY_DIGEST_HEX),
            payload_digest: decode_hex::<32>(ABC_SHA256_HEX),
            payload_offset: 88,
            payload_length: 3,
        })
    );

    let cleaned = decode_hex_vec(OPEN_CLEANED_VALUE_HEX);
    assert_eq!(
        child_value(
            &open_key,
            durable_child_kind::OPEN,
            durable_open_state::CLEANED,
            b"",
        ),
        cleaned,
    );
    assert_eq!(
        validate_durable_child_value_v1(&open_key, &cleaned, 1),
        Ok(ValidatedDurableChildV1 {
            struct_size: 88,
            value_kind: durable_child_kind::OPEN,
            state: durable_open_state::CLEANED,
            identity_digest: decode_hex::<32>(OPEN_KEY_DIGEST_HEX),
            payload_digest: decode_hex::<32>(EMPTY_SHA256_HEX),
            payload_offset: 0,
            payload_length: 0,
        })
    );

    let wrapped_cases: [(DurableKeyIdentityV1, u16, &[u16]); 10] = [
        (
            DurableKeyIdentityV1::Open { kernel_open_id: 1 },
            durable_child_kind::OPEN,
            &[durable_open_state::LIVE, durable_open_state::CLEANED],
        ),
        (
            DurableKeyIdentityV1::Prepare { op_id: OP },
            durable_child_kind::PREPARE,
            &[durable_prepare_state::PREPARED],
        ),
        (
            DurableKeyIdentityV1::ImmutableRequest { op_id: OP },
            durable_child_kind::IMMUTABLE_REQUEST,
            &[durable_immutable_request_state::RETAINED],
        ),
        (
            DurableKeyIdentityV1::CommittedResult { op_id: OP },
            durable_child_kind::COMMITTED_RESULT,
            &[durable_committed_result_state::COMMITTED],
        ),
        (
            DurableKeyIdentityV1::Journal { op_id: OP },
            durable_child_kind::JOURNAL,
            &[
                durable_journal_state::PREPARED,
                durable_journal_state::COMMITTED,
            ],
        ),
        (
            DurableKeyIdentityV1::QueryDirSnapshot {
                kernel_open_id: 1,
                generation: 2,
            },
            durable_child_kind::QUERY_DIR_SNAPSHOT,
            &[durable_query_dir_snapshot_state::ACTIVE],
        ),
        (
            DurableKeyIdentityV1::QueryDirAttempt {
                kernel_open_id: 1,
                generation: 2,
                input_cookie: 3,
                attempt_digest: [0; 32],
            },
            durable_child_kind::QUERY_DIR_ATTEMPT,
            &[durable_query_dir_attempt_state::ACCEPTED],
        ),
        (
            DurableKeyIdentityV1::QueryDirCookie {
                kernel_open_id: 1,
                generation: 2,
                cookie: 3,
            },
            durable_child_kind::QUERY_DIR_COOKIE,
            &[durable_query_dir_cookie_state::ACTIVE],
        ),
        (
            DurableKeyIdentityV1::PtEpochIntent {
                file_id: FILE,
                pt_epoch: 1,
            },
            durable_child_kind::PT_EPOCH_INTENT,
            &[
                durable_pt_epoch_intent_state::PENDING,
                durable_pt_epoch_intent_state::ACCEPTED,
                durable_pt_epoch_intent_state::REVOKED,
            ],
        ),
        (
            DurableKeyIdentityV1::PtLane {
                ring_index: 0,
                kind_ordinal: 1,
            },
            durable_child_kind::PT_LANE,
            &[durable_pt_lane_state::PRESENT],
        ),
    ];
    for (identity, kind, states) in wrapped_cases {
        let key = encode_key(identity);
        for state in states {
            let value = child_value(&key, kind, *state, b"opaque");
            let validated = validate_durable_child_value_v1(&key, &value, 64).unwrap();
            assert_eq!(validated.value_kind, kind);
            assert_eq!(validated.state, *state);
            assert_eq!(validated.payload_offset, 88);
            assert_eq!(validated.payload_length, 6);
        }
        let invalid_state = child_value(&key, kind, u16::MAX, b"opaque");
        assert_metadata_error(
            validate_durable_child_value_v1(&key, &invalid_state, 64),
            DurableMetadataError::InvalidState,
        );
    }
}

#[test]
fn metadata_mutations_fail_with_closed_precedence() {
    let root_key = encode_key(DurableKeyIdentityV1::Root);
    let root = root_record();
    let root_bytes = encode_pod(&root);
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key[..33], &root_bytes[..159], 1),
        DurableMetadataError::InvalidLength,
    );

    let mut invalid_root_key = root_key.clone();
    invalid_root_key[..16].fill(0);
    assert_metadata_error(
        validate_provider_mount_root_v1(&invalid_root_key, &root_bytes, 1),
        DurableMetadataError::InvalidNamespace,
    );

    let mut mutated_root = root_record();
    mutated_root.reserved[0] = 1;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::FlagsOrReserved,
    );
    mutated_root = root_record();
    mutated_root.state = 0;
    mutated_root.reserved[0] = 1;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::FlagsOrReserved,
    );
    mutated_root = root_record();
    mutated_root.state = 0;
    mutated_root.latest_session_epoch = 0;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidIdentity,
    );
    mutated_root = root_record();
    mutated_root.state = 0;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidState,
    );
    mutated_root = root_record();
    mutated_root.version = 0;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidState,
    );
    mutated_root = root_record();
    mutated_root.latest_session_epoch = 0;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidIdentity,
    );
    mutated_root = root_record();
    mutated_root.mount_id.lo ^= 1;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidNamespace,
    );
    mutated_root = root_record();
    mutated_root.service_sid_length = 31;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidServiceSid,
    );
    mutated_root = root_record();
    mutated_root.service_sid[0] = 0;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidServiceSid,
    );
    mutated_root = root_record();
    mutated_root.service_sid[32] = 1;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidServiceSid,
    );
    mutated_root = root_record();
    mutated_root.selected_features.words[1] = 1;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::FlagsOrReserved,
    );
    mutated_root = root_record();
    mutated_root.selected_features.words[0] = 0x1c | 0x100;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::FlagsOrReserved,
    );
    mutated_root = root_record();
    mutated_root.selected_features.words[0] = 0x18;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidState,
    );
    mutated_root = root_record();
    mutated_root.journal_version = 0;
    assert_metadata_error(
        validate_provider_mount_root_v1(&root_key, &encode_pod(&mutated_root), 1),
        DurableMetadataError::InvalidState,
    );

    let open_key = encode_key(DurableKeyIdentityV1::Open { kernel_open_id: 1 });
    let live = child_value(
        &open_key,
        durable_child_kind::OPEN,
        durable_open_state::LIVE,
        b"abc",
    );
    let mutate_u16 = |offset: usize, value: u16| {
        let mut bytes = live.clone();
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        bytes
    };
    let mutate_u32 = |offset: usize, value: u32| {
        let mut bytes = live.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        bytes
    };

    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &live[..87], 1),
        DurableMetadataError::InvalidLength,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u32(0, 88), 1),
        DurableMetadataError::Header,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u16(4, 2), 1),
        DurableMetadataError::Header,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u16(6, 1), 1),
        DurableMetadataError::Header,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u32(12, 1), 1),
        DurableMetadataError::FlagsOrReserved,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u16(8, durable_child_kind::PREPARE), 1),
        DurableMetadataError::InvalidKind,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u16(10, 0), 1),
        DurableMetadataError::InvalidState,
    );

    let mut identity_digest = live.clone();
    identity_digest[16] ^= 1;
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &identity_digest, 1),
        DurableMetadataError::IdentityDigest,
    );
    let mut payload_digest = live.clone();
    payload_digest[48] ^= 1;
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &payload_digest, 1),
        DurableMetadataError::PayloadDigest,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u32(80, 89), 1),
        DurableMetadataError::InvalidPayloadShape,
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &mutate_u32(84, u32::MAX), 1),
        DurableMetadataError::InvalidPayloadShape,
    );
    let mut padding = live.clone();
    padding[95] = 1;
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &padding, 1),
        DurableMetadataError::TailPadding,
    );

    let root_wrapper = child_value(
        &root_key,
        durable_child_kind::ROOT,
        provider_mount_root_state::ACTIVE as u16,
        b"",
    );
    assert_metadata_error(
        validate_durable_child_value_v1(&root_key, &root_wrapper, 1),
        DurableMetadataError::InvalidKind,
    );

    let mut header_precedence = live.clone();
    header_precedence[4..6].copy_from_slice(&2u16.to_le_bytes());
    header_precedence[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &header_precedence, 1),
        DurableMetadataError::Header,
    );

    let mut flags_before_kind = live.clone();
    flags_before_kind[8..10].copy_from_slice(&durable_child_kind::PREPARE.to_le_bytes());
    flags_before_kind[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert_metadata_error(
        validate_durable_child_value_v1(&open_key, &flags_before_kind, 1),
        DurableMetadataError::FlagsOrReserved,
    );
}

#[test]
fn reservation_index_fixed_external_and_receipt_values_cross_check() {
    let target_key = encode_key(DurableKeyIdentityV1::Root);
    let target_value = decode_hex_vec(ROOT_VALUE_HEX);
    let target_digest = decode_hex::<32>(ROOT_KEY_DIGEST_HEX);
    let reservation_key = encode_key(DurableKeyIdentityV1::AccountingReservation {
        target_key_digest: target_digest,
    });
    let reservation = AccountingReservationV1 {
        target_child_kind: durable_child_kind::ROOT,
        flags: 0,
        target_key_length: target_key.len().try_into().unwrap(),
        charged_bytes: 264,
        target_key_digest: target_digest,
    };
    let reservation_bytes = decode_hex_vec(ACCOUNTING_RESERVATION_VALUE_HEX);
    assert_eq!(encode_pod(&reservation), reservation_bytes);
    let parsed_reservation = validate_accounting_reservation_v1(
        &reservation_key,
        &reservation_bytes,
        &target_key,
        target_value.len() as u64,
        1,
    )
    .unwrap();
    assert_eq!(
        parsed_reservation.target_child_kind,
        durable_child_kind::ROOT
    );
    assert_eq!(parsed_reservation.flags, 0);
    assert_eq!(parsed_reservation.target_key_length, 34);
    assert_eq!(parsed_reservation.charged_bytes, 264);
    assert_eq!(parsed_reservation.target_key_digest, target_digest);

    let mut wrong_charge = reservation;
    wrong_charge.charged_bytes -= 1;
    assert_metadata_error(
        validate_accounting_reservation_v1(
            &reservation_key,
            &encode_pod(&wrong_charge),
            &target_key,
            target_value.len() as u64,
            1,
        ),
        DurableMetadataError::ChargeMismatch,
    );
    let mut reservation_flags = reservation;
    reservation_flags.flags = 1;
    assert_metadata_error(
        validate_accounting_reservation_v1(
            &reservation_key,
            &encode_pod(&reservation_flags),
            &target_key,
            target_value.len() as u64,
            1,
        ),
        DurableMetadataError::FlagsOrReserved,
    );
    let mut reservation_kind = reservation;
    reservation_kind.target_child_kind = durable_child_kind::OPEN;
    assert_metadata_error(
        validate_accounting_reservation_v1(
            &reservation_key,
            &encode_pod(&reservation_kind),
            &target_key,
            target_value.len() as u64,
            1,
        ),
        DurableMetadataError::InvalidKind,
    );
    let mut reservation_digest = reservation;
    reservation_digest.target_key_digest[0] ^= 1;
    assert_metadata_error(
        validate_accounting_reservation_v1(
            &reservation_key,
            &encode_pod(&reservation_digest),
            &target_key,
            target_value.len() as u64,
            1,
        ),
        DurableMetadataError::IdentityDigest,
    );
    let other_namespace = DurableNamespaceV1 {
        mount_id: MountId {
            lo: MOUNT.lo ^ 1,
            hi: MOUNT.hi,
        },
        boot_instance_id: BOOT,
    };
    let mut other_target = [0u8; 90];
    let other_length = encode_durable_key_v1(
        &DurableKeyV1 {
            namespace: other_namespace,
            identity: DurableKeyIdentityV1::Root,
        },
        &mut other_target,
    )
    .unwrap();
    assert_metadata_error(
        validate_accounting_reservation_v1(
            &reservation_key,
            &reservation_bytes,
            &other_target[..other_length],
            target_value.len() as u64,
            1,
        ),
        DurableMetadataError::InvalidNamespace,
    );

    let prepare_index_key = encode_key(DurableKeyIdentityV1::PrepareTxIndex { transaction_id: TX });
    let prepare_index = PrepareTxIndexValueV1 {
        op_id: OP,
        identity_digest: decode_hex::<32>(
            "fd668df86ae5336ded869c6399c27cb7e4ad1692fee1612ec885274af1407d31",
        ),
    };
    let prepare_index_bytes = decode_hex_vec(PREPARE_TX_INDEX_VALUE_HEX);
    assert_eq!(encode_pod(&prepare_index), prepare_index_bytes);
    let parsed_index =
        validate_prepare_tx_index_value_v1(&prepare_index_key, &prepare_index_bytes, 1).unwrap();
    assert_eq!(parsed_index.op_id, OP);
    assert_eq!(
        parsed_index.identity_digest,
        decode_hex::<32>("fd668df86ae5336ded869c6399c27cb7e4ad1692fee1612ec885274af1407d31")
    );
    let mut zero_op = prepare_index;
    zero_op.op_id = OpId::ZERO;
    assert_metadata_error(
        validate_prepare_tx_index_value_v1(&prepare_index_key, &encode_pod(&zero_op), 1),
        DurableMetadataError::InvalidIdentity,
    );
    let mut wrong_index_digest = prepare_index;
    wrong_index_digest.identity_digest[0] ^= 1;
    assert_metadata_error(
        validate_prepare_tx_index_value_v1(&prepare_index_key, &encode_pod(&wrong_index_digest), 1),
        DurableMetadataError::IdentityDigest,
    );

    let latest_key = encode_key(DurableKeyIdentityV1::ExternalNotifyOutbox {
        identity: ExternalNotifyKeyIdentityV1::LatestProcessed,
    });
    let latest = LatestProcessedV1 {
        first_ordinal: 0,
        through_ordinal: u64::MAX,
        volume_commit_sequence: 1u64 << 63,
        semantic_digest: [0xa5; 32],
    };
    let latest_bytes = decode_hex_vec(LATEST_PROCESSED_VALUE_HEX);
    assert_eq!(encode_pod(&latest), latest_bytes);
    let parsed_latest = validate_latest_processed_v1(&latest_key, &latest_bytes, 1).unwrap();
    assert_eq!(parsed_latest.first_ordinal, 0);
    assert_eq!(parsed_latest.through_ordinal, u64::MAX);
    assert_eq!(parsed_latest.volume_commit_sequence, 1u64 << 63);
    assert_eq!(parsed_latest.semantic_digest, [0xa5; 32]);
    assert_metadata_error(
        validate_latest_processed_v1(&target_key, &encode_pod(&latest), 1),
        DurableMetadataError::InvalidKind,
    );

    let raw_keys = [
        DurableKeyIdentityV1::PtEpochCounter { file_id: FILE },
        DurableKeyIdentityV1::VolumeCommitCounter,
        DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: ExternalNotifyKeyIdentityV1::OrdinalCounter,
        },
        DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: ExternalNotifyKeyIdentityV1::AttachCut { session_epoch: 1 },
        },
    ];
    let raw_value_hex = [
        "0000000000000000",
        "ffffffffffffffff",
        "1122334455667788",
        "1122334455667788",
    ];
    for ((index, identity), literal_hex) in raw_keys.into_iter().enumerate().zip(raw_value_hex) {
        let key = encode_key(identity);
        let value = if index == 0 {
            0
        } else if index == 1 {
            u64::MAX
        } else {
            0x8877_6655_4433_2211
        };
        let literal = decode_hex::<8>(literal_hex);
        assert_eq!(value.to_le_bytes(), literal);
        assert_eq!(validate_durable_u64_value_v1(&key, &literal, 1), Ok(value));
    }
    assert_metadata_error(
        validate_durable_u64_value_v1(&target_key, &0u64.to_le_bytes(), 1),
        DurableMetadataError::InvalidKind,
    );
    assert_metadata_error(
        validate_durable_u64_value_v1(
            &encode_key(DurableKeyIdentityV1::VolumeCommitCounter),
            &[0; 7],
            1,
        ),
        DurableMetadataError::InvalidLength,
    );

    let receipt_key = decode_hex::<32>(RECEIPT_KEY_HEX);
    let mut encoded_receipt_key = [0u8; 32];
    assert_eq!(
        encode_retire_receipt_key_v1(NS, &mut encoded_receipt_key),
        Ok(32)
    );
    assert_eq!(encoded_receipt_key, receipt_key);
    let receipt = RetireReceiptV1 {
        retire_token: RetireToken {
            lo: 0,
            hi: u64::MAX,
        },
        state: retire_receipt_state::RECEIPT_PENDING_ACK,
        reserved: [0; 12],
    };
    let receipt_bytes = decode_hex_vec(RETIRE_RECEIPT_VALUE_HEX);
    assert_eq!(encode_pod(&receipt), receipt_bytes);
    let parsed_receipt = validate_retire_receipt_v1(&receipt_key, &receipt_bytes).unwrap();
    assert_eq!(parsed_receipt.retire_token, receipt.retire_token);
    assert_eq!(
        parsed_receipt.state,
        retire_receipt_state::RECEIPT_PENDING_ACK
    );
    assert_eq!(parsed_receipt.reserved, [0; 12]);
    let mut invalid_receipt_state = receipt;
    invalid_receipt_state.state = 0;
    assert_metadata_error(
        validate_retire_receipt_v1(&receipt_key, &encode_pod(&invalid_receipt_state)),
        DurableMetadataError::InvalidState,
    );
    let mut invalid_receipt_reserved = receipt;
    invalid_receipt_reserved.reserved[0] = 1;
    assert_metadata_error(
        validate_retire_receipt_v1(&receipt_key, &encode_pod(&invalid_receipt_reserved)),
        DurableMetadataError::FlagsOrReserved,
    );
    let mut invalid_receipt_precedence = receipt;
    invalid_receipt_precedence.state = 0;
    invalid_receipt_precedence.reserved[0] = 1;
    assert_metadata_error(
        validate_retire_receipt_v1(&receipt_key, &encode_pod(&invalid_receipt_precedence)),
        DurableMetadataError::FlagsOrReserved,
    );
}

#[test]
fn durable_accounting_goldens_limits_and_round_trips_are_exact() {
    assert_eq!(CONST_RECORD_CHARGE, Ok(264));
    assert_eq!(CONST_ACCOUNTING_VALID, Ok(()));
    assert_eq!(
        CONST_ADD_ORDINARY,
        Ok(DurableAccountingV1 {
            ordinary_charged_bytes: 1,
            receipt_count: 0,
            receipt_actual_bytes: 0,
        })
    );
    assert_eq!(
        CONST_REMOVE_ORDINARY,
        Ok(DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 0,
            receipt_actual_bytes: 0,
        })
    );
    assert_eq!(
        CONST_ADD_RECEIPT,
        Ok(DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 1,
            receipt_actual_bytes: 128,
        })
    );
    assert_eq!(
        CONST_REMOVE_RECEIPT,
        Ok(DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 0,
            receipt_actual_bytes: 0,
        })
    );

    for (key_bytes, value_bytes, expected) in [
        (34, 160, 264),
        (66, 48, 184),
        (50, 48, 168),
        (36, 56, 160),
        (36, 8, 112),
        (34, 8, 112),
        (44, 8, 120),
        (32, 32, 128),
    ] {
        assert_eq!(
            durable_record_charge_v1(key_bytes, value_bytes),
            Ok(expected)
        );
    }
    for remainder in 0u64..8 {
        let expected = ((remainder + 7) & !7) + DURABLE_RECORD_ACCOUNTING_OVERHEAD;
        assert_eq!(durable_record_charge_v1(remainder, 0), Ok(expected));
    }
    assert_eq!(
        durable_record_charge_v1(u64::MAX, 1),
        Err(DurableAccountingError::ArithmeticOverflow)
    );
    assert_eq!(
        durable_record_charge_v1(u64::MAX, 0),
        Err(DurableAccountingError::ArithmeticOverflow)
    );
    assert_eq!(
        durable_record_charge_v1(u64::MAX - 64, 0),
        Err(DurableAccountingError::ArithmeticOverflow)
    );

    let zero = DurableAccountingV1 {
        ordinary_charged_bytes: 0,
        receipt_count: 0,
        receipt_actual_bytes: 0,
    };
    assert_eq!(validate_durable_accounting_v1(zero), Ok(()));
    assert_eq!(
        validate_durable_accounting_v1(DurableAccountingV1 {
            ordinary_charged_bytes: MAX_DURABLE_ORDINARY_BYTES_GLOBAL + 1,
            ..zero
        }),
        Err(DurableAccountingError::OrdinaryLimitExceeded)
    );
    assert_eq!(
        validate_durable_accounting_v1(DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: u64::MAX,
            receipt_actual_bytes: 0,
        }),
        Err(DurableAccountingError::ArithmeticOverflow)
    );
    assert_eq!(
        validate_durable_accounting_v1(DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 65,
            receipt_actual_bytes: 65 * RETIRE_RECEIPT_CHARGE_BYTES,
        }),
        Err(DurableAccountingError::ReceiptCountExceeded)
    );
    assert_eq!(
        validate_durable_accounting_v1(DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 1,
            receipt_actual_bytes: 0,
        }),
        Err(DurableAccountingError::ReceiptBytesMismatch)
    );
    assert_eq!(
        MAX_DURABLE_RETIRE_RECEIPTS * RETIRE_RECEIPT_CHARGE_BYTES,
        RETIRE_RECEIPT_RESERVED_BYTES
    );
    assert_eq!(
        MAX_DURABLE_ORDINARY_BYTES_GLOBAL + RETIRE_RECEIPT_RESERVED_BYTES,
        MAX_DURABLE_RECOVERY_BYTES_GLOBAL
    );
    let _closed_errors = [
        DurableAccountingError::ReceiptReserveExceeded,
        DurableAccountingError::GlobalLimitExceeded,
    ];

    let ordinary = checked_add_ordinary_charge_v1(zero, 264).unwrap();
    assert_eq!(ordinary.ordinary_charged_bytes, 264);
    assert_eq!(ordinary.receipt_count, 0);
    assert_eq!(ordinary.receipt_actual_bytes, 0);
    assert_eq!(checked_remove_ordinary_charge_v1(ordinary, 264), Ok(zero));
    assert_eq!(
        checked_remove_ordinary_charge_v1(zero, 1),
        Err(DurableAccountingError::Underflow)
    );
    assert_eq!(
        checked_add_ordinary_charge_v1(zero, MAX_DURABLE_ORDINARY_BYTES_GLOBAL)
            .unwrap()
            .ordinary_charged_bytes,
        MAX_DURABLE_ORDINARY_BYTES_GLOBAL
    );
    assert_eq!(
        checked_add_ordinary_charge_v1(zero, MAX_DURABLE_ORDINARY_BYTES_GLOBAL + 1),
        Err(DurableAccountingError::OrdinaryLimitExceeded)
    );

    let with_receipt = checked_add_retire_receipt_v1(zero).unwrap();
    assert_eq!(
        with_receipt,
        DurableAccountingV1 {
            ordinary_charged_bytes: 0,
            receipt_count: 1,
            receipt_actual_bytes: RETIRE_RECEIPT_CHARGE_BYTES,
        }
    );
    assert_eq!(checked_remove_retire_receipt_v1(with_receipt), Ok(zero));
    assert_eq!(
        checked_remove_retire_receipt_v1(zero),
        Err(DurableAccountingError::Underflow)
    );

    let invalid_input = DurableAccountingV1 {
        ordinary_charged_bytes: MAX_DURABLE_ORDINARY_BYTES_GLOBAL + 1,
        receipt_count: 0,
        receipt_actual_bytes: 0,
    };
    assert_eq!(
        checked_add_ordinary_charge_v1(invalid_input, 0),
        Err(DurableAccountingError::OrdinaryLimitExceeded)
    );
    assert_eq!(
        checked_add_retire_receipt_v1(invalid_input),
        Err(DurableAccountingError::OrdinaryLimitExceeded)
    );
}

#[test]
fn slice_apis_reject_lengths_without_panicking() {
    let root_key = encode_key(DurableKeyIdentityV1::Root);
    let valid_key = durable_key(DurableKeyIdentityV1::Root);
    for length in 0usize..=256 {
        let input = vec![0u8; length];
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = validate_durable_key_v1(&input, 1);
            let _ = durable_key_digest_v1(&input, 1);
            let _ = validate_retire_receipt_key_v1(&input);
            let _ = validate_provider_mount_root_v1(&input, &input, 1);
            let _ = validate_durable_child_value_v1(&input, &input, 1);
            let _ = validate_accounting_reservation_v1(&input, &input, &input, 0, 1);
            let _ = validate_prepare_tx_index_value_v1(&input, &input, 1);
            let _ = validate_latest_processed_v1(&input, &input, 1);
            let _ = validate_durable_u64_value_v1(&input, &input, 1);
            let _ = validate_retire_receipt_v1(&input, &input);

            let mut output = vec![0xa5; length];
            let _ = encode_durable_key_v1(&valid_key, &mut output);
            let _ = encode_retire_receipt_key_v1(NS, &mut output);
        }));
        assert!(
            result.is_ok(),
            "public slice API panicked at length {length}"
        );
    }
    assert_eq!(
        validate_durable_key_v1(&root_key, 1),
        Ok(durable_key(DurableKeyIdentityV1::Root))
    );
}

#[test]
fn derive_and_pod_surface_is_exact() {
    let helper_derive = "#[derive(Clone, Copy, Debug, PartialEq, Eq)]";
    for declaration in [
        "pub struct DurableNamespaceV1 {",
        "pub enum ExternalNotifyKeyIdentityV1 {",
        "pub enum DurableKeyIdentityV1 {",
        "pub struct DurableKeyV1 {",
        "pub enum DurableKeyError {",
    ] {
        assert_exact_derive_line("src/durable/key.rs", declaration, helper_derive, None);
    }
    for declaration in [
        "pub struct DurableAccountingV1 {",
        "pub enum DurableAccountingError {",
    ] {
        assert_exact_derive_line(
            "src/durable/accounting.rs",
            declaration,
            helper_derive,
            None,
        );
    }
    for declaration in [
        "pub struct ValidatedDurableChildV1 {",
        "pub enum DurableMetadataError {",
    ] {
        assert_exact_derive_line("src/validate/durable.rs", declaration, helper_derive, None);
    }
    for (declaration, repr) in [
        ("pub struct ProviderMountRootV1 {", "#[repr(C)]"),
        ("pub struct DurableChildValueV1 {", "#[repr(C, align(8))]"),
        ("pub struct AccountingReservationV1 {", "#[repr(C)]"),
        ("pub struct PrepareTxIndexValueV1 {", "#[repr(C)]"),
        ("pub struct LatestProcessedV1 {", "#[repr(C)]"),
        ("pub struct RetireReceiptV1 {", "#[repr(C)]"),
    ] {
        assert_exact_derive_line(
            "src/durable/metadata.rs",
            declaration,
            "#[derive(Clone, Copy)]",
            Some(repr),
        );
    }

    for (path, expected_count) in [
        ("src/durable/metadata.rs", 6usize),
        ("src/durable/key.rs", 0),
        ("src/durable/accounting.rs", 0),
        ("src/validate/durable.rs", 0),
    ] {
        let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap();
        assert_eq!(
            source.matches("unsafe impl Pod for ").count(),
            expected_count,
            "{path}"
        );
    }
}

#[test]
fn wave4b_keeps_abi_identity_and_artifacts_frozen() {
    // Wave 10 activation rebaseline + Wave 15 ZIP rebaseline: identity is 2.1,
    // the header and Cargo.lock stay byte-frozen, `durable` is now exported, and
    // the durable wire types are in the header while the internal namespace/
    // accounting/key items stay hidden. The two ZIPs are regenerated in Wave 15
    // (freeze lifted); their SHA-256s are recorded in the durable ledger, not
    // pinned here — fsring-abi.zip's hash cannot be self-asserted because this
    // test file is a member of that archive.
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.1");
    assert_eq!(FSRING_ABI_MINOR, 1);
    assert_eq!(
        durable_payload_digest_v1(include_bytes!("../include/fsring_abi.h")),
        decode_hex::<32>("7bc16346475e8bd786306368ef90d80e6f3009b8cc44adc11ca6dfd60509ab2d")
    );
    // Wave 15 ZIP rebaseline: the two ZIP-hash freeze assertions are retired
    // (the archives are regenerated and their SHA-256s recorded in the durable
    // ledger; fsring-abi.zip's hash cannot be self-asserted here because this
    // test file is a member of that archive). The header and Cargo.lock freezes
    // remain guarded below and above.
    assert_eq!(
        durable_payload_digest_v1(include_bytes!("../Cargo.lock")),
        decode_hex::<32>("0c662af3fadb2e635e7b004943ad1102a3451b87218ef7a236d48f7e6926b017")
    );

    let crate_root = include_str!("../src/lib.rs");
    assert_eq!(crate_root.matches("pub mod durable;").count(), 1);
    assert!(!crate_root.contains("/// cbindgen:ignore\npub mod durable;"));
    assert!(!crate_root.contains("pub use durable"));

    let header = core::str::from_utf8(include_bytes!("../include/fsring_abi.h")).unwrap();
    // The durable child-value wire type is now part of the activated contract.
    assert!(header.contains("DurableChildValueV1"));
    for forbidden in [
        "DurableNamespaceV1",
        "DurableAccountingV1",
        "durable_key_digest_v1",
        "MAX_DURABLE_RECOVERY_BYTES_GLOBAL",
    ] {
        assert!(
            !header.contains(forbidden),
            "{forbidden} leaked into header"
        );
    }
}
