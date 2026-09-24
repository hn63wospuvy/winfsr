use core::mem::{align_of, offset_of, size_of};
use fsring_abi::{
    codec::Pod,
    features::{os_cap, protocol_feature, FeatureError, FeatureSet},
    ids::{
        AckToken, FileId, IdError, LinkId, MountId, OpId, ReqId, TransactionId, REQ_GENERATION_MAX,
        REQ_INDEX_MAX,
    },
};

fn assert_pod<T: Pod>() {}

macro_rules! assert_wire_layout {
    ($ty:ty, $size:expr, $align:expr; $($field:ident : $field_ty:ty => $offset:expr),+ $(,)?) => {{
        assert_eq!(size_of::<$ty>(), $size, "{} size", stringify!($ty));
        assert_eq!(align_of::<$ty>(), $align, "{} alignment", stringify!($ty));
        let mut next = 0usize;
        $(
            let _: fn(&$ty) -> $field_ty = |value| value.$field;
            let expected_offset: usize = $offset;
            assert_eq!(
                offset_of!($ty, $field),
                expected_offset,
                "{}.{} offset",
                stringify!($ty),
                stringify!($field)
            );
            assert_eq!(
                expected_offset,
                next,
                "implicit gap before {}.{}",
                stringify!($ty),
                stringify!($field)
            );
            next += size_of::<$field_ty>();
        )+
        assert_eq!(next, size_of::<$ty>(), "{} tail padding", stringify!($ty));
        assert_pod::<$ty>();
    }};
}

#[test]
fn req_id_uses_all_40_generation_bits() {
    let generation = (1u64 << 39) | 0x1234;
    let id = ReqId::try_new(generation, REQ_INDEX_MAX).unwrap();
    assert_eq!(id.generation(), generation);
    assert_eq!(id.slot_index(), REQ_INDEX_MAX);
    assert_eq!(id.raw(), (generation << 24) | REQ_INDEX_MAX as u64);
}

#[test]
fn req_id_rejects_out_of_range_fields() {
    assert_eq!(
        ReqId::try_new(REQ_GENERATION_MAX + 1, 0),
        Err(IdError::GenerationOutOfRange)
    );
    assert_eq!(
        ReqId::try_new(0, REQ_INDEX_MAX + 1),
        Err(IdError::SlotOutOfRange)
    );
}

#[test]
fn typed_128_bit_ids_have_c_stable_size() {
    assert_eq!(size_of::<OpId>(), 16);
    assert_eq!(size_of::<FileId>(), 16);
    assert_eq!(size_of::<AckToken>(), 16);
    assert_eq!(OpId::ZERO, OpId { lo: 0, hi: 0 });
}

#[test]
fn foundational_wire_fields_have_exact_types_and_gapless_offsets() {
    assert_wire_layout!(FeatureSet, 16, 8;
        words: [u64; 2] => 0,
    );

    assert_wire_layout!(OpId, 16, 8; lo: u64 => 0, hi: u64 => 8);
    assert_wire_layout!(FileId, 16, 8; lo: u64 => 0, hi: u64 => 8);
    assert_wire_layout!(LinkId, 16, 8; lo: u64 => 0, hi: u64 => 8);
    assert_wire_layout!(MountId, 16, 8; lo: u64 => 0, hi: u64 => 8);
    assert_wire_layout!(TransactionId, 16, 8; lo: u64 => 0, hi: u64 => 8);
    assert_wire_layout!(AckToken, 16, 8; lo: u64 => 0, hi: u64 => 8);

    assert_eq!(size_of::<ReqId>(), 8);
    assert_eq!(align_of::<ReqId>(), 8);
    assert_eq!(ReqId::from_raw(u64::MAX).raw(), u64::MAX);
    assert_pod::<ReqId>();
}

#[test]
fn feature_sets_cover_128_bits_and_check_bounds() {
    let mut offered = FeatureSet::default();
    offered.insert(protocol_feature::PT).unwrap();
    offered.insert(protocol_feature::HOT_RESTART).unwrap();
    offered.insert(os_cap::ARM64).unwrap();
    assert!(offered.contains(protocol_feature::PT));
    assert!(offered.contains(protocol_feature::HOT_RESTART));
    assert!(offered.contains(os_cap::ARM64));
    assert_eq!(offered.insert(128), Err(FeatureError::BitOutOfRange));
    assert!(!offered.contains(128));
}

#[test]
fn feature_sets_support_bit_127() {
    let mut features = FeatureSet::default();

    features.insert(127).unwrap();

    assert!(features.contains(127));
    assert_eq!(features.words, [0, 1u64 << 63]);
}

#[test]
fn feature_subset_checks_both_words() {
    let mut offered = FeatureSet::default();
    offered.insert(protocol_feature::MMAP).unwrap();
    offered.insert(127).unwrap();

    let requested = offered;
    assert!(requested.is_subset_of(offered));

    let mut missing_low_word = requested;
    missing_low_word
        .insert(protocol_feature::HOT_RESTART)
        .unwrap();
    assert!(!missing_low_word.is_subset_of(offered));

    let mut missing_high_word = requested;
    missing_high_word.insert(126).unwrap();
    assert!(!missing_high_word.is_subset_of(offered));
}
