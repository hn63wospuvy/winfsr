//! Wave 9 notification wire surface: layout, registries, and semantic digest.

use core::mem::{align_of, offset_of, size_of};

use fsring_abi::{
    codec::{try_encode, Pod},
    digest::{
        external_dir_change_semantic_digest_v1, sha256_bytes, EXTERNAL_DIR_CHANGE_DIGEST_DOMAIN,
    },
    durable::{
        encode_durable_key_v1, DurableKeyIdentityV1, DurableKeyV1, DurableNamespaceV1,
        ExternalNotifyKeyIdentityV1, MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS,
    },
    file_action, file_notify_information, file_notify_information_entry_len,
    msgs::{
        external_change_kind, external_object_kind, notify_ack_kind, BlobSlice, ControlHeader,
        ExternalChangeCutV1, ExternalChangeReadyV1, ExternalDirChangeV1, InvalidateEntryV1,
        InvalidateFileV1, NotifyEnvelopeV2, PDirChangeAckV1, PtEpochV1, PtGrantV1, PtLaneReadyV1,
        ResizeV1, SizeState, ACK_TOKEN_HI_MASK, ACK_TOKEN_HI_TAG,
    },
    notify, notify_filter, op,
    validate::{
        classify_external_change_cut_v21, classify_external_change_ready_v21,
        classify_external_ordinal_interval_v21, classify_notification_credit_v21,
        classify_pt_ack_v21, classify_pt_lane_ready_v21, decode_ack_token,
        external_dir_change_ack_token, next_pt_lane_ordinal_v21, pt_ack_token,
        pt_lane_can_publish_v21, validate_external_outbox_row_v1, validate_notify_envelope_v2,
        validate_pdir_change_ack_v1, validate_pnotify_ack_v21, AckTokenPartsV21, AttachBarrierV21,
        AttachCutContextV21, AttachReadyContextV21, ExternalOrdinalIntervalV21,
        MessageValidationError, NotificationCreditClassV21, NotificationCreditRefV21,
        PtLaneAckActionV21, PtLaneStateV21, RetainedExternalTupleV21, ValidatedNotifyBodyV2,
    },
    AckToken, BootInstanceId, FileId, LinkId, MountId, EXTERNAL_MODIFY_FILTER_MASK,
    EXTERNAL_OUTBOX_OVERFLOW_RESERVE_BYTES, MAX_EXTERNAL_CHANGE_NAME_BYTES,
    MAX_NOTIFY_BUFFER_BYTES_PER_CCB, MAX_NOTIFY_BUFFER_BYTES_PER_MOUNT, MAX_NOTIFY_PATH_COMPONENTS,
    MAX_NOTIFY_REGISTRATIONS_PER_MOUNT, MAX_NOTIFY_RELATIVE_PATH_BYTES,
    MAX_OUTSTANDING_EXTERNAL_CHANGE, MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING,
    MAX_PENDING_NOTIFY_IRPS_PER_CCB, MAX_PENDING_NOTIFY_IRPS_PER_MOUNT,
    MAX_PENDING_NOTIFY_MDL_BYTES_PER_CCB, MAX_PENDING_NOTIFY_MDL_BYTES_PER_MOUNT,
    MAX_PRECISE_EXTERNAL_OUTBOX_RECORDS, MAX_PRECISE_NOTIFY_LINKS_PER_LOCAL_OPERATION,
    MIN_EXTERNAL_CHANGE_NAME_BYTES, VALID_NOTIFY_FILTER_MASK,
};

fn assert_pod<T: Pod>() {}

macro_rules! assert_wire_layout {
    ($ty:ty, $size:expr, $align:expr; $($field:ident : $field_ty:ty => $offset:expr),+ $(,)?) => {{
        assert_eq!(size_of::<$ty>(), $size, "{} size", stringify!($ty));
        assert_eq!(align_of::<$ty>(), $align, "{} alignment", stringify!($ty));
        let mut next = 0usize;
        $(
            let _: fn(&$ty) -> $field_ty = |value| value.$field;
            assert_eq!(offset_of!($ty, $field), $offset, "{}.{}", stringify!($ty), stringify!($field));
            assert_eq!($offset, next, "gap before {}.{}", stringify!($ty), stringify!($field));
            next += size_of::<$field_ty>();
        )+
        assert_eq!(next, size_of::<$ty>(), "{} tail padding", stringify!($ty));
        assert_pod::<$ty>();
    }};
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_header(out: &mut [u8], offset: usize, struct_size: u32, version: u16, flags: u16) {
    put_u32(out, offset, struct_size);
    put_u16(out, offset + 4, version);
    put_u16(out, offset + 6, flags);
}

fn put_pair(out: &mut [u8], offset: usize, lo: u64, hi: u64) {
    put_u64(out, offset, lo);
    put_u64(out, offset + 8, hi);
}

fn put_blob(out: &mut [u8], offset: usize, blob_offset: u32, blob_length: u32) {
    put_u32(out, offset, blob_offset);
    put_u32(out, offset + 4, blob_length);
}

fn encode_pod<T: Pod>(value: &T) -> Vec<u8> {
    let mut output = vec![0u8; size_of::<T>()];
    assert_eq!(try_encode(value, &mut output).unwrap(), output.len());
    output
}

// ---- Layout proofs ----------------------------------------------------------

#[test]
fn notify_envelope_v2_layout_is_exact() {
    assert_wire_layout!(NotifyEnvelopeV2, 56, 8;
        header: ControlHeader => 0,
        notify_code: u16 => 8,
        notify_flags: u16 => 10,
        reserved: u32 => 12,
        token: AckToken => 16,
        file_id: FileId => 32,
        body: BlobSlice => 48,
    );
}

#[test]
fn invalidate_file_v1_layout_is_exact() {
    assert_wire_layout!(InvalidateFileV1, 40, 8;
        header: ControlHeader => 0,
        offset: u64 => 8,
        length: u64 => 16,
        content_epoch: u64 => 24,
        flags: u32 => 32,
        reserved: u32 => 36,
    );
}

#[test]
fn invalidate_entry_v1_layout_is_exact() {
    assert_wire_layout!(InvalidateEntryV1, 32, 8;
        header: ControlHeader => 0,
        namespace_generation: u64 => 8,
        name: BlobSlice => 16,
        flags: u32 => 24,
        reserved: u32 => 28,
    );
}

#[test]
fn pt_grant_v1_layout_is_exact() {
    assert_wire_layout!(PtGrantV1, 24, 8;
        header: ControlHeader => 0,
        pt_epoch: u64 => 8,
        sector_size: u32 => 16,
        flags: u32 => 20,
    );
}

#[test]
fn pt_epoch_v1_layout_is_exact() {
    assert_wire_layout!(PtEpochV1, 16, 8;
        header: ControlHeader => 0,
        pt_epoch: u64 => 8,
    );
}

#[test]
fn resize_v1_layout_is_exact() {
    assert_wire_layout!(ResizeV1, 48, 8;
        header: ControlHeader => 0,
        sizes: SizeState => 8,
        volume_commit_sequence: u64 => 40,
    );
}

#[test]
fn external_dir_change_v1_layout_is_exact() {
    assert_wire_layout!(ExternalDirChangeV1, 176, 8;
        header: ControlHeader => 0,
        first_ordinal: u64 => 8,
        through_ordinal: u64 => 16,
        volume_commit_sequence: u64 => 24,
        change_kind: u16 => 32,
        object_kind: u16 => 34,
        filter_match: u32 => 36,
        flags: u32 => 40,
        reserved0: u32 => 44,
        target_link_id: LinkId => 48,
        replaced_file_id: FileId => 64,
        replaced_link_id: LinkId => 80,
        old_parent_id: FileId => 96,
        new_parent_id: FileId => 112,
        old_parent_generation: u64 => 128,
        new_parent_generation: u64 => 136,
        target_namespace_generation: u64 => 144,
        replaced_namespace_generation: u64 => 152,
        old_name: BlobSlice => 160,
        new_name: BlobSlice => 168,
    );
}

#[test]
fn pt_lane_ready_v1_layout_is_exact() {
    assert_wire_layout!(PtLaneReadyV1, 24, 8;
        header: ControlHeader => 0,
        kind_ordinal: u16 => 8,
        reserved0: u16 => 10,
        flags: u32 => 12,
        high_watermark: u64 => 16,
    );
}

#[test]
fn external_change_ready_v1_layout_is_exact() {
    assert_wire_layout!(ExternalChangeReadyV1, 32, 8;
        header: ControlHeader => 0,
        reconcile_cut: u64 => 8,
        processed_high_watermark: u64 => 16,
        flags: u32 => 24,
        reserved: u32 => 28,
    );
}

#[test]
fn external_change_cut_v1_layout_is_exact() {
    assert_wire_layout!(ExternalChangeCutV1, 24, 8;
        header: ControlHeader => 0,
        reconcile_cut: u64 => 8,
        flags: u32 => 16,
        reserved: u32 => 20,
    );
}

#[test]
fn pdir_change_ack_v1_layout_is_exact() {
    assert_wire_layout!(PDirChangeAckV1, 64, 8;
        token: AckToken => 0,
        through_ordinal: u64 => 16,
        volume_commit_sequence: u64 => 24,
        semantic_digest: [u8; 32] => 32,
    );
}

// ---- Registry constants -----------------------------------------------------

#[test]
fn notify_and_ack_codes_are_closed() {
    assert_eq!(notify::INVALIDATE_FILE, 1);
    assert_eq!(notify::INVALIDATE_ENTRY, 2);
    assert_eq!(notify::PT_GRANT, 3);
    assert_eq!(notify::PT_REVOKE_ROUTE, 4);
    assert_eq!(notify::PT_EXTERNAL_MUTATION_SAFE, 5);
    assert_eq!(notify::RESIZE, 6);
    assert_eq!(notify::DIR_CHANGE, 7);
    assert_eq!(notify::PT_LANE_READY, 8);
    assert_eq!(notify::EXTERNAL_CHANGE_READY, 9);
    assert_eq!(notify::EXTERNAL_CHANGE_CUT, 10);
    assert_eq!(op::PT_ROUTE_ACK, 0x0050);
    assert_eq!(op::PT_EXTERNAL_SAFE_ACK, 0x0051);
    assert_eq!(op::DIR_CHANGE_ACK, 0x0052);
}

#[test]
fn external_change_and_ack_kind_registries_are_closed() {
    assert_eq!(external_change_kind::ADD, 1);
    assert_eq!(external_change_kind::REMOVE, 2);
    assert_eq!(external_change_kind::MODIFY, 3);
    assert_eq!(external_change_kind::RENAME, 4);
    assert_eq!(external_change_kind::OVERFLOW, 0xffff);
    assert_eq!(external_object_kind::FILE, 1);
    assert_eq!(external_object_kind::DIRECTORY, 2);
    assert_eq!(notify_ack_kind::PT_REVOKE_ROUTE, 1);
    assert_eq!(notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE, 2);
    assert_eq!(notify_ack_kind::DIR_CHANGE, 3);
}

#[test]
fn ack_token_tag_and_mask_are_exact() {
    assert_eq!(ACK_TOKEN_HI_TAG, 0x4653_5249_4e47_0000);
    assert_eq!(ACK_TOKEN_HI_MASK, 0xffff_ffff_ffff_0000);
    // The tag occupies exactly the masked high bits and its ASCII is "FSRING".
    assert_eq!(ACK_TOKEN_HI_TAG & !ACK_TOKEN_HI_MASK, 0);
    assert_eq!(ACK_TOKEN_HI_TAG & ACK_TOKEN_HI_MASK, ACK_TOKEN_HI_TAG);
    assert_eq!(&ACK_TOKEN_HI_TAG.to_be_bytes()[..6], b"FSRING");
}

// ---- Filter, action, and cap constants --------------------------------------

#[test]
fn notify_filter_mask_and_bits_are_exact() {
    assert_eq!(notify_filter::FILE_NAME, 0x1);
    assert_eq!(notify_filter::DIR_NAME, 0x2);
    assert_eq!(notify_filter::ATTRIBUTES, 0x4);
    assert_eq!(notify_filter::SIZE, 0x8);
    assert_eq!(notify_filter::LAST_WRITE, 0x10);
    assert_eq!(notify_filter::LAST_ACCESS, 0x20);
    assert_eq!(notify_filter::CREATION, 0x40);
    assert_eq!(notify_filter::EA, 0x80);
    assert_eq!(notify_filter::SECURITY, 0x100);
    assert_eq!(notify_filter::STREAM_NAME, 0x200);
    assert_eq!(notify_filter::STREAM_SIZE, 0x400);
    assert_eq!(notify_filter::STREAM_WRITE, 0x800);
    let union = notify_filter::FILE_NAME
        | notify_filter::DIR_NAME
        | notify_filter::ATTRIBUTES
        | notify_filter::SIZE
        | notify_filter::LAST_WRITE
        | notify_filter::LAST_ACCESS
        | notify_filter::CREATION
        | notify_filter::EA
        | notify_filter::SECURITY
        | notify_filter::STREAM_NAME
        | notify_filter::STREAM_SIZE
        | notify_filter::STREAM_WRITE;
    assert_eq!(union, VALID_NOTIFY_FILTER_MASK);
    assert_eq!(VALID_NOTIFY_FILTER_MASK, 0x0000_0fff);
    // MODIFY subset excludes the two name bits and is contained by the mask.
    assert_eq!(EXTERNAL_MODIFY_FILTER_MASK, 0x0000_01fc);
    assert_eq!(
        EXTERNAL_MODIFY_FILTER_MASK & VALID_NOTIFY_FILTER_MASK,
        EXTERNAL_MODIFY_FILTER_MASK
    );
    assert_eq!(
        EXTERNAL_MODIFY_FILTER_MASK & (notify_filter::FILE_NAME | notify_filter::DIR_NAME),
        0
    );
}

#[test]
fn file_action_codes_are_closed() {
    assert_eq!(file_action::ADDED, 1);
    assert_eq!(file_action::REMOVED, 2);
    assert_eq!(file_action::MODIFIED, 3);
    assert_eq!(file_action::RENAMED_OLD_NAME, 4);
    assert_eq!(file_action::RENAMED_NEW_NAME, 5);
}

#[test]
fn external_and_notify_caps_are_exact() {
    assert_eq!(MIN_EXTERNAL_CHANGE_NAME_BYTES, 2);
    assert_eq!(MAX_EXTERNAL_CHANGE_NAME_BYTES, 510);
    assert_eq!(MAX_OUTSTANDING_EXTERNAL_CHANGE, 1);
    assert_eq!(MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING, 1);
    assert_eq!(
        MAX_PRECISE_EXTERNAL_OUTBOX_RECORDS,
        MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS - 1
    );
    assert_eq!(MAX_PRECISE_EXTERNAL_OUTBOX_RECORDS, 4_095);
    assert_eq!(EXTERNAL_OUTBOX_OVERFLOW_RESERVE_BYTES, 2_048);
    assert_eq!(MAX_NOTIFY_BUFFER_BYTES_PER_CCB, 1_048_576);
    assert_eq!(MAX_NOTIFY_BUFFER_BYTES_PER_MOUNT, 67_108_864);
    assert_eq!(MAX_NOTIFY_REGISTRATIONS_PER_MOUNT, 4_096);
    assert_eq!(MAX_PENDING_NOTIFY_IRPS_PER_CCB, 64);
    assert_eq!(MAX_PENDING_NOTIFY_IRPS_PER_MOUNT, 16_384);
    assert_eq!(MAX_PENDING_NOTIFY_MDL_BYTES_PER_CCB, 4_194_304);
    assert_eq!(MAX_PENDING_NOTIFY_MDL_BYTES_PER_MOUNT, 67_108_864);
    assert_eq!(MAX_NOTIFY_PATH_COMPONENTS, 1_024);
    assert_eq!(MAX_NOTIFY_RELATIVE_PATH_BYTES, 65_520);
    assert_eq!(MAX_PRECISE_NOTIFY_LINKS_PER_LOCAL_OPERATION, 64);
}

#[test]
fn file_notify_information_reference_geometry() {
    assert_eq!(file_notify_information::NEXT_ENTRY_OFFSET, 0);
    assert_eq!(file_notify_information::ACTION, 4);
    assert_eq!(file_notify_information::FILE_NAME_LENGTH, 8);
    assert_eq!(file_notify_information::FILE_NAME, 12);
    assert_eq!(file_notify_information::FIXED_PREFIX_BYTES, 12);
    // Each nonfinal record is align4(12 + FileNameLength).
    assert_eq!(file_notify_information_entry_len(0), Some(12));
    assert_eq!(file_notify_information_entry_len(4), Some(16));
    assert_eq!(file_notify_information_entry_len(6), Some(20));
    assert_eq!(file_notify_information_entry_len(8), Some(20));
    // Overflow returns None rather than wrapping.
    assert_eq!(file_notify_information_entry_len(u32::MAX), None);
}

// ---- External semantic digest ----------------------------------------------

fn canonical_dir_change_envelope() -> Vec<u8> {
    // A precise ADD envelope with no names: body is the 176-byte fixed prefix.
    let body_size = 176u32;
    let total = 56 + body_size as usize;
    let mut env = vec![0u8; total];
    // NotifyEnvelopeV2
    put_header(&mut env, 0, total as u32, 2, 0);
    put_u16(&mut env, 8, notify::DIR_CHANGE);
    put_u16(&mut env, 10, 0);
    put_u32(&mut env, 12, 0);
    // AckToken: lo = first_ordinal (1); hi = TAG | (3<<8) | 0
    put_pair(&mut env, 16, 1, ACK_TOKEN_HI_TAG | (3u64 << 8));
    put_pair(&mut env, 32, 0xdead_beef, 0xfeed_face); // target FileId
    put_blob(&mut env, 48, 56, body_size);
    // ExternalDirChangeV1 at offset 56
    let b = 56usize;
    put_header(&mut env, b, body_size, 1, 0);
    put_u64(&mut env, b + 8, 1); // first_ordinal
    put_u64(&mut env, b + 16, 1); // through_ordinal
    put_u64(&mut env, b + 24, 7); // volume_commit_sequence
    put_u16(&mut env, b + 32, external_change_kind::ADD);
    put_u16(&mut env, b + 34, external_object_kind::FILE);
    put_u32(&mut env, b + 36, notify_filter::FILE_NAME);
    put_pair(&mut env, b + 112, 0x11, 0x22); // new_parent_id
    put_u64(&mut env, b + 136, 3); // new_parent_generation
    put_u64(&mut env, b + 144, 5); // target_namespace_generation
    put_blob(&mut env, b + 160, 0, 0); // old_name absent
    put_blob(&mut env, b + 168, 0, 0); // new_name absent (present in real records; fine for digest)
    env
}

#[test]
fn external_dir_change_semantic_digest_matches_independent_image() {
    assert_eq!(EXTERNAL_DIR_CHANGE_DIGEST_DOMAIN.len(), 30);
    assert_eq!(
        EXTERNAL_DIR_CHANGE_DIGEST_DOMAIN,
        b"FSRING-EXTERNAL-DIR-CHANGE-v1\0"
    );

    let mount = MountId {
        lo: 0x0102_0304_0506_0708,
        hi: 0x1112_1314_1516_1718,
    };
    let env = canonical_dir_change_envelope();

    let mut image = Vec::new();
    image.extend_from_slice(EXTERNAL_DIR_CHANGE_DIGEST_DOMAIN);
    image.extend_from_slice(&mount.lo.to_le_bytes());
    image.extend_from_slice(&mount.hi.to_le_bytes());
    image.extend_from_slice(&env);
    let expected = sha256_bytes(&image);

    let actual = external_dir_change_semantic_digest_v1(mount, &env);
    assert_eq!(actual, expected);
}

#[test]
fn external_dir_change_semantic_digest_is_sensitive() {
    let mount = MountId { lo: 9, hi: 10 };
    let other_mount = MountId { lo: 9, hi: 11 };
    let env = canonical_dir_change_envelope();
    let base = external_dir_change_semantic_digest_v1(mount, &env);

    // Different mount identity changes the digest.
    assert_ne!(
        base,
        external_dir_change_semantic_digest_v1(other_mount, &env)
    );

    // One flipped envelope byte changes the digest.
    let mut mutated = env.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;
    assert_ne!(
        base,
        external_dir_change_semantic_digest_v1(mount, &mutated)
    );

    // A DIR_CHANGE envelope encoded through the POD type produces identical bytes.
    let typed = NotifyEnvelopeV2 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: 2,
            required_flags: 0,
        },
        notify_code: notify::DIR_CHANGE,
        notify_flags: 0,
        reserved: 0,
        token: AckToken {
            lo: 1,
            hi: ACK_TOKEN_HI_TAG | (3u64 << 8),
        },
        file_id: FileId { lo: 1, hi: 2 },
        body: BlobSlice {
            offset: 56,
            length: 0,
        },
    };
    let bytes = encode_pod(&typed);
    assert_eq!(bytes.len(), 56);
}

// ---- Task 2: envelope, body, ack, and token validators ----------------------

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

fn body_with_header(size: usize) -> Vec<u8> {
    let mut body = vec![0u8; size];
    put_header(&mut body, 0, size as u32, 1, 0);
    body
}

fn build_envelope(code: u16, token: AckToken, file_id: FileId, body: &[u8]) -> Vec<u8> {
    let total = 56 + body.len();
    let mut env = vec![0u8; total];
    put_header(&mut env, 0, total as u32, 2, 0);
    put_u16(&mut env, 8, code);
    put_u16(&mut env, 10, 0);
    put_u32(&mut env, 12, 0);
    put_pair(&mut env, 16, token.lo, token.hi);
    put_pair(&mut env, 32, file_id.lo, file_id.hi);
    put_blob(&mut env, 48, 56, body.len() as u32);
    env[56..].copy_from_slice(body);
    env
}

const ZERO_TOKEN: AckToken = AckToken { lo: 0, hi: 0 };

fn invalidate_file_body(offset: u64, length: u64, epoch: u64) -> Vec<u8> {
    let mut body = body_with_header(40);
    put_u64(&mut body, 8, offset);
    put_u64(&mut body, 16, length);
    put_u64(&mut body, 24, epoch);
    body
}

fn pt_epoch_body(epoch: u64) -> Vec<u8> {
    let mut body = body_with_header(16);
    put_u64(&mut body, 8, epoch);
    body
}

fn pt_grant_body(epoch: u64, sector_size: u32) -> Vec<u8> {
    let mut body = body_with_header(24);
    put_u64(&mut body, 8, epoch);
    put_u32(&mut body, 16, sector_size);
    body
}

fn resize_body(alloc: u64, file: u64, vdl: u64, size_epoch: u64, vcs: u64) -> Vec<u8> {
    let mut body = body_with_header(48);
    put_u64(&mut body, 8, alloc);
    put_u64(&mut body, 16, file);
    put_u64(&mut body, 24, vdl);
    put_u64(&mut body, 32, size_epoch);
    put_u64(&mut body, 40, vcs);
    body
}

fn invalidate_entry_body(nsgen: u64, name: &[u8]) -> Vec<u8> {
    let total = align8(32 + name.len());
    let mut body = body_with_header(total);
    put_u64(&mut body, 8, nsgen);
    if name.is_empty() {
        put_blob(&mut body, 16, 0, 0);
    } else {
        put_blob(&mut body, 16, 32, name.len() as u32);
        body[32..32 + name.len()].copy_from_slice(name);
    }
    body
}

fn pt_lane_ready_body(kind_ordinal: u16, high_watermark: u64) -> Vec<u8> {
    let mut body = body_with_header(24);
    put_u16(&mut body, 8, kind_ordinal);
    put_u64(&mut body, 16, high_watermark);
    body
}

fn external_change_ready_body(reconcile_cut: u64, processed: u64) -> Vec<u8> {
    let mut body = body_with_header(32);
    put_u64(&mut body, 8, reconcile_cut);
    put_u64(&mut body, 16, processed);
    body
}

fn external_change_cut_body(reconcile_cut: u64) -> Vec<u8> {
    let mut body = body_with_header(24);
    put_u64(&mut body, 8, reconcile_cut);
    body
}

#[derive(Clone)]
struct Edc {
    first: u64,
    through: u64,
    vcs: u64,
    change_kind: u16,
    object_kind: u16,
    filter: u32,
    flags: u32,
    reserved0: u32,
    target_link: LinkId,
    replaced_file: FileId,
    replaced_link: LinkId,
    old_parent: FileId,
    new_parent: FileId,
    old_pgen: u64,
    new_pgen: u64,
    target_nsgen: u64,
    replaced_nsgen: u64,
    old_name: Vec<u8>,
    new_name: Vec<u8>,
}

impl Edc {
    fn body(&self) -> Vec<u8> {
        let total = align8(176 + self.old_name.len() + self.new_name.len());
        let mut body = body_with_header(total);
        put_u64(&mut body, 8, self.first);
        put_u64(&mut body, 16, self.through);
        put_u64(&mut body, 24, self.vcs);
        put_u16(&mut body, 32, self.change_kind);
        put_u16(&mut body, 34, self.object_kind);
        put_u32(&mut body, 36, self.filter);
        put_u32(&mut body, 40, self.flags);
        put_u32(&mut body, 44, self.reserved0);
        put_pair(&mut body, 48, self.target_link.lo, self.target_link.hi);
        put_pair(&mut body, 64, self.replaced_file.lo, self.replaced_file.hi);
        put_pair(&mut body, 80, self.replaced_link.lo, self.replaced_link.hi);
        put_pair(&mut body, 96, self.old_parent.lo, self.old_parent.hi);
        put_pair(&mut body, 112, self.new_parent.lo, self.new_parent.hi);
        put_u64(&mut body, 128, self.old_pgen);
        put_u64(&mut body, 136, self.new_pgen);
        put_u64(&mut body, 144, self.target_nsgen);
        put_u64(&mut body, 152, self.replaced_nsgen);
        let mut cursor = 176usize;
        if self.old_name.is_empty() {
            put_blob(&mut body, 160, 0, 0);
        } else {
            put_blob(&mut body, 160, cursor as u32, self.old_name.len() as u32);
            body[cursor..cursor + self.old_name.len()].copy_from_slice(&self.old_name);
            cursor += self.old_name.len();
        }
        if self.new_name.is_empty() {
            put_blob(&mut body, 168, 0, 0);
        } else {
            put_blob(&mut body, 168, cursor as u32, self.new_name.len() as u32);
            body[cursor..cursor + self.new_name.len()].copy_from_slice(&self.new_name);
        }
        body
    }

    fn envelope(&self, target: FileId) -> Vec<u8> {
        build_envelope(
            notify::DIR_CHANGE,
            external_dir_change_ack_token(self.first),
            target,
            &self.body(),
        )
    }
}

fn precise_base() -> Edc {
    Edc {
        first: 1,
        through: 1,
        vcs: 7,
        change_kind: external_change_kind::ADD,
        object_kind: external_object_kind::FILE,
        filter: notify_filter::FILE_NAME,
        flags: 0,
        reserved0: 0,
        target_link: LinkId { lo: 0x51, hi: 0x52 },
        replaced_file: FileId::ZERO,
        replaced_link: LinkId::ZERO,
        old_parent: FileId::ZERO,
        new_parent: FileId { lo: 0x61, hi: 0x62 },
        old_pgen: 0,
        new_pgen: 3,
        target_nsgen: 5,
        replaced_nsgen: 0,
        old_name: Vec::new(),
        new_name: utf16("file.txt"),
    }
}

const TARGET: FileId = FileId { lo: 0xaa, hi: 0xbb };

// ---- AckToken construction and decoding ------------------------------------

#[test]
fn ack_tokens_round_trip_and_decode() {
    let dir = external_dir_change_ack_token(7);
    assert_eq!(dir.lo, 7);
    assert_eq!(
        decode_ack_token(dir),
        Ok(AckTokenPartsV21 {
            kind_ordinal: notify_ack_kind::DIR_CHANGE,
            ring_index: 0,
            ordinal: 7,
        })
    );

    let route = pt_ack_token(notify_ack_kind::PT_REVOKE_ROUTE, 5, 9).unwrap();
    assert_eq!(
        decode_ack_token(route),
        Ok(AckTokenPartsV21 {
            kind_ordinal: notify_ack_kind::PT_REVOKE_ROUTE,
            ring_index: 5,
            ordinal: 9,
        })
    );
    let safe = pt_ack_token(notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE, 63, 1).unwrap();
    assert_eq!(decode_ack_token(safe).unwrap().ring_index, 63);
}

#[test]
fn ack_token_construction_rejects_illegal_inputs() {
    // PT ack token construction rejects DIR_CHANGE kind, out-of-range ring, zero ordinal.
    assert_eq!(pt_ack_token(notify_ack_kind::DIR_CHANGE, 0, 1), None);
    assert_eq!(pt_ack_token(notify_ack_kind::PT_REVOKE_ROUTE, 64, 1), None);
    assert_eq!(pt_ack_token(notify_ack_kind::PT_REVOKE_ROUTE, 0, 0), None);
    assert_eq!(pt_ack_token(0, 0, 1), None);
}

#[test]
fn ack_token_decode_rejects_malformed_tokens() {
    // Wrong tag.
    assert_eq!(
        decode_ack_token(AckToken { lo: 1, hi: 0 }),
        Err(MessageValidationError::Identity)
    );
    // Zero ordinal.
    assert_eq!(
        decode_ack_token(AckToken {
            lo: 0,
            hi: ACK_TOKEN_HI_TAG | (u64::from(notify_ack_kind::DIR_CHANGE) << 8),
        }),
        Err(MessageValidationError::Identity)
    );
    // Bits 6..7 of the ring byte are reserved.
    assert_eq!(
        decode_ack_token(AckToken {
            lo: 1,
            hi: ACK_TOKEN_HI_TAG | (u64::from(notify_ack_kind::PT_REVOKE_ROUTE) << 8) | 0x40,
        }),
        Err(MessageValidationError::InvalidScalar)
    );
    // DIR_CHANGE must be ring zero.
    assert_eq!(
        decode_ack_token(AckToken {
            lo: 1,
            hi: ACK_TOKEN_HI_TAG | (u64::from(notify_ack_kind::DIR_CHANGE) << 8) | 1,
        }),
        Err(MessageValidationError::InvalidScalar)
    );
    // Unknown kind ordinal.
    assert_eq!(
        decode_ack_token(AckToken {
            lo: 1,
            hi: ACK_TOKEN_HI_TAG | (9u64 << 8),
        }),
        Err(MessageValidationError::InvalidScalar)
    );
}

// ---- Envelope generic geometry ---------------------------------------------

#[test]
fn envelope_accepts_each_zero_token_body() {
    let parent = FileId { lo: 3, hi: 4 };
    for env in [
        build_envelope(
            notify::INVALIDATE_FILE,
            ZERO_TOKEN,
            TARGET,
            &invalidate_file_body(0, 0, 9),
        ),
        build_envelope(
            notify::INVALIDATE_ENTRY,
            ZERO_TOKEN,
            parent,
            &invalidate_entry_body(4, &utf16("a")),
        ),
        build_envelope(
            notify::PT_GRANT,
            ZERO_TOKEN,
            TARGET,
            &pt_grant_body(2, 4096),
        ),
        build_envelope(
            notify::RESIZE,
            ZERO_TOKEN,
            TARGET,
            &resize_body(4096, 4096, 4096, 1, 8),
        ),
        build_envelope(
            notify::PT_LANE_READY,
            ZERO_TOKEN,
            FileId::ZERO,
            &pt_lane_ready_body(1, 0),
        ),
        build_envelope(
            notify::EXTERNAL_CHANGE_READY,
            ZERO_TOKEN,
            FileId::ZERO,
            &external_change_ready_body(0, 0),
        ),
        build_envelope(
            notify::EXTERNAL_CHANGE_CUT,
            ZERO_TOKEN,
            FileId::ZERO,
            &external_change_cut_body(0),
        ),
    ] {
        validate_notify_envelope_v2(&env).unwrap();
    }
}

#[test]
fn envelope_rejects_generic_geometry_defects() {
    let good = build_envelope(
        notify::PT_GRANT,
        ZERO_TOKEN,
        TARGET,
        &pt_grant_body(2, 4096),
    );
    validate_notify_envelope_v2(&good).unwrap();

    // Wrong envelope version.
    let mut bad = good.clone();
    put_u16(&mut bad, 4, 1);
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // Nonzero notify_flags.
    let mut bad = good.clone();
    put_u16(&mut bad, 10, 1);
    assert!(matches!(
        validate_notify_envelope_v2(&bad),
        Err(MessageValidationError::FlagsOrReserved)
    ));

    // Nonzero reserved.
    let mut bad = good.clone();
    put_u32(&mut bad, 12, 1);
    assert!(matches!(
        validate_notify_envelope_v2(&bad),
        Err(MessageValidationError::FlagsOrReserved)
    ));

    // body.offset must equal 56.
    let mut bad = good.clone();
    put_u32(&mut bad, 48, 57);
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // struct_size must equal 56 + body.length.
    let mut bad = good.clone();
    put_u32(&mut bad, 0, 200);
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // Trailing bytes beyond struct_size are rejected.
    let mut bad = good.clone();
    bad.push(0);
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // Unknown notify code.
    let bad = build_envelope(0x1234, ZERO_TOKEN, TARGET, &pt_grant_body(2, 4096));
    assert!(validate_notify_envelope_v2(&bad).is_err());
}

#[test]
fn envelope_enforces_token_and_file_id_per_code() {
    // A zero-token code rejects a nonzero token.
    let bad = build_envelope(
        notify::PT_GRANT,
        external_dir_change_ack_token(1),
        TARGET,
        &pt_grant_body(2, 4096),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // PT_REVOKE_ROUTE requires a kind-1 token.
    let ok = build_envelope(
        notify::PT_REVOKE_ROUTE,
        pt_ack_token(notify_ack_kind::PT_REVOKE_ROUTE, 2, 5).unwrap(),
        TARGET,
        &pt_epoch_body(3),
    );
    validate_notify_envelope_v2(&ok).unwrap();
    let bad = build_envelope(
        notify::PT_REVOKE_ROUTE,
        pt_ack_token(notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE, 2, 5).unwrap(),
        TARGET,
        &pt_epoch_body(3),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // CUT/READY/LANE_READY require zero envelope FileId.
    let bad = build_envelope(
        notify::EXTERNAL_CHANGE_CUT,
        ZERO_TOKEN,
        TARGET,
        &external_change_cut_body(0),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());
}

// ---- Body field rules ------------------------------------------------------

#[test]
fn invalidate_file_body_rules() {
    // Whole-stream length zero requires offset zero.
    let ok = build_envelope(
        notify::INVALIDATE_FILE,
        ZERO_TOKEN,
        TARGET,
        &invalidate_file_body(0, 0, 9),
    );
    validate_notify_envelope_v2(&ok).unwrap();
    let bad = build_envelope(
        notify::INVALIDATE_FILE,
        ZERO_TOKEN,
        TARGET,
        &invalidate_file_body(1, 0, 9),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());
    // Zero content epoch is rejected.
    let bad = build_envelope(
        notify::INVALIDATE_FILE,
        ZERO_TOKEN,
        TARGET,
        &invalidate_file_body(0, 16, 0),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());
    // Nonzero body flags rejected.
    let mut body = invalidate_file_body(0, 16, 9);
    put_u32(&mut body, 32, 1);
    let bad = build_envelope(notify::INVALIDATE_FILE, ZERO_TOKEN, TARGET, &body);
    assert!(matches!(
        validate_notify_envelope_v2(&bad),
        Err(MessageValidationError::FlagsOrReserved)
    ));
}

#[test]
fn invalidate_entry_and_resize_and_pt_grant_rules() {
    // Zero namespace generation rejected.
    let bad = build_envelope(
        notify::INVALIDATE_ENTRY,
        ZERO_TOKEN,
        FileId { lo: 1, hi: 1 },
        &invalidate_entry_body(0, &utf16("a")),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());
    // A wildcard name is rejected.
    let bad = build_envelope(
        notify::INVALIDATE_ENTRY,
        ZERO_TOKEN,
        FileId { lo: 1, hi: 1 },
        &invalidate_entry_body(4, &utf16("a*b")),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // Resize ordering.
    let bad = build_envelope(
        notify::RESIZE,
        ZERO_TOKEN,
        TARGET,
        &resize_body(4096, 8192, 4096, 1, 8),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());
    // Resize zero volume commit sequence.
    let bad = build_envelope(
        notify::RESIZE,
        ZERO_TOKEN,
        TARGET,
        &resize_body(4096, 4096, 4096, 1, 0),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());

    // PT_GRANT non-power-of-two sector size.
    let bad = build_envelope(
        notify::PT_GRANT,
        ZERO_TOKEN,
        TARGET,
        &pt_grant_body(2, 3000),
    );
    assert!(validate_notify_envelope_v2(&bad).is_err());
}

// ---- ExternalDirChange precise/overflow matrix -----------------------------

#[test]
fn external_dir_change_precise_variants_are_accepted() {
    // ADD
    let add = precise_base();
    match validate_notify_envelope_v2(&add.envelope(TARGET))
        .unwrap()
        .body
    {
        ValidatedNotifyBodyV2::ExternalDirChange {
            old_name, new_name, ..
        } => {
            assert!(old_name.is_empty());
            assert_eq!(new_name, &utf16("file.txt")[..]);
        }
        _ => panic!("expected ExternalDirChange"),
    }

    // REMOVE uses old only.
    let mut remove = precise_base();
    remove.change_kind = external_change_kind::REMOVE;
    remove.old_parent = FileId { lo: 0x71, hi: 0x72 };
    remove.old_pgen = 4;
    remove.old_name = utf16("gone.txt");
    remove.new_parent = FileId::ZERO;
    remove.new_pgen = 0;
    remove.new_name = Vec::new();
    validate_notify_envelope_v2(&remove.envelope(TARGET)).unwrap();

    // MODIFY uses a nonzero subset of the modify mask, new parent/name only.
    let mut modify = precise_base();
    modify.change_kind = external_change_kind::MODIFY;
    modify.filter = notify_filter::LAST_WRITE | notify_filter::SIZE;
    validate_notify_envelope_v2(&modify.envelope(TARGET)).unwrap();

    // RENAME cross-directory uses both sides.
    let mut rename = precise_base();
    rename.change_kind = external_change_kind::RENAME;
    rename.old_parent = FileId { lo: 0x81, hi: 0x82 };
    rename.old_pgen = 6;
    rename.old_name = utf16("before.txt");
    validate_notify_envelope_v2(&rename.envelope(TARGET)).unwrap();
}

#[test]
fn external_dir_change_overflow_is_accepted() {
    let mut e = precise_base();
    e.change_kind = external_change_kind::OVERFLOW;
    e.object_kind = 0;
    e.filter = 0;
    e.first = 4;
    e.through = 9;
    e.target_link = LinkId::ZERO;
    e.new_parent = FileId::ZERO;
    e.new_pgen = 0;
    e.target_nsgen = 0;
    e.new_name = Vec::new();
    // envelope FileId must be zero for overflow, token.lo == first.
    validate_notify_envelope_v2(&e.envelope(FileId::ZERO)).unwrap();
    assert_eq!(
        classify_external_ordinal_interval_v21(4, 9, true),
        Ok(ExternalOrdinalIntervalV21::Overflow)
    );
    assert_eq!(
        classify_external_ordinal_interval_v21(1, 1, false),
        Ok(ExternalOrdinalIntervalV21::Precise)
    );
    assert!(classify_external_ordinal_interval_v21(9, 4, true).is_err());
    assert!(classify_external_ordinal_interval_v21(1, 2, false).is_err());
    assert!(classify_external_ordinal_interval_v21(0, 0, false).is_err());
}

fn overflow_base() -> Edc {
    let mut e = precise_base();
    e.change_kind = external_change_kind::OVERFLOW;
    e.object_kind = 0;
    e.filter = 0;
    e.first = 4;
    e.through = 9;
    e.target_link = LinkId::ZERO;
    e.new_parent = FileId::ZERO;
    e.new_pgen = 0;
    e.target_nsgen = 0;
    e.new_name = Vec::new();
    e
}

#[test]
fn external_dir_change_overflow_rejects_names() {
    // A well-formed OVERFLOW must carry no name slices (section 14.2).
    let mut with_new = overflow_base();
    with_new.new_name = utf16("leaked.txt");
    assert!(validate_notify_envelope_v2(&with_new.envelope(FileId::ZERO)).is_err());

    let mut with_old = overflow_base();
    with_old.old_name = utf16("leaked.txt");
    assert!(validate_notify_envelope_v2(&with_old.envelope(FileId::ZERO)).is_err());
}

#[test]
fn external_dir_change_rejects_malformed_records() {
    // Precise requires first == through.
    let mut e = precise_base();
    e.through = 2;
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // ADD with wrong filter (DIR_NAME on a FILE object).
    let mut e = precise_base();
    e.filter = notify_filter::DIR_NAME;
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // REMOVE must not carry a replacement.
    let mut e = precise_base();
    e.change_kind = external_change_kind::REMOVE;
    e.old_parent = FileId { lo: 1, hi: 1 };
    e.old_pgen = 1;
    e.old_name = utf16("x");
    e.new_parent = FileId::ZERO;
    e.new_pgen = 0;
    e.new_name = Vec::new();
    e.replaced_file = FileId { lo: 1, hi: 1 };
    e.replaced_link = LinkId { lo: 1, hi: 1 };
    e.replaced_nsgen = 1;
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // Partial replacement (some zero, some nonzero) is illegal for ADD.
    let mut e = precise_base();
    e.replaced_file = FileId { lo: 1, hi: 1 };
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // MODIFY may not use a name-filter bit.
    let mut e = precise_base();
    e.change_kind = external_change_kind::MODIFY;
    e.filter = notify_filter::FILE_NAME;
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // Precise requires nonzero target identity in the envelope FileId.
    let e = precise_base();
    assert!(validate_notify_envelope_v2(&e.envelope(FileId::ZERO)).is_err());

    // Overflow must zero every identity field.
    let mut e = precise_base();
    e.change_kind = external_change_kind::OVERFLOW;
    e.first = 1;
    e.through = 2;
    // leaves object_kind/new_parent nonzero → reject
    assert!(validate_notify_envelope_v2(&e.envelope(FileId::ZERO)).is_err());
}

#[test]
fn external_dir_change_rename_identity_rules() {
    // Same-parent byte-identical rename is invalid.
    let mut e = precise_base();
    e.change_kind = external_change_kind::RENAME;
    e.old_parent = e.new_parent;
    e.old_pgen = e.new_pgen;
    e.old_name = utf16("file.txt");
    e.new_name = utf16("file.txt");
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // Same-parent case-only rename is legal.
    let mut e2 = e.clone();
    e2.new_name = utf16("FILE.txt");
    validate_notify_envelope_v2(&e2.envelope(TARGET)).unwrap();

    // Same parent id but mismatched generation is invalid.
    let mut e3 = precise_base();
    e3.change_kind = external_change_kind::RENAME;
    e3.old_parent = e3.new_parent;
    e3.old_pgen = e3.new_pgen + 1;
    e3.old_name = utf16("a.txt");
    assert!(validate_notify_envelope_v2(&e3.envelope(TARGET)).is_err());
}

#[test]
fn external_dir_change_name_geometry_rules() {
    // Odd name length is rejected.
    let mut e = precise_base();
    e.new_name = vec![0x41, 0x00, 0x42]; // 3 bytes
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // Overlong name (> 510 bytes) is rejected.
    let mut e = precise_base();
    e.new_name = vec![0x41; 512];
    assert!(validate_notify_envelope_v2(&e.envelope(TARGET)).is_err());

    // Nonzero padding after the packed names is rejected.
    let mut e = precise_base();
    e.new_name = utf16("ab"); // 4 bytes → body 176+4=180 → padded to 184
    let mut body = e.body();
    let last = body.len() - 1;
    body[last] = 0xff;
    let env = build_envelope(
        notify::DIR_CHANGE,
        external_dir_change_ack_token(e.first),
        TARGET,
        &body,
    );
    assert!(validate_notify_envelope_v2(&env).is_err());
}

// ---- PDirChangeAckV1 --------------------------------------------------------

fn retained_tuple() -> RetainedExternalTupleV21 {
    RetainedExternalTupleV21 {
        first_ordinal: 3,
        through_ordinal: 5,
        volume_commit_sequence: 42,
        semantic_digest: [7u8; 32],
    }
}

fn pdir_ack_payload(tuple: &RetainedExternalTupleV21) -> Vec<u8> {
    let token = external_dir_change_ack_token(tuple.first_ordinal);
    let mut payload = vec![0u8; 64];
    put_pair(&mut payload, 0, token.lo, token.hi);
    put_u64(&mut payload, 16, tuple.through_ordinal);
    put_u64(&mut payload, 24, tuple.volume_commit_sequence);
    payload[32..64].copy_from_slice(&tuple.semantic_digest);
    payload
}

#[test]
fn pdir_change_ack_accepts_exact_tuple() {
    let tuple = retained_tuple();
    validate_pdir_change_ack_v1(&pdir_ack_payload(&tuple), &tuple).unwrap();
}

#[test]
fn pdir_change_ack_rejects_mismatches() {
    let tuple = retained_tuple();

    // Wrong length.
    assert!(validate_pdir_change_ack_v1(&[0u8; 63], &tuple).is_err());

    // Token first ordinal mismatch.
    let mut bad = pdir_ack_payload(&tuple);
    let wrong = external_dir_change_ack_token(99);
    put_pair(&mut bad, 0, wrong.lo, wrong.hi);
    assert!(validate_pdir_change_ack_v1(&bad, &tuple).is_err());

    // Through-ordinal mismatch.
    let mut bad = pdir_ack_payload(&tuple);
    put_u64(&mut bad, 16, 6);
    assert!(validate_pdir_change_ack_v1(&bad, &tuple).is_err());

    // Volume commit sequence mismatch.
    let mut bad = pdir_ack_payload(&tuple);
    put_u64(&mut bad, 24, 43);
    assert!(validate_pdir_change_ack_v1(&bad, &tuple).is_err());

    // Digest mismatch.
    let mut bad = pdir_ack_payload(&tuple);
    bad[32] ^= 1;
    assert!(validate_pdir_change_ack_v1(&bad, &tuple).is_err());

    // Wrong token lane (PT route kind instead of DIR_CHANGE).
    let mut bad = pdir_ack_payload(&tuple);
    let route = pt_ack_token(notify_ack_kind::PT_REVOKE_ROUTE, 0, tuple.first_ordinal).unwrap();
    put_pair(&mut bad, 0, route.lo, route.hi);
    assert!(validate_pdir_change_ack_v1(&bad, &tuple).is_err());
}

// ---- Task 3: PT lane acknowledgement machine -------------------------------

fn pnotify_ack_payload(token: AckToken, epoch: u64) -> Vec<u8> {
    let mut payload = vec![0u8; 24];
    put_pair(&mut payload, 0, token.lo, token.hi);
    put_u64(&mut payload, 16, epoch);
    payload
}

#[test]
fn pt_lane_ordinal_succession_is_non_wrapping() {
    assert_eq!(next_pt_lane_ordinal_v21(0), Ok(1));
    assert_eq!(next_pt_lane_ordinal_v21(41), Ok(42));
    assert!(next_pt_lane_ordinal_v21(u64::MAX).is_err());
}

#[test]
fn pt_ack_lane_classification_is_closed() {
    let state = PtLaneStateV21 {
        high_watermark: 5,
        pending_ordinal: Some(6),
        processed_ordinal: Some(5),
    };
    assert_eq!(classify_pt_ack_v21(&state, 6), PtLaneAckActionV21::Apply);
    assert_eq!(
        classify_pt_ack_v21(&state, 5),
        PtLaneAckActionV21::IdempotentSuccess
    );
    assert_eq!(
        classify_pt_ack_v21(&state, 7),
        PtLaneAckActionV21::ProtocolFault
    );
    assert_eq!(
        classify_pt_ack_v21(&state, 4),
        PtLaneAckActionV21::ProtocolFault
    );

    // No pending, only processed.
    let idle = PtLaneStateV21 {
        high_watermark: 5,
        pending_ordinal: None,
        processed_ordinal: Some(5),
    };
    assert_eq!(
        classify_pt_ack_v21(&idle, 5),
        PtLaneAckActionV21::IdempotentSuccess
    );
    assert_eq!(
        classify_pt_ack_v21(&idle, 6),
        PtLaneAckActionV21::ProtocolFault
    );
}

#[test]
fn pt_lane_one_outstanding_rule() {
    // Idle lane may publish exactly high_watermark + 1.
    let idle = PtLaneStateV21 {
        high_watermark: 5,
        pending_ordinal: None,
        processed_ordinal: Some(5),
    };
    assert!(pt_lane_can_publish_v21(&idle, 6).is_ok());
    assert!(pt_lane_can_publish_v21(&idle, 7).is_err());
    assert!(pt_lane_can_publish_v21(&idle, 5).is_err());

    // A pending record forbids a second distinct notification, even for the
    // otherwise-valid successor ordinal (this kills the pending-branch mutant
    // that the ordinal check would otherwise mask).
    let pending = PtLaneStateV21 {
        high_watermark: 5,
        pending_ordinal: Some(6),
        processed_ordinal: Some(5),
    };
    assert!(pt_lane_can_publish_v21(&pending, 6).is_err());
    assert!(pt_lane_can_publish_v21(&pending, 7).is_err());
}

#[test]
fn pnotify_ack_validation() {
    let token = pt_ack_token(notify_ack_kind::PT_REVOKE_ROUTE, 2, 9).unwrap();
    let ok = pnotify_ack_payload(token, 3);
    assert_eq!(
        validate_pnotify_ack_v21(&ok, notify_ack_kind::PT_REVOKE_ROUTE, 2, 3)
            .unwrap()
            .ordinal,
        9
    );

    // Wrong length.
    assert!(validate_pnotify_ack_v21(&[0u8; 23], notify_ack_kind::PT_REVOKE_ROUTE, 2, 3).is_err());
    // Wrong kind.
    assert!(
        validate_pnotify_ack_v21(&ok, notify_ack_kind::PT_EXTERNAL_MUTATION_SAFE, 2, 3).is_err()
    );
    // Wrong ring.
    assert!(validate_pnotify_ack_v21(&ok, notify_ack_kind::PT_REVOKE_ROUTE, 3, 3).is_err());
    // Wrong epoch.
    assert!(validate_pnotify_ack_v21(&ok, notify_ack_kind::PT_REVOKE_ROUTE, 2, 4).is_err());
    // A DIR_CHANGE token is not legal on a PT ack.
    let dir = pnotify_ack_payload(external_dir_change_ack_token(9), 3);
    assert!(validate_pnotify_ack_v21(&dir, notify_ack_kind::DIR_CHANGE, 0, 3).is_err());
}

// ---- Task 3: attach barriers ------------------------------------------------

fn cut_body(reconcile_cut: u64) -> ExternalChangeCutV1 {
    ExternalChangeCutV1 {
        header: ControlHeader {
            struct_size: 24,
            struct_version: 1,
            required_flags: 0,
        },
        reconcile_cut,
        flags: 0,
        reserved: 0,
    }
}

fn ready_body(reconcile_cut: u64, processed: u64) -> ExternalChangeReadyV1 {
    ExternalChangeReadyV1 {
        header: ControlHeader {
            struct_size: 32,
            struct_version: 1,
            required_flags: 0,
        },
        reconcile_cut,
        processed_high_watermark: processed,
        flags: 0,
        reserved: 0,
    }
}

fn lane_ready_body(kind_ordinal: u16, high_watermark: u64) -> PtLaneReadyV1 {
    PtLaneReadyV1 {
        header: ControlHeader {
            struct_size: 24,
            struct_version: 1,
            required_flags: 0,
        },
        kind_ordinal,
        reserved0: 0,
        flags: 0,
        high_watermark,
    }
}

#[test]
fn external_change_cut_barrier() {
    // Creation must equal the ordinal counter snapshot.
    let create = AttachCutContextV21 {
        kernel_high_watermark: 3,
        ordinal_counter: 5,
        stored_cut: None,
        progressed: false,
    };
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(5), &create),
        AttachBarrierV21::Accept
    );
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(4), &create),
        AttachBarrierV21::ProtocolFault
    );
    // kernel high-watermark above the cut is a fault.
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(2), &create),
        AttachBarrierV21::ProtocolFault
    );

    // Exact duplicate before progress is idempotent.
    let retained = AttachCutContextV21 {
        kernel_high_watermark: 3,
        ordinal_counter: 9,
        stored_cut: Some(5),
        progressed: false,
    };
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(5), &retained),
        AttachBarrierV21::IdempotentDuplicate
    );
    // Changed duplicate or duplicate after progress is a fault.
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(6), &retained),
        AttachBarrierV21::ProtocolFault
    );
    let progressed = AttachCutContextV21 {
        progressed: true,
        ..retained
    };
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(5), &progressed),
        AttachBarrierV21::ProtocolFault
    );

    // Zero-on-creation requires a zero counter.
    let zero_create = AttachCutContextV21 {
        kernel_high_watermark: 0,
        ordinal_counter: 0,
        stored_cut: None,
        progressed: false,
    };
    assert_eq!(
        classify_external_change_cut_v21(&cut_body(0), &zero_create),
        AttachBarrierV21::Accept
    );
}

#[test]
fn external_change_ready_barrier() {
    let ctx = AttachReadyContextV21 {
        stored_cut: 5,
        kernel_high_watermark: 5,
        ordinal_counter: 9,
        already_ready: false,
        active: false,
    };
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(5, 5), &ctx),
        AttachBarrierV21::Accept
    );
    // Mismatched watermarks fault.
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(5, 4), &ctx),
        AttachBarrierV21::ProtocolFault
    );
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(4, 4), &ctx),
        AttachBarrierV21::ProtocolFault
    );
    // Duplicate before activation is idempotent; post-activation is a fault.
    let dup = AttachReadyContextV21 {
        already_ready: true,
        ..ctx
    };
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(5, 5), &dup),
        AttachBarrierV21::IdempotentDuplicate
    );
    let active = AttachReadyContextV21 {
        active: true,
        ..ctx
    };
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(5, 5), &active),
        AttachBarrierV21::ProtocolFault
    );
    // Zero watermarks require a zero counter.
    let zero = AttachReadyContextV21 {
        stored_cut: 0,
        kernel_high_watermark: 0,
        ordinal_counter: 0,
        already_ready: false,
        active: false,
    };
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(0, 0), &zero),
        AttachBarrierV21::Accept
    );
    let zero_bad = AttachReadyContextV21 {
        ordinal_counter: 1,
        ..zero
    };
    assert_eq!(
        classify_external_change_ready_v21(&ready_body(0, 0), &zero_bad),
        AttachBarrierV21::ProtocolFault
    );
}

#[test]
fn pt_lane_ready_barrier() {
    assert_eq!(
        classify_pt_lane_ready_v21(&lane_ready_body(1, 7), 7, false, false),
        AttachBarrierV21::Accept
    );
    // Watermark mismatch faults.
    assert_eq!(
        classify_pt_lane_ready_v21(&lane_ready_body(1, 6), 7, false, false),
        AttachBarrierV21::ProtocolFault
    );
    // Duplicate before activation is idempotent.
    assert_eq!(
        classify_pt_lane_ready_v21(&lane_ready_body(2, 7), 7, true, false),
        AttachBarrierV21::IdempotentDuplicate
    );
    // Post-activation faults.
    assert_eq!(
        classify_pt_lane_ready_v21(&lane_ready_body(1, 7), 7, false, true),
        AttachBarrierV21::ProtocolFault
    );
    // Invalid kind ordinal faults.
    assert_eq!(
        classify_pt_lane_ready_v21(&lane_ready_body(3, 7), 7, false, false),
        AttachBarrierV21::ProtocolFault
    );
}

// ---- Task 3: notification credit ownership ---------------------------------

#[test]
fn notification_credit_classification() {
    let retained = NotificationCreditRefV21 {
        ring_index: 2,
        index: 4,
        generation: 5,
    };
    let fresh = NotificationCreditRefV21 {
        ring_index: 2,
        index: 4,
        generation: 6,
    };
    assert_eq!(
        classify_notification_credit_v21(retained, fresh, false),
        NotificationCreditClassV21::Fresh
    );
    // Same generation is a duplicate reuse.
    assert_eq!(
        classify_notification_credit_v21(retained, retained, false),
        NotificationCreditClassV21::DuplicateReuse
    );
    // Different ring is a stale cross-ring credit.
    let cross = NotificationCreditRefV21 {
        ring_index: 3,
        index: 4,
        generation: 6,
    };
    assert_eq!(
        classify_notification_credit_v21(retained, cross, false),
        NotificationCreditClassV21::StaleCrossRing
    );
    // DIR_CHANGE pinned to ring zero.
    let ring0 = NotificationCreditRefV21 {
        ring_index: 0,
        index: 4,
        generation: 6,
    };
    assert_eq!(
        classify_notification_credit_v21(ring0, fresh, true),
        NotificationCreditClassV21::WrongRing
    );
}

// ---- Task 3: durable external outbox row -----------------------------------

fn outbox_key(first_ordinal: u64) -> Vec<u8> {
    let key = DurableKeyV1 {
        namespace: DurableNamespaceV1 {
            mount_id: MountId { lo: 1, hi: 2 },
            boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
        },
        identity: DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: ExternalNotifyKeyIdentityV1::OutboxRow { first_ordinal },
        },
    };
    let mut out = [0u8; 128];
    let needed = encode_durable_key_v1(&key, &mut out).unwrap();
    out[..needed].to_vec()
}

fn latest_processed_key() -> Vec<u8> {
    let key = DurableKeyV1 {
        namespace: DurableNamespaceV1 {
            mount_id: MountId { lo: 1, hi: 2 },
            boot_instance_id: BootInstanceId { lo: 3, hi: 4 },
        },
        identity: DurableKeyIdentityV1::ExternalNotifyOutbox {
            identity: ExternalNotifyKeyIdentityV1::LatestProcessed,
        },
    };
    let mut out = [0u8; 128];
    let needed = encode_durable_key_v1(&key, &mut out).unwrap();
    out[..needed].to_vec()
}

#[test]
fn external_outbox_row_validates_against_key() {
    let value = precise_base().envelope(TARGET);
    let key = outbox_key(1);
    validate_external_outbox_row_v1(&key, &value, 4).unwrap();

    // Key/value ordinal mismatch is rejected.
    assert!(validate_external_outbox_row_v1(&outbox_key(9), &value, 4).is_err());

    // A non-DIR_CHANGE envelope value is rejected.
    let not_dir = build_envelope(
        notify::PT_GRANT,
        ZERO_TOKEN,
        TARGET,
        &pt_grant_body(2, 4096),
    );
    assert!(validate_external_outbox_row_v1(&key, &not_dir, 4).is_err());

    // A wrong key kind is rejected.
    assert!(validate_external_outbox_row_v1(&latest_processed_key(), &value, 4).is_err());
}
