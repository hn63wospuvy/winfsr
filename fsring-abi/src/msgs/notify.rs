//! Version 1 and version 2 notification envelopes, notification bodies, and
//! authenticated-control donations.

use core::mem::{align_of, offset_of, size_of};

use crate::{
    codec::Pod,
    ids::{AckToken, FileId, LinkId},
};

use super::{BlobSlice, BufferRef, ControlHeader, SizeState};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NotifyEnvelopeV1 {
    pub header: ControlHeader,
    pub notify_code: u16,
    pub notify_flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub token: AckToken,
    pub file_id: FileId,
    pub body: BufferRef,
}

/// Authenticated control-IOCTL payload; never valid on an unestablished ring.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DonateBackingV1 {
    pub header: ControlHeader,
    pub file_id: FileId,
    pub pt_epoch: u64,
    pub daemon_handle: u64,
    pub sector_size: u32,
    pub flags: u32,
}

/// Authenticated control-IOCTL payload; never valid on an unestablished ring.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DonateSecurityContextV1 {
    pub header: ControlHeader,
    pub security_context_id: u64,
    pub daemon_handle: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

unsafe impl Pod for NotifyEnvelopeV1 {}
unsafe impl Pod for DonateBackingV1 {}
unsafe impl Pod for DonateSecurityContextV1 {}

const _: () = assert!(size_of::<NotifyEnvelopeV1>() == 72);
const _: () = assert!(align_of::<NotifyEnvelopeV1>() == 8);
const _: () = assert!(size_of::<DonateBackingV1>() == 48);
const _: () = assert!(align_of::<DonateBackingV1>() == 8);
const _: () = assert!(size_of::<DonateSecurityContextV1>() == 32);
const _: () = assert!(align_of::<DonateSecurityContextV1>() == 8);

// ---- Wave 9 notification bodies and acknowledgement payloads ----------------
//
// Every item below is hidden from cbindgen until Wave 10 activates ABI minor 1
// and regenerates the exhaustive C contract. The `NotifyEnvelopeV2` inline
// `BlobSlice` body starts at byte 56; V1 is illegal in the 2.1 map.

/// High-half tag identifying an FSRING-scoped `AckToken` (ASCII "FSRING").
/// cbindgen:ignore
pub const ACK_TOKEN_HI_TAG: u64 = 0x4653_5249_4e47_0000;
/// Mask selecting the tag bits of an `AckToken` high half.
/// cbindgen:ignore
pub const ACK_TOKEN_HI_MASK: u64 = 0xffff_ffff_ffff_0000;

/// Closed `ExternalDirChangeV1.change_kind` registry.
/// cbindgen:ignore
pub mod external_change_kind {
    pub const ADD: u16 = 1;
    pub const REMOVE: u16 = 2;
    pub const MODIFY: u16 = 3;
    pub const RENAME: u16 = 4;
    pub const OVERFLOW: u16 = 0xffff;
}

/// Closed `ExternalDirChangeV1.object_kind` registry; zero for OVERFLOW.
/// cbindgen:ignore
pub mod external_object_kind {
    pub const FILE: u16 = 1;
    pub const DIRECTORY: u16 = 2;
}

/// Closed `AckToken` lane kind ordinals encoded into `token.hi`.
/// cbindgen:ignore
pub mod notify_ack_kind {
    pub const PT_REVOKE_ROUTE: u16 = 1;
    pub const PT_EXTERNAL_MUTATION_SAFE: u16 = 2;
    pub const DIR_CHANGE: u16 = 3;
}

/// ABI 2.1 notification envelope carrying an inline `BlobSlice` body at byte 56.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NotifyEnvelopeV2 {
    pub header: ControlHeader,
    pub notify_code: u16,
    pub notify_flags: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
    pub token: AckToken,
    pub file_id: FileId,
    pub body: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InvalidateFileV1 {
    pub header: ControlHeader,
    pub offset: u64,
    /// Zero means the whole stream and requires `offset == 0`.
    pub length: u64,
    pub content_epoch: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct InvalidateEntryV1 {
    pub header: ControlHeader,
    pub namespace_generation: u64,
    /// Inline UTF-16 name; begins at byte 32 and consumes the body tail.
    pub name: BlobSlice,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtGrantV1 {
    pub header: ControlHeader,
    pub pt_epoch: u64,
    pub sector_size: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtEpochV1 {
    pub header: ControlHeader,
    pub pt_epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResizeV1 {
    pub header: ControlHeader,
    pub sizes: SizeState,
    pub volume_commit_sequence: u64,
}

/// External directory-change notification body; 176-byte fixed prefix, with
/// body-relative old/new names beginning at byte 176.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExternalDirChangeV1 {
    pub header: ControlHeader,
    pub first_ordinal: u64,
    pub through_ordinal: u64,
    pub volume_commit_sequence: u64,
    pub change_kind: u16,
    pub object_kind: u16,
    pub filter_match: u32,
    pub flags: u32,
    pub reserved0: u32,
    pub target_link_id: LinkId,
    pub replaced_file_id: FileId,
    pub replaced_link_id: LinkId,
    pub old_parent_id: FileId,
    pub new_parent_id: FileId,
    pub old_parent_generation: u64,
    pub new_parent_generation: u64,
    pub target_namespace_generation: u64,
    pub replaced_namespace_generation: u64,
    pub old_name: BlobSlice,
    pub new_name: BlobSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtLaneReadyV1 {
    pub header: ControlHeader,
    pub kind_ordinal: u16,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved0: u16,
    pub flags: u32,
    pub high_watermark: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExternalChangeReadyV1 {
    pub header: ControlHeader,
    pub reconcile_cut: u64,
    pub processed_high_watermark: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExternalChangeCutV1 {
    pub header: ControlHeader,
    pub reconcile_cut: u64,
    pub flags: u32,
    /// Reserved ABI field: senders write zero; receivers validate zero.
    pub reserved: u32,
}

/// `DIR_CHANGE_ACK` SQE-inline payload; `PControl`/`BufferRef` forms are illegal.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PDirChangeAckV1 {
    pub token: AckToken,
    pub through_ordinal: u64,
    pub volume_commit_sequence: u64,
    pub semantic_digest: [u8; 32],
}

// SAFETY: each repr(C) type has only Pod fields that accept every bit pattern,
// and the assertions below prove every byte belongs to an explicit field.
unsafe impl Pod for NotifyEnvelopeV2 {}
// SAFETY: see the shared note above.
unsafe impl Pod for InvalidateFileV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for InvalidateEntryV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for PtGrantV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for PtEpochV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for ResizeV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for ExternalDirChangeV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for PtLaneReadyV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for ExternalChangeReadyV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for ExternalChangeCutV1 {}
// SAFETY: see the shared note above.
unsafe impl Pod for PDirChangeAckV1 {}

const _: () = {
    assert!(size_of::<NotifyEnvelopeV2>() == 56);
    assert!(align_of::<NotifyEnvelopeV2>() == 8);
    assert!(offset_of!(NotifyEnvelopeV2, header) == 0);
    assert!(offset_of!(NotifyEnvelopeV2, notify_code) == 8);
    assert!(offset_of!(NotifyEnvelopeV2, notify_flags) == 10);
    assert!(offset_of!(NotifyEnvelopeV2, reserved) == 12);
    assert!(offset_of!(NotifyEnvelopeV2, token) == 16);
    assert!(offset_of!(NotifyEnvelopeV2, file_id) == 32);
    assert!(offset_of!(NotifyEnvelopeV2, body) == 48);
    assert!(offset_of!(NotifyEnvelopeV2, body) + 8 == 56);

    assert!(size_of::<InvalidateFileV1>() == 40);
    assert!(align_of::<InvalidateFileV1>() == 8);
    assert!(offset_of!(InvalidateFileV1, header) == 0);
    assert!(offset_of!(InvalidateFileV1, offset) == 8);
    assert!(offset_of!(InvalidateFileV1, length) == 16);
    assert!(offset_of!(InvalidateFileV1, content_epoch) == 24);
    assert!(offset_of!(InvalidateFileV1, flags) == 32);
    assert!(offset_of!(InvalidateFileV1, reserved) == 36);
    assert!(offset_of!(InvalidateFileV1, reserved) + 4 == 40);

    assert!(size_of::<InvalidateEntryV1>() == 32);
    assert!(align_of::<InvalidateEntryV1>() == 8);
    assert!(offset_of!(InvalidateEntryV1, header) == 0);
    assert!(offset_of!(InvalidateEntryV1, namespace_generation) == 8);
    assert!(offset_of!(InvalidateEntryV1, name) == 16);
    assert!(offset_of!(InvalidateEntryV1, flags) == 24);
    assert!(offset_of!(InvalidateEntryV1, reserved) == 28);
    assert!(offset_of!(InvalidateEntryV1, reserved) + 4 == 32);

    assert!(size_of::<PtGrantV1>() == 24);
    assert!(align_of::<PtGrantV1>() == 8);
    assert!(offset_of!(PtGrantV1, header) == 0);
    assert!(offset_of!(PtGrantV1, pt_epoch) == 8);
    assert!(offset_of!(PtGrantV1, sector_size) == 16);
    assert!(offset_of!(PtGrantV1, flags) == 20);
    assert!(offset_of!(PtGrantV1, flags) + 4 == 24);

    assert!(size_of::<PtEpochV1>() == 16);
    assert!(align_of::<PtEpochV1>() == 8);
    assert!(offset_of!(PtEpochV1, header) == 0);
    assert!(offset_of!(PtEpochV1, pt_epoch) == 8);
    assert!(offset_of!(PtEpochV1, pt_epoch) + 8 == 16);

    assert!(size_of::<ResizeV1>() == 48);
    assert!(align_of::<ResizeV1>() == 8);
    assert!(offset_of!(ResizeV1, header) == 0);
    assert!(offset_of!(ResizeV1, sizes) == 8);
    assert!(offset_of!(ResizeV1, volume_commit_sequence) == 40);
    assert!(offset_of!(ResizeV1, volume_commit_sequence) + 8 == 48);

    assert!(size_of::<ExternalDirChangeV1>() == 176);
    assert!(align_of::<ExternalDirChangeV1>() == 8);
    assert!(offset_of!(ExternalDirChangeV1, header) == 0);
    assert!(offset_of!(ExternalDirChangeV1, first_ordinal) == 8);
    assert!(offset_of!(ExternalDirChangeV1, through_ordinal) == 16);
    assert!(offset_of!(ExternalDirChangeV1, volume_commit_sequence) == 24);
    assert!(offset_of!(ExternalDirChangeV1, change_kind) == 32);
    assert!(offset_of!(ExternalDirChangeV1, object_kind) == 34);
    assert!(offset_of!(ExternalDirChangeV1, filter_match) == 36);
    assert!(offset_of!(ExternalDirChangeV1, flags) == 40);
    assert!(offset_of!(ExternalDirChangeV1, reserved0) == 44);
    assert!(offset_of!(ExternalDirChangeV1, target_link_id) == 48);
    assert!(offset_of!(ExternalDirChangeV1, replaced_file_id) == 64);
    assert!(offset_of!(ExternalDirChangeV1, replaced_link_id) == 80);
    assert!(offset_of!(ExternalDirChangeV1, old_parent_id) == 96);
    assert!(offset_of!(ExternalDirChangeV1, new_parent_id) == 112);
    assert!(offset_of!(ExternalDirChangeV1, old_parent_generation) == 128);
    assert!(offset_of!(ExternalDirChangeV1, new_parent_generation) == 136);
    assert!(offset_of!(ExternalDirChangeV1, target_namespace_generation) == 144);
    assert!(offset_of!(ExternalDirChangeV1, replaced_namespace_generation) == 152);
    assert!(offset_of!(ExternalDirChangeV1, old_name) == 160);
    assert!(offset_of!(ExternalDirChangeV1, new_name) == 168);
    assert!(offset_of!(ExternalDirChangeV1, new_name) + 8 == 176);

    assert!(size_of::<PtLaneReadyV1>() == 24);
    assert!(align_of::<PtLaneReadyV1>() == 8);
    assert!(offset_of!(PtLaneReadyV1, header) == 0);
    assert!(offset_of!(PtLaneReadyV1, kind_ordinal) == 8);
    assert!(offset_of!(PtLaneReadyV1, reserved0) == 10);
    assert!(offset_of!(PtLaneReadyV1, flags) == 12);
    assert!(offset_of!(PtLaneReadyV1, high_watermark) == 16);
    assert!(offset_of!(PtLaneReadyV1, high_watermark) + 8 == 24);

    assert!(size_of::<ExternalChangeReadyV1>() == 32);
    assert!(align_of::<ExternalChangeReadyV1>() == 8);
    assert!(offset_of!(ExternalChangeReadyV1, header) == 0);
    assert!(offset_of!(ExternalChangeReadyV1, reconcile_cut) == 8);
    assert!(offset_of!(ExternalChangeReadyV1, processed_high_watermark) == 16);
    assert!(offset_of!(ExternalChangeReadyV1, flags) == 24);
    assert!(offset_of!(ExternalChangeReadyV1, reserved) == 28);
    assert!(offset_of!(ExternalChangeReadyV1, reserved) + 4 == 32);

    assert!(size_of::<ExternalChangeCutV1>() == 24);
    assert!(align_of::<ExternalChangeCutV1>() == 8);
    assert!(offset_of!(ExternalChangeCutV1, header) == 0);
    assert!(offset_of!(ExternalChangeCutV1, reconcile_cut) == 8);
    assert!(offset_of!(ExternalChangeCutV1, flags) == 16);
    assert!(offset_of!(ExternalChangeCutV1, reserved) == 20);
    assert!(offset_of!(ExternalChangeCutV1, reserved) + 4 == 24);

    assert!(size_of::<PDirChangeAckV1>() == 64);
    assert!(align_of::<PDirChangeAckV1>() == 8);
    assert!(offset_of!(PDirChangeAckV1, token) == 0);
    assert!(offset_of!(PDirChangeAckV1, through_ordinal) == 16);
    assert!(offset_of!(PDirChangeAckV1, volume_commit_sequence) == 24);
    assert!(offset_of!(PDirChangeAckV1, semantic_digest) == 32);
    assert!(offset_of!(PDirChangeAckV1, semantic_digest) + 32 == 64);
};
