//! BootContext wire records and checked publication arithmetic.

use core::mem::{align_of, offset_of, size_of};

use crate::{
    codec::Pod,
    features::FeatureSet,
    ids::{BootInstanceId, MountId},
};

/// cbindgen:ignore
pub const BOOT_CONTEXT_SECTION_BYTES: u32 = 65_536;
/// cbindgen:ignore
pub const BOOT_CONTEXT_HEADER_BYTES: u32 = 256;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SLOT_BYTES: u32 = 256;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SLOT_COUNT: u32 = 64;
/// cbindgen:ignore
pub const BOOT_CONTEXT_USED_BYTES: u32 = 16_640;
/// cbindgen:ignore
pub const BOOT_CONTEXT_MAGIC: u64 = 0x4342_474e_4952_5346;
/// cbindgen:ignore
pub const BOOT_CONTEXT_VERSION: u32 = 1;
/// cbindgen:ignore
pub const BOOT_CONTEXT_INITIAL_SEQUENCE: u64 = 2;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SEQUENCE_STEP: u64 = 2;
/// cbindgen:ignore
pub const BOOT_CONTEXT_RETIRE_KEY_BYTES: u32 = 32;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SERVICE_SID_BYTES: u32 = 32;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SERVICE_SID_BUFFER_BYTES: u32 = 68;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SETUP_REQUIRED_PUBLICATIONS: u32 = 5;
/// cbindgen:ignore
pub const BOOT_CONTEXT_ATTACH_REQUIRED_PUBLICATIONS: u32 = 4;
/// cbindgen:ignore
pub const BOOT_CONTEXT_STARTUP_RETIRE_REQUIRED_PUBLICATIONS: u32 = 2;
/// cbindgen:ignore
pub const BOOT_CONTEXT_HEADER_REQUIRED_PUBLICATIONS: u32 = 1;
/// cbindgen:ignore
pub const BOOT_CONTEXT_SECTION_NAME: &str = "\\KernelObjects\\FsRingBootContext-v1";
/// cbindgen:ignore
pub const BOOT_CONTEXT_LOCK_NAME: &str = "\\KernelObjects\\FsRingBootContextLock-v1";

/// cbindgen:ignore
pub mod boot_context_init_state {
    pub const EMPTY: u32 = 0;
    pub const INITIALIZING: u32 = 1;
    pub const READY: u32 = 2;
}

/// cbindgen:ignore
pub mod boot_context_slot_state {
    pub const FREE: u32 = 0;
    pub const STAGING: u32 = 1;
    pub const LIVE: u32 = 2;
    pub const TERMINALIZING: u32 = 3;
    pub const TERMINAL: u32 = 4;
}

/// Stable BootContext header wire image.
///
/// `Pod` applies only to a private, stable record image. Callers must not cast,
/// decode, borrow, or read a live mapped BootContext record. Runtime code must
/// first obtain an accepted private copy through the binding seqlock/barrier
/// protocol.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct BootContextHeaderV1 {
    pub magic: u64,
    pub format_version: u32,
    pub header_size: u32,
    pub context_size: u32,
    pub slot_size: u32,
    pub slot_count: u32,
    pub init_state: u32,
    pub flags: u32,
    pub reserved0: u32,
    pub header_sequence: u64,
    pub mount_sequence: u64,
    pub mount_sequence_complement: u64,
    pub load_generation: u64,
    pub load_generation_complement: u64,
    pub boot_instance_id: BootInstanceId,
    pub per_boot_retire_key: [u8; 32],
    pub digest: [u8; 32],
    pub reserved: [u8; 96],
}

/// Stable BootContext slot wire image.
///
/// `Pod` applies only to a private, stable record image. Callers must not cast,
/// decode, borrow, or read a live mapped BootContext record. Runtime code must
/// first obtain an accepted private copy through the binding seqlock/barrier
/// protocol.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct BootContextSlotV1 {
    pub sequence: u64,
    pub state: u32,
    pub service_sid_length: u32,
    pub load_generation: u64,
    pub mount_sequence: u64,
    pub mount_id: MountId,
    pub boot_instance_id: BootInstanceId,
    pub latest_session_epoch: u64,
    pub selected_features: FeatureSet,
    pub journal_version: u32,
    pub flags: u32,
    pub service_sid: [u8; 68],
    pub reserved: [u8; 60],
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootSequenceError {
    InvalidCurrent,
    InvalidPublicationCount,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootCounterError {
    InvalidCurrent,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootIdentityError {
    ZeroMountSequence,
    ZeroRandomHigh,
}

// SAFETY: both records are repr(C, align(64)); every field accepts every bit
// pattern; compile-time assertions prove every offset, full size, alignment,
// and absence of implicit/tail padding.
unsafe impl Pod for BootContextHeaderV1 {}
unsafe impl Pod for BootContextSlotV1 {}

const _: () = {
    assert!(size_of::<BootContextHeaderV1>() == 256);
    assert!(align_of::<BootContextHeaderV1>() == 64);
    assert!(offset_of!(BootContextHeaderV1, magic) == 0);
    assert!(offset_of!(BootContextHeaderV1, format_version) == 8);
    assert!(offset_of!(BootContextHeaderV1, header_size) == 12);
    assert!(offset_of!(BootContextHeaderV1, context_size) == 16);
    assert!(offset_of!(BootContextHeaderV1, slot_size) == 20);
    assert!(offset_of!(BootContextHeaderV1, slot_count) == 24);
    assert!(offset_of!(BootContextHeaderV1, init_state) == 28);
    assert!(offset_of!(BootContextHeaderV1, flags) == 32);
    assert!(offset_of!(BootContextHeaderV1, reserved0) == 36);
    assert!(offset_of!(BootContextHeaderV1, header_sequence) == 40);
    assert!(offset_of!(BootContextHeaderV1, mount_sequence) == 48);
    assert!(offset_of!(BootContextHeaderV1, mount_sequence_complement) == 56);
    assert!(offset_of!(BootContextHeaderV1, load_generation) == 64);
    assert!(offset_of!(BootContextHeaderV1, load_generation_complement) == 72);
    assert!(offset_of!(BootContextHeaderV1, boot_instance_id) == 80);
    assert!(offset_of!(BootContextHeaderV1, per_boot_retire_key) == 96);
    assert!(offset_of!(BootContextHeaderV1, digest) == 128);
    assert!(offset_of!(BootContextHeaderV1, reserved) == 160);
    assert!(offset_of!(BootContextHeaderV1, reserved) + 96 == 256);
    assert!(size_of::<BootContextSlotV1>() == 256);
    assert!(align_of::<BootContextSlotV1>() == 64);
    assert!(offset_of!(BootContextSlotV1, sequence) == 0);
    assert!(offset_of!(BootContextSlotV1, state) == 8);
    assert!(offset_of!(BootContextSlotV1, service_sid_length) == 12);
    assert!(offset_of!(BootContextSlotV1, load_generation) == 16);
    assert!(offset_of!(BootContextSlotV1, mount_sequence) == 24);
    assert!(offset_of!(BootContextSlotV1, mount_id) == 32);
    assert!(offset_of!(BootContextSlotV1, boot_instance_id) == 48);
    assert!(offset_of!(BootContextSlotV1, latest_session_epoch) == 64);
    assert!(offset_of!(BootContextSlotV1, selected_features) == 72);
    assert!(offset_of!(BootContextSlotV1, journal_version) == 88);
    assert!(offset_of!(BootContextSlotV1, flags) == 92);
    assert!(offset_of!(BootContextSlotV1, service_sid) == 96);
    assert!(offset_of!(BootContextSlotV1, reserved) == 164);
    assert!(offset_of!(BootContextSlotV1, digest) == 224);
    assert!(offset_of!(BootContextSlotV1, digest) + 32 == 256);
    assert!(
        BOOT_CONTEXT_HEADER_BYTES + BOOT_CONTEXT_SLOT_COUNT * BOOT_CONTEXT_SLOT_BYTES
            == BOOT_CONTEXT_USED_BYTES,
    );
    assert!(BOOT_CONTEXT_USED_BYTES <= BOOT_CONTEXT_SECTION_BYTES);
};

pub const fn boot_context_slot_offset_v1(index: u32) -> Option<u32> {
    if index >= BOOT_CONTEXT_SLOT_COUNT {
        return None;
    }
    let relative = match index.checked_mul(BOOT_CONTEXT_SLOT_BYTES) {
        Some(value) => value,
        None => return None,
    };
    BOOT_CONTEXT_HEADER_BYTES.checked_add(relative)
}

pub const fn checked_boot_context_publication_sequence(
    current: u64,
    publications: u32,
) -> Result<u64, BootSequenceError> {
    if current == 0 || current & 1 != 0 {
        return Err(BootSequenceError::InvalidCurrent);
    }
    if publications == 0 {
        return Err(BootSequenceError::InvalidPublicationCount);
    }
    let delta = match (publications as u64).checked_mul(BOOT_CONTEXT_SEQUENCE_STEP) {
        Some(value) => value,
        None => return Err(BootSequenceError::Exhausted),
    };
    match current.checked_add(delta) {
        Some(value) => Ok(value),
        None => Err(BootSequenceError::Exhausted),
    }
}

pub const fn checked_next_mount_sequence(current: u64) -> Result<u64, BootCounterError> {
    match current.checked_add(1) {
        Some(value) => Ok(value),
        None => Err(BootCounterError::Exhausted),
    }
}

pub const fn checked_next_load_generation(current: u64) -> Result<u64, BootCounterError> {
    if current == 0 {
        return Err(BootCounterError::InvalidCurrent);
    }
    match current.checked_add(1) {
        Some(value) => Ok(value),
        None => Err(BootCounterError::Exhausted),
    }
}

pub const fn mount_id_from_burned_sequence(
    mount_sequence: u64,
    random_hi: u64,
) -> Result<MountId, BootIdentityError> {
    if mount_sequence == 0 {
        return Err(BootIdentityError::ZeroMountSequence);
    }
    if random_hi == 0 {
        return Err(BootIdentityError::ZeroRandomHigh);
    }
    Ok(MountId {
        lo: mount_sequence,
        hi: random_hi,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_offsets_cover_exact_section_range() {
        assert_eq!(boot_context_slot_offset_v1(0), Some(256));
        assert_eq!(boot_context_slot_offset_v1(1), Some(512));
        assert_eq!(boot_context_slot_offset_v1(63), Some(16_384));
        assert_eq!(boot_context_slot_offset_v1(64), None);
        assert_eq!(boot_context_slot_offset_v1(u32::MAX), None);
    }

    #[test]
    fn publication_sequence_boundaries_are_nonwrapping() {
        assert_eq!(checked_boot_context_publication_sequence(2, 1), Ok(4));
        assert_eq!(checked_boot_context_publication_sequence(2, 2), Ok(6));
        assert_eq!(checked_boot_context_publication_sequence(2, 4), Ok(10));
        assert_eq!(checked_boot_context_publication_sequence(2, 5), Ok(12));
        assert_eq!(
            checked_boot_context_publication_sequence(0, 1),
            Err(BootSequenceError::InvalidCurrent),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(1, 1),
            Err(BootSequenceError::InvalidCurrent),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(3, 1),
            Err(BootSequenceError::InvalidCurrent),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX, 1),
            Err(BootSequenceError::InvalidCurrent),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(2, 0),
            Err(BootSequenceError::InvalidPublicationCount),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 3, 1),
            Ok(u64::MAX - 1),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 1, 1),
            Err(BootSequenceError::Exhausted),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 5, 2),
            Ok(u64::MAX - 1),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 3, 2),
            Err(BootSequenceError::Exhausted),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 7, 3),
            Ok(u64::MAX - 1),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 5, 3),
            Err(BootSequenceError::Exhausted),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 9, 4),
            Ok(u64::MAX - 1),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 7, 4),
            Err(BootSequenceError::Exhausted),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 11, 5),
            Ok(u64::MAX - 1),
        );
        assert_eq!(
            checked_boot_context_publication_sequence(u64::MAX - 9, 5),
            Err(BootSequenceError::Exhausted),
        );
    }

    #[test]
    fn counter_and_mount_identity_helpers_are_checked() {
        assert_eq!(checked_next_mount_sequence(0), Ok(1));
        assert_eq!(checked_next_mount_sequence(1), Ok(2));
        assert_eq!(checked_next_mount_sequence(u64::MAX - 1), Ok(u64::MAX));
        assert_eq!(
            checked_next_mount_sequence(u64::MAX),
            Err(BootCounterError::Exhausted),
        );
        assert_eq!(
            checked_next_load_generation(0),
            Err(BootCounterError::InvalidCurrent),
        );
        assert_eq!(checked_next_load_generation(1), Ok(2));
        assert_eq!(checked_next_load_generation(u64::MAX - 1), Ok(u64::MAX));
        assert_eq!(
            checked_next_load_generation(u64::MAX),
            Err(BootCounterError::Exhausted),
        );
        assert_eq!(
            mount_id_from_burned_sequence(0, 1),
            Err(BootIdentityError::ZeroMountSequence),
        );
        assert_eq!(
            mount_id_from_burned_sequence(0, 0),
            Err(BootIdentityError::ZeroMountSequence),
        );
        assert_eq!(
            mount_id_from_burned_sequence(1, 0),
            Err(BootIdentityError::ZeroRandomHigh),
        );
        assert_eq!(
            mount_id_from_burned_sequence(1, 1),
            Ok(MountId { lo: 1, hi: 1 }),
        );
        assert_eq!(
            mount_id_from_burned_sequence(u64::MAX, u64::MAX),
            Ok(MountId {
                lo: u64::MAX,
                hi: u64::MAX,
            }),
        );
    }
}
