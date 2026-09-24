use core::mem::{align_of, offset_of, size_of};

use crate::codec::Pod;

pub const REQ_INDEX_BITS: u32 = 24;
pub const REQ_GENERATION_BITS: u32 = 40;
pub const REQ_INDEX_MAX: u32 = (1u32 << REQ_INDEX_BITS) - 1;
pub const REQ_GENERATION_MAX: u64 = (1u64 << REQ_GENERATION_BITS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdError {
    GenerationOutOfRange,
    SlotOutOfRange,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReqId(u64);

impl ReqId {
    pub const fn try_new(generation: u64, slot_index: u32) -> Result<Self, IdError> {
        if generation > REQ_GENERATION_MAX {
            return Err(IdError::GenerationOutOfRange);
        }
        if slot_index > REQ_INDEX_MAX {
            return Err(IdError::SlotOutOfRange);
        }
        Ok(Self((generation << REQ_INDEX_BITS) | slot_index as u64))
    }
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    pub const fn generation(self) -> u64 {
        self.0 >> REQ_INDEX_BITS
    }
    pub const fn slot_index(self) -> u32 {
        (self.0 & REQ_INDEX_MAX as u64) as u32
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OpId {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FileId {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LinkId {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MountId {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BootInstanceId {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TransactionId {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AckToken {
    pub lo: u64,
    pub hi: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RetireToken {
    pub lo: u64,
    pub hi: u64,
}

macro_rules! impl_zero {
    ($($name:ident),+ $(,)?) => {
        $(
            impl $name {
                pub const ZERO: Self = Self { lo: 0, hi: 0 };
            }
        )+
    };
}

impl_zero!(
    OpId,
    FileId,
    LinkId,
    MountId,
    BootInstanceId,
    TransactionId,
    AckToken,
    RetireToken,
);

// SAFETY: each type is a repr(C) pair of u64 fields with no padding,
// every bit pattern is valid, and the compile-time assertions fix its layout.
unsafe impl Pod for BootInstanceId {}
unsafe impl Pod for RetireToken {}

const _: () = {
    assert!(size_of::<BootInstanceId>() == 16);
    assert!(align_of::<BootInstanceId>() == 8);
    assert!(offset_of!(BootInstanceId, lo) == 0);
    assert!(offset_of!(BootInstanceId, hi) == 8);
    assert!(size_of::<RetireToken>() == 16);
    assert!(align_of::<RetireToken>() == 8);
    assert!(offset_of!(RetireToken, lo) == 0);
    assert!(offset_of!(RetireToken, hi) == 8);
};
