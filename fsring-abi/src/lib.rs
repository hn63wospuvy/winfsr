//! Byte-exact FSRING ABI v2 shared-memory and control-message definitions.
//!
//! Kernel builds disable default features to select `no_std`; the `std`
//! feature is reserved for host-side tests; the ABI and v2 transport are
//! core-only.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod codec;
pub mod control;
/// cbindgen:ignore
pub mod digest;
pub mod durable;
pub mod features;
pub mod ids;
pub mod layout;
pub mod limits;
pub mod msgs;
pub mod ring;
pub mod section_layout;
pub mod slots;
pub mod validate;

pub use features::{FeatureError, FeatureSet};
pub use ids::{
    AckToken, BootInstanceId, FileId, IdError, LinkId, MountId, OpId, ReqId, RetireToken,
    TransactionId,
};
pub use layout::*;
pub use limits::*;
pub use ring::{
    ConsumerPark, CursorFault, MpscProducer, NativeReservation, ParkProtocol, PopError,
    ProducerPark, PushError, PushReceipt, ReservationHooks, SingleConsumer, SpscProducer,
    MAX_RESERVE_RETRIES,
};
pub use slots::{SlotToken, SlotTokenError};
