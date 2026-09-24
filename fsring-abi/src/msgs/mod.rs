//! ABI v2 payloads.
//!
//! Fixed ring payloads and versioned control blobs are split by protocol area,
//! then re-exported here as the public message surface.
//!
//! # Ring payload map
//!
//! - PREPARE_OPEN, COMMIT_OPEN, ABORT_OPEN, QUERY_INFO, MUTATE, QUERY_DIR,
//!   QUERY_VOLUME, QUERY_SECURITY, FSCTL, REPLAY_OPEN, QUERY_OP, and ACK_RESULT
//!   carry [`PControl`] and return extensible data through [`OControl`].
//! - CLEANUP, CLOSE, and FLUSH carry [`PBarrier`].
//! - READ carries [`PRw`]; WRITE carries [`PControl`] referencing [`WriteV2`].
//!   Both return extensible data through [`OControl`] in ABI 2.1; [`ORw`] is
//!   retained only as an ABI-major layout and is not a legal 2.1 result.
//! - MUTATE carries [`PControl`] referencing [`MutationV2`] with a K2U body
//!   blob and U2K reply/kind-result grants; [`MutationV1`] remains defined
//!   only as an ABI-major layout and is not a legal 2.1 request.
//! - QUERY_INFO, QUERY_VOLUME, and QUERY_SECURITY carry their V1 requests;
//!   QUERY_DIR carries [`QueryDirV2`]. [`QueryDirV1`] and [`FsctlV1`] are
//!   registry-only layouts: neither is a legal ABI 2.1 wire form.
//! - CANCEL carries [`PCancel`] with `sqe_flags::NO_COMPLETION`.
//! - PT_ROUTE_ACK and PT_EXTERNAL_SAFE_ACK carry [`PNotifyAck`].
//! - ABI 2.1 notifications require the deferred `NotifyEnvelopeV2`;
//!   [`NotifyEnvelopeV1`] remains defined but is illegal in the 2.1 map.
//! - ATTACH, [`DonateBackingV1`], and [`DonateSecurityContextV1`] travel only
//!   through the authenticated control IOCTL, never an unestablished ring.

pub mod common;
pub mod io;
pub mod mutation;
pub mod notify;
pub mod open;
pub mod protocol;
pub mod query;
pub mod recovery;

pub use common::*;
pub use io::*;
pub use mutation::*;
pub use notify::*;
pub use open::*;
pub use protocol::*;
pub use query::*;
pub use recovery::*;

use core::mem::size_of;

use crate::{
    codec::Pod,
    features::FeatureSet,
    ids::{AckToken, FileId, LinkId, MountId, OpId, ReqId, TransactionId},
    layout::{CQE_OUT_LEN, SQE_PAYLOAD_LEN},
};

// These foundational wire types have only integer fields, stable explicit
// layouts, no compiler gaps, and accept every possible bit pattern. Semantic
// validation remains the receiver's responsibility.
unsafe impl Pod for FeatureSet {}
unsafe impl Pod for ReqId {}
unsafe impl Pod for OpId {}
unsafe impl Pod for FileId {}
unsafe impl Pod for LinkId {}
unsafe impl Pod for MountId {}
unsafe impl Pod for TransactionId {}
unsafe impl Pod for AckToken {}

const _: () = assert!(size_of::<PControl>() <= SQE_PAYLOAD_LEN);
const _: () = assert!(size_of::<PBarrier>() <= SQE_PAYLOAD_LEN);
const _: () = assert!(size_of::<PRw>() <= SQE_PAYLOAD_LEN);
const _: () = assert!(size_of::<PCancel>() <= SQE_PAYLOAD_LEN);
const _: () = assert!(size_of::<PNotifyAck>() <= SQE_PAYLOAD_LEN);
const _: () = assert!(size_of::<OControl>() <= CQE_OUT_LEN);
const _: () = assert!(size_of::<ORw>() <= CQE_OUT_LEN);
