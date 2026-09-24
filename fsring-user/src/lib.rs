//! `fsring-user`: the `std`/OS daemon-side runtime for the FSRING ring transport.
//!
//! The frozen [`fsring_abi`] crate owns every wire type, the ring algorithm, and
//! the section/topology validators. This crate supplies what that `no_std`
//! library cannot: real peer-shared memory, a park/wake primitive, section
//! construction and hostile-input validation, and the ENTER loop that drives one
//! request to completion. The ring algorithm itself is never re-derived here.
//!
//! Delivered so far: the ring transport foundation ([`section`], [`layout`],
//! [`ring`], [`handshake`]), the [`provider`] dispatch seam driven by
//! [`daemon::pump_once`], the [`namematch`] name-match helper, and the C4
//! four-frame smoke route ([`smoke`]). ATTACH / durable / PT / notifications
//! and `mirrorfs` are later sub-projects.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod control;
pub mod daemon;
pub mod dataio;
pub mod direnum;
pub mod error;
pub mod filesystem;
pub mod grant;
pub mod handshake;
pub mod layout;
pub mod lifecycle;
pub mod mutation;
pub mod namematch;
pub mod native;
pub mod openbody;
pub mod payload;
pub mod provider;
pub mod querydir;
pub mod queryinfo;
pub mod querysecurity;
pub mod queryvolume;
pub mod ring;
pub mod section;
pub mod smoke;

#[cfg(any(test, feature = "testkit"))]
mod fixture;

#[cfg(loom)]
mod loom_model;

#[cfg(feature = "testkit")]
pub mod testkit;

pub use control::{pcontrol_body_ref, AbortRequest, ControlBodyError};
pub use daemon::{pump_once, Daemon, PumpStats};
pub use dataio::{
    build_read_completion, build_write_result, decode_read, decode_write, ReadRequest, WriteEffect,
    WriteOutcome, WriteRequest,
};
pub use direnum::{DirCandidate, DirEntryFields, DirEnumerator, QueryDirBatch};
pub use error::{
    DaemonError, DataIoError, DecodeError, EnumError, GrantError, LifecycleFault, MutationError,
    MutationResultError, OpenBodyError, OpenResultError, ProviderViolation, PumpError,
    QueryDirError, QueryInfoError, QuerySecurityError, QueryVolumeError, ResultError, RingFault,
    SectionError, TransportError, WriteResultError,
};
pub use filesystem::{FileSystem, FileSystemResult, MutationContext, ProviderError};
pub use grant::{resolve_body, write_body, BodyView, GrantTable};
pub use layout::{PhysicalLayout, RingRegions};
pub use lifecycle::{CommitEffect, CommittedResult, OpenLifecycle, PrepareResult, RowState};
pub use mutation::{
    build_mutate_completion, build_mutation_result, decode_mutation, revalidate_context,
    DecodedBody, MutationEffect, MutationRequest, MutationResultBytes, Replaced,
};
pub use namematch::{name_in_expression, NameMatchError, NameMatcher};
pub use openbody::{
    build_commit_completion, build_commit_result, build_prepare_completion, build_prepare_result,
    decode_commit, decode_prepare, CommitRequest, PreparedRequest,
};
pub use payload::{BarrierRequest, PayloadError};
pub use provider::{
    resolve_completion, Completion, EchoProvider, OutBuf, Provider, StatusProvider,
};
pub use querydir::{build_query_dir_completion, decode_query_dir, QueryDirRequest};
pub use queryinfo::{build_file_info, decode_query_info, FileInfoFields, QueryInfoRequest};
pub use querysecurity::{
    build_query_security_completion, decode_query_security, QuerySecurityRequest,
};
pub use queryvolume::{
    build_volume_size_info, decode_query_volume, QueryVolumeRequest, VolumeSizeFields,
};

/// Re-exported so a provider can name the output context the ABI output matrix
/// requires for the request-derived opcodes (READ/WRITE, QUERY_*).
pub use fsring_abi::validate::CompletionOutputContextV21;
pub use ring::{DaemonRing, KernelRing};
pub use section::{CondvarWaiter, HeapSection, SharedSection, Waiter};

#[cfg(all(windows, not(miri)))]
pub use section::{EventWaiter, MappedSection};
