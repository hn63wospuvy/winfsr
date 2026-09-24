//! Multi-grant decode of the transactional-OPEN control bodies.
//!
//! `PREPARE_OPEN` and `COMMIT_OPEN` each carry a `PControl` (24 bytes) whose
//! `body: BufferRef` points at a granted slot holding a `PrepareOpenV2` (192) or
//! `CommitOpenV2` (104). Unlike the barrier opcodes those bodies carry *further*
//! `BufferRef`s (a `PrepareOpenV2` names six grants), so decoding one resolves a
//! whole grant graph. The frozen ABI owns the wire rules: this module drives
//! `validate_prepare_open_v2` / `validate_commit_open_v2` with grant bindings the
//! A2 [`GrantTable`] produces, single-fetches the K2U input bytes, and hands the
//! lifecycle engine an owned request value. The U2K `reply`/`result-SD` grants
//! are output buffers — validated, never fetched or written here.

use core::mem::size_of;

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::ids::{FileId, OpId, TransactionId};
use fsring_abi::layout::{op, SqeBody};
use fsring_abi::msgs::{
    buffer_kind, BufferRef, CommitOpenResultV2, CommitOpenV2, ControlHeader, OControl,
    PrepareOpenResultV1, PrepareOpenV2, CONTROL_VERSION_V1, CONTROL_VERSION_V2,
};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    validate_commit_open_success_v2, validate_commit_open_v2, validate_completion_output_v21,
    validate_prepare_open_success_v21, validate_prepare_open_v2, CompletionOutputContextV21,
    GrantBindingV21, MessageValidationError, PrepareOpenV2Context,
};

use crate::control::pcontrol_body_ref;
use crate::error::{GrantError, OpenBodyError, OpenResultError};
use crate::grant::{encode_pod, resolve_body, GrantTable};
use crate::lifecycle::{CommittedResult, PrepareResult};
use crate::provider::{Completion, OutBuf};
use crate::section::SharedSection;

/// The retained raw wire request (`CommitOpenV2` / `PrepareOpenV2`), carried on
/// the decoded request so the frozen *success* validators — which re-run the
/// *request* validators — can be driven host-side by [`build_commit_result`] /
/// [`build_prepare_result`].
///
/// It is deliberately excluded from the request's identity: two decoded
/// requests are equal iff their **semantic** fields match (the raw is the wire
/// echo the result builder replays, and its grant coordinates legitimately
/// differ between an original request and an idempotent replay), and it is
/// elided from `Debug`. This lets `CommitRequest` / `PreparedRequest` keep
/// deriving `PartialEq`/`Eq`/`Debug` even though the frozen V2 wire structs
/// derive none of them.
#[derive(Clone, Copy)]
struct RawEcho<T>(T);

impl<T> PartialEq for RawEcho<T> {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<T> Eq for RawEcho<T> {}

impl<T> core::fmt::Debug for RawEcho<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<raw>")
    }
}

/// A decoded, ABI-validated `PREPARE_OPEN` request: the exact semantic request
/// by value, carrying owned `name`/SD/EA bytes for the open-prepare record's
/// idempotence comparison. Grant coordinates and the output buffers are excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRequest {
    pub op_id: OpId,
    pub parent_id: FileId,
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub open_flags: u32,
    pub name: Box<[u8]>,
    pub requested_security_descriptor: Option<Box<[u8]>>,
    pub extended_attributes: Option<Box<[u8]>>,
    /// The retained raw wire request, replayed by [`build_prepare_result`] into
    /// the frozen success validator. Excluded from identity (see [`RawEcho`]).
    raw: RawEcho<PrepareOpenV2>,
}

impl PreparedRequest {
    /// The U2K `reply` grant the `PrepareOpenResultV1` write-back targets — the
    /// output buffer [`crate::daemon::Daemon`] writes [`build_prepare_result`]'s
    /// 136 bytes into. Taken from the retained raw wire request (the same grant
    /// the frozen success validator re-checks), never a stored engine record.
    pub fn reply(&self) -> BufferRef {
        self.raw.0.reply
    }

    /// The U2K `result_security_descriptor` grant the prepared descriptor bytes
    /// write-back targets — the output buffer [`crate::daemon::Daemon`] writes
    /// the [`PrepareResult`]`::security_descriptor` into (guarded on a non-empty
    /// descriptor). Taken from the retained raw wire request, mirroring
    /// [`reply`](Self::reply).
    pub fn result_security_descriptor(&self) -> BufferRef {
        self.raw.0.result_security_descriptor
    }

    /// Assemble a decoded prepare request from the raw wire record plus its
    /// single-fetched owned input bytes. The semantic scalar fields are taken
    /// from `raw`; `name` / `requested_security_descriptor` /
    /// `extended_attributes` are the owned K2U copies (`raw` holds only their
    /// grant coordinates). The raw is retained so [`build_prepare_result`] can
    /// re-run the request validator host-side.
    pub fn from_raw(
        raw: PrepareOpenV2,
        name: Box<[u8]>,
        requested_security_descriptor: Option<Box<[u8]>>,
        extended_attributes: Option<Box<[u8]>>,
    ) -> Self {
        Self {
            op_id: raw.op_id,
            parent_id: raw.parent_id,
            desired_access: raw.desired_access,
            share_access: raw.share_access,
            disposition: raw.disposition,
            create_options: raw.create_options,
            file_attributes: raw.file_attributes,
            open_flags: raw.open_flags,
            name,
            requested_security_descriptor,
            extended_attributes,
            raw: RawEcho(raw),
        }
    }
}

/// Decode and ABI-validate the granted `PrepareOpenV2` an SQE's `PControl`
/// points at, into a [`PreparedRequest`]. `owner` is the grant owner the six
/// bindings are validated against (the request's `ReqId`).
pub fn decode_prepare<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<PreparedRequest, OpenBodyError> {
    // 1. The outer PControl points at the slot holding the 192-byte body.
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let body = resolve_body(section, &validated_outer)?;
    let prepare: PrepareOpenV2 =
        try_decode(body.as_slice()).map_err(|_| OpenBodyError::Truncated)?;

    // 2. Bind the six inner grants and run the frozen ABI validator, which owns
    //    every wire rule (op_id nonzero, name-length echo, reply >= 136,
    //    result-SD == 65536, optional SD/EA shape).
    let has_sd = prepare.requested_security_descriptor.kind != buffer_kind::NONE;
    let has_ea = prepare.extended_attributes.kind != buffer_kind::NONE;
    let context = PrepareOpenV2Context {
        name: bind(table, &prepare.name, owner)?,
        requested_security_descriptor: if has_sd {
            Some(bind(table, &prepare.requested_security_descriptor, owner)?)
        } else {
            None
        },
        extended_attributes: if has_ea {
            Some(bind(table, &prepare.extended_attributes, owner)?)
        } else {
            None
        },
        reply: bind(table, &prepare.reply, owner)?,
        result_security_descriptor: bind(table, &prepare.result_security_descriptor, owner)?,
        // These `validated_*_length` fields echo the request's own BufferRef
        // lengths, so the validator's `request.length == validated_length` checks
        // are tautological — the real length authority is `BufferRefPolicy::Exact`
        // inside `validate_bound`, which pins each length to the *issued grant*.
        validated_name_length: prepare.name.length,
        validated_security_descriptor_length: has_sd
            .then_some(prepare.requested_security_descriptor.length),
        validated_ea_length: has_ea.then_some(prepare.extended_attributes.length),
    };
    let validated = validate_prepare_open_v2(&prepare, &context)?;

    // 3. Single-fetch the K2U input bytes into owned copies (the U2K reply /
    //    result-SD are output buffers — validated above, never fetched).
    let name = fetch_owned(section, &validated.name())?;
    let requested_security_descriptor = match validated.requested_security_descriptor() {
        Some(buffer) => Some(fetch_owned(section, &buffer)?),
        None => None,
    };
    let extended_attributes = match validated.extended_attributes() {
        Some(buffer) => Some(fetch_owned(section, &buffer)?),
        None => None,
    };

    Ok(PreparedRequest::from_raw(
        prepare,
        name,
        requested_security_descriptor,
        extended_attributes,
    ))
}

/// A decoded, ABI-validated `COMMIT_OPEN` request. All fields are fixed scalars
/// (`CommitOpenV2` carries no variable input bytes), so no single-fetch is needed
/// beyond the 104-byte body itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitRequest {
    pub op_id: OpId,
    pub transaction_id: TransactionId,
    pub expected_namespace_generation: u64,
    pub expected_security_generation: u64,
    pub kernel_open_id: u64,
    pub granted_access: u32,
    pub commit_flags: u32,
    /// The retained raw wire request, replayed by [`build_commit_result`] into
    /// the frozen success validator. Excluded from identity (see [`RawEcho`]).
    raw: RawEcho<CommitOpenV2>,
}

impl CommitRequest {
    /// The U2K `reply` grant the `CommitOpenResultV2` write-back targets — the
    /// output buffer [`crate::daemon::Daemon`] writes [`build_commit_result`]'s
    /// 112 bytes into. Taken from the retained raw wire request, never a stored
    /// engine record.
    pub fn reply(&self) -> BufferRef {
        self.raw.0.reply
    }

    /// Assemble a decoded commit request from the raw wire record. Every
    /// semantic field is taken from `raw`; the raw is retained so
    /// [`build_commit_result`] can re-run the request validator host-side.
    pub fn from_raw(raw: CommitOpenV2) -> Self {
        Self {
            op_id: raw.op_id,
            transaction_id: raw.transaction_id,
            expected_namespace_generation: raw.expected_namespace_generation,
            expected_security_generation: raw.expected_security_generation,
            kernel_open_id: raw.kernel_open_id,
            granted_access: raw.granted_access,
            commit_flags: raw.commit_flags,
            raw: RawEcho(raw),
        }
    }
}

/// Decode and ABI-validate the granted `CommitOpenV2` an SQE's `PControl` points
/// at, into a [`CommitRequest`].
pub fn decode_commit<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<CommitRequest, OpenBodyError> {
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let body = resolve_body(section, &validated_outer)?;
    let commit: CommitOpenV2 = try_decode(body.as_slice()).map_err(|_| OpenBodyError::Truncated)?;

    // The single reply grant (U2K-W, >= 112) is bound and the frozen ABI
    // validator enforces the reserved/identity/reply rules.
    let reply = bind(table, &commit.reply, owner)?;
    validate_commit_open_v2(&commit, reply)?;

    Ok(CommitRequest::from_raw(commit))
}

/// Build the 112-byte `CommitOpenResultV2` from the committed `effect`,
/// self-validate it host-side via the frozen `validate_commit_open_success_v2`
/// (which re-runs the request validator over the retained `raw` and its reply
/// grant, then checks the result identity/flags/sizes), and return the encoded
/// bytes. Provably total: a bad effect is rejected, never emitted as illegal
/// bytes.
pub fn build_commit_result(
    request: &CommitRequest,
    effect: &CommittedResult,
    table: &GrantTable,
    owner: GrantOwner,
) -> Result<Vec<u8>, OpenResultError> {
    let raw = &request.raw.0;
    let reply = bind(table, &raw.reply, owner)?;
    let output = OControl {
        body: shrunk_echo(&raw.reply, size_of::<CommitOpenResultV2>() as u32),
    };
    let result = CommitOpenResultV2 {
        header: ControlHeader {
            struct_size: size_of::<CommitOpenResultV2>() as u32,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        provider_open_cookie: effect.provider_open_cookie,
        file_id: effect.file_id,
        link_id: effect.link_id,
        sizes: effect.sizes,
        namespace_generation: effect.namespace_generation,
        security_generation: effect.security_generation,
        create_result: effect.create_result,
        result_flags: 0,
        volume_commit_sequence: effect.volume_commit_sequence,
    };
    validate_commit_open_success_v2(raw, reply, &output, &result)
        .map_err(OpenResultError::Message)?;
    Ok(encode_pod(&result))
}

/// Build the 136-byte `PrepareOpenResultV1` from the prepared `effect` and the
/// issued `transaction_id`, self-validate it host-side via the frozen
/// `validate_prepare_open_success_v21` (which re-runs the request validator over
/// the retained `raw` and its rebuilt six-grant context, then checks the result
/// reserved/transaction/sizes and the result-SD shrunk echo), and return the
/// encoded bytes. Provably total.
///
/// `transaction_id` is supplied separately — the lifecycle engine issues it at
/// `prepare` time and neither the effect nor the raw request carries it,
/// mirroring `build_write_result`'s separate `information`.
pub fn build_prepare_result(
    request: &PreparedRequest,
    effect: &PrepareResult,
    transaction_id: TransactionId,
    table: &GrantTable,
    owner: GrantOwner,
) -> Result<Vec<u8>, OpenResultError> {
    let raw = &request.raw.0;
    // Rebuild the six-grant context exactly as `decode_prepare` did — the same
    // grants the re-run request validator will re-check.
    let has_sd = raw.requested_security_descriptor.kind != buffer_kind::NONE;
    let has_ea = raw.extended_attributes.kind != buffer_kind::NONE;
    let context = PrepareOpenV2Context {
        name: bind(table, &raw.name, owner)?,
        requested_security_descriptor: if has_sd {
            Some(bind(table, &raw.requested_security_descriptor, owner)?)
        } else {
            None
        },
        extended_attributes: if has_ea {
            Some(bind(table, &raw.extended_attributes, owner)?)
        } else {
            None
        },
        reply: bind(table, &raw.reply, owner)?,
        result_security_descriptor: bind(table, &raw.result_security_descriptor, owner)?,
        validated_name_length: raw.name.length,
        validated_security_descriptor_length: has_sd
            .then_some(raw.requested_security_descriptor.length),
        validated_ea_length: has_ea.then_some(raw.extended_attributes.length),
    };
    let output = OControl {
        body: shrunk_echo(&raw.reply, size_of::<PrepareOpenResultV1>() as u32),
    };
    // The result-SD grant is echoed at the descriptor's byte length; the actual
    // SD bytes write-back into that U2K grant is the Daemon's job, not here. An
    // SD longer than `u32::MAX` (a >4GB descriptor) is a provider-effect fault,
    // classified rather than silently truncated by an `as` cast.
    let security_descriptor = shrunk_echo(
        &raw.result_security_descriptor,
        u32::try_from(effect.security_descriptor.len())
            .map_err(|_| OpenResultError::Message(MessageValidationError::InvalidScalar))?,
    );
    let result = PrepareOpenResultV1 {
        header: ControlHeader {
            struct_size: size_of::<PrepareOpenResultV1>() as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        transaction_id,
        file_id: effect.file_id,
        link_id: effect.link_id,
        security_descriptor,
        sizes: effect.sizes,
        namespace_generation: effect.namespace_generation,
        security_generation: effect.security_generation,
        object_flags: effect.object_flags,
        reserved: 0,
    };
    validate_prepare_open_success_v21(raw, &context, &output, &result)
        .map_err(OpenResultError::Message)?;
    Ok(encode_pod(&result))
}

/// Build the `COMMIT_OPEN` success completion — an `OControl` echo of the reply
/// grant shrunk to the fixed 112-byte `CommitOpenResultV2` size — and
/// self-validate it against the frozen ABI output matrix before handing it to
/// [`crate::provider::resolve_completion`]. `COMMIT_OPEN` is an exact-
/// information row (112, `None` context).
pub fn build_commit_completion(request: &CommitRequest) -> Result<Completion, OpenResultError> {
    open_completion(
        &request.raw.0.reply,
        op::COMMIT_OPEN,
        size_of::<CommitOpenResultV2>() as u64,
    )
}

/// Build the `PREPARE_OPEN` success completion — an `OControl` echo of the reply
/// grant shrunk to the fixed 136-byte `PrepareOpenResultV1` size — and
/// self-validate it. `PREPARE_OPEN` is an exact-information row (136, `None`
/// context).
pub fn build_prepare_completion(request: &PreparedRequest) -> Result<Completion, OpenResultError> {
    open_completion(
        &request.raw.0.reply,
        op::PREPARE_OPEN,
        size_of::<PrepareOpenResultV1>() as u64,
    )
}

/// The shared body of the two open-lifecycle completions: an `OControl` echo of
/// the `reply` grant shrunk to `information` bytes, self-validated against the
/// frozen `(opcode, SUCCESS, 24, information, None)` matrix row. `out_len`
/// shares the same `size_of::<OControl>()` source of truth as the `OutBuf`.
fn open_completion(
    reply: &BufferRef,
    opcode: u16,
    information: u64,
) -> Result<Completion, OpenResultError> {
    let echo = OControl {
        body: shrunk_echo(reply, information as u32),
    };
    let mut out_bytes = vec![0u8; size_of::<OControl>()];
    try_encode(&echo, &mut out_bytes).expect("OControl is its own size");
    let out = OutBuf::new(&out_bytes).expect("size_of::<OControl>() (24) <= CQE_OUT_LEN");
    validate_completion_output_v21(
        opcode,
        0,
        size_of::<OControl>() as u32,
        information,
        CompletionOutputContextV21::None,
    )
    .map_err(OpenResultError::Message)?;
    Ok(Completion::complete(0, information, out))
}

/// Single-fetch an ABI-validated K2U input buffer into an owned byte box.
fn fetch_owned<S: SharedSection>(
    section: &S,
    buffer: &fsring_abi::slots::ValidatedBuffer,
) -> Result<Box<[u8]>, OpenBodyError> {
    Ok(resolve_body(section, buffer)?
        .as_slice()
        .to_vec()
        .into_boxed_slice())
}

/// Build a `GrantBindingV21` for `bref`'s token, or `UnknownToken`. Returns the
/// raw `GrantError` so either error type (`OpenBodyError` at decode,
/// `OpenResultError` at build) can wrap it via `?`.
fn bind<'a>(
    table: &'a GrantTable,
    bref: &BufferRef,
    owner: GrantOwner,
) -> Result<GrantBindingV21<'a>, GrantError> {
    let grant = table
        .grant_for(bref.token)
        .ok_or(GrantError::UnknownToken)?;
    Ok(GrantBindingV21 {
        grant,
        expected_session_epoch: table.session_epoch(),
        expected_owner: owner,
    })
}

/// A shrunk echo of `grant` (an output `BufferRef` of exactly `length` bytes).
fn shrunk_echo(grant: &BufferRef, length: u32) -> BufferRef {
    BufferRef {
        token: grant.token,
        offset: 0,
        length,
        kind: grant.kind,
        access: grant.access,
        reserved: 0,
    }
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::testkit::{CommitFixture, PrepareFixture};

    #[test]
    fn decodes_a_well_formed_prepare() {
        let fx = PrepareFixture::build();
        let decoded = decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner)
            .expect("well-formed prepare decodes");
        assert_eq!(decoded.op_id.lo, fx.op_id.lo);
        assert_eq!(decoded.op_id.hi, fx.op_id.hi);
        assert_eq!(decoded.name.as_ref(), fx.name_bytes.as_slice());
        assert_eq!(decoded.disposition, fx.disposition);
        assert!(decoded.requested_security_descriptor.is_some());
        assert!(decoded.extended_attributes.is_some());
    }

    #[test]
    fn rejects_short_reply_grant() {
        let fx = PrepareFixture::with_reply_len(100);
        assert!(matches!(
            decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_wrong_result_sd_length() {
        let fx = PrepareFixture::with_result_sd_len(65_535);
        assert!(matches!(
            decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_zero_op_id() {
        let fx = PrepareFixture::with_zero_op_id();
        assert!(matches!(
            decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_unknown_inner_token() {
        let fx = PrepareFixture::with_unknown_name_token();
        assert_eq!(
            decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Grant(GrantError::UnknownToken))
        );
    }

    #[test]
    fn decodes_a_well_formed_commit() {
        let fx = CommitFixture::build();
        let decoded = decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner)
            .expect("well-formed commit decodes");
        assert_eq!(decoded.op_id.lo, fx.op_id.lo);
        assert_eq!(decoded.transaction_id.lo, fx.transaction_id.lo);
        assert_eq!(decoded.kernel_open_id, fx.kernel_open_id);
        assert_eq!(
            decoded.expected_namespace_generation,
            fx.expected_namespace_generation
        );
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let fx = CommitFixture::with_reserved(1);
        assert!(matches!(
            decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_zero_transaction_id() {
        let fx = CommitFixture::with_zero_transaction_id();
        assert!(matches!(
            decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_zero_kernel_open_id() {
        let fx = CommitFixture::with_zero_kernel_open_id();
        assert!(matches!(
            decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_short_commit_reply_grant() {
        let fx = CommitFixture::with_reply_len(100);
        assert!(matches!(
            decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Message(_))
        ));
    }

    #[test]
    fn rejects_unknown_commit_reply_token() {
        let fx = CommitFixture::with_unknown_reply_token();
        assert_eq!(
            decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(OpenBodyError::Grant(GrantError::UnknownToken))
        );
    }

    // --- Task 7: open-lifecycle result encoders + completions ---
    //
    // The frozen success validators re-run the request validators over the
    // retained `raw`, so a well-formed decoded request drives a build that
    // self-validates; a bad provider effect (a value the success validator
    // names) is rejected rather than emitted as illegal bytes.

    use crate::lifecycle::{CommittedResult, PrepareResult};
    use crate::provider::resolve_completion;
    use fsring_abi::ids::LinkId;
    use fsring_abi::msgs::{create_result, SizeState};

    /// A valid `SizeState` (monotone, nonzero epoch).
    fn ok_sizes() -> SizeState {
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        }
    }

    /// A committed effect that passes `validate_commit_open_success_v2`: a
    /// nonzero cookie/volume-commit sequence and an in-registry `create_result`.
    fn committed(create_result: u32) -> CommittedResult {
        CommittedResult {
            provider_open_cookie: 1,
            create_result,
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            volume_commit_sequence: 5,
        }
    }

    /// A prepared effect whose result security descriptor is `sd_len` bytes.
    fn prepared_effect(sd_len: usize) -> PrepareResult {
        PrepareResult {
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            security_descriptor: vec![0u8; sd_len].into_boxed_slice(),
            object_flags: 0,
        }
    }

    /// A nonzero transaction id (`validate_prepare_open_success_v21` requires it).
    const RESULT_TX: TransactionId = TransactionId { lo: 0x22, hi: 0 };

    #[test]
    fn commit_result_builds_and_self_validates() {
        let fx = CommitFixture::build();
        let req = decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let bytes = build_commit_result(
            &req,
            &committed(create_result::CREATED),
            &fx.table,
            fx.owner,
        )
        .expect("commit result builds");
        assert_eq!(bytes.len(), 112);
    }

    #[test]
    fn commit_result_rejects_zero_provider_open_cookie() {
        let fx = CommitFixture::build();
        let req = decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let mut effect = committed(create_result::CREATED);
        effect.provider_open_cookie = 0;
        assert!(matches!(
            build_commit_result(&req, &effect, &fx.table, fx.owner),
            Err(OpenResultError::Message(_))
        ));
    }

    #[test]
    fn commit_result_rejects_zero_volume_commit_sequence() {
        let fx = CommitFixture::build();
        let req = decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let mut effect = committed(create_result::CREATED);
        effect.volume_commit_sequence = 0;
        assert!(matches!(
            build_commit_result(&req, &effect, &fx.table, fx.owner),
            Err(OpenResultError::Message(_))
        ));
    }

    #[test]
    fn commit_result_rejects_out_of_registry_create_result() {
        let fx = CommitFixture::build();
        let req = decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        // 4 = EXISTS, above create_result::OVERWRITTEN(3): a provider-effect fault.
        assert!(matches!(
            build_commit_result(&req, &committed(4), &fx.table, fx.owner),
            Err(OpenResultError::Message(_))
        ));
    }

    #[test]
    fn commit_completion_resolves_with_information_112() {
        let fx = CommitFixture::build();
        let req = decode_commit(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let completion = build_commit_completion(&req).expect("builds");
        let cqe = resolve_completion(&fx.sqe, completion)
            .expect("legal")
            .expect("a completion");
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 112);
    }

    #[test]
    fn prepare_result_builds_and_self_validates() {
        let fx = PrepareFixture::build();
        let req = decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let bytes =
            build_prepare_result(&req, &prepared_effect(20), RESULT_TX, &fx.table, fx.owner)
                .expect("prepare result builds");
        assert_eq!(bytes.len(), 136);
    }

    #[test]
    fn prepare_result_rejects_zero_transaction_id() {
        let fx = PrepareFixture::build();
        let req = decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let zero = TransactionId { lo: 0, hi: 0 };
        assert!(matches!(
            build_prepare_result(&req, &prepared_effect(20), zero, &fx.table, fx.owner),
            Err(OpenResultError::Message(_))
        ));
    }

    #[test]
    fn prepare_result_rejects_bad_size_state() {
        let fx = PrepareFixture::build();
        let req = decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let mut effect = prepared_effect(20);
        effect.sizes.size_epoch = 0; // a zero epoch is an invalid SizeState
        assert!(matches!(
            build_prepare_result(&req, &effect, RESULT_TX, &fx.table, fx.owner),
            Err(OpenResultError::Message(_))
        ));
    }

    #[test]
    fn prepare_result_rejects_short_security_descriptor() {
        let fx = PrepareFixture::build();
        let req = decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        // 19 < the 20-byte security-descriptor floor.
        assert!(matches!(
            build_prepare_result(&req, &prepared_effect(19), RESULT_TX, &fx.table, fx.owner),
            Err(OpenResultError::Message(_))
        ));
    }

    #[test]
    fn prepare_completion_resolves_with_information_136() {
        let fx = PrepareFixture::build();
        let req = decode_prepare(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let completion = build_prepare_completion(&req).expect("builds");
        let cqe = resolve_completion(&fx.sqe, completion)
            .expect("legal")
            .expect("a completion");
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 136);
    }
}
