//! Decode a granted READ/WRITE data-io request, and build + host-validate the
//! WRITE result.
//!
//! READ's `PRw` (80 bytes) travels **inline** in the SQE payload — its fixed
//! record fits the 88-byte `SqeBody` payload directly, so there is no
//! `PControl` indirection to resolve (`decode_read` checks the inline framing
//! itself: `payload_len == size_of::<PRw>()` plus a zero tail, mirroring
//! `control::pcontrol_body_ref`'s wire-shape rule). WRITE's `WriteV2` (112
//! bytes) does not fit inline, so its SQ is a `PControl` whose `body` grant
//! holds the envelope — decoded exactly like `mutation.rs`'s `MutationV2` path:
//! resolve the outer grant, single-fetch the K2U blob, `try_decode` it, bind
//! the two inner grants (`data` K2U, `reply` U2K), and run the frozen
//! `validate_write_v2`.
//!
//! READ's own `data` grant is U2K (an output slot the daemon writes the
//! fetched bytes into later) — never fetched here. WRITE's K2U `data` is
//! single-fetched here (the caller's write bytes); its U2K `reply` grant is
//! validated, never written (that byte write-back is a later slice's job).
//!
//! `build_write_result` builds the 56-byte `WriteResultV2` from a
//! provider-supplied [`WriteEffect`] + `information` (bytes written),
//! self-validates it host-side via `validate_write_success_v2` (reconstructing
//! the `OControl` echo from the request's own `reply` grant), and returns the
//! encoded bytes.

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::ids::OpId;
use fsring_abi::layout::{SqeBody, SQE_PAYLOAD_LEN};
use fsring_abi::msgs::{
    BufferRef, ControlHeader, OControl, PRw, SizeState, WriteResultV2, WriteV2, CONTROL_VERSION_V2,
};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    validate_read_success_v21, validate_read_v21, validate_write_success_v2, validate_write_v2,
    CompletionOutputContextV21, GrantBindingV21, WriteV2Context,
};

use crate::control::{pcontrol_body_ref, ControlBodyError};
use crate::error::{DataIoError, GrantError, WriteResultError};
use crate::grant::{encode_pod, resolve_body, GrantTable};
use crate::provider::{Completion, OutBuf};
use crate::section::SharedSection;

/// A decoded, ABI-validated READ request. `data` is the U2K grant the daemon
/// will later write the fetched bytes into — validated here, but never
/// fetched (a READ's `data` buffer is an output, not caller-supplied input).
///
/// `raw` is the retained wire `PRw` (private), replayed by
/// [`build_read_completion`] into the frozen `validate_read_success_v21`
/// host-side — the same "retain the raw echo" pattern [`WriteRequest`] and
/// [`crate::openbody::PreparedRequest`] use. `PRw` derives no
/// `Debug`/`PartialEq`/`Eq`, so this struct derives only `Clone`/`Copy`.
#[derive(Clone, Copy)]
pub struct ReadRequest {
    pub offset: u64,
    pub length: u32,
    pub data: BufferRef,
    raw: PRw,
}

/// A decoded, ABI-validated WRITE request. `raw` is private so the decoded
/// bytes/reply always agree with the envelope the frozen validator accepted
/// (mirroring `MutationRequest`); `data_bytes` is the single-fetched K2U
/// caller-write payload.
#[derive(Clone)]
pub struct WriteRequest {
    raw: WriteV2,
    data_bytes: Box<[u8]>,
}

impl WriteRequest {
    /// The envelope `op_id` (nonzero — WRITE's identity, unlike READ's zero).
    pub fn op_id(&self) -> OpId {
        self.raw.op_id
    }

    /// The file offset the write starts at.
    pub fn offset(&self) -> u64 {
        self.raw.offset
    }

    /// The write length (equals `data_bytes().len()`).
    pub fn length(&self) -> u32 {
        self.raw.length
    }

    /// The caller's expected pre-write size epoch (nonzero).
    pub fn expected_size_epoch(&self) -> u64 {
        self.raw.expected_size_epoch
    }

    /// The single-fetched K2U caller-write bytes (exactly `length()` bytes).
    pub fn data(&self) -> &[u8] {
        &self.data_bytes
    }

    /// The U2K `reply` grant `build_write_result` echoes.
    pub fn reply(&self) -> BufferRef {
        self.raw.reply
    }
}

/// The provider-supplied committed WRITE effect: the post-write size state and
/// the volume commit sequence (`validate_write_success_v2` requires this
/// nonzero).
#[derive(Clone, Copy)]
pub struct WriteEffect {
    pub sizes: SizeState,
    pub volume_commit_sequence: u64,
}

/// A provider-supplied WRITE outcome: the exact committed byte count together
/// with the post-write effect used to build the wire result.
#[derive(Clone, Copy)]
pub struct WriteOutcome {
    pub information: u32,
    pub effect: WriteEffect,
}

/// Decode and ABI-validate the inline `PRw` an SQE's payload carries directly
/// (READ never travels behind a `PControl` indirection).
pub fn decode_read(
    sqe: &SqeBody,
    table: &GrantTable,
    owner: GrantOwner,
) -> Result<ReadRequest, DataIoError> {
    // READ's PRw (80 bytes) travels inline — the whole payload is the record,
    // with the untouched SQE payload tail beyond it required to be zero
    // (mirroring `control::pcontrol_body_ref`'s own wire-shape rule).
    let prw_len = core::mem::size_of::<PRw>();
    if sqe.payload_len as usize != prw_len {
        return Err(DataIoError::Control(ControlBodyError::WrongLength));
    }
    if sqe.payload[prw_len..SQE_PAYLOAD_LEN]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(DataIoError::Control(ControlBodyError::NonZeroTail));
    }
    // An exactly-80-byte slice is exactly `PRw`'s size, so `try_decode` cannot
    // truncate here (the `payload_len == prw_len` check above guarantees it).
    let raw: PRw =
        try_decode(&sqe.payload[..prw_len]).expect("an 80-byte slice is exactly PRw's size");

    // The data grant is U2K_WRITE: an output slot the daemon writes the
    // fetched bytes into later, so only its binding is validated, never
    // fetched.
    let data_binding = grant_binding(table, &raw.data, owner)?;
    validate_read_v21(&raw, data_binding)?;

    Ok(ReadRequest {
        offset: raw.offset,
        length: raw.length,
        data: raw.data,
        raw,
    })
}

/// Decode and ABI-validate the granted `WriteV2` an SQE's `PControl` points
/// at, single-fetching the K2U `data` grant's caller-write bytes.
pub fn decode_write<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
) -> Result<WriteRequest, DataIoError> {
    // 1. The outer PControl points at the 112-byte WriteV2 envelope.
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let blob = resolve_body(section, &validated_outer)?;
    let raw: WriteV2 = try_decode(blob.as_slice()).map_err(|_| DataIoError::Truncated)?;

    // 2. Bind the two inner grants and run the frozen envelope validator.
    let context = WriteV2Context {
        data: grant_binding(table, &raw.data, owner)?,
        reply: grant_binding(table, &raw.reply, owner)?,
    };
    let validated = validate_write_v2(&raw, &context)?;

    // 3. Single-fetch the K2U data grant (reusing the buffer the envelope
    //    validator already proved) — the caller's write bytes. The U2K reply
    //    grant is only retained (as `raw.reply`), never fetched here.
    let data_blob = resolve_body(section, &validated.data())?;

    Ok(WriteRequest {
        raw,
        data_bytes: data_blob.as_slice().to_vec().into_boxed_slice(),
    })
}

/// Build the `WriteResultV2` from `effect` + `information` (bytes written),
/// self-validate it host-side via `validate_write_success_v2` (reconstructing
/// the `OControl` echo from `request`'s own `reply` grant), and return the
/// encoded bytes.
pub fn build_write_result(
    request: &WriteRequest,
    effect: &WriteEffect,
    information: u64,
    table: &GrantTable,
    owner: GrantOwner,
) -> Result<Vec<u8>, WriteResultError> {
    // Rebuild the context (grant bindings) from the request's own grant refs.
    let context = WriteV2Context {
        data: grant_binding(table, &request.raw.data, owner)?,
        reply: grant_binding(table, &request.raw.reply, owner)?,
    };
    let result = WriteResultV2 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        sizes: effect.sizes,
        volume_commit_sequence: effect.volume_commit_sequence,
        flags: 0,
        reserved: 0,
    };
    let output = OControl {
        body: shrunk_echo(&request.raw.reply, 56),
    };

    validate_write_success_v2(&request.raw, &context, &output, information, &result)
        .map_err(WriteResultError::Message)?;

    Ok(encode_pod(&result))
}

/// Build the READ success completion for `information` fetched bytes and
/// self-validate it host-side via the frozen `validate_read_success_v21` — which
/// re-runs `validate_read_v21` over the retained raw `PRw` + its data grant,
/// checks the transferred count against the request length, and checks the
/// shrunk `OControl` output echo — before returning the [`Completion`] the
/// daemon posts. Mirrors how [`build_write_result`] self-validates the WRITE
/// echo. The caller establishes `information > 0` (the zero-byte read is the EOF
/// path); the frozen `validate_information` rejects a zero `information` as a
/// backstop.
pub fn build_read_completion(
    request: &ReadRequest,
    information: u64,
    table: &GrantTable,
    owner: GrantOwner,
) -> Result<Completion, DataIoError> {
    let data_binding = grant_binding(table, &request.raw.data, owner)?;
    let output = OControl {
        body: shrunk_echo(&request.raw.data, information as u32),
    };
    validate_read_success_v21(&request.raw, data_binding, &output, information)?;

    let mut out_bytes = vec![0u8; core::mem::size_of::<OControl>()];
    try_encode(&output, &mut out_bytes).expect("OControl encodes into its own size");
    let out = OutBuf::new(&out_bytes).expect("size_of::<OControl>() (24) <= CQE_OUT_LEN");
    Ok(Completion::complete_with(
        0,
        information,
        out,
        CompletionOutputContextV21::RequestLength(request.length),
    ))
}

/// Build a `GrantBindingV21` for `bref`'s token, or `UnknownToken`.
fn grant_binding<'a>(
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
    use crate::testkit::{ReadFixture, WriteFixture};

    #[test]
    fn decode_read_accepts_a_valid_inline_prw() {
        let fx = ReadFixture::valid();
        let req = decode_read(&fx.sqe, &fx.table, fx.owner).expect("decode");
        assert_eq!(req.offset, 0);
        assert_eq!(req.length, 4096);
        assert_eq!(req.data.length, 4096);
    }

    #[test]
    fn decode_read_rejects_nonzero_op_id() {
        let fx = ReadFixture::with_nonzero_op_id();
        assert!(matches!(
            decode_read(&fx.sqe, &fx.table, fx.owner),
            Err(DataIoError::Message(_))
        ));
    }

    #[test]
    fn decode_read_rejects_length_mismatch() {
        let fx = ReadFixture::with_length_mismatch();
        assert!(matches!(
            decode_read(&fx.sqe, &fx.table, fx.owner),
            Err(DataIoError::Message(_))
        ));
    }

    #[test]
    fn decode_read_rejects_bad_inline_payload_len() {
        // `payload_len != size_of::<PRw>()` (80) fails the inline-PRw framing
        // check before any decode — the `DataIoError::Control(WrongLength)` path.
        let fx = ReadFixture::with_bad_payload_len(79);
        assert!(matches!(
            decode_read(&fx.sqe, &fx.table, fx.owner),
            Err(DataIoError::Control(ControlBodyError::WrongLength))
        ));
    }

    #[test]
    fn decode_read_rejects_nonzero_inline_tail() {
        // A nonzero byte past the inline `PRw` (in `[80..88]`) fails the zero-tail
        // framing check — the `DataIoError::Control(NonZeroTail)` path.
        let fx = ReadFixture::with_nonzero_tail();
        assert!(matches!(
            decode_read(&fx.sqe, &fx.table, fx.owner),
            Err(DataIoError::Control(ControlBodyError::NonZeroTail))
        ));
    }

    #[test]
    fn decode_write_accepts_a_valid_writev2_and_fetches_the_data() {
        let fx = WriteFixture::valid();
        let req = decode_write(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        assert_eq!(req.data(), fx.data_bytes.as_slice());
        assert_eq!(req.reply().length, 56);
        assert_eq!(req.length(), fx.data_bytes.len() as u32);
    }

    #[test]
    fn decode_write_rejects_zero_op_id() {
        let fx = WriteFixture::with_zero_op_id();
        assert!(matches!(
            decode_write(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(DataIoError::Message(_))
        ));
    }

    #[test]
    fn decode_write_rejects_zero_expected_size_epoch() {
        let fx = WriteFixture::with_zero_expected_size_epoch();
        assert!(matches!(
            decode_write(&fx.sqe, &fx.table, fx.section(), fx.owner),
            Err(DataIoError::Message(_))
        ));
    }

    /// A `WriteEffect` covering the fixture's write (`offset 0 + information
    /// 4096 <= file_size == valid_data_length == 4096`).
    fn valid_effect() -> WriteEffect {
        WriteEffect {
            sizes: SizeState {
                allocation_size: 8192,
                file_size: 4096,
                valid_data_length: 4096,
                size_epoch: 2,
            },
            volume_commit_sequence: 5,
        }
    }

    #[test]
    fn build_write_result_builds_and_validates() {
        let fx = WriteFixture::valid();
        let req = decode_write(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let bytes = build_write_result(&req, &valid_effect(), 4096, &fx.table, fx.owner)
            .expect("result builds");
        assert_eq!(bytes.len(), 56);
    }

    #[test]
    fn build_write_result_rejects_zero_volume_commit_sequence() {
        let fx = WriteFixture::valid();
        let req = decode_write(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let mut effect = valid_effect();
        effect.volume_commit_sequence = 0;
        assert!(matches!(
            build_write_result(&req, &effect, 4096, &fx.table, fx.owner),
            Err(WriteResultError::Message(_))
        ));
    }

    #[test]
    fn build_write_result_rejects_coverage_past_file_size() {
        let fx = WriteFixture::valid();
        let req = decode_write(&fx.sqe, &fx.table, fx.section(), fx.owner).expect("decode");
        let mut effect = valid_effect();
        // file_size/valid_data_length (2048) < offset(0) + information(4096)
        // -> a write-coverage relationship fault.
        effect.sizes.file_size = 2048;
        effect.sizes.valid_data_length = 2048;
        assert!(matches!(
            build_write_result(&req, &effect, 4096, &fx.table, fx.owner),
            Err(WriteResultError::Message(_))
        ));
    }
}
