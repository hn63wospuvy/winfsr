//! Decode a granted `MutationV2` namespace mutation and build + host-validate
//! its result.
//!
//! `SET_INFORMATION`'s SQ is a `PControl` → a K2U control body holding a
//! `MutationV2` envelope, which names three inner grants: `body` (K2U, the kind
//! body), `reply` (U2K, the 112-byte `MutationResultV2` echo), and `kind_result`
//! (U2K, the `Rename`/`Link`/`Unlink` result). C2 decodes the envelope +
//! rename/link/unlink body via the frozen request validators, then builds the
//! result from a provider effect and validates it host-side by constructing the
//! `OControl` echo from the known reply grant. Non-namespace kinds are
//! out of scope. Only the K2U bodies are single-fetched; the U2K grants are
//! validated, never written here (that byte write-back is E's).

use fsring_abi::codec::{try_decode, try_encode};
use fsring_abi::ids::{FileId, LinkId, OpId};
use fsring_abi::layout::{op, SqeBody};
use fsring_abi::msgs::{
    buffer_kind, mutation_kind, BufferRef, ControlHeader, LinkResultV2, LinkV1, MutationResultV2,
    MutationV2, OControl, RenameResultV2, RenameV1, SetBasicInfoV1, SetSecurityV1, SetSizeV1,
    SizeState, UnlinkResultV1, UnlinkV1, CONTROL_VERSION_V1, CONTROL_VERSION_V2,
};
use fsring_abi::slots::{BufferRefPolicy, GrantOwner};
use fsring_abi::validate::{
    validate_completion_output_v21, validate_mutation_body_v21, validate_mutation_success_v2,
    validate_mutation_v2, CompletionOutputContextV21, GrantBindingV21, MutationBodyRefV21,
    MutationKindResultRefV21, MutationV2Context,
};

use crate::control::pcontrol_body_ref;
use crate::error::{GrantError, MutationError, MutationResultError};
use crate::filesystem::MutationContext;
use crate::grant::{encode_pod, resolve_body, GrantTable};
use crate::provider::{Completion, OutBuf};
use crate::section::SharedSection;

/// The decoded namespace-mutation body: the raw wire record (kept for the result
/// validator's cross-checks) plus, for RENAME/LINK, the owned name bytes.
#[derive(Clone)]
pub enum DecodedBody {
    SetBasicInfo {
        raw: SetBasicInfoV1,
    },
    SetAllocationSize {
        raw: SetSizeV1,
    },
    SetEndOfFile {
        raw: SetSizeV1,
    },
    SetValidDataLength {
        raw: SetSizeV1,
    },
    Rename {
        raw: RenameV1,
        name: Box<[u8]>,
    },
    Link {
        raw: LinkV1,
        name: Box<[u8]>,
    },
    Unlink {
        raw: UnlinkV1,
    },
    SetSecurity {
        raw: SetSecurityV1,
        descriptor: Box<[u8]>,
    },
}

/// A decoded, ABI-validated namespace-mutation request. `body` is private so the
/// decoded body always agrees with the envelope `mutation_kind` (the value stays
/// the internally-consistent one the validators accepted).
#[derive(Clone)]
pub struct MutationRequest {
    raw: MutationV2,
    kernel_open_id: u64,
    same_parent_rename: bool,
    body: DecodedBody,
    body_bytes: Box<[u8]>,
    #[cfg(test)]
    body_fetch_count: u8,
}

impl MutationRequest {
    /// The envelope `op_id`.
    pub fn op_id(&self) -> OpId {
        self.raw.op_id
    }

    /// The retained kernel-open identity from the SQE carrying this mutation.
    ///
    /// This is captured by [`decode_mutation`] together with the granted
    /// envelope so a real provider can target the exact retained handle
    /// without accepting a separately supplied, potentially divergent value.
    pub fn kernel_open_id(&self) -> u64 {
        self.kernel_open_id
    }

    /// The `mutation_kind` (`RENAME`/`LINK`/`UNLINK`).
    pub fn mutation_kind(&self) -> u16 {
        self.raw.mutation_kind
    }

    pub fn expected_namespace_generation(&self) -> u64 {
        self.raw.expected_namespace_generation
    }

    pub fn expected_size_epoch(&self) -> u64 {
        self.raw.expected_size_epoch
    }

    pub fn expected_security_generation(&self) -> u64 {
        self.raw.expected_security_generation
    }

    pub fn same_parent_rename(&self) -> bool {
        self.same_parent_rename
    }

    /// The decoded rename/link/unlink body.
    pub fn body(&self) -> &DecodedBody {
        &self.body
    }

    /// The envelope's U2K `reply` grant — the 112-byte `MutationResultV2`
    /// write-back target the Daemon writes `build_mutation_result`'s `result`
    /// bytes into.
    pub fn reply(&self) -> BufferRef {
        self.raw.reply
    }

    /// The envelope's U2K `kind_result` grant — the rename/link/unlink
    /// write-back target the Daemon writes `build_mutation_result`'s
    /// `kind_result` bytes into. A `buffer_kind::NONE` ref for a kind without a
    /// kind result (basic_info/size/security).
    pub fn kind_result(&self) -> BufferRef {
        self.raw.kind_result
    }
}

/// Decode and ABI-validate the granted `MutationV2` an SQE's `PControl` points
/// at. `same_parent_rename` is a caller-supplied hint (from the backing state)
/// for the RENAME body/result validation.
pub fn decode_mutation<S: SharedSection>(
    sqe: &SqeBody,
    table: &GrantTable,
    section: &S,
    owner: GrantOwner,
    same_parent_rename: bool,
) -> Result<MutationRequest, MutationError> {
    // 1. The outer PControl points at the 128-byte MutationV2 envelope.
    let outer = pcontrol_body_ref(sqe)?;
    let validated_outer = table.resolve(&outer, owner, BufferRefPolicy::Exact)?;
    let env_blob = resolve_body(section, &validated_outer)?;
    let raw: MutationV2 = try_decode(env_blob.as_slice()).map_err(|_| MutationError::Truncated)?;

    // 2. Bind the three inner grants and run the frozen envelope validator (the
    //    kind_result binding is None for a kind without a kind result).
    let context = MutationV2Context {
        body: grant_binding(table, &raw.body, owner).map_err(MutationError::Grant)?,
        reply: grant_binding(table, &raw.reply, owner).map_err(MutationError::Grant)?,
        kind_result: kind_result_binding(table, &raw.kind_result, owner)
            .map_err(MutationError::Grant)?,
        reparse_selected: false,
        same_parent_rename,
    };
    let validated = validate_mutation_v2(&raw, &context)?;

    // 3. Single-fetch the body grant (reusing the buffer the envelope validator
    //    already proved) and validate + decode the namespace body. Any other
    //    (valid) kind is out of this slice's scope.
    let body_blob = resolve_body(section, &validated.body())?;
    let body_bytes = body_blob.as_slice().to_vec().into_boxed_slice();
    let blob = body_bytes.as_ref();
    let body = match raw.mutation_kind {
        mutation_kind::SET_BASIC_INFO => {
            let record: SetBasicInfoV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::SET_BASIC_INFO,
                MutationBodyRefV21::SetBasicInfo(&record),
                blob,
                same_parent_rename,
            )?;
            DecodedBody::SetBasicInfo { raw: record }
        }
        mutation_kind::SET_ALLOCATION_SIZE => {
            let record: SetSizeV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::SET_ALLOCATION_SIZE,
                MutationBodyRefV21::SetAllocationSize(&record),
                blob,
                same_parent_rename,
            )?;
            DecodedBody::SetAllocationSize { raw: record }
        }
        mutation_kind::SET_END_OF_FILE => {
            let record: SetSizeV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::SET_END_OF_FILE,
                MutationBodyRefV21::SetEndOfFile(&record),
                blob,
                same_parent_rename,
            )?;
            DecodedBody::SetEndOfFile { raw: record }
        }
        mutation_kind::SET_VALID_DATA_LENGTH => {
            let record: SetSizeV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::SET_VALID_DATA_LENGTH,
                MutationBodyRefV21::SetValidDataLength(&record),
                blob,
                same_parent_rename,
            )?;
            DecodedBody::SetValidDataLength { raw: record }
        }
        mutation_kind::RENAME => {
            let record: RenameV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::RENAME,
                MutationBodyRefV21::Rename(&record),
                blob,
                same_parent_rename,
            )?;
            let name = owned_name(blob, 72, record.name.length);
            DecodedBody::Rename { raw: record, name }
        }
        mutation_kind::LINK => {
            let record: LinkV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::LINK,
                MutationBodyRefV21::Link(&record),
                blob,
                same_parent_rename,
            )?;
            let name = owned_name(blob, 64, record.name.length);
            DecodedBody::Link { raw: record, name }
        }
        mutation_kind::UNLINK => {
            let record: UnlinkV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::UNLINK,
                MutationBodyRefV21::Unlink(&record),
                blob,
                same_parent_rename,
            )?;
            DecodedBody::Unlink { raw: record }
        }
        mutation_kind::SET_SECURITY => {
            let record: SetSecurityV1 = try_decode(blob).map_err(|_| MutationError::Truncated)?;
            validate_mutation_body_v21(
                mutation_kind::SET_SECURITY,
                MutationBodyRefV21::SetSecurity(&record),
                blob,
                same_parent_rename,
            )?;
            // The descriptor tail is at [24 .. 24+length], bounds already proven
            // by the validator; reuse owned_name for the single-fetch copy.
            let descriptor = owned_name(blob, 24, record.security_descriptor.length);
            DecodedBody::SetSecurity {
                raw: record,
                descriptor,
            }
        }
        other => return Err(MutationError::NotInScope { kind: other }),
    };

    Ok(MutationRequest {
        raw,
        kernel_open_id: sqe.kernel_open_id,
        same_parent_rename,
        body,
        body_bytes,
        #[cfg(test)]
        body_fetch_count: 1,
    })
}

/// Re-run both frozen mutation validators against the retained grant refs and
/// owned body bytes using provider-supplied backing-state context.
pub fn revalidate_context(
    mut request: MutationRequest,
    table: &GrantTable,
    owner: GrantOwner,
    context: MutationContext,
) -> Result<MutationRequest, MutationError> {
    let validation_context = MutationV2Context {
        body: grant_binding(table, &request.raw.body, owner).map_err(MutationError::Grant)?,
        reply: grant_binding(table, &request.raw.reply, owner).map_err(MutationError::Grant)?,
        kind_result: kind_result_binding(table, &request.raw.kind_result, owner)
            .map_err(MutationError::Grant)?,
        reparse_selected: false,
        same_parent_rename: context.same_parent_rename,
    };
    validate_mutation_v2(&request.raw, &validation_context)?;

    let body = match &request.body {
        DecodedBody::SetBasicInfo { raw } => MutationBodyRefV21::SetBasicInfo(raw),
        DecodedBody::SetAllocationSize { raw } => MutationBodyRefV21::SetAllocationSize(raw),
        DecodedBody::SetEndOfFile { raw } => MutationBodyRefV21::SetEndOfFile(raw),
        DecodedBody::SetValidDataLength { raw } => MutationBodyRefV21::SetValidDataLength(raw),
        DecodedBody::Rename { raw, .. } => MutationBodyRefV21::Rename(raw),
        DecodedBody::Link { raw, .. } => MutationBodyRefV21::Link(raw),
        DecodedBody::Unlink { raw } => MutationBodyRefV21::Unlink(raw),
        DecodedBody::SetSecurity { raw, .. } => MutationBodyRefV21::SetSecurity(raw),
    };
    validate_mutation_body_v21(
        request.raw.mutation_kind,
        body,
        &request.body_bytes,
        context.same_parent_rename,
    )?;
    request.same_parent_rename = context.same_parent_rename;
    Ok(request)
}

/// A replacement identity a rename/link committed over (all fields nonzero, or
/// the tuple is absent). `link_count` may be zero.
#[derive(Clone, Copy)]
pub struct Replaced {
    pub file_id: FileId,
    pub link_id: LinkId,
    pub namespace_generation: u64,
    pub link_count: u32,
}

/// The provider-supplied committed namespace effect the backing filesystem
/// produced. `build_mutation_result` reads the fields relevant to the request's
/// kind (RENAME preserves the body `source_link_id`; UNLINK's removed id is the
/// body `link_id`; LINK's new id is `new_link_id`).
#[derive(Clone, Copy)]
pub struct MutationEffect {
    pub file_id: FileId,
    pub new_link_id: LinkId,
    pub replaced: Option<Replaced>,
    pub link_count: u32,
    pub namespace_generation: u64,
    pub source_parent_generation: u64,
    pub target_parent_generation: u64,
    pub parent_generation: u64,
    pub sizes: SizeState,
    pub retained_sizes: SizeState,
    pub volume_commit_sequence: u64,
    pub security_generation: u64,
}

/// The two owned result buffers a caller (E) copies into the `reply` /
/// `kind_result` U2K grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationResultBytes {
    pub result: Vec<u8>,
    pub kind_result: Vec<u8>,
}

/// Build the `MutationResultV2` + kind result from `effect`, validate it
/// host-side via `validate_mutation_success_v2` (constructing the `OControl`
/// echo from the reply grant), and return the encoded bytes.
pub fn build_mutation_result(
    request: &MutationRequest,
    effect: &MutationEffect,
    table: &GrantTable,
    owner: GrantOwner,
) -> Result<MutationResultBytes, MutationResultError> {
    // Rebuild the context (grant bindings) from the request's grant refs.
    let context = MutationV2Context {
        body: grant_binding(table, &request.raw.body, owner)?,
        reply: grant_binding(table, &request.raw.reply, owner)?,
        kind_result: kind_result_binding(table, &request.raw.kind_result, owner)?,
        reparse_selected: false,
        same_parent_rename: request.same_parent_rename,
    };
    // The result identity fields differ by kind's generation lane:
    // rename/link/unlink/set_basic_info carry the namespace generation; the
    // three size kinds carry neither (both lanes zero); set_security carries
    // the security generation (and passes namespace_generation through
    // unchanged rather than hard-zeroing it, so a provider effect that
    // mistakenly sets it nonzero is still caught by the ABI success validator's
    // "namespace_generation must be zero for this kind" check below, instead of
    // being silently swallowed here).
    let (namespace_generation, security_generation) = match &request.body {
        DecodedBody::Rename { .. }
        | DecodedBody::Link { .. }
        | DecodedBody::Unlink { .. }
        | DecodedBody::SetBasicInfo { .. } => (effect.namespace_generation, 0),
        DecodedBody::SetAllocationSize { .. }
        | DecodedBody::SetEndOfFile { .. }
        | DecodedBody::SetValidDataLength { .. } => (0, 0),
        DecodedBody::SetSecurity { .. } => {
            (effect.namespace_generation, effect.security_generation)
        }
    };
    // kind_result: a real shrunk echo for rename/link/unlink; the NONE ref for a
    // kind without a kind result.
    let kind_result = match &request.body {
        DecodedBody::Rename { .. } => shrunk_echo(&request.raw.kind_result, 112),
        DecodedBody::Link { .. } => shrunk_echo(&request.raw.kind_result, 104),
        DecodedBody::Unlink { .. } => shrunk_echo(&request.raw.kind_result, 56),
        DecodedBody::SetBasicInfo { .. }
        | DecodedBody::SetAllocationSize { .. }
        | DecodedBody::SetEndOfFile { .. }
        | DecodedBody::SetValidDataLength { .. }
        | DecodedBody::SetSecurity { .. } => none_ref(),
    };
    let result = MutationResultV2 {
        header: ControlHeader {
            struct_size: 112,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        op_id: request.raw.op_id,
        volume_commit_sequence: effect.volume_commit_sequence,
        mutation_kind: request.raw.mutation_kind,
        result_flags: 0,
        reserved: 0,
        sizes: effect.sizes,
        namespace_generation,
        security_generation,
        kind_result,
    };
    let output = OControl {
        body: shrunk_echo(&request.raw.reply, 112),
    };

    // Build the kind record, validate the full result host-side, and encode.
    let kind_result_bytes = match &request.body {
        DecodedBody::Rename { raw, .. } => {
            let record = build_rename_result(raw, effect);
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::Rename(raw),
                &output,
                &result,
                MutationKindResultRefV21::Rename(&record),
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            encode_pod(&record)
        }
        DecodedBody::Link { raw, .. } => {
            let record = build_link_result(effect);
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::Link(raw),
                &output,
                &result,
                MutationKindResultRefV21::Link(&record),
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            encode_pod(&record)
        }
        DecodedBody::Unlink { raw } => {
            let record = build_unlink_result(raw, effect);
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::Unlink(raw),
                &output,
                &result,
                MutationKindResultRefV21::Unlink(&record),
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            encode_pod(&record)
        }
        // The metadata/size kinds carry no kind result: the frozen validator
        // just needs the NONE ref (already built above) plus the matching body.
        DecodedBody::SetBasicInfo { raw } => {
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::SetBasicInfo(raw),
                &output,
                &result,
                MutationKindResultRefV21::None,
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            Vec::new()
        }
        DecodedBody::SetAllocationSize { raw } => {
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::SetAllocationSize(raw),
                &output,
                &result,
                MutationKindResultRefV21::None,
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            Vec::new()
        }
        DecodedBody::SetEndOfFile { raw } => {
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::SetEndOfFile(raw),
                &output,
                &result,
                MutationKindResultRefV21::None,
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            Vec::new()
        }
        DecodedBody::SetValidDataLength { raw } => {
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::SetValidDataLength(raw),
                &output,
                &result,
                MutationKindResultRefV21::None,
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            Vec::new()
        }
        DecodedBody::SetSecurity { raw, .. } => {
            validate_mutation_success_v2(
                &request.raw,
                &context,
                MutationBodyRefV21::SetSecurity(raw),
                &output,
                &result,
                MutationKindResultRefV21::None,
                effect.retained_sizes,
            )
            .map_err(MutationResultError::Message)?;
            Vec::new()
        }
    };

    Ok(MutationResultBytes {
        result: encode_pod(&result),
        kind_result: kind_result_bytes,
    })
}

/// Build the `MUTATE` success completion, and self-validate it against the
/// frozen ABI output matrix (`validate_completion_output_v21`) before handing
/// it to [`crate::provider::resolve_completion`].
///
/// `MUTATE` is an exact-information row (112, `None` context): the 24-byte
/// output is an `OControl` echo of the request's `reply` grant shrunk to the
/// fixed 112-byte `MutationResultV2` size — `build_mutation_result` already
/// produced those bytes for the Daemon to write into `reply()`; this reports
/// that the full 112 bytes are valid.
pub fn build_mutate_completion(
    request: &MutationRequest,
) -> Result<Completion, MutationResultError> {
    let echo = OControl {
        body: shrunk_echo(&request.raw.reply, 112),
    };
    let mut out_bytes = vec![0u8; core::mem::size_of::<OControl>()];
    try_encode(&echo, &mut out_bytes).expect("OControl is its own size");
    let out = OutBuf::new(&out_bytes).expect("size_of::<OControl>() (24) <= CQE_OUT_LEN");
    let context = CompletionOutputContextV21::None;

    validate_completion_output_v21(
        op::MUTATE,
        0,
        core::mem::size_of::<OControl>() as u32,
        112,
        context,
    )
    .map_err(MutationResultError::Message)?;

    Ok(Completion::complete(0, 112, out))
}

/// Build a `GrantBindingV21` for `bref`'s token, or `UnknownToken`. Returns the
/// raw `GrantError` so either error type (`MutationError`/`MutationResultError`)
/// can wrap it.
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

/// The `kind_result` grant binding: `None` when the request carries a `NONE`
/// reference (a kind without a kind result), else a real binding.
fn kind_result_binding<'a>(
    table: &'a GrantTable,
    bref: &BufferRef,
    owner: GrantOwner,
) -> Result<Option<GrantBindingV21<'a>>, GrantError> {
    if bref.kind == buffer_kind::NONE {
        Ok(None)
    } else {
        Ok(Some(grant_binding(table, bref, owner)?))
    }
}

/// The `NONE` `BufferRef` (a kind result the request never granted).
fn none_ref() -> BufferRef {
    BufferRef {
        token: 0,
        offset: 0,
        length: 0,
        kind: buffer_kind::NONE,
        access: 0,
        reserved: 0,
    }
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

/// Build the `RenameResultV2` kind record from the body (link id preserved) + the
/// effect (replacement tuple all-zero when absent).
fn build_rename_result(body: &RenameV1, effect: &MutationEffect) -> RenameResultV2 {
    let (replaced_file_id, replaced_link_id, replaced_namespace_generation, replaced_link_count) =
        match effect.replaced {
            Some(r) => (r.file_id, r.link_id, r.namespace_generation, r.link_count),
            None => (FileId { lo: 0, hi: 0 }, LinkId { lo: 0, hi: 0 }, 0, 0),
        };
    RenameResultV2 {
        header: ControlHeader {
            struct_size: 112,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        file_id: effect.file_id,
        link_id: body.source_link_id,
        replaced_file_id,
        replaced_link_id,
        source_parent_generation: effect.source_parent_generation,
        target_parent_generation: effect.target_parent_generation,
        replaced_namespace_generation,
        link_count: effect.link_count,
        replaced_link_count,
        flags: 0,
        reserved: 0,
    }
}

/// Build the `LinkResultV2` from the effect (a new nonzero `new_link_id`;
/// replacement tuple all-zero when absent).
fn build_link_result(effect: &MutationEffect) -> LinkResultV2 {
    let (replaced_file_id, replaced_link_id, replaced_namespace_generation, replaced_link_count) =
        match effect.replaced {
            Some(r) => (r.file_id, r.link_id, r.namespace_generation, r.link_count),
            None => (FileId { lo: 0, hi: 0 }, LinkId { lo: 0, hi: 0 }, 0, 0),
        };
    LinkResultV2 {
        header: ControlHeader {
            struct_size: 104,
            struct_version: CONTROL_VERSION_V2,
            required_flags: 0,
        },
        file_id: effect.file_id,
        new_link_id: effect.new_link_id,
        replaced_file_id,
        replaced_link_id,
        target_parent_generation: effect.target_parent_generation,
        replaced_namespace_generation,
        link_count: effect.link_count,
        replaced_link_count,
        flags: 0,
        reserved: 0,
    }
}

/// Build the `UnlinkResultV1` (V1 header, no replacement) — the removed link id is
/// the body's `link_id`.
fn build_unlink_result(body: &UnlinkV1, effect: &MutationEffect) -> UnlinkResultV1 {
    UnlinkResultV1 {
        header: ControlHeader {
            struct_size: 56,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        file_id: effect.file_id,
        removed_link_id: body.link_id,
        parent_generation: effect.parent_generation,
        remaining_link_count: effect.link_count,
        flags: 0,
    }
}

/// Copy `blob[offset..offset+length]` into an owned box (a body name).
fn owned_name(blob: &[u8], offset: usize, length: u32) -> Box<[u8]> {
    blob[offset..offset + length as usize]
        .to_vec()
        .into_boxed_slice()
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::*;
    use crate::provider::resolve_completion;
    use crate::testkit::MutationFixture;
    use fsring_abi::msgs::BlobSlice;

    #[test]
    fn decodes_rename() {
        let fx = MutationFixture::rename();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        assert_eq!(req.mutation_kind(), mutation_kind::RENAME);
        assert!(matches!(req.body(), DecodedBody::Rename { .. }));
    }

    #[test]
    fn mutation_context_revalidation_keeps_the_single_body_fetch() {
        let fx = MutationFixture::rename();
        let request =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        assert_eq!(request.body_fetch_count, 1);

        let request = revalidate_context(
            request,
            &fx.table,
            fx.owner,
            MutationContext {
                same_parent_rename: true,
            },
        )
        .expect("revalidate retained body");
        assert_eq!(request.body_fetch_count, 1);
    }

    #[test]
    fn every_supported_mutation_retains_the_exact_kernel_open_id_through_revalidation() {
        let fixtures = [
            MutationFixture::set_basic_info(),
            MutationFixture::set_allocation_size(),
            MutationFixture::set_end_of_file(),
            MutationFixture::set_valid_data_length(),
            MutationFixture::rename(),
            MutationFixture::link(),
            MutationFixture::unlink(),
            MutationFixture::set_security(),
        ];
        for (index, mut fixture) in fixtures.into_iter().enumerate() {
            let kernel_open_id = 0xE200_u64 + index as u64;
            fixture.sqe.kernel_open_id = kernel_open_id;
            let request = decode_mutation(
                &fixture.sqe,
                &fixture.table,
                fixture.section(),
                fixture.owner,
                false,
            )
            .expect("public decoder accepts supported mutation");
            assert_eq!(request.kernel_open_id(), kernel_open_id);
            let request = revalidate_context(
                request,
                &fixture.table,
                fixture.owner,
                MutationContext::default(),
            )
            .expect("revalidate retained mutation");
            assert_eq!(request.kernel_open_id(), kernel_open_id);
        }
    }

    #[test]
    fn reply_and_kind_result_accessors_match_the_fixture() {
        // The rename fixture issues a real (non-NONE) 112-byte reply grant and
        // a real 112-byte kind_result grant; the accessors must return the
        // exact refs the table issued, not a stale or reconstructed copy.
        let fx = MutationFixture::rename();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");

        let reply_grant = fx
            .table
            .grant_for(req.reply().token)
            .expect("reply grant")
            .issued;
        assert_eq!(req.reply(), reply_grant);
        assert_eq!(req.reply().length, 112);

        let kind_result_grant = fx
            .table
            .grant_for(req.kind_result().token)
            .expect("kind_result grant")
            .issued;
        assert_eq!(req.kind_result(), kind_result_grant);
        assert_eq!(req.kind_result().length, 112);
    }

    #[test]
    fn builds_and_self_validates_a_mutate_completion() {
        let (fx, req) = decoded_rename();
        let completion = build_mutate_completion(&req).expect("builds");
        // End-to-end: the built completion is wire-legal for a MUTATE CQE.
        let cqe = resolve_completion(&fx.sqe, completion)
            .expect("legal")
            .expect("a completion");
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 112);
    }

    #[test]
    fn decodes_link_and_unlink() {
        let link = MutationFixture::link();
        let ln = decode_mutation(&link.sqe, &link.table, link.section(), link.owner, false)
            .expect("link decode");
        assert_eq!(ln.mutation_kind(), mutation_kind::LINK);

        let unlink = MutationFixture::unlink();
        let un = decode_mutation(
            &unlink.sqe,
            &unlink.table,
            unlink.section(),
            unlink.owner,
            false,
        )
        .expect("unlink decode");
        assert_eq!(un.mutation_kind(), mutation_kind::UNLINK);
        assert!(matches!(un.body(), DecodedBody::Unlink { .. }));
    }

    #[test]
    fn rejects_zero_op_id() {
        let fx = MutationFixture::with_zero_op_id();
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn decodes_set_basic_info() {
        let fx = MutationFixture::set_basic_info();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        assert_eq!(req.mutation_kind(), mutation_kind::SET_BASIC_INFO);
        assert!(matches!(req.body(), DecodedBody::SetBasicInfo { .. }));
    }

    #[test]
    fn decodes_the_three_size_kinds() {
        let alloc = MutationFixture::set_allocation_size();
        let req = decode_mutation(
            &alloc.sqe,
            &alloc.table,
            alloc.section(),
            alloc.owner,
            false,
        )
        .expect("decode");
        assert_eq!(req.mutation_kind(), mutation_kind::SET_ALLOCATION_SIZE);
        assert!(matches!(req.body(), DecodedBody::SetAllocationSize { .. }));

        let eof = MutationFixture::set_end_of_file();
        let req =
            decode_mutation(&eof.sqe, &eof.table, eof.section(), eof.owner, false).expect("decode");
        assert_eq!(req.mutation_kind(), mutation_kind::SET_END_OF_FILE);
        assert!(matches!(req.body(), DecodedBody::SetEndOfFile { .. }));

        let vdl = MutationFixture::set_valid_data_length();
        let req =
            decode_mutation(&vdl.sqe, &vdl.table, vdl.section(), vdl.owner, false).expect("decode");
        assert_eq!(req.mutation_kind(), mutation_kind::SET_VALID_DATA_LENGTH);
        assert!(matches!(req.body(), DecodedBody::SetValidDataLength { .. }));
    }

    #[test]
    fn rejects_unimplementable_kind_at_envelope() {
        // SET_SPARSE (11) is > DELETE_REPARSE — the envelope validator rejects it
        // (Message), never reaching the scope dispatch.
        let fx = MutationFixture::set_sparse();
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn rejects_rename_with_zero_source_link() {
        let fx = MutationFixture::rename_with_zero_source_link();
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    fn sizes() -> SizeState {
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        }
    }

    fn base_effect(replaced: Option<Replaced>, namespace_generation: u64) -> MutationEffect {
        MutationEffect {
            file_id: FileId { lo: 0x100, hi: 0 },
            new_link_id: LinkId { lo: 0x101, hi: 0 },
            replaced,
            link_count: 1,
            namespace_generation,
            source_parent_generation: 2,
            target_parent_generation: 2,
            parent_generation: 2,
            sizes: sizes(),
            retained_sizes: sizes(),
            volume_commit_sequence: 5,
            security_generation: 0,
        }
    }

    /// A `MutationEffect` for the SET_SECURITY lane: `namespace_generation` is
    /// always zero (the security lane must not carry it), `sizes`/`retained_sizes`
    /// reuse `sizes()` (a size_epoch of 1, satisfying the non-size-kind
    /// `size_epoch >= retained.size_epoch` check).
    fn sec_effect(security_generation: u64) -> MutationEffect {
        let mut effect = base_effect(None, 0);
        effect.security_generation = security_generation;
        effect
    }

    fn decoded_rename() -> (MutationFixture, MutationRequest) {
        let fx = MutationFixture::rename();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        (fx, req)
    }

    #[test]
    fn rename_result_builds_and_validates() {
        let (fx, req) = decoded_rename();
        let bytes = build_mutation_result(&req, &base_effect(None, 2), &fx.table, fx.owner)
            .expect("result builds");
        assert_eq!(bytes.result.len(), 112);
        assert_eq!(bytes.kind_result.len(), 112);
    }

    #[test]
    fn rename_result_with_replacement_validates() {
        let (fx, req) = decoded_rename();
        let replaced = Some(Replaced {
            file_id: FileId { lo: 0x200, hi: 0 },
            link_id: LinkId { lo: 0x201, hi: 0 },
            namespace_generation: 3,
            link_count: 0,
        });
        assert!(
            build_mutation_result(&req, &base_effect(replaced, 2), &fx.table, fx.owner).is_ok()
        );
    }

    #[test]
    fn rename_result_half_present_replacement_rejected() {
        let (fx, req) = decoded_rename();
        // replaced_file_id nonzero but replaced_link_id zero -> half-present tuple.
        let replaced = Some(Replaced {
            file_id: FileId { lo: 0x200, hi: 0 },
            link_id: LinkId { lo: 0, hi: 0 },
            namespace_generation: 3,
            link_count: 0,
        });
        assert!(matches!(
            build_mutation_result(&req, &base_effect(replaced, 2), &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn rename_result_stale_namespace_generation_rejected() {
        let (fx, req) = decoded_rename();
        // namespace_generation == expected(1) is not strictly greater -> rejected.
        assert!(matches!(
            build_mutation_result(&req, &base_effect(None, 1), &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn link_result_builds_and_validates() {
        let fx = MutationFixture::link();
        let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).unwrap();
        let bytes = build_mutation_result(&req, &base_effect(None, 2), &fx.table, fx.owner)
            .expect("link result");
        assert_eq!(bytes.result.len(), 112);
        assert_eq!(bytes.kind_result.len(), 104);
    }

    #[test]
    fn unlink_result_builds_and_validates() {
        let fx = MutationFixture::unlink();
        let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).unwrap();
        let bytes = build_mutation_result(&req, &base_effect(None, 2), &fx.table, fx.owner)
            .expect("unlink result");
        assert_eq!(bytes.result.len(), 112);
        assert_eq!(bytes.kind_result.len(), 56);
    }

    #[test]
    fn link_result_replaced_equal_new_link_rejected() {
        let fx = MutationFixture::link();
        let req = decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).unwrap();
        // replaced_link_id == new_link_id (0x101) is a relationship fault.
        let replaced = Some(Replaced {
            file_id: FileId { lo: 0x200, hi: 0 },
            link_id: LinkId { lo: 0x101, hi: 0 },
            namespace_generation: 3,
            link_count: 0,
        });
        assert!(matches!(
            build_mutation_result(&req, &base_effect(replaced, 2), &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn rename_result_consistent_alias_validates() {
        let (fx, req) = decoded_rename();
        // replaced_file_id == file_id (0x100): the alias must carry the result's
        // namespace_generation (2) and link_count (1) — §9.7 alias rule.
        let replaced = Some(Replaced {
            file_id: FileId { lo: 0x100, hi: 0 },
            link_id: LinkId { lo: 0x201, hi: 0 },
            namespace_generation: 2,
            link_count: 1,
        });
        assert!(
            build_mutation_result(&req, &base_effect(replaced, 2), &fx.table, fx.owner).is_ok()
        );
    }

    #[test]
    fn rename_result_contradictory_alias_rejected() {
        let (fx, req) = decoded_rename();
        // replaced_file_id == file_id but a differing replaced generation (3 vs 2)
        // violates the alias equality -> fault.
        let replaced = Some(Replaced {
            file_id: FileId { lo: 0x100, hi: 0 },
            link_id: LinkId { lo: 0x201, hi: 0 },
            namespace_generation: 3,
            link_count: 1,
        });
        assert!(matches!(
            build_mutation_result(&req, &base_effect(replaced, 2), &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn decodes_set_security() {
        let fx = MutationFixture::set_security();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        assert_eq!(req.mutation_kind(), mutation_kind::SET_SECURITY);
        match req.body() {
            DecodedBody::SetSecurity { descriptor, .. } => assert_eq!(descriptor.len(), 20),
            _ => panic!("expected SetSecurity"),
        }
    }

    #[test]
    fn rejects_set_security_short_descriptor() {
        let fx = MutationFixture::set_security_bad_descriptor_len();
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn rejects_set_basic_info_mask_outside_all() {
        // A well-framed body (valid header; all timestamps/attributes zero, so
        // the timestamp-coupling and FILE_ATTRIBUTES-coupling checks are
        // satisfied) whose set_mask (0x20) is nonzero but has a bit outside
        // basic_info_set_mask::ALL (0x1F) -> InvalidScalar, attributable to the
        // mask-subset rule alone (it is the first field check after the header
        // prefix, so no earlier gate can be responsible).
        let fx = MutationFixture::set_basic_info();
        let record = SetBasicInfoV1 {
            header: ControlHeader {
                struct_size: 48,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            attributes: 0,
            set_mask: 0x20,
        };
        let mut bytes = [0u8; 48];
        try_encode(&record, &mut bytes).expect("SetBasicInfoV1 fits 48");
        fx.overwrite_body(&bytes);
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn rejects_set_allocation_size_above_max_file_size() {
        // A well-framed body whose new_size (0x8000_0000_0000_0000) exceeds
        // MAX_FILE_SIZE (i64::MAX) -> InvalidScalar, attributable to the
        // new_size ceiling alone (flags/reserved are both zero, so the earlier
        // FlagsOrReserved gate cannot be responsible).
        let fx = MutationFixture::set_allocation_size();
        let record = SetSizeV1 {
            header: ControlHeader {
                struct_size: 24,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            new_size: 0x8000_0000_0000_0000,
            flags: 0,
            reserved: 0,
        };
        let mut bytes = [0u8; 24];
        try_encode(&record, &mut bytes).expect("SetSizeV1 fits 24");
        fx.overwrite_body(&bytes);
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn rejects_set_end_of_file_above_max_file_size() {
        // A well-framed body whose new_size (0x8000_0000_0000_0000) exceeds
        // MAX_FILE_SIZE (i64::MAX) -> InvalidScalar, attributable to the
        // new_size ceiling alone (flags/reserved are both zero, so the earlier
        // FlagsOrReserved gate cannot be responsible).
        let fx = MutationFixture::set_end_of_file();
        let record = SetSizeV1 {
            header: ControlHeader {
                struct_size: 24,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            new_size: 0x8000_0000_0000_0000,
            flags: 0,
            reserved: 0,
        };
        let mut bytes = [0u8; 24];
        try_encode(&record, &mut bytes).expect("SetSizeV1 fits 24");
        fx.overwrite_body(&bytes);
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn rejects_set_valid_data_length_above_max_file_size() {
        // A well-framed body whose new_size (0x8000_0000_0000_0000) exceeds
        // MAX_FILE_SIZE (i64::MAX) -> InvalidScalar, attributable to the
        // new_size ceiling alone (flags/reserved are both zero, so the earlier
        // FlagsOrReserved gate cannot be responsible).
        let fx = MutationFixture::set_valid_data_length();
        let record = SetSizeV1 {
            header: ControlHeader {
                struct_size: 24,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            new_size: 0x8000_0000_0000_0000,
            flags: 0,
            reserved: 0,
        };
        let mut bytes = [0u8; 24];
        try_encode(&record, &mut bytes).expect("SetSizeV1 fits 24");
        fx.overwrite_body(&bytes);
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn rejects_set_security_information_outside_set_mask() {
        // A well-framed body (valid header/prefix, zero descriptor + padding
        // tail so the framing/padding checks pass) whose security_information
        // (0x80) has a bit outside security_information::SET_MASK (0xF001007F)
        // -> InvalidScalar, attributable to the security_information mask rule
        // alone (flags is zero, so the earlier FlagsOrReserved gate cannot be
        // responsible).
        let fx = MutationFixture::set_security();
        let record = SetSecurityV1 {
            header: ControlHeader {
                struct_size: 48,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            security_information: 0x80,
            flags: 0,
            security_descriptor: BlobSlice {
                offset: 24,
                length: 20,
            },
        };
        let mut bytes = [0u8; 48];
        try_encode(&record, &mut bytes[..24]).expect("SetSecurityV1 fits 24");
        fx.overwrite_body(&bytes);
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn same_parent_rename_accepts_equal_parent_generations() {
        // The rename fixture has equal expected source/target parent generations,
        // so same_parent_rename = true is accepted at decode.
        let fx = MutationFixture::rename();
        assert!(decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, true).is_ok());
    }

    #[test]
    fn same_parent_rename_rejects_unequal_parent_generations() {
        // Unequal expected source/target parent generations under same_parent_rename
        // is a body relationship fault.
        let fx = MutationFixture::rename_unequal_parents();
        assert!(matches!(
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, true),
            Err(MutationError::Message(_))
        ));
    }

    #[test]
    fn same_parent_rename_result_requires_equal_parent_generations() {
        let fx = MutationFixture::rename();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, true).expect("decode");
        // base_effect has source == target parent generation (2) -> ok.
        assert!(build_mutation_result(&req, &base_effect(None, 2), &fx.table, fx.owner).is_ok());
        // A same-parent result with differing parent generations -> fault.
        let mut effect = base_effect(None, 2);
        effect.target_parent_generation = 3;
        assert!(matches!(
            build_mutation_result(&req, &effect, &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn set_basic_info_result_builds_and_validates() {
        let fx = MutationFixture::set_basic_info();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        // namespace_generation 2 > the fixture's expected 1.
        let bytes = build_mutation_result(&req, &base_effect(None, 2), &fx.table, fx.owner)
            .expect("basic info result builds");
        assert_eq!(bytes.result.len(), 112);
        assert!(bytes.kind_result.is_empty());
    }

    #[test]
    fn set_basic_info_result_stale_namespace_generation_rejected() {
        let fx = MutationFixture::set_basic_info();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        // namespace_generation == expected(1) is not strictly greater -> rejected.
        assert!(matches!(
            build_mutation_result(&req, &base_effect(None, 1), &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    /// A `MutationEffect` carrying a valid per-`kind` `SizeState`
    /// relationship (`sizes.size_epoch = 2 > retained.size_epoch = 1`, matching
    /// each size kind's `new_size = 4096` fixture body).
    fn size_effect(kind: u16) -> MutationEffect {
        let (sizes, retained_sizes) = match kind {
            mutation_kind::SET_ALLOCATION_SIZE => (
                SizeState {
                    allocation_size: 8192,
                    file_size: 4096,
                    valid_data_length: 4096,
                    size_epoch: 2,
                },
                SizeState {
                    allocation_size: 4096,
                    file_size: 4096,
                    valid_data_length: 4096,
                    size_epoch: 1,
                },
            ),
            mutation_kind::SET_END_OF_FILE => (
                SizeState {
                    allocation_size: 8192,
                    file_size: 4096,
                    valid_data_length: 2048,
                    size_epoch: 2,
                },
                SizeState {
                    allocation_size: 8192,
                    file_size: 2048,
                    valid_data_length: 2048,
                    size_epoch: 1,
                },
            ),
            mutation_kind::SET_VALID_DATA_LENGTH => (
                SizeState {
                    allocation_size: 8192,
                    file_size: 4096,
                    valid_data_length: 4096,
                    size_epoch: 2,
                },
                SizeState {
                    allocation_size: 8192,
                    file_size: 4096,
                    valid_data_length: 2048,
                    size_epoch: 1,
                },
            ),
            other => panic!("size_effect: not a size kind: {other}"),
        };
        let mut effect = base_effect(None, 2);
        effect.sizes = sizes;
        effect.retained_sizes = retained_sizes;
        effect
    }

    #[test]
    fn size_kind_results_build_and_validate() {
        let alloc = MutationFixture::set_allocation_size();
        let req = decode_mutation(
            &alloc.sqe,
            &alloc.table,
            alloc.section(),
            alloc.owner,
            false,
        )
        .expect("decode");
        let bytes = build_mutation_result(
            &req,
            &size_effect(mutation_kind::SET_ALLOCATION_SIZE),
            &alloc.table,
            alloc.owner,
        )
        .expect("allocation size result builds");
        assert_eq!(bytes.result.len(), 112);
        assert!(bytes.kind_result.is_empty());

        let eof = MutationFixture::set_end_of_file();
        let req =
            decode_mutation(&eof.sqe, &eof.table, eof.section(), eof.owner, false).expect("decode");
        let bytes = build_mutation_result(
            &req,
            &size_effect(mutation_kind::SET_END_OF_FILE),
            &eof.table,
            eof.owner,
        )
        .expect("end of file result builds");
        assert_eq!(bytes.result.len(), 112);
        assert!(bytes.kind_result.is_empty());

        let vdl = MutationFixture::set_valid_data_length();
        let req =
            decode_mutation(&vdl.sqe, &vdl.table, vdl.section(), vdl.owner, false).expect("decode");
        let bytes = build_mutation_result(
            &req,
            &size_effect(mutation_kind::SET_VALID_DATA_LENGTH),
            &vdl.table,
            vdl.owner,
        )
        .expect("valid data length result builds");
        assert_eq!(bytes.result.len(), 112);
        assert!(bytes.kind_result.is_empty());
    }

    #[test]
    fn set_end_of_file_result_wrong_file_size_rejected() {
        let fx = MutationFixture::set_end_of_file();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        let mut effect = size_effect(mutation_kind::SET_END_OF_FILE);
        // file_size (2048) != new_size (4096) -> relationship fault.
        effect.sizes.file_size = 2048;
        assert!(matches!(
            build_mutation_result(&req, &effect, &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn set_valid_data_length_result_wrong_vdl_rejected() {
        let fx = MutationFixture::set_valid_data_length();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        let mut effect = size_effect(mutation_kind::SET_VALID_DATA_LENGTH);
        // valid_data_length (2048) != new_size (4096) -> relationship fault.
        effect.sizes.valid_data_length = 2048;
        assert!(matches!(
            build_mutation_result(&req, &effect, &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn set_allocation_size_result_below_floor_rejected() {
        let fx = MutationFixture::set_allocation_size();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        let mut effect = size_effect(mutation_kind::SET_ALLOCATION_SIZE);
        // allocation_size (2048) < max(new_size=4096, file_size=2048) = 4096 ->
        // relationship fault, symmetric with the EOF/VDL reject tests above.
        effect.sizes.allocation_size = 2048;
        effect.sizes.file_size = 2048;
        effect.sizes.valid_data_length = 2048;
        assert!(matches!(
            build_mutation_result(&req, &effect, &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn set_security_result_builds_and_validates() {
        let fx = MutationFixture::set_security();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        // security_generation 2 > the fixture's expected 1.
        let bytes = build_mutation_result(&req, &sec_effect(2), &fx.table, fx.owner)
            .expect("security result builds");
        assert_eq!(bytes.result.len(), 112);
        assert!(bytes.kind_result.is_empty());
    }

    #[test]
    fn set_security_result_stale_security_generation_rejected() {
        let fx = MutationFixture::set_security();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        // security_generation == expected(1) is not strictly greater -> rejected.
        assert!(matches!(
            build_mutation_result(&req, &sec_effect(1), &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }

    #[test]
    fn set_security_result_nonzero_namespace_generation_rejected() {
        let fx = MutationFixture::set_security();
        let req =
            decode_mutation(&fx.sqe, &fx.table, fx.section(), fx.owner, false).expect("decode");
        // The security lane must zero namespace_generation -> a nonzero value on
        // the wrong lane is rejected even though security_generation is valid.
        let mut effect = sec_effect(2);
        effect.namespace_generation = 2;
        assert!(matches!(
            build_mutation_result(&req, &effect, &fx.table, fx.owner),
            Err(MutationResultError::Message(_))
        ));
    }
}
