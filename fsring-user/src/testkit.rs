//! Kernel-role harness for exercising the transport in user space.
//!
//! The harness plays the part the kernel driver will later play: it constructs a
//! valid section from a validated SETUP and hands out the kernel-role and
//! daemon-role ring handles over that one shared section. It is gated behind the
//! non-default `testkit` feature so it never ships in a production daemon build.

use core::ptr;

use fsring_abi::codec::try_encode;
use fsring_abi::ids::{FileId, LinkId, OpId, ReqId, TransactionId};
use fsring_abi::layout::{op, SqeBody, SQE_PAYLOAD_LEN};
use fsring_abi::msgs::{
    buffer_kind, create_result, file_attributes, mutation_kind, query_dir_flags, query_info_class,
    query_volume_class, BlobSlice, BufferRef, CommitOpenV2, ControlHeader, LinkV1, MutationV2, PRw,
    PrepareOpenV2, QueryDirV2, QueryInfoV1, QuerySecurityV1, QueryVolumeV1, RenameV1,
    SetBasicInfoV1, SetSecurityV1, SetSizeV1, SizeState, UnlinkV1, WriteV2, CONTROL_VERSION_V1,
    CONTROL_VERSION_V2,
};
use fsring_abi::slots::{
    resolve_slot, validate_slot_arena, GrantOwner, SlotDirection, SlotToken, ValidatedSlotArena,
};

use crate::dataio::WriteEffect;
use crate::direnum::DirCandidate;
use crate::filesystem::{FileSystem, FileSystemResult, MutationContext};
use crate::fixture::valid_setup;
use crate::grant::GrantTable;
use crate::layout::PhysicalLayout;
use crate::lifecycle::{CommitEffect, PrepareResult};
use crate::mutation::{MutationEffect, MutationRequest};
use crate::openbody::{CommitRequest, PreparedRequest};
use crate::querydir::QueryDirRequest;
use crate::queryinfo::FileInfoFields;
use crate::queryvolume::VolumeSizeFields;
use crate::ring::{DaemonRing, KernelRing};
use crate::section::{HeapSection, SharedSection};

/// Default host page size for heap-backed sections.
pub const HOST_PAGE_SIZE: u32 = 4096;

/// A constructed, validated single-section transport shared by both roles.
pub struct Harness {
    section: HeapSection,
    layout: PhysicalLayout,
}

impl Harness {
    /// Build a one-ring section (`sq_capacity = 8`, `cq_capacity = 2`) from the
    /// canonical Win10-x64 SETUP, backed by a [`HeapSection`].
    pub fn new_single_ring() -> Self {
        let setup = valid_setup(1);
        let layout = PhysicalLayout::compute(&setup, HOST_PAGE_SIZE).expect("compute layout");
        let section = HeapSection::with_len(layout.section_size as usize, HOST_PAGE_SIZE as usize);
        // SAFETY: `section` is a freshly allocated, zeroed mapping of exactly
        // `section_size` bytes.
        unsafe { layout.construct(section.base(), section.len()) };
        Self { section, layout }
    }

    /// Borrow the shared section (for its [`SharedSection::waiter`]).
    pub fn section(&self) -> &HeapSection {
        &self.section
    }

    /// The daemon-role handle for ring 0.
    pub fn daemon_ring(&self) -> DaemonRing<'_> {
        // SAFETY: the section outlives the returned handle (its lifetime is tied
        // to `&self`); this is the sole daemon-side handle for ring 0.
        unsafe { DaemonRing::attach(self.section.base(), &self.layout.rings[0]) }
    }

    /// The kernel-role handle for ring 0.
    pub fn kernel_ring(&self) -> KernelRing<'_> {
        // SAFETY: same section, tied to `&self`; the sole kernel-side handle.
        unsafe { KernelRing::attach(self.section.base(), &self.layout.rings[0]) }
    }

    /// The session epoch grants validate against.
    pub fn session_epoch(&self) -> u64 {
        self.layout.session_epoch()
    }

    /// The validated k2u slot arena for this section.
    pub fn k2u_arena(&self) -> ValidatedSlotArena {
        validate_slot_arena(
            SlotDirection::K2u,
            self.layout.section_size,
            self.layout.k2u_slots,
            self.layout.k2u_slot_classes,
        )
        .expect("the computed k2u arena is ABI-valid")
    }

    /// The validated u2k slot arena for this section (the daemon-writable
    /// direction: `reply` / `result_security_descriptor` echoes live here).
    pub fn u2k_arena(&self) -> ValidatedSlotArena {
        validate_slot_arena(
            SlotDirection::U2k,
            self.layout.section_size,
            self.layout.u2k_arena,
            self.layout.u2k_slot_classes,
        )
        .expect("the computed u2k arena is ABI-valid")
    }

    /// Write `bytes` into the slot named by `token` in `arena` (kernel-role fill).
    pub fn write_slot(&self, arena: &ValidatedSlotArena, token: SlotToken, bytes: &[u8]) {
        let resolved = resolve_slot(arena, token).expect("resolve_slot");
        let start = resolved.section_range().start as usize;
        assert!(
            bytes.len() <= resolved.slot_size() as usize,
            "body fits the slot"
        );
        // Defense in depth: the slot must lie within this harness's section
        // (guards against a caller passing a foreign, larger-section arena).
        debug_assert!(
            resolved.section_range().end as usize <= self.section.len(),
            "slot range within the section"
        );
        // SAFETY: `start + bytes.len()` is within the resolved slot, within the
        // section; `bytes` and the section do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.section.base().add(start), bytes.len())
        };
    }

    /// Rewrite an already-granted, no-pattern `QueryDirV2` body for a bounded
    /// initial/continuation sequence that keeps one daemon enumerator alive.
    /// `output` must be the real U2K grant issued for the request.
    pub fn rewrite_query_dir_page(
        &self,
        sqe: &mut SqeBody,
        output: BufferRef,
        kernel_open_id: u64,
        flags: u32,
        cookie: u64,
        generation: u64,
    ) {
        let raw = QueryDirV2 {
            header: ControlHeader {
                struct_size: 64,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            enumeration_cookie: cookie,
            flags,
            reserved: 0,
            pattern: BlobSlice {
                offset: 0,
                length: 0,
            },
            output,
            enumeration_generation: generation,
        };
        let mut blob = [0u8; 64];
        try_encode(&raw, &mut blob).expect("QueryDirV2 fits");
        self.write_slot(&self.k2u_arena(), tok(0, 0), &blob);
        sqe.kernel_open_id = kernel_open_id;
    }

    /// Issue a k2u grant of `body`'s length to `owner`, and build the
    /// `ABORT_OPEN` SQE whose `PControl` echoes the grant.
    pub fn grant_abort_sqe(
        &self,
        table: &mut GrantTable,
        owner: GrantOwner,
        token: SlotToken,
        req_id: u64,
        body: &[u8],
    ) -> SqeBody {
        let reference = table
            .issue_k2u(&self.k2u_arena(), owner, token, body.len() as u32)
            .expect("issue k2u grant");
        let mut payload = [0u8; SQE_PAYLOAD_LEN];
        payload[0..8].copy_from_slice(&reference.token.to_le_bytes());
        payload[8..12].copy_from_slice(&reference.offset.to_le_bytes());
        payload[12..16].copy_from_slice(&reference.length.to_le_bytes());
        payload[16..18].copy_from_slice(&reference.kind.to_le_bytes());
        payload[18..20].copy_from_slice(&reference.access.to_le_bytes());
        payload[20..24].copy_from_slice(&reference.reserved.to_le_bytes());
        SqeBody {
            opcode: op::ABORT_OPEN,
            flags: 0,
            payload_len: 24,
            reserved: 0,
            req_id,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload,
        }
    }
}

/// A generation-1 slot token in `class`/`index`.
fn tok(class: u8, index: u32) -> SlotToken {
    SlotToken::try_new(class, index, 1).expect("valid slot token")
}

/// A `PControl` SQE (`payload_len = 24`) whose 24-byte payload echoes `body_ref`.
fn pcontrol_sqe(opcode: u16, req_id: u64, body_ref: &BufferRef) -> SqeBody {
    let mut payload = [0u8; SQE_PAYLOAD_LEN];
    payload[0..8].copy_from_slice(&body_ref.token.to_le_bytes());
    payload[8..12].copy_from_slice(&body_ref.offset.to_le_bytes());
    payload[12..16].copy_from_slice(&body_ref.length.to_le_bytes());
    payload[16..18].copy_from_slice(&body_ref.kind.to_le_bytes());
    payload[18..20].copy_from_slice(&body_ref.access.to_le_bytes());
    payload[20..24].copy_from_slice(&body_ref.reserved.to_le_bytes());
    SqeBody {
        opcode,
        flags: 0,
        payload_len: 24,
        reserved: 0,
        req_id,
        kernel_open_id: 0,
        ccb_sequence: 0,
        payload,
    }
}

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

const OPEN_REQ_ID: u64 = 0x0001_0000_0001;

#[derive(Clone, Copy)]
struct PrepareOverrides {
    reply_len: u32,
    result_sd_len: u32,
    zero_op_id: bool,
    unknown_name_token: bool,
}

impl Default for PrepareOverrides {
    fn default() -> Self {
        Self {
            reply_len: 136,
            result_sd_len: 65_536,
            zero_op_id: false,
            unknown_name_token: false,
        }
    }
}

/// A fully-granted `PrepareOpenV2` laid into a heap section, plus the
/// `PREPARE_OPEN` SQE whose `PControl` echoes the 192-byte body grant. The
/// kernel-role fixture for exercising [`crate::openbody::decode_prepare`]: six
/// grants (K2U body/name/SD/EA + U2K reply/result-SD) issued into distinct
/// slots of the computed arenas, with the input bytes written K2U-side.
pub struct PrepareFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
    pub op_id: OpId,
    pub name_bytes: Vec<u8>,
    pub disposition: u32,
}

impl PrepareFixture {
    /// A well-formed prepare that decodes cleanly.
    pub fn build() -> Self {
        Self::build_with(PrepareOverrides::default())
    }

    /// Build a provider-facing PREPARE request with caller-owned semantic
    /// identities and scalars. The name is encoded into a real K2U grant and
    /// the reply/descriptor targets are real U2K grants; optional input SD/EA
    /// refs are NONE, so the public decoder produces `None` rather than a
    /// test-only semantic shortcut.
    #[allow(clippy::too_many_arguments)]
    pub fn provider(
        parent_id: FileId,
        name: &str,
        op_id: OpId,
        desired_access: u32,
        share_access: u32,
        disposition: u32,
        create_options: u32,
        file_attributes: u32,
        open_flags: u32,
    ) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();

        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 192)
            .expect("body grant");
        let name_ref = table
            .issue_k2u(&k2u, owner, tok(0, 1), name_bytes.len() as u32)
            .expect("name grant");
        let reply_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), 136)
            .expect("reply grant");
        let result_sd_ref = table
            .issue_u2k(&u2k, owner, tok(1, 1), 65_536)
            .expect("result-sd grant");
        harness.write_slot(&k2u, tok(0, 1), &name_bytes);

        let prepare = PrepareOpenV2 {
            header: ControlHeader {
                struct_size: 192,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id,
            parent_id,
            name: name_ref,
            security_context_id: 0,
            desired_access,
            share_access,
            disposition,
            create_options,
            file_attributes,
            open_flags,
            requested_security_descriptor: none_ref(),
            extended_attributes: none_ref(),
            reply: reply_ref,
            result_security_descriptor: result_sd_ref,
        };
        let mut body = [0u8; 192];
        try_encode(&prepare, &mut body).expect("PrepareOpenV2 fits");
        harness.write_slot(&k2u, tok(0, 0), &body);
        let sqe = pcontrol_sqe(op::PREPARE_OPEN, OPEN_REQ_ID, &body_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            op_id,
            name_bytes,
            disposition,
        }
    }

    /// A prepare whose `reply` grant is `len` bytes (`< 136` triggers the ABI
    /// `reply.length` floor).
    pub fn with_reply_len(len: u32) -> Self {
        Self::build_with(PrepareOverrides {
            reply_len: len,
            ..Default::default()
        })
    }

    /// A prepare whose `result_security_descriptor` grant is `len` bytes
    /// (`!= 65536` is illegal).
    pub fn with_result_sd_len(len: u32) -> Self {
        Self::build_with(PrepareOverrides {
            result_sd_len: len,
            ..Default::default()
        })
    }

    /// A prepare whose `op_id` is the zero pair (an identity fault).
    pub fn with_zero_op_id() -> Self {
        Self::build_with(PrepareOverrides {
            zero_op_id: true,
            ..Default::default()
        })
    }

    /// A prepare whose inner `name` `BufferRef` echoes a token the grant table
    /// never issued.
    pub fn with_unknown_name_token() -> Self {
        Self::build_with(PrepareOverrides {
            unknown_name_token: true,
            ..Default::default()
        })
    }

    /// Borrow the backing section (feeds `decode_prepare`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` PREPARE_OPEN round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    /// Overwrite the 192-byte body slot with arbitrary bytes (fuzz hook): the
    /// outer grant + SQE stay valid, so `decode_prepare` reaches `try_decode`
    /// and the inner-grant resolution over an attacker-chosen `PrepareOpenV2`.
    pub fn overwrite_body(&self, bytes: &[u8]) {
        let mut body = [0u8; 192];
        let n = bytes.len().min(body.len());
        body[..n].copy_from_slice(&bytes[..n]);
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &body);
    }

    fn build_with(ov: PrepareOverrides) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        let name_bytes = b"a.txt".to_vec();
        let disposition = 1u32;
        let op_id = if ov.zero_op_id {
            OpId { lo: 0, hi: 0 }
        } else {
            OpId { lo: 0x11, hi: 0 }
        };

        // K2U: body(192), name, requested-SD(20), EA(1). U2K: reply, result-SD.
        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 192)
            .expect("body grant");
        let mut name_ref = table
            .issue_k2u(&k2u, owner, tok(0, 1), name_bytes.len() as u32)
            .expect("name grant");
        let sd_ref = table
            .issue_k2u(&k2u, owner, tok(0, 2), 20)
            .expect("sd grant");
        let ea_ref = table
            .issue_k2u(&k2u, owner, tok(0, 3), 1)
            .expect("ea grant");
        let reply_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), ov.reply_len)
            .expect("reply grant");
        let result_sd_ref = table
            .issue_u2k(&u2k, owner, tok(1, 1), ov.result_sd_len)
            .expect("result-sd grant");

        // Fill the K2U input slots (the U2K reply/result-SD are output buffers).
        harness.write_slot(&k2u, tok(0, 1), &name_bytes);
        harness.write_slot(&k2u, tok(0, 2), &[0u8; 20]);
        harness.write_slot(&k2u, tok(0, 3), &[0u8; 1]);

        if ov.unknown_name_token {
            name_ref.token ^= 0xdead_0000;
        }

        let prepare = PrepareOpenV2 {
            header: ControlHeader {
                struct_size: 192,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id,
            parent_id: FileId { lo: 7, hi: 0 },
            name: name_ref,
            security_context_id: 0,
            desired_access: 1,
            share_access: 0,
            disposition,
            create_options: 0,
            file_attributes: 0,
            open_flags: 0,
            requested_security_descriptor: sd_ref,
            extended_attributes: ea_ref,
            reply: reply_ref,
            result_security_descriptor: result_sd_ref,
        };
        let mut body = [0u8; 192];
        try_encode(&prepare, &mut body).expect("PrepareOpenV2 fits its 192-byte body");
        harness.write_slot(&k2u, tok(0, 0), &body);

        let sqe = pcontrol_sqe(op::PREPARE_OPEN, OPEN_REQ_ID, &body_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            op_id,
            name_bytes,
            disposition,
        }
    }
}

#[derive(Clone, Copy)]
struct CommitOverrides {
    reply_len: u32,
    reserved: u32,
    zero_transaction_id: bool,
    zero_kernel_open_id: bool,
    unknown_reply_token: bool,
}

impl Default for CommitOverrides {
    fn default() -> Self {
        Self {
            reply_len: 112,
            reserved: 0,
            zero_transaction_id: false,
            zero_kernel_open_id: false,
            unknown_reply_token: false,
        }
    }
}

/// A granted `CommitOpenV2` laid into a heap section, plus the `COMMIT_OPEN`
/// SQE whose `PControl` echoes the 104-byte body grant. Kernel-role fixture for
/// [`crate::openbody::decode_commit`]: a K2U body grant plus one U2K reply grant.
pub struct CommitFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
    pub op_id: OpId,
    pub transaction_id: TransactionId,
    pub kernel_open_id: u64,
    pub expected_namespace_generation: u64,
    pub expected_security_generation: u64,
}

impl CommitFixture {
    /// A well-formed commit that decodes cleanly.
    pub fn build() -> Self {
        Self::build_with(CommitOverrides::default())
    }

    /// Build a provider-facing COMMIT request with the exact prepared
    /// identities, generations, retained open id, and granted access.
    pub fn provider(
        op_id: OpId,
        transaction_id: TransactionId,
        kernel_open_id: u64,
        expected_namespace_generation: u64,
        expected_security_generation: u64,
        granted_access: u32,
    ) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();
        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 104)
            .expect("body grant");
        let reply = table
            .issue_u2k(&u2k, owner, tok(1, 0), 112)
            .expect("reply grant");
        let raw = CommitOpenV2 {
            header: ControlHeader {
                struct_size: 104,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id,
            transaction_id,
            expected_namespace_generation,
            expected_security_generation,
            kernel_open_id,
            commit_flags: 0,
            reserved: 0,
            granted_access,
            reserved2: 0,
            reply,
        };
        let mut body = [0u8; 104];
        try_encode(&raw, &mut body).expect("CommitOpenV2 fits");
        harness.write_slot(&k2u, tok(0, 0), &body);
        let mut sqe = pcontrol_sqe(op::COMMIT_OPEN, OPEN_REQ_ID, &body_ref);
        sqe.kernel_open_id = kernel_open_id;
        Self {
            harness,
            table,
            sqe,
            owner,
            op_id,
            transaction_id,
            kernel_open_id,
            expected_namespace_generation,
            expected_security_generation,
        }
    }

    /// A commit whose `reply` grant is `len` bytes (`< 112` is illegal).
    pub fn with_reply_len(len: u32) -> Self {
        Self::build_with(CommitOverrides {
            reply_len: len,
            ..Default::default()
        })
    }

    /// A commit whose `reserved` field is non-zero (a flags/reserved fault).
    pub fn with_reserved(value: u32) -> Self {
        Self::build_with(CommitOverrides {
            reserved: value,
            ..Default::default()
        })
    }

    /// A commit whose `transaction_id` is the zero pair (an identity fault).
    pub fn with_zero_transaction_id() -> Self {
        Self::build_with(CommitOverrides {
            zero_transaction_id: true,
            ..Default::default()
        })
    }

    /// A commit whose `kernel_open_id` is zero (an identity fault).
    pub fn with_zero_kernel_open_id() -> Self {
        Self::build_with(CommitOverrides {
            zero_kernel_open_id: true,
            ..Default::default()
        })
    }

    /// A commit whose `reply` `BufferRef` echoes an unissued token.
    pub fn with_unknown_reply_token() -> Self {
        Self::build_with(CommitOverrides {
            unknown_reply_token: true,
            ..Default::default()
        })
    }

    /// Borrow the backing section (feeds `decode_commit`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` COMMIT_OPEN round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    /// Overwrite the 104-byte body slot with arbitrary bytes (fuzz hook).
    pub fn overwrite_body(&self, bytes: &[u8]) {
        let mut body = [0u8; 104];
        let n = bytes.len().min(body.len());
        body[..n].copy_from_slice(&bytes[..n]);
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &body);
    }

    fn build_with(ov: CommitOverrides) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        let op_id = OpId { lo: 0x11, hi: 0 };
        let transaction_id = if ov.zero_transaction_id {
            TransactionId { lo: 0, hi: 0 }
        } else {
            TransactionId { lo: 0x22, hi: 0 }
        };
        let kernel_open_id = if ov.zero_kernel_open_id { 0 } else { 0x33 };
        let expected_namespace_generation = 1;
        let expected_security_generation = 1;

        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 104)
            .expect("body grant");
        let mut reply_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), ov.reply_len)
            .expect("reply grant");
        if ov.unknown_reply_token {
            reply_ref.token ^= 0xdead_0000;
        }

        let commit = CommitOpenV2 {
            header: ControlHeader {
                struct_size: 104,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id,
            transaction_id,
            expected_namespace_generation,
            expected_security_generation,
            kernel_open_id,
            commit_flags: 0,
            reserved: ov.reserved,
            granted_access: 1,
            reserved2: 0,
            reply: reply_ref,
        };
        let mut body = [0u8; 104];
        try_encode(&commit, &mut body).expect("CommitOpenV2 fits its 104-byte body");
        harness.write_slot(&k2u, tok(0, 0), &body);

        let sqe = pcontrol_sqe(op::COMMIT_OPEN, OPEN_REQ_ID, &body_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            op_id,
            transaction_id,
            kernel_open_id,
            expected_namespace_generation,
            expected_security_generation,
        }
    }
}

/// A nonzero enumeration generation for the query fixtures.
const QUERY_GEN: u64 = 5;
/// An output grant length that fits at least one maximum canonical entry
/// (>= 40 + MAX_CANONICAL_DIR_ENTRY_BYTES).
const QUERY_OUTPUT_LEN: u32 = 4096;

/// A granted `QueryDirV2` control blob (`QueryDirV2` 64B + optional align8 pattern
/// tail) laid into a K2U slot, plus a U2K `output` grant, plus the `QUERY_DIR`
/// SQE whose `PControl` echoes the blob grant. Kernel-role fixture for
/// [`crate::querydir::decode_query_dir`].
pub struct QueryDirFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
    pub enumeration_generation: u64,
    pub enumeration_cookie: u64,
    blob_len: usize,
}

impl QueryDirFixture {
    /// An `InitialMatchAll` request (RESTART, empty pattern).
    pub fn match_all() -> Self {
        Self::build(
            query_dir_flags::RESTART,
            0,
            QUERY_GEN,
            &[],
            QUERY_OUTPUT_LEN,
        )
    }

    /// A provider-facing initial match-all page with caller-supplied retained
    /// open id and enumeration generation.
    pub fn provider_match_all(kernel_open_id: u64, generation: u64, output_len: u32) -> Self {
        let mut fixture = Self::build(query_dir_flags::RESTART, 0, generation, &[], output_len);
        fixture.sqe.kernel_open_id = kernel_open_id;
        fixture
    }

    /// A `Continuation` request (no RESTART, nonzero cookie, empty pattern).
    pub fn continuation(cookie: u64) -> Self {
        Self::build(0, cookie, QUERY_GEN, &[], QUERY_OUTPUT_LEN)
    }

    /// An `InitialExpression` request carrying `pattern` (UTF-16). `exact` sets the
    /// `EXACT_PATTERN` flag (which must agree with the pattern's wildcard content).
    pub fn expression(pattern: &[u16], exact: bool) -> Self {
        let flags = query_dir_flags::RESTART
            | if exact {
                query_dir_flags::EXACT_PATTERN
            } else {
                0
            };
        let bytes: Vec<u8> = pattern.iter().flat_map(|u| u.to_le_bytes()).collect();
        Self::build(flags, 0, QUERY_GEN, &bytes, QUERY_OUTPUT_LEN)
    }

    /// RESTART with a zero enumeration generation (an identity fault).
    pub fn with_zero_generation() -> Self {
        Self::build(query_dir_flags::RESTART, 0, 0, &[], QUERY_OUTPUT_LEN)
    }

    /// RESTART whose `output` grant is `len` bytes (`< 40` is illegal).
    pub fn with_bad_output_len(len: u32) -> Self {
        Self::build(query_dir_flags::RESTART, 0, QUERY_GEN, &[], len)
    }

    /// A RESTART request that also carries a nonzero cookie — an ABI
    /// relationship fault (RESTART requires cookie zero).
    pub fn with_restart_and_cookie() -> Self {
        Self::build(
            query_dir_flags::RESTART,
            7,
            QUERY_GEN,
            &[],
            QUERY_OUTPUT_LEN,
        )
    }

    /// An expression whose `EXACT_PATTERN` flag disagrees with its wildcard
    /// pattern (`*.txt` marked exact) — an ABI relationship fault.
    pub fn with_exact_flag_mismatch() -> Self {
        let pattern: Vec<u16> = "*.txt".encode_utf16().collect();
        let bytes: Vec<u8> = pattern.iter().flat_map(|u| u.to_le_bytes()).collect();
        Self::build(
            query_dir_flags::RESTART | query_dir_flags::EXACT_PATTERN,
            0,
            QUERY_GEN,
            &bytes,
            QUERY_OUTPUT_LEN,
        )
    }

    /// Borrow the backing section (feeds `decode_query_dir`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` round-trip: submit `sqe` on `harness.kernel_ring()`, pump on
    /// `harness.daemon_ring()` with `table`/`harness.section()`, then reap.
    /// Returning `Harness` by value (rather than a borrow) lets the caller move
    /// `table` into the `Daemon` while still deriving both rings + the section
    /// from the same live section (a borrow would forbid that partial move).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    /// Overwrite the control blob slot (this fixture's full blob length) with
    /// arbitrary bytes (fuzz hook): the outer grant + SQE stay valid, so
    /// `decode_query_dir` reaches `try_decode` + `validate_query_dir_v2` over an
    /// attacker-chosen `QueryDirV2`. On an `expression` fixture the blob is `> 64`
    /// bytes, so the pattern-tail decode path is driven too.
    pub fn overwrite_blob(&self, bytes: &[u8]) {
        let mut blob = vec![0u8; self.blob_len];
        let n = bytes.len().min(self.blob_len);
        blob[..n].copy_from_slice(&bytes[..n]);
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &blob);
    }

    /// Rewrite this fixture's granted 64-byte control body as another
    /// match-all/continuation request. This lets a bounded scenario preserve
    /// one real daemon enumerator while reusing the same physical slots.
    pub fn rewrite_page(&mut self, flags: u32, cookie: u64, generation: u64) {
        assert_eq!(self.blob_len, 64, "page rewrite requires no pattern tail");
        let output = self
            .table
            .grant_for(tok(1, 0).raw())
            .expect("fixture output grant")
            .issued;
        let raw = QueryDirV2 {
            header: ControlHeader {
                struct_size: 64,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            enumeration_cookie: cookie,
            flags,
            reserved: 0,
            pattern: BlobSlice {
                offset: 0,
                length: 0,
            },
            output,
            enumeration_generation: generation,
        };
        let mut blob = [0u8; 64];
        try_encode(&raw, &mut blob).expect("QueryDirV2 fits");
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &blob);
        self.enumeration_generation = generation;
        self.enumeration_cookie = cookie;
    }

    fn build(flags: u32, cookie: u64, generation: u64, pattern: &[u8], output_len: u32) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        // U2K output grant (control class) where the daemon would write entries.
        let output_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), output_len)
            .expect("output grant");

        // blob = QueryDirV2 (64) + optional pattern tail, align8-padded.
        let (pattern_slice, blob_len) = if pattern.is_empty() {
            (
                BlobSlice {
                    offset: 0,
                    length: 0,
                },
                64usize,
            )
        } else {
            let unpadded = 64 + pattern.len();
            (
                BlobSlice {
                    offset: 64,
                    length: pattern.len() as u32,
                },
                (unpadded + 7) & !7,
            )
        };
        let query = QueryDirV2 {
            header: ControlHeader {
                struct_size: blob_len as u32,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            enumeration_cookie: cookie,
            flags,
            reserved: 0,
            pattern: pattern_slice,
            output: output_ref,
            enumeration_generation: generation,
        };
        let mut blob = vec![0u8; blob_len];
        try_encode(&query, &mut blob[..64]).expect("QueryDirV2 fits its 64-byte prefix");
        if !pattern.is_empty() {
            blob[64..64 + pattern.len()].copy_from_slice(pattern);
        }
        let blob_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), blob_len as u32)
            .expect("blob grant");
        harness.write_slot(&k2u, tok(0, 0), &blob);

        let sqe = pcontrol_sqe(op::QUERY_DIR, OPEN_REQ_ID, &blob_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            enumeration_generation: generation,
            enumeration_cookie: cookie,
            blob_len,
        }
    }
}

/// The full 65536-byte U2K output grant length `QuerySecurityV1.output` must
/// carry exactly (`validate_query_security_v1`'s `output.length != 65_536` gate).
const QUERY_SECURITY_OUTPUT_LEN: u32 = 65_536;

/// A granted `QuerySecurityV1` control blob (40B, fixed size, no tail) laid
/// into a K2U slot, plus a U2K `output` grant, plus the `QUERY_SECURITY` SQE
/// whose `PControl` echoes the blob grant. Kernel-role fixture for
/// [`crate::querysecurity::decode_query_security`].
pub struct QuerySecurityFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
    blob_len: usize,
    /// The issued `output` `BufferRef` (a real, matching-token grant), so a
    /// fuzz caller can preserve it across a scalar-only mutation (see
    /// [`Self::overwrite_scalars`]).
    output_ref: BufferRef,
}

impl QuerySecurityFixture {
    /// A well-formed request: `security_information = OWNER|GROUP|DACL`
    /// (0x7), `flags = 0`, output grant exactly 65536 bytes.
    pub fn valid() -> Self {
        Self::build(0x7, 0, QUERY_SECURITY_OUTPUT_LEN)
    }

    /// A provider-facing query for the exact retained open and accepted
    /// security-information mask.
    pub fn provider(kernel_open_id: u64, security_information: u32) -> Self {
        let mut fixture = Self::build(security_information, 0, QUERY_SECURITY_OUTPUT_LEN);
        fixture.sqe.kernel_open_id = kernel_open_id;
        fixture
    }

    /// `security_information = 0x10` (LABEL) — outside `QUERY_ACCEPTED_MASK`
    /// (0x0F), an ABI mask fault.
    pub fn with_bad_mask() -> Self {
        Self::build(0x10, 0, QUERY_SECURITY_OUTPUT_LEN)
    }

    /// A nonzero `flags` field — ABI 2.1 requires `flags == 0`.
    pub fn with_nonzero_flags() -> Self {
        Self::build(0x7, 1, QUERY_SECURITY_OUTPUT_LEN)
    }

    /// An `output` grant of `len` bytes (anything other than exactly 65536 is
    /// illegal).
    pub fn with_bad_output_len(len: u32) -> Self {
        Self::build(0x7, 0, len)
    }

    /// Borrow the backing section (feeds `decode_query_security`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` QUERY_SECURITY round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    /// Overwrite the control blob slot (this fixture's full 40-byte
    /// `QuerySecurityV1` length) with arbitrary bytes (fuzz hook): the outer
    /// grant + SQE stay valid, so `decode_query_security` reaches `try_decode`
    /// + `validate_query_security_v1` over an attacker-chosen blob.
    pub fn overwrite_blob(&self, bytes: &[u8]) {
        let mut blob = vec![0u8; self.blob_len];
        let n = bytes.len().min(self.blob_len);
        blob[..n].copy_from_slice(&bytes[..n]);
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &blob);
    }

    /// Overwrite the 40-byte blob's scalar prefix (`header` +
    /// `security_information` + `flags`, bytes `[0..16]`) with up to 16 fuzz
    /// bytes, while re-encoding the real issued `output` grant into bytes
    /// `[16..40]` (a `BufferRef` is exactly 24 bytes). Unlike
    /// [`Self::overwrite_blob`], this keeps `output.token` a token the grant
    /// table actually issued, so `decode_query_security` reliably passes
    /// `grant_for` and reaches `validate_query_security_v1`'s mask/flags/
    /// length checks instead of almost always bailing at `UnknownToken` on an
    /// arbitrary fuzzed token.
    pub fn overwrite_scalars(&self, bytes: &[u8]) {
        let mut blob = [0u8; 40];
        let n = bytes.len().min(16);
        blob[..n].copy_from_slice(&bytes[..n]);
        try_encode(&self.output_ref, &mut blob[16..40]).expect("BufferRef fits its 24 bytes");
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &blob);
    }

    fn build(security_information: u32, flags: u32, output_len: u32) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        // U2K output grant where the daemon would write the security descriptor.
        let output_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), output_len)
            .expect("output grant");

        let blob_len = core::mem::size_of::<QuerySecurityV1>();
        let request = QuerySecurityV1 {
            header: ControlHeader {
                struct_size: blob_len as u32,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            security_information,
            flags,
            output: output_ref,
        };
        let mut blob = vec![0u8; blob_len];
        try_encode(&request, &mut blob).expect("QuerySecurityV1 fits its 40-byte layout");
        let blob_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), blob_len as u32)
            .expect("blob grant");
        harness.write_slot(&k2u, tok(0, 0), &blob);

        let sqe = pcontrol_sqe(op::QUERY_SECURITY, OPEN_REQ_ID, &blob_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            blob_len,
            output_ref,
        }
    }
}

/// The minimum legal U2K `output` grant length `QueryInfoV1.output` must carry
/// (`validate_query_info_v1`'s `output.length < 104` gate) — the fixture's
/// `valid()` uses exactly this minimum.
const QUERY_INFO_OUTPUT_LEN: u32 = 104;

/// A granted `QueryInfoV1` control blob (40B, fixed size, no tail) laid into a
/// K2U slot, plus a U2K `output` grant, plus the `QUERY_INFO` SQE whose
/// `PControl` echoes the blob grant. Kernel-role fixture for
/// [`crate::queryinfo::decode_query_info`].
pub struct QueryInfoFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
}

impl QueryInfoFixture {
    /// A well-formed request: `info_class = CANONICAL`, `flags = 0`,
    /// `reserved = 0`, output grant exactly 104 bytes (the minimum legal
    /// length).
    pub fn valid() -> Self {
        Self::build(query_info_class::CANONICAL, QUERY_INFO_OUTPUT_LEN)
    }

    /// A canonical provider query for one exact retained open.
    pub fn provider(kernel_open_id: u64) -> Self {
        let mut fixture = Self::valid();
        fixture.sqe.kernel_open_id = kernel_open_id;
        fixture
    }

    /// `info_class = INVALID` (0) — not the ABI's `CANONICAL` (1) class.
    pub fn with_bad_class() -> Self {
        Self::build(query_info_class::INVALID, QUERY_INFO_OUTPUT_LEN)
    }

    /// An `output` grant of `len` bytes (anything below 104 is illegal).
    pub fn with_bad_output_len(len: u32) -> Self {
        Self::build(query_info_class::CANONICAL, len)
    }

    /// Borrow the backing section (feeds `decode_query_info`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` QUERY_INFO round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    fn build(info_class: u16, output_len: u32) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        // U2K output grant where the daemon would write the FileInfoV1.
        let output_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), output_len)
            .expect("output grant");

        let blob_len = core::mem::size_of::<QueryInfoV1>();
        let request = QueryInfoV1 {
            header: ControlHeader {
                struct_size: blob_len as u32,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            info_class,
            flags: 0,
            reserved: 0,
            output: output_ref,
        };
        let mut blob = vec![0u8; blob_len];
        try_encode(&request, &mut blob).expect("QueryInfoV1 fits its 40-byte layout");
        let blob_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), blob_len as u32)
            .expect("blob grant");
        harness.write_slot(&k2u, tok(0, 0), &blob);

        let sqe = pcontrol_sqe(op::QUERY_INFO, OPEN_REQ_ID, &blob_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
        }
    }
}

/// The minimum legal U2K `output` grant length `QueryVolumeV1.output` must
/// carry (`validate_query_volume_v1`'s `output.length < 40` gate) — the
/// fixture's `valid()` uses exactly this minimum.
const QUERY_VOLUME_OUTPUT_LEN: u32 = 40;

/// A granted `QueryVolumeV1` control blob (40B, fixed size, no tail) laid
/// into a K2U slot, plus a U2K `output` grant, plus the `QUERY_VOLUME` SQE
/// whose `PControl` echoes the blob grant. Kernel-role fixture for
/// [`crate::queryvolume::decode_query_volume`].
pub struct QueryVolumeFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
}

impl QueryVolumeFixture {
    /// A well-formed request: `info_class = SIZE`, `flags = 0`,
    /// `reserved = 0`, output grant exactly 40 bytes (the minimum legal
    /// length).
    pub fn valid() -> Self {
        Self::build(query_volume_class::SIZE, QUERY_VOLUME_OUTPUT_LEN)
    }

    /// A canonical provider volume-size query.
    pub fn provider() -> Self {
        Self::valid()
    }

    /// `info_class = INVALID` (0) — not the ABI's `SIZE` (1) class.
    pub fn with_bad_class() -> Self {
        Self::build(query_volume_class::INVALID, QUERY_VOLUME_OUTPUT_LEN)
    }

    /// An `output` grant of `len` bytes (anything below 40 is illegal).
    pub fn with_bad_output_len(len: u32) -> Self {
        Self::build(query_volume_class::SIZE, len)
    }

    /// Borrow the backing section (feeds `decode_query_volume`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` QUERY_VOLUME round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    fn build(info_class: u16, output_len: u32) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        // U2K output grant where the daemon would write the VolumeSizeInfoV1.
        let output_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), output_len)
            .expect("output grant");

        let blob_len = core::mem::size_of::<QueryVolumeV1>();
        let request = QueryVolumeV1 {
            header: ControlHeader {
                struct_size: blob_len as u32,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            info_class,
            flags: 0,
            reserved: 0,
            output: output_ref,
        };
        let mut blob = vec![0u8; blob_len];
        try_encode(&request, &mut blob).expect("QueryVolumeV1 fits its 40-byte layout");
        let blob_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), blob_len as u32)
            .expect("blob grant");
        harness.write_slot(&k2u, tok(0, 0), &blob);

        let sqe = pcontrol_sqe(op::QUERY_VOLUME, OPEN_REQ_ID, &blob_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
        }
    }
}

/// Fixed identities for the mutation fixtures (nonzero, distinct).
const MUT_OP: OpId = OpId { lo: 0x11, hi: 0 };
const MUT_SOURCE_LINK: LinkId = LinkId { lo: 0x22, hi: 0 };
const MUT_TARGET_PARENT: FileId = FileId { lo: 0x33, hi: 0 };
const MUT_SOURCE_FILE: FileId = FileId { lo: 0x44, hi: 0 };
const MUT_UNLINK_PARENT: FileId = FileId { lo: 0x55, hi: 0 };
const MUT_GEN: u64 = 1;

fn mut_name_bytes() -> Vec<u8> {
    "a.txt"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

fn align8_usize(n: usize) -> usize {
    (n + 7) & !7
}

/// A granted `MutationV2` (a rename/link/unlink or an out-of-scope kind) laid
/// into a heap section, plus the K2U body grant, the U2K reply/kind_result
/// grants, and the `MUTATE` SQE whose `PControl` echoes the envelope grant.
/// Kernel-role fixture for the `mutation` module.
pub struct MutationFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
    /// The RENAME/UNLINK source link id the fixture used (for a result effect).
    pub source_link_id: LinkId,
    /// The LINK source file id the fixture used.
    pub source_file_id: FileId,
    /// The K2U body grant length (so `overwrite_body` fills the whole slot).
    body_len: usize,
}

/// The default (valid) SET_SECURITY descriptor length used by every fixture
/// except `set_security_bad_descriptor_len`.
const DEFAULT_SECURITY_DESCRIPTOR_LEN: u32 = 20;

/// Semantic inputs for a provider-facing mutation fixture. Each variant is
/// encoded into its frozen ABI body and then consumed only through
/// [`crate::mutation::decode_mutation`].
pub enum ProviderMutation {
    Rename {
        source_link_id: LinkId,
        target_parent_id: FileId,
        expected_source_parent_generation: u64,
        expected_target_parent_generation: u64,
        name: String,
        flags: u32,
    },
    Link {
        source_file_id: FileId,
        target_parent_id: FileId,
        expected_target_parent_generation: u64,
        name: String,
        flags: u32,
    },
    Unlink {
        link_id: LinkId,
        parent_id: FileId,
        expected_parent_generation: u64,
        flags: u32,
    },
    SetBasicInfo {
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        attributes: u32,
        set_mask: u32,
    },
    SetAllocationSize {
        new_size: u64,
    },
    SetEndOfFile {
        new_size: u64,
    },
    SetValidDataLength {
        new_size: u64,
    },
    SetSecurity {
        security_information: u32,
        descriptor: Vec<u8>,
    },
}

impl MutationFixture {
    /// Build a provider-facing mutation with exact caller identities,
    /// generations and retained open id. This function constructs the real
    /// `MutationV2` and kind body grants; callers still obtain semantic state
    /// exclusively by invoking the public decoder.
    pub fn provider(
        kernel_open_id: u64,
        op_id: OpId,
        expected_namespace_generation: u64,
        expected_size_epoch: u64,
        expected_security_generation: u64,
        mutation: ProviderMutation,
    ) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        let (kind, body_blob, source_link_id, source_file_id) = match mutation {
            ProviderMutation::Rename {
                source_link_id,
                target_parent_id,
                expected_source_parent_generation,
                expected_target_parent_generation,
                name,
                flags,
            } => {
                let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let size = align8_usize(72 + name.len());
                let raw = RenameV1 {
                    header: ControlHeader {
                        struct_size: size as u32,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    source_link_id,
                    target_parent_id,
                    expected_source_parent_generation,
                    expected_target_parent_generation,
                    name: BlobSlice {
                        offset: 72,
                        length: name.len() as u32,
                    },
                    flags,
                    reserved: 0,
                };
                let mut body = vec![0; size];
                try_encode(&raw, &mut body[..72]).expect("RenameV1 fits");
                body[72..72 + name.len()].copy_from_slice(&name);
                (mutation_kind::RENAME, body, source_link_id, FileId::ZERO)
            }
            ProviderMutation::Link {
                source_file_id,
                target_parent_id,
                expected_target_parent_generation,
                name,
                flags,
            } => {
                let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let size = align8_usize(64 + name.len());
                let raw = LinkV1 {
                    header: ControlHeader {
                        struct_size: size as u32,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    source_file_id,
                    target_parent_id,
                    expected_target_parent_generation,
                    name: BlobSlice {
                        offset: 64,
                        length: name.len() as u32,
                    },
                    flags,
                    reserved: 0,
                };
                let mut body = vec![0; size];
                try_encode(&raw, &mut body[..64]).expect("LinkV1 fits");
                body[64..64 + name.len()].copy_from_slice(&name);
                (mutation_kind::LINK, body, LinkId::ZERO, source_file_id)
            }
            ProviderMutation::Unlink {
                link_id,
                parent_id,
                expected_parent_generation,
                flags,
            } => {
                let raw = UnlinkV1 {
                    header: ControlHeader {
                        struct_size: 56,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    link_id,
                    parent_id,
                    expected_parent_generation,
                    flags,
                    reserved: 0,
                };
                let mut body = vec![0; 56];
                try_encode(&raw, &mut body).expect("UnlinkV1 fits");
                (mutation_kind::UNLINK, body, link_id, FileId::ZERO)
            }
            ProviderMutation::SetBasicInfo {
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                attributes,
                set_mask,
            } => {
                let raw = SetBasicInfoV1 {
                    header: ControlHeader {
                        struct_size: 48,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    creation_time,
                    last_access_time,
                    last_write_time,
                    change_time,
                    attributes,
                    set_mask,
                };
                let mut body = vec![0; 48];
                try_encode(&raw, &mut body).expect("SetBasicInfoV1 fits");
                (
                    mutation_kind::SET_BASIC_INFO,
                    body,
                    LinkId::ZERO,
                    FileId::ZERO,
                )
            }
            ProviderMutation::SetAllocationSize { new_size } => {
                let raw = SetSizeV1 {
                    header: ControlHeader {
                        struct_size: 24,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    new_size,
                    flags: 0,
                    reserved: 0,
                };
                let mut body = vec![0; 24];
                try_encode(&raw, &mut body).expect("SetSizeV1 fits");
                (
                    mutation_kind::SET_ALLOCATION_SIZE,
                    body,
                    LinkId::ZERO,
                    FileId::ZERO,
                )
            }
            ProviderMutation::SetEndOfFile { new_size } => {
                let raw = SetSizeV1 {
                    header: ControlHeader {
                        struct_size: 24,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    new_size,
                    flags: 0,
                    reserved: 0,
                };
                let mut body = vec![0; 24];
                try_encode(&raw, &mut body).expect("SetSizeV1 fits");
                (
                    mutation_kind::SET_END_OF_FILE,
                    body,
                    LinkId::ZERO,
                    FileId::ZERO,
                )
            }
            ProviderMutation::SetValidDataLength { new_size } => {
                let raw = SetSizeV1 {
                    header: ControlHeader {
                        struct_size: 24,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    new_size,
                    flags: 0,
                    reserved: 0,
                };
                let mut body = vec![0; 24];
                try_encode(&raw, &mut body).expect("SetSizeV1 fits");
                (
                    mutation_kind::SET_VALID_DATA_LENGTH,
                    body,
                    LinkId::ZERO,
                    FileId::ZERO,
                )
            }
            ProviderMutation::SetSecurity {
                security_information,
                descriptor,
            } => {
                let size = align8_usize(24 + descriptor.len());
                let raw = SetSecurityV1 {
                    header: ControlHeader {
                        struct_size: size as u32,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    security_information,
                    flags: 0,
                    security_descriptor: BlobSlice {
                        offset: 24,
                        length: descriptor.len() as u32,
                    },
                };
                let mut body = vec![0; size];
                try_encode(&raw, &mut body[..24]).expect("SetSecurityV1 fits");
                body[24..24 + descriptor.len()].copy_from_slice(&descriptor);
                (
                    mutation_kind::SET_SECURITY,
                    body,
                    LinkId::ZERO,
                    FileId::ZERO,
                )
            }
        };

        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 1), body_blob.len() as u32)
            .expect("body grant");
        harness.write_slot(&k2u, tok(0, 1), &body_blob);
        let reply = table
            .issue_u2k(&u2k, owner, tok(1, 0), 112)
            .expect("reply grant");
        let kind_result = match kind {
            mutation_kind::RENAME => table
                .issue_u2k(&u2k, owner, tok(1, 1), 112)
                .expect("rename result grant"),
            mutation_kind::LINK => table
                .issue_u2k(&u2k, owner, tok(1, 1), 104)
                .expect("link result grant"),
            mutation_kind::UNLINK => table
                .issue_u2k(&u2k, owner, tok(1, 1), 56)
                .expect("unlink result grant"),
            _ => none_ref(),
        };
        let raw = MutationV2 {
            header: ControlHeader {
                struct_size: 128,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id,
            mutation_kind: kind,
            mutation_flags: 0,
            reserved: 0,
            expected_namespace_generation,
            expected_size_epoch,
            expected_security_generation,
            body: body_ref,
            reply,
            kind_result,
        };
        let mut envelope = [0; 128];
        try_encode(&raw, &mut envelope).expect("MutationV2 fits");
        let envelope_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 128)
            .expect("envelope grant");
        harness.write_slot(&k2u, tok(0, 0), &envelope);
        let mut sqe = pcontrol_sqe(op::MUTATE, OPEN_REQ_ID, &envelope_ref);
        sqe.kernel_open_id = kernel_open_id;
        Self {
            harness,
            table,
            sqe,
            owner,
            source_link_id,
            source_file_id,
            body_len: body_blob.len(),
        }
    }

    /// A well-formed RENAME (equal expected source/target parent generations).
    pub fn rename() -> Self {
        Self::build(
            mutation_kind::RENAME,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A RENAME whose body's expected target-parent generation differs from the
    /// source (so `same_parent_rename = true` must be rejected).
    pub fn rename_unequal_parents() -> Self {
        Self::build(
            mutation_kind::RENAME,
            false,
            false,
            true,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed LINK.
    pub fn link() -> Self {
        Self::build(
            mutation_kind::LINK,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed UNLINK.
    pub fn unlink() -> Self {
        Self::build(
            mutation_kind::UNLINK,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A RENAME whose envelope `op_id` is the zero pair (an identity fault).
    pub fn with_zero_op_id() -> Self {
        Self::build(
            mutation_kind::RENAME,
            true,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed `SET_BASIC_INFO` (creation-time only, no attributes).
    pub fn set_basic_info() -> Self {
        Self::build(
            mutation_kind::SET_BASIC_INFO,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed `SET_ALLOCATION_SIZE`.
    pub fn set_allocation_size() -> Self {
        Self::build(
            mutation_kind::SET_ALLOCATION_SIZE,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed `SET_END_OF_FILE`.
    pub fn set_end_of_file() -> Self {
        Self::build(
            mutation_kind::SET_END_OF_FILE,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed `SET_VALID_DATA_LENGTH`.
    pub fn set_valid_data_length() -> Self {
        Self::build(
            mutation_kind::SET_VALID_DATA_LENGTH,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A valid `SET_SPARSE` envelope (kind 11) — still-unimplementable; the
    /// envelope validator rejects it before body decode (`Message`).
    pub fn set_sparse() -> Self {
        Self::build(
            mutation_kind::SET_SPARSE,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A well-formed `SET_SECURITY` (a 20-byte zero descriptor tail — content
    /// validity is a WDK gate, out of this crate's scope).
    pub fn set_security() -> Self {
        Self::build(
            mutation_kind::SET_SECURITY,
            false,
            false,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }
    /// A `SET_SECURITY` whose `security_descriptor.length` (19) is below
    /// `MIN_SECURITY_DESCRIPTOR_BYTES` (20) — a body-validator reject.
    pub fn set_security_bad_descriptor_len() -> Self {
        Self::build(mutation_kind::SET_SECURITY, false, false, false, 19)
    }
    /// A RENAME whose body `source_link_id` is the zero pair (a body fault).
    pub fn rename_with_zero_source_link() -> Self {
        Self::build(
            mutation_kind::RENAME,
            false,
            true,
            false,
            DEFAULT_SECURITY_DESCRIPTOR_LEN,
        )
    }

    /// Borrow the backing section (feeds the single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` MUTATE round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    /// Overwrite the 128-byte `MutationV2` envelope slot with arbitrary bytes
    /// (fuzz hook): the outer grant + SQE stay valid, so `decode_mutation`
    /// reaches `try_decode` + `validate_mutation_v2` over an attacker-chosen
    /// envelope.
    pub fn overwrite_env(&self, bytes: &[u8]) {
        let mut blob = [0u8; 128];
        let n = bytes.len().min(blob.len());
        blob[..n].copy_from_slice(&bytes[..n]);
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 0), &blob);
    }

    /// Overwrite the K2U body slot with arbitrary bytes (fuzz hook): the envelope
    /// and its grants stay valid, so `decode_mutation` reaches `try_decode` +
    /// `validate_mutation_body_v21` + `owned_name` over an attacker-chosen body.
    pub fn overwrite_body(&self, bytes: &[u8]) {
        let mut blob = vec![0u8; self.body_len];
        let n = bytes.len().min(blob.len());
        blob[..n].copy_from_slice(&bytes[..n]);
        self.harness
            .write_slot(&self.harness.k2u_arena(), tok(0, 1), &blob);
    }

    fn build(
        kind: u16,
        zero_op_id: bool,
        zero_source_link: bool,
        unequal_target_gen: bool,
        security_descriptor_len: u32,
    ) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(OPEN_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        // The kind body blob (K2U). An out-of-scope kind is rejected before its
        // body is decoded, so a fixed 48-byte zero body satisfies the length floor.
        let name = mut_name_bytes();
        let body_blob: Vec<u8> = match kind {
            mutation_kind::RENAME => {
                let ss = align8_usize(72 + name.len());
                let record = RenameV1 {
                    header: ControlHeader {
                        struct_size: ss as u32,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    source_link_id: if zero_source_link {
                        LinkId { lo: 0, hi: 0 }
                    } else {
                        MUT_SOURCE_LINK
                    },
                    target_parent_id: MUT_TARGET_PARENT,
                    expected_source_parent_generation: MUT_GEN,
                    expected_target_parent_generation: if unequal_target_gen {
                        MUT_GEN + 1
                    } else {
                        MUT_GEN
                    },
                    name: BlobSlice {
                        offset: 72,
                        length: name.len() as u32,
                    },
                    flags: 0,
                    reserved: 0,
                };
                let mut b = vec![0u8; ss];
                try_encode(&record, &mut b[..72]).expect("RenameV1 fits 72");
                b[72..72 + name.len()].copy_from_slice(&name);
                b
            }
            mutation_kind::LINK => {
                let ss = align8_usize(64 + name.len());
                let record = LinkV1 {
                    header: ControlHeader {
                        struct_size: ss as u32,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    source_file_id: MUT_SOURCE_FILE,
                    target_parent_id: MUT_TARGET_PARENT,
                    expected_target_parent_generation: MUT_GEN,
                    name: BlobSlice {
                        offset: 64,
                        length: name.len() as u32,
                    },
                    flags: 0,
                    reserved: 0,
                };
                let mut b = vec![0u8; ss];
                try_encode(&record, &mut b[..64]).expect("LinkV1 fits 64");
                b[64..64 + name.len()].copy_from_slice(&name);
                b
            }
            mutation_kind::UNLINK => {
                let record = UnlinkV1 {
                    header: ControlHeader {
                        struct_size: 56,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    link_id: MUT_SOURCE_LINK,
                    parent_id: MUT_UNLINK_PARENT,
                    expected_parent_generation: MUT_GEN,
                    flags: 0,
                    reserved: 0,
                };
                let mut b = vec![0u8; 56];
                try_encode(&record, &mut b).expect("UnlinkV1 fits 56");
                b
            }
            mutation_kind::SET_BASIC_INFO => {
                let record = SetBasicInfoV1 {
                    header: ControlHeader {
                        struct_size: 48,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    creation_time: 0x01D9_0000_0000_0001,
                    last_access_time: 0,
                    last_write_time: 0,
                    change_time: 0,
                    attributes: 0,
                    set_mask: 0x1, // CREATION_TIME
                };
                let mut b = vec![0u8; 48];
                try_encode(&record, &mut b).expect("SetBasicInfoV1 fits 48");
                b
            }
            mutation_kind::SET_ALLOCATION_SIZE
            | mutation_kind::SET_END_OF_FILE
            | mutation_kind::SET_VALID_DATA_LENGTH => {
                let record = SetSizeV1 {
                    header: ControlHeader {
                        struct_size: 24,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    new_size: 4096,
                    flags: 0,
                    reserved: 0,
                };
                let mut b = vec![0u8; 24];
                try_encode(&record, &mut b).expect("SetSizeV1 fits 24");
                b
            }
            mutation_kind::SET_SECURITY => {
                let ss = align8_usize(24 + security_descriptor_len as usize);
                let record = SetSecurityV1 {
                    header: ControlHeader {
                        struct_size: ss as u32,
                        struct_version: CONTROL_VERSION_V1,
                        required_flags: 0,
                    },
                    security_information: 0x4, // DACL ⊆ SET_MASK
                    flags: 0,
                    security_descriptor: BlobSlice {
                        offset: 24,
                        length: security_descriptor_len,
                    },
                };
                let mut b = vec![0u8; ss];
                try_encode(&record, &mut b[..24]).expect("SetSecurityV1 fits 24");
                b
            }
            // SET_SPARSE (11) — still-unimplementable; the envelope validator
            // itself rejects it before body decode, so content is irrelevant.
            _ => vec![0u8; 48],
        };

        // Grants: body (K2U), reply (U2K 112), kind_result (U2K 112/104/56 for
        // rename/link/unlink, else a NONE reference).
        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 1), body_blob.len() as u32)
            .expect("body grant");
        harness.write_slot(&k2u, tok(0, 1), &body_blob);
        let reply_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), 112)
            .expect("reply grant");
        let kind_result_ref = match kind {
            mutation_kind::RENAME => table.issue_u2k(&u2k, owner, tok(1, 1), 112).expect("kr"),
            mutation_kind::LINK => table.issue_u2k(&u2k, owner, tok(1, 1), 104).expect("kr"),
            mutation_kind::UNLINK => table.issue_u2k(&u2k, owner, tok(1, 1), 56).expect("kr"),
            _ => BufferRef {
                token: 0,
                offset: 0,
                length: 0,
                kind: buffer_kind::NONE,
                access: 0,
                reserved: 0,
            },
        };

        // The envelope generation shape is kind-dependent (validate_mutation_v2).
        let namespace_kind = matches!(
            kind,
            mutation_kind::SET_BASIC_INFO
                | mutation_kind::RENAME
                | mutation_kind::LINK
                | mutation_kind::UNLINK
                | mutation_kind::SET_REPARSE
                | mutation_kind::DELETE_REPARSE
        );
        let size_kind = matches!(
            kind,
            mutation_kind::SET_ALLOCATION_SIZE
                | mutation_kind::SET_END_OF_FILE
                | mutation_kind::SET_VALID_DATA_LENGTH
        );
        let security_kind = kind == mutation_kind::SET_SECURITY;
        let envelope = MutationV2 {
            header: ControlHeader {
                struct_size: 128,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id: if zero_op_id {
                OpId { lo: 0, hi: 0 }
            } else {
                MUT_OP
            },
            mutation_kind: kind,
            mutation_flags: 0,
            reserved: 0,
            expected_namespace_generation: if namespace_kind { MUT_GEN } else { 0 },
            expected_size_epoch: if size_kind { MUT_GEN } else { 0 },
            expected_security_generation: if security_kind { MUT_GEN } else { 0 },
            body: body_ref,
            reply: reply_ref,
            kind_result: kind_result_ref,
        };
        let mut env_blob = [0u8; 128];
        try_encode(&envelope, &mut env_blob).expect("MutationV2 fits 128");
        let env_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 128)
            .expect("envelope grant");
        harness.write_slot(&k2u, tok(0, 0), &env_blob);

        let sqe = pcontrol_sqe(op::MUTATE, OPEN_REQ_ID, &env_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            source_link_id: MUT_SOURCE_LINK,
            source_file_id: MUT_SOURCE_FILE,
            body_len: body_blob.len(),
        }
    }
}

const READ_REQ_ID: u64 = 0x0004_0000_0001;
/// The default READ `length` (and matching `data` grant length) the fixture
/// builds — nonzero, so `validate_rw_scalars` classifies it `Emit` rather than
/// the `LocalOnlyWireForm`-rejected `CompleteLocally` (a zero-length request).
const READ_DEFAULT_LEN: u32 = 4096;

/// A granted `PRw` READ request laid inline into an SQE's payload (never a
/// `PControl` indirection — READ's fixed 80-byte record fits the 88-byte SQE
/// payload directly), plus the U2K `data` grant the daemon will later write the
/// fetched bytes into. Kernel-role fixture for [`crate::dataio::decode_read`].
pub struct ReadFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
}

impl ReadFixture {
    /// A well-formed READ: `op_id` zero, `data.length == length` (4096).
    pub fn valid() -> Self {
        Self::build(OpId { lo: 0, hi: 0 }, READ_DEFAULT_LEN, READ_DEFAULT_LEN)
    }

    /// A provider-facing positional READ for an exact retained open.
    pub fn provider(kernel_open_id: u64, offset: u64, size_epoch: u64, length: u32) -> Self {
        let mut fixture = Self::build(OpId::ZERO, length, length);
        let data = fixture
            .table
            .grant_for(tok(1, 0).raw())
            .expect("fixture data grant")
            .issued;
        let raw = PRw {
            op_id: OpId::ZERO,
            offset,
            size_epoch,
            initialized_offset: 0,
            data,
            length,
            initialized_length: 0,
            rw_flags: 0,
            reserved: 0,
        };
        try_encode(
            &raw,
            &mut fixture.sqe.payload[..core::mem::size_of::<PRw>()],
        )
        .expect("PRw fits");
        fixture.sqe.kernel_open_id = kernel_open_id;
        fixture
    }

    /// A READ whose `op_id` is nonzero — READ requires `OpId::ZERO` (an
    /// identity fault).
    pub fn with_nonzero_op_id() -> Self {
        Self::build(OpId { lo: 0x11, hi: 0 }, READ_DEFAULT_LEN, READ_DEFAULT_LEN)
    }

    /// A READ whose `data` grant length (2048) disagrees with the request
    /// `length` (4096) — a body relationship fault.
    pub fn with_length_mismatch() -> Self {
        Self::build(OpId { lo: 0, hi: 0 }, READ_DEFAULT_LEN, 2048)
    }

    /// A valid READ whose SQE `payload_len` is overwritten to `payload_len` (not
    /// the 80-byte `PRw` size) — the inline framing check
    /// (`payload_len != size_of::<PRw>()`) rejects it before decode, exercising
    /// the `DataIoError::Control(WrongLength)` path.
    pub fn with_bad_payload_len(payload_len: u16) -> Self {
        let mut fx = Self::valid();
        fx.sqe.payload_len = payload_len;
        fx
    }

    /// A valid READ with a nonzero byte set in the SQE payload tail (`[80..88]`,
    /// past the inline `PRw`) — the zero-tail framing check rejects it,
    /// exercising the `DataIoError::Control(NonZeroTail)` path.
    pub fn with_nonzero_tail() -> Self {
        let mut fx = Self::valid();
        fx.sqe.payload[core::mem::size_of::<PRw>()] = 1;
        fx
    }

    /// Borrow the backing section (unused by `decode_read` itself — READ has
    /// no variable-length tail to single-fetch — but the U2K `data` grant the
    /// daemon writes the fetched bytes into lives here).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces (see
    /// [`QueryDirFixture::into_parts`]) for a full `Daemon` READ round-trip.
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    fn build(op_id: OpId, length: u32, data_grant_len: u32) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(READ_REQ_ID));
        let u2k = harness.u2k_arena();

        // READ's data buffer is U2K_WRITE: an output slot the daemon writes the
        // fetched bytes into later. The fixture only needs a live grant.
        let data_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), data_grant_len)
            .expect("data grant");

        let request = PRw {
            op_id,
            offset: 0,
            size_epoch: 1,
            initialized_offset: 0,
            data: data_ref,
            length,
            initialized_length: 0,
            rw_flags: 0,
            reserved: 0,
        };
        let prw_len = core::mem::size_of::<PRw>();
        let mut payload = [0u8; SQE_PAYLOAD_LEN];
        try_encode(&request, &mut payload[..prw_len]).expect("PRw fits its 80-byte payload");

        let sqe = SqeBody {
            opcode: op::READ,
            flags: 0,
            payload_len: prw_len as u16,
            reserved: 0,
            req_id: READ_REQ_ID,
            kernel_open_id: 0,
            ccb_sequence: 0,
            payload,
        };
        Self {
            harness,
            table,
            sqe,
            owner,
        }
    }
}

const WRITE_REQ_ID: u64 = 0x0005_0000_0001;
/// The default WRITE `length` (and matching K2U `data` grant length) the
/// fixture builds.
const WRITE_DEFAULT_LEN: u32 = 4096;
/// The minimum legal `reply` grant length (`validate_write_v2` requires
/// `reply.length >= 56`).
const WRITE_DEFAULT_REPLY_LEN: u32 = 56;

#[derive(Clone, Copy)]
struct WriteOverrides {
    zero_op_id: bool,
    zero_expected_size_epoch: bool,
    reply_len: u32,
}

impl Default for WriteOverrides {
    fn default() -> Self {
        Self {
            zero_op_id: false,
            zero_expected_size_epoch: false,
            reply_len: WRITE_DEFAULT_REPLY_LEN,
        }
    }
}

/// A granted `WriteV2` laid into a heap section (a `PControl` body grant, like
/// `MutationV2`), plus the K2U `data` grant holding the caller's write bytes,
/// the U2K `reply` grant, and the `WRITE` SQE whose `PControl` echoes the
/// 112-byte body grant. Kernel-role fixture for [`crate::dataio::decode_write`].
pub struct WriteFixture {
    harness: Harness,
    pub table: GrantTable,
    pub sqe: SqeBody,
    pub owner: GrantOwner,
    /// The bytes written into the K2U `data` slot — what `decode_write` must
    /// single-fetch back out.
    pub data_bytes: Vec<u8>,
}

impl WriteFixture {
    /// A well-formed WRITE: nonzero `op_id`, nonzero `expected_size_epoch`, a
    /// 4096-byte K2U `data` grant, a 56-byte U2K `reply` grant.
    pub fn valid() -> Self {
        Self::build(WriteOverrides::default())
    }

    /// A well-formed WRITE with caller-supplied bytes. This keeps focused
    /// dispatcher tests small while exercising the same granted envelope path
    /// as the default 4096-byte fixture.
    pub fn with_data_bytes(data_bytes: Vec<u8>) -> Self {
        Self::build_with_data(WriteOverrides::default(), data_bytes)
    }

    /// A provider-facing positional WRITE for an exact retained open and
    /// caller-supplied expected size epoch.
    pub fn provider(
        kernel_open_id: u64,
        op_id: OpId,
        offset: u64,
        expected_size_epoch: u64,
        data_bytes: Vec<u8>,
    ) -> Self {
        let mut fixture = Self::build_with_data(WriteOverrides::default(), data_bytes);
        let data = fixture
            .table
            .grant_for(tok(0, 1).raw())
            .expect("fixture data grant")
            .issued;
        let reply = fixture
            .table
            .grant_for(tok(1, 0).raw())
            .expect("fixture reply grant")
            .issued;
        let raw = WriteV2 {
            header: ControlHeader {
                struct_size: 112,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id,
            offset,
            expected_size_epoch,
            initialized_offset: 0,
            data,
            length: fixture.data_bytes.len() as u32,
            initialized_length: 0,
            rw_flags: 0,
            reserved: 0,
            reply,
        };
        let mut body = [0u8; 112];
        try_encode(&raw, &mut body).expect("WriteV2 fits");
        fixture
            .harness
            .write_slot(&fixture.harness.k2u_arena(), tok(0, 0), &body);
        fixture.sqe.kernel_open_id = kernel_open_id;
        fixture
    }

    /// A WRITE whose `op_id` is the zero pair — an identity fault (WRITE
    /// requires a nonzero `OpId`, the opposite of READ).
    pub fn with_zero_op_id() -> Self {
        Self::build(WriteOverrides {
            zero_op_id: true,
            ..Default::default()
        })
    }

    /// A WRITE whose `expected_size_epoch` is zero — an identity fault.
    pub fn with_zero_expected_size_epoch() -> Self {
        Self::build(WriteOverrides {
            zero_expected_size_epoch: true,
            ..Default::default()
        })
    }

    /// Borrow the backing section (feeds `decode_write`'s single-fetch).
    pub fn section(&self) -> &HeapSection {
        self.harness.section()
    }

    /// Consume the fixture into its owned pieces so a caller can drive a full
    /// `Daemon` WRITE round-trip (see [`QueryDirFixture::into_parts`]).
    pub fn into_parts(self) -> (Harness, GrantTable, SqeBody, GrantOwner) {
        (self.harness, self.table, self.sqe, self.owner)
    }

    fn build(ov: WriteOverrides) -> Self {
        let data_bytes: Vec<u8> = (0..WRITE_DEFAULT_LEN).map(|i| (i % 256) as u8).collect();
        Self::build_with_data(ov, data_bytes)
    }

    fn build_with_data(ov: WriteOverrides, data_bytes: Vec<u8>) -> Self {
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(WRITE_REQ_ID));
        let k2u = harness.k2u_arena();
        let u2k = harness.u2k_arena();

        let data_ref = table
            .issue_k2u(&k2u, owner, tok(0, 1), data_bytes.len() as u32)
            .expect("data grant");
        harness.write_slot(&k2u, tok(0, 1), &data_bytes);

        let reply_ref = table
            .issue_u2k(&u2k, owner, tok(1, 0), ov.reply_len)
            .expect("reply grant");

        let write = WriteV2 {
            header: ControlHeader {
                struct_size: 112,
                struct_version: CONTROL_VERSION_V2,
                required_flags: 0,
            },
            op_id: if ov.zero_op_id {
                OpId { lo: 0, hi: 0 }
            } else {
                OpId { lo: 0x11, hi: 0 }
            },
            offset: 0,
            expected_size_epoch: if ov.zero_expected_size_epoch { 0 } else { 1 },
            initialized_offset: 0,
            data: data_ref,
            length: data_bytes.len() as u32,
            initialized_length: 0,
            rw_flags: 0,
            reserved: 0,
            reply: reply_ref,
        };
        let mut body = [0u8; 112];
        try_encode(&write, &mut body).expect("WriteV2 fits its 112-byte body");
        let body_ref = table
            .issue_k2u(&k2u, owner, tok(0, 0), 112)
            .expect("body grant");
        harness.write_slot(&k2u, tok(0, 0), &body);

        let sqe = pcontrol_sqe(op::WRITE, WRITE_REQ_ID, &body_ref);
        Self {
            harness,
            table,
            sqe,
            owner,
            data_bytes,
        }
    }
}

/// A generically-valid `SizeState` (allocation >= file >= valid, nonzero
/// epoch) reused by every canned effect below that isn't itself a size-kind
/// mutation (which instead needs a size relationship tied to its own fixed
/// `new_size` body — see [`stub_mutation_effect`]).
fn stub_sizes() -> SizeState {
    SizeState {
        allocation_size: 8192,
        file_size: 4096,
        valid_data_length: 4096,
        size_epoch: 2,
    }
}

/// A `MutationEffect` shaped to `request.mutation_kind()`: the namespace
/// kinds (RENAME/LINK/UNLINK/SET_BASIC_INFO) get `namespace_generation = 2`
/// (exceeding every fixture's `MUT_GEN = 1`); `SET_SECURITY` zeroes the
/// namespace lane and carries `security_generation = 2`; the three size kinds
/// carry a `SizeState` relationship matching the fixtures' fixed
/// `new_size = 4096` body (mirroring `mutation.rs`'s own `size_effect` test
/// helper, so the frozen success validator's per-kind size-coverage rule
/// accepts it).
fn stub_mutation_effect(request: &MutationRequest) -> MutationEffect {
    let flat = SizeState {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        size_epoch: 1,
    };
    let base = MutationEffect {
        file_id: FileId { lo: 0x100, hi: 0 },
        new_link_id: LinkId { lo: 0x101, hi: 0 },
        replaced: None,
        link_count: 1,
        namespace_generation: 2,
        source_parent_generation: 2,
        target_parent_generation: 2,
        parent_generation: 2,
        sizes: flat,
        retained_sizes: flat,
        volume_commit_sequence: 5,
        security_generation: 0,
    };
    match request.mutation_kind() {
        mutation_kind::SET_SECURITY => MutationEffect {
            namespace_generation: 0,
            security_generation: 2,
            ..base
        },
        mutation_kind::SET_ALLOCATION_SIZE => MutationEffect {
            namespace_generation: 0,
            sizes: SizeState {
                allocation_size: 8192,
                file_size: 4096,
                valid_data_length: 4096,
                size_epoch: 2,
            },
            retained_sizes: SizeState {
                allocation_size: 4096,
                file_size: 4096,
                valid_data_length: 4096,
                size_epoch: 1,
            },
            ..base
        },
        mutation_kind::SET_END_OF_FILE => MutationEffect {
            namespace_generation: 0,
            sizes: SizeState {
                allocation_size: 8192,
                file_size: 4096,
                valid_data_length: 2048,
                size_epoch: 2,
            },
            retained_sizes: SizeState {
                allocation_size: 8192,
                file_size: 2048,
                valid_data_length: 2048,
                size_epoch: 1,
            },
            ..base
        },
        mutation_kind::SET_VALID_DATA_LENGTH => MutationEffect {
            namespace_generation: 0,
            sizes: SizeState {
                allocation_size: 8192,
                file_size: 4096,
                valid_data_length: 4096,
                size_epoch: 2,
            },
            retained_sizes: SizeState {
                allocation_size: 8192,
                file_size: 4096,
                valid_data_length: 2048,
                size_epoch: 1,
            },
            ..base
        },
        // RENAME / LINK / UNLINK / SET_BASIC_INFO: namespace kinds, base as-is.
        _ => base,
    }
}

/// A deterministic stub [`FileSystem`]: every method returns a canned,
/// internally-consistent effect sized to validate against the frozen success
/// validators for the per-op fixtures above (every generation a fixture
/// compares against — `MUT_GEN`/`expected_namespace_generation`/
/// `expected_security_generation`, all `1` — is strictly exceeded here).
/// Four fields are test-configurable (the READ fill count, the WRITE count, the
/// QUERY_DIR candidates, and the QUERY_SECURITY descriptor); every other method
/// returns a fixed canned value. The four bookkeeping vectors record the
/// abort/cleanup/close/flush calls for assertion.
pub struct StubFileSystem {
    /// `read` fills this many bytes of the caller's buffer with a fixed
    /// `i % 251` pattern and returns that count (capped to `buf.len()`); `0`
    /// drives the `END_OF_FILE` completion path.
    pub read_returns: usize,
    /// `Some(n)` makes `write` report exactly `n` bytes. The daemon must reject
    /// zero or a count beyond the request and preserve an in-range partial
    /// count; `None` reports the full request length.
    pub write_information: Option<u32>,
    /// `query_dir` returns exactly this candidate set, in order.
    pub query_dir_candidates: Vec<DirCandidate>,
    /// `query_security` returns exactly these bytes (default: a valid 20-byte
    /// descriptor; a caller wanting a specific one sets this before driving).
    pub query_security_descriptor: Vec<u8>,
    /// `abort` calls, in order.
    pub aborted: Vec<TransactionId>,
    /// `cleanup` calls, in order.
    pub cleaned_up: Vec<u64>,
    /// `close` calls, in order.
    pub closed: Vec<u64>,
    /// `flush` calls, in order.
    pub flushed: Vec<u64>,
}

impl Default for StubFileSystem {
    fn default() -> Self {
        Self {
            read_returns: 0,
            write_information: None,
            query_dir_candidates: Vec::new(),
            query_security_descriptor: vec![0xABu8; 20],
            aborted: Vec::new(),
            cleaned_up: Vec::new(),
            closed: Vec::new(),
            flushed: Vec::new(),
        }
    }
}

impl FileSystem for StubFileSystem {
    fn prepare(
        &mut self,
        _request: &PreparedRequest,
        _transaction_id: TransactionId,
    ) -> FileSystemResult<PrepareResult> {
        Ok(PrepareResult {
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: stub_sizes(),
            namespace_generation: 2,
            security_generation: 2,
            // A DISTINCTIVE non-zero 20-byte descriptor (`0,1,..,19`): the
            // PREPARE_OPEN drive test reads the result-SD grant back and asserts
            // it equals this, so a zero read-back (a missing write-back) is
            // unambiguous rather than aliasing a zero-init grant.
            security_descriptor: (0u8..20).collect::<Vec<u8>>().into_boxed_slice(),
            object_flags: 0,
        })
    }

    fn commit(&mut self, _request: &CommitRequest) -> FileSystemResult<CommitEffect> {
        Ok(CommitEffect {
            create_result: create_result::CREATED,
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: stub_sizes(),
            namespace_generation: 2,
            security_generation: 2,
            volume_commit_sequence: 5,
        })
    }

    fn abort(&mut self, transaction_id: TransactionId) {
        self.aborted.push(transaction_id);
    }

    fn cleanup(&mut self, kernel_open_id: u64) {
        self.cleaned_up.push(kernel_open_id);
    }

    fn close(&mut self, kernel_open_id: u64) {
        self.closed.push(kernel_open_id);
    }

    fn read(
        &mut self,
        _kernel_open_id: u64,
        _offset: u64,
        buf: &mut [u8],
    ) -> FileSystemResult<usize> {
        let read = self.read_returns.min(buf.len());
        for (index, byte) in buf[..read].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        Ok(read)
    }

    fn write(
        &mut self,
        _kernel_open_id: u64,
        request: &crate::dataio::WriteRequest,
    ) -> FileSystemResult<crate::dataio::WriteOutcome> {
        // Coverage-consistent regardless of `offset`: the post-write file size
        // (and valid-data length) always exactly cover the written range.
        let information = self.write_information.unwrap_or(request.length());
        let end = request.offset() + u64::from(information);
        Ok(crate::dataio::WriteOutcome {
            information,
            effect: WriteEffect {
                sizes: SizeState {
                    allocation_size: end.max(8192),
                    file_size: end,
                    valid_data_length: end,
                    size_epoch: 2,
                },
                volume_commit_sequence: 5,
            },
        })
    }

    fn flush(&mut self, kernel_open_id: u64) -> FileSystemResult<()> {
        self.flushed.push(kernel_open_id);
        Ok(())
    }

    fn query_dir(
        &mut self,
        _kernel_open_id: u64,
        _request: &QueryDirRequest,
    ) -> FileSystemResult<Vec<DirCandidate>> {
        Ok(self.query_dir_candidates.clone())
    }

    fn query_info(&mut self, _kernel_open_id: u64) -> FileSystemResult<FileInfoFields> {
        Ok(FileInfoFields {
            creation_time: 1,
            last_access_time: 2,
            last_write_time: 3,
            change_time: 4,
            sizes: stub_sizes(),
            namespace_generation: 2,
            security_generation: 2,
            attributes: file_attributes::ARCHIVE,
            link_count: 1,
        })
    }

    fn query_volume(&mut self) -> FileSystemResult<VolumeSizeFields> {
        Ok(VolumeSizeFields {
            total_allocation_units: 1_000_000,
            available_allocation_units: 500_000,
            sectors_per_allocation_unit: 8,
            bytes_per_sector: 512,
        })
    }

    fn query_security(
        &mut self,
        _kernel_open_id: u64,
        _security_information: u32,
    ) -> FileSystemResult<Vec<u8>> {
        Ok(self.query_security_descriptor.clone())
    }

    fn mutation_context(
        &mut self,
        _request: &MutationRequest,
    ) -> FileSystemResult<MutationContext> {
        Ok(MutationContext::default())
    }

    fn mutate(&mut self, request: &MutationRequest) -> FileSystemResult<MutationEffect> {
        Ok(stub_mutation_effect(request))
    }
}

// Task 11: drive every one of the 13 Daemon opcodes end-to-end against a
// canned `StubFileSystem` (the testkit provider stub Task 10 deferred). Each
// test submits a fixture-built, grant-backed SQE to a real `Daemon` wired over
// ONE coherent `Harness`/`GrantTable`/section, `pump_once`s it, reaps the CQE,
// and — for the write-back opcodes — reads the U2K destination grant back via
// `resolve_body` and compares it to the expected built result computed the
// same way `Daemon::dispatch` builds it (same decode, same effect, same
// `build_*` call), so a mismatch here is a genuine behavioral regression, not
// a copy/paste typo. `StubFileSystem` itself does not exist yet, so this
// module fails to compile — the RED state.
#[cfg(test)]
mod tests {
    use super::{
        tok, CommitFixture, Harness, MutationFixture, PrepareFixture, QueryDirFixture,
        QueryInfoFixture, QuerySecurityFixture, QueryVolumeFixture, ReadFixture, StubFileSystem,
        WriteFixture,
    };
    use crate::daemon::Daemon;
    use crate::dataio::{build_write_result, decode_read, decode_write};
    use crate::direnum::{DirCandidate, DirEntryFields, DirEnumerator};
    use crate::filesystem::FileSystem;
    use crate::grant::{resolve_body, GrantTable};
    use crate::lifecycle::{CommitEffect, CommittedResult, OpenLifecycle, PrepareResult, RowState};
    use crate::mutation::{build_mutation_result, decode_mutation};
    use crate::openbody::{
        build_commit_result, build_prepare_result, decode_commit, decode_prepare, CommitRequest,
        PreparedRequest,
    };
    use crate::querydir::decode_query_dir;
    use crate::queryinfo::{build_file_info, decode_query_info};
    use crate::querysecurity::decode_query_security;
    use crate::queryvolume::{build_volume_size_info, decode_query_volume};

    use fsring_abi::codec::{try_decode, try_encode};
    use fsring_abi::ids::{FileId, LinkId, OpId, ReqId, TransactionId};
    use fsring_abi::layout::{op, SqeBody, SQE_PAYLOAD_LEN};
    use fsring_abi::msgs::{
        create_result, file_attributes, AbortOpenV1, BufferRef, CommitOpenV2, ControlHeader,
        MutationResultV2, PrepareOpenV2, SizeState, CONTROL_VERSION_V1,
    };
    use fsring_abi::slots::{BufferRefPolicy, GrantOwner};

    /// A generation-1 `SizeState` shared by the lifecycle-seeding helpers below
    /// (mirrors `daemon.rs`'s own `ok_sizes`).
    fn ok_sizes() -> SizeState {
        SizeState {
            allocation_size: 0,
            file_size: 0,
            valid_data_length: 0,
            size_epoch: 1,
        }
    }

    /// A zeroed-tail `PBarrier` SQE for a barrier opcode (CLEANUP/CLOSE/FLUSH):
    /// `payload_len = 24`, an all-zero payload, carrying the `kernel_open_id`
    /// the barrier targets (mirrors `daemon.rs`'s own `barrier_sqe`).
    fn barrier_sqe(opcode: u16, req_id: u64, kernel_open_id: u64) -> SqeBody {
        SqeBody {
            opcode,
            flags: 0,
            payload_len: 24,
            reserved: 0,
            req_id,
            kernel_open_id,
            ccb_sequence: 0,
            payload: [0u8; SQE_PAYLOAD_LEN],
        }
    }

    /// A UTF-16LE-named `DirCandidate` (mirrors `daemon.rs`'s own `candidate`).
    fn candidate(name: &str) -> DirCandidate {
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        DirCandidate {
            name: utf16.into_boxed_slice(),
            fields: DirEntryFields {
                file_id: FileId { lo: 1, hi: 0 },
                link_id: LinkId { lo: 1, hi: 0 },
                sizes: ok_sizes(),
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                change_time: 0,
                namespace_generation: 1,
                attributes: file_attributes::NORMAL,
            },
        }
    }

    /// Seed a live OPEN row at `kernel_open_id` by driving the engine's public
    /// prepare+commit path directly (mirrors `daemon.rs`'s own `seed_open`), so
    /// a CLEANUP/CLOSE for that open finds a LIVE row instead of a
    /// `RowCorruption` fault.
    fn seed_live_open(lifecycle: &mut OpenLifecycle, kernel_open_id: u64) {
        let mut prepare_raw: PrepareOpenV2 =
            try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
        prepare_raw.op_id = OpId { lo: 1, hi: 0 };
        let prepared = PreparedRequest::from_raw(
            prepare_raw,
            b"a.txt".to_vec().into_boxed_slice(),
            None,
            None,
        );
        let result = PrepareResult {
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            security_descriptor: vec![0u8; 20].into_boxed_slice(),
            object_flags: 0,
        };
        lifecycle
            .prepare(prepared, result, 0, TransactionId { lo: 0x22, hi: 0 })
            .expect("seed prepare");

        let mut commit_raw: CommitOpenV2 =
            try_decode(&[0u8; 104]).expect("zeroed CommitOpenV2 decodes");
        commit_raw.op_id = OpId { lo: 1, hi: 0 };
        commit_raw.transaction_id = TransactionId { lo: 0x22, hi: 0 };
        commit_raw.expected_namespace_generation = 1;
        commit_raw.expected_security_generation = 1;
        commit_raw.kernel_open_id = kernel_open_id;
        commit_raw.granted_access = 1;
        let commit = CommitRequest::from_raw(commit_raw);
        let effect = CommitEffect {
            create_result: create_result::CREATED,
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: 1,
            security_generation: 1,
            volume_commit_sequence: 5,
        };
        lifecycle.commit(&commit, effect).expect("seed commit");
    }

    /// Seed only the PREPARE half of the lifecycle (no row created) at the
    /// given identity, so a subsequent real COMMIT_OPEN dispatch through the
    /// Daemon resolves the transaction and passes the `SemanticMismatch` check
    /// (`05`'s "verify stored semantic fields" rule).
    fn seed_prepared_only(
        lifecycle: &mut OpenLifecycle,
        op_id: OpId,
        transaction_id: TransactionId,
        expected_namespace_generation: u64,
        expected_security_generation: u64,
    ) {
        let mut prepare_raw: PrepareOpenV2 =
            try_decode(&[0u8; 192]).expect("zeroed PrepareOpenV2 decodes");
        prepare_raw.op_id = op_id;
        let prepared = PreparedRequest::from_raw(
            prepare_raw,
            b"a.txt".to_vec().into_boxed_slice(),
            None,
            None,
        );
        let result = PrepareResult {
            file_id: FileId { lo: 9, hi: 0 },
            link_id: LinkId { lo: 9, hi: 0 },
            sizes: ok_sizes(),
            namespace_generation: expected_namespace_generation,
            security_generation: expected_security_generation,
            security_descriptor: vec![0u8; 20].into_boxed_slice(),
            object_flags: 0,
        };
        lifecycle
            .prepare(prepared, result, 0, transaction_id)
            .expect("seed prepare");
    }

    /// A 24-byte `AbortOpenV1` body carrying `transaction_id`.
    fn abort_body_bytes(transaction_id: TransactionId) -> [u8; 24] {
        let record = AbortOpenV1 {
            header: ControlHeader {
                struct_size: 24,
                struct_version: CONTROL_VERSION_V1,
                required_flags: 0,
            },
            transaction_id,
        };
        let mut bytes = [0u8; 24];
        try_encode(&record, &mut bytes).expect("AbortOpenV1 fits its 24 bytes");
        bytes
    }

    #[test]
    fn prepare_open_round_trips_and_writes_the_result_back() {
        let (harness, table, sqe, owner) = PrepareFixture::build().into_parts();
        let request = decode_prepare(&sqe, &table, harness.section(), owner).expect("decode");

        let mut fs = StubFileSystem::default();
        let expected_tx = TransactionId { lo: 1, hi: 0 }; // a fresh Daemon's first transaction
        let effect = fs
            .prepare(&request, expected_tx)
            .expect("stub prepare succeeds");
        let expected_bytes = build_prepare_result(&request, &effect, expected_tx, &table, owner)
            .expect("expected result builds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected_bytes.len() as u64);

        let shrunk = BufferRef {
            token: request.reply().token,
            offset: 0,
            length: expected_bytes.len() as u32,
            kind: request.reply().kind,
            access: request.reply().access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve reply");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected_bytes.as_slice());
    }

    #[test]
    fn prepare_open_writes_the_result_security_descriptor_back() {
        // PrepareOpenV2 has TWO U2K output grants: `reply` (the 136-byte result)
        // AND `result_security_descriptor` (the SD bytes the result's BufferRef
        // points at). This asserts the SECOND grant is populated — the reply
        // write-back is covered by the test above.
        let (harness, table, sqe, owner) = PrepareFixture::build().into_parts();
        let request = decode_prepare(&sqe, &table, harness.section(), owner).expect("decode");

        let mut fs = StubFileSystem::default();
        // The stub returns a distinctive non-zero 20-byte descriptor.
        let expected_sd = fs
            .prepare(&request, TransactionId { lo: 1, hi: 0 })
            .expect("stub prepare succeeds")
            .security_descriptor;
        assert_eq!(
            expected_sd.as_ref(),
            (0u8..20).collect::<Vec<u8>>().as_slice()
        );

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);

        // The result-SD U2K grant must hold the provider's descriptor bytes in
        // its front, read back via a ShrinkOnly resolve to the descriptor length.
        let sd_grant = request.result_security_descriptor();
        let shrunk = BufferRef {
            token: sd_grant.token,
            offset: 0,
            length: expected_sd.len() as u32,
            kind: sd_grant.kind,
            access: sd_grant.access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve result-SD");
        let view = resolve_body(harness.section(), &validated).expect("read back SD");
        assert_eq!(view.as_slice(), expected_sd.as_ref());
    }

    #[test]
    fn commit_open_round_trips_and_writes_the_result_back() {
        let fx = CommitFixture::build();
        let op_id = fx.op_id;
        let transaction_id = fx.transaction_id;
        let expected_namespace_generation = fx.expected_namespace_generation;
        let expected_security_generation = fx.expected_security_generation;
        let (harness, table, sqe, owner) = fx.into_parts();

        let request = decode_commit(&sqe, &table, harness.section(), owner).expect("decode");
        let mut fs = StubFileSystem::default();
        let effect = fs.commit(&request).expect("stub commit succeeds");
        let committed = CommittedResult {
            provider_open_cookie: 1, // the Daemon's fresh lifecycle issues cookie 1 first
            create_result: effect.create_result,
            file_id: effect.file_id,
            link_id: effect.link_id,
            sizes: effect.sizes,
            namespace_generation: effect.namespace_generation,
            security_generation: effect.security_generation,
            volume_commit_sequence: effect.volume_commit_sequence,
        };
        let expected_bytes = build_commit_result(&request, &committed, &table, owner)
            .expect("expected result builds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        seed_prepared_only(
            daemon.lifecycle_mut(),
            op_id,
            transaction_id,
            expected_namespace_generation,
            expected_security_generation,
        );
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected_bytes.len() as u64);

        let shrunk = BufferRef {
            token: request.reply().token,
            offset: 0,
            length: expected_bytes.len() as u32,
            kind: request.reply().kind,
            access: request.reply().access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve reply");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected_bytes.as_slice());
    }

    #[test]
    fn abort_open_round_trips_through_the_daemon() {
        const REQ_ID: u64 = 0x0009_0000_0001;
        let harness = Harness::new_single_ring();
        let mut table = GrantTable::new(harness.session_epoch());
        let owner = GrantOwner::Request(ReqId::from_raw(REQ_ID));
        let transaction_id = TransactionId { lo: 0x77, hi: 0 };
        let body = abort_body_bytes(transaction_id);
        let token = tok(0, 0);
        harness.write_slot(&harness.k2u_arena(), token, &body);
        let sqe = harness.grant_abort_sqe(&mut table, owner, token, REQ_ID, &body);

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut fs = StubFileSystem::default();
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.information, 0);
        assert_eq!(fs.aborted, vec![transaction_id]);
    }

    #[test]
    fn cleanup_round_trips_through_the_daemon() {
        let harness = Harness::new_single_ring();
        let table = GrantTable::new(harness.session_epoch());
        let mut fs = StubFileSystem::default();
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        seed_live_open(daemon.lifecycle_mut(), 0x33);

        let kernel = harness.kernel_ring();
        let _receipt = kernel
            .submit(barrier_sqe(op::CLEANUP, 7, 0x33))
            .expect("submit");
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);
        assert_eq!(
            daemon.lifecycle_mut().row_state(0x33),
            Some(RowState::Cleaned)
        );

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.information, 0);
        assert_eq!(fs.cleaned_up, vec![0x33]);
    }

    #[test]
    fn close_round_trips_through_the_daemon() {
        let harness = Harness::new_single_ring();
        let table = GrantTable::new(harness.session_epoch());
        let mut fs = StubFileSystem::default();
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        seed_live_open(daemon.lifecycle_mut(), 0x44);
        daemon.lifecycle_mut().cleanup(0x44).expect("seed cleanup");

        let kernel = harness.kernel_ring();
        let _receipt = kernel
            .submit(barrier_sqe(op::CLOSE, 7, 0x44))
            .expect("submit");
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);
        assert_eq!(daemon.lifecycle_mut().row_state(0x44), None);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.information, 0);
        assert_eq!(fs.closed, vec![0x44]);
    }

    #[test]
    fn flush_round_trips_through_the_daemon() {
        let harness = Harness::new_single_ring();
        let table = GrantTable::new(harness.session_epoch());
        let mut fs = StubFileSystem::default();
        let kernel = harness.kernel_ring();
        let _receipt = kernel
            .submit(barrier_sqe(op::FLUSH, 7, 0x55))
            .expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 0);
        assert_eq!(cqe.information, 0);
        assert_eq!(fs.flushed, vec![0x55]);
    }

    #[test]
    fn read_round_trips_and_writes_the_fetched_bytes() {
        let (harness, table, sqe, owner) = ReadFixture::valid().into_parts();
        let request = decode_read(&sqe, &table, owner).expect("decode");

        let mut fs = StubFileSystem {
            read_returns: request.length as usize,
            ..Default::default()
        };
        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, request.length as u64);

        let validated = daemon
            .table()
            .resolve(&request.data, owner, BufferRefPolicy::Exact)
            .expect("resolve data");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        let expected: Vec<u8> = (0..request.length as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(view.as_slice(), expected.as_slice());
    }

    #[test]
    fn read_partial_writes_the_fetched_prefix_and_a_zero_tail() {
        // A short read (`1 < n < length`): the completion reports `n`, the front
        // `n` bytes carry the provider pattern, and the untouched tail stays zero.
        let (harness, table, sqe, owner) = ReadFixture::valid().into_parts();
        let request = decode_read(&sqe, &table, owner).expect("decode");
        let length = request.length as usize;
        let partial = length / 2;
        assert!(partial > 1 && partial < length);

        let mut fs = StubFileSystem {
            read_returns: partial,
            ..Default::default()
        };
        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, partial as u64);

        let validated = daemon
            .table()
            .resolve(&request.data, owner, BufferRefPolicy::Exact)
            .expect("resolve data");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        let bytes = view.as_slice();
        let expected_prefix: Vec<u8> = (0..partial).map(|i| (i % 251) as u8).collect();
        assert_eq!(&bytes[..partial], expected_prefix.as_slice());
        assert!(
            bytes[partial..].iter().all(|&b| b == 0),
            "the tail past the short read stays zero"
        );
    }

    #[test]
    fn write_round_trips_and_writes_the_result_back() {
        let (harness, table, sqe, owner) = WriteFixture::valid().into_parts();
        let request = decode_write(&sqe, &table, harness.section(), owner).expect("decode");

        let mut fs = StubFileSystem::default();
        let outcome = fs.write(0, &request).expect("stub write succeeds");
        let information = u64::from(outcome.information);
        let expected_bytes =
            build_write_result(&request, &outcome.effect, information, &table, owner)
                .expect("expected result builds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, information);

        let shrunk = BufferRef {
            token: request.reply().token,
            offset: 0,
            length: expected_bytes.len() as u32,
            kind: request.reply().kind,
            access: request.reply().access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve reply");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected_bytes.as_slice());
    }

    #[test]
    fn query_dir_round_trips_and_writes_the_batch_back() {
        let candidates = vec![candidate("a.txt"), candidate("b.txt")];
        let (harness, table, sqe, owner) = QueryDirFixture::match_all().into_parts();

        let request = decode_query_dir(&sqe, &table, harness.section(), owner).expect("decode");
        let mut reference = DirEnumerator::new();
        let expected = reference
            .open(sqe.kernel_open_id, &request, candidates.clone())
            .expect("reference batch");

        let mut fs = StubFileSystem {
            query_dir_candidates: candidates,
            ..Default::default()
        };
        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected.blob.len() as u64);

        let shrunk = BufferRef {
            token: request.output.token,
            offset: 0,
            length: expected.blob.len() as u32,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve output");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected.blob.as_slice());
    }

    #[test]
    fn query_info_round_trips_and_writes_the_fields_back() {
        let (harness, table, sqe, owner) = QueryInfoFixture::valid().into_parts();
        let request = decode_query_info(&sqe, &table, harness.section(), owner).expect("decode");

        let mut fs = StubFileSystem::default();
        let fields = fs.query_info(0).expect("stub query-info succeeds");
        let expected_bytes = build_file_info(&fields).expect("expected builds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected_bytes.len() as u64);

        let shrunk = BufferRef {
            token: request.output.token,
            offset: 0,
            length: expected_bytes.len() as u32,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve output");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected_bytes.as_slice());
    }

    #[test]
    fn query_volume_round_trips_and_writes_the_fields_back() {
        let (harness, table, sqe, owner) = QueryVolumeFixture::valid().into_parts();
        let request = decode_query_volume(&sqe, &table, harness.section(), owner).expect("decode");

        let mut fs = StubFileSystem::default();
        let fields = fs.query_volume().expect("stub query-volume succeeds");
        let expected_bytes = build_volume_size_info(&fields).expect("expected builds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected_bytes.len() as u64);

        let shrunk = BufferRef {
            token: request.output.token,
            offset: 0,
            length: expected_bytes.len() as u32,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve output");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected_bytes.as_slice());
    }

    #[test]
    fn query_security_round_trips_and_writes_the_descriptor_back() {
        let (harness, table, sqe, owner) = QuerySecurityFixture::valid().into_parts();
        let request =
            decode_query_security(&sqe, &table, harness.section(), owner).expect("decode");

        let mut fs = StubFileSystem {
            query_security_descriptor: vec![0xCDu8; 64],
            ..Default::default()
        };
        let expected = fs
            .query_security(0, request.security_information)
            .expect("stub query-security succeeds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, expected.len() as u64);

        let shrunk = BufferRef {
            token: request.output.token,
            offset: 0,
            length: expected.len() as u32,
            kind: request.output.kind,
            access: request.output.access,
            reserved: 0,
        };
        let validated = daemon
            .table()
            .resolve(&shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve output");
        let view = resolve_body(harness.section(), &validated).expect("read back");
        assert_eq!(view.as_slice(), expected.as_slice());
    }

    #[test]
    fn mutate_rename_round_trips_and_writes_both_results_back() {
        let (harness, table, sqe, owner) = MutationFixture::rename().into_parts();
        let request =
            decode_mutation(&sqe, &table, harness.section(), owner, false).expect("decode");

        let mut fs = StubFileSystem::default();
        let effect = fs.mutate(&request).expect("stub mutation succeeds");
        let expected = build_mutation_result(&request, &effect, &table, owner)
            .expect("expected result builds");

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(cqe.information, 112);

        let reply_shrunk = BufferRef {
            token: request.reply().token,
            offset: 0,
            length: expected.result.len() as u32,
            kind: request.reply().kind,
            access: request.reply().access,
            reserved: 0,
        };
        let reply_validated = daemon
            .table()
            .resolve(&reply_shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve reply");
        let reply_view =
            resolve_body(harness.section(), &reply_validated).expect("read back reply");
        assert_eq!(reply_view.as_slice(), expected.result.as_slice());

        let kind_shrunk = BufferRef {
            token: request.kind_result().token,
            offset: 0,
            length: expected.kind_result.len() as u32,
            kind: request.kind_result().kind,
            access: request.kind_result().access,
            reserved: 0,
        };
        let kind_validated = daemon
            .table()
            .resolve(&kind_shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve kind_result");
        let kind_view =
            resolve_body(harness.section(), &kind_validated).expect("read back kind_result");
        assert_eq!(kind_view.as_slice(), expected.kind_result.as_slice());
    }

    #[test]
    fn mutate_set_security_round_trips_and_skips_the_kind_result() {
        // A non-RENAME/LINK/UNLINK kind (SET_SECURITY) has an EMPTY kind_result
        // and a NONE kind_result grant, so the Daemon's write-back must take the
        // `if !result.kind_result.is_empty()` skip branch — a successful pump is
        // itself the proof (writing a NONE grant would 404 at `resolve`).
        let (harness, table, sqe, owner) = MutationFixture::set_security().into_parts();
        let request =
            decode_mutation(&sqe, &table, harness.section(), owner, false).expect("decode");

        let mut fs = StubFileSystem::default();
        let effect = fs.mutate(&request).expect("stub mutation succeeds");
        let expected = build_mutation_result(&request, &effect, &table, owner)
            .expect("expected result builds");
        assert!(
            expected.kind_result.is_empty(),
            "SET_SECURITY carries no kind result"
        );

        let kernel = harness.kernel_ring();
        let _receipt = kernel.submit(sqe).expect("submit");
        let mut daemon = Daemon::new(harness.daemon_ring(), harness.section(), table, &mut fs);
        let stats = daemon.pump_once().expect("pump");
        assert_eq!(stats.handled, 1);
        assert_eq!(stats.posted, 1);

        let mut kernel = kernel;
        let cqe = kernel.reap().expect("reap").expect("a completion");
        assert_eq!(cqe.status, 0);
        assert_eq!(cqe.out_len, 24);
        assert_eq!(
            cqe.information,
            core::mem::size_of::<MutationResultV2>() as u64
        );

        let reply_shrunk = BufferRef {
            token: request.reply().token,
            offset: 0,
            length: expected.result.len() as u32,
            kind: request.reply().kind,
            access: request.reply().access,
            reserved: 0,
        };
        let reply_validated = daemon
            .table()
            .resolve(&reply_shrunk, owner, BufferRefPolicy::ShrinkOnly)
            .expect("resolve reply");
        let reply_view =
            resolve_body(harness.section(), &reply_validated).expect("read back reply");
        assert_eq!(reply_view.as_slice(), expected.result.as_slice());
    }
}
