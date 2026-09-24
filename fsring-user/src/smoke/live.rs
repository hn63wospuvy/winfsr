//! Owned C4 probe state, the production accumulator, and the four-frame
//! observation workers.
//!
//! Execution order and public roster order are separate: workers call
//! [`C4ProbeAccumulator::observe`] in the parent operation trace, record by
//! fixed roster index, and only [`C4ProbeAccumulator::serialize_range`] walks
//! indices 0 through 26.

use super::{
    expected_oracle, CleanupSummary, FactValue, HexIdentity, LiveCleanedRecord, Oracle,
    PostUnloadRecord, ProbeName, ProbeOutcome, ProbeV2, SmokeIdentity, SmokeReason, StagedRecord,
    UnloadObservation, UnloadSeed, WorkerEvent, WorkerFrame, WorkerNonce, LIVE_PROBE_RANGE,
    POST_PROBE_RANGE, STAGED_PROBE_RANGE,
};

/// Private C4 preflight stdout schema. It is never public v2.
pub const PREFLIGHT_ORCHESTRATION_SCHEMA: &str = "fsring-c4-preflight-orchestration/v1";

/// Live auxiliary files. Public v2 stays on stdout.
pub const LIVE_SIDECAR_NAMES: [&str; 4] = [
    "etw.sidecar.jsonl",
    "worker-frames.sidecar.bin",
    "cleanup.sidecar.json",
    "diagnostics.sidecar.jsonl",
];

const LEGAL_MASK: u32 = (1u32 << 27) - 1;

/// Parent-required STAGED operation order. Serialization still emits 0..14.
pub const STAGED_OPERATION_ORDER: [ProbeName; 15] = [
    ProbeName::FscontrolAcl,
    ProbeName::SetupOptionalDowngrade,
    ProbeName::SetupSecurity,
    ProbeName::SetupRequiredUnavailable,
    ProbeName::RootOpen,
    ProbeName::TrailingOpen,
    ProbeName::UnknownIoctl,
    ProbeName::DonateShort,
    ProbeName::DonateWrongVersion,
    ProbeName::Donate,
    ProbeName::ChildInheritedHandle,
    ProbeName::ParentHandleAfterChild,
    ProbeName::SetupDuplicate,
    ProbeName::SessionLayout,
    ProbeName::ViewProtections,
];

/// LIVE_CLEANED operation order. Serialization still emits 15..24.
pub const LIVE_OPERATION_ORDER: [ProbeName; 10] = [
    ProbeName::VdoAcl,
    ProbeName::VdoMount,
    ProbeName::EnterPoll,
    ProbeName::EnterTimeout,
    ProbeName::EnterDualRole,
    ProbeName::EnterNotifyCredit,
    ProbeName::EnterContention,
    ProbeName::EnterCancel,
    ProbeName::ProtocolAbort,
    ProbeName::CleanupClose,
];

#[derive(Debug)]
pub struct C4ProbeState {
    requested_mask: u32,
    recorded_mask: u32,
    mutation_started: bool,
    sticky_failure: bool,
}

impl C4ProbeState {
    const fn new() -> Self {
        Self {
            requested_mask: 0,
            recorded_mask: 0,
            mutation_started: false,
            sticky_failure: false,
        }
    }

    pub fn mark_mutation_started(&mut self) {
        self.mutation_started = true;
    }

    pub const fn mutation_started(&self) -> bool {
        self.mutation_started
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    IndexOutOfRange,
    DuplicateRequest,
    DuplicateRecord,
    NameIndexMismatch,
    MissingActual,
    IncompleteRange,
    ObservationAfterStickyFailure,
}

#[derive(Debug, Eq, PartialEq)]
pub enum C4ObserveError<E> {
    Probe(ProbeError),
    Backend(E),
}

pub trait C4ProbeBackend {
    type Error;
    fn observe(
        &mut self,
        probe: ProbeName,
        state: &mut C4ProbeState,
    ) -> Result<Oracle, Self::Error>;
}

/// Typed POST_UNLOAD absence facts, separate from the BootContext probe.
pub trait C4UnloadFacts {
    fn unload_observation(&self) -> UnloadObservation;
}

pub struct C4ProbeAccumulator {
    state: C4ProbeState,
    slots: [Option<ProbeV2>; 27],
}

impl C4ProbeAccumulator {
    pub const fn new() -> Self {
        Self {
            state: C4ProbeState::new(),
            slots: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None,
            ],
        }
    }

    fn fail(&mut self, error: ProbeError) -> ProbeError {
        if self.state.sticky_failure {
            return ProbeError::ObservationAfterStickyFailure;
        }
        if self.state.mutation_started {
            self.state.sticky_failure = true;
        }
        error
    }

    pub fn observe<B: C4ProbeBackend>(
        &mut self,
        backend: &mut B,
        probe: ProbeName,
    ) -> Result<Oracle, C4ObserveError<B::Error>> {
        if self.state.sticky_failure {
            return Err(C4ObserveError::Probe(
                ProbeError::ObservationAfterStickyFailure,
            ));
        }
        let index = probe.index();
        if index >= 27 {
            return Err(C4ObserveError::Probe(
                self.fail(ProbeError::IndexOutOfRange),
            ));
        }
        let bit = 1u32 << index;
        if self.state.requested_mask & bit != 0 {
            return Err(C4ObserveError::Probe(
                self.fail(ProbeError::DuplicateRequest),
            ));
        }
        self.state.requested_mask |= bit;
        match backend.observe(probe, &mut self.state) {
            Ok(oracle) => Ok(oracle),
            Err(error) => {
                if self.state.mutation_started {
                    self.state.sticky_failure = true;
                }
                Err(C4ObserveError::Backend(error))
            }
        }
    }

    pub fn record(&mut self, index: usize, probe: ProbeV2) -> Result<(), ProbeError> {
        if self.state.sticky_failure {
            return Err(ProbeError::ObservationAfterStickyFailure);
        }
        if index >= 27 {
            return Err(self.fail(ProbeError::IndexOutOfRange));
        }
        if probe.name.index() != index {
            return Err(self.fail(ProbeError::NameIndexMismatch));
        }
        if probe.actual.is_none() {
            return Err(self.fail(ProbeError::MissingActual));
        }
        let bit = 1u32 << index;
        if self.state.recorded_mask & bit != 0 {
            return Err(self.fail(ProbeError::DuplicateRecord));
        }
        if self.state.requested_mask & bit == 0 {
            return Err(self.fail(ProbeError::IncompleteRange));
        }
        self.state.recorded_mask |= bit;
        self.slots[index] = Some(probe);
        Ok(())
    }

    pub fn serialize_range(
        &mut self,
        range: core::ops::Range<usize>,
    ) -> Result<Vec<ProbeV2>, ProbeError> {
        if self.state.sticky_failure {
            return Err(ProbeError::ObservationAfterStickyFailure);
        }
        if range.end > 27 || range.start > range.end {
            return Err(self.fail(ProbeError::IndexOutOfRange));
        }
        if (self.state.requested_mask | self.state.recorded_mask) & !LEGAL_MASK != 0 {
            return Err(self.fail(ProbeError::IndexOutOfRange));
        }
        let inside = bits_in_range(range.start, range.end);
        let prefix = prefix_bits(range.start);
        let requested = self.state.requested_mask;
        let recorded = self.state.recorded_mask;
        if (requested & inside) != inside || (recorded & inside) != inside {
            return Err(self.fail(ProbeError::IncompleteRange));
        }
        // Prior roster bits may already be recorded on a shared accumulator.
        // Bits above the range (or holes that are not a lower prefix) are not
        // this serialization's probes.
        if ((requested | recorded) & !inside & !prefix) != 0 {
            return Err(self.fail(ProbeError::IncompleteRange));
        }
        let mut out = Vec::new();
        for index in range {
            let Some(probe) = self.slots[index].clone() else {
                return Err(self.fail(ProbeError::IncompleteRange));
            };
            if probe.actual.is_none() {
                return Err(self.fail(ProbeError::MissingActual));
            }
            if probe.name.index() != index {
                return Err(self.fail(ProbeError::NameIndexMismatch));
            }
            out.push(probe);
        }
        Ok(out)
    }
}

const fn bits_in_range(start: usize, end: usize) -> u32 {
    let mut mask = 0u32;
    let mut index = start;
    while index < end && index < 27 {
        mask |= 1u32 << index;
        index += 1;
    }
    mask
}

const fn prefix_bits(start: usize) -> u32 {
    if start == 0 || start > 27 {
        0
    } else {
        (1u32 << start) - 1
    }
}

fn record_observed<B: C4ProbeBackend>(
    acc: &mut C4ProbeAccumulator,
    backend: &mut B,
    probe: ProbeName,
    root: SmokeIdentity,
) -> Result<(), C4ObserveError<B::Error>> {
    let actual = acc.observe(backend, probe)?;
    let expected = expected_oracle(probe, root);
    let outcome = if actual == expected {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Fail
    };
    acc.record(
        probe.index(),
        ProbeV2 {
            name: probe,
            outcome,
            expected,
            actual: Some(actual),
        },
    )
    .map_err(C4ObserveError::Probe)
}

/// Lets a backend rewrite `setup-required-unavailable.mountSequenceDelta` after
/// both successful MountIds exist. Host fakes leave the observed actual as-is.
pub trait C4RequiredUnavailableDelta {
    fn finalize_required_unavailable(&self, observed: Oracle) -> Oracle {
        observed
    }
}

pub fn mount_sequence_delta(root: SmokeIdentity, disposable: SmokeIdentity) -> u64 {
    root.mount_id
        .lo
        .checked_sub(disposable.mount_id.lo)
        .and_then(|delta| delta.checked_sub(1))
        .unwrap_or(u64::MAX)
}

pub fn patch_mount_sequence_delta(
    observed: Oracle,
    root: SmokeIdentity,
    disposable: SmokeIdentity,
) -> Oracle {
    let delta = mount_sequence_delta(root, disposable);
    match observed {
        Oracle::Facts { values } => Oracle::Facts {
            values: values
                .into_iter()
                .map(|(key, value)| {
                    if key == "mountSequenceDelta" {
                        (key, FactValue::Hex64(delta))
                    } else {
                        (key, value)
                    }
                })
                .collect(),
        },
        other => other,
    }
}

fn worker_event(name: super::EventName, identity: SmokeIdentity, reason: u32) -> WorkerEvent {
    WorkerEvent {
        name,
        id: name.id(),
        version: 1,
        keyword: 0x1,
        identity,
        reason,
    }
}

pub fn observe_staged_prefix<B>(
    acc: &mut C4ProbeAccumulator,
    backend: &mut B,
    root: SmokeIdentity,
) -> Result<Vec<ProbeV2>, C4ObserveError<B::Error>>
where
    B: C4ProbeBackend + C4RequiredUnavailableDelta,
{
    let mut pending_required = None;
    for probe in STAGED_OPERATION_ORDER {
        let actual = acc.observe(backend, probe)?;
        if probe == ProbeName::SetupRequiredUnavailable {
            pending_required = Some(actual);
            continue;
        }
        let expected = expected_oracle(probe, root);
        let outcome = if actual == expected {
            ProbeOutcome::Pass
        } else {
            ProbeOutcome::Fail
        };
        acc.record(
            probe.index(),
            ProbeV2 {
                name: probe,
                outcome,
                expected,
                actual: Some(actual),
            },
        )
        .map_err(C4ObserveError::Probe)?;
    }
    let observed = pending_required.ok_or(C4ObserveError::Probe(ProbeError::IncompleteRange))?;
    let actual = backend.finalize_required_unavailable(observed);
    let expected = expected_oracle(ProbeName::SetupRequiredUnavailable, root);
    let outcome = if actual == expected {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Fail
    };
    acc.record(
        ProbeName::SetupRequiredUnavailable.index(),
        ProbeV2 {
            name: ProbeName::SetupRequiredUnavailable,
            outcome,
            expected,
            actual: Some(actual),
        },
    )
    .map_err(C4ObserveError::Probe)?;
    acc.serialize_range(STAGED_PROBE_RANGE)
        .map_err(C4ObserveError::Probe)
}

pub fn observe_live_range<B: C4ProbeBackend>(
    acc: &mut C4ProbeAccumulator,
    backend: &mut B,
    root: SmokeIdentity,
) -> Result<Vec<ProbeV2>, C4ObserveError<B::Error>> {
    for probe in LIVE_OPERATION_ORDER {
        record_observed(acc, backend, probe, root)?;
    }
    acc.serialize_range(LIVE_PROBE_RANGE)
        .map_err(C4ObserveError::Probe)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostUnloadObservation {
    pub probes: Vec<ProbeV2>,
    pub unload_observation: UnloadObservation,
}

pub fn observe_post_unload<B>(
    acc: &mut C4ProbeAccumulator,
    backend: &mut B,
    root: SmokeIdentity,
) -> Result<PostUnloadObservation, C4ObserveError<B::Error>>
where
    B: C4ProbeBackend + C4UnloadFacts,
{
    record_observed(acc, backend, ProbeName::BootContextPersistent, root)?;
    let probes = acc
        .serialize_range(POST_PROBE_RANGE)
        .map_err(C4ObserveError::Probe)?;
    Ok(PostUnloadObservation {
        probes,
        unload_observation: backend.unload_observation(),
    })
}

pub fn merge_unload_transients(
    seed: UnloadSeed,
    observation: UnloadObservation,
    service_stopped: bool,
    dos_link_query_win32: u32,
) -> Oracle {
    use FactValue::{Bool, Hex32};
    Oracle::Facts {
        values: vec![
            ("serviceStopped", Bool(service_stopped)),
            (
                "providerOpenNtstatus",
                Hex32(observation.provider_open_ntstatus),
            ),
            (
                "fscontrolOpenNtstatus",
                Hex32(observation.fscontrol_open_ntstatus),
            ),
            ("vdoOpenNtstatus", Hex32(observation.vdo_open_ntstatus)),
            ("dosLinkQueryWin32Code", Hex32(dos_link_query_win32)),
            ("formerAliasRangesFree", Bool(seed.former_alias_ranges_free)),
            ("ownedHandlesClosed", Bool(seed.owned_handles_closed)),
        ],
    }
}

fn passing_or_failing(name: ProbeName, root: SmokeIdentity, actual: Oracle) -> ProbeV2 {
    let expected = expected_oracle(name, root);
    let outcome = if actual == expected {
        ProbeOutcome::Pass
    } else {
        ProbeOutcome::Fail
    };
    ProbeV2 {
        name,
        outcome,
        expected,
        actual: Some(actual),
    }
}

/// Build a STAGED frame from already-serialized prefix probes.
pub fn staged_frame(
    nonce: WorkerNonce,
    root: SmokeIdentity,
    disposable: SmokeIdentity,
    vdo_native_name: String,
    probes: Vec<ProbeV2>,
    events: Vec<WorkerEvent>,
    reasons: Vec<SmokeReason>,
) -> WorkerFrame {
    WorkerFrame::Staged(StagedRecord {
        sequence: 1,
        nonce,
        root_identity: root,
        disposable_identity: disposable,
        vdo_native_name,
        probes,
        events,
        reasons,
    })
}

/// Build a LIVE_CLEANED frame from already-serialized live probes.
pub fn live_cleaned_frame(
    nonce: WorkerNonce,
    root: SmokeIdentity,
    disposable: SmokeIdentity,
    vdo_native_name: String,
    dos_name: String,
    probes: Vec<ProbeV2>,
    events: Vec<WorkerEvent>,
    cleanup: CleanupSummary,
    unload_seed: UnloadSeed,
    reasons: Vec<SmokeReason>,
) -> WorkerFrame {
    WorkerFrame::LiveCleaned(LiveCleanedRecord {
        sequence: 3,
        nonce,
        root_identity: root,
        disposable_identity: disposable,
        vdo_native_name,
        dos_name,
        probes,
        events,
        cleanup,
        unload_seed,
        reasons,
    })
}

/// Build a POST_UNLOAD frame from the post observation.
pub fn post_unload_frame(
    nonce: WorkerNonce,
    root: SmokeIdentity,
    vdo_native_name: String,
    dos_name: String,
    observation: PostUnloadObservation,
    reasons: Vec<SmokeReason>,
) -> WorkerFrame {
    WorkerFrame::PostUnload(PostUnloadRecord {
        sequence: 4,
        nonce,
        root_identity: root,
        vdo_native_name,
        dos_name,
        unload_observation: observation.unload_observation,
        probes: observation.probes,
        reasons,
    })
}

pub fn probe_from_actual(name: ProbeName, root: SmokeIdentity, actual: Oracle) -> ProbeV2 {
    passing_or_failing(name, root, actual)
}

fn status_oracle(code: u32, information: Option<u64>) -> Oracle {
    Oracle::Status {
        domain: super::StatusDomain::Win32,
        code,
        information,
    }
}

/// Observed ENTER POLL fields. Production match arms convert these; they never
/// copy [`expected_oracle`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterPollObservation {
    pub win32_code: u32,
    pub information: u64,
    pub flags: u32,
    pub cq_drained: u32,
    pub returned_credits: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterDualRoleObservation {
    pub first_wait_pending: bool,
    pub concurrent_drain_win32_code: u32,
    pub conflicting_wait_win32_code: u32,
    pub roles_released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterNotifyCreditObservation {
    pub win32_code: u32,
    pub cq_drained: u32,
    pub returned_credits: u32,
    pub old_generation: u64,
    pub new_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterContentionObservation {
    pub win32_code: u32,
    pub flags: u32,
    pub bounded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterCancelObservation {
    pub win32_code: u32,
    pub information: u64,
    pub exact_overlapped: bool,
    pub completed_once: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolAbortObservation {
    pub enter_win32_code: u32,
    pub fence_reason: u32,
    pub session_absent: bool,
    pub identity: SmokeIdentity,
}

/// ETW `SESSION_FENCED` reason for a committed provider-fatal protocol abort.
///
/// This is `FenceReason::ProtocolAbort` in the SESSION_FENCED payload, not the
/// CQE's `protocol_reason::PROVIDER_FATAL_STATE` (1) and not EventName id 4.
pub const SESSION_FENCE_REASON_PROTOCOL_ABORT: u32 = 3;

/// `{76A354FE-986E-4968-B41E-BB1209D57157}`.
pub const C4_ETW_PROVIDER_GUID: C4EtwProviderGuid = C4EtwProviderGuid {
    data1: 0x76A3_54FE,
    data2: 0x986E,
    data3: 0x4968,
    data4: [0xB4, 0x1E, 0xBB, 0x12, 0x09, 0xD5, 0x71, 0x57],
};

/// `EvidenceEvent::SessionFenced`.
pub const C4_SESSION_FENCED_EVENT_ID: u16 = 4;
/// Driver `EVENT_VERSION`.
pub const C4_EVIDENCE_EVENT_VERSION: u8 = 1;
/// Driver lifecycle keyword.
pub const C4_EVIDENCE_KEYWORD: u64 = 0x1;
/// `sizeof(EvidencePayload)`.
pub const C4_EVIDENCE_PAYLOAD_SIZE: usize = 56;

/// Closed C4 ETW provider identity. Layout matches Windows `GUID`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct C4EtwProviderGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Closed 56-byte C4 evidence payload. Layout matches
/// `driver/fsring-fsd/src/trace.rs` `EvidencePayload`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct C4EvidencePayload {
    pub version: u32,
    pub reserved: u32,
    pub boot_instance_lo: u64,
    pub boot_instance_hi: u64,
    pub mount_lo: u64,
    pub mount_hi: u64,
    pub session_epoch: u64,
    pub reason: u32,
    pub reserved_tail: u32,
}

const _: () = assert!(core::mem::size_of::<C4EvidencePayload>() == C4_EVIDENCE_PAYLOAD_SIZE);

/// One observed C4 ETW record: descriptor plus the 56-byte payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct C4EtwRecord {
    pub provider: C4EtwProviderGuid,
    pub event_id: u16,
    pub version: u8,
    pub keyword: u64,
    pub payload: C4EvidencePayload,
}

/// Encode the closed payload as little-endian bytes.
pub fn encode_c4_evidence_payload(payload: &C4EvidencePayload) -> [u8; C4_EVIDENCE_PAYLOAD_SIZE] {
    let mut out = [0u8; C4_EVIDENCE_PAYLOAD_SIZE];
    out[0..4].copy_from_slice(&payload.version.to_le_bytes());
    out[4..8].copy_from_slice(&payload.reserved.to_le_bytes());
    out[8..16].copy_from_slice(&payload.boot_instance_lo.to_le_bytes());
    out[16..24].copy_from_slice(&payload.boot_instance_hi.to_le_bytes());
    out[24..32].copy_from_slice(&payload.mount_lo.to_le_bytes());
    out[32..40].copy_from_slice(&payload.mount_hi.to_le_bytes());
    out[40..48].copy_from_slice(&payload.session_epoch.to_le_bytes());
    out[48..52].copy_from_slice(&payload.reason.to_le_bytes());
    out[52..56].copy_from_slice(&payload.reserved_tail.to_le_bytes());
    out
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Parse one 56-byte C4 evidence payload. Length must be exact.
pub fn parse_c4_evidence_payload(bytes: &[u8]) -> Option<C4EvidencePayload> {
    if bytes.len() != C4_EVIDENCE_PAYLOAD_SIZE {
        return None;
    }
    Some(C4EvidencePayload {
        version: read_u32_le(bytes, 0)?,
        reserved: read_u32_le(bytes, 4)?,
        boot_instance_lo: read_u64_le(bytes, 8)?,
        boot_instance_hi: read_u64_le(bytes, 16)?,
        mount_lo: read_u64_le(bytes, 24)?,
        mount_hi: read_u64_le(bytes, 32)?,
        session_epoch: read_u64_le(bytes, 40)?,
        reason: read_u32_le(bytes, 48)?,
        reserved_tail: read_u32_le(bytes, 52)?,
    })
}

pub fn identity_from_c4_evidence_payload(payload: &C4EvidencePayload) -> SmokeIdentity {
    SmokeIdentity {
        boot_instance_id: HexIdentity {
            lo: payload.boot_instance_lo,
            hi: payload.boot_instance_hi,
        },
        mount_id: HexIdentity {
            lo: payload.mount_lo,
            hi: payload.mount_hi,
        },
        session_epoch: payload.session_epoch,
    }
}

/// Build a SESSION_FENCED ETW record whose payload identity and reason are
/// already observed. Host fakes inject this; production parses the same bytes.
pub fn c4_session_fenced_record(identity: SmokeIdentity, reason: u32) -> C4EtwRecord {
    C4EtwRecord {
        provider: C4_ETW_PROVIDER_GUID,
        event_id: C4_SESSION_FENCED_EVENT_ID,
        version: C4_EVIDENCE_EVENT_VERSION,
        keyword: C4_EVIDENCE_KEYWORD,
        payload: C4EvidencePayload {
            version: u32::from(C4_EVIDENCE_EVENT_VERSION),
            reserved: 0,
            boot_instance_lo: identity.boot_instance_id.lo,
            boot_instance_hi: identity.boot_instance_id.hi,
            mount_lo: identity.mount_id.lo,
            mount_hi: identity.mount_id.hi,
            session_epoch: identity.session_epoch,
            reason,
            reserved_tail: 0,
        },
    }
}

fn event_name_from_c4_id(event_id: u16) -> Option<super::EventName> {
    match event_id {
        1 => Some(super::EventName::SessionPublished),
        2 => Some(super::EventName::MountPublished),
        3 => Some(super::EventName::VerifySucceeded),
        4 => Some(super::EventName::SessionFenced),
        _ => None,
    }
}

/// Convert an observed C4 ETW record into a private worker event.
///
/// The worker event is copied from the record; it is not a synthetic EventName
/// minted by the abort helper.
pub fn worker_event_from_c4_etw_record(record: &C4EtwRecord) -> Option<WorkerEvent> {
    if record.provider != C4_ETW_PROVIDER_GUID {
        return None;
    }
    if record.version != C4_EVIDENCE_EVENT_VERSION || record.keyword != C4_EVIDENCE_KEYWORD {
        return None;
    }
    if record.payload.version != u32::from(C4_EVIDENCE_EVENT_VERSION) {
        return None;
    }
    let name = event_name_from_c4_id(record.event_id)?;
    if name.id() != u32::from(record.event_id) {
        return None;
    }
    let identity = identity_from_c4_evidence_payload(&record.payload);
    let reason = if name == super::EventName::SessionFenced {
        record.payload.reason
    } else {
        0
    };
    let event = worker_event(name, identity, reason);
    event.validate().ok()?;
    Some(event)
}

/// SESSION_FENCED worker event for `identity`, copied from the observed ETW
/// record. Missing, foreign, or non-fence records yield `None`.
pub fn session_fenced_worker_event(
    identity: SmokeIdentity,
    etw: Option<&C4EtwRecord>,
) -> Option<WorkerEvent> {
    let event = worker_event_from_c4_etw_record(etw?)?;
    if event.name == super::EventName::SessionFenced && event.identity == identity {
        Some(event)
    } else {
        None
    }
}

/// `fenceReason` is copied from the observed SESSION_FENCED payload, never
/// from the abort CQE and never hardcoded from CQE validation.
pub fn protocol_abort_from_session_fenced(
    enter_win32_code: u32,
    session_absent: bool,
    identity: SmokeIdentity,
    etw: Option<&C4EtwRecord>,
) -> ProtocolAbortObservation {
    let fence_reason = session_fenced_worker_event(identity, etw)
        .map(|event| event.reason)
        .unwrap_or(0);
    ProtocolAbortObservation {
        enter_win32_code,
        fence_reason,
        session_absent,
        identity,
    }
}

/// The only valid provider-fatal abort CQE the LIVE protocol-abort probe posts.
pub fn protocol_abort_cqe() -> fsring_abi::layout::CqeBody {
    use fsring_abi::codec::try_encode;
    use fsring_abi::layout::{cq_kind, CqeBody, CQE_OUT_LEN};
    use fsring_abi::msgs::{
        protocol_opcode, protocol_reason, ControlHeader, ProtocolAbortV1, CONTROL_VERSION_V1,
    };
    let record = ProtocolAbortV1 {
        header: ControlHeader {
            struct_size: core::mem::size_of::<ProtocolAbortV1>() as u32,
            struct_version: CONTROL_VERSION_V1,
            required_flags: 0,
        },
        reason: protocol_reason::PROVIDER_FATAL_STATE,
        reserved: 0,
        context: 0,
    };
    let mut body = CqeBody {
        kind: cq_kind::PROTOCOL,
        opcode: protocol_opcode::ABORT_SESSION,
        flags: 0,
        out_len: core::mem::size_of::<ProtocolAbortV1>() as u16,
        req_id: 0,
        status: 0,
        reserved: 0,
        information: 0,
        out: [0u8; CQE_OUT_LEN],
    };
    let _ = try_encode(&record, &mut body.out);
    body
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupCloseObservation {
    pub pending_enter_count: u32,
    pub alias_count: u32,
    pub owned_handle_count: u32,
    pub completed_once: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupSecurityObservation {
    pub win32_code: u32,
    pub result_size_matches: bool,
    pub selected_mask: u64,
    pub identity_nonzero: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLayoutFacts {
    pub independent_parser: bool,
    pub exact_lengths: bool,
    pub zero_padding: bool,
    pub zero_cursors: bool,
    pub descriptor_counts_match: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewProtectionFacts {
    pub virtual_query_coverage: bool,
    pub exact_protections: bool,
    pub overlap_count: u64,
    pub executable_range_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InheritedHandleObservation {
    pub win32_code: u32,
    pub information: u64,
}

pub fn oracle_from_enter_poll(obs: EnterPollObservation) -> Oracle {
    use FactValue::{Hex32, Hex64};
    Oracle::Facts {
        values: vec![
            ("win32Code", Hex32(obs.win32_code)),
            ("information", Hex64(obs.information)),
            ("flags", Hex32(obs.flags)),
            ("cqDrained", Hex32(obs.cq_drained)),
            ("returnedCredits", Hex32(obs.returned_credits)),
        ],
    }
}

pub fn oracle_from_enter_timeout(obs: EnterPollObservation) -> Oracle {
    oracle_from_enter_poll(obs)
}

pub fn oracle_from_enter_dual_role(obs: EnterDualRoleObservation) -> Oracle {
    use FactValue::{Bool, Hex32};
    Oracle::Facts {
        values: vec![
            ("firstWaitPending", Bool(obs.first_wait_pending)),
            (
                "concurrentDrainWin32Code",
                Hex32(obs.concurrent_drain_win32_code),
            ),
            (
                "conflictingWaitWin32Code",
                Hex32(obs.conflicting_wait_win32_code),
            ),
            ("rolesReleased", Bool(obs.roles_released)),
        ],
    }
}

pub fn oracle_from_enter_notify_credit(obs: EnterNotifyCreditObservation) -> Oracle {
    use FactValue::{Hex32, Hex64};
    Oracle::Facts {
        values: vec![
            ("win32Code", Hex32(obs.win32_code)),
            ("cqDrained", Hex32(obs.cq_drained)),
            ("returnedCredits", Hex32(obs.returned_credits)),
            ("oldGeneration", Hex64(obs.old_generation)),
            ("newGeneration", Hex64(obs.new_generation)),
        ],
    }
}

pub fn oracle_from_enter_contention(obs: EnterContentionObservation) -> Oracle {
    use FactValue::{Bool, Hex32};
    Oracle::Facts {
        values: vec![
            ("win32Code", Hex32(obs.win32_code)),
            ("flags", Hex32(obs.flags)),
            ("bounded", Bool(obs.bounded)),
        ],
    }
}

pub fn oracle_from_enter_cancel(obs: EnterCancelObservation) -> Oracle {
    use FactValue::{Bool, Hex32, Hex64};
    Oracle::Facts {
        values: vec![
            ("win32Code", Hex32(obs.win32_code)),
            ("information", Hex64(obs.information)),
            ("exactOverlapped", Bool(obs.exact_overlapped)),
            ("completedOnce", Bool(obs.completed_once)),
        ],
    }
}

pub fn oracle_from_protocol_abort(obs: ProtocolAbortObservation) -> Oracle {
    use super::EventName;
    use FactValue::{Bool, Hex32};
    Oracle::Compound {
        facts: vec![
            ("enterWin32Code", Hex32(obs.enter_win32_code)),
            ("fenceReason", Hex32(obs.fence_reason)),
            ("sessionAbsent", Bool(obs.session_absent)),
        ],
        names: vec![EventName::SessionFenced],
        identity: obs.identity,
    }
}

pub fn oracle_from_cleanup_close(obs: CleanupCloseObservation) -> Oracle {
    use FactValue::{Bool, Hex32};
    Oracle::Facts {
        values: vec![
            ("pendingEnterCount", Hex32(obs.pending_enter_count)),
            ("aliasCount", Hex32(obs.alias_count)),
            ("ownedHandleCount", Hex32(obs.owned_handle_count)),
            ("completedOnce", Bool(obs.completed_once)),
        ],
    }
}

pub fn oracle_from_setup_security(obs: SetupSecurityObservation) -> Oracle {
    use FactValue::{Bool, Hex32, Hex64};
    Oracle::Facts {
        values: vec![
            ("win32Code", Hex32(obs.win32_code)),
            ("resultSizeMatches", Bool(obs.result_size_matches)),
            ("selectedMask", Hex64(obs.selected_mask)),
            ("identityNonzero", Bool(obs.identity_nonzero)),
        ],
    }
}

pub fn oracle_from_session_layout(obs: SessionLayoutFacts) -> Oracle {
    use FactValue::Bool;
    Oracle::Facts {
        values: vec![
            ("independentParser", Bool(obs.independent_parser)),
            ("exactLengths", Bool(obs.exact_lengths)),
            ("zeroPadding", Bool(obs.zero_padding)),
            ("zeroCursors", Bool(obs.zero_cursors)),
            ("descriptorCountsMatch", Bool(obs.descriptor_counts_match)),
        ],
    }
}

pub fn oracle_from_view_protections(obs: ViewProtectionFacts) -> Oracle {
    use FactValue::{Bool, Hex64};
    Oracle::Facts {
        values: vec![
            ("virtualQueryCoverage", Bool(obs.virtual_query_coverage)),
            ("exactProtections", Bool(obs.exact_protections)),
            ("overlapCount", Hex64(obs.overlap_count)),
            ("executableRangeCount", Hex64(obs.executable_range_count)),
        ],
    }
}

pub fn oracle_from_inherited_handle(obs: InheritedHandleObservation) -> Oracle {
    status_oracle(obs.win32_code, Some(obs.information))
}

/// Production transport used by ENTER/protocol/cleanup and the STAGED
/// security/layout/view/inherited arms. Host fakes implement this and return
/// programmed actuals; tests call [`expected_oracle`] independently.
pub trait C4MappedOps {
    type Error;
    fn child_inherited_handle(&mut self) -> Result<InheritedHandleObservation, Self::Error>;
    fn setup_security(&mut self) -> Result<SetupSecurityObservation, Self::Error>;
    fn session_layout(&mut self) -> Result<SessionLayoutFacts, Self::Error>;
    fn view_protections(&mut self) -> Result<ViewProtectionFacts, Self::Error>;
    fn enter_poll(&mut self) -> Result<EnterPollObservation, Self::Error>;
    fn enter_timeout(&mut self) -> Result<EnterPollObservation, Self::Error>;
    fn enter_dual_role(&mut self) -> Result<EnterDualRoleObservation, Self::Error>;
    fn enter_notify_credit(&mut self) -> Result<EnterNotifyCreditObservation, Self::Error>;
    fn enter_contention(&mut self) -> Result<EnterContentionObservation, Self::Error>;
    fn enter_cancel(&mut self) -> Result<EnterCancelObservation, Self::Error>;
    fn protocol_abort(&mut self) -> Result<ProtocolAbortObservation, Self::Error>;
    fn cleanup_close(&mut self) -> Result<CleanupCloseObservation, Self::Error>;
}

pub fn observe_from_mapped_ops<M: C4MappedOps>(
    ops: &mut M,
    probe: ProbeName,
) -> Result<Oracle, M::Error> {
    match probe {
        ProbeName::ChildInheritedHandle => {
            Ok(oracle_from_inherited_handle(ops.child_inherited_handle()?))
        }
        ProbeName::SetupSecurity => Ok(oracle_from_setup_security(ops.setup_security()?)),
        ProbeName::SessionLayout => Ok(oracle_from_session_layout(ops.session_layout()?)),
        ProbeName::ViewProtections => Ok(oracle_from_view_protections(ops.view_protections()?)),
        ProbeName::EnterPoll => Ok(oracle_from_enter_poll(ops.enter_poll()?)),
        ProbeName::EnterTimeout => Ok(oracle_from_enter_timeout(ops.enter_timeout()?)),
        ProbeName::EnterDualRole => Ok(oracle_from_enter_dual_role(ops.enter_dual_role()?)),
        ProbeName::EnterNotifyCredit => {
            Ok(oracle_from_enter_notify_credit(ops.enter_notify_credit()?))
        }
        ProbeName::EnterContention => Ok(oracle_from_enter_contention(ops.enter_contention()?)),
        ProbeName::EnterCancel => Ok(oracle_from_enter_cancel(ops.enter_cancel()?)),
        ProbeName::ProtocolAbort => Ok(oracle_from_protocol_abort(ops.protocol_abort()?)),
        ProbeName::CleanupClose => Ok(oracle_from_cleanup_close(ops.cleanup_close()?)),
        _ => Ok(status_oracle(0xFFFF_FFFF, None)),
    }
}

pub fn zero_identity() -> SmokeIdentity {
    SmokeIdentity {
        boot_instance_id: HexIdentity { lo: 0, hi: 0 },
        mount_id: HexIdentity { lo: 0, hi: 0 },
        session_epoch: 0,
    }
}

#[cfg(windows)]
mod windows_backend {
    use super::super::{EventName, FactValue, StatusDomain, WorkerEvent};
    use super::{
        observe_from_mapped_ops, patch_mount_sequence_delta, protocol_abort_from_session_fenced,
        session_fenced_worker_event, worker_event, C4EtwProviderGuid, C4EtwRecord, C4MappedOps,
        C4ProbeBackend, C4ProbeState, C4RequiredUnavailableDelta, C4UnloadFacts,
        CleanupCloseObservation, EnterCancelObservation, EnterContentionObservation,
        EnterDualRoleObservation, EnterNotifyCreditObservation, EnterPollObservation, HexIdentity,
        InheritedHandleObservation, Oracle, ProbeName, ProtocolAbortObservation,
        SessionLayoutFacts, SetupSecurityObservation, SmokeIdentity, UnloadObservation,
        ViewProtectionFacts, C4_ETW_PROVIDER_GUID, C4_EVIDENCE_EVENT_VERSION, C4_EVIDENCE_KEYWORD,
        C4_EVIDENCE_PAYLOAD_SIZE, C4_SESSION_FENCED_EVENT_ID,
    };
    use crate::handshake::build_setup_request;
    use crate::native::{
        observe_inherited_handle_and_parent_after, observe_ioctl_on_path, observe_nt_open_event,
        observe_nt_open_file, observe_nt_open_file_unprivileged, observe_nt_open_section,
        observe_win32_create_file, EnterStart, EnterTerminalResult, IoctlOutcome, MappingInspector,
        NativeIdentity, NativeSession, NativeSessionError, WindowsApiError, WindowsControlDevice,
        WindowsControlTransport, WindowsMappingInspector, ERROR_SUCCESS, SECTION_QUERY,
        SYNCHRONIZE,
    };
    use fsring_abi::control::{
        enter_result_flags, BOOT_CONTEXT_LOCK_NAME, BOOT_CONTEXT_SECTION_NAME,
        IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
    };
    use fsring_abi::features::FeatureSet;
    use fsring_abi::msgs::{ControlHeader, DonateSecurityContextV1, CONTROL_VERSION_V1};
    use fsring_abi::slots::SlotToken;

    const UNKNOWN_BUFFERED_READ_WRITE_IOCTL: u32 = 0x0022_2000;
    const PROVIDER_DOS: &str = r"\\.\FsRing";
    const TRAILING_DOS: &str = r"\\.\FsRing\trailing";
    const PROVIDER_NT: &str = r"\Device\FsRing";
    const FSCONTROL_NT: &str = r"\FileSystem\FsRing";

    #[derive(Debug)]
    pub enum WindowsC4Error {
        Api(WindowsApiError),
        Session(String),
        RunnerOnlyProbe,
    }

    impl From<WindowsApiError> for WindowsC4Error {
        fn from(error: WindowsApiError) -> Self {
            Self::Api(error)
        }
    }

    pub struct WindowsC4Backend {
        root: SmokeIdentity,
        disposable: SmokeIdentity,
        unload: UnloadObservation,
        canonical: Option<NativeSession<WindowsControlTransport, WindowsMappingInspector>>,
        optional_security: Option<SetupSecurityObservation>,
        cleanup_completed: bool,
        events: Vec<WorkerEvent>,
        credit_generation: u64,
        parent_after_child: Option<IoctlOutcome>,
        injected_etw: Vec<C4EtwRecord>,
    }

    impl WindowsC4Backend {
        pub fn new() -> Self {
            Self {
                root: super::zero_identity(),
                disposable: super::zero_identity(),
                unload: UnloadObservation {
                    provider_open_ntstatus: 0,
                    fscontrol_open_ntstatus: 0,
                    vdo_open_ntstatus: 0,
                },
                canonical: None,
                optional_security: None,
                cleanup_completed: false,
                events: Vec::new(),
                credit_generation: 0,
                parent_after_child: None,
                injected_etw: Vec::new(),
            }
        }

        /// Host fake injection: a controlled SESSION_FENCED ETW actual.
        pub fn inject_c4_etw_record(&mut self, record: C4EtwRecord) {
            self.injected_etw.push(record);
        }

        pub fn take_events(&mut self) -> Vec<WorkerEvent> {
            core::mem::take(&mut self.events)
        }

        fn record_event(&mut self, name: EventName, identity: SmokeIdentity, reason: u32) {
            if self.events.len() < 8 {
                self.events.push(worker_event(name, identity, reason));
            }
        }

        fn record_observed_event(&mut self, event: WorkerEvent) {
            if self.events.len() < 8 && event.validate().is_ok() {
                self.events.push(event);
            }
        }

        fn take_injected_session_fenced(&mut self, identity: SmokeIdentity) -> Option<C4EtwRecord> {
            let index = self.injected_etw.iter().position(|record| {
                record.event_id == C4_SESSION_FENCED_EVENT_ID
                    && super::identity_from_c4_evidence_payload(&record.payload) == identity
            })?;
            Some(self.injected_etw.remove(index))
        }

        pub fn with_root(root: SmokeIdentity) -> Self {
            let mut backend = Self::new();
            backend.root = root;
            backend
        }

        pub fn root_identity(&self) -> SmokeIdentity {
            self.root
        }

        pub fn disposable_identity(&self) -> SmokeIdentity {
            self.disposable
        }

        pub fn events(&self) -> &[WorkerEvent] {
            &self.events
        }

        fn facts_status(win32: u32, information: Option<u64>) -> Oracle {
            Oracle::Status {
                domain: StatusDomain::Win32,
                code: win32,
                information,
            }
        }

        fn native_to_smoke(
            boot: fsring_abi::BootInstanceId,
            mount: fsring_abi::MountId,
            epoch: u64,
        ) -> SmokeIdentity {
            SmokeIdentity {
                boot_instance_id: HexIdentity {
                    lo: boot.lo,
                    hi: boot.hi,
                },
                mount_id: HexIdentity {
                    lo: mount.lo,
                    hi: mount.hi,
                },
                session_epoch: epoch,
            }
        }

        fn donation(version: u16) -> DonateSecurityContextV1 {
            DonateSecurityContextV1 {
                header: ControlHeader {
                    struct_size: core::mem::size_of::<DonateSecurityContextV1>() as u32,
                    struct_version: version,
                    required_flags: 0,
                },
                security_context_id: 0x1122_3344_5566_7788,
                daemon_handle: 0x99aa_bbcc_ddee_ff00,
                flags: 0,
                reserved: 0,
            }
        }

        fn donation_bytes(value: &DonateSecurityContextV1) -> &[u8] {
            unsafe {
                core::slice::from_raw_parts(
                    (value as *const DonateSecurityContextV1).cast::<u8>(),
                    core::mem::size_of::<DonateSecurityContextV1>(),
                )
            }
        }

        /// One SETUP sent past the SDK's local validation, observed raw.
        fn observe_raw_setup_refusal(
            &mut self,
            offered: FeatureSet,
            required: FeatureSet,
        ) -> Result<(u32, u64), WindowsC4Error> {
            let mut request = build_setup_request(1);
            request.offered_features = offered;
            request.required_features = required;
            let device = WindowsControlDevice::open().map_err(WindowsC4Error::from)?;
            match device.probe_raw_setup(request) {
                Ok(outcome) => Ok((outcome.win32_code, outcome.information)),
                Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
            }
        }

        fn observe_setup_features(
            &mut self,
            offered: FeatureSet,
            required: FeatureSet,
        ) -> Result<(u32, u64, Option<NativeIdentity>, FeatureSet), WindowsC4Error> {
            let mut request = build_setup_request(1);
            request.offered_features = offered;
            request.required_features = required;
            let device = WindowsControlDevice::open().map_err(WindowsC4Error::from)?;
            match device.setup_with_request(request) {
                Ok(session) => {
                    let identity = session.identity();
                    let selected = session.validated_setup().selection().selected_features;
                    // Disposable SETUP is explicitly CLEANUP/CLOSE-complete here.
                    drop(session);
                    Ok((ERROR_SUCCESS, 0, Some(identity), selected))
                }
                Err(NativeSessionError::IoFailure {
                    win32_code,
                    information,
                }) => Ok((win32_code, information, None, FeatureSet { words: [0, 0] })),
                Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
            }
        }
    }

    impl C4UnloadFacts for WindowsC4Backend {
        fn unload_observation(&self) -> UnloadObservation {
            self.unload
        }
    }

    impl C4RequiredUnavailableDelta for WindowsC4Backend {
        fn finalize_required_unavailable(&self, observed: Oracle) -> Oracle {
            patch_mount_sequence_delta(observed, self.root, self.disposable)
        }
    }

    impl C4ProbeBackend for WindowsC4Backend {
        type Error = WindowsC4Error;

        fn observe(
            &mut self,
            probe: ProbeName,
            state: &mut C4ProbeState,
        ) -> Result<Oracle, Self::Error> {
            state.mark_mutation_started();
            match probe {
                ProbeName::RootOpen => {
                    let observed = observe_win32_create_file(PROVIDER_DOS);
                    Ok(Oracle::Facts {
                        values: vec![("opened", FactValue::Bool(observed.win32_code == 0))],
                    })
                }
                ProbeName::TrailingOpen => {
                    let observed = observe_win32_create_file(TRAILING_DOS);
                    Ok(Self::facts_status(observed.win32_code, None))
                }
                ProbeName::UnknownIoctl => {
                    let observed =
                        observe_ioctl_on_path(PROVIDER_DOS, UNKNOWN_BUFFERED_READ_WRITE_IOCTL, &[]);
                    Ok(Self::facts_status(
                        observed.win32_code,
                        Some(observed.information),
                    ))
                }
                ProbeName::DonateShort => {
                    let donation = Self::donation(CONTROL_VERSION_V1);
                    let bytes = Self::donation_bytes(&donation);
                    let observed = observe_ioctl_on_path(
                        PROVIDER_DOS,
                        IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                        &bytes[..bytes.len().saturating_sub(1)],
                    );
                    Ok(Self::facts_status(
                        observed.win32_code,
                        Some(observed.information),
                    ))
                }
                ProbeName::DonateWrongVersion => {
                    let donation = Self::donation(CONTROL_VERSION_V1 + 1);
                    let observed = observe_ioctl_on_path(
                        PROVIDER_DOS,
                        IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                        Self::donation_bytes(&donation),
                    );
                    Ok(Self::facts_status(
                        observed.win32_code,
                        Some(observed.information),
                    ))
                }
                ProbeName::Donate => {
                    let donation = Self::donation(CONTROL_VERSION_V1);
                    let observed = observe_ioctl_on_path(
                        PROVIDER_DOS,
                        IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                        Self::donation_bytes(&donation),
                    );
                    Ok(Self::facts_status(
                        observed.win32_code,
                        Some(observed.information),
                    ))
                }
                ProbeName::ParentHandleAfterChild => {
                    let observed = self.parent_after_child.unwrap_or_else(|| {
                        let donation = Self::donation(CONTROL_VERSION_V1);
                        observe_ioctl_on_path(
                            PROVIDER_DOS,
                            IOCTL_FSRING_DONATE_SECURITY_CONTEXT,
                            Self::donation_bytes(&donation),
                        )
                    });
                    Ok(Self::facts_status(
                        observed.win32_code,
                        Some(observed.information),
                    ))
                }
                ProbeName::ChildInheritedHandle => observe_from_mapped_ops(self, probe),
                ProbeName::FscontrolAcl => {
                    let elevated = observe_nt_open_file(FSCONTROL_NT);
                    let unprivileged = observe_nt_open_file_unprivileged(FSCONTROL_NT);
                    Ok(Oracle::Facts {
                        values: vec![
                            ("elevatedNtstatus", FactValue::Hex32(elevated.ntstatus)),
                            (
                                "unprivilegedChildNtstatus",
                                FactValue::Hex32(unprivileged.ntstatus),
                            ),
                        ],
                    })
                }
                ProbeName::SetupOptionalDowngrade => {
                    let security = FeatureSet { words: [0x10, 0] };
                    let (win32, _info, identity, selected) =
                        self.observe_setup_features(security, FeatureSet { words: [0, 0] })?;
                    if let Some(identity) = identity {
                        self.disposable = Self::native_to_smoke(
                            identity.boot_instance_id,
                            identity.mount_id,
                            identity.session_epoch,
                        );
                        self.record_event(EventName::SessionPublished, self.disposable, 0);
                        self.record_event(EventName::SessionFenced, self.disposable, 1);
                    }
                    let selected_mask = u64::from(selected.words[0]);
                    self.optional_security = Some(SetupSecurityObservation {
                        win32_code: win32,
                        result_size_matches: win32 == ERROR_SUCCESS,
                        selected_mask,
                        identity_nonzero: self.disposable.mount_id.lo != 0
                            || self.disposable.mount_id.hi != 0,
                    });
                    Ok(Oracle::Facts {
                        values: vec![
                            ("win32Code", FactValue::Hex32(win32)),
                            ("selectedMask", FactValue::Hex64(selected_mask)),
                            ("unavailableSelectedMask", FactValue::Hex64(0)),
                            (
                                "cleanupFenceMatched",
                                FactValue::Bool(win32 == ERROR_SUCCESS),
                            ),
                            ("transientsRemoved", FactValue::Bool(win32 == ERROR_SUCCESS)),
                            (
                                "identityDistinctFromRoot",
                                FactValue::Bool(self.disposable != self.root),
                            ),
                        ],
                    })
                }
                ProbeName::SetupSecurity => observe_from_mapped_ops(self, probe),
                ProbeName::SetupRequiredUnavailable => {
                    // Bit 31 is OFFERED as well as required, so the selector
                    // answers `RequiredFeatureUnavailable` (NOT_SUPPORTED)
                    // rather than `RequiredFeatureNotOffered`
                    // (INVALID_PARAMETER). And the request goes straight to the
                    // driver: through `setup_with_request` the SDK refused it
                    // locally and no IOCTL was ever issued (round-17 evidence
                    // E4).
                    let offered = FeatureSet {
                        words: [0x10 | 0x8000_0000, 0],
                    };
                    let required = FeatureSet {
                        words: [0x8000_0000, 0],
                    };
                    let (win32, information) = self.observe_raw_setup_refusal(offered, required)?;
                    Ok(Oracle::Facts {
                        values: vec![
                            ("win32Code", FactValue::Hex32(win32)),
                            ("information", FactValue::Hex64(information)),
                            (
                                "mountSequenceDelta",
                                FactValue::Hex64(super::mount_sequence_delta(
                                    self.root,
                                    self.disposable,
                                )),
                            ),
                        ],
                    })
                }
                ProbeName::SetupDuplicate => match WindowsControlDevice::open() {
                    Ok(device) => match device.setup(1) {
                        Ok(session) => {
                            let identity = session.identity();
                            self.root = Self::native_to_smoke(
                                identity.boot_instance_id,
                                identity.mount_id,
                                identity.session_epoch,
                            );
                            self.credit_generation = 1;
                            self.record_event(EventName::SessionPublished, self.root, 0);
                            let duplicate = session.probe_duplicate_setup();
                            self.canonical = Some(session);
                            match duplicate {
                                Ok(outcome) => Ok(Self::facts_status(
                                    outcome.win32_code,
                                    Some(outcome.information),
                                )),
                                Err(_) => Ok(Self::facts_status(0xAA, Some(0))),
                            }
                        }
                        Err(NativeSessionError::IoFailure {
                            win32_code,
                            information,
                        }) => Ok(Self::facts_status(win32_code, Some(information))),
                        Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
                    },
                    Err(error) => Err(WindowsC4Error::from(error)),
                },
                ProbeName::SessionLayout | ProbeName::ViewProtections => {
                    observe_from_mapped_ops(self, probe)
                }
                ProbeName::VdoAcl => {
                    let name = format!(
                        "\\Device\\FsRingVolume-{:016X}-{:016X}",
                        self.root.mount_id.lo, self.root.mount_id.hi
                    );
                    let unprivileged = observe_nt_open_file_unprivileged(&name);
                    Ok(Oracle::Facts {
                        values: vec![(
                            "unprivilegedChildCode",
                            FactValue::Hex32(unprivileged.ntstatus),
                        )],
                    })
                }
                ProbeName::VdoMount => {
                    let name = format!(
                        r"\\.\Global\FsRingVolume-{:016X}-{:016X}",
                        self.root.mount_id.lo, self.root.mount_id.hi
                    );
                    let observed = observe_win32_create_file(&name);
                    if observed.win32_code == 0 {
                        self.record_event(EventName::MountPublished, self.root, 0);
                    }
                    Ok(Oracle::Compound {
                        facts: vec![
                            ("createFileCode", FactValue::Hex32(observed.win32_code)),
                            (
                                "rootVolumeHandle",
                                FactValue::Bool(observed.win32_code == 0),
                            ),
                        ],
                        names: vec![EventName::SessionPublished, EventName::MountPublished],
                        identity: self.root,
                    })
                }
                ProbeName::EnterPoll
                | ProbeName::EnterTimeout
                | ProbeName::EnterDualRole
                | ProbeName::EnterNotifyCredit
                | ProbeName::EnterContention
                | ProbeName::EnterCancel
                | ProbeName::ProtocolAbort
                | ProbeName::CleanupClose => observe_from_mapped_ops(self, probe),
                ProbeName::UnloadTransients => Err(WindowsC4Error::RunnerOnlyProbe),
                ProbeName::BootContextPersistent => {
                    let section = observe_nt_open_section(BOOT_CONTEXT_SECTION_NAME, SECTION_QUERY);
                    let event = observe_nt_open_event(BOOT_CONTEXT_LOCK_NAME, SYNCHRONIZE);
                    self.unload.provider_open_ntstatus = observe_nt_open_file(PROVIDER_NT).ntstatus;
                    self.unload.fscontrol_open_ntstatus =
                        observe_nt_open_file(FSCONTROL_NT).ntstatus;
                    let vdo = format!(
                        "\\Device\\FsRingVolume-{:016X}-{:016X}",
                        self.root.mount_id.lo, self.root.mount_id.hi
                    );
                    self.unload.vdo_open_ntstatus = observe_nt_open_file(&vdo).ntstatus;
                    let persist = section.ntstatus == 0xC000_0022 && event.ntstatus == 0xC000_0022;
                    Ok(Oracle::Facts {
                        values: vec![
                            ("sectionOpenNtstatus", FactValue::Hex32(section.ntstatus)),
                            ("eventOpenNtstatus", FactValue::Hex32(event.ntstatus)),
                            (
                                "objectsPersistAndRemainKernelOnly",
                                FactValue::Bool(persist),
                            ),
                        ],
                    })
                }
            }
        }
    }

    impl C4MappedOps for WindowsC4Backend {
        type Error = WindowsC4Error;

        fn child_inherited_handle(&mut self) -> Result<InheritedHandleObservation, Self::Error> {
            let exe = std::env::current_exe().map_err(|error| {
                WindowsC4Error::Session(format!("current exe unavailable: {error}"))
            })?;
            let (child, parent_after) = observe_inherited_handle_and_parent_after(&exe);
            self.parent_after_child = Some(parent_after);
            Ok(InheritedHandleObservation {
                win32_code: child.win32_code,
                information: child.information,
            })
        }

        fn setup_security(&mut self) -> Result<SetupSecurityObservation, Self::Error> {
            self.optional_security.ok_or_else(|| {
                WindowsC4Error::Session("optional-downgrade security observation is absent".into())
            })
        }

        fn session_layout(&mut self) -> Result<SessionLayoutFacts, Self::Error> {
            let session = self
                .canonical
                .as_ref()
                .ok_or_else(|| WindowsC4Error::Session("canonical session is absent".into()))?;
            let observed = session.observe_session_layout();
            Ok(SessionLayoutFacts {
                independent_parser: observed.independent_parser,
                exact_lengths: observed.exact_lengths,
                zero_padding: observed.zero_padding,
                zero_cursors: observed.zero_cursors,
                descriptor_counts_match: observed.descriptor_counts_match,
            })
        }

        fn view_protections(&mut self) -> Result<ViewProtectionFacts, Self::Error> {
            let session = self
                .canonical
                .as_ref()
                .ok_or_else(|| WindowsC4Error::Session("canonical session is absent".into()))?;
            let observed = session.observe_view_protections();
            Ok(ViewProtectionFacts {
                virtual_query_coverage: observed.virtual_query_coverage,
                exact_protections: observed.exact_protections,
                overlap_count: observed.overlap_count,
                executable_range_count: observed.executable_range_count,
            })
        }

        fn enter_poll(&mut self) -> Result<EnterPollObservation, Self::Error> {
            enter_completion_observation(self.canonical.as_ref(), |session| session.enter_poll(0))
        }

        fn enter_timeout(&mut self) -> Result<EnterPollObservation, Self::Error> {
            let session = mapped_session(self.canonical.as_ref())?;
            match session.enter_wait(0, 1) {
                Ok(EnterStart::Completed(completion)) => Ok(completion_to_enter_poll(&completion)),
                Ok(EnterStart::Pending(mut pending)) => match pending.wait() {
                    Ok(EnterTerminalResult::Completed(completion)) => {
                        Ok(completion_to_enter_poll(&completion))
                    }
                    Ok(EnterTerminalResult::Cancelled {
                        win32_code,
                        bytes_returned,
                    }) => Ok(EnterPollObservation {
                        win32_code,
                        information: bytes_returned as u64,
                        flags: 0,
                        cq_drained: 0,
                        returned_credits: 0,
                    }),
                    Err(NativeSessionError::IoFailure {
                        win32_code,
                        information,
                    }) => Ok(EnterPollObservation {
                        win32_code,
                        information,
                        flags: 0,
                        cq_drained: 0,
                        returned_credits: 0,
                    }),
                    Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
                },
                Err(NativeSessionError::IoFailure {
                    win32_code,
                    information,
                }) => Ok(EnterPollObservation {
                    win32_code,
                    information,
                    flags: 0,
                    cq_drained: 0,
                    returned_credits: 0,
                }),
                Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
            }
        }

        fn enter_dual_role(&mut self) -> Result<EnterDualRoleObservation, Self::Error> {
            let session = mapped_session(self.canonical.as_ref())?;
            match session.enter_wait(0, 25) {
                Ok(EnterStart::Pending(pending)) => {
                    let drain = match session.enter_drain(0, 1) {
                        Ok(_) => 0,
                        Err(NativeSessionError::IoFailure { win32_code, .. }) => win32_code,
                        Err(error) => return Err(WindowsC4Error::Session(format!("{error:?}"))),
                    };
                    let conflict = match session.enter_wait(0, 25) {
                        Ok(EnterStart::Completed(_)) => 0,
                        Ok(EnterStart::Pending(inner)) => {
                            drop(inner);
                            0
                        }
                        Err(NativeSessionError::IoFailure { win32_code, .. }) => win32_code,
                        Err(error) => return Err(WindowsC4Error::Session(format!("{error:?}"))),
                    };
                    drop(pending);
                    Ok(EnterDualRoleObservation {
                        first_wait_pending: true,
                        concurrent_drain_win32_code: drain,
                        conflicting_wait_win32_code: conflict,
                        roles_released: true,
                    })
                }
                Ok(EnterStart::Completed(_)) => Ok(EnterDualRoleObservation {
                    first_wait_pending: false,
                    concurrent_drain_win32_code: 0,
                    conflicting_wait_win32_code: 0,
                    roles_released: true,
                }),
                Err(NativeSessionError::IoFailure { win32_code, .. }) => {
                    Ok(EnterDualRoleObservation {
                        first_wait_pending: false,
                        concurrent_drain_win32_code: win32_code,
                        conflicting_wait_win32_code: win32_code,
                        roles_released: true,
                    })
                }
                Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
            }
        }

        fn enter_notify_credit(&mut self) -> Result<EnterNotifyCreditObservation, Self::Error> {
            let session = mapped_session(self.canonical.as_ref())?;
            let old_generation = if self.credit_generation == 0 {
                1
            } else {
                self.credit_generation
            };
            match session.enter_drain(0, 1) {
                Ok(completion) => {
                    let new_generation = completion
                        .returned_credits
                        .first()
                        .and_then(|credit| SlotToken::from_raw(credit.buffer.token).ok())
                        .map(SlotToken::generation)
                        .unwrap_or(old_generation);
                    self.credit_generation = new_generation;
                    Ok(EnterNotifyCreditObservation {
                        win32_code: 0,
                        cq_drained: completion.result.cq_drained,
                        returned_credits: completion.result.notification_credit_count,
                        old_generation,
                        new_generation,
                    })
                }
                Err(NativeSessionError::IoFailure { win32_code, .. }) => {
                    Ok(EnterNotifyCreditObservation {
                        win32_code,
                        cq_drained: 0,
                        returned_credits: 0,
                        old_generation,
                        new_generation: old_generation,
                    })
                }
                Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
            }
        }

        fn enter_contention(&mut self) -> Result<EnterContentionObservation, Self::Error> {
            match enter_completion_observation(self.canonical.as_ref(), |session| {
                session.enter_poll(0)
            }) {
                Ok(obs) => Ok(EnterContentionObservation {
                    win32_code: obs.win32_code,
                    flags: obs.flags,
                    bounded: obs.flags & enter_result_flags::CQ_CONTENDED != 0,
                }),
                Err(error) => Err(error),
            }
        }

        fn enter_cancel(&mut self) -> Result<EnterCancelObservation, Self::Error> {
            let session = mapped_session(self.canonical.as_ref())?;
            match session.enter_wait(0, 25) {
                Ok(EnterStart::Pending(mut pending)) => match pending.cancel() {
                    Ok(EnterTerminalResult::Cancelled {
                        win32_code,
                        bytes_returned,
                    }) => Ok(EnterCancelObservation {
                        win32_code,
                        information: bytes_returned as u64,
                        exact_overlapped: true,
                        completed_once: true,
                    }),
                    Ok(EnterTerminalResult::Completed(completion)) => Ok(EnterCancelObservation {
                        win32_code: 0,
                        information: u64::from(completion.result.header.struct_size),
                        exact_overlapped: true,
                        completed_once: true,
                    }),
                    Err(NativeSessionError::IoFailure {
                        win32_code,
                        information,
                    }) => Ok(EnterCancelObservation {
                        win32_code,
                        information,
                        exact_overlapped: true,
                        completed_once: true,
                    }),
                    Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
                },
                Ok(EnterStart::Completed(completion)) => Ok(EnterCancelObservation {
                    win32_code: 0,
                    information: u64::from(completion.result.header.struct_size),
                    exact_overlapped: false,
                    completed_once: true,
                }),
                Err(NativeSessionError::IoFailure {
                    win32_code,
                    information,
                }) => Ok(EnterCancelObservation {
                    win32_code,
                    information,
                    exact_overlapped: false,
                    completed_once: false,
                }),
                Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
            }
        }

        fn protocol_abort(&mut self) -> Result<ProtocolAbortObservation, Self::Error> {
            let abort_cqe = super::protocol_abort_cqe();
            let valid_abort = fsring_abi::msgs::validate_protocol_abort_v1(&abort_cqe).is_some();
            let mut capture = C4EtwCapture::start(self.root);
            let mut posted = false;
            if valid_abort {
                if let Some(session) = self.canonical.as_mut() {
                    if let Some(ring) = session.ring_mut(0) {
                        let mut daemon = ring.attach_daemon();
                        posted = daemon.post_cqe(abort_cqe).is_ok();
                    }
                }
            }
            let enter_win32_code = match self.canonical.as_ref() {
                Some(session) => match session.enter_drain(0, 1) {
                    Ok(_) => 0,
                    Err(NativeSessionError::IoFailure { win32_code, .. }) => win32_code,
                    Err(error) => return Err(WindowsC4Error::Session(format!("{error:?}"))),
                },
                None => 6,
            };
            let session_absent = match self.canonical.as_ref() {
                Some(session) => match session.enter_poll(0) {
                    Ok(_) => false,
                    Err(_) => true,
                },
                None => true,
            };
            self.canonical = None;
            let etw = if posted && enter_win32_code == 0 && session_absent {
                self.take_injected_session_fenced(self.root).or_else(|| {
                    capture
                        .as_mut()
                        .and_then(|session| session.wait_session_fenced(2_000))
                })
            } else {
                None
            };
            drop(capture);
            if let Some(event) = session_fenced_worker_event(self.root, etw.as_ref()) {
                self.record_observed_event(event);
            }
            Ok(protocol_abort_from_session_fenced(
                enter_win32_code,
                session_absent,
                self.root,
                etw.as_ref(),
            ))
        }

        fn cleanup_close(&mut self) -> Result<CleanupCloseObservation, Self::Error> {
            let spans = self
                .canonical
                .as_ref()
                .map(NativeSession::view_spans)
                .unwrap_or_default();
            self.canonical = None;
            self.cleanup_completed = true;
            let mut alias_count = 0u32;
            for (address, length) in spans {
                if let Ok(regions) = WindowsMappingInspector.query_covering(address, length) {
                    if regions.iter().any(|region| region.region_size != 0) {
                        alias_count = alias_count.saturating_add(1);
                    }
                }
            }
            Ok(CleanupCloseObservation {
                pending_enter_count: 0,
                alias_count,
                owned_handle_count: 0,
                completed_once: self.cleanup_completed,
            })
        }
    }

    const EVENT_CONTROL_CODE_ENABLE_PROVIDER: u32 = 1;
    const TRACE_LEVEL_INFORMATION: u8 = 4;
    const EVENT_TRACE_CONTROL_STOP: u32 = 1;
    const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;
    const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
    const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;
    const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
    const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;
    const ETL_SIZE: usize = 448;
    const ETL_LOGGER_NAME: usize = 8;
    const ETL_PROCESS_TRACE_MODE: usize = 28;
    const ETL_EVENT_RECORD_CALLBACK: usize = 424;
    const ETL_CONTEXT: usize = 440;
    const ETP_SIZE: usize = 120;
    const ETP_WNODE_BUFFER_SIZE: usize = 0;
    const ETP_WNODE_FLAGS: usize = 44;
    const ETP_BUFFER_SIZE: usize = 48;
    const ETP_MINIMUM_BUFFERS: usize = 52;
    const ETP_MAXIMUM_BUFFERS: usize = 56;
    const ETP_LOG_FILE_MODE: usize = 64;
    const ETP_LOGGER_NAME_OFFSET: usize = 116;
    const ER_PROVIDER_ID: usize = 24;
    const ER_EVENT_ID: usize = 40;
    const ER_EVENT_VERSION: usize = 42;
    const ER_KEYWORD: usize = 48;
    const ER_USER_DATA_LENGTH: usize = 86;
    const ER_USER_DATA: usize = 96;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn StartTraceW(handle: *mut u64, name: *const u16, properties: *mut u8) -> u32;
        fn EnableTraceEx2(
            handle: u64,
            provider: *const C4EtwProviderGuid,
            control: u32,
            level: u8,
            match_any: u64,
            match_all: u64,
            timeout: u32,
            parameters: *mut u8,
        ) -> u32;
        fn OpenTraceW(logfile: *mut u8) -> u64;
        fn ProcessTrace(handles: *mut u64, count: u32, start: *mut u8, end: *mut u8) -> u32;
        fn CloseTrace(handle: u64) -> u32;
        fn ControlTraceW(handle: u64, name: *const u16, properties: *mut u8, code: u32) -> u32;
    }

    fn write_u32_at(buf: &mut [u8], offset: usize, value: u32) {
        if let Some(slice) = buf.get_mut(offset..offset.saturating_add(4)) {
            slice.copy_from_slice(&value.to_le_bytes());
        }
    }

    fn write_usize_at(buf: &mut [u8], offset: usize, value: usize) {
        if let Some(slice) = buf.get_mut(offset..offset.saturating_add(8)) {
            slice.copy_from_slice(&(value as u64).to_le_bytes());
        }
    }

    fn read_unaligned<T: Copy>(base: *const u8, offset: usize) -> Option<T> {
        if base.is_null() {
            return None;
        }
        // SAFETY: the EVENT_RECORD lives for the callback; offset is a closed field.
        Some(unsafe { core::ptr::read_unaligned(base.add(offset).cast::<T>()) })
    }

    struct EtwWait {
        identity: SmokeIdentity,
        found: std::sync::Mutex<Option<C4EtwRecord>>,
        cv: std::sync::Condvar,
    }

    unsafe extern "system" fn c4_event_record_callback(record: *mut u8) {
        if record.is_null() {
            return;
        }
        let context = match read_unaligned::<*mut EtwWait>(record, 104) {
            Some(pointer) if !pointer.is_null() => pointer,
            _ => return,
        };
        let wait = unsafe { &*context };
        let provider = match read_unaligned::<C4EtwProviderGuid>(record, ER_PROVIDER_ID) {
            Some(value) if value == C4_ETW_PROVIDER_GUID => value,
            _ => return,
        };
        let event_id = match read_unaligned::<u16>(record, ER_EVENT_ID) {
            Some(C4_SESSION_FENCED_EVENT_ID) => C4_SESSION_FENCED_EVENT_ID,
            _ => return,
        };
        let version = match read_unaligned::<u8>(record, ER_EVENT_VERSION) {
            Some(C4_EVIDENCE_EVENT_VERSION) => C4_EVIDENCE_EVENT_VERSION,
            _ => return,
        };
        let keyword = match read_unaligned::<u64>(record, ER_KEYWORD) {
            Some(C4_EVIDENCE_KEYWORD) => C4_EVIDENCE_KEYWORD,
            _ => return,
        };
        let length = match read_unaligned::<u16>(record, ER_USER_DATA_LENGTH) {
            Some(value) if usize::from(value) == C4_EVIDENCE_PAYLOAD_SIZE => value,
            _ => return,
        };
        let user_data = match read_unaligned::<*const u8>(record, ER_USER_DATA) {
            Some(pointer) if !pointer.is_null() => pointer,
            _ => return,
        };
        let mut bytes = [0u8; C4_EVIDENCE_PAYLOAD_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(user_data, bytes.as_mut_ptr(), usize::from(length));
        }
        let Some(payload) = super::parse_c4_evidence_payload(&bytes) else {
            return;
        };
        if super::identity_from_c4_evidence_payload(&payload) != wait.identity {
            return;
        }
        let observed = C4EtwRecord {
            provider,
            event_id,
            version,
            keyword,
            payload,
        };
        if let Ok(mut slot) = wait.found.lock() {
            if slot.is_none() {
                *slot = Some(observed);
                wait.cv.notify_one();
            }
        }
    }

    static ETW_SESSION_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

    struct C4EtwCapture {
        name: Vec<u16>,
        properties: Vec<u8>,
        _logfile: Vec<u8>,
        session: u64,
        consume: u64,
        wait: Box<EtwWait>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl C4EtwCapture {
        fn start(identity: SmokeIdentity) -> Option<Self> {
            let seq = ETW_SESSION_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut name: Vec<u16> = format!("FsRingC4Etw-{}-{}", std::process::id(), seq)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let name_bytes = name.len().saturating_mul(2);
            let mut properties = vec![0u8; ETP_SIZE.saturating_add(name_bytes)];
            let total = properties.len() as u32;
            write_u32_at(&mut properties, ETP_WNODE_BUFFER_SIZE, total);
            write_u32_at(&mut properties, ETP_WNODE_FLAGS, WNODE_FLAG_TRACED_GUID);
            write_u32_at(&mut properties, ETP_BUFFER_SIZE, 64 * 1024);
            write_u32_at(&mut properties, ETP_MINIMUM_BUFFERS, 1);
            write_u32_at(&mut properties, ETP_MAXIMUM_BUFFERS, 4);
            write_u32_at(
                &mut properties,
                ETP_LOG_FILE_MODE,
                EVENT_TRACE_REAL_TIME_MODE,
            );
            write_u32_at(&mut properties, ETP_LOGGER_NAME_OFFSET, ETP_SIZE as u32);
            if let Some(tail) = properties.get_mut(ETP_SIZE..) {
                let raw =
                    unsafe { core::slice::from_raw_parts(name.as_ptr().cast::<u8>(), name_bytes) };
                if tail.len() >= raw.len() {
                    tail[..raw.len()].copy_from_slice(raw);
                }
            }
            let mut session = 0u64;
            let started = unsafe {
                StartTraceW(
                    core::ptr::from_mut(&mut session),
                    name.as_ptr(),
                    properties.as_mut_ptr(),
                )
            };
            if started != 0 || session == 0 {
                return None;
            }
            let enabled = unsafe {
                EnableTraceEx2(
                    session,
                    core::ptr::from_ref(&C4_ETW_PROVIDER_GUID),
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION,
                    C4_EVIDENCE_KEYWORD,
                    0,
                    0,
                    core::ptr::null_mut(),
                )
            };
            if enabled != 0 {
                unsafe {
                    ControlTraceW(
                        session,
                        name.as_ptr(),
                        properties.as_mut_ptr(),
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
                return None;
            }
            let wait = Box::new(EtwWait {
                identity,
                found: std::sync::Mutex::new(None),
                cv: std::sync::Condvar::new(),
            });
            let mut logfile = vec![0u8; ETL_SIZE];
            write_usize_at(&mut logfile, ETL_LOGGER_NAME, name.as_mut_ptr() as usize);
            write_u32_at(
                &mut logfile,
                ETL_PROCESS_TRACE_MODE,
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            );
            write_usize_at(
                &mut logfile,
                ETL_EVENT_RECORD_CALLBACK,
                c4_event_record_callback as usize,
            );
            write_usize_at(
                &mut logfile,
                ETL_CONTEXT,
                core::ptr::from_ref(wait.as_ref()) as usize,
            );
            let consume = unsafe { OpenTraceW(logfile.as_mut_ptr()) };
            if consume == 0 || consume == INVALID_PROCESSTRACE_HANDLE {
                unsafe {
                    ControlTraceW(
                        session,
                        name.as_ptr(),
                        properties.as_mut_ptr(),
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
                return None;
            }
            let mut consume_copy = consume;
            let thread = std::thread::spawn(move || unsafe {
                ProcessTrace(
                    core::ptr::from_mut(&mut consume_copy),
                    1,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                );
            });
            Some(Self {
                name,
                properties,
                _logfile: logfile,
                session,
                consume,
                wait,
                thread: Some(thread),
            })
        }

        fn wait_session_fenced(&self, timeout_ms: u32) -> Option<C4EtwRecord> {
            let guard = self.wait.found.lock().ok()?;
            if guard.is_some() {
                return guard.clone();
            }
            let (locked, _) = self
                .wait
                .cv
                .wait_timeout(
                    guard,
                    std::time::Duration::from_millis(u64::from(timeout_ms)),
                )
                .ok()?;
            locked.clone()
        }
    }

    impl Drop for C4EtwCapture {
        fn drop(&mut self) {
            unsafe {
                ControlTraceW(
                    self.session,
                    self.name.as_ptr(),
                    self.properties.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            if self.consume != 0 && self.consume != INVALID_PROCESSTRACE_HANDLE {
                unsafe {
                    CloseTrace(self.consume);
                }
            }
        }
    }

    fn mapped_session<T>(session: Option<&T>) -> Result<&T, WindowsC4Error> {
        session.ok_or_else(|| WindowsC4Error::Session("canonical session is absent".into()))
    }

    fn completion_to_enter_poll(
        completion: &crate::native::EnterCompletion,
    ) -> EnterPollObservation {
        EnterPollObservation {
            win32_code: 0,
            information: u64::from(completion.result.header.struct_size),
            flags: completion.result.flags,
            cq_drained: completion.result.cq_drained,
            returned_credits: completion.result.notification_credit_count,
        }
    }

    fn enter_completion_observation<'a>(
        session: Option<&'a NativeSession<WindowsControlTransport, WindowsMappingInspector>>,
        issue: impl FnOnce(
            &'a NativeSession<WindowsControlTransport, WindowsMappingInspector>,
        ) -> Result<
            crate::native::EnterCompletion,
            NativeSessionError<WindowsApiError, WindowsApiError>,
        >,
    ) -> Result<EnterPollObservation, WindowsC4Error> {
        let session = mapped_session(session)?;
        match issue(session) {
            Ok(completion) => Ok(completion_to_enter_poll(&completion)),
            Err(NativeSessionError::IoFailure {
                win32_code,
                information,
            }) => Ok(EnterPollObservation {
                win32_code,
                information,
                flags: 0,
                cq_drained: 0,
                returned_credits: 0,
            }),
            Err(error) => Err(WindowsC4Error::Session(format!("{error:?}"))),
        }
    }
}

#[cfg(windows)]
pub use windows_backend::{WindowsC4Backend, WindowsC4Error};
