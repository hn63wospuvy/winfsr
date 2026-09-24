//! Allocation-free request-table admission.
//!
//! The table borrows caller-owned backing and links application slots into an
//! intrusive free list. It neither allocates nor manufactures request
//! completion ownership.

use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

use fsring_abi::{
    ReqId, classify_req_index,
    ids::REQ_GENERATION_MAX,
    layout::{cq_kind, op},
    limits::{
        GLOBAL_EXTERNAL_CHANGE_ACK_REQID, MAX_INFLIGHT, MAX_RING_COUNT, MIN_RING_COUNT,
        ReqIndexClass, ReqIndexError, SYSTEM_REQID_BASE, SYSTEM_REQUEST_SLOTS_PER_RING,
    },
    validate::{ValidatedTopology, next_req_generation_v21},
};

use crate::typestate::{CompletionOwner, CompletionSink, PendingToken};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTopology {
    ring_count: u32,
    max_inflight: u32,
}

impl RequestTopology {
    pub fn try_new(ring_count: u32, max_inflight: u32) -> Result<Self, TopologyError> {
        if !(MIN_RING_COUNT..=MAX_RING_COUNT).contains(&ring_count) {
            return Err(TopologyError::RingCountOutOfRange);
        }
        if max_inflight == 0 || max_inflight > MAX_INFLIGHT {
            return Err(TopologyError::MaxInflightOutOfRange);
        }
        let topology = Self {
            ring_count,
            max_inflight,
        };
        if !matches!(
            classify_table_index(topology, 0),
            Ok(ReqIndexClass::Application { index: 0 })
        ) {
            return Err(TopologyError::InvalidPartition);
        }
        let Some(last_system) = ring_count
            .checked_mul(SYSTEM_REQUEST_SLOTS_PER_RING)
            .and_then(|count| count.checked_sub(1))
            .and_then(|offset| fsring_abi::SYSTEM_REQID_BASE.checked_add(offset))
        else {
            return Err(TopologyError::InvalidPartition);
        };
        if classify_table_index(topology, last_system).is_err()
            || !matches!(
                classify_table_index(topology, GLOBAL_EXTERNAL_CHANGE_ACK_REQID),
                Ok(ReqIndexClass::ExternalChangeAck)
            )
        {
            return Err(TopologyError::InvalidPartition);
        }
        Ok(topology)
    }

    pub const fn from_validated(value: ValidatedTopology) -> Self {
        Self {
            ring_count: value.ring_count(),
            max_inflight: value.max_inflight(),
        }
    }

    pub const fn ring_count(self) -> u32 {
        self.ring_count
    }

    pub const fn max_inflight(self) -> u32 {
        self.max_inflight
    }
}

fn classify_table_index(
    topology: RequestTopology,
    index: u32,
) -> Result<ReqIndexClass, ReqIndexError> {
    classify_req_index(index, topology.ring_count, topology.max_inflight)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationCaptureRole {
    CompletionOnly,
    JournaledSemantic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationPhase {
    opcode: u16,
    capture_role: ApplicationCaptureRole,
}

impl ApplicationPhase {
    pub const fn new(opcode: u16) -> Result<Self, ApplicationPhaseError> {
        if is_application_opcode(opcode) {
            Ok(Self {
                opcode,
                capture_role: ApplicationCaptureRole::CompletionOnly,
            })
        } else {
            Err(ApplicationPhaseError::UnsupportedOpcode)
        }
    }

    pub const fn journaled_semantic(opcode: u16) -> Result<Self, ApplicationPhaseError> {
        if !is_application_opcode(opcode) {
            return Err(ApplicationPhaseError::UnsupportedOpcode);
        }
        if matches!(opcode, op::COMMIT_OPEN | op::WRITE | op::MUTATE) {
            Ok(Self {
                opcode,
                capture_role: ApplicationCaptureRole::JournaledSemantic,
            })
        } else {
            Err(ApplicationPhaseError::NotJournaledSemantic)
        }
    }

    pub const fn opcode(self) -> u16 {
        self.opcode
    }

    pub const fn capture_role(self) -> ApplicationCaptureRole {
        self.capture_role
    }
}

const fn is_application_opcode(opcode: u16) -> bool {
    matches!(
        opcode,
        op::PREPARE_OPEN
            | op::COMMIT_OPEN
            | op::ABORT_OPEN
            | op::CLEANUP
            | op::CLOSE
            | op::READ
            | op::WRITE
            | op::FLUSH
            | op::QUERY_INFO
            | op::MUTATE
            | op::QUERY_DIR
            | op::QUERY_VOLUME
            | op::QUERY_SECURITY
            | op::QUERY_OP
            | op::ACK_RESULT
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlLane {
    OpenLifecycle { ring_index: u32 },
    PtRouteAck { ring_index: u32 },
    PtExternalSafeAck { ring_index: u32 },
    ExternalChangeAck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPhase {
    ReplayOpen,
    RecoveryCleanup,
    RecoveryClose,
    PtRouteAck,
    PtExternalSafeAck,
    ExternalChangeAck,
}

impl ControlPhase {
    pub const fn opcode(self) -> u16 {
        match self {
            Self::ReplayOpen => op::REPLAY_OPEN,
            Self::RecoveryCleanup => op::CLEANUP,
            Self::RecoveryClose => op::CLOSE,
            Self::PtRouteAck => op::PT_ROUTE_ACK,
            Self::PtExternalSafeAck => op::PT_EXTERNAL_SAFE_ACK,
            Self::ExternalChangeAck => op::DIR_CHANGE_ACK,
        }
    }
}

const fn control_lane_accepts_phase(lane: ControlLane, phase: ControlPhase) -> bool {
    matches!(
        (lane, phase),
        (
            ControlLane::OpenLifecycle { .. },
            ControlPhase::ReplayOpen | ControlPhase::RecoveryCleanup | ControlPhase::RecoveryClose
        ) | (ControlLane::PtRouteAck { .. }, ControlPhase::PtRouteAck)
            | (
                ControlLane::PtExternalSafeAck { .. },
                ControlPhase::PtExternalSafeAck
            )
            | (
                ControlLane::ExternalChangeAck,
                ControlPhase::ExternalChangeAck
            )
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableMode {
    Active,
    Fencing,
    Draining,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireState {
    BetweenPhases,
    PreparedNotVisible,
    Visible,
    Capturing,
    Captured,
    Quarantined,
    GenerationExhausted,
}

enum ApplicationSlotState<S: CompletionSink> {
    Pristine,
    Free {
        next_free: Option<u32>,
        generation: u64,
    },
    #[allow(dead_code)] // Task 5 terminal reclaim constructs this reserved state.
    Retired {
        generation: u64,
    },
    Terminalizing {
        birth_session_epoch: NonZeroU64,
        birth_generation: u64,
        terminal_wire_session_epoch: NonZeroU64,
        terminal_req_id: ReqId,
    },
    Live {
        pending: PendingToken<S>,
        phase: ApplicationPhase,
        birth_session_epoch: NonZeroU64,
        birth_generation: u64,
        req_id: ReqId,
        wire_state: WireState,
        cancel_requested: bool,
    },
}

pub struct ApplicationSlot<S: CompletionSink> {
    state: ApplicationSlotState<S>,
}

impl<S: CompletionSink> ApplicationSlot<S> {
    pub const fn pristine() -> Self {
        Self {
            state: ApplicationSlotState::Pristine,
        }
    }
}

enum ControlSlotState<C> {
    Pristine,
    Available {
        generation: u64,
    },
    #[allow(dead_code)] // Task 5 control release reclaim constructs this reserved state.
    Retired {
        generation: u64,
    },
    Terminalizing {
        lane: ControlLane,
        birth_session_epoch: NonZeroU64,
        birth_generation: u64,
        terminal_wire_session_epoch: NonZeroU64,
        terminal_req_id: ReqId,
        terminal_kind: ControlTerminalKind,
    },
    Occupied {
        continuation: C,
        phase: ControlPhase,
        lane: ControlLane,
        birth_session_epoch: NonZeroU64,
        birth_generation: u64,
        req_id: ReqId,
        wire_state: WireState,
    },
}

pub struct ControlSlot<C> {
    state: ControlSlotState<C>,
}

impl<C> ControlSlot<C> {
    pub const fn pristine() -> Self {
        Self {
            state: ControlSlotState::Pristine,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RequestTableId(NonZeroU64);

impl RequestTableId {
    #[cfg(test)]
    const fn get(self) -> u64 {
        self.0.get()
    }
}

static NEXT_TABLE_ID: AtomicU64 = AtomicU64::new(1);

fn allocate_table_id(next_id: &AtomicU64) -> Result<RequestTableId, TableInitError> {
    let mut current = next_id.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return Err(TableInitError::TableIdExhausted);
        }
        if current == 0 {
            match next_id.compare_exchange_weak(0, 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => current = 1,
                Err(observed) => current = observed,
            }
            continue;
        }
        let next = current.checked_add(1).unwrap_or(u64::MAX);
        match next_id.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                let Some(id) = NonZeroU64::new(current) else {
                    return Err(TableInitError::TableIdExhausted);
                };
                return Ok(RequestTableId(id));
            }
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationKey {
    table_id: RequestTableId,
    slot_index: u32,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationAdmission {
    key: ApplicationKey,
    req_id: ReqId,
}

impl ApplicationAdmission {
    pub const fn key(&self) -> ApplicationKey {
        self.key
    }

    pub const fn req_id(&self) -> ReqId {
        self.req_id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlKey {
    table_id: RequestTableId,
    slot_index: u32,
    lane: ControlLane,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlAdmission {
    key: ControlKey,
    req_id: ReqId,
}

impl ControlAdmission {
    pub const fn key(&self) -> ControlKey {
        self.key
    }

    pub const fn req_id(&self) -> ReqId {
        self.req_id
    }
}

#[must_use]
#[derive(Debug)]
pub enum CaptureToken {
    Application(ApplicationCapture),
    Control(ControlCapture),
}

#[must_use]
#[derive(Debug)]
pub struct ApplicationCapture {
    table_id: RequestTableId,
    slot_index: u32,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    wire_session_epoch: NonZeroU64,
    req_id: ReqId,
    expected_opcode: u16,
}

#[must_use]
#[derive(Debug)]
pub struct ControlCapture {
    table_id: RequestTableId,
    slot_index: u32,
    lane: ControlLane,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    wire_session_epoch: NonZeroU64,
    req_id: ReqId,
    expected_opcode: u16,
}

#[must_use]
#[derive(Debug)]
pub struct CapturedApplication {
    table_id: RequestTableId,
    slot_index: u32,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    wire_session_epoch: NonZeroU64,
    req_id: ReqId,
}

#[must_use]
#[derive(Debug)]
pub struct CapturedControl {
    table_id: RequestTableId,
    slot_index: u32,
    lane: ControlLane,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    wire_session_epoch: NonZeroU64,
    req_id: ReqId,
}

#[must_use]
pub struct TerminalApplication<S: CompletionSink> {
    table_id: NonZeroU64,
    slot_index: u32,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    terminal_wire_session_epoch: NonZeroU64,
    terminal_req_id: ReqId,
    pending: PendingToken<S>,
}

#[must_use]
pub struct CompletionReceipt {
    table_id: NonZeroU64,
    slot_index: u32,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    terminal_wire_session_epoch: NonZeroU64,
    terminal_req_id: ReqId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlTerminalKind {
    Captured,
    Unpublished,
    FenceNoCandidate,
    FenceGenerationExhausted,
    Drained,
}

#[must_use]
pub struct TerminalControl<C> {
    table_id: NonZeroU64,
    slot_index: u32,
    lane: ControlLane,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    terminal_wire_session_epoch: NonZeroU64,
    terminal_req_id: ReqId,
    terminal_kind: ControlTerminalKind,
    continuation: C,
}

#[must_use]
pub struct ControlRelease {
    table_id: NonZeroU64,
    slot_index: u32,
    lane: ControlLane,
    birth_session_epoch: NonZeroU64,
    birth_generation: u64,
    terminal_wire_session_epoch: NonZeroU64,
    terminal_req_id: ReqId,
    terminal_kind: ControlTerminalKind,
}

impl<S: CompletionSink> TerminalApplication<S> {
    /// Complete the application request.
    ///
    /// **Requires a [`crate::effect::CompletionClearance`]**, threaded to
    /// [`crate::typestate::CompletionOwner::complete`]. `06-locking.md` §6
    /// forbids `IoCompleteRequest` under a ring token, domain/FCB/CCB lock,
    /// notification gate or mount rundown; C1 modelled that rule and left this
    /// path unchecked, and C2 makes the check a precondition the compiler
    /// enforces rather than a discipline a caller remembers.
    pub fn complete(
        self,
        cleared: crate::effect::CompletionClearance<'_>,
        status: i32,
        information: usize,
    ) -> CompletionReceipt {
        let Self {
            table_id,
            slot_index,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            pending,
        } = self;
        pending.into_owner().complete(cleared, status, information);
        CompletionReceipt {
            table_id,
            slot_index,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
        }
    }
}

impl<C> TerminalControl<C> {
    pub const fn lane(&self) -> ControlLane {
        self.lane
    }

    pub const fn req_id(&self) -> ReqId {
        self.terminal_req_id
    }

    pub const fn terminal_kind(&self) -> ControlTerminalKind {
        self.terminal_kind
    }

    pub fn release(self) -> (C, ControlRelease) {
        let Self {
            table_id,
            slot_index,
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
            continuation,
        } = self;
        (
            continuation,
            ControlRelease {
                table_id,
                slot_index,
                lane,
                birth_session_epoch,
                birth_generation,
                terminal_wire_session_epoch,
                terminal_req_id,
                terminal_kind,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelTarget {
    req_id: ReqId,
    session_epoch: NonZeroU64,
}

impl CancelTarget {
    pub const fn req_id(&self) -> ReqId {
        self.req_id
    }

    pub const fn session_epoch(&self) -> NonZeroU64 {
        self.session_epoch
    }
}

impl CaptureToken {
    pub const fn req_id(&self) -> ReqId {
        match self {
            Self::Application(token) => token.req_id,
            Self::Control(token) => token.req_id,
        }
    }

    pub const fn expected_opcode(&self) -> u16 {
        match self {
            Self::Application(token) => token.expected_opcode,
            Self::Control(token) => token.expected_opcode,
        }
    }

    pub const fn validate_envelope(&self, kind: u16, opcode: u16) -> Result<(), EnvelopeError> {
        if kind != cq_kind::COMPLETION {
            return Err(EnvelopeError::WrongKind);
        }
        if opcode != self.expected_opcode() {
            return Err(EnvelopeError::WrongOpcode);
        }
        Ok(())
    }
}

#[must_use]
pub struct PreservedError<E, T> {
    error: E,
    value: T,
}

impl<E, T> PreservedError<E, T> {
    const fn new(error: E, value: T) -> Self {
        Self { error, value }
    }

    pub const fn error(&self) -> &E {
        &self.error
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub fn into_parts(self) -> (E, T) {
        (self.error, self.value)
    }
}

pub struct RequestTable<'a, S: CompletionSink, C> {
    table_id: RequestTableId,
    session_epoch: NonZeroU64,
    topology: RequestTopology,
    application: &'a mut [ApplicationSlot<S>],
    _system: &'a mut [ControlSlot<C>],
    _global: &'a mut ControlSlot<C>,
    free_head: Option<u32>,
    application_retired: u32,
    mode: TableMode,
    needs_quiesce: bool,
}

impl<'a, S: CompletionSink, C> RequestTable<'a, S, C> {
    pub fn try_new(
        session_epoch: NonZeroU64,
        topology: RequestTopology,
        application: &'a mut [ApplicationSlot<S>],
        system: &'a mut [ControlSlot<C>],
        global: &'a mut ControlSlot<C>,
    ) -> Result<Self, TableInitError> {
        let Ok(application_len) = u32::try_from(application.len()) else {
            return Err(TableInitError::ApplicationLength);
        };
        if application_len != topology.max_inflight {
            return Err(TableInitError::ApplicationLength);
        }
        let Some(system_len) = topology
            .ring_count
            .checked_mul(SYSTEM_REQUEST_SLOTS_PER_RING)
        else {
            return Err(TableInitError::SystemLength);
        };
        if usize::try_from(system_len) != Ok(system.len()) {
            return Err(TableInitError::SystemLength);
        }
        if application
            .iter()
            .any(|slot| !matches!(&slot.state, ApplicationSlotState::Pristine))
        {
            return Err(TableInitError::NonPristineApplication);
        }
        if system
            .iter()
            .any(|slot| !matches!(&slot.state, ControlSlotState::Pristine))
        {
            return Err(TableInitError::NonPristineSystem);
        }
        if !matches!(&global.state, ControlSlotState::Pristine) {
            return Err(TableInitError::NonPristineGlobal);
        }

        let table_id = allocate_table_id(&NEXT_TABLE_ID)?;
        for (index, slot) in (0..application_len).zip(application.iter_mut()) {
            let next_free = index
                .checked_add(1)
                .and_then(|next| (next < application_len).then_some(next));
            slot.state = ApplicationSlotState::Free {
                next_free,
                generation: 0,
            };
        }
        for slot in system.iter_mut() {
            slot.state = ControlSlotState::Available { generation: 0 };
        }
        global.state = ControlSlotState::Available { generation: 0 };

        Ok(Self {
            table_id,
            session_epoch,
            topology,
            application,
            _system: system,
            _global: global,
            free_head: Some(0),
            application_retired: 0,
            mode: TableMode::Active,
            needs_quiesce: false,
        })
    }

    pub fn admit_application(
        &mut self,
        phase: ApplicationPhase,
        owner: CompletionOwner<S>,
    ) -> Result<ApplicationAdmission, PreservedError<AdmissionError, CompletionOwner<S>>> {
        if self.mode != TableMode::Active {
            return Err(PreservedError::new(AdmissionError::TableNotActive, owner));
        }
        let Some(slot_index) = self.free_head else {
            if self.application_retired == self.topology.max_inflight {
                self.needs_quiesce = true;
                return Err(PreservedError::new(
                    AdmissionError::SessionGenerationExhausted,
                    owner,
                ));
            }
            return Err(PreservedError::new(AdmissionError::Full, owner));
        };
        if !matches!(
            classify_table_index(self.topology, slot_index),
            Ok(ReqIndexClass::Application { index }) if index == slot_index
        ) {
            return Err(PreservedError::new(AdmissionError::Full, owner));
        }
        let Ok(index) = usize::try_from(slot_index) else {
            return Err(PreservedError::new(AdmissionError::Full, owner));
        };
        let Some(slot) = self.application.get_mut(index) else {
            return Err(PreservedError::new(AdmissionError::Full, owner));
        };
        let ApplicationSlotState::Free {
            next_free,
            generation,
        } = &slot.state
        else {
            return Err(PreservedError::new(AdmissionError::Full, owner));
        };
        let next_free = *next_free;
        let Ok(generation) = next_req_generation_v21(*generation) else {
            self.needs_quiesce = true;
            return Err(PreservedError::new(
                AdmissionError::SessionGenerationExhausted,
                owner,
            ));
        };
        let Ok(req_id) = ReqId::try_new(generation, slot_index) else {
            self.needs_quiesce = true;
            return Err(PreservedError::new(
                AdmissionError::SessionGenerationExhausted,
                owner,
            ));
        };
        let key = ApplicationKey {
            table_id: self.table_id,
            slot_index,
            birth_session_epoch: self.session_epoch,
            birth_generation: generation,
        };

        let pending = owner.pending();
        slot.state = ApplicationSlotState::Live {
            pending,
            phase,
            birth_session_epoch: self.session_epoch,
            birth_generation: generation,
            req_id,
            wire_state: WireState::PreparedNotVisible,
            cancel_requested: false,
        };
        self.free_head = next_free;
        Ok(ApplicationAdmission { key, req_id })
    }

    pub fn admit_control(
        &mut self,
        lane: ControlLane,
        phase: ControlPhase,
        continuation: C,
    ) -> Result<ControlAdmission, PreservedError<ControlAdmissionError, C>> {
        if self.mode != TableMode::Active {
            return Err(PreservedError::new(
                ControlAdmissionError::TableNotActive,
                continuation,
            ));
        }
        if !control_lane_accepts_phase(lane, phase) {
            return Err(PreservedError::new(
                ControlAdmissionError::WrongLanePhase,
                continuation,
            ));
        }
        let storage = match control_storage(self.topology, lane) {
            Ok(storage) => storage,
            Err(error) => return Err(PreservedError::new(error, continuation)),
        };
        let (slot_index, slot) = match storage {
            ControlStorage::System {
                slot_index,
                backing_index,
            } => {
                let Some(slot) = self._system.get_mut(backing_index) else {
                    return Err(PreservedError::new(
                        ControlAdmissionError::RingOutOfRange,
                        continuation,
                    ));
                };
                (slot_index, slot)
            }
            ControlStorage::Global { slot_index } => (slot_index, &mut *self._global),
        };
        let generation = match &slot.state {
            ControlSlotState::Available { generation } => *generation,
            ControlSlotState::Retired { .. }
            | ControlSlotState::Occupied {
                wire_state: WireState::GenerationExhausted,
                ..
            } => {
                self.needs_quiesce = true;
                return Err(PreservedError::new(
                    ControlAdmissionError::SessionGenerationExhausted,
                    continuation,
                ));
            }
            ControlSlotState::Occupied { .. } | ControlSlotState::Terminalizing { .. } => {
                return Err(PreservedError::new(
                    ControlAdmissionError::Busy,
                    continuation,
                ));
            }
            ControlSlotState::Pristine => {
                return Err(PreservedError::new(
                    ControlAdmissionError::TableNotActive,
                    continuation,
                ));
            }
        };
        let Ok(generation) = next_req_generation_v21(generation) else {
            self.needs_quiesce = true;
            return Err(PreservedError::new(
                ControlAdmissionError::SessionGenerationExhausted,
                continuation,
            ));
        };
        let Ok(req_id) = ReqId::try_new(generation, slot_index) else {
            self.needs_quiesce = true;
            return Err(PreservedError::new(
                ControlAdmissionError::SessionGenerationExhausted,
                continuation,
            ));
        };
        let key = ControlKey {
            table_id: self.table_id,
            slot_index,
            lane,
            birth_session_epoch: self.session_epoch,
            birth_generation: generation,
        };
        slot.state = ControlSlotState::Occupied {
            continuation,
            phase,
            lane,
            birth_session_epoch: self.session_epoch,
            birth_generation: generation,
            req_id,
            wire_state: WireState::PreparedNotVisible,
        };
        Ok(ControlAdmission { key, req_id })
    }

    pub fn mark_application_visible(
        &mut self,
        key: ApplicationKey,
    ) -> Result<ReqId, ApplicationError> {
        if self.mode != TableMode::Active {
            return Err(ApplicationError::Phase(PhaseError::TableNotActive));
        }
        let index = self.validate_application_key(key)?;
        let Some(slot) = self.application.get_mut(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            req_id, wire_state, ..
        } = &mut slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::PreparedNotVisible {
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        }
        *wire_state = WireState::Visible;
        Ok(*req_id)
    }

    pub fn mark_control_visible(&mut self, key: ControlKey) -> Result<ReqId, ControlError> {
        if self.mode != TableMode::Active {
            return Err(ControlError::Phase(PhaseError::TableNotActive));
        }
        let storage = self.validate_control_key(key)?;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(ControlError::Key(KeyError::SlotOutOfRange));
        };
        let ControlSlotState::Occupied {
            req_id, wire_state, ..
        } = &mut slot.state
        else {
            return Err(ControlError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::PreparedNotVisible {
            return Err(ControlError::Phase(PhaseError::WrongState));
        }
        *wire_state = WireState::Visible;
        Ok(*req_id)
    }

    pub fn begin_application_phase(
        &mut self,
        key: ApplicationKey,
        phase: ApplicationPhase,
    ) -> Result<ReqId, ApplicationError> {
        if self.mode != TableMode::Active {
            return Err(ApplicationError::Phase(PhaseError::TableNotActive));
        }
        let index = self.validate_application_key(key)?;
        let Some(slot) = self.application.get_mut(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            phase: current_phase,
            req_id,
            wire_state,
            ..
        } = &mut slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::BetweenPhases {
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        }
        let Ok(generation) = next_req_generation_v21(req_id.generation()) else {
            *wire_state = WireState::GenerationExhausted;
            self.needs_quiesce = true;
            return Err(ApplicationError::Phase(PhaseError::GenerationExhausted));
        };
        let Ok(next_req_id) = ReqId::try_new(generation, key.slot_index) else {
            *wire_state = WireState::GenerationExhausted;
            self.needs_quiesce = true;
            return Err(ApplicationError::Phase(PhaseError::GenerationExhausted));
        };
        *current_phase = phase;
        *req_id = next_req_id;
        *wire_state = WireState::PreparedNotVisible;
        Ok(next_req_id)
    }

    pub fn begin_control_phase(
        &mut self,
        key: ControlKey,
        phase: ControlPhase,
    ) -> Result<ReqId, ControlError> {
        if self.mode != TableMode::Active {
            return Err(ControlError::Phase(PhaseError::TableNotActive));
        }
        if !control_lane_accepts_phase(key.lane, phase) {
            return Err(ControlError::Phase(PhaseError::WrongPhaseClass));
        }
        let storage = self.validate_control_key(key)?;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(ControlError::Key(KeyError::SlotOutOfRange));
        };
        let ControlSlotState::Occupied {
            phase: current_phase,
            req_id,
            wire_state,
            ..
        } = &mut slot.state
        else {
            return Err(ControlError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::BetweenPhases {
            return Err(ControlError::Phase(PhaseError::WrongState));
        }
        let Ok(generation) = next_req_generation_v21(req_id.generation()) else {
            *wire_state = WireState::GenerationExhausted;
            self.needs_quiesce = true;
            return Err(ControlError::Phase(PhaseError::GenerationExhausted));
        };
        let Ok(next_req_id) = ReqId::try_new(generation, key.slot_index) else {
            *wire_state = WireState::GenerationExhausted;
            self.needs_quiesce = true;
            return Err(ControlError::Phase(PhaseError::GenerationExhausted));
        };
        *current_phase = phase;
        *req_id = next_req_id;
        *wire_state = WireState::PreparedNotVisible;
        Ok(next_req_id)
    }

    pub fn begin_capture(
        &mut self,
        observed_epoch: u64,
        kind: u16,
        req_id: ReqId,
    ) -> Result<CaptureToken, CaptureError> {
        if self.mode == TableMode::Draining {
            return Err(CaptureError::TableNotActive);
        }
        if observed_epoch != self.session_epoch.get() {
            return Err(CaptureError::WrongSession);
        }
        if req_id.raw() == 0 {
            return Err(CaptureError::ZeroRequestId);
        }
        if req_id.generation() == 0 {
            return Err(CaptureError::ZeroGeneration);
        }
        let class = classify_table_index(self.topology, req_id.slot_index())
            .map_err(|_| CaptureError::UnassignedIndex)?;
        match class {
            ReqIndexClass::Application { index } => {
                let Ok(backing_index) = usize::try_from(index) else {
                    return Err(CaptureError::Vacant);
                };
                let Some(slot) = self.application.get_mut(backing_index) else {
                    return Err(CaptureError::Vacant);
                };
                match &mut slot.state {
                    ApplicationSlotState::Pristine | ApplicationSlotState::Free { .. } => {
                        Err(CaptureError::Vacant)
                    }
                    ApplicationSlotState::Retired { .. } => Err(CaptureError::Retired),
                    ApplicationSlotState::Terminalizing { .. } => Err(CaptureError::NotVisible),
                    ApplicationSlotState::Live {
                        phase,
                        birth_session_epoch,
                        birth_generation,
                        req_id: current_req_id,
                        wire_state,
                        ..
                    } => {
                        if *current_req_id != req_id {
                            return Err(CaptureError::StaleCurrentGeneration);
                        }
                        if *wire_state != WireState::Visible {
                            return Err(capture_state_error(*wire_state));
                        }
                        if kind != cq_kind::COMPLETION
                            && phase.capture_role() != ApplicationCaptureRole::JournaledSemantic
                        {
                            return Err(CaptureError::WrongKindCaptureRole);
                        }
                        let token = ApplicationCapture {
                            table_id: self.table_id,
                            slot_index: index,
                            birth_session_epoch: *birth_session_epoch,
                            birth_generation: *birth_generation,
                            wire_session_epoch: self.session_epoch,
                            req_id,
                            expected_opcode: phase.opcode(),
                        };
                        *wire_state = WireState::Capturing;
                        Ok(CaptureToken::Application(token))
                    }
                }
            }
            class => {
                let Some(lane) = control_lane_from_class(class) else {
                    return Err(CaptureError::UnassignedIndex);
                };
                let table_id = self.table_id;
                let session_epoch = self.session_epoch;
                let Some(slot) = self.control_slot_by_req_index_mut(req_id.slot_index()) else {
                    return Err(CaptureError::Vacant);
                };
                match &mut slot.state {
                    ControlSlotState::Pristine | ControlSlotState::Available { .. } => {
                        Err(CaptureError::Vacant)
                    }
                    ControlSlotState::Retired { .. } => Err(CaptureError::Retired),
                    ControlSlotState::Terminalizing { .. } => Err(CaptureError::NotVisible),
                    ControlSlotState::Occupied {
                        phase,
                        lane: current_lane,
                        birth_session_epoch,
                        birth_generation,
                        req_id: current_req_id,
                        wire_state,
                        ..
                    } => {
                        if *current_lane != lane || *current_req_id != req_id {
                            return Err(CaptureError::StaleCurrentGeneration);
                        }
                        if *wire_state != WireState::Visible {
                            return Err(capture_state_error(*wire_state));
                        }
                        if kind != cq_kind::COMPLETION {
                            return Err(CaptureError::WrongKindCaptureRole);
                        }
                        let token = ControlCapture {
                            table_id,
                            slot_index: req_id.slot_index(),
                            lane,
                            birth_session_epoch: *birth_session_epoch,
                            birth_generation: *birth_generation,
                            wire_session_epoch: session_epoch,
                            req_id,
                            expected_opcode: phase.opcode(),
                        };
                        *wire_state = WireState::Capturing;
                        Ok(CaptureToken::Control(token))
                    }
                }
            }
        }
    }

    pub fn install_application_candidate(
        &mut self,
        token: ApplicationCapture,
    ) -> Result<CapturedApplication, PreservedError<CaptureFinishError, ApplicationCapture>> {
        if token.table_id != self.table_id {
            return Err(PreservedError::new(CaptureFinishError::ForeignTable, token));
        }
        if token.req_id.slot_index() != token.slot_index
            || !matches!(
                classify_table_index(self.topology, token.slot_index),
                Ok(ReqIndexClass::Application { index }) if index == token.slot_index
            )
        {
            return Err(PreservedError::new(CaptureFinishError::WrongClass, token));
        }
        let Ok(index) = usize::try_from(token.slot_index) else {
            return Err(PreservedError::new(
                CaptureFinishError::SlotOutOfRange,
                token,
            ));
        };
        let Some(slot) = self.application.get_mut(index) else {
            return Err(PreservedError::new(
                CaptureFinishError::SlotOutOfRange,
                token,
            ));
        };
        let ApplicationSlotState::Live {
            phase,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &mut slot.state
        else {
            return Err(PreservedError::new(CaptureFinishError::StaleBirth, token));
        };
        if *birth_session_epoch != token.birth_session_epoch
            || *birth_generation != token.birth_generation
        {
            return Err(PreservedError::new(CaptureFinishError::StaleBirth, token));
        }
        if self.session_epoch != token.wire_session_epoch
            || *req_id != token.req_id
            || phase.opcode() != token.expected_opcode
        {
            return Err(PreservedError::new(
                CaptureFinishError::StaleWireIdentity,
                token,
            ));
        }
        if *wire_state != WireState::Capturing {
            return Err(PreservedError::new(CaptureFinishError::WrongState, token));
        }
        *wire_state = WireState::Captured;
        Ok(CapturedApplication {
            table_id: token.table_id,
            slot_index: token.slot_index,
            birth_session_epoch: token.birth_session_epoch,
            birth_generation: token.birth_generation,
            wire_session_epoch: token.wire_session_epoch,
            req_id: token.req_id,
        })
    }

    pub fn install_control_candidate(
        &mut self,
        token: ControlCapture,
    ) -> Result<CapturedControl, PreservedError<CaptureFinishError, ControlCapture>> {
        if token.table_id != self.table_id {
            return Err(PreservedError::new(CaptureFinishError::ForeignTable, token));
        }
        let class = match classify_table_index(self.topology, token.slot_index) {
            Ok(class) => class,
            Err(_) => {
                return Err(PreservedError::new(CaptureFinishError::WrongClass, token));
            }
        };
        if token.req_id.slot_index() != token.slot_index
            || control_lane_from_class(class) != Some(token.lane)
        {
            return Err(PreservedError::new(CaptureFinishError::WrongClass, token));
        }
        let session_epoch = self.session_epoch;
        let Some(slot) = self.control_slot_by_req_index_mut(token.slot_index) else {
            return Err(PreservedError::new(
                CaptureFinishError::SlotOutOfRange,
                token,
            ));
        };
        let ControlSlotState::Occupied {
            phase,
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &mut slot.state
        else {
            return Err(PreservedError::new(CaptureFinishError::StaleBirth, token));
        };
        if *lane != token.lane
            || *birth_session_epoch != token.birth_session_epoch
            || *birth_generation != token.birth_generation
        {
            return Err(PreservedError::new(CaptureFinishError::StaleBirth, token));
        }
        if session_epoch != token.wire_session_epoch
            || *req_id != token.req_id
            || phase.opcode() != token.expected_opcode
        {
            return Err(PreservedError::new(
                CaptureFinishError::StaleWireIdentity,
                token,
            ));
        }
        if *wire_state != WireState::Capturing {
            return Err(PreservedError::new(CaptureFinishError::WrongState, token));
        }
        *wire_state = WireState::Captured;
        Ok(CapturedControl {
            table_id: token.table_id,
            slot_index: token.slot_index,
            lane: token.lane,
            birth_session_epoch: token.birth_session_epoch,
            birth_generation: token.birth_generation,
            wire_session_epoch: token.wire_session_epoch,
            req_id: token.req_id,
        })
    }

    pub fn retain_application(
        &mut self,
        captured: CapturedApplication,
    ) -> Result<ApplicationKey, PreservedError<ApplicationError, CapturedApplication>> {
        if self.mode == TableMode::Draining {
            return Err(PreservedError::new(
                ApplicationError::Phase(PhaseError::TableNotActive),
                captured,
            ));
        }
        self.finish_application_disposition(captured, WireState::BetweenPhases)
    }

    pub fn retain_control(
        &mut self,
        captured: CapturedControl,
    ) -> Result<ControlKey, PreservedError<ControlError, CapturedControl>> {
        if self.mode == TableMode::Draining {
            return Err(PreservedError::new(
                ControlError::Phase(PhaseError::TableNotActive),
                captured,
            ));
        }
        self.finish_control_disposition(captured, WireState::BetweenPhases)
    }

    pub fn quarantine_application(
        &mut self,
        captured: CapturedApplication,
    ) -> Result<ApplicationKey, PreservedError<ApplicationError, CapturedApplication>> {
        self.finish_application_disposition(captured, WireState::Quarantined)
    }

    pub fn quarantine_control(
        &mut self,
        captured: CapturedControl,
    ) -> Result<ControlKey, PreservedError<ControlError, CapturedControl>> {
        self.finish_control_disposition(captured, WireState::Quarantined)
    }

    pub fn terminalize_application(
        &mut self,
        captured: CapturedApplication,
    ) -> Result<TerminalApplication<S>, PreservedError<ApplicationError, CapturedApplication>> {
        if self.mode == TableMode::Draining {
            return Err(PreservedError::new(
                ApplicationError::Phase(PhaseError::TableNotActive),
                captured,
            ));
        }
        if captured.table_id != self.table_id {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::ForeignTable),
                captured,
            ));
        }
        if captured.req_id.slot_index() != captured.slot_index
            || !matches!(
                classify_table_index(self.topology, captured.slot_index),
                Ok(ReqIndexClass::Application { index }) if index == captured.slot_index
            )
        {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::WrongClass),
                captured,
            ));
        }
        let Ok(index) = usize::try_from(captured.slot_index) else {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::SlotOutOfRange),
                captured,
            ));
        };
        let Some(slot) = self.application.get_mut(index) else {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::SlotOutOfRange),
                captured,
            ));
        };
        let ApplicationSlotState::Live {
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &slot.state
        else {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::Vacant),
                captured,
            ));
        };
        if *birth_session_epoch != captured.birth_session_epoch
            || *birth_generation != captured.birth_generation
        {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::StaleBirth),
                captured,
            ));
        }
        if self.session_epoch != captured.wire_session_epoch
            || *req_id != captured.req_id
            || *wire_state != WireState::Captured
        {
            return Err(PreservedError::new(
                ApplicationError::Phase(PhaseError::WrongState),
                captured,
            ));
        }

        let terminal_state = ApplicationSlotState::Terminalizing {
            birth_session_epoch: captured.birth_session_epoch,
            birth_generation: captured.birth_generation,
            terminal_wire_session_epoch: captured.wire_session_epoch,
            terminal_req_id: captured.req_id,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ApplicationSlotState::Live { pending, .. } = previous else {
            slot.state = previous;
            return Err(PreservedError::new(
                ApplicationError::Phase(PhaseError::WrongState),
                captured,
            ));
        };
        Ok(TerminalApplication {
            table_id: captured.table_id.0,
            slot_index: captured.slot_index,
            birth_session_epoch: captured.birth_session_epoch,
            birth_generation: captured.birth_generation,
            terminal_wire_session_epoch: captured.wire_session_epoch,
            terminal_req_id: captured.req_id,
            pending,
        })
    }

    pub fn withdraw_unpublished_application(
        &mut self,
        key: ApplicationKey,
    ) -> Result<TerminalApplication<S>, ApplicationError> {
        let index = self.validate_application_key(key)?;
        let terminal_wire_session_epoch = self.session_epoch;
        let Some(slot) = self.application.get_mut(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::PreparedNotVisible {
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        }
        let birth_session_epoch = *birth_session_epoch;
        let birth_generation = *birth_generation;
        let terminal_req_id = *req_id;
        let terminal_state = ApplicationSlotState::Terminalizing {
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ApplicationSlotState::Live { pending, .. } = previous else {
            slot.state = previous;
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        };
        Ok(TerminalApplication {
            table_id: self.table_id.0,
            slot_index: key.slot_index,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            pending,
        })
    }

    pub fn terminalize_control(
        &mut self,
        captured: CapturedControl,
    ) -> Result<TerminalControl<C>, PreservedError<ControlError, CapturedControl>> {
        if self.mode == TableMode::Draining {
            return Err(PreservedError::new(
                ControlError::Phase(PhaseError::TableNotActive),
                captured,
            ));
        }
        if captured.table_id != self.table_id {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::ForeignTable),
                captured,
            ));
        }
        let storage = match control_storage(self.topology, captured.lane) {
            Ok(storage)
                if storage.slot_index() == captured.slot_index
                    && captured.req_id.slot_index() == captured.slot_index =>
            {
                storage
            }
            _ => {
                return Err(PreservedError::new(
                    ControlError::Key(KeyError::WrongClass),
                    captured,
                ));
            }
        };
        let session_epoch = self.session_epoch;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::SlotOutOfRange),
                captured,
            ));
        };
        let ControlSlotState::Occupied {
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &slot.state
        else {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::Vacant),
                captured,
            ));
        };
        if *lane != captured.lane
            || *birth_session_epoch != captured.birth_session_epoch
            || *birth_generation != captured.birth_generation
        {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::StaleBirth),
                captured,
            ));
        }
        if session_epoch != captured.wire_session_epoch
            || *req_id != captured.req_id
            || *wire_state != WireState::Captured
        {
            return Err(PreservedError::new(
                ControlError::Phase(PhaseError::WrongState),
                captured,
            ));
        }

        let terminal_kind = ControlTerminalKind::Captured;
        let terminal_state = ControlSlotState::Terminalizing {
            lane: captured.lane,
            birth_session_epoch: captured.birth_session_epoch,
            birth_generation: captured.birth_generation,
            terminal_wire_session_epoch: captured.wire_session_epoch,
            terminal_req_id: captured.req_id,
            terminal_kind,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ControlSlotState::Occupied { continuation, .. } = previous else {
            slot.state = previous;
            return Err(PreservedError::new(
                ControlError::Phase(PhaseError::WrongState),
                captured,
            ));
        };
        Ok(TerminalControl {
            table_id: captured.table_id.0,
            slot_index: captured.slot_index,
            lane: captured.lane,
            birth_session_epoch: captured.birth_session_epoch,
            birth_generation: captured.birth_generation,
            terminal_wire_session_epoch: captured.wire_session_epoch,
            terminal_req_id: captured.req_id,
            terminal_kind,
            continuation,
        })
    }

    pub fn withdraw_unpublished_control(
        &mut self,
        key: ControlKey,
    ) -> Result<TerminalControl<C>, ControlError> {
        let storage = self.validate_control_key(key)?;
        let terminal_wire_session_epoch = self.session_epoch;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(ControlError::Key(KeyError::SlotOutOfRange));
        };
        let ControlSlotState::Occupied {
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &slot.state
        else {
            return Err(ControlError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::PreparedNotVisible {
            return Err(ControlError::Phase(PhaseError::WrongState));
        }
        let lane = *lane;
        let birth_session_epoch = *birth_session_epoch;
        let birth_generation = *birth_generation;
        let terminal_req_id = *req_id;
        let terminal_kind = ControlTerminalKind::Unpublished;
        let terminal_state = ControlSlotState::Terminalizing {
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ControlSlotState::Occupied { continuation, .. } = previous else {
            slot.state = previous;
            return Err(ControlError::Phase(PhaseError::WrongState));
        };
        Ok(TerminalControl {
            table_id: self.table_id.0,
            slot_index: key.slot_index,
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
            continuation,
        })
    }

    pub fn reclaim_completed(
        &mut self,
        receipt: CompletionReceipt,
    ) -> Result<(), PreservedError<ReclaimError, CompletionReceipt>> {
        if receipt.table_id != self.table_id.0 {
            return Err(PreservedError::new(ReclaimError::ForeignTable, receipt));
        }
        if receipt.terminal_req_id.slot_index() != receipt.slot_index
            || !matches!(
                classify_table_index(self.topology, receipt.slot_index),
                Ok(ReqIndexClass::Application { index }) if index == receipt.slot_index
            )
        {
            return Err(PreservedError::new(ReclaimError::WrongClass, receipt));
        }
        let Ok(index) = usize::try_from(receipt.slot_index) else {
            return Err(PreservedError::new(ReclaimError::SlotOutOfRange, receipt));
        };
        let Some(slot) = self.application.get_mut(index) else {
            return Err(PreservedError::new(ReclaimError::SlotOutOfRange, receipt));
        };
        let ApplicationSlotState::Terminalizing {
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
        } = &slot.state
        else {
            return Err(PreservedError::new(ReclaimError::NotTerminalizing, receipt));
        };
        if *birth_session_epoch != receipt.birth_session_epoch
            || *birth_generation != receipt.birth_generation
        {
            return Err(PreservedError::new(ReclaimError::StaleBirth, receipt));
        }
        if *terminal_wire_session_epoch != receipt.terminal_wire_session_epoch
            || *terminal_req_id != receipt.terminal_req_id
        {
            return Err(PreservedError::new(
                ReclaimError::StaleTerminalIdentity,
                receipt,
            ));
        }

        let terminal_generation = receipt.terminal_req_id.generation();
        if receipt.terminal_wire_session_epoch == self.session_epoch
            && terminal_generation == REQ_GENERATION_MAX
        {
            slot.state = ApplicationSlotState::Retired {
                generation: terminal_generation,
            };
            self.application_retired = self.application_retired.saturating_add(1);
            self.needs_quiesce = true;
        } else {
            let generation = if receipt.terminal_wire_session_epoch == self.session_epoch {
                terminal_generation
            } else {
                0
            };
            slot.state = ApplicationSlotState::Free {
                next_free: self.free_head,
                generation,
            };
            self.free_head = Some(receipt.slot_index);
        }
        Ok(())
    }

    pub fn reclaim_control(
        &mut self,
        receipt: ControlRelease,
    ) -> Result<(), PreservedError<ReclaimError, ControlRelease>> {
        if receipt.table_id != self.table_id.0 {
            return Err(PreservedError::new(ReclaimError::ForeignTable, receipt));
        }
        let storage = match control_storage(self.topology, receipt.lane) {
            Ok(storage)
                if storage.slot_index() == receipt.slot_index
                    && receipt.terminal_req_id.slot_index() == receipt.slot_index =>
            {
                storage
            }
            _ => return Err(PreservedError::new(ReclaimError::WrongClass, receipt)),
        };
        let current_session_epoch = self.session_epoch;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(PreservedError::new(ReclaimError::SlotOutOfRange, receipt));
        };
        let ControlSlotState::Terminalizing {
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
        } = &slot.state
        else {
            return Err(PreservedError::new(ReclaimError::NotTerminalizing, receipt));
        };
        if *lane != receipt.lane
            || *birth_session_epoch != receipt.birth_session_epoch
            || *birth_generation != receipt.birth_generation
        {
            return Err(PreservedError::new(ReclaimError::StaleBirth, receipt));
        }
        if *terminal_wire_session_epoch != receipt.terminal_wire_session_epoch
            || *terminal_req_id != receipt.terminal_req_id
            || *terminal_kind != receipt.terminal_kind
        {
            return Err(PreservedError::new(
                ReclaimError::StaleTerminalIdentity,
                receipt,
            ));
        }

        let terminal_generation = receipt.terminal_req_id.generation();
        if receipt.terminal_wire_session_epoch == current_session_epoch
            && terminal_generation == REQ_GENERATION_MAX
        {
            let generation = terminal_generation;
            slot.state = ControlSlotState::Retired { generation };
            self.needs_quiesce = true;
        } else {
            let generation = if receipt.terminal_wire_session_epoch == current_session_epoch {
                terminal_generation
            } else {
                0
            };
            slot.state = ControlSlotState::Available { generation };
        }
        Ok(())
    }

    pub fn record_cancel(&mut self, key: ApplicationKey) -> Result<(), ApplicationError> {
        let index = self.validate_application_key(key)?;
        let Some(slot) = self.application.get_mut(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            cancel_requested, ..
        } = &mut slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        *cancel_requested = true;
        Ok(())
    }

    pub fn pcancel_target(
        &self,
        key: ApplicationKey,
    ) -> Result<Option<CancelTarget>, ApplicationError> {
        let index = self.validate_application_key(key)?;
        let Some(slot) = self.application.get(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            phase,
            req_id,
            wire_state,
            cancel_requested,
            ..
        } = &slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        if !*cancel_requested
            || *wire_state != WireState::Visible
            || !phase_is_pcancel_eligible(*phase)
        {
            return Ok(None);
        }
        Ok(Some(CancelTarget {
            req_id: *req_id,
            session_epoch: self.session_epoch,
        }))
    }

    pub const fn mode(&self) -> TableMode {
        self.mode
    }

    pub const fn needs_quiesce(&self) -> bool {
        self.needs_quiesce
    }

    pub fn begin_fence(&mut self) -> Result<(), SessionTransitionError> {
        if self.mode != TableMode::Active {
            return Err(SessionTransitionError::WrongMode);
        }
        self.mode = TableMode::Fencing;
        Ok(())
    }

    pub fn retain_after_fence(&mut self, key: ApplicationKey) -> Result<(), ApplicationError> {
        if self.mode != TableMode::Fencing {
            return Err(ApplicationError::Phase(PhaseError::TableNotActive));
        }
        let index = self.validate_application_key(key)?;
        let Some(slot) = self.application.get_mut(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live { wire_state, .. } = &mut slot.state else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        if *wire_state != WireState::Visible {
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        }
        *wire_state = WireState::BetweenPhases;
        Ok(())
    }

    pub fn terminalize_application_after_fence(
        &mut self,
        key: ApplicationKey,
    ) -> Result<TerminalApplication<S>, ApplicationError> {
        if self.mode != TableMode::Fencing {
            return Err(ApplicationError::Phase(PhaseError::TableNotActive));
        }
        let index = self.validate_application_key(key)?;
        let Some(slot) = self.application.get_mut(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            cancel_requested,
            ..
        } = &slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        if !*cancel_requested
            || !matches!(
                *wire_state,
                WireState::Visible | WireState::BetweenPhases | WireState::GenerationExhausted
            )
        {
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        }
        let birth_session_epoch = *birth_session_epoch;
        let birth_generation = *birth_generation;
        let terminal_req_id = *req_id;
        let terminal_wire_session_epoch = self.session_epoch;
        let terminal_state = ApplicationSlotState::Terminalizing {
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ApplicationSlotState::Live { pending, .. } = previous else {
            slot.state = previous;
            return Err(ApplicationError::Phase(PhaseError::WrongState));
        };
        Ok(TerminalApplication {
            table_id: self.table_id.0,
            slot_index: key.slot_index,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            pending,
        })
    }

    pub fn terminalize_control_after_fence(
        &mut self,
        key: ControlKey,
    ) -> Result<TerminalControl<C>, ControlError> {
        if self.mode != TableMode::Fencing {
            return Err(ControlError::Phase(PhaseError::TableNotActive));
        }
        let storage = self.validate_control_key(key)?;
        let terminal_wire_session_epoch = self.session_epoch;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(ControlError::Key(KeyError::SlotOutOfRange));
        };
        let ControlSlotState::Occupied {
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &slot.state
        else {
            return Err(ControlError::Key(KeyError::Vacant));
        };
        let terminal_kind = match *wire_state {
            WireState::Visible | WireState::BetweenPhases => ControlTerminalKind::FenceNoCandidate,
            WireState::GenerationExhausted => ControlTerminalKind::FenceGenerationExhausted,
            _ => return Err(ControlError::Phase(PhaseError::WrongState)),
        };
        let lane = *lane;
        let birth_session_epoch = *birth_session_epoch;
        let birth_generation = *birth_generation;
        let terminal_req_id = *req_id;
        let terminal_state = ControlSlotState::Terminalizing {
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ControlSlotState::Occupied { continuation, .. } = previous else {
            slot.state = previous;
            return Err(ControlError::Phase(PhaseError::WrongState));
        };
        Ok(TerminalControl {
            table_id: self.table_id.0,
            slot_index: key.slot_index,
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
            continuation,
        })
    }

    pub fn rebind_session(
        &mut self,
        next_epoch: NonZeroU64,
        topology: RequestTopology,
    ) -> Result<(), SessionTransitionError> {
        if self.mode != TableMode::Fencing {
            return Err(SessionTransitionError::WrongMode);
        }
        let Some(expected_epoch) = self.session_epoch.get().checked_add(1) else {
            return Err(SessionTransitionError::EpochExhausted);
        };
        if next_epoch.get() != expected_epoch {
            return Err(SessionTransitionError::WrongEpoch);
        }
        if topology != self.topology {
            return Err(SessionTransitionError::TopologyChanged);
        }

        for slot in self.application.iter() {
            if let ApplicationSlotState::Live { wire_state, .. } = &slot.state {
                match wire_state {
                    WireState::Capturing => {
                        return Err(SessionTransitionError::UnresolvedCapture);
                    }
                    WireState::PreparedNotVisible | WireState::Visible | WireState::Captured => {
                        return Err(SessionTransitionError::UnresolvedApplicationPhase);
                    }
                    WireState::BetweenPhases
                    | WireState::Quarantined
                    | WireState::GenerationExhausted => {}
                }
            }
        }
        for slot in self._system.iter().chain(core::iter::once(&*self._global)) {
            if let ControlSlotState::Occupied { wire_state, .. } = &slot.state {
                if *wire_state == WireState::Capturing {
                    return Err(SessionTransitionError::UnresolvedCapture);
                }
                return Err(SessionTransitionError::LiveControlLane);
            }
        }

        self.free_head = None;
        self.application_retired = 0;
        let mut backing_index = self.application.len();
        while let Some(index) = backing_index.checked_sub(1) {
            backing_index = index;
            let Some(slot) = self.application.get_mut(index) else {
                continue;
            };
            let Ok(slot_index) = u32::try_from(index) else {
                continue;
            };
            match &mut slot.state {
                ApplicationSlotState::Free { .. } | ApplicationSlotState::Retired { .. } => {
                    slot.state = ApplicationSlotState::Free {
                        next_free: self.free_head,
                        generation: 0,
                    };
                    self.free_head = Some(slot_index);
                }
                ApplicationSlotState::Live {
                    req_id, wire_state, ..
                } => {
                    *req_id = ReqId::from_raw(u64::from(slot_index));
                    if *wire_state == WireState::GenerationExhausted {
                        *wire_state = WireState::BetweenPhases;
                    }
                }
                ApplicationSlotState::Terminalizing { .. } | ApplicationSlotState::Pristine => {}
            }
            if index == 0 {
                break;
            }
        }
        for slot in self._system.iter_mut() {
            if matches!(
                &slot.state,
                ControlSlotState::Available { .. } | ControlSlotState::Retired { .. }
            ) {
                slot.state = ControlSlotState::Available { generation: 0 };
            }
        }
        if matches!(
            &self._global.state,
            ControlSlotState::Available { .. } | ControlSlotState::Retired { .. }
        ) {
            self._global.state = ControlSlotState::Available { generation: 0 };
        }
        self.session_epoch = next_epoch;
        self.needs_quiesce = false;
        self.mode = TableMode::Active;
        Ok(())
    }

    pub fn begin_drain(&mut self) {
        self.mode = TableMode::Draining;
    }

    pub fn drain_next_application(&mut self) -> Result<Option<TerminalApplication<S>>, DrainError> {
        if self.mode != TableMode::Draining {
            return Err(DrainError::NotDraining);
        }
        let mut unresolved_capture = false;
        for (index, slot) in self.application.iter_mut().enumerate() {
            let ApplicationSlotState::Live {
                birth_session_epoch,
                birth_generation,
                req_id,
                wire_state,
                ..
            } = &slot.state
            else {
                continue;
            };
            if matches!(*wire_state, WireState::Capturing | WireState::Captured) {
                unresolved_capture = true;
                continue;
            }
            let Ok(slot_index) = u32::try_from(index) else {
                continue;
            };
            let birth_session_epoch = *birth_session_epoch;
            let birth_generation = *birth_generation;
            let terminal_req_id = *req_id;
            let terminal_wire_session_epoch = self.session_epoch;
            let terminal_state = ApplicationSlotState::Terminalizing {
                birth_session_epoch,
                birth_generation,
                terminal_wire_session_epoch,
                terminal_req_id,
            };
            let previous = core::mem::replace(&mut slot.state, terminal_state);
            let ApplicationSlotState::Live { pending, .. } = previous else {
                slot.state = previous;
                continue;
            };
            return Ok(Some(TerminalApplication {
                table_id: self.table_id.0,
                slot_index,
                birth_session_epoch,
                birth_generation,
                terminal_wire_session_epoch,
                terminal_req_id,
                pending,
            }));
        }
        if unresolved_capture {
            Err(DrainError::UnresolvedCapture)
        } else {
            Ok(None)
        }
    }

    pub fn drain_next_control(&mut self) -> Result<Option<TerminalControl<C>>, DrainError> {
        if self.mode != TableMode::Draining {
            return Err(DrainError::NotDraining);
        }
        let table_id = self.table_id;
        let session_epoch = self.session_epoch;
        let mut unresolved_capture = false;
        for (index, slot) in self._system.iter_mut().enumerate() {
            let Ok(offset) = u32::try_from(index) else {
                continue;
            };
            let Some(slot_index) = SYSTEM_REQID_BASE.checked_add(offset) else {
                continue;
            };
            if let Some(terminal) = Self::drain_control_slot(
                table_id,
                session_epoch,
                slot_index,
                slot,
                &mut unresolved_capture,
            ) {
                return Ok(Some(terminal));
            }
        }
        if let Some(terminal) = Self::drain_control_slot(
            table_id,
            session_epoch,
            GLOBAL_EXTERNAL_CHANGE_ACK_REQID,
            &mut *self._global,
            &mut unresolved_capture,
        ) {
            return Ok(Some(terminal));
        }
        if unresolved_capture {
            Err(DrainError::UnresolvedCapture)
        } else {
            Ok(None)
        }
    }

    fn drain_control_slot(
        table_id: RequestTableId,
        terminal_wire_session_epoch: NonZeroU64,
        slot_index: u32,
        slot: &mut ControlSlot<C>,
        unresolved_capture: &mut bool,
    ) -> Option<TerminalControl<C>> {
        let ControlSlotState::Occupied {
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &slot.state
        else {
            return None;
        };
        if matches!(*wire_state, WireState::Capturing | WireState::Captured) {
            *unresolved_capture = true;
            return None;
        }
        let lane = *lane;
        let birth_session_epoch = *birth_session_epoch;
        let birth_generation = *birth_generation;
        let terminal_req_id = *req_id;
        let terminal_kind = ControlTerminalKind::Drained;
        let terminal_state = ControlSlotState::Terminalizing {
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
        };
        let previous = core::mem::replace(&mut slot.state, terminal_state);
        let ControlSlotState::Occupied { continuation, .. } = previous else {
            slot.state = previous;
            return None;
        };
        Some(TerminalControl {
            table_id: table_id.0,
            slot_index,
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
            continuation,
        })
    }

    fn validate_application_key(&self, key: ApplicationKey) -> Result<usize, ApplicationError> {
        if key.table_id != self.table_id {
            return Err(ApplicationError::Key(KeyError::ForeignTable));
        }
        if !matches!(
            classify_table_index(self.topology, key.slot_index),
            Ok(ReqIndexClass::Application { index }) if index == key.slot_index
        ) {
            return Err(ApplicationError::Key(KeyError::WrongClass));
        }
        let Ok(index) = usize::try_from(key.slot_index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let Some(slot) = self.application.get(index) else {
            return Err(ApplicationError::Key(KeyError::SlotOutOfRange));
        };
        let ApplicationSlotState::Live {
            pending,
            birth_session_epoch,
            birth_generation,
            ..
        } = &slot.state
        else {
            return Err(ApplicationError::Key(KeyError::Vacant));
        };
        let _ = pending;
        if *birth_session_epoch != key.birth_session_epoch
            || *birth_generation != key.birth_generation
        {
            return Err(ApplicationError::Key(KeyError::StaleBirth));
        }
        Ok(index)
    }

    fn validate_control_key(&self, key: ControlKey) -> Result<ControlStorage, ControlError> {
        if key.table_id != self.table_id {
            return Err(ControlError::Key(KeyError::ForeignTable));
        }
        let storage = control_storage(self.topology, key.lane)
            .map_err(|_| ControlError::Key(KeyError::WrongClass))?;
        if storage.slot_index() != key.slot_index {
            return Err(ControlError::Key(KeyError::WrongClass));
        }
        let Some(slot) = self.control_slot(storage) else {
            return Err(ControlError::Key(KeyError::SlotOutOfRange));
        };
        let ControlSlotState::Occupied {
            continuation,
            lane,
            birth_session_epoch,
            birth_generation,
            ..
        } = &slot.state
        else {
            return Err(ControlError::Key(KeyError::Vacant));
        };
        let _ = continuation;
        if *lane != key.lane
            || *birth_session_epoch != key.birth_session_epoch
            || *birth_generation != key.birth_generation
        {
            return Err(ControlError::Key(KeyError::StaleBirth));
        }
        Ok(storage)
    }

    fn finish_application_disposition(
        &mut self,
        captured: CapturedApplication,
        next_state: WireState,
    ) -> Result<ApplicationKey, PreservedError<ApplicationError, CapturedApplication>> {
        if captured.table_id != self.table_id {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::ForeignTable),
                captured,
            ));
        }
        if captured.req_id.slot_index() != captured.slot_index
            || !matches!(
                classify_table_index(self.topology, captured.slot_index),
                Ok(ReqIndexClass::Application { index }) if index == captured.slot_index
            )
        {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::WrongClass),
                captured,
            ));
        }
        let Ok(index) = usize::try_from(captured.slot_index) else {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::SlotOutOfRange),
                captured,
            ));
        };
        let Some(slot) = self.application.get_mut(index) else {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::SlotOutOfRange),
                captured,
            ));
        };
        let ApplicationSlotState::Live {
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &mut slot.state
        else {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::Vacant),
                captured,
            ));
        };
        if *birth_session_epoch != captured.birth_session_epoch
            || *birth_generation != captured.birth_generation
        {
            return Err(PreservedError::new(
                ApplicationError::Key(KeyError::StaleBirth),
                captured,
            ));
        }
        if self.session_epoch != captured.wire_session_epoch
            || *req_id != captured.req_id
            || *wire_state != WireState::Captured
        {
            return Err(PreservedError::new(
                ApplicationError::Phase(PhaseError::WrongState),
                captured,
            ));
        }
        *wire_state = next_state;
        Ok(ApplicationKey {
            table_id: captured.table_id,
            slot_index: captured.slot_index,
            birth_session_epoch: captured.birth_session_epoch,
            birth_generation: captured.birth_generation,
        })
    }

    fn finish_control_disposition(
        &mut self,
        captured: CapturedControl,
        next_state: WireState,
    ) -> Result<ControlKey, PreservedError<ControlError, CapturedControl>> {
        if captured.table_id != self.table_id {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::ForeignTable),
                captured,
            ));
        }
        let storage = match control_storage(self.topology, captured.lane) {
            Ok(storage) if storage.slot_index() == captured.slot_index => storage,
            _ => {
                return Err(PreservedError::new(
                    ControlError::Key(KeyError::WrongClass),
                    captured,
                ));
            }
        };
        let session_epoch = self.session_epoch;
        let Some(slot) = self.control_slot_mut(storage) else {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::SlotOutOfRange),
                captured,
            ));
        };
        let ControlSlotState::Occupied {
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            ..
        } = &mut slot.state
        else {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::Vacant),
                captured,
            ));
        };
        if *lane != captured.lane
            || *birth_session_epoch != captured.birth_session_epoch
            || *birth_generation != captured.birth_generation
        {
            return Err(PreservedError::new(
                ControlError::Key(KeyError::StaleBirth),
                captured,
            ));
        }
        if session_epoch != captured.wire_session_epoch
            || *req_id != captured.req_id
            || *wire_state != WireState::Captured
        {
            return Err(PreservedError::new(
                ControlError::Phase(PhaseError::WrongState),
                captured,
            ));
        }
        *wire_state = next_state;
        Ok(ControlKey {
            table_id: captured.table_id,
            slot_index: captured.slot_index,
            lane: captured.lane,
            birth_session_epoch: captured.birth_session_epoch,
            birth_generation: captured.birth_generation,
        })
    }

    fn control_slot(&self, storage: ControlStorage) -> Option<&ControlSlot<C>> {
        match storage {
            ControlStorage::System { backing_index, .. } => self._system.get(backing_index),
            ControlStorage::Global { .. } => Some(&*self._global),
        }
    }

    fn control_slot_mut(&mut self, storage: ControlStorage) -> Option<&mut ControlSlot<C>> {
        match storage {
            ControlStorage::System { backing_index, .. } => self._system.get_mut(backing_index),
            ControlStorage::Global { .. } => Some(&mut *self._global),
        }
    }

    fn control_slot_by_req_index_mut(&mut self, slot_index: u32) -> Option<&mut ControlSlot<C>> {
        if slot_index == GLOBAL_EXTERNAL_CHANGE_ACK_REQID {
            return Some(&mut *self._global);
        }
        let backing_index = slot_index.checked_sub(SYSTEM_REQID_BASE)?;
        let backing_index = usize::try_from(backing_index).ok()?;
        self._system.get_mut(backing_index)
    }
}

#[derive(Clone, Copy)]
enum ControlStorage {
    System {
        slot_index: u32,
        backing_index: usize,
    },
    Global {
        slot_index: u32,
    },
}

impl ControlStorage {
    const fn slot_index(self) -> u32 {
        match self {
            Self::System { slot_index, .. } | Self::Global { slot_index } => slot_index,
        }
    }
}

fn control_storage(
    topology: RequestTopology,
    lane: ControlLane,
) -> Result<ControlStorage, ControlAdmissionError> {
    if lane == ControlLane::ExternalChangeAck {
        return match classify_table_index(topology, GLOBAL_EXTERNAL_CHANGE_ACK_REQID) {
            Ok(ReqIndexClass::ExternalChangeAck) => Ok(ControlStorage::Global {
                slot_index: GLOBAL_EXTERNAL_CHANGE_ACK_REQID,
            }),
            _ => Err(ControlAdmissionError::RingOutOfRange),
        };
    }

    let (ring_index, lane_offset, expected_class) = match lane {
        ControlLane::OpenLifecycle { ring_index } => {
            (ring_index, 0, ReqIndexClass::OpenLifecycle { ring_index })
        }
        ControlLane::PtRouteAck { ring_index } => {
            (ring_index, 1, ReqIndexClass::PtRouteAck { ring_index })
        }
        ControlLane::PtExternalSafeAck { ring_index } => (
            ring_index,
            2,
            ReqIndexClass::PtExternalSafeAck { ring_index },
        ),
        ControlLane::ExternalChangeAck => {
            return Err(ControlAdmissionError::RingOutOfRange);
        }
    };
    if ring_index >= topology.ring_count {
        return Err(ControlAdmissionError::RingOutOfRange);
    }
    let Some(slot_index) = ring_index
        .checked_mul(SYSTEM_REQUEST_SLOTS_PER_RING)
        .and_then(|offset| offset.checked_add(lane_offset))
        .and_then(|offset| SYSTEM_REQID_BASE.checked_add(offset))
    else {
        return Err(ControlAdmissionError::RingOutOfRange);
    };
    if classify_table_index(topology, slot_index) != Ok(expected_class) {
        return Err(ControlAdmissionError::RingOutOfRange);
    }
    let Some(backing_index) = slot_index.checked_sub(SYSTEM_REQID_BASE) else {
        return Err(ControlAdmissionError::RingOutOfRange);
    };
    let Ok(backing_index) = usize::try_from(backing_index) else {
        return Err(ControlAdmissionError::RingOutOfRange);
    };
    Ok(ControlStorage::System {
        slot_index,
        backing_index,
    })
}

const fn control_lane_from_class(class: ReqIndexClass) -> Option<ControlLane> {
    match class {
        ReqIndexClass::OpenLifecycle { ring_index } => {
            Some(ControlLane::OpenLifecycle { ring_index })
        }
        ReqIndexClass::PtRouteAck { ring_index } => Some(ControlLane::PtRouteAck { ring_index }),
        ReqIndexClass::PtExternalSafeAck { ring_index } => {
            Some(ControlLane::PtExternalSafeAck { ring_index })
        }
        ReqIndexClass::ExternalChangeAck => Some(ControlLane::ExternalChangeAck),
        ReqIndexClass::Application { .. } => None,
    }
}

const fn capture_state_error(state: WireState) -> CaptureError {
    match state {
        WireState::Capturing => CaptureError::CaptureInProgress,
        WireState::Captured => CaptureError::CandidateInstalled,
        WireState::BetweenPhases
        | WireState::PreparedNotVisible
        | WireState::Visible
        | WireState::Quarantined
        | WireState::GenerationExhausted => CaptureError::NotVisible,
    }
}

const fn phase_is_pcancel_eligible(phase: ApplicationPhase) -> bool {
    !matches!(
        phase.opcode(),
        op::PREPARE_OPEN | op::QUERY_OP | op::ACK_RESULT
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyError {
    RingCountOutOfRange,
    MaxInflightOutOfRange,
    InvalidPartition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableInitError {
    ApplicationLength,
    SystemLength,
    NonPristineApplication,
    NonPristineSystem,
    NonPristineGlobal,
    TableIdExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationPhaseError {
    UnsupportedOpcode,
    NotJournaledSemantic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Full,
    TableNotActive,
    SessionGenerationExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlAdmissionError {
    WrongLanePhase,
    RingOutOfRange,
    Busy,
    TableNotActive,
    SessionGenerationExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    TableNotActive,
    WrongSession,
    ZeroRequestId,
    ZeroGeneration,
    UnassignedIndex,
    Vacant,
    Retired,
    StaleCurrentGeneration,
    NotVisible,
    CaptureInProgress,
    CandidateInstalled,
    WrongKindCaptureRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    WrongKind,
    WrongOpcode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureFinishError {
    ForeignTable,
    WrongClass,
    SlotOutOfRange,
    StaleBirth,
    StaleWireIdentity,
    WrongState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    ForeignTable,
    WrongClass,
    SlotOutOfRange,
    StaleBirth,
    Vacant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseError {
    WrongState,
    WrongPhaseClass,
    GenerationExhausted,
    TableNotActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationError {
    Key(KeyError),
    Phase(PhaseError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    Key(KeyError),
    Phase(PhaseError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclaimError {
    ForeignTable,
    WrongClass,
    SlotOutOfRange,
    StaleBirth,
    StaleTerminalIdentity,
    NotTerminalizing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionTransitionError {
    WrongMode,
    WrongEpoch,
    EpochExhausted,
    TopologyChanged,
    UnresolvedApplicationPhase,
    UnresolvedCapture,
    LiveControlLane,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainError {
    NotDraining,
    UnresolvedCapture,
}

#[cfg(test)]
mod tests;
