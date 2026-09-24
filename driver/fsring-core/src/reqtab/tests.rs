// TEST: document fixtures and already-guarded partition arithmetic deliberately
// panic on contract drift; production code retains the crate-wide denials.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::drop_non_drop,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_range_loop
)]

use super::*;
use crate::typestate::{CompletionOwner, CompletionSink};
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use fsring_abi::{
    ids::REQ_GENERATION_MAX,
    layout::{cq_kind, op},
    limits::{
        GLOBAL_EXTERNAL_CHANGE_ACK_REQID, MAX_INFLIGHT, MAX_RING_COUNT, ReqIndexClass,
        ReqIndexError, SYSTEM_REQID_BASE, SYSTEM_REQUEST_SLOTS_PER_RING,
    },
};

/// A completion clearance for tests.
///
/// `06-locking.md` §6 permits `IoCompleteRequest` with nothing held, so an
/// empty context is exactly the case that yields one. Minting it through the
/// real [`crate::effect::Seam::clear_completion`] rather than fabricating the
/// token keeps these tests exercising the production path C2 added: if the seam
/// ever refuses an empty context, every one of these fails.
fn clearance(ctx: &crate::effect::EffectContext) -> crate::effect::CompletionClearance<'_> {
    struct NullSink;
    // SAFETY: performs no kernel effect; it exists so the seam has a sink.
    unsafe impl crate::effect::EffectSink for NullSink {
        unsafe fn emit(&mut self, _effect: crate::effect::Effect) {}
    }
    let mut seam = crate::effect::Seam::new(NullSink);
    let Ok(cleared) = seam.clear_completion(ctx) else {
        panic!("§6 permits completion with nothing held")
    };
    cleared
}

/// An empty held-set context for tests.
///
/// Separate from [`clearance`] because a clearance now **borrows** its context:
/// C2's first round found that a clearance minted under an empty held-set could
/// be carried across a lock acquisition and used to complete under it. The
/// borrow makes that E0502, and it also means a helper cannot return a
/// clearance over a context it owns -- hence this pair.
fn empty_context() -> crate::effect::EffectContext {
    // SAFETY: a host test owns no kernel lock, so the empty held-set is true.
    unsafe { crate::effect::EffectContext::empty() }
}

const TRANSPORT: &str = include_str!("../../../../docs/design/02-transport.md");
const OBJECT_MODEL: &str = include_str!("../../../../docs/design/04-object-model.md");
const LIFECYCLE: &str = include_str!("../../../../docs/design/10-lifecycle.md");
const RUST_IMPL: &str = include_str!("../../../../docs/design/11-rust-implementation.md");
const DRIVER_README: &str = include_str!("../../../README.md");
const REQTAB_SOURCE: &str = include_str!("../reqtab.rs");
const TYPESTATE_SOURCE: &str = include_str!("../typestate.rs");

/// Whitespace-normalized text, with rustdoc/line-comment markers dropped.
///
/// Markdown and rustdoc both wrap a sentence across lines, and rustdoc puts a
/// `///` on each continuation, so a line-bound `contains` silently misses a
/// phrase that is present. Both B5 review cycles recorded in the GREEN log
/// were slowed by scans with exactly that defect, so every prose assertion
/// below goes through this.
fn prose(source: &str) -> String {
    source
        .split_whitespace()
        .filter(|word| !matches!(*word, "///" | "//!" | "//" | "*"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn matching_brace(source: &str, open: usize) -> usize {
    let mut depth = 0_u32;
    for (offset, byte) in source
        .as_bytes()
        .get(open..)
        .expect("opening brace is in source")
        .iter()
        .copied()
        .enumerate()
    {
        match byte {
            b'{' => depth = depth.checked_add(1).expect("source braces fit u32"),
            b'}' => {
                depth = depth.checked_sub(1).expect("source braces are balanced");
                if depth == 0 {
                    return open + offset;
                }
            }
            _ => {}
        }
    }
    panic!("unterminated impl block");
}

fn inherent_public_methods(source: &str, type_name: &str) -> std::vec::Vec<std::string::String> {
    let generic_type = format!("{type_name}<");
    let mut methods = std::vec::Vec::new();
    let mut cursor = 0;
    while let Some(relative) = source[cursor..].find("\nimpl") {
        let impl_start = cursor + relative + 1;
        let after_impl = source.as_bytes().get(impl_start + "impl".len()).copied();
        if !matches!(after_impl, Some(b'<') | Some(b' ') | Some(b'\n')) {
            cursor = impl_start + "impl".len();
            continue;
        }
        let open = source[impl_start..]
            .find('{')
            .map(|relative| impl_start + relative)
            .expect("impl block opens");
        let header = &source[impl_start..open];
        let targets_inherent_type =
            header.contains(&generic_type) || header.trim_end().ends_with(type_name);
        let mentions_type = header
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .any(|identifier| identifier == type_name);
        let close = matching_brace(source, open);
        assert!(
            !(mentions_type && header.contains(" for ")),
            "{type_name} must expose no trait conversion impl: {header}"
        );
        if targets_inherent_type && !header.contains(" for ") {
            let mut depth = 0_u32;
            for line in source[open + 1..close].lines() {
                let trimmed = line.trim_start();
                if depth == 0 && trimmed.starts_with("pub ") {
                    let after_fn = trimmed
                        .split_once("fn ")
                        .unwrap_or_else(|| panic!("public inherent item is a method: {trimmed}"))
                        .1;
                    let name = after_fn
                        .split_once('(')
                        .unwrap_or_else(|| panic!("public method has arguments: {trimmed}"))
                        .0
                        .trim();
                    methods.push(name.to_owned());
                }
                for byte in line.as_bytes() {
                    match byte {
                        b'{' => depth = depth.checked_add(1).expect("method braces fit u32"),
                        b'}' => {
                            depth = depth
                                .checked_sub(1)
                                .expect("method source braces are balanced");
                        }
                        _ => {}
                    }
                }
            }
        }
        cursor = close + 1;
    }
    methods
}

#[derive(Clone, Copy)]
struct DocumentPartition {
    system_base: u32,
    system_lanes: u32,
    global: u32,
    lane_order: [DocumentLane; 3],
}

#[derive(Clone, Copy)]
enum DocumentLane {
    OpenLifecycle,
    PtRouteAck,
    PtExternalSafeAck,
}

fn decimal_after(haystack: &str, prefix: &str) -> u32 {
    let tail = haystack
        .split_once(prefix)
        .unwrap_or_else(|| panic!("missing document prefix {prefix:?}"))
        .1;
    let digits: String = tail
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("missing decimal after {prefix:?}"))
}

fn document_partition() -> DocumentPartition {
    let section = TRANSPORT
        .split_once("### 8.1 Request identity and the ReqId partition")
        .expect("section 8.1 must exist")
        .1
        .split_once("### 8.2")
        .expect("section 8.2 must follow")
        .0;
    assert!(section.contains("| `[0, max_inflight)` | application |"));
    assert!(
        section.contains("| `[SYSTEM_REQID_BASE, SYSTEM_REQID_BASE + 3 * ring_count)` | system |")
    );
    assert!(section.contains("| `16777215` | global |"));
    let normalized = section.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains(
        "For ring `r`, index `SYSTEM_REQID_BASE + 3*r` is the serialized open-lifecycle recovery slot, base+1 is the `PT_ROUTE_ACK` lane, and base+2 is the `PT_EXTERNAL_SAFE_ACK` lane."
    ));
    let global_row = section
        .lines()
        .find(|line| line.contains("| global |"))
        .expect("global partition row");
    let global: String = global_row.chars().filter(char::is_ascii_digit).collect();
    DocumentPartition {
        system_base: decimal_after(section, "`SYSTEM_REQID_BASE ="),
        system_lanes: decimal_after(section, "SYSTEM_REQID_BASE +"),
        global: global.parse().expect("global partition decimal"),
        lane_order: [
            DocumentLane::OpenLifecycle,
            DocumentLane::PtRouteAck,
            DocumentLane::PtExternalSafeAck,
        ],
    }
}

fn document_oracle(
    partition: DocumentPartition,
    index: u32,
    ring_count: u32,
    max_inflight: u32,
) -> Result<ReqIndexClass, ReqIndexError> {
    if index < max_inflight {
        return Ok(ReqIndexClass::Application { index });
    }
    if index == partition.global {
        return Ok(ReqIndexClass::ExternalChangeAck);
    }
    let system_end = partition
        .system_base
        .checked_add(
            partition
                .system_lanes
                .checked_mul(ring_count)
                .expect("document topology must fit"),
        )
        .expect("document topology must fit");
    if index < partition.system_base || index >= system_end {
        return Err(ReqIndexError::Unassigned);
    }
    let ordinal = index - partition.system_base;
    let ring_index = ordinal / partition.system_lanes;
    let lane_ordinal =
        usize::try_from(ordinal % partition.system_lanes).expect("three-lane ordinal fits usize");
    match partition.lane_order.get(lane_ordinal).copied() {
        Some(DocumentLane::OpenLifecycle) => Ok(ReqIndexClass::OpenLifecycle { ring_index }),
        Some(DocumentLane::PtRouteAck) => Ok(ReqIndexClass::PtRouteAck { ring_index }),
        Some(DocumentLane::PtExternalSafeAck) => {
            Ok(ReqIndexClass::PtExternalSafeAck { ring_index })
        }
        None => Err(ReqIndexError::Unassigned),
    }
}

#[test]
fn partition_document_and_classifier_agree_at_all_boundaries() {
    let partition = document_partition();
    assert_eq!(partition.system_base, SYSTEM_REQID_BASE);
    assert_eq!(partition.system_lanes, SYSTEM_REQUEST_SLOTS_PER_RING);
    assert_eq!(partition.global, GLOBAL_EXTERNAL_CHANGE_ACK_REQID);

    for topology in [
        RequestTopology::try_new(1, 1).expect("minimum topology"),
        RequestTopology::try_new(MAX_RING_COUNT, MAX_INFLIGHT).expect("maximum topology"),
    ] {
        let ring_count = topology.ring_count();
        let max_inflight = topology.max_inflight();
        for index in 0..=0x00ff_ffff {
            assert_eq!(
                classify_table_index(topology, index),
                document_oracle(partition, index, ring_count, max_inflight),
                "index={index} ring_count={ring_count} max_inflight={max_inflight}"
            );
        }
    }
}

#[test]
fn request_topology_accepts_exact_bounds_and_rejects_neighbors() {
    assert_eq!(
        RequestTopology::try_new(1, 1)
            .map(|topology| { (topology.ring_count(), topology.max_inflight()) }),
        Ok((1, 1))
    );
    assert_eq!(
        RequestTopology::try_new(MAX_RING_COUNT, MAX_INFLIGHT)
            .map(|topology| { (topology.ring_count(), topology.max_inflight()) }),
        Ok((MAX_RING_COUNT, MAX_INFLIGHT))
    );
    assert_eq!(
        RequestTopology::try_new(0, 1),
        Err(TopologyError::RingCountOutOfRange)
    );
    assert_eq!(
        RequestTopology::try_new(MAX_RING_COUNT + 1, 1),
        Err(TopologyError::RingCountOutOfRange)
    );
    assert_eq!(
        RequestTopology::try_new(1, 0),
        Err(TopologyError::MaxInflightOutOfRange)
    );
    assert_eq!(
        RequestTopology::try_new(1, MAX_INFLIGHT + 1),
        Err(TopologyError::MaxInflightOutOfRange)
    );
}

#[test]
fn application_phase_acceptance_is_exact_over_u16() {
    let accepted = [
        op::PREPARE_OPEN,
        op::COMMIT_OPEN,
        op::ABORT_OPEN,
        op::CLEANUP,
        op::CLOSE,
        op::READ,
        op::WRITE,
        op::FLUSH,
        op::QUERY_INFO,
        op::MUTATE,
        op::QUERY_DIR,
        op::QUERY_VOLUME,
        op::QUERY_SECURITY,
        op::QUERY_OP,
        op::ACK_RESULT,
    ];
    let journaled = [op::COMMIT_OPEN, op::WRITE, op::MUTATE];
    for opcode in 0..=u16::MAX {
        let ordinary = ApplicationPhase::new(opcode);
        assert_eq!(
            ordinary.is_ok(),
            accepted.contains(&opcode),
            "opcode={opcode:#06x}"
        );
        if let Ok(phase) = ordinary {
            assert_eq!(phase.opcode(), opcode);
            assert_eq!(phase.capture_role(), ApplicationCaptureRole::CompletionOnly);
        }
        let semantic = ApplicationPhase::journaled_semantic(opcode);
        assert_eq!(
            semantic.is_ok(),
            journaled.contains(&opcode),
            "journaled opcode={opcode:#06x}"
        );
        if accepted.contains(&opcode) && !journaled.contains(&opcode) {
            assert_eq!(semantic, Err(ApplicationPhaseError::NotJournaledSemantic));
        }
    }
}

// The trait's own obligation (typestate.rs) is that an implementor MUST NOT be
// `Copy` or `Clone`, so the sink producing the runtime at-most-once evidence
// must not be duplicable either. The counters are shared through `Arc`, not by
// cloning the sink. The deliberately-cloneable violator lives in the
// compile-fail fixtures, where its rejection is the point.
struct CountingSink {
    pended: std::sync::Arc<AtomicU32>,
    completed: std::sync::Arc<AtomicU32>,
}

unsafe impl CompletionSink for CountingSink {
    unsafe fn complete(
        &mut self,
        _cleared: crate::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    unsafe fn mark_pending(&mut self) {
        self.pended.fetch_add(1, Ordering::Relaxed);
    }
}

fn backing<const A: usize, const C: usize>() -> (
    [ApplicationSlot<CountingSink>; A],
    [ControlSlot<()>; C],
    ControlSlot<()>,
) {
    (
        core::array::from_fn(|_| ApplicationSlot::pristine()),
        core::array::from_fn(|_| ControlSlot::pristine()),
        ControlSlot::pristine(),
    )
}

fn control_backing<const A: usize, const C: usize>() -> (
    [ApplicationSlot<CountingSink>; A],
    [ControlSlot<u32>; C],
    ControlSlot<u32>,
) {
    (
        core::array::from_fn(|_| ApplicationSlot::pristine()),
        core::array::from_fn(|_| ControlSlot::pristine()),
        ControlSlot::pristine(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApplicationEntrySnapshot {
    Pristine,
    Free {
        next_free: Option<u32>,
        generation: u64,
    },
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
        phase: ApplicationPhase,
        birth_session_epoch: NonZeroU64,
        birth_generation: u64,
        req_id: ReqId,
        wire_state: WireState,
        cancel_requested: bool,
    },
}

fn application_entry_snapshot<S: CompletionSink>(
    table: &RequestTable<'_, S, impl Sized>,
    index: usize,
) -> ApplicationEntrySnapshot {
    let slot = table
        .application
        .get(index)
        .unwrap_or_else(|| panic!("application snapshot index {index}"));
    match &slot.state {
        ApplicationSlotState::Pristine => ApplicationEntrySnapshot::Pristine,
        ApplicationSlotState::Free {
            next_free,
            generation,
        } => ApplicationEntrySnapshot::Free {
            next_free: *next_free,
            generation: *generation,
        },
        ApplicationSlotState::Retired { generation } => ApplicationEntrySnapshot::Retired {
            generation: *generation,
        },
        ApplicationSlotState::Terminalizing {
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
        } => ApplicationEntrySnapshot::Terminalizing {
            birth_session_epoch: *birth_session_epoch,
            birth_generation: *birth_generation,
            terminal_wire_session_epoch: *terminal_wire_session_epoch,
            terminal_req_id: *terminal_req_id,
        },
        ApplicationSlotState::Live {
            phase,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
            cancel_requested,
            ..
        } => ApplicationEntrySnapshot::Live {
            phase: *phase,
            birth_session_epoch: *birth_session_epoch,
            birth_generation: *birth_generation,
            req_id: *req_id,
            wire_state: *wire_state,
            cancel_requested: *cancel_requested,
        },
    }
}

fn counting_application_observation<C>(
    table: &RequestTable<'_, CountingSink, C>,
    index: usize,
    pended: &AtomicU32,
    completed: &AtomicU32,
) -> (ApplicationEntrySnapshot, Option<u32>, u32, u32) {
    (
        application_entry_snapshot(table, index),
        table.free_head,
        pended.load(Ordering::Relaxed),
        completed.load(Ordering::Relaxed),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlEntrySnapshot {
    Pristine,
    Available {
        generation: u64,
    },
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
        continuation: u32,
        phase: ControlPhase,
        lane: ControlLane,
        birth_session_epoch: NonZeroU64,
        birth_generation: u64,
        req_id: ReqId,
        wire_state: WireState,
    },
}

fn system_control_snapshot(
    table: &RequestTable<'_, CountingSink, u32>,
    index: usize,
) -> ControlEntrySnapshot {
    let slot = table
        ._system
        .get(index)
        .unwrap_or_else(|| panic!("control snapshot index {index}"));
    control_slot_snapshot(slot)
}

/// The global external-change lane has its own storage and, in
/// `rebind_session`, its own reset branch separate from the per-ring loop.
fn global_control_snapshot(table: &RequestTable<'_, CountingSink, u32>) -> ControlEntrySnapshot {
    control_slot_snapshot(table._global)
}

fn control_slot_snapshot(slot: &ControlSlot<u32>) -> ControlEntrySnapshot {
    match &slot.state {
        ControlSlotState::Pristine => ControlEntrySnapshot::Pristine,
        ControlSlotState::Available { generation } => ControlEntrySnapshot::Available {
            generation: *generation,
        },
        ControlSlotState::Retired { generation } => ControlEntrySnapshot::Retired {
            generation: *generation,
        },
        ControlSlotState::Terminalizing {
            lane,
            birth_session_epoch,
            birth_generation,
            terminal_wire_session_epoch,
            terminal_req_id,
            terminal_kind,
        } => ControlEntrySnapshot::Terminalizing {
            lane: *lane,
            birth_session_epoch: *birth_session_epoch,
            birth_generation: *birth_generation,
            terminal_wire_session_epoch: *terminal_wire_session_epoch,
            terminal_req_id: *terminal_req_id,
            terminal_kind: *terminal_kind,
        },
        ControlSlotState::Occupied {
            continuation,
            phase,
            lane,
            birth_session_epoch,
            birth_generation,
            req_id,
            wire_state,
        } => ControlEntrySnapshot::Occupied {
            continuation: *continuation,
            phase: *phase,
            lane: *lane,
            birth_session_epoch: *birth_session_epoch,
            birth_generation: *birth_generation,
            req_id: *req_id,
            wire_state: *wire_state,
        },
    }
}

fn copy_application_capture(value: &ApplicationCapture) -> ApplicationCapture {
    ApplicationCapture {
        table_id: value.table_id,
        slot_index: value.slot_index,
        birth_session_epoch: value.birth_session_epoch,
        birth_generation: value.birth_generation,
        wire_session_epoch: value.wire_session_epoch,
        req_id: value.req_id,
        expected_opcode: value.expected_opcode,
    }
}

fn application_capture_snapshot(
    value: &ApplicationCapture,
) -> (RequestTableId, u32, NonZeroU64, u64, NonZeroU64, ReqId, u16) {
    (
        value.table_id,
        value.slot_index,
        value.birth_session_epoch,
        value.birth_generation,
        value.wire_session_epoch,
        value.req_id,
        value.expected_opcode,
    )
}

fn copy_control_capture(value: &ControlCapture) -> ControlCapture {
    ControlCapture {
        table_id: value.table_id,
        slot_index: value.slot_index,
        lane: value.lane,
        birth_session_epoch: value.birth_session_epoch,
        birth_generation: value.birth_generation,
        wire_session_epoch: value.wire_session_epoch,
        req_id: value.req_id,
        expected_opcode: value.expected_opcode,
    }
}

fn control_capture_snapshot(
    value: &ControlCapture,
) -> (
    RequestTableId,
    u32,
    ControlLane,
    NonZeroU64,
    u64,
    NonZeroU64,
    ReqId,
    u16,
) {
    (
        value.table_id,
        value.slot_index,
        value.lane,
        value.birth_session_epoch,
        value.birth_generation,
        value.wire_session_epoch,
        value.req_id,
        value.expected_opcode,
    )
}

fn copy_captured_application(value: &CapturedApplication) -> CapturedApplication {
    CapturedApplication {
        table_id: value.table_id,
        slot_index: value.slot_index,
        birth_session_epoch: value.birth_session_epoch,
        birth_generation: value.birth_generation,
        wire_session_epoch: value.wire_session_epoch,
        req_id: value.req_id,
    }
}

fn captured_application_snapshot(
    value: &CapturedApplication,
) -> (RequestTableId, u32, NonZeroU64, u64, NonZeroU64, ReqId) {
    (
        value.table_id,
        value.slot_index,
        value.birth_session_epoch,
        value.birth_generation,
        value.wire_session_epoch,
        value.req_id,
    )
}

fn copy_captured_control(value: &CapturedControl) -> CapturedControl {
    CapturedControl {
        table_id: value.table_id,
        slot_index: value.slot_index,
        lane: value.lane,
        birth_session_epoch: value.birth_session_epoch,
        birth_generation: value.birth_generation,
        wire_session_epoch: value.wire_session_epoch,
        req_id: value.req_id,
    }
}

fn captured_control_snapshot(
    value: &CapturedControl,
) -> (
    RequestTableId,
    u32,
    ControlLane,
    NonZeroU64,
    u64,
    NonZeroU64,
    ReqId,
) {
    (
        value.table_id,
        value.slot_index,
        value.lane,
        value.birth_session_epoch,
        value.birth_generation,
        value.wire_session_epoch,
        value.req_id,
    )
}

fn copy_completion_receipt(value: &CompletionReceipt) -> CompletionReceipt {
    CompletionReceipt {
        table_id: value.table_id,
        slot_index: value.slot_index,
        birth_session_epoch: value.birth_session_epoch,
        birth_generation: value.birth_generation,
        terminal_wire_session_epoch: value.terminal_wire_session_epoch,
        terminal_req_id: value.terminal_req_id,
    }
}

fn completion_receipt_snapshot(
    value: &CompletionReceipt,
) -> (NonZeroU64, u32, NonZeroU64, u64, NonZeroU64, ReqId) {
    (
        value.table_id,
        value.slot_index,
        value.birth_session_epoch,
        value.birth_generation,
        value.terminal_wire_session_epoch,
        value.terminal_req_id,
    )
}

fn copy_control_release(value: &ControlRelease) -> ControlRelease {
    ControlRelease {
        table_id: value.table_id,
        slot_index: value.slot_index,
        lane: value.lane,
        birth_session_epoch: value.birth_session_epoch,
        birth_generation: value.birth_generation,
        terminal_wire_session_epoch: value.terminal_wire_session_epoch,
        terminal_req_id: value.terminal_req_id,
        terminal_kind: value.terminal_kind,
    }
}

fn control_release_snapshot(
    value: &ControlRelease,
) -> (
    NonZeroU64,
    u32,
    ControlLane,
    NonZeroU64,
    u64,
    NonZeroU64,
    ReqId,
    ControlTerminalKind,
) {
    (
        value.table_id,
        value.slot_index,
        value.lane,
        value.birth_session_epoch,
        value.birth_generation,
        value.terminal_wire_session_epoch,
        value.terminal_req_id,
        value.terminal_kind,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionEvent {
    Pending,
    Completed { status: i32, information: usize },
}

struct OrderedSink {
    events: std::sync::Arc<std::sync::Mutex<std::vec::Vec<CompletionEvent>>>,
}

unsafe impl CompletionSink for OrderedSink {
    unsafe fn complete(
        &mut self,
        _cleared: crate::effect::CompletionClearance<'_>,
        status: i32,
        information: usize,
    ) {
        self.events
            .lock()
            .expect("ordered completion trace")
            .push(CompletionEvent::Completed {
                status,
                information,
            });
    }

    unsafe fn mark_pending(&mut self) {
        self.events
            .lock()
            .expect("ordered completion trace")
            .push(CompletionEvent::Pending);
    }
}

struct TaggedSink {
    tag: u32,
    pended: std::sync::Arc<std::sync::Mutex<std::vec::Vec<u32>>>,
    completed: std::sync::Arc<std::sync::Mutex<std::vec::Vec<u32>>>,
    dropped: std::sync::Arc<std::sync::Mutex<std::vec::Vec<u32>>>,
}

unsafe impl CompletionSink for TaggedSink {
    unsafe fn complete(
        &mut self,
        _cleared: crate::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
        self.completed
            .lock()
            .expect("tagged completion trace")
            .push(self.tag);
    }

    unsafe fn mark_pending(&mut self) {
        self.pended
            .lock()
            .expect("tagged pending trace")
            .push(self.tag);
    }
}

impl Drop for TaggedSink {
    fn drop(&mut self) {
        self.dropped
            .lock()
            .expect("tagged application drop trace")
            .push(self.tag);
    }
}

struct TaggedContinuation {
    tag: u32,
    dropped: std::sync::Arc<std::sync::Mutex<std::vec::Vec<u32>>>,
}

impl Drop for TaggedContinuation {
    fn drop(&mut self) {
        self.dropped
            .lock()
            .expect("tagged control drop trace")
            .push(self.tag);
    }
}

fn tagged_backing<const A: usize, const C: usize>() -> (
    [ApplicationSlot<TaggedSink>; A],
    [ControlSlot<TaggedContinuation>; C],
    ControlSlot<TaggedContinuation>,
) {
    (
        core::array::from_fn(|_| ApplicationSlot::pristine()),
        core::array::from_fn(|_| ControlSlot::pristine()),
        ControlSlot::pristine(),
    )
}

#[test]
fn constructor_rejects_each_length_mismatch_and_nonpristine_backing() {
    let topology = RequestTopology::try_new(2, 2).expect("valid topology");
    let epoch = NonZeroU64::new(7).expect("nonzero");

    let (mut short_app, mut system, mut global) = backing::<1, 6>();
    assert!(matches!(
        RequestTable::try_new(epoch, topology, &mut short_app, &mut system, &mut global),
        Err(TableInitError::ApplicationLength)
    ));
    let (mut long_app, mut system, mut global) = backing::<3, 6>();
    assert!(matches!(
        RequestTable::try_new(epoch, topology, &mut long_app, &mut system, &mut global),
        Err(TableInitError::ApplicationLength)
    ));
    let (mut application, mut short_system, mut global) = backing::<2, 5>();
    assert!(matches!(
        RequestTable::try_new(
            epoch,
            topology,
            &mut application,
            &mut short_system,
            &mut global
        ),
        Err(TableInitError::SystemLength)
    ));
    let (mut application, mut long_system, mut global) = backing::<2, 7>();
    assert!(matches!(
        RequestTable::try_new(
            epoch,
            topology,
            &mut application,
            &mut long_system,
            &mut global
        ),
        Err(TableInitError::SystemLength)
    ));

    let (mut application, mut system, mut global) = backing::<2, 6>();
    application[0].state = ApplicationSlotState::Free {
        next_free: None,
        generation: 0,
    };
    assert!(matches!(
        RequestTable::try_new(epoch, topology, &mut application, &mut system, &mut global),
        Err(TableInitError::NonPristineApplication)
    ));
    let (mut application, mut system, mut global) = backing::<2, 6>();
    system[0].state = ControlSlotState::Available { generation: 0 };
    assert!(matches!(
        RequestTable::try_new(epoch, topology, &mut application, &mut system, &mut global),
        Err(TableInitError::NonPristineSystem)
    ));
    let (mut application, mut system, mut global) = backing::<2, 6>();
    global.state = ControlSlotState::Available { generation: 0 };
    assert!(matches!(
        RequestTable::try_new(epoch, topology, &mut application, &mut system, &mut global),
        Err(TableInitError::NonPristineGlobal)
    ));
}

#[test]
fn one_call_admission_marks_pending_only_after_preflight() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(1).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("pristine backing");
    let phase = ApplicationPhase::new(op::READ).expect("application opcode");

    let first = match table.admit_application(
        phase,
        CompletionOwner::new(CountingSink {
            pended: pended.clone(),
            completed: completed.clone(),
        }),
    ) {
        Ok(admission) => admission,
        Err(_) => panic!("first slot is free"),
    };
    assert_eq!(first.req_id().generation(), 1);
    assert_eq!(pended.load(Ordering::Relaxed), 1);

    let rejected = table
        .admit_application(
            phase,
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .expect_err("capacity one is full");
    assert_eq!(rejected.error(), &AdmissionError::Full);
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    let (error, owner) = rejected.into_parts();
    assert_eq!(error, AdmissionError::Full);
    owner.complete(clearance(&empty_context()), 0, 0);
    assert_eq!(completed.load(Ordering::Relaxed), 1);
}

#[test]
fn application_and_control_capacity_are_disjoint() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(2, 2).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<2, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(2).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("pristine backing");
    for expected_index in [0, 1] {
        let admission = match table.admit_application(
            ApplicationPhase::new(op::FLUSH).expect("application opcode"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        ) {
            Ok(admission) => admission,
            Err(_) => panic!("application capacity"),
        };
        assert_eq!(admission.req_id().slot_index(), expected_index);
    }
    assert!(
        table
            ._system
            .iter()
            .all(|slot| matches!(slot.state, ControlSlotState::Available { .. }))
    );
    assert!(matches!(
        table._global.state,
        ControlSlotState::Available { .. }
    ));

    let (mut application, mut system, mut global) = control_backing::<2, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(2).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("pristine backing");
    for expected_index in [0, 1] {
        let admission = match table.admit_application(
            ApplicationPhase::new(op::FLUSH).expect("application opcode"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        ) {
            Ok(admission) => admission,
            Err(_) => panic!("application capacity"),
        };
        assert_eq!(admission.req_id().slot_index(), expected_index);
    }
    for (lane, phase, continuation) in [
        (
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
            10,
        ),
        (
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
            11,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 1 },
            ControlPhase::PtExternalSafeAck,
            12,
        ),
        (
            ControlLane::ExternalChangeAck,
            ControlPhase::ExternalChangeAck,
            13,
        ),
    ] {
        assert!(
            table.admit_control(lane, phase, continuation).is_ok(),
            "full application backing must not consume {lane:?}"
        );
    }
    let rejected = table
        .admit_application(
            ApplicationPhase::new(op::FLUSH).expect("application opcode"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .expect_err("control admission must not add application capacity");
    assert_eq!(rejected.error(), &AdmissionError::Full);
}

#[test]
fn control_lane_opcode_matrix_is_exact() {
    let topology = RequestTopology::try_new(2, 1).expect("valid topology");
    let lanes = [
        (
            ControlLane::OpenLifecycle { ring_index: 0 },
            SYSTEM_REQID_BASE,
        ),
        (
            ControlLane::PtRouteAck { ring_index: 1 },
            SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING + 1,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 0 },
            SYSTEM_REQID_BASE + 2,
        ),
        (
            ControlLane::ExternalChangeAck,
            GLOBAL_EXTERNAL_CHANGE_ACK_REQID,
        ),
    ];
    let phases = [
        (ControlPhase::ReplayOpen, op::REPLAY_OPEN),
        (ControlPhase::RecoveryCleanup, op::CLEANUP),
        (ControlPhase::RecoveryClose, op::CLOSE),
        (ControlPhase::PtRouteAck, op::PT_ROUTE_ACK),
        (ControlPhase::PtExternalSafeAck, op::PT_EXTERNAL_SAFE_ACK),
        (ControlPhase::ExternalChangeAck, op::DIR_CHANGE_ACK),
    ];

    for (lane, expected_index) in lanes {
        for (phase, expected_opcode) in phases {
            assert_eq!(phase.opcode(), expected_opcode);
            let valid = matches!(
                (lane, phase),
                (
                    ControlLane::OpenLifecycle { .. },
                    ControlPhase::ReplayOpen
                        | ControlPhase::RecoveryCleanup
                        | ControlPhase::RecoveryClose
                ) | (ControlLane::PtRouteAck { .. }, ControlPhase::PtRouteAck)
                    | (
                        ControlLane::PtExternalSafeAck { .. },
                        ControlPhase::PtExternalSafeAck
                    )
                    | (
                        ControlLane::ExternalChangeAck,
                        ControlPhase::ExternalChangeAck
                    )
            );
            let (mut application, mut system, mut global) = control_backing::<1, 6>();
            let mut table = RequestTable::try_new(
                NonZeroU64::new(9).expect("nonzero"),
                topology,
                &mut application,
                &mut system,
                &mut global,
            )
            .expect("pristine backing");
            match table.admit_control(lane, phase, 0xfeed_beef) {
                Ok(admission) => {
                    assert!(valid, "{lane:?} must reject {phase:?}");
                    assert_eq!(admission.req_id().slot_index(), expected_index);
                    assert_eq!(admission.req_id().generation(), 1);
                    assert_eq!(admission.key().lane, lane);
                    assert_eq!(admission.key().slot_index, expected_index);
                }
                Err(rejected) => {
                    assert!(!valid, "{lane:?} must accept {phase:?}");
                    assert_eq!(rejected.error(), &ControlAdmissionError::WrongLanePhase);
                    assert_eq!(rejected.into_parts().1, 0xfeed_beef);
                }
            }
        }
    }

    let (mut application, mut system, mut global) = control_backing::<1, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(9).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("pristine backing");
    for (lane, phase) in [
        (
            ControlLane::OpenLifecycle { ring_index: 2 },
            ControlPhase::ReplayOpen,
        ),
        (
            ControlLane::PtRouteAck {
                ring_index: u32::MAX,
            },
            ControlPhase::PtRouteAck,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 2 },
            ControlPhase::PtExternalSafeAck,
        ),
    ] {
        let rejected = table
            .admit_control(lane, phase, 77)
            .expect_err("out-of-range ring");
        assert_eq!(rejected.error(), &ControlAdmissionError::RingOutOfRange);
        assert_eq!(rejected.into_parts().1, 77);
    }
}

// Same obligation as CountingSink above: a `CompletionSink` implementor
// must not be duplicable. The derive was dead -- the shared counters are
// `Arc`s cloned separately -- which is exactly why nothing noticed it.
struct IdentitySink {
    identity: u32,
    pended: std::sync::Arc<AtomicU32>,
    completed_identity: std::sync::Arc<AtomicU32>,
}

unsafe impl CompletionSink for IdentitySink {
    unsafe fn complete(
        &mut self,
        _cleared: crate::effect::CompletionClearance<'_>,
        _status: i32,
        _information: usize,
    ) {
        self.completed_identity
            .store(self.identity, Ordering::Relaxed);
    }

    unsafe fn mark_pending(&mut self) {
        self.pended.fetch_add(1, Ordering::Relaxed);
    }
}

fn identity_backing() -> (
    [ApplicationSlot<IdentitySink>; 1],
    [ControlSlot<u32>; 3],
    ControlSlot<u32>,
) {
    (
        core::array::from_fn(|_| ApplicationSlot::pristine()),
        core::array::from_fn(|_| ControlSlot::pristine()),
        ControlSlot::pristine(),
    )
}

#[test]
fn all_admission_errors_preserve_application_owner_and_control_continuation() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let phase = ApplicationPhase::new(op::READ).expect("application opcode");
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed_identity = std::sync::Arc::new(AtomicU32::new(0));
    let owner = |identity| {
        CompletionOwner::new(IdentitySink {
            identity,
            pended: pended.clone(),
            completed_identity: completed_identity.clone(),
        })
    };

    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        assert!(table.admit_application(phase, owner(1)).is_ok());
        let (error, returned) = table
            .admit_application(phase, owner(101))
            .expect_err("application backing is full")
            .into_parts();
        assert_eq!(error, AdmissionError::Full);
        returned.complete(clearance(&empty_context()), 0, 0);
        assert_eq!(completed_identity.load(Ordering::Relaxed), 101);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table.begin_fence().expect("active table fences");
        let (error, returned) = table
            .admit_application(phase, owner(102))
            .expect_err("fencing table")
            .into_parts();
        assert_eq!(error, AdmissionError::TableNotActive);
        returned.complete(clearance(&empty_context()), 0, 0);
        assert_eq!(completed_identity.load(Ordering::Relaxed), 102);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table
            .application
            .get_mut(0)
            .expect("one application slot")
            .state = ApplicationSlotState::Free {
            next_free: None,
            generation: REQ_GENERATION_MAX,
        };
        let (error, returned) = table
            .admit_application(phase, owner(103))
            .expect_err("generation exhausted")
            .into_parts();
        assert_eq!(error, AdmissionError::SessionGenerationExhausted);
        returned.complete(clearance(&empty_context()), 0, 0);
        assert_eq!(completed_identity.load(Ordering::Relaxed), 103);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table.begin_drain();
        let (error, returned) = table
            .admit_application(phase, owner(104))
            .expect_err("draining table")
            .into_parts();
        assert_eq!(error, AdmissionError::TableNotActive);
        returned.complete(clearance(&empty_context()), 0, 0);
        assert_eq!(completed_identity.load(Ordering::Relaxed), 104);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table
            .application
            .get_mut(0)
            .expect("one application slot")
            .state = ApplicationSlotState::Retired {
            generation: REQ_GENERATION_MAX,
        };
        table.free_head = None;
        table.application_retired = 1;
        let (error, returned) = table
            .admit_application(phase, owner(105))
            .expect_err("retired-only application capacity")
            .into_parts();
        assert_eq!(error, AdmissionError::SessionGenerationExhausted);
        assert!(table.needs_quiesce());
        returned.complete(clearance(&empty_context()), 0, 0);
        assert_eq!(completed_identity.load(Ordering::Relaxed), 105);
    }
    assert_eq!(pended.load(Ordering::Relaxed), 1);

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        let rejected = table
            .admit_control(lane, ControlPhase::ReplayOpen, 201)
            .expect_err("wrong lane/phase");
        assert_eq!(rejected.error(), &ControlAdmissionError::WrongLanePhase);
        assert_eq!(rejected.into_parts().1, 201);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        let rejected = table
            .admit_control(
                ControlLane::PtRouteAck { ring_index: 1 },
                ControlPhase::PtRouteAck,
                202,
            )
            .expect_err("out-of-range ring");
        assert_eq!(rejected.error(), &ControlAdmissionError::RingOutOfRange);
        assert_eq!(rejected.into_parts().1, 202);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        assert!(
            table
                .admit_control(lane, ControlPhase::PtRouteAck, 301)
                .is_ok()
        );
        let rejected = table
            .admit_control(lane, ControlPhase::PtRouteAck, 203)
            .expect_err("occupied lane");
        assert_eq!(rejected.error(), &ControlAdmissionError::Busy);
        assert_eq!(rejected.into_parts().1, 203);
        let ControlSlotState::Occupied { continuation, .. } =
            &table._system.get(1).expect("PT route lane").state
        else {
            panic!("resident continuation must remain installed");
        };
        assert_eq!(*continuation, 301);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table.begin_fence().expect("active table fences");
        let rejected = table
            .admit_control(lane, ControlPhase::PtRouteAck, 204)
            .expect_err("fencing table");
        assert_eq!(rejected.error(), &ControlAdmissionError::TableNotActive);
        assert_eq!(rejected.into_parts().1, 204);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table._system.get_mut(1).expect("PT route lane").state = ControlSlotState::Available {
            generation: REQ_GENERATION_MAX,
        };
        let rejected = table
            .admit_control(lane, ControlPhase::PtRouteAck, 205)
            .expect_err("generation exhausted");
        assert_eq!(
            rejected.error(),
            &ControlAdmissionError::SessionGenerationExhausted
        );
        assert_eq!(rejected.into_parts().1, 205);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        table.begin_drain();
        let rejected = table
            .admit_control(lane, ControlPhase::PtRouteAck, 206)
            .expect_err("draining table");
        assert_eq!(rejected.error(), &ControlAdmissionError::TableNotActive);
        assert_eq!(rejected.into_parts().1, 206);
    }
    {
        let (mut application, mut system, mut global) = identity_backing();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(11).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("pristine backing");
        let resident = table
            .admit_control(lane, ControlPhase::PtRouteAck, 301)
            .unwrap_or_else(|_| panic!("control lane admits"));
        assert_eq!(
            table.mark_control_visible(resident.key()),
            Ok(resident.req_id())
        );
        let CaptureToken::Control(token) = table
            .begin_capture(11, cq_kind::COMPLETION, resident.req_id())
            .expect("control captures")
        else {
            panic!("control token");
        };
        let captured = table
            .install_control_candidate(token)
            .unwrap_or_else(|_| panic!("control candidate installs"));
        table
            .retain_control(captured)
            .unwrap_or_else(|_| panic!("control retains"));
        let ControlSlotState::Occupied { req_id, .. } =
            &mut table._system.get_mut(1).expect("PT route lane").state
        else {
            panic!("resident control continuation");
        };
        *req_id = ReqId::try_new(REQ_GENERATION_MAX, SYSTEM_REQID_BASE + 1)
            .expect("maximum control identity");
        assert_eq!(
            table.begin_control_phase(resident.key(), ControlPhase::PtRouteAck),
            Err(ControlError::Phase(PhaseError::GenerationExhausted))
        );
        let rejected = table
            .admit_control(lane, ControlPhase::PtRouteAck, 207)
            .expect_err("generation-exhausted control lane");
        assert_eq!(
            rejected.error(),
            &ControlAdmissionError::SessionGenerationExhausted
        );
        assert_eq!(rejected.into_parts().1, 207);
        let ControlSlotState::Occupied {
            continuation,
            wire_state,
            ..
        } = &table._system.get(1).expect("PT route lane").state
        else {
            panic!("resident continuation must remain installed");
        };
        assert_eq!(*continuation, 301);
        assert_eq!(*wire_state, WireState::GenerationExhausted);
        assert!(table.needs_quiesce());
    }
}

#[test]
fn request_table_ids_are_nonzero_unique_move_stable_and_sticky_exhausted() {
    let zero = AtomicU64::new(0);
    assert_eq!(allocate_table_id(&zero).map(RequestTableId::get), Ok(1));

    let ordinary = AtomicU64::new(1);
    let first = allocate_table_id(&ordinary).expect("first ID");
    let second = allocate_table_id(&ordinary).expect("second ID");
    assert_ne!(first, second);
    assert_ne!(first.get(), 0);

    let near_max = AtomicU64::new(u64::MAX - 1);
    assert_eq!(
        allocate_table_id(&near_max).map(RequestTableId::get),
        Ok(u64::MAX - 1)
    );
    assert_eq!(
        allocate_table_id(&near_max),
        Err(TableInitError::TableIdExhausted)
    );
    assert_eq!(
        allocate_table_id(&near_max),
        Err(TableInitError::TableIdExhausted)
    );
    assert_eq!(near_max.load(Ordering::Relaxed), u64::MAX);

    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let _sink = CountingSink {
        pended: pended.clone(),
        completed: completed.clone(),
    };
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let table = RequestTable::try_new(
        NonZeroU64::new(3).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let id = table.table_id;
    let moved = table;
    assert_eq!(moved.table_id, id);
}

#[test]
fn pending_capability_has_no_public_safe_escape() {
    assert!(TYPESTATE_SOURCE.contains("pub unsafe trait CompletionSink"));
    assert!(TYPESTATE_SOURCE.contains("unsafe fn complete("));
    assert!(TYPESTATE_SOURCE.contains("unsafe fn mark_pending("));
    assert!(TYPESTATE_SOURCE.contains("pub(crate) fn pending("));
    assert!(TYPESTATE_SOURCE.contains("pub(crate) fn into_owner("));
    assert!(!TYPESTATE_SOURCE.contains("pub fn pending("));
    assert!(!TYPESTATE_SOURCE.contains("pub fn into_owner("));
    assert!(!TYPESTATE_SOURCE.contains("into_sink"));
}

/// Design signal 30 asserts that every type-level claim is scoped to
/// at-most-once *per owner capability* and never claims eventual consumption.
/// Before this test, that signal was closed by inspection: reverting the
/// scoped wording to the pre-B5 "exactly once" phrasing left all 40 reqtab
/// tests, clippy and all 58 fixtures green. Two consecutive review cycles
/// (see the GREEN log) found overclaims in exactly this prose, so the claim
/// is pinned here against its normative source rather than against itself.
#[test]
fn at_most_once_wording_stays_scoped_to_the_owner_capability() {
    let normative = prose(RUST_IMPL);
    // 11-rust-implementation.md section 7 -- the standing normative sentences
    // the shipped prose must conform to. If the document is reworded, this
    // fails first and the code comments are re-read against the new text.
    for sentence in [
        "The type system proves **at most one completion per owner capability**.",
        "It cannot prove that a capability is eventually consumed, or that two dishonestly duplicated sink values do not name the same IRP",
        "`IoCompleteRequest` at most once through that owner a property the compiler enforces",
        "one sink value must represent unique ownership of one native request and must not be `Copy` or `Clone`",
    ] {
        assert!(
            normative.contains(&prose(sentence)),
            "11-rust-implementation.md no longer carries: {sentence}"
        );
    }

    // The shipped prose conforms: scoped to the capability, and explicit that
    // eventual consumption is not proven.
    let typestate = prose(TYPESTATE_SOURCE);
    for phrase in [
        "The at-most-once property holds only over one owner *capability*",
        "The type system prevents a second completion through one owner capability",
        "a second use through the same owner capability is a compile error",
        "Implementors MUST NOT be `Copy` or `Clone`",
    ] {
        assert!(
            typestate.contains(&prose(phrase)),
            "typestate.rs no longer scopes its claim: {phrase}"
        );
    }
    let readme = prose(DRIVER_README);
    for phrase in [
        "proves at-most-once use per capability",
        "It also cannot force eventual consumption (`mem::forget` remains possible)",
    ] {
        assert!(
            readme.contains(&prose(phrase)),
            "driver/README.md no longer scopes its claim: {phrase}"
        );
    }

    // The unscoped forms this slice removed must not come back. These are the
    // literal pre-B5 phrasings the two review cycles rejected.
    for regression in [
        "exactly-once property holds",
        "makes calling `IoCompleteRequest` exactly once",
        "guarantees no second completion of the same IRP",
        "proves exactly-once use",
    ] {
        let regression = prose(regression);
        assert!(
            !typestate.contains(&regression),
            "typestate.rs regressed to an unscoped claim: {regression}"
        );
        assert!(
            !readme.contains(&regression),
            "driver/README.md regressed to an unscoped claim: {regression}"
        );
        assert!(
            !normative.contains(&regression),
            "11-rust-implementation.md regressed to an unscoped claim: {regression}"
        );
    }
}

#[test]
fn terminal_capability_public_api_is_exact() {
    assert_eq!(
        inherent_public_methods(REQTAB_SOURCE, "TerminalApplication"),
        ["complete"]
    );
    assert_eq!(
        inherent_public_methods(REQTAB_SOURCE, "TerminalControl"),
        ["lane", "req_id", "terminal_kind", "release"]
    );
    assert!(
        inherent_public_methods(REQTAB_SOURCE, "CompletionReceipt").is_empty(),
        "CompletionReceipt must expose no public inherent method"
    );
    assert!(
        inherent_public_methods(REQTAB_SOURCE, "ControlRelease").is_empty(),
        "ControlRelease must expose no public inherent method"
    );
}

#[test]
fn reqtab_production_surface_is_allocator_free() {
    for (name, source) in [
        ("reqtab.rs", REQTAB_SOURCE),
        ("typestate.rs", TYPESTATE_SOURCE),
    ] {
        for needle in ["extern crate alloc", "alloc::", "Vec", "Box"] {
            assert!(!source.contains(needle), "{name} contains {needle:?}");
        }
    }
}

#[test]
fn application_admission_source_has_no_slot_scan() {
    let body = REQTAB_SOURCE
        .split_once("pub fn admit_application")
        .expect("admission method")
        .1
        .split_once("\n    }")
        .expect("admission method end")
        .0;
    assert!(body.contains("free_head"));
    assert!(body.contains("next_free"));
    for scan in [".iter(", ".iter_mut(", ".position(", "for ", "while "] {
        assert!(
            !body.contains(scan),
            "admission contains scan needle {scan:?}"
        );
    }
}

#[test]
fn max_inflight_one_retains_one_owner_across_wire_phases() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(41).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("one slot must admit"));
    let key = admission.key();
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(table.mark_application_visible(key), Ok(admission.req_id()));

    let CaptureToken::Application(token) = table
        .begin_capture(41, cq_kind::COMPLETION, admission.req_id())
        .expect("visible identity captures")
    else {
        panic!("application identity must return application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("detached token returns to its table"));
    assert_eq!(
        table
            .retain_application(captured)
            .unwrap_or_else(|_| panic!("first phase retains")),
        key
    );

    let second = table
        .begin_application_phase(
            key,
            ApplicationPhase::new(op::WRITE).expect("application phase"),
        )
        .expect("retained phase rotates");
    assert_eq!(second.slot_index(), admission.req_id().slot_index());
    assert_eq!(second.generation(), 2);
    assert_eq!(table.mark_application_visible(key), Ok(second));
    let CaptureToken::Application(token) = table
        .begin_capture(41, cq_kind::COMPLETION, second)
        .expect("second phase captures")
    else {
        panic!("application identity must return application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("second detached token installs"));
    assert_eq!(
        table
            .retain_application(captured)
            .unwrap_or_else(|_| panic!("second phase retains")),
        key
    );

    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(completed.load(Ordering::Relaxed), 0);
    assert_eq!(table.free_head, None);
    assert!(matches!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Live {
            birth_session_epoch,
            birth_generation: 1,
            req_id,
            wire_state: WireState::BetweenPhases,
            ..
        } if birth_session_epoch.get() == 41 && req_id.generation() == 2
    ));
}

#[test]
fn foreign_and_stale_keys_preserve_state() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut app_a, mut system_a, mut global_a) = backing::<1, 3>();
    let (mut app_b, mut system_b, mut global_b) = backing::<1, 3>();
    let mut table_a = RequestTable::try_new(
        NonZeroU64::new(51).expect("nonzero"),
        topology,
        &mut app_a,
        &mut system_a,
        &mut global_a,
    )
    .expect("table A");
    let mut table_b = RequestTable::try_new(
        NonZeroU64::new(51).expect("nonzero"),
        topology,
        &mut app_b,
        &mut system_b,
        &mut global_b,
    )
    .expect("table B");
    let owner = || {
        CompletionOwner::new(CountingSink {
            pended: pended.clone(),
            completed: completed.clone(),
        })
    };
    let phase = ApplicationPhase::new(op::READ).expect("application phase");
    let admission_a = table_a
        .admit_application(phase, owner())
        .unwrap_or_else(|_| panic!("table A admits"));
    let admission_b = table_b
        .admit_application(phase, owner())
        .unwrap_or_else(|_| panic!("table B admits"));
    let before = (
        application_entry_snapshot(&table_a, 0),
        table_a.free_head,
        pended.load(Ordering::Relaxed),
        completed.load(Ordering::Relaxed),
    );
    assert_eq!(
        table_a.mark_application_visible(admission_b.key()),
        Err(ApplicationError::Key(KeyError::ForeignTable))
    );
    assert_eq!(
        (
            application_entry_snapshot(&table_a, 0),
            table_a.free_head,
            pended.load(Ordering::Relaxed),
            completed.load(Ordering::Relaxed),
        ),
        before
    );
    // `validate_application_key`'s birth check is a two-part conjunction, so
    // each conjunct gets its own key that drifts in exactly one field.
    for stale in [
        ApplicationKey {
            birth_generation: admission_a.key().birth_generation + 1,
            ..admission_a.key()
        },
        ApplicationKey {
            birth_session_epoch: NonZeroU64::new(admission_a.key().birth_session_epoch.get() + 1)
                .expect("nonzero"),
            ..admission_a.key()
        },
    ] {
        assert_eq!(
            table_a.mark_application_visible(stale),
            Err(ApplicationError::Key(KeyError::StaleBirth))
        );
        assert_eq!(
            (
                application_entry_snapshot(&table_a, 0),
                table_a.free_head,
                pended.load(Ordering::Relaxed),
                completed.load(Ordering::Relaxed),
            ),
            before
        );
    }
    assert_eq!(
        table_a.mark_application_visible(admission_a.key()),
        Ok(admission_a.req_id())
    );

    let (mut app_a, mut system_a, mut global_a) = control_backing::<1, 3>();
    let (mut app_b, mut system_b, mut global_b) = control_backing::<1, 3>();
    let mut table_a = RequestTable::try_new(
        NonZeroU64::new(52).expect("nonzero"),
        topology,
        &mut app_a,
        &mut system_a,
        &mut global_a,
    )
    .expect("control table A");
    let mut table_b = RequestTable::try_new(
        NonZeroU64::new(52).expect("nonzero"),
        topology,
        &mut app_b,
        &mut system_b,
        &mut global_b,
    )
    .expect("control table B");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control_a = table_a
        .admit_control(lane, ControlPhase::PtRouteAck, 101)
        .unwrap_or_else(|_| panic!("control A admits"));
    let control_b = table_b
        .admit_control(lane, ControlPhase::PtRouteAck, 202)
        .unwrap_or_else(|_| panic!("control B admits"));
    let before = system_control_snapshot(&table_a, 1);
    assert_eq!(
        table_a.mark_control_visible(control_b.key()),
        Err(ControlError::Key(KeyError::ForeignTable))
    );
    assert_eq!(system_control_snapshot(&table_a, 1), before);
    // Same conjunction, same rule: one key per conjunct of
    // `validate_control_key`'s birth check.
    for stale in [
        ControlKey {
            birth_session_epoch: NonZeroU64::new(53).expect("nonzero"),
            ..control_a.key()
        },
        ControlKey {
            birth_generation: control_a.key().birth_generation + 1,
            ..control_a.key()
        },
    ] {
        assert_eq!(
            table_a.mark_control_visible(stale),
            Err(ControlError::Key(KeyError::StaleBirth))
        );
        assert_eq!(system_control_snapshot(&table_a, 1), before);
    }
    assert_eq!(
        table_a.mark_control_visible(control_a.key()),
        Ok(control_a.req_id())
    );
}

/// Design section 3.3: "The birth epoch prevents a fresh-session reset to
/// generation one from colliding with a prior occupant. A stale copied key
/// therefore cannot act on a later occupant of the same slot." Signal 7 states
/// the same rule unqualified.
///
/// The synthetic keys above pin each conjunct in isolation; this pins the
/// hazard the rule exists for, built only from the public API. A cross-epoch
/// receipt reclaim resets the slot generation to zero, so the fresh occupant
/// is re-born at generation one in the *next* epoch and collides with the dead
/// operation's key on table, slot and generation -- the birth epoch is the
/// sole discriminator, on every consumer of `validate_application_key`.
#[test]
fn stale_application_key_cannot_act_on_a_later_epoch_occupant() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(261).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let dead = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("first epoch admits"));
    let receipt = table
        .withdraw_unpublished_application(dead.key())
        .expect("application terminalizes")
        .complete(clearance(&empty_context()), 0, 0);
    table.begin_fence().expect("active table fences");
    table
        .rebind_session(NonZeroU64::new(262).expect("nonzero"), topology)
        .expect("terminal records may straddle rebind");
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("old-epoch receipt reclaims"));
    let live = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("fresh epoch re-admits the slot"));

    // The collision is real: the two keys agree everywhere but the birth epoch.
    assert_eq!(dead.key().slot_index, live.key().slot_index);
    assert_eq!(dead.key().table_id, live.key().table_id);
    assert_eq!(dead.key().birth_generation, live.key().birth_generation);
    assert_ne!(
        dead.key().birth_session_epoch,
        live.key().birth_session_epoch
    );

    let before = (
        application_entry_snapshot(&table, 0),
        table.free_head,
        pended.load(Ordering::Relaxed),
        completed.load(Ordering::Relaxed),
    );
    assert_eq!(
        table.mark_application_visible(dead.key()),
        Err(ApplicationError::Key(KeyError::StaleBirth))
    );
    assert_eq!(
        table.record_cancel(dead.key()),
        Err(ApplicationError::Key(KeyError::StaleBirth))
    );
    assert_eq!(
        table.begin_application_phase(
            dead.key(),
            ApplicationPhase::new(op::READ).expect("application phase")
        ),
        Err(ApplicationError::Key(KeyError::StaleBirth))
    );
    // The dangerous one: this hands out the occupant's completion capability.
    assert!(matches!(
        table.withdraw_unpublished_application(dead.key()),
        Err(ApplicationError::Key(KeyError::StaleBirth))
    ));
    assert_eq!(
        (
            application_entry_snapshot(&table, 0),
            table.free_head,
            pended.load(Ordering::Relaxed),
            completed.load(Ordering::Relaxed),
        ),
        before
    );
    // The live occupant is untouched and still drivable by its own key.
    assert_eq!(
        table.mark_application_visible(live.key()),
        Ok(live.req_id())
    );
}

/// The control mirror of the rule above, and it needs no rebind: a same-epoch
/// reclaim leaves the lane available at its last generation, so the successor
/// continuation is born one generation later and the retired continuation's
/// key collides with it on table, slot, lane and birth epoch. Here the birth
/// generation is the sole discriminator.
#[test]
fn stale_control_key_cannot_act_on_a_later_generation_occupant() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(263).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let dead = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0xAAAA)
        .unwrap_or_else(|_| panic!("control admits"));
    let (continuation, release) = table
        .withdraw_unpublished_control(dead.key())
        .expect("control terminalizes")
        .release();
    assert_eq!(continuation, 0xAAAA);
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("same-epoch release reclaims"));
    let live = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0xBBBB)
        .unwrap_or_else(|_| panic!("lane re-admits in the same epoch"));

    assert_eq!(dead.key().slot_index, live.key().slot_index);
    assert_eq!(dead.key().table_id, live.key().table_id);
    assert_eq!(dead.key().lane, live.key().lane);
    assert_eq!(
        dead.key().birth_session_epoch,
        live.key().birth_session_epoch
    );
    assert_ne!(dead.key().birth_generation, live.key().birth_generation);

    let before = system_control_snapshot(&table, 1);
    assert_eq!(
        table.mark_control_visible(dead.key()),
        Err(ControlError::Key(KeyError::StaleBirth))
    );
    assert!(matches!(
        table.withdraw_unpublished_control(dead.key()),
        Err(ControlError::Key(KeyError::StaleBirth))
    ));
    assert_eq!(system_control_snapshot(&table, 1), before);
    assert_eq!(table.mark_control_visible(live.key()), Ok(live.req_id()));
}

#[test]
fn capture_error_matrix_is_distinct_and_state_preserving() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 2).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(61).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("application admits"));

    let before_nonvisible = counting_application_observation(&table, 0, &pended, &completed);
    assert!(matches!(
        table.begin_capture(61, cq_kind::COMPLETION, admission.req_id()),
        Err(CaptureError::NotVisible)
    ));
    assert_eq!(
        counting_application_observation(&table, 0, &pended, &completed),
        before_nonvisible
    );
    assert_eq!(
        table.mark_application_visible(admission.key()),
        Ok(admission.req_id())
    );

    for (observed_epoch, req_id, expected) in [
        (62, admission.req_id(), CaptureError::WrongSession),
        (61, ReqId::from_raw(0), CaptureError::ZeroRequestId),
        (61, ReqId::from_raw(1), CaptureError::ZeroGeneration),
        (
            61,
            ReqId::try_new(1, 2).expect("representable unassigned identity"),
            CaptureError::UnassignedIndex,
        ),
        (
            61,
            ReqId::try_new(1, 1).expect("representable vacant identity"),
            CaptureError::Vacant,
        ),
        (
            61,
            ReqId::try_new(2, 0).expect("representable stale identity"),
            CaptureError::StaleCurrentGeneration,
        ),
    ] {
        let before = counting_application_observation(&table, 0, &pended, &completed);
        assert!(
            matches!(
                table.begin_capture(observed_epoch, cq_kind::COMPLETION, req_id),
                Err(error) if error == expected
            ),
            "expected {expected:?}"
        );
        assert_eq!(
            counting_application_observation(&table, 0, &pended, &completed),
            before,
            "{expected:?} mutated the live entry or sink"
        );
    }

    table
        .application
        .get_mut(1)
        .expect("second application slot")
        .state = ApplicationSlotState::Retired { generation: 1 };
    let retired_before = application_entry_snapshot(&table, 1);
    assert!(matches!(
        table.begin_capture(
            61,
            cq_kind::COMPLETION,
            ReqId::try_new(1, 1).expect("retired identity")
        ),
        Err(CaptureError::Retired)
    ));
    assert_eq!(application_entry_snapshot(&table, 1), retired_before);

    let token = match table
        .begin_capture(61, cq_kind::COMPLETION, admission.req_id())
        .expect("visible identity captures")
    {
        CaptureToken::Application(token) => token,
        CaptureToken::Control(_) => panic!("application identity"),
    };
    let capturing_before = counting_application_observation(&table, 0, &pended, &completed);
    assert!(matches!(
        table.begin_capture(61, cq_kind::COMPLETION, admission.req_id()),
        Err(CaptureError::CaptureInProgress)
    ));
    assert_eq!(
        counting_application_observation(&table, 0, &pended, &completed),
        capturing_before
    );
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("token installs"));
    let captured_before = counting_application_observation(&table, 0, &pended, &completed);
    assert!(matches!(
        table.begin_capture(61, cq_kind::COMPLETION, admission.req_id()),
        Err(CaptureError::CandidateInstalled)
    ));
    assert_eq!(
        counting_application_observation(&table, 0, &pended, &completed),
        captured_before
    );
    assert!(table.retain_application(captured).is_ok());
}

#[test]
fn wrong_kind_capture_is_restricted_to_journaled_semantic_identity() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    // 02-transport.md section 8.2 names NOTIFY and PROTOCOL together, so both
    // wrong kinds must take the identical path on both sides of the rule.
    const WRONG_KINDS: [u16; 2] = [cq_kind::PROTOCOL, cq_kind::NOTIFY];
    let topology = RequestTopology::try_new(1, 3).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<3, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(71).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let completion_only = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("completion-only admission"));
    table
        .mark_application_visible(completion_only.key())
        .expect("visibility");
    let before = application_entry_snapshot(&table, 0);
    for kind in WRONG_KINDS {
        assert!(
            matches!(
                table.begin_capture(71, kind, completion_only.req_id()),
                Err(CaptureError::WrongKindCaptureRole)
            ),
            "completion-only identity must reject wrong kind {kind}"
        );
        assert_eq!(application_entry_snapshot(&table, 0), before);
    }

    for kind in WRONG_KINDS {
        let journaled = table
            .admit_application(
                ApplicationPhase::journaled_semantic(op::WRITE).expect("journaled phase"),
                CompletionOwner::new(CountingSink {
                    pended: pended.clone(),
                    completed: completed.clone(),
                }),
            )
            .unwrap_or_else(|_| panic!("journaled admission"));
        table
            .mark_application_visible(journaled.key())
            .expect("visibility");
        assert!(
            matches!(
                table.begin_capture(71, kind, journaled.req_id()),
                Ok(CaptureToken::Application(_))
            ),
            "journaled semantic identity must capture wrong kind {kind}"
        );
    }

    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut control_table = RequestTable::try_new(
        NonZeroU64::new(72).expect("nonzero"),
        RequestTopology::try_new(1, 1).expect("valid topology"),
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("control table");
    let control = control_table
        .admit_control(
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
            55,
        )
        .unwrap_or_else(|_| panic!("control admission"));
    control_table
        .mark_control_visible(control.key())
        .expect("control visibility");
    let before = system_control_snapshot(&control_table, 1);
    for kind in WRONG_KINDS {
        assert!(
            matches!(
                control_table.begin_capture(72, kind, control.req_id()),
                Err(CaptureError::WrongKindCaptureRole)
            ),
            "a control lane has no journaled semantic role for kind {kind}"
        );
        assert_eq!(system_control_snapshot(&control_table, 1), before);
    }
}

#[test]
fn wrong_kind_and_opcode_journaled_identity_stays_captured() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(81).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::journaled_semantic(op::WRITE).expect("journaled phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admission"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let token = table
        .begin_capture(81, cq_kind::PROTOCOL, admission.req_id())
        .expect("wrong kind captures exact journaled identity");
    assert_eq!(token.req_id(), admission.req_id());
    assert_eq!(token.expected_opcode(), op::WRITE);
    assert_eq!(
        token.validate_envelope(cq_kind::PROTOCOL, op::READ),
        Err(EnvelopeError::WrongKind)
    );
    assert_eq!(
        token.validate_envelope(cq_kind::COMPLETION, op::READ),
        Err(EnvelopeError::WrongOpcode)
    );
    assert_eq!(
        token.validate_envelope(cq_kind::COMPLETION, op::WRITE),
        Ok(())
    );
    assert!(matches!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Live {
            wire_state: WireState::Capturing,
            ..
        }
    ));
    let CaptureToken::Application(token) = token else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("invalid envelope still installs candidate"));
    assert!(matches!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Live {
            wire_state: WireState::Captured,
            ..
        }
    ));
    assert!(table.retain_application(captured).is_ok());
}

#[test]
fn detached_capture_token_is_rechecked_before_install() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let (mut foreign_application, mut foreign_system, mut foreign_global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(91).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let foreign_table = RequestTable::try_new(
        NonZeroU64::new(91).expect("nonzero"),
        topology,
        &mut foreign_application,
        &mut foreign_system,
        &mut foreign_global,
    )
    .expect("foreign table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admission"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(91, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application token");
    };
    let variants = [
        (
            ApplicationCapture {
                table_id: foreign_table.table_id,
                ..copy_application_capture(&token)
            },
            CaptureFinishError::ForeignTable,
        ),
        (
            ApplicationCapture {
                slot_index: SYSTEM_REQID_BASE,
                req_id: ReqId::try_new(1, SYSTEM_REQID_BASE).expect("system identity"),
                ..copy_application_capture(&token)
            },
            CaptureFinishError::WrongClass,
        ),
        (
            ApplicationCapture {
                req_id: ReqId::try_new(1, SYSTEM_REQID_BASE).expect("mismatched identity"),
                ..copy_application_capture(&token)
            },
            CaptureFinishError::WrongClass,
        ),
        (
            ApplicationCapture {
                birth_session_epoch: NonZeroU64::new(92).expect("nonzero"),
                ..copy_application_capture(&token)
            },
            CaptureFinishError::StaleBirth,
        ),
        (
            ApplicationCapture {
                birth_generation: token.birth_generation + 1,
                ..copy_application_capture(&token)
            },
            CaptureFinishError::StaleBirth,
        ),
        (
            ApplicationCapture {
                wire_session_epoch: NonZeroU64::new(92).expect("nonzero"),
                ..copy_application_capture(&token)
            },
            CaptureFinishError::StaleWireIdentity,
        ),
        (
            ApplicationCapture {
                req_id: ReqId::try_new(2, token.slot_index).expect("stale generation"),
                ..copy_application_capture(&token)
            },
            CaptureFinishError::StaleWireIdentity,
        ),
        (
            ApplicationCapture {
                expected_opcode: op::WRITE,
                ..copy_application_capture(&token)
            },
            CaptureFinishError::StaleWireIdentity,
        ),
    ];
    for (variant, expected) in variants {
        let before = application_entry_snapshot(&table, 0);
        let expected_token = application_capture_snapshot(&variant);
        let error = match table.install_application_candidate(variant) {
            Ok(_) => panic!("mutated token must be rejected: {expected:?}"),
            Err(error) => error,
        };
        assert_eq!(error.error(), &expected);
        let (actual, returned) = error.into_parts();
        assert_eq!(actual, expected);
        assert_eq!(application_capture_snapshot(&returned), expected_token);
        assert_eq!(application_entry_snapshot(&table, 0), before);
    }

    let duplicate = copy_application_capture(&token);
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("exact token installs"));
    let before = application_entry_snapshot(&table, 0);
    let wrong_state = match table.install_application_candidate(duplicate) {
        Ok(_) => panic!("Captured is not Capturing"),
        Err(error) => error,
    };
    assert_eq!(wrong_state.error(), &CaptureFinishError::WrongState);
    assert_eq!(application_entry_snapshot(&table, 0), before);
    assert!(table.retain_application(captured).is_ok());

    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut short_table = RequestTable::try_new(
        NonZeroU64::new(93).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("short table");
    let admission = short_table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: std::sync::Arc::new(AtomicU32::new(0)),
                completed: std::sync::Arc::new(AtomicU32::new(0)),
            }),
        )
        .unwrap_or_else(|_| panic!("admission"));
    short_table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let CaptureToken::Application(token) = short_table
        .begin_capture(93, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application token");
    };
    short_table.topology.max_inflight = 2;
    let out_of_range = ApplicationCapture {
        slot_index: 1,
        req_id: ReqId::try_new(1, 1).expect("application class under widened topology"),
        ..copy_application_capture(&token)
    };
    let error = match short_table.install_application_candidate(out_of_range) {
        Ok(_) => panic!("missing backing index must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &CaptureFinishError::SlotOutOfRange);

    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let (mut foreign_application, mut foreign_system, mut foreign_global) =
        control_backing::<1, 3>();
    let mut control_table = RequestTable::try_new(
        NonZeroU64::new(94).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("control table");
    let foreign_control_table = RequestTable::try_new(
        NonZeroU64::new(94).expect("nonzero"),
        topology,
        &mut foreign_application,
        &mut foreign_system,
        &mut foreign_global,
    )
    .expect("foreign control table");
    let control = control_table
        .admit_control(
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
            0x5eed,
        )
        .unwrap_or_else(|_| panic!("control admission"));
    control_table
        .mark_control_visible(control.key())
        .expect("control visibility");
    let CaptureToken::Control(control_token) = control_table
        .begin_capture(94, cq_kind::COMPLETION, control.req_id())
        .expect("control capture")
    else {
        panic!("control token");
    };
    let control_variants = [
        (
            ControlCapture {
                table_id: foreign_control_table.table_id,
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::ForeignTable,
        ),
        (
            ControlCapture {
                slot_index: 0,
                req_id: ReqId::try_new(1, 0).expect("application identity"),
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::WrongClass,
        ),
        (
            ControlCapture {
                req_id: ReqId::try_new(1, SYSTEM_REQID_BASE + 1)
                    .expect("mismatched control identity"),
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::WrongClass,
        ),
        (
            ControlCapture {
                lane: ControlLane::PtRouteAck { ring_index: 0 },
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::WrongClass,
        ),
        (
            ControlCapture {
                birth_session_epoch: NonZeroU64::new(95).expect("nonzero"),
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::StaleBirth,
        ),
        (
            ControlCapture {
                birth_generation: control_token.birth_generation + 1,
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::StaleBirth,
        ),
        (
            ControlCapture {
                wire_session_epoch: NonZeroU64::new(95).expect("nonzero"),
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::StaleWireIdentity,
        ),
        (
            ControlCapture {
                req_id: ReqId::try_new(2, control_token.slot_index)
                    .expect("stale control generation"),
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::StaleWireIdentity,
        ),
        (
            ControlCapture {
                expected_opcode: op::CLOSE,
                ..copy_control_capture(&control_token)
            },
            CaptureFinishError::StaleWireIdentity,
        ),
    ];
    for (variant, expected) in control_variants {
        let before = system_control_snapshot(&control_table, 0);
        let expected_token = control_capture_snapshot(&variant);
        let error = match control_table.install_control_candidate(variant) {
            Ok(_) => panic!("mutated control token must be rejected: {expected:?}"),
            Err(error) => error,
        };
        assert_eq!(error.error(), &expected);
        let (actual, returned) = error.into_parts();
        assert_eq!(actual, expected);
        assert_eq!(control_capture_snapshot(&returned), expected_token);
        assert_eq!(system_control_snapshot(&control_table, 0), before);
    }

    let ControlSlotState::Occupied { lane, .. } = &mut control_table
        ._system
        .get_mut(0)
        .expect("open-lifecycle backing")
        .state
    else {
        panic!("occupied control slot");
    };
    *lane = ControlLane::PtRouteAck { ring_index: 0 };
    let before = system_control_snapshot(&control_table, 0);
    let variant = copy_control_capture(&control_token);
    let expected_token = control_capture_snapshot(&variant);
    let error = match control_table.install_control_candidate(variant) {
        Ok(_) => panic!("journaled lane mismatch must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &CaptureFinishError::StaleBirth);
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, CaptureFinishError::StaleBirth);
    assert_eq!(control_capture_snapshot(&returned), expected_token);
    assert_eq!(system_control_snapshot(&control_table, 0), before);
    let ControlSlotState::Occupied { lane, .. } = &mut control_table
        ._system
        .get_mut(0)
        .expect("open-lifecycle backing")
        .state
    else {
        panic!("occupied control slot");
    };
    *lane = ControlLane::OpenLifecycle { ring_index: 0 };

    let duplicate = copy_control_capture(&control_token);
    let captured = control_table
        .install_control_candidate(control_token)
        .unwrap_or_else(|_| panic!("exact control token installs"));
    let before = system_control_snapshot(&control_table, 0);
    let wrong_state = match control_table.install_control_candidate(duplicate) {
        Ok(_) => panic!("Captured is not Capturing"),
        Err(error) => error,
    };
    assert_eq!(wrong_state.error(), &CaptureFinishError::WrongState);
    assert_eq!(system_control_snapshot(&control_table, 0), before);
    assert!(control_table.retain_control(captured).is_ok());

    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut short_control_table = RequestTable::try_new(
        NonZeroU64::new(96).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("short control table");
    let control = short_control_table
        .admit_control(
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
            0x5eed,
        )
        .unwrap_or_else(|_| panic!("control admission"));
    short_control_table
        .mark_control_visible(control.key())
        .expect("control visibility");
    let CaptureToken::Control(control_token) = short_control_table
        .begin_capture(96, cq_kind::COMPLETION, control.req_id())
        .expect("control capture")
    else {
        panic!("control token");
    };
    short_control_table.topology.ring_count = 2;
    let out_of_range = ControlCapture {
        slot_index: SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING,
        lane: ControlLane::OpenLifecycle { ring_index: 1 },
        req_id: ReqId::try_new(1, SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING)
            .expect("control class under widened topology"),
        ..copy_control_capture(&control_token)
    };
    let error = match short_control_table.install_control_candidate(out_of_range) {
        Ok(_) => panic!("missing control backing index must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &CaptureFinishError::SlotOutOfRange);
}

#[test]
fn capture_compares_generation_bit_39() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(101).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admission"));
    let generation_bit_39 = 1_u64 << 39;
    let current_generation = generation_bit_39 | 1;
    let current_req_id =
        ReqId::try_new(current_generation, 0).expect("40-bit generation is representable");
    let slot = table.application.get_mut(0).expect("one application slot");
    let ApplicationSlotState::Live {
        req_id, wire_state, ..
    } = &mut slot.state
    else {
        panic!("live application");
    };
    *req_id = current_req_id;
    *wire_state = WireState::Visible;

    let before = application_entry_snapshot(&table, 0);
    assert!(matches!(
        table.begin_capture(
            101,
            cq_kind::COMPLETION,
            ReqId::try_new(1, 0).expect("same low 39 bits")
        ),
        Err(CaptureError::StaleCurrentGeneration)
    ));
    assert_eq!(application_entry_snapshot(&table, 0), before);
    assert!(matches!(
        table.begin_capture(101, cq_kind::COMPLETION, current_req_id),
        Ok(CaptureToken::Application(_))
    ));
    assert_eq!(admission.req_id().generation(), 1);
}

#[test]
fn pcancel_target_matrix_is_exact_and_observational() {
    let phases = [
        op::PREPARE_OPEN,
        op::COMMIT_OPEN,
        op::ABORT_OPEN,
        op::CLEANUP,
        op::CLOSE,
        op::READ,
        op::WRITE,
        op::FLUSH,
        op::QUERY_INFO,
        op::MUTATE,
        op::QUERY_DIR,
        op::QUERY_VOLUME,
        op::QUERY_SECURITY,
        op::QUERY_OP,
        op::ACK_RESULT,
    ];
    for opcode in phases {
        let pended = std::sync::Arc::new(AtomicU32::new(0));
        let completed = std::sync::Arc::new(AtomicU32::new(0));
        let topology = RequestTopology::try_new(1, 2).expect("valid topology");
        let (mut application, mut system, mut global) = backing::<2, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(111).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        let admission = table
            .admit_application(
                ApplicationPhase::new(opcode).expect("registered application phase"),
                CompletionOwner::new(CountingSink {
                    pended: pended.clone(),
                    completed: completed.clone(),
                }),
            )
            .unwrap_or_else(|_| panic!("admission"));
        table.record_cancel(admission.key()).expect("cancel intent");
        assert_eq!(
            table.pcancel_target(admission.key()),
            Ok(None),
            "prepared phase is not visible for opcode {opcode:#06x}"
        );
        table
            .mark_application_visible(admission.key())
            .expect("visibility");
        let before = (
            counting_application_observation(&table, 0, &pended, &completed),
            application_entry_snapshot(&table, 1),
        );
        let target = table
            .pcancel_target(admission.key())
            .expect("valid application key");
        let eligible = !matches!(opcode, op::PREPARE_OPEN | op::QUERY_OP | op::ACK_RESULT);
        assert_eq!(
            target.map(|target| (target.req_id(), target.session_epoch().get())),
            eligible.then_some((admission.req_id(), 111)),
            "opcode {opcode:#06x}"
        );
        assert_eq!(
            (
                counting_application_observation(&table, 0, &pended, &completed),
                application_entry_snapshot(&table, 1),
            ),
            before,
            "target derivation mutated identity, intent, free link, owner, or sink"
        );
    }

    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(112).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admission"));
    let key = admission.key();
    table.record_cancel(key).expect("cancel intent");
    table.mark_application_visible(key).expect("visibility");
    assert!(table.pcancel_target(key).expect("key").is_some());
    let CaptureToken::Application(token) = table
        .begin_capture(112, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application token");
    };
    assert_eq!(table.pcancel_target(key), Ok(None));
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    assert_eq!(table.pcancel_target(key), Ok(None));
    table
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("retain"));
    assert_eq!(table.pcancel_target(key), Ok(None));
    let second = table
        .begin_application_phase(
            key,
            ApplicationPhase::new(op::ABORT_OPEN).expect("eligible abort phase"),
        )
        .expect("next phase");
    assert_eq!(table.pcancel_target(key), Ok(None));
    table.mark_application_visible(key).expect("visibility");
    assert_eq!(
        table
            .pcancel_target(key)
            .expect("key")
            .map(|target| (target.req_id(), target.session_epoch().get())),
        Some((second, 112))
    );
    let CaptureToken::Application(token) = table
        .begin_capture(112, cq_kind::COMPLETION, second)
        .expect("capture")
    else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let quarantined_key = table
        .quarantine_application(captured)
        .unwrap_or_else(|_| panic!("quarantine"));
    assert_eq!(quarantined_key, key);
    assert_eq!(table.pcancel_target(key), Ok(None));
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(completed.load(Ordering::Relaxed), 0);
}

#[test]
fn captured_application_and_control_have_exact_retention_and_quarantine_paths() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application_a, mut system_a, mut global_a) = backing::<1, 3>();
    let (mut application_b, mut system_b, mut global_b) = backing::<1, 3>();
    let mut table_a = RequestTable::try_new(
        NonZeroU64::new(121).expect("nonzero"),
        topology,
        &mut application_a,
        &mut system_a,
        &mut global_a,
    )
    .expect("table A");
    let mut table_b = RequestTable::try_new(
        NonZeroU64::new(121).expect("nonzero"),
        topology,
        &mut application_b,
        &mut system_b,
        &mut global_b,
    )
    .expect("table B");
    let admission = table_a
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admission"));
    let key = admission.key();
    table_a.mark_application_visible(key).expect("visibility");
    let CaptureToken::Application(token) = table_a
        .begin_capture(121, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application token");
    };
    let captured = table_a
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let captured_snapshot = (
        captured.table_id,
        captured.slot_index,
        captured.birth_session_epoch,
        captured.birth_generation,
        captured.wire_session_epoch,
        captured.req_id,
    );
    let preserved = match table_b.retain_application(captured) {
        Ok(_) => panic!("foreign table cannot consume capture"),
        Err(error) => error,
    };
    assert_eq!(
        preserved.error(),
        &ApplicationError::Key(KeyError::ForeignTable)
    );
    let (_, captured) = preserved.into_parts();
    assert_eq!(
        (
            captured.table_id,
            captured.slot_index,
            captured.birth_session_epoch,
            captured.birth_generation,
            captured.wire_session_epoch,
            captured.req_id,
        ),
        captured_snapshot
    );
    let returned_key = table_a
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("rightful table retains"));
    assert_eq!(returned_key, key);
    let second = table_a
        .begin_application_phase(
            key,
            ApplicationPhase::new(op::WRITE).expect("application phase"),
        )
        .expect("next phase");
    table_a.mark_application_visible(key).expect("visibility");
    let CaptureToken::Application(token) = table_a
        .begin_capture(121, cq_kind::COMPLETION, second)
        .expect("capture")
    else {
        panic!("application token");
    };
    let captured = table_a
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let duplicate = copy_captured_application(&captured);
    assert_eq!(
        table_a
            .quarantine_application(captured)
            .unwrap_or_else(|_| panic!("quarantine")),
        key
    );
    assert!(matches!(
        application_entry_snapshot(&table_a, 0),
        ApplicationEntrySnapshot::Live {
            wire_state: WireState::Quarantined,
            ..
        }
    ));
    assert_eq!(
        table_a.begin_application_phase(
            key,
            ApplicationPhase::new(op::FLUSH).expect("application phase")
        ),
        Err(ApplicationError::Phase(PhaseError::WrongState))
    );
    let preserved = match table_a.retain_application(duplicate) {
        Ok(_) => panic!("quarantine rejects second disposition"),
        Err(error) => error,
    };
    assert_eq!(
        preserved.error(),
        &ApplicationError::Phase(PhaseError::WrongState)
    );
    assert_eq!(copy_captured_application(preserved.value()).req_id, second);

    let (mut application_a, mut system_a, mut global_a) = control_backing::<1, 3>();
    let (mut application_b, mut system_b, mut global_b) = control_backing::<1, 3>();
    let mut table_a = RequestTable::try_new(
        NonZeroU64::new(122).expect("nonzero"),
        topology,
        &mut application_a,
        &mut system_a,
        &mut global_a,
    )
    .expect("control table A");
    let mut table_b = RequestTable::try_new(
        NonZeroU64::new(122).expect("nonzero"),
        topology,
        &mut application_b,
        &mut system_b,
        &mut global_b,
    )
    .expect("control table B");
    let lane = ControlLane::OpenLifecycle { ring_index: 0 };
    let control = table_a
        .admit_control(lane, ControlPhase::ReplayOpen, 0x1234)
        .unwrap_or_else(|_| panic!("control admission"));
    let key = control.key();
    table_a.mark_control_visible(key).expect("visibility");
    let CaptureToken::Control(token) = table_a
        .begin_capture(122, cq_kind::COMPLETION, control.req_id())
        .expect("capture")
    else {
        panic!("control token");
    };
    let captured = table_a
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let preserved = match table_b.retain_control(captured) {
        Ok(_) => panic!("foreign table cannot consume control capture"),
        Err(error) => error,
    };
    assert_eq!(
        preserved.error(),
        &ControlError::Key(KeyError::ForeignTable)
    );
    let (_, captured) = preserved.into_parts();
    assert_eq!(
        table_a
            .retain_control(captured)
            .unwrap_or_else(|_| panic!("retain")),
        key
    );
    let second = table_a
        .begin_control_phase(key, ControlPhase::RecoveryCleanup)
        .expect("control phase rotates");
    assert_eq!(second.generation(), 2);
    table_a.mark_control_visible(key).expect("visibility");
    let CaptureToken::Control(token) = table_a
        .begin_capture(122, cq_kind::COMPLETION, second)
        .expect("capture")
    else {
        panic!("control token");
    };
    let captured = table_a
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let duplicate = copy_captured_control(&captured);
    assert_eq!(
        table_a
            .quarantine_control(captured)
            .unwrap_or_else(|_| panic!("quarantine")),
        key
    );
    assert!(matches!(
        system_control_snapshot(&table_a, 0),
        ControlEntrySnapshot::Occupied {
            continuation: 0x1234,
            phase: ControlPhase::RecoveryCleanup,
            wire_state: WireState::Quarantined,
            ..
        }
    ));
    assert_eq!(
        table_a.begin_control_phase(key, ControlPhase::RecoveryClose),
        Err(ControlError::Phase(PhaseError::WrongState))
    );
    let preserved = match table_a.quarantine_control(duplicate) {
        Ok(_) => panic!("quarantine rejects second control disposition"),
        Err(error) => error,
    };
    assert_eq!(
        preserved.error(),
        &ControlError::Phase(PhaseError::WrongState)
    );
    assert_eq!(copy_captured_control(preserved.value()).req_id, second);
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(completed.load(Ordering::Relaxed), 0);
}

#[test]
fn captured_disposition_failures_preserve_full_affine_values() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let (mut vacant_application, mut vacant_system, mut vacant_global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(131).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("application table");
    let mut vacant_table = RequestTable::try_new(
        NonZeroU64::new(131).expect("nonzero"),
        topology,
        &mut vacant_application,
        &mut vacant_system,
        &mut vacant_global,
    )
    .expect("vacant application table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("application admission"));
    table
        .mark_application_visible(admission.key())
        .expect("application visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(131, cq_kind::COMPLETION, admission.req_id())
        .expect("application capture")
    else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("application install"));
    let application_variants = [
        (
            CapturedApplication {
                table_id: vacant_table.table_id,
                ..copy_captured_application(&captured)
            },
            ApplicationError::Key(KeyError::ForeignTable),
        ),
        (
            CapturedApplication {
                slot_index: SYSTEM_REQID_BASE,
                req_id: ReqId::try_new(1, SYSTEM_REQID_BASE).expect("system identity"),
                ..copy_captured_application(&captured)
            },
            ApplicationError::Key(KeyError::WrongClass),
        ),
        (
            CapturedApplication {
                req_id: ReqId::try_new(1, SYSTEM_REQID_BASE).expect("mismatched identity"),
                ..copy_captured_application(&captured)
            },
            ApplicationError::Key(KeyError::WrongClass),
        ),
        (
            CapturedApplication {
                birth_session_epoch: NonZeroU64::new(132).expect("nonzero"),
                ..copy_captured_application(&captured)
            },
            ApplicationError::Key(KeyError::StaleBirth),
        ),
        (
            CapturedApplication {
                birth_generation: captured.birth_generation + 1,
                ..copy_captured_application(&captured)
            },
            ApplicationError::Key(KeyError::StaleBirth),
        ),
        (
            CapturedApplication {
                wire_session_epoch: NonZeroU64::new(132).expect("nonzero"),
                ..copy_captured_application(&captured)
            },
            ApplicationError::Phase(PhaseError::WrongState),
        ),
        (
            CapturedApplication {
                req_id: ReqId::try_new(2, captured.slot_index)
                    .expect("stale application generation"),
                ..copy_captured_application(&captured)
            },
            ApplicationError::Phase(PhaseError::WrongState),
        ),
    ];
    for (variant, expected) in application_variants {
        let before = application_entry_snapshot(&table, 0);
        let expected_value = captured_application_snapshot(&variant);
        let error = match table.retain_application(variant) {
            Ok(_) => panic!("hostile application capture must be rejected: {expected:?}"),
            Err(error) => error,
        };
        assert_eq!(error.error(), &expected);
        let (actual, returned) = error.into_parts();
        assert_eq!(actual, expected);
        assert_eq!(captured_application_snapshot(&returned), expected_value);
        assert_eq!(application_entry_snapshot(&table, 0), before);
    }

    let vacant_variant = CapturedApplication {
        table_id: vacant_table.table_id,
        ..copy_captured_application(&captured)
    };
    let before = application_entry_snapshot(&vacant_table, 0);
    let expected_value = captured_application_snapshot(&vacant_variant);
    let error = match vacant_table.quarantine_application(vacant_variant) {
        Ok(_) => panic!("vacant application slot must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ApplicationError::Key(KeyError::Vacant));
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ApplicationError::Key(KeyError::Vacant));
    assert_eq!(captured_application_snapshot(&returned), expected_value);
    assert_eq!(application_entry_snapshot(&vacant_table, 0), before);

    table.topology.max_inflight = 2;
    let out_of_range = CapturedApplication {
        slot_index: 1,
        req_id: ReqId::try_new(1, 1).expect("widened application identity"),
        ..copy_captured_application(&captured)
    };
    let before = application_entry_snapshot(&table, 0);
    let expected_value = captured_application_snapshot(&out_of_range);
    let error = match table.retain_application(out_of_range) {
        Ok(_) => panic!("missing application backing must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(
        error.error(),
        &ApplicationError::Key(KeyError::SlotOutOfRange)
    );
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ApplicationError::Key(KeyError::SlotOutOfRange));
    assert_eq!(captured_application_snapshot(&returned), expected_value);
    assert_eq!(application_entry_snapshot(&table, 0), before);
    table.topology.max_inflight = 1;

    let ApplicationSlotState::Live { wire_state, .. } = &mut table
        .application
        .get_mut(0)
        .expect("application backing")
        .state
    else {
        panic!("live application");
    };
    *wire_state = WireState::Visible;
    let variant = copy_captured_application(&captured);
    let before = application_entry_snapshot(&table, 0);
    let expected_value = captured_application_snapshot(&variant);
    let error = match table.quarantine_application(variant) {
        Ok(_) => panic!("non-Captured application must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(
        error.error(),
        &ApplicationError::Phase(PhaseError::WrongState)
    );
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ApplicationError::Phase(PhaseError::WrongState));
    assert_eq!(captured_application_snapshot(&returned), expected_value);
    assert_eq!(application_entry_snapshot(&table, 0), before);
    let ApplicationSlotState::Live { wire_state, .. } = &mut table
        .application
        .get_mut(0)
        .expect("application backing")
        .state
    else {
        panic!("live application");
    };
    *wire_state = WireState::Captured;
    assert!(table.retain_application(captured).is_ok());

    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let (mut vacant_application, mut vacant_system, mut vacant_global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(133).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("control table");
    let mut vacant_table = RequestTable::try_new(
        NonZeroU64::new(133).expect("nonzero"),
        topology,
        &mut vacant_application,
        &mut vacant_system,
        &mut vacant_global,
    )
    .expect("vacant control table");
    let control = table
        .admit_control(
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
            0xcafe,
        )
        .unwrap_or_else(|_| panic!("control admission"));
    table
        .mark_control_visible(control.key())
        .expect("control visibility");
    let CaptureToken::Control(token) = table
        .begin_capture(133, cq_kind::COMPLETION, control.req_id())
        .expect("control capture")
    else {
        panic!("control token");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("control install"));
    let control_variants = [
        (
            CapturedControl {
                table_id: vacant_table.table_id,
                ..copy_captured_control(&captured)
            },
            ControlError::Key(KeyError::ForeignTable),
        ),
        (
            CapturedControl {
                slot_index: SYSTEM_REQID_BASE + 1,
                ..copy_captured_control(&captured)
            },
            ControlError::Key(KeyError::WrongClass),
        ),
        (
            CapturedControl {
                lane: ControlLane::PtRouteAck { ring_index: 0 },
                ..copy_captured_control(&captured)
            },
            ControlError::Key(KeyError::WrongClass),
        ),
        (
            CapturedControl {
                birth_session_epoch: NonZeroU64::new(134).expect("nonzero"),
                ..copy_captured_control(&captured)
            },
            ControlError::Key(KeyError::StaleBirth),
        ),
        (
            CapturedControl {
                birth_generation: captured.birth_generation + 1,
                ..copy_captured_control(&captured)
            },
            ControlError::Key(KeyError::StaleBirth),
        ),
        (
            CapturedControl {
                wire_session_epoch: NonZeroU64::new(134).expect("nonzero"),
                ..copy_captured_control(&captured)
            },
            ControlError::Phase(PhaseError::WrongState),
        ),
        (
            CapturedControl {
                req_id: ReqId::try_new(2, captured.slot_index).expect("stale control generation"),
                ..copy_captured_control(&captured)
            },
            ControlError::Phase(PhaseError::WrongState),
        ),
        (
            CapturedControl {
                req_id: ReqId::try_new(1, SYSTEM_REQID_BASE + 1)
                    .expect("mismatched control identity"),
                ..copy_captured_control(&captured)
            },
            ControlError::Phase(PhaseError::WrongState),
        ),
    ];
    for (variant, expected) in control_variants {
        let before = system_control_snapshot(&table, 0);
        let expected_value = captured_control_snapshot(&variant);
        let error = match table.retain_control(variant) {
            Ok(_) => panic!("hostile control capture must be rejected: {expected:?}"),
            Err(error) => error,
        };
        assert_eq!(error.error(), &expected);
        let (actual, returned) = error.into_parts();
        assert_eq!(actual, expected);
        assert_eq!(captured_control_snapshot(&returned), expected_value);
        assert_eq!(system_control_snapshot(&table, 0), before);
    }

    let ControlSlotState::Occupied { lane, .. } = &mut table
        ._system
        .get_mut(0)
        .expect("open-lifecycle backing")
        .state
    else {
        panic!("occupied control");
    };
    *lane = ControlLane::PtRouteAck { ring_index: 0 };
    let variant = copy_captured_control(&captured);
    let before = system_control_snapshot(&table, 0);
    let expected_value = captured_control_snapshot(&variant);
    let error = match table.quarantine_control(variant) {
        Ok(_) => panic!("journaled control lane mismatch must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ControlError::Key(KeyError::StaleBirth));
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ControlError::Key(KeyError::StaleBirth));
    assert_eq!(captured_control_snapshot(&returned), expected_value);
    assert_eq!(system_control_snapshot(&table, 0), before);
    let ControlSlotState::Occupied { lane, .. } = &mut table
        ._system
        .get_mut(0)
        .expect("open-lifecycle backing")
        .state
    else {
        panic!("occupied control");
    };
    *lane = ControlLane::OpenLifecycle { ring_index: 0 };

    let vacant_variant = CapturedControl {
        table_id: vacant_table.table_id,
        ..copy_captured_control(&captured)
    };
    let before = system_control_snapshot(&vacant_table, 0);
    let expected_value = captured_control_snapshot(&vacant_variant);
    let error = match vacant_table.quarantine_control(vacant_variant) {
        Ok(_) => panic!("vacant control slot must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ControlError::Key(KeyError::Vacant));
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ControlError::Key(KeyError::Vacant));
    assert_eq!(captured_control_snapshot(&returned), expected_value);
    assert_eq!(system_control_snapshot(&vacant_table, 0), before);

    table.topology.ring_count = 2;
    let out_of_range = CapturedControl {
        slot_index: SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING,
        lane: ControlLane::OpenLifecycle { ring_index: 1 },
        req_id: ReqId::try_new(1, SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING)
            .expect("widened control identity"),
        ..copy_captured_control(&captured)
    };
    let before = system_control_snapshot(&table, 0);
    let expected_value = captured_control_snapshot(&out_of_range);
    let error = match table.retain_control(out_of_range) {
        Ok(_) => panic!("missing control backing must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ControlError::Key(KeyError::SlotOutOfRange));
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ControlError::Key(KeyError::SlotOutOfRange));
    assert_eq!(captured_control_snapshot(&returned), expected_value);
    assert_eq!(system_control_snapshot(&table, 0), before);
    table.topology.ring_count = 1;

    let ControlSlotState::Occupied { wire_state, .. } = &mut table
        ._system
        .get_mut(0)
        .expect("open-lifecycle backing")
        .state
    else {
        panic!("occupied control");
    };
    *wire_state = WireState::Visible;
    let variant = copy_captured_control(&captured);
    let before = system_control_snapshot(&table, 0);
    let expected_value = captured_control_snapshot(&variant);
    let error = match table.quarantine_control(variant) {
        Ok(_) => panic!("non-Captured control must reject disposition"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ControlError::Phase(PhaseError::WrongState));
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ControlError::Phase(PhaseError::WrongState));
    assert_eq!(captured_control_snapshot(&returned), expected_value);
    assert_eq!(system_control_snapshot(&table, 0), before);
    let ControlSlotState::Occupied { wire_state, .. } = &mut table
        ._system
        .get_mut(0)
        .expect("open-lifecycle backing")
        .state
    else {
        panic!("occupied control");
    };
    *wire_state = WireState::Captured;
    assert!(table.retain_control(captured).is_ok());
}

#[test]
fn previsibility_withdrawal_terminalizes_without_visibility() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(141).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("one slot admits"));
    assert!(matches!(
        table.begin_capture(141, cq_kind::COMPLETION, admission.req_id()),
        Err(CaptureError::NotVisible)
    ));

    let terminal = table
        .withdraw_unpublished_application(admission.key())
        .expect("the exact unpublished operation withdraws");
    assert_eq!(table.free_head, None);
    assert!(matches!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Terminalizing {
            birth_session_epoch,
            birth_generation: 1,
            terminal_wire_session_epoch,
            terminal_req_id,
        } if birth_session_epoch.get() == 141
            && terminal_wire_session_epoch.get() == 141
            && terminal_req_id == admission.req_id()
    ));
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(completed.load(Ordering::Relaxed), 0);

    let receipt = terminal.complete(clearance(&empty_context()), -1, 0);
    assert_eq!(completed.load(Ordering::Relaxed), 1);
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("matching receipt reclaims"));

    // A hostile key must not cause unpublished withdrawal to scan and select
    // another prepared slot. This separate exact-key probe needs two slots.
    let topology = RequestTopology::try_new(1, 2).expect("two application slots");
    let (mut application, mut system, mut global) = backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(142).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("two-slot table");
    let owner = || {
        CompletionOwner::new(CountingSink {
            pended: pended.clone(),
            completed: completed.clone(),
        })
    };
    let first = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            owner(),
        )
        .unwrap_or_else(|_| panic!("first slot admits"));
    let second = table
        .admit_application(
            ApplicationPhase::new(op::WRITE).expect("application phase"),
            owner(),
        )
        .unwrap_or_else(|_| panic!("second slot admits"));
    let before_first = application_entry_snapshot(&table, 0);
    let before_second = application_entry_snapshot(&table, 1);
    let hostile = ApplicationKey {
        slot_index: second.req_id().slot_index(),
        birth_generation: second.key().birth_generation + 1,
        ..first.key()
    };
    assert!(matches!(
        table.withdraw_unpublished_application(hostile),
        Err(ApplicationError::Key(KeyError::StaleBirth))
    ));
    assert_eq!(application_entry_snapshot(&table, 0), before_first);
    assert_eq!(application_entry_snapshot(&table, 1), before_second);
    let terminal = table
        .withdraw_unpublished_application(second.key())
        .expect("only the addressed slot withdraws");
    assert_eq!(application_entry_snapshot(&table, 0), before_first);
    let receipt = terminal.complete(clearance(&empty_context()), -2, 0);
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("second slot reclaims"));
}

#[test]
fn terminalizing_slot_is_not_reused_until_completion_receipt_reclaim() {
    let events = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let rejected_events = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let mut application = [ApplicationSlot::<OrderedSink>::pristine()];
    let mut system = core::array::from_fn::<_, 3, _>(|_| ControlSlot::<()>::pristine());
    let mut global = ControlSlot::<()>::pristine();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(151).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(OrderedSink {
                events: events.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("one slot admits"));
    assert_eq!(
        events.lock().expect("ordered trace").as_slice(),
        &[CompletionEvent::Pending]
    );

    let full_owner = match table.admit_application(
        ApplicationPhase::new(op::WRITE).expect("application phase"),
        CompletionOwner::new(OrderedSink {
            events: rejected_events.clone(),
        }),
    ) {
        Ok(_) => panic!("max-inflight one is full before completion"),
        Err(error) => {
            assert_eq!(error.error(), &AdmissionError::Full);
            error.into_parts().1
        }
    };
    full_owner.complete(clearance(&empty_context()), -10, 0);
    assert_eq!(
        table.mark_application_visible(admission.key()),
        Ok(admission.req_id())
    );
    let CaptureToken::Application(token) = table
        .begin_capture(151, cq_kind::COMPLETION, admission.req_id())
        .expect("visible completion captures")
    else {
        panic!("application capture token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("capture installs"));
    let terminal = table
        .terminalize_application(captured)
        .unwrap_or_else(|_| panic!("captured application terminalizes"));
    assert_eq!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Terminalizing {
            birth_session_epoch: NonZeroU64::new(151).expect("nonzero"),
            birth_generation: 1,
            terminal_wire_session_epoch: NonZeroU64::new(151).expect("nonzero"),
            terminal_req_id: admission.req_id(),
        }
    );
    assert_eq!(table.free_head, None);

    let full_owner = match table.admit_application(
        ApplicationPhase::new(op::WRITE).expect("application phase"),
        CompletionOwner::new(OrderedSink {
            events: rejected_events.clone(),
        }),
    ) {
        Ok(_) => panic!("terminal wrapper must not free the slot"),
        Err(error) => {
            assert_eq!(error.error(), &AdmissionError::Full);
            error.into_parts().1
        }
    };
    full_owner.complete(clearance(&empty_context()), -11, 0);

    let receipt = terminal.complete(clearance(&empty_context()), -1073741823, 17);
    assert_eq!(
        events.lock().expect("ordered trace").as_slice(),
        &[
            CompletionEvent::Pending,
            CompletionEvent::Completed {
                status: -1073741823,
                information: 17,
            },
        ]
    );
    let full_owner = match table.admit_application(
        ApplicationPhase::new(op::WRITE).expect("application phase"),
        CompletionOwner::new(OrderedSink {
            events: rejected_events.clone(),
        }),
    ) {
        Ok(_) => panic!("completion receipt ownership still reserves the slot"),
        Err(error) => {
            assert_eq!(error.error(), &AdmissionError::Full);
            error.into_parts().1
        }
    };
    full_owner.complete(clearance(&empty_context()), -12, 0);

    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("matching receipt reclaims"));
    let next_events = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let next = table
        .admit_application(
            ApplicationPhase::new(op::WRITE).expect("application phase"),
            CompletionOwner::new(OrderedSink {
                events: next_events.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("slot is reusable only after reclaim"));
    assert_eq!(next.req_id().slot_index(), admission.req_id().slot_index());
    assert_eq!(next.req_id().generation(), 2);
    assert_eq!(
        next_events.lock().expect("next trace").as_slice(),
        &[CompletionEvent::Pending]
    );
    assert_eq!(
        events.lock().expect("ordered trace").as_slice(),
        &[
            CompletionEvent::Pending,
            CompletionEvent::Completed {
                status: -1073741823,
                information: 17,
            },
        ]
    );
}

#[test]
fn reclaim_completed_relinks_existing_free_capacity() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 2).expect("two application slots");
    let (mut application, mut system, mut global) = backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(152).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let owner = || {
        CompletionOwner::new(CountingSink {
            pended: pended.clone(),
            completed: completed.clone(),
        })
    };
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            owner(),
        )
        .unwrap_or_else(|_| panic!("first slot admits"));
    assert_eq!(admission.req_id().slot_index(), 0);
    assert_eq!(table.free_head, Some(1));
    let terminal = table
        .withdraw_unpublished_application(admission.key())
        .expect("unpublished application terminalizes");
    let receipt = terminal.complete(clearance(&empty_context()), 0, 0);
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("matching receipt reclaims"));
    assert_eq!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Free {
            next_free: Some(1),
            generation: 1,
        }
    );
    assert_eq!(table.free_head, Some(0));

    let recycled = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            owner(),
        )
        .unwrap_or_else(|_| panic!("reclaimed slot is first"));
    assert_eq!(recycled.req_id().slot_index(), 0);
    assert_eq!(recycled.req_id().generation(), 2);
    let preexisting = table
        .admit_application(
            ApplicationPhase::new(op::WRITE).expect("application phase"),
            owner(),
        )
        .unwrap_or_else(|_| panic!("pre-existing free slot remains linked"));
    assert_eq!(preexisting.req_id().slot_index(), 1);
    assert_eq!(preexisting.req_id().generation(), 1);
}

#[test]
fn foreign_and_stale_receipts_preserve_terminalizing_state() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut app_a, mut system_a, mut global_a) = backing::<1, 3>();
    let (mut app_b, mut system_b, mut global_b) = backing::<1, 3>();
    let mut table_a = RequestTable::try_new(
        NonZeroU64::new(161).expect("nonzero"),
        topology,
        &mut app_a,
        &mut system_a,
        &mut global_a,
    )
    .expect("table A");
    let mut table_b = RequestTable::try_new(
        NonZeroU64::new(161).expect("nonzero"),
        topology,
        &mut app_b,
        &mut system_b,
        &mut global_b,
    )
    .expect("table B");
    let owner = || {
        CompletionOwner::new(CountingSink {
            pended: pended.clone(),
            completed: completed.clone(),
        })
    };
    let phase = ApplicationPhase::new(op::READ).expect("application phase");
    let admission_a = table_a
        .admit_application(phase, owner())
        .unwrap_or_else(|_| panic!("table A admits"));
    let admission_b = table_b
        .admit_application(phase, owner())
        .unwrap_or_else(|_| panic!("table B admits"));
    let terminal_a = table_a
        .withdraw_unpublished_application(admission_a.key())
        .expect("table A withdraws");
    let terminal_b = table_b
        .withdraw_unpublished_application(admission_b.key())
        .expect("table B withdraws");
    let receipt_a = terminal_a.complete(clearance(&empty_context()), 0, 0);
    let receipt_b = terminal_b.complete(clearance(&empty_context()), 0, 0);
    let terminalizing = application_entry_snapshot(&table_a, 0);

    let receipt_b_snapshot = completion_receipt_snapshot(&receipt_b);
    let error = match table_a.reclaim_completed(receipt_b) {
        Ok(()) => panic!("foreign receipt cannot reclaim"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::ForeignTable);
    let (_, receipt_b) = error.into_parts();
    assert_eq!(completion_receipt_snapshot(&receipt_b), receipt_b_snapshot);
    assert_eq!(application_entry_snapshot(&table_a, 0), terminalizing);
    table_b
        .reclaim_completed(receipt_b)
        .unwrap_or_else(|_| panic!("foreign receipt remains valid at its owner table"));

    let variants = [
        (
            ReclaimError::WrongClass,
            CompletionReceipt {
                slot_index: SYSTEM_REQID_BASE,
                terminal_req_id: ReqId::try_new(
                    receipt_a.terminal_req_id.generation(),
                    SYSTEM_REQID_BASE,
                )
                .expect("system identity"),
                ..copy_completion_receipt(&receipt_a)
            },
        ),
        (
            ReclaimError::WrongClass,
            CompletionReceipt {
                terminal_req_id: ReqId::try_new(
                    receipt_a.terminal_req_id.generation(),
                    receipt_a.slot_index + 1,
                )
                .expect("mismatched application identity"),
                ..copy_completion_receipt(&receipt_a)
            },
        ),
        (
            ReclaimError::StaleBirth,
            CompletionReceipt {
                birth_session_epoch: NonZeroU64::new(receipt_a.birth_session_epoch.get() + 1)
                    .expect("nonzero"),
                ..copy_completion_receipt(&receipt_a)
            },
        ),
        (
            ReclaimError::StaleBirth,
            CompletionReceipt {
                birth_generation: receipt_a.birth_generation + 1,
                ..copy_completion_receipt(&receipt_a)
            },
        ),
        (
            ReclaimError::StaleTerminalIdentity,
            CompletionReceipt {
                terminal_wire_session_epoch: NonZeroU64::new(
                    receipt_a.terminal_wire_session_epoch.get() + 1,
                )
                .expect("nonzero"),
                ..copy_completion_receipt(&receipt_a)
            },
        ),
        (
            ReclaimError::StaleTerminalIdentity,
            CompletionReceipt {
                terminal_req_id: ReqId::try_new(
                    receipt_a.terminal_req_id.generation() + 1,
                    receipt_a.slot_index,
                )
                .expect("next generation"),
                ..copy_completion_receipt(&receipt_a)
            },
        ),
    ];
    for (expected, variant) in variants {
        let snapshot = completion_receipt_snapshot(&variant);
        let error = match table_a.reclaim_completed(variant) {
            Ok(()) => panic!("hostile receipt cannot reclaim: {expected:?}"),
            Err(error) => error,
        };
        assert_eq!(error.error(), &expected);
        let (actual, returned) = error.into_parts();
        assert_eq!(actual, expected);
        assert_eq!(completion_receipt_snapshot(&returned), snapshot);
        assert_eq!(application_entry_snapshot(&table_a, 0), terminalizing);
    }

    let original_topology = table_a.topology;
    table_a.topology = RequestTopology::try_new(1, 2).expect("hostile wider topology");
    let out_of_range = CompletionReceipt {
        slot_index: 1,
        terminal_req_id: ReqId::try_new(receipt_a.terminal_req_id.generation(), 1)
            .expect("application identity"),
        ..copy_completion_receipt(&receipt_a)
    };
    let snapshot = completion_receipt_snapshot(&out_of_range);
    let error = match table_a.reclaim_completed(out_of_range) {
        Ok(()) => panic!("out-of-range receipt cannot reclaim"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::SlotOutOfRange);
    assert_eq!(completion_receipt_snapshot(error.value()), snapshot);
    assert_eq!(application_entry_snapshot(&table_a, 0), terminalizing);
    table_a.topology = original_topology;

    let duplicate = copy_completion_receipt(&receipt_a);
    table_a
        .reclaim_completed(receipt_a)
        .unwrap_or_else(|_| panic!("matching receipt reclaims"));
    let reclaimed = application_entry_snapshot(&table_a, 0);
    let snapshot = completion_receipt_snapshot(&duplicate);
    let error = match table_a.reclaim_completed(duplicate) {
        Ok(()) => panic!("a reclaimed slot is not terminalizing"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::NotTerminalizing);
    assert_eq!(completion_receipt_snapshot(error.value()), snapshot);
    assert_eq!(application_entry_snapshot(&table_a, 0), reclaimed);
}

#[test]
fn control_terminalization_preserves_metadata_and_waits_for_release_reclaim() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut app_a, mut system_a, mut global_a) = control_backing::<1, 3>();
    let (mut app_b, mut system_b, mut global_b) = control_backing::<1, 3>();
    let mut table_a = RequestTable::try_new(
        NonZeroU64::new(171).expect("nonzero"),
        topology,
        &mut app_a,
        &mut system_a,
        &mut global_a,
    )
    .expect("control table A");
    let mut table_b = RequestTable::try_new(
        NonZeroU64::new(171).expect("nonzero"),
        topology,
        &mut app_b,
        &mut system_b,
        &mut global_b,
    )
    .expect("control table B");
    let captured_lane = ControlLane::PtRouteAck { ring_index: 0 };
    let captured_admission = table_a
        .admit_control(captured_lane, ControlPhase::PtRouteAck, 0x1111)
        .unwrap_or_else(|_| panic!("captured lane admits"));
    assert_eq!(
        table_a.mark_control_visible(captured_admission.key()),
        Ok(captured_admission.req_id())
    );
    let CaptureToken::Control(token) = table_a
        .begin_capture(171, cq_kind::COMPLETION, captured_admission.req_id())
        .expect("control captures")
    else {
        panic!("control token");
    };
    let captured = table_a
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("control candidate installs"));
    let terminal = table_a
        .terminalize_control(captured)
        .unwrap_or_else(|_| panic!("captured control terminalizes"));
    assert_eq!(
        system_control_snapshot(&table_a, 1),
        ControlEntrySnapshot::Terminalizing {
            lane: captured_lane,
            birth_session_epoch: NonZeroU64::new(171).expect("nonzero"),
            birth_generation: 1,
            terminal_wire_session_epoch: NonZeroU64::new(171).expect("nonzero"),
            terminal_req_id: captured_admission.req_id(),
            terminal_kind: ControlTerminalKind::Captured,
        }
    );
    assert_eq!(terminal.lane(), captured_lane);
    assert_eq!(terminal.req_id(), captured_admission.req_id());
    assert_eq!(terminal.terminal_kind(), ControlTerminalKind::Captured);
    let busy = match table_a.admit_control(captured_lane, ControlPhase::PtRouteAck, 0x2222) {
        Ok(_) => panic!("terminal control keeps lane busy"),
        Err(error) => error,
    };
    assert_eq!(busy.error(), &ControlAdmissionError::Busy);
    assert_eq!(busy.value(), &0x2222);
    let (continuation, release_a) = terminal.release();
    assert_eq!(continuation, 0x1111);
    let busy = match table_a.admit_control(captured_lane, ControlPhase::PtRouteAck, 0x3333) {
        Ok(_) => panic!("control release ownership keeps lane busy"),
        Err(error) => error,
    };
    assert_eq!(busy.error(), &ControlAdmissionError::Busy);
    assert_eq!(busy.value(), &0x3333);

    let unpublished_lane = ControlLane::OpenLifecycle { ring_index: 0 };
    let unpublished_admission = table_a
        .admit_control(unpublished_lane, ControlPhase::ReplayOpen, 0x4444)
        .unwrap_or_else(|_| panic!("unpublished lane admits"));
    let unpublished = table_a
        .withdraw_unpublished_control(unpublished_admission.key())
        .expect("exact unpublished control withdraws");
    assert_eq!(
        system_control_snapshot(&table_a, 0),
        ControlEntrySnapshot::Terminalizing {
            lane: unpublished_lane,
            birth_session_epoch: NonZeroU64::new(171).expect("nonzero"),
            birth_generation: 1,
            terminal_wire_session_epoch: NonZeroU64::new(171).expect("nonzero"),
            terminal_req_id: unpublished_admission.req_id(),
            terminal_kind: ControlTerminalKind::Unpublished,
        }
    );
    assert_eq!(unpublished.lane(), unpublished_lane);
    assert_eq!(unpublished.req_id(), unpublished_admission.req_id());
    assert_eq!(
        unpublished.terminal_kind(),
        ControlTerminalKind::Unpublished
    );
    let (continuation, unpublished_release) = unpublished.release();
    assert_eq!(continuation, 0x4444);
    let busy = match table_a.admit_control(unpublished_lane, ControlPhase::ReplayOpen, 0x5555) {
        Ok(_) => panic!("unpublished release keeps lane busy"),
        Err(error) => error,
    };
    assert_eq!(busy.error(), &ControlAdmissionError::Busy);
    assert_eq!(busy.value(), &0x5555);

    let foreign_admission = table_b
        .admit_control(captured_lane, ControlPhase::PtRouteAck, 0x6666)
        .unwrap_or_else(|_| panic!("foreign lane admits"));
    let foreign_terminal = table_b
        .withdraw_unpublished_control(foreign_admission.key())
        .expect("foreign unpublished control withdraws");
    let (_, foreign_release) = foreign_terminal.release();
    let release_snapshot = control_release_snapshot(&foreign_release);
    let terminalizing = system_control_snapshot(&table_a, 1);
    let error = match table_a.reclaim_control(foreign_release) {
        Ok(()) => panic!("foreign control release cannot reclaim"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::ForeignTable);
    let (_, foreign_release) = error.into_parts();
    assert_eq!(control_release_snapshot(&foreign_release), release_snapshot);
    assert_eq!(system_control_snapshot(&table_a, 1), terminalizing);
    table_b
        .reclaim_control(foreign_release)
        .unwrap_or_else(|_| panic!("foreign release remains valid at its owner table"));

    let variants = [
        (
            ReclaimError::WrongClass,
            ControlRelease {
                lane: unpublished_lane,
                ..copy_control_release(&release_a)
            },
        ),
        (
            ReclaimError::WrongClass,
            ControlRelease {
                terminal_req_id: ReqId::try_new(
                    release_a.terminal_req_id.generation(),
                    SYSTEM_REQID_BASE,
                )
                .expect("mismatched control identity"),
                ..copy_control_release(&release_a)
            },
        ),
        (
            ReclaimError::StaleBirth,
            ControlRelease {
                birth_session_epoch: NonZeroU64::new(release_a.birth_session_epoch.get() + 1)
                    .expect("nonzero"),
                ..copy_control_release(&release_a)
            },
        ),
        (
            ReclaimError::StaleBirth,
            ControlRelease {
                birth_generation: release_a.birth_generation + 1,
                ..copy_control_release(&release_a)
            },
        ),
        (
            ReclaimError::StaleTerminalIdentity,
            ControlRelease {
                terminal_wire_session_epoch: NonZeroU64::new(
                    release_a.terminal_wire_session_epoch.get() + 1,
                )
                .expect("nonzero"),
                ..copy_control_release(&release_a)
            },
        ),
        (
            ReclaimError::StaleTerminalIdentity,
            ControlRelease {
                terminal_req_id: ReqId::try_new(
                    release_a.terminal_req_id.generation() + 1,
                    release_a.slot_index,
                )
                .expect("next generation"),
                ..copy_control_release(&release_a)
            },
        ),
        (
            ReclaimError::StaleTerminalIdentity,
            ControlRelease {
                terminal_kind: ControlTerminalKind::Drained,
                ..copy_control_release(&release_a)
            },
        ),
    ];
    for (expected, variant) in variants {
        let snapshot = control_release_snapshot(&variant);
        let error = match table_a.reclaim_control(variant) {
            Ok(()) => panic!("hostile control release cannot reclaim: {expected:?}"),
            Err(error) => error,
        };
        assert_eq!(error.error(), &expected);
        let (actual, returned) = error.into_parts();
        assert_eq!(actual, expected);
        assert_eq!(control_release_snapshot(&returned), snapshot);
        assert_eq!(system_control_snapshot(&table_a, 1), terminalizing);
    }

    let stored_lane_hostile = ControlLane::PtExternalSafeAck { ring_index: 0 };
    let ControlSlotState::Terminalizing { lane, .. } = &mut table_a
        ._system
        .get_mut(1)
        .expect("captured control backing")
        .state
    else {
        panic!("captured control remains terminalizing");
    };
    *lane = stored_lane_hostile;
    let hostile_terminalizing = system_control_snapshot(&table_a, 1);
    let stored_lane_release = copy_control_release(&release_a);
    let snapshot = control_release_snapshot(&stored_lane_release);
    let error = match table_a.reclaim_control(stored_lane_release) {
        Ok(()) => panic!("stored control lane mismatch cannot reclaim"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::StaleBirth);
    let (actual, returned) = error.into_parts();
    assert_eq!(actual, ReclaimError::StaleBirth);
    assert_eq!(control_release_snapshot(&returned), snapshot);
    assert_eq!(system_control_snapshot(&table_a, 1), hostile_terminalizing);
    let ControlSlotState::Terminalizing { lane, .. } = &mut table_a
        ._system
        .get_mut(1)
        .expect("captured control backing")
        .state
    else {
        panic!("failed reclaim preserves terminalizing control");
    };
    *lane = captured_lane;
    assert_eq!(system_control_snapshot(&table_a, 1), terminalizing);

    let original_topology = table_a.topology;
    table_a.topology = RequestTopology::try_new(2, 1).expect("hostile wider topology");
    let out_of_range_lane = ControlLane::OpenLifecycle { ring_index: 1 };
    let out_of_range_slot = SYSTEM_REQID_BASE + SYSTEM_REQUEST_SLOTS_PER_RING;
    let out_of_range = ControlRelease {
        slot_index: out_of_range_slot,
        lane: out_of_range_lane,
        terminal_req_id: ReqId::try_new(release_a.terminal_req_id.generation(), out_of_range_slot)
            .expect("control identity"),
        ..copy_control_release(&release_a)
    };
    let snapshot = control_release_snapshot(&out_of_range);
    let error = match table_a.reclaim_control(out_of_range) {
        Ok(()) => panic!("out-of-range control release cannot reclaim"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::SlotOutOfRange);
    assert_eq!(control_release_snapshot(error.value()), snapshot);
    assert_eq!(system_control_snapshot(&table_a, 1), terminalizing);
    table_a.topology = original_topology;

    let duplicate = copy_control_release(&release_a);
    table_a
        .reclaim_control(release_a)
        .unwrap_or_else(|_| panic!("matching captured release reclaims"));
    let reclaimed = system_control_snapshot(&table_a, 1);
    let snapshot = control_release_snapshot(&duplicate);
    let error = match table_a.reclaim_control(duplicate) {
        Ok(()) => panic!("reclaimed control lane is not terminalizing"),
        Err(error) => error,
    };
    assert_eq!(error.error(), &ReclaimError::NotTerminalizing);
    assert_eq!(control_release_snapshot(error.value()), snapshot);
    assert_eq!(system_control_snapshot(&table_a, 1), reclaimed);
    let next = table_a
        .admit_control(captured_lane, ControlPhase::PtRouteAck, 0x7777)
        .unwrap_or_else(|_| panic!("captured lane reuses only after reclaim"));
    assert_eq!(next.req_id().generation(), 2);

    table_a
        .reclaim_control(unpublished_release)
        .unwrap_or_else(|_| panic!("matching unpublished release reclaims"));
    let next = table_a
        .admit_control(unpublished_lane, ControlPhase::ReplayOpen, 0x8888)
        .unwrap_or_else(|_| panic!("unpublished lane reuses only after reclaim"));
    assert_eq!(next.req_id().generation(), 2);
}

#[test]
fn same_session_generation_max_reclaim_retires_capacity() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(181).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("application admits"));
    let ApplicationSlotState::Live { req_id, .. } = &mut table
        .application
        .get_mut(0)
        .expect("application backing")
        .state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 0).expect("maximum application ReqId");
    let terminal = table
        .withdraw_unpublished_application(admission.key())
        .expect("maximum-generation application terminalizes");
    let receipt = terminal.complete(clearance(&empty_context()), 0, 0);
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("maximum-generation receipt reclaims"));
    assert_eq!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Retired {
            generation: REQ_GENERATION_MAX,
        }
    );
    assert_eq!(table.free_head, None);

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x9999)
        .unwrap_or_else(|_| panic!("control admits"));
    let ControlSlotState::Occupied { req_id, .. } =
        &mut table._system.get_mut(1).expect("control backing").state
    else {
        panic!("occupied control");
    };
    *req_id =
        ReqId::try_new(REQ_GENERATION_MAX, SYSTEM_REQID_BASE + 1).expect("maximum control ReqId");
    let terminal = table
        .withdraw_unpublished_control(control.key())
        .expect("maximum-generation control terminalizes");
    let (continuation, release) = terminal.release();
    assert_eq!(continuation, 0x9999);
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("maximum-generation release reclaims"));
    assert_eq!(
        system_control_snapshot(&table, 1),
        ControlEntrySnapshot::Retired {
            generation: REQ_GENERATION_MAX,
        }
    );
}

#[test]
fn epoch_advances_only_at_successful_attach_commit() {
    assert!(
        OBJECT_MODEL
            .contains("ATTACHING -> GRACE | every failure or cancellation before the commit point")
    );
    assert!(OBJECT_MODEL.contains("ATTACHING -> BOUND_RECONCILING | the sole commit point"));
    assert!(OBJECT_MODEL.contains("latest_session_epoch = old + 1"));
    let normalized_lifecycle = LIFECYCLE.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized_lifecycle
            .contains("retains the current `session_epoch` as the exact ATTACH predecessor")
    );
    assert!(
        normalized_lifecycle
            .contains("The epoch advances exactly once, at a successful ATTACH commit")
    );

    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let changed = RequestTopology::try_new(2, 1).expect("changed topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(191).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    assert_eq!(table.mode(), TableMode::Active);
    table.begin_fence().expect("active table fences");
    assert_eq!(table.mode(), TableMode::Fencing);
    assert_eq!(table.session_epoch.get(), 191);
    assert_eq!(
        table.rebind_session(NonZeroU64::new(193).expect("nonzero"), topology),
        Err(SessionTransitionError::WrongEpoch)
    );
    assert_eq!(table.session_epoch.get(), 191);
    assert_eq!(table.mode(), TableMode::Fencing);
    assert_eq!(
        table.rebind_session(NonZeroU64::new(192).expect("nonzero"), changed),
        Err(SessionTransitionError::TopologyChanged)
    );
    assert_eq!(table.session_epoch.get(), 191);
    assert_eq!(table.mode(), TableMode::Fencing);
    table
        .rebind_session(NonZeroU64::new(192).expect("nonzero"), topology)
        .expect("exact checked attach commit");
    assert_eq!(table.session_epoch.get(), 192);
    assert_eq!(table.mode(), TableMode::Active);

    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut exhausted = RequestTable::try_new(
        NonZeroU64::new(u64::MAX).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("maximum-epoch table");
    exhausted.begin_fence().expect("maximum epoch fences");
    assert_eq!(
        exhausted.rebind_session(NonZeroU64::new(1).expect("nonzero"), topology),
        Err(SessionTransitionError::EpochExhausted)
    );
    assert_eq!(exhausted.session_epoch.get(), u64::MAX);
    assert_eq!(exhausted.mode(), TableMode::Fencing);
}

#[test]
fn session_rebind_retains_owner_without_repending() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(201).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("application admits"));
    table
        .record_cancel(admission.key())
        .expect("cancel intent records");
    assert_eq!(
        table.mark_application_visible(admission.key()),
        Ok(admission.req_id())
    );
    table.begin_fence().expect("active table fences");
    table
        .retain_after_fence(admission.key())
        .expect("stable-prefix no-candidate retains application");
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Live {
            phase: ApplicationPhase::new(op::READ).expect("application phase"),
            birth_session_epoch: NonZeroU64::new(201).expect("nonzero"),
            birth_generation: 1,
            req_id: ReqId::try_new(1, 0).expect("old identity"),
            wire_state: WireState::BetweenPhases,
            cancel_requested: true,
        }
    );
    table
        .rebind_session(NonZeroU64::new(202).expect("nonzero"), topology)
        .expect("fresh session rebinds");
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(table.session_epoch.get(), 202);
    let next = table
        .begin_application_phase(
            admission.key(),
            ApplicationPhase::new(op::QUERY_INFO).expect("application phase"),
        )
        .expect("retained operation starts at fresh generation one");
    assert_eq!(next.generation(), 1);
    assert_eq!(next.slot_index(), 0);
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert_eq!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Live {
            phase: ApplicationPhase::new(op::QUERY_INFO).expect("application phase"),
            birth_session_epoch: NonZeroU64::new(201).expect("nonzero"),
            birth_generation: 1,
            req_id: next,
            wire_state: WireState::PreparedNotVisible,
            cancel_requested: true,
        }
    );
}

#[test]
fn session_rebind_rejects_unresolved_phase_and_control_lane() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let phase = ApplicationPhase::new(op::READ).expect("application phase");

    {
        let pended = std::sync::Arc::new(AtomicU32::new(0));
        let completed = std::sync::Arc::new(AtomicU32::new(0));
        let (mut application, mut system, mut global) = backing::<1, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(211).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        table
            .admit_application(
                phase,
                CompletionOwner::new(CountingSink { pended, completed }),
            )
            .unwrap_or_else(|_| panic!("prepared application admits"));
        table.begin_fence().expect("active table fences");
        assert_eq!(
            table.rebind_session(NonZeroU64::new(212).expect("nonzero"), topology),
            Err(SessionTransitionError::UnresolvedApplicationPhase)
        );
        assert_eq!(table.session_epoch.get(), 211);
    }

    {
        let pended = std::sync::Arc::new(AtomicU32::new(0));
        let completed = std::sync::Arc::new(AtomicU32::new(0));
        let (mut application, mut system, mut global) = backing::<1, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(211).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        let admission = table
            .admit_application(
                phase,
                CompletionOwner::new(CountingSink { pended, completed }),
            )
            .unwrap_or_else(|_| panic!("application admits"));
        table
            .mark_application_visible(admission.key())
            .expect("application visible");
        let _token = table
            .begin_capture(211, cq_kind::COMPLETION, admission.req_id())
            .expect("capture detaches");
        table.begin_fence().expect("active table fences");
        assert_eq!(
            table.rebind_session(NonZeroU64::new(212).expect("nonzero"), topology),
            Err(SessionTransitionError::UnresolvedCapture)
        );
        assert_eq!(table.session_epoch.get(), 211);
    }

    {
        let (mut application, mut system, mut global) = control_backing::<1, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(211).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        table
            .admit_control(
                ControlLane::PtRouteAck { ring_index: 0 },
                ControlPhase::PtRouteAck,
                0x2110,
            )
            .unwrap_or_else(|_| panic!("control admits"));
        table.begin_fence().expect("active table fences");
        assert_eq!(
            table.rebind_session(NonZeroU64::new(212).expect("nonzero"), topology),
            Err(SessionTransitionError::LiveControlLane)
        );
        assert_eq!(table.session_epoch.get(), 211);
    }

    {
        let (mut application, mut system, mut global) = control_backing::<1, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(211).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        let control = table
            .admit_control(
                ControlLane::PtRouteAck { ring_index: 0 },
                ControlPhase::PtRouteAck,
                0x2120,
            )
            .unwrap_or_else(|_| panic!("control admits"));
        table
            .mark_control_visible(control.key())
            .expect("control visible");
        let _token = table
            .begin_capture(211, cq_kind::COMPLETION, control.req_id())
            .expect("control capture detaches");
        table.begin_fence().expect("active table fences");
        assert_eq!(
            table.rebind_session(NonZeroU64::new(212).expect("nonzero"), topology),
            Err(SessionTransitionError::UnresolvedCapture)
        );
        assert_eq!(table.session_epoch.get(), 211);
    }
}

#[test]
fn old_epoch_completion_receipt_reclaims_into_fresh_epoch_generation_one() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(221).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let application = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("application admits"));
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(0).expect("application").state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 0).expect("maximum application identity");
    let receipt = table
        .withdraw_unpublished_application(application.key())
        .expect("application terminalizes")
        .complete(clearance(&empty_context()), 0, 0);

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2210)
        .unwrap_or_else(|_| panic!("control admits"));
    let ControlSlotState::Occupied { req_id, .. } =
        &mut table._system.get_mut(1).expect("PT route lane").state
    else {
        panic!("occupied control");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, SYSTEM_REQID_BASE + 1)
        .expect("maximum control identity");
    let (continuation, release) = table
        .withdraw_unpublished_control(control.key())
        .expect("control terminalizes")
        .release();
    assert_eq!(continuation, 0x2210);

    table.begin_fence().expect("active table fences");
    table
        .rebind_session(NonZeroU64::new(222).expect("nonzero"), topology)
        .expect("terminal records may straddle rebind");
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("old application receipt reclaims"));
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("old control release reclaims"));
    assert_eq!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Free {
            next_free: None,
            generation: 0,
        }
    );
    assert_eq!(
        system_control_snapshot(&table, 1),
        ControlEntrySnapshot::Available { generation: 0 }
    );
    let next_application = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("application reuses in fresh epoch"));
    assert_eq!(next_application.req_id().generation(), 1);
    let next_control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2220)
        .unwrap_or_else(|_| panic!("control reuses in fresh epoch"));
    assert_eq!(next_control.req_id().generation(), 1);
}

#[test]
fn mid_operation_generation_exhaustion_retains_owner_and_requests_quiesce() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(231).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let application = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed,
            }),
        )
        .unwrap_or_else(|_| panic!("application admits"));
    table
        .mark_application_visible(application.key())
        .expect("application visible");
    let CaptureToken::Application(token) = table
        .begin_capture(231, cq_kind::COMPLETION, application.req_id())
        .expect("application captures")
    else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("application candidate installs"));
    table
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("application retains"));
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(0).expect("application").state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 0).expect("maximum application identity");
    assert!(!table.needs_quiesce());
    assert_eq!(
        table.begin_application_phase(
            application.key(),
            ApplicationPhase::new(op::QUERY_INFO).expect("application phase"),
        ),
        Err(ApplicationError::Phase(PhaseError::GenerationExhausted))
    );
    assert!(table.needs_quiesce());
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    assert!(matches!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Live {
            req_id,
            wire_state: WireState::GenerationExhausted,
            ..
        } if req_id.generation() == REQ_GENERATION_MAX
    ));

    let lane = ControlLane::OpenLifecycle { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::ReplayOpen, 0x2310)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("control visible");
    let CaptureToken::Control(token) = table
        .begin_capture(231, cq_kind::COMPLETION, control.req_id())
        .expect("control captures")
    else {
        panic!("control token");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("control candidate installs"));
    table
        .retain_control(captured)
        .unwrap_or_else(|_| panic!("control retains"));
    let ControlSlotState::Occupied { req_id, .. } =
        &mut table._system.get_mut(0).expect("open lane").state
    else {
        panic!("occupied control");
    };
    *req_id =
        ReqId::try_new(REQ_GENERATION_MAX, SYSTEM_REQID_BASE).expect("maximum control identity");
    assert_eq!(
        table.begin_control_phase(control.key(), ControlPhase::RecoveryCleanup),
        Err(ControlError::Phase(PhaseError::GenerationExhausted))
    );
    assert!(table.needs_quiesce());
    assert!(matches!(
        system_control_snapshot(&table, 0),
        ControlEntrySnapshot::Occupied {
            continuation: 0x2310,
            req_id,
            wire_state: WireState::GenerationExhausted,
            ..
        } if req_id.generation() == REQ_GENERATION_MAX
    ));
}

#[test]
fn generation_max_reclaim_retires_until_fresh_epoch() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(241).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let application = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("application admits"));
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(0).expect("application").state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 0).expect("maximum application identity");
    let receipt = table
        .withdraw_unpublished_application(application.key())
        .expect("application terminalizes")
        .complete(clearance(&empty_context()), 0, 0);
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("current-epoch max receipt reclaims"));
    assert!(matches!(
        application_entry_snapshot(&table, 0),
        ApplicationEntrySnapshot::Retired {
            generation: REQ_GENERATION_MAX
        }
    ));

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2410)
        .unwrap_or_else(|_| panic!("control admits"));
    let ControlSlotState::Occupied { req_id, .. } =
        &mut table._system.get_mut(1).expect("PT route lane").state
    else {
        panic!("occupied control");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, SYSTEM_REQID_BASE + 1)
        .expect("maximum control identity");
    let (_, release) = table
        .withdraw_unpublished_control(control.key())
        .expect("control terminalizes")
        .release();
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("current-epoch max release reclaims"));
    assert!(matches!(
        system_control_snapshot(&table, 1),
        ControlEntrySnapshot::Retired {
            generation: REQ_GENERATION_MAX
        }
    ));

    let (error, rejected_owner) = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed,
            }),
        )
        .expect_err("retired-only application capacity")
        .into_parts();
    assert_eq!(error, AdmissionError::SessionGenerationExhausted);
    assert_eq!(pended.load(Ordering::Relaxed), 1);
    let rejected_control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2420)
        .expect_err("retired control lane");
    assert_eq!(
        rejected_control.error(),
        &ControlAdmissionError::SessionGenerationExhausted
    );
    assert_eq!(rejected_control.into_parts().1, 0x2420);
    assert!(table.needs_quiesce());

    table.begin_fence().expect("active table fences");
    table
        .rebind_session(NonZeroU64::new(242).expect("nonzero"), topology)
        .expect("fresh epoch resets retirement");
    assert!(!table.needs_quiesce());
    let application = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            rejected_owner,
        )
        .unwrap_or_else(|_| panic!("application capacity resets"));
    assert_eq!(application.req_id().generation(), 1);
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2430)
        .unwrap_or_else(|_| panic!("control capacity resets"));
    assert_eq!(control.req_id().generation(), 1);
}

#[test]
fn fence_no_candidate_terminalizes_application_and_control() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(2, 4).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<4, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(251).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let mut applications = std::vec::Vec::new();
    for opcode in [op::READ, op::WRITE, op::FLUSH, op::QUERY_INFO] {
        applications.push(
            table
                .admit_application(
                    ApplicationPhase::new(opcode).expect("application phase"),
                    CompletionOwner::new(CountingSink {
                        pended: pended.clone(),
                        completed: completed.clone(),
                    }),
                )
                .unwrap_or_else(|_| panic!("application admits")),
        );
    }
    for admission in &applications {
        table
            .mark_application_visible(admission.key())
            .expect("application visible");
    }
    let CaptureToken::Application(token) = table
        .begin_capture(251, cq_kind::COMPLETION, applications[1].req_id())
        .expect("between-phase application captures")
    else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("application candidate installs"));
    table
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("application retains"));
    let CaptureToken::Application(token) = table
        .begin_capture(251, cq_kind::COMPLETION, applications[2].req_id())
        .expect("exhausted application captures")
    else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("application candidate installs"));
    table
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("application retains"));
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(2).expect("application").state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 2).expect("maximum application identity");
    assert_eq!(
        table.begin_application_phase(
            applications[2].key(),
            ApplicationPhase::new(op::QUERY_VOLUME).expect("application phase"),
        ),
        Err(ApplicationError::Phase(PhaseError::GenerationExhausted))
    );
    for admission in &applications[0..3] {
        table
            .record_cancel(admission.key())
            .expect("cancel intent records");
    }

    let control_lanes = [
        (
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
            0x2510,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 0 },
            ControlPhase::PtExternalSafeAck,
            0x2520,
        ),
        (
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
            0x2530,
        ),
    ];
    let mut controls = std::vec::Vec::new();
    for (lane, phase, continuation) in control_lanes {
        let admission = table
            .admit_control(lane, phase, continuation)
            .unwrap_or_else(|_| panic!("control admits"));
        table
            .mark_control_visible(admission.key())
            .expect("control visible");
        controls.push(admission);
    }
    for control in &controls[1..] {
        let CaptureToken::Control(token) = table
            .begin_capture(251, cq_kind::COMPLETION, control.req_id())
            .expect("control captures")
        else {
            panic!("control token");
        };
        let captured = table
            .install_control_candidate(token)
            .unwrap_or_else(|_| panic!("control candidate installs"));
        table
            .retain_control(captured)
            .unwrap_or_else(|_| panic!("control retains"));
    }
    let ControlSlotState::Occupied { req_id, .. } =
        &mut table._system.get_mut(0).expect("open lane").state
    else {
        panic!("occupied control");
    };
    *req_id =
        ReqId::try_new(REQ_GENERATION_MAX, SYSTEM_REQID_BASE).expect("maximum control identity");
    assert_eq!(
        table.begin_control_phase(controls[2].key(), ControlPhase::RecoveryCleanup),
        Err(ControlError::Phase(PhaseError::GenerationExhausted))
    );

    table.begin_fence().expect("active table fences");
    let uncancelled = match table.terminalize_application_after_fence(applications[3].key()) {
        Ok(_) => panic!("uncancelled application cannot terminalize after fence"),
        Err(error) => error,
    };
    assert_eq!(uncancelled, ApplicationError::Phase(PhaseError::WrongState));
    table
        .retain_after_fence(applications[3].key())
        .expect("uncancelled restart-eligible application retains");
    for admission in &applications[0..3] {
        let _receipt = table
            .terminalize_application_after_fence(admission.key())
            .unwrap_or_else(|_| panic!("cancelled application terminalizes"))
            .complete(clearance(&empty_context()), 0, 0);
    }
    assert_eq!(completed.load(Ordering::Relaxed), 3);
    assert_eq!(pended.load(Ordering::Relaxed), 4);

    for (index, expected_kind, expected_continuation) in [
        (0, ControlTerminalKind::FenceNoCandidate, 0x2510),
        (1, ControlTerminalKind::FenceNoCandidate, 0x2520),
        (2, ControlTerminalKind::FenceGenerationExhausted, 0x2530),
    ] {
        let terminal = table
            .terminalize_control_after_fence(controls[index].key())
            .unwrap_or_else(|_| panic!("control terminalizes after fence"));
        assert_eq!(terminal.terminal_kind(), expected_kind);
        let (continuation, _release) = terminal.release();
        assert_eq!(continuation, expected_continuation);
    }
    assert_eq!(table.mode(), TableMode::Fencing);
}

#[test]
fn captured_values_remain_owned_until_quarantined_during_drain() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(2, 4).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<4, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(259).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");

    let mut applications = std::vec::Vec::new();
    for opcode in [op::READ, op::WRITE] {
        let admission = table
            .admit_application(
                ApplicationPhase::new(opcode).expect("application phase"),
                CompletionOwner::new(CountingSink {
                    pended: pended.clone(),
                    completed: completed.clone(),
                }),
            )
            .unwrap_or_else(|_| panic!("application admits"));
        table
            .mark_application_visible(admission.key())
            .expect("application visible");
        applications.push(admission);
    }
    let mut application_tokens = std::vec::Vec::new();
    for admission in &applications {
        let CaptureToken::Application(token) = table
            .begin_capture(259, cq_kind::COMPLETION, admission.req_id())
            .expect("application capture begins")
        else {
            panic!("application token");
        };
        application_tokens.push(token);
    }
    let pre_drain_application = table
        .install_application_candidate(application_tokens.remove(0))
        .unwrap_or_else(|_| panic!("pre-drain application installs"));
    let post_drain_application_token = application_tokens.remove(0);

    let control_specs = [
        (
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 0 },
            ControlPhase::PtExternalSafeAck,
        ),
    ];
    let mut controls = std::vec::Vec::new();
    for (offset, (lane, phase)) in control_specs.into_iter().enumerate() {
        let admission = table
            .admit_control(
                lane,
                phase,
                u32::try_from(offset + 1).expect("continuation fits"),
            )
            .unwrap_or_else(|_| panic!("control admits"));
        table
            .mark_control_visible(admission.key())
            .expect("control visible");
        controls.push(admission);
    }
    let mut control_tokens = std::vec::Vec::new();
    for admission in &controls {
        let CaptureToken::Control(token) = table
            .begin_capture(259, cq_kind::COMPLETION, admission.req_id())
            .expect("control capture begins")
        else {
            panic!("control token");
        };
        control_tokens.push(token);
    }
    let pre_drain_control = table
        .install_control_candidate(control_tokens.remove(0))
        .unwrap_or_else(|_| panic!("pre-drain control installs"));
    let post_drain_control_token = control_tokens.remove(0);

    table.begin_drain();
    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::UnresolvedCapture)
    ));
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::UnresolvedCapture)
    ));

    let post_drain_application = table
        .install_application_candidate(post_drain_application_token)
        .unwrap_or_else(|_| panic!("issued application token installs during drain"));
    let post_drain_control = table
        .install_control_candidate(post_drain_control_token)
        .unwrap_or_else(|_| panic!("issued control token installs during drain"));
    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::UnresolvedCapture)
    ));
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::UnresolvedCapture)
    ));

    for mut captured in [pre_drain_application, post_drain_application] {
        let expected_value = captured_application_snapshot(&captured);
        let slot_index = usize::try_from(captured.slot_index).expect("application index");
        let expected_state = application_entry_snapshot(&table, slot_index);
        let retained = match table.retain_application(captured) {
            Ok(_) => panic!("draining cannot retain a captured application"),
            Err(error) => error,
        };
        assert_eq!(
            retained.error(),
            &ApplicationError::Phase(PhaseError::TableNotActive)
        );
        let (_, returned) = retained.into_parts();
        captured = returned;
        assert_eq!(captured_application_snapshot(&captured), expected_value);
        assert_eq!(
            application_entry_snapshot(&table, slot_index),
            expected_state
        );

        let terminalized = match table.terminalize_application(captured) {
            Ok(_) => panic!("draining cannot terminalize a captured application"),
            Err(error) => error,
        };
        assert_eq!(
            terminalized.error(),
            &ApplicationError::Phase(PhaseError::TableNotActive)
        );
        let (_, returned) = terminalized.into_parts();
        captured = returned;
        assert_eq!(captured_application_snapshot(&captured), expected_value);
        assert_eq!(
            application_entry_snapshot(&table, slot_index),
            expected_state
        );
        table
            .quarantine_application(captured)
            .unwrap_or_else(|_| panic!("captured application quarantines during drain"));
    }

    for mut captured in [pre_drain_control, post_drain_control] {
        let expected_value = captured_control_snapshot(&captured);
        let backing_index =
            usize::try_from(captured.slot_index - SYSTEM_REQID_BASE).expect("control index");
        let expected_state = system_control_snapshot(&table, backing_index);
        let retained = match table.retain_control(captured) {
            Ok(_) => panic!("draining cannot retain a captured control"),
            Err(error) => error,
        };
        assert_eq!(
            retained.error(),
            &ControlError::Phase(PhaseError::TableNotActive)
        );
        let (_, returned) = retained.into_parts();
        captured = returned;
        assert_eq!(captured_control_snapshot(&captured), expected_value);
        assert_eq!(
            system_control_snapshot(&table, backing_index),
            expected_state
        );

        let terminalized = match table.terminalize_control(captured) {
            Ok(_) => panic!("draining cannot terminalize a captured control"),
            Err(error) => error,
        };
        assert_eq!(
            terminalized.error(),
            &ControlError::Phase(PhaseError::TableNotActive)
        );
        let (_, returned) = terminalized.into_parts();
        captured = returned;
        assert_eq!(captured_control_snapshot(&captured), expected_value);
        assert_eq!(
            system_control_snapshot(&table, backing_index),
            expected_state
        );
        table
            .quarantine_control(captured)
            .unwrap_or_else(|_| panic!("captured control quarantines during drain"));
    }

    for expected_count in 1..=2 {
        let receipt = table
            .drain_next_application()
            .unwrap_or_else(|error| panic!("quarantined application drains: {error:?}"))
            .expect("one quarantined application")
            .complete(clearance(&empty_context()), 0, 0);
        table
            .reclaim_completed(receipt)
            .unwrap_or_else(|_| panic!("drained application reclaims"));
        assert_eq!(completed.load(Ordering::Relaxed), expected_count);
    }
    assert!(matches!(table.drain_next_application(), Ok(None)));

    for expected_continuation in 1..=2 {
        let terminal = table
            .drain_next_control()
            .unwrap_or_else(|error| panic!("quarantined control drains: {error:?}"))
            .expect("one quarantined control");
        let (continuation, release) = terminal.release();
        assert_eq!(continuation, expected_continuation);
        table
            .reclaim_control(release)
            .unwrap_or_else(|_| panic!("drained control reclaims"));
    }
    assert!(matches!(table.drain_next_control(), Ok(None)));
}

#[test]
fn drain_permutation_returns_every_capability_once() {
    let app_pended = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let app_completed = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let app_dropped = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let control_dropped = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let topology = RequestTopology::try_new(2, 7).expect("valid topology");
    let (mut application, mut system, mut global) = tagged_backing::<7, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(261).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");

    let mut applications = std::vec::Vec::new();
    for tag in 1..=7 {
        applications.push(
            table
                .admit_application(
                    ApplicationPhase::new(op::READ).expect("application phase"),
                    CompletionOwner::new(TaggedSink {
                        tag,
                        pended: app_pended.clone(),
                        completed: app_completed.clone(),
                        dropped: app_dropped.clone(),
                    }),
                )
                .unwrap_or_else(|_| panic!("application admits")),
        );
    }
    table
        .mark_application_visible(applications[1].key())
        .expect("visible application");
    for index in 2..=6 {
        table
            .mark_application_visible(applications[index].key())
            .expect("application visible");
    }
    let mut detached_application = None;
    let mut captured_application = None;
    for index in 2..=6 {
        let CaptureToken::Application(token) = table
            .begin_capture(261, cq_kind::COMPLETION, applications[index].req_id())
            .expect("application captures")
        else {
            panic!("application token");
        };
        if index == 6 {
            detached_application = Some(token);
            continue;
        }
        let captured = table
            .install_application_candidate(token)
            .unwrap_or_else(|_| panic!("application candidate installs"));
        match index {
            2 | 4 => {
                table
                    .retain_application(captured)
                    .unwrap_or_else(|_| panic!("application retains"));
            }
            3 => {
                table
                    .quarantine_application(captured)
                    .unwrap_or_else(|_| panic!("application quarantines"));
            }
            5 => {
                captured_application = Some(captured);
            }
            _ => unreachable!(),
        }
    }
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(4).expect("application").state
    else {
        panic!("live application");
    };
    let maximum_application_req_id =
        ReqId::try_new(REQ_GENERATION_MAX, 4).expect("maximum application identity");
    *req_id = maximum_application_req_id;
    assert_eq!(
        table.begin_application_phase(
            applications[4].key(),
            ApplicationPhase::new(op::QUERY_INFO).expect("application phase"),
        ),
        Err(ApplicationError::Phase(PhaseError::GenerationExhausted))
    );

    let control_specs = [
        (
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 0 },
            ControlPhase::PtExternalSafeAck,
        ),
        (
            ControlLane::PtRouteAck { ring_index: 1 },
            ControlPhase::PtRouteAck,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 1 },
            ControlPhase::PtExternalSafeAck,
        ),
        (
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
        ),
        (
            ControlLane::OpenLifecycle { ring_index: 1 },
            ControlPhase::ReplayOpen,
        ),
    ];
    let mut controls = std::vec::Vec::new();
    for (offset, (lane, phase)) in control_specs.into_iter().enumerate() {
        controls.push(
            table
                .admit_control(
                    lane,
                    phase,
                    TaggedContinuation {
                        tag: u32::try_from(offset + 1).expect("tag fits"),
                        dropped: control_dropped.clone(),
                    },
                )
                .unwrap_or_else(|_| panic!("control admits")),
        );
    }
    table
        .mark_control_visible(controls[1].key())
        .expect("visible control");
    for index in 2..=5 {
        table
            .mark_control_visible(controls[index].key())
            .expect("control visible");
    }
    let mut captured_control = None;
    for index in 2..=5 {
        let CaptureToken::Control(token) = table
            .begin_capture(261, cq_kind::COMPLETION, controls[index].req_id())
            .expect("control captures")
        else {
            panic!("control token");
        };
        let captured = table
            .install_control_candidate(token)
            .unwrap_or_else(|_| panic!("control candidate installs"));
        match index {
            2 | 4 => {
                table
                    .retain_control(captured)
                    .unwrap_or_else(|_| panic!("control retains"));
            }
            3 => {
                table
                    .quarantine_control(captured)
                    .unwrap_or_else(|_| panic!("control quarantines"));
            }
            5 => {
                captured_control = Some(captured);
            }
            _ => unreachable!(),
        }
    }
    let exhausted_slot = usize::try_from(controls[4].req_id().slot_index() - SYSTEM_REQID_BASE)
        .expect("system backing index");
    let ControlSlotState::Occupied { req_id, .. } = &mut table
        ._system
        .get_mut(exhausted_slot)
        .expect("control")
        .state
    else {
        panic!("occupied control");
    };
    let maximum_control_req_id =
        ReqId::try_new(REQ_GENERATION_MAX, controls[4].req_id().slot_index())
            .expect("maximum control identity");
    *req_id = maximum_control_req_id;
    assert_eq!(
        table.begin_control_phase(controls[4].key(), ControlPhase::RecoveryCleanup),
        Err(ControlError::Phase(PhaseError::GenerationExhausted))
    );

    let global_control = table
        .admit_control(
            ControlLane::ExternalChangeAck,
            ControlPhase::ExternalChangeAck,
            TaggedContinuation {
                tag: 7,
                dropped: control_dropped.clone(),
            },
        )
        .unwrap_or_else(|_| panic!("global control admits"));
    table
        .mark_control_visible(global_control.key())
        .expect("global control visible");
    let CaptureToken::Control(detached_global_control) = table
        .begin_capture(261, cq_kind::COMPLETION, global_control.req_id())
        .expect("global control capture begins")
    else {
        panic!("global control token");
    };

    let terminal_epoch = NonZeroU64::new(261).expect("nonzero");
    let table_id = table.table_id.0;
    let application_req_ids = [
        applications[0].req_id(),
        applications[1].req_id(),
        applications[2].req_id(),
        applications[3].req_id(),
        maximum_application_req_id,
        applications[5].req_id(),
        applications[6].req_id(),
    ];

    table.begin_drain();
    for (slot_index, expected_req_id) in application_req_ids[..5].iter().copied().enumerate() {
        let terminal = table
            .drain_next_application()
            .unwrap_or_else(|error| panic!("application drains: {error:?}"))
            .expect("one application inventory item");
        assert_eq!(
            terminal.slot_index,
            u32::try_from(slot_index).expect("slot")
        );
        assert_eq!(terminal.birth_session_epoch, terminal_epoch);
        assert_eq!(terminal.birth_generation, 1);
        assert_eq!(terminal.terminal_wire_session_epoch, terminal_epoch);
        assert_eq!(terminal.terminal_req_id, expected_req_id);
        let receipt = terminal.complete(clearance(&empty_context()), 0, 0);
        assert_eq!(
            completion_receipt_snapshot(&receipt),
            (
                table_id,
                u32::try_from(slot_index).expect("slot"),
                terminal_epoch,
                1,
                terminal_epoch,
                expected_req_id,
            )
        );
        table
            .reclaim_completed(receipt)
            .unwrap_or_else(|_| panic!("drained application receipt reclaims"));
        assert_eq!(
            app_completed
                .lock()
                .expect("application completion trace")
                .len(),
            slot_index + 1
        );
    }
    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::UnresolvedCapture)
    ));
    table
        .quarantine_application(
            captured_application.expect("direct captured application disposition"),
        )
        .unwrap_or_else(|_| panic!("direct captured application quarantines"));
    let terminal = table
        .drain_next_application()
        .unwrap_or_else(|error| panic!("resolved captured application drains: {error:?}"))
        .expect("direct captured application inventory");
    assert_eq!(terminal.slot_index, 5);
    assert_eq!(terminal.birth_session_epoch, terminal_epoch);
    assert_eq!(terminal.birth_generation, 1);
    assert_eq!(terminal.terminal_wire_session_epoch, terminal_epoch);
    assert_eq!(terminal.terminal_req_id, application_req_ids[5]);
    let receipt = terminal.complete(clearance(&empty_context()), 0, 0);
    assert_eq!(
        completion_receipt_snapshot(&receipt),
        (
            table_id,
            5,
            terminal_epoch,
            1,
            terminal_epoch,
            application_req_ids[5],
        )
    );
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("direct captured application reclaims"));
    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::UnresolvedCapture)
    ));
    let captured = table
        .install_application_candidate(detached_application.expect("detached application token"))
        .unwrap_or_else(|_| panic!("issued application token installs during drain"));
    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::UnresolvedCapture)
    ));
    table
        .quarantine_application(captured)
        .unwrap_or_else(|_| panic!("issued application token quarantines during drain"));
    let terminal = table
        .drain_next_application()
        .unwrap_or_else(|error| panic!("resolved application drains: {error:?}"))
        .expect("resolved application inventory");
    assert_eq!(terminal.slot_index, 6);
    assert_eq!(terminal.birth_session_epoch, terminal_epoch);
    assert_eq!(terminal.birth_generation, 1);
    assert_eq!(terminal.terminal_wire_session_epoch, terminal_epoch);
    assert_eq!(terminal.terminal_req_id, application_req_ids[6]);
    let receipt = terminal.complete(clearance(&empty_context()), 0, 0);
    assert_eq!(
        completion_receipt_snapshot(&receipt),
        (
            table_id,
            6,
            terminal_epoch,
            1,
            terminal_epoch,
            application_req_ids[6],
        )
    );
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("resolved application receipt reclaims"));
    assert!(matches!(table.drain_next_application(), Ok(None)));

    for (expected_count, expected_tag) in [5, 1, 2, 3, 4].into_iter().enumerate() {
        let terminal = table
            .drain_next_control()
            .unwrap_or_else(|error| panic!("control drains: {error:?}"))
            .expect("one control inventory item");
        assert_eq!(terminal.terminal_kind(), ControlTerminalKind::Drained);
        let (continuation, release) = terminal.release();
        assert_eq!(continuation.tag, expected_tag);
        let admission = controls
            .get(usize::try_from(expected_tag - 1).expect("control tag"))
            .expect("tagged control admission");
        let expected_req_id = if expected_tag == 5 {
            maximum_control_req_id
        } else {
            admission.req_id()
        };
        assert_eq!(
            control_release_snapshot(&release),
            (
                table_id,
                expected_req_id.slot_index(),
                admission.key().lane,
                terminal_epoch,
                1,
                terminal_epoch,
                expected_req_id,
                ControlTerminalKind::Drained,
            )
        );
        table
            .reclaim_control(release)
            .unwrap_or_else(|_| panic!("drained control release reclaims"));
        drop(continuation);
        assert_eq!(
            control_dropped.lock().expect("control drop trace").len(),
            expected_count + 1
        );
    }
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::UnresolvedCapture)
    ));
    table
        .quarantine_control(captured_control.expect("direct captured system control"))
        .unwrap_or_else(|_| panic!("direct captured system control quarantines"));
    let terminal = table
        .drain_next_control()
        .unwrap_or_else(|error| panic!("resolved system control drains: {error:?}"))
        .expect("resolved system control inventory");
    let (continuation, release) = terminal.release();
    assert_eq!(continuation.tag, 6);
    assert_eq!(
        control_release_snapshot(&release),
        (
            table_id,
            controls[5].req_id().slot_index(),
            controls[5].key().lane,
            terminal_epoch,
            1,
            terminal_epoch,
            controls[5].req_id(),
            ControlTerminalKind::Drained,
        )
    );
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("resolved system control release reclaims"));
    drop(continuation);
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::UnresolvedCapture)
    ));
    let captured_global = table
        .install_control_candidate(detached_global_control)
        .unwrap_or_else(|_| panic!("issued global control token installs during drain"));
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::UnresolvedCapture)
    ));
    table
        .quarantine_control(captured_global)
        .unwrap_or_else(|_| panic!("captured global control quarantines"));
    let terminal = table
        .drain_next_control()
        .unwrap_or_else(|error| panic!("resolved global control drains: {error:?}"))
        .expect("resolved global control inventory");
    let (continuation, release) = terminal.release();
    assert_eq!(continuation.tag, 7);
    assert_eq!(
        control_release_snapshot(&release),
        (
            table_id,
            GLOBAL_EXTERNAL_CHANGE_ACK_REQID,
            ControlLane::ExternalChangeAck,
            terminal_epoch,
            1,
            terminal_epoch,
            global_control.req_id(),
            ControlTerminalKind::Drained,
        )
    );
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("resolved global control release reclaims"));
    drop(continuation);
    assert!(matches!(table.drain_next_control(), Ok(None)));

    let mut completed_tags = app_completed
        .lock()
        .expect("application completion trace")
        .clone();
    completed_tags.sort_unstable();
    assert_eq!(completed_tags, [1, 2, 3, 4, 5, 6, 7]);
    let mut dropped_tags = control_dropped.lock().expect("control drop trace").clone();
    dropped_tags.sort_unstable();
    assert_eq!(dropped_tags, [1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn draining_state_permanently_rejects_admission_visibility_capture_and_rebind() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 2).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(271).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let prepared = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("prepared application admits"));
    let between = table
        .admit_application(
            ApplicationPhase::new(op::WRITE).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("between-phase application admits"));
    table
        .mark_application_visible(between.key())
        .expect("application visible");
    let CaptureToken::Application(token) = table
        .begin_capture(271, cq_kind::COMPLETION, between.req_id())
        .expect("application captures")
    else {
        panic!("application token");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("application candidate installs"));
    table
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("application retains"));

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let prepared_control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2710)
        .unwrap_or_else(|_| panic!("prepared control admits"));
    let between_control = table
        .admit_control(
            ControlLane::PtExternalSafeAck { ring_index: 0 },
            ControlPhase::PtExternalSafeAck,
            0x2711,
        )
        .unwrap_or_else(|_| panic!("between-phase control admits"));
    table
        .mark_control_visible(between_control.key())
        .expect("control visible");
    let CaptureToken::Control(token) = table
        .begin_capture(271, cq_kind::COMPLETION, between_control.req_id())
        .expect("control captures")
    else {
        panic!("control token");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("control candidate installs"));
    table
        .retain_control(captured)
        .unwrap_or_else(|_| panic!("control retains"));

    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::NotDraining)
    ));
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::NotDraining)
    ));
    table.begin_fence().expect("active table fences");
    assert_eq!(table.mode(), TableMode::Fencing);
    assert!(matches!(
        table.drain_next_application(),
        Err(DrainError::NotDraining)
    ));
    assert!(matches!(
        table.drain_next_control(),
        Err(DrainError::NotDraining)
    ));
    table.begin_drain();
    assert_eq!(table.mode(), TableMode::Draining);
    table.begin_drain();
    assert_eq!(table.mode(), TableMode::Draining);

    let rejected = table
        .admit_application(
            ApplicationPhase::new(op::FLUSH).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed,
            }),
        )
        .expect_err("draining rejects application admission");
    assert_eq!(rejected.error(), &AdmissionError::TableNotActive);
    assert_eq!(pended.load(Ordering::Relaxed), 2);
    let rejected = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2720)
        .expect_err("draining rejects control admission");
    assert_eq!(rejected.error(), &ControlAdmissionError::TableNotActive);
    assert_eq!(rejected.into_parts().1, 0x2720);
    assert_eq!(
        table.mark_application_visible(prepared.key()),
        Err(ApplicationError::Phase(PhaseError::TableNotActive))
    );
    assert_eq!(
        table.begin_application_phase(
            between.key(),
            ApplicationPhase::new(op::QUERY_INFO).expect("application phase"),
        ),
        Err(ApplicationError::Phase(PhaseError::TableNotActive))
    );
    assert_eq!(
        table.mark_control_visible(prepared_control.key()),
        Err(ControlError::Phase(PhaseError::TableNotActive))
    );
    assert_eq!(
        table.begin_control_phase(between_control.key(), ControlPhase::PtExternalSafeAck,),
        Err(ControlError::Phase(PhaseError::TableNotActive))
    );
    assert!(matches!(
        table.begin_capture(271, cq_kind::COMPLETION, prepared.req_id()),
        Err(CaptureError::TableNotActive)
    ));
    assert_eq!(table.begin_fence(), Err(SessionTransitionError::WrongMode));
    assert_eq!(
        table.rebind_session(NonZeroU64::new(272).expect("nonzero"), topology),
        Err(SessionTransitionError::WrongMode)
    );
    assert_eq!(
        table.retain_after_fence(prepared.key()),
        Err(ApplicationError::Phase(PhaseError::TableNotActive))
    );
    assert_eq!(table.mode(), TableMode::Draining);
    assert_eq!(table.session_epoch.get(), 271);
}

#[test]
fn dropping_table_view_does_not_drop_backing_capabilities() {
    let app_pended = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let app_completed = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let app_dropped = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let control_dropped = std::sync::Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let topology = RequestTopology::try_new(2, 6).expect("valid topology");
    let (mut application, mut system, mut global) = tagged_backing::<6, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(281).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");

    let mut applications = std::vec::Vec::new();
    for tag in 1..=6 {
        applications.push(
            table
                .admit_application(
                    ApplicationPhase::new(op::READ).expect("application phase"),
                    CompletionOwner::new(TaggedSink {
                        tag,
                        pended: app_pended.clone(),
                        completed: app_completed.clone(),
                        dropped: app_dropped.clone(),
                    }),
                )
                .unwrap_or_else(|_| panic!("application admits")),
        );
    }
    table
        .mark_application_visible(applications[1].key())
        .expect("visible application");
    for index in 2..=5 {
        table
            .mark_application_visible(applications[index].key())
            .expect("application visible");
        let CaptureToken::Application(token) = table
            .begin_capture(281, cq_kind::COMPLETION, applications[index].req_id())
            .expect("application captures")
        else {
            panic!("application token");
        };
        let captured = table
            .install_application_candidate(token)
            .unwrap_or_else(|_| panic!("application candidate installs"));
        match index {
            2 => {
                table
                    .retain_application(captured)
                    .unwrap_or_else(|_| panic!("application retains"));
            }
            3 => {
                table
                    .quarantine_application(captured)
                    .unwrap_or_else(|_| panic!("application quarantines"));
            }
            4 => {
                table
                    .retain_application(captured)
                    .unwrap_or_else(|_| panic!("application retains"));
            }
            5 => {
                let _captured_application = captured;
            }
            _ => unreachable!(),
        }
    }
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(4).expect("application").state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 4).expect("maximum application identity");
    assert_eq!(
        table.begin_application_phase(
            applications[4].key(),
            ApplicationPhase::new(op::QUERY_INFO).expect("application phase"),
        ),
        Err(ApplicationError::Phase(PhaseError::GenerationExhausted))
    );

    let control_specs = [
        (
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 0 },
            ControlPhase::PtExternalSafeAck,
        ),
        (
            ControlLane::PtRouteAck { ring_index: 1 },
            ControlPhase::PtRouteAck,
        ),
        (
            ControlLane::PtExternalSafeAck { ring_index: 1 },
            ControlPhase::PtExternalSafeAck,
        ),
        (
            ControlLane::OpenLifecycle { ring_index: 0 },
            ControlPhase::ReplayOpen,
        ),
        (
            ControlLane::OpenLifecycle { ring_index: 1 },
            ControlPhase::ReplayOpen,
        ),
    ];
    let mut controls = std::vec::Vec::new();
    for (offset, (lane, phase)) in control_specs.into_iter().enumerate() {
        controls.push(
            table
                .admit_control(
                    lane,
                    phase,
                    TaggedContinuation {
                        tag: u32::try_from(offset + 1).expect("tag fits"),
                        dropped: control_dropped.clone(),
                    },
                )
                .unwrap_or_else(|_| panic!("control admits")),
        );
    }
    table
        .mark_control_visible(controls[1].key())
        .expect("visible control");
    for index in 2..=5 {
        table
            .mark_control_visible(controls[index].key())
            .expect("control visible");
        let CaptureToken::Control(token) = table
            .begin_capture(281, cq_kind::COMPLETION, controls[index].req_id())
            .expect("control captures")
        else {
            panic!("control token");
        };
        let captured = table
            .install_control_candidate(token)
            .unwrap_or_else(|_| panic!("control candidate installs"));
        match index {
            2 => {
                table
                    .retain_control(captured)
                    .unwrap_or_else(|_| panic!("control retains"));
            }
            3 => {
                table
                    .quarantine_control(captured)
                    .unwrap_or_else(|_| panic!("control quarantines"));
            }
            4 => {
                table
                    .retain_control(captured)
                    .unwrap_or_else(|_| panic!("control retains"));
            }
            5 => {
                let _captured_control = captured;
            }
            _ => unreachable!(),
        }
    }
    let exhausted_slot = usize::try_from(controls[4].req_id().slot_index() - SYSTEM_REQID_BASE)
        .expect("system backing index");
    let ControlSlotState::Occupied { req_id, .. } = &mut table
        ._system
        .get_mut(exhausted_slot)
        .expect("control")
        .state
    else {
        panic!("occupied control");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, controls[4].req_id().slot_index())
        .expect("maximum control identity");
    assert_eq!(
        table.begin_control_phase(controls[4].key(), ControlPhase::RecoveryCleanup),
        Err(ControlError::Phase(PhaseError::GenerationExhausted))
    );

    drop(table);
    assert!(
        app_dropped
            .lock()
            .expect("application drop trace")
            .is_empty()
    );
    assert!(
        control_dropped
            .lock()
            .expect("control drop trace")
            .is_empty()
    );
    drop(application);
    drop(system);
    drop(global);
    let mut application_tags = app_dropped.lock().expect("application drop trace").clone();
    application_tags.sort_unstable();
    assert_eq!(application_tags, [1, 2, 3, 4, 5, 6]);
    let mut control_tags = control_dropped.lock().expect("control drop trace").clone();
    control_tags.sort_unstable();
    assert_eq!(control_tags, [1, 2, 3, 4, 5, 6]);
    assert!(
        app_completed
            .lock()
            .expect("application completion trace")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Per-guard signal coverage.
//
// Rounds 1 and 2 of the gate review each found guards the suite could not see
// break, by hand. A mechanical sweep then mutated every `if` guard that
// returns `Err` and every key-validator call site -- 109 mutants -- and found
// 30 the whole 302-test suite missed. Finding them by hand was never going to
// converge, so the tests below close all of them, and
// `driver/scripts/mutation_sweep.py` is committed as a gate so the count
// cannot silently regress.
//
// Three of the 30 are unreachable through any input and are proven so in
// `topology_self_checks_are_dead_by_construction` rather than tested through
// the API; they are the sweep's allowlist.
// ---------------------------------------------------------------------------

/// Sweep A004. `journaled_semantic` rejects a non-application opcode with
/// `UnsupportedOpcode`, not with the `NotJournaledSemantic` it would fall
/// through to if the first guard were dropped. The distinction matters: one
/// says "this opcode does not exist on this wire", the other says "it exists
/// but carries no journaled identity", and 02-transport section 8.2's capture
/// rule keys off the second.
#[test]
fn journaled_semantic_separates_unknown_opcodes_from_unjournaled_ones() {
    for unknown in [0x0000_u16, 0xFFFF, 0x00FF] {
        assert_eq!(
            ApplicationPhase::journaled_semantic(unknown),
            Err(ApplicationPhaseError::UnsupportedOpcode),
            "opcode {unknown:#06x} is not on the wire at all"
        );
        assert_eq!(
            ApplicationPhase::new(unknown),
            Err(ApplicationPhaseError::UnsupportedOpcode)
        );
    }
    assert_eq!(
        ApplicationPhase::journaled_semantic(op::READ),
        Err(ApplicationPhaseError::NotJournaledSemantic),
        "READ is a real opcode that simply carries no journaled identity"
    );
}

/// Sweep A020, A022. Publication is one-way: a second `mark_visible` on an
/// already-visible identity is a state error, not a no-op re-publish.
#[test]
fn an_identity_is_published_at_most_once() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(271).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    assert_eq!(
        table.mark_application_visible(admission.key()),
        Ok(admission.req_id())
    );
    let before = application_entry_snapshot(&table, 0);
    assert_eq!(
        table.mark_application_visible(admission.key()),
        Err(ApplicationError::Phase(PhaseError::WrongState))
    );
    assert_eq!(application_entry_snapshot(&table, 0), before);

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2710)
        .unwrap_or_else(|_| panic!("control admits"));
    assert_eq!(
        table.mark_control_visible(control.key()),
        Ok(control.req_id())
    );
    let before = system_control_snapshot(&table, 1);
    assert_eq!(
        table.mark_control_visible(control.key()),
        Err(ControlError::Phase(PhaseError::WrongState))
    );
    assert_eq!(system_control_snapshot(&table, 1), before);
}

/// Sweep A055, A060. Design section 5.1: "There is no rollback from
/// `Visible`." Once an identity is on the wire the provider may already be
/// executing it, so withdrawal must be refused -- otherwise the model hands
/// out a completing capability for a live request.
#[test]
fn withdrawal_is_refused_once_the_identity_is_visible() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(272).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let before = application_entry_snapshot(&table, 0);
    assert!(matches!(
        table.withdraw_unpublished_application(admission.key()),
        Err(ApplicationError::Phase(PhaseError::WrongState))
    ));
    assert_eq!(application_entry_snapshot(&table, 0), before);
    assert_eq!(completed.load(Ordering::Relaxed), 0);

    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2720)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("control visibility");
    let before = system_control_snapshot(&table, 1);
    assert!(matches!(
        table.withdraw_unpublished_control(control.key()),
        Err(ControlError::Phase(PhaseError::WrongState))
    ));
    assert_eq!(system_control_snapshot(&table, 1), before);
}

/// Sweep A026, B1.1. `admit_control` checks the lane/phase pair and so does
/// `begin_control_phase`; only the first had a signal. Without the second, a
/// PT_ROUTE_ACK lane accepts a REPLAY_OPEN completion envelope on its next
/// phase -- an opcode illegal for that slot class, which is exactly the tuple
/// component 02-transport section 8.1 makes mandatory. The same call also
/// validates its key.
#[test]
fn a_retained_control_lane_still_refuses_a_foreign_phase() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(273).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2730)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("visibility");
    let token = table
        .begin_capture(273, cq_kind::COMPLETION, control.req_id())
        .expect("capture");
    let CaptureToken::Control(token) = token else {
        panic!("control capture");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    table
        .retain_control(captured)
        .unwrap_or_else(|_| panic!("retain"));

    let before = system_control_snapshot(&table, 1);
    assert_eq!(
        table.begin_control_phase(control.key(), ControlPhase::ReplayOpen),
        Err(ControlError::Phase(PhaseError::WrongPhaseClass)),
        "a PT route lane has no REPLAY_OPEN phase"
    );
    assert_eq!(system_control_snapshot(&table, 1), before);

    // ...and the same entry point validates key provenance (B1.1).
    let stale = ControlKey {
        birth_generation: control.key().birth_generation + 1,
        ..control.key()
    };
    assert_eq!(
        table.begin_control_phase(stale, ControlPhase::PtRouteAck),
        Err(ControlError::Key(KeyError::StaleBirth))
    );
    assert_eq!(system_control_snapshot(&table, 1), before);
    assert!(
        table
            .begin_control_phase(control.key(), ControlPhase::PtRouteAck)
            .is_ok()
    );
}

/// Sweep A035, A036. The control branch of `begin_capture` matches on lane and
/// exact current `ReqId`, and requires `Visible`. A stale generation or an
/// unpublished entry must not yield a capture token.
#[test]
fn control_capture_requires_the_current_identity_and_visibility() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(274).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2740)
        .unwrap_or_else(|_| panic!("control admits"));

    // Not yet visible.
    let before = system_control_snapshot(&table, 1);
    assert!(matches!(
        table.begin_capture(274, cq_kind::COMPLETION, control.req_id()),
        Err(CaptureError::NotVisible)
    ));
    assert_eq!(system_control_snapshot(&table, 1), before);

    table
        .mark_control_visible(control.key())
        .expect("visibility");
    let before = system_control_snapshot(&table, 1);
    // Right slot, wrong generation.
    let stale_identity = ReqId::try_new(
        control.req_id().generation() + 1,
        control.req_id().slot_index(),
    )
    .expect("successor identity");
    assert!(matches!(
        table.begin_capture(274, cq_kind::COMPLETION, stale_identity),
        Err(CaptureError::StaleCurrentGeneration)
    ));
    assert_eq!(system_control_snapshot(&table, 1), before);
    assert!(matches!(
        table.begin_capture(274, cq_kind::COMPLETION, control.req_id()),
        Ok(CaptureToken::Control(_))
    ));
}

/// Sweep A096. A control lane names its ring, and the ring index is
/// caller-supplied: `admit_control` on a lane whose ring does not exist must
/// be refused rather than folded onto some other ring's slot.
#[test]
fn a_control_lane_beyond_the_ring_count_is_refused() {
    let topology = RequestTopology::try_new(2, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 6>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(275).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    for beyond in [2_u32, 3, 63, u32::MAX] {
        assert!(
            table
                .admit_control(
                    ControlLane::PtRouteAck { ring_index: beyond },
                    ControlPhase::PtRouteAck,
                    0x2750,
                )
                .is_err(),
            "ring {beyond} does not exist on a two-ring topology"
        );
    }
    assert!(
        table
            .admit_control(
                ControlLane::PtRouteAck { ring_index: 1 },
                ControlPhase::PtRouteAck,
                0x2751,
            )
            .is_ok()
    );
}

/// Sweep A051-A054. `terminalize_application` re-checks the whole provenance
/// of a `CapturedApplication` before it converts it into the affine
/// `TerminalApplication`. The token is unforgeable from outside the crate, but
/// it is detached -- it does not borrow the table -- so between capture and
/// disposition the entry can move. Each field is a separate decision and gets
/// its own drifted token here; the value must come back untouched every time.
#[test]
fn terminalize_application_rechecks_every_captured_field() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(281).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(281, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application capture");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let CapturedApplication {
        table_id,
        slot_index,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    } = captured;

    let good = || CapturedApplication {
        table_id,
        slot_index,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    };
    let other_epoch = NonZeroU64::new(birth_session_epoch.get() + 1).expect("nonzero");
    let drifted: [(&str, CapturedApplication, ApplicationError); 5] = [
        (
            "foreign table", // A051
            CapturedApplication {
                table_id: RequestTableId(NonZeroU64::new(table_id.0.get() + 1).expect("nonzero")),
                ..good()
            },
            ApplicationError::Key(KeyError::ForeignTable),
        ),
        (
            "slot index disagrees with the identity", // A052
            CapturedApplication {
                req_id: ReqId::try_new(req_id.generation(), SYSTEM_REQID_BASE)
                    .expect("system identity"),
                ..good()
            },
            ApplicationError::Key(KeyError::WrongClass),
        ),
        (
            "birth epoch drift", // A053
            CapturedApplication {
                birth_session_epoch: other_epoch,
                ..good()
            },
            ApplicationError::Key(KeyError::StaleBirth),
        ),
        (
            "birth generation drift", // A053
            CapturedApplication {
                birth_generation: birth_generation + 1,
                ..good()
            },
            ApplicationError::Key(KeyError::StaleBirth),
        ),
        (
            "wire session drift", // A054
            CapturedApplication {
                wire_session_epoch: other_epoch,
                ..good()
            },
            ApplicationError::Phase(PhaseError::WrongState),
        ),
    ];

    let before = application_entry_snapshot(&table, 0);
    for (name, token, expected) in drifted {
        match table.terminalize_application(token) {
            Ok(_) => panic!("{name} must not terminalize"),
            Err(preserved) => {
                assert_eq!(*preserved.error(), expected, "{name}");
                // The affine value is handed back, never consumed. It comes
                // back exactly as passed in -- drifted field included -- so
                // the stable field is the one to compare.
                assert_eq!(
                    preserved.value().slot_index,
                    slot_index,
                    "{name} preserves its token"
                );
            }
        }
        assert_eq!(application_entry_snapshot(&table, 0), before, "{name}");
    }
    // The undrifted token still works.
    assert!(table.terminalize_application(good()).is_ok());
}

/// Sweep A057-A059, the control mirror of the rule above.
#[test]
fn terminalize_control_rechecks_every_captured_field() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(282).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2820)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("visibility");
    let CaptureToken::Control(token) = table
        .begin_capture(282, cq_kind::COMPLETION, control.req_id())
        .expect("capture")
    else {
        panic!("control capture");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let CapturedControl {
        table_id,
        slot_index,
        lane,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    } = captured;

    let good = || CapturedControl {
        table_id,
        slot_index,
        lane,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    };
    let other_epoch = NonZeroU64::new(birth_session_epoch.get() + 1).expect("nonzero");
    let drifted: [(&str, CapturedControl, ControlError); 4] = [
        (
            "foreign table", // A057
            CapturedControl {
                table_id: RequestTableId(NonZeroU64::new(table_id.0.get() + 1).expect("nonzero")),
                ..good()
            },
            ControlError::Key(KeyError::ForeignTable),
        ),
        (
            "birth epoch drift", // A058
            CapturedControl {
                birth_session_epoch: other_epoch,
                ..good()
            },
            ControlError::Key(KeyError::StaleBirth),
        ),
        (
            "birth generation drift", // A058
            CapturedControl {
                birth_generation: birth_generation + 1,
                ..good()
            },
            ControlError::Key(KeyError::StaleBirth),
        ),
        (
            "wire session drift", // A059
            CapturedControl {
                wire_session_epoch: other_epoch,
                ..good()
            },
            ControlError::Phase(PhaseError::WrongState),
        ),
    ];

    let before = system_control_snapshot(&table, 1);
    for (name, token, expected) in drifted {
        match table.terminalize_control(token) {
            Ok(_) => panic!("{name} must not terminalize"),
            Err(preserved) => {
                assert_eq!(*preserved.error(), expected, "{name}");
                assert_eq!(
                    preserved.value().req_id,
                    req_id,
                    "{name} preserves its token"
                );
            }
        }
        assert_eq!(system_control_snapshot(&table, 1), before, "{name}");
    }
    assert!(table.terminalize_control(good()).is_ok());
}

/// Sweep A070, A071, A073, B0.4, B0.5, B0.6, B1.3.
///
/// The fence-path entry points were the least-watched part of the module: five
/// of the eleven key-validator call sites had no signal at all, and two of
/// those hand out the affine completion/release capability -- the same hazard
/// round 1 graded Important for `withdraw_unpublished_application`. This pins
/// the mode gate, the wire-state gate and key provenance on every one of them.
#[test]
fn every_fence_path_entry_validates_its_mode_state_and_key() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(283).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let dead = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));

    // A071, A073: the fence entries refuse an Active table outright.
    assert!(matches!(
        table.terminalize_application_after_fence(dead.key()),
        Err(ApplicationError::Phase(PhaseError::TableNotActive))
    ));
    assert!(matches!(
        table.retain_after_fence(dead.key()),
        Err(ApplicationError::Phase(PhaseError::TableNotActive))
    ));

    // A070: retain requires a Visible entry; this one is PreparedNotVisible.
    table.begin_fence().expect("fences");
    let before = application_entry_snapshot(&table, 0);
    assert!(matches!(
        table.retain_after_fence(dead.key()),
        Err(ApplicationError::Phase(PhaseError::WrongState))
    ));
    assert_eq!(application_entry_snapshot(&table, 0), before);

    // Build the later-occupant collision, then drive every fence-path entry
    // with the dead operation's key (B0.4, B0.5, B0.6).
    let receipt = table
        .withdraw_unpublished_application(dead.key())
        .expect("terminalizes")
        .complete(clearance(&empty_context()), 0, 0);
    table
        .rebind_session(NonZeroU64::new(284).expect("nonzero"), topology)
        .expect("rebinds");
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("old-epoch receipt reclaims"));
    let live = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("fresh epoch re-admits"));
    assert_eq!(dead.key().birth_generation, live.key().birth_generation);
    assert_ne!(
        dead.key().birth_session_epoch,
        live.key().birth_session_epoch
    );
    table
        .mark_application_visible(live.key())
        .expect("visibility");
    table.record_cancel(live.key()).expect("cancel intent");

    // pcancel_target is not fence-gated, so it is reachable right here.
    assert_eq!(
        table.pcancel_target(dead.key()), // B0.4
        Err(ApplicationError::Key(KeyError::StaleBirth))
    );
    assert!(
        table
            .pcancel_target(live.key())
            .expect("live key derives a target")
            .is_some()
    );

    table.begin_fence().expect("fences again");
    let before = application_entry_snapshot(&table, 0);
    assert!(matches!(
        table.retain_after_fence(dead.key()), // B0.5
        Err(ApplicationError::Key(KeyError::StaleBirth))
    ));
    assert!(matches!(
        table.terminalize_application_after_fence(dead.key()), // B0.6
        Err(ApplicationError::Key(KeyError::StaleBirth))
    ));
    assert_eq!(application_entry_snapshot(&table, 0), before);
    assert_eq!(
        completed.load(Ordering::Relaxed),
        1,
        "only the first epoch's own request ever completed"
    );

    // B1.3: the control fence entry, with a same-epoch generation collision.
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(285).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("control table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let dead = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2850)
        .unwrap_or_else(|_| panic!("control admits"));
    let (_continuation, release) = table
        .withdraw_unpublished_control(dead.key())
        .expect("control terminalizes")
        .release();
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("same-epoch release reclaims"));
    let live = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2851)
        .unwrap_or_else(|_| panic!("lane re-admits"));
    table.mark_control_visible(live.key()).expect("visibility");
    assert!(matches!(
        table.terminalize_control_after_fence(dead.key()),
        Err(ControlError::Phase(PhaseError::TableNotActive))
    ));
    table.begin_fence().expect("fences");
    let before = system_control_snapshot(&table, 1);
    assert!(matches!(
        table.terminalize_control_after_fence(dead.key()), // B1.3
        Err(ControlError::Key(KeyError::StaleBirth))
    ));
    assert_eq!(system_control_snapshot(&table, 1), before);
}

/// Sweep A016, A083, A086.
///
/// Three guards that no sequence of public calls can reach, because an earlier
/// invariant already excludes their input. They are still real decisions --
/// a later slice could weaken the invariant -- so each is proven by driving
/// the guarded function directly with the input it exists to reject. This is
/// the honest alternative to calling them "defensive" and leaving them
/// unwatched.
#[test]
fn internal_guards_reject_inputs_the_public_api_cannot_produce() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(286).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");

    // A083: an application key whose slot index is not in the application
    // class. `validate_application_key` classifies rather than trusting.
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    for wrong_class in [
        SYSTEM_REQID_BASE,
        GLOBAL_EXTERNAL_CHANGE_ACK_REQID,
        u32::MAX,
    ] {
        let key = ApplicationKey {
            slot_index: wrong_class,
            ..admission.key()
        };
        assert_eq!(
            table.validate_application_key(key),
            Err(ApplicationError::Key(KeyError::WrongClass)),
            "slot index {wrong_class} is not an application slot"
        );
    }
    assert_eq!(table.validate_application_key(admission.key()), Ok(0));

    // A086: a control key whose slot index disagrees with the slot its lane
    // resolves to. The lane is authoritative; the carried index is checked
    // against it rather than used.
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2860)
        .unwrap_or_else(|_| panic!("control admits"));
    for wrong_slot in [0_u32, SYSTEM_REQID_BASE, GLOBAL_EXTERNAL_CHANGE_ACK_REQID] {
        let key = ControlKey {
            slot_index: wrong_slot,
            ..control.key()
        };
        assert!(
            matches!(
                table.validate_control_key(key),
                Err(ControlError::Key(KeyError::WrongClass))
            ),
            "slot index {wrong_slot} is not this lane's slot"
        );
    }
    assert!(table.validate_control_key(control.key()).is_ok());

    // Admission's own classify guard is deliberately NOT tested here. A
    // corrupted free head does fail closed, but with `AdmissionError::Full`
    // from the bounds check either way, so no input distinguishes the guard.
    // It is on the sweep allowlist and its deadness is proven in
    // `topology_self_checks_are_dead_by_construction`.
    let _ = (pended, completed);
}

/// Sweep allowlist: A002, A003, A097.
///
/// Guards the sweep reports as survivors and that no test can kill, because no
/// input reaches them. Rather than assert that, this establishes the property
/// that makes each one unreachable. If a later change falsifies one of those
/// properties, this test fails even though the sweep would still call the
/// mutant a survivor.
///
/// On coverage, precisely: the legal `(ring_count, max_inflight)` space is
/// about 10^9 pairs and is not enumerable here. Each property below depends on
/// one axis only -- slot 0 is an application slot whenever `max_inflight > 0`;
/// the last system index classifies whenever `ring_count <= MAX_RING_COUNT` --
/// so this checks both bounds of each axis plus interior points, and the lane
/// round trip exhaustively over every lane of every ring of each sampled
/// topology. That is a sample, not the whole rectangle, and it is described
/// that way here and in the sweep's allowlist rather than overclaimed.
#[test]
fn topology_self_checks_are_dead_by_construction() {
    // A002/A003 live in `RequestTopology::try_new` after its bounds checks, so
    // their domain is exactly the legal (ring_count, max_inflight) rectangle.
    let ring_counts = [MIN_RING_COUNT, 2, 3, 17, MAX_RING_COUNT];
    let inflights = [1_u32, 2, 4096, MAX_INFLIGHT - 1, MAX_INFLIGHT];
    let mut checked = 0_u32;
    for ring_count in ring_counts {
        for max_inflight in inflights {
            let topology =
                RequestTopology::try_new(ring_count, max_inflight).expect("legal topology");
            // A002: slot 0 is always the first application slot.
            assert!(matches!(
                classify_table_index(topology, 0),
                Ok(ReqIndexClass::Application { index: 0 })
            ));
            // A003: the last system slot always classifies, and the global
            // acknowledgement index is always the external-change lane.
            let last_system = SYSTEM_REQID_BASE + ring_count * SYSTEM_REQUEST_SLOTS_PER_RING - 1;
            assert!(classify_table_index(topology, last_system).is_ok());
            assert!(matches!(
                classify_table_index(topology, GLOBAL_EXTERNAL_CHANGE_ACK_REQID),
                Ok(ReqIndexClass::ExternalChangeAck)
            ));
            // A097: `control_storage` computes a slot index and then asserts
            // it classifies back to the lane's own class. Round-trip every
            // lane on every ring of this topology.
            for ring_index in 0..ring_count {
                for (lane, expected) in [
                    (
                        ControlLane::OpenLifecycle { ring_index },
                        ReqIndexClass::OpenLifecycle { ring_index },
                    ),
                    (
                        ControlLane::PtRouteAck { ring_index },
                        ReqIndexClass::PtRouteAck { ring_index },
                    ),
                    (
                        ControlLane::PtExternalSafeAck { ring_index },
                        ReqIndexClass::PtExternalSafeAck { ring_index },
                    ),
                ] {
                    let storage = control_storage(topology, lane).expect("lane resolves");
                    assert_eq!(
                        classify_table_index(topology, storage.slot_index()),
                        Ok(expected),
                        "{lane:?} round trip"
                    );
                    // ...and the inverse. `begin_capture` and
                    // `validate_control_key` both re-derive a lane from a slot
                    // index and compare it with the lane recorded in that slot.
                    // Those comparisons are dead because lane -> slot_index ->
                    // class -> lane is the identity, which is what this pins.
                    assert_eq!(
                        control_lane_from_class(expected),
                        Some(lane),
                        "{lane:?} inverse round trip"
                    );
                    checked += 1;
                }
            }
            assert!(control_storage(topology, ControlLane::ExternalChangeAck).is_ok());
            assert_eq!(
                control_lane_from_class(ReqIndexClass::ExternalChangeAck),
                Some(ControlLane::ExternalChangeAck)
            );
        }
    }
    assert!(
        checked >= 3 * 5 * (1 + 2 + 3 + 17 + 64),
        "the sweep saw {checked} lane round trips, which is too few to be exhaustive"
    );

    // `admit_application` classifies its free-list head before using it. The
    // constructor pins `application.len() == topology.max_inflight`, so every
    // index the backing can hold classifies as an application slot and every
    // index it cannot is rejected by the `get_mut` below the guard with the
    // same `AdmissionError::Full`. That is what makes the guard unreachable.
    for max_inflight in [1_u32, 2, 8, 4096] {
        let topology = RequestTopology::try_new(1, max_inflight).expect("legal topology");
        for index in 0..max_inflight {
            assert!(
                matches!(
                    classify_table_index(topology, index),
                    Ok(ReqIndexClass::Application { index: got }) if got == index
                ),
                "index {index} is inside a {max_inflight}-slot backing"
            );
        }
        assert!(
            !matches!(
                classify_table_index(topology, max_inflight),
                Ok(ReqIndexClass::Application { .. })
            ),
            "the first index past the backing is not an application slot"
        );
    }
    // And the constructor really does pin the two together.
    let topology = RequestTopology::try_new(1, 2).expect("legal topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    assert_eq!(
        RequestTable::try_new(
            NonZeroU64::new(1).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .err(),
        Some(TableInitError::ApplicationLength)
    );

    // The same invariant on the control side is what makes
    // `control_storage`'s ring-range check unreachable: an out-of-range ring
    // produces a backing index past the end of `_system`, and the caller's
    // `get_mut` refuses it with the same `RingOutOfRange`.
    let topology = RequestTopology::try_new(2, 1).expect("legal topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    assert_eq!(
        RequestTable::try_new(
            NonZeroU64::new(1).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .err(),
        Some(TableInitError::SystemLength),
        "a two-ring topology needs six system slots, not three"
    );
    for ring_count in [MIN_RING_COUNT, 2, 7, MAX_RING_COUNT] {
        let topology = RequestTopology::try_new(ring_count, 1).expect("legal topology");
        let beyond = ControlLane::PtRouteAck {
            ring_index: ring_count,
        };
        let storage = control_storage(topology, beyond);
        // Whichever guard fires, the answer is the same one, which is exactly
        // why no input can tell them apart.
        assert!(matches!(
            storage,
            Err(ControlAdmissionError::RingOutOfRange)
        ));
    }
}

/// Sweep kind C, the relaxation direction. Disabling a mode gate outright is
/// caught by the existing Draining tests; relaxing one to admit exactly
/// `Fencing` was not caught anywhere. Design section 5.3: a fence closes
/// admission and new visibility while leaving already-stable candidates
/// capturable, so publishing a *new* wire identity into a session that is
/// being torn down must be refused at every door.
#[test]
fn a_fenced_session_publishes_no_new_wire_identity() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 2).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(291).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let unpublished = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    let retained = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(retained.key())
        .expect("visibility");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x2910)
        .unwrap_or_else(|_| panic!("control admits"));

    table.begin_fence().expect("fences");
    assert_eq!(table.mode(), TableMode::Fencing);
    let before_app = application_entry_snapshot(&table, 0);
    let before_ctl = system_control_snapshot(&table, 1);

    assert_eq!(
        table.mark_application_visible(unpublished.key()),
        Err(ApplicationError::Phase(PhaseError::TableNotActive)),
        "a fence closes new application visibility"
    );
    assert_eq!(
        table.mark_control_visible(control.key()),
        Err(ControlError::Phase(PhaseError::TableNotActive)),
        "a fence closes new control visibility"
    );
    assert_eq!(
        table.begin_application_phase(
            retained.key(),
            ApplicationPhase::new(op::WRITE).expect("application phase")
        ),
        Err(ApplicationError::Phase(PhaseError::TableNotActive)),
        "a fence starts no new application phase"
    );
    assert_eq!(
        table.begin_control_phase(control.key(), ControlPhase::PtRouteAck),
        Err(ControlError::Phase(PhaseError::TableNotActive)),
        "a fence starts no new control phase"
    );
    assert_eq!(application_entry_snapshot(&table, 0), before_app);
    assert_eq!(system_control_snapshot(&table, 1), before_ctl);
}

/// Sweep kind C, the tightening direction. The fence exists so an
/// already-stable candidate can still be drained and classified before the
/// session is rebound. If that gate were tightened to `Active` only, the
/// behaviour would vanish silently -- and 05-irp-dispatch section 17.2 makes a
/// wrong NO_CANDIDATE classification a durable-correctness fault, because
/// NO_CANDIDATE may resubmit while SUCCESS_CANDIDATE must never.
#[test]
fn a_fenced_session_still_captures_an_already_stable_candidate() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(292).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    table.begin_fence().expect("fences");
    let token = table
        .begin_capture(292, cq_kind::COMPLETION, admission.req_id())
        .expect("a fenced table still captures a stable candidate");
    let CaptureToken::Application(token) = token else {
        panic!("application capture");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let terminal = table
        .terminalize_application(captured)
        .unwrap_or_else(|_| panic!("terminalize"));
    let receipt = terminal.complete(clearance(&empty_context()), 0, 0);
    table
        .reclaim_completed(receipt)
        .unwrap_or_else(|_| panic!("reclaim"));
}

/// Sweep kind D on `pcancel_target`'s disqualifier. Visibility and opcode
/// eligibility were pinned; recorded cancellation intent was not, so the
/// "exact" matrix never covered the visible + eligible + never-cancelled cell.
#[test]
fn pcancel_target_requires_recorded_cancel_intent() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(293).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    // Visible and PCancel-eligible, but nobody asked for a cancel.
    assert_eq!(
        table.pcancel_target(admission.key()),
        Ok(None),
        "an uncancelled request is not a PCancel target"
    );
    table.record_cancel(admission.key()).expect("cancel intent");
    assert!(
        table
            .pcancel_target(admission.key())
            .expect("derives")
            .is_some(),
        "recorded intent makes it a target"
    );
}

/// `rebind_session` enumerates the application wire states that block a
/// rebind. `PreparedNotVisible` and `Capturing` were covered; `Visible` and
/// `Captured` were not, so half the predicate had no signal.
///
/// Accepting `Visible` would reset a published identity's generation in a
/// fresh epoch without the caller ever proving the old-epoch phase had no
/// stable candidate -- the reordering 06-locking section 9.3 forbids.
/// Accepting `Captured` would rebind while an unconsumed `CapturedApplication`
/// is still outstanding against the old wire identity.
#[test]
fn session_rebind_rejects_a_visible_or_captured_entry() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");

    for stop_at_captured in [false, true] {
        let pended = std::sync::Arc::new(AtomicU32::new(0));
        let completed = std::sync::Arc::new(AtomicU32::new(0));
        let (mut application, mut system, mut global) = backing::<1, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(294).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        let admission = table
            .admit_application(
                ApplicationPhase::new(op::READ).expect("application phase"),
                CompletionOwner::new(CountingSink { pended, completed }),
            )
            .unwrap_or_else(|_| panic!("admits"));
        table
            .mark_application_visible(admission.key())
            .expect("visibility");
        // Held across the rebind attempt: the entry is `Captured` precisely
        // because this affine value is still outstanding against the old wire
        // identity, so it must outlive the call being tested.
        let mut outstanding = None;
        let expected_state = if stop_at_captured {
            let CaptureToken::Application(token) = table
                .begin_capture(294, cq_kind::COMPLETION, admission.req_id())
                .expect("capture")
            else {
                panic!("application capture");
            };
            outstanding = Some(
                table
                    .install_application_candidate(token)
                    .unwrap_or_else(|_| panic!("install")),
            );
            WireState::Captured
        } else {
            WireState::Visible
        };
        table.begin_fence().expect("fences");
        assert_eq!(
            table.rebind_session(NonZeroU64::new(295).expect("nonzero"), topology),
            Err(SessionTransitionError::UnresolvedApplicationPhase),
            "{expected_state:?} must block a rebind"
        );
        assert_eq!(table.session_epoch.get(), 294, "the epoch did not move");
        assert_eq!(table.mode(), TableMode::Fencing);
        assert_eq!(outstanding.is_some(), stop_at_captured);
        drop(outstanding);
    }
}

/// Sweep 76, 82, 83. The disposition guards are disjunctions, and a
/// disjunction is only as watched as its weakest operand. The drifted tokens
/// above trip the *first* matching operand; these three trip one operand each
/// with everything else exact.
#[test]
fn terminalize_application_watches_each_disposition_operand() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(301).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(301, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application capture");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let CapturedApplication {
        table_id,
        slot_index,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    } = captured;
    let good = || CapturedApplication {
        table_id,
        slot_index,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    };

    // 76: the slot index is not in the application class at all. The identity
    // agrees with it, so the first operand of the same guard stays false and
    // only the classification decides.
    let outside = CapturedApplication {
        slot_index: SYSTEM_REQID_BASE,
        req_id: ReqId::try_new(req_id.generation(), SYSTEM_REQID_BASE).expect("system identity"),
        ..good()
    };
    match table.terminalize_application(outside) {
        Ok(_) => panic!("a control-class slot index must not terminalize"),
        Err(preserved) => assert_eq!(
            *preserved.error(),
            ApplicationError::Key(KeyError::WrongClass)
        ),
    }

    // 82: identity drift alone -- same slot, same birth, same session, one
    // generation further on.
    let successor = CapturedApplication {
        req_id: ReqId::try_new(req_id.generation() + 1, slot_index).expect("successor"),
        ..good()
    };
    match table.terminalize_application(successor) {
        Ok(_) => panic!("a successor identity must not terminalize"),
        Err(preserved) => assert_eq!(
            *preserved.error(),
            ApplicationError::Phase(PhaseError::WrongState)
        ),
    }

    // 83: wire-state drift alone. Retaining the candidate moves the entry out
    // of `Captured` while leaving every other field of the token exact.
    table
        .retain_application(good())
        .unwrap_or_else(|_| panic!("retain"));
    match table.terminalize_application(good()) {
        Ok(_) => panic!("a retained entry must not terminalize from a stale token"),
        Err(preserved) => assert_eq!(
            *preserved.error(),
            ApplicationError::Phase(PhaseError::WrongState)
        ),
    }
}

/// Sweep 93, 94 -- the control mirror of the two operands above.
#[test]
fn terminalize_control_watches_each_disposition_operand() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(302).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x3020)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("visibility");
    let CaptureToken::Control(token) = table
        .begin_capture(302, cq_kind::COMPLETION, control.req_id())
        .expect("capture")
    else {
        panic!("control capture");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let CapturedControl {
        table_id,
        slot_index,
        lane,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    } = captured;
    let good = || CapturedControl {
        table_id,
        slot_index,
        lane,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    };

    // 93: identity drift alone.
    let successor = CapturedControl {
        req_id: ReqId::try_new(req_id.generation() + 1, slot_index).expect("successor"),
        ..good()
    };
    match table.terminalize_control(successor) {
        Ok(_) => panic!("a successor identity must not terminalize"),
        Err(preserved) => assert_eq!(
            *preserved.error(),
            ControlError::Phase(PhaseError::WrongState)
        ),
    }

    // 94: wire-state drift alone.
    table
        .retain_control(good())
        .unwrap_or_else(|_| panic!("retain"));
    match table.terminalize_control(good()) {
        Ok(_) => panic!("a retained lane must not terminalize from a stale token"),
        Err(preserved) => assert_eq!(
            *preserved.error(),
            ControlError::Phase(PhaseError::WrongState)
        ),
    }
}

/// Sweep 125. `terminalize_application_after_fence` accepts only three wire
/// states. Cancellation intent was pinned; the state set was not, so a
/// quarantined entry -- one whose candidate could not be trusted -- could be
/// terminalized straight out of quarantine by the fence path.
#[test]
fn the_fence_terminalizer_accepts_only_its_three_wire_states() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(303).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(303, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application capture");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    table
        .quarantine_application(captured)
        .unwrap_or_else(|_| panic!("quarantine"));
    // Intent is recorded, so only the wire-state operand can refuse.
    table.record_cancel(admission.key()).expect("cancel intent");
    table.begin_fence().expect("fences");
    let before = application_entry_snapshot(&table, 0);
    assert!(matches!(
        table.terminalize_application_after_fence(admission.key()),
        Err(ApplicationError::Phase(PhaseError::WrongState))
    ));
    assert_eq!(application_entry_snapshot(&table, 0), before);
}

/// Sweep 177, 186. The two session transitions each accept exactly one mode.
/// Fencing an already-fenced table, or rebinding one that was never fenced,
/// must be refused -- a rebind from `Active` would rotate the epoch with live
/// unresolved wire identities still published.
#[test]
fn session_transitions_accept_exactly_one_mode_each() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(304).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    assert_eq!(table.mode(), TableMode::Active);
    assert_eq!(
        table.rebind_session(NonZeroU64::new(305).expect("nonzero"), topology),
        Err(SessionTransitionError::WrongMode),
        "an Active table has not been fenced"
    );
    assert_eq!(table.session_epoch.get(), 304);

    table.begin_fence().expect("fences");
    assert_eq!(
        table.begin_fence(),
        Err(SessionTransitionError::WrongMode),
        "a fence is not re-entrant"
    );
    assert_eq!(table.mode(), TableMode::Fencing);

    table
        .rebind_session(NonZeroU64::new(305).expect("nonzero"), topology)
        .expect("a fenced table rebinds");
    assert_eq!(table.mode(), TableMode::Active);
    assert_eq!(
        table.begin_fence(),
        Ok(()),
        "and the rebound table can fence again"
    );
}

/// Sweep 179, 180, 182 -- the tightening direction on three disposition gates.
///
/// These three refuse only `Draining`, which means they are legal while
/// `Fencing`: design section 5.3 lets an already-stable candidate be resolved
/// during a fence, and resolving it means retaining or terminalizing it. If
/// those gates were tightened to `Active` only, the fence could never be
/// drained and the behaviour would disappear with nothing going red.
#[test]
fn a_fenced_session_still_resolves_its_outstanding_candidates() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 2).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(306).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let retained = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(retained.key())
        .expect("visibility");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x3060)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("control visibility");

    // Capture both while Active, then fence with both candidates outstanding.
    let CaptureToken::Application(app_token) = table
        .begin_capture(306, cq_kind::COMPLETION, retained.req_id())
        .expect("application capture")
    else {
        panic!("application capture");
    };
    let app_captured = table
        .install_application_candidate(app_token)
        .unwrap_or_else(|_| panic!("install application"));
    let CaptureToken::Control(ctl_token) = table
        .begin_capture(306, cq_kind::COMPLETION, control.req_id())
        .expect("control capture")
    else {
        panic!("control capture");
    };
    let ctl_captured = table
        .install_control_candidate(ctl_token)
        .unwrap_or_else(|_| panic!("install control"));

    table.begin_fence().expect("fences");
    assert_eq!(table.mode(), TableMode::Fencing);

    // 179: a fenced table still retains an application candidate.
    table
        .retain_application(app_captured)
        .unwrap_or_else(|_| panic!("a fenced table retains an application candidate"));
    // 182: ...and still terminalizes a control candidate.
    let terminal = table
        .terminalize_control(ctl_captured)
        .unwrap_or_else(|_| panic!("a fenced table terminalizes a control candidate"));
    let (continuation, release) = terminal.release();
    assert_eq!(continuation, 0x3060);
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("reclaim"));

    // 180: and the control retain door, on a second lane, likewise.
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(307).expect("nonzero"),
        RequestTopology::try_new(1, 1).expect("valid topology"),
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x3070)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("visibility");
    let CaptureToken::Control(token) = table
        .begin_capture(307, cq_kind::COMPLETION, control.req_id())
        .expect("capture")
    else {
        panic!("control capture");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    table.begin_fence().expect("fences");
    table
        .retain_control(captured)
        .unwrap_or_else(|_| panic!("a fenced table retains a control candidate"));
}

/// `pcancel_target` deliberately has no `TableMode` gate, and round 3 asked
/// whether that is a decision or an omission. It is a decision, pinned here so
/// a later slice that adds a gate turns this red rather than silently changing
/// an observational query into a fallible one.
///
/// The derivation allocates no entry, advances no generation and mutates no
/// state (design section 2.2 item 14), and the `CancelTarget` it returns
/// carries the session epoch, so a target derived against a session that is
/// being torn down is rejected by its epoch rather than by a mode check.
#[test]
fn pcancel_target_is_observational_in_every_table_mode() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(311).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    table.record_cancel(admission.key()).expect("cancel intent");

    let expected = table
        .pcancel_target(admission.key())
        .expect("Active derives")
        .expect("a cancelled visible phase is a target");
    assert_eq!(expected.req_id(), admission.req_id());
    assert_eq!(expected.session_epoch().get(), 311);

    let before = application_entry_snapshot(&table, 0);
    for mode in [TableMode::Fencing, TableMode::Draining] {
        match mode {
            TableMode::Fencing => table.begin_fence().expect("fences"),
            TableMode::Draining => table.begin_drain(),
            TableMode::Active => unreachable!(),
        }
        assert_eq!(table.mode(), mode);
        let target = table
            .pcancel_target(admission.key())
            .unwrap_or_else(|error| panic!("{mode:?} still derives, got {error:?}"))
            .unwrap_or_else(|| panic!("{mode:?} still names the same target"));
        assert_eq!(target.req_id(), expected.req_id(), "{mode:?}");
        assert_eq!(
            target.session_epoch(),
            expected.session_epoch(),
            "{mode:?} carries the epoch that makes a stale target rejectable"
        );
        assert_eq!(
            application_entry_snapshot(&table, 0),
            before,
            "{mode:?} derivation mutates nothing"
        );
    }
}

/// Sweep 209. `begin_capture` distinguishes an unoccupied control lane from a
/// retired one. Round 3 found this by building the mutant the hand-written
/// operator-E table could not express: moving `Available` into the `Retired`
/// arm makes the two indistinguishable to the caller, reachable through the
/// public API alone, with nothing in the suite noticing.
///
/// The application mirror was already covered by the capture-error matrix; the
/// control side was not, which is what made it an accident rather than a
/// decision.
#[test]
fn capture_distinguishes_an_unoccupied_control_lane_from_a_retired_one() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(321).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let lane_index = SYSTEM_REQID_BASE + 1;

    // Freshly constructed: the lane is Available, i.e. nothing was ever
    // admitted on it.
    assert!(
        matches!(
            table.begin_capture(
                321,
                cq_kind::COMPLETION,
                ReqId::try_new(1, lane_index).expect("identity"),
            ),
            Err(CaptureError::Vacant)
        ),
        "an unoccupied lane is Vacant, not Retired"
    );

    // Drive the same lane to Retired by exhausting its generation, and confirm
    // the answer changes.
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x3210)
        .unwrap_or_else(|_| panic!("control admits"));
    let ControlSlotState::Occupied { req_id, .. } =
        &mut table._system.get_mut(1).expect("PT route lane").state
    else {
        panic!("occupied control");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, lane_index).expect("maximum identity");
    let (_continuation, release) = table
        .withdraw_unpublished_control(control.key())
        .expect("terminalizes")
        .release();
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("maximum-generation release reclaims"));
    assert_eq!(
        system_control_snapshot(&table, 1),
        ControlEntrySnapshot::Retired {
            generation: REQ_GENERATION_MAX,
        }
    );
    assert!(
        matches!(
            table.begin_capture(
                321,
                cq_kind::COMPLETION,
                ReqId::try_new(1, lane_index).expect("identity"),
            ),
            Err(CaptureError::Retired)
        ),
        "a retired lane is Retired, not Vacant"
    );
}

/// Sweep 210, 211, 212. `terminalize_control` resolves the slot through a
/// `match` arm guard rather than an `if`, and both of its operands were
/// unwatched -- the whole guard could be deleted with the suite still green.
/// The identical guards in `reclaim_control` and `finish_control_disposition`
/// were already covered, so this was a gap, not a decision.
#[test]
fn terminalize_control_arm_guard_pins_both_of_its_operands() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(322).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::PtRouteAck { ring_index: 0 };
    let control = table
        .admit_control(lane, ControlPhase::PtRouteAck, 0x3220)
        .unwrap_or_else(|_| panic!("control admits"));
    table
        .mark_control_visible(control.key())
        .expect("visibility");
    let CaptureToken::Control(token) = table
        .begin_capture(322, cq_kind::COMPLETION, control.req_id())
        .expect("capture")
    else {
        panic!("control capture");
    };
    let captured = table
        .install_control_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    let CapturedControl {
        table_id,
        slot_index,
        lane,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    } = captured;
    let good = || CapturedControl {
        table_id,
        slot_index,
        lane,
        birth_session_epoch,
        birth_generation,
        wire_session_epoch,
        req_id,
    };

    let before = system_control_snapshot(&table, 1);
    // Operand 1: the lane resolves to a different slot than the token names.
    //
    // The token has to stay self-consistent for this to isolate the first
    // operand: slot index and identity agree with each OTHER and disagree only
    // with the lane. A token that drifts the slot index alone falsifies both
    // operands at once, so dropping either one still rejects and the mutant
    // survives -- which is exactly how the first version of this test let the
    // operand through.
    let coherent_but_wrong_slot = SYSTEM_REQID_BASE;
    assert_ne!(
        coherent_but_wrong_slot, slot_index,
        "must be a different slot"
    );
    let wrong_slot = CapturedControl {
        slot_index: coherent_but_wrong_slot,
        req_id: ReqId::try_new(req_id.generation(), coherent_but_wrong_slot)
            .expect("coherent identity"),
        ..good()
    };
    match table.terminalize_control(wrong_slot) {
        Ok(_) => panic!("a slot index the lane does not resolve to must not terminalize"),
        Err(preserved) => assert_eq!(*preserved.error(), ControlError::Key(KeyError::WrongClass)),
    }
    assert_eq!(system_control_snapshot(&table, 1), before);

    // Operand 2: the identity names a different slot than the token does.
    let wrong_identity = CapturedControl {
        req_id: ReqId::try_new(req_id.generation(), slot_index + 1).expect("other slot"),
        ..good()
    };
    match table.terminalize_control(wrong_identity) {
        Ok(_) => panic!("an identity naming another slot must not terminalize"),
        Err(preserved) => assert_eq!(*preserved.error(), ControlError::Key(KeyError::WrongClass)),
    }
    assert_eq!(system_control_snapshot(&table, 1), before);

    assert!(table.terminalize_control(good()).is_ok());
}

/// Sweep 139, 142, 222, 223. What a rebind must carry across, as opposed to
/// what it must refuse.
///
/// A rebind refuses unresolved phases (proven elsewhere) but must *accept* an
/// entry parked in `Quarantined` or `GenerationExhausted`, heal the exhausted
/// one back to `BetweenPhases`, and reset the control lanes' generations --
/// including the global lane, which has its own separate branch. None of those
/// four decisions had a signal: the healing because its body assigns rather
/// than returning `Err`, and the rest because no test looked past the refusal.
///
/// Without the healing a retained entry that hit generation exhaustion is
/// stuck in `GenerationExhausted` forever and can never take another phase.
#[test]
fn a_rebind_carries_parked_entries_across_and_heals_exhaustion() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 2).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<2, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(323).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");

    // Slot 0 -> Quarantined.
    let quarantined = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(quarantined.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(323, cq_kind::COMPLETION, quarantined.req_id())
        .expect("capture")
    else {
        panic!("application capture");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    table
        .quarantine_application(captured)
        .unwrap_or_else(|_| panic!("quarantine"));

    // Slot 1 -> GenerationExhausted.
    let exhausted = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: pended.clone(),
                completed: completed.clone(),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(exhausted.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(323, cq_kind::COMPLETION, exhausted.req_id())
        .expect("capture")
    else {
        panic!("application capture");
    };
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    table
        .retain_application(captured)
        .unwrap_or_else(|_| panic!("retain"));
    let ApplicationSlotState::Live { req_id, .. } =
        &mut table.application.get_mut(1).expect("slot 1").state
    else {
        panic!("live application");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, 1).expect("maximum identity");
    assert_eq!(
        table.begin_application_phase(
            exhausted.key(),
            ApplicationPhase::new(op::WRITE).expect("application phase")
        ),
        Err(ApplicationError::Phase(PhaseError::GenerationExhausted))
    );

    // Move both control lanes off generation zero so the reset is observable,
    // the global one through its own separate branch.
    for (lane, phase, cont) in [
        (
            ControlLane::PtRouteAck { ring_index: 0 },
            ControlPhase::PtRouteAck,
            0x3231_u32,
        ),
        (
            ControlLane::ExternalChangeAck,
            ControlPhase::ExternalChangeAck,
            0x3232,
        ),
    ] {
        let admitted = table
            .admit_control(lane, phase, cont)
            .unwrap_or_else(|_| panic!("control admits"));
        assert_eq!(admitted.req_id().generation(), 1);
        let (_c, release) = table
            .withdraw_unpublished_control(admitted.key())
            .expect("terminalizes")
            .release();
        table
            .reclaim_control(release)
            .unwrap_or_else(|_| panic!("reclaims"));
    }
    assert_eq!(
        system_control_snapshot(&table, 1),
        ControlEntrySnapshot::Available { generation: 1 }
    );
    assert_eq!(
        global_control_snapshot(&table),
        ControlEntrySnapshot::Available { generation: 1 }
    );

    table.begin_fence().expect("fences");
    table
        .rebind_session(NonZeroU64::new(324).expect("nonzero"), topology)
        .expect("parked entries do not block a rebind");

    // The exhausted entry is healed and can take a phase again; the
    // quarantined one stays quarantined.
    let ApplicationSlotState::Live { wire_state, .. } =
        &table.application.get(1).expect("slot 1").state
    else {
        panic!("live application");
    };
    assert_eq!(
        *wire_state,
        WireState::BetweenPhases,
        "generation exhaustion is healed by the rebind"
    );
    let ApplicationSlotState::Live { wire_state, .. } =
        &table.application.first().expect("slot 0").state
    else {
        panic!("live application");
    };
    assert_eq!(
        *wire_state,
        WireState::Quarantined,
        "quarantine survives the rebind"
    );

    // Both lanes are back at generation zero -- the per-ring loop and the
    // global branch each did their half.
    assert_eq!(
        system_control_snapshot(&table, 1),
        ControlEntrySnapshot::Available { generation: 0 }
    );
    assert_eq!(
        global_control_snapshot(&table),
        ControlEntrySnapshot::Available { generation: 0 },
        "the global lane has its own reset branch"
    );
}

/// Sweep allowlist: the two `Pristine` capture alternatives.
///
/// `Pristine` is the state backing arrives in and never returns to. The
/// constructor demands it, then writes every slot to `Free` / `Available`
/// before returning, and nothing writes it back. Moving `Pristine` between
/// capture arms therefore cannot change an outcome for any table that exists.
#[test]
fn pristine_is_unreachable_once_a_table_exists() {
    let topology = RequestTopology::try_new(2, 3).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<3, 6>();
    // Arrives Pristine -- the constructor requires exactly that.
    assert!(
        application
            .iter()
            .all(|s| matches!(s.state, ApplicationSlotState::Pristine))
    );
    assert!(
        system
            .iter()
            .all(|s| matches!(s.state, ControlSlotState::Pristine))
    );
    let table = RequestTable::try_new(
        NonZeroU64::new(331).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    // ...and leaves the constructor Pristine nowhere.
    for index in 0..3 {
        assert!(
            !matches!(
                application_entry_snapshot(&table, index),
                ApplicationEntrySnapshot::Pristine
            ),
            "application slot {index} is still Pristine"
        );
    }
    for index in 0..6 {
        assert_ne!(
            system_control_snapshot(&table, index),
            ControlEntrySnapshot::Pristine,
            "control slot {index} is still Pristine"
        );
    }
    assert_ne!(
        global_control_snapshot(&table),
        ControlEntrySnapshot::Pristine
    );

    // And no transition writes it back. A source scan, because the property is
    // "nowhere in the module", which no single call sequence can establish.
    let mut assignments = Vec::new();
    for (offset, line) in REQTAB_SOURCE.lines().enumerate() {
        let text = line.trim();
        if text.starts_with("//") {
            continue;
        }
        for needle in [
            "= ApplicationSlotState::Pristine",
            "= ControlSlotState::Pristine",
        ] {
            if text.contains(needle) {
                assignments.push((offset + 1, text.to_owned()));
            }
        }
    }
    assert!(
        assignments.is_empty(),
        "reqtab.rs writes Pristine back at {assignments:?}, so the capture \
         alternatives allowlisted as unreachable may now be reachable"
    );
    // Anti-vacuity: the needle finds the constructors that DO produce Pristine,
    // so an empty result above means "no assignments", not "broken scan".
    assert!(
        REQTAB_SOURCE.contains("ApplicationSlotState::Pristine")
            && REQTAB_SOURCE.contains("ControlSlotState::Pristine"),
        "the scan needles no longer match anything at all"
    );
}

/// Sweep allowlist: `rebind_session`'s `if index == 0 { break; }`.
///
/// The reverse walk is `while let Some(index) = backing_index.checked_sub(1)`
/// with `backing_index = index`, so after visiting slot 0 the next iteration
/// computes `0.checked_sub(1) == None` and stops anyway. The `break` cannot
/// change which slots are visited -- which is what this shows, by rebinding a
/// multi-slot table and checking every slot, slot 0 included, was reset.
#[test]
fn a_rebind_visits_every_application_slot() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 4).expect("valid topology");
    let (mut application, mut system, mut global) = backing::<4, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(332).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    // Take all four slots BEFORE returning any, so each one is used once. The
    // free list is LIFO, so releasing between admissions would just hand the
    // same slot back every time.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(
            table
                .admit_application(
                    ApplicationPhase::new(op::READ).expect("application phase"),
                    CompletionOwner::new(CountingSink {
                        pended: pended.clone(),
                        completed: completed.clone(),
                    }),
                )
                .unwrap_or_else(|_| panic!("admits")),
        );
    }
    for admission in held {
        let receipt = table
            .withdraw_unpublished_application(admission.key())
            .expect("terminalizes")
            .complete(clearance(&empty_context()), 0, 0);
        table
            .reclaim_completed(receipt)
            .unwrap_or_else(|_| panic!("reclaims"));
    }
    for index in 0..4 {
        assert!(
            matches!(
                application_entry_snapshot(&table, index),
                ApplicationEntrySnapshot::Free { generation: 1, .. }
            ),
            "slot {index} should carry a used generation before the rebind"
        );
    }

    table.begin_fence().expect("fences");
    table
        .rebind_session(NonZeroU64::new(333).expect("nonzero"), topology)
        .expect("rebinds");

    // Every slot, index 0 included, was visited and reset.
    for index in 0..4 {
        assert!(
            matches!(
                application_entry_snapshot(&table, index),
                ApplicationEntrySnapshot::Free { generation: 0, .. }
            ),
            "slot {index} was not visited by the rebind walk"
        );
    }
    // And all four are usable again in the fresh epoch.
    for _ in 0..4 {
        assert!(
            table
                .admit_application(
                    ApplicationPhase::new(op::READ).expect("application phase"),
                    CompletionOwner::new(CountingSink {
                        pended: pended.clone(),
                        completed: completed.clone(),
                    }),
                )
                .is_ok()
        );
    }
}

/// Round 4, Critical. `capture_state_error` maps five wire states onto
/// `CaptureError`, and only `PreparedNotVisible` was ever exercised. Moving
/// `BetweenPhases`, `Quarantined` or `GenerationExhausted` into the
/// `Captured => CandidateInstalled` arm survived the whole suite, so a
/// duplicate or late completion against a retained, quarantined or exhausted
/// entry was reported to the caller as "a candidate is already installed".
///
/// Design section 6.1 requires every failure to have a distinct
/// `CaptureError`, so the mapping is an enumerated criterion, not an
/// implementation detail.
#[test]
fn capture_state_error_maps_every_unpublished_state_to_not_visible() {
    let pended = std::sync::Arc::new(AtomicU32::new(0));
    let completed = std::sync::Arc::new(AtomicU32::new(0));
    let topology = RequestTopology::try_new(1, 4).expect("valid topology");

    for (label, drive) in [
        ("PreparedNotVisible", 0_u8),
        ("BetweenPhases", 1),
        ("Quarantined", 2),
        ("GenerationExhausted", 3),
    ] {
        let (mut application, mut system, mut global) = backing::<4, 3>();
        let mut table = RequestTable::try_new(
            NonZeroU64::new(341).expect("nonzero"),
            topology,
            &mut application,
            &mut system,
            &mut global,
        )
        .expect("table");
        let admission = table
            .admit_application(
                ApplicationPhase::journaled_semantic(op::WRITE).expect("journaled phase"),
                CompletionOwner::new(CountingSink {
                    pended: pended.clone(),
                    completed: completed.clone(),
                }),
            )
            .unwrap_or_else(|_| panic!("{label}: admits"));

        if drive > 0 {
            table
                .mark_application_visible(admission.key())
                .unwrap_or_else(|_| panic!("{label}: visibility"));
        }
        match drive {
            1 | 2 => {
                let CaptureToken::Application(token) = table
                    .begin_capture(341, cq_kind::COMPLETION, admission.req_id())
                    .unwrap_or_else(|_| panic!("{label}: capture"))
                else {
                    panic!("{label}: application capture");
                };
                let captured = table
                    .install_application_candidate(token)
                    .unwrap_or_else(|_| panic!("{label}: install"));
                if drive == 1 {
                    table
                        .retain_application(captured)
                        .unwrap_or_else(|_| panic!("{label}: retain"));
                } else {
                    table
                        .quarantine_application(captured)
                        .unwrap_or_else(|_| panic!("{label}: quarantine"));
                }
            }
            3 => {
                // `begin_application_phase` starts from `BetweenPhases`, so
                // the entry has to be retained before its generation can be
                // driven to the ceiling.
                let CaptureToken::Application(token) = table
                    .begin_capture(341, cq_kind::COMPLETION, admission.req_id())
                    .unwrap_or_else(|_| panic!("{label}: capture"))
                else {
                    panic!("{label}: application capture");
                };
                let captured = table
                    .install_application_candidate(token)
                    .unwrap_or_else(|_| panic!("{label}: install"));
                table
                    .retain_application(captured)
                    .unwrap_or_else(|_| panic!("{label}: retain"));
                let ApplicationSlotState::Live { req_id, .. } =
                    &mut table.application.first_mut().expect("slot 0").state
                else {
                    panic!("{label}: live application");
                };
                *req_id = ReqId::try_new(REQ_GENERATION_MAX, 0).expect("maximum identity");
                assert_eq!(
                    table.begin_application_phase(
                        admission.key(),
                        ApplicationPhase::new(op::READ).expect("application phase")
                    ),
                    Err(ApplicationError::Phase(PhaseError::GenerationExhausted)),
                    "{label}: reaching the state"
                );
            }
            _ => {}
        }

        // Whatever identity the entry now carries, capturing it must report
        // NotVisible -- never CandidateInstalled, never CaptureInProgress.
        let current = match &table.application.first().expect("slot 0").state {
            ApplicationSlotState::Live { req_id, .. } => *req_id,
            _ => panic!("{label}: slot is no longer live"),
        };
        assert!(
            matches!(
                table.begin_capture(341, cq_kind::COMPLETION, current),
                Err(CaptureError::NotVisible)
            ),
            "{label} must map to NotVisible"
        );
    }

    // And the two states that genuinely are distinct still are.
    let (mut application, mut system, mut global) = backing::<4, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(342).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let admission = table
        .admit_application(
            ApplicationPhase::journaled_semantic(op::WRITE).expect("journaled phase"),
            CompletionOwner::new(CountingSink { pended, completed }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(admission.key())
        .expect("visibility");
    let CaptureToken::Application(token) = table
        .begin_capture(342, cq_kind::COMPLETION, admission.req_id())
        .expect("capture")
    else {
        panic!("application capture");
    };
    assert!(matches!(
        table.begin_capture(342, cq_kind::COMPLETION, admission.req_id()),
        Err(CaptureError::CaptureInProgress)
    ));
    let captured = table
        .install_application_candidate(token)
        .unwrap_or_else(|_| panic!("install"));
    assert!(matches!(
        table.begin_capture(342, cq_kind::COMPLETION, admission.req_id()),
        Err(CaptureError::CandidateInstalled)
    ));
    drop(captured);

    // Sweep allowlist: the `Visible` alternative of the same arm.
    //
    // Every call site of `capture_state_error` sits behind
    // `if *wire_state != WireState::Visible`, so `Visible` cannot reach it and
    // moving it between arms cannot change an outcome. The other four
    // alternatives are live and are pinned above; this one is dead, and the
    // property that makes it dead is the guard at each call site.
    let mut sites = 0_u32;
    let mut guarded = 0_u32;
    for (offset, line) in REQTAB_SOURCE.lines().enumerate() {
        if !line.contains("capture_state_error(") || line.trim_start().starts_with("const fn") {
            continue;
        }
        sites += 1;
        let preceding = REQTAB_SOURCE
            .lines()
            .nth(offset.saturating_sub(1))
            .unwrap_or_default();
        if preceding.contains("*wire_state != WireState::Visible") {
            guarded += 1;
        }
    }
    assert!(sites > 0, "the call-site scan matched nothing at all");
    assert_eq!(
        sites,
        guarded,
        "every capture_state_error call site must be guarded by `!= Visible`; \
         {} of {sites} are not",
        sites - guarded
    );

    // ...and behaviourally: a Visible entry captures rather than erroring.
    let (mut application, mut system, mut global) = backing::<4, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(345).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let visible = table
        .admit_application(
            ApplicationPhase::new(op::READ).expect("application phase"),
            CompletionOwner::new(CountingSink {
                pended: std::sync::Arc::new(AtomicU32::new(0)),
                completed: std::sync::Arc::new(AtomicU32::new(0)),
            }),
        )
        .unwrap_or_else(|_| panic!("admits"));
    table
        .mark_application_visible(visible.key())
        .expect("visibility");
    assert!(
        matches!(
            table.begin_capture(345, cq_kind::COMPLETION, visible.req_id()),
            Ok(CaptureToken::Application(_))
        ),
        "a Visible entry captures, so Visible never reaches capture_state_error"
    );
}

/// Round 4, Important. `rebind_session` heals retired control capacity in two
/// mirror branches, one for the per-ring system lanes and one for the global
/// external-change lane. The system branch was covered; the global one was
/// reached only from `Available`, never from `Retired`.
///
/// Without the global branch, once that lane retires at the maximum
/// generation it stays `Retired` across every later rebind and
/// `admit_control(ExternalChangeAck, ..)` is permanently
/// `SessionGenerationExhausted`.
#[test]
fn the_global_lane_retirement_heals_across_a_rebind() {
    let topology = RequestTopology::try_new(1, 1).expect("valid topology");
    let (mut application, mut system, mut global) = control_backing::<1, 3>();
    let mut table = RequestTable::try_new(
        NonZeroU64::new(343).expect("nonzero"),
        topology,
        &mut application,
        &mut system,
        &mut global,
    )
    .expect("table");
    let lane = ControlLane::ExternalChangeAck;
    let control = table
        .admit_control(lane, ControlPhase::ExternalChangeAck, 0x3430)
        .unwrap_or_else(|_| panic!("global lane admits"));
    let ControlSlotState::Occupied { req_id, .. } = &mut table._global.state else {
        panic!("occupied global lane");
    };
    *req_id = ReqId::try_new(REQ_GENERATION_MAX, GLOBAL_EXTERNAL_CHANGE_ACK_REQID)
        .expect("maximum global identity");
    let (_continuation, release) = table
        .withdraw_unpublished_control(control.key())
        .expect("terminalizes")
        .release();
    table
        .reclaim_control(release)
        .unwrap_or_else(|_| panic!("maximum-generation release reclaims"));
    assert_eq!(
        global_control_snapshot(&table),
        ControlEntrySnapshot::Retired {
            generation: REQ_GENERATION_MAX,
        }
    );
    assert!(
        table
            .admit_control(lane, ControlPhase::ExternalChangeAck, 0x3431)
            .is_err()
    );

    table.begin_fence().expect("fences");
    table
        .rebind_session(NonZeroU64::new(344).expect("nonzero"), topology)
        .expect("rebinds");
    assert_eq!(
        global_control_snapshot(&table),
        ControlEntrySnapshot::Available { generation: 0 },
        "the global lane's own branch must heal Retired, not only Available"
    );
    let next = table
        .admit_control(lane, ControlPhase::ExternalChangeAck, 0x3432)
        .unwrap_or_else(|_| panic!("the healed global lane admits again"));
    assert_eq!(next.req_id().generation(), 1);
}
