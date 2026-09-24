//! C4 production-route tests: accumulator ownership, operation-versus-roster
//! order, and independent oracle comparison.
//!
//! The host fake records requested names and returns caller-supplied actuals.
//! Tests call [`expected_oracle`] themselves to derive PASS/FAIL, so a shared
//! mistake in the production operation-order table cannot make a comparison
//! pass.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use fsring_user::smoke::*;

const ROOT: SmokeIdentity = SmokeIdentity {
    boot_instance_id: HexIdentity { lo: 1, hi: 2 },
    mount_id: HexIdentity { lo: 3, hi: 4 },
    session_epoch: 5,
};
const DISPOSABLE: SmokeIdentity = SmokeIdentity {
    boot_instance_id: HexIdentity { lo: 1, hi: 2 },
    mount_id: HexIdentity { lo: 7, hi: 4 },
    session_epoch: 1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeError {
    Issued,
}

struct HostFakeBackend {
    operations: Vec<ProbeName>,
    actuals: Vec<(ProbeName, Oracle)>,
    fail_on: Option<ProbeName>,
    mutate_on: Option<ProbeName>,
}

impl HostFakeBackend {
    fn happy() -> Self {
        let mut actuals = Vec::new();
        for probe in PROBE_ROSTER_V2 {
            actuals.push((probe, expected_oracle(probe, ROOT)));
        }
        Self {
            operations: Vec::new(),
            actuals,
            fail_on: None,
            mutate_on: None,
        }
    }

    fn actual_for(&self, probe: ProbeName) -> Oracle {
        self.actuals
            .iter()
            .find(|(name, _)| *name == probe)
            .map(|(_, oracle)| oracle.clone())
            .expect("the fake is configured for every requested probe")
    }
}

impl C4RequiredUnavailableDelta for HostFakeBackend {}

impl C4UnloadFacts for HostFakeBackend {
    fn unload_observation(&self) -> UnloadObservation {
        UnloadObservation {
            provider_open_ntstatus: 0xC000_0034,
            fscontrol_open_ntstatus: 0xC000_0034,
            vdo_open_ntstatus: 0xC000_0034,
        }
    }
}

impl C4ProbeBackend for HostFakeBackend {
    type Error = FakeError;

    fn observe(
        &mut self,
        probe: ProbeName,
        state: &mut C4ProbeState,
    ) -> Result<Oracle, Self::Error> {
        self.operations.push(probe);
        if self.mutate_on == Some(probe) {
            state.mark_mutation_started();
        }
        if self.fail_on == Some(probe) {
            return Err(FakeError::Issued);
        }
        Ok(self.actual_for(probe))
    }
}

/// Parent-required STAGED operation trace. Literal in the test so it cannot
/// silently share the production ordering table.
const PARENT_STAGED_TRACE: [ProbeName; 15] = [
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

const PARENT_LIVE_TRACE: [ProbeName; 10] = [
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

fn passing_probe(name: ProbeName, actual: Oracle) -> ProbeV2 {
    let expected = expected_oracle(name, ROOT);
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

/// The C4 live worker must reach the production STAGED observer itself.
///
/// A binary crate exports no items, so this route is read out of the source the
/// binary is built from. It is read inside `run_c4_live_worker`'s own body and
/// against the whole call expression, because the bare name also appears in
/// that body's `use` list -- a name in an import is not a route.
#[test]
fn live_worker_source_observes_staged_prefix() {
    const SRC: &str = include_str!("../src/bin/fsring-control-smoke.rs");
    const WORKER: &str = "
fn run_c4_live_worker(nonce: &str) -> std::process::ExitCode {
";
    const CALL: &str = "observe_staged_prefix(&mut acc, &mut backend, zero_identity())";

    assert_eq!(
        SRC.matches(WORKER).count(),
        1,
        "the live worker is defined exactly once"
    );
    let after = &SRC[SRC.find(WORKER).expect("the worker is defined") + WORKER.len()..];
    let body = match after.find(
        "
fn ",
    ) {
        Some(end) => &after[..end],
        None => panic!("the live worker body is not delimited by a following item"),
    };
    assert!(
        body.contains("observe_staged_prefix"),
        "the worker body still imports the observer"
    );
    assert_eq!(
        body.matches(CALL).count(),
        1,
        "the live worker must call the production STAGED observer exactly once"
    );
}

#[test]
fn c4_live_mode_routes_to_public_v2_not_the_v1_harness() {
    assert_eq!(PUBLIC_SCHEMA_V2, "fsring-control-smoke/v2");
    assert_ne!(PUBLIC_SCHEMA_V2, "fsring-control-smoke/v1");
    assert_ne!(PUBLIC_SCHEMA_V2, "fsring-driver-smoke/v1");
    for (index, probe) in PROBE_ROSTER_V2.iter().enumerate() {
        assert_eq!(probe.index(), index, "{}", probe.wire());
    }
    let report = SmokeReportV2 {
        overall: Overall::Pass,
        exit_code: 0,
        identity: Some(ROOT),
        probes: PROBE_ROSTER_V2
            .iter()
            .copied()
            .map(|name| passing_probe(name, expected_oracle(name, ROOT)))
            .collect(),
        reasons: Vec::new(),
    };
    let bytes = encode_public_report_v2(&report).expect("canonical v2");
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(
        text.starts_with("{\"schema\":\"fsring-control-smoke/v2\""),
        "{text}"
    );
    assert!(!text.contains("fsring-control-smoke/v1"));
    assert!(!text.contains("fsring-driver-smoke/v1"));
}

#[test]
fn staged_worker_observes_all_fifteen_prefix_probes() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let probes = observe_staged_prefix(&mut acc, &mut backend, ROOT).expect("staged");
    assert_eq!(probes.len(), 15);
    for (index, probe) in probes.iter().enumerate() {
        assert_eq!(probe.name, PROBE_ROSTER_V2[index]);
        assert!(probe.actual.is_some(), "{}", probe.name.wire());
        assert_eq!(
            probe.actual.as_ref(),
            Some(&expected_oracle(probe.name, ROOT)),
            "{}",
            probe.name.wire()
        );
        assert_eq!(probe.derived_outcome(), ProbeOutcome::Pass);
    }
}

#[test]
fn staged_operations_follow_parent_order_while_output_remains_roster_order() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let probes = observe_staged_prefix(&mut acc, &mut backend, ROOT).expect("staged");
    assert_eq!(backend.operations, PARENT_STAGED_TRACE.as_slice());
    let serialized_names: Vec<ProbeName> = probes.iter().map(|probe| probe.name).collect();
    assert_eq!(serialized_names, PROBE_ROSTER_V2[0..15].to_vec());
    assert_ne!(
        backend.operations.as_slice(),
        &PROBE_ROSTER_V2[0..15],
        "the parent operation trace is not roster order"
    );
}

#[test]
fn live_worker_observes_all_ten_live_and_cleanup_probes() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let _ = observe_staged_prefix(&mut acc, &mut backend, ROOT).expect("staged");
    backend.operations.clear();
    let probes = observe_live_range(&mut acc, &mut backend, ROOT).expect("live");
    assert_eq!(probes.len(), 10);
    assert_eq!(backend.operations, PARENT_LIVE_TRACE.as_slice());
    for (offset, probe) in probes.iter().enumerate() {
        assert_eq!(probe.name, PROBE_ROSTER_V2[15 + offset]);
        assert!(probe.actual.is_some(), "{}", probe.name.wire());
        assert_eq!(
            probe.actual.as_ref(),
            Some(&expected_oracle(probe.name, ROOT))
        );
    }
}

#[test]
fn post_worker_observes_bootcontext_persistence() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let observation = observe_post_unload(&mut acc, &mut backend, ROOT).expect("post");
    assert_eq!(observation.probes.len(), 1);
    assert_eq!(observation.probes[0].name, ProbeName::BootContextPersistent);
    assert_eq!(
        observation.probes[0].actual.as_ref(),
        Some(&expected_oracle(ProbeName::BootContextPersistent, ROOT))
    );
    assert_eq!(
        observation.unload_observation,
        UnloadObservation {
            provider_open_ntstatus: 0xC000_0034,
            fscontrol_open_ntstatus: 0xC000_0034,
            vdo_open_ntstatus: 0xC000_0034,
        }
    );
}

#[test]
fn unload_transients_merge_live_post_and_runner_observations() {
    let seed = UnloadSeed {
        former_alias_ranges_free: true,
        owned_handles_closed: true,
    };
    let observation = UnloadObservation {
        provider_open_ntstatus: 0xC000_0034,
        fscontrol_open_ntstatus: 0xC000_0034,
        vdo_open_ntstatus: 0xC000_0034,
    };
    let merged = merge_unload_transients(seed, observation, true, 0x0000_0002);
    assert_eq!(merged, expected_oracle(ProbeName::UnloadTransients, ROOT));
    let stopped_false = merge_unload_transients(seed, observation, false, 0x0000_0002);
    assert_ne!(
        stopped_false,
        expected_oracle(ProbeName::UnloadTransients, ROOT)
    );
}

#[test]
fn happy_path_has_twenty_seven_non_null_actuals_and_no_reasons() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let staged = observe_staged_prefix(&mut acc, &mut backend, ROOT).expect("staged");
    let live = observe_live_range(&mut acc, &mut backend, ROOT).expect("live");
    let post = observe_post_unload(&mut acc, &mut backend, ROOT).expect("post");
    let unload = merge_unload_transients(
        UnloadSeed {
            former_alias_ranges_free: true,
            owned_handles_closed: true,
        },
        post.unload_observation,
        true,
        0x0000_0002,
    );
    acc.observe(&mut backend, ProbeName::UnloadTransients)
        .expect("request runner-only probe");
    acc.record(
        ProbeName::UnloadTransients.index(),
        passing_probe(ProbeName::UnloadTransients, unload),
    )
    .expect("record unload");
    let probes = acc.serialize_range(0..27).expect("full roster");
    assert_eq!(probes.len(), 27);
    assert_eq!(staged.len(), 15);
    assert_eq!(live.len(), 10);
    assert_eq!(post.probes.len(), 1);
    for probe in &probes {
        assert!(probe.actual.is_some(), "{}", probe.name.wire());
        assert_eq!(
            probe.actual.as_ref(),
            Some(&expected_oracle(probe.name, ROOT))
        );
    }
    assert_eq!(derive_overall(&probes, &[], Some(ROOT)), Overall::Pass);
}

#[test]
fn accumulator_owns_exact_probe_state_for_record_and_serialization() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let actual = acc
        .observe(&mut backend, ProbeName::RootOpen)
        .expect("observe");
    acc.record(
        ProbeName::RootOpen.index(),
        passing_probe(ProbeName::RootOpen, actual),
    )
    .expect("record");
    let serialized = acc.serialize_range(0..1).expect("range");
    assert_eq!(serialized.len(), 1);
    assert_eq!(serialized[0].name, ProbeName::RootOpen);
    assert_eq!(
        acc.record(
            ProbeName::RootOpen.index(),
            passing_probe(
                ProbeName::RootOpen,
                expected_oracle(ProbeName::RootOpen, ROOT)
            ),
        )
        .err(),
        Some(ProbeError::DuplicateRecord)
    );
    assert_eq!(
        acc.observe(&mut backend, ProbeName::RootOpen).err(),
        Some(C4ObserveError::Probe(ProbeError::DuplicateRequest))
    );
    assert_eq!(
        acc.record(
            3,
            passing_probe(
                ProbeName::RootOpen,
                expected_oracle(ProbeName::RootOpen, ROOT)
            ),
        )
        .err(),
        Some(ProbeError::NameIndexMismatch)
    );
    assert_eq!(
        acc.serialize_range(0..15).err(),
        Some(ProbeError::IncompleteRange)
    );
}

#[test]
fn serialize_range_rejects_requested_bits_outside_the_exact_range() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    let actual = acc
        .observe(&mut backend, ProbeName::RootOpen)
        .expect("root");
    acc.record(
        ProbeName::RootOpen.index(),
        passing_probe(ProbeName::RootOpen, actual),
    )
    .expect("record root");
    let trailing = acc
        .observe(&mut backend, ProbeName::TrailingOpen)
        .expect("trailing");
    acc.record(
        ProbeName::TrailingOpen.index(),
        passing_probe(ProbeName::TrailingOpen, trailing),
    )
    .expect("record trailing");
    assert_eq!(
        acc.serialize_range(0..1).err(),
        Some(ProbeError::IncompleteRange)
    );
    let slice = acc.serialize_range(0..2).expect("exact two-probe range");
    assert_eq!(slice.len(), 2);
}

#[test]
fn observe_preserves_structural_and_backend_error_domains() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    backend.fail_on = Some(ProbeName::TrailingOpen);
    let first = acc
        .observe(&mut backend, ProbeName::RootOpen)
        .expect("first observe issues the backend");
    assert_eq!(first, expected_oracle(ProbeName::RootOpen, ROOT));
    match acc.observe(&mut backend, ProbeName::TrailingOpen) {
        Err(C4ObserveError::Backend(FakeError::Issued)) => {}
        other => panic!("backend error must be lossless: {other:?}"),
    }
    assert_eq!(
        acc.observe(&mut backend, ProbeName::RootOpen).err(),
        Some(C4ObserveError::Probe(ProbeError::DuplicateRequest)),
        "structural refusal is Probe, never Backend"
    );
    assert_eq!(
        backend.operations,
        vec![ProbeName::RootOpen, ProbeName::TrailingOpen]
    );
}

#[test]
fn not_run_after_external_mutation_is_a_sticky_failure() {
    let mut acc = C4ProbeAccumulator::new();
    let mut backend = HostFakeBackend::happy();
    backend.mutate_on = Some(ProbeName::RootOpen);
    backend.fail_on = Some(ProbeName::TrailingOpen);
    acc.observe(&mut backend, ProbeName::RootOpen)
        .expect("mutation starts");
    match acc.observe(&mut backend, ProbeName::TrailingOpen) {
        Err(C4ObserveError::Backend(FakeError::Issued)) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        acc.observe(&mut backend, ProbeName::UnknownIoctl).err(),
        Some(C4ObserveError::Probe(
            ProbeError::ObservationAfterStickyFailure
        ))
    );
    assert_eq!(
        acc.record(
            ProbeName::UnknownIoctl.index(),
            passing_probe(
                ProbeName::UnknownIoctl,
                expected_oracle(ProbeName::UnknownIoctl, ROOT)
            ),
        )
        .err(),
        Some(ProbeError::ObservationAfterStickyFailure)
    );
    assert_eq!(
        acc.serialize_range(0..1).err(),
        Some(ProbeError::ObservationAfterStickyFailure)
    );
}

#[test]
fn preflight_uses_orchestration_envelope_not_public_v2_schema() {
    assert_eq!(
        PREFLIGHT_ORCHESTRATION_SCHEMA,
        "fsring-c4-preflight-orchestration/v1"
    );
    assert_ne!(PREFLIGHT_ORCHESTRATION_SCHEMA, PUBLIC_SCHEMA_V2);
}

#[test]
fn live_stdout_is_one_json_object_and_raw_etw_goes_to_sidecars() {
    assert_eq!(
        LIVE_SIDECAR_NAMES,
        [
            "etw.sidecar.jsonl",
            "worker-frames.sidecar.bin",
            "cleanup.sidecar.json",
            "diagnostics.sidecar.jsonl",
        ]
    );
    let report = SmokeReportV2 {
        overall: Overall::Pass,
        exit_code: 0,
        identity: Some(ROOT),
        probes: PROBE_ROSTER_V2
            .iter()
            .copied()
            .map(|name| passing_probe(name, expected_oracle(name, ROOT)))
            .collect(),
        reasons: Vec::new(),
    };
    let bytes = encode_public_report_v2(&report).expect("canonical");
    assert_eq!(bytes.last().copied(), Some(b'\n'));
    let body = &bytes[..bytes.len() - 1];
    assert_eq!(body.iter().filter(|byte| **byte == b'\n').count(), 0);
}

#[test]
fn v1_selftest_and_c3_regression_never_parse_as_v2() {
    let v1 = br#"{"schema":"fsring-control-smoke/v1","overall":"PASS","exitCode":0,"probes":[],"reasons":[]}
"#;
    assert_eq!(
        decode_public_report_v2(v1).err(),
        Some(SmokeSchemaError::WrongLiteral)
    );
    let wrapper =
        br#"{"schema":"fsring-driver-smoke/v1","mode":"SelfTest","overall":"PASS","exitCode":0}
"#;
    assert_eq!(
        decode_public_report_v2(wrapper).err(),
        Some(SmokeSchemaError::WrongLiteral)
    );
}

#[allow(dead_code)]
fn _disposable_identity_is_retained_for_delta_checks() {
    let _ = DISPOSABLE;
}

struct RecordingMappedOps {
    calls: Vec<&'static str>,
    inherited: InheritedHandleObservation,
    security: SetupSecurityObservation,
    layout: SessionLayoutFacts,
    views: ViewProtectionFacts,
    poll: EnterPollObservation,
    timeout: EnterPollObservation,
    dual: EnterDualRoleObservation,
    notify: EnterNotifyCreditObservation,
    contention: EnterContentionObservation,
    cancel: EnterCancelObservation,
    abort: ProtocolAbortObservation,
    cleanup: CleanupCloseObservation,
}

impl RecordingMappedOps {
    fn mismatched() -> Self {
        Self {
            calls: Vec::new(),
            inherited: InheritedHandleObservation {
                win32_code: 7,
                information: 1,
            },
            security: SetupSecurityObservation {
                win32_code: 1,
                result_size_matches: false,
                selected_mask: 0,
                identity_nonzero: false,
            },
            layout: SessionLayoutFacts {
                independent_parser: false,
                exact_lengths: false,
                zero_padding: false,
                zero_cursors: false,
                descriptor_counts_match: false,
            },
            views: ViewProtectionFacts {
                virtual_query_coverage: false,
                exact_protections: false,
                overlap_count: 3,
                executable_range_count: 2,
            },
            poll: EnterPollObservation {
                win32_code: 1,
                information: 0,
                flags: 1,
                cq_drained: 9,
                returned_credits: 9,
            },
            timeout: EnterPollObservation {
                win32_code: 1,
                information: 0,
                flags: 0,
                cq_drained: 0,
                returned_credits: 0,
            },
            dual: EnterDualRoleObservation {
                first_wait_pending: false,
                concurrent_drain_win32_code: 1,
                conflicting_wait_win32_code: 1,
                roles_released: false,
            },
            notify: EnterNotifyCreditObservation {
                win32_code: 1,
                cq_drained: 0,
                returned_credits: 0,
                old_generation: 9,
                new_generation: 9,
            },
            contention: EnterContentionObservation {
                win32_code: 1,
                flags: 0,
                bounded: false,
            },
            cancel: EnterCancelObservation {
                win32_code: 1,
                information: 8,
                exact_overlapped: false,
                completed_once: false,
            },
            abort: ProtocolAbortObservation {
                enter_win32_code: 1,
                fence_reason: 1,
                session_absent: false,
                identity: ROOT,
            },
            cleanup: CleanupCloseObservation {
                pending_enter_count: 3,
                alias_count: 3,
                owned_handle_count: 3,
                completed_once: false,
            },
        }
    }
}

impl C4MappedOps for RecordingMappedOps {
    type Error = FakeError;

    fn child_inherited_handle(&mut self) -> Result<InheritedHandleObservation, Self::Error> {
        self.calls.push("child_inherited_handle");
        Ok(self.inherited)
    }
    fn setup_security(&mut self) -> Result<SetupSecurityObservation, Self::Error> {
        self.calls.push("setup_security");
        Ok(self.security)
    }
    fn session_layout(&mut self) -> Result<SessionLayoutFacts, Self::Error> {
        self.calls.push("session_layout");
        Ok(self.layout)
    }
    fn view_protections(&mut self) -> Result<ViewProtectionFacts, Self::Error> {
        self.calls.push("view_protections");
        Ok(self.views)
    }
    fn enter_poll(&mut self) -> Result<EnterPollObservation, Self::Error> {
        self.calls.push("enter_poll");
        Ok(self.poll)
    }
    fn enter_timeout(&mut self) -> Result<EnterPollObservation, Self::Error> {
        self.calls.push("enter_timeout");
        Ok(self.timeout)
    }
    fn enter_dual_role(&mut self) -> Result<EnterDualRoleObservation, Self::Error> {
        self.calls.push("enter_dual_role");
        Ok(self.dual)
    }
    fn enter_notify_credit(&mut self) -> Result<EnterNotifyCreditObservation, Self::Error> {
        self.calls.push("enter_notify_credit");
        Ok(self.notify)
    }
    fn enter_contention(&mut self) -> Result<EnterContentionObservation, Self::Error> {
        self.calls.push("enter_contention");
        Ok(self.contention)
    }
    fn enter_cancel(&mut self) -> Result<EnterCancelObservation, Self::Error> {
        self.calls.push("enter_cancel");
        Ok(self.cancel)
    }
    fn protocol_abort(&mut self) -> Result<ProtocolAbortObservation, Self::Error> {
        self.calls.push("protocol_abort");
        Ok(self.abort)
    }
    fn cleanup_close(&mut self) -> Result<CleanupCloseObservation, Self::Error> {
        self.calls.push("cleanup_close");
        Ok(self.cleanup)
    }
}

#[test]
fn production_match_arms_drive_mapped_ops_not_the_oracle_table() {
    let mut ops = RecordingMappedOps::mismatched();
    let mapped = [
        ProbeName::ChildInheritedHandle,
        ProbeName::SetupSecurity,
        ProbeName::SessionLayout,
        ProbeName::ViewProtections,
        ProbeName::EnterPoll,
        ProbeName::EnterTimeout,
        ProbeName::EnterDualRole,
        ProbeName::EnterNotifyCredit,
        ProbeName::EnterContention,
        ProbeName::EnterCancel,
        ProbeName::ProtocolAbort,
        ProbeName::CleanupClose,
    ];
    for probe in mapped {
        let actual = observe_from_mapped_ops(&mut ops, probe).expect("mapped observation");
        assert_ne!(
            actual,
            expected_oracle(probe, ROOT),
            "{} production arm must not copy expected_oracle",
            probe.wire()
        );
    }
    assert_eq!(
        ops.calls,
        [
            "child_inherited_handle",
            "setup_security",
            "session_layout",
            "view_protections",
            "enter_poll",
            "enter_timeout",
            "enter_dual_role",
            "enter_notify_credit",
            "enter_contention",
            "enter_cancel",
            "protocol_abort",
            "cleanup_close",
        ]
    );
}

#[test]
fn mapped_ops_oracles_match_expected_oracle_only_when_observations_do() {
    let poll = EnterPollObservation {
        win32_code: 0,
        information: 0x30,
        flags: 0,
        cq_drained: 0,
        returned_credits: 0,
    };
    assert_eq!(
        oracle_from_enter_poll(poll),
        expected_oracle(ProbeName::EnterPoll, ROOT)
    );
    assert_ne!(
        oracle_from_enter_poll(EnterPollObservation {
            win32_code: 2,
            information: 0x30,
            flags: 0,
            cq_drained: 0,
            returned_credits: 0,
        }),
        expected_oracle(ProbeName::EnterPoll, ROOT)
    );
    assert_eq!(
        oracle_from_inherited_handle(InheritedHandleObservation {
            win32_code: 5,
            information: 0,
        }),
        expected_oracle(ProbeName::ChildInheritedHandle, ROOT)
    );
    let consecutive_root = SmokeIdentity {
        boot_instance_id: ROOT.boot_instance_id,
        mount_id: HexIdentity { lo: 8, hi: 4 },
        session_epoch: ROOT.session_epoch,
    };
    assert_eq!(mount_sequence_delta(consecutive_root, DISPOSABLE), 0);
    assert_ne!(mount_sequence_delta(ROOT, DISPOSABLE), 0);
    assert_eq!(
        SESSION_FENCE_REASON_PROTOCOL_ABORT, 0x0000_0003,
        "PASS-table fenceReason is SESSION_FENCED ProtocolAbort, not the CQE reason"
    );
    assert_eq!(C4_SESSION_FENCED_EVENT_ID, 4);
    assert_eq!(
        EventName::SessionFenced.id(),
        u32::from(C4_SESSION_FENCED_EVENT_ID)
    );
    assert_ne!(
        u32::from(C4_SESSION_FENCED_EVENT_ID),
        SESSION_FENCE_REASON_PROTOCOL_ABORT,
        "EventName id 4 is not FenceReason::ProtocolAbort"
    );
    const PROVIDER_FATAL_STATE: u32 = 1;
    assert_ne!(PROVIDER_FATAL_STATE, SESSION_FENCE_REASON_PROTOCOL_ABORT);
    let abort_cqe = protocol_abort_cqe();
    let abort_record = fsring_abi::msgs::validate_protocol_abort_v1(&abort_cqe)
        .expect("the LIVE abort CQE must be a valid provider-fatal PROTOCOL record");
    assert_eq!(abort_record.reason, PROVIDER_FATAL_STATE);
    let fenced = c4_session_fenced_record(ROOT, SESSION_FENCE_REASON_PROTOCOL_ABORT);
    let payload_bytes = encode_c4_evidence_payload(&fenced.payload);
    assert_eq!(payload_bytes.len(), C4_EVIDENCE_PAYLOAD_SIZE);
    assert_eq!(
        parse_c4_evidence_payload(&payload_bytes),
        Some(fenced.payload)
    );
    assert_eq!(
        u32::from_le_bytes(payload_bytes[48..52].try_into().expect("reason field")),
        SESSION_FENCE_REASON_PROTOCOL_ABORT
    );
    assert_eq!(identity_from_c4_evidence_payload(&fenced.payload), ROOT);
    let observed = worker_event_from_c4_etw_record(&fenced).expect("SESSION_FENCED worker event");
    assert_eq!(observed.name, EventName::SessionFenced);
    assert_eq!(observed.id, 4);
    assert_eq!(observed.reason, SESSION_FENCE_REASON_PROTOCOL_ABORT);
    assert_eq!(observed.identity, ROOT);
    assert_eq!(
        session_fenced_worker_event(ROOT, Some(&fenced)),
        Some(observed)
    );
    let abort_pass = protocol_abort_from_session_fenced(0, true, ROOT, Some(&fenced));
    assert_eq!(abort_pass.fence_reason, SESSION_FENCE_REASON_PROTOCOL_ABORT);
    assert_eq!(
        oracle_from_protocol_abort(abort_pass),
        expected_oracle(ProbeName::ProtocolAbort, ROOT)
    );
    assert_ne!(
        oracle_from_protocol_abort(protocol_abort_from_session_fenced(
            0,
            true,
            ROOT,
            Some(&c4_session_fenced_record(ROOT, PROVIDER_FATAL_STATE)),
        )),
        expected_oracle(ProbeName::ProtocolAbort, ROOT),
        "CQE PROVIDER_FATAL_STATE must not be copied as fenceReason"
    );
    assert_eq!(
        protocol_abort_from_session_fenced(0, true, ROOT, None).fence_reason,
        0,
        "missing SESSION_FENCED evidence cannot forge ProtocolAbort"
    );
    assert_eq!(
        protocol_abort_from_session_fenced(
            0,
            true,
            ROOT,
            Some(&c4_session_fenced_record(
                DISPOSABLE,
                SESSION_FENCE_REASON_PROTOCOL_ABORT
            )),
        )
        .fence_reason,
        0,
        "a SESSION_FENCED event for another identity is not the root abort"
    );
}
