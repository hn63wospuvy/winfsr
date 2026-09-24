//! The public v2 schema and the closed private worker protocol.
//!
//! The claims under test are the ones a wrong report would satisfy anyway if
//! nobody checked them: the roster is exactly 27 names in one order, the
//! aggregate verdict is *derived* rather than read, and a private frame that is
//! wrong anywhere contributes nothing at all rather than its good prefix.

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
const NONCE: &str = "0123456789ABCDEF0123456789ABCDEF";
const VDO: &str = "\\Device\\FsRingVolume-0000000000000003-0000000000000004";
const DOS: &str = "Global\\FsRingC4-00001234-0123456789ABCDEF0123456789ABCDEF";

fn nonce() -> WorkerNonce {
    WorkerNonce::parse(NONCE).expect("a canonical nonce")
}

/// One probe that passes: `actual` is the table's own expectation.
fn passing(name: ProbeName) -> ProbeV2 {
    let expected = expected_oracle(name, ROOT);
    ProbeV2 {
        name,
        outcome: ProbeOutcome::Pass,
        actual: Some(expected.clone()),
        expected,
    }
}

fn not_run(name: ProbeName) -> ProbeV2 {
    ProbeV2 {
        name,
        outcome: ProbeOutcome::NotRun,
        expected: expected_oracle(name, ROOT),
        actual: None,
    }
}

fn all_passing() -> Vec<ProbeV2> {
    PROBE_ROSTER_V2.iter().copied().map(passing).collect()
}

fn slice(range: std::ops::Range<usize>) -> Vec<ProbeV2> {
    PROBE_ROSTER_V2[range]
        .iter()
        .copied()
        .map(passing)
        .collect()
}

// ---------------------------------------------------------------------------
// The public roster and derivation
// ---------------------------------------------------------------------------

#[test]
fn the_roster_is_exactly_twenty_seven_names_in_one_order() {
    assert_eq!(PROBE_ROSTER_V2.len(), 27);
    let names: Vec<&str> = PROBE_ROSTER_V2.iter().map(|probe| probe.wire()).collect();
    assert_eq!(
        names,
        vec![
            "root-open",
            "trailing-open",
            "unknown-ioctl",
            "donate-short",
            "donate-wrong-version",
            "donate",
            "child-inherited-handle",
            "parent-handle-after-child",
            "fscontrol-acl",
            "setup-required-unavailable",
            "setup-optional-downgrade",
            "setup-security",
            "setup-duplicate",
            "session-layout",
            "view-protections",
            "vdo-acl",
            "vdo-mount",
            "enter-poll",
            "enter-timeout",
            "enter-dual-role",
            "enter-notify-credit",
            "enter-contention",
            "enter-cancel",
            "protocol-abort",
            "cleanup-close",
            "unload-transients",
            "bootcontext-persistent",
        ],
    );
    // Every wire name round-trips, so a renamed probe cannot silently parse as
    // its neighbour.
    for probe in PROBE_ROSTER_V2 {
        assert_eq!(ProbeName::parse(probe.wire()), Some(probe));
    }
}

#[test]
fn all_pass_with_no_reason_is_pass() {
    assert_eq!(
        derive_overall(&all_passing(), &[], Some(ROOT)),
        Overall::Pass
    );
    assert_eq!(Overall::Pass.exit_code(), 0);
    assert_eq!(Overall::Fail.exit_code(), 1);
    assert_eq!(Overall::NotRun.exit_code(), 2);
}

#[test]
fn a_not_run_probe_after_mutation_is_a_failure() {
    let mut probes = all_passing();
    probes[26] = not_run(ProbeName::BootContextPersistent);
    // A retained root identity means mutation began, so the gap is a failure.
    assert_eq!(derive_overall(&probes, &[], Some(ROOT)), Overall::Fail);
    // Before any mutation, the same gap is honestly "not run".
    assert_eq!(derive_overall(&probes, &[], None), Overall::NotRun);
}

#[test]
fn the_reported_outcome_is_ignored_and_the_comparison_redone() {
    let mut probes = all_passing();
    // A probe that claims PASS while its actual disagrees with the table.
    probes[0].outcome = ProbeOutcome::Pass;
    probes[0].actual = Some(Oracle::Facts {
        values: vec![("opened", FactValue::Bool(false))],
    });
    assert_eq!(
        derive_overall(&probes, &[], Some(ROOT)),
        Overall::Fail,
        "a self-reported PASS is worth nothing",
    );
    assert_eq!(probes[0].derived_outcome(), ProbeOutcome::Fail);
}

#[test]
fn a_reserved_infrastructure_reason_forces_failure() {
    let reason = SmokeReason::parse("INFRASTRUCTURE:LIVE_STAGED:runner:0x00000001", true)
        .expect("the runner may emit the reserved form");
    assert!(reason.is_infrastructure());
    assert_eq!(
        derive_overall(&all_passing(), std::slice::from_ref(&reason), Some(ROOT)),
        Overall::Fail,
    );
}

#[test]
fn an_ordinary_reason_may_never_use_the_reserved_prefix() {
    assert_eq!(
        SmokeReason::parse("INFRASTRUCTURE:LIVE_STAGED:runner:0x00000001", false).err(),
        Some(SmokeSchemaError::InvalidReason),
    );
    // And a non-empty ordinary reason still forces failure on its own.
    let reason = SmokeReason::parse("the volume did not mount", false).expect("ordinary");
    assert_eq!(
        derive_overall(&all_passing(), std::slice::from_ref(&reason), Some(ROOT)),
        Overall::Fail,
    );
}

#[test]
fn reason_bounds_are_enforced() {
    assert_eq!(
        SmokeReason::parse("", false).err(),
        Some(SmokeSchemaError::InvalidReason),
    );
    let long = "x".repeat(513);
    assert_eq!(
        SmokeReason::parse(&long, false).err(),
        Some(SmokeSchemaError::InvalidReason),
    );
    assert!(SmokeReason::parse(&"x".repeat(512), false).is_ok());
    assert_eq!(
        SmokeReason::parse("has\u{0}nul", false).err(),
        Some(SmokeSchemaError::InvalidReason),
    );
    assert_eq!(
        SmokeReason::parse("has\ncontrol", false).err(),
        Some(SmokeSchemaError::InvalidReason),
    );
}

#[test]
fn a_reordered_or_short_roster_is_a_failure() {
    let mut probes = all_passing();
    probes.swap(0, 1);
    assert_eq!(derive_overall(&probes, &[], Some(ROOT)), Overall::Fail);
    let short = all_passing()[..26].to_vec();
    assert_eq!(derive_overall(&short, &[], Some(ROOT)), Overall::Fail);
}

// ---------------------------------------------------------------------------
// The expected-oracle table
// ---------------------------------------------------------------------------

#[test]
fn every_probe_has_the_kind_the_design_table_names() {
    use ProbeName as P;
    for probe in PROBE_ROSTER_V2 {
        let kind = expected_oracle(probe, ROOT).kind();
        let want = match probe {
            P::TrailingOpen
            | P::UnknownIoctl
            | P::DonateShort
            | P::DonateWrongVersion
            | P::Donate
            | P::ChildInheritedHandle
            | P::ParentHandleAfterChild
            | P::SetupDuplicate => "status",
            P::VdoMount | P::ProtocolAbort => "compound",
            _ => "facts",
        };
        assert_eq!(kind, want, "{}", probe.wire());
    }
}

#[test]
fn the_two_identity_bearing_oracles_use_the_root_identity() {
    for probe in [ProbeName::VdoMount, ProbeName::ProtocolAbort] {
        let Oracle::Compound {
            names, identity, ..
        } = expected_oracle(probe, ROOT)
        else {
            panic!("{} is compound", probe.wire());
        };
        assert_eq!(identity, ROOT);
        assert!(!names.is_empty());
    }
}

#[test]
fn the_mount_sequence_delta_expectation_is_exactly_zero() {
    let Oracle::Facts { values } = expected_oracle(ProbeName::SetupRequiredUnavailable, ROOT)
    else {
        panic!("facts");
    };
    assert_eq!(
        values,
        vec![
            ("win32Code", FactValue::Hex32(0x0000_0032)),
            ("information", FactValue::Hex64(0)),
            ("mountSequenceDelta", FactValue::Hex64(0)),
        ],
        "the two successful SETUPs must be consecutive burns",
    );
}

#[test]
fn bootcontext_persistence_is_denied_not_absent() {
    let Oracle::Facts { values } = expected_oracle(ProbeName::BootContextPersistent, ROOT) else {
        panic!("facts");
    };
    assert_eq!(
        values,
        vec![
            ("sectionOpenNtstatus", FactValue::Hex32(0xC000_0022)),
            ("eventOpenNtstatus", FactValue::Hex32(0xC000_0022)),
            ("objectsPersistAndRemainKernelOnly", FactValue::Bool(true)),
        ],
        "a success or a name-not-found is not a valid public fact here",
    );
}

#[test]
fn a_probe_whose_actual_has_the_wrong_kind_is_refused() {
    let mut probe = passing(ProbeName::RootOpen);
    probe.actual = Some(Oracle::Status {
        domain: StatusDomain::Win32,
        code: 0,
        information: None,
    });
    assert_eq!(probe.validate().err(), Some(SmokeSchemaError::WrongType));
}

#[test]
fn a_not_run_probe_may_not_carry_an_actual() {
    let mut probe = not_run(ProbeName::RootOpen);
    probe.actual = Some(expected_oracle(ProbeName::RootOpen, ROOT));
    assert_eq!(probe.validate().err(), Some(SmokeSchemaError::WrongType));
    let mut executed = passing(ProbeName::RootOpen);
    executed.actual = None;
    assert_eq!(executed.validate().err(), Some(SmokeSchemaError::WrongType));
}

// ---------------------------------------------------------------------------
// Nonces and events
// ---------------------------------------------------------------------------

#[test]
fn a_nonce_is_exactly_thirty_two_uppercase_hex_digits() {
    assert!(WorkerNonce::parse(NONCE).is_ok());
    for bad in [
        "0123456789abcdef0123456789abcdef",
        "0x23456789ABCDEF0123456789ABCDEF01",
        "0123456789ABCDEF0123456789ABCDE",
        "0123456789ABCDEF0123456789ABCDEF0",
        "",
    ] {
        assert_eq!(
            WorkerNonce::parse(bad).err(),
            Some(SmokeSchemaError::InvalidNonce),
            "{bad:?}",
        );
    }
    assert_eq!(nonce().as_text(), NONCE);
}

#[test]
fn an_event_is_pinned_to_its_id_version_keyword_and_reason() {
    for name in [
        EventName::SessionPublished,
        EventName::MountPublished,
        EventName::VerifySucceeded,
    ] {
        let good = WorkerEvent {
            name,
            id: name.id(),
            version: 1,
            keyword: 0x1,
            identity: ROOT,
            reason: 0,
        };
        assert!(good.validate().is_ok(), "{}", name.wire());
        // Only a fence carries a reason.
        let mut with_reason = good;
        with_reason.reason = 1;
        assert_eq!(
            with_reason.validate().err(),
            Some(SmokeSchemaError::InvalidEvent),
        );
        for wrong in [
            WorkerEvent { id: 9, ..good },
            WorkerEvent { version: 2, ..good },
            WorkerEvent { keyword: 2, ..good },
        ] {
            assert_eq!(wrong.validate().err(), Some(SmokeSchemaError::InvalidEvent));
        }
    }
    let fence = WorkerEvent {
        name: EventName::SessionFenced,
        id: 4,
        version: 1,
        keyword: 0x1,
        identity: ROOT,
        reason: 3,
    };
    assert!(fence.validate().is_ok());
    for reason in [0u32, 5, 99] {
        let wrong = WorkerEvent { reason, ..fence };
        assert_eq!(wrong.validate().err(), Some(SmokeSchemaError::InvalidEvent));
    }
}

// ---------------------------------------------------------------------------
// Private frames
// ---------------------------------------------------------------------------

fn staged() -> WorkerFrame {
    WorkerFrame::Staged(StagedRecord {
        sequence: 1,
        nonce: nonce(),
        root_identity: ROOT,
        disposable_identity: DISPOSABLE,
        vdo_native_name: VDO.to_string(),
        probes: slice(0..15),
        events: vec![WorkerEvent {
            name: EventName::SessionPublished,
            id: 1,
            version: 1,
            keyword: 0x1,
            identity: ROOT,
            reason: 0,
        }],
        reasons: Vec::new(),
    })
}

fn live_cleaned() -> WorkerFrame {
    let probes = slice(15..25);
    let cleanup_probe = probes
        .iter()
        .find(|probe| probe.name == ProbeName::CleanupClose)
        .expect("the live slice ends at cleanup-close");
    let Some(Oracle::Facts { values }) = cleanup_probe.actual.as_ref() else {
        panic!("facts");
    };
    let _ = values;
    WorkerFrame::LiveCleaned(LiveCleanedRecord {
        sequence: 3,
        nonce: nonce(),
        root_identity: ROOT,
        disposable_identity: DISPOSABLE,
        vdo_native_name: VDO.to_string(),
        dos_name: DOS.to_string(),
        probes,
        events: Vec::new(),
        cleanup: CleanupSummary {
            pending_enter_count: 0,
            alias_count: 0,
            owned_handle_count: 0,
            completed_once: true,
        },
        unload_seed: UnloadSeed {
            former_alias_ranges_free: true,
            owned_handles_closed: true,
        },
        reasons: Vec::new(),
    })
}

fn post_unload() -> WorkerFrame {
    WorkerFrame::PostUnload(PostUnloadRecord {
        sequence: 4,
        nonce: nonce(),
        root_identity: ROOT,
        vdo_native_name: VDO.to_string(),
        dos_name: DOS.to_string(),
        unload_observation: UnloadObservation {
            provider_open_ntstatus: 0xC000_0034,
            fscontrol_open_ntstatus: 0xC000_0034,
            vdo_open_ntstatus: 0xC000_0034,
        },
        probes: slice(26..27),
        reasons: Vec::new(),
    })
}

fn run_mount() -> WorkerFrame {
    WorkerFrame::RunMount(RunMountCommand {
        sequence: 2,
        nonce: nonce(),
        root_identity: ROOT,
        vdo_native_name: VDO.to_string(),
        dos_name: DOS.to_string(),
    })
}

#[test]
fn every_frame_round_trips_byte_for_byte() {
    for frame in [staged(), run_mount(), live_cleaned(), post_unload()] {
        let bytes = encode_worker_frame(&frame).expect("encodes");
        let decoded = decode_worker_frame(&bytes).expect("decodes");
        assert_eq!(decoded, frame);
        let again = encode_worker_frame(&decoded).expect("re-encodes");
        assert_eq!(again, bytes, "the encoding is canonical");
    }
}

#[test]
fn the_four_stages_carry_their_exact_sequences() {
    assert_eq!(staged().sequence(), 1);
    assert_eq!(run_mount().sequence(), 2);
    assert_eq!(live_cleaned().sequence(), 3);
    assert_eq!(post_unload().sequence(), 4);
    assert_eq!(staged().stage(), "STAGED");
    assert_eq!(run_mount().stage(), "RUN_MOUNT");
    assert_eq!(live_cleaned().stage(), "LIVE_CLEANED");
    assert_eq!(post_unload().stage(), "POST_UNLOAD");
}

#[test]
fn a_sequence_that_disagrees_with_its_stage_is_refused() {
    let bytes = encode_worker_frame(&staged()).expect("encodes");
    let text = String::from_utf8(bytes).expect("utf8");
    let forged = text.replacen("\"sequence\":1", "\"sequence\":3", 1);
    assert_eq!(
        decode_worker_frame(forged.as_bytes()).err(),
        Some(SmokeSchemaError::WrongSequence),
    );
}

#[test]
fn the_three_private_slices_skip_unload_transients() {
    assert_eq!(STAGED_PROBE_RANGE, 0..15);
    assert_eq!(LIVE_PROBE_RANGE, 15..25);
    assert_eq!(POST_PROBE_RANGE, 26..27);
    assert_eq!(PROBE_ROSTER_V2[25], ProbeName::UnloadTransients);
    for range in [STAGED_PROBE_RANGE, LIVE_PROBE_RANGE, POST_PROBE_RANGE] {
        assert!(
            !PROBE_ROSTER_V2[range].contains(&ProbeName::UnloadTransients),
            "only the runner may observe the unload transients",
        );
    }
}

#[test]
fn a_frame_carrying_the_wrong_probe_slice_is_refused() {
    let WorkerFrame::Staged(mut record) = staged() else {
        panic!("staged");
    };
    record.probes = slice(15..25);
    assert_eq!(
        WorkerFrame::Staged(record).validate().err(),
        Some(SmokeSchemaError::InvalidProbeRoster),
    );
}

#[test]
fn a_worker_may_not_emit_the_reserved_infrastructure_reason() {
    let WorkerFrame::Staged(mut record) = staged() else {
        panic!("staged");
    };
    // The constructor refuses it, so a forged one has to be built by hand.
    record.reasons =
        vec![SmokeReason::parse("INFRASTRUCTURE:LIVE_STAGED:runner:0x00000001", true).unwrap()];
    assert_eq!(
        WorkerFrame::Staged(record).validate().err(),
        Some(SmokeSchemaError::InvalidReason),
    );
}

#[test]
fn a_duplicate_event_is_refused() {
    let WorkerFrame::Staged(mut record) = staged() else {
        panic!("staged");
    };
    let event = record.events[0];
    record.events.push(event);
    assert_eq!(
        WorkerFrame::Staged(record).validate().err(),
        Some(SmokeSchemaError::InvalidEvent),
    );
}

#[test]
fn more_than_eight_events_is_refused() {
    let WorkerFrame::Staged(mut record) = staged() else {
        panic!("staged");
    };
    record.events.clear();
    for reason in 1..=9u32 {
        record.events.push(WorkerEvent {
            name: EventName::SessionFenced,
            id: 4,
            version: 1,
            keyword: 0x1,
            identity: SmokeIdentity {
                session_epoch: u64::from(reason),
                ..ROOT
            },
            reason: (reason % 4) + 1,
        });
    }
    assert_eq!(
        WorkerFrame::Staged(record).validate().err(),
        Some(SmokeSchemaError::InvalidEvent),
    );
}

#[test]
fn the_cleanup_summary_must_equal_the_cleanup_probe_facts() {
    let WorkerFrame::LiveCleaned(mut record) = live_cleaned() else {
        panic!("live");
    };
    record.cleanup.alias_count = 1;
    assert_eq!(
        WorkerFrame::LiveCleaned(record).validate().err(),
        Some(SmokeSchemaError::InvalidCleanup),
        "two statements of the same numbers are compared, not averaged",
    );
}

#[test]
fn trailing_bytes_invalidate_the_whole_frame() {
    let mut bytes = encode_worker_frame(&post_unload()).expect("encodes");
    bytes.push(b' ');
    assert_eq!(
        decode_worker_frame(&bytes).err(),
        Some(SmokeSchemaError::TrailingBytes),
    );
}

#[test]
fn a_bom_a_nul_or_invalid_utf8_invalidates_the_whole_frame() {
    let good = encode_worker_frame(&run_mount()).expect("encodes");
    let mut with_bom = vec![0xEF, 0xBB, 0xBF];
    with_bom.extend_from_slice(&good);
    assert_eq!(
        decode_worker_frame(&with_bom).err(),
        Some(SmokeSchemaError::Json),
    );
    let mut with_nul = good.clone();
    with_nul.insert(1, 0);
    assert_eq!(
        decode_worker_frame(&with_nul).err(),
        Some(SmokeSchemaError::Utf8),
    );
    let mut invalid = good;
    invalid.insert(1, 0xFF);
    assert_eq!(
        decode_worker_frame(&invalid).err(),
        Some(SmokeSchemaError::Utf8),
    );
}

#[test]
fn a_reordered_root_key_is_refused() {
    let bytes = encode_worker_frame(&run_mount()).expect("encodes");
    let text = String::from_utf8(bytes).expect("utf8");
    let swapped = text.replacen(
        "\"sequence\":2,\"stage\":\"RUN_MOUNT\"",
        "\"stage\":\"RUN_MOUNT\",\"sequence\":2",
        1,
    );
    assert_eq!(
        decode_worker_frame(swapped.as_bytes()).err(),
        Some(SmokeSchemaError::UnknownOrReorderedKey),
    );
}

#[test]
fn an_escaped_equivalent_key_is_refused() {
    let bytes = encode_worker_frame(&run_mount()).expect("encodes");
    let text = String::from_utf8(bytes).expect("utf8");
    let escaped = text.replacen("\"nonce\"", "\"\\u006Eonce\"", 1);
    assert!(
        decode_worker_frame(escaped.as_bytes()).is_err(),
        "an escaped key must never alias its plain form",
    );
}

#[test]
fn a_wrong_hex_width_is_refused() {
    let bytes = encode_worker_frame(&run_mount()).expect("encodes");
    let text = String::from_utf8(bytes).expect("utf8");
    let narrowed = text.replacen("\"0x0000000000000001\"", "\"0x00000001\"", 1);
    assert_eq!(
        decode_worker_frame(narrowed.as_bytes()).err(),
        Some(SmokeSchemaError::WrongType),
    );
}

#[test]
fn a_lowercase_hex_value_is_refused() {
    let bytes = encode_worker_frame(&run_mount()).expect("encodes");
    let text = String::from_utf8(bytes).expect("utf8");
    let lowered = text.replacen(NONCE, &NONCE.to_lowercase(), 1);
    assert_eq!(
        decode_worker_frame(lowered.as_bytes()).err(),
        Some(SmokeSchemaError::InvalidNonce),
    );
}

#[test]
fn a_length_outside_the_bounds_is_refused() {
    assert_eq!(
        decode_worker_frame(b"{").err(),
        Some(SmokeSchemaError::Length),
    );
    let huge = vec![b'x'; WORKER_FRAME_MAX + 1];
    assert_eq!(
        decode_worker_frame(&huge).err(),
        Some(SmokeSchemaError::Length),
    );
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

#[test]
fn a_frame_streams_through_the_length_prefix() {
    let frame = staged();
    let mut buffer = Vec::new();
    write_worker_frame(&mut buffer, &frame).expect("writes");
    let payload = encode_worker_frame(&frame).expect("encodes");
    assert_eq!(&buffer[..4], &(payload.len() as u32).to_le_bytes());
    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = read_worker_frame(&mut cursor).expect("reads");
    assert_eq!(decoded, frame);
}

#[test]
fn an_early_eof_is_distinguished_from_a_malformed_payload() {
    let frame = staged();
    let mut buffer = Vec::new();
    write_worker_frame(&mut buffer, &frame).expect("writes");
    buffer.truncate(buffer.len() - 1);
    let mut cursor = std::io::Cursor::new(buffer);
    assert!(
        matches!(
            read_worker_frame(&mut cursor),
            Err(WorkerIoError::UnexpectedEof)
        ),
        "a dead worker is not a lying worker",
    );

    // A complete frame whose payload is wrong is a schema error instead.
    let payload = b"{\"schema\":\"wrong\"}".to_vec();
    let mut malformed = (payload.len() as u32).to_le_bytes().to_vec();
    malformed.extend_from_slice(&payload);
    let mut cursor = std::io::Cursor::new(malformed);
    assert!(matches!(
        read_worker_frame(&mut cursor),
        Err(WorkerIoError::Schema(_))
    ));
}

#[test]
fn a_declared_length_outside_the_bounds_is_refused_before_the_read() {
    let mut buffer = (WORKER_FRAME_MAX as u32 + 1).to_le_bytes().to_vec();
    buffer.extend_from_slice(b"{}");
    let mut cursor = std::io::Cursor::new(buffer);
    assert!(matches!(
        read_worker_frame(&mut cursor),
        Err(WorkerIoError::Schema(SmokeSchemaError::Length))
    ));
}

#[test]
fn c4_live_mode_routes_to_public_v2_not_the_v1_harness() {
    assert_eq!(PUBLIC_SCHEMA_V2, "fsring-control-smoke/v2");
    for (index, probe) in PROBE_ROSTER_V2.iter().enumerate() {
        assert_eq!(probe.index(), index);
        assert_eq!(ProbeName::from_index(index), Some(*probe));
    }
    let mut acc = C4ProbeAccumulator::new();
    assert!(acc.serialize_range(0..0).expect("empty").is_empty());
    let report = SmokeReportV2 {
        overall: Overall::Pass,
        exit_code: 0,
        identity: Some(ROOT),
        probes: all_passing(),
        reasons: Vec::new(),
    };
    let bytes = encode_public_report_v2(&report).expect("v2");
    let text = String::from_utf8(bytes).expect("utf8");
    assert!(text.starts_with("{\"schema\":\"fsring-control-smoke/v2\""));
    assert!(!text.contains("fsring-control-smoke/v1"));
}

#[test]
fn v1_selftest_and_c3_regression_never_parse_as_v2() {
    let v1 = br#"{"schema":"fsring-control-smoke/v1","overall":"PASS","exitCode":0,"identity":null,"probes":[],"reasons":[]}
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
