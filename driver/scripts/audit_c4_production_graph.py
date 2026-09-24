"""Identity-bound production-reachability gate for the C4 recovery.

The C4 recovery stages R3/R4/R5 machinery in the same tree as production long
before any of it is allowed to run. `cargo check` proves that staged code
*compiles*; it says nothing about whether a dispatch, callback, or unload path
can reach it. This auditor is the thing that says so: it builds a call graph
from the Rust sources, walks it from a closed set of declared production roots,
and fails if a staged symbol is reachable.

Five properties make the answer worth something:

* **Roots are declared, not inferred.** A root that no longer exists, or that
  two definitions answer to, is a refusal rather than a silently smaller graph.
  A gate that quietly loses a root reports "unreachable" for everything. The
  manifest's own `productionRoots` roster is cross-checked against every gate,
  so a gate cannot walk a narrower set than the manifest advertises.
* **An edge is a mention, not a call.** A callback installed into a dispatch
  table — `*slot = Some(dispatch_default)` — is a production edge with no call
  syntax anywhere. Counting only `name(` missed exactly those, which are the
  edges a *driver* is made of. Any mention of a known function's name inside a
  body is an edge here. That over-approximates, which is the safe direction:
  this gate proves *un*reachability, so extra edges can only cause a false
  failure, never a false pass.
* **Direct contracts use exact nodes.** Task 12's sole-runner boundary is a
  separate source-qualified index: a node includes its source and optional
  inherent-impl owner, and every call expression retains its source offset.
  That index preserves multiplicity and closed caller sets; it never replaces
  the conservative mention graph used for R4/R5 unreachability.
* **Test code is not production.** Items inside `#[cfg(test)]` are excluded, so
  a recording test that constructs staged authority cannot make the staged
  symbol look reachable. Excluding them correctly needs a real lexer: a brace
  inside a string literal used to unbalance the scan, and the first file that
  did it silently pulled a whole test module back into the graph.
* **The answer is bound to an identity.** Stdout carries the canonical source
  identity, the manifest hash, this file's own hash, and the traversal roots the
  answer was computed over, so a PASS cannot be quoted for a tree — or a
  traversal — it was not computed for.

A PASS is also a *build input*, not only a printed result. `--refresh-attestation
--profile P` reruns the profile's closed gate and property rows and atomically
replaces `driver/audit/c4-production-attestation.json`; `fsring-core`'s build
script runs `--verify-attestation` whenever the private `production-attested`
feature is on — which only `fsring-fsd`'s dependency turns on — and refuses to
build if that document no longer names this exact source identity. So a
production image cannot embed a witness for a tree it was not built from.
`--verify-current-attestation --profile P` recomputes every row in memory and
requires byte equality, and never writes.

What the conservative graph does NOT do, and what therefore may not be claimed
of R4/R5 staging: its edges are mentions of bare function names, so a name that
several inherent impls answer to is one merged node, and a field read is
indistinguishable from a call. That over-approximates in the safe direction for
unreachability. Exact caller/multiplicity claims belong only to the separate
source-qualified direct rows; the manifest's `coverageBoundary` records staged
symbols still measured by their constructors in the conservative graph.
"""

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Optional

# ---------------------------------------------------------------------------
# The nested-tool marker for rows 33 and 34.
#
# The source-gate runner leases every frozen payload it supplies and hashes it
# before and after the row, but a lease proves the payload was SUPPLIED, not
# that this auditor launched it. Until this marker existed, rows 33 and 34
# declared a three-role roster that nothing observed: deleting the `+1.85.0`
# substitution in `c4_frozen_launch` below would have left the payload
# supplied, unused, and the row green.
#
# PRE and POST are both emitted so a payload swapped midway cannot report the
# truth twice, and `launchCounts` reports what THIS process launched.
#
# `rustc` and `rustdoc` are registered at zero deliberately. They are handed to
# cargo through CARGO/RUSTC/RUSTDOC and launched by cargo, not by this script;
# reporting them as launched here would be a claim this process cannot make.
# `mutation_sweep.py` records them the same way for the same reason.
#
# Nothing is emitted unless the runner set a nonce, so an ordinary developer
# run is byte-for-byte unchanged. The matrix never runs this auditor, so the
# only consumer of a marker-bearing stdout is the runner, which strips marker
# lines before it hashes a row's output.
# ---------------------------------------------------------------------------

C4_MARKER_SENTINEL = "FSRING-C4-NESTED-TOOLS "
C4_MARKER_SCHEMA = "fsring-c4-nested-tools-marker/v1"
C4_TOOL_ROLE_ORDER = (
    "powershell", "python", "git", "git-bash", "cmd",
    "cargo-1.82.0", "rustc-1.82.0", "rustdoc-1.82.0",
    "cargo-fmt-1.82.0", "rustfmt-1.82.0",
    "cargo-1.85.0", "rustc-1.85.0", "rustdoc-1.85.0",
    "cargo-fmt-1.85.0", "rustfmt-1.85.0",
    "cargo-clippy-1.85.0", "clippy-driver-1.85.0",
    "cargo-wdk-0.1.1", "infverif", "signtool",
)
C4_LAUNCH_COUNTS = {}


def c4_role_suffix(role):
    return role.upper().replace("-", "_").replace(".", "_")


def c4_note_launch(role, count=1):
    """Record one launch of a frozen role. `count=0` registers a role that was
    handed to a child rather than launched here, so the marker names it without
    claiming it ran."""
    C4_LAUNCH_COUNTS[role] = C4_LAUNCH_COUNTS.get(role, 0) + count


def c4_emit_marker(phase):
    nonce = os.environ.get("FSRING_C4_MARKER_NONCE")
    if not nonce:
        return
    tools = []
    for role in C4_TOOL_ROLE_ORDER:
        suffix = c4_role_suffix(role)
        path = os.environ.get("FSRING_C4_TOOL_" + suffix)
        if not path:
            continue
        digest = hashlib.sha256(io.open(path, "rb").read()).hexdigest()
        tools.append({
            "role": role,
            "path": path,
            "volumeSerial": os.environ.get("FSRING_C4_TOOL_" + suffix + "_VOLUME", ""),
            "fileId": os.environ.get("FSRING_C4_TOOL_" + suffix + "_FILEID", ""),
            "sha256": digest,
        })
    counts = [
        {"role": role, "count": C4_LAUNCH_COUNTS[role]}
        for role in C4_TOOL_ROLE_ORDER
        if role in C4_LAUNCH_COUNTS
    ]
    marker = {
        "schema": C4_MARKER_SCHEMA,
        "version": 1,
        "nonce": nonce,
        "phase": phase,
        "commandId": os.environ.get("FSRING_C4_COMMAND_ID", ""),
        "tools": tools,
        "launchCounts": counts,
    }
    sys.stdout.write(C4_MARKER_SENTINEL + json.dumps(
        marker, separators=(",", ":"), sort_keys=False) + "\n")
    sys.stdout.flush()


SCHEMA = "fsring-c4-production-graph/v2"
TASK12_GATE = "task12_r3_cutover_has_exactly_one_terminal_delete_path"
TASK25_GATE = "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path"
# The immutable 53-entry Task 25 zero roster, in the approved design's exact
# section 16 order. The tracked manifest must carry this same list as literal
# strings; a drift is a refusal rather than a silently smaller scan.
#
# It was 47 until Task 28's reconciliation. The design table's six-entry
# "superseded R2/R3 predecessor ownership path" row was carried only by the
# Task 12 gate, and the final `r5-cutover` profile does not carry that gate --
# so at the state this roster exists to close, six approved entries were
# guarded by nothing. Six plants into production source proved the final gate
# saw none of them. `DriverState.mounts` is spelled `.mounts` here for the
# same reason the Task 12 gate spells it that way: the scan is a substring
# search over stripped production text, and a regression writes `self.mounts`.
TASK25_ZERO_ROSTER = (
    "run_checkpoint_teardown",
    "finish_checkpoint_teardown",
    "R3TeardownComplete",
    "R3AuthorityAbsence",
    "R3PreparedCheckpointFinish",
    "R3PreparedCheckpointFinish::prepare",
    "R3FenceIncomplete",
    "R3DeletionReadiness",
    "R3FinalizerDeposit",
    "R4TeardownComplete",
    "R4AuthorityAbsence",
    "R4PreparedCheckpointFinish",
    "R4PreparedCheckpointFinish::prepare",
    "R4ResidualLedger",
    "R4FenceIncomplete",
    "R4FenceIncomplete::BaseRefusal",
    "R4FenceIncomplete::PendingRefusal",
    "R4FenceIncomplete::PublicationBlocked",
    "R4DeletionReadiness",
    "R4FinalizerDeposit",
    "PrepareCheckpointFinish",
    "CheckpointTerminalBlocked",
    "CheckpointTerminalBlocked::R3",
    "CheckpointTerminalBlocked::R4",
    "MountRegistry",
    ".mounts",
    "claim_by_process",
    "fence_all",
    "live_count",
    "fence_bound_session",
    "run_provisional_fence",
    "LegacyCompletedFenceAdapter",
    "LegacyFinalizerDepositView",
    "LegacyFenceNotRepresentable",
    "LegacyCompletedFenceAdapter::from_completed_only",
    "LegacyCompletedFenceAdapter::try_from_outcome",
    "publish_installed_setup_legacy",
    "LegacyProviderDisposition",
    "split_legacy_provider_disposition",
    "ALLOW_CHECKPOINT_TEARDOWN_PRODUCTION_EDGE",
    "ALLOW_LEGACY_SETUP_PUBLISHER_PRODUCTION_EDGE",
    "ALLOW_LEGACY_PROVIDER_DISPOSITION_PRODUCTION_EDGE",
    "ALLOW_PROVISIONAL_FENCE_PRODUCTION_EDGE",
    "run_terminal -> run_checkpoint_teardown",
    "run_terminal -> R3PreparedCheckpointFinish::prepare",
    "run_terminal -> R4PreparedCheckpointFinish::prepare",
    "run_terminal -> finish_checkpoint_teardown",
    "run_terminal -> run_provisional_fence",
    "run_provisional_fence -> package_completed_fence",
    "run_provisional_fence -> LegacyCompletedFenceAdapter::from_completed_only",
    "LegacyCompletedFenceAdapter::try_from_outcome -> LegacyFinalizerDepositView::Completed",
    "execute_setup -> publish_installed_setup_legacy",
    "fsring_dispatch_provider -> split_legacy_provider_disposition",
)
TASK25_ZERO_ROSTER_FILES = (
    "driver/audit/c4-imports-win10-x64.json",
    "driver/audit/c4-imports-win10-arm64.json",
    "driver/audit/c4-imports-win7-x64.json",
    "driver/audit/win10-imports.allow",
    "driver/audit/win7-sp1-imports.allow",
    "driver/audit/c4-stack-roots.json",
)
GATE_ORACLE_NAMES = (
        "task09_11_r3_staging_is_production_unreachable",
        "task12_r3_cutover_has_exactly_one_terminal_delete_path",
        "task13_18_r4_staging_is_production_unreachable",
        "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path",
        "task20_24_r5_staging_is_production_unreachable",
        "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path",
    )
GATE_ORACLE_ROOTS = (
        "dispatch_default",
        "driver_entry",
        "fsring_dispatch_cleanup",
        "fsring_dispatch_close",
        "fsring_dispatch_create",
        "fsring_dispatch_device_control",
        "fsring_dispatch_enter",
        "fsring_dispatch_file_system_control",
        "fsring_dispatch_fscontrol",
        "fsring_dispatch_mount",
        "fsring_dispatch_provider",
        "fsring_dispatch_setup",
        "fsring_dispatch_vdo",
        "fsring_dispatch_vdo_ioctl",
        "fsring_dispatch_verify",
        "fsring_dispatch_volume",
        "fsring_driver_unload",
        "fsring_process_loss",
        "fsring_setup_callout",
        "fsring_trace_enable_callback",
    )
GATE_ORACLE_STAGED = {
    "task09_11_r3_staging_is_production_unreachable": (
        "acknowledge_completed_control",
        "store_close_right",
        "decide_scan_continuation",
        "decide_terminal_wait",
        "decide_blocked_arrival",
        "delete_preparation_survives",
    ),
    "task12_r3_cutover_has_exactly_one_terminal_delete_path": (),
    "task13_18_r4_staging_is_production_unreachable": (
        "begin_ring_set",
        "next_ring",
        "allocate_nonzero",
        "reserve_for_setup",
        "publish_installed_setup_with_ring_set",
        "completed_ring_set",
        "contains_brand",
        "into_brand",
        "build_ring_runtime_parts",
        "for_brand",
        "is_covered",
        "acquire_sq_wait",
        "acquire_cq_consumer",
        "release_sq_wait",
        "release_cq_consumer",
        "mint_invocation",
        "check_release",
        "acquire_owner",
        "release_owner",
        "record_wake",
        "take_for_worker",
        "queue_worker",
        "begin_worker_pass",
        "finish_worker_pass",
        "begin_worker_completion",
        "handoff_done",
        "begin_install",
        "bind_install",
        "park",
        "dequeue",
        "take_early_receipt",
        "early_disposition",
        "run_next",
        "downgrade_stable_release",
        "occupy",
        "is_reusable",
        "commit_result_write",
        "commit_irp_completion",
        "commit_final_publication",
        "acquire_sq_wait_aggregate",
        "acquire_cq_consumer_aggregate",
        "authorize_resume",
        "bind_cq_consumer",
        "for_resume",
        "record_commit",
        "into_plan_parts",
        "bind_sq_wait",
        "rebind_resumed",
        "observe_cancel",
        "observe_irp",
        "arbitrate_cq_mutation",
        "has_committed",
        "prepare_for_irp",
        "commit_after_io_complete",
        "into_dispatch_status",
        "publish_vacant",
        "park_publication_fail_stop",
        "admits_install",
        "driver_owns_completion",
        "record_initialized",
        "rollback_span",
        "next_uninitialized_index",
        "begin_pending_install",
        "select_pending_install",
        "commit_pending_handoff",
        "commit_after_queue",
        "from_handoff",
        "finite_due_time_100ns",
        "dpc_entered",
        "dpc_exiting",
        "arm",
        "record_and_schedule_pending",
        "commit_after_work_queued",
        "next_reverse",
        "initialize_staged_pending_slot",
        "observe_insert_outcome",
        "from_csq",
        "csq_insert_irp",
        "csq_remove_irp",
        "csq_peek_next_irp",
        "csq_acquire_lock",
        "csq_release_lock",
        "csq_complete_canceled_irp",
        "begin_dpc_pass",
        "run_next_dpc_effect",
        "commit_after_exit_signalled",
        "forbidden_at_dispatch_level",
        "decide_pending_park",
        "exhausted_pending_completion",
        "publish_sq_or_terminalize",
        "owed_signal_generation",
        "fsring_pending_enter_timer_dpc",
        "fsring_pending_enter_worker",
        "perform_pending_effect",
        "finite_due_time",
        "allocate_pending_arena",
        "begin_pending_runtime",
        "initialize_pending_context",
        "commit_pending_context",
        "finish_pending_runtime",
        "rollback_pending_runtime",
        "free_pending_work_item",
        "queue_pending_worker",
        "slot_result_view",
        "prepare_installed_ring_setup",
        "into_uncommitted_parts",
        "commit_after_native_runtime_install",
        "build_pending_slot_parts",
        "from_parts",
        "serving_install",
        # `slot_owed_signal_generation` was here until round 16. `62bfd68`
        # deleted it from the source, no commit in that round updated either
        # side, and the manifest carried a roster entry for a symbol that exists
        # nowhere in the tree. Removed from both, which this oracle is what
        # enforces: dropping it from the JSON alone is a drift failure here.
        "finalize_native_pending_publication",
        "observe_pending_for_unload",
    ),
    "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path": (),
    "task20_24_r5_staging_is_production_unreachable": (
        "prepare_cq_release",
        "commit_cq_release",
        "bind_storage",
        "borrow_consumer",
        "cq_stream",
        "bind_drain",
        "bind_refusal",
        "bind_cq_drain",
        "try_peek",
        "preflight_notify_shape",
        "prepare_notify_commit",
        "mutation_witness",
        "credit_mutation_witness",
        "has_conservative_notify_shape",
        "names_an_arena_body",
        "cursor_mut",
        "serves",
        "is_cq_domain",
        "entry_bytes",
        "bind_credit",
        "prepare_credit_claim",
        "read_out_control",
        "grant_source_range",
        "from_published",
        "base_of",
        "arena_offset",
        "preflight_protocol",
        "prepare_consumer_release",
        "bind_mutation",
        "protocol_mutation_witness",
        "authenticated_locator",
        "protocol_commit_witness",
        "pop_packet_identity",
        "packet_identity",
        "into_consumer_token",
        "commit_protocol_abort",
        "reject_committed_protocol",
        "complete_protocol_reject",
        "into_terminal_record",
        "prepare_protocol_terminal_claim",
        "into_result",
        "commit_protocol_claim",
        "execute_effect",
        "bind_native_storage",
        "push_acquired",
        "begin_release",
        "pop_for_release",
        "park_partial_release",
        "finish_release",
        "prepare_drain",
        "restart_released_partial",
        "restart_from_complete",
        "drain_stable_prefixes_with_proof",
        "retire_credits_with_proof",
        "pair",
        "record_failed_ring",
        "into_release_proof",
        "resume_effect",
        "release_next",
        "retry_point",
        "drain_proof",
        "into_terminal_authorities",
        "release_protocol_join",
        "release_opaque_protocol_join",
        "prepare_protocol_terminal_reject",
        "try_new_fence_retry_lifecycle",
        "try_new_from_source",
        "prepare_fence_retry",
        "begin_fence_retry_run",
        "lifecycle_state",
        "begin_delay_dpc",
        "queue_from_dpc",
        "defer",
        "prepare_complete",
        "prepare_initial_complete",
        "checked_retry_due_time_100ns",
        "same_key_attempts",
        "residual_retry_point",
        "try_new_fence_residual",
        "accumulate_failed_mask",
        "residual_failed_mask",
        "fail_stop_reason",
        "due_time_100ns",
        "same_point_attempts",
        "into_queued_right",
        "into_run_right",
        "into_initial_binding",
        "has_completed_consumers",
        "has_pending_mount_bind",
        "is_transient_native",
        "from_invoked_native_refusal",
        "from_invariant_refusal",
        "allocate_fence_retry_lifecycle_id",
        "commit_retry_complete",
        "commit_initial_complete",
        "into_initial_prepare_parts",
        "into_defer_parts",
    ),
    # Round-18 evidence E1. The `task09_11` note claimed 32 names were "Now
    # production-reachable"; seven were in no edge of the graph at all. A note is
    # prose and no row read it, so the claim is a row now: these six are present
    # and unreachable, and this gate -- which the live `r5-cutover` profile runs
    # -- fails if one becomes reachable, and refuses if one is deleted. They are
    # the R3 staging surface's residue, not Task 25's own names.
    #
    # `release_control_strong_ref` is the seventh and is NOT here: it has two
    # definitions, both in `driver/fsring-fsd/src/fence.rs`, and the
    # bare-identifier edge model makes them one node, which is exactly the
    # condition `stagedTargets` refuses. Its status is recorded in the note.
    "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path": (
        "checkpoint_ledger_is_discharged",
        "from_embedded_artifact",
        "incomplete_from_refusal",
        "into_preparation_refusal",
        "preparation_refusal",
        "with_absence",
    ),
}
GATE_ORACLE_REQUIRED = {
    "task09_11_r3_staging_is_production_unreachable": (),
    "task12_r3_cutover_has_exactly_one_terminal_delete_path": (
        "prepare_native_terminal_claim",
        "claim_native_cleanup_route",
        "run_checkpoint_teardown",
        "prepare_checkpoint_finish",
        "finish_checkpoint_teardown",
        "release_strong_and_deposit",
        "prepare_final_delete",
        "run_queued_finalizer",
        "scan_one_cell_for_process",
    ),
    "task13_18_r4_staging_is_production_unreachable": (),
    "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path": (
        "initialize_staged_pending_slot",
        "fsring_pending_enter_timer_dpc",
        "fsring_pending_enter_worker",
        "finalize_native_pending_publication",
        "observe_pending_for_unload",
        "prepare_installed_ring_setup",
        "commit_after_native_runtime_install",
        "build_pending_slot_parts",
        "begin_pending_runtime",
        "finish_pending_runtime",
        "queue_pending_worker",
        "classify_worker_dequeue",
    ),
    "task20_24_r5_staging_is_production_unreachable": (),
    "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path": (
        "execute_effect",
        "drain_stable_prefixes_with_proof",
        "retire_credits_with_proof",
        "try_new_fence_retry_lifecycle",
        "prepare_complete",
        "prepare_initial_complete",
        "commit_retry_complete",
        "commit_initial_complete",
        "prepare_fence_retry",
        "begin_fence_retry_run",
        "bind_native_storage",
    ),
}
GATE_ORACLE_FORBIDDEN_SYMBOLS = {
    "task09_11_r3_staging_is_production_unreachable": (
        "execute_checkpoint_effect",
        "fence_bound_session",
        "is_published_session",
        "perform_checkpoint_effect",
        "store_deposit_and_queue",
        "verify_ledgers",
        "wait_for_terminal_outcome",
    ),
    "task12_r3_cutover_has_exactly_one_terminal_delete_path": (
        "fence_bound_session",
        "is_published_session",
        "fence_all",
        "claim_by_process",
        "live_count",
    ),
    "task13_18_r4_staging_is_production_unreachable": (),
    "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path": (
        "publish_installed_setup_legacy",
        "split_legacy_provider_disposition",
    ),
    "task20_24_r5_staging_is_production_unreachable": (),
    "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path": (
        "run_checkpoint_teardown",
        "finish_checkpoint_teardown",
    ),
}
GATE_ORACLE_PROFILES = {
    "task09_11_r3_staging_is_production_unreachable": "r3-stage",
    "task12_r3_cutover_has_exactly_one_terminal_delete_path": "r3-cutover",
    "task13_18_r4_staging_is_production_unreachable": "r4-stage",
    "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path": "r4-cutover",
    "task20_24_r5_staging_is_production_unreachable": "r5-stage",
    "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path": "r5-cutover",
}

R2_R3_PREDECESSOR_ABSENCE = (
    "fence_bound_session",
    "is_published_session",
    "fence_all",
    "claim_by_process",
    "live_count",
    "MountRegistry",
    "MountEntry",
)

TASK19_LEGACY_TOKENS = (
    "publish_installed_setup_legacy",
    "split_legacy_provider_disposition",
)

KERNEL_FENCE_NATIVE_FORWARDS = (
    ("close_session_admission", "native_close_generation_admission"),
    ("signal_pending_enter", "native_schedule_linked_pending"),
    ("wait_control_rundown", "native_wait_control_and_access_rundown"),
    ("remove_producer_mappings_reverse", "native_unmap_producer_aliases_reverse"),
    ("wait_producer_and_mapping_capture_rundown", "native_wait_producer_capture_rundown"),
    ("acquire_consumers_increasing", "native_acquire_consumers_increasing"),
    ("drain_stable_prefixes_bounded", "native_drain_stable_prefixes_bounded"),
    ("retire_credits", "native_retire_grants"),
    ("release_consumers", "native_release_consumers"),
    ("queue_installed_work", "native_queue_installed_work"),
    ("wait_pending_and_owners", "native_wait_pending_and_owner_rundown"),
    ("release_read_only_mappings_reverse", "native_unmap_readonly_aliases_reverse"),
    ("release_mdls_and_system_view", "native_release_mdls_and_system_view"),
    ("release_captured_process", "native_dereference_process"),
    ("dismount_and_delete_devices", "native_take_or_join_mount_and_delete"),
    ("release_transient_backing", "native_release_transient_arrays"),
)

GATE_KEYS = frozenset(
    {
        "profile",
        "note",
        "coverageBoundary",
        "roots",
        "requiredReachable",
        "requiredDirectEdges",
        "soleDirectCallers",
        "deniedIngresses",
        "stagedTargets",
        "ambiguousUnstaged",
        "unstageableViaAmbiguousCaller",
        "forbiddenSymbols",
        "forbiddenEdges",
        "forbiddenText",
        "zeroRoster",
        "zeroRosterFiles",
    }
)
TASK12_GATE_KEYS = frozenset(
    {
        "profile",
        "note",
        "roots",
        "requiredReachable",
        "requiredDirectEdges",
        "soleDirectCallers",
        "deniedIngresses",
        "stagedTargets",
        "forbiddenSymbols",
        "forbiddenEdges",
        "forbiddenText",
    }
)
TASK12_ORACLE_KEYS = (
    "requiredDirectEdges",
    "soleDirectCallers",
    "deniedIngresses",
)

# The closed source-identity domain, exactly as the recovery plan fixes it. It
# is deliberately literal: a glob that grew a directory would silently change
# what an identity means.
IDENTITY_PACKAGE_ROOTS = (
    "fsring-abi",
    "driver/fsring-core",
    "driver/fsring-fsd",
    "driver/fsring-sys",
)
IDENTITY_EXTRA_FILES = (
    "fsring-abi/Cargo.toml",
    "driver/fsring-core/Cargo.toml",
    "driver/fsring-fsd/Cargo.toml",
    "driver/fsring-sys/Cargo.toml",
    "driver/Cargo.toml",
    "driver/Cargo.lock",
)


class AuditError(Exception):
    """A refusal. Every one of these is a nonzero exit, never a warning."""


# ---------------------------------------------------------------------------
# Source identity
# ---------------------------------------------------------------------------


def repo_root():
    return os.getcwd()


def tracked_files(root):
    """Every path git tracks, normalized to forward slashes.

    Tracked, not on-disk: an untracked Rust file inside the domain is a refusal
    rather than an input, so an identity cannot be moved by a file nobody
    committed.
    """
    result = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise AuditError("git ls-files failed; the source identity needs a git tree")
    names = result.stdout.decode("utf-8").split("\0")
    return [name for name in names if name]


def untracked_rust_inputs(root, tracked):
    """Rust sources on disk inside the domain that git does not track.

    Selecting the domain from `git ls-files` alone makes an untracked `.rs` an
    *omission* rather than a refusal: a new file could join the build without
    joining the identity, which is exactly how a stale attestation would keep
    passing. Cargo's own output is not source, so `target` is skipped.
    """
    offenders = []
    for package in IDENTITY_PACKAGE_ROOTS:
        base = os.path.join(root, package.replace("/", os.sep))
        for current, directories, files in os.walk(base):
            directories[:] = [name for name in directories if name not in ("target", ".git")]
            for name in files:
                if not name.endswith(".rs"):
                    continue
                full = os.path.join(current, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                if rel not in tracked:
                    offenders.append(rel)
    return sorted(offenders)


def identity_domain(root, auditor_path, manifest_path):
    """The ordered closed domain the canonical identity is computed over."""
    tracked = set(tracked_files(root))
    untracked = untracked_rust_inputs(root, tracked)
    if untracked:
        raise AuditError(
            "untracked Rust inputs inside the identity domain: %s (stage them first)"
            % ", ".join(untracked)
        )
    selected = set()
    for package in IDENTITY_PACKAGE_ROOTS:
        prefix = package + "/"
        for name in tracked:
            if name.startswith(prefix) and name.endswith(".rs"):
                selected.add(name)
    for name in IDENTITY_EXTRA_FILES:
        if name not in tracked:
            raise AuditError("identity domain member is not tracked: %s" % name)
        selected.add(name)
    for name in (auditor_path, manifest_path):
        rel = os.path.relpath(name, root).replace(os.sep, "/")
        if rel not in tracked:
            # The auditor and manifest are inputs to the identity they stamp.
            # Refusing an untracked one is what stops a PASS from being minted
            # by a script or manifest that exists only in a working tree.
            raise AuditError("identity domain member is not tracked: %s" % rel)
        selected.add(rel)
    lowered = {}
    for name in selected:
        key = name.lower()
        if key in lowered and lowered[key] != name:
            raise AuditError("case-colliding identity paths: %s and %s" % (lowered[key], name))
        lowered[key] = name
    return sorted(selected)


def source_identity(root, domain, source_roots):
    """SHA-256 over the traversal roots, then each member's path and bytes.

    The traversal roots are inside the hash, not beside it: two runs over
    different `--source-root` sets walk different graphs and must not be able
    to produce the same stamp.
    """
    digest = hashlib.sha256()
    digest.update(b"source-roots\0")
    for entry in sorted(source_roots):
        digest.update(entry.replace(os.sep, "/").encode("utf-8"))
        digest.update(b"\0")
    digest.update(b"files\0")
    for name in domain:
        path = os.path.join(root, name.replace("/", os.sep))
        if os.path.islink(path):
            raise AuditError("identity domain member is a symlink: %s" % name)
        with io.open(path, "rb") as handle:
            data = handle.read()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest().upper()


def file_sha256(path):
    with io.open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest().upper()


# ---------------------------------------------------------------------------
# Lexing
# ---------------------------------------------------------------------------
#
# The predecessor scanned for `//` and counted `{`/`}` positionally. Both are
# wrong in the presence of literals: `format!("struct {name} {{")` unbalances
# the brace scan, and `"http://x"` truncates a line at the `//`. A single
# literal-aware pass replaces both, and everything downstream reads its output.


def blank_literals_and_comments(text):
    """Return `text` with comments and literal *contents* replaced by spaces.

    Lengths and line structure are preserved, so every offset computed on the
    result is an offset into the original. Only the delimiters of a literal
    survive, which is enough for the brace scan and removes every identifier a
    literal could otherwise contribute to the graph.
    """
    out = list(text)
    index = 0
    length = len(text)

    def blank(start, stop):
        for position in range(start, min(stop, length)):
            if out[position] != "\n":
                out[position] = " "

    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ""

        if char == "/" and nxt == "/":
            stop = text.find("\n", index)
            stop = length if stop < 0 else stop
            blank(index, stop)
            index = stop
            continue

        if char == "/" and nxt == "*":
            # Rust block comments nest.
            depth = 0
            scan = index
            while scan < length:
                if text.startswith("/*", scan):
                    depth += 1
                    scan += 2
                elif text.startswith("*/", scan):
                    depth -= 1
                    scan += 2
                    if depth == 0:
                        break
                else:
                    scan += 1
            blank(index, scan)
            index = scan
            continue

        if char == "r" and (nxt == '"' or nxt == "#"):
            # Raw string: r"...", r#"..."#, r##"..."##
            hashes = 0
            scan = index + 1
            while scan < length and text[scan] == "#":
                hashes += 1
                scan += 1
            if scan < length and text[scan] == '"':
                terminator = '"' + "#" * hashes
                stop = text.find(terminator, scan + 1)
                stop = length if stop < 0 else stop + len(terminator)
                blank(scan + 1, stop - len(terminator))
                index = stop
                continue

        if char == '"':
            scan = index + 1
            while scan < length:
                if text[scan] == "\\":
                    scan += 2
                    continue
                if text[scan] == '"':
                    break
                scan += 1
            blank(index + 1, scan)
            index = min(scan + 1, length)
            continue

        if char == "'":
            # A char literal, or a lifetime. A lifetime is `'ident` with no
            # closing quote, and blanking it would be harmless anyway; the
            # distinction matters only so the scan does not run away.
            scan = index + 1
            if scan < length and text[scan] == "\\":
                scan += 2
                while scan < length and text[scan] != "'":
                    scan += 1
                blank(index + 1, scan)
                index = min(scan + 1, length)
                continue
            if scan + 1 < length and text[scan + 1] == "'":
                blank(index + 1, scan + 1)
                index = scan + 2
                continue
            index += 1
            continue

        index += 1

    return "".join(out)


def matching_brace(text, open_index):
    """Index of the `}` closing the `{` at `open_index`, or -1.

    `text` must already have been through `blank_literals_and_comments`.
    """
    depth = 0
    index = open_index
    while index < len(text):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


# ---------------------------------------------------------------------------
# The Rust call graph
# ---------------------------------------------------------------------------

FN_DEFINITION = re.compile(
    r"(?:^|\n)[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r'(?:extern\s+"[^"]*"\s+)?'
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)

DIRECT_FN_DEFINITION = re.compile(
    r"(?:^|[\n{};])[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r'(?:extern\s+"[^"]*"\s+)?'
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _matching_square_bracket(text, open_index):
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "[":
            depth += 1
        elif text[index] == "]":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _cfg_test_value(predicate):
    """Three-valued cfg result with the production fact `test = false`."""
    predicate = predicate.strip()
    if predicate == "test":
        return False
    match = re.fullmatch(r"(all|any|not)\s*\((.*)\)", predicate, re.DOTALL)
    if match is None:
        return None
    operator, arguments_text = match.groups()
    values = [_cfg_test_value(argument) for argument in _split_top_level(arguments_text)]
    if operator == "not":
        return None if len(values) != 1 or values[0] is None else not values[0]
    if operator == "all":
        if any(value is False for value in values):
            return False
        return True if all(value is True for value in values) else None
    if any(value is True for value in values):
        return True
    return False if all(value is False for value in values) else None


def _cfg_attribute_value(kind, arguments):
    if kind == "cfg":
        return _cfg_test_value(arguments)
    parts = _split_top_level(arguments)
    if len(parts) < 2:
        raise AuditError("cfg_attr has no applied attribute")
    condition = _cfg_test_value(parts[0])
    if condition is False:
        return True
    applied = []
    for attribute in parts[1:]:
        match = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", attribute, re.DOTALL)
        if match is not None:
            applied.append(_cfg_test_value(match.group(1)))
    if not applied:
        return True
    if any(value is False for value in applied):
        applied_value = False
    elif all(value is True for value in applied):
        applied_value = True
    else:
        applied_value = None
    if condition is True:
        return applied_value
    # Unknown non-test predicates stay in the conservative graph. Exact rows
    # may only rely on cfg/cfg_attr outcomes made decidable by `test = false`.
    return True if applied_value is True else None


def _skip_outer_attributes(text, index):
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if not text.startswith("#[", index):
            return index
        close = _matching_square_bracket(text, index + 1)
        if close < 0:
            raise AuditError("an outer attribute is unbalanced")
        index = close + 1


def _attributed_construct_end(text, after_attribute):
    start = _skip_outer_attributes(text, after_attribute)
    if start >= len(text):
        raise AuditError("a cfg-disabled construct has no body to remove")
    if text[start] == "{":
        close = matching_brace(text, start)
        if close < 0:
            raise AuditError("a cfg-disabled block is unbalanced")
        return close + 1

    item_prefix = re.match(
        r"(?:pub(?:\s*\([^)]*\))?\s+)?"
        r"(?:(?:default|const|async|unsafe)\s+)*"
        r"(?:extern\s+\"[^\"]*\"\s+)?"
        r"(?:fn|impl|trait|mod|struct|enum|union|macro_rules)\b",
        text[start:],
    )
    if item_prefix is not None:
        brace = text.find("{", start + item_prefix.end())
        semicolon = text.find(";", start + item_prefix.end())
        if semicolon >= 0 and (brace < 0 or semicolon < brace):
            return semicolon + 1
        if brace < 0:
            raise AuditError("a cfg-disabled item has no delimiter")
        close = matching_brace(text, brace)
        if close < 0:
            raise AuditError("a cfg-disabled item's body is unbalanced")
        return close + 1

    paren = bracket = brace = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket:
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}" and brace:
            brace -= 1
        elif char == "}" and paren == 0 and bracket == 0:
            return index
        elif char in ";," and paren == 0 and bracket == 0 and brace == 0:
            return index + 1
    raise AuditError("a cfg-disabled construct has no delimiter")


def strip_cfg_test(text):
    """Blank constructs disabled when Rust compiles with `test = false`.

    Test code is not production, and this is the only reason the gate can say
    anything at all: the recording tests deliberately construct staged
    authority, so counting them would make every staged symbol reachable and
    the gate would answer "unreachable" about nothing, forever.

    `text` must already have been through `blank_literals_and_comments`, so a
    brace inside a string cannot unbalance the scan. A `#[cfg(test)]` whose
    body cannot be delimited is a refusal, not a silent skip: silently keeping
    the module is exactly how test code re-entered the graph unnoticed.
    """
    # Blank instead of deleting so every later direct-call offset remains an
    # offset into the original source file.
    out = list(text)
    cursor = 0
    pattern = re.compile(r"#\[\s*(cfg(?:_attr)?)\s*\(")
    for match in pattern.finditer(text):
        start = match.start()
        if start < cursor:
            continue
        attribute_close = _matching_square_bracket(text, match.start() + 1)
        if attribute_close < 0:
            raise AuditError("a cfg attribute is unbalanced")
        arguments_close = _matching_paren(text, match.end() - 1)
        if arguments_close < 0 or arguments_close > attribute_close:
            raise AuditError("a cfg attribute's arguments are unbalanced")
        arguments = text[match.end() : arguments_close]
        value = _cfg_attribute_value(match.group(1), arguments)
        end = (
            _attributed_construct_end(text, attribute_close + 1)
            if value is False
            else attribute_close + 1
        )
        for position in range(start, end):
            if out[position] != "\n":
                out[position] = " "
        cursor = end
    return "".join(out)


def signature_body_start(text, after):
    """Index of the `{` that opens a function body, or `None` for no body.

    **The naive "first `;` before the first `{`" test is wrong**, and it was
    wrong here for a long time: a signature containing an array type --
    `[u64; SLOT_CLASS_COUNT]`, `-> Result<[u8; 32], E>` -- has a semicolon
    *inside* brackets, so the function read as a bodyless trait signature and
    its body was never scanned. Thirty-seven functions across the two source
    roots were invisible to the reachability walk, including production boot-path
    code, which means every edge out of them was missing from the proof.

    Depth is tracked over `(` and `[` only. Angle brackets are not tracked
    because they are ambiguous with comparison operators, and they do not need
    to be: every `;` a generic argument can contain is inside an array type, and
    that array's brackets are counted.
    """
    depth = 0
    index = after
    while index < len(text):
        char = text[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif depth == 0:
            if char == ";":
                return None
            if char == "{":
                return index
        index += 1
    return None


def function_bodies(text):
    """Yield `(name, body)` for every function definition in `text`."""
    for match in FN_DEFINITION.finditer(text):
        name = match.group(1)
        brace = signature_body_start(text, match.end())
        if brace is None:
            # A trait method signature with no body.
            continue
        close = matching_brace(text, brace)
        if close == -1:
            continue
        yield name, text[brace + 1 : close]


@dataclass(frozen=True)
class NodeRef:
    """One exact function definition in the direct-call index."""

    source: str
    owner: Optional[str]
    symbol: str


@dataclass(frozen=True)
class DirectFunction:
    node: NodeRef
    body: str
    body_start: int
    definition_start: int
    signature_end: int
    inherent: bool


@dataclass(frozen=True)
class DirectCall:
    caller: NodeRef
    callee: NodeRef
    source_offset: int


@dataclass(frozen=True)
class IndirectReference:
    caller: NodeRef
    target: NodeRef
    source_offset: int
    kind: str


def _top_level_keyword(text, keyword):
    """Return the last top-level `keyword` offset, or -1."""
    angle = paren = bracket = 0
    found = -1
    index = 0
    while index < len(text):
        char = text[index]
        if char == "<":
            angle += 1
        elif char == ">" and angle:
            angle -= 1
        elif char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket:
            bracket -= 1
        if angle == 0 and paren == 0 and bracket == 0 and text.startswith(keyword, index):
            before = text[index - 1] if index else " "
            after_index = index + len(keyword)
            after = text[after_index] if after_index < len(text) else " "
            if not (before.isalnum() or before == "_") and not (
                after.isalnum() or after == "_"
            ):
                found = index
        index += 1
    return found


def _strip_leading_generics(text):
    text = text.lstrip()
    if not text.startswith("<"):
        return text
    depth = 0
    for index, char in enumerate(text):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth == 0:
                return text[index + 1 :].lstrip()
    return text


def _type_owner(text):
    """The terminal path identifier of an impl/trait self type."""
    text = text.strip()
    where = _top_level_keyword(text, "where")
    if where >= 0:
        text = text[:where].rstrip()
    angle = text.find("<")
    if angle >= 0:
        text = text[:angle].rstrip()
    identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return identifiers[-1] if identifiers else None


def rust_owner_blocks(text):
    """`(open, close, owner, inherent)` for impl and trait item blocks."""
    blocks = []
    for match in re.finditer(r"(?m)^[ \t]*(?:unsafe\s+)?impl\b", text):
        impl_word = text.find("impl", match.start(), match.end())
        brace = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        close = matching_brace(text, brace)
        if close < 0:
            continue
        header = _strip_leading_generics(text[impl_word + len("impl") : brace])
        for_offset = _top_level_keyword(header, "for")
        inherent = for_offset < 0
        self_type = header if inherent else header[for_offset + len("for") :]
        owner = _type_owner(self_type)
        if owner:
            blocks.append((brace, close, owner, inherent))
    for match in re.finditer(
        r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?trait\s+"
        r"([A-Za-z_][A-Za-z0-9_]*)\b",
        text,
    ):
        brace = text.find("{", match.end())
        if brace < 0:
            continue
        close = matching_brace(text, brace)
        if close >= 0:
            blocks.append((brace, close, match.group(1), False))
    return blocks


def direct_function_definitions(rel, text):
    """Exact direct-graph definitions from one stripped production source."""
    owner_blocks = rust_owner_blocks(text)
    definitions = []
    for match in DIRECT_FN_DEFINITION.finditer(text):
        name = match.group(1)
        brace = signature_body_start(text, match.end())
        if brace is None:
            continue
        close = matching_brace(text, brace)
        if close < 0:
            continue
        containers = [
            block for block in owner_blocks if block[0] < match.start(1) < block[1]
        ]
        if containers:
            _open, _close, owner, inherent = min(
                containers, key=lambda block: block[1] - block[0]
            )
        else:
            owner, inherent = None, False
        start = match.start() + (
            1 if text[match.start() : match.start() + 1] in "\n{};" else 0
        )
        definitions.append(
            DirectFunction(
                node=NodeRef(rel, owner, name),
                body=text[brace + 1 : close],
                body_start=brace + 1,
                definition_start=start,
                signature_end=brace,
                inherent=inherent,
            )
        )
    return definitions


CALL_EXPRESSION = re.compile(
    r"(?<![A-Za-z0-9_:.])"
    r"(?P<path>(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*::\s*<[^;{}()]*>)?\s*\("
)


def _blank_ranges(text, ranges):
    out = list(text)
    for start, end in sorted(ranges):
        for index in range(max(0, start), min(len(out), end)):
            if out[index] != "\n":
                out[index] = " "
    return "".join(out)


def _closure_starts_expression(text, start):
    index = start - 1
    while index >= 0 and text[index].isspace():
        index -= 1
    if index < 0 or text[index] in "=([{,;:":
        return True
    if text[index] == ">" and index and text[index - 1] == "=":
        return True
    word = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", text[: index + 1])
    return word is not None and word.group(1) in {"return", "break", "yield"}


def _non_immediate_expression_end(text, start):
    paren = bracket = brace = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "(":
            paren += 1
        elif char == ")":
            if paren == 0 and bracket == 0 and brace == 0:
                return index
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            if bracket == 0 and paren == 0 and brace == 0:
                return index
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            if brace == 0 and paren == 0 and bracket == 0:
                return index
            brace = max(0, brace - 1)
        elif char in ",;" and paren == 0 and bracket == 0 and brace == 0:
            return index
    return len(text)


def blank_non_immediate_scopes(body):
    """Blank nested code whose construction is not a call by the outer fn."""
    ranges = []
    macro_invocation = re.compile(
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*"
        r"[A-Za-z_][A-Za-z0-9_]*\s*!\s*([({[])"
    )
    for match in macro_invocation.finditer(body):
        open_index = match.end() - 1
        opener = body[open_index]
        if opener == "{":
            close = matching_brace(body, open_index)
        elif opener == "(":
            close = _matching_paren(body, open_index)
        else:
            close = _matching_square_bracket(body, open_index)
        if close < 0:
            raise AuditError("a macro token tree is unbalanced")
        ranges.append((match.start(), close + 1))
    block_patterns = (
        re.compile(r"\basync(?:\s+move)?\s*\{"),
        re.compile(r"\bconst\s*\{"),
        re.compile(r"\bmacro_rules\s*!\s*[A-Za-z_][A-Za-z0-9_]*\s*\{"),
    )
    for pattern in block_patterns:
        for match in pattern.finditer(body):
            brace = body.find("{", match.start(), match.end())
            close = matching_brace(body, brace)
            if close < 0:
                raise AuditError("a nested non-immediate scope is unbalanced")
            ranges.append((match.start(), close + 1))

    for match in DIRECT_FN_DEFINITION.finditer(body):
        brace = body.find("{", match.end())
        semicolon = body.find(";", match.end())
        if brace >= 0 and (semicolon < 0 or brace < semicolon):
            close = matching_brace(body, brace)
            if close < 0:
                raise AuditError("a nested function body is unbalanced")
            ranges.append((match.start(), close + 1))

    closure = re.compile(r"(?:(?:async|move)\s+)*(?:\|\||\|[^|\n]*\|)")
    for match in closure.finditer(body):
        if not _closure_starts_expression(body, match.start()):
            continue
        expression = match.end()
        while expression < len(body) and body[expression].isspace():
            expression += 1
        if expression < len(body) and body[expression] == "{":
            close = matching_brace(body, expression)
            if close < 0:
                raise AuditError("a closure body is unbalanced")
            end = close + 1
        else:
            end = _non_immediate_expression_end(body, expression)
        ranges.append((match.start(), end))
    return _blank_ranges(body, ranges)


def _source_module(node):
    parts = node.source.replace("\\", "/").split("/")
    if "src" in parts:
        parts = parts[parts.index("src") + 1 :]
    if not parts:
        return ()
    filename = parts[-1]
    stem = filename[:-3] if filename.endswith(".rs") else filename
    modules = parts[:-1]
    if stem not in {"lib", "main", "mod"}:
        modules.append(stem)
    return tuple(modules)


def _qualified_source_matches(prefix, caller, target):
    target_module = _source_module(target)
    caller_module = _source_module(caller)
    if not prefix:
        return True
    if prefix[0] == "crate":
        return tuple(prefix[1:]) == target_module
    if prefix[0] == "self":
        return caller_module + tuple(prefix[1:]) == target_module
    if prefix[0] == "super":
        count = 0
        while count < len(prefix) and prefix[count] == "super":
            count += 1
        if count > len(caller_module):
            return False
        return caller_module[: len(caller_module) - count] + tuple(prefix[count:]) == target_module
    return tuple(prefix) == target_module


def _call_target(path, caller, definitions):
    segments = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", path)
    if not segments:
        return None
    symbol = segments[-1]
    owner = None
    prefix = segments[:-1]
    if prefix:
        proposed = caller.owner if prefix[-1] == "Self" else prefix[-1]
        if proposed and any(
            definition.node.owner == proposed and definition.node.symbol == symbol
            for definition in definitions
        ):
            owner = proposed
            prefix = prefix[:-1]
    candidates = [
        definition.node
        for definition in definitions
        if definition.node.owner == owner
        and definition.node.symbol == symbol
        and (len(segments) == 1 or _qualified_source_matches(prefix, caller, definition.node))
    ]
    return candidates[0] if len(candidates) == 1 else None


USE_STATEMENT = re.compile(r"\buse\s+([^;]+);", re.DOTALL)


def _use_tree_aliases(tree, prefix=""):
    tree = tree.strip()
    brace = tree.find("{")
    if brace >= 0:
        close = matching_brace(tree, brace)
        if close < 0:
            raise AuditError("a grouped use tree is unbalanced")
        head = re.sub(r"\s*::\s*$", "", tree[:brace].strip())
        base = "::".join(part for part in (prefix, head) if part)
        aliases = []
        for branch in _split_top_level(tree[brace + 1 : close]):
            aliases.extend(_use_tree_aliases(branch, base))
        return aliases
    match = re.fullmatch(
        r"(?P<path>(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*"
        r"[A-Za-z_][A-Za-z0-9_]*)\s+as\s+"
        r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)",
        tree,
    )
    if match is None:
        return []
    path = "::".join(part for part in (prefix, match.group("path")) if part)
    return [(path, match.group("alias"))]


def _use_alias_targets(sources, definitions):
    aliases = {}
    pending = []
    by_symbol = {}
    for definition in definitions:
        by_symbol.setdefault(definition.node.symbol, []).append(definition.node)
    for rel, text in sources:
        module = NodeRef(rel, None, "__module__")
        for statement in USE_STATEMENT.finditer(text):
            for path, alias in _use_tree_aliases(statement.group(1)):
                target = _call_target(path, module, definitions)
                if target is None:
                    final = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", path)[-1]
                    candidates = by_symbol.get(final, ())
                    target = candidates[0] if len(candidates) == 1 else None
                if target is not None:
                    aliases.setdefault(alias, set()).add(target)
                else:
                    pending.append((alias, path))
    changed = True
    while changed and pending:
        changed = False
        remaining = []
        for alias, path in pending:
            final = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", path)[-1]
            targets = aliases.get(final)
            if targets:
                aliases.setdefault(alias, set()).update(targets)
                changed = True
            else:
                remaining.append((alias, path))
        pending = remaining
    return aliases


def build_direct_call_index(root, source_roots, test_files):
    """Return exact definitions and multiplicity-preserving direct calls."""
    sources = list(production_sources(root, source_roots, test_files))
    definitions = []
    for rel, text in sources:
        definitions.extend(direct_function_definitions(rel, text))
    calls = []
    direct_target_offsets = set()
    for definition in definitions:
        executable_body = blank_non_immediate_scopes(definition.body)
        for match in CALL_EXPRESSION.finditer(executable_body):
            callee = _call_target(match.group("path"), definition.node, definitions)
            if callee is not None:
                identifiers = list(IDENTIFIER.finditer(match.group("path")))
                target_offset = (
                    definition.body_start
                    + match.start("path")
                    + identifiers[-1].start()
                )
                calls.append(
                    DirectCall(
                        caller=definition.node,
                        callee=callee,
                        source_offset=definition.body_start + match.start("path"),
                    )
                )
                direct_target_offsets.add((definition.node, callee, target_offset))

    by_symbol = {}
    for definition in definitions:
        by_symbol.setdefault(definition.node.symbol, []).append(definition.node)
    aliases = _use_alias_targets(sources, definitions)
    indirect = []
    for definition in definitions:
        for mention in IDENTIFIER.finditer(definition.body):
            offset = definition.body_start + mention.start()
            symbol = mention.group(0)
            targets = set()
            candidates = by_symbol.get(symbol, ())
            if len(candidates) == 1:
                targets.add(candidates[0])
            targets.update(aliases.get(symbol, ()))
            for target in targets:
                if (definition.node, target, offset) in direct_target_offsets:
                    continue
                indirect.append(
                    IndirectReference(
                        caller=definition.node,
                        target=target,
                        source_offset=offset,
                        kind="use alias" if symbol in aliases else "function item",
                    )
                )
    return definitions, calls, indirect


def _parse_node_ref(row, role):
    if not isinstance(row, dict) or set(row) != {"source", "symbol"}:
        raise AuditError("%s NodeRef must contain exactly source and symbol" % role)
    source = row["source"]
    symbol = row["symbol"]
    if not isinstance(source, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+\.rs", source):
        raise AuditError("%s NodeRef has an invalid source" % role)
    if source.startswith("/") or ".." in source.split("/") or "\\" in source:
        raise AuditError("%s NodeRef source is not repo-relative" % role)
    if not isinstance(symbol, str):
        raise AuditError("%s NodeRef has an invalid symbol" % role)
    match = re.fullmatch(
        r"(?:(?P<owner>[A-Za-z_][A-Za-z0-9_]*)::)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        symbol,
    )
    if not match:
        raise AuditError("%s NodeRef has an invalid symbol: %r" % (role, symbol))
    return NodeRef(source, match.group("owner"), match.group("name"))


def _display_node(node):
    symbol = "%s::%s" % (node.owner, node.symbol) if node.owner else node.symbol
    return "%s#%s" % (node.source, symbol)


def _resolve_node_ref(row, role, definitions, require_inherent=False):
    requested = _parse_node_ref(row, role)
    candidates = [
        definition
        for definition in definitions
        if definition.node.owner == requested.owner
        and definition.node.symbol == requested.symbol
    ]
    if require_inherent and requested.owner is not None:
        candidates = [definition for definition in candidates if definition.inherent]
    if not candidates:
        raise AuditError(
            "%s definition is absent or has the wrong owner: %s"
            % (role, _display_node(requested))
        )
    # An inherent method and a trait impl of the same name, on the same type in
    # the same file, are ONE node here: the direct-call index keys every call by
    # (source, owner, symbol), so it cannot attribute a call to one body rather
    # than the other, and a bypass added to either body raises this node's
    # observed count. Collapsing them is therefore exact for counting and fails
    # closed. Ambiguity the declared source cannot settle — the same symbol
    # defined in more than one file — stays an error.
    sources = sorted({item.node.source for item in candidates})
    if len(sources) != 1:
        raise AuditError(
            "%s definition is ambiguous: %s in %s" % (role, _display_node(requested), sources)
        )
    resolved = candidates[0]
    if resolved.node.source != requested.source:
        raise AuditError(
            "%s definition is in %s, not declared source %s"
            % (role, resolved.node.source, requested.source)
        )
    return resolved


def evaluate_required_direct_edges(rows, definitions, calls):
    """Evaluate exact direct rows and return `(violations, evidence)`."""
    if not isinstance(rows, list):
        raise AuditError("requiredDirectEdges is not a list")
    violations = []
    evidence = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "caller",
            "callee",
            "exactCalls",
            "soleCaller",
        }:
            raise AuditError(
                "requiredDirectEdges[%d] must contain exactly caller, callee, exactCalls, soleCaller"
                % index
            )
        exact = row["exactCalls"]
        sole = row["soleCaller"]
        if isinstance(exact, bool) or not isinstance(exact, int) or exact < 1:
            raise AuditError("requiredDirectEdges[%d].exactCalls is not a positive integer" % index)
        if not isinstance(sole, bool):
            raise AuditError("requiredDirectEdges[%d].soleCaller is not boolean" % index)
        caller_definition = _resolve_node_ref(row["caller"], "direct caller", definitions)
        requested_callee = _parse_node_ref(row["callee"], "direct callee")
        callee_definition = _resolve_node_ref(
            row["callee"],
            "direct callee",
            definitions,
            require_inherent=requested_callee.owner is not None,
        )
        matching = [
            call
            for call in calls
            if call.caller == caller_definition.node and call.callee == callee_definition.node
        ]
        all_to_callee = [call for call in calls if call.callee == callee_definition.node]
        observed = len(matching)
        if observed != exact:
            violations.append(
                "required direct edge %s -> %s expected %d calls, observed %d"
                % (
                    _display_node(caller_definition.node),
                    _display_node(callee_definition.node),
                    exact,
                    observed,
                )
            )
        unexpected = sorted(
            {
                _display_node(call.caller)
                for call in all_to_callee
                if call.caller != caller_definition.node
            }
        )
        if sole and (unexpected or len(all_to_callee) != exact):
            observed_callers = sorted(
                {_display_node(call.caller) for call in all_to_callee}
            )
            violations.append(
                "sole direct caller for %s must be %s with %d calls; observed callers %s and %d calls"
                % (
                    _display_node(callee_definition.node),
                    _display_node(caller_definition.node),
                    exact,
                    observed_callers,
                    len(all_to_callee),
                )
            )
        evidence.append(
            {
                "caller": _display_node(caller_definition.node),
                "callee": _display_node(callee_definition.node),
                "requiredCalls": exact,
                "observedCalls": observed,
                "soleCaller": sole,
                "observedOffsets": [call.source_offset for call in matching],
            }
        )
    return violations, evidence


def evaluate_sole_direct_callers(rows, definitions, calls, indirect_references):
    """Evaluate closed caller rosters for sensitive direct destinations."""
    if not isinstance(rows, list):
        raise AuditError("soleDirectCallers is not a list")
    violations = []
    evidence = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"callee", "callers"}:
            raise AuditError(
                "soleDirectCallers[%d] must contain exactly callee and callers" % index
            )
        requested_callee = _parse_node_ref(row["callee"], "sensitive callee")
        callee = _resolve_node_ref(
            row["callee"],
            "sensitive callee",
            definitions,
            require_inherent=requested_callee.owner is not None,
        )
        caller_rows = row["callers"]
        if not isinstance(caller_rows, list) or not caller_rows:
            raise AuditError("soleDirectCallers[%d].callers is not a nonempty list" % index)
        expected = {}
        for caller_index, caller_row in enumerate(caller_rows):
            if not isinstance(caller_row, dict) or set(caller_row) != {
                "caller",
                "exactCalls",
            }:
                raise AuditError(
                    "soleDirectCallers[%d].callers[%d] must contain exactly caller and exactCalls"
                    % (index, caller_index)
                )
            exact = caller_row["exactCalls"]
            if isinstance(exact, bool) or not isinstance(exact, int) or exact < 1:
                raise AuditError(
                    "soleDirectCallers[%d].callers[%d].exactCalls is not a positive integer"
                    % (index, caller_index)
                )
            caller = _resolve_node_ref(caller_row["caller"], "sensitive caller", definitions)
            if caller.node in expected:
                raise AuditError(
                    "soleDirectCallers[%d] repeats caller %s"
                    % (index, _display_node(caller.node))
                )
            expected[caller.node] = exact

        observed_calls = [call for call in calls if call.callee == callee.node]
        observed = {}
        offsets = {}
        for call in observed_calls:
            observed[call.caller] = observed.get(call.caller, 0) + 1
            offsets.setdefault(call.caller, []).append(call.source_offset)
        for caller, exact in expected.items():
            actual = observed.get(caller, 0)
            if actual != exact:
                violations.append(
                    "closed direct caller roster for %s expected %s with %d calls, observed %d"
                    % (_display_node(callee.node), _display_node(caller), exact, actual)
                )
        unexpected = sorted(set(observed) - set(expected), key=_display_node)
        if unexpected:
            violations.append(
                "closed direct caller roster for %s has unexpected callers %s"
                % (
                    _display_node(callee.node),
                    ", ".join(_display_node(caller) for caller in unexpected),
                )
            )
        for reference in indirect_references:
            if reference.target != callee.node:
                continue
            violations.append(
                "closed direct caller roster for %s has indirect reference from %s at %d (%s)"
                % (
                    _display_node(callee.node),
                    _display_node(reference.caller),
                    reference.source_offset,
                    reference.kind,
                )
            )
        evidence.append(
            {
                "callee": _display_node(callee.node),
                "requiredCallers": [
                    {
                        "caller": _display_node(caller),
                        "requiredCalls": exact,
                        "observedCalls": observed.get(caller, 0),
                        "observedOffsets": offsets.get(caller, []),
                    }
                    for caller, exact in sorted(
                        expected.items(), key=lambda item: _display_node(item[0])
                    )
                ],
                "unexpectedCallers": [
                    {
                        "caller": _display_node(caller),
                        "observedCalls": observed[caller],
                        "observedOffsets": offsets[caller],
                    }
                    for caller in unexpected
                ],
            }
        )
    return violations, evidence


def _split_top_level(text, separator=","):
    parts = []
    start = 0
    angle = paren = bracket = brace = 0
    for index, char in enumerate(text):
        if char == "<":
            angle += 1
        elif char == ">" and angle:
            angle -= 1
        elif char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket:
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}" and brace:
            brace -= 1
        elif char == separator and not (angle or paren or bracket or brace):
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def _top_level_colon(text):
    angle = paren = bracket = brace = 0
    for index, char in enumerate(text):
        if char == "<":
            angle += 1
        elif char == ">" and angle:
            angle -= 1
        elif char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket:
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}" and brace:
            brace -= 1
        elif char == ":" and not (angle or paren or bracket or brace):
            before = text[index - 1] if index else ""
            after = text[index + 1] if index + 1 < len(text) else ""
            if before != ":" and after != ":":
                return index
    return -1


def _matching_paren(text, open_index):
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _normalize_rust_fragment(text):
    text = re.sub(r"\s+", " ", text.strip())
    text = re.sub(r"\s*::\s*", "::", text)
    text = re.sub(r"\*\s*(mut|const)\s+", r"*\1 ", text)
    text = re.sub(r"\s*&\s*", "&", text)
    text = re.sub(r"\s*<\s*", "<", text)
    text = re.sub(r"(?<!-)\s*>\s*", ">", text)
    text = re.sub(r"\s*->\s*", " -> ", text)
    return text


def canonical_function_signature(definition, source_text):
    """Signature with the row-owned symbol and parameter names removed."""
    signature = source_text[definition.definition_start : definition.signature_end]
    fn_match = re.search(
        r"\bfn\s+%s\b" % re.escape(definition.node.symbol), signature
    )
    if fn_match is None:
        raise AuditError("cannot parse signature for %s" % _display_node(definition.node))
    open_paren = signature.find("(", fn_match.end())
    close_paren = _matching_paren(signature, open_paren)
    if open_paren < 0 or close_paren < 0:
        raise AuditError("cannot delimit signature for %s" % _display_node(definition.node))
    prefix = signature[: fn_match.start()] + "fn"
    prefix = _normalize_rust_fragment(prefix)
    parameter_types = []
    for parameter in _split_top_level(signature[open_paren + 1 : close_paren]):
        parameter = parameter.strip()
        if not parameter:
            continue
        colon = _top_level_colon(parameter)
        if colon < 0:
            raise AuditError(
                "denied-ingress signature has an untyped receiver: %s"
                % _display_node(definition.node)
            )
        parameter_types.append(_normalize_rust_fragment(parameter[colon + 1 :]))
    suffix = _normalize_rust_fragment(signature[close_paren + 1 :])
    canonical = "%s(%s)" % (prefix, ", ".join(parameter_types))
    if suffix:
        canonical += " " + suffix
    return _normalize_rust_fragment(canonical)


TYPE_ALIAS = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?type\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);"
)


def _observed_type_aliases(texts):
    observed = {}
    for text in texts:
        stripped = blank_literals_and_comments(text)
        for match in TYPE_ALIAS.finditer(stripped):
            observed.setdefault(match.group(1), set()).add(
                _normalize_rust_fragment(match.group(2))
            )
    return observed


def _unique_type_aliases(observed):
    return {
        name: next(iter(values))
        for name, values in observed.items()
        if len(values) == 1
    }


def _type_alias_index(raw_sources):
    """One global/local alias census with exactly one scan per source."""
    global_observed = {}
    local_aliases = {}
    for source, text in raw_sources.items():
        observed = _observed_type_aliases((text,))
        local_aliases[source] = _unique_type_aliases(observed)
        for name, values in observed.items():
            global_observed.setdefault(name, set()).update(values)
    return _unique_type_aliases(global_observed), local_aliases, len(raw_sources)


def _type_aliases_for_source(global_aliases, local_aliases, source):
    aliases = dict(global_aliases)
    aliases.update(local_aliases.get(source, ()))
    return aliases


def _expand_type_aliases(type_text, aliases):
    def collapse_paths(value):
        return re.sub(
            r"\b(?:[A-Za-z_][A-Za-z0-9_]*::)+([A-Za-z_][A-Za-z0-9_]*)\b",
            r"\1",
            value,
        )

    expanded = collapse_paths(_normalize_rust_fragment(type_text))
    for _ in range(len(aliases) + 1):
        changed = False
        for name, replacement in aliases.items():
            updated = re.sub(r"\b%s\b" % re.escape(name), replacement, expanded)
            if updated != expanded:
                expanded = collapse_paths(_normalize_rust_fragment(updated))
                changed = True
        if not changed:
            break
    return expanded


def structural_abi_shape(signature, aliases):
    """ABI/parameter/return shape independent of visibility and `unsafe`."""
    match = re.search(r'\bextern\s+"([^"]+)"\s+fn\s*\(', signature)
    if match is None:
        return None
    open_paren = signature.find("(", match.start())
    close_paren = _matching_paren(signature, open_paren)
    if close_paren < 0:
        return None
    parameters = tuple(
        _expand_type_aliases(parameter, aliases)
        for parameter in _split_top_level(signature[open_paren + 1 : close_paren])
        if parameter.strip()
    )
    suffix = _normalize_rust_fragment(signature[close_paren + 1 :]).strip()
    if not suffix.startswith("-> "):
        return_type = "()"
    else:
        return_type = _expand_type_aliases(suffix[3:], aliases)
    return match.group(1), parameters, return_type


def _direct_reaches(adjacency, start, targets):
    pending = [start]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current in targets and current != start:
            return True
        pending.extend(adjacency.get(current, ()))
    return False


def evaluate_denied_ingresses(
    rows,
    roots,
    definitions,
    calls,
    indirect_references,
    stripped_sources,
    raw_sources,
):
    """Validate exact denied ABI stubs and reject renamed terminal ingresses."""
    if not isinstance(rows, list):
        raise AuditError("deniedIngresses is not a list")
    violations = []
    evidence = []
    declared = set()
    denied_shapes = set()
    global_aliases, local_aliases, alias_source_scans = _type_alias_index(raw_sources)
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {
            "source",
            "symbol",
            "attribute",
            "signature",
            "normalizedBody",
            "outgoingDirectCalls",
        }:
            raise AuditError(
                "deniedIngresses[%d] has fields other than the exact denied-ingress schema"
                % index
            )
        node_row = {"source": row["source"], "symbol": row["symbol"]}
        definition = _resolve_node_ref(node_row, "denied ingress", definitions)
        if definition.node.owner is not None:
            raise AuditError("denied ingress must be a free function")
        if not all(isinstance(row[key], str) for key in ("attribute", "signature", "normalizedBody")):
            raise AuditError("denied ingress string fields are not strings")
        outgoing_expected = row["outgoingDirectCalls"]
        if isinstance(outgoing_expected, bool) or not isinstance(outgoing_expected, int):
            raise AuditError("denied ingress outgoingDirectCalls is not an integer")
        stripped = stripped_sources[definition.node.source]
        raw = raw_sources[definition.node.source]
        prefix = stripped[: definition.definition_start].rstrip()
        attribute_ok = prefix.endswith(row["attribute"])
        signature = canonical_function_signature(definition, raw)
        body = "".join(definition.body.split())
        body_ok = body == "".join(row["normalizedBody"].split())
        outgoing = [call for call in calls if call.caller == definition.node]
        if not attribute_ok:
            violations.append(
                "denied ingress %s does not carry exact attribute %s"
                % (_display_node(definition.node), row["attribute"])
            )
        if signature != row["signature"]:
            violations.append(
                "denied ingress %s signature is %r, expected %r"
                % (_display_node(definition.node), signature, row["signature"])
            )
        if not body_ok:
            violations.append(
                "denied ingress %s body is not the exact refusal expression"
                % _display_node(definition.node)
            )
        if len(outgoing) != outgoing_expected:
            violations.append(
                "denied ingress %s expected %d outgoing direct calls, observed %d"
                % (_display_node(definition.node), outgoing_expected, len(outgoing))
            )
        if definition.node.symbol in roots:
            violations.append(
                "denied ingress %s is still an intended production root"
                % _display_node(definition.node)
            )
        declared.add(definition.node)
        denied_shape = structural_abi_shape(
            row["signature"],
            _type_aliases_for_source(
                global_aliases, local_aliases, definition.node.source
            ),
        )
        if denied_shape is None:
            raise AuditError("denied ingress signature is not an extern ABI function")
        denied_shapes.add(denied_shape)
        evidence.append(
            {
                "node": _display_node(definition.node),
                "attribute": row["attribute"],
                "signature": signature,
                "normalizedBody": body,
                "requiredDirectCalls": outgoing_expected,
                "observedDirectCalls": len(outgoing),
            }
        )

    adjacency = {}
    for call in calls:
        adjacency.setdefault(call.caller, set()).add(call.callee)
    # Renamed raw-pointer ingresses retain conservative function-item and
    # alias semantics. The exact call index stays expression-only; this second
    # edge class exists solely for closed-roster/denied-ingress refusal.
    for reference in indirect_references:
        if reference.target != reference.caller:
            adjacency.setdefault(reference.caller, set()).add(reference.target)
    terminal_symbols = {
        "run_terminal",
        "run_checkpoint_teardown",
        "finish_checkpoint_teardown",
        "release_strong_and_deposit",
        "prepare_final_delete",
        "execute_prepared_delete",
        "run_queued_finalizer",
        "queue_cell_finalizer",
        "free_session_shell_allocation",
    }
    terminal_targets = {
        definition.node
        for definition in definitions
        if definition.node.symbol in terminal_symbols
        or (
            definition.node.owner == "R3PreparedCheckpointFinish"
            and definition.node.symbol == "prepare"
        )
    }
    for definition in definitions:
        if definition.node in declared:
            continue
        raw_signature = raw_sources[definition.node.source][
            definition.definition_start : definition.signature_end
        ]
        if not re.search(r'\bextern\s+"system"', raw_signature):
            continue
        try:
            signature = canonical_function_signature(
                definition, raw_sources[definition.node.source]
            )
        except AuditError as error:
            violations.append(
                "cannot classify extern system ingress %s: %s"
                % (_display_node(definition.node), error)
            )
            continue
        candidate_aliases = _type_aliases_for_source(
            global_aliases, local_aliases, definition.node.source
        )
        if structural_abi_shape(signature, candidate_aliases) not in denied_shapes:
            continue
        if _direct_reaches(adjacency, definition.node, terminal_targets):
            violations.append(
                "raw-pointer ingress %s reaches a terminal boundary"
                % _display_node(definition.node)
            )
    return violations, evidence, alias_source_scans


def mentions_in(body):
    """Every identifier a body mentions.

    Not "every call": a driver installs its dispatch routines as *values*
    (`*slot = Some(dispatch_default)`), and an edge model that only sees
    `name(` is blind to precisely the edges that make a callback reachable.
    Filtering these down to known function names happens in `build_graph`.
    """
    return set(IDENTIFIER.findall(body))


def production_sources(root, source_roots, test_files):
    """`(rel, text)` for every non-test source file, comments and literals gone.

    Split out of `build_graph` because the graph is not the only question the
    manifest asks. A gate may also need to say that a *spelling* is absent —
    a struct, a field, a constant prefix — and none of those are function nodes,
    so the reachability walk cannot see them at all. Both callers share this one
    stripper so a text row and an edge row always agree on what "production"
    means: no `#[cfg(test)]`, no comment, no string literal.
    """
    for source_root in source_roots:
        base = os.path.join(root, source_root.replace("/", os.sep))
        if not os.path.isdir(base):
            raise AuditError("source root does not exist: %s" % source_root)
        for directory, subdirectories, files in os.walk(base):
            subdirectories.sort()
            for name in sorted(files):
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                if rel in test_files:
                    continue
                # Fail closed on a test module the manifest never declared.
                #
                # `#[cfg(test)]` on a `mod tests;` *declaration* lives in the
                # parent file, so the module's own file carries no attribute for
                # `strip_cfg_test` to find. An undeclared one is therefore read
                # as production in full: its functions become definitions (which
                # can make a real production name ambiguous, or a staged row
                # unstageable) and its bodies become edges out of any node whose
                # name they share (which can make a `requiredReachable` row pass
                # through a route the shipped image does not contain).
                #
                # `adapter/fence/tests.rs` sat in exactly that state: 53 names
                # only it defined, twelve inflated definition counts, six of
                # them turning unique names ambiguous, and one node reachable
                # from a production root through nothing but test bodies. No
                # verdict was wrong, but every verdict was computed from a graph
                # that contained code the driver does not ship.
                #
                # A comment would not have caught it. This does.
                #
                # A child of a test module lives under a `tests/` directory
                # (`adapter/lifecycle/tests/close_choreography.rs`, declared by
                # `mod close_choreography;` inside `tests.rs`) and carries no
                # attribute either. Keyed on the file NAME alone, this guard read
                # such a file as production without a word -- the same hole one
                # directory down.
                if name == "tests.rs" or "tests" in rel.split("/")[:-1]:
                    raise AuditError(
                        "undeclared test module: %s -- add it to the manifest's "
                        "testFiles, or the graph counts its bodies as production"
                        % rel
                    )
                with io.open(path, encoding="utf-8") as handle:
                    text = handle.read()
                try:
                    text = strip_cfg_test(blank_literals_and_comments(text))
                except AuditError as error:
                    raise AuditError("%s: %s" % (rel, error)) from error
                yield rel, text


def build_graph(root, source_roots, test_files):
    """`(edges, definitions)` over every non-test function in the source roots.

    `definitions` maps a function name to the list of files defining it, so an
    ambiguous root or staged target is a refusal rather than a coin flip.
    """
    bodies = []
    definitions = {}
    for rel, text in production_sources(root, source_roots, test_files):
        for function, body in function_bodies(text):
            definitions.setdefault(function, []).append(rel)
            bodies.append((function, body))

    known = set(definitions)
    edges = {}
    for function, body in bodies:
        edges.setdefault(function, set()).update(
            name for name in mentions_in(body) if name in known and name != function
        )
    return edges, definitions


def reachable_from(edges, roots):
    """Every function name reachable from `roots`, plus walked edges."""
    seen = set()
    pending = list(roots)
    walked_edges = []
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for callee in sorted(edges.get(current, ())):
            walked_edges.append("%s -> %s" % (current, callee))
            if callee not in seen:
                pending.append(callee)
    return seen, len(walked_edges), walked_edges


def shortest_path(edges, roots, target):
    """One concrete root→target path, so a failure names the route it found."""
    queue = [(root, [root]) for root in roots]
    seen = set(roots)
    while queue:
        current, path = queue.pop(0)
        if current == target:
            return path
        for callee in sorted(edges.get(current, ())):
            if callee in seen:
                continue
            seen.add(callee)
            queue.append((callee, path + [callee]))
    return []


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def _reject_nonliteral_roster(gate_name, field, values):
    if not isinstance(values, list):
        return
    seen = []
    for value in values:
        if not isinstance(value, str):
            continue
        if value in seen:
            raise AuditError("gate %s %s has a duplicate: %s" % (gate_name, field, value))
        seen.append(value)
        if "*" in value or "?" in value or value.startswith("^") or value.endswith("$"):
            raise AuditError(
                "gate %s %s has a wildcard/pattern: %s" % (gate_name, field, value)
            )


def validate_gate_schema(gate_name, gate):
    if not isinstance(gate, dict):
        raise AuditError("gate %s is not an object" % gate_name)
    unknown = set(gate) - GATE_KEYS
    if unknown:
        raise AuditError(
            "gate %s has unknown keys: %s"
            % (gate_name, ", ".join(sorted(unknown)))
        )
    _reject_nonliteral_roster(gate_name, "stagedTargets", gate.get("stagedTargets", []))
    _reject_nonliteral_roster(
        gate_name, "requiredReachable", gate.get("requiredReachable", [])
    )
    _reject_nonliteral_roster(
        gate_name, "forbiddenSymbols", gate.get("forbiddenSymbols", [])
    )
    _reject_nonliteral_roster(gate_name, "zeroRoster", gate.get("zeroRoster", []))
    if gate_name != TASK12_GATE:
        return
    missing = TASK12_GATE_KEYS - set(gate)
    if missing:
        raise AuditError(
            "gate %s is missing required keys: %s"
            % (gate_name, ", ".join(sorted(missing)))
        )
    extra = set(gate) - TASK12_GATE_KEYS
    if extra:
        raise AuditError(
            "gate %s has unknown keys: %s"
            % (gate_name, ", ".join(sorted(extra)))
        )
    for key in TASK12_ORACLE_KEYS:
        if not isinstance(gate[key], list) or not gate[key]:
            raise AuditError("gate %s %s must be a nonempty list" % (gate_name, key))


def load_manifest(path):
    with io.open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("schema") != SCHEMA:
        raise AuditError("manifest schema is not %s" % SCHEMA)
    for key in ("gates", "productionRoots", "testFiles"):
        if key not in manifest:
            raise AuditError("manifest is missing the %s key" % key)
    if not isinstance(manifest["gates"], dict):
        raise AuditError("manifest gates is not an object")
    if TASK12_GATE not in manifest["gates"]:
        raise AuditError("manifest is missing the %s gate" % TASK12_GATE)
    for gate_name, gate in manifest["gates"].items():
        validate_gate_schema(gate_name, gate)
    return manifest


def evaluate_gate(root, manifest, gate_name, source_roots):
    """The whole decision, with no identity in it.

    Split out so `--self-test` can drive *this* over fixture trees. The
    predecessor's self-test exercised `build_graph` and `reachable_from`
    directly and never reached the gate, so every refusal below — and the
    reachability check itself — could be deleted with the self-test still
    reporting PASS.

    Returns `(violations, stats)`.
    """
    gates = manifest["gates"]
    if gate_name not in gates:
        raise AuditError("manifest declares no gate named %s" % gate_name)
    gate = gates[gate_name]
    validate_gate_schema(gate_name, gate)

    roots = list(gate.get("roots", ()))
    if not roots:
        raise AuditError("gate %s declares no production roots" % gate_name)

    # The manifest's own roster is load-bearing: a gate that walks fewer roots
    # than the manifest advertises would report unreachability the manifest
    # does not claim.
    advertised = set(manifest["productionRoots"])
    missing_from_gate = advertised - set(roots)
    if missing_from_gate:
        raise AuditError(
            "gate %s omits declared production roots: %s"
            % (gate_name, ", ".join(sorted(missing_from_gate)))
        )
    undeclared = set(roots) - advertised
    if undeclared:
        raise AuditError(
            "gate %s walks roots the manifest does not declare: %s"
            % (gate_name, ", ".join(sorted(undeclared)))
        )

    test_files = set(manifest["testFiles"])
    edges, definitions = build_graph(root, source_roots, test_files)
    direct_rows = gate.get("requiredDirectEdges", [])
    sensitive_rows = gate.get("soleDirectCallers", [])
    denied_rows = gate.get("deniedIngresses", [])
    if direct_rows or sensitive_rows or denied_rows:
        direct_definitions, direct_calls, indirect_references = build_direct_call_index(
            root, source_roots, test_files
        )
    else:
        direct_definitions, direct_calls, indirect_references = [], [], []

    missing = [name for name in roots if name not in definitions]
    if missing:
        raise AuditError("declared production roots are absent: %s" % ", ".join(sorted(missing)))
    ambiguous = [name for name in roots if len(definitions[name]) != 1]
    if ambiguous:
        raise AuditError(
            "declared production roots are ambiguous: %s"
            % ", ".join("%s in %s" % (name, definitions[name]) for name in sorted(ambiguous))
        )

    staged = list(gate.get("stagedTargets", ()))
    staged_missing = [name for name in staged if name not in definitions]
    if staged_missing:
        # A staged target that no longer exists makes the gate vacuous for that
        # row: it would report "unreachable" about nothing.
        raise AuditError(
            "declared staged targets are absent: %s" % ", ".join(sorted(staged_missing))
        )

    # A staged row on an ambiguous name is worse than no row. The edge model is
    # bare identifiers, so two definitions of one name are ONE node: the row
    # then reports routes into a body nobody staged, or -- if the other
    # definition is production-reachable -- fails for a reason that has nothing
    # to do with the staged surface. Production roots and requiredReachable
    # already refuse ambiguity; staged targets are the criterion by which a
    # symbol gets a row at all, so they must refuse it too.
    staged_ambiguous = [name for name in staged if len(definitions[name]) != 1]
    if staged_ambiguous:
        raise AuditError(
            "declared staged targets are ambiguous: %s"
            % ", ".join(
                "%s in %s" % (name, definitions[name]) for name in sorted(staged_ambiguous)
            )
        )

    # The recorded excuses have to stay true. A name listed as ambiguous that
    # has become unique is a row somebody now owes; a name listed with the
    # wrong count is a transcription rather than a reading.
    unstaged = gate.get("ambiguousUnstaged", {})
    if not isinstance(unstaged, dict):
        raise AuditError("ambiguousUnstaged must be an object")
    stale = []
    for name, declared in sorted(unstaged.items()):
        if name == "note":
            continue
        actual = len(definitions.get(name, ()))
        if actual != declared:
            stale.append("%s declared %r, tree has %d" % (name, declared, actual))
        elif actual == 1:
            stale.append("%s is no longer ambiguous and owes a staged row" % name)
    if stale:
        raise AuditError("ambiguousUnstaged is stale: %s" % "; ".join(stale))

    # The second exclusion reason: the symbol's own name is unique, but its only
    # caller's name is not, so a row on it would report a route through the
    # merged caller node into a body nobody staged. Both halves are checked, so
    # an excuse cannot outlive its reason: the symbol must still be unique, and
    # the caller must still be ambiguous.
    via_caller = gate.get("unstageableViaAmbiguousCaller", {})
    if not isinstance(via_caller, dict):
        raise AuditError("unstageableViaAmbiguousCaller must be an object")
    caller_stale = []
    for name, caller in sorted(via_caller.items()):
        if name == "note":
            continue
        if not isinstance(caller, str):
            raise AuditError(
                "unstageableViaAmbiguousCaller[%s] must name its caller" % name
            )
        defined = len(definitions.get(name, ()))
        if defined == 0:
            caller_stale.append("%s no longer exists" % name)
            continue
        if defined != 1:
            caller_stale.append(
                "%s has %d definitions and belongs in ambiguousUnstaged" % (name, defined)
            )
        if len(definitions.get(caller, ())) < 2:
            caller_stale.append(
                "%s is excused by %s, which is no longer ambiguous" % (name, caller)
            )
    if caller_stale:
        raise AuditError(
            "unstageableViaAmbiguousCaller is stale: %s" % "; ".join(caller_stale)
        )

    reached, walked, walked_edges = reachable_from(edges, roots)
    violations = []
    direct_evidence = []
    if direct_rows:
        direct_violations, direct_evidence = evaluate_required_direct_edges(
            direct_rows, direct_definitions, direct_calls
        )
        violations.extend(direct_violations)
    sensitive_evidence = []
    if sensitive_rows:
        sensitive_violations, sensitive_evidence = evaluate_sole_direct_callers(
            sensitive_rows, direct_definitions, direct_calls, indirect_references
        )
        violations.extend(sensitive_violations)
    denied_evidence = []
    denied_alias_source_scans = 0
    if denied_rows:
        stripped_sources = dict(production_sources(root, source_roots, test_files))
        raw_sources = {}
        for rel in stripped_sources:
            with io.open(
                os.path.join(root, rel.replace("/", os.sep)), encoding="utf-8"
            ) as handle:
                raw_sources[rel] = handle.read()
        (
            denied_violations,
            denied_evidence,
            denied_alias_source_scans,
        ) = evaluate_denied_ingresses(
            denied_rows,
            roots,
            direct_definitions,
            direct_calls,
            indirect_references,
            stripped_sources,
            raw_sources,
        )
        violations.extend(denied_violations)
    for name in staged:
        if name in reached:
            path = shortest_path(edges, roots, name)
            violations.append("%s is reachable: %s" % (name, " -> ".join(path)))

    # The mirror image of a staged target. A cutover gate has to say what the
    # cutover *made* reachable, not only what is still unreachable: a gate that
    # checked absence alone would pass a tree in which the new path exists and
    # nothing calls it, which is exactly the pre-cutover tree.
    for name in gate.get("requiredReachable", ()):
        if name not in definitions:
            raise AuditError("required-reachable symbol is absent: %s" % name)
        if len(definitions[name]) != 1:
            raise AuditError(
                "required-reachable symbol is ambiguous: %s in %s" % (name, definitions[name])
            )
        if name not in reached:
            violations.append("required symbol is unreachable: %s" % name)

    for token in gate.get("forbiddenSymbols", ()):
        if token in definitions:
            violations.append("forbidden symbol is still defined: %s" % token)
        if token in reached:
            violations.append("forbidden symbol is reachable: %s" % token)

    # `forbiddenSymbols` can only ever see a *function* that is defined or
    # walked. Task 12's cutover also has to delete a struct, a `DriverState`
    # field, and a constant prefix, and planting each of those in a reachable
    # body left the gate green — a row that reads as coverage and measures
    # nothing. Text rows are the mechanism that can see them.
    forbidden_text = list(gate.get("forbiddenText", ()))
    if forbidden_text:
        for rel, text in production_sources(root, source_roots, test_files):
            for needle in forbidden_text:
                if needle in text:
                    violations.append("forbidden text is present: %s in %s" % (needle, rel))

    for pair in gate.get("forbiddenEdges", ()):
        caller, callee = pair["caller"], pair["callee"]
        if callee in edges.get(caller, ()):
            violations.append("forbidden edge is present: %s -> %s" % (caller, callee))

    zero_roster = list(gate.get("zeroRoster", ()))
    forbidden_results = []
    if zero_roster:
        zero_files = list(gate.get("zeroRosterFiles", ()))
        zero_violations, forbidden_results = evaluate_zero_roster(
            root,
            source_roots,
            test_files,
            zero_roster,
            zero_files,
            gate_name=gate_name,
        )
        violations.extend(zero_violations)

    stats = {
        "profile": gate.get("profile", ""),
        "productionRoots": list(roots),
        "productionRootCount": len(roots),
        "reachableEdges": walked_edges,
        "reachableEdgeCount": walked,
        "forbiddenResults": forbidden_results,
        "requiredDirectEdges": direct_evidence,
        "soleDirectCallers": sensitive_evidence,
        "deniedIngresses": denied_evidence,
        "deniedIngressAliasSourceScans": denied_alias_source_scans,
    }
    return violations, stats


def evaluate_zero_roster(
    root, source_roots, test_files, roster, extra_files, gate_name=""
):
    """Count each literal roster entry in production source and named manifests.

    Substring search on stripped production text, plus the extra files as raw
    bytes decoded as UTF-8. Comments and string literals in Rust are already
    blanked by `production_sources`, so a comment that names a retired type is
    not a result. Manifests have no such stripper: they are the compatibility
    surfaces the plan names, and a leftover token there is a leftover consumer.
    """
    if gate_name == TASK25_GATE:
        if tuple(roster) != TASK25_ZERO_ROSTER:
            raise AuditError(
                "zeroRoster is not the immutable 53-entry Task 25 table"
            )
        if tuple(extra_files) != TASK25_ZERO_ROSTER_FILES:
            raise AuditError(
                "zeroRosterFiles is not the closed Task 25 compatibility-manifest set"
            )

    corpus = []
    for rel, text in production_sources(root, source_roots, test_files):
        corpus.append((rel, text))
    for rel in extra_files:
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            raise AuditError("zero-roster file is absent: %s" % rel)
        with io.open(path, encoding="utf-8") as handle:
            corpus.append((rel, handle.read()))

    violations = []
    results = []
    for entry in roster:
        hits = [rel for rel, text in corpus if entry in text]
        results.append({"entry": entry, "count": len(hits), "files": hits})
        if hits:
            violations.append(
                "zero-roster entry has %d results: %s in %s"
                % (len(hits), entry, ", ".join(hits))
            )
    return violations, results


def run_gate(root, manifest_path, gate_name, source_roots, auditor_path, injected=None):
    manifest = load_manifest(manifest_path)
    violations, stats = evaluate_gate(root, manifest, gate_name, source_roots)
    domain = identity_domain(root, auditor_path, manifest_path)
    status = "PASS" if not violations else "FAIL"
    report = {
        "gate": gate_name,
        "status": status,
        "result": status,
        "sourceIdentity": source_identity(root, domain, source_roots),
        "sourceRoots": sorted(entry.replace(os.sep, "/") for entry in source_roots),
        "manifestSha256": file_sha256(manifest_path),
        "auditorSha256": file_sha256(auditor_path),
        "profile": stats["profile"],
        "productionRoots": list(stats.get("productionRoots", ())),
        "productionRootCount": stats["productionRootCount"],
        "reachableEdges": list(stats.get("reachableEdges", ())),
        "reachableEdgeCount": stats["reachableEdgeCount"],
        "forbiddenResults": list(stats.get("forbiddenResults", ())),
        "requiredDirectEdges": stats["requiredDirectEdges"],
        "soleDirectCallers": stats["soleDirectCallers"],
        "deniedIngresses": stats["deniedIngresses"],
        "injectedMutation": injected or "",
    }
    return report, violations


def canonical_gate_stdout(report):
    return json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"


def emit(report):
    sys.stdout.write(canonical_gate_stdout(report))


# ---------------------------------------------------------------------------
# The same-artifact attestation
# ---------------------------------------------------------------------------
#
# A PASS printed by this file is a claim about one source tree. Nothing stops
# somebody quoting yesterday's PASS for today's sources -- unless the PASS is a
# *build input* whose identity the compiler re-checks. That is what the
# attestation is: a canonical document binding a profile's gate and property
# rows to the exact source identity they were computed over, verified by
# `fsring-core`'s build script before a production image may embed a witness.
#
# Two things it is deliberately not. It is not a hash the caller supplies: the
# only writer is `--refresh-attestation`, which reruns every row first. And it
# is not self-referential: the attestation file is outside the identity domain
# it stamps, so refreshing it cannot change the identity it records.

ATTESTATION_SCHEMA = "fsring-c4-production-attestation/v1"
ATTESTATION_VERSION = 1
ATTESTATION_RELATIVE_PATH = "driver/audit/c4-production-attestation.json"

# The exact root keys, in this order. A document with extra, missing, or
# reordered keys is refused rather than normalized.
ATTESTATION_KEYS = (
    "schema",
    "version",
    "profile",
    "sourceIdentity",
    "manifestSha256",
    "auditorSha256",
    "requiredGates",
    "requiredProperties",
    "rows",
)

ROW_IDENTITY_KEYS = ("sourceIdentity", "manifestSha256", "auditorSha256")


def validate_attestation_row_identity(row, enclosing):
    """Deferred Step 4 primitive; not called by the cheap verifier yet.

    Step 1 provides the mutation-tested primitive. The late Step 4 schema bump
    attaches these fields to every persisted gate/property row; keeping that
    publication change out of Step 1 avoids rewriting the tracked attestation
    before the source and mutation freeze.
    """
    for key in ROW_IDENTITY_KEYS:
        if key not in row:
            raise AuditError("attestation row is missing %s" % key)
        if row[key] != enclosing.get(key):
            raise AuditError("attestation row %s differs from the enclosing artifact" % key)


def load_profiles(manifest):
    profiles = manifest.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise AuditError("manifest declares no attestation profiles")
    return profiles


def profile_rows(manifest, profile):
    profiles = load_profiles(manifest)
    if profile not in profiles:
        raise AuditError(
            "profile %s is not one of the closed set %s"
            % (profile, ", ".join(sorted(profiles)))
        )
    entry = profiles[profile]
    gates = list(entry.get("gates", ()))
    properties = list(entry.get("properties", ()))
    if not gates:
        raise AuditError("profile %s declares no gate rows" % profile)
    if not properties:
        raise AuditError("profile %s declares no property rows" % profile)
    return gates, properties


# ---------------------------------------------------------------------------
# Canonical test stdout
# ---------------------------------------------------------------------------
#
# Raw harness stdout is evidence, not an identity: it carries elapsed times and
# a per-run thread order. Hashing it would make every refresh differ from every
# other. Hashing a *summary* would be worse -- a run with different tests could
# collide. So the whole output is parsed against a closed grammar, and anything
# unrecognized is a refusal rather than a silently dropped line.

_RUNNING_RE = re.compile(r"^running (\d+) tests?$")
# `#[should_panic]` rows print `test NAME - should panic ... ok`. The
# annotation sits between the name and the verdict, so a parser anchored
# straight from name to `...` rejects the line and the whole refresh fails
# with "unparsed record in test stdout" -- a legitimate test form that this
# gate simply could not read.
_TEST_RE = re.compile(r"^test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)$")
_RESULT_RE = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in [0-9.]+m?s$"
)


def canonical_test_records(text):
    """Parse a whole `cargo test` stdout into ordered `{name,status,count}`.

    Cargo's progress lines go to stderr, so stdout is only harness output. Each
    binary contributes its sorted test lines -- sorting is what removes the
    thread-order noise -- followed by its result record, whose count is the
    passed total. Elapsed time never enters the sequence.
    """
    records = []
    pending = []
    passed_total = 0
    open_section = False
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if not line:
            continue
        running = _RUNNING_RE.match(line)
        if running:
            if open_section:
                raise AuditError("test stdout starts a section before closing one")
            open_section = True
            pending = []
            continue
        test = _TEST_RE.match(line)
        if test:
            if not open_section:
                raise AuditError("test stdout reports a test outside any section")
            pending.append({"name": test.group(1), "status": test.group(2), "count": 1})
            continue
        result = _RESULT_RE.match(line)
        if result:
            if not open_section:
                raise AuditError("test stdout reports a result outside any section")
            passed = int(result.group(2))
            pending.sort(key=lambda record: record["name"])
            records.extend(pending)
            records.append(
                {"name": "<result>", "status": result.group(1), "count": passed}
            )
            passed_total += passed
            open_section = False
            pending = []
            continue
        raise AuditError("unparsed record in test stdout: %r" % line)
    if open_section:
        raise AuditError("test stdout ends inside an unterminated section")
    return records, passed_total


def canonical_records_sha256(records):
    payload = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().upper()


def property_argv(prop):
    """The exact command one property row runs.

    It is derived from the manifest rather than written into the attestation by
    hand, so a row cannot claim one filter and have run another.
    """
    for key in ("name", "package", "filter"):
        if key not in prop:
            raise AuditError("property row is missing the %s key" % key)
    return [
        "cargo",
        "+1.85.0",
        "test",
        "--manifest-path",
        "driver/Cargo.toml",
        "-p",
        str(prop["package"]),
        str(prop["filter"]),
        "--locked",
        "--offline",
    ]


def c4_frozen_launch(argv):
    """Rewrite one child argv to launch a frozen payload, if the gate supplied one.

    A property row is written the way a person types it -- `cargo +1.85.0 test`
    -- and that `+1.85.0` is a RUSTUP SELECTOR. The C4 source gate deliberately
    removes the rustup proxy from the child PATH, so under the gate the bare
    `cargo` resolves to a toolchain payload, which cannot accept a selector at
    all: the row exited 101 and every fsd mutant that depends on this baseline
    became unjudgeable.

    Only the LAUNCH is rewritten. The recorded `argv` stays the manifest
    literal, so an attestation computed inside the gate and one computed
    outside it are the same document -- which is the whole point of attesting.
    """
    launch = list(argv)
    env = dict(os.environ)
    if len(launch) > 1 and launch[0] == "cargo" and launch[1].startswith("+"):
        version = launch[1][1:]
        suffix = version.replace(".", "_")
        payload = os.environ.get("FSRING_C4_TOOL_CARGO_" + suffix)
        if payload:
            # The selector element is dropped, not kept: a payload cargo given
            # `+1.85.0` tries to re-dispatch through the rustup proxy that is
            # not there.
            del launch[1]
            launch[0] = payload
            # Counted HERE rather than at the call sites: this is the only
            # place a frozen payload reaches an argv, so a new caller cannot
            # launch one without being counted.
            c4_note_launch("cargo-" + version)
            for name, role in (("CARGO", "CARGO"), ("RUSTC", "RUSTC"), ("RUSTDOC", "RUSTDOC")):
                member = os.environ.get("FSRING_C4_TOOL_%s_%s" % (role, suffix))
                if member:
                    env[name] = member
                    if role != "CARGO":
                        c4_note_launch(role.lower() + "-" + version, 0)
    return launch, env


def run_property_row(root, prop):
    argv = property_argv(prop)
    launch, env = c4_frozen_launch(argv)
    completed = subprocess.run(launch, cwd=root, capture_output=True, env=env)
    stdout = completed.stdout.decode("utf-8", "replace")
    if completed.returncode != 0:
        raise AuditError(
            "property %s exited %d; refresh never attests a failing row"
            % (prop["name"], completed.returncode)
        )
    records, passed = canonical_test_records(stdout)
    if passed == 0:
        # A filter that matches nothing would otherwise attest an empty PASS.
        raise AuditError("property %s ran zero tests" % prop["name"])
    return {
        "kind": "property",
        "name": str(prop["name"]),
        "argv": argv,
        "exit": 0,
        "testCount": passed,
        "stdoutSha256": canonical_records_sha256(records),
    }


def gate_argv(manifest_path, gate_name, source_roots, root):
    return [
        "python",
        "driver/scripts/audit_c4_production_graph.py",
        "--manifest",
        os.path.relpath(manifest_path, root).replace(os.sep, "/"),
        "--gate",
        gate_name,
    ] + [
        item
        for entry in sorted(source_roots)
        for item in ("--source-root", entry.replace(os.sep, "/"))
    ]


def run_gate_row(root, manifest_path, auditor_path, gate_name, source_roots):
    report, violations = run_gate(root, manifest_path, gate_name, source_roots, auditor_path)
    if violations:
        raise AuditError(
            "gate %s did not pass; refresh never attests a failing row: %s"
            % (gate_name, "; ".join(violations))
        )
    stdout = canonical_gate_stdout(report)
    return {
        "kind": "gate",
        "name": gate_name,
        "argv": gate_argv(manifest_path, gate_name, source_roots, root),
        "exit": 0,
        "testCount": 0,
        "stdoutSha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest().upper(),
    }


def compute_attestation(root, manifest_path, auditor_path, profile, source_roots):
    manifest = load_manifest(manifest_path)
    gates, properties = profile_rows(manifest, profile)
    domain = identity_domain(root, auditor_path, manifest_path)
    rows = []
    for gate_name in gates:
        rows.append(run_gate_row(root, manifest_path, auditor_path, gate_name, source_roots))
    for prop in properties:
        rows.append(run_property_row(root, prop))
    document = {
        "schema": ATTESTATION_SCHEMA,
        "version": ATTESTATION_VERSION,
        "profile": profile,
        "sourceIdentity": source_identity(root, domain, source_roots),
        "manifestSha256": file_sha256(manifest_path),
        "auditorSha256": file_sha256(auditor_path),
        "requiredGates": list(gates),
        "requiredProperties": [str(prop["name"]) for prop in properties],
        "rows": rows,
    }
    return document


def canonical_attestation_bytes(document):
    if list(document.keys()) != list(ATTESTATION_KEYS):
        raise AuditError("attestation root keys are not the exact ordered set")
    return (json.dumps(document, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def write_attestation(path, document):
    """Write the document to a temporary file, fsync it, then rename it.

    A half-written attestation is worse than a missing one: it fails the build
    with an identity error instead of the honest 'not attested'. The rename is
    the only publication step.
    """
    payload = canonical_attestation_bytes(document)
    directory = os.path.dirname(path)
    handle_fd, temporary = tempfile.mkstemp(prefix=".c4-attestation-", dir=directory)
    try:
        with os.fdopen(handle_fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise


def load_attestation(path):
    if not os.path.exists(path):
        raise AuditError("no attestation at %s; run --refresh-attestation" % path)
    with io.open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise AuditError("attestation is not a JSON object")
    if list(document.keys()) != list(ATTESTATION_KEYS):
        raise AuditError(
            "attestation root keys are %s, not the exact ordered set %s"
            % (", ".join(document.keys()), ", ".join(ATTESTATION_KEYS))
        )
    if document["schema"] != ATTESTATION_SCHEMA:
        raise AuditError("attestation schema is not %s" % ATTESTATION_SCHEMA)
    if document["version"] != ATTESTATION_VERSION:
        raise AuditError("attestation version is not %d" % ATTESTATION_VERSION)
    return document


def verify_attestation_identity(root, manifest_path, auditor_path, path, source_roots):
    """The cheap check a production build runs. It never invokes cargo.

    Rerunning the rows here would recurse: the property rows build the very
    crate whose build script is asking. So this recomputes the *identity* --
    which is only file hashing -- and checks the stored rows structurally
    against the manifest profile.
    """
    document = load_attestation(path)
    manifest = load_manifest(manifest_path)
    profile = document["profile"]
    gates, properties = profile_rows(manifest, profile)

    domain = identity_domain(root, auditor_path, manifest_path)
    current_identity = source_identity(root, domain, source_roots)
    if document["sourceIdentity"] != current_identity:
        raise AuditError(
            "attested source identity %s is stale; current is %s"
            % (document["sourceIdentity"], current_identity)
        )
    if document["manifestSha256"] != file_sha256(manifest_path):
        raise AuditError("attested manifest hash is stale")
    if document["auditorSha256"] != file_sha256(auditor_path):
        raise AuditError("attested auditor hash is stale")

    expected_names = list(gates) + [str(prop["name"]) for prop in properties]
    if document["requiredGates"] != list(gates):
        raise AuditError("attested required gates differ from the manifest profile")
    if document["requiredProperties"] != [str(prop["name"]) for prop in properties]:
        raise AuditError("attested required properties differ from the manifest profile")
    rows = document["rows"]
    if not isinstance(rows, list):
        raise AuditError("attested rows are not a list")
    observed_names = [row.get("name") for row in rows]
    if observed_names != expected_names:
        raise AuditError(
            "attested rows are %s, not the exact ordered %s"
            % (", ".join(str(name) for name in observed_names), ", ".join(expected_names))
        )
    property_count = 0
    for row in rows:
        if row.get("exit") != 0:
            raise AuditError("attested row %s did not pass" % row.get("name"))
        if row.get("kind") == "property":
            property_count += 1
            if not isinstance(row.get("testCount"), int) or row["testCount"] <= 0:
                raise AuditError("attested property %s has no tests" % row.get("name"))
    if property_count != len(properties):
        raise AuditError("attested property count does not match the manifest profile")
    return document


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

SELF_TESTS = (
    "production_graph_auditor_rejects_duplicate_and_bypass_edges",
    "production_graph_auditor_rejects_primary_staged_route_edges",
    "production_direct_graph_contract_rejects_every_caller_bypass",
    # Added with the attestation protocol. The plan names the graph rows above as
    # the ones this file owns; the protocol it grew afterwards has to be
    # self-tested by something, and folding its checks into a row named for
    # staged-route edges would make that row's name a lie.
    "production_attestation_refresh_is_deterministic_and_fails_closed",
    # Task 12's cutover row. It lives here rather than in a Rust test because
    # what it asserts is the absence of a spelling from production source, and
    # the auditor is the thing that already knows which text is production.
    "no_legacy_mount_registry_consumer_survives_cutover",
    "production_sensitive_destinations_have_closed_direct_caller_rosters",
    "denied_raw_pointer_ingress_is_an_exact_zero_edge_stub",
    "task8_step1_distinguishes_expected_source_gate_red",
    # Added after `adapter/fence/tests.rs` was found undeclared. The graph is
    # only as honest as its idea of which files the driver ships.
    "every_test_module_is_declared_or_the_graph_refuses",
    "task25_zero_roster_reinsertion_and_cutover_mutants_fail_the_gate",
)

# Independently reported Task 27 cases. Existing SELF_TESTS indices stay
# stable; these names must each appear as a `check(name, ...)` subject.
REQUIRED_INDEPENDENT_CASES = (
    "task09_11_r3_staging_is_production_unreachable",
    "task13_18_r4_staging_is_production_unreachable",
    "task20_24_r5_staging_is_production_unreachable",
    "task12_r3_cutover_has_exactly_one_terminal_delete_path",
    "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path",
    "task25_r5_cutover_has_exactly_one_all16_terminal_delete_path",
    "production_graph_auditor_rejects_duplicate_and_bypass_edges",
    "production_graph_auditor_rejects_primary_staged_route_edges",
    "r3_authority_absence_revalidation_rejects_r4_production_edge",
    "r4_authority_absence_revalidation_rejects_r5_production_edge",
)

CANONICAL_GATE_OUTPUT_KEYS = (
    "gate",
    "status",
    "sourceIdentity",
    "manifestSha256",
    "productionRoots",
    "reachableEdges",
    "forbiddenResults",
    "injectedMutation",
)

EXPECTED_STEP1_SOURCE_RED = (
    "direct callee definition is absent or has the wrong owner: "
    "driver/fsring-fsd/src/fence.rs#R3PreparedCheckpointFinish::prepare"
)


def is_expected_step1_source_red(detail):
    return detail == EXPECTED_STEP1_SOURCE_RED


def _fixture_gate(tree, gate, source_root="src", gate_name="fixture", test_files=()):
    """Run the real `evaluate_gate` over a temporary source tree.

    Returns `(violations, stats)` or raises `AuditError`, exactly as the
    production path does — this is the same function `run_gate` calls.
    """
    with tempfile.TemporaryDirectory(prefix="c4-graph-selftest-") as work:
        src = os.path.join(work, source_root)
        os.makedirs(src)
        for name, text in tree.items():
            path = os.path.join(src, name.replace("/", os.sep))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with io.open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
        manifest = {
            "schema": SCHEMA,
            "testFiles": list(test_files),
            "productionRoots": list(gate.get("roots", ())),
            "gates": {gate_name: gate},
        }
        return evaluate_gate(work, manifest, gate_name, [source_root])


def construct_authority_absence(kind, cutover_report, later_reports, injected_edge=""):
    """Same-artifact R3/R4 absence constructor.

    Accepts only the matching source/manifest identity from the cutover
    property plus every required later pre-cutover revalidation. A mutated
    identity or a later production edge is a refusal, never a stale PASS.
    """
    identity = cutover_report.get("sourceIdentity")
    manifest = cutover_report.get("manifestSha256")
    if not identity or not manifest:
        raise AuditError("%s absence is missing identity" % kind)
    if cutover_report.get("status") != "PASS":
        raise AuditError("%s cutover did not pass" % kind)
    for report in later_reports:
        if report.get("sourceIdentity") != identity or report.get("manifestSha256") != manifest:
            raise AuditError("%s later revalidation is not same-artifact" % kind)
        if report.get("status") != "PASS":
            raise AuditError("%s later revalidation failed" % kind)
    if injected_edge:
        raise AuditError("%s refuses production edge %s" % (kind, injected_edge))
    return {
        "kind": kind,
        "status": "PASS",
        "sourceIdentity": identity,
        "manifestSha256": manifest,
        "injectedMutation": "",
    }


def compare_gate_oracle(manifest, gate_name):
    """Python literal table versus JSON manifest, independently maintained."""
    if gate_name not in GATE_ORACLE_STAGED:
        return ["unknown gate %s" % gate_name]
    gate = manifest["gates"].get(gate_name)
    if not isinstance(gate, dict):
        return ["manifest is missing %s" % gate_name]
    errors = []
    if tuple(manifest.get("productionRoots", ())) != GATE_ORACLE_ROOTS:
        errors.append("productionRoots drift")
    if tuple(gate.get("roots", ())) != GATE_ORACLE_ROOTS:
        errors.append("gate roots drift")
    if tuple(gate.get("stagedTargets", ())) != GATE_ORACLE_STAGED[gate_name]:
        errors.append("stagedTargets drift")
    if tuple(gate.get("requiredReachable", ())) != GATE_ORACLE_REQUIRED[gate_name]:
        errors.append("requiredReachable drift")
    if tuple(gate.get("forbiddenSymbols", ())) != GATE_ORACLE_FORBIDDEN_SYMBOLS[gate_name]:
        errors.append("forbiddenSymbols drift")
    if gate.get("profile") != GATE_ORACLE_PROFILES[gate_name]:
        errors.append("profile drift")
    if gate_name == TASK25_GATE:
        if tuple(gate.get("zeroRoster", ())) != TASK25_ZERO_ROSTER:
            errors.append("zeroRoster drift")
        if len(KERNEL_FENCE_NATIVE_FORWARDS) != 16:
            errors.append("native forwards are not the closed 16-effect set")
    return errors


def _canonical_report_from_stats(gate_name, stats, violations, injected=""):
    status = "PASS" if not violations else "FAIL"
    return {
        "gate": gate_name,
        "status": status,
        "sourceIdentity": "FIXTURE",
        "manifestSha256": "FIXTURE",
        "productionRoots": list(stats.get("productionRoots", ())),
        "reachableEdges": list(stats.get("reachableEdges", ())),
        "forbiddenResults": list(stats.get("forbiddenResults", ())),
        "injectedMutation": injected,
    }


def self_test(manifest_path, auditor_path):
    """Prove the gate fails on the routes it exists to reject.

    Every check below drives `evaluate_gate` — the same function the real gate
    calls — so a deleted refusal or a weakened reachability walk fails here.
    """
    checks = 0
    failures = []
    reported_names = set()

    def check(name, condition, detail):
        nonlocal checks
        checks += 1
        reported_names.add(name)
        if not condition:
            failures.append("%s: %s" % (name, detail))

    STAGED = {"roots": ["production_root"], "stagedTargets": ["staged_claim"]}

    # -- production_graph_auditor_rejects_primary_staged_route_edges ----------
    clean = {
        "a.rs": (
            "pub fn production_root() {\n    helper();\n}\n"
            "fn helper() {\n    let _ = 1;\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        )
    }
    violations, stats = _fixture_gate(clean, STAGED)
    check(SELF_TESTS[1], not violations, "the clean fixture must pass, got %r" % (violations,))
    check(
        SELF_TESTS[1],
        stats["reachableEdgeCount"] >= 1,
        "the clean fixture must walk its own helper edge, or the walk is dead",
    )

    injected = {
        "a.rs": (
            "pub fn production_root() {\n    helper();\n    staged_claim();\n}\n"
            "fn helper() {\n    let _ = 1;\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        )
    }
    # A signature carrying an array type must not read as a bodyless trait
    # method. It did for a long time -- the naive "first `;` before the first
    # `{`" test saw the semicolon inside `[u8; 4]` -- and the consequence is
    # exactly this fixture: the route through `helper` was invisible, so a
    # staged target it reached looked unreachable. Thirty-seven real functions
    # across the two source roots were in that state, including boot-path code.
    array_signature = {
        "a.rs": (
            "pub fn production_root() {\n    helper([0u8; 4]);\n}\n"
            "fn helper(bytes: [u8; 4]) -> [u8; 4] {\n    staged_claim();\n    bytes\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        )
    }
    array_violations, _array_stats = _fixture_gate(array_signature, STAGED)
    check(
        SELF_TESTS[1],
        len(array_violations) == 1
        and array_violations[0].startswith("staged_claim is reachable:"),
        "a route through an array-typed signature must be seen, got %r"
        % (array_violations,),
    )

    violations, _ = _fixture_gate(injected, STAGED)
    check(
        SELF_TESTS[1],
        len(violations) == 1 and violations[0].startswith("staged_claim is reachable:"),
        "an injected production-root -> staged-claim edge must fail the gate, got %r"
        % (violations,),
    )
    check(
        SELF_TESTS[1],
        violations and violations[0].endswith("production_root -> staged_claim"),
        "the failure must name the exact route it found, got %r" % (violations,),
    )

    # A callback installed as a *value* is an edge. This is the shape a driver
    # dispatch table has, and a call-syntax-only model cannot see it.
    as_value = {
        "a.rs": (
            "pub fn production_root() {\n    let slot = Some(staged_claim);\n    let _ = slot;\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        )
    }
    violations, _ = _fixture_gate(as_value, STAGED)
    check(
        SELF_TESTS[1],
        len(violations) == 1,
        "a callee referenced as a value must still be an edge, got %r" % (violations,),
    )

    # A staged symbol reached only through a `#[cfg(test)]` item is not
    # production. Without this the gate could never pass, because the recording
    # tests call the staged API on purpose.
    test_only = {
        "a.rs": (
            "pub fn production_root() {\n    helper();\n}\n"
            "fn helper() {\n    let _ = 1;\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
            "#[cfg(test)]\nmod tests {\n"
            "    #[test]\n    fn drives_it() {\n        super::staged_claim();\n    }\n"
            "}\n"
        )
    }
    violations, _ = _fixture_gate(test_only, STAGED)
    check(
        SELF_TESTS[1],
        not violations,
        "a cfg(test) caller must not make a staged symbol production-reachable",
    )

    # ...and the stripper must survive a brace inside a string literal, which is
    # what silently pulled a whole test module back into the graph before.
    hostile_literal = {
        "a.rs": (
            "pub fn production_root() {\n    helper();\n}\n"
            "fn helper() {\n    let _ = 1;\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
            "#[cfg(test)]\nmod tests {\n"
            '    fn names() -> &\'static str {\n        "struct X {"\n    }\n'
            "    #[test]\n    fn drives_it() {\n        super::staged_claim();\n        names();\n"
            "    }\n"
            "}\n"
        )
    }
    violations, _ = _fixture_gate(hostile_literal, STAGED)
    check(
        SELF_TESTS[1],
        not violations,
        "an unbalanced brace inside a string must not defeat the cfg(test) stripper",
    )

    # A `//` inside a string literal must not truncate the line.
    commented_literal = {
        "a.rs": (
            'pub fn production_root() {\n    let _ = "scheme://host";\n    staged_claim();\n}\n'
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        )
    }
    violations, _ = _fixture_gate(commented_literal, STAGED)
    check(
        SELF_TESTS[1],
        len(violations) == 1,
        "a // inside a string literal must not hide the rest of the line, got %r" % (violations,),
    )

    # A name that appears only inside a literal is not an edge.
    literal_only = {
        "a.rs": (
            'pub fn production_root() {\n    let _ = "staged_claim";\n}\n'
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        )
    }
    violations, _ = _fixture_gate(literal_only, STAGED)
    check(
        SELF_TESTS[1],
        not violations,
        "a name mentioned only inside a string literal is not an edge, got %r" % (violations,),
    )

    # The conservative graph remains the R4/R5 guard. A direct root edge to
    # either retained staged layer must still fail even though the new exact
    # direct index is a separate data structure.
    later_stage_gate = {
        "roots": ["production_root"],
        "stagedTargets": ["begin_ring_set", "prepare_cq_release"],
    }
    later_stage_clean = (
        "pub fn production_root() {}\n"
        "fn begin_ring_set() {}\n"
        "fn prepare_cq_release() {}\n"
    )
    violations, _ = _fixture_gate({"a.rs": later_stage_clean}, later_stage_gate)
    check(SELF_TESTS[1], not violations, "an unreached R4/R5 fixture must pass")
    for target in ("begin_ring_set", "prepare_cq_release"):
        mutated = later_stage_clean.replace(
            "pub fn production_root() {}",
            "pub fn production_root() { %s(); }" % target,
            1,
        )
        violations, _ = _fixture_gate({"a.rs": mutated}, later_stage_gate)
        check(
            SELF_TESTS[1],
            any(violation.startswith("%s is reachable:" % target) for violation in violations),
            "a primary production edge to staged %s must fail: %r" % (target, violations),
        )

    # SETUP publication and terminal cutover are one source-gate identity. A
    # tree with only either half must fail, while the same fixture with both
    # production paths passes.
    cutover_pair_gate = {
        "roots": ["production_root"],
        "requiredReachable": ["publish_locked_suffix", "run_terminal"],
    }
    cutover_parts = (
        "fn publish_locked_suffix() {}\n"
        "fn run_terminal() {}\n"
    )
    for present, absent in (
        ("publish_locked_suffix", "run_terminal"),
        ("run_terminal", "publish_locked_suffix"),
    ):
        fixture = {
            "a.rs": "pub fn production_root() { %s(); }\n%s" % (present, cutover_parts)
        }
        violations, _ = _fixture_gate(fixture, cutover_pair_gate)
        check(
            SELF_TESTS[1],
            violations == ["required symbol is unreachable: %s" % absent],
            "%s-only half-cutover must fail the absent %s half: %r"
            % (present, absent, violations),
        )
    both_cutovers = {
        "a.rs": (
            "pub fn production_root() { publish_locked_suffix(); run_terminal(); }\n"
            + cutover_parts
        )
    }
    violations, _ = _fixture_gate(both_cutovers, cutover_pair_gate)
    check(SELF_TESTS[1], not violations, "the same-tree full cutover must pass: %r" % violations)

    # -- production_direct_graph_contract_rejects_every_caller_bypass --------
    # These rows deliberately exercise `evaluate_gate`, not a parser helper.
    # The contract names exact source-qualified definitions and call
    # expressions; a bare mention or same-named definition must not satisfy it.
    direct_name = SELF_TESTS[2]
    direct_rows = [
        {
            "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
            "callee": {"source": "src/a.rs", "symbol": "run_checkpoint_teardown"},
            "exactCalls": 1,
            "soleCaller": True,
        },
        {
            "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
            "callee": {
                "source": "src/a.rs",
                "symbol": "R3PreparedCheckpointFinish::prepare",
            },
            "exactCalls": 1,
            "soleCaller": True,
        },
        {
            "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
            "callee": {"source": "src/a.rs", "symbol": "finish_checkpoint_teardown"},
            "exactCalls": 1,
            "soleCaller": True,
        },
    ]
    direct_gate = {"roots": ["production_root"], "requiredDirectEdges": direct_rows}
    direct_clean = (
        "pub fn production_root() { run_terminal(); }\n"
        "fn run_terminal() {\n"
        "    run_checkpoint_teardown();\n"
        "    R3PreparedCheckpointFinish::prepare();\n"
        "    finish_checkpoint_teardown();\n"
        "}\n"
        "fn run_checkpoint_teardown() {}\n"
        "struct R3PreparedCheckpointFinish;\n"
        "impl R3PreparedCheckpointFinish { fn prepare() {} }\n"
        "fn finish_checkpoint_teardown() {}\n"
    )
    violations, stats = _fixture_gate({"a.rs": direct_clean}, direct_gate)
    check(direct_name, not violations, "the exact three-edge fixture must pass: %r" % violations)
    check(
        direct_name,
        len(stats.get("requiredDirectEdges", ())) == 3,
        "the report must expose all three required direct rows: %r" % stats,
    )

    for spelling in (
        "    run_checkpoint_teardown();\n",
        "    R3PreparedCheckpointFinish::prepare();\n",
        "    finish_checkpoint_teardown();\n",
    ):
        mutated = direct_clean.replace(spelling, "", 1)
        violations, _ = _fixture_gate({"a.rs": mutated}, direct_gate)
        check(
            direct_name,
            any("required direct edge" in violation for violation in violations),
            "removing %s must fail its direct row: %r" % (spelling.strip(), violations),
        )

    for spelling in (
        "    run_checkpoint_teardown();\n",
        "    R3PreparedCheckpointFinish::prepare();\n",
        "    finish_checkpoint_teardown();\n",
    ):
        mutated = direct_clean.replace(spelling, spelling + spelling, 1)
        violations, _ = _fixture_gate({"a.rs": mutated}, direct_gate)
        check(
            direct_name,
            any("required direct edge" in violation for violation in violations),
            "duplicating %s must preserve multiplicity and fail: %r"
            % (spelling.strip(), violations),
        )

    for spelling in (
        "run_checkpoint_teardown();",
        "R3PreparedCheckpointFinish::prepare();",
        "finish_checkpoint_teardown();",
    ):
        mutated = direct_clean + "fn bypass() { %s }\n" % spelling
        violations, _ = _fixture_gate({"a.rs": mutated}, direct_gate)
        check(
            direct_name,
            any("sole direct caller" in violation for violation in violations),
            "a second caller of %s must fail the closed caller set: %r" % (spelling, violations),
        )

    indirect = direct_clean.replace(
        "    run_checkpoint_teardown();\n",
        "    wrapper();\n",
        1,
    ) + "fn wrapper() { run_checkpoint_teardown(); }\n"
    violations, _ = _fixture_gate({"a.rs": indirect}, direct_gate)
    check(
        direct_name,
        any("required direct edge" in violation for violation in violations),
        "run_terminal -> wrapper -> boundary must not satisfy a direct row: %r" % violations,
    )

    for substitute, extra in (
        ("OtherPreparedFinish::prepare();", "struct OtherPreparedFinish;\nimpl OtherPreparedFinish { fn prepare() {} }\n"),
        ("prepare();", "fn prepare() {}\n"),
    ):
        mutated = direct_clean.replace("R3PreparedCheckpointFinish::prepare();", substitute, 1) + extra
        violations, _ = _fixture_gate({"a.rs": mutated}, direct_gate)
        check(
            direct_name,
            any("required direct edge" in violation for violation in violations),
            "%s must not satisfy the owned prepare row: %r" % (substitute, violations),
        )

    for substitute in (
        "// run_checkpoint_teardown();",
        'let _ = "run_checkpoint_teardown();";',
        "#[cfg(test)] { run_checkpoint_teardown(); }",
        "let _callback = run_checkpoint_teardown;",
    ):
        mutated = direct_clean.replace("run_checkpoint_teardown();", substitute, 1)
        violations, _ = _fixture_gate({"a.rs": mutated}, direct_gate)
        check(
            direct_name,
            any("required direct edge" in violation for violation in violations),
            "%s is not a production direct call: %r" % (substitute, violations),
        )

    for label, substitute in (
        (
            "a never-invoked closure",
            "let _never = || { run_checkpoint_teardown(); };",
        ),
        (
            "a never-polled async block",
            "let _never = async { run_checkpoint_teardown(); };",
        ),
        (
            "an uninvoked local macro definition",
            "macro_rules! never { () => { run_checkpoint_teardown(); } }",
        ),
        (
            "an ignored macro token tree",
            "ignore_tokens!(run_checkpoint_teardown());",
        ),
    ):
        mutated = direct_clean.replace("run_checkpoint_teardown();", substitute, 1)
        if label == "an ignored macro token tree":
            mutated += "macro_rules! ignore_tokens { ($($token:tt)*) => {}; }\n"
        violations, _ = _fixture_gate({"a.rs": mutated}, direct_gate)
        check(
            direct_name,
            any("required direct edge" in violation for violation in violations),
            "%s must not donate a call to its enclosing function: %r" % (label, violations),
        )

    cfg_attr_call = direct_clean.replace(
        "    run_checkpoint_teardown();\n",
        "    #[cfg_attr(not(test), cfg(test))]\n"
        "    run_checkpoint_teardown();\n",
        1,
    )
    violations, _ = _fixture_gate({"a.rs": cfg_attr_call}, direct_gate)
    check(
        direct_name,
        any("required direct edge" in violation for violation in violations),
        "a call removed by production cfg_attr must not satisfy a direct row: %r" % violations,
    )

    cfg_not_test_call = direct_clean.replace(
        "    run_checkpoint_teardown();\n",
        "    #[cfg(not(test))]\n    run_checkpoint_teardown();\n",
        1,
    )
    violations, _ = _fixture_gate({"a.rs": cfg_not_test_call}, direct_gate)
    check(
        direct_name,
        not violations,
        "a cfg(not(test)) call is production and must satisfy the row: %r" % violations,
    )

    external_qualified_gate = {
        "roots": ["production_root"],
        "requiredDirectEdges": [
            {
                "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
                "callee": {"source": "src/a.rs", "symbol": "drop"},
                "exactCalls": 1,
                "soleCaller": True,
            }
        ],
    }
    external_qualified = (
        "pub fn production_root() { run_terminal(); }\n"
        "fn run_terminal() { core::mem::drop(1u8); }\n"
        "fn drop<T>(_value: T) {}\n"
    )
    violations, _ = _fixture_gate({"a.rs": external_qualified}, external_qualified_gate)
    check(
        direct_name,
        any("required direct edge" in violation for violation in violations),
        "an external qualified path must not bind a same-named local function: %r" % violations,
    )

    try:
        _fixture_gate(
            {
                "a.rs": direct_clean,
                "b.rs": "fn run_terminal() { run_checkpoint_teardown(); }\n",
            },
            direct_gate,
        )
        check(direct_name, False, "a same-named caller in another file must be refused")
    except AuditError as error:
        check(direct_name, "ambiguous" in str(error), "wrong duplicate-caller refusal: %s" % error)

    offset_evidence = _fixture_gate({"a.rs": direct_clean}, direct_gate)[1][
        "requiredDirectEdges"
    ]
    check(
        direct_name,
        offset_evidence[0]["observedOffsets"]
        == [direct_clean.index("run_checkpoint_teardown();", direct_clean.index("fn run_terminal"))],
        "direct-call evidence must retain the exact source offset: %r" % offset_evidence,
    )

    wrong_source = json.loads(json.dumps(direct_gate))
    wrong_source["requiredDirectEdges"][0]["callee"]["source"] = "src/b.rs"
    try:
        _fixture_gate({"a.rs": direct_clean, "b.rs": "fn unrelated() {}\n"}, wrong_source)
        check(direct_name, False, "a wrong-file direct row must be refused")
    except AuditError as error:
        check(direct_name, "not declared source" in str(error), "wrong file refusal: %s" % error)

    wrong_owner = json.loads(json.dumps(direct_gate))
    wrong_owner["requiredDirectEdges"][1]["callee"]["symbol"] = "OtherPreparedFinish::prepare"
    try:
        _fixture_gate({"a.rs": direct_clean}, wrong_owner)
        check(direct_name, False, "a wrong-owner direct row must be refused")
    except AuditError as error:
        check(direct_name, "wrong owner" in str(error), "wrong owner refusal: %s" % error)

    trait_only = direct_clean.replace(
        "impl R3PreparedCheckpointFinish { fn prepare() {} }",
        "trait PreparedFinish { fn prepare() {} }\n"
        "impl PreparedFinish for R3PreparedCheckpointFinish { fn prepare() {} }",
    )
    try:
        _fixture_gate({"a.rs": trait_only}, direct_gate)
        check(direct_name, False, "a trait impl must not satisfy an inherent-target row")
    except AuditError as error:
        check(direct_name, "wrong owner" in str(error), "wrong inherent refusal: %s" % error)

    duplicate_callee = {
        "a.rs": direct_clean,
        "b.rs": "fn run_checkpoint_teardown() {}\n",
    }
    try:
        _fixture_gate(duplicate_callee, direct_gate)
        check(direct_name, False, "an ambiguous free-function target must be refused")
    except AuditError as error:
        check(direct_name, "ambiguous" in str(error), "wrong target ambiguity refusal: %s" % error)

    # An inherent method and a trait impl of the same name, on the same type in
    # the same file, are ONE node. The call index keys every call by
    # (source, owner, symbol) and cannot attribute a call to one body rather
    # than the other, so resolution must collapse them the same way. Production
    # depends on this: NativeCheckpointExecutor::release_control_strong_ref is
    # an inherent method plus a trait forwarder, and the closed roster names it
    # once.
    merged_owner = (
        "pub fn production_root() { Executor::release_control_strong_ref(); }\n"
        "struct Executor;\n"
        "trait Ops { fn release_control_strong_ref(); }\n"
        "impl Executor { fn release_control_strong_ref() { release_strong_and_deposit(); } }\n"
        "impl Ops for Executor { fn release_control_strong_ref() {} }\n"
        "fn release_strong_and_deposit() {}\n"
    )
    merged_gate = {
        "roots": ["production_root"],
        "soleDirectCallers": [
            {
                "callee": {"source": "src/a.rs", "symbol": "release_strong_and_deposit"},
                "callers": [
                    {
                        "caller": {
                            "source": "src/a.rs",
                            "symbol": "Executor::release_control_strong_ref",
                        },
                        "exactCalls": 1,
                    }
                ],
            }
        ],
    }
    violations, _ = _fixture_gate({"a.rs": merged_owner}, merged_gate)
    check(
        direct_name,
        not violations,
        "an inherent+trait pair in one file must resolve as one node: %r" % violations,
    )

    # Collapsing is only safe because the count is the SUM: a bypass grown in
    # EITHER body moves the observed count off the roster. Without this the
    # collapse would be a hole rather than an over-approximation.
    merged_bypass = merged_owner.replace(
        "impl Ops for Executor { fn release_control_strong_ref() {} }",
        "impl Ops for Executor { fn release_control_strong_ref()"
        " { release_strong_and_deposit(); } }",
    )
    violations, _ = _fixture_gate({"a.rs": merged_bypass}, merged_gate)
    check(
        direct_name,
        any("closed direct caller roster" in violation for violation in violations),
        "a bypass grown in the trait body must still be counted: %r" % violations,
    )

    # A destination whose only definition is a trait impl must still be
    # nameable as a caller. Production depends on this too:
    # NativeSessionShell::destroy_shell_then_release_root exists only as the
    # capability-sealed PreparedDeleteStorageOps impl.
    trait_only_caller = (
        "pub fn production_root() { Shell::destroy(); }\n"
        "struct Shell;\n"
        "trait StorageOps { fn destroy(); }\n"
        "impl StorageOps for Shell { fn destroy() { free_shell_allocation(); } }\n"
        "fn free_shell_allocation() {}\n"
    )
    trait_only_gate = {
        "roots": ["production_root"],
        "soleDirectCallers": [
            {
                "callee": {"source": "src/a.rs", "symbol": "free_shell_allocation"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "Shell::destroy"},
                        "exactCalls": 1,
                    }
                ],
            }
        ],
    }
    violations, _ = _fixture_gate({"a.rs": trait_only_caller}, trait_only_gate)
    check(
        direct_name,
        not violations,
        "a trait-impl-only definition must be nameable as a caller: %r" % violations,
    )

    # The collapse is per-file only. The same owner::name in two files leaves
    # the declared source unable to settle which body the row means, so it
    # stays an error.
    split_caller = {
        "a.rs": trait_only_caller,
        "b.rs": "struct Shell;\nimpl Shell { fn destroy() {} }\n",
    }
    try:
        _fixture_gate(split_caller, trait_only_gate)
        check(direct_name, False, "the same owner::name in two files must stay ambiguous")
    except AuditError as error:
        check(
            direct_name,
            "ambiguous" in str(error),
            "wrong caller ambiguity refusal: %s" % error,
        )

    # Every destructive or authority-releasing destination has a closed caller
    # roster. This catches a bypass even when the new caller is not reachable
    # from today's roots; newly introduced wrappers cannot hide outside a
    # hand-maintained list of entry points.
    sensitive_name = SELF_TESTS[5]
    sensitive_gate = {
        "roots": ["production_root"],
        "soleDirectCallers": [
            {
                "callee": {"source": "src/a.rs", "symbol": "release_strong_and_deposit"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "finish_checkpoint_teardown"},
                        "exactCalls": 1,
                    },
                    {
                        "caller": {
                            "source": "src/a.rs",
                            "symbol": "NativeCheckpointExecutor::release_control_strong_ref",
                        },
                        "exactCalls": 1,
                    },
                    {
                        "caller": {
                            "source": "src/a.rs",
                            "symbol": "NativeCheckpointExecutor::release_mount_reference",
                        },
                        "exactCalls": 1,
                    },
                ],
            },
            {
                "callee": {"source": "src/a.rs", "symbol": "prepare_final_delete"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "run_queued_finalizer"},
                        "exactCalls": 1,
                    }
                ],
            },
            {
                "callee": {"source": "src/a.rs", "symbol": "execute_prepared_delete"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "run_queued_finalizer"},
                        "exactCalls": 1,
                    }
                ],
            },
            {
                "callee": {"source": "src/a.rs", "symbol": "run_queued_finalizer"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "fsring_finalizer_callback"},
                        "exactCalls": 1,
                    }
                ],
            },
            {
                "callee": {"source": "src/a.rs", "symbol": "queue_cell_finalizer"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "queue_finalizer"},
                        "exactCalls": 1,
                    }
                ],
            },
            {
                "callee": {"source": "src/a.rs", "symbol": "free_session_shell_allocation"},
                "callers": [
                    {
                        "caller": {
                            "source": "src/a.rs",
                            "symbol": "UnpublishedNativeSessionShell::destroy",
                        },
                        "exactCalls": 1,
                    },
                    {
                        "caller": {
                            "source": "src/a.rs",
                            "symbol": "NativeSessionShell::destroy_shell_then_release_root",
                        },
                        "exactCalls": 1,
                    },
                ],
            },
        ],
    }
    sensitive_clean = (
        "pub fn production_root() {}\n"
        "fn release_strong_and_deposit() {}\n"
        "fn finish_checkpoint_teardown() { release_strong_and_deposit(); }\n"
        "struct NativeCheckpointExecutor;\n"
        "impl NativeCheckpointExecutor {\n"
        " fn release_control_strong_ref() { release_strong_and_deposit(); }\n"
        " fn release_mount_reference() { release_strong_and_deposit(); }\n"
        "}\n"
        "fn prepare_final_delete() {}\n"
        "fn execute_prepared_delete() {}\n"
        "fn run_queued_finalizer() { prepare_final_delete(); execute_prepared_delete(); }\n"
        "fn fsring_finalizer_callback() { run_queued_finalizer(); }\n"
        "fn queue_cell_finalizer() {}\n"
        "fn queue_finalizer() { queue_cell_finalizer(); }\n"
        "fn free_session_shell_allocation() {}\n"
        "struct UnpublishedNativeSessionShell;\n"
        "impl UnpublishedNativeSessionShell { fn destroy() { free_session_shell_allocation(); } }\n"
        "struct NativeSessionShell;\n"
        "trait PreparedDeleteStorageOps { fn destroy_shell_then_release_root(); }\n"
        "impl PreparedDeleteStorageOps for NativeSessionShell {\n"
        " fn destroy_shell_then_release_root() { free_session_shell_allocation(); }\n"
        "}\n"
    )
    violations, stats = _fixture_gate({"a.rs": sensitive_clean}, sensitive_gate)
    check(sensitive_name, not violations, "the exact sensitive roster must pass: %r" % violations)
    check(
        sensitive_name,
        len(stats.get("soleDirectCallers", ())) == 6,
        "the report must expose all six sensitive rosters: %r" % stats,
    )
    for destination in (
        "finish_checkpoint_teardown",
        "release_strong_and_deposit",
        "prepare_final_delete",
        "execute_prepared_delete",
        "run_queued_finalizer",
        "queue_cell_finalizer",
        "free_session_shell_allocation",
    ):
        mutated = sensitive_clean.replace(
            "pub fn production_root() {}",
            "pub fn production_root() { %s(); }" % destination,
            1,
        )
        # finish_checkpoint_teardown is the required-edge boundary in the real
        # manifest; include its one-row direct contract in this focused fixture.
        gate = dict(sensitive_gate)
        if destination == "finish_checkpoint_teardown":
            gate["requiredDirectEdges"] = [
                {
                    "caller": {"source": "src/a.rs", "symbol": "approved_terminal"},
                    "callee": {"source": "src/a.rs", "symbol": destination},
                    "exactCalls": 1,
                    "soleCaller": True,
                }
            ]
            mutated += "fn approved_terminal() { finish_checkpoint_teardown(); }\n"
        violations, _ = _fixture_gate({"a.rs": mutated}, gate)
        check(
            sensitive_name,
            any(
                "sole direct caller" in violation or "closed direct caller roster" in violation
                for violation in violations
            ),
            "a production-root bypass to %s must fail: %r" % (destination, violations),
        )

    function_item_bypass = sensitive_clean + (
        "fn hidden_release() {\n"
        "    let release = release_strong_and_deposit;\n"
        "    release();\n"
        "}\n"
    )
    violations, _ = _fixture_gate({"a.rs": function_item_bypass}, sensitive_gate)
    check(
        sensitive_name,
        any("indirect reference" in violation for violation in violations),
        "a function-item indirection to a sensitive callee must fail: %r" % violations,
    )

    use_alias_bypass = (
        "use crate::release_strong_and_deposit as hidden_release;\n"
        + sensitive_clean
        + "fn hidden_release_caller() { hidden_release(); }\n"
    )
    violations, _ = _fixture_gate({"a.rs": use_alias_bypass}, sensitive_gate)
    check(
        sensitive_name,
        any("indirect reference" in violation for violation in violations),
        "a use-alias indirection to a sensitive callee must fail: %r" % violations,
    )
    grouped_use_alias_bypass = (
        "use crate::{release_strong_and_deposit as grouped_release};\n"
        + sensitive_clean
        + "fn grouped_release_caller() { grouped_release(); }\n"
    )
    violations, _ = _fixture_gate({"a.rs": grouped_use_alias_bypass}, sensitive_gate)
    check(
        sensitive_name,
        any("indirect reference" in violation for violation in violations),
        "a grouped use-alias indirection to a sensitive callee must fail: %r"
        % violations,
    )

    # The ABI-retained raw-pointer fence is evidence of refusal, never a
    # scheduler root. Its complete shape is closed: changing an argument use,
    # statement, signature, attribute, or edge must fail even if ordinary
    # reachability would still call the tree safe.
    denied_name = SELF_TESTS[6]
    denied_gate = {
        "roots": ["production_root"],
        "deniedIngresses": [
            {
                "source": "src/a.rs",
                "symbol": "fsring_session_fence",
                "attribute": "#[unsafe(no_mangle)]",
                "signature": 'pub unsafe extern "system" fn(*mut NativeSession, u32) -> NTSTATUS',
                "normalizedBody": "STATUS_INVALID_DEVICE_STATE",
                "outgoingDirectCalls": 0,
            }
        ],
    }
    denied_clean = (
        "pub struct NativeSession;\n"
        "pub type NTSTATUS = i32;\n"
        "const STATUS_INVALID_DEVICE_STATE: NTSTATUS = -1;\n"
        "pub fn production_root() {}\n"
        "fn run_terminal() {}\n"
        "#[unsafe(no_mangle)]\n"
        "pub unsafe extern \"system\" fn fsring_session_fence(\n"
        "    _session: *mut NativeSession,\n"
        "    _reason: u32,\n"
        ") -> NTSTATUS {\n"
        "    STATUS_INVALID_DEVICE_STATE\n"
        "}\n"
    )
    violations, stats = _fixture_gate({"a.rs": denied_clean}, denied_gate)
    check(denied_name, not violations, "the exact denied stub must pass: %r" % violations)
    check(
        denied_name,
        len(stats.get("deniedIngresses", ())) == 1
        and stats["deniedIngresses"][0].get("observedDirectCalls") == 0,
        "the report must expose the denied stub's zero-edge evidence: %r" % stats,
    )
    for body in (
        "unsafe { (*_session).touch(); } STATUS_INVALID_DEVICE_STATE",
        "let _decoded = _reason & 1; STATUS_INVALID_DEVICE_STATE",
        "emit_evidence(); STATUS_INVALID_DEVICE_STATE",
        "resolve_locator(_session); STATUS_INVALID_DEVICE_STATE",
        "run_terminal(); STATUS_INVALID_DEVICE_STATE",
        "let _ = 0; STATUS_INVALID_DEVICE_STATE",
    ):
        mutated = denied_clean.replace(
            "    STATUS_INVALID_DEVICE_STATE\n",
            "    %s\n" % body,
            1,
        )
        violations, _ = _fixture_gate({"a.rs": mutated}, denied_gate)
        check(
            denied_name,
            any("denied ingress" in violation for violation in violations),
            "a denied-stub body mutation must fail (%s): %r" % (body, violations),
        )

    without_attribute = denied_clean.replace("#[unsafe(no_mangle)]\n", "", 1)
    violations, _ = _fixture_gate({"a.rs": without_attribute}, denied_gate)
    check(
        denied_name,
        any("denied ingress" in violation for violation in violations),
        "removing the ABI attribute must fail: %r" % violations,
    )

    renamed_bypass = denied_clean + (
        "#[unsafe(no_mangle)]\n"
        "pub unsafe extern \"system\" fn renamed_fence(\n"
        "    _session: *mut NativeSession, reason: u32,\n"
        ") -> NTSTATUS { run_terminal(); let _ = reason; STATUS_INVALID_DEVICE_STATE }\n"
    )
    violations, _ = _fixture_gate({"a.rs": renamed_bypass}, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "a renamed raw-pointer terminal ingress must fail: %r" % violations,
    )
    renamed_function_item = denied_clean + (
        "#[unsafe(no_mangle)]\n"
        "pub unsafe extern \"system\" fn renamed_fence_item(\n"
        "    _session: *mut NativeSession, reason: u32,\n"
        ") -> NTSTATUS { let _callback = run_terminal; let _ = reason; STATUS_INVALID_DEVICE_STATE }\n"
    )
    violations, _ = _fixture_gate({"a.rs": renamed_function_item}, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "a renamed raw-pointer function-item terminal edge must fail: %r" % violations,
    )

    cfg_attr_denied = denied_clean.replace(
        "#[unsafe(no_mangle)]\n",
        "#[cfg_attr(not(test), cfg(test))]\n#[unsafe(no_mangle)]\n",
        1,
    )
    try:
        violations, _ = _fixture_gate({"a.rs": cfg_attr_denied}, denied_gate)
        check(
            denied_name,
            any("denied ingress" in violation for violation in violations),
            "a denied export removed from production by cfg_attr must fail: %r" % violations,
        )
    except AuditError as error:
        check(
            denied_name,
            "denied ingress" in str(error),
            "wrong cfg_attr-denied refusal: %s" % error,
        )

    structural_ingress = denied_clean + (
        "#[unsafe(no_mangle)]\n"
        "pub(crate) extern \"system\" fn renamed_structural_fence(\n"
        "    _session: *mut NativeSession, reason: u32,\n"
        ") -> NTSTATUS { run_terminal(); let _ = reason; STATUS_INVALID_DEVICE_STATE }\n"
    )
    violations, _ = _fixture_gate({"a.rs": structural_ingress}, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "visibility and unsafe spelling must not hide an ABI-equivalent ingress: %r"
        % violations,
    )

    aliased_abi_ingress = denied_clean + (
        "type SessionPointer = *mut NativeSession; type FenceReason = u32;\n"
        "pub(crate) extern \"system\" fn renamed_aliased_abi(\n"
        "    _session: SessionPointer, reason: FenceReason,\n"
        ") -> NTSTATUS { run_terminal(); let _ = reason; STATUS_INVALID_DEVICE_STATE }\n"
    )
    violations, _ = _fixture_gate({"a.rs": aliased_abi_ingress}, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "type aliases must not hide an ABI-equivalent ingress: %r" % violations,
    )
    conflicting_alias_tree = {
        "a.rs": aliased_abi_ingress,
        "b.rs": "type FenceReason = u64;\n",
    }
    violations, stats = _fixture_gate(conflicting_alias_tree, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "an unrelated module's same-named alias must not hide an ABI-equivalent ingress: %r"
        % violations,
    )
    check(
        denied_name,
        stats.get("deniedIngressAliasSourceScans") == len(conflicting_alias_tree),
        "denied-ingress alias indexing must scan each source exactly once: %r" % stats,
    )
    qualified_abi_ingress = denied_clean + (
        "pub(crate) extern \"system\" fn renamed_qualified_abi(\n"
        "    _session: *mut crate::a::NativeSession,\n"
        "    reason: core::primitive::u32,\n"
        ") -> NTSTATUS { run_terminal(); let _ = reason; STATUS_INVALID_DEVICE_STATE }\n"
    )
    violations, _ = _fixture_gate({"a.rs": qualified_abi_ingress}, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "qualified spellings must not hide an ABI-equivalent ingress: %r" % violations,
    )

    aliased_transitive_ingress = (
        "use crate::run_terminal as terminal_alias;\n"
        + denied_clean
        + "fn hidden_terminal_wrapper() { terminal_alias(); }\n"
        + "#[unsafe(no_mangle)]\n"
        + "pub unsafe extern \"system\" fn renamed_aliased_fence(\n"
        + "    _session: *mut NativeSession, reason: u32,\n"
        + ") -> NTSTATUS { hidden_terminal_wrapper(); let _ = reason; "
        + "STATUS_INVALID_DEVICE_STATE }\n"
    )
    violations, _ = _fixture_gate({"a.rs": aliased_transitive_ingress}, denied_gate)
    check(
        denied_name,
        any("raw-pointer ingress" in violation for violation in violations),
        "a renamed ingress must not hide a transitive terminal edge behind a use alias: %r"
        % violations,
    )

    closed_gate_name = "task12_r3_cutover_has_exactly_one_terminal_delete_path"
    closed_tree = {
        "a.rs": (
            "pub struct NativeSession;\n"
            "pub type NTSTATUS = i32;\n"
            "const STATUS_INVALID_DEVICE_STATE: NTSTATUS = -1;\n"
            "pub fn production_root() { run_terminal(); }\n"
            "fn run_terminal() { boundary(); }\n"
            "fn boundary() {}\n"
            "#[unsafe(no_mangle)]\n"
            "pub unsafe extern \"system\" fn fsring_session_fence(\n"
            "    _session: *mut NativeSession, _reason: u32,\n"
            ") -> NTSTATUS { STATUS_INVALID_DEVICE_STATE }\n"
        )
    }
    closed_gate = {
        "profile": "fixture",
        "note": "closed Task 12 fixture",
        "roots": ["production_root"],
        "requiredReachable": ["run_terminal"],
        "requiredDirectEdges": [
            {
                "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
                "callee": {"source": "src/a.rs", "symbol": "boundary"},
                "exactCalls": 1,
                "soleCaller": True,
            }
        ],
        "soleDirectCallers": [
            {
                "callee": {"source": "src/a.rs", "symbol": "boundary"},
                "callers": [
                    {
                        "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
                        "exactCalls": 1,
                    }
                ],
            }
        ],
        "deniedIngresses": denied_gate["deniedIngresses"],
        "stagedTargets": [],
        "forbiddenSymbols": [],
        "forbiddenEdges": [],
        "forbiddenText": [],
    }
    violations, _ = _fixture_gate(
        closed_tree, closed_gate, gate_name=closed_gate_name
    )
    check(
        direct_name,
        not violations,
        "the exact closed Task 12 gate schema must pass: %r" % violations,
    )
    unknown_gate_key = json.loads(json.dumps(closed_gate))
    unknown_gate_key["requiredDirectEdge"] = []
    try:
        _fixture_gate(closed_tree, unknown_gate_key, gate_name=closed_gate_name)
        check(direct_name, False, "an unknown Task 12 gate key must be refused")
    except AuditError as error:
        check(
            direct_name,
            "unknown" in str(error),
            "wrong unknown-gate-key refusal: %s" % error,
        )
    for oracle_key in ("requiredDirectEdges", "soleDirectCallers", "deniedIngresses"):
        for invalid in ("missing", None, []):
            weakened_gate = json.loads(json.dumps(closed_gate))
            if invalid == "missing":
                del weakened_gate[oracle_key]
            else:
                weakened_gate[oracle_key] = invalid
            try:
                _fixture_gate(closed_tree, weakened_gate, gate_name=closed_gate_name)
                check(
                    direct_name,
                    False,
                    "Task 12 %s=%r must be refused" % (oracle_key, invalid),
                )
            except AuditError as error:
                check(
                    direct_name,
                    oracle_key in str(error),
                    "wrong fail-closed %s refusal: %s" % (oracle_key, error),
                )

    # -- production_graph_auditor_rejects_duplicate_and_bypass_edges ---------
    duplicate = {
        "a.rs": "pub fn production_root() {\n    let _ = 1;\n}\n",
        "b.rs": "pub fn production_root() {\n    let _ = 2;\n}\n",
    }
    try:
        _fixture_gate(duplicate, {"roots": ["production_root"]})
        check(SELF_TESTS[0], False, "two definitions of one root must be refused")
    except AuditError as error:
        check(SELF_TESTS[0], "ambiguous" in str(error), "wrong refusal: %s" % error)

    try:
        _fixture_gate({"a.rs": "fn other() {}\n"}, {"roots": ["production_root"]})
        check(SELF_TESTS[0], False, "an absent root must be refused")
    except AuditError as error:
        check(SELF_TESTS[0], "absent" in str(error), "wrong refusal: %s" % error)

    try:
        _fixture_gate(
            {"a.rs": "pub fn production_root() {}\n"},
            {"roots": ["production_root"], "stagedTargets": ["gone"]},
        )
        check(SELF_TESTS[0], False, "an absent staged target must be refused")
    except AuditError as error:
        check(SELF_TESTS[0], "staged targets are absent" in str(error), "wrong refusal: %s" % error)

    # A bypass caller that nothing reaches is not reachable, and the forbidden
    # rows fire on definition as well as on reachability.
    bypass = {
        "a.rs": (
            "pub fn production_root() {\n    approved();\n}\n"
            "fn approved() {\n    let _ = 1;\n}\n"
            "fn bypass() {\n    approved();\n}\n"
        )
    }
    violations, _ = _fixture_gate(bypass, {"roots": ["production_root"], "stagedTargets": ["bypass"]})
    check(SELF_TESTS[0], not violations, "an unreached bypass definition is not reachable")
    violations, _ = _fixture_gate(
        bypass, {"roots": ["production_root"], "forbiddenSymbols": ["bypass"]}
    )
    check(
        SELF_TESTS[0],
        len(violations) == 1 and "still defined" in violations[0],
        "a forbidden symbol must fail on definition alone, got %r" % (violations,),
    )
    violations, _ = _fixture_gate(
        bypass,
        {"roots": ["production_root"], "forbiddenEdges": [{"caller": "bypass", "callee": "approved"}]},
    )
    check(
        SELF_TESTS[0],
        len(violations) == 1 and "forbidden edge" in violations[0],
        "a forbidden edge must fail even when unreached, got %r" % (violations,),
    )

    # A cutover gate's required-reachable rows are the mirror of a staged
    # target, and they fail in the direction a staging gate cannot see: the new
    # path exists but nothing calls it.
    required = {"roots": ["production_root"], "requiredReachable": ["cutover_route"]}
    unreached = {
        "a.rs": (
            "pub fn production_root() {\n    helper();\n}\n"
            "fn helper() {\n    let _ = 1;\n}\n"
            "pub fn cutover_route() {\n    let _ = 2;\n}\n"
        )
    }
    violations, _ = _fixture_gate(unreached, required)
    check(
        SELF_TESTS[0],
        len(violations) == 1 and violations[0].startswith("required symbol is unreachable:"),
        "an uncalled cutover route must fail its gate, got %r" % (violations,),
    )
    reached_fixture = {
        "a.rs": (
            "pub fn production_root() {\n    cutover_route();\n}\n"
            "pub fn cutover_route() {\n    let _ = 2;\n}\n"
        )
    }
    violations, _ = _fixture_gate(reached_fixture, required)
    check(SELF_TESTS[0], not violations, "a called cutover route must pass, got %r" % (violations,))
    try:
        _fixture_gate({"a.rs": "pub fn production_root() {}\n"}, required)
        check(SELF_TESTS[0], False, "an absent required-reachable symbol must be refused")
    except AuditError as error:
        check(
            SELF_TESTS[0],
            "required-reachable symbol is absent" in str(error),
            "wrong refusal: %s" % error,
        )

    # -- no_legacy_mount_registry_consumer_survives_cutover ------------------
    # Task 12 must leave literal zero results for the predecessor mount
    # registry. Its pieces are a struct, a `DriverState` field, and a constant
    # prefix -- *none* of them function nodes -- so the reachability walk cannot
    # see any of them. This row was first written as `forbiddenSymbols`, and
    # planting each token in a reachable body left the gate green: a row that
    # read as coverage and measured nothing. The checks below drive the real
    # `evaluate_gate` over a tree that still has each consumer, so deleting the
    # text mechanism fails here rather than passing quietly.
    LEGACY = {
        "roots": ["production_root"],
        "forbiddenText": ["MountRegistry", "MountEntry", ".mounts", "MOUNT_SLOT_", "live_count"],
    }
    cutover = {
        "a.rs": (
            "pub fn production_root() {\n    occupied_cell_count();\n}\n"
            "fn occupied_cell_count() {\n    let _ = 1;\n}\n"
        )
    }
    violations, _ = _fixture_gate(cutover, LEGACY)
    check(
        SELF_TESTS[4],
        not violations,
        "the post-cutover tree must pass, got %r" % (violations,),
    )

    for consumer, needle in (
        ("    let _p: MountRegistry;\n", "MountRegistry"),
        ("    let _p: MountEntry;\n", "MountEntry"),
        ("    let _p = state.mounts;\n", ".mounts"),
        ("    let _p = MOUNT_SLOT_LIVE;\n", "MOUNT_SLOT_"),
        ("    let _p = live_count();\n", "live_count"),
    ):
        survivor = {
            "a.rs": (
                "pub fn production_root() {\n%s}\n" % consumer
                + "fn occupied_cell_count() {\n    let _ = 1;\n}\n"
            )
        }
        violations, _ = _fixture_gate(survivor, LEGACY)
        check(
            SELF_TESTS[4],
            any(violation.startswith("forbidden text is present: %s " % needle) for violation in violations),
            "a surviving %s consumer must fail the gate, got %r" % (needle, violations),
        )

    # And the stripper is what makes the row a statement about code rather than
    # about prose: the retired registry is described at length in the comments
    # this cutover leaves behind, and a scanner that could not tell the two
    # apart would be unsatisfiable.
    documented = {
        "a.rs": (
            "// The predecessor MountRegistry and its MOUNT_SLOT_ states are gone.\n"
            "pub fn production_root() {\n    occupied_cell_count();\n}\n"
            "fn occupied_cell_count() {\n    let _ = 1;\n}\n"
        )
    }
    violations, _ = _fixture_gate(documented, LEGACY)
    check(
        SELF_TESTS[4],
        not violations,
        "a comment naming the retired registry is not a consumer, got %r" % (violations,),
    )

    # The manifest's advertised roster is cross-checked against the gate's.
    try:
        with tempfile.TemporaryDirectory(prefix="c4-graph-selftest-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8", newline="") as handle:
                handle.write("pub fn production_root() {}\npub fn other_root() {}\n")
            manifest = {
                "schema": SCHEMA,
                "testFiles": [],
                "productionRoots": ["production_root", "other_root"],
                "gates": {"fixture": {"roots": ["production_root"]}},
            }
            evaluate_gate(work, manifest, "fixture", ["src"])
        check(SELF_TESTS[0], False, "a gate that omits a declared root must be refused")
    except AuditError as error:
        check(SELF_TESTS[0], "omits declared" in str(error), "wrong refusal: %s" % error)

    # The tracked manifest must still parse and name gates, or the checks above
    # are proving a fixture the tree does not use.
    base_manifest = load_manifest(manifest_path)
    check(SELF_TESTS[0], bool(base_manifest["gates"]), "the tracked manifest declares no gate")

    # -- production_attestation_refresh_is_deterministic_and_fails_closed -----
    name = SELF_TESTS[3]

    # Thread order is noise; the same tests in a different order are the same
    # result. Elapsed time is noise too.
    first = (
        "\nrunning 2 tests\ntest beta ... ok\ntest alpha ... ok\n\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;"
        " finished in 0.31s\n"
    )
    second = (
        "\nrunning 2 tests\ntest alpha ... ok\ntest beta ... ok\n\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;"
        " finished in 12.04s\n"
    )
    records_a, passed_a = canonical_test_records(first)
    records_b, passed_b = canonical_test_records(second)
    check(
        name,
        canonical_records_sha256(records_a) == canonical_records_sha256(records_b),
        "thread order and elapsed time must not change the canonical stdout",
    )
    check(name, passed_a == 2 and passed_b == 2, "the canonical count is the passed total")

    # A different *set* of tests is a different result, or the canonicalization
    # would be a summary two runs could collide on.
    third = (
        "\nrunning 2 tests\ntest alpha ... ok\ntest gamma ... ok\n\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;"
        " finished in 0.31s\n"
    )
    records_c, _ = canonical_test_records(third)
    check(
        name,
        canonical_records_sha256(records_a) != canonical_records_sha256(records_c),
        "a different test set must not hash the same",
    )

    # Anything outside the closed grammar is a refusal, not a dropped line.
    for hostile, why in (
        ("running 1 tests\ntest a ... ok\nsurprise\n", "an unrecognized line"),
        ("test a ... ok\n", "a test outside any section"),
        ("running 1 tests\ntest a ... ok\n", "an unterminated section"),
    ):
        try:
            canonical_test_records(hostile)
            check(name, False, "%s must be refused" % why)
        except AuditError:
            check(name, True, "")

    # The document shape is exact: reordered or extra root keys are refused.
    sample = {key: None for key in ATTESTATION_KEYS}
    try:
        canonical_attestation_bytes(sample)
        check(name, True, "")
    except AuditError:
        check(name, False, "the exact ordered key set must be accepted")
    reordered = {key: None for key in reversed(ATTESTATION_KEYS)}
    try:
        canonical_attestation_bytes(reordered)
        check(name, False, "reordered root keys must be refused")
    except AuditError:
        check(name, True, "")

    enclosing_identity = {
        "sourceIdentity": "SOURCE",
        "manifestSha256": "MANIFEST",
        "auditorSha256": "AUDITOR",
    }
    bound_row = dict(enclosing_identity)
    try:
        validate_attestation_row_identity(bound_row, enclosing_identity)
        check(name, True, "")
    except AuditError as error:
        check(name, False, "an exactly identity-bound row must pass: %s" % error)
    for identity_key in ROW_IDENTITY_KEYS:
        mixed = dict(bound_row)
        mixed[identity_key] = "DIFFERENT"
        try:
            validate_attestation_row_identity(mixed, enclosing_identity)
            check(name, False, "a mixed %s row must be refused" % identity_key)
        except AuditError as error:
            check(
                name,
                identity_key in str(error),
                "the mixed-row refusal must name %s: %s" % (identity_key, error),
            )

    check(
        SELF_TESTS[7],
        is_expected_step1_source_red(EXPECTED_STEP1_SOURCE_RED),
        "the one known pre-cutover source diagnostic must be classified as expected RED",
    )
    check(
        SELF_TESTS[7],
        not is_expected_step1_source_red(
            "denied ingress driver/fsring-fsd/src/session.rs#fsring_session_fence changed"
        ),
        "a denied-ingress regression must not be reclassified as expected source RED",
    )

    # Two same-source refreshes must produce byte-identical documents once the
    # source gate is ready. During Step 1 the new v2 manifest intentionally
    # precedes the sole-runner source cutover, so the direct source gate is RED.
    # That expected RED is reported separately and is accepted only when it is
    # one of the exact direct/closed-caller/denied-ingress diagnostics. A cargo
    # failure, zero-test row, or stale attestation is never reclassified as the
    # expected source RED.
    root = os.path.dirname(os.path.dirname(os.path.dirname(auditor_path)))
    profiles = sorted(load_profiles(load_manifest(manifest_path)))
    current_profile = "r5-cutover" if "r5-cutover" in profiles else profiles[0]
    marker = os.path.join(root, ATTESTATION_RELATIVE_PATH.replace("/", os.sep))
    before = file_sha256(marker) if os.path.exists(marker) else None
    source_gate_status = "GREEN"
    try:
        one = compute_attestation(
            root, manifest_path, auditor_path, current_profile, list(DEFAULT_SOURCE_ROOTS)
        )
        two = compute_attestation(
            root, manifest_path, auditor_path, current_profile, list(DEFAULT_SOURCE_ROOTS)
        )
        check(
            name,
            canonical_attestation_bytes(one) == canonical_attestation_bytes(two),
            "two same-source refreshes must be byte-identical",
        )
        check(name, len(one["rows"]) >= 2, "a profile must attest a gate and a property row")
    except AuditError as error:
        detail = str(error)
        expected_direct_red = is_expected_step1_source_red(detail)
        check(
            SELF_TESTS[7],
            expected_direct_red,
            "the source gate failed for a reason other than the pending direct cutover: %s"
            % detail,
        )
        if expected_direct_red:
            source_gate_status = "EXPECTED RED (%s)" % detail
    check(
        name,
        (file_sha256(marker) if os.path.exists(marker) else None) == before,
        "--self-test must never write an attestation",
    )

    # -- every_test_module_is_declared_or_the_graph_refuses ------------------
    #
    # Both directions, and both drive `evaluate_gate` rather than reimplementing
    # the rule: a guard checked by a copy of itself is not checked.
    undeclared = {
        "a.rs": (
            "pub fn production_root() {\n    helper();\n}\n"
            "fn helper() {\n    let _ = 1;\n}\n"
            "pub fn staged_claim() {\n    let _ = 2;\n}\n"
        ),
        "tests.rs": (
            "fn helper() {\n    staged_claim();\n}\n"
        ),
    }
    refused = None
    try:
        _fixture_gate(undeclared, STAGED)
    except AuditError as error:
        refused = str(error)
    check(
        SELF_TESTS[8],
        refused is not None and "undeclared test module" in refused,
        "an undeclared tests.rs must refuse the whole gate, got %r" % (refused,),
    )

    # Declared, the same tree passes -- so the refusal is about the declaration,
    # not about the file existing. Without this the guard could be "refuse any
    # tree containing a tests.rs" and still look correct.
    declared_violations, _declared_stats = _fixture_gate(
        undeclared, STAGED, test_files=["src/tests.rs"]
    )
    check(
        SELF_TESTS[8],
        not declared_violations,
        "a declared tests.rs must be skipped entirely, got %r" % (declared_violations,),
    )

    # And its bodies must not reach the staged target once declared: the second
    # `helper` above calls `staged_claim`, so a manifest that skipped the file
    # for *definitions* but still walked it for *edges* fails here.
    # ... and it contributes no edges at all. The declared module's `helper`
    # calls `staged_claim`; if the walk still saw that call the count would be
    # two, and this is what distinguishes "skipped" from "skipped for
    # definitions but still walked for edges".
    check(
        SELF_TESTS[8],
        _declared_stats["reachableEdgeCount"] == 1,
        "a declared test module must contribute no edge, saw %r"
        % (_declared_stats["reachableEdgeCount"],),
    )

    # A test module's CHILD, one directory down, is refused the same way. It is
    # not named `tests.rs`, so a guard keyed on the file name alone read it as
    # production; declared, it is skipped like any other test file.
    nested = {
        "a.rs": undeclared["a.rs"],
        "tests/child.rs": "fn helper() {\n    staged_claim();\n}\n",
    }
    nested_refused = None
    try:
        _fixture_gate(nested, STAGED)
    except AuditError as error:
        nested_refused = str(error)
    check(
        SELF_TESTS[8],
        nested_refused is not None and "undeclared test module" in nested_refused,
        "an undeclared child of a test module must refuse the whole gate, got %r"
        % (nested_refused,),
    )
    nested_violations, nested_stats = _fixture_gate(
        nested, STAGED, test_files=["src/tests/child.rs"]
    )
    check(
        SELF_TESTS[8],
        not nested_violations and nested_stats["reachableEdgeCount"] == 1,
        "a declared child of a test module must be skipped entirely, got %r / %r"
        % (nested_violations, nested_stats["reachableEdgeCount"]),
    )

    # -- task25_zero_roster_reinsertion_and_cutover_mutants_fail_the_gate ----
    task25_name = SELF_TESTS[9]
    tracked = load_manifest(manifest_path)
    tracked_gate = tracked["gates"].get(TASK25_GATE)
    check(
        task25_name,
        isinstance(tracked_gate, dict),
        "the tracked manifest must declare %s" % TASK25_GATE,
    )
    if isinstance(tracked_gate, dict):
        check(
            task25_name,
            tuple(tracked_gate.get("zeroRoster", ())) == TASK25_ZERO_ROSTER,
            "the tracked Task 25 zeroRoster must be the immutable 53-entry table",
        )
        check(
            task25_name,
            tuple(tracked_gate.get("zeroRosterFiles", ())) == TASK25_ZERO_ROSTER_FILES,
            "the tracked Task 25 zeroRosterFiles must be the closed compatibility set",
        )
        check(
            task25_name,
            len(TASK25_ZERO_ROSTER) == 53,
            "the Task 25 zero roster must have exactly 53 entries, got %d"
            % len(TASK25_ZERO_ROSTER),
        )

    clean_cutover = {
        "a.rs": (
            "pub fn production_root() {\n"
            "    run_terminal();\n"
            "}\n"
            "fn run_terminal() {\n"
            "    let _worker = fsring_fence_retry_worker;\n"
            "    let _ops = KernelFenceOps::try_new();\n"
            "    finish_fence();\n"
            "}\n"
            "fn finish_fence() {}\n"
            "fn fsring_fence_retry_worker() {\n"
            "    let _ops = KernelFenceOps::resume();\n"
            "}\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    cutover_gate = {
        "roots": ["production_root"],
        "requiredReachable": ["try_new", "resume", "finish_fence"],
        "forbiddenSymbols": ["run_checkpoint_teardown"],
        "zeroRoster": list(TASK25_ZERO_ROSTER),
    }
    violations, _ = _fixture_gate(clean_cutover, cutover_gate)
    check(
        task25_name,
        not violations,
        "the clean Task 25 fixture must pass, got %r" % (violations,),
    )

    for entry in TASK25_ZERO_ROSTER:
        planted = {
            "a.rs": (
                "pub fn production_root() {\n"
                "    run_terminal();\n"
                "    leftover %s ;\n"
                "}\n"
                "fn run_terminal() {\n"
                "    let _worker = fsring_fence_retry_worker;\n"
                "    let _ops = KernelFenceOps::try_new();\n"
                "    finish_fence();\n"
                "}\n"

                "fn finish_fence() {}\n"
                "fn fsring_fence_retry_worker() {\n"
                "    let _ops = KernelFenceOps::resume();\n"
                "}\n"

                "struct KernelFenceOps;\n"
                "impl KernelFenceOps {\n"
                "    fn try_new() {}\n"
                "    fn resume() {}\n"
                "}\n" % entry
            )
        }
        violations, _ = _fixture_gate(planted, cutover_gate)
        check(
            task25_name,
            any(
                "zero-roster entry has" in item and entry in item
                for item in violations
            ),
            "reinserting %r must fail the zero roster, got %r" % (entry, violations),
        )

    r4_scheduler = {
        "a.rs": (
            "pub fn production_root() {\n    run_terminal();\n}\n"
            "fn run_terminal() {\n    let _worker = fsring_fence_retry_worker;\n    run_checkpoint_teardown();\n    finish_fence();\n}\n"
            "fn run_checkpoint_teardown() {}\n"

            "fn finish_fence() {}\n"
            "fn fsring_fence_retry_worker() { KernelFenceOps::resume(); }\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    violations, _ = _fixture_gate(r4_scheduler, cutover_gate)
    check(
        task25_name,
        any("forbidden symbol is still defined: run_checkpoint_teardown" in item for item in violations)
        or any("forbidden symbol is reachable: run_checkpoint_teardown" in item for item in violations),
        "a retained R4 scheduler edge must fail the Task 25 gate, got %r" % (violations,),
    )

    second_try_new = {
        "a.rs": (
            "pub fn production_root() {\n    run_terminal();\n    extra();\n}\n"
            "fn run_terminal() {\n    let _worker = fsring_fence_retry_worker;\n    KernelFenceOps::try_new();\n    finish_fence();\n}\n"
            "fn extra() {\n    KernelFenceOps::try_new();\n}\n"

            "fn finish_fence() {}\n"
            "fn fsring_fence_retry_worker() { KernelFenceOps::resume(); }\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    sole_try_new = {
        "roots": ["production_root"],
        "requiredReachable": ["try_new", "resume", "finish_fence"],
        "forbiddenSymbols": ["run_checkpoint_teardown"],
        "zeroRoster": list(TASK25_ZERO_ROSTER),
        "requiredDirectEdges": [
            {
                "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
                "callee": {"source": "src/a.rs", "symbol": "KernelFenceOps::try_new"},
                "exactCalls": 1,
                "soleCaller": True,
            }
        ],
    }
    violations, _ = _fixture_gate(second_try_new, sole_try_new)
    check(
        task25_name,
        any("sole direct caller" in item for item in violations),
        "a second KernelFenceOps::try_new caller must fail the Task 25 gate, got %r"
        % (violations,),
    )

    bypass_finish = {
        "a.rs": (
            "pub fn production_root() {\n    run_terminal();\n    extra();\n}\n"
            "fn run_terminal() {\n    let _worker = fsring_fence_retry_worker;\n    KernelFenceOps::try_new();\n}\n"
            "fn extra() {\n    finish_fence();\n}\n"

            "fn finish_fence() {}\n"
            "fn fsring_fence_retry_worker() { KernelFenceOps::resume(); }\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    sole_finish = {
        "roots": ["production_root"],
        "requiredReachable": ["try_new", "resume", "finish_fence"],
        "forbiddenSymbols": ["run_checkpoint_teardown"],
        "zeroRoster": list(TASK25_ZERO_ROSTER),
        "requiredDirectEdges": [
            {
                "caller": {"source": "src/a.rs", "symbol": "run_terminal"},
                "callee": {"source": "src/a.rs", "symbol": "finish_fence"},
                "exactCalls": 1,
                "soleCaller": True,
            }
        ],
    }
    violations, _ = _fixture_gate(bypass_finish, sole_finish)
    check(
        task25_name,
        any("sole direct caller" in item or "expected" in item for item in violations),
        "a direct finish/deposit/finalizer bypass must fail the Task 25 gate, got %r"
        % (violations,),
    )

    outside_retry = {
        "a.rs": (
            "pub fn production_root() {\n    run_terminal();\n    extra();\n}\n"
            "fn run_terminal() {\n    let _worker = fsring_fence_retry_worker;\n    KernelFenceOps::try_new();\n    finish_fence();\n}\n"
            "fn extra() {\n    KernelFenceOps::resume();\n}\n"

            "fn finish_fence() {}\n"
            "fn fsring_fence_retry_worker() { KernelFenceOps::resume(); }\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    sole_resume = {
        "roots": ["production_root"],
        "requiredReachable": ["try_new", "resume", "finish_fence"],
        "forbiddenSymbols": ["run_checkpoint_teardown"],
        "zeroRoster": list(TASK25_ZERO_ROSTER),
        "requiredDirectEdges": [
            {
                "caller": {"source": "src/a.rs", "symbol": "fsring_fence_retry_worker"},
                "callee": {"source": "src/a.rs", "symbol": "KernelFenceOps::resume"},
                "exactCalls": 1,
                "soleCaller": True,
            }
        ],
    }
    violations, _ = _fixture_gate(outside_retry, sole_resume)
    check(
        task25_name,
        any("sole direct caller" in item for item in violations),
        "a retry caller outside the preallocated worker must fail the Task 25 gate, got %r"
        % (violations,),
    )

    unload_skip = {
        "a.rs": (
            "pub fn production_root() {\n    fsring_driver_unload();\n}\n"
            "fn fsring_driver_unload() {\n    observe_unload();\n}\n"
            "fn observe_unload() { let _ = 1; }\n"

            "fn finish_fence() {}\n"
            "fn run_terminal() { let _worker = fsring_fence_retry_worker; KernelFenceOps::try_new(); finish_fence(); }\n"
            "fn fsring_fence_retry_worker() { KernelFenceOps::resume(); }\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    residual_required = {
        "roots": ["production_root"],
        "requiredReachable": ["try_new", "resume", "finish_fence", "observe_residual_authority"],
        "forbiddenSymbols": ["run_checkpoint_teardown"],
        "zeroRoster": list(TASK25_ZERO_ROSTER),
    }
    try:
        _fixture_gate(unload_skip, residual_required)
        check(
            task25_name,
            False,
            "an unload consumer that skips residual authority must fail the Task 25 gate",
        )
    except AuditError as error:
        check(
            task25_name,
            "required-reachable symbol is absent" in str(error)
            or "unreachable" in str(error),
            "wrong unload-skip residual refusal: %s" % error,
        )

    staged_lifecycle = {
        "a.rs": (
            "pub fn production_root() {\n    run_queued_finalizer();\n}\n"
            "fn run_queued_finalizer() {\n    try_new_fence_retry_lifecycle();\n    finish_fence();\n}\n"
            "fn try_new_fence_retry_lifecycle() {}\n"

            "fn finish_fence() {}\n"
            "fn run_terminal() { let _worker = fsring_fence_retry_worker; KernelFenceOps::try_new(); finish_fence(); }\n"
            "fn fsring_fence_retry_worker() { KernelFenceOps::resume(); }\n"
            "struct KernelFenceOps;\n"
            "impl KernelFenceOps {\n"
            "    fn try_new() {}\n"
            "    fn resume() {}\n"
            "}\n"
        )
    }
    staged_lifecycle_gate = {
        "roots": ["production_root"],
        "requiredReachable": ["try_new", "resume", "finish_fence"],
        "forbiddenSymbols": ["run_checkpoint_teardown"],
        "forbiddenEdges": [
            {
                "caller": "run_queued_finalizer",
                "callee": "try_new_fence_retry_lifecycle",
            }
        ],
        "zeroRoster": list(TASK25_ZERO_ROSTER),
    }
    violations, _ = _fixture_gate(staged_lifecycle, staged_lifecycle_gate)
    check(
        task25_name,
        any("forbidden edge is present" in item for item in violations),
        "a finalizer edge into a staged lifecycle type must fail the Task 25 gate, got %r"
        % (violations,),
    )

    tracked = load_manifest(manifest_path)
    for gate_name in GATE_ORACLE_NAMES:
        oracle_errors = compare_gate_oracle(tracked, gate_name)
        check(
            gate_name,
            not oracle_errors,
            "Python/JSON oracle mismatch: %s" % "; ".join(oracle_errors),
        )

    r3_stage_clean = {
        "a.rs": (
            "pub fn production_root() { helper(); }\n"
            "fn helper() { let _ = 1; }\n"
            "fn acknowledge_completed_control() {}\n"
        )
    }
    r3_stage_gate = {
        "roots": ["production_root"],
        "stagedTargets": ["acknowledge_completed_control"],
    }
    violations, stats = _fixture_gate(r3_stage_clean, r3_stage_gate)
    check(
        "task09_11_r3_staging_is_production_unreachable",
        not violations,
        "R3 staging clean fixture must pass, got %r" % (violations,),
    )
    r3_stage_injected = {
        "a.rs": (
            "pub fn production_root() { acknowledge_completed_control(); }\n"
            "fn acknowledge_completed_control() {}\n"
        )
    }
    violations, _ = _fixture_gate(r3_stage_injected, r3_stage_gate)
    check(
        "task09_11_r3_staging_is_production_unreachable",
        any("acknowledge_completed_control is reachable" in item for item in violations),
        "primary R3 staged-route edge must fail, got %r" % (violations,),
    )

    r4_stage_clean = {
        "a.rs": (
            "pub fn production_root() { helper(); }\n"
            "fn helper() { let _ = 1; }\n"
            "fn initialize_staged_pending_slot() {}\n"
        )
    }
    r4_stage_gate = {
        "roots": ["production_root"],
        "stagedTargets": ["initialize_staged_pending_slot"],
    }
    violations, _ = _fixture_gate(r4_stage_clean, r4_stage_gate)
    check(
        "task13_18_r4_staging_is_production_unreachable",
        not violations,
        "R4 staging clean fixture must pass, got %r" % (violations,),
    )
    r4_stage_injected = {
        "a.rs": (
            "pub fn production_root() { initialize_staged_pending_slot(); }\n"
            "fn initialize_staged_pending_slot() {}\n"
        )
    }
    violations, _ = _fixture_gate(r4_stage_injected, r4_stage_gate)
    check(
        "task13_18_r4_staging_is_production_unreachable",
        any("initialize_staged_pending_slot is reachable" in item for item in violations),
        "primary R4 staged-route edge must fail, got %r" % (violations,),
    )

    r5_stage_clean = {
        "a.rs": (
            "pub fn production_root() { helper(); }\n"
            "fn helper() { let _ = 1; }\n"
            "fn execute_effect() {}\n"
        )
    }
    r5_stage_gate = {
        "roots": ["production_root"],
        "stagedTargets": ["execute_effect"],
    }
    violations, _ = _fixture_gate(r5_stage_clean, r5_stage_gate)
    check(
        "task20_24_r5_staging_is_production_unreachable",
        not violations,
        "R5 staging clean fixture must pass, got %r" % (violations,),
    )
    r5_stage_injected = {
        "a.rs": (
            "pub fn production_root() { execute_effect(); }\n"
            "fn execute_effect() {}\n"
        )
    }
    violations, _ = _fixture_gate(r5_stage_injected, r5_stage_gate)
    check(
        "task20_24_r5_staging_is_production_unreachable",
        any("execute_effect is reachable" in item for item in violations),
        "primary R5 staged-route edge must fail, got %r" % (violations,),
    )

    r3_cutover_ok = {
        "a.rs": (
            "pub fn production_root() { prepare_native_terminal_claim(); }\n"
            "fn prepare_native_terminal_claim() {}\n"
        )
    }
    r3_cutover_gate = {
        "roots": ["production_root"],
        "requiredReachable": ["prepare_native_terminal_claim"],
        "forbiddenSymbols": ["fence_bound_session"],
    }
    violations, stats = _fixture_gate(r3_cutover_ok, r3_cutover_gate)
    report = _canonical_report_from_stats(
        "task12_r3_cutover_has_exactly_one_terminal_delete_path", stats, violations
    )
    check(
        "task12_r3_cutover_has_exactly_one_terminal_delete_path",
        not violations and all(key in report for key in CANONICAL_GATE_OUTPUT_KEYS),
        "R3 cutover clean fixture must pass with canonical keys, got %r %r"
        % (violations, sorted(report)),
    )
    r3_cutover_dup = {
        "a.rs": (
            "pub fn production_root() { prepare_native_terminal_claim(); extra(); }\n"
            "fn extra() { prepare_native_terminal_claim(); }\n"
            "fn prepare_native_terminal_claim() {}\n"
        )
    }
    r3_cutover_sole = {
        "roots": ["production_root"],
        "requiredReachable": ["prepare_native_terminal_claim"],
        "requiredDirectEdges": [
            {
                "caller": {"source": "src/a.rs", "symbol": "production_root"},
                "callee": {"source": "src/a.rs", "symbol": "prepare_native_terminal_claim"},
                "exactCalls": 1,
                "soleCaller": True,
            }
        ],
    }
    violations, _ = _fixture_gate(r3_cutover_dup, r3_cutover_sole)
    check(
        "task12_r3_cutover_has_exactly_one_terminal_delete_path",
        any("sole direct caller" in item for item in violations),
        "duplicate predecessor edge must fail the R3 cutover gate, got %r" % (violations,),
    )

    r4_cutover_ok = {
        "a.rs": (
            "pub fn production_root() { initialize_staged_pending_slot(); }\n"
            "fn initialize_staged_pending_slot() {}\n"
        )
    }
    r4_cutover_gate = {
        "roots": ["production_root"],
        "requiredReachable": ["initialize_staged_pending_slot"],
        "forbiddenSymbols": list(TASK19_LEGACY_TOKENS),
    }
    violations, _ = _fixture_gate(r4_cutover_ok, r4_cutover_gate)
    check(
        "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path",
        not violations,
        "R4 cutover clean fixture must pass, got %r" % (violations,),
    )
    for token in TASK19_LEGACY_TOKENS:
        planted = {
            "a.rs": (
                "pub fn production_root() { initialize_staged_pending_slot(); %s(); }\n"
                "fn initialize_staged_pending_slot() {}\n"
                "fn %s() {}\n" % (token, token)
            )
        }
        violations, _ = _fixture_gate(planted, r4_cutover_gate)
        check(
            "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path",
            any(token in item for item in violations),
            "legacy Task 19 token %s must fail, got %r" % (token, violations),
        )
    r3_blocked = {
        "a.rs": (
            "pub fn production_root() { initialize_staged_pending_slot(); CheckpointTerminalBlockedR3(); }\n"
            "fn initialize_staged_pending_slot() {}\n"
            "fn CheckpointTerminalBlockedR3() {}\n"
        )
    }
    r4_cutover_blocked = dict(r4_cutover_gate)
    r4_cutover_blocked["forbiddenSymbols"] = list(TASK19_LEGACY_TOKENS) + [
        "CheckpointTerminalBlockedR3"
    ]
    violations, _ = _fixture_gate(r3_blocked, r4_cutover_blocked)
    check(
        "task19_r4_cutover_has_exactly_one_pending_terminal_delete_path",
        any("CheckpointTerminalBlockedR3" in item for item in violations),
        "R3 blocked variant must fail the R4 cutover gate, got %r" % (violations,),
    )

    violations, stats = _fixture_gate(clean_cutover, cutover_gate)
    report = _canonical_report_from_stats(TASK25_GATE, stats, violations)
    check(
        TASK25_GATE,
        not violations and all(key in report for key in CANONICAL_GATE_OUTPUT_KEYS),
        "Task 25 canonical report must contain %s, got %r"
        % (CANONICAL_GATE_OUTPUT_KEYS, sorted(report)),
    )
    check(
        TASK25_GATE,
        len(KERNEL_FENCE_NATIVE_FORWARDS) == 16,
        "Task 25 must freeze all 16 native KernelFenceOps forwards",
    )
    wildcard_gate = {
        "roots": ["production_root"],
        "stagedTargets": ["staged_*"],
    }
    try:
        _fixture_gate(clean, wildcard_gate)
        check(SELF_TESTS[0], False, "wildcard staged target must be refused")
    except AuditError as error:
        check(
            SELF_TESTS[0],
            "wildcard" in str(error).lower() or "pattern" in str(error).lower()
            or "staged targets are absent" in str(error),
            "wildcard refusal: %s" % error,
        )

    r3_pass = {
        "status": "PASS",
        "sourceIdentity": "SRC-R3",
        "manifestSha256": "MAN-R3",
    }
    r4_stage_pass = {
        "status": "PASS",
        "sourceIdentity": "SRC-R3",
        "manifestSha256": "MAN-R3",
    }
    try:
        construct_authority_absence("r3", r3_pass, [r4_stage_pass])
        check(
            "r3_authority_absence_revalidation_rejects_r4_production_edge",
            True,
            "",
        )
    except AuditError as error:
        check(
            "r3_authority_absence_revalidation_rejects_r4_production_edge",
            False,
            "matching R3 absence must construct: %s" % error,
        )
    try:
        construct_authority_absence(
            "r3", r3_pass, [r4_stage_pass], injected_edge="run_terminal -> initialize_staged_pending_slot"
        )
        check(
            "r3_authority_absence_revalidation_rejects_r4_production_edge",
            False,
            "R3 absence must refuse an R4 production edge",
        )
    except AuditError as error:
        check(
            "r3_authority_absence_revalidation_rejects_r4_production_edge",
            "initialize_staged_pending_slot" in str(error),
            "wrong R3/R4 edge refusal: %s" % error,
        )
    stale = dict(r3_pass, sourceIdentity="DIFFERENT")
    try:
        construct_authority_absence("r3", r3_pass, [dict(r4_stage_pass, sourceIdentity="DIFFERENT")])
        check(
            "r3_authority_absence_revalidation_rejects_r4_production_edge",
            False,
            "stale later identity must be refused",
        )
    except AuditError as error:
        check(
            "r3_authority_absence_revalidation_rejects_r4_production_edge",
            "same-artifact" in str(error),
            "wrong stale-identity refusal: %s" % error,
        )
    _ = stale

    r4_pass = {
        "status": "PASS",
        "sourceIdentity": "SRC-R4",
        "manifestSha256": "MAN-R4",
    }
    r5_stage_pass = {
        "status": "PASS",
        "sourceIdentity": "SRC-R4",
        "manifestSha256": "MAN-R4",
    }
    try:
        construct_authority_absence("r4", r4_pass, [r5_stage_pass])
        check(
            "r4_authority_absence_revalidation_rejects_r5_production_edge",
            True,
            "",
        )
    except AuditError as error:
        check(
            "r4_authority_absence_revalidation_rejects_r5_production_edge",
            False,
            "matching R4 absence must construct: %s" % error,
        )
    try:
        construct_authority_absence(
            "r4", r4_pass, [r5_stage_pass], injected_edge="run_terminal -> execute_effect"
        )
        check(
            "r4_authority_absence_revalidation_rejects_r5_production_edge",
            False,
            "R4 absence must refuse an R5 production edge",
        )
    except AuditError as error:
        check(
            "r4_authority_absence_revalidation_rejects_r5_production_edge",
            "execute_effect" in str(error),
            "wrong R4/R5 edge refusal: %s" % error,
        )

    missing_independent = [
        name for name in REQUIRED_INDEPENDENT_CASES if name not in reported_names
    ]
    for name in missing_independent:
        checks += 1
        failures.append("%s: independently reported case was not executed" % name)

    verdict = "PASS" if not failures else "FAIL"
    for failure in failures:
        sys.stdout.write("FAIL: %s\n" % failure)
    # Round-16 E7. Section 5 of the gate document says the two auditor-rejection
    # cases "must appear in every `--self-test` run", and this run did enforce it
    # -- `missing_independent` above fails when one is absent. But it printed
    # only a count, so the sealed evidence of row 33 named neither, and the only
    # thing binding them was `verify_spec.py` pinning their names against this
    # file's SOURCE: that proves the names are written here, not that the run
    # executed them. A reader of the attempt can see it now.
    for name in REQUIRED_INDEPENDENT_CASES:
        sys.stdout.write(
            "audit_c4_production_graph independent case: %s %s\n"
            % ("EXECUTED" if name in reported_names else "ABSENT", name)
        )
    sys.stdout.write("audit_c4_production_graph source gate: %s\n" % source_gate_status)
    sys.stdout.write(
        "audit_c4_production_graph self-test: %s (%d checks, %d failures)\n"
        % (verdict, checks, len(failures))
    )
    return 0 if not failures else 1


DEFAULT_SOURCE_ROOTS = ("driver/fsring-core/src", "driver/fsring-fsd/src")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--gate")
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--refresh-attestation",
        action="store_true",
        help="rerun the profile's closed rows and atomically replace the attestation",
    )
    parser.add_argument(
        "--verify-attestation",
        action="store_true",
        help="identity-only check for a production build; never runs cargo and never writes",
    )
    parser.add_argument(
        "--verify-current-attestation",
        action="store_true",
        help="recompute every row in memory and require byte equality; never writes",
    )
    parser.add_argument("--profile")
    args = parser.parse_args()

    root = repo_root()
    auditor_path = os.path.abspath(__file__)
    manifest_path = os.path.abspath(args.manifest)
    attestation_path = os.path.join(root, ATTESTATION_RELATIVE_PATH.replace("/", os.sep))
    source_roots = args.source_root or list(DEFAULT_SOURCE_ROOTS)

    if args.self_test:
        return self_test(manifest_path, auditor_path)

    modes = [
        args.refresh_attestation,
        args.verify_attestation,
        args.verify_current_attestation,
    ]
    if sum(1 for mode in modes if mode) > 1:
        sys.stderr.write("the attestation modes are mutually exclusive\n")
        return 2

    if args.refresh_attestation:
        if not args.profile:
            sys.stderr.write("--refresh-attestation requires --profile\n")
            return 2
        try:
            document = compute_attestation(
                root, manifest_path, auditor_path, args.profile, source_roots
            )
            write_attestation(attestation_path, document)
        except AuditError as error:
            sys.stderr.write("FAIL: %s\n" % error)
            return 1
        except OSError as error:
            sys.stderr.write("FAIL: attestation write failed: %s\n" % error)
            return 1
        sys.stdout.write(
            json.dumps(
                {
                    "mode": "refresh-attestation",
                    "profile": document["profile"],
                    "result": "PASS",
                    "rowCount": len(document["rows"]),
                    "sourceIdentity": document["sourceIdentity"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0

    if args.verify_attestation:
        try:
            document = verify_attestation_identity(
                root, manifest_path, auditor_path, attestation_path, source_roots
            )
            if args.profile and document["profile"] != args.profile:
                raise AuditError(
                    "attested profile %s is not the requested %s"
                    % (document["profile"], args.profile)
                )
        except AuditError as error:
            sys.stderr.write("FAIL: %s\n" % error)
            return 1
        sys.stdout.write(
            json.dumps(
                {
                    "mode": "verify-attestation",
                    "profile": document["profile"],
                    "result": "PASS",
                    "rowCount": len(document["rows"]),
                    "sourceIdentity": document["sourceIdentity"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0

    if args.verify_current_attestation:
        if not args.profile:
            sys.stderr.write("--verify-current-attestation requires --profile\n")
            return 2
        try:
            stored = load_attestation(attestation_path)
            recomputed = compute_attestation(
                root, manifest_path, auditor_path, args.profile, source_roots
            )
            if canonical_attestation_bytes(stored) != canonical_attestation_bytes(recomputed):
                raise AuditError("the recomputed attestation is not byte-identical")
        except AuditError as error:
            sys.stderr.write("FAIL: %s\n" % error)
            return 1
        sys.stdout.write(
            json.dumps(
                {
                    "mode": "verify-current-attestation",
                    "profile": args.profile,
                    "result": "PASS",
                    "rowCount": len(recomputed["rows"]),
                    "sourceIdentity": recomputed["sourceIdentity"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0

    if not args.gate:
        sys.stderr.write("a gate name is required outside --self-test\n")
        return 2
    if not args.source_root:
        sys.stderr.write("at least one --source-root is required\n")
        return 2

    try:
        report, violations = run_gate(
            root, manifest_path, args.gate, args.source_root, auditor_path
        )
    except AuditError as error:
        sys.stderr.write("FAIL: %s\n" % error)
        return 1
    emit(report)
    for violation in violations:
        sys.stderr.write("FAIL: %s\n" % violation)
    return 0 if not violations else 1


def main_under_marker():
    """`main` with the PRE/POST marker pair around it.

    POST is in a `finally` so a refusal still reports what was launched before
    it; a row that emitted only PRE is a runner refusal rather than a silent
    half-observation."""
    c4_emit_marker("PRE")
    try:
        return main()
    finally:
        c4_emit_marker("POST")


if __name__ == "__main__":
    raise SystemExit(main_under_marker())
