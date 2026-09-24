#!/usr/bin/env python
"""Deterministic source audit for locator-only session publication.

Task 8 established the rule this enforces: a published session is reached by
`SessionLocator` plus a live access rundown, never by a stored pointer. A raw
`*mut NativeSession`, a `NonNull<NativeSession>`, or an `AtomicPtr` to one, held
in a *long-lived* structure, is the defect — because the structure outlives the
generation the pointer names, and the next reader dereferences a session that was
freed and whose slot has been reused.

The audit is deliberately narrow, and the boundary is stated rather than implied:

* The carrier rule looks at **struct fields**. Native capability checks also
  freeze protected APIs and each balanced function body that owns a registry
  projection, so a local pointer is allowed only in its reviewed lock grammar.
* It looks at the long-lived carriers Task 8 named: the control binding, the
  registry entry/cell, the volume device extension, and the mounted-volume
  extension. A missing named carrier or production owner is an audit finding.
* It reads production source only: `#[cfg(test)]` blocks, comments, and string
  literals are stripped, so prose describing the retired pointer is not a hit.

Exit 0 on a clean tree, 1 on a violation, 2 on a usage error.
"""

import argparse
import collections
import concurrent.futures
import functools
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata

NEWLINE = chr(10)

# The long-lived carriers whose fields must be locator-only. Each entry is the
# Rust struct name and a one-line statement of what outliving what makes a
# stored pointer wrong there.
CARRIERS = {
    "ControlFileContext": "a control file outlives every session it sets up",
    "RegistrySlot": "a slot is reused by the next generation",
    "VolumeExtension": "a VDO outlives the mount that created it",
    "MountedVolumeExtension": "a mounted VDO outlives its session",
    "NativeSessionCell": "a permanent cell outlives every generation in it",
}

# Production carriers are a closed field grammar, not merely a ban list.  A
# pointer hidden behind a newtype/enum would evade spelling-based pointer
# detection, while any extra field would create new long-lived authority.
CARRIER_BODIES = {
    (
        "driver/fsring-fsd/src/control.rs",
        "ControlFileContext",
    ): "rundown:MaybeUninit<EX_RUNDOWN_REF>,requestor:AtomicPtr<c_void>,binding_phase_tag:AtomicU32,binding:UnsafeCell<ControlBinding>,lifetime:UnsafeCell<ControlContextLifetime>,setup_cancel:MaybeUninit<KEVENT>,setup_complete:MaybeUninit<KEVENT>,",
    (
        "driver/fsring-core/src/session.rs",
        "RegistrySlot",
    ): "generation:u64,identity:Option<SessionIdentity>,state:RegistrySlotState,strong_count:u32,fence_done:bool,",
    (
        "driver/fsring-fsd/src/volume.rs",
        "VolumeExtension",
    ): "pub(crate)header:ExtensionHeader,locator:UnsafeCell<MaybeUninit<SessionLocator>>,locator_state:AtomicU32,pub(crate)mount_lo:u64,pub(crate)mount_hi:u64,",
    (
        "driver/fsring-fsd/src/volume.rs",
        "MountedVolumeExtension",
    ): "pub(crate)header:ExtensionHeader,pub(crate)locator:SessionLocator,pub(crate)vdo:PDEVICE_OBJECT,pub(crate)vcb:MaybeUninit<VolumeControlBlock>,",
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "NativeSessionCell",
    ): "access:EX_RUNDOWN_REF,terminal_outcome:KEVENT,joiners_drained:KEVENT,visibility_resolution:KEVENT,mount_complete:KEVENT,mount_waiters_drained:KEVENT,mount_reset_complete:KEVENT,mount_reset_waiters_drained:KEVENT,generation:u64,identity:Option<SessionIdentity>,phase:NativeCellPhase,session:*mutNativeSession,process:PEPROCESS,registry_lease:Option<RegistryLease>,control_owner:Option<ControlOwner>,recorded_control_context:Option<NonNull<ControlFileContext>>,shell_owner:Option<NativeSessionOwner>,root_release:Option<SessionRootReleaseRight>,mount_rendezvous:NativeMountRendezvous,terminal_rendezvous:TerminalRendezvous,process_loss_handled:bool,checkpoint_readiness:Option<crate::fence::FenceDeletionReadiness>,pending_runtime:Option<crate::pending_enter::PendingRuntimeReady>,pending_ledger:Option<fsring_core::session::PendingControlLedger<{crate::session::MAX_PENDING_LINKS}>>,fail_stop:crate::fence::R3FailStopSlot,finalizer_handoff:Option<FinalizerVisibilityHandoff>,finalizer:fsring_core::adapter::fence::R3FinalizerCell<crate::fence::R4DeletionOwners>,finalizer_context:FinalizerWorkItemContext,finalizer_work_item:PIO_WORKITEM,finalizer_callback_admitted:Option<FinalizerCallbackAdmission>,fence_retry_timer:MaybeUninit<KTIMER>,fence_retry_dpc:MaybeUninit<KDPC>,fence_retry_dpc_exit:MaybeUninit<KEVENT>,fence_retry_work_item:PIO_WORKITEM,fence_retry_park:Option<crate::fence::ParkedFenceResidual>,",
}

NATIVE_OWNER_FILES = {
    "driver/fsring-fsd/src/lifecycle.rs",
    "driver/fsring-fsd/src/session.rs",
    "driver/fsring-fsd/src/volume.rs",
}

# Files whose evidence counts toward the production-check total, which is a
# larger set than the native owner files above. Membership in
# `NATIVE_OWNER_FILES` means "this file's whole native lifetime contract --
# type declarations, method rosters, body digests -- is frozen"; that is not
# yet true of `pending_enter.rs`, which Tasks 18 and 19 reshape. What IS frozen
# about it is its one staged struct shape, and that evidence should still be
# counted rather than reported as vacuous.
COUNTED_EVIDENCE_FILES = NATIVE_OWNER_FILES | {
    "driver/fsring-fsd/src/pending_enter.rs",
    # The three files the round-11 SDDL high reaches. Their rules run whether
    # or not they are listed here -- a finding from an uncounted file still
    # fails the audit -- but leaving them out understated the evidence total,
    # and the total is what the self-test reads to prove this mode is not
    # vacuous. A check that can fail and is not counted is exactly the kind of
    # silent, uncounted guard this project keeps being burned by.
    "driver/fsring-fsd/src/kernel.rs",
    "driver/fsring-fsd/src/control.rs",
    "driver/fsring-fsd/src/fscontrol.rs",
    # Round-12 M1, found by review: 475 labels were being emitted and 473
    # counted, and the two that fell out were `fence.rs`'s -- while the comment
    # directly above argued that an uncounted check is the hazard. Counting
    # them makes the argument and the set agree; every file this function
    # emits a label for is now counted, so the total and the evidence are the
    # same measurement.
    "driver/fsring-fsd/src/fence.rs",
    # The one core file carrying a native contract. `begin_native_worker_pass`
    # is the frame BELOW `begin_pass`, and its refusals are part of the same
    # decision, so its check is counted for the same reason as the rest.
    "driver/fsring-core/src/enter.rs",
    # Round 15: `driver.rs` emits a label now (the provider-device publish
    # order), and a check that can fail while going uncounted is the exact
    # hazard the note above argues against.
    "driver/fsring-fsd/src/driver.rs",
}

# Staged R4 shapes whose field grammar is frozen, but which are NOT
# locator-only carriers: `PendingEnterContext` stores the parked `PIRP` on
# purpose, so it cannot join `CARRIERS` without either failing its pointer rule
# or being granted a mirror exception that would weaken that rule for everyone.
#
# What this freezes instead is the exact field list. That is what makes
# `pending_context_contains_no_inline_result_storage` a structural refusal
# rather than a size bound: the Rust-side `size_of <= 1024` assertion would
# happily accept an inline `[u8; 512]` result buffer, while an added,
# retyped, reordered or removed field fails here.
PENDING_SHAPE_BODIES = {
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "PendingEnterContext",
    ): "csq:IO_CSQ,csq_irp_context:IO_CSQ_IRP_CONTEXT,lock:KSPIN_LOCK,slot_state:PendingSlotState,install_axis:Option<InstallAxis>,irp_axis:Option<IrpAxis>,irp:PIRP,control_context:*mutc_void,timer:KTIMER,dpc:KDPC,dpc_exited:KEVENT,result_view:*mutu8,work_item:PIO_WORKITEM,publication_fail_stop:Option<PublicationFailStop>,runtime:Option<PendingSlotRuntime>,timer_state:TimerState,dpc_entered:bool,observed_generation:u64,",
}

# Every lowercase `resolve` token in the production fsd source has one exact
# role. This closes acquisitions in modules that do not otherwise own a native
# lifetime contract, and also rejects UFCS/function-item/macro aliases because
# they necessarily add or move a `resolve` token outside these exact contexts.
FSD_RESOLVE_CONTEXTS = {
    "driver/fsring-fsd/src/boot.rs": (),
    # Round 21: CLEANUP reads its expansion through `resolve_cleanup`, which is
    # not a `resolve` token, so this file holds none. SETUP's reading in
    # `session.rs` is the one `stackexpand::resolve` left.
    "driver/fsring-fsd/src/control.rs": (),
    "driver/fsring-fsd/src/driver.rs": (),
    "driver/fsring-fsd/src/fence.rs": (),
    "driver/fsring-fsd/src/fscontrol.rs": (),
    "driver/fsring-fsd/src/kernel.rs": (),
    "driver/fsring-fsd/src/lib.rs": (),
    "driver/fsring-fsd/src/lifecycle.rs": ("pub(crate)unsafefnresolve(",),
    # Task 17's staged CSQ slots. The empty tuple is load-bearing: this module
    # resolves nothing and observes no live-cell mirror, and the census is what
    # keeps that true as Tasks 18 and 19 grow it.
    "driver/fsring-fsd/src/pending_enter.rs": (),
    "driver/fsring-fsd/src/platform.rs": (),
    "driver/fsring-fsd/src/seh.rs": (),
    "driver/fsring-fsd/src/session.rs": (
        "fsring_core::adapter::stackexpand::resolve(",
        "registry.as_ref().resolve(locator)",
    ),
    "driver/fsring-fsd/src/trace.rs": (),
    "driver/fsring-fsd/src/volume.rs": ("registry.as_ref().resolve(locator)",),
}

# The fsd-wide native capability census complements the lowercase `resolve`
# roster. These names are the only routes that may observe the permanent cell
# mirror: one pointer-free predicate, one typed resolver projection, and the
# one affine Task 12 terminal exception.
FSD_NATIVE_CAPABILITY_REFERENCES = {
    "driver/fsring-fsd/src/boot.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/control.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/driver.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/fence.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 1,
        "shell_owner": 1,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/fscontrol.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/kernel.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/lib.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/lifecycle.rs": {
        "matches_live_locator": 4,
        "project_resolved_session": 2,
        "into_checkpoint_parts": 1,
        "shell_owner": 27,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/pending_enter.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/platform.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/seh.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/session.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/trace.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
    "driver/fsring-fsd/src/volume.rs": {
        "matches_live_locator": 0,
        "project_resolved_session": 0,
        "into_checkpoint_parts": 0,
        "shell_owner": 0,
        "execute_checkpoint_effect": 0,
        "live_session": 0,
        "mirror_session_ptr": 0,
    },
}

# Exact owner/call roster for the registry guard's reusable projections. The
# permanent cell has intentional Task 12 uses outside lifecycle.rs, including
# four event callbacks that run after unlocking, so the raw primitive cannot be
# banned outright. Instead every reference and every owning function is closed
# across the canonical 14-file fsd tree. A new helper, UFCS call, function item,
# or retained-after-unlock path necessarily changes this roster.
REGISTRY_PROJECTION_NAMES = ("cell_ptr", "cell_mut", "core_ptr", "core_mut")
FSD_REGISTRY_PROJECTION_OWNERS = {
    "driver/fsring-fsd/src/boot.rs": (),
    "driver/fsring-fsd/src/control.rs": (),
    "driver/fsring-fsd/src/driver.rs": (),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "cell_finish_preflight",
            1,
            0,
            0,
            0,
        ),
        (
            "release_strong_and_deposit",
            1,
            0,
            1,
            0,
        ),
        (
            "prepare_final_delete",
            0,
            0,
            1,
            0,
        ),
        (
            "observe_delete_preflight",
            1,
            0,
            0,
            0,
        ),
        (
            "session_ptr",
            1,
            0,
            0,
            0,
        ),
        (
            "pending_runtime_ptr",
            1,
            0,
            0,
            0,
        ),
        (
            "wait_until_mount_drained",
            1,
            0,
            0,
            0,
        ),
        (
            "complete_mount_owner",
            3,
            0,
            0,
            0,
        ),
        (
            "complete_mount_reset_join",
            2,
            0,
            0,
            0,
        ),
        (
            "complete_mount_join",
            1,
            0,
            0,
            0,
        ),
        (
            "dismount_and_delete_devices",
            1,
            0,
            0,
            0,
        ),
        (
            "verify_session_and_root_ledgers",
            1,
            0,
            0,
            0,
        ),
        (
            "has_only_terminal_strong_owner",
            0,
            0,
            0,
            1,
        ),
        (
            "close_session_admission",
            1,
            0,
            0,
            0,
        ),
        (
            "release_transient_arrays_and_backing",
            1,
            0,
            0,
            0,
        ),
        (
            "run_terminal_for_process",
            1,
            0,
            0,
            0,
        ),
        (
            "run_queued_finalizer",
            1,
            0,
            0,
            0,
        ),
        (
            "store_fail_stop_locked",
            1,
            0,
            0,
            0,
        ),
        (
            "run_kernel_fence",
            1,
            0,
            0,
            0,
        ),
        (
            "park_and_arm_fence_retry",
            3,
            0,
            0,
            0,
        ),
        (
            "run_terminal",
            2,
            0,
            0,
            0,
        ),
    ),
    "driver/fsring-fsd/src/fscontrol.rs": (),
    "driver/fsring-fsd/src/kernel.rs": (),
    "driver/fsring-fsd/src/lib.rs": (),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "close_global_admissions",
            0,
            0,
            0,
            1,
        ),
        (
            "observe_r3_finalizer_for_drain",
            1,
            0,
            0,
            0,
        ),
        (
            "acknowledge_r3_finalizer_after_rundown",
            1,
            0,
            0,
            0,
        ),
        (
            "cell_mut",
            1,
            0,
            0,
            0,
        ),
        (
            "project_resolved_session",
            0,
            1,
            0,
            0,
        ),
        (
            "prepare_native_terminal_claim",
            1,
            0,
            1,
            0,
        ),
        (
            "claim_committed_protocol",
            1,
            0,
            1,
            0,
        ),
        (
            "queue_cell_finalizer",
            1,
            0,
            0,
            0,
        ),
        (
            "fsring_finalizer_callback",
            2,
            0,
            0,
            0,
        ),
        (
            "reset_cell_and_publish",
            0,
            0,
            1,
            0,
        ),
        (
            "wait_mount_observation",
            1,
            0,
            0,
            0,
        ),
        (
            "prepare_locked_mount_publication",
            1,
            0,
            0,
            0,
        ),
        (
            "resolve",
            0,
            2,
            0,
            1,
        ),
        (
            "observe_r3_unload_cell",
            1,
            0,
            0,
            0,
        ),
        (
            "observe_r3_unload_preflight",
            0,
            0,
            0,
            1,
        ),
        (
            "scan_one_cell_for_process",
            1,
            0,
            0,
            0,
        ),
        (
            "park_wait_enter",
            0,
            1,
            0,
            0,
        ),
        (
            "wake_ready_parked_waits",
            0,
            1,
            0,
            0,
        ),
        (
            "store_parked_wait",
            0,
            1,
            0,
            0,
        ),
        (
            "acquire_parked_strong_refs",
            0,
            1,
            0,
            2,
        ),
        (
            "release_parked_strong_refs",
            0,
            1,
            0,
            1,
        ),
    ),
    "driver/fsring-fsd/src/pending_enter.rs": (
        (
            "release_parked_strong_refs",
            0,
            0,
            0,
            1,
        ),
    ),
    "driver/fsring-fsd/src/platform.rs": (),
    "driver/fsring-fsd/src/seh.rs": (),
    "driver/fsring-fsd/src/session.rs": (
        (
            "install_staging",
            1,
            0,
            1,
            0,
        ),
        (
            "publish_locked_suffix",
            1,
            0,
            2,
            0,
        ),
        (
            "prepare_setup_rollback",
            1,
            0,
            1,
            0,
        ),
        (
            "commit_setup_rollback",
            1,
            0,
            1,
            0,
        ),
    ),
    "driver/fsring-fsd/src/trace.rs": (),
    "driver/fsring-fsd/src/volume.rs": (
        (
            "perform_mount",
            1,
            0,
            0,
            1,
        ),
        (
            "expose_published_mount",
            1,
            0,
            0,
            0,
        ),
    ),
}
FSD_REGISTRY_PROJECTION_OWNERS.update(
    {
        "driver/fsring-fsd/src/boot.rs": (),
        "driver/fsring-fsd/src/control.rs": (),
        "driver/fsring-fsd/src/driver.rs": (),
        "driver/fsring-fsd/src/fence.rs": (
            (
                "cell_finish_preflight",
                1,
                0,
                0,
                0,
            ),
            (
                "release_strong_and_deposit",
                1,
                0,
                1,
                0,
            ),
            (
                "prepare_final_delete",
                0,
                0,
                1,
                0,
            ),
            (
                "observe_delete_preflight",
                1,
                0,
                0,
                0,
            ),
            (
                "session_ptr",
                1,
                0,
                0,
                0,
            ),
            (
                "pending_runtime_ptr",
                1,
                0,
                0,
                0,
            ),
            (
                "wait_until_mount_drained",
                1,
                0,
                0,
                0,
            ),
            (
                "complete_mount_owner",
                3,
                0,
                0,
                0,
            ),
            (
                "complete_mount_reset_join",
                2,
                0,
                0,
                0,
            ),
            (
                "complete_mount_join",
                1,
                0,
                0,
                0,
            ),
            (
                "dismount_and_delete_devices",
                1,
                0,
                0,
                0,
            ),
            (
                "verify_session_and_root_ledgers",
                1,
                0,
                0,
                0,
            ),
            (
                "has_only_terminal_strong_owner",
                0,
                0,
                0,
                1,
            ),
            (
                "close_session_admission",
                1,
                0,
                0,
                0,
            ),
            (
                "release_transient_arrays_and_backing",
                1,
                0,
                0,
                0,
            ),
            (
                "run_terminal_for_process",
                1,
                0,
                0,
                0,
            ),
            (
                "run_queued_finalizer",
                1,
                0,
                0,
                0,
            ),
            (
                "store_fail_stop_locked",
                1,
                0,
                0,
                0,
            ),
            (
                "run_kernel_fence",
                1,
                0,
                0,
                0,
            ),
            (
                "park_and_arm_fence_retry",
                3,
                0,
                0,
                0,
            ),
            (
                "run_terminal",
                2,
                0,
                0,
                0,
            ),
        ),
        "driver/fsring-fsd/src/fscontrol.rs": (),
        "driver/fsring-fsd/src/kernel.rs": (),
        "driver/fsring-fsd/src/lib.rs": (),
        "driver/fsring-fsd/src/lifecycle.rs": (
            (
                "close_global_admissions",
                0,
                0,
                0,
                1,
            ),
            (
                "observe_r3_finalizer_for_drain",
                1,
                0,
                0,
                0,
            ),
            (
                "acknowledge_r3_finalizer_after_rundown",
                1,
                0,
                0,
                0,
            ),
            (
                "cell_mut",
                1,
                0,
                0,
                0,
            ),
            (
                "project_resolved_session",
                0,
                1,
                0,
                0,
            ),
            (
                "prepare_native_terminal_claim",
                1,
                0,
                1,
                0,
            ),
            (
                "claim_committed_protocol",
                1,
                0,
                1,
                0,
            ),
            (
                "queue_cell_finalizer",
                1,
                0,
                0,
                0,
            ),
            (
                "fsring_finalizer_callback",
                2,
                0,
                0,
                0,
            ),
            (
                "reset_cell_and_publish",
                0,
                0,
                1,
                0,
            ),
            (
                "wait_mount_observation",
                1,
                0,
                0,
                0,
            ),
            (
                "prepare_locked_mount_publication",
                1,
                0,
                0,
                0,
            ),
            (
                "resolve",
                0,
                2,
                0,
                1,
            ),
            (
                "observe_r3_unload_cell",
                1,
                0,
                0,
                0,
            ),
            (
                "observe_r3_unload_preflight",
                0,
                0,
                0,
                1,
            ),
            (
                "scan_one_cell_for_process",
                1,
                0,
                0,
                0,
            ),
            (
                "park_wait_enter",
                0,
                1,
                0,
                0,
            ),
            (
                "wake_ready_parked_waits",
                0,
                1,
                0,
                0,
            ),
            (
                "store_parked_wait",
                0,
                1,
                0,
                0,
            ),
            (
                # The abandon path a refused store reaches: one `cell_mut`
                # projection to find the pending runtime it must fail through.
                "fail_unstored_parked_wait",
                0,
                1,
                0,
                0,
            ),
            (
                "acquire_parked_strong_refs",
                0,
                1,
                0,
                2,
            ),
            (
                "release_parked_strong_refs",
                0,
                1,
                0,
                1,
            ),
        ),
        "driver/fsring-fsd/src/pending_enter.rs": (
            (
                "unlink_parked_control_link",
                0,
                1,
                0,
                0,
            ),
            (
                "link_parked_control",
                0,
                1,
                0,
                0,
            ),
            (
                "release_parked_strong_refs",
                0,
                0,
                0,
                1,
            ),
        ),
        "driver/fsring-fsd/src/platform.rs": (),
        "driver/fsring-fsd/src/seh.rs": (),
        "driver/fsring-fsd/src/session.rs": (
            (
                "install_staging",
                1,
                0,
                1,
                0,
            ),
            (
                "publish_locked_suffix",
                1,
                0,
                2,
                0,
            ),
            (
                "prepare_setup_rollback",
                1,
                0,
                1,
                0,
            ),
            (
                "commit_setup_rollback",
                1,
                0,
                1,
                0,
            ),
        ),
        "driver/fsring-fsd/src/trace.rs": (),
        "driver/fsring-fsd/src/volume.rs": (
            (
                "perform_mount",
                1,
                0,
                0,
                1,
            ),
            (
                "expose_published_mount",
                1,
                0,
                0,
                0,
            ),
        ),
    }
)

# `function_items` brace-matches each owner before whitespace normalization.
# Freezing the complete non-comment body, rather than aggregate token counts,
# rejects every residual alias, wrapper, cast, helper/macro call, or reordered
# unlock/dereference statement in a raw-projection scope.
FSD_REGISTRY_PROJECTION_FUNCTION_BODIES = {
    "driver/fsring-fsd/src/boot.rs": (),
    "driver/fsring-fsd/src/control.rs": (),
    "driver/fsring-fsd/src/driver.rs": (),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "cell_finish_preflight",
            "letSome(cell)=(unsafe{lock.cell_ptr(locator.slot_index())})else{returnErr(LifecycleError::WrongLocator);};unsafe{(*cell).checkpoint_finish_preflight(locator)}",
        ),
        (
            "observe_delete_preflight",
            "letcell=unsafe{lock.cell_ptr(locator.slot_index())}?;Some(unsafe{(*cell).delete_preflight_observation(locator)})",
        ),
        (
            "session_ptr",
            "letmutlock=unsafe{KernelSessionRegistry::lock(self.registry)};letsession=matchunsafe{lock.cell_ptr(self.locator.slot_index())}{Some(cell)=>unsafe{(*cell).session_mirror()},None=>core::ptr::null_mut(),};unsafe{lock.release()};session",
        ),
        (
            "pending_runtime_ptr",
            "letmutlock=unsafe{KernelSessionRegistry::lock(self.registry)};letruntime=matchunsafe{lock.cell_ptr(self.locator.slot_index())}{Some(cell)=>unsafe{(*cell).pending_runtime()}.map_or(core::ptr::null(),|runtime|runtimeas*const_),None=>core::ptr::null(),};unsafe{lock.release()};runtime",
        ),
        (
            "verify_session_and_root_ledgers",
            "letmutlock=unsafe{KernelSessionRegistry::lock(self.registry)};letcell=unsafe{lock.cell_ptr(self.locator.slot_index())};letverdict=matchcell{Some(cell)=>unsafe{(*cell).checkpoint_ledger_is_discharged(self.locator)},None=>false,};unsafe{lock.release()};verdict",
        ),
        (
            "has_only_terminal_strong_owner",
            "letmutlock=unsafe{KernelSessionRegistry::lock(self.registry)};letverdict=unsafe{lock.core_mut().r3_checkpoint_has_only_terminal_strong_owner(self.locator)};unsafe{lock.release()};verdict",
        ),
        (
            "close_session_admission",
            "letmutlock=unsafe{KernelSessionRegistry::lock(self.registry)};ifletSome(cell)=unsafe{lock.cell_ptr(self.locator.slot_index())}{unsafe{(*cell).close_pending_admission()};}unsafe{lock.release()};self.shell.checkpoint_close_session_admission()",
        ),
        (
            "release_transient_arrays_and_backing",
            "letmutlock=unsafe{KernelSessionRegistry::lock(self.registry)};letruntime=matchunsafe{lock.cell_ptr(self.locator.slot_index())}{Some(cell)=>unsafe{(*cell).take_pending_runtime()},None=>None,};unsafe{lock.release()};ifletSome(runtime)=runtime{unsafe{runtime.release_pending_runtime(&mutcrate::pending_enter::NativePendingRuntimeDdi)};}self.shell.checkpoint_release_transient_arrays_and_backing()",
        ),
        (
            "run_terminal_for_process",
            "letmutlock=unsafe{KernelSessionRegistry::lock(registry)};letcontext=matchunsafe{lock.cell_ptr(locator.slot_index())}{Some(cell)=>unsafe{(*cell).recorded_control_context()},None=>None,};letclaimed=matchcontext{Some(context)=>{matchunsafe{prepare_native_terminal_claim(&mutlock,context,locator,TerminalRequest::ProcessLoss,)}{Ok(prepared)=>Some((context,unsafe{prepared.commit()})),Err(_)=>None,}}None=>None,};unsafe{lock.release()};letSome((context,disposition))=claimedelse{returnfalse;};let_outcome=unsafe{run_terminal_from_disposition(registry,context,disposition)};true",
        ),
        (
            "run_kernel_fence",
            "letlocator=owners.locator();letsession={letmutlock=unsafe{KernelSessionRegistry::lock(registry)};letsession=matchunsafe{lock.cell_ptr(locator.slot_index())}{Some(cell)=>unsafe{(*cell).session_mirror()},None=>core::ptr::null_mut(),};unsafe{lock.release()};session};ifsession.is_null(){returnKernelFencePassOutcome::FailStop(incomplete_from_missing_session(owners,control));}letSome(set)=(unsafe{(*session).ring_set()})else{returnKernelFencePassOutcome::FailStop(incomplete_from_missing_session(owners,control));};let(mutlifecycle,initial)=matchfsring_core::adapter::fence::FenceRetryLifecycle::try_new_fence_retry_lifecycle(locator,){Ok(pair)=>pair,Err(_)=>{returnKernelFencePassOutcome::FailStop(incomplete_from_missing_session(owners,control,));}};let_prepare_complete=fsring_core::adapter::fence::FenceRetryLifecycle::prepare_complete;let_commit_retry=fsring_core::adapter::fence::PreparedFenceRetryComplete::commit_retry_complete;let_begin_run=fsring_core::adapter::fence::FenceRetryLifecycle::begin_fence_retry_run;letddi=unsafe{NativeFenceDdi::new(registry,owners.shell_owner(),context,control,set,None)};letoutcome=matchKernelFenceOps::try_new(ddi,set){Ok(ops)=>ops.finish(),Err(failure)=>{let(ddi,incomplete)=failure.into_start_failure_parts();FenceRunOutcome::Residual{ddi,incomplete}}};matchoutcome{FenceRunOutcome::Complete{mutddi,completed}=>{letreleased_control=ddi.take_unreleased_control();ifletSome(control)=released_control{letmutlock=unsafe{KernelSessionRegistry::lock(registry)};let_=unsafe{release_strong_and_deposit(&mutlock,R4ReleaseAuthority::Stable(control.into_reference()),None,)};unsafe{lock.release()};}let_=ddi;let(winner,terminal,closing,shell,root)=owners.into_parts();letreason=winner.reason();letresult=fsring_core::session::TerminalResult{reason,fence_failures:completed.report().failed_mask(),};letauthenticated=matchAuthenticatedTerminalResult::new(winner,result){Ok(authenticated)=>authenticated,Err(_)=>{unreachable!()}};letaccumulated=fsring_core::adapter::fence::begin_accumulated_terminal_result(authenticated);letprepared=matchfsring_core::adapter::fence::prepare_terminal_winner_finalize(accumulated,completed,){Ok(prepared)=>prepared,Err(_failed)=>{returnKernelFencePassOutcome::FailStop(incomplete_from_missing_session_parts(terminal,closing,shell,root),);}};{letobservation=prepared.completion_observation();matchlifecycle.prepare_initial_complete(initial,observation){Ok(ready)=>ready.commit_initial_complete(),Err(_refused)=>{returnKernelFencePassOutcome::FailStop(incomplete_from_missing_session_parts(terminal,closing,shell,root),);}}}letcompleted_result=prepared.commit();KernelFencePassOutcome::Complete(R4CheckpointCandidate{complete:completed_result,terminal,closing,shell,root,})}FenceRunOutcome::Residual{mutddi,incomplete,}=>{letcontrol=ddi.take_unreleased_control();let_=ddi;let(winner,terminal,closing,shell,root)=owners.into_parts();letreason=winner.reason();letresult=fsring_core::session::TerminalResult{reason,fence_failures:incomplete.report().failed_mask(),};letauthenticated=matchAuthenticatedTerminalResult::new(winner,result){Ok(authenticated)=>authenticated,Err(_)=>{unreachable!()}};let(_report,residual,needed)=incomplete.into_residual_run_parts();matchlifecycle.prepare_fence_retry(initial,needed){Ok(fsring_core::adapter::fence::FenceRetryDisposition::Delay(delay))=>{park_and_arm_fence_retry(registry,residual,delay,lifecycle,terminal,authenticated,closing,control,shell,root,)}Ok(fsring_core::adapter::fence::FenceRetryDisposition::FailStop(_right))=>{KernelFencePassOutcome::FailStop(FenceIncompletePacket{progress:FenceIncompletePacketProgress::Residual{residual,control},terminal,result:authenticated,closing,shell,root,})}Err(_refused)=>KernelFencePassOutcome::FailStop(FenceIncompletePacket{progress:FenceIncompletePacketProgress::Residual{residual,control},terminal,result:authenticated,closing,shell,root,}),}}}",
        ),
        (
            "park_and_arm_fence_retry",
            "letlocator=terminal.locator();letdue=delay.due_time_100ns();letmutlock=unsafe{KernelSessionRegistry::lock(registry)};ifletSome(cell)=unsafe{lock.cell_ptr(locator.slot_index())}{unsafe{(*cell).park_fence_retry(ParkedFenceResidual{residual,delay:Some(delay),queued:None,lifecycle,terminal,result,closing,control,shell,root,});}}lettimer=unsafe{lock.cell_ptr(locator.slot_index()).map(|cell|(*cell).fence_retry_timer_ptr())};letdpc=unsafe{lock.cell_ptr(locator.slot_index()).map(|cell|(*cell).fence_retry_dpc_ptr())};unsafe{lock.release()};iflet(Some(timer),Some(dpc))=(timer,dpc){letdue_time=wdk_sys::LARGE_INTEGER{QuadPart:due};unsafe{let_=fsring_sys::c4::KeSetTimer(timer,due_time,dpc);}let_=due_time;}KernelFencePassOutcome::RetryQueued",
        ),
    ),
    "driver/fsring-fsd/src/fscontrol.rs": (),
    "driver/fsring-fsd/src/kernel.rs": (),
    "driver/fsring-fsd/src/lib.rs": (),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "cell_mut",
            "unsafe{self.cell_ptr(index)}.map(|cell|unsafe{&mut*cell})",
        ),
        (
            "project_resolved_session",
            "letcell=unsafe{self.cell_mut(index)}?;if!cell.matches_live_locator(locator){returnNone;}Some(unsafe{SharedSessionProjection::from_non_null(NonNull::new(cell.session)?)})",
        ),
        (
            "claim_committed_protocol",
            "letlocator=committed.authenticated_locator();letregistry=unsafe{NonNull::new_unchecked((selfas*constSelf).cast_mut())};letmutlock=unsafe{KernelSessionRegistry::lock(registry)};letSome(cell)=(unsafe{lock.cell_ptr(locator.slot_index())})else{unsafe{lock.release()};unreachable!();};letSome(context)=(unsafe{(*cell).recorded_control_context()})else{unsafe{lock.release()};unreachable!();};letcore=unsafe{lock.core_ptr()};letNativeSessionCell{phase,control_owner,shell_owner,root_release,terminal_rendezvous,registry_lease,..}=unsafe{&mut*cell};letbinding=unsafe{crate::control::binding_mut(context)};letprepared=fsring_core::adapter::lifecycle::prepare_protocol_terminal_claim(unsafe{&mut*core},binding,terminal_rendezvous,registry_lease,committed,);letdisposition=prepared.commit_protocol_claim();letresult=matchdisposition{fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Winner{work,join,}=>{let(winner,terminal)=work.into_terminal_authorities();letmutcell_claim=PreparedNativeCellClaim{phase,control_owner,shell_owner,root_release,};let(owner,shell,root)=cell_claim.take_winner_owners();let(control,closing)=owner.split();*cell_claim.phase=NativeCellPhase::Removing;NativeProtocolTerminalDisposition::Terminal(TerminalDisposition::Winner{work:TerminalWork{locator,winner,terminal,control,closing,shell,root,},join:TerminalJoinGuard{registry,locator,ticket:NativeTerminalJoinAuthority::Protocol(join),},})}fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Join(join)=>{NativeProtocolTerminalDisposition::Terminal(TerminalDisposition::Join(TerminalJoinGuard{registry,locator,ticket:NativeTerminalJoinAuthority::Protocol(join),},))}fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Completed(completed,)=>NativeProtocolTerminalDisposition::Terminal(TerminalDisposition::Completed(completed.into_result(),)),fsring_core::adapter::lifecycle::CommittedProtocolTerminalDisposition::Reject(receipt,)=>NativeProtocolTerminalDisposition::Reject(receipt),};unsafe{lock.release()};result",
        ),
        (
            "resolve",
            "letslot_index=locator.slot_index();letmutrundown:Option<*mutEX_RUNDOWN_REF>=None;letmutlock:Option<RegistryLockGuard>=None;letmutsession:Option<SharedSessionProjection<'_,NativeSession>>=None;letmutprogress=ResolvePlan::begin();loop{letpending=matchprogress{ResolveProgress::Step(pending)=>pending,ResolveProgress::Resolved(_)=>{letSome(session)=sessionelse{ifletSome(held)=rundown.take(){unsafe{fsring_sys::c4::ExReleaseRundownProtection(held.cast())};}returnErr(SessionAccessError::StaleLocator);};returnOk(SessionAccessGuard{registry:core::ptr::from_ref(self),slot_index,locator,session,});}ResolveProgress::Refused(refusal)=>{ifrefusal.releases_lock(){ifletSome(held)=lock.take(){unsafe{held.release()};}}ifrefusal.releases_rundown(){ifletSome(held)=rundown.take(){unsafe{fsring_sys::c4::ExReleaseRundownProtection(held.cast())};}}returnErr(SessionAccessError::from_rejection(refusal.reason()));}};progress=matchpending.step(){ResolveStep::BoundsCheckLocator=>matchself.access_rundown_ptr(slot_index){Some(_)=>pending.succeeded(),None=>pending.refused(ResolveRejection::OutOfRange),},ResolveStep::AcquireAccessRundown=>{letSome(target)=self.access_rundown_ptr(slot_index)else{progress=pending.refused(ResolveRejection::OutOfRange);continue;};letacquired=unsafe{fsring_sys::c4::ExAcquireRundownProtection(target.cast())};ifacquired==0{pending.refused(ResolveRejection::RundownRefused)}else{rundown=Some(target);pending.succeeded()}}ResolveStep::AcquireRegistryLock=>{letheld=unsafe{Self::lock(NonNull::from(self).cast::<KernelSessionRegistry>())};lock=Some(held);pending.succeeded()}ResolveStep::ValidateCoreLive=>{letSome(held)=lock.as_mut()else{progress=pending.refused(ResolveRejection::StaleCell);continue;};letcore=unsafe{held.core_mut()};matchcore.validate_live(locator){Ok(())=>pending.succeeded(),Err(_)=>pending.refused(ResolveRejection::NotLive),}}ResolveStep::ValidateCellIdentity=>{letSome(held)=lock.as_mut()else{progress=pending.refused(ResolveRejection::StaleCell);continue;};matchunsafe{held.cell_mut(slot_index)}{Some(cell)ifcell.matches_live_locator(locator)=>pending.succeeded(),Some(_)|None=>pending.refused(ResolveRejection::StaleCell),}}ResolveStep::ValidateNativeOwnerSlots=>{letSome(held)=lock.as_mut()else{progress=pending.refused(ResolveRejection::StaleCell);continue;};matchunsafe{held.cell_mut(slot_index)}{Some(cell)ifcell.owners_match(locator)=>pending.succeeded(),Some(_)|None=>pending.refused(ResolveRejection::MissingOwners),}}ResolveStep::ProjectSessionPointer=>{letSome(held)=lock.as_mut()else{progress=pending.refused(ResolveRejection::StaleCell);continue;};letprojected=unsafe{held.project_resolved_session(slot_index,locator)};matchprojected{Some(pointer)=>{session=Some(pointer);pending.succeeded()}None=>pending.refused(ResolveRejection::StaleCell),}}ResolveStep::ReleaseRegistryLock=>{ifletSome(held)=lock.take(){unsafe{held.release()};}pending.succeeded()}};}",
        ),
        (
            "park_wait_enter",
            'letregistry=NonNull::new(self.registryas*mutKernelSessionRegistry).ok_or(wdk_sys::STATUS_INVALID_DEVICE_STATE)?;letmutlock=unsafe{KernelSessionRegistry::lock(registry)};letSome(cell)=(unsafe{lock.cell_mut(self.slot_index)})else{unsafe{lock.release()};returnErr(wdk_sys::STATUS_INVALID_DEVICE_STATE);};letSome(runtime)=cell.pending_runtime()else{unsafe{lock.release()};returnErr(wdk_sys::STATUS_INVALID_DEVICE_STATE);};letruntime=runtimeas*constcrate::pending_enter::PendingRuntimeReady;unsafe{lock.release()};unsafe{crate::pending_enter::park_wait_enter(&*runtime,ring_index,irp,timeout_ms)}',
        ),
        (
            "wake_ready_parked_waits",
            "letSome(registry)=NonNull::new(self.registryas*mutKernelSessionRegistry)else{returntrue;};letmutlock=unsafe{KernelSessionRegistry::lock(registry)};letSome(cell)=(unsafe{lock.cell_mut(self.slot_index)})else{unsafe{lock.release()};returntrue;};letSome(runtime)=cell.pending_runtime()else{unsafe{lock.release()};returntrue;};letruntime=runtimeas*constcrate::pending_enter::PendingRuntimeReady;unsafe{lock.release()};unsafe{(*runtime).deposit_readiness_wakes(self.session.get()as*constcrate::session::NativeSession)}",
        ),
        (
            "fail_unstored_parked_wait",
            'letSome(registry)=NonNull::new(self.registryas*mutKernelSessionRegistry)else{returnfalse;};letmutlock=unsafe{KernelSessionRegistry::lock(registry)};letruntime=matchunsafe{lock.cell_mut(self.slot_index)}{Some(cell)=>cell.pending_runtime().map(|runtime|runtimeas*constcrate::pending_enter::PendingRuntimeReady),None=>None,};unsafe{lock.release()};letSome(runtime)=runtimeelse{returnfalse;};unsafe{crate::pending_enter::fail_unstored_parked_wait(&*runtime,ring_index)}',
        ),
    ),
    "driver/fsring-fsd/src/pending_enter.rs": (
        (
            "unlink_parked_control_link",
            'letraw=context.as_ptr();letold_irql=unsafe{KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock))};letunlock=unsafe{PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock),old_irql)};letregistry=matchunsafe{(*raw).runtime.as_ref()}{Some(runtime)=>runtime.parked_strong_registry,None=>core::ptr::null_mut(),};unlock.release();letSome(registry)=NonNull::new(registry)else{return;};letindex=link.locator().slot_index();letmutlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(registry)};ifletSome(cell)=unsafe{lock.cell_mut(index)}{ifletSome(ledger)=cell.pending_ledger_mut(){let_=ledger.unlink(link);}}unsafe{lock.release()};',
        ),
        (
            "link_parked_control",
            'letraw=context.as_ptr();letold_irql=unsafe{KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock))};letunlock=unsafe{PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock),old_irql)};letregistry=matchunsafe{(*raw).runtime.as_ref()}{Some(runtime)=>runtime.parked_strong_registry,None=>core::ptr::null_mut(),};unlock.release();letSome(registry)=NonNull::new(registry)else{returnErr(PendingError::WrongSession);};letindex=install.locator().slot_index();letmutlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(registry)};letresult=matchunsafe{lock.cell_mut(index)}{Some(cell)=>matchcell.pending_ledger_mut(){Some(ledger)=>ledger.link(install),None=>Err(PendingError::WrongSession),},None=>Err(PendingError::WrongSession),};unsafe{lock.release()};result',
        ),
        (
            "release_parked_strong_refs",
            "letraw=context.as_ptr();letold_irql=unsafe{KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of_mut!((*raw).lock))};letunlock=unsafe{PendingContextUnlock::armed(core::ptr::addr_of_mut!((*raw).lock),old_irql)};let(reference,registry)=matchunsafe{(*raw).runtime.as_mut()}{Some(runtime)=>(runtime.parked_strong.take(),runtime.parked_strong_registry),None=>(None,core::ptr::null_mut()),};unlock.release();letSome(reference)=referenceelse{return;};letSome(registry)=NonNull::new(registry)else{return;};letmutlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(registry)};let_=unsafe{lock.core_mut().release(reference)};unsafe{lock.release()};",
        ),
    ),
    "driver/fsring-fsd/src/platform.rs": (),
    "driver/fsring-fsd/src/seh.rs": (),
    "driver/fsring-fsd/src/session.rs": (
        (
            "prepare_setup_rollback",
            "let_setup_epoch=context.setup_epoch;ifcontext.prepared_rollback.is_some()||context.rollback_reason.is_some(){returnErr(STATUS_INVALID_DEVICE_STATE);}context.rollback_reason=Some(reason);letSome(reservation)=context.reservation.take()else{returnErr(STATUS_INVALID_DEVICE_STATE);};letmutlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(context.registry)};letprepared=ifletSome(installed)=context.installed.take(){letSome(transaction)=context.transaction.take()else{context.reservation=Some(reservation);context.installed=Some(installed);unsafe{lock.release()};returnErr(STATUS_INVALID_DEVICE_STATE);};letlocator=installed.locator();matchunsafe{prepare_installed_setup_rollback(transaction,reason,&*lock.core_ptr(),crate::control::binding_ref(context.control),reservation,installed,)}{Ok(prepared)=>{ifletSome(cell_index)=context.cell_index{letSome(cell)=(unsafe{lock.cell_ptr(cell_index)})else{unsafe{lock.release()};returnErr(STATUS_INVALID_DEVICE_STATE);};ifunsafe{(*cell).clear_staging(locator)}.is_err(){unreachable!()}}PreparedSetupRollback::Installed(prepared)}Err(failure)=>{let(_,transaction,_,reservation,installed)=failure.into_parts();context.transaction=Some(transaction);context.reservation=Some(reservation);context.installed=Some(installed);unsafe{lock.release()};returnErr(STATUS_INVALID_DEVICE_STATE);}}}elseifletSome(transaction)=context.transaction.take(){matchunsafe{prepare_uninstalled_setup_rollback(transaction,reason,crate::control::binding_ref(context.control),reservation,)}{Ok(prepared)=>PreparedSetupRollback::Uninstalled(prepared),Err(failure)=>{let(_,transaction,_,reservation)=failure.into_parts();context.transaction=Some(transaction);context.reservation=Some(reservation);unsafe{lock.release()};returnErr(STATUS_INVALID_DEVICE_STATE);}}}else{matchunsafe{prepare_reserved_setup_rollback(crate::control::binding_ref(context.control),reservation,)}{Ok(prepared)=>PreparedSetupRollback::Reserved(prepared),Err((_,reservation))=>{context.reservation=Some(reservation);unsafe{lock.release()};returnErr(STATUS_INVALID_DEVICE_STATE);}}};context.prepared_rollback=Some(prepared);unsafe{lock.release()};Ok(())",
        ),
        (
            "commit_setup_rollback",
            "letSome(prepared)=context.prepared_rollback.take()else{returnErr(STATUS_INVALID_DEVICE_STATE);};letmutlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(context.registry)};letmutretired=None;matchprepared{PreparedSetupRollback::Reserved(prepared)=>unsafe{let_=commit_prepared_reserved_setup_rollback(prepared,crate::control::binding_mut(context.control),);},PreparedSetupRollback::Uninstalled(prepared)=>unsafe{let_=commit_prepared_uninstalled_setup_rollback(prepared,crate::control::binding_mut(context.control),);},PreparedSetupRollback::Installed(prepared)=>unsafe{let(_,disposition,_)=commit_prepared_installed_setup_rollback(prepared,&mut*lock.core_ptr(),crate::control::binding_mut(context.control),);ifdisposition==SlotDisposition::Retired{retired=context.cell_index;}},}unsafe{crate::control::publish_binding_phase(context.control)};unsafe{lock.release()};ifletSome(index)=retired{letmutlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(context.registry)};letSome(cell)=(unsafe{lock.cell_ptr(index)})else{unsafe{lock.release()};returnErr(STATUS_INVALID_DEVICE_STATE);};unsafe{lock.release()};unsafe{(*cell).permanently_close_access()};}Ok(())",
        ),
    ),
    "driver/fsring-fsd/src/trace.rs": (),
    "driver/fsring-fsd/src/volume.rs": (),
}

# These bodies changed in the Task 12 affine cutover and are frozen by the
# cross-crate Task 12 grammar below.  The older locator audit still owns their
# exact projection counts and owning-function order.
TASK12_REPLACED_PROJECTION_BODIES = {
    "driver/fsring-fsd/src/driver.rs": {
        "perform_unload",
    },
    "driver/fsring-fsd/src/fence.rs": {
        "release_strong_and_deposit",
        "prepare_final_delete",
        "dismount_and_delete_devices",
        "wait_until_mount_drained",
        "complete_mount_owner",
        "complete_mount_reset_join",
        "complete_mount_join",
        "run_queued_finalizer",
        "store_fail_stop_locked",
        "publish_completed_generation",
        "run_terminal",
        "run_terminal_for_unload",
    },
    "driver/fsring-fsd/src/lifecycle.rs": {
        "store_parked_wait",
        "acquire_parked_strong_refs",
        "release_parked_strong_refs",
        "into_checkpoint_parts_with_locked_mirror",
        "wait_for_terminal_outcome",
        "occupied_cell_count",
        "prepare_native_terminal_claim",
        "close_global_admissions",
        "observe_r3_finalizer_for_drain",
        "acknowledge_r3_finalizer_after_rundown",
        "queue_cell_finalizer",
        "fsring_finalizer_callback",
        "signal_terminal_outcome",
        "wait_joiners_drained",
        "complete_cell_access_rundown",
        "reset_cell_and_publish",
        "wait_mount_observation",
        "prepare_locked_mount_publication",
        "observe_r3_unload_cell",
        "observe_r3_unload_preflight",
        "scan_one_cell_for_process",
        "signal_mount_complete_after_unlock",
        "signal_mount_waiters_drained_after_unlock",
        "signal_mount_reset_complete_after_unlock",
        "signal_mount_reset_waiters_drained_after_unlock",
    },
    "driver/fsring-fsd/src/session.rs": {
        "install_staging",
        "publish_locked_suffix",
    },
    "driver/fsring-fsd/src/volume.rs": {
        "perform_mount",
        "undo_mount",
        "expose_published_mount",
    },
}

REGISTRY_PROJECTION_BODIES = {
    "core_ptr": "unsafe{self.registry.as_ref().core.get()}",
    "cell_ptr": (
        "letindex=usize::try_from(index).ok()?;"
        "unsafe{self.registry.as_ref()}.cells.get(index).map(|cell|cell.get())"
    ),
    "core_mut": "unsafe{&mut*self.registry.as_ref().core.get()}",
    "cell_mut": "unsafe{self.cell_ptr(index)}.map(|cell|unsafe{&mut*cell})",
}

NATIVE_TYPE_DECLARATIONS = {
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "struct",
            "KernelSessionRegistry",
        ),
        (
            "struct",
            "FinalizerWorkItemContext",
        ),
        (
            "struct",
            "NativeSessionCell",
        ),
        (
            "enum",
            "RegistryInitializationStep",
        ),
        (
            "enum",
            "CellEvent",
        ),
        (
            "enum",
            "CellInitializationStep",
        ),
        (
            "struct",
            "NativeMountedDeviceOwner",
        ),
        (
            "struct",
            "NativeMountedVpbOwner",
        ),
        (
            "struct",
            "PreparedNativeMountInstall",
        ),
        (
            "struct",
            "NativeMountOwnerPublication",
        ),
        (
            "struct",
            "NativeMountRendezvous",
        ),
        (
            "struct",
            "UnpublishedNativeSessionShell",
        ),
        (
            "struct",
            "NativeSessionShell",
        ),
        (
            "struct",
            "DriverRootRelease",
        ),
        (
            "type",
            "NativeSessionOwner",
        ),
        (
            "type",
            "SessionRootReleaseRight",
        ),
        (
            "type",
            "Mirror",
        ),
        (
            "struct",
            "PreparedNativeMountActivation",
        ),
        (
            "struct",
            "NonPagedAllocationOwner",
        ),
        (
            "struct",
            "ControlContextLease",
        ),
        (
            "struct",
            "SetupAdmissionGuard",
        ),
        (
            "struct",
            "ClosedGlobalAdmissions",
        ),
        (
            "struct",
            "R3UnloadScanAdmission",
        ),
        (
            "struct",
            "ProcessCallbackAdmissionClosed",
        ),
        (
            "struct",
            "SetupAdmissionClosed",
        ),
        (
            "struct",
            "ControlContextAdmissionClosed",
        ),
        (
            "struct",
            "FinalizerAdmissionClosed",
        ),
        (
            "struct",
            "FinalizerRundownDrained",
        ),
        (
            "struct",
            "FinalizersDrained",
        ),
        (
            "struct",
            "FinalizerCallbackAdmission",
        ),
        (
            "struct",
            "AdmittedR3FinalizerKick",
        ),
        (
            "struct",
            "ProcessCallbacksDrained",
        ),
        (
            "struct",
            "SetupAdmissionDrained",
        ),
        (
            "struct",
            "ControlContextAdmissionDrained",
        ),
        (
            "struct",
            "PrivateR3UnloadScanAdmission",
        ),
        (
            "struct",
            "PrivateProcessAdmissionClosed",
        ),
        (
            "struct",
            "PrivateSetupAdmissionClosed",
        ),
        (
            "struct",
            "PrivateControlAdmissionClosed",
        ),
        (
            "struct",
            "PrivateFinalizerAdmissionClosed",
        ),
        (
            "struct",
            "PrivateFinalizerCallbackAdmissionAuthority",
        ),
        (
            "struct",
            "RegistryLockGuard",
        ),
        (
            "struct",
            "PreparedLockedMountPublication",
        ),
        (
            "struct",
            "CloseContextRight",
        ),
        (
            "struct",
            "CompletedControlRecord",
        ),
        (
            "struct",
            "ControlOwner",
        ),
        (
            "struct",
            "ClosingControlOwner",
        ),
        (
            "struct",
            "ProcessCallbackGuard",
        ),
        (
            "enum",
            "R3FinalizerDrainObservation",
        ),
        (
            "struct",
            "LockedR3FinalizerDrainNonMatch",
        ),
        (
            "struct",
            "PrivateLockedR3FinalizerDrainNonMatch",
        ),
        (
            "struct",
            "LockedR3FinalizerOrdinaryInFlight",
        ),
        (
            "struct",
            "PrivateLockedR3FinalizerOrdinaryInFlight",
        ),
        (
            "struct",
            "ControlStrongRef",
        ),
        (
            "struct",
            "TerminalWork",
        ),
        (
            "struct",
            "TerminalOwners",
        ),
        (
            "enum",
            "NativeProtocolTerminalDisposition",
        ),
        (
            "enum",
            "NativeTerminalJoinAuthority",
        ),
        (
            "struct",
            "TerminalJoinGuard",
        ),
        (
            "enum",
            "OpaqueFailStopWaitPreparation",
        ),
        (
            "enum",
            "TerminalVisibilityResolution",
        ),
        (
            "enum",
            "R3UnloadVisibilityResolution",
        ),
        (
            "struct",
            "OpaqueFailStopWaitGuard",
        ),
        (
            "struct",
            "BlockedUnloadWaitGuard",
        ),
        (
            "struct",
            "RetainedPublishedJoinWaitGuard",
        ),
        (
            "struct",
            "ReleasedPublishedJoin",
        ),
        (
            "struct",
            "FinalizerHandoffRight",
        ),
        (
            "enum",
            "FinalizerVisibilityHandoff",
        ),
        (
            "struct",
            "FinalizerMissingHandoffGuard",
        ),
        (
            "enum",
            "FinalizerWinnerResolution",
        ),
        (
            "enum",
            "TerminalDisposition",
        ),
        (
            "struct",
            "PreparedNativeCellClaim",
        ),
        (
            "struct",
            "PreparedNativeTerminalClaim",
        ),
        (
            "enum",
            "NativeCleanupRoute",
        ),
        (
            "enum",
            "MountCellEvent",
        ),
        (
            "type",
            "Kind",
        ),
        (
            "type",
            "Kind",
        ),
        (
            "type",
            "Kind",
        ),
        (
            "type",
            "Kind",
        ),
        (
            "type",
            "Kind",
        ),
        (
            "enum",
            "SessionAccessError",
        ),
        (
            "struct",
            "SessionAccessGuard",
        ),
        (
            "struct",
            "NativeRingGuard",
        ),
        (
            "enum",
            "ProcessScanAction",
        ),
        (
            "struct",
            "PreparedProcessScanAction",
        ),
        (
            "enum",
            "ProcessScanStep",
        ),
        (
            "struct",
            "LockedR3UnloadNonMatch",
        ),
        (
            "struct",
            "PrivateLockedR3UnloadNonMatch",
        ),
        (
            "enum",
            "R3UnloadCellAction",
        ),
        (
            "enum",
            "R3UnloadCellObservation",
        ),
        (
            "struct",
            "R3NativeUnloadPreflightObservation",
        ),
        (
            "struct",
            "R3NativeLedgersClear",
        ),
        (
            "struct",
            "R3SoleDriverRoot",
        ),
        (
            "struct",
            "PrivateR3NativeLedgersClear",
        ),
        (
            "struct",
            "PrivateR3SoleDriverRoot",
        ),
        (
            # The typed refusal a parked-WAIT store hands back, so its caller
            # has to decide rather than cast the answer to `let _`.
            "enum",
            "ParkedStoreRefusal",
        ),
    ),
    "driver/fsring-fsd/src/session.rs": (
        (
            "struct",
            "RawArray",
        ),
        (
            "struct",
            "MasterMdl",
        ),
        (
            "struct",
            "UserAlias",
        ),
        (
            "struct",
            "RingState",
        ),
        (
            "struct",
            "NativeRingState",
        ),
        (
            "struct",
            "NativeRingSlot",
        ),
        (
            "struct",
            "NativeSession",
        ),
        (
            "struct",
            "NativeSessionView",
        ),
        (
            "struct",
            "SetupContext",
        ),
        (
            "struct",
            "SetupCalloutBlock",
        ),
        (
            "enum",
            "DrainFinish",
        ),
        (
            "struct",
            "GrantLock",
        ),
    ),
    "driver/fsring-fsd/src/volume.rs": (
        (
            "struct",
            "VolumeExtension",
        ),
        (
            "struct",
            "VolumeControlBlock",
        ),
        (
            "struct",
            "MountedVolumeExtension",
        ),
        (
            "struct",
            "NativeVcbStorage",
        ),
        (
            "struct",
            "NativeInitializedVcb",
        ),
        (
            "struct",
            "MountContext",
        ),
        (
            "struct",
            "NativeMountOps",
        ),
    ),
}

NATIVE_USE_ALIASES = {
    "driver/fsring-fsd/src/lifecycle.rs": (
        "CoreNativeSessionOwner",
        "CoreSessionRootReleaseRight",
        "P",
    ),
    "driver/fsring-fsd/src/session.rs": (
        "enter_plan",
        "plan",
    ),
    "driver/fsring-fsd/src/volume.rs": ("adapter",),
}

NATIVE_CRATE_EXPORTS = {
    "driver/fsring-fsd/src/lifecycle.rs": ((
        "const",
        "SESSION_CELL_COUNT",
        "usize",
    ),),
    "driver/fsring-fsd/src/session.rs": (
        (
            "const",
            "MAX_PENDING_LINKS",
            "usize",
        ),
        (
            "const",
            "SETUP_STACK_EXPANSION_BYTES",
            "usize",
        ),
    ),
    "driver/fsring-fsd/src/volume.rs": ((
        "const",
        "VOLUME_NAME_UNITS",
        "usize",
    ),),
}

PROTECTED_IMPL_HEADERS = {
    "driver/fsring-fsd/src/lifecycle.rs": (
        "implUnpublishedNativeSessionShell",
        "implNativeSessionSharedOpsforNativeSessionShell",
        "implDriverRootRelease",
        "unsafeimplfsring_core::adapter::fence::PreparedDeleteStorageOps<DriverRootRelease>forNativeSessionShell",
        "implNonPagedAllocationOwner",
        "implControlContextLease",
        "implKernelSessionRegistry",
        "implRegistryLockGuard",
        "implRegistryLockGuard",
        "implTerminalWork",
        "implRegistryLockGuard",
        "implKernelSessionRegistry",
        "implNativeSessionCell",
        "implNativeSessionCell",
        "implRegistryLockGuard",
        "implKernelSessionRegistry",
        "implNativeSessionCell",
        "implRegistryLockGuard",
        "implKernelSessionRegistry",
        "impl<'registry>SessionAccessGuard<'registry>",
        "implDropforSessionAccessGuard<'_>",
        "implNativeRingGuard<'_,'_>",
        "implDropforNativeRingGuard<'_,'_>",
    ),
    "driver/fsring-fsd/src/session.rs": (
        "unsafeimplSyncforNativeRingSlot",
        "implNativeRingSlot",
        "implNativeSession",
        "implNativeSessionView",
        "implNativeSession",
    ),
    "driver/fsring-fsd/src/volume.rs": ("implVolumeExtension",),
}

PROTECTED_RECEIVER_METHODS = {
    "KernelSessionRegistry": (
        (
            "pub(crate)unsafefnlock(registry:NonNull<Self>)->RegistryLockGuard",
            "pub(crate)unsafefninitialize_in_place(target:*mutMaybeUninit<Self>,)->Result<(),NTSTATUS>",
            "pub(crate)unsafefninitialize_work_items(&mutself,provider:PDEVICE_OBJECT,)->Result<(),NTSTATUS>",
            "pub(crate)unsafefnrollback_initialization(&mutself)",
            "pub(crate)unsafefndestroy_prepared_work_items(&mutself,proof:&R3NativeLedgersClear)",
        ),
        (
            "pub(crate)fnclaim_committed_protocol(&self,committed:fsring_core::adapter::enter::CommittedProtocolAbort,)->NativeProtocolTerminalDisposition",
        ),
        (
            "pub(crate)fnaccess_rundown_ptr(&self,slot_index:u32)->Option<*mutEX_RUNDOWN_REF>",
            "pub(crate)unsafefnresolve(&self,locator:SessionLocator,)->Result<SessionAccessGuard<'_>,SessionAccessError>",
        ),
        ("pub(crate)unsafefnscan_one_cell_for_process(guard:&ProcessCallbackGuard,process:PEPROCESS,index:u32,)->ProcessScanStep",),
    ),
    "RegistryLockGuard": (
        (
            "pub(crate)unsafefnobserve_r3_finalizer_for_drain(&mutself,index:u32,)->R3FinalizerDrainObservation",
            "pub(crate)unsafefnacknowledge_r3_finalizer_after_rundown(&mutself,index:u32,)->Option<LockedR3FinalizerDrainNonMatch>",
        ),
        (
            "pub(crate)unsafefncore_ptr(&mutself)->*mutSessionRegistry<SESSION_CELL_COUNT>",
            "pub(crate)unsafefncell_ptr(&mutself,index:u32)->Option<*mutNativeSessionCell>",
            "pub(crate)unsafefncell_mut_prevalidated(&mutself,index:u32)->&mutNativeSessionCell",
            "pub(crate)unsafefncore_mut(&mutself)->&mutSessionRegistry<SESSION_CELL_COUNT>",
            "pub(crate)unsafefncell_mut(&mutself,index:u32)->Option<&mutNativeSessionCell>",
            "pub(crate)unsafefnpublish_completed_generation(&mutself,locator:SessionLocator,closing:ClosingControlOwner,winner:fsring_core::session::TerminalWinner,result:TerminalResult,)->fsring_core::session::TerminalOutcomeSignal",
            "unsafefnproject_resolved_session<'registry>(&mutself,index:u32,locator:SessionLocator,)->Option<SharedSessionProjection<'registry,NativeSession>>",
            "pub(crate)unsafefnrelease(self)",
        ),
        (
            "pub(crate)fnprepare_published_unload_wait(&mutself,locator:SessionLocator,)->Option<BlockedUnloadWaitGuard>",
            "fnprepare_released_published_unload_wait(&mutself,released:ReleasedPublishedJoin,)->Result<(BlockedUnloadWaitGuard,Option<fsring_core::session::TerminalJoinersDrainedSignal>,),ReleasedPublishedJoin,>",
            "fnprepare_retained_published_join_wait(&mutself,registry:NonNull<KernelSessionRegistry>,locator:SessionLocator,ticket:fsring_core::session::TerminalJoinTicket,)->Result<RetainedPublishedJoinWaitGuard,fsring_core::session::TerminalJoinTicket>",
            "pub(crate)fnprepare_opaque_unload_wait(&mutself,locator:SessionLocator,)->Option<OpaqueFailStopWaitGuard>",
        ),
        (
            "#[allow(clippy::result_large_err)]pub(crate)unsafefnprepare_locked_mount_done_publication(&mutself,publication:MountDonePublication,)->Result<PreparedLockedMountPublication<'_,MountDonePublication>,(LifecycleError,MountDonePublication),>",
            "#[allow(clippy::result_large_err)]pub(crate)unsafefnprepare_locked_mount_join_conversion(&mutself,conversion:MountJoinConversion,)->Result<PreparedLockedMountPublication<'_,MountJoinConversion>,(LifecycleError,MountJoinConversion),>",
            "#[allow(clippy::result_large_err)]pub(crate)unsafefnprepare_locked_mount_reset_publication(&mutself,publication:MountResetPublication,)->Result<PreparedLockedMountPublication<'_,MountResetPublication>,(LifecycleError,MountResetPublication),>",
            "#[allow(clippy::result_large_err)]pub(crate)unsafefnprepare_locked_mount_reset_join_release(&mutself,release:MountResetJoinRelease,)->Result<PreparedLockedMountPublication<'_,MountResetJoinRelease>,(LifecycleError,MountResetJoinRelease),>",
        ),
        (
            "pub(crate)unsafefnobserve_r3_unload_cell(&mutself,index:u32)->R3UnloadCellObservation",
            "unsafefnobserve_r3_unload_preflight(&mutself)->R3NativeUnloadPreflightObservation",
            "unsafefnprepare_r3_native_ledgers_clear(&mutself,)->Result<R3NativeLedgersClear,fsring_core::adapter::load::R3UnloadPredicate>",
            "pub(crate)unsafefnprepare_r3_unload_locked_root(&mutself,state:core::ptr::NonNull<crate::driver::DriverState>,)->Result<(R3NativeLedgersClear,R3SoleDriverRoot),fsring_core::adapter::load::R3UnloadPredicate,>",
        ),
    ),
    "TerminalWork": ((
        "pub(crate)constfnlocator(&self)->SessionLocator",
        "pub(crate)constfnreason(&self)->fsring_core::session::TerminalReason",
        "pub(crate)constfncontrol_context(&self)->NonNull<ControlFileContext>",
        "pub(crate)fninto_checkpoint_parts(self)->(ControlStrongRef,TerminalOwners)",
    ),),
    "NativeSessionCell": (
        (
            "fnr3_finalizer_ledger_is_exactly_empty(&self)->bool",
            "fnr3_finalizer_is_authenticated_ordinary_in_flight(&self,registry:NonNull<KernelSessionRegistry>,locator:SessionLocator,)->bool",
            "fnmatches_live_locator(&self,locator:SessionLocator)->bool",
            "pub(crate)fnstaging_publication_preflight(&self,locator:SessionLocator,session:*mutNativeSession,process:PEPROCESS,)->Result<(),NTSTATUS>",
            "pub(crate)fninstall_staging(&mutself,locator:SessionLocator,session:*mutNativeSession,process:PEPROCESS,)->Result<(),NTSTATUS>",
            "pub(crate)fnclear_staging(&mutself,locator:SessionLocator)->Result<(),NTSTATUS>",
            "pub(crate)unsafefnpublish_live(&mutself,locator:SessionLocator,registry_lease:RegistryLease,control_owner:ControlOwner,shell_owner:NativeSessionOwner,root_release:SessionRootReleaseRight,finalizer_right:R3FinalizerCellBindRight,)",
            "pub(crate)fnterminal_rendezvous_mut(&mutself)->&mutTerminalRendezvous",
            "pub(crate)constfnterminal_rendezvous_ref(&self)->&TerminalRendezvous",
            "pub(crate)fnlive_locator(&self)->Option<SessionLocator>",
            "pub(crate)fnrecorded_control_context(&self)->Option<NonNull<ControlFileContext>>",
            "pub(crate)constfnsession_mirror(&self)->*mutNativeSession",
            "pub(crate)fncheckpoint_finish_preflight(&self,locator:SessionLocator,)->Result<(),LifecycleError>",
            "pub(crate)fnrelease_deposit_preflight(&self,locator:SessionLocator,deletes:bool,supplies_readiness:bool,)->Result<(),LifecycleError>",
            "pub(crate)fncheckpoint_ledger_is_discharged(&self,locator:SessionLocator)->bool",
            "pub(crate)fndelete_preflight_observation(&self,locator:SessionLocator,)->fsring_core::adapter::fence::DeletePreflightObservation",
            "pub(crate)unsafefnstore_and_resolve_fail_stop(&mutself,packet:crate::fence::R3FailStopPacket,)->crate::fence::R3FailStopVisibility",
            "fnrelease_opaque_join(&mutself,receipt:&crate::fence::OpaqueFailStopReceipt,ticket:fsring_core::session::TerminalJoinTicket,)->Result<Option<fsring_core::session::TerminalJoinersDrainedSignal>,fsring_core::session::TerminalJoinTicket,>",
            "fnauthenticate_closed_fail_stop(&self,locator:SessionLocator,)->Option<crate::fence::ClosedFailStopAuthentication>",
            "pub(crate)unsafefninstall_pending_runtime(&mutself,runtime:crate::pending_enter::PendingRuntimeReady,)",
            "pub(crate)constfnpending_runtime(&self,)->Option<&crate::pending_enter::PendingRuntimeReady>",
            "pub(crate)fntake_pending_runtime(&mutself,)->Option<crate::pending_enter::PendingRuntimeReady>",
            "pub(crate)unsafefninstall_pending_ledger(&mutself,ledger:fsring_core::session::PendingControlLedger<{crate::session::MAX_PENDING_LINKS}>,)",
            "pub(crate)fnpending_ledger_mut(&mutself,)->Option<&mutfsring_core::session::PendingControlLedger<{crate::session::MAX_PENDING_LINKS}>,>",
            "pub(crate)fnclose_pending_admission(&mutself)",
            "pub(crate)fnpark_fence_retry(&mutself,parked:crate::fence::ParkedFenceResidual)",
            "pub(crate)fnfence_retry_timer_ptr(&mutself)->*mutKTIMER",
            "pub(crate)fnfence_retry_dpc_ptr(&mutself)->*mutKDPC",
            "pub(crate)fntake_fence_retry_park(&mutself)->Option<crate::fence::ParkedFenceResidual>",
            "pub(crate)fnfence_retry_registry(&self)->NonNull<KernelSessionRegistry>",
            "pub(crate)fnfence_retry_work_item(&self)->PIO_WORKITEM",
            "pub(crate)fnfence_retry_dpc_exit_ptr(&mutself)->*mutKEVENT",
            "pub(crate)fnpark_readiness(&mutself,readiness:crate::fence::FenceDeletionReadiness)",
            "pub(crate)fntake_parked_readiness(&mutself,locator:SessionLocator,)->Option<crate::fence::FenceDeletionReadiness>",
            "pub(crate)unsafefnstore_deposit_and_mint_kick(&mutself,readiness:crate::fence::FenceDeletionReadiness,right:fsring_core::session::DeleteSessionRight,)->Result<fsring_core::adapter::fence::R3FinalizerKick,(crate::fence::FenceDeletionReadiness,fsring_core::session::DeleteSessionRight,),>",
            "pub(crate)unsafefnstore_deposit_and_mint_kick_prevalidated(&mutself,readiness:crate::fence::FenceDeletionReadiness,right:fsring_core::session::DeleteSessionRight,)->fsring_core::adapter::fence::R3FinalizerKick",
            "pub(crate)fnmount_rendezvous(&self)->&NativeMountRendezvous",
            "pub(crate)fnmount_rendezvous_mut(&mutself)->&mutNativeMountRendezvous",
            "pub(crate)fnprepare_mount_install(&self,locator:SessionLocator,reference:&StrongSessionRef,mounted:&NativeMountedDeviceOwner,vpb:&NativeMountedVpbOwner,)->Result<PreparedNativeMountInstall,LifecycleError>",
            "pub(crate)unsafefncommit_prepared_mount_install(&mutself,prepared:PreparedNativeMountInstall,reference:StrongSessionRef,mounted:NativeMountedDeviceOwner,vpb:NativeMountedVpbOwner,)->NativeMountOwnerPublication",
            "pub(crate)unsafefntake_or_join_mount(&mutself,expected:ExpectedMountTeardown,)->Result<MountClaim<NativeMountedDeviceOwner,NativeMountedVpbOwner>,LifecycleError>",
            "pub(crate)unsafefnrelease_mount_join(&mutself,ticket:MountJoinTicket,)->Result<MountJoinConversion,(LifecycleError,MountJoinTicket)>",
            "pub(crate)unsafefnpermanently_close_access(&mutself)",
            "fnprocess_locator(&self,process:PEPROCESS)->Option<SessionLocator>",
            "fnmark_process_loss_handled(&mutself,locator:SessionLocator)->bool",
            "fnowners_match(&self,locator:SessionLocator)->bool",
        ),
        (
            "pub(crate)fntake_deposit_and_run_for_callback(&mutself,cell_index:u32,context:fsring_core::adapter::fence::R3FinalizerCallbackContext,)->Option<(crate::fence::FinalizerDeposit,fsring_core::adapter::fence::R3FinalizerRunningRight,FinalizerHandoffRight,)>",
            "pub(crate)fnterminal_outcome_event(&mutself)->*mutKEVENT",
            "pub(crate)fnjoiners_drained_event(&mutself)->*mutKEVENT",
            "pub(crate)fnvisibility_resolution_event(&mutself)->*mutKEVENT",
            "pub(crate)fnstore_ordinary_finalizer_handoff(&mutself,right:FinalizerHandoffRight,)->Result<(),FinalizerHandoffRight>",
            "pub(crate)fnstore_opaque_finalizer_handoff(&mutself,right:FinalizerHandoffRight,receipt:crate::fence::OpaqueFailStopReceipt,)->Result<(),(FinalizerHandoffRight,crate::fence::OpaqueFailStopReceipt)>",
            "fntake_finalizer_handoff(&mutself)->Option<FinalizerVisibilityHandoff>",
            "pub(crate)unsafefnclear_terminal_generation_events(&mutself)",
            "pub(crate)unsafefnreset_after_delete(&mutself,core:&mutSessionRegistry<SESSION_CELL_COUNT>,pending:fsring_core::adapter::fence::PendingFinalDeleteReset<crate::fence::PreparedCellResetRight,>,)->(fsring_core::session::SlotDisposition,fsring_core::adapter::fence::FinalDeleteProof,)",
            "pub(crate)unsafefncomplete_access_rundown(&mutself)",
            "pub(crate)unsafefnreinitialize_access_rundown(&mutself)",
        ),
        (
            "fnr3_unload_preflight_cell_is_empty(&self)->bool",
            "fnr3_unload_scan_is_exactly_empty(&self)->bool",
            "fnr3_unload_scan_is_exactly_empty_except_finalizer_callback(&self)->bool",
        ),
    ),
}

AFFINE_OWNER_METHODS = {
    "NativeMountedDeviceOwner": (
        "pub(crate)unsafefnfrom_created(device:PDEVICE_OBJECT)->Option<Self>",
        "pub(crate)fnas_ptr(&self)->PDEVICE_OBJECT",
        "pub(crate)unsafefndelete(self)",
    ),
    "NativeMountedVpbOwner": (
        "pub(crate)unsafefnfrom_mount_vpb(vpb:*mutVPB)->Option<Self>",
        "pub(crate)fnas_ptr(&self)->*mutVPB",
        "pub(crate)unsafefnclear_binding(self)",
    ),
    "UnpublishedNativeSessionShell": (
        "pub(crate)unsafefnfrom_fresh_allocation(session:NonNull<NativeSession>)->Self",
        "pub(crate)fnas_ptr(&self)->*mutNativeSession",
        "pub(crate)fninto_published_payload(self)->NativeSessionShell",
        "pub(crate)unsafefndestroy(self)",
    ),
    "DriverRootRelease": (
        "pub(crate)unsafefnacquire(state:NonNull<crate::driver::DriverState>,)->Result<Self,LifecycleError>",
        "pub(crate)unsafefnrelease_unpublished(self)",
    ),
    "NonPagedAllocationOwner": (
        "pub(crate)unsafefnallocate(bytes:usize,tag:u32)->Result<Self,NTSTATUS>",
        "pub(crate)constfnregion(&self)->(NonNull<u8>,usize)",
        "pub(crate)unsafefnrelease(self)",
    ),
    "ControlContextLease": (
        "pub(crate)unsafefnacquire(registry:NonNull<KernelSessionRegistry>,)->Result<Self,NTSTATUS>",
        "pub(crate)unsafefnrelease(self)",
    ),
}

PROTECTED_STRUCT_BODIES = {
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "KernelSessionRegistry",
    ): "lock:UnsafeCell<MaybeUninit<KSPIN_LOCK>>,setup_admission_open:UnsafeCell<bool>,control_context_admission_open:UnsafeCell<bool>,process_callback_admission_open:UnsafeCell<bool>,finalizer_admission_open:UnsafeCell<bool>,setup_admission:UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,control_context_admission:UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,process_callback_admission:UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,finalizer_admission:UnsafeCell<MaybeUninit<EX_RUNDOWN_REF>>,blocked_unload:UnsafeCell<MaybeUninit<KEVENT>>,core:UnsafeCell<SessionRegistry<SESSION_CELL_COUNT>>,cells:[UnsafeCell<NativeSessionCell>;SESSION_CELL_COUNT],",
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "NativeSessionCell",
    ): "access:EX_RUNDOWN_REF,terminal_outcome:KEVENT,joiners_drained:KEVENT,visibility_resolution:KEVENT,mount_complete:KEVENT,mount_waiters_drained:KEVENT,mount_reset_complete:KEVENT,mount_reset_waiters_drained:KEVENT,generation:u64,identity:Option<SessionIdentity>,phase:NativeCellPhase,session:*mutNativeSession,process:PEPROCESS,registry_lease:Option<RegistryLease>,control_owner:Option<ControlOwner>,recorded_control_context:Option<NonNull<ControlFileContext>>,shell_owner:Option<NativeSessionOwner>,root_release:Option<SessionRootReleaseRight>,mount_rendezvous:NativeMountRendezvous,terminal_rendezvous:TerminalRendezvous,process_loss_handled:bool,checkpoint_readiness:Option<crate::fence::FenceDeletionReadiness>,pending_runtime:Option<crate::pending_enter::PendingRuntimeReady>,pending_ledger:Option<fsring_core::session::PendingControlLedger<{crate::session::MAX_PENDING_LINKS}>>,fail_stop:crate::fence::R3FailStopSlot,finalizer_handoff:Option<FinalizerVisibilityHandoff>,finalizer:fsring_core::adapter::fence::R3FinalizerCell<crate::fence::R4DeletionOwners>,finalizer_context:FinalizerWorkItemContext,finalizer_work_item:PIO_WORKITEM,finalizer_callback_admitted:Option<FinalizerCallbackAdmission>,fence_retry_timer:MaybeUninit<KTIMER>,fence_retry_dpc:MaybeUninit<KDPC>,fence_retry_dpc_exit:MaybeUninit<KEVENT>,fence_retry_work_item:PIO_WORKITEM,fence_retry_park:Option<crate::fence::ParkedFenceResidual>,",
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "RegistryLockGuard",
    ): "registry:NonNull<KernelSessionRegistry>,old_irql:KIRQL,",
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "TerminalWork",
    ): "locator:SessionLocator,winner:fsring_core::session::TerminalWinner,terminal:fsring_core::session::TerminalSessionRef,control:ControlStrongRef,closing:ClosingControlOwner,shell:NativeSessionOwner,root:SessionRootReleaseRight,",
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "SessionAccessGuard",
    ): "registry:*constKernelSessionRegistry,slot_index:u32,locator:SessionLocator,session:SharedSessionProjection<'registry,NativeSession>,",
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "NativeRingGuard",
    ): "access:&'accessSessionAccessGuard<'registry>,ring_index:u32,slot:&'accesscrate::session::NativeRingSlot,old_irql:Option<SavedIrql<KIRQL>>,",
    (
        "driver/fsring-fsd/src/session.rs",
        "NativeRingSlot",
    ): "lock:UnsafeCell<MaybeUninit<KSPIN_LOCK>>,state:UnsafeCell<NativeRingState>,",
    (
        "driver/fsring-fsd/src/session.rs",
        "NativeSession",
    ): "state:*mutDriverState,identity:SessionIdentity,setup:ValidatedSetupRequest,layout:SectionLayoutPlan,profile:PlatformProfile,section_handle:HANDLE,section_object:PVOID,system_view:PVOID,system_view_size:SIZE_T,captured_process:PEPROCESS,masters:RawArray<MasterMdl>,aliases:RawArray<UserAlias>,grants:RawArray<GrantEntry>,grant_lock:UnsafeCell<MaybeUninit<KSPIN_LOCK>>,grant_table_id:Option<GrantTableIdentity>,ring_views:RawArray<RingViewLayout>,credits:RawArray<NotificationCreditV1>,output:RawArray<u8>,rings:RawArray<NativeRingSlot>,fence_scratch:*mutu8,fence_scratch_bytes:usize,ring_set:Option<fsring_core::session::SessionRingSetBrand>,cq_tokens:RawArray<core::mem::MaybeUninit<Option<fsring_core::enter::CqConsumerToken>>>,vdo:PDEVICE_OBJECT,registry_slot:u32,published:AtomicU32,",
    (
        "driver/fsring-fsd/src/session.rs",
        "NativeSessionView",
    ): "identity:SessionIdentity,layout:SectionLayoutPlan,profile:PlatformProfile,ring_count:u32,",
}

# The pointer shapes that are never a field of those carriers. `session` is
# matched as a bare mirror field too, because Task 12's cell keeps one
# deliberately and it must stay the *only* one.
POINTER_SHAPES = (
    re.compile(r"\*\s*(?:mut|const)\s+NativeSession\b"),
    re.compile(r"NonNull\s*<\s*NativeSession\s*>"),
    re.compile(r"AtomicPtr\s*<\s*NativeSession\s*>"),
    re.compile(r"session\s*:\s*\*\s*(?:mut|const)\s+(?:core::ffi::)?c_void\b"),
    re.compile(r"session\s*:\s*AtomicPtr\s*<\s*(?:core::ffi::)?c_void\s*>"),
)


def address_aliases(text):
    """Local aliases/wrappers that resolve to pointer/reference authority."""
    text = re.sub(r"\br#([A-Za-z_]\w*)", r"\1", text)
    definitions = [
        (match.group(1), match.group(2))
        for match in re.finditer(
            r"\btype\s+([A-Za-z_]\w*)(?:\s*<[^;=]*>)?\s*=\s*([^;]+);",
            text,
        )
    ]
    definitions.extend(
        (match.group(1), match.group(2))
        for match in re.finditer(
            r"\bstruct\s+([A-Za-z_]\w*)(?:\s*<[^;(){}]*>)?\s*\(([^;]*)\)\s*;",
            text,
        )
    )
    definitions.extend(
        (name, body)
        for name, body in struct_bodies(text)
    )
    definitions.extend(
        (name, body)
        for name, body in enum_bodies(text)
    )
    definitions.extend((name, body) for name, body in union_bodies(text))
    shaped = {
        match.group(1)
        for match in re.finditer(
            r"\buse\s+[^;]*\b(?:NonNull|AtomicPtr)\s+as\s+([A-Za-z_]\w*)\s*;",
            text,
        )
    }
    changed = True
    while changed:
        changed = False
        for name, target in definitions:
            if name in shaped:
                continue
            direct = re.search(
                r"(?:\*\s*(?:mut|const)\b|&\s*(?:'\w+\s*)?(?:mut\s+)?\b|"
                r"\b(?:NonNull|AtomicPtr)\s*<)",
                target,
            )
            nested = any(re.search(r"\b" + re.escape(alias) + r"\b", target) for alias in shaped)
            if direct or nested:
                shaped.add(name)
                changed = True
    return shaped


class LifetimeAuditError(Exception):
    """A usage or input error, distinct from a finding."""


def _blank_noncode(fragment):
    """Blank a lexical fragment without moving braces or line boundaries."""
    return "".join("\n" if char == "\n" else " " for char in fragment)


RUST_CHAR_LITERAL = re.compile(
    r"(?:b)?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\}|[^\r\n])|[^\\'\r\n])'"
)
RUST_RAW_STRING_START = re.compile(r"(?:br|cr|r)(?P<hashes>#{0,255})\"")
RUST_STRING_START = re.compile(r'(?:b|c)?"')


def strip_noncode(text):
    """Remove `#[cfg(test)]` items, nested comments, and Rust literals.

    Prose describing a retired pointer is not a stored pointer. A scanner that
    could not tell them apart would be satisfied by documentation, which is the
    failure mode `seam_discipline.rs` documents for its own predicates.
    """
    out = []
    index = 0
    length = len(text)
    while index < length:
        raw = RUST_RAW_STRING_START.match(text, index)
        if raw:
            closing = '"' + raw.group("hashes")
            end = text.find(closing, raw.end())
            end = length if end < 0 else end + len(closing)
            out.append(_blank_noncode(text[index:end]))
            index = end
            continue
        string = RUST_STRING_START.match(text, index)
        if string:
            end = string.end()
            while end < length:
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == '"':
                    end += 1
                    break
                end += 1
            out.append(_blank_noncode(text[index:end]))
            index = end
            continue
        rust_char = RUST_CHAR_LITERAL.match(text, index)
        if rust_char:
            out.append(_blank_noncode(text[index : rust_char.end()]))
            index = rust_char.end()
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = length if end < 0 else end
            out.append(_blank_noncode(text[index:end]))
            index = end
            continue
        if text.startswith("/*", index):
            end = index + 2
            depth = 1
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            out.append(_blank_noncode(text[index:end]))
            index = end
            continue
        char = text[index]
        out.append(char)
        index += 1
    stripped = "".join(out)
    return _drop_cfg_test_items(stripped)


def _drop_cfg_test_items(text):
    """Delete exact test-only items without swallowing later production code.

    Rust accepts both braced items (`mod tests { ... }`) and declarations
    (`mod tests;`).  Treating every marker as braced makes a declaration consume
    the next unrelated brace and can hide the rest of a production file.
    """
    marker = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    while True:
        found = marker.search(text)
        if found is None:
            return text
        start = found.start()
        cursor = found.end()
        paren = bracket = 0
        delimiter = None
        while cursor < len(text):
            char = text[cursor]
            if char == "(":
                paren += 1
            elif char == ")" and paren:
                paren -= 1
            elif char == "[":
                bracket += 1
            elif char == "]" and bracket:
                bracket -= 1
            elif char in "{;" and paren == 0 and bracket == 0:
                delimiter = cursor
                break
            cursor += 1
        if delimiter is None:
            return text[:start]
        if text[delimiter] == ";":
            text = text[:start] + text[delimiter + 1 :]
            continue
        depth = 0
        index = delimiter
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if depth != 0:
            return text[:start]
        text = text[:start] + text[index + 1 :]


def braced_item_bodies(text, kind):
    """Balanced bodies for braced Rust items, including generic/where headers."""
    for match in re.finditer(r"\b" + re.escape(kind) + r"\s+(?:r#)?([A-Za-z_]\w*)", text):
        name = match.group(1)
        brace = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        depth = 0
        index = brace
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if depth == 0:
            yield name, text[brace + 1 : index]


def struct_bodies(text):
    """`(name, body)` for every braced struct item."""
    yield from braced_item_bodies(text, "struct")


def enum_bodies(text):
    """`(name, body)` for balanced enum items, including struct variants."""
    yield from braced_item_bodies(text, "enum")


def union_bodies(text):
    """`(name, body)` for balanced union items."""
    yield from braced_item_bodies(text, "union")


def impl_items(text):
    """Normalized header and balanced body for every impl item."""
    for match in re.finditer(r"\b(?:unsafe\s+)?impl\b", text):
        brace = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        if brace < 0 or (semicolon >= 0 and semicolon < brace):
            continue
        depth = 0
        index = brace
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if depth == 0:
            yield (
                re.sub(r"\s+", "", text[match.start() : brace]),
                text[brace + 1 : index],
            )


def impl_headers(text):
    """Normalized headers for impl items, without assuming a simple self path."""
    for header, _body in impl_items(text):
        yield header


def impl_bodies(text, type_name):
    """Bodies of inherent impls for one named production type."""
    pattern = re.compile(
        r"\bimpl(?:\s*<[^{}]*>)?\s+" + re.escape(type_name) + r"(?:\s*<[^{}]*>)?\s*\{"
    )
    for match in pattern.finditer(text):
        depth = 0
        index = match.end() - 1
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        yield text[match.end() : index]


def trait_impl_bodies(text, trait_name, type_name):
    """Bodies of exact `impl Trait for Type<'_, '_>` production blocks."""
    pattern = re.compile(
        r"\bimpl\s+"
        + re.escape(trait_name)
        + r"\s+for\s+"
        + re.escape(type_name)
        + r"\s*<\s*'_\s*,\s*'_\s*>\s*\{"
    )
    for match in pattern.finditer(text):
        depth = 0
        index = match.end() - 1
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        yield text[match.end() : index]


def function_bodies(text, name):
    """Bodies of named functions/methods, using braces rather than line regexes.

    Shares `function_signature_and_body` with `function_items` so the two
    cannot disagree about where a body begins. They did: this one is what
    every frozen `TASK12_BODY_GRAMMAR` digest is computed from, so its copy of
    the naive first-`{` scan meant a digest over a function with a
    const-generic parameter froze that parameter instead of the body.
    """
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    for match in pattern.finditer(text):
        span = function_signature_and_body(text, match.end())
        if span is None:
            continue
        body_open, body_close = span
        yield text[body_open + 1 : body_close]


FUNCTION_NAME = re.compile(r"\bfn\s+([A-Za-z_]\w*)\b")


def _skip_balanced_braces(text, index):
    """Index just past the `{`-delimited block that starts at `index`."""
    depth = 0
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return index


def function_signature_and_body(text, start):
    """Split one `fn` item into its signature end and its balanced body.

    Returns `(body_open, body_close)` or `None` for a declaration with no body.

    The naive form of this walker took the FIRST `{` after the name as the body
    opener, which is wrong for a signature that carries a const-generic
    argument: `PendingControlLedger<{ crate::session::MAX_PENDING_LINKS }>` in a
    parameter list made the "body" of `park_wait_enter` the 35 characters
    ` crate::session::MAX_PENDING_LINKS `. Every frozen digest and every
    per-function census over such an item was therefore measuring a fragment of
    its own parameter list -- silently, because a short body is not an error.
    A brace is part of the signature when it is inside the parameter list, or
    when it opens a const-generic argument in the return type, which is exactly
    when it follows a `<`.
    """
    index = start
    paren = 0
    while index < len(text):
        char = text[index]
        if char == "(":
            paren += 1
        elif char == ")":
            paren -= 1
        elif char == ";" and paren == 0:
            return None
        elif char == "{":
            previous = text[:index].rstrip()
            if paren > 0 or previous.endswith("<"):
                index = _skip_balanced_braces(text, index)
                continue
            close = _skip_balanced_braces(text, index) - 1
            if close <= index or text[close] != "}":
                return None
            return index, close
        index += 1
    return None


def function_items(text):
    """Every balanced function/method body in lexical source order."""
    for match in FUNCTION_NAME.finditer(text):
        span = function_signature_and_body(text, match.end())
        if span is None:
            continue
        body_open, body_close = span
        yield match.group(1), text[body_open + 1 : body_close]


def function_headers_and_bodies(text):
    """Every balanced function/method header and body in lexical source order."""
    for match in FUNCTION_NAME.finditer(text):
        span = function_signature_and_body(text, match.end())
        if span is None:
            continue
        body_open, body_close = span
        yield (
            match.group(1),
            text[match.start() : body_open],
            text[body_open + 1 : body_close],
        )


CALL_LIKE = re.compile(
    r"(?P<callee>(?:\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*|\.[A-Za-z_]\w*))"
    r"\s*(?:!\s*)?(?:::\s*<[^(){};]*>)?\s*\("
)


def closed_call_roster(body):
    """Ordered call/call-like tokens, failing closed on indirect invocation."""
    if re.search(r"\)\s*(?:::\s*<[^(){};]*>)?\s*\(", body):
        return None
    return tuple(
        match.group("callee")
        for match in CALL_LIKE.finditer(body)
        if match.group("callee") not in {"if", "while", "for", "match"}
    )


RESOLVE_CALL_ROSTER = (
    ".slot_index", "ResolvePlan::begin", "ResolveProgress::Step",
    "ResolveProgress::Resolved", "Some", "Some", ".take",
    "fsring_sys::c4::ExReleaseRundownProtection", ".cast", "Err", "Ok",
    "core::ptr::from_ref", "ResolveProgress::Refused", ".releases_lock", "Some", ".take", ".release",
    ".releases_rundown", "Some", ".take",
    "fsring_sys::c4::ExReleaseRundownProtection", ".cast", "Err",
    "SessionAccessError::from_rejection", ".reason", ".step",
    ".access_rundown_ptr", "Some", ".succeeded", ".refused", "Some",
    ".access_rundown_ptr", ".refused",
    "fsring_sys::c4::ExAcquireRundownProtection", ".cast", ".refused", "Some",
    ".succeeded", "Self::lock", "NonNull::from", ".cast", "Some", ".succeeded",
    "Some", ".as_mut", ".refused", ".core_mut", ".validate_live", "Ok",
    ".succeeded", "Err", ".refused", "Some", ".as_mut", ".refused",
    ".cell_mut", "Some", ".matches_live_locator", ".succeeded", "Some",
    ".refused", "Some", ".as_mut", ".refused", ".cell_mut", "Some",
    ".owners_match", ".succeeded", "Some", ".refused", "Some", ".as_mut",
    ".refused", ".project_resolved_session", "Some", "Some", ".succeeded",
    ".refused", "Some", ".take", ".release",
    ".succeeded",
)

RESOLVE_CONTROL_CENSUS = {
    "if": 9, "else": 7, "match": 7, "loop": 1, "return": 3,
    "break": 0, "continue": 5, "while": 0, "for": 0,
}

PROCESS_SCAN_BODY = (
    "letregistry=guard.registry();letOk(cell_count)=u32::try_from(SESSION_CELL_COUNT)else{"
    "returnProcessScanStep::Complete;};ifindex>=cell_count||process.is_null(){"
    "returnProcessScanStep::Complete;}letresume_at=index.checked_add(1).filter(|next|"
    "*next<cell_count);letmutlock=unsafe{Self::lock(registry)};letmutmatched_without_action=false;"
    "letprepared=matchunsafe{lock.cell_ptr(index)}{Some(cell)=>matchunsafe{(*cell)"
    ".process_locator(process)}{Some(locator)=>{letcontext=unsafe{(*cell)"
    ".recorded_control_context()};ifletSome(context)=context{matchunsafe{"
    "prepare_native_terminal_claim(&mutlock,context,locator,TerminalRequest::ProcessLoss,)}{"
    "Ok(claim)=>Some(PreparedProcessScanAction{cell:unsafe{NonNull::new_unchecked(cell)},locator,"
    "action:ProcessScanAction::Winner{context,disposition:unsafe{claim.commit()},},}),Err(_)=>{"
    "matched_without_action=true;None}}}else{matchunsafe{(*cell).terminal_rendezvous"
    ".outcome_for_locator(locator)}{Some(fsring_core::session::TerminalRendezvousOutcome::Open)=>{"
    "matchunsafe{&mut(*cell).terminal_rendezvous}.r3_join_open_locked(locator){Ok(ticket)=>"
    "Some(PreparedProcessScanAction{cell:unsafe{NonNull::new_unchecked(cell)},locator,action:"
    "ProcessScanAction::Join(TerminalJoinGuard::ordinary(registry,locator,ticket),),}),Err(_)=>{"
    "matched_without_action=true;None}}}Some(fsring_core::session::TerminalRendezvousOutcome::"
    "Completed(result,))=>Some(PreparedProcessScanAction{cell:unsafe{NonNull::new_unchecked(cell)},"
    "locator,action:ProcessScanAction::Completed(result),}),Some(fsring_core::session::"
    "TerminalRendezvousOutcome::Blocked(blocked,))=>Some(PreparedProcessScanAction{cell:unsafe{"
    "NonNull::new_unchecked(cell)},locator,action:ProcessScanAction::Blocked(blocked),}),None=>"
    "matchunsafe{(*cell).authenticate_closed_fail_stop(locator)}{Some(crate::fence::"
    "ClosedFailStopAuthentication::Opaque(receipt,))=>Some(PreparedProcessScanAction{cell:unsafe{"
    "NonNull::new_unchecked(cell)},locator,action:ProcessScanAction::Opaque(receipt),}),_=>{"
    "matched_without_action=true;None}},}}}None=>None,},None=>None,};letaction=prepared.map("
    "|prepared|unsafe{prepared.commit()});unsafe{lock.release()};matchaction{Some(action)=>"
    "ProcessScanStep::Action(action),Noneifmatched_without_action=>ProcessScanStep::FailStop,None=>"
    "matchresume_at{Some(resume_at)=>ProcessScanStep::Skip{resume_at:Some(resume_at),},None=>"
    "ProcessScanStep::Complete,},}"
)

RESOLVER_PROJECTION_BODY = (
    "letcell=unsafe{self.cell_mut(index)}?;"
    "if!cell.matches_live_locator(locator){returnNone;}"
    "Some(unsafe{SharedSessionProjection::from_non_null(NonNull::new(cell.session)?)})"
)

# The checkpoint executor borrows the intact affine shell owner; no raw mirror
# crosses the registry unlock.  Freeze both complete owner-live scopes.
FENCE_CHECKPOINT_TEARDOWN_BODY = (
    "letlocator=owners.locator();letmutexecutor=unsafe{NativeCheckpointExecutor::new(registry,owners."
    "shell_owner(),locator,context,control)};letroster=unsafe{fsring_core::adapter::fence::run_checkp"
    "oint_roster(locator,&mutexecutor)};letcontrol=executor.take_unreleased_control();letpending_moun"
    "t_bind=executor.take_pending_mount_bind();drop(executor);let(winner,terminal,closing,shell,root)="
    "owners.into_parts();letreason=winner.reason();letresult=fsring_core::session::TerminalResult{rea"
    "son,fence_failures:0,};letauthenticated=matchAuthenticatedTerminalResult::new(winner,result){Ok("
    "authenticated)=>authenticated,Err(_)=>{unreachable!()}};matchroster{fsring_core::adapter::fence"
    "::CheckpointRosterOutcome::Complete(complete)=>{letabsence=matchR3AuthorityAbsence::from_embedd"
    "ed_artifact(locator){Ok(absence)=>absence,Err(_)=>{returnErr(incomplete_from_refusal(complete.in"
    "to_preparation_refusal(),None,terminal,authenticated,closing,control,shell,root,pending_mount_b"
    "ind,));}};letcomplete=matchcomplete.with_absence(absence){Ok(complete)=>complete,Err(_)=>{unreac"
    "hable!()}};Ok(R3CheckpointCandidate{complete,terminal,result:authenticated,closing,shell,root,}"
    ")}fsring_core::adapter::fence::CheckpointRosterOutcome::Refused(refused)=>{Err(incomplete_from_"
    "refusal(refused,None,terminal,authenticated,closing,control,shell,root,pending_mount_bind,))}}"
)

FENCE_TERMINAL_WINNER_DIGEST = "5af0249a60ec53193372e6e4752621881259a95f3087c0bc3568b9510840afec"

MOUNT_ACCESS_CALL_ROSTER = (
    ".as_ref", ".resolve", "Ok", "Err", ".status", ".view", ".identity",
    ".is_published", "Ok", "begin_mount", "Some",
    "crate::lifecycle::NativeMountedVpbOwner::from_mount_vpb",
    "RetainedAccessGuard::new", ".run", "Some", "drive_mount",
    "adapter::NativeVolumePlan::mount",
)

ENTER_ACCESS_CALL_ROSTER = (
    ".as_ref", ".resolve", "Ok", "Err", ".status", ".is_published",
    ".wake_ready_parked_waits",
    # Round-17 evidence E4: the length is judged by the validator after the
    # version and required flags, through core's bounded snapshot, and the
    # refusal completes with the validator's own status.
    "Some", "fsring_core::controldev::control_request_snapshot_len", "Some", ".get_mut",
    "core::ptr::copy_nonoverlapping", ".as_mut_ptr", ".len",
    ".validate_enter_request", "Ok", "Err", ".status",
    "enter_plan::NativeEnterPlan::begin", "Ok", "Err",
    "Err", ".session", "allow", "core::ptr::null_mut",
    "enter_plan::EnterProgress::Complete", "DrainFinish::Complete",
    "enter_plan::EnterProgress::ReleaseRole", "Some", ".as_mut", ".release_pending",
    "Ok", ".lock_ring", "DrainFinish::Status", ".release_pending",
    "crate::lifecycle::NativeRingGuard::release", "Ok", "Err", "DrainFinish::Status",
    "enter_plan::EnterProgress::Effect", ".effect", "matches", "Some",
    "write_enter_result", "Ok", "Ok", "Err", "Err", "Err", "matches", ".is_none",
    ".lock_ring", "Ok", "Some", ".grant_table_id", "Some", ".topology",
    ".acquire_grant_spin", "Some", "core::ptr::from_ref", ".cast_mut",
    ".grants_slice_mut", "GrantTable::attach", "Ok", "Some", ".as_mut", "Some",
    "core::ptr::null_mut", "Ok", "Err", "Err", "Err", "Err", "Err", "Ok",
    ".as_ref", ".is_null", "Err", "Err", "Ok", "Some", "classify_enter_cq", "Ok",
    "Err", "matches", "Ok", "perform_enter", "Ok",
    "enter_plan::EnterEffectOutcome::ReadinessObserved", "Some",
    "enter_plan::EnterEffectOutcome::CqClassified", "cq_result_state", ".succeeded",
    "Ok", "Err", "DrainFinish::Status", "Err", "DrainFinish::Unwind", ".failed",
    "enter_plan::EnterProgress::ClaimCredit", ".is_null", "DrainFinish::Status",
    "bind_credit", "Ok", "Err", "DrainFinish::Unwind",
    "enter_plan::EnterProgress::AdvanceCqHead", ".command", "DrainFinish::Status",
    "Some", ".cq_cursors", "Some", ".checked_add", ".store_cq_head",
    ".completed_release", "enter_plan::EnterProgress::RefreshCredit",
    "NotificationCreditV1::default", ".refresh", "write_credit_descriptor",
    ".is_err", "DrainFinish::Status", ".saturating_add",
    "enter_plan::EnterProgress::Pending", ".into_owned_wait", ".store_parked_wait",
    # The refusal is answered rather than discarded: a failed store takes the
    # IRP back out of the CSQ and fails it once.
    ".is_err", ".fail_unstored_parked_wait",
    "core::ptr::write",
    "DrainFinish::Complete", "core::ptr::write",
    "DrainFinish::Status", "DrainFinish::Unwind", "unwind_enter",
)
MOUNT_ACCESS_CONTROL = {
    "if": 2, "else": 3, "match": 1, "loop": 0, "return": 4,
    "break": 0, "continue": 0, "while": 0, "for": 0,
}
ENTER_ACCESS_CONTROL = {
    # `if` 15 -> 16 and `return` 8 -> 9: the readiness sweep's aggregate answer
    # is now read at this call site instead of being discarded, and a refused
    # deposit refuses the ENTER.
    # `if` 16 -> 17: a refused parked-WAIT store is answered here too.
    # Round-17 evidence E4: `if` 17 -> 16 (the up-front length refusal is gone),
    # `else` 8 -> 9 (two let-else: below the header, the bounded copy), `match`
    # 16 -> 17 (the validator's answer), `return` 9 -> 10 (three refusal exits
    # where there were two).
    "if": 16, "else": 9, "match": 17, "loop": 1, "return": 10,
    "break": 9, "continue": 0, "while": 0, "for": 0,
}

PRIVATE_AUTHORITY_MACRO = (
    "macro_rules!private_authority_seals{($($name:ident),+$(,)?)=>{"
    "$(struct$name(());)+};}private_authority_seals!("
    "PrivateControlContextLeaseAuthority,PrivateCloseContextRightAuthority,"
    "PrivateClosingCompletionObligation,PrivateNonPagedAllocationAuthority,"
    "PrivateNativeMountActivationAuthority,PrivateUnpublishedNativeSessionShellAuthority,);"
)

# Task 12 is a cross-crate affine grammar.  These are SHA-256 digests of
# whitespace-normalized, lexically masked *balanced Rust item bodies*.  A digest
# is used only after the parser has proved exact-one name/header/file identity;
# it therefore freezes the complete body without relying on a permissive regex.
TASK12_ITEM_GRAMMAR = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        (
            "struct",
            "NativeSessionOwner",
            "pubstructNativeSessionOwner<Shell>",
            "bf1e0792427f44358322e7ce6fca53cf60762791a0e7b74bf12481d294172f51",
        ),
        (
            "struct",
            "SessionRootReleaseRight",
            "pubstructSessionRootReleaseRight<RootRelease>",
            "411778688e115b0a6844805dda8d38aad6790f1a56edff400c59deeed95fc38b",
        ),
        (
            "struct",
            "SharedSessionProjection",
            "pubstructSharedSessionProjection<'access,T:?Sized>",
            "60e573b58ddb94fa187c5246984072e265e17fbced3e5d068615cf17b51f25cd",
        ),
    ),
    "driver/fsring-core/src/adapter/fence.rs": (
        (
            "struct",
            "R4DeletionOwnerChain",
            "pubstructR4DeletionOwnerChain<Tail,Shell,RootRelease>",
            "fb9c7fa6c59c0f01931cdaff4c744409b54ae59df1fb714c52fed2d645c1d02e",
        ),
        (
            "trait",
            "R4DeletionTailOps",
            "pubtraitR4DeletionTailOps",
            "c3c837fb57dcef554bf304ec4f32477280498ae089d40b186e46f9246504a78b",
        ),
        (
            "struct",
            "FenceDeletionReadiness",
            "pubstructFenceDeletionReadiness<Owners>",
            "4d3e2aded13ac3867d5172ac1b2533b984ab0da47acfac465732a0fa631b6659",
        ),
        (
            "struct",
            "FinalizerDeposit",
            "pubstructFinalizerDeposit<Owners>",
            "5e001cb596cbbb884b386df3e4d8ec66b6eae1f56d07ae124c33705a140a6350",
        ),
        (
            "struct",
            "R3FinalizerKick",
            "pubstructR3FinalizerKick",
            "48f11917d19d4223f6f02d00d8462307f723e745ad61d261d003da11fd48a36c",
        ),
        (
            "struct",
            "R3FinalizerRunningRight",
            "pubstructR3FinalizerRunningRight",
            "1b6da3d0c381a810b66f77a30dbbb904e8990fd9c0414297d4ab517754766519",
        ),
        (
            "struct",
            "R3FinalizerRunningPermit",
            "structR3FinalizerRunningPermit",
            "5cf43471fd9adf1d47823a8068d81c90a2e94d32cee709b2c4d39aaf9f54856f",
        ),
        (
            "struct",
            "TerminalRendezvousResetRight",
            "pubstructTerminalRendezvousResetRight",
            "2c2429a1a960f4b986fefd250c09495b4fa4be43460d244422d9314bf1406b37",
        ),
        (
            "struct",
            "PreparedDeleteExecutionPermit",
            "pubstructPreparedDeleteExecutionPermit",
            "9ea615f3dea9acf514d2410853a41385c8fc1a5115830ca2f58061adffcf2f1c",
        ),
        (
            "struct",
            "PreparedDeleteStorage",
            "pubstructPreparedDeleteStorage<Shell,RootRelease,NativeReset>",
            "f703c551a6484d3d657d04fbc29446760a5d9e7e754af4ac6f28c3574c8076f6",
        ),
        (
            "trait",
            "PreparedDeleteStorageOps",
            "pubunsafetraitPreparedDeleteStorageOps<RootRelease>:Sized",
            "026ca15921fed21f05c368d2206ab3f0e2bca4e7b40b5e630d2ea45eae8758f7",
        ),
        (
            "struct",
            "R3FinalizerCell",
            "pubstructR3FinalizerCell<Owners>",
            "bbe9ee1897a44bd333e5f62639e7ff3c657cbecc0c821eed160bb5a8a5c11046",
        ),
        (
            "struct",
            "DeletePreflightObservation",
            "pubstructDeletePreflightObservation",
            "dbf1154c82393ee7ab05fbee36dc190dde95d1e673d102f3fb985523e089228e",
        ),
        (
            "struct",
            "FinalDeleteRecord",
            "structFinalDeleteRecord",
            "3349dcb2bab4eebf518ad9a17e9ef23977bd143d650ec2e979f033243d7b1477",
        ),
        (
            "struct",
            "FinalDeleteResetBundle",
            "structFinalDeleteResetBundle<NativeReset>",
            "4f28d0eece595e92f793d9f83d210cd38fd1f02cad16d1b855b99850c7748600",
        ),
        (
            "struct",
            "FinalDeleteCursor",
            "pubstructFinalDeleteCursor<constNEXT:u8,NativeReset=()>",
            "efe32255bc05f81ecc0b8519c303666381f68fb97b95a77340a22027462dc06b",
        ),
        (
            "type",
            "PendingCompletedPublication",
            "pubtypePendingCompletedPublication<NativeReset=()>=FinalDeleteCursor<2,NativeReset>",
            None,
        ),
        (
            "type",
            "PendingOutcomeSignal",
            "pubtypePendingOutcomeSignal<NativeReset=()>=FinalDeleteCursor<4,NativeReset>",
            None,
        ),
        (
            "type",
            "PendingJoinerDrain",
            "pubtypePendingJoinerDrain<NativeReset=()>=FinalDeleteCursor<6,NativeReset>",
            None,
        ),
        (
            "type",
            "PendingAccessRundown",
            "pubtypePendingAccessRundown<NativeReset=()>=FinalDeleteCursor<7,NativeReset>",
            None,
        ),
        (
            "type",
            "PendingRundownDisposition",
            "pubtypePendingRundownDisposition<NativeReset=()>=FinalDeleteCursor<8,NativeReset>",
            None,
        ),
        (
            "type",
            "PendingFinalDeleteReset",
            "pubtypePendingFinalDeleteReset<NativeReset=()>=FinalDeleteCursor<9,NativeReset>",
            None,
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "struct",
            "FinalizerWorkItemContext",
            "structFinalizerWorkItemContext",
            "6dc33438129c51545597b756dcdfdf074b8a7cfd05436f07ab33ebb4704fc5eb",
        ),
        (
            "type",
            "NativeSessionOwner",
            "pub(crate)typeNativeSessionOwner=CoreNativeSessionOwner<NativeSessionShell>",
            None,
        ),
        (
            "type",
            "SessionRootReleaseRight",
            "pub(crate)typeSessionRootReleaseRight=CoreSessionRootReleaseRight<DriverRootRelease>",
            None,
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "struct",
            "CellResetRight",
            "pub(crate)structCellResetRight",
            "08df717df5c875ddb03361566d2e0408884b699e682be232ca6f80cbeca3190a",
        ),
        (
            "struct",
            "PreparedCellResetRight",
            "pub(crate)structPreparedCellResetRight",
            "e0737ad8d3e362cf2314775e6cbd2f981e3205db336b9168a46fae65e8d5a691",
        ),
        (
            "struct",
            "R4DeletionTail",
            "pub(crate)structR4DeletionTail",
            "222cb0d5ca8ff1a0307e4bb44a940e14d984da695e7a6b51db9c9012a69b31fb",
        ),
        (
            "type",
            "R4DeletionOwners",
            "pub(crate)typeR4DeletionOwners=R4DeletionOwnerChain<R4DeletionTail,NativeSessionShell,DriverRootRelease>",
            None,
        ),
        (
            "type",
            "FenceDeletionReadiness",
            "pub(crate)typeFenceDeletionReadiness=CoreFenceDeletionReadiness<R4DeletionOwners>",
            None,
        ),
        (
            "type",
            "FinalizerDeposit",
            "pub(crate)typeFinalizerDeposit=CoreFinalizerDeposit<R4DeletionOwners>",
            None,
        ),
        (
            "type",
            "R3PreparedDeleteStorage",
            "typeR3PreparedDeleteStorage=PreparedDeleteStorage<NativeSessionShell,DriverRootRelease,PreparedCellResetRight>",
            None,
        ),
        (
            "struct",
            "PreparedDelete",
            "pub(crate)structPreparedDelete",
            "a46850755b3eac55d2eb196102b770622a63d9bbfa6dca3040a069360c2bcba7",
        ),
    ),
}

TASK12_TOKEN_NAMES = (
    "NativeSessionOwner",
    "SessionRootReleaseRight",
    "R3FinalizerKick",
    "R3FinalizerRunningRight",
    "R3FinalizerRunningPermit",
    "TerminalRendezvousResetRight",
    "CellResetRight",
    "PreparedCellResetRight",
    "PreparedDeleteStorageOps",
    "PreparedDelete",
    "SharedSessionProjection",
    "FinalizerDeposit",
)
TASK12_TOKEN_CENSUS = {
    "driver/fsring-core/src/adapter/fence.rs": (
        7,
        7,
        6,
        9,
        6,
        5,
        0,
        0,
        3,
        0,
        0,
        7,
    ),
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        7,
        6,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        2,
        0,
    ),
    "driver/fsring-core/src/session.rs": (
        3,
        3,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/fence.rs": (
        12,
        7,
        0,
        3,
        0,
        0,
        5,
        7,
        0,
        5,
        0,
        7,
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        11,
        10,
        3,
        1,
        0,
        0,
        0,
        2,
        1,
        0,
        5,
        1,
    ),
}

TASK12_BODY_GRAMMAR = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        (
            "native_delete_mirror_matches",
            ("6388ac65a622cd5482e9d68d079cb52d85c30491d50ddbf5313b1b095820d698",),
            "Task 12 delete mirror Deleting phase",
        ),
        (
            "bind_native_session_owner",
            ("bd63a423e2fc981550e9e58b45d78f26573ef9d594acf52e66db1272a3ce6ed2",),
            "Task 12 protected authority surface",
        ),
        (
            "bind_session_root_release",
            ("a482d07be7b20af47153dc90cda164e0d4aaf482aab02de280192f13024525ab",),
            "Task 12 protected authority surface",
        ),
        (
            "execute_prepared_delete_payloads",
            ("497c07368d565b4a107a1c75e187868f236bda7003d7830254273101de3e3812",),
            "Task 12 prepared-delete payload order",
        ),
    ),
    "driver/fsring-core/src/adapter/fence.rs": (
        (
            "run_r3_prepared_delete_suffix",
            ("aca7701a9684a1e3f8c073a05c1884fd85d2f8827639168c5609666f80c803e5",),
            "Task 12 final-delete suffix order and post-destroy access",
        ),
        (
            "finish_run_and_reset",
            ("1f796a4a4a2db5208e92a1175ade07447966736e48cfc7282f33fa6f723046e9",),
            "Task 12 running-locator reset brand",
        ),
        (
            "into_prepared_delete_storage_prevalidated",
            ("4c582b85abc9e0476d2f1e2ca07111a5ec9237b56fcd84d4fbc4cf118cbc841c",),
            "Task 12 running-locator reset brand",
        ),
        (
            "validate_final_delete_core",
            ("852a5992a77a127756ea86c2459071966648c0751479e2ad1f739d21f8ef31d6",),
            "Task 12 authentic core-delete observation order",
        ),
        (
            "execute",
            ("82af4e6bcfa30482f1ead633ba8f8bc099fd64f927e5394cd4851a36a52528ba",),
            "Task 12 no post-destroy access",
        ),
        (
            "decide_delete_preflight",
            ("3d18bcac3cff44b8597ce9ca493cff4be02f1d139b7fc7f0fd7fea6896f6aa10",),
            "Task 12 open join admission observation",
        ),
        (
            "finish_after_reset",
            ("fe1c100c4f4f9d30386fbb986a770c7286e7b5780660512a526e93e87cac20b1",),
            "Task 12 terminal-reset locator brand",
        ),
    ),
    "driver/fsring-core/src/session.rs": (
        (
            "deactivate_after_delete_prepared",
            ("3452579849170054a5c98c7b6b11675a6960882df0bf92ee191f0908b09c5ff7",),
            "Task 12 terminal-reset locator brand",
        ),
        (
            "validate_finish_delete_with_mount",
            ("a385eda047fd149da7cbf67ac90a60205e66478f28482d9b6d48946aaa78c015",),
            "Task 12 authentic core-delete observation order",
        ),
        (
            "prepare_finish_delete_with_mount",
            ("84ea5f1c1242d2bba38649d326e01eabd1c6be22ef68cdf33d450461bc63c580",),
            "Task 12 authentic core-delete observation order",
        ),
        (
            "finish_delete",
            ("5b77f9cb762896440f09b4c370afef3859f52b7830cfa36e2fe7180bac730ad1",),
            "Task 12 prevalidated finish-delete",
        ),
    ),
    "driver/fsring-fsd/src/control.rs": (
        (
            "binding_is_closing_live",
            ("01f4aac19941a34513b5f1262a5567183c235ebbf29999023987755c9cea8dfe",),
            "Task 12 exact ClosingLive and owned lease",
        ),
        (
            "completed_record_is_absent",
            ("3065801d3358d7bfe72b9d5a6784472a5614fc31dee4d35dae6295e51c0be6d2",),
            "Task 12 completed-slot observation",
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "closing_live_context_and_lease",
            ("709a8e6e7f8be4fb490d23f3d36f02cad58a35720dc577b13d50613f08719f22",),
            "Task 12 exact ClosingLive and owned lease",
        ),
        (
            "completed_record_is_absent",
            ("bedbb58eae823821adadbaba0c7bbba97ed6287b749605c5a08938b9dc611a61",),
            "Task 12 completed-slot observation",
        ),
        (
            "blocked_observation",
            (
                "0a39b22daf2fcbcf6c55944512a2f550ef40f317e07983f1ec943fe28e022a75",
                "40f5e8aabe8e1e479dcf39e48ae06beef2ff573df93aecebd1d73b35a72535a3",
                "a02df3b71d13b8a4c4568fc3f1e7ed0214231fa462863b03cabc5792d6dc60d9",
            ),
            "Task 12 blocked observation authority",
        ),
        (
            "prepare_final_delete",
            ("c9771cf7675e480542131415b0c794f1bbbd2a2e2b688a9bd5e44a732b1e47d5",),
            "Task 12 authentic core-delete observation order",
        ),
        (
            "run_queued_finalizer",
            ("de83139ff6e0bb0fa27d5f6bd469989e26a7cbb4924d3f58769cd62b7035d3ad",),
            "Task 12 exact-cell finalizer callback",
        ),
        (
            "execute_prepared_delete",
            ("3d94363ae79794784474d74f674900b2eda75664fd41cb17c15dfd44d6a205b9",),
            "Task 12 final-delete join/event order",
        ),
        (
            "release_control_strong_ref",
            (
                "92680ca0965de50ece41179a40de51858bd6c08c97776166b0c6d26078354884",
                "afc5550243b4c357a4b4d941941a3daba484006afd34c82d6e719bc9e2ccf3e4",
            ),
            "Task 12 sole production finalizer kick sink",
        ),
        (
            "release_strong_and_deposit",
            ("2e74d803d7ec0690914568c65a183d27120ba591fb41c2fa4354c376aa81915c",),
            "Task 12 replaced projection body closure",
        ),
        (
            "publish_completed_generation",
            ("e922b25b1c150be383c049f528d8f05e89c52d153d2ab4f2f5393f4d2e79d6af",),
            "Task 12 replaced projection body closure",
        ),
        (
            "native_wait_control_and_access_rundown",
            ("34114dd636b8f7309114fd25bec59ebe112ec5e0e7c862c87a6bdf10b6cecf77",),
            "Task 12 control-and-access rundown wait pairing",
        ),
        (
            "queue_finalizer",
            ("b887cbe09f6355e6733aaf6930958a703343b6582054cce2f6f8f2721a7e0254",),
            "Task 12 queue_finalizer is the sole kick sink",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "destroy_shell_then_release_root",
            ("dd9c402897a784676942d38604f3857afded3f9b86cca8ddfcd9708448c115d7",),
            "Task 12 prepared-delete payload order",
        ),
        (
            "initialize_cells_in_place",
            ("a49e7d12bd2757f4843d55d7bf0be6848cb327a310e7cc878d6b1c2db20003e0",),
            "Task 12 finalizer queue boundary",
        ),
        (
            "initialize_work_items",
            ("f4afb1c73561889f46433f8424de767b94239bd1c0900fecef5a386f667391eb",),
            "Task 12 finalizer queue boundary",
        ),
        (
            "store_deposit_and_mint_kick",
            ("a1b2c083206369fd7c14e9b0ad7f879d379aaaf739d924c393029ae993667421",),
            "Task 12 native Deleting transition",
        ),
        (
            "delete_preflight_observation",
            ("5125ad5da3e14058dde5c6d49c455b26c877b652c2face9e736e7dd103867f09",),
            "Task 12 terminal-event observation",
        ),
        (
            "queue_cell_finalizer",
            ("4c2d5a1adbfe5e5ee489ea69888787f9124c74d6b50b2580d16eacce9174d82f",),
            "Task 12 finalizer queue boundary",
        ),
        (
            "fsring_finalizer_callback",
            ("03e2555337464434efa105f20e73aeb0c803dbb0803c74451e94c7cd0132aace",),
            "Task 12 finalizer callback",
        ),
        (
            "take_deposit_and_run_for_callback",
            ("f98830fe8332e1395caea7188004e7857c081e17c9f428d2b2ef10e9456e063e",),
            "Task 12 exact-cell finalizer callback",
        ),
        (
            "reset_after_delete",
            ("f76a8af3ee6b656c55eff6fae0735af9a09fa36be0abc6c60908584238b35f5c",),
            "Task 12 final-delete cursor/reset bundle",
        ),
        (
            "reset_cell_and_publish",
            ("4f325d8675e9bf6a6f31182fa957a3d28d8d729f31ff664fc88e334ed5fd210a",),
            "Task 12 final-delete cursor/reset bundle",
        ),
        (
            "complete_cell_access_rundown",
            ("52e46063651abb04813f1c352b15635c5322031ee3a904819d0dac0d0a326fee",),
            "Task 12 rundown DDI IRQL boundary",
        ),
        (
            "reinitialize_cell_access_rundown",
            ("ec8942e88d4f5955d8c40b3bdb8c97128c97e1a165bd35756b252c97fb40e48c",),
            "Task 12 rundown DDI IRQL boundary",
        ),
        (
            "reinitialize_access_rundown",
            ("b41d31b14512a0e3ff1ee335be6dfd948d542194e6cedc5ed1696e2b59d6bf4b",),
            "Task 12 rundown DDI IRQL boundary",
        ),
        (
            "close_global_admissions",
            ("9a7752fcd6c84e2a5ef26e9090ee1931a1f5d6008eea2cc42d848b814be50896",),
            "Task 12 process-callback rundown IRQL boundary",
        ),
        (
            "prepare_native_terminal_claim",
            ("dd3fe26639e255f04e7ed25a8f1e697aef052356abc3247ea11c9ead434d2a75",),
            "Task 12 exact native terminal claim",
        ),
        (
            "wait_for_visibility_resolution",
            ("db9bda4f4671c5ff0344d1fcf5c56eac53717946e7047699317391df1ac3689f",),
            "Task 12 replaced projection body closure",
        ),
        (
            "wait_for_unload_visibility",
            ("1a9e4299b4cead61a6b3b2937b5bc35b0019a9c9c03459d07369fa4148e9d61c",),
            "Task 12 unload visibility authentication",
        ),
        (
            "wait_joiners_drained",
            ("b5a0bb58e20696b806028989ea7af65c77b322bccce2320d534897d5f87a5217",),
            "Task 12 replaced projection body closure",
        ),
    ),
    "driver/fsring-fsd/src/session.rs": (
        (
            "install_staging",
            ("aa5510eca816fc73d2d03c60a4f744c1d2c52fa132b03fd057cd9ba747a4faa1",),
            "Task 12 replaced projection body closure",
        ),
        (
            "publish_locked_suffix",
            ("67814096d09fa33c2d8ca9c2f8ec92aff0cf1e4991120a422d02eed5a353d4ad",),
            "Task 12 replaced projection body closure",
        ),
    ),
    "driver/fsring-fsd/src/driver.rs": (
        (
            "unload",
            ("223682eac66cd6213b1cc618df5e0687730b493ef2601921dd72ed00643fbe5a",),
            "Task 12 process-callback rundown IRQL boundary",
        ),
        (
            "perform",
            # Regenerated (round 15) after `PublishProvider` gained the write
            # of the one dispatch-visible root field, ahead of the publish
            # that clears DO_DEVICE_INITIALIZING.
            ("eb719dcff5bcd4e302581249cf4ff399303f0453c9d1a8b461c3d30e7651314c",),
            "Task 12 finalizer queue boundary",
        ),
    ),
    # Task 27. Ten `pending_enter.rs` and two `volume.rs` mutants SURVIVED the
    # first honest measurement of this suite: the auditors carried no rule that
    # could see a reordered publication, a completion thunk, a fabricated CSQ
    # receipt, a wrapped epoch, a fail-stop reported as drained, or a mounted
    # delete that stopped reading VPB_MOUNTED. Each body below is the one the
    # surviving edit lands in, and each digest was regenerated through this
    # module's own `strip_noncode`/`function_bodies` pair.
    "driver/fsring-fsd/src/pending_enter.rs": (
        (
            "csq_insert_irp",
            ("faf7b82b2f40459cafac68866fe584d9b7455de56efb8a2927e398b4617e52ea",),
            "Task 12 staged CSQ insert publishes the IRP before its axis",
        ),
        (
            "observe_insert_outcome",
            ("de06ca370f67b4d5094eac24e848f0a5ad213585ba4986504847d7711ffbd36a",),
            "Task 12 staged CSQ insert receipt is never fabricated",
        ),
        (
            "csq_complete_canceled_irp",
            ("cb8a987130f76baae8d1a99125c0c5736ca890cb2b1bffdff62df1d7889dcba2",),
            "Task 12 cancelled-IRP completion is not a thunk",
        ),
        (
            "complete_parked_irp",
            ("3614d8739958eba19c82717838dcccee71e78bf24325baafc867331b580b32ec",),
            "Task 12 parked-IRP completion is not a thunk",
        ),
        (
            "initialize_staged_pending_slot",
            ("61447fa48feec36df65e54fd899e2d355ba300995f05a581cb0f8ee7bdb2f94c",),
            "Task 12 staged pending slot epoch, timer and fail-stop initialisation",
        ),
        (
            "observe_pending_for_unload",
            # Regenerated (round 15): the three invariant failures now leave
            # the hold as a value and fire after `unlock.release()`, because
            # `panic = "abort"` means the guard's `Drop` never runs.
            ("5f87dd150a81633dbbf4704bf4a6e3ebe6ad13a6714e655755ef350fedc03a17",),
            "Task 12 unload observation preserves a publication fail-stop",
        ),
        (
            "wait_contexts_drained",
            ("d39e439e32431521efc12123f0440b307655f5b7260ed609420ca2e205ce0210",),
            "Task 12 unload wait separates fail-stop from drained",
        ),
        (
            "perform_pending_effect",
            ("6a8cf286c33f50fa0430d08b65002bcef740042050cdb2575b810fd391971bf9",),
            "Task 12 DPC-exit wait skips only on a proved Quiesced",
        ),
        (
            # The rendezvous itself. It reads `timer_state` under the slot lock,
            # clears a previous generation's standing signal there, and returns
            # only on an observed `Quiesced` -- a single wait satisfied by a
            # stale set is what let a pass free an arena a live KDPC still
            # named. Frozen so removing the clear, the re-read, or the loop is
            # a change something can see.
            "wait_pending_dpc_exit",
            ("d5f80291912c7094df150d0b0df3548fd862b379b188982fea32acb450e7a9f6",),
            "Task 12 DPC-exit wait proves Quiesced under the lock",
        ),
        (
            # Unload's timer quiescence, and the only reason the arena free
            # below it is safe: `wait_contexts_drained` reads `slot_state` and
            # says nothing about a queued KDPC.
            "quiesce_pending_timer_for_teardown",
            ("5cc7bd51079b5ec1e0d1772cce58d356752ee07e80a46931ddbecb261f13df7d",),
            "Task 12 unload cancels the timer and waits the DPC out",
        ),
        (
            "release_pending_runtime",
            ("639120a8a3083a46ac6dd0d61c5548bfb12659a32299841d59e66c97d916e968",),
            "Task 12 unload quiesces every slot before the arena is freed",
        ),
        (
            # Every ring is offered its Fence wake. Returning at the first
            # refusal left every higher ring without one.
            "deposit_fence_wakes",
            ("7b36f4d1f1f9f671bdcd9928e0506534738e924efbfbdf0c81253c23aaa768ce",),
            "Task 12 fence wake sweep reaches every ring",
        ),
        (
            # The closing half of an install, checked rather than discarded. A
            # `parked_plan` left behind made every later park on this ring
            # refuse.
            "release_install",
            ("05681800c3871a1950ac430422bdb73a06f0360965f78adbab19369b1c59f342",),
            "Task 12 install release clears and reports every bound value",
        ),
        (
            # `Closing` is not a refusal: an install already delivering its
            # terminal needs no further wake. Without that classification every
            # completing ring reported a refusal, ENTER would refuse routinely,
            # and the aggregate the sweeps now report would mean nothing.
            "wake_deposit_accepted",
            ("ae89c38aedfe0c8bb7007d4f2edae6f81329503d09635a51e211adf31ad7201d",),
            "Task 12 a closing install is not a refused wake",
        ),
        (
            "deposit_locked_wake",
            ("879a035e5a12f8e21eb3858308f499b70cb71679f8383d3f6116694d7f5bf3e1",),
            "Task 12 one wake classification, shared by both sweeps",
        ),
        (
            # The plan comes out before the receipt is minted and the one-shot
            # terminal contended, so a missing plan is a refusal rather than a
            # stranded IRP with a spent terminal.
            "take_arbitrated_completion",
            ("18abeb14c5e59b4e9cba994cc00eefc99fa02421df5825e6dd084be04d496f41",),
            "Task 12 arbitration takes the plan before it spends anything",
        ),
        (
            # `KeSetTimer` runs inside the hold that published `Armed`, so
            # `Armed` means "in the timer queue" -- the fact `KeCancelTimer`'s
            # BOOLEAN is interpreted against.
            # Re-frozen in round 17 for N16-3: the refused-handoff arm stopped
            # being collapsed with the committed one. The property this digest
            # guards -- `KeSetTimer` inside the hold that published `Armed` -- is
            # unchanged, and was re-read against the new body before refreezing.
            "park_wait_enter",
            ("e5d491f02ced22f3671e9a3da3f0338787685c2d36ad403596d0b9d849d6e9f0",),
            "Task 12 park arms and queues the timer in one lock hold",
        ),
    ),
    "driver/fsring-fsd/src/volume.rs": (
        (
            "read_verify_under_lock",
            ("810822ea36b28c5b73ff4390e6598bb7e94b057af06eab0b80b07e21be72ff2c",),
            "Task 12 mounted delete requires the VPB_MOUNTED flag",
        ),
        (
            "delete",
            ("4880075b3134e3146fad3a196a1a0d7a50a2839eea8b8b6d01c5fff21a622868",),
            "Task 12 VDO delete is the last touch of that device",
        ),
    ),
}

TASK12_IMPL_GRAMMAR = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        (
            "impl<Shell>NativeSessionOwner<Shell>",
            "07f7c073a87c3858be022188b5fbbd5ca74489efada02829523ddffbed3113ba",
        ),
        (
            "impl<Shell:NativeSessionSharedOps>NativeSessionOwner<Shell>",
            "5c231a46a349c418415bdf330df9a2066422184f10ce17df732d800805ed6ac9",
        ),
        (
            "impl<RootRelease>SessionRootReleaseRight<RootRelease>",
            "07f7c073a87c3858be022188b5fbbd5ca74489efada02829523ddffbed3113ba",
        ),
        (
            "impl<'access,T:?Sized>SharedSessionProjection<'access,T>",
            "64b639dfb6f2cfe2e6fcddd743efaa4380685fcc9960f3d7ad0b4e90bda1cdf1",
        ),
    ),
    "driver/fsring-core/src/adapter/fence.rs": (
        (
            "implR3FinalizerRunningRight",
            "07f7c073a87c3858be022188b5fbbd5ca74489efada02829523ddffbed3113ba",
        ),
        (
            "implTerminalRendezvousResetRight",
            "c620d07e3800c1ac13c49e45158ccee45cc20e2cb4f53e1c360d2b025f336090",
        ),
        (
            "impl<Owners>FenceDeletionReadiness<Owners>",
            "3fd64ed0ce7677726e5530c0acf09ede85e2b8c3a9b757adf991a7c3fe06d4c0",
        ),
        (
            "impl<Owners>FinalizerDeposit<Owners>",
            "46acf51b8c21ef679542d2e61de0aa0fb3c504ec50e94bbeab9d55da8555e9f0",
        ),
        (
            "implR3FinalizerKick",
            "920ea14eaaef1fc62327263545a65ddae31d0f37645233b10af41c714f537beb",
        ),
        (
            "implFnOnce(u32)->Option<&'cellmutR3FinalizerCell<Owners>>,)->Option<(FinalizerDeposit<Owners>,R3FinalizerRunningRight)>",
            "48c5c6aa65e065ca1e9e6da3efce8e2b75bbd1535a448ae5febd06a6a35f715d",
        ),
        (
            "impl<Owners>R3FinalizerCell<Owners>",
            "d1bbab23ba0feb2fcc7e2770003ac9436a0454f83257280c359ad4fab800528c",
        ),
        (
            "implPreparedDeleteExecutionPermit",
            "4e47b4d7894f3f1d29279caa4f592803148d284151fe174957e0b4408beb7b4f",
        ),
        (
            "impl<Tail,Shell,RootRelease>FenceDeletionReadiness<R4DeletionOwnerChain<Tail,Shell,RootRelease>>",
            "c6150a2b88ab8e4c4babdfc35dee3b84db972f6daf15716b61631657c058b048",
        ),
        (
            "impl<Tail,Shell,RootRelease>FenceDeletionReadiness<R4DeletionOwnerChain<Tail,Shell,RootRelease>>whereTail:R4DeletionTailOps,",
            "90bf83ac94d859871ed2c118a66d12ff6786fa903cac162309e51644afb29619",
        ),
        (
            "impl<Tail,Shell,RootRelease>FinalizerDeposit<R4DeletionOwnerChain<Tail,Shell,RootRelease>>whereTail:R4DeletionTailOps,",
            "d44240df4d36864264c99543ea728dcbdb45261cff0111639c72c38e545203c4",
        ),
        (
            "impl<Shell,RootRelease,NativeReset>PreparedDeleteStorage<Shell,RootRelease,NativeReset>whereShell:PreparedDeleteStorageOps<RootRelease>,",
            "f35fd88417b6683d3884ed80ce05a513f0641fa9f1f615dd5e1225075e198f0f",
        ),
        (
            "implDeletePreflightObservation",
            "0b61f06753175559e96f38da569f244db95b7e64aef45b701ebc80cc89582ecc",
        ),
        (
            "impl<constNEXT:u8,NativeReset>FinalDeleteCursor<NEXT,NativeReset>",
            "07f7c073a87c3858be022188b5fbbd5ca74489efada02829523ddffbed3113ba",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<2,NativeReset>",
            "0bb92df1b374a78cbb07b0dbae6eada63deb1be32a218d10cae4a53008bc2268",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<4,NativeReset>",
            "a107d7dda362887b6aa30311973643c4e1aee6f0989c76c00405c7d721e142a3",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<5,NativeReset>",
            "76d0a36b7b1e9612e03261cf6897ecaa5364b2ab19b308be510871286fcf6608",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<6,NativeReset>",
            "8dd8447be81923201442f5f994a4893227b291c7e7ba860a136a38571637a350",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<7,NativeReset>",
            "cd3091036fd2261c6002db1fc2f46867d22cb12a7826590cc134bd90a2aaa838",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<8,NativeReset>",
            "8d4ec30e48eb7e80b112834e8a987413d56f51a010077498cd6f7b010e40c0cb",
        ),
        (
            "impl<NativeReset>FinalDeleteCursor<9,NativeReset>",
            "8613b9e4e3797fb71ce9ecbd97496b018a6337b5b03de96e7a69689b6b24de8e",
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "implCellResetRight",
            "27d6601f4b57d25a6cc5734acac79b0c2e622c146ef2c7185375b65dafa1faac",
        ),
        (
            "implPreparedCellResetRight",
            "02f223870cb52b14f8d379fef5d0f7075de192f0adb25c09213ee9842c2a9fd7",
        ),
        (
            "implR4DeletionTailOpsforR4DeletionTail",
            "6e2789ca1f85956d9db29197570b3087e65a338ddcf68d5d23217462e85ea714",
        ),
        (
            "implR4DeleteFailStopVisibilityforFinalizerDeposit",
            "5a8415fe74cd8a44b38a36b891033d1de0b12cf49df088879eafa02073c3dc4d",
        ),
        (
            "implNativePreparedDeleteOps",
            "7e37cf60fb5348c8acaab3521cb3053ef41b3dc8bd5246213672c2285cab4c63",
        ),
        (
            "unsafeimplR3PreparedDeleteNativeOps<PreparedCellResetRight>forNativePreparedDeleteOps",
            "143f386d9b0c685df51a1d962ff6cfe023f59d16c09da24957659738fe8abda7",
        ),
        (
            "implPreparedDelete",
            "bf7305cd0792a9c4c438feb0681f77e8de00dcdb6d34041ea19da456318c7dd1",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "implUnpublishedNativeSessionShell",
            "3ca4287b58d58f97f598c784179d799d7d0926e9880b07a687753539e10e5bd8",
        ),
        (
            "implNativeSessionSharedOpsforNativeSessionShell",
            "cfb29f027e3ffa669fd8699a8a808556275a0f3237229cc524631c626cb2c3f5",
        ),
        (
            "implDriverRootRelease",
            "5a6965f1c891d02b48c2c365f30a01d110a2f6d9051a5a54d08185f9684f814e",
        ),
        (
            "unsafeimplfsring_core::adapter::fence::PreparedDeleteStorageOps<DriverRootRelease>forNativeSessionShell",
            "bbbdb210e82e5c134a9995a9b0768da2729c4548560acfb91411bc03ec700b56",
        ),
        (
            "implAdmittedR3FinalizerKick",
            "6e239a2a3430e0d873113f833b687df34186e011af5811d1af558a6fc417f73f",
        ),
    ),
}

TASK12_IMPL_MARKERS = (
    "NativeSessionOwner",
    "SessionRootReleaseRight",
    "SharedSessionProjection",
    "R3FinalizerRunningRight",
    "TerminalRendezvousResetRight",
    "FenceDeletionReadiness",
    "FinalizerDeposit",
    "R3FinalizerKick",
    "R3FinalizerCell",
    "PreparedDeleteExecutionPermit",
    "PreparedDeleteStorage",
    "DeletePreflightObservation",
    "FinalDeleteCursor",
    "CellResetRight",
    "PreparedCellResetRight",
    "R4DeletionTail",
    "PreparedDelete",
    "UnpublishedNativeSessionShell",
    "NativeSessionShell",
    "DriverRootRelease",
)

TASK12_SEAM_TOKEN_NAMES = (
    "binding_is_closing_live",
    "lifetime_is_cell_owned",
    "completed_record_is_absent",
    "admitted_for_locator",
    "outcome_for_locator",
    "KeReadStateEvent",
    "validate_final_delete_core",
    "prepare_final_delete_core",
    "decide_delete_preflight",
    "take_deposit_and_run_for_callback",
    "take_deposit_and_begin_run",
    "take_deposit_and_run",
    "blocked_observation",
    "queue_cell_finalizer",
)
TASK12_SEAM_TOKEN_CENSUS = {
    "driver/fsring-core/src/adapter/fence.rs": (
        0,
        0,
        5,
        0,
        0,
        0,
        1,
        1,
        1,
        0,
        2,
        0,
        0,
        0,
    ),
    "driver/fsring-core/src/session.rs": (
        0,
        0,
        0,
        3,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/boot.rs": (
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/control.rs": (
        1,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/fence.rs": (
        2,
        2,
        5,
        0,
        0,
        1,
        1,
        1,
        1,
        1,
        0,
        0,
        6,
        1,
    ),
    "driver/fsring-fsd/src/lib.rs": (
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        0,
        0,
        0,
        1,
        6,
        10,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        1,
    ),
    "driver/fsring-fsd/src/session.rs": (
        0,
        0,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
}

# Task 5's durable fail-stop storage is a second closed grammar beside the
# existing Task 12 delete carrier.  These items include the core-owned Stored
# receipt boundary, the private native packet/slot, and the only opaque winner
# handoff.  Exact impl digests below close every method on those carriers, so a
# retry, projection, clear, or alternate visibility transition cannot be
# appended behind an unchanged canonical method.
TASK5_FAIL_STOP_ITEM_GRAMMAR = {
    "driver/fsring-core/src/session.rs": (
        (
            "enum",
            "PrivateTerminalRendezvousState",
            "enumPrivateTerminalRendezvousState",
            "d4107ab5dd99b51458487b0b3f91600d2e3bf2c0f0f5d184d8d31781e0d029e7",
        ),
        (
            "enum",
            "ControlBindingState",
            "pubenumControlBindingState",
            "eae3d9c19930a57474cf740b5bf75bce6fd35e782a8fd5bf8a3d8c8bba7e145a",
        ),
        (
            "enum",
            "StoredFailStopPublicationMode",
            "pubenumStoredFailStopPublicationMode",
            "4a3b1054a3fe45e068fa388938e9b5021792d08aa513b830c8bccc3b277775dc",
        ),
        (
            "enum",
            "StoredFailStopResolution",
            "pubenumStoredFailStopResolution",
            "55f0f8ad2493e3648820c5cc1f88d98401cfca1d26d28312a8b78c83f17eabb7",
        ),
        (
            "enum",
            "DurableFailStopObservation",
            "pubenumDurableFailStopObservation",
            "f64a621113e40e34bd45a41bae6581a49ce468fef1585190e175b3982c3d8be7",
        ),
        (
            "enum",
            "DurableFailStopVisibility",
            "enumDurableFailStopVisibility",
            "a5223fc124f4da21b91b000f45a99e058c83889f32c2e9256ccc835f4526658b",
        ),
        (
            "enum",
            "DurableFailStopSlotState",
            "enumDurableFailStopSlotState<Packet>",
            "ebca8492881ad92517fe8bb4bd030b81d0a86b939fb57f3d8685a3705608bbc7",
        ),
        (
            "struct",
            "DurableFailStopSlot",
            "pubstructDurableFailStopSlot<Packet>",
            "15d46b75c5f3ad1ebcf0a307762768ba292aa47913a1d7ca685f439dd952077a",
        ),
        (
            "struct",
            "StoredFailStopReceipt",
            "pubstructStoredFailStopReceipt<'stored>",
            "ff7874e31d4459b8bb4a61c11428280d3e3d2144b694ae8ffb072f560d7c3902",
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "enum",
            "R3FailStopPayload",
            "enumR3FailStopPayload",
            "dfb8bcac4d61e7ff4ea56d752a84de8cf06dfe7bee851b6fae6b482a503b645e",
        ),
        (
            "struct",
            "R3FailStopPacket",
            "pub(crate)structR3FailStopPacket(R3FailStopPayload)",
            None,
        ),
        (
            "struct",
            "R3FailStopSlot",
            "pub(crate)structR3FailStopSlot",
            "d2c31a890ce4522dd20052cccd2c75d337f6cb7807025e0e3f0ea7b2f37210ee",
        ),
        (
            "enum",
            "R3FailStopObservation",
            "pub(crate)enumR3FailStopObservation",
            "f64a621113e40e34bd45a41bae6581a49ce468fef1585190e175b3982c3d8be7",
        ),
        (
            "enum",
            "ClosedFailStopAuthentication",
            "pub(crate)enumClosedFailStopAuthentication",
            "58ebaec162e7a736d44e511a883b91069c0158a22be68b69963d4facdb50d2c1",
        ),
        (
            "struct",
            "OpaqueFailStopReceipt",
            "pub(crate)structOpaqueFailStopReceipt",
            "2a5d3f8275f3ebc8e1fd824653aac1828377c64fcb25a3091d4066112742d4e6",
        ),
        (
            "enum",
            "R3FailStopVisibility",
            "pub(crate)enumR3FailStopVisibility",
            "53f8cf8281804f6b5828c1fc0adf4bb2a279b744a81c2c10207e6abbfdab265a",
        ),
        (
            "struct",
            "R3FailStopReentryGuard",
            "pub(crate)structR3FailStopReentryGuard",
            "9447974ceb4ae50040e10d6103032208820a4abb338d8743d66f5ab07ef1044f",
        ),
        (
            "struct",
            "R4CheckpointCandidate",
            "pub(crate)structR4CheckpointCandidate",
            "2d572e03a3e05dab09188c847feadf87aeeaabb3ccc158268ef0e53b6b09312e",
        ),
        (
            "struct",
            "FenceIncompletePacket",
            "pub(crate)structFenceIncompletePacket",
            "8ad8722cdc85b81a803e7243b39cef2b51c28520b0c080dcbc5a0351893e9396",
        ),
        (
            "enum",
            "FenceIncompletePacketProgress",
            "enumFenceIncompletePacketProgress",
            "743383b112aeed30c69e30be1e1677fa2513eedd7e77f37642c6dc9ac246cec6",
        ),
        (
            "struct",
            "PreparedDelete",
            "pub(crate)structPreparedDelete",
            "a46850755b3eac55d2eb196102b770622a63d9bbfa6dca3040a069360c2bcba7",
        ),
        (
            "struct",
            "DeleteFailStop",
            "pub(crate)structDeleteFailStop<Deposit>",
            "201e8ce87f7772ff321cfae8222fbb9a2e4cf21f8b6fb241f66802cf1be3b26a",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "enum",
            "OpaqueFailStopWaitPreparation",
            "pub(crate)enumOpaqueFailStopWaitPreparation",
            "0ada8dace8cddf0cc21baec4a73fd3d7ba70fdfc8ea715d104880325530084a8",
        ),
        (
            "struct",
            "OpaqueFailStopWaitGuard",
            "pub(crate)structOpaqueFailStopWaitGuard",
            "9b2f0da092ddf25fd4fbd787fc4c16b702d59f0a582abd26e6bc4ccbdbbf6b5d",
        ),
        (
            "struct",
            "FinalizerHandoffRight",
            "pub(crate)structFinalizerHandoffRight",
            "47c31a796c1f5b6a793984b852004a67f2943d8de6a26141916779aa9e8b3f93",
        ),
        (
            "enum",
            "FinalizerVisibilityHandoff",
            "pub(crate)enumFinalizerVisibilityHandoff",
            "e86c06fb0a50f18b64536c7b550ecb67a6e8fad9caae1072a043eebc30707fc3",
        ),
        (
            "struct",
            "FinalizerMissingHandoffGuard",
            "pub(crate)structFinalizerMissingHandoffGuard",
            "84cfeb925ee169606913382a6347ecf5d3ea8f5c45dbd42c30061168e482a000",
        ),
        (
            "enum",
            "FinalizerWinnerResolution",
            "pub(crate)enumFinalizerWinnerResolution",
            "39d8f2c11c8aa832f03776fd747d54c5087592cf72868e80ad83f05126d3f180",
        ),
        (
            "enum",
            "NativeCleanupRoute",
            "pub(crate)enumNativeCleanupRoute",
            # Round 15: `CompletedControl` carries `{generation, result}`
            # instead of the `CompletedControlRecord` itself. Carrying the
            # record out of the registry lock is what let the one consumer
            # drop it, taking the `CloseContextRight` with it, so CLOSE
            # freed nothing and unload waited on a rundown release that
            # could never come. The record is acknowledged inside the hold
            # that takes it now.
            "d9a6513cb27c403950a7f469cdee08ee71889383ac219f35c181da47ed3afef5",
        ),
    ),
}

TASK5_FAIL_STOP_IMPL_GRAMMAR = {
    "driver/fsring-core/src/session.rs": ((
        "impl<Packet>DurableFailStopSlot<Packet>",
        "33278c556d4d59a447311371ac77a45d5e34c2feb33eaf7845dfdda45e9028ba",
    ),),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "implR3FailStopSlot",
            "4a64f8cc7e741791aeaaab9daa8b142b19d53a034e73c200bf14c03d982d476c",
        ),
        (
            "implR4CheckpointCandidate",
            "ae96520d4de728997a7a926c1daf1cb68b25250e0d8897143c483fe373de3d19",
        ),
        (
            "implFenceIncompletePacket",
            "6aebbd0af28d92a9433fc359ff298385ff391f1c2bb04035535f68909643b2cf",
        ),
        (
            "implR4CheckpointCandidate",
            "aa3a845bd9a55407ef104d0bfe70c0d7b20ca8c3a4412b4a14a3db9e329c4b13",
        ),
        (
            "impl<Deposit>DeleteFailStop<Deposit>",
            "a385019a9b5ac68498de55731024f75a65d12d423a0739e1221eb8184b583494",
        ),
        (
            "implPreparedDelete",
            "bf7305cd0792a9c4c438feb0681f77e8de00dcdb6d34041ea19da456318c7dd1",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "implFinalizerHandoffRight",
            "2db7dd0f68aea8c10226a3668b19cf9bdcc3c8450c6ccf373597f519474eec96",
        ),
        (
            "implFinalizerMissingHandoffGuard",
            "316f811ae498bb90a56ca9cb5fb7e65ba29d113261a72b03b5f1b703bdc103ba",
        ),
        (
            "implOpaqueFailStopWaitGuard",
            "c18e24b1fa1d3a3b8ee10e27c66520b623656046abc54222d999f5494ce25e74",
        ),
        (
            "implTerminalJoinGuard",
            "f76cea0efa911283b940021a6a9e25eb0892a71a2f534c96a1f83bc6c9a1694c",
        ),
    ),
}

TASK5_FAIL_STOP_BODY_GRAMMAR = {
    "driver/fsring-fsd/src/fence.rs": (
        (
            "finish_finalizer_fail_stop_visibility",
            ("0809be237b9f85a062d133db963df027a3ab8b64e0482fdf42ff4e0f69fa6436",),
        ),
        (
            "store_fail_stop_locked",
            ("34bb55f9e15f74816accdc2a9390b4d85f9229aa9bec27f663d5daa04fee4bab",),
        ),
    ),
}

# Task 6 replaces the predecessor unload walker with one closed R3 grammar.
# These identities deliberately cover both sides of every native boundary:
# core fixes the 16-effect/31-predicate language, while FSD owns the private
# fixed-domain cursors, authenticated waits, effect-nine capability, and the
# infallible 10->16 suffix.  Exact body digests are paired with semantic
# rosters below so a coordinated rename/deletion cannot preserve the audit by
# merely moving a dangerous operation into a sibling helper.
TASK6_UNLOAD_EFFECTS = (
    "CloseGlobalAdmissions",
    "UnregisterProcessNotify",
    "WaitProcessCallbacks",
    "WaitSetupAdmission",
    "ClaimOrJoinOneSession",
    "RestartSessionScan",
    "DrainR3Finalizers",
    "WaitControlContextAdmission",
    "PreflightR3LedgersAndRoot",
    "UnregisterFilesystem",
    "DeleteFscontrol",
    "RemoveProviderDosLink",
    "DeleteProvider",
    "ReleaseBootObjects",
    "ReleaseDriverState",
    "UnregisterEtw",
)

TASK6_UNLOAD_PREDICATES = (
    "CoreAdmissionClosed",
    "ProcessCallbackAdmissionClosed",
    "ProcessCallbacksDrained",
    "SetupAdmissionClosed",
    "SetupAdmissionDrained",
    "SessionScanStableEmpty",
    "CoreSessionSlotsEmpty",
    "NativeSessionCellsEmpty",
    "TerminalRendezvousInactive",
    "TerminalJoinersDrained",
    "TerminalEventsQuiescent",
    "MountOwnerAbsent",
    "MountTicketsAndWaitersDrained",
    "MountSignalsAcknowledged",
    "FinalizerAdmissionClosed",
    "FinalizersDrained",
    "FinalizerDepositsAbsent",
    "FinalizerHandoffsAbsent",
    "FailStopSlotsEmpty",
    "SessionShellOwnersAbsent",
    "SessionRootOwnersAbsent",
    "RegistryLeasesAbsent",
    "ControlOwnersAbsent",
    "CheckpointReadinessAbsent",
    "ControlContextAdmissionClosed",
    "ControlContextAdmissionDrained",
    "ControlBindingsClosed",
    "CompletedControlRecordsAbsent",
    "CloseRightsAbsent",
    "ControlContextsAbsent",
    "SoleDriverRootReference",
)

TASK6_UNLOAD_ITEM_GRAMMAR = {
    "driver/fsring-core/src/adapter/load.rs": (
        (
            "enum",
            "UnloadEffect",
            "pubenumUnloadEffect",
            "95160c1f7d893a6abb973cf12bdaea7dc758bd713f96c90369760b132e8239a2",
        ),
        (
            "enum",
            "ProcessNotifyUnregisterDisposition",
            "pubenumProcessNotifyUnregisterDisposition",
            "28a940abc225b01bc58a8d06ae7788925e5beda4ff9ff733cf2ab8a4d5093ef7",
        ),
        (
            "enum",
            "R3UnloadPredicate",
            "pubenumR3UnloadPredicate",
            "7924bd79cfb70c7d5e5cc47d7b92324f038242b7553f7f9a636d887ed480249d",
        ),
        (
            "struct",
            "PrivateR3UnloadBoundaryAuthority",
            "structPrivateR3UnloadBoundaryAuthority(())",
            None,
        ),
        (
            "struct",
            "R3UnloadPreflightBoundary",
            "pubstructR3UnloadPreflightBoundary",
            "d94d311ecdb8e7ce578891e17850363d998b8a4598fb1742d1d59e219eef0e09",
        ),
        (
            "struct",
            "PendingR3UnloadEffect",
            "pubstructPendingR3UnloadEffect",
            "fb40598abf03fdc12cd666745fabad038e3560586b42c86820dcc65873da7c8d",
        ),
        (
            "enum",
            "R3UnloadPlanProgress",
            "pubenumR3UnloadPlanProgress",
            "06f77ac986e94ced3c8c723229cb0873257366b133f8e7c36645d823eadc12fc",
        ),
        (
            "struct",
            "UnloadPlan",
            "pubstructUnloadPlan",
            None,
        ),
    ),
    "driver/fsring-fsd/src/driver.rs": (
        (
            "struct",
            "PreparedUnloadDestruction",
            "structPreparedUnloadDestruction",
            "6e8bb7db581887e97823085545373d7e59b8a393f94411a6787df2c99d9ca8e6",
        ),
        (
            "struct",
            "PrivatePreparedUnloadDestruction",
            "structPrivatePreparedUnloadDestruction(())",
            None,
        ),
        (
            "struct",
            "R3UnloadSuffix",
            "structR3UnloadSuffix<constNEXT:u8>",
            "fec7e50b11d8b903bbb9af6042415451e418a3d43a29bf8bfa9083da5b04a1d6",
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "struct",
            "R3UnloadProgress",
            "pub(crate)structR3UnloadProgress",
            "1588d18b64274b27080c26a080b2446a0d35db6b1ae8f3022011c9f1c59ee49d",
        ),
        (
            "struct",
            "R3UnloadWork",
            "pub(crate)structR3UnloadWork",
            "555124350c555d243d35c70d6b5972d5208a0f7aa8f8577126c7bce2b3a4c4e8",
        ),
        (
            "struct",
            "R3StableEmptyPass",
            "pub(crate)structR3StableEmptyPass",
            "851c70da98c4f6f4e64e6e44cbd7698e6f667510bd70c04fb7d8c01e66a41c76",
        ),
        (
            "struct",
            "R3FinalizerFullPass",
            "pub(crate)structR3FinalizerFullPass",
            "0e6971baee89dc819a2ff7668d4d8885acb9b89de8777d5b860a1b978449d63a",
        ),
        (
            "struct",
            "R3FinalizerAcknowledgedPass",
            "pub(crate)structR3FinalizerAcknowledgedPass",
            "03bd8e0a57ff8c6de1bdcfa36a414cbcecd73f5fb681e4d496324c2315508cf4",
        ),
        (
            "struct",
            "R3FinalizersDrained",
            "pub(crate)structR3FinalizersDrained",
            "1bf199c7897230455ef48a4a1587cb8f9c6c5fe1a7cc78158f469e01781f33de",
        ),
        (
            "struct",
            "PrivateR3StableEmptyPassAuthority",
            "structPrivateR3StableEmptyPassAuthority(())",
            None,
        ),
        (
            "struct",
            "PrivateR3FinalizerFullPassAuthority",
            "structPrivateR3FinalizerFullPassAuthority(())",
            None,
        ),
        (
            "struct",
            "PrivateR3FinalizerAcknowledgedPassAuthority",
            "structPrivateR3FinalizerAcknowledgedPassAuthority(())",
            None,
        ),
        (
            "enum",
            "R3UnloadScanStep",
            "pub(crate)enumR3UnloadScanStep",
            "93a77364a6b003e1b95100db3bcdbb723798f8312faf6bf28a8bf92b8016f886",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "struct",
            "ClosedGlobalAdmissions",
            "pub(crate)structClosedGlobalAdmissions",
            "693a58b02cb7a8e352e1d9f1c091fa6cabfc7ce5ada6e384b562c22b8e1df6cc",
        ),
        (
            "struct",
            "R3UnloadScanAdmission",
            "pub(crate)structR3UnloadScanAdmission",
            "3775830afac9b47f1c8a3e6b2a71cfbc0acb964061d38f644152343a40e2c387",
        ),
        (
            "struct",
            "FinalizerRundownDrained",
            "pub(crate)structFinalizerRundownDrained",
            "f470a4e2112f98b292836c51d6fc942e6157a5d8e98c45e4ee0fecf6f422c8f8",
        ),
        (
            "struct",
            "FinalizersDrained",
            "pub(crate)structFinalizersDrained",
            "e046fcaf48e4448ef3a210a7cf25173bcc4377377b94cb0e53c2faefc84ed759",
        ),
        (
            "enum",
            "R3FinalizerDrainObservation",
            "pub(crate)enumR3FinalizerDrainObservation",
            "65422df2a66f7eb639389eb8110dd3818a5d4d3111c1143dcbcbd21dad95669c",
        ),
        (
            "struct",
            "LockedR3FinalizerDrainNonMatch",
            "pub(crate)structLockedR3FinalizerDrainNonMatch",
            "1515e84d640a9b56c83033e5847e6f037cb9c338751c1ea2c9b9b1aee2491872",
        ),
        (
            "struct",
            "LockedR3FinalizerOrdinaryInFlight",
            "pub(crate)structLockedR3FinalizerOrdinaryInFlight",
            "d3f4d37567696b14118aabd8319dfd9df00a3382d0dc36ea780403e026cef814",
        ),
        (
            "enum",
            "ProcessScanAction",
            "pub(crate)enumProcessScanAction",
            "beb9e41672e7e5c314e7c83d8a00afd26d629760e9be9698393146c3f978df39",
        ),
        (
            "struct",
            "PreparedProcessScanAction",
            "structPreparedProcessScanAction",
            "057cae186700f5c19a25addf472c605d4b0b70fea10062185da75e4dad03c672",
        ),
        (
            "enum",
            "ProcessScanStep",
            "pub(crate)enumProcessScanStep",
            "503690287ea7b77287e1faca5952695bd938ded9594fe7e4d2d847fd2a325b0c",
        ),
        (
            "enum",
            "R3UnloadCellAction",
            "pub(crate)enumR3UnloadCellAction",
            "e372b77b2bb8f2a86d434a8b39b431e877f4e27bae0f1486823c6a9e69679de6",
        ),
        (
            "enum",
            "R3UnloadCellObservation",
            "pub(crate)enumR3UnloadCellObservation",
            "b67aad3328b197f9e9c70d75b384afb55824a2be3f227249980a81cd21429bdd",
        ),
        (
            "struct",
            "R3NativeUnloadPreflightObservation",
            "structR3NativeUnloadPreflightObservation",
            "530d61a53afaddeefe0eeab611d5ef437214c6e665b7d308d3505e5518a46c7e",
        ),
        (
            "struct",
            "R3NativeLedgersClear",
            "pub(crate)structR3NativeLedgersClear",
            "35868aa3110165070f265ecf5cacbbb166f0fb0eb25d18cbaebabc5065a01bdc",
        ),
        (
            "struct",
            "R3SoleDriverRoot",
            "pub(crate)structR3SoleDriverRoot",
            "583efb540564dc8365c5a5e7feaea9e392621fd81148d4913e52ddf7fc1af23f",
        ),
    ),
}

TASK6_UNLOAD_IMPL_GRAMMAR = {
    "driver/fsring-core/src/adapter/load.rs": (
        ("implR3UnloadPredicate", "e4cf54aa92d4238513290b676e471a9454f4cc6c08cea66548ad448c6bcdd04d"),
        ("implUnloadPlan", "ab1e672cd87d2b87cfa248cda0b822383e94db5a51783b65d7ab56e93bcbdda9"),
        ("implPendingR3UnloadEffect", "2fadb9530570f3e288765df6a1636fa85d2de5ff6494cf9f32d70fc48e90e521"),
    ),
    "driver/fsring-fsd/src/driver.rs": (
        ("implDriverState", "7d9ca638f38d1731ac6268e6edb64dc58d0d9ce38912d666e876054f141e0437"),
        ("implPreparedUnloadDestruction", "ba4745f7ecad078d3ebf87c332128d72151f34a9389cf8f474197c3b247c7310"),
        ("implR3UnloadSuffix<10>", "255543b6e2ea7e810838720c5b26933489027c9c46c00ea08cb636491600ce88"),
        ("implR3UnloadSuffix<11>", "c1d80b497c1284ed21efa3dc48bfbd5ebf2291ecf38ca4143a8288fd4b1c9ba0"),
        ("implR3UnloadSuffix<12>", "29c0789bb77001c02f1643741208c45ec43dc2df99df1767a1cb52a6899c257b"),
        ("implR3UnloadSuffix<13>", "70f4b5b59df90c1be4fbd6282a05f9a90c25bb688d7801640113a078a77444cb"),
        ("implR3UnloadSuffix<14>", "04a5ec9000322dd8371581c4ae6d0d4ad697ac94fe2af62d53737799b83569b8"),
        ("implR3UnloadSuffix<15>", "1207b8ded04d046210468222fad06b6fb135b6b857d9e31b9e561ed0e230388b"),
        ("implR3UnloadSuffix<16>", "0b5784c7866c1b953337276235094568ce6a013e0e607434a481527da2ab808a"),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        ("implR3UnloadProgress", "3ad3585a12b85bc349978607292ff23db88408254d761cb4b1bb0ecf755f0a54"),
        ("implR3UnloadWork", "146abbd15a8155fe3e3733e196692b259b51cdd6d5e303d9ddddc69b09b72d33"),
        ("implR3FinalizersDrained", "f4668f2cff46463f1974262600a9f5bd42061d205d55640625a975ee3b850e2a"),
        ("implR3FinalizerFullPass", "be6efe76b5b9a2ed84539fc7b40dde5c0e7fedbfe157a8d32356a9ae41aa4ea0"),
        ("implR3FinalizerAcknowledgedPass", "19b68af55078e6334fa57eec114d79d27e9ae1ceeb0f6753ad1dac6e29608cba"),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        ("implClosedGlobalAdmissions", "d277b07f312d17b971c0b87d12183255b7299e7e8f0f2251bdfb3e4cc068b78e"),
        ("implProcessCallbacksDrained", "9d44767488147ec5267d00e46b63d9a96ee2b7f6cbb68c7dfec0eb6ffba17956"),
        ("implSetupAdmissionDrained", "53863406fe674bf7bc4ee76386ddf011cdfb836a8c64902c2548a59179f00638"),
        ("implControlContextAdmissionDrained", "9cd521ffddefa803e1b34fb7fe15cc0f71a0b43c20c5cba9fac32ee810a4e229"),
        ("implR3UnloadScanAdmission", "4fa2dc60d0537d05b1651c2e6020aea2307fb7ca814f37ab9e4f201cf32b4f04"),
        ("implLockedR3FinalizerDrainNonMatch", "afe99f046f211236a8591da6608efc1b02f45ee718c27b415d33f3c626e3e192"),
        ("implLockedR3FinalizerOrdinaryInFlight", "f037b3904fe36561e8d5d785e624930424ef4665b49ffb9ce32ec2085919be4e"),
        ("implPreparedProcessScanAction", "81c0db59f9a6f5f216d9e97377eda635087f4394a6245e1884e79fa0708e5bf0"),
        ("implR3NativeLedgersClear", "dc989dc14684ab09c5034a73b861158abbb2ebb6187b81da822a1f1bb7626ee9"),
        ("implR3SoleDriverRoot", "dc989dc14684ab09c5034a73b861158abbb2ebb6187b81da822a1f1bb7626ee9"),
    ),
}

TASK6_UNLOAD_BODY_GRAMMAR = {
    "driver/fsring-core/src/resolver.rs": ((
        "resolve_all",
        "2f4d81a2a142bb4121cbda5cd7a78287a19d7a9a5f8ac5e7fb2227f2cdd63642",
        "Task 6 optional-DDI resolver table is the sole dynamic resolution route",
    ),),
    "driver/fsring-core/src/session.rs": (
        (
            "r3_unload_admission_is_closed",
            "df3083bf4f74f8a9ac98e849fc994856e66198acfcd829806448a93471b32944",
            "Task 6 independent core admission predicate",
        ),
        (
            "r3_unload_slots_are_empty",
            "371755ce9ff0da21b83c3d1eec169aa8bbf090352f01a7798f29b54efce248da",
            "Task 6 independent core slot-emptiness predicate",
        ),
    ),
    "driver/fsring-core/src/adapter/load.rs": (
        (
            "classify_process_notify_unregister",
            "acefe260a264b109c5466b3068dd1215af2b199318ee8e6830966176c1f862c4",
            "Task 6 unregister failure cannot advance",
        ),
        (
            "expect_r3_unload_effect",
            "0f0af4606c64fd2f0d41730d614b7f90212af86423e60f90a3917daa69f18f48",
            "Task 6 prefix cursor closure",
        ),
    ),
    "driver/fsring-fsd/src/driver.rs": (
        (
            "fsring_driver_unload",
            "ac612a8659de955ab1e2456df2d1b9097a5e6da1df68940848b5e09702ea9625",
            "Task 6 missing unload authority is nonreturning",
        ),
        (
            "unload",
            "223682eac66cd6213b1cc618df5e0687730b493ef2601921dd72ed00643fbe5a",
            "Task 6 exact production 16-effect order",
        ),
        (
            "finish_r3_session_scan",
            "57998d42b4e7aa560a0f1e2ef5255f4cf861703be9f057fd22f27f960735f6a6",
            "Task 6 restart-to-zero session scan",
        ),
        (
            "bugcheck_r3_unload_preflight",
            "14513c3cd2bb0f2ee01c28f7499542f6b340e3d8a91650e775140931183fa63e",
            "Task 6 named effect-nine refusal",
        ),
        (
            "bugcheck_r3_unload_invariant",
            "3375bfe8d423fad41821ce07e26d05941a511a385bcb900b74c533063320590d",
            "Task 6 unload invariant is distinct from predicates",
        ),
        (
            "fsring_process_loss",
            "3ee8b898d2ecab5fd37aa3f1ed00ee3703f436593788b22114906d6f27f2607a",
            "Task 6 one-guard process callback runner",
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "release_strong_and_deposit",
            "2e74d803d7ec0690914568c65a183d27120ba591fb41c2fa4354c376aa81915c",
            "Task 6 finalizer admission precedes deposit commit",
        ),
        (
            "begin_after_drains",
            "f72db215dbcd6197d2b9d5ff65328dabb8f6984c5e2189605e6720d0380da466",
            "Task 6 stable scan is drain-lineage bound",
        ),
        (
            "observe_one",
            "3f0cad39381a16cf6d7ccb14a6607372466371388365178b8de0b7a777977db6",
            "Task 6 fixed 64-cell authenticated scan",
        ),
        (
            "discharge",
            "ab1645b3a06d1d0c139be5fb6646083a0ff024bc76da8d165df1ca5c2b2e5d08",
            "Task 6 every matched unload action restarts zero",
        ),
        (
            "drain_r3_finalizers",
            "fe0b22f494893e2887d21ec399183aa27882f70d4dca1815774005c76e51d4b6",
            "Task 6 fixed 64-cell finalizer resolution and ACK passes",
        ),
        (
            "run_terminal_for_process",
            "df35a16fb9b633b333fc4c978eadbe64093b45f2fba4820ce468faf9c3a353bf",
            "Task 6 typed process action discharge",
        ),
        (
            "join_terminal_outcome",
            "295a19aa9a457f8f14fd593aa74ee80109d3a16f99bbeae500aaf481f266e4d9",
            "Task 6 process visibility resolution",
        ),
    ),
    "driver/fsring-fsd/src/kernel.rs": (
        (
            "resolve_one",
            "a7f403e1b44b4d0356e8a454e0c538b938551897ab2678c27888ad6818f5b5de",
            "Task 6 exact optional-DDI name resolver",
        ),
        (
            "resolve_optional_ddis",
            "18cf017d382dd37cefe29f8b2c0007337934dcd138149aad263b227984b72bf7",
            "Task 6 dynamic resolution is confined to the optional-DDI table",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "close_global_admissions",
            "9a7752fcd6c84e2a5ef26e9090ee1931a1f5d6008eea2cc42d848b814be50896",
            "Task 6 atomic four-door admission close",
        ),
        (
            "wait_process_callbacks_drained",
            "4d513cd810e493759def452500d0f89a2bcea0236944ea35a8361c09d1e29f2c",
            "Task 6 process callback rundown wait",
        ),
        (
            "wait_setup_admission_drained",
            "e8ff75cb84f197fca464f54434538c1133f7aa4d70efd037123892afda3c77ef",
            "Task 6 setup rundown wait",
        ),
        (
            "wait_control_context_admission_drained",
            "e5104a52ba290eb3142779a6e868fbf7764af0b9e2acc60c0bd74c4a28ba9cc9",
            "Task 6 control-context rundown wait",
        ),
        (
            "close_finalizer_admission",
            "b06e82b90f170a570bdc8df0367e217dba1fe02f8a12404c758769d73630cd2c",
            "Task 6 effect-seven finalizer close",
        ),
        (
            "wait_finalizers_drained",
            "0fd17948239539b08ad3e2aedab3c6870d156ec1bd11112e21efb079829efaa6",
            "Task 6 finalizer rundown consumes full resolution pass",
        ),
        (
            "finish_finalizers_drained",
            "34b54b7739acbaba96e53f3faec3c655b87114c2e9d7f1e6764bcf82088ba4e5",
            "Task 6 FinalizersDrained consumes post-rundown ACK",
        ),
        (
            "observe_r3_finalizer_for_drain",
            "da200d13f064128e244e51a2b9e08866a01749e0f56c26f2e161cb8c30bb044c",
            "Task 6 authenticated finalizer resolution matrix",
        ),
        (
            "acknowledge_r3_finalizer_after_rundown",
            "e17d8fca465d38a7691f4ebff91b0b7f25f084ebb18d38db7b50e075543a0584",
            "Task 6 post-rundown latch ACK pass",
        ),
        (
            "r3_finalizer_is_authenticated_ordinary_in_flight",
            "84b9f7dcdf8ea2a87d7ae90dfc7a14cd9baaabef0917a1917c9d3e55774274bb",
            "Task 6 Completed and exact Ordinary handoff authentication",
        ),
        (
            "queue_cell_finalizer",
            "4c2d5a1adbfe5e5ee489ea69888787f9124c74d6b50b2580d16eacce9174d82f",
            "Task 6 queue-to-callback finalizer admission",
        ),
        (
            "fsring_finalizer_callback",
            "03e2555337464434efa105f20e73aeb0c803dbb0803c74451e94c7cd0132aace",
            "Task 6 callback-last-access admission release",
        ),
        (
            "clear_terminal_generation_events",
            "349b3aa0639f341d53e4ba0cbb90e921666fe25e43c7ad47262d2f2f7658c84f",
            "Task 6 next-Staging generation event clear",
        ),
        (
            "reset_after_delete",
            "f76a8af3ee6b656c55eff6fae0735af9a09fa36be0abc6c60908584238b35f5c",
            "Task 6 visibility latch survives ordinary reset",
        ),
        (
            "wait_for_visibility_resolution",
            "db9bda4f4671c5ff0344d1fcf5c56eac53717946e7047699317391df1ac3689f",
            "Task 6 broadcast visibility resolution",
        ),
        (
            "wait_for_unload_visibility",
            "1a9e4299b4cead61a6b3b2937b5bc35b0019a9c9c03459d07369fa4148e9d61c",
            "Task 6 Published/Opaque ticket authentication order",
        ),
        (
            "prepare_published_unload_wait",
            "b2c3991d274c890af65f8f3cfa5403cd6030a018c6979d99c81c5aab9bfe2e1f",
            "Task 6 no-ticket Published authentication",
        ),
        (
            "prepare_released_published_unload_wait",
            "8f6198d5a5c6709ab66a9363528747f1b43cba747b0d10a7cd4fb80873dcf45d",
            "Task 6 released-ticket Published authentication",
        ),
        (
            "prepare_opaque_unload_wait",
            "78d75a980647553c4c6c4eee53e09177608628868a44c44eff6378d7de2514e7",
            "Task 6 fused no-ticket Opaque authentication",
        ),
        (
            "mark_process_loss_handled",
            "ffbccd378e583ca10391f90eb44d74b7171bbfb72cec0a9b761fde274768368a",
            "Task 6 per-generation process-loss marker",
        ),
        (
            "scan_one_cell_for_process",
            "090b189ad1b10b28166e6c3c82e710befa83539bf74514b64a7edc4a7277b01d",
            "Task 6 guard-bound typed process scan matrix",
        ),
        (
            "observe_r3_unload_cell",
            "bd179dee04d22dbf82f071af103e349c239c73417dc53b93a6f37aeaf10448a5",
            "Task 6 locked native unload cell observation",
        ),
        (
            "r3_unload_preflight_cell_is_empty",
            "8a2c83c6fc295bb10f0b660ef0265047d0adf1856c820317cbb6870dd461da9e",
            "Task 6 independent base native-cell predicate",
        ),
        (
            "observe_r3_unload_preflight",
            "fddb773bee0dcd3a552004646c041b96444da0b39fc1ebfb665029f3730d2b67",
            "Task 6 exact native effect-nine observations",
        ),
        (
            "prepare_r3_native_ledgers_clear",
            "d2fc922228e8c7b8a1ba2ff549c362d160e9819a86bf84f06dfe4eeed37d55b7",
            "Task 6 sealed 17 native predicates",
        ),
        (
            "prepare_r3_unload_locked_root",
            "7d5c2e6adda55c27e448500ed4a65bda5dbc7c5bdb2f3005080fb11a5cd3d63a",
            "Task 6 same-lock native ledgers and sole-root proof",
        ),
    ),
}

TASK6_UNLOAD_TOKEN_NAMES = (
    "PreparedUnloadDestruction", "R3UnloadSuffix", "R3UnloadPreflightBoundary",
    "R3UnloadProgress", "R3StableEmptyPass", "R3FinalizerFullPass",
    "R3FinalizerAcknowledgedPass", "R3NativeLedgersClear", "R3SoleDriverRoot",
    "process_loss_handled", "mark_process_loss_handled", "visibility_resolution",
    "OrdinaryInFlight", "wait_finalizers_drained", "finish_finalizers_drained",
    "observe_r3_unload_cell", "prepare_r3_unload_locked_root",
    "destroy_prepared_work_items",
)

TASK6_UNLOAD_TOKEN_CENSUS = {
    "driver/fsring-core/src/adapter/load.rs": (0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    "driver/fsring-fsd/src/driver.rs": (6, 27, 3, 1, 2, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1),
    "driver/fsring-fsd/src/fence.rs": (0, 0, 0, 4, 6, 4, 3, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0),
    "driver/fsring-fsd/src/lifecycle.rs": (0, 0, 0, 0, 0, 1, 1, 6, 4, 11, 2, 8, 2, 1, 1, 1, 1, 1),
}

# Effects 10-16 are not protected merely by the private suffix cursor: every
# callable destructive wrapper and its underlying DDI/free sink has an exact
# production owner census.  This preserves legitimate load rollback and
# per-session destruction while rejecting an appended sibling bypass.
TASK6_DESTRUCTIVE_CALLER_CENSUS = (
    (
        "crate::fscontrol::unregister(",
        (
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
            ("driver/fsring-fsd/src/driver.rs", "unregister_filesystem", 1),
        ),
    ),
    (
        "fsring_sys::c4::IoUnregisterFileSystem(",
        (("driver/fsring-fsd/src/fscontrol.rs", "unregister", 1),),
    ),
    (
        "crate::kernel::delete_device(",
        (
            ("driver/fsring-fsd/src/control.rs", "create_provider_device", 1),
            ("driver/fsring-fsd/src/driver.rs", "delete_fscontrol", 1),
            ("driver/fsring-fsd/src/driver.rs", "delete_provider", 1),
            ("driver/fsring-fsd/src/driver.rs", "perform", 1),
            ("driver/fsring-fsd/src/driver.rs", "undo", 2),
            ("driver/fsring-fsd/src/fscontrol.rs", "create", 1),
            ("driver/fsring-fsd/src/lifecycle.rs", "delete", 1),
            ("driver/fsring-fsd/src/volume.rs", "create_mounted_device", 1),
            ("driver/fsring-fsd/src/volume.rs", "create_staging", 1),
            ("driver/fsring-fsd/src/volume.rs", "delete", 1),
            ("driver/fsring-fsd/src/volume.rs", "perform_mount", 1),
        ),
    ),
    (
        "fsring_sys::IoDeleteDevice(",
        (("driver/fsring-fsd/src/kernel.rs", "delete_device", 1),),
    ),
    (
        "crate::control::remove_dos_link(",
        (
            ("driver/fsring-fsd/src/driver.rs", "remove_provider_dos_link", 1),
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
        ),
    ),
    (
        "crate::kernel::delete_symbolic_link(",
        (("driver/fsring-fsd/src/control.rs", "remove_dos_link", 1),),
    ),
    (
        "fsring_sys::IoDeleteSymbolicLink(",
        (("driver/fsring-fsd/src/kernel.rs", "delete_symbolic_link", 1),),
    ),
    (
        ".destroy_prepared_work_items(",
        (("driver/fsring-fsd/src/driver.rs", "delete_provider", 1),),
    ),
    (
        "fsring_sys::c4::IoFreeWorkItem(",
        (
            ("driver/fsring-fsd/src/lifecycle.rs", "destroy_prepared_work_items", 2),
            ("driver/fsring-fsd/src/lifecycle.rs", "rollback_initialization", 2),
        ),
    ),
    (
        "crate::boot::unmap_system_view(",
        (
            ("driver/fsring-fsd/src/driver.rs", "release_boot_objects", 1),
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
        ),
    ),
    (
        "crate::boot::close_section(",
        (
            ("driver/fsring-fsd/src/driver.rs", "release_boot_objects", 1),
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
        ),
    ),
    (
        "crate::boot::close_lock_event(",
        (
            ("driver/fsring-fsd/src/driver.rs", "release_boot_objects", 1),
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
        ),
    ),
    (
        "fsring_sys::c4::MmUnmapViewInSystemSpace(",
        (
            ("driver/fsring-fsd/src/boot.rs", "map_system_view", 1),
            ("driver/fsring-fsd/src/boot.rs", "unmap_system_view", 1),
            ("driver/fsring-fsd/src/session.rs", "allocate_section", 1),
            ("driver/fsring-fsd/src/session.rs", "checkpoint_release_mdls_and_system_view", 1),
            ("driver/fsring-fsd/src/session.rs", "undo", 1),
        ),
    ),
    (
        "fsring_sys::ObfDereferenceObject(",
        (
            ("driver/fsring-fsd/src/boot.rs", "close_lock_event", 1),
            ("driver/fsring-fsd/src/boot.rs", "close_section", 1),
            ("driver/fsring-fsd/src/boot.rs", "open_and_acquire_lock_event", 2),
            ("driver/fsring-fsd/src/boot.rs", "open_or_create_section", 3),
            ("driver/fsring-fsd/src/control.rs", "wait_and_release_requestor", 1),
            ("driver/fsring-fsd/src/session.rs", "checkpoint_release_captured_process", 1),
            ("driver/fsring-fsd/src/session.rs", "checkpoint_release_mdls_and_system_view", 1),
            ("driver/fsring-fsd/src/session.rs", "perform_view_undo", 1),
            ("driver/fsring-fsd/src/session.rs", "undo", 2),
        ),
    ),
    (
        "close_handle(",
        (
            ("driver/fsring-fsd/src/boot.rs", "close_lock_event", 1),
            ("driver/fsring-fsd/src/boot.rs", "close_section", 1),
            ("driver/fsring-fsd/src/boot.rs", "open_and_acquire_lock_event", 3),
            ("driver/fsring-fsd/src/boot.rs", "open_or_create_section", 4),
        ),
    ),
    (
        "fsring_sys::c4::ZwClose(",
        (
            ("driver/fsring-fsd/src/boot.rs", "close_handle", 1),
            ("driver/fsring-fsd/src/session.rs", "checkpoint_release_mdls_and_system_view", 1),
            ("driver/fsring-fsd/src/session.rs", "undo", 1),
        ),
    ),
    (
        "crate::trace::unregister(",
        (
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
            ("driver/fsring-fsd/src/driver.rs", "unregister_etw", 1),
        ),
    ),
    (
        "fsring_sys::c4::EtwUnregister(",
        (("driver/fsring-fsd/src/trace.rs", "unregister", 1),),
    ),
    (
        "allocation.release(",
        (
            ("driver/fsring-fsd/src/driver.rs", "allocate_state", 4),
            ("driver/fsring-fsd/src/driver.rs", "undo", 1),
            ("driver/fsring-fsd/src/driver.rs", "unregister_etw", 1),
            # Task 18's staged pending arena. One free, at the end of the
            # reverse rollback, after every work item it built is released.
            ("driver/fsring-fsd/src/pending_enter.rs", "release_arena", 1),
        ),
    ),
    (
        "fsring_sys::ExFreePoolWithTag(",
        (
            ("driver/fsring-fsd/src/control.rs", "fsring_dispatch_create", 1),
            ("driver/fsring-fsd/src/control.rs", "rollback", 1),
            ("driver/fsring-fsd/src/control.rs", "run_close_plan", 1),
            ("driver/fsring-fsd/src/kernel.rs", "free_pool", 1),
            ("driver/fsring-fsd/src/lib.rs", "bring_up", 1),
            ("driver/fsring-fsd/src/lifecycle.rs", "release", 1),
        ),
    ),
)

TASK6_DRIVER_STATE_RELEASE_CALLERS = (
    ("driver/fsring-fsd/src/driver.rs", "prepare", 1),
    # `unload`'s release moved into the typestate op `release_driver_state`,
    # whose signature names `R3UnloadSuffix<15>` rather than `DriverState`, so
    # this signature-scoped roster no longer sees it. Nothing is uncovered:
    # TASK6_GLOBAL_RELEASE_CALLERS is receiver-independent and still counts it.
    ("driver/fsring-fsd/src/session.rs", "execute_enter", 2),
    ("driver/fsring-fsd/src/session.rs", "execute_setup", 3),
)

TASK6_GLOBAL_ACQUIRE_CALLERS = (
    (
        "driver/fsring-core/src/effect.rs",
        "acquire",
        2,
    ),
    (
        "driver/fsring-core/src/effect.rs",
        "acquire_if_unheld",
        1,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "fsring_dispatch_cleanup",
        1,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "fsring_dispatch_create",
        1,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "fsring_dispatch_provider",
        1,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "acquire_guard",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "acquire",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "acquire_parked_strong_refs",
        1,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "execute_setup",
        1,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "install_staging",
        1,
    ),
    (
        "driver/fsring-fsd/src/volume.rs",
        "perform_mount",
        1,
    ),
)

TASK6_GLOBAL_RELEASE_CALLERS = (
    (
        # Task 20: `BrandedPendingCqPop::abort` declines one CQ entry through
        # the ABI's explicit `PendingPop::release`, which is the whole point of
        # that method existing -- a drain that cannot account for an entry says
        # so at the call site rather than by dropping the value.
        "driver/fsring-core/src/adapter/enter.rs",
        "abort",
        1,
    ),
    (
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "release_pending",
        1,
    ),
    (
        # Task 21: the sole route out of a sealed protocol join. It forwards to
        # `TerminalRendezvous::release` and re-seals the ticket on every arm, so
        # this is the receiver-independent call the census exists to notice --
        # and it is one call, in one function, with no bare ticket escaping.
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "release_protocol_join",
        1,
    ),
    (
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "release_rollback",
        1,
    ),
    (
        "driver/fsring-core/src/effect.rs",
        "drop",
        1,
    ),
    (
        "driver/fsring-fsd/src/boot.rs",
        "release_lock_event",
        1,
    ),
    # 4 -> 3, round 18: `fsring_dispatch_cleanup` now reads the device state
    # before it acquires the dispatch rundown, so the null-state refusal no
    # longer has a guard to release. A CLEANUP refused that rundown takes the
    # committed route instead of completing at once (native review N17-2).
    (
        "driver/fsring-fsd/src/control.rs",
        "fsring_dispatch_cleanup",
        3,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "fsring_dispatch_create",
        2,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "fsring_dispatch_provider",
        1,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "release_close_or_lease",
        2,
    ),
    (
        "driver/fsring-fsd/src/control.rs",
        "release_outer",
        1,
    ),
    # 1 -> 2, round 18: `run_close_plan` releases the registry lock it takes
    # around `take_close_ownership`, before the free.
    (
        "driver/fsring-fsd/src/control.rs",
        "run_close_plan",
        2,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "allocate_state",
        4,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "close_global_admissions",
        1,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "prepare",
        1,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "release_driver_state",
        1,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "release_guard",
        1,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "undo",
        1,
    ),
    (
        "driver/fsring-fsd/src/driver.rs",
        "unregister_etw",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "close_session_admission",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "complete_mount_join",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "complete_mount_owner",
        3,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "complete_mount_reset_join",
        2,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "dismount_and_delete_devices",
        3,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "drain_r3_finalizers",
        3,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "finish_finalizer_fail_stop_visibility",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "fsring_fence_retry_dpc",
        1,
    ),
    (
        # 2 -> 3 (round 15): the retry worker's `Complete` arm now releases the
        # control strong reference it takes, as the primary path always did.
        # Discarding it left `strong_count` one too high, so the terminal
        # release answered `Retained` and the session was never deleted. The
        # third `release` is the registry lock's, around that deposit.
        "driver/fsring-fsd/src/fence.rs",
        "fsring_fence_retry_worker",
        3,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "has_only_terminal_strong_owner",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "observe_one",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "park_and_arm_fence_retry",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "pending_runtime_ptr",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "publish_completed_generation",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "release_control_strong_ref",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "release_mount_reference",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "release_transient_arrays_and_backing",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "resolve_checkpoint_fail_stop_for_mode",
        4,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "run_kernel_fence",
        2,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "run_queued_finalizer",
        8,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "run_terminal",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "run_terminal_arrival",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "run_terminal_for_process",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "session_ptr",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "verify_session_and_root_ledgers",
        1,
    ),
    (
        "driver/fsring-fsd/src/fence.rs",
        "wait_until_mount_drained",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "acquire",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "acquire_parked_strong_refs",
        6,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "claim_committed_protocol",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "claim_native_cleanup_route",
        2,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "complete_cell_access_rundown",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "destroy_shell_then_release_root",
        1,
    ),
    (
        # The abandon path a refused `store_parked_wait` reaches: one registry
        # lock release around the runtime lookup.
        "driver/fsring-fsd/src/lifecycle.rs",
        "fail_unstored_parked_wait",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "fsring_finalizer_callback",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "park_wait_enter",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "queue_cell_finalizer",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "reinitialize_cell_access_rundown",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "release",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "release_parked_strong_refs",
        5,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "release_unpublished",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "reset_cell_and_publish",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "resolve",
        2,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "scan_one_cell_for_process",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "signal_joiners_drained",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "signal_terminal_outcome",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "store_parked_wait",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wait_for_finalizer_resolution",
        7,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wait_for_unload_visibility",
        13,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wait_for_visibility_resolution",
        8,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wait_joiners_drained",
        1,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wait_mount_observation",
        2,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wait_protocol_join_visibility",
        3,
    ),
    (
        "driver/fsring-fsd/src/lifecycle.rs",
        "wake_ready_parked_waits",
        3,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "cancel_pending_timer",
        2,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "deposit_fence_wakes",
        1,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "deposit_readiness_wakes",
        1,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "discharge_parked_handoff",
        1,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        # 2 -> 4 in round 16: the two bugchecks round 15's N2 found firing under
        # the slot-lock hold now release the guard first, which is two more
        # `unlock.release()` call sites on paths that end in a panic.
        "finalize_native_pending_publication",
        4,
    ),
    (
        # Finding #2's fix: read `parked_strong_registry` under this slot's
        # own lock, then release it before the registry-lock-only `link`.
        "driver/fsring-fsd/src/pending_enter.rs",
        "link_parked_control",
        2,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "observe_pending_for_unload",
        1,
    ),
    (
        # Never counted until the `fn` walker was fixed: this signature carries
        # a const-generic argument, so the old parser took `<{ ... }>` from the
        # parameter list as the whole body and the census saw a 35-character
        # fragment instead of these `unlock.release()` calls.
        #
        # 13 -> 15: the installer's handoff obligation is now parked in the slot
        # under its own hold instead of being queued here, because queueing it
        # here races `store_parked_wait` and a worker that wins that race wedges
        # the ring.
        # 15 -> 16: finding #2's three-phase split adds one more release --
        # Phase A's lock, released once before the registry-lock-only link.
        "driver/fsring-fsd/src/pending_enter.rs",
        # 16 -> 17 in round 17: N16-3's repair releases the guard before the
        # bugcheck on a refused handoff, which is one more `.release()` site.
        "park_wait_enter",
        17,
    ),
    (
        # The roster's own `FinishWorkerPass`: one `unlock.release()` around the
        # close of a worker pass, which is where the schedule decides whether
        # another pass is due.
        # 1 -> 3: RemoveIrpFromCsq and PollAndRecheck each gained their own
        # lock hold (item 3's fix for the two writes that raced the DPC), one
        # `unlock.release()` apiece.
        # 3 -> 2: the RemoveIrpFromCsq arm is gone. The dequeue is performed by
        # `run_pending_completion_pass` once it holds the authorities, so a
        # refused pass no longer strands an uncancellable request.
        "driver/fsring-fsd/src/pending_enter.rs",
        "perform_pending_effect",
        2,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "queue_installed_work",
        1,
    ),
    (
        # Unload's timer quiescence: one `unlock.release()` per lock hold, around
        # the epoch read and around the `KeCancelTimer` interpretation.
        "driver/fsring-fsd/src/pending_enter.rs",
        "quiesce_pending_timer_for_teardown",
        2,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "release_arena",
        1,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "release_parked_strong_refs",
        3,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "release_slot_sq_wait",
        1,
    ),
    (
        # 3 -> 5: the dequeue arrived here, bringing the hold that publishes
        # the handoff and the hold on which a NULL CSQ return puts every
        # authority back -- including the completion declaration, because
        # `Completing` refuses both to finish and to queue.
        "driver/fsring-fsd/src/pending_enter.rs",
        "run_pending_completion_pass",
        5,
    ),
    (
        # H3: `store_parked_session_wait` is now a wrapper with one exit and
        # no lock of its own. The two unlock releases moved to the inner
        # function, and the discharge that covers every failing path takes
        # a third of its own -- which is the shape that makes "every exit
        # discharges the handoff obligation" true by construction.
        "driver/fsring-fsd/src/pending_enter.rs",
        "store_parked_session_wait_inner",
        2,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "store_parked_strong_session",
        1,
    ),
    (
        "driver/fsring-fsd/src/pending_enter.rs",
        "take_parked_strong_session",
        1,
    ),
    (
        # Item 1's fix: read `parked_strong_registry` under this slot's own
        # lock, release it, then release the registry lock after `unlink`.
        "driver/fsring-fsd/src/pending_enter.rs",
        "unlink_parked_control_link",
        2,
    ),
    (
        # Finding #2's rollback path: release this slot's own lock before
        # restoring `slot_state`/`install_axis`/the schedule-owner-slot trio.
        "driver/fsring-fsd/src/pending_enter.rs",
        "unwind_reserved_install",
        1,
    ),
    (
        # The generation-checked DPC-exit rendezvous releases the slot lock once
        # per look, before it waits.
        "driver/fsring-fsd/src/pending_enter.rs",
        "wait_pending_dpc_exit",
        1,
    ),
    (
        # The teardown's proof that a DPC which published `Quiesced` has also
        # made its last store into the arena.
        "driver/fsring-fsd/src/pending_enter.rs",
        "wait_pending_dpc_exit_signal",
        1,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "commit_setup_rollback",
        3,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "execute_enter",
        3,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "execute_setup",
        3,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "finish_setup_rollback",
        1,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "install_staging",
        5,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "perform",
        1,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "perform_enter",
        1,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "prepare_setup_rollback",
        6,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "publish_locked_suffix",
        7,
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "unwind_enter",
        1,
    ),
    (
        "driver/fsring-fsd/src/volume.rs",
        "expose_published_mount",
        1,
    ),
    (
        "driver/fsring-fsd/src/volume.rs",
        "perform_mount",
        4,
    ),
    (
        "driver/fsring-fsd/src/volume.rs",
        "undo_mount",
        1,
    ),
)

TASK6_DESTRUCTIVE_SYMBOL_CENSUS = (
    ("IoUnregisterFileSystem", 1),
    ("IoDeleteDevice", 1),
    ("IoDeleteSymbolicLink", 1),
    ("IoFreeWorkItem", 7),
    ("MmUnmapViewInSystemSpace", 5),
    ("ObfDereferenceObject", 13),
    ("ZwClose", 3),
    ("EtwUnregister", 1),
    ("ExFreePoolWithTag", 6),
    ("destroy_prepared_work_items", 2),
    ("remove_dos_link", 3),
    ("unmap_system_view", 3),
    ("close_section", 3),
    ("close_lock_event", 3),
    ("unregister_etw", 5),
    ("delete_fscontrol", 5),
    ("delete_provider", 5),
    ("release_driver_state", 5),
    ("delete_device", 13),
    ("unregister", 6),
    ("delete_symbolic_link", 2),
    ("resolve_one", 2),
    ("MmGetSystemRoutineAddress", 1),
    ("resolve_optional_ddis", 2),
    ("resolve_all", 3),
    ("RESOLVER_TABLE", 2),
    ("NonPagedAllocationOwner", 10),
    ("DriverState", 34),
    ("references", 5),
)

# The complete Task 4 mount-publication closure.  Body hashes are coupled to
# exact-one named items/functions below; the token census closes appended or
# path-shifted helpers that might otherwise preserve each reviewed body.
TASK12_MOUNT_BODY_GRAMMAR = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        (
            "matches_publication_observation",
            ("292ec26d62e7c8a33470d06cce185adec4728a7b605ad87b087b5e97e19602b4",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "publication_observation",
            (
                "3c2ca78b38e439799e92e56f1df36db4cb74749fff623079ba925873c01d58bc",
                "d86f077ca325de153f832e58a96d6ee42aba5ec1c0df6d7929258c3ee7b87712",
                "952053b0c0c320abf94187fde2f85cd4c83319bc99beb1532bd1b228b037a2a5",
                "889ea070090ce4da0b944d2ed00eea7836bdf784157206a876c4d02f4f09c024",
            ),
            "Task 12 locked mount bundle kind seal",
        ),
        (
            "signal_then_ack",
            (
                "96333be63fe4f92c39f2b17bcb1a63e2f0270151f5e71a79264c26e6c7215599",
                "470663b5968f0d993e3fa83d3a7b00dcb4337be810fe7e4e0e91a761bf9791f5",
                "c1e89f046433502ce8231cce4741afb62a1954386dbc9efb254972ce4a3eecc6",
                "1a69ef97420f4a58c3ba682cc0f285b8725593ffccff6ae713342016fe7d32d5",
            ),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "run_r3_mount_done_signal_ack",
            ("f48a40cb7eddd3129e081d21eb32a1c36cff6150f3ebc94affb3e69ebc6ab90b",),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "matches_generation",
            ("0d1b2983aa77081d28c000de6bf67e4df8a1fe3280142b6627402bdc16720434",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "matches_wait_observation",
            ("c0e9461c1296c59d5d56978baadf04b07ff95790b209b0d2624cc206c0cc2326",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "poll_drain",
            ("c3c5ea5c3b19c809d763e6232bef92b619c06e1512b262ecbea2ad7d53312065",),
            "Task 12 late Join drain retry authority",
        ),
    ),
    "driver/fsring-core/src/adapter/fence.rs": (
        (
            "bind_completed_mount_teardown",
            ("aff200685b7d9801f166b28cffc3d40f228d6b7f56668d3ddd1919953bcaefc9",),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "locator_eq",
            ("c805f978d642d36dc1740a5433e6c0fa3dc63f5c9cb87d734e64c4e7cf7f90fe",),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "identity_eq",
            ("37673ffa6e06e6614752713e892667c161f41f18beff19854574ecdf6654a303",),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "absence_cursor_eq",
            ("32925fa47031997b3eb64d0f6bac53c8b98cfec9c21b9683c9ea2adce0697284",),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "mount_teardown_permits_delete",
            ("1bc3038fe555495dad10146a0b6d4cfef4c4996842ec15e23a1782eaa9a285bc",),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "matches",
            ("5bae043c522cf9a221c7869e950286842dee014706d3b213dc03c5b1cd67fa31",),
            "Task 12 shell VDO post-bind suffix",
        ),
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "observed_mount_event",
            ("2e4e9495894cfc0c0e4b8742df8822eef80c785e6e5b1cd58b0b444de27e7de4",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "mount_event_ptr",
            ("ee6a7c9ce1d4d8921a97bd71a7a7604d81b44bdc484592adaaf016e7b28e0eee",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "set_prepared_mount_event",
            ("ca720f80164086551b8c2249e9f14896c76227e0731d68e1502292d9a8e19d86",),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "wait_mount_observation",
            ("536663db480de4b17e06ae477aaa78369e90807a679d861000430e835837759e",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "prepare_locked_mount_publication",
            ("291d04481c4ba0c32b5ef692056286a3df723642ccc4895e70226e769a7ab192",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "publish_mount_complete_locked",
            ("112f13434f06c0e6c14fb033347f6f15cc0ef5a0b1fcc0634158467d0a8347ef",),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "publish_mount_waiters_drained_locked",
            ("9c03f89fec6e2746ba47a0d8a30819071fc9d2633d87ce3852cb6a4cb8a4be07",),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "publish_mount_reset_complete_locked",
            ("20464c922080868befc0bafb45a082669572eb56f3784cbb3de65611e5425ea3",),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "publish_mount_reset_waiters_drained_locked",
            ("ae304715d1a4dd908fd9d2a1e72c414d74ad86d1b431db21530f367e09d644a0",),
            "Task 12 locked mount signal-then-ack window",
        ),
        (
            "signal_terminal_outcome",
            ("d57036a2144ed141681fc7c4c817e7f839a03400ea62a6af3f69addc3057a68a",),
            "Task 12 terminal signal post-unlock",
        ),
        (
            "signal_joiners_drained",
            ("05ac8f818271078f874b8ce7ab6cf0b03b07eb11b1d2c50f5df6488c9c377259",),
            "Task 12 terminal signal post-unlock",
        ),
        (
            "mount_rendezvous",
            ("18e244b4d83b444077b01588b91f998dbb7dab867dce788ac3ab746cc0d9b177",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "mount_rendezvous_mut",
            ("c64813a1677faea95196db749b2d56b4c85f440da84df92599c288839bc171db",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "matches_wait_observation",
            ("0dac03d8fb244ad6cb0223002ade7e8a35a95f8527b60dfc78bb6db4e711ced5",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "delete",
            ("7e96b0f2e7448107e727c5f4e0b11ac074047da5a9ec99e4c9da50fc8a212f87",),
            "Task 12 mount-owned teardown owner-only",
        ),
        (
            "clear_binding",
            ("b9993afdcc0f086ea33075d132bb6d28cb577b44d5515b909c31e43770f33a6e",),
            "Task 12 mount-owned teardown owner-only",
        ),
        (
            "prepare_mount_install",
            ("51743d50ee0c1ecb655a0abb311b20e24ecad24e615269def02a91b21cd0f954",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "commit_prepared_mount_install",
            ("c37862c53ac7ea57d8ad8f5efdaedc8e450fbd251bd033273dbbe885e556d8bc",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "take_or_join_mount",
            ("a9b78918de3beebe942315a835c3018ecdd4590290f4640bbbad9a94406c898c",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "release_mount_join",
            ("5bfd22aa24a6b7acea445b09653de5acd5068b6a58720fb5baae53c752bfa2db",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "prepare_locked_mount_done_publication",
            ("3e58aa61b38963e0081053b8d72fedcd963ad38fe1bc5f02b565fe80a2ecf56f",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "prepare_locked_mount_join_conversion",
            ("af304f16d496b68e94675e805723bf7cf971762619926c643490ba9dcc85085f",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "prepare_locked_mount_reset_publication",
            ("3e58aa61b38963e0081053b8d72fedcd963ad38fe1bc5f02b565fe80a2ecf56f",),
            "Task 12 prepared locked mount publication aggregate",
        ),
        (
            "prepare_locked_mount_reset_join_release",
            ("7eb5cf3128a5f83a0b70e63d9d2c1778aad0d300f06bf64c2ea495d7fed68745",),
            "Task 12 prepared locked mount publication aggregate",
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "wait_until_mount_drained",
            ("bde7a397234d4fd782ed8e4f22e7bbb117cec731409b399ea6a25587610bc237",),
            "Task 12 late Join drain retry authority",
        ),
        (
            "bind_mount_completion_and_delete_shell_vdo",
            ("011a69688b12602c98dbbe0bee5fef7287f19767cbf9092411eb3e6cba0986c2",),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "complete_mount_owner",
            ("3c0accb1c204bf7bd9d7a7fa963938b394b4723926ae8078828132fbee4e50e8",),
            "Task 12 mount-owned teardown owner-only",
        ),
        (
            "complete_mount_reset_join",
            ("a304b733ba2292d6bd83f598f93a7f825705df6f5171c41a89d8cae70fcdb685",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "complete_mount_join",
            ("91977103972ffef1f2bf81ec2a31b2cc4d68909023f592edf4e0158cf969cce2",),
            "Task 12 mount wake-to-registry-first",
        ),
        (
            "dismount_and_delete_devices",
            (
                "5ade5d9546bfc2710566388a73cf2edf2ed5ec0eac91bb3f809aecafca08ff03",
                "cf462b95b287ec3cd9e815d0131cbff82e9184591793e3ed92aa02396fbccbaa",
            ),
            "Task 12 shell VDO post-bind suffix",
        ),
        (
            "delete_shell_vdo",
            ("dc807c5429d5b57395b7007a3481a49723124753ba53353cc58fcf65bc22f712",),
            "Task 12 shell VDO post-bind suffix",
        ),
    ),
    "driver/fsring-fsd/src/session.rs": (
        (
            "vdo_slot_contains_device",
            ("7f676724d39484e8ec7c45204c20216f8c6ce2f9c1e1893baa5528fd496172c7",),
            "Task 12 shell VDO take-once deletion",
        ),
        (
            "delete_vdo_once",
            ("8bb08634ed082817ed05ab61be5a850da691520ac6be86da328acd6b5744c432",),
            "Task 12 shell VDO take-once deletion",
        ),
    ),
    "driver/fsring-fsd/src/volume.rs": (
        (
            "mount_vpb",
            ("e233d952a74e613c403d934770fdd89ea3f107ad39b8ee5a31cf29e4914a28d7",),
            "Task 12 exact mount rollback plan",
        ),
        (
            "mounted_device",
            ("5969fabbb4389b9b555342d3be4fba759511f3e5d5242f12e098eaa60bfeafd7",),
            "Task 12 exact mount rollback plan",
        ),
        (
            "acquire_vpb",
            (
                "bd8824baccb50ec0e67d11e500080b4f0e74cecbd5c621a0141a315aabc3b691",
                "12d08ce4cc9dbc0ac3bdfe1cc6adf48ea755103e2aa8b22b079f5b45f8819dcd",
            ),
            "Task 12 exact mount rollback plan",
        ),
        (
            "commit_revalidation_has_vpb_lock",
            ("84859bc8a17fbed33493092da05f24b311d4da8b0876b1f9535003dbeffbde21",),
            "Task 12 mount commit VPB lock continuity",
        ),
        (
            "release_vpb",
            (
                "78387cebd742f5553e759b332fda997e2ed69ca0c2d4ea2424e4eefc362e12c0",
                "7803efacd0c6756c12ffea08a230290ae3b3ffdecc9629ec72aecde034e46d69",
            ),
            "Task 12 exact mount rollback plan",
        ),
        (
            "drive_mount",
            ("23841a013764e7ca16c8881352d7c7038ff9df3a9d57423f02c2c0f22f065cd3",),
            "Task 12 exact mount rollback plan",
        ),
        (
            "perform_mount",
            ("b36b68ecf6a52ac77e82f596516c1925ebed8fe232553e3b3d5bcd27578fed24",),
            "Task 12 mount commit VPB lock continuity",
        ),
        (
            "unwind_mount",
            ("4ab85bd19903acf24c27d72cab43c9da62bea05b13dd8b8b437ed5656f24aa93",),
            "Task 12 exact mount rollback plan",
        ),
        (
            "undo_mount",
            ("c9518bcd1dbd8830d053d6db38256dc11a38faf08c6df28c5ff4c4236c9f4d1c",),
            "Task 12 exact mount rollback plan",
        ),
    ),
    "driver/fsring-core/src/volume.rs": (
        (
            "vpb_clear_semantics",
            ("ef5f8b015e9b5e8b641497f31ccb12494fe304625aba774cdad0e9a004c74d9b",),
            "Task 12 exact mount rollback plan",
        ),
        (
            "pre_effect_rollback",
            ("0082187841f10069bc60e48f2e7b93c9996799cc3e140b2e37062ea2f0af303a",),
            "Task 12 exact mount rollback plan",
        ),
    ),
}

TASK12_MOUNT_IMPL_GRAMMAR = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        (
            "implMountOwnerPublication",
            "33a603e401d403d57b0de9e3f653a58e9c3158d3d13f93160bc7487621908cd1",
        ),
        (
            "implMountDonePublication",
            "bc5d5143f59b2e1fc1de7d15ac78cee7d8522aab90dca6a33258df113ba2a45d",
        ),
        (
            "implMountJoinConversion",
            "b834e0a1c36f898db030481e28ffe0225107c3a65dba5600c968e027d2135ab3",
        ),
        (
            "implMountResetPublication",
            "33b9ec7cd466e5cf71111a7e5d7b31931cd5958997f3bb06f09b541ed96649ff",
        ),
        (
            "implMountResetJoinRelease",
            "96022f21e6848d70fad14fbdc879409daa0db9e55247d0b6177f4fd92a27bd94",
        ),
        (
            "implMountDonePublication",
            "a89c915cc4d4df54fbde4d2063d6d5d1601c565407d9330883e32e5624985590",
        ),
        (
            "implMountJoinConversion",
            "d09c12f8537136451ab3d043c20aab5ab48d88e0b58ee5d7dc39be36125f44a1",
        ),
        (
            "implMountResetPublication",
            "5167011e436203d955c987b7e5b8676b275ab806ee714769d15f61ed8019ea29",
        ),
        (
            "implMountResetJoinRelease",
            "7442f04b51371a9f93b0428a710d8bfa9051b8f9cb819ea84b13c9418493bec5",
        ),
        (
            "impl<Device,Vpb>MountRendezvous<Device,Vpb>",
            "36ec54b785eeb5e19efef028d6efea978aa616ae325976f8ee6e58d3c202c6da",
        ),
        (
            "implFnOnce(&Device),)->Result<(),(LifecycleError,MountOwnerPublication)>",
            "e7a28a29696bef5e66925b4d12fe9b9a8cd76ebebacc5f9b9e63ce6a430729ce",
        ),
    ),
    "driver/fsring-core/src/adapter/fence.rs": ((
        "implCompletedMountTeardown",
        "7d6f147ed33e866ccc0014763af5b3eb2d5127b0733c82e9d9d715706d4b3ac3",
    ),),
    "driver/fsring-core/src/volume.rs": ((
        "implMountRollbackEffect",
        "8fb469786e285dd4841ddd6e7d6b515f0e4355fb3806eec52430c4e9cddd5ed1",
    ),),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "implNativeMountedDeviceOwner",
            "c8b22e7933295c506d7edb773e8a47ae7ac974b2aca779e192a31cffa1bb9942",
        ),
        (
            "implNativeMountedVpbOwner",
            "cc07f5af8fc5853ea0a5b0add20ca4a8ed28f43431fff80b1c084020bfb84d6c",
        ),
        (
            "implNativeMountOwnerPublication",
            "0da88ff8b978e20db0baf946c01916020c011a38578f71ab3d72ba29cfad2642",
        ),
        (
            "implNativeMountRendezvous",
            "05e58bd3b6d79ec94383482570ffc88fea8439c409b1f516b84745351c7684a5",
        ),
    ),
}

TASK12_MOUNT_IMPL_TYPES = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        "MountOwnerPublication", "MountDonePublication", "MountJoinConversion", "MountResetPublication",
        "MountResetJoinRelease", "MountRendezvous",
    ),
    "driver/fsring-core/src/adapter/fence.rs": ("CompletedMountTeardown",),
    "driver/fsring-core/src/volume.rs": ("MountRollbackEffect",),
    "driver/fsring-fsd/src/lifecycle.rs": (
        "NativeMountedDeviceOwner", "NativeMountedVpbOwner", "NativeMountOwnerPublication",
        "NativeMountRendezvous",
    ),
}

TASK12_MOUNT_TOKEN_NAMES = (
    "LockedMountPublicationBundle", "PreparedLockedMountPublication",
    "MountPublicationObservation", "MountPublicationKind", "signal_then_ack",
    "set_prepared_mount_event", "acknowledge_done_signal", "acknowledge_join_signal",
    "acknowledge_reset_signal", "acknowledge_reset_join_signal",
    "wait_mount_observation", "MountDrainRight", "delete_shell_vdo",
    "delete_vdo_once", "acquire_vpb", "commit_revalidation_has_vpb_lock",
    "MountRollbackEffect", "MountDonePublication", "MountJoinConversion",
    "MountResetPublication", "MountResetJoinRelease",
)

TASK12_MOUNT_TOKEN_CENSUS = {
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        0,
        0,
        11,
        5,
        8,
        0,
        2,
        2,
        2,
        2,
        0,
        12,
        0,
        0,
        0,
        0,
        0,
        6,
        6,
        6,
        6,
    ),
    "driver/fsring-core/src/adapter/volume.rs": (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-core/src/effect.rs": (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        13,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-core/src/volume.rs": (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        33,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/fence.rs": (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        2,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/lifecycle.rs": (
        6,
        15,
        7,
        3,
        0,
        5,
        0,
        0,
        0,
        0,
        1,
        5,
        0,
        1,
        0,
        0,
        0,
        9,
        10,
        9,
        9,
    ),
    "driver/fsring-fsd/src/session.rs": (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ),
    "driver/fsring-fsd/src/volume.rs": (
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        4,
        2,
        8,
        0,
        0,
        0,
        0,
    ),
}

TASK12_ROLLBACK_TOKEN_CENSUS = {
    "driver/fsring-core/src/effect.rs": 13,
    "driver/fsring-core/src/volume.rs": 33,
    "driver/fsring-fsd/src/volume.rs": 8,
}

TASK12_UNSAFE_TOKEN_CENSUS = {
    # Task 20's credit lane adds one: `PendingCqCommit::commit` converts the
    # claim through `ClaimedNotification::after_release_head_advance`, whose
    # safety obligation -- that the Release head store happened exactly once,
    # immediately before -- is discharged by the line above the call and by this
    # being the only route from that type to the advanced one.
    "driver/fsring-core/src/adapter/enter.rs": 8,
    "driver/fsring-core/src/adapter/fence.rs": 121,
    "driver/fsring-core/src/adapter/lifecycle.rs": 20,
    "driver/fsring-core/src/adapter/load.rs": 45,
    "driver/fsring-core/src/alloc.rs": 1,
    "driver/fsring-core/src/effect.rs": 7,
    "driver/fsring-core/src/enter.rs": 8,
    "driver/fsring-core/src/grant.rs": 1,
    "driver/fsring-core/src/session.rs": 17,
    "driver/fsring-core/src/typestate.rs": 6,
    "driver/fsring-fsd/src/boot.rs": 102,
    # 218 -> 223, round 18: CLOSE takes ownership under the registry lock
    # (`run_close_plan`: the lock, its release, and the detach-only arm for a
    # device with no state) and `fsring_dispatch_close` projects that registry
    # (`state_from_device`, `NonNull::new_unchecked`).
    # 223 -> 224, round 19 (native review N18-1): the wait between a refused
    # stack expansion and the next attempt. One block, holding nothing -- the
    # outer file rundown is released before the callout and the registry lock
    # is taken inside it.
    # 224 -> 225, round 20 (native review N18-2): CLOSE reads the binding's
    # state inside the hold that takes the lifetime slot, which is what decides
    # whether the CREATE lease in it is anybody else's.
    "driver/fsring-fsd/src/control.rs": 225,
    # 173 -> 176 (round 15): `publish_provider_device`, which moves the one
    # DISPATCH-visible root field ahead of the publish that clears
    # DO_DEVICE_INITIALIZING. Its `unsafe fn`, its body write, and the call
    # in the `PublishProvider` arm; the write it replaces in `finish` is
    # inside an existing `unsafe` block, so removing it frees no token.
    "driver/fsring-fsd/src/driver.rs": 176,
    # 498 -> 502 (round 15): the retry worker's `Complete` arm gained the
    # registry lock/release pair around the control-strong-ref deposit, and the
    # `queue_finalizer` call whose kick that arm previously discarded. Four
    # `unsafe` tokens for two repairs the primary path already performed.
    "driver/fsring-fsd/src/fence.rs": 502,
    "driver/fsring-fsd/src/fscontrol.rs": 13,
    "driver/fsring-fsd/src/kernel.rs": 32,
    "driver/fsring-fsd/src/lib.rs": 31,
    # 524 -> 529: the refused-store abandon wrapper.
    # 529 -> 531 (round 15): the CLEANUP completed-record arm gained the
    # `acknowledge_completed_control` call and the put-back that its refusal
    # edge owes, both under the lock the contract names.
    "driver/fsring-fsd/src/lifecycle.rs": 531,
    # 308 -> 311: the CSQ dequeue moved out of the roster prefix into
    # `run_pending_completion_pass`, which added its own publication hold and
    # the refusal hold that hands the completion declaration back.
    # 311 -> 317: `fail_unstored_parked_wait` and its inner half.
    "driver/fsring-fsd/src/pending_enter.rs": 319,
    "driver/fsring-fsd/src/seh.rs": 4,
    # ENTER drain lives on `execute_enter`; the trampoline's `unsafe { }`
    # call plus `unsafe fn execute_enter` add two tokens. 511 -> 510 when the
    # shared `static mut APC_STATE: KAPC_STATE = unsafe { core::mem::zeroed() }`
    # was deleted: its initializer was the removed token, and the per-window
    # `MaybeUninit::uninit()` scratch that replaced it is a safe expression.
    # 510 -> 511: the refused-store abandon call is one more `unsafe` block.
    # 509 -> 511 (round 15): the ring-set loop's unguarded shell projection
    # and its mutable ring slice, for the brand stamp described above.
    # 511 -> 518 (round 15): `r4_checkpoint_sq_roles_are_drained` (4) and
    # `checkpoint_wait_sq_roles_with_consumers_held` (3), the R4 drain's own
    # SQ-only predicate and its per-ring walk.
    # 518 -> 519 (round 15, B7): the pending runtime's consuming release at
    # the head of `unwind`. It had no unwind entry at all, and
    # `PendingRuntimeReady` has no `Drop`, so every SETUP that refused after
    # `build_pending_runtime` leaked the arena and up to 64 work items.
    # 519 -> 520, round-17 evidence E4 (`609d934`): SETUP no longer refuses a
    # wrong length before the header is read, so its snapshot has three
    # refusal exits (below the header, the bounded copy, the validator's own
    # status) where it had two.
    #
    # Re-derived in round 21 by replaying this count -- `strip_noncode`, then
    # `\bunsafe\b` -- over every commit from `23f532f`: it is 519 at
    # `c7c30af`, 520 at `609d934`, and never moves again. `0bfefa6`, which
    # moved the snapshot into `snapshot_and_validate_setup`, changed nothing:
    # four tokens out (the length refusal's rollback, the `get_mut` refusal's
    # rollback, the inline copy block, the validator refusal's rollback) and
    # four in (the helper's `unsafe fn`, its copy block, the call to it, and
    # the rollback after that call). Round 19 attributed the move to that
    # refactor and deleted the explanation above (round-20 evidence review,
    # E1).
    "driver/fsring-fsd/src/session.rs": 520,
    "driver/fsring-fsd/src/trace.rs": 8,
    # 141 -> 143: the two driver-object reads the mount ownership check makes.
    "driver/fsring-fsd/src/volume.rs": 143,
}

# --------------------------------------------------------------------------
# The process-attach scratch (round-9 blocker 1)
# --------------------------------------------------------------------------
#
# `KeStackAttachProcess` saves the CALLING THREAD's `ApcState` into the buffer
# it is handed and `KeUnstackDetachProcess` restores from it, so that buffer
# must be owned by the attaching thread for the whole window. Before this rule
# existed the driver passed one `static mut APC_STATE` to every attach and
# detach, and two concurrent SETUPs -- or a SETUP and a terminal fence --
# overwrote each other's saved state.
#
# Three things are frozen, and the third is deliberately roster-independent:
#
#   * every `static` item in the two production roots, so a new shared buffer
#     under any name has to change this table;
#   * the exact (file, function, callee, argument) tuple of every attach,
#     detach and `attach_session_process` call site, so a respelled argument
#     has to change it too;
#   * the SHAPE of every observed scratch argument, checked against the source
#     rather than against the table. Updating the table to match bad code does
#     not buy past this one: an argument that reaches a global -- `addr_of!`,
#     `addr_of_mut!`, or a SCREAMING_CASE item path -- is a finding whatever
#     the roster says.
#
# What this does NOT prove: that each buffer is uniquely owned by the attaching
# thread at run time. `fsring-fsd` has no executing tests, so that remains a
# soundness argument over frame ownership, not a measured property.
ATTACH_SCRATCH_DDIS = ("KeStackAttachProcess", "KeUnstackDetachProcess")

ATTACH_SCRATCH_HELPER = "attach_session_process"

# (relative path, item name) for every `static` in production source.
ATTACH_SCRATCH_STATIC_ROSTER = (
    ("driver/fsring-core/src/adapter/fence.rs", "NEXT_FENCE_RETRY_LIFECYCLE_ID"),
    ("driver/fsring-core/src/adapter/lifecycle.rs", "NEXT_MOUNT_PUBLICATION_ID"),
    ("driver/fsring-core/src/enter.rs", "NEXT_ENTER_STATE_ID"),
    ("driver/fsring-core/src/grant.rs", "NEXT_GRANT_TABLE_ID"),
    ("driver/fsring-core/src/pagingledger.rs", "NEXT_SEQUENCER_ID"),
    ("driver/fsring-core/src/reqtab.rs", "NEXT_TABLE_ID"),
    ("driver/fsring-core/src/session.rs", "NEXT_CONTROL_BINDING_ID"),
    ("driver/fsring-core/src/session.rs", "NEXT_RING_SET_ID"),
    ("driver/fsring-core/src/session.rs", "NEXT_RING_STATE_ID"),
    ("driver/fsring-core/src/session.rs", "NEXT_CONTROL_PENDING_LEDGER_ID"),
    ("driver/fsring-core/src/terminal.rs", "NEXT_ARBITRATION"),
    ("driver/fsring-fsd/src/driver.rs", "fsring_driver_state"),
    ("driver/fsring-fsd/src/kernel.rs", "fsring_resolved_ex_allocate_pool2"),
    ("driver/fsring-fsd/src/session.rs", "NEXT_ENTER_INVOCATION"),
)

# (relative path, enclosing function, callee, whitespace-stripped arguments).
ATTACH_SCRATCH_CALL_ROSTER = (
    (
        "driver/fsring-fsd/src/session.rs",
        "attach_captured",
        "KeStackAttachProcess",
        "process.cast(),context.apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "guarded_detach",
        "KeUnstackDetachProcess",
        "context.apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "detach_current",
        "KeUnstackDetachProcess",
        "context.apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "checkpoint_release_read_only_mappings_reverse",
        "KeUnstackDetachProcess",
        "apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "checkpoint_release_read_only_mappings_reverse",
        "attach_session_process",
        "session,apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "unmap_writable_aliases",
        "KeUnstackDetachProcess",
        "apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "unmap_writable_aliases",
        "attach_session_process",
        "session,apc_state.as_mut_ptr()",
    ),
    (
        "driver/fsring-fsd/src/session.rs",
        "attach_session_process",
        "KeStackAttachProcess",
        "process.cast(),scratch",
    ),
)

ATTACH_SCRATCH_STATIC_ITEM = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?static\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*([^=;]+?)\s*="
)

ATTACH_SCRATCH_CONST_ITEM = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?const\s+([A-Za-z_]\w*)\s*:\s*([^=;]+?)\s*="
)

ATTACH_SCRATCH_GLOBAL_ARGUMENT = re.compile(r"addr_of|\b[A-Z][A-Z0-9_]{2,}\b")


def _attach_scratch_call_arguments(body, open_paren):
    """The balanced argument text of one call, or None when unbalanced."""
    depth = 0
    collected = []
    for index in range(open_paren, len(body)):
        char = body[index]
        if char == "(":
            depth += 1
            if depth == 1:
                continue
        elif char == ")":
            depth -= 1
            if depth == 0:
                return "".join(collected)
        if depth >= 1:
            collected.append(char)
    return None


def _attach_scratch_split(arguments):
    """Split one argument text on top-level commas."""
    parts = []
    depth = 0
    current = []
    for char in arguments:
        if char in "([<":
            depth += 1
        elif char in ")]>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def attach_scratch_findings(production, evidence=None):
    """Freeze where every process-attach window keeps its `KAPC_STATE`."""
    findings = []

    def require(condition, label, detail):
        if evidence is not None:
            evidence.append("driver/fsring-fsd/src/session.rs:attach-scratch-" + label)
        if not condition:
            findings.append(detail)

    observed_statics = []
    kapc_items = []
    observed_calls = []
    shaped = []
    for rel in sorted(production):
        text = strip_noncode(production[rel])
        for match in ATTACH_SCRATCH_STATIC_ITEM.finditer(text):
            observed_statics.append((rel, match.group(1)))
            if "KAPC_STATE" in match.group(2):
                kapc_items.append("%s: static %s" % (rel, match.group(1)))
        for match in ATTACH_SCRATCH_CONST_ITEM.finditer(text):
            if "KAPC_STATE" in match.group(2):
                kapc_items.append("%s: const %s" % (rel, match.group(1)))
        for name, _header, body in function_headers_and_bodies(text):
            for callee in ATTACH_SCRATCH_DDIS + (ATTACH_SCRATCH_HELPER,):
                for match in re.finditer(r"\b%s\s*\(" % callee, body):
                    arguments = _attach_scratch_call_arguments(body, match.end() - 1)
                    if arguments is None:
                        findings.append(
                            "%s: %s call in %s has unbalanced arguments" % (rel, callee, name)
                        )
                        continue
                    observed_calls.append(
                        (rel, name, callee, "".join(arguments.split()))
                    )
                    parts = _attach_scratch_split(arguments)
                    scratch = parts[-1].strip() if parts else ""
                    shaped.append((rel, name, callee, scratch))

    require(
        tuple(sorted(observed_statics)) == tuple(sorted(ATTACH_SCRATCH_STATIC_ROSTER)),
        "static-roster",
        "the production `static` roster changed: a new shared item is a candidate "
        "attach scratch and has to be reviewed as one",
    )
    require(
        not kapc_items,
        "no-kapc-item",
        "a `static`/`const` item declares KAPC_STATE storage, which every attach "
        "window would then share: " + ", ".join(sorted(kapc_items)),
    )
    require(
        tuple(observed_calls) == tuple(ATTACH_SCRATCH_CALL_ROSTER),
        "call-roster",
        "the attach/detach call roster changed; every window's scratch argument "
        "is frozen",
    )
    # Roster-independent: whatever the table says, the argument that reaches the
    # kernel must not be a global. Updating the roster to match bad code is the
    # obvious way past a frozen table, and this check does not consult it.
    global_arguments = [
        "%s: %s in %s passes `%s`" % (rel, callee, name, scratch)
        for rel, name, callee, scratch in shaped
        if ATTACH_SCRATCH_GLOBAL_ARGUMENT.search(scratch)
    ]
    require(
        not global_arguments,
        "argument-shape",
        "an attach scratch argument reaches a global rather than a frame or "
        "context binding: " + ", ".join(sorted(global_arguments)),
    )
    require(
        len(shaped) >= len(ATTACH_SCRATCH_CALL_ROSTER),
        "argument-shape-coverage",
        "the shape check saw fewer call sites than the roster names, so it "
        "measured nothing",
    )
    return findings


TASK12_MACRO_DEFINITION_GRAMMAR = (
    ("driver/fsring-core/src/adapter/fence.rs", "private_authority_seals", "{", "94c16a6a159f9a097767bc76da9850e15d8ebfa7276a7b4fdbf5616d612d0b0e"),
    ("driver/fsring-core/src/adapter/lifecycle.rs", "private_authority_seals", "{", "94c16a6a159f9a097767bc76da9850e15d8ebfa7276a7b4fdbf5616d612d0b0e"),
    ("driver/fsring-core/src/adapter/lifecycle.rs", "mount_generation_observers", "{", "92209cf61108ba40e8de51056ab70b87b350a6721ea0b1f07265971cbb1af9b0"),
    ("driver/fsring-core/src/adapter/lifecycle.rs", "mount_completion_observers", "{", "6e3d4b2d1556ea443f5beb821609ca65df20fa67607e7f864821ca3f806c01fd"),
    ("driver/fsring-core/src/adapter/lifecycle.rs", "mount_publication_kinds", "{", "616ed2735d563446f48111eb96f9481a865fa52545b8d1172ee9925872795f15"),
    ("driver/fsring-core/src/adapter/lifecycle.rs", "mount_wait_observer", "{", "12e3d7ed34ee0a520832679cb4ab266976b2042022f2e74ab1e0478ada0e90ac"),
    ("driver/fsring-core/src/controldev.rs", "control_ioctl_registry", "{", "580564d21edb6078fb1cd5b38ce007d7ec691a40a34e8c6ef7c573f67beff993"),
    ("driver/fsring-core/src/enter.rs", "pending_authority_seals", "{", "94c16a6a159f9a097767bc76da9850e15d8ebfa7276a7b4fdbf5616d612d0b0e"),
    ("driver/fsring-core/src/session.rs", "private_authority_seals", "{", "ccd9f06beffcbdfb4bdca92d55727ab93cf30b28dbb8218d681c86f1bd262ccc"),
    ("driver/fsring-core/src/session.rs", "locator_getter", "{", "ee2be77c2fd442b08e60ac32c82bfff520fbc7a2dd558b9d7b16d6430a9fcd28"),
    ("driver/fsring-fsd/src/control.rs", "private_authority_seals", "{", "4c15f20c5e610fd1970cd9b13d315d5818314dfeda9e4815e74a2b5ec77d04fe"),
    ("driver/fsring-fsd/src/fence.rs", "private_authority_seals", "{", "4c15f20c5e610fd1970cd9b13d315d5818314dfeda9e4815e74a2b5ec77d04fe"),
    ("driver/fsring-fsd/src/lifecycle.rs", "private_authority_seals", "{", "4c15f20c5e610fd1970cd9b13d315d5818314dfeda9e4815e74a2b5ec77d04fe"),
)

TASK12_MACRO_INVOCATION_CENSUS = {
    "driver/fsring-core/src/adapter/enter.rs": (
        # Task 20: the const assertion that ties the CQE's 24 output bytes to
        # `size_of::<OControl>()`, so the shape check in
        # `has_conservative_notify_shape` cannot outlive the ABI shape it reads.
        (
            "assert",
            1,
        ),
        (
            "matches",
            2,
        ),
        (
            "panic",
            1,
        ),
        # Task 21: `BoundProtocolCommit::commit_protocol_abort` proves the
        # release cannot fail there -- `commit_cq_release` is handed the
        # identity `prepare_cq_release` recorded from the same still-held token,
        # and the token has been inside the packet the whole time. The
        # `unreachable!` states that, so a future edit that made the release
        # fallible again would panic rather than silently drop the role.
        (
            "unreachable",
            5,
        ),
    ),
    "driver/fsring-core/src/adapter/fence.rs": (
        (
            "debug_assert",
            1,
        ),
        # 23 -> 22 in round 16: `restore_released_token`'s phase gate became an
        # in-flight-ring comparison, which is not a `matches!`. The phase could
        # not answer "is this the token this cursor handed out", and reading it
        # instead refused exactly ring 0 -- round 15's N1.
        (
            "matches",
            22,
        ),
        (
            "private_authority_seals",
            5,
        ),
        (
            "unreachable",
            5,
        ),
    ),
    "driver/fsring-core/src/adapter/lifecycle.rs": (
        (
            "debug_assert",
            5,
        ),
        (
            "debug_assert_eq",
            9,
        ),
        (
            "matches",
            17,
        ),
        (
            "mount_completion_observers",
            3,
        ),
        (
            "mount_generation_observers",
            1,
        ),
        (
            "mount_publication_kinds",
            1,
        ),
        (
            "mount_wait_observer",
            5,
        ),
        (
            "private_authority_seals",
            1,
        ),
        (
            # Task 21: `complete_protocol_reject` states that a zero-length
            # failure always validates, so an edit that made the reject's
            # completion fallible would panic rather than silently answer a
            # rejected arrival with a success.
            "unreachable",
            5,
        ),
    ),
    "driver/fsring-core/src/adapter/load.rs": (
        (
            "assert",
            1,
        ),
        (
            "matches",
            1,
        ),
        (
            "unreachable",
            2,
        ),
    ),
    "driver/fsring-core/src/adapter/mod.rs": ((
        "assert",
        2,
    ),),
    "driver/fsring-core/src/adapter/setup.rs": (
        (
            "assert",
            1,
        ),
        (
            "matches",
            12,
        ),
    ),
    "driver/fsring-core/src/adapter/volume.rs": ((
        "matches",
        5,
    ),),
    "driver/fsring-core/src/controldev.rs": (
        (
            "control_ioctl_registry",
            2,
        ),
        (
            "matches",
            4,
        ),
    ),
    "driver/fsring-core/src/effect.rs": ((
        "matches",
        11,
    ),),
    "driver/fsring-core/src/effect/oracles.rs": (
        (
            "include_str",
            2,
        ),
        (
            "matches",
            5,
        ),
    ),
    "driver/fsring-core/src/enter.rs": (
        (
            "debug_assert_eq",
            1,
        ),
        (
            "matches",
            8,
        ),
        (
            "panic",
            1,
        ),
        (
            "pending_authority_seals",
            5,
        ),
        (
            "unreachable",
            8,
        ),
    ),
    "driver/fsring-core/src/grant.rs": (
        (
            "matches",
            4,
        ),
        (
            "unreachable",
            7,
        ),
    ),
    "driver/fsring-core/src/lockrank.rs": ((
        # Task 20's `SPIN_LOCK_MASK` folds `kind()` over `ALL_RANKS`, so the
        # leaf rule reads the same source the kind census does. That is the
        # third `matches!`.
        "matches",
        3,
    ),),
    "driver/fsring-core/src/pagingledger.rs": (
        (
            "debug_assert_eq",
            1,
        ),
        (
            "matches",
            3,
        ),
        (
            "unreachable",
            3,
        ),
    ),
    "driver/fsring-core/src/reqtab.rs": ((
        "matches",
        20,
    ),),
    "driver/fsring-core/src/session.rs": (
        (
            "assert",
            7,
        ),
        (
            "debug_assert",
            1,
        ),
        (
            "env",
            6,
        ),
        (
            "locator_getter",
            4,
        ),
        (
            "matches",
            16,
        ),
        (
            "panic",
            7,
        ),
        (
            "private_authority_seals",
            3,
        ),
        (
            "unreachable",
            30,
        ),
    ),
    "driver/fsring-core/src/size.rs": ((
        "matches",
        2,
    ),),
    "driver/fsring-core/src/volume.rs": ((
        "matches",
        2,
    ),),
    "driver/fsring-fsd/src/boot.rs": (
        (
            "assert",
            20,
        ),
        (
            "matches",
            1,
        ),
        (
            "offset_of",
            2,
        ),
    ),
    # `addr_of_mut` 12 -> 14, round 18: `fsring_dispatch_close` projects the
    # registry for CLOSE's locked take, and `run_close_plan`'s no-registry arm
    # detaches `FsContext` on its own.
    # `addr_of_mut` 14 -> 15 and `assert` 3 -> 4, round 19 (native review
    # N18-1): the retry around the CLEANUP expansion passes the kernel the
    # address of its own delay interval, and the const assertion holds
    # `CLEANUP_STACK_EXPANSION_BYTES` under the smallest architecture ceiling.
    # That turns one listed refusal, a too-large request, into a build failure;
    # it does not make every other refusal a shortage worth waiting on, which
    # is what this line used to say (round-20 native review, N1).
    # `assert` 4 -> 5, round 21: the const assertion that core's
    # `STATUS_NO_MEMORY` literal -- the one refusal the retry waits on -- is
    # `wdk_sys::STATUS_NO_MEMORY`.
    "driver/fsring-fsd/src/control.rs": (
        (
            "addr_of",
            5,
        ),
        (
            "addr_of_mut",
            15,
        ),
        (
            "assert",
            5,
        ),
        (
            "matches",
            5,
        ),
        (
            "private_authority_seals",
            1,
        ),
        (
            "unreachable",
            4,
        ),
    ),
    "driver/fsring-fsd/src/driver.rs": (
        (
            "addr_of_mut",
            12,
        ),
        (
            "assert",
            2,
        ),
        (
            "debug_assert_eq",
            4,
        ),
        (
            "matches",
            1,
        ),
    ),
    "driver/fsring-fsd/src/fence.rs": (
        (
            "debug_assert_eq",
            1,
        ),
        (
            "matches",
            3,
        ),
        (
            "private_authority_seals",
            1,
        ),
        (
            "unreachable",
            36,
        ),
    ),
    "driver/fsring-fsd/src/fscontrol.rs": ((
        "assert",
        1,
    ),),
    "driver/fsring-fsd/src/kernel.rs": ((
        "assert",
        1,
    ),),
    "driver/fsring-fsd/src/lifecycle.rs": (
        (
            "addr_of",
            10,
        ),
        (
            "addr_of_mut",
            72,
        ),
        (
            "assert",
            3,
        ),
        (
            "assert_eq",
            2,
        ),
        (
            "debug_assert_eq",
            1,
        ),
        (
            "matches",
            19,
        ),
        (
            "panic",
            2,
        ),
        (
            "private_authority_seals",
            1,
        ),
        (
            "unreachable",
            12,
        ),
    ),
    "driver/fsring-fsd/src/pending_enter.rs": (
        (
            # 78 -> 79: the cancel completion's foreign-IRP arm releases
            # the slot lock before it bugchecks, because a bugcheck under
            # a spin lock hangs every other processor on this ring.
            # 81 -> 93: park_wait_enter's control-ledger link moved out from
            # under the per-ring lock into its own registry-lock-only
            # critical section (link_parked_control), and a refusal now
            # unwinds through two more self-locking helpers
            # (unwind_reserved_install, unlink_parked_control_link) --
            # each acquire/release pair is two more `addr_of_mut!` sites.
            "addr_of_mut",
            97,
        ),
        (
            # 11 -> 10: the cancel completion no longer asserts that the
            # slot still names the IRP. `csq_remove_irp` runs first on
            # the cancel path and clears it, so that assertion fired on
            # every cancel; the decision now classifies in the core.
            # 10 -> 9 (round 15): `observe_pending_for_unload` carries its
            # three broken-invariant cases out of the slot-lock hold as a
            # value and fires ONE `panic!` after the release, so one
            # `assert!` and two `panic!` became a single `panic!`. The
            # invariants are unchanged; `panic = "abort"` means `Drop` never
            # runs, so a bugcheck inside the hold leaves the lock held and
            # hangs every other processor that touches this ring -- which is
            # what the siblings in this file release early to avoid.
            "assert",
            9,
        ),
        (
            # 10 -> 9: the DPC-exit rendezvous no longer decides with
            # `matches!` on one state; it maps the state and the caller's
            # obligation together, because `Armed` means an unfired deadline
            # to one caller and a queued DPC to the other.
            # 10 -> 11: the completion loop's new UnlinkControlPending
            # branch tests `plan.stage()` with one more `matches!` before
            # calling `take_control_link`, the same shape the adjacent
            # ReleaseSqWaitRole/ReleaseStrongSessionRef branches already used.
            "matches",
            13,
        ),
        (
            "offset_of",
            1,
        ),
        (
            # 14 -> 15: the one state that is genuinely unreachable -- a
            # slot naming a DIFFERENT IRP -- keeps a bugcheck, now as an
            # explicit arm rather than as the else of an assertion.
            # 15 -> 14: `a pending install without its dequeued IRP` is gone.
            # It was reachable exactly when the cancel routine owned the
            # request, and the completion pass now refuses that state before
            # it can reach a bugcheck -- so the site is deleted, not guarded,
            # and restoring it moves this count back.
            # 14 -> 13 (round 15): the two in `observe_pending_for_unload`
            # became one, fired after the hold is released rather than
            # inside it. See the `assert` note above for why.
            # 13 -> 14 in round 17: N16-3 turned a refused handoff that had been
            # collapsed with a committed one into the invariant violation it is,
            # bugchecking after the guard is released.
            "panic",
            14,
        ),
        (
            # 2 -> 1: `take_arbitrated_completion`'s `unreachable!` is gone. It
            # was justified by a check performed in a different lock hold, and
            # it stood after the receipt was minted and the terminal contended,
            # so the one state it claimed was impossible would have stranded the
            # IRP. The plan is taken before anything is spent instead.
            "unreachable",
            1,
        ),
    ),
    "driver/fsring-fsd/src/platform.rs": (
        (
            "assert",
            22,
        ),
        (
            "compile_error",
            3,
        ),
        (
            "matches",
            3,
        ),
    ),
    "driver/fsring-fsd/src/session.rs": (
        (
            # 9 -> 3 when the shared `static mut APC_STATE` was deleted: its six
            # `core::ptr::addr_of_mut!(APC_STATE)` argument sites became frame
            # and context bindings, which are not macro invocations. The three
            # that remain are the ring-lock and event sites.
            "addr_of_mut",
            3,
        ),
        (
            "assert",
            9,
        ),
        (
            "matches",
            7,
        ),
        (
            "unreachable",
            18,
        ),
    ),
    "driver/fsring-fsd/src/trace.rs": ((
        "assert",
        1,
    ),),
    "driver/fsring-fsd/src/volume.rs": (
        (
            "addr_of_mut",
            5,
        ),
        (
            "assert",
            3,
        ),
        (
            "debug_assert",
            5,
        ),
        (
            "matches",
            4,
        ),
        (
            "unreachable",
            18,
        ),
    ),
}


def resolver_body_is_closed(body):
    control_census = {
        keyword: len(re.findall(r"\b" + keyword + r"\b", body))
        for keyword in RESOLVE_CONTROL_CENSUS
    }
    plain_assignments = len(
        re.findall(r"(?<![=!<>+\-*/%&|^])=(?!=|>)", body)
    )
    augmented_assignments = sum(
        body.count(operator)
        for operator in ("+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=")
    )
    return (
        closed_call_roster(body) == RESOLVE_CALL_ROSTER
        and control_census == RESOLVE_CONTROL_CENSUS
        and plain_assignments == 29
        and augmented_assignments == 0
    )


BARE_LINE_CITATION = re.compile(r"`:\d+(?:-\d+)?`")


def comment_texts(source):
    """`(line, text)` for every comment in Rust `source`.

    Round-17 evidence E2: the bare-citation row read only lines that BEGIN with
    `//` or `/*`, so a citation in a trailing `//` after code, or on a
    continuation line inside a `/* ... */`, was never read. A `//` inside a
    string literal is not a comment: the quotes before it on its line must
    balance, which also means a `//` after an odd number of quotes -- a `'"'`
    char literal -- is skipped rather than read.
    """
    texts = []
    in_block = False
    for number, line in enumerate(source.split("\n"), 1):
        rest = line
        if in_block:
            end = rest.find("*/")
            if end == -1:
                texts.append((number, rest))
                continue
            texts.append((number, rest[:end]))
            rest = rest[end + 2:]
            in_block = False
        at = 0
        while True:
            slash = rest.find("//", at)
            star = rest.find("/*", at)
            candidates = [i for i in (slash, star) if i != -1]
            if not candidates:
                break
            first = min(candidates)
            if rest[:first].count('"') % 2:
                at = first + 2
                continue
            if first == slash:
                texts.append((number, rest[first + 2:]))
                break
            end = rest.find("*/", first + 2)
            if end == -1:
                texts.append((number, rest[first + 2:]))
                in_block = True
                break
            texts.append((number, rest[first + 2:end]))
            at = end + 2
    return texts


def bare_line_citations(raw_sources):
    """Every bare `` `:NNNN` `` or `` `:NNNN-MMMM` `` cited in a comment.

    REACHES: whole-line, trailing and block comments, in the raw sources handed
    in (this row passes core and fsd), with the number or range in backticks.
    DOES NOT REACH: an unbackticked `:1234`, which is also how a time, a port or
    a ratio is written, so matching it would be noise rather than a rule; and
    any file outside the sources handed in.
    """
    found = []
    for rel, source in sorted(raw_sources.items()):
        for number, text in comment_texts(source):
            for hit in BARE_LINE_CITATION.findall(text):
                found.append("%s:%d %s" % (rel, number, hit))
    return found


def access_scope_is_closed(scope, calls, controls, assignments):
    observed_controls = {
        keyword: len(re.findall(r"\b" + keyword + r"\b", scope))
        for keyword in controls
    }
    plain_assignments = len(
        re.findall(r"(?<![=!<>+\-*/%&|^])=(?!=|>)", scope)
    )
    augmented_assignments = sum(
        scope.count(operator)
        for operator in ("+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=")
    )
    return (
        closed_call_roster(scope) == calls
        and observed_controls == controls
        and plain_assignments == assignments
        and augmented_assignments == 0
    )


def top_level_methods(body):
    """Return every inherent method name/header regardless of Rust modifiers.

    `body` is already lexically masked.  Looking only for a preferred spelling
    such as `pub(crate) fn` is open to `async fn`, an ABI modifier, or a
    function item with a complex return type.  This walker recognizes the `fn`
    token only at the impl's own brace depth and scans its complete signature.
    """
    methods = []
    depth = 0
    index = 0
    item_start = 0
    while index < len(body):
        char = body[index]
        if char == "{":
            depth += 1
            index += 1
            continue
        if char == "}":
            depth -= 1
            index += 1
            if depth == 0:
                item_start = index
            continue
        if char == ";" and depth == 0:
            item_start = index + 1
            index += 1
            continue
        match = re.match(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\b", body[index:])
        if depth == 0 and match and (index == 0 or not (body[index - 1].isalnum() or body[index - 1] == "_")):
            name = match.group(1)
            cursor = index + match.end()
            paren = 0
            bracket = 0
            angle = 0
            while cursor < len(body):
                token = body[cursor]
                if token == "(":
                    paren += 1
                elif token == ")":
                    paren -= 1
                elif token == "[":
                    bracket += 1
                elif token == "]":
                    bracket -= 1
                elif token == "<":
                    angle += 1
                elif token == ">" and angle:
                    angle -= 1
                elif token in "{;" and paren == 0 and bracket == 0 and angle == 0:
                    break
                cursor += 1
            prefix = body[item_start:index]
            methods.append((name, prefix + body[index:cursor]))
        index += 1
    return methods


def top_level_macro_names(text):
    """Macro invocations outside brace-delimited items."""
    names = []
    depth = 0
    index = 0
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        elif depth == 0:
            match = re.match(r"\b([A-Za-z_]\w*)\s*!\s*[({[]", text[index:])
            if match and match.group(1) != "macro_rules":
                names.append(match.group(1))
                index += match.end() - 1
        index += 1
    return tuple(names)


def top_level_named_items(text):
    """Yield top-level Rust type items as ``(kind, name, header, body)``.

    Associated types and declarations hidden inside a macro/impl do not count
    as production definitions.  Headers and bodies are whitespace-normalized;
    alias items have ``None`` bodies and retain their complete right-hand side
    in the header.
    """
    depths = []
    depth = 0
    for char in text:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    pattern = re.compile(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+)?"
        r"(struct|enum|union|trait|type)\s+([A-Za-z_]\w*)"
    )
    for match in pattern.finditer(text):
        if depths[match.start()] != 0:
            continue
        cursor = match.end()
        angle = 0
        paren = 0
        bracket = 0
        while cursor < len(text):
            char = text[cursor]
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
            elif char in "{;" and angle == 0 and paren == 0 and bracket == 0:
                break
            cursor += 1
        if cursor >= len(text):
            continue
        header = re.sub(r"\s+", "", text[match.start() : cursor])
        body = None
        if text[cursor] == "{":
            nested = 0
            end = cursor
            while end < len(text):
                if text[end] == "{":
                    nested += 1
                elif text[end] == "}":
                    nested -= 1
                    if nested == 0:
                        break
                end += 1
            if nested != 0:
                continue
            body = re.sub(r"\s+", "", text[cursor + 1 : end])
        yield match.group(1), match.group(2), header, body


def top_level_const_items(text):
    """Yield top-level Rust consts as compact ``(name, type, value)`` tuples."""
    depths = []
    depth = 0
    for char in text:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    pattern = re.compile(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?const\s+([A-Za-z_]\w*)\s*:"
    )
    for match in pattern.finditer(text):
        if depths[match.start()] != 0:
            continue
        cursor = match.end()
        paren = bracket = angle = 0
        equals = None
        while cursor < len(text):
            char = text[cursor]
            if char == "(":
                paren += 1
            elif char == ")" and paren:
                paren -= 1
            elif char == "[":
                bracket += 1
            elif char == "]" and bracket:
                bracket -= 1
            elif char == "<":
                angle += 1
            elif char == ">" and angle:
                angle -= 1
            elif char == "=" and paren == 0 and bracket == 0 and angle == 0:
                equals = cursor
                break
            elif char == ";" and paren == 0 and bracket == 0 and angle == 0:
                break
            cursor += 1
        if equals is None:
            continue
        cursor = equals + 1
        paren = bracket = brace = 0
        while cursor < len(text):
            char = text[cursor]
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
            elif char == ";" and paren == 0 and bracket == 0 and brace == 0:
                break
            cursor += 1
        if cursor >= len(text):
            continue
        yield (
            match.group(1),
            re.sub(r"\s+", "", text[match.end() : equals]),
            re.sub(r"\s+", "", text[equals + 1 : cursor]),
        )


_RUST_IDENTIFIER_JOIN_CONTROLS = frozenset({"\u200c", "\u200d"})


def _is_rust_identifier_start(char):
    """The Unicode XID-start class accepted by Rust identifiers."""
    return char == "_" or (char != "_" and char.isidentifier())


def _is_rust_identifier_continue(char):
    """The Unicode XID-continue class accepted by Rust identifiers."""
    return (
        _is_rust_identifier_start(char)
        or ("_" + char).isidentifier()
        or char in _RUST_IDENTIFIER_JOIN_CONTROLS
    )


def rust_identifier_at(text, start):
    """Return one NFC-normalized Rust identifier and its end offset.

    Raw identifiers retain the same logical name while their returned end
    includes the ``r#`` prefix.  Callers get ``None`` at an identifier
    continuation or at a non-identifier start, so a combining-mark suffix
    cannot be reinterpreted as a second token.
    """
    if start < 0 or start >= len(text):
        return None
    if start and _is_rust_identifier_continue(text[start - 1]):
        return None
    identifier_start = start
    if text.startswith("r#", start):
        identifier_start += 2
    if identifier_start >= len(text) or not _is_rust_identifier_start(
        text[identifier_start]
    ):
        return None
    end = identifier_start + 1
    while end < len(text) and _is_rust_identifier_continue(text[end]):
        end += 1
    spelling = text[identifier_start:end]
    if spelling == "_":
        return None
    return unicodedata.normalize("NFC", spelling), end


def rust_identifier_tokens(text):
    """Yield ``(start, end, logical_name, is_raw)`` for every Rust token."""
    index = 0
    while index < len(text):
        parsed = rust_identifier_at(text, index)
        if parsed is None:
            index += 1
            continue
        name, end = parsed
        yield index, end, name, text.startswith("r#", index)
        index = end


def rust_keyword_spans(text, keyword):
    """Yield non-raw occurrences of one Rust keyword."""
    for start, end, name, is_raw in rust_identifier_tokens(text):
        if name == keyword and not is_raw:
            yield start, end


def _skip_whitespace(text, start):
    while start < len(text) and text[start].isspace():
        start += 1
    return start


def _split_top_level(text, delimiter=","):
    """Split a Rust fragment on one delimiter outside balanced groups."""
    segments = []
    start = 0
    paren = bracket = brace = angle = 0
    for index, char in enumerate(text):
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
        elif char == "<":
            angle += 1
        elif char == ">" and angle and (index == 0 or text[index - 1] != "-"):
            angle -= 1
        elif char == delimiter and paren == bracket == brace == angle == 0:
            segments.append(text[start:index])
            start = index + 1
    segments.append(text[start:])
    return tuple(segments)


def _strip_leading_outer_attributes(text):
    """Skip balanced outer attributes on a generic parameter fragment."""
    cursor = _skip_whitespace(text, 0)
    while cursor < len(text) and text[cursor] == "#":
        bracket = cursor + 1
        if bracket < len(text) and text[bracket] == "!":
            bracket += 1
        bracket = _skip_whitespace(text, bracket)
        if bracket >= len(text) or text[bracket] != "[":
            break
        depth = 0
        end = bracket
        while end < len(text):
            if text[end] == "[":
                depth += 1
            elif text[end] == "]":
                depth -= 1
                if depth == 0:
                    cursor = _skip_whitespace(text, end + 1)
                    break
            end += 1
        else:
            break
    return text[cursor:]


def _generic_parameter_segments(generic):
    """Return normalized type-parameter names paired with their declarations."""
    parameters = []
    for segment in _split_top_level(generic):
        declaration = _strip_leading_outer_attributes(segment)
        parsed = rust_identifier_at(declaration, 0)
        if parsed is None:
            continue
        name, _end = parsed
        if name == "const" and not declaration.startswith("r#"):
            continue
        parameters.append((name, declaration))
    return tuple(parameters)


def _contains_type_parameter_identifier(text, parameter):
    """Whether a type fragment names the parameter outside a lifetime token."""
    return any(
        name == parameter and (start == 0 or text[start - 1] != "'")
        for start, _end, name, _raw in rust_identifier_tokens(text)
    )


def use_alias_targets(declaration):
    """Logical source names immediately preceding ``as Alias`` clauses."""
    tokens = tuple(rust_identifier_tokens(declaration))
    return tuple(
        tokens[index - 1][2]
        for index, token in enumerate(tokens)
        if index > 0
        and index + 1 < len(tokens)
        and token[2] == "as"
        and not token[3]
    )


def alias_declarations(text):
    """Compact ``type ... = ...;`` and ``use ... as ...;`` aliases everywhere.

    Type aliases may put generics, bounds, and a ``where`` clause before their
    defining equals sign.  Scan a balanced declaration instead of guessing
    that header with a regular expression; sources have already had comments
    and literals blanked by :func:`strip_noncode`.
    """
    aliases = []
    for item_start, keyword_end in rust_keyword_spans(text, "type"):
        name_start = _skip_whitespace(text, keyword_end)
        parsed_name = rust_identifier_at(text, name_start)
        if parsed_name is None:
            continue
        paren = bracket = brace = angle = 0
        defining_equals = False
        cursor = parsed_name[1]
        while cursor < len(text):
            char = text[cursor]
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
            elif char == "<":
                angle += 1
            elif char == ">" and angle:
                angle -= 1
            elif char == "=" and paren == bracket == brace == angle == 0:
                defining_equals = True
            elif char == ";" and paren == bracket == brace == angle == 0:
                if defining_equals:
                    aliases.append(" ".join(text[item_start : cursor + 1].split()))
                break
            cursor += 1
    for item_start, keyword_end in rust_keyword_spans(text, "use"):
        brace = 0
        cursor = keyword_end
        while cursor < len(text):
            char = text[cursor]
            if char == "{":
                brace += 1
            elif char == "}" and brace:
                brace -= 1
            elif char == ";" and brace == 0:
                declaration = text[item_start : cursor + 1]
                if use_alias_targets(declaration):
                    aliases.append(" ".join(declaration.split()))
                break
            cursor += 1
    return tuple(sorted(aliases))


def top_level_inline_module_items(text):
    """Yield exact top-level inline modules as ``(name, header, body)``."""
    depths = []
    depth = 0
    for char in text:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    for keyword_start, keyword_end in rust_keyword_spans(text, "mod"):
        item_start = keyword_start
        visibility = re.search(
            r"\bpub(?:\s*\([^)]*\))?\s+$", text[:keyword_start]
        )
        if visibility is not None and depths[visibility.start()] == depths[keyword_start]:
            item_start = visibility.start()
        if depths[item_start] != 0:
            continue
        name_start = _skip_whitespace(text, keyword_end)
        parsed_name = rust_identifier_at(text, name_start)
        if parsed_name is None:
            continue
        name, cursor = parsed_name
        while cursor < len(text) and text[cursor] not in "{;":
            cursor += 1
        if cursor >= len(text) or text[cursor] == ";":
            continue
        nested = 0
        end = cursor
        while end < len(text):
            if text[end] == "{":
                nested += 1
            elif text[end] == "}":
                nested -= 1
                if nested == 0:
                    break
            end += 1
        if nested != 0:
            continue
        yield (
            name,
            re.sub(r"\s+", "", text[item_start:cursor]),
            re.sub(r"\s+", "", text[cursor + 1 : end]),
        )


def _rust_item_delimiter(text, start):
    """First top-level body/declaration delimiter after one Rust item start."""
    paren = bracket = angle = embedded_brace = 0
    index = start
    while index < len(text):
        char = text[index]
        if char == "(" and embedded_brace == 0:
            paren += 1
        elif char == ")" and paren and embedded_brace == 0:
            paren -= 1
        elif char == "[" and embedded_brace == 0:
            bracket += 1
        elif char == "]" and bracket and embedded_brace == 0:
            bracket -= 1
        elif char == "{" and (paren or bracket or angle or embedded_brace):
            embedded_brace += 1
        elif char == "}" and embedded_brace:
            embedded_brace -= 1
        elif char == "<" and embedded_brace == 0:
            angle += 1
        elif (
            char == ">"
            and angle
            and embedded_brace == 0
            and (index == 0 or text[index - 1] != "-")
        ):
            angle -= 1
        elif char in "{;" and paren == bracket == angle == embedded_brace == 0:
            return index
        index += 1
    return None


def _balanced_body_end(text, brace):
    depth = 0
    index = brace
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _matching_angle(text, opening):
    angle = embedded_brace = 0
    index = opening
    while index < len(text):
        char = text[index]
        if char == "{" and angle:
            embedded_brace += 1
        elif char == "}" and embedded_brace:
            embedded_brace -= 1
        elif char == "<" and embedded_brace == 0:
            angle += 1
        elif (
            char == ">"
            and angle
            and embedded_brace == 0
            and (index == 0 or text[index - 1] != "-")
        ):
            angle -= 1
            if angle == 0:
                return index
        index += 1
    return None


def generic_trait_impl_headers(text):
    """Generic trait impls, including const-expression trait arguments."""
    headers = []
    for match in re.finditer(r"\bimpl\s*<", text):
        delimiter = _rust_item_delimiter(text, match.start())
        if delimiter is None or text[delimiter] != "{":
            continue
        header = " ".join(text[match.start() : delimiter].split())
        if re.search(r"\sfor\s", header):
            headers.append(header)
    return tuple(headers)


TASK12_SAFE_GENERIC_UNSAFE_RETURN_WHITELIST = frozenset({
    # Task 23's two safe proof wrappers. Each is the sole caller of one
    # raw DDI, which is what makes a replayed native success
    # unrepresentable in safe code; the digests pin the exact bodies
    # reviewed, so changing either re-opens this check.
    (
        "driver/fsring-core/src/adapter/fence.rs",
        "fndrain_stable_prefixes_with_proof<D:FenceKernelDdi>(ddi:&mutD"
        ",mutprepared:PreparedConsumerDrain,)->Result<DrainedConsumerPr"
        "efix,(KernelFenceError<D::Error>,PreparedConsumerDrain)>",
        "f5bcf15eda8728b1437322636438ae3c80de52dc26a62a23b2d28d5074d7181f",
    ),
    (
        "driver/fsring-core/src/adapter/fence.rs",
        "fnretire_credits_with_proof<D:FenceKernelDdi>(ddi:&mutD,draine"
        "d:DrainedConsumerPrefix,)->Result<RetiredConsumerPrefix,(Kerne"
        "lFenceError<D::Error>,DrainedConsumerPrefix)>",
        "6861519d23989a42e76faca9773642f7d6fdca31b8a401e959902388ac9cef5c",
    ),
    (
        "driver/fsring-core/src/adapter/fence.rs",
        "fninto_prepared_delete_storage<NativeReset>(self,"
        "commit:PreparedDeleteCoreCommit,running:R3FinalizerRunningRight,"
        "native_reset:NativeReset,)->Result<(Tail,PreparedDeleteStorage<"
        "Shell,RootRelease,NativeReset>),(Self,PreparedDeleteCoreCommit,"
        "R3FinalizerRunningRight,NativeReset,),>",
        "897937fa35a291d0a19ab67a537d9731d0a9bba6b14b10d9199070e8620b1763",
    ),
    # Task 25 native grant slab: the drained-proof callback is the only
    # safe wrapper that reborrows the live grant table. The digest pins
    # that the callback cannot outlive the proof.
    (
        "driver/fsring-fsd/src/fence.rs",
        "fnwith_entries<R>(&mutself,f:implFnOnce(&mut[fsring_core::grant"
        "::GrantEntry],&DrainCompletedProof)->R,)->R",
        "4867c1549fdcdc72268b08f6f7269ca9f8008fde210715d11f6d875cbc2a493c",
    ),
})


def generic_safe_fabricator_headers(text, rel=None):
    """Safe functions whose unsafe body returns any declared generic type."""
    findings = []
    for function_start, keyword_end in rust_keyword_spans(text, "fn"):
        name_start = _skip_whitespace(text, keyword_end)
        parsed_name = rust_identifier_at(text, name_start)
        if parsed_name is None:
            continue
        _name, name_end = parsed_name
        opening = _skip_whitespace(text, name_end)
        if opening >= len(text) or text[opening] != "<":
            continue
        closing = _matching_angle(text, opening)
        delimiter = _rust_item_delimiter(text, function_start)
        if closing is None or delimiter is None or text[delimiter] != "{":
            continue
        body_end = _balanced_body_end(text, delimiter)
        if body_end is None:
            continue
        before_fn = text[max(0, function_start - 32) : function_start]
        if re.search(r"\bunsafe\s*$", before_fn):
            continue
        body = text[delimiter + 1 : body_end]
        if not re.search(r"\bunsafe\b", body):
            continue
        generic = text[opening + 1 : closing]
        header_tail = text[closing + 1 : delimiter]
        arrow = header_tail.find("->")
        if arrow < 0:
            continue
        where_span = next(
            (
                (start, end)
                for start, end in rust_keyword_spans(header_tail, "where")
                if start > arrow
            ),
            None,
        )
        result_end = len(header_tail) if where_span is None else where_span[0]
        result = header_tail[arrow + 2 : result_end]
        if any(
            _contains_type_parameter_identifier(result, parameter)
            for parameter, _declaration in _generic_parameter_segments(generic)
        ):
            compact_header = re.sub(r"\s+", "", text[function_start:delimiter])
            compact_body = re.sub(r"\s+", "", body)
            identity = (
                rel,
                compact_header,
                hashlib.sha256(compact_body.encode("utf-8")).hexdigest(),
            )
            if identity not in TASK12_SAFE_GENERIC_UNSAFE_RETURN_WHITELIST:
                findings.append(" ".join(text[function_start:delimiter].split()))
    return tuple(findings)


def named_item_attributes(text, kind, name):
    """Normalized contiguous outer attributes on one named type item."""
    pattern = re.compile(
        r"((?:#\s*\[[^\[\]]*\]\s*)*)"
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?"
        + re.escape(kind)
        + r"\s+"
        + re.escape(name)
        + r"\b"
    )
    return tuple(
        re.sub(r"\s+", "", match.group(1))
        for match in pattern.finditer(text)
    )


def macro_definition_items(text):
    """Exact names, delimiters, and balanced bodies of ``macro_rules!`` items."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    for macro_start, keyword_end in rust_keyword_spans(text, "macro_rules"):
        cursor = _skip_whitespace(text, keyword_end)
        if cursor >= len(text) or text[cursor] != "!":
            continue
        name_start = _skip_whitespace(text, cursor + 1)
        parsed_name = rust_identifier_at(text, name_start)
        if parsed_name is None:
            continue
        name, cursor = parsed_name
        cursor = _skip_whitespace(text, cursor)
        if cursor >= len(text) or text[cursor] not in pairs:
            continue
        opening = text[cursor]
        closing = pairs[opening]
        depth = 0
        end = cursor
        while end < len(text):
            if text[end] == opening:
                depth += 1
            elif text[end] == closing:
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if depth == 0:
            yield (
                name,
                opening,
                re.sub(r"\s+", "", text[cursor + 1 : end]),
            )


def macro_invocation_census(text):
    """All production macro calls by name, independent of item nesting."""
    calls = []
    for _start, end, name, _raw in rust_identifier_tokens(text):
        cursor = _skip_whitespace(text, end)
        if cursor >= len(text) or text[cursor] != "!":
            continue
        cursor = _skip_whitespace(text, cursor + 1)
        if cursor < len(text) and text[cursor] in "({[" and name not in {
            "macro_rules", "if", "while",
        }:
            calls.append(name)
    return tuple(
        sorted(collections.Counter(calls).items())
    )


def protected_receiver_from_impl_header(header):
    """The exact protected receiver named by an inherent or trait impl."""
    for type_name in PROTECTED_RECEIVER_METHODS:
        if re.search(
            r"(?:impl|for|::|\(|>)" + re.escape(type_name) + r"(?:<|\)|$)",
            header,
        ):
            return type_name
    return None


def protected_receiver_escape_findings(text, rel):
    """Reject every extra impl/method/macro on cell projection receivers."""
    findings = []
    canonical = re.sub(r"\br#([A-Za-z_]\w*)", r"\1", text)
    allowed_methods = {
        type_name: {
            method
            for implementation in implementations
            for method in implementation
        }
        for type_name, implementations in PROTECTED_RECEIVER_METHODS.items()
    }
    for header, body in impl_items(canonical):
        type_name = protected_receiver_from_impl_header(header)
        if type_name is None:
            continue
        normalized_methods = tuple(
            re.sub(r"\s+", "", method_header)
            for _name, method_header in top_level_methods(body)
        )
        unauthorized = (
            header != "impl" + type_name
            or any(method not in allowed_methods[type_name] for method in normalized_methods)
            or any(
                name not in {"addr_of", "addr_of_mut", "assert_unchecked", "debug_assert_eq", "matches", "unreachable"}
                for name in re.findall(r"\b([A-Za-z_]\w*)\s*!\s*[({[]", body)
            )
        )
        if unauthorized:
            findings.append(
                "%s: protected native receiver `%s` has an unauthorized impl, method, or macro"
                % (rel, type_name)
            )
    return findings


def pattern_bodies(text, pattern):
    """Bodies introduced by an exact declaration pattern."""
    for match in re.finditer(pattern, text):
        depth = 0
        index = match.end() - 1
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        yield text[match.end() : index]


# Every panic-family site in `pending_enter.rs` that fires with the slot lock
# held, as (function, which hold). Swept in round 16; see the boundary note above
# `finalize_native_pending_publication` for what is covered and what is not.
#
# Both survivors are `csq_insert_irp`'s assertions, and they are deliberate: the
# callback runs under the CSQ framework's hold, which `csq_acquire_lock` took and
# `csq_release_lock` will drop, so the callback cannot release it without
# breaking the framework's pairing and has no return value to refuse with.
# Moving them means checking before the insert, in a caller that owns the
# pairing -- a design change, not a sweep.
PENDING_PANIC_IN_HOLD = (
    ("csq_insert_irp", "csq-framework"),
    ("csq_insert_irp", "csq-framework"),
)

_PENDING_PANIC = re.compile(
    r"\b(?:panic!|assert!|assert_eq!|assert_ne!|unreachable!|todo!|unimplemented!)"
)
# `strip_noncode` deletes string literals, so `extern "C" fn` arrives as
# `extern     fn`. Requiring the literal made this walker match nothing at all
# and report an empty set -- a green row over an unmeasured file.
_PENDING_FN = re.compile(
    r"^\s*(?:pub(?:\(crate\))?\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+(?:\"[^\"]*\"\s+)?)?fn\s+(\w+)"
)
# The four callbacks the CSQ framework invokes with the slot lock already held.
_PENDING_CSQ_HELD = (
    "csq_insert_irp",
    "csq_remove_irp",
    "csq_peek_next_irp",
    "csq_complete_canceled_irp",
)


def _pending_panics_inside_a_hold(text):
    """(function, hold) for each panic-family site under a slot-lock hold.

    Round-16 N16-2. The first version cleared `guarded` on the FIRST line
    containing `.release()` and never re-armed it, so every function shaped

        if refused { unlock.release(); return ...; }
        ... more code, still holding ...

    was uncounted past its first early return -- `park_wait_enter`,
    `store_parked_session_wait_inner` and `finalize_native_pending_publication`
    among them. A bugcheck planted after such a release passed the census.

    The release is now matched against BRACE DEPTH. A `.release()` at the depth
    the guard was armed at ends the hold for the rest of the function; one deeper
    than that belongs to a branch, and the code after that branch is still
    holding.

    A conditional release ends the hold for THAT BRANCH ONLY. When the branch
    closes -- depth falls back below where the release sat -- the guard resumes,
    because the path that did not take the branch is still holding. Without the
    resume the walker under-reports (what shipped); without the branch scope it
    over-reports, and immediately flagged this file's own two correct
    `release(); panic!()` arms.

    LIMIT: a release inside a branch that FALLS THROUGH rather than returning
    resumes the guard when the branch closes, although the lock is released on
    that path. The error is in the SAFE direction: code after such a branch is
    counted as still holding, so a panic there would be over-reported, never
    missed. This docstring used to say every conditional release in this file
    returns or diverges; `park_wait_enter` has two if/else pairs that release on
    both arms and fall through -- the timer-arming hold and the queued-handoff
    hold -- and no panic-family site follows either, so the frozen roster is
    unaffected (native review observation on N16-2, round 17).
    """
    name = None
    raw_depth = 0
    guarded = False
    guard_depth = 0
    released_at = None
    csq_released = False
    depth = 0
    found = []
    for line in text.split("\n"):
        match = _PENDING_FN.match(line)
        if match:
            name, raw_depth, guarded = match.group(1), 0, False
            csq_released = False
            released_at = None
            depth = 0
        if "KeAcquireSpinLockRaiseToDpc" in line:
            raw_depth += 1
        if "PendingContextUnlock::armed" in line:
            # The guard adopts the acquire it was armed from.
            guarded = True
            guard_depth = depth
            released_at = None
            if raw_depth:
                raw_depth -= 1
        stripped = line.lstrip()
        if _PENDING_PANIC.search(line) and not stripped.startswith("//"):
            if raw_depth:
                found.append((name, "raw"))
            elif guarded:
                found.append((name, "guard"))
            elif name in _PENDING_CSQ_HELD and not csq_released:
                # A CSQ callback is inside the framework's hold until it
                # releases: `csq_complete_canceled_irp` drops the lock before its
                # one bugcheck and says so, so it is not in this set.
                found.append((name, "csq-framework"))
        if "KeReleaseSpinLock" in line:
            if raw_depth:
                raw_depth -= 1
            csq_released = True
        if ".release()" in line and guarded:
            guarded = False
            released_at = depth
        # Depth is updated AFTER the line is judged, so a panic or a release on
        # the same line as its opening brace is judged at the depth it is in.
        depth += line.count("{") - line.count("}")
        # The branch that released has closed: the path that did not take it is
        # still holding, so the guard resumes.
        if released_at is not None and depth < released_at:
            guarded = True
            released_at = None
    return tuple(found)


def native_contract_findings(text, rel, evidence=None):
    """Closed production-native lifetime contracts for the three owning files."""
    findings = []

    def require(condition, label, detail):
        if evidence is not None:
            evidence.append("%s:%s" % (rel, label))
        if not condition:
            findings.append("%s: %s" % (rel, detail))

    if rel == "driver/fsring-fsd/src/session.rs":
        # Round-14 medium, found by the native review. `RawArray` has no `Drop`,
        # so a block that has been allocated and not yet adopted into the shell
        # is freed by nobody if anything between the two refuses. `masters`
        # already defended itself against exactly this and says so at its own
        # adoption; `credits` did not -- three fallible steps stood between its
        # allocation and its adoption at the end of the function, of which the
        # `output` allocation's `?` is reachable.
        #
        # Pinned as the adjacency, because the adjacency IS the property: the
        # adoption must be the very next statement, not merely present
        # somewhere later in the function. Anything inserted between the two
        # reintroduces the window.
        credits_collapsed = re.sub(r"\s+", "", text)
        require(
            "letcredits=unsafe{RawArray::allocate(&mutpool,context.policy,"
            "credit_count,NotificationCreditV1::default(),)}?;"
            "unsafe{(*session).credits=credits};" in credits_collapsed
            # And the issue step reads the shell's copy, not a local that would
            # mean the block had been left unadopted after all.
            and "table.issue_notification_credits(unsafe{(*session).credits"
            ".as_mut_slice()})" in credits_collapsed,
            "credit-backing-is-adopted-before-the-next-fallible-step",
            "the notification-credit block is no longer adopted into the shell "
            "as the statement after its allocation: a refusal in between drops "
            "a `RawArray` that has no `Drop`, and nothing can free it",
        )

        # Round-14 HIGH (B7), found by the native review. `build_pending_runtime`
        # is the LAST thing a precommit SETUP builds and had NO unwind entry, and
        # `PendingRuntimeReady` has no `Drop`. So a SETUP that refused anywhere
        # after it -- every refusal in `publish_locked_suffix`, each of which
        # carefully hands the runtime back to the context on its way out --
        # dropped the pool arena and up to 64 `IoAllocateWorkItem` items, every
        # one holding a reference on the PERMANENT provider device.
        #
        # Pinned as the head of `unwind`, not merely as a call somewhere in the
        # file. The position is the property twice over: it must run for BOTH
        # rollback entry points (`rollback_setup` and
        # `rollback_setup_with_effects` both funnel through here, so an entry in
        # one of their effect lists would miss the other), and it must run
        # BEFORE the effect loop, because the release quiesces each slot's timer
        # and waits its DPC out while those contexts can still reach ring state
        # that `FreeEventsAndScratch` frees.
        unwind_collapsed = re.sub(r"\s+", "", text)
        require(
            "unsafefnunwind(context:&mutSetupContext,"
            "effects:&[plan::SetupRollbackEffect]){"
            "ifletSome(runtime)=context.pending_runtime.take(){"
            "unsafe{runtime.release_pending_runtime("
            "&mutcrate::pending_enter::NativePendingRuntimeDdi)};}"
            "foreffectineffects.iter().copied(){" in unwind_collapsed
            # One release, one take: a second would be a double free of an
            # arena whose contexts the first already tore down.
            # Three mentions of the release (the failed-build path in
            # `build_pending_runtime`, its ledger-reservation twin, and the
            # unwind above) and exactly two takes of the slot: the unwind's,
            # and the publication's own. A third take is a second owner for
            # something whose release is consuming.
            and unwind_collapsed.count("release_pending_runtime") == 3
            and unwind_collapsed.count("context.pending_runtime.take()") == 2,
            "setup-unwind-releases-the-pending-runtime-first",
            "the SETUP unwind no longer releases the pending runtime before its "
            "effect loop: a refused SETUP leaks the pending arena and up to 64 "
            "work items, each pinning the permanent provider device, or the "
            "release now runs after effects that free what its contexts reach",
        )
        # Round-14 BLOCKER, found by the native review. `allocate_events_and_
        # scratch` builds every shell ring's `RingEnterState` with `new`, which
        # sets `brand: None`, because it runs before the ring set exists. That
        # shell state is the one every production ENTER and the FENCE operate
        # on, and an unbranded state answers `WrongState` to `acquire_sq_wait`,
        # `acquire_cq_consumer` and every `check_release`. So the fence could
        # never acquire a CQ consumer on ring 0 of any fence; `do_acquire`
        # parked a `TransientNative` retry, `prepare_fence_retry` always turned
        # it into `Delay`, and CLEANUP, process loss, protocol abort and unload
        # each retried for ever with the calling thread blocked on
        # `visibility_resolution`.
        #
        # The stamp is pinned where it happens: in the ring-set loop, reading
        # the brand from the right BEFORE that right is spent, and adopting it
        # through the unguarded projection the unpublished session licenses.
        # Pinned as the whole step, not as the presence of `adopt_ring_brand`
        # somewhere in the file -- a call that ran after the session was
        # published, or on a slot chosen by anything other than the brand's own
        # ring index, would be a different and wrong repair.
        brand_stamp_collapsed = re.sub(r"\s+", "", text)
        require(
            "letring_brand=right.ring_brand();"
            "letring_index=matchusize::try_from(ring_brand.ring_index()){"
            "Ok(index)=>index,"
            "Err(_)=>{failure=Some(STATUS_INVALID_DEVICE_STATE);break;}};"
            "letshell_rings=unsafe{(*session).rings.as_mut_slice_any()};"
            "letSome(shell_ring)=shell_rings.get_mut(ring_index)else{"
            "failure=Some(STATUS_INVALID_DEVICE_STATE);break;};"
            "letadopted=unsafe{shell_ring.state_unshared()}.enter_mut()"
            ".adopt_ring_brand(ring_brand);"
            "ifadopted.is_err(){" in brand_stamp_collapsed
            and brand_stamp_collapsed.count("adopt_ring_brand") == 1,
            "shell-ring-state-carries-its-r4-brand",
            "the session shell's per-ring `RingEnterState` is no longer given "
            "the ring set's brand during SETUP: every R4 role request on it "
            "answers `WrongState`, so the fence cannot acquire a CQ consumer "
            "and every terminal retries for ever",
        )

    if rel == "driver/fsring-core/src/enter.rs":
        # The adoption itself, pinned whole. It is the only way to brand a
        # state `new` built, so its refusals are what stop it becoming a way to
        # re-identify a live ring: already branded, wrong ring index, or a role
        # already issued under the identity this would replace.
        adopt_collapsed = re.sub(r"\s+", "", text)
        require(
            "pubfnadopt_ring_brand(&mutself,brand:SessionRingBrand)"
            "->Result<(),RoleError>{"
            "ifself.brand.is_some(){returnErr(RoleError::WrongState);}"
            "ifself.ring_index!=brand.ring_index(){returnErr(RoleError::WrongRing);}"
            "ifself.sq_owner.is_some()||self.cq_owner.is_some(){"
            "returnErr(RoleError::DeviceBusy);}"
            "self.brand=Some(brand);Ok(())}" in adopt_collapsed
            and adopt_collapsed.count("adopt_ring_brand") == 1,
            "brand-adoption-is-one-shot-and-checked",
            "`adopt_ring_brand` no longer refuses an already-branded state, a "
            "brand for another ring, or a state that has already issued a "
            "role: it becomes a way to re-identify a live ring under the "
            "tokens its old identity minted",
        )

    if rel == "driver/fsring-core/src/enter.rs":
        # The frame BELOW. Every rule for the queued pass lives under
        # `rel == ".../pending_enter.rs"`, so pinning `begin_pass`'s body pins
        # only the four tokens it passes to this function -- and an adversarial
        # pass restored the round-11 livelock by putting the extra refusal
        # HERE, in a crate the queued-pass rule cannot see. `begin_pass`'s
        # refusal set is the union of its own body and this callee's, so the
        # callee is pinned whole for the same reason its caller is.
        #
        # This does not close the class: the defect can move again, one frame
        # further down or into a field these conditions read. It closes the two
        # frames a pass actually traverses, which is what makes the round-11
        # livelock unreachable by the routes that were demonstrated rather than
        # merely by the one that was repaired.
        worker_pass_collapsed = re.sub(r"\s+", "", text)
        require(
            worker_pass_collapsed.count("fnbegin_native_worker_pass") == 1
            and "fnbegin_native_worker_pass(install:PendingInstallId,"
            "schedule:&mutPendingWorkerSchedule,wake:&mutPendingWakeSlot,"
            "worker_owner:&mutOption<PendingOwnerToken>,)"
            "->Result<PendingReason,PendingError>{"
            "letSome(token)=worker_owner.as_ref()else"
            "{returnErr(PendingError::WrongOwnerKind);};"
            "ifschedule.install!=Some(install)||token.install!=install"
            "{returnErr(PendingError::WrongInstall);}"
            "iftoken.kind!=PendingOwnerKind::Worker"
            "{returnErr(PendingError::WrongOwnerKind);}"
            "ifschedule.state!=WorkerScheduleState::Queued"
            "{returnErr(PendingError::WrongRingState);}"
            "ifwake.brand!=install.brand(){returnErr(PendingError::WrongRing);}"
            "letdecision=wake.take_for_worker(install)?;"
            "letreason=decision.reason();letbatch=decision.into_batch();"
            "letSome(token)=worker_owner.take()else{unreachable!()};"
            "matchschedule.begin_worker_pass(token,batch){"
            "Ok((token,_batch))=>{*worker_owner=Some(token);Ok(reason)}"
            "Err((error,token,_batch))=>{*worker_owner=Some(token);Err(error)}}}"
            in worker_pass_collapsed,
            "worker-pass-refuses-only-on-the-owner-and-schedule-it-declares",
            "`begin_native_worker_pass` refuses on something its caller's "
            "admission does not test: a pass that can be queued and can never "
            "begin, requeued for ever on a system worker thread",
        )

    if rel == "driver/fsring-fsd/src/driver.rs":
        # Round-14 medium, found by the native review. `(*state).provider_device`
        # was written in `finish`, AFTER `PublishProvider` had cleared
        # `DO_DEVICE_INITIALIZING`. A dispatch reaches the root through the
        # device extension rather than through `fsring_driver_state`, so a SETUP
        # arriving in that window read null and refused with
        # `STATUS_INVALID_DEVICE_STATE` at `build_pending_runtime`'s provider
        # check -- and `finish`'s own comment claimed every dispatch-visible
        # field had been written before endpoint creation, which was false for
        # exactly this one.
        #
        # The ORDER is the property, so both statements are pinned in sequence:
        # the field is written, and only then does the publish make the endpoint
        # reachable. A rule that merely found `publish_provider_device`
        # somewhere in the file would pass with the two lines swapped, which is
        # the whole defect.
        publish_collapsed = re.sub(r"\s+", "", text)
        require(
            "plan::LoadEffect::PublishProvider=>{"
            "letready=context.dispatch_ready_root()?;"
            "unsafe{ready.publish_provider_device(context.provider_device)};"
            "unsafe{crate::control::publish(context.provider_device)};"
            in publish_collapsed
            # And it does NOT go back to being written in `finish`, where the
            # unload-only fields live.
            and "(*state).provider_device=context.provider_device;"
            not in publish_collapsed,
            "provider-device-is-visible-before-its-endpoint-is",
            "the root's `provider_device` is no longer written before the "
            "publish that clears `DO_DEVICE_INITIALIZING`: a SETUP arriving in "
            "that window reads null through the device extension and refuses "
            "the first session",
        )

    if rel == "driver/fsring-fsd/src/kernel.rs":
        # Round-11 high N2, found by review against this machine's WDK headers
        # (`wdmsec.h`, `DECLARE_CONST_UNICODE_STRING`). One argument of
        # `WdmlibIoCreateDeviceSecure` was being built two incompatible ways:
        # `DefaultSDDLString` is a TERMINATED string whose `MaximumLength`
        # counts the terminator, while the Object Manager name beside it is
        # COUNTED and unterminated. Both were minted by
        # `counted_unicode_units`, so the SDDL arrived claiming
        # `MaximumLength == Length` over a buffer with no NUL in it, and at
        # most one of those two readings can be right.
        #
        # The separation is what this pins, in both directions: the terminated
        # mint must refuse a buffer whose last unit is not NUL -- that refusal
        # is the only thing stopping a caller from reaching for it with an
        # Object Manager name -- and must report a `MaximumLength` that is NOT
        # its `Length`, while the counted mint must keep reporting the two
        # equal. Collapsing either one into the other is how the two
        # conventions became one, so a rule that named only one of them would
        # be satisfied by the defect it exists to refuse.
        # Round-12 E3, found by review: the previous version claimed to pin "a
        # `MaximumLength` that is NOT its `Length`" and anchored only the field
        # initialiser's IDENTIFIER. `let maximum = length;` therefore restored
        # `MaximumLength == Length` inside the terminated mint -- the exact
        # defect this rule exists to refuse -- and passed with 0 failures,
        # because `maximum` was still the name in the initialiser.
        #
        # A name is not a value. Both mint bodies are pinned whole and
        # contiguously instead, so what is fixed is the COMPUTATION each
        # `MaximumLength` comes from: `buffer.len()` including the terminator
        # for the terminated mint, and the same `length` it already reports for
        # the counted one.
        mint_collapsed = re.sub(r"\s+", "", text)
        require(
            "fncounted_unicode_sz(buffer:&mut[u16])->Option<wdk_sys::UNICODE_STRING>{"
            "ifbuffer.last().copied()!=Some(0){returnNone;}"
            "letunits=buffer.len().checked_sub(1)?;"
            "letlength=u16::try_from(units.checked_mul(core::mem::size_of::<u16>())?).ok()?;"
            "letmaximum=u16::try_from(buffer.len().checked_mul(core::mem::size_of::<u16>())?)"
            ".ok()?;"
            "Some(wdk_sys::UNICODE_STRING{Length:length,MaximumLength:maximum,"
            "Buffer:buffer.as_mut_ptr(),})}" in mint_collapsed
            and "fncounted_unicode_units(buffer:&mut[u16])->Option<wdk_sys::UNICODE_STRING>{"
            "letbytes=buffer.len().checked_mul(core::mem::size_of::<u16>())?;"
            "letlength=u16::try_from(bytes).ok()?;"
            "Some(wdk_sys::UNICODE_STRING{Length:length,MaximumLength:length,"
            "Buffer:buffer.as_mut_ptr(),})}" in mint_collapsed
            # Exactly one definition of each mint, for the same reason the
            # queued-pass rule counts its definitions: an adversarial pass kept
            # each pinned body verbatim as a `#[cfg]`-gated twin and as a dead
            # decoy module, and put the collapsed convention in the definition
            # that actually compiles. A contiguous body match cannot tell those
            # apart; a definition count can.
            and mint_collapsed.count("fncounted_unicode_sz") == 1
            and mint_collapsed.count("fncounted_unicode_units") == 1,
            "unicode-mints-keep-the-two-wdk-conventions-apart",
            "the terminated and counted `UNICODE_STRING` mints are no longer "
            "two conventions: either the SDDL mint stopped refusing an "
            "unterminated buffer, or its `MaximumLength` stopped being "
            "computed over the whole buffer including the terminator, or the "
            "Object Manager name mint stopped reporting `MaximumLength == "
            "Length`",
        )

    if rel in (
        "driver/fsring-fsd/src/control.rs",
        "driver/fsring-fsd/src/fscontrol.rs",
        "driver/fsring-fsd/src/volume.rs",
    ):
        # The other half of N2, at each of the three roles that create a
        # secure device. `strip_noncode` blanks Rust literals, so the SDDL
        # text itself is not observable here and is not what this reads: the
        # DECLARED unit count is, and 28 units for a 27-character SDDL is the
        # terminator. That number plus the mint's own run-time refusal above
        # is what makes the descriptor right -- neither alone would be.
        # Round-12 E2, found by review: the previous version accepted a bare
        # local `counted_unicode(&mut sddl…)` as an alternative spelling at all
        # three roles, but only required that name to FORWARD to the terminated
        # mint in `control.rs`. Planting a local alias of exactly that shape,
        # forwarding to the counted mint, restored the pre-repair defect in
        # `volume.rs` and in `fscontrol.rs` with 0 failures.
        #
        # The alternative is gone. Every role now names the mint by its own
        # path, and a fully qualified call has no local name to repoint: to
        # defeat this a plant would have to move `counted_unicode_sz` itself,
        # which is the body the `kernel.rs` rule above pins whole. `control.rs`
        # keeps its local alias for Object Manager NAMES, where either
        # convention is well formed; it no longer stands between the SDDL and
        # the mint.
        sddl_collapsed = re.sub(r"\s+", "", text)
        require(
            re.search(r"const[A-Z_]+_SDDL:\[u16;28\]=", sddl_collapsed) is not None
            and "counted_unicode_units(&mutsddl" not in sddl_collapsed
            and "letSome(sddl)=crate::kernel::counted_unicode_sz(&mutsddl"
            in sddl_collapsed
            # Exactly one SDDL is minted per role, so a second, differently
            # built descriptor cannot be introduced beside the pinned one.
            and sddl_collapsed.count("letSome(sddl)=") == 1,
            "sddl-reaches-the-wdk-by-the-terminated-convention",
            "this role's `DefaultSDDLString` is no longer built by the "
            "terminated mint under its own qualified name, or its SDDL "
            "constant stopped declaring the unit that holds the terminator: "
            "the WDK is handed a descriptor whose `MaximumLength` and buffer "
            "disagree",
        )

    if rel == "driver/fsring-fsd/src/session.rs":
        # Round-10 blocker, found by review after a fully green 38-row
        # battery. The spine alias maps by section view on EVERY profile, so a
        # profile-wide branch in an unmap loop hands `MmUnmapLockedPages` a
        # NULL partial together with an address `ZwMapViewOfSection` produced
        # -- at the teardown of every successful SETUP on Win10X64 and
        # Win10Arm64. The repair that created it moved the ROLLBACK PLAN to a
        # per-alias dispatch and left the three loops that actually run
        # dispatching on the profile; both mutants it added targeted the plan,
        # so nothing could see the half that runs. This rule watches that half.
        #
        # Two mechanisms are legitimate and each must be named at the call: the
        # plan-driven `UnmapAliasReverse` effect, which the plan already
        # dispatches per alias, and a loop that asks the alias record which
        # mechanism mapped it. The profile is not an answer to that question.
        unmap_collapsed = re.sub(r"\s+", "", text)
        unmap_sites = [
            match.start()
            for match in re.finditer(r"MmUnmapLockedPages\(", unmap_collapsed)
        ]
        require(
            len(unmap_sites) == 4
            and all(
                "partial.is_null()" in unmap_collapsed[max(0, site - 300):site]
                or "UnmapAliasReverse" in unmap_collapsed[max(0, site - 700):site]
                for site in unmap_sites
            )
            and "is_modern" not in unmap_collapsed,
            "alias-unmap-dispatches-per-alias-not-per-profile",
            "an alias unmap decides its mechanism from the profile again, or an "
            "unguarded unmap site appeared: the spine is a section view on every "
            "profile, so this hands MmUnmapLockedPages a null MDL at the "
            "teardown of every successful SETUP on a modern profile",
        )

        # Round-9 high 1. The master MDLs are what make this driver's
        # system-space view of a pagefile-backed section resident, and the
        # ENTER drain reads and writes that view with the ring spin lock held
        # -- at DISPATCH_LEVEL -- on every shipped profile. The legacy profile
        # used to allocate none, so on Win7X64 the drain touched pageable
        # memory above APC_LEVEL. The count must not be profile-conditional
        # again; the alias mechanism may be, and is.
        master_collapsed = re.sub(r"\s+", "", text)
        require(
            "letmaster_count=(layout.ring_count()asusize).saturating_add(2);"
            in master_collapsed
            # Spelling-independent: any conditional form at all, not just the
            # one helper round 9 happened to use. `is_modern` no longer exists
            # in this file, so pinning its name would have retired the check.
            and "letmaster_count=if" not in master_collapsed,
            "master-residency-is-profile-independent",
            "the master MDL count is profile-conditional again, which leaves "
            "the legacy profile dereferencing a pageable section view at "
            "DISPATCH_LEVEL",
        )

        # Round-9 high 3. `store_parked_wait`'s refusal used to be cast to
        # `let _`, and its own callee doc comment names this caller as the
        # leak. On refusal the parked plan is never stored, so `begin_pass`
        # refuses every later wake -- Fence and Unload included -- and nothing
        # in the driver can complete the request. The call must therefore be
        # answered, and the answer must reach the abandon path that fails the
        # IRP once.
        collapsed_session = re.sub(r"\s+", "", text)
        require(
            "let_=unsafe{access.store_parked_wait(" not in collapsed_session
            and collapsed_session.count("access.store_parked_wait(") == 1
            and "ifstored.is_err(){" in collapsed_session
            and collapsed_session.count("access.fail_unstored_parked_wait(") == 1,
            "parked-store-refusal-is-answered",
            "the parked-WAIT store's refusal is discarded again, or no longer "
            "reaches the path that takes the IRP back out of the CSQ and fails "
            "it once",
        )

    if rel == "driver/fsring-fsd/src/fence.rs":
        # Round-14 HIGH (B3), found by the native review, and the half that
        # makes the round-14 BLOCKER's repair a repair rather than a relocation.
        #
        # Two consumer models live side by side. The R3 checkpoint pair takes
        # nothing and gives nothing back -- both halves just re-prove
        # `cq_consumer_is_free()`. The R4 pair really acquires a
        # `CqConsumerToken` per ring into a `ConsumerPrefix` and must hand each
        # one back to the ring it came from. Production had the R4 acquire wired
        # to the R3 release, and `native_release_consumers` opened
        # `let _ = prefix;`.
        #
        # While the acquire could never succeed (the shell ring carried no
        # brand) that mismatch was invisible. The moment the acquire works, the
        # effect order `AcquireConsumersIncreasing -> DrainStablePrefixesBounded
        # -> RetireCredits -> ReleaseConsumers` puts two rows inside the window
        # where THIS fence owns every ring's consumer:
        #   * the drain asked the R3 predicate, whose `cq_owner.is_none()` is
        #     false on exactly the rings the acquire just succeeded on;
        #   * the release dropped every token, leaving `cq_owner` `Some(..)`
        #     with no holder, so every later acquire finds it busy for ever.
        # So both rows are pinned here, together with the repair that unblocks
        # them -- fixing the acquire alone moves the hang one row down.
        #
        # Round-15 N1 moved this pin, and how is worth recording. The frozen
        # text below used to end the refusal arm with
        # `let_=prefix.restore_released_token(ring,token);returnErr(());`, so
        # this check was holding the discarded refusal in place: the restore it
        # named could never succeed for ring 0, and `let _ =` dropped the affine
        # token the refusal carried. A pin over a body freezes whatever that
        # body does, correct or not, and every repair of the defect fails the
        # pin. The arm now keeps the token -- and the loop accounts for each one
        # that reached its ring, which is what lets core refuse to mint a
        # release proof over a token that did not.
        consumer_collapsed = re.sub(r"\s+", "", text)
        require(
            "whileprefix.release_remaining()>0{letOk((ring,token))=prefix.p"
            "op_for_release()else{returnErr(());};ifletErr(token)=unsafe{cr"
            "ate::session::fence_release_cq_consumer_at(session,ring,token)"
            "}{ifletErr((_,_unreturnable))=prefix.restore_released_token(ri"
            "ng,token){}returnErr(());}ifprefix.confirm_released_token(ring"
            ").is_err(){returnErr(());}}Ok(())}" in consumer_collapsed
            # The drain reads the SQ half, and only after proving this fence
            # holds the CQ half -- the phase assertion is part of the property,
            # not decoration: without it the SQ-only read would be unguarded.
            and "prefix_phase()!=fsring_core::adapter::fence::ConsumerPrefixPhase"
            "::AcquiredComplete{returnErr(());}" in consumer_collapsed
            and "ifunsafe{crate::session::checkpoint_wait_sq_roles_with_consumers_held"
            "(session)}{Ok(())}else{Err(())}" in consumer_collapsed
            # And the R3 release helper stays off the R4 path.
            and "self.inner.release_consumers()" not in consumer_collapsed
            and "checkpoint_wait_existing_sq_cq_roles_and_consumers(session)"
            not in consumer_collapsed,
            "r4-consumers-are-returned-to-the-rings-they-came-from",
            "the R4 consumer rows no longer match the R4 acquire: either the "
            "release stopped handing each popped token back to its own ring "
            "(leaving `cq_owner` owned by nobody and every later acquire busy "
            "for ever), or the drain went back to asking whether a consumer "
            "this fence is holding is free, which refuses every fence whose "
            "acquire succeeded",
        )
        # Round-14 highs, found by the native review. The retry worker's
        # `Complete` arm did two things the PRIMARY path's `Complete` arm has
        # always done, and did neither: it took the control strong reference
        # and dropped it (`let _ = ddi.take_unreleased_control();`), leaving
        # `strong_count` one too high so the terminal release answered
        # `Retained` and the session was never deleted; and it wrote
        # `let _ = finish_fence(...)`, discarding a
        # `StrongReleaseDisposition::Finalizer(kick)` so a fence that completed
        # after a retry never queued its finalizer and lost its admission
        # rundown reference. A fence completing on a retry could not finish
        # what the same fence completing first time did.
        #
        # Both are pinned as WHOLE arms rather than by counting `.release(` or
        # `unsafe` tokens. Those counts moved when the repair landed and had to
        # be updated, so they do observe a revert -- but they observe it as
        # arithmetic, and this project has been failed four rounds running for
        # exactly that: an observer watching an artefact instead of the
        # decision. What must hold is that the taken reference is DEPOSITED and
        # that `finish_fence`'s answer is ACTED ON, and that is what is written
        # here.
        retry_collapsed = re.sub(r"\s+", "", text)
        require(
            "FenceRunOutcome::Complete{mutddi,completed}=>{"
            "letreleased_control=ddi.take_unreleased_control();"
            "ifletSome(control)=released_control{"
            "letmutlock=unsafe{KernelSessionRegistry::lock(registry)};"
            "let_=unsafe{release_strong_and_deposit(&mutlock,"
            "R4ReleaseAuthority::Stable(control.into_reference()),None,)};"
            in retry_collapsed
            and "letdisposition=matchunsafe{prepare_finish_fence(&mutlock,candidate)}{"
            "Ok(prepared)=>Some(unsafe{finish_fence(&mutlock,prepared)}),"
            "Err(_)=>None,};"
            "unsafe{lock.release()};"
            "matchdisposition{"
            "Some(StrongReleaseDisposition::Finalizer(kick))=>{"
            "unsafe{queue_finalizer(kick)};}"
            "Some(StrongReleaseDisposition::Retained)|None=>{}}"
            in retry_collapsed
            # No revert to the discarding forms, in any spelling that keeps the
            # call and throws the answer away.
            and "let_=ddi.take_unreleased_control();" not in retry_collapsed
            and "let_=unsafe{finish_fence(" not in retry_collapsed,
            "fence-retry-complete-deposits-and-acts-on-its-answers",
            "the fence retry worker's completing arm no longer deposits the "
            "control strong reference it takes, or no longer acts on "
            "`finish_fence`'s disposition: a fence that completes after a "
            "retry leaves the session undeletable, or never queues the "
            "finalizer its generation still owes",
        )
        # Round-10 blocker. The fence retry worker's fail-stop arm held
        # seven affine owners with no `Drop` and returned without
        # depositing any of them: the shell block, the `DriverState`
        # reference whose absence makes unload's sole-reference predicate
        # bugcheck, and a control-context rundown reference that
        # `wait_control_context_admission_drained` then waits on for ever.
        # The three constructs are ONE rule -- a packet nobody stores, or
        # a store whose visibility answer nobody resolves, is the same
        # silent loss in a different shape.
        require(
            re.search(
                r"FenceRetryDisposition::FailStop\(_\)\)\s*\|\s*Err\(_\)\s*=>\s*\{"
                r".{0,2500}?R3FailStopPacket::checkpoint\(FenceIncompletePacket"
                r".{0,800}?FenceIncompletePacketProgress::Residual\s*\{\s*residual\s*,\s*control\s*\}"
                r".{0,1500}?store_fail_stop_locked\("
                r".{0,800}?finish_finalizer_fail_stop_visibility\(",
                text,
                re.S,
            )
            is not None,
            "fence-retry-fail-stop-deposits-its-owners",
            "the fence retry worker's fail-stop arm no longer deposits the "
            "packet its owners belong to, so a refused retry silently drops "
            "the shell, the DriverState reference and a control rundown "
            "reference",
        )

    if rel == "driver/fsring-fsd/src/control.rs":
        # Round 16's blocker was every published session leaking its context,
        # so that `fsring_driver_unload` waited for ever on
        # `control_context_admission`. Its cause was CLEANUP never acknowledging
        # the finalizer's record -- the winner and joiner claimed once, before
        # the terminal ran, and a CLEANUP refused the dispatch rundown claimed
        # nothing -- not CLOSE's classification. Round 17 answered it here by
        # taking the close right out of the unacknowledged `Completed` record,
        # and the process-loss and unload scans then dereferenced the freed
        # context (native review N17-1).
        #
        # The decision lives in `fsring-core` as
        # `ControlContextCloseOwnership::for_lifetime`, the design's rule again,
        # and core's `close_choreography` walk shows the acknowledgement now
        # reachable through `continue_cleanup`. This row exists because that
        # holds only while THIS file still asks core and never takes the right
        # out of a record itself: `fsring-fsd` has no host test target, so
        # nothing else can see it do either.
        #
        # LIMIT, stated because a pin over source text is not a proof about
        # behaviour: this checks that the delegation is present and that the
        # local verdicts and the round-17 take are gone. It cannot see a caller
        # that bypasses `take_close_ownership` altogether.
        collapsed_close = re.sub(r"\s+", "", text)
        # Round 20 (N18-2): the delegation has two steps now -- the
        # classification, then `adopt_unused_lease`. The needle drops the
        # terminator so this row keeps watching the call it is about rather
        # than going red for a change that belongs to the row below.
        require(
            "letownership=ControlContextCloseOwnership::for_lifetime(kind)"
            in collapsed_close
            # Round 17 took the close right out of an unacknowledged record.
            # The design forbids that; CLEANUP is the record's only consumer.
            and "into_close_right" not in collapsed_close
            # And the answers this crate used to invent are gone: every arm
            # reports core's `ownership`, so none of the three variants can be
            # named here again.
            and "(ControlContextCloseOwnership::CloseRight,Some(close))"
            not in collapsed_close
            and "(ControlContextCloseOwnership::CellOwned,None)" not in collapsed_close
            and "(ControlContextCloseOwnership::Lease,None)" not in collapsed_close,
            "close-ownership-is-decided-in-core",
            "CLOSE's control-context ownership is decided in fsring-fsd again, or "
            "takes the close right out of a record no CLEANUP acknowledged: the "
            "process-loss and unload scans can then dereference a freed context",
        )

        # Round 18. The four driver facts core's `close_choreography` walk
        # models, plus the call into its continuation. That walk shows each one
        # load-bearing -- remove any and a context is freed while still named,
        # stranded, raced, or deadlocked -- but it runs over core's model, not
        # over this file, and `fsring-fsd` has no host test target. These rows
        # are what keep the driver agreeing with the walk. Each is graded by a
        # retained plant in the self-test.
        require(
            "letlock=unsafe{crate::lifecycle::KernelSessionRegistry::lock(registry)};"
            "lettaken=unsafe{take_close_ownership(context)};"
            "unsafe{lock.release()};" in collapsed_close,
            "close-takes-ownership-under-the-registry-lock",
            "CLOSE empties and restores the control-context lifetime slot without "
            "the lock the finalizer stores it under: the finalizer's preflight can "
            "see the emptied slot, or the restore can overwrite a stored record",
        )
        require(
            "letprecommit=matchunsafe{ControlDispatchRundownGuard::acquire(context)}"
            "{None=>None," in collapsed_close
            and "ControlDispatchRundownGuard::acquire(context)})else{"
            "returnunsafe{complete(irp,STATUS_SUCCESS)};" not in collapsed_close,
            "late-cleanup-takes-the-committed-route",
            "a CLEANUP refused at the dispatch rundown completes without claiming: "
            "the terminal's record is never acknowledged and CLOSE strands the "
            "context (native review N17-2)",
        )
        require(
            "matchcontinue_cleanup(pass,result){" in collapsed_close
            and "CleanupContinuation::ReclaimOnceifpass==CleanupPass::First=>"
            "{pass=CleanupPass::Reclaim;}" in collapsed_close,
            "cleanup-reclaims-after-its-terminal",
            "CLEANUP no longer claims again after its terminal: the finalizer's "
            "record is never acknowledged and every published context is stranded",
        )
        require(
            "NativeCleanupClaim::new(guard,claim).release_outer()" in collapsed_close,
            "cleanup-releases-the-rundown-before-the-route",
            "CLEANUP's committed route no longer runs after the dispatch rundown "
            "is released: a winner deadlocks against the fence's own rundown wait",
        )

        # Round 21 (round-20 native review N1, N2). N18-1's retry asked again
        # on every refusal, for ever, having thrown away the status that says
        # whether asking again can help, and this row matched three tokens a
        # `break` after the delay kept. Core now reads the status and owns the
        # budget; this row pins the WHOLE loop that follows it, collapsed,
        # verbatim and exactly once. Any edit inside it fails here: a `break`
        # or `return` in the retry arm, the budget moved into the loop, the
        # status replaced, an arm merged, the delay removed, or a changed
        # interval. A deliberate edit updates this needle in the same commit.
        #
        # LIMIT: source text. It proves the dispatch is the loop that core's
        # `stackexpand` tests and the `close_choreography` walk describe. What
        # the budget answers is theirs to prove.
        cleanup_expansion_loop = (
            "letmutbudget=CleanupExpansionBudget::per_arrival();"
            "letoutcome=loop{"
            "letmutblock=CleanupCalloutBlock{registry:registry.as_ptr(),"
            "context:context.as_ptr(),outcome:None,};"
            "letstatus=unsafe{fsring_sys::c4::KeExpandKernelStackAndCallout("
            "Some(fsring_cleanup_callout),"
            "core::ptr::addr_of_mut!(block).cast::<c_void>(),"
            "CLEANUP_STACK_EXPANSION_BYTESasfsring_sys::SIZE_T,)};"
            "letfault=matchresolve_cleanup(status,block.outcome.take()){"
            "Ok(outcome)=>breakoutcome,Err(fault)=>fault,};"
            "matchbudget.answer_refusal(fault){"
            "CleanupExpansionRecourse::DelayAndRetry=>{"
            "letmutinterval=fsring_sys::c4::LARGE_INTEGER{"
            "QuadPart:-EXPANSION_RETRY_INTERVAL_100NS,};"
            "let_elapsed=unsafe{fsring_sys::c4::KeDelayExecutionThread("
            "0,0asBOOLEAN,core::ptr::addr_of_mut!(interval),)};}"
            "CleanupExpansionRecourse::Exhausted|CleanupExpansionRecourse::Surrender=>{"
            "breakCleanupTerminalOutcome::Refuse;}}};"
            "matchoutcome{CleanupTerminalOutcome::Proceed=>{}"
            "CleanupTerminalOutcome::Refuse=>{"
            "unsafe{wait_and_release_requestor(context.as_ptr())};"
            "returnunsafe{complete(irp,STATUS_INVALID_DEVICE_STATE)};}}"
        )
        require(
            collapsed_close.count(cleanup_expansion_loop) == 1
            and "constEXPANSION_RETRY_INTERVAL_100NS:i64=100_000;" in collapsed_close,
            "cleanup-retries-only-a-memory-refusal-within-its-budget",
            "the CLEANUP expansion loop is no longer the one core's budget and "
            "the close_choreography walk describe: a refusal can hang the "
            "closing thread for ever, give up without asking again, or run the "
            "callout twice (round-20 native review N1, N2)",
        )

        # Round 20, native review N18-2. A CLOSE that found the CREATE
        # admission lease still in the slot detached and returned: the pool
        # block leaked and the lease -- the rundown `fsring_driver_unload`
        # waits on -- was never released. CLOSE now adopts it, but only on the
        # binding's own word that nothing is installed through the context,
        # read in the same hold that takes the slot. This row is what keeps
        # this file asking core both questions and handing the converted right
        # out; `fsring-fsd` has no host test target.
        #
        # LIMIT: source text, not behaviour. It sees the two calls and the
        # conversion, not that the lock is held across them --
        # `close-takes-ownership-under-the-registry-lock` above is what sees
        # that.
        require(
            "letownership=ControlContextCloseOwnership::for_lifetime(kind)"
            ".adopt_unused_lease(holds_no_installation);" in collapsed_close
            and "binding_holds_no_installation(" in collapsed_close
            and "ControlContextLifetime::Lease(lease)ifownership.may_free()=>("
            "ownership,Some(crate::lifecycle::CloseContextRight::new(lease)),)"
            in collapsed_close,
            "close-adopts-an-uninstalled-lease",
            "a CLOSE that finds the CREATE admission lease detaches and leaks "
            "both the context and the admission, so unload waits for ever on a "
            "rundown with no signaller (native review N18-2)",
        )

    if rel == "driver/fsring-fsd/src/pending_enter.rs":
        require(
            "ExposedLockPacket" not in text,
            "pending-lock-packet-closed",
            "pending lock-bearing fail-stop packet API is exposed",
        )
        # Round-15 N2, swept in round 16. A bugcheck holding this file's slot
        # spin lock hangs every other processor that touches the ring, and
        # `PendingContextUnlock`'s `Drop` cannot save it: `panic = "abort"` plus
        # the crate's `#[panic_handler]` means nothing unwinds. `a56eedb` moved
        # three sites out of a hold and did not generalise, so two more were
        # still there one commit later.
        #
        # The population is frozen here rather than described in a comment,
        # because round 15's finding was that describing a shape and telling the
        # next reader to look for more is not sweeping. A NEW panic on a held
        # path fails this row.
        #
        # The walk mirrors the file's two hold styles: a raw
        # `KeAcquireSpinLockRaiseToDpc` ... `KeReleaseSpinLock` pair, and a guard
        # armed from a raw acquire (which ADOPTS it -- the release is the guard's
        # `.release()`, so counting both would double-count every guarded frame).
        # The four CSQ callbacks run inside the framework's own hold for their
        # whole body.
        # Round-16 N16-3. The refused-handoff arm was collapsed with `Ready`:
        # `Ok(PendingHandoffCommit::Ready(_)) | Err(_) => None`. `Ready` means the
        # handoff COMMITTED and owes no queue call; `Err` means it did not happen
        # and hands the installer token back. Collapsed, the refusal dropped that
        # token and fell through to publish `handoff_done()` and
        # `InstallAxis::HandoffDone` -- a transition that never occurred, on a
        # slot whose IRP is already in the CSQ.
        #
        # `fsring-fsd` has no host test target, so this is the only thing that can
        # see the two arms merged again.
        handoff_collapsed = re.sub(r"\s+", "", text)
        require(
            "Ok(PendingHandoffCommit::Ready(_))|Err(_)=>None,"
            not in handoff_collapsed
            and "Ok(PendingHandoffCommit::Ready(_))=>None," in handoff_collapsed,
            "refused-handoff-is-not-ready",
            "`park_wait_enter` treats a refused `commit_pending_handoff` as a "
            "committed one again: the installer token the refusal returns is "
            "dropped and `HandoffDone` is published for a handoff that did not "
            "happen",
        )
        held_panics = _pending_panics_inside_a_hold(text)
        require(
            held_panics == PENDING_PANIC_IN_HOLD,
            "pending-panics-inside-a-hold",
            "the set of panic-family sites reachable inside a slot-lock hold in "
            "pending_enter.rs is not the frozen one: a bugcheck holding this "
            "lock hangs every processor that touches the ring, and the unlock "
            "guard's Drop never runs under `panic = \"abort\"`. Expected %r, "
            "found %r" % (PENDING_PANIC_IN_HOLD, held_panics),
        )
        # Round-9 blocker 2. The worker's completion authority is whatever
        # `classify_worker_dequeue` says about ONE locked observation of the
        # axis and the pointer -- never the slot pointer read on its own,
        # which cannot tell "the driver was handed this IRP" from "the cancel
        # routine still owns it".
        #
        # The argument spelling is part of the rule on purpose: a call that
        # passes a constant axis satisfies a presence-only check while
        # reinstating the whole defect, so the observed axis argument has to be
        # the field read, not a literal.
        # Two call sites, both pinned: the pass asks before it goes to the
        # CSQ, and the abandoned pass asks again to learn whether the cancel
        # path adopted the request while it stood `Completing`. Requiring the
        # count rather than "at least one" is what stops a third, unreviewed
        # classification appearing, and requiring the axis spelling at BOTH is
        # what stops either being fed a literal.
        classified_axis = re.findall(
            r"classify_worker_dequeue\(\s*\(\*raw\)\.irp_axis\s*,", text
        )
        require(
            "letirp=unsafe{(*raw).irp};" not in re.sub(r"\s+", "", text)
            and text.count("classify_worker_dequeue(") == 2
            and len(classified_axis) == 2
            and text.count(
                "WorkerDequeueAuthority::ReleasedToDriver(irp) => Some(irp),"
            ) == 1,
            "pending-completion-authority-is-the-classified-release",
            "the pending completion pass no longer takes its IRP from the "
            "classified CSQ release: either the raw slot read is back, or the "
            "classifier is gone or fed a constant axis",
        )
        # Round-11 high, found by review: the previous version of this rule
        # required only that the abandon CALLED the ask, so the one-line
        # guard that fixes what the ask got wrong satisfied it unchanged.
        # It graded the artefact. This grades the decision.
        #
        # Nothing in this driver re-reads a stored wake, so a reason left in
        # the slot with the schedule `Idle` is a request nobody will serve --
        # but queueing a pass for a slot no pass can BEGIN on is worse than
        # leaving it: `begin_pass` refuses without emptying the wake slot, so
        # the abandon queues another, and `fail_unstored_parked_wait` leaves
        # `parked_plan` None for the life of the slot. That is a work item
        # requeueing itself for ever on a system worker thread.
        #
        # So the rule pins the DECISION and its single mint: one
        # `pass_admission`, testing all four fields a pass needs, is the only
        # thing that constructs a `PassAdmission`, and the ask takes one by
        # value. A caller cannot then queue a pass without having asked, and
        # a second mint would have to appear here to get around it.
        #
        # It ALSO pins both call sites, and their count. Grading the decision
        # alone repeats the very failure this rule was rewritten for, one
        # level up: a rule that says only "the admission is well formed" is
        # satisfied by a tree in which nothing asks it. The round-11 review
        # found exactly that hole on the store side -- deleting the store's
        # queue call, or its `owed` gate, produced no finding while the
        # comment two lines above claimed "both instants ask". So both
        # instants are named here, each with its own ask, and the number of
        # calls is fixed at two: a third call site added later is a queue
        # instant nobody reasoned about, and it fails rather than passing
        # quietly.
        # Round-14 medium, found by the native review. `observe_pending_for_unload`
        # had three `panic!`/`assert!` sites INSIDE the `PendingContextUnlock`
        # scope, i.e. with the slot spin lock held. This driver builds
        # `panic = "abort"` in both profiles, so `Drop` never runs and the guard
        # would not release: a bugcheck holding this lock hangs every other
        # processor that touches the ring. Two siblings in the same file release
        # first for exactly this reason and say so.
        #
        # The three cases are carried OUT of the hold as a value and fail after
        # the release, so what is pinned is that adjacency: the release, then the
        # decision. A pin that merely found a `panic!` in the function would pass
        # with it back inside the hold, which is the whole defect.
        unlock_panic_collapsed = re.sub(r"\s+", "", text)
        require(
            "unlock.release();matchobserved{"
            "Ok(observation)=>observation,"
            "Err(reason)=>panic!(),}" in unlock_panic_collapsed,
            "unload-observation-fails-outside-the-slot-hold",
            "`observe_pending_for_unload` no longer carries a broken invariant "
            "out of the slot-lock hold before failing on it: with "
            "`panic = \"abort\"` the guard's `Drop` never runs, so the bugcheck "
            "leaves the ring's spin lock held",
        )

        # Round-12 N1/E1, found by BOTH lenses: the version of this rule that
        # replaced the artefact check still graded an artefact. It required the
        # four field tests to be SPELLED, not to decide anything, so wrapping
        # both of them in `if false { ... }` one nesting level out left
        # `pass_admission` admitting every slot and this audit reporting
        # `PASS (473 checks, 0 failures)`. And it pinned nothing at all about
        # `begin_pass` -- while this rule's own finding message claimed to
        # detect "the admission stopped testing what `begin_pass` refuses on".
        # Adding one refusal to `begin_pass` that the admission does not test
        # reproduces the round-11 permanent worker-thread livelock under a
        # fully green 38-row battery.
        #
        # Both bodies are therefore pinned WHOLE and contiguously, from the
        # signature to the closing brace. A contiguous body match is not a
        # spelling check: an inserted guard, a wrapped guard, a reordered test,
        # a dropped `return None;` effect and a deleted ask all break it,
        # because there is nowhere in the match for them to hide. This is the
        # fourth round in which a rule was found watching the shape of a
        # decision instead of the decision, so it stops describing the body and
        # starts being the body.
        admission_collapsed = re.sub(r"\s+", "", text)
        require(
            # The decision itself: two guards, each with its refusal EFFECT,
            # and one mint reachable only after both.
            "fnpass_admission(&self)->Option<PassAdmission>{"
            "ifself.parked_plan.is_none()||self.arbiter.is_none(){returnNone;}"
            "ifself.parked_role.is_none()||self.control_link.is_none(){returnNone;}"
            "Some(PassAdmission(()))}" in admission_collapsed
            # The consumer whose refusal set the admission must equal. `install`
            # is asked here and at the queue, and NOTHING else may refuse: any
            # further condition is a reason a pass will not begin that no queue
            # instant consults, which is precisely the livelock.
            and "fnbegin_pass(&mutself)->Option<PendingReason>{"
            "letinstall=self.install?;"
            "letPassAdmission(())=self.pass_admission()?;"
            "begin_native_worker_pass(install,&mutself.schedule,&mutself.wake,"
            "&mutself.worker_owner,).ok()}" in admission_collapsed
            and admission_collapsed.count("Some(PassAdmission(()))") == 1
            # The DISCHARGE, pinned whole. Round 13 pinned this function's
            # signature and its two call sites and not one byte of its body,
            # so both instants could still ask, still hold a real
            # `PassAdmission`, still call -- and nothing would ever be queued.
            # An adversarial pass made the body `return None;` unconditionally
            # and this audit stayed at PASS 475/0. A decision nobody discharges
            # is not a decision.
            and "fnqueue_wake_still_owed(&mutself,admission:PassAdmission)"
            "->Option<QueueWorkRight>{"
            "letPassAdmission(())=admission;"
            "letinstall=self.install?;"
            "ifself.queue_right.is_some()||self.handoff_queue.is_some(){returnNone;}"
            "schedule_stored_wake(install,&mutself.schedule,&self.wake,"
            "&mutself.owners,&mutself.worker_owner,).unwrap_or_default()}"
            in admission_collapsed
            and "Err(_)=>self.abandon_queued_pass()," in admission_collapsed
            # The abandon instant, pinned WHOLE rather than through a regex
            # with `.{0,900}?` slack between the signature and the ask. That
            # slack was not cosmetic: an adversarial pass inserted an early
            # `return None;` at the top of this function -- killing the instant
            # outright -- and the gap swallowed it at PASS 475/0.
            and "fnabandon_queued_pass(&mutself)->Option<QueueWorkRight>{"
            "lettoken=self.worker_owner.take()?;"
            "matchself.schedule.abandon_queued_pass(token){"
            "Ok(token)=>{let_=self.owners.release_owner(token);"
            "letadmission=self.pass_admission()?;"
            "self.queue_wake_still_owed(admission)}"
            "Err((_,token))=>{self.worker_owner=Some(token);None}}}"
            in admission_collapsed
            # Exactly one definition of each pinned name. A contiguous body
            # match is satisfied by ANY occurrence of that text, so a
            # `#[cfg(...)]`-gated twin, a dead decoy module, or a trait impl
            # carrying the pinned body verbatim leaves the pin green while a
            # second definition is what actually compiles and runs. Counting
            # the definitions is what makes the pinned body the ONLY body.
            and admission_collapsed.count("fnpass_admission") == 1
            and admission_collapsed.count("fnbegin_pass") == 1
            and admission_collapsed.count("fnqueue_wake_still_owed") == 1
            and admission_collapsed.count("fnabandon_queued_pass(&mutself)") == 1
            # Every OCCURRENCE of the mint and of the discharge, counted by
            # bare identifier rather than by one punctuation-decorated
            # spelling. An adversarial pass forged an admission with a bare
            # `PassAdmission(())` -- invisible to a counter that only looks for
            # the `Some(`-wrapped form -- and called the discharge through
            # UFCS as `Self::queue_wake_still_owed(`, invisible to a counter
            # that requires a leading dot. Both counters were mine, and both
            # were spellings. These four are the whole census: 1 mint inside
            # `pass_admission`, 3 more `PassAdmission(())` as the destructuring
            # in the discharge, in `begin_pass` and in the mint's own `Some`;
            # 1 definition plus 2 call sites of the discharge; 1 definition
            # plus 3 asks of the admission.
            and admission_collapsed.count("PassAdmission(())") == 4
            and admission_collapsed.count("queue_wake_still_owed") == 3
            and admission_collapsed.count("pass_admission") == 4
            # The frame ABOVE. Pinning a body pins nothing about the expression
            # that calls it, and an adversarial pass restored the round-11
            # livelock verbatim with a readiness guard at this call site --
            # `begin_pass` itself untouched. The one call site is pinned with
            # the conditions that may gate its answer, so a new gate in front
            # of it, or a second call site, is a refusal nobody consults.
            #
            # Counted by BARE IDENTIFIER: 1 definition + 1 call. The first
            # version counted `begin_pass()`, a punctuation-decorated spelling,
            # so a UFCS second call site passed -- reintroducing one commit
            # later exactly the defect the identifier counts above were added
            # to close. Both round-14 reviews found it independently.
            and admission_collapsed.count("begin_pass") == 2
            #
            # The gates are unchanged; the true-branch gained the undo the
            # round-14 review asked for (a `Completing` declared with no
            # authorities to follow is given straight back). What this pin
            # owns is the GATES in front of `begin_pass`, so it quotes the
            # whole expression and moves with it.
            and "letreason=runtime.begin_pass();"
            "lettaken=ifreason.is_some()"
            "&&!matches!(handed,WorkerDequeueAuthority::NoParkedIrp)"
            "&&runtime.begin_completion(){"
            "lettaken=runtime.take_completion_authorities();"
            "iftaken.is_none(){runtime.abandon_completion();}"
            "taken}else{None};" in admission_collapsed
            # The store instant: a wake that landed before the plan was
            # published, asked only where the handoff did not already publish
            # a `Queued`, so the slot still owes exactly one queue call.
            and re.search(
                r"letowed=ifstored\.is_ok\(\)&&queued\.is_none\(\)\{"
                r"slot_runtime\.pass_admission\(\)\.and_then\("
                r"\|admission\|slot_runtime\.queue_wake_still_owed\(admission\)\)"
                r"\}else\{None\};",
                admission_collapsed,
                re.S,
            )
            is not None
            and admission_collapsed.count(".queue_wake_still_owed(") == 2,
            "a-queued-pass-is-owed-only-where-one-could-begin",
            "the queued-pass decision changed: either `pass_admission`'s body "
            "is no longer exactly two guarded refusals and one mint, or "
            "`begin_pass` refuses on something the admission does not test (a "
            "pass that will never begin, queued for ever), or one of the two "
            "instants that owe a queue call stopped asking, leaving a stored "
            "wake for nobody",
        )

        # Round-10 blocker 1. `record_and_schedule_pending` refuses a wake in
        # `Completing` BEFORE it records one, so a cancel that lands while a
        # pass stands declared `Completing` is dropped, not stored -- and once
        # `e224144` made that declaration abandonable, the abandoned pass
        # became the last thing that can notice the framework adopted its
        # request. The re-classification and the deposit are ONE rule: the
        # re-read alone answers a question nobody acts on, and a deposit alone
        # would fire for a request the cancel path never took.
        require(
            re.search(
                r"runtime\.abandon_completion\(\);"
                r".{0,3000}?matches!\(\s*adopted\s*,\s*"
                r"WorkerDequeueAuthority::ReleasedToDriver\(_\)\s*\)"
                r".{0,400}?runtime\.deposit_locked_wake\(PendingReason::Cancel\)",
                text,
                re.S,
            )
            is not None,
            "pending-abandoned-completion-deposits-the-adopted-cancel",
            "an abandoned completion no longer deposits the Cancel the "
            "framework's adoption left unstored, so a cancelled parked ENTER "
            "is dequeued, adopted and completed by nobody",
        )
        # Round-9 high 2. The dequeue must happen INSIDE the completion pass,
        # after the authorities are held -- not in the worker's unconditional
        # roster prefix, where a pass that then refused left the request out of
        # the queue with its cancel routine cleared and nothing scheduled.
        #
        # Both halves are checked: where the DDI is called, and that the
        # refusal paths hand the completion declaration back. `Completing`
        # refuses to finish and refuses to queue, so a refusal that skipped
        # `abandon_completion` would wedge the slot permanently -- a worse
        # defect than the one being repaired.
        #
        # 1 -> 2 abandon sites (round-12 native finding 2, found by review).
        # This function has TWO refusal arms after `begin_completion`, not one:
        # the NULL dequeue answer, and `PendingCompletionPlan::begin` handing
        # every authority back. Only the first undid the declaration; the
        # second returned the authorities and left the schedule at
        # `Completing`, with the IRP already dequeued and its cancel routine
        # spent, so no later wake could rescue the slot. Freezing the count at
        # one is what made the missing undo look like the intended shape --
        # the census recorded the arm that existed rather than the property
        # every refusal arm owes.
        dequeue_callers = tuple(
            name
            for name, _header, body in function_headers_and_bodies(text)
            if "IoCsqRemoveIrp(" in body
        )
        collapsed = re.sub(r"\s+", "", text)
        # Exactly two callers, each named: the completion pass that takes the
        # IRP it is authorised to complete, and the abandon path that takes it
        # back when its plan was never stored. Anything else is the prefix
        # dequeue coming back under another name.
        require(
            text.count("IoCsqRemoveIrp(") == 2
            and sorted(dequeue_callers)
            == ["fail_unstored_parked_wait_at", "run_pending_completion_pass"]
            and "PendingCallbackAction::BeginWorkerPass,PendingCallbackAction::PollAndRecheck,]"
            in collapsed
            # The DECLARATION's own arm, pinned as a decision rather than left
            # to the count below. The round-14 review made this criticism of the
            # previous version and it was right: counting the abandons freezes
            # how many refusal arms EXIST, not the property that every one of
            # them undoes the declaration -- the same census-instead-of-property
            # shape that rule's comment claims to be repairing. It also found a
            # THIRD exit that had no abandon (`take_completion_authorities`
            # answering `None` while the schedule already read `Completing`),
            # which is exactly what a count of the arms that exist cannot see.
            #
            # So the undo is pinned where the declaration is made, in the same
            # lock hold: if the authorities do not come, `Completing` is given
            # back before this frame does anything else. That is checkable text
            # about a decision, and it is what makes the third exit harmless.
            # Quoted WITHOUT the gate conditions in front of it: those belong
            # to the queued-pass rule, which pins this same call site to keep
            # a readiness guard from appearing in front of `begin_pass`. Two
            # rules quoting one span is two copies to keep in step, so each
            # quotes only the part it owns -- that one owns the gates, this
            # one owns the undo.
            and "{lettaken=runtime.take_completion_authorities();"
            "iftaken.is_none(){runtime.abandon_completion();}"
            "taken}" in collapsed
            # The count stays, and stays honest about its reach: three arms
            # undo the declaration -- this one, the NULL dequeue, and the plan
            # refusal. It notices an abandon being REMOVED. It cannot notice a
            # fourth exit being ADDED without one, because a return this rule
            # does not quote is a return it cannot see; that is the residual,
            # and the pin above is what keeps the reachable path from needing
            # the count to be a proof.
            and collapsed.count("runtime.abandon_completion();") == 3,
            "pending-dequeue-follows-the-authorities",
            "the parked IRP is dequeued outside `run_pending_completion_pass`, "
            "or the worker roster prefix walks the dequeue again, or one of "
            "the two refusal arms no longer abandons its completion, leaving "
            "the schedule wedged at `Completing` with the IRP dequeued and "
            "uncancellable: observed dequeue callers %r" % (dequeue_callers,),
        )

    if rel in NATIVE_OWNER_FILES:
        canonical = re.sub(r"\br#([A-Za-z_]\w*)", r"\1", text)
        declarations = tuple(
            re.findall(r"\b(struct|enum|union|type)\s+([A-Za-z_]\w*)", canonical)
        )
        use_aliases = tuple(
            alias
            for clause in re.findall(r"\buse\b([^;]+);", canonical)
            for alias in re.findall(r"\bas\s+([A-Za-z_]\w*)", clause)
        )
        extern_crates = tuple(
            re.findall(
                r"\bextern\s+crate\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?\s*;",
                canonical,
            )
        )
        exports = tuple(
            (kind.replace(" ", ""), name, re.sub(r"\s+", "", value_type))
            for kind, name, value_type in re.findall(
                r"\bpub(?:\s*\([^)]*\))?\s+(const|static(?:\s+mut)?)\s+"
                r"([A-Za-z_]\w*)\s*:\s*([^=;]+)=",
                canonical,
            )
        )
        require(
            declarations == NATIVE_TYPE_DECLARATIONS[rel]
            and use_aliases == NATIVE_USE_ALIASES[rel]
            and not extern_crates
            and exports == NATIVE_CRATE_EXPORTS[rel],
            "native-item-namespace-closed",
            "native owner type/use/export declarations are outside the closed roster",
        )
        protected = (
            "KernelSessionRegistry", "NativeSessionCell", "RegistryLockGuard", "TerminalWork",
            "UnpublishedNativeSessionShell", "NativeSessionShell", "DriverRootRelease",
            "NonPagedAllocationOwner",
            "ControlContextLease",
            "SessionAccessGuard", "NativeRingGuard", "NativeRingSlot", "NativeSession",
            "NativeSessionView", "VolumeExtension", "MountedVolumeExtension",
        )
        protected_impls = tuple(
            header
            for header in impl_headers(canonical)
            if any(
                re.search(
                    r"(?:impl|for|::|\(|>)" + re.escape(type_name) + r"(?:<|\)|$)",
                    header,
                )
                for type_name in protected
            )
        )
        require(
            protected_impls == PROTECTED_IMPL_HEADERS[rel],
            "native-protected-impl-roster-closed",
            "native affine owners/guards have an unauthorized implementation",
        )
        if rel == "driver/fsring-fsd/src/lifecycle.rs":
            receiver_methods_closed = all(
                tuple(
                    tuple(
                        re.sub(r"\s+", "", header)
                        for _name, header in top_level_methods(body)
                    )
                    for body in impl_bodies(canonical, type_name)
                ) == expected
                for type_name, expected in PROTECTED_RECEIVER_METHODS.items()
            )
            require(
                receiver_methods_closed,
                "native-protected-receiver-methods-closed",
                "native cell/registry/lock/terminal receiver methods are outside their exact rosters",
            )
            owner_methods_closed = all(
                len(bodies := list(impl_bodies(canonical, type_name))) == 1
                and tuple(
                    re.sub(r"\s+", "", header)
                    for _name, header in top_level_methods(bodies[0])
                ) == expected
                for type_name, expected in AFFINE_OWNER_METHODS.items()
            )
            require(
                owner_methods_closed,
                "native-affine-owner-methods-closed",
                "native affine owner constructor/consumer surface is outside its exact roster",
            )
        protected_impl_bodies = [
            body
            for type_name in protected
            for body in impl_bodies(canonical, type_name)
        ]
        macro_definitions = tuple(
            re.findall(r"\bmacro_rules\s*!\s*([A-Za-z_]\w*)", canonical)
        )
        allowed_macro_definitions = (
            ("private_authority_seals",)
            if rel == "driver/fsring-fsd/src/lifecycle.rs"
            else ()
        )
        top_level_macros = top_level_macro_names(canonical)
        compact_owner = re.sub(r"\s+", "", canonical)
        macro_contract_ok = (
            compact_owner.count(PRIVATE_AUTHORITY_MACRO) == 1
            if rel == "driver/fsring-fsd/src/lifecycle.rs"
            else not macro_definitions
        )
        has_item_macro = (
            not macro_contract_ok
            or macro_definitions != allowed_macro_definitions
            or any(name not in {"assert", "private_authority_seals"} for name in top_level_macros)
            or (rel != "driver/fsring-fsd/src/lifecycle.rs" and "private_authority_seals" in top_level_macros)
        ) or any(
            name not in {"addr_of", "addr_of_mut", "assert_unchecked", "debug_assert_eq", "matches", "unreachable"}
            for body in protected_impl_bodies
            for name in re.findall(r"\b([A-Za-z_]\w*)\s*!\s*[({[]", body)
        )
        require(
            not has_item_macro,
            "native-protected-impls-macro-free",
            "native protected items may not be generated by a macro",
        )
        expected_resolves = 1 if rel in {
            "driver/fsring-fsd/src/session.rs",
            "driver/fsring-fsd/src/volume.rs",
        } else 0
        access_scope_closed = text.count(".resolve(") == expected_resolves
        if rel == "driver/fsring-fsd/src/session.rs":
            roots = list(function_bodies(text, "execute_enter"))
            start = roots[0].find("let access = match") if len(roots) == 1 else -1
            access_scope_closed = (
                access_scope_closed
                and start >= 0
                # Assignments 48 -> 50, round-17 evidence E4: `snapshot_len`
                # and `copy`, the bounded snapshot core decides the length of.
                and access_scope_is_closed(
                    roots[0][start:], ENTER_ACCESS_CALL_ROSTER, ENTER_ACCESS_CONTROL, 50
                )
            )
        elif rel == "driver/fsring-fsd/src/volume.rs":
            roots = list(function_bodies(text, "fsring_dispatch_mount"))
            start = roots[0].find("let access = match") if len(roots) == 1 else -1
            access_scope_closed = (
                access_scope_closed
                and start >= 0
                and access_scope_is_closed(
                    roots[0][start:], MOUNT_ACCESS_CALL_ROSTER, MOUNT_ACCESS_CONTROL, 9
                )
            )
        require(
            access_scope_closed,
            "native-access-live-scope-closed",
            "resolved access lifetime has an unowned call or acquisition",
        )

    if rel.startswith("driver/fsring-fsd/src/"):
        fixed_names = (
            "initialize_lock",
            "acquire_lock",
            "release_lock",
            "acquire_role",
            "release_pending",
            "release_rollback",
            "signal_pending_enter",
        )
        expected_references = {
            "driver/fsring-fsd/src/lifecycle.rs": (0, 1, 1, 2, 2, 2, 0),
            # Task 19 renamed the roster's wake row to SignalPendingEnter, so
            # the trait method fsd implements now carries that name too. One
            # reference, and it is the impl - not a second wake site.
            # Task 25's residual retry DPC is a second SignalPendingEnter
            # consumer on the same per-slot lock, not a second wake site class.
            "driver/fsring-fsd/src/fence.rs": (0, 0, 0, 0, 0, 0, 2),
            # acquire_lock/release_lock moved 2 -> 3 with the new read-only
            # `r3_checkpoint_roles_and_consumers_are_drained` observation, which
            # correctly does NOT signal. signal_pending_enter stays at 2 (its
            # definition plus the one `checkpoint_signal_existing_enter_waiters`
            # loop that wakes every ring): no design or plan text calls for a
            # second wake site, and the R1-R6 evidence records this wake moving
            # OFF the unguarded projection onto each slot's own lock rather than
            # gaining another caller. This census is descriptive - it exists so a
            # new reference cannot appear unnoticed - so it must state what the
            # source actually has.
            # Task 19's roster extension added five per-slot operations, and
            # every one of them takes the slot's own lock: acquire/release
            # 3 -> 8. `signal_pending_enter` stays at 2 -- the new
            # `deposit_pending_fence_wake` is a second HALF of the same roster
            # row, not a second wake site, and this census is what would notice
            # if it became one.
            # Task 25's live CQ consumer acquire/release on NativeRingSlot
            # takes the same per-slot lock as the Task 19 drained observation.
            # The R6 parked-WAIT repair added `mark_parked_sq_wait`, which
            # records that this ring's SQ owner is a CSQ-parked waiter so the
            # fence's role observation does not refuse it: acquire/release
            # 11 -> 12. It is one more taker of the same per-slot lock, not a
            # new wake site, so `signal_pending_enter` stays at 2.
            # acquire/release 12 -> 13 with `r4_checkpoint_sq_roles_are_drained`
            # (round 15): the R4 drain row needs the SQ half alone, because
            # between AcquireConsumersIncreasing and ReleaseConsumers the fence
            # itself holds every ring's CQ consumer and the R3 predicate asks
            # whether that role is free. One more taker of the same per-slot
            # lock, not a new wake site, so `signal_pending_enter` stays at 2.
            "driver/fsring-fsd/src/session.rs": (2, 13, 13, 3, 4, 3, 2),
        }.get(rel, (0, 0, 0, 0, 0, 0, 0))
        observed_references = tuple(
            len(re.findall(r"\b" + re.escape(name) + r"\b", text))
            for name in fixed_names
        )
        if rel in NATIVE_OWNER_FILES or any(observed_references):
            require(
                observed_references == expected_references,
                "ring-fixed-reference-census",
                "fixed native ring operations have an unowned definition or reference",
            )
    private_names = ("lock_ptr", "state_mut", "state_unshared")
    expected_private = {
        # state_mut 5 -> 6 with the same new drained observation; state_unshared
        # stays at 4 for the reason above.
        # state_mut 6 -> 11 with Task 19's five per-slot operations;
        # state_unshared stays at 4, because none of them reaches the
        # unguarded projection.
        # state_mut 15 -> 16 with `mark_parked_sq_wait`, which reads and marks
        # the SQ owner under the slot lock; state_unshared stays at 4.
        # state_unshared 4 -> 5 (round 15): SETUP stamps each ring set brand
        # into the shell's own `RingEnterState`, which `allocate_events_and_
        # scratch` built by `new` with no brand because the ring set did not
        # exist yet. It takes the UNGUARDED projection on purpose -- the
        # session is unpublished, which is exactly the case that projection
        # documents -- so `state_mut` stays at 16.
        # state_mut 16 -> 17 (round 15): the R4 drain projection above, which
        # takes the slot lock like every other guarded reader.
        "driver/fsring-fsd/src/session.rs": (4, 17, 5),
    }.get(rel, (0, 0, 0))
    observed_private = tuple(
        len(re.findall(r"\b" + re.escape(name) + r"\b", text))
        for name in private_names
    )
    if rel in NATIVE_OWNER_FILES or any(observed_private):
        require(
            observed_private == expected_private,
            "ring-private-reference-census",
            "private native ring projections have an unowned definition or reference",
        )

    if rel == "driver/fsring-fsd/src/lifecycle.rs":
        # Round 18, native review N17-1. `recorded_control_context` had one
        # writer and one clearer (registry initialization), and the process-loss
        # and unload scans dereference what it names under the registry lock.
        # Once CLOSE could free the context, both read freed pool. The hold that
        # stores the completed record now retires it, before CLEANUP can
        # acknowledge that record and so before CLOSE can free. Pinned as the
        # adjacency to the cell projection in that hold, because the property is
        # WHERE it is retired, not that a `None` is written somewhere.
        retire_collapsed = re.sub(r"\s+", "", text)
        require(
            "letcell=unsafe{self.cell_mut_prevalidated(locator.slot_index())};"
            "cell.recorded_control_context=None;" in retire_collapsed,
            "recorded-context-retired-at-completion",
            "the hold that stores a completed record no longer retires the cell's "
            "recorded control-context pointer: the process-loss and unload scans "
            "dereference the context after CLOSE frees it (native review N17-1)",
        )

        # Round-14 BLOCKER, found by the native review. `take_completed_record`
        # empties the context's lifetime slot to `BlockedCellOwned` and hands
        # back the record holding the `CloseContextRight`; its own contract says
        # the caller must put that right back "in the same lock hold".
        # `acknowledge_completed_control` exists to do exactly that and had ZERO
        # production callers. The route carried the record out of the hold
        # instead, the lock was released, and the single consumer's catch-all
        # arm dropped it -- so CLOSE took the `CellOwned` path with no
        # `ExFreePoolWithTag` and no `ExReleaseRundownProtection`, and unload's
        # `ExWaitForRundownProtectionRelease(control_context_admission)` waited
        # for a release that could never happen.
        #
        # The whole arm is pinned, including its refusal edge: a `store_close_right`
        # that cannot place the right must put the RECORD back, because dropping
        # it there is the same leak by a shorter route. Pinned as an arm rather
        # than left to the frozen enum digest and the `unsafe` count that also
        # moved -- both notice a revert, but as arithmetic over the shape, not
        # as the decision that the right is returned before the lock is.
        cleanup_ack_collapsed = re.sub(r"\s+", "", text)
        require(
            "CleanupRoute::CompletedRecord{..}=>{"
            "matchunsafe{crate::control::take_completed_record(context)}{"
            "Some(record)=>{"
            "matchunsafe{acknowledge_completed_control(context,record)}{"
            "Ok((generation,result))=>{"
            "Ok(NativeCleanupRoute::CompletedControl{generation,result})}"
            "Err(record)=>{unsafe{"
            "crate::control::store_completed_control_record_prepared(context,record,)};"
            "Err(wdk_sys::STATUS_INVALID_DEVICE_STATE)}}}"
            in cleanup_ack_collapsed
            # One acknowledgement, and it is this one.
            and cleanup_ack_collapsed.count("acknowledge_completed_control") == 2
            # The record may not leave the hold in the route again.
            and "CompletedControl(record)" not in cleanup_ack_collapsed,
            "cleanup-returns-the-close-right-inside-the-hold-that-took-it",
            "the CLEANUP completed-record arm no longer returns the "
            "`CloseContextRight` to the context inside the lock hold that took "
            "it, or drops the record on its refusal edge: CLOSE then frees no "
            "pool and releases no rundown, and unload waits for ever",
        )
        registry_projection_bodies_closed = all(
            len(bodies := list(function_bodies(text, name))) == 1
            and re.sub(r"\s+", "", bodies[0]) == expected
            for name, expected in REGISTRY_PROJECTION_BODIES.items()
        )
        require(
            registry_projection_bodies_closed,
            "registry-projection-bodies-closed",
            "registry lock projection primitives are outside their exact bodies",
        )
        resolves = list(function_bodies(text, "resolve"))
        require(len(resolves) == 1, "resolve-one", "expected exactly one native resolver")
        if len(resolves) == 1:
            body = resolves[0]
            compact = re.sub(r"\s+", "", body)
            acquire = body.find("ExAcquireRundownProtection")
            projection = body.find("held.project_resolved_session")
            require(
                acquire >= 0
                and projection > acquire
                and (body.find(".session") < 0 or body.find(".session") > acquire),
                "resolve-rundown-before-projection",
                "native resolver projects a shell before access rundown",
            )
            require(
                compact.startswith(
                    "letslot_index=locator.slot_index();"
                    "letmutrundown:Option<*mutEX_RUNDOWN_REF>=None;"
                    "letmutlock:Option<RegistryLockGuard>=None;"
                    "letmutsession:Option<SharedSessionProjection<'_,NativeSession>>=None;"
                    "letmutprogress=ResolvePlan::begin();loop{"
                )
                and len(re.findall(r"\breturn\b", body)) == 3,
                "resolve-entry-closed",
                "native resolver has an early path outside the typed progression",
            )
            require(
                resolver_body_is_closed(body),
                "resolve-body-closed",
                "native resolver has a residual call or control-flow effect",
            )
            require(
                "matchcore.validate_live(locator){Ok(())=>pending.succeeded(),"
                "Err(_)=>pending.refused(ResolveRejection::NotLive),}" in compact
                and "Some(cell)ifcell.matches_live_locator(locator)=>"
                "pending.succeeded(),Some(_)|None=>pending.refused("
                "ResolveRejection::StaleCell)," in compact
                and "Some(cell)ifcell.owners_match(locator)=>pending.succeeded(),"
                "Some(_)|None=>pending.refused(ResolveRejection::MissingOwners),"
                in compact
                and "ifrefusal.releases_lock(){ifletSome(held)=lock.take(){"
                "unsafe{held.release()};}}" in compact
                and "ifrefusal.releases_rundown(){ifletSome(held)=rundown.take(){"
                "unsafe{fsring_sys::c4::ExReleaseRundownProtection(held.cast())};}}"
                in compact
                and "ifacquired==0{pending.refused(ResolveRejection::RundownRefused)}"
                "else{rundown=Some(target);pending.succeeded()}" in compact,
                "resolve-effect-map-closed",
                "native resolver does not map each validation result exactly",
            )
            require(
                body.count("ExReleaseRundownProtection") == 2,
                "resolve-refusal-release",
                "native resolver does not retain both exact rundown-release paths",
            )
            require(
                body.count("core.validate_live(locator)") == 1,
                "resolve-core-live",
                "native resolver does not perform exact core Live validation",
            )
            require(
                body.count("cell.owners_match(locator)") == 1,
                "resolve-native-owners",
                "native resolver does not validate the shell/root owner slots",
            )
            require(
                body.count("cell.matches_live_locator(locator)") == 1
                and body.count("held.project_resolved_session(slot_index, locator)") == 1,
                "resolve-cell-identity",
                "native resolver does not validate and typed-project the same live cell",
            )
        projections = list(function_bodies(text, "project_resolved_session"))
        require(
            len(projections) == 1
            and re.sub(r"\s+", "", projections[0]) == RESOLVER_PROJECTION_BODY,
            "resolve-typed-projection-closed",
            "typed resolver projection is outside its exact lock/rundown-bound body",
        )
        require(
            not re.search(r"\binto_checkpoint_parts_with_locked_mirror\b", text),
            "terminal-mirror-capability-retired",
            "retired Task 12 terminal mirror capability is still present",
        )
        owner_checks = list(function_bodies(text, "owners_match"))
        require(len(owner_checks) == 1, "owner-check-one", "expected one owner-slot validator")
        if len(owner_checks) == 1:
            owner = re.sub(r"\s+", "", owner_checks[0])
            require(
                owner
                == "native_owner_slots_match(locator,NativeOwnerSlotObservation{"
                "shell_locator:self.shell_owner.as_ref().map(NativeSessionOwner::locator),"
                "root_locator:self.root_release.as_ref().map(SessionRootReleaseRight::locator),"
                "shell_matches_mirror:self.shell_owner.as_ref().is_some_and(|shell|"
                "shell.matches_mirror(self.session)),},)",
                "owner-check-closed",
                "native owner validation omits shell, root, branding, or mirror identity",
            )
        scans = list(function_bodies(text, "scan_one_cell_for_process"))
        require(len(scans) == 1, "process-scan-one", "expected exactly one process scan")
        if len(scans) == 1:
            body = scans[0]
            compact_scan = re.sub(r"\s+", "", body)
            observation = body.find(".process_locator(process)")
            release = body.find("lock.release()")
            require(
                observation >= 0 and release > observation and ".session" not in body,
                "process-scan-no-projection",
                "process scan is not one locked pointer-free observation",
            )
            require(
                compact_scan == PROCESS_SCAN_BODY,
                "process-scan-body-closed",
                "process scan is outside its exact recording-only body grammar",
            )
        process_locators = list(function_bodies(text, "process_locator"))
        process_locator = (
            re.sub(r"\s+", "", process_locators[0])
            if len(process_locators) == 1
            else ""
        )
        require(
            len(process_locators) == 1
            and process_locator
            == "ifself.process_loss_handled{returnNone;}letpublished_locator=self.terminal_rendezvous."
            "r3_locked_locator().and_then(|locator|{(self.identity==Some(locator.identity())&&"
            "self.generation==locator.generation()).then_some(locator)});"
            "observe_cell_process(&NativeCellProcessObservation{recorded_process:"
            "NonNull::new(self.process),phase:self.phase,published_locator,},"
            "NonNull::new(process)?,)",
            "process-observation-closed",
            "native process observation does not compare the requested process exactly",
        )
        require(
            text.count("slot.acquire_lock()") == 1,
            "ring-guard-acquire",
            "NativeRingGuard does not exclusively own the lifecycle lock acquire",
        )
        access_drops = list(
            pattern_bodies(
                text,
                r"\bimpl\s+Drop\s+for\s+SessionAccessGuard\s*<\s*'_\s*>\s*\{",
            )
        )
        require(
            len(access_drops) == 1
            and re.sub(r"\s+", "", access_drops[0])
            == "fndrop(&mutself){letregistry=unsafe{&*self.registry};"
            "ifletSome(target)=registry.access_rundown_ptr(self.slot_index){"
            "unsafe{fsring_sys::c4::ExReleaseRundownProtection(target.cast())};}}",
            "access-guard-drop",
            "SessionAccessGuard Drop does not release its exact cell rundown once",
        )

    if rel == "driver/fsring-fsd/src/session.rs":
        require(
            sum(1 for name, _body in struct_bodies(text) if name == "NativeSessionView") == 1
            and len(list(impl_bodies(text, "NativeSessionView"))) == 1,
            "native-view-one",
            "expected one exact NativeSessionView and one observation impl",
        )
        views = list(function_bodies(text, "view"))
        view_body = re.sub(r"\s+", "", views[0]) if len(views) == 1 else ""
        require(
            len(views) == 1
            and view_body
            == "NativeSessionView{identity:self.identity,layout:self.layout,"
            "profile:self.profile,ring_count:self.layout.ring_count(),}",
            "native-view-constructor",
            "NativeSessionView is not constructed from the exact four session values",
        )
        initializers = list(function_bodies(text, "initialize_lock"))
        initializer = re.sub(r"\s+", "", initializers[0]) if len(initializers) == 1 else ""
        require(
            len(initializers) == 1
            and initializer
            == "unsafe{fsring_sys::c4::KeInitializeSpinLock(self.lock_ptr())};"
            and text.count("slot.initialize_lock()") == 1,
            "ring-lock-initialized",
            "every native ring lock is not initialized exactly once before publication",
        )
        require(
            text.count("initialize_ring_locks(") == 1
            and text.count("context.ring_locks = Some(initialized)") == 1,
            "ring-lock-proof",
            "ring initialization does not mint and retain its complete proof",
        )
        acquirers = list(function_bodies(text, "acquire_lock"))
        releasers = list(function_bodies(text, "release_lock"))
        acquirer = re.sub(r"\s+", "", acquirers[0]) if len(acquirers) == 1 else ""
        releaser = re.sub(r"\s+", "", releasers[0]) if len(releasers) == 1 else ""
        require(
            len(acquirers) == 1
            and acquirer
            == "unsafe{fsring_sys::c4::KeAcquireSpinLockRaiseToDpc(self.lock_ptr())}"
            and len(releasers) == 1
            and releaser
            == "unsafe{fsring_sys::c4::KeReleaseSpinLock(self.lock_ptr(),old_irql)};",
            "ring-native-ddis",
            "native ring acquire/release DDI pair is outside its fixed wrapper",
        )
        fixed_transitions = {
            "acquire_role": (
                "LockedEnterState::from_locked(unsafe{self.state_mut()}.enter_mut())"
                ".acquire_role(invocation,role)"
            ),
            "release_pending": (
                "LockedEnterState::from_locked(unsafe{self.state_mut()}.enter_mut())"
                ".release_pending(pending)"
            ),
            "release_rollback": (
                "LockedEnterState::from_locked(unsafe{self.state_mut()}.enter_mut())"
                ".release_rollback(pending)"
            ),
        }
        require(
            all(
                len(list(function_bodies(text, name))) == 1
                and re.sub(r"\s+", "", list(function_bodies(text, name))[0]) == expected
                for name, expected in fixed_transitions.items()
            ),
            "ring-transitions-closed",
            "NativeRingSlot transition body is outside the fixed no-wait grammar",
        )
        signals = list(function_bodies(text, "signal_pending_enter"))
        if len(signals) == 1:
            signal = re.sub(r"\s+", "", signals[0])
            closed = signal == (
                "letold_irql=unsafe{self.acquire_lock()};"
                "letstate=unsafe{self.state_mut()};"
                "unsafe{fsring_sys::c4::KeSetEvent("
                "state.event_ptr(),0,0asfsring_sys::BOOLEAN)};"
                "unsafe{self.release_lock(old_irql)};"
            )
        else:
            closed = False
        require(
            len(signals) == 1 and closed and text.count("ring.signal_pending_enter()") == 1,
            "ring-fence-locked",
            "fence wake bypasses the fixed native ring lock operation",
        )
        require(
            "pub(crate) state: *mut DriverState" not in text,
            "session-root-private",
            "NativeSession DriverState backpointer is crate-visible",
        )
        require(
            "fn system_view_base" not in text and "fn section_view" not in text,
            "mapped-view-no-raw-getter",
            "native session API exposes a mapped-section address",
        )
        require(
            text.count(".lock_ring(") == 4,
            "ring-callsite-census",
            "native lock_ring callsite census is not the exact four transitions",
        )

    if rel == "driver/fsring-fsd/src/volume.rs":
        volume_impls = list(impl_bodies(text, "VolumeExtension"))
        mounted_impls = list(impl_bodies(text, "MountedVolumeExtension"))
        require(
            not any(
                re.search(
                    r"\bfn\s+\w*session\w*[^{};]*->\s*\*\s*(?:mut|const)\s*"
                    r"(?:(?:crate::session::)?NativeSession|(?:core::ffi::)?c_void)\b",
                    body,
                )
                for body in volume_impls + mounted_impls
            )
            and not re.search(
                r"\bsession\s*:\s*(?:\*\s*mut|AtomicPtr\s*<)\s*"
                r"(?:core::ffi::)?c_void",
                text,
            ),
            "volume-no-raw-session",
            "volume code restores raw or type-erased session authority",
        )
        publishers = list(function_bodies(text, "publish_locator"))
        require(len(publishers) == 1, "vdo-publisher-one", "expected one VDO locator publisher")
        if len(publishers) == 1:
            body = re.sub(r"\s+", "", publishers[0])
            ready = body.find("DO_DEVICE_INITIALIZING")
            owner = body.find("VDO_LOCATOR_INITIALIZING")
            write = body.find("write(locator)")
            publish = body.find("store(VDO_LOCATOR_INITIALIZED,Ordering::Release)")
            require(
                ready >= 0
                and "if!initializing" in body
                and owner > ready
                and "!=VDO_LOCATOR_INITIALIZING" in body
                and write > owner
                and publish > write
                and body.startswith(
                    "ifdevice.is_null(){returnErr(STATUS_INVALID_PARAMETER);}"
                )
                and len(re.findall(r"\breturn\b", publishers[0])) == 4
                and body.count("returnErr(STATUS_INVALID_DEVICE_STATE);") == 3
                and "if!initializing{returnErr(STATUS_INVALID_DEVICE_STATE);}" in body
                and "if(*extension).locator_state.load(Ordering::Acquire)"
                "!=VDO_LOCATOR_INITIALIZING{returnErr(STATUS_INVALID_DEVICE_STATE);}" in body
                and body.endswith("Ok(())"),
                "vdo-publication-order",
                "VDO locator publication bypasses readiness/ownership/order",
            )
        readers = list(function_bodies(text, "locator_of"))
        reader = re.sub(r"\s+", "", readers[0]) if len(readers) == 1 else ""
        require(
            len(readers) == 1
            and reader
            == "ifextension.is_null(){returnNone;}letstate=unsafe{(*extension)"
            ".locator_state.load(Ordering::Acquire)};ifstate!="
            "VDO_LOCATOR_INITIALIZED{returnNone;}Some(unsafe{(*(*extension)"
            ".locator.get()).assume_init()})",
            "vdo-read-after-acquire",
            "VDO locator can be read before initialized publication is acquired",
        )
        mounts = list(function_bodies(text, "fsring_dispatch_mount"))
        require(len(mounts) == 1, "mount-one", "expected one native mount root")
        if len(mounts) == 1:
            body = re.sub(r"\s+", "", mounts[0])
            retained = body.find("RetainedAccessGuard::new(access)")
            run = body.find("retained.run(|access|")
            drive = body.find("drive_mount(", run)
            require(
                retained >= 0
                and run > retained
                and drive > run
                and body.startswith(
                    "ifdevice.is_null(){returnSTATUS_INVALID_DEVICE_REQUEST;}"
                )
                # 11 -> 12: the mount preflight refuses a target this driver did not
                # create, before any extension of it is projected.
                and len(re.findall(r"\breturn\b", mounts[0])) == 12
                and "if!routing_target_matches{returnSTATUS_INVALID_DEVICE_REQUEST;}" in body
                and "ifidentity.mount_id.lo!=mount_lo||identity.mount_id.hi!=mount_hi"
                "{returnSTATUS_INVALID_DEVICE_REQUEST;}" in body
                and body.endswith("status"),
                "mount-retains-guard",
                "native mount does not retain access through its progression",
            )

            # Round-9 high 4. A device object names the driver that created it,
            # and only that driver knows the layout behind `DeviceExtension`.
            # The mount preflight used to project the target's extension and
            # accept it on a 4-byte tag, which is a foreign struct read at a
            # guessed offset. The ownership question must be answered first,
            # and it must be answered by comparing the dispatch's own device
            # with the mount target -- comparing either one with itself is the
            # shape that satisfies a presence-only rule while proving nothing.
            own_driver = body.find("letown_driver=unsafe{(*device).DriverObject}")
            target_driver = body.find("lettarget_driver=unsafe{(*target).DriverObject}")
            ownership_refusal = body.find(
                "ifown_driver.is_null()||target_driver!=own_driver"
                "{returnSTATUS_INVALID_DEVICE_REQUEST;}"
            )
            first_extension = body.find("(*target).DeviceExtension")
            require(
                own_driver >= 0
                and target_driver >= 0
                and ownership_refusal > own_driver
                and ownership_refusal > target_driver
                and first_extension > ownership_refusal
                and body.count("(*device).DriverObject") == 1
                and body.count("(*target).DriverObject") == 1,
                "mount-target-owned-before-projection",
                "the mount preflight projects the target's device extension "
                "before proving the target belongs to this driver, or the "
                "ownership comparison no longer names both devices",
            )
            require(
                "ExtensionHeader::kind_of(target_extension)" in body
                and "Some(DeviceKind::VirtualDisk)" in body
                and "identity.mount_id.lo!=mount_lo" in body
                and "identity.mount_id.hi!=mount_hi" in body,
                "mount-volume-owner",
                "native mount bypasses VDO kind or MountId ownership validation",
            )
    return findings


def ring_drop_body_is_closed(body):
    """The sole allowed native ring Drop implementation."""
    pattern = re.compile(
        r"\s*fn\s+drop\s*\(\s*&mut\s+self\s*\)\s*\{\s*"
        r"if\s+let\s+Some\s*\(\s*saved\s*\)\s*=\s*"
        r"self\.old_irql\.take\s*\(\s*\)\s*\{\s*"
        r"saved\.release_with\s*\(\s*\|\s*old_irql\s*\|\s*unsafe\s*\{\s*"
        r"self\.slot\.release_lock\s*\(\s*old_irql\s*\)\s*"
        r"\}\s*\)\s*;\s*"
        r"\}\s*"
        r"\}\s*"
    )
    return pattern.fullmatch(body) is not None


def attribute_targets(text, with_spans=False):
    """Offsets decorated by balanced Rust attributes, plus malformed status."""
    targets = []
    malformed = False
    for marker in re.finditer(r"#\s*!?\s*\[", text):
        index = marker.start()
        while True:
            opening_match = re.match(r"#\s*!?\s*\[", text[index:])
            if opening_match is None:
                break
            opening = index + opening_match.end() - 1
            stack = ["]"]
            index = opening + 1
            while index < len(text) and stack:
                char = text[index]
                if char == "[":
                    stack.append("]")
                elif char == "(":
                    stack.append(")")
                elif char == "{":
                    stack.append("}")
                elif char in "])}":
                    if char != stack[-1]:
                        malformed = True
                        break
                    stack.pop()
                index += 1
            if stack:
                malformed = True
                break
            while index < len(text) and text[index].isspace():
                index += 1
            if re.match(r"#\s*!?\s*\[", text[index:]) is None:
                break
        if malformed:
            continue
        targets.append((marker.start(), index) if with_spans else index)
    return targets, malformed


def has_native_contract_attribute(text):
    """Reject attributes that can rewrite any audited native contract item."""
    targets, malformed = attribute_targets(text, with_spans=True)
    if malformed:
        return True
    declarations = tuple(
        re.compile(pattern)
        for pattern in (
            r"(?:pub(?:\(crate\))?\s+)?struct\s+(?:KernelSessionRegistry|NativeSessionCell|"
            r"RegistryLockGuard|TerminalWork|SessionAccessGuard|NativeSession|"
            r"NativeSessionView|NativeRingSlot|NativeRingGuard|VolumeExtension|MountedVolumeExtension)\b",
            r"impl(?:\s*<[^{}]*>)?\s+(?:KernelSessionRegistry|NativeSessionCell|"
            r"RegistryLockGuard|TerminalWork|SessionAccessGuard|NativeSession|"
            r"NativeSessionView|NativeRingSlot|NativeRingGuard|VolumeExtension|MountedVolumeExtension)\b",
            r"impl\s+Drop\s+for\s+(?:SessionAccessGuard|NativeRingGuard)\b",
            r"(?:pub(?:\(crate\))?\s+)?(?:(?:const|unsafe|async|extern)\s+)*fn\s+"
            r"(?:resolve|matches_live_locator|project_resolved_session|"
            r"into_checkpoint_parts_with_locked_mirror|owners_match|process_locator|"
            r"scan_one_cell_for_process|run_terminal|drop|view|"
            r"initialize_lock|acquire_lock|release_lock|acquire_role|release_pending|"
            r"release_rollback|signal_pending_enter|publish_locator|locator_of|"
            r"fsring_dispatch_mount)\b",
        )
    )
    for start, target in targets:
        if not any(declaration.match(text, target) for declaration in declarations):
            continue
        attributes = re.sub(r"\s+", "", text[start:target])
        decorated = text[target:]
        safe = (
            attributes == "#[repr(C)]"
            and re.match(
                r"(?:pub(?:\(crate\))?\s+)?struct\s+(?:KernelSessionRegistry|NativeSessionCell|"
                r"NativeRingSlot|NativeSession|"
                r"VolumeExtension|MountedVolumeExtension)\b",
                decorated,
            ) is not None
        ) or (
            attributes in {
                "#[derive(Clone,Copy)]",
                "#[allow(dead_code)]",
                "#[derive(Clone,Copy)]#[allow(dead_code)]",
            }
            and re.match(
                r"(?:pub(?:\(crate\))?\s+)?struct\s+NativeSessionView\b",
                decorated,
            ) is not None
        ) or (
            attributes == "#[allow(dead_code)]"
            and re.match(r"impl\s+NativeSessionView\b", decorated) is not None
        ) or (
            attributes == "#[allow(clippy::mut_from_ref)]"
            and re.match(r"(?:unsafe\s+)?fn\s+state_mut\b", decorated) is not None
        ) or (
            # `#[inline(never)]` on the terminal runner, and nowhere else.
            #
            # The rule above exists because an attribute can rewrite a contract:
            # `#[cfg]` deletes the item from the image, `#[no_mangle]` changes
            # who can reach it. Neither applies here. `#[inline(never)]` is a
            # codegen hint with no semantic effect -- it cannot remove the
            # function, change its signature, or change its callers, and the
            # production graph still pins its three outgoing edges as
            # soleCaller.
            #
            # It is required because one shared `run_terminal` carries both
            # arrival modes, so the stack auditor's worst-case walk mixes them
            # and charges CLEANUP for the UNLOAD arm it cannot reach. Threading
            # the mode as a const generic separates them in the linked image;
            # without the barrier LLVM folds each specialisation straight back
            # into its caller and the frame moves rather than splits.
            attributes == "#[inline(never)]"
            and re.match(
                r"(?:pub(?:\(crate\))?\s+)?(?:unsafe\s+)?fn\s+run_terminal\b",
                decorated,
            ) is not None
        ) or (
            attributes == "#[allow(clippy::result_large_err)]"
            and re.match(
                r"(?:pub(?:\(crate\))?\s+)?(?:unsafe\s+)?fn\s+"
                r"(?:release_pending|release_rollback)\b",
                decorated,
            ) is not None
        ) or (
            attributes == "#[unsafe(no_mangle)]"
            and re.match(
                r"pub\s+unsafe\s+extern\s+fn\s+fsring_dispatch_mount\b",
                decorated,
            ) is not None
        )
        if not safe:
            return True
    return False


def has_carrier_attribute(text):
    """Reject macro rewriting of every long-lived locator-only carrier."""
    targets, malformed = attribute_targets(text, with_spans=True)
    if malformed:
        return True
    names = "|".join(sorted(CARRIERS))
    declarations = (
        re.compile(r"(?:pub(?:\(crate\))?\s+)?struct\s+(?:" + names + r")\b"),
        re.compile(r"impl(?:\s*<[^{}]*>)?\s+(?:" + names + r")\b"),
    )
    safe = re.compile(
        r"(?:#\s*\[\s*(?:repr\s*\(\s*C\s*\)|"
        r"derive\s*\(\s*Clone\s*,\s*Copy\s*,\s*Debug\s*,\s*PartialEq\s*,\s*Eq\s*\))"
        r"\s*\]\s*)+"
    )
    for start, target in targets:
        if not any(declaration.match(text, target) for declaration in declarations):
            continue
        if safe.fullmatch(text[start:target]) is None:
            return True
    return False


def guard_api_findings(text, rel):
    """Reject raw access escape and arbitrary/waiting locked-ring APIs."""
    findings = protected_receiver_escape_findings(text, rel)
    if has_carrier_attribute(text):
        findings.append("%s: a locator-only carrier may not be rewritten by an attribute" % rel)
    native_contract_shape = re.search(
        r"\b(?:struct|impl)\s+(?:KernelSessionRegistry|NativeSessionCell|"
        r"RegistryLockGuard|TerminalWork|SessionAccessGuard|NativeSession|NativeSessionView|"
        r"NativeRingSlot|NativeRingGuard|VolumeExtension|MountedVolumeExtension)\b",
        text,
    ) is not None or re.search(
        r"\b(?:unsafe\s+)?fn\s+run_terminal\b", text
    ) is not None
    if (rel in NATIVE_OWNER_FILES or native_contract_shape) and has_native_contract_attribute(text):
        findings.append("%s: a native lifetime contract may not be rewritten by an attribute" % rel)
    for (owner, type_name), expected_body in PROTECTED_STRUCT_BODIES.items():
        if rel != owner:
            continue
        bodies = [body for name, body in struct_bodies(text) if name == type_name]
        if len(bodies) != 1 or re.sub(r"\s+", "", bodies[0]) != expected_body:
            findings.append(
                "%s: %s is outside its exact sealed field grammar" % (rel, type_name)
            )
    for body in impl_bodies(text, "SessionAccessGuard"):
        methods = top_level_methods(body)
        normalized = [re.sub(r"\s+", "", header) for _name, header in methods]
        if normalized != [
            "pub(crate)constfnlocator(&self)->SessionLocator",
            "pub(crate)fnview(&self)->crate::session::NativeSessionView",
            "pub(crate)fnis_published(&self)->bool",
            "pub(crate)fnlock_ring<'access>(&'accessself,ring_index:u32,)->Result<NativeRingGuard<'access,'registry>,SessionAccessError>",
            "pub(crate)fnvalidate_enter_request(&self,input:&[u8],)->Result<fsring_abi::control::EnterRequestV1,fsring_abi::validate::SessionValidationError>",
            "pub(crate)unsafefnpark_wait_enter(&self,ring_index:u32,irp:PIRP,timeout_ms:u32,)->Result<(),NTSTATUS>",
            "pub(crate)unsafefnwake_ready_parked_waits(&self)->bool",
            "pub(crate)unsafefnstore_parked_wait(&self,ring_index:u32,owned:fsring_core::adapter::enter::ParkedWaitInstall,request:fsring_abi::control::EnterRequestV1,)->Result<(),ParkedStoreRefusal>",
            "pub(crate)unsafefnfail_unstored_parked_wait(&self,ring_index:u32)->bool",
            "fnrelease_parked_wait_role(ring:&crate::session::NativeRingSlot,mutowned:fsring_core::adapter::enter::ParkedWaitInstall,)",
            "pub(crate)unsafefnacquire_parked_strong_refs(&self,ring_index:u32,irp:PIRP)->bool",
            "pub(crate)unsafefnrelease_parked_session_role(&self,ring_index:u32,lease:fsring_core::enter::RoleLease,)",
            "pub(crate)unsafefnrelease_parked_strong_refs(&self,ring_index:u32)",
            "pub(crate)unsafefnstore_cq_head(&self,ring_index:u32,next_head:u64)",
            "pub(crate)fncq_cursors(&self,ring_index:u32)->Option<(u64,u64)>",
            "pub(crate)fnread_cqe(&self,ring_index:u32,consumed:u64,)->Option<fsring_abi::layout::Cqe>",
            "pub(crate)fnsession(&self)->&crate::session::NativeSession",
            "pub(crate)fnsq_cursors(&self,ring_index:u32)->Option<(u64,u64)>",
        ]:
            findings.append(
                "%s: SessionAccessGuard is outside its closed field-specific signature roster"
                % rel
            )
        if re.search(
            r"\bfn\s+\w+[^{};]*->\s*\*\s*(?:mut|const)\s+NativeSession\b",
            body,
        ):
            findings.append(
                "%s: SessionAccessGuard exposes a raw NativeSession getter" % rel
            )
        if re.search(r"\bfn\s+\w+[^{};]*->\s*\*\s*(?:mut|const)\b", body):
            findings.append(
                "%s: SessionAccessGuard exposes a raw-address getter" % rel
            )
    ring_slot_impls = list(impl_bodies(text, "NativeRingSlot"))
    for body in ring_slot_impls:
        if re.search(
            r"\bpub\(crate\)\s+(?:unsafe\s+)?fn\s+\w+[^{};]*->\s*"
            r"(?:\*\s*(?:mut|const)\b|&\s*mut\s+NativeRingState\b)",
            body,
        ):
            findings.append(
                "%s: NativeRingSlot exposes a crate-visible raw projection" % rel
            )
    if ring_slot_impls:
        slot_methods = (
            top_level_methods(ring_slot_impls[0]) if len(ring_slot_impls) == 1 else []
        )
        normalized = [re.sub(r"\s+", "", header) for _name, header in slot_methods]
        if len(ring_slot_impls) != 1 or normalized != [
            "fnnew(ring_index:u32)->Self",
            "fnlock_ptr(&self)->*mutKSPIN_LOCK",
            "#[allow(clippy::mut_from_ref)]unsafefnstate_mut(&self)->&mutNativeRingState",
            "pub(crate)unsafefninitialize_lock(&self)",
            "pub(crate)unsafefnacquire_lock(&self)->KIRQL",
            "pub(crate)unsafefnrelease_lock(&self,old_irql:KIRQL)",
            "pub(crate)unsafefnclassify_cq(&self,observation:CqObservation,grants:&GrantTable<'_>,)->DrainPlan",
            "pub(crate)unsafefnacquire_role(&self,invocation:u64,role:EnterRole,)->Result<fsring_core::enter::RoleLease,fsring_core::enter::EnterError>",
            "pub(crate)unsafefnrelease_held_role(&self,lease:fsring_core::enter::RoleLease,)->Result<(),(fsring_core::enter::EnterError,fsring_core::enter::RoleLease,),>",
            "pub(crate)unsafefnrelease_parked_session_role(&self,lease:fsring_core::enter::RoleLease)",
            "#[allow(clippy::result_large_err)]pub(crate)unsafefnrelease_pending<'g>(&self,pending:fsring_core::adapter::enter::PendingRoleRelease<'g>,)->Result<fsring_core::adapter::enter::EnterProgress<'g>,(fsring_core::enter::EnterError,fsring_core::adapter::enter::PendingRoleRelease<'g>,),>",
            "#[allow(clippy::result_large_err)]pub(crate)unsafefnrelease_rollback(&self,pending:fsring_core::adapter::enter::PendingRollbackRoleRelease,)->Result<fsring_core::adapter::enter::EnterRollbackProgress,(fsring_core::enter::EnterError,fsring_core::adapter::enter::PendingRollbackRoleRelease,),>",
            "pub(crate)unsafefnsignal_pending_enter(&self)",
            "pub(crate)unsafefndeposit_pending_fence_wake(&self)->bool",
            "pub(crate)unsafefncheckpoint_acquire_consumer(&self)->bool",
            "pub(crate)unsafefnfence_acquire_cq_consumer(&self,)->Result<fsring_core::enter::CqConsumerToken,()>",
            "pub(crate)unsafefnfence_release_cq_consumer(&self,token:fsring_core::enter::CqConsumerToken,)->Result<(),fsring_core::enter::CqConsumerToken>",
            "pub(crate)unsafefncheckpoint_release_consumer(&self)->bool",
            "pub(crate)unsafefnqueue_installed_pending_work(&self)->bool",
            "pub(crate)unsafefnwait_pending_context_drained(&self)->bool",
            "pub(crate)unsafefnr3_checkpoint_roles_and_consumers_are_drained(&self)->bool",
            # The R4 drain reads the SQ half alone, under the same slot lock.
            "pub(crate)unsafefnr4_checkpoint_sq_roles_are_drained(&self)->bool",
            "pub(crate)unsafefnmark_parked_sq_wait(&self,lease:&fsring_core::enter::RoleLease)->bool",
            "unsafefnstate_unshared(&mutself)->&mutNativeRingState",
        ]:
            findings.append(
                "%s: NativeRingSlot is outside its exact fixed-operation signature roster"
                % rel
            )
    for struct, body in struct_bodies(text):
        if struct == "NativeSession" and re.search(
            r"\bpub\(crate\)\s+state\s*:\s*\*\s*mut\s+DriverState\b", body
        ):
            findings.append(
                "%s: NativeSession exposes its DriverState backpointer" % rel
            )
        if struct == "NativeSessionView":
            fields = re.findall(r"\b(\w+)\s*:\s*([^,]+)", body)
            expected = [
                ("identity", "SessionIdentity"),
                ("layout", "SectionLayoutPlan"),
                ("profile", "PlatformProfile"),
                ("ring_count", "u32"),
            ]
            normalized = [(name, "".join(kind.split())) for name, kind in fields]
            if normalized != expected:
                findings.append(
                    "%s: NativeSessionView is not the exact four-value observation set"
                    % rel
                )
    for body in impl_bodies(text, "NativeSessionView"):
        methods = top_level_methods(body)
        normalized = [re.sub(r"\s+", "", header) for _name, header in methods]
        if normalized != [
            "pub(crate)constfnidentity(&self)->SessionIdentity",
            "pub(crate)constfnlayout(&self)->SectionLayoutPlan",
            "pub(crate)constfnprofile(&self)->PlatformProfile",
            "pub(crate)constfnring_count(&self)->u32",
        ]:
            findings.append(
                "%s: NativeSessionView does not expose exactly four value getters" % rel
            )
        if re.search(r"\bfn\s+\w+[^{};]*->\s*&", body):
            findings.append(
                "%s: NativeSessionView returns a borrowed observation" % rel
            )
    native_session_impls = [
        [name for name, _header in top_level_methods(body)]
        for body in impl_bodies(text, "NativeSession")
    ]
    if native_session_impls and native_session_impls != [
        [
            "identity",
            "layout",
            "is_published",
            "view",
            "validate_enter_request",
            "cq_cursors",
            "read_cqe",
            "store_cq_head",
            "sq_cursors",
            "ring_slot",
        ],
        [
            "ring_set",
            "grant_lock_ptr",
            "grant_table_id",
            "topology",
            "acquire_grant_spin",
            "release_grant_spin",
            "grants_slice_mut",
            "bind_fence_consumer_slab",
        ],
    ]:
        findings.append(
            "%s: NativeSession is outside its closed field-specific method roster" % rel
        )
    for body in impl_bodies(text, "NativeSession"):
        if re.search(
            r"\bpub\(crate\)\s+(?:unsafe\s+)?fn\s+\w+[^{};]*->\s*(?:\*\s*(?:mut|const)\b|"
            r"NonNull\s*<|AtomicPtr\s*<)",
            body,
        ):
            findings.append(
                "%s: NativeSession exposes an address-shaped observation" % rel
            )
    if rel == "driver/fsring-fsd/src/volume.rs":
        volume_impls = list(impl_bodies(text, "VolumeExtension"))
        mounted_impls = list(impl_bodies(text, "MountedVolumeExtension"))
        volume_methods = (
            top_level_methods(volume_impls[0]) if len(volume_impls) == 1 else []
        )
        normalized = [re.sub(r"\s+", "", header) for _name, header in volume_methods]
        if len(volume_impls) != 1 or normalized != [
            "pub(crate)unsafefnlocator_of(extension:*constSelf)->Option<SessionLocator>",
            "pub(crate)unsafefnpublish_locator(device:PDEVICE_OBJECT,locator:SessionLocator,)->Result<(),NTSTATUS>",
        ] or mounted_impls:
            findings.append(
                "%s: native volume extensions are outside their exact method roster" % rel
            )
    if rel in {
        "driver/fsring-fsd/src/lifecycle.rs",
        "driver/fsring-fsd/src/session.rs",
        "driver/fsring-fsd/src/volume.rs",
    }:
        allowed_free_headers = {
            "driver/fsring-fsd/src/lifecycle.rs": {
                "pub(crate)unsafefnclose_global_admissions(lock:&mutRegistryLockGuard,)->ClosedGlobalAdmissions",
                "pub(crate)unsafefnwait_process_callbacks_drained(closed:ProcessCallbackAdmissionClosed,)->ProcessCallbacksDrained",
                "pub(crate)unsafefnwait_setup_admission_drained(closed:SetupAdmissionClosed,)->SetupAdmissionDrained",
                "pub(crate)unsafefnwait_control_context_admission_drained(closed:ControlContextAdmissionClosed,)->ControlContextAdmissionDrained",
                "pub(crate)unsafefnclose_finalizer_admission(lock:&mutRegistryLockGuard,)->FinalizerAdmissionClosed",
                "pub(crate)unsafefnwait_finalizers_drained(full_pass:crate::fence::R3FinalizerFullPass,closed:FinalizerAdmissionClosed,)->FinalizerRundownDrained",
                "pub(crate)fnfinish_finalizers_drained(acknowledged:crate::fence::R3FinalizerAcknowledgedPass,rundown:FinalizerRundownDrained,)->FinalizersDrained",
                "pub(crate)unsafefnwait_blocked_unload_forever(registry:NonNull<KernelSessionRegistry>)->!",
                "pub(crate)unsafefnwait_process_scan_invariant_forever(registry:NonNull<KernelSessionRegistry>,)->!",
                "pub(crate)unsafefnacknowledge_completed_control(context:NonNull<ControlFileContext>,record:CompletedControlRecord,)->Result<(u64,TerminalResult),CompletedControlRecord>",
                "pub(crate)unsafefnbugcheck_direct_blocked_unload_without_slot_auth()->!",
                "#[allow(clippy::needless_lifetimes)]pub(crate)unsafefnprepare_native_terminal_claim<'objects>(lock:&'objectsmutRegistryLockGuard,context:NonNull<ControlFileContext>,locator:SessionLocator,request:TerminalRequest,)->Result<PreparedNativeTerminalClaim<'objects>,LifecycleError>",
                "pub(crate)unsafefnclaim_native_cleanup_route(registry:NonNull<KernelSessionRegistry>,context:NonNull<ControlFileContext>,request:TerminalRequest,)->Result<NativeCleanupRoute,NTSTATUS>",
                "pub(crate)unsafefnqueue_cell_finalizer(admitted:AdmittedR3FinalizerKick)",
                "pub(crate)unsafeexternfnfsring_finalizer_callback(_device:PDEVICE_OBJECT,context:*mutcore::ffi::c_void,)",
                "pub(crate)unsafefnstore_completed_record(context:NonNull<ControlFileContext>,closing:ClosingControlOwner,generation:u64,result:TerminalResult,)->bool",
                "pub(crate)unsafefnsignal_terminal_outcome(registry:NonNull<KernelSessionRegistry>,signal:fsring_core::session::TerminalOutcomeSignal,)",
                "pub(crate)unsafefnsignal_joiners_drained(registry:NonNull<KernelSessionRegistry>,signal:fsring_core::session::TerminalJoinersDrainedSignal,)",
                "pub(crate)unsafefnwait_joiners_drained(registry:NonNull<KernelSessionRegistry>,locator:SessionLocator,)",
                "unsafefnwait_protocol_join_visibility(registry:NonNull<KernelSessionRegistry>,locator:SessionLocator,mutlock:RegistryLockGuard,join:fsring_core::adapter::lifecycle::CommittedProtocolJoin,)->TerminalVisibilityResolution",
                "pub(crate)unsafefncomplete_cell_access_rundown(registry:NonNull<KernelSessionRegistry>,locator:SessionLocator,)",
                "pub(crate)unsafefnreinitialize_cell_access_rundown(registry:NonNull<KernelSessionRegistry>,locator:SessionLocator,)",
                "pub(crate)unsafefnreset_cell_and_publish(registry:NonNull<KernelSessionRegistry>,pending:fsring_core::adapter::fence::PendingFinalDeleteReset<crate::fence::PreparedCellResetRight,>,)->fsring_core::adapter::fence::FinalDeleteProof",
                "pub(crate)unsafefnwait_mount_observation(registry:NonNull<KernelSessionRegistry>,observation:MountWaitObservation,)->bool",
                "pub(crate)unsafefnpublish_mount_complete_locked(prepared:PreparedLockedMountPublication<'_,MountDonePublication>,)->Result<MountDrainRight,(LifecycleError,MountDoneAcknowledgement)>",
                "pub(crate)unsafefnpublish_mount_waiters_drained_locked(prepared:PreparedLockedMountPublication<'_,MountJoinConversion>,)->Result<MountResetJoinTicket,(LifecycleError,MountJoinAcknowledgement)>",
                "pub(crate)unsafefnpublish_mount_reset_complete_locked(prepared:PreparedLockedMountPublication<'_,MountResetPublication>,)->Result<MountResetProof,(LifecycleError,MountResetAcknowledgement)>",
                "pub(crate)unsafefnpublish_mount_reset_waiters_drained_locked(prepared:PreparedLockedMountPublication<'_,MountResetJoinRelease>,)->Result<JoinedMountResetProof,(LifecycleError,MountResetJoinAcknowledgement)>",
            },
            "driver/fsring-fsd/src/session.rs": {
                "pub(crate)unsafefnexecute_setup(driver:&mutDRIVER_OBJECT,state:*mutDriverState,control:NonNull<crate::control::ControlFileContext>,system_buffer:*mutu8,input_length:usize,output_length:usize,requestor:PEPROCESS,)->Result<usize,NTSTATUS>",
                "pub(crate)unsafefnfree_session_shell_allocation(session:*mutNativeSession)",
                "pub(crate)unsafefnperform_checkpoint_effect(session:*mutNativeSession,effect:fsring_core::adapter::fence::CheckpointFenceEffect,)->Option<bool>",
                "pub(crate)unsafefncheckpoint_close_session_admission(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_signal_existing_enter_waiters(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_wait_existing_sq_cq_roles_and_consumers(session:*mutNativeSession,)->bool",
                # The R4 drain's SQ-only twin of the row above. Separate rather
                # than a change to it: the R3 roster asks `cq_owner.is_none()`
                # where nothing holds a consumer, and the R4 drain runs while
                # this fence holds every one of them.
                "pub(crate)unsafefncheckpoint_wait_sq_roles_with_consumers_held(session:*mutNativeSession,)->bool",
                "pub(crate)unsafefncheckpoint_remove_producer_mappings_reverse(session:*mutNativeSession,)->bool",
                "pub(crate)unsafefncheckpoint_wait_producer_and_mapping_capture_rundown(session:*mutNativeSession,)->bool",
                "pub(crate)unsafefncheckpoint_retire_existing_grant_and_credit_state(session:*mutNativeSession,)->bool",
                "pub(crate)unsafefncheckpoint_release_read_only_mappings_reverse(session:*mutNativeSession,)->bool",
                "pub(crate)unsafefncheckpoint_release_mdls_and_system_view(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_release_captured_process(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_release_transient_arrays_and_backing(session:*mutNativeSession,)->bool",
                "pub(crate)unsafefncheckpoint_deposit_pending_fence_wakes(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_acquire_consumers_increasing(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_release_consumers(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_queue_installed_work(session:*mutNativeSession)->bool",
                "pub(crate)unsafefncheckpoint_wait_pending_and_owners(session:*mutNativeSession)->bool",
                "pub(crate)unsafefndelete_vdo_once(session:*mutNativeSession)->bool",
                "pub(crate)unsafefnfence_acquire_cq_consumer_at(session:*mutNativeSession,ring_index:u32,)->Result<fsring_core::enter::CqConsumerToken,()>",
                "pub(crate)unsafefnfence_release_cq_consumer_at(session:*mutNativeSession,ring_index:u32,token:fsring_core::enter::CqConsumerToken,)->Result<(),fsring_core::enter::CqConsumerToken>",
                "pub(crate)unsafefnbind_fence_consumer_slab(session:*mutNativeSession,set:fsring_core::session::SessionRingSetBrand,)->Result<fsring_core::adapter::fence::ConsumerTokenSlabOwner,fsring_core::adapter::fence::FenceError,>",
            },
            "driver/fsring-fsd/src/volume.rs": {
                "pub(crate)fnvolume_name(mount_id:MountId)->Option<[u16;VOLUME_NAME_UNITS]>",
                "pub(crate)unsafefncreate_staging(driver:&mutDRIVER_OBJECT,state:*mutDriverState,mount_id:MountId,)->Result<PDEVICE_OBJECT,NTSTATUS>",
                "pub(crate)unsafefnclear_initializing(device:PDEVICE_OBJECT)",
                "pub(crate)unsafefndelete(device:PDEVICE_OBJECT)",
                "pub(crate)unsafefnroute_by_kind(kind:DeviceKind,device:PDEVICE_OBJECT,irp:PIRP,major:u8,minor_or_ioctl:u32,root_open:bool,)->NTSTATUS",
            },
        }[rel]
        allowed_raw_free = {
            ("mount_event_ptr", "*mutKEVENT"),
            ("mount_vpb", "Option<*mutwdk_sys::VPB>"),
            ("master_base", "PVOID"),
        }
        shaped_aliases = address_aliases(text)
        for name, header in top_level_methods(text):
            compact = re.sub(r"\s+", "", header)
            if compact.startswith("pub(crate)") and compact not in allowed_free_headers:
                findings.append(
                    "%s: crate-visible free function `%s` is outside the exact native API roster"
                    % (rel, name)
                )
            if "->" not in compact:
                continue
            returned = compact.rsplit("->", 1)[1]
            returned = re.sub(r"\br#([A-Za-z_]\w*)", r"\1", returned)
            returned_base = re.match(
                r"(?:::)?(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)",
                returned,
            )
            protected_context = re.search(
                r"\b(?:KernelSessionRegistry|NativeSessionCell|RegistryLockGuard|TerminalWork|"
                r"SessionAccessGuard|NativeSession|NativeRingSlot|"
                r"NativeRingGuard|NativeRingState|LockedEnterState)\b",
                compact.rsplit("->", 1)[0],
            ) is not None
            address_shaped = (
                re.search(r"(?:\*mut|\*const|&|\bNonNull<|\bAtomicPtr<)", returned) is not None
                or (returned == "usize" and protected_context)
                or "NativeRingState" in returned
                or "LockedEnterState" in returned
                or "NativeSession" in returned
                or "KSPIN_LOCK" in returned
                or (returned_base is not None and returned_base.group(1) in shaped_aliases)
            )
            if (
                address_shaped
                and compact not in allowed_free_headers
                and (name, returned) not in allowed_raw_free
            ):
                findings.append(
                    "%s: free function `%s` exposes native shell/ring address authority"
                    % (rel, name)
                )
    ring_impls = list(impl_bodies(text, "NativeRingGuard"))
    for body in ring_impls:
        if re.search(
            r"\bfn\s+\w+[^{};]*->\s*(?:LockedEnterState\b|&\s*mut\s+RingEnterState\b)",
            body,
        ):
            findings.append(
                "%s: NativeRingGuard exposes an arbitrary ENTER projection" % rel
            )
        if re.search(r"\b(?:KeWait\w*|wait\w*)\s*\(", body):
            findings.append("%s: NativeRingGuard waits while its spin lock is held" % rel)
    ring_impl_text = "\n".join(ring_impls)
    if ring_impls:
        ring_methods = (
            top_level_methods(ring_impls[0]) if len(ring_impls) == 1 else []
        )
        normalized = [re.sub(r"\s+", "", header) for _name, header in ring_methods]
        if len(ring_impls) != 1 or normalized != [
            "pub(crate)constfnring_index(&self)->u32",
            "pub(crate)constfnlocator(&self)->SessionLocator",
            "pub(crate)fnclassify_cq(&self,observation:fsring_core::enter::CqObservation,grants:&fsring_core::grant::GrantTable<'_>,)->fsring_core::enter::DrainPlan",
            "pub(crate)fnacquire_role(&mutself,invocation:u64,role:fsring_core::enter::EnterRole,)->Result<fsring_core::enter::RoleLease,fsring_core::enter::EnterError>",
            "pub(crate)unsafefnrelease_held_role(&mutself,lease:fsring_core::enter::RoleLease,)->Result<(),(fsring_core::enter::EnterError,fsring_core::enter::RoleLease,),>",
            "#[allow(clippy::result_large_err)]pub(crate)fnrelease_pending<'g>(&mutself,pending:fsring_core::adapter::enter::PendingRoleRelease<'g>,)->Result<fsring_core::adapter::enter::EnterProgress<'g>,(fsring_core::enter::EnterError,fsring_core::adapter::enter::PendingRoleRelease<'g>,),>",
            "#[allow(clippy::result_large_err)]pub(crate)fnrelease_rollback(&mutself,pending:fsring_core::adapter::enter::PendingRollbackRoleRelease,)->Result<fsring_core::adapter::enter::EnterRollbackProgress,(fsring_core::enter::EnterError,fsring_core::adapter::enter::PendingRollbackRoleRelease,),>",
            "pub(crate)fnrelease(self)",
        ]:
            findings.append(
                "%s: NativeRingGuard is outside its exact fixed-operation signature roster"
                % rel
            )
    raw_release_count = len(re.findall(r"\bfn\s+release\b", ring_impl_text))
    release_bodies = re.findall(
        r"\bpub\(crate\)\s+fn\s+release\s*\(\s*self\s*\)\s*\{([^{}]*)\}",
        ring_impl_text,
    )
    declares_guard = re.search(r"\bstruct\s+NativeRingGuard\b", text) is not None
    drop_bodies = list(trait_impl_bodies(text, "Drop", "NativeRingGuard"))
    raw_drop_count = len(
        re.findall(r"\bimpl\s+Drop\s+for\s+NativeRingGuard\b", text)
    )
    ring_shape_present = declares_guard or bool(ring_impls) or raw_drop_count != 0
    if ring_shape_present:
        if raw_release_count != 1 or len(release_bodies) != 1 or release_bodies[0].strip():
            findings.append(
                "%s: NativeRingGuard must have exactly one empty consuming release method"
                % rel
            )
        if (
            raw_drop_count != 1
            or len(drop_bodies) != 1
            or not ring_drop_body_is_closed(drop_bodies[0])
        ):
            findings.append(
                "%s: NativeRingGuard Drop is outside the closed saved-IRQL release grammar"
                % rel
            )
    return findings


LOCK_RING_ACQUIRE = re.compile(
    r"let\s+Ok\s*\(\s*mut\s+(\w+)\s*\)\s*=\s*"
    r"[^;{}]*?\.lock_ring\s*\([^;{}]*\)\s*else\s*\{[^{}]*\}\s*;",
    re.DOTALL,
)
RUST_IDENTIFIER = r"[A-Za-z_]\w*"


def enclosing_block_end(text, position):
    """End offset of the innermost brace block containing `position`."""
    stack = []
    for index, char in enumerate(text[:position]):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            stack.pop()
    if not stack:
        return len(text)
    depth = 0
    for index in range(stack[-1], len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def fixed_ring_transition_end(text, start, end, guard):
    """End offset of the one production-owned transition, or ``None``."""
    receiver = re.escape(guard)
    result = RUST_IDENTIFIER
    argument = RUST_IDENTIFIER
    patterns = (
        r"\s*let\s+%s\s*=\s*%s\.release_pending\s*\(\s*%s\s*\)\s*;"
        % (result, receiver, argument),
        r"\s*let\s+%s\s*=\s*%s\.release_rollback\s*\(\s*%s\s*\)\s*;"
        % (result, receiver, argument),
        r"\s*let\s+%s\s*=\s*%s\.acquire_role\s*\(\s*"
        r"next_invocation\s*\(\s*\)\s*,\s*%s\s*\)\s*;"
        % (result, receiver, argument),
    )
    scope = text[start:end]
    for pattern in patterns:
        transition = re.match(pattern, scope)
        if transition is not None:
            return start + transition.end()
    return None


def direct_drop_offset(text, start, end, guard):
    """Offset of a drop directly following the fixed transition."""
    pattern = (
        r"\s*(?P<drop>crate::lifecycle::NativeRingGuard::release\s*\(\s*"
        + re.escape(guard)
        + r"\s*\)\s*;)"
    )
    drop = re.match(pattern, text[start:end])
    return None if drop is None else start + drop.start("drop")


def ring_callsite_findings(text, rel):
    """Audit the full lexical lifetime of every native ring-lock guard."""
    findings = []
    raw_count = len(re.findall(r"\.lock_ring\s*\(", text))
    acquisitions = list(LOCK_RING_ACQUIRE.finditer(text))
    match_locks = len(re.findall(r"match\s+[^{;]*\.lock_ring\s*\(", text))
    drain_match = (
        rel.endswith("session.rs")
        and raw_count == 4
        and len(acquisitions) == 3
        and match_locks == 1
    )
    if len(acquisitions) != raw_count and not drain_match:
        findings.append(
            "%s: parsed %d of %d lock_ring acquisitions"
            % (rel, len(acquisitions), raw_count)
        )
    for acquisition in acquisitions:
        guard = acquisition.group(1)
        block_end = enclosing_block_end(text, acquisition.end())
        transition_end = fixed_ring_transition_end(
            text, acquisition.end(), block_end, guard
        )
        if transition_end is None:
            findings.append(
                "%s: `%s` live scope is outside the closed transition grammar"
                % (rel, guard)
            )
            continue
        drop_offset = direct_drop_offset(text, transition_end, block_end, guard)
        if drop_offset is None:
            findings.append(
                "%s: `%s` has no explicit drop before its lexical scope ends"
                % (rel, guard)
            )
            continue
    return findings


# The one documented exception, encoded exactly rather than waived.
#
# `NativeSessionCell` keeps a *nonowning mirror* of the shell so a locked reader
# can reach it without a second lookup; the authentic owner is `shell_owner`,
# deposited by the publication suffix. The exception is therefore not "this
# carrier may hold pointers" but "this carrier may hold exactly one field, named
# `session`, of exactly `*mut NativeSession`". A second pointer, a different
# name, or a `NonNull`/`AtomicPtr` shape is still a finding — which is what keeps
# the waiver from becoming a hole.
MIRROR_EXCEPTION = {
    "NativeSessionCell": ("session", re.compile(r"session[ ]*:[ ]*\*[ ]*mut[ ]+NativeSession")),
}


def fsd_resolve_census_findings(sources):
    """Require the full fsd file roster and the exact four `resolve` roles."""
    findings = []
    observed_files = set(sources)
    expected_files = set(FSD_RESOLVE_CONTEXTS)
    for rel in sorted(expected_files - observed_files):
        findings.append("fsd resolve census is missing `%s`" % rel)
    for rel in sorted(observed_files - expected_files):
        findings.append("fsd resolve census has unowned Rust source `%s`" % rel)
    for rel in sorted(expected_files & observed_files):
        canonical = re.sub(r"\br#([A-Za-z_]\w*)", r"\1", sources[rel])
        compact = re.sub(r"\s+", "", canonical)
        expected = FSD_RESOLVE_CONTEXTS[rel]
        exact_contexts = all(compact.count(context) == 1 for context in expected)
        resolve_tokens = len(re.findall(r"\bresolve\b", canonical))
        if not exact_contexts or resolve_tokens != len(expected):
            findings.append(
                "%s: resolve tokens are outside the exact global acquisition roster" % rel
            )
    return findings


def fsd_native_capability_census_findings(sources):
    """Own every live-cell projection and the one affine terminal exception."""
    findings = []
    expected_files = set(FSD_NATIVE_CAPABILITY_REFERENCES)
    if set(sources) != expected_files:
        findings.append("fsd native capability census does not own the exact 14-file roster")
        return findings
    for rel in sorted(expected_files):
        canonical = re.sub(r"\br#([A-Za-z_]\w*)", r"\1", sources[rel])
        expected = FSD_NATIVE_CAPABILITY_REFERENCES[rel]
        observed = {
            name: len(re.findall(r"\b" + re.escape(name) + r"\b", canonical))
            for name in expected
        }
        if observed != expected:
            findings.append(
                "%s: native cell projection references are outside the exact global roster"
                % rel
            )
    fence_source = sources.get("driver/fsring-fsd/src/fence.rs", "")
    checkpoint_teardowns = list(
        function_bodies(strip_noncode(fence_source), "run_kernel_fence")
    )
    if (
        len(checkpoint_teardowns) != 1
        or _task12_digest(re.sub(r"\s+", "", checkpoint_teardowns[0]))
        != "50899e224b92fd942cc597dc69ab8f79598b64cf3936eeb35b054f930725f47c"
    ):
        findings.append(
            "driver/fsring-fsd/src/fence.rs: checkpoint teardown owner-live body is outside its exact grammar"
        )
    terminal_winners = list(
        function_bodies(strip_noncode(fence_source), "run_terminal")
    )
    if (
        len(terminal_winners) != 1
        or _task12_digest(re.sub(r"\s+", "", terminal_winners[0]))
        != FENCE_TERMINAL_WINNER_DIGEST
    ):
        findings.append(
            "driver/fsring-fsd/src/fence.rs: terminal winner owner-live body is outside its exact grammar"
        )
    fence = re.sub(r"\s+", "", fence_source)
    if "into_checkpoint_parts_with_locked_mirror" in fence:
        findings.append(
            "driver/fsring-fsd/src/fence.rs: retired terminal mirror callsite remains"
        )
    for rel in sorted(expected_files):
        canonical = strip_noncode(sources[rel])
        expected_owners = FSD_REGISTRY_PROJECTION_OWNERS[rel]
        observed_owners = []
        observed_bodies = []
        for name, body in function_items(canonical):
            compact = re.sub(r"\s+", "", body)
            counts = tuple(
                len(re.findall(r"\b" + re.escape(projection) + r"\s*\(", compact))
                for projection in REGISTRY_PROJECTION_NAMES
            )
            if any(counts):
                observed_owners.append((name,) + counts)
                observed_bodies.append((name, compact))
        replaced_bodies = TASK12_REPLACED_PROJECTION_BODIES.get(rel, set())
        expected_bodies = tuple(
            item
            for item in FSD_REGISTRY_PROJECTION_FUNCTION_BODIES.get(rel, ())
            if item[0] not in replaced_bodies
        )
        observed_closed_bodies = tuple(
            item for item in observed_bodies if item[0] not in replaced_bodies
        )
        expected_tokens = tuple(
            sum(owner[index + 1] for owner in expected_owners)
            + (1 if rel == "driver/fsring-fsd/src/lifecycle.rs" else 0)
            for index in range(len(REGISTRY_PROJECTION_NAMES))
        )
        observed_tokens = tuple(
            len(re.findall(r"\b" + re.escape(projection) + r"\b", canonical))
            for projection in REGISTRY_PROJECTION_NAMES
        )
        if (
            tuple(observed_owners) != expected_owners
            or observed_tokens != expected_tokens
            or observed_closed_bodies != expected_bodies
        ):
            findings.append(
                "%s: registry cell projection references are outside the exact owner/call/control/body grammar"
                % rel
            )
        if re.search(
            r"\bwork\s*:\s*(?:crate\s*::\s*lifecycle\s*::\s*)?TerminalWork\b"
            r".{0,800}\bwork\s*\.\s*into_parts\s*\(",
            canonical,
            flags=re.DOTALL,
        ):
            findings.append(
                "%s: terminal owner split bypasses the affine locked mirror capability"
                % rel
            )
    return findings


def _task12_digest(body):
    """Digest one already-balanced, whitespace-normalized Rust body."""
    if body is None:
        return None
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def task6_unload_findings(production, evidence=None):
    """Freeze the exact R3 unload ledger introduced by closure Task 6."""
    findings = []

    def require(condition, label, detail):
        if evidence is not None:
            evidence.append("driver/fsring-fsd/src/lifecycle.rs:task6-unload-" + label)
        if not condition:
            findings.append(detail)

    required = (
        set(TASK6_UNLOAD_ITEM_GRAMMAR)
        | set(TASK6_UNLOAD_IMPL_GRAMMAR)
        | set(TASK6_UNLOAD_BODY_GRAMMAR)
    )
    require(
        required <= set(production),
        "required-files",
        "Task 6 unload protected file roster is incomplete",
    )

    for rel, expected in TASK6_UNLOAD_ITEM_GRAMMAR.items():
        names = {name for _kind, name, _header, _digest in expected}
        actual = tuple(
            (kind, name, header, _task12_digest(body))
            for kind, name, header, body in top_level_named_items(
                production.get(rel, "")
            )
            if name in names
        )
        require(
            actual == expected,
            "item-roster-" + rel,
            "Task 6 unload capability/item grammar",
        )

    for rel, expected in TASK6_UNLOAD_IMPL_GRAMMAR.items():
        markers = tuple(header for header, _digest in expected)
        actual = tuple(
            (header, _task12_digest(re.sub(r"\s+", "", body)))
            for header, body in impl_items(production.get(rel, ""))
            if header in markers
        )
        require(
            actual == expected,
            "impl-roster-" + rel,
            "Task 6 unload exact implementation closure",
        )

    for rel, expected in TASK6_UNLOAD_BODY_GRAMMAR.items():
        for name, digest, detail in expected:
            actual = tuple(
                _task12_digest(re.sub(r"\s+", "", body))
                for body in function_bodies(production.get(rel, ""), name)
            )
            require(
                actual == (digest,),
                "body-%s-%s" % (rel, name),
                detail,
            )

    core_load = production.get("driver/fsring-core/src/adapter/load.rs", "")
    driver = production.get("driver/fsring-fsd/src/driver.rs", "")
    fence = production.get("driver/fsring-fsd/src/fence.rs", "")
    lifecycle = production.get("driver/fsring-fsd/src/lifecycle.rs", "")

    def exact_enum_variants(source, enum_name):
        bodies = tuple(body for name, body in enum_bodies(source) if name == enum_name)
        if len(bodies) != 1:
            return ()
        variants = []
        for fragment in _split_top_level(bodies[0]):
            match = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?([A-Z][A-Za-z0-9_]*)", fragment)
            if match is not None:
                variants.append(match.group(1))
        return tuple(variants)

    require(
        exact_enum_variants(core_load, "UnloadEffect") == TASK6_UNLOAD_EFFECTS,
        "exact-16-effects",
        "Task 6 exact 16-effect unload ledger",
    )
    require(
        exact_enum_variants(core_load, "R3UnloadPredicate")
        == TASK6_UNLOAD_PREDICATES,
        "exact-31-predicate-enum",
        "Task 6 exact independent 31-predicate roster",
    )
    core_load_compact = re.sub(r"\s+", "", core_load)
    all_predicates = "pubconstALL:[Self;31]=[" + "".join(
        "Self::%s," % predicate for predicate in TASK6_UNLOAD_PREDICATES
    ) + "];"
    require(
        core_load_compact.count(all_predicates) == 1,
        "exact-31-predicate-all",
        "Task 6 exact independent 31-predicate mapping",
    )
    all_effects = "pubconstEFFECTS:[UnloadEffect;16]=[" + "".join(
        "UnloadEffect::%s," % effect for effect in TASK6_UNLOAD_EFFECTS
    ) + "];"
    require(
        core_load_compact.count(all_effects) == 1,
        "exact-16-effect-plan",
        "Task 6 exact production 16-effect order",
    )

    native_predicates = TASK6_UNLOAD_PREDICATES[0:1] + TASK6_UNLOAD_PREDICATES[6:14] + TASK6_UNLOAD_PREDICATES[16:24]
    receipt_predicates = (
        "ProcessCallbackAdmissionClosed", "ProcessCallbacksDrained",
        "SetupAdmissionClosed", "SetupAdmissionDrained", "SessionScanStableEmpty",
        "FinalizerAdmissionClosed", "FinalizersDrained",
        "ControlContextAdmissionClosed", "ControlContextAdmissionDrained",
        "ControlBindingsClosed", "CompletedControlRecordsAbsent",
        "CloseRightsAbsent", "ControlContextsAbsent", "SoleDriverRootReference",
    )
    native_ledgers_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(lifecycle, "prepare_r3_native_ledgers_clear")
    )
    prepared_impls = tuple(
        re.sub(r"\s+", "", body)
        for header, body in impl_items(driver)
        if header == "implPreparedUnloadDestruction"
    )
    native_ledgers_body = native_ledgers_bodies[0] if len(native_ledgers_bodies) == 1 else ""
    prepared_body = prepared_impls[0] if len(prepared_impls) == 1 else ""
    native_observation_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(lifecycle, "observe_r3_unload_preflight")
    )
    native_observation = (
        native_observation_bodies[0] if len(native_observation_bodies) == 1 else ""
    )
    require(
        native_observation.count(
            "native_session_cells_empty&=cell.r3_unload_preflight_cell_is_empty();"
        ) == 1
        and "native_session_cells_empty&=cell.r3_unload_scan_is_exactly_empty();"
        not in native_observation,
        "independent-native-cell-predicate",
        "Task 6 native cell predicate is collapsed into the stable-scan aggregate",
    )
    require(
        tuple(
            predicate
            for predicate in native_predicates
            if native_ledgers_body.count("P::" + predicate) == 1
        ) == native_predicates
        and all(
            native_ledgers_body.count("P::" + predicate) == 0
            for predicate in receipt_predicates
        ),
        "native-17-predicate-mapping",
        "Task 6 sealed 17 native predicate mapping",
    )
    require(
        tuple(
            predicate
            for predicate in receipt_predicates
            if prepared_body.count("plan::R3UnloadPredicate::" + predicate) == 1
        ) == receipt_predicates,
        "typed-14-predicate-mapping",
        "Task 6 exact 14 typed-receipt predicate mapping",
    )
    require(
        len(native_predicates) == 17
        and len(receipt_predicates) == 14
        and set(native_predicates).isdisjoint(receipt_predicates)
        and set(native_predicates) | set(receipt_predicates)
        == set(TASK6_UNLOAD_PREDICATES),
        "predicate-partition",
        "Task 6 17-plus-14 predicate partition",
    )

    suffix_headers = tuple(
        header
        for header, _body in impl_items(driver)
        if header.startswith("implR3UnloadSuffix<")
    )
    require(
        suffix_headers
        == tuple("implR3UnloadSuffix<%d>" % effect for effect in range(10, 17)),
        "suffix-type-state-roster",
        "Task 6 private infallible effects 10-16 cursor",
    )
    suffix_methods = tuple(
        re.sub(r"\s+", "", method_header)
        for header, body in impl_items(driver)
        if header.startswith("implR3UnloadSuffix<")
        for _name, method_header in top_level_methods(body)
    )
    require(
        suffix_methods == (
            "unsafefnunregister_filesystem(self)->R3UnloadSuffix<11>",
            "unsafefndelete_fscontrol(self)->R3UnloadSuffix<12>",
            "unsafefnremove_provider_dos_link(self)->R3UnloadSuffix<13>",
            "unsafefndelete_provider(self)->R3UnloadSuffix<14>",
            "unsafefnrelease_boot_objects(self)->R3UnloadSuffix<15>",
            "unsafefnrelease_driver_state(self)->R3UnloadSuffix<16>",
            "unsafefnunregister_etw(self)",
        )
        and not any("Result<" in header or "Option<" in header for header in suffix_methods),
        "suffix-method-roster",
        "Task 6 effects 10-16 have no refusal or bypass surface",
    )
    # The destructive suffix order moved into core with the unload runner: fsd
    # now supplies one `R3UnloadNativeOps` method per effect and core sequences
    # them. Pin the order where it actually lives, threaded through the typed
    # stage values so effect N+1 is unreachable without effect N's receipt.
    require(
        re.sub(r"\s+", "", production.get("driver/fsring-core/src/adapter/load.rs", "")).count(
            "letfilesystem=unsafe{native.unregister_filesystem(prepared)};"
            "letfscontrol=unsafe{native.delete_fscontrol(filesystem)};"
            "letlink=unsafe{native.remove_provider_dos_link(fscontrol)};"
            "letprovider=unsafe{native.delete_provider(link)};"
            "letboot=unsafe{native.release_boot_objects(provider)};"
            "letstate=unsafe{native.release_driver_state(boot)};"
            "unsafe{native.unregister_etw(state)};"
        ) == 1,
        "suffix-call-chain",
        "Task 6 exact infallible suffix call order",
    )

    combined = "\n".join(production.values())
    require(
        re.search(r"\bR3UnloadProgress\s*<", combined) is None
        and re.search(r"\b(?:occupied_cell_count|run_terminal_for_unload|wait_for_terminal_outcome)\b", combined) is None,
        "no-shortcut-surface",
        "Task 6 no generic/aggregate/legacy unload scan bypass",
    )
    require(
        re.sub(r"\s+", "", lifecycle).count(
            "pub(crate)constSESSION_CELL_COUNT:usize=crate::platform::MOUNT_REGISTRY_CAPACITY;"
        ) == 1
        and re.sub(r"\s+", "", lifecycle).count(
            "const_:()=assert!(SESSION_CELL_COUNT==64);"
        ) == 1
        and fence.count("SESSION_CELL_COUNT") >= 4,
        "fixed-domain",
        "Task 6 fixed 64-cell unload domain",
    )
    drain_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(fence, "drain_r3_finalizers")
    )
    drain_body = drain_bodies[0] if len(drain_bodies) == 1 else ""
    require(
        drain_body.count("OrdinaryInFlight(receipt)") == 1
        and drain_body.count("wait_finalizers_drained(full_pass,closed)") == 1
        and drain_body.count("acknowledge_r3_finalizer_after_rundown(cursor)") == 1
        and drain_body.count("finish_finalizers_drained(acknowledged,rundown)") == 1,
        "two-pass-finalizer-drain",
        "Task 6 fixed 64-cell finalizer resolution and post-rundown ACK",
    )

    ordinary_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(
            lifecycle, "r3_finalizer_is_authenticated_ordinary_in_flight"
        )
    )
    ordinary = ordinary_bodies[0] if len(ordinary_bodies) == 1 else ""
    require(
        ordinary.count("TerminalRendezvousOutcome::Completed(_)") == 1
        and ordinary.count("FinalizerVisibilityHandoff::Ordinary(right)") == 1
        and ordinary.count("right.matches(locator)") == 1
        and ordinary.count("FinalizerVisibilityHandoff::Opaque{..}") == 1,
        "ordinary-completed-handoff-auth",
        "Task 6 Completed and exact Ordinary handoff authentication",
    )
    reset_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(lifecycle, "reset_after_delete")
    )
    ack_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(lifecycle, "acknowledge_r3_finalizer_after_rundown")
    )
    require(
        len(reset_bodies) == 1
        and reset_bodies[0].count("visibility_resolution") == 0
        and len(ack_bodies) == 1
        and ack_bodies[0].count("KeClearEvent") == 1
        and ack_bodies[0].count("r3_unload_scan_is_exactly_empty()") == 1,
        "visibility-latch-ack",
        "Task 6 ordinary visibility latch survives reset until locked ACK",
    )
    visibility_clear_owners = tuple(
        (name, body.count("KeClearEvent"), body.count("visibility_resolution"))
        for name, body in function_items(lifecycle)
        if "KeClearEvent" in body and "visibility_resolution" in body
    )
    require(
        visibility_clear_owners == (
            ("observe_r3_finalizer_for_drain", 1, 5),
            ("acknowledge_r3_finalizer_after_rundown", 1, 1),
            ("clear_terminal_generation_events", 3, 1),
        ),
        "visibility-clear-site-census",
        "Task 6 exact effect-seven ACK or next-Staging visibility clear sites",
    )

    require(
        len(re.findall(r"process_loss_handled\s*=\s*true", lifecycle)) == 1
        and len(re.findall(r"\.mark_process_loss_handled\s*\(", lifecycle)) == 1
        and len(re.findall(r"process_loss_handled\s*=\s*false", lifecycle)) == 3
        and len(re.findall(r"process_loss_handled\)\.write\(false\)", lifecycle)) == 1,
        "process-loss-marker-census",
        "Task 6 centralized per-generation process-loss marker",
    )
    require(
        re.sub(r"\s+", "", lifecycle).count(
            "#[unsafe(no_mangle)]pub(crate)unsafeexternfnfsring_finalizer_callback"
        ) == 1,
        "finalizer-callback-abi",
        "Task 6 finalizer callback ABI/root identity",
    )

    for needle, expected in TASK6_DESTRUCTIVE_CALLER_CENSUS:
        actual = tuple(
            sorted(
                (rel, name, count)
                for rel, source in production.items()
                for name, body in function_items(source)
                for count in (re.sub(r"\s+", "", body).count(needle),)
                if count
            )
        )
        require(
            actual == expected,
            "destructive-caller-census-" + re.sub(r"\W+", "-", needle).strip("-"),
            "Task 6 effects 10-16 destructive sink caller census",
        )

    # `DriverState::release` is safe and consequently does not appear in an
    # unsafe-token census. Freeze its three legitimate syntactic consumers,
    # and independently reject a new function taking DriverState that grows
    # any `.release()` call (including the review mutation `state.release()`).
    root_release_forms = (
        "(*state).release()",
        "unsafe{state.as_ref()}.release()",
        "unsafe{root.state.as_ref()}.release()",
    )
    root_release_callers = tuple(
        sorted(
            (rel, name, sum(body.count(form) for form in root_release_forms))
            for rel, source in production.items()
            for name, raw_body in function_items(source)
            for body in (re.sub(r"\s+", "", raw_body),)
            if any(form in body for form in root_release_forms)
        )
    )
    require(
        root_release_callers
        == (
            ("driver/fsring-fsd/src/driver.rs", "release_driver_state", 1),
            ("driver/fsring-fsd/src/lifecycle.rs", "destroy_shell_then_release_root", 1),
            ("driver/fsring-fsd/src/lifecycle.rs", "release_unpublished", 1),
        )
        and combined.count("DriverState::release(") == 0,
        "driver-state-release-owner-census",
        "Task 6 effect 15 DriverState release owner census",
    )
    typed_driver_state_release_callers = tuple(
        sorted(
            (rel, name, count)
            for rel, source in production.items()
            for name, header, raw_body in function_headers_and_bodies(source)
            if "DriverState" in re.sub(r"\s+", "", header)
            for count in (re.sub(r"\s+", "", raw_body).count(".release("),)
            if count
        )
    )
    require(
        typed_driver_state_release_callers == TASK6_DRIVER_STATE_RELEASE_CALLERS,
        "driver-state-typed-caller-census",
        "Task 6 effect 15 safe DriverState release bypass",
    )
    require(
        tuple(
            (name, len(re.findall(r"\b" + re.escape(name) + r"\b", combined)))
            for name, _expected in TASK6_DESTRUCTIVE_SYMBOL_CENSUS
        ) == TASK6_DESTRUCTIVE_SYMBOL_CENSUS,
        "destructive-symbol-census",
        "Task 6 effects 10-16 destructive symbol/import/macro census",
    )
    protected_destructive_names = {
        name for name, _expected in TASK6_DESTRUCTIVE_SYMBOL_CENSUS
    }
    require(
        re.search(r"\bextern\s*(?:\"[^\"]*\")?\s*\{", combined) is None
        and re.search(r"\blink_name\b", combined) is None,
        "foreign-destructive-binding-denial",
        "Task 6 alternate FFI/link_name destructive sink bypass",
    )
    require(
        not any(
            any(
                re.search(r"\b" + re.escape(name) + r"\b", declaration)
                for name in protected_destructive_names
            )
            for source in production.values()
            for declaration in alias_declarations(source)
        ),
        "destructive-alias-denial",
        "Task 6 effects 10-16 destructive sink/type alias bypass",
    )
    references_callers = tuple(
        sorted(
            (rel, name, count)
            for rel, source in production.items()
            for name, _header, body in function_headers_and_bodies(source)
            for count in (len(re.findall(r"\breferences\b", body)),)
            if count
        )
    )
    require(
        references_callers
        == (
            ("driver/fsring-fsd/src/driver.rs", "acquire", 1),
            ("driver/fsring-fsd/src/driver.rs", "initialize", 1),
            ("driver/fsring-fsd/src/driver.rs", "reference_count", 1),
            ("driver/fsring-fsd/src/driver.rs", "release", 1),
        ),
        "driver-state-reference-field-owner-census",
        "Task 6 effect 15 direct DriverState reference mutation bypass",
    )
    for method, expected in (
        ("acquire", TASK6_GLOBAL_ACQUIRE_CALLERS),
        ("release", TASK6_GLOBAL_RELEASE_CALLERS),
    ):
        pattern = re.compile(
            r"(?:\.|::)" + method + r"(?:\s*::\s*<[^>]*>)?\("
        )
        actual = []
        for rel, source in production.items():
            by_name = {}
            for name, body in function_items(source):
                by_name[name] = by_name.get(name, 0) + len(
                    pattern.findall(re.sub(r"\s+", "", body))
                )
            actual.extend(
                (rel, name, count)
                for name, count in sorted(by_name.items())
                if count
            )
        require(
            tuple(sorted(actual)) == expected,
            "global-%s-call-owner-census" % method,
            "Task 6 receiver-independent DriverState %s bypass" % method,
        )
    root_allocation_owners = {
        needle: tuple(
            sorted(
                (rel, name, count)
                for rel, source in production.items()
                for name, body in function_items(source)
                for count in (re.sub(r"\s+", "", body).count(needle),)
                if count
            )
        )
        for needle in ("fsring_driver_state", "allocation.take(", "core::ptr::drop_in_place(")
    }
    require(
        root_allocation_owners
        == {
            "fsring_driver_state": (
                ("driver/fsring-fsd/src/driver.rs", "finish", 1),
                ("driver/fsring-fsd/src/driver.rs", "release_driver_state", 1),
                ("driver/fsring-fsd/src/driver.rs", "root", 1),
            ),
            "allocation.take(": (
                ("driver/fsring-fsd/src/driver.rs", "initialize", 1),
                ("driver/fsring-fsd/src/driver.rs", "undo", 1),
                ("driver/fsring-fsd/src/driver.rs", "unregister_etw", 1),
            ),
            "core::ptr::drop_in_place(": (
                ("driver/fsring-fsd/src/driver.rs", "undo", 1),
                ("driver/fsring-fsd/src/driver.rs", "unregister_etw", 1),
                ("driver/fsring-fsd/src/session.rs", "free_any", 1),
                ("driver/fsring-fsd/src/session.rs", "free_session_shell_allocation", 1),
            ),
        },
        "root-allocation-owner-census",
        "Task 6 effects 15-16 root anchor/allocation owner census",
    )

    token_census = {
        rel: tuple(
            len(re.findall(r"\b" + re.escape(name) + r"\b", source))
            for name in TASK6_UNLOAD_TOKEN_NAMES
        )
        for rel, source in production.items()
    }
    token_census = {rel: counts for rel, counts in token_census.items() if any(counts)}
    require(
        token_census == TASK6_UNLOAD_TOKEN_CENSUS,
        "token-census",
        "Task 6 unload capability/caller census",
    )
    return findings


_TASK6_SELF_TEST_PRODUCTION = None


def _initialize_task6_self_test(production):
    global _TASK6_SELF_TEST_PRODUCTION
    _TASK6_SELF_TEST_PRODUCTION = production


def _run_task6_mutation_case(job):
    label, rel, mutated_source, expected = job
    mutated = dict(_TASK6_SELF_TEST_PRODUCTION)
    mutated[rel] = mutated_source
    findings = task6_unload_findings(mutated)
    if expected in findings:
        return None
    return "%s expected %r, got %r" % (label, expected, findings)


_SELF_TEST_WAVE_WIDTH = max(1, min(8, os.cpu_count() or 1))


def _run_task12_mutation_case(repo, job):
    """Plant one probe into a private tree and run the real production check.

    Each probe owns its own copy and its own subprocess, so the wave observes
    exactly what the serial form did: the shipped `--production-check` entry
    point reading a whole tree from disk, never an in-process shortcut that
    could agree with the auditor by construction.
    """
    label, rel, old, new, _expected, extra_edits = job
    anchor_failures = []
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-task12-") as work:
        for crate in ("fsring-core", "fsring-fsd"):
            shutil.copytree(
                os.path.join(repo, "driver", crate, "src"),
                os.path.join(work, "driver", crate, "src"),
            )
        for edit_rel, edit_old, edit_new in ((rel, old, new),) + tuple(extra_edits):
            path = os.path.join(work, edit_rel.replace("/", os.sep))
            with io.open(path, encoding="utf-8") as handle:
                source = handle.read()
            if source.count(edit_old) != 1:
                anchor_failures.append("%s probe anchor is not exact-one" % label)
            with io.open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(source.replace(edit_old, edit_new, 1))
        result = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    return anchor_failures, result.returncode, result.stdout, result.stderr


def task12_lifetime_findings(sources, evidence=None, raw_sources=None):
    """Freeze the complete cross-crate Task 12 affine lifetime grammar."""
    findings = []

    def require(condition, label, detail):
        if evidence is not None:
            evidence.append("driver/fsring-fsd/src/lifecycle.rs:task12-" + label)
        if not condition:
            findings.append(detail)

    def require_mount(condition, label, detail):
        if evidence is not None:
            evidence.append("driver/fsring-fsd/src/lifecycle.rs:task12-mount-" + label)
        if not condition:
            findings.append(detail)

    required = set(TASK12_ITEM_GRAMMAR) | set(TASK12_BODY_GRAMMAR)
    require(
        required <= set(sources),
        "required-files",
        "Task 12 protected file roster is incomplete",
    )
    production = {
        rel: source
        for rel, source in sources.items()
        if not rel.endswith("/tests.rs") and "/tests/" not in rel
    }
    findings.extend(task6_unload_findings(production, evidence))
    findings.extend(attach_scratch_findings(production, evidence))

    # Task 4's mount protocol is independently exact: item identities close
    # the private typed aggregate/trait, body digests close every transition,
    # and the global census rejects an appended legacy/raw helper.
    core_lifecycle_rel = "driver/fsring-core/src/adapter/lifecycle.rs"
    fsd_lifecycle_rel = "driver/fsring-fsd/src/lifecycle.rs"
    core_volume_rel = "driver/fsring-core/src/volume.rs"
    core_lifecycle_source = production.get(core_lifecycle_rel, "")
    fsd_lifecycle_source = production.get(fsd_lifecycle_rel, "")

    for rel, expected in TASK5_FAIL_STOP_ITEM_GRAMMAR.items():
        names = {name for _kind, name, _header, _digest in expected}
        actual = tuple(
            (kind, name, header, _task12_digest(body))
            for kind, name, header, body in top_level_named_items(
                production.get(rel, "")
            )
            if name in names
        )
        require(
            actual == expected,
            "durable-fail-stop-items-%s" % rel,
            "Task 5 exact durable fail-stop carrier/state grammar",
        )
    for rel, expected in TASK5_FAIL_STOP_IMPL_GRAMMAR.items():
        markers = tuple(header for header, _digest in expected)
        actual = tuple(
            (header, _task12_digest(re.sub(r"\s+", "", body)))
            for header, body in impl_items(production.get(rel, ""))
            if header in markers
        )
        require(
            actual == expected,
            "durable-fail-stop-impls-%s" % rel,
            "Task 5 exact durable fail-stop method closure",
        )
    for rel, grammar in TASK5_FAIL_STOP_BODY_GRAMMAR.items():
        for name, expected in grammar:
            actual = tuple(
                _task12_digest(re.sub(r"\s+", "", body))
                for body in function_bodies(production.get(rel, ""), name)
            )
            require(
                actual == expected,
                "durable-fail-stop-body-%s-%s" % (rel, name),
                "Task 5 exact durable fail-stop method closure",
            )

    fsd_fence_fail_stop = production.get("driver/fsring-fsd/src/fence.rs", "")
    fail_stop_combined = "\n".join(production.values())
    require(
        "visibility_context_key" not in fail_stop_combined,
        "durable-fail-stop-no-address-projection",
        "Task 5 fail-stop packet exposes a raw visibility address",
    )
    require(
        re.search(
            r"\b(?:R3FailStopSlot|PreparedDelete)\s*::\s*into_parts\s*\(",
            fail_stop_combined,
        ) is None
        and re.search(
            r"\bprepared\s*\.\s*into_parts\s*\(", fsd_fence_fail_stop
        ) is None,
        "durable-fail-stop-no-projection",
        "Task 5 durable packet or PreparedDelete payload is projected",
    )
    require(
        re.search(
            r"(?:mem::|core::mem::)?forget\s*\([^)]*(?:candidate|incomplete|fail_stop|packet|deposit)",
            fail_stop_combined,
        ) is None,
        "durable-fail-stop-no-forget",
        "Task 5 affine refusal packet or checkpoint candidate is forgotten",
    )
    require(
        fsd_fence_fail_stop.count(".store_ordinary_finalizer_handoff(") == 3
        and all(
            ".store_ordinary_finalizer_handoff(" not in source
            for rel, source in production.items()
            if rel != "driver/fsring-fsd/src/fence.rs"
        ),
        "ordinary-finalizer-handoff-caller-census",
        "Task 5 ordinary finalizer handoff caller census",
    )
    protected_bundle_names = (
        "MountOwnerPublication", "MountDonePublication", "MountJoinConversion",
        "MountResetPublication", "MountResetJoinRelease",
    )
    protected_bundle_aliases = tuple(
        (rel, declaration)
        for rel in sorted(production)
        for declaration in alias_declarations(production[rel])
        if (
            declaration.startswith("type ")
            and any(
                re.search(r"\b" + re.escape(name) + r"\b", declaration)
                for name in protected_bundle_names
            )
        ) or (
            declaration.startswith("use ")
            and any(
                target in protected_bundle_names
                for target in use_alias_targets(declaration)
            )
        )
    )
    require_mount(
        protected_bundle_aliases == (),
        "protected-bundle-alias-roster",
        "Task 12 locked mount bundle kind seal",
    )
    require_mount(
        tuple(
            (rel, header)
            for rel in sorted(production)
            for header in generic_trait_impl_headers(production[rel])
        ) == (
            (
                "driver/fsring-core/src/adapter/fence.rs",
                "impl<D: FenceKernelDdi> FenceNativeOps for KernelFenceOps<D>",
            ),
        ),
        "blanket-impl-roster",
        "Task 12 locked mount bundle kind seal",
    )
    require_mount(
        tuple(
            (rel, header)
            for rel in sorted(production)
            for header in generic_safe_fabricator_headers(production[rel], rel)
        ) == (),
        "generic-safe-fabricator-roster",
        "Task 12 locked mount bundle kind seal",
    )
    require_mount(
        tuple(
            (name, named_item_attributes(core_lifecycle_source, "struct", name))
            for name in protected_bundle_names
        ) == tuple(
            (name, ("#[derive(Debug)]",))
            for name in protected_bundle_names
        ),
        "bundle-attribute-roster",
        "Task 12 locked mount bundle kind seal",
    )
    require_mount(
        tuple(
            (name, header, _task12_digest(body))
            for name, header, body in top_level_inline_module_items(core_lifecycle_source)
        ) == (
            (
                "mount_publication_kind_seal",
                "modmount_publication_kind_seal",
                "981bfcb8db35d16529371fdf4f8937e7f55c7763d1d6da6873dd2606513893d4",
            ),
        ),
        "inline-module-roster",
        "Task 12 locked mount bundle kind seal",
    )

    mount_items = {
        (rel, name): (kind, header, _task12_digest(body))
        for rel in (core_lifecycle_rel, fsd_lifecycle_rel)
        for kind, name, header, body in top_level_named_items(production.get(rel, ""))
        if name in {
            "MountPublicationKind", "MountPublicationObservation",
            "PreparedLockedMountPublication", "LockedMountPublicationBundle",
            "MountOwnerPublication", "MountDonePublication", "MountJoinConversion", "MountResetPublication",
            "MountResetJoinRelease", "NativeMountedDeviceOwner", "NativeMountedVpbOwner",
            "PreparedNativeMountInstall", "NativeMountOwnerPublication", "NativeMountRendezvous",
        }
    }
    require_mount(
        mount_items == {
            (core_lifecycle_rel, "MountPublicationKind"): (
                "trait", "pubtraitMountPublicationKind:mount_publication_kind_seal::Sealed+Copy",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (core_lifecycle_rel, "MountPublicationObservation"): (
                "struct", "pubstructMountPublicationObservation<Kind:MountPublicationKind>",
                "27f05647f1542f1fe6393ed9f298329e3fbeafe459ee37e5b88e6247c9f93e79",
            ),
            (core_lifecycle_rel, "MountOwnerPublication"): (
                "struct", "pubstructMountOwnerPublication",
                "f53a70b10da4bc4688c31517b8c9d32fc5bc4c1171bf61a9011589c64985aebe",
            ),
            (core_lifecycle_rel, "MountDonePublication"): (
                "struct", "pubstructMountDonePublication",
                "3e64ff0b3a95c79f1df64a3e1895da3a7647579537a381fb4fcfdd7737270336",
            ),
            (core_lifecycle_rel, "MountJoinConversion"): (
                "struct", "pubstructMountJoinConversion",
                "fcac17345a045b98e2da39c488c48e4bed0e2477618a29486145544e0c57e4b4",
            ),
            (core_lifecycle_rel, "MountResetPublication"): (
                "struct", "pubstructMountResetPublication",
                "91ac246b527f0552d0c9154a24e19f5b779a90c893096033cfcf313674ef2435",
            ),
            (core_lifecycle_rel, "MountResetJoinRelease"): (
                "struct", "pubstructMountResetJoinRelease",
                "76be3c912861a60a204a9b379395eeab5cf8008c8ea9519b3541a646ca14daf3",
            ),
            (fsd_lifecycle_rel, "PreparedLockedMountPublication"): (
                "struct", "pub(crate)structPreparedLockedMountPublication<'lock,Bundle>",
                "da39fa9f2fdebcbfab3e8dd691eb4522b5305aad111bcf043f46e9490129c92d",
            ),
            (fsd_lifecycle_rel, "LockedMountPublicationBundle"): (
                "trait", "traitLockedMountPublicationBundle",
                "e4145446fbf49bf5839f487db4e9ddd5b7c1d4ec13e47c4142ad8654cc4a40ce",
            ),
            (fsd_lifecycle_rel, "NativeMountedDeviceOwner"): (
                "struct", "pub(crate)structNativeMountedDeviceOwner",
                "d7d8ec653b414fbc4201a74ed78a734642eaf6cc6b9bbfda382b22f3d93cb368",
            ),
            (fsd_lifecycle_rel, "NativeMountedVpbOwner"): (
                "struct", "pub(crate)structNativeMountedVpbOwner",
                "04fcc958f3834c63e3ac62b0cc75cc45274d27294055809e1bb99de583bc57be",
            ),
            (fsd_lifecycle_rel, "PreparedNativeMountInstall"): (
                "struct", "pub(crate)structPreparedNativeMountInstall",
                "3670bd5552226eba50217dac30b87f817c26d3e7edb5d80568f769794c3d9ea7",
            ),
            (fsd_lifecycle_rel, "NativeMountOwnerPublication"): (
                "struct", "pub(crate)structNativeMountOwnerPublication",
                "beb6107c43f5e5ba880c0b8f82e6c6eb1e0b051c26df20125d3cd63fbb5d240a",
            ),
            (fsd_lifecycle_rel, "NativeMountRendezvous"): (
                "struct", "pub(crate)structNativeMountRendezvous",
                "d5b3ffa96210f4e26586d97703cb769d83d4c1551493abfa5e7e9922a3384a39",
            ),
        },
        "typed-items",
        "Task 12 prepared locked mount publication aggregate",
    )
    mount_impls = tuple(
        (header, _task12_digest(re.sub(r"\s+", "", body)))
        for header, body in impl_items(fsd_lifecycle_source)
        if "LockedMountPublicationBundlefor" in header
    )
    require_mount(
        mount_impls == (
            ("implLockedMountPublicationBundleforMountDonePublication", "1ecf8968ad2556d44c1a46b11d528a71db27d8a9237683e63c9aa9bc3f345b49"),
            ("implLockedMountPublicationBundleforMountJoinConversion", "4e8f02bf2cf83c46061ac8f988c22647ef47157f168ea0c42a96326908fd58b9"),
            ("implLockedMountPublicationBundleforMountResetPublication", "baf9f3da1ce509676ec14cd0025d1c7e00f637b08aae663b3559c5a5cf61e22b"),
            ("implLockedMountPublicationBundleforMountResetJoinRelease", "6467c572f077e4afda2fd3d489fd5263673fe3a7f807262483b9d2b810b4e656"),
        ),
        "bundle-impls",
        "Task 12 locked mount bundle kind seal",
    )
    global_mount_impls = tuple(
        (rel, header, _task12_digest(re.sub(r"\s+", "", body)))
        for rel in sorted(production)
        for header, body in impl_items(production[rel])
        if any(
            re.search(
                r"(?:impl|for|::|\(|>|,)" + re.escape(type_name)
                + r"(?:<|\)|,|$)",
                header,
            )
            for type_name in protected_bundle_names + ("MountRendezvous",)
        )
    )
    require_mount(
        global_mount_impls == (
            (core_lifecycle_rel, "implMountOwnerPublication", "33a603e401d403d57b0de9e3f653a58e9c3158d3d13f93160bc7487621908cd1"),
            (core_lifecycle_rel, "implMountDonePublication", "bc5d5143f59b2e1fc1de7d15ac78cee7d8522aab90dca6a33258df113ba2a45d"),
            (core_lifecycle_rel, "implMountJoinConversion", "b834e0a1c36f898db030481e28ffe0225107c3a65dba5600c968e027d2135ab3"),
            (core_lifecycle_rel, "implMountResetPublication", "33b9ec7cd466e5cf71111a7e5d7b31931cd5958997f3bb06f09b541ed96649ff"),
            (core_lifecycle_rel, "implMountResetJoinRelease", "96022f21e6848d70fad14fbdc879409daa0db9e55247d0b6177f4fd92a27bd94"),
            (core_lifecycle_rel, "implMountDonePublication", "a89c915cc4d4df54fbde4d2063d6d5d1601c565407d9330883e32e5624985590"),
            (core_lifecycle_rel, "implMountJoinConversion", "d09c12f8537136451ab3d043c20aab5ab48d88e0b58ee5d7dc39be36125f44a1"),
            (core_lifecycle_rel, "implMountResetPublication", "5167011e436203d955c987b7e5b8676b275ab806ee714769d15f61ed8019ea29"),
            (core_lifecycle_rel, "implMountResetJoinRelease", "7442f04b51371a9f93b0428a710d8bfa9051b8f9cb819ea84b13c9418493bec5"),
            (core_lifecycle_rel, "impl<Device,Vpb>MountRendezvous<Device,Vpb>", "36ec54b785eeb5e19efef028d6efea978aa616ae325976f8ee6e58d3c202c6da"),
            (core_lifecycle_rel, "implFnOnce(&Device),)->Result<(),(LifecycleError,MountOwnerPublication)>", "e7a28a29696bef5e66925b4d12fe9b9a8cd76ebebacc5f9b9e63ce6a430729ce"),
            (fsd_lifecycle_rel, "implLockedMountPublicationBundleforMountDonePublication", "1ecf8968ad2556d44c1a46b11d528a71db27d8a9237683e63c9aa9bc3f345b49"),
            (fsd_lifecycle_rel, "implLockedMountPublicationBundleforMountJoinConversion", "4e8f02bf2cf83c46061ac8f988c22647ef47157f168ea0c42a96326908fd58b9"),
            (fsd_lifecycle_rel, "implLockedMountPublicationBundleforMountResetPublication", "baf9f3da1ce509676ec14cd0025d1c7e00f637b08aae663b3559c5a5cf61e22b"),
            (fsd_lifecycle_rel, "implLockedMountPublicationBundleforMountResetJoinRelease", "6467c572f077e4afda2fd3d489fd5263673fe3a7f807262483b9d2b810b4e656"),
        ),
        "global-bundle-impl-roster",
        "Task 12 locked mount bundle kind seal",
    )
    for rel, expected in TASK12_MOUNT_IMPL_GRAMMAR.items():
        protected_types = TASK12_MOUNT_IMPL_TYPES[rel]
        actual = tuple(
            (header, _task12_digest(re.sub(r"\s+", "", body)))
            for header, body in impl_items(production.get(rel, ""))
            if any(
                re.search(
                    r"(?:impl|for|::|\(|>|,)" + re.escape(type_name)
                    + r"(?:<|\)|,|$)",
                    header,
                )
                for type_name in protected_types
            )
        )
        require_mount(
            actual == expected,
            "complete-impl-roster-%s" % rel,
            "Task 12 locked mount bundle kind seal"
            if rel == core_lifecycle_rel
            else "Task 12 mount transitive implementation closure",
        )
    core_lifecycle_compact_mount = re.sub(r"\s+", "", core_lifecycle_source)
    require_mount(
        core_lifecycle_compact_mount.count(
            "modmount_publication_kind_seal{pub(super)constDONE:u8=0;"
            "pub(super)constJOIN_CONVERSION:u8=1;pub(super)constRESET:u8=2;"
            "pub(super)constRESET_JOIN_RELEASE:u8=3;pubtraitSealed{constKIND:u8;}}"
            "pubtraitMountPublicationKind:mount_publication_kind_seal::Sealed+Copy{}"
            "macro_rules!mount_publication_kinds{($($name:ident=>$kind:ident),+$(,)?)=>{"
            "$(#[derive(Clone,Copy,Debug,PartialEq,Eq)]pubenum$name{}"
            "implmount_publication_kind_seal::Sealedfor$name{"
            "constKIND:u8=mount_publication_kind_seal::$kind;}"
            "implMountPublicationKindfor$name{})+};}"
            "mount_publication_kinds!(MountDonePublicationKind=>DONE,"
            "MountJoinConversionKind=>JOIN_CONVERSION,MountResetPublicationKind=>RESET,"
            "MountResetJoinReleaseKind=>RESET_JOIN_RELEASE,);"
        ) == 1,
        "kind-macro",
        "Task 12 locked mount bundle kind seal",
    )
    core_mount_macros = tuple(
        (name, _task12_digest(re.sub(r"\s+", "", bodies[0])))
        for name in (
            "mount_generation_observers", "mount_completion_observers",
            "mount_publication_kinds", "mount_wait_observer",
        )
        if len(bodies := list(pattern_bodies(
            core_lifecycle_source,
            r"\bmacro_rules\s*!\s*" + re.escape(name) + r"\s*\{",
        ))) == 1
    )
    require_mount(
        core_mount_macros == (
            ("mount_generation_observers", "92209cf61108ba40e8de51056ab70b87b350a6721ea0b1f07265971cbb1af9b0"),
            ("mount_completion_observers", "6e3d4b2d1556ea443f5beb821609ca65df20fa67607e7f864821ca3f806c01fd"),
            ("mount_publication_kinds", "616ed2735d563446f48111eb96f9481a865fa52545b8d1172ee9925872795f15"),
            ("mount_wait_observer", "12e3d7ed34ee0a520832679cb4ab266976b2042022f2e74ab1e0478ada0e90ac"),
        ),
        "core-macro-roster",
        "Task 12 locked mount bundle kind seal",
    )
    mount_headers = tuple(
        (name, re.sub(r"\s+", "", header))
        for name, header in top_level_methods(fsd_lifecycle_source)
        if name in {
            "prepare_locked_mount_publication", "publish_mount_complete_locked",
            "publish_mount_waiters_drained_locked", "publish_mount_reset_complete_locked",
            "publish_mount_reset_waiters_drained_locked",
        }
    )
    require_mount(
        mount_headers[:1] == (
            ("prepare_locked_mount_publication", "#[allow(clippy::needless_lifetimes)]unsafefnprepare_locked_mount_publication<'lock,Bundle>(lock:&'lockmutRegistryLockGuard,bundle:Bundle,)->Result<PreparedLockedMountPublication<'lock,Bundle>,(LifecycleError,Bundle)>whereBundle:LockedMountPublicationBundle,"),
        ),
        "preparer-header",
        "Task 12 locked mount bundle kind seal",
    )
    require_mount(
        mount_headers[1:] == (
            ("publish_mount_complete_locked", "pub(crate)unsafefnpublish_mount_complete_locked(prepared:PreparedLockedMountPublication<'_,MountDonePublication>,)->Result<MountDrainRight,(LifecycleError,MountDoneAcknowledgement)>"),
            ("publish_mount_waiters_drained_locked", "pub(crate)unsafefnpublish_mount_waiters_drained_locked(prepared:PreparedLockedMountPublication<'_,MountJoinConversion>,)->Result<MountResetJoinTicket,(LifecycleError,MountJoinAcknowledgement)>"),
            ("publish_mount_reset_complete_locked", "pub(crate)unsafefnpublish_mount_reset_complete_locked(prepared:PreparedLockedMountPublication<'_,MountResetPublication>,)->Result<MountResetProof,(LifecycleError,MountResetAcknowledgement)>"),
            ("publish_mount_reset_waiters_drained_locked", "pub(crate)unsafefnpublish_mount_reset_waiters_drained_locked(prepared:PreparedLockedMountPublication<'_,MountResetJoinRelease>,)->Result<JoinedMountResetProof,(LifecycleError,MountResetJoinAcknowledgement)>"),
        ),
        "function-headers",
        "Task 12 prepared locked mount publication aggregate",
    )
    prepared_mount_bodies = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(fsd_lifecycle_source, "prepare_locked_mount_publication")
    )
    require_mount(
        len(prepared_mount_bodies) == 1
        and prepared_mount_bodies[0].count("bundle.publication_observation()") == 1
        and prepared_mount_bodies[0].count(
            "returnErr((LifecycleError::WrongLocator,bundle))"
        ) == 1
        and prepared_mount_bodies[0].count(
            "returnErr((LifecycleError::AdmissionClosed,bundle))"
        ) == 1,
        "same-bundle-refusal",
        "Task 12 locked mount bundle kind seal",
    )
    for rel, grammar in TASK12_MOUNT_BODY_GRAMMAR.items():
        for name, expected, detail in grammar:
            actual = tuple(
                _task12_digest(re.sub(r"\s+", "", body))
                for body in function_bodies(production.get(rel, ""), name)
            )
            require_mount(actual == expected, "body-%s-%s" % (rel, name), detail)
    mount_tokens = {
        rel: tuple(
            len(re.findall(r"\b" + re.escape(name) + r"\b", source))
            for name in TASK12_MOUNT_TOKEN_NAMES
        )
        for rel, source in production.items()
    }
    mount_tokens = {rel: counts for rel, counts in mount_tokens.items() if any(counts)}
    require_mount(
        mount_tokens == TASK12_MOUNT_TOKEN_CENSUS,
        "token-census",
        "Task 12 prepared locked mount publication aggregate",
    )
    unsafe_tokens = {
        rel: len(re.findall(r"\bunsafe\b", source))
        for rel, source in production.items()
    }
    unsafe_tokens = {rel: count for rel, count in unsafe_tokens.items() if count}
    require_mount(
        unsafe_tokens == TASK12_UNSAFE_TOKEN_CENSUS,
        "unsafe-token-census",
        "Task 12 locked mount bundle kind seal",
    )
    macro_definitions = tuple(
        (rel, name, delimiter, _task12_digest(body))
        for rel in sorted(production)
        for name, delimiter, body in macro_definition_items(production[rel])
    )
    require_mount(
        macro_definitions == TASK12_MACRO_DEFINITION_GRAMMAR,
        "macro-definition-roster",
        "Task 12 locked mount bundle kind seal",
    )
    macro_invocations = {
        rel: macro_invocation_census(source)
        for rel, source in production.items()
    }
    macro_invocations = {
        rel: census for rel, census in macro_invocations.items() if census
    }
    require_mount(
        macro_invocations == TASK12_MACRO_INVOCATION_CENSUS,
        "macro-invocation-roster",
        "Task 12 locked mount bundle kind seal",
    )
    # Round-16 E3. The sweep that replaced a line-number enumeration with one
    # keyed on enclosing functions -- and wrote, in the gate document, that line
    # numbers "decay on their own" -- planted twenty bare `:NNNN` citations into
    # driver comments in the same commit. At least fifteen were already wrong
    # when committed, shifted by that commit's own edits.
    #
    # Writing the rule down did not produce compliance with it, so it is a row.
    # The bare form is banned outright: it names no file, so it rots silently on
    # any edit above it and a reader cannot even tell which file to check. Cite
    # the enclosing function or type instead -- those move with the code.
    #
    # A qualified `file.rs:NNNN` is NOT banned here: it names its file. This
    # comment used to say "One exists tree-wide"; round-17 evidence E2 counted
    # five in driver Rust -- four in `fsring-core/src/size.rs` (three in
    # comments, one in a test's string) and one in `fsring-sys/src/lib.rs`,
    # outside this row's sources -- so the sentence was a population claim
    # nobody had measured. What `bare_line_citations` does and does not reach
    # is stated on the function.
    bare_citations = bare_line_citations(raw_sources or {})
    require_mount(
        not bare_citations,
        "no-bare-line-number-citations",
        "a driver comment cites a bare `:NNNN` line number, which names no file "
        "and is wrong as soon as anything above it moves: %s"
        % ", ".join(bare_citations[:6]),
    )
    mount_event_owners = tuple(
        name
        for name, body in function_items(fsd_lifecycle_source)
        if "KeSetEvent" in body
    )
    require_mount(
        mount_event_owners == (
            "signal_terminal_outcome", "signal_joiners_drained", "set_prepared_mount_event",
        ),
        "event-owner-roster",
        "Task 12 locked mount signal-then-ack window",
    )
    global_event_owners = tuple(
        (rel, name, body.count("KeSetEvent"))
        for rel in sorted(production)
        for name, body in function_items(production[rel])
        if "KeSetEvent" in body
    )
    require_mount(
        global_event_owners == (
            ("driver/fsring-fsd/src/boot.rs", "release_lock_event", 1),
            ("driver/fsring-fsd/src/control.rs", "fsring_dispatch_cleanup", 1),
            ("driver/fsring-fsd/src/fence.rs", "signal_visibility_resolution", 1),
            # Task 25 residual retry DPC: KeSetEvent is the DPC-exit signal after
            # the parked residual is queued, same shape as the pending-enter timer DPC.
            ("driver/fsring-fsd/src/fence.rs", "fsring_fence_retry_dpc", 1),
            ("driver/fsring-fsd/src/lifecycle.rs", "signal_terminal_outcome", 2),
            ("driver/fsring-fsd/src/lifecycle.rs", "signal_joiners_drained", 1),
            ("driver/fsring-fsd/src/lifecycle.rs", "set_prepared_mount_event", 1),
            # Task 18's timer DPC. Its one `KeSetEvent` is the exit signal, and
            # the `PendingDpcExitTicket` it consumes is the only authority for
            # it -- which is what makes "signalled last, after the owner is
            # released and Quiesced is published" structural rather than a
            # statement order this census would have to police.
            ("driver/fsring-fsd/src/pending_enter.rs", "fsring_pending_enter_timer_dpc", 1),
            ("driver/fsring-fsd/src/session.rs", "signal_pending_enter", 1),
            ("driver/fsring-fsd/src/session.rs", "perform", 1),
            ("driver/fsring-fsd/src/session.rs", "finish_setup_rollback", 1),
        ),
        "global-event-owner-roster",
        "Task 12 locked mount signal-then-ack window",
    )
    global_event_tokens = {
        rel: len(re.findall(r"\bKeSetEvent\b", source))
        for rel, source in production.items()
    }
    global_event_tokens = {
        rel: count for rel, count in global_event_tokens.items() if count
    }
    require_mount(
        global_event_tokens == {
            "driver/fsring-fsd/src/boot.rs": 1,
            "driver/fsring-fsd/src/control.rs": 1,
            "driver/fsring-fsd/src/fence.rs": 2,
            "driver/fsring-fsd/src/lib.rs": 1,
            "driver/fsring-fsd/src/lifecycle.rs": 4,
            "driver/fsring-fsd/src/pending_enter.rs": 2,
            "driver/fsring-fsd/src/session.rs": 3,
        },
        "global-event-token-census",
        "Task 12 locked mount signal-then-ack window",
    )
    locked_publisher_bodies = tuple(
        re.sub(r"\s+", "", body)
        for name in (
            "publish_mount_complete_locked", "publish_mount_waiters_drained_locked",
            "publish_mount_reset_complete_locked", "publish_mount_reset_waiters_drained_locked",
        )
        for body in function_bodies(fsd_lifecycle_source, name)
    )
    require_mount(
        len(locked_publisher_bodies) == 4
        and all(
            not any(raw in body for raw in (
                "cell_ptr(", "cell_mut(", "core_ptr(", "core_mut(", "slot_index()",
            ))
            for body in locked_publisher_bodies
        )
        and "signal_mount_complete_after_unlock" not in fsd_lifecycle_source
        and "signal_mount_waiters_drained_after_unlock" not in fsd_lifecycle_source
        and "signal_mount_reset_complete_after_unlock" not in fsd_lifecycle_source
        and "signal_mount_reset_waiters_drained_after_unlock" not in fsd_lifecycle_source,
        "no-raw-or-after-unlock-helper",
        "Task 12 prepared locked mount publication aggregate",
    )
    fsd_fence_mount = production.get("driver/fsring-fsd/src/fence.rs", "")
    owner_effect_functions = tuple(
        name for name, body in function_items(fsd_fence_mount)
        if any(token in re.sub(r"\s+", "", body) for token in (
            ".clear_binding()", "mounted.delete()", "self.release_mount_reference(reference)",
        ))
    )
    # The three take-once effects are performed by the ops impl that core's
    # `run_r3_mount_owner_teardown_prefix` drives, so the two ops methods appear
    # here beside their driver. Admitting them by name alone would be a real
    # weakening: this roster carries no location, so the generic spellings
    # `clear_vpb_binding`/`delete_mounted_device` would then be licensed in any
    # function in the file. Require instead that the impl is lexically NESTED
    # inside `complete_mount_owner` -- a nested impl cannot be named by any
    # other function, which closes the second-call-site hazard more tightly than
    # a flat roster, and keeps the locator/generation check and the fixed effect
    # order in core instead of restating them natively.
    owner_driver_bodies = [
        re.sub(r"\s+", "", body)
        for name, body in function_items(fsd_fence_mount)
        if name == "complete_mount_owner"
    ]
    require_mount(
        owner_effect_functions
        == ("complete_mount_owner", "clear_vpb_binding", "delete_mounted_device")
        and len(owner_driver_bodies) == 1
        and "R3MountOwnerTeardownOps" in owner_driver_bodies[0]
        and "fnclear_vpb_binding" in owner_driver_bodies[0]
        and "fndelete_mounted_device" in owner_driver_bodies[0]
        and "run_r3_mount_owner_teardown_prefix(" in owner_driver_bodies[0],
        "owner-effect-roster",
        "Task 12 mount-owned teardown owner-only",
    )
    shell_vdo_callers = tuple(
        name for name, body in function_items(fsd_fence_mount)
        if "self.delete_shell_vdo()" in re.sub(r"\s+", "", body)
    )
    require_mount(
        shell_vdo_callers == ("bind_mount_completion_and_delete_shell_vdo",),
        "vdo-caller-roster",
        "Task 12 shell VDO post-bind suffix",
    )

    core_volume = production.get(core_volume_rel, "")
    rollback_tokens = {
        rel: len(re.findall(r"\bMountRollbackEffect\b", source))
        for rel, source in production.items()
    }
    rollback_tokens = {
        rel: count for rel, count in rollback_tokens.items() if count
    }
    require_mount(
        rollback_tokens == TASK12_ROLLBACK_TOKEN_CENSUS,
        "rollback-token-census",
        "Task 12 exact mount rollback plan",
    )
    rollback_constants = tuple(
        (name, value)
        for name, value_type, value in top_level_const_items(core_volume)
        if value_type == "&[MountRollbackEffect]"
    )
    require_mount(
        rollback_constants == (
            ("ROLLBACK_NONE", "&[]"),
            ("ROLLBACK_INITIAL_VPB", "&[MountRollbackEffect::ReleaseVpbIfHeld]"),
            ("ROLLBACK_REFERENCE", "&[MountRollbackEffect::ReleaseSessionReference]"),
            ("ROLLBACK_DEVICE", "&[MountRollbackEffect::DeleteMountedDevice,MountRollbackEffect::ReleaseSessionReference,]"),
            ("ROLLBACK_VCB", "&[MountRollbackEffect::FreeVcb,MountRollbackEffect::DeleteMountedDevice,MountRollbackEffect::ReleaseSessionReference,]"),
            ("ROLLBACK_COMMIT_VPB", "&[MountRollbackEffect::ReleaseVpbIfHeld,MountRollbackEffect::FreeVcb,MountRollbackEffect::DeleteMountedDevice,MountRollbackEffect::ReleaseSessionReference,]"),
            ("ROLLBACK_BOUND_VPB", "&[MountRollbackEffect::ClearUnpublishedVpbBinding,MountRollbackEffect::ReleaseVpbIfHeld,MountRollbackEffect::FreeVcb,MountRollbackEffect::DeleteMountedDevice,MountRollbackEffect::ReleaseSessionReference,]"),
            ("ROLLBACK_BOUND_VPB_AFTER_RELEASE", "&[MountRollbackEffect::ClearUnpublishedVpbBinding,MountRollbackEffect::FreeVcb,MountRollbackEffect::DeleteMountedDevice,MountRollbackEffect::ReleaseSessionReference,]"),
        ),
        "rollback-roster",
        "Task 12 exact mount rollback plan",
    )

    # Production module identity must be ordinary Rust module resolution. A
    # path override or textual include can replace the item bodies after this
    # checker has inspected the canonical-looking file.
    source_shadow = any(
        re.search(r"#\s*\[\s*path\b", source)
        or re.search(r"\binclude\s*!\s*[({[]", source)
        for source in production.values()
    )
    require(
        not source_shadow,
        "source-shadow",
        "Task 12 production source shadow",
    )

    core_lifecycle = production.get("driver/fsring-core/src/adapter/lifecycle.rs", "")
    rewritten_owner = re.search(
        r"#\s*\[(?!\s*doc\b)[^]]+\]\s*pub\s+struct\s+NativeSessionOwner\b",
        core_lifecycle,
    ) is not None
    extra_macros = []
    for rel in TASK12_IMPL_GRAMMAR:
        extra_macros.extend(
            name
            for name in re.findall(
                r"\bmacro_rules\s*!\s*([A-Za-z_]\w*)",
                production.get(rel, ""),
            )
            if name != "private_authority_seals"
            and not (
                rel == "driver/fsring-core/src/adapter/lifecycle.rs"
                and name in {
                    "mount_generation_observers", "mount_completion_observers",
                    "mount_publication_kinds", "mount_wait_observer",
                }
            )
        )
    require(
        not rewritten_owner and not extra_macros,
        "attribute-macro",
        "Task 12 protected attribute or macro rewrite",
    )

    for rel, expected in TASK12_ITEM_GRAMMAR.items():
        source = production.get(rel, "")
        names = {name for _kind, name, _header, _digest in expected}
        actual = tuple(
            (kind, name, header, _task12_digest(body))
            for kind, name, header, body in top_level_named_items(source)
            if name in names
        )
        for index, item in enumerate(expected):
            kind, name, _header, _digest = item
            exact = index < len(actual) and actual[index] == item
            if name in {"NativeSessionOwner", "SessionRootReleaseRight"} and kind == "type":
                detail = "Task 12 protected alias"
            elif name == "R3FinalizerCell":
                detail = "Task 12 protected generic declaration"
            elif name in {"CellResetRight", "PreparedCellResetRight"}:
                detail = "Task 12 cell-reset locator brand"
            elif name == "TerminalRendezvousResetRight":
                detail = "Task 12 terminal-reset locator brand"
            elif name.startswith("FinalDelete") or name.startswith("Pending"):
                detail = "Task 12 final-delete cursor/reset bundle"
            elif name == "FinalizerWorkItemContext":
                detail = "Task 12 finalizer queue boundary"
            else:
                detail = "Task 12 protected authority surface"
            require(exact, "item-%s-%s" % (kind, name), detail)
        require(
            actual == expected,
            "item-roster-%s" % rel,
            "Task 12 protected generic declaration",
        )

    for rel, expected in TASK12_IMPL_GRAMMAR.items():
        actual = tuple(
            (header, _task12_digest(re.sub(r"\s+", "", body)))
            for header, body in impl_items(production.get(rel, ""))
            if any(marker in header for marker in TASK12_IMPL_MARKERS)
        )
        detail = (
            "Task 12 protected authority surface"
            if rel.endswith("adapter/lifecycle.rs")
            else "Task 12 final-delete cursor/reset bundle"
        )
        require(actual == expected, "impl-roster-%s" % rel, detail)

    for rel, grammar in TASK12_BODY_GRAMMAR.items():
        source = production.get(rel, "")
        for name, expected, detail in grammar:
            actual = tuple(
                hashlib.sha256(re.sub(r"\s+", "", body).encode("utf-8")).hexdigest()
                for body in function_bodies(source, name)
            )
            require(actual == expected, "body-%s-%s" % (rel, name), detail)

    observed_tokens = {
        rel: tuple(
            len(re.findall(r"\b" + re.escape(name) + r"\b", source))
            for name in TASK12_TOKEN_NAMES
        )
        for rel, source in production.items()
    }
    observed_tokens = {
        rel: counts for rel, counts in observed_tokens.items() if any(counts)
    }
    require(
        observed_tokens == TASK12_TOKEN_CENSUS,
        "affine-token-census",
        "Task 12 sole native-owner consumer",
    )
    require(
        observed_tokens.get("driver/fsring-fsd/src/fence.rs")
        == TASK12_TOKEN_CENSUS["driver/fsring-fsd/src/fence.rs"],
        "nested-consumer",
        "Task 12 nested production consumer",
    )
    require(
        # 9, not 8: the finalizer cell resolver now takes a cell-lookup closure,
        # and its `-> Option<(R3FinalizerDeposit<Owners>, R3FinalizerRunningRight)>`
        # signature is the ninth mention. The type does not exist at HEAD at all,
        # so 8 was captured from an intermediate state of this same tree.
        observed_tokens.get("driver/fsring-core/src/adapter/fence.rs", (0,) * 12)[3] == 9,
        "running-brand-census",
        "Task 12 running-locator reset brand",
    )
    require(
        observed_tokens.get("driver/fsring-core/src/session.rs", (0,) * 12)[5] == 1,
        "terminal-reset-census",
        "Task 12 terminal-reset locator brand",
    )

    # The unsafe payload bridge has exactly one FSD implementation, and its
    # complete impl body is already frozen above. Trait bounds on core storage
    # are not implementations and are intentionally excluded here.
    payload_impls = tuple(
        (rel, header, _task12_digest(re.sub(r"\s+", "", body)))
        for rel, source in sorted(production.items())
        for header, body in impl_items(source)
        if header.startswith("unsafeimpl")
        and "PreparedDeleteStorageOps" in header
        and "for" in header
    )
    require(
        payload_impls == ((
            "driver/fsring-fsd/src/lifecycle.rs",
            "unsafeimplfsring_core::adapter::fence::PreparedDeleteStorageOps<DriverRootRelease>forNativeSessionShell",
            "bbbdb210e82e5c134a9995a9b0768da2729c4548560acfb91411bc03ec700b56",
        ),),
        "payload-impl",
        "Task 12 sole prepared-delete payload impl",
    )

    for rel, expected in TASK12_SEAM_TOKEN_CENSUS.items():
        source = production.get(rel, "")
        actual = tuple(
            len(re.findall(r"\b" + re.escape(name) + r"\b", source))
            for name in TASK12_SEAM_TOKEN_NAMES
        )
        mismatched = {
            index for index, (seen, wanted) in enumerate(zip(actual, expected))
            if seen != wanted
        }
        require(
            not (mismatched & {0}),
            "closing-live-census-%s" % rel,
            "Task 12 exact ClosingLive and owned lease",
        )
        require(
            not (mismatched & {1, 2}),
            "completed-slot-census-%s" % rel,
            "Task 12 completed-slot observation",
        )
        require(
            not (mismatched & {3}),
            "admission-census-%s" % rel,
            "Task 12 open join admission observation",
        )
        require(
            not (mismatched & {4, 5}),
            "event-census-%s" % rel,
            "Task 12 terminal-event observation",
        )
        require(
            not (mismatched & {6, 7, 8}),
            "core-delete-census-%s" % rel,
            "Task 12 authentic core-delete observation order",
        )
        require(
            not (mismatched & {9, 10, 11}),
            "exact-cell-census-%s" % rel,
            "Task 12 exact-cell finalizer callback",
        )
        require(
            not (mismatched & {12}),
            "blocked-observation-census-%s" % rel,
            "Task 12 blocked observation authority",
        )
        require(
            not (mismatched & {13}),
            "queue-boundary-census-%s" % rel,
            "Task 12 finalizer queue boundary",
        )

    fsd_fence = production.get("driver/fsring-fsd/src/fence.rs", "")
    reset_authority_structs = tuple(
        name
        for _kind, name, _header, body in top_level_named_items(fsd_fence)
        if body is not None and "PrivateCellResetAuthority" in body
    )
    require(
        reset_authority_structs == ("CellResetRight",),
        "cell-reset-authority",
        "Task 12 cell-reset locator brand",
    )

    # Any rundown DDI/helper reached after acquiring the registry spin lock
    # must have a consuming release between the acquire and that call.
    rundown_under_lock = False
    callback_close_under_lock = False
    for source in production.values():
        for _name, body in function_items(source):
            compact = re.sub(r"\s+", "", body)
            for call in re.finditer(
                r"(?:ExRundownCompleted|ExReInitializeRundownProtection)\s*\(", compact
            ):
                lock = compact.rfind("KernelSessionRegistry::lock(", 0, call.start())
                if lock >= 0 and compact.find(".release()", lock, call.start()) < 0:
                    rundown_under_lock = True
            for call in re.finditer(r"close_process_callback_admission\s*\(", compact):
                lock = compact.rfind("KernelSessionRegistry::lock(", 0, call.start())
                if lock >= 0 and compact.find(".release()", lock, call.start()) < 0:
                    callback_close_under_lock = True
    require(
        not rundown_under_lock,
        "rundown-irql",
        "Task 12 rundown DDI IRQL boundary",
    )
    require(
        not callback_close_under_lock,
        "callback-rundown-irql",
        "Task 12 process-callback rundown IRQL boundary",
    )

    # WDK requires a drain wait before a rundown is marked completed.  Audit
    # every production function that reaches this permanent admission object,
    # not merely the canonical helper: an appended/nested helper must not be
    # able to restore the reversed ordering behind an unchanged exact body.
    process_callback_completion_bodies = []
    for source in production.values():
        for _name, body in function_items(source):
            compact = re.sub(r"\s+", "", body)
            if (
                "process_callback_admission" not in compact
                or "ExRundownCompleted(" not in compact
            ):
                continue
            process_callback_completion_bodies.append(compact)
    process_callback_order_is_closed = len(process_callback_completion_bodies) == 1
    if process_callback_order_is_closed:
        callback_body = process_callback_completion_bodies[0]
        wait_call = "ExWaitForRundownProtectionRelease(rundown)"
        completed_call = "ExRundownCompleted(rundown)"
        process_callback_order_is_closed = (
            callback_body.count(wait_call) == 1
            and callback_body.count(completed_call) == 1
            and callback_body.find(wait_call) < callback_body.find(completed_call)
        )
    require(
        process_callback_order_is_closed,
        "callback-rundown-wait-order",
        "Task 12 process-callback wait-before-completed order",
    )

    delete_observations = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(
            production.get("driver/fsring-fsd/src/lifecycle.rs", ""),
            "delete_preflight_observation",
        )
    )
    require(
        len(delete_observations) == 1
        and "outcome_open_and_admission_open:outcome_is_open&&outcome_event_is_nonsignaled"
        "&&admitted_joiners>0&&admitted_joiners<u32::MAX" in delete_observations[0],
        "join-admission-bounds",
        "Task 12 open join admission observation",
    )

    fsd_lifecycle_compact = re.sub(
        r"\s+", "", production.get("driver/fsring-fsd/src/lifecycle.rs", "")
    )
    reset_header = (
        "pub(crate)unsafefnreset_cell_and_publish("
        "registry:NonNull<KernelSessionRegistry>,"
        "pending:fsring_core::adapter::fence::PendingFinalDeleteReset<"
        "crate::fence::PreparedCellResetRight,>,)"
        "->fsring_core::adapter::fence::FinalDeleteProof{"
    )
    require(
        fsd_lifecycle_compact.count(reset_header) == 1,
        "prepared-cell-reset-generic",
        "Task 12 final-delete cursor/reset bundle",
    )

    delete_wrappers = tuple(
        re.sub(r"\s+", "", body)
        for body in function_bodies(
            production.get("driver/fsring-fsd/src/fence.rs", ""),
            "execute_prepared_delete",
        )
    )
    prepared_delete_impls = tuple(
        body
        for header, body in impl_items(
            production.get("driver/fsring-fsd/src/fence.rs", "")
        )
        if header == "implPreparedDelete"
    )
    prepared_delete_suffixes = tuple(
        re.sub(r"\s+", "", method)
        for body in prepared_delete_impls
        for method in function_bodies(body, "execute")
    )
    no_post_destroy_assertion = (
        delete_wrappers == ("unsafe{prepared.execute(registry)};",)
        and len(prepared_delete_suffixes) == 1
    )
    if no_post_destroy_assertion:
        suffix = prepared_delete_suffixes[0]
        # The ten-step destructive suffix moved into core, so the native
        # anchor is now the call that hands the storage to it rather than the
        # old `storage.execute()`. The property is unchanged: nothing may
        # observe, assert on, or branch off the generation after the
        # destructive step. Core's own ordering inside the suffix stays pinned
        # by its own body digest, pinned in TASK12_BODY_GRAMMAR.
        execute = suffix.find("run_r3_prepared_delete_suffix(")
        post_destroy = suffix[execute:]
        no_post_destroy_assertion = (
            execute >= 0
            and re.search(
                r"(?:debug_assert|assert)(?:_eq|_ne)?!|\breturn\b|\bErr\s*\(|\?",
                post_destroy,
            ) is None
        )
    require(
        no_post_destroy_assertion,
        "post-destroy-access",
        "Task 12 no post-destroy access",
    )

    combined = "\n".join(production.values())
    require(
        re.search(r"(?:mem::|core::mem::)?forget\s*\(\s*kick\s*\)", combined) is None,
        "sole-kick-sink",
        "Task 12 sole production finalizer kick sink",
    )
    return findings


def canonical_source_roots(root, source_roots):
    """Resolved, repository-relative source roots with duplicate detection."""
    root_path = os.path.normcase(os.path.realpath(os.path.abspath(root)))
    canonical = []
    for source_root in source_roots:
        candidate = (
            source_root
            if os.path.isabs(source_root)
            else os.path.join(root_path, source_root.replace("/", os.sep))
        )
        resolved = os.path.normcase(os.path.realpath(os.path.abspath(candidate)))
        try:
            inside = os.path.commonpath((root_path, resolved)) == root_path
        except ValueError:
            inside = False
        if not inside:
            raise LifetimeAuditError("source root escapes repository: %s" % source_root)
        canonical.append(os.path.relpath(resolved, root_path).replace(os.sep, "/"))
    if len(set(canonical)) != len(canonical):
        raise LifetimeAuditError("source roots contain a duplicate resolved identity")
    return tuple(canonical)


def audit_tree(
    root, source_roots, evidence=None, native_files_seen=None, pending_shapes_seen=None
):
    """Every carrier field that stores a session pointer."""
    findings = []
    audited = set()
    fsd_sources = {}
    task12_sources = {}
    task12_raw_sources = {}
    canonical_roots = canonical_source_roots(root, source_roots)
    enforce_fsd_resolve_census = (
        native_files_seen is not None and "driver/fsring-fsd/src" in canonical_roots
    )
    enforce_task12 = (
        native_files_seen is not None
        and set(canonical_roots)
        == {"driver/fsring-core/src", "driver/fsring-fsd/src"}
    )
    for source_root in canonical_roots:
        base = os.path.join(root, source_root.replace("/", os.sep))
        if not os.path.isdir(base):
            raise LifetimeAuditError("source root does not exist: %s" % source_root)
        for directory, _subdirectories, files in os.walk(base):
            for name in sorted(files):
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                if native_files_seen is not None and rel in NATIVE_OWNER_FILES:
                    native_files_seen.add(rel)
                with io.open(path, encoding="utf-8") as handle:
                    raw_text = handle.read()
                text = strip_noncode(raw_text)
                if enforce_fsd_resolve_census and rel.startswith("driver/fsring-fsd/src/"):
                    fsd_sources[rel] = text
                if enforce_task12:
                    task12_sources[rel] = text
                    # RAW, not stripped: the bare-line-citation row below reads
                    # comments, and `strip_noncode` deletes them. A check handed
                    # the stripped text sees no comment at all and passes over
                    # every file -- which is exactly what it did on its first run.
                    task12_raw_sources[rel] = raw_text
                shaped_aliases = address_aliases(text)
                findings.extend(guard_api_findings(text, rel))
                findings.extend(ring_callsite_findings(text, rel))
                findings.extend(native_contract_findings(text, rel, evidence))
                for struct, body in struct_bodies(text):
                    frozen_shape = PENDING_SHAPE_BODIES.get((rel, struct))
                    if frozen_shape is not None:
                        # Deliberately NOT added to `audited`: that set is the
                        # locator-only carrier census, and reporting a staged
                        # shape there would inflate a count other checks read.
                        if pending_shapes_seen is not None:
                            pending_shapes_seen.add((rel, struct))
                        evidence.append(
                            "%s:pending-shape-%s" % (rel, struct.lower())
                        )
                        if re.sub(r"\s+", "", body) != frozen_shape:
                            findings.append(
                                "%s: %s is outside its exact staged pending field "
                                "grammar; the result backing is out of line and "
                                "no field may be added, retyped, or reordered"
                                % (rel, struct)
                            )
                    if struct not in CARRIERS:
                        continue
                    audited.add(struct)
                    expected_body = CARRIER_BODIES.get((rel, struct))
                    if (
                        expected_body is not None
                        and re.sub(r"\s+", "", body) != expected_body
                    ):
                        findings.append(
                            "%s: %s is outside its exact locator-only field grammar"
                            % (rel, struct)
                        )
                    allowance = MIRROR_EXCEPTION.get(struct)
                    hits = [
                        found.group(0).strip()
                        for shape in POINTER_SHAPES
                        for found in shape.finditer(body)
                    ]
                    if expected_body is None:
                        hits.extend(
                            found.group(0).strip()
                            for alias in shaped_aliases
                            for found in re.finditer(
                                r"\b[A-Za-z_]\w*\s*:\s*" + re.escape(alias) + r"\b",
                                body,
                            )
                        )
                    if allowance is not None:
                        field, pattern = allowance
                        mirrors = pattern.findall(body)
                        # The waiver is exactly one field, of exactly one shape,
                        # under exactly one name. Anything else -- a second
                        # pointer, a NonNull, an AtomicPtr, or a differently
                        # named field -- is still a finding, which is what keeps
                        # a documented exception from becoming a hole.
                        if len(mirrors) == 1 and len(hits) == 1:
                            continue
                        if len(mirrors) > 1:
                            findings.append(
                                "%s: %s stores %d `%s` mirrors; exactly one is permitted"
                                % (rel, struct, len(mirrors), field)
                            )
                            continue
                    for hit in hits:
                        findings.append(
                            "%s: %s stores %s -- %s" % (rel, struct, hit, CARRIERS[struct])
                        )

    if enforce_fsd_resolve_census:
        findings.extend(fsd_resolve_census_findings(fsd_sources))
        findings.extend(fsd_native_capability_census_findings(fsd_sources))
        if evidence is not None:
            evidence.append(
                "driver/fsring-fsd/src/lifecycle.rs:global-resolve-acquisition-roster"
            )
            evidence.append(
                "driver/fsring-fsd/src/lifecycle.rs:global-native-capability-roster"
            )
    if enforce_task12:
        findings.extend(
            task12_lifetime_findings(task12_sources, evidence, task12_raw_sources)
        )

    return findings, audited


TASK27_LIFETIME_CASES = (
    "raw/NonNull/AtomicPtr NativeSession in control binding",
    "raw session pointer in registry entry, VDO, or mounted extension",
    "process-loss dereference before claim",
    "locator projection before access-rundown acquire",
    "missing slot/generation/identity/Live recheck",
    "missing rundown release on a reject path",
    "second permanent-cell owning pointer",
    "inline session free outside setup rollback/finalizer",
)


def self_test(fail_fast=False, skip_task12_wave=False):
    """Plant each forbidden shape and require the audit to name it.

    Every case drives `audit_tree`, the same function the real run calls, so a
    deleted shape or a weakened struct walk fails here rather than passing
    quietly.
    """
    checks = 0
    failures = []
    reported_lifetime = set()

    def check(condition, detail):
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(detail)
            if fail_fast:
                print("FAIL: %s" % detail)
                print(
                    "audit_c4_lifetime self-test: FAIL (%d checks, %d failures)"
                    % (checks, len(failures))
                )
                raise SystemExit(1)

    def check_named(name, condition, detail):
        reported_lifetime.add(name)
        check(condition, "%s: %s" % (name, detail))

    clean = "pub struct ControlFileContext {\n    locator: SessionLocator,\n}\n"
    for shape in (
        "*mut NativeSession",
        "*const NativeSession",
        "NonNull<NativeSession>",
        "AtomicPtr<NativeSession>",
        "*mut core::ffi::c_void",
        "AtomicPtr<core::ffi::c_void>",
    ):
        planted = "pub struct ControlFileContext {\n    session: %s,\n}\n" % shape
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, audited = audit_tree(work, ["src"])
        check(len(findings) == 1, "%s must be one finding, got %r" % (shape, findings))
        check(
            "ControlFileContext" in audited,
            "%s must mark the carrier audited" % shape,
        )
    planted = (
        "type ShellPtr = *mut NativeSession;\n"
        "pub struct ControlFileContext { session: ShellPtr }\n"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
        src = os.path.join(work, "src")
        os.makedirs(src)
        with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
            handle.write(planted)
        findings, audited = audit_tree(work, ["src"])
    check(len(findings) == 1, "an aliased carrier pointer must be one finding, got %r" % findings)
    check("ControlFileContext" in audited, "an aliased carrier pointer must audit its carrier")
    planted = (
        "struct ShellPtr(*mut NativeSession);\n"
        "pub(crate) struct NativeSessionCell { session: ShellPtr }\n"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
        path = os.path.join(work, "driver", "fsring-fsd", "src")
        os.makedirs(path)
        with io.open(os.path.join(path, "lifecycle.rs"), "w", encoding="utf-8") as handle:
            handle.write(planted)
        findings, _ = audit_tree(work, ["driver/fsring-fsd/src"])
    check(
        any("exact locator-only field grammar" in finding for finding in findings),
        "a newtype-wrapped carrier pointer must fail the closed field grammar, got %r"
        % findings,
    )

    # Every carrier, not just the first: a walk that stopped at one struct would
    # pass the loop above and miss the other four.
    # Every carrier except the one with a documented mirror exception, which a block
    # covers separately. Scoping the loop rather than loosening its assertion
    # keeps its claim exact: for these, a stored session pointer is always a finding.
    for carrier in (name for name in CARRIERS if name not in MIRROR_EXCEPTION):
        planted = "pub struct %s {\n    session: *mut NativeSession,\n}\n" % carrier
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, audited = audit_tree(work, ["src"])
        check(len(findings) == 1, "%s must be audited, got %r" % (carrier, findings))

    # A clean carrier passes, so the checks above are about the pointer and not
    # about the carrier name appearing at all.
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
        src = os.path.join(work, "src")
        os.makedirs(src)
        with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
            handle.write(clean)
        findings, _ = audit_tree(work, ["src"])
    check(not findings, "a locator-only carrier must pass, got %r" % (findings,))

    # A pointer in a *local* is the access rundown working as designed, and a
    # pointer in a struct this audit does not carry is out of scope. Both must
    # pass, or the audit would forbid the design it exists to protect.
    for allowed in (
        "fn project(cell: &Cell) -> *mut NativeSession {\n    cell.session\n}\n",
        "struct SomethingElse {\n    session: *mut NativeSession,\n}\n",
    ):
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(allowed)
            findings, _ = audit_tree(work, ["src"])
        check(not findings, "in-scope-only: %r must pass, got %r" % (allowed, findings))

    # Prose and `#[cfg(test)]` fixtures are not stored pointers.
    for benign, expected_carrier in (
        ('pub struct ControlFileContext {\n    // session: *mut NativeSession, retired in Task 8\n}\n', True),
        ('pub struct ControlFileContext {\n    doc: &\'static str,\n}\nconst D: &str = "session: *mut NativeSession";\n', True),
        (
            "#[cfg(test)]\nmod tests {\n"
            "    struct ControlFileContext { session: *mut NativeSession }\n"
            "}\n",
            False,
        ),
        (
            "#[cfg(test)]\nmod tests;\n"
            "pub struct ControlFileContext { session_id: u64 }\n",
            True,
        ),
    ):
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(benign)
            findings, audited = audit_tree(work, ["src"])
        check(
            not findings
            and (("ControlFileContext" in audited) == expected_carrier),
            "benign/parser case must pass and retain later production items, got %r/%r for %r"
            % (findings, audited, benign),
        )

    # The mirror exception is exactly one field, not a waiver for the carrier.
    cell = 'pub struct NativeSessionCell {' + NEWLINE
    for planted, expect_finding in (
        (cell + '    session: *mut NativeSession,' + NEWLINE + '}' + NEWLINE, False),
        (
            cell
            + '    session: *mut NativeSession,' + NEWLINE
            + '    spare: *mut NativeSession,' + NEWLINE
            + '}' + NEWLINE,
            True,
        ),
        (cell + '    mirror: NonNull<NativeSession>,' + NEWLINE + '}' + NEWLINE, True),
        (cell + '    session: AtomicPtr<NativeSession>,' + NEWLINE + '}' + NEWLINE, True),
    ):
        with tempfile.TemporaryDirectory(prefix='c4-lifetime-') as work:
            src = os.path.join(work, 'src')
            os.makedirs(src)
            with io.open(os.path.join(src, 'a.rs'), 'w', encoding='utf-8') as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ['src'])
        check(
            bool(findings) == expect_finding,
            'mirror exception: %r expected finding=%s, got %r'
            % (planted, expect_finding, findings),
        )

    # The short access/ring guards are APIs, not long-lived carrier fields.
    # Their negative fixtures still drive the production audit so an exposed
    # raw shell getter, arbitrary ENTER projection, or wait under a ring lock
    # cannot pass merely because the carrier scan is clean.
    closed_ring_release = (
        "impl NativeRingGuard<'_, '_> {\n"
        "    pub(crate) fn release(self) {}\n"
        "}\n"
    )
    closed_ring_drop = (
        "impl Drop for NativeRingGuard<'_, '_> {\n"
        "    fn drop(&mut self) {\n"
        "        if let Some(saved) = self.old_irql.take() {\n"
        "            saved.release_with(|old_irql| unsafe {\n"
        "                self.slot.release_lock(old_irql)\n"
        "            });\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    for label, planted in (
        (
            "raw access getter",
            "impl SessionAccessGuard<'_> {\n"
            "    pub unsafe fn session_ptr(&self) -> *mut NativeSession { loop {} }\n"
            "}\n",
        ),
        (
            "arbitrary ring projection",
            "impl NativeRingGuard<'_, '_> {\n"
            "    pub unsafe fn enter_state(&mut self) -> LockedEnterState<'_> { loop {} }\n"
            "}\n",
        ),
        (
            "ring wait",
            "impl NativeRingGuard<'_, '_> {\n"
            "    pub fn release_role(&mut self) { KeWaitForSingleObject(); }\n"
            "}\n",
        ),
        (
            "nonempty consuming ring release",
            "impl NativeRingGuard<'_, '_> {\n"
            "    pub(crate) fn release(self) { hidden_wait!(); }\n"
            "}\n"
            + closed_ring_drop,
        ),
        (
            "attributed consuming ring release",
            "impl NativeRingGuard<'_, '_> {\n"
            "    #[inject_wait]\n"
            "    pub(crate) fn release(self) {}\n"
            "}\n"
            + closed_ring_drop,
        ),
        (
            "nested-attribute consuming ring release",
            "impl NativeRingGuard<'_, '_> {\n"
            "    #[inject_wait([])]\n"
            "    pub(crate) fn release(self) {}\n"
            "}\n"
            + closed_ring_drop,
        ),
        (
            "malformed consuming-ring attribute",
            "impl NativeRingGuard<'_, '_> {\n"
            "    #[inject_wait(\n"
            "    pub(crate) fn release(self) {}\n"
            "}\n"
            + closed_ring_drop,
        ),
        (
            "completion in ring drop",
            "impl NativeRingGuard<'_, '_> { pub(crate) fn release(self) {} }\n"
            "impl Drop for NativeRingGuard<'_, '_> {\n"
            "    fn drop(&mut self) { complete_irp(); }\n"
            "}\n",
        ),
        (
            "terminal macro in ring drop",
            "impl NativeRingGuard<'_, '_> { pub(crate) fn release(self) {} }\n"
            "impl Drop for NativeRingGuard<'_, '_> {\n"
            "    fn drop(&mut self) { terminal_work!(); }\n"
            "}\n",
        ),
        (
            "ring drop omits saved IRQL release",
            "impl NativeRingGuard<'_, '_> { pub(crate) fn release(self) {} }\n"
            "impl Drop for NativeRingGuard<'_, '_> { fn drop(&mut self) {} }\n",
        ),
        (
            "ring drop returns before releasing",
            "impl NativeRingGuard<'_, '_> { pub(crate) fn release(self) {} }\n"
            "impl Drop for NativeRingGuard<'_, '_> {\n"
            "    fn drop(&mut self) { return; }\n"
            "}\n",
        ),
        (
            "ring drop panic macro",
            "impl NativeRingGuard<'_, '_> { pub(crate) fn release(self) {} }\n"
            "impl Drop for NativeRingGuard<'_, '_> {\n"
            "    fn drop(&mut self) { panic!(); }\n"
            "}\n",
        ),
        (
            "missing ring Drop implementation",
            closed_ring_release,
        ),
        (
            "attributed ring guard declaration",
            "#[inject_wait]\n"
            "struct NativeRingGuard<'a, 'b> { marker: &'a &'b () }\n"
            + closed_ring_release
            + closed_ring_drop,
        ),
        (
            "nested-attribute ring guard declaration",
            "#[inject_wait([])]\n"
            "struct NativeRingGuard<'a, 'b> { marker: &'a &'b () }\n"
            + closed_ring_release
            + closed_ring_drop,
        ),
        (
            "nested-attribute inherent ring impl",
            "#[inject_wait([])]\n"
            + closed_ring_release
            + closed_ring_drop,
        ),
        (
            "nested-attribute generic inherent ring impl",
            "#[inject_wait([])]\n"
            "impl<'a, 'b> NativeRingGuard<'a, 'b> {\n"
            "    pub(crate) fn release(self) {}\n"
            "}\n"
            + closed_ring_drop,
        ),
        (
            "nested-attribute ring Drop impl",
            closed_ring_release
            + "#[inject_wait(foo([{}]))]\n"
            + closed_ring_drop,
        ),
    ):
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check(bool(findings), "%s must be rejected, got %r" % (label, findings))

    for label, planted in (
        ("attributed access guard impl", "#[inject_raw]\nimpl<'a> SessionAccessGuard<'a> {}"),
        ("attributed access guard Drop", "#[inject_no_drop]\nimpl Drop for SessionAccessGuard<'_> {}"),
        ("attributed resolver", "#[inject_refusal]\npub(crate) unsafe fn resolve(&self) {}"),
        (
            "export attribute on resolver",
            "#[unsafe(no_mangle)]\npub(crate) unsafe fn resolve(&self) {}",
        ),
        ("attributed process observer", "#[inject_claim]\nfn process_locator(&self) {}"),
        ("attributed native session", "#[inject_raw]\nimpl NativeSession {}"),
        ("attributed native view", "#[inject_fifth]\nimpl NativeSessionView {}"),
        ("attributed VDO publisher", "#[inject_publish]\npub(crate) unsafe fn publish_locator() {}"),
        ("attributed VDO impl", "#[inject_raw]\nimpl VolumeExtension {}"),
        (
            "attributed mounted VDO impl",
            "#[inject_raw]\nimpl MountedVolumeExtension {}",
        ),
        ("attributed mount root", "#[inject_drop]\npub unsafe extern fn fsring_dispatch_mount() {}"),
        (
            "malicious attribute before safe lint attribute",
            "#[inject_raw]\n#[allow(dead_code)]\nimpl NativeSession {}",
        ),
    ):
        planted_findings = guard_api_findings(
            strip_noncode(planted), "driver/fsring-fsd/src/lifecycle.rs"
        )
        check(
            any("native lifetime contract may not be rewritten" in finding
                for finding in planted_findings),
            "%s must be rejected by the balanced native attribute roster" % label,
        )
    terminal_attribute_findings = guard_api_findings(
        strip_noncode(
            "#[inject_owner_drop]\n"
            "unsafe fn run_terminal() {}\n"
        ),
        "driver/fsring-fsd/src/fence.rs",
    )
    check(
        any("native lifetime contract may not be rewritten" in finding
            for finding in terminal_attribute_findings),
        "the terminal owner-live body may not be rewritten by an attribute",
    )
    for label, planted in (
        ("built-in repr", "#[repr(C)]\npub struct NativeSession {}"),
        (
            "fixed view derives",
            "#[derive(Clone, Copy)]\npub(crate) struct NativeSessionView {}",
        ),
        ("built-in lint allow", "#[allow(clippy::result_large_err)]\nfn release_pending() {}"),
        (
            "fixed mount export",
            "#[unsafe(no_mangle)]\npub unsafe extern fn fsring_dispatch_mount() {}",
        ),
    ):
        check(
            not has_native_contract_attribute(strip_noncode(planted)),
            "%s must remain in the exact built-in attribute set" % label,
        )
    check(
        has_native_contract_attribute("#[inject_raw([])\nimpl NativeSession {}"),
        "a malformed native contract attribute must fail closed",
    )
    for carrier in sorted(CARRIERS):
        planted_struct = "#[inject_ptr]\nstruct %s {}" % carrier
        check(
            any(
                "locator-only carrier may not be rewritten" in finding
                for finding in guard_api_findings(strip_noncode(planted_struct), "src/a.rs")
            ),
            "%s struct attributes must fail closed" % carrier,
        )
        planted_impl = "#[inject_getter]\nimpl %s {}" % carrier
        check(
            any(
                "locator-only carrier may not be rewritten" in finding
                for finding in guard_api_findings(strip_noncode(planted_impl), "src/a.rs")
            ),
            "%s impl attributes must fail closed" % carrier,
        )
    check(
        not has_carrier_attribute("#[repr(C)]\nstruct NativeSessionCell {}"),
        "the exact carrier representation attribute must remain allowed",
    )
    check(
        not has_carrier_attribute(
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct RegistrySlot {}"
        ),
        "the exact RegistrySlot derives must remain allowed",
    )

    # These receiver forms are compile-plausible in the real fsring-fsd crate.
    # Each can recover the permanent cell's nonowning shell mirror without a
    # SessionAccessGuard unless the cell/registry/lock-guard API is itself a
    # closed lifetime contract. The expected finding is intentionally driven
    # through guard_api_findings, the same production check used by audit_tree.
    protected_receiver_probes = (
        (
            "public cell raw getter",
            "impl NativeSessionCell {\n"
            "    pub fn unchecked_session(&self) -> *mut NativeSession { self.session }\n"
            "}\n",
        ),
        (
            "crate-visible cell raw getter",
            "impl NativeSessionCell {\n"
            "    pub(crate) fn unchecked_session(&self) -> *mut NativeSession { self.session }\n"
            "}\n",
        ),
        (
            "cell trait raw getter",
            "trait CellProjection { fn unchecked_session(&self) -> *mut NativeSession; }\n"
            "impl CellProjection for NativeSessionCell {\n"
            "    fn unchecked_session(&self) -> *mut NativeSession { self.session }\n"
            "}\n",
        ),
        (
            "qualified cell inherent raw getter",
            "impl crate::lifecycle::NativeSessionCell {\n"
            "    pub(crate) fn unchecked_session(&self) -> *mut NativeSession { self.session }\n"
            "}\n",
        ),
        (
            "generic cell raw getter",
            "impl NativeSessionCell {\n"
            "    pub(crate) fn unchecked_session<T>(&self) -> *mut NativeSession { self.session }\n"
            "}\n",
        ),
        (
            "macro-generated cell raw getter",
            "macro_rules! leak_cell {\n"
            "    () => { pub(crate) fn unchecked_session(&self) -> *mut NativeSession { self.session } };\n"
            "}\n"
            "impl NativeSessionCell { leak_cell!(); }\n",
        ),
        (
            "attributed registry-lock raw getter",
            "#[allow(dead_code)]\nimpl RegistryLockGuard {\n"
            "    pub(crate) unsafe fn unchecked_session(&mut self) -> *mut NativeSession { loop {} }\n"
            "}\n",
        ),
        (
            "aliased wrapped registry raw getter",
            "type LeakedSession = Option<*mut NativeSession>;\n"
            "impl KernelSessionRegistry {\n"
            "    pub(crate) fn unchecked_session(&self) -> LeakedSession { None }\n"
            "}\n",
        ),
        (
            "union-wrapped registry raw getter",
            "union LeakedSession { pointer: *mut NativeSession }\n"
            "impl KernelSessionRegistry {\n"
            "    pub(crate) fn unchecked_session(&self) -> LeakedSession {\n"
            "        LeakedSession { pointer: core::ptr::null_mut() }\n"
            "    }\n"
            "}\n",
        ),
        (
            "registry-lock pointer retained after release",
            "impl RegistryLockGuard {\n"
            "    pub(crate) unsafe fn retain_after_release(mut self, index: u32)\n"
            "        -> *mut NativeSession\n"
            "    {\n"
            "        let answer = unsafe { self.cell_mut(index) }\n"
            "            .map_or(core::ptr::null_mut(), |cell| cell.session);\n"
            "        unsafe { self.release() };\n"
            "        answer\n"
            "    }\n"
            "}\n",
        ),
    )
    for label, planted in protected_receiver_probes:
        planted_findings = guard_api_findings(
            strip_noncode(planted), "driver/fsring-fsd/src/lifecycle.rs"
        )
        check(
            any("protected native receiver" in finding for finding in planted_findings),
            "%s must be rejected by the protected receiver contract, got %r"
            % (label, planted_findings),
        )

    for label, rel, planted in (
        (
            "free mapped pointer getter",
            "driver/fsring-fsd/src/session.rs",
            "pub(crate) unsafe fn mapped_view(session: *mut NativeSession) -> *const u8 { loop {} }",
        ),
        (
            "free wrapped mapped getter",
            "driver/fsring-fsd/src/session.rs",
            "pub(crate) unsafe fn mapped_view(session: *mut NativeSession) -> NonNull<u8> { loop {} }",
        ),
        (
            "free shell reference getter",
            "driver/fsring-fsd/src/session.rs",
            "pub(crate) unsafe fn project(session: *mut NativeSession) -> &'static NativeSession { loop {} }",
        ),
        (
            "free ring-state projection",
            "driver/fsring-fsd/src/session.rs",
            "pub(crate) unsafe fn project_ring(slot: &NativeRingSlot) -> &mut NativeRingState { loop {} }",
        ),
        (
            "lifecycle free access projection",
            "driver/fsring-fsd/src/lifecycle.rs",
            "pub(crate) fn project<'a>(access: &'a SessionAccessGuard<'a>) -> &'a NativeSession { loop {} }",
        ),
        (
            "private lifecycle access projection",
            "driver/fsring-fsd/src/lifecycle.rs",
            "fn project(access: &SessionAccessGuard<'_>) -> &NativeSession { loop {} }",
        ),
        (
            "private mapped pointer getter",
            "driver/fsring-fsd/src/session.rs",
            "unsafe fn mapped(session: *mut NativeSession) -> *const u8 { loop {} }",
        ),
        (
            "aliased free shell projection",
            "driver/fsring-fsd/src/lifecycle.rs",
            "type SessionAddress = *mut NativeSession;\n"
            "pub(crate) fn leak(session: *mut NativeSession) -> SessionAddress { session }",
        ),
        (
            "import-aliased wrapped mapped projection",
            "driver/fsring-fsd/src/session.rs",
            "use core::ptr::NonNull as Address;\n"
            "unsafe fn mapped(session: *mut NativeSession) -> Address<u8> { loop {} }",
        ),
        (
            "newtype-wrapped mapped projection",
            "driver/fsring-fsd/src/session.rs",
            "struct Address(NonNull<u8>);\n"
            "unsafe fn mapped(session: *mut NativeSession) -> Address { loop {} }",
        ),
        (
            "enum-struct-variant mapped projection",
            "driver/fsring-fsd/src/session.rs",
            "enum AddressCarrier { Ptr { value: NonNull<u8> } }\n"
            "unsafe fn mapped(session: *mut NativeSession) -> AddressCarrier { loop {} }",
        ),
        (
            "qualified aliased mapped projection",
            "driver/fsring-fsd/src/session.rs",
            "type Address = NonNull<u8>;\n"
            "unsafe fn mapped(session: *mut NativeSession) -> self::Address { loop {} }",
        ),
        (
            "raw-identifier aliased mapped projection",
            "driver/fsring-fsd/src/session.rs",
            "type r#Address = NonNull<u8>;\n"
            "unsafe fn mapped(session: *mut NativeSession) -> r#Address { loop {} }",
        ),
        (
            "volume free shell projection",
            "driver/fsring-fsd/src/volume.rs",
            "pub(crate) unsafe fn hidden_volume_projection(\n"
            "    session: *mut crate::session::NativeSession,\n"
            ") -> *mut crate::session::NativeSession { session }",
        ),
    ):
        planted_findings = guard_api_findings(strip_noncode(planted), rel)
        check(
            any("free function" in finding and (
                "address authority" in finding or "exact native API roster" in finding
            )
                for finding in planted_findings),
            "%s must be rejected, got %r" % (label, planted_findings),
        )
    with io.open(
        os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "fsring-fsd", "src", "lifecycle.rs"
            )
        ),
        encoding="utf-8",
    ) as handle:
        lifecycle = strip_noncode(handle.read())
    mounted_owner_bodies = list(impl_bodies(lifecycle, "NativeMountedDeviceOwner"))
    check(
        len(mounted_owner_bodies) == 1
        and tuple(
            re.sub(r"\s+", "", header)
            for _name, header in top_level_methods(mounted_owner_bodies[0])
        )
        == AFFINE_OWNER_METHODS["NativeMountedDeviceOwner"],
        "the exact sole-owner mounted-device delete remains allowed",
    )
    volume_method_projection = (
        "impl VolumeExtension {\n"
        "    pub(crate) unsafe fn project(\n"
        "        &self, session: *mut crate::session::NativeSession,\n"
        "    ) -> *mut crate::session::NativeSession { session }\n"
        "}\n"
    )
    check(
        bool(
            guard_api_findings(
                strip_noncode(volume_method_projection),
                "driver/fsring-fsd/src/volume.rs",
            )
        ),
        "a VolumeExtension method may not restore raw session projection",
    )

    # Guarded native observations and ring transitions are deliberately
    # field-specific. These are the concrete source shapes that would reopen a
    # raw pointer/projection bypass or broaden the exact four-value view.
    for label, planted in (
        (
            "raw mapped-section getter",
            "impl SessionAccessGuard<'_> {\n"
            "    pub(crate) unsafe fn section_view(&self) -> *const u8 { loop {} }\n"
            "}\n",
        ),
        (
            "wrapped mapped-section getter",
            "impl SessionAccessGuard<'_> {\n"
            "    pub(crate) fn mapped(&self) -> core::ptr::NonNull<u8> { loop {} }\n"
            "}\n",
        ),
        (
            "integer mapped-section getter",
            "impl SessionAccessGuard<'_> {\n"
            "    pub(crate) fn mapped(&self) -> usize { 0 }\n"
            "}\n",
        ),
        (
            "borrowed native shell view",
            "impl SessionAccessGuard<'_> {\n"
            "    pub(crate) fn view(&self) -> &crate::session::NativeSession { loop {} }\n"
            "}\n",
        ),
        (
            "crate-visible ring lock pointer",
            "impl NativeRingSlot {\n"
            "    pub(crate) fn lock_ptr(&self) -> *mut KSPIN_LOCK { loop {} }\n"
            "}\n",
        ),
        (
            "crate-visible mutable ring state",
            "impl NativeRingSlot {\n"
            "    pub(crate) unsafe fn state_mut(&self) -> &mut NativeRingState { loop {} }\n"
            "}\n",
        ),
        (
            "arbitrary ring ENTER projection method",
            "impl NativeRingSlot {\n"
            "    pub(crate) unsafe fn enter_projection(&self) -> &mut RingEnterState {\n"
            "        unsafe { self.state_mut().enter_mut() }\n"
            "    }\n"
            "}\n",
        ),
        (
            "free hidden-wait ring projection",
            "pub(crate) unsafe fn hidden_ring_wait(slot: &NativeRingSlot) {\n"
            "    let _state = unsafe { slot.state_mut() };\n"
            "    hidden_wait();\n"
            "}\n",
        ),
        (
            "free unshared ring projection",
            "unsafe fn hidden_unshared(slot: &mut NativeRingSlot) {\n"
            "    let _state = unsafe { slot.state_unshared() };\n"
            "    hidden_wait();\n"
            "}\n",
        ),
        (
            "arbitrary ring-guard raw projection",
            "impl NativeRingGuard<'_, '_> {\n"
            "    pub(crate) fn raw_state(&self) -> *mut NativeRingState { loop {} }\n"
            "}\n",
        ),
        (
            "arbitrary ring-guard completion",
            "impl NativeRingGuard<'_, '_> {\n"
            "    pub(crate) fn complete(&self) { complete_irp(); }\n"
            "}\n",
        ),
        (
            "attributed fixed ring operation",
            "impl NativeRingSlot {\n"
            "    #[inject_wait([])]\n"
            "    pub(crate) unsafe fn signal_pending_enter(&self) {}\n"
            "}\n",
        ),
        (
            "namespaced allow attribute on fixed ring operation",
            "impl NativeRingSlot {\n"
            "    #[allow::inject_wait([])]\n"
            "    pub(crate) unsafe fn signal_pending_enter(&self) {}\n"
            "}\n",
        ),
        (
            "namespaced repr attribute on fixed ring operation",
            "impl NativeRingSlot {\n"
            "    #[repr::inject_wait([])]\n"
            "    pub(crate) unsafe fn signal_pending_enter(&self) {}\n"
            "}\n",
        ),
        (
            "renamed raw mapped-section getter",
            "impl NativeSession {\n"
            " pub(crate) fn mapped_view(&self) -> *const u8 { loop {} }\n"
            "}\n",
        ),
        (
            "wrapped raw mapped-section getter",
            "impl NativeSession {\n"
            " pub(crate) fn mapped_view(&self) -> NonNull<u8> { loop {} }\n"
            "}\n",
        ),
        (
            "async integer mapped-section getter",
            "impl NativeSession {\n"
            " pub(crate) async fn mapped_view(&self) -> usize { 0 }\n"
            "}\n",
        ),
        (
            "extern integer mapped-section getter",
            "impl NativeSession {\n"
            " pub(crate) extern \"C\" fn mapped_view(&self) -> usize { 0 }\n"
            "}\n",
        ),
        (
            "native session backpointer visibility",
            "pub struct NativeSession {\n"
            "    pub(crate) state: *mut DriverState,\n"
            "}\n",
        ),
        (
            "fifth native session observation",
            "#[derive(Clone, Copy)]\n"
            "pub(crate) struct NativeSessionView {\n"
            " identity: SessionIdentity, layout: SectionLayoutPlan,\n"
            " profile: PlatformProfile, ring_count: u32, setup: ValidatedSetupRequest,\n"
            "}\n",
        ),
        (
            "borrowed native session layout observation",
            "impl NativeSessionView {\n"
            " pub(crate) const fn layout(&self) -> &SectionLayoutPlan { loop {} }\n"
            "}\n",
        ),
        (
            "fifth native session observation getter",
            "impl NativeSessionView {\n"
            " pub(crate) const fn identity(&self) -> SessionIdentity { loop {} }\n"
            " pub(crate) const fn layout(&self) -> SectionLayoutPlan { loop {} }\n"
            " pub(crate) const fn profile(&self) -> PlatformProfile { loop {} }\n"
            " pub(crate) const fn ring_count(&self) -> u32 { loop {} }\n"
            " pub(crate) const fn setup_epoch(&self) -> u64 { 0 }\n"
            "}\n",
        ),
        (
            "pointer-shaped fifth native session getter",
            "impl NativeSessionView {\n"
            " pub(crate) const fn identity(&self) -> SessionIdentity { loop {} }\n"
            " pub(crate) const fn layout(&self) -> SectionLayoutPlan { loop {} }\n"
            " pub(crate) const fn profile(&self) -> PlatformProfile { loop {} }\n"
            " pub(crate) const fn ring_count(&self) -> u32 { loop {} }\n"
            " pub(crate) fn layout_ptr(&self) -> *const SectionLayoutPlan { loop {} }\n"
            "}\n",
        ),
        (
            "tuple-shaped fifth native session getter",
            "impl NativeSessionView {\n"
            " pub(crate) const fn identity(&self) -> SessionIdentity { loop {} }\n"
            " pub(crate) const fn layout(&self) -> SectionLayoutPlan { loop {} }\n"
            " pub(crate) const fn profile(&self) -> PlatformProfile { loop {} }\n"
            " pub(crate) const fn ring_count(&self) -> u32 { loop {} }\n"
            " pub(crate) fn extra_pair(&self) -> (u32, u32) { loop {} }\n"
            "}\n",
        ),
    ):
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check(bool(findings), "%s must be rejected, got %r" % (label, findings))

    for label, planted in (
        (
            "UFCS native ring transition",
            "fn bypass(slot: &NativeRingSlot) {\n"
            " let _ = NativeRingSlot::acquire_role(slot, 1, role);\n"
            "}\n",
        ),
        (
            "qualified native ring function item",
            "fn bypass() { let _release = <NativeRingSlot>::release_lock; }\n",
        ),
        (
            "aliased native ring function item",
            "use crate::session::NativeRingSlot as SlotAlias;\n"
            "fn bypass() { let _acquire = SlotAlias::acquire_lock; }\n",
        ),
        (
            "type-aliased native ring call",
            "type SlotAlias = crate::session::NativeRingSlot;\n"
            "fn bypass(slot: &SlotAlias) { SlotAlias::release_lock(slot, 0); }\n",
        ),
    ):
        findings = native_contract_findings(
            strip_noncode(planted), "driver/fsring-fsd/src/control.rs"
        )
        check(bool(findings), "%s must be rejected, got %r" % (label, findings))

    planted = (
        "struct NativeRingGuard<'a, 'b> { marker: &'a &'b () }\n"
        + closed_ring_release
        + closed_ring_drop
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
        src = os.path.join(work, "src")
        os.makedirs(src)
        with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
            handle.write(planted)
        findings, _ = audit_tree(work, ["src"])
    check(
        not any("exactly one empty consuming release" in finding for finding in findings),
        "the exact empty consuming ring release must pass its own rule, got %r" % findings,
    )

    # Every native lock-ring call site has one lexical lock lifetime. A helper
    # with an innocent name is still forbidden there: the closed call roster,
    # not a spelling search for `wait`, proves no wait/completion/terminal work
    # can be hidden behind another function.
    callsite_prefix = (
        "fn drive(access: &Access) {\n"
        "    let Ok(mut ring) = access.lock_ring(0) else { return; };\n"
    )
    for label, operation in (
        ("hidden wait under ring lock", "hidden_wait();"),
        ("completion under ring lock", "complete_irp();"),
        ("terminal work under ring lock", "run_terminal();"),
        ("macro call under ring lock", "hidden_wait!();"),
        ("turbofish call under ring lock", "hidden_wait::<u8>();"),
        ("indirect call under ring lock", "(hidden_wait)();"),
        ("method turbofish under ring lock", "helper.hidden_wait::<u8>();"),
        ("unknown statement under ring lock", "let marker = 1;"),
    ):
        planted = (
            callsite_prefix
            + "    "
            + operation
            + "\n    crate::lifecycle::NativeRingGuard::release(ring);\n}\n"
        )
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check(bool(findings), "%s must be rejected, got %r" % (label, findings))

    for label, transition in (
        ("release pending", "let outcome = ring.release_pending(pending);"),
        ("release rollback", "let outcome = ring.release_rollback(pending);"),
        (
            "acquire role",
            "let acquired = ring.acquire_role(next_invocation(), role);",
        ),
    ):
        planted = (
            callsite_prefix
            + "    "
            + transition
            + "\n    crate::lifecycle::NativeRingGuard::release(ring);\n}\n"
        )
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check(
            not findings,
            "%s plus explicit drop must pass: %r" % (label, findings),
        )

    planted = (
        "fn drive(access: &Access) {\n"
        + "    let braces = (\"{\", r#\"}\"#, '{');\n"
        + "    let Ok(mut ring) = access.lock_ring(0) else { return; };\n"
        + "    /* outer { /* nested } */ still-comment } */\n"
        + "    let outcome = ring.release_pending(pending);\n"
        + "    crate::lifecycle::NativeRingGuard::release(ring);\n"
        + "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
        src = os.path.join(work, "src")
        os.makedirs(src)
        with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
            handle.write(planted)
        findings, _ = audit_tree(work, ["src"])
    check(
        not findings,
        "comments, strings, and chars must not spoof lexical depth: %r" % findings,
    )

    for label, planted in (
        (
            "unparsed lock acquisition",
            "fn drive(access: &Access) {\n"
            "    let mut ring = access.lock_ring(0).unwrap();\n"
            "    drop(ring);\n"
            "}\n",
        ),
        (
            "missing explicit drop",
            callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "}\n",
        ),
        (
            "conditional drop does not end the lexical lifetime",
            callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    if condition { crate::lifecycle::NativeRingGuard::release(ring); }\n"
            + "    hidden_wait();\n"
            + "}\n",
        ),
        (
            "closure drop does not end the lexical lifetime",
            callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    let deferred = || crate::lifecycle::NativeRingGuard::release(ring);\n"
            + "    hidden_wait();\n"
            + "}\n",
        ),
        (
            "loop drop does not end the lexical lifetime",
            callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    while condition { crate::lifecycle::NativeRingGuard::release(ring); }\n"
            + "    hidden_wait();\n"
            + "}\n",
        ),
        (
            "shadowed unqualified drop is not a terminal drop",
            "fn drop<T>(_value: T) { hidden_wait(); }\n"
            + callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    drop(ring);\n"
            + "}\n",
        ),
        (
            "import-aliased drop is not a terminal drop",
            "use helper::wait_then_consume as drop;\n"
            + callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    drop(ring);\n"
            + "}\n",
        ),
        (
            "closure-bound drop is not a terminal drop",
            "fn drive(access: &Access) {\n"
            + "    let drop = |guard| hidden_wait(guard);\n"
            + "    let Ok(mut ring) = access.lock_ring(0) else { return; };\n"
            + "    let outcome = ring.release_pending(pending);\n"
            + "    drop(ring);\n"
            + "}\n",
        ),
        (
            "relative core module cannot spoof the terminal drop",
            "mod core { pub mod mem { pub fn drop<T>(_value: T) { hidden_wait(); } } }\n"
            + callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    core::mem::drop(ring);\n"
            + "}\n",
        ),
        (
            "absolute core alias cannot spoof the terminal drop",
            "#![no_std]\n"
            + "extern crate self as core;\n"
            + "pub mod mem { pub fn drop<T>(_value: T) { hidden_wait(); } }\n"
            + callsite_prefix
            + "    let outcome = ring.release_pending(pending);\n"
            + "    ::core::mem::drop(ring);\n"
            + "}\n",
        ),
    ):
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check(bool(findings), "%s must fail closed, got %r" % (label, findings))

    # Exercise the public CLI path, not merely the carrier helper. A scoped run
    # that sees one carrier must fail because the other four carriers, all three
    # required native owner files, and the one frozen pending shape were not
    # audited: four + three + one = eight.
    #
    # This expected count was a literal `7` and had been wrong since Task 17/18
    # added `PENDING_SHAPE_BODIES` and its "was not found in the audited roots"
    # finding. Nothing noticed, because `build_matrix.cmd` runs this file with
    # `--production-check` and never with `--self-test` — the same shape of gap
    # as the matrix not running this auditor at all. Deriving the number from
    # the three rosters rather than restating it is what stops the next addition
    # from silently repeating it.
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-main-") as work:
        src = os.path.join(work, "src")
        os.makedirs(src)
        with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
            handle.write(clean)
        completed = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--root",
                work,
                "--source-root",
                "src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    scoped_missing = (
        len(CARRIERS) - 1 + len(NATIVE_OWNER_FILES) + len(PENDING_SHAPE_BODIES)
    )
    check(
        completed.returncode == 1
        and '"result":"FAIL"' in completed.stdout
        and ('"findings":%d' % scoped_missing) in completed.stdout,
        "main path must count all missing carriers/owners/shapes as findings, expected %d, got exit=%d stdout=%r stderr=%r"
        % (scoped_missing, completed.returncode, completed.stdout, completed.stderr),
    )

    # All three WDK-facing owners are mandatory. Copy the two clean owner files
    # plus every carrier, but deliberately omit session.rs; production mode
    # must fail for the absent owner even though all five carriers remain.
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-owner-roster-") as work:
        for rel in (
            "driver/fsring-core/src/session.rs",
            "driver/fsring-fsd/src/control.rs",
            "driver/fsring-fsd/src/lifecycle.rs",
            "driver/fsring-fsd/src/volume.rs",
        ):
            destination = os.path.join(work, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.copy2(os.path.join(repo, rel.replace("/", os.sep)), destination)
        missing_owner = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        missing_owner.returncode == 1
        and "driver/fsring-fsd/src/session.rs" in missing_owner.stderr,
        "production mode must fail when a native owner file is absent, got exit=%d stdout=%r stderr=%r"
        % (missing_owner.returncode, missing_owner.stdout, missing_owner.stderr),
    )

    # The attach-scratch rule, called directly against the real production
    # sources. This block deliberately does not go through the Task-12 probe
    # wave: the owning command that grades a mutant against this file runs the
    # self-test with `--skip-task12-wave`, so a rule whose only coverage lived
    # in the wave would be ungraded exactly where grading is claimed.
    attach_production = {}
    for source_root in ("driver/fsring-core/src", "driver/fsring-fsd/src"):
        base = os.path.join(repo, source_root.replace("/", os.sep))
        for directory, _subdirectories, names in os.walk(base):
            for name in sorted(names):
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, repo).replace(os.sep, "/")
                if rel.endswith("/tests.rs") or "/tests/" in rel:
                    continue
                with io.open(path, encoding="utf-8") as handle:
                    attach_production[rel] = strip_noncode(handle.read())
    attach_session_rel = "driver/fsring-fsd/src/session.rs"
    check(
        attach_session_rel in attach_production,
        "attach scratch self-test must read the real session.rs",
    )
    check(
        attach_scratch_findings(attach_production) == [],
        "the real tree must satisfy the attach-scratch rule, got %r"
        % (attach_scratch_findings(attach_production),),
    )
    attach_probe_table = (
        (
            "context.apc_state.as_mut_ptr()",
            "core::ptr::addr_of_mut!(APC_STATE)",
            "reaches a global rather than a frame or context binding",
        ),
        (
            "unsafe fn attach_captured(context: &mut SetupContext)",
            "static mut APC_STATE: KAPC_STATE = unsafe { core::mem::zeroed() };\n"
            "unsafe fn attach_captured(context: &mut SetupContext)",
            "declares KAPC_STATE storage",
        ),
        (
            # A frame binding under another name, renamed at the call sites too
            # so the argument text really changes. The shape check is content
            # with it -- it is still a binding, not a global -- so only the
            # frozen roster can see this one.
            "apc_state",
            "apc_scratch",
            "the attach/detach call roster changed",
        ),
    )
    for old, new, expected in attach_probe_table:
        mutated = dict(attach_production)
        source = mutated[attach_session_rel]
        check(
            source.count(old) >= 1,
            "attach scratch probe anchor %r is absent from session.rs" % old,
        )
        mutated[attach_session_rel] = source.replace(old, new)
        produced = attach_scratch_findings(mutated)
        check(
            any(expected in finding for finding in produced),
            "attach scratch probe %r must report %r, got %r" % (old, expected, produced),
        )
    # Anti-vacuity for the shape half: with the file gone the scan sees no call
    # site at all, which must be a finding rather than a silent pass.
    attach_without_session = {
        rel: source
        for rel, source in attach_production.items()
        if rel != attach_session_rel
    }
    check(
        any(
            "measured nothing" in finding
            for finding in attach_scratch_findings(attach_without_session)
        ),
        "the attach-scratch shape check must refuse to pass when it sees no call site",
    )

    # The production contracts are exercised against the real WDK-facing
    # sources with one adversarial edit at a time. The production C4 targets
    # run the same rules directly against their mutated copy; these fixtures
    # protect the rules themselves from being weakened.
    native_cases = (
        ("driver/fsring-fsd/src/lifecycle.rs", "core.validate_live(locator)", "core.skip_live(locator)"),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "Ok(()) => pending.succeeded(),",
            "Ok(()) => pending.refused(ResolveRejection::NotLive),",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "Some(cell) if cell.matches_live_locator(locator) => pending.succeeded(),",
            "Some(_cell) => pending.refused(ResolveRejection::StaleCell),",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "held.project_resolved_session(slot_index, locator)",
            "held.skip_resolved_session(slot_index, locator)",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "                        unsafe { held.release() };\n"
            "                    }\n"
            "                    pending.succeeded()\n",
            "                        core::mem::forget(held);\n"
            "                    }\n"
            "                    pending.succeeded()\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "if refusal.releases_lock() {",
            "if false && refusal.releases_lock() {",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "if refusal.releases_rundown() {",
            "if false && refusal.releases_rundown() {",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "if let Some(target) = registry.access_rundown_ptr(self.slot_index) {",
            "if let Some(target) = None::<*mut EX_RUNDOWN_REF> {\n            let _ = registry.access_rundown_ptr(self.slot_index);",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "    ) -> Result<SessionAccessGuard<'_>, SessionAccessError> {\n        let slot_index = locator.slot_index();",
            "    ) -> Result<SessionAccessGuard<'_>, SessionAccessError> {\n        return Err(SessionAccessError::StaleLocator);\n        let slot_index = locator.slot_index();",
        ),
        ("driver/fsring-fsd/src/lifecycle.rs", "cell.owners_match(locator)", "cell.skip_owners(locator)"),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "fn owners_match(&self, locator: SessionLocator) -> bool {\n        native_owner_slots_match(",
            "fn owners_match(&self, locator: SessionLocator) -> bool {\n        return true;\n        native_owner_slots_match(",
        ),
        ("driver/fsring-fsd/src/lifecycle.rs", "(*cell).process_locator(process)", "(*cell).session; (*cell).process_locator(process)"),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "NonNull::new(process)?,",
            "NonNull::new(self.process)?,",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "                ResolveStep::ValidateCoreLive => {\n",
            "                ResolveStep::ValidateCoreLive => {\n"
            "                    unsafe { queue_cell_finalizer(NonNull::from(self).cast(), locator) };\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "                ResolveStep::ValidateCoreLive => {\n",
            "                ResolveStep::ValidateCoreLive => {\n"
            "                    rundown = None;\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "                ResolveStep::ValidateCoreLive => {\n",
            "                ResolveStep::ValidateCoreLive => {\n"
            "                    lock = None;\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "                ResolveStep::ValidateCoreLive => {\n",
            "                ResolveStep::ValidateCoreLive => {\n"
            "                    session = None;\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "                    if acquired == 0 {\n",
            "                    if acquired != 0 {\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "        let mut lock = unsafe { Self::lock(registry) };\n",
            "        let mut lock = unsafe { Self::lock(registry) };\n"
            "        unsafe { close_process_callback_admission(registry) };\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "pub(crate) fn view(&self) -> crate::session::NativeSessionView {",
            "pub(crate) fn view(&self) -> &crate::session::NativeSession {",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl NativeRingGuard<'_, '_> {\n",
            "impl NativeRingGuard<'_, '_> {\n"
            "    pub(crate) fn raw_state(&self) -> *mut NativeRingState { loop {} }\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "    pub(crate) fn release(self) {}\n",
            "    pub(crate) fn release(self) { core::mem::forget(self); }\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "            saved.release_with(|old_irql| unsafe { self.slot.release_lock(old_irql) });\n",
            "            if false {\n"
            "                saved.release_with(|old_irql| unsafe { self.slot.release_lock(old_irql) });\n"
            "            }\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "pub(crate) unsafe fn acknowledge_completed_control(\n",
            "type SessionAddress = *mut NativeSession;\n"
            "pub(crate) fn leak(session: *mut NativeSession) -> SessionAddress { session }\n\n"
            "pub(crate) unsafe fn acknowledge_completed_control(\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "pub(crate) unsafe fn acknowledge_completed_control(\n",
            "pub static PROJECT: for<'a> fn(&'a SessionAccessGuard<'a>) -> &'a NativeSession =\n"
            "    |access| access.session.get();\n\n"
            "pub(crate) unsafe fn acknowledge_completed_control(\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl<'registry> SessionAccessGuard<'registry> {\n",
            "macro_rules! leak_access {\n"
            "    () => { pub(crate) fn raw_session(&self) -> *mut NativeSession {\n"
            "        core::ptr::from_ref(self.session.get()).cast_mut()\n"
            "    } };\n"
            "}\n"
            "impl<'registry> SessionAccessGuard<'registry> {\n"
            "    leak_access!();\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl Drop for SessionAccessGuard<'_> {\n",
            "impl Clone for crate::lifecycle::SessionAccessGuard<'_> {\n"
            "    fn clone(&self) -> Self {\n"
            "        Self { registry: self.registry, slot_index: self.slot_index, locator: self.locator,\n"
            "            session: unsafe { SharedSessionProjection::from_non_null(NonNull::new_unchecked(\n"
            "                self.session.get() as *const NativeSession as *mut NativeSession)) } }\n"
            "    }\n"
            "}\n\n"
            "impl Drop for SessionAccessGuard<'_> {\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl NativeSessionSharedOps for NativeSessionShell {\n",
            "impl Clone for NativeSessionShell {\n"
            "    fn clone(&self) -> Self { Self { session: self.session } }\n"
            "}\n\nimpl NativeSessionSharedOps for NativeSessionShell {\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl UnpublishedNativeSessionShell {\n",
            "impl UnpublishedNativeSessionShell {\n"
            "    pub(crate) unsafe fn from_ptr(session: *mut NativeSession) -> Self {\n"
            "        Self { session: unsafe { NonNull::new_unchecked(session) },\n"
            "            authority: PrivateUnpublishedNativeSessionShellAuthority(()) }\n"
            "    }\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl<'registry> SessionAccessGuard<'registry> {\n",
            "impl crate::lifecycle::SessionAccessGuard<'_> {\n"
            "    pub(crate) fn raw_session(&self) -> *mut NativeSession {\n"
            "        core::ptr::from_ref(self.session.get()).cast_mut()\n"
            "    }\n"
            "}\n\nimpl<'registry> SessionAccessGuard<'registry> {\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl Drop for SessionAccessGuard<'_> {\n",
            "impl Clone for (SessionAccessGuard<'_>) {\n"
            "    fn clone(&self) -> Self { loop {} }\n"
            "}\n\n"
            "impl Drop for SessionAccessGuard<'_> {\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "impl Drop for SessionAccessGuard<'_> {\n",
            "extern crate self as fsring_fsd;\n"
            "impl Clone for ::fsring_fsd::lifecycle::SessionAccessGuard<'_> {\n"
            "    fn clone(&self) -> Self { loop {} }\n"
            "}\n\n"
            "impl Drop for SessionAccessGuard<'_> {\n",
        ),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "        let resume_at = index.checked_add(1).filter(|next| *next < cell_count);\n"
            "        // SAFETY: the caller's registry contract.\n"
            "        let mut lock = unsafe { Self::lock(registry) };",
            "        let resume_at = index.checked_add(1).filter(|next| *next < cell_count);\n"
            "        // SAFETY: the caller's registry contract.\n"
            "        let mut lock = unsafe { Self::lock(registry) };\n"
            "        let _leaked_cursor = resume_at;",
        ),
        ("driver/fsring-fsd/src/lifecycle.rs", "slot.acquire_lock()", "slot.skip_lock()"),
        (
            "driver/fsring-fsd/src/lifecycle.rs",
            "shell.matches_mirror(self.session)",
            "true",
        ),
        ("driver/fsring-fsd/src/session.rs", "slot.initialize_lock()", "slot.skip_initialize_lock()"),
        ("driver/fsring-fsd/src/session.rs", "context.ring_locks = Some(initialized)", "drop(initialized)"),
        ("driver/fsring-fsd/src/session.rs", "KeAcquireSpinLockRaiseToDpc(self.lock_ptr())", "skip_acquire(self.lock_ptr())"),
        ("driver/fsring-fsd/src/session.rs", "KeReleaseSpinLock(self.lock_ptr(), old_irql)", "skip_release(self.lock_ptr(), old_irql)"),
        ("driver/fsring-fsd/src/session.rs", "ring.signal_pending_enter()", "ring.skip_signal_pending_enter()"),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeRingSlot {\n",
            "impl NativeRingSlot {\n"
            "    pub(crate) unsafe fn enter_projection(&self) -> &mut RingEnterState {\n"
            "        unsafe { self.state_mut().enter_mut() }\n"
            "    }\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeRingSlot {\n",
            "impl NativeRingSlot {\n    pub(crate) fn marker(&self) {}\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
            "pub(crate) unsafe fn hidden_ring_wait(slot: &NativeRingSlot) {\n"
            "    let _state = unsafe { slot.state_mut() };\n"
            "    hidden_wait();\n"
            "}\n\n"
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
            "union Address { pointer: *mut u8 }\n"
            "unsafe fn hidden_union_projection(session: *mut NativeSession) -> Address {\n"
            "    Address { pointer: unsafe { (*session).system_view.cast() } }\n"
            "}\n\nimpl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
            "unsafe fn hidden_option_projection(session: *mut NativeSession) -> Option<*mut u8> {\n"
            "    Some(unsafe { (*session).system_view.cast() })\n"
            "}\n\nimpl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
            "mod hidden_address { pub(super) struct Address(pub NonNull<u8>); }\n"
            "struct Address(u64);\n"
            "unsafe fn mapped(session: *mut NativeSession) -> hidden_address::Address {\n"
            "    hidden_address::Address(unsafe { NonNull::new_unchecked((*session).system_view.cast()) })\n"
            "}\n\n"
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "    let access = match unsafe { registry.as_ref().resolve(locator) } {\n"
            "        Ok(access) => access,\n"
            "        Err(error) => return error.status(),\n"
            "    };\n",
            "    let access = match unsafe { registry.as_ref().resolve(locator) } {\n"
            "        Ok(access) => access,\n"
            "        Err(error) => return error.status(),\n"
            "    };\n"
            "    unsafe { crate::lifecycle::wait_joiners_drained(registry, locator) };\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
            "pub(crate) fn marker() {}\n\n"
            "impl NativeSession {\n    pub(crate) const fn identity(&self) -> SessionIdentity {\n",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "unsafe { fsring_sys::c4::KeSetEvent(state.event_ptr(), 0, 0 as fsring_sys::BOOLEAN) };",
            "unsafe { complete_irp() };\n        unsafe { fsring_sys::c4::KeSetEvent(state.event_ptr(), 0, 0 as fsring_sys::BOOLEAN) };",
        ),
        (
            "driver/fsring-fsd/src/session.rs",
            "ring_count: self.layout.ring_count(),",
            "ring_count: 0,",
        ),
        ("driver/fsring-fsd/src/volume.rs", "if !initializing {", "if false {"),
        ("driver/fsring-fsd/src/volume.rs", "Ordering::Release);", "Ordering::Relaxed);"),
        (
            "driver/fsring-fsd/src/volume.rs",
            "        if state != VDO_LOCATOR_INITIALIZED {\n",
            "        if state == VDO_LOCATOR_INITIALIZED {\n",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "let state = unsafe { (*extension).locator_state.load(Ordering::Acquire) };",
            "let state = unsafe { (*extension).locator_state.load(Ordering::Relaxed) };",
        ),
        ("driver/fsring-fsd/src/volume.rs", "RetainedAccessGuard::new(access)", "RetainedAccessGuard::new(())"),
        ("driver/fsring-fsd/src/volume.rs", "Some(DeviceKind::VirtualDisk)", "Some(DeviceKind::MountedVolume)"),
        (
            "driver/fsring-fsd/src/volume.rs",
            ") -> Result<(), NTSTATUS> {\n        if device.is_null() {",
            ") -> Result<(), NTSTATUS> {\n        return Ok(());\n        if device.is_null() {",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "if !initializing {",
            "if !initializing || initializing {",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "if (*extension).locator_state.load(Ordering::Acquire) != VDO_LOCATOR_INITIALIZING {",
            "if (*extension).locator_state.load(Ordering::Acquire) != VDO_LOCATOR_INITIALIZING || (*extension).locator_state.load(Ordering::Acquire) == VDO_LOCATOR_INITIALIZING {",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "if !initializing {\n            return Err(STATUS_INVALID_DEVICE_STATE);\n        }",
            "if !initializing {\n            return Ok(());\n        }",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "pub unsafe extern \"system\" fn fsring_dispatch_mount(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {\n    if device.is_null() {",
            "pub unsafe extern \"system\" fn fsring_dispatch_mount(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {\n    return STATUS_INVALID_DEVICE_REQUEST;\n    if device.is_null() {",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "if !routing_target_matches {",
            "if !routing_target_matches || routing_target_matches {",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "    let retained = RetainedAccessGuard::new(access);\n",
            "    let retained = RetainedAccessGuard::new(access);\n"
            "    unsafe { crate::lifecycle::wait_joiners_drained(registry, locator) };\n",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "    retained.run(|access| {\n"
            "        let mut context = MountContext {\n"
            "            vdo: target,\n"
            "            vpb: Some(vpb_owner),\n"
            "            mounted: None,\n"
            "            vcb_storage: None,\n"
            "            initialized_vcb: None,\n"
            "            publication: None,\n"
            "            owner_published: false,\n"
            "            access,\n"
            "            locator,\n"
            "            state: root,\n"
            "            identity,\n"
            "            vpb_held: false,\n"
            "            vpb_irql: 0,\n"
            "            reference: None,\n"
            "        };\n"
            "        // SAFETY: PASSIVE_LEVEL mount thread; the context owns everything the\n"
            "        // transaction acquires. `run` retains the access guard through either\n"
            "        // the commit or rollback suffix.\n"
            "        status = unsafe {\n"
            "            drive_mount(\n"
            "                &mut context,\n"
            "                device,\n"
            "                adapter::NativeVolumePlan::mount(progress),\n"
            "            )\n"
            "        };\n"
            "    });\n",
            "    if false {\n"
            "        retained.run(|access| {\n"
            "            let mut context = MountContext {\n"
            "                vdo: target, vpb: Some(vpb_owner), mounted: None,\n"
            "                vcb_storage: None, initialized_vcb: None, publication: None,\n"
            "                owner_published: false, access, locator,\n"
            "                state: root, identity, vpb_held: false, vpb_irql: 0, reference: None,\n"
            "            };\n"
            "            status = unsafe { drive_mount(&mut context, device, adapter::NativeVolumePlan::mount(progress)) };\n"
            "        });\n"
            "    }\n",
        ),
        (
            "driver/fsring-fsd/src/volume.rs",
            "if identity.mount_id.lo != mount_lo || identity.mount_id.hi != mount_hi {",
            "if identity.mount_id.lo != mount_lo || identity.mount_id.hi != mount_hi || identity.mount_id.lo == mount_lo {",
        ),
        # Round-9 blocker 2, the shape the presence-only rule would have
        # missed: the classifier is still called, still exactly once, and its
        # release arm is intact -- but the axis it classifies is a constant, so
        # a slot the cancel routine owns answers `ReleasedToDriver` again.
        (
            "driver/fsring-fsd/src/pending_enter.rs",
            # Round 10 added a second, more deeply indented classification,
            # and this anchor is matched as a SUBSTRING -- the deeper line
            # contains it. The call line disambiguates them.
            "        classify_worker_dequeue(\n            (*raw).irp_axis,",
            "        classify_worker_dequeue(\n            Some(IrpAxis::Dequeued),",
        ),
        # Round-9 high 1: the legacy profile stops locking master MDLs, so
        # its ENTER drain touches a pageable view at DISPATCH_LEVEL again.
        (
            "driver/fsring-fsd/src/session.rs",
            "    let master_count = (layout.ring_count() as usize).saturating_add(2);",
            "    let master_count = if matches!(profile, PlatformProfile::Win10X64 | PlatformProfile::Win10Arm64) { (layout.ring_count() as usize).saturating_add(2) } else { 0 };",
        ),
        # Round-9 high 4: the ownership comparison degenerates into comparing
        # the target with itself -- present, well-named, and proving nothing.
        (
            "driver/fsring-fsd/src/volume.rs",
            "let own_driver = unsafe { (*device).DriverObject };",
            "let own_driver = unsafe { (*target).DriverObject };",
        ),
        # And the ordering: the extension is projected before ownership is
        # established, which is the foreign-struct read itself.
        (
            "driver/fsring-fsd/src/volume.rs",
            "    let own_driver = unsafe { (*device).DriverObject };",
            "    let _early = unsafe { (*target).DeviceExtension.cast::<ExtensionHeader>() };\n    let own_driver = unsafe { (*device).DriverObject };",
        ),
        # Round-9 high 3: the parked-WAIT store's refusal goes back to being
        # discarded, so a slot whose plan was never stored keeps a client
        # waiting on a request nothing in the driver can complete.
        (
            "driver/fsring-fsd/src/session.rs",
            "let stored = unsafe { access.store_parked_wait(ring_index, owned, request) };",
            "let _ = unsafe { access.store_parked_wait(ring_index, owned, request) };\n                    let stored: Result<(), ()> = Ok(());",
        ),
        # Round-9 high 2: the dequeue walks in the unconditional roster prefix
        # again, which is where a refused pass stranded an uncancellable IRP.
        (
            "driver/fsring-fsd/src/pending_enter.rs",
            "        PendingCallbackAction::PollAndRecheck,\n    ] {",
            "        PendingCallbackAction::PollAndRecheck,\n        PendingCallbackAction::RemoveIrpFromCsq,\n    ] {",
        ),
        # And the wedge: a refused pass keeps the completion declaration, so
        # the schedule stays `Completing` -- which refuses to finish and
        # refuses to queue -- for the life of the session.
        #
        # The leading newline pins the indentation, and so the call site. Round
        # 13 added a SECOND `abandon_completion()` one nesting level deeper (a
        # review found the other refusal arm never undid its declaration), and
        # without the newline this 12-space anchor also matched inside that
        # 16-space line -- failing "must resolve once". The identical anchor in
        # `mutation_sweep.py` needed the same fix.
        (
            "driver/fsring-fsd/src/pending_enter.rs",
            "\n            runtime.abandon_completion();",
            "",
        ),
        # And the classified release stops being the thing the pass completes
        # from: the arm that names the released IRP is gone.
        (
            "driver/fsring-fsd/src/pending_enter.rs",
            "WorkerDequeueAuthority::ReleasedToDriver(irp) => Some(irp),",
            "WorkerDequeueAuthority::ReleasedToDriver(_) => None,",
        ),
    )
    for rel, anchor, replacement in native_cases:
        path = os.path.join(repo, rel.replace("/", os.sep))
        with io.open(path, encoding="utf-8") as handle:
            original = handle.read()
        check(
            original.count(anchor) == 1,
            "native fixture anchor must resolve once: %s %r" % (rel, anchor),
        )
        mutated = strip_noncode(original.replace(anchor, replacement, 1))
        planted_findings = guard_api_findings(mutated, rel)
        planted_findings.extend(native_contract_findings(mutated, rel))
        check(
            bool(planted_findings),
            "native contract mutation must be rejected: %s %r" % (rel, anchor),
        )

    check(
        canonical_source_roots(repo, ["driver/fsring-fsd/src/."])
        == ("driver/fsring-fsd/src",),
        "dot-spelled fsd root must resolve to the closed source identity",
    )
    check(
        canonical_source_roots(
            repo, [os.path.abspath(os.path.join(repo, "driver", "fsring-fsd", "src"))]
        ) == ("driver/fsring-fsd/src",),
        "absolute fsd root must resolve to the closed source identity",
    )
    try:
        canonical_source_roots(
            repo, ["driver/fsring-fsd/src", "driver/fsring-fsd/src/."]
        )
        duplicate_roots_rejected = False
    except LifetimeAuditError:
        duplicate_roots_rejected = True
    check(duplicate_roots_rejected, "duplicate resolved source roots must be rejected")
    omitted_root = subprocess.run(
        [
            sys.executable,
            os.path.abspath(__file__),
            "--production-check",
            "--root",
            repo,
            "--source-root",
            "driver/fsring-core/src",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    check(
        omitted_root.returncode == 2 and "exact core/fsd source-root identities" in omitted_root.stderr,
        "production mode must reject an omitted root, got exit=%d stderr=%r"
        % (omitted_root.returncode, omitted_root.stderr),
    )

    # Main-path census: an acquisition planted in a normally unaudited fsd
    # module must fail production mode for both method and UFCS spellings.
    driver_probe = (
        "\nunsafe fn hidden_access_wait(locator: fsring_core::session::SessionLocator) {\n"
        "    let state = unsafe { &*root() };\n"
        "    let access = match unsafe { %s } {\n"
        "        Ok(access) => access,\n"
        "        Err(_) => return,\n"
        "    };\n"
        "    unsafe { crate::lifecycle::wait_joiners_drained(\n"
        "        core::ptr::NonNull::from(&state.sessions), locator,\n"
        "    ) };\n"
        "    drop(access);\n"
        "}\n"
    )
    for call, fsd_source_root in (
        ("state.sessions.resolve(locator)", "driver/fsring-fsd/src"),
        (
            "crate::lifecycle::KernelSessionRegistry::resolve(&state.sessions, locator)",
            "driver/fsring-fsd/src/.",
        ),
    ):
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-global-resolve-") as work:
            shutil.copytree(
                os.path.join(repo, "driver", "fsring-fsd", "src"),
                os.path.join(work, "driver", "fsring-fsd", "src"),
            )
            core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
            os.makedirs(os.path.dirname(core_session), exist_ok=True)
            shutil.copy2(
                os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
                core_session,
            )
            driver_path = os.path.join(work, "driver", "fsring-fsd", "src", "driver.rs")
            with io.open(driver_path, "a", encoding="utf-8") as handle:
                handle.write(driver_probe % call)
            planted = subprocess.run(
                [
                    sys.executable,
                    os.path.abspath(__file__),
                    "--production-check",
                    "--root",
                    work,
                    "--source-root",
                    "driver/fsring-core/src",
                    "--source-root",
                    fsd_source_root,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        check(
            planted.returncode == 1
            and "driver/fsring-fsd/src/driver.rs" in planted.stderr,
            "global resolve census must reject %s, got exit=%d stdout=%r stderr=%r"
            % (call, planted.returncode, planted.stdout, planted.stderr),
        )

    # Main-path capability census: another terminal winner consumer in a module
    # with no native owner declarations is compile-plausible, but would mint a
    # second raw shell projection outside the one checkpoint executor.
    terminal_probe = (
        "\nunsafe fn hidden_terminal_projection(\n"
        "    registry: core::ptr::NonNull<crate::lifecycle::KernelSessionRegistry>,\n"
        "    work: crate::lifecycle::TerminalWork,\n"
        ") {\n"
        "    let (_session, _control, _owners) = unsafe {\n"
        "        work.into_checkpoint_parts_with_locked_mirror(registry)\n"
        "    };\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-global-capability-") as work:
        shutil.copytree(
            os.path.join(repo, "driver", "fsring-fsd", "src"),
            os.path.join(work, "driver", "fsring-fsd", "src"),
        )
        core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
        os.makedirs(os.path.dirname(core_session), exist_ok=True)
        shutil.copy2(
            os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
            core_session,
        )
        fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
        with io.open(fence_path, "a", encoding="utf-8") as handle:
            handle.write(terminal_probe)
        planted = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        planted.returncode == 1
        and "retired terminal mirror callsite" in planted.stderr,
        "global native capability census must reject a second terminal projection, "
        "got exit=%d stdout=%r stderr=%r"
        % (planted.returncode, planted.stdout, planted.stderr),
    )

    # Duplicate the current opaque owner aggregate before its sole checkpoint
    # consumer. The complete terminal-winner body must reject this even though
    # no raw payload projection is available after the affine cutover.
    terminal_split = "    let (control, owners) = work.into_checkpoint_parts();\n"
    duplicated_terminal_owners = (
        terminal_split
        + "    let duplicated = unsafe { core::ptr::read(&owners) };\n"
        "    core::mem::forget(duplicated);\n"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-terminal-owner-live-") as work:
        shutil.copytree(
            os.path.join(repo, "driver", "fsring-fsd", "src"),
            os.path.join(work, "driver", "fsring-fsd", "src"),
        )
        core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
        os.makedirs(os.path.dirname(core_session), exist_ok=True)
        shutil.copy2(
            os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
            core_session,
        )
        fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
        with io.open(fence_path, encoding="utf-8") as handle:
            fence_source = handle.read()
        if fence_source.count(terminal_split) != 1:
            failures.append("terminal owner-live probe anchor is not exact-one")
        with io.open(fence_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(
                fence_source.replace(terminal_split, duplicated_terminal_owners, 1)
            )
        planted = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        planted.returncode == 1 and "terminal winner owner-live body" in planted.stderr,
        "terminal mirror consumer must retain its authentic shell owner through teardown, "
        "got exit=%d stdout=%r stderr=%r"
        % (planted.returncode, planted.stdout, planted.stderr),
    )

    teardown_split = (
        "            let (winner, terminal, closing, shell, root) = owners.into_parts();\n"
        "            let reason = winner.reason();\n"
        "            let result = fsring_core::session::TerminalResult {\n"
        "                reason,\n"
        "                fence_failures: completed.report().failed_mask(),\n"
    )
    early_teardown_destroy = (
        teardown_split
        + "    let duplicated_shell = unsafe { core::ptr::read(&shell) };\n"
        "    unsafe { duplicated_shell.destroy() };\n"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-checkpoint-owner-live-") as work:
        shutil.copytree(
            os.path.join(repo, "driver", "fsring-fsd", "src"),
            os.path.join(work, "driver", "fsring-fsd", "src"),
        )
        core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
        os.makedirs(os.path.dirname(core_session), exist_ok=True)
        shutil.copy2(
            os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
            core_session,
        )
        fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
        with io.open(fence_path, encoding="utf-8") as handle:
            fence_source = handle.read()
        if fence_source.count(teardown_split) != 1:
            failures.append("checkpoint owner-live probe anchor is not exact-one")
        with io.open(fence_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(fence_source.replace(teardown_split, early_teardown_destroy, 1))
        planted = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        planted.returncode == 1 and "checkpoint teardown owner-live body" in planted.stderr,
        "checkpoint teardown must retain the shell owner while the executor uses its session, "
        "got exit=%d stdout=%r stderr=%r"
        % (planted.returncode, planted.stdout, planted.stderr),
    )

    # Alternate cross-module spellings must not bypass the protected receiver
    # roster. Both helpers compile in fsring-fsd at the RED checkpoint: the
    # first splits TerminalWork through its legacy owner path, and the second
    # retains the permanent-cell pointer after consuming the registry lock.
    cross_module_capability_probes = (
        (
            "legacy terminal owner split",
            "\nunsafe fn hidden_terminal_owner_projection(\n"
            "    work: crate::lifecycle::TerminalWork,\n"
            ") -> *mut crate::session::NativeSession {\n"
            "    let (_winner, _terminal, _control, _closing, shell, _root) =\n"
            "        work.into_parts();\n"
            "    shell.as_ptr()\n"
            "}\n",
            "terminal owner split",
        ),
        (
            "cell pointer retained after registry unlock",
            "\nunsafe fn hidden_cell_projection_after_unlock(\n"
            "    registry: core::ptr::NonNull<crate::lifecycle::KernelSessionRegistry>,\n"
            "    index: u32,\n"
            ") -> Option<*mut crate::lifecycle::NativeSessionCell> {\n"
            "    let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };\n"
            "    let cell = unsafe { lock.cell_ptr(index) };\n"
            "    unsafe { lock.release() };\n"
            "    cell\n"
            "}\n",
            "registry cell projection",
        ),
    )
    for label, probe, expected in cross_module_capability_probes:
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-cross-module-") as work:
            shutil.copytree(
                os.path.join(repo, "driver", "fsring-fsd", "src"),
                os.path.join(work, "driver", "fsring-fsd", "src"),
            )
            core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
            os.makedirs(os.path.dirname(core_session), exist_ok=True)
            shutil.copy2(
                os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
                core_session,
            )
            fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
            with io.open(fence_path, "a", encoding="utf-8") as handle:
                handle.write(probe)
            planted = subprocess.run(
                [
                    sys.executable,
                    os.path.abspath(__file__),
                    "--production-check",
                    "--root",
                    work,
                    "--source-root",
                    "driver/fsring-core/src",
                    "--source-root",
                    "driver/fsring-fsd/src",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        check(
            planted.returncode == 1 and expected in planted.stderr,
            "%s must fail the global protected capability roster, "
            "got exit=%d stdout=%r stderr=%r"
            % (label, planted.returncode, planted.stdout, planted.stderr),
        )

    # Keep the call and owner counts constant while moving the lock release
    # ahead of the raw-cell dereference. Only the closed control trace can see
    # this mutation; it is the exact retained-after-unlock use the call roster
    # must not mistake for an approved Task 12 permanent-cell exception.
    locked_ledgers = (
        "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
        "        let verdict = match cell {\n"
        "            // SAFETY: the lock is held and the index is in range.\n"
        "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
        "            None => false,\n"
        "        };\n"
        "        unsafe { lock.release() };\n"
        "        verdict"
    )
    unlocked_ledgers = (
        "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
        "        unsafe { lock.release() };\n"
        "        let verdict = match cell {\n"
        "            // Mutant: the raw permanent-cell pointer outlives the lock.\n"
        "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
        "            None => false,\n"
        "        };\n"
        "        verdict"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-cell-control-") as work:
        shutil.copytree(
            os.path.join(repo, "driver", "fsring-fsd", "src"),
            os.path.join(work, "driver", "fsring-fsd", "src"),
        )
        core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
        os.makedirs(os.path.dirname(core_session), exist_ok=True)
        shutil.copy2(
            os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
            core_session,
        )
        fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
        with io.open(fence_path, encoding="utf-8") as handle:
            fence_source = handle.read()
        if fence_source.count(locked_ledgers) != 1:
            failures.append("locked ledger control probe anchor is not exact-one")
        with io.open(fence_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(fence_source.replace(locked_ledgers, unlocked_ledgers, 1))
        planted = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        planted.returncode == 1 and "owner/call/control/body grammar" in planted.stderr,
        "registry cell control roster must reject unlock-before-dereference, "
        "got exit=%d stdout=%r stderr=%r"
        % (planted.returncode, planted.stdout, planted.stderr),
    )

    # Keep the existing cell dereference in its expected locked position, but
    # copy the raw pointer first and dereference that alias after release. A
    # name-specific trace sees only `*cell` and incorrectly accepts this unless
    # assignments and every raw dereference are part of the closed grammar.
    aliased_ledgers = (
        "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
        "        let escaped = cell;\n"
        "        let _locked_observation = match cell {\n"
        "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
        "            None => false,\n"
        "        };\n"
        "        unsafe { lock.release() };\n"
        "        match escaped {\n"
        "            Some(escaped) => unsafe {\n"
        "                (*escaped).checkpoint_ledger_is_discharged(self.locator)\n"
        "            }\n"
        "            None => false,\n"
        "        }"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-cell-alias-") as work:
        shutil.copytree(
            os.path.join(repo, "driver", "fsring-fsd", "src"),
            os.path.join(work, "driver", "fsring-fsd", "src"),
        )
        core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
        os.makedirs(os.path.dirname(core_session), exist_ok=True)
        shutil.copy2(
            os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
            core_session,
        )
        fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
        with io.open(fence_path, encoding="utf-8") as handle:
            fence_source = handle.read()
        if fence_source.count(locked_ledgers) != 1:
            failures.append("aliased ledger control probe anchor is not exact-one")
        with io.open(fence_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(fence_source.replace(locked_ledgers, aliased_ledgers, 1))
        planted = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        planted.returncode == 1 and "owner/call/control/body grammar" in planted.stderr,
        "registry cell control roster must reject an aliased post-unlock dereference, "
        "got exit=%d stdout=%r stderr=%r"
        % (planted.returncode, planted.stdout, planted.stderr),
    )

    # Preserve the aggregate assignment and unary-dereference counts while
    # wrapping the permanent-cell pointer before release. The closed grammar
    # must reject the wrapper itself rather than relying on count changes.
    wrapped_ledgers = (
        "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
        "        let escaped = match cell {\n"
        "            Some(cell) => {\n"
        "                unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) };\n"
        "                NonNull::new(cell)\n"
        "            }\n"
        "            None => None,\n"
        "        };\n"
        "        unsafe { lock.release() };\n"
        "        match escaped {\n"
        "            Some(escaped) => unsafe {\n"
        "                escaped.as_ref().checkpoint_ledger_is_discharged(self.locator)\n"
        "            }\n"
        "            None => false,\n"
        "        }"
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-cell-wrapper-") as work:
        shutil.copytree(
            os.path.join(repo, "driver", "fsring-fsd", "src"),
            os.path.join(work, "driver", "fsring-fsd", "src"),
        )
        core_session = os.path.join(work, "driver", "fsring-core", "src", "session.rs")
        os.makedirs(os.path.dirname(core_session), exist_ok=True)
        shutil.copy2(
            os.path.join(repo, "driver", "fsring-core", "src", "session.rs"),
            core_session,
        )
        fence_path = os.path.join(work, "driver", "fsring-fsd", "src", "fence.rs")
        with io.open(fence_path, encoding="utf-8") as handle:
            fence_source = handle.read()
        if fence_source.count(locked_ledgers) != 1:
            failures.append("wrapped ledger control probe anchor is not exact-one")
        with io.open(fence_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(fence_source.replace(locked_ledgers, wrapped_ledgers, 1))
        planted = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    check(
        planted.returncode == 1 and "owner/call/control/body grammar" in planted.stderr,
        "registry cell grammar must reject a count-preserving post-unlock wrapper, "
        "got exit=%d stdout=%r stderr=%r"
        % (planted.returncode, planted.stdout, planted.stderr),
    )

    # Task 12's affine cutover is a cross-crate grammar, so exercise bypasses
    # against complete production copies.  Each probe asks for its own finding
    # family; an unrelated baseline failure therefore cannot make a probe pass.
    rust_identifier_cases = (
        ("ASCII", "Bundle", "Bundle"),
        ("lowercase", "bundle", "bundle"),
        ("non-ASCII", "\u03c4Bundle", "\u03c4Bundle"),
        ("combining mark", "dupe\u0301", "dup\u00e9"),
        ("Other_ID_Start", "\u2118bundle", "\u2118bundle"),
        ("Other_ID_Continue", "a\u00b7b", "a\u00b7b"),
        ("raw", "r#match", "match"),
        ("join control", "a\u200cb", "a\u200cb"),
    )
    for label, spelling, logical in rust_identifier_cases:
        check(
            rust_identifier_at(spelling, 0) == (logical, len(spelling)),
            "%s Rust identifier must scan as one normalized token" % label,
        )
    for spelling in ("9bundle", "\u0301bundle", "#bundle", "r#9bundle"):
        check(
            rust_identifier_at(spelling, 0) is None,
            "invalid Rust identifier start must be rejected: %r" % spelling,
        )
    check(
        rust_identifier_at("bundle-name", 0) == ("bundle", len("bundle")),
        "Rust identifier scanner must stop at an invalid delimiter",
    )
    unsafe_generic_body = (
        " { unsafe { core::hint::assert_unchecked(true) }; panic!() }"
    )
    generic_fabricator_rule_table = (
        ("borrowed only", "fn duplicate<T>(source: &T) -> T" + unsafe_generic_body, 1),
        ("mutably borrowed", "fn duplicate<T>(source: &mut T) -> T" + unsafe_generic_body, 1),
        ("nested borrow", "fn duplicate<T>(source: Option<&T>) -> T" + unsafe_generic_body, 1),
        (
            "borrowed plus owned",
            "fn substitute<T>(source: &T, replacement: T) -> T" + unsafe_generic_body,
            1,
        ),
        (
            "owned plus borrowed",
            "fn substitute<T>(replacement: T, source: &T) -> T" + unsafe_generic_body,
            1,
        ),
        (
            "alias borrow plus owned",
            "type Borrow<'a, U> = &'a U; "
            "fn substitute<'a, T>(source: Borrow<'a, T>, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        (
            "wrapper plus owned",
            "fn substitute<T>(source: Option<T>, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        (
            "pointer plus owned",
            "fn substitute<T>(source: *const T, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        (
            "path wrapper plus owned",
            "fn substitute<T>(source: crate::Wrapper<T>, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        (
            "associated type plus owned",
            "fn substitute<T: Trait>(source: <T as Trait>::Output, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        ("no owned input", "fn fabricate<T>() -> T" + unsafe_generic_body, 1),
        (
            "unsafe by-value identity",
            "fn identity<T>(value: T) -> T { "
            "unsafe { core::hint::assert_unchecked(true) }; value }",
            1,
        ),
        ("inline Copy", "fn copy<T: Copy>(source: &T) -> T" + unsafe_generic_body, 1),
        ("where Copy", "fn copy<T>(source: &T) -> T where T: Copy" + unsafe_generic_body, 1),
        (
            "qualified Copy",
            "fn copy<T: core::marker::Copy>(source: &T) -> T" + unsafe_generic_body,
            1,
        ),
        (
            "nested Copy is not a bound",
            "fn duplicate<T: Trait<Copy>>(source: &T) -> T" + unsafe_generic_body,
            1,
        ),
        (
            "Copy alias plus owned",
            "type Borrow<'a, U> = &'a U; "
            "fn copy<'a, T: Copy>(source: Borrow<'a, T>, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        (
            "multiple direct owned",
            "fn select<T>(first: T, second: T) -> T" + unsafe_generic_body,
            1,
        ),
        (
            "Deref projection plus owned",
            "fn substitute<T, U: core::ops::Deref<Target = T>>(source: U, replacement: T) -> T"
            + unsafe_generic_body,
            1,
        ),
        (
            "where Deref projection plus owned",
            "fn substitute<T, U>(source: U, replacement: T) -> T "
            "where U: core::ops::Deref<Target = T>"
            + unsafe_generic_body,
            1,
        ),
        (
            "unsafe API",
            "unsafe fn duplicate<T>(source: &T) -> T { "
            "unsafe { core::ptr::read(source) } }",
            0,
        ),
        (
            "safe body",
            "fn clone_safe<T: Clone>(source: &T) -> T { source.clone() }",
            0,
        ),
        (
            "safe by-value identity",
            "fn identity<T>(value: T) -> T { value }",
            0,
        ),
        (
            "unrelated generic borrow",
            "fn identity<T, U>(value: T, other: &U) -> T { "
            "unsafe { core::hint::assert_unchecked(true) }; value }",
            1,
        ),
        (
            "raw by-value identity",
            "fn identity<r#type>(value: r#type) -> r#type { "
            "unsafe { core::hint::assert_unchecked(true) }; value }",
            1,
        ),
        (
            "non-generic return",
            "fn inspect<T>(value: &T) -> usize" + unsafe_generic_body,
            0,
        ),
    )
    for label, source, expected in generic_fabricator_rule_table:
        check(
            len(generic_safe_fabricator_headers(source)) == expected,
            "%s generic fabricator rule must yield %d finding(s)" % (label, expected),
        )

    task12_jobs = []
    # Two independent counters, not one queue length. An emptied queue proves
    # only that nothing is *waiting*; these prove every probe that was declared
    # was also given a verdict, which is the property a silently dropped or
    # cleared-without-grading wave would break while still reading as covered.
    task12_declared = 0
    task12_graded = 0

    def task12_mutation(label, rel, old, new, expected, extra_edits=()):
        """Queue one planted whole-tree probe for the parallel wave.

        Every probe is an independent copy-edit-subprocess triple, so queueing
        them costs nothing but lets `flush_task12_mutations` use every core.
        Declaration order is preserved when the verdicts are graded.
        """
        nonlocal task12_declared
        task12_declared += 1
        task12_jobs.append((label, rel, old, new, expected, tuple(extra_edits)))

    def flush_task12_mutations():
        """Run every queued probe and grade the verdicts in declaration order."""
        nonlocal task12_graded
        if skip_task12_wave:
            task12_graded = task12_declared
            task12_jobs.clear()
            return
        if not task12_jobs:
            return
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(_SELF_TEST_WAVE_WIDTH, len(task12_jobs))
        ) as executor:
            outcomes = list(
                executor.map(
                    functools.partial(_run_task12_mutation_case, repo), task12_jobs
                )
            )
        # `strict` because a short result list would otherwise let `zip` drop
        # the tail silently, and the queue is cleared below either way -- the
        # exact shape of an ungraded probe that still reads as covered.
        for job, outcome in zip(task12_jobs, outcomes, strict=True):
            label, _rel, _old, _new, expected, _extra = job
            anchor_failures, returncode, stdout, stderr = outcome
            failures.extend(anchor_failures)
            check(
                returncode == 1 and expected in stderr,
                "%s must fail with %r, got exit=%d stdout=%r stderr=%r"
                % (label, expected, returncode, stdout, stderr),
            )
            task12_graded += 1
        del task12_jobs[:]

    # The attach-scratch rule, one probe per check. Each plants a different way
    # of putting the shared `KAPC_STATE` back and requires the shipped
    # production check to say so, so the rule cannot be quietly neutered: a
    # deleted check turns its own probe into a self-test failure.
    task12_mutation(
        "attach scratch: block-scoped static restored",
        "driver/fsring-fsd/src/session.rs",
        "    let session = context.session;\n"
        "    // SAFETY: the shell is written.\n"
        "    let process = unsafe { (*session).captured_process };",
        "    static mut APC_STATE: KAPC_STATE = unsafe { core::mem::zeroed() };\n"
        "    let session = context.session;\n"
        "    // SAFETY: the shell is written.\n"
        "    let process = unsafe { (*session).captured_process };",
        "roster changed: a new shared item is a candidate attach scratch",
    )
    task12_mutation(
        "attach scratch: top-level static restored",
        "driver/fsring-fsd/src/session.rs",
        "unsafe fn attach_captured(context: &mut SetupContext) -> Result<(), NTSTATUS> {",
        "static mut APC_STATE: KAPC_STATE = unsafe { core::mem::zeroed() };\n\n"
        "unsafe fn attach_captured(context: &mut SetupContext) -> Result<(), NTSTATUS> {",
        "declares KAPC_STATE storage",
    )
    task12_mutation(
        "attach scratch: fence call site respelled to a global",
        "driver/fsring-fsd/src/session.rs",
        "if !unsafe { attach_session_process(session, apc_state.as_mut_ptr()) } {\n"
        "        return false;\n"
        "    }\n"
        "    let mut ok = true;\n"
        "    let aliases = unsafe { (*session).aliases.as_mut_slice() };",
        "if !unsafe { attach_session_process(session, core::ptr::addr_of_mut!(APC_STATE)) } {\n"
        "        return false;\n"
        "    }\n"
        "    let mut ok = true;\n"
        "    let aliases = unsafe { (*session).aliases.as_mut_slice() };",
        "the attach/detach call roster changed",
    )
    task12_mutation(
        "attach scratch: detach argument respelled to a global",
        "driver/fsring-fsd/src/session.rs",
        "    unsafe { fsring_sys::c4::KeUnstackDetachProcess(context.apc_state.as_mut_ptr()) };\n"
        "    *attached = false;",
        "    unsafe { fsring_sys::c4::KeUnstackDetachProcess(core::ptr::addr_of_mut!(APC_STATE)) };\n"
        "    *attached = false;",
        "reaches a global rather than a frame or context binding",
    )
    task12_mutation(
        "raw affine-owner constructor",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl<Shell> NativeSessionOwner<Shell> {\n",
        "impl<Shell> NativeSessionOwner<Shell> {\n"
        "    pub unsafe fn from_raw(locator: SessionLocator, payload: Shell) -> Self {\n"
        "        Self { locator, payload }\n"
        "    }\n\n",
        "Task 12 protected authority surface",
    )
    task12_mutation(
        "second affine-owner consumer",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "pub fn native_owner_slots_match(\n",
        "pub fn consume_owner_again<Shell>(owner: NativeSessionOwner<Shell>) {\n"
        "    core::mem::forget(owner);\n"
        "}\n\n"
        "pub fn native_owner_slots_match(\n",
        "Task 12 sole native-owner consumer",
    )
    task12_mutation(
        "owner payload projection",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl<Shell> NativeSessionOwner<Shell> {\n",
        "impl<Shell> NativeSessionOwner<Shell> {\n"
        "    pub fn into_payload(self) -> Shell { self.payload }\n\n",
        "Task 12 protected authority surface",
    )
    task12_mutation(
        "missing finalizer generic",
        "driver/fsring-core/src/adapter/fence.rs",
        "pub struct R3FinalizerCell<Owners> {\n",
        "pub struct R3FinalizerCell {\n",
        "Task 12 protected generic declaration",
    )
    task12_mutation(
        "cross-crate owner alias rewrite",
        "driver/fsring-fsd/src/lifecycle.rs",
        "pub(crate) type NativeSessionOwner = CoreNativeSessionOwner<NativeSessionShell>;",
        "pub(crate) type NativeSessionOwner = NativeSessionShell;",
        "Task 12 protected alias",
    )
    task12_mutation(
        "path-shadowed lifecycle module",
        "driver/fsring-fsd/src/lib.rs",
        "mod lifecycle;",
        "#[path = \"shadow_lifecycle.rs\"]\nmod lifecycle;",
        "Task 12 production source shadow",
    )
    task12_mutation(
        "include-macro lifecycle rewrite",
        "driver/fsring-fsd/src/lib.rs",
        "mod lifecycle;",
        "include!(\"shadow_lifecycle.rs\");\nmod lifecycle;",
        "Task 12 production source shadow",
    )
    task12_mutation(
        "attribute-rewritten affine owner",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "pub struct NativeSessionOwner<Shell> {\n",
        "#[rewrite_affine_owner]\npub struct NativeSessionOwner<Shell> {\n",
        "Task 12 protected attribute or macro rewrite",
    )
    task12_mutation(
        "macro-generated affine owner",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "pub struct NativeSessionOwner<Shell> {\n",
        "macro_rules! NativeSessionOwner { () => {}; }\n"
        "pub struct NativeSessionOwner<Shell> {\n",
        "Task 12 protected attribute or macro rewrite",
    )
    task12_mutation(
        "second prepared-delete payload implementation",
        "driver/fsring-fsd/src/lifecycle.rs",
        "/// A preflighted native mount activation.\n",
        "unsafe impl fsring_core::adapter::fence::PreparedDeleteStorageOps<DriverRootRelease>\n"
        "    for UnpublishedNativeSessionShell\n"
        "{\n"
        "    unsafe fn destroy_shell_then_release_root(\n"
        "        self, root: DriverRootRelease,\n"
        "        _permit: &fsring_core::adapter::fence::PreparedDeleteExecutionPermit,\n"
        "    ) { core::mem::forget(self); core::mem::forget(root); }\n"
        "}\n\n"
        "/// A preflighted native mount activation.\n",
        "Task 12 sole prepared-delete payload impl",
    )
    task12_mutation(
        "prepared-delete payload body omission",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };\n"
        "        unsafe { root.state.as_ref() }.release();",
        "        core::mem::forget(self);\n"
        "        core::mem::forget(root);",
        "Task 12 prepared-delete payload order",
    )
    task12_mutation(
        "prepared-delete payload order reversal",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };\n"
        "        unsafe { root.state.as_ref() }.release();",
        "        unsafe { root.state.as_ref() }.release();\n"
        "        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };",
        "Task 12 prepared-delete payload order",
    )
    task12_mutation(
        "kick queue accepts copied locator",
        "driver/fsring-fsd/src/lifecycle.rs",
        "pub(crate) unsafe fn queue_cell_finalizer(admitted: AdmittedR3FinalizerKick) {\n"
        "    let (registry, admitted) = admitted.into_parts();\n"
        "    let locator = admitted.locator();",
        "pub(crate) unsafe fn queue_cell_finalizer(\n"
        "    registry: NonNull<KernelSessionRegistry>,\n"
        "    locator: SessionLocator,\n"
        ") {",
        "Task 12 finalizer queue boundary",
    )
    task12_mutation(
        "kick queue retains kick after locator projection",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    let (registry, admitted) = admitted.into_parts();\n"
        "    let locator = admitted.locator();\n",
        "    let (registry, admitted) = admitted.into_parts();\n"
        "    let locator = admitted.locator();\n"
        "    let _retained_kick = admitted;\n",
        "Task 12 finalizer queue boundary",
    )
    task12_mutation(
        "kick queue passes null callback context",
        "driver/fsring-fsd/src/lifecycle.rs",
        "                fsring_sys::c4::DelayedWorkQueue,\n"
        "                context,\n",
        "                fsring_sys::c4::DelayedWorkQueue,\n"
        "                core::ptr::null_mut(),\n",
        "Task 12 finalizer queue boundary",
    )
    task12_mutation(
        "finalizer callback restores nullable refusal",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    let context = unsafe { NonNull::new_unchecked(context.cast::<FinalizerWorkItemContext>()) };",
        "    let Some(context) = NonNull::new(context.cast::<FinalizerWorkItemContext>()) else {\n"
        "        return;\n"
        "    };",
        "Task 12 finalizer callback",
    )
    task12_mutation(
        "final reset drops bundled cursor",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    pending: fsring_core::adapter::fence::PendingFinalDeleteReset<\n"
        "        crate::fence::PreparedCellResetRight,\n"
        "    >,",
        "    pending: fsring_core::adapter::fence::PendingFinalDeleteReset,",
        "Task 12 final-delete cursor/reset bundle",
    )
    task12_mutation(
        # The ten-step order moved into core with the suffix; the plant follows.
        "join drain moves after access rundown",
        "driver/fsring-core/src/adapter/fence.rs",
        "    unsafe { native.wait_joiners_drained(locator) };\n"
        "    let cursor = cursor.joiners_drained();\n\n"
        "    unsafe { native.complete_access_rundown(locator) };\n"
        "    let cursor = cursor.access_rundown_completed();",
        "    unsafe { native.complete_access_rundown(locator) };\n"
        "    let cursor = cursor.access_rundown_completed();\n\n"
        "    unsafe { native.wait_joiners_drained(locator) };\n"
        "    let cursor = cursor.joiners_drained();",
        "Task 12 final-delete suffix order and post-destroy access",
    )
    task12_mutation(
        "native delete mirror omits the Deleting phase",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "    phase == NativeCellPhase::Deleting\n"
        "        && generation == requested.generation()",
        "    generation == requested.generation()",
        "Task 12 delete mirror Deleting phase",
    )
    task12_mutation(
        "queued deposit omits the native Deleting transition",
        "driver/fsring-fsd/src/lifecycle.rs",
        "            Ok(kick) => {\n"
        "                self.phase = NativeCellPhase::Deleting;\n"
        "                Ok(kick)\n"
        "            }",
        "            Ok(kick) => Ok(kick)",
        "Task 12 native Deleting transition",
    )
    task12_mutation(
        # The impossible-take arm is a permanent park, not a return: silently
        # returning would drop a deposit the kick proves exists. The plant swaps
        # the fail-stop for exactly that lost-work return.
        "exact-cell worker restores a nullable lost-work return",
        "driver/fsring-fsd/src/fence.rs",
        "    let Some((deposit, running, handoff_right)) =\n"
        "        (unsafe { (*cell).take_deposit_and_run_for_callback(cell_index, context) })\n"
        "    else {\n"
        "        unsafe { lock.release() };\n"
        "        unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }\n"
        "    };",
        "    let Some((deposit, running, handoff_right)) =\n"
        "        (unsafe { (*cell).take_deposit_and_run_for_callback(cell_index, context) })\n"
        "    else {\n"
        "        unsafe { lock.release() };\n"
        "        return;\n"
        "    };",
        "Task 12 exact-cell finalizer callback",
    )
    task12_mutation(
        # `storage.execute()` moved into core with the suffix.
        "prepared-delete suffix restores a post-destroy debug assertion",
        "driver/fsring-core/src/adapter/fence.rs",
        "    let cursor = unsafe { storage.execute() };\n"
        "    let locator = cursor.locator();",
        "    let cursor = unsafe { storage.execute() };\n"
        "    let locator = cursor.locator();\n"
        "    debug_assert!(locator.slot_index() != u32::MAX);",
        "Task 12 final-delete suffix order and post-destroy access",
    )
    task12_mutation(
        "prevalidated core finish restores panic-capable slot lookup",
        "driver/fsring-core/src/session.rs",
        "        let index = unsafe { usize::try_from(prepared.authority.slot_index).unwrap_unchecked() };\n"
        "        let slot = unsafe { self.slots.get_unchecked_mut(index) };",
        "        let index = usize::try_from(prepared.authority.slot_index).unwrap();\n"
        "        let slot = &mut self.slots[index];",
        "Task 12 prevalidated finish-delete",
    )
    task12_mutation(
        "blocked checkpoint observation accepts a copied locator",
        "driver/fsring-fsd/src/fence.rs",
        "    pub(crate) const fn blocked_observation(&self) -> TerminalBlocked {\n"
        "        TerminalBlocked::from_fence(\n"
        "            self.result.locator(),",
        "    pub(crate) const fn blocked_observation(\n"
        "        &self, locator: SessionLocator,\n"
        "    ) -> TerminalBlocked {\n"
        "        TerminalBlocked::from_fence(\n"
        "            locator,",
        "Task 12 blocked observation authority",
    )
    task12_mutation(
        "ClosingLive locator check is omitted while the lease remains",
        "driver/fsring-fsd/src/fence.rs",
        "        unsafe {\n"
        "            crate::control::binding_is_closing_live(self.closing.context(), locator)\n"
        "                && crate::control::lifetime_is_cell_owned(self.closing.context())\n"
        "        }",
        "        unsafe { crate::control::lifetime_is_cell_owned(self.closing.context()) }",
        "Task 12 exact ClosingLive and owned lease",
    )
    task12_mutation(
        "open outcome and event omit the counted admission bounds",
        "driver/fsring-fsd/src/lifecycle.rs",
        "            outcome_open_and_admission_open: outcome_is_open\n"
        "                && outcome_event_is_nonsignaled\n"
        "                && admitted_joiners > 0\n"
        "                && admitted_joiners < u32::MAX,",
        "            outcome_open_and_admission_open: outcome_is_open\n"
        "                && outcome_event_is_nonsignaled,",
        "Task 12 open join admission observation",
    )

    # Task 12 mount-publication closure.  These probes are deliberately
    # one-mutation production copies: each bypass must trip the mount-specific
    # grammar rather than merely inheriting a failure from some other frozen
    # Task 12 surface.
    task12_mutation(
        "mount preparer accepts a separate A/B observation",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    lock: &'lock mut RegistryLockGuard,\n"
        "    bundle: Bundle,\n"
        ") -> Result<PreparedLockedMountPublication<'lock, Bundle>, (LifecycleError, Bundle)>",
        "    lock: &'lock mut RegistryLockGuard,\n"
        "    bundle: Bundle,\n"
        "    observation: MountPublicationObservation<Bundle::Kind>,\n"
        ") -> Result<PreparedLockedMountPublication<'lock, Bundle>, (LifecycleError, Bundle)>",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "mount bundle maps Done to the wrong Kind",
        "driver/fsring-fsd/src/lifecycle.rs",
        "impl LockedMountPublicationBundle for MountDonePublication {\n"
        "    type Kind = fsring_core::adapter::lifecycle::MountDonePublicationKind;",
        "impl LockedMountPublicationBundle for MountDonePublication {\n"
        "    type Kind = fsring_core::adapter::lifecycle::MountJoinConversionKind;",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "mount bundle refusal returns a replacement bundle",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        None => return Err((LifecycleError::WrongLocator, bundle)),",
        "        None => return Err((LifecycleError::WrongLocator, unsafe { core::mem::zeroed() })),",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "prepared mount aggregate drops its guard borrow",
        "driver/fsring-fsd/src/lifecycle.rs",
        "pub(crate) struct PreparedLockedMountPublication<'lock, Bundle> {\n"
        "    lock: &'lock mut RegistryLockGuard,",
        "pub(crate) struct PreparedLockedMountPublication<'lock, Bundle> {\n"
        "    lock: *mut RegistryLockGuard,",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount publisher accepts a separate raw cell",
        "driver/fsring-fsd/src/lifecycle.rs",
        "pub(crate) unsafe fn publish_mount_complete_locked(\n"
        "    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,\n"
        ") -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)>",
        "pub(crate) unsafe fn publish_mount_complete_locked(\n"
        "    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,\n"
        "    raw_cell: *mut NativeSessionCell,\n"
        ") -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)>",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount preparer selects a copied cell index",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    let cell = match unsafe { lock.cell_ptr(locator.slot_index()) } {\n"
        "        Some(cell) => cell,",
        "    let cell = match unsafe { lock.cell_ptr(0) } {\n"
        "        Some(cell) => cell,",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount preparer omits the native generation check",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        (*cell).generation == locator.generation()\n"
        "            && (*cell).identity == Some(locator.identity())\n"
        "            && (*cell)\n"
        "                .mount_rendezvous()\n"
        "                .matches_publication_observation(&observation)",
        "        (*cell).identity == Some(locator.identity())\n"
        "            && (*cell)\n"
        "                .mount_rendezvous()\n"
        "                .matches_publication_observation(&observation)",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount preparer omits the private Kind/generation validation",
        "driver/fsring-fsd/src/lifecycle.rs",
        "            && (*cell)\n"
        "                .mount_rendezvous()\n"
        "                .matches_publication_observation(&observation)",
        "            && true",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount preparer substitutes the wrong native event",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        MountWaitEvent::OrdinaryWaitersDrained => MountCellEvent::WaitersDrained,",
        "        MountWaitEvent::OrdinaryWaitersDrained => MountCellEvent::ResetWaitersDrained,",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount publisher relooks up a raw cell after preparation",
        "driver/fsring-fsd/src/lifecycle.rs",
        "pub(crate) unsafe fn publish_mount_complete_locked(\n"
        "    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,\n"
        ") -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {\n"
        "    let PreparedLockedMountPublication {\n"
        "        lock: _lock,\n"
        "        cell,\n"
        "        event,\n"
        "        bundle: publication,\n"
        "    } = prepared;\n"
        "    unsafe {",
        "pub(crate) unsafe fn publish_mount_complete_locked(\n"
        "    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,\n"
        ") -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {\n"
        "    let PreparedLockedMountPublication {\n"
        "        lock: _lock,\n"
        "        cell,\n"
        "        event,\n"
        "        bundle: publication,\n"
        "    } = prepared;\n"
        "    let _raw = unsafe { _lock.cell_ptr(cell.as_ptr() as u32) };\n"
        "    unsafe {",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "mount signal uses Wait TRUE",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        fsring_sys::c4::KeSetEvent(event.as_ptr(), 0, 0 as fsring_sys::BOOLEAN);",
        "        fsring_sys::c4::KeSetEvent(event.as_ptr(), 0, 1 as fsring_sys::BOOLEAN);",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        "mount publisher unlocks before signalling",
        "driver/fsring-fsd/src/lifecycle.rs",
        "pub(crate) unsafe fn publish_mount_complete_locked(\n"
        "    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,\n"
        ") -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {\n"
        "    let PreparedLockedMountPublication {\n"
        "        lock: _lock,\n"
        "        cell,\n"
        "        event,\n"
        "        bundle: publication,\n"
        "    } = prepared;\n"
        "    unsafe {",
        "pub(crate) unsafe fn publish_mount_complete_locked(\n"
        "    prepared: PreparedLockedMountPublication<'_, MountDonePublication>,\n"
        ") -> Result<MountDrainRight, (LifecycleError, MountDoneAcknowledgement)> {\n"
        "    let PreparedLockedMountPublication {\n"
        "        lock,\n"
        "        cell,\n"
        "        event,\n"
        "        bundle: publication,\n"
        "    } = prepared;\n"
        "    unsafe { lock.release() };\n"
        "    unsafe {",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        "mount publisher skips its signal",
        "driver/fsring-fsd/src/lifecycle.rs",
        "            .run_done_signal_ack(publication, |_| {\n"
        "                let Some(event) = event else {\n"
        "                    core::hint::unreachable_unchecked()\n"
        "                };\n"
        "                set_prepared_mount_event(event);\n"
        "            })",
        "            .run_done_signal_ack(publication, |_| {\n"
        "                let Some(event) = event else {\n"
        "                    core::hint::unreachable_unchecked()\n"
        "                };\n"
        "                let _retained = event;\n"
        "            })",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        "mount publisher signals twice",
        "driver/fsring-fsd/src/lifecycle.rs",
        "            .run_ordinary_drained_signal_ack(conversion, |_| {\n"
        "                let Some(event) = event else {\n"
        "                    core::hint::unreachable_unchecked()\n"
        "                };\n"
        "                set_prepared_mount_event(event);\n"
        "            })",
        "            .run_ordinary_drained_signal_ack(conversion, |_| {\n"
        "                let Some(event) = event else {\n"
        "                    core::hint::unreachable_unchecked()\n"
        "                };\n"
        "                set_prepared_mount_event(event);\n"
        "                set_prepared_mount_event(event);\n"
        "            })",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        "nonlast mount release fabricates a signal",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "            None => false,\n"
        "        };\n"
        "        MountResetJoinAcknowledgement {",
        "            None => {\n"
        "                signal(unsafe { core::mem::zeroed() });\n"
        "                true\n"
        "            }\n"
        "        };\n"
        "        MountResetJoinAcknowledgement {",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        # Under the forwarder shape the native publisher hands both halves to
        # core in ONE call, so a native gap between signal and ack is no longer
        # expressible. The window that remains is core's own, and that is where
        # the plant has to go: anything between `signal_then_ack` and the
        # matching acknowledgement widens the exact interval this rule exists
        # to keep empty.
        "mount publisher performs work between signal and ack",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "    let acknowledgement = unsafe { publication.signal_then_ack(signal) };\n"
        "    rendezvous.acknowledge_done_signal(acknowledgement)",
        "    let acknowledgement = unsafe { publication.signal_then_ack(signal) };\n"
        "    core::hint::spin_loop();\n"
        "    rendezvous.acknowledge_done_signal(acknowledgement)",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        "mount wake performs work before reacquiring the registry",
        "driver/fsring-fsd/src/fence.rs",
        "    unsafe fn complete_mount_join(\n"
        "        &self,\n"
        "        ticket: fsring_core::adapter::lifecycle::MountJoinTicket,\n"
        "    ) -> CompletedMountTeardown {\n"
        "        unsafe { self.wait_mount(ticket.wait_observation()) };\n"
        "        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };\n"
        "        let cell = unsafe {\n"
        "            lock.cell_ptr(self.locator.slot_index())",
        "    unsafe fn complete_mount_join(\n"
        "        &self,\n"
        "        ticket: fsring_core::adapter::lifecycle::MountJoinTicket,\n"
        "    ) -> CompletedMountTeardown {\n"
        "        unsafe { self.wait_mount(ticket.wait_observation()) };\n"
        "        core::hint::spin_loop();\n"
        "        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };\n"
        "        let cell = unsafe {\n"
        "            lock.cell_ptr(self.locator.slot_index())",
        "Task 12 mount wake-to-registry-first",
    )
    task12_mutation(
        "late Join retry drops its returned drain right",
        "driver/fsring-fsd/src/fence.rs",
        "                    unsafe { lock.release() };\n"
        "                    drain = returned;\n"
        "                }\n"
        "                Err((_error, returned)) => {",
        "                    unsafe { lock.release() };\n"
        "                    core::mem::drop(returned);\n"
        "                }\n"
        "                Err((_error, returned)) => {",
        "Task 12 late Join drain retry authority",
    )
    task12_mutation(
        "late Join retry replaces its returned drain right",
        "driver/fsring-fsd/src/fence.rs",
        "                    drain = returned;\n"
        "                }\n"
        "                Err((_error, returned)) => {",
        "                    let _retained = returned;\n"
        "                    drain = unsafe { core::mem::zeroed() };\n"
        "                }\n"
        "                Err((_error, returned)) => {",
        "Task 12 late Join drain retry authority",
    )
    task12_mutation(
        "late Join retry forgets its returned drain right",
        "driver/fsring-fsd/src/fence.rs",
        "                    drain = returned;\n"
        "                }\n"
        "                Err((_error, returned)) => {",
        "                    core::mem::forget(returned);\n"
        "                }\n"
        "                Err((_error, returned)) => {",
        "Task 12 late Join drain retry authority",
    )
    task12_mutation(
        "late Join retry accepts an unrelated error",
        "driver/fsring-fsd/src/fence.rs",
        "                Err((_error, returned)) => {\n"
        "                    unsafe { lock.release() };\n"
        "                    let _retained = returned;\n"
        "                    unreachable!(\"an authentic drain right can only race a late ordinary Join\")\n"
        "                }",
        "                Err((_error, returned)) => {\n"
        "                    unsafe { lock.release() };\n"
        "                    drain = returned;\n"
        "                    continue;\n"
        "                }",
        "Task 12 late Join drain retry authority",
    )
    task12_mutation(
        "late Join retry replays destructive work",
        "driver/fsring-fsd/src/fence.rs",
        "                Err((LifecycleError::AdmissionClosed, returned)) => {\n"
        "                    unsafe { lock.release() };\n"
        "                    drain = returned;\n"
        "                }",
        "                Err((LifecycleError::AdmissionClosed, returned)) => {\n"
        "                    unsafe { lock.release() };\n"
        "                    self.delete_shell_vdo();\n"
        "                    drain = returned;\n"
        "                }",
        "Task 12 late Join drain retry authority",
    )
    task12_mutation(
        "Join executes mount-owned teardown effects",
        "driver/fsring-fsd/src/fence.rs",
        "    unsafe fn complete_mount_join(\n"
        "        &self,\n"
        "        ticket: fsring_core::adapter::lifecycle::MountJoinTicket,\n"
        "    ) -> CompletedMountTeardown {\n"
        "        unsafe { self.wait_mount(ticket.wait_observation()) };\n"
        "        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };",
        "    unsafe fn complete_mount_join(\n"
        "        &self,\n"
        "        ticket: fsring_core::adapter::lifecycle::MountJoinTicket,\n"
        "    ) -> CompletedMountTeardown {\n"
        "        unsafe { self.wait_mount(ticket.wait_observation()) };\n"
        "        unsafe { vpb.clear_binding() };\n"
        "        unsafe { mounted.delete() };\n"
        "        unsafe { self.release_mount_reference(reference) };\n"
        "        let mut lock = unsafe { KernelSessionRegistry::lock(self.registry) };",
        "Task 12 mount-owned teardown owner-only",
    )
    task12_mutation(
        "shell VDO is deleted before authentic completion bind",
        "driver/fsring-fsd/src/fence.rs",
        "    ) -> bool {\n"
        "        match bind_completed_mount_teardown(expected, completed) {\n"
        "            Ok(bound) => {",
        "    ) -> bool {\n"
        "        self.delete_shell_vdo();\n"
        "        match bind_completed_mount_teardown(expected, completed) {\n"
        "            Ok(bound) => {",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "shell VDO post-bind deletion is missing",
        "driver/fsring-fsd/src/fence.rs",
        "                self.bound_mount = Some(bound);\n"
        "                self.delete_shell_vdo();\n"
        "                permitted",
        "                self.bound_mount = Some(bound);\n"
        "                permitted",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "shell VDO post-bind deletion runs twice",
        "driver/fsring-fsd/src/fence.rs",
        "                self.bound_mount = Some(bound);\n"
        "                self.delete_shell_vdo();\n"
        "                permitted",
        "                self.bound_mount = Some(bound);\n"
        "                self.delete_shell_vdo();\n"
        "                self.delete_shell_vdo();\n"
        "                permitted",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "shell VDO deletion is restored inside the Join claim",
        "driver/fsring-fsd/src/fence.rs",
        "            Ok(MountClaim::Join { ticket, expected }) => {\n"
        "                let _ = expected;\n"
        "                unsafe { self.complete_mount_join(ticket) }\n"
        "            }",
        "            Ok(MountClaim::Join { ticket, expected }) => {\n"
        "                let _ = expected;\n"
        "                self.delete_shell_vdo();\n"
        "                unsafe { self.complete_mount_join(ticket) }\n"
        "            }",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "shell VDO deletion runs on bind refusal",
        "driver/fsring-fsd/src/fence.rs",
        "            Err(pending) => {\n"
        "                self.pending_mount_bind = Some(pending);\n"
        "                false\n"
        "            }",
        "            Err(pending) => {\n"
        "                self.pending_mount_bind = Some(pending);\n"
        "                self.delete_shell_vdo();\n"
        "                false\n"
        "            }",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "commit revalidation reacquires the already-held VPB spin lock",
        "driver/fsring-fsd/src/volume.rs",
        "            if !commit_revalidation_has_vpb_lock(context.vpb_held) {\n"
        "                return None;\n"
        "            }\n"
        "            // SAFETY: the VPB lock is held.\n"
        "            let vpb = mount_vpb(context)?;",
        "            if !unsafe { acquire_vpb(context) }\n"
        "                || !commit_revalidation_has_vpb_lock(context.vpb_held)\n"
        "            {\n"
        "                return None;\n"
        "            }\n"
        "            // SAFETY: the VPB lock is held.\n"
        "            let vpb = mount_vpb(context)?;",
        "Task 12 mount commit VPB lock continuity",
    )
    task12_mutation(
        "null session is accepted as a successful shell VDO delete",
        "driver/fsring-fsd/src/session.rs",
        "    if session.is_null() {\n"
        "        return false;\n"
        "    }\n"
        "    let device = unsafe { core::mem::replace(&mut (*session).vdo, core::ptr::null_mut()) };",
        "    if session.is_null() {\n"
        "        return true;\n"
        "    }\n"
        "    let device = unsafe { core::mem::replace(&mut (*session).vdo, core::ptr::null_mut()) };",
        "Task 12 shell VDO take-once deletion",
    )
    task12_mutation(
        "taken VDO slot is accepted as a replayed successful delete",
        "driver/fsring-fsd/src/session.rs",
        "    if !vdo_slot_contains_device(device) {\n"
        "        return false;\n"
        "    }\n"
        "    unsafe { crate::volume::delete(device) };",
        "    if !vdo_slot_contains_device(device) {\n"
        "        return true;\n"
        "    }\n"
        "    unsafe { crate::volume::delete(device) };",
        "Task 12 shell VDO take-once deletion",
    )
    task12_mutation(
        "pre-Bind refusal adds a blanket foreign VPB clear",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_COMMIT_VPB: &[MountRollbackEffect] = &[\n"
        "    MountRollbackEffect::ReleaseVpbIfHeld,",
        "const ROLLBACK_COMMIT_VPB: &[MountRollbackEffect] = &[\n"
        "    MountRollbackEffect::ClearUnpublishedVpbBinding,\n"
        "    MountRollbackEffect::ReleaseVpbIfHeld,",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "native mount executor discards the exact Plan(Mount) rollback",
        "driver/fsring-fsd/src/volume.rs",
        "                // SAFETY: the core returned the exact post-effect rollback. In\n"
        "                // particular, a refused pre-Bind revalidation cannot clear a\n"
        "                // foreign VPB binding.\n"
        "                unsafe { unwind_mount(context, rollback.effects()) };",
        "                let _retained = rollback;\n"
        "                unsafe {\n"
        "                    unwind_mount(\n"
        "                        context,\n"
        "                        &[MountRollbackEffect::ClearUnpublishedVpbBinding],\n"
        "                    )\n"
        "                };",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "lowercase extra rollback slice escapes the exact plan roster",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n"
        "const rollback_shadow: &[MountRollbackEffect] = &[\n"
        "    MountRollbackEffect::ClearUnpublishedVpbBinding,\n"
        "];\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "rollback reference plan substitutes the wrong effect",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_REFERENCE: &[MountRollbackEffect] = &[MountRollbackEffect::ReleaseSessionReference];",
        "const ROLLBACK_REFERENCE: &[MountRollbackEffect] = &[MountRollbackEffect::ReleaseVpbIfHeld];",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "native unwind bypasses the selected rollback effect",
        "driver/fsring-fsd/src/volume.rs",
        "        unsafe { undo_mount(context, effect) };\n",
        "        let _bypassed = (context, effect);\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "VPB rollback omits its acquire-clear-release suffix",
        "driver/fsring-fsd/src/volume.rs",
        "            if acquired_here {\n",
        "            if false && acquired_here {\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "mount rollback suppresses its session-reference release branch",
        "driver/fsring-fsd/src/volume.rs",
        "            if let Some(reference) = context.reference.take() {\n",
        "            if let Some(reference) = None {\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "mount owner exposure receipt gains manual Clone and Copy impls",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountOwnerPublication {\n"
        "    pub const fn locator(&self) -> SessionLocator {\n",
        "impl Clone for MountOwnerPublication {\n"
        "    fn clone(&self) -> Self {\n"
        "        Self {\n"
        "            locator: self.locator,\n"
        "            mount_generation: self.mount_generation,\n"
        "            publication_id: self.publication_id,\n"
        "            authority: PrivateMountPublicationAuthority(()),\n"
        "        }\n"
        "    }\n"
        "}\n\n"
        "impl Copy for MountOwnerPublication {}\n\n"
        "impl MountOwnerPublication {\n"
        "    pub const fn locator(&self) -> SessionLocator {\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "mount publication bundle gains an unsafe Clone impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "impl Clone for MountDonePublication {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "mount publication bundle gains a duplicate method",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "impl MountJoinConversion {\n"
        "    pub unsafe fn duplicate(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "local type alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "type MountDoneAlias = MountDonePublication;\n"
        "impl Clone for MountDoneAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "self-qualified type alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "type MountJoinAlias = self::MountJoinConversion;\n"
        "impl Clone for MountJoinAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "crate-qualified type alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountResetPublication {\n"
        "    pub const fn publication_observation(\n",
        "type MountResetAlias = crate::adapter::lifecycle::MountResetPublication;\n"
        "impl Clone for MountResetAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountResetPublication {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "use-alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountResetJoinRelease {\n"
        "    pub const fn publication_observation(\n",
        "use self::MountResetJoinRelease as MountResetJoinReleaseAlias;\n"
        "impl Clone for MountResetJoinReleaseAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountResetJoinRelease {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "grouped use-alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "use self::{MountDonePublication as GroupedMountDoneAlias};\n"
        "impl Clone for GroupedMountDoneAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "nested grouped use-alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "use crate::adapter::{lifecycle::MountJoinConversion as NestedMountJoinAlias};\n"
        "impl Clone for NestedMountJoinAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "nested module type alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "mod hidden_mount_done_alias {\n"
        "    type Alias = super::MountDonePublication;\n"
        "    impl Clone for Alias {\n"
        "        fn clone(&self) -> Self {\n"
        "            unsafe { core::ptr::read(self) }\n"
        "        }\n"
        "    }\n"
        "}\n\n"
        "impl MountDonePublication {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "nested module use alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "mod hidden_mount_join_alias {\n"
        "    use super::{MountJoinConversion as Alias};\n"
        "    impl Clone for Alias {\n"
        "        fn clone(&self) -> Self {\n"
        "            unsafe { core::ptr::read(self) }\n"
        "        }\n"
        "    }\n"
        "}\n\n"
        "impl MountJoinConversion {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "where-clause alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "impl MountResetPublication {\n"
        "    pub const fn publication_observation(\n",
        "type Alias where (): Sized = MountResetPublication;\n"
        "impl Clone for Alias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n\n"
        "impl MountResetPublication {\n"
        "    pub const fn publication_observation(\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "cross-file type alias gains a duplicating bundle impl",
        "driver/fsring-core/src/adapter/mod.rs",
        "pub mod lifecycle;\n",
        "pub mod lifecycle;\n"
        "type MountDoneAlias = lifecycle::MountDonePublication;\n"
        "impl Clone for MountDoneAlias {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "cross-file path-qualified bundle impl duplicates authority",
        "driver/fsring-core/src/adapter/mod.rs",
        "pub mod lifecycle;\n",
        "pub mod lifecycle;\n"
        "impl Clone for crate::adapter::lifecycle::MountJoinConversion {\n"
        "    fn clone(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "cross-file blanket trait duplicates every bundle",
        "driver/fsring-core/src/adapter/mod.rs",
        "pub mod lifecycle;\n",
        "pub mod lifecycle;\n"
        "pub trait DuplicateBundle: Sized {\n"
        "    fn duplicate_bundle(&self) -> Self;\n"
        "}\n"
        "impl<T> DuplicateBundle for T {\n"
        "    fn duplicate_bundle(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "mount publication bundle derives Clone",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "#[derive(Debug)]\n"
        "pub struct MountDonePublication {\n",
        "#[derive(Debug, Clone)]\n"
        "pub struct MountDonePublication {\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "count-preserving generic free function duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn duplicate<T>(value: &T) -> T {\n"
        "            unsafe { core::ptr::read(value) }\n"
        "        }\n"
        "        let _duplicate = duplicate::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "lowercase generic free function duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn duplicate<t>(value: &t) -> t {\n"
        "            unsafe { core::ptr::read(value) }\n"
        "        }\n"
        "        let _duplicate = duplicate::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "Unicode generic free function duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn duplicate<\u03c4>(value: &\u03c4) -> \u03c4 {\n"
        "            unsafe { core::ptr::read(value) }\n"
        "        }\n"
        "        let _duplicate = duplicate::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "combining-mark function name duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn duplicat\u0301e<T>(value: &T) -> T {\n"
        "            unsafe { core::ptr::read(value) }\n"
        "        }\n"
        "        let _duplicate = duplicat\u0301e::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "Other_ID_Start function name duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn \u2118<T>(value: &T) -> T {\n"
        "            unsafe { core::ptr::read(value) }\n"
        "        }\n"
        "        let _duplicate = \u2118::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "Other_ID_Continue function name duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn a\u00b7b<T>(value: &T) -> T {\n"
        "            unsafe { core::ptr::read(value) }\n"
        "        }\n"
        "        let _duplicate = a\u00b7b::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "owned replacement hides a borrowed bundle duplication",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn substitute<T>(source: &T, replacement: T) -> T {\n"
        "            let _replacement = replacement;\n"
        "            unsafe { core::ptr::read(source) }\n"
        "        }\n"
        "        let _duplicate = substitute::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "generic borrow alias hides a bundle duplication",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        type Borrow<'a, U> = &'a U;\n"
        "        fn substitute<'a, T>(source: Borrow<'a, T>, replacement: T) -> T {\n"
        "            let _replacement = replacement;\n"
        "            unsafe { core::ptr::read(source) }\n"
        "        }\n"
        "        let _duplicate = substitute::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "Deref projection hides a bundle duplication",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn substitute<T, U: core::ops::Deref<Target = T>>(\n"
        "            source: U, replacement: T,\n"
        "        ) -> T {\n"
        "            let _replacement = replacement;\n"
        "            unsafe { core::ptr::read(&*source) }\n"
        "        }\n"
        "        let _duplicate = substitute::<Self, &Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "unsafe by-value identity duplicates a bundle",
        "driver/fsring-core/src/effect.rs",
        "    pub const unsafe fn empty() -> Self {\n",
        "    pub const fn empty() -> Self {\n"
        "        fn duplicate<T>(value: T) -> T {\n"
        "            unsafe { core::ptr::read(&value) }\n"
        "        }\n"
        "        let _duplicate = duplicate::<Self>;\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "known safe generic unsafe-return whitelist body drifts",
        "driver/fsring-core/src/adapter/fence.rs",
        "        if commit.locator() != self.locator || running.locator() != self.locator {\n",
        "        if commit.locator() == self.locator || running.locator() != self.locator {\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "macro-generated blanket trait duplicates every bundle",
        "driver/fsring-core/src/effect.rs",
        "#[cfg(test)]\nmod tests {\n",
        "pub trait DuplicateBundle: Sized {\n"
        "    fn duplicate_bundle(&self) -> Self;\n"
        "}\n"
        "macro_rules! blanket_duplicate {\n"
        "    ($($generic:tt)*) => {\n"
        "        impl $($generic)* DuplicateBundle for T {\n"
        "            fn duplicate_bundle(&self) -> Self {\n"
        "                unsafe { core::ptr::read(self) }\n"
        "            }\n"
        "        }\n"
        "    };\n"
        "}\n"
        "blanket_duplicate!(<T>);\n\n"
        "#[cfg(test)]\nmod tests {\n",
        "Task 12 locked mount bundle kind seal",
        extra_edits=((
            "driver/fsring-core/src/effect.rs",
            "    pub const unsafe fn empty() -> Self {\n",
            "    pub const fn empty() -> Self {\n",
        ),),
    )
    task12_mutation(
        "const-generic blanket trait duplicates every bundle",
        "driver/fsring-core/src/adapter/mod.rs",
        "pub mod lifecycle;\n",
        "pub mod lifecycle;\n"
        "pub trait DuplicateBundle<const N: usize>: Sized {\n"
        "    fn duplicate_bundle(&self) -> Self;\n"
        "}\n"
        "impl<const N: usize, T> DuplicateBundle<{ N }> for T {\n"
        "    fn duplicate_bundle(&self) -> Self {\n"
        "        unsafe { core::ptr::read(self) }\n"
        "    }\n"
        "}\n",
        "Task 12 locked mount bundle kind seal",
    )
    task12_mutation(
        "completed mount bind accepts a foreign completion",
        "driver/fsring-core/src/adapter/fence.rs",
        "    if completed.matches(&expected) {\n",
        "    if true {\n",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "bound Owner and Joined completions no longer permit deletion",
        "driver/fsring-core/src/adapter/fence.rs",
        "        CompletedMountTeardown::Owner(_) | CompletedMountTeardown::Joined(_) => true,\n",
        "        CompletedMountTeardown::Owner(_) | CompletedMountTeardown::Joined(_) => false,\n",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "completed mount matching ignores its locator",
        "driver/fsring-core/src/adapter/fence.rs",
        "        if !locator_eq(locator, expected.locator()) {\n",
        "        if false {\n",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        # The per-effect native dispatcher was retired with the roster hoist;
        # the take-once VDO slot is now consumed through `delete_shell_vdo`.
        "shell VDO delete wrapper suppresses the take-once effect",
        "driver/fsring-fsd/src/fence.rs",
        "    fn delete_shell_vdo(&self) {\n"
        "        if !self.shell.checkpoint_delete_vdo_once() {\n",
        "    fn delete_shell_vdo(&self) {\n"
        "        if false && !self.shell.checkpoint_delete_vdo_once() {\n",
        "Task 12 shell VDO post-bind suffix",
    )
    task12_mutation(
        "mounted-device owner forgets instead of deleting",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        unsafe { crate::kernel::delete_device(self.device.as_ptr()) };\n",
        "        core::mem::forget(self);\n",
        "Task 12 mount-owned teardown owner-only",
    )
    task12_mutation(
        "mounted VPB owner forgets instead of clearing",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    pub(crate) unsafe fn clear_binding(self) {\n"
        "        let mut irql: KIRQL = 0;\n"
        "        unsafe { fsring_sys::c4::IoAcquireVpbSpinLock(&raw mut irql) };\n"
        "        unsafe {\n"
        "            (*self.vpb.as_ptr()).DeviceObject = core::ptr::null_mut();\n"
        "            (*self.vpb.as_ptr()).Flags &= !(wdk_sys::VPB_MOUNTED as u16);\n"
        "        }\n"
        "        unsafe { fsring_sys::c4::IoReleaseVpbSpinLock(irql) };\n"
        "    }",
        "    pub(crate) unsafe fn clear_binding(self) {\n"
        "        core::mem::forget(self);\n"
        "    }",
        "Task 12 mount-owned teardown owner-only",
    )
    task12_mutation(
        "private raw mount KeSetEvent helper escapes the owner roster",
        "driver/fsring-fsd/src/fence.rs",
        "// ---------------------------------------------------------------------------\n"
        "// The scheduler\n",
        "unsafe fn hidden_mount_signal(event: *mut fsring_sys::KEVENT) {\n"
        "    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };\n"
        "}\n\n"
        "// ---------------------------------------------------------------------------\n"
        "// The scheduler\n",
        "Task 12 locked mount signal-then-ack window",
    )
    task12_mutation(
        "mount drain retry loses its authentic AdmissionClosed result",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "        {\n"
        "            return Err((LifecycleError::AdmissionClosed, right));\n"
        "        }\n"
        "        self.state = PrivateMountRendezvousState::Resetting {",
        "        {\n"
        "            return Err((LifecycleError::WrongState, right));\n"
        "        }\n"
        "        self.state = PrivateMountRendezvousState::Resetting {",
        "Task 12 late Join drain retry authority",
    )
    task12_mutation(
        "mount wait observation substitutes its event kind",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "        match (observation.event, &self.state) {\n"
        "            (\n"
        "                MountWaitEvent::Complete,\n",
        "        match (observation.event, &self.state) {\n"
        "            (\n"
        "                MountWaitEvent::ResetComplete,\n",
        "Task 12 mount wake-to-registry-first",
    )
    task12_mutation(
        "mount generation predicate ignores its locator",
        "driver/fsring-core/src/adapter/lifecycle.rs",
        "    rendezvous.locator() == Some(locator)\n"
        "        && match rendezvous.state {",
        "    true\n"
        "        && match rendezvous.state {",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "native mount wait wrapper accepts every observation",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    pub(crate) fn matches_wait_observation(&self, observation: &MountWaitObservation) -> bool {\n"
        "        self.core.matches_wait_observation(observation)\n"
        "    }",
        "    pub(crate) fn matches_wait_observation(&self, _observation: &MountWaitObservation) -> bool {\n"
        "        true\n"
        "    }",
        "Task 12 mount wake-to-registry-first",
    )
    task12_mutation(
        "cleared shell VDO slot is accepted as live",
        "driver/fsring-fsd/src/session.rs",
        "const fn vdo_slot_contains_device(device: PDEVICE_OBJECT) -> bool {\n"
        "    !device.is_null()\n"
        "}",
        "const fn vdo_slot_contains_device(_device: PDEVICE_OBJECT) -> bool {\n"
        "    true\n"
        "}",
        "Task 12 shell VDO take-once deletion",
    )
    task12_mutation(
        "commit revalidation ignores the carried VPB lock state",
        "driver/fsring-fsd/src/volume.rs",
        "const fn commit_revalidation_has_vpb_lock(vpb_held: bool) -> bool {\n"
        "    vpb_held\n"
        "}",
        "const fn commit_revalidation_has_vpb_lock(_vpb_held: bool) -> bool {\n"
        "    true\n"
        "}",
        "Task 12 mount commit VPB lock continuity",
    )
    task12_mutation(
        "mount Join admission omits its drained-event clear",
        "driver/fsring-fsd/src/lifecycle.rs",
        "                MountClaim::Join { .. } => {\n"
        "                    fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(\n"
        "                        self.mount_waiters_drained\n"
        "                    ));\n"
        "                }",
        "                MountClaim::Join { .. } => {}",
        "Task 12 mount wake-to-registry-first",
    )
    task12_mutation(
        "mount Join conversion omits its reset-drained-event clear",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        unsafe {\n"
        "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_reset_waiters_drained));\n"
        "        }\n"
        "        Ok(conversion)",
        "        Ok(conversion)",
        "Task 12 mount wake-to-registry-first",
    )
    task12_mutation(
        "rollback VPB acquire helper skips the acquisition DDI",
        "driver/fsring-fsd/src/volume.rs",
        "    unsafe { fsring_sys::c4::IoAcquireVpbSpinLock(&raw mut irql) };\n"
        "    context.vpb_irql = irql;",
        "    let _retained = &raw mut irql;\n"
        "    context.vpb_irql = irql;",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "rollback VPB release helper skips the release DDI",
        "driver/fsring-fsd/src/volume.rs",
        "    unsafe { fsring_sys::c4::IoReleaseVpbSpinLock(context.vpb_irql) };\n"
        "    context.vpb_held = false;",
        "    let _retained = context.vpb_irql;\n"
        "    context.vpb_held = false;",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "rollback VPB clear semantics stop reacquiring when unheld",
        "driver/fsring-core/src/volume.rs",
        "                acquire_release_if_unheld: true,\n",
        "                acquire_release_if_unheld: false,\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "private static rollback slice escapes the plan roster",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n"
        "static rollback_static: &[MountRollbackEffect] = &[];\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "explicit-static-lifetime rollback slice escapes the plan roster",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n"
        "const rollback_lifetime: &'static [MountRollbackEffect] = &[];\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "qualified rollback slice escapes the plan roster",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n"
        "const rollback_qualified: &[crate::volume::MountRollbackEffect] = &[];\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "alias-typed rollback slice escapes the plan roster",
        "driver/fsring-core/src/volume.rs",
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n",
        "type RollbackEffectAlias = MountRollbackEffect;\n"
        "const ROLLBACK_NONE: &[MountRollbackEffect] = &[];\n"
        "const rollback_aliased: &[RollbackEffectAlias] = &[];\n",
        "Task 12 exact mount rollback plan",
    )
    task12_mutation(
        "native terminal claim ignores the exact control context",
        "driver/fsring-fsd/src/lifecycle.rs",
        "        if owner.context() != context {\n",
        "        if false {\n",
        "Task 12 exact native terminal claim",
    )
    task12_mutation(
        "legacy mount after-unlock helper returns",
        "driver/fsring-fsd/src/lifecycle.rs",
        "// ---------------------------------------------------------------------------\n"
        "// Checked locator resolution",
        "unsafe fn signal_mount_complete_after_unlock(\n"
        "    registry: NonNull<KernelSessionRegistry>,\n"
        "    cell_index: u32,\n"
        "    publication: MountDonePublication,\n"
        ") {\n"
        "    let mut lock = KernelSessionRegistry::lock(registry);\n"
        "    let _raw = lock.cell_ptr(cell_index);\n"
        "    lock.release();\n"
        "    core::mem::forget(publication);\n"
        "}\n\n"
        "// ---------------------------------------------------------------------------\n"
        "// Checked locator resolution",
        "Task 12 prepared locked mount publication aggregate",
    )
    task12_mutation(
        "terminal outcome event is signalled under the registry lock",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    unsafe { lock.release() };\n"
        "    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };\n"
        "}",
        "    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };\n"
        "    unsafe { lock.release() };\n"
        "}",
        "Task 12 terminal signal post-unlock",
    )
    task12_mutation(
        "terminal joiners-drained event is signalled under the registry lock",
        "driver/fsring-fsd/src/lifecycle.rs",
        "    unsafe { lock.release() };\n"
        "    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };\n"
        "}\n\n"
        "/// Wait until every counted arrival has released.",
        "    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };\n"
        "    unsafe { lock.release() };\n"
        "}\n\n"
        "/// Wait until every counted arrival has released.",
        "Task 12 terminal signal post-unlock",
    )

    # The Rust side bounds `size_of::<PendingEnterContext>()` at 1024, which an
    # inline 512-byte result buffer fits comfortably. Only the frozen field
    # grammar refuses it, so that is what this plants.
    task12_mutation(
        "inline result storage in the staged pending context",
        "driver/fsring-fsd/src/pending_enter.rs",
        "    /// The parked IRP, or null. Written only under `lock`.\n    irp: PIRP,",
        "    result_bytes: [u8; 512],\n"
        "    /// The parked IRP, or null. Written only under `lock`.\n    irp: PIRP,",
        "PendingEnterContext is outside its exact staged pending field grammar",
    )

    flush_task12_mutations()

    # One combined production copy keeps this blocker wave bounded while each
    # bypass still demands its own finding family.  The probes are additive, so
    # they remain useful after production closes the corresponding current
    # source hole; none depends on retaining today's defective anchor.
    blocker_probes = {
        "driver/fsring-core/src/adapter/fence.rs": (
            "\nfn probe_ignores_running_locator(right: R3FinalizerRunningRight) {\n"
            "    let R3FinalizerRunningRight { locator: _, authority: _ } = right;\n"
            "}\n"
        ),
        "driver/fsring-core/src/session.rs": (
            "\nfn probe_discards_terminal_reset_locator(\n"
            "    right: crate::adapter::fence::TerminalRendezvousResetRight,\n"
            ") {\n"
            "    let _locator = right.into_locator();\n"
            "}\n"
        ),
        "driver/fsring-fsd/src/lifecycle.rs": (
            "\nfn probe_omits_terminal_event_state(\n"
            "    cell: &NativeSessionCell, locator: SessionLocator,\n"
            ") -> bool {\n"
            "    matches!(cell.terminal_rendezvous.outcome_for_locator(locator), "
            "Some(fsring_core::session::TerminalRendezvousOutcome::Open))\n"
            "}\n"
            "\nunsafe fn probe_calls_rundown_ddis_under_registry_spin_lock(\n"
            "    registry: NonNull<KernelSessionRegistry>, locator: SessionLocator,\n"
            ") {\n"
            "    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };\n"
            "    let cell = unsafe { lock.cell_ptr(locator.slot_index()).unwrap_unchecked() };\n"
            "    unsafe { fsring_sys::c4::ExRundownCompleted(core::ptr::addr_of_mut!((*cell).access)) };\n"
            "    unsafe { fsring_sys::c4::ExReInitializeRundownProtection(core::ptr::addr_of_mut!((*cell).access)) };\n"
            "    unsafe { lock.release() };\n"
            "}\n"
            "\nunsafe fn probe_closes_process_callback_rundown_under_registry_spin_lock(\n"
            "    registry: NonNull<KernelSessionRegistry>,\n"
            ") {\n"
            "    let lock = unsafe { KernelSessionRegistry::lock(registry) };\n"
            "    unsafe { close_process_callback_admission(registry) };\n"
            "    unsafe { lock.release() };\n"
            "}\n"
            "\nunsafe fn probe_completes_process_callback_rundown_before_waiting(\n"
            "    registry: NonNull<KernelSessionRegistry>,\n"
            ") {\n"
            "    let rundown = unsafe {\n"
            "        registry.as_ref().process_callback_admission.get().cast()\n"
            "    };\n"
            "    unsafe { fsring_sys::c4::ExRundownCompleted(rundown) };\n"
            "    unsafe { fsring_sys::c4::ExWaitForRundownProtectionRelease(rundown) };\n"
            "}\n"
        ),
        "driver/fsring-fsd/src/fence.rs": (
            "\nstruct ProbeUnbrandedCellResetRight {\n"
            "    authority: PrivateCellResetAuthority,\n"
            "}\n"
            "\nunsafe fn probe_scans_first_queued_cell(\n"
            "    registry: NonNull<KernelSessionRegistry>,\n"
            ") {\n"
            "    let mut index = 0u32;\n"
            "    while index < SESSION_CELL_COUNT as u32 {\n"
            "        let mut lock = unsafe { KernelSessionRegistry::lock(registry) };\n"
            "        let taken = unsafe { lock.cell_ptr(index) }\n"
            "            .and_then(|cell| unsafe { (*cell).take_deposit_and_run() });\n"
            "        unsafe { lock.release() };\n"
            "        if taken.is_some() { return; }\n"
            "        index = index.saturating_add(1);\n"
            "    }\n"
            "}\n"
            "\nfn probe_conflates_completed_slot_with_context(\n"
            "    context: NonNull<ControlFileContext>,\n"
            ") -> (bool, bool) {\n"
            "    let intact = unsafe { crate::control::lifetime_is_cell_owned(context) };\n"
            "    (intact, intact)\n"
            "}\n"
            "\nunsafe fn probe_decides_before_authentic_core_check(\n"
            "    lock: &mut RegistryLockGuard,\n"
            "    deposit: R3FinalizerDeposit,\n"
            "    running: R3FinalizerRunningRight,\n"
            ") {\n"
            "    let locator = running.locator();\n"
            "    let observation = unsafe { observe_delete_preflight(lock, locator) }.unwrap();\n"
            "    let _ = fsring_core::adapter::fence::decide_delete_preflight(observation);\n"
            "    let core = unsafe { &*lock.core_ptr() };\n"
            "    let _ = deposit.prepare_final_delete_core(core);\n"
            "}\n"
            "\n#[allow(dead_code)]\n"
            "mod probe_nested_production_consumer {\n"
            "    use super::*;\n"
            "    fn consume(owner: NativeSessionOwner) { core::mem::forget(owner); }\n"
            "}\n"
            "\nfn probe_forgets_a_normal_finalizer_kick(\n"
            "    kick: fsring_core::adapter::fence::R3FinalizerKick,\n"
            ") -> bool {\n"
            "    core::mem::forget(kick);\n"
            "    false\n"
            "}\n"
        ),
    }
    blocker_expectations = (
        ("registry-only callback can scan another queued cell", "Task 12 exact-cell finalizer callback"),
        ("running locator is ignored during reset", "Task 12 running-locator reset brand"),
        ("cell reset authority has no locator", "Task 12 cell-reset locator brand"),
        ("terminal reset locator is discarded", "Task 12 terminal-reset locator brand"),
        ("completed-slot absence is conflated", "Task 12 completed-slot observation"),
        ("terminal event state is omitted", "Task 12 terminal-event observation"),
        ("delete decision precedes authentic core check", "Task 12 authentic core-delete observation order"),
        ("nested non-cfg dead code consumes an owner", "Task 12 nested production consumer"),
        ("rundown DDIs execute while the registry spin lock is held", "Task 12 rundown DDI IRQL boundary"),
        ("process-callback admission closes while the registry spin lock is held", "Task 12 process-callback rundown IRQL boundary"),
        ("process-callback rundown completes before its required wait", "Task 12 process-callback wait-before-completed order"),
        ("a normal finalizer kick is forgotten instead of queued", "Task 12 sole production finalizer kick sink"),
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-task12-blockers-") as work:
        for crate in ("fsring-core", "fsring-fsd"):
            shutil.copytree(
                os.path.join(repo, "driver", crate, "src"),
                os.path.join(work, "driver", crate, "src"),
            )
        for rel, probe in blocker_probes.items():
            path = os.path.join(work, rel.replace("/", os.sep))
            with io.open(path, "a", encoding="utf-8", newline="") as handle:
                handle.write(probe)
        blockers = subprocess.run(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--production-check",
                "--root",
                work,
                "--source-root",
                "driver/fsring-core/src",
                "--source-root",
                "driver/fsring-fsd/src",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    for label, expected in blocker_expectations:
        check(
            blockers.returncode == 1 and expected in blockers.stderr,
            "%s must fail with %r, got exit=%d stdout=%r stderr=%r"
            % (label, expected, blockers.returncode, blockers.stdout, blockers.stderr),
        )

    production = subprocess.run(
        [
            sys.executable,
            os.path.abspath(__file__),
            "--production-check",
            "--root",
            repo,
            "--source-root",
            "driver/fsring-core/src",
            "--source-root",
            "driver/fsring-fsd/src",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    check(
        production.returncode == 0
        # 447 -> 456: nine frozen bodies were added to `TASK12_BODY_GRAMMAR`
        # for the R6 rendezvous repair, and the production check counts one
        # per entry. Raised deliberately, which is what this file's anti-rot
        # rule asks for when a real change moves a count.
        # 456 -> 461: the round-9 attach-scratch rule contributes five checks
        # (static roster, no KAPC_STATE item, call roster, argument shape, and
        # the shape check's own coverage floor).
        # 461 -> 462: the round-9 blocker-2 rule over the pending completion
        # pass's classified CSQ release.
        # 462 -> 463: the round-9 high-2 rule placing the dequeue after the
        # authorities and requiring the refusal to abandon its completion.
        # 463 -> 464: the round-9 high-3 rule requiring the parked-WAIT store's
        # refusal to be answered rather than discarded.
        # 464 -> 465: the round-9 high-4 rule ordering the mount ownership proof
        # before any projection of the target's extension.
        # 465 -> 466: the round-9 high-1 rule keeping master-MDL residency
        # profile-independent.
        # 466 -> 467: the round-10 blocker-1 rule requiring an abandoned
        # completion to deposit the Cancel the framework's adoption left
        # unstored.
        # 467 -> 468: the round-10 blocker rule keeping every alias unmap
        # dispatched per alias rather than per profile.
        # 468 -> 469: the round-10 high rule making the abandoned queued
        # pass queue the wake its stored reasons are still owed.
        # 469 -> 473: the round-11 SDDL high. One rule on `kernel.rs` keeping
        # the terminated and counted `UNICODE_STRING` mints apart, and one on
        # each of the three roles that create a secure device, requiring the
        # `DefaultSDDLString` to be built by the terminated one. Those three
        # files and `kernel.rs` also joined `COUNTED_EVIDENCE_FILES`: their
        # rules already failed the audit, and only the total was blind to
        # them. (That commit message mis-decomposed the step: `volume.rs` was
        # already counted through `NATIVE_OWNER_FILES`, so it was 469 + 1 new
        # rule on an already-counted file + 3 newly counted files.)
        # 473 -> 475: `fence.rs` joined `COUNTED_EVIDENCE_FILES` too. Its two
        # checks were being emitted and not counted, which is the same
        # uncounted-guard hazard the comment on that set argues against.
        # 475 -> 476: the frame BELOW `begin_pass`. `begin_native_worker_pass`
        # lives in `driver/fsring-core/src/enter.rs`, which every queued-pass
        # rule was blind to because they are all keyed on `pending_enter.rs`;
        # an adversarial pass put the round-11 livelock's extra refusal there.
        # 476 -> 477: the round-14 highs in the fence retry worker's completing
        # arm, pinned as whole arms rather than left to the `.release(` and
        # `unsafe` token counts that happened to move when the repair landed.
        # 477 -> 478: the round-14 BLOCKER in the CLEANUP completed-record
        # arm, pinned as an arm rather than left to the frozen enum digest
        # and the `unsafe` count that also moved when it was repaired.
        # 478 -> 480: the round-14 BLOCKER that left every shell ring
        # unbranded, pinned in two places -- the SETUP stamp that gives the
        # shell its brand, and the one-shot checked adoption that is the
        # only way to perform it.
        # 480 -> 481: the round-14 HIGH that left the R4 acquire wired to the
        # R3 release, pinned together with the drain predicate -- the two rows
        # inside the window where the fence owns every ring's consumer.
        # 481 -> 482: the round-14 HIGH that left a refused SETUP leaking the
        # pending arena and up to 64 work items, pinned at the HEAD of the
        # unwind because both rollback entry points funnel through it and the
        # release must precede the effects that free what its contexts reach.
        # 482 -> 483: the round-14 medium that left the notification-credit
        # block unadopted across three fallible steps.
        # 483 -> 484: the round-14 medium that published the provider
        # endpoint before the root field a dispatch reads through it, with
        # `driver.rs` joining the counted set for the same reason `fence.rs`
        # did.
        # 484 -> 485: the round-14 medium that bugchecked with the ring
        # spin lock held, which `panic = "abort"` makes permanent.
        # 485 -> 486: the round-15 medium that found TWO MORE of those, one
        # commit after 485's repair, because that repair produced the construct
        # at the three sites it was given and did not sweep. The new row freezes
        # the whole population of panic-family sites inside a slot-lock hold in
        # `pending_enter.rs`, so the next one fails here rather than in a review.
        # 486 -> 487: the round-16 BLOCKER. CLOSE classified a context holding a
        # completed record as somebody else's, leaked it, and left unload waiting
        # for ever. The decision moved to `fsring-core` where tests can drive it;
        # the new row keeps `control.rs` asking, which is the half no test in
        # this repository can reach.
        # 487 -> 488: round-16 E3's enforced rule. The sweep that wrote "line
        # numbers decay on their own" planted twenty bare `:NNNN` citations in
        # the same commit, at least fifteen already wrong. A written rule did not
        # produce compliance; this row does.
        # 488 -> 489: round-16 N16-3. A refused `commit_pending_handoff`
        # was collapsed with a committed one, so the installer token it
        # hands back was dropped and `HandoffDone` published anyway. fsd
        # has no host tests; this row is what can see the arms merged.
        # 489 -> 494: round 18's close choreography, one row per driver fact
        # core's `close_choreography` walk shows load-bearing:
        # `close-takes-ownership-under-the-registry-lock`,
        # `late-cleanup-takes-the-committed-route` (N17-2),
        # `cleanup-reclaims-after-its-terminal`,
        # `cleanup-releases-the-rundown-before-the-route` in `control.rs`, and
        # `recorded-context-retired-at-completion` (N17-1) in `lifecycle.rs`.
        # The rewritten `close-ownership-is-decided-in-core` row was already
        # counted and adds nothing.
        # 494 -> 495: round-19 native review N18-1. A CLEANUP whose stack
        # expansion the kernel refused completed having claimed nothing, which
        # left the generation live, CLOSE with nothing it may free and unload
        # waiting on an admission with no signaller -- round 16's blocker on a
        # narrow path. Round 21 replaced the row: the dispatch asks again only
        # for a memory refusal and only within core's budget (round-20 native
        # review N1), and the row pins that whole loop verbatim (N2). One row
        # for one, so the count did not move.
        # 495 -> 496: round-20 native review N18-2. A CLOSE that found the
        # CREATE admission lease in the slot detached and returned, leaking the
        # block and the rundown unload waits on. It adopts the lease now, on the
        # binding's own word that nothing is installed through the context.
        and "audit_c4_lifetime production-check: PASS (496 checks, 0 failures)"
        in production.stdout,
        "production mode must emit counted non-vacuous evidence, got exit=%d stdout=%r stderr=%r"
        % (production.returncode, production.stdout, production.stderr),
    )

    # Every declared probe must have been given a verdict. A probe queued after
    # the wave flushed is left unrun; a wave that clears its queue instead of
    # grading it leaves nothing waiting either. Both are silent, and both read
    # as covered, so the count that has to agree is declared-versus-graded --
    # not whether the queue happens to be empty now.
    check(
        task12_graded == task12_declared and not task12_jobs,
        "every declared Task 12 probe must be graded: declared=%d graded=%d "
        "still queued=%r" % (task12_declared, task12_graded, [job[0] for job in task12_jobs]),
    )

    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    lifecycle_rel = "driver/fsring-fsd/src/lifecycle.rs"
    lifecycle_path = os.path.join(repo, lifecycle_rel.replace("/", os.sep))
    with io.open(lifecycle_path, encoding="utf-8") as handle:
        lifecycle_source = handle.read()

    def named_lifecycle_plant(name, old, new, expected):
        if lifecycle_source.count(old) != 1:
            check_named(name, False, "anchor is not exact-one for %r" % old[:80])
            return
        planted = strip_noncode(lifecycle_source.replace(old, new, 1))
        findings = native_contract_findings(planted, lifecycle_rel)
        check_named(
            name,
            any(expected in finding for finding in findings),
            "expected %r, got %r" % (expected, findings),
        )

    for shape in (
        "*mut NativeSession",
        "NonNull<NativeSession>",
        "AtomicPtr<NativeSession>",
    ):
        planted = "pub struct ControlFileContext {\n    session: %s,\n}\n" % shape
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-t27-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check_named(
            "raw/NonNull/AtomicPtr NativeSession in control binding",
            bool(findings),
            "%s must be refused, got %r" % (shape, findings),
        )

    for carrier in ("RegistrySlot", "VolumeExtension", "MountedVolumeExtension"):
        planted = "pub struct %s {\n    session: *mut NativeSession,\n}\n" % carrier
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-t27-") as work:
            src = os.path.join(work, "src")
            os.makedirs(src)
            with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
                handle.write(planted)
            findings, _ = audit_tree(work, ["src"])
        check_named(
            "raw session pointer in registry entry, VDO, or mounted extension",
            bool(findings),
            "%s must be refused, got %r" % (carrier, findings),
        )

    named_lifecycle_plant(
        "process-loss dereference before claim",
        "            Some(cell) => match unsafe { (*cell).process_locator(process) } {\n",
        "            Some(cell) => match unsafe { let _ = (*cell).session; (*cell).process_locator(process) } {\n",
        "process scan is not one locked pointer-free observation",
    )
    named_lifecycle_plant(
        "locator projection before access-rundown acquire",
        "                    let acquired =\n"
        "                        unsafe { fsring_sys::c4::ExAcquireRundownProtection(target.cast()) };\n",
        "                    let _ = unsafe { lock.as_mut().map(|held| held.project_resolved_session(slot_index, locator)) };\n"
        "                    let acquired =\n"
        "                        unsafe { fsring_sys::c4::ExAcquireRundownProtection(target.cast()) };\n",
        "native resolver projects a shell before access rundown",
    )
    named_lifecycle_plant(
        "missing slot/generation/identity/Live recheck",
        "                    match core.validate_live(locator) {\n"
        "                        Ok(()) => pending.succeeded(),\n"
        "                        Err(_) => pending.refused(ResolveRejection::NotLive),\n"
        "                    }\n",
        "                    pending.succeeded()\n",
        "native resolver does not perform exact core Live validation",
    )
    named_lifecycle_plant(
        "missing rundown release on a reject path",
        "                    if refusal.releases_rundown() {\n"
        "                        if let Some(held) = rundown.take() {\n"
        "                            // SAFETY: this frame acquired exactly one rundown\n"
        "                            // reference on that cell and releases it once.\n"
        "                            unsafe { fsring_sys::c4::ExReleaseRundownProtection(held.cast()) };\n"
        "                        }\n"
        "                    }\n",
        "                    let _ = refusal.releases_rundown();\n",
        "native resolver does not retain both exact rundown-release paths",
    )
    cell = "pub struct NativeSessionCell {" + NEWLINE
    planted = (
        cell
        + "    session: *mut NativeSession," + NEWLINE
        + "    spare: *mut NativeSession," + NEWLINE
        + "}" + NEWLINE
    )
    with tempfile.TemporaryDirectory(prefix="c4-lifetime-t27-") as work:
        src = os.path.join(work, "src")
        os.makedirs(src)
        with io.open(os.path.join(src, "a.rs"), "w", encoding="utf-8") as handle:
            handle.write(planted)
        findings, _ = audit_tree(work, ["src"])
    check_named(
        "second permanent-cell owning pointer",
        bool(findings),
        "a second cell pointer must be refused, got %r" % (findings,),
    )
    named_lifecycle_plant(
        "inline session free outside setup rollback/finalizer",
        "                ResolveStep::ValidateCoreLive => {\n",
        "                ResolveStep::ValidateCoreLive => {\n"
        "                    unsafe { crate::session::free_session_shell_allocation(core::ptr::null_mut()) };\n",
        "native resolver has a residual call or control-flow effect",
    )

    # Round 18: the close choreography's driver half. Each plant puts back one
    # defect the `close_choreography` walk in core shows load-bearing, in the
    # REAL source, and names the one row that must see it. Retained here on
    # purpose: round 17's grading plants lived in a scratch script, and once
    # its commit landed they protected nothing.
    control_rel = "driver/fsring-fsd/src/control.rs"
    with io.open(
        os.path.join(repo, control_rel.replace("/", os.sep)), encoding="utf-8"
    ) as handle:
        control_source = handle.read()

    def named_control_plant(name, old, new, expected):
        if control_source.count(old) != 1:
            check_named(name, False, "anchor is not exact-one for %r" % old[:80])
            return
        planted = strip_noncode(control_source.replace(old, new, 1))
        findings = native_contract_findings(planted, control_rel)
        check_named(
            name,
            any(expected in finding for finding in findings),
            "expected %r, got %r" % (expected, findings),
        )

    named_control_plant(
        "round-17 close right taken out of an unacknowledged record",
        "        other => {\n            *lifetime = other;\n            (ownership, None)\n",
        "        ControlContextLifetime::Completed(record) => "
        "(ownership, Some(record.into_close_right())),\n"
        "        other => {\n            *lifetime = other;\n            (ownership, None)\n",
        "takes the close right out of a record no CLEANUP acknowledged",
    )
    named_control_plant(
        "close ownership taken without the registry lock",
        "    let lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };\n"
        "    let taken = unsafe { take_close_ownership(context) };\n"
        "    unsafe { lock.release() };\n",
        "    let taken = unsafe { take_close_ownership(context) };\n",
        "without the lock the finalizer stores it under",
    )
    named_control_plant(
        "late cleanup completes without claiming",
        "                None => None,\n",
        "                None => return unsafe { complete(irp, STATUS_SUCCESS) },\n",
        "a CLEANUP refused at the dispatch rundown completes without claiming",
    )
    named_control_plant(
        "cleanup never claims again after its terminal",
        "            CleanupContinuation::ReclaimOnce if pass == CleanupPass::First => {\n",
        "            CleanupContinuation::ReclaimOnce if false => {\n",
        "CLEANUP no longer claims again after its terminal",
    )
    # Round 21 (round-20 native review N2): the row these seven grade pins the
    # whole CLEANUP expansion loop verbatim. The first is the native lens's
    # own plant -- a `break` after the delay, which kept every token round
    # 20's row matched. Each was run against `native_contract_findings`
    # before it was retained here.
    cleanup_retry_arm_end = (
        "                                };\n"
        "                            }\n"
        "                            // Out of budget, or a refusal no wait clears. The\n"
    )
    named_control_plant(
        "cleanup gives up after one wait",
        cleanup_retry_arm_end,
        "                                };\n"
        "                                break CleanupTerminalOutcome::Refuse;\n"
        "                            }\n"
        "                            // Out of budget, or a refusal no wait clears. The\n",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "cleanup returns after one wait",
        cleanup_retry_arm_end,
        "                                };\n"
        "                                return unsafe { complete(irp, STATUS_INVALID_DEVICE_STATE) };\n"
        "                            }\n"
        "                            // Out of budget, or a refusal no wait clears. The\n",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "cleanup budget restarts on every attempt",
        "                    let mut budget = CleanupExpansionBudget::per_arrival();\n"
        "                    let outcome = loop {\n",
        "                    let outcome = loop {\n"
        "                        let mut budget = CleanupExpansionBudget::per_arrival();\n",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "cleanup expansion status thrown away",
        "match resolve_cleanup(status, block.outcome.take()) {",
        "match resolve_cleanup(STATUS_SUCCESS, block.outcome.take()) {",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "cleanup proceeds on a spent budget",
        "                            CleanupExpansionRecourse::Exhausted\n"
        "                            | CleanupExpansionRecourse::Surrender => {\n",
        "                            CleanupExpansionRecourse::Exhausted => break CleanupTerminalOutcome::Proceed,\n"
        "                            CleanupExpansionRecourse::Surrender => {\n",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "cleanup retries without waiting",
        "                                let _elapsed = unsafe {\n"
        "                                    fsring_sys::c4::KeDelayExecutionThread(\n"
        "                                        0,\n"
        "                                        0 as BOOLEAN,\n"
        "                                        core::ptr::addr_of_mut!(interval),\n"
        "                                    )\n"
        "                                };\n",
        "",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "cleanup retry interval neutered",
        "const EXPANSION_RETRY_INTERVAL_100NS: i64 = 100_000;",
        "const EXPANSION_RETRY_INTERVAL_100NS: i64 = 0;",
        "is no longer the one core's budget",
    )
    named_control_plant(
        "close stops asking whether the lease may be adopted",
        "    let ownership =\n"
        "        ControlContextCloseOwnership::for_lifetime(kind)"
        ".adopt_unused_lease(holds_no_installation);\n",
        "    let ownership = ControlContextCloseOwnership::for_lifetime(kind);\n",
        "detaches and leaks",
    )
    named_control_plant(
        "close frees an adopted lease without releasing it",
        "            Some(crate::lifecycle::CloseContextRight::new(lease)),\n",
        "            None,\n",
        "detaches and leaks",
    )
    named_control_plant(
        "cleanup route runs before the dispatch rundown is released",
        "NativeCleanupClaim::new(guard, claim).release_outer()",
        "NativeCleanupClaim::new(guard, claim).release_outer_later()",
        "CLEANUP's committed route no longer runs after the dispatch rundown",
    )
    named_lifecycle_plant(
        "completion keeps the recorded control context",
        "        cell.recorded_control_context = None;\n",
        "",
        "no longer retires the cell's recorded control-context pointer",
    )
    # Round-17 evidence E2: the bare-citation row, called directly. Round 17
    # graded it with a scratch plant; the four spellings it missed are retained
    # here, with the three it must leave alone.
    for label, source, expected in (
        ("a whole-line comment", "// see `:1234`\nfn a() {}\n", 1),
        ("a backticked range", "/// see `:1234-1240`\n", 1),
        ("a trailing comment", "let x = 1; // see `:1234`\n", 1),
        ("a block continuation line", "/* first line\n   see `:1234`\n*/\n", 1),
        ("no string literal", 'let s = "// `:1234`";\n', 0),
        ("no qualified citation", "// see `messages.rs:1622`\n", 0),
        ("no unbackticked number", "// at 12:34\n", 0),
    ):
        got = len(bare_line_citations({"driver/fsring-fsd/src/x.rs": source}))
        check_named(
            "bare-citation row reaches " + label,
            got == expected,
            "expected %d citation(s), got %d" % (expected, got),
        )

    # The `fn` walker, directly. Every per-function census and every frozen
    # `TASK12_BODY_GRAMMAR` digest is computed from these two helpers, and a
    # walker that stops at the first `{` after the name silently freezes a
    # fragment of the signature instead of the body when the signature carries
    # a const-generic argument -- which is not an error, just a very small
    # body that agrees with itself forever. `park_wait_enter` sat in exactly
    # that state, and 13 `.release()` calls sat outside the census with it.
    const_generic_fn = (
        "pub(crate) unsafe fn park_wait_enter(\n"
        "    ledger: &mut PendingControlLedger<{ crate::session::MAX_PENDING_LINKS }>,\n"
        ") -> Result<(), NTSTATUS> {\n"
        "    marker.release();\n"
        "    Ok(())\n"
        "}\n"
    )
    walked = dict(function_items(const_generic_fn))
    check(
        "marker.release()" in walked.get("park_wait_enter", ""),
        "the fn walker must find the body of a function with a const-generic "
        "parameter, got %r" % (walked.get("park_wait_enter"),),
    )
    check(
        "MAX_PENDING_LINKS" not in walked.get("park_wait_enter", "x"),
        "the fn walker must not return a const-generic argument as a body",
    )
    bodies = list(function_bodies(const_generic_fn, "park_wait_enter"))
    check(
        len(bodies) == 1 and "marker.release()" in bodies[0],
        "function_bodies must agree with function_items about where a body "
        "begins, got %r" % (bodies,),
    )
    returned_const_generic = (
        "fn make() -> PendingControlLedger<{ crate::session::MAX_PENDING_LINKS }> {\n"
        "    build()\n"
        "}\n"
    )
    check(
        "build()" in dict(function_items(returned_const_generic)).get("make", ""),
        "a const-generic argument in the RETURN type is signature, not body",
    )
    # A regression guard, not a falsification of the repair: the first-`{`
    # walker satisfied this one too, through its `[^;{]*`. It is here because
    # the repaired walker reaches the same answer by a different route -- an
    # explicit `;`-at-paren-depth-zero return -- and that route needs a case.
    check(
        dict(function_items("fn declared(&self) -> bool;\n")) == {},
        "a declaration with no body must yield nothing",
    )

    for name in TASK27_LIFETIME_CASES:
        if name not in reported_lifetime:
            checks += 1
            failures.append("%s: independently reported case was not executed" % name)

    for failure in failures:
        print("FAIL: %s" % failure)
    print(
        "audit_c4_lifetime self-test: %s (%d checks, %d failures)"
        % ("PASS" if not failures else "FAIL", checks, len(failures))
    )
    return 1 if failures else 0


def task5_self_test():
    """Focused planted mutations for the durable fail-stop closure."""
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    cases = (
        (
            "forgotten finish candidate",
            "driver/fsring-fsd/src/fence.rs",
            "                    let incomplete = candidate.into_finish_preparation_incomplete();",
            "                    core::mem::forget(candidate);\n"
            "                    let incomplete = unsafe { core::hint::unreachable_unchecked() };",
            "Task 5 affine refusal packet or checkpoint candidate is forgotten",
        ),
        (
            "forgotten refusal packet",
            "driver/fsring-fsd/src/fence.rs",
            "        Some(cell) => unsafe { (*cell).store_and_resolve_fail_stop(packet) },",
            "        Some(_cell) => { core::mem::forget(packet); loop {} },",
            "Task 5 affine refusal packet or checkpoint candidate is forgotten",
        ),
        (
            "visibility before durable store",
            "driver/fsring-core/src/session.rs",
            "        self.state = DurableFailStopSlotState::Occupied {\n"
            "            visibility: DurableFailStopVisibility::Stored,\n"
            "            packet,\n"
            "        };\n"
            "        let resolution = match &self.state {",
            "        let resolution = match &self.state {",
            "Task 5 exact durable fail-stop method closure",
        ),
        (
            "opaque converted to ordinary publication",
            "driver/fsring-fsd/src/fence.rs",
            "                    } else {\n"
            "                        StoredFailStopPublicationMode::RequireOpaque\n"
            "                    };",
            "                    } else {\n"
            "                        StoredFailStopPublicationMode::PublishIfExact\n"
            "                    };",
            "Task 5 exact durable fail-stop method closure",
        ),
        (
            "opaque path signals terminal outcome",
            "driver/fsring-fsd/src/fence.rs",
            "        R3FailStopVisibility::OpaqueRetained(receipt) => unsafe {\n"
            "            OpaqueFailStopWaitGuard::after_closed_slot_scan(registry, receipt).wait_forever()\n"
            "        },",
            "        R3FailStopVisibility::OpaqueRetained(receipt) => unsafe {\n"
            "            crate::lifecycle::signal_terminal_outcome(registry, receipt);\n"
            "            OpaqueFailStopWaitGuard::after_closed_slot_scan(registry, receipt).wait_forever()\n"
            "        },",
            "Task 5 exact durable fail-stop method closure",
        ),
        (
            "opaque slot gains retry",
            "driver/fsring-fsd/src/fence.rs",
            "impl R3FailStopSlot {\n",
            "impl R3FailStopSlot {\n"
            "    pub(crate) fn retry(&mut self) {}\n",
            "Task 5 exact durable fail-stop method closure",
        ),
        (
            "occupied slot may be overwritten",
            "driver/fsring-core/src/session.rs",
            "        if !self.is_empty() {\n"
            "            return Err(packet);\n"
            "        }",
            "        if !self.is_empty() { /* overwrite the resident packet */ }",
            "Task 5 exact durable fail-stop method closure",
        ),
        (
            "PreparedDelete gains payload projection",
            "driver/fsring-fsd/src/fence.rs",
            "impl PreparedDelete {\n",
            "impl PreparedDelete {\n"
            "    fn into_parts(self) -> (R3PreparedDeleteStorage, R3DeletionTail, TerminalOutcomePublisher) {\n"
            "        (self.storage, self.tail, self.publisher)\n"
            "    }\n",
            "Task 5 exact durable fail-stop method closure",
        ),
        (
            "ordinary finalizer handoff is forged by a sibling module",
            "driver/fsring-fsd/src/session.rs",
            "#[cfg(test)]\nmod native_shape_tests {\n",
            "unsafe fn forged_ordinary_finalizer_handoff(\n"
            "    cell: &mut crate::lifecycle::NativeSessionCell,\n"
            "    locator: fsring_core::session::SessionLocator,\n"
            ") {\n"
            "    let _ = cell.store_ordinary_finalizer_handoff(locator);\n"
            "}\n\n"
            "#[cfg(test)]\nmod native_shape_tests {\n",
            "Task 5 ordinary finalizer handoff caller census",
        ),
    )
    failures = []
    for label, rel, old, new, expected in cases:
        with tempfile.TemporaryDirectory(prefix="c4-lifetime-task5-") as work:
            for crate in ("fsring-core", "fsring-fsd"):
                shutil.copytree(
                    os.path.join(repo, "driver", crate, "src"),
                    os.path.join(work, "driver", crate, "src"),
                )
            path = os.path.join(work, rel.replace("/", os.sep))
            with io.open(path, encoding="utf-8") as handle:
                source = handle.read()
            if source.count(old) != 1:
                failures.append("%s anchor is not exact-one" % label)
                continue
            with io.open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(source.replace(old, new, 1))
            result = subprocess.run(
                [
                    sys.executable,
                    os.path.abspath(__file__),
                    "--production-check",
                    "--root",
                    work,
                    "--source-root",
                    "driver/fsring-core/src",
                    "--source-root",
                    "driver/fsring-fsd/src",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        if result.returncode != 1 or expected not in result.stderr:
            failures.append(
                "%s expected %r, got exit=%d stdout=%r stderr=%r"
                % (label, expected, result.returncode, result.stdout, result.stderr)
            )
    for failure in failures:
        print("FAIL: %s" % failure)
    print(
        "audit_c4_lifetime task5-self-test: %s (%d mutations, %d failures)"
        % ("PASS" if not failures else "FAIL", len(cases), len(failures))
    )
    return 1 if failures else 0


def task6_self_test():
    """Focused planted mutations for the exact R3 unload closure."""
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    raw_production = {}
    for crate in ("fsring-core", "fsring-fsd"):
        base = os.path.join(repo, "driver", crate, "src")
        for directory, _subdirectories, files in os.walk(base):
            for name in sorted(files):
                if not name.endswith(".rs") or name == "tests.rs" or "tests" in os.path.relpath(directory, base).split(os.sep):
                    continue
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, repo).replace(os.sep, "/")
                with io.open(path, encoding="utf-8") as handle:
                    raw_production[rel] = handle.read()
    production = {
        path: strip_noncode(text) for path, text in raw_production.items()
    }
    cases = (
        (
            "16-effect roster loses its fixed width",
            "driver/fsring-core/src/adapter/load.rs",
            "pub const EFFECTS: [UnloadEffect; 16] = [",
            "pub const EFFECTS: [UnloadEffect; 15] = [",
            "Task 6 exact production 16-effect order",
        ),
        (
            "failed process unregister advances",
            "driver/fsring-fsd/src/driver.rs",
            "== plan::ProcessNotifyUnregisterDisposition::FailStop",
            "== plan::ProcessNotifyUnregisterDisposition::ContinueToCallbackDrain",
            "Task 6 exact production 16-effect order",
        ),
        (
            "effect one omits the control-context door",
            "driver/fsring-fsd/src/lifecycle.rs",
            "        *registry.as_ref().control_context_admission_open.get() = false;\n",
            "",
            "Task 6 atomic four-door admission close",
        ),
        (
            "stable scan accepts a one-cell pass",
            "driver/fsring-fsd/src/fence.rs",
            "if usize::try_from(next).map_or(true, |next| next >= SESSION_CELL_COUNT) {\n"
            "                    R3UnloadScanStep::StableEmpty",
            "if usize::try_from(next).map_or(true, |next| next >= 1) {\n"
            "                    R3UnloadScanStep::StableEmpty",
            "Task 6 fixed 64-cell authenticated scan",
        ),
        (
            "ordinary finalizer drops Completed authentication",
            "driver/fsring-fsd/src/lifecycle.rs",
            "self.terminal_rendezvous.outcome_for_locator(locator),\n"
            "                Some(fsring_core::session::TerminalRendezvousOutcome::Completed(\n"
            "                    _\n"
            "                ))",
            "self.terminal_rendezvous.outcome_for_locator(locator),\n"
            "                Some(fsring_core::session::TerminalRendezvousOutcome::Blocked(\n"
            "                    _\n"
            "                ))",
            "Task 6 Completed and exact Ordinary handoff authentication",
        ),
        (
            "ordinary finalizer accepts an opaque handoff",
            "driver/fsring-fsd/src/lifecycle.rs",
            "            Some(FinalizerVisibilityHandoff::Opaque { .. }) => false,",
            "            Some(FinalizerVisibilityHandoff::Opaque { .. }) => true,",
            "Task 6 Completed and exact Ordinary handoff authentication",
        ),
        (
            "post-rundown ACK pass is deleted",
            "driver/fsring-fsd/src/fence.rs",
            "let receipt = unsafe { lock.acknowledge_r3_finalizer_after_rundown(cursor) };",
            "let receipt = None;",
            "Task 6 fixed 64-cell finalizer resolution and ACK passes",
        ),
        (
            "ordinary reset clears the visibility latch too early",
            "driver/fsring-fsd/src/lifecycle.rs",
            "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.terminal_outcome));\n"
            "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_complete));",
            "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.terminal_outcome));\n"
            "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.visibility_resolution));\n"
            "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_complete));",
            "Task 6 ordinary visibility latch survives reset until locked ACK",
        ),
        (
            "process scan omits its per-generation handled commit",
            "driver/fsring-fsd/src/lifecycle.rs",
            "        self.process_loss_handled = true;",
            "        self.process_loss_handled = false;",
            "Task 6 per-generation process-loss marker",
        ),
        (
            "Published ticket skips locked released-slot authentication",
            "driver/fsring-fsd/src/lifecycle.rs",
            "lock.prepare_released_published_unload_wait(released);",
            "None;",
            "Task 6 Published/Opaque ticket authentication order",
        ),
        (
            "suffix skips effect fourteen",
            "driver/fsring-fsd/src/driver.rs",
            "        let effect_15 = unsafe { effect_14.release_boot_objects() };",
            "        let effect_15 = unsafe { core::hint::unreachable_unchecked() };",
            "Task 6 exact infallible suffix call order",
        ),
        (
            "predicate ALL duplicates a row",
            "driver/fsring-core/src/adapter/load.rs",
            "        Self::MountSignalsAcknowledged,",
            "        Self::MountOwnerAbsent,",
            "Task 6 exact independent 31-predicate mapping",
        ),
        (
            "sole-root preflight accepts a second reference",
            "driver/fsring-fsd/src/lifecycle.rs",
            "        if unsafe { state.as_ref().reference_count() } != 1 {",
            "        if false {",
            "Task 6 same-lock native ledgers and sole-root proof",
        ),
        (
            "core slot predicate collapses admission closure",
            "driver/fsring-core/src/session.rs",
            "    pub fn r3_unload_slots_are_empty(&self) -> bool {\n"
            "        self.slots.iter().all(|slot| {",
            "    pub fn r3_unload_slots_are_empty(&self) -> bool {\n"
            "        !self.admission_open && self.slots.iter().all(|slot| {",
            "Task 6 independent core slot-emptiness predicate",
        ),
        (
            "native base-cell predicate delegates to stable aggregate",
            "driver/fsring-fsd/src/lifecycle.rs",
            "    fn r3_unload_preflight_cell_is_empty(&self) -> bool {\n"
            "        matches!(self.phase, NativeCellPhase::Free | NativeCellPhase::Retired)",
            "    fn r3_unload_preflight_cell_is_empty(&self) -> bool {\n"
            "        self.r3_unload_scan_is_exactly_empty() && matches!(self.phase, NativeCellPhase::Free | NativeCellPhase::Retired)",
            "Task 6 independent base native-cell predicate",
        ),
        (
            "stable scan advances from FailStop without sealed nonmatch",
            "driver/fsring-fsd/src/fence.rs",
            "            crate::lifecycle::R3UnloadCellObservation::NonMatch(_receipt) => {",
            "            crate::lifecycle::R3UnloadCellObservation::NonMatch(_receipt)\n"
            "            | crate::lifecycle::R3UnloadCellObservation::FailStop => {",
            "Task 6 fixed 64-cell authenticated scan",
        ),
        (
            "Opaque no-ticket factory drops rendezvous authentication",
            "driver/fsring-fsd/src/lifecycle.rs",
            "        if cell\n"
            "            .terminal_rendezvous\n"
            "            .opaque_retained_admitted_for_locator(locator)\n"
            "            .is_none()\n"
            "        {\n"
            "            return None;\n"
            "        }\n"
            "        match cell.authenticate_closed_fail_stop(locator)? {",
            "        match cell.authenticate_closed_fail_stop(locator)? {",
            "Task 6 fused no-ticket Opaque authentication",
        ),
        (
            "Published path authenticates before releasing its exact ticket",
            "driver/fsring-fsd/src/lifecycle.rs",
            "                    // Published asymmetry: release the real ticket first.\n"
            "                    let released = cell.terminal_rendezvous.release(ticket);",
            "                    // Mutant: slot authentication happens before ticket release.\n"
            "                    let _premature = lock.prepare_published_unload_wait(locator);\n"
            "                    let released = cell.terminal_rendezvous.release(ticket);",
            "Task 6 Published/Opaque ticket authentication order",
        ),
        (
            "finalizer admission is acquired after a destructive release commit",
            "driver/fsring-fsd/src/fence.rs",
            "    let finalizer_admission = if deletes {",
            "    let finalizer_admission = if unsafe { prepared.commit(); deletes } {",
            "Task 6 finalizer admission precedes deposit commit",
        ),
        (
            "finalizer callback releases admission before its last root access",
            "driver/fsring-fsd/src/lifecycle.rs",
            "    unsafe { crate::fence::run_queued_finalizer(registry, cell_index) };",
            "    unsafe { FinalizerCallbackAdmission::release_before_callback_for_test() };\n"
            "    unsafe { crate::fence::run_queued_finalizer(registry, cell_index) };",
            "Task 6 callback-last-access admission release",
        ),
        (
            "next-Staging no longer clears the visibility latch",
            "driver/fsring-fsd/src/lifecycle.rs",
            "            fsring_sys::c4::KeClearEvent(self.visibility_resolution_event());",
            "",
            "Task 6 next-Staging generation event clear",
        ),
        (
            "native effect-nine mapping omits one of its 17 rows",
            "driver/fsring-fsd/src/lifecycle.rs",
            "            (observed.core_admission_closed, P::CoreAdmissionClosed),",
            "            (observed.core_admission_closed, P::CoreSessionSlotsEmpty),",
            "Task 6 sealed 17 native predicate mapping",
        ),
        (
            "typed effect-nine mapping omits one of its 14 rows",
            "driver/fsring-fsd/src/driver.rs",
            "                plan::R3UnloadPredicate::ProcessCallbackAdmissionClosed,",
            "                plan::R3UnloadPredicate::ProcessCallbacksDrained,",
            "Task 6 exact 14 typed-receipt predicate mapping",
        ),
        (
            "safe sibling DriverState release bypass",
            "driver/fsring-fsd/src/driver.rs",
            "    pub(crate) fn reference_count(&self) -> u32 {",
            "    pub(crate) fn task6_bypass(&self) { self.release(); }\n\n"
            "    pub(crate) fn reference_count(&self) -> u32 {",
            "Task 6 unload exact implementation closure",
        ),
        (
            "DriverState Self release function-item bypass",
            "driver/fsring-fsd/src/driver.rs",
            "    pub(crate) fn reference_count(&self) -> u32 {",
            "    pub(crate) fn task6_bypass(&self) { let f = Self::release; f(self); }\n\n"
            "    pub(crate) fn reference_count(&self) -> u32 {",
            "Task 6 unload exact implementation closure",
        ),
        (
            "direct DriverState references mutation bypass",
            "driver/fsring-fsd/src/driver.rs",
            "    /// Release one root reference.\n"
            "    pub(crate) fn release(&self) {",
            "    pub(crate) fn task6_bypass(&self) { let _ = self.references.fetch_sub(1, Ordering::AcqRel); }\n\n"
            "    /// Release one root reference.\n"
            "    pub(crate) fn release(&self) {",
            "Task 6 effect 15 direct DriverState reference mutation bypass",
        ),
        (
            "aliased raw device-delete DDI bypass",
            "driver/fsring-fsd/src/driver.rs",
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "use fsring_sys::IoDeleteDevice as task6_burn;\n"
            "unsafe fn task6_bypass(d: PDEVICE_OBJECT) { unsafe { task6_burn(d) } }\n\n"
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "Task 6 effects 10-16 destructive symbol/import/macro census",
        ),
        (
            "destructive wrapper function-item bypass",
            "driver/fsring-fsd/src/driver.rs",
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "unsafe fn task6_bypass(d: PDEVICE_OBJECT) { let f = crate::kernel::delete_device; unsafe { f(d) } }\n\n"
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "Task 6 effects 10-16 destructive symbol/import/macro census",
        ),
        (
            "alternate foreign destructive binding bypass",
            "driver/fsring-fsd/src/driver.rs",
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "unsafe extern \"system\" {\n"
            "    #[link_name = \"IoDeleteDevice\"]\n"
            "    safe fn task6_burn(device: PDEVICE_OBJECT);\n"
            "}\n"
            "fn task6_bypass(device: PDEVICE_OBJECT) { task6_burn(device); }\n\n"
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "Task 6 alternate FFI/link_name destructive sink bypass",
        ),
        (
            "dynamic resolver destructive DDI bypass",
            "driver/fsring-fsd/src/kernel.rs",
            "pub fn resolve_optional_ddis() -> ResolvedDdis {\n"
            "    resolve_all(resolve_one)\n"
            "}",
            "pub fn resolve_optional_ddis() -> ResolvedDdis {\n"
            "    resolve_all(resolve_one)\n"
            "}\n\n"
            "unsafe fn task6_bypass(device: wdk_sys::PDEVICE_OBJECT) {\n"
            "    let address = resolve_one(\"IoDeleteDevice\").unwrap_or(0);\n"
            "    let burn: extern \"C\" fn(wdk_sys::PDEVICE_OBJECT) = unsafe { core::mem::transmute(address) };\n"
            "    burn(device);\n"
            "}",
            "Task 6 effects 10-16 destructive symbol/import/macro census",
        ),
        (
            "inferred-root release bypass",
            "driver/fsring-fsd/src/driver.rs",
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "unsafe fn task6_bypass() { let p = root(); unsafe { (*p).release() } }\n\n"
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "Task 6 receiver-independent DriverState release bypass",
        ),
        (
            "type-aliased DriverState release bypass",
            "driver/fsring-fsd/src/driver.rs",
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "type Task6Root = DriverState;\n"
            "fn task6_bypass(root: &Task6Root) { root.release(); }\n\n"
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "Task 6 effects 10-16 destructive sink/type alias bypass",
        ),
        (
            "inferred-root acquire bypass after effect-nine proof",
            "driver/fsring-fsd/src/driver.rs",
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "unsafe fn task6_bypass() { let p = root(); let _ = unsafe { (*p).acquire() }; }\n\n"
            "// ---------------------------------------------------------------------------\n// Unload\n",
            "Task 6 receiver-independent DriverState acquire bypass",
        ),
    )
    failures = []
    jobs = []
    for label, rel, old, new, expected in cases:
        source = raw_production.get(rel, "")
        if source.count(old) != 1:
            failures.append("%s anchor is not exact-one" % label)
            continue
        jobs.append((label, rel, strip_noncode(source.replace(old, new, 1)), expected))
    if jobs:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=min(4, len(jobs)),
            initializer=_initialize_task6_self_test,
            initargs=(production,),
        ) as executor:
            failures.extend(
                failure
                for failure in executor.map(_run_task6_mutation_case, jobs)
                if failure is not None
            )
    for failure in failures:
        print("FAIL: %s" % failure)
    print(
        "audit_c4_lifetime task6-self-test: %s (%d mutations, %d failures)"
        % ("PASS" if not failures else "FAIL", len(cases), len(failures))
    )
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="exit on the first self-test failure (C4 auditor mutants)",
    )
    parser.add_argument(
        "--skip-task12-wave",
        action="store_true",
        help="grade Task 12 whole-tree probes as declared without running them",
    )
    parser.add_argument("--task5-self-test", action="store_true")
    parser.add_argument("--task6-self-test", action="store_true")
    parser.add_argument("--production-check", action="store_true")
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--root", default=os.getcwd())
    args = parser.parse_args()

    if args.self_test:
        return self_test(
            fail_fast=args.fail_fast, skip_task12_wave=args.skip_task12_wave
        )
    if args.task5_self_test:
        return task5_self_test()
    if args.task6_self_test:
        return task6_self_test()
    if not args.source_root:
        print("FAIL: --source-root is required", file=sys.stderr)
        return 2

    try:
        if args.production_check:
            production_roots = canonical_source_roots(args.root, args.source_root)
            expected_roots = {
                "driver/fsring-core/src",
                "driver/fsring-fsd/src",
            }
            if len(production_roots) != 2 or set(production_roots) != expected_roots:
                raise LifetimeAuditError(
                    "production-check requires the exact core/fsd source-root identities"
                )
        evidence = []
        native_files_seen = set()
        pending_shapes_seen = set()
        findings, audited = audit_tree(
            args.root,
            args.source_root,
            evidence,
            native_files_seen,
            pending_shapes_seen,
        )
    except LifetimeAuditError as error:
        print("FAIL: %s" % error, file=sys.stderr)
        return 2

    # An unaudited carrier is reported, not silently treated as clean. A carrier
    # that was renamed or deleted would otherwise make this audit pass by
    # looking at nothing.
    missing = sorted(set(CARRIERS) - audited)
    findings.extend(
        "carrier `%s` was not found in the audited roots" % carrier
        for carrier in missing
    )
    findings.extend(
        "native owner file `%s` was not found in the audited roots" % rel
        for rel in sorted(NATIVE_OWNER_FILES - native_files_seen)
    )
    findings.extend(
        "%s: frozen pending shape `%s` was not found in the audited roots"
        % (rel, struct)
        for rel, struct in sorted(set(PENDING_SHAPE_BODIES) - pending_shapes_seen)
    )
    for finding in findings:
        print("FAIL: %s" % finding, file=sys.stderr)
    print(
        '{"audit":"c4-lifetime","result":"%s","carriersAudited":%d,"findings":%d}'
        % ("FAIL" if findings else "PASS", len(audited), len(findings))
    )
    if args.production_check:
        checks = sum(
            1 for label in evidence
            if label.split(":", 1)[0] in COUNTED_EVIDENCE_FILES
        )
        print(
            "audit_c4_lifetime production-check: %s (%d checks, %d failures)"
            % ("PASS" if not findings else "FAIL", checks, len(findings))
        )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
