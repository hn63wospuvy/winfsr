#!/usr/bin/env python3
"""Per-guard mutation gate for a named `fsring-core` source file.

Pointed with --src; ALLOWLISTS, FLOORS and MIN_CAUGHT are all keyed by that
path, because each is a fact about one file. Default target: reqtab.rs.

Why this exists
---------------
Rounds 1 and 2 of the B5 gate review each found guards the suite could not see
break, by hand; round 2 found thirteen more than round 1. That does not
converge, so this enumerates them mechanically instead.

Rounds 3 and 4 then found the *enumeration's* completeness claim false, twice:
round 3 because operator E was a hand-written table whose comment asserted
"there are four arms", and round 4 because the parser that replaced it was
wrapped in an undeclared `any("Err(" in arm)` filter. Both times a publicly
reachable unwatched decision was hiding in the gap.

So this file no longer claims to enumerate every decision in the module. It
states exactly which syntactic constructs it covers, and exactly which it does
not. A claim that names its own boundary cannot be falsified by finding
something outside it; a universal quantifier can, and twice was.

WHAT IS COVERED
---------------
  A  every `if <cond> { .. }` STATEMENT -- condition forced to `false`
  D  every top-level `||` operand of such a condition, dropped individually
  C  the three mode-gate comparisons, direction-swapped
  E  every alternative of an or-pattern in a `match` arm, MOVED to the sibling
     arm that would otherwise accept it (moved, not deleted: deleting makes an
     exhaustive match non-exhaustive, and a mutant the compiler rejects proves
     nothing)
  G  every `match` arm `if` guard, disabled, plus each of its `&&` operands
  H  every top-level alternative of a `matches!` pattern, dropped individually
  B  every `validate_application_key` / `validate_control_key` call site,
     bypassed
  I  every `let .. else { .. }` failure branch, asserted unreachable. A
     refutable pattern cannot be forced to match, so the mutation asserts the
     branch is never taken: CAUGHT means a test drives it, SURVIVED means
     nothing does. This family was the named unmeasured gap through rev 5.
     It is REPORTED BUT NON-BLOCKING -- see NON_BLOCKING above for why, and
     for what the number does and does not establish. This is a weaker
     guarantee than operators A-H carry, and it is labelled as one.

E, G, H and I are derived by parsing the source. There is no hand-written list of
sites anywhere in this file.

WHAT IS NOT COVERED — measured, not assumed
-------------------------------------------
Each of these was checked BY HAND, PER TARGET FILE, and the result is recorded
so a later reader knows whether the gap is empty or merely unexplored. A new
--src target does NOT inherit these results: re-run the hand-check and record it,
which is what slice C1 did in
docs/superpowers/reviews/evidence/2026-07-28-driver-c1-uncovered-constructs.md
after its own review round 1 caught the block being silently inherited.

Measured for reqtab.rs (B5) and, where noted, for effect.rs / lockrank.rs (C1):

  * `if` used as an EXPRESSION (`let x = if c { a } else { b }`). Operator A's
    scan is anchored to statement position.
      reqtab.rs:   two sites (`reclaim_completed`, `reclaim_control`, both
                   epoch-carry ternaries); both hand-mutated, both CAUGHT.
      effect.rs / lockrank.rs (C1): two sites, both the `IoCompleteRequest` arm
                   of their checker; both hand-mutated, both CAUGHT.
  * top-level `&&` operands of statement `if`s. Operator D splits only `||`.
      reqtab.rs:   six operands; all six hand-dropped, all six CAUGHT.
      effect.rs (C1): five rules, each a two-conjunct `&&`; both conjuncts of
                   each hand-dropped -- ten mutants, all ten CAUGHT.

  * comparison-operator swaps (`<` for `<=`) and arithmetic. Not attempted.
  * `typestate.rs`. Contains zero fallible guards; its properties are proven by
    compile-fail fixtures, not runtime branches.

If a later slice puts a real decision into one of those constructs, this
section is wrong and should be corrected rather than quietly relied upon.

Each operator carries a floor on how many mutants it must enumerate. C, B and
the mode-swap literals are matched against source text, so a rename or a
reformat would otherwise yield zero mutants with the run still printing PASS.
The floors caught exactly that during development, when an escape arrived
mangled and operator H silently enumerated nothing.

Verdicts
--------
  CAUGHT     the suite went red. This is the goal.
  SURVIVED   nothing noticed. A failure unless the mutant is in ALLOWLIST.
  NOCOMPILE  not a behavioural mutant; reported, not counted against the gate.
             Ten at the SHA this was written against, in three families, all
             stable: four `if let` bindings operator A cannot express (forcing
             the condition to `false` deletes the binding the body uses); two
             match-arm guards in `terminalize_control` / `reclaim_control`,
             which A also matches as statement-level `if`s and which operator G
             mutates properly; and four operator-E moves in `rebind_session`
             that produce a type error. All are left in the enumeration rather
             than filtered out so the count stays honest, and their behaviour is
             covered by `drain_permutation_returns_every_capability_once`,
             `a_rebind_carries_parked_entries_across_and_heals_exhaustion` and
             `terminalize_control_arm_guard_pins_both_of_its_operands`.
  HARNESS    the detector executed zero tests, so the run proves nothing. Always
             a failure -- the first version of this harness graded eight mutants
             from runs of zero tests and reported them all as survivors.

The gate fails on any unexpected survivor AND on any allowlisted mutant that has
become CAUGHT, so the allowlist cannot rot into a list of excuses.

Runtime is roughly 8s per mutant (a full rebuild and test run each), so this is
a slice-closing gate, not a per-commit one. The C4 suite is heavier because
some owning commands compile the native image. Parallel workers and a crash
journal change wall-clock time and recoverability, not the oracle: every
mandatory mutant still runs its exact owning command, HARNESS is never
replayed, and a journalled CAUGHT/SURVIVED/NOCOMPILE is reused only when the
git tree fingerprint, roster, and runner bytes still match. Run it from the
repository root:

    python driver/scripts/mutation_sweep.py            # gate
    python driver/scripts/mutation_sweep.py --list     # enumerate, do not run
    python driver/scripts/mutation_sweep.py --suite c4 --jobs 4
    python driver/scripts/mutation_sweep.py --self-test
"""
import argparse
import hashlib
import json
import queue
import shutil
import tempfile
import threading
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REL_SRC = "driver/fsring-core/src/reqtab.rs"

# Operators whose survivors are REPORTED but do not fail the gate, with the
# reason stated. Only operator I is in here, and the reason is structural
# rather than convenient.
#
# A `let .. else` failure branch is fail-closed defensive code whose PURPOSE is
# to be unreachable: `let Some(slot) = self.application.get(index)` after the
# validator already bounds-checked `index`, `let ApplicationSlotState::Live =
# &slot.state` after the same validator already matched `Live`, `let Ok(i) =
# usize::try_from(u32)` on a 64-bit target. A survivor there means "no test
# drives this branch", which for defensive code is the expected answer, not a
# defect.
#
# That is NOT true of operators A-H, where a survivor means a real decision
# nothing is watching. So operator I is measured and reported, and the number
# is carried in the evidence rather than being forced to zero. Forcing it to
# zero would mean either 69 hand-written allowlist justifications -- the
# hand-table defect that failed rounds 3 and 4, one more time -- or 69 tests
# asserting that unreachable code is unreachable.
#
# What the number DOES establish: a floor on how many of these branches ARE
# driven by tests. If a change makes a previously-exercised defensive branch
# unreachable, MIN_CAUGHT below trips.
NON_BLOCKING = {"[I]"}
# PER SOURCE FILE, for the same reason as ALLOWLISTS and FLOORS: the number of
# defensive branches a suite happens to drive is a fact about one file's tests,
# and reqtab.rs's 20 says nothing about another file's. Measured at the SHA each
# entry was added; a drop means a branch that used to be exercised no longer is.
MIN_CAUGHT = {
    "driver/fsring-core/src/reqtab.rs": {"[I]": 20},
    # Measured 2026-07-28 at slice C1. effect.rs's let-else branches are almost
    # all in TESTS -- `let Ok(g) = ctx.acquire(..) else { panic!(..) }` -- whose
    # failure arms are deliberately never taken, which is exactly the shape
    # operator I is documented as reporting rather than blocking.
    "driver/fsring-core/src/effect.rs": {"[I]": 1},
    # Measured 2026-07-28. Without an entry here lockrank.rs would have no [I]
    # regression floor at all -- the same "no entry quietly means no check"
    # hole the FLOORS bootstrap closes.
    "driver/fsring-core/src/lockrank.rs": {"[I]": 3},
    # Measured 2026-07-30 for C3 Task 1. The control IOCTL demux's `let else`
    # failure branch is live for an unknown code and must stay exercised.
    "driver/fsring-core/src/controldev.rs": {"[I]": 1},
}


# Survivors that no input can reach, because an earlier invariant already
# excludes it. Each is proven unreachable by a named test that establishes the
# guarded property across the whole admissible domain -- which is what makes
# the guard dead -- rather than by asserting the mutant is acceptable.
# Allowlists are PER SOURCE FILE. reqtab.rs's fourteen proofs are proofs about
# reqtab.rs's guards; pointing --src at another file must not inherit them. A
# file with no entry gets no allowlist, which is the correct default -- an
# unproven survivor fails.
# Anti-rot floors, PER SOURCE FILE, for the same reason the allowlists are:
# these are the operator counts measured at the SHA each file's gate was written
# against, and reqtab.rs's counts say nothing about another file. A file with no
# entry gets no floors, and a run against such a file ABORTS rather than
# proceeding unprotected -- "no entry" must not quietly become "no anti-rot
# check". `--measure-floors` prints the counts for a new file so they can be
# recorded here deliberately.
FLOORS = {
    "driver/fsring-core/src/reqtab.rs": {
        "[A]": 100, "[D]": 60, "[C]": 16, "[E]": 16, "[G]": 7, "[B]": 11, "[H]": 10, "[I]": 50,
    },
    # Measured 2026-07-28 by --measure-floors at slice C1. Operators C, B and G
    # enumerate ZERO here, and that is recorded as measured-absent rather than
    # as a floor of zero: C keys on reqtab's three mode-gate comparisons, B on
    # its validate_*_key call sites, G on match-arm `if` guards, and none of
    # those constructs exists in these files. A floor of 0 would pass whether
    # the operator was absent or blind, which is the distinction these floors
    # exist to preserve.
    "driver/fsring-core/src/effect.rs": {
        "[A]": 13, "[D]": 2, "[H]": 10, "[I]": 11,
    },
    # [A] fell 21 -> 20 and [I] appeared at 4 when C1 replaced three dead `if`
    # guards this sweep itself exposed (two `held.bits() != bits` filters that
    # `from_bits`'s masking makes unreachable, and one redundant `continue`)
    # and added the kind-classification test. Updated deliberately, which is
    # what this file's own anti-rot comment asks for when a real refactor moves
    # a count.
    "driver/fsring-core/src/lockrank.rs": {
        "[A]": 21, "[D]": 6, "[E]": 20, "[H]": 15, "[I]": 4,
    },
    # Measured 2026-07-30 for C3 Task 1. [A] is six (three CREATE, two
    # authorization, and the synchronous IOCTL authorization gate); [D] is
    # two. [I] is the unknown-control-code demux failure branch. Generated
    # code/function comparisons remain inside macro expansion and are invisible
    # to this source mutator. Operators C, E, G and H enumerate ZERO and are
    # left OUT rather than floored at 0. Absent is not blind, and a floor of 0
    # would pass either way.
    "driver/fsring-core/src/controldev.rs": {
        "[A]": 6, "[D]": 2, "[I]": 1,
    },
}

ALLOWLISTS = {
    "driver/fsring-core/src/reqtab.rs": {
    "RequestTopology::try_new/!matches!(classify_table_index(topology,0),Ok(ReqIndexClass::Application{index:0}))":
        "slot 0 is the first application slot for every legal topology; "
        "max_inflight == 0 is rejected by the bounds check above. The property "
        "depends only on max_inflight > 0, and "
        "topology_self_checks_are_dead_by_construction checks it at both bounds "
        "of each axis plus interior points -- a sample, not the whole legal "
        "rectangle, which is ~10^9 pairs and is not enumerable.",
    "RequestTopology::try_new/classify_table_index(topology,last_system).is_err()||!matches!(classify_table_index(topology,GLOBAL_EXTERNAL_CHANGE_ACK_REQID),Ok(ReqIndexClass::ExternalChangeAck))":
        "ring_count <= MAX_RING_COUNT makes the last system index classify, and "
        "the global acknowledgement index is a fixed constant. Same test.",
    "ControlStorage::control_storage/classify_table_index(topology,slot_index)!=Ok(expected_class)":
        "slot_index is computed from the lane's own ring and offset immediately "
        "above, after the ring-range check, so it always classifies back to that "
        "lane's class. Round-tripped for every lane on every ring by the same test.",
    "RequestTable::admit_application/!matches!(classify_table_index(self.topology,slot_index),Ok(ReqIndexClass::Application{index})ifindex==slot_index)":
        "the constructor pins application.len() == topology.max_inflight "
        "(reqtab.rs, TableInitError::ApplicationLength), so every index below "
        "the backing length classifies as Application and every index at or "
        "above it is rejected by the `get_mut` below with the same "
        "AdmissionError::Full. The guard cannot change an outcome. Proven by "
        "topology_self_checks_are_dead_by_construction.",

    # The lane bijection. `control_storage` maps a lane to exactly one slot
    # index and `control_lane_from_class(classify(index))` maps it back, so a
    # slot can only ever hold the lane that resolves to it. Every comparison of
    # a re-derived lane against a recorded one is therefore dead. Proven both
    # directions, for every lane on every ring, by
    # topology_self_checks_are_dead_by_construction.
    "RequestTable::begin_capture/*current_lane!=lane||*current_req_id!=req_id#drop0":
        "lane is derived from the slot's own class; the slot was occupied by "
        "admit_control through the inverse map. Identity comparison in the same "
        "guard remains watched.",
    "RequestTable::terminalize_control/*lane!=captured.lane||*birth_session_epoch!=captured.birth_session_epoch||*birth_generation!=captured.birth_generation#drop0":
        "the slot is fetched through control_storage(captured.lane), so a lane "
        "mismatch would mean the slot resolved from one lane recorded another. "
        "Birth comparisons in the same guard remain watched.",
    "RequestTable::validate_control_key/*lane!=key.lane||*birth_session_epoch!=key.birth_session_epoch||*birth_generation!=key.birth_generation#drop0":
        "same fetch, same bijection; the guard above already pins "
        "storage.slot_index() == key.slot_index. Birth comparisons remain watched.",

    # `Pristine` is unreachable once a table exists: `RequestTable::try_new`
    # requires every backing slot to arrive Pristine and then writes them all
    # to `Free` / `Available` before returning, and no transition writes
    # Pristine back. Moving it between capture arms therefore cannot change an
    # outcome. Proven by pristine_is_unreachable_once_a_table_exists.
    "RequestTable::begin_capture/orpattern/ApplicationSlotState::Pristine|ApplicationSlotState::Free{..}#alt0":
        "an application slot is never Pristine after construction.",
    "RequestTable::begin_capture/orpattern/ControlSlotState::Pristine|ControlSlotState::Available{..}#alt0":
        "a control slot is never Pristine after construction.",

    "RequestTable::rebind_session/index==0":
        "the reverse walk is `while let Some(index) = backing_index.checked_sub(1)` "
        "with `backing_index = index`, so the iteration after index 0 computes "
        "`0.checked_sub(1) == None` and the loop ends anyway. The `break` is a "
        "redundant early exit that cannot change which slots are visited. "
        "Proven by a_rebind_visits_every_application_slot.",

    "ControlStorage::capture_state_error/orpattern/WireState::BetweenPhases|WireState::PreparedNotVisible|WireState::Visible|WireState::Quarantined|WireState::GenerationExhausted#alt2":
        "both call sites of capture_state_error sit behind "
        "`if *wire_state != WireState::Visible`, so Visible can never reach it. "
        "The other four alternatives of the same arm are live and watched; only "
        "this one is unreachable. Proven by "
        "capture_state_error_maps_every_unpublished_state_to_not_visible, which "
        "scans the call sites and shows a Visible entry captures instead.",

    "ControlStorage::control_storage/ring_index>=topology.ring_count":
        "redundant with the classification check below it AND with the backing "
        "bounds check in the caller: the constructor pins system.len() == "
        "ring_count * SYSTEM_REQUEST_SLOTS_PER_RING, so an out-of-range ring "
        "yields a backing index past the end and the same RingOutOfRange. All "
        "three paths agree, so no input distinguishes this guard. Removing the "
        "whole set is still refused -- a_control_lane_beyond_the_ring_count_is_refused "
        "asserts the refusal itself, and the backing invariant is proven in "
        "topology_self_checks_are_dead_by_construction.",
    },
}

# --- the C4 source gate's frozen tool contract -----------------------------
#
# A pinned toolchain SELECTOR (`cargo +1.85.0`) is not a pinned toolchain: it
# asks whatever rustup is on PATH to pick a payload, and the gate has already
# removed every selector variable from this process's environment. So under the
# gate each child is launched through the exact frozen payload path, verified
# against the SHA-256 the runner measured through its retained deny-write
# handle, with CARGO/RUSTC/RUSTDOC set to the same set.
#
# Outside the gate nothing is supplied and the argv is used unchanged, so an
# ordinary developer sweep still works.

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
C4_LAUNCH_LOCK = threading.Lock()
MUTATION_JOURNAL_SCHEMA = "fsring-mutation-journal/v1"
JOURNALABLE_VERDICTS = ("CAUGHT", "SURVIVED", "NOCOMPILE")


def c4_role_suffix(role):
    return role.upper().replace("-", "_").replace(".", "_")


def c4_frozen_tool(role):
    """The verified absolute path for one frozen role, or None outside the gate.

    The hash check is the point: a path that still exists proves nothing about
    the bytes behind it."""
    suffix = c4_role_suffix(role)
    path = os.environ.get("FSRING_C4_TOOL_" + suffix)
    if not path:
        return None
    expected = os.environ.get("FSRING_C4_TOOL_" + suffix + "_SHA256")
    if not expected:
        raise SystemExit("frozen role %s has no SHA-256" % role)
    digest = hashlib.sha256(io.open(path, "rb").read()).hexdigest()
    if digest != expected:
        raise SystemExit("frozen role %s does not match its frozen SHA-256" % role)
    return path


def c4_under_source_gate():
    return bool(os.environ.get("FSRING_C4_MARKER_NONCE"))


def c4_apply_frozen_tools(cmd, env):
    """Rewrite one child argv to launch a frozen payload, and record the launch."""
    cmd = list(cmd)
    env = dict(env)
    head = cmd[0] if cmd else ""
    role = None
    version = None
    if head == "cargo" and len(cmd) > 1 and cmd[1] in ("+1.82.0", "+1.85.0"):
        version = cmd[1][1:]
        role = "cargo-" + version
    elif head in ("powershell.exe", "powershell"):
        role = "powershell"
    elif head in ("python", "python.exe"):
        role = "python"
    if role is None:
        return cmd, env
    path = c4_frozen_tool(role)
    if path is None:
        if c4_under_source_gate():
            raise SystemExit(
                "the C4 source gate supplied no frozen payload for role %s" % role)
        return cmd, env
    if version is not None:
        # The selector element is DROPPED, not kept: leaving `+1.85.0` in the
        # argv of a payload cargo makes it try to re-dispatch through rustup.
        del cmd[1]
        for name, member in (("CARGO", "cargo"), ("RUSTC", "rustc"), ("RUSTDOC", "rustdoc")):
            member_path = c4_frozen_tool(member + "-" + version)
            if member_path is None:
                raise SystemExit(
                    "the C4 source gate supplied no frozen %s-%s" % (member, version))
            env[name] = member_path
            with C4_LAUNCH_LOCK:
                C4_LAUNCH_COUNTS[member + "-" + version] = C4_LAUNCH_COUNTS.get(
                    member + "-" + version, 0)
    cmd[0] = path
    with C4_LAUNCH_LOCK:
        C4_LAUNCH_COUNTS[role] = C4_LAUNCH_COUNTS.get(role, 0) + 1
    return cmd, env


def c4_emit_marker(phase):
    """One sentinel-prefixed canonical line naming every supplied frozen role.

    The ROSTER is the runner's oracle, not this script's: it supplies exactly
    the roles its literal per-row map allows, and every one is echoed here only
    after its bytes were verified. `launchCounts` additionally reports what this
    process actually launched, which is what a helper that ignored a supplied
    payload cannot fake."""
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


# Cargo paints `error` and `:` with separate CSI wraps, so a literal
# `error: could not compile` misses parse errors and grades them HARNESS.
_ANSI_CSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def write_utf8(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.flush()


def sh(cmd, cwd, env=None):
    cmd, child_env = c4_apply_frozen_tools(cmd, env or os.environ.copy())
    p = subprocess.run(cmd, capture_output=True, cwd=cwd,
                       env=child_env)
    def decode(raw):
        if not raw:
            return ""
        return raw.decode("utf-8", errors="replace")
    # Windows devenv wrappers emit CRLF; grader regexes anchor on `$`.
    text = (decode(p.stdout) + decode(p.stderr)).replace("\r\n", "\n").replace("\r", "\n")
    return p.returncode, _ANSI_CSI.sub("", text)


def enclosing_fn(src, offset):
    """Name of the `fn` the offset sits inside -- a stable mutant identity that
    survives line moves, unlike a line number."""
    best = "?"
    for m in re.finditer(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+([A-Za-z0-9_]+)", src[:offset]):
        best = m.group(1)
    # Qualify by the enclosing `impl` type so `RequestTopology::try_new` and
    # `RequestTable::try_new` cannot collapse into one identity and share an
    # allowlist entry. Round 3 filed the collision as latent; keying an
    # allowlist on a non-unique string is how it stops being latent.
    owner = ""
    for m in re.finditer(r"(?m)^impl(?:<[^>]*>)?\s+(?:[^\n{]+\s+for\s+)?([A-Za-z0-9_]+)", src[:offset]):
        owner = m.group(1)
    return f"{owner}::{best}" if owner else best


def norm(text):
    return "".join(text.split())


def find_guards(src):
    out = []
    for m in re.finditer(r"(?m)^([ \t]*)(\} else if |if )", src):
        cond_start = m.end()
        i, depth = cond_start, 0
        while i < len(src):
            c = src[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif c == "{" and depth == 0:
                break
            elif c == ";" and depth == 0:
                i = -1
                break
            i += 1
        if i <= 0 or i >= len(src):
            continue
        d, j = 0, i
        while j < len(src):
            if src[j] == "{":
                d += 1
            elif src[j] == "}":
                d -= 1
                if d == 0:
                    break
            j += 1
        # EVERY `if` condition, not only early-exit ones. Round 3 found
        # `rebind_session`'s generation-exhaustion healing unwatched
        # precisely because its body assigns instead of returning `Err`,
        # so an early-exit filter never enumerated it. A decision is a
        # decision whatever its body does.
        cond = src[cond_start:i].strip()
        if not cond or cond == "false" or len(cond) > 400:
            continue
        out.append((cond_start, i, cond))
    return out


def split_conjuncts(cond):
    parts, depth, start, i = [], 0, 0, 0
    while i < len(cond):
        c = cond[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and cond[i:i + 2] == "||":
            parts.append((start, i))
            i += 2
            start = i
            continue
        i += 1
    parts.append((start, len(cond)))
    return parts if len(parts) > 1 else []


MODE_SWAPS = [
    ("self.mode != TableMode::Active", "self.mode == TableMode::Draining"),
    ("self.mode == TableMode::Draining", "self.mode != TableMode::Active"),
    ("self.mode != TableMode::Fencing", "self.mode == TableMode::Draining"),
]

# ---------------------------------------------------------------------------
# Match-arm parsing. Operators E and G are DERIVED from the source, not listed.
#
# Round 3 found the need for this the hard way. E used to be a hand-written
# eight-entry table whose own comment asserted "there are four arms". There
# were more, and a publicly reachable unwatched decision was hiding in the gap:
# an unoccupied control lane and a retired one were indistinguishable to the
# caller with no test noticing. A hand table drifts from the source; an
# enumeration cannot.
# ---------------------------------------------------------------------------
WS = " \t\r\n"


def _matching_brace(src, open_idx):
    depth, i = 0, open_idx
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_match_blocks(src):
    """(body_open, body_close) for every `match .. { .. }`."""
    out = []
    for m in re.finditer(r"\bmatch\b", src):
        i, depth = m.end(), 0
        while i < len(src):
            c = src[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif c == "{" and depth == 0:
                break
            elif c == ";":
                i = -1
                break
            i += 1
        if i <= 0 or i >= len(src):
            continue
        close = _matching_brace(src, i)
        if close > 0:
            out.append((i, close))
    return out


def split_arms(src, open_idx, close_idx):
    """(pat_start, pat_end, body_start, body_end) for each arm of one match."""
    arms, i = [], open_idx + 1
    while i < close_idx:
        while i < close_idx and src[i] in WS:
            i += 1
        if i >= close_idx:
            break
        if src.startswith("//", i):
            nl = src.find("\n", i)
            if nl < 0:
                break
            i = nl + 1
            continue
        pat_start, depth, arrow = i, 0, -1
        while i < close_idx:
            c = src[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0 and src.startswith("=>", i):
                arrow = i
                break
            i += 1
        if arrow < 0:
            break
        j = arrow + 2
        while j < close_idx and src[j] in WS:
            j += 1
        if j < close_idx and src[j] == "{":
            body_end = _matching_brace(src, j) + 1
        else:
            d, body_end = 0, j
            while body_end < close_idx:
                c = src[body_end]
                if c in "([{":
                    d += 1
                elif c in ")]}":
                    if d == 0:
                        break
                    d -= 1
                elif c == "," and d == 0:
                    break
                body_end += 1
        arms.append((pat_start, arrow, j, body_end))
        i = body_end
        while i < close_idx and (src[i] in WS or src[i] == ","):
            i += 1
    return arms


def split_pattern(pat):
    """(top-level `|` alternatives, trailing `if` guard text or None)."""
    guard, depth, i, body = None, 0, 0, pat
    while i < len(pat):
        c = pat[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and re.match(r"\bif\b", pat[i:]):
            body, guard = pat[:i], pat[i:]
            break
        i += 1
    parts, depth, start, i = [], 0, 0, 0
    while i < len(body):
        c = body[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "|" and body[i:i + 2] != "||" and (i == 0 or body[i - 1] != "|"):
            parts.append(body[start:i])
            start = i + 1
        i += 1
    parts.append(body[start:])
    return [p.strip() for p in parts if p.strip()], guard


def _macro_sites(src, name):
    """Offsets of every `name` token, found by plain scan. No regex: this used
    to be `re.finditer(r"\\b" + name + ...)` and the escape kept arriving
    mangled, which silently made the operator enumerate nothing."""
    out, pos = [], 0
    while True:
        pos = src.find(name, pos)
        if pos < 0:
            return out
        before = src[pos - 1] if pos else " "
        after = src[pos + len(name):pos + len(name) + 8].lstrip()
        if not (before.isalnum() or before == "_") and after.startswith("("):
            out.append(pos)
        pos += len(name)


def matches_macro_mutants(src):
    """Operator H: drop one top-level alternative from a `matches!` pattern.

    `matches!` is a macro, so `find_match_blocks` never sees it and operators
    A-G cannot reach inside one. Round 4 found `rebind_session`'s global
    control lane healing unwatched for exactly that reason, while the system
    lane's identical `matches!` was covered -- an asymmetry, not a decision.
    Operator A can only force the whole `if matches!(..)` to false; this drops
    one state out of the set.
    """
    out = []
    for pos in _macro_sites(src, "matches!"):
        open_paren = src.index("(", pos + len("matches!"))
        depth, i = 0, open_paren
        while i < len(src):
            c = src[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= len(src):
            continue
        inner = src[open_paren + 1:i]
        # split scrutinee from pattern at the first top-level comma
        d, comma = 0, -1
        for k, c in enumerate(inner):
            if c in "([{":
                d += 1
            elif c in ")]}":
                d -= 1
            elif c == "," and d == 0:
                comma = k
                break
        if comma < 0:
            continue
        pat = inner[comma + 1:]
        alts, _guard = split_pattern(pat)
        if len(alts) < 2:
            continue
        fn = enclosing_fn(src, pos)
        for ai, alt in enumerate(alts):
            kept = " | ".join(a for n, a in enumerate(alts) if n != ai)
            mutated = src[:open_paren + 1] + inner[:comma + 1] + " " + kept + src[i:]
            out.append((
                f"{fn}/matches/{norm(pat)}#alt{ai}",
                f"[H] {fn}: matches! alternative dropped -- "
                f"{' '.join(alt.split())[:80]}",
                mutated,
            ))
    return out


def let_else_mutants(src):
    """Operator I: replace each `let .. else { .. }` failure branch with
    `unreachable!()`.

    A refutable pattern cannot be forced to match, so the meaningful mutation
    is to assert the failure branch is never taken. CAUGHT means a test drives
    that branch. SURVIVED means nothing does -- the branch is either dead by
    construction or unwatched, and the allowlist has to say which.

    This family was named as the sweep's largest UNMEASURED gap through rev 5.
    It is measured now.
    """
    out = []
    for m in re.finditer(r"(?m)^([ \t]*)let\s", src):
        i, depth, else_at = m.end(), 0, -1
        while i < len(src):
            c = src[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif c == ";" and depth == 0:
                break
            elif (depth == 0 and src.startswith("else", i)
                  and src[i - 1] in " \t\n"
                  and src[i + 4:i + 6].lstrip().startswith("{")):
                else_at = i
                break
            i += 1
        if else_at < 0:
            continue
        brace = src.index("{", else_at)
        close = _matching_brace(src, brace)
        if close < 0 or not src[brace + 1:close].strip():
            continue
        fn = enclosing_fn(src, m.start())
        head = " ".join(src[m.start():else_at].split())[:90]
        out.append((
            f"{fn}/letelse/{norm(head)}",
            f"[I] {fn}: let-else failure branch asserted unreachable -- {head}",
            src[:brace + 1]
            + ' unreachable!("mutation: let-else branch taken") '
            + src[close:],
        ))
    return out


def match_mutants(src):
    """Operator E (or-pattern alternative moved to the sibling arm) and
    operator G (match-arm `if` guard disabled, and its conjuncts dropped)."""
    out = []
    for open_idx, close_idx in find_match_blocks(src):
        arms = split_arms(src, open_idx, close_idx)
        # EVERY match, with no filter on what its arms return. Rev 4 kept an
        # `any("Err(" in arm)` heuristic here and round 4 filed it as a
        # Critical: it silently excluded three match blocks and eleven
        # or-pattern alternatives, one of which
        # (`capture_state_error`) hid a publicly observable unwatched
        # decision. An undeclared filter behind a universal quantifier is the
        # same defect as the hand-written table it replaced, one level down.
        for k, (ps, pe, bs, be) in enumerate(arms):
            pat = src[ps:pe]
            alts, guard = split_pattern(pat)

            if guard is not None:
                fn = enclosing_fn(src, ps)
                gtext = guard.strip()
                cond = gtext[2:].strip() if gtext.startswith("if") else gtext
                # G: disable the arm guard entirely.
                out.append((
                    f"{fn}/armguard/{norm(cond)}",
                    f"[G] {fn}: match-arm guard disabled -- {' '.join(cond.split())[:90]}",
                    src[:ps] + pat.replace(guard, "if true ") + src[pe:],
                ))
                # G: drop each top-level `&&` operand of the arm guard.
                ops, d, st, i = [], 0, 0, 0
                while i < len(cond):
                    c = cond[i]
                    if c in "([{":
                        d += 1
                    elif c in ")]}":
                        d -= 1
                    elif d == 0 and cond[i:i + 2] == "&&":
                        ops.append(cond[st:i])
                        st = i + 2
                        i += 2
                        continue
                    i += 1
                ops.append(cond[st:])
                ops = [o.strip() for o in ops if o.strip()]
                if len(ops) > 1:
                    for oi in range(len(ops)):
                        kept = " && ".join(o for n, o in enumerate(ops) if n != oi)
                        out.append((
                            f"{fn}/armguard/{norm(cond)}#drop{oi}",
                            f"[G] {fn}: arm-guard operand dropped -- "
                            f"{' '.join(ops[oi].split())[:80]}",
                            src[:ps] + pat.replace(guard, f"if {kept} ") + src[pe:],
                        ))

            if len(alts) > 1:
                sib = arms[k + 1] if k + 1 < len(arms) else (arms[k - 1] if k else None)
                if sib is None:
                    continue
                sps, spe = sib[0], sib[1]
                fn = enclosing_fn(src, ps)
                for ai, alt in enumerate(alts):
                    kept = [a for n, a in enumerate(alts) if n != ai]
                    new_pat = "\n                | ".join(kept)
                    if guard:
                        new_pat = new_pat + " " + guard
                    sib_pat = src[sps:spe].rstrip()
                    new_sib = sib_pat + "\n                | " + alt + " "
                    # rebuild right-to-left so the earlier offsets stay valid
                    if sps > ps:
                        mutated = (src[:ps] + new_pat + src[pe:sps] + new_sib + src[spe:])
                    else:
                        mutated = (src[:sps] + new_sib + src[spe:ps] + new_pat + src[pe:])
                    out.append((
                        f"{fn}/orpattern/{norm(pat)}#alt{ai}",
                        f"[E] {fn}: or-pattern alternative moved to the sibling arm -- "
                        f"{' '.join(alt.split())[:80]}",
                        mutated,
                    ))
    return out


VALIDATOR_SITES = [
    ("let index = self.validate_application_key(key)?;",
     "let index = usize::try_from(key.slot_index).unwrap_or(0);"),
    ("let storage = self.validate_control_key(key)?;",
     "let storage = match control_storage(self.topology, key.lane) { Ok(s) => s, "
     "Err(_) => return Err(ControlError::Key(KeyError::WrongClass)) };"),
]


def build_mutants(src, floors):
    """(identity, description, mutated_source) for every mutant, in a stable order."""
    out = []
    guards = find_guards(src)
    for a, b, cond in guards:
        fn = enclosing_fn(src, a)
        out.append((f"{fn}/{norm(cond)}", f"[A] {fn}: guard disabled -- {' '.join(cond.split())[:100]}",
                    src[:a] + " false " + src[b:]))
        for pi, (pa, pb) in enumerate(split_conjuncts(cond)):
            kept = [cond[x:y].strip() for k, (x, y) in enumerate(split_conjuncts(cond)) if k != pi]
            dropped = " ".join(cond[pa:pb].split())
            out.append((f"{fn}/{norm(cond)}#drop{pi}",
                        f"[D] {fn}: conjunct dropped -- {dropped[:100]}",
                        src[:a] + " " + " || ".join(kept) + " " + src[b:]))
    for needle, repl in MODE_SWAPS:
        start = 0
        while True:
            idx = src.find(needle, start)
            if idx < 0:
                break
            fn = enclosing_fn(src, idx)
            out.append((f"{fn}/modeswap/{norm(needle)}->{norm(repl)}",
                        f"[C] {fn}: {needle} -> {repl}",
                        src[:idx] + repl + src[idx + len(needle):]))
            start = idx + 1
    out.extend(match_mutants(src))
    out.extend(matches_macro_mutants(src))
    out.extend(let_else_mutants(src))
    for needle, repl in VALIDATOR_SITES:
        start = 0
        while True:
            idx = src.find(needle, start)
            if idx < 0:
                break
            fn = enclosing_fn(src, idx)
            out.append((f"{fn}/bypass/{norm(needle)}",
                        f"[B] {fn}: key validation bypassed",
                        src[:idx] + repl + src[idx + len(needle):]))
            start = idx + 1

    # Anti-rot. Operators C and B are literal-matched against the source, so a
    # reformat, a rename, or rustfmt splitting a call site across lines silently
    # yields zero mutants -- and the run would still print PASS. Round 3 filed
    # exactly that. These floors are the counts at the SHA the gate was written
    # against; if a legitimate refactor changes them, update the number and say
    # so in the commit, which is the point.
    for tag, floor in floors.items():
        got = sum(1 for _, desc, _ in out if desc.startswith(tag))
        if got < floor:
            raise SystemExit(
                f"operator {tag} enumerated {got} mutants, expected at least "
                f"{floor}. An anchor stopped matching -- the sweep is now blind "
                "to that operator, so the run is aborted rather than reported "
                "as a pass.")

    # Disambiguate identical identities. Two guards in one function can carry
    # the same condition text -- `begin_capture` tests
    # `*wire_state != WireState::Visible` on both its application and its
    # control branch. Left alone, one allowlist entry would excuse both, which
    # is the whole reason the allowlist is keyed on identity rather than on a
    # line number. The suffix is assigned in source order, so it is stable
    # unless the guards themselves are reordered.
    seen = {}
    deduped = []
    counts = {}
    for ident, desc, mutated in out:
        counts[ident] = counts.get(ident, 0) + 1
    for ident, desc, mutated in out:
        if counts[ident] > 1:
            seen[ident] = seen.get(ident, 0) + 1
            ident = f"{ident}@{seen[ident]}"
        deduped.append((ident, desc, mutated))
    idents = [i for i, _, _ in deduped]
    if len(set(idents)) != len(idents):
        raise SystemExit("identity disambiguation failed; ids are still not unique")
    return deduped


# ---------------------------------------------------------------------------
# The additive C4 suite
# ---------------------------------------------------------------------------
#
# `--suite c4` is separate from the legacy reqtab sweep on purpose: the default
# sweep's floors and allowlists are keyed to one source, and a C4 result must
# never be able to stand in for it. Both are reported independently.

CARGO_ABI = ("cargo", "+1.82.0", "test", "-p", "fsring-abi")
CARGO_CORE = ("cargo", "+1.85.0", "test", "--manifest-path", "driver/Cargo.toml",
              "-p", "fsring-core")
CARGO_USER = ("cargo", "+1.82.0", "test", "-p", "fsring-user")
LOCKED = ("--locked", "--offline")

POWERSHELL_SELFTEST = (
    "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "driver/scripts/smoke_driver.ps1", "-SelfTest",
)


def POWERSHELL_SCRIPT_SELFTEST(script):
    return (
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", "driver/scripts/%s" % script, "-SelfTest",
    )


def PYTHON_SELFTEST(script):
    """The audit script's own anti-rot kill signal.

    Neither auditor is reachable from a cargo test, so a weakened check inside
    one is invisible to every other gate: the matrix runs them against
    conformant artifacts, and conformant input can only expose a check that was
    inverted, never one that was deleted.
    """
    return ("python", f"driver/scripts/{script}", "--self-test")


NATIVE_MUTANT_PRODUCTION = (
    "python", "driver/scripts/audit_c4_native_mutant.py", "--root", ".",
)

# path -> (owning command, minimum mutation floor)
C4_TARGETS = {
    "fsring-abi/src/features.rs":
        (CARGO_ABI + ("--test", "control_v21") + LOCKED, 4),
    "fsring-abi/src/section_layout.rs":
        (CARGO_ABI + ("--test", "section_layout_v21") + LOCKED, 6),
    "driver/fsring-core/src/bootctx.rs":
        (CARGO_CORE + ("bootctx::tests",) + LOCKED, 4),
    # Raised 6 -> 12 at Task 9 of the C4 recovery: the nine
    # pre-Task-9 operators plus four for the one locked terminal claim,
    # less one for headroom so a single anchor that stops matching trips
    # `--list` rather than the floor.
    "driver/fsring-core/src/session.rs":
        (CARGO_CORE + ("session::tests",) + LOCKED, 16),
    "driver/fsring-core/src/grant.rs":
        (CARGO_CORE + ("grant::tests",) + LOCKED, 5),
    "driver/fsring-core/src/enter.rs":
        (CARGO_CORE + ("enter::tests",) + LOCKED, 8),
    # Raised 4 -> 6 at Task 11 of the C4 recovery: the reordered mount
    # roster and its two lock-overlap rules.
    "driver/fsring-core/src/volume.rs":
        (CARGO_CORE + ("volume::tests",) + LOCKED, 7),
    "driver/fsring-core/src/adapter/load.rs":
        (CARGO_CORE + ("adapter::load::tests",) + LOCKED, 4),
    # Raised 6 -> 22 at Task 7 of the C4 recovery: the ten pre-recovery
    # operators plus the thirteen locked-suffix, CLOSE-order, and shell/root/VDO
    # ownership operators, less one for headroom, so a single anchor that stops
    # matching still trips `--list` rather than the floor.
    "driver/fsring-core/src/adapter/setup.rs":
        (CARGO_CORE + ("adapter::setup::tests",) + LOCKED, 24),
    # Task 8 closure raises the lifecycle floor for the process-observation,
    # native-owner, ring-initialization, and saved-IRQL seams. Native-only
    # lifetime structure remains independently measured by Task 27's auditor.
    "driver/fsring-core/src/adapter/lifecycle.rs":
        (CARGO_CORE + ("adapter::lifecycle::tests",) + LOCKED, 21),
    "driver/fsring-core/src/adapter/enter.rs":
        (CARGO_CORE + ("adapter::enter::tests",) + LOCKED, 6),
    # 16 -> 39 at Tasks 22-24 of the C4 recovery: the prior checkpoint
    # operators plus the exhaustive dispatcher, consumer-recovery cursor,
    # and residual retry lifecycle plants, floor one below so a single
    # anchor that stops matching trips `--list` rather than the floor.
    "driver/fsring-core/src/adapter/fence.rs":
        (CARGO_CORE + ("adapter::fence::tests",) + LOCKED, 39),
    # Task 8 closure adds the production-consumed retained mount scope.
    "driver/fsring-core/src/adapter/volume.rs":
        (CARGO_CORE + ("adapter::volume::tests",) + LOCKED, 5),
    "driver/fsring-core/src/adapter/stackexpand.rs":
        (CARGO_CORE + ("adapter::stackexpand::tests",) + LOCKED, 2),
    "driver/fsring-fsd/src/driver.rs": (NATIVE_MUTANT_PRODUCTION, 1),
    "driver/fsring-fsd/src/fence.rs": (NATIVE_MUTANT_PRODUCTION, 6),
    "driver/fsring-fsd/src/lifecycle.rs": (NATIVE_MUTANT_PRODUCTION, 31),
    # 20 -> 22 with the two round-9 attach-scratch operators.
    "driver/fsring-fsd/src/session.rs": (NATIVE_MUTANT_PRODUCTION, 22),
    "driver/fsring-fsd/src/volume.rs": (NATIVE_MUTANT_PRODUCTION, 14),
    "fsring-user/src/native.rs":
        (CARGO_USER + ("--test", "native_session") + LOCKED, 6),
    "fsring-user/src/smoke.rs":
        (CARGO_USER + ("--test", "smoke_v2") + LOCKED, 4),
    "driver/scripts/smoke_driver.ps1": (POWERSHELL_SELFTEST, 8),
    # Round-9 high 5: this row's launch counts became a measurement, so the
    # script that takes the measurement is now itself graded.
    "driver/scripts/package_c4_candidate.ps1":
        (POWERSHELL_SCRIPT_SELFTEST("package_c4_candidate.ps1"), 2),
    "driver/scripts/audit_c4_imports.py":
        (PYTHON_SELFTEST("audit_c4_imports.py"), 16),
    # 42 -> 43 when the frame-source census split by disagreement shape: the
    # one `maxDisagreements` bound became a `declined` bound and a `truncated`
    # bound, and each needs its own mutant or the unnamed half stays green
    # whatever happens to it. Raised deliberately, which is what this file's
    # anti-rot rule asks for when a real refactor moves a count.
    "driver/scripts/audit_c4_stack.py":
        (PYTHON_SELFTEST("audit_c4_stack.py"), 43),
    # 47 -> 48 for the concurrent Task 12 probe wave. The wave introduced one
    # failure mode the previous 47 could not express -- verdicts that are
    # discarded rather than graded -- so it needs its own mutant or that half
    # stays green whatever happens to it. Raised deliberately, which is what
    # this file's anti-rot rule asks for when a real refactor moves a count.
    "driver/scripts/audit_c4_lifetime.py":
        (PYTHON_SELFTEST("audit_c4_lifetime.py"), 49),
    # 6 -> 7 for the baseline-guard on a manifest-consistency credit.
    # Raised deliberately, as this file's anti-rot rule requires when a
    # real change moves a count.
    "driver/scripts/audit_c4_native_mutant.py":
        (PYTHON_SELFTEST("audit_c4_native_mutant.py"), 7),
}

# The closed named operators. Each anchor is a literal UTF-8 source string that
# must match exactly once; a zero or multi match fails the suite rather than
# quietly skipping. `\n` below is a real LF and the following spaces are
# significant rustfmt output.
C4_NAMED_MUTANTS = [
    ("implementation-mask-omitted", "fsring-abi/src/features.rs",
     "let implemented = offered.intersection(input.implementation_protocol_mask);",
     "let implemented = offered;"),
    ("mount-id-reused", "driver/fsring-core/src/bootctx.rs",
     "let next = checked_next_mount_sequence(header.mount_sequence)"
     ".map_err(BootPlanError::Counter)?;",
     "let next = header.mount_sequence;"),
    ("credit-generation-reused", "driver/fsring-core/src/grant.rs",
     "let next_generation = observed_generation.checked_add(1);",
     "let next_generation = Some(observed_generation);"),
    ("claim-before-preflight", "driver/fsring-core/src/grant.rs",
     "GrantCommitStep::Preflight,\n        GrantCommitStep::Claim,\n"
     "        GrantCommitStep::AdvanceHead,\n        GrantCommitStep::Refresh,",
     "GrantCommitStep::Claim,\n        GrantCommitStep::Preflight,\n"
     "        GrantCommitStep::AdvanceHead,\n        GrantCommitStep::Refresh,"),
    ("cleanup-expansion-refusal-surrenders", "driver/fsring-core/src/adapter/stackexpand.rs",
     "CleanupExpansionRecourse::DelayAndRetry\n",
     "CleanupExpansionRecourse::Surrender\n"),
    ("cleanup-expansion-budget-never-exhausts", "driver/fsring-core/src/adapter/stackexpand.rs",
     "CleanupExpandFault::ShortOfMemory if self.attempts < self.limit => {",
     "CleanupExpandFault::ShortOfMemory if true => {"),
    ("cleanup-expansion-retries-a-permanent-refusal", "driver/fsring-core/src/adapter/stackexpand.rs",
     "(_, None) => Err(CleanupExpandFault::Refused),",
     "(_, None) => Err(CleanupExpandFault::ShortOfMemory),"),
    ("cleanup-expansion-reruns-a-contradicted-callout", "driver/fsring-core/src/adapter/stackexpand.rs",
     "(_, Some(_)) => Err(CleanupExpandFault::Contradicted),",
     "(_, Some(_)) => Err(CleanupExpandFault::ShortOfMemory),"),
    ("close-refuses-an-uninstalled-lease", "driver/fsring-core/src/adapter/setup.rs",
     "(Self::Lease, true) => Self::CloseRight,",
     "(Self::Lease, true) => Self::Lease,"),
    ("ring-scratch-aliased", "driver/fsring-core/src/adapter/setup.rs",
     "ScratchIdentity::drain(ring_index)", "ScratchIdentity::drain(0)"),
    ("publish-before-output-validation", "driver/fsring-core/src/adapter/setup.rs",
     "SetupEffect::ValidateOutput,\n        SetupEffect::InstallStaging,\n"
     "        SETUP_COMMIT[0],\n        SETUP_COMMIT[1],",
     "SetupEffect::InstallStaging,\n        SETUP_COMMIT[0],\n"
     "        SETUP_COMMIT[1],\n        SetupEffect::ValidateOutput,"),
    ("wait-before-enter-signal", "driver/fsring-core/src/session.rs",
     "FenceEffect::SignalPendingEnter,\n        FenceEffect::WaitControlRundown,",
     "FenceEffect::WaitControlRundown,\n        FenceEffect::SignalPendingEnter,"),
    ("drain-before-producer-revoke", "driver/fsring-core/src/session.rs",
     "FenceStage::RemoveProducerMappings,\n        FenceStage::AcquireConsumers,\n"
     "        FenceStage::DrainStablePrefixes,",
     "FenceStage::DrainStablePrefixes,\n        FenceStage::AcquireConsumers,\n"
     "        FenceStage::RemoveProducerMappings,"),
    ("views-freed-before-role-drain", "driver/fsring-core/src/session.rs",
     "FenceStage::ReleaseAndDrainOwners,\n        FenceStage::ReleaseViewsDevicesAndBacking,",
     "FenceStage::ReleaseViewsDevicesAndBacking,\n        FenceStage::ReleaseAndDrainOwners,"),
    ("executable-mapping-accepted", "fsring-user/src/native.rs",
     "if protection & PAGE_EXECUTE_MASK != 0 {", "if false {"),
    ("worker-continuity-drift-accepted", "driver/scripts/smoke_driver.ps1",
     "if (-not $c4Continuity.Valid) {", "if ($false) {"),
    ("dos-remove-before-containment", "driver/scripts/smoke_driver.ps1",
     "@('contain-worker', 'remove-dos-link', 'stop-service', 'delete-service', 'post-unload')",
     "@('remove-dos-link', 'contain-worker', 'stop-service', 'delete-service', 'post-unload')"),
    ("dos-remove-not-exact", "driver/scripts/smoke_driver.ps1",
     "$script:DDD_REMOVE_DEFINITION -bor $script:DDD_EXACT_MATCH_ON_REMOVE "
     "-bor $script:DDD_RAW_TARGET_PATH -bor $script:DDD_NO_BROADCAST_SYSTEM",
     "$script:DDD_REMOVE_DEFINITION -bor $script:DDD_RAW_TARGET_PATH "
     "-bor $script:DDD_NO_BROADCAST_SYSTEM"),
    ("scm-cleanup-failure-ignored", "driver/scripts/smoke_driver.ps1",
     "if (-not $scmCleanup.Success) {", "if ($false) {"),
    ("aggregate-pass-with-reason", "driver/scripts/smoke_driver.ps1",
     "if ($passedProbeCount -eq 27 -and $reasonCount -eq 0) {",
     "if ($passedProbeCount -eq 27 -or $reasonCount -eq 0) {"),
    ("post-staged-not-run-accepted", "driver/scripts/smoke_driver.ps1",
     "if ($rootIdentity -ne $null -and $notRunCount -ne 0) {", "if ($false) {"),
    ("unload-fragment-omitted", "driver/scripts/smoke_driver.ps1",
     "$script:C4UnloadMergeKeys = @('serviceStopped', 'providerOpenNtstatus', "
     "'fscontrolOpenNtstatus', 'vdoOpenNtstatus', 'dosLinkQueryWin32Code', "
     "'formerAliasRangesFree', 'ownedHandlesClosed')",
     "$script:C4UnloadMergeKeys = @('serviceStopped', 'providerOpenNtstatus', "
     "'fscontrolOpenNtstatus', 'vdoOpenNtstatus', 'dosLinkQueryWin32Code', "
     "'formerAliasRangesFree')"),
    ("worker-reason-limit-raised", "driver/scripts/smoke_driver.ps1",
     "$script:C4WorkerReasonLimit = 26", "$script:C4WorkerReasonLimit = 35"),
    # The plan listed this operator; the suite shipped without it, so the
    # post-clear recheck - the race the clear-then-recheck sequence exists for -
    # was the one ENTER rule with no mutation behind it.
    ("post-clear-recheck-omitted", "driver/fsring-core/src/enter.rs",
     "let changed = current_generation != snapshot.generation;",
     "let changed = false;"),
    # The frame BELOW `begin_pass`. `begin_native_worker_pass` refusing on
    # anything its caller's admission does not test is a pass that can be
    # queued and can never begin -- the round-11 livelock, moved one crate
    # away from every rule that guards it. This refusal FIRES in the states
    # the tests construct, which is the whole point: the first version of this
    # plant duplicated an invariant those states already satisfy, so it was
    # inert and survived, and an inert plant measures nothing.
    ("worker-pass-refuses-the-queued-schedule-it-was-given",
     "driver/fsring-core/src/enter.rs",
     "    let decision = wake.take_for_worker(install)?;",
     "    if schedule.state == WorkerScheduleState::Queued {\n"
     "        return Err(PendingError::WrongRingState);\n"
     "    }\n"
     "    let decision = wake.take_for_worker(install)?;"),
    # `take_control_link` must actually hand back the right it is holding, or
    # native has nothing to give the session's `PendingControlLedger` at the
    # `UnlinkControlPending` stage -- the round-7 blocker this operator names:
    # a ring served exactly one parked ENTER-WAIT per session because the
    # right was silently dropped instead of reaching the ledger.
    ("unlink-control-pending-drops-the-right-instead-of-taking-it",
     "driver/fsring-core/src/enter.rs",
     "self.control_link.take()",
     "None"),
    # A failure reported *for* the Release store must still unwind: `>=` here
    # answers a never-published session with a publication proof.
    ("setup-commit-boundary-inclusive", "driver/fsring-core/src/adapter/setup.rs",
     "if plan.next > INDEX_PUBLISH_LOCKED_SUFFIX {",
     "if plan.next >= INDEX_PUBLISH_LOCKED_SUFFIX {"),
    # 0xffffffff is the indefinite wait and may never be answered TIMED_OUT.
    ("wait-sentinel-may-time-out", "driver/fsring-core/src/adapter/enter.rs",
     "if cq_budget != 0 || timeout_ms == 0 || timeout_ms == u32::MAX {",
     "if cq_budget != 0 || timeout_ms == 0 {"),
    # All four revalidation facts must hold immediately before VPB_MOUNTED.
    ("mount-revalidation-partial", "driver/fsring-core/src/volume.rs",
     "revalidation.target_identity_matches\n                    && revalidation.admission_open\n"
     "                    && revalidation.binding_unchanged\n"
     "                    && revalidation.session_active",
     "revalidation.target_identity_matches"),
    ("profile-base-security-not-forced", "fsring-abi/src/features.rs",
     "    let required_with_base = union(input.required_features, BASE_REQUIRED_PROTOCOL_MASK);\n",
     "    let required_with_base = input.required_features;\n"),
    ("mapped-io-kept-without-mdl-guarantees", "fsring-abi/src/features.rs",
     "        runtime_protocol = without_bit(runtime_protocol, protocol_feature::MAPPED_IO);\n",
     "        runtime_protocol = union(runtime_protocol, FeatureSet { words: [0, 0] });\n"),
    ("restart-pair-matched-by-either", "fsring-abi/src/features.rs",
     "    set.contains(protocol_feature::HOT_RESTART) == set.contains(protocol_feature::EXACTLY_ONCE)\n",
     "    set.contains(protocol_feature::HOT_RESTART) || set.contains(protocol_feature::EXACTLY_ONCE)\n"),
    ("hot-restart-kept-without-service-sid", "fsring-abi/src/features.rs",
     "        runtime_protocol = without_bit(runtime_protocol, protocol_feature::HOT_RESTART);\n",
     "        runtime_protocol = union(runtime_protocol, FeatureSet { words: [0, 0] });\n"),
    ("align-up-rounds-down", "fsring-abi/src/section_layout.rs",
     "    Some(with_mask & !mask)\n",
     "    Some(value & !mask)\n"),
    ("view-span-not-view-aligned", "fsring-abi/src/section_layout.rs",
     "    let span = checked_align_up(length, USER_VIEW_OFFSET_ALIGNMENT)\n",
     "    let span = Some(length)\n"),
    ("page-size-power-of-two-unchecked", "fsring-abi/src/section_layout.rs",
     "        if page_size == 0 || !page_size.is_power_of_two() {\n",
     "        if page_size == 0 {\n"),
    ("advance-uses-length-not-span", "fsring-abi/src/section_layout.rs",
     "    let span = match region_span(region) {\n",
     "    let span = match Some(region.length) {\n"),
    ("output-must-be-zero-dropped", "fsring-abi/src/section_layout.rs",
     "        if output.iter().any(|byte| *byte != 0) {\n",
     "        if output.iter().all(|byte| *byte != 0) {\n"),
    ("construct-buffer-bound-halved", "fsring-abi/src/section_layout.rs",
     "        if output.len() < needed {\n",
     "        if output.len() < needed / 2 {\n"),
    ("header-identity-ignores-section-size", "fsring-abi/src/section_layout.rs",
     "        && actual.section_size == expected.section_size\n",
     ""),
    ("header-regions-ignore-notify-names", "fsring-abi/src/section_layout.rs",
     "        && actual.notify_names == expected.notify_names\n",
     ""),
    ("ring-index-bound-off-by-one", "fsring-abi/src/section_layout.rs",
     "        if index >= self.ring_count {\n",
     "        if index > self.ring_count {\n"),
    ("open-not-found-is-not-create", "driver/fsring-core/src/adapter/load.rs",
     "    } else if status == STATUS_OBJECT_NAME_NOT_FOUND {\n",
     "    } else if status != STATUS_SUCCESS {\n"),
    ("create-collision-is-not-reopen", "driver/fsring-core/src/adapter/load.rs",
     "    } else if status == STATUS_OBJECT_NAME_COLLISION {\n",
     "    } else if status == STATUS_SUCCESS {\n"),
    ("reopen-accepts-any-status", "driver/fsring-core/src/adapter/load.rs",
     "pub const fn decide_reopen(status: i32) -> ReopenDecision {\n"
     "    if status == STATUS_SUCCESS {\n",
     "pub const fn decide_reopen(status: i32) -> ReopenDecision {\n"
     "    if status != i32::MIN {\n"),
    ("absolute-descriptor-accepted", "driver/fsring-core/src/adapter/load.rs",
     "    if control & SE_SELF_RELATIVE == 0 {\n",
     "    if control & SE_SELF_RELATIVE == 1 {\n"),
    ("sd-revision-unchecked", "driver/fsring-core/src/adapter/load.rs",
     "    if bytes.first().copied()? != SD_REVISION {\n",
     "    bytes.first().copied()?;\n"
     "    if false {\n"),
    ("acl-may-leave-the-image", "driver/fsring-core/src/adapter/load.rs",
     "        if end > bytes.len() {\n",
     "        if end > bytes.len().saturating_mul(2) {\n"),
    ("mount-accepts-a-verify-observation",
     "driver/fsring-core/src/adapter/volume.rs",
     "                    VolumeEffectOutcome::VerifyObserved(_) => {\n"
     "                        return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));\n"
     "                    }\n",
     "                    VolumeEffectOutcome::VerifyObserved(_) => MountEffectOutcome::Done,\n"),
    ("verify-decision-ignores-identity", "driver/fsring-core/src/adapter/volume.rs",
     "                let decision = decide_verify(observation.state, observation.identity_matches);\n",
     "                let decision = decide_verify(observation.state, true);\n"),
    ("clear-accepts-a-revalidated-mount",
     "driver/fsring-core/src/adapter/volume.rs",
     "                VolumeEffect::Mount(MountEffect::ClearDeviceInitializing),\n"
     "            ) => {\n"
     "                if !matches!(outcome, VolumeEffectOutcome::Done) {\n"
     "                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));\n"
     "                }\n",
     "                VolumeEffect::Mount(MountEffect::ClearDeviceInitializing),\n"
     "            ) => {\n"),
    ("mount-evidence-accepts-any-outcome",
     "driver/fsring-core/src/adapter/volume.rs",
     "            (NativeVolumeState::EmitMount(published), VolumeEffect::EmitMountPublished) => {\n"
     "                if !matches!(outcome, VolumeEffectOutcome::Done) {\n"
     "                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));\n"
     "                }\n",
     "            (NativeVolumeState::EmitMount(published), VolumeEffect::EmitMountPublished) => {\n"),
    ("dismount-step-accepts-any-outcome",
     "driver/fsring-core/src/adapter/volume.rs",
     "            (NativeVolumeState::Dismount { plan, next }, VolumeEffect::Dismount(_)) => {\n"
     "                if !matches!(outcome, VolumeEffectOutcome::Done) {\n"
     "                    return Err(VolumeEffectFailure::Invalid(AdapterPlanError::InvalidInput));\n"
     "                }\n",
     "            (NativeVolumeState::Dismount { plan, next }, VolumeEffect::Dismount(_)) => {\n"),
    ("slot-array-length-not-exact", "driver/fsring-core/src/bootctx.rs",
     "    if slots.len() != BOOT_CONTEXT_SLOT_COUNT as usize {\n",
     "    if slots.len() > BOOT_CONTEXT_SLOT_COUNT as usize {\n"),
    ("occupied-slot-not-noticed", "driver/fsring-core/src/bootctx.rs",
     "        if validated.state != boot_context_slot_state::FREE {\n",
     "        if validated.state == boot_context_slot_state::FREE {\n"),
    ("duplicate-mount-sequence-allowed", "driver/fsring-core/src/bootctx.rs",
     "                    && other.mount_sequence == slot.mount_sequence\n",
     "                    && other.mount_sequence != slot.mount_sequence\n"),
    ("active-permanent-slot-not-refused", "driver/fsring-core/src/bootctx.rs",
     "    if has_active_permanent_slot {\n",
     "    if false {\n"),
    ("verify-identity-precedence-lost", "driver/fsring-core/src/volume.rs",
     "    if !identity_matches {\n",
     "    if false {\n"),
    ("staging-and-active-verify-successfully", "driver/fsring-core/src/volume.rs",
     "        VolumeState::Staging | VolumeState::Active => VerifyDecision::InvalidTarget,\n",
     "        VolumeState::Staging | VolumeState::Active => VerifyDecision::Success,\n"),
    ("provider-control-not-failed-closed", "driver/fsring-core/src/volume.rs",
     "    if matches!(kind, DeviceKind::ProviderControl) {\n",
     "    if false {\n"),
    ("create-ignores-root-open", "driver/fsring-core/src/volume.rs",
     "        return if root_open {\n",
     "        return if true {\n"),
    ("backing-need-not-be-free", "driver/fsring-core/src/grant.rs",
     "        if entries.len() != layout.required\n"
     "            || entries.iter().any(|entry| *entry != GrantEntry::FREE)\n"
     "        {\n",
     "        if entries.len() != layout.required\n"
     "        {\n"),
    ("credit-output-bound-halved", "driver/fsring-core/src/grant.rs",
     "        if output.len() < count {\n",
     "        if output.len() < count / 2 {\n"),
    ("publish-into-a-closed-registry", "driver/fsring-core/src/session.rs",
     "        } else if !registry.admission_open {\n",
     "        } else if false {\n"),
    ("binding-need-not-be-staging", "driver/fsring-core/src/session.rs",
     "        ControlBindingState::Staging(setup_epoch) if setup_epoch == reservation.setup_epoch => {\n",
     "        ControlBindingState::Staging(setup_epoch) if setup_epoch != reservation.setup_epoch => {\n"),
    # The same identity check appears twice: once on the publication path and
    # once on the rollback copy. Continuing the anchor through the
    # publication-only `admission_open` arm is what keeps this exact-one; the
    # bare `if` block matched both.
    #
    # It drops the transaction/authority binding, which is the only comparison
    # in this block that decides anything. The block used to carry two more
    # clauses — the control identity against the transaction, and the two
    # authorities against each other — and both were already implied: equal
    # authorities carry equal identities, and `publish_preflight` compares the
    # pair itself. Deleting either changed no outcome, which a mutation operator
    # cannot tell apart from a check that was never load-bearing, so they were
    # removed and this operator retargeted onto the clause that survives alone.
    ("publication-identity-not-cross-checked",
     "driver/fsring-core/src/session.rs",
     "            if installed.registry.authority.identity != transaction.staging.identity {\n"
     "                Some(SessionError::IdentityMismatch)\n"
     "            } else if !registry.admission_open {\n",
     "            if false {\n"
     "                Some(SessionError::IdentityMismatch)\n"
     "            } else if !registry.admission_open {\n"),
    ("rollback-identity-not-cross-checked",
     "driver/fsring-core/src/session.rs",
     "                if installed.registry.authority.identity != transaction.staging.identity {\n"
     "                    Err(SessionError::IdentityMismatch)\n",
     "                if false {\n"
     "                    Err(SessionError::IdentityMismatch)\n"),
    ("setup-entry-ignores-prior-completion", "driver/fsring-core/src/adapter/setup.rs",
     "        if !prior_setup_complete {\n",
     "        if false && !prior_setup_complete {\n"),
    ("unknown-enter-flags-accepted", "driver/fsring-core/src/enter.rs",
     "        if request.flags & !enter_request_flags::KNOWN_MASK != 0 || (drains && waits) {\n",
     "        if drains && waits {\n"),
    ("drain-and-wait-requested-together", "driver/fsring-core/src/enter.rs",
     "        if request.flags & !enter_request_flags::KNOWN_MASK != 0 || (drains && waits) {\n",
     "        if request.flags & !enter_request_flags::KNOWN_MASK != 0 {\n"),
    ("enter-ring-index-not-this-ring", "driver/fsring-core/src/enter.rs",
     "            || request.ring_index != self.ring_index\n",
     "            || false\n"),
    ("enter-session-epoch-unchecked", "driver/fsring-core/src/enter.rs",
     "            || request.session_epoch != identity.session_epoch\n",
     "            || false\n"),
    ("drain-budget-bounds-dropped", "driver/fsring-core/src/enter.rs",
     "        if (drains && (request.cq_budget == 0 || request.cq_budget > maximum_budget))\n",
     "        if (drains && false)\n"),
    ("timeout-on-a-non-waiting-role", "driver/fsring-core/src/enter.rs",
     "        if !waits && request.timeout_ms != 0 {\n",
     "        if false {\n"),
    ("fenced-session-still-enters", "driver/fsring-core/src/enter.rs",
     "        if observation.fenced {\n",
     "        if false {\n"),
    ("poll-is-treated-as-a-wait", "driver/fsring-core/src/enter.rs",
     "        } else if drains || request.timeout_ms == 0 {\n",
     "        } else if drains {\n"),
    ("infinite-wait-encoding-inverted", "driver/fsring-core/src/enter.rs",
     "        } else if request.timeout_ms == u32::MAX {\n",
     "        } else if request.timeout_ms == 0 {\n"),
    ("table-identity-exhaustion-ignored", "driver/fsring-core/src/grant.rs",
     "        if current == u64::MAX {\n",
     "        if false {\n"),
    ("zero-session-epoch-accepted", "driver/fsring-core/src/grant.rs",
     "    if session_epoch == 0 {\n",
     "    if false {\n"),
    ("drain-budget-and-timeout-unchecked", "driver/fsring-core/src/adapter/enter.rs",
     "                if cq_budget == 0 || cq_budget > fsring_abi::MAX_ENTER_CQ_BUDGET || timeout_ms != 0\n",
     "                if false\n"),
    ("poll-may-carry-a-budget-or-timeout", "driver/fsring-core/src/adapter/enter.rs",
     "                if cq_budget != 0 || timeout_ms != 0 {\n",
     "                if false {\n"),
    ("finite-wait-accepts-the-sentinels", "driver/fsring-core/src/adapter/enter.rs",
     "                if cq_budget != 0 || timeout_ms == 0 || timeout_ms == u32::MAX {\n",
     "                if cq_budget != 0 {\n"),
    ("infinite-wait-accepts-any-timeout", "driver/fsring-core/src/adapter/enter.rs",
     "                if cq_budget != 0 || timeout_ms != u32::MAX {\n",
     "                if cq_budget != 0 {\n"),
    ("enter-output-capacity-unchecked", "driver/fsring-core/src/adapter/enter.rs",
     "        if output_capacity < information_for(0)? {\n",
     "        if output_capacity < information_for(0)?.saturating_sub(information_for(0)?) {\n"),
    ("layout-not-recomputed", "driver/fsring-core/src/adapter/setup.rs",
     "        if recomputed != layout {\n",
     "        if false {\n"),
    ("setup-output-capacity-unchecked", "driver/fsring-core/src/adapter/setup.rs",
     "        if output_capacity < required_size {\n",
     "        if output_capacity < required_size / 2 {\n"),
    ("views-effect-takes-a-plain-completion", "driver/fsring-core/src/adapter/setup.rs",
     "        if matches!(self.effect, SetupEffect::BuildProtectedViews) {\n",
     "        if false {\n"),
    ("receipt-accepted-outside-its-effect", "driver/fsring-core/src/adapter/setup.rs",
     "        if !matches!(self.effect, SetupEffect::BuildProtectedViews) {\n",
     "        if false {\n"),
    ("nonce-length-unchecked", "fsring-user/src/smoke.rs",
     "        if bytes.len() != 32 {\n",
     "        if bytes.len() > 32 {\n"),
    ("reason-length-bound-dropped", "fsring-user/src/smoke.rs",
     "        if text.is_empty() || text.len() > REASON_MAX_BYTES {\n",
     "        if text.is_empty() {\n"),
    ("reason-control-bytes-allowed", "fsring-user/src/smoke.rs",
     "        if text.bytes().any(|byte| byte == 0 || byte < 0x20) {\n",
     "        if false {\n"),
    ("worker-may-claim-the-runner-prefix", "fsring-user/src/smoke.rs",
     "        if !allow_infrastructure && text.starts_with(INFRASTRUCTURE_PREFIX) {\n",
     "        if false {\n"),
    ("mapping-gap-allowed", "fsring-user/src/native.rs",
     "            if region.base_address > cursor {\n",
     "            if false {\n"),
    ("uncommitted-region-accepted", "fsring-user/src/native.rs",
     "            if region.state != MEM_COMMIT {\n",
     "            if false {\n"),
    ("private-mapping-accepted", "fsring-user/src/native.rs",
     "            if region.mapping_type != MEM_MAPPED {\n",
     "            if false {\n"),
    ("executable-view-accepted", "fsring-user/src/native.rs",
     "            if protection & PAGE_EXECUTE_MASK != 0 {\n",
     "            if false {\n"),
    ("forbidden-protection-modifiers-accepted", "fsring-user/src/native.rs",
     "            if protection & PAGE_FORBIDDEN_MODIFIERS != 0 {\n",
     "            if false {\n"),
    ("short-write-accepted", "fsring-user/src/native.rs",
     "        if written != required {\n",
     "        if written > required {\n"),
    ("receipt-layout-not-cross-checked", "driver/fsring-core/src/adapter/setup.rs",
     "                    || *receipt.layout() != plan.layout\n",
     "                    || false\n"),
    ("receipt-identity-not-checked", "driver/fsring-core/src/adapter/setup.rs",
     "        if self.plan.identity != Some(receipt.identity()) {\n",
     "        if false {\n"),
    # Task 7's locked publication suffix, its CLOSE deallocation order, and the
    # shell/root/VDO ownership model. Four of these weaken a *proof* rather than
    # the sequence it judges: the suffix and close rosters have exactly one
    # production order, so a proof evaluated only against that order cannot be
    # seen failing, and a hard-coded `true` would grade identically to one that
    # reads the walk. The `begin_with_roster` test seams exist so these mutants
    # have somewhere to be caught.
    ("suffix-core-live-before-mount-active",
     "driver/fsring-core/src/adapter/setup.rs",
     "        LockedSetupSuffixEffect::ActivateNativeMountRendezvous,\n"
     "        LockedSetupSuffixEffect::InstallPendingRuntime,\n"
     "        LockedSetupSuffixEffect::CommitCoreRingSetupPublication,\n",
     "        LockedSetupSuffixEffect::CommitCoreRingSetupPublication,\n"
     "        LockedSetupSuffixEffect::InstallPendingRuntime,\n"
     "        LockedSetupSuffixEffect::ActivateNativeMountRendezvous,\n"),
    ("suffix-mount-activation-unrecorded",
     "driver/fsring-core/src/adapter/setup.rs",
     "            LockedSetupSuffixEffect::ActivateNativeMountRendezvous => {\n"
     "                self.record.mount_activated = Some(at);\n"
     "            }\n",
     "            LockedSetupSuffixEffect::ActivateNativeMountRendezvous => {}\n"),
    ("suffix-mount-order-proof-vacuous",
     "driver/fsring-core/src/adapter/setup.rs",
     "            (Some(mount), Some(live)) => mount < live,\n",
     "            (Some(_mount), Some(_live)) => true,\n"),
    ("suffix-vdo-order-proof-vacuous",
     "driver/fsring-core/src/adapter/setup.rs",
     "            (Some(released), Some(cleared)) => cleared < released,\n",
     "            (Some(_released), Some(_cleared)) => true,\n"),
    ("suffix-vdo-flag-cleared-before-locator",
     "driver/fsring-core/src/adapter/setup.rs",
     "        LockedSetupSuffixEffect::WriteVdoLocator,\n"
     "        LockedSetupSuffixEffect::ClearVdoInitializing,\n",
     "        LockedSetupSuffixEffect::ClearVdoInitializing,\n"
     "        LockedSetupSuffixEffect::WriteVdoLocator,\n"),
    ("suffix-locator-order-proof-vacuous",
     "driver/fsring-core/src/adapter/setup.rs",
     "            (Some(written), Some(cleared)) => written < cleared,\n",
     "            (Some(_written), Some(_cleared)) => true,\n"),
    ("close-admission-released-before-free",
     "driver/fsring-core/src/adapter/setup.rs",
     "        ControlContextCloseEffect::DetachFsContext,\n"
     "        ControlContextCloseEffect::DestroyAndFreeContext,\n"
     "        ControlContextCloseEffect::ReleaseControlContextAdmission,\n"
     "    ];\n",
     "        ControlContextCloseEffect::ReleaseControlContextAdmission,\n"
     "        ControlContextCloseEffect::DetachFsContext,\n"
     "        ControlContextCloseEffect::DestroyAndFreeContext,\n"
     "    ];\n"),
    # The predecessor implementation: a position compared against a constant,
    # which reports a free the roster never ran once the index passes 1.
    ("close-free-observation-positional",
     "driver/fsring-core/src/adapter/setup.rs",
     "        self.roster\n"
     "            .iter()\n"
     "            .take(usize::from(self.next))\n"
     "            .any(|effect| matches!(effect, "
     "ControlContextCloseEffect::DestroyAndFreeContext))\n",
     "        self.next > 1\n"),
    ("close-free-before-release-proof-vacuous",
     "driver/fsring-core/src/adapter/setup.rs",
     "            (Some(freed), Some(released)) => freed < released,\n",
     "            (Some(_freed), Some(_released)) => true,\n"),
    ("shell-owner-fabricated", "driver/fsring-core/src/adapter/setup.rs",
     "            ShellOwnerState::Absent => return Err(OwnershipFault::Fabricated),\n",
     "            ShellOwnerState::Absent => ShellOwnerId::new(0),\n"),
    ("shell-destroyed-without-allocation",
     "driver/fsring-core/src/adapter/setup.rs",
     "            ShellOwnerState::Absent => Err(OwnershipFault::Fabricated),\n",
     "            ShellOwnerState::Absent => Ok(()),\n"),
    ("shell-freed-while-cell-owned",
     "driver/fsring-core/src/adapter/setup.rs",
     "            ShellOwnerState::CellOwned { .. } | ShellOwnerState::Destroyed(_) => {\n"
     "                Err(OwnershipFault::NotRepeatable)\n"
     "            }\n",
     "            ShellOwnerState::CellOwned { .. } | ShellOwnerState::Destroyed(_) => Ok(()),\n"),
    ("root-released-without-acquisition",
     "driver/fsring-core/src/adapter/setup.rs",
     "            RootRightState::Absent => Err(OwnershipFault::Fabricated),\n",
     "            RootRightState::Absent => Ok(()),\n"),
    ("root-released-while-cell-owned",
     "driver/fsring-core/src/adapter/setup.rs",
     "            RootRightState::CellOwned(_) | RootRightState::Released(_) => {\n"
     "                Err(OwnershipFault::NotRepeatable)\n"
     "            }\n",
     "            RootRightState::CellOwned(_) | RootRightState::Released(_) => Ok(()),\n"),
    ("vdo-written-after-initializing-clear",
     "driver/fsring-core/src/adapter/setup.rs",
     "        if !vdo.device_initializing || !vdo.locator_uninitialized {\n",
     "        if !vdo.locator_uninitialized {\n"),
    # Task 8's ordered access resolution. Three of these weaken a proof rather
    # than the walk it judges, for the same reason as the suffix operators
    # above: production drives exactly one roster, so a proof that stopped
    # reading the walk would agree with it on every real input.
    ("resolve-projects-before-rundown",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        ResolveStep::BoundsCheckLocator,\n"
     "        ResolveStep::AcquireAccessRundown,\n"
     "        ResolveStep::AcquireRegistryLock,\n",
     "        ResolveStep::BoundsCheckLocator,\n"
     "        ResolveStep::AcquireRegistryLock,\n"
     "        ResolveStep::AcquireAccessRundown,\n"),
    ("resolve-projection-unrecorded",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "            ResolveStep::ProjectSessionPointer => self.record.projected = Some(at),\n",
     "            ResolveStep::ProjectSessionPointer => {}\n"),
    # The fourth mandated Task 9 name. It cannot live in core: core's
    # `run_process_callback_scan` refuses with `let guard = guard?;` before any
    # `observe`, and with no guard there is no way to reach a cell, so no core
    # edit can express "refused entry touches a cell". In fsd the ordering is
    # real - `fsring_process_loss` resolves the registry and then hands it to
    # the runner, which acquires admission first - so the defect is a cell touch
    # placed BEFORE admission is decided. Graded by NATIVE_MUTANT_PRODUCTION
    # (audit_c4_lifetime --production-check), which pins this exact body:
    # TASK6_UNLOAD_BODY_GRAMMAR's `fsring_process_loss` row, detail
    # "Task 6 one-guard process callback runner".
    ("process-callback-refused-entry-touches-cell",
     "driver/fsring-fsd/src/driver.rs",
     "    unsafe { plan::run_r3_process_callback("
     "NativeR3ProcessCallbackOps { registry, process }) };\n",
     "    let mut lock = unsafe { crate::lifecycle::KernelSessionRegistry::lock(registry) };\n"
     "    let _touched = unsafe { lock.cell_ptr(0) };\n"
     "    unsafe { lock.release() };\n"
     "    unsafe { plan::run_r3_process_callback("
     "NativeR3ProcessCallbackOps { registry, process }) };\n"),
    # Task 12 closure, Task 9: the three process-scan restart rules the plan
    # names. `decide_scan_continuation` states that a matching observation
    # restarts, so a Completed or Blocked first match that advances the cursor
    # instead would walk straight past a second matching cell. Both are graded
    # by adapter::lifecycle::tests, which owns this file.
    #
    # The covering row for BOTH is the decision-table half of
    # `process_loss_open_waits_then_restarts_generation_scan`, which asserts
    # each arm of `decide_scan_continuation` directly. It is deliberately not
    # `process_loss_restarts_after_*_and_finds_second_matching_cell`: those
    # drive `run_process_callback_scan`, whose loop resets the cursor itself
    # and never consults `decide_scan_continuation`, so they cannot observe a
    # mutation in it. Asserting only the Completed arm let the Blocked mutant
    # survive once; keep an assertion per arm, not per combined arm.
    ("process-loss-completed-stops-before-later-cell",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        ScanAction::Claim\n"
     "        | ScanAction::Join\n"
     "        | ScanAction::ObserveCompleted(_)\n"
     "        | ScanAction::ObserveBlocked(_) => ScanContinuation::RestartScan,\n",
     "        ScanAction::Claim\n"
     "        | ScanAction::Join\n"
     "        | ScanAction::ObserveBlocked(_) => ScanContinuation::RestartScan,\n"
     "        ScanAction::ObserveCompleted(_) => ScanContinuation::NextCell,\n"),
    ("process-loss-blocked-stops-before-later-cell",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        ScanAction::Claim\n"
     "        | ScanAction::Join\n"
     "        | ScanAction::ObserveCompleted(_)\n"
     "        | ScanAction::ObserveBlocked(_) => ScanContinuation::RestartScan,\n",
     "        ScanAction::Claim\n"
     "        | ScanAction::Join\n"
     "        | ScanAction::ObserveCompleted(_) => ScanContinuation::RestartScan,\n"
     "        ScanAction::ObserveBlocked(_) => ScanContinuation::NextCell,\n"),
    # One guard must span every restart. Returning it at the first match
    # releases the process-callback admission mid-scan, which is exactly what
    # `one_guard_spanned_every_touch` and the restart count are there to see.
    ("process-callback-releases-guard-before-restart",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "                handle(&guard, action);\n"
     "                cursor = 0;\n",
     "                handle(&guard, action);\n"
     "                return Some(guard);\n"),
    ("resolve-refusal-keeps-the-rundown",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        if self.record.rundown_acquired.is_some() && self.record.rundown_released.is_none() {\n"
     "            self.record.rundown_released = Some(at);\n",
     "        if false {\n"
     "            self.record.rundown_released = Some(at);\n"),
    # Not a counter mutation: a refusal ends the walk, so the release runs at
    # most once and `saturating_add(1)` versus `= 1` is an equivalent mutant.
    # What decides is the acquisition guard — dropping it makes the two
    # refusals that run before the rundown exists release one anyway.
    ("resolve-refusal-releases-an-unacquired-rundown",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        if self.record.rundown_acquired.is_some() && self.record.rundown_released.is_none() {\n",
     "        if self.record.rundown_released.is_none() {\n"),
    ("resolve-order-proof-vacuous",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        match (self.record.rundown_acquired, self.record.projected) {\n"
     "            (Some(rundown), Some(projected)) => rundown < projected,\n",
     "        match (self.record.rundown_acquired, self.record.projected) {\n"
     "            (Some(_rundown), Some(_projected)) => true,\n"),
    ("resolve-validation-proof-vacuous",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "                core < projected && cell < projected && owners < projected\n",
     "                core < projected && cell < projected\n"),
    ("scan-claims-a-staging-cell",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "            NativeCellPhase::Free | NativeCellPhase::Staging | NativeCellPhase::Retired => {\n"
     "                ScanAction::Skip\n"
     "            }\n",
     "            NativeCellPhase::Free | NativeCellPhase::Staging | NativeCellPhase::Retired => {\n"
     "                ScanAction::Claim\n"
     "            }\n"),
    ("process-cell-observation-accepts-the-wrong-process",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    if observed.recorded_process.as_ref() != Some(&requested_process) {\n"
     "        return None;\n"
     "    }\n",
     "    if observed.recorded_process.as_ref() == Some(&requested_process) {\n"
     "        return None;\n"
     "    }\n"),
    ("native-owner-missing-root-is-accepted",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    observed.shell_locator == Some(requested)\n"
     "        && observed.root_locator == Some(requested)\n"
     "        && observed.shell_matches_mirror\n",
     "    observed.shell_locator == Some(requested)\n"
     "        && observed.root_locator.is_none()\n"
     "        && observed.shell_matches_mirror\n"),
    ("ring-lock-initialization-walk-is-skipped",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    for index in 0..ring_count {\n"
     "        initialize(index);\n"
     "    }\n",
     "    for index in 0..0 {\n"
     "        initialize(index);\n"
     "    }\n"),
    ("ring-release-discards-the-saved-irql",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    SavedIrql {\n"
     "        value: Some(acquire()),\n"
     "    }\n",
     "    let _ = acquire();\n"
     "    SavedIrql { value: None }\n"),
    ("mount-access-guard-drops-before-the-suffix",
     "driver/fsring-core/src/adapter/volume.rs",
     "    pub fn run(self, operation: impl FnOnce(&G)) {\n"
     "        operation(&self.guard);\n"
     "    }\n",
     "    pub fn run(self, _operation: impl FnOnce(&G)) {\n"
     "        drop(self);\n"
     "    }\n"),
    ("validate-live-accepts-a-removing-slot",
     "driver/fsring-core/src/session.rs",
     "        if slot.state != RegistrySlotState::Live\n"
     "            || slot.generation != locator.generation\n"
     "            || slot.identity != Some(locator.identity)\n"
     "        {\n"
     "            return Err(SessionError::ReferenceNotFound);\n"
     "        }\n"
     "        Ok(())\n",
     "        if slot.generation != locator.generation\n"
     "            || slot.identity != Some(locator.identity)\n"
     "        {\n"
     "            return Err(SessionError::ReferenceNotFound);\n"
     "        }\n"
     "        Ok(())\n"),
    ("validate-live-ignores-closed-admission",
     "driver/fsring-core/src/session.rs",
     "    pub fn validate_live(&self, locator: SessionLocator) -> Result<(), SessionError> {\n"
     "        if !self.admission_open {\n",
     "    pub fn validate_live(&self, locator: SessionLocator) -> Result<(), SessionError> {\n"
     "        if false {\n"),
    ("native-resolver-projects-before-rundown",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        let slot_index = locator.slot_index();\n"
     "        let mut rundown: Option<*mut EX_RUNDOWN_REF> = None;",
     "        let slot_index = locator.slot_index();\n"
     "        let _early_session = unsafe { (*self.cells[slot_index as usize].get()).session };\n"
     "        let mut rundown: Option<*mut EX_RUNDOWN_REF> = None;"),
    ("native-resolver-refusal-skips-rundown-release",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                            // SAFETY: this frame acquired exactly one rundown\n"
     "                            // reference on that cell and releases it once.\n"
     "                            unsafe { fsring_sys::c4::ExReleaseRundownProtection(held.cast()) };",
     "                            // Mutant: leak the acquired refusal reference.\n"
     "                            let _ = held;"),
    ("native-resolver-refusal-skips-lock-unwind",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                    if refusal.releases_lock() {\n",
     "                    if false && refusal.releases_lock() {\n"),
    ("native-resolver-refusal-skips-rundown-unwind",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                    if refusal.releases_rundown() {\n",
     "                    if false && refusal.releases_rundown() {\n"),
    ("native-resolver-skips-core-live",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                    match core.validate_live(locator) {",
     "                    match Ok::<(), fsring_core::session::SessionError>(()) {"),
    ("native-resolver-skips-cell-live",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                        Some(cell) if cell.matches_live_locator(locator) => pending.succeeded(),",
     "                        Some(_cell) => pending.succeeded(),"),
    ("native-cell-crate-visible-live-getter-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    fn matches_live_locator(&self, locator: SessionLocator) -> bool {\n",
     "    pub(crate) fn unchecked_live_session(\n"
     "        &self,\n"
     "        locator: SessionLocator,\n"
     "    ) -> Option<*mut NativeSession> {\n"
     "        (self.phase == NativeCellPhase::Live && self.generation == locator.generation())\n"
     "            .then_some(self.session)\n"
     "    }\n"
     "\n"
     "    fn matches_live_locator(&self, locator: SessionLocator) -> bool {\n"),
    ("native-terminal-legacy-owner-split-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "impl TerminalWork {\n"
     "    pub(crate) const fn locator(&self) -> SessionLocator {",
     "impl TerminalWork {\n"
     "    pub(crate) fn into_parts(\n"
     "        self,\n"
     "    ) -> (\n"
     "        fsring_core::session::TerminalWinner,\n"
     "        fsring_core::session::TerminalSessionRef,\n"
     "        ControlStrongRef,\n"
     "        ClosingControlOwner,\n"
     "        NativeSessionOwner,\n"
     "        SessionRootReleaseRight,\n"
     "    ) {\n"
     "        let Self { locator: _, winner, terminal, control, closing, shell, root } = self;\n"
     "        (winner, terminal, control, closing, shell, root)\n"
     "    }\n\n"
     "    pub(crate) const fn locator(&self) -> SessionLocator {"),
    ("native-fence-retains-cell-after-unlock",
     "driver/fsring-fsd/src/fence.rs",
     "/// Queue the one finalizer work item this kick names.\n",
     "unsafe fn retained_cell_after_unlock(\n"
     "    registry: NonNull<KernelSessionRegistry>,\n"
     "    index: u32,\n"
     ") -> Option<*mut crate::lifecycle::NativeSessionCell> {\n"
     "    let mut lock = unsafe { KernelSessionRegistry::lock(registry) };\n"
     "    let cell = unsafe { lock.cell_ptr(index) };\n"
     "    unsafe { lock.release() };\n"
     "    cell\n"
     "}\n\n"
     "/// Queue the one finalizer work item this kick names.\n"),
    ("native-fence-uses-cell-after-unlock",
     "driver/fsring-fsd/src/fence.rs",
     "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
     "        let verdict = match cell {\n"
     "            // SAFETY: the lock is held and the index is in range.\n"
     "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
     "            None => false,\n"
     "        };\n"
     "        unsafe { lock.release() };\n"
     "        verdict",
     "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
     "        unsafe { lock.release() };\n"
     "        let verdict = match cell {\n"
     "            // Mutant: the raw permanent-cell pointer outlives the lock.\n"
     "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
     "            None => false,\n"
     "        };\n"
     "        verdict"),
    ("native-fence-aliases-cell-across-unlock",
     "driver/fsring-fsd/src/fence.rs",
     "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
     "        let verdict = match cell {\n"
     "            // SAFETY: the lock is held and the index is in range.\n"
     "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
     "            None => false,\n"
     "        };\n"
     "        unsafe { lock.release() };\n"
     "        verdict",
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
     "        }"),
    ("native-fence-wraps-cell-across-unlock",
     "driver/fsring-fsd/src/fence.rs",
     "        let cell = unsafe { lock.cell_ptr(self.locator.slot_index()) };\n"
     "        let verdict = match cell {\n"
     "            // SAFETY: the lock is held and the index is in range.\n"
     "            Some(cell) => unsafe { (*cell).checkpoint_ledger_is_discharged(self.locator) },\n"
     "            None => false,\n"
     "        };\n"
     "        unsafe { lock.release() };\n"
     "        verdict",
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
     "        }"),
    ("native-terminal-destroys-shell-before-checkpoint",
     "driver/fsring-fsd/src/fence.rs",
     "    let (control, owners) = work.into_checkpoint_parts();\n",
     "    let (control, owners) = work.into_checkpoint_parts();\n"
     "    let _ = owners\n"
     "        .shell_owner()\n"
     "        .checkpoint_release_transient_arrays_and_backing();\n"),
    # Was `-destroys-shell-before-roster`, which stopped compiling when the
    # shell moved inside `NativeSessionOwner`: that type exposes no destructive
    # method at all, so early DESTRUCTION is now unrepresentable and
    # `shell_destruction_is_impossible_while_core_live` covers what remains of
    # it. The ordering the mutant was really about is still expressible --
    # `owners.shell_owner()` hands out a shared reference before the walk, and
    # the shell's VDO slot is take-once, so spending it early leaves the
    # roster's own `delete_shell_vdo` finding it already gone.
    ("native-checkpoint-spends-shell-vdo-before-roster",
     "driver/fsring-fsd/src/fence.rs",
     "    let ddi =\n"
     "        unsafe { NativeFenceDdi::new(registry, owners.shell_owner(), context, control, set, None) };\n"
     "    let outcome = match KernelFenceOps::try_new(ddi, set) {\n",
     "    let _early_vdo = owners.shell_owner().checkpoint_delete_vdo_once();\n"
     "    let ddi =\n"
     "        unsafe { NativeFenceDdi::new(registry, owners.shell_owner(), context, control, set, None) };\n"
     "    let outcome = match KernelFenceOps::try_new(ddi, set) {\n"),
    ("native-resolver-skips-owner-slots",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                        Some(cell) if cell.owners_match(locator) => pending.succeeded(),",
     "                        Some(_cell) => pending.succeeded(),"),
    ("native-process-scan-projects-shell",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        let prepared = match unsafe { lock.cell_ptr(index) } {\n"
     "            Some(cell) => match unsafe { (*cell).process_locator(process) } {\n",
     "        let prepared = match unsafe { lock.cell_ptr(index) } {\n"
     "            Some(cell) => match unsafe {\n"
     "                let _shell = (*cell).session;\n"
     "                (*cell).process_locator(process)\n"
     "            } {\n"),
    ("native-process-observation-ignores-requested-process",
     "driver/fsring-fsd/src/lifecycle.rs",
     "            NonNull::new(process)?,\n",
     "            NonNull::new(self.process)?,\n"),
    ("native-resolver-injects-finalizer-side-effect",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                ResolveStep::ValidateCoreLive => {\n",
     "                ResolveStep::ValidateCoreLive => {\n"
     "                    unsafe { wait_joiners_drained(NonNull::from(self).cast(), locator) };\n"),
    ("native-resolver-destroys-rundown-bookkeeping",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                ResolveStep::ValidateCoreLive => {\n",
     "                ResolveStep::ValidateCoreLive => {\n"
     "                    rundown = None;\n"),
    ("native-resolver-inverts-rundown-result",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                    if acquired == 0 {\n",
     "                    if acquired != 0 {\n"),
    ("native-resolver-export-attribute-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    pub(crate) unsafe fn resolve(\n",
     "    #[unsafe(no_mangle)]\n"
     "    pub(crate) unsafe fn resolve(\n"),
    ("native-driver-hidden-access-wait-restored",
     "driver/fsring-fsd/src/driver.rs",
     "pub(crate) unsafe fn root() -> *mut DriverState {\n",
     "unsafe fn hidden_access_wait(locator: fsring_core::session::SessionLocator) {\n"
     "    let state = unsafe { &*root() };\n"
     "    let access = match unsafe { state.sessions.resolve(locator) } {\n"
     "        Ok(access) => access,\n"
     "        Err(_) => return,\n"
     "    };\n"
     "    unsafe { crate::lifecycle::wait_joiners_drained(\n"
     "        core::ptr::NonNull::from(&state.sessions), locator,\n"
     "    ) };\n"
     "    drop(access);\n"
     "}\n\n"
     "pub(crate) unsafe fn root() -> *mut DriverState {\n"),
    # Retargeted: `close_process_callback_admission` was folded into
    # `close_global_admissions`, so the old call no longer compiled and the
    # mutant scored NOCOMPILE, which the gate excludes. The plant now writes
    # the same admission flag the retired helper wrote, so the property --
    # the process scan must not mutate callback admission -- is unchanged.
    ("native-process-scan-mutates-callback-admission",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        let mut lock = unsafe { Self::lock(registry) };\n",
     "        let mut lock = unsafe { Self::lock(registry) };\n"
     "        unsafe { *registry.as_ref().process_callback_admission_open.get() = false };\n"),
    ("native-access-view-borrow-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    pub(crate) fn view(&self) -> crate::session::NativeSessionView {\n"
     "        // SAFETY: the access rundown this guard holds keeps the shell alive,\n"
     "        // and every field `view` copies was written before publication.\n"
     "        self.session.get().view()\n"
     "    }",
     "    pub(crate) fn view(&self) -> &crate::session::NativeSession {\n"
     "        // Mutant: the guard exposes the live shell instead of four values.\n"
     "        self.session.get()\n"
     "    }"),
    ("native-access-guard-free-projection-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "pub(crate) unsafe fn acknowledge_completed_control(\n",
     "pub(crate) unsafe fn project_access<'a>(\n"
     "    access: &'a SessionAccessGuard<'a>,\n"
     ") -> &'a NativeSession {\n"
     "    unsafe { access.session.get() }\n"
     "}\n\n"
     "pub(crate) unsafe fn acknowledge_completed_control(\n"),
    ("native-ring-guard-raw-session-method-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "impl NativeRingGuard<'_, '_> {\n",
     "impl NativeRingGuard<'_, '_> {\n"
     "    pub(crate) fn raw_session(&self) -> *mut NativeSession {\n"
     "        core::ptr::from_ref(self.access.session.get()).cast_mut()\n"
     "    }\n"),
    ("native-ring-consuming-helper-forgets-guard",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    pub(crate) fn release(self) {}\n",
     "    pub(crate) fn release(self) { core::mem::forget(self); }\n"),
    ("native-ring-drop-omits-saved-irql-release",
     "driver/fsring-fsd/src/lifecycle.rs",
     "            saved.release_with(|old_irql| unsafe { self.slot.release_lock(old_irql) });\n",
     "            if false {\n"
     "                saved.release_with(|old_irql| unsafe { self.slot.release_lock(old_irql) });\n"
     "            }\n"),
    ("native-cell-session-pointer-alias-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "#[repr(C)]\n"
     "pub(crate) struct NativeSessionCell {\n"
     "    access: EX_RUNDOWN_REF,\n"
     "    terminal_outcome: KEVENT,\n"
     "    joiners_drained: KEVENT,\n"
     "    /// Broadcast generation visibility: set after either ordinary finalizer\n"
     "    /// resolution or durable Published/Opaque storage. Unlike the take-once\n"
     "    /// `finalizer_handoff`, every counted joiner may wait on this event.\n"
     "    visibility_resolution: KEVENT,\n"
     "    mount_complete: KEVENT,\n"
     "    mount_waiters_drained: KEVENT,\n"
     "    mount_reset_complete: KEVENT,\n"
     "    mount_reset_waiters_drained: KEVENT,\n"
     "    generation: u64,\n"
     "    identity: Option<SessionIdentity>,\n"
     "    phase: NativeCellPhase,\n"
     "    session: *mut NativeSession,\n",
     "type NativeCellSessionPtr = *mut NativeSession;\n"
     "\n"
     "#[repr(C)]\n"
     "pub(crate) struct NativeSessionCell {\n"
     "    access: EX_RUNDOWN_REF,\n"
     "    terminal_outcome: KEVENT,\n"
     "    joiners_drained: KEVENT,\n"
     "    /// Broadcast generation visibility: set after either ordinary finalizer\n"
     "    /// resolution or durable Published/Opaque storage. Unlike the take-once\n"
     "    /// `finalizer_handoff`, every counted joiner may wait on this event.\n"
     "    visibility_resolution: KEVENT,\n"
     "    mount_complete: KEVENT,\n"
     "    mount_waiters_drained: KEVENT,\n"
     "    mount_reset_complete: KEVENT,\n"
     "    mount_reset_waiters_drained: KEVENT,\n"
     "    generation: u64,\n"
     "    identity: Option<SessionIdentity>,\n"
     "    phase: NativeCellPhase,\n"
     "    session: NativeCellSessionPtr,\n"),
    ("native-access-guard-drop-skips-rundown-release",
     "driver/fsring-fsd/src/lifecycle.rs",
     "            // SAFETY: `resolve` acquired exactly one reference on this cell's\n"
     "            // rundown and this is its one release.\n"
     "            unsafe { fsring_sys::c4::ExReleaseRundownProtection(target.cast()) };",
     "            // Mutant: the affine guard leaks its rundown reference.\n"
     "            let _ = target;"),
    ("native-access-guard-drop-condition-never-releases",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        if let Some(target) = registry.access_rundown_ptr(self.slot_index) {\n",
     "        if let Some(target) = None::<*mut EX_RUNDOWN_REF> {\n"
     "            let _ = registry.access_rundown_ptr(self.slot_index);\n"),
    ("native-process-scan-skips-registry-unlock",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        // SAFETY: this frame took the lock and releases it once.\n"
     "        unsafe { lock.release() };\n"
     "        match action {\n",
     "        // SAFETY: this frame took the lock and releases it once.\n"
     "        if false {\n"
     "            unsafe { lock.release() };\n"
     "        }\n"
     "        match action {\n"),
    ("native-session-owner-clone-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "pub(crate) type NativeSessionOwner = CoreNativeSessionOwner<NativeSessionShell>;\n",
     "impl Clone for UnpublishedNativeSessionShell {\n"
     "    fn clone(&self) -> Self {\n"
     "        Self {\n"
     "            session: self.session,\n"
     "            authority: PrivateUnpublishedNativeSessionShellAuthority(()),\n"
     "        }\n"
     "    }\n"
     "}\n"
     "\n"
     "pub(crate) type NativeSessionOwner = CoreNativeSessionOwner<NativeSessionShell>;\n"),
    ("native-session-owner-raw-constructor-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "impl UnpublishedNativeSessionShell {\n",
     "impl UnpublishedNativeSessionShell {\n"
     "    /// # Safety\n"
     "    /// `session` names a live allocation.\n"
     "    pub(crate) unsafe fn from_ptr(session: *mut NativeSession) -> Self {\n"
     "        Self {\n"
     "            session: unsafe { NonNull::new_unchecked(session) },\n"
     "            authority: PrivateUnpublishedNativeSessionShellAuthority(()),\n"
     "        }\n"
     "    }\n"
     "\n"),
    ("native-qualified-access-guard-impl-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "impl<'registry> SessionAccessGuard<'registry> {\n",
     "impl crate::lifecycle::SessionAccessGuard<'_> {\n"
     "    pub(crate) fn raw_session(&self) -> *mut NativeSession {\n"
     "        core::ptr::from_ref(self.session.get()).cast_mut()\n"
     "    }\n"
     "}\n\nimpl<'registry> SessionAccessGuard<'registry> {\n"),
    ("native-access-guard-macro-method-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "impl<'registry> SessionAccessGuard<'registry> {\n",
     "macro_rules! leak_access {\n"
     "    () => { pub(crate) fn raw_session(&self) -> *mut NativeSession {\n"
     "        core::ptr::from_ref(self.session.get()).cast_mut()\n"
     "    } };\n"
     "}\n"
     "impl<'registry> SessionAccessGuard<'registry> {\n"
     "    leak_access!();\n"),
    ("native-access-projection-static-restored",
     "driver/fsring-fsd/src/lifecycle.rs",
     "pub(crate) unsafe fn acknowledge_completed_control(\n",
     "pub static PROJECT: for<'a> fn(&'a SessionAccessGuard<'a>) -> &'a NativeSession =\n"
     "    |access| access.session.get();\n\n"
     "pub(crate) unsafe fn acknowledge_completed_control(\n"),
    ("native-enter-access-hidden-wait-restored",
     "driver/fsring-fsd/src/session.rs",
     "    let access = match unsafe { registry.as_ref().resolve(locator) } {\n"
     "        Ok(access) => access,\n"
     "        Err(error) => return error.status(),\n"
     "    };\n",
     "    let access = match unsafe { registry.as_ref().resolve(locator) } {\n"
     "        Ok(access) => access,\n"
     "        Err(error) => return error.status(),\n"
     "    };\n"
     "    unsafe { crate::lifecycle::wait_joiners_drained(registry, locator) };\n"),
    ("native-ring-discards-saved-irql",
     "driver/fsring-fsd/src/lifecycle.rs",
     "            saved.release_with(|old_irql| unsafe { self.slot.release_lock(old_irql) });",
     "            saved.release_with(|_old_irql| unsafe { self.slot.release_lock(0) });"),
    ("native-ring-lock-initialization-skipped",
     "driver/fsring-fsd/src/session.rs",
     "            unsafe { slot.initialize_lock() };",
     "            let _ = slot;"),
    ("native-ring-initialization-proof-discarded",
     "driver/fsring-fsd/src/session.rs",
     "    context.ring_locks = Some(initialized);",
     "    drop(initialized);"),
    ("native-ring-acquire-ddi-bypassed",
     "driver/fsring-fsd/src/session.rs",
     "        unsafe { fsring_sys::c4::KeAcquireSpinLockRaiseToDpc(self.lock_ptr()) }",
     "        0"),
    ("native-ring-release-ddi-bypassed",
     "driver/fsring-fsd/src/session.rs",
     "        unsafe { fsring_sys::c4::KeReleaseSpinLock(self.lock_ptr(), old_irql) };",
     "        let _ = old_irql;"),
    ("native-fence-ring-lock-bypassed",
     "driver/fsring-fsd/src/session.rs",
     "        unsafe { ring.signal_pending_enter() };",
     "                let _ = ring;"),
    ("native-ring-slot-extra-method-restored",
     "driver/fsring-fsd/src/session.rs",
     "impl NativeRingSlot {\n",
     "impl NativeRingSlot {\n    pub(crate) fn marker(&self) {}\n"),
    ("native-ring-unshared-hidden-caller-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "unsafe fn hidden_unshared(slot: &mut NativeRingSlot) {\n"
     "    let _state = unsafe { slot.state_unshared() };\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-free-api-marker-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "pub(crate) fn marker() {}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-import-aliased-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "use core::ptr::NonNull as Address;\n"
     "unsafe fn mapped(session: *mut NativeSession) -> Address<u8> {\n"
     "    unsafe { Address::new_unchecked((*session).system_view.cast()) }\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-newtype-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "struct Address(NonNull<u8>);\n"
     "unsafe fn mapped(session: *mut NativeSession) -> Address {\n"
     "    Address(unsafe { NonNull::new_unchecked((*session).system_view.cast()) })\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-enum-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "enum AddressCarrier { Ptr { value: NonNull<u8> } }\n"
     "unsafe fn mapped(session: *mut NativeSession) -> AddressCarrier {\n"
     "    AddressCarrier::Ptr { value: unsafe { NonNull::new_unchecked((*session).system_view.cast()) } }\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-qualified-alias-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "type Address = NonNull<u8>;\n"
     "unsafe fn mapped(session: *mut NativeSession) -> self::Address {\n"
     "    unsafe { NonNull::new_unchecked((*session).system_view.cast()) }\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-union-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "union Address { pointer: *mut u8 }\n"
     "unsafe fn hidden_union_projection(session: *mut NativeSession) -> Address {\n"
     "    Address { pointer: unsafe { (*session).system_view.cast() } }\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-option-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "unsafe fn hidden_option_projection(\n"
     "    session: *mut NativeSession,\n"
     ") -> Option<*mut u8> {\n"
     "    Some(unsafe { (*session).system_view.cast() })\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-session-raw-section-getter-restored",
     "driver/fsring-fsd/src/session.rs",
     "impl NativeSession {\n"
     "    pub(crate) const fn identity(&self) -> SessionIdentity {",
     "impl NativeSession {\n"
     "    pub(crate) fn system_view_base(&self) -> *const u8 {\n"
     "        self.system_view.cast::<u8>().cast_const()\n"
     "    }\n\n"
     "    pub(crate) const fn identity(&self) -> SessionIdentity {"),
    ("native-session-view-borrow-restored",
     "driver/fsring-fsd/src/session.rs",
     "impl NativeSessionView {\n"
     "    pub(crate) const fn identity(&self) -> SessionIdentity {",
     "impl NativeSessionView {\n"
     "    pub(crate) const fn layout_ref(&self) -> &SectionLayoutPlan { &self.layout }\n\n"
     "    pub(crate) const fn identity(&self) -> SessionIdentity {"),
    ("native-session-root-backpointer-reexposed",
     "driver/fsring-fsd/src/session.rs",
     "pub struct NativeSession {\n    state: *mut DriverState,",
     "pub struct NativeSession {\n    pub(crate) state: *mut DriverState,"),
    ("native-session-free-mapped-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "pub(crate) unsafe fn mapped_view(session: *mut NativeSession) -> *const u8 {\n"
     "    unsafe { (*session).system_view.cast::<u8>().cast_const() }\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    ("native-ring-free-state-pointer-restored",
     "driver/fsring-fsd/src/session.rs",
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n",
     "pub(crate) unsafe fn project_ring(slot: &NativeRingSlot) -> *mut NativeRingState {\n"
     "    slot.state.get()\n"
     "}\n"
     "\n"
     "pub(crate) unsafe fn delete_vdo_once(session: *mut NativeSession) -> bool {\n"),
    # Round-9 blocker 1. Two operators, one per half of the attach-scratch
    # rule: the first puts the shared buffer back AND respells the argument
    # that reaches the kernel, the second only reintroduces the shared item.
    # Both compile (a `static` is a legal block item and `fsring-fsd` denies no
    # dead-code lint), so each is graded by the lifetime production check that
    # `audit_c4_native_mutant.py` runs, not by the compiler.
    ("native-attach-scratch-shared-static-restored",
     "driver/fsring-fsd/src/session.rs",
     "        fsring_sys::c4::KeStackAttachProcess(process.cast(), context.apc_state.as_mut_ptr());",
     "        static mut APC_STATE: KAPC_STATE = unsafe { core::mem::zeroed() };\n"
     "        fsring_sys::c4::KeStackAttachProcess(process.cast(), core::ptr::addr_of_mut!(APC_STATE));"),
    ("native-attach-scratch-shared-item-reintroduced",
     "driver/fsring-fsd/src/session.rs",
     "unsafe fn attach_captured(context: &mut SetupContext) -> Result<(), NTSTATUS> {",
     "static mut APC_STATE: KAPC_STATE = unsafe { core::mem::zeroed() };\n\n"
     "unsafe fn attach_captured(context: &mut SetupContext) -> Result<(), NTSTATUS> {"),
    # Round-9 blocker 2. The core operator is graded by EXECUTION -- the
    # only crate whose tests run in this battery -- and the fsd operator by
    # the lifetime auditor. The fsd one deliberately keeps the call site: a
    # mutant that deleted it would be refused by the graph gate at the
    # refresh stage, and `audit_c4_native_mutant.py` returns there without
    # ever reaching the rule the mutant claims to grade.
    ("csq-worker-dequeue-completes-a-still-queued-slot",
     "driver/fsring-core/src/enter.rs",
     "        (Some(IrpAxis::Queued), _) => WorkerDequeueAuthority::NoHandoffPublished,",
     "        (Some(IrpAxis::Queued), Some(irp)) => WorkerDequeueAuthority::ReleasedToDriver(irp),"),
    ("pending-completion-classifies-a-constant-axis",
     "driver/fsring-fsd/src/pending_enter.rs",
     # Two `classify_worker_dequeue` calls exist since round 10, and the
     # deeper one contains this line's text as a substring, so the anchor
     # carries the call line that tells them apart.
     "        classify_worker_dequeue(\n            (*raw).irp_axis,",
     "        classify_worker_dequeue(\n            Some(IrpAxis::Dequeued),"),
    # Round-9 high 1. Three operators for one property: two in core, graded
    # by executing tests, and one in fsd, graded by the auditor.
    ("win7-roster-skips-the-master-locks",
     "driver/fsring-core/src/adapter/setup.rs",
     "        let masters = master_count(ring_count)?;\n        if index < masters {\n            let (region, access) = master_at(ring_count, index)?;\n            return Some(ProtectedViewEffect::AllocateAndLockMaster { region, access });\n        }\n        let index = index.checked_sub(masters)?;",
     "        let index = index;"),
    ("win7-masters-are-not-unwound",
     "driver/fsring-core/src/adapter/setup.rs",
     "            return Some((masters_locked, 0, self.mapped_aliases));",
     "            return Some((0, 0, self.mapped_aliases));"),
    ("native-master-residency-is-profile-conditional",
     "driver/fsring-fsd/src/session.rs",
     "    let master_count = (layout.ring_count() as usize).saturating_add(2);",
     "    let master_count = if matches!(profile, PlatformProfile::Win10X64 | PlatformProfile::Win10Arm64) { (layout.ring_count() as usize).saturating_add(2) } else { 0 };"),
    # Round-9 high 5. The tally stops being a measurement and becomes the
    # oracle restated -- the exact self-certifying shape the finding named.
    ("package-launch-counts-restate-the-oracle",
     "driver/scripts/package_c4_candidate.ps1",
     "        $launchCounts = Get-C4PackageLaunchTally $journalPath $markerRoster",
     "        $launchCounts = $script:ExpectedNestedLaunchCounts"),
    # And the coverage guard stops refusing anything, so a launch site added
    # outside the noted choke point would go unseen.
    ("package-launch-coverage-guard-neutered",
     "driver/scripts/package_c4_candidate.ps1",
     "        throw (\"package verifier launches outside the noted choke point: {0}\" -f ($unnoted -join '; '))",
     "        $null = $unnoted"),
    # Round-11 high, found by review: the admission stops testing the field
    # `begin_pass` refuses on, so a queued pass refuses identically for ever.
    ("pass-admission-ignores-the-missing-plan",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        if self.parked_plan.is_none() || self.arbiter.is_none() {",
     "        if false {"),
    # Round-11 medium M2, and the reason the two below exist at all: the rule
    # above graded the DECISION and nothing required either instant to ask
    # it. Deleting the store's queue call produced no finding while the
    # comment beside it claimed both instants ask. One mutant per instant,
    # because one mutant would leave the other half in exactly that state.
    #
    # The store instant: a wake that landed before the plan was published is
    # owed a pass, and this is the only place that notices.
    ("store-owed-pass-is-never-queued",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    let owed = if stored.is_ok() && queued.is_none() {",
     "    let owed = if false {"),
    # The abandon instant: keeps the ask -- so an observer watching only for
    # a `pass_admission()` call still sees one -- and drops the queue it
    # answers for. `let _ =` rather than deleting the line, because an unused
    # binding would land as NOCOMPILE and NOCOMPILE grades nothing.
    ("abandon-drops-the-pass-it-owes",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                let admission = self.pass_admission()?;\n"
     "                self.queue_wake_still_owed(admission)",
     "                let _ = self.pass_admission()?;\n"
     "                None"),
    # Round-11 high N2: `DefaultSDDLString` is a terminated string and the
    # Object Manager name beside it is counted, and both were minted the same
    # way. One mutant per limb of the repair, because each limb is separately
    # sufficient to hand the WDK a descriptor whose `MaximumLength` and buffer
    # disagree.
    #
    # The mint stops refusing an unterminated buffer, which is the only thing
    # keeping a caller from reaching for the terminated convention with a name.
    ("sddl-mint-accepts-an-unterminated-buffer",
     "driver/fsring-fsd/src/kernel.rs",
     "    if buffer.last().copied() != Some(0) {",
     "    if false {"),
    # A role builds its SDDL with the counted-name convention again.
    ("volume-sddl-uses-the-counted-name-convention",
     "driver/fsring-fsd/src/volume.rs",
     "crate::kernel::counted_unicode_sz(&mut sddl_units)",
     "crate::kernel::counted_unicode_units(&mut sddl_units)"),
    # `control.rs` used to reach the mint through a local alias; round 13 put
    # the SDDL on the mint's own qualified path, because a review restored the
    # defect by repointing an alias of exactly that shape in a role whose rule
    # only checked that SOME local name was used.
    ("control-sddl-uses-the-counted-name-convention",
     "driver/fsring-fsd/src/control.rs",
     "crate::kernel::counted_unicode_sz(&mut sddl_buffer)",
     "crate::kernel::counted_unicode_units(&mut sddl_buffer)"),
    # `fscontrol.rs` had NO mutant at all, so its instance of the SDDL rule was
    # graded by nothing -- named by the round-12 evidence review.
    ("fscontrol-sddl-uses-the-counted-name-convention",
     "driver/fsring-fsd/src/fscontrol.rs",
     "crate::kernel::counted_unicode_sz(&mut sddl_units)",
     "crate::kernel::counted_unicode_units(&mut sddl_units)"),
    # Round-12 E3: the rule anchored the field initialiser's IDENTIFIER, so
    # `MaximumLength == Length` came back inside the terminated mint under the
    # name `maximum` and passed. One mutant per newly pinned limb, as the
    # review asked, so the closure is graded rather than asserted.
    ("sz-mint-maximum-equals-its-length",
     "driver/fsring-fsd/src/kernel.rs",
     "    let maximum = u16::try_from(buffer.len().checked_mul(core::mem::size_of::<u16>())?).ok()?;",
     "    let maximum = length;"),
    # Round-12 E1: the admission's guards were required to be SPELLED, not to
    # decide. This keeps both tests exactly as written and removes the refusal
    # EFFECT from one of them.
    ("admission-guard-tests-without-refusing",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        if self.parked_plan.is_none() || self.arbiter.is_none() {\n"
     "            return None;\n"
     "        }\n",
     "        if self.parked_plan.is_none() || self.arbiter.is_none() {\n"
     "            let _ = self.install;\n"
     "        }\n"),
    # Round-12 N1: nothing observed what `begin_pass` refuses on, so a refusal
    # it does not share with the admission reproduced the round-11 permanent
    # worker-thread livelock under a fully green 38-row battery.
    ("begin-pass-refuses-outside-the-admission",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        let PassAdmission(()) = self.pass_admission()?;\n"
     "        begin_native_worker_pass(",
     "        let PassAdmission(()) = self.pass_admission()?;\n"
     "        if self.queue_right.is_some() {\n"
     "            return None;\n"
     "        }\n"
     "        begin_native_worker_pass("),
    # Round-14 medium: `begin_completion` declares `Completing` and the
    # authorities do not come, and the declaration is no longer given back --
    # the schedule then refuses to finish, to abandon and to queue for the life
    # of the slot. This is the THIRD such exit; the review found it precisely
    # because the rule counted the arms that existed instead of pinning the
    # decision.
    # The leading newline pins the 24-space indent, and so this call site: all
    # three `abandon_completion()` calls differ only by depth.
    ("completion-declared-without-authorities-stays-completing",
     "driver/fsring-fsd/src/pending_enter.rs",
     "\n                        runtime.abandon_completion();",
     "\n                        let _ = taken.is_some();"),
    # Round-14 medium: the unload observation bugchecks INSIDE the slot-lock
    # hold again. With `panic = "abort"` the guard's `Drop` never runs, so the
    # lock stays held and every other processor touching this ring hangs. The
    # panic is still present and still fires on the same states -- only its
    # position relative to the release changes, which is the whole defect.
    ("unload-observation-bugchecks-under-the-slot-lock",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    unlock.release();\n"
     "    match observed {\n"
     "        Ok(observation) => observation,\n"
     "        Err(reason) => panic!(\"{reason}\"),\n"
     "    }\n"
     "}",
     "    let resolved = match observed {\n"
     "        Ok(observation) => observation,\n"
     "        Err(reason) => panic!(\"{reason}\"),\n"
     "    };\n"
     "    unlock.release();\n"
     "    resolved\n"
     "}"),
    # Round-14 medium: the endpoint is published before the root field a
    # dispatch reads through it, so a SETUP arriving in that window sees null
    # and refuses the first session. The two statements are simply swapped --
    # both still present, which is what a rule that only looked for the call
    # would miss.
    ("provider-endpoint-published-before-its-root-field",
     "driver/fsring-fsd/src/driver.rs",
     "            unsafe { ready.publish_provider_device(context.provider_device) };\n"
     "            // SAFETY: the extension and link are complete.\n"
     "            unsafe { crate::control::publish(context.provider_device) };",
     "            // SAFETY: the extension and link are complete.\n"
     "            unsafe { crate::control::publish(context.provider_device) };\n"
     "            unsafe { ready.publish_provider_device(context.provider_device) };"),
    # Round-14 medium: the credit backing goes back to being adopted only at the
    # end of the function, so the three fallible steps in between drop a
    # `RawArray` that has no `Drop` and nothing can free it.
    # A fallible step put back INTO the window, which is the defect itself:
    # deleting the adoption instead would leave the local unused and grade as a
    # compile problem rather than as the leak.
    ("credit-backing-left-unadopted-across-a-fallible-step",
     "driver/fsring-fsd/src/session.rs",
     "    unsafe { (*session).credits = credits };",
     "    let Ok(_probe) = u32::try_from(credit_count) else {\n"
     "        return Err(STATUS_INVALID_PARAMETER);\n"
     "    };\n"
     "    unsafe { (*session).credits = credits };"),
    # Round-14 HIGH: the SETUP unwind stops releasing the pending runtime, so a
    # refused SETUP drops the pool arena and up to 64 work items, each holding a
    # reference on the permanent provider device. `PendingRuntimeReady` has no
    # `Drop`, so nothing else gives them back.
    ("setup-unwind-leaks-the-pending-runtime",
     "driver/fsring-fsd/src/session.rs",
     "    if let Some(runtime) = context.pending_runtime.take() {\n"
     "        // SAFETY: PASSIVE_LEVEL rollback with no lock held, the arena is still\n"
     "        // resident, and the runtime was never installed into a cell -- the\n"
     "        // contract `release_pending_runtime` states for itself.\n"
     "        unsafe {\n"
     "            runtime.release_pending_runtime(&mut crate::pending_enter::NativePendingRuntimeDdi)\n"
     "        };\n"
     "    }\n"
     "    for effect in effects.iter().copied() {",
     "    for effect in effects.iter().copied() {"),
    # And the ORDER: the release still happens, but after the effect loop has
    # already freed ring state the slots' timers and DPCs can still reach.
    ("setup-unwind-releases-the-runtime-too-late",
     "driver/fsring-fsd/src/session.rs",
     "    if let Some(runtime) = context.pending_runtime.take() {\n"
     "        // SAFETY: PASSIVE_LEVEL rollback with no lock held, the arena is still\n"
     "        // resident, and the runtime was never installed into a cell -- the\n"
     "        // contract `release_pending_runtime` states for itself.\n"
     "        unsafe {\n"
     "            runtime.release_pending_runtime(&mut crate::pending_enter::NativePendingRuntimeDdi)\n"
     "        };\n"
     "    }\n"
     "    for effect in effects.iter().copied() {\n"
     "        // SAFETY: each release below is guarded and idempotent.\n"
     "        unsafe { undo(context, effect) };\n"
     "    }\n",
     "    for effect in effects.iter().copied() {\n"
     "        // SAFETY: each release below is guarded and idempotent.\n"
     "        unsafe { undo(context, effect) };\n"
     "    }\n"
     "    if let Some(runtime) = context.pending_runtime.take() {\n"
     "        // SAFETY: PASSIVE_LEVEL rollback with no lock held, the arena is still\n"
     "        // resident, and the runtime was never installed into a cell -- the\n"
     "        // contract `release_pending_runtime` states for itself.\n"
     "        unsafe {\n"
     "            runtime.release_pending_runtime(&mut crate::pending_enter::NativePendingRuntimeDdi)\n"
     "        };\n"
     "    }\n"),
    # Round-14 BLOCKER: SETUP stops stamping the ring set's brand into the
    # shell's own `RingEnterState`, so it stays as `new` built it -- unbranded
    # -- and every R4 role request on it answers `WrongState`. The fence can
    # then never acquire a CQ consumer and every terminal retries for ever.
    ("setup-leaves-the-shell-ring-unbranded",
     "driver/fsring-fsd/src/session.rs",
     "        let adopted = unsafe { shell_ring.state_unshared() }\n"
     "            .enter_mut()\n"
     "            .adopt_ring_brand(ring_brand);\n"
     "        if adopted.is_err() {",
     "        let adopted: Result<(), ()> = Ok(());\n"
     "        if adopted.is_err() {"),
    # And the adoption stops being one-shot, so it becomes a way to re-identify
    # a live ring under the tokens its previous identity already minted.
    ("brand-adoption-accepts-an-already-branded-state",
     "driver/fsring-core/src/enter.rs",
     "        if self.brand.is_some() {\n"
     "            return Err(RoleError::WrongState);\n"
     "        }\n"
     "        if self.ring_index != brand.ring_index() {",
     "        if self.ring_index != brand.ring_index() {"),
    # Round-14 BLOCKER: the CLEANUP completed-record arm drops the record on
    # its refusal edge instead of putting it back, which loses the
    # `CloseContextRight` exactly as carrying it out of the hold did. The
    # subtler half of the repair, and the one a reader is most likely to
    # "simplify" away.
    ("cleanup-drops-the-close-right-on-its-refusal-edge",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                        Err(record) => {\n"
     "                            // SAFETY: same hold, same context, and the slot is\n"
     "                            // the one `take_completed_record` emptied.\n"
     "                            unsafe {\n"
     "                                crate::control::store_completed_control_record_prepared(\n"
     "                                    context, record,\n"
     "                                )\n"
     "                            };\n"
     "                            Err(wdk_sys::STATUS_INVALID_DEVICE_STATE)\n"
     "                        }",
     "                        Err(_record) => Err(wdk_sys::STATUS_INVALID_DEVICE_STATE),"),
    # Round-14 HIGH: the R4 release goes back to discarding the prefix and
    # calling the R3 helper, so every acquired token is dropped and each ring's
    # `cq_owner` stays Some(..) with no holder -- busy for ever.
    ("r4-release-discards-the-consumer-prefix",
     "driver/fsring-fsd/src/fence.rs",
     "        while prefix.release_remaining() > 0 {",
     "        let _ = prefix;\n"
     "        if false {"),
    # And the drain goes back to the R3 predicate, which asks whether a consumer
    # THIS fence is holding is free -- false on exactly the rings the acquire
    # succeeded on, so every working fence refuses one row later.
    ("r4-drain-asks-whether-its-own-consumer-is-free",
     "driver/fsring-fsd/src/fence.rs",
     "crate::session::checkpoint_wait_sq_roles_with_consumers_held(session)",
     "crate::session::checkpoint_wait_existing_sq_cq_roles_and_consumers(session)"),
    # Round-14 highs: the fence retry worker's completing arm did neither of
    # the two things the primary path's completing arm always did.
    ("retry-complete-drops-the-control-reference",
     "driver/fsring-fsd/src/fence.rs",
     "            let released_control = ddi.take_unreleased_control();\n"
     "            if let Some(control) = released_control {\n"
     "                let mut lock = unsafe { KernelSessionRegistry::lock(registry) };\n"
     "                let _ = unsafe {\n"
     "                    release_strong_and_deposit(\n"
     "                        &mut lock,\n"
     "                        R4ReleaseAuthority::Stable(control.into_reference()),\n"
     "                        None,\n"
     "                    )\n"
     "                };\n"
     "                unsafe { lock.release() };\n"
     "            }\n"
     "            let _ = ddi;\n"
     "            let accumulated =",
     "            let _ = ddi.take_unreleased_control();\n"
     "            let _ = ddi;\n"
     "            let accumulated ="),
    # And the answer `finish_fence` exists to give is thrown away again, so a
    # fence completing after a retry never queues the finalizer it owes.
    ("retry-complete-discards-the-finish-disposition",
     "driver/fsring-fsd/src/fence.rs",
     "            let disposition = match unsafe { prepare_finish_fence(&mut lock, candidate) } {\n"
     "                Ok(prepared) => Some(unsafe { finish_fence(&mut lock, prepared) }),\n"
     "                Err(_) => None,\n"
     "            };",
     "            let disposition: Option<StrongReleaseDisposition> = None;\n"
     "            if let Ok(prepared) = unsafe { prepare_finish_fence(&mut lock, candidate) } {\n"
     "                let _ = unsafe { finish_fence(&mut lock, prepared) };\n"
     "            }"),
    # The frame ABOVE `begin_pass`. An adversarial pass restored the round-11
    # livelock with a readiness guard at this call site, leaving `begin_pass`
    # itself untouched, and every rule that pins its body passed.
    ("begin-pass-gated-at-its-call-site",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                let reason = runtime.begin_pass();",
     "                let reason = if runtime.queue_right.is_some() { None } else { runtime.begin_pass() };"),
    # Round-12 native finding 2: the second refusal arm returned the three
    # authorities and left the schedule at `Completing` -- refusing to finish
    # and refusing to queue, with the IRP dequeued and its cancel routine spent.
    ("completion-refusal-skips-the-abandon",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                runtime.abandon_completion();\n"
     "            }\n"
     "            unlock.release();\n"
     "            return false;\n"
     "        }\n"
     "    };",
     "            }\n"
     "            unlock.release();\n"
     "            return false;\n"
     "        }\n"
     "    };"),
    # Round-10 blocker, found by review under a green 38-row battery: the
    # production fence unmap stops asking the alias record which mechanism
    # mapped it, so the spine section view is handed to MmUnmapLockedPages
    # with a null partial at the teardown of every successful SETUP.
    ("fence-unmap-ignores-the-alias-mechanism",
     "driver/fsring-fsd/src/session.rs",
     "        // the teardown of every successful SETUP on a modern profile.\n        if !alias.partial.is_null() {",
     "        // the teardown of every successful SETUP on a modern profile.\n        if true {"),
    # Round-10 high: the spine master goes back to spanning the whole
    # section, which is the ~32 MiB `MDL.Size` cap that refused SETUP for
    # every large topology the layout accepts.
    ("spine-master-spans-the-whole-section",
     "driver/fsring-core/src/adapter/setup.rs",
     "            let length = directory.offset.checked_add(directory.length)?;",
     "            let length = layout.section_size();"),
    # And the spine goes back to a partial MDL, which cannot describe it.
    ("spine-maps-through-a-partial-mdl",
     "driver/fsring-core/src/adapter/setup.rs",
     "        if mapping == 0 {",
     "        if false {"),
    # Round-10 blocker: the fence retry worker's fail-stop stops storing the
    # packet, so the seven affine owners it holds -- shell, DriverState
    # reference, control rundown reference among them -- are dropped.
    ("fence-retry-fail-stop-stores-nothing",
     "driver/fsring-fsd/src/fence.rs",
     "                    let visibility = unsafe { store_fail_stop_locked(&mut lock, packet) };",
     "                    let visibility = R3FailStopVisibility::ReentryRetained(R3FailStopReentryGuard::retain(packet));"),
    # Round-10 blocker: the abandoned completion stops depositing the Cancel
    # the framework adopted while the pass stood Completing, so the parked
    # ENTER is dequeued, adopted and completed by nobody.
    ("abandoned-completion-drops-the-adopted-cancel",
     "driver/fsring-fsd/src/pending_enter.rs",
     "            if matches!(adopted, WorkerDequeueAuthority::ReleasedToDriver(_)) {",
     "            if matches!(adopted, WorkerDequeueAuthority::NoParkedIrp) {"),
    # Round-10 high: the store stops asking whether a wake stranded before
    # the plan existed is owed a pass, so a finite WAIT never times out.
    ("stored-wake-after-the-plan-store-is-never-queued",
     "driver/fsring-core/src/enter.rs",
     "    if schedule.axis != InstallAxis::HandoffDone || schedule.state != WorkerScheduleState::Idle {",
     "    if true {"),
    # Round-10 blocker: an Idle finish keeps the Worker owner, so the ledger
    # refuses every later wake with DuplicateOwner and the ring serves no
    # further parked ENTER for the life of the install.
    ("worker-token-survives-an-idle-finish",
     "driver/fsring-core/src/enter.rs",
     "            match owners.release_owner(token) {",
     "            match Err::<(), (PendingError, PendingOwnerToken)>((PendingError::WrongOwnerKind, token)) {"),
    # Round-10 blocker: the journal goes back inside the sealed attempt.
    # The runner builds its closed file roster only after the last row, so
    # this costs a whole battery and then leaves the attempt unsealed --
    # unrecordable even as the FAIL it was.
    ("package-journal-written-into-the-attempt",
     "driver/scripts/package_c4_candidate.ps1",
     "        $journalPath = Join-Path $journalRoot $script:VerifierLaunchJournalName",
     "        $journalPath = Join-Path $attemptRoot $script:VerifierLaunchJournalName"),
    # Round-9 high 4. The ownership comparison still exists and still names
    # a driver object -- it just compares the target with itself, which is
    # the shape a presence-only rule cannot tell from the real check.
    ("mount-ownership-compares-the-target-with-itself",
     "driver/fsring-fsd/src/volume.rs",
     "let own_driver = unsafe { (*device).DriverObject };",
     "let own_driver = unsafe { (*target).DriverObject };"),
    # And the ordering defect itself: the foreign extension is projected
    # before the driver-object question is asked.
    ("mount-projects-extension-before-ownership",
     "driver/fsring-fsd/src/volume.rs",
     "    let own_driver = unsafe { (*device).DriverObject };",
     "    let _early = unsafe { (*target).DeviceExtension.cast::<ExtensionHeader>() };\n    let own_driver = unsafe { (*device).DriverObject };"),
    # Round-9 high 3: the refusal goes back to being discarded. It
    # compiles, so the lifetime auditor that owns session.rs grades it.
    ("parked-store-refusal-discarded",
     "driver/fsring-fsd/src/session.rs",
     "let stored = unsafe { access.store_parked_wait(ring_index, owned, request) };",
     "let _ = unsafe { access.store_parked_wait(ring_index, owned, request) };\n                    let stored: Result<(), ()> = Ok(());"),
    # Round-9 high 2. Both compile, so both are graded by the auditor that
    # owns this file rather than by the compiler: the first walks the
    # dequeue in the unconditional prefix again, the second lets a refused
    # pass keep its completion declaration and wedge the slot in
    # `Completing`.
    ("pending-worker-dequeues-before-authority",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        PendingCallbackAction::PollAndRecheck,\n    ] {",
     "        PendingCallbackAction::PollAndRecheck,\n        PendingCallbackAction::RemoveIrpFromCsq,\n    ] {"),
    # The leading newline is load-bearing: round 13 added a SECOND
    # `abandon_completion()` call one nesting level deeper, and this anchor
    # without it matched inside that 16-space line too, failing exact-one.
    # Anchoring the line break pins the indentation and so the call site.
    ("pending-refused-pass-stays-completing",
     "driver/fsring-fsd/src/pending_enter.rs",
     "\n            runtime.abandon_completion();",
     ""),
    ("native-vdo-read-before-ready",
     "driver/fsring-fsd/src/volume.rs",
     "        let state = unsafe { (*extension).locator_state.load(Ordering::Acquire) };\n"
     "        if state != VDO_LOCATOR_INITIALIZED {\n"
     "            return None;\n"
     "        }\n"
     "        // SAFETY: the Acquire load proves the initializing store happened\n"
     "        // before this read, and the field is never written again.\n"
     "        Some(unsafe { (*(*extension).locator.get()).assume_init() })",
     "        let locator = unsafe { (*(*extension).locator.get()).assume_init() };\n"
     "        let state = unsafe { (*extension).locator_state.load(Ordering::Acquire) };\n"
     "        (state == VDO_LOCATOR_INITIALIZED).then_some(locator)"),
    ("native-vdo-readiness-check-bypassed",
     "driver/fsring-fsd/src/volume.rs",
     "        if !initializing {",
     "        if false {"),
    ("native-vdo-owner-state-check-bypassed",
     "driver/fsring-fsd/src/volume.rs",
     "            if (*extension).locator_state.load(Ordering::Acquire) != VDO_LOCATOR_INITIALIZING {",
     "            if false {"),
    ("native-vdo-publication-release-weakened",
     "driver/fsring-fsd/src/volume.rs",
     "                .store(VDO_LOCATOR_INITIALIZED, Ordering::Release);",
     "                .store(VDO_LOCATOR_INITIALIZED, Ordering::Relaxed);"),
    ("native-vdo-ready-predicate-inverted",
     "driver/fsring-fsd/src/volume.rs",
     "        if state != VDO_LOCATOR_INITIALIZED {\n",
     "        if state == VDO_LOCATOR_INITIALIZED {\n"),
    ("native-volume-free-session-projection-restored",
     "driver/fsring-fsd/src/volume.rs",
     "pub(crate) fn volume_name(mount_id: MountId) -> Option<[u16; VOLUME_NAME_UNITS]> {\n",
     "pub(crate) unsafe fn hidden_volume_projection(\n"
     "    session: *mut crate::session::NativeSession,\n"
     ") -> *mut crate::session::NativeSession { session }\n\n"
     "pub(crate) fn volume_name(mount_id: MountId) -> Option<[u16; VOLUME_NAME_UNITS]> {\n"),
    ("native-volume-method-session-projection-restored",
     "driver/fsring-fsd/src/volume.rs",
     "impl VolumeExtension {\n",
     "impl VolumeExtension {\n"
     "    pub(crate) unsafe fn project(\n"
     "        &self, session: *mut crate::session::NativeSession,\n"
     "    ) -> *mut crate::session::NativeSession { session }\n"),
    ("native-mount-device-kind-bypassed",
     "driver/fsring-fsd/src/volume.rs",
     "    let routing_target_matches = matches!(\n"
     "        unsafe { ExtensionHeader::kind_of(target_extension) },\n"
     "        Some(DeviceKind::VirtualDisk)\n"
     "    );",
     "    let routing_target_matches = true;"),
    ("native-mount-identity-bypassed",
     "driver/fsring-fsd/src/volume.rs",
     "    if identity.mount_id.lo != mount_lo || identity.mount_id.hi != mount_hi {",
     "    if false {"),
    ("native-volume-raw-session-projection-restored",
     "driver/fsring-fsd/src/volume.rs",
     "impl VolumeExtension {\n"
     "    /// The locator this VDO names, once publication has written it.",
     "impl VolumeExtension {\n"
     "    pub(crate) unsafe fn raw_session(extension: *const Self) -> *mut core::ffi::c_void {\n"
     "        unsafe { (*extension).locator.get().cast() }\n"
     "    }\n\n"
     "    /// The locator this VDO names, once publication has written it."),
    ("native-mounted-volume-raw-session-projection-restored",
     "driver/fsring-fsd/src/volume.rs",
     "const MOUNTED_EXTENSION_SIZE: ULONG = core::mem::size_of::<MountedVolumeExtension>() as ULONG;",
     "impl MountedVolumeExtension {\n"
     "    pub(crate) fn raw_session(&self) -> *mut core::ffi::c_void {\n"
     "        core::ptr::from_ref(&self.locator).cast_mut().cast()\n"
     "    }\n"
     "}\n\n"
     "const MOUNTED_EXTENSION_SIZE: ULONG = core::mem::size_of::<MountedVolumeExtension>() as ULONG;"),
    ("native-mount-retained-run-bypassed",
     "driver/fsring-fsd/src/volume.rs",
     "    let retained = RetainedAccessGuard::new(access);\n"
     "    let mut status = STATUS_INVALID_DEVICE_REQUEST;\n"
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
     "    });\n"
     "    status\n",
     "    drop(access);\n"
     "    STATUS_INVALID_DEVICE_REQUEST\n"),
    ("native-mount-access-hidden-wait-restored",
     "driver/fsring-fsd/src/volume.rs",
     "    let retained = RetainedAccessGuard::new(access);\n",
     "    let retained = RetainedAccessGuard::new(access);\n"
     "    unsafe { crate::lifecycle::wait_joiners_drained(registry, locator) };\n"),
    ("native-mount-retained-run-made-conditional",
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
     "                vdo: target,\n"
     "                vpb: Some(vpb_owner),\n"
     "                mounted: None,\n"
     "                vcb_storage: None,\n"
     "                initialized_vcb: None,\n"
     "                publication: None,\n"
     "                owner_published: false,\n"
     "                access,\n"
     "                locator,\n"
     "                state: root,\n"
     "                identity,\n"
     "                vpb_held: false,\n"
     "                vpb_irql: 0,\n"
     "                reference: None,\n"
     "            };\n"
     "            // SAFETY: PASSIVE_LEVEL mount thread; the context owns everything the\n"
     "            // transaction acquires. `run` retains the access guard through either\n"
     "            // the commit or rollback suffix.\n"
     "            status = unsafe {\n"
     "                drive_mount(\n"
     "                    &mut context,\n"
     "                    device,\n"
     "                    adapter::NativeVolumePlan::mount(progress),\n"
     "                )\n"
     "            };\n"
     "        });\n"
     "    }\n"),
    ("audit-lifetime-unparsed-lock-site-passes",
     "driver/scripts/audit_c4_lifetime.py",
     "    if len(acquisitions) != raw_count and not drain_match:\n",
     "    if False:\n"),
    ("audit-lifetime-missing-ring-drop-passes",
     "driver/scripts/audit_c4_lifetime.py",
     "        if drop_offset is None:\n"
     "            findings.append(\n"
     "                \"%s: `%s` has no explicit drop before its lexical scope ends\"\n"
     "                % (rel, guard)\n"
     "            )\n"
     "            continue",
     "        if drop_offset is None:\n"
     "            continue"),
    ("audit-lifetime-ring-scope-call-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if transition_end is None:\n"
     "            findings.append(\n"
     "                \"%s: `%s` live scope is outside the closed transition grammar\"\n"
     "                % (rel, guard)\n"
     "            )\n"
     "            continue",
     "        if transition_end is None:\n"
     "            continue"),
    ("audit-lifetime-nested-drop-accepted",
     "driver/scripts/audit_c4_lifetime.py",
     "    drop = re.match(pattern, text[start:end])\n",
     "    drop = re.search(pattern, text[start:end])\n"),
    ("audit-lifetime-shadowable-drop-accepted",
     "driver/scripts/audit_c4_lifetime.py",
     "        r\"\\s*(?P<drop>crate::lifecycle::NativeRingGuard::release\\s*\\(\\s*\"\n",
     "        r\"\\s*(?P<drop>(?:crate::lifecycle::NativeRingGuard::release|::core::mem::drop)\\s*\\(\\s*\"\n"),
    ("audit-lifetime-consuming-helper-body-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if raw_release_count != 1 or len(release_bodies) != 1 or release_bodies[0].strip():\n",
     "        if False:\n"),
    ("audit-lifetime-ring-drop-body-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if (\n"
     "            raw_drop_count != 1\n"
     "            or len(drop_bodies) != 1\n"
     "            or not ring_drop_body_is_closed(drop_bodies[0])\n"
     "        ):\n",
     "        if False:\n"),
    ("audit-lifetime-missing-carriers-not-findings",
     "driver/scripts/audit_c4_lifetime.py",
     "    findings.extend(\n"
     "        \"carrier `%s` was not found in the audited roots\" % carrier\n"
     "        for carrier in missing\n"
     "    )",
     "    if False:\n"
     "        findings.extend(missing)"),
    ("audit-lifetime-native-contract-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if evidence is not None:\n"
     "            evidence.append(\"%s:%s\" % (rel, label))\n"
     "        if not condition:\n"
     "            findings.append(\"%s: %s\" % (rel, detail))",
     "        if evidence is not None:\n"
     "            evidence.append(\"%s:%s\" % (rel, label))\n"
     "        if False:\n"
     "            findings.append(\"%s: %s\" % (rel, detail))"),
    ("audit-lifetime-production-summary-omitted",
     "driver/scripts/audit_c4_lifetime.py",
     "    if args.production_check:\n"
     "        checks = sum(\n"
     "            1 for label in evidence\n"
     "            if label.split(\":\", 1)[0] in COUNTED_EVIDENCE_FILES\n"
     "        )",
     "    if False:\n"
     "        checks = 0"),
    ("audit-lifetime-missing-native-owner-not-finding",
     "driver/scripts/audit_c4_lifetime.py",
     "    findings.extend(\n"
     "        \"native owner file `%s` was not found in the audited roots\" % rel\n"
     "        for rel in sorted(NATIVE_OWNER_FILES - native_files_seen)\n"
     "    )",
     "    if False:\n"
     "        findings.extend(NATIVE_OWNER_FILES - native_files_seen)"),
    ("audit-lifetime-native-contract-attribute-rejection-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    if (rel in NATIVE_OWNER_FILES or native_contract_shape) and has_native_contract_attribute(text):\n"
     "        findings.append(\"%s: a native lifetime contract may not be rewritten by an attribute\" % rel)",
     "    if False:\n"
     "        findings.append(\"native contract attribute ignored\")"),
    ("audit-lifetime-carrier-attribute-rejection-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    if has_carrier_attribute(text):\n"
     "        findings.append(\"%s: a locator-only carrier may not be rewritten by an attribute\" % rel)",
     "    if False:\n"
     "        findings.append(\"carrier attribute ignored\")"),
    ("audit-lifetime-access-guard-signature-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if normalized != [\n"
     "            \"pub(crate)constfnlocator(&self)->SessionLocator\",",
     "        if False and normalized != [\n"
     "            \"pub(crate)constfnlocator(&self)->SessionLocator\","),
    ("audit-lifetime-ring-slot-signature-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if len(ring_slot_impls) != 1 or normalized != [\n"
     "            \"fnnew(ring_index:u32)->Self\",",
     "        if False and len(ring_slot_impls) != 1 or False and normalized != [\n"
     "            \"fnnew(ring_index:u32)->Self\","),
    ("audit-lifetime-ring-private-census-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    if rel in NATIVE_OWNER_FILES or any(observed_private):\n"
     "        require(\n"
     "            observed_private == expected_private,",
     "    if False:\n"
     "        require(\n"
     "            observed_private == expected_private,"),
    ("audit-lifetime-ring-guard-signature-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if len(ring_impls) != 1 or normalized != [\n"
     "            \"pub(crate)constfnring_index(&self)->u32\",",
     "        if False and len(ring_impls) != 1 or False and normalized != [\n"
     "            \"pub(crate)constfnring_index(&self)->u32\","),
    ("audit-lifetime-free-api-signature-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            if compact.startswith(\"pub(crate)\") and compact not in allowed_free_headers:\n",
     "            if False:\n"),
    ("audit-lifetime-address-alias-resolution-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    return shaped\n\n\nclass LifetimeAuditError",
     "    return set()\n\n\nclass LifetimeAuditError"),
    ("audit-lifetime-imported-pointer-alias-resolution-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    shaped = {\n"
     "        match.group(1)\n"
     "        for match in re.finditer(\n"
     "            r\"\\buse\\s+[^;]*\\b(?:NonNull|AtomicPtr)\\s+as\\s+([A-Za-z_]\\w*)\\s*;\",\n"
     "            text,\n"
     "        )\n"
     "    }",
     "    shaped = set()"),
    ("audit-lifetime-pointer-newtype-resolution-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    definitions.extend(\n"
     "        (match.group(1), match.group(2))\n"
     "        for match in re.finditer(\n"
     "            r\"\\bstruct\\s+([A-Za-z_]\\w*)(?:\\s*<[^;(){}]*>)?\\s*\\(([^;]*)\\)\\s*;\",\n"
     "            text,\n"
     "        )\n"
     "    )",
     "    if False:\n"
     "        definitions.extend(())"),
    ("audit-lifetime-pointer-enum-resolution-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    definitions.extend(\n"
     "        (name, body)\n"
     "        for name, body in enum_bodies(text)\n"
     "    )",
     "    if False:\n"
     "        definitions.extend(())"),
    ("audit-lifetime-qualified-return-resolution-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                r\"(?:::)?(?:[A-Za-z_]\\w*::)*([A-Za-z_]\\w*)\",\n"
     "                returned,",
     "                r\"([A-Za-z_]\\w*)\",\n"
     "                returned,"),
    ("audit-lifetime-volume-method-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if len(volume_impls) != 1 or normalized != [\n"
     "            \"pub(crate)unsafefnlocator_of(extension:*constSelf)->Option<SessionLocator>\",",
     "        if False and len(volume_impls) != 1 or False and normalized != [\n"
     "            \"pub(crate)unsafefnlocator_of(extension:*constSelf)->Option<SessionLocator>\","),
    ("audit-lifetime-volume-free-owner-scan-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        \"driver/fsring-fsd/src/volume.rs\",\n"
     "    }:\n"
     "        allowed_free_headers = {",
     "    }:\n"
     "        allowed_free_headers = {"),
    ("audit-lifetime-carrier-field-grammar-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                    if (\n"
     "                        expected_body is not None\n"
     "                        and re.sub(r\"\\s+\", \"\", body) != expected_body\n"
     "                    ):",
     "                    if False:"),
    ("audit-lifetime-resolver-body-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                resolver_body_is_closed(body),",
     "                True,"),
    ("audit-lifetime-process-scan-body-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                compact_scan == PROCESS_SCAN_BODY,\n"
     "                \"process-scan-body-closed\",",
     "                True,\n"
     "                \"process-scan-body-closed\","),
    ("audit-lifetime-resolver-acquire-predicate-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                and \"ifacquired==0{pending.refused(ResolveRejection::RundownRefused)}\"\n"
     "                \"else{rundown=Some(target);pending.succeeded()}\" in compact,",
     "                and True,"),
    ("audit-lifetime-vdo-reader-predicate-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            and reader\n"
     "            == \"ifextension.is_null(){returnNone;}letstate=unsafe{(*extension)\"",
     "            and True\n"
     "            and \"ifextension.is_null(){returnNone;}letstate=unsafe{(*extension)\""),
    ("audit-lifetime-attribute-association-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            attributes == \"#[unsafe(no_mangle)]\"\n"
     "            and re.match(\n"
     "                r\"pub\\s+unsafe\\s+extern\\s+fn\\s+fsring_dispatch_mount\\b\",",
     "            attributes == \"#[unsafe(no_mangle)]\"\n"
     "            and re.match(\n"
     "                r\".*\","),
    ("audit-lifetime-free-projection-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            if (\n"
     "                address_shaped\n"
     "                and compact not in allowed_free_headers\n"
     "                and (name, returned) not in allowed_raw_free\n"
     "            ):\n"
     "                findings.append(\n"
     "                    \"%s: free function `%s` exposes native shell/ring address authority\"\n"
     "                    % (rel, name)\n"
     "                )",
     "            if False:\n"
     "                findings.append(\"free projection ignored\")"),
    ("audit-lifetime-native-item-namespace-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            declarations == NATIVE_TYPE_DECLARATIONS[rel]\n"
     "            and use_aliases == NATIVE_USE_ALIASES[rel]\n"
     "            and not extern_crates\n"
     "            and exports == NATIVE_CRATE_EXPORTS[rel],",
     "            True,"),
    ("audit-lifetime-protected-impl-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            protected_impls == PROTECTED_IMPL_HEADERS[rel],\n"
     "            \"native-protected-impl-roster-closed\",",
     "            True,\n"
     "            \"native-protected-impl-roster-closed\","),
    ("audit-lifetime-affine-owner-method-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                owner_methods_closed,\n"
     "                \"native-affine-owner-methods-closed\",",
     "                True,\n"
     "                \"native-affine-owner-methods-closed\","),
    ("audit-lifetime-protected-macro-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            not has_item_macro,\n"
     "            \"native-protected-impls-macro-free\",",
     "            True,\n"
     "            \"native-protected-impls-macro-free\","),
    ("audit-lifetime-access-live-scope-roster-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            access_scope_closed,\n"
     "            \"native-access-live-scope-closed\",",
     "            True,\n"
     "            \"native-access-live-scope-closed\","),
    ("audit-lifetime-nested-return-pointer-shape-open",
     "driver/scripts/audit_c4_lifetime.py",
     "                re.search(r\"(?:\\*mut|\\*const|&|\\bNonNull<|\\bAtomicPtr<)\", returned) is not None",
     "                returned.startswith((\"*mut\", \"*const\", \"&\", \"NonNull<\", \"AtomicPtr<\"))"),
    ("audit-lifetime-global-resolve-census-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        findings.extend(fsd_resolve_census_findings(fsd_sources))",
     "        findings.extend(())"),
    ("audit-lifetime-native-capability-census-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        findings.extend(fsd_native_capability_census_findings(fsd_sources))",
     "        findings.extend(())"),
    ("audit-lifetime-registry-projection-census-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if (\n"
     "            tuple(observed_owners) != expected_owners\n"
     "            or observed_tokens != expected_tokens\n"
     "            or observed_closed_bodies != expected_bodies\n"
     "        ):",
     "        if False:"),
    ("audit-lifetime-registry-projection-body-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            or observed_closed_bodies != expected_bodies",
     "            or False"),
    ("audit-lifetime-terminal-winner-body-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    if (\n"
     "        len(terminal_winners) != 1\n"
     "        or _task12_digest(re.sub(r\"\\s+\", \"\", terminal_winners[0]))\n"
     "        != FENCE_TERMINAL_WINNER_DIGEST\n"
     "    ):",
     "    if False:"),
    ("audit-lifetime-checkpoint-owner-body-open",
     "driver/scripts/audit_c4_lifetime.py",
     "    if (\n"
     "        len(checkpoint_teardowns) != 1\n"
     "        or _task12_digest(re.sub(r\"\\s+\", \"\", checkpoint_teardowns[0]))\n"
     "        != \"50899e224b92fd942cc597dc69ab8f79598b64cf3936eeb35b054f930725f47c\"\n"
     "    ):",
     "    if False:"),
    ("audit-lifetime-terminal-owner-split-census-open",
     "driver/scripts/audit_c4_lifetime.py",
     "        if re.search(\n"
     "            r\"\\bwork\\s*:\\s*(?:crate\\s*::\\s*lifecycle\\s*::\\s*)?TerminalWork\\b\"",
     "        if False and re.search(\n"
     "            r\"\\bwork\\s*:\\s*(?:crate\\s*::\\s*lifecycle\\s*::\\s*)?TerminalWork\\b\""),
    ("audit-lifetime-resolve-census-raw-root-gating-restored",
     "driver/scripts/audit_c4_lifetime.py",
     "    enforce_fsd_resolve_census = (\n"
     "        native_files_seen is not None and \"driver/fsring-fsd/src\" in canonical_roots\n"
     "    )",
     "    enforce_fsd_resolve_census = (\n"
     "        native_files_seen is not None and \"driver/fsring-fsd/src\" in source_roots\n"
     "    )"),
    ("audit-lifetime-production-root-set-open",
     "driver/scripts/audit_c4_lifetime.py",
     "            if len(production_roots) != 2 or set(production_roots) != expected_roots:\n"
     "                raise LifetimeAuditError(\n"
     "                    \"production-check requires the exact core/fsd source-root identities\"\n"
     "                )",
     "            if False:\n"
     "                raise LifetimeAuditError(\"production root set ignored\")"),
    # The Task 12 probe wave runs concurrently, so its 119 verdicts arrive
    # through a queue. This plants the failure that queue makes possible and
    # nothing else can see: the jobs are cleared instead of graded, so nothing
    # is left waiting, no probe reports a finding, and the summary still says
    # PASS -- 119 whole-tree probes measuring nothing while reading as covered.
    ("audit-lifetime-task12-wave-cleared-without-grading",
     "driver/scripts/audit_c4_lifetime.py",
     "    flush_task12_mutations()\n",
     "    del task12_jobs[:]\n"),
    # The attach-scratch call roster stops comparing anything. Its own planted
    # probe then reports no finding, so the self-test that ships with the
    # auditor fails -- which is the point: a rule nobody can neuter silently.
    ("audit-lifetime-attach-scratch-roster-neutered",
     "driver/scripts/audit_c4_lifetime.py",
     "        tuple(observed_calls) == tuple(ATTACH_SCRATCH_CALL_ROSTER),\n",
     "        True,\n"),
    # The guard no longer removes the branch -- a gate refusal is credited on
    # purpose now -- so the defect worth planting is crediting EVERY refresh
    # failure, which is what the old `if False:` amounted to.
    ("native-mutant-helper-refresh-failure-credited",
     "driver/scripts/audit_c4_native_mutant.py",
     "        if baseline_gate and MANIFEST_REFUSAL.search(refresh_log):\n"
     "            # With the baseline verified clean, a count that no longer matches\n"
     "            # can only have been changed by the mutation.\n"
     "            return \"CAUGHT\"\n"
     "        return \"HARNESS\"",
     "        if baseline_gate and MANIFEST_REFUSAL.search(refresh_log):\n"
     "            # With the baseline verified clean, a count that no longer matches\n"
     "            # can only have been changed by the mutation.\n"
     "            return \"CAUGHT\"\n"
     "        return \"CAUGHT\""),
    # The credit path this session added. Dropping the baseline guard makes a
    # drifted manifest indistinguishable from a detection -- the "caught by a
    # generic identity mismatch instead of by the rule it names" failure. It is
    # the newest branch here, so it is the one most in need of a watcher.
    ("native-mutant-helper-manifest-credit-drops-its-baseline-guard",
     "driver/scripts/audit_c4_native_mutant.py",
     "        if baseline_gate and MANIFEST_REFUSAL.search(refresh_log):\n",
     "        if MANIFEST_REFUSAL.search(refresh_log):\n"),
    # The other direction. Without it, deleting the credit branch would leave
    # the suite green and the graph-gate-blinded family silently blind again.
    ("native-mutant-helper-gate-refusal-not-credited",
     "driver/scripts/audit_c4_native_mutant.py",
     "        if GATE_REFUSAL.search(refresh_log):\n"
     "            return \"CAUGHT\"",
     "        if GATE_REFUSAL.search(refresh_log):\n"
     "            return \"HARNESS\""),
    ("native-mutant-helper-compile-failure-credited",
     "driver/scripts/audit_c4_native_mutant.py",
     "        return \"HARNESS\"\n"
     "    if compile_code != 0:\n"
     "        return \"NOCOMPILE\"",
     "        return \"HARNESS\"\n"
     "    if False:\n"
     "        return \"NOCOMPILE\""),
    ("native-mutant-helper-missing-evidence-credited",
     "driver/scripts/audit_c4_native_mutant.py",
     "    if audit_checks < 20:\n"
     "        return \"HARNESS\"",
     "    if False:\n"
     "        return \"HARNESS\""),
    ("native-mutant-helper-audit-failure-survives",
     "driver/scripts/audit_c4_native_mutant.py",
     "    if audit_code == 1:\n"
     "        return \"CAUGHT\"",
     "    if False:\n"
     "        return \"CAUGHT\""),
    ("native-mutant-helper-nocompile-summary-short",
     "driver/scripts/audit_c4_native_mutant.py",
     "        return \"NOCOMPILE\", 3, \"native compile failed:\\n%s\" % compile_log",
     "        return \"NOCOMPILE\", 2, \"native compile failed:\\n%s\" % compile_log"),
    # The auditors themselves. Their only kill signal is their own --self-test,
    # so an operator here is the measurement that a fixture drives the rule it
    # claims to drive. Anchors are Python: indentation is significant and none
    # of them may be retyped by hand.
    # Anchored on `frame_bound`, not `manifest["maxFrameBytes"]`: slice C4.2
    # routed this comparison through `root_bounds()` so an expansion root is
    # judged by its own declared bound, and the anchor has to track wherever
    # the comparison itself now lives or it stops matching the source at all.
    ("audit-frame-bound-never-fires", "driver/scripts/audit_c4_stack.py",
     "        elif frame > frame_bound:",
     "        elif False:"),
    ("audit-root-absence-not-reported", "driver/scripts/audit_c4_stack.py",
     "        if not rows:\n"
     "            findings.append(f\"root {root} is absent from the link map\")\n"
     "            continue",
     "        if not rows:\n"
     "            continue"),
    ("audit-imports-missing-rows-never-raise", "driver/scripts/audit_c4_imports.py",
     "def compare_two_way(kind: str, expected: list, observed: list) -> None:\n"
     "    missing = sorted(set(expected) - set(observed))\n"
     "    extra = sorted(set(observed) - set(expected))\n"
     "    if missing:",
     "def compare_two_way(kind: str, expected: list, observed: list) -> None:\n"
     "    missing = sorted(set(expected) - set(observed))\n"
     "    extra = sorted(set(observed) - set(expected))\n"
     "    if False:"),
    ("audit-imports-extra-rows-never-raise", "driver/scripts/audit_c4_imports.py",
     "    if extra:",
     "    if False:"),
    ("audit-imports-duplicate-never-raises", "driver/scripts/audit_c4_imports.py",
     "    if len(set(observed)) != len(observed):",
     "    if False:"),
    ("audit-imports-root-absence-skipped", "driver/scripts/audit_c4_imports.py",
     "        if root not in symbols:\n"
     "            raise AuditError(f\"wrapper root {root} is absent from the link map\")",
     "        if root not in symbols:\n"
     "            continue"),
    ("audit-imports-ambiguous-root-skipped", "driver/scripts/audit_c4_imports.py",
     "        if root in header[\"duplicates\"]:",
     "        if False:"),
    ("audit-imports-root-member-unchecked", "driver/scripts/audit_c4_imports.py",
     "        if symbols[root][1] != wrapper[\"rootMember\"]:",
     "        if False:"),
    # This one reproduces the exact defect the G1 comment records: filtering
    # the observed side down to the declared side makes the comparison vacuous
    # while still reading as two-way.
    ("audit-imports-reachable-members-vacuous", "driver/scripts/audit_c4_imports.py",
     "        compare_two_way(f\"{root} reachable members\",\n"
     "                        wrapper[\"reachableMembers\"], observed_members)",
     "        compare_two_way(f\"{root} reachable members\",\n"
     "                        wrapper[\"reachableMembers\"], wrapper[\"reachableMembers\"])"),
    ("audit-imports-edge-ids-unchecked", "driver/scripts/audit_c4_imports.py",
     "            if edge_id not in edge_ids:",
     "            if False:"),
    ("audit-imports-downstream-presence-unchecked", "driver/scripts/audit_c4_imports.py",
     "            if entry not in observed:",
     "            if False:"),
    ("audit-identity-machine-unchecked", "driver/scripts/audit_c4_imports.py",
     "    if not any(token.lower() in seen for token in expected):",
     "    if False:"),
    ("audit-identity-map-timestamp-unchecked", "driver/scripts/audit_c4_imports.py",
     "    if header[\"timestamp\"] != pe[\"timestamp\"]:",
     "    if False:"),
    ("audit-identity-map-base-unchecked", "driver/scripts/audit_c4_imports.py",
     "    if header[\"base\"] != pe[\"base\"]:",
     "    if False:"),
    ("audit-identity-pdb-name-unchecked", "driver/scripts/audit_c4_imports.py",
     "    if os.path.basename(view[\"name\"]).lower() != os.path.basename(pdb_name).lower():",
     "    if False:"),
    ("audit-identity-pdb-age-unchecked", "driver/scripts/audit_c4_imports.py",
     "    if view[\"age\"] is not None and str(pdb_age) != str(view[\"age\"]):",
     "    if False:"),
    # Deleting this one restores the defect 16db735 closed: another leg's
    # fsring_fsd.pdb accepted on its basename alone.
    ("audit-identity-guid-search-deleted", "driver/scripts/audit_c4_imports.py",
     "    if packed not in image_bytes:",
     "    if False:"),
    ("audit-alias-absent-canonical-skipped", "driver/scripts/audit_c4_stack.py",
     "        if canonical not in symbols:\n"
     "            findings.append(f\"alias canonical {canonical} is absent from the map\")\n"
     "            continue",
     "        if canonical not in symbols:\n"
     "            continue"),
    ("audit-alias-canonical-member-unchecked", "driver/scripts/audit_c4_stack.py",
     "        if canonical_member != alias[\"mapMember\"]:",
     "        if False:"),
    ("audit-alias-absent-alias-skipped", "driver/scripts/audit_c4_stack.py",
     "            if name not in symbols:\n"
     "                findings.append(f\"declared alias {name} is absent from the map\")\n"
     "                continue",
     "            if name not in symbols:\n"
     "                continue"),
    ("audit-alias-address-and-member-unchecked", "driver/scripts/audit_c4_stack.py",
     "            if address != canonical_address or member != canonical_member:",
     "            if False:"),
    ("audit-fold-grouping-vacuous", "driver/scripts/audit_c4_stack.py",
     "        if len(names) < 2:",
     "        if True:"),
    ("audit-edge-absent-symbol-skipped", "driver/scripts/audit_c4_stack.py",
     "            if name not in symbols:\n"
     "                findings.append(f\"indirect edge {edge['id']} names absent symbol {name}\")",
     "            if name not in symbols:\n"
     "                pass"),
    ("audit-edge-closed-target-unchecked", "driver/scripts/audit_c4_stack.py",
     "                if target[\"kind\"] == \"internal\" and target[\"symbol\"] not in symbols:",
     "                if False:"),
    ("audit-edge-storage-may-be-a-root", "driver/scripts/audit_c4_stack.py",
     "        if edge[\"storage\"] in declared_roots:",
     "        if False:"),
    # Presence of an edge is not the same as walking it. This operator leaves
    # every presence check intact and only stops charging the resolved call,
    # which is the failure a presence check cannot see.
    ("audit-edge-never-charged-to-chain", "driver/scripts/audit_c4_stack.py",
     "                indirect.setdefault(edge[\"caller\"], set()).add(target[\"symbol\"])",
     "                pass"),
    # The stack auditor had no identity binding of any kind: a stale or foreign
    # map was accepted, and every number below it was then about another build.
    ("audit-map-machine-unbound", "driver/scripts/audit_c4_stack.py",
     "    if not any(token.lower() in seen for token in expected):",
     "    if False:"),
    ("audit-map-timestamp-unbound", "driver/scripts/audit_c4_stack.py",
     "    elif int(header[\"timestamp\"], 16) != pe[\"timestamp\"]:",
     "    elif False:"),
    ("audit-map-base-unbound", "driver/scripts/audit_c4_stack.py",
     "    elif header[\"base\"] != pe[\"base\"]:",
     "    elif False:"),
    # All three manifests carry identical import sets, so this comparison is
    # the only thing separating the win10-x64 and win7-x64 legs.
    ("audit-imports-profile-unbound", "driver/scripts/audit_c4_imports.py",
     "    if manifest[\"profile\"] != profile:",
     "    if False:"),
    # Same drift, same fix: `chain_bound` is the per-root bound `root_bounds()`
    # resolves, not the manifest global.
    ("audit-chain-bound-never-fires", "driver/scripts/audit_c4_stack.py",
     "        total, path = chain_bytes(root, frames, calls, indirect)\n"
     "        if total > chain_bound:",
     "        total, path = chain_bytes(root, frames, calls, indirect)\n"
     "        if False:"),
    ("audit-root-two-addresses-unchecked", "driver/scripts/audit_c4_stack.py",
     "        if len({address for address, _ in rows}) != 1:",
     "        if False:"),
    ("audit-root-may-be-an-alias", "driver/scripts/audit_c4_stack.py",
     "        if root in alias_names:",
     "        if False:"),
    # The three frame-measurement corrections. Each of these mutants restores
    # one of the defects this slice found.
    ("audit-prologue-drops-its-pushes", "driver/scripts/audit_c4_stack.py",
     "            if X64_PUSH.search(line):",
     "            if False:"),
    ("audit-chkstk-probe-not-charged", "driver/scripts/audit_c4_stack.py",
     "                if owner_at(code, int(target.group(1), 16)) == \"__chkstk\":",
     "                if False:"),
    ("audit-unwind-alloclarge-read-as-bytes", "driver/scripts/audit_c4_stack.py",
     "                total += slots * 8",
     "                total += slots"),
    ("audit-unwind-arm-preindex-not-charged", "driver/scripts/audit_c4_stack.py",
     "            total += int(pre.group(1))",
     "            total += 0"),
    # The guards that make a source going blind loud. The unwind reader
    # contributed zero on every leg for the whole of slice C4 and nothing
    # noticed, because nothing counted what it resolved.
    ("audit-unwind-coverage-floor-never-fires", "driver/scripts/audit_c4_stack.py",
     "    if len(unwind) < census[\"minUnwindFunctions\"]:",
     "    if False:"),
    ("audit-prologue-coverage-floor-never-fires", "driver/scripts/audit_c4_stack.py",
     "    if len(prologue) < census[\"minPrologueFunctions\"]:",
     "    if False:"),
    # Two bounds since the census was split by the SHAPE of each
    # disagreement: `declined` is the linked-library floor the prologue
    # reader will not follow at all, `truncated` is a prologue it followed
    # and stopped short of. One mutant each, because a single mutant would
    # leave whichever bound it did not name still measuring and still green.
    ("audit-frame-source-declined-uncounted", "driver/scripts/audit_c4_stack.py",
     "    if len(declined) > census[\"maxDeclinedDisagreements\"]:",
     "    if False:"),
    ("audit-frame-source-truncated-uncounted", "driver/scripts/audit_c4_stack.py",
     "    if len(truncated) > census[\"maxTruncatedDisagreements\"]:",
     "    if False:"),
    # The direction rule is what the count could not do: it refused eight ARM64
    # records the census had accepted, and they turned out to be a fourth
    # measurement defect.
    ("audit-over-counting-direction-allowed", "driver/scripts/audit_c4_stack.py",
     "    over_counting = [name for name in disagree if prologue[name] > unwind[name]]",
     "    over_counting = []"),
    ("audit-packed-unwind-frame-size-ignored", "driver/scripts/audit_c4_stack.py",
     "            total = int(packed.group(1))",
     "            total = 0"),
    # Slice C4.2. The expanded-stack contract and the audit that keeps the
    # expansion a boundary rather than a comment.
    ("stackexpand-unwritten-slot-accepted",
     "driver/fsring-core/src/adapter/stackexpand.rs",
     "        (true, None) => Err(ExpandFault::SlotUnwritten),",
     "        (true, Some(value)) => Ok(value),\n"
     "        (true, None) => Err(ExpandFault::Refused),"),
    ("stackexpand-refusal-trusts-the-slot",
     "driver/fsring-core/src/adapter/stackexpand.rs",
     "        (false, _) => Err(ExpandFault::Refused),",
     "        (false, None) => Err(ExpandFault::Refused),\n"
     "        (false, Some(value)) => Ok(value),"),
    ("audit-expansion-frame-bound-global",
     "driver/scripts/audit_c4_stack.py",
     "    entry = expansions.get(root)\n"
     "    if entry is None:\n"
     "        return manifest[\"maxFrameBytes\"], manifest[\"maxChainBytes\"]",
     "    entry = None\n"
     "    if entry is None:\n"
     "        return manifest[\"maxFrameBytes\"], manifest[\"maxChainBytes\"]"),
    ("audit-expansion-direct-call-allowed",
     "driver/scripts/audit_c4_stack.py",
     "        if callers:",
     "        if False:"),
    ("audit-expansion-ddi-ceiling-ignored",
     "driver/scripts/audit_c4_stack.py",
     "        if entry[\"expansionBytes\"] > MAXIMUM_EXPANSION_SIZE:",
     "        if False:"),
    ("audit-expansion-bound-may-exceed-request",
     "driver/scripts/audit_c4_stack.py",
     "            if entry[key] > entry[\"expansionBytes\"]:",
     "            if False:"),
    ("audit-expansion-root-need-not-be-declared",
     "driver/scripts/audit_c4_stack.py",
     "        if entry[\"root\"] not in declared_roots:",
     "        if False:"),
    ("audit-expansion-source-constant-unread",
     "driver/scripts/audit_c4_stack.py",
     "        if requested != entry[\"expansionBytes\"]:",
     "        if False:"),
    ("audit-expansion-ddi-undeclared-import",
     "driver/scripts/audit_c4_stack.py",
     "        if entry[\"ddi\"] not in declared:",
     "        if False:"),
    # Decision 9, added by Task 7b after a reviewer defeated the first version
    # of this check with a decoy comment. The exact-match condition is the one
    # that has to stay killable: containment is what let the decoy through.
    # Not `if ...: False`. Since attribution became per-DDI the branch
    # below indexes `passed[root]`, so switching the guard off leaves
    # `root` as `None` and raises rather than mis-passing -- neither CAUGHT
    # nor SURVIVED. Mutating the LOOKUP makes every site resolve to some
    # declared root, which is what "argument unchecked" actually means.
    ("audit-expansion-callout-argument-unchecked",
     "driver/scripts/audit_c4_stack.py",
     "                root = wanted.get(normalized)",
     "                root = next(iter(wanted.values()))"),
    ("audit-expansion-unparsable-argument-passes",
     "driver/scripts/audit_c4_stack.py",
     "                if argument is None:",
     "                if False:"),
    ("audit-expansion-callsite-absence-ignored",
     "driver/scripts/audit_c4_stack.py",
     "            if passed[root] == 0:",
     "            if False:"),
    # Decision 8: the boundary is not just declared, the caller must actually
    # reach the DDI. Task 7 implemented both halves of this check; the final
    # whole-branch review found the test was substring containment
    # (`entry["ddi"] in name for name in reached`) rather than exact
    # membership, and it was fixed in the same line this anchor now tracks.
    ("audit-expansion-caller-edge-unchecked",
     "driver/scripts/audit_c4_stack.py",
     "        if entry[\"ddi\"] not in reached:",
     "        if False:"),
    # CRITICAL 1, final whole-branch review: decision 9 (the source-text
    # check above) cannot ENUMERATE its call sites - a `use ... as` alias, a
    # parenthesised fully-qualified path call, or a second site under a path
    # the source walk skips all reach the real DDI without ever matching
    # `needle`. This decision closes it on the BINARY, where spelling is
    # irrelevant: the set of image functions that call a declared DDI must
    # equal exactly the declared `expansionRoots[].caller` set.
    ("audit-expansion-undeclared-caller-unchecked",
     "driver/scripts/audit_c4_stack.py",
     "        for extra in sorted(observed - declared_set):",
     "        for extra in sorted(set()):"),
    ("audit-expansion-declared-caller-unverified",
     "driver/scripts/audit_c4_stack.py",
     "        for missing in sorted(declared_set - observed):",
     "        for missing in sorted(set()):"),
    # IMPORTANT 2, final whole-branch review: `"expansionRoots": []` used to
    # load cleanly and turn every decision above into a no-op while the image
    # still called the DDI - the exact C4.1a hole, restorable by a two-line
    # manifest edit. `EXPANSION_DDIS` lives in this script, not the manifest,
    # so deleting the manifest row cannot un-arm this check.
    ("audit-expansion-ddi-without-declared-root-unchecked",
     "driver/scripts/audit_c4_stack.py",
     "    for ddi in EXPANSION_DDIS:\n"
     "        if (any(ddi in callees for callees in calls.values())\n"
     "                and ddi not in declared_ddis):",
     "    for ddi in EXPANSION_DDIS:\n"
     "        if False:"),
    # IMPORTANT 2: an `expansionRoots` row missing e.g. `expansionBytes` used
    # to raise a bare `KeyError` out of `analyze` rather than a named FAIL
    # from `load_roots` - the same gap the other four collection keys
    # (`indirectEdges`, `aliases`, `frameSources`, and the top-level key set
    # itself) were already closed for.
    ("audit-expansion-root-key-set-unchecked",
     "driver/scripts/audit_c4_stack.py",
     "    for entry in manifest[\"expansionRoots\"]:\n"
     "        if set(entry) != _REQUIRED_EXPANSION_KEYS:\n"
     "            raise AuditError(\"an expansion root row has a missing or extra key\")",
     "    for entry in manifest[\"expansionRoots\"]:\n"
     "        pass"),
    # FINAL DISCLOSURE CORRECTIONS residual: `load_imports` (44efa8e) raises a
    # named FAIL for a well-formed JSON object with no "direct" key, instead
    # of leaving a bare `KeyError` for `expansion_import_findings` to hit.
    # Structural, like the `audit-expansion-root-key-set-unchecked` mutant
    # above and for the same reason - it had a self-test fixture ("an imports
    # file with no direct key fails closed") but no named operator proving it
    # killable until now.
    ("audit-imports-missing-direct-key-unchecked",
     "driver/scripts/audit_c4_stack.py",
     "    if not isinstance(parsed, dict) or \"direct\" not in parsed:",
     "    if False:"),
    # The split that lets a frame-pointer record excuse an over-count must not
    # become a blanket excuse. Inverting the membership test makes the strict
    # arm fire for the excused functions and stay silent for the ones it exists
    # to refuse, which is exactly the blanket the census prevents.
    ("stack-frame-pointer-excuses-every-over-count",
     "driver/scripts/audit_c4_stack.py",
     "    invented = [name for name in over_counting if name not in framepointers]",
     "    invented = [name for name in over_counting if name in framepointers]"),
    # -- Task 9 of the C4 recovery: the counted terminal claim ----------------
    #
    # Two guards in `preflight_terminal_claim` are deliberately NOT operators
    # here, and this is the record of why rather than a silent omission. The
    # slot-identity comparison and the rendezvous-locator comparison each pin
    # the same exact generation, so deleting either one leaves the other
    # answering `WrongLocator` for every input a test can build: they are
    # equivalent mutants under the current cross-product, not gaps. Deleting
    # *both* is a two-anchor mutation this suite does not express.
    ("terminal-claim-admits-a-second-live-claimant",
     "driver/fsring-core/src/session.rs",
     "            PrivateTerminalRendezvousState::Open { admitted: 0, .. } => {\n"
     "                self.state = PrivateTerminalRendezvousState::Open {\n"
     "                    locator,\n"
     "                    admitted: 1,\n"
     "                };\n",
     "            PrivateTerminalRendezvousState::Open { admitted: 0 | 1, .. } => {\n"
     "                self.state = PrivateTerminalRendezvousState::Open {\n"
     "                    locator,\n"
     "                    admitted: 1,\n"
     "                };\n"),
    ("terminal-claim-leaves-the-core-slot-live",
     "driver/fsring-core/src/session.rs",
     "        slot.state = RegistrySlotState::Removing;\n"
     "        slot.fence_done = false;\n"
     "        TerminalSessionRef {\n",
     "        slot.fence_done = false;\n"
     "        TerminalSessionRef {\n"),
    ("terminal-claim-leaves-the-binding-active",
     "driver/fsring-core/src/session.rs",
     "                commit_prepared_live_binding_claim(close, binding);\n",
     "                let _ = (&close, &binding);\n"),
    ("prepared-claim-misreports-a-join-as-a-winner",
     "driver/fsring-core/src/session.rs",
     "            PreparedTerminalOutcome::Join => CoreTerminalClaimKind::Join,\n",
     "            PreparedTerminalOutcome::Join => CoreTerminalClaimKind::Winner,\n"),
    ("terminal-winner-runs-before-releasing-its-outer-rundown",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    pub const WINNER_STEPS: [TerminalRouteStep; 4] = [\n"
     "        TerminalRouteStep::ClaimUnderRegistryLock,\n"
     "        TerminalRouteStep::ReleaseOuterFileRundown,\n"
     "        TerminalRouteStep::RunTerminal,\n"
     "        TerminalRouteStep::AcknowledgeOutcome,\n"
     "    ];\n",
     "    pub const WINNER_STEPS: [TerminalRouteStep; 4] = [\n"
     "        TerminalRouteStep::ClaimUnderRegistryLock,\n"
     "        TerminalRouteStep::RunTerminal,\n"
     "        TerminalRouteStep::ReleaseOuterFileRundown,\n"
     "        TerminalRouteStep::AcknowledgeOutcome,\n"
     "    ];\n"),
    ("terminal-joiner-waits-before-releasing-its-outer-rundown",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    pub const JOIN_STEPS: [TerminalRouteStep; 4] = [\n"
     "        TerminalRouteStep::ClaimUnderRegistryLock,\n"
     "        TerminalRouteStep::ReleaseOuterFileRundown,\n"
     "        TerminalRouteStep::WaitTerminalOutcome,\n"
     "        TerminalRouteStep::AcknowledgeOutcome,\n"
     "    ];\n",
     "    pub const JOIN_STEPS: [TerminalRouteStep; 4] = [\n"
     "        TerminalRouteStep::ClaimUnderRegistryLock,\n"
     "        TerminalRouteStep::WaitTerminalOutcome,\n"
     "        TerminalRouteStep::ReleaseOuterFileRundown,\n"
     "        TerminalRouteStep::AcknowledgeOutcome,\n"
     "    ];\n"),
    ("process-scan-keeps-its-index-after-a-claim",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "            ProcessCallbackCell::Claim(action)\n"
     "            | ProcessCallbackCell::Join(action)\n",
     "            ProcessCallbackCell::Claim(action) => {\n"
     "                handle(&guard, action);\n"
     "                cursor = cursor.saturating_add(1);\n"
     "            }\n"
     "            ProcessCallbackCell::Join(action)\n"),
    ("terminal-wait-admits-one-released-short-guard",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "    if pre.outer_file_rundown_released\n"
     "        && pre.session_access_guard_released\n"
     "        && pre.registry_lock_released\n"
     "    {\n",
     "    if pre.outer_file_rundown_released\n"
     "        || pre.session_access_guard_released\n"
     "        || pre.registry_lock_released\n"
     "    {\n"),
    ("unload-returns-from-a-blocked-generation",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        TerminalArrivalSource::Unload => BlockedArrivalAction::BlockForever,\n",
     "        TerminalArrivalSource::Unload => BlockedArrivalAction::ReportInvalidDeviceState,\n"),
    ("late-cleanup-claims-instead-of-joining",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        CleanupBindingClaim::JoinLive(locator) => CleanupRoute::JoinTerminal(*locator),\n",
     "        CleanupBindingClaim::JoinLive(locator) => CleanupRoute::ClaimTerminal(*locator),\n"),
    # -- Tasks 22-24 of the C4 recovery: the R5 fence dispatch seam, the
    # consumer-recovery cursor and its four proofs, and the residual retry
    # lifecycle. Each was run by hand as a plant-and-restore sweep and
    # reported CAUGHT; folding them in is what makes the falsification
    # repeatable rather than a claim about one afternoon.
    ("fence-dispatch-answers-an-effect-with-another-method",
     "driver/fsring-core/src/adapter/fence.rs",
     "FenceEffect::RetireCredits => ops.retire_credits(),",
     "FenceEffect::RetireCredits => ops.release_consumers(),"),
    ("fence-dispatch-swallows-a-refusal",
     "driver/fsring-core/src/adapter/fence.rs",
     "FenceEffect::QueueInstalledWork => ops.queue_installed_work(),",
     "FenceEffect::QueueInstalledWork => {\n"
     "            let _ = ops.queue_installed_work();\n"
     "            Ok(())\n"
     "        }"),
    ("fence-dispatch-retries-a-native-effect",
     "driver/fsring-core/src/adapter/fence.rs",
     "FenceEffect::ReleaseCapturedProcess => ops.release_captured_process(),",
     "FenceEffect::ReleaseCapturedProcess => match ops.release_captured_process() {\n"
     "            Ok(()) => Ok(()),\n"
     "            Err(_) => ops.release_captured_process(),\n"
     "        },"),
    ("fence-dispatch-performs-two-operations-for-one-effect",
     "driver/fsring-core/src/adapter/fence.rs",
     "FenceEffect::ReleaseMdlsAndSystemView => ops.release_mdls_and_system_view(),",
     "FenceEffect::ReleaseMdlsAndSystemView => {\n"
     "            ops.release_captured_process()?;\n"
     "            ops.release_mdls_and_system_view()\n"
     "        }"),
    ("fence-dispatch-grows-a-default-success-arm",
     "driver/fsring-core/src/adapter/fence.rs",
     "        FenceEffect::DismountAndDeleteDevices => ops.dismount_and_delete_devices(),\n"
     "        FenceEffect::ReleaseTransientBacking => ops.release_transient_backing(),",
     "        _ => Ok(()),"),
    ("consumer-prefix-admits-a-skipped-ring",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if ring_index > self.high_water {\n"
     "            return Err((FenceError::NonIncreasingRing, token));\n"
     "        }",
     ""),
    ("consumer-prefix-admits-a-duplicate-ring",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if ring_index < self.high_water {\n"
     "            return Err((FenceError::DuplicateConsumer, token));\n"
     "        }",
     ""),
    ("consumer-drain-prepares-from-an-incomplete-set",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if !matches!(self.phase, ConsumerPrefixPhase::AcquiredComplete) {\n"
     "            return Err((FenceError::IncompleteConsumerSet, self));\n"
     "        }",
     ""),
    # Round 16's N1 repair added the `in_flight` clause to this condition, which
    # moved the anchor and made this mutant HARNESS -- caught by row
    # 13-mutation-c4-list, which is where an anchor that no longer matches
    # exactly once surfaces. The mutant's intent is unchanged: mint the proof
    # without checking anything.
    ("consumer-release-proof-minted-with-tokens-live",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if self.in_flight.is_none()\n"
     "            && self.release_remaining == 0\n"
     "            && matches!(self.phase, ConsumerPrefixPhase::ReleasedComplete)\n"
     "        {",
     "        if true {"),
    # The three guards round 16 added, one mutant each. A token between
    # `pop_for_release` and the native call is owned by neither the slab nor its
    # ring, and only the caller knows which; each of these puts back one of the
    # ways the cursor used to lose that distinction.
    ("consumer-pop-declares-the-release-over",
     "driver/fsring-core/src/adapter/fence.rs",
     "        self.phase = if index == 0 {\n"
     "            ConsumerPrefixPhase::ReleasingComplete\n"
     "        } else {\n"
     "            ConsumerPrefixPhase::ReleasingPartial\n"
     "        };",
     "        self.phase = if index == 0 {\n"
     "            ConsumerPrefixPhase::ReleasedComplete\n"
     "        } else if index == 1 {\n"
     "            ConsumerPrefixPhase::ReleasingComplete\n"
     "        } else {\n"
     "            ConsumerPrefixPhase::ReleasingPartial\n"
     "        };"),
    ("consumer-restore-refuses-the-last-ring",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if self.in_flight != Some(ring_index) {\n"
     "            return Err((FenceError::InvalidConsumerPhase, token));\n"
     "        }",
     "        if !matches!(\n"
     "            self.phase,\n"
     "            ConsumerPrefixPhase::ReleasingPartial | "
     "ConsumerPrefixPhase::ReleasingComplete\n"
     "        ) {\n"
     "            return Err((FenceError::InvalidConsumerPhase, token));\n"
     "        }"),
    ("consumer-park-abandons-a-token-in-flight",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if self.in_flight.is_some() {\n"
     "            return Err(FenceError::IncompleteConsumerSet);\n"
     "        }",
     ""),
    ("consumer-release-runs-in-acquisition-order",
     "driver/fsring-core/src/adapter/fence.rs",
     "        let Some(index) = self.release_remaining.checked_sub(1) else {",
     "        let index = self.high_water.saturating_sub(self.release_remaining);\n"
     "        let Some(index) = Some(index).filter(|_| self.release_remaining > 0) else {"),
    ("drain-proof-minted-on-a-refusal",
     "driver/fsring-core/src/adapter/fence.rs",
     "        Err(error) => Err((KernelFenceError::Native(error), prepared)),",
     "        Err(error) => {\n"
     "            let _ = error;\n"
     "            let PreparedConsumerDrain { prefix, .. } = prepared;\n"
     "            let set = prefix.set;\n"
     "            return Ok(DrainedConsumerPrefix {\n"
     "                prefix,\n"
     "                drained: DrainCompletedProof {\n"
     "                    set,\n"
     "                    authority: PrivateDrainCompletedAuthority(()),\n"
     "                },\n"
     "            });\n"
     "        }"),
    ("partial-acquisition-cannot-release-what-it-holds",
     "driver/fsring-core/src/adapter/fence.rs",
     "            ConsumerPrefixPhase::Acquiring\n"
     "            | ConsumerPrefixPhase::AcquiredComplete\n"
     "            | ConsumerPrefixPhase::ReleasedPartial => {}",
     "            ConsumerPrefixPhase::AcquiredComplete\n"
     "            | ConsumerPrefixPhase::ReleasedPartial => {}"),
    ("consumer-resume-forgets-what-it-still-holds",
     "driver/fsring-core/src/adapter/fence.rs",
     "        prefix.high_water = prefix.release_remaining;",
     "        prefix.high_water = 0;"),
    ("retry-backoff-never-saturates",
     "driver/fsring-core/src/adapter/fence.rs",
     "        let last = FENCE_RETRY_DELAY_MS.len().saturating_sub(1);\n"
     "        let index = if self.same_key_attempts as usize >= last {\n"
     "            last\n"
     "        } else {\n"
     "            self.same_key_attempts as usize\n"
     "        };",
     "        let index = self.same_key_attempts as usize % FENCE_RETRY_DELAY_MS.len();"),
    ("retry-progress-does-not-reset-the-backoff",
     "driver/fsring-core/src/adapter/fence.rs",
     "        self.same_key_attempts = if self.last_key == Some(key) {\n"
     "            self.same_key_attempts.saturating_add(1)\n"
     "        } else {\n"
     "            0\n"
     "        };",
     "        self.same_key_attempts = self.same_key_attempts.saturating_add(1);"),
    ("retry-due-time-is-absolute-not-relative",
     "driver/fsring-core/src/adapter/fence.rs",
     "    match (delay_ms as i64).checked_mul(10_000) {\n"
     "        Some(scaled) => scaled.checked_neg(),\n"
     "        None => None,\n"
     "    }",
     "    (delay_ms as i64).checked_mul(10_000)"),
    ("invariant-refusal-is-classified-transient",
     "driver/fsring-core/src/adapter/fence.rs",
     "            cause: PrivateFenceRetryCause::Invariant(reason),",
     "            cause: {\n"
     "                let _ = reason;\n"
     "                PrivateFenceRetryCause::TransientNative\n"
     "            },"),
    ("retry-lifecycle-accepts-a-foreign-binding",
     "driver/fsring-core/src/adapter/fence.rs",
     "        let refusal = if initial.lifecycle != self.id {\n"
     "            Some(LifecycleError::WrongState)\n"
     "        } else if !matches!(self.state, FenceRetryLifecycleState::Idle) {",
     "        let refusal = if !matches!(self.state, FenceRetryLifecycleState::Idle) {"),
    ("retry-lifecycle-accepts-a-foreign-delay-right",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if right.lifecycle != self.id || right.locator != self.locator {\n"
     "            return Err((LifecycleError::WrongLocator, right));\n"
     "        }\n"
     "        if !matches!(self.state, FenceRetryLifecycleState::DelayArmed) {",
     "        if !matches!(self.state, FenceRetryLifecycleState::DelayArmed) {"),
    ("retry-identity-exhaustion-reuses-an-identity",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if current == u64::MAX {\n"
     "            return Err(LifecycleError::GenerationExhausted);\n"
     "        }",
     "        if current == u64::MAX {\n"
     "            let Some(reused) = NonZeroU64::new(1) else {\n"
     "                return Err(LifecycleError::GenerationExhausted);\n"
     "            };\n"
     "            return Ok(FenceRetryLifecycleId(reused));\n"
     "        }"),
    ("retry-completion-never-reaches-idle",
     "driver/fsring-core/src/adapter/fence.rs",
     "        lifecycle.state = FenceRetryLifecycleState::Idle;\n"
     "        lifecycle.last_key = None;\n"
     "        lifecycle.same_key_attempts = 0;",
     "        lifecycle.last_key = None;\n"
     "        lifecycle.same_key_attempts = 0;"),
    ("initial-completion-mutates-the-lifecycle",
     "driver/fsring-core/src/adapter/fence.rs",
     "        debug_assert!(matches!(lifecycle.state, FenceRetryLifecycleState::Idle));",
     "        assert!(!matches!(lifecycle.state, FenceRetryLifecycleState::Idle));"),
    ("residual-accepts-a-foreign-branded-prefix",
     "driver/fsring-core/src/adapter/fence.rs",
     "            FenceRetryPoint::ReleaseConsumersThen { prefix, .. }\n"
     "            | FenceRetryPoint::ReacquireConsumersThen { prefix, .. } => {\n"
     "                if prefix.set_brand() != set {\n"
     "                    Some(FenceError::WrongRingSet)\n"
     "                } else {\n"
     "                    None\n"
     "                }\n"
     "            }",
     "            FenceRetryPoint::ReleaseConsumersThen { prefix, .. }\n"
     "            | FenceRetryPoint::ReacquireConsumersThen { prefix, .. } => {\n"
     "                let _ = prefix;\n"
     "                None\n"
     "            }"),
    ("join-route-projects-the-control-context",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        matches!(self, Self::ClaimTerminal(_))\n",
     "        matches!(self, Self::JoinTerminal(_))\n"),
    # -- Task 10 of the C4 recovery: the R3 checkpoint and deletion ------
    ("checkpoint-roster-runs-out-of-dependency-order",
     "driver/fsring-core/src/adapter/fence.rs",
     "    CheckpointFenceEffect::CloseSessionAdmission,\n"
     "    CheckpointFenceEffect::SignalPendingEnter,\n"
     "    CheckpointFenceEffect::WaitControlRundown,\n",
     "    CheckpointFenceEffect::SignalPendingEnter,\n"
     "    CheckpointFenceEffect::CloseSessionAdmission,\n"
     "    CheckpointFenceEffect::WaitControlRundown,\n"),
    ("checkpoint-refusal-does-not-record-the-failing-effect",
     "driver/fsring-core/src/adapter/fence.rs",
     "        self.attempted_mask |= effect.mask_bit();\n"
     "        self.failed_mask |= effect.mask_bit();\n",
     "        self.attempted_mask |= effect.mask_bit();\n"),
    ("authority-absence-accepts-a-foreign-generation",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if absence.locator() != self.locator {\n"
     "            return Err(self);\n"
     "        }\n",
     "        if false {\n"
     "            return Err(self);\n"
     "        }\n"),
    ("authenticated-result-accepts-a-relabelled-reason",
     "driver/fsring-core/src/adapter/fence.rs",
     "        if winner.reason() != result.reason {\n"
     "            return Err((winner, result));\n"
     "        }\n",
     "        if false {\n"
     "            return Err((winner, result));\n"
     "        }\n"),
    ("delete-preflight-reports-the-last-failing-check",
     "driver/fsring-core/src/adapter/fence.rs",
     "    if !observation.core_deleting_with_exact_right {\n"
     "        return Err(FinalizerPreflightStep::CoreDeleting);\n"
     "    }\n",
     "    if !observation.running_with_sole_authorities {\n"
     "        return Err(FinalizerPreflightStep::RunningDepositAndPublisher);\n"
     "    }\n"),
    ("delete-preparation-tolerates-a-shrinking-join-count",
     "driver/fsring-core/src/adapter/fence.rs",
     "    if after.admitted_joiners < before.admitted_joiners {\n"
     "        return false;\n"
     "    }\n",
     "    if after.admitted_joiners > before.admitted_joiners {\n"
     "        return false;\n"
     "    }\n"),
    ("final-delete-signals-before-it-publishes-the-outcome",
     "driver/fsring-core/src/adapter/fence.rs",
     "        FinalDeleteStep::PublishClosingCompleteAndOutcome,\n"
     "        FinalDeleteStep::SignalTerminalOutcome,\n",
     "        FinalDeleteStep::SignalTerminalOutcome,\n"
     "        FinalDeleteStep::PublishClosingCompleteAndOutcome,\n"),
    ("blocked-class-collapses-a-delete-fail-stop-into-a-checkpoint",
     "driver/fsring-core/src/session.rs",
     "            PrivateTerminalBlocked::Delete { .. } => TerminalBlockedClass::DeleteInvariant,\n",
     "            PrivateTerminalBlocked::Delete { .. } => TerminalBlockedClass::FenceInvariant,\n"),
    ("embedded-witness-ignores-the-required-profile",
     "driver/fsring-core/src/session.rs",
     "        if !profiles_match(self.identity.profile, required) {\n"
     "            return Err(ProductionAttestationError::WrongProfile);\n"
     "        }\n",
     "        if false {\n"
     "            return Err(ProductionAttestationError::WrongProfile);\n"
     "        }\n"),
    # -- Task 11 of the C4 recovery: the mount ledger --------------------
    ("mount-takes-the-registry-reference-under-the-vpb-lock",
     "driver/fsring-core/src/volume.rs",
     "        MountEffect::AcquireVpb,\n"
     "        MountEffect::ValidateTarget,\n"
     "        MountEffect::ReleaseVpb,\n"
     "        MountEffect::AcquireSessionReference,\n",
     "        MountEffect::AcquireVpb,\n"
     "        MountEffect::ValidateTarget,\n"
     "        MountEffect::AcquireSessionReference,\n"
     "        MountEffect::ReleaseVpb,\n"),
    ("mount-unwind-releases-the-registry-under-the-vpb-lock",
     "driver/fsring-core/src/volume.rs",
     "const ROLLBACK_COMMIT_VPB: &[MountRollbackEffect] = &[\n"
     "    MountRollbackEffect::ReleaseVpbIfHeld,\n"
     "    MountRollbackEffect::FreeVcb,\n"
     "    MountRollbackEffect::DeleteMountedDevice,\n"
     "    MountRollbackEffect::ReleaseSessionReference,\n"
     "];\n",
     "const ROLLBACK_COMMIT_VPB: &[MountRollbackEffect] = &[\n"
     "    MountRollbackEffect::FreeVcb,\n"
     "    MountRollbackEffect::DeleteMountedDevice,\n"
     "    MountRollbackEffect::ReleaseSessionReference,\n"
     "    MountRollbackEffect::ReleaseVpbIfHeld,\n"
     "];\n"),
    ("bind-ignores-the-mount-generation",
     "driver/fsring-core/src/adapter/fence.rs",
     "            ) => owner.mount_generation() == *mount_generation,\n",
     "            ) => true,\n"),
    ("bind-accepts-a-completion-of-the-wrong-kind",
     "driver/fsring-core/src/adapter/fence.rs",
     "            (Self::Absent(absent), ExpectedMountTeardown::Absent { cursor, .. }) => {\n"
     "                absence_cursor_eq(absent.cursor(), *cursor)\n"
     "            }\n"
     "            _ => false,\n",
     "            (Self::Absent(absent), ExpectedMountTeardown::Absent { cursor, .. }) => {\n"
     "                absence_cursor_eq(absent.cursor(), *cursor)\n"
     "            }\n"
     "            _ => true,\n"),
    ("absence-cursor-reuses-the-maximum-mount-generation",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "            None => PrivateMountRendezvousState::Exhausted { locator },\n",
     "            None => PrivateMountRendezvousState::Unmounted {\n"
     "                locator,\n"
     "                next_generation: NonZeroU64::new(generation),\n"
     "            },\n"),
    # -- Task 12 of the C4 recovery: the R2+R3 cutover -------------------
    ("preparation-refusal-reports-a-roster-cursor",
     "driver/fsring-core/src/adapter/fence.rs",
     "        RefusedCheckpointTeardown::preparation_refusal(report)\n",
     "        RefusedCheckpointTeardown {\n"
     "            cursor: FencePassCursor::ExecutorBinding,\n"
     "            report,\n"
     "        }\n"),
    ("closing-complete-published-without-its-record",
     "driver/fsring-core/src/session.rs",
     "        let prepared = prepare_closing_complete(self, locator, result, record_present)?;\n",
     "        let prepared = prepare_closing_complete(self, locator, result, true)?;\n"),
    ("live-cell-scan-skips-instead-of-claiming",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "            NativeCellPhase::Live => ScanAction::Claim,\n",
     "            NativeCellPhase::Live => ScanAction::Skip,\n"),
    ("copied-completion-restarts-the-scan",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        ScanAction::Skip => ScanContinuation::NextCell,\n",
     "        ScanAction::Skip => ScanContinuation::RestartScan,\n"),
    ("exhausted-mount-absence-refuses-deletion",
     "driver/fsring-core/src/adapter/fence.rs",
     "            MountAbsenceCursor::Next(_) | MountAbsenceCursor::Exhausted => true,\n",
     "            MountAbsenceCursor::Next(_) => true,\n"
     "            MountAbsenceCursor::Exhausted => false,\n"),

    ("final-delete-resets-the-cell-before-freeing-the-shell",
     "driver/fsring-core/src/adapter/fence.rs",
     "        FinalDeleteStep::DestroyAndFreeShell,\n"
     "        FinalDeleteStep::ReleaseRootReference,\n",
     "        FinalDeleteStep::ReleaseRootReference,\n"
     "        FinalDeleteStep::ResetCellAndPublishDisposition,\n"),
    ("mount-bind-ignores-the-completion-locator",
     "driver/fsring-core/src/adapter/fence.rs",
     "        let locator = self.locator();\n"
     "        if !locator_eq(locator, expected.locator()) {\n"
     "            return false;\n"
     "        }\n",
     "        let locator = self.locator();\n"
     "        if false {\n"
     "            let _ = locator;\n"
     "            return false;\n"
     "        }\n"),
    ("drained-signal-minted-before-the-last-release",
     "driver/fsring-core/src/session.rs",
     "                    drained: if next == 0 {\n",
     "                    drained: if next >= 0 {\n"),
    ("blocked-release-always-reports-drained",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     "        TerminalJoinRelease::Released {\n"
     "            outcome: TerminalClosedOutcome::Blocked(blocked),\n"
     "            drained,\n"
     "        } => TerminalWaitDisposition::Blocked { blocked, drained },\n",
     "        TerminalJoinRelease::Released {\n"
     "            outcome: TerminalClosedOutcome::Blocked(blocked),\n"
     "            drained: _,\n"
     "        } => TerminalWaitDisposition::Blocked {\n"
     "            blocked,\n"
     "            drained: None,\n"
     "        },\n"),
    ("re-observation-tolerates-a-shrinking-joiner-count",
     "driver/fsring-core/src/adapter/fence.rs",
     "    if after.admitted_joiners < before.admitted_joiners {\n"
     "        return false;\n"
     "    }\n",
     "    if false {\n"
     "        return false;\n"
     "    }\n"),
    ("delete-preflight-skips-the-sole-authority-check",
     "driver/fsring-core/src/adapter/fence.rs",
     "    if !observation.running_with_sole_authorities {\n"
     "        return Err(FinalizerPreflightStep::RunningDepositAndPublisher);\n"
     "    }\n",
     ""),
    ("mount-takes-the-session-reference-under-the-initial-vpb-lock",
     "driver/fsring-core/src/volume.rs",
     "            Self::ValidateTarget => MountPhase::Ordinary(Self::ReleaseInitialVpb),\n"
     "            Self::ReleaseInitialVpb => MountPhase::Ordinary(Self::AcquireSessionReference),\n"
     "            Self::AcquireSessionReference => MountPhase::Ordinary(Self::CreateMountedDevice),\n",
     "            Self::ValidateTarget => MountPhase::Ordinary(Self::AcquireSessionReference),\n"
     "            Self::AcquireSessionReference => MountPhase::Ordinary(Self::ReleaseInitialVpb),\n"
     "            Self::ReleaseInitialVpb => MountPhase::Ordinary(Self::CreateMountedDevice),\n"),
    ("roster-walk-continues-past-a-refusal",
     "driver/fsring-core/src/adapter/fence.rs",
     "                if succeeded {\n"
     "                    pending.succeeded()\n"
     "                } else {\n"
     "                    pending.refused()\n"
     "                }\n",
     "                let _ = succeeded;\n"
     "                pending.succeeded()\n"),
    ("roster-walk-treats-success-as-refusal",
     "driver/fsring-core/src/adapter/fence.rs",
     "                if succeeded {\n"
     "                    pending.succeeded()\n"
     "                } else {\n"
     "                    pending.refused()\n"
     "                }\n",
     "                if succeeded {\n"
     "                    pending.refused()\n"
     "                } else {\n"
     "                    pending.succeeded()\n"
     "                }\n"),
    ("native-fence-close-admission-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_close_generation_admission() }.map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-signal-pending-enter-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_schedule_linked_pending() }.map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-wait-control-rundown-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_wait_control_and_access_rundown() }\n"
     "            .map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-remove-producer-mappings-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_unmap_producer_aliases_reverse() }\n"
     "            .map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-wait-producer-mapping-rundown-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_wait_producer_capture_rundown() }.map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-acquire-consumers-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        match unsafe { self.ddi.native_acquire_consumers_increasing(prefix) } {",
     "        match Result::<(), D::Error>::Ok(()) {"),
    ("native-fence-drain-stable-prefixes-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "    match unsafe { ddi.native_drain_stable_prefixes_bounded(&mut prepared) } {",
     "    match Result::<(), D::Error>::Ok(()) {"),
    ("native-fence-retire-credits-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "    match unsafe { ddi.native_retire_grants(&mut call) } {",
     "    match Result::<(), D::Error>::Ok(()) {"),
    ("native-fence-release-consumers-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        match unsafe { self.ddi.native_release_consumers(&mut prefix) } {",
     "        match Result::<(), D::Error>::Ok(()) {"),
    ("native-fence-queue-installed-work-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_queue_installed_work() }.map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-wait-pending-owners-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        match unsafe { self.ddi.native_wait_pending_and_owner_rundown() } {\n"
     "            Ok(()) => self.wait_pending_done = true,\n"
     "            Err(PendingOwnerWaitFailure::Native(_)) => self.record_native(effect),\n"
     "            Err(PendingOwnerWaitFailure::PublicationFailStop(witness)) => {\n"
     "                self.record_first_retry(\n"
     "                    FenceRetryPoint::Effect(effect),\n"
     "                    PrivateFenceRetryCause::Invariant(FenceFailStopReason::PendingPublication(\n"
     "                        witness,\n"
     "                    )),\n"
     "                );\n"
     "            }\n"
     "        }\n",
     "        self.wait_pending_done = true;\n"),
    ("native-fence-release-readonly-mappings-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_unmap_readonly_aliases_reverse() }\n"
     "            .map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-release-mdls-system-view-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_release_mdls_and_system_view() }.map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-release-captured-process-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        unsafe { self.ddi.native_dereference_process() }.map_err(KernelFenceError::Native)",
     "        Ok(())"),
    ("native-fence-dismount-delete-devices-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        match unsafe { self.ddi.native_take_or_join_mount_and_delete() } {\n"
     "            Ok(bound) => {\n"
     "                self.bound_mount = Some(bound);\n"
     "                self.dismount_done = true;\n"
     "            }\n"
     "            Err(MountTeardownCallError::Native(_)) => self.record_native(effect),\n"
     "            Err(MountTeardownCallError::Bind(bind)) => {\n"
     "                self.pending_mount_bind = Some(bind);\n"
     "                self.record_first_retry(\n"
     "                    FenceRetryPoint::Effect(effect),\n"
     "                    PrivateFenceRetryCause::Invariant(FenceFailStopReason::MountBindMismatch),\n"
     "                );\n"
     "            }\n"
     "        }\n",
     "        self.dismount_done = true;\n"),
    ("native-fence-release-transient-backing-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "        match unsafe { self.ddi.native_release_transient_arrays(proof) } {",
     "        match Result::<(), (D::Error, ConsumerReleaseProof)>::Ok(()) {"),
    ("native-access-rundown-acquire-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                    let acquired =\n"
     "                        unsafe { fsring_sys::c4::ExAcquireRundownProtection(target.cast()) };\n",
     "                    let acquired = 1;\n"),
    ("native-access-generation-recheck-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "                    match core.validate_live(locator) {\n"
     "                        Ok(()) => pending.succeeded(),\n"
     "                        Err(_) => pending.refused(ResolveRejection::NotLive),\n"
     "                    }\n",
     "                    pending.succeeded()\n"),
    ("native-access-rundown-release-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "            unsafe { fsring_sys::c4::ExReleaseRundownProtection(target.cast()) };\n",
     "            let _ = target;\n"),
    ("native-access-rundown-wait-noop",
     "driver/fsring-fsd/src/fence.rs",
     "        unsafe { self.wait_access_rundown() }\n",
     "        true\n"),
    ("access-rundown-wait-omitted",
     "driver/fsring-fsd/src/fence.rs",
     "        if unsafe { self.inner.wait_control_rundown() && self.inner.wait_session_access_rundown() }\n",
     "        if unsafe { self.inner.wait_control_rundown() }\n"),
    ("native-join-close-admission-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        self.phase = NativeCellPhase::Retired;\n"
     "        unsafe { fsring_sys::c4::ExRundownCompleted(core::ptr::addr_of_mut!(self.access)) };\n",
     "        self.phase = NativeCellPhase::Retired;\n"),
    ("cq-execution-domain-check-omitted",
     "driver/fsring-core/src/enter.rs",
     "        if execution.domain() != EnterExecutionDomain::CqConsumer {\n"
     "            return Err(RoleError::WrongState);\n"
     "        }\n",
     "        let _ = execution.domain();\n"),
    ("smoke-staged-probes-unobserved",
     "fsring-user/src/smoke/live.rs",
     "    for probe in STAGED_OPERATION_ORDER {\n"
     "        let actual = acc.observe(backend, probe)?;\n",
     "    for probe in STAGED_OPERATION_ORDER {\n"
     "        let actual = expected_oracle(probe, root);\n"),
    ("smoke-live-probes-unobserved",
     "fsring-user/src/smoke/live.rs",
     "    for probe in LIVE_OPERATION_ORDER {\n"
     "        record_observed(acc, backend, probe, root)?;\n"
     "    }\n",
     "    if false {\n"
     "        for probe in LIVE_OPERATION_ORDER {\n"
     "            record_observed(acc, backend, probe, root)?;\n"
     "        }\n"
     "    }\n"),
    ("smoke-post-probes-unobserved",
     "fsring-user/src/smoke/live.rs",
     "    record_observed(acc, backend, ProbeName::BootContextPersistent, root)?;\n",
     "    if false {\n"
     "        record_observed(acc, backend, ProbeName::BootContextPersistent, root)?;\n"
     "    }\n"),
    ("smoke-live-route-uses-v1",
     "fsring-user/src/bin/fsring-control-smoke.rs",
     "        let staged_probes = match observe_staged_prefix(&mut acc, &mut backend, zero_identity()) {\n",
     "        let staged_probes = match Result::<_, fsring_user::smoke::C4ObserveError<()>>::Ok(Vec::new()) {\n"),
    ("smoke-v2-parser-bypassed",
     "driver/scripts/smoke_driver.ps1",
     "                    $selected.PublicSchema -ceq 'fsring-control-smoke/v2'\n",
     "                    $false\n"),
    ("smoke-after-mutation-not-run",
     "fsring-user/src/smoke/live.rs",
     "        if self.state.sticky_failure {\n"
     "            return Err(C4ObserveError::Probe(\n"
     "                ProbeError::ObservationAfterStickyFailure,\n"
     "            ));\n"
     "        }\n",
     "        if false && self.state.sticky_failure {\n"
     "            return Err(C4ObserveError::Probe(\n"
     "                ProbeError::ObservationAfterStickyFailure,\n"
     "            ));\n"
     "        }\n"),
    ("control-cleanup-frees-context",
     "driver/fsring-core/src/adapter/setup.rs",
     "        ControlContextCloseEffect::DetachFsContext,\n"
     "        ControlContextCloseEffect::DestroyAndFreeContext,\n"
     "        ControlContextCloseEffect::ReleaseControlContextAdmission,\n",
     "        ControlContextCloseEffect::DestroyAndFreeContext,\n"
     "        ControlContextCloseEffect::DetachFsContext,\n"
     "        ControlContextCloseEffect::ReleaseControlContextAdmission,\n"),
    ("control-close-free-twice",
     "driver/fsring-core/src/adapter/setup.rs",
     "            .any(|effect| matches!(effect, ControlContextCloseEffect::DestroyAndFreeContext))\n",
     "            .any(|effect| true)\n"),
    ("native-finalizer-preflight-step-noop",
     "driver/fsring-fsd/src/fence.rs",
     "    if let Err(step) = fsring_core::adapter::fence::decide_delete_preflight(observation) {\n",
     "    if false {\n"
     "        let step = loop {};\n"
     "        let _ = fsring_core::adapter::fence::decide_delete_preflight(observation);\n"),
    ("native-terminal-event-signal-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        fsring_sys::c4::KeSetEvent(outcome, 0, 0 as fsring_sys::BOOLEAN);\n",
     "        let _ = outcome;\n"),
    ("native-terminal-event-clear-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        unsafe {\n"
     "            fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!(self.mount_reset_waiters_drained));\n"
     "        }\n",
     "        let _ = core::ptr::addr_of_mut!(self.mount_reset_waiters_drained);\n"),
    ("native-terminal-event-wait-noop",
     "driver/fsring-fsd/src/fence.rs",
     "    let _retain_ticket = join;\n"
     "    unsafe { crate::lifecycle::wait_blocked_unload_forever(registry) }\n",
     "    let _retain_ticket = join;\n"
     "    let _ = registry;\n"
     "    loop {}\n"),
    ("native-joiners-drained-signal-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        fsring_sys::c4::KeSetEvent(visibility, 0, 0 as fsring_sys::BOOLEAN);\n",
     "        let _ = visibility;\n"),
    ("native-joiners-drained-wait-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    unsafe { fsring_sys::c4::KeSetEvent(event, 0, 0 as fsring_sys::BOOLEAN) };\n",
     "    let _ = event;\n"),
    ("native-finalizer-queue-noop",
     "driver/fsring-fsd/src/fence.rs",
     "    unsafe { crate::lifecycle::queue_cell_finalizer(kick) };\n",
     "    let _ = kick;\n"),
    ("native-finalizer-rundown-completed-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    pub(crate) unsafe fn complete_access_rundown(&mut self) {\n"
     "        // SAFETY: the caller's contract.\n"
     "        unsafe { fsring_sys::c4::ExRundownCompleted(core::ptr::addr_of_mut!(self.access)) };\n"
     "    }\n",
     "    pub(crate) unsafe fn complete_access_rundown(&mut self) {}\n"),
    ("native-finalizer-rundown-reinitialize-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "            fsring_sys::c4::ExReInitializeRundownProtection(core::ptr::addr_of_mut!(self.access))\n",
     "            let _ = core::ptr::addr_of_mut!(self.access);\n"),
    ("native-finalizer-free-shell-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };\n"
     "        unsafe { root.state.as_ref() }.release();",
     "        let _ = self.session.as_ptr();\n"
     "        unsafe { root.state.as_ref() }.release();"),
    ("finalizer-finish-prepared-delete-noop",
     "driver/fsring-core/src/session.rs",
     "        reset_slot(slot, prepared.disposition);\n"
     "        prepared.disposition\n",
     "        prepared.disposition\n"),
    ("native-finalizer-root-release-noop",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };\n"
     "        unsafe { root.state.as_ref() }.release();",
     "        unsafe { crate::session::free_session_shell_allocation(self.session.as_ptr()) };\n"
     "        let _ = root;"),
    ("joiner-drained-signal-omitted",
     "driver/fsring-core/src/session.rs",
     "                    drained: if next == 0 {\n"
     "                        Some(TerminalJoinersDrainedSignal {\n",
     "                    drained: if false && next == 0 {\n"
     "                        Some(TerminalJoinersDrainedSignal {\n"),
    ("pending-mark-after-csq",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        (*context.as_ptr()).irp = irp;\n"
     "        (*context.as_ptr()).irp_axis = Some(IrpAxis::Queued);\n",
     "        (*context.as_ptr()).irp_axis = Some(IrpAxis::Queued);\n"
     "        (*context.as_ptr()).irp = irp;\n"),
    ("pending-dpc-exit-signal-omitted",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        KeSetEvent(core::ptr::addr_of_mut!((*raw).dpc_exited), 0, 0 as BOOLEAN);\n",
     "        let _ = core::ptr::addr_of_mut!((*raw).dpc_exited);\n"),
    ("pending-thunk-completes",
     "driver/fsring-fsd/src/pending_enter.rs",
     "unsafe fn complete_parked_irp(observed: IrpObservation, status: u32, information: usize) {\n",
     "unsafe fn complete_parked_irp(observed: IrpObservation, status: u32, information: usize) {\n"
     "    let _ = (observed, status, information);\n"
     "    return;\n"),
    ("cq-kind-after-request-lookup",
     "driver/fsring-core/src/enter.rs",
     "        let execution = token.execution();\n"
     "        if execution.ring() != ring {\n"
     "            return Err(RoleError::WrongRing);\n"
     "        }\n",
     "        let execution = token.execution();\n"
     "        let _ = ring;\n"),
    ("notify-head-before-claim",
     "driver/fsring-core/src/grant.rs",
     "        GrantCommitStep::Preflight,\n        GrantCommitStep::Claim,\n",
     "        GrantCommitStep::Claim,\n        GrantCommitStep::Preflight,\n"),
    ("control-terminal-frees-context",
     "driver/fsring-core/src/adapter/setup.rs",
     "        ControlContextCloseEffect::DetachFsContext,\n"
     "        ControlContextCloseEffect::DestroyAndFreeContext,\n"
     "        ControlContextCloseEffect::ReleaseControlContextAdmission,\n",
     "        ControlContextCloseEffect::DetachFsContext,\n"
     "        ControlContextCloseEffect::ReleaseControlContextAdmission,\n"
     "        ControlContextCloseEffect::DestroyAndFreeContext,\n"),
    ("control-post-close-touches-context",
     "driver/fsring-core/src/adapter/setup.rs",
     "    pub fn context_freed(&self) -> bool {\n",
     "    pub fn context_freed(&self) -> bool {\n"
     "        let _ = self.next;\n"
     "        return false;\n"),
    ("terminal-winner-cas-omitted",
     "driver/fsring-core/src/terminal.rs",
     "        match self.state.compare_exchange(\n"
     "            0,\n"
     "            who.code(),\n"
     "            // Acquire-Release: the winner's subsequent work must be ordered\n"
     "            // after the claim, and a loser must observe the winner's prior\n"
     "            // publication.\n"
     "            Ordering::AcqRel,\n"
     "            Ordering::Acquire,\n"
     "        ) {\n",
     "        match { let _ = &self.state; let _ = who; Ok(0u8) } {\n"),
    ("vpb-clear-after-delete",
     "driver/fsring-fsd/src/volume.rs",
     "                    (*vpb).Flags &= !VPB_MOUNTED;\n",
     "                    let _ = vpb;\n"),
    ("pending-handoff-before-guard-release",
     "driver/fsring-core/src/enter.rs",
     "        if self.axis != InstallAxis::Installing {\n"
     "            return Err(PendingError::WrongRingState);\n"
     "        }\n"
     "        self.axis = InstallAxis::HandoffDone;\n",
     "        if self.axis != InstallAxis::Installing {\n"
     "            return Err(PendingError::WrongRingState);\n"
     "        }\n"),
    ("pending-worker-idle-before-owner-release",
     "driver/fsring-core/src/enter.rs",
     "            WorkerScheduleState::Running => {\n"
     "                self.state = WorkerScheduleState::Idle;\n"
     "                Ok((token, None))\n",
     "            WorkerScheduleState::Running => {\n"
     "                Ok((token, None))\n"),
    # The reschedule arm publishes `Queued`, and a `Queued` schedule refuses to
    # queue again -- so handing the caller nothing to discharge wedges the ring
    # exactly as the discarded `bool` did.
    ("pending-reschedule-publishes-queued-owing-nothing",
     "driver/fsring-core/src/enter.rs",
     "                self.state = WorkerScheduleState::Queued;\n"
     "                let install = token.install;\n",
     "                let install = token.install;\n"),
    ("pending-worker-state-without-owner",
     "driver/fsring-core/src/enter.rs",
     "            WorkerScheduleState::Idle => WorkerScheduleState::Queued,\n",
     "            WorkerScheduleState::Idle => WorkerScheduleState::Idle,\n"),
    # Retargeted (round 15): the arm yields a `Result` now, because the three
    # invariant failures leave the slot-lock hold as values and fire after the
    # release -- `panic = "abort"` would otherwise strand the ring's spin lock.
    ("pending-publication-fail-stop-variant-omitted",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                    Some(packet) => Ok(PendingUnloadObservation::PublicationFailStop(\n"
     "                        packet.witness(),\n"
     "                    )),\n",
     "                    Some(_packet) => Ok(PendingUnloadObservation::Drained),\n"),
    ("pending-publication-fail-stop-unload-predicate-omitted",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                    PendingUnloadObservation::PublicationFailStop(_) => {\n"
     "                        wait.observed_publication_fail_stop()\n"
     "                    }\n",
     "                    PendingUnloadObservation::PublicationFailStop(_) => wait.observed_drained(),\n"),
    ("notify-refresh-before-head",
     "driver/fsring-core/src/grant.rs",
     "        GrantCommitStep::AdvanceHead,\n        GrantCommitStep::Refresh,",
     "        GrantCommitStep::Refresh,\n        GrantCommitStep::AdvanceHead,"),
    ("protocol-abort-not-committed",
     "driver/fsring-core/src/enter.rs",
     "        if self.cq_owner != Some(execution.invocation().get()) {\n"
     "            return Err(RoleError::WrongInvocation);\n"
     "        }\n",
     "        let _ = self.cq_owner;\n"),
    ("completion-accepted",
     "driver/fsring-core/src/enter.rs",
     "        if execution.domain() != EnterExecutionDomain::CqConsumer {\n"
     "            return Err(RoleError::WrongState);\n"
     "        }\n"
     "        if self.cq_owner != Some(execution.invocation().get()) {\n",
     "        let _ = execution.domain();\n"
     "        if self.cq_owner != Some(execution.invocation().get()) {\n"),
    ("cancel-after-commit-wins",
     "driver/fsring-core/src/enter.rs",
     "        if self.axis != InstallAxis::HandoffDone {\n",
     "        if false && self.axis != InstallAxis::HandoffDone {\n"),
    ("mount-reset-before-waiters-drained",
     "driver/fsring-fsd/src/volume.rs",
     "                (*vpb).Flags |= VPB_MOUNTED;\n",
     "                (*vpb).Flags |= VPB_MOUNTED;\n"
     "                let _reset_early = true;\n"),
    ("mount-reset-proof-bypassed",
     "driver/fsring-fsd/src/volume.rs",
     "                    binding_unchanged: flags & VPB_MOUNTED == 0,\n",
     "                    binding_unchanged: true,\n"),
    ("mount-root-ref-substituted",
     "driver/fsring-fsd/src/volume.rs",
     "            (real_device == context.vdo && flags & VPB_MOUNTED == 0)\n",
     "            true\n"),
    ("mounted-delete-duplicated",
     "driver/fsring-fsd/src/volume.rs",
     "    if !mounted_device.is_null() && flags & VPB_MOUNTED != 0 {\n",
     "    if !mounted_device.is_null() {\n"),
    # Retargeted at Task 27. The predecessor added an unused constant. The
    # name's defect is a read *through the deleted device pointer*, which is
    # what `delete` exists to make the last touch.
    ("vdo-read-after-delete",
     "driver/fsring-fsd/src/volume.rs",
     "    // SAFETY: the caller's device contract; deleted exactly once.\n"
     "    unsafe { crate::kernel::delete_device(device) };\n",
     "    // SAFETY: the caller's device contract; deleted exactly once.\n"
     "    unsafe { crate::kernel::delete_device(device) };\n"
     "    // SAFETY: none. This is the defect.\n"
     "    let _flags = unsafe { (*device).Flags };\n"),
    ("session-root-release-before-finalizer",
     "driver/fsring-fsd/src/fence.rs",
     "unsafe fn queue_finalizer(kick: AdmittedR3FinalizerKick) {\n",
     "unsafe fn queue_finalizer(kick: AdmittedR3FinalizerKick) {\n"
     "    let _root_early = true;\n"),
    ("finalizer-queue-duplicated",
     "driver/fsring-fsd/src/lifecycle.rs",
     "pub(crate) unsafe fn queue_cell_finalizer(admitted: AdmittedR3FinalizerKick) {\n",
     "pub(crate) unsafe fn queue_cell_finalizer(admitted: AdmittedR3FinalizerKick) {\n"
     "    let _dup = true;\n"),
    ("rundown-reinit-before-join-drain",
     "driver/fsring-fsd/src/lifecycle.rs",
     "    pub(crate) unsafe fn reinitialize_access_rundown(&mut self) {\n",
     "    pub(crate) unsafe fn reinitialize_access_rundown(&mut self) {\n"
     "        let _early = true;\n"),
    ("terminal-clear-before-join-drain",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        fsring_sys::c4::KeSetEvent(event.as_ptr(), 0, 0 as fsring_sys::BOOLEAN);\n",
     "        let _ = event;\n"),
    ("terminal-retry-report-merge-noop",
     "driver/fsring-core/src/adapter/fence.rs",
     "            | FenceResidualMergeFailStopInput::Retry { failed, .. } => match failed.error {\n",
     "            | FenceResidualMergeFailStopInput::Retry { failed, .. } => match { let _ = failed.error; FenceError::RingCountOutOfRange } {\n"),
    ("fence-discharge-proof-with-residual",
     "driver/fsring-core/src/adapter/fence.rs",
     "        let roster_complete = first_retry.is_none()\n",
     "        let roster_complete = true;\n"
     "        let _ = first_retry.is_none()\n"),
    ("terminal-finalize-before-residual-empty",
     "driver/fsring-core/src/adapter/fence.rs",
     "            (true, Some(consumers), Some(mount)) => {\n",
     "            (true, Some(consumers), Some(mount)) if false => {\n"),
    ("pending-contend-before-dequeue",
     "driver/fsring-core/src/adapter/enter.rs",
     "        if execution.domain() != EnterExecutionDomain::CqConsumer {\n"
     "            return Err(PendingError::WrongExecutionDomain);\n"
     "        }\n",
     "        let _ = execution.domain();\n"),
    # Retargeted at Task 27. The predecessor added a dead local, which nothing
    # reads and nothing should: an inert edit is not a defect, and grading it
    # CAUGHT would measure the digest rather than the property. This module
    # never calls `KeCancelTimer` -- Task 17 leaves the timer absent -- so the
    # nearest real bearer of the same rule is the PASSIVE DPC-exit wait, which
    # may skip only on a *proved* Quiesced.
    # Retargeted with the rendezvous. The unlocked `Running` pre-check this
    # anchored on is gone: the decision now happens inside
    # `wait_pending_dpc_exit`, under the slot lock, and the plant inverts it
    # there. Same property, same file, same owning command -- a timer that is
    # not quiesced must be waited for.
    ("pending-exit-wait-ignores-a-nonquiesced-timer",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        let owes_wait = !matches!(unsafe { (*raw).timer_state }, "
     "TimerState::Quiesced);\n",
     "        let owes_wait = matches!(unsafe { (*raw).timer_state }, "
     "TimerState::Quiesced);\n"),
    # H2, planted: clearing the latch when a new generation arms races the store
    # it guards. A DPC publishes `Quiesced` and releases the lock BEFORE its
    # `KeSetEvent`, so an install arming in that window erased an obligation
    # still owed and unload freed the arena the set was about to write into.
    ("pending-teardown-latch-cleared-on-arm",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        let armed = unsafe { (*raw).timer_state.arm(epoch) }.is_ok();\n",
     "        let armed = unsafe { (*raw).timer_state.arm(epoch) }.is_ok();\n"
     "        if armed {\n"
     "            unsafe { (*raw).dpc_entered = false };\n"
     "        }\n"),
    # H3, planted: the discharge that makes \"every exit discharges\" a shape
    # rather than a thing to remember. Without it an install that fails after
    # the handoff leaves the schedule saying `Queued` with no work item queued,
    # so no pass runs and `abandon_queued_pass` has nothing to run on.
    ("pending-handoff-obligation-left-undischarged",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    unsafe { discharge_parked_handoff(runtime, ring_index) };\n",
     ""),
    # H1, planted in CORE where `enter::tests` kills it behaviourally: a
    # DPC-exit wait is sound only immediately after the cancel that bounds it.
    # Ordered the other way it waits on a deadline that has not fired -- the
    # client's whole `timeout_ms` on a `DelayedWorkQueue` thread, which is the
    # blocker the previous round shipped.
    ("pending-exit-wait-precedes-the-cancel-that-bounds-it",
     "driver/fsring-core/src/enter.rs",
     "    PendingCompletionEffect::CancelTimer,\n"
     "    PendingCompletionEffect::WaitDpcExitIfRequired,\n",
     "    PendingCompletionEffect::WaitDpcExitIfRequired,\n"
     "    PendingCompletionEffect::CancelTimer,\n"),
    # The stale set is what made a single wait unsound. Deleting the clear
    # restores exactly the defect: a set left standing by the previous
    # install's DPC satisfies this generation's wait.
    ("pending-dpc-exit-wait-skips-the-stale-clear",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        if owes_wait {\n"
     "            // SAFETY: under the hold, and `dpc_exited` is initialized before\n"
     "            // the DPC can be bound to a timer. See the paragraph above for why\n"
     "            // clearing here cannot erase the set this frame is waiting for.\n"
     "            unsafe { fsring_sys::c4::KeClearEvent(core::ptr::addr_of_mut!"
     "((*raw).dpc_exited)) };\n"
     "        }\n",
     ""),
    # Unload's proof that a DPC which published `Quiesced` inside the lock has
    # also made its last store outside it. Skipping the wait frees the arena the
    # `KeSetEvent` is about to write into.
    ("pending-teardown-skips-the-exit-signal-wait",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    let owed = unsafe { (*raw).dpc_entered };\n",
     "    let owed = false;\n"),
    # The wedge half: a pass that could not begin must put `Queued` back, or the
    # ring accepts no further wake and the already-dequeued IRP is stranded.
    # Planted in core, where `enter::tests` observes the state change, rather
    # than on the fsd wrapper, where the only available witness was a digest.
    # The cancel path's whole discrimination: the framework runs `CsqRemoveIrp`
    # before `CsqCompleteCanceledIrp`, so an EMPTY slot at completion is the
    # normal order and not a foreign IRP. Calling it foreign is a bugcheck on
    # every user-mode cancel of a parked ENTER, and it shipped that way from
    # `079ec55` until it was classified here.
    ("csq-cancel-completion-refuses-the-removed-irp",
     "driver/fsring-core/src/enter.rs",
     "        (None, Some(_)) => CsqCancelCompletion::AdoptRemoved,\n",
     "        (None, Some(_)) => CsqCancelCompletion::ForeignIrp,\n"),
    ("pending-abandoned-pass-leaves-the-ring-queued",
     "driver/fsring-core/src/enter.rs",
     "        self.state = WorkerScheduleState::Idle;\n        Ok(token)\n    }\n\n"
     "    /// Move a drained pass into `Completing`, consuming the Worker token.",
     "        Ok(token)\n    }\n\n"
     "    /// Move a drained pass into `Completing`, consuming the Worker token."),
    # Unload waits only when the cancel says a DPC is still in flight. Waiting
    # on the dequeued arm instead means the one case that needs the rendezvous
    # never gets it, and the arena holding the KTIMER, the KDPC and the exit
    # event is freed underneath a queued DPC.
    ("pending-teardown-waits-the-wrong-cancel-arm",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    if matches!(outcome, PendingTimerCancel::RequiresDpcExitWait) {\n",
     "    if matches!(outcome, PendingTimerCancel::DequeuedBeforeRun) {\n"),
    # Returning at the first refusing ring leaves every higher ring with no
    # Fence wake at all.
    ("pending-fence-wake-sweep-abandons-higher-rings",
     "driver/fsring-fsd/src/pending_enter.rs",
     "            if !deposited {\n                refused = true;\n            }\n",
     "            if !deposited {\n                refused = true;\n"
     "                return false;\n            }\n"),
    # A closing install must not read as a refused wake. Flipping this arm
    # makes every completing ring report a refusal, which makes the aggregate
    # both sweeps now return meaningless and refuses ENTER routinely.
    ("pending-closing-wake-counts-as-a-refusal",
     "driver/fsring-fsd/src/pending_enter.rs",
     "            Err(PendingError::Closing) => true,\n",
     "            Err(PendingError::Closing) => false,\n"),
    # Observing the plan instead of taking it leaves it bound to a released
    # install, and `store_session_wait` then refuses every later park.
    ("pending-release-install-keeps-the-parked-plan",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        if self.parked_plan.is_some() || self.session_role.is_some() "
     "|| self.dpc_owner.is_some() {\n",
     "        if self.session_role.is_some() || self.dpc_owner.is_some() {\n"),
    # Arming the timer outside the hold that published `Armed` reopens the
    # window in which the state claims a queued DPC that is not queued yet,
    # which is what sent a completion pass to wait on a signal nothing owed.
    ("pending-timer-armed-after-its-lock",
     "driver/fsring-fsd/src/pending_enter.rs",
     "            unsafe {\n                KeSetTimer(\n"
     "                    core::ptr::addr_of_mut!((*raw).timer),\n"
     "                    due_time,\n"
     "                    core::ptr::addr_of_mut!((*raw).dpc),\n"
     "                );\n            }\n        }\n        unlock.release();\n",
     "        }\n        unlock.release();\n        if armed {\n"
     "            unsafe {\n                KeSetTimer(\n"
     "                    core::ptr::addr_of_mut!((*raw).timer),\n"
     "                    due_time,\n"
     "                    core::ptr::addr_of_mut!((*raw).dpc),\n"
     "                );\n            }\n        }\n"),
    ("pending-handoff-published-twice",
     "driver/fsring-core/src/enter.rs",
     "        if self.axis != InstallAxis::HandoffDone {\n",
     "        if self.axis != InstallAxis::HandoffDone || true {\n"),
    ("pending-owner-released-before-handoff",
     "driver/fsring-core/src/enter.rs",
     "        self.axis = InstallAxis::HandoffDone;\n"
     "        Ok(())\n",
     "        self.install = None;\n"
     "        self.axis = InstallAxis::HandoffDone;\n"
     "        Ok(())\n"),
    ("pending-worker-queued-before-installer-release",
     "driver/fsring-core/src/enter.rs",
     "        if self.axis != InstallAxis::HandoffDone {\n"
     "            return Err(PendingError::WrongRingState);\n"
     "        }\n"
     "        self.state = match self.state {\n",
     "        self.state = match self.state {\n"),
    ("pending-fabricated-dequeue-receipt",
     "driver/fsring-fsd/src/pending_enter.rs",
     "            Some(IrpAxis::Queued) => CsqInsertOutcome::Inserted,\n",
     "            Some(IrpAxis::Queued) => CsqInsertOutcome::Inserted,\n"
     "            Some(_) => CsqInsertOutcome::Inserted,\n"),
    ("pending-dpc-exit-signal-before-owner-release",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    unsafe {\n"
     "        KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);\n"
     "    }\n"
     "    // The final action, and the ticket is the only authority for it. By the\n",
     "    unsafe {\n"
     "        KeSetEvent(core::ptr::addr_of_mut!((*raw).dpc_exited), 0, 0 as BOOLEAN);\n"
     "        KeReleaseSpinLock(core::ptr::addr_of_mut!((*raw).lock), raised);\n"
     "    }\n"
     "    // The final action, and the ticket is the only authority for it. By the\n"),
    ("pending-work-clear-recheck-omitted",
     "driver/fsring-core/src/enter.rs",
     "            WorkerScheduleState::Running => {\n"
     "                self.state = WorkerScheduleState::Idle;\n",
     "            WorkerScheduleState::Running => {\n"
     "                self.state = WorkerScheduleState::Queued;\n"),
    ("pending-epoch-wraps",
     "driver/fsring-fsd/src/pending_enter.rs",
     "        (*raw).observed_generation = 0;\n",
     "        (*raw).observed_generation = u64::MAX;\n"),
    ("pending-early-cancel-returns-complete",
     "driver/fsring-fsd/src/pending_enter.rs",
     "unsafe extern \"C\" fn csq_complete_canceled_irp(csq: PIO_CSQ, irp: PIRP) {\n",
     "unsafe extern \"C\" fn csq_complete_canceled_irp(csq: PIO_CSQ, irp: PIRP) {\n"
     "    let _ = (csq, irp);\n"
     "    return;\n"),
    # Retargeted at Task 27, for the same reason. `observe_pending_for_unload`
    # documents that it never takes, clears or projects the unique packet; the
    # defect is the observation consuming it, which leaves a parked slot naming
    # a fail-stop nothing backs.
    ("pending-publication-fail-stop-packet-cleared",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                match (*raw).publication_fail_stop.as_ref() {\n",
     "                match (*raw).publication_fail_stop.take().as_ref() {\n"),
    # Retargeted (round 15) for the same reason: the observation is a `Result`
    # now. This one keeps the packet and reports the slot drained anyway, which
    # is the distinct defect -- the arm above omits the variant entirely.
    ("pending-publication-fail-stop-treated-drained",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                    Some(packet) => Ok(PendingUnloadObservation::PublicationFailStop(\n"
     "                        packet.witness(),\n"
     "                    )),\n",
     "                    Some(packet) => {\n"
     "                        let _ = packet.witness();\n"
     "                        Ok(PendingUnloadObservation::Drained)\n"
     "                    }\n"),
    # Retargeted at Task 27. The predecessor appended a *comment*, which the
    # auditor strips before it reads anything. The predicate that actually
    # stops a delete is the drain refusal: turning it into a break lets a
    # parked publication satisfy `wait_contexts_drained`, and the checkpoint
    # then deletes the session under its own still-parked IRP.
    ("pending-publication-fail-stop-delete-predicate-omitted",
     "driver/fsring-fsd/src/pending_enter.rs",
     "                    PendingDrainStep::Refused(_) => return false,\n",
     "                    PendingDrainStep::Refused(_) => break,\n"),
    ("pending-final-publication-lock-packet-exposed",
     "driver/fsring-fsd/src/pending_enter.rs",
     "    PublicationFailStop(PublicationFailStopWitness),\n",
     "    PublicationFailStop(PublicationFailStopWitness),\n"
     "    #[cfg(any())]\n"
     "    ExposedLockPacket,\n"),
    ("blocked-notify-consumed",
     "driver/fsring-core/src/enter.rs",
     "        matches!(self.execution.domain, EnterExecutionDomain::CqConsumer)\n",
     "        true\n"),
    # Round 18: the close choreography. CLEANUP stops at its terminal again, so
    # the finalizer's record is never acknowledged. The continuation's table
    # test and `close_choreography`'s load-bearing walk must both see it.
    ("cleanup-never-reclaims-after-its-terminal",
     "driver/fsring-core/src/adapter/lifecycle.rs",
     '        (CleanupPass::First, CleanupRouteResult::Terminal(TerminalOutcomeKind::Completed)) => {\n            ReclaimOnce\n        }\n',
     '        (CleanupPass::First, CleanupRouteResult::Terminal(TerminalOutcomeKind::Completed)) => {\n            Proceed\n        }\n'),
    # CLOSE frees an unacknowledged `Completed` record again -- round 17's
    # repair, which turned a leak into two use-after-frees (native N17-1). The
    # anchor is the `CellOwned` arm's three code lines and nothing else: the
    # first version spanned both arms with their comments, and a comment edit in
    # the same round turned it HARNESS. Moving `Completed` to its own arm keeps
    # the pattern reachable, so the mutant compiles under `-D warnings`.
    ("close-frees-an-unacknowledged-record",
     "driver/fsring-core/src/adapter/setup.rs",
     "            ControlContextLifetimeKind::LiveCellOwned\n"
     "            | ControlContextLifetimeKind::Completed\n"
     "            | ControlContextLifetimeKind::BlockedCellOwned => Self::CellOwned,\n",
     "            ControlContextLifetimeKind::Completed => Self::CloseRight,\n"
     "            ControlContextLifetimeKind::LiveCellOwned\n"
     "            | ControlContextLifetimeKind::BlockedCellOwned => Self::CellOwned,\n"),
    # The completion hold keeps the recorded pointer again, so the process-loss
    # and unload scans dereference a context CLOSE has freed (native N17-1).
    # `fsring-fsd` has no host tests; the lifetime row
    # `recorded-context-retired-at-completion` is what must see it.
    ("completion-keeps-the-recorded-context",
     "driver/fsring-fsd/src/lifecycle.rs",
     "        cell.recorded_control_context = None;\n",
     ""),
]

C4_SKIP_DIRS = {".git", "target", "__pycache__", ".vs", ".idea", ".superpowers"}

# Cargo and rustc scratch for this sweep. C: TEMP filled the disk (os error 112)
# mid-suite; keep copies and CARGO_TARGET_DIR off the system drive.
C4_WORK_ROOT = os.environ.get("FSRING_C4_WORK_ROOT", r"E:\fsring-c4-work")


def c4_work_root():
    root = os.path.abspath(C4_WORK_ROOT)
    os.makedirs(root, exist_ok=True)
    return root


def c4_scratch_env(env, work, worker=0):
    bound = (env or os.environ).copy()
    scratch = os.path.join(work, "scratch-%d" % worker)
    os.makedirs(scratch, exist_ok=True)
    bound["CARGO_TARGET_DIR"] = os.path.join(work, "cargo-target-%d" % worker)
    bound["CARGO_TERM_COLOR"] = "never"
    bound["CARGO_TERM_PROGRESS_WHEN"] = "never"
    bound["TMP"] = scratch
    bound["TEMP"] = scratch
    bound["TMPDIR"] = scratch
    return bound


def c4_resolve_jobs(requested):
    """Parallel workers. Quality-neutral: each worker owns a private tree."""
    if requested is not None:
        return max(1, int(requested))
    env = os.environ.get("FSRING_C4_MUTATION_JOBS")
    if env:
        return max(1, int(env))
    cpu = os.cpu_count() or 1
    return max(1, min(4, cpu))


def c4_resume_enabled(flag):
    if flag is False:
        return False
    if os.environ.get("FSRING_C4_MUTATION_NO_RESUME") == "1":
        return False
    return True


def c4_repo_fingerprint(repo):
    """Identity of the tree a mutation run observes.

    HEAD plus every tracked/untracked difference. A journal from a different
    tree is not a measurement of this one.
    """
    def git_bytes(args):
        completed = subprocess.run(
            ["git", "-C", repo] + args,
            check=False,
            capture_output=True,
        )
        if completed.returncode != 0:
            raise SystemExit(
                "git %s failed while fingerprinting the mutation tree"
                % " ".join(args)
            )
        return completed.stdout

    digest = hashlib.sha256()
    digest.update(git_bytes(["rev-parse", "HEAD"]))
    digest.update(b"\0")
    digest.update(git_bytes(["diff-index", "-p", "HEAD"]))
    digest.update(b"\0")
    digest.update(git_bytes(["ls-files", "--others", "--exclude-standard", "-z"]))
    return digest.hexdigest()


def c4_suite_identity(repo, roster, skip_targets, only_mutant, only_target):
    digest = hashlib.sha256()
    digest.update(MUTATION_JOURNAL_SCHEMA.encode("utf-8"))
    digest.update(b"\0c4-suite\0")
    digest.update(c4_repo_fingerprint(repo).encode("ascii"))
    digest.update(b"\0")
    runner = os.path.join(repo, "driver", "scripts", "mutation_sweep.py")
    digest.update(io.open(runner, "rb").read())
    digest.update(b"\0")
    for row in roster:
        digest.update(row["target"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(row["id"].encode("utf-8"))
        digest.update(b"\0")
        digest.update("\0".join(row["owningCommand"]).encode("utf-8"))
        digest.update(b"\0")
    digest.update(("skip=" + ",".join(sorted(skip_targets))).encode("utf-8"))
    digest.update(b"\0")
    digest.update(("only_mutant=" + (only_mutant or "")).encode("utf-8"))
    digest.update(b"\0")
    digest.update(("only_target=" + (only_target or "")).encode("utf-8"))
    return digest.hexdigest()


def default_sweep_identity(repo, rel_src):
    digest = hashlib.sha256()
    digest.update(MUTATION_JOURNAL_SCHEMA.encode("utf-8"))
    digest.update(b"\0default-sweep\0")
    digest.update(c4_repo_fingerprint(repo).encode("ascii"))
    digest.update(b"\0")
    digest.update(rel_src.encode("utf-8"))
    digest.update(b"\0")
    runner = os.path.join(repo, "driver", "scripts", "mutation_sweep.py")
    digest.update(io.open(runner, "rb").read())
    digest.update(b"\0")
    src_path = os.path.join(repo, rel_src.replace("/", os.sep))
    digest.update(io.open(src_path, "rb").read())
    return digest.hexdigest()


def mutation_journal_path(identity):
    return os.path.join(c4_work_root(), "journals", identity + ".jsonl")


def _journal_header_line(header):
    return json.dumps(header, sort_keys=True, separators=(",", ":")) + "\n"


def mutation_journal_create(path, header):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload = _journal_header_line(header)
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def mutation_journal_append(path, lock, target, ident, verdict):
    if verdict not in JOURNALABLE_VERDICTS:
        return
    record = {
        "id": ident,
        "record": "result",
        "target": target,
        "verdict": verdict,
    }
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    directory = os.path.dirname(path)
    with lock:
        if directory:
            os.makedirs(directory, exist_ok=True)
        if not os.path.isfile(path):
            raise SystemExit("mutation journal was not opened: %s" % path)
        with io.open(path, "a", encoding="utf-8", newline="") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())


def mutation_journal_load(path, expected_header):
    if not os.path.isfile(path):
        return {}
    try:
        with io.open(path, encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line]
    except OSError:
        return {}
    if not lines:
        return {}
    try:
        header = json.loads(lines[0])
    except ValueError:
        return {}
    if header != expected_header:
        return {}
    completed = {}
    for line in lines[1:]:
        try:
            row = json.loads(line)
        except ValueError:
            return {}
        if row.get("record") != "result":
            return {}
        if row.get("verdict") not in JOURNALABLE_VERDICTS:
            return {}
        completed[(row["target"], row["id"])] = row["verdict"]
    return completed


def mutation_journal_open(path, header):
    completed = mutation_journal_load(path, header)
    if completed:
        return completed
    if os.path.isfile(path):
        try:
            with io.open(path, encoding="utf-8") as handle:
                first = handle.readline()
            if first.strip() == _journal_header_line(header).strip():
                return {}
        except OSError:
            pass
        rejected = path + ".rejected"
        try:
            os.replace(path, rejected)
        except OSError:
            try:
                os.remove(path)
            except OSError:
                pass
    mutation_journal_create(path, header)
    return {}


def c4_clone_tree(src, dst):
    """Byte-copy a worker tree. robocopy is the fast path on this host."""
    if not os.path.isdir(src):
        return
    os.makedirs(dst, exist_ok=True)
    robocopy = shutil.which("robocopy")
    if robocopy:
        completed = subprocess.run(
            [
                robocopy, src, dst, "/E", "/COPY:DAT", "/R:1", "/W:1",
                "/MT:8", "/NFL", "/NDL", "/NJH", "/NJS", "/NP",
            ],
            check=False,
            capture_output=True,
        )
        # robocopy: 0-7 are success (files copied / extra / mismatched).
        if completed.returncode < 8:
            return
    shutil.copytree(src, dst, dirs_exist_ok=True)


def c4_grade_one_mutant(copy_root, env, rel_src, name, original, anchor, replacement, command):
    source_path = os.path.join(copy_root, rel_src.replace("/", os.sep))
    try:
        write_utf8(source_path, original.replace(anchor, replacement, 1))
        verdict, log = c4_run(command, copy_root, env)
        if verdict in ("HARNESS", "NOCOMPILE"):
            sys.stderr.write(
                "C4 diagnostic %s/%s [%s]:\n%s\n"
                % (rel_src, name, verdict, log)
            )
        return verdict
    finally:
        write_utf8(source_path, original)


def mutation_sweep_self_test():
    failures = []
    header = {
        "identity": "abc",
        "schema": MUTATION_JOURNAL_SCHEMA,
        "suite": "c4",
        "version": 1,
    }
    with tempfile.TemporaryDirectory(prefix="fsring-mut-journal-") as tmp:
        path = os.path.join(tmp, "j.jsonl")
        lock = threading.Lock()
        mutation_journal_create(path, header)
        mutation_journal_append(path, lock, "t.rs", "m1", "CAUGHT")
        mutation_journal_append(path, lock, "t.rs", "m2", "HARNESS")
        loaded = mutation_journal_load(path, header)
        if loaded != {("t.rs", "m1"): "CAUGHT"}:
            failures.append("journal load %r" % loaded)
        if mutation_journal_load(path, dict(header, identity="other")):
            failures.append("mismatched header was trusted")
        opened = mutation_journal_open(path, header)
        if opened != {("t.rs", "m1"): "CAUGHT"}:
            failures.append("journal open %r" % opened)
        empty = mutation_journal_open(os.path.join(tmp, "fresh.jsonl"), header)
        if empty != {}:
            failures.append("fresh journal %r" % empty)
        if c4_resolve_jobs(1) != 1 or c4_resolve_jobs(7) != 7:
            failures.append("jobs resolver ignored an explicit value")
        os.environ["FSRING_C4_MUTATION_NO_RESUME"] = "1"
        try:
            if c4_resume_enabled(True):
                failures.append("NO_RESUME did not disable resume")
        finally:
            del os.environ["FSRING_C4_MUTATION_NO_RESUME"]
        if not c4_resume_enabled(True) or c4_resume_enabled(False):
            failures.append("resume flag polarity")
    checks = 6
    for failure in failures:
        print("FAIL: %s" % failure)
    print(
        "mutation_sweep self-test: %s (%d checks, %d failures)"
        % ("PASS" if not failures else "FAIL", checks, len(failures))
    )
    return 1 if failures else 0

# The same-artifact attestation. Every C4 source anchor edits a file inside its
# closed identity domain, so applying one makes the tracked attestation stale by
# construction. That matters for exactly one reason: if an owning command
# verified the attestation, every single mutant would be "caught" by a generic
# identity mismatch instead of by the rule it names -- a suite reporting 100%
# while proving nothing.
#
# Today no owning command does. They are cargo tests, a PowerShell self-test,
# Python auditor self-tests, and the lifetime auditor's counted production
# mode; none enables `production-attested`, which is the only feature that turns
# the core build script's verification on. `c4_attestation_precondition` below
# re-checks that on every run rather than trusting this paragraph, and the runner
# proves the real tracked attestation is byte-identical afterwards.
C4_ATTESTATION = "driver/audit/c4-production-attestation.json"


def c4_attestation_precondition(targets):
    """Owning commands that would consume the production attestation.

    A nonempty answer means credit-by-stale-identity has become reachable and
    the suite must stop rather than report it as coverage. The fix at that point
    is the derived-attestation flow: save the baseline, apply the anchor,
    refresh the owning profile into an isolated derived document, and credit a
    refusal only when the declared oracle is that exact named row.
    """
    offenders = []
    for rel_src, (command, _floor) in sorted(targets.items()):
        parts = [str(part) for part in command]
        consumes = any("production-attested" in part for part in parts) or any(
            part == "fsring-fsd" for part in parts
        )
        if consumes:
            offenders.append(rel_src)
    return offenders


def c4_copy_workspace(repo, destination):
    """Create-new copy of the checkout, minus everything that is regenerated.

    The real checkout is never mutated: every operator edits this copy and the
    `finally` below restores it.
    """
    for directory, subdirectories, files in os.walk(repo):
        subdirectories[:] = [name for name in subdirectories
                             if name not in C4_SKIP_DIRS
                             and os.path.join(directory, name) != destination]
        relative = os.path.relpath(directory, repo)
        if relative.startswith(".."):
            continue
        target_dir = destination if relative == "." else os.path.join(destination, relative)
        os.makedirs(target_dir, exist_ok=True)
        for name in files:
            if name.endswith(".zip"):
                continue
            shutil.copy2(os.path.join(directory, name), os.path.join(target_dir, name))


def c4_powershell_evidence(log):
    """Exact strict JSON evidence from a PowerShell self-test, or zero.

    Closed over the two schemas that exist, never a wildcard: an unrecognised
    object returns zero, which grades HARNESS rather than quietly reading a
    mutant as survived. A PASS means the mutant was NOT caught; the magnitude
    is the evidence that the harness actually ran.
    """
    text = log.strip()
    start = text.find("{")
    if start < 0:
        return 0
    try:
        parsed = json.loads(text[start:].lstrip("﻿"))
    except ValueError:
        return 0
    schema = parsed.get("schema")
    if schema == "fsring-driver-smoke/v1":
        if parsed.get("mode") != "SelfTest":
            return 0
        roster = parsed.get("tests") or []
        if not roster:
            return 0
        return len(roster) if parsed.get("overall") == "PASS" else -len(roster)
    if schema == "fsring-c4-package-candidate-selftest/v1":
        checks = parsed.get("checks")
        if not isinstance(checks, int) or checks <= 0:
            return 0
        return checks if parsed.get("status") == "PASS" else -checks
    return 0


C4_PYTHON_SUMMARY = re.compile(
    r"^audit_c4_(imports|stack|lifetime) (self-test|production-check): (PASS|FAIL) "
    r"\((\d+) checks, (\d+) failures\)$", re.MULTILINE)

# Measured 2026-08-07. Before slice C4.1a: audit_c4_imports ran 30 checks and
# audit_c4_stack 44. After it: 56 and 72. The floor sits just under each so
# that a mutant which collapses the fixture set grades HARNESS instead of
# reporting a clean PASS over the handful of checks that survived. Raise these
# with the fixture count, never below what the tree actually runs.
#
# Re-measured 2026-08-08 after the final whole-branch review's fix wave:
# audit_c4_imports is unchanged at 57 (that file was not touched);
# audit_c4_stack grew 113 -> 132 for the caller-set decision (Critical 1),
# the DDI-without-a-declared-root refusal and the expansion-root key-set
# validation (Important 2), and their fixtures.
# Re-measured 2026-08-12 for Task 8 closure: lifetime is 278 checks; its floor
# leaves six checks of headroom while refusing any material fixture collapse.
C4_PYTHON_MIN_CHECKS = {
    "imports": 52,
    "lifetime": 272,
    "stack": 126,
}
C4_PYTHON_PRODUCTION_MIN_CHECKS = {"lifetime": 20}
NATIVE_MUTANT_SUMMARY = re.compile(
    r"^audit_c4_native_mutant production-check: "
    r"(PASS|CAUGHT|HARNESS|NOCOMPILE) \((\d+) checks, (\d+) failures\)$",
    re.MULTILINE,
)
NATIVE_MUTANT_SELFTEST_SUMMARY = re.compile(
    r"^audit_c4_native_mutant self-test: (PASS|FAIL) "
    r"\((\d+) checks, (\d+) failures\)$",
    re.MULTILINE,
)


def c4_python_evidence(log):
    """Checks run by an audit script's own self-test, negated when it failed.

    Zero means the run proved too little to grade: no summary line at all (a
    traceback, an import error) or fewer checks than the script is known to
    run. A mutant killed by a crash is not killed by a check, so it grades
    HARNESS rather than CAUGHT.
    """
    match = C4_PYTHON_SUMMARY.search(log)
    if not match:
        return 0
    which, mode, verdict, checks = (
        match.group(1), match.group(2), match.group(3), int(match.group(4))
    )
    floors = (C4_PYTHON_MIN_CHECKS if mode == "self-test"
              else C4_PYTHON_PRODUCTION_MIN_CHECKS)
    if which not in floors or checks < floors[which]:
        return 0
    return checks if verdict == "PASS" else -checks


def c4_run(command, cwd, env):
    code, log = sh(list(command), cwd, env)
    if any(part.endswith("audit_c4_native_mutant.py") for part in command):
        if "--self-test" in command:
            match = NATIVE_MUTANT_SELFTEST_SUMMARY.search(log)
            if match is None or int(match.group(2)) < 6:
                return "HARNESS", log
            return (
                "SURVIVED" if code == 0 and match.group(1) == "PASS" else "CAUGHT"
            ), log
        match = NATIVE_MUTANT_SUMMARY.search(log)
        if match is None or int(match.group(2)) != 3:
            return "HARNESS", log
        state = match.group(1)
        expected = {"PASS": 0, "CAUGHT": 1, "HARNESS": 2, "NOCOMPILE": 3}
        if code != expected[state]:
            return "HARNESS", log
        return {
            "PASS": "SURVIVED",
            "CAUGHT": "CAUGHT",
            "HARNESS": "HARNESS",
            "NOCOMPILE": "NOCOMPILE",
        }[state], log
    if command[0].startswith("powershell"):
        evidence = c4_powershell_evidence(log)
        if evidence == 0:
            return "HARNESS", log
        # The self-test's own PASS/FAIL is the kill signal.
        return ("SURVIVED" if code == 0 and evidence > 0 else "CAUGHT"), log
    if (
        any(part.endswith("audit_c4_lifetime.py") for part in command)
        and "--fail-fast" in command
    ):
        match = C4_PYTHON_SUMMARY.search(log)
        if match is not None and match.group(3) == "FAIL" and int(match.group(4)) >= 1:
            return "CAUGHT", log
    if any(part.endswith((
            "audit_c4_imports.py",
            "audit_c4_lifetime.py",
            "audit_c4_stack.py",
        ))
           for part in command):
        evidence = c4_python_evidence(log)
        if evidence == 0:
            return "HARNESS", log
        # A PASS here means the weakened check was not noticed by anything.
        return ("SURVIVED" if code == 0 and evidence > 0 else "CAUGHT"), log
    if executed(log) == 0:
        return ("NOCOMPILE" if code != 0 else "HARNESS"), log
    return ("SURVIVED" if code == 0 else "CAUGHT"), log


C4_MUTATION_ROW_KEYS = ("target", "id", "anchorCount", "owningCommand")
C4_PINNED_TOOLCHAINS = ("+1.82.0", "+1.85.0")


def validate_owning_command(command, origin="<command>"):
    """Refuse unpinned or unlocked cargo; pin PowerShell/python as invoked."""
    if not isinstance(command, (list, tuple)) or not command:
        raise SystemExit("%s owningCommand must be a nonempty argv list" % origin)
    parts = [str(part) for part in command]
    if parts[0] == "cargo":
        if len(parts) < 2 or parts[1] not in C4_PINNED_TOOLCHAINS:
            raise SystemExit(
                "%s cargo owningCommand is unpinned (need +1.82.0 or +1.85.0)"
                % origin
            )
        if "--locked" not in parts or "--offline" not in parts:
            raise SystemExit(
                "%s cargo owningCommand is unlocked (need --locked --offline)"
                % origin
            )
    return tuple(parts)


def load_c4_mutation_manifest(path):
    """Read the checked-in exact-one C4 roster. Never write it."""
    if not os.path.isfile(path):
        raise SystemExit("C4 mutation manifest is missing: %s" % path)
    with io.open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or document.get("schema") != "fsring-c4-mutations/v1":
        raise SystemExit("C4 mutation manifest schema is not fsring-c4-mutations/v1")
    rows = document.get("mutants")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("C4 mutation manifest mutants list is empty")
    seen_ids = []
    seen_pairs = []
    normalized = []
    for index, row in enumerate(rows):
        origin = "c4-mutations.json[%d]" % index
        if not isinstance(row, dict) or set(row) != set(C4_MUTATION_ROW_KEYS):
            raise SystemExit(
                "%s keys must be exactly target, id, anchorCount, owningCommand"
                % origin
            )
        if row["anchorCount"] != 1:
            raise SystemExit("%s anchorCount must equal 1" % origin)
        ident = row["id"]
        target = row["target"]
        if not isinstance(ident, str) or not ident:
            raise SystemExit("%s id is empty" % origin)
        if not isinstance(target, str) or not target:
            raise SystemExit("%s target is empty" % origin)
        if ident in seen_ids:
            raise SystemExit("duplicate C4 mutation id: %s" % ident)
        pair = (target, ident)
        if pair in seen_pairs:
            raise SystemExit("duplicate C4 mutation target/id: %s %s" % pair)
        seen_ids.append(ident)
        seen_pairs.append(pair)
        command = validate_owning_command(row["owningCommand"], origin)
        normalized.append(
            {
                "target": target,
                "id": ident,
                "anchorCount": 1,
                "owningCommand": command,
            }
        )
    return normalized


def c4_named_by_id():
    table = {}
    for name, path, anchor, replacement in C4_NAMED_MUTANTS:
        if name in table:
            raise SystemExit("duplicate C4_NAMED_MUTANTS id: %s" % name)
        table[name] = (path, anchor, replacement)
    return table


def run_c4_suite(repo, list_only=False, only_mutant=None, only_target=None,
                 skip_targets=(), roster=None, jobs=1, resume=True):
    results = []
    counts = {}
    if roster is None:
        raise SystemExit("C4 suite requires the checked-in mutation manifest")
    named = c4_named_by_id()
    roster_ids = [row["id"] for row in roster]
    extra_ids = sorted(set(named) - set(roster_ids))
    missing_ids = sorted(set(roster_ids) - set(named))
    if extra_ids or missing_ids:
        for ident in missing_ids:
            results.append(("<manifest>", ident, "HARNESS"))
        for ident in extra_ids:
            results.append(("<named-mutants>", ident, "HARNESS"))
        if list_only:
            return results, counts
    targets = {}
    for row in roster:
        ident = row["id"]
        target = row["target"]
        if ident in named and named[ident][0] != target:
            results.append((target, ident, "HARNESS"))
            continue
        targets.setdefault(target, []).append(row)
    command_by_target = {}
    for target, rows in targets.items():
        commands = {row["owningCommand"] for row in rows}
        if len(commands) != 1:
            results.append((target, "<owningCommand>", "HARNESS"))
            continue
        command_by_target[target] = next(iter(commands))

    offenders = c4_attestation_precondition(
        {path: (command_by_target[path], len(targets[path])) for path in command_by_target}
    )
    for rel_src in offenders:
        # Not a warning. A mutant graded by an identity mismatch is credited to
        # a rule it never exercised, and the whole sweep would then be a
        # measurement of the attestation rather than of the code.
        results.append((rel_src, "<owning-command-consumes-attestation>", "HARNESS"))

    attestation_path = os.path.join(repo, C4_ATTESTATION.replace("/", os.sep))
    baseline_attestation = None
    if os.path.exists(attestation_path):
        baseline_attestation = io.open(attestation_path, "rb").read()

    if list_only:
        for rel_src, rows in sorted(targets.items()):
            if rel_src in skip_targets:
                results.append((rel_src, "<skipped-by-request>", "SKIPPED"))
                continue
            source_path = os.path.join(repo, rel_src.replace("/", os.sep))
            if not os.path.isfile(source_path):
                results.append((rel_src, "<missing>", "HARNESS"))
                counts[rel_src] = 0
                continue
            original = io.open(source_path, encoding="utf-8").read()
            named_all = []
            for row in rows:
                ident = row["id"]
                if ident not in named:
                    results.append((rel_src, ident, "HARNESS"))
                    continue
                path, anchor, replacement = named[ident]
                named_all.append((ident, anchor, replacement))
            unresolved = [name for name, anchor, _ in named_all if original.count(anchor) != 1]
            for name in unresolved:
                results.append((rel_src, name, "HARNESS"))
            floor = len(rows)
            counts[rel_src] = len(named_all) - len(unresolved)
            if counts[rel_src] < floor:
                results.append((rel_src, "<floor>", "HARNESS"))
        return results, counts

    skip_targets = tuple(skip_targets)
    header = {
        "identity": c4_suite_identity(
            repo, roster, skip_targets, only_mutant, only_target
        ),
        "schema": MUTATION_JOURNAL_SCHEMA,
        "suite": "c4",
        "version": 1,
    }
    journal_lock = threading.Lock()
    journal_path = mutation_journal_path(header["identity"])
    completed = {}
    if c4_resume_enabled(resume):
        completed = mutation_journal_open(journal_path, header)
        if completed:
            sys.stderr.write(
                "C4 resume: replaying %d journalled verdicts from %s\n"
                % (len(completed), journal_path)
            )
    else:
        mutation_journal_create(journal_path, header)

    planned = []
    for rel_src, rows in sorted(targets.items()):
        command = command_by_target.get(rel_src)
        floor = len(rows)
        if rel_src in skip_targets:
            results.append((rel_src, "<skipped-by-request>", "SKIPPED"))
            continue
        if command is None:
            results.append((rel_src, "<owningCommand>", "HARNESS"))
            counts[rel_src] = 0
            continue
        source_path = os.path.join(repo, rel_src.replace("/", os.sep))
        if not os.path.isfile(source_path):
            results.append((rel_src, "<missing>", "HARNESS"))
            counts[rel_src] = 0
            continue
        original = io.open(source_path, encoding="utf-8").read()
        named_all = []
        for row in rows:
            ident = row["id"]
            if ident not in named:
                results.append((rel_src, ident, "HARNESS"))
                continue
            path, anchor, replacement = named[ident]
            named_all.append((ident, anchor, replacement))
        unresolved = [name for name, anchor, _ in named_all
                      if original.count(anchor) != 1]
        for name in unresolved:
            results.append((rel_src, name, "HARNESS"))
        counts[rel_src] = len(named_all) - len(unresolved)
        if counts[rel_src] < floor:
            results.append((rel_src, "<floor>", "HARNESS"))
        named_run = [
            row for row in named_all
            if (only_mutant is None or row[0] == only_mutant)
            and (only_target is None or rel_src == only_target)
            and row[0] not in unresolved
        ]
        planned.append((rel_src, command, original, named_run))

    pending = []
    for rel_src, command, original, named_run in planned:
        for name, anchor, replacement in named_run:
            key = (rel_src, name)
            if key in completed:
                results.append((rel_src, name, completed[key]))
                continue
            pending.append((rel_src, name, original, anchor, replacement, command))

    executed_verdicts = {}
    native_baseline_clean = False
    command_baseline_clean = {}
    if pending:
        worker_count = c4_resolve_jobs(jobs)
        if worker_count > len(pending):
            worker_count = len(pending)
        with tempfile.TemporaryDirectory(prefix="fsring-c4-mut-", dir=c4_work_root()) as work:
            copies = []
            envs = []
            copy0 = os.path.join(work, "repo-0")
            c4_copy_workspace(repo, copy0)
            env0 = c4_scratch_env(os.environ, work, 0)
            copies.append(copy0)
            envs.append(env0)

            pending_commands = {item[5] for item in pending}
            native_needed = NATIVE_MUTANT_PRODUCTION in pending_commands
            if native_needed:
                baseline_verdict, baseline_log = c4_run(
                    NATIVE_MUTANT_PRODUCTION, copy0, env0
                )
                native_baseline_clean = baseline_verdict == "SURVIVED"
                if baseline_verdict != "SURVIVED":
                    results.append(
                        ("driver/fsring-fsd/src/lifecycle.rs", "<native-baseline>", "HARNESS")
                    )
                    sys.stderr.write(
                        "C4 native baseline [%s]:\n%s\n"
                        % (baseline_verdict, baseline_log)
                    )
                else:
                    print("C4 native baseline: PASS (derived attestation, compile, audit)")
                command_baseline_clean[NATIVE_MUTANT_PRODUCTION] = native_baseline_clean
            for command in sorted(pending_commands, key=lambda parts: " ".join(parts)):
                if command in command_baseline_clean:
                    continue
                verdict, log = c4_run(command, copy0, env0)
                command_baseline_clean[command] = verdict == "SURVIVED"
                if verdict != "SURVIVED":
                    sys.stderr.write(
                        "C4 owning-command baseline [%s] for %s:\n%s\n"
                        % (verdict, " ".join(str(part) for part in command), log)
                    )

            runnable = []
            skipped_red = set()
            for rel_src, name, original, anchor, replacement, command in pending:
                if not command_baseline_clean.get(command, True):
                    skipped_red.add(rel_src)
                    continue
                mutant_command = command
                if command == NATIVE_MUTANT_PRODUCTION and native_baseline_clean:
                    mutant_command = command + ("--baseline-gate", "pass")
                runnable.append(
                    (rel_src, name, original, anchor, replacement, mutant_command)
                )
            for rel_src in sorted(skipped_red):
                results.append((rel_src, "<owning-command-baseline>", "HARNESS"))

            if worker_count > 1 and runnable:
                for index in range(1, worker_count):
                    copy_n = os.path.join(work, "repo-%d" % index)
                    c4_clone_tree(copy0, copy_n)
                    c4_clone_tree(
                        os.path.join(work, "cargo-target-0"),
                        os.path.join(work, "cargo-target-%d" % index),
                    )
                    copies.append(copy_n)
                    envs.append(c4_scratch_env(os.environ, work, index))
                sys.stderr.write(
                    "C4 parallel: %d workers, %d mutants remaining\n"
                    % (worker_count, len(runnable))
                )

            total = len(completed) + len(runnable)
            progress = {"done": len(completed)}

            def record_verdict(rel_src, name, verdict):
                mutation_journal_append(
                    journal_path, journal_lock, rel_src, name, verdict
                )
                with journal_lock:
                    executed_verdicts[(rel_src, name)] = verdict
                    progress["done"] += 1
                    sys.stderr.write(
                        "C4 progress %d/%d %s %s %s\n"
                        % (progress["done"], total, verdict, rel_src, name)
                    )
                    sys.stderr.flush()

            if worker_count <= 1 or len(runnable) <= 1:
                copy_root, env = copies[0], envs[0]
                for rel_src, name, original, anchor, replacement, command in runnable:
                    verdict = c4_grade_one_mutant(
                        copy_root, env, rel_src, name, original, anchor, replacement, command
                    )
                    record_verdict(rel_src, name, verdict)
            else:
                task_queue = queue.Queue()
                threads = []

                def worker(copy_root, env):
                    while True:
                        spec = task_queue.get()
                        try:
                            if spec is None:
                                return
                            rel_src, name, original, anchor, replacement, command = spec
                            verdict = c4_grade_one_mutant(
                                copy_root, env, rel_src, name, original,
                                anchor, replacement, command
                            )
                            record_verdict(rel_src, name, verdict)
                        finally:
                            task_queue.task_done()

                for index in range(worker_count):
                    thread = threading.Thread(
                        target=worker,
                        args=(copies[index], envs[index]),
                        daemon=True,
                    )
                    thread.start()
                    threads.append(thread)
                for spec in runnable:
                    task_queue.put(spec)
                for _ in range(worker_count):
                    task_queue.put(None)
                for thread in threads:
                    thread.join()

            for rel_src, name, _original, _anchor, _replacement, _command in runnable:
                verdict = executed_verdicts.get((rel_src, name))
                if verdict is None:
                    results.append((rel_src, name, "HARNESS"))
                else:
                    results.append((rel_src, name, verdict))

    # Every anchor was applied to the workspace copy, so the tracked attestation
    # must be byte-identical. Restoring it and reporting is better than leaving
    # a tree whose next production build fails for a reason nobody can trace.
    if baseline_attestation is not None:
        current = io.open(attestation_path, "rb").read()
        if current != baseline_attestation:
            io.open(attestation_path, "wb").write(baseline_attestation)
            results.append((C4_ATTESTATION, "<baseline-attestation-restored>", "HARNESS"))
    return results, counts


def executed(log):
    return sum(int(n) for n in re.findall(r"(\d+) (?:passed|failed)\b", log))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="enumerate mutants and exit")
    ap.add_argument(
        "--json",
        help="C4 suite with --list: write the enumerated roster here (the "
             "checked-in manifest stays read-only). C4 suite without --list: "
             "roster input override. Default suite: write results here.",
    )
    ap.add_argument("--measure-floors", action="store_true",
                    help="print this source's per-operator mutant counts and "
                         "exit, for recording in FLOORS")
    ap.add_argument("--src", default=REL_SRC,
                    help="repo-relative source file to mutate "
                         "(default: " + REL_SRC + ")")
    ap.add_argument("--suite", choices=("c4",),
                    help="run an additive named suite instead of the default "
                         "single-source sweep; it never substitutes for it")
    ap.add_argument("--only-c4-mutant",
                    help="run one exact C4 named mutant for focused TDD/debugging")
    ap.add_argument("--only-c4-target",
                    help="run the exact C4 named mutants owned by one source")
    ap.add_argument("--skip-c4-target", action="append", default=[],
                    metavar="REL_SRC",
                    help="exclude one source target from this run; repeatable. "
                         "The run is then PARTIAL by construction and says so: "
                         "skipped targets are excluded from the roster count and "
                         "from the floor check, and their mutants are not "
                         "mandatory. Never record a skipped run as a full suite.")
    ap.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="parallel workers with private trees (default: min(4, CPU), "
             "or FSRING_C4_MUTATION_JOBS). Same mutants, same oracles.",
    )
    ap.add_argument(
        "--no-resume",
        action="store_true",
        help="ignore the crash journal and re-execute every mutant",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the crash journal and job resolver; do not mutate sources",
    )
    args = ap.parse_args()

    c4_emit_marker("PRE")
    try:
        return _main(args)
    finally:
        c4_emit_marker("POST")


def _main(args):
    if args.self_test:
        return mutation_sweep_self_test()
    if args.suite == "c4":
        repo = os.getcwd()
        # With --list the checked-in manifest is READ-ONLY and --json names an
        # output: row 13 of the source gate writes the enumeration into its
        # external attempt and the runner compares it with the authoritative
        # file. Letting --json redirect the input there would compare a copy
        # with itself.
        roster_output = args.json if args.list else None
        roster_path = os.path.join("driver", "audit", "c4-mutations.json")
        if args.json and not args.list:
            roster_path = args.json
        try:
            validate_owning_command(("cargo", "test"))
            print("FAIL: unpinned cargo owningCommand was accepted")
            return 1
        except SystemExit as error:
            if "unpinned" not in str(error):
                print("FAIL: %s" % error)
                return 1
        try:
            validate_owning_command(("cargo", "+1.85.0", "test"))
            print("FAIL: unlocked cargo owningCommand was accepted")
            return 1
        except SystemExit as error:
            if "unlocked" not in str(error):
                print("FAIL: %s" % error)
                return 1
        try:
            roster = load_c4_mutation_manifest(roster_path)
        except SystemExit as error:
            print("FAIL: %s" % error)
            return 1
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print("FAIL: C4 mutation manifest is unreadable: %s" % error)
            return 1
        results, counts = run_c4_suite(
            repo, list_only=args.list, only_mutant=args.only_c4_mutant,
            only_target=args.only_c4_target,
            skip_targets=tuple(args.skip_c4_target),
            roster=roster,
            jobs=c4_resolve_jobs(args.jobs),
            resume=not args.no_resume)
        failures = []
        floors = {}
        for row in roster:
            if row["target"] in args.skip_c4_target:
                continue
            floors[row["target"]] = floors.get(row["target"], 0) + 1
        for rel_src, floor in sorted(floors.items()):
            observed = counts.get(rel_src, 0)
            print("%-52s %3d (floor %d)" % (rel_src, observed, floor))
            if observed < floor:
                failures.append("%s is below its mutation floor" % rel_src)
        if args.list:
            for rel_src, name, verdict in results:
                if verdict == "HARNESS" and name not in ("<floor>", "<missing>"):
                    print("HARNESS    %-52s %s" % (rel_src, name))
                    failures.append(
                        "%s/%s: exact-one roster or owning-command seam failed"
                        % (rel_src, name))
            if roster_output:
                # Reconstructed from the rows the loader validated and this run
                # actually walked -- not copied from the file -- so a drift
                # between the enumeration and the manifest is visible.
                document = {
                    "schema": "fsring-c4-mutations/v1",
                    "mutants": [
                        {
                            "target": row["target"],
                            "id": row["id"],
                            "anchorCount": row["anchorCount"],
                            "owningCommand": list(row["owningCommand"]),
                        }
                        for row in roster
                    ],
                }
                io.open(roster_output, "w", encoding="utf-8", newline="").write(
                    json.dumps(document, indent=2) + "\n")
            print("c4 list: %d mutants, %d targets" % (len(roster), len(floors)))
            for failure in failures:
                print("FAIL: %s" % failure)
            return 1 if failures else 0
        mandatory = {
            row["id"]
            for row in roster
            if row["target"] not in args.skip_c4_target
            if args.only_c4_mutant is None or row["id"] == args.only_c4_mutant
            if args.only_c4_target is None or row["target"] == args.only_c4_target
        }
        if (args.only_c4_mutant is not None or args.only_c4_target is not None) and not mandatory:
            failures.append("unknown focused C4 selection")
        caught = set()
        for rel_src, name, verdict in results:
            print("%-10s %-52s %s" % (verdict, rel_src, name))
            if verdict == "CAUGHT":
                caught.add(name)
            elif name in mandatory or verdict != "CAUGHT":
                failures.append("%s/%s: %s" % (rel_src, name, verdict))
        for name in sorted(mandatory - caught):
            failures.append("mandatory mutant %s was not killed" % name)
        for failure in failures:
            print("FAIL: %s" % failure)
        print("c4 suite: %s (%d mandatory, %d caught)" % (
            "PASS" if not failures else "FAIL", len(mandatory), len(caught)))
        return 1 if failures else 0

    repo = os.getcwd()
    rel_src = args.src.replace(chr(92), "/")
    allowlist = ALLOWLISTS.get(rel_src, {})
    src_path = os.path.join(repo, rel_src)
    if not os.path.isfile(src_path):
        print("run me from the repository root", file=sys.stderr)
        return 2
    original = io.open(src_path, encoding="utf-8").read()

    if args.measure_floors:
        counts = {}
        for _, desc, _ in build_mutants(original, {}):
            tag = desc[:3]
            counts[tag] = counts.get(tag, 0) + 1
        print(f"measured floors for {rel_src}:")
        print("    " + ", ".join(f'"{t}": {counts[t]}' for t in sorted(counts)))
        print("record these in FLOORS deliberately; an operator absent here is "
              "absent, not blind, and must be left OUT rather than floored at 0")
        return 0

    floors = FLOORS.get(rel_src)
    if not floors:
        print(f"no anti-rot floors recorded for {rel_src}. Run with "
              "--measure-floors and add them to FLOORS. Refusing to sweep a "
              "source with no anti-rot protection.", file=sys.stderr)
        return 2
    mutants = build_mutants(original, floors)

    if args.list:
        for ident, desc, _ in mutants:
            print(f"{desc}\n    id: {ident}")
        covered = sum(1 for i, _, _ in mutants
                      if i in allowlist or i.split("#drop")[0] in allowlist)
        # Entries and covered mutants are DIFFERENT numbers: an allowlisted
        # guard covers its own dropped-conjunct variants, so 12 entries can
        # cover 14 mutants. Reporting only one of them invites a reader to
        # conclude entries were lost when they were not.
        print(f"\n{len(mutants)} mutants; {len(allowlist)} allowlist entries "
              f"covering {covered} mutants in {rel_src}")
        return 0

    header = {
        "identity": default_sweep_identity(repo, rel_src),
        "schema": MUTATION_JOURNAL_SCHEMA,
        "src": rel_src,
        "suite": "default",
        "version": 1,
    }
    journal_path = mutation_journal_path("default-" + header["identity"])
    journal_lock = threading.Lock()
    completed = {}
    if c4_resume_enabled(not args.no_resume):
        completed = mutation_journal_open(journal_path, header)
        if completed:
            print(
                "resume: replaying %d journalled verdicts from %s"
                % (len(completed), journal_path),
                file=sys.stderr,
            )
    else:
        mutation_journal_create(journal_path, header)

    remaining = [
        (ident, desc, mutated)
        for ident, desc, mutated in mutants
        if (rel_src, ident) not in completed
    ]
    fresh = {}
    work = tempfile.mkdtemp(prefix="fsring-mutation-", dir=c4_work_root())
    try:
        if remaining:
            # The tests `include_str!` the docs/design/ documents and
            # driver/README.md, so the copy needs those too.
            os.makedirs(os.path.join(work, "driver"))
            shutil.copytree(
                os.path.join(repo, "docs", "design"),
                os.path.join(work, "docs", "design"),
            )
            ignore = shutil.ignore_patterns("target")
            shutil.copytree(os.path.join(repo, "driver"), os.path.join(work, "driver"),
                            ignore=ignore, dirs_exist_ok=True)
            shutil.copytree(os.path.join(repo, "fsring-abi"), os.path.join(work, "fsring-abi"),
                            ignore=ignore)
            wsrc = os.path.join(work, rel_src)
            env = c4_scratch_env(os.environ, work)
            env["CARGO_TARGET_DIR"] = os.path.join(work, "_target")
            cmd = ["cargo", "+1.85.0", "test", "--manifest-path",
                   os.path.join(work, "driver", "Cargo.toml"), "-p", "fsring-core", "--lib"]

            rc, log = sh(cmd, work, env)
            base = executed(log)
            if rc != 0 or base == 0:
                print(f"BASELINE NOT GREEN (exit {rc}, executed {base})", file=sys.stderr)
                print(log[-4000:], file=sys.stderr)
                return 2
            print(f"baseline: {base} tests green")
            print(f"{len(mutants)} mutants ({len(allowlist)} allowlisted) over {rel_src}\n")

            for ident, desc, mutated in remaining:
                write_utf8(wsrc, mutated)
                rc, log = sh(cmd, work, env)
                ran = executed(log)
                if "error[E" in log or "error: could not compile" in log:
                    verdict = "NOCOMPILE"
                elif ran == 0:
                    verdict = "HARNESS"
                elif rc != 0:
                    verdict = "CAUGHT"
                else:
                    verdict = "SURVIVED"
                fresh[ident] = (verdict, ran)
                mutation_journal_append(
                    journal_path, journal_lock, rel_src, ident, verdict
                )
            write_utf8(wsrc, original)
        else:
            print(f"{len(mutants)} mutants ({len(allowlist)} allowlisted) over {rel_src}\n")

        rows, bad = [], []
        for n, (ident, desc, _mutated) in enumerate(mutants, 1):
            replayed = False
            if ident in fresh:
                verdict, ran = fresh[ident]
            elif (rel_src, ident) in completed:
                verdict, ran = completed[(rel_src, ident)], -1
                replayed = True
            else:
                verdict, ran = "HARNESS", 0
            # A guard no input can reach cannot be reached by a weakening of
            # it either, so an allowlisted guard covers its own dropped-conjunct
            # variants. Nothing else is inherited.
            allowed = ident in allowlist or ident.split("#drop")[0] in allowlist
            tag = desc[:3]
            if verdict == "HARNESS":
                bad.append(("harness executed no tests", ident, desc))
            elif verdict == "SURVIVED" and not allowed and tag not in NON_BLOCKING:
                bad.append(("unwatched guard", ident, desc))
            elif verdict == "CAUGHT" and allowed:
                bad.append(("allowlisted but now caught -- remove it", ident, desc))
            rows.append({"id": ident, "desc": desc, "verdict": verdict,
                         "allowlisted": allowed, "executed": ran,
                         "replayed": replayed})
            marker = " (allowed)" if allowed else ""
            if replayed:
                marker += " (replayed)"
            print(f"  {n:>3}/{len(mutants)}  {verdict:<9}{marker}  {desc}")

        # An allowlist entry matching NO mutant is a stale proof: the guard it
        # exempted no longer exists, or --src moved and the entry belongs to a
        # different file. The existing "allowlisted but now caught" check cannot
        # see this -- it only inspects mutants that ran -- so a re-pointed sweep
        # would otherwise report PASS over a proof set it does not have.
        ids = {r["id"] for r in rows}
        stems = {i.split("#drop")[0] for i in ids}
        for entry in allowlist:
            if entry not in ids and entry not in stems:
                bad.append(("allowlisted mutant does not exist -- stale proof",
                            entry, "no mutant in " + rel_src + " matches this id"))

        counts = {}
        for r in rows:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print("\n" + "  ".join(f"{k} {v}" for k, v in sorted(counts.items())))

        # Non-blocking families: report the split, and hold the CAUGHT floor.
        for tag in sorted(NON_BLOCKING):
            fam = [r for r in rows if r["desc"].startswith(tag)]
            caught = sum(1 for r in fam if r["verdict"] == "CAUGHT")
            surv = sum(1 for r in fam if r["verdict"] == "SURVIVED")
            print(f"{tag} (reported, non-blocking): {len(fam)} mutants, "
                  f"{caught} caught, {surv} unreached")
            floor = MIN_CAUGHT.get(rel_src, {}).get(tag)
            if floor is not None and caught < floor:
                bad.append((
                    f"{tag} caught {caught}, floor {floor} -- a defensive branch "
                    "that used to be exercised no longer is",
                    tag, f"{tag} family"))
        if args.json:
            io.open(args.json, "w", encoding="utf-8").write(json.dumps(rows, indent=1))
        if bad:
            print(f"\nMUTATION SWEEP: FAIL ({len(bad)})")
            for why, ident, desc in bad:
                print(f"  {why}\n    {desc}\n    id: {ident}")
            return 1
        print("\nMUTATION SWEEP: PASS")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


sys.exit(main())
