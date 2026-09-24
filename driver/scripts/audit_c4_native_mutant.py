#!/usr/bin/env python
"""Compile-validity owner for production fsring-fsd C4 mutants."""

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tempfile


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
    "driver/scripts/audit_c4_production_graph.py",
    "driver/audit/c4-production-graph.json",
)
AUDIT_SUMMARY = re.compile(
    r"^audit_c4_lifetime production-check: (PASS|FAIL) "
    r"\((\d+) checks, (\d+) failures\)$",
    re.MULTILINE,
)
# A production gate refusing to attest the mutated source. The refresh stage
# runs the graph gates before anything else can look at the mutation, so this
# is the shape a mutation takes when the graph gate is the thing that sees it.
# Anchored on the gate's own refusal sentence rather than on any mutant's
# message, so it cannot be satisfied by an unrelated stderr line.
GATE_REFUSAL = re.compile(
    r"^FAIL: gate \S+ did not pass; "
    r"refresh never attests a failing row: ",
    re.MULTILINE,
)
# The gate's *other* way of observing a mutation. A plant that adds or removes a
# definition changes a count the manifest records, and the refresh refuses with
# this instead of with the sentence above -- so a real detection was landing as
# HARNESS. `native-terminal-legacy-owner-split-restored` sat in that state from
# the moment `ambiguousUnstaged` arrived at Task 20.
#
# It cannot be credited unconditionally. The same sentence appears when the
# manifest has drifted and no mutation is involved, and crediting that is
# exactly the "caught by a generic identity mismatch instead of by the rule it
# names" failure `mutation_sweep.py` documents. So it counts only when the
# caller states that the gate passed on the unmutated tree, which is a fact
# this helper cannot establish for itself: by the time it runs, the tree is
# already mutated.
MANIFEST_REFUSAL = re.compile(
    r"^FAIL: ambiguousUnstaged is stale: ",
    re.MULTILINE,
)


def classify(refresh_code, compile_code, audit_code, audit_checks,
             refresh_log="", baseline_gate=False):
    if refresh_code != 0:
        # Two unrelated failures used to share this verdict. A production gate
        # that REFUSED to attest the mutated source has OBSERVED the mutation:
        # that is a detection by this helper's own first stage, not a run that
        # proves nothing. Anything else that stops the refresh -- a missing
        # interpreter, an exhausted disk, a concurrent writer -- still proves
        # nothing and is still HARNESS.
        if GATE_REFUSAL.search(refresh_log):
            return "CAUGHT"
        if baseline_gate and MANIFEST_REFUSAL.search(refresh_log):
            # With the baseline verified clean, a count that no longer matches
            # can only have been changed by the mutation.
            return "CAUGHT"
        return "HARNESS"
    if compile_code != 0:
        return "NOCOMPILE"
    if audit_checks < 20:
        return "HARNESS"
    if audit_code == 0:
        return "PASS"
    if audit_code == 1:
        return "CAUGHT"
    return "HARNESS"


def run(command, root, env):
    completed = subprocess.run(
        command,
        cwd=root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode, completed.stdout + completed.stderr


def initialize_identity_git(root):
    """Stage the auditor's exact closed identity domain in the copied repo."""
    identity = []
    for package in IDENTITY_PACKAGE_ROOTS:
        base = os.path.join(root, package.replace("/", os.sep))
        for current, directories, files in os.walk(base):
            directories[:] = sorted(name for name in directories if name != "target")
            for name in sorted(files):
                if name.endswith(".rs"):
                    identity.append(
                        os.path.relpath(os.path.join(current, name), root).replace(os.sep, "/")
                    )
    identity.extend(IDENTITY_EXTRA_FILES)
    if len(identity) != len(set(identity)):
        raise RuntimeError("identity roster contains duplicate paths")
    missing = [path for path in identity if not os.path.isfile(os.path.join(root, path))]
    if missing:
        raise RuntimeError("identity roster is missing: %s" % ", ".join(missing))
    code, log = run(("git", "init", "--quiet"), root, os.environ.copy())
    if code != 0:
        raise RuntimeError("git init failed: %s" % log)
    code, log = run(("git", "add", "--force", "--") + tuple(sorted(identity)), root, os.environ.copy())
    if code != 0:
        raise RuntimeError("git add identity failed: %s" % log)
    return len(identity)


def execute(root, baseline_gate=False):
    root = os.path.abspath(root)
    env = os.environ.copy()
    # wdk-build 0.5.1 locates the top-level manifest by walking from OUT_DIR
    # to Cargo.lock and explicitly cannot use a target directory outside that
    # ancestry. This remains an isolated target in the copied repository, and
    # lets all native mutants reuse one incremental cache without touching the
    # real checkout's driver/target.
    env["CARGO_TARGET_DIR"] = os.path.join(root, "driver", "target-c4-native")
    try:
        identity_count = initialize_identity_git(root)
        with io.open(
            os.path.join(root, "driver", "audit", "c4-production-attestation.json"),
            encoding="utf-8",
        ) as handle:
            profile = json.load(handle)["profile"]
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        return "HARNESS", 0, "identity setup failed: %s" % error

    refresh = (
        sys.executable,
        "driver/scripts/audit_c4_production_graph.py",
        "--manifest",
        "driver/audit/c4-production-graph.json",
        "--refresh-attestation",
        "--profile",
        profile,
    )
    refresh_code, refresh_log = run(refresh, root, env)
    if refresh_code != 0:
        # Three positions, not one, for the same reason the compile stage below
        # documents: the outer sweep treats the count as this helper's fixed
        # summary schema and downgrades anything else to HARNESS, which is what
        # used to hide a gate refusal even once it was classified correctly.
        return (
            classify(refresh_code, 0, 0, 0, refresh_log, baseline_gate),
            3,
            "attestation refresh failed:\n%s" % refresh_log,
        )

    helper = os.path.join(root, "driver", "scripts", "_in_devenv.cmd")
    cargo = (
        "cargo +1.85.0 check --manifest-path Cargo.toml -p fsring-fsd "
        "--target x86_64-pc-windows-msvc --features platform-win10 "
        "--no-default-features --locked --offline"
    )
    compile_code, compile_log = run(
        ("cmd.exe", "/d", "/c", "call", helper, "amd64", cargo), root, env
    )
    if compile_code != 0:
        # The outer sweep treats the count as this helper's fixed summary
        # schema, not the number of stages that happened to complete. Preserve
        # all three positions so it can retain the NOCOMPILE classification.
        return "NOCOMPILE", 3, "native compile failed:\n%s" % compile_log

    audit = (
        sys.executable,
        "driver/scripts/audit_c4_lifetime.py",
        "--production-check",
        "--root",
        ".",
        "--source-root",
        "driver/fsring-core/src",
        "--source-root",
        "driver/fsring-fsd/src",
    )
    audit_code, audit_log = run(audit, root, env)
    summary = AUDIT_SUMMARY.search(audit_log)
    if summary is None:
        return "HARNESS", 3, "native audit emitted no counted summary:\n%s" % audit_log
    checks = int(summary.group(2))
    verdict = classify(refresh_code, compile_code, audit_code, checks)
    detail = "identityFiles=%d profile=%s auditChecks=%d\n%s" % (
        identity_count,
        profile,
        checks,
        audit_log,
    )
    return verdict, 3, detail


def self_test():
    gate_refusal_log = (
        "FAIL: gate task12_r3_cutover_has_exactly_one_terminal_delete_path did "
        "not pass; refresh never attests a failing row: closed direct caller "
        "roster for x#queue_cell_finalizer has unexpected callers y#resolve\n"
    )
    manifest_refusal_log = (
        "FAIL: ambiguousUnstaged is stale: into_parts declared 23, tree has 24"
    )
    cases = (
        ((0, 0, 0, 32), "PASS"),
        ((1, 0, 0, 32), "HARNESS"),
        # A gate that refused the mutated source saw the mutation.
        ((1, 0, 0, 32, gate_refusal_log), "CAUGHT"),
        # Anti-vacuity for the row above: a refresh that died for any other
        # reason still proves nothing, however loud its log is.
        ((1, 0, 0, 32, "python: can't open file 'audit_c4_production_graph.py'"),
         "HARNESS"),
        # And a gate refusal only counts when the refresh actually failed.
        ((0, 0, 0, 32, gate_refusal_log), "PASS"),
        # A manifest-consistency refusal is a detection -- but only when the
        # caller has verified the baseline. Both rows, because the whole point
        # is that the unverified case must NOT be credited.
        ((1, 0, 0, 32, manifest_refusal_log, True), "CAUGHT"),
        ((1, 0, 0, 32, manifest_refusal_log, False), "HARNESS"),
        # A verified baseline does not turn every refresh failure into a
        # detection either.
        ((1, 0, 0, 32, "python: can't open file 'x.py'", True), "HARNESS"),
        ((0, 2, 0, 32), "NOCOMPILE"),
        ((0, 0, 1, 32), "CAUGHT"),
        ((0, 0, 2, 32), "HARNESS"),
        ((0, 0, 0, 0), "HARNESS"),
    )
    failures = []
    for inputs, expected in cases:
        actual = classify(*inputs)
        if actual != expected:
            failures.append("%r classified %s, expected %s" % (inputs, actual, expected))

    # Exercise execute(), not only the pure classifier: the outer mutation
    # runner requires the helper's summary to retain the exact three-check
    # schema even when native compilation stops before the audit stage.
    with tempfile.TemporaryDirectory(prefix="c4-native-nocompile-") as work:
        audit_dir = os.path.join(work, "driver", "audit")
        os.makedirs(audit_dir)
        with io.open(
            os.path.join(audit_dir, "c4-production-attestation.json"),
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump({"profile": "r5-stage"}, handle)
        original_initialize = initialize_identity_git
        original_run = run
        calls = iter(((0, "refresh passed"), (1, "compile failed")))
        try:
            globals()["initialize_identity_git"] = lambda _root: 1
            globals()["run"] = lambda _command, _root, _env: next(calls)
            verdict, reported_checks, _detail = execute(work)
        finally:
            globals()["initialize_identity_git"] = original_initialize
            globals()["run"] = original_run
        if (verdict, reported_checks) != ("NOCOMPILE", 3):
            failures.append(
                "compile failure summarized %s/%d, expected NOCOMPILE/3"
                % (verdict, reported_checks)
            )
    checks = len(cases) + 1
    for failure in failures:
        print("FAIL: %s" % failure)
    print(
        "audit_c4_native_mutant self-test: %s (%d checks, %d failures)"
        % ("PASS" if not failures else "FAIL", checks, len(failures))
    )
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", default=".")
    # Stated by the caller, never assumed. Absent, the helper keeps its old,
    # stricter behaviour and reports HARNESS for a manifest refusal.
    parser.add_argument("--baseline-gate", choices=("pass", "fail"))
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    verdict, checks, detail = execute(args.root, args.baseline_gate == "pass")
    failures = 0 if verdict == "PASS" else 1
    print(detail.rstrip())
    print(
        "audit_c4_native_mutant production-check: %s (%d checks, %d failures)"
        % (verdict, checks, failures)
    )
    return {"PASS": 0, "CAUGHT": 1, "HARNESS": 2, "NOCOMPILE": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main())
