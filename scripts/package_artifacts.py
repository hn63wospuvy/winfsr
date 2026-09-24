#!/usr/bin/env python3
"""Deterministic FSRING ABI 2.1 distribution archive builder.

Base: the verbatim implementation from
``docs/superpowers/plans/2026-07-15-fsring-abi-v2.md`` Task 11 Step 1. The
only Wave 15 extension is the exact ABI 2.1 archive-membership assertion:
``ABI_REQUIRED_MEMBERS`` (2.1 marker files that MUST be present in
``fsring-abi.zip``) and ``ABI_FORBIDDEN_MEMBERS`` (ABI-2.0-only files that MUST
be absent), enforced by ``verify_archive`` and wired through ``main``. The
spec archive keeps its exact-13-file membership. A ``--verify-existing`` path
evaluates the membership assertion against the already-present archives
without rebuilding (used to capture RED against the frozen ABI-2.0 archive).

``--output-directory <dir>`` (added by Task 28) redirects both archives to an
external directory. The C4 recovery source gate runs rows 30 and 32 that way so
an attempt writes and verifies its own copies; when it is supplied the ignored
worktree archives are never opened for writing, which is what stops a Task 29
run from quietly regenerating a checked-in artifact.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC_ROOT = ROOT / "docs" / "design"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
SPEC_FILES = [
    "00-INDEX.md", "01-principles-architecture.md", "02-transport.md",
    "03-messages.md", "04-object-model.md", "05-irp-dispatch.md",
    "06-locking.md", "07-cache-mm.md", "08-passthrough.md",
    "09-security.md", "10-lifecycle.md", "11-rust-implementation.md",
    "12-test-plan.md",
]
SKIP_PARTS = {"target", ".git", ".idea", ".vscode", "__pycache__"}
SKIP_SUFFIXES = {".obj", ".pdb", ".ilk", ".pyc", ".tmp"}

# Wave 15 ABI 2.1 archive-membership assertion (the only extension over the
# verbatim v2 implementation). These files distinguish the activated ABI 2.1
# source tree from the frozen ABI-2.0 archive: the generated header, the
# cbindgen config, the ARM64/x64 C 2.1 layout test, the split module
# directories, and the 2.1 test suites. The lone forbidden marker is the flat
# ``src/msgs.rs`` module the 2.1 tree replaced with the ``src/msgs/`` directory.
ABI_REQUIRED_MEMBERS = {
    "fsring-abi/include/fsring_abi.h",
    "fsring-abi/cbindgen.toml",
    "fsring-abi/tests/c/layout_v21.c",
    "fsring-abi/src/msgs/mod.rs",
    "fsring-abi/src/control/mod.rs",
    "fsring-abi/src/durable/mod.rs",
    "fsring-abi/src/validate/mod.rs",
    "fsring-abi/src/msgs/recovery.rs",
    "fsring-abi/src/msgs/notify.rs",
    "fsring-abi/src/msgs/query.rs",
    "fsring-abi/src/msgs/mutation.rs",
    "fsring-abi/tests/boot_v21.rs",
    "fsring-abi/tests/semantics_v21.rs",
    "fsring-abi/tests/notify_v21.rs",
    "fsring-abi/tests/control_v21.rs",
    "fsring-abi/tests/messages_v21.rs",
    "fsring-abi/tests/durable_v21.rs",
    "fsring-abi/tests/durable_payloads_v21.rs",
    "fsring-abi/tests/digest_v21.rs",
    "fsring-abi/tests/foundations_v21.rs",
    "fsring-abi/tests/header_v21.rs",
}
ABI_FORBIDDEN_MEMBERS = {
    "fsring-abi/src/msgs.rs",
}

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def spec_entries() -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    for name in SPEC_FILES:
        source = SPEC_ROOT / name
        if not source.is_file():
            raise SystemExit(f"missing specification source: {source}")
        entries.append((f"spec/{name}", source.read_bytes()))
    return entries

def abi_entries() -> list[tuple[str, bytes]]:
    source_root = ROOT / "fsring-abi"
    if not (source_root / "Cargo.toml").is_file():
        raise SystemExit(f"missing ABI source tree: {source_root}")
    entries: list[tuple[str, bytes]] = []
    for source in sorted(source_root.rglob("*"), key=lambda p: p.as_posix()):
        relative = source.relative_to(ROOT)
        if not source.is_file():
            continue
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if source.suffix.lower() in SKIP_SUFFIXES or source.name.endswith("~"):
            continue
        entries.append((relative.as_posix(), source.read_bytes()))
    return entries

def directory_names(entries: list[tuple[str, bytes]]) -> list[str]:
    names: set[str] = set()
    for name, _ in entries:
        parts = name.split("/")[:-1]
        for count in range(1, len(parts) + 1):
            names.add("/".join(parts[:count]) + "/")
    return sorted(names)

def info(name: str, is_directory: bool) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name, FIXED_TIME)
    entry.create_system = 3
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = ((0o40755 if is_directory else 0o100644) << 16)
    if is_directory:
        entry.external_attr |= 0x10
    return entry

def write_archive(path: Path, entries: list[tuple[str, bytes]]) -> None:
    ordered = sorted(entries, key=lambda item: item[0])
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, allowZip64=True) as archive:
        for name in directory_names(ordered):
            archive.writestr(info(name, True), b"", compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
        for name, data in ordered:
            archive.writestr(info(name, False), data, compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)

def verify_archive(path: Path, prefix: str, expected_files: set[str] | None,
                   required_members: set[str] | None = None,
                   forbidden_members: set[str] | None = None,
                   source_entries: list[tuple[str, bytes]] | None = None) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        names = [entry.filename for entry in archive.infolist()]
        member_names = set(names)
        # Wave 15 ABI 2.1 membership assertion (evaluated first so its failure
        # identity — missing required + present forbidden — is the surfaced
        # error). Additive over the verbatim checks that follow.
        missing = sorted(required_members - member_names) if required_members else []
        present_forbidden = sorted(forbidden_members & member_names) if forbidden_members else []
        if missing or present_forbidden:
            raise SystemExit(
                f"ABI 2.1 membership failure in {path.name}: "
                f"{len(missing)} required member(s) missing {missing!r}; "
                f"{len(present_forbidden)} forbidden member(s) present {present_forbidden!r}"
            )
        if len(names) != len(set(names)):
            raise SystemExit(f"duplicate ZIP member in {path}")
        folded = [name.casefold() for name in names]
        if len(folded) != len(set(folded)):
            raise SystemExit(f"case-colliding ZIP member in {path}")
        if any(not name.startswith(prefix) for name in names):
            raise SystemExit(f"member outside {prefix!r} in {path}")
        if expected_files is not None:
            files = {name for name in names if not name.endswith("/")}
            if files != expected_files:
                raise SystemExit(f"unexpected member set in {path}: {sorted(files)!r}")
        bad_time = [entry.filename for entry in archive.infolist() if entry.date_time != FIXED_TIME]
        if bad_time:
            raise SystemExit(f"non-deterministic timestamps in {path}: {bad_time!r}")
        # C4 source-byte equality. Membership and timestamps say an archive is
        # well formed and complete; they say nothing about whether its bytes are
        # the bytes now in the tree. An archive built before the C4 sources
        # existed passes every check above and is still wrong, so every
        # non-directory member is compared with the live source map. The
        # comparison runs last so a structural failure (duplicate,
        # case-collision) is reported as itself rather than as a content
        # mismatch.
        if source_entries is not None:
            source_map = dict(source_entries)
            archived = {name for name in names if not name.endswith("/")}
            missing_members = sorted(set(source_map) - archived)
            extra_members = sorted(archived - set(source_map))
            changed = sorted(name for name in (archived & set(source_map))
                             if archive.read(name) != source_map[name])
            if missing_members or extra_members or changed:
                raise SystemExit(
                    f"archive is not the current source in {path.name}: "
                    f"{len(missing_members)} missing {missing_members[:8]!r}; "
                    f"{len(extra_members)} extra {extra_members[:8]!r}; "
                    f"{len(changed)} changed {changed[:8]!r}"
                )

def build_reproducibly(target: Path, entries: list[tuple[str, bytes]],
                       prefix: str, expected_files: set[str] | None,
                       required_members: set[str] | None = None,
                       forbidden_members: set[str] | None = None) -> str:
    # Stage beside the *target*, not beside the repository: os.replace cannot
    # move across drives, and an external attempt directory is routinely on a
    # different volume than the worktree.
    staging_root = target.parent if target.parent.is_dir() else ROOT
    with tempfile.TemporaryDirectory(prefix="fsring-package-", dir=staging_root) as temp_name:
        temp = Path(temp_name)
        first = temp / "first.zip"
        second = temp / "second.zip"
        write_archive(first, entries)
        write_archive(second, entries)
        first_hash = sha256(first)
        second_hash = sha256(second)
        if first_hash != second_hash:
            raise SystemExit(f"non-reproducible archive {target.name}: {first_hash} != {second_hash}")
        os.replace(first, target)
    verify_archive(target, prefix, expected_files, required_members, forbidden_members)
    return sha256(target)

def self_test() -> int:
    """Prove `verify_archive` rejects each way an archive can drift.

    Every fixture calls the real `verify_archive`. A fixture that reimplemented
    the comparison would pass while the shipped function was switched off, so
    the mutation is applied to a real ZIP and the shipped function is asked
    about it.
    """
    entries = [
        ("self/a.txt", b"alpha\n"),
        ("self/b.txt", b"bravo\n"),
        ("self/nested/c.txt", b"charlie\n"),
    ]
    expected = {name for name, _ in entries}

    def check(target: Path, source: list[tuple[str, bytes]] | None = entries) -> str | None:
        try:
            verify_archive(target, "self/", expected, None, None, source)
        except SystemExit as failure:
            return str(failure)
        return None

    def rebuild(temp: Path, name: str, members: list[tuple[str, bytes, tuple]],
                directories: bool = True) -> Path:
        target = temp / name
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED,
                             allowZip64=True) as archive:
            if directories:
                for directory in directory_names([(item[0], item[1]) for item in members]):
                    archive.writestr(info(directory, True), b"")
            for member, data, when in members:
                record = info(member, False)
                record.date_time = when
                archive.writestr(record, data)
        return target

    baseline = [(name, data, FIXED_TIME) for name, data in entries]
    # name -> (mutated member list, the substring its rejection must contain)
    fixtures = {
        "changed": ([(n, b"MUTATED\n" if n == "self/b.txt" else d, t)
                     for n, d, t in baseline], "changed"),
        "missing": ([item for item in baseline if item[0] != "self/b.txt"],
                    "unexpected member set"),
        "extra": (baseline + [("self/d.txt", b"delta\n", FIXED_TIME)],
                  "unexpected member set"),
        "duplicate": (baseline + [("self/b.txt", b"bravo\n", FIXED_TIME)],
                      "duplicate ZIP member"),
        "case-colliding": (baseline + [("self/A.txt", b"alpha\n", FIXED_TIME)],
                           "case-colliding ZIP member"),
        "timestamp-changed": ([(n, d, (1981, 2, 3, 4, 5, 6) if n == "self/a.txt" else t)
                               for n, d, t in baseline], "non-deterministic timestamps"),
    }

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="fsring-package-selftest-") as temp_name:
        temp = Path(temp_name)
        # Anti-vacuity: the unmutated archive must pass, or every rejection
        # below could be the fixture harness failing rather than the guard
        # working.
        clean = rebuild(temp, "clean.zip", baseline)
        reason = check(clean)
        if reason is not None:
            failures.append(f"clean: rejected a correct archive: {reason}")
        # And membership alone must not be able to see the content drift: the
        # byte comparison is the only check that catches `changed`.
        drifted = rebuild(temp, "membership-only.zip", fixtures["changed"][0])
        if check(drifted, None) is not None:
            failures.append("changed: membership checks alone already rejected it, "
                            "so this fixture cannot show the byte comparison works")

        for name, (members, needle) in fixtures.items():
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                target = rebuild(temp, f"{name}.zip", members)
            reason = check(target)
            if reason is None:
                failures.append(f"{name}: accepted a {name} archive")
            elif needle not in reason:
                failures.append(f"{name}: rejected for the wrong reason: {reason}")

    # --- the external archive target -----------------------------------
    # Rows 30 and 32 of the frozen source-gate manifest redirect both archives
    # into the attempt. The refusals below are what stop that redirection from
    # ever writing back into the repository.
    with tempfile.TemporaryDirectory() as raw_temp:
        temp = Path(raw_temp).resolve()
        target = temp / "archives"

        def resolve(argv: list[str]) -> str | None:
            try:
                resolve_output_directory(argv)
            except SystemExit as failure:
                return str(failure)
            return None

        rejections = [
            ("relative target", ["--output-directory", "archives"], "must be absolute"),
            ("missing value", ["--output-directory"], "requires a value"),
            ("value eaten by a flag", ["--output-directory", "--verify-existing"],
             "requires a value"),
            ("relative segment", ["--output-directory", str(temp / ".." / "x")],
             "relative segment"),
            ("inside the repository",
             ["--output-directory", str(ROOT / "attempt" / "archives")],
             "outside the repository"),
            ("the repository itself", ["--output-directory", str(ROOT)],
             "outside the repository"),
            ("absent parent",
             ["--output-directory", str(temp / "absent" / "archives")],
             "parent does not exist"),
        ]
        for name, argv, needle in rejections:
            reason = resolve(argv)
            if reason is None:
                failures.append(f"output-directory {name}: accepted what it must refuse")
            elif needle not in reason:
                failures.append(
                    f"output-directory {name}: refused for the wrong reason: {reason}")

        # Absent, or exactly the two archives, and nothing else.
        occupied = temp / "occupied"
        occupied.mkdir()
        (occupied / "stray.txt").write_bytes(b"stray")
        reason = resolve(["--output-directory", str(occupied)])
        if reason is None:
            failures.append("output-directory occupied: accepted a target holding other files")
        elif "must be absent or contain exactly" not in reason:
            failures.append(f"output-directory occupied: wrong reason: {reason}")

        # A *directory* named like an archive passes the name check, so this is
        # the only shape that reaches the entry-kind check.
        nested = temp / "nested"
        nested.mkdir()
        (nested / ARCHIVE_NAMES[0]).mkdir()
        (nested / ARCHIVE_NAMES[1]).write_bytes(b"")
        reason = resolve(["--output-directory", str(nested)])
        if reason is None:
            failures.append(
                "output-directory nested: accepted a directory masquerading as an archive")
        elif "directory or reparse entry" not in reason:
            failures.append(f"output-directory nested: wrong reason: {reason}")

        # A target that already holds exactly the two archives is the ordinary
        # re-run case and must still be accepted.
        rerun = temp / "rerun"
        rerun.mkdir()
        for name in ARCHIVE_NAMES:
            (rerun / name).write_bytes(b"")
        if resolve(["--output-directory", str(rerun)]) is not None:
            failures.append("output-directory rerun: refused a target holding exactly the two archives")

        # Anti-vacuity: an honest external target has to be accepted, or every
        # rejection above could be coming from a blanket refusal.
        if resolve(["--output-directory", str(target)]) is not None:
            failures.append("output-directory: refused an honest external target")
        if resolve_output_directory([]) is not None:
            failures.append("output-directory: invented a target when none was asked for")

        # And the property the rows actually depend on: a redirected generate
        # writes only there, and leaves the committed archives untouched.
        worktree = {
            name: sha256(ROOT / name)
            for name in ("fsring-abi.zip", "fsring-spec.zip")
            if (ROOT / name).is_file()
        }
        main(["--output-directory", str(target)])
        for name in ("fsring-abi.zip", "fsring-spec.zip"):
            if not (target / name).is_file():
                failures.append(f"output-directory: {name} was not written to the target")
        for name, digest in worktree.items():
            if sha256(ROOT / name) != digest:
                failures.append(
                    f"output-directory: the worktree {name} was rewritten by a "
                    f"redirected generate")
        main(["--verify-existing", "--output-directory", str(target)])

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        raise SystemExit(f"package_artifacts self-test: {len(failures)} failure(s)")
    print(f"package_artifacts self-test OK: {len(fixtures)} rejection fixture(s) "
          f"plus clean-accept and byte-comparison anti-vacuity checks, and 10 "
          f"external-target refusals with a redirected generate that leaves the "
          f"worktree archives byte-identical")
    return 0

ARCHIVE_NAMES = ("fsring-abi.zip", "fsring-spec.zip")


def resolve_output_directory(argv: list[str]) -> Path | None:
    """The external archive target, or None for the committed worktree copies.

    Refuses anything that would let an attempt write back into the repository:
    the value must be an absolute, canonical, non-reparse path outside the
    worktree, and its parent must already exist so a typo creates a stray tree
    instead of being silently accepted.
    """
    if "--output-directory" not in argv:
        return None
    index = argv.index("--output-directory")
    if index + 1 >= len(argv):
        raise SystemExit("--output-directory requires a value")
    raw = argv[index + 1]
    if not raw or raw.startswith("-"):
        raise SystemExit("--output-directory requires a value")
    if ".." in raw.replace("\\", "/").split("/"):
        raise SystemExit(f"--output-directory must not contain a relative segment: {raw}")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise SystemExit(f"--output-directory must be absolute: {raw}")
    resolved = Path(os.path.abspath(str(candidate)))
    try:
        inside = resolved == ROOT or ROOT in resolved.parents
    except OSError:
        inside = False
    if inside:
        raise SystemExit(
            f"--output-directory must live outside the repository: {resolved}")
    parent = resolved.parent
    if not parent.is_dir():
        raise SystemExit(f"--output-directory parent does not exist: {parent}")
    if resolved.exists():
        if not resolved.is_dir():
            raise SystemExit(f"--output-directory is not a directory: {resolved}")
        if resolved.is_symlink():
            raise SystemExit(f"--output-directory is a reparse point: {resolved}")
        # Absent, or exactly the two archives. A target that already holds
        # anything else is somebody else's directory, and writing into it would
        # mix these bytes with theirs.
        present = sorted(entry.name for entry in resolved.iterdir())
        if present and present != sorted(ARCHIVE_NAMES):
            raise SystemExit(
                f"--output-directory must be absent or contain exactly "
                f"{sorted(ARCHIVE_NAMES)}, found {present}: {resolved}")
        for entry in resolved.iterdir():
            if entry.is_dir() or entry.is_symlink():
                raise SystemExit(
                    f"--output-directory carries a directory or reparse entry: {entry}")
    return resolved


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    spec_expected = {f"spec/{name}" for name in SPEC_FILES}
    if "--self-test" in argv:
        return self_test()
    output_directory = resolve_output_directory(argv)
    target_root = ROOT if output_directory is None else output_directory
    if "--verify-existing" in argv:
        checks = [
            (target_root / "fsring-abi.zip", "fsring-abi/", None,
             ABI_REQUIRED_MEMBERS, ABI_FORBIDDEN_MEMBERS, abi_entries()),
            (target_root / "fsring-spec.zip", "spec/", spec_expected, None, None,
             spec_entries()),
        ]
        for target, prefix, expected, required, forbidden, source in checks:
            if not target.is_file():
                raise SystemExit(f"missing archive: {target}")
            verify_archive(target, prefix, expected, required, forbidden, source)
            print(f"{target.name} membership OK + {len(source)} member(s) equal "
                  f"to current source bytes sha256={sha256(target)}")
        return 0
    if output_directory is not None:
        output_directory.mkdir(parents=False, exist_ok=True)
    outputs = [
        (target_root / "fsring-abi.zip", abi_entries(), "fsring-abi/", None,
         ABI_REQUIRED_MEMBERS, ABI_FORBIDDEN_MEMBERS),
        (target_root / "fsring-spec.zip", spec_entries(), "spec/", spec_expected, None, None),
    ]
    for target, entries, prefix, expected, required, forbidden in outputs:
        digest = build_reproducibly(target, entries, prefix, expected, required, forbidden)
        print(f"{target.name} sha256={digest}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
