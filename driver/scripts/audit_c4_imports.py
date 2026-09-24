#!/usr/bin/env python3
"""Prove the final image imports exactly what the manifest froze.

The existing `audit_sys.sh` allowlists say which imports are *permitted*.
Permission is not presence: an allowlist stays green when a required DDI
silently disappears because its only caller was dead-stripped. This auditor is
the other direction — it fails when an expected import is **missing**, and it
compares in both directions so an undeclared new import fails too.

It never writes a manifest. A verifier that regenerates the thing it verifies
proves only that it can copy.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

SCHEMA = "fsring-c4-imports/v1"
SCOPE = "complete-final-image"
MACHINES = {"x64", "arm64"}
MAX_MANIFEST_BYTES = 1_048_576
FORBIDDEN_INLINE_HELPERS = frozenset({"ntoskrnl.exe!IoMarkIrpPending"})

# The v1 row schema intentionally remains frozen at logical/module/symbol.
# Task 6 provenance belongs to the verifier and reviewed allowlist comments,
# not to ad-hoc per-row keys that older verifiers would silently ignore.
TASK6_DIRECT_IMPORT_PROVENANCE = {
    "ntoskrnl.exe!IoAllocateWorkItem":
        ("10.0.26100", "wdm.h", 35830, "NTDDI_WIN2K"),
    "ntoskrnl.exe!IoFreeWorkItem":
        ("10.0.26100", "wdm.h", 35837, "NTDDI_WIN2K"),
    "ntoskrnl.exe!KeInitializeSpinLock":
        ("10.0.26100", "wdm.h", 23646, "NTDDI_WIN2K"),
}

MAP_SYMBOL = re.compile(
    r"^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\s+(f\s+)?(\S+)\s*$")
MAP_TIMESTAMP = re.compile(r"^\s*Timestamp is ([0-9a-fA-F]+)\s")
MAP_BASE = re.compile(r"^\s*Preferred load address is ([0-9a-fA-F]+)\s*$")


class AuditError(Exception):
    """A refusal. Every one of these fails the gate."""


def tool(name: str) -> str:
    override = os.environ.get(f"FSRING_{name.upper().replace('-', '_')}")
    if override:
        return override
    for candidate in (rf"C:\Program Files\LLVM\bin\{name}.exe", name):
        if os.path.isfile(candidate) or candidate == name:
            return candidate
    return name


def run(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as error:
        raise AuditError(f"cannot run {argv[0]}: {error}") from error
    if completed.returncode != 0:
        raise AuditError(f"{argv[0]} failed: {completed.stderr.strip()[:400]}")
    return completed.stdout


def load_manifest(path: str) -> dict:
    """Strict bounded JSON with an exact key set."""
    try:
        size = os.path.getsize(path)
    except OSError as error:
        raise AuditError(f"manifest is unreadable: {error}") from error
    if size > MAX_MANIFEST_BYTES:
        raise AuditError("manifest exceeds its size bound")
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise AuditError("manifest carries a BOM")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"manifest is not strict UTF-8 JSON: {error}") from error
    expected = {"schema", "scope", "profile", "machine", "direct", "wrappers"}
    if set(manifest) != expected:
        raise AuditError("manifest has a missing or extra root key")
    if manifest["schema"] != SCHEMA:
        raise AuditError("manifest schema is not fsring-c4-imports/v1")
    if manifest["scope"] != SCOPE:
        raise AuditError("manifest scope is not complete-final-image")
    if manifest["machine"] not in MACHINES:
        raise AuditError("manifest machine is unknown")
    if not isinstance(manifest["direct"], list) or not manifest["direct"]:
        raise AuditError("manifest direct set is empty")
    for row in manifest["direct"]:
        if set(row) != {"logical", "module", "symbol"}:
            raise AuditError("manifest direct row has a missing or extra key")
    for wrapper in manifest["wrappers"]:
        if set(wrapper) != {
            "logical", "rootSymbol", "rootMember", "provenance",
            "reachableMembers", "indirectEdgeIds", "downstreamImports",
        }:
            raise AuditError("manifest wrapper row has a missing or extra key")
        if wrapper["provenance"] != "final-image-callgraph":
            raise AuditError("a wrapper row without call-graph provenance is not evidence")
    for row in manifest["direct"]:
        key = f"{row['module']}!{row['symbol']}"
        if key in FORBIDDEN_INLINE_HELPERS:
            raise AuditError(f"inline helper treated as import: {key}")
        if row["logical"] != row["symbol"]:
            raise AuditError(
                f"direct import logical/symbol mismatch: {row['logical']} vs {row['symbol']}"
            )
    return manifest


def require_task6_direct_imports(manifest: dict) -> None:
    """Require the measured Task 6 final-image imports in every C4 profile."""
    direct = {
        f"{row['module']}!{row['symbol']}"
        for row in manifest["direct"]
    }
    missing = sorted(set(TASK6_DIRECT_IMPORT_PROVENANCE) - direct)
    if missing:
        raise AuditError(f"Task 6 direct imports are absent: {missing}")


def task6_provenance_row(entry: str, value: tuple) -> tuple[str, str, int, str, str]:
    """Validate and unpack one frozen verifier-side provenance row."""
    if not isinstance(value, tuple) or len(value) != 4:
        raise AuditError(f"Task 6 provenance for {entry} has the wrong shape")
    version, header, line, gate = value
    if (not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version)
            or not isinstance(header, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", header)
            or not isinstance(line, int) or line <= 0
            or not isinstance(gate, str) or not re.fullmatch(r"NTDDI_[A-Z0-9_]+", gate)):
        raise AuditError(f"Task 6 provenance for {entry} is malformed")
    try:
        module, symbol = entry.split("!", 1)
    except ValueError as error:
        raise AuditError(f"Task 6 provenance key is malformed: {entry}") from error
    if module != "ntoskrnl.exe" or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        raise AuditError(f"Task 6 provenance key is malformed: {entry}")
    return version, header, line, gate, symbol


def validate_task6_header_text(text: str, provenance: dict) -> None:
    """Prove each claimed declaration line and its active NTDDI gate."""
    lines = text.splitlines()
    directives = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")
    active: list[str] = []
    stacks: list[tuple[str, ...]] = [tuple()] * (len(lines) + 1)
    for index, source in enumerate(lines, start=1):
        match = directives.match(source)
        if match:
            directive, expression = match.groups()
            expression = expression.strip()
            if directive in ("if", "ifdef", "ifndef"):
                active.append(expression)
            elif directive == "elif":
                if not active:
                    raise AuditError(f"unbalanced #elif before header line {index}")
                active[-1] = expression
            elif directive == "else":
                if not active:
                    raise AuditError(f"unbalanced #else before header line {index}")
                active[-1] = f"else({active[-1]})"
            elif directive == "endif":
                if not active:
                    raise AuditError(f"unbalanced #endif at header line {index}")
                active.pop()
        stacks[index] = tuple(active)

    for entry, value in provenance.items():
        _, _, line, gate, symbol = task6_provenance_row(entry, value)
        if line > len(lines):
            raise AuditError(f"Task 6 {symbol} line {line} is outside the header")
        if not re.fullmatch(rf"\s*{re.escape(symbol)}\s*\(\s*", lines[line - 1]):
            raise AuditError(f"Task 6 {symbol} is not declared at claimed line {line}")
        gate_pattern = re.compile(
            rf"^\(*\s*NTDDI_VERSION\s*>=\s*{re.escape(gate)}\s*\)*$")
        if not any(gate_pattern.fullmatch(expression) for expression in stacks[line]):
            raise AuditError(f"Task 6 {symbol} is not actively gated at {gate}")


def task6_header_path(version: str, header: str) -> str:
    """Resolve only the exact installed WDK include version claimed above."""
    include_version = f"{version}.0"
    roots = []
    sdk_root = os.environ.get("WindowsSdkDir")
    if sdk_root:
        roots.append(sdk_root)
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    roots.append(os.path.join(program_files_x86, "Windows Kits", "10"))
    candidates = [
        os.path.join(root, "Include", include_version, "km", header)
        for root in roots
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    raise AuditError(
        f"installed WDK {version} {header} is absent from exact candidates: {candidates}")


def validate_task6_allowlist_text(text: str, provenance: dict, label: str) -> None:
    """Cross-check one allowlist against independently verified provenance."""
    lines = text.splitlines()
    for entry, value in provenance.items():
        version, header, line, gate, _ = task6_provenance_row(entry, value)
        comment = (
            f"# {entry} - direct ntoskrnl.lib; WDK {version} "
            f"{header}:{line}; gate {gate}.")
        if lines.count(comment) != 1 or lines.count(entry) != 1:
            raise AuditError(f"{label} lacks exact Task 6 provenance for {entry}")


def validate_task6_provenance() -> None:
    """Validate installed declarations/gates and both reviewed allowlists."""
    headers = {
        (task6_provenance_row(entry, value)[0],
         task6_provenance_row(entry, value)[1])
        for entry, value in TASK6_DIRECT_IMPORT_PROVENANCE.items()
    }
    if len(headers) != 1:
        raise AuditError("Task 6 direct imports do not share one exact WDK header")
    version, header = next(iter(headers))
    path = task6_header_path(version, header)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        header_text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise AuditError(f"cannot read exact Task 6 header {path}: {error}") from error
    validate_task6_header_text(header_text, TASK6_DIRECT_IMPORT_PROVENANCE)

    driver_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for filename in ("win10-imports.allow", "win7-sp1-imports.allow"):
        allowlist = os.path.join(driver_root, "audit", filename)
        try:
            with open(allowlist, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as error:
            raise AuditError(f"cannot read {filename}: {error}") from error
        validate_task6_allowlist_text(text, TASK6_DIRECT_IMPORT_PROVENANCE, filename)


def load_edges(path: str) -> dict:
    with open(path, "rb") as handle:
        edges = json.loads(handle.read().decode("utf-8"))
    if edges.get("schema") != "fsring-c4-stack-roots/v2":
        raise AuditError("edge manifest schema is wrong")
    return edges


def observed_imports(image: str) -> list[dict]:
    text = run([tool("llvm-readobj"), "--coff-imports", image])
    rows: list[dict] = []
    module = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Name: "):
            module = line[len("Name: "):]
        elif line.startswith("Symbol: ") and module:
            symbol = line[len("Symbol: "):].split(" (")[0]
            if not symbol:
                raise AuditError("an import row has no symbol name")
            rows.append({"logical": symbol, "module": module, "symbol": symbol})
    if not rows:
        raise AuditError("the final image declares no imports")
    return rows


def parse_map(path: str) -> tuple[dict[str, tuple[int, str]], set[str], dict]:
    """Symbol -> (address, library:member), the member set, and header facts."""
    symbols: dict[str, tuple[int, str]] = {}
    members: set[str] = set()
    header: dict = {}
    duplicates: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stamp = MAP_TIMESTAMP.match(line)
            if stamp:
                header["timestamp"] = int(stamp.group(1), 16)
                continue
            base = MAP_BASE.match(line)
            if base:
                header["base"] = int(base.group(1), 16)
                continue
            match = MAP_SYMBOL.match(line)
            if not match:
                continue
            name, address, _, member = match.groups()
            if name in symbols and symbols[name][0] != int(address, 16):
                duplicates.add(name)
            symbols.setdefault(name, (int(address, 16), member))
            members.add(member)
    if "timestamp" not in header or "base" not in header:
        raise AuditError("the link map has no timestamp or preferred base")
    header["duplicates"] = duplicates
    return symbols, members, header


def pe_facts(image: str) -> dict:
    text = run([tool("llvm-readobj"), "--file-headers", image])
    facts: dict = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("TimeDateStamp:"):
            value = stripped.split("(")[-1].rstrip(")")
            try:
                facts["timestamp"] = int(value, 16)
            except ValueError:
                pass
        elif stripped.startswith("ImageBase:"):
            facts["base"] = int(stripped.split(":")[1].strip(), 16)
        elif stripped.startswith("Machine:"):
            facts["machine"] = stripped
    if "timestamp" not in facts or "base" not in facts:
        raise AuditError("the final image has no COFF timestamp or image base")
    return facts


def codeview(image: str) -> dict:
    """The RSDS record: the only thing that ties this PE to that PDB."""
    text = run([tool("llvm-readobj"), "--coff-debug-directory", image])
    guid = age = name = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("PDBSignature:"):
            guid = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("PDBAge:"):
            age = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("PDBFileName:"):
            name = stripped.split(":", 1)[1].strip()
    if not name:
        raise AuditError("the final image carries no CodeView PDB reference")
    return {"guid": guid, "age": age, "name": name}


def identity_findings(machine: str, pe: dict, view: dict, pdb_name: str,
                      pdb_guid, pdb_age, header: dict,
                      image_bytes: bytes) -> list[str]:
    """Every way the three artifacts can fail to be one build.

    Pure over parsed facts, so `--self-test` can plant each mismatch. Before
    this split, seven of these eight comparisons had no fixture at all -
    including the GUID search, which is the only real PDB-to-image binding and
    whose deletion would have restored the exact defect `16db735` closed while
    leaving both gates green.

    Findings are collected rather than raised one at a time: a stale artifact
    usually breaks more than one comparison, and reporting only the first hides
    which of the three is the wrong one.
    """
    findings: list[str] = []
    expected = ("AMD64", "0x8664") if machine == "x64" else ("ARM64", "0xaa64")
    seen = pe.get("machine", "").lower()
    if not any(token.lower() in seen for token in expected):
        findings.append(f"final image machine is not {machine}: {pe.get('machine')}")
    if header["timestamp"] != pe["timestamp"]:
        findings.append("the link map timestamp is not the PE COFF timestamp")
    if header["base"] != pe["base"]:
        findings.append("the link map preferred base is not the PE image base")
    if os.path.basename(view["name"]).lower() != os.path.basename(pdb_name).lower():
        findings.append("the PE CodeView record names a different PDB")
    if pdb_guid is None or pdb_age is None:
        findings.append(f"the PDB reports no GUID/age: {pdb_name}")
        return findings
    if view["age"] is not None and str(pdb_age) != str(view["age"]):
        findings.append(
            f"the PDB age {pdb_age} is not the image's CodeView age {view['age']}")
    try:
        fields = pdb_guid.split("-")
        packed = (
            int(fields[0], 16).to_bytes(4, "little")
            + int(fields[1], 16).to_bytes(2, "little")
            + int(fields[2], 16).to_bytes(2, "little")
            + bytes.fromhex(fields[3] + fields[4])
        )
    except (IndexError, ValueError):
        findings.append(f"the PDB GUID {pdb_guid!r} is not a GUID")
        return findings
    if packed not in image_bytes:
        findings.append(
            f"the image carries no CodeView record for PDB GUID {pdb_guid}: "
            f"{os.path.basename(pdb_name)} belongs to a different build")
    return findings


def prove_identity(image: str, pdb: str, map_path: str, machine: str) -> None:
    """Fresh mtimes are never identity: the three files must agree on facts."""
    for path in (image, pdb, map_path):
        if not os.path.isfile(path):
            raise AuditError(f"artifact is missing: {path}")
    pe = pe_facts(image)
    _, _, header = parse_map(map_path)
    view = codeview(image)
    # The basename is not identity: every leg's PDB is called fsring_fsd.pdb,
    # so a name check accepts another leg's symbols, or a random file with the
    # right name. The GUID is what binds a PDB to an image.
    #
    # `llvm-readobj --coff-debug-directory` reports the RSDS signature magic and
    # the age but not the GUID, so the GUID is read from the PDB itself and then
    # required to appear in the image's own bytes: the CodeView record embeds it
    # verbatim, and a 16-byte GUID does not occur there by accident.
    summary = run([tool("llvm-pdbutil"), "dump", "--summary", pdb])
    guid = age = None
    for line in summary.splitlines():
        stripped = line.strip()
        if stripped.startswith("GUID:"):
            guid = stripped.split(":", 1)[1].strip().strip("{}")
        elif stripped.startswith("Age:"):
            age = stripped.split(":", 1)[1].strip()
    with open(image, "rb") as handle:
        image_bytes = handle.read()
    findings = identity_findings(machine, pe, view, pdb, guid, age,
                                 header, image_bytes)
    if findings:
        raise AuditError("; ".join(findings))


def compare_two_way(kind: str, expected: list, observed: list) -> None:
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    if missing:
        raise AuditError(f"{kind}: required rows are absent from the image: {missing[:8]}")
    if extra:
        raise AuditError(f"{kind}: the image carries undeclared rows: {extra[:8]}")


def analyze(manifest: dict, edges: dict, observed: list[str],
            symbols: dict[str, tuple[int, str]], members: set[str],
            header: dict, profile: str) -> None:
    """Every rule this auditor enforces, over already-parsed inputs.

    Taking parsed data rather than paths is what lets `--self-test` drive the
    shipped rules with a planted defect. A self-test that cannot call the
    analysis cannot notice when the analysis stops working, and this half of
    the auditor previously had no fixture at all: the matrix exercises it only
    against conformant artifacts, which can expose an inverted check but never
    a deleted one.
    """
    # `profile` was validated for presence and never compared to anything.
    # Current tracked manifests carry 94 `direct` rows whose
    # `module!symbol` sets are IDENTICAL, symmetric difference zero. The
    # `machine` field separates ARM64 and is checked against the PE, but
    # win10-x64 and win7-x64 both declare `machine: "x64"`, so either one
    # passed against either image. This is the only thing that tells them
    # apart.
    if manifest["profile"] != profile:
        raise AuditError(
            f"manifest declares profile {manifest['profile']}, "
            f"not the audited {profile}")
    expected = [f"{row['module']}!{row['symbol']}" for row in manifest["direct"]]
    if len(set(observed)) != len(observed):
        raise AuditError("the final image declares a duplicate import")
    compare_two_way("direct imports", expected, observed)

    edge_ids = {edge["id"] for edge in edges.get("indirectEdges", [])}
    for wrapper in manifest["wrappers"]:
        root = wrapper["rootSymbol"]
        if root not in symbols:
            raise AuditError(f"wrapper root {root} is absent from the link map")
        if root in header["duplicates"]:
            raise AuditError(f"wrapper root {root} is ambiguous in the link map")
        if symbols[root][1] != wrapper["rootMember"]:
            raise AuditError(
                f"wrapper root {root} lives in {symbols[root][1]}, "
                f"not {wrapper['rootMember']}")
        library = wrapper["rootMember"].split(":", 1)[0]
        observed_members = sorted(m for m in members if m.startswith(f"{library}:")
                                  and not m.endswith(".exe"))
        compare_two_way(f"{root} reachable members",
                        wrapper["reachableMembers"], observed_members)
        for edge_id in wrapper["indirectEdgeIds"]:
            if edge_id not in edge_ids:
                raise AuditError(f"{root} names an undeclared indirect edge {edge_id}")
        # Every declared downstream import must really be in the image. This
        # direction is enforced; the other one is not.
        #
        # KNOWN GAP: an *undeclared* downstream import is not detected. Doing
        # that needs per-member import attribution, which the link map does not
        # give: it attributes `__imp_*` thunks to the import library
        # (`ntoskrnl:ntoskrnl.exe`), not to the wrapper object that calls them.
        # The previous code filtered the observed side down to the declared
        # side, which made the comparison vacuous while reading as two-way; a
        # stated gap is worth more than that.
        #
        # Measured 2026-08-07: the 31 declared rows are a subset of the current 94
        # `direct` rows, which are compared two-way above, so the enforced
        # direction cannot raise on the shipped manifests either - the direct
        # comparison fails first. Both directions of this relation are
        # unmeasured today. See slice C4.1b.
        for entry in wrapper["downstreamImports"]:
            if entry not in observed:
                raise AuditError(f"{root} downstream import {entry} is absent")


def audit(manifest_path: str, edges_path: str, image: str, pdb: str,
          map_path: str, profile: str) -> None:
    """Read the artifacts, then hand the parsed facts to `analyze`."""
    validate_task6_provenance()
    manifest = load_manifest(manifest_path)
    require_task6_direct_imports(manifest)
    edges = load_edges(edges_path)
    prove_identity(image, pdb, map_path, manifest["machine"])
    observed = [f"{row['module']}!{row['symbol']}" for row in observed_imports(image)]
    symbols, members, header = parse_map(map_path)
    analyze(manifest, edges, observed, symbols, members, header, profile)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

MINIMAL = {
    "schema": SCHEMA,
    "scope": SCOPE,
    "profile": "Win10X64",
    "machine": "x64",
    "direct": [{"logical": "IoRegisterFileSystem", "module": "ntoskrnl.exe",
                "symbol": "IoRegisterFileSystem"}],
    "wrappers": [{
        "logical": "IoCreateDeviceSecure",
        "rootSymbol": "WdmlibIoCreateDeviceSecure",
        "rootMember": "wdmsec:wlwrap.obj",
        "provenance": "final-image-callgraph",
        "reachableMembers": ["wdmsec:iodevobj.obj", "wdmsec:wlwrap.obj"],
        "indirectEdgeIds": ["wdmsec-create-device-secure"],
        "downstreamImports": ["ntoskrnl.exe!IoCreateDevice"],
    }],
}


def self_test() -> int:
    import copy
    import tempfile

    failures: list[str] = []
    # Every check that actually executed. A failure count alone cannot tell
    # "everything passed" from "nothing ran", and a mutant that guts the
    # fixture set would otherwise report a clean PASS.
    ran: list[str] = []

    def check(name: str, condition: bool) -> None:
        ran.append(name)
        if not condition:
            failures.append(name)

    with tempfile.TemporaryDirectory() as directory:
        def write(obj, filename="manifest.json") -> str:
            path = os.path.join(directory, filename)
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(obj, handle)
            return path

        def rejects(obj) -> bool:
            try:
                load_manifest(write(obj))
                return False
            except AuditError:
                return True

        check("minimal manifest parses", load_manifest(write(MINIMAL)) == MINIMAL)

        task6 = copy.deepcopy(MINIMAL)
        for entry in TASK6_DIRECT_IMPORT_PROVENANCE:
            module, symbol = entry.split("!", 1)
            task6["direct"].append({"logical": symbol, "module": module,
                                    "symbol": symbol})
        try:
            require_task6_direct_imports(task6)
            check("Task 6 generated direct imports are complete", True)
        except AuditError:
            check("Task 6 generated direct imports are complete", False)
        missing_task6 = copy.deepcopy(task6)
        missing_task6["direct"] = [
            row for row in missing_task6["direct"]
            if row["symbol"] != "IoFreeWorkItem"
        ]
        try:
            require_task6_direct_imports(missing_task6)
            check("a missing Task 6 generated import is refused", False)
        except AuditError:
            check("a missing Task 6 generated import is refused", True)
        # An independent synthetic header plants the three declarations at the
        # reviewed lines under real preprocessor gates. The production map is
        # the input, so arbitrary version/header/line/gate edits cannot update
        # this fixture in lockstep and remain green.
        header_lines = [""] * 35840
        header_lines[23642] = "#if (NTDDI_VERSION >= NTDDI_WIN2K)"
        header_lines[23645] = "KeInitializeSpinLock ("
        header_lines[23647] = "#endif"
        header_lines[35825] = "#if (NTDDI_VERSION >= NTDDI_WIN2K)"
        header_lines[35829] = "IoAllocateWorkItem("
        header_lines[35836] = "IoFreeWorkItem("
        header_lines[35839] = "#endif"
        header_fixture = "\n".join(header_lines)

        def header_accepts(provenance: dict, text=header_fixture) -> bool:
            try:
                validate_task6_header_text(text, provenance)
                return True
            except AuditError:
                return False

        check("Task 6 independent header provenance fixture",
              header_accepts(TASK6_DIRECT_IMPORT_PROVENANCE))
        for entry, value in TASK6_DIRECT_IMPORT_PROVENANCE.items():
            version, header, line, gate = value
            declaration_drift = header_lines.copy()
            declaration_drift[line - 1] = "ForbiddenMutant("
            check(f"Task 6 {entry} declaration drift is refused",
                  not header_accepts(TASK6_DIRECT_IMPORT_PROVENANCE,
                                     "\n".join(declaration_drift)))
            line_drift = copy.deepcopy(TASK6_DIRECT_IMPORT_PROVENANCE)
            line_drift[entry] = (version, header, line + 1, gate)
            check(f"Task 6 {entry} line drift is refused",
                  not header_accepts(line_drift))
            gate_drift = copy.deepcopy(TASK6_DIRECT_IMPORT_PROVENANCE)
            gate_drift[entry] = (version, header, line, "NTDDI_FUTURE")
            check(f"Task 6 {entry} gate drift is refused",
                  not header_accepts(gate_drift))

        allowlist_fixture = """# ntoskrnl.exe!IoAllocateWorkItem - direct ntoskrnl.lib; WDK 10.0.26100 wdm.h:35830; gate NTDDI_WIN2K.
ntoskrnl.exe!IoAllocateWorkItem
# ntoskrnl.exe!IoFreeWorkItem - direct ntoskrnl.lib; WDK 10.0.26100 wdm.h:35837; gate NTDDI_WIN2K.
ntoskrnl.exe!IoFreeWorkItem
# ntoskrnl.exe!KeInitializeSpinLock - direct ntoskrnl.lib; WDK 10.0.26100 wdm.h:23646; gate NTDDI_WIN2K.
ntoskrnl.exe!KeInitializeSpinLock
"""

        def allowlist_accepts(provenance: dict) -> bool:
            try:
                validate_task6_allowlist_text(
                    allowlist_fixture, provenance, "independent fixture")
                return True
            except AuditError:
                return False

        check("Task 6 independent allowlist provenance fixture",
              allowlist_accepts(TASK6_DIRECT_IMPORT_PROVENANCE))
        for entry, value in TASK6_DIRECT_IMPORT_PROVENANCE.items():
            version, header, line, gate = value
            for property_name, mutated_value in (
                    ("version", ("99.0.0", header, line, gate)),
                    ("header", (version, "arbitrary.h", line, gate)),
                    ("line", (version, header, line + 1, gate)),
                    ("gate", (version, header, line, "NTDDI_FUTURE"))):
                drift = copy.deepcopy(TASK6_DIRECT_IMPORT_PROVENANCE)
                drift[entry] = mutated_value
                check(f"Task 6 {entry} allowlist {property_name} drift is refused",
                      not allowlist_accepts(drift))

        for key in list(MINIMAL):
            mutated = copy.deepcopy(MINIMAL)
            del mutated[key]
            check(f"missing root key {key}", rejects(mutated))
        extra = copy.deepcopy(MINIMAL)
        extra["surprise"] = 1
        check("extra root key", rejects(extra))

        for key, bad in (("schema", "other/v1"), ("scope", "partial"),
                         ("machine", "mips")):
            mutated = copy.deepcopy(MINIMAL)
            mutated[key] = bad
            check(f"wrong {key}", rejects(mutated))

        empty = copy.deepcopy(MINIMAL)
        empty["direct"] = []
        check("empty direct set", rejects(empty))

        for key in ("logical", "module", "symbol"):
            mutated = copy.deepcopy(MINIMAL)
            del mutated["direct"][0][key]
            check(f"direct row missing {key}", rejects(mutated))

        for key in ("rootSymbol", "rootMember", "reachableMembers",
                    "indirectEdgeIds", "downstreamImports", "provenance"):
            mutated = copy.deepcopy(MINIMAL)
            del mutated["wrappers"][0][key]
            check(f"wrapper row missing {key}", rejects(mutated))

        weak = copy.deepcopy(MINIMAL)
        weak["wrappers"][0]["provenance"] = "map-member"
        check("a map member alone is not provenance", rejects(weak))

        bom = os.path.join(directory, "bom.json")
        with open(bom, "wb") as handle:
            handle.write(b"\xef\xbb\xbf" + json.dumps(MINIMAL).encode("utf-8"))
        try:
            load_manifest(bom)
            check("BOM rejected", False)
        except AuditError:
            check("BOM rejected", True)

        broken = os.path.join(directory, "broken.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("{")
        try:
            load_manifest(broken)
            check("malformed JSON rejected", False)
        except AuditError:
            check("malformed JSON rejected", True)

        # Two-way comparison: a missing required row and an undeclared extra
        # row must both fail, in both directions.
        try:
            compare_two_way("t", ["a", "b"], ["a"])
            check("missing row fails", False)
        except AuditError:
            check("missing row fails", True)
        try:
            compare_two_way("t", ["a"], ["a", "b"])
            check("extra row fails", False)
            check("extra-import", False)
        except AuditError:
            check("extra row fails", True)
            check("extra-import", True)
        try:
            compare_two_way("t", ["a"], ["a"])
            check("equal sets pass", True)
        except AuditError:
            check("equal sets pass", False)

        wrong_module = copy.deepcopy(MINIMAL)
        wrong_module["direct"][0]["module"] = "hal.dll"
        try:
            analyze(wrong_module, {"indirectEdges": []},
                    ["ntoskrnl.exe!IoRegisterFileSystem"],
                    {"WdmlibIoCreateDeviceSecure": (0, "wdmsec:wlwrap.obj")},
                    set(), {"duplicates": set()}, "Win10X64")
            check("wrong-module", False)
        except AuditError:
            check("wrong-module", True)

        wrong_symbol = copy.deepcopy(MINIMAL)
        wrong_symbol["direct"][0]["symbol"] = "IoMarkIrpPending"
        wrong_symbol["direct"][0]["logical"] = "IoMarkIrpPending"
        try:
            load_manifest(write(wrong_symbol, "inline.json"))
            check("inline-helper-as-import", False)
        except AuditError as error:
            check("inline-helper-as-import", "inline helper" in str(error))
        try:
            analyze(copy.deepcopy(MINIMAL), {"indirectEdges": []},
                    ["ntoskrnl.exe!IoRegisterFileSystem"],
                    {"WdmlibIoCreateDeviceSecure": (0, "wdmsec:wlwrap.obj")},
                    set(), {"duplicates": set()}, "Win7X64")
            check("wrong-symbol-or-profile", False)
        except AuditError:
            check("wrong-symbol-or-profile", True)

        # Missing artifacts fail closed rather than being skipped.
        try:
            prove_identity(os.path.join(directory, "no.sys"),
                           os.path.join(directory, "no.pdb"),
                           os.path.join(directory, "no.map"), "x64")
            check("missing artifacts fail", False)
            check("missing-image", False)
        except AuditError:
            check("missing artifacts fail", True)
            check("missing-image", True)

        # A map whose timestamp disagrees with the PE is not an identity match.
        bad_map = os.path.join(directory, "bad.map")
        with open(bad_map, "w", encoding="utf-8") as handle:
            handle.write(" Timestamp is 00000001 (x)\n"
                         " Preferred load address is 0000000180000000\n")
        symbols, members, header = parse_map(bad_map)
        check("map header parsed", header["timestamp"] == 1 and
              header["base"] == 0x180000000)
        # On its own this is vacuously true whenever MAP_SYMBOL matches
        # nothing - the self-checking shape that once let a broken prologue
        # regex report a zero-byte frame for every root. The real-row fixture
        # below is what keeps it honest.
        check("empty map has no members", not members and not symbols)
        real_map = os.path.join(directory, "real.map")
        with open(real_map, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(" Timestamp is 6a74549d (x)\n"
                         " Preferred load address is 0000000180000000\n"
                         " 0001:00000000       DriverEntry"
                         "                0000000180001000 f   fsring_fsd.lib:a.obj\n")
        real_symbols, real_members, _ = parse_map(real_map)
        check("a real map row parses to its address and member",
              real_symbols.get("DriverEntry") == (0x180001000,
                                                  "fsring_fsd.lib:a.obj"))
        check("a real map row records its member",
              "fsring_fsd.lib:a.obj" in real_members)

        # --- fixtures that drive the real analysis -------------------------
        #
        # Everything below this line was previously unreachable from the
        # self-test: it never called `audit`, so the whole binary half of this
        # auditor was driven by nothing and a deleted check stayed green in
        # both gates. Each fixture plants exactly one defect against a clean
        # baseline, so a finding names the rule under test rather than
        # whichever gate happens to fire first.
        clean_observed = ["ntoskrnl.exe!IoRegisterFileSystem",
                          "ntoskrnl.exe!IoCreateDevice"]
        clean_symbols = {
            "WdmlibIoCreateDeviceSecure": (0x180001000, "wdmsec:wlwrap.obj"),
            "IoDevObjCreateDeviceSecure": (0x180002000, "wdmsec:iodevobj.obj"),
        }
        # `wdmsec:ntoskrnl.exe` is the member carrying the import thunks; the
        # reachable-member comparison must exclude it, and this fixture is what
        # proves the exclusion is still there.
        clean_members = {"wdmsec:wlwrap.obj", "wdmsec:iodevobj.obj",
                         "wdmsec:ntoskrnl.exe"}
        clean_header = {"duplicates": set()}
        clean_edges = {"indirectEdges": [{"id": "wdmsec-create-device-secure"}]}
        golden = copy.deepcopy(MINIMAL)
        golden["direct"].append({"logical": "IoCreateDevice",
                                 "module": "ntoskrnl.exe",
                                 "symbol": "IoCreateDevice"})

        def analyzed(manifest=None, edges=None, observed=None, symbols=None,
                     members=None, header=None, profile="Win10X64"):
            """The shipped analysis over one deliberately mutated input."""
            try:
                analyze(golden if manifest is None else manifest,
                        clean_edges if edges is None else edges,
                        clean_observed if observed is None else observed,
                        clean_symbols if symbols is None else symbols,
                        clean_members if members is None else members,
                        clean_header if header is None else header,
                        profile)
                return None
            except AuditError as error:
                return str(error)

        check("the clean fixture raises nothing", analyzed() is None)
        # The real pair: both declare machine "x64" and identical import sets,
        # so before this check either manifest passed against either image.
        check("a manifest for another profile is refused",
              "not the audited Win7X64" in (analyzed(profile="Win7X64") or ""))
        check("the profile comparison is not vacuous",
              analyzed(manifest={**golden, "profile": "Win7X64"}) is not None)
        check("a missing direct import is named",
              "required rows are absent"
              in (analyzed(observed=["ntoskrnl.exe!IoCreateDevice"]) or ""))
        check("an undeclared direct import is named",
              "undeclared rows" in (analyzed(
                  observed=clean_observed + ["ntoskrnl.exe!ExAllocatePool2"]) or ""))
        check("a duplicated image import is refused",
              "duplicate import" in (analyzed(
                  observed=clean_observed + ["ntoskrnl.exe!IoCreateDevice"]) or ""))
        check("an absent wrapper root is refused",
              "absent from the link map" in (analyzed(symbols={}) or ""))
        check("an ambiguous wrapper root is refused",
              "ambiguous" in (analyzed(
                  header={"duplicates": {"WdmlibIoCreateDeviceSecure"}}) or ""))
        check("a wrapper root in the wrong member is refused",
              "lives in" in (analyzed(symbols={
                  **clean_symbols,
                  "WdmlibIoCreateDeviceSecure": (0x180001000, "wdmsec:other.obj"),
              }) or ""))
        check("a missing reachable member is refused",
              "reachable members" in (analyzed(
                  members={"wdmsec:wlwrap.obj", "wdmsec:ntoskrnl.exe"}) or ""))
        check("an extra reachable member is refused",
              "reachable members" in (analyzed(
                  members=clean_members | {"wdmsec:extra.obj"}) or ""))
        check("an undeclared indirect edge id is refused",
              "undeclared indirect edge" in (analyzed(
                  edges={"indirectEdges": []}) or ""))
        check("an absent downstream import is refused",
              "downstream import" in (analyzed(
                  manifest={**golden, "direct": [MINIMAL["direct"][0]]},
                  observed=["ntoskrnl.exe!IoRegisterFileSystem"]) or ""))
        # A member comparison that stopped looking at `members` would accept an
        # empty set. That is exactly how the `.exe` exclusion could be widened
        # into uselessness while reading as two-way, so it is asserted here.
        check("the reachable-member comparison is not vacuous",
              analyzed(members=set()) is not None)

        # --- identity, over parsed facts -----------------------------------
        #
        # `prove_identity` runs three LLVM tools, so before the pure half was
        # split out only its missing-artifact refusal could be driven. The
        # GUID search below is the one that matters: it is the only thing that
        # stops another leg's fsring_fsd.pdb from being accepted by basename.
        pdb_guid = "01234567-89AB-CDEF-0123-456789ABCDEF"
        packed_guid = bytes.fromhex("67452301AB89EFCD0123456789ABCDEF")
        clean_pe = {"timestamp": 0x6A74549D, "base": 0x180000000,
                    "machine": "Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)"}
        clean_view = {"guid": None, "age": "1", "name": "fsring_fsd.pdb"}
        clean_map_header = {"timestamp": 0x6A74549D, "base": 0x180000000}

        def identity(**overrides):
            args = dict(machine="x64", pe=clean_pe, view=clean_view,
                        pdb_name="fsring_fsd.pdb", pdb_guid=pdb_guid,
                        pdb_age="1", header=clean_map_header,
                        image_bytes=b"\x00" * 32 + packed_guid)
            args.update(overrides)
            return identity_findings(**args)

        check("a matching identity has no finding", identity() == [])
        check("a foreign machine is named",
              any("machine" in f for f in identity(machine="arm64")))
        check("a stale map timestamp is named",
              any("timestamp" in f for f in identity(
                  header={**clean_map_header, "timestamp": 0x6A745400})))
        check("a relocated map base is named",
              any("preferred base" in f for f in identity(
                  header={**clean_map_header, "base": 0x140000000})))
        check("a foreign pdb name is named",
              any("different PDB" in f for f in identity(pdb_name="other.pdb")))
        check("a mismatched pdb age is named",
              any("CodeView age" in f for f in identity(pdb_age="2")))
        check("a pdb without a guid is refused",
              any("no GUID/age" in f for f in identity(pdb_guid=None)))
        check("a malformed pdb guid is refused",
              any("is not a GUID" in f for f in identity(pdb_guid="not-a-guid")))
        check("a pdb whose guid is absent from the image is named",
              any("belongs to a different build" in f
                  for f in identity(image_bytes=b"\x00" * 64)))
        # Replacing the byte search with `pass` restores the defect 16db735
        # closed. This is the fixture that would notice.
        check("the guid search is not vacuous", identity(image_bytes=b"") != [])

    # A completeness claim needs a producer. The decision-signal evidence says
    # what each decision in this file is seen by; this counts the decisions, so
    # one cannot be added or removed without the number changing and the table
    # being revisited. Frozen for Task 6 Fix Round 1 at 47 refusals and 8
    # findings after adding installed-header and allowlist provenance checks.
    import ast
    tree = ast.parse(open(__file__, encoding="utf-8").read())
    sites = sum(
        1 for node in ast.walk(tree)
        if (isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "AuditError")
        or (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "findings"))
    check("the decision-site census is unchanged", sites == 57)

    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"audit_c4_imports self-test: "
          f"{'PASS' if not failures else 'FAIL'} "
          f"({len(ran)} checks, {len(failures)} failures)")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--manifest")
    parser.add_argument("--edges")
    parser.add_argument("--image")
    parser.add_argument("--pdb")
    parser.add_argument("--map", dest="map_path")
    parser.add_argument("--profile")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    required = (args.manifest, args.edges, args.image, args.pdb, args.map_path,
                args.profile)
    if not all(required):
        parser.error(
            "--manifest --edges --image --pdb --map --profile are all required")
    try:
        audit(args.manifest, args.edges, args.image, args.pdb, args.map_path,
              args.profile)
    except AuditError as error:
        print(f"FAIL: {error}")
        return 1
    print(f"PASS: {args.manifest} matches the final image in both directions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
