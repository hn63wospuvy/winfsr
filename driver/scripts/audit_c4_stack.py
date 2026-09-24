#!/usr/bin/env python3
"""Prove every C4 entry root's stack is bounded and its edges are declared.

Two independent checks share one manifest:

* a **binary** check over the final image — each root exists exactly once, is
  measured by at least one of the two frame sources, its frame fits
  `maxFrameBytes`, and the deepest reachable chain fits `maxChainBytes`; every
  same-address fold **containing a declared canonical** must be an exact
  declared alias, and a root may never be one. A fold group with no declared
  canonical is a recorded KNOWN GAP, not a check;
* a **source** check over the four exact source roots — no function-local array
  whose length comes from a topology ceiling, and both pool owners present as
  reachable tagged-pool constructors.

The source half exists because the frame bound alone cannot see it: a
`[u8; MAX_RING_COUNT]` local is 64 bytes, passes a 2048-byte limit, and is
still a topology-sized array on a kernel stack.
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import subprocess
import sys

SCHEMA = "fsring-c4-stack-roots/v2"

# `MAXIMUM_EXPANSION_SIZE` from ntddk.h line 9805,
# `KERNEL_LARGE_STACK_SIZE - PAGE_SIZE / 2`, generated as 71680 by wdk-sys for
# both architectures. A request over it is refused by the DDI at run time, so
# the manifest may not declare one.
MAXIMUM_EXPANSION_SIZE = 71680

# The DDIs that expand the kernel stack, named HERE rather than in the
# manifest. An `expansionRoots` entry is what BOUNDS a call to one of these;
# deleting the entry (or the whole manifest key) must not silently un-arm the
# nine decisions that bound it. If this list lived in the manifest, deleting
# the entry would delete the fact that anything needs bounding at all -
# exactly the C4.1a hole `"expansionRoots": []` reopens. `analyze` refuses the
# image if it calls one of these with no matching declared entry, regardless
# of what the manifest says.
EXPANSION_DDIS = frozenset({"KeExpandKernelStackAndCallout"})

# The exact key set a roots manifest must carry. Named rather than inline so
# the self-test can assert membership instead of retyping the tuple, which is
# how `maxChainBytes` once went missing from the check that guards it.
_REQUIRED_ROOT_KEYS = frozenset({
    "schema", "maxFrameBytes", "maxChainBytes", "roots",
    "sourceGuard", "indirectEdges", "aliases", "frameSources", "expansionRoots",
    "asyncCallbackRoots", "nativeEffectCalls", "nativeLifecycleCalls",
})

# The exact key set every `expansionRoots` row must carry. Before this,
# `load_roots` validated the OTHER four collection keys' rows
# (`indirectEdges`, `aliases`, `frameSources`) but not this one: a row missing
# `expansionBytes` raised a bare `KeyError` out of `analyze` instead of a named
# FAIL, and nothing here refused it at load time.
_REQUIRED_EXPANSION_KEYS = frozenset({
    "root", "caller", "ddi", "expansionBytes", "maxFrameBytes",
    "maxChainBytes", "sourceFile", "sourceConstant",
})

MAP_SYMBOL = re.compile(
    r"^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\s+(f\s+)?(\S+)\s*$")
MAP_BASE = re.compile(r"Preferred load address is\s+([0-9a-fA-F]+)")

# The unwind table, per architecture, using the tool that actually works on
# this image. Measured 2026-08-07 on the 2026-08-06 build:
#
#   x64   `llvm-readobj --unwind` CRASHES (0xC0000005) after 61 of 228
#         blocks, so `run` discards everything; `llvm-objdump --unwind-info`
#         exits 0 and prints 132 function tables.
#   ARM64 `llvm-objdump --unwind-info` refuses ("unsupported image machine
#         type"); `llvm-readobj --unwind` exits 0 and prints 133 records.
#
# The pair this replaced looked for `Function:` and `StackSize:` lines. x64
# emits neither, and ARM64 emits `Function: 0x180001000` - an ADDRESS, which
# the old pattern captured as if it were a symbol name, so it keyed frames by
# hex strings that match nothing. The whole second source was inert on every
# leg and had never contributed a byte.
UNWIND_X64_START = re.compile(r"^\s*Start Address:\s*0x([0-9a-fA-F]+)")
UNWIND_X64_CODE = re.compile(r"^\s*0x[0-9a-fA-F]+:\s*UOP_(\w+)\s*(.*)$")
UNWIND_ARM_FUNCTION = re.compile(r"^\s*Function:\s*0x([0-9a-fA-F]+)")
UNWIND_ARM_SUB_SP = re.compile(r";\s*sub\s+sp,\s*#(\d+)")
UNWIND_ARM_PRE = re.compile(r";\s*(?:stp|str)\s+.*\[sp,\s*#-(\d+)\]!")
# `set_fp` (0xe1). After it the unwinder restores SP from FP, so the record
# stops describing allocation; see `frame_pointer_functions`.
UNWIND_ARM_SET_FP = re.compile(r";\s*mov\s+fp,\s*sp\b")
# ARM64 carries TWO unwind encodings in one image. The packed form declares
# the allocation outright as `FrameSize:` and prints a synthesized prologue
# with no `0xNN ;` byte-code prefix, so the two patterns above - which key on
# that prefix - match none of it. Reading only those patterns reported 0 for
# every packed record and, because a 0 was stored as if it were a
# measurement, produced eight ARM64 functions where the unwind source
# "disagreed" with a prologue it had simply failed to read.
UNWIND_ARM_FRAME_SIZE = re.compile(r"^\s*FrameSize:\s*(\d+)")

# A Rust or C function-local array. The capture is the length expression.
RUST_ARRAY = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*\[[^;\]]+;\s*(?P<ty>[^\]]+)\])?"
    r"\s*=\s*\[[^;\]]*;\s*(?P<len>[^\]]+)\]")
MAYBE_UNINIT = re.compile(r"MaybeUninit::<\s*\[[^;\]]+;\s*(?P<len>[^\]]+)\]\s*>")
FROM_FN = re.compile(r"core::array::from_fn::<[^,]+,\s*(?P<len>[^>]+)>")
C_VLA = re.compile(r"^\s*\w[\w \t*]*\s+\w+\s*\[\s*(?!\s*\])(?P<len>[^\]]*[A-Za-z_][^\]]*)\]\s*;")
ALLOCA = re.compile(r"\b(?:alloca|_alloca|_malloca)\s*\(")
CONST_ALIAS = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*[^=]+=\s*([^;]+);")
# A `pub const NAME: usize = 32768;` declaration, digit separators allowed.
USIZE_CONST = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*usize\s*"
    r"=\s*(?P<value>[0-9][0-9_]*)\s*;", re.MULTILINE)

# Task 6 walks permanent cells with one cursor and at most one affine action.
# These ceilings deliberately do not join the global topology seeds: for
# example, BOOT_CONTEXT_SLOT_COUNT legitimately sizes a bounded boot-time
# validator outside unload. Only the exact unload surface below is denied a
# fixed-domain local array.
_UNLOAD_FIXED_DOMAIN_LENGTHS = frozenset({
    "SESSION_CELL_COUNT", "MOUNT_REGISTRY_CAPACITY", "BOOT_CONTEXT_SLOT_COUNT",
})
_REQUIRED_UNLOAD_SURFACE_ROSTER = (
    "R3UnloadProgress", "R3UnloadWork", "R3StableEmptyPass",
    "R3FinalizerDrainProgress", "R3FinalizerFullPass",
    "R3FinalizerAcknowledgedPass", "R3UnloadScanAdmission",
    "FinalizerRundownDrained",
)
_UNLOAD_CURSOR_IMPLS = frozenset(_REQUIRED_UNLOAD_SURFACE_ROSTER)
_UNLOAD_FINALIZER_FUNCTIONS = frozenset({
    "drain_r3_finalizers", "wait_finalizers_drained",
    "finish_finalizers_drained", "observe_r3_finalizer_for_drain",
})
_RAW_STRING_START = re.compile(r"(?:b|c)?r(?P<hashes>#{0,255})\"")
_CHAR_LITERAL = re.compile(r"'(?:\\.|[^\\'\n])'")
_SOURCE_TOKEN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f_]+[A-Za-z]*|"
    r"[0-9][0-9A-Za-z_]*|::|->|=>|&&|\|\||[^\s]")
_EXPECTED_UNLOAD_SOURCE_FILES = {
    "fence.rs": "fsring-fsd/src/fence.rs",
    "lifecycle.rs": "fsring-fsd/src/lifecycle.rs",
}
_UNLOAD_STRUCT_FILES = {
    "R3UnloadProgress": "fence.rs",
    "R3UnloadWork": "fence.rs",
    "R3StableEmptyPass": "fence.rs",
    "R3FinalizerDrainProgress": "fence.rs",
    "R3FinalizerFullPass": "fence.rs",
    "R3FinalizerAcknowledgedPass": "fence.rs",
    "R3UnloadScanAdmission": "lifecycle.rs",
    "FinalizerRundownDrained": "lifecycle.rs",
}
_UNLOAD_IMPL_FILES = {
    "R3UnloadProgress": "fence.rs",
    "R3UnloadWork": "fence.rs",
    "R3StableEmptyPass": "fence.rs",
    "R3FinalizerFullPass": "fence.rs",
    "R3FinalizerAcknowledgedPass": "fence.rs",
    "R3UnloadScanAdmission": "lifecycle.rs",
}
_UNLOAD_FUNCTION_FILES = {
    "drain_r3_finalizers": "fence.rs",
    "wait_finalizers_drained": "lifecycle.rs",
    "finish_finalizers_drained": "lifecycle.rs",
    "observe_r3_finalizer_for_drain": "lifecycle.rs",
    "acknowledge_r3_finalizer_after_rundown": "lifecycle.rs",
}
_UNLOAD_IMPL_METHOD_SIGNATURES = {
    "R3UnloadProgress": {
        "begin_after_drains": (
            "(", "admission", ":", "crate", "::", "lifecycle", "::",
            "R3UnloadScanAdmission", ",", "process", ":", "&", "crate", "::",
            "lifecycle", "::", "ProcessCallbacksDrained", ",", "setup", ":",
            "&", "crate", "::", "lifecycle", "::", "SetupAdmissionDrained",
            ")", "->", "Self",
        ),
        "restart": (
            "(", "registry", ":", "NonNull", "<", "KernelSessionRegistry",
            ">", ")", "->", "Self",
        ),
        "observe_one": ("(", "self", ")", "->", "R3UnloadScanStep"),
    },
    "R3UnloadWork": {
        # `discharge` yields the whole scan step, not just progress: the
        # unload runner needs a Blocked arm that never returns, and
        # `R3UnloadScanStep::Scanning` still carries `R3UnloadProgress`.
        "discharge": ("(", "self", ")", "->", "R3UnloadScanStep"),
    },
    "R3StableEmptyPass": {
        "registry": (
            "(", "&", "self", ")", "->", "NonNull", "<",
            "KernelSessionRegistry", ">",
        ),
    },
    "R3FinalizerFullPass": {
        "into_registry": (
            "(", "self", ")", "->", "NonNull", "<",
            "KernelSessionRegistry", ">",
        ),
    },
    "R3FinalizerAcknowledgedPass": {
        "into_registry": (
            "(", "self", ")", "->", "NonNull", "<",
            "KernelSessionRegistry", ">",
        ),
    },
    "R3UnloadScanAdmission": {
        "into_registry_after_drains": (
            "(", "self", ",", "process", ":", "&",
            "ProcessCallbacksDrained", ",", "setup", ":", "&",
            "SetupAdmissionDrained", ")", "->", "NonNull", "<",
            "KernelSessionRegistry", ">",
        ),
    },
}
_UNLOAD_FREE_FUNCTION_SIGNATURES = {
    "drain_r3_finalizers": (
        "(", "stable", ":", "R3StableEmptyPass", ")", "->",
        "R3FinalizersDrained",
    ),
    "wait_finalizers_drained": (
        "(", "full_pass", ":", "crate", "::", "fence", "::",
        "R3FinalizerFullPass", ",", "closed", ":",
        "FinalizerAdmissionClosed", ")", "->", "FinalizerRundownDrained",
    ),
    "finish_finalizers_drained": (
        "(", "acknowledged", ":", "crate", "::", "fence", "::",
        "R3FinalizerAcknowledgedPass", ",", "rundown", ":",
        "FinalizerRundownDrained", ")", "->", "FinalizersDrained",
    ),
}
_UNLOAD_HELPER_METHOD_SIGNATURES = {
    "observe_r3_finalizer_for_drain": (
        "RegistryLockGuard",
        ("(", "&", "mut", "self", ",", "index", ":", "u32", ")",
         "->", "R3FinalizerDrainObservation"),
    ),
    "acknowledge_r3_finalizer_after_rundown": (
        "RegistryLockGuard",
        ("(", "&", "mut", "self", ",", "index", ":", "u32", ")",
         "->", "Option", "<", "LockedR3FinalizerDrainNonMatch", ">"),
    ),
}


class AuditError(Exception):
    """A refusal. Every one of these fails the gate."""


def tool(name: str) -> str:
    override = os.environ.get(f"FSRING_{name.upper().replace('-', '_')}")
    if override:
        return override
    candidate = rf"C:\Program Files\LLVM\bin\{name}.exe"
    return candidate if os.path.isfile(candidate) else name


def run(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as error:
        raise AuditError(f"cannot run {argv[0]}: {error}") from error
    if completed.returncode != 0:
        raise AuditError(f"{argv[0]} failed: {completed.stderr.strip()[:400]}")
    return completed.stdout


def load_roots(path: str) -> dict:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise AuditError(f"roots manifest is unreadable: {error}") from error
    if raw.startswith(b"\xef\xbb\xbf"):
        raise AuditError("roots manifest carries a BOM")
    # Decoded and parsed inside the refusal, so a malformed manifest leaves
    # by a named FAIL line rather than by a traceback main() cannot catch.
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise AuditError(f"roots manifest is not valid UTF-8 JSON: {error}") from error
    if set(manifest) != _REQUIRED_ROOT_KEYS:
        raise AuditError("roots manifest has a missing or extra root key")
    if manifest["schema"] != SCHEMA:
        raise AuditError("roots manifest schema is wrong")
    roots = manifest["roots"]
    if len(roots) != len(set(roots)):
        raise AuditError("roots manifest repeats a root")
    if not roots:
        raise AuditError("roots manifest is empty")
    guard = manifest["sourceGuard"]
    if set(guard) != {"sourceRoots", "topologyLengthSeeds",
                      "topologyNameFragments", "requiredPoolOwners"}:
        raise AuditError("source guard has a missing or extra key")
    for edge in manifest["indirectEdges"]:
        if "id" not in edge or "caller" not in edge or "storage" not in edge:
            raise AuditError("an indirect edge row is incomplete")
        if edge.get("kind") not in {"resolved-external", "closed-target-set"}:
            raise AuditError("an indirect edge row has an unknown kind")
    for alias in manifest["aliases"]:
        if set(alias) != {"canonical", "aliases", "profiles", "mapMember"}:
            raise AuditError("an alias row has a missing or extra key")
    for profile, census in manifest["frameSources"].items():
        if set(census) != {"minPrologueFunctions", "minUnwindFunctions",
                           "maxDeclinedDisagreements",
                           "maxTruncatedDisagreements",
                           "maxFramePointerDisagreements"}:
            raise AuditError(
                f"the frame-source census for {profile} has a missing or extra key")
    for entry in manifest["expansionRoots"]:
        if set(entry) != _REQUIRED_EXPANSION_KEYS:
            raise AuditError("an expansion root row has a missing or extra key")
    return manifest


def load_imports(path: str) -> dict:
    """The profile's `c4-imports-*.json`, opened by the same convention as
    `load_roots`: a malformed file leaves by a named FAIL line, not a
    traceback `main()` cannot catch. This does not validate the imports
    schema itself - `audit_c4_imports.py` owns that - it only reads the bytes
    `expansion_import_findings` compares `calls` against, and guards the one
    key that function actually subscripts (`imports["direct"]`): a
    well-formed JSON object with no `direct` key used to raise a bare
    `KeyError` out of `expansion_import_findings` instead of a named FAIL
    here.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise AuditError(f"imports manifest is unreadable: {error}") from error
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise AuditError(f"imports manifest is not valid UTF-8 JSON: {error}") from error
    if not isinstance(parsed, dict) or "direct" not in parsed:
        raise AuditError('imports manifest has no "direct" key')
    return parsed


def parse_map(path: str) -> tuple[dict[str, list[tuple[int, str]]], dict]:
    """`name -> [(address, member)]`, plus the header facts.

    `header["code"]` is every symbol the map itself flagged as a function,
    sorted by address. It is what `owner_at` resolves an instruction to. A map
    with no flagged function leaves it empty, which measures no frame at all
    and fails every root rather than passing them.
    """
    symbols: dict[str, list[tuple[int, str]]] = {}
    header: dict = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip().startswith("Timestamp is"):
                header["timestamp"] = line.strip().split()[2]
            base = MAP_BASE.search(line)
            if base:
                # The preferred load address turns the unwind table's RVAs into
                # the virtual addresses `owner_at` resolves.
                header["base"] = int(base.group(1), 16)
            match = MAP_SYMBOL.match(line)
            if not match:
                continue
            name, address, flag, member = match.groups()
            symbols.setdefault(name, []).append((int(address, 16), member))
            if flag:
                header.setdefault("code", []).append((int(address, 16), name))
    if not symbols:
        raise AuditError("the link map declares no symbols")
    header["code"] = sorted(header.get("code", []))
    return symbols, header


def owner_at(code: list[tuple[int, str]], address: int) -> str | None:
    """The map symbol that owns `address`, or None below the first one.

    The link map is the only complete symbol table available here. A final PE
    carries no COFF symbol table, so `llvm-objdump` labels the disassembly from
    the export directory alone - 26 names for 228 functions in the C4 image.
    Attributing by label therefore charges every internal function to whichever
    export precedes it, which both inflates that export's frame and rewrites
    its call edges. Addresses are unambiguous; labels are not.
    """
    index = bisect.bisect_right(code, address, key=lambda row: row[0]) - 1
    return code[index][1] if index >= 0 else None


# NOTE: these patterns are matched with `search`, and none of them may begin
# with an escape a non-raw string would reinterpret. The original three began
# with a literal 0x08 byte - a `\b` written outside a raw string and then
# frozen into one - which no disassembler ever emits, so nothing matched and
# every root measured a zero-byte frame. --self-test now feeds real objdump
# lines through them so that failure cannot return silently again.
SUB_RSP = re.compile(
    r"\bsub\s+rsp,\s*(?:0x([0-9a-fA-F]+)|(\d+))"
    r"|\bsubq?\s+\$?(?:0x([0-9a-fA-F]+)|(\d+))\s*,\s*%rsp"
)
# A register operand means a __chkstk-probed frame, whose size is the
# immediate loaded into eax/rax just above the call.
CHKSTK_SIZE = re.compile(
    r"\bmov\s+(?:eax|rax),\s*(?:0x([0-9a-fA-F]+)|(\d+))"
    r"|\bmovl?\s+\$?(?:0x([0-9a-fA-F]+)|(\d+))\s*,\s*%eax"
)
# NOTE: there is deliberately no `__chkstk` NAME pattern here. One existed and
# matched nothing: `__chkstk` is not exported, so `llvm-objdump` prints every
# call to it as an offset from an unrelated export. The call is resolved
# through the link map by address instead, in `prologue_allocation`.
ARM_SUB_SP = re.compile(r"\bsub\s+sp,\s*sp,\s*#(?:0x([0-9a-fA-F]+)|(\d+))")
ARM_STP_PRE = re.compile(
    r"\bstp\s+\S+,\s*\S+,\s*\[sp,\s*#-(?:0x([0-9a-fA-F]+)|(\d+))\]!"
)
ARM_STR_PRE = re.compile(
    r"\bstr\s+\S+,\s*\[sp,\s*#-(?:0x([0-9a-fA-F]+)|(\d+))\]!"
)
X64_PUSH = re.compile(r"\bpush[qlwb]?\s+%?\w+\b")
# Prologue instructions that move no stack pointer: the frame-register setup
# and the saves that store into space an earlier instruction already
# allocated. An instruction recognised by neither this set nor an allocating
# pattern ends the prologue.
X64_PROLOGUE_NEUTRAL = {"mov", "movq", "movl", "lea", "leaq", "movaps",
                        "movups", "movdqa", "movdqu", "movsd", "movss",
                        "sub", "subq", "and", "andq"}
ARM_PROLOGUE_NEUTRAL = {"stp", "str", "mov", "add", "sub"}


def immediate(match) -> int:
    """The value of whichever alternation fired; odd groups are hexadecimal."""
    for index, digits in enumerate(match.groups(), start=1):
        if digits is not None:
            return int(digits, 16 if index % 2 else 10)
    return 0


def prologue_allocation(disassembly: str, machine: str,
                        code: list[tuple[int, str]]) -> dict[str, int]:
    """Function -> the bytes its prologue moves SP by, summed.

    Every instruction is charged to the map symbol that owns its address, not
    to the label `llvm-objdump` printed above it: those labels come from the
    export directory alone, so an internal function's frame would otherwise be
    charged to whichever exported root precedes it in `.text`.

    This reader previously took the MAXIMUM of the stack-moving instructions it
    saw anywhere in a function. A prologue allocates in several steps, so the
    maximum reports the largest step rather than the frame. Measured on the
    2026-08-06 images: the first x64 function pushes eight nonvolatiles and
    then subtracts 0x438, allocating 1144 bytes, and was reported as 1080; the
    first ARM64 function stores `[sp, #-0x60]!` and then subtracts 0x420,
    allocating 1152, and was reported as 1056. `chain_bytes` sums frames, so
    the shortfall compounded along every chain.

    Accumulation stops at the first instruction that is not a recognised
    prologue form. Read that literally: the recognised set includes a frame- or
    shadow-register move or spill (`mov`/`lea` naming `%rsp`, `%rbp` or `%r11`
    on x64; `stp`/`str`/`mov`/`add` naming `sp` on ARM64), so a body store
    through the stack pointer keeps the window open and a `sub rsp` reached
    while it is still open IS charged. That over-measures rather than
    under-measures, which is the safe direction for a bound, and the
    disagreement rule refuses it in the one direction where it could invent a
    frame - but the window is wider than "the prologue", and saying otherwise
    would be a claim this function does not keep.
    """
    frames: dict[str, int] = {}
    current: str | None = None
    in_prologue = False
    probe = 0
    for line in disassembly.splitlines():
        instruction = DISASM_INSTRUCTION.match(line)
        if not instruction:
            continue
        owner = owner_at(code, int(instruction.group(1), 16))
        if owner is None:
            continue
        if owner != current:
            current, in_prologue, probe = owner, True, 0
        frames.setdefault(current, 0)
        if not in_prologue:
            continue
        fields = line.split("\t")
        mnemonic = fields[1].strip().lower() if len(fields) > 1 else ""
        if machine == "x64":
            if X64_PUSH.search(line):
                frames[current] += 8
                continue
            allocation = SUB_RSP.search(line)
            if allocation:
                frames[current] += immediate(allocation)
                continue
            size = CHKSTK_SIZE.search(line)
            if size:
                probe = immediate(size)
                continue
            target = CALL_TARGET.search(line)
            if target:
                # Resolve the callee BY ADDRESS. `__chkstk` is not exported, so
                # `llvm-objdump` prints every call to it as an offset from some
                # unrelated export - measured 2026-08-07, the string
                # "__chkstk" occurs zero times in this image's disassembly.
                # The name-matching detector this replaced therefore never
                # fired, and the one function that probes a 5944-byte frame was
                # measured at 64 bytes. The link map names it at its address.
                if owner_at(code, int(target.group(1), 16)) == "__chkstk":
                    frames[current] += probe
                    probe = 0
                    continue
                in_prologue = False
                continue
            # `%r11` is the MSVC shadow-store prologue: `mov %rsp, %r11`, then
            # the nonvolatile saves go through r11 before the push and sub.
            if mnemonic in X64_PROLOGUE_NEUTRAL and (
                    "%rsp" in line or "%rbp" in line or "%r11" in line):
                continue
            in_prologue = False
        else:
            allocation = ARM_STP_PRE.search(line) or ARM_STR_PRE.search(line)
            if allocation:
                frames[current] += immediate(allocation)
                continue
            allocation = ARM_SUB_SP.search(line)
            if allocation:
                frames[current] += immediate(allocation)
                continue
            # `sp` as an operand, not as a substring: a demangled symbol
            # comment on the line ("...disp...", "...sp_v21...") would
            # otherwise keep the prologue window open across body code.
            operands = line.split("<", 1)[0]
            if mnemonic in ARM_PROLOGUE_NEUTRAL and re.search(r"\bsp\b", operands):
                continue
            in_prologue = False
    return frames


def unwind_allocation(image: str, machine: str, code: list[tuple[int, str]],
                      base: int) -> tuple[dict[str, int], set[str]]:
    """Function -> the stack allocation its unwind record declares, and the set
    of functions whose record establishes a frame pointer.

    The second, independent measurement. Every record is keyed by its start
    ADDRESS and resolved through `owner_at`, never by a printed name: on ARM64
    the tool prints `Function: 0x180001000`, and on x64 it prints no name at
    all.

    A map symbol may own several unwind records, and they are folded by
    maximum rather than summed. That is right for the epilog records this
    image carries. It is NOT right for a genuinely chained record
    (`UNW_FLAG_CHAININFO`), whose allocation is additive with its parent's:
    such a record would be under-measured here. No chained record has been
    observed in these three images, and nothing in this file would notice one
    appearing - a recorded gap, not a proven absence.

    The x64 operand encoding was measured, not assumed (2026-08-07, over the
    132 records of the shipped image cross-checked against the disassembly):
    `UOP_AllocLarge` prints SLOTS and must be multiplied by eight, while
    `UOP_AllocSmall` prints BYTES. `UOP_PushNonVol` is eight bytes each;
    `SaveXMM128`, `SaveNonVol`, `SetFPReg` and `Epilog` store into space
    already allocated and add nothing.
    """
    try:
        text = run([tool("llvm-objdump" if machine == "x64" else "llvm-readobj"),
                    "--unwind-info" if machine == "x64" else "--unwind", image])
    except AuditError:
        # A tool that refuses this image contributes nothing, and the coverage
        # of what it did resolve is reported by the caller rather than assumed.
        return {}, set()
    return (unwind_from_text(text, machine, code, base),
            frame_pointer_functions(text, machine, code, base))


def unwind_from_text(text: str, machine: str, code: list[tuple[int, str]],
                     base: int) -> dict[str, int]:
    """The unwind parse, over already-captured tool output.

    Split from the tool invocation for the same reason `analyze` is: a reader
    that no fixture can drive is a reader that stops working in silence. The
    pair this replaced had no fixture text at all, and neither of its patterns
    matched anything either tool prints.
    """
    frames: dict[str, int] = {}
    owner: str | None = None
    total = 0

    def flush() -> None:
        if owner is not None:
            frames[owner] = max(frames.get(owner, 0), total)

    if machine == "x64":
        for line in text.splitlines():
            start = UNWIND_X64_START.match(line)
            if start:
                flush()
                owner = owner_at(code, base + int(start.group(1), 16))
                total = 0
                continue
            entry = UNWIND_X64_CODE.match(line)
            if not entry or owner is None:
                continue
            uop, operand = entry.group(1), entry.group(2).strip()
            if uop == "PushNonVol":
                total += 8
            elif uop == "AllocLarge":
                slots = int(operand.split()[0])
                # UWOP_ALLOC_LARGE has two encodings. op_info=0 stores the
                # allocation in slots, which is what every record in these
                # images uses and what the x8 below decodes. op_info=1 stores
                # a byte count and reaches 4 GB; llvm-objdump prints the two
                # identically, so a large operand is refused rather than
                # multiplied into a number this reader cannot justify.
                if slots > 0xFFFF:
                    raise AuditError(
                        f"UOP_AllocLarge operand {slots} exceeds the op_info=0 "
                        f"range; the op_info=1 byte encoding is not modelled")
                total += slots * 8
            elif uop == "AllocSmall":
                total += int(operand.split()[0])
        flush()
        return frames

    for line in text.splitlines():
        function = UNWIND_ARM_FUNCTION.match(line)
        if function:
            flush()
            owner = owner_at(code, int(function.group(1), 16))
            total = 0
            continue
        if owner is None:
            continue
        packed = UNWIND_ARM_FRAME_SIZE.match(line)
        if packed:
            # The packed encoding states the allocation directly; it is the
            # authority for this record and there are no byte codes to sum.
            total = int(packed.group(1))
            continue
        pre = UNWIND_ARM_PRE.search(line)
        if pre:
            total += int(pre.group(1))
            continue
        sub = UNWIND_ARM_SUB_SP.search(line)
        if sub:
            total += int(sub.group(1))
    flush()
    return frames


def frame_pointer_functions(text: str, machine: str,
                            code: list[tuple[int, str]], base: int) -> set[str]:
    """Functions whose unwind record establishes a frame pointer.

    This is not a stack measurement, it is the reason one is unavailable. An
    unwind record exists to unwind, not to state a frame size: once the
    prologue has set FP, the unwinder restores SP from FP, so the record has no
    reason to describe whatever the function allocated afterwards and generally
    does not. `core::panicking::panic_bounds_check` on ARM64 is exactly that
    shape -- its record is `mov fp, sp`, `stp x29, x30, [sp, #-16]!`, `end`,
    declaring 16, while the disassembly plainly allocates 112:

        stp x29, x30, [sp, #-0x10]!
        mov x29, sp
        sub sp, sp, #0x60

    The prologue reader is right and the unwind record is not wrong either;
    they answer different questions. Only `frame_source_findings` uses this,
    and only to decide whether a disagreement can be explained.
    """
    functions: set[str] = set()
    owner: str | None = None
    if machine == "x64":
        for line in text.splitlines():
            start = UNWIND_X64_START.match(line)
            if start:
                owner = owner_at(code, base + int(start.group(1), 16))
                continue
            entry = UNWIND_X64_CODE.match(line)
            if entry and owner is not None and entry.group(1) == "SetFPReg":
                functions.add(owner)
        return functions
    for line in text.splitlines():
        function = UNWIND_ARM_FUNCTION.match(line)
        if function:
            owner = owner_at(code, int(function.group(1), 16))
            continue
        if owner is not None and UNWIND_ARM_SET_FP.search(line):
            functions.add(owner)
    return functions


def measure_frames(image: str, machine: str, code: list[tuple[int, str]],
                   base: int) -> tuple[dict[str, int], dict[str, int],
                                       dict[str, int], set[str]]:
    """The enforced frame measurement, and the two sources it came from.

    The enforced value is the maximum of the two, because over-measuring a
    stack bound fails closed. Their disagreement is reported separately: if the
    prologue and the unwind record disagree about one function, one of them is
    wrong, and it was exactly such a disagreement that exposed three defects in
    this file.
    """
    disassembly = run([tool("llvm-objdump"), "-d", "--demangle", image])
    prologue = prologue_allocation(disassembly, machine, code)
    unwind, framepointers = unwind_allocation(image, machine, code, base)
    frames = dict(prologue)
    for name, value in unwind.items():
        frames[name] = max(frames.get(name, 0), value)
    return frames, prologue, unwind, framepointers


DISASM_INSTRUCTION = re.compile(r"^\s*([0-9a-fA-F]+):\s")
CALL_TARGET = re.compile(r"\b(?:call|callq|bl)\S*\s+0x([0-9a-fA-F]+)\b")


def calls_from_disassembly(disassembly: str,
                           code: list[tuple[int, str]]) -> dict[str, set[str]]:
    """Caller -> the set of symbols it calls directly.

    Both ends of an edge are resolved by address through the map, so a call to
    an internal function names that function rather than the export above it,
    and a call to an import thunk names the thunk - which the map attributes to
    its module, and which allocates nothing, so the chain terminates there.

    Only direct calls are here: an indirect call through a resolved pointer has
    no target address at the callsite, which is exactly why the manifest
    declares those edges separately and `chain_bytes` charges them.

    KNOWN GAP: a tail transfer - a branch whose target belongs to another map
    symbol - is not an edge. Address ownership now makes those countable, and
    the C4 images carry 5 on x64 and 9 on ARM64: all but one land on an import
    thunk or a pool wrapper, and the exception (`fsring_dispatch_fscontrol` to
    `fsring_dispatch_mount`) is a transfer between two separately bounded
    roots. Charging one needs `chain_bytes` to model a replaced frame rather
    than a stacked one, which is a different measurement than this walk does.
    """
    calls: dict[str, set[str]] = {}
    for line in disassembly.splitlines():
        instruction = DISASM_INSTRUCTION.match(line)
        if not instruction:
            continue
        current = owner_at(code, int(instruction.group(1), 16))
        if current is None:
            continue
        calls.setdefault(current, set())
        target = CALL_TARGET.search(line)
        if not target:
            continue
        callee = owner_at(code, int(target.group(1), 16))
        if callee is not None:
            calls[current].add(callee)
    return calls


def parse_calls(image: str, code: list[tuple[int, str]]) -> dict[str, set[str]]:
    return calls_from_disassembly(
        run([tool("llvm-objdump"), "-d", "--demangle", image]), code)


def chain_bytes(root: str, frames: dict[str, int], calls: dict[str, set[str]],
                indirect: dict[str, set[str]]) -> tuple[int, list[str]]:
    """The deepest reachable stack consumption from `root`, and its path.

    A cycle is charged once and then cut: a recursive kernel dispatch would be
    a defect of its own, and this function must terminate to report it rather
    than hang.

    An unknown callee contributes ZERO, not a finding. Only a declared root
    that neither source measured is reported (`analyze`, "has neither an
    unwind record nor a disassembled prologue"); a callee reached from a root
    but absent from `frames` adds nothing to the chain and says nothing about
    it. `prologue_allocation` gives every symbol owning a disassembled
    instruction an entry, so this is not reachable on a well-formed image -
    but nothing in this file enforces that, and an earlier version of this
    docstring claimed a refusal that does not exist.

    KNOWN GAP: a cycle is cut, not reported. The C4 x64 image has exactly one -
    `fsring_core::adapter::enter::EnterRollbackPlan::next` self-calls in its
    skip-`ReleaseRole` branch, an 80-byte frame whose depth is bounded by the
    fixed `ROLLBACK_ORDER` table it advances through - so charging it once is
    right there. Failing every cycle, which is the stricter rule, needs a
    declared-recursion manifest with a proven depth bound; until that exists
    an undeclared recursion is charged once rather than refused. Before the
    address attribution below this could not have been noticed at all: the
    call graph was built from export labels, so every internal call read as a
    self-edge and was dropped.
    """
    best: dict[str, tuple[int, list[str]]] = {}

    def walk(name: str, stack: tuple[str, ...]) -> tuple[int, list[str]]:
        if name in stack:
            return 0, [f"{name} (cycle cut)"]
        if name in best:
            return best[name]
        own = frames.get(name, 0)
        deepest, path = 0, []
        for callee in sorted(calls.get(name, set()) | indirect.get(name, set())):
            if callee == name:
                continue
            depth, sub = walk(callee, stack + (name,))
            if depth > deepest:
                deepest, path = depth, sub
        total = own + deepest
        result = (total, [f"{name}({own})"] + path)
        if not stack:
            return result
        best[name] = result
        return result

    return walk(root, ())


def pe_facts(image: str) -> dict:
    """The COFF facts a link map must agree with to be the same build.

    Deliberately a small duplicate of the sibling auditor's reader rather than
    a shared module: a new file is a new packaging and matrix surface, and
    after this slice both copies are driven by their own fixtures.
    """
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


def image_identity_findings(machine: str, pe: dict, header: dict) -> list[str]:
    """Every way this map can fail to describe this image.

    This auditor previously performed NO identity check at all. It declared
    `--imports` and `--pdb`, used neither, and parsed the map's `Timestamp is`
    line only to discard it - so a stale or foreign `.map` was accepted in
    silence, and every frame, edge and bound was then measured against the
    wrong symbol table. The sibling auditor proves the PDB binding; this one
    proves the map binding, which is the artifact it actually reads.
    """
    findings: list[str] = []
    expected = ("AMD64", "0x8664") if machine == "x64" else ("ARM64", "0xaa64")
    seen = pe.get("machine", "").lower()
    if not any(token.lower() in seen for token in expected):
        findings.append(f"final image machine is not {machine}: {pe.get('machine')}")
    if "timestamp" not in header:
        findings.append("the link map declares no timestamp")
    elif int(header["timestamp"], 16) != pe["timestamp"]:
        findings.append("the link map timestamp is not the PE COFF timestamp")
    if "base" not in header:
        findings.append("the link map declares no preferred load address")
    elif header["base"] != pe["base"]:
        findings.append("the link map preferred base is not the PE image base")
    return findings


def frame_source_findings(manifest: dict, profile: str, prologue: dict[str, int],
                          unwind: dict[str, int],
                          framepointers: set[str] | None = None) -> list[str]:
    """Both frame sources must still measure something, and still agree.

    A source that silently stops resolving anything is the exact defect this
    measurement replaced: for the whole of slice C4 the unwind reader
    contributed zero on every leg, and nothing noticed because nothing counted
    what it resolved. These floors are frozen measurements, not estimates, and
    a change that moves them belongs in the same commit that moves them.

    Disagreement is censused rather than forbidden. The enforced frame is the
    maximum of the two sources, so neither direction of a disagreement makes
    the bound unsafe; what a growing census means is that one reader is losing
    ground, and that is worth failing on before it loses all of it.

    Which reader, and how, is censused SEPARATELY, because the two shapes
    trade off against each other under a single total:

      declined  - the prologue reader resolved 0 where the unwind record
                  resolved something: it would not follow the function at all.
                  Measured 8 on both x64 profiles and 31 on ARM64, and on
                  ARM64 every one of the 31 is linked WDK static-library code.
                  That is a floor set by which libraries the image links.

      truncated - the prologue reader resolved a NONZERO allocation short of
                  the unwind record: it followed a prologue and stopped. This
                  is the live signal, and every one measured is ours.

    A single total let the truncated count grow while the library floor fell
    by the same amount, with nothing firing. Two bounds cannot be traded.
    """
    census = manifest["frameSources"].get(profile)
    if census is None:
        return [f"no frame-source census is declared for profile {profile}"]
    # Defaulting to empty means "no record established a frame pointer", which
    # sends every over-count down the refusing path. A caller that cannot say
    # therefore gets the strict reading, not the lenient one.
    framepointers = set() if framepointers is None else framepointers
    findings: list[str] = []
    if len(unwind) < census["minUnwindFunctions"]:
        findings.append(
            f"the unwind source resolved {len(unwind)} functions, fewer than the "
            f"declared {census['minUnwindFunctions']}")
    if len(prologue) < census["minPrologueFunctions"]:
        findings.append(
            f"the prologue source resolved {len(prologue)} functions, fewer than "
            f"the declared {census['minPrologueFunctions']}")
    disagree = sorted(name for name in set(prologue) & set(unwind)
                      if prologue[name] != unwind[name])
    # The SHAPE of the disagreement, not only its count. The three buckets
    # partition `disagree` exactly, because a name is in it only when the two
    # readers differ. Under-counting in either bucket leaves the bound correct
    # - the enforced frame is the maximum of the two sources - but the other
    # direction means the prologue reader is charging something the unwind
    # record does not, which is how a frame gets invented. That one is refused
    # outright rather than censused.
    over_counting = [name for name in disagree if prologue[name] > unwind[name]]
    declined = [name for name in disagree if prologue[name] == 0]
    truncated = [name for name in disagree
                 if 0 < prologue[name] < unwind[name]]
    # Over-counting splits by whether the unwind record can be read as a frame
    # size at all. Once a record establishes a frame pointer the unwinder
    # restores SP from FP, so the record stops describing the allocation and
    # `prologue > unwind` is the prologue reader being MORE accurate, not a
    # frame being invented -- measured on the ARM64 image, where
    # `panic_bounds_check`'s record declares 16 (`mov fp, sp`, `stp`, `end`)
    # against a disassembly that allocates 112. The enforced value is the
    # maximum either way, so no bound moves; what moves is whether this is
    # called a defect.
    #
    # Without a frame pointer the original reading stands and is refused
    # outright: there the unwind record IS a frame statement, and a prologue
    # charging more than it is how a frame gets invented. Measured over all
    # three images, every over-count is a frame-pointer one and none is not.
    invented = [name for name in over_counting if name not in framepointers]
    frame_pointer = [name for name in over_counting if name in framepointers]
    if invented:
        findings.append(
            f"the prologue source disagrees with the unwind record in the "
            f"over-counting direction on {len(invented)} functions: "
            + ", ".join(invented[:6]))
    if len(frame_pointer) > census.get("maxFramePointerDisagreements", 0):
        findings.append(
            f"the prologue source charged more than the unwind record on "
            f"{len(frame_pointer)} frame-pointer functions, more than the "
            f"declared {census.get('maxFramePointerDisagreements', 0)}: "
            + ", ".join(frame_pointer[:6]))
    if len(declined) > census["maxDeclinedDisagreements"]:
        findings.append(
            f"the prologue source declined {len(declined)} functions the unwind "
            f"record resolved, more than the declared "
            f"{census['maxDeclinedDisagreements']}: "
            + ", ".join(declined[:6]))
    if len(truncated) > census["maxTruncatedDisagreements"]:
        findings.append(
            f"the prologue source stopped short of the unwind record on "
            f"{len(truncated)} functions, more than the declared "
            f"{census['maxTruncatedDisagreements']}: "
            + ", ".join(truncated[:6]))
    return findings


def declared_indirect_edges(manifest: dict, profile: str) -> dict[str, set[str]]:
    """Caller -> the internal targets its declared indirect edges resolve to.

    A call through a resolved pointer carries no target address at the
    callsite, so the manifest declares the edge and this is where it becomes a
    graph edge. Only an `internal` target adds a callee: a resolved external
    routine's stack is not this image's to measure.

    One function rather than two identical loops, because a second copy is a
    second thing to keep in step - and because a mutation operator needs a
    single anchor to weaken.
    """
    indirect: dict[str, set[str]] = {}
    for edge in manifest["indirectEdges"]:
        if profile not in edge["profiles"]:
            continue
        for target in edge.get("targets", []):
            if target.get("kind") == "internal" and target.get("symbol"):
                indirect.setdefault(edge["caller"], set()).add(target["symbol"])
    return indirect


def audit_binary(manifest: dict, profile: str, image: str, map_path: str,
                 imports: dict | None = None) -> list[str]:
    symbols, header = parse_map(map_path)
    code = header["code"]
    machine = "arm64" if profile.endswith("Arm64") else "x64"
    identity = image_identity_findings(machine, pe_facts(image), header)
    if identity:
        # Measuring against a map that does not describe this image reports
        # numbers about some other build, so this refuses rather than continues.
        return identity
    frames, prologue, unwind, framepointers = measure_frames(
        image, machine, code, header["base"])
    calls = parse_calls(image, code)
    findings = (frame_source_findings(manifest, profile, prologue, unwind,
                                      framepointers)
                + analyze(manifest, profile, symbols, frames, calls))
    if imports is not None:
        findings += expansion_import_findings(manifest, imports, calls)
    return findings


def root_bounds(manifest: dict, expansions: dict, root: str) -> tuple[int, int]:
    """The frame and chain bounds this root is judged by.

    An expansion root spends both on a stack its caller never touches, so both
    come from its own declaration rather than from the manifest's global pair.
    """
    entry = expansions.get(root)
    if entry is None:
        return manifest["maxFrameBytes"], manifest["maxChainBytes"]
    return entry["maxFrameBytes"], entry["maxChainBytes"]


def analyze(manifest: dict, profile: str, symbols: dict, frames: dict[str, int],
            calls: dict[str, set[str]]) -> list[str]:
    """Every finding, computed from already-read facts.

    Taking parsed inputs rather than paths is what lets `--self-test` drive this
    function with a frame over the bound, a chain over the bound, and an
    undeclared fold. A self-test that cannot call the analysis cannot notice
    when the analysis stops working.
    """
    findings: list[str] = []

    alias_names: dict[str, str] = {}
    for alias in manifest["aliases"]:
        if profile not in alias["profiles"]:
            continue
        canonical = alias["canonical"]
        if canonical not in symbols:
            findings.append(f"alias canonical {canonical} is absent from the map")
            continue
        canonical_address, canonical_member = symbols[canonical][0]
        if canonical_member != alias["mapMember"]:
            findings.append(
                f"alias {canonical} lives in {canonical_member}, not {alias['mapMember']}")
        for name in alias["aliases"]:
            alias_names[name] = canonical
            if name not in symbols:
                findings.append(f"declared alias {name} is absent from the map")
                continue
            address, member = symbols[name][0]
            if address != canonical_address or member != canonical_member:
                findings.append(
                    f"alias {name} is not the same address and member as {canonical}")

    # Every same-address fold must be one exact declared alias.
    by_address: dict[tuple[int, str], list[str]] = {}
    for name, rows in symbols.items():
        address, member = rows[0]
        by_address.setdefault((address, member), []).append(name)
    for (_, _), names in by_address.items():
        if len(names) < 2:
            continue
        folded = sorted(names)
        # `$unwind$X` rows are unwind *data*, not code, and identical records
        # share storage by design. Compiler-generated panic shims are likewise
        # folded by ICF in every release build. Neither is what "every fold is
        # a declared alias" is about, and reporting them would bury the folds
        # that do matter - two audited functions sharing one address.
        interesting = [name for name in folded
                       if not name.startswith("$unwind$")
                       and not name.startswith("_ZN4core")]
        if len(interesting) < 2:
            continue
        folded = interesting
        canonical = [n for n in folded if n in {a["canonical"] for a in manifest["aliases"]}]
        if not canonical:
            # KNOWN GAP: a group with no declared canonical is skipped, so two
            # production functions folded by ICF are not reported. Enforcing it
            # naively drowns in linker metadata - dozens of zero-size symbols
            # (__guard_*, __hybrid_*, and `__imp_X` beside `X` for data
            # exports) legitimately share an address, and the link map does not
            # distinguish them here. Closing this needs the map's function flag
            # or a section-kind filter, not a wider comparison.
            continue
        for name in folded:
            if name in canonical or alias_names.get(name) in canonical:
                continue
            findings.append(f"undeclared same-address fold: {name} with {canonical[0]}")

    declared_roots = set(manifest["roots"])

    # EXPANSION_DDIS is a constant in THIS SCRIPT, not a manifest key, exactly
    # so that deleting a manifest row cannot silently un-arm it. Before this,
    # `"expansionRoots": []` loaded cleanly and turned every one of the nine
    # decisions below into a no-op while the image still called the DDI and
    # the 23048-byte chain went back to being unmeasured - the exact C4.1a
    # hole, restorable by a two-line manifest edit. This check does not care
    # whether `expansionRoots` is present, empty, or wrong: it reads the
    # image's own call graph and refuses if ANY function calls a stack-
    # expanding DDI that no declared entry names.
    declared_ddis = {entry["ddi"] for entry in manifest["expansionRoots"]}
    for ddi in EXPANSION_DDIS:
        if (any(ddi in callees for callees in calls.values())
                and ddi not in declared_ddis):
            findings.append(
                f"the image calls {ddi}, which expands the kernel stack, but "
                f"no expansionRoots entry declares it")

    # An expansion root runs on a stack the driver asked for, so it carries its
    # own frame and chain bounds. The declaration is checked before it is used:
    # a budget nobody can reach, one the DDI would refuse, or one looser than
    # the request would each make the two bounds below meaningless.
    expansions = {entry["root"]: entry for entry in manifest["expansionRoots"]}
    for entry in manifest["expansionRoots"]:
        if entry["root"] not in declared_roots:
            findings.append(
                f"expansion root {entry['root']} is not a declared root")
        if entry["expansionBytes"] > MAXIMUM_EXPANSION_SIZE:
            findings.append(
                f"expansion root {entry['root']} requests {entry['expansionBytes']} bytes, "
                f"over the {MAXIMUM_EXPANSION_SIZE}-byte DDI ceiling")
        for key in ("maxFrameBytes", "maxChainBytes"):
            if entry[key] > entry["expansionBytes"]:
                findings.append(
                    f"expansion root {entry['root']} enforces a {entry[key]}-byte {key} "
                    f"against a {entry['expansionBytes']}-byte request")
        # The boundary itself. Reaching this symbol by an ordinary call puts
        # the whole expanded chain back on the caller's stack, and every bound
        # below would still read green.
        callers = sorted(name for name, callees in calls.items()
                         if entry["root"] in callees)
        if callers:
            findings.append(
                f"expansion root {entry['root']} is called directly by "
                + ", ".join(callers[:4]))

    for root in manifest["roots"]:
        rows = symbols.get(root)
        if not rows:
            findings.append(f"root {root} is absent from the link map")
            continue
        if len({address for address, _ in rows}) != 1:
            findings.append(f"root {root} occurs at more than one address")
        if root in alias_names:
            findings.append(f"root {root} is an alias, which a root may never be")
        frame_bound, _chain_bound = root_bounds(manifest, expansions, root)
        frame = frames.get(root)
        if frame is None:
            # Absent from both the unwind dump and the disassembly means the
            # symbol is not in the image at all, which the map row above should
            # already have caught; refuse rather than assume zero.
            findings.append(
                f"root {root} has neither an unwind record nor a disassembled prologue")
        elif frame > frame_bound:
            findings.append(
                f"root {root} allocates {frame} bytes, over the "
                f"{frame_bound}-byte frame bound")

    # The chain bound. Direct edges come from the disassembly; the manifest's
    # declared indirect edges are added so a resolved-pointer call is charged
    # rather than silently ending a chain.
    indirect = declared_indirect_edges(manifest, profile)
    for root in manifest["roots"]:
        if root not in symbols:
            continue
        _frame_bound, chain_bound = root_bounds(manifest, expansions, root)
        total, path = chain_bytes(root, frames, calls, indirect)
        if total > chain_bound:
            findings.append(
                f"root {root} reaches {total} bytes of stack, over the "
                f"{chain_bound}-byte chain bound, via "
                + " -> ".join(path[:12]))

    for edge in manifest["indirectEdges"]:
        if profile not in edge["profiles"]:
            continue
        for name in (edge["caller"], edge["storage"]):
            if name not in symbols:
                findings.append(f"indirect edge {edge['id']} names absent symbol {name}")
        if edge["kind"] == "closed-target-set":
            for target in edge["targets"]:
                if target["kind"] == "internal" and target["symbol"] not in symbols:
                    findings.append(
                        f"closed target {target['symbol']} of {edge['id']} is absent")
        if edge["storage"] in declared_roots:
            findings.append(f"indirect storage {edge['storage']} may not also be a root")
    return findings


def resolve_consts(text: str) -> dict[str, str]:
    """`const A: u32 = MAX_RING_COUNT;` makes A a topology seed too."""
    return {match.group(1): match.group(2).strip()
            for match in CONST_ALIAS.finditer(text)}


def expand_seeds(seeds: set[str], sources: list[tuple[str, str]]) -> set[str]:
    expanded = set(seeds)
    for _ in range(4):
        grew = False
        for _, text in sources:
            for name, value in resolve_consts(text).items():
                if name in expanded:
                    continue
                if any(seed in value for seed in expanded):
                    expanded.add(name)
                    grew = True
        if not grew:
            break
    return expanded


def strip_noise(line: str) -> str:
    """Comments and string literals are not code."""
    without_strings = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return without_strings.split("//")[0]


def _blank_source_span(text: str) -> str:
    """Erase code while preserving byte offsets and line numbers."""
    return "".join("\n" if char == "\n" else " " for char in text)


def _matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _strip_source_noise(text: str) -> str:
    """Strip Rust/C comments and literals without moving any source offset.

    The unload scanner below has to find balanced item bodies. Braces planted
    in a comment, ordinary string, raw string, or character literal therefore
    have to disappear before that scan, while newlines remain for diagnostics.
    """
    out = list(text)
    index = 0
    block_depth = 0
    while index < len(text):
        if block_depth:
            if text.startswith("/*", index):
                out[index:index + 2] = "  "
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                out[index:index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if text[index] != "\n":
                    out[index] = " "
                index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
            out[index:end] = " " * (end - index)
            index = end
            continue
        if text.startswith("/*", index):
            out[index:index + 2] = "  "
            block_depth = 1
            index += 2
            continue

        raw = _RAW_STRING_START.match(text, index)
        if raw:
            hashes = raw.group("hashes")
            closing = '"' + hashes
            end = text.find(closing, raw.end())
            end = len(text) if end < 0 else end + len(closing)
            replacement = _blank_source_span(text[index:end])
            out[index:end] = replacement
            index = end
            continue
        if text[index] == '"':
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                end += 1
                if text[end - 1] == '"':
                    break
            out[index:end] = _blank_source_span(text[index:end])
            index = end
            continue
        char_literal = _CHAR_LITERAL.match(text, index)
        if char_literal:
            end = char_literal.end()
            out[index:end] = " " * (end - index)
            index = end
            continue
        index += 1
    return "".join(out)


def _source_tokens(text: str) -> list[tuple[str, int, int]]:
    return [(match.group(), match.start(), match.end())
            for match in _SOURCE_TOKEN.finditer(text)]


def _token_pairs(tokens: list[tuple[str, int, int]]) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stacks: dict[str, list[int]] = {"(": [], "[": [], "{": []}
    closing = {")": "(", "]": "[", "}": "{"}
    for index, (value, _, _) in enumerate(tokens):
        if value in stacks:
            stacks[value].append(index)
        elif value in closing and stacks[closing[value]]:
            opening = stacks[closing[value]].pop()
            pairs[opening] = index
            pairs[index] = opening
    return pairs


def _cfg_tokens(expression: str) -> list[str] | None:
    """Tokenize one cfg predicate without collapsing key/value atoms."""
    tokens: list[str] = []
    cursor = 0
    token = re.compile(
        r'\s+|[A-Za-z_][A-Za-z0-9_]*|[0-9][0-9_]*|'
        r'"(?:\\.|[^"\\])*"|[(),=]')
    while cursor < len(expression):
        match = token.match(expression, cursor)
        if match is None:
            return None
        value = match.group()
        if not value.isspace():
            tokens.append(value)
        cursor = match.end()
    return tokens


def _cfg_parse(tokens: list[str], position: int = 0
               ) -> tuple[object, int, bool]:
    if position >= len(tokens) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", tokens[position]):
        return ("unknown",), position, False
    name = tokens[position]
    position += 1
    if position < len(tokens) and tokens[position] == "=":
        position += 1
        if (position >= len(tokens)
                or tokens[position] in {"(", ")", ",", "="}):
            return ("unknown",), position, False
        value = tokens[position]
        return ("atom", f"{name}={value}"), position + 1, True
    if position >= len(tokens) or tokens[position] != "(":
        return ("atom", name), position, True
    position += 1
    children: list[object] = []
    if position < len(tokens) and tokens[position] == ")":
        position += 1
    else:
        while position < len(tokens):
            child, position, valid = _cfg_parse(tokens, position)
            if not valid:
                return ("unknown",), position, False
            children.append(child)
            if position >= len(tokens):
                return ("unknown",), position, False
            if tokens[position] == ")":
                position += 1
                break
            if tokens[position] != ",":
                return ("unknown",), position, False
            position += 1
            if position >= len(tokens):
                return ("unknown",), position, False
            if tokens[position] == ")":
                position += 1
                break
        else:
            return ("unknown",), position, False
    if name == "not" and len(children) != 1:
        return ("unknown",), position, False
    if name not in {"all", "any", "not"}:
        return ("atom", f"{name}({','.join(map(repr, children))})"), position, True
    return (name, tuple(children)), position, True


def _cfg_values_without_test(node: object) -> set[bool]:
    def simplify(candidate: object) -> object:
        kind = candidate[0]
        if kind == "atom":
            return False if candidate[1] == "test" else candidate
        if kind in {"all", "any"}:
            children = [simplify(child) for child in candidate[1]]
            if kind == "all":
                if False in children:
                    return False
                children = [child for child in children if child is not True]
                return True if not children else ("all", tuple(children))
            if True in children:
                return True
            children = [child for child in children if child is not False]
            return False if not children else ("any", tuple(children))
        if kind == "not" and candidate[1]:
            child = simplify(candidate[1][0])
            return not child if isinstance(child, bool) else ("not", (child,))
        return candidate

    simplified = simplify(node)
    if isinstance(simplified, bool):
        return {simplified}

    atoms: set[str] = set()

    def collect(candidate: object) -> None:
        kind = candidate[0]
        if kind == "atom":
            atoms.add(repr(candidate))
        elif kind in {"all", "any", "not"}:
            for child in candidate[1]:
                collect(child)
        else:
            atoms.add(repr(candidate))

    def evaluate(candidate: object, assignment: dict[str, bool]) -> bool:
        if isinstance(candidate, bool):
            return candidate
        kind = candidate[0]
        if kind == "atom":
            return assignment[repr(candidate)]
        if kind == "all":
            return all(evaluate(child, assignment) for child in candidate[1])
        if kind == "any":
            return any(evaluate(child, assignment) for child in candidate[1])
        if kind == "not" and candidate[1]:
            return not evaluate(candidate[1][0], assignment)
        return assignment[repr(candidate)]

    collect(simplified)
    ordered = sorted(atoms)
    if len(ordered) > 16:
        return {False, True}
    values: set[bool] = set()
    for mask in range(1 << len(ordered)):
        assignment = {atom: bool(mask & (1 << index))
                      for index, atom in enumerate(ordered)}
        values.add(evaluate(simplified, assignment))
        if len(values) == 2:
            break
    return values


def _cfg_expression_values(expression: str) -> set[bool]:
    tokens = _cfg_tokens(expression)
    if not tokens:
        return {False, True}
    node, position, valid = _cfg_parse(tokens)
    if not valid or position != len(tokens):
        # Malformed/unsupported cfg syntax must retain the guarded item. The
        # source guard may not erase code it cannot prove test-only.
        return {False, True}
    return _cfg_values_without_test(node)


def _split_cfg_arguments(text: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            arguments.append(text[start:index])
            start = index + 1
    arguments.append(text[start:])
    return arguments


def _cfg_attribute_is_test_only(contents: str) -> bool:
    cfg = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", contents, re.DOTALL)
    if cfg:
        return True not in _cfg_expression_values(cfg.group(1))
    cfg_attr = re.fullmatch(r"\s*cfg_attr\s*\((.*)\)\s*", contents,
                            re.DOTALL)
    if not cfg_attr:
        return False
    arguments = _split_cfg_arguments(cfg_attr.group(1))
    if len(arguments) < 2:
        return False
    predicate = _cfg_expression_values(arguments[0])
    # cfg_attr(P, cfg(Q)) excludes the item only when P is unconditionally
    # true in production and Q is unconditionally false there. If some
    # production configuration survives, the stack guard must retain it.
    if predicate != {True}:
        return False
    for attribute in arguments[1:]:
        nested = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", attribute, re.DOTALL)
        if nested and True not in _cfg_expression_values(nested.group(1)):
            return True
    return False


def _attribute_end(text: str, start: int) -> int | None:
    opening = text.find("[", start, start + 3)
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "[":
            depth += 1
        elif text[index] == "]":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _cfg_item_end(text: str, start: int) -> int:
    cursor = start
    while cursor < len(text):
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if not text.startswith("#[", cursor):
            break
        attribute_end = _attribute_end(text, cursor)
        if attribute_end is None:
            return len(text)
        cursor = attribute_end
    parens = 0
    brackets = 0
    index = cursor
    while index < len(text):
        char = text[index]
        if char == "(":
            parens += 1
        elif char == ")":
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
        elif char == ";" and parens == 0 and brackets == 0:
            return index + 1
        elif char == "{" and parens == 0 and brackets == 0:
            closing = _matching_brace(text, index)
            return len(text) if closing is None else closing + 1
        index += 1
    return len(text)


def _strip_cfg_test_items(text: str) -> str:
    """Erase items that cannot exist in any non-test configuration."""
    structural = _strip_source_noise(text)
    spans: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = structural.find("#[", cursor)
        if start < 0:
            break
        end = _attribute_end(structural, start)
        if end is None:
            break
        if _cfg_attribute_is_test_only(text[start + 2:end - 1]):
            item_end = _cfg_item_end(structural, end)
            spans.append((start, item_end))
            cursor = item_end
        else:
            cursor = end
    if not spans:
        return text
    out = list(text)
    for start, end in spans:
        out[start:end] = _blank_source_span(text[start:end])
    return "".join(out)


def _body_after(tokens: list[tuple[str, int, int]], pairs: dict[int, int],
                start: int) -> tuple[int, int] | None:
    for index in range(start, len(tokens)):
        value = tokens[index][0]
        if value == ";":
            return None
        if value == "{" and index in pairs:
            return tokens[index][2], tokens[pairs[index]][1]
    return None


def _unload_surface_spans(text: str, c_source: bool = False) -> list[tuple[int, int]]:
    """Return production Task-6 unload cursor/scan function bodies."""
    tokens = _source_tokens(text)
    pairs = _token_pairs(tokens)
    spans: list[tuple[int, int]] = []
    if c_source:
        for index in range(len(tokens) - 1):
            name = tokens[index][0]
            if ("unload" not in name.lower()
                    or not re.fullmatch(r"[A-Za-z_]\w*", name)
                    or tokens[index + 1][0] != "("):
                continue
            closing = pairs.get(index + 1)
            if closing is None:
                continue
            body = _body_after(tokens, pairs, closing + 1)
            if body is not None:
                spans.append(body)
    else:
        for index, (value, _, _) in enumerate(tokens):
            if value == "impl":
                header: list[str] = []
                cursor = index + 1
                while cursor < len(tokens) and tokens[cursor][0] not in {"{", ";"}:
                    header.append(tokens[cursor][0])
                    cursor += 1
                if not _UNLOAD_CURSOR_IMPLS.intersection(header):
                    continue
                body = _body_after(tokens, pairs, cursor)
                if body is not None:
                    spans.append(body)
            elif value == "fn" and index + 1 < len(tokens):
                name = tokens[index + 1][0]
                if ("unload" not in name.lower()
                        and name not in _UNLOAD_FINALIZER_FUNCTIONS):
                    continue
                body = _body_after(tokens, pairs, index + 2)
                if body is not None:
                    spans.append(body)
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _statement_end(tokens: list[tuple[str, int, int]], pairs: dict[int, int],
                   start: int, limit: int) -> int | None:
    cursor = start
    while cursor < limit:
        value = tokens[cursor][0]
        if value in {"(", "[", "{"} and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if value == ";":
            return cursor
        cursor += 1
    return None


def _alias_assignment(tokens: list[tuple[str, int, int]],
                      pairs: dict[int, int], start: int,
                      end: int) -> tuple[int, int] | None:
    cursor = start
    while cursor < end:
        if tokens[cursor][0] in {"(", "[", "{"} and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if tokens[cursor][0] == "=":
            return cursor + 1, end
        cursor += 1
    return None


def _collect_rust_aliases(
        tokens: list[tuple[str, int, int]], pairs: dict[int, int]
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    type_aliases: dict[str, list[str]] = {}
    const_aliases: dict[str, list[str]] = {}
    for index, (value, _, _) in enumerate(tokens):
        if value not in {"type", "const"} or index + 1 >= len(tokens):
            continue
        name = tokens[index + 1][0]
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        end = _statement_end(tokens, pairs, index + 2, len(tokens))
        if end is None:
            continue
        assignment = _alias_assignment(tokens, pairs, index + 2, end)
        if assignment is None:
            continue
        expression = [tokens[cursor][0]
                      for cursor in range(assignment[0], assignment[1])]
        (type_aliases if value == "type" else const_aliases)[name] = expression
    return type_aliases, const_aliases


def _collect_rust_import_aliases(
        tokens: list[tuple[str, int, int]], pairs: dict[int, int]
) -> dict[str, str]:
    """Collect the simple renamed imports relevant to allocation syntax."""
    aliases: dict[str, str] = {}
    for index, (value, _, _) in enumerate(tokens):
        if value != "use":
            continue
        end = _statement_end(tokens, pairs, index + 1, len(tokens))
        if end is None:
            continue
        for cursor in range(index + 2, end - 1):
            if (tokens[cursor][0] == "as"
                    and re.fullmatch(r"[A-Za-z_]\w*", tokens[cursor - 1][0])
                    and re.fullmatch(r"[A-Za-z_]\w*", tokens[cursor + 1][0])):
                aliases[tokens[cursor + 1][0]] = tokens[cursor - 1][0]
    return aliases


def _collect_c_const_aliases(text: str,
                             tokens: list[tuple[str, int, int]],
                             pairs: dict[int, int]) -> dict[str, list[str]]:
    aliases: dict[str, list[str]] = {}
    for line in text.splitlines():
        macro = re.match(r"\s*#\s*define\s+([A-Za-z_]\w*)\s+(.+?)\s*$", line)
        if macro and "(" not in macro.group(1):
            aliases[macro.group(1)] = [token[0]
                                       for token in _source_tokens(macro.group(2))]
    for index, (value, _, _) in enumerate(tokens):
        if value != "const":
            continue
        end = _statement_end(tokens, pairs, index + 1, len(tokens))
        if end is None:
            continue
        assignment = _alias_assignment(tokens, pairs, index + 1, end)
        if assignment is None or assignment[0] < 2:
            continue
        name = tokens[assignment[0] - 2][0]
        if re.fullmatch(r"[A-Za-z_]\w*", name):
            aliases[name] = [tokens[cursor][0]
                             for cursor in range(assignment[0], assignment[1])]
    return aliases


def _collect_c_type_aliases(
        tokens: list[tuple[str, int, int]], pairs: dict[int, int]
) -> dict[str, list[str]]:
    aliases: dict[str, list[str]] = {}
    for index, (value, _, _) in enumerate(tokens):
        if value != "typedef":
            continue
        end = _statement_end(tokens, pairs, index + 1, len(tokens))
        if end is None:
            continue
        brackets = [cursor for cursor in range(index + 1, end)
                    if tokens[cursor][0] == "[" and cursor in pairs]
        if brackets:
            name_index = brackets[0] - 1
        else:
            identifiers = [cursor for cursor in range(index + 1, end)
                           if re.fullmatch(r"[A-Za-z_]\w*", tokens[cursor][0])]
            if not identifiers:
                continue
            name_index = identifiers[-1]
        name = tokens[name_index][0]
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        aliases[name] = [tokens[cursor][0]
                         for cursor in range(index + 1, end)
                         if cursor != name_index]
    return aliases


def _fixed_domain_tokens(values: list[str], aliases: dict[str, list[str]],
                         seen: frozenset[str] = frozenset()) -> bool:
    for value in values:
        if value in _UNLOAD_FIXED_DOMAIN_LENGTHS:
            return True
        compact = value.replace("_", "").lower()
        if re.fullmatch(
                r"64(?:usize|u(?:8|16|32|64|128)|i(?:8|16|32|64|128)|u?l{1,2})?",
                compact) or re.fullmatch(r"0x40(?:usize|u?l{0,2})?", compact):
            return True
        if value in aliases and value not in seen:
            if _fixed_domain_tokens(aliases[value], aliases, seen | {value}):
                return True
    return False


def _c_type_alias_has_fixed_array(name: str,
                                  type_aliases: dict[str, list[str]],
                                  const_aliases: dict[str, list[str]],
                                  seen: frozenset[str] = frozenset()) -> bool:
    if name in seen:
        return False
    values = type_aliases.get(name, [])
    synthetic = [(value, index, index + 1)
                 for index, value in enumerate(values)]
    pairs = _token_pairs(synthetic)
    for index, (value, _, _) in enumerate(synthetic):
        if value == "[" and index in pairs:
            if _fixed_domain_tokens(
                    [synthetic[item][0]
                     for item in range(index + 1, pairs[index])], const_aliases):
                return True
    # A pointer typedef layered over an array typedef denotes a pointer-sized
    # local, not another array object. Do not recurse through that indirection.
    if "*" in values:
        return False
    for value in values:
        if value in type_aliases and _c_type_alias_has_fixed_array(
                value, type_aliases, const_aliases, seen | {name}):
            return True
    return False


def _array_length_token_range(tokens: list[tuple[str, int, int]],
                              pairs: dict[int, int], opening: int
                              ) -> tuple[int, int] | None:
    closing = pairs.get(opening)
    if closing is None:
        return None
    cursor = opening + 1
    while cursor < closing:
        if tokens[cursor][0] in {"(", "[", "{"} and cursor in pairs:
            cursor = pairs[cursor] + 1
            continue
        if tokens[cursor][0] == ";":
            return cursor + 1, closing
        cursor += 1
    return None


def _generic_token_range(tokens: list[tuple[str, int, int]], start: int,
                         limit: int) -> tuple[int, int, int] | None:
    """Return the contents and closing token of `Name::<...>`/`Name<...>`."""
    opening = start + 1
    if opening < limit and tokens[opening][0] == "::":
        opening += 1
    if opening >= limit or tokens[opening][0] != "<":
        return None
    depth = 1
    cursor = opening + 1
    while cursor < limit:
        if tokens[cursor][0] == "<":
            depth += 1
        elif tokens[cursor][0] == ">":
            depth -= 1
            if depth == 0:
                return opening + 1, cursor, cursor
        cursor += 1
    return None


def _tokens_have_fixed_array_type(values: list[str],
                                  type_aliases: dict[str, list[str]],
                                  const_aliases: dict[str, list[str]]) -> bool:
    synthetic = [(value, index, index + 1)
                 for index, value in enumerate(values)]
    pairs = _token_pairs(synthetic)
    for index, (value, _, _) in enumerate(synthetic):
        if value == "[":
            length = _array_length_token_range(synthetic, pairs, index)
            if length and _fixed_domain_tokens(
                    [synthetic[item][0]
                     for item in range(length[0], length[1])], const_aliases):
                return True
        if value in type_aliases and _type_alias_has_fixed_array(
                value, type_aliases, const_aliases, frozenset()):
            return True
    return False


def _type_alias_targets_maybe_uninit(
        name: str, type_aliases: dict[str, list[str]],
        import_aliases: dict[str, str],
        seen: frozenset[str] = frozenset()) -> bool:
    if name in seen:
        return False
    values = type_aliases.get(name, [])
    if any(import_aliases.get(value, value) == "MaybeUninit"
           for value in values):
        return True
    return any(value in type_aliases
               and _type_alias_targets_maybe_uninit(
                   value, type_aliases, import_aliases, seen | {name})
               for value in values)


def _call_opening_after(
        tokens: list[tuple[str, int, int]], pairs: dict[int, int],
        expression_start: int, after: int, limit: int) -> int | None:
    """Find a call after a path, including balanced wrapping parentheses."""
    while (after < limit and tokens[after][0] == ")"
           and pairs.get(after, after) < expression_start):
        after += 1
    if after < limit and tokens[after][0] == "(":
        return after
    return None


def _rust_local_array_offsets(text: str, start: int, end: int,
                              type_aliases: dict[str, list[str]],
                              const_aliases: dict[str, list[str]],
                              import_aliases: dict[str, str]) -> list[int]:
    tokens = _source_tokens(text[start:end])
    tokens = [(value, token_start + start, token_end + start)
              for value, token_start, token_end in tokens]
    pairs = _token_pairs(tokens)
    offsets: list[int] = []
    declaration_spans: list[tuple[int, int]] = []
    for index, (value, _, _) in enumerate(tokens):
        if value not in {"type", "const", "static"}:
            continue
        statement_end = _statement_end(tokens, pairs, index + 1, len(tokens))
        if statement_end is not None:
            declaration_spans.append((index, statement_end))

    def in_declaration(index: int) -> bool:
        return any(first <= index <= last
                   for first, last in declaration_spans)

    expression_predecessors = {
        "(", "[", "{", ",", ";", "=", "=>", ":", "return", "break",
        "yield", "else", "||",
    }
    for index, (value, _, _) in enumerate(tokens):
        if value != "[":
            continue
        length = _array_length_token_range(tokens, pairs, index)
        if not length or not _fixed_domain_tokens(
                [tokens[item][0] for item in range(length[0], length[1])],
                const_aliases):
            continue
        if in_declaration(index):
            continue
        previous = tokens[index - 1][0] if index else "{"
        statement = index - 1
        while statement >= 0 and tokens[statement][0] not in {";", "{", "}"}:
            statement -= 1
        local_binding = any(tokens[cursor][0] == "let"
                            for cursor in range(statement + 1, index))
        if local_binding or previous in expression_predecessors:
            offsets.append(tokens[index][1])
    for index, (value, _, _) in enumerate(tokens):
        if value != "let":
            continue
        statement_end = _statement_end(tokens, pairs, index + 1, len(tokens))
        if statement_end is None:
            continue
        for cursor in range(index + 1, statement_end):
            if tokens[cursor][0] != "[":
                continue
            length = _array_length_token_range(tokens, pairs, cursor)
            if length and _fixed_domain_tokens(
                    [tokens[item][0] for item in range(length[0], length[1])],
                    const_aliases):
                offsets.append(tokens[cursor][1])
        equals = next((cursor for cursor in range(index + 1, statement_end)
                       if tokens[cursor][0] == "="), statement_end)
        colon = next((cursor for cursor in range(index + 1, equals)
                      if tokens[cursor][0] == ":"), None)
        if colon is not None:
            for cursor in range(colon + 1, equals):
                alias = type_aliases.get(tokens[cursor][0])
                if alias and _type_alias_has_fixed_array(
                        tokens[cursor][0], type_aliases, const_aliases,
                        frozenset()):
                    offsets.append(tokens[cursor][1])
                    break
        if any(tokens[cursor][0] == "MaybeUninit"
               for cursor in range(equals + 1, statement_end)):
            for cursor in range(equals + 1, statement_end):
                if (tokens[cursor][0] in type_aliases
                        and _type_alias_has_fixed_array(
                            tokens[cursor][0], type_aliases, const_aliases,
                            frozenset())):
                    offsets.append(tokens[cursor][1])
                    break
        for cursor in range(index + 1, statement_end):
            if import_aliases.get(tokens[cursor][0], tokens[cursor][0]) != "from_fn":
                continue
            generic = cursor + 1
            if (generic + 1 < statement_end
                    and tokens[generic][0] == "::"
                    and tokens[generic + 1][0] == "<"):
                generic += 2
                close = generic
                while close < statement_end and tokens[close][0] != ">":
                    close += 1
                if (_fixed_domain_tokens(
                        [tokens[item][0] for item in range(generic, close)],
                        const_aliases)
                        and _call_opening_after(
                            tokens, pairs, cursor, close + 1,
                            statement_end) is not None):
                    offsets.append(tokens[cursor][1])
    # Constructors also allocate when returned or passed directly to another
    # call; they do not need a named `let` binding to consume the kernel stack.
    for index, (value, _, _) in enumerate(tokens):
        resolved_value = import_aliases.get(value, value)
        if resolved_value == "from_fn":
            statement_end = _statement_end(tokens, pairs, index + 1, len(tokens))
            if statement_end is None:
                statement_end = len(tokens)
            generic = index + 1
            if (generic + 1 < statement_end
                    and tokens[generic][0] == "::"
                    and tokens[generic + 1][0] == "<"):
                generic += 2
                close = generic
                while close < statement_end and tokens[close][0] != ">":
                    close += 1
                if (_fixed_domain_tokens(
                        [tokens[item][0] for item in range(generic, close)],
                        const_aliases)
                        and _call_opening_after(
                            tokens, pairs, index, close + 1,
                            statement_end) is not None):
                    offsets.append(tokens[index][1])
        statement_end = _statement_end(tokens, pairs, index + 1, len(tokens))
        if statement_end is None:
            statement_end = len(tokens)
        generic = _generic_token_range(tokens, index, statement_end)
        arguments = ([] if generic is None else
                     [tokens[cursor][0]
                      for cursor in range(generic[0], generic[1])])
        allocation_type_is_fixed = (
            bool(generic) and _tokens_have_fixed_array_type(
                arguments, type_aliases, const_aliases))
        allocation_type_is_fixed = allocation_type_is_fixed or (
            value in type_aliases and _type_alias_has_fixed_array(
                value, type_aliases, const_aliases, frozenset()))
        if not allocation_type_is_fixed:
            continue
        after = index + 1 if generic is None else generic[2] + 1
        call_opening = _call_opening_after(
            tokens, pairs, index, after, statement_end)
        if resolved_value in {"zeroed", "uninitialized"}:
            if call_opening is not None:
                offsets.append(tokens[index][1])
            continue
        maybe_uninit = (resolved_value == "MaybeUninit"
                        or _type_alias_targets_maybe_uninit(
                            value, type_aliases, import_aliases))
        if (maybe_uninit and after + 2 < statement_end
                and tokens[after][0] == "::"
                and tokens[after + 1][0] in {"uninit", "zeroed", "new"}
                and tokens[after + 2][0] == "("):
            offsets.append(tokens[index][1])
    return sorted(set(offsets))


def _type_alias_has_fixed_array(name: str,
                                type_aliases: dict[str, list[str]],
                                const_aliases: dict[str, list[str]],
                                seen: frozenset[str]) -> bool:
    if name in seen:
        return False
    values = type_aliases.get(name, [])
    synthetic = [(value, index, index + 1)
                 for index, value in enumerate(values)]
    pairs = _token_pairs(synthetic)
    for index, (value, _, _) in enumerate(synthetic):
        if value == "[":
            length = _array_length_token_range(synthetic, pairs, index)
            if length and _fixed_domain_tokens(
                    [synthetic[item][0]
                     for item in range(length[0], length[1])], const_aliases):
                return True
        if value in type_aliases and _type_alias_has_fixed_array(
                value, type_aliases, const_aliases, seen | {name}):
            return True
    return False


def _c_local_array_offsets(text: str, start: int, end: int,
                           const_aliases: dict[str, list[str]],
                           type_aliases: dict[str, list[str]]) -> list[int]:
    tokens = _source_tokens(text[start:end])
    tokens = [(value, token_start + start, token_end + start)
              for value, token_start, token_end in tokens]
    pairs = _token_pairs(tokens)
    paren_depths: list[int] = []
    parens = 0
    for value, _, _ in tokens:
        if value == ")":
            parens = max(0, parens - 1)
        paren_depths.append(parens)
        if value == "(":
            parens += 1
    statement_start = 0
    starts: list[int] = []
    for index, (value, _, _) in enumerate(tokens):
        starts.append(statement_start)
        if value in {";", "{", "}"} and paren_depths[index] == 0:
            statement_start = index + 1
    offsets: list[int] = []
    reverse_pairs = {closing: opening for opening, closing in pairs.items()
                     if opening < closing}
    for opening, (value, _, _) in enumerate(tokens):
        if value != "[" or opening not in pairs:
            continue
        length = opening + 1, pairs[opening]
        if not _fixed_domain_tokens(
                [tokens[item][0] for item in range(length[0], length[1])],
                const_aliases):
            continue
        # `(TYPE[COUNT]){...}` is a C compound literal, hence an actual array
        # object. A `TYPE (*)[COUNT]` declarator is only a pointer and remains
        # excluded.
        enclosing = next((left for left, right in pairs.items()
                          if left < opening < right
                          and tokens[left][0] == "("
                          and right + 1 < len(tokens)
                          and tokens[right + 1][0] == "{"), None)
        if enclosing is not None:
            closing = pairs[enclosing]
            if "*" not in {tokens[item][0]
                           for item in range(enclosing + 1, closing)}:
                offsets.append(tokens[opening][1])
            continue
        first = opening
        while first > 0 and tokens[first - 1][0] == "]":
            prior = reverse_pairs.get(first - 1)
            if prior is None:
                break
            first = prior
        variable = first - 1
        if (variable < starts[first]
                or not re.fullmatch(r"[A-Za-z_]\w*", tokens[variable][0])
                or paren_depths[first] != 0):
            continue
        prefix = [tokens[item][0] for item in range(starts[first], variable)]
        if (not any(re.fullmatch(r"[A-Za-z_]\w*", item) for item in prefix)
                or any(item in {"=", "return", ".", "->"} for item in prefix)):
            continue
        offsets.append(tokens[opening][1])

    # A typedef can hide the array brackets at the declaration or compound
    # literal site. Resolve it only when the alias denotes a fixed array.
    for index, (value, _, _) in enumerate(tokens):
        if not _c_type_alias_has_fixed_array(
                value, type_aliases, const_aliases):
            continue
        # Type qualifiers may precede the typedef name inside a compound
        # literal: `(const Claims){0}` still materializes a Claims object.
        qualifier_tokens = {"const", "volatile", "restrict", "_Atomic"}
        compound_open = next(
            (left for left, right in pairs.items()
             if left < index < right and tokens[left][0] == "("
             and right + 1 < len(tokens) and tokens[right + 1][0] == "{"
             and all(tokens[item][0] in qualifier_tokens | {value}
                     for item in range(left + 1, right))
             and sum(tokens[item][0] == value
                     for item in range(left + 1, right)) == 1),
            None)
        if compound_open is not None:
            offsets.append(tokens[index][1])
            continue
        first = starts[index]
        prefix = [tokens[item][0] for item in range(first, index)]
        if any(item not in {"const", "volatile", "static", "register", "auto"}
               for item in prefix):
            continue
        variable = index + 1
        while variable < len(tokens) and tokens[variable][0] in {
                "const", "volatile"}:
            variable += 1
        if variable >= len(tokens) or tokens[variable][0] == "*":
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", tokens[variable][0]):
            offsets.append(tokens[index][1])
    return sorted(set(offsets))


def _production_source_key(path: str) -> str | None:
    normalized = os.path.normpath(path).replace("\\", "/").lower()
    for key, suffix in _EXPECTED_UNLOAD_SOURCE_FILES.items():
        if normalized == suffix or normalized.endswith("/" + suffix):
            return key
    return None


def _named_rust_body(text: str, kind: str, name: str) -> tuple[int, int] | None:
    tokens = _source_tokens(text)
    pairs = _token_pairs(tokens)
    for index, (value, _, _) in enumerate(tokens):
        if value != kind:
            continue
        cursor = index + 1
        if kind in {"struct", "fn"}:
            if cursor >= len(tokens) or tokens[cursor][0] != name:
                continue
        else:
            header: list[str] = []
            while cursor < len(tokens) and tokens[cursor][0] not in {"{", ";"}:
                header.append(tokens[cursor][0])
                cursor += 1
            if name not in header:
                continue
        body = _body_after(tokens, pairs, cursor + (1 if kind in {"struct", "fn"} else 0))
        if body is not None and _source_tokens(text[body[0]:body[1]]):
            return body
    return None


def _inherent_impl_body(text: str, name: str) -> tuple[int, int] | None:
    """Find the exact top-level `impl Name`, never `impl Trait for Name`."""
    tokens = _source_tokens(text)
    pairs = _token_pairs(tokens)
    brace_depth = 0
    for index, (value, _, _) in enumerate(tokens):
        if value == "}" and brace_depth:
            brace_depth -= 1
        if value == "impl" and brace_depth == 0:
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor][0] not in {"{", ";"}:
                cursor += 1
            header = [tokens[item][0] for item in range(index + 1, cursor)]
            if (cursor < len(tokens) and tokens[cursor][0] == "{"
                    and header == [name] and cursor in pairs):
                return tokens[cursor][2], tokens[pairs[cursor]][1]
        if value == "{":
            brace_depth += 1
    return None


def _rust_functions_at_depth(text: str, required_depth: int = 0
                             ) -> dict[str, tuple[tuple[str, ...], tuple[int, int]]]:
    """Return named function signatures/bodies at one exact brace depth."""
    tokens = _source_tokens(text)
    pairs = _token_pairs(tokens)
    functions: dict[str, tuple[tuple[str, ...], tuple[int, int]]] = {}
    brace_depth = 0
    for index, (value, _, _) in enumerate(tokens):
        if value == "}" and brace_depth:
            brace_depth -= 1
        if (value == "fn" and brace_depth == required_depth
                and index + 1 < len(tokens)
                and re.fullmatch(r"[A-Za-z_]\w*", tokens[index + 1][0])):
            cursor = index + 2
            while cursor < len(tokens) and tokens[cursor][0] not in {"{", ";"}:
                cursor += 1
            if (cursor < len(tokens) and tokens[cursor][0] == "{"
                    and cursor in pairs):
                name = tokens[index + 1][0]
                raw_signature = [tokens[item][0]
                                 for item in range(index + 2, cursor)]
                signature = tuple(
                    value for item, value in enumerate(raw_signature)
                    if not (value == "," and item + 1 < len(raw_signature)
                            and raw_signature[item + 1] == ")"))
                body = (tokens[cursor][2], tokens[pairs[cursor]][1])
                functions[name] = signature, body
        if value == "{":
            brace_depth += 1
    return functions


def _exact_inherent_methods(
        text: str, target: str
) -> dict[str, tuple[tuple[str, ...], tuple[int, int]]] | None:
    body = _inherent_impl_body(text, target)
    if body is None:
        return None
    relative = _rust_functions_at_depth(text[body[0]:body[1]])
    return {name: (signature, (span[0] + body[0], span[1] + body[0]))
            for name, (signature, span) in relative.items()}


def _exact_free_function(
        text: str, name: str
) -> tuple[tuple[str, ...], tuple[int, int]] | None:
    return _rust_functions_at_depth(text).get(name)


def _drain_binds_acknowledged_pass_to_finish(body: str) -> bool:
    """Require one locally minted acknowledged pass to feed the finish sink."""
    tokens = _source_tokens(body)
    pairs = _token_pairs(tokens)
    minted: set[str] = set()
    for index, (value, _, _) in enumerate(tokens):
        if (value != "let" or index + 3 >= len(tokens)
                or not re.fullmatch(r"[A-Za-z_]\w*", tokens[index + 1][0])):
            continue
        end = _statement_end(tokens, pairs, index + 2, len(tokens))
        if end is None:
            continue
        equals = next((cursor for cursor in range(index + 2, end)
                       if tokens[cursor][0] == "="), None)
        if (equals is not None
                and any(tokens[cursor][0] == "R3FinalizerAcknowledgedPass"
                        for cursor in range(equals + 1, end))):
            minted.add(tokens[index + 1][0])
    for index, (value, _, _) in enumerate(tokens):
        if value != "finish_finalizers_drained":
            continue
        opening = index + 1
        if opening >= len(tokens) or tokens[opening][0] != "(":
            continue
        closing = pairs.get(opening)
        if closing is None:
            continue
        cursor = opening + 1
        while cursor < closing and tokens[cursor][0] in {"&", "mut"}:
            cursor += 1
        if cursor < closing and tokens[cursor][0] in minted:
            return True
    return False


def unload_fixed_domain_stack_findings(
        sources: list[tuple[str, str]], require_surface_census: bool = False
) -> list[str]:
    """Reject per-cell token arrays only inside the production unload walk.

    A global seed would reject legitimate boot validators, while scanning raw
    files would treat host-only inline tests as kernel paths. This uses
    comment/string/cfg(test)-stripped production bodies and checks every local
    array spelling the Task-7 brief calls out.
    """
    findings: list[str] = []
    # Only files that can contribute a named unload body (plus the two exact
    # census files) need lexical processing. The full source walk remains the
    # caller's responsibility; avoiding tokenization of unrelated modules
    # keeps this guard inside the existing source-audit runtime envelope.
    processed: list[tuple[str, str]] = []
    for path, original in sources:
        lowered = original.lower()
        if (_production_source_key(path) is None
                and "unload" not in lowered
                and not any(name in original
                            for name in _UNLOAD_FINALIZER_FUNCTIONS)):
            continue
        processed.append(
            (path, _strip_source_noise(_strip_cfg_test_items(original))))
    production_files = {key: text for path, text in processed
                        if (key := _production_source_key(path)) is not None}
    census_required = require_surface_census or bool(production_files)
    census_issues: list[str] = []
    if census_required:
        for key in _EXPECTED_UNLOAD_SOURCE_FILES:
            if key not in production_files:
                census_issues.append(f"production source {key} is absent")
        for name, key in _UNLOAD_STRUCT_FILES.items():
            text = production_files.get(key)
            if text is not None and _named_rust_body(text, "struct", name) is None:
                declared = any(
                    tokens[index][0] in {"type", "enum", "union", "struct"}
                    and index + 1 < len(tokens)
                    and tokens[index + 1][0] == name
                    for tokens in [_source_tokens(text)]
                    for index in range(len(tokens)))
                census_issues.append(
                    f"surface {name} "
                    + ("is not a concrete production struct" if declared else
                       "is absent from production"))
        for name, key in _UNLOAD_IMPL_FILES.items():
            text = production_files.get(key)
            if text is None:
                continue
            methods = _exact_inherent_methods(text, name)
            expected = _UNLOAD_IMPL_METHOD_SIGNATURES[name]
            if (methods is None
                    or set(methods) != set(expected)
                    or any(methods[method][0] != signature
                           or not _source_tokens(
                               text[methods[method][1][0]:methods[method][1][1]])
                           for method, signature in expected.items())):
                census_issues.append(
                    f"surface {name} has no exact production inherent "
                    "impl/function body method roster/signatures")
        for name, signature in _UNLOAD_FREE_FUNCTION_SIGNATURES.items():
            key = _UNLOAD_FUNCTION_FILES[name]
            text = production_files.get(key)
            if text is None:
                continue
            function = _exact_free_function(text, name)
            if (function is None or function[0] != signature
                    or not _source_tokens(text[function[1][0]:function[1][1]])):
                census_issues.append(
                    f"surface {name} has no exact protected-type-bound "
                    "production impl/function body")
        for name, (target, signature) in _UNLOAD_HELPER_METHOD_SIGNATURES.items():
            key = _UNLOAD_FUNCTION_FILES[name]
            text = production_files.get(key)
            if text is None:
                continue
            methods = _exact_inherent_methods(text, target)
            function = None if methods is None else methods.get(name)
            if (function is None or function[0] != signature
                    or not _source_tokens(text[function[1][0]:function[1][1]])):
                census_issues.append(
                    f"surface {name} has no exact protected-type-bound "
                    "production impl/function body")
        drain_text = production_files.get("fence.rs")
        drain_function = (None if drain_text is None else
                          _exact_free_function(drain_text, "drain_r3_finalizers"))
        drain_body = None if drain_function is None else drain_function[1]
        if (drain_body is not None
                and "R3FinalizerDrainProgress" not in {
                    token[0] for token in _source_tokens(
                        drain_text[drain_body[0]:drain_body[1]])
                }):
            census_issues.append(
                "surface R3FinalizerDrainProgress is not bound to the "
                "production impl/function body")
        if (drain_body is not None
                and not _drain_binds_acknowledged_pass_to_finish(
                    drain_text[drain_body[0]:drain_body[1]])):
            census_issues.append(
                "surface drain_r3_finalizers does not bind "
                "R3FinalizerAcknowledgedPass to finish_finalizers_drained")
        for issue in census_issues:
            findings.append(f"unload stack guard {issue}")

    for path, text in processed:
        reported: set[int] = set()
        tokens = _source_tokens(text)
        pairs = _token_pairs(tokens)
        type_aliases, rust_const_aliases = _collect_rust_aliases(tokens, pairs)
        rust_import_aliases = _collect_rust_import_aliases(tokens, pairs)
        c_aliases = _collect_c_const_aliases(text, tokens, pairs)
        c_type_aliases = _collect_c_type_aliases(tokens, pairs)
        c_source = path.lower().endswith((".c", ".h"))
        for start, end in _unload_surface_spans(
                text, c_source):
            offsets = (_c_local_array_offsets(
                           text, start, end, c_aliases, c_type_aliases)
                       if c_source else
                       _rust_local_array_offsets(
                           text, start, end, type_aliases, rust_const_aliases,
                           rust_import_aliases))
            for absolute in offsets:
                if absolute in reported:
                    continue
                reported.add(absolute)
                line = text.count("\n", 0, absolute) + 1
                findings.append(
                    f"{path}:{line}: unload scan keeps a fixed-domain local array")
    return findings


def expansion_source_findings(manifest: dict,
                              sources: list[tuple[str, str]]) -> list[str]:
    """Bind each declared expansion budget to the constant the driver requests.

    Taking already-read `(path, text)` pairs rather than walking the tree is
    what lets the self-test drive this with a planted mismatch.

    STATED BOUNDARY: this binds the manifest to the SOURCE CONSTANT, not to the
    immediate operand in the emitted instruction stream. A build in which the
    compiler materialised a different value at the call site satisfies this
    check. Recorded as measured-uncovered in the decision-signal evidence.
    """
    findings: list[str] = []
    for entry in manifest["expansionRoots"]:
        wanted = os.path.normpath(entry["sourceFile"]).replace("\\", "/")
        text = None
        for path, body in sources:
            normalized = os.path.normpath(path).replace("\\", "/")
            # A PATH-BOUNDARY match, not `endswith()`: a trailing-substring
            # match would let `session.rs` resolve to a file named e.g.
            # `evilsession.rs`, which merely ends in the wanted characters.
            # Equal, or ending in "/" + wanted, both land on a "/" or the
            # start of the string immediately before the match - a real
            # path boundary, not merely a shared tail.
            if normalized == wanted or normalized.endswith("/" + wanted):
                text = body
                break
        if text is None:
            findings.append(
                f"expansion root {entry['root']} names an unread source file "
                f"{entry['sourceFile']}")
            continue
        values = {match.group("name"): match.group("value")
                  for match in USIZE_CONST.finditer(text)}
        raw = values.get(entry["sourceConstant"])
        if raw is None:
            findings.append(
                f"expansion root {entry['root']} names an absent constant "
                f"{entry['sourceConstant']} in {entry['sourceFile']}")
            continue
        requested = int(raw.replace("_", ""))
        if requested != entry["expansionBytes"]:
            findings.append(
                f"expansion root {entry['root']} requests {requested} bytes in "
                f"{entry['sourceFile']} but declares {entry['expansionBytes']}")
    return findings


def first_call_argument(text: str, start: int) -> str | None:
    """The span of a call's first argument, starting just after its `(`.

    Tracks depth over `(`/`)` and `[`/`]`. The argument ends at the first
    comma seen at depth 0, or at the `)` that closes the call itself (which
    would take depth below 0). Reaching the end of `text` before either of
    those happens means the call could not be parsed, and `None` says so
    rather than returning a partial, unterminated span - a call site this
    reader cannot follow must fail closed, not pass by default.

    This is a raw-text scan, run BEFORE comments or strings are stripped, so
    it is depth-tracking that finds the boundary; matching what is actually
    inside that boundary is a separate step in the caller.
    """
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char in "([":
            depth += 1
        elif char == ")":
            if depth == 0:
                return text[start:index]
            depth -= 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            return text[start:index]
    return None


def expansion_callsite_findings(manifest: dict,
                                sources: list[tuple[str, str]]) -> list[str]:
    """Bind each declared expansion root to the pointer its call site passes.

    A callback pointer is formed by taking an address, not by calling it, so
    the disassembly carries NO edge from the caller to the callout and the
    binary walk cannot see this. Every other decision would hold if the call
    site were repointed at an undeclared function and the declared root left
    orphaned: the root is `no_mangle`, so it survives, still measures small,
    and still has no incoming call edge.

    The DDI's first argument is PARSED, not matched by a fixed-width text
    window: `first_call_argument` finds the actual argument span by
    tracking bracket depth, `strip_noise` removes any comment or string
    literal from it line by line, and the result must equal `Some(<root>)`
    EXACTLY once whitespace is collapsed - containment is what let a decoy
    naming the declared root anywhere within a fixed window pass a call site
    that does not actually pass that root, whether the decoy sits after the
    call or inside the argument list ahead of the real argument. An
    argument list this reader cannot terminate is reported, not passed.

    STATED BOUNDARY: this reads the SOURCE, not the emitted instruction
    stream. It proves the checked-in call site names the declared root; it
    does not prove the linker emitted that address. Recorded as
    measured-uncovered in the decision-signal evidence.

    STATED BOUNDARY: `needle`, a literal substring search for the DDI's own
    name immediately followed by `(`, cannot ENUMERATE every call site: a
    `use ... as OtherName` alias, a parenthesised fully-qualified path call
    `(module::path::Ddi)(...)`, or a file whose path this walk skips (see
    `audit_source`'s `tests` filter) all reach the real DDI without this
    text ever matching. `expansion_import_findings`'s caller-set decision is
    the companion check that closes this for any such call from a caller
    other than the declared one - spelling is irrelevant to it, because it
    reads the compiled call graph, not source text - but it cannot see a
    call rewritten IN PLACE, from the already-declared caller, to pass a
    different pointer; only this function's exact-argument match can, and
    only when the rewritten call still matches `needle`.

    Sites are attributed PER DDI, not per entry. A site must pass SOME
    declared root of its DDI, and every declared root must have at least one
    site that passes it. Both original properties survive unchanged: a site
    repointed at an undeclared function passes no declared root, and a root
    left orphaned has no site of its own. What no longer happens is two rows
    sharing one `ddi` each reading as a violation of the other -- the
    limitation this docstring used to record as unfixed for want of a second
    root to test against. `fsring_cleanup_callout` is that second root.

    STATED BOUNDARY: attribution is by the pointer a site passes, not by
    which source file it sits in. A site that passes a declared root is
    accepted wherever it appears, so this cannot say that the SETUP root is
    requested from session.rs rather than from somewhere else. The
    caller-set decision in `expansion_import_findings` is what binds a DDI
    call to a particular function, and it reads the compiled graph.
    """
    findings: list[str] = []
    roots_by_ddi: dict[str, list[str]] = {}
    for entry in manifest["expansionRoots"]:
        roots_by_ddi.setdefault(entry["ddi"], []).append(entry["root"])
    for ddi, roots in roots_by_ddi.items():
        needle = ddi + "("
        wanted = {f"Some({root})": root for root in roots}
        passed = {root: 0 for root in roots}
        for path, text in sources:
            start = 0
            while True:
                at = text.find(needle, start)
                if at < 0:
                    break
                start = at + len(needle)
                argument = first_call_argument(text, start)
                if argument is None:
                    findings.append(
                        f"expansion DDI {ddi}: the call site "
                        f"in {path} has an argument list that could not be parsed")
                    continue
                normalized = "".join(
                    "".join(strip_noise(line).split())
                    for line in argument.splitlines())
                root = wanted.get(normalized)
                if root is None:
                    findings.append(
                        f"expansion DDI {ddi}: the call site in {path} "
                        f"does not pass the declared callout of any declared root")
                    continue
                passed[root] += 1
        for root in roots:
            if passed[root] == 0:
                findings.append(
                    f"expansion root {root}: {ddi} has no call site "
                    f"in the source roots that passes it")
    return findings


def expansion_import_findings(manifest: dict, imports: dict,
                              calls: dict[str, set[str]]) -> list[str]:
    """Tie the expansion declaration to the import that makes it possible,
    and bind the DDI's ACTUAL callers to the declared ones - on the binary,
    where spelling is irrelevant.

    The first two rules alone do not prove the driver calls the DDI only from
    where it says it does. Composed with `audit_c4_imports.py`'s
    both-directions rule, the first proves the import cannot silently vanish;
    the second proves the declared caller has SOME edge to the DDI. The caller
    edge test is exact membership in `calls[caller]`, not
    `entry["ddi"] in name for name in reached`: the old substring form would
    accept any callee whose NAME merely contains the DDI's name as a
    substring, which is not what "calls this exact DDI" means.

    THE NEW DECISION (added after a reviewer defeated
    `expansion_callsite_findings`'s source-text enumeration with four
    evasions - a `use ... as` alias, a parenthesised fully-qualified path
    call, a second call site under a path the source walk skips, and the
    production site rewritten with a decoy comment): the set of image
    functions that call a declared DDI must equal EXACTLY the set of
    `expansionRoots[].caller` entries declaring that DDI. `calls` is built by
    `calls_from_disassembly`, which resolves BOTH ends of a DIRECT call
    instruction to a map symbol by ADDRESS - so however such a call was
    spelled in source (an alias, a parenthesised path, a file the text scan
    never reads), it compiles to the identical call instruction and is
    attributed to its true caller here. A second DIRECT call site added
    anywhere in the compiled tree, from any function other than the declared
    caller, shows up as an undeclared caller regardless of the syntax used to
    write it - which is exactly the coverage gap the source-only check
    cannot close on its own. Verified against the shipped images: the actual
    caller set of `KeExpandKernelStackAndCallout` is exactly
    `{fsring_dispatch_setup}` on all three profiles today, matching the one
    declared entry.

    STATED BOUNDARY: this decision inherits `calls_from_disassembly`'s own
    KNOWN GAP - a TAIL TRANSFER is not an edge, because `CALL_TARGET` matches
    only `call|callq|bl`, never a `jmp`-shaped tail jump. An UNDECLARED
    function whose call to the DDI is compiled as a tail transfer therefore
    contributes no edge to `calls` and is invisible here, and so is the
    `EXPANSION_DDIS` manifest-deletion refusal in `analyze`, which reads the
    same `calls` table. This is measured, not hypothetical: the shipped x64
    image carries 5 tail transfers (9 on ARM64), and two of the five already
    land on ntoskrnl import thunks today -
    `_ZN10fsring_fsd7session6unwind17h931718fae193960dE` tail-jumps to
    `ExFreePoolWithTag`, and `fsring_allocate_fence_scratch` tail-jumps to
    `ExAllocatePoolWithTag`, the latter a Rust function of exactly the
    offending shape (a Rust caller whose tail is an imported call). Whether a
    given call tail-jumps is a CODEGEN decision, not something a source edit
    controls directly, so this is at least as much a silent-coverage-loss
    hazard for an honest future author as it is a sabotage vector - if
    anything the stronger argument for stating it. What stays true: the
    DECLARED caller still fails closed - if `fsring_dispatch_setup`'s own
    call to the DDI ever became a tail transfer, the `declared_set -
    observed` direction below still fires, because that direction reports a
    caller LOSING its edge, not one gaining it. Only an UNDECLARED
    tail-transferring caller is invisible.

    STATED BOUNDARY: this compares CALLERS, not ARGUMENTS, so it closes three
    of the four evasions above (each adds a direct call from an undeclared
    function) and leaves the fourth OPEN: any call to the DDI from the
    ALREADY-declared caller, passing a DIFFERENT callback pointer, whether
    the existing call site is rewritten IN PLACE or a second, aliased
    expansion call is added alongside it inside the same function - the
    caller set this decision reads is `{fsring_dispatch_setup}` either way,
    so neither variant moves it. The declared caller still calls the
    declared DDI - nothing changes here - so this decision cannot see it;
    only `expansion_callsite_findings`'s source-text match can, and only
    when the added or rewritten call still matches that function's `needle`
    search. No check in this file proves the pointer argument a legitimate,
    correctly-edged caller's OWN call site passes at the binary level.
    Recorded as measured-uncovered in the decision-signal evidence.
    """
    declared = {row["symbol"] for row in imports["direct"]}
    findings: list[str] = []
    ddi_callers: dict[str, set[str]] = {}
    for entry in manifest["expansionRoots"]:
        if entry["ddi"] not in declared:
            findings.append(
                f"expansion root {entry['root']} names DDI {entry['ddi']}, which the "
                f"imports manifest does not declare")
        reached = calls.get(entry["caller"], set())
        if entry["ddi"] not in reached:
            findings.append(
                f"expansion caller {entry['caller']} has no call edge to {entry['ddi']}")
        ddi_callers.setdefault(entry["ddi"], set()).add(entry["caller"])

    # Every image function that calls a declared DDI, resolved by ADDRESS
    # through the map exactly like every other edge in this file - never by
    # any source spelling. This is what makes A, B and C above impossible to
    # hide from: whatever the source said, the compiled call still lands here.
    actual_callers: dict[str, set[str]] = {ddi: set() for ddi in ddi_callers}
    for caller, callees in calls.items():
        for ddi in ddi_callers:
            if ddi in callees:
                actual_callers[ddi].add(caller)
    for ddi, declared_set in ddi_callers.items():
        observed = actual_callers[ddi]
        for extra in sorted(observed - declared_set):
            findings.append(
                f"{extra} calls {ddi} but is not a declared expansion caller")
        for missing in sorted(declared_set - observed):
            findings.append(
                f"declared expansion caller {missing} shows no call edge to "
                f"{ddi} in the image")
    return findings


def _function_body(text: str, symbol: str) -> str | None:
    bodies = []
    for token in (f"fn {symbol}", f"struct {symbol}"):
        start = 0
        while True:
            found = text.find(token, start)
            if found < 0:
                break
            brace = text.find("{", found)
            semi = text.find(";", found)
            if brace < 0 or (semi >= 0 and semi < brace):
                start = found + len(token)
                continue
            depth = 0
            end = None
            for index, char in enumerate(text[brace:], brace):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
            bodies.append(text[found:end or found + 400])
            start = found + len(token)
        if bodies:
            break
    if not bodies:
        return None
    return max(bodies, key=len)


def native_call_findings(manifest: dict, sources: list[tuple[str, str]]) -> list[str]:
    findings: list[str] = []
    if "nativeEffectCalls" not in manifest and "nativeLifecycleCalls" not in manifest:
        return findings
    rows = list(manifest.get("nativeEffectCalls") or []) + list(
        manifest.get("nativeLifecycleCalls") or []
    )
    if "nativeEffectCalls" not in manifest:
        findings.append("missing-native-effect-call: nativeEffectCalls roster is absent")
    if "nativeLifecycleCalls" not in manifest:
        findings.append("missing-native-lifecycle-call: nativeLifecycleCalls roster is absent")
    by_rel: dict[str, str] = {}
    for path, text in sources:
        rel = path.replace("\\", "/")
        by_rel[rel] = text
        for key, value in (
            ("driver/fsring-core/src/adapter/fence.rs", "/adapter/fence.rs"),
            ("driver/fsring-fsd/src/lifecycle.rs", "/fsring-fsd/src/lifecycle.rs"),
            ("driver/fsring-fsd/src/fence.rs", "/fsring-fsd/src/fence.rs"),
            ("driver/fsring-core/src/session.rs", "/fsring-core/src/session.rs"),
            ("driver/fsring-core/src/enter.rs", "/fsring-core/src/enter.rs"),
        ):
            if rel.endswith(value):
                by_rel[key] = text
    for row in rows:
        if set(row) < {"id", "source", "symbol", "requiredCall"}:
            findings.append(f"native call row {row.get('id')} is incomplete")
            continue
        text = by_rel.get(row["source"])
        if text is None:
            findings.append(
                f"changed-source-root: native call {row['id']} source {row['source']} is absent"
            )
            continue
        body = _function_body(text, row["symbol"])
        haystack = text if body is None or row["symbol"][:1].isupper() else body
        if body is None and row["symbol"] not in text:
            findings.append(f"missing-native-effect-call: {row['symbol']} is absent")
            continue
        if body is not None:
            compact = "".join(body.split())
            if compact.endswith("Ok(())}") or compact.endswith("Ok(());}"):
                findings.append(
                    f"success-only-body: {row['source']}#{row['symbol']} returns only success"
                )
                continue
        if row["requiredCall"] not in haystack:
            findings.append(
                f"wrong-edge-or-profile: {row['source']}#{row['symbol']} "
                f"does not call {row['requiredCall']}"
            )
    return findings


def async_root_findings(manifest: dict, sources: list[tuple[str, str]]) -> list[str]:
    findings: list[str] = []
    if "asyncCallbackRoots" not in manifest:
        return findings
    required = list(manifest.get("asyncCallbackRoots") or [])
    if not required:
        findings.append("missing-callback-root: asyncCallbackRoots is empty")
        return findings
    blob = "\n".join(text for _path, text in sources)
    for name in required:
        if f"fn {name}" not in blob:
            findings.append(f"missing-callback-root: {name} is absent from source")
    return findings


def audit_source(manifest: dict, source_roots: list[str]) -> list[str]:
    findings: list[str] = []
    guard = manifest["sourceGuard"]
    sources: list[tuple[str, str]] = []
    for root in source_roots:
        if not os.path.isdir(root):
            findings.append(f"source root is missing: {root}")
            continue
        for directory, _, files in os.walk(root):
            for name in files:
                if not name.endswith((".rs", ".c", ".h")):
                    continue
                path = os.path.join(directory, name)
                # Tests are host-only helpers; they never run on a kernel stack.
                if os.sep + "tests" in path or name == "tests.rs":
                    continue
                try:
                    with open(path, encoding="utf-8") as handle:
                        sources.append((path, handle.read()))
                except UnicodeDecodeError:
                    findings.append(f"source is not strict UTF-8: {path}")
    findings += expansion_source_findings(manifest, sources)
    findings += expansion_callsite_findings(manifest, sources)
    findings += native_call_findings(manifest, sources)
    findings += async_root_findings(manifest, sources)
    unload_census_required = any(
        os.path.normpath(root).replace("\\", "/").lower().rstrip("/")
        .endswith("/fsring-fsd/src")
        for root in source_roots)
    findings += unload_fixed_domain_stack_findings(
        sources, require_surface_census=unload_census_required)
    seeds = expand_seeds(set(guard["topologyLengthSeeds"]), sources)
    fragments = [fragment.lower() for fragment in guard["topologyNameFragments"]]

    for path, text in sources:
        for number, raw in enumerate(text.splitlines(), start=1):
            line = strip_noise(raw)
            if not line.strip():
                continue
            if ALLOCA.search(line):
                findings.append(f"{path}:{number}: alloca on a kernel path")
            for pattern in (RUST_ARRAY, MAYBE_UNINIT, FROM_FN):
                match = pattern.search(line)
                if not match:
                    continue
                length = match.groupdict().get("len", "")
                if any(seed in length for seed in seeds):
                    findings.append(
                        f"{path}:{number}: function-local array sized by a topology "
                        f"ceiling ({length.strip()})")
                    continue
                name = (match.groupdict().get("name") or "").lower()
                declared = (match.groupdict().get("ty") or "").lower()
                literal = length.strip().isdigit()
                if literal and any(fragment in name or fragment in declared
                                   for fragment in fragments):
                    findings.append(
                        f"{path}:{number}: topology-named local array with a literal "
                        f"ceiling ({name or declared})")
            if path.endswith((".c", ".h")):
                vla = C_VLA.match(line)
                if vla and any(seed in vla.group("len") for seed in seeds):
                    findings.append(f"{path}:{number}: C VLA sized by a topology ceiling")

    joined = "\n".join(text for _, text in sources)
    for owner in guard["requiredPoolOwners"]:
        if f"fn {owner}" not in joined:
            findings.append(f"required pool owner {owner} is absent from the source roots")
    return findings


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def self_test() -> int:
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

    # --- fixtures that drive the real analysis -----------------------------
    #
    # Each one plants exactly one defect and asserts the shipped `analyze`
    # reports it. The clean case is what keeps the rest non-vacuous.
    fixture_manifest = {
        "schema": SCHEMA,
        "maxFrameBytes": 2048,
        "maxChainBytes": 8192,
        "roots": ["root_a", "root_b"],
        "aliases": [],
        "indirectEdges": [],
        "sourceGuard": {"seeds": [], "roots": []},
        "expansionRoots": [],
    }
    clean_symbols = {
        "root_a": [(0x1000, "obj:a.obj")],
        "root_b": [(0x2000, "obj:b.obj")],
        "leaf": [(0x3000, "obj:c.obj")],
    }
    clean_frames = {"root_a": 512, "root_b": 256, "leaf": 128}
    clean_calls = {"root_a": {"leaf"}, "root_b": set(), "leaf": set()}

    check("analyze accepts a bounded fixture",
          analyze(fixture_manifest, "Win10X64", clean_symbols, clean_frames,
                  clean_calls) == [])

    over_frame = dict(clean_frames, root_a=4096)
    findings = analyze(fixture_manifest, "Win10X64", clean_symbols, over_frame, clean_calls)
    check("analyze rejects a frame over the bound",
          any("over the 2048-byte frame bound" in f for f in findings))

    deep_calls = {"root_a": {"leaf"}, "root_b": set(), "leaf": {"deeper"}, "deeper": set()}
    deep_symbols = dict(clean_symbols, deeper=[(0x4000, "obj:d.obj")])
    deep_frames = dict(clean_frames, leaf=2000, deeper=2000)
    tight = dict(fixture_manifest, maxChainBytes=1024)
    findings = analyze(tight, "Win10X64", deep_symbols, deep_frames, deep_calls)
    check("analyze rejects a chain over the bound",
          any("chain bound" in f for f in findings))

    # A chain bound that is never computed accepts everything; this is the
    # fixture that would have caught that.
    check("the chain bound is not vacuous",
          analyze(dict(fixture_manifest, maxChainBytes=1),
                  "Win10X64", clean_symbols, clean_frames, clean_calls) != [])

    check("analyze rejects a root absent from the map",
          any("absent from the link map" in f for f in
              analyze(dict(fixture_manifest, roots=["root_a", "ghost"]), "Win10X64",
                      clean_symbols, clean_frames, clean_calls)))

    # --- expansion roots -----------------------------------------------------
    #
    # An expansion root runs on a stack the driver asked the kernel for, so it
    # is judged by the budget its own call site requests. Every fixture below
    # plants exactly one defect in that declaration and asserts `analyze`
    # reports it.
    expansion_entry = {
        "root": "root_b", "caller": "root_a", "ddi": "KeExpandKernelStackAndCallout",
        "expansionBytes": 32768, "maxFrameBytes": 8192, "maxChainBytes": 24576,
        "sourceFile": "driver/fsring-fsd/src/session.rs",
        "sourceConstant": "SETUP_STACK_EXPANSION_BYTES",
    }
    expansion_manifest = dict(fixture_manifest, expansionRoots=[expansion_entry])
    # root_b is over the GLOBAL frame bound of 2048 and inside its OWN 8192.
    expansion_frames = dict(clean_frames, root_b=6008)
    expansion_calls = {"root_a": {"leaf"}, "root_b": {"leaf"}, "leaf": set()}

    check("an expansion root is judged by its own frame bound",
          analyze(expansion_manifest, "Win10X64", clean_symbols,
                  expansion_frames, expansion_calls) == [])

    check("a non-expansion root keeps the global frame bound",
          any("over the 2048-byte frame bound" in f for f in
              analyze(fixture_manifest, "Win10X64", clean_symbols,
                      expansion_frames, expansion_calls)))

    check("an expansion root over its own frame bound is reported",
          any("over the 8192-byte frame bound" in f for f in
              analyze(expansion_manifest, "Win10X64", clean_symbols,
                      dict(expansion_frames, root_b=9000), expansion_calls)))

    check("an expansion root over its own chain bound is reported",
          any("chain bound" in f for f in
              analyze(dict(expansion_manifest,
                           expansionRoots=[dict(expansion_entry, maxChainBytes=1)]),
                      "Win10X64", clean_symbols, expansion_frames, expansion_calls)))

    check("an expansion root that is not a declared root is reported",
          any("is not a declared root" in f for f in
              analyze(dict(expansion_manifest,
                           expansionRoots=[dict(expansion_entry, root="ghost_root")]),
                      "Win10X64", clean_symbols, expansion_frames, expansion_calls)))

    check("a request over the DDI ceiling is reported",
          any("DDI ceiling" in f for f in
              analyze(dict(expansion_manifest,
                           expansionRoots=[dict(expansion_entry, expansionBytes=71681)]),
                      "Win10X64", clean_symbols, expansion_frames, expansion_calls)))

    check("a bound larger than the request is reported",
          any("against a 32768-byte request" in f for f in
              analyze(dict(expansion_manifest,
                           expansionRoots=[dict(expansion_entry, maxChainBytes=40000)]),
                      "Win10X64", clean_symbols, expansion_frames, expansion_calls)))

    # The decision that keeps the expansion a boundary rather than a comment.
    check("a direct call into an expansion root is reported",
          any("is called directly by" in f for f in
              analyze(expansion_manifest, "Win10X64", clean_symbols, expansion_frames,
                      dict(expansion_calls, leaf={"root_b"}))))

    # A caller that DOES reach the DDI, reused by the DDI-without-root fixture
    # below and by the import/caller-set fixtures that follow it.
    reaching_calls = dict(expansion_calls,
                          root_a={"leaf", "KeExpandKernelStackAndCallout"})

    # --- the DDI list lives in the script, not the manifest -----------------
    #
    # `"expansionRoots": []` (or the key deleted, or the one entry removed)
    # must not silently turn the nine decisions above into no-ops while the
    # image still calls the DDI - that is the exact C4.1a hole a two-line
    # manifest edit used to reopen. `EXPANSION_DDIS` is a module constant the
    # manifest cannot touch.
    check("the image calling an expansion DDI with no declared entry is refused",
          any("no expansionRoots entry declares it" in f for f in
              analyze(dict(fixture_manifest, expansionRoots=[]), "Win10X64",
                      clean_symbols, clean_frames,
                      dict(clean_calls, root_a={"leaf", "KeExpandKernelStackAndCallout"}))))
    check("a declared expansion root silences the DDI-without-root check",
          not any("no expansionRoots entry declares it" in f for f in
                  analyze(expansion_manifest, "Win10X64", clean_symbols,
                          expansion_frames, reaching_calls)))

    # --- the two manifests, and the call that justifies the import ---------
    imports_fixture = {"direct": [
        {"logical": "KeExpandKernelStackAndCallout", "module": "ntoskrnl.exe",
         "symbol": "KeExpandKernelStackAndCallout"}]}

    check("a declared DDI present in both manifests is accepted",
          expansion_import_findings(expansion_manifest, imports_fixture,
                                    reaching_calls) == [])

    check("a DDI the imports manifest does not declare is reported",
          any("does not declare" in f for f in expansion_import_findings(
              expansion_manifest, {"direct": []}, reaching_calls)))

    # "has no call edge to" is decision 8's own phrasing, distinct from
    # decision 11's "shows no call edge to ... in the image" below - both
    # fire on this fixture (nobody calls the DDI at all), so the substring
    # asserted here has to be the one decision 8 alone produces, or mutating
    # decision 8 away would still leave decision 11 covering for it and the
    # mutant would survive undetected.
    check("a caller with no edge to the DDI is reported",
          any("has no call edge to" in f for f in expansion_import_findings(
              expansion_manifest, imports_fixture, expansion_calls)))

    # --- the binary caller-set decision (Critical 1's fix) ------------------
    #
    # `calls` is resolved by ADDRESS, so this decision is immune to every
    # source-text evasion `expansion_callsite_findings` alone cannot
    # enumerate: a `use ... as` alias, a parenthesised fully-qualified path
    # call, or a second site under a path the source walk skips would all
    # still compile to a real call edge from SOME function - and if that
    # function is not the declared caller, this is what catches it.
    calls_with_impostor_caller = dict(reaching_calls,
                                      impostor={"KeExpandKernelStackAndCallout"})
    check("an undeclared function calling the DDI is reported",
          any("but is not a declared expansion caller" in f for f in
              expansion_import_findings(expansion_manifest, imports_fixture,
                                        calls_with_impostor_caller)))
    # The twin: with the impostor gone, the same fixture is clean. Without
    # this the check above could be satisfied by a helper that always
    # reports SOMETHING, whether or not an impostor is actually present.
    check("the caller-set check is not vacuous",
          expansion_import_findings(expansion_manifest, imports_fixture,
                                    reaching_calls) == [])

    # The reverse direction: a declared caller that never reaches the DDI is
    # reported even when a DIFFERENT function does - two independent
    # findings, not one masking the other.
    calls_wrong_caller = {"root_a": {"leaf"}, "root_b": {"leaf"}, "leaf": set(),
                          "impostor": {"KeExpandKernelStackAndCallout"}}
    wrong_caller_findings = expansion_import_findings(
        expansion_manifest, imports_fixture, calls_wrong_caller)
    check("a declared caller that never calls the DDI is reported even when "
          "another function does",
          any("shows no call edge to" in f for f in wrong_caller_findings))
    check("the undeclared caller is reported alongside it",
          any("but is not a declared expansion caller" in f
              for f in wrong_caller_findings))

    # Exact membership, not `entry["ddi"] in name`: a callee whose name merely
    # CONTAINS the DDI's name as a substring must not satisfy the caller edge.
    # Again "has no call edge to" (decision 8's own phrasing), not the
    # generic substring both decisions' messages share.
    check("a callee whose name only contains the DDI as a substring does not count",
          any("has no call edge to" in f for f in expansion_import_findings(
              expansion_manifest, imports_fixture,
              dict(expansion_calls,
                   root_a={"NotKeExpandKernelStackAndCalloutReally"}))))

    # --- the request in the source, and the budget in the manifest ----------
    #
    # `expansionBytes` is a number in a manifest. This is what ties it to the
    # number the driver actually passes to the DDI.
    good_source = [(
        os.path.join("driver", "fsring-fsd", "src", "session.rs"),
        "pub const SETUP_STACK_EXPANSION_BYTES: usize = 32768;\n")]

    check("a matching constant is accepted",
          expansion_source_findings(expansion_manifest, good_source) == [])

    check("a constant that disagrees with the manifest is reported",
          any("but declares 32768" in f for f in expansion_source_findings(
              expansion_manifest,
              [(good_source[0][0],
                "pub const SETUP_STACK_EXPANSION_BYTES: usize = 4096;\n")])))

    check("an absent constant is reported",
          any("absent constant" in f for f in expansion_source_findings(
              expansion_manifest, [(good_source[0][0], "// nothing here\n")])))

    check("an unread source file is reported",
          any("unread source file" in f for f in
              expansion_source_findings(expansion_manifest, [])))

    # A digit-separated literal is legal Rust and must not read as a mismatch.
    check("an underscored literal is read as its value",
          expansion_source_findings(
              expansion_manifest,
              [(good_source[0][0],
                "pub const SETUP_STACK_EXPANSION_BYTES: usize = 32_768;\n")]) == [])

    # --- the pointer actually handed to the DDI ----------------------------
    #
    # The root is bounded, never called directly, and its budget is bound to
    # the source constant. None of that says it is the pointer the call site
    # passes. Without this, repointing the argument at an undeclared function
    # leaves every other check green while the real callout goes unmeasured.
    #
    # This block's fixture text names the real production root
    # (`fsring_setup_callout`), so it is checked against a manifest declaring
    # that root rather than against `expansion_manifest`'s generic `root_b` -
    # every other fixture in this file keeps using `root_a`/`root_b`, so
    # nothing above or below this block is touched.
    callsite_manifest = dict(
        expansion_manifest,
        expansionRoots=[dict(expansion_entry, root="fsring_setup_callout")])
    callsite_path = os.path.join("driver", "fsring-fsd", "src", "session.rs")
    callsite_text = (
        "    let expanded = unsafe {\n"
        "        fsring_sys::c4::KeExpandKernelStackAndCallout(\n"
        "            Some(fsring_setup_callout),\n"
        "            core::ptr::addr_of_mut!(block).cast::<c_void>(),\n"
        "            SETUP_STACK_EXPANSION_BYTES as SIZE_T,\n"
        "        )\n"
        "    };\n")

    check("a call site passing the declared root is accepted",
          expansion_callsite_findings(
              callsite_manifest, [(callsite_path, callsite_text)]) == [])

    check("a call site passing some other function is reported",
          any("does not pass the declared callout" in f for f in
              expansion_callsite_findings(
                  callsite_manifest,
                  [(callsite_path,
                    callsite_text.replace("Some(fsring_setup_callout)",
                                          "Some(some_other_callout)"))])))

    check("no call site at all is reported",
          any("has no call site" in f for f in expansion_callsite_findings(
              callsite_manifest, [(callsite_path, "// nothing here\n")])))

    # The re-export in fsring-sys names the DDI without calling it. A reader
    # that counted it as a call site would demand a callout argument that a
    # `pub use` list cannot have.
    check("a re-export is not a call site",
          any("has no call site" in f for f in expansion_callsite_findings(
              callsite_manifest,
              [(os.path.join("driver", "fsring-sys", "src", "c4.rs"),
                "pub use wdk_sys::ntddk::{\n"
                "    KeEnterCriticalRegion, KeExpandKernelStackAndCallout,\n"
                "    KeInitializeDpc,\n"
                "};\n")])))

    # A fixed-width text window is defeated by a decoy that merely CONTAINS
    # the declared root's name somewhere nearby. This is the reviewer's live
    # counter-example: repoint the real argument, then plant the declared
    # root's name in a comment within the window so the old check saw it and
    # passed. The decoy sits after the whole call here - outside the parsed
    # argument entirely.
    # --- two roots sharing one DDI ------------------------------------------
    #
    # The case the docstring above used to record as untestable. Each root's
    # own call site used to read as a violation of the other's, so declaring a
    # second root would have failed the audit for a driver that was correct.
    two_root_manifest = dict(
        expansion_manifest,
        expansionRoots=[dict(expansion_entry, root="fsring_setup_callout"),
                        dict(expansion_entry, root="fsring_cleanup_callout")])
    cleanup_path = os.path.join("driver", "fsring-fsd", "src", "control.rs")
    cleanup_text = callsite_text.replace("fsring_setup_callout",
                                         "fsring_cleanup_callout")

    check("two roots each with their own call site are accepted",
          expansion_callsite_findings(
              two_root_manifest,
              [(callsite_path, callsite_text),
               (cleanup_path, cleanup_text)]) == [])

    # Anti-vacuity for the check above: it must not pass by accepting
    # everything. A second root whose call site is missing is still reported,
    # even though the FIRST root's site is present and valid.
    check("a second root with no call site of its own is still reported",
          any("fsring_cleanup_callout" in f and "has no call site" in f
              for f in expansion_callsite_findings(
                  two_root_manifest, [(callsite_path, callsite_text)])))

    check("a site passing neither declared root is reported",
          any("does not pass the declared callout" in f for f in
              expansion_callsite_findings(
                  two_root_manifest,
                  [(callsite_path, callsite_text),
                   (cleanup_path,
                    cleanup_text.replace("Some(fsring_cleanup_callout)",
                                         "Some(some_other_callout)"))])))

    check("a decoy naming the root outside the first argument is reported",
          any("does not pass the declared callout" in f for f in
              expansion_callsite_findings(
                  callsite_manifest,
                  [(callsite_path,
                    callsite_text.replace("Some(fsring_setup_callout)",
                                          "Some(some_other_callout)")
                    + "    // decoy for audit text-matching: Some(fsring_setup_callout)\n")])))

    # The harder case `strip_noise` exists for: the decoy comment sits
    # INSIDE the argument list, immediately before the real (wrong) argument.
    # A depth scan alone would include the decoy's `(` and `)` in its span
    # and stop at the real argument's trailing comma - so the comment must
    # be stripped from the span before it is compared, not merely bounded.
    check("a decoy naming the root inside the first argument is reported",
          any("does not pass the declared callout" in f for f in
              expansion_callsite_findings(
                  callsite_manifest,
                  [(callsite_path,
                    callsite_text.replace(
                        "Some(fsring_setup_callout)",
                        "// decoy for audit text-matching: "
                        "Some(fsring_setup_callout)\n"
                        "            Some(some_other_callout)"))])))

    # An argument list this reader cannot terminate - here, a call site whose
    # text ends before the closing paren is ever reached - must be reported,
    # not silently treated as a pass. Without this fixture, `argument is
    # None` has a check with no mutant driving it: an audit that stopped
    # reporting an unparsable call site would still show every other check
    # green. The guard is also what keeps this call from indexing into the
    # `None` it just failed to parse, so a mutant that deletes it is caught
    # here as a reported finding, not chased down as a crash elsewhere.
    try:
        unterminated_findings = expansion_callsite_findings(
            callsite_manifest,
            [(callsite_path,
              "    let expanded = unsafe {\n"
              "        fsring_sys::c4::KeExpandKernelStackAndCallout(\n"
              "            Some(fsring_setup_callout)\n")])
    except AttributeError:
        unterminated_findings = []
    check("an unterminated argument list is reported as unparsable",
          any("could not be parsed" in f for f in unterminated_findings))

    # --- aliases and same-address folds ------------------------------------
    #
    # Every fixture above sets `aliases` and `indirectEdges` empty, so the
    # whole alias block, the whole fold block and every indirect-edge rule ran
    # against nothing - while guarding four alias rows and two edges in the
    # shipped manifest. These drive them.
    alias_manifest = dict(fixture_manifest, aliases=[{
        "canonical": "memcpy", "aliases": ["memmove"],
        "profiles": ["Win10X64"], "mapMember": "ntoskrnl:memcpy.obj"}])
    alias_symbols = dict(clean_symbols,
                         memcpy=[(0x4000, "ntoskrnl:memcpy.obj")],
                         memmove=[(0x4000, "ntoskrnl:memcpy.obj")])
    alias_frames = dict(clean_frames, memcpy=0, memmove=0)
    alias_calls = dict(clean_calls, memcpy=set(), memmove=set())

    def aliased(symbols=None, manifest=None):
        return analyze(alias_manifest if manifest is None else manifest,
                       "Win10X64",
                       alias_symbols if symbols is None else symbols,
                       alias_frames, alias_calls)

    check("a declared alias pair is accepted", aliased() == [])
    check("an alias at a different address is refused",
          any("not the same address and member" in f for f in aliased(
              symbols=dict(alias_symbols,
                           memmove=[(0x5000, "ntoskrnl:memcpy.obj")]))))
    check("an alias in a different member is refused",
          any("not the same address and member" in f for f in aliased(
              symbols=dict(alias_symbols,
                           memmove=[(0x4000, "ntoskrnl:other.obj")]))))
    check("a canonical in the wrong member is refused",
          any("lives in" in f for f in aliased(manifest=dict(
              alias_manifest, aliases=[dict(alias_manifest["aliases"][0],
                                            mapMember="ntoskrnl:other.obj")]))))
    check("an absent canonical is refused",
          any("canonical memcpy is absent" in f for f in aliased(
              symbols=clean_symbols)))
    check("an absent declared alias is refused",
          any("declared alias memmove is absent" in f for f in aliased(
              symbols=dict(clean_symbols,
                           memcpy=[(0x4000, "ntoskrnl:memcpy.obj")]))))
    check("an undeclared fold beside a declared canonical is named",
          any("undeclared same-address fold" in f for f in aliased(
              symbols=dict(alias_symbols,
                           stranger=[(0x4000, "ntoskrnl:memcpy.obj")]))))
    # A fold rule that stopped grouping would accept the line above; this is
    # the twin that keeps the accept case from being the only evidence.
    check("the fold rule does not fire on the declared pair alone",
          not any("undeclared same-address fold" in f for f in aliased()))

    check("a root that occurs at two addresses is refused",
          any("more than one address" in f for f in analyze(
              fixture_manifest, "Win10X64",
              dict(clean_symbols,
                   root_a=[(0x1000, "obj:a.obj"), (0x9000, "obj:z.obj")]),
              clean_frames, clean_calls)))
    check("a root that is a declared alias is refused",
          any("is an alias" in f for f in analyze(
              dict(alias_manifest, roots=["root_a", "memmove"]), "Win10X64",
              alias_symbols, alias_frames, alias_calls)))

    # --- declared indirect edges -------------------------------------------
    edge_manifest = dict(fixture_manifest, indirectEdges=[{
        "id": "fixture-edge", "profiles": ["Win10X64"],
        "caller": "root_a", "storage": "slot_a", "kind": "closed-target-set",
        "targets": [{"kind": "internal", "symbol": "heavy",
                     "mapMember": "obj:h.obj"}]}])
    edge_symbols = dict(clean_symbols,
                        slot_a=[(0x6000, "obj:s.obj")],
                        heavy=[(0x7000, "obj:h.obj")])
    edge_frames = dict(clean_frames, slot_a=0, heavy=4096)
    edge_calls = dict(clean_calls, slot_a=set(), heavy=set())

    check("a well-formed indirect edge is accepted",
          analyze(edge_manifest, "Win10X64", edge_symbols, edge_frames,
                  edge_calls) == [])
    check("an indirect edge naming an absent storage slot is refused",
          any("names absent symbol slot_a" in f for f in analyze(
              edge_manifest, "Win10X64",
              {k: v for k, v in edge_symbols.items() if k != "slot_a"},
              edge_frames, edge_calls)))
    check("a closed target absent from the map is refused",
          any("closed target heavy" in f for f in analyze(
              edge_manifest, "Win10X64",
              {k: v for k, v in edge_symbols.items() if k != "heavy"},
              edge_frames, edge_calls)))
    check("an indirect storage slot may not also be a root",
          any("may not also be a root" in f for f in analyze(
              dict(edge_manifest, roots=["root_a", "root_b", "slot_a"]),
              "Win10X64", edge_symbols, edge_frames, edge_calls)))
    # The presence checks above pass even if the edge is never walked. This is
    # the one that proves a resolved-pointer call is actually charged: without
    # the union, root_a reaches 640 bytes and clears a 1024-byte bound.
    check("a declared indirect edge is charged to the chain",
          any("chain bound" in f for f in analyze(
              dict(edge_manifest, maxChainBytes=1024), "Win10X64", edge_symbols,
              edge_frames, edge_calls)))
    check("an edge for another profile is not charged",
          analyze(dict(edge_manifest, maxChainBytes=1024), "Win10Arm64",
                  edge_symbols, edge_frames, edge_calls) == [])

    # --- both frame sources must keep measuring, and keep agreeing ----------
    #
    # The unwind source contributed zero on every leg for the whole of slice
    # C4 and nothing noticed, because nothing counted what it resolved. These
    # are the two guards that make that loud.
    census_manifest = dict(fixture_manifest, frameSources={
        "Win10X64": {"minPrologueFunctions": 3, "minUnwindFunctions": 2,
                     "maxDeclinedDisagreements": 0,
                     "maxTruncatedDisagreements": 0}})
    census_prologue = {"a": 100, "b": 200, "c": 300}
    census_unwind = {"a": 100, "b": 200}
    check("a census that is met has no finding",
          frame_source_findings(census_manifest, "Win10X64", census_prologue,
                                census_unwind) == [])
    check("an unwind source that resolved too little is named",
          any("unwind source resolved" in f for f in frame_source_findings(
              census_manifest, "Win10X64", census_prologue, {"a": 100})))
    # This is the one that matters: a source that goes completely blind.
    check("an unwind source that resolved nothing is named",
          any("unwind source resolved 0" in f for f in frame_source_findings(
              census_manifest, "Win10X64", census_prologue, {})))
    check("a prologue source that resolved too little is named",
          any("prologue source resolved" in f for f in frame_source_findings(
              census_manifest, "Win10X64", {"a": 100}, census_unwind)))
    # `prologue 0, unwind N`: a prologue the reader declines to follow, where
    # the enforced maximum takes the unwind value. The whole of both x64
    # profiles, and 31 of ARM64's 34.
    declined_prologue = {"a": 0, "b": 200, "c": 300}
    check("a declined disagreement beyond the census is named",
          any("declined 1 functions" in f for f in frame_source_findings(
              census_manifest, "Win10X64", declined_prologue, census_unwind)))
    tolerate_declined = dict(census_manifest, frameSources={
        "Win10X64": dict(census_manifest["frameSources"]["Win10X64"],
                         maxDeclinedDisagreements=1)})
    check("a declined disagreement is accepted within the census",
          frame_source_findings(tolerate_declined, "Win10X64",
                                declined_prologue, census_unwind) == [])

    # `0 < prologue < unwind`: the reader followed a prologue and stopped
    # short. ARM64's other three, all of them ours, and the live signal.
    truncated_prologue = {"a": 50, "b": 200, "c": 300}
    check("a truncated disagreement beyond the census is named",
          any("stopped short" in f for f in frame_source_findings(
              census_manifest, "Win10X64", truncated_prologue, census_unwind)))
    check("a truncated disagreement is accepted within its own census",
          frame_source_findings(
              dict(census_manifest, frameSources={
                  "Win10X64": dict(census_manifest["frameSources"]["Win10X64"],
                                   maxTruncatedDisagreements=1)}),
              "Win10X64", truncated_prologue, census_unwind) == [])

    # The masking the split exists to refuse, as one pair. Both fixtures have
    # exactly ONE disagreement, so a single total could not tell them apart:
    # the library floor falling by one while our truncations rise by one used
    # to leave the census green. The declined allowance is spent above; the
    # truncated one is not spendable by it.
    check("the same total reported as truncated instead is refused",
          any("stopped short" in f for f in frame_source_findings(
              tolerate_declined, "Win10X64", truncated_prologue, census_unwind)))


    # The other direction means the prologue reader is charging something the
    # unwind record does not, which is how a frame gets invented. It is
    # refused however small the census allowance is.
    check("a disagreement in the over-counting direction is refused",
          any("over-counting direction" in f for f in frame_source_findings(
              dict(census_manifest, frameSources={
                  "Win10X64": dict(census_manifest["frameSources"]["Win10X64"],
                                   maxDeclinedDisagreements=9,
                                   maxTruncatedDisagreements=9)}),
              "Win10X64", {"a": 999, "b": 200, "c": 300}, census_unwind)))
    check("a profile with no declared census is refused",
          any("no frame-source census" in f for f in frame_source_findings(
              census_manifest, "Win7X64", census_prologue, census_unwind)))

    # An over-count on a function whose unwind record sets a frame pointer is
    # the record declining to state a size, not a frame being invented: after
    # `mov fp, sp` the unwinder restores SP from FP. It is censused rather than
    # refused -- and the census is the only thing standing between it and the
    # refusal above, so both directions get a case.
    over_prologue = {"a": 999, "b": 200, "c": 300}
    permissive = dict(census_manifest, frameSources={
        "Win10X64": dict(census_manifest["frameSources"]["Win10X64"],
                         maxDeclinedDisagreements=9,
                         maxTruncatedDisagreements=9)})
    check("an over-count on a frame-pointer function is not called invented",
          not any("over-counting direction" in f for f in frame_source_findings(
              permissive, "Win10X64", over_prologue, census_unwind, {"a"})))
    check("an over-count on a frame-pointer function beyond its census is named",
          any("frame-pointer functions" in f for f in frame_source_findings(
              permissive, "Win10X64", over_prologue, census_unwind, {"a"})))
    check("an over-count on a frame-pointer function within its census passes",
          frame_source_findings(
              dict(census_manifest, frameSources={
                  "Win10X64": dict(census_manifest["frameSources"]["Win10X64"],
                                   maxDeclinedDisagreements=9,
                                   maxTruncatedDisagreements=9,
                                   maxFramePointerDisagreements=1)}),
              "Win10X64", over_prologue, census_unwind, {"a"}) == [])
    # The strict reading is what a caller gets by saying nothing: a frame
    # pointer has to be PROVED from the record, never assumed.
    check("an over-count is still refused when no frame pointer is proved",
          any("over-counting direction" in f for f in frame_source_findings(
              permissive, "Win10X64", over_prologue, census_unwind)))
    check("a frame pointer on some other function does not excuse this one",
          any("over-counting direction" in f for f in frame_source_findings(
              permissive, "Win10X64", over_prologue, census_unwind, {"b"})))

    # The reader that produces that set, over the exact text each tool prints.
    arm_fp_record = "\n".join([
        "  RuntimeFunction {",
        "    Function: 0x180034F84",
        "    ExceptionData {",
        "      Prologue [",
        "        0xe1                ; mov fp, sp",
        "        0x81                ; stp x29, x30, [sp, #-16]!",
        "        0xe4                ; end",
        "      ]",
        "    }",
        "  }",
    ])
    check("the ARM64 set_fp opcode is read from the record",
          frame_pointer_functions(arm_fp_record, "arm64",
                                  [(0x180034F84, "fp")], 0) == {"fp"})
    check("an ARM64 record without set_fp reports no frame pointer",
          frame_pointer_functions(
              arm_fp_record.replace("; mov fp, sp", "; nop"), "arm64",
              [(0x180034F84, "fp")], 0) == set())

    # --- the map must describe the image it measures ------------------------
    #
    # This auditor performed no identity check of any kind: it declared
    # `--imports` and `--pdb`, read neither, and parsed the map timestamp only
    # to discard it. A stale or foreign map was accepted in silence and every
    # number below it was then about a different build.
    identity_pe = {"timestamp": 0x6A74549D, "base": 0x180000000,
                   "machine": "Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)"}
    identity_map = {"timestamp": "6a74549d", "base": 0x180000000}
    check("a map that describes the image has no finding",
          image_identity_findings("x64", identity_pe, identity_map) == [])
    check("a stale map timestamp is refused",
          any("timestamp is not the PE" in f for f in image_identity_findings(
              "x64", identity_pe, dict(identity_map, timestamp="6a745400"))))
    check("a relocated map base is refused",
          any("preferred base" in f for f in image_identity_findings(
              "x64", identity_pe, dict(identity_map, base=0x140000000))))
    check("a map from the other architecture is refused",
          any("machine" in f for f in image_identity_findings(
              "arm64", identity_pe, identity_map)))
    check("a map with no timestamp is refused",
          any("no timestamp" in f for f in image_identity_findings(
              "x64", identity_pe, {"base": 0x180000000})))
    check("a map with no preferred base is refused",
          any("no preferred load address" in f
              for f in image_identity_findings(
                  "x64", identity_pe, {"timestamp": "6a74549d"})))

    # --- the frame readers must match real disassembler output -------------
    for text, pattern, expected in (
        ("  sub rsp, 0x438", SUB_RSP, 0x438),
        ("  subq\t$0x438, %rsp", SUB_RSP, 0x438),
        ("  sub sp, sp, #0x30", ARM_SUB_SP, 0x30),
        ("  stp x29, x30, [sp, #-0x20]!", ARM_STP_PRE, 0x20),
    ):
        match = pattern.search(text)
        digits = [g for g in match.groups() if g is not None] if match else []
        check(f"frame reader matches {text.strip()!r}",
              bool(digits) and int(digits[0], 16) == expected)
    check("the chkstk probe size is read",
          bool(CHKSTK_SIZE.search("  movl\t$0xe38, %eax")))

    # --- the prologue is summed, not maximised -----------------------------
    #
    # Text taken verbatim from `llvm-objdump -d` on the 2026-08-06 x64 and
    # ARM64 images, tabs included. The reader this replaced took the maximum
    # of the stack-moving instructions, so it reported 1080 where the x64
    # prologue allocates 1144 and 1056 where the ARM64 prologue allocates
    # 1152.
    x64_prologue = "\n".join((
        "180001000: 41 57\tpushq\t%r15",
        "180001002: 41 56\tpushq\t%r14",
        "180001004: 48 81 ec 38 04 00 00\tsubq\t$0x438, %rsp",
        "180001013: 48 89 d3\tmovq\t%rdx, %rbx",
        "180001016: 48 81 ec 00 09 00 00\tsubq\t$0x900, %rsp",
    ))
    x64_code = [(0x180001000, "one")]
    check("an x64 prologue sums its pushes and its sub",
          prologue_allocation(x64_prologue, "x64", x64_code) == {"one": 0x438 + 16})
    # The trailing `subq $0x900` sits after the first body instruction. A
    # reader that kept accumulating would report 0x438 + 16 + 0x900.
    check("allocation after the prologue is not charged",
          prologue_allocation(x64_prologue, "x64", x64_code)["one"] < 0x438 + 16 + 0x900)

    arm_prologue = "\n".join((
        "180001000: a9ba53f3\tstp\tx19, x20, [sp, #-0x60]!",
        "180001004: a9015bf5\tstp\tx21, x22, [sp, #0x10]",
        "180001018: d11083ff\tsub\tsp, sp, #0x420",
        "18000101c: b9414c36\tldr\tw22, [x1, #0x14c]",
    ))
    check("an ARM64 prologue sums its pre-indexed save and its sub",
          prologue_allocation(arm_prologue, "arm64", [(0x180001000, "one")])
          == {"one": 0x60 + 0x420})

    # `__chkstk` is not exported, so the disassembly labels every call to it as
    # an offset from an unrelated export - measured 2026-08-07, the string
    # "__chkstk" appears zero times in this image. Only the link map names it,
    # and only at its address.
    chkstk_text = "\n".join((
        "180002250: 41 57\tpushq\t%r15",
        "18000225c: b8 38 17 00 00\tmovl\t$0x1738, %eax",
        "180002261: e8 5c 2d 01 00\tcallq\t0x180014fc2 <__GSHandlerCheck_EH4+0xc2>",
        "180002266: 48 29 c4\tsubq\t%rax, %rsp",
    ))
    chkstk_code = [(0x180002250, "probed"), (0x180014fc2, "__chkstk")]
    check("a probed frame is charged through the map, not the label",
          prologue_allocation(chkstk_text, "x64", chkstk_code)
          == {"probed": 0x1738 + 8})
    # Without the map row for `__chkstk` the same call is an ordinary callee and
    # the probe is not charged. This is the twin that keeps the check above from
    # passing for the wrong reason.
    check("a probe is not charged to an unrelated callee",
          prologue_allocation(chkstk_text, "x64",
                              [(0x180002250, "probed")]) == {"probed": 8})

    # --- the unwind source, over verbatim tool output -----------------------
    #
    # The reader this replaced had no fixture text at all, and neither of its
    # two patterns matched a single line either tool prints. Both blocks below
    # are copied verbatim from this machine's output on the 2026-08-06 images.
    x64_unwind = "\n".join((
        "Function Table:",
        "  Start Address: 0x1000",
        "  End Address: 0x1b14",
        "    Unwind Codes:",
        "      0x13: UOP_AllocLarge 135",
        "      0x0c: UOP_PushNonVol RBX",
        "      0x0b: UOP_PushNonVol RBP",
        "Function Table:",
        "  Start Address: 0x2000",
        "    Unwind Codes:",
        "      0x0a: UOP_AllocSmall 72",
        "      0x06: UOP_SaveXMM128 XMM6 [0x0030]",
        "      0x04: UOP_SetFPReg ",
    ))
    x64_unwind_code = [(0x180001000, "large"), (0x180002000, "small")]
    # AllocLarge prints SLOTS and AllocSmall prints BYTES. Cross-checked over
    # all 132 records of the shipped image: 135 slots is 1080 bytes, so `large`
    # is 1080 + two pushes; `small` is 72 bytes flat, and neither SaveXMM128
    # nor SetFPReg allocates.
    check("the x64 unwind operand encoding is slots for large, bytes for small",
          unwind_from_text(x64_unwind, "x64", x64_unwind_code, 0x180000000)
          == {"large": 135 * 8 + 16, "small": 72})
    check("an unwind record is resolved by address, not by label",
          unwind_from_text(x64_unwind, "x64", [(0x180001000, "large")],
                           0x180000000)["large"] == 135 * 8 + 16)
    # Two records inside one map symbol are an epilog record, not a second
    # frame: they fold by maximum rather than summing.
    check("two records for one symbol fold by maximum",
          unwind_from_text(x64_unwind, "x64", [(0x180001000, "one")],
                           0x180000000) == {"one": 135 * 8 + 16})

    arm_unwind = "\n".join((
        "  RuntimeFunction {",
        "    Function: 0x180001000",
        "    ExceptionData {",
        "      Prologue [",
        "        0xc042              ; sub sp, #1056",
        "        0x4a                ; stp x29, x30, [sp, #80]",
        "        0x2c                ; stp x19, x20, [sp, #-96]!",
        "        0xe4                ; end",
    ))
    # `Function:` is an ADDRESS here. The reader this replaced captured it as a
    # symbol name, which matched nothing in the map, which is why the ARM64
    # unwind source silently contributed zero.
    check("the ARM64 unwind reader sums its prologue by address",
          unwind_from_text(arm_unwind, "arm64", [(0x180001000, "one")], 0)
          == {"one": 1056 + 96})
    check("an ARM64 record below the first symbol is owned by nobody",
          unwind_from_text(arm_unwind, "arm64", [(0x180002000, "later")], 0) == {})

    # The PACKED ARM64 encoding, verbatim. It states the allocation outright
    # and prints a synthesized prologue with no `0xNN ;` byte-code prefix, so
    # the two byte-code patterns match none of it. Reading only those patterns
    # summed every packed record to zero and stored that zero as a
    # measurement, which is how eight ARM64 functions with a 96-byte frame
    # were recorded as frameless.
    arm_packed = "\n".join((
        "  RuntimeFunction {",
        "    Function: 0x18000EA38",
        "    Fragment: No",
        "    FunctionLength: 576",
        "    RegF: 0",
        "    RegI: 10",
        "    HomedParameters: No",
        "    CR: 1",
        "    FrameSize: 96",
        "    Prologue [",
        "      str lr, [sp, #80]",
        "      stp x27, x28, [sp, #64]",
        "      stp x19, x20, [sp, #-96]!",
    ))
    check("the packed ARM64 encoding is read from FrameSize",
          unwind_from_text(arm_packed, "arm64", [(0x18000EA38, "packed")], 0)
          == {"packed": 96})
    # The twin: with FrameSize removed, the synthesized prologue supplies
    # nothing, because those lines carry no `0xNN ;` byte-code prefix. This is
    # what proves the 96 above comes from FrameSize and not from the store
    # below it — and it is the shape the reader used to see for every packed
    # record.
    check("a packed record without FrameSize measures nothing, not a guess",
          unwind_from_text("\n".join(l for l in arm_packed.splitlines()
                                     if "FrameSize" not in l),
                           "arm64", [(0x18000EA38, "packed")], 0)
          == {"packed": 0})

    # --- attribution: address ownership, not disassembler labels -----------
    #
    # A final PE has no COFF symbol table, so `llvm-objdump` labels only the
    # exports. This fixture reproduces that exactly: one label for three
    # functions. Charging by label gives the export its neighbour's 0x900 frame
    # and turns the call into a self-edge the chain walk drops, which is how a
    # frame moved out of a root - and nothing else - could pass both bounds.
    attribution = "\n".join((
        "0000000180001000 <root_a>:",
        "180001000: 48 83 ec 40                   subq    $0x40, %rsp",
        "180001004: e8 f7 00 00 00                callq   0x180001100 <root_a+0x100>",
        "180001009: e8 f2 0f 00 00                callq   0x180002000 <root_a+0x1000>",
        "18000100e: c3                            retq",
        "180001100: 48 81 ec 00 09 00 00          sub     rsp, 0x900",
        "180001107: c3                            retq",
        "180002000: ff 25 00 00 00 00             jmpq    *(%rip)",
    ))
    attribution_code = [(0x180001000, "root_a"), (0x180001100, "helper"),
                        (0x180002000, "KeSetEvent")]
    measured = prologue_allocation(attribution, "x64", attribution_code)
    check("the owning function is charged its own frame", measured.get("helper") == 0x900)
    check("a neighbour's frame is not charged to the export above it",
          measured.get("root_a") == 0x40)
    edges = calls_from_disassembly(attribution, attribution_code)
    check("a call to an internal function names that function",
          edges.get("root_a") == {"helper", "KeSetEvent"})
    check("an import thunk allocates nothing and ends the chain",
          measured.get("KeSetEvent", 0) == 0 and not edges.get("KeSetEvent"))
    check("an address below the first symbol is owned by nobody",
          owner_at(attribution_code, 0x180000fff) is None)
    check("a map that flags no function measures nothing rather than zero",
          prologue_allocation(attribution, "x64", []) == {})

    # The two together: with the frame moved into `helper`, the root's own
    # frame passes while the chain still charges it. Label attribution reported
    # a 1-symbol chain of 0x900 for the root; address attribution reports both.
    moved_manifest = dict(fixture_manifest, roots=["root_a"], maxChainBytes=2048)
    moved_symbols = {"root_a": [(0x180001000, "obj:a.obj")],
                     "helper": [(0x180001100, "obj:a.obj")],
                     "KeSetEvent": [(0x180002000, "ntoskrnl:ntoskrnl.exe")]}
    check("a frame moved into a callee is still charged to the chain",
          any("chain bound" in f and "helper" in f for f in
              analyze(moved_manifest, "Win10X64", moved_symbols, measured, edges)))

    # Resolved from this file, not from the working directory. It used to be a
    # relative path, so `--self-test` only worked when it was run from the repo
    # root - and `build_matrix.cmd --self-test` performs no `cd`, so it
    # inherited whatever directory the caller happened to be in and died on an
    # uncaught TypeError rather than a named failure.
    production_roots = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    os.pardir, "audit", "c4-stack-roots.json")
    base = (json.loads(open(production_roots, encoding="utf-8").read())
            if os.path.isfile(production_roots) else None)
    check("production roots manifest parses",
          base is not None and load_roots(production_roots) == base)

    with tempfile.TemporaryDirectory() as directory:
        def write_manifest(obj) -> str:
            path = os.path.join(directory, "roots.json")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(obj, handle)
            return path

        def rejects(obj) -> bool:
            try:
                load_roots(write_manifest(obj))
                return False
            except (AuditError, json.JSONDecodeError):
                return True

        import copy
        duplicate = copy.deepcopy(base)
        duplicate["roots"] = duplicate["roots"] + [duplicate["roots"][0]]
        check("duplicate root rejected", rejects(duplicate))
        empty = copy.deepcopy(base)
        empty["roots"] = []
        check("missing root rejected", rejects(empty))
        # `maxChainBytes` was missing from this tuple, so the key-set check was
        # untested for the one key the chain bound depends on.
        for key in ("schema", "maxFrameBytes", "maxChainBytes", "roots",
                    "sourceGuard", "indirectEdges", "aliases", "frameSources",
                    "expansionRoots"):
            mutated = copy.deepcopy(base)
            del mutated[key]
            check(f"missing manifest key {key}", rejects(mutated))
        bad_kind = copy.deepcopy(base)
        bad_kind["indirectEdges"][0]["kind"] = "anything-goes"
        check("unknown indirect kind rejected", rejects(bad_kind))
        bad_alias = copy.deepcopy(base)
        del bad_alias["aliases"][0]["mapMember"]
        check("alias row missing member rejected", rejects(bad_alias))

        # A row missing `expansionBytes` used to raise a bare `KeyError` out
        # of `analyze` rather than a named FAIL from `load_roots` - the same
        # class of gap `maxChainBytes`'s comment above already recorded for
        # the top-level keys, just one level deeper.
        for key in _REQUIRED_EXPANSION_KEYS:
            bad_expansion = copy.deepcopy(base)
            bad_expansion["expansionRoots"][0] = dict(bad_expansion["expansionRoots"][0])
            del bad_expansion["expansionRoots"][0][key]
            check(f"expansion root row missing {key} rejected", rejects(bad_expansion))
        extra_expansion = copy.deepcopy(base)
        extra_expansion["expansionRoots"][0] = dict(
            extra_expansion["expansionRoots"][0], surprise=1)
        check("expansion root row with an extra key rejected",
              rejects(extra_expansion))

        # --- the imports manifest is opened by the same convention ----------
        good_imports = os.path.join(directory, "imports.json")
        with open(good_imports, "w", encoding="utf-8", newline="\n") as handle:
            handle.write('{"direct": []}')
        check("a well-formed imports file loads",
              load_imports(good_imports) == {"direct": []})
        try:
            load_imports(os.path.join(directory, "no-imports.json"))
            check("a missing imports file fails closed", False)
        except AuditError:
            check("a missing imports file fails closed", True)
        broken_imports = os.path.join(directory, "broken-imports.json")
        with open(broken_imports, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("{not json")
        try:
            load_imports(broken_imports)
            check("a malformed imports file fails closed", False)
        except AuditError:
            check("a malformed imports file fails closed", True)
        # A well-formed JSON object missing the one key
        # `expansion_import_findings` actually subscripts used to raise a
        # bare `KeyError` here instead of a named FAIL.
        no_direct_key_imports = os.path.join(directory, "no-direct-key-imports.json")
        with open(no_direct_key_imports, "w", encoding="utf-8", newline="\n") as handle:
            handle.write('{"wrappers": []}')
        try:
            load_imports(no_direct_key_imports)
            check("an imports file with no direct key fails closed", False)
        except AuditError:
            check("an imports file with no direct key fails closed", True)

        # --- the source guard's own negatives -------------------------------
        guard_root = os.path.join(directory, "src")
        os.makedirs(guard_root)

        def guard_findings(body: str, filename: str = "probe.rs") -> list[str]:
            path = os.path.join(guard_root, filename)
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(body)
            manifest = copy.deepcopy(base)
            manifest["sourceGuard"]["requiredPoolOwners"] = []
            # This fixture's source root is a bare temp directory, so the real
            # expansion root's `session.rs` is never in it. Left declared, the
            # new expansion check would report it unread on every call here,
            # which is a defect of the isolated array-guard fixture and not of
            # the check - the same reason `requiredPoolOwners` is cleared above.
            manifest["expansionRoots"] = []
            manifest.pop("nativeEffectCalls", None)
            manifest.pop("nativeLifecycleCalls", None)
            manifest.pop("asyncCallbackRoots", None)
            result = audit_source(manifest, [guard_root])
            os.remove(path)
            return result

        # The case a 2048-byte frame limit alone would miss.
        check("64-byte topology array caught",
              guard_findings("fn f() { let mut a = [0u8; MAX_RING_COUNT]; }"))
        check("transitive const alias caught", guard_findings(
            "pub const RING_CAP: usize = MAX_RING_COUNT;\n"
            "fn f() { let mut a = [0u8; RING_CAP]; }"))
        check("notification scratch caught", guard_findings(
            "fn f() { let s = [0u8; MAX_NOTIFICATION_CREDIT_SIZE]; }"))
        check("literal topology ceiling caught",
              guard_findings("fn f() { let mut ring_counts = [0u32; 64]; }"))
        check("MaybeUninit array caught", guard_findings(
            "fn f() { let a = MaybeUninit::<[u8; MAX_SLOT_COUNT]>::uninit(); }"))
        check("from_fn caught", guard_findings(
            "fn f() { let a = core::array::from_fn::<u8, MAX_RING_COUNT>(|_| 0); }"))
        check("alloca caught", guard_findings("void f(int n) { char *p = alloca(n); }",
                                              "probe.c"))
        check("C VLA caught",
              guard_findings("void f(void) {\n  char buf[MAX_RING_COUNT];\n}\n", "probe.c"))
        check("comment is not code",
              not guard_findings("// let a = [0u8; MAX_RING_COUNT];\nfn f() {}"))
        check("string is not code",
              not guard_findings('fn f() { let s = "[0u8; MAX_RING_COUNT]"; }'))
        check("module static is not a local", not guard_findings(
            "static TABLE: [u8; MAX_RING_COUNT] = [0; MAX_RING_COUNT];"))
        check("an ordinary small local passes",
              not guard_findings("fn f() { let a = [0u8; 8]; }"))

        # Task 6's fixed-domain unload walk must never regress to keeping one
        # affine claim/ticket slot per permanent cell on the kernel stack.
        # These three cell-count names are intentionally *not* global topology
        # seeds: doing that would also reject unrelated bounded validators.
        check("unload scan affine claim array is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "unsafe fn observe_r3_unload_cell() {\n"
                "    let affine_claims = "
                "[None::<TerminalJoinTicket>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("inline cfg-test unload array is ignored", not guard_findings(
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn observe_r3_unload_cell() {\n"
            "        let affine_claims = "
            "[None::<TerminalJoinTicket>; SESSION_CELL_COUNT];\n"
            "    }\n"
            "}\n"))
        check("cfg-not-test unload array remains production code", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg(not(test))]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let affine_claims = [None::<u8>; 64];\n"
                "}\n")))
        check("C unload VLA is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "void fsring_unload_scan(void) {\n"
                "    void *tickets[SESSION_CELL_COUNT];\n"
                "}\n",
                "probe.c")))
        check("unload from-fn literal const generic is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    let claims = array::from_fn::<_, 64, _>(|_| None);\n"
                "}\n")))
        check("unbound unload from-fn allocation is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    consume(array::from_fn::<_, 64, _>(|_| None));\n"
                "}\n")))
        check("unbound unload MaybeUninit allocation is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    consume(MaybeUninit::<[u8; SESSION_CELL_COUNT]>::uninit());\n"
                "}\n")))
        check("unbound unload array literal is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    consume([None::<u8>; SESSION_CELL_COUNT]);\n"
                "}\n")))
        check("uninitialized typed unload array is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    let claims: [Option<u8>; MOUNT_REGISTRY_CAPACITY];\n"
                "}\n")))
        check("braced literal unload ceiling is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; { 64 }];\n"
                "}\n")))
        check("suffixed cast unload ceiling is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; ({ 64_u64 } as usize)];\n"
                "}\n")))
        check("Rust array type alias is resolved at a local binding", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type Claims = [Option<u8>; SESSION_CELL_COUNT];\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims: Claims = unsafe { core::mem::zeroed() };\n"
                "}\n")))
        check("Rust array alias nested in a local MaybeUninit is resolved", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type Claims = [Option<u8>; SESSION_CELL_COUNT];\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = MaybeUninit::<Claims>::uninit();\n"
                "}\n")))
        check("Rust zeroed generic return resolves an array alias", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type Claims = [Option<u8>; SESSION_CELL_COUNT];\n"
                "fn observe_r3_unload_cell() -> Claims {\n"
                "    unsafe { core::mem::zeroed::<Claims>() }\n"
                "}\n")))
        check("generic MaybeUninit alias constructor resolves its argument", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type Claims = [Option<u8>; SESSION_CELL_COUNT];\n"
                "type MU<T> = core::mem::MaybeUninit<T>;\n"
                "fn observe_r3_unload_cell() -> MU<Claims> {\n"
                "    MU::<Claims>::uninit()\n"
                "}\n")))
        check("generic MaybeUninit alias zeroed expression is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type Claims = [Option<u8>; SESSION_CELL_COUNT];\n"
                "type MU<T> = core::mem::MaybeUninit<T>;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(MU::<Claims>::zeroed());\n"
                "}\n")))
        check("fixed MaybeUninit alias constructor resolves its nested array", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type Claims = [u8; 64];\n"
                "type ClaimsMU = MaybeUninit<Claims>;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(ClaimsMU::uninit());\n"
                "}\n")))
        check("generic MaybeUninit array alias substitutes its type argument", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "type MU<T> = MaybeUninit<[T; 64]>;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(MU::<u8>::uninit());\n"
                "}\n")))
        check("renamed zeroed import remains an allocation constructor", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "use core::mem::zeroed as z;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(unsafe { z::<[u8; 64]>() });\n"
                "}\n")))
        check("renamed MaybeUninit import remains an allocation constructor", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "use core::mem::MaybeUninit as MU;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(MU::<[u8; 64]>::uninit());\n"
                "}\n")))
        check("renamed from_fn import remains an allocation constructor", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "use core::array::from_fn as make;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(make::<u8, 64, _>(|_| 0));\n"
                "}\n")))
        check("renamed MaybeUninit import survives a generic type alias", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "use core::mem::MaybeUninit as MU;\n"
                "type Claims = [u8; 64];\n"
                "type Wrap<T> = MU<T>;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(Wrap::<Claims>::uninit());\n"
                "}\n")))
        check("parenthesized renamed zeroed call is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "use core::mem::zeroed as z;\n"
                "fn observe_r3_unload_cell() {\n"
                "    consume(unsafe { (z::<[u8; 64]>)() });\n"
                "}\n")))
        check("immediately invoked closure array expression is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    consume((|| [0u8; 64])());\n"
                "}\n")))
        check("renamed from_fn function item is not an allocation",
              not guard_findings(
                  "use core::array::from_fn as make;\n"
                  "fn observe_r3_unload_cell() {\n"
                  "    let ctor = make::<u8, 64, _>;\n"
                  "    consume(ctor);\n"
                  "}\n"))
        check("unused Rust array type alias is not a stack allocation",
              not guard_findings(
                  "type Claims = [Option<u8>; SESSION_CELL_COUNT];\n"
                  "type MU<T> = core::mem::MaybeUninit<T>;\n"
                  "fn observe_r3_unload_cell() {}\n"))
        check("Rust const count alias is resolved", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "const CLAIM_COUNT: usize = SESSION_CELL_COUNT;\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; CLAIM_COUNT];\n"
                "}\n")))
        check("Rust literal count alias is resolved", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "const CLAIM_COUNT: usize = { 64usize };\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; CLAIM_COUNT];\n"
                "}\n")))
        check("nested MaybeUninit unload array is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    let claims = MaybeUninit::<Option<MaybeUninit<"
                "[u8; SESSION_CELL_COUNT]>>>::uninit();\n"
                "}\n")))
        check("match-arm array expression is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell(flag: bool) {\n"
                "    consume(match flag { true => [0u8; 64], "
                "false => [0u8; 1] });\n"
                "}\n")))
        check("struct-field array expression is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() {\n"
                "    consume(Packet { claims: [0u8; SESSION_CELL_COUNT] });\n"
                "}\n")))
        check("returned struct array expression is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "fn observe_r3_unload_cell() -> Packet {\n"
                "    return Packet { claims: [0u8; SESSION_CELL_COUNT] };\n"
                "}\n")))
        check("local type const and static array declarations are ignored",
              not guard_findings(
                  "fn observe_r3_unload_cell() {\n"
                  "    type Claims = [u8; SESSION_CELL_COUNT];\n"
                  "    const ZERO: [u8; SESSION_CELL_COUNT] = "
                  "[0u8; SESSION_CELL_COUNT];\n"
                  "    static ZEROES: [u8; SESSION_CELL_COUNT] = "
                  "[0u8; SESSION_CELL_COUNT];\n"
                  "}\n"))
        check("unrelated boot validator remains outside unload surface",
              not guard_findings(
                  "fn validate_boot_context() {\n"
                  "    let seen = [0u64; BOOT_CONTEXT_SLOT_COUNT];\n"
                  "}\n"))
        check("cfg-test const unload function is ignored", not guard_findings(
            "impl R3UnloadProgress {\n"
            "    #[cfg(test)]\n"
            "    const fn probe() {\n"
            "        let marker = 0;\n"
            "        let claims = [None::<u8>; 64];\n"
            "    }\n"
            "}\n"))
        check("cfg-any-test-or-kernel unload function remains production", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg(any(test, feature = \"kernel\"))]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("cfg-all-test unload module is ignored", not guard_findings(
            "#[cfg(all(test, feature = \"host-probe\"))]\n"
            "mod tests {\n"
            "    fn observe_r3_unload_cell() {\n"
            "        let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
            "    }\n"
            "}\n"))
        check("valid trailing-comma cfg parses completely", not guard_findings(
            "#[cfg(all(test,))]\n"
            "fn observe_r3_unload_cell() {\n"
            "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
            "}\n"))
        check("cfg formula that logically implies test is ignored",
              not guard_findings(
                  "#[cfg(all(any(test, host_probe), not(host_probe)))]\n"
                  "fn observe_r3_unload_cell() {\n"
                  "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                  "}\n"))
        check("cfg key-value atoms remain distinct production choices", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg(all(feature = \"kernel\", "
                "not(feature = \"host\")))]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("cfg any-all feature combination remains production capable", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg(any(all(feature = \"kernel\", "
                "feature = \"trace\"), test))]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("cfg_attr not-test non-cfg attribute remains production", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg_attr(not(test), allow(dead_code))]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("malformed cfg expression fails closed", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg(all(test, feature = \"host\")]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("cfg-test async extern unload function is ignored",
              not guard_findings(
                  "#[cfg(test)]\n"
                  "pub async unsafe extern \"C\" fn fsring_unload_probe() {\n"
                  "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                  "}\n"))
        check("cfg-attr induced test-only unload function is ignored",
              not guard_findings(
                  "#[cfg_attr(not(test), cfg(test))]\n"
                  "fn observe_r3_unload_cell() {\n"
                  "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                  "}\n"))
        check("production-capable cfg-attr unload function remains", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#[cfg_attr(test, allow(dead_code))]\n"
                "fn observe_r3_unload_cell() {\n"
                "    let claims = [None::<u8>; SESSION_CELL_COUNT];\n"
                "}\n")))
        check("C pointer unload array is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "void fsring_unload_scan(void) {\n"
                "    HANDLE* tickets[SESSION_CELL_COUNT] = {0};\n"
                "}\n", "probe.c")))
        check("C multidimensional unload array checks every dimension", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "void fsring_unload_scan(void) {\n"
                "    HANDLE tickets[2][MOUNT_REGISTRY_CAPACITY] = {{0}};\n"
                "}\n", "probe.c")))
        check("C suffixed literal unload array is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "void fsring_unload_scan(void) {\n"
                "    HANDLE tickets[64UL];\n"
                "}\n", "probe.c")))
        check("C declspec unload function is scanned", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "__declspec(noinline) static void fsring_unload_scan(void) {\n"
                "    HANDLE tickets[SESSION_CELL_COUNT] = { NULL };\n"
                "}\n", "probe.c")))
        check("C macro count alias is resolved", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "#define CLAIM_COUNT SESSION_CELL_COUNT\n"
                "void fsring_unload_scan(void) {\n"
                "    HANDLE tickets[CLAIM_COUNT];\n"
                "}\n", "probe.c")))
        check("C const count alias is resolved", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "const unsigned long CLAIM_COUNT = 64UL;\n"
                "void fsring_unload_scan(void) {\n"
                "    HANDLE tickets[CLAIM_COUNT] = {0};\n"
                "}\n", "probe.c")))
        check("C typedef array local is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "typedef HANDLE Claims[SESSION_CELL_COUNT];\n"
                "void fsring_unload_scan(void) {\n"
                "    Claims claims;\n"
                "}\n", "probe.c")))
        check("C typedef array compound literal is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "typedef HANDLE Claims[SESSION_CELL_COUNT];\n"
                "void fsring_unload_scan(void) {\n"
                "    consume((Claims){0});\n"
                "}\n", "probe.c")))
        check("C qualified typedef array compound literal is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "typedef HANDLE Claims[SESSION_CELL_COUNT];\n"
                "void fsring_unload_scan(void) {\n"
                "    consume((const Claims){0});\n"
                "}\n", "probe.c")))
        check("C direct array compound literal is caught", any(
            "unload scan keeps a fixed-domain local array" in finding
            for finding in guard_findings(
                "void fsring_unload_scan(void) {\n"
                "    consume((HANDLE[SESSION_CELL_COUNT]){0});\n"
                "}\n", "probe.c")))
        check("C pointer-to-array local is not an array allocation",
              not guard_findings(
                  "void fsring_unload_scan(void) {\n"
                  "    HANDLE (*claims)[SESSION_CELL_COUNT];\n"
                  "}\n", "probe.c"))
        check("C typedef pointer-to-array local is not an array allocation",
              not guard_findings(
                  "typedef HANDLE (*Claims)[SESSION_CELL_COUNT];\n"
                  "void fsring_unload_scan(void) {\n"
                  "    Claims claims;\n"
                  "}\n", "probe.c"))
        check("C pointer-only typedef layering is not an array allocation",
              not guard_findings(
                  "typedef HANDLE Claims[SESSION_CELL_COUNT];\n"
                  "typedef Claims *PClaims;\n"
                  "void fsring_unload_scan(void) {\n"
                  "    PClaims claims;\n"
                  "}\n", "probe.c"))

        production_unload_surfaces = [
            ("driver/fsring-fsd/src/fence.rs",
             "struct R3UnloadProgress { cursor: u32 }\n"
             "struct R3UnloadWork { action: u8 }\n"
             "struct R3StableEmptyPass { authority: u8 }\n"
             "struct R3FinalizerDrainProgress { cursor: u32 }\n"
             "struct R3FinalizerFullPass { authority: u8 }\n"
             "struct R3FinalizerAcknowledgedPass { authority: u8 }\n"
             "impl R3UnloadProgress {\n"
             " fn begin_after_drains(admission: crate::lifecycle::R3UnloadScanAdmission, "
             "process: &crate::lifecycle::ProcessCallbacksDrained, "
             "setup: &crate::lifecycle::SetupAdmissionDrained) -> Self { work(); }\n"
             " fn restart(registry: NonNull<KernelSessionRegistry>) -> Self { work(); }\n"
             " fn observe_one(self) -> R3UnloadScanStep { work(); }\n"
             "}\n"
             "impl R3UnloadWork { fn discharge(self) -> R3UnloadScanStep { work(); } }\n"
             "impl R3StableEmptyPass { fn registry(&self) -> "
             "NonNull<KernelSessionRegistry> { work(); } }\n"
             "impl R3FinalizerFullPass { fn into_registry(self) -> "
             "NonNull<KernelSessionRegistry> { work(); } }\n"
             "impl R3FinalizerAcknowledgedPass { fn into_registry(self) -> "
             "NonNull<KernelSessionRegistry> { work(); } }\n"
             "fn drain_r3_finalizers(stable: R3StableEmptyPass) "
             "-> R3FinalizersDrained {\n"
             "    let progress = R3FinalizerDrainProgress { cursor: 0 };\n"
             "    work(progress);\n"
             "    let acknowledged = R3FinalizerAcknowledgedPass { authority: 0 };\n"
             "    let native = crate::lifecycle::finish_finalizers_drained("
             "acknowledged, rundown);\n"
             "    R3FinalizersDrained { native }\n"
             "}\n"),
            ("driver/fsring-fsd/src/lifecycle.rs",
             "struct R3UnloadScanAdmission { authority: u8 }\n"
             "struct FinalizerRundownDrained { closed: u8 }\n"
             "impl R3UnloadScanAdmission {\n"
             " fn into_registry_after_drains(self, process: &ProcessCallbacksDrained, "
             "setup: &SetupAdmissionDrained) -> NonNull<KernelSessionRegistry> "
             "{ work(); }\n"
             "}\n"
             "fn wait_finalizers_drained(full_pass: crate::fence::R3FinalizerFullPass, "
             "closed: FinalizerAdmissionClosed) -> FinalizerRundownDrained "
             "{ work(); }\n"
             "fn finish_finalizers_drained("
             "acknowledged: crate::fence::R3FinalizerAcknowledgedPass, "
             "rundown: FinalizerRundownDrained) -> FinalizersDrained { work(); }\n"
             "impl RegistryLockGuard {\n"
             "    fn observe_r3_finalizer_for_drain(&mut self, index: u32) "
             "-> R3FinalizerDrainObservation { work(); }\n"
             "    fn acknowledge_r3_finalizer_after_rundown(&mut self, index: u32) "
             "-> Option<LockedR3FinalizerDrainNonMatch> { work(); }\n"
             "}\n"),
        ]
        check("independent explicit unload surface roster is exact",
              _REQUIRED_UNLOAD_SURFACE_ROSTER == (
                  "R3UnloadProgress", "R3UnloadWork", "R3StableEmptyPass",
                  "R3FinalizerDrainProgress", "R3FinalizerFullPass",
                  "R3FinalizerAcknowledgedPass", "R3UnloadScanAdmission",
                  "FinalizerRundownDrained",
              ))
        check("exact production unload surface census passes",
              not unload_fixed_domain_stack_findings(production_unload_surfaces))
        missing_unload_surface = [
            production_unload_surfaces[0],
            (production_unload_surfaces[1][0], "struct RenamedAdmission;"),
        ]
        check("renamed production unload surface fails closed", any(
            "unload stack guard surface R3UnloadScanAdmission is absent" in finding
            for finding in unload_fixed_domain_stack_findings(missing_unload_surface)))
        check("missing fence production source fails closed", any(
            "fence.rs is absent" in finding
            for finding in unload_fixed_domain_stack_findings(
                [production_unload_surfaces[1]])))
        check("missing lifecycle production source fails closed", any(
            "lifecycle.rs is absent" in finding
            for finding in unload_fixed_domain_stack_findings(
                [production_unload_surfaces[0]])))
        check("explicit production-root census fails if both files are absent",
              len(unload_fixed_domain_stack_findings(
                  [], require_surface_census=True)) == 2)
        alias_unload_surfaces = [
            (production_unload_surfaces[0][0], "\n".join(
                f"type {name} = Concrete;" for name in (
                    "R3UnloadProgress", "R3UnloadWork", "R3StableEmptyPass",
                    "R3FinalizerDrainProgress", "R3FinalizerFullPass",
                    "R3FinalizerAcknowledgedPass"))),
            (production_unload_surfaces[1][0],
             "type R3UnloadScanAdmission = Concrete;\n"
             "type FinalizerRundownDrained = Concrete;"),
        ]
        check("type aliases cannot satisfy unload surface census", any(
            "is not a concrete production struct" in finding
            for finding in unload_fixed_domain_stack_findings(
                alias_unload_surfaces)))
        bodyless_unload_surfaces = [
            (production_unload_surfaces[0][0],
             "struct R3UnloadProgress { cursor: u32 }\n"
             "struct R3UnloadWork { action: u8 }\n"
             "struct R3StableEmptyPass { authority: u8 }\n"
             "struct R3FinalizerDrainProgress { cursor: u32 }\n"
             "struct R3FinalizerFullPass { authority: u8 }\n"),
            (production_unload_surfaces[1][0],
             "struct R3UnloadScanAdmission { authority: u8 }\n"
             "struct FinalizerRundownDrained { closed: u8 }\n"),
        ]
        check("bodyless placeholder surface cannot satisfy census", any(
            "production impl/function body" in finding
            for finding in unload_fixed_domain_stack_findings(
                bodyless_unload_surfaces)))
        trait_decoy_surfaces = copy.deepcopy(production_unload_surfaces)
        trait_decoy_surfaces[0] = (
            trait_decoy_surfaces[0][0],
            trait_decoy_surfaces[0][1].replace(
                "impl R3UnloadWork { fn discharge(self) -> R3UnloadScanStep { work(); } }",
                "impl Decoy for R3UnloadWork { fn discharge(self) "
                "-> R3UnloadScanStep { work(); } }"))
        check("trait impl cannot satisfy an inherent unload impl", any(
            "surface R3UnloadWork" in finding
            for finding in unload_fixed_domain_stack_findings(
                trait_decoy_surfaces)))
        const_only_surfaces = copy.deepcopy(production_unload_surfaces)
        const_only_surfaces[0] = (
            const_only_surfaces[0][0],
            const_only_surfaces[0][1].replace(
                "impl R3UnloadWork { fn discharge(self) -> R3UnloadScanStep { work(); } }",
                "impl R3UnloadWork { const DECOY: usize = 1; }"))
        check("const-only inherent impl cannot satisfy method roster", any(
            "surface R3UnloadWork" in finding
            for finding in unload_fixed_domain_stack_findings(
                const_only_surfaces)))
        wrong_method_surfaces = copy.deepcopy(production_unload_surfaces)
        wrong_method_surfaces[0] = (
            wrong_method_surfaces[0][0],
            wrong_method_surfaces[0][1].replace(
                "fn discharge(self)", "fn discharge(&self)"))
        check("wrong unload method receiver fails the exact signature", any(
            "surface R3UnloadWork" in finding
            for finding in unload_fixed_domain_stack_findings(
                wrong_method_surfaces)))
        unbound_function_surfaces = copy.deepcopy(production_unload_surfaces)
        unbound_function_surfaces[0] = (
            unbound_function_surfaces[0][0],
            unbound_function_surfaces[0][1].replace(
                "fn drain_r3_finalizers(stable: R3StableEmptyPass) "
                "-> R3FinalizersDrained",
                "fn drain_r3_finalizers(decoy: usize) -> R3FinalizersDrained"))
        check("required unload free function must bind protected types", any(
            "surface drain_r3_finalizers" in finding
            for finding in unload_fixed_domain_stack_findings(
                unbound_function_surfaces)))
        missing_acknowledged_pass = copy.deepcopy(production_unload_surfaces)
        missing_acknowledged_pass[0] = (
            missing_acknowledged_pass[0][0],
            missing_acknowledged_pass[0][1].replace(
                "struct R3FinalizerAcknowledgedPass { authority: u8 }\n", ""))
        check("missing finalizer acknowledged pass fails the exact census", any(
            "surface R3FinalizerAcknowledgedPass is absent" in finding
            for finding in unload_fixed_domain_stack_findings(
                missing_acknowledged_pass)))
        missing_acknowledged_conversion = copy.deepcopy(production_unload_surfaces)
        missing_acknowledged_conversion[0] = (
            missing_acknowledged_conversion[0][0],
            missing_acknowledged_conversion[0][1].replace(
                "impl R3FinalizerAcknowledgedPass { fn into_registry(self) -> "
                "NonNull<KernelSessionRegistry> { work(); } }\n", ""))
        check("acknowledged pass requires its exact consuming conversion", any(
            "surface R3FinalizerAcknowledgedPass" in finding
            for finding in unload_fixed_domain_stack_findings(
                missing_acknowledged_conversion)))
        aliased_rundown_receipt = copy.deepcopy(production_unload_surfaces)
        aliased_rundown_receipt[1] = (
            aliased_rundown_receipt[1][0],
            aliased_rundown_receipt[1][1].replace(
                "struct FinalizerRundownDrained { closed: u8 }",
                "type FinalizerRundownDrained = FinalizersDrained;"))
        check("rundown receipt alias substitution cannot satisfy the census", any(
            "surface FinalizerRundownDrained is not a concrete production struct"
            in finding for finding in unload_fixed_domain_stack_findings(
                aliased_rundown_receipt)))
        wrong_wait_sink = copy.deepcopy(production_unload_surfaces)
        wrong_wait_sink[1] = (
            wrong_wait_sink[1][0],
            wrong_wait_sink[1][1].replace(
                ") -> FinalizerRundownDrained { work(); }",
                ") -> FinalizersDrained { work(); }"))
        check("finalizer wait must return the rundown receipt", any(
            "surface wait_finalizers_drained" in finding
            for finding in unload_fixed_domain_stack_findings(wrong_wait_sink)))
        wrong_finish_source = copy.deepcopy(production_unload_surfaces)
        wrong_finish_source[1] = (
            wrong_finish_source[1][0],
            wrong_finish_source[1][1].replace(
                "acknowledged: crate::fence::R3FinalizerAcknowledgedPass, ",
                "acknowledged: usize, "))
        check("finalizer finish must consume the acknowledged pass", any(
            "surface finish_finalizers_drained" in finding
            for finding in unload_fixed_domain_stack_findings(
                wrong_finish_source)))
        wrong_acknowledgement_sink = copy.deepcopy(production_unload_surfaces)
        wrong_acknowledgement_sink[1] = (
            wrong_acknowledgement_sink[1][0],
            wrong_acknowledgement_sink[1][1].replace(
                "-> Option<LockedR3FinalizerDrainNonMatch> { work(); }",
                "-> bool { work(); }"))
        check("post-rundown acknowledgement helper keeps its exact receipt", any(
            "surface acknowledge_r3_finalizer_after_rundown" in finding
            for finding in unload_fixed_domain_stack_findings(
                wrong_acknowledgement_sink)))
        decoy_drain_binding = copy.deepcopy(production_unload_surfaces)
        decoy_drain_binding[0] = (
            decoy_drain_binding[0][0],
            decoy_drain_binding[0][1].replace(
                "    let acknowledged = R3FinalizerAcknowledgedPass { authority: 0 };\n"
                "    let native = crate::lifecycle::finish_finalizers_drained("
                "acknowledged, rundown);\n"
                "    R3FinalizersDrained { native }\n",
                "    work(progress);\n")
            + "fn finalizer_binding_decoy() {\n"
              "    let acknowledged = R3FinalizerAcknowledgedPass { authority: 0 };\n"
              "    let native = crate::lifecycle::finish_finalizers_drained("
              "acknowledged, rundown);\n"
              "    consume(native);\n"
              "}\n")
        check("decoy cannot bind the finalizer drain to its finish sink", any(
            "surface drain_r3_finalizers does not bind "
            "R3FinalizerAcknowledgedPass to finish_finalizers_drained" in finding
            for finding in unload_fixed_domain_stack_findings(
                decoy_drain_binding)))

        missing_owner = copy.deepcopy(base)
        findings = audit_source(missing_owner, [guard_root])
        check("absent pool owners are reported",
              any("required pool owner" in finding for finding in findings))

        # A frame over the bound and an absent root both fail.
        fake_map = os.path.join(directory, "fake.map")
        with open(fake_map, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(" Timestamp is 00000001 (x)\n")
            handle.write(" 0001:00000000       DriverEntry"
                         "                0000000180001000 f   fsring_fsd.lib:a.obj\n")
        symbols, fake_header = parse_map(fake_map)
        check("map symbol parsed", "DriverEntry" in symbols)
        # `header["code"]` is the address table every attribution resolves
        # through. Asserting only that the name reached `symbols` would leave a
        # break in the flag branch invisible, and then every frame in the image
        # would be charged to nobody.
        check("a flagged row lands in the code table",
              fake_header["code"] == [(0x180001000, "DriverEntry")])
        try:
            parse_map(os.path.join(directory, "no.map"))
            check("missing map fails", False)
        except (AuditError, OSError):
            check("missing map fails", True)

    # A completeness claim needs a producer. The decision-signal evidence says
    # what each decision in this file is seen by; this counts the decisions, so
    # one cannot be added or removed without the number changing and the table
    # being revisited. Frozen 2026-08-16 (frame-source census split) at 21
    # refusals and 48 findings - one finding beyond the prior freeze:
    # `frame_source_findings` now reports its declined and truncated
    # populations separately instead of as one total, so the shape that used to
    # be a single count is two. The refusal count is unchanged, and
    # `expansion_callsite_findings`'s per-DDI attribution replaced one finding
    # with another rather than adding one. The preceding freeze was
    # 2026-08-08 (fix-wave disclosure corrections) at
    # 21 refusals and 47 findings - two findings beyond the prior freeze:
    # Task 7's production-only unload fixed-domain array guard and its
    # fail-closed exact-surface census. The preceding freeze had 21 refusals
    # and 45 findings - one more refusal than its prior
    # freeze
    # (20/45, final whole-branch review fix wave): `load_imports` now raises a
    # named `AuditError` for a well-formed JSON object with no `direct` key,
    # instead of leaving a bare `KeyError` for `expansion_import_findings` to
    # hit. Structural, like the pre-existing key-set checks it sits beside;
    # not given its own decision-table row for the same reason those are not.
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
    # 78 -> 79: the over-counting refusal split in two. One arm keeps the
    # original outright refusal for a function with no frame pointer, where the
    # unwind record IS a frame statement; the new arm censuses the case where
    # the record establishes a frame pointer and therefore states no size at
    # all. A split, not a relaxation: the strict arm is what a caller gets by
    # default, and `maxFramePointerDisagreements` is 0 on two of three profiles.
    check("the decision-site census is unchanged", sites == 79)

    missing_root_manifest = dict(fixture_manifest, asyncCallbackRoots=["ghost_callback"])
    check("missing-callback-root",
          any("missing-callback-root" in f for f in
              async_root_findings(missing_root_manifest, [("a.rs", "fn other() {}")])))
    missing_call_row = {
        "id": "close", "source": "driver/fsring-core/src/adapter/fence.rs",
        "symbol": "close_session_admission", "requiredCall": "native_close_generation_admission",
    }
    check("missing-native-effect-call",
          any("missing-native-effect-call" in f for f in
              native_call_findings({"nativeLifecycleCalls": []}, [("x.rs", "")])))
    check("missing-native-lifecycle-call",
          any("missing-native-lifecycle-call" in f for f in
              native_call_findings({"nativeEffectCalls": []}, [("x.rs", "")])))
    success_src = "fn close_session_admission() { Ok(()) }"
    check("success-only-body",
          any("success-only-body" in f for f in native_call_findings(
              {"nativeEffectCalls": [missing_call_row], "nativeLifecycleCalls": []},
              [("driver/fsring-core/src/adapter/fence.rs", success_src)])))
    wrong_src = "fn close_session_admission() { other_helper(); }"
    check("wrong-edge-or-profile",
          any("wrong-edge-or-profile" in f for f in native_call_findings(
              {"nativeEffectCalls": [missing_call_row], "nativeLifecycleCalls": []},
              [("driver/fsring-core/src/adapter/fence.rs", wrong_src)])))
    check("changed-source-root",
          any("changed-source-root" in f for f in native_call_findings(
              {"nativeEffectCalls": [missing_call_row], "nativeLifecycleCalls": []},
              [("other.rs", "fn close_session_admission() { native_close_generation_admission(); }")])))

    for failure in failures:
        print(f"FAIL: {failure}")
    print(f"audit_c4_stack self-test: "
          f"{'PASS' if not failures else 'FAIL'} "
          f"({len(ran)} checks, {len(failures)} failures)")
    return 1 if failures else 0


def report_frames(manifest: dict, profile: str, image: str, map_path: str) -> int:
    """Print what the corrected measurement reports, and enforce nothing.

    The frame measurement was rebuilt because both of its sources were wrong,
    so the numbers it now produces are larger than the numbers the frozen
    bounds were set against. This mode exists so that the change of bound
    pressure is a measurement taken before any decision, rather than a gate
    that turns red and forces one.
    """
    symbols, header = parse_map(map_path)
    code = header["code"]
    machine = "arm64" if profile.endswith("Arm64") else "x64"
    # The same identity refusal the gate performs. This mode produced the
    # numbers in the frame-measurement evidence, so it may not accept a map
    # that does not describe the image: without the preferred load address in
    # particular, every x64 unwind record resolves to no owner and the source
    # reports zero functions while still printing a table.
    identity = image_identity_findings(machine, pe_facts(image), header)
    if identity:
        for finding in identity:
            print(f"FAIL: {finding}")
        return 1
    base = header["base"]
    frames, prologue, unwind, framepointers = measure_frames(
        image, machine, code, base)
    calls = parse_calls(image, code)

    indirect = declared_indirect_edges(manifest, profile)

    print(f"profile {profile}  machine {machine}  image base 0x{base:x}")
    print(f"map functions {len(code)}  prologue-measured {len(prologue)}  "
          f"unwind-measured {len(unwind)}")

    disagree = sorted((name for name in set(prologue) & set(unwind)
                       if prologue[name] != unwind[name]),
                      key=lambda n: abs(prologue[n] - unwind[n]), reverse=True)
    print(f"sources disagree on {len(disagree)} of "
          f"{len(set(prologue) & set(unwind))} functions measured by both")
    for name in disagree[:12]:
        print(f"    {name}: prologue {prologue[name]} unwind {unwind[name]}")

    for finding in frame_source_findings(manifest, profile, prologue, unwind,
                                         framepointers):
        print(f"census: {finding}")

    widest = max(frames.values()) if frames else 0
    print(f"widest frame anywhere in the image: {widest}")

    print(f"{'root':<40} {'frame':>7} {'chain':>7}   bound "
          f"{manifest['maxFrameBytes']}/{manifest['maxChainBytes']}")
    over = 0
    for root in manifest["roots"]:
        if root not in symbols:
            print(f"{root:<40} {'absent':>7}")
            continue
        if root not in frames:
            # Absent is not zero. A root that neither source measured is what
            # the gate refuses; printing it as 0 reads as a frameless leaf.
            print(f"{root:<40} {'unmeasured':>10}")
            continue
        frame = frames[root]
        total, _path = chain_bytes(root, frames, calls, indirect)
        flag = ""
        if frame > manifest["maxFrameBytes"]:
            flag += " FRAME-OVER"
        if total > manifest["maxChainBytes"]:
            flag += " CHAIN-OVER"
        if flag:
            over += 1
        print(f"{root:<40} {frame:>7} {total:>7}{flag}")
        if flag:
            print("        via " + " -> ".join(_path[:14]))
    print(f"roots over a bound: {over}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--measure-frames", action="store_true",
                        help="report the corrected measurement; enforce nothing")
    parser.add_argument("--profile")
    parser.add_argument("--roots")
    parser.add_argument("--source-root", action="append", default=[])
    parser.add_argument("--image")
    parser.add_argument("--map", dest="map_path")
    parser.add_argument("--imports",
                        help="the profile's c4-imports-*.json; the expansion "
                             "roots' DDI must be declared there too")
    # `--pdb` was accepted here and never read. A flag a script ignores is a
    # claim its caller cannot rely on, so it is gone from the parser and from
    # every `build_matrix.cmd` invocation. The PDB binding lives in
    # audit_c4_imports.py, which actually consumes it. `--imports` is
    # restored above and consumed here, tying the expansion roots' DDI to the
    # imports manifest that declares it.
    #
    # `--imports` was OPTIONAL here until this fix: dropping it from an
    # invocation (e.g. an edit to `build_matrix.cmd`) silently switched off
    # decisions 7, 8 and the binary caller-set decision, with `exit 0` and no
    # named finding to say so, and no mutant in this file's own suite covers
    # `build_matrix.cmd` to catch that drop. It is required below, alongside
    # `--profile`/`--roots`/`--image`/`--map`, for every enforcing run -
    # `--measure-frames` is a reporting mode that consumes no imports
    # manifest and stays exempt, same as `--self-test`.
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not all((args.profile, args.roots, args.image, args.map_path)):
        parser.error("--profile --roots --image --map are required")
    if args.measure_frames:
        try:
            return report_frames(load_roots(args.roots), args.profile,
                                 args.image, args.map_path)
        except AuditError as error:
            print(f"FAIL: {error}")
            return 1
    if not args.imports:
        parser.error("--imports is required")
    try:
        manifest = load_roots(args.roots)
        imports = load_imports(args.imports)
        findings = audit_binary(manifest, args.profile, args.image,
                                args.map_path, imports)
        findings += audit_source(manifest, args.source_root or
                                 manifest["sourceGuard"]["sourceRoots"])
    except AuditError as error:
        print(f"FAIL: {error}")
        return 1
    for finding in findings:
        print(f"FAIL: {finding}")
    if findings:
        print(f"audit_c4_stack: FAIL ({len(findings)} findings)")
        return 1
    print(f"PASS: {args.profile} roots are bounded and every edge is declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
