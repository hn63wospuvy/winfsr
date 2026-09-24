# FSRING kernel-driver workspace

This is a **separate Cargo workspace** from the repository root. It hosts the
FSRING kernel driver crates: `fsring-fsd`, the WDM image, and `fsring-core`,
the WDK-free pure core it compiles in. Between them they carry the compiled
platform profile, the frozen `fsring-abi` wire contract, the shipped B1–B5
core state machines and safety typestates, and C1's checked effect seam. There
is now one deliberately narrow native integration, extended twice: C3 publishes
the secure control device and wires synchronous CREATE, CLEANUP, CLOSE, and
DEVICE_CONTROL IRPs with per-handle lifetime, and C4 adds the native session
transport foundation — SETUP's twenty-three-effect choreography with one commit
at `PublishActive`, ENTER's role/credit acquisition, the bounded six-stage
session fence, a per-mount `FILE_DEVICE_VIRTUAL_DISK` device, and
MOUNT/VERIFY/dismount against a separate filesystem registration device. C4 is
**not** natively verified, and its source-complete claim was withdrawn on
2026-08-07 (see the C4 status section below). Request round trips over the
established rings, the filesystem object model, cache/MM, PT, and data-path
lifecycle call sites remain unwired.
Designs:
`../docs/superpowers/specs/2026-07-24-fsring-driver-toolchain-bringup-design.md`
(slice 1),
`../docs/superpowers/specs/2026-07-25-fsring-driver-abi-wiring-platform-profile-design.md`
(slice A1) and
`../docs/superpowers/specs/2026-07-25-fsring-driver-core-crate-proof-harness-design.md`
(slice A2), and
`../docs/superpowers/specs/2026-07-28-fsring-driver-c1-held-context-effect-seam-design.md`
(slice C1, the first of Phase C), and
`../docs/superpowers/specs/2026-07-28-fsring-driver-c2-control-device-decidable-half-design.md`
(slice C2), and
`../docs/superpowers/specs/2026-07-29-fsring-driver-c3-native-control-smoke-design.md`
(slice C3), and
`../docs/superpowers/specs/2026-08-04-fsring-driver-c4-native-session-transport-foundation-design.md`
(slice C4).

## Slice C4 status — source-complete claim withdrawn 2026-08-07, not natively verified

`C4_SOURCE_COMPLETE` is what the local gates establish, and they establish
nothing more: the root and driver test suites, the compile-fail runner, three
RELEASE images with the enforcing PE audit, the C4 import and stack audits, the
`--suite c4` mutation sweep with every mandatory mutant killed, and the two
PowerShell self-tests. **None of them loads a driver.**

> **Withdrawn, 2026-08-07.** `C4_SOURCE_COMPLETE` no longer holds. The
> stack audit passed on all three legs because it under-measured: two of its
> three frame-measurement paths produced nothing at all. Slice C4.1a corrected
> the measurement, and three roots on x64 and Win7 and one on ARM64 exceeded a
> frozen bound. Slice C4.2 has since closed that specific gap (see the
> `audit_c4_*` section below); re-establishing `C4_SOURCE_COMPLETE` itself
> remains a judgement for that slice's gate review and is not asserted here.
> Numbers and causes:
> `../docs/superpowers/reviews/evidence/2026-08-07-c4-1a-frame-measurement.md`.

`C4_NATIVE_VERIFIED` requires one public `fsring-control-smoke/v2` PASS from a
real live run on a separately provisioned elevated x64 host with test signing
enabled. Until that run exists the level is **pending**. A `-SelfTest` result,
a static audit, and a green build are not partial evidence for it — the smoke
harness deliberately refuses to emit a public v2 report unless it actually ran
live, and reports an honest `NOT RUN` instead.

What C4 implements, all of it covered by the gates above:

- **SETUP** — twenty-three ordered effects with exactly one commit boundary at
  `PublishActive`. Failure or cancellation before it unwinds in exact reverse;
  at or after it there is no unwind and cancellation loses. A burned MountId is
  never reused, even on rollback.
- **Protected views** — one read-only whole-section spine plus per-ring
  writable masters, mapped through MDLs with the alias record — never the
  returned user address — as the authoritative unmap key.
- **ENTER** — role acquisition, credit preflight/claim/advance/refresh as
  affine capabilities, and pended completion with exact cancellation.
- **Fence** — one bounded six-stage teardown reached identically by CLEANUP,
  process loss, protocol abort, and unload; read-only aliases, MDLs, the system
  view, and the captured process all survive to stage 6.
- **Volume roles** — a named per-MountId VDO created by SETUP so the I/O
  manager supplies its VPB, a separate named filesystem registration device,
  and an unnamed mounted-volume device bound under the VPB spin lock with a
  full revalidation immediately before `VPB_MOUNTED`.

What C4 still does not do: no request is carried over an established ring, no
file object is created, no cache or memory-manager integration exists, no
passthrough, no restart or replay, and no release evidence.

## Why a separate workspace

Every driver artifact requires `panic = "abort"` (dev + release) plus a
`opt-level=3 / lto=true / overflow-checks=true` release profile and a `>=1.85`
toolchain. Cargo honors `[profile.*]` only at a workspace root, so keeping these
crates out of the repo root keeps `fsring-abi`'s frozen
`cargo +1.82.0 test --release --locked` battery and the root `Cargo.lock`
byte-for-byte intact.

## Prerequisites (one-time, on the build machine)

1. Visual Studio 2022 with **Desktop development with C++**, the **MSVC
   Spectre-mitigated libs (x64)** component, and the **Windows SDK 10.0.26100**
   component.
2. The **standalone WDK 10.0.26100 installer** (this, not the VS "Windows Driver
   Kit" component — that is only the VSIX — delivers the `km` headers/libs).
   Let it install the WDK VSIX into VS2022.
3. `cargo +1.85.0 install cargo-wdk --version 0.1.1 --locked`.
4. LLVM/libclang for `wdk-sys` bindgen — 18.1.8 is present and is measured
   working for **both** x64 and ARM64 against WDK 10.0.26100; see
   [Toolchain](#toolchain) for the scope of that measurement and for the
   upstream caution it refutes.

The SDK and WDK **build numbers must match** (`10.0.26100.x`).

## Build

```powershell
cargo wdk build
```

Produces the packaged `fsring_fsd.sys`. A bare `cargo build` emits the
`cdylib` (`.dll`-named); the `.sys` naming/packaging comes from `cargo-wdk`.

## Native control load smoke orchestration

Run these commands from the repository root. `-SelfTest` is dependency-free
and invokes no real package verifier, smoke harness, or service controller:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File driver\scripts\smoke_driver.ps1 -SelfTest
```

Preflight and live modes require `-ExpectedHarnessSha256` to be exactly 64
uppercase hexadecimal characters. Resolve the canonical x64 package and debug
harness paths, measure the harness once, and preserve that exact
`(PackageDirectory, HarnessPath, ExpectedHarnessSha256)` tuple:

```powershell
$packageDirectory = (Resolve-Path -LiteralPath 'driver\target\x86_64-pc-windows-msvc\release\fsring_fsd_package').ProviderPath
$harnessPath = (Resolve-Path -LiteralPath 'target\debug\fsring-control-smoke.exe').ProviderPath
$expectedHarnessSha256 = (Get-FileHash -LiteralPath $harnessPath -Algorithm SHA256).Hash
if ($expectedHarnessSha256 -cnotmatch '^[0-9A-F]{64}$') {
    throw 'The measured harness SHA-256 is not exactly 64 uppercase hexadecimal characters.'
}

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File driver\scripts\smoke_driver.ps1 -PreflightOnly `
  -PackageDirectory $packageDirectory `
  -HarnessPath $harnessPath `
  -ExpectedHarnessSha256 $expectedHarnessSha256
```

Preflight performs every read-only gate and creates/starts/stops/deletes no
service. When those gates are valid, `-PreflightOnly` deliberately declines
live and reports an honest `NOT RUN` with exit 2, including when
`preflight.runnable=true`; a fatal preflight defect remains `FAIL` with exit 1.
Live is eligible only when that exact preflight result has
`preflight.runnable=true`. From an already elevated 64-bit PowerShell terminal,
reuse the unchanged tuple:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File driver\scripts\smoke_driver.ps1 `
  -PackageDirectory $packageDirectory `
  -HarnessPath $harnessPath `
  -ExpectedHarnessSha256 $expectedHarnessSha256
```

Any package or harness rebuild/replacement, or any package/harness path change,
invalidates the tuple. Resolve the new paths, measure a new harness hash, and
run a new preflight before considering live execution. Each invocation opens a
mandatory non-inheritable read-only harness pin before the verifier or any
mutation and retains it through the final JSON newline and flush. The pin and
identity rechecks protect against stale/accidental, reparse-path, ordinary
TOCTOU identity changes; they do not defend against a malicious local
administrator.

Default non-C4 Live/Preflight/SelfTest still emit exactly one compact
`fsring-driver-smoke/v1` JSON result. Public exit `0` means the complete live
main-probe, owned cleanup, and post-stop absence workflow passed. Exit `1`
means a fatal preflight, live, cleanup, or result-contract failure. Exit `2`
means `NOT RUN`: for example, the token is not elevated, package integrity
passes but `trustReady=false`, or `-PreflightOnly` deliberately declines the
live workflow. A pre-existing `fsring_fsd` is never reconfigured, stopped, or
deleted. Owned cleanup is performed only after client-tree containment is
confirmed; an unconfirmed tree retains its lease through final JSON output and
blocks later service mutation or cleanup.

C4 production mode is explicit: add `-C4` plus lowercase GUID-N `-AttemptId`,
`-CandidateManifestPath`, and lowercase `-ExpectedCandidateManifestSha256`.
The script derives service `fsring-c4-<attemptId>` and DOS name
`Global\FsRingC4-<worker-pid:08X>-<UPPERCASE-attemptId>` internally and
rejects caller name overrides. `-C4 -PreflightOnly` emits one private
`fsring-c4-preflight-orchestration/v1` envelope with `overall=NOT RUN` and
exit 2, performs zero mutation, and writes no script-owned sidecar.
`-C4 -CleanupOnly` is the private recovery set used by the native
orchestrator; it reserves `-CleanupEvidencePath` with CreateNew semantics and
emits `fsring-c4-cleanup-recovery/v1`. Capture of those child processes uses
`driver\scripts\invoke_c4_evidence.ps1`. `-SelfTest` keeps wrapper schema
`fsring-driver-smoke/v1` and `mode=SelfTest`.

The script does not self-elevate; change BCD, test-signing, Secure Boot,
certificate stores, trust policy, or reboot state; or try to repair an unmet
precondition. A live PASS proves only the C3 native control-device slice. It
does **not** prove a mounted filesystem, filesystem I/O, Driver Verifier, SDV,
HVCI, HLK/WHCP, ARM64 execution, or Windows 7 execution.

## Platform profiles

`../docs/design/11-rust-implementation.md` §2 makes platform selection a **compile-time**
decision. `fsring-fsd` exposes two mutually exclusive features:

| Feature | Profile | Targets |
|---|---|---|
| `platform-win10` (default) | `Win10X64`, `Win10Arm64` | x64 and ARM64 |
| `platform-win7` | `Win7X64` | x64 only — ARM64 is modern-only |

`src/platform.rs` turns that into data: `PROFILE`, `PROFILE_NAME`,
`PROTOCOL_MASK`, `OS_CAPABILITY_MASK`, and the `DriverEntry` banner. It is
WDK-free and re-derives **no** wire number — every mask is obtained by calling
`fsring-abi`'s `PlatformProfile`. Three `compile_error!` guards reject the
illegal selections; each also emits a secondary `E0432` for the absent
`selected` module, but the `compile_error!` is the authoritative diagnostic and
is emitted first:

- both features → `platform-win10 and platform-win7 are mutually exclusive…`
- neither → `exactly one of platform-win10 (default) or platform-win7…`
- `platform-win7` + `aarch64` → `platform-win7 is x64-only…`

A `const` battery pins the selection *and* the transcription: under each
feature/arch combination it asserts `matches!(PROFILE, …)` and that the masks
equal the §2 table (`0x9f`/`0x3`, `0x9f`/`0xb`, `0x1f`/`0x0`). It is `cfg`-gated
on purpose — a variant-addressed battery would never consult `PROFILE` and so
would not verify the selection logic at all. Both mutants fail the build with
`E0080`: perturbing an expected mask, and making the x64 arm select `Win7X64`.

## Build and audit matrix (the gate)

```
cmd /c driver\scripts\build_matrix.cmd
```

One command; builds and audits all three **release-profile** images, verifies
both packaged images, runs the three negative feature builds, runs clippy in
four configurations with `-D warnings`, and executes the core host proofs.
Before its first batch subroutine call, each `.cmd` entry point rejects mixed
CRLF/LF files because mixed endings can corrupt `cmd.exe` label-return offsets.
Before changing `PATH`, the matrix resolves the absolute native
`rustup.exe` proxy source and cargo-wdk source. It create-new copies the
hash-checked Rustup bytes as `cargo.exe` and `rustc.exe` into a separate fresh
GUID selector directory whose exact allowlist contains only those two files;
the PATH-installed reparse proxy leaves are never executed. Native handles
prove the source, selector copies, cargo-wdk source, exact Rust 1.85.0
compiler, actual Cargo beside that compiler, and default Rustup home have the
requested final DOS paths and expected file/directory kinds. The matrix
records and rechecks exact versions and uppercase SHA-256 values around each
package leg and at final exit. The dependency-free native shim also recomputes
the three Cargo/rustc hashes with its dependency-free, streaming pure-Rust
SHA-256 implementation before it can attest or spawn Cargo. A hash-rechecked
locked-selector closure runs immediately before and after the direct metadata
process and each cargo-wdk process. It requires exactly the regular,
non-reparse `cargo.exe` and `rustc.exe` selector children, native final-path
identity for their directory/files and the canonical `rustup.exe` source, and
byte-identical expected hashes; a closure failure overrides the child result.
The shim independently repeats the same pure-Rust selector closure during
initial validation, after durable attestation immediately before spawn,
immediately after successful spawn, and after wait/reap. If the post-spawn
check detects contamination, it best-effort kills and definitely reaps the
child before returning the selector failure; a later child exit cannot convert
that failure to success. Exact rustc first
compiles and runs the tracked SHA-256 unit tests (empty, `abc`,
55/56/63/64-byte padding boundaries, multiblock streaming, and length
overflow); the test executable is then removed and the fresh application
directory is proved empty before the production shim is compiled. The tracked,
hash-rechecked native-directory helper enforces a transient allowlist containing
the required `sha256-tests.exe` and only its optional exact-name PDB immediately
before that test launch and again after it returns.

Every invocation creates a new GUID-named application directory under the
canonical `driver\target\fsring-generated-tools` parent with create-new
semantics. The tracked native-directory helper rejects reparse/final-path
escapes and enforces a lifecycle-specific closed direct-child allowlist before
every executable launch. Exact rustc compiles
`scripts/locked-cargo/cargo_shim.rs` into that fresh directory, and the already
version/hash-validated cargo-wdk bytes are copied there without executing the
source installation. A stale app-local DLL or any other unapproved entry makes
the launch gate fail.

Rust 1.85's Windows process search checks the parent application's directory
before its inherited `PATH`. Because an installed cargo-wdk normally sits
beside ambient Cargo, merely prepending a native shim is still bypassable. The
matrix therefore copies the already version/hash-validated cargo-wdk bytes
beside the generated `cargo.exe`, proves the copy is byte-identical, and uses
that absolute launch copy only for the two package legs. cargo-wdk runs from
the `fsring-fsd` workspace member so each leg has exactly one hard-coded
`cargo build` child. The package environment rejects ambient Cargo/Rust/MSVC
compiler, wrapper, flag, target, target-directory, profile, linker, and
bindgen overrides. After `VsDevCmd.bat`, it scrubs the same exact and
target-qualified `CC_`, `CXX_`, `AR_`, `RANLIB_`, `CFLAGS_`, `CXXFLAGS_`, and
`BINDGEN_EXTRA_CLANG_ARGS_` families before setting exact `CARGO`, `RUSTC`,
`RUSTUP_HOME`, `RUSTUP_TOOLCHAIN=1.85.0`, `CARGO_NET_OFFLINE=true`, and
canonical `CARGO_TARGET_DIR`. Cargo configuration discovery is closed to the
tracked `driver\.cargo\config.toml`; locked/offline metadata from the package
working directory must report that exact target and workspace before either
package leg.

The shim accepts only `build`, preserves native argument boundaries, and
invokes exact `+1.85.0` with final
`--target-dir <canonical-driver-target> --locked --offline`. Before spawning
Cargo it create-new writes one strict format-2 UTF-16-hex attestation binding a
fresh per-architecture nonce, Cargo proxy and actual-Cargo paths/hashes, exact
rustc path/hash, Rustup home, target directory, toolchain, and complete final
argument vector. The tracked verifier opens that regular file without sharing,
checks its length before allocating (64 KiB maximum), strictly decodes UTF-8
and bounded UTF-16 fields/arguments, and rejects missing, stale, duplicate,
malformed, oversized, or mismatched evidence. Each architecture's exact
package directory is containment-checked and removed before its leg, so only a
fresh current output can pass. The matrix rechecks all authoritative tools,
helpers, config, lockfile, launch-copy and shim identities around the package
legs and rejects any `Cargo.lock` byte change. Ordinary Cargo commands never
put the fresh generated-tools directory on `PATH`.

| Image | Command | Notes |
|---|---|---|
| Win10 x64 | `cargo wdk build --profile release --target-arch amd64` | packaged, test-signed, infverif |
| Win10 ARM64 | `cargo wdk build --profile release --target-arch arm64` | packaged |
| Win7 x64 | `cargo build --release --target x86_64-pc-windows-msvc --no-default-features --features platform-win7` | bare PE |

**`cargo wdk build` has no `--features` flag** (its options are `--profile`,
`--target-arch`, `--verify-signature`, `--sample`), so the nondefault Win7
profile cannot go through the packaging front end. Its image is therefore
unpackaged and unsigned. That is a packaging gap, not an audit gap: the audited
properties come from the linker via `build.rs` →
`wdk_build::configure_wdk_binary_build()`, which a bare `cargo build` also
runs. Win7 packaging belongs to the release-audit slice.

**Git Bash, explicitly.** `where bash` resolves to `C:\Windows\System32\bash.exe`
(WSL) on a machine with WSL installed, which is the wrong interpreter. The
matrix uses `%ProgramFiles%\Git\bin\bash.exe`; set `FSRING_BASH` to override.

## Static audit

```bash
bash scripts/audit_sys.sh [--expect-machine x64|arm64] [--expect-profile <name>] \
                          [--modules-allow <file>] [--allowlist <file>] <image>
```

Eight checks, every failure exiting nonzero: PE machine matches, subsystem is
NATIVE, every imported **module** is in `audit/kernel-modules.allow`, no
forbidden user-mode CRT module is imported, `DriverEntry` is **exported**
(exact-name match), the
`--expect-profile` string is present in the image, and — when `--allowlist` is
given — every imported **symbol** is in it, and no `--resolver-table` name is
statically imported. C2 added `--expect-string`, which
`audit_sys.sh` uses to check ASCII import presence or absence.
`audit_selftest.sh` exercises representative present and absent fixtures.
`--expect-string` also searches UTF-16LE and self-tests the wide mechanism
before trusting a negative. It runs only when `audit_sys.sh` is called with the
option.

Two rules the script encodes, both learned the hard way:

- **Exact export match.** `ntdll.dll` exports ten names containing
  "DriverEntry" (`NtAddDriverEntry`, `ZwSetDriverEntryOrder`, …) and none of
  them is an entry point, so a substring match is not a check.
- **No `grep -q` in a pipeline.** Under `set -o pipefail`, `grep -q` exits on
  its first match and the producer dies of SIGPIPE, so the pipeline reports
  failure even though the pattern *was* found — `llvm-readobj` over ntdll's
  2435 exports returns 74 that way. Every check reads its producer to
  completion through a command substitution.

`scripts/audit_selftest.sh <x64-image> [arm64-image]` exercises representative
success and failure fixtures. A check that has never failed is not evidence.

### Allowlists

`audit/kernel-modules.allow` lists the import **modules** any FSRING image may
reference; `audit/win7-sp1-imports.allow` is the Windows-7-SP1 **symbol**
allowlist of `../docs/design/11-rust-implementation.md` §8; `audit/win10-imports.allow` is its
modern-profile counterpart. These are closed enumerations, not patterns. Each
symbol allowlist now contains 85 normalized pairs, measured in all three
release images across the two allowed modules — up from the 44 pairs measured
at the C3 result cited below; the most recent addition is C4.2's
`ntoskrnl.exe!KeExpandKernelStackAndCallout`, carrying that slice's own
provenance note in both files. A slice that needs a new module or symbol adds
it **in the same commit**, with a provenance note, so review sees it.

Read the Win7 allowlist for what it is: it proves *"no import outside the
reviewed set"*. It does **not** prove every entry is genuinely
Windows-7-SP1-exported — no Windows 7 SP1 binary is available here, so those
provenance notes are assertions recorded for review, not measurements.

### The two C4 auditors — what each proves, and what it does not

`scripts/audit_c4_imports.py` and `scripts/audit_c4_stack.py` run in both modes
of `build_matrix.cmd`: their `--self-test` in each, and six real invocations
across the three profiles in the production path. The allowlists above say
which imports are *permitted*; these two say which are *present*, because an
allowlist stays green when a required DDI is silently dead-stripped.

**The import auditor proves**, per profile: that the final image's `direct`
imports are exactly the frozen manifest's, compared in both directions; that
the manifest belongs to the profile being audited; and that the image, its PDB
and its link map are one build — the map's timestamp and preferred base against
the PE's, and the PDB's own GUID required to appear verbatim in the image
bytes, because every leg's PDB is named `fsring_fsd.pdb` and a basename is not
identity.

**It does not prove** that a static-library wrapper introduces no *undeclared*
downstream import. The link map attributes `__imp_*` thunks to the import
library rather than to the calling object, so only the declared direction is
enforced — and measured 2026-08-08, all 31 declared rows are a subset of the 85
`direct` rows already compared two-way, so that direction cannot raise either.
Both directions of the wrapper relation are unmeasured. (Slice C4.2 added
`KeExpandKernelStackAndCallout` as a direct import, raising this count from the
84 measured at C4.1a.)

**The stack auditor proves**, per profile: that each of the nineteen declared
roots exists once in the map, is not a declared alias, and fits its bound —
`maxFrameBytes` 2048 and `maxChainBytes` 8192 for an ordinary root, or its own
declared pair for an **expansion root** (below); that each declared indirect
edge names live symbols and is charged to the chain; that a fold group
containing a declared canonical contains nothing else; that no function-local
array is sized by a topology ceiling; and that the link map describes the image
it is measuring.

**It does not prove** three things, each a recorded gap with a measured
population: a fold group with no declared canonical is skipped (five f-flagged
groups per x64 leg, eight on ARM64, including two live production folds); an
undeclared recursion is charged once rather than refused (one on x64); and a
tail transfer is not an edge at all (five on x64, nine on ARM64).

Frames, call edges and unwind records are all attributed by **address** through
the link map, never by the disassembler's label — a final PE carries no COFF
symbol table, so those labels name only the 26 exports among 228 functions. The
frame itself is measured from two address-resolved sources whose maximum is
enforced. Each source must resolve a frozen minimum number of functions, so one
that goes blind fails rather than contributing nothing. A disagreement is a
finding when the prologue charges more than the unwind record; in the other
direction it is counted against a frozen census and reported only in excess.

**Neither auditor's own checks were visible to anything before slice C4.1a.**
The production path ran neither self-test and the self-test path ran no real
audit, so a check replaced by `pass` stayed green in both. Both scripts are now
targets of `mutation_sweep.py --suite c4`; which of their decisions a fixture
drives, which are proven by a named mutant, and which are measured-uncovered is
recorded in
`../docs/superpowers/reviews/evidence/2026-08-07-c4-1a-decision-signal.md`.

**Current result: the stack audit PASSES on all three profiles.** Correcting
the frame measurement (slice C4.1a) had raised three roots on x64 and Win7 and
one on ARM64 above a frozen bound — a `fsring_dispatch_setup` frame of about
6 KB and a dispatch chain of about 23 KB against the 2048/8192 global pair;
numbers and causes are in
`../docs/superpowers/reviews/evidence/2026-08-07-c4-1a-frame-measurement.md`.
Slice C4.2 closed that gap by declaring `fsring_setup_callout` — the function
that does SETUP's own ~23 KB of validation — an **expansion root**: it runs on
a stack `fsring_dispatch_setup` requests through `KeExpandKernelStackAndCallout`
(32768 bytes requested, 24576 enforced against the root's own frame/chain
bounds rather than the global pair), and the audit measures its chain at 23048
bytes on Win10X64/Win7X64 and 7792 on Win10Arm64 — both inside that bound.
`fsring_dispatch_setup`'s own chain, which used to carry the whole ~23 KB,
collapsed to 120 bytes (96 on ARM64) once the deep work moved onto the expanded
stack. No bound was raised and no existing driver source was changed to fit;
the new root is judged by its own declared pair. The auditor's `--imports`
argument (a profile's frozen imports manifest, now threaded through
`build_matrix.cmd`'s three invocations) additionally lets it check: an
expansion root whose declared DDI is not a present import, or whose declared
caller has no call edge to it, is refused. The after-measurement, the ten
enforced decisions and the three measured-uncovered boundaries are in
`../docs/superpowers/reviews/evidence/2026-08-08-c4-2-frame-measurement.md` and
`../docs/superpowers/reviews/evidence/2026-08-07-c4-1a-decision-signal.md` §7.

## The core crate and the host proof harness

`fsring-core` is the WDK-free half of the driver: state machines, closed tables
and total functions that decide the kernel contract of documents 04-10 without
touching a kernel DDI. `fsring-fsd` compiles it into the `.sys`; `cargo test`
compiles the same source for the host. That is how the driver phase gets real
test coverage on a machine that cannot load a driver.

Two rules define it:

- **No WDK, no OS.** Its only dependency is the frozen `fsring-abi`, and
  `tests/dependency_closure.rs` checks it rather than trusting it. The walk cuts
  the `loom` edge, because a `Cargo.lock` records `cfg`-gated dependencies
  unconditionally and `fsring-abi`'s `cfg(loom)` test dependency drags `libc`
  and `windows-sys` into the lock without any driver build compiling them. Two
  assertions stop that cut from becoming a silent escape hatch.
- **Profiles are values, not `cfg`s.** A profile-dependent decision takes
  `PlatformProfile` as a parameter, so one host build exercises all three
  profiles. Compile-time selection stays in `fsring-fsd::platform`.

`DriverEntry` mints and holds a `Passive` token, so the dependency is referenced
rather than merely declared: a core that fails to compile for a kernel target
fails the image build. The token is zero-sized — that is a compile-time claim,
adding no bytes to the image and making no runtime IRQL check.

### Compile-fail proofs

```bash
bash scripts/compile_fail.sh
```

Every fixture in `tests/compile-fail/` must fail to compile **with the message
its `.expected` file names**. A fixture that compiles is a failure; a fixture
that fails with the wrong message is a failure. Exit codes separate the two
things that go wrong: **1** means a fixture misbehaved, **2** means `fsring-core`
itself would not build.

To add one: write `foo.rs` next to the others and `foo.expected` containing a
substring the compiler output must contain — the crate's own diagnostic text
where one exists, otherwise a stable rustc error code such as `E0382`, so a
compiler that rewords a message does not break the gate.

The fixtures are deliberately **not** workspace members. The runner builds
`fsring-core` into a target directory it owns and invokes the **pinned** rustc
(`rustup which rustc`, resolved inside `driver/`) against that rlib. Using a
bare `rustc` picks up the machine's default toolchain instead, and every fixture
then fails with `E0514` (incompatible rustc version) rather than its own error —
which the message-matching rule catches, and an exit-code-only runner would not.

### The `#[allow]` proof-comment rule

`../docs/design/11-rust-implementation.md` §5 permits a local `#[allow]` of the four denied
lints **only with a written proof-of-safety comment**. `fsring-core`'s
`allowscan` module mechanizes the omission case: a pure scanner with unit tests
in both directions, plus a test that walks the whole driver workspace.

Read it for what it is. It makes a *missing* comment impossible; it does not
judge a comment's quality, and being line-based it cannot tell the attribute
from a string literal that starts a line with the same text. It fails toward the
false positive, which is the right direction for a check whose alternative is
parsing Rust.

## Kernel bindings, the allocator, and randomness

`fsring-sys` is the **only** crate that writes an `extern` block, and
`fsring-core/tests/extern_quarantine.rs` enforces that: the import audit and its
allowlists then have exactly one place to look. Most of the surface is
re-exported from `wdk-sys`; three items are hand-written because they cannot
come from there, each with the header, line and reason recorded beside it:

| Item | Why it is hand-written |
|---|---|
| `ExAllocatePoolWithTag` | `wdk-build` blocklists it as deprecated (`bindgen.rs:99`). It is a real declaration at `wdm.h:25297`, gated at `NTDDI_WIN2K`. |
| `BCryptGenRandom` | Not in the WDM base header set; linked from `km/x64/ksecdd.lib`. |
| `mm_get_system_address_for_mdl_safe` | A `FORCEINLINE` in `wdm.h` with no export — its logic is **ported**, not bound. |

**The allocator.** There is no `#[global_allocator]` at all, and no `wdk-alloc`.
One exists to make `alloc`'s infallible APIs work, which is the path
`../docs/design/11-rust-implementation.md` §5 forbids. Every allocation goes through
`fsring_core::alloc::try_alloc` and returns a `Result`; a null return is an
error, never a panic. The Win7 profile additionally owes an explicit zeroing,
because that baseline has neither an NX pool nor a zeroing guarantee.

**The panic handler** calls `KeBugCheckEx` with a vendor-range code, replacing
`wdk-panic`'s bare `loop {}` — an infinite spin at whatever IRQL the panic
occurred, which hangs the machine instead of producing a diagnosable dump. It is
proven load-bearing by a compile-fail fixture: two `#[panic_handler]`s cannot
coexist (`E0152`).

**Randomness** comes only from `BCryptGenRandom` with the system-preferred RNG,
drawn through `fsring_core::random::draw_nonzero`: at most eight retries on a
zero sample, then failure. There is no weaker fallback. `RtlRandom` and
`RtlRandomEx` are bound by `wdk-sys` and forbidden by §4, so a test asserts no
driver **code** mentions them — prose forbidding them is exempt, or the rule
would punish its own documentation.

### The optional-DDI resolver

`../docs/design/00-INDEX.md` §5: the modern image may static-import only DDIs present at the
Windows 10 **1507** baseline. `ExAllocatePool2` is `NTDDI_WIN10_VB` (Windows 10
2004), so it is resolved through `MmGetSystemRoutineAddress` during bring-up and
latched; a null result clears the capability and selects the static
`ExAllocatePoolWithTag` path.

`driver/audit/resolver-names.allow` lists every such name, and
`audit_sys.sh --resolver-table` fails if any of them appears in an image's
**static import directory**. A `fsring-core` test asserts that file equals
`fsring_core::resolver::RESOLVER_TABLE`, so the audit and the driver cannot
drift apart.

This rule exists because the alternative is undetectable here: an image that
statically imports a post-baseline DDI builds, signs and audits clean on this
machine and fails only on a kernel it cannot boot.

## The universal lock order

`fsring_core::lockrank` is `../docs/design/06-locking.md` §1's five-position acquisition order
made checkable: `may_acquire(held, next)` and `may_perform(held, action)`, both
total, both `const`.

| Order | Position | Kind |
|---|---|---|
| 1 | lifecycle-admission gate | gate |
| 2 | per-open lifecycle gate | gate |
| 3 | size gate | gate |
| 4 | sequencer | **spin lock** |
| 5 | AdvanceOnly CSQ | **spin lock** |

Spin locks are leaves, with exactly two fixed nestings out: `sequencer -> CSQ`
and `notification-state -> CSQ`. Neither reverse is legal. Nothing may be waited
on, allocated, mapped, or sent to the provider under a spin lock, and
`IoCompleteRequest` requires holding **nothing at all** (§6) — which is stricter
than the spin-lock rule, so a mere gate forbids it too.

`NotificationState` is modelled with the highest discriminant on purpose: the
document places it *outside* the five-position order, so an ordinal comparison
must never put it between two of the five.

**Read the claim narrowly.** This does not prevent a deadlock; it checks one
named order at sites that call it. Driver Verifier's deadlock detection is the
real gate and cannot run here. A future acquisition site that does not consult
the table gains nothing from it.

## One terminal owner, one refund

`fsring_core::terminal` is `../docs/design/06-locking.md` §5: every terminal arbitration is one
CAS with one owner, and that owner refunds its quota ticket exactly once — only
after the last driver MDL/system-VA access and after `IoCompleteRequest`
*returns*.

`TerminalOwner` is a real `AtomicU8` `compare_exchange`, not a model to be
replaced by the real thing later. The refund path is a chain of typestates, each
encoding one sentence of the document:

```
QuotaTicket<NotYetVisible> --rollback_before_visibility()--> Refund
                           |                                 (§11 "cancel, never visible":
                           |                                  no arbitration at all)
                           --may_be_visible(&owner)--> QuotaTicket<MayBeVisible>
                                                       (bound to THAT arbitration)
RefundGate<Charged> --last_access_done()--> <LastAccessDone>
                    --completion_returned()--> <CompletionReturned> --refund()--> Refund
```

`RefundGate::new` takes a `TerminalClaim` and a ticket, and **fails** unless the
claim was won in the very arbitration the ticket was published under. Without
that binding the types guarantee only that the refunder won *something*: an
adversarial review compiled a probe that lost the real arbitration, minted a
fresh `TerminalOwner`, won it trivially, and refunded the real ticket with that
claim. `refund` exists only on the last state and consumes the gate, so
refunding early, refunding after only one precondition, and refunding twice are
all compile errors with fixtures pinning their messages. `Refund`'s fields are
private, so a receipt cannot be written without performing a refund.

The registry is `§5.2`'s **eleven** arbitrations, and the test that guards it
parses `../docs/design/06-locking.md` and compares against the document — count, order, names,
and a bijection over claimant phrases. The first revision hand-copied ten rows
and asserted "§5.2 has ten rows" as a fact; nothing in it could notice the
missing one. Alongside: `charge_disposition`, total over §5.1's survival table,
where the two rows sharing the word "fence" mean **opposite** things.

**Read the claim narrowly.** These are guarantees about *safe* code — `transmute`
and `ptr::read` defeat them, as they defeat every typestate in Rust. Nothing here touches an IRP,
an MDL, a budget object or a rundown reference, so the typestates prove only that
the code cannot reach a refund without asserting the preconditions, never that
the assertions are true. The race test is empirical evidence on one machine. And
a call site that does not use these types is not protected by them.

## The size domain, the epoch, and the truncate order

`fsring_core::size` is `../docs/design/04-object-model.md` §8.1's domain, `../docs/design/07-cache-mm.md` §3's
trio and epoch, and `07 §5` with `../docs/design/06-locking.md` §3.3's order.

**It delegates the domain rather than restating it.** `MAX_FILE_SIZE`,
`validate_file_range` and `validate_size_state_v21` are frozen in `fsring-abi`
and correct; a second copy would agree today and drift tomorrow. A **source
scan** enforces that: no comparison between two different fields of one state
may appear in the shipped half of the module. The needle is that specific
because `classify_request` is made of same-field cross-state comparisons, which
is exactly what this module is for. A planted *faithful* copy — one returning
identical answers, invisible to any behavioural test — fails the scan.

What the frozen validators cannot express is a **transition** and a **sequence**:

- `classify_request(current, requested) -> Result<SizeChange, _>`, total over all
  27 transitions. A decrease in allocation **or** file size is a `Reduce` — `07
  §5`'s own disjunction — so an allocation-only shrink runs the MM veto and the
  purge. A VDL decrease no reduction absorbs is `Err(VdlRegression)`, not a
  classification.
- `accept_size_response_epoch` — named for its lane, because `size_epoch` has
  three documented comparison regimes and `04 §8.3`'s merge lane gives the
  **opposite** verdict on both `equal` and `higher`. It restates a frozen rule
  (`messages.rs:1622`) at finer grain and carries an equivalence guard for it.
- `Truncation<S>` over §5's five steps, and `Extension<S>` over §3's three
  clauses. Each state carries the document's own wording, and the tests **walk
  the transitions** and compare the labels they collect against the parsed
  document — so a swap in the code is caught, not merely a drift in a stored
  copy. Everything after the irreversible provider commit is infallible by a
  declared `Nonfailing` bound.
- `publish_sizes_to_cc` takes A2's `Passive` token and B1's `HeldLocks`, and
  refuses `IoOrigin::Paging`. It **calls** `may_perform`; a table nothing
  consults is what B1's own gate warned about.

**Read the claim narrowly.** No kernel routine is called here — every Cc and Mm
name is decided about, never invoked. A typestate proves a sequence cannot be
*expressed* out of order; it cannot prove the driver executes it, and §5 warns
that `CcPurgeCacheSection` is not proof that mapped views have gone away. The
zero-fill and VDL-advance rules are the **single-writer** halves of §3's
guarantee; `07 §6`'s ledger is what makes them hold under concurrency. Three of
`06 §3.3`'s `TRUNCATING` obligations are named but not modelled. And a call site
that does not use these types is not protected by them.

## The paging-write issue ledger

`fsring_core::pagingledger` is `../docs/design/07-cache-mm.md` §6 — which that document calls
**"this document's centerpiece because it is what makes sections 3 and 7's
zero-fill and VDL-advance guarantees actually hold under concurrency rather than
only in the single-writer case"** — plus §7's `AdvanceOnly` barrier.

B3 shipped the single-writer halves (`must_zero_fill` and
`vdl_after_cached_write`). B4 models the concurrent provenance decision that
prevents VDL from being advanced over bytes that no completed paging WRITE has
proved written.

**What B4 ships.**

- **One FCB lifecycle owner.** Each FCB owns one `SequencerState` for its
  lifetime. It owns the checked issue counter, active membership, evidence, and
  VDL baseline as one aggregate. Its nonzero `SequencerId` is process-unique, so
  a capability branded by one FCB cannot be used by another even when both have
  issued the same numeric issue.
- **One-call admission.** `SequencerState::admit` consumes an extracted write,
  owner-bound size snapshot, and owner-bound context-claim observation in one
  call. A rejected claim is distinct from issue exhaustion: rejection records
  the complete range as a numbered terminal `INSUFFICIENT_RESOURCES` result;
  exhaustion closes admission permanently and returns the fatal outcome without
  retrying or minting a reusable issue. Existing active writes may still drain.
- **Combined terminal exits.** The aggregate's `complete` and `terminalize`
  calls preflight ownership, liveness, and coverage, then record exact proven
  coverage or failure evidence **before** removing the active issue and
  recomputing the O(1) prefix. Failed exits require `FailureStatus`, whose
  constructor accepts only negative NTSTATUS values; raw success or pending
  status cannot be terminal evidence.
- **Exact bounded evidence.** Ordinary intervals and the inline `UNKNOWN` span
  are projected together before a mutation. An exact representable projection
  retains both residuals; otherwise the conservative fallback preserves the
  lowest issue and its status. The explicit degradation precedence is interval
  bound, failed reservation, inexact representation, then exhausted preclaim
  budget. The 64-ordinary-interval bound includes the two inline slots; no
  update silently drops evidence.
- **Aggregate-owned VDL and barrier.** A same-owner ordinary size snapshot may
  only monotonically advance the sequencer's verified-VDL baseline. Only the
  B3 `VdlClamped` truncation proof, bound into `TruncateSnapshot`, may reset it.
  `advance_only_barrier` validates snapshot ownership before observing admission
  or evidence, computes `target_vdl = min(EndOfFile, current file_size)`, and
  returns the lowest-issue ordinary or `UNKNOWN` blocker (or
  `IssuesExhausted`) rather than a boolean.
- **Affine liveness is deliberate.** Dropping a linearized `PagingWrite` does
  not retire its active issue, so the terminal prefix stalls below it. This
  proves the aggregate does not invent completion; Phase C still owns the
  liveness discipline and call-site audit for every fallible step after
  linearization.

**Normative boundary (design §8).** The aggregate admission model, O(1) prefix,
combined record-before-remove exits, owner-branded snapshots, bounded ledger
decision, five never-clearing event decisions, and barrier query are **SHIPPED**.
The following remain **PENDING**, owned by Phase C: truthful context-pool claims
in fixed global/mount/FCB order; truthful current `SizeState` and B3 truncation
proofs captured under the required FCB locks; real intrusive active nodes,
overflow-node pools, quotas, and active-context charges; teardown/drain and real
waiter/CLEANUP/fence/ATTACH paths; mount terminalization before issue reuse; and
the open-class audit of every further fallible step. An
`ActiveTerminalReceipt` proves sequencer removal only, not the final IRP/MDL
access or pool return; a claim-rejection receipt proves neither.

The `AdvanceOnly` waiter, full revalidation, and the weld from a successful
barrier to the actual VDL mutation are **OUT-OF-SCOPE** for this slice. The
model's node budget and reservation are inputs to the decision function, not
observations of kernel allocation or locking. `MergeTrigger::Inexact` remains
**PENDING**: the enum/fallback is present, but valid host arithmetic has no
producer. No statement here claims that a lock-held FCB observation, real pool
or charge, teardown, or VDL publication has been implemented.

## The request table and `ReqId` partition

`fsring_core::reqtab` is the B5 host model for the request-table portions of
documents 02, 03, 05, 06, and 11. It borrows caller-supplied application,
per-ring system, and global backing and keeps application completion
capabilities disjoint from typed control continuations.

**What B5 ships.**

- **One-call application admission.** Every fallible phase, capacity,
  generation, and `ReqId` preflight precedes the single unsafe
  `mark_pending` effect. The infallible tail installs the resulting pending
  token into an application slot selected through the intrusive free list.
  The per-ring open-lifecycle/PT lanes and global external-change ACK lane
  use separate control backing and never borrow application capacity.
- **Detached candidate capture.** Exact current session/class/generation/state
  identity changes `Visible` to `Capturing` before returning an affine token
  which does not borrow the table. Installation rechecks the token's complete
  provenance and expected opcode after the caller reacquires its gate. Wrong
  kind/opcode on an exact journaled semantic identity remains captured for an
  invalid candidate; other wrong-kind identities acquire no capability.
- **Terminal receipts, not early reuse.** Application and control extraction
  first reserve the slot or lane as `Terminalizing`. Consuming application
  completion returns a `CompletionReceipt` only after the sink call returns;
  consuming control release returns a `ControlRelease`. Only exact validated
  reclaim of the corresponding affine receipt makes capacity reusable or
  retires a generation-max slot.
- **Fence and exact-next rebind.** `Fencing` closes admission and new
  visibility while allowing already-stable old-epoch capture. Explicit
  no-candidate dispositions retain or terminalize the affected capability.
  Rebind requires identical topology and the exact next nonzero epoch, rejects
  unresolved wire phases/control lanes, invalidates old wire identities, and
  retains application owners without a second pending mark.
- **Permanent explicit drain.** `begin_drain` has no reverse transition.
  Already-issued detached captures may resolve and quarantine during drain.
  Only the captured entry remains ineligible for inventory until that
  resolution; bounded inventory calls can continue moving every other eligible
  application/control capability out. Drain never silently drops a capability
  and never bypasses terminal receipt/release reclaim.

`CompletionSink` is deliberately an `unsafe trait`, and `mark_pending` and
`complete` are unsafe effects. Each implementation must bind one nonduplicable
sink value to exactly one native request. The safe request-table API proves
at-most-once use per capability and the ordering of its model transitions; it
does **not** prove that Phase C supplied truthful locks, stable-prefix facts,
rundown/resource completion, or sink provenance. It also cannot force eventual
consumption (`mem::forget` remains possible), prove native IRP uniqueness, or
show that any image loads.

Phase C remains responsible for real nonpaged backing lifetime, one
mount-owned table view across sessions, state-lock and SQ/CQ memory ordering,
candidate bytes, grant/mapping rundown, B2 terminal arbitration, completion
outside forbidden locks and after final MDL/system-VA access, honest opcode
metadata, capture-token retention, quiesce policy, and draining before backing
destruction. Driver Verifier, SDV, HVCI, VM-load, ARM64 execution, HLK/WHCP,
and `winfsp-tests` evidence remain unclaimed.

## The held context and the observed effect

`fsring_core::effect` is the C1 instrument every Phase-C call site will be
measured by. It adds no DDI, no import and no wire vocabulary: at the C1 commit,
part of its own gate was that all three RELEASE images' normalized
`module!symbol` sets remained equal to B5's. That was set equality, not a claim
that architecture-specific PE bytes, import ordinals, or RVAs were identical.

**What C1 ships.**

- **A vocabulary that can state more of the rules.** `HeldLocks` widened from a
  `u8` over seven positions to a `u32` over fifteen. That is **not** every
  position `../docs/design/06-locking.md` names — FCB rundown, the session/ring/mount-control
  locks, the namespace lock, the registration rundown and the global cancel
  spin lock are known examples outside it.
  `KNOWN_UNMODELLED_POSITIONS_IN_C1` pins those reviewed examples both ways but
  is explicitly non-exhaustive. §1's five-row table is parsed; the rest of the
  roster is transcribed and occurrence-checked, which is weaker and is labelled
  as such. Unlisted positions remain review-bound. Ordering still applies to
  §1's five positions and only those.
- **Effects that carry their targets.** §2's two corollaries land differently on
  the same held set — a provider round trip under the size gate is deliberately
  legal, an admission-resource wait under it is forbidden — so `Wait` carries
  what is waited for and `Allocate` what is allocated. A `TopLevelContext`
  dimension makes `../docs/design/07-cache-mm.md` §4's cache-sentinel rule statable at all; it
  constrains the thread, not the held set.
- **A checker that refuses the curated C1 rules.** `may_emit` replaces B1's
  blanket `Ok` for working effects under a logical gate with named cases for the
  manually transcribed enforcing sentences. An exhaustive sweep over 983,040
  cells compares it to B1's rule and requires every divergence to name one of
  those sentences.
- **A bounded completion certificate.** The four classes named in §6's
  **opening sentence** — ring token, domain/FCB/CCB lock, notification gate,
  mount rundown — are modelled now, so an empty held-set certifies those four.
  Through B5 it certified none of them. It is **not** a certificate over all of
  §6: that section's per-subsystem bullets name detached rundown,
  `cq_enter_owner`, ring/session rundown and the embedded work owner, and C1
  models only mount rundown among them.
- **One observed boundary, *within `effect.rs`*.** `Seam::emit` checks, records
  in issue order, then forwards; a refused effect reaches neither the sink nor
  the log. It generalizes B5's `CompletionSink` pattern from completion to the
  curated C1 effect vocabulary. It is **not** the crate's only emission path:
  `typestate::CompletionOwner::pending` still performs `IoMarkIrpPending`
  unchecked and unrecorded, live-called from `reqtab.rs`.
  `Seam::clear_completion` has zero non-test callers in C2; `Seam::emit` has the
  production caller `Guard::emit`. **Slice C2 closed the `complete` half by
  construction**, not by a live clearance call: `CompletionSink::complete`, the
  raw completion sink, requires a `CompletionClearance`, and the safe path
  obtains one through `Seam::clear_completion` from the reviewed, byte-frozen
  `effect/clearance.rs`. `b5s_pending_path_still_bypasses_the_seam` measures the
  still-open `pending` half. `completion_sink_without_clearance`,
  `completion_sink_call_without_clearance`, and
  `completion_clearance_reaches_raw_sink_once` measure the closed `complete`
  half so it cannot be reopened silently.
- **Guards, including `../docs/design/07-cache-mm.md` §10's conditional one.** A position is
  recordable as held only through a guard that consulted the checker. The
  conditional guard acquires only if the thread does not already own the
  position and releases only what it acquired, and still refuses an illegal
  acquisition rather than returning a guard that took nothing. The spin-lock
  guard is `typestate::Dispatch`'s producer, which A2 said a later slice would
  supply.

**What C1 does not prove.** The checker proves refusal *given* a context; it does
not prove a call site passed a truthful one. C1's contribution is that the
context is threaded structurally instead of asserted locally — the limit moves,
it does not disappear. The recorder observes sequencing that lives in
`fsring-core`; under `../docs/design/11-rust-implementation.md` §1's 2026-07-28 clarification
that is where sequencing belongs, but nothing detects sequencing that drifts into
`fsring-fsd`. Nothing inspects the running IRQL, so a `Dispatch` token minted in
the wrong context is caught by Driver Verifier, not by `rustc`. The effect set
covers the nine manually transcribed, occurrence-checked forbidding sentences in
the C1 evidence log. It does not claim that corpus contains every relevant
document sentence or every effect Phase C will need.

**C1 retires no PENDING.** It tried to retire B4's *"never allocates while the
sequencer lock is held"*, and its own review round 1 showed the attempt was
vacuous: no production ledger path reaches the seam, so a planted heap
allocation left the test green. That test is deleted; the PENDING stands. Every
PENDING B1–B5 handed to Phase C is carried forward unchanged, as is the standing
environment gate:
driver load, Driver Verifier, SDV, HVCI, VM-load, ARM64 execution, HLK/WHCP and
`winfsp-tests`.

## The control device's decidable half

Slice C2. **No device object is created**, here or anywhere in C2 — the title
says so because the first thing a reader should know is what is out of reach.
`IoCreateDeviceSecure`, the SDDL's actual ACL, `FILE_DEVICE_SECURE_OPEN`, and
whether a captured `EPROCESS` is really the requestor are **all load-gated**: no
evidence for any of them is obtainable on a machine that cannot load a driver,
and a static string audit proves bytes reached the image, not that a DDI was
called with them.

What *is* decidable is the precedence those properties surround.

- **The CREATE precedence is parsed, not transcribed.** `../docs/design/09-security.md` §1 is
  sliced by heading, its numbered list read in document order, and the oracle
  `decide_create` is swept against is built from that parse. The two documents
  that restate the precedence are parsed in their own forms —
  `../docs/design/05-irp-dispatch.md` §4's ordered table and `../docs/design/02-transport.md` §10's ordered
  prose — and all three must yield the same sequence of statuses and rule kinds. Reversing the first two
  rules in **any** of the three turns the suite red; that was measured, not
  assumed. `../docs/design/10-lifecycle.md` is deliberately excluded, because it says the rules
  *"are not restated here"*, and a test asserts it still declines.
- **What the parse does not cover.** It supplies each rule's *order* and the
  *status it names*. Which requests a rule refuses is hand-written in
  `RuleKind::refuses` and bound to the document only by tokens. A reviewer must
  read that one function against §1; nothing in the crate can check it.
- **The clearance token's exact bound.** The complete trusted construction
  boundary is the reviewed, byte-frozen `effect/clearance.rs`: it checks
  `may_emit(ctx, Effect::CompleteIrp)` before constructing the private-field
  token. Safe code outside that file cannot fabricate a clearance through
  normal Rust construction. Unsafe code can still violate the invariant with
  `MaybeUninit`, `transmute`, or an equivalent fabrication and then call the
  unsafe, clearance-bearing `CompletionSink::complete`; a bypass therefore
  requires either a genuine clearance from the safe API or a new unsafe
  invariant violation. The token also **borrows** the `EffectContext` it was
  cleared against, so a lock cannot be acquired on that same context value
  while a clearance from it is outstanding.
- **Sixteen cells, four outcomes, one IOCTL registry.** The CREATE domain is
  four booleans and is enumerated. One `control_ioctl_registry!` invocation
  generates `ControlIoctl`, its complete array, accessors, and demux; adding a
  registry row without the corresponding normative §10.2 row fails the
  independent document cardinality/equality checks.
  `Authorization::Refused` is fieldless, so a refusal cannot carry a mapping.

**What C2 does not prove.** Everything in the load-gated list above, plus:
`RuleKind::refuses`; a live call to `Seam::clear_completion` (it has zero
non-test callers in C2, while `Seam::emit` has the production caller
`Guard::emit`); and `pending`, which still bypasses the seam by decision.
**C2 retires only the `complete` half of C1's completion-bypass gap.** Every
other PENDING B1–B5 and C1 is carried forward.

## Toolchain

Pinned to Rust **1.85.0** via `rust-toolchain.toml` (the windows-drivers-rs
stack cannot build on 1.82). Both kernel targets — `x86_64-pc-windows-msvc` and
`aarch64-pc-windows-msvc` — are pinned there too, so the ARM64 leg of the matrix
reproduces from a fresh checkout rather than from a hand-run
`rustup target add`. `fsring-abi` remains on 1.82 in the repo root.

**LLVM for bindgen.** Upstream `wdk-build` 0.5.1 documents that ARM64 bindings
*fail to generate* under LLVM 18. Measured here on 2026-07-25: ARM64 generation
**and** packaging succeed with clang 18.1.8 against WDK 10.0.26100 and
`wdk-sys` 0.5.1. That refutes the caution **for this combination only** — the
underlying bindgen defect is header-dependent, so a different WDK or `wdk-sys`
may still need LLVM 19+ or 17.0.6.

## Resolved dependency versions

`wdk` 0.4.1, `wdk-alloc` 0.4.1, `wdk-panic` 0.4.1, `wdk-sys` 0.5.1 (single,
shared), build-dep `wdk-build` 0.5.1 — pinned in `Cargo.lock`.

## Bring-up gate result — PASS (2026-07-24)

- **Toolchain:** Rust 1.85.0 (`x86_64-pc-windows-msvc`), `cargo-wdk` 0.1.1,
  built inside the VS2022 x64 developer environment.
- **WDK/SDK:** 10.0.26100 (`km` headers/libs verified; `wdk-sys` bindgen ran
  against `ntifs.h`).
- **Build:** `cargo wdk build` → `Finished dev profile … in 49.01s`, then
  `stampinf → inf2cat → makecert → signtool → infverif` all succeeded.
  Artifact: `driver/target/debug/fsring_fsd.sys` (packaged + test-signed;
  `fsring_fsd_package/`).
- **Static audit at that bring-up commit** (`scripts/audit_sys.sh`):
  **AUDIT: PASS** — machine x64, subsystem NATIVE, the historical then-current
  one-pair import `ntoskrnl.exe → DbgPrint`, **no user-mode CRT module**,
  `DriverEntry` exported. This is not the current 44-pair C3 result below.
- **Not claimed** (real-environment / later slices): driver load, Driver
  Verifier, Static Driver Verifier, HVCI scan, the CI three-binary import
  audit, Win7/ARM64 images, `winfsp-tests`. (Slice A1 has since built and
  audited the Win7 and ARM64 images; everything else in this list is still
  unclaimed — see below.)

## Slice A1 gate result — PASS (2026-07-25)

- **Built and audited:** all three release images — Win10 x64 (packaged,
  test-signed, infverif), Win10 ARM64 (packaged), Win7 x64 (bare PE). Each
  audited `AUDIT: PASS` for its own machine and profile string. At that A1
  commit, each imported exactly `ntoskrnl.exe → DbgPrint`; this is historical,
  not the current C3 import set recorded below.
- **Proven to fail closed:** `audit_selftest.sh` 7/7, and a deliberately
  sabotaged copy of the matrix (one audit leg given the wrong expected
  profile) reports `MATRIX: FAIL` with exit 1 while the other legs still pass.
- **Frozen state:** root `Cargo.lock` `242562501e…`, `fsring-abi/` untouched,
  generated header SHA-256 `7BC16346…09AB2D`.
- **Still not claimed, on any profile:** driver load, Driver Verifier, Static
  Driver Verifier, HVCI readiness, retail or attestation signing (these images
  carry a local test certificate only), the Windows 7 SP1 VM load, ARM64
  execution, HLK/WHCP, `fio`, and `winfsp-tests`. **Building and statically
  auditing an image is not evidence that it loads.**

## Slice C3 static-import result — measured (2026-07-30)

- Direct `llvm-readobj --coff-imports` inspection of Win10 x64, Win10 ARM64,
  and Win7 x64 found identical normalized sets of 44 case-folded
  `module!symbol` pairs in all three images, across exactly `ntoskrnl.exe` and
  `ksecdd.sys`. This is set equality, not byte identity: architecture-specific
  PE bytes, import ordinals, and RVAs differ.
- Of those pairs, 5 were already reviewed. C3 adds the 39 observed
  `ntoskrnl.exe` pairs to both profile allowlists: 12 direct
  `ntoskrnl.lib` imports and 27 downstream imports from code pulled out of the
  static `wdmsec.lib` archive. There is no `wdmsec.sys` runtime import.
- `_snwprintf`, `_wcsnicmp`, and `wcschr` are kernel CRT-named exports supplied
  by `ntoskrnl.exe`; they do not introduce forbidden user-mode CRT modules such
  as `msvcrt.dll`, `ucrtbase.dll`, or `vcruntime*.dll`. Data imports such as
  `IoDeviceObjectType` and `SeExports` remain explicitly audited.
- The Win7 entries are backed by installed-header gates and the documented
  Wdmsec baseline, not by a Windows 7 kernel or VM measurement. Likewise, the
  ARM64 leg is build/static-audit evidence, not ARM64 execution evidence.
  None of these static results proves driver load on any profile.

## Slice C4 smoke orchestration — schema only, not a live result

C4 adds a second public smoke schema and a private worker protocol. Both are
**schema and parser work**; neither is evidence that a driver loaded.

- `fsring-control-smoke/v1` is unchanged and remains C3's regression contract.
  `Test-HarnessResult` still parses it byte for byte. The two schemas are never
  mixed: `Test-HarnessResultV2` is a separate parser with its own roster.
- `fsring-control-smoke/v2` has one closed 27-probe roster. Its aggregate
  verdict is **derived**, never read: the parser recompares every `expected`
  against its `actual` and ignores both the per-probe outcome string and the
  top-level `overall`. All 27 matching with no reason is `PASS`; any mismatch, a
  reserved infrastructure reason, or a `NOT RUN` probe once a root identity
  exists is `FAIL`; only a gap before any mutation is `NOT RUN`.
- The private `fsring-c4-worker/v1` frames are little-endian length-prefixed
  JSON with exact sequences 1-4 and stages `STAGED`, `RUN_MOUNT`,
  `LIVE_CLEANED`, `POST_UNLOAD`. `Test-C4FrameContinuity` is the one strict
  helper; a frame that fails it anywhere contributes **nothing** — no identity,
  no event, no probe fact — rather than its well-formed prefix.
- Probe index 25, `unload-transients`, is absent from every worker slice and is
  constructed by PowerShell alone, from exactly three sources: its own retained
  `serviceStopped` and `dosLinkQueryWin32Code`, the live record's
  `formerAliasRangesFree`/`ownedHandlesClosed`, and the post-unload record's
  three open statuses. A missing fragment leaves the probe `NOT RUN`; no field
  is defaulted or inferred, because a defaulted teardown fact reads exactly like
  an observed one.
- `bootcontext-persistent` requires both permanent-object opens to be
  **denied** (`0xC0000022`). A success, a name-not-found, or any worker claim
  about the header or a slot byte is not a valid public fact.
- Ordinary worker reasons have a cumulative budget of 26 per invocation, checked
  before a frame is accepted, and PowerShell emits at most the first
  infrastructure reason for each of the nine closed stages, in stage order. The
  public 35-entry bound is therefore lossless: nothing is truncated, deduplicated
  or replaced.
- The DOS link is PowerShell's alone. `$script:C4DosRemoveFlags` is exactly
  `DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE | DDD_RAW_TARGET_PATH |
  DDD_NO_BROADCAST_SYSTEM`, and removal targets only the exact retained
  name/target pair. `$script:C4CleanupOrder` is
  `contain-worker, remove-dos-link, stop-service, delete-service, post-unload`;
  both are asserted by exact equality in `-SelfTest`.
- `-SelfTest` exercises all of the above with fixtures and creates, starts,
  stops or deletes **no** service. `C4_NATIVE_VERIFIED` still requires a live
  `fsring-control-smoke/v2` run on a separately provisioned elevated x64 host,
  and none of this section supplies it.
