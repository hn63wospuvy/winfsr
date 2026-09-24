# 11 - Rust implementation, platform profiles, and driver packaging

Status: normative for FSRING ABI 2.1. This document defines the complete
Rust/platform implementation contract for the FSRING driver: the workspace
and crate boundary around the `no_std` source-of-truth library, the
compile-time `platform-win10`/`platform-win7` profile split and its
optional-DDI resolution rule, the allocator and MDL/section mapping-protection
matrix that separates the modern and legacy images, the fallible and
no-panic-on-untrusted-input rules the wire library already enforces, the SEH
C-shim boundary, the Rust-specific typestate safety the C model cannot
express, and the build/import-audit/signing/HVCI packaging discipline. It
supersedes the 2.0 implementation draft in full; no 2.0 crate layout, config
key, or signing note survives into 2.1.

The authoritative registries for this document are the unpacked crate sources
`fsring-abi/src/features.rs` (`PlatformProfile`, `protocol_feature`, `os_cap`,
`select_features_v21`, `BASE_REQUIRED_PROTOCOL_MASK`,
`WIN10_X64_PROTOCOL_MASK`/`WIN10_ARM64_PROTOCOL_MASK`/`WIN7_X64_PROTOCOL_MASK`),
`fsring-abi/src/validate/mod.rs` and `fsring-abi/src/validate/messages.rs` (the
fallible, allocation-free validators and the registered-provider-NTSTATUS
allowlist: `is_registered_completion_status_v21`, `MUTATE_FAILURES`,
`OPEN_FAILURES`, `READ_FAILURES`, `WRITE_FAILURES`, `FLUSH_FAILURES`,
`QUERY_FAILURES`, `CompletionDispositionV21`, `classify_completion_v21`),
`fsring-abi/src/validate/boot.rs` (`is_dedicated_service_sid_v1`,
`validate_boot_context_header_v1`), and the checked-range primitives
`CheckedRange64`/`CheckedRange32` in `fsring-abi/src/validate/mod.rs`, together
with the frozen generated header `fsring-abi/include/fsring_abi.h`
(SHA-256 `7BC16346475E8BD786306368EF90D80E6F3009B8CC44ADC11CA6DFD60509AB2D`). If
prose, generated archives, or an implementation disagree with those unpacked
sources, the unpacked sources win. Every feature bit, mask, and status value
below is transcribed from that registry.

A closed set of identifiers below names WDK/kernel-driver concepts that the
`fsring-abi` crate does not and will never carry, because that crate is the
`no_std` wire-format and validation library, not the driver binary itself:
`MmGetSystemRoutineAddress`, `ExAllocatePoolWithTag`, `NonPagedPoolNx`,
`ZwMapViewOfSection`/`ZwUnmapViewOfSection`, `PAGE_READONLY`, `PAGE_READWRITE`,
`PAGE_EXECUTE*`, `MdlMappingNoWrite`, `MdlMappingNoExecute`,
`MmGetSystemAddressForMdlSafe`, `BCryptGenRandom`, `KeBugCheckEx`,
`IoCompleteRequest`, `IoMarkIrpPending`, `HVCI`, and the Static Driver
Verifier / import-audit vocabulary. Each is transcribed from
`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md`
section 1 (the platform decision and compatibility boundary, the allocator and
mapping matrix, the randomness rule, and the CI import audit) and from
`docs/superpowers/specs/2026-07-15-fsring-abi-v2-design.md` sections 11 and 13
(the error model, the Rust kernel rules, the SEH-shim rule, and the
release-signing posture) -- never from the superseded 2.0 draft prose without
independent verification against those sources.

RFC 2119 keywords ("MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY") are used
as defined in RFC 2119.

## 1. Workspace and crate boundary

The implementation is a Cargo workspace whose center is the `fsring-abi`
`no_std` source-of-truth crate. That crate holds every wire type, constant,
opcode, feature bit, and semantic validator, and is the single numeric
authority the whole tree cites; the generated C header
`fsring-abi/include/fsring_abi.h` is produced from it and is byte-frozen at the
SHA-256 above. The remaining crates surround `fsring-abi` and never redefine a
wire value:

```text
fsring/
  Cargo.toml                # [workspace] members; shared release profile
  fsring-abi/               # no_std source of truth: layout, features, msgs, validate/*
  fsring-core/              # no_std WDK-free pure core: state machines, closed tables, total functions
  fsring-sys/               # pinned WDK bindings: IRP, DEVICE_OBJECT, MDL, Cc/Mm/FsRtl/Ob/Se
  fsring-seh/               # C shim crate: __try/__except wrappers with NTSTATUS contracts
  fsring-fsd/               # WDM driver: dispatch, object model, transport glue, PT, cache, lifecycle
  fsring-user/              # daemon SDK: provider trait, ring client, name-match helper
  mirrorfs/                 # sample daemon: mirrors a real directory for the release test suites
```

The driver crate `fsring-fsd` builds to a `.sys` image. It is compiled with the
unwind table disabled and with the release profile set so that a Rust panic
cannot unwind across the FFI boundary into WDK code: the release profile sets
panic=abort, expressed in the driver workspace's `Cargo.toml`
(`driver/Cargo.toml`, see the workspace-split note below) as

```toml
[profile.release]
panic = "abort"
opt-level = 3
lto = true
overflow-checks = true
```

`panic = "abort"` (and its debug-profile equivalent) MUST be in force for every
driver artifact; no profile that permits unwinding across FFI is a release
configuration.

**Workspace-split note (ABI 2.1 refinement, 2026-07-24).** The tree above is a
logical grouping, not a single Cargo workspace. The driver crates
(`fsring-core`, `fsring-sys`, `fsring-seh`, `fsring-fsd`) live in a **separate Cargo workspace
rooted at `driver/`**, which the repository-root workspace `exclude`s; the root
workspace holds only `fsring-abi`, `fsring-user`, and `mirrorfs`. Cargo honors
`[profile.*]` only at a workspace root, so co-locating the driver crates in the
root would impose their `panic="abort"` (both `[profile.dev]` and
`[profile.release]`, the latter with `opt-level=3`/`lto`/`overflow-checks`) on
`fsring-abi`'s frozen `cargo +1.82.0 test --release` battery — changing its
byte-for-byte build environment — and on every host binary, and would add the
driver dependency graph to the root `Cargo.lock`. The separate workspace keeps
the root's `Cargo.lock` and frozen verification byte-for-byte intact. (This
corrects an earlier root-`Cargo.toml` comment that claimed a root
`panic="abort"` would make the frozen `--release` battery "fail on stable";
empirically it does not — Cargo ignores the `panic` setting when building test
units — but the other profile keys and the dev-profile abort are real reasons
the split is required.) See
`docs/superpowers/specs/2026-07-24-fsring-driver-toolchain-bringup-design.md`.

**Pure-core crate (ABI 2.1 refinement, 2026-07-25).** `fsring-core` is a fourth
kernel-side crate: `no_std`, WDK-free, and depending only on `fsring-abi`. It
holds the driver's *decidable* half — the state machines, closed tables and
total functions that the subsystem documents specify — while `fsring-fsd` keeps
everything that touches a kernel DDI. `fsring-fsd` compiles it into the `.sys`
image; `cargo test` compiles the same source for the host.

The reason is verification, not taste. The gates that would exercise driver
behavior — driver load, Driver Verifier, Static Driver Verifier, HVCI, HLK and
`winfsp-tests` — are environment-only (`00-INDEX.md` section 7.2) and cannot be
run in this repository. Splitting the decidable half into a crate that builds
for the host makes the largest possible part of the kernel contract provable
without a load, and leaves the unprovable remainder small and explicitly
labelled.

Two rules keep the split honest. `fsring-core` takes `PlatformProfile` **as a
value**, never as a compile-time feature, so one host build exercises all three
profiles and the compile-time profile selection of section 2 stays in the driver
image where it belongs. And the crate's dependency allowlist is checked, not
merely documented: a test walks the driver lock file and fails if the crate's
**compiled** closure reaches a WDK or OS binding crate. The `cfg(loom)` edge
that a `Cargo.lock` records unconditionally is cut — no driver build compiles
it — and two assertions keep that cut from becoming an escape hatch. See
`docs/superpowers/specs/2026-07-25-fsring-driver-core-crate-proof-harness-design.md`.

**Sequencing clarification (ABI 2.1 refinement, 2026-07-28).** `fsring-core`
owns call-site **sequencing**, not only scalar decisions. An ordered sequence of
kernel effects — install-before-Release, reserve-before-map, linearize-before-
fallible-step, refund-after-completion-returns — belongs in the pure core, and
`fsring-fsd` is the argument-marshalling adapter that performs the effects the
core issues. This follows from this section's own rationale for a pure core: it
exists to make the largest possible part of the kernel contract provable without
a load, and an ordering obligation that lives in `fsring-fsd` cannot be measured
on a machine that cannot load a driver. The mechanism is
`fsring_core::effect::Seam`, whose host recorder observes effects in issue order.

The consequence is accepted rather than discovered: `fsring-core` grows to hold
most of the driver's logic. What it buys is that an ordering, exclusion, or
rollback-completeness claim becomes a measurement rather than an assertion. See
`docs/superpowers/specs/2026-07-28-fsring-driver-c1-held-context-effect-seam-design.md`.

`fsring-abi` itself remains the wire-format and validation
library the whole tree depends on, and it is the very crate boundary that the
corrective design's Rust-boundary rules protect: the driver, the SDK, and the
sample all import their wire vocabulary from `fsring-abi/`, and none re-derives
a size, offset, or status. The daemon SDK (`fsring-user`) reuses the same
`fsring-abi/` validators host-side so the daemon and the kernel agree on
byte-for-byte wire legality before a message crosses the ring.

The exposed ABI is `FSRING_ABI_MAJOR = 2`, `FSRING_ABI_MINOR = 1`,
`FSRING_ABI_MIN_COMPAT_MINOR = 1`. SETUP negotiates an intersection of an
explicit minor range but never selects minor 0; a peer offering only the
pre-release draft is rejected, as `01-principles-architecture.md` section 4 and
`02-transport.md` section 1.1 state. No ABI 2.0 configuration is a supported or
release-ready target.

## 2. Platform profiles (this document's center)

Platform selection is a **compile-time** decision, not a runtime branch. The
crate exposes exactly two mutually exclusive Cargo features:

- `platform-win10` -- the **default** modern profile;
- `platform-win7` -- a **nondefault**, mutually exclusive legacy profile with
  the default features disabled.

Selecting both `platform-win10` and `platform-win7`, or selecting neither, in a
release artifact is a **build error**. The profile is fixed in the binary at
compile time; the driver never chooses its platform at load. The crate models
the three concrete build targets as `PlatformProfile` in
`fsring-abi/src/features.rs` (`Win10X64`, `Win10Arm64`, `Win7X64`), each
carrying its own protocol and OS-capability mask.

The default `platform-win10` profile targets **Windows 10 1507**+ on x64 and
**Windows 10 1709**+ (build 16299) on ARM64, the first ARM64 driver packaging
baseline. ARM64 is **modern-only**: there is no ARM64 legacy image. The
`platform-win7` profile targets **Windows 7 SP1**/Server 2008 R2 SP1 x64
through Windows 8.1/Server 2012 R2, x64 only. Its install prerequisite is a
fully serviced SHA-2-capable machine including KB3033929 and KB4474419 (or a
superseding rollup); an unsupported signing state fails **install**, not driver
initialization after partial use. The modern and legacy packages have separate
audited binaries, catalogs, and exact INF OS decorations, and the default
package never selects the legacy image.

All profiles speak the **exact ABI 2.1 wire contract**. OS differences are
surfaced only through the negotiated `protocol_features`/`os_capabilities`
sets, never by silently changing a wire meaning. The profile masks in
`fsring-abi/src/features.rs` are the authority (low word; the high word is
zero):

| Profile | `protocol_mask` | `os_capability_mask` |
|---|---|---|
| `Win10X64` | `0x9f` (PT, MMAP, HOT_RESTART, EXACTLY_ONCE, SECURITY, MAPPED_IO) | `0x3` (MDL_NO_WRITE, MDL_NO_EXECUTE) |
| `Win10Arm64` | `0x9f` | `0xb` (MDL_NO_WRITE, MDL_NO_EXECUTE, ARM64) |
| `Win7X64` | `0x1f` (PT, MMAP, HOT_RESTART, EXACTLY_ONCE, SECURITY; **no** MAPPED_IO) | `0x0` |

The Win7 profile omits MAPPED_IO because it advertises neither MDL no-write nor
MDL no-execute, and `select_features_v21` clears MAPPED_IO unless both are
detected. `SECURITY` (`BASE_REQUIRED_PROTOCOL_MASK`) is a kernel-required base
feature on every profile. The Cargo/WDK feature gate changes these masks and
the compiled implementation, **not** the numeric wire registry; the exact
negotiation formula lives in `01-principles-architecture.md` and
`02-transport.md` and is not restated here.

## 3. Optional-DDI resolution

The Win7 image MUST contain **no static import first exported after Windows 7
SP1**. Every optional newer DDI is either compiled out of the `platform-win7`
image entirely or reached **only** through a typed function pointer returned by
`MmGetSystemRoutineAddress`. A null pointer from `MmGetSystemRoutineAddress`
clears that capability and selects the complete legacy path **before any mount
is admitted** -- the capability is resolved and latched during BootContext
bring-up, not lazily on a hot path.

Guarding a direct call to a newer DDI with an OS-version runtime check is
**FORBIDDEN**, because the kernel loader resolves the driver's static import
table before `DriverEntry` runs: a static import to a symbol absent on the
running OS fails the load outright, so an OS-version `if` around the call site
never executes. The only correct mechanism for an optional newer DDI on the
legacy image is compile-out or the typed `MmGetSystemRoutineAddress` pointer.

`MmGetSystemRoutineAddress` is used **only** for documented kernel/HAL exports;
it is never treated as a general module resolver, and no address is accepted
from an arbitrary image. A resolved pointer is validated for non-null before
first use and stored in the resolver-name table (see section 8), never in the
static import directory.

## 4. Allocator and mapping-protection matrix

The modern and legacy profiles diverge in exactly how they allocate kernel
storage and how they protect mapped views. Writable data is **never**
interpreted as code on either path.

**Modern profile (`platform-win10`).** Kernel storage uses non-paged NX pool
via `NonPagedPoolNx` (or a dynamically resolved stronger allocator obtained
through the `MmGetSystemRoutineAddress` rule in section 3). Mapped descriptor
lists apply the **detected** no-write/no-execute protections: a modern MDL
mapping ORs `MdlMappingNoWrite` and `MdlMappingNoExecute` when the OS-capability
probe reports them (`os_cap::MDL_NO_WRITE`, `os_cap::MDL_NO_EXECUTE`). No
storage is ever both writable and executable.

**Per-page-direction clarification (ABI 2.1 refinement, 2026-07-25).** The
sentence above states the profile axis and is silent on the page direction.
`02-transport.md` and `05-irp-dispatch.md` state it, and `00-INDEX.md` section 4
ranks `02-transport.md` above this document, so they govern: the modern profile
passes `NormalPagePriority | MdlMappingNoExecute` and additionally
`MdlMappingNoWrite` **only for input-only pages — output pages remain
writable**, while the Win7 profile passes only `NormalPagePriority`. There is no
conflict on the profile axis, because the OS-capability masks are compile-time
profile constants (`WIN10_X64_OS_CAPABILITIES = 0x3`,
`WIN10_ARM64_OS_CAPABILITIES = 0xb`, `WIN7_X64_OS_CAPABILITIES = 0` in
`fsring-abi/src/features.rs`), so "when the probe reports them" is satisfied by
construction on every modern profile and never on the legacy one. Applying
`MdlMappingNoWrite` to an output page would break the very transfer the mapping
exists for; `fsring-core::mapping` implements the six profile-by-direction cells
and asserts that one explicitly. See
`docs/superpowers/specs/2026-07-25-fsring-driver-sys-panic-alloc-design.md`.

**Legacy profile (`platform-win7`).** Kernel storage uses the explicit
`ExAllocatePoolWithTag(NonPagedPool)` fallback. That allocator:

- **zeroes every allocation before publication** (there is no
  `NonPagedPoolNx` on the Win7 baseline, so the profile never claims non-paged
  pool NX);
- keeps its pool blocks **kernel-only**; they are never user-mapped. Storage
  shared with the daemon is **section-backed** instead of pool-backed;
- maps section views via `ZwMapViewOfSection`/`ZwUnmapViewOfSection` with an
  explicit `PAGE_READONLY` or `PAGE_READWRITE` protection, and **every original
  and alias view rejects `PAGE_EXECUTE*`**;
- passes only supported page-priority bits on an MDL mapping and **never ORs
  `MdlMappingNoWrite` or `MdlMappingNoExecute`**, whose encodings are not a Win7
  contract. Applying either flag on a Win7 mapping is a defect; the legacy
  image applies **neither**.

This asymmetry is intentional and load-bearing: the modern image relies on
detected MDL protections, and the legacy image relies on `PAGE_READONLY`/
`PAGE_READWRITE` section protections that reject execute, so both reach a
no-writable-code posture through the mechanism their OS supports.

**Randomness (both profiles).** All kernel randomness is generated at
PASSIVE_LEVEL by `BCryptGenRandom(NULL, ..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)`
through the kernel CNG import, which is available to the Win7 profile as well.
Time, counters, PIDs, `RtlRandom*`, and daemon-supplied bytes are **never**
entropy. There is **no weaker fallback**: a `BCryptGenRandom` failure aborts
BootContext initialization / `DriverEntry`, or returns `INSUFFICIENT_RESOURCES`
before a SETUP `MountId` is published (fail-closed). A required nonzero random
field is drawn into a private zeroed buffer and retried at most eight times if
the complete sampled integer is zero; eight consecutive zero samples fail
closed. The BootContext identity that consumes this randomness is defined in
`10-lifecycle.md` section 3; the crate's `validate/boot.rs` validates the
resulting header.

## 5. Fallible, no-panic Rust rules

Kernel Rust is `no_std` and does **not** unwind across FFI. The production
input paths prohibit `unwrap`/`expect`, unchecked indexing, unchecked integer
arithmetic, and infallible allocation APIs. These are enforced as crate lints
on the driver and validation code:

```rust
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
)]
```

A local `#[allow(...)]` is permitted only with a written proof-of-safety
comment. All allocation wrappers are **fallible** and return `Result`/NTSTATUS;
steady-state I/O uses bounded pools/lookasides and never depends on an
allocator that aborts on out-of-memory. This is the crate-level meaning of
"fallible allocation" the corrective and original designs require.

Every untrusted length, offset, count, alignment, enum, flag, reserved field,
UTF-16 string, generation, session, opcode, status, and object identity is
validated before use by the allocation-free helpers in
`fsring-abi/src/validate/`. Untrusted `u64` quantities are reduced to a
`usize` slice bound only through **checked arithmetic**: the crate's
`CheckedRange64` computes its length with `checked_sub` and only accepts a
range whose end does not precede its start, so a hostile length/offset cannot
wrap into an in-bounds slice. The governing rule is the error model of the
original design: **a daemon-controlled value can fail a request, session, or
volume, but MUST NOT directly cause an unchecked dereference, integer wrap,
panic, or system bugcheck.** Provider-returned NTSTATUS values are restricted to
an operation-appropriate **allowlist** or normalized to a safe failure; the
crate's `fsring-abi/src/validate/messages.rs` carries that allowlist
(`is_registered_completion_status_v21`, and the per-class
`OPEN_FAILURES`/`READ_FAILURES`/`WRITE_FAILURES`/`MUTATE_FAILURES`/
`FLUSH_FAILURES`/`QUERY_FAILURES` sets), and a malformed or contradictory
answer is classified as a session protocol fault (`CompletionDispositionV21`)
that quarantines the session into GRACE/teardown per `10-lifecycle.md`
section 7.

Because untrusted input must never reach a panic path, the driver installs a
`#[panic_handler]` that calls `KeBugCheckEx` with a coded bugcheck value: a
Rust panic in the kernel is a **real, proven kernel bug**, not a recoverable
condition, and it is expressed as a coded bugcheck, **never** silent unwinding.
If an internal invariant proves that kernel memory ownership is already
corrupted, fail-fast via bugcheck is preferable to continuing and corrupting
unrelated kernel state.

The lock model is **not** re-derived here. The CSQ, spinlock, and rundown
discipline -- the acquisition order, the cancel-safe queue used to pend
GRACE-blocked work, and the run-down protection that governs teardown -- is
defined normatively in `06-locking.md`. This document states only that the Rust
side encodes that discipline in RAII guards and the typestate tokens of
section 7, and that the static lock-order lint is a best-effort supplement to
the Driver Verifier deadlock-detection battery in `12-test-plan.md`.

## 6. SEH boundary

Rust cannot express `__try`/`__except`, so every memory access that **may
fault** passes through a minimal C **SEH** shim with an explicit NTSTATUS
contract. The shim crate `fsring-seh` exposes probe/copy/validate entry points:

```c
NTSTATUS fsring_seh_probe_read (const void* p, SIZE_T len);            // ProbeForRead in __try
NTSTATUS fsring_seh_probe_write(void* p, SIZE_T len);                  // ProbeForWrite in __try
NTSTATUS fsring_seh_copy_in    (void* dst, const void* usr_src, SIZE_T len);
NTSTATUS fsring_seh_copy_out   (void* usr_dst, const void* src, SIZE_T len);
NTSTATUS fsring_seh_valid_sd   (const void* sd, SIZE_T len, ULONG info_mask);
```

Rust calls these through FFI and receives an NTSTATUS; Rust **never**
dereferences a raw user pointer directly, and Rust **never** attempts to catch
SEH -- the `__except` filter belongs to C, and a structured exception that
escapes the shim is a defect, not something Rust unwinds. The buffer method
(buffered / direct / neither) is decided at dispatch:

- **Direct I/O** accesses the system virtual address of the locked MDL via
  `MmGetSystemAddressForMdlSafe` (see `05-irp-dispatch.md`); this address is
  kernel-safe and needs **no** SEH shim.
- **Neither I/O** hands the driver a raw user pointer, which **MUST** go
  through the probe/copy shim under `__try`/`__except` before any read or
  write.
- **Buffered I/O** uses the system buffer and needs no user-pointer probe.

The `fsring-seh` boundary and the `MmGetSystemAddressForMdlSafe` path together
are the only ways the driver touches memory that a hostile daemon or user could
have unmapped or reprotected.

## 7. Typestate safety (Rust-specific)

The driver uses the Rust type system to make two kernel-safety properties
**compile-time** facts that the equivalent C model can only assert at runtime:
IRQL discipline and completion ownership.

**IRQL capability tokens.** A zero-sized `Passive`/`Dispatch` token is
threaded through the call graph so that an API requiring PASSIVE_LEVEL cannot be
called from a raised-IRQL context. Raising IRQL yields a token and lowering
reclaims it; the token is not `Copy`/`Clone` while it represents a held
elevation.

```rust
pub struct Passive(());   // constructible only at a PASSIVE_LEVEL dispatch entry
pub struct Dispatch(());

fn cc_set_file_sizes(_p: &Passive, /* ... */);   // will not compile without a Passive token
```

**Completion ownership.** A move-only `CompletionOwner` wraps the in-flight
IRP. Its `complete` method **consumes** `self`, which makes calling
`IoCompleteRequest` at most once through that owner a property the compiler
enforces: a double-complete does not type-check.

```rust
pub struct CompletionOwner { /* not Clone, not Copy */ }
impl CompletionOwner {
    pub fn complete(self, status: NtStatus, info: usize) { /* at most once through this owner */ }
    pub(crate) fn pending(self) -> PendingToken { /* request-table admission only */ }
}
```

The request table holds the `CompletionOwner` until its completion arrives;
drain takes it out and calls `complete`, and the move-only property guarantees
no second completion through that owner. Together with the unsafe sink
uniqueness contract below, this is the Rust-specific safety that the C driver
model cannot express structurally.

**Pending-ownership clarification (ABI 2.1 refinement, 2026-07-25).** The
paragraph above and the code sketch above it cannot both be read literally: if
`pending(self)` consumes the owner, no table can afterwards hold a
`CompletionOwner` whose IRP has been marked pending. **The code sketch
governs.** `pending` consumes the owner and yields a move-only `PendingToken`
carrying the sole route back to a completing value; the request table holds that
token and consumes it to re-materialize the single `CompletionOwner` that
completes the IRP. The preceding paragraph's "holds the `CompletionOwner`"
describes the same ownership chain informally and is superseded on the literal
point. `fsring-core::typestate` implements the sketch.

The safe public surface does not expose `pending` or any conversion from
`PendingToken`: one request-table admission call performs every fallible
preflight, marks pending, and installs the token in one nonfailing tail. On a
terminal path the table moves the token into an affine completing value but
keeps the slot in `TERMINALIZING`. Consuming completion returns an opaque
receipt only after `IoCompleteRequest` returns; the table may return the slot to
its free list, or retire its maximum generation, only when it consumes that
receipt after the remaining mapping/rundown preconditions are also satisfied.
Dropping either affine value leaks progress conservatively and never makes the
slot reusable.

`CompletionSink` is an unsafe implementation contract: one sink value must
represent unique ownership of one native request and must not be `Copy` or
`Clone`. The type system proves **at most one completion per owner
capability**. It cannot prove that a capability is eventually consumed, or
that two dishonestly duplicated sink values do not name the same IRP; the
unsafe kernel adapter and teardown audit own those obligations.

Both sink-effect methods are themselves `unsafe fn`. Calling `mark_pending`
requires unique ownership of an unmarked request and calling `complete`
requires unique terminal ownership plus the documented IRQL/lock/rundown
preconditions. `CompletionOwner` and the request table encapsulate those unsafe
calls behind their safe affine transitions. Owning a sink value directly is
not safe authority to invoke either kernel effect.

Two limits of this mechanism are stated here so no implementation over-reads it.
The move-only property makes a second `complete` on **one owner** a compile
error; keeping it to **one owner per IRP** is the obligation of the
`CompletionSink` implementor, which MUST NOT be `Copy` or `Clone` and MUST be
constructible only where ownership of the request is transferred. And the IRQL
tokens are a compile-time discipline: nothing in them inspects the running IRQL,
so a token minted in the wrong context is caught by the Driver Verifier IRQL
checks of `12-test-plan.md`, not by the compiler. The minting points are
therefore `unsafe`, with the required context stated in each safety contract.

## 8. Build, import audit, signing, and HVCI

**Link posture.** The driver is pure WDM (KMDF is not used for a filesystem
driver): the image links with `DriverEntry` as the WDM entry point,
`/SUBSYSTEM:NATIVE`, `/DRIVER`, and no C runtime.

**CI separate-binary builds and import audit.** CI builds three separate
binaries -- Win10 x64, Win10 ARM64, and `platform-win7` x64 -- and audits each:

- `llvm-readobj --coff-imports` (and WDK `dumpbin /imports` in the WDK job)
  dumps the import table; the Win7 import table is compared against a
  **checked-in Windows-7-SP1 import allowlist**, and any import first exported
  after Windows 7 SP1 fails the job;
- PE machine and subsystem metadata are verified per profile;
- the Rust settings are verified to be panic-abort / no-unwind;
- the **absence of CRT imports** is verified;
- every modern optional symbol is verified to appear **only** in the
  resolver-name table (resolved through `MmGetSystemRoutineAddress`), never in
  the static import directory.

A Windows 7 SP1 VM MUST load the **exact audited artifact** before its
conformance tests run; the audit and the load-in-a-Win7-VM check are enumerated
as gates in `12-test-plan.md`.

**HVCI.** The driver MUST be `HVCI`-compatible: no self-modifying code and no
writable-executable (RWX) pages. This is reached by the combination of
panic=abort (no unwinder-generated dynamic code), no JIT, and the
`MdlMappingNoExecute` / non-paged-NX allocator posture of section 4 on the
modern profile. HVCI readiness is checked with the Device Guard / HVCI
readiness scan before signing.

**Static Driver Verifier and signing.** Every release binary passes
**Static Driver Verifier** before it is submitted for signing. Production
signing goes through the current Microsoft Hardware Program path. Attestation
signing is **not** documented as a substitute for retail HLK/WHCP
qualification, and it is **not** a Windows 7 compatibility mechanism: the Win7
image's compatibility comes from its SHA-2 servicing prerequisite and its
audited legacy import surface (sections 2-3), not from the signing method.
Development test-signing or a managed WDAC signing policy may be established
only through a separately authorized operator procedure in an isolated
driver-test lab, and either MUST be recorded in the deployment audit record.
Boot configuration, Secure Boot, certificate and trust stores, reboot state,
and signing policy are operator-owned and outside both smoke preflight and live
smoke. This document intentionally provides no host-mutation command. When the
required lab state is absent, smoke reports `NOT RUN` rather than changing it.

## 9. Configuration and observability

The driver reads a per-volume configuration surface at SETUP (the base defaults
live under the service `Parameters` key, overridable per volume through the
SETUP request). Power-of-two ring capacities are validated at SETUP and a bad
value fails `STATUS_INVALID_PARAMETER`. The tunable keys and their wire
provenance:

| Key | Default | Source document |
|---|---|---|
| `reqtab_capacity` | 4096 | `02-transport.md` section 8 |
| `max_queued_irps` | 65536 | `02-transport.md` section 9 |
| `mapped_threshold` | 262144 (256 KiB) | driver policy gated by `MAPPED_IO` (`02-transport.md` section 1.2) |
| `sq_capacity` | 256 | `02-transport.md` section 2 |
| `cq_capacity` | 512 | `02-transport.md` section 2 |
| `ring_count` | `min(nproc, 16)` | `02-transport.md` section 2 |
| `notify_area_size` | 65536 | `02-transport.md` section 9 |
| `info_cache_ttl_ms` | 1000 | `07-cache-mm.md` section 9 |

The hot-restart **grace deadline is not a configuration key.** It is the
**fixed** compile-time constant `RESTART_GRACE_TIMEOUT_MS = 30000` defined by
ABI 2.1; it is not daemon- or registry-configurable, and there is deliberately
no configuration row for it. The lifecycle contract that consumes this fixed
deadline is stated in `10-lifecycle.md` section 4. (This corrects the 2.0
draft, which exposed the deadline as a configurable registry value; ABI 2.1
carries only the fixed constant.)

**Observability.** A fixed-GUID ETW / TraceLogging provider emits the minimal
event set -- submit, complete, bad-CQE, ring-full, park/wake, PT grant/revoke,
GRACE/ATTACH (keyed by `MountId`/`BootInstanceId`, not by any per-volume GUID),
and notification-dropped -- with per-request latency computed from the request
table's submit timestamp. ABI 2.1 defines no stats-query control op (the
control registry is exactly SETUP/ENTER/ATTACH/DONATE_BACKING/
DONATE_SECURITY_CONTEXT/DETACH/RETIRE_MOUNT, `02-transport.md` section 10), so
these counters are ETW-only and feed the performance harness of
`12-test-plan.md`.

## 10. Definition of done (stated, not executed)

This document's contract is complete when the following hold; the executable
form of each is a named gate in `12-test-plan.md`:

- the whole-workspace **host** build (`fsring-abi`, `fsring-user`, `mirrorfs`)
  is clean; the `fsring-fsd` driver builds on Windows with the pinned
  **Rust 1.85** toolchain and WDK, for `platform-win10` (x64 and ARM64) and
  `platform-win7` (x64), each artifact separately audited per section 8. (The
  driver toolchain is pinned to Rust 1.85, not 1.82: the `windows-drivers-rs`
  stack is Rust 2024 edition with `wdk-build` 0.5.1 declaring MSRV 1.85.0, so
  1.82 cannot build it. `fsring-abi` and its frozen battery stay pinned to
  Rust 1.82; the two pins are independent because the driver crates are a separate
  workspace, per section 1's workspace-split note.);
- `fsring-abi` `cargo test` is green under the `no_std`, panic-abort release
  profile (already met by the frozen crate);
- a host `cargo fuzz` decoder soak over the control/completion decoders in
  `fsring-abi/src/validate/messages.rs` finds no out-of-bounds access or panic
  before those decoders run in the kernel;
- the CI import audit passes on all three binaries (`llvm-readobj`
  `--coff-imports` / `dumpbin /imports` vs the Win7-SP1 allowlist, PE
  machine/subsystem, panic-abort/no-unwind, no CRT imports, resolver-only
  optional symbols), and the audited Win7 artifact loads in a Windows 7 SP1 VM
  on the SHA-2 servicing baseline;
- a test-signed driver loads, passes **Static Driver Verifier**, and reports
  `HVCI` readiness with no RWX or self-modifying code.

Every item above is cross-referenced to `12-test-plan.md`, which owns the
environment, workload, threshold, and evidence for each gate; this document
states the contract those gates verify and does not itself execute them.

## C4 implementation surface and evidence

`fsring-core` gained the WDK-free adapter plans `adapter::setup`,
`adapter::enter`, and `adapter::volume`. Each states one native choreography as
ordered data plus affine capabilities; `fsring-fsd` translates one typed effect
into exactly one native call and restates no transition order. Three places are
capability types rather than tag effects, because each is where an executor
could otherwise skip a step: `PendingCreditClaim` spends the preflight through
the caller's grant table, `PendingCqHeadAdvance` converts its private claim only
through an `unsafe` method whose contract is the Release store, and
`PendingRoleRelease` hands the retained lease back to its ring.

`fsring-user` gained `native` (the `ControlTransport`/`MappingInspector` seams,
`ControlDevice::setup`, and owned overlapped ENTER) and `smoke` (the public v2
report and the closed private worker protocol). The overlapped owner's `Drop`
performs exact cancellation and a terminal observation; if the transport still
cannot show the OS is finished, it deliberately leaks the pending object rather
than freeing memory the kernel may still write.

Evidence: `driver/scripts/audit_c4_imports.py` proves the final image's *direct*
imports are exactly what `driver/audit/c4-imports-*.json` froze, in both
directions — the existing allowlists say what is *permitted*, and
permission is not presence. It also binds the three artifacts to one build: the map's
timestamp and preferred base to the PE's, and the PDB's GUID to bytes that must
appear in the image. A wrapper's *downstream* imports are proven present but not
exhaustive; an undeclared one is a recorded gap, not a claim.
`driver/scripts/audit_c4_stack.py` proves every entry root is bounded in its own
frame and in its deepest chain, that every same-address fold containing a
declared canonical is a declared alias, and that no function-local array is
sized by a topology ceiling. A fold group containing no declared canonical is a
recorded gap; so are an undeclared recursion, which is charged once rather than
refused, and a tail transfer, which is not an edge.

Frames and call edges are attributed to the link map symbol owning each
instruction address, never to the disassembler's label: a final PE carries no
COFF symbol table, so those labels name only the exports and would charge every
internal function to whichever export precedes it. The same rule governs the
frame itself, which is measured from two address-resolved sources — the summed
prologue and the unwind table — whose maximum is enforced. Each source must
resolve at least a frozen per-profile minimum of functions, so a source that
goes blind fails instead of contributing nothing. A disagreement between them
is a finding when the prologue charges *more* than the unwind record, and
otherwise is counted against a frozen per-profile census and reported only in
excess; the reasoning is recorded in
`docs/superpowers/reviews/evidence/2026-08-07-c4-1a-frame-measurement.md`.

A root may declare that it runs on a stack the driver asked the kernel for. An
**expansion root** names the DDI that expands the stack, the caller that
requests it, the number of bytes requested, and the source constant that number
must equal; it is judged against its own frame and chain bounds rather than
against the default pair. `fsring_setup_callout` is the first: SETUP's own
validation reaches about 23 KB, of which about 16 KB is a frozen `fsring-abi`
frame, so `fsring_dispatch_setup` requests 32768 bytes through
`KeExpandKernelStackAndCallout` and the audit enforces 24576 against it. The
gap is declared headroom, not slack. The audit refuses a request over the DDI's
own ceiling, a bound looser than the request, a budget declared for a symbol
that is not a root, a constant that disagrees with the manifest, a DDI the
imports manifest does not declare, a caller with no call edge to its declared
DDI, an image function *other than* the declared caller that has a call edge
to that DDI, a checked-in call site whose parsed first argument does not read
`Some(<declared root>)` once comments and strings are stripped, an image that
calls a stack-expanding DDI no `expansionRoots` entry declares at all, and —
the decision that makes the boundary real — any direct call into the callout,
which would put the whole expanded chain back on the caller's stack. What
binds the manifest to the request is the source constant, not the emitted
immediate; what binds the call site's source text is a parsed, exact match,
not the linked instruction stream; and no check here proves the pointer
argument a correctly-edged caller's own call site emits into that stream —
five measured-uncovered boundaries, not one, none of them closed by this
paragraph's claim.
`docs/superpowers/reviews/evidence/2026-08-07-c4-1a-decision-signal.md` §7,
not this paragraph, is the authority on all of them.

Both run in `build_matrix.cmd`, in **both** of its modes, with their own
self-tests, and both are targets of `mutation_sweep.py --suite c4`. Named
operators cover the decisions the decision-signal table lists as proven; the
remainder are recorded there as fixture-only or as measured-uncovered, with the
consequence of a silent break stated for each. That table, not this paragraph,
is the authority on what these two scripts can see:
`docs/superpowers/reviews/evidence/2026-08-07-c4-1a-decision-signal.md`.

Each effect of the load choreography is compiled as its own frame, so the entry
root costs the deepest effect rather than the sum of all of them.

The sixteen fence effects have one executor. `KernelFenceOps` is the single
generic runner, parameterised over the `FenceKernelDdi` trait that names the
sixteen native operations; core tests drive it through a recording DDI and the
driver binds it to the real one. There is no second per-DDI runner and no
specialization, so the arm a host test proves is the arm production runs.
