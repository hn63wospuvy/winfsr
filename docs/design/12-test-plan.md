# 12 - ABI 2.1 release verification and test plan

Status: normative for FSRING ABI 2.1. This document defines the complete
release-test contract: the toolchain and RED discipline that gate every
source change, the layout and platform-build matrix that proves the wire
format on each supported architecture, the Driver Verifier battery and OS
test matrix, the correctness/model-checking/fuzz/differential suites, the
lifecycle and exactly-once restart suite, the performance gates, the
per-document DoD-to-case map, and the explicit list of environment-only
gates that this wave states as requirements but does not execute. It
supersedes the 2.0 test-plan draft in full; no 2.0 milestone label, exit
threshold, or feature-gated subtest survives into 2.1.

The authoritative registries for this document are the unpacked crate
sources under `fsring-abi/` — `layout.rs` (the golden size/alignment/offset
assertions and the constant/opcode registry), `msgs/*` and `control/*` and
`durable/*` (every wire struct that a golden or fuzz case exercises),
`features.rs` (`protocol_feature::SECURITY`, the paired `HOT_RESTART`/
`EXACTLY_ONCE` bits, `BASE_REQUIRED_PROTOCOL_MASK`, and
`UNSELECTABLE_PROTOCOL_MASK`), and `validate/*` (the fallible, no-panic
validators whose fault paths the fuzz and fault-injection suites drive —
together with the frozen generated header `fsring-abi/include/fsring_abi.h`,
whose SHA-256 is
`7BC16346475E8BD786306368EF90D80E6F3009B8CC44ADC11CA6DFD60509AB2D`, and the
already-normative documents `02-transport.md`, `03-messages.md`,
`04-object-model.md`, `05-irp-dispatch.md`, `06-locking.md`, `07-cache-mm.md`,
`08-passthrough.md`, and `09-security.md`. If prose, a generated archive, or
an implementation disagrees with those unpacked sources, the unpacked
sources win, and every wire value a test asserts is transcribed from that
registry, never from the superseded 2.0 prose.

A closed set of identifiers below names toolchain, kernel-driver, OS, and
laboratory concepts that the `no_std` `fsring-abi` crate does not and will
never carry as named constants: the `Rust 1.82` toolchain gates, the MSVC/
clang-cl layout compile, the PE machine/subsystem and import-`allowlist`
audits, the `Driver Verifier` battery (`Special Pool`, pool tracking,
force-pending I/O, I/O verification, `deadlock detection`, security checks,
IRQL checking, and systematic `low-resource` injection), the ARM64
barrier-disassembly gate, `winfsp-tests`, `HLK` filesystem tests, `fio`/
`diskspd`, and Windows Defender. These, together with the numeric release
thresholds — at least `10,000` restart/attach/replay cycles, the `24-hour`
Driver Verifier soak per profile, PT sequential at least `90%` and PT 4 KiB
QD32 at least `80%` of direct backing NTFS, the CI regression ceilings of
`5%` throughput and `10%` p99, and the p50/p99/`p99.9` per-run metric set —
are transcribed from corrective-design section 15 (the verification spine)
and original-design section 12 (the correctness and performance release
gates), which the crate does not encode. This is intentional: the release
gate matrix, not the crate, is the subject of this document.

The keywords MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as
described in RFC 2119.

No release proceeds while any correctness gate below fails. A milestone
closes only when every DoD of each referenced document is green **and** the
exit criteria in this document hold. Test is the contract: a feature without
a corresponding test is not done, and no gate in this document may be
reported as passed in Wave 14 — Wave 14 defines the contract, it does not
run the kernel/laboratory gates (see section 8).

## 1. Toolchain, RED discipline, and the layout gate

The host-side gate that runs today on the crate alone is the numeric
foundation for every kernel gate below.

- **Exact toolchain.** The `fsring-abi` crate MUST build and test under
  `Rust 1.82` exactly and under the current stable toolchain; both MUST be
  clean. The release profile is `no_std` with `panic=abort` (no unwinding
  across FFI), as `11-rust-implementation.md` section 1 requires.
- **Lint and undefined-behavior gates.** `clippy` MUST pass with warnings
  denied on the default and all-feature configurations. `Miri` MUST pass on
  every test it supports (the pure-Rust layout, message round-trip, and
  model suites); tests that exercise real kernel FFI are out of Miri scope
  and are covered by the Driver Verifier battery in section 3 instead.
- **Generated-header gate.** The generated C header MUST be reproducible
  from the crate and byte-identical to the frozen
  `fsring-abi/include/fsring_abi.h`. In a freeze wave the check regenerates
  to a temporary file and byte-diffs it against the frozen header; it never
  overwrites the frozen artifact.
- **RED before source.** Every source change is preceded by a RED test that
  fails against the pre-change tree and passes only after the change. The
  layout, message, and validator suites are RED-authored first; the
  environment gates below are RED-authored as stated requirements even where
  the laboratory to execute them is not yet stood up.
- **Layout gate.** An exhaustive layout test MUST prove every type, constant,
  offset, and status value in both Rust and generated C: the 136-byte
  `SessionResult` prefix/tail formulas, the 96-byte `RetireMountResultV1`,
  the 48-byte `DonateBackingV2` plus path tail, the 256-byte
  `BootContextHeaderV1` header/slots, `ProviderMountRootV1`,
  `DurableChildValueV1` and every canonical child payload, the external
  change/ack bodies, the READY bodies, the volume commit counter, the
  complete `ReqId` partition, and `MAX_FILE_SIZE`. This is the golden
  cross-check that binds the Rust registry, the frozen header, and documents
  `02-transport.md` and `03-messages.md` to one set of bytes.

The host crate `cargo test` layout/message/model suite is GREEN as of the
Wave 10 freeze and is re-verified unchanged each subsequent wave; it is the
only already-passing element of this plan. Everything else in sections 2–6
is a stated requirement whose execution is pending (section 8).

## 2. Layout and platform-build matrix

The wire format is identical on every profile; only the build target,
import surface, and memory-barrier lowering differ, so each is proven
independently.

- **Cross-compiler layout compile.** The exhaustive C layout test MUST
  compile and pass under `MSVC x64` and under `clang-cl ARM64`. Passing both
  proves that no struct offset, padding rule, or enum width depends on the
  compiler or the target pointer/endianness model.
- **Per-profile PE/import audit.** The driver MUST build as three separate
  binaries — Win10 x64, Win10 ARM64, and `Win7 SP1 x64` — and each MUST pass
  a static audit of PE machine and subsystem, absence of CRT and unwind
  imports (consistent with `panic=abort`), and the exact Win7-SP1 import
  `allowlist` checked into the tree. The audit runs `llvm-readobj
  --coff-imports` and the WDK `dumpbin /imports` and rejects any import first
  exported after Windows 7 SP1 in the legacy image. This gate is the CI
  enforcement of the optional-DDI rule stated in `11-rust-implementation.md`
  section 3: an import the loader would resolve before `DriverEntry` cannot
  be present in the Win7 image.
- **Legacy load proof.** The audited `Win7 SP1 x64` artifact MUST install
  only on the declared SHA-2 servicing baseline (KB3033929/KB4474419), load,
  and exercise the legacy allocation and MDL-mapping path in a clean
  Windows 7 SP1 virtual machine. Installation on an un-serviced image MUST be
  refused, not silently degraded.
- **ARM64 barrier-disassembly gate.** An ARM64 disassembly gate MUST prove a
  hardware full barrier at both `BootContextHeaderV1` seqlock barrier sites
  (the durable identity read and publish paths of `10-lifecycle.md`
  section 3), and a static audit MUST reject every non-atomic alias to any of
  the 32 naturally aligned 64-bit words of that structure. An
  acquire/release lowered to a plain load/store on ARM64 is a gate failure,
  not a warning.

## 3. Driver Verifier battery and OS test matrix

Checked builds MUST pass the full `Driver Verifier` battery on every image in
the OS matrix before signing.

Verifier options enabled on `fsring.sys` for the checked runs:

- `Special Pool` — catches out-of-bounds and use-after-free at the allocation
  boundary immediately;
- pool tracking — proves no pool leak (unload leaves zero tracked
  allocations, see the unload check below);
- force-pending I/O — proves every dispatch tolerates `STATUS_PENDING` at any
  point;
- I/O verification (with enhanced I/O) — proves IRP construction and
  exactly-once completion, matching the completion-ownership typestate of
  `11-rust-implementation.md` section 7 and the CSQ discipline of
  `05-irp-dispatch.md`;
- `deadlock detection` — proves no lock-order violation across the acquire
  order defined in `06-locking.md`;
- security checks and IRQL checking — prove no privileged bypass and no paged
  access at `DISPATCH_LEVEL`;
- systematic `low-resource` injection — drives every fallible allocation and
  map failure path, exercising the backpressure and fail-closed behavior of
  `02-transport.md` and the fallible-allocation wrappers of
  `11-rust-implementation.md` section 5.

DMA verification does not apply and is not enabled.

**OS test matrix.** Each Verifier run and each correctness suite MUST pass on:

| Profile | Image |
|---|---|
| Legacy x64 | `Win7 SP1 x64` (Windows 7 SP1 / Server 2008 R2 SP1, serviced) |
| Modern baseline x64 | `Windows 10 1507` x64 (minimum modern baseline) |
| Modern current x64 | Windows 10 22H2 x64 and current Windows 11 x64 |
| Modern ARM64 | Windows 10 1709+ ARM64 and current `Windows 11 ARM64` |

An OS/architecture combination MUST NOT be advertised as supported until its
required suite passes on that image.

**Unload cleanliness.** After the driver unloads under Verifier, the system
MUST hold no object, MDL, section, subject, IRP, oplock, work item, or
rundown reference belonging to the driver **except** the two intended
permanent BootContext objects (`\KernelObjects\FsRingBootContext-v1` and its
lock), which survive unload by design per `10-lifecycle.md` section 3. Any
other surviving reference is a gate failure.

**Soak.** A `24-hour` `Driver Verifier` soak MUST run per release profile
with the full option set above and complete with zero bugcheck, zero leak,
and zero out-of-bounds report.

## 4. Correctness, model-checking, fuzz, and differential suites

No release proceeds with a failing correctness gate. The suites are:

- **Golden layout.** The C/Rust golden layout tests of section 1, run on x64
  and ARM64 for every ABI structure.
- **Model checking.** `Loom` model checking of ring publication/consumption,
  cancel/completion ownership, and reduced-width generation wrap, plus the
  WAIT_SQ/DRAIN_CQ role and fence interleavings of `02-transport.md`. `Loom`
  proves one consumer per cell, no skipped or double-retired cell, and no
  lost wake under weak memory ordering.
- **Stateful fuzzing.** `cargo fuzz` MUST drive every control and completion
  decoder with fully randomized fields — including malformed dirents and
  forged security descriptors — against the `validate/*` boundary and prove
  no panic, no unchecked dereference, and no integer wrap escapes into a
  bugcheck. A hostile-daemon CQE-injection fuzz MUST run against the live
  drain under Verifier for the `24-hour` window of section 3.
- **Fault injection.** Fault injection MUST fire at every allocation, map,
  cancel, completion, attach, and transaction boundary and prove reverse
  rollback with no partial durable record, no leaked count, and no provider
  visibility of a failed operation.
- **Differential semantics.** `differential` semantics tests MUST compare the
  filesystem against direct NTFS for create, open, share, delete, rename,
  hardlink, security, EOF/VDL, byte-range locks, and oplocks, driven by
  `winfsp-tests` (the user-mode behavior suite, reused independently of
  WinFsp) and the applicable `HLK` filesystem (IFS) tests. A behavioral
  divergence from NTFS that is not an explicitly documented 2.1 semantic is a
  gate failure.
- **Security suites (unconditional).** The security suites MUST run in every
  profile with no feature-off form and are never gated on any optional
  security switch: the control-device deny path (an ordinary user opening
  `\Device\FsRing` receives `ACCESS_DENIED`), the `SeAccessCheck` deny path,
  and the `QUERY_SECURITY`/`SET_SECURITY` round-trip and validation vectors,
  exactly as `09-security.md` establishes — `SECURITY` (`protocol_feature::
  SECURITY`) is selected in every successful 2.1 session, so there is no
  configuration in which the ACL/security coverage is switched off. Feature-
  profile tests additionally cover Win10 x64, Win10 ARM64, gated Win7 x64,
  the mandatory `SECURITY` selection, the paired `HOT_RESTART`/`EXACTLY_ONCE`
  bits, and every unselectable bit (REPARSE, TOKEN_DONATION, NOTIFY_NAMES,
  CASE_SENSITIVE_NAMES) proving off.
- **Cache and mapping stress.** Cache, mmap, truncate, lazy-writer, and
  memory-pressure stress MUST prove data-hash equality and zero corruption,
  and the `INVALIDATE_FILE` purge/coherency recipe of `07-cache-mm.md`
  section 8 MUST make a post-purge reader observe the daemon's new data.

## 5. Lifecycle and exactly-once restart suite

The hot-restart contract of `10-lifecycle.md` is proven by a dedicated
suite. It MUST establish:

- **Exactly-once across restart.** At least `10,000` daemon restart/attach/
  replay cycles MUST complete with no lost and no duplicate mutation. Each
  cycle kills the daemon with `-9` under I/O saturation, brings up a new
  daemon that ATTACHes in GRACE before the retained deadline, and confirms
  every pending IRP completes exactly once with no error and no loss.
- **Fresh-rings ATTACH.** The suite MUST prove the new daemon receives fresh
  rings, slots, mappings, and provider cookies, and that the old section's
  bytes are never treated as replay authority; in-flight state is
  reconstructed only from the durable journal (a `ReplayOpenV2` per retained
  OPEN, then `QueryOpV2`/`AckResultV2` per ambiguous mutation), never
  resubmitted from stale section memory.
- **Write dedupe.** With the durable journal enabled, a backend that counts
  applications MUST show each mutation applied exactly once after replay,
  deduplicated by the stable `operation_digest`.
- **PT survives GRACE.** A surviving passthrough backing handle MUST continue
  reads, flushes, and non-extending writes throughout GRACE while ring/
  metadata/allocation-changing work waits for replay, as `10-lifecycle.md`
  section 4 and `08-passthrough.md` require.
- **Deadline expiry.** Expiry of the fixed `RESTART_GRACE_TIMEOUT_MS`
  deadline without an ATTACH MUST dismount cleanly, completing every pending
  IRP with `STATUS_VOLUME_DISMOUNTED`.
- **Wrong-identity ATTACH.** An ATTACH with a wrong `MountId` or
  `BootInstanceId`, or without the dedicated service-SID `RetireToken`/
  `StateToken` authorization, MUST fail; it MUST NOT bind an epoch or disturb
  the retained deadline.
- **Unload check.** The restart storm MUST leave only the two permanent
  BootContext objects after final unload (section 3).

All items in this section are cross-referenced to `10-lifecycle.md` for the
normative state machine and identity model; this document owns only their
executable form and thresholds.

## 6. Performance gates

Benchmarks run on fixed hardware and images against direct backing NTFS and
against an equivalent WinFsp provider. They cover cached and noncached I/O,
4 KiB random I/O at QD1 and QD32, large sequential I/O, metadata operations,
mapped faults, ring mode, PT mode, and restart recovery. Initial acceptance
targets:

- PT large-sequential throughput MUST reach at least `90%` of direct backing
  NTFS;
- PT 4 KiB QD32 throughput MUST reach at least `80%` of direct backing NTFS;
- transport-only ring throughput MUST be no lower than an equivalent WinFsp
  provider, with CPU per operation no more than `10%` higher — the ring-vs-
  IOCTL-transact round-trip advantage MUST at least hold parity;
- the steady-state read/write data path MUST perform zero heap allocation and
  hold no volume-global lock (proven by O(1) indexed lookup on ring publish/
  capture, ordinary ENTER completion, grant validation, and PT page-I/O
  paths);
- the checked-in same-hardware CI baseline MUST fail on a statistically
  significant throughput regression greater than `5%` or a p99 regression
  greater than `10%`, unless an approved benchmark update explains the
  tradeoff — and a correctness or fail-closed regression always overrides any
  such performance waiver.

Every run MUST record throughput/IOPS, p50, p99, `p99.9`, CPU cycles per
operation, context switches per operation, allocations per operation, and
working set, for reproducible x64 and ARM64 microbenchmarks (empty poll,
1/64/4096-cell drains, copy sizes, and domain apply) and for the
sequential/random/metadata/notify workloads. Time sources are the request
slot submit timestamp and the ETW/TraceLogging completion latency emitted by
the provider (`11-rust-implementation.md` section 9). Results are automated,
exported to CSV, and gated against the baseline. **Performance results are
invalid if validation, durability, cache coherency, security, or error
handling differs in any way from the correctness configuration** — a "fast"
build with a relaxed validation path produces no admissible number.

## 7. Per-document DoD-to-case map and implementation order

Each subsystem document's Definition of Done maps to concrete cases here. A
feature named in a document without a corresponding case below is not done.

| Document | Principal test cases |
|---|---|
| `02-transport.md` | golden ring layout; FIFO full/empty and u32 generation wrap; multi-producer/multi-consumer full-scale correctness; cancellation and mapping/slot rundown; six-step teardown with no use-after-free; hostile-daemon CQE `cargo fuzz` for `24-hour` under Verifier |
| `03-messages.md` | golden hex for every SQE/CQE struct (kernel C and daemon Rust agree); decoder `cargo fuzz`; malformed dirent or forged SD stops safely; `SECURITY` selected in every successful session |
| `04-object-model.md` | OPEN/CLEANUP/CLOSE ordering; hardlink sharing one FCB by file id; DeletePending/DeleteOnClose matrix; retained `CLEANUP_PENDING` and `REPLAY_STATE_PAGING_ONLY` replay before the barrier |
| `05-irp-dispatch.md` | each major-function error branch (NOT_A_DIRECTORY, FILE_IS_A_DIRECTORY, dir buffer overflow, EOF and zero-length read); FastIO questionable under oplock; CSQ pend and complete-once |
| `06-locking.md` | concurrent cross rename with `deadlock detection` clean; acquire-order lint; the 2.1 lock model uses no volume-global lock and is proven only by cross-reference, not re-derived here |
| `07-cache-mm.md` | truncate-under-mmap yields `STATUS_USER_MAPPED_FILE`; lazy-writer plus concurrent reader hash equality; `INVALIDATE_FILE` purge coherency; Cc teardown |
| `08-passthrough.md` | `fio` PT sequential and 4 KiB QD32 throughput; Windows Defender full scan of a PT volume with no BSOD; no double-free MDL under Verifier; delete-to-unlink; grant/revoke storm; mmap `INVALIDATE_FILE` |
| `09-security.md` | control-device deny; `SeAccessCheck` deny path; `QUERY_SECURITY`/`SET_SECURITY` round-trip; MAPPED tier read-only; SD-validate fuzz — run unconditionally in every profile |
| `10-lifecycle.md` | hot-restart exactly-once; PT survives GRACE; write dedupe by `operation_digest`; deadline-expiry dismount; wrong `MountId`/`BootInstanceId` ATTACH fails; two-permanent-objects unload; the `10,000`-cycle restart storm |
| `11-rust-implementation.md` | no-panic CI (`clippy` + `Miri` + `checked arithmetic`); typestate double-complete MUST fail to compile; PE/import `allowlist` audit; HVCI readiness; Static Driver Verifier before signing |

**Recommended implementation order** (risk-reduction sequence, from the
original milestone plan):

1. ABI layouts, generators, golden tests, and the ring model (host-side;
   already green) — prove the wire format and round-trip numbers before any
   filesystem code exists.
2. Transport, cancellation, mapping/slot rundown, and hostile-daemon
   handling — bring up the control device, SETUP, and the ENTER loop, and
   prove real round-trip numbers.
3. Namespace and object model, transactional OPEN, security, and cleanup/
   close ordering — use the `winfsp-tests` base group as the early behavioral
   measure.
4. Cache Manager integration, size epochs, cached and noncached I/O, and
   mmap — the highest-risk area, built only after the ring path is solid.
5. Passthrough donation, forwarding, the coherency lease, and grant/revoke
   rundown — the core value, built once the FCB and forward infrastructure
   exist.
6. Hot restart and exactly-once (BootContext identity, ATTACH, durable
   replay) — completed last, on a proven base.

**Ordering principle.** Cc and PT MUST NOT be built before the ring path and
object model pass the `winfsp-tests` base group and the `HLK` create/rename
subset. Building cache or passthrough on an unproven ring path only forces
debugging of the hard layer on top of a shifting foundation.

## 8. Pending environment gates (stated, not executed in Wave 14)

Wave 14 authors this contract; it stands up no kernel, no laboratory, and no
benchmark rig. Every gate below is a **stated requirement** with a named
environment, workload, threshold, and evidence, and is explicitly **PENDING**
in Wave 14 — none of them is reported as passed. Only the host-side
`fsring-abi` `cargo test` layout/message/model suite of section 1 is green
today; nothing in this table is.

| Gate | Environment | Workload / count | Threshold | Evidence | Status |
|---|---|---|---|---|---|
| Native driver load | Test-signed `fsring.sys` on each OS-matrix image | Control device create, SETUP, first ENTER loop | Loads and reaches steady state; control-device deny holds | Boot log + Verifier-clean load | **PENDING** |
| Driver Verifier fuzz/stress | Checked build, full option set | Hostile-daemon CQE injection under saturation | Zero bugcheck, zero leak, zero OOB | Verifier report per image | **PENDING** |
| `24-hour` Verifier soak | Checked build per release profile | Continuous mixed I/O for `24-hour` | Zero bugcheck/leak/OOB over the window | Soak report per profile | **PENDING** |
| HLK filesystem (IFS) | `HLK`/HCK controller + each OS image | Applicable filesystem test packages | All required packages pass | HLK submission log | **PENDING** |
| ARM64 barrier disassembly | `clang-cl ARM64` build | Disassemble both `BootContextHeaderV1` seqlock sites | Hardware full barrier present; no non-atomic 64-bit alias | Disassembly + static-audit artifact | **PENDING** |
| Defender full-scan on PT | Windows Defender on a PT volume | Full scan of a passthrough volume with minifilter interop | Completes with no BSOD | Scan completion log | **PENDING** |
| `fio`/`diskspd` throughput | Fixed hardware vs direct backing NTFS and equivalent WinFsp | Sequential and 4 KiB QD32 PT profiles | PT sequential at least `90%`, PT 4 KiB QD32 at least `80%`; ring CPU/op within `10%`; no `5%`/`10%` CI regression | CSV + baseline diff, p50/p99/`p99.9` | **PENDING** |
| `10,000`-cycle restart storm | Live volume under saturation | At least `10,000` kill-`-9`/ATTACH/replay cycles | No lost or duplicate mutation; two-permanent-objects unload | Restart-storm counter log | **PENDING** |
| `24-hour` restart/coherency soak | Live volume under mixed load | Continuous restart, cache-coherency, and PT stress | No corruption, no leak, no hang over `24-hour` | Soak report | **PENDING** |

None of the environment gates in this section may be claimed as passing until
the corresponding laboratory result exists; asserting a pass without the
named evidence is itself a gate violation. The pending status of these gates
is the reason the document set is not yet declared release-ready, consistent
with the whole-project verification that `00-INDEX.md` still reserves for a
later wave.

## C4 evidence levels

`C4_SOURCE_COMPLETE` is established by the local gates alone: the ABI, core,
user and smoke test suites; the compile-fail runner; the three release image
builds with their import and stack audits; the `--suite c4` mutation sweep with
every mandatory mutant killed; and the two PowerShell self-tests. None of them
loads a driver.

> **Amended 2026-08-07 by slice C4.1a.** The level is **withdrawn**, not held.
> The stack audit named above passed on all three legs because it
> under-measured — two of its three frame-measurement paths produced nothing at
> all — so it was not measuring what this section credits it with. The
> corrected measurement places three roots over a frozen bound on x64 and Win7
> and one on ARM64, and the build matrix fails. A level established by a gate
> that was not measuring cannot be treated as merely pending.

`C4_NATIVE_VERIFIED` requires strictly more: one public
`fsring-control-smoke/v2` PASS from a real live run on a separately provisioned
elevated x64 host. Until that exists the level is **pending**, and no static or
host result may be read as standing in for it.

The v2 report has one closed 27-probe roster and a **derived** verdict: the
parser recompares every `expected` against its `actual` and ignores both the
per-probe outcome string and the top-level `overall`. All 27 matching with no
reason is PASS; any mismatch, a reserved infrastructure reason, or a NOT RUN
probe once a root identity exists is FAIL; only a gap before any mutation is
NOT RUN. Probe 25, `unload-transients`, is absent from every private worker
slice and is constructed by PowerShell alone from exactly three sources.

Source evidence and native evidence are kept in separate roots and are never
merged: `c4-recovery-logs` holds source-battery attempts and
`c4-recovery-native` holds live-host attempts. A source attempt can never
publish a native claim, and the separation is structural rather than a naming
convention -- the two roots have different stageability rules and different
recorder modes.
