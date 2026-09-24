# 10 - ABI 2.1 lifecycle: mount bring-up, hot restart, and durable recovery

Status: normative for FSRING ABI 2.1. This document defines the complete
mount and session lifecycle: the control-device and per-volume device-object
bring-up, the `SETUP -> ACTIVE -> GRACE -> ATTACH(BOUND_RECONCILING) -> ACTIVE`
volume state machine and its single cancel-safe `TEARDOWN` edge keyed to the
crate's `retire_mount_state`, the `BootContextHeaderV1` seqlock-published
durable identity and the two permanent kernel objects that survive driver
unload, the fixed `RESTART_GRACE_TIMEOUT_MS` grace deadline, the fresh-rings
ATTACH model in which the retired section's bytes are never replay authority,
the `ReplayOpenV2`/`QueryOpV2`/`AckResultV2` exactly-once replay orchestration
over the durable journal, and the authenticated `RetireMountV1`/
`RetireMountResultV1` retirement and teardown handshake. It supersedes the 2.0
lifecycle draft in full; no 2.0 volume-GUID identity, registry-configurable
grace value, ring re-map/resubmit replay flow, or opcode/struct name survives
into 2.1.

The authoritative registries for this document are the unpacked crate sources
`fsring-abi/src/control/boot.rs` (`BOOT_CONTEXT_MAGIC`, `BOOT_CONTEXT_VERSION`,
`BootContextHeaderV1`, `BootContextSlotV1`, `BOOT_CONTEXT_SECTION_NAME`,
`BOOT_CONTEXT_LOCK_NAME`, the checked publication/mount-sequence/load-generation
and `mount_id_from_burned_sequence` helpers), `control/session.rs`
(`RetireMountV1`, `RetireMountResultV1`, `AttachV1`, `SessionResultV1`,
`MountId`, `BootInstanceId`, `RetireToken`), `control/mod.rs`
(`retire_mount_state`, `retire_mount_action`, `BOUND_RECONCILING`, the
`ioctl_function`/`status` control registries, `CONTROL_DEVICE_SDDL`,
`FSRING_MOUNT_CONTROL`), `durable/metadata.rs` (`ProviderMountRootV1`,
`DurableChildValueV1`, `provider_mount_root_state`, `LatestProcessedV1`,
`RetireReceiptV1`), `durable/payloads.rs` (`OpenRecoveryPayloadV1`,
`PrepareRecoveryPayloadV1`, `JournalStateV1`, `operation_digest`,
`volume_commit_sequence`, `committed_result_kind`), `msgs/recovery.rs`
(`ReplayOpenV2`, `QueryOpV2`, `AckResultV2`, `query_op_state`,
`journal_version`, `query_op_required_flags`), `features.rs` (the
`protocol_feature::HOT_RESTART`/`EXACTLY_ONCE` pair, `SECURITY`,
`BASE_REQUIRED_PROTOCOL_MASK`, `select_features_v21`), `limits.rs`
(`RESTART_GRACE_TIMEOUT_MS`, `MAX_INFLIGHT`, the retained-open caps), and
`layout.rs` (the `REPLAY_OPEN` opcode number; the crate carries the
`ReplayOpenV2` state flag as a plain `state_flags` `u64`, and the named value
`REPLAY_STATE_PAGING_ONLY = 0x0000000000000001` is defined normatively in
`02-transport.md`/`04-object-model.md`), together with the frozen generated
header `fsring-abi/include/fsring_abi.h`
(SHA-256 `7BC16346475E8BD786306368EF90D80E6F3009B8CC44ADC11CA6DFD60509AB2D`).
Every size, alignment, offset, constant, and state value below is transcribed
from that registry and the already-normative `02-transport.md`,
`03-messages.md`, `04-object-model.md`, `05-irp-dispatch.md`,
`08-passthrough.md`, and `09-security.md`; if prose, generated archives, or an
implementation disagree with those unpacked sources, the unpacked sources win.
This document cites those wire byte tables by filename and does not re-derive
them.

A closed set of identifiers below name WDK/kernel-driver concepts that the
`fsring-abi` crate does not and will never carry, because the crate is the
`no_std` wire-format and validation library, not the driver itself:
`\Device\FsRing`, `IoCreateDeviceSecure`, `IoRegisterFileSystem`,
`IRP_MN_MOUNT_VOLUME`, `IRP_MN_VERIFY_VOLUME`, `FSCTL_DISMOUNT_VOLUME`,
`VOLUME_DISMOUNTED`, the FastFat-style virtual-disk device object (VDO), volume
control block (VCB), and volume parameter block (VPB) mount mechanics,
`PsSetCreateProcessNotifyRoutineEx`, `KeQueryUnbiasedInterruptTime`,
`SeAccessCheck`, `SeCaptureSubjectContextEx`, `RtlLengthSid`, the driver-owned
cancel-safe queue (`IO_CSQ`), `IoCompleteRequest`, and the S3/S4/Fast-Startup
power vocabulary. Each is transcribed from
`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md`
section 6 (the authenticated control IOCTL and mount-lifecycle registry) and
section 12 (the durable digest and committed-result recovery), or from
`docs/superpowers/specs/2026-07-15-fsring-abi-v2-design.md` section 10 (the
original hot-restart and exactly-once model the corrective amendment does not
restate) -- never from the superseded 2.0 draft prose without independent
verification against those sources.

RFC 2119 keywords ("MUST", "MUST NOT", "SHOULD", "MAY") are used as defined in
RFC 2119.

## 1. Device objects and mount bring-up

FSRING presents three kinds of kernel object, and the lifecycle contract begins
at driver load.

- **Control device.** At `DriverEntry` the driver creates a single control
  device object with the restrictive security descriptor `CONTROL_DEVICE_SDDL`
  (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), whose meaning and per-IOCTL authorization
  are defined by `09-security.md` section 1 and are not restated here. The
  control device carries no filesystem stack; it accepts only the authenticated
  control IOCTL registry `ioctl_function` (`SETUP = 0x800`, `ENTER = 0x801`,
  `ATTACH = 0x802`, `DONATE_BACKING = 0x803`, `DONATE_SECURITY_CONTEXT = 0x804`,
  `DETACH = 0x805`, `RETIRE_MOUNT = 0x806`), every one `METHOD_BUFFERED`. The
  wire schemas and completion-status allowlists for these IOCTLs are defined by
  `03-messages.md` and `09-security.md`; this document defines only their
  lifecycle sequencing.

- **Per-volume device pair.** A successful `SETUP` (`SetupRequestV1 ->
  SessionResultV1`, the schema in `03-messages.md`) brings up one virtual-disk
  device object (VDO) and, on `IRP_MN_MOUNT_VOLUME`, one mounted volume device
  object with its volume control block (VCB) and volume parameter block (VPB).
  The crate carries no named constant for these FastFat-style VDO/VCB/VPB mount
  mechanics; they are named here as driver-behavior provenance from the original
  design section 10 and corrective-design section 6 and MUST follow the
  documented Windows filesystem-driver mount pattern. `IRP_MN_VERIFY_VOLUME`
  succeeds while the mount is live because the virtual volume has no removable
  media; it fails the volume only when the mount has already entered `TEARDOWN`.

`SETUP` performs, in this order, three lifecycle-visible acts that later
sections depend on:

1. it burns a new `MountId` from the durable BootContext mount-sequence counter
   (section 3): the header's `mount_sequence` is advanced by
   `checked_next_mount_sequence`, and `mount_id_from_burned_sequence` composes
   `MountId { lo = burned mount_sequence, hi = nonzero random high word }`. A
   zero mount sequence or zero random high word is rejected. The `MountId` is
   routing identity, not authentication;
2. it creates the section and rings for the session (the section/ring geometry
   and the `SessionResultV1` view descriptors are defined by `02-transport.md`);
   and
3. for a restart-eligible mount it publishes the durable `ProviderMountRootV1`
   for the new `MountId` and starts `session_epoch = 1` (section 3, section 4).

`session_epoch` starts at exactly 1 at `SETUP`; each subsequent successful
ATTACH publishes exactly `old + 1`, and epoch exhaustion terminalizes the mount
rather than wrapping. The daemon assigns a drive letter or mount point out of
band after `SETUP`; that step is outside the kernel ABI.

## 2. Volume state machine

The mount runs one closed state machine. The prose states below are one
vocabulary with the crate's durable classification `retire_mount_state`, which
is exactly what `RetireMountResultV1.mount_state` reports to an authenticated
`RETIRE_MOUNT` QUERY (section 7):

```text
MOUNTING --> ACTIVE --> GRACE --> ATTACH / BOUND_RECONCILING --> ACTIVE
   |            |          |                    |                   |
   +------------+----------+--------------------+-------------------+--> TEARDOWN --> dismounted
```

| Prose state | `retire_mount_state` | Meaning |
|---|---|---|
| MOUNTING | (slot STAGING; QUERY answers `DEVICE_BUSY`) | `SETUP` in progress; not yet published `ACTIVE` |
| ACTIVE | `ACTIVE = 2` | ordinary session; rings and dispatch run normally |
| GRACE | `GRACE = 3` | daemon absent; restart deadline armed (section 4) |
| ATTACH / BOUND_RECONCILING | `BOUND_RECONCILING = 5` | a new epoch is bound and reconciling over fresh rings (section 5, section 6) |
| TEARDOWN | `TERMINAL = 4`; then `ABSENT = 1` after retirement ACK | cancel-safe terminal path (section 7) |

`retire_mount_state` is `ABSENT = 1, ACTIVE = 2, GRACE = 3, TERMINAL = 4,
BOUND_RECONCILING = 5` (a `u16`, from `control/mod.rs`). `ABSENT` is reported
when no owned slot holds the queried `MountId`; the transient slot states
STAGING and TERMINALIZING answer `DEVICE_BUSY` rather than exposing a
half-built or half-torn mount.

Every IRP dispatch checks the entry state before it acts (the per-opcode
dispatch discipline is defined by `05-irp-dispatch.md`):

- **ACTIVE** runs the operation normally over the live rings.
- **GRACE** pends new ring-path work on the driver-owned cancel-safe queue
  until an ATTACH admits the work or the grace deadline expires; a surviving
  passthrough (PT) backing handle continues its own data path throughout GRACE
  (section 4, section 6). No new ring/metadata/allocation-changing work is
  submitted while GRACE holds, because there is no daemon to consume it.
- **BOUND_RECONCILING** admits only recovery control traffic; ordinary
  application requests remain fenced until the atomic transition to ACTIVE
  (section 5, section 6).
- **TEARDOWN** completes outstanding IRPs and dismounts; new file IRPs complete
  `VOLUME_DISMOUNTED` (section 7).

A restart mount, clean DETACH, grace expiry, protocol abort, irreversible
teardown, and driver unload all contend on a single lifecycle terminal-owner
compare-and-swap, so exactly one actor wins the transition out of a live state.

## 3. BootContext durable identity

Same-boot restart identity lives in a durable, permanently named section, not
in any per-volume GUID. The wire image is `BootContextHeaderV1` (256/64) plus
`BOOT_CONTEXT_SLOT_COUNT = 64` records of `BootContextSlotV1` (256/64); the used
prefix `BOOT_CONTEXT_USED_BYTES = 16640` sits inside the
`BOOT_CONTEXT_SECTION_BYTES = 65536` section. `BootContextHeaderV1.magic` is
`BOOT_CONTEXT_MAGIC = 0x4342474E49525346` ("FSRINGBC" little-endian) and
`format_version` is `BOOT_CONTEXT_VERSION = 1`. The full field tables for both
records are carried by `02-transport.md`; this section states only their
lifecycle role.

Two kernel objects back that section and are the two **permanent** objects the
driver leaves behind:

- `\KernelObjects\FsRingBootContext-v1` (`BOOT_CONTEXT_SECTION_NAME`), the
  BootContext section itself; and
- `\KernelObjects\FsRingBootContextLock-v1` (`BOOT_CONTEXT_LOCK_NAME`), its
  permanent named `SynchronizationEvent` publication lock.

The lock object is not a mutant or semaphore. It is created initially signaled
and is acquired by the fixed, bounded, non-alertable signaled-to-nonsignaled
event protocol in `02-transport.md` section 10.10. Ownership is an affine guard
released exactly once; recursive acquisition, abandonment recovery, timeout
stealing, and force-setting are forbidden.

These two objects MUST survive driver unload and reload within one boot: they
are created once per boot, are never destroyed by `TEARDOWN` or DETACH, and a
clean driver unload MUST leave exactly these two objects and nothing else (the
unload-cleanliness check is a release gate in `12-test-plan.md`). Within one
boot the driver reattaches to the existing objects on reload; a cold boot,
S4/hibernate resume that discards the section, or Fast Startup that does not
preserve it yields a fresh section with a new per-boot identity.

The header is seqlock-published: `header_sequence`, `mount_sequence`, and
`load_generation` are even-numbered publication counters that begin at
`BOOT_CONTEXT_INITIAL_SEQUENCE = 2` and advance by `BOOT_CONTEXT_SEQUENCE_STEP =
2` under checked arithmetic, and `mount_sequence`/`load_generation` each carry a
complement field so a reader can reject a torn or wrapped record. A `SETUP`
publication is 5 record writes, an ATTACH publication is 4, a startup-retire is
2, and a bare header refresh is 1; every publication count is checked so it
cannot exhaust or wrap the sequence. `init_state` is `EMPTY = 0, INITIALIZING =
1, READY = 2`; each slot's `state` is `FREE = 0, STAGING = 1, LIVE = 2,
TERMINALIZING = 3, TERMINAL = 4`.

The durable identity a mount carries is the pair `MountId` + `BootInstanceId`:

- `BootInstanceId` is the current per-boot random identity in
  `BootContextHeaderV1.boot_instance_id`; every authenticated result, including
  `RetireMountResultV1` and `SessionResultV1`, returns the current nonzero
  `BootInstanceId`.
- `MountId` is burned once per `SETUP` from the mount-sequence counter (section
  1) and is never reused inside one `BootInstanceId`.

This pair supersedes any per-volume GUID: the crate carries no volume-GUID
field, and no lifecycle decision keys on one. A `MountId` identifies exactly one
boot-local mount incarnation within its `BootInstanceId`. Only after an
authenticated `SessionResult`/`RetireMountResult` reports a **different**
`BootInstanceId` is there proof that no prior-incarnation application IRP or
kernel cache result survives; within the same `BootInstanceId`, including a
driver reload, reboot inference is forbidden.

## 4. Hot restart and the fixed grace deadline

Hot restart lets a daemon crash or upgrade while a new daemon reattaches to the
same mount, so application I/O is suspended during a bounded grace window rather
than failed. It is the paired feature `HOT_RESTART` + `EXACTLY_ONCE`
(`protocol_feature` bits 2 and 3): `select_features_v21` requires the two bits
to be offered and required together, and clears both unless the `SETUP` caller
presents the dedicated service SID (below). A mount that did not select the pair
has no GRACE state at all: daemon death tears it down immediately through the
`TEARDOWN` path.

**Authorization is the dedicated service SID.** Selecting the pair requires the
caller's primary token to contain exactly one enabled, non-deny-only *dedicated*
Windows service SID of the byte-exact shape `S-1-5-80-a-b-c-d-e` (revision 1,
`SECURITY_NT_AUTHORITY`, subauthority count 6, first subauthority 80), with
`RtlLengthSid = 32`; the generic `S-1-5-80-0` and every other `S-1-5-80-*` shape
are excluded, not counted. The identical parser and predicate gate `SETUP`,
ATTACH, and both `RETIRE_MOUNT` actions; there is no LocalSystem or
Administrators bypass. If the predicate does not yield exactly one such SID, the
runtime mask clears `HOT_RESTART` + `EXACTLY_ONCE` and any request that requires
the pair fails `ACCESS_DENIED = 0xC0000022`. The full access-check construction
(`FSRING_MOUNT_CONTROL = 0x00000001`, the one-SID protected DACL, the
`SeCaptureSubjectContextEx`/`SeAccessCheck` sequence) is defined by
`09-security.md` and is not restated here; note only that `SECURITY` is required
in every successful ABI 2.1 session (`BASE_REQUIRED_PROTOCOL_MASK`), so no
lifecycle behavior is gated behind an optional security switch.

**Daemon-death detection.** The driver detects daemon loss through
control-channel cleanup and process ownership (a clean control-handle cleanup or
the process-exit notification). On detection the driver, under the single
lifecycle terminal-owner CAS, moves the mount to GRACE, retains the current
`session_epoch` as the exact ATTACH predecessor, and immediately quarantines
that epoch's shared section so that no later completion can reactivate it. The
epoch advances exactly once, at a successful ATTACH commit as specified below;
the old mappings are released only after kernel rundown and are never reused
(section 5).

**The grace deadline is fixed.** `RESTART_GRACE_TIMEOUT_MS = 30000` (30 seconds,
from `limits.rs`) is fixed in ABI 2.1 and is **not** daemon- or
registry-configurable. There is no configurable grace value and no per-daemon
override. Entering GRACE snapshots a checked unbiased deadline
(`KeQueryUnbiasedInterruptTime() + 300000000` in 100-ns units), so
sleep/hibernate (S3/S4) does not consume restart time and a wall-clock
adjustment can neither extend nor shorten it. A timer only schedules the
passive lifecycle owner; the owner and every QUERY/ATTACH/reconciliation entry
recheck the same absolute deadline. Expiry terminalizes the mount through the
one terminal-owner path; it is never an IOCTL timeout, and no completion after
expiry can reactivate the mount.

**Passthrough survives GRACE.** A backing `FILE_OBJECT` donated through
`DONATE_BACKING` (the PT contract in `08-passthrough.md`) is referenced by the
kernel independently of the daemon, so during GRACE a surviving PT handle
continues reads, flushes, and non-extending writes while its coherency lease and
PT epoch remain valid. Ring-path work, metadata operations, and writes that
change allocation, end-of-file, or valid-data length wait for a successful
ATTACH and replay. PT child data I/O completed entirely by the kernel is never
replayed as a provider mutation (section 6).

## 5. ATTACH: fresh rings, never stale reuse

A new daemon reattaches with the ATTACH IOCTL (`AttachV1 -> SessionResultV1`;
`AttachV1` is 56/8, field table in `03-messages.md`). `AttachV1` carries
`prior_session_epoch`, `requested_features`, `mount_id`, `journal_version`, and
zero `flags`. ATTACH is legal only while the mount is in GRACE and only before
the retained grace deadline; a mount that is not in GRACE, or whose deadline has
passed, fails (`INVALID_DEVICE_STATE = 0xC0000184` or `OBJECT_NAME_NOT_FOUND =
0xC0000034` as appropriate). ATTACH also requires the exact `MountId`, a
`prior_session_epoch` equal to the retained current epoch, `requested_features`
equal to the retained selected set, `journal_version = 1`, and membership of the
same dedicated service SID in the new requestor process primary token. A wrong
`MountId`, a stale epoch, a changed feature set, or a missing SID is refused;
`MountId` is routing, not authentication, and the service-SID access check plus
the retained-identity match are what authorize the bind.

ATTACH must win its epoch/binding commit before the deadline: it publishes
exactly `old + 1` as the new `session_epoch`, binds the new handle and views,
and moves the mount to `BOUND_RECONCILING`. The **same original grace deadline
remains armed** while the new epoch is `BOUND_RECONCILING`; the bind does not
restart or extend the clock, and all open, PT, and external replay barriers
(section 6) MUST complete before that same deadline for the atomic transition to
ACTIVE. The IOCTL may return its mappings after the binding commit because the
daemon needs them to reconcile; ATTACH `SUCCESS` means "bound", not "ordinary
I/O admitted".

The new daemon receives **fresh rings**, slots, mappings, and provider cookies.
This is the load-bearing correction the 2.0 draft got wrong: the retired
section is quarantined, and old shared-memory bytes are never replay authority.
The kernel does not re-map the old section into the new daemon and does not
resubmit in-flight SQEs from stale slot memory. Instead, the kernel retains its
own canonical request state outside the old section: locked application MDLs may
be re-mapped into the new session under new mapping rundown, and any slot data
the kernel still owns is copied into freshly allocated slots of the new session.
In-flight and retained work is reconstructed from the durable journal
(`ProviderMountRootV1` plus the recovery records of section 6), a
`ReplayOpenV2` per retained OPEN and then `QueryOpV2`/`AckResultV2` per
ambiguous mutation, and never from the retired section's bytes.

Identity and authorization for the reconciliation are proven by the
`MountId` + `BootInstanceId` pair under the service-SID HMAC tokens described in
section 7 (`RetireToken` / `StateToken`); the SDK refreshes its durable
`ProviderMountRootV1` to `RECOVERING` at exactly the bound epoch and
`StateToken` before it may treat the mount as reconciling.

## 6. Durable replay orchestration and exactly-once mutation

Exactly-once mutation means each logical provider mutation is applied exactly
once across any number of daemon deaths and reattaches; physical media
durability remains governed by FLUSH/FUA and the backing filesystem. It rests on
a durable journal keyed to a stable `operation_digest` and driven by the
version-2 recovery control requests.

### 6.1 The durable journal

The SDK stores one canonical `ProviderMountRootV1` (160/8) per `MountId` whose
`state` is `provider_mount_root_state` `ACTIVE = 1, RECOVERING = 2, RETIRING =
3`. Every ordinary recovery record is a child under that root's 32-byte
`MountId`/`BootInstanceId` prefix, wrapped (except for the fixed schemas) in a
`DurableChildValueV1` (88/8) whose `identity_digest` and `payload_digest` bind
the key and payload. The recovery payloads this document orchestrates are:

- `OpenRecoveryPayloadV1` (152/8) -- one retained OPEN per `kernel_open_id`,
  state LIVE or CLEANED;
- `PrepareRecoveryPayloadV1` (184/8) -- one PREPARED create/overwrite/supersede
  transaction; and
- `JournalStateV1` (64/8), whose `operation_digest` sits at offset 32 and whose
  `state` is PREPARED or COMMITTED, plus the committed-result records
  (`committed_result_kind`) that hold the exact replayable outcome.

The full byte tables for these records live in `02-transport.md` and
`03-messages.md`; this document does not re-derive them. `query_op_state`
(`INVALID = 0, NOT_FOUND = 1, PREPARED = 2, COMMITTED = 3`) and `journal_version`
(`NONE = 0, V1 = 1`) come from `msgs/recovery.rs`.

### 6.2 The PREPARED / COMMITTED / ACK contract

For a mutation to have any ambiguous effect the provider MUST first durably
record `PREPARED(op_id, operation_digest, prerequisites)`; before returning
success it MUST atomically transition the exact bundle to
`COMMITTED(op_id, complete result)` including the backing effect,
`volume_commit_sequence`, reservations, accounting, and durable result; and the
kernel MUST acknowledge before the provider prunes the committed bundle. Reusing
an `op_id` with a different `operation_digest` is a protocol fault, detected
before replay can duplicate or misapply a mutation. A provider that cannot make
its mutation and its committed result atomic (or provide identity-based
reconciliation) MUST NOT advertise `HOT_RESTART`/`EXACTLY_ONCE`.

`volume_commit_sequence` is one mount-wide `u64` transaction order shared by
every successful COMMIT_OPEN, WRITE, MUTATE, RESIZE, and external DIR_CHANGE
(child kind `VOLUME_COMMIT_COUNTER`, allocated only in an in-effect
transaction). Zero is invalid; each committed transaction allocates a value
strictly greater than every prior value; the counter never wraps, and the mount
is retired before another state-changing transaction if `u64::MAX` has been
allocated. Ordinary completion, durable result, QUERY_OP replay, and any
notification for the same transaction repeat its exact original value.

### 6.3 Reconstruction while BOUND_RECONCILING

While the mount is `BOUND_RECONCILING`, the kernel pumps recovery control
traffic onto the fresh rings, which the daemon services through the `ENTER`
IOCTL (`EnterRequestV1`). These retained recovery publications are the only
traffic legal during `BOUND_RECONCILING`; new ordinary semantic requests remain
banned until ACTIVE.

1. **Replay opens.** For each retained OPEN the kernel issues a `ReplayOpenV2`
   (104/8) -- the 80-byte V1 prefix plus a reply `BufferRef`. Replay is **per
   CCB, not merely per FCB**: the provider reconstructs a fresh session-local
   `provider_open_cookie` from the kernel-supplied open identity and state in
   the `OpenRecoveryPayloadV1`, rather than from any process-local memory of the
   dead daemon. A LIVE handle with no pending lifecycle transition MUST become
   replay-ready in the exact epoch. A retained `CLEANUP_PENDING` open (including
   its `DRAIN_REPLAY` and predecessor-recovery substates) MUST reach
   CLEANED/CLEANUP_DONE and then paging-only readiness while its stream gate
   stays open; a CLEANED handle awaiting native CLOSE MUST complete a
   `REPLAY_STATE_PAGING_ONLY = 0x0000000000000001` replay before ACTIVE. The
   object-model rules for these open states and the `REPLAY_STATE_PAGING_ONLY`
   state flag are defined by `04-object-model.md` and `05-irp-dispatch.md`; a
   zero-flag replay after CLEANED, a `REPLAY_STATE_PAGING_ONLY` replay before
   CLEANED, and any replay after complete ABSENT are protocol faults.

2. **Resolve ambiguous mutations.** For every mutation the kernel could not
   prove committed, it issues `QueryOpV2` (104/8 -- the 56-byte V1 prefix plus
   reply and committed-result `BufferRef`s) carrying the retained `op_id` and
   `operation_digest`. The provider answers strictly from its durable bundle:
   `NOT_FOUND`, `PREPARED`, or the exact `COMMITTED` result; it MUST NEVER
   execute a committed mutation again. If a cancellation is pending, the kernel
   sends `QueryOpV2` with the `ABORT_IF_PREPARED` required flag
   (`query_op_required_flags`), and the provider atomically deletes and refunds a
   PREPARED bundle (reporting `NOT_FOUND`) while leaving a COMMITTED bundle
   untouched (reporting `COMMITTED`). A `PREPARED` result is resumed as that
   exact transaction; a `COMMITTED` result is validated field-for-field against
   the retained request (excluding only the session-local
   `provider_open_cookie`) and applied to kernel state exactly once.

3. **Acknowledge.** After the kernel applies a verified `COMMITTED` result it
   reserves and fills `AckResultV2` (56/8 -- the 24-byte V1 prefix plus the exact
   32-byte `operation_digest`) and publishes it so the provider may atomically
   delete and refund the exact matching bundle. `AckResultV1` (an `op_id`
   without a digest) is illegal in ABI 2.1 because an `op_id` alone cannot
   authenticate which durable semantic operation may be pruned. `AckResultV2` is
   idempotent only when the complete bundle is already absent, so a lost
   acknowledgement can be retried without leaving a bearer tombstone.

Reconstruction preserves `volume_commit_sequence` order, per-CCB sequence, and
the CLEANUP/CLOSE barriers, and preserves the stable `kernel_open_id`, FCB
identity, LinkId identity, disposition, access, and share state carried in the
recovery payloads. The retained-open caps make this finite: at most
`MAX_RETAINED_OPENS_PER_RING = 4096` open-lifecycle nodes queue on one ring
(with per-mount and global caps above that), so reconciliation cannot grow
unbounded, and `MAX_INFLIGHT = 16777023` bounds journaled operations. The finite
bound is a deadlock/resource guarantee, not a promise that a stalled provider
answers within the 30-second deadline; failing to finish before expiry takes the
safe `TEARDOWN` path (section 7), never a deadline extension.

### 6.4 Ordinary-path exactly-once confirmation

The same handshake protects the live ACTIVE path. When `EXACTLY_ONCE` is
selected, an ordinary successful COMMIT_OPEN, WRITE, or MUTATE CQE is only a
*candidate* result: before applying it the kernel snapshots the candidate, runs
its grant rundown, and issues `QueryOpV2` on the authenticated live session with
the same `op_id` and `operation_digest`, requiring the durable read-back to
match field-for-field. A crash before either the SETUP or ATTACH root commit
leaves no ordinary provider side effect and the kernel fences to GRACE; a crash
after an ATTACH commit is recovered by `ACTIVE`-to-`RECOVERING`. Session loss
alone is never acknowledgement.

## 7. RETIRE_MOUNT and the teardown path

Retirement is the authenticated same-boot handshake that observes and finally
retires a mount slot. `RETIRE_MOUNT` (`0x806`) is legal only on a fresh unbound
root control handle and uses `RetireMountV1` (48/8: `header`, `mount_id`,
`token` of type `RetireToken`, `action`, zero `reserved`) with
`retire_mount_action` `QUERY = 1, ACK = 2`. Both actions require the dedicated
service SID predicate and `SeAccessCheck` against the exact one-SID descriptor
(`09-security.md`).

**QUERY** (`action = QUERY`, zero token, output capacity exactly 96) returns
`RetireMountResultV1` (96/8: `header`, `mount_id`, `boot_instance_id`,
`proof_token` of type `RetireToken`, `latest_session_epoch`,
`selected_features`, `journal_version`, `mount_state:u16`, zero `flags:u16`,
`reserved:u64`). A nonzero input `MountId` is an exact state query; a zero
`MountId` is a recovery inventory that selects the lowest-mount-sequence GRACE
slot, else the lowest TERMINAL slot, and never returns ACTIVE or
`BOUND_RECONCILING`. The result's `mount_state` is one of the
`retire_mount_state` values; ACTIVE/`BOUND_RECONCILING`/GRACE/TERMINAL carry the
exact retained epoch, features, and journal version, while ABSENT zeroes those
fields. An `ID` owned by a different SID is `ACCESS_DENIED`; a STAGING or
TERMINALIZING slot is `DEVICE_BUSY`.

**Proof tokens.** Each result carries a 128-bit proof token computed under the
per-boot key that never leaves the section:

```text
RetireToken = Truncate128(HMAC-SHA256(per_boot_retire_key,
  "FSRING-RETIRE-v2\0" || BootInstanceId || MountId ||
  service_sid_length || canonical_binary_service_sid))         // TERMINAL only

StateToken  = Truncate128(HMAC-SHA256(per_boot_retire_key,
  "FSRING-MOUNT-STATE-v2\0" || BootInstanceId || result_MountId ||
  mount_state || flags || latest_session_epoch ||
  selected_features || journal_version ||
  service_sid_length || canonical_binary_service_sid))         // every other state
```

The `StateToken` is provider audit evidence and is never accepted as an ACK
token; the `RetireToken` proves TERMINAL. The SDK drives its
`ProviderMountRootV1` transitions off these tokens: a pre-ATTACH exact GRACE
refreshes ROOT `RECOVERING` at the returned epoch/`StateToken`; a post-binding
`BOUND_RECONCILING` refreshes it to the bound epoch; a post-barrier ACTIVE
commits ROOT `ACTIVE`; an exact TERMINAL commits ROOT `RETIRING` at that
epoch/`RetireToken`.

**ACK** (`action = ACK`, nonzero `MountId`, zero reserved, no output, the exact
`RetireToken`) changes a restart slot from TERMINAL to FREE; `MountId` is never
reused in that `BootInstanceId`. Constant-time token equality makes a lost-reply
ACK idempotently successful without turning the receipt into a bearer token. A
malformed action/token shape is `INVALID_PARAMETER`; a SID/access mismatch or a
well-shaped incorrect token is `ACCESS_DENIED`.

**DETACH versus BOUND_RECONCILING and teardown.** A clean DETACH first acquires
the mount's cancel-safe exclusive lifecycle-admission gate and closes all new
filesystem/journal/ACK admission; if the retained-blocker count is nonzero it
reopens admission and returns `DEVICE_BUSY`. A DETACH that observes a
`BOUND_RECONCILING` mount returns `DEVICE_BUSY` **without disturbing that mount's
retained grace deadline or barriers**; one that observes TERMINAL, GRACE, or a
noncurrent epoch returns `INVALID_DEVICE_STATE`. A clean DETACH is also
`DEVICE_BUSY` while any retained request is PREPARED/COMMITTED or any
`AckResultV2` is outstanding, and it succeeds only after the journal handshake
drains.

The mount reaches `TEARDOWN` (the single cancel-safe terminal edge, prose state
mapping to `retire_mount_state` `TERMINAL = 4`) in exactly these ways:

- **grace expiry.** The deadline of section 4 passes without a winning ATTACH;
  the terminal owner terminalizes the already-bound epoch, drains all
  mappings/PT/IRPs, and dismounts, completing outstanding file IRPs
  `VOLUME_DISMOUNTED`. Expiry after an ATTACH `SUCCESS` still terminalizes the
  bound epoch through the same one path.
- **disabled hot restart.** A mount that never selected the `HOT_RESTART` /
  `EXACTLY_ONCE` pair tears down immediately on daemon death, with no GRACE.
- **protocol fault.** A malformed or contradictory replay answer, a digest
  mismatch, an impossible journal-state transition, or a COMMITTED result for a
  different operation quarantines the session (corrective-design section 13
  session-protocol-fault classification) and enters the same cancel-safe
  `TEARDOWN` path rather than guessing an outcome.

Terminal retirement removes the durable rows only through the authenticated
receipt/deletion/ACK handshake above; if an empty-prefix lost `SETUP` is first
discovered only after GRACE has already expired to TERMINAL, the SDK commits the
receipt-only retirement (`RetireReceiptV1`) with ordinary quota full and never
performs a late root/counter bootstrap. No timeout or failed ATTACH alone
authorizes pruning a PREPARED or COMMITTED bundle.

## 8. Definition of done (stated, not executed in Wave 14)

The following behaviors define lifecycle completeness. Wave 14 states them as
requirements; the environment-bound stress and durability runs are executed and
evidenced by `12-test-plan.md`, which owns their environment/workload/threshold
matrix.

1. **Exactly-once under saturation.** Kill (`-9`) the daemon while I/O is
   saturated, then ATTACH a new daemon within GRACE: every pending application
   IRP completes exactly once with no loss and no spurious error. Reconstruction
   uses fresh rings and the durable journal (`ReplayOpenV2` per retained OPEN,
   then `QueryOpV2` -> `AckResultV2` per ambiguous mutation), never a resubmit
   from the retired section.
2. **Passthrough continuity.** Read and write on a PT file continue throughout
   GRACE without error, proving the PT data path (`08-passthrough.md`) does not
   depend on the daemon.
3. **Write dedupe.** A mutation whose committed CQE was lost before daemon death
   is applied exactly once after replay: the kernel's `QueryOpV2` on the stable
   `operation_digest` observes `COMMITTED` and never reapplies it, and the
   backend mutation counter increments exactly once.
4. **Clean deadline expiry.** With no ATTACH before `RESTART_GRACE_TIMEOUT_MS`,
   the mount dismounts cleanly through `TEARDOWN`, completing outstanding file
   IRPs `VOLUME_DISMOUNTED`.
5. **Identity enforcement.** An ATTACH with a wrong `MountId` or against the
   wrong `BootInstanceId` fails; a stale `prior_session_epoch`, a changed
   feature set, or a missing service SID is likewise refused.
6. **Restart storm and unload cleanliness.** At least 10,000 daemon
   restart/attach/replay cycles complete with no lost or duplicate mutation, and
   a subsequent clean driver unload leaves exactly the two permanent BootContext
   objects (`\KernelObjects\FsRingBootContext-v1` and
   `\KernelObjects\FsRingBootContextLock-v1`) and nothing else. Both checks are
   run and evidenced in `12-test-plan.md`.

A lifecycle behavior without a corresponding case in `12-test-plan.md` is not
done.

## C4 session fence and teardown

CLEANUP, process loss, protocol abort, and unload all reach the same bounded
six-stage fence through one symbol, `fsring_session_fence`. The stage order is
load-bearing:

1. close session admission, signal every pending ENTER, wait the control
   rundown — the signal precedes every wait, or the wait blocks on the very
   dispatches the fence exists to release;
2. remove **producer-writable** aliases in reverse and wait producer/mapping
   capture rundown;
3. acquire consumers in increasing ring order;
4. drain bounded stable prefixes and retire credits;
5. release consumers, queue installed work, wait pending and owners;
6. release the remaining read-only aliases in reverse, free partial and master
   MDLs and the system view, release the captured process, dismount and delete
   devices, release transient backing.

The read-only alias, every MDL, the kernel system view, and the referenced
process all survive to stage 6. That is what lets stage 3-4 still read the CQ.
An alias already absent at its assigned stage is recorded as a native cleanup
failure rather than silently accepted, and a failed step does not stop the
fence: stopping halfway is how a mapping outlives its session.

The process-exit callback claims its preallocated terminal and runs the same
bounded fence before the last exiting thread returns, so address-space teardown
cannot erase the retained stage-6 aliases first. It allocates nothing, issues no
user callback, and waits on no daemon progress.

Three refusals are permanent rather than retried, and each keeps every authority
it holds. A publication fail-stop parks the pending slot behind a packet that
blocks drain, delete and unload. A fence fail-stop parks the fence with its
obligations undischarged. A delete fail-stop parks the deletion with the
complete mutable cross-product unconsumed. None of them is a checkpoint state,
none of them decays into success, and each reaches a typed blocked-safe
rendezvous rather than a completed result.
