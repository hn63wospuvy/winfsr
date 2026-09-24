# 08 - Passthrough (PT)

Status: normative for FSRING ABI 2.1. This document defines the complete
production-passthrough contract: the `DONATE_BACKING` control-IOCTL
protocol that opens and isolates a backing `FILE_OBJECT`, the two named
state machines that govern backing-donation lifecycle and per-route
forwarding and how they compose, the forward engine that carries
READ/WRITE/LOCK_CONTROL and paging I/O to the backing device, the mmap
coherency lease, the PT notification codes and their acknowledgement
opcodes, and the fallback/downgrade matrix. It supersedes the 2.0
passthrough draft in full; no 2.0 opcode name, state name, or wire
structure survives into 2.1.

The authoritative registries for this document are the unpacked crate
sources `fsring-abi/src/control/session.rs` (`DonateBackingV2`),
`control/mod.rs` (`BOUND_RECONCILING`), `layout.rs` (`PT_LANE_READY` and the
closed notification-code registry), `durable/key.rs` and
`durable/payloads.rs` (`pt_epoch`, `PtEpochIntentPayloadV1`,
`PtLanePayloadV1`), `msgs/notify.rs` (`PtGrantV1`, `PtEpochV1`), and
`validate/backing_path.rs`, together with the frozen generated header
`fsring-abi/include/fsring_abi.h` and the already-normative
`02-transport.md`, `03-messages.md`, `04-object-model.md`,
`05-irp-dispatch.md`, and `06-locking.md`. If prose disagrees with those
unpacked sources, the unpacked sources win.

A closed set of identifiers below name WDK/kernel-driver concepts that the
`fsring-abi` crate does not and will never carry, because the crate is the
`no_std` wire-format and validation library, not the driver itself:
`IO_STOP_ON_SYMLINK`, `FILE_OPEN_REQUIRING_OPLOCK`, `OBJ_KERNEL_HANDLE`,
`MmDoesFileHaveUserWritableReferences`, `MmCanFileBeTruncated`,
`FSCTL_REQUEST_OPLOCK`, `STOPPED_ON_SYMLINK`,
`MAX_OPENING_BACKING_ATTEMPTS_PER_MOUNT`/`_GLOBAL`, `PtComplete`, and
`IoFreeIrp`, plus the ordinary WDK types used to describe the forward
engine (`IoAllocateIrp`, `IoCallDriver`, `IoSetCompletionRoutine`,
`STATUS_MORE_PROCESSING_REQUIRED`). Each is transcribed from
`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md`
section 6 (the `DONATE_BACKING` protocol, section 14.2 for the
notification bodies) or from
`docs/superpowers/specs/2026-07-15-fsring-abi-v2-design.md` section 9 (the
original production-passthrough design, for the forward-engine and
teardown mechanics the corrective amendment does not restate) -- never
from the superseded 2.0 draft prose without independent verification
against those sources.

RFC 2119 keywords ("MUST", "MUST NOT", "SHOULD", "MAY") are used as
defined in RFC 2119.

## 1. Scope and identity

Passthrough (PT) lets a stream's data plane go directly to a backing file
on local disk (NTFS/ReFS) instead of through the daemon, removing the
daemon from every READ/WRITE/paging operation on that stream. v1 is
**whole-stream 1:1**: offset in the virtual file equals offset in the
backing file. Offset translation (multiple concatenated backing extents,
or a hidden header) is out of scope for v1 and is deferred per
`01-principles-architecture.md`.

- **PT_DATA** forwards the data plane (READ/WRITE/paging/LOCK_CONTROL/mmap
  fault). **PT_ATTRS** is optional and, when active, reads query
  information directly from the backing file instead of the ring path. A
  file MAY have PT_DATA without PT_ATTRS.
- The backing target MUST be a file on a **local disk volume**. It MUST
  NOT be a network device and MUST NOT be a FSRING-managed volume
  (recursion). A driver-owned device-root allowlist rejects `\Device\Mup`
  and every FSRING volume before a backing name can be opened (section 2).
- CCBs remain virtual opens. FSRING -- not the daemon and not the backing
  filesystem -- owns granted access, share access, byte-range locks,
  oplocks, delete, cleanup, and close semantics for every PT-routed
  stream; the daemon supplies backing storage, never an access decision.
  The kernel does not forward virtual `LOCK_CONTROL` state or per-open
  file-position state as identity -- raw forwarded requests always carry
  explicit byte offsets (section 4).
- Cached PT I/O stays inside the virtual FCB's own cache domain (one
  `SECTION_OBJECT_POINTERS` per FCB, `04-object-model.md`): application
  cached I/O or a mapped fault goes through the virtual Cache
  Manager/section, then a virtual paging IRP, then a PT raw child IRP,
  then the backing filesystem. The backing `FILE_OBJECT` is never a
  second user-visible cached open (`07-cache-mm.md` for the ring-path vs.
  PT cache-domain boundary; that document states PT never builds a
  ring-path cache domain because the backing filesystem's own cache
  serves it -- the fact that makes PT coherent by construction for
  ordinary READ/WRITE; section 8.1 below states the one remaining
  incoherency window, mmap).

## 2. The `DONATE_BACKING` control-IOCTL protocol

`DONATE_BACKING` is legal only on the current bound session with the PT
protocol feature selected. While the mount session state (`control/mod.rs`
`retire_mount_state`) is `ACTIVE` it proposes the exact next `pt_epoch`.
While the session is `BOUND_RECONCILING` it is legal only for a retained PT
rebuild barrier, and its FileId, epoch, path bytes/digest, sector size, and
flags MUST equal the durable PT intent being recovered; it MUST NOT create
a new backing relationship in that state. Every other session state or
tuple returns `INVALID_DEVICE_STATE` with no open.

### 2.1 Wire body and path syntax

`DonateBackingV2` is 48/8:

```text
+0  header:ControlHeader
+8  file_id:FileId          // 16 bytes
+24 pt_epoch:u64
+32 sector_size:u32
+36 flags:u32
+40 backing_path:BlobSlice  // 8 bytes; tail begins at byte 48
```

`backing_path` begins exactly at byte 48, is the only tail, and is 2--32760
bytes of well-formed UTF-16LE: an absolute `\Device\...` path with no NUL,
slash, empty/dot/dot-dot component, trailing separator, or named-stream
colon. DOS-device and relative paths are rejected. Fixed fields, a nonzero
`file_id`/`pt_epoch`, a power-of-two `sector_size` in `[512, 65536]`, zero
`flags`, and the complete private path snapshot are validated before any
open is attempted (`validate/backing_path.rs`).

### 2.2 Device-root allowlist and PASSIVE_LEVEL open

Before any name open, the kernel parses the first device-root component of
`backing_path` and requires an exact component-boundary match in a
driver-owned local-volume target table. Each entry was built from a
mounted disk-filesystem volume over a referenced local disk device,
retains its canonical NT device-root name and target device object, and
was rejected at table-build time if its attached stack contains FSRING or
any network/provider device. `\Device\Mup`, UNC/DOS aliases, unlisted
roots, stale PnP generations, prefix-only matches, FSRING volumes, and
non-local targets all fail before a create can enter such a stack.

At PASSIVE_LEVEL the driver initializes `IO_DRIVER_CREATE_CONTEXT` with
that allowlisted volume as `DeviceObjectHint` and calls `IoCreateFileEx`
with `IO_FORCE_ACCESS_CHECK|IO_STOP_ON_SYMLINK`, a null root,
`OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE|OBJ_FORCE_ACCESS_CHECK`, desired
access `FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE`,
`ShareAccess=0`, `FILE_OPEN`, and create options exactly
`FILE_NON_DIRECTORY_FILE|FILE_NO_INTERMEDIATE_BUFFERING|
FILE_OPEN_REQUIRING_OPLOCK`. It requests neither the synchronous-I/O flag
nor append/execute/delete access. The returned handle is never inserted
into or duplicated to any user-mode handle table.

The kernel performs no query, read, metadata operation, stack callback, or
other filesystem I/O between `FILE_OPEN_REQUIRING_OPLOCK` success and
submission of `FSCTL_REQUEST_OPLOCK` (section 2.4). A driver-global
pre-open table keyed by canonical path digest, and a post-open exclusion
table keyed by referenced `FILE_OBJECT` identity, reject competing
attempts until the opening/lower-IRP/PT rundown for that attempt is
complete. `MAX_OPENING_BACKING_ATTEMPTS_PER_MOUNT=8` and the matching
global cap `=64` are charged before the path-table insert; exhaustion
returns `INSUFFICIENT_RESOURCES` with no create, and both caps include
abandoned opens until their workers return.

### 2.3 Status mapping

Every lower status is translated before the IOCTL's terminal-owner CAS; no
raw filesystem/device status escapes this closed registry:

| Source outcome | `DONATE_BACKING` status |
|---|---|
| pre-open syntax/header/sector validation failure | `INVALID_PARAMETER` |
| caller/control authorization failure, or lower `ACCESS_DENIED`/`PRIVILEGE_NOT_HELD` | `ACCESS_DENIED` |
| current `OPENING`/`ISOLATING`/`CANCEL_DRAINING`, or a canonical-path/`FILE_OBJECT` exclusion conflict | `DEVICE_BUSY` |
| epoch/tuple/session-state violation not classified as an in-progress conflict | `INVALID_DEVICE_STATE` |
| `NO_MEMORY`, `INSUFFICIENT_RESOURCES`, `INSUFFICIENT_QUOTA`, MDL/IRP/context allocation failure | `INSUFFICIENT_RESOURCES` |
| `NOT_SUPPORTED`, `NOT_IMPLEMENTED`, `INVALID_DEVICE_REQUEST` from the target/oplock stack | `NOT_SUPPORTED` |
| lower `CANCELLED` when the IOCTL cancellation owner won | `CANCELLED` |
| `STOPPED_ON_SYMLINK`, `MOUNT_POINT_NOT_RESOLVED`, `INVALID_DEVICE_OBJECT_PARAMETER`, `REPARSE`/`REPARSE_POINT_ENCOUNTERED`, `CANNOT_BREAK_OPLOCK`, `OPLOCK_NOT_GRANTED`, `SHARING_VIOLATION`, `OBJECT_NAME`/`PATH_NOT_FOUND`, `OBJECT_TYPE_MISMATCH`, `FILE_IS_A_DIRECTORY`, lower `INVALID_PARAMETER`, device-not-ready/disconnect/I/O failure, synchronous oplock completion, or a post-open validation veto | `INVALID_DEVICE_STATE` |

When `IO_STOP_ON_SYMLINK` returns its documented allocated reparse buffer,
the driver frees that buffer before translation on every race path. No
other `Information` value is treated as a pointer. Every successful create
that does not reach `PENDING` closes its handle and drains/removes both
exclusion table entries.

### 2.4 Isolation proof and oplock acquisition

Donation requires proof of exclusive mutation control, not merely share
flags. Immediately after a successful atomic open the kernel references
the backing `FILE_OBJECT`, installs the global isolation entry, and
submits one kernel-owned asynchronous `FSCTL_REQUEST_OPLOCK` using
`REQUEST_OPLOCK_CURRENT_VERSION`, `REQUEST`, and
`CACHE_READ|CACHE_WRITE|CACHE_HANDLE` (Read-Write-Handle). Only
`STATUS_PENDING` is a grant; unsupported FSCTL/stack behavior maps to
`NOT_SUPPORTED`, and an oplock not granted, a synchronous handle, a
writable-section-present indication, or an isolation veto maps to
`INVALID_DEVICE_STATE`.

Only after the oplock has returned `STATUS_PENDING` does the kernel query
`FileAttributeTagInformation` (requiring no reparse attribute/tag),
revalidate the same target/PnP generation and complete attached stack,
check alignment, and run the MM predicates: while the oplock is held, and
before PT acceptance, the kernel requires both
`MmDoesFileHaveUserWritableReferences(SectionObjectPointer)==FALSE` and
`MmCanFileBeTruncated(SectionObjectPointer,NULL)==TRUE`. The latter
zero-length test vetoes image sections and every data mapping/reference
that could survive a closed handle. Any network, FSRING/self-recursive,
unsupported-stack, mismatched, or non-local result -- or a break racing
these checks -- cancels the oplock attempt and closes the handle; failure
to prove every condition enters `CANCEL_DRAINING` (section 3) and accepts
no epoch.

For a restart-pair mount the daemon allocates `pt_epoch` from a durable
nonwrapping per-Mount/FileId counter in the same transaction that records
the PT-epoch intent (`durable/payloads.rs` `PtEpochIntentPayloadV1`); gaps
are legal. A nonrestart mount uses the identical nonwrapping algorithm in
session-local volatile state and destroys it on direct teardown. The
kernel accepts a new donation only when `pt_epoch` is strictly greater
than the last accepted epoch for that FileId, and burns that value when
the fully isolated pending tuple is installed (section 3). An exact
same-session retry with the identical retained tuple is idempotent and
returns success without a second open/oplock; every other equal/lower
value, or a greater value while a distinct tuple is pending/live, is
`INVALID_DEVICE_STATE`. Counter exhaustion permanently retires PT for that
file. The pending donation activates only on a matching `PT_GRANT`
(section 8.2).

## 3. Two composed state machines (binding naming decision)

The 2.0 draft conflated backing-open lifecycle and per-route forwarding
into one loose narrative. This document states them as two named,
explicitly composed machines sharing `pt_epoch` as their join key.

### 3.1 Backing-donation state machine (per `FileId`)

```text
NONE -> OPENING -> ISOLATING -> PENDING -> ACTIVE -> BREAKING_CLOSED -> REVOKED
failure edge: OPENING | ISOLATING -> CANCEL_DRAINING -> NONE
```

This machine governs whether a backing `FILE_OBJECT` exists and is
isolated/oplocked for a given file, independent of any particular open.
`OPENING` moves the copied path and immutable attempt identity into a
nonpaged driver-global context, acquires driver rundown, and installs the
path-digest exclusion before the blocking create; it holds no user
pointer, mapped view, or unreferenced mount pointer. After the kernel
open, the backing-isolation gate inserts the referenced `FILE_OBJECT` and
installs `ISOLATING`, then releases the gate before issuing the oplock
FSCTL and MM predicates (section 2.4) -- the gate is a short-hold
admission gate only and is never held across a blocking call
(`06-locking.md` section 10, cross-referenced not restated). It
reacquires the gate and installs `PENDING` only if the same attempt is
still `ISOLATING`, the session is still open, the oplock remains pending,
and no break, fence, cancellation, or competing owner appeared; that
`PENDING` publication is the epoch-burn point. `PENDING` transitions to
`ACTIVE` on the matching `PT_GRANT` (section 8.2).

Cancellation or session fencing during `OPENING` atomically detaches and
completes the `DONATE_BACKING` IRP with a `CANCELLED`/terminal status,
changes the attempt to `NONE`, and leaves only the driver-global abandoned
context; a same- or different-tuple retry while `OPENING`, `ISOLATING`, or
`CANCEL_DRAINING` returns `DEVICE_BUSY`. Cancellation in `ISOLATING`
atomically enters `CANCEL_DRAINING` and requests cancellation of the
kernel-owned oplock IRP; because that cancellation is asynchronous, only
the lower IRP completion routine may remove the exclusion entry, the
handle, buffers, and the context, transition to `NONE`, and complete the
`DONATE_BACKING` IRP `CANCELLED`.

An external oplock break moves an `ACTIVE` donation to `BREAKING_CLOSED`
(`06-locking.md` section 10 for the exact PASSIVE-level break-owner order:
drain page-I/O/mapping/route rundown without holding the gate, revoke
every grant/route, burn the accepted epoch into a fully-revoked marker,
and only then acknowledge the oplock break). `BREAKING_CLOSED` completes
to `REVOKED` once the backing reference is released (section 6).

### 3.2 Route rundown state machine (per CCB/route)

```text
RING -> GRANTING -> PT_ACTIVE -> REVOKING -> RING
```

This machine governs whether one particular open's I/O is currently
forwarded. A route MAY enter `GRANTING` only while the backing-donation
machine for its FileId is `ACTIVE`, and the route's `pt_epoch` MUST equal
the backing-donation machine's current epoch or the acquisition is a
protocol fault. A CCB's route begins in `RING` at CREATE and MAY be
offered `GRANTING` only after that CCB's `COMMIT_OPEN` has published its
live result (`05-irp-dispatch.md`, the CREATE state machine's own
normative territory, not re-derived here); PT is never offered while an
open remains in the `PREPARE_OPEN` phase of that two-phase CREATE
(`05-irp-dispatch.md`), and a route reaching `REVOKING` MUST complete back
to `RING` no later than that CCB's CLEANUP barrier.

### 3.3 Composition rule

Forwarding requires **both**: route rundown acquisition in `PT_ACTIVE`
**and** a `pt_epoch` match with the owning backing-donation machine's
current epoch. Revoke atomically blocks new acquisitions, flushes the
virtual cache through the current route, drains in-flight child IRPs
(section 6), and only then switches routing back to `RING`. Grant and
revoke never replace the virtual FCB's own `SECTION_OBJECT_POINTERS`
(`04-object-model.md`); existing mappings stay in the same cache domain
across a grant or a revoke. Neither machine substitutes for the other:
the backing-donation machine can be `ACTIVE` with every route still in
`RING` (donated but not yet granted to any open), and a route reaching
`PT_ACTIVE` is only possible while its file's donation is `ACTIVE` with a
matching epoch.

## 4. Forward engine (data path)

The forward engine applies to a `PT_ACTIVE` route's IRP_MJ_READ/WRITE
(cached/noncached/paging), `LOCK_CONTROL`, and mmap fault. It never copies
data and never issues a ring-path operation: it builds a child IRP
forwarded to `backing_fo->DeviceObject`.

### 4.1 Forwarding one READ/WRITE IRP

```text
sub = IoAllocateIrp(backing_dev->StackSize, FALSE);
set sub's MJ = Irp->MJ; sub's stack location:
   FileObject = backing_fo;
   Parameters.Read/Write = { Length, ByteOffset (already backing offset
                              = virtual offset in v1), Key };
sub->MdlAddress = Irp->MdlAddress;   // MDL reuse, zero copy
   // or sub->AssociatedIrp.SystemBuffer / sub->UserBuffer, chosen from
   // backing_dev's buffering-method flags queried once at donation time
propagate Irp->Flags PAGING_IO/NOCACHE -> sub->Flags;
IoSetCompletionRoutine(sub, PtComplete, ctx=Irp, TRUE, TRUE, TRUE);
IoCallDriver(backing_dev, sub);
return STATUS_PENDING;
```

`PtComplete(dev, sub, ctx)`:

```text
Irp = ctx;
Irp->IoStatus = sub->IoStatus;
sub->MdlAddress = NULL;   // REQUIRED before IoFreeIrp
IoFreeIrp(sub);
IoCompleteRequest(Irp, IO_DISK_INCREMENT);
return STATUS_MORE_PROCESSING_REQUIRED;
```

`sub->MdlAddress = NULL` before `IoFreeIrp` is **REQUIRED**: the MDL was
created by the I/O manager for the original IRP. If it is left attached to
the child IRP, `IoFreeIrp(sub)` frees an MDL that still belongs to the
original IRP, producing a double free/corruption when the original IRP
later completes. `STATUS_MORE_PROCESSING_REQUIRED` is returned because
`PtComplete` calls `IoCompleteRequest` on the original IRP from inside the
child IRP's own completion routine, so the I/O manager MUST NOT continue
processing the child IRP after `PtComplete` has freed it.

Buffering-method selection is read from the backing device's flags once,
at donation time, never hardcoded: direct I/O reuses the MDL as above;
buffered I/O aliases `sub->AssociatedIrp.SystemBuffer` to the original
IRP's system buffer without setting a deallocate-buffer flag (the buffer
belongs to the original IRP); neither-I/O aliases `sub->UserBuffer`.

### 4.2 IRQL and context

The forward path runs at or below DISPATCH -- `IoAllocateIrp` and
`IoCallDriver` are legal there. Paging I/O forwards normally. The engine
never synchronously waits; completion is always asynchronous through
`PtComplete`. Because no user buffer is copied in the kernel, the forward
path needs no process attach and no PASSIVE-level context switch.

### 4.3 Fast PT (optional)

For a `PT_ACTIVE` route, FastIoRead/Write MAY call the backing device's
own FastIo dispatch directly against `backing_fo` when the backing device
exposes one. If the backing device has no FastIo entry, or returns
`FALSE`, the caller returns `FALSE` so the I/O manager issues an ordinary
IRP through section 4.1. This is the fastest available path (no child
IRP) and is optional in v1.

## 5. Forward `LOCK_CONTROL`

A PT FCB holds no FsRtl lock table of its own (`05-irp-dispatch.md`).
`IRP_MJ_LOCK_CONTROL` forwards to the backing file exactly as section 4.1,
without an MDL. The backing filesystem enforces byte-range locks natively;
because every READ/WRITE on the route also forwards to that same backing
`FILE_OBJECT`, locking stays consistent by construction. No oplock is
layered on top of PT: the backing file already has its own oplock with
respect to any other opener of the backing path, and FSRING does not
create a second one.

## 6. Keepalive and lifecycle

The reference behind `backing_fo` holds an FCB refcount, keeping the FCB
alive until PT is fully released. PT is released only when every CCB of
the stream has reached CLOSE **and** no forwarded child IRP remains in
flight; at that point the kernel dereferences `backing_fo` and releases
the FCB refcount.

The daemon's own backing handle survives daemon failure and
grace/replay independently of the kernel's reference: it is closed only
when the kernel sends CLEANUP for the last handle on that stream. CLEANUP
carries delete-pending processing and emits `UNLINK` at the actual
namespace-removal point (`05-irp-dispatch.md` section 7); delete-pending
itself is kernel CCB/LCB state, not a backing-side flag. The ordering is:
CLEANUP (delete-pending recorded, `UNLINK` emitted at removal) -> CLOSE ->
daemon closes its backing handle -> kernel dereferences `backing_fo`.
Kernel dereference and daemon handle-close are independent references on
the backing file; only when both have dropped does the backing filesystem
see its last reference and unlink a delete-pending file. The kernel MUST
dereference `backing_fo` once CLOSE processing for that stream is
complete, or the backing filesystem retains an orphaned reference and
cannot unlink.

## 7. Revoke and teardown

### 7.1 Acknowledged revoke

The daemon revokes a route by sending `PT_REVOKE_ROUTE` with the live
`pt_epoch`. The PASSIVE-level owner atomically blocks new route
acquisitions, then -- without holding the backing-isolation gate across a
blocking wait (`06-locking.md` section 10) -- drains every in-flight
forwarded child IRP for that route to zero. Only after the drain completes
does it flush the virtual cache through the (still-routed) path if
needed, dereference `backing_fo` for that route's grant, and switch the
route back to `RING`. The daemon receives `PT_ROUTE_ACK` (section 8) once
the switch is Release-visible. After an acknowledged revoke, the stream is
ring-path: READ/WRITE go to the daemon as ordinary operations, and the
daemon again has full control over the backing file's data.

Downgrade is exclusively through this revoke path -- there is no direct
PT-to-ring transition outside `REVOKING`, and the design intentionally
does not support rapid grant/revoke thrashing; the daemon SHOULD decide
PT eligibility once per file rather than flapping it.

### 7.2 Volume teardown (daemon-independent)

Volume teardown revokes every `PT_ACTIVE`/`GRANTING` route internally
without daemon coordination and without sending an acknowledgement --
the daemon may already be gone. It blocks new forwards, drains in-flight
IRPs, and dereferences `backing_fo` for each route exactly as section 7.1,
but skips the `PT_ROUTE_ACK` round trip. Because a dead daemon's process
exit already closed its own backing handle, the backing filesystem
reclaims that reference independently; the kernel only needs to drop its
own `backing_fo` reference so it does not hold an orphaned one.

## 8. Coherency lease (mmap) and PT notifications

### 8.1 The one remaining incoherency window

Ordinary forwarded READ/WRITE is coherent by construction (section 1):
data always comes from or goes to the backing filesystem's own cache.
mmap is the exception. When an application maps the virtual file (a
section built on the virtual FCB) while a `PT_ACTIVE` route is forwarding
paging reads, the first fault forwards to the backing file and loads a
page into the *virtual* section -- but Windows' Memory Manager then holds
that page in the virtual section independent of later backing changes.
Routing revocation and external-mutation safety are therefore separate
states: revoking a route does not, by itself, prove that a mapped view of
stale data has disappeared, and the kernel never uses cache purge as false
proof that active mapped views are gone.

The fix is `INVALIDATE_FILE` (the 2.1 successor to the 2.0 draft's
invalidate notification): on receipt, the kernel runs
`MmFlushImageSection` and `CcPurgeCacheSection` against the *virtual*
section (not the backing file's own cache, which the backing filesystem
already manages), forcing the next fault to forward again and observe the
current backing data (`07-cache-mm.md` owns the general purge/coherency
recipe; this is PT's mmap-specific variant of it, cross-referenced there,
stated here).

Application writes through a RW mapping are the reverse direction and are
coherent: the mapped-page writer issues a top-level paging WRITE, which
forwards to the backing file exactly as section 4, so app-to-backing
writes are durable on the backing file. The remaining case -- an
application writing through an RW mapping while the daemon (or another
process) writes the backing file directly, uncoordinated -- is explicitly
**not guaranteed** to be coherent, matching the general dual-writer
disclaimer in `01-principles-architecture.md`. A daemon that intends to
write a backing region directly SHOULD revoke PT for that file first.

PT MUST NOT be offered for a file the daemon intends to write
uncoordinated while PT is active, and MUST NOT be offered into a
recursive or network backing target (section 1, section 2).

### 8.2 Notification codes and acknowledgement opcodes

The closed PT-relevant notification codes and their acknowledgement
opcodes (`layout.rs`, `03-messages.md`):

| Notification | code | Acknowledgement opcode |
|---|---|---|
| `PT_GRANT` | 3 | none; AckToken zero |
| `PT_REVOKE_ROUTE` | 4 | `PT_ROUTE_ACK` = `0x0050` |
| `PT_EXTERNAL_MUTATION_SAFE` | 5 | `PT_EXTERNAL_SAFE_ACK` = `0x0051` |
| `PT_LANE_READY` | 8 | none; AckToken zero |

Body layouts (`msgs/notify.rs`):

- `PtGrantV1` 24/8: `header`; `pt_epoch:u64`; `sector_size:u32`;
  `flags:u32`. Backing handles never travel on this notification -- they
  stay entirely on the authenticated `DONATE_BACKING` control path
  (section 2). A `PtGrantV1` MUST match a prior authenticated
  current-session backing donation for the same FileId, exact `pt_epoch`,
  and supported sector size, with no active grant already present; an
  exact duplicate of an already-applied grant is idempotent, a lower
  different grant is stale and ignored, and an unknown greater epoch is a
  protocol fault (`03-messages.md` section 9).
- `PtEpochV1` 16/8: `header`; `pt_epoch:u64`. This is the body of both
  `PT_REVOKE_ROUTE` and `PT_EXTERNAL_MUTATION_SAFE`; the carried
  `pt_epoch` MUST match the exact live transition epoch, and a mismatch is
  a protocol fault (`03-messages.md` section 9).
- `PtLaneReadyV1` 24/8: `header`; `kind_ordinal:u16`; `reserved0:u16`;
  `flags:u32`; `high_watermark:u64`. `kind_ordinal` is exactly 1 (route
  revoke lane) or 2 (external-mutation-safe lane); envelope FileId and
  AckToken are zero.

`PT_REVOKE_ROUTE` and `PT_EXTERNAL_MUTATION_SAFE` require a nonzero
AckToken and are acknowledged with the generic 24-byte `PNotifyAck`
(`token:AckToken` at offset 0, `epoch:u64` at offset 16) on their distinct
SQ opcodes; `PT_GRANT` and `PT_LANE_READY` require AckToken zero and are
never acknowledged. `03-messages.md` section 9 owns the exact AckToken
lane/ordinal encoding and is not re-derived here.

### 8.3 `PT_LANE_READY` and session reconciliation

`PT_LANE_READY` is legal only while the session is in PT reconciliation,
which begins when ATTACH initializes every per-session lane-ready bit
false -- the same reconciliation window in which the mount session may sit
in `BOUND_RECONCILING` while a retained backing-donation barrier (section
2) is rebuilt. For each lane the daemon publishes `PT_LANE_READY` only
after its reconciliation probe, every pre-ATTACH pending notification on
that lane, the matching kernel acknowledgement, and the daemon's own
success completion have all finished; the kernel verifies the carried
`high_watermark` equals its own retained value. An exact duplicate READY
before PT activation is idempotent; an early, cross-lane, mismatched, or
post-activation READY is a protocol fault. No PT fast path is enabled
until READY has been consumed for both lane kinds on every ring and open
replay is complete, and every fence clears all ready bits along with all
backing/grant state -- each file needs a fresh current-session
`DONATE_BACKING` and matching `PT_GRANT` after a fence
(`06-locking.md` section 10; `03-messages.md` section 9).

## 9. Fallback/downgrade matrix

PT is an optimization, never a requirement for correctness: every row
below downgrades to the ring path rather than failing the operation that
triggered it.

| Situation | Handling |
|---|---|
| reference/backing-donation failure (bad handle, insufficient rights) | downgrade to ring path, clear the PT_DATA grant, emit an ETW warning; CREATE MUST NOT fail |
| backing target is FSRING's own volume, or a network device | PT refused at donation time (section 2.2); ring path |
| backing device buffering method not recognized | ring path (the choice in section 4.1 is made from known flags only) |
| an operation whose semantics cannot be forwarded (for example an FSCTL) | always dispatched on the ring path -- FSCTL is never forwarded |
| revoke in progress (route in `REVOKING`) | new forwards pend or fall back to the ring path temporarily until the route reaches `RING` |
| PT_ATTRS query fails | fall back to the ordinary `QUERY_INFO` operation (05's closed opcode, `05-irp-dispatch.md`) |

## 10. Stated (not executed) DoD

The following acceptance criteria are stated as this document's Definition
of Done; they are environment/hardware-gated and are reported as pending,
never as passed, in this wave:

- fio throughput on a PT file: >=95% of raw NTFS sequential, >=85% at 4K
  QD32.
- Windows Defender full scan on a PT volume completes without a bugcheck
  -- the minifilter stack runs on the backing device exactly as it would
  on any other file.
- mmap on a PT file plus `INVALIDATE_FILE` (section 8.1): the application
  observes new backing data after the purge.
- Revoke storm: 10,000 PT files revoked concurrently drain every in-flight
  forwarded IRP, leak no `backing_fo` reference under Driver Verifier, and
  do not hang.
- Delete of a PT file: CLEANUP(delete-pending)->CLOSE->dereference
  (section 6) reaches a real NTFS unlink; the file disappears from the
  backing volume.
- No double-free of the MDL under Driver Verifier with the forward
  READ/WRITE path saturated (section 4.1).
