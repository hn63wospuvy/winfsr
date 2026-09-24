# 04 - ABI 2.1 kernel object model and identity

Status: normative for FSRING ABI 2.1. This document binds the kernel-side
object tree (VCB, FCB, LCB, CCB), the scope and lifetime of every identity
the ABI names, the durable OPEN lifecycle with its retained-open admission,
the CLEANED stream lane, the mount/session state registry, the durable
identity anchors, delete disposition, and the cached-state identity rules
applied over `volume_commit_sequence`.

The authoritative registries for this document are the unpacked crate sources
`fsring-abi/src/ids.rs`, `limits.rs`, `control/*`, `durable/*`, and
`msgs/*`, together with the frozen generated header
`fsring-abi/include/fsring_abi.h`. If prose, generated archives, or an
implementation disagree with those unpacked sources, the unpacked sources
win. Every width, state value, child kind, and constant below is transcribed
from that registry; byte layouts already given in `02-transport.md` and
`03-messages.md` are cross-referenced, never restated. Kernel-behavior state
names and bounds that the crate does not carry as named constants are
transcribed from the corrective design
`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md` and
are named as such where they appear: the volatile lifecycle state names
(STAGING, ATTACHING, TERMINALIZING, DETACHING, `CLEANUP_PENDING`,
`CLEANUP_DONE`, `CLOSE_PENDING`, `CLOSED`, `DRAIN_REPLAY`, and the provider
replay states UNSEEN/PENDING/DONE) and the `ReplayOpenV2` state-flag value
`REPLAY_STATE_PAGING_ONLY` (the crate carries `state_flags` as a plain
`u64`).

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are normative. Correctness, memory safety, isolation, and bounded
execution are absolute requirements. A performance optimization is valid
only when it preserves every identity, lifetime, and validation rule below.

## 1. Object tree and ownership

### 1.1 The four objects

One mounted FSRING volume is exactly one VCB. Below it the kernel maintains
three object classes whose ownership boundaries this section fixes:

```text
VCB: one mounted volume (MountId, current session_epoch, rings, quotas)
 |- FCB: one provider stream, keyed by FileId (u128)
 |    |- size authority: AllocationSize >= FileSize >= VDL, size_epoch
 |    |- exactly one SECTION_OBJECT_POINTERS and one internal stream
 |    |    FILE_OBJECT for the whole stream
 |    |- oplock, share-accounting, and byte-range-lock state
 |    |- security_generation for the stream's security descriptor
 |    `- zero or more LCB links
 |- LCB: one namespace link = parent FileId + name + namespace_generation
 |    |- LinkId (u128)
 |    `- delete-disposition state shared with the CCBs opened through it
 `- CCB: one virtual FILE_OBJECT / one open
      |- kernel_open_id (u64, per-mount, never reused)
      |- the opened LCB
      |- granted access, granted share mode, normalized disposition
      |- cleanup/close sequence state and the CCB's ccb_sequence order
      `- provider_open_cookie scoped to the current session
```

### 1.2 FCB identity

An FCB represents one stream identity, not one pathname. The key is the
provider-allocated `FileId` (`u128`, encoded as the `lo`/`hi` `u64` pair of
`fsring-abi/src/ids.rs`). `FileId` is stable for the lifetime of the
underlying stream, including provider restart, rename, and hard-link
changes. Reusing a `FileId` for a different live stream is a protocol
fault. A provider that selects the restart pair MUST persist or
deterministically reconstruct this identity before hot-restart
reconciliation; a provider without the pair MUST still keep it stable for
the life of the mount.

Each FCB owns exactly one `SECTION_OBJECT_POINTERS` and one internal stream
`FILE_OBJECT`; they survive until every cache map, data section, mapped
view, and dependent request has drained. Passthrough never creates a second
user-visible cache domain for the stream. The deep Cache-Manager and
memory-manager semantics behind that rule (size/VDL/epoch interaction,
purge and flush mechanics, the paging-write issue ledger) are defined by
`07-cache-mm.md`; this document carries only the identity boundary.

### 1.3 LCB and hard links

An LCB is one namespace link: the triple of parent `FileId`, the validated
link name, and the parent-directory namespace generation under which the
binding was observed. Hard links to one stream share that stream's single
FCB and have distinct LCBs with distinct `LinkId` values.

Rename changes an LCB. It MUST NOT replace the FCB, MUST NOT change
`FileId`, and MUST NOT silently clear delete disposition held by another
CCB. A rename that moves a link between parents produces a new
parent/name/generation binding for the same `LinkId` or a replaced link
identity exactly as the mutation kind-result rules of `03-messages.md`
section 8 report it; the kernel installs whichever identity outcome the
validated kind result names and nothing else.

### 1.4 CCB contents

A CCB is one virtual `FILE_OBJECT`, that is, one open. It carries:

- `kernel_open_id`: the per-mount open identity of section 2.2;
- the opened LCB (and through it the FCB);
- the access actually granted by the kernel, the granted share mode, and
  the normalized create disposition — the kernel, not the provider, owns
  the final access and share decision (`05-irp-dispatch.md`);
- cleanup/close sequence state: the volatile `CLEANUP_PENDING` /
  `CLEANUP_DONE` / `CLOSE_PENDING` progression of `05-irp-dispatch.md` and
  the CCB's `ccb_sequence` ordering authority of section 2.3;
- `provider_open_cookie`: the session-local provider authority of
  section 2.4.

The CCB retains its FCB/LCB and session-independent state until close
rundown finishes. A CCB never migrates between FCBs, LCBs, or mounts.

## 2. Identity scope table

### 2.1 One row per identity

| Identity | Scope | Width | Allocator | Zero and exhaustion rules |
|---|---|---|---|---|
| `FileId` | one provider stream within a MountId | u128 (`lo`/`hi` u64 pair) | provider; stable for the stream's lifetime through restart, rename, and hard-link changes | zero pair is invalid wherever a stream identity is required; reuse for a different live stream is a protocol fault; not a counter, no wrap rule |
| `LinkId` | one namespace link of a stream within a MountId | u128 (`lo`/`hi` u64 pair) | provider, allocated with the committed transaction that creates the link | zero pair is invalid for a live link; each hard link has a distinct `LinkId`; preserved/new/removed link identity follows the mutation kind results of `03-messages.md` section 8 |
| `kernel_open_id` | one kernel open within one live MountId | u64 | kernel, per-mount monotonically increasing nonzero allocator, linearized before the first PREPARE_OPEN publication | zero is never issued; values may be burned and are never reused until mount retirement; `u64::MAX` may be issued once and then permanently latches a CREATE-local STATUS_INTEGER_OVERFLOW (section 2.2) |
| `ccb_sequence` | order of ordinary requests on one CCB | u64 | kernel-authoritative, nonzero, nonwrapping | zero is exclusively the stream lane of section 4; the sequence never regresses; it is deliberately not durable (section 2.3) |
| `TransactionId` | one prepared open transaction within a MountId | u128 (`lo`/`hi` u64 pair) | provider, nonzero at PREPARE_OPEN success | zero pair is invalid; it is simultaneously the unique PREPARE_TX_INDEX key targeting exactly one OpId, and a collision with another OpId is corruption |
| `provider_open_cookie` | one open within one bound session | u64 | provider, issued by an ordinary `CommitOpenResultV2` or by `REPLAY_OPEN` in the current session | session-local authority in ordinary or paging-only mode; MUST NOT be stored in a durable committed result; a fence, provider exit, or epoch change closes and destroys every old cookie (section 2.4) |
| `namespace_generation` | the namespace state of one file or one parent directory | u64 | provider, advanced by each committed namespace mutation of that domain | a regressing value under an equal-or-greater `volume_commit_sequence` is a protocol fault (section 8); expected-generation checks use the exact retained value |
| `security_generation` | the security-descriptor state of one stream | u64 | provider, advanced by each committed security mutation | same regression and comparison rules as `namespace_generation`, applied to the security domain only |
| `size_epoch` | the SizeState (AllocationSize/FileSize/VDL) of one stream | u64 | provider, advanced by each committed size-changing transaction | carried inside every `SizeState`; comparison and regression rules of section 8; the size domain obeys `MAX_FILE_SIZE` (section 8.1) |
| `volume_commit_sequence` | mount-wide committed-transaction order | u64 | provider, allocated strictly greater than every previously allocated value, in the same durable transaction as the backing effect | zero is invalid; the counter never wraps; the mount is retired before another state-changing transaction if `u64::MAX` has been allocated |
| `session_epoch` | one bound daemon session of a mount | u64 | kernel; SETUP starts at exactly 1 and each successful ATTACH publishes exactly `old + 1` | zero is invalid; epoch exhaustion terminalizes the mount instead of wrapping |
| `MountId` | one mount within a BootInstanceId | u128 (`lo`/`hi` u64 pair) | kernel; `lo` is the burned permanent nonwrapping mount sequence allocated under the affine BootContext lock-event guard, `hi` is nonzero random | never reused within that BootInstanceId, even for a burned-and-failed SETUP; MountId is routing, not authentication |
| `BootInstanceId` | one Object Manager boot namespace | u128 (`lo`/`hi` u64 pair) | kernel-mode CSPRNG at BootContext creation | zero is invalid; established only by an authenticated SessionResult or RetireMountResult; time, uptime, PID, service restart, or driver reload is never reboot evidence |

`namespace_generation`, `security_generation`, and `size_epoch` are three
distinct counters and are never one shared value. The generation carried
for a file and the generation carried for its parent directory are distinct
domain values: a namespace mutation validates and reports the parent
directory's generation separately from the file's own, exactly as the
prerequisite and result-generation tables of `05-irp-dispatch.md` bind per
mutation kind.

### 2.2 `kernel_open_id` allocation

For one live MountId the kernel allocates `kernel_open_id` from a per-mount
monotonically increasing nonzero `u64` allocator. Allocation is linearized
before the first PREPARE_OPEN publication of the owning CREATE, MAY be
burned by any later abort or failure, and is never reused after a failed
create, CLEANUP, CLOSE, or row deletion until mount retirement. Concurrent
allocation is atomic. Value `u64::MAX` may be issued once and then
permanently latches a CREATE-local STATUS_INTEGER_OVERFLOW before any
PREPARE or COMMIT visibility; zero is never issued. A driver reload
terminalizes old-generation mounts rather than resuming their kernel opens,
so no new allocator may issue under the old MountId.

This nonreuse invariant is what makes a possibly visible CLOSE finding
complete ABSENT unambiguous: because no other open can ever occupy the same
`kernel_open_id`, a reissued CLOSE that observes no OPEN row and no
reservation is observing its own completed effect and succeeds
idempotently (section 3.4).

### 2.3 `ccb_sequence`

`ccb_sequence` is the kernel-authoritative, nonzero, nonwrapping current
CCB request order. It is deliberately not durable: no OPEN row stores it.
Ordinary requests on a CCB carry the nonzero sequence; a zero sequence is
exclusively the closed stream lane of section 4 and is always paired with a
nonzero `kernel_open_id`. In a zero-flag `REPLAY_OPEN` the replayed
sequence MUST equal the enclosing SQE `ccb_sequence`, and the value may
stay equal or advance but never regresses across epochs; the accepted value
is captured into the provider's first volatile PENDING/DONE replay
projection. A legitimate cross-epoch ordinary CCB advance does not mutate
the durable OPEN row.

### 2.4 `provider_open_cookie`

`provider_open_cookie` is session-local authority whose mode is ordinary or
paging-only. It may appear in an ordinary `CommitOpenResultV2`, but it MUST
NOT be stored in a durable committed result. Recovery applies the durable
OPEN replay projection and obtains a fresh cookie through `REPLAY_OPEN`;
the replacement never changes `kernel_open_id`. A session fence, provider
process exit, or epoch change closes every old cookie and destroys every
old volatile replay state, so no cookie outlives the session that issued
it. For each bound session the provider keeps bounded volatile replay state
keyed by (`session_epoch`, `kernel_open_id`) with the closed progression
UNSEEN -> PENDING -> DONE, where DONE stores the exact
persistent-plus-volatile request projection, the authority mode, and the
current-session cookie (section 4.4).

## 3. The durable OPEN lifecycle

### 3.1 Row states

Restart mounts (mounts whose SETUP selected the inseparable
HOT_RESTART+EXACTLY_ONCE pair) have this closed durable OPEN lifecycle:

```text
ABSENT --successful COMMIT_OPEN--> LIVE
LIVE   --successful CLEANUP-----> CLEANED
CLEANED--successful CLOSE-------> ABSENT
```

The OPEN row (durable child kind 3, section 6) uses the wrapper state
values `LIVE = 1` and `CLEANED = 2` from `fsring-abi/src/durable/mod.rs`
and carries exactly one `OpenRecoveryPayloadV1` whose byte layout is
defined in `02-transport.md` section 10.14. OpenRecovery is an immutable
open-time audit/replay record: its disposition is the exact normalized
PREPARE disposition; its sizes, generations, parent/name, security
descriptor, and attributes are the successful COMMIT snapshot and are never
rewritten by later WRITE, namespace, size, basic-info, or security
mutation. Those snapshot fields are not reinstalled as current cache state
on ATTACH; the provider's current backing state plus the monotonic merge
rules of section 8 remain authoritative.

Nonrestart mounts use the same logical LIVE/CLEANED transitions only in
volatile state and create no OPEN child; any purported durable row for such
a mount is an SDK error.

### 3.2 Retained-open admission order and caps

Every CREATE is assigned one immutable owning ring before PREPARE. Before
its COMMIT effect, admission reserves retained-open counts in fixed
global, then mount, then owning-ring order against the exact crate
constants:

```text
MAX_RETAINED_OPENS_PER_RING  = 4096
MAX_RETAINED_OPENS_PER_MOUNT = 262144
MAX_RETAINED_OPENS_GLOBAL    = 1048576
```

Partial failure rolls back in reverse order (owning ring, mount, global)
and returns the registered nonmutating INSUFFICIENT_RESOURCES result;
checked counter overflow is the same failure. Successful COMMIT transfers
that ticket to the kernel open plus the durable OPEN reservation.

The refund rule is exactly once: CLOSE/ABSENT terminal ownership or
terminal mount retirement refunds the ticket exactly once; CLEANUP, session
fences, replay, and journal ACK never refund it. Volatile nonrestart opens
hold the identical in-memory ticket without a durable row. The
open-lifecycle recovery FIFO of `02-transport.md` section 10.5 is therefore
bounded by charged live opens, never by `max_inflight`, and many
sequentially created opens cannot create unaccounted recovery nodes.

### 3.3 COMMIT_OPEN and the row transaction

Successful COMMIT_OPEN computes and admits the exact canonical OPEN row,
OpenRecovery payload and tails, reservation, and accounting delta before
any effect, then creates OPEN(LIVE) in the same serializable transaction as
the filesystem effect, the journal PREPARED-to-COMMITTED bundle transition,
the `volume_commit_sequence` allocation, and the PREPARE and
PREPARE_TX_INDEX deletion (section 6.3). Quota failure is a registered
nonmutating Commit failure and leaves no OPEN row. Journal ACK later
deletes only the COMMITTED bundle; it never deletes OPEN.

### 3.4 CLEANUP and CLOSE row semantics

CLEANUP consumes no `volume_commit_sequence` and is an idempotent row-state
transaction. From LIVE it performs all provider per-handle cleanup and
publishes CLEANED atomically before its success CQ; an exact CLEANED retry
repeats success without repeating the effect. ABSENT, an unknown state, or
a mismatched payload observed by CLEANUP is corruption. Provider CLEANUP
atomically revokes share/handle/user semantics and transforms any current
replay state to paging-only before its success CQ. A recovery CLEANUP from
durable LIVE installs the same paging-only provider state without needing
to return a cookie in its zero-output CQ; an exact CLEANED retry after
response loss or provider restart reconstructs missing volatile paging-only
state before its idempotent success CQ but never repeats durable cleanup
effects.

From CLEANED, provider CLOSE atomically deletes and refunds the OPEN row,
its reservation, and the paging-only volatile state, and publishes success
only after commit. Reissuing a possibly visible CLOSE finds complete ABSENT
and succeeds idempotently; LIVE or a one-sided row/reservation observed by
CLOSE is corruption. ABSENT authorizes no other deletion. LIVE and CLEANED
rows are clean-DETACH blockers, and terminal prefix retirement removes
either through the ordinary receipt transaction of `02-transport.md`
section 10.15.

The kernel-side CLEANUP barrier, the `CLEANUP_PENDING` /
`CLOSE_PENDING` substates, and predecessor draining are the dispatch
contract of `05-irp-dispatch.md`; this document binds only the row
semantics and the identity consequences above.

## 4. CLEANED semantics and the stream lane

### 4.1 What CLEANED owns

CLEANED never admits ordinary CCB work.

A CLEANED open retains exactly two things until CLOSE: the canonical
recovery payload (the immutable OpenRecovery snapshot) and a volatile
paging-only stream authority. It owns no ordinary CCB authority: an
ordinary zero-flag `REPLAY_OPEN` or any user/CCB request against CLEANED is
a protocol fault. `REPLAY_OPEN` with `REPLAY_STATE_PAGING_ONLY` and the
closed kernel stream lane below remain legal.

### 4.2 The stream-admission gate

Windows may issue cached paging work after IRP_MJ_CLEANUP and before the
final IRP_MJ_CLOSE. Therefore every FileObject open has a separate
FCB-referenced stream-admission gate and rundown that survives CCB
cleanup. The stream-admission gate is the per-FileObject admission point
for the closed lane of section 4.3; its interaction with the per-open
lifecycle gate and the universal lock order is bound by `06-locking.md`.
CLOSE closes the gate: under it the kernel snapshots every admitted stream
operation before `CLOSE_PENDING` can publish, per `05-irp-dispatch.md`.

### 4.3 Closed lane admission rules

The closed stream lane admits only:

1. a KernelMode READ or WRITE carrying the actual paging-I/O stack flag and
   the wire `rw_flags` `PAGING` bit; or
2. the trusted Cache Manager AdvanceOnly adapter canonicalized to
   SET_VALID_DATA_LENGTH.

Its SQE carries the same nonzero `kernel_open_id` but outer
`ccb_sequence = 0`; an AdvanceOnly journal QueryOp/ACK recovery phase
preserves that stream ownership. Nonpaging READ/WRITE, QueryDir, notify,
user size requests, and every other opcode still require a live ordinary
CCB and a nonzero sequence. The provider accepts the zero-sequence lane in
OPEN(LIVE) under ordinary replay authority or in OPEN(CLEANED) under
paging-only authority, and in no other row/mode combination. Paging
authority is kernel-only and does not reapply or widen the former user
handle's granted access; it permits only the cache/MM operations needed to
preserve stream data.

Stream work arriving after CLEANUP linearization obtains its normal
bounded quota/context, is marked `POST_CLEANUP_HELD` under the stream
gate (`05-irp-dispatch.md`), and reserves no application slot or SQE until
CLEANED and paging authority are ready; successful CLEANUP releases held
stream work in FIFO order and a fence retains it for paging-only replay.

### 4.4 Replay modes

The `ReplayOpenV2` state-flags registry is closed; the crate carries
`state_flags` as a plain `u64` and the single legal flag value is bound by
the corrective design:

```text
REPLAY_STATE_PAGING_ONLY = 0x0000000000000001
```

- **Zero flags** require OPEN(LIVE) and restore ordinary-plus-stream
  authority. The replayed `ccb_sequence` follows section 2.3. REPLAY_OPEN
  compares its `kernel_open_id`, `FileId`, `LinkId`, desired access, share
  access, create options, and disposition exactly with the durable OPEN
  row.
- **`REPLAY_STATE_PAGING_ONLY`** requires OPEN(CLEANED), both the
  `ReplayOpenV2` and outer `ccb_sequence` zero, and restores only the
  kernel stream paging/cache authority of section 4.3; it can never
  authorize a user/CCB request.
- **ABSENT always faults**: zero-flag replay after CLEANED, paging-only
  replay before CLEANED or after ABSENT, and every replay after complete
  ABSENT are protocol faults without authority.
- **`DRAIN_REPLAY`** is a kernel-only substate that uses the zero-flag LIVE
  wire form and changes no `REPLAY_OPEN` wire byte or provider validation.
  It installs a fresh cookie usable only by the frozen cleanup-predecessor
  set; it never reopens CCB admission and never marks the handle ordinarily
  replay-ready.

Same-epoch duplicates MUST repeat the complete mode-specific projection
exactly; a changed duplicate is a protocol fault. Unknown or composed
flags, a row-state/mode mismatch, a changed disposition, or a sequence
mismatch is a protocol fault. `REPLAY_OPEN` has no durable child row,
reservation, or accounting charge, and durable OPEN is unchanged solely by
replay.

### 4.5 Per-epoch replay-readiness bits

The kernel keeps three per-open, per-epoch readiness states:

| Readiness bit | Set by | Grants |
|---|---|---|
| ordinary replay-ready | capturing the exact successful ordinary (zero-flag) `REPLAY_OPEN` CQE in the current epoch | ordinary CCB plus stream admission |
| cleanup-drain authority | a successful `DRAIN_REPLAY` capture | drain of the frozen predecessor set only |
| stream-ready | a successful `REPLAY_STATE_PAGING_ONLY` replay | the closed stream lane only |

A session fence clears all three. ACTIVE publication and provider ordinary
dispatch require every retained OPEN(LIVE) handle to hold ordinary replay
readiness, and every retained OPEN(CLEANED) stream-open handle to hold
paging-only readiness, in that exact epoch.

## 5. The mount and session state registry

### 5.1 `retire_mount_state` and the volatile states

The authenticated mount-state registry is the crate's `retire_mount_state`
(`u16`, `fsring-abi/src/control/mod.rs`), returned by RETIRE_MOUNT QUERY in
`RetireMountResultV1.mount_state`:

```text
retire_mount_state:
  ABSENT = 1, ACTIVE = 2, GRACE = 3, TERMINAL = 4, BOUND_RECONCILING = 5
```

The volatile in-memory states STAGING, ATTACHING, TERMINALIZING, and
DETACHING never appear in a wire result: a retirement query that observes
STAGING or TERMINALIZING returns DEVICE_BUSY, and DETACHING exists only for
volatile mounts on their direct-destruction path. In the permanent
BootContext slot (`02-transport.md` section 10.10) the persistent states
are FREE=0, STAGING=1, LIVE=2, TERMINALIZING=3, TERMINAL=4; persistent LIVE
covers the in-memory states ACTIVE, BOUND_RECONCILING, and GRACE.

### 5.2 Transition edges

| Edge | Trigger and rule |
|---|---|
| FREE -> STAGING | restart SETUP burns the next mount sequence (even if later staging fails), then publishes STAGING with the exact dedicated SID, selected features, journal version 1, and epoch 1 |
| STAGING -> LIVE (in-memory ACTIVE) | SETUP's single success publication: a Release transition performed only after every fallible step and output byte is ready, and before I/O manager completion; before it there is no visible volume, producer authority, or filesystem I/O |
| STAGING -> FREE | any prepublication SETUP error; the burned MountId is never reused |
| ACTIVE / BOUND_RECONCILING -> GRACE | the session fence (daemon loss, protocol abort, lost ATTACH output); entering GRACE snapshots the checked absolute deadline of section 5.3 |
| GRACE -> ATTACHING | exactly one atomic GRACE-to-ATTACHING winner; a losing concurrent ATTACH returns DEVICE_BUSY and destroys only its private staging |
| ATTACHING -> GRACE | every failure or cancellation before the commit point unmaps private views and restores the exact same GRACE authorization, deadline, and epoch |
| ATTACHING -> BOUND_RECONCILING | the sole commit point, under the lifecycle gate and affine BootContext lock-event guard, atomically persists `latest_session_epoch = old + 1` in the slot, binds the new handle/views, and Release-publishes BOUND_RECONCILING |
| BOUND_RECONCILING -> ACTIVE | consumption of the last open/PT/external READY barrier before the retained deadline atomically publishes ACTIVE and opens kernel ordinary admission |
| LIVE -> TERMINALIZING (restart) / ACTIVE -> DETACHING (volatile) | exactly one lifecycle terminal-owner winner among clean DETACH, grace expiry, protocol abort, irreversible teardown, and unload; the winner claims the terminal owner while the exclusive lifecycle-admission gate is closed and the retained-blocker count is provably zero |
| TERMINALIZING -> TERMINAL | the noncancelable drain of all mappings, PT state, IRPs, and users, then TERMINAL publication |
| TERMINAL -> FREE | only an authenticated RETIRE_MOUNT ACK carrying the exact RetireToken; MountId is never reused in that BootInstanceId |
| DETACHING -> destroyed | volatile mounts complete destruction directly; nothing survives for ATTACH, and an exact retirement query afterwards sees ordinary ABSENT because no durable classification survives |

Two concurrent valid DETACH calls have exactly one SUCCESS winner. A DETACH
that observes another terminal owner or TERMINALIZING/DETACHING returns
DEVICE_BUSY; one that observes BOUND_RECONCILING returns DEVICE_BUSY
without disturbing the retained deadline or barriers; one that observes
TERMINAL, GRACE, or a noncurrent epoch returns INVALID_DEVICE_STATE. If the
stable retained-blocker count is nonzero — any LIVE or CLEANED OPEN row,
any retained PREPARED/COMMITTED request, or any outstanding ACK — DETACH
reopens admission without a visibility gap and returns DEVICE_BUSY.

### 5.3 The GRACE deadline and BOUND_RECONCILING

`RESTART_GRACE_TIMEOUT_MS = 30000` is fixed in ABI 2.1 and is not daemon-
or registry-configurable. Entering GRACE snapshots the checked value
`KeQueryUnbiasedInterruptTime() + 300000000` (100-ns units), so sleep and
hibernate do not consume restart time and wall-clock changes cannot extend
it. A timer only schedules the PASSIVE lifecycle owner; the owner and every
QUERY, ATTACH, and reconciliation entry recheck the same absolute deadline
under the lifecycle gate.

ATTACH must win its epoch/binding commit before that deadline, and the same
original deadline remains armed while the new epoch is BOUND_RECONCILING.
The IOCTL may return its mappings after that commit because the daemon
needs them to reconcile; its SUCCESS means "bound", not "ordinary I/O
admitted". All open, PT, and external READY barriers must complete before
the deadline for the atomic transition to ACTIVE. Expiry terminalizes the
already-bound epoch through the one terminal-owner path; it is never an
IOCTL timeout, and no completion after expiry can reactivate the mount.

While the mount is BOUND_RECONCILING, only authenticated recovery-system
SQ/CQ traffic, exact reissue/QueryOp/ABORT/ACK of an already-retained
logical request, DONATE_BACKING needed for PT rebuild, ENTER, QUERY, and
lifecycle control are admitted; every new native filesystem IRP is held in
its existing bounded queue or fails through the terminal owner, and no
newly admitted semantic SQE is published.

The ATTACH open barrier is exhaustive over the section 3 lifecycle:

| Handle state at ATTACH | Barrier obligation before ACTIVE |
|---|---|
| LIVE, no lifecycle transition pending | become ordinary replay-ready in the exact epoch |
| `CLEANUP_PENDING`, including `DRAIN_REPLAY` and predecessor recovery | reach CLEANED/CLEANUP_DONE and then paging-only readiness while its stream gate remains open |
| CLEANED/CLEANUP_DONE awaiting native CLOSE | complete the paging-only replay before ACTIVE |
| `CLOSE_PENDING` | replay paging authority only when retained stream predecessors need it, drain them, and complete ABSENT |
| CLOSED/ABSENT | no barrier work |

The retained-open caps of section 3.2 make this reconciliation work
finite: at most `MAX_RETAINED_OPENS_PER_RING` open-lifecycle nodes are
queued on one ring and rings service those queues in parallel. This is a
resource and deadlock bound, not a promise that an untrusted or stalled
provider answers all phases within 30 seconds; failure to do so takes the
safe expiry path rather than extending the deadline or exposing ordinary
I/O.

### 5.4 `session_epoch` monotonicity

Setup starts `session_epoch = 1`. Each successful ATTACH publishes exactly
`old + 1`, requires the exact MountId, a prior epoch equal to the retained
current epoch, requested features equal to the retained selected set,
journal version 1, and zero flags. Epoch exhaustion terminalizes the mount
instead of wrapping. Old views, tokens, cookies, and replay generations of
a superseded epoch are invalid the moment the fence closes them; no PT
route, grant, backing reference, or raw handle survives into a new epoch.

## 6. Durable identity anchors

### 6.1 The closed child-kind registry

Every ordinary recovery key begins with the exact 32-byte MountId range
prefix (`MountId.lo_le || MountId.hi_le || BootInstanceId.lo_le ||
BootInstanceId.hi_le`), followed by `child_kind_le:u16` and that schema's
minimally encoded identity tail (`02-transport.md` section 10.14). The
closed child kinds, from `fsring-abi/src/durable/mod.rs`:

| Kind | Value | Key tail after the 34-byte header | Identity role in this document |
|---|---:|---|---|
| ROOT | 1 | none | the one `ProviderMountRootV1` mount anchor |
| ACCOUNTING_RESERVATION | 2 | `target_key_digest:[u8;32]` | reservation sidecar keyed by the target key digest |
| OPEN | 3 | `kernel_open_id:u64` | the durable open row of section 3 (LIVE=1 or CLEANED=2, one `OpenRecoveryPayloadV1`) |
| PREPARE | 4 | `OpId.lo:u64, OpId.hi:u64` | the restart-stable open-prepare record |
| — | 5 | — | explicitly unassigned and illegal in ABI 2.1; not a durable replay record; encountering it under a MountId prefix is corruption |
| IMMUTABLE_REQUEST | 6 | `OpId.lo:u64, OpId.hi:u64` | the retained semantic request bytes of a PREPARED operation |
| COMMITTED_RESULT | 7 | `OpId.lo:u64, OpId.hi:u64` | the canonical committed result of a COMMITTED operation |
| JOURNAL | 8 | `OpId.lo:u64, OpId.hi:u64` | the journal state row of the bundle table below |
| QUERY_DIR_SNAPSHOT | 9 | `kernel_open_id:u64, generation:u64` | the retained directory snapshot of one open and enumeration generation |
| QUERY_DIR_ATTEMPT | 10 | `kernel_open_id:u64, generation:u64, input_cookie:u64, attempt_digest:[u8;32]` | one accepted enumeration attempt |
| QUERY_DIR_COOKIE | 11 | `kernel_open_id:u64, generation:u64, cookie:u64` | one verified continuation cookie |
| PT_EPOCH_INTENT | 12 | `FileId.lo:u64, FileId.hi:u64, pt_epoch:u64` | one recorded passthrough donation intent |
| PT_EPOCH_COUNTER | 13 | `FileId.lo:u64, FileId.hi:u64` | the per-file nonwrapping PT epoch allocator |
| PT_LANE | 14 | `ring_index:u8, kind_ordinal:u8` | one PT acknowledgement lane |
| EXTERNAL_NOTIFY_OUTBOX | 15 | closed subkind tail (`02-transport.md` section 10.15) | the external-change outbox and its metadata rows |
| VOLUME_COMMIT_COUNTER | 16 | none | the materialized `volume_commit_sequence` allocator row |
| PREPARE_TX_INDEX | 17 | `TransactionId.lo:u64, TransactionId.hi:u64` | the unique TransactionId-to-OpId index of section 2.1 |

Unknown kinds are corruption; a future kind is illegal until an ABI
amendment adds its number and retirement rule, and the later values remain
fixed and are not renumbered. Key generations, cookies, epochs, OpIds,
TransactionIds, and kernel-open IDs in key tails are nonzero. The wrapper
(`DurableChildValueV1`), every fixed payload layout, and every charge
formula stay in `02-transport.md` sections 10.14 and 10.15 and are not
restated here.

### 6.2 04-relevant key ownership

Three tails carry identities this document owns: OPEN is keyed by
`kernel_open_id` alone (one row per kernel open, made unambiguous by the
nonreuse invariant of section 2.2); the QueryDir snapshot, attempt, and
cookie rows are keyed by `kernel_open_id` plus the nonzero enumeration
generation (so a replayed enumeration can never alias another open or an
older generation); and the PT intent/counter rows are keyed by `FileId`
(stream identity, not link or open identity, so hard links and reopens
share one PT domain). The PT donation and revocation contract itself is
`08-passthrough.md`.

### 6.3 Journal bundles

The physical journal registry has exactly three legal bundles per OpId.
"Absent" means the row and its accounting reservation are both absent;
"present" means both exist and their canonical charge is reflected in the
counters:

| Logical state | IMMUTABLE_REQUEST | JOURNAL | COMMITTED_RESULT |
|---|---|---|---|
| ABSENT | absent | absent | absent |
| PREPARED | RETAINED | PREPARED | absent |
| COMMITTED | absent | COMMITTED | COMMITTED |

All present rows use the same MountId prefix and OpId, and their opcode,
mutation kind, operation digest, payload digest, and result projection
cross-check exactly. `ABSENT -> PREPARED` atomically creates the immutable
request and PREPARED journal rows, their reservations, and every accounting
delta before any backing effect. `PREPARED -> COMMITTED` atomically
performs the backing effect, allocates the `volume_commit_sequence`,
changes JOURNAL to COMMITTED, inserts COMMITTED_RESULT, deletes and refunds
IMMUTABLE_REQUEST and its reservation, and updates all accounting;
COMMIT_OPEN additionally deletes and refunds its PREPARE and
PREPARE_TX_INDEX pair in that same transaction. An abort or a registered
terminal failure with no effect atomically deletes and refunds the complete
PREPARED bundle; ACK_RESULT atomically deletes and refunds the complete
COMMITTED bundle.

QUERY_OP classifies NOT_FOUND only from complete ABSENT, PREPARED only from
the exact PREPARED bundle, and COMMITTED only from the exact COMMITTED
bundle. Any partial, one-sided, wrong-state, extra-row, mismatched-digest,
orphan-reservation, or inconsistent-charge combination is corruption and is
never normalized to NOT_FOUND. The recovery dispatch machine that consumes
these classifications is `05-irp-dispatch.md`.

## 7. Delete disposition

Delete disposition belongs to the relevant CCB and LCB, never to the FCB as
a whole and never to the provider:

- `DeletePending` on a link prevents incompatible new opens through that
  link; the kernel makes that admission decision from its own object state.
- Removing one hard link removes that LCB only. The stream is deleted when
  namespace/link and open-reference rules allow it; other LCBs of the same
  FCB are untouched.
- Rename changes an LCB and never silently clears delete disposition held
  by another CCB (section 1.3).
- The kernel emits the durable UNLINK mutation at the actual namespace
  removal point — the committed transaction in which the link leaves the
  namespace — not at handle close as such. The UNLINK kind result reports
  the removed `LinkId` and the affected generations per `03-messages.md`
  section 8, and section 8 of this document governs how the removal merges
  into cached state.
- POSIX-semantics delete disposition is deferred: ABI 2.1 registers no
  mutation kind for it, and the kernel MUST NOT accept a disposition
  request that only that semantics could satisfy.

## 8. Cached-state identity rules over `volume_commit_sequence`

### 8.1 The size domain

`MAX_FILE_SIZE = 0x7fffffffffffffff` (`i64::MAX`). Every wire field that
represents allocation size, EOF/file size, VDL, file offset, byte-range
end, or a native volume byte total is an unsigned encoding of a value in
`[0, MAX_FILE_SIZE]` and is rejected before conversion to `LARGE_INTEGER`
otherwise. For a nonempty range, checked arithmetic MUST prove
`offset < MAX_FILE_SIZE`, `1 <= length <= MAX_FILE_SIZE`, and
`offset + length <= MAX_FILE_SIZE`; a schema whose zero length means the
whole stream additionally requires offset zero. A provider value outside
the domain is a protocol fault before any native or cache call. No opcode
may fall back to unsigned wrap or an implementation-defined volume maximum.

### 8.2 Order, provenance, and floors

`volume_commit_sequence` is one mount-wide `u64` transaction order shared
by successful COMMIT_OPEN, WRITE, MUTATE, RESIZE, and external DIR_CHANGE.
Every distinct committed provider or external transaction allocates a value
strictly greater than every previously allocated value; ordinary
completion, the durable result, QUERY_OP, replay, and any notification for
the same transaction repeat its exact original value rather than allocating
another. Ring delivery is explicitly not ordered by this counter.

The kernel retains a last-applied sequence plus compact provenance per
affected FileId/parent/cache-state domain. Each precise external event
installs an invalidation floor equal to its sequence on every affected
file, parent, namespace, size, security, and content domain. A floor stores
a comparable domain generation only when that exact event schema carries
one; MODIFY filters without a matching external RESIZE create
generation-less floors for those domains, and no generation is inferred
from a target namespace generation. A synthetic OVERFLOW cold-invalidates
all provider-derived domains and advances a volume-wide cold floor to its
highest covered sequence; OVERFLOW carries no comparable generation and has
no equal-sequence precision exception. A delayed operation or notification
with sequence less than or equal to an applicable floor may still complete,
ACK, or repeat conservative invalidation, but may not install precise
provider cache state; only a strictly greater sequence can do so. Floor
suppression precedes the generic merge below.

### 8.3 The merge rules

A validated result merges into cached identity state as follows:

- **Lower sequence.** An older committed result: its IRP still completes
  with the validated status and information and its durable COMMITTED
  bundle is acknowledged, but it cannot replace newer cached state. Before
  treating it as stale, every nonzero carried `size_epoch` and
  namespace/security/parent generation is compared with retained state when
  no applicable floor already suppressed that domain: lower is stale, equal
  requires the complete corresponding state to match, and higher is
  causally impossible under the global order and is a protocol fault. A
  stale namespace or link result conservatively invalidates every affected
  FCB, LCB, and parent cache instead of installing a partial precise
  mutation.
- **Equal sequence.** Operation-to-operation repetition requires the same
  retained OpId and semantic request (including the digest when
  EXACTLY_ONCE is selected) plus exact equality of every identity,
  SizeState, generation, count, and kind payload. The closed cross-form
  exceptions are (a) a local-operation RESIZE bearing that same retained
  OpId provenance and (b) an external RESIZE plus the contiguous precise
  DIR_CHANGE group from the one external transaction, with exact equality
  of overlapping complete SizeState required whichever form arrived first.
  Any other equal-sequence reuse — a different FileId, changed overlap,
  operation/external provenance collision, or noncontiguous external group
  — is a protocol fault.
- **Greater sequence.** May advance a counter. A lower `size_epoch` or
  namespace/security generation under a greater sequence is a protocol
  fault; an equal counter requires the full corresponding state to be
  byte-for-byte identical; a greater counter applies the full state. All
  affected domains and the new per-domain sequence become visible
  atomically.
- **Multi-entity namespace results.** If a rename, link, unlink, or
  replacement result is older for any affected entity, the kernel performs
  only conservative invalidation for the whole relation and advances other
  monotonic metadata where safe; it never installs half a rename, link,
  unlink, or replacement.

Session-local `provider_open_cookie` installation and IRP byte-count
completion are not rolled back merely because their metadata snapshot is
older; they are validated independently while cached metadata follows the
merge above. These rules also apply after QUERY_OP recovery, so arrival
order cannot regress a SizeState or a namespace/security generation.

### 8.4 Scope boundary

These are identity rules only: which values may be compared, which may be
installed, and which combinations fault. The deep cache semantics that
consume them — Cache-Manager size/VDL updates, purge and flush ordering,
mapped-section interaction, and the paging-write issue ledger — are defined
by `07-cache-mm.md`, and the external-change acknowledgement lane that
produces the precise and OVERFLOW
events is defined by `03-messages.md` section 9 with its kernel dispatch in
`05-irp-dispatch.md`.

## C4 recovered object model

C4 publishes no raw session-pointer authority anywhere. A control file's binding
is a copyable observation, `ControlBindingState`, and its variants carry identity
rather than address: `Staging` carries a setup epoch, `Active` carries a
`SessionLocator`, and closing is split in two because the two closes have
different authority. `ClosingSetup` carries the setup epoch and closes a binding
that never published; `ClosingLive` carries the locator and closes one that did.
Native owners stay out of that observation entirely.

The registry behind the locator is an owning generation registry: it owns fixed
backing, stamps every authority with a nonwrapping generation, keeps a
zero-reference session `Deleting` until native destruction completes, and cannot
reuse an outstanding generation. A locator is therefore a name, not a
capability. Every dereference that starts from one is covered by a validated
live-generation access rundown held from before the projection until the work
finishes; a `Staging`, `Removing` or `Deleting` dereference additionally
requires the matching affine setup, pending, terminal or deletion owner. Public
metadata views are by value.

ENTER identity is minted by the state, not supplied by the caller. A request brand comes from the ring state that admitted it:
a state-minted request identity, never a caller-supplied one. The execution
brand it carries names one of two disjoint
`EnterExecutionDomain` values, so an SQ-wait authority can never be spent as a
CQ-stream authority or the reverse. A refused arrival returns the exact
authority it was handed.

Pending publication is permanent once it fails. The refusal is carried by a
`PublicationFailStopWitness` whose packet outlives the slot state that names it,
which is why a parked slot can be observed for unload without the observation
consuming, clearing, retrying or projecting the unique packet.

Mount takes a real reference: the transaction obtains a core session strong
reference into the exact `MountOwner`, and rollback, dismount and terminal
release spend it exactly once.

Two refusal carriers are permanent parts of this model and are not checkpoint
residue: `FenceTerminalBlocked` and `DeleteTerminalBlocked` are the typed
`Blocked` rendezvous publications a durably parked fence or delete reaches. They
retain all authority and are the only terminal publications that are not a
`Completed` result.
