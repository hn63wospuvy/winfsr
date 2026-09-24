# 06 - ABI 2.1 locking, concurrency, and rundown order

Status: normative for FSRING ABI 2.1. This document defines the complete
concurrency contract of the kernel driver: the one universal lock order, the
gate inventory, the rule that every daemon wait is a state-machine boundary,
the one-terminal-owner CAS registry with its exact rundown and refund
points, the session-fence and notify-fence orders, cancellation concurrency,
PT rundown ordering, and the terminal-path transition table. It supersedes
the 2.0 locking draft in full; no 2.0 lock name, lock order, or wait rule
survives into 2.1.

The authoritative registries for this document are the unpacked crate
sources `fsring-abi/src/layout.rs`, `ids.rs`, `slots.rs`, `limits.rs`,
`features.rs`, `ring.rs`, `msgs/*`, `control/*`, `durable/*`, and
`validate/*`, together with the frozen generated header
`fsring-abi/include/fsring_abi.h`. If prose, generated archives, or an
implementation disagree with those unpacked sources, the unpacked sources
win. Every wire value below is transcribed from that registry:
`MAX_APPLY_DOMAINS_PER_OPERATION = 6`, `MAX_QUERY_OP_BTS_RETRIES = 1`, and
the apply-domain kinds `FILE_STATE = 1`, `DIRECTORY_NAMESPACE = 2`,
`LINK_STATE = 3`, `OPEN_STATE = 4` are carried by
`fsring-abi/src/validate/messages.rs`; the bounds
`RESTART_GRACE_TIMEOUT_MS = 30000` and
`MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING = 1` are carried by
`fsring-abi/src/limits.rs`; and every CQE or control-IOCTL completion
status named below is a member of the closed status registries in
`fsring-abi/src/validate/messages.rs` and `fsring-abi/src/control/mod.rs`.
Kernel-behavior gate names, owner states, and values that the crate does
not carry as named constants -- the lifecycle-admission and per-open
lifecycle gates, the `TRUNCATING` size-gate substate, the AdvanceOnly CSQ
owner states, `sq_wait_owner` and `cq_enter_owner`, `DETACHED_HANDLER`,
`notify_fence_generation`, the PT per-file and PT ack states, and the
native change-notify completion statuses `STATUS_NOTIFY_CLEANUP =
0x0000010b` and `STATUS_NOTIFY_ENUM_DIR = 0x0000010c` -- are transcribed
from the corrective design
(`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md`)
and are binding driver behavior, not wire values. `TRUNCATING` itself is
this document's binding name for the corrective design's size-gate
reduction substate.

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are normative. Correctness, memory safety, isolation, and bounded
execution are absolute requirements. A performance optimization is valid
only when it preserves every validation and lifetime rule below.

Transport-side ring, cursor, credit, and ENTER rules are defined in
02-transport.md; message payloads and legality maps in 03-messages.md;
object identities and durable lifecycle rows in 04-object-model.md;
per-IRP-major dispatch in 05-irp-dispatch.md. Deep Cache-Manager/MM
semantics belong to 07-cache-mm.md and the full PT
donation/isolation/revocation contract belongs to 08-passthrough.md; this
document binds only the ordering, locking, and rundown constraints those
subsystems must obey.

## 1. The universal lock order

The driver has exactly one blocking-acquisition order. Whenever a path needs
more than one of the ordered acquisitions, the universal order is
`lifecycle-admission -> per-open lifecycle -> size gate -> sequencer ->
AdvanceOnly CSQ`, omitting locks a path does not need. No path acquires any
earlier lock from the sequencer, and no path waits, allocates, maps, calls
the provider, or completes an IRP while holding the sequencer or CSQ lock.

The five ordered positions are:

| Order | Acquisition | Kind | Scope | Serializes |
|---|---|---|---|---|
| 1 | lifecycle-admission gate | cancel-safe shared/exclusive logical gate | mount | filesystem/journal/ACK admission against DETACH, teardown, and ACTIVE publication (section 3.1) |
| 2 | per-open lifecycle gate | logical state gate | one open (`kernel_open_id`) | REPLAY_OPEN, CLEANUP, and CLOSE, and BOUND_RECONCILING classification (sections 3.2, 3.7) |
| 3 | size gate | logical per-FCB gate, entered while the FCB main/paging resources are owned | FCB | every allocation, EOF, and VDL mutation; the `TRUNCATING` substate (section 3.3) |
| 4 | sequencer | per-FCB spin lock | FCB | paging-WRITE issue order, the failure ledger, and the AdvanceOnly FIFOs (section 3.4) |
| 5 | AdvanceOnly CSQ | IO_CSQ spin lock | FCB/mount queue | queue links and IRP ownership only (section 3.5) |

Rules that complete the order:

- Spin locks are leaves. No path acquires a gate, a push lock, another spin
  lock outside the two fixed nestings below, or any blocking resource while
  it owns a spin lock, and no spin lock is retained across a wait, an
  allocation, a mapping, a provider call, or an IRP completion.
- The AdvanceOnly path nests `sequencer -> CSQ` and only that way: dispatch
  calls `IoCsqInsertIrpEx` and `IoCsqRemoveIrp` while it owns the sequencer,
  and no CSQ callback acquires the sequencer or touches `sequencer_link`.
- The change-notify path nests notification-state push lock followed by the
  CSQ spin lock as the only nested queue order on that side; no path takes
  the reverse order, and cancellation/CSQ callbacks never take notification
  state. The CSQ spin lock protects only queue links/IRP ownership.
- The per-request operation state lock (section 9) and the domain locks
  (section 4) are acquired with no session, ring, mount-control, or
  operation-state lock owned, in their own fixed sort orders, and are
  therefore outside and below the five-position order: nothing else is
  acquired from inside them except the fixed pairs this document names.
- The per-ring sole-consumer token (section 7) is a physical cursor/credit
  token, not a lock tier: it is acquired only by the single admitted CQ-role
  owner or the fence, and nothing blocking is ever acquired under it.

The sequencer spin lock exclusively owns `last_issued`, the ordered active
set, the contiguous terminal prefix, the failure intervals and the inline
UNKNOWN accumulator, `ledger_version`, the waiter/ready/stream-held FIFOs,
and the stream publication-admission flags. The logical size gate owns
SizeState. A WRITE result path enters the size gate, applies its verified
SizeState, then under the sequencer records coverage/failure, updates
`ledger_version`, removes the active issue, and detaches newly eligible
waiters before releasing locks and scheduling them. An early failure that
needs no SizeState may take only the sequencer and record the full
conservative range. VDL-based trimming and final AdvanceOnly revalidation
always use the combined order. Thus prefix publication cannot expose a torn
SizeState/ledger decision or invert against an AdvanceOnly mutation.

**Editorial note (ABI 2.1, 2026-07-28, slice C1).** Two different questions are
asked of this section and answered differently, and an implementation that
conflates them gets one of them wrong.

*Ordering* applies to the five positions in the table above, and only to them.
*Membership* — what a path currently owns — is a larger set: the FCB
main/paging resources of row 3, the FCB rundown of section 2 corollary 1, the
per-request operation state lock (section 9), the domain locks (section 4), the
session, ring and mount-control locks named in the fourth bullet above, the
per-ring sole-consumer token (section 7), the namespace lock (section 7.1), and
the mount rundown, registration rundown and CCB lock named by sections 6 and 8.
Section 6's no-completion rule and the no-work-under-a-spin-lock rule above are
both stated in terms of what is owned, not in terms of the table.

This note records that distinction where the table is read, because reading the
table alone suggests a shorter list than the rules use. It states no new
requirement: the preamble makes MUST normative, and no MUST is introduced here.
An earlier revision of this note asserted that an implementation "MUST represent
all of them" — that was a new requirement wearing an editorial label, and slice
C1, which wrote it, did not meet it.

## 2. Daemon waits are state-machine boundaries

Every daemon wait is a state-machine boundary: the waiting thread owns
no ERESOURCE, no push lock, no spin lock, and no gate that a completion,
fence, or rundown path can require; continuation state is carried by logical
gates and rundown references that are not thread-owned.

This is the load-bearing liveness rule of the driver. The provider is an
untrusted user-mode process: it may stall, exit, or answer arbitrarily late.
Because no kernel thread parks inside a blocking resource that a completion,
cancellation, fence, or teardown path can require, a dead daemon can never
wedge the kernel; the session fence, the GRACE deadline, DETACH, and
teardown always run to their terminal states through the one terminal-owner
CAS regardless of provider progress.

The inventory of daemon-dependent waits and their continuation carriers:

| Wait | Waiting owner | Continuation state carrier |
|---|---|---|
| ENTER SQ readiness | the sole `sq_wait_owner` | the `sq_publish_generation` seqlock and `sq_ready_event` protocol (section 5.3) |
| ENTER CQ semantic continuation | `cq_enter_owner` | the `DETACHED_HANDLER` descriptor installed under the record's state gate (section 7.2) |
| journaled confirmation and ACK | the retained operation | the QUERY_OP phase machine and the per-request state lock (sections 5, 9) |
| AdvanceOnly barrier and resources | `AdvanceIrpContext` | BARRIER_WAIT/RESOURCE_READY FIFO links plus the one owner CAS (section 3.5) |
| CLEANUP predecessor drain | the open's lifecycle state | `CLEANUP_PENDING(DRAIN_PREDECESSORS)` with a retained count plus per-operation references (section 3.2) |
| CLOSE stream drain | the open's lifecycle state | the `CLOSE_PENDING(DRAIN_STREAM)` snapshot under the stream gate (section 3.6) |
| size-change provider round trip | the retained size operation | the logical size gate plus FCB rundown; terminal reentry is nonfailing (section 3.3) |
| PT break/revocation drain | the PASSIVE break owner | BREAKING_CLOSED plus the PT rundown counts (section 10) |
| GRACE deadline | the PASSIVE lifecycle owner | the absolute unbiased-interrupt-time deadline rechecked under the lifecycle gate (section 11) |

Two corollaries are binding:

1. Blocking resources are released before provider execution while the
   logical size gate and FCB rundown remain held. The size path acquires the
   FCB main/paging resources, decides, publishes, and then releases those
   blocking resources before the provider runs; terminal reentry installs
   the already-validated SizeState and performs only nonfailing cache-size
   update and gate-release work.
2. The AdvanceOnly resource worker waits for the application slot,
   ApplyReserve, grant, digest, and every other fallible resource with both
   the sequencer and the CSQ lock released and no size gate owned; no size
   path waits for an application slot, ApplyReserve, allocation, grant, or
   other admission resource while it owns the logical gate. Thus a preceding
   WRITE may finish and free the sole `max_inflight = 1` slot while
   AdvanceOnly waits outside the gate.

The kernel scheduler contributes no sleep or table scan between a freed
control cell and the next ready lifecycle phase; progress bounds are
resource and deadlock bounds, never a promise that a stalled provider
answers in time. Failure to answer takes the safe expiry path of section 11
rather than extending any deadline.

## 3. Gate inventory

### 3.1 The lifecycle-admission gate

One cancel-safe shared/exclusive gate per mount closes and opens admission
as a unit.

- Shared acquisition admits ordinary filesystem work, journal traffic, and
  ACK publication, and is what every BOUND_RECONCILING classification and
  native lifecycle transition takes first (section 3.7).
- Exclusive acquisition is taken by DETACH, by teardown, and by ACTIVE
  publication. A valid DETACH first acquires the mount's cancel-safe
  exclusive lifecycle-admission gate; cancellation can win only before that
  acquisition and returns CANCELLED. The exclusive gate closes all new
  filesystem/journal/ACK admission and makes the exact retained-blocker
  count stable. If the count is nonzero, DETACH reopens admission without a
  visibility gap and returns DEVICE_BUSY. Otherwise it atomically claims the
  terminal owner while the gate remains closed. No post-check operation can
  appear.

The gate is a logical admission gate, not a thread-owned blocking resource:
its closed state and the retained-blocker count carry the decision, and no
path parks inside it while owning anything a completion path needs.

### 3.2 The per-open lifecycle gate

One kernel per-open state gate serializes REPLAY_OPEN, CLEANUP, and CLOSE
for each open. If CLEANUP wins before a queued replay's SQ Release, it
cancels that replay only when the frozen predecessor set needs no fresh
cookie; otherwise the queued phase is retained as DRAIN_REPLAY. If replay
has crossed SQ Release, CLEANUP closes new ordinary admission and records
intent but waits for replay terminal ownership. A session fence discards
every ordinary/paging replay generation and repeats the mode-specific
decision on the next ATTACH. CLOSE is admitted only after CLEANUP_DONE and
follows the same gate plus stream drain. No newly admitted ordinary request
can pass while either transition is pending; frozen predecessor drain and
bounded POST_CLEANUP_HELD stream traffic are the only closed exceptions,
and the latter cannot publish until PAGING_ONLY readiness.

CLEANUP linearization happens under this gate: it closes new ordinary
admission and snapshots as predecessors every logical operation already
admitted on that CCB plus stream work already ADMITTING or provider-visible
for the FileObject. Queued ordinary work that was never semantically visible
is cancelled locally in CCB order; pre-handoff stream work moves to
POST_CLEANUP_HELD without losing its issue; possibly-visible nonjournaled
work uses the one terminal-owner arbitration of section 9; journaled work
reaches a verified terminal through its retained QueryOp/ABORT/ACK state
machine. CLEANUP is not publishable until every predecessor has released its
request-table slot, grant/MDL ticket, and operation rundown. The lifecycle
gate is released while any predecessor waits; a retained count plus
per-operation references, not a held gate or a table scan, detects the zero
transition.

Ordering against the mount gate is fixed: No path may hold a per-open gate
while acquiring the lifecycle-admission gate. Whoever needs both takes the
lifecycle-admission gate first, the per-open gate second, and releases in
reverse order.

The provider maintains the matching serialization domain: it uses the same
per-open serialization domain for all three opcodes and both replay modes.
REPLAY_OPEN holds it from OPEN lookup through volatile PENDING/DONE
installation and CQ Release, and immediately before installing authority
revalidates either OPEN(LIVE) with zero flags or OPEN(CLEANED) with
PAGING_ONLY. CLEANUP and CLOSE hold it through their row transaction and CQ
Release; provider stream operations take compatible rundown and cannot cross
either transition's frozen boundary. Therefore CLEANUP cannot commit CLEANED
between replay validation and cookie publication. The
`provider_open_cookie` this domain protects is session-local; a fence closes
and destroys it, and a DRAIN_REPLAY installs a fresh cookie usable only by
the frozen predecessor set.

### 3.3 The per-FCB size gate and the TRUNCATING substate

After successful ordinary oplock arbitration, or after the trusted
AdvanceOnly admission sequence of section 3.5, the kernel first reserves
every ordinary fallible publication/apply resource, then acquires the FCB
main/paging resources and enters a per-FCB size-change gate serializing
every allocation, EOF, and VDL mutation. Only the documented reduction
prerequisites below may be discovered under the gate; no
request-table/grant/allocator admission is allowed there.

This document names the corrective design's size-gate reduction substate
`TRUNCATING`. Only a reduction enters TRUNCATING:

- it blocks new section creation for the stream;
- it performs byte-range-lock arbitration and the MM truncation vetoes,
  `MmCanFileBeTruncated` and the mapped/image-section vetoes;
- it completes every fallible flush/purge step before SQ publication.

A veto returns USER_MAPPED_FILE locally with no ReqId, grant, digest, or
SQE. Extensions and VDL advances use the common gate and size epoch but skip
all reduction-only MM and flush/purge work. Blocking resources are released
before provider execution while the logical gate and FCB rundown remain
held. Terminal reentry installs the already-validated SizeState and performs
only nonfailing cache-size update and gate-release work. The kernel never
discovers a new fallible prerequisite after an irreversible provider size
change.

A wait or resource drop invalidates the captured size epoch and repeats the
size decision if state changed; the closed AdvanceOnly adapter is the only
path that bypasses ordinary oplock arbitration, because its originating
cached WRITE already underwent the required arbitration.

### 3.4 The paging sequencer

Each FCB embeds a small volatile paging-WRITE sequencer header protected by
the sequencer spin lock of section 1. For each nonzero paging WRITE,
dispatch first performs only checked extraction of the immutable native
`[offset, end)` range, then attempts to claim one bounded `WriteIrpContext`.
If that claim fails, it takes the sequencer, allocates a checked
monotonically increasing nonzero issue, records the complete range as an
immediately terminal INSUFFICIENT_RESOURCES failure through the
allocation-free ledger fallback, advances the prefix if possible, and only
then completes the IRP. If the claim succeeds, the same critical section
allocates the issue and inserts the context into the intrusive ordered
active set. Only after that linearization may dispatch validate the incoming
MDL, reserve the common quota ticket, map pages, allocate or claim any
remaining resource, pend, queue, allocate a ReqId/grant, or publish an SQE.
Every structural MDL, quota, context-tail, mapping, cancellation, and later
resource failure terminalizes that issue and records all unproven bytes
before completion. The context-pool claim is therefore the only fallible
attempt before ordinary issue installation, and no paging WRITE with a valid
extracted range returns an unnumbered failure. Issue exhaustion terminalizes
the mount before reuse.

The sequencer retains `last_issued` and an ordered set containing exactly
the nonterminal issues; the contiguous terminal prefix is `last_issued` when
the set is empty, or `minimum_active_issue - 1` otherwise, recomputed on
every terminal removal, so out-of-order completion needs no retained
terminal table entry. The failure ledger (two inline interval slots, bounded
overflow nodes, and the inline UNKNOWN accumulator) is updated only under
the sequencer, and nothing allocates while the sequencer is owned: a
terminal update may preclaim at most its bounded reserve nodes before
entering the size gate/sequencer, and any update needing more merges into
the inline UNKNOWN span. Memory pressure makes the proof more conservative;
it never drops it and never allocates under the lock. Waiter absence,
timeout, CLEANUP, fence, and ATTACH never discard or normalize a failure.

### 3.5 The AdvanceOnly CSQ

AdvanceOnly admission first reserves its count-only ticket by checked CAS in
fixed global, mount, then FCB order, then allocates a nonpaged
`AdvanceIrpContext` with an embedded nonsignaled completion gate and
distinct intrusive `csq_link` and `sequencer_link`. Allocation or any
partial reservation failure rolls back everything in reverse order and
completes INSUFFICIENT_RESOURCES with zero information before pending or
visibility. Its closed owner states are:

| Owner state | Meaning | Exits to |
|---|---|---|
| INSERTING | created under the sequencer; the unconditional pending dispatch-return decision is stored; `IoMarkIrpPending` has run; `IoCsqInsertIrpEx` is called in fixed `sequencer -> CSQ` order | BARRIER_WAIT on successful insertion; TERMINAL on rejection or an already-claimed cancellation |
| BARRIER_WAIT | linked into the nondecreasing-fence FIFO with its immutable `last_issued` snapshot as fence; carries no FCB resource, application request slot, grant, or size gate; later WRITE admission does not extend its fence | RESOURCE_READY by the O(1) barrier-wake CAS; TERMINAL by cancellation or teardown |
| RESOURCE_READY | the terminal prefix covers its fence; the preallocated resource worker is queued; the IRP deliberately remains in the CSQ and stays CSQ-cancellable | a local terminal decision, POST_CLEANUP_HELD, or ADMITTING |
| POST_CLEANUP_HELD | `CLEANUP_PENDING` was observed at revalidation; private resources are rolled back and the context parks on the stream-held FIFO, still in the CSQ, until CLEANED PAGING_ONLY readiness returns it to RESOURCE_READY | RESOURCE_READY; TERMINAL |
| ADMITTING | `IoCsqRemoveIrp` succeeded in `sequencer -> CSQ` order, the standard cancel-spin-lock handoff ran, and the ordinary mutation cancel routine plus the retained-operation registry entry were installed before the sequencer was released; ownership never returns to the CSQ | the ordinary retained-operation terminal machinery |
| TERMINAL | the single terminal owner is claimed (rejection, CSQ_CANCEL, a local candidate, or teardown); completion, refund, and free happen only after every lock is released | -- |

From `IoMarkIrpPending` onward dispatch always returns STATUS_PENDING,
including insertion rejection or synchronous observation of an
already-cancelled IRP. The cancel callback only CAS-claims TERMINAL via
CSQ_CANCEL and queues the context to a deferred PASSIVE list; it never
completes, frees, refunds, or touches sequencer state. `CsqRemoveIrp`
unlinks only `csq_link`. A deferred cancel worker first waits for the
embedded completion gate, acquires the sequencer, removes `sequencer_link`
from BARRIER_WAIT, RESOURCE_READY, or POST_CLEANUP_HELD if still present,
detaches any private-resource rollback, and releases the lock before
completion/refund/free. Wake, resource handoff, cancellation, and teardown
use the one owner CAS, so no path can leave a freed context on a waiter
FIFO. Stream close and terminal teardown first close admission under the
sequencer, then use sequencer-to-CSQ removal and the same deferred unlink
protocol; no insertion can appear after their drain snapshot.

The RESOURCE_READY worker first acquires the size gate, then the sequencer,
snapshots SizeState/ledger, and computes
`target_vdl = min(EndOfFile, current file_size)`. A target at or below the
retained VDL is the SUCCESS/zero local candidate even when unresolved
evidence exists above VDL; otherwise the lowest-issue unresolved/UNKNOWN
interval intersecting `[current valid_data_length, target_vdl)` is the local
failure candidate. For a local candidate the worker removes the IRP from the
CSQ and CAS-claims terminal ownership in the same lock order; cancellation
that already removed it wins. It releases every lock before completion and
refund and emits no mutation SQE.

If mutation remains necessary, the worker releases both locks without
changing CSQ membership and acquires the application slot, ApplyReserve,
grant, digest, and every other fallible resource outside the size gate
(section 2). It then reacquires the size gate and the sequencer in the
section-1 order, revalidates the complete SizeState/epoch and the stream
publication gate, and either proceeds to ADMITTING, parks as
POST_CLEANUP_HELD, or rolls its private resources back to the cancellation
winner. The context is continuously visible either in CSQ/sequencer state
or in the ordinary retained-operation registry; cleanup, close, and
teardown cannot pass through a direct-ADMITTING gap.

After ADMITTING, the surviving mutation canonicalizes to the existing
SET_VALID_DATA_LENGTH wire mutation with `new_vdl = target_vdl`, the
revalidated size epoch, every wire flag zero, and outer `ccb_sequence` zero
under the closed stream-lane authority of 04-object-model.md; the
`MutationV2` wire form is defined in 03-messages.md. The ticket plus the
referenced FCB/mount/rundown objects transfer with the owner state and are
refunded once by the eventual terminal owner. A recoverable session fence is
not terminal for this path: preceding writes and the waiter remain through
ATTACH. Mount teardown wakes every waiter with the operation class's
registered teardown failure.

### 3.6 The stream-admission gate

Each FileObject with stream authority owns one FCB-referenced
stream-admission gate and rundown that survive CCB cleanup. The closed-lane
admission rules (KernelMode paging READ/WRITE with the wire `PAGING` flag,
or AdvanceOnly canonicalized to SET_VALID_DATA_LENGTH; outer `ccb_sequence`
zero with nonzero `kernel_open_id`) are 04-object-model.md's contract; this
gate is where they are enforced in lock terms:

- At CLEANUP linearization, stream work already handed to ADMITTING or
  provider-visible joins the frozen predecessor set. A paging/AdvanceOnly
  request arriving afterward obtains its normal bounded quota/context, is
  marked POST_CLEANUP_HELD under the stream gate, and reserves no
  application slot or SQE until CLEANED and paging authority are ready; it
  does not extend the frozen predecessor count or starve CLEANUP.
  Paging-WRITE issue assignment and failure-ledger recording still occur
  before this hold, so quota/resource failure is represented and a later
  AdvanceOnly cannot cross it. Successful CLEANUP establishes PAGING_ONLY
  readiness before releasing any POST_CLEANUP_HELD work, and releases held
  stream work in FIFO order; a fence retains it for PAGING_ONLY replay.
- Native CLOSE, accepted only after CLEANUP_DONE, enters
  `CLOSE_PENDING(DRAIN_STREAM)` under the stream gate, closes further
  paging/AdvanceOnly admission, and snapshots every admitted stream
  operation, RESOURCE_READY waiter, and journal recovery phase. BARRIER_WAIT
  is included as an admitted stream waiter; POST_CLEANUP_HELD is included
  and must be released under PAGING_ONLY authority; each either reaches its
  frozen fence or terminalizes through the same CAS. CLOSE reserves no
  application slot before that count/rundown reaches zero.

### 3.7 The BOUND_RECONCILING ordering protocol

While the mount is BOUND_RECONCILING, classification and every later native
lifecycle transition first acquires the lifecycle-admission gate shared,
then its per-open gate, and registers a unit in the mount recovery-work
counter before releasing the gates in reverse order. No path may hold a
per-open gate while acquiring the lifecycle-admission gate. ACTIVE
publication takes the lifecycle-admission gate exclusively, closes
registration, then acquires and rechecks each classified per-open gate one
at a time in the same `lifecycle-admission -> per-open` order; it commits
only when every classification and the counter are satisfied.

Each open has one idempotent registered-unit bit; consumption clears it
exactly once, and checked u64 overflow terminalizes the mount rather than
wrapping. A transition waiting for shared admission that observes ACTIVE
after the exclusive closer releases follows ordinary ACTIVE rules and
registers no stale unit. A cleanup that linearizes before closure is barrier
work; one that loses closure starts after ACTIVE under ordinary rules.
Consequently no cleanup can fall between per-open classification and
READY/ACTIVE publication.

The retained recovery publications of the ATTACH open barrier (DRAIN_REPLAY,
predecessor recovery, PAGING_ONLY replay) are legal in BOUND_RECONCILING
despite the ban on new semantic requests; a DETACH that observes
BOUND_RECONCILING returns DEVICE_BUSY without disturbing the retained GRACE
deadline or barriers (section 11).

## 4. APPLYING and the domain locks

### 4.1 ApplyReserve

Every operation that can commit provider state owns one complete nonpaged
`ApplyReserve` before the first semantic SQ sequence Release. CREATE obtains
it before PREPARE_OPEN; WRITE and MUTATE obtain it before their semantic
request. It contains all typed blank FCB/cache, namespace, link, and open
objects, update shadows, private maximum committed-result storage, one blank
local-notification descriptor/rescan fallback, known-object references, and
an inline deduplicated canonical lock vector. Variable names, security
descriptors, request bytes, and write bytes are also immutable retained
storage before Release.

`MAX_APPLY_DOMAINS_PER_OPERATION = 6`
(`fsring-abi/src/validate/messages.rs`); the exact worst-case domain counts
are:

```text
COMMIT_OPEN: FILE=1, DIRECTORY_NAMESPACE=1, LINK=1, OPEN=1
WRITE and non-namespace MUTATE except SET_BASIC_INFO: FILE=1
SET_BASIC_INFO: FILE=1, OPEN=1
RENAME without replacement: FILE=1, DIRECTORY_NAMESPACE=2, LINK=1
RENAME with replacement:    FILE=2, DIRECTORY_NAMESPACE=2, LINK=2
LINK without replacement:   FILE=1, DIRECTORY_NAMESPACE=1, LINK=1
LINK with replacement:      FILE=2, DIRECTORY_NAMESPACE=1, LINK=2
UNLINK:                     FILE=1, DIRECTORY_NAMESPACE=1, LINK=1
```

Aliases reduce the used count but never the prepublication reservation. One
domain slot guarantees every blank/update object needed for that domain, so
no result-dependent growth is possible. Admission obtains the reserve from a
bounded nonpaged lookaside-backed pool, cancel-safely; unavailability queues
only the existing IRP under normal `max_inflight` admission or completes
INSUFFICIENT_RESOURCES before any ReqId/digest/SQ/PREPARED visibility. The
retained logical operation owns the reserve through cancellation after
publication, fencing, ATTACH/QUERY_OP recovery, APPLYING, local notify
delivery/rescan, and ACK retirement; it cannot be borrowed, reclaimed, or
downgraded.

### 4.2 COMMITTED_VERIFIED closes fallibility

Returned identities only bind reserved blanks or, under the identity-table
lock, select an already-live object whose lifetime reference is obtained by
an infallible reference increment; a tearing-down or missing object is
replaced by the reserved blank atomically. After COMMITTED_VERIFIED there is
no allocator, growable container, object creation, rundown acquisition that
may fail, provider access, or other fallible resource acquisition of any
kind. Precise path/security work after APPLYING uses the preallocated
per-ring scratch and may conservatively choose rescan; it can never roll
back a committed operation.

### 4.3 The domain-lock order

The kernel enters COMMITTED_VERIFIED only if the complete prepublication
ApplyReserve is still attached. It binds returned identities to that
reserve, resolves existing live objects without fallible acquisition, and
sorts the reserve's fixed deduplicated lock vector by
`(FileId.hi, FileId.lo, domain_kind, LinkId.hi, LinkId.lo)` where the
domain kinds are `FILE_STATE = 1`, `DIRECTORY_NAMESPACE = 2`,
`LINK_STATE = 3`, and `OPEN_STATE = 4`. It holds no session, ring,
mount-control, or operation-state lock while acquiring every listed domain
lock exclusively in that order. Readers take the corresponding domain lock
shared; a reader spanning domains uses the same order. Writers release all
locks only after the whole relation is visible, so no observer can see half
a rename, link, unlink, or replacement.

### 4.4 APPLYING

With the domain locks held, the kernel takes the operation state gate,
revalidates COMMITTED_VERIFIED and all retained provenance, then enters the
internal transient APPLYING state. A changed phase or provenance releases
the locks and restarts or fails closed; it never applies stale prework.
APPLYING performs one fully prevalidated and infallible state transition,
applies any retained SetBasic CCB policy delta under OPEN_STATE, installs
the exact local-notification descriptor (or NOT_DUE), and enters
APPLIED_NOTIFY_PENDING before releasing the state gate and then the domain
locks in reverse order. No fallible allocation, parsing, lock/rundown
acquisition, or provider access is legal inside APPLYING. The fence holds no
conflicting session/control lock while waiting for the state gate, so it
cannot form a lock cycle; it observes only the pre-apply or complete
post-apply relation. Neither CQ consumption nor recovery can re-enter
APPLYING.

Outside every domain and ring lock, the detached PASSIVE notification worker
either reports the staged event through the driver-owned queue of
05-irp-dispatch.md or atomically increments and uses a rescan generation. A
fence may win that coverage but cannot discard the descriptor as silence.
The source IRP and ACK_RESULT publication wait for
DELIVERED/COVERED_BY_RESCAN; post-commit cancellation does not suppress the
event, and a racing fence covers every STAGED descriptor with its new
generation. The ordinary completion CQ head may be released after private
candidate capture; causality is tied to verified apply, not transport-head
lifetime.

## 5. The one-terminal-owner CAS registry

### 5.1 The refund law

Every direct-I/O admission produces one nonpaged quota ticket storing the
exact charge and the referenced global/mount/I/O-owner and optional
class-budget owners. Once the IRP may be visible to cancellation or a queue,
that ticket follows the one terminal-owner CAS; losing paths never refund
it. The charge survives READ/WRITE chunking, QUERY_SECURITY recovery,
internal QueryDir batches, every recoverable GRACE/ATTACH, notification
FANOUT, and deferred completion. A notification fence is terminal and
refunds; a restart-eligible QueryDir/READ/WRITE/QUERY_SECURITY fence retains
the ticket through reissue. The terminal owner refunds exactly once only
after the last driver MDL/system-VA access and after `IoCompleteRequest`
returns; ticket references keep I/O-owner/mount budget objects and driver
rundown alive through that refund.

### 5.2 The registry

Every terminal arbitration in the driver is one CAS with one owner. The
closed registry is:

| Terminal arbitration | CAS owner state | Competing claimants | Exact rundown/refund point |
|---|---|---|---|
| direct-I/O quota ticket (section 5.1) | the request's single terminal owner | completion, cancellation, fence, teardown | after the last driver MDL/system-VA access and after `IoCompleteRequest` returns; ticket references keep budget objects and driver rundown alive through the refund |
| per-request semantic state (section 9) | the single terminal owner recorded with `semantic_may_be_visible` and `cancel_requested` under the one state lock | a stable matching CQ candidate, a registered provider CANCELLED completion, a session fence after its stable-prefix drain | no slot, token, or grant is reused until the owner and all mapping rundown finish; the ticket refunds per section 5.1 |
| journaled candidate capture (section 9) | CANDIDATE_CAPTURE then FAILURE/SUCCESS/INVALID_CANDIDATE installed under the state gate | CQ consumer, session fence (which waits for any capture in progress) | candidate installation precedes CQ-head Release, old-ReqId invalidation, and grant release; ACKNOWLEDGED is installed before its CQ-head Release and the logical slot retires only after rundown |
| ENTER SQ wait (section 5.3) | the sole `sq_wait_owner` bit | cancellation, timeout, fence -- each arbitrates the bit exactly once | the pure SQ-role completion clears `sq_wait_owner` after constructing its fixed output and before dropping its rundown; it never creates a detached semantic handler |
| ENTER CQ role (sections 5.3, 7) | the `cq_enter_owner` bit plus, per captured record, the record's semantic terminal owner | the normal drain, the `DETACHED_HANDLER` continuation, the fence | the normal handler finalizes the ENTER prefix/tail, releases every domain/state lock, decrements detached rundown, clears `cq_enter_owner`, and releases ring/session/mount rundown before completion; a fence-created handler releases only its embedded work-owner and detached rundown |
| change-notify CSQ IRP (section 5.4) | the first successful `IoCsqRemoveIrp`/`IoCsqRemoveNextIrp`, or the cancel callback's CSQ_CANCEL claim | cancellation, CCB CLEANUP, a normal event, overflow, the session fence | every terminal owner retains the notify quota ticket through its last MDL access and completion, then refunds it exactly once per section 5.1; the deferred worker completes only after the dispatch-side Release marker proves the outer state lock is gone |
| AdvanceOnly context (section 3.5) | the one owner CAS over INSERTING/BARRIER_WAIT/RESOURCE_READY/POST_CLEANUP_HELD/ADMITTING/TERMINAL | barrier wake, resource handoff, CSQ_CANCEL, rejection, stream close, teardown | completion, refund, and free happen only after `sequencer_link` removal and full lock release; after ADMITTING the ordinary retained-operation owner performs all later arbitration |
| paging-WRITE active context (section 3.4) | the issue's terminal recording under the sequencer | completion, structural failure, cancellation, teardown | the pool charge returns after removal from the sequencer and the last IRP/MDL access; mount or FCB teardown drains every active node before releasing the embedded header |
| DETACH / mount-lifecycle terminal (section 11) | the mount lifecycle terminal-owner CAS claimed under the closed exclusive lifecycle-admission gate | clean DETACH, grace expiry, protocol abort, irreversible teardown, unload | after the noncancelable drain of all mappings/PT/IRPs/users and the TERMINAL publication (or volatile destruction); exactly one SUCCESS winner |
| PT acknowledgement (sections 5.5, 10) | PT_ACK_UNSENT -> PT_ACK_MAY_BE_VISIBLE -> PT_ACKNOWLEDGED under the shared notification/PT state gate | ack publication, session fence, teardown | PT_ACK_UNSENT is installed before the notification CQ head or credit is released; PT_ACKNOWLEDGED is entered before CQ-head Release; heavy phase/rundown state releases afterward while the bounded lane high-watermark and latest tuple remain |
| session fence (section 7) | the fence's per-record preallocated semantic terminal owner, installed under the normal state gate | in-flight ENTER continuations, detached owners, late CQ candidates | the fence completes the remaining session/mapping rundown and discards old views only after every owned prefix record and detached owner has finished; it does not wait for unrelated durable journal terminal state |

### 5.3 The ENTER role owners

ENTER has two independent bounded per-ring roles: one CQ-drain owner and one
SQ-wait owner. Atomic per-ring `cq_enter_owner` and `sq_wait_owner` bits
admit the two roles; a second call for the same role returns DEVICE_BUSY,
while one pure WAIT and one pure DRAIN may run concurrently. The CQ bit
stays set across CQ work, any detached handler, its SQ readiness poll, and
final output construction; the SQ bit stays set only across its poll/wait
and output construction. Both take mount-wide shared admission rundown.

The SQ wait is the canonical daemon wait of section 2 and is level-triggered
through a seqlock, never a bare poll-then-wait: each ring has a nonpaged
manual-reset `sq_ready_event`, a private nonwrapping u64
`sq_publish_generation`, and the sole `sq_wait_owner`. After the SQ
cell/tail Release publication, every successful kernel SQ producer
Release-increments the generation and sets the event. The waiter snapshots
the generation with Acquire, polls readiness/terminal state, and, only if
still empty and live, clears the event; it then Acquire-reloads the
generation and repeats the SQ/terminal poll before entering its cancel-safe
wait. A publication before the clear is found by the generation recheck, one
after the clear either changes the recheck or leaves the event signaled, and
a publication after the recheck wakes the wait. Every wake loops through the
poll; readiness is never inferred from the event alone. Cancellation,
timeout, and fence compete through the ENTER terminal-owner CAS,
Release-publish their terminal state, and set the same event, so a waiter
cannot remain asleep after teardown. Only the SQ owner clears the event;
CQ-role readiness polls never do. The session is fenced before the
generation could increment past `u64::MAX`. Bounded validation that never
yields a stable record returns `CQ_CONTENDED` (02-transport.md), never a
spin without returning control.

The configured semantic-owner bound is
`max_inflight + 3*ring_count + 1 <= MAX_INFLIGHT + 3*MAX_RING_COUNT + 1 =
16777216` (`MAX_INFLIGHT = 16777023` and `MAX_RING_COUNT = 64` in
`fsring-abi/src/limits.rs`); every such owner reuses its application,
per-ring system, or global-system state. At most one inline
unacknowledged-NOTIFY continuation exists in each outstanding CQ-role
ENTER, so the total execution-continuation bound is 16777280 at maximum
topology, and live ENTER IRP contexts are separately bounded by
`2*ring_count <= 128`. Fence processing folds further unacknowledged
notifications into its one conservative cold-invalidation state instead of
materializing another owner. SQ waiters create no semantic owner.

A kernel implementation that guards its per-ring state with a spin lock nests
those guards in one fixed order. Let `R` be the set of ENTER roles the caller
holds: exactly `{SQ wait}` for a poll or wait, `{CQ consumer}` for a
synchronous CQ-only drain, or both together for an authenticated readiness
resume, whose SQ lease and derived CQ token belong to one request. The only
admitted nestings are `R` -> per-ring spin lock, `{R, per-ring}` -> the
session-wide grant spin lock, `{R, per-ring}` -> the global IRP cancel spin
lock, and `{R, per-ring, grant}` -> the cancel spin lock. A per-ring spin lock
is never taken with `R` empty, because a per-ring guard with no role names a
ring nobody is speaking for; the grant lock is never reached except through an
already-held per-ring guard, which is what keeps two rings from forming
overlapping mutable views of one session-wide grant table; and a grant hold with
no per-ring guard never reaches the cancel lock. The registry spin lock is
released before any of these are taken. Cancel remains a terminal leaf, and
section 6's no-completion rule and section 1's no-work-under-a-spin-lock rule
apply to both new positions unchanged.

### 5.4 Change-notify terminal owners

The driver owns every IRP_MN_NOTIFY_CHANGE_DIRECTORY(_EX) IRP in its own
IO_CSQ (05-irp-dispatch.md); no FsRtl opaque notify registration exists.
Terminal ownership of a queued IRP is the first successful
`IoCsqRemoveIrp`/`IoCsqRemoveNextIrp`, and the removal winners are closed:

| Removal winner | Status | Information | Registration effect |
|---|---|---:|---|
| CSQ cancellation callback | CANCELLED `0xc0000120` | 0 | none |
| CCB CLEANUP | STATUS_NOTIFY_CLEANUP `0x0000010b` | 0 | terminal CLEANED |
| normal event | SUCCESS | exact packed bytes, or 0 for a zero-length signal-only IRP | batch cleared after fan-out |
| buffer/path/security-proof overflow | STATUS_NOTIFY_ENUM_DIR `0x0000010c` | 0 | accumulator cleared, ordinary marker consumed |
| session fence | STATUS_NOTIFY_ENUM_DIR `0x0000010c` | 0 | registration cleared, post-fence marker retained |

Because an already-cancelled insertion may synchronously invoke
`CsqCompleteCanceledIrp`, that callback never calls IoCompleteRequest,
frees a context, or touches registration state: it only CAS-claims terminal
owner CSQ_CANCEL and pushes the preallocated `NotifyIrpContext` onto a
lock-free deferred-completion list. The deferred PASSIVE worker cannot
complete until the dispatch-side Release marker (the embedded completion
gate signaled after dispatch drops notification state) proves the outer
state lock is gone. The terminal-owner CAS makes every path complete
exactly once, and every terminal owner retains the quota ticket through its
last MDL access and completion, then refunds it exactly once by section
5.1.

### 5.5 PT acknowledgement owners

There is exactly one pending PT acknowledgement-required notification per
lane: `MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING = 1`. After privately
copying and validating the pending notification, the kernel requires the
exact next ordinal, performs the route-revoke or external-safety
transition, advances the lane high-watermark/latest tuple, and installs
PT_ACK_UNSENT under the shared notification/PT state gate before releasing
the notification CQ head or credit. Publishing `PNotifyAck`
(03-messages.md) uses the owning ring's dedicated system ReqId/SQ lane and
a fresh generation; the kernel enters PT_ACK_MAY_BE_VISIBLE before any
SQ/producer Release, and rollback requires locked proof of nonvisibility. A
stable exact SUCCESS CQE enters PT_ACKNOWLEDGED before CQ-head Release.
Heavy phase/rundown state may then be released, but the bounded lane
high-watermark and latest tuple remain (section 10).

## 6. No completion under a lock

There is no IoCompleteRequest under a ring token, domain/FCB/CCB lock, notification gate, or mount rundown.

The rule specializes per subsystem:

- A handler created by a normal ENTER finalizes the already-zeroed ENTER
  prefix/tail, releases every domain/state lock, decrements detached
  rundown, clears `cq_enter_owner`, and releases ring/session/mount rundown
  before `IoCompleteRequest`. A fence-created semantic handler has no ENTER
  IRP; after the same semantic terminal transition it only releases its
  embedded work-owner and detached rundown. A standalone nonpaged
  completion-owner reference protects only the IRP, SystemBuffer,
  FileObject, and DeviceObject during the normal-ENTER final call and never
  dereferences mount state.
- On the change-notify side, privilege and access checks, allocation and
  free, waits, user-buffer copies, and `IoCompleteRequest` occur under
  neither the notification-state push lock nor the CSQ spin lock.
  No notify completion occurs under a ring token, CSQ/state/FCB/domain/session lock, and every subject/IRP/context has one release owner.
- Deferred completion workers always wait for the dispatch-side Release
  marker before touching an IRP, so no completion races the dispatch path
  that still owns a state lock.
- The AdvanceOnly and paging-WRITE paths complete, refund, and free only
  after `sequencer_link`/`csq_link` removal and full lock release (sections
  3.4, 3.5).
- The sole-consumer token discipline of section 7 keeps `IoCompleteRequest`
  out of every token-owning region by construction.

## 7. The session-fence order

### 7.1 The exact step order

A session fence has a closed old-CQ disposition before any old view is
discarded. Its steps are exact and ordered:

1. Its state transition atomically blocks new filesystem I/O and SQ
   publication, closes ENTER admission on every ring, revokes the old
   daemon's producer authority, and signals every outstanding ENTER to
   leave its wait. The notify-admission gate closes atomically with ENTER
   admission (section 8).
2. It removes the old daemon's writable producer mappings and waits only
   the producer publication/mapping-capture rundown needed to prove that no
   later CQ Release is possible. It does not yet wait for ENTER
   continuations or detached workers.
3. It acquires every per-ring sole-consumer token in increasing ring-index
   order; this waits out any normal capture critical section and prevents
   another one from starting.
4. With no writer or other consumer left, it retains all tokens while it
   walks each ring's stable CQ prefix in order, at most `cq_capacity`
   cells, using one SETUP-preallocated `MAX_NOTIFICATION_CREDIT_SIZE`
   scratch buffer. Each stable completion, PROTOCOL record, and
   acknowledgement-required NOTIFY is privately captured, assigned its
   preallocated semantic terminal owner under the normal state gate, and
   CQ-head Released. Unacknowledged notifications are validated and folded
   into the fence's conservative cold-invalidation state.
   No domain/FCB/CCB/namespace lock, access check, callback, or blocking action runs while a token is held.
   A fence-consumed notification credit is retired with the old section
   rather than returned through ENTER; ATTACH creates and returns a
   completely fresh credit pool. The walk stops at the first unready
   sequence because no later cell is a published prefix member; it never
   skips a cell or interprets bytes after the first gap.
5. Only after every stable prefix has been owned and all tokens have been
   released does the fence queue the newly installed work and wait for
   every pre-existing or new shared ENTER continuation and detached
   semantic owner that references the old CQ, grants, or views. Those
   workers may take ordinary locks but cannot republish into the closed
   session.
6. The fence then completes the remaining session/mapping rundown and
   discards the old views.

This order admits no owner after the wait snapshot and cannot deadlock a
worker behind a retained CQ token; it does not wait for unrelated durable
journal terminal state. A fence wake before any CQ commit completes the
ENTER with INVALID_DEVICE_STATE and zero output; after the first commit,
ENTER returns SUCCESS with exactly its committed prefix and credits.

### 7.2 The sole-consumer token and DETACHED_HANDLER

Only the admitted CQ owner takes the ring's sole-consumer token, and that
physical token protects only cursor/credit operations: stable cell capture,
bounded private validation, semantic ownership installation, credit
claim/refresh or retirement, and CQ-head Release. It is never held while
acquiring an FCB/CCB/namespace/domain lock, running an access check or
notification callback, waiting for SQ, or completing an IRP.

If a captured record needs such work, the token owner first installs a
complete preallocated `DETACHED_HANDLER` descriptor and terminal owner
under the record's state gate, increments the mount/ring detached-handler
rundown, performs the CQ-head Release, and stops this ENTER's drain. The
work item and descriptor are embedded in the ENTER context or the retained
request/system-lane state; CQ handling never allocates them. For a
COMMITTED operation the descriptor contains the retained COMMITTED_VERIFIED
operation and ApplyReserve; for an external notification it contains the
complete captured event and claimed credit. This state is sufficient for a
racing fence either to let the handler finish or to satisfy it by
conservative overflow. The owner then releases the physical token and
performs domain locking, apply, notify delivery, or access checks. No other
CQ-role ENTER can execute on that ring while `cq_enter_owner` is set, even
though the token is free; the independent SQ waiter may remain active.

### 7.3 What the fence guarantees to caches and PT

Draining a stable prefix cannot prove that a provider died before an
intended notification Release. Therefore, before entering recoverable
GRACE, the fence also suspends every PT fast path and conservatively
invalidates all clean provider-derived data, name, negative-name,
directory, size, security, and coherency cache state for the MountId
(07-cache-mm.md carries the deep cache semantics). Dirty/paging writes
and journaled operations remain blocked and follow their retained recovery
states; they are not silently
discarded. If cache-section purge, mapped-section rundown, or PT rundown
cannot be proven complete, the mount enters deterministic teardown instead
of ATTACH. Thus an ordinary INVALIDATE, RESIZE, or DIR_CHANGE that was
never stably published cannot leave stale cache visible in the new session.

## 8. The notify fence and rescan markers

The mount owns a nonzero, nonwrapping `notify_fence_generation`. The
notify-admission gate closes atomically with ENTER admission, independently
of which DIR_CHANGE records were in the stable prefix. The notify fence
order is exact: close admission, signal workers/ENTER, wait rundown, update
notification state, remove via IO_CSQ, release locks, then complete.

- The fence increments `notify_fence_generation`, waits notification-event
  rundown with no FCB/session/ring/notification lock held, clears every
  registration and accumulator, and removes each still-queued mount IRP
  through IO_CSQ.
- Each successful removal has one completion owner and returns
  `STATUS_NOTIFY_ENUM_DIR = 0x0000010c`, zero information, and untouched
  output. A racing request that observes the closed gate receives the same
  result without queueing.
- Every pre-existing directory CCB retains a post-fence rescan marker; its
  first request after ATTACH returns the same status and advances the
  marker even if an event owner completed an older IRP just before the
  fence. A new post-ATTACH CCB starts at the current generation. The marker
  check occurs after safe output preflight but before first-registration
  resource commit, and CLEANED takes precedence for a new request.
- Generation exhaustion terminalizes the mount rather than wrapping.
- This overflow outcome is installed before GRACE becomes externally
  visible, so an unpublished provider change cannot be reported as silence.

Lock discipline on this path repeats section 1: the only nested queue order
is the notification-state push lock followed by the CSQ spin lock, no path
takes the reverse order, and namespace/domain locks produce referenced
topology/security snapshots before notification-state acquisition. Workers
hold mount and registration rundown, and section 5.4's removal-winner CAS
guarantees exactly one completion owner per IRP.

## 9. Cancellation concurrency

### 9.1 The one shared state lock

Every retained semantic request, including READ, FLUSH, all QUERY forms,
QueryDir, and the journaled operations, has one state lock shared by
cancellation, SQ publication, CQ consumption, and the session-fence
snapshot. The retained state records `semantic_may_be_visible`,
`cancel_requested`, and a single terminal owner.

Before any Release operation can make the semantic SQ record or its
producer position observable, the publisher sets `semantic_may_be_visible`
under the lock. Cancellation observed before the transition wins and
releases everything. Cancellation observed at or after it is
post-publication even if the daemon has not yet consumed the cell. A failed
reservation may roll the bit back only while the same lock proves that no
SQ cell or producer state was ever observable and no fence snapshot
intervened; otherwise recovery takes the conservative published path.

### 9.2 Nonjournaled arbitration

For a nonjournaled/observational request, prepublication cancellation
completes locally. Postpublication cancellation records `cancel_requested`,
publishes at most one same-ring `PCancel` through the control reserve, and
retains the native IRP, ReqId generation, every grant/mapping, and request
bytes. A locked CAS selects exactly one terminal observation: a stable
matching CQ candidate, a registered provider CANCELLED completion, or a
session fence after its stable-prefix drain. A matching CQ captured first
wins with its validated outcome; CANCELLED captured first completes
cancellation. If a fence sees no candidate, pending cancellation completes
CANCELLED; otherwise a restart-eligible observation remains retained for
exact reissue after ATTACH, while direct teardown completes its registered
terminal failure. No slot, token, or grant is reused until that owner and
all mapping rundown finish. QueryDir additionally applies its
generation/cookie rules but uses this same terminal arbitration; it cannot
turn a legitimate late CQ into a stale-generation protocol fault by freeing
early.

`PCancel` (03-messages.md) is advisory and slot-free: opcode CANCEL, flags
NO_COMPLETION, outer `req_id = 0`, zero `kernel_open_id` and
`ccb_sequence`, with `target_req_id` naming the currently live semantic
ReqId and `target_session_epoch` its current session epoch. CANCEL consumes
no request-table entry, does not advance any ReqId generation, and receives
no CQE. Under the operation lock it may target only the still-live semantic
generation; candidate capture retires that target, and a session fence
forbids publication against every old-session generation. After
authenticated ATTACH and an actual exact semantic resubmission, a
still-pending cancellation may publish a new PCancel against the fresh live
generation.

### 9.3 Journaled arbitration and CANDIDATE_CAPTURE

After possible semantic publication of a journaled operation, the kernel
records `cancel_requested` but retains the OpId, digest, request
transcript, immutable inputs, and logical request slot; cancellation never
releases recovery state early. As soon as any stable CQ cell carries the
currently live semantic ReqId, the CQ consumer enters the internal
transient CANDIDATE_CAPTURE phase under the operation lock before
validating CQ kind, opcode, status, output, or payload. While still holding
the operation's rundown reference, it privately copies the complete cell,
validates every grant identity and range against immutable kernel ownership
state before dereference, copies only safely bounded referenced bytes, and
validates that immutable snapshot. It then atomically installs
FAILURE_CANDIDATE, SUCCESS_CANDIDATE, or INVALID_CANDIDATE plus the
complete snapshot under the same state gate before the CQ-head Release,
old-ReqId invalidation, or grant release. None may fall back to
NO_CANDIDATE.

A session fence shares that gate, waits for any CANDIDATE_CAPTURE to
finish, and drains any already-stable matching candidate CQ cell with the
same capture ordering before it may classify the operation as NO_CANDIDATE;
it cannot observe or publish an intermediate capture. QUERY_OP reuses the
same slot index with the next generation, every legal BTS retry does so
again (`MAX_QUERY_OP_BTS_RETRIES = 1`,
`fsring-abi/src/validate/messages.rs`), and ACK_RESULT does so after the
QueryOp completion; every old generation remains stale. QueryOp phase
transitions and ACKNOWLEDGED are likewise installed before their CQ-head
Release and ReqId retirement. Thus `max_inflight = 1` can make progress
without allocating a second application slot, while confirmations for
different logical operations may still be pipelined. Generation exhaustion
retires the slot/session rather than wrapping.

## 10. PT rundown ordering

The per-file PT state machine
`NONE -> OPENING -> ISOLATING -> PENDING -> ACTIVE -> BREAKING_CLOSED ->
REVOKED`, with the failure edge
`OPENING|ISOLATING -> CANCEL_DRAINING -> NONE`, is an ordering contract as
much as a state registry. The full PT donation/isolation/revocation
contract is 08-passthrough.md; the binding ordering constraints are:

- The backing-isolation gate is a short-hold admission gate only. The gate
  is never held while `IoCreateFileEx`, an FSCTL, MM predicate, rundown
  wait, or file-system callback can block. OPENING moves the copied path
  and immutable attempt identity into a nonpaged driver-global context,
  acquires driver rundown, and installs the path-digest exclusion before
  the blocking create; it holds no user pointer, mapped view, or
  unreferenced mount pointer. After the kernel open, the gate inserts the
  referenced FileObject and installs ISOLATING, then releases the gate
  before issuing the oplock FSCTL and MM predicates. It reacquires the gate
  and installs PENDING only if the same attempt is still ISOLATING, the
  session is still open, the oplock remains pending, and no break, fence,
  cancellation, or competing owner appeared; that PENDING publication is
  the epoch-burn point.
- Cancellation or session fencing during OPENING atomically detaches and
  completes the DONATE_BACKING IRP with CANCELLED/terminal status and
  leaves only the driver-global abandoned-open context; the worker that
  owns the blocking create later closes any new handle, removes the path
  exclusion, and releases driver rundown. Thus mount teardown never waits
  for a name open and cannot use freed mount/IRP state. Cancellation in
  ISOLATING atomically enters CANCEL_DRAINING and requests `IoCancelIrp` on
  the kernel-owned oplock IRP; because cancellation is asynchronous, only
  the lower IRP completion routine may remove the exclusion entry, handle,
  buffers, and context, transition to NONE, and queue CANCELLED completion.
  No cancel callback waits for the backing stack or completes/frees the
  lower context.
- The oplock-break owner order is fixed. The PASSIVE_LEVEL break owner
  atomically changes PT admission to BREAKING_CLOSED, then without holding
  the PT gate waits for all page-I/O, mapping, and route PT rundown. It
  revokes every grant/route, burns the accepted epoch into
  `fully_revoked_epoch`, and only after that state is Release-visible ACKs
  the break with `FSCTL_REQUEST_OPLOCK`. It never ACKs, closes the backing
  FileObject, or releases the oplock early. A malformed break, failed
  drain, or failed acknowledgement enters deterministic mount teardown.
  Only an ACK-required break permits the claim that PT is drained before
  the blocked external operation is released; a no-ACK break that permits
  incompatible access is an isolation violation that immediately blocks new
  PT, marks every affected in-flight PT result untrusted, cold-invalidates
  provider-derived cache state, and fail-stops the mount.
- Every session fence uses the same close/drain owner: it atomically moves
  any pending/live accepted epoch to fully revoked, destroys all
  grants/routes/backing references and the oplock context before GRACE, and
  retains `last_accepted_epoch`. No PT route, grant, backing reference, or
  raw handle survives into the next session epoch; ATTACH requires fresh
  donation and PT_GRANT after lane reconciliation.
- ATTACH initializes all `2 * ring_count` per-session lane-ready bits false
  and enters PT_RECONCILING; every fence clears all ready bits as well as
  all backing/grant state. No PT fast path is enabled until READY has been
  consumed for both kinds on every ring and open replay is complete; each
  file additionally requires a fresh current-session DONATE_BACKING and
  matching PT_GRANT.
- The PT ack states order exactly as section 5.5: PT_ACK_UNSENT under the
  shared notification/PT state gate before the notification CQ head or
  credit is released, PT_ACK_MAY_BE_VISIBLE before any SQ/producer Release,
  PT_ACKNOWLEDGED before CQ-head Release. A fence preserves the lane
  high-watermark/latest tuple and PT_ACK_UNSENT/PT_ACK_MAY_BE_VISIBLE,
  discards old ReqId generations, and leaves PT suspended; no fence,
  attach, detach, timeout, or credit path can lose a pending lane record or
  exceed the two-record lane bound.

## 11. Terminal-path transition table

Every terminal path in the driver is listed here with its trigger, CAS
owner, the locks it may and must not own at the decisive claim, and its
exact rundown/refund point.

| Terminal path | Trigger | CAS owner | Owned at the claim / forbidden at the claim | Exact rundown/refund point |
|---|---|---|---|---|
| cancel, never visible | cancellation observed before `semantic_may_be_visible` | the canceling path under the per-request state lock | owns the state lock only / MUST NOT complete the IRP or touch any gate under it | local completion after full reservation rollback; nothing was visible, so no ticket transfer occurred |
| cancel, possibly visible | `cancel_requested` after publication | the locked CAS among CQ candidate, provider CANCELLED, and post-drain fence (section 9.2) | owns the state lock at each observation / MUST NOT reuse ReqId, grant, MDL, or slot early | completion after the last MDL/system-VA access; ticket refunds after `IoCompleteRequest` returns; restart-eligible observations retain everything through reissue |
| journaled cancel/abort | `cancel_requested` on a journaled operation | the retained QueryOp/ABORT/ACK machine (section 9.3) | owns the state gate at each phase install / MUST NOT release recovery state early | ACKNOWLEDGED before CQ-head Release; the logical slot retires only after rundown |
| truncate veto | a byte-lock or MM veto inside TRUNCATING | the size path itself, locally | owns the size gate and FCB main/paging resources / MUST NOT have allocated a ReqId, grant, digest, or SQE | USER_MAPPED_FILE completes locally; the gate releases with no provider-visible state |
| truncate, provider path | verified provider size result | the retained size operation's terminal owner | terminal reentry owns the logical gate and FCB rundown / MUST NOT discover any new fallible prerequisite | installs the already-validated SizeState, performs only nonfailing cache-size update and gate-release work, then completes and refunds per section 5.1 |
| AdvanceOnly cancel | CSQ_CANCEL or teardown on a queued context | the one AdvanceOnly owner CAS (section 3.5) | the cancel callback owns only the CSQ lock / MUST NOT complete, free, refund, or touch sequencer state there | the deferred worker waits the completion gate, unlinks `sequencer_link` under the sequencer, releases the lock, then completes/refunds/frees |
| replay discard | session fence during REPLAY_OPEN | the per-open gate's replay terminal ownership (section 3.2) | lifecycle-admission shared then per-open / MUST NOT hold a per-open gate while acquiring the lifecycle-admission gate | every ordinary/paging replay generation is discarded; the mode-specific decision repeats on the next ATTACH; DRAIN_REPLAY cookies serve only the frozen predecessor set |
| INDETERMINATE quarantine | a provider answer that contradicts the retained phase | the retained operation, fail-closed | none beyond the state gate / MUST NOT send an ACK, apply candidate state, or replay in that MountId | the kernel blocks new mount I/O, conservatively invalidates caches, records the journal-integrity violation, and completes affected IRPs FILE_CORRUPT_ERROR with zero information only after the mount is quarantined; only bounded administrative teardown follows |
| PT break | an external oplock break on an ACTIVE donation | the PASSIVE break owner via BREAKING_CLOSED (section 10) | atomically claims admission under the PT gate / MUST NOT wait for PT rundown while owning the PT gate, and MUST NOT ACK before revocation is Release-visible | grants/routes revoked, epoch burned into `fully_revoked_epoch`, ACK sent, then context release; failure enters deterministic mount teardown |
| clean DETACH | authorized DETACH on ACTIVE/LIVE | the mount lifecycle terminal-owner CAS under the closed exclusive lifecycle-admission gate | owns the exclusive gate / MUST NOT leave a visibility gap when reopening on DEVICE_BUSY | the stable retained-blocker check runs under the closed gate (no post-check operation can appear); a clean DETACH is DEVICE_BUSY while any retained request is PREPARED/COMMITTED or any ACK is outstanding and succeeds only after the journal handshake is drained; after the claim it is noncancelable, drains all mappings/PT/IRPs/users, and publishes TERMINAL or completes volatile destruction with exactly one SUCCESS winner |
| grace expiry | the retained absolute deadline (RESTART_GRACE_TIMEOUT_MS = 30000, unbiased interrupt time) passes | the same mount lifecycle terminal-owner path | the PASSIVE lifecycle owner rechecks the deadline under the lifecycle gate / MUST NOT surface as an IOCTL timeout | expiry terminalizes the already-bound epoch through the one terminal-owner path; it is never an IOCTL timeout and no completion after expiry can reactivate the mount |
| mount teardown | protocol abort, unproven rundown, fail-stop, or grace-ineligible loss | the same lifecycle terminal-owner CAS | closes admission first / MUST NOT complete an IRP under any gate it closes | wakes every waiter with the operation class's registered teardown failure, drains all IRPs/mappings/PT/users, then destroys or terminalizes the mount |
| driver unload | service stop after all mounts are terminal | the driver-global unload owner | closes new admission first / MUST NOT wait for a name open inside any mount lock | quiesces and waits for the bounded set of driver-global abandoned-open contexts, releases every object, MDL, section, subject, IRP, oplock, work item, and rundown reference, and leaves only the two permanent BootContext objects (`\KernelObjects\FsRingBootContext-v1` and `\KernelObjects\FsRingBootContextLock-v1`) |

Three cross-cutting rules close the table:

1. Exactly one SUCCESS winner exists for any two concurrent valid DETACH
   calls; a DETACH that observes another terminal owner or an in-progress
   transition returns DEVICE_BUSY, one that observes BOUND_RECONCILING
   returns DEVICE_BUSY without disturbing its retained deadline or
   barriers, and one that observes TERMINAL, GRACE, or a noncurrent epoch
   returns INVALID_DEVICE_STATE.
2. Every terminal path's refund obeys section 5.1: losing paths never
   refund, and the terminal owner refunds exactly once after the last
   MDL/system-VA access and after IoCompleteRequest returns.
3. Every terminal path is reachable without provider cooperation. That is
   the point of this document: the daemon wait rules of section 2, the
   universal order of section 1, and the one terminal-owner CAS registry of
   section 5 together guarantee that cancellation, fencing, DETACH, grace
   expiry, teardown, and unload always terminate against a hostile, dead,
   or stalled provider.

## C4 recovered ordering and quiescence

The pending-ENTER path orders authority before publication, never the reverse.
An owned parked plan holds unclaimed terminal authority until two things have
happened: the install publishes `HandoffDoneReceipt`, and the worker takes
a CSQ dequeue receipt. Only a non-null `IoCsqRemoveIrp` return mints it, and
only the PASSIVE worker performs a noncancel dequeue -- the DPC never dequeues,
never waits, never writes output and never completes an IRP. The transient
install guards are released before the atomic transition to `HandoffDone`, so a
worker that observes the handoff cannot observe half-published state.

Timer quiescence is decided by the DDI answer, not by an assumption. `TimerState`
records where one install's timer is in its life, with `Armed` and `Running`
carrying the epoch they belong to so a DPC that arrives for a previous install is
recognised as stale. `PendingTimerCancel` is what a cancel attempt obliges the
canceller to do next, and it maps the real `KeCancelTimer` result: nothing armed
means there is no DPC owner and nothing to wait for; TRUE means the DPC was
dequeued before running, so the canceller takes the DPC owner back and does not
wait; FALSE means the DPC already ran or is running, so the canceller waits the
`dpc_exited` event and does not take the owner, because the DPC releases it on
its own way out. The canceller names the epoch its own install reserved rather
than reading it back out of the state it is validating, which is what keeps the
`NotThisInstall` refusal reachable.

`Armed` means the timer is in the queue. `KeSetTimer` runs inside the same lock
hold that publishes `Armed`, so the state and the timer queue cannot disagree;
with the insertion outside that hold there was a window in which a cancel got
FALSE from `KeCancelTimer` for a DPC nothing had queued yet, and the canceller
then waited on a signal nobody owed.

There are two waits, and they prove different things. The state rendezvous,
`wait_pending_dpc_exit`, decides on `timer_state`; the exit-signal wait,
`wait_pending_dpc_exit_signal`, decides on the dispatcher object. Neither alone
is enough, and the reason each exists is the reason the other does not cover it.

The exit event is the wakeup, not the proof. `dpc_exited` is a
NotificationEvent, and the DPC publishes `Quiesced` under the slot lock *before*
it signals outside that lock -- a gap in which the whole install can complete
and the slot be reused, leaving the set standing with no owner. So the state
rendezvous does not read the event and believe it: it takes the slot lock, reads
`timer_state`, returns on an observed `Quiesced`, and otherwise clears the
standing signal there before waiting again. Under that hold no DPC is between
its own entry clear and its exit set, which is what makes a signal found beside
a non-quiesced timer provably a previous generation's.

**Only a frame that has already cancelled may enter that rendezvous.** `Armed`
means two different things -- a deadline that has not fired, and a DPC queued
after a `KeCancelTimer` that answered FALSE -- and `timer_state` alone cannot
tell them apart. Waiting on the first blocks a `DelayedWorkQueue` thread for the
client's whole `timeout_ms`. So the rendezvous lives in the completion plan,
immediately after its `CancelTimer` stage, and nowhere else. A copy of it stood
second in the worker's roster walk, where no cancel precedes it; it could not be
correct there in either direction -- widened to `Armed` it waited on an unfired
deadline, narrowed to `Running` it never waited at all, because `Running` exists
only inside the DPC's own hold of the slot lock and no observer can see it --
and it has been removed rather than tuned.

Unload quiesces before it frees, and needs the second wait to do it. It cancels
each slot's timer and runs the state rendezvous, which returns on an observed
`Quiesced` -- but `Quiesced` is published INSIDE the lock and the DPC's last act,
`KeSetEvent(dpc_exited)`, happens after it releases. So the teardown then waits
for that signal itself, gated on `dpc_entered`: a latch, set when a DPC enters
and never cleared, so that a slot whose timer was never armed does not wait
forever on an event nothing will set. The latch is deliberately not
per-generation. Clearing it when a new install armed raced exactly the store it
guards, because an install can arm inside the window between a DPC's release and
that DPC's set.

`wait_contexts_drained` proves no *install* is outstanding by reading
`slot_state`, which says nothing about a queued KDPC, which is why both waits
run before the arena holding that KTIMER, KDPC and exit event is released.
Neither `KeRemoveQueueDpc` nor `KeFlushQueuedDpcs` exists in this image to catch
a DPC afterwards; there is no afterwards, and it is the pair of waits that makes
that sentence true rather than the first one alone.

Final publication is one total, no-lock-bearing operation. Its result never
carries a lock, so no caller can be handed a value whose drop order decides a
release; the lock is taken and released inside the operation, and the reusable
state is the last write under that hold.

Two events are signalled only after the registry lock is released:
`TerminalJoinersDrainedSignal` and the terminal outcome event. Signalling either
under the lock would wake a joiner into a lock it cannot take.

The finalizer has exactly one kick sink. Every queued finalization reaches
`queue_cell_finalizer`, which owns the cell's preallocated work item; no path
forgets a kick instead of queuing it.
