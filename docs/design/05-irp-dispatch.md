# 05 - ABI 2.1 IRP dispatch and completion contract

Status: normative for FSRING ABI 2.1. ABI major 2 is intentionally
incompatible with the earlier wire format, and minor 1 is the first
interoperable minor of that major: minor 0 is a superseded pre-release draft
and is never selected by SETUP.

The authoritative registries for this document are the unpacked crate sources
`fsring-abi/src/layout.rs`, `ids.rs`, `slots.rs`, `limits.rs`, `features.rs`,
`ring.rs`, `msgs/*`, `control/*`, `durable/*`, `digest.rs`, and `validate/*`,
together with the frozen generated header `fsring-abi/include/fsring_abi.h`.
If prose, generated archives, or an implementation disagree with those
unpacked sources, the unpacked sources win. Every wire size, alignment,
offset, opcode, registry value, status value, and quota below is transcribed
from that registry or from the Wave 11 normative tables in `02-transport.md`
and `03-messages.md`, except the native Windows adapter constants named at
the end of this block and a bounded set of named driver-behavior bounds
and kernel-side state names that the crate does not carry as named constants
and that are transcribed from the corrective design instead: the QueryDir
admission caps `MAX_QUERY_DIR_IRPS_PER_CCB`,
`MAX_PENDING_QUERY_DIR_IRPS_PER_MOUNT`,
`MAX_PENDING_QUERY_DIR_MDL_BYTES_PER_CCB`,
`MAX_PENDING_QUERY_DIR_MDL_BYTES_PER_MOUNT`, and
`MAX_QUERY_DIR_SPILL_BYTES_PER_CCB`; the AdvanceOnly and paging-WRITE
sequencer bounds (`MAX_PENDING_ADVANCE_ONLY_IRPS_*`,
`MAX_ACTIVE_PAGING_WRITE_CONTEXTS_*`, and the paging-write failure-ledger
constants); and every kernel-side state name used by this document (the
CREATE phase states, the CLEANUP/CLOSE substates, the QueryDir
`snapshot_state` registry, the change-notify delivery states, the AdvanceOnly
CSQ owner states, and the retained recovery phases including
`CANDIDATE_CAPTURE`). Native Windows adapter constants that no crate
registry, header, or Wave 11 table carries as a status value -- the
query/directory adapter information-class, directory-class, and
attribute-flag values, the derived query-only attribute mask `0x00004e10`,
and the native-adapter statuses `INVALID_INFO_CLASS = 0xc0000003`,
`INFO_LENGTH_MISMATCH = 0xc0000004`, `OBJECT_NAME_INVALID = 0xc0000033`,
`NAME_TOO_LONG = 0xc0000106`, `STATUS_NOTIFY_CLEANUP = 0x0000010b`, and
`STATUS_NO_MEMORY = 0xc0000017` (the SEH exception the shim normalizes to
`INSUFFICIENT_RESOURCES`; the bare `NO_MEMORY` token in `02-transport.md`
is a normalization input, not a carried status value) -- are likewise
transcribed from the corrective design. Every other NTSTATUS value below is a
member of the crate completion-status registries in
`fsring-abi/src/validate/messages.rs` and `fsring-abi/src/control/mod.rs` or
of the `02-transport.md` / `03-messages.md` status tables, including
`STATUS_BUFFER_OVERFLOW = 0x80000005` (crate `BUFFER_OVERFLOW`;
`03-messages.md`).

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY are normative. Correctness, memory safety, isolation, and bounded
execution are absolute requirements. A performance optimization is valid only
when it preserves every validation and lifetime rule below.

This document defines, per IRP major function, how the kernel driver admits,
validates, publishes, cancels, recovers, and completes work against the ABI
2.1 rings defined in `02-transport.md`, using the wire forms defined in
`03-messages.md`, over the object model defined in `04-object-model.md`,
under the lock and rundown order defined in `06-locking.md`. Wire-form byte
layouts are referenced, never duplicated: `PrepareOpenV2`, `CommitOpenV2`,
`AbortOpenV1`, `WriteV2`, `MutationV2`, `QueryDirV2`, `ReplayOpenV2`,
`QueryOpV2`, and `AckResultV2` are defined byte-exactly in `03-messages.md`
section 4. Cross-references into `07-cache-mm.md` through `12-test-plan.md`
resolve to those documents' normative ABI 2.1 sections.

## 1. Global dispatch model

### 1.1 Volume device flags and adapter classes

Every mounted volume device sets `DO_DIRECT_IO`, clears `DO_BUFFERED_IO`, and
finishes those flags before clearing `DO_DEVICE_INITIALIZING`. This single
choice applies to every IRP-based READ, WRITE, QUERY_DIRECTORY,
CHANGE_NOTIFY, EA, and quota path that obeys volume flags; an opcode-specific
adapter MUST NOT assume a `SystemBuffer`. Base 2.1 advertises no data
Fast-I/O callback, so cache-manager or application data Fast-I/O probes
return FALSE and fall back to these IRPs.

The dispatch adapters form three closed classes:

| Class | Majors | Buffer mechanism |
|---|---|---|
| direct I/O | READ, WRITE, DIRECTORY_CONTROL (query and notify), EA and quota paths that obey volume flags | incoming `Irp->MdlAddress` under the structural preflight below |
| buffered | QUERY_INFORMATION, QUERY_VOLUME_INFORMATION | `AssociatedIrp.SystemBuffer` per section 10 |
| neither I/O | QUERY_SECURITY | the conditional-MDL contract in section 11 |

The buffered and neither-I/O classes are not subject to the mandatory
incoming-MDL rule of this section.

### 1.2 Structural MDL preflight

For every legal nonzero native input/output range on the direct-I/O majors,
structural dispatch preflight requires, before touching any caller byte:

1. a non-null `Irp->MdlAddress`;
2. `mdl->Next == NULL` — every accepted nonzero incoming MDL is a single
   chain element;
3. checked `MmGetMdlByteCount(mdl) >= requested_length`;
4. checked range and page-span arithmetic (pointer, page-count,
   multiplication, and counter arithmetic are all checked).

The paging-WRITE ordering exception first checks only its nonzero native file
range, installs or immediately terminalizes its sequencer issue as section
9.6 defines, and then performs these MDL structural checks; every other
direct-I/O adapter completes all structural checks first. After the common
quota ticket of section 2 is reserved, dispatch requires one successful
`MmGetSystemAddressForMdlSafe` mapping before any semantic filesystem state
mutation. Paging-WRITE issue bookkeeping is not provider visibility and never
dereferences the MDL.

Mapping flags are profile-fixed: the modern profile passes
`NormalPagePriority|MdlMappingNoExecute` and additionally `MdlMappingNoWrite`
only for input-only pages, while output pages remain writable; the Win7
profile passes only `NormalPagePriority`. A missing/short/chained MDL
completes `STATUS_INVALID_USER_BUFFER=0xc00000e8`; a null mapping completes
INSUFFICIENT_RESOURCES(0xc000009a). Both use zero information, touch no
caller byte, and create no ReqId, grant, or SQE. A nonzero paging WRITE
nevertheless terminalizes its already-linearized issue and records its
unresolved range before completing any post-range structural, mapping, or
admission failure. The retained system VA never outlives the IRP-owned MDL
and is used in exactly the probed direction.

### 1.3 Zero-length rules

Zero-length behavior is opcode-specific: zero-length READ/WRITE completes
locally per section 5 and is never emitted; a zero-length change-notify
request is the signal-only registration form in section 13; queries whose
native fixed prefix is nonzero fail their documented length preflight in
sections 10 through 12. Neither profile fabricates an MDL for a zero range.
Zero-capacity QUERY_SECURITY and zero-length notify are count-only forms
only when `Irp->MdlAddress == NULL`; a nonnull MDL on either zero-range form
is `STATUS_INVALID_USER_BUFFER` with zero information before ticket
admission, irrespective of its byte count or chain.

## 2. Asynchronous admission quotas and the quota ticket

Every asynchronous IRP that retains locked caller pages — emitted READ and
WRITE, QUERY_DIRECTORY, CHANGE_NOTIFY, and QUERY_SECURITY — obeys these
common bounds from `fsring-abi/src/limits.rs`:

| Constant | Value |
|---|---:|
| `MAX_PENDING_ASYNC_IRPS_PER_IO_OWNER` | 1024 |
| `MAX_PENDING_ASYNC_IRPS_PER_MOUNT` | 16384 |
| `MAX_PENDING_ASYNC_IRPS_GLOBAL` | 65536 |
| `MAX_PENDING_ASYNC_MDL_BYTES_PER_IO_OWNER` | 67108864 |
| `MAX_PENDING_ASYNC_MDL_BYTES_PER_MOUNT` | 268435456 |
| `MAX_PENDING_ASYNC_MDL_BYTES_GLOBAL` | 1073741824 |

The I/O owner is the live CCB for ordinary requests and a referenced per-FCB
paging-budget owner for paging I/O; it remains valid through completion. The
directory and notify class caps in sections 12 and 13 are additional stricter
counters over the same ticket, not replacements for these common bounds.

The byte charge for a nonzero accepted MDL is the complete checked
locked-page span, not the requested or logical subrange:

```text
ADDRESS_AND_SIZE_TO_SPAN_PAGES(
    MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl)) * PAGE_SIZE
```

QUERY_SECURITY with an existing source MDL charges that MDL's complete span
even though it maps only a checked at-most-65536-byte partial range; without
a source MDL it computes and reserves the exact UserBuffer/capacity page span
before allocating, probing, or locking its own exact MDL. Accepted zero forms
consume one pending-IRP count but zero MDL bytes. Zero-length READ/WRITE
remains local and consumes neither. A WRITE parent ticket survives all
ordered child chunks even after its immutable snapshot is copied.

Admission reserves count and byte budgets in fixed global, then mount, then
I/O-owner order with cacheline-separated atomic CAS before
`MmGetSystemAddressForMdlSafe`, the QUERY_SECURITY probe/lock, grant or
mapping creation, request-table admission, queue visibility, ReqId
allocation, or SQ publication. Partial reservation, MDL or partial-MDL
allocation failure, or mapping failure rolls every reservation back and
returns the operation's registered INSUFFICIENT_RESOURCES result with zero
information. A QUERY_SECURITY probe/lock exception instead uses its
operation-specific `STATUS_INVALID_USER_BUFFER` result with zero information
while performing the same complete rollback. Invalid, forbidden-zero-range,
or chained MDLs also return `STATUS_INVALID_USER_BUFFER` with zero
information. No global dispatch-path lock is introduced.

The resulting nonpaged quota ticket stores the exact charge and the
referenced global, mount, I/O-owner, and optional class-budget owners. Once
the IRP may be visible to cancellation or a queue, that ticket follows the
one terminal-owner CAS registry of `06-locking.md`; losing paths never
refund it. The charge survives READ/WRITE chunking, QUERY_SECURITY recovery,
internal QueryDir batches, every recoverable GRACE/ATTACH, notification
FANOUT, and deferred completion. A notification fence is terminal and
refunds; a restart-eligible QueryDir, READ, WRITE, or QUERY_SECURITY fence
retains the ticket through reissue. The terminal owner refunds exactly once,
only after the last driver MDL or system-VA access and after
`IoCompleteRequest` returns; ticket references keep I/O-owner and mount
budget objects and driver rundown alive through that refund.

## 3. Request identity and scheduling

### 3.1 ReqId partition and reserved system slots

A ReqId is a 64-bit value composed of a 24-bit slot index and a 40-bit
nonzero, nonwrapping generation (`fsring-abi/src/ids.rs`). `max_inflight`
counts only application logical requests and uses exactly slot indices
`[0, max_inflight)`. Slot indices
`[SYSTEM_REQID_BASE, SYSTEM_REQID_BASE + 3 * ring_count)` with
`SYSTEM_REQID_BASE = 16777023` are kernel-reserved system-control entries.
For ring `r`, base `SYSTEM_REQID_BASE + 3*r` is the serialized
open-lifecycle recovery slot, base+1 is PT_ROUTE_ACK, and base+2 is
PT_EXTERNAL_SAFE_ACK. The first slot carries exactly one REPLAY_OPEN,
recovery CLEANUP, or recovery CLOSE phase at a time; ordinary same-session
CLEANUP/CLOSE remain application requests. The three system entries are
never exposed through or borrowed by application admission, and each has its
own nonzero no-wrap generation. Slot index
`GLOBAL_EXTERNAL_CHANGE_ACK_REQID = 16777215` is the one global, ring-zero
EXTERNAL_CHANGE_ACK slot with its own no-wrap generation. Application
indices, the up-to-192 ring-scoped reserved entries (three per configured
ring), and this final global entry never exceed the 2^24 ReqId index space,
which they exactly fill at the 64-ring maximum topology.

The lifecycle system ReqId is legal only for REPLAY_OPEN, CLEANUP, and
CLOSE. CLEANUP/CLOSE may use it only for a lifecycle transition retained
into BOUND_RECONCILING; REPLAY_OPEN never uses an application ReqId. An
application-range CLEANUP/CLOSE is legal only for the ordinary same-session
path. A reserved/application range, opcode, ring, mount-state, or
retained-phase mismatch is a protocol fault.

### 3.2 Control cells and the five logical classes

Each SQ has `CONTROL_SQ_RESERVE_PER_RING = 4` physical control cells that
application semantic admission may never reserve or borrow. At most
`sq_capacity - CONTROL_SQ_RESERVE_PER_RING` application semantic cells may be
outstanding. The control scheduler uses the reserve for five bounded logical
classes:

1. a retained logical request's next phase (COMMIT_OPEN, ABORT_OPEN,
   QUERY_OP, ACK_RESULT, an exact reissue) or its PCancel;
2. the serialized open-lifecycle recovery system slot;
3. PT_ROUTE_ACK;
4. PT_EXTERNAL_SAFE_ACK;
5. EXTERNAL_CHANGE_ACK on its distinct global ReqId.

At most one wire phase owns each system slot. Application control work uses a
per-ring FIFO of length at most `max_inflight`; each retained application
state embeds one intrusive ready node. Open-lifecycle recovery uses a
separate per-ring FIFO whose length is at most
`MAX_RETAINED_OPENS_PER_RING = 4096`; each retained open embeds one lifecycle
ready node, independent of whether it currently owns an application slot.
Enqueue, dequeue, and cancel/fence removal are O(1), and each node may be on
at most one matching FIFO. FIFO order is the fairness order within a class.
Strict round-robin across all five logical classes selects a class whenever
any control cell frees, then removes its head waiter, before new semantic
admission. No scheduler path scans the retained-operation table.

Because application producers cannot consume the reserve, continuous
application load cannot starve QUERY_OP/ACK/CANCEL traffic, open-lifecycle
recovery, PT acknowledgement, or external change acknowledgement. The
minimum SQ capacity (`MIN_SQ_CAPACITY = 8`) leaves four ordinary cells in
addition to the four physical control cells; five logical classes do not
require five simultaneous cells for progress.

### 3.3 The `max_inflight = 1` progress guarantee

One logical application operation occupies one request-table slot through
every wire phase it needs, each phase reusing the slot index with a fresh
nonzero generation (sections 4 and 17). Because recovery, PT, and external
acknowledgement traffic run on reserved system slots and the control-cell
reserve, `max_inflight = 1` cannot prevent open replay, lifecycle recovery,
or a PT notification handshake from making progress while that one
application slot is retained through recovery.

### 3.4 ENTER as the completion transport

The daemon consumes CQ records and publishes SQ readiness through
IOCTL_FSRING_ENTER, which has two independent, bounded per-ring roles: one
CQ-drain owner and one SQ-wait owner. `DRAIN_CQ|WAIT_SQ` is invalid; a DRAIN
call never waits and a WAIT call never consumes CQ; at most one call of each
role may be outstanding per ring, and a second call for the same role
returns DEVICE_BUSY. This split is mandatory: a provider worker may publish
an asynchronous CQ and issue a DRAIN while the dedicated SQ waiter remains
blocked, so no CQ doorbell or cancel-before-completion convention exists.
The ring algorithm, ENTER field/flag invariants, credit-reservation rules,
and the CQ_CONTENDED bounded-validation contract are defined in
`02-transport.md` sections 6 and 10; the kernel-side wait protocol
(`sq_wait_owner`, `cq_enter_owner`, the ENTER terminal-owner CAS) is defined
in `06-locking.md`. Every kernel-side CQ consumption step named in this
document (CANDIDATE_CAPTURE, QueryDir batch installation, notification
credit handling, external-change capture) runs inside an ENTER CQ drain and
installs its retained state before the CQ-head Release for that record.

## 4. IRP_MJ_CREATE

### 4.1 Control-device CREATE

The control device (`FILE_DEVICE_UNKNOWN`, `FILE_DEVICE_SECURE_OPEN`
required, SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`) accepts only a root open whose
`FileObject->FileName` is empty and whose `RelatedFileObject` is null. The
CREATE behavior is closed and uses this precedence:

| Order | Condition | Status | Information |
|---:|---|---|---:|
| 1 | `RequestorMode != UserMode` | ACCESS_DENIED(0xc0000022) | 0 |
| 2 | trailing-name, relative, or otherwise non-root create | OBJECT_NAME_NOT_FOUND(0xc0000034) | 0 |
| 3 | per-file context allocation/reference failure | INSUFFICIENT_RESOURCES(0xc000009a) | 0 |
| 4 | success | SUCCESS | 0 |

Every failure installs no file context. A successful UserMode root create
atomically captures and references the IRP requestor EPROCESS in the
per-file context before returning SUCCESS. Cleanup/close releases that
reference only after IOCTL rundown. No SETUP or ATTACH has yet occurred at
CREATE time; every trailing-name, relative, or non-root create is rejected
before a process, mount, epoch, or view can be bound to the file object. The
IOCTL registry and lifecycle behind this open are defined in
`02-transport.md` section 10 and `04-object-model.md`.

### 4.2 Volume CREATE is one logical two-phase operation

PREPARE_OPEN and COMMIT_OPEN are phases of one logical native CREATE, not
two independent application requests. The CREATE occupies one application
request-table slot from its first Prepare publication until Prepare failure
or a successful Commit/Abort and, when journaled, final ACK. Each wire phase
reuses that slot index with a fresh nonzero generation. This rule includes
PREPARE retry, COMMIT, ABORT_OPEN, QUERY_OP, ACK_RESULT, and any bounded
QUERY_OP buffer-too-small retry, so `max_inflight = 1` makes progress.
`PrepareOpenV2` and `CommitOpenV2` (192/8 and 104/8; layouts in
`03-messages.md` section 4) carry the same nonzero OpId for this logical
CREATE; it keys the open-prepare record before commit and the physical
journal bundle/digest at commit. No other logical operation may use that
OpId within the MountId.

### 4.3 Kernel-owned authorization

The kernel performs the final access decision, share accounting, privilege
checks, and delete-pending checks from PREPARE_OPEN's validated metadata,
using the captured requestor subject context. The provider never makes the
final access or share decision. `CommitOpenV2` carries the access actually
granted by the kernel (`granted_access`), and the provider treats it as
input to record, not authority to compute. Create security-descriptor and EA
inputs are validated by the kernel before submission
(`MIN_SECURITY_DESCRIPTOR_BYTES = 20`,
`MAX_SECURITY_DESCRIPTOR_BYTES = 65536`, EA chain walked with checked
offsets, canonical alignment, bounded names/values, and no trailing bytes)
and are included by value in the durable digest where applicable.

### 4.4 The open-prepare record

Before returning PREPARE_OPEN success, the provider creates a restart-stable
open-prepare record keyed by `(MountId, Prepare OpId)`. The record contains
the exact semantic Prepare request by value — parent, validated name,
requested security descriptor and EA, desired/share access, disposition,
create options, file attributes, and open flags — plus the exact successful
Prepare result and its nonzero TransactionId. BufferRef coordinates, ReqId,
grants, and session epoch are excluded. The same OpId and semantic bytes are
idempotent and return the same TransactionId/result; reuse with different
bytes is a protocol fault. The TransactionId also uniquely indexes that
record within the MountId.

### 4.5 Kernel CREATE phase states

The kernel retains the bounded semantic inputs and exactly one of these
phases under the logical CREATE state gate:

| Phase | Meaning | ATTACH/fence behavior |
|---|---|---|
| `PREPARE_UNSENT` | Prepare not yet publishable | may be cancelled locally |
| `PREPARE_MAY_BE_VISIBLE` | installed before any SQ Release can expose Prepare | with no stable candidate, reissue the identical Prepare after ATTACH with the same OpId and a fresh ReqId; provider idempotence returns the same result if the first publication succeeded |
| `PREPARE_SUCCEEDED` | a valid success CQE was captured with the entire result and TransactionId, before CQ-head Release | never forgotten or downgraded at ATTACH: it continues with the exact Commit, or the exact Abort if cancellation won, without allocating a second logical CREATE |
| `PREPARE_FAILED` | a valid registered failure was captured before CQ-head Release | completes the saved failure |

Any stable CQ cell carrying the live Prepare ReqId is captured before
validation. A provider may publish a registered Prepare failure only after
proving no open-prepare record/index exists. A malformed matching Prepare
candidate installs a fail-closed invalid phase and quarantines the MountId
rather than fabricating a result, classifying the request as unseen, or
resubmitting a different transaction. The session fence shares the CREATE
state gate and waits for capture. When HOT_RESTART+EXACTLY_ONCE is selected,
the open-prepare record and all variable bytes are in shared or durable
provider state understood by a replacement daemon; it survives process exit,
session fencing, and ATTACH. Without the paired restart features, session
loss tears down the mount and the provider's ordinary cleanup policy retires
the boot-local open-prepare/index pair.

### 4.6 Prepare admission and refund

`MAX_RETAINED_PREPARE_BYTES_PER_MOUNT = 67108864`
(`fsring-abi/src/durable/mod.rs`). Before Prepare SQ publication, kernel
admission charges the name, requested SD, EA, fixed request/result state,
and a full `MAX_SECURITY_DESCRIPTOR_BYTES` kernel-transient reserve for the
variable successful result SD. Once it has constructed a candidate in
private memory, the provider validates the exact result length, computes the
final PREPARE plus PREPARE_TX_INDEX rows/reservations charge, and atomically
admits only that exact durable charge while creating both rows. There is no
provider-durable 64-KiB placeholder and no refund that depends on observing
a kernel copy. If the exact durable admission fails, Prepare is nonmutating
and the provider returns a registered resource failure with no record or
index. After CQ capture the kernel alone refunds the unused portion of its
transient maximum; failure/Abort releases its whole local charge, while
record/index deletion refunds their exact durable charge transactionally.
Overflow or kernel allocation failure completes INSUFFICIENT_RESOURCES
locally before publication. A provider MAY return a registered failure but
MUST NOT create an evictable successful record or publish a success whose
exact durable result was not already charged.

The kernel always grants the complete `MAX_SECURITY_DESCRIPTOR_BYTES` for
the Prepare result-SD grant, so PREPARE_OPEN BUFFER_TOO_SMALL is a protocol
fault and can never drive an internal retry. The Prepare reply grant is U2K
of at least 136 bytes; success echoes it as the CQ OControl with
`information = 136` (section 18).

### 4.7 COMMIT_OPEN

COMMIT_OPEN resolves the exact TransactionId index, requires its OpId to
equal the Commit OpId, exact-queries the open-prepare record, and verifies
its stored semantic fields against the retained request and operation
digest. When HOT_RESTART+EXACTLY_ONCE is selected, successful commit
atomically performs the filesystem transaction, performs the complete
PREPARED-to-COMMITTED journal bundle transition, creates and admission-
charges the exact durable OPEN(LIVE) row, and retires the open-prepare/index
pair in that same transaction. Without the restart pair it atomically
performs the filesystem transaction and retires the open-prepare/index pair
but creates no journal bundle or operation digest; nonrestart mounts use the
same logical LIVE/CLEANED transitions only in volatile state.

A registered non-success Commit removes/refunds its complete PREPARED
bundle before CQ publication but keeps the open-prepare/index pair reusable,
because an unseen failure candidate may legally cause the exact Commit to be
attempted again. Quota failure at commit is a registered nonmutating Commit
failure and leaves no OPEN row. Journal ACK later deletes only the COMMITTED
bundle; it never deletes OPEN.

The successful Commit reply is `CommitOpenResultV2` (112/8; layout in
`03-messages.md`), echoed shrunk to exactly 112 bytes with
`information = 112`. Its `create_result` accepts only the values 0 through 3
of the crate registry: SUPERSEDED=0, OPENED=1, CREATED=2, OVERWRITTEN=3.
EXISTS=4 and DOES_NOT_EXIST=5 are reference constants exported for the
native `Information` vocabulary, never legal wire results. Failed COMMIT has
no output. The session-local `provider_open_cookie` MAY appear in an
ordinary `CommitOpenResultV2` but MUST NOT be stored in a durable committed
result; recovery obtains a fresh cookie through REPLAY_OPEN (section 17.1).

### 4.8 The AbortOpenV1 / ABORT_IF_PREPARED handshake

After QUERY_OP NOT_FOUND confirms a visible failure or a cancellation, the
kernel sends idempotent ABORT_OPEN on the same logical slot before
completing the native IRP. The wire form is `AbortOpenV1 { TransactionId }`
(24/8; `03-messages.md` section 4). ABORT_OPEN deletes only the exact
retained open-prepare/index pair; joint absence succeeds idempotently, while
a one-sided or mismatched pair is corruption. Local failure or cancellation
after Prepare success but before Commit publication follows the same ABORT
handshake. Session loss at any point retains the slot and retries that
ABORT after ATTACH. Neither timeout nor daemon exit discards a prepared
open transaction.

The QUERY_OP `ABORT_IF_PREPARED` operation (the only nonzero
`QueryOpV2.header.required_flags` bit, `0x0001`) deletes/refunds only the
complete journal PREPARED bundle; for COMMIT_OPEN the separate
open-prepare/index pair remains until the kernel's ABORT_OPEN or a
successful Commit. Therefore a non-cancelled NO_CANDIDATE/NOT_FOUND can
resubmit the exact Commit with the original TransactionId and inputs,
including at the crash point after Prepare success but before the journal
bundle's ABSENT-to-PREPARED transaction; a cancelled one follows the
mandatory ABORT_OPEN subprotocol of section 17.3 before completing.

### 4.9 CREATE statuses

PREPARE_OPEN accepts SUCCESS or a member of `OPEN_FAILURES`; COMMIT_OPEN
accepts SUCCESS, RETRY(0xc000022d), or a member of `OPEN_FAILURES`;
ABORT_OPEN accepts SUCCESS only (section 18). Native completion translates
the committed `create_result` into `IoStatus.Information` using the Windows
create-information vocabulary. Feature-gate precedence applies before
emission: a create input carrying FILE_ATTRIBUTE_REPARSE_POINT(0x00000400)
or FILE_OPEN_REPARSE_POINT(0x00200000) is rejected locally with
NOT_SUPPORTED(0xc00000bb), zero information, and no SQE, because REPARSE is
unselectable in base 2.1.

## 5. IRP_MJ_READ and IRP_MJ_WRITE

### 5.1 Wire forms and OpId ownership

READ requires zero OpId; WRITE requires nonzero OpId. READ has
`payload_len = 80` and an inline `PRw` with zero OpId and a U2K data grant.
WRITE has `payload_len = 24` and a `PControl` whose K2U body is exactly one
validated `WriteV2` (112/8; layout in `03-messages.md` section 4); its OpId
is nonzero and its data grant is K2U with exactly the request length. The
version-1 inline WRITE encoding and the version-1 WRITE result form are
illegal in ABI 2.1; READ alone retains the inline `PRw` payload. The
enclosing SQE `kernel_open_id`, the `WriteV2` expected size epoch,
offset/length, and the retained FCB identity MUST all describe the same live
request before either the data or the reply grant is exposed.

### 5.2 Stream versus ordinary provenance

Every actual paging READ/WRITE is stream-owned: its outer `kernel_open_id`
is nonzero, its outer `ccb_sequence` is zero, and the wire `PAGING` flag is
set. Ordinary nonpaging READ/WRITE requires a live ordinary CCB and a
nonzero current `ccb_sequence`. Zero sequence on another opcode or
provenance, `PAGING` with nonzero sequence, or a stream request whose OPEN
row/replay mode is not LIVE-ordinary or CLEANED-PAGING_ONLY is a protocol
fault. The stream lane and its OPEN-row admission rules are defined in
`04-object-model.md`; CLEANED never admits ordinary CCB work.

### 5.3 The rw-flag registry

The closed mask from `fsring-abi/src/msgs/io.rs`:

| Flag | Value |
|---|---:|
| `PAGING` | 0x01 |
| `NOCACHE` | 0x02 |
| `WRITE_THROUGH` | 0x04 |
| `MAPPED` | 0x08 |
| `SYNC_PAGING` | 0x10 |
| `EXTENDING` | 0x20 |
| `ZERO_RANGE_VALID` | 0x40 |

Direction, paging, mapped, extension, initialized-range, and cache-mode
combinations are validated against the originating IRP and FCB rather than
trusted from the wire. Unknown rw-flag bits and a nonzero reserved field
fail before submission. Without the MMAP feature the kernel never emits an
rw record with `MAPPED`, and receiving that flag is a protocol fault.

### 5.4 Size domain and zero length

`MAX_FILE_SIZE = 0x7fffffffffffffff` (`i64::MAX`;
`fsring-abi/src/limits.rs`). Every wire field that represents allocation
size, EOF/file size, VDL, file offset, byte-range end, or a native volume
byte total is an unsigned encoding of a value in `[0, MAX_FILE_SIZE]` and is
rejected before conversion to `LARGE_INTEGER` otherwise. For a nonempty file
byte range, checked arithmetic MUST prove `offset < MAX_FILE_SIZE`,
`1 <= length <= MAX_FILE_SIZE`, and `offset + length <= MAX_FILE_SIZE`. A
negative native `LARGE_INTEGER` size completes locally with
INVALID_PARAMETER(0xc000000d), zero information, and no ReqId, grant, or SQ
publication. A provider value outside the domain is a protocol fault before
any native or cache call. Zero-length READ/WRITE is completed in the kernel
and never emitted. For an emitted request, data length equals the nonzero
request length, initialized length does not exceed it, and every
offset/length/end calculation satisfies `MAX_FILE_SIZE`.

### 5.5 Chunking and the immutable WRITE snapshot

When EXACTLY_ONCE is selected, WRITE semantic bytes come only from a
kernel-owned immutable snapshot: the kernel copies the source once into a
K2U slot or shadow MDL with no application-writable alias, computes the
digest from that same snapshot, and retains it through PREPARED recovery
until a terminal result and ACK/rundown.
`MAX_JOURNALED_WRITE_BYTES_PER_REQUEST = 16777216` and
`MAX_IMMUTABLE_WRITE_BYTES_PER_MOUNT = 268435456`
(`fsring-abi/src/digest.rs`); larger application writes are split in CCB
order into independently identified chunks, each with its own OpId, digest,
and CQ byte count, while the parent IRP reports the ordered committed prefix
under normal Windows partial-write rules. Without an immutable
shadow-mapping grant, the effective per-request chunk cap is
`min(MAX_JOURNALED_WRITE_BYTES_PER_REQUEST, largest K2U slot size)`. The
parent ticket from section 2 is charged on the complete incoming MDL span,
including bytes beyond the wire chunk, and survives every ordered child
chunk and all recovery reissues. Without EXACTLY_ONCE, `WriteV2` remains the
wire form but an original-IRP MAPPING grant may use the negotiated zero-copy
path; such a mount has no daemon-restart replay, and caller mutation of an
outstanding direct-I/O source has ordinary Windows race semantics.

### 5.6 Results, grant echo, and statuses

A successful emitted READ or WRITE transfers `1..=request_length` bytes.
READ success echoes the U2K data grant as OControl shrunk to the transferred
bytes; WRITE success echoes the U2K reply grant (at least 56 bytes) shrunk
to exactly the 56-byte `WriteResultV2`, whose SizeState satisfies the
SizeState invariant and covers the committed byte prefix reported in CQ
information. Result flags and reserved fields are zero. A read with no byte
available at EOF uses END_OF_FILE(0xc0000011) with zero information; SUCCESS
with zero information is illegal for both opcodes. READ accepts SUCCESS,
END_OF_FILE, or a member of `READ_FAILURES`; WRITE accepts SUCCESS or a
member of `WRITE_FAILURES` (section 18; full value lists in
`03-messages.md` section 5). Byte-range lock arbitration precedes READ/WRITE
emission (section 14), and every emitted READ/WRITE already owns the common
locked-page ticket of section 2.

## 6. IRP_MJ_FLUSH_BUFFERS

FLUSH is an emitted provider operation with no payload beyond its envelope
(`03-messages.md` section 5). It accepts SUCCESS or a member of
`FLUSH_FAILURES`. Success completes with `out_len = 0`, zero information,
and zero output. FLUSH is retained and cancelled under the same
observational one-terminal-owner arbitration as READ (section 16); it is
never journaled in base 2.1. Cache-manager flush interactions are
`07-cache-mm.md`.

## 7. IRP_MJ_CLEANUP and the CLEANUP barrier

### 7.1 The barrier rule

Native CLEANUP is a barrier after all earlier CCB requests: CLEANUP is not
publishable until every predecessor has released its request-table slot,
grant/MDL ticket, and operation rundown. This CLEANUP barrier is enforced by
a retained predecessor count plus per-operation references, not by a held
gate or a table scan; the per-open lifecycle gate is released while any
predecessor waits.

### 7.2 Substates and the predecessor snapshot

The kernel marks the handle `CLEANUP_PENDING(DRAIN_PREDECESSORS)` before the
first CLEANUP publication and retains that state across a lost CQ or a
fence. Under the per-open gate this linearization closes new ordinary
admission and snapshots as predecessors every logical operation already
admitted on that CCB plus stream work already ADMITTING or provider-visible
for the FileObject. Disposition of already-queued work is closed:

| Predecessor class | Disposition |
|---|---|
| queued ordinary work never semantically visible | cancelled locally in CCB order |
| pre-handoff stream work | moved to `POST_CLEANUP_HELD` without losing its paging-WRITE issue |
| possibly-visible nonjournaled work | the one terminal-owner arbitration of section 16 |
| journaled work | its retained QUERY_OP/ABORT/ACK state machine (section 17) |
| QueryDir and notification work | their class-specific cleanup arbitration (sections 12 and 13) |

CLEANUP's lightweight lifecycle state reserves no application ReqId, slot,
grant, or SQ cell before the predecessor count and rundown reach zero, at
which point the state becomes `CLEANUP_PENDING(READY_TO_PUBLISH)`. A
still-bound same-session CLEANUP may then reserve an application slot;
recovery CLEANUP instead uses the reserved lifecycle slot and the durable
OPEN payload and allocates no new application slot. If an ordinary CLEANUP
phase was possibly visible before a fence, its old application slot remains
retained until the recovery result owns the terminal outcome. CLEANUP
success establishes PAGING_ONLY readiness before releasing any
`POST_CLEANUP_HELD` work in FIFO order; a fence retains held stream work for
PAGING_ONLY replay. Thus `max_inflight = 1` progresses even when the sole
slot was retained by a pre-cleanup request.

### 7.3 DRAIN_REPLAY

If a fence destroyed the session-local provider cookie while a predecessor
still requires one, ATTACH may issue an ordinary REPLAY_OPEN solely as
`DRAIN_REPLAY` even though cleanup is pending. It uses the reserved
open-lifecycle recovery slot, still requires OPEN(LIVE), and installs a
fresh cookie usable only by the frozen predecessor set; it never reopens CCB
admission or marks the handle ordinarily replay-ready. `DRAIN_REPLAY` is a
kernel-only substate and changes no REPLAY_OPEN wire byte or provider
validation. Exact nonjournaled reissues and journal QUERY_OP/ABORT/ACK
phases then reuse their already-owned application slot and the existing
control reserve; these retained recovery publications are legal in
BOUND_RECONCILING despite the ban on new semantic requests. If no retained
predecessor needs a cookie, replay is skipped.

### 7.4 The wire CLEANUP transition

Wire CLEANUP consumes no volume sequence and is an idempotent row-state
transaction: from OPEN(LIVE) the provider performs all per-handle cleanup
and publishes CLEANED atomically before its success CQ; an exact CLEANED
repeat returns success without repeating the effect; ABSENT, an unknown
state, or a mismatched payload is corruption. Provider CLEANUP atomically
revokes share, handle, and user semantics and transforms any current replay
state to PAGING_ONLY before its success CQ. A recovery CLEANUP from durable
LIVE installs the same paging-only provider state without needing to return
a cookie in its zero-output CQ. An exact CLEANED retry after response loss
or provider restart reconstructs missing volatile PAGING_ONLY state before
its idempotent success CQ but never repeats durable cleanup effects.
CLEANUP accepts SUCCESS only, with `out_len = 0` and zero information.

Native-side teardown at CLEANUP: the CCB's notify registration is torn down
with STATUS_NOTIFY_CLEANUP per section 13, QueryDir admission is closed and
queued IRPs cancelled in order per section 12, share accounting is released,
delete-disposition processing emits the durable UNLINK at the actual
namespace removal point (`04-object-model.md`), and the FCB-referenced
stream-admission gate survives so that post-cleanup paging and AdvanceOnly
traffic can continue under the closed stream lane.

### 7.5 The per-open gate

One kernel per-open state gate serializes REPLAY_OPEN, CLEANUP, and CLOSE.
If CLEANUP wins before a queued replay's SQ Release, it cancels that replay
only when the frozen predecessor set needs no fresh cookie; otherwise the
queued phase is retained as `DRAIN_REPLAY`. If replay has crossed SQ
Release, CLEANUP closes new ordinary admission and records intent but waits
for replay terminal ownership. A session fence discards every
ordinary/paging replay generation and repeats the mode-specific decision on
the next ATTACH. No newly admitted ordinary request can pass while either
transition is pending; frozen predecessor drain and bounded
`POST_CLEANUP_HELD` stream traffic are the only closed exceptions, and the
latter cannot publish until PAGING_ONLY readiness. The provider uses the
same per-open serialization domain for all three opcodes and both replay
modes, so CLEANUP cannot commit CLEANED between replay validation and cookie
publication. The gate ordering rules live in `06-locking.md`.

## 8. IRP_MJ_CLOSE

The kernel accepts native CLOSE only after CLEANUP_DONE. Under the stream
gate it first enters `CLOSE_PENDING(DRAIN_STREAM)`, closes further
paging/AdvanceOnly admission, and snapshots every admitted stream operation,
RESOURCE_READY waiter, and journal recovery phase. BARRIER_WAIT is included
as an admitted stream waiter; `POST_CLEANUP_HELD` is included and MUST be
released under PAGING_ONLY authority; each snapshot member either reaches
its frozen fence or terminalizes through the same one-terminal-owner CAS.
CLOSE reserves no application slot before that count/rundown reaches zero.
Same-session work drains normally; after a fence, REPLAY_OPEN(PAGING_ONLY)
restores only the authority needed to exact-reissue or QUERY_OP/ACK the
frozen stream set. State then becomes `CLOSE_PENDING(READY_TO_PUBLISH)`.

From CLEANED, provider CLOSE atomically deletes/refunds the OPEN row and
retained-open reservation and the paging-only volatile state, and publishes
success only after commit. Reissuing a possibly-visible CLOSE finds complete
ABSENT and succeeds idempotently; LIVE or a one-sided row/reservation is
corruption. A recovery CLOSE uses the lifecycle slot and allocates no new
application slot; any old possibly-visible ordinary CLOSE slot remains
retained until terminal outcome. ABSENT authorizes no other deletion. CLOSE
accepts SUCCESS only, with `out_len = 0` and zero information. The
retained-open admission ticket is refunded exactly once at CLOSE/ABSENT
terminal ownership or terminal mount retirement; CLEANUP, fences, replay,
and journal ACK never refund it (`04-object-model.md`). LIVE and CLEANED
rows are clean-DETACH blockers until then.

## 9. IRP_MJ_SET_INFORMATION and IRP_MJ_SET_SECURITY

### 9.1 Mutation kinds and native origin

All native metadata mutations canonicalize to `MutationV2` (128/8; layout in
`03-messages.md` section 4) with a kind from the closed crate registry
(`fsring-abi/src/msgs/mutation.rs`):

| Kind | Value | Native origin |
|---|---:|---|
| `INVALID` | 0 | never legal |
| `SET_BASIC_INFO` | 1 | FileBasicInformation after canonicalization (section 9.3) |
| `SET_ALLOCATION_SIZE` | 2 | FileAllocationInformation |
| `SET_END_OF_FILE` | 3 | ordinary FileEndOfFileInformation |
| `SET_VALID_DATA_LENGTH` | 4 | FileValidDataLengthInformation; also the canonicalized AdvanceOnly adapter (section 9.6) |
| `RENAME` | 5 | FileRenameInformation(Ex) |
| `LINK` | 6 | FileLinkInformation(Ex) |
| `UNLINK` | 7 | emitted by the kernel at the actual namespace removal point; delete-pending itself is kernel CCB/LCB state |
| `SET_SECURITY` | 8 | IRP_MJ_SET_SECURITY |
| `SET_REPARSE` | 9 | never emitted in base 2.1 (REPARSE unselectable) |
| `DELETE_REPARSE` | 10 | never emitted in base 2.1 |
| `SET_SPARSE` | 11 | assigned/reserved; never selectable in base 2.1 |

Outer mutation flags are zero in 2.1; only rename/link accept their single
`REPLACE_IF_EXISTS` body bit. POSIX disposition is deferred behind a later
negotiated feature/required flag. Native get/set/delete-reparse requests
complete locally with NOT_SUPPORTED and emit no SQE; a provider
SET_REPARSE/DELETE_REPARSE result, a returned REPARSE_POINT attribute, or a
nonzero reparse tag is a protocol fault. No validator accepts `SetSparseV1`.

### 9.2 Prerequisite and result-generation tables

The target FileId is not duplicated inside `MutationV2`: it is the retained
FCB identity bound to the enclosing SQE's nonzero `kernel_open_id`, and the
provider must already have that exact open mapping in the current session.
"File generation" is the retained generation for namespace-visible metadata
and the file link set; "parent generation" is the retained
directory-entry-set generation. They are distinct counters even when backed
by one provider transaction. The outer prerequisite table is exact:

| Kind | Outer `expected_namespace_generation` identifies | size epoch | security generation | Body parent prerequisite(s) |
|---|---|---|---|---|
| SET_BASIC_INFO | target FileId file generation, nonzero | zero | zero | none |
| SET_ALLOCATION_SIZE / SET_END_OF_FILE / SET_VALID_DATA_LENGTH | zero | target FileId size epoch, nonzero | zero | none |
| RENAME | source FileId link-set generation, nonzero | zero | zero | source and target parent generations, both nonzero |
| LINK | source FileId link-set generation, nonzero | zero | zero | target parent generation, nonzero |
| UNLINK | target FileId link-set generation, nonzero | zero | zero | parent generation, nonzero |
| SET_SECURITY | zero | zero | target FileId security generation, nonzero | none |
| SET_REPARSE / DELETE_REPARSE | target FileId file generation, nonzero | zero | zero | none |

Every identity relation and every generation is checked as one precondition;
a stale or contradictory value yields RETRY and no partial mutation.

The result-generation meaning in `MutationResultV2` (112/8) is also exact:

| Kind | `namespace_generation` | `security_generation` | Kind-result parent generation(s) |
|---|---|---|---|
| SET_BASIC_INFO / SET_REPARSE / DELETE_REPARSE | resulting target FileId file generation, nonzero | zero | none |
| size mutations | zero | zero | none |
| RENAME / LINK / UNLINK | resulting affected FileId link-set generation, nonzero | zero | source+target / target / parent respectively, all nonzero |
| SET_SECURITY | zero | resulting target FileId security generation, nonzero | none |

Each returned generation is the post-commit value for the exact retained
entity named in the corresponding request row and is strictly greater than
its required input generation, including for a semantically no-op successful
mutation. A result field specified as zero is exactly zero.

### 9.3 SetBasicInfo canonicalization

Native FileBasicInformation is canonicalized before any wire mutation. The
settable attribute mask is exactly `0x000031a7`
(`file_attributes::SETTABLE_BASIC_MASK`): READONLY, HIDDEN, SYSTEM, ARCHIVE,
NORMAL, TEMPORARY, OFFLINE, and NOT_CONTENT_INDEXED. The query-only or
derived bits DIRECTORY, SPARSE_FILE, REPARSE_POINT, COMPRESSED, and
ENCRYPTED form `0x00004e10`; none can be changed through this information
class. Native attributes zero means unchanged. A nonzero value must be a
subset of the settable mask, with NORMAL legal only alone; it replaces the
mutable attribute set while the provider preserves the retained
DIRECTORY/type bit. Any other bit is INVALID_PARAMETER except
REPARSE_POINT, whose earlier feature-gate precedence is NOT_SUPPORTED. A
file is never converted to or from a directory.

Native CreationTime is either zero (unchanged) or a strictly positive
absolute 100-ns time; every negative value is INVALID_PARAMETER. Native
LastAccessTime, LastWriteTime, and ChangeTime each accept a strictly
positive absolute time, zero, `-1`, or `-2`; values below `-2` are
INVALID_PARAMETER. For those three fields, `-1` stages setting and `-2`
stages clearing the corresponding per-CCB automatic-update-suppression bit;
zero stages nothing. The CCB delta is local handle state and is never sent
to the provider. Only strictly positive native times set their
`basic_info_set_mask` bit and appear in `SetBasicInfoV1`; only nonzero valid
attributes set FILE_ATTRIBUTES. Every excluded wire time/attribute field is
zero, so the provider wire never contains `0`, `-1`, or `-2` as a selected
timestamp. If the call contains only zero/sentinel fields and attributes
zero, the kernel applies the staged CCB bits under its handle lock and
returns SUCCESS with information zero and no ReqId, digest, or SQE. For a
mixed call, the sentinel delta is retained with the operation and applied
atomically only after the provider mutation is successfully committed; a
terminal provider failure applies none of it. There is exactly one accepted
byte representation for a semantic `SetBasicInfoV1` body: mask-excluded
values, alternate slice placement, extra tail bytes, and nonzero alignment
padding fail before digesting or submission.

### 9.4 Ordinary size changes: oplock check, size gate, truncating substate

An ordinary size request requires oplock arbitration when it would change
retained allocation, EOF, or VDL. Before allocating a ReqId, grant, or
digest, and before publishing an SQE, every ordinary
FileAllocationInformation, FileEndOfFileInformation, and
FileValidDataLengthInformation change performs the Windows
IRP_MJ_SET_INFORMATION oplock check using the originating FILE_OBJECT and
oplock key and the documented break/acknowledge matrix. Only SUCCESS
continues. STATUS_PENDING transfers the IRP to the oplock package; dispatch
returns STATUS_PENDING, Information remains zero, and the continuation
reacquires and revalidates the complete SizeState/epoch before any SQ
publication. Any other status completes unchanged with Information zero and
no provider-visible state. A wait or resource drop invalidates the captured
epoch and repeats the size decision if state changed. The AdvanceOnly
adapter of section 9.6 is the only path that bypasses this ordinary oplock
arbitration.

After successful oplock arbitration (or the trusted AdvanceOnly admission
sequence), the kernel first reserves every ordinary fallible
publication/apply resource, then acquires the FCB main/paging resources and
enters the per-FCB size-change gate serializing every allocation, EOF, and
VDL mutation. Only the documented reduction prerequisites may be discovered
under the gate; no request-table, grant, or allocator admission is allowed
there. Only a reduction enters the gate's truncating substate, whose
transition table `06-locking.md` defines under the name TRUNCATING: it
blocks new section creation, performs byte-lock arbitration,
`MmCanFileBeTruncated` and mapped/image-section vetoes, and completes every
fallible flush/purge step before SQ publication. A veto returns
USER_MAPPED_FILE(0xc0000243) locally with no ReqId, grant, digest, or SQE.
Extensions and VDL advances use the common gate and epoch but skip all
reduction-only MM and flush/purge work. Blocking resources are released
before daemon execution while the logical gate and FCB rundown remain held;
terminal reentry installs the already-validated SizeState and performs only
nonfailing cache-size update and gate-release work. The kernel never
discovers a new fallible prerequisite after an irreversible provider size
change.

Size-body semantics are exact (`SetSizeV1`, 24/8). SET_ALLOCATION_SIZE is
legal only for a non-directory file and accepts a requested allocation in
`[0, MAX_FILE_SIZE]`, including a value below the retained EOF; if below
EOF, the one provider transaction atomically sets the resulting EOF to the
requested value and resulting VDL to `min(old VDL, new EOF)`. The returned
allocation is at least the resulting EOF and at least the requested
allocation, and the complete returned SizeState is committed with those
EOF/VDL changes; a provider that cannot perform the combined shrink returns
a registered failure with no side effect, and the kernel never decomposes it
into crash-visible allocation and EOF operations. SET_END_OF_FILE accepts a
size in `[0, MAX_FILE_SIZE]`; on shrink the provider returns allocation at
least the new EOF and VDL no greater than it. For SET_VALID_DATA_LENGTH,
success additionally requires `allocation_size == retained allocation_size`,
`file_size == retained file_size`, and
`valid_data_length == requested new VDL`, with the advancing epoch as the
only other SizeState change; any different successful state is a protocol
fault before cache/FCB installation or native completion.

### 9.5 FileValidDataLengthInformation privilege preflight

An ordinary native FileValidDataLengthInformation request is legal only for
a non-directory, non-sparse, non-compressed file and requires
`0 <= current VDL < new VDL <= current EOF`; zero and equality are not
no-ops. Violation completes locally with INVALID_PARAMETER, zero
information, and no ReqId, grant, or SQE. The kernel MUST also successfully
check `SeManageVolumePrivilege` in the captured request subject context
before SQ emission. No daemon result can grant or substitute for that
privilege check.

### 9.6 The Cache Manager AdvanceOnly adapter

The `AdvanceOnly` form is a separate closed native adapter. The bit is legal
only with native FileEndOfFileInformation, kernel requestor mode, a regular
non-directory file, and the actual SetFile stack parameter carrying
`AdvanceOnly=TRUE`; it is never inferred from thread or process identity.
`AdvanceOnly=TRUE` on another class or a user-mode request is
INVALID_PARAMETER with zero information, no state change, and no SQE. The
EndOfFile input must be in `[0, MAX_FILE_SIZE]`, but zero, a value at or
below retained VDL, and a value above retained EOF are structurally legal.
This trusted form is the sole exception to the ordinary
sparse/compressed, strict-increase, privilege, and oplock-adapter rules; it
cannot expose unwritten data because the ordered paging-write barrier
precedes any VDL advance. It is FCB/stream-owned rather than
ordinary-CCB-owned: CLEANUP may hold it for PAGING_ONLY readiness but does
not reject it, while CLOSE closes its stream gate.

The bounded adapter state is corrective-design provenance:

```text
MAX_PENDING_ADVANCE_ONLY_IRPS_PER_FCB   = 64
MAX_PENDING_ADVANCE_ONLY_IRPS_PER_MOUNT = 4096
MAX_PENDING_ADVANCE_ONLY_IRPS_GLOBAL    = 16384
```

AdvanceOnly admission first reserves its count-only ticket by checked CAS in
fixed global, mount, then FCB order, then allocates a nonpaged
`AdvanceIrpContext` with an embedded nonsignaled completion gate and
distinct intrusive CSQ and sequencer links. Allocation or any partial
reservation failure rolls back everything in reverse order and completes
INSUFFICIENT_RESOURCES with zero information before pending or visibility.
Its closed owner states are INSERTING, BARRIER_WAIT, RESOURCE_READY,
`POST_CLEANUP_HELD`, ADMITTING, and TERMINAL; the CSQ owner-state transition
rules are `06-locking.md`.

Under the paging-WRITE sequencer lock, dispatch revalidates FCB/mount stream
admission and snapshots `last_issued` as its immutable fence. Every valid
request, including one whose terminal prefix already covers that fence,
enters INSERTING, stores the unconditional pending dispatch-return decision,
calls `IoMarkIrpPending`, and while retaining the sequencer calls
`IoCsqInsertIrpEx` in fixed sequencer-to-CSQ order. From `IoMarkIrpPending`
onward dispatch always returns STATUS_PENDING, including on insertion
rejection or synchronous observation of an already-cancelled IRP; an
insertion rejection is the terminal `Irp->IoStatus.Status`, never the
dispatch return value. The cancel callback only CAS-claims terminal
ownership and queues the context to a deferred PASSIVE list; it never
completes, frees, refunds, or touches sequencer state.

When the barrier is satisfied, the resource worker acquires the size gate,
then the sequencer, snapshots SizeState and the failure ledger, and computes
`target_vdl = min(EndOfFile, current file_size)`. A target at or below
retained VDL is the SUCCESS/zero local candidate even when unresolved
evidence exists above VDL; otherwise the lowest-issue unresolved interval
intersecting `[current valid_data_length, target_vdl)` is the local failure
candidate; for a local candidate the worker removes the IRP from the CSQ,
CAS-claims terminal ownership, releases every lock before completion and
refund, and emits no mutation SQE. If mutation remains necessary, the worker
reserves its application request-table slot, ApplyReserve/domain slots,
reply grant, and digest/journal buffers outside the size gate — so a
preceding WRITE may finish and free the sole `max_inflight = 1` slot while
AdvanceOnly waits — then reenters the size gate and sequencer, atomically
revalidates the complete SizeState/epoch, target, immutable fence, and
failure ledger, and canonicalizes to the SET_VALID_DATA_LENGTH wire mutation
with `new_vdl = target_vdl`, the revalidated size epoch, every wire flag
zero, and outer `ccb_sequence` zero under the stream authority of section
5.2. It performs neither a second oplock check nor `SeManageVolumePrivilege`
because the originating cached WRITE already underwent its required
arbitration. The provider transaction changes only VDL to exactly
`target_vdl`, preserves allocation and EOF, and advances the size epoch.
With the restart pair selected this is an ordinary
digest/journal/QUERY_OP/ACK mutation, so crash recovery repeats the exact
operation without a special persisted provenance bit. AdvanceOnly never
reduces VDL, changes allocation or EOF, or uses a nonzero `SetSizeV1` or
outer mutation flag. If CLEANUP is pending at final revalidation, the
context rolls back its private resources, enters `POST_CLEANUP_HELD` on the
stream-held FIFO, and remains in the CSQ until CLEANED PAGING_ONLY readiness
moves it back to RESOURCE_READY.

### 9.7 Rename, link, and unlink identity obligations

For RENAME, the source `LinkId` must belong to the target FileId, its source
parent is resolved from that retained link and must match the explicit
expected source-parent generation; if source and target are the same
directory, both expected parent fields must be equal. LINK's source FileId
equals the target FileId resolved from the SQE `kernel_open_id`. UNLINK's
LinkId must belong to that target FileId and its explicit parent.

Kind-result validation is closed (`RenameResultV2` 112/8, `LinkResultV2`
104/8, `UnlinkResultV1` 56/8; layouts in `03-messages.md`): all flags and
reserved fields are zero. With no replacement, both replacement identities,
the replaced generation, and the replaced link count are zero. With a
replacement, both identities and the post-commit replaced-file link-set
generation are nonzero; the replaced link count is its exact remaining count
and may be zero. A half-present replacement tuple is invalid. Rename
preserves its LinkId; link returns a new nonzero LinkId distinct from every
retained and replaced LinkId; unlink returns the removed nonzero LinkId. The
ordinary `link_count` is the post-commit count for the affected FileId. If
`replaced_file_id == file_id`, the ordinary and replaced post-commit
link-set generations and link counts must be exactly equal and the kernel
updates that one FCB once; contradictory aliases are a protocol fault.
Rename of a link within one directory returns equal source and target
parent generations. Every identity, generation, and count is validated
against retained state before both affected FCB/LCB cache states are
updated atomically. Rename changes an LCB, never replaces the FCB, and
never silently clears another CCB's delete disposition
(`04-object-model.md`).

### 9.8 SET_SECURITY

The SET_SECURITY body (`SetSecurityV1`, 24/4) carries the complete
security-information mask registry of `fsring-abi/src/msgs/mutation.rs` and
one validated self-relative descriptor of
`MIN_SECURITY_DESCRIPTOR_BYTES..=MAX_SECURITY_DESCRIPTOR_BYTES`. The kernel
additionally applies Windows privilege and per-operation validity rules
before emitting SET_SECURITY (SACL access requires the normal open-time
privilege path; see `09-security.md`). SECURITY is selected in every
successful 2.1 session, so QUERY_SECURITY and SET_SECURITY have no
feature-off form.

### 9.9 Statuses and grants

Every mutation is emitted as `MutationV2` with a K2U body grant of exactly
the body `struct_size`, a U2K reply grant of at least 112 bytes echoed
shrunk to exactly the 112-byte `MutationResultV2`, and a kind-result grant
of exactly 112/104/56 bytes for RENAME/LINK/UNLINK (NONE for all other
kinds). MUTATE accepts SUCCESS or a member of `MUTATE_FAILURES` (which
includes RETRY and USER_MAPPED_FILE; full list in `03-messages.md` section
5). Success completes with `out_len = 24` and `information = 112`.

## 10. IRP_MJ_QUERY_INFORMATION and IRP_MJ_QUERY_VOLUME_INFORMATION

These adapters are buffered: they use the I/O-manager
`AssociatedIrp.SystemBuffer`, not a direct-I/O MDL, and are outside the
section 1.2 preflight. Provider-backed rows derive from one validated
`FileInfoV1` snapshot (104/8) or `VolumeSizeInfoV1` (40/8) obtained through
`QueryInfoV1`/`QueryVolumeV1` with class CANONICAL/SIZE — the only nonzero
classes in the crate query registries. Provider-backed success zeroes and
fills exactly the table size and does not modify the caller tail.

### 10.1 QUERY_INFORMATION classes

| Native class | Value | Minimum/exact output | Source and mapping |
|---|---:|---:|---|
| FileBasicInformation | 4 | 40 | four times and attributes |
| FileStandardInformation | 5 | 24 | allocation/EOF, retained link count, delete-pending, directory bit |
| FilePositionInformation | 14 | 8 | `IrpSp->FileObject->CurrentByteOffset`; local, no provider request or CCB mirror |
| FileNetworkOpenInformation | 34 | 56 | times, allocation/EOF, attributes |
| FileAttributeTagInformation | 35 | 8 | attributes and zero reparse tag |
| FileIdInformation | 59 | 24 | modern only; volume serial64 plus the complete canonical FileId |

Unlisted classes return INVALID_INFO_CLASS(0xc0000003) with zero
information and no SQE. After class/profile selection, every supported class
requires `Parameters.QueryFile.Length` at least its fixed size; a shorter
buffer returns INFO_LENGTH_MISMATCH(0xc0000004), zero information, touches
no caller byte, changes no state, and emits no SQE. FilePositionInformation
snapshots `IrpSp->FileObject->CurrentByteOffset` exactly once under the I/O
manager's per-FILE_OBJECT synchronous-I/O ordering, writes exactly one
FILE_POSITION_INFORMATION, returns SUCCESS with `information = 8`, and
leaves the tail untouched; `FILE_OBJECT.CurrentByteOffset` is the sole
canonical position, the driver keeps no CCB mirror, and no FCB, provider, or
ring lock is taken for this local query. Standard-information booleans are
canonical zero/one bytes and its two reserved bytes are zero.
`FileIdInformation.VolumeSerialNumber` is the first little-endian u64 of
`SHA256("FSRING-VOLUME-SERIAL-v1\0" || MountId.lo_le || MountId.hi_le)` and
is stable through every ATTACH. The Win7 profile rejects class 59 with
INVALID_INFO_CLASS. FileInternalInformation and FileAllInformation are
deliberately unsupported: base 2.1 never truncates a 128-bit FileId into a
collision-prone 64-bit value.

### 10.2 QUERY_VOLUME classes

| Native class | Value | Minimum capacity / completion Information | Source and mapping |
|---|---:|---|---|
| FileFsVolumeInformation | 1 | 24 / 18 | creation time 0, serial32 from serial64 low bits, empty label, SupportsObjects=0 |
| FileFsSizeInformation | 3 | 24 / 24 | validated `VolumeSizeInfoV1` |
| FileFsDeviceInformation | 4 | 8 / 8 | FILE_DEVICE_DISK_FILE_SYSTEM `0x8`, FILE_DEVICE_IS_MOUNTED `0x20` |
| FileFsAttributeInformation | 5 | 12 / 12-24 | 12-byte header plus partial/full UTF-16 `FSRING` |
| FileFsFullSizeInformation | 7 | 32 / 32 | validated size; caller/actual available counts equal |

Unlisted volume classes return INVALID_INFO_CLASS with zero information and
no SQE. The three fixed-size classes require their listed minimum; below it
they return INFO_LENGTH_MISMATCH with zero information and touch no byte.
FileFsVolumeInformation at capacity at least 24 writes only bytes 0-17 and
returns SUCCESS with `information = 18`, leaving bytes 18 onward untouched.
FileFsAttributeInformation requires 12; at capacity 12-23 it writes the full
12-byte header (FileSystemNameLength remains 12), copies exactly
`min(buffer_length-12, 12)` raw bytes of UTF-16LE `FSRING` (including an odd
final byte at that exact capacity), returns STATUS_BUFFER_OVERFLOW
(0x80000005), and sets Information to `12+copied`; at 24 or more it returns
SUCCESS with `information = 24`. Attribute flags are exactly
CASE_PRESERVED_NAMES `0x2`, UNICODE_ON_DISK `0x4`, PERSISTENT_ACLS `0x8`,
and SUPPORTS_HARD_LINKS `0x00400000`, plus CASE_SENSITIVE_SEARCH `0x1` iff
CASE_SENSITIVE_NAMES is selected; no unsupported capability is advertised.
Only the two size classes emit QUERY_VOLUME SIZE and both use the same
canonical result; the others complete locally from immutable mount/session
identity. Volume size validation requires
`available_allocation_units <= total_allocation_units`, a power-of-two
`bytes_per_sector` in `[512, 65536]`, a nonzero power-of-two
`sectors_per_allocation_unit`, a checked product no greater than 16 MiB, and
derived native byte totals each at most `MAX_FILE_SIZE` before conversion to
signed native fields. Both opcodes accept SUCCESS or a member of
`QUERY_FAILURES`.

## 11. IRP_MJ_QUERY_SECURITY

Native QUERY_SECURITY accepts only the query-specific closed mask
OWNER|GROUP|DACL|SACL (`0x0000000f`) with at least one bit required; LABEL,
ATTRIBUTE, SCOPE, BACKUP, all four PROTECTED/UNPROTECTED modifiers, and
every unknown bit are rejected with INVALID_PARAMETER, zero information,
and no SQE. The restriction is identical on Win7 and modern profiles.

Before grant reservation or SQ publication, the adapter derives and enforces
the union of exact handle rights: OWNER/GROUP/DACL require READ_CONTROL and
SACL requires ACCESS_SYSTEM_SECURITY. A missing right returns ACCESS_DENIED
with zero information and no grant or SQE; the open-time privilege checks
required to obtain ACCESS_SYSTEM_SECURITY are never delegated to the
provider.

QUERY_SECURITY ignores volume buffering flags and is neither-I/O. The kernel
first reserves the common section 2 ticket, then a 65536-byte U2K progress
grant, and obtains one complete validated self-relative descriptor from the
provider; the provider never receives native capacity and returns only
SUCCESS with one complete descriptor or a registered `QUERY_FAILURES`
status. Effective native capacity is
`min(IrpSp->Parameters.QuerySecurity.Length, 65536)`. For nonzero capacity,
an existing `Irp->MdlAddress` is accepted only as a locked or nonpaged-pool
source MDL with `Next == NULL` whose byte count covers that capacity; the
ticket charges the complete source-MDL page span, checked arithmetic must
prove the logical range lies wholly inside the source before
`IoBuildPartialMdl`, and the driver never unlocks or frees the caller-owned
source. With no existing MDL, it allocates an MDL for exactly that range
over `Irp->UserBuffer` after reserving the checked exact page-span charge,
calls `MmProbeAndLockPages(Irp->RequestorMode, IoWriteAccess)` inside the
WDK C SEH shim, and records that only this MDL's pages must be unlocked.
Both paths create one safe system mapping (modern no-execute; Win7 priority
bits only), retain the source/partial/owned distinction through asynchronous
completion, and map or lock no more than 65536 bytes. A zero capacity
requires `Irp->MdlAddress == NULL` and needs no MDL. A mismatched, unlocked,
short, null-start, or arithmetically invalid existing MDL and a probe
exception map to `STATUS_INVALID_USER_BUFFER`; MDL/partial-MDL allocation or
mapping failure maps to INSUFFICIENT_RESOURCES, all with no SQE.

After privately copying and validating a successful descriptor, the kernel
calls `SeQuerySecurityDescriptorInfo` at PASSIVE_LEVEL with a local length
initialized to the effective native capacity (zero capacity uses a valid
aligned kernel scratch pointer with local length zero). Local
STATUS_BUFFER_TOO_SMALL converts to native STATUS_BUFFER_OVERFLOW
(0x80000005); the returned local length becomes
`IrpSp->Parameters.QuerySecurity.Length`, `IoStatus.Information = 0`, and no
caller byte is exposed. CQ information is never trusted as a required native
length: the exact required size comes only from
`SeQuerySecurityDescriptorInfo` after complete provider descriptor
validation. Provider BUFFER_TOO_SMALL is unregistered for this opcode and
never drives a retry or supplies a native length (its structurally empty
form normalizes under section 18.4). Local SUCCESS copies exactly the
selected self-relative descriptor to the mapped system VA, returns that byte
count, and leaves the tail untouched; no partial or unvalidated descriptor
is ever exposed. Exact teardown leaves the source MDL untouched, frees a
partial MDL with `IoFreeMdl` without `MmUnlockPages`, and performs
`MmUnlockPages` then `IoFreeMdl` only for a driver-allocated locked MDL,
clearing any IRP link before completion. Every terminal path carries the
ticket through its last MDL access and refunds it exactly once per section
2; a recoverable fence retains it.

## 12. IRP_MJ_DIRECTORY_CONTROL / IRP_MN_QUERY_DIRECTORY

### 12.1 Native class table and preflight

`fixed_prefix` is `FIELD_OFFSET(native_type, FileName)` and is also the
minimum native buffer:

| FILE_INFORMATION_CLASS | Value | Native type | fixed_prefix | Platforms |
|---|---:|---|---:|---|
| FileDirectoryInformation | 1 | FILE_DIRECTORY_INFORMATION | 64 | Win7/Win10 |
| FileFullDirectoryInformation | 2 | FILE_FULL_DIR_INFORMATION | 68 | Win7/Win10 |
| FileBothDirectoryInformation | 3 | FILE_BOTH_DIR_INFORMATION | 94 | Win7/Win10 |
| FileNamesInformation | 12 | FILE_NAMES_INFORMATION | 12 | Win7/Win10 |
| FileIdExtdDirectoryInformation | 60 | FILE_ID_EXTD_DIR_INFORMATION | 88 | Win10 only |
| FileIdExtdBothDirectoryInformation | 63 | FILE_ID_EXTD_BOTH_DIR_INFORMATION | 114 | Win10 only |

Classes 37 and 38 complete locally with INVALID_INFO_CLASS because base 2.1
has no collision-free stable 128-to-64 FileId projection; every other
unlisted class completes locally with INVALID_INFO_CLASS(0xc0000003), zero
information, and no provider request. The `platform-win7` build also rejects
60 and 63 that way. A native buffer shorter than the table's fixed prefix
completes locally with INFO_LENGTH_MISMATCH(0xc0000004), zero information,
no pattern or first-call state change, no snapshot-generation increment, no
cookie change, and no SQ publication. The kernel writes zero FileIndex, EA
size, and short-name fields; classes 60/63 copy the complete canonical
FileId; reparse tags are zero because REPARSE is unselectable.

### 12.2 Native stack flags

Stack flags are parsed before pattern or cursor mutation and are never
copied numerically into wire flags. The common known mask is
`SL_RESTART_SCAN(0x1) | SL_RETURN_SINGLE_ENTRY(0x2) |
SL_INDEX_SPECIFIED(0x4) | SL_RETURN_ON_DISK_ENTRIES_ONLY(0x8)`; the modern
adapter also recognizes `SL_NO_CURSOR_UPDATE_QUERY(0x10)`. Unknown bits
return INVALID_PARAMETER. `SL_INDEX_SPECIFIED` returns NOT_SUPPORTED because
ABI 2.1 defines no stable FileIndex position, and modern
`SL_NO_CURSOR_UPDATE_QUERY` returns NOT_SUPPORTED because no nonmutating
per-call snapshot is negotiated; both use zero information and change no
first-call, pattern, generation, cookie, spill, or SQ state. The Win7
profile treats `0x10` as unknown. `SL_RETURN_ON_DISK_ENTRIES_ONLY` is an
exact no-op because the provider's immutable match sequence is the base
filesystem's authoritative stored namespace. Only native restart/single
translate to wire RESTART/SINGLE, while wire EXACT_PATTERN is derived solely
from the captured pattern, so native `0x4` can never collide with it.

### 12.3 Admission caps

These bounds are corrective-design provenance (the crate carries no named
constants for them):

```text
MAX_QUERY_DIR_IRPS_PER_CCB             = 64
MAX_PENDING_QUERY_DIR_IRPS_PER_MOUNT   = 4096
MAX_PENDING_QUERY_DIR_MDL_BYTES_PER_CCB   = 67108864
MAX_PENDING_QUERY_DIR_MDL_BYTES_PER_MOUNT = 268435456
```

One CCB enumeration lock owns the captured native search expression,
snapshot state, spill, active IRP, and a cancel-safe FIFO of at most 63
additional IRPs; exactly one logical QueryDir IRP may publish or format at a
time. Before changing enumeration state, admission reserves the per-CCB and
per-mount counts, full-MDL byte spans, and the shared global count/bytes of
section 2. Admission beyond any cap, checked-counter failure, or failure to
allocate the bounded queue node completes INSUFFICIENT_RESOURCES with zero
information, rolls back the complete ticket, and changes no enumeration
state. A queued cancellation removes only that IRP and completes CANCELLED;
CLEANUP closes admission, cancels queued IRPs in order, and arbitrates the
active owner before releasing enumeration state.

### 12.4 Retained fields and pattern capture

The retained per-handle fields are `{native_first_call_seen,
captured_pattern_kind, captured_uppercase_pattern, captured_exact_mode,
next_enumeration_generation, generation_exhausted, snapshot_state, spill,
spill_cursor, deferred_cookie, deferred_status}`. Pattern kind is exactly
MATCH_ALL (native FileName pointer was NULL), MATCH_NONE (pointer non-NULL
and Length zero), or EXPRESSION. The first-call marker and captured pattern
kind/bytes are handle-lifetime state; RESTART never resets or replaces them.
Snapshot, spill, and exhaustion are resettable enumeration state.

The first accepted native directory IRP captures FileName presence
separately from byte length. A nonempty value is snapshotted, must be at
most 255 UTF-16 code units (`MAX_COMPONENT_UTF16_CODE_UNITS`) with an even
byte length and valid surrogate pairs, and may contain the five registered
wildcard tokens but no NUL, slash, backslash, or colon. Invalid
encoding/character completes locally with OBJECT_NAME_INVALID(0xc0000033);
an overlength expression uses NAME_TOO_LONG(0xc0000106); bounded-buffer
allocation or upcase failure uses INSUFFICIENT_RESOURCES. Each has zero
information and changes no first-call, pattern, generation, cookie, spill,
or SQ state. For EXPRESSION, the kernel preallocates a same-size buffer and
applies the running OS `RtlUpcaseUnicodeString` table before any state
commit. Later native FileName arguments are ignored.

### 12.5 The `snapshot_state` registry and ACTIVE_AT_START precedence

`snapshot_state` is exactly:

| State | Meaning |
|---|---|
| UNINITIALIZED | legal only before the first initial/restart SQ publication |
| ACTIVE_AT_START | nonzero generation committed, nothing returned yet |
| ACTIVE | nonzero generation, nonzero cookie, at least one batch returned |
| SPILLING | ACTIVE with a nonempty bounded spill |
| EXHAUSTED | provider-backed terminal snapshot result, nonzero generation |
| EXHAUSTED_LOCAL_NONE | the permanent local MATCH_NONE state |

Initial-call and SL_RESTART_SCAN changes are transactional with SQ
publication: the active IRP constructs a private PENDING_QUERY_DIR
transition holding the captured pattern kind/uppercase bytes, the tentative
next nonzero generation, and the old spill/cookie/exhaustion state it would
replace; no retained CCB field changes while it reserves and fills the SQ
cell. Under the enumeration lock, cancellation may discard this stage,
leaving the entire old enumeration state intact; the CANCELLED completion
itself is delivered only after every lock is released. Otherwise the kernel
sets QUERY_MAY_BE_VISIBLE, atomically installs the staged state, and only
then performs the SQ Release. Rollback is legal only while
the same lock proves no SQ cell or producer state was observable and no
fence snapshot intervened; an ambiguous publication retains the committed
stage for ATTACH replay. Reservation failure or contention never consumes a
generation.

The first committed call behaves as RESTART. ACTIVE_AT_START has precedence
over the native restart flag: until one nonempty batch or a provider-backed
terminal snapshot result is accepted, every recovery replay and every later
native retry, including one with SL_RESTART_SCAN, repeats the same
generation, cookie zero, RESTART bit, pattern bytes, and EXACT_PATTERN
value, and does not discard or allocate anything. Only ACTIVE, SPILLING, or
provider-backed EXHAUSTED may honor a later SL_RESTART_SCAN by
transactionally discarding spill, deferred status, and old snapshot state
and allocating the next generation with the captured expression.
Continuation retains the same generation. MATCH_NONE takes the same
cancellation/terminal-owner arbitration but emits no SQ: it atomically
installs `native_first_call_seen` plus EXHAUSTED_LOCAL_NONE and returns
NO_SUCH_FILE(0xc000000f) on the first committed native call, then
NO_MORE_FILES(0x80000006) on every later call including RESTART, always
with zero information and without allocating an enumeration generation.

### 12.6 The generation-wrap latch

If the next generation would wrap, the kernel sets only the permanent
`generation_exhausted` CCB latch and completes the triggering and every
later QueryDir IRP through CLOSE with `STATUS_INTEGER_OVERFLOW=0xc0000095`,
`IoStatus.Information = 0`, and no output. It publishes no SQE and changes
no pattern, snapshot, spill, cookie, generation, or provider state. A new
CCB starts with the latch clear; no generation ever wraps.
STATUS_INTEGER_OVERFLOW is a local native completion and is deliberately
absent from the provider QUERY_DIR status registry; receiving it in a CQE is
an unregistered provider status.

### 12.7 Wire identity: `QueryDirV2`, generations, and verified ordinals

Every MATCH_ALL or EXPRESSION initial/genuine-restart request is
`QueryDirV2` (64/8; layout in `03-messages.md` section 4) with cookie zero,
RESTART, and the newly committed nonzero `enumeration_generation`. MATCH_ALL
uses pattern `{0,0}`; an EXPRESSION pattern starts exactly at byte 64,
contains the captured running-OS uppercase UTF-16LE bytes, and consumes the
tail except zero eight-byte alignment padding. EXACT_PATTERN is present
exactly when those bytes contain none of STAR, QUESTION, DOS_STAR, DOS_QM,
or DOS_DOT. A continuation from ACTIVE has the same generation, the exact
retained nonzero cookie, RESTART and EXACT_PATTERN clear, and pattern
`{0,0}`. SINGLE remains per native IRP and is part of every internal attempt
over that IRP; MATCH_NONE never has a wire form.

The provider keys a snapshot by
`(MountId, kernel_open_id, enumeration_generation)`. First accepted
observation of a new generation atomically creates one immutable ordered
match sequence; a cookie denotes a stable position in that sequence, not a
destructive provider cursor. The exact attempt key is `(generation,
input_cookie, RESTART, EXACT_PATTERN, SINGLE, pattern bytes, output
capacity)`. Cookies are verified ordinals: input cookie zero is the start
position; if a successful batch does not carry EOF, checked arithmetic must
prove `next_cookie = input_cookie + entry_count`; a successful final batch
carries EOF and `next_cookie = 0`, and zero has no other successor meaning.
Same-cookie, skipped-cookie, wrapped, and cyclic successors are protocol
faults. Capacity or SINGLE changes may change `entry_count` and therefore
the deterministic successor, but never the meaning of an input ordinal. Only
the next genuine generation may supersede the snapshot; a lower, skipped,
reused-with-different-pattern, or wrapped generation is a protocol fault.
This identity distinguishes an ATTACH retry from a new application restart
without relying on session-scoped ReqId. Nonzero directory cookies and
generations are MountId/open-scoped, not session pointers or authority;
REPLAY_OPEN's fresh provider-open cookie does not invalidate the
MountId-scoped enumeration identity.

### 12.8 Batch budget and the 648-byte spill

`MAX_CONTROL_BLOB = 16777216`, `MAX_CANONICAL_DIR_ENTRY_BYTES = 648`
(136-byte `DirEntryV1` prefix, at most 510 name bytes, and alignment), and
`MAX_QUERY_DIR_SPILL_BYTES_PER_CCB = 648` (spill bound:
corrective-design provenance). For each internal provider batch, with
`native_remaining` the unformatted bytes in the current native IRP and
`largest_entries_grant` the largest available U2K grant capacity minus the
40-byte `QueryDirResultV1` prefix, the kernel issues exactly

```text
entries_budget = min(MAX_CONTROL_BLOB - 40,
                     largest_entries_grant,
                     max(native_remaining, MAX_CANONICAL_DIR_ENTRY_BYTES))
output_grant_length = 40 + entries_budget
```

and never issues a batch when `native_remaining = 0`. The 131072-byte
progress class guarantees at least one maximum entry. When
`native_remaining >= 648`, the compile-time size inequality
(`align8(fixed_prefix + name_bytes) <= DirEntryV1.struct_size` for every
enabled class) proves that every canonical record returned in the batch fits
natively; when it is smaller, the complete unformatted suffix is at most 648
bytes and is copied into the bounded CCB spill state. A 16-MiB native
request can therefore use multiple 128-KiB provider batches without a 16-MiB
slot, and over-fetch is lossless and strictly bounded. After a zero-prefix
attempt is abandoned, the next IRP recomputes this formula from its own
`native_remaining`; capacity-sensitive deterministic replay cannot increase
spill beyond 648 bytes.

### 12.9 Transactional publication and CQ consumption

The enumeration lock and a single terminal-owner bit are shared by normal
ENTER CQ consumption, cancellation, CLEANUP, and session fencing. A stable
matching CQE is privately copied and validated, then all native
prefix/spill/deferred-cookie/EXHAUSTED changes are installed under that lock
before CQ-head Release and grant rundown. A loser observes the committed
state and never formats, advances, or completes the IRP twice. A returned
next_cookie/EOF is deferred while spill is nonempty; no provider call occurs
until spill drains, and draining the last spill record atomically installs
the deferred cookie or EXHAUSTED state. The kernel installs a successor only
after the full batch is privately copied and validated and every entry is
either formatted or owned by the bounded spill; a cancelled, failed, fenced,
or stale-generation attempt with no accepted batch chooses no successor.
INSUFFICIENT_RESOURCES, cancellation, matcher OOM, quota refusal, and every
other registered transient zero-prefix failure select no snapshot successor
and create no required failure cache; ACTIVE_AT_START/ACTIVE and the input
cookie stay unchanged, so an exact retry may later differ and succeed.

### 12.10 Native formatting

- If at least one complete native record fits, the IRP returns SUCCESS with
  that prefix; the first record that does not fit and every later record
  remain in the at-most-648-byte spill, and the visible last
  `NextEntryOffset` is zero.
- Only the very first accepted native directory call on the handle may
  return a partial first record. Its fixed prefix fits by preflight; the
  kernel writes as many complete UTF-16 code-unit bytes as fit, leaves
  `FileNameLength` equal to the full canonical name length, sets the
  record's `NextEntryOffset = 0`, returns BUFFER_OVERFLOW(0x80000005), and
  consumes exactly that record. `IoStatus.Information` is exactly
  `fixed_prefix + 2*floor((native_length-fixed_prefix)/2)` and no byte at or
  above that value is modified. A later RESTART is not a first native call.
- On every later call, if no complete record fits after the fixed-prefix
  preflight, return SUCCESS with zero information and consume no spill
  record, cookie, or generation state.
- SINGLE stops after exactly one complete or first-call-partial record over
  the whole native IRP, including spill; it never resets per internal batch.
- Before the active QueryDir SQ publication, cancellation may win with
  CANCELLED and zero information. After publication, a valid successful
  batch wins and is formatted; once any record is committed to native
  output, later cancellation only stops further batches and that prefix
  completes.
- A registered non-cancellation provider error after a native prefix is
  retained once in `deferred_status`; the current IRP completes with its
  successful prefix and the next non-RESTART IRP returns that status with
  zero information before retrying the unchanged cookie. Provider CANCELLED
  with no earlier native prefix completes the current IRP CANCELLED; with a
  prefix it stops further batches and that prefix succeeds.
- A structurally empty unregistered QUERY_DIR status is first normalized to
  IO_DEVICE_ERROR under section 18.4, then follows the same
  prefix/deferred-status rule; with no prefix it completes the current IRP
  as IO_DEVICE_ERROR.

EOF on a successful final batch becomes EXHAUSTED after its spill drains.
NO_SUCH_FILE on an empty provider snapshot also installs EXHAUSTED; the
kernel returns native NO_SUCH_FILE only when that IRP was the first accepted
native call on the handle, otherwise native NO_MORE_FILES. Provider
NO_MORE_FILES installs the same state. Every later non-RESTART IRP completes
locally with NO_MORE_FILES, zero information, and no cookie-zero provider
call. Provider transitions are closed: SINGLE returns at most one entry;
success contains at least one complete entry; every issued grant fits a
maximum entry, so provider BUFFER_TOO_SMALL and empty success are protocol
faults; a repeated nonzero input cookie is nondestructive.

### 12.11 Pattern matching: the FsRtlIsNameInExpression contract

Pattern matching is one closed OS-backed algorithm. The kernel passes the
already-uppercased expression and each original candidate name to
`FsRtlIsNameInExpression(Expression, Name, TRUE, NULL)` at PASSIVE_LEVEL
through a tiny WDK C SEH shim; the SDK passes the same values to the
Windows 7+ `RtlIsNameInExpression` NTDLL export with `IgnoreCase=TRUE` and a
null UpcaseTable. Both therefore use the running OS default upcase table and
the same five wildcard meanings. Candidate names satisfy the
stored-component rule and contain no wildcard token. The provider MUST use
this SDK predicate when building the immutable match sequence; kernel
revalidation of returned positive matches cannot detect an omitted matching
entry. The SEH shim catches STATUS_NO_MEMORY: on the provider it produces
registered INSUFFICIENT_RESOURCES without advancing the input position; on
the kernel it accepts none of that batch and returns local
INSUFFICIENT_RESOURCES with zero information, or defers that local status
once when an earlier internal batch already produced a native prefix.
ACTIVE_AT_START/ACTIVE and the cookie remain unchanged. No other exception
is converted into a match, and the ABI performs no Unicode normalization.

### 12.12 Fence and replay identity

Session fencing uses the enumeration lock to capture and format any stable
ready result before releasing the old CQ head. With no stable result, a
zero-prefix IRP is reissued after ATTACH with the exact
generation/cookie/capacity; a native prefix completes and the next queued
IRP continues retained state. Cancellation may win while a zero-prefix IRP
waits in GRACE. With HOT_RESTART+EXACTLY_ONCE, provider snapshot state is
stateless or shared/durable across ATTACH, bounded by
`MAX_DURABLE_QUERY_DIR_SNAPSHOT_BYTES_PER_OPEN = 67108864` and
`MAX_DURABLE_QUERY_DIR_BYTES_PER_MOUNT = 268435456`
(`fsring-abi/src/durable/mod.rs`); one open owns at most one durable
snapshot. A genuine next generation atomically deletes/refunds the old
snapshot while admitting the new one; CLEANUP/CLOSE retires it; a session
fence alone does not. Native exposure is the commit point: no provider
cookie advances past a record that is neither returned nor retained in
bounded spill.

QUERY_DIR accepts SUCCESS, NO_MORE_FILES, NO_SUCH_FILE, or a member of
`QUERY_FAILURES` (section 18).

## 13. IRP_MJ_DIRECTORY_CONTROL / IRP_MN_NOTIFY_CHANGE_DIRECTORY

### 13.1 Sole ownership

The driver does not call `FsRtlNotifyFullChangeDirectory`,
`FsRtlNotifyFullReportChange`, or any other opaque FsRtl notify-list routine
in base 2.1. Each mount owns one `IO_CSQ` initialized with
`IoCsqInitializeEx`, a CSQ spin lock/list, a PASSIVE_LEVEL
notification-state push lock, notification event rundown, the notify
admission gate, and the nonwrapping notify fence generation. This is the
sole owner of every `IRP_MN_NOTIFY_CHANGE_DIRECTORY` and
`IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX` IRP and is what makes the exact
fence/cleanup statuses below implementable. The lock order and fence
protocol are `06-locking.md`.

### 13.2 Constants

From `fsring-abi/src/limits.rs`:

```text
VALID_NOTIFY_FILTER_MASK           = 0x00000fff
MAX_NOTIFY_BUFFER_BYTES_PER_CCB    = 1048576
MAX_NOTIFY_BUFFER_BYTES_PER_MOUNT  = 67108864
MAX_NOTIFY_REGISTRATIONS_PER_MOUNT = 4096
MAX_PENDING_NOTIFY_IRPS_PER_CCB    = 64
MAX_PENDING_NOTIFY_IRPS_PER_MOUNT  = 16384
MAX_PENDING_NOTIFY_MDL_BYTES_PER_CCB   = 4194304
MAX_PENDING_NOTIFY_MDL_BYTES_PER_MOUNT = 67108864
MAX_NOTIFY_PATH_COMPONENTS         = 1024
MAX_NOTIFY_RELATIVE_PATH_BYTES     = 65520
MAX_PRECISE_NOTIFY_LINKS_PER_LOCAL_OPERATION = 64
```

The valid mask is the OR of FILE_NAME `0x1`, DIR_NAME `0x2`, ATTRIBUTES
`0x4`, SIZE `0x8`, LAST_WRITE `0x10`, LAST_ACCESS `0x20`, CREATION `0x40`,
EA `0x80`, SECURITY `0x100`, STREAM_NAME `0x200`, STREAM_SIZE `0x400`, and
STREAM_WRITE `0x800`; `0x80` is the standard EA bit, not a reserved hole.
Stream filter bits are accepted but never match in base 2.1 because named
stream events have no negotiated schema.

### 13.3 Registration preflight

A valid request names a live directory CCB that has not seen CLEANUP and
whose granted access contains FILE_LIST_DIRECTORY; violations return
respectively STATUS_NOT_A_DIRECTORY(0xc0000103), STATUS_NOTIFY_CLEANUP
(0x0000010b), or ACCESS_DENIED, with zero information before registration.
It has an output length no greater than the per-CCB bound, a nonzero
completion filter contained in `VALID_NOTIFY_FILTER_MASK`, and only the
native watch-tree flag. The legacy minor always uses
`Parameters.NotifyDirectory` and is implicitly `DirectoryNotifyInformation`
on every OS. Only the EX minor reads
`Parameters.NotifyDirectoryEx.DirectoryNotifyInformationClass`; it accepts
exactly `DirectoryNotifyInformation`, while extended/full classes return
NOT_SUPPORTED with zero information. The EX branch is compile/runtime-gated
to the modern profile; `platform-win7` contains no post-Win7 symbol or
import and returns INVALID_DEVICE_REQUEST for that unknown minor.

The first request allocates exactly its output length as the CCB accumulator
under the mount byte/registration quotas (zero length is a signal-only
registration with no allocation), captures and references the requestor
`SECURITY_SUBJECT_CONTEXT`, and freezes root FileId, completion filter, and
watch-tree until overflow reset, fence, or cleanup. A later request with a
different filter/watch-tree returns INVALID_PARAMETER; a different output
length is legal and is checked independently at completion. Accumulator
storage and pending MDL pages are independent quotas: each later IRP is
charged from its own complete MDL span regardless of the first
registration's length. Allocation/quota failure returns
INSUFFICIENT_RESOURCES, information zero, before CSQ insertion.

Section 1.2's direct-I/O preflight applies. The nonzero write-locked output
MDL is mapped once and its system VA is retained in `NotifyIrpContext`,
remains backed by the IRP-owned MDL until terminal completion, and is never
read as input. `NotifyIrpContext` also owns the exact pending-count/MDL
quota ticket. Zero-length requests require `Irp->MdlAddress == NULL`, need
neither MDL nor mapping, and still carry their zero-byte-count ticket; a
nonnull value is `STATUS_INVALID_USER_BUFFER` with zero information before
registration.

### 13.4 Insertion protocol

Each IRP has a preallocated nonpaged `NotifyIrpContext` containing an
embedded notification `KEVENT completion_gate` initialized nonsignaled
before insertion; DriverContext[0] may reference it and DriverContext[3] is
reserved exclusively for IO_CSQ. After preflight the dispatch path takes
notification state. OVERFLOWED is claimed and completed immediately with
STATUS_NOTIFY_ENUM_DIR; a nonempty accumulated batch is changed to immutable
FANOUT and claimed for immediate delivery. Otherwise dispatch creates a
provisional INSERTING context carrying the already reserved
per-CCB/per-mount/global count and MDL-byte ticket, marks the IRP pending,
and, while still holding notification state, calls `IoCsqInsertIrpEx`; this
fixed notification-state-then-CSQ order closes the gap in which an event
could be accumulated just before insertion. Under the CSQ lock the insert
callback revalidates CCB/mount admission and the reserved counts and either
inserts or returns the exact rejection status. No CSQ callback acquires
notification state.

`IoMarkIrpPending` is called immediately before `IoCsqInsertIrpEx`. From
that call onward the dispatch routine's return value is unconditionally
STATUS_PENDING, whether insertion succeeds, insertion rejects, cancellation
is observed synchronously, or a gated worker completes the IRP before
dispatch returns. An insertion rejection is the terminal
`Irp->IoStatus.Status`, never the dispatch return status; the dispatch
routine stores this constant return decision before any possible
completion. Preflight, OVERFLOWED, and immediate-FANOUT paths occur before
`IoMarkIrpPending`; they complete synchronously and return their final
status and Information.

Because an already-cancelled insertion may synchronously invoke
`CsqCompleteCanceledIrp`, that callback never calls `IoCompleteRequest`,
frees a context, or touches registration state. It only CAS-claims terminal
owner CSQ_CANCEL and pushes the preallocated context onto a lock-free
deferred-completion list. On return from `IoCsqInsertIrpEx`, dispatch still
holds notification state: successful insertion commits INSERTING to QUEUED;
rejection or an already-claimed cancellation transfers the complete quota
ticket to the winning terminal owner. If this was the first request, its
accumulator/subject/quota remain provisional and are committed only with
QUEUED; otherwise dispatch rolls them all back, preserving any preexisting
registration. Dispatch drops notification state and then signals the
embedded completion gate. If dispatch owns a rejection, it sets that exact
status with Information zero, leaves output untouched, completes once, and
still returns STATUS_PENDING; otherwise it leaves the cancel owner to a
PASSIVE worker, which waits nonalertably at PASSIVE_LEVEL on the gate. The
event handoff publishes all provisional commit/rollback state before any
worker completes CANCELLED with zero information and untouched output.
Dispatch never dereferences the IRP after a path may have completed it.
Every terminal owner retains the ticket through its last MDL access and
completion, then refunds it exactly once per section 2. Neither synchronous
insertion cancellation nor ordinary rejection completes an IRP under the
push lock. Once insertion succeeds dispatch does not touch the IRP.

### 13.5 Delivery states and output

Registration delivery state is exactly IDLE, FANOUT, OVERFLOWED, or
CLEANED, plus the independent post-fence marker. In IDLE an event first
appends every complete matching record to the fixed CCB accumulator;
exceeding its byte capacity or a path/link/security-proof bound clears it
and enters OVERFLOWED. If IRPs are queued after a successful append, the
accumulator becomes an immutable FANOUT batch; the worker removes every
then-queued IRP for that CCB through IO_CSQ, gives each a
registration-rundown reference, and releases all locks before copying and
completing. Each recipient receives the same batch if its buffer fits; a
smaller buffer receives STATUS_NOTIFY_ENUM_DIR; a zero-length recipient
receives SUCCESS with zero information and no name copy and does not force
other recipients to overflow. A zero-capacity registration is an explicit
branch rather than an attempted append: if a visible event finds queued
IRPs, the worker removes the whole then-queued set — every zero-length
signal-only recipient completes SUCCESS with zero information, and every
nonzero recipient completes STATUS_NOTIFY_ENUM_DIR with zero information
because no batch was retained — consuming the event and returning the
registration to IDLE; with no queued recipient the event installs OVERFLOWED
so the next request receives rescan.

The one accumulator remains immutable until every fan-out owner drops its
rundown; no per-recipient batch allocation is made. A new event during
FANOUT sets a deferred-overflow bit instead of modifying the buffer; new
notify IRPs may queue for the next delivery. After the last owner, the
worker clears the batch and returns to IDLE, or enters OVERFLOWED and drains
the new IRPs with rescan when deferred overflow was set. OVERFLOWED with
queued IRPs removes all of them and completes rescan; with none queued, the
next request atomically consumes the marker without registering. An
accumulated batch, insertion, cancellation, and a new event therefore have
one total order and no event is silently lost.

Normal output is one or more standard `FILE_NOTIFY_INFORMATION` records
(`NextEntryOffset:u32, Action:u32, FileNameLength:u32, FileName:[u16]`).
The only emitted actions are FILE_ACTION_ADDED=1, FILE_ACTION_REMOVED=2,
FILE_ACTION_MODIFIED=3, FILE_ACTION_RENAMED_OLD_NAME=4, and
FILE_ACTION_RENAMED_NEW_NAME=5; object-ID/tunnelling action codes and every
other value are never synthesized in base 2.1. The name is the original
stored UTF-16 spelling relative to the watched directory; recursive
components are joined by one backslash; there is no normalization or case
folding and no empty, dot, dot-dot, NUL, slash, or trailing-separator form.
Each nonfinal offset is `align4(12 + FileNameLength)` with zero padding;
the final offset is zero. `IoStatus.Information` ends immediately after the
final name and excludes unused caller tail. No partial batch is returned; a
rename pair is indivisible and adjacent in one completion. If the selected
complete batch/path/pair does not fit, the outcome is STATUS_NOTIFY_ENUM_DIR
with zero information and untouched output, except for the explicit
zero-length signal-only completion above.

### 13.6 The removal-winner table

Terminal ownership is the first successful `IoCsqRemoveIrp` or
`IoCsqRemoveNextIrp`:

| Removal winner | Status | Information | Registration effect |
|---|---|---:|---|
| CSQ cancellation callback | CANCELLED `0xc0000120` | 0 | none |
| CCB CLEANUP | STATUS_NOTIFY_CLEANUP `0x0000010b` | 0 | terminal CLEANED |
| normal event | SUCCESS | exact packed bytes, or 0 for a zero-length signal-only IRP | batch cleared after fan-out |
| buffer/path/security-proof overflow | STATUS_NOTIFY_ENUM_DIR `0x0000010c` | 0 | accumulator cleared, ordinary marker consumed |
| session fence | STATUS_NOTIFY_ENUM_DIR `0x0000010c` | 0 | registration cleared, post-fence marker retained |

### 13.7 CLEANUP and fence teardown

CLEANUP first closes that CCB's notify admission, marks CLEANED, removes all
its IRPs, waits registration rundown, releases the subject context, and
frees the accumulator; later notify calls on the FileObject return
STATUS_NOTIFY_CLEANUP. A fence closes mount admission, increments the fence
generation, waits event rundown with no FCB/session/ring/notification lock
held, clears all registrations and accumulators, and removes all remaining
mount IRPs. Every old CCB retains a post-fence marker even if its queued IRP
was just completed by the fence; after ATTACH, its first request returns
STATUS_NOTIFY_ENUM_DIR and only advances that marker without allocating an
accumulator or capturing a subject, while the next request registers anew.
CLEANED takes precedence for a new request. The marker check occurs after
safe output preflight but before first-registration resource commit. For an
already queued IRP the first removal owner always wins.

### 13.8 Event matching and the deferred-completion worker

Base 2.1 forbids directory hard links: root has no parent and every other
live directory has exactly one parent LinkId. A file event carries a nonzero
FileId and the exact nonzero LinkId/parent/name that changed. Non-namespace
metadata or data changes to a multiply linked file generate one event per
live link; if the complete link set is unavailable or exceeds
`MAX_PRECISE_NOTIFY_LINKS_PER_LOCAL_OPERATION = 64`, every active
registration is covered by rescan. Direct watches match
`event_parent == watched_root`; watch-tree requests match when the watched
root is the event parent or an ancestor of it; a change to the watched
directory itself is not reported.

The worker proves ancestry and original components from one
namespace-topology snapshot. Missing/stale topology, more than 1024
components, more than 65520 relative-name bytes, a changed topology epoch,
or unavailable fixed scratch causes rescan rather than guessed output. It
locks the captured subject and checks enabled SeChangeNotifyPrivilege;
without it, `SeAccessCheck(UserMode, FILE_TRAVERSE)` must succeed against
every descendant directory from immediately below the watched root through
the event parent. Definite denial makes that side invisible and copies no
name bytes; missing/stale security or resource failure causes rescan. For
rename, both visible sides yield OLD+NEW, old-only becomes REMOVED, new-only
becomes ADDED, and neither-visible yields no record.

The CSQ spin lock protects only queue links and IRP ownership.
Namespace/domain locks produce referenced topology/security snapshots before
notification-state acquisition. Privilege/access checks, allocation/free,
waits, user-buffer copies, and `IoCompleteRequest` occur under neither lock.
The only nested queue order is the notification-state push lock followed by
the CSQ spin lock; cancellation/CSQ callbacks never take notification state,
and no path takes the reverse order. `CsqCompleteCanceledIrp` performs only
its terminal-owner CAS and lock-free enqueue; the deferred worker cannot
complete until the dispatch-side Release marker proves the outer state lock
is gone. Workers hold mount and registration rundown. Fence order is: close
admission, signal workers/ENTER, wait rundown, update notification state,
remove via IO_CSQ, release locks, then complete. No notify completion occurs
under a ring token, CSQ/state/FCB/domain/session lock, and every
subject/IRP/context has one release owner (`06-locking.md`).

## 14. IRP_MJ_LOCK_CONTROL

Byte-range locks are kernel-local: ABI 2.1 defines no wire operation for
lock, unlock, or lock query, and the provider never observes native
LOCK_CONTROL. The kernel arbitrates shared/exclusive byte-range locks per
the Windows contract over its own retained per-FCB lock state, and that
arbitration precedes READ/WRITE emission — an emitted READ or WRITE has
already passed byte-range arbitration for the requesting handle, and the
truncating size-gate substate performs byte-lock arbitration before any size
reduction is published (section 9.4). Lock-conflict failures for data I/O
complete locally with FILE_LOCK_CONFLICT(0xc0000054) and zero information.

FILE_LOCK_CONFLICT nevertheless remains a registered provider failure: it is
a member of both `READ_FAILURES` and `WRITE_FAILURES`, because a provider
backed by a real filesystem may surface its own mandatory-lock or
range-conflict condition. The kernel treats such a completion as any other
registered data failure; it never reinterprets or suppresses it.
LOCK_CONTROL consumes no ReqId, grant, credit, or ring entry.

## 15. IRP_MJ_FILE_SYSTEM_CONTROL

ABI 2.1 registers no FSCTL code, so the kernel MUST NOT emit FSCTL and no
FSCTL completion is legal. The `FsctlV1` wire layout (64/8) exists in the
registry for structural stability only; a later minor may add a code only
together with its exact input/output schema, access rule, maximum sizes, and
status array. A provider FSCTL completion in any session is an unregistered
protocol opcode completion and faults the session (section 18.4).

Feature-gated local completions are closed:

- native `FSCTL_SET_SPARSE` (TRUE or FALSE) completes locally with
  NOT_SUPPORTED(0xc00000bb), zero information, and no SQE, because sparse
  mutation is unselectable in base 2.1; mutation kind SET_SPARSE,
  `SetSparseV1`, or a provider result for it is a protocol fault
  (assignment 11 reserves registry compatibility only);
- native get/set/delete-reparse FSCTL forms complete locally with
  NOT_SUPPORTED and no SQE, because REPARSE is unselectable; a provider
  reparse result is a protocol fault;
- every other data-path FSCTL completes locally with its documented native
  status (INVALID_DEVICE_REQUEST for unrecognized codes) and no SQE.

Mount-path FSCTLs (mount/verify/dismount volume plumbing) are
`10-lifecycle.md`.

## 16. Cancellation model

### 16.1 The per-request state lock

Every retained semantic request — READ, FLUSH, all QUERY forms, QueryDir,
and the journaled operations — has one state lock shared by cancellation, SQ
publication, CQ consumption, and the session-fence snapshot. The retained
state records `semantic_may_be_visible`, `cancel_requested`, and a single
terminal owner. Before any Release operation can make the semantic SQ record
or its producer position observable, the publisher sets
`semantic_may_be_visible` under the lock. Cancellation observed before that
transition wins and releases everything locally. Cancellation observed at or
after it is post-publication even if the daemon has not yet consumed the
cell. A failed reservation may roll the bit back only while the same lock
proves that no SQ cell or producer state was ever observable and no fence
snapshot intervened; otherwise recovery takes the conservative published
path.

### 16.2 PCancel

`PCancel` is an advisory, slot-free record with exactly one legal SQE
encoding: opcode CANCEL, flags NO_COMPLETION, payload length 16, reserved
zero, outer `req_id = 0`, `kernel_open_id = 0`, `ccb_sequence = 0`,
`PCancel.target_req_id` equal to the currently live semantic ReqId (the
initial publication or an exact recovery resubmission),
`target_session_epoch` equal to that generation's current session epoch, and
all unused payload bytes zero. ReqId zero is never an allocatable
request-table identity. CANCEL consumes no request-table entry, does not
advance any ReqId generation, and receives no CQE. It is published on the
same SQ ring and after the target semantic cell, through the control-cell
reserve of section 3.2. Under the operation lock it may target only the
still-live semantic generation; candidate capture retires that target. A
session fence forbids publication against every old-session generation;
after authenticated ATTACH and an actual exact semantic resubmission, a
still-pending cancellation may publish a new PCancel against that fresh live
semantic generation. PCancel may target any currently live application
semantic generation but never targets QUERY_OP, ACK_RESULT,
PREPARE/REPLAY_OPEN recovery control traffic, or PT/external
acknowledgements. A stale or duplicate target is ignored by the provider
without completion.

### 16.3 Observational one-terminal-owner arbitration

For a nonjournaled/observational request, prepublication cancellation
completes locally with CANCELLED. Postpublication cancellation records
intent, publishes at most one same-ring PCancel through the control reserve,
and retains the native IRP, the ReqId generation, every grant/mapping, and
the request bytes. A locked CAS selects exactly one terminal observation:

| Terminal observation | Outcome |
|---|---|
| stable matching CQ candidate captured first | the validated outcome completes the IRP |
| registered provider CANCELLED captured first | cancellation completes with CANCELLED |
| session fence with no candidate after its stable-prefix drain | pending cancellation completes CANCELLED |
| session fence with a restart-eligible observation | the request remains retained for exact reissue after ATTACH |
| direct teardown | the operation class's registered terminal failure |

No slot, token, grant, or mapping is reused until that owner and all mapping
rundown finish. QueryDir additionally applies its generation/cookie rules
but uses this same terminal arbitration; it cannot turn a legitimate late CQ
into a stale-generation protocol fault by freeing early. The native CANCEL
routine interlocks (`IoSetCancelRoutine` and the CSQ paths of sections 9.6
and 13) resolve through the same one-terminal-owner CAS registry defined in
`06-locking.md`.

### 16.4 Journaled cancellation

After possible semantic publication, the kernel records `cancel_requested`
but retains the OpId, digest, request transcript, immutable inputs, and the
logical request slot. A provider may return registered CANCELLED only after
removing its PREPARED bundle with no side effect; QUERY_OP NOT_FOUND must
confirm it. After session loss, or after an observation QUERY_OP reports
PREPARED while cancellation is pending, the kernel sends `QueryOpV2` with
`ABORT_IF_PREPARED` rather than trying to address an obsolete ReqId. The
provider handles that query and the physical journal bundle in one atomic
transaction: an exact PREPARED bundle is deleted/refunded and reported
NOT_FOUND; complete ABSENT reports NOT_FOUND; an exact COMMITTED bundle is
left untouched and its durable result is reported COMMITTED. It can never
report PREPARED in abort mode. A digest mismatch is a protocol fault, and
every partial bundle is corruption. Verified COMMITTED always wins, while a
successful abort completes CANCELLED. Session loss at any point enters the
phase table of section 17.2; cancellation never releases recovery state
early.

## 17. Recovery dispatch

### 17.1 The reserved open-lifecycle replay lane and REPLAY_OPEN

`provider_open_cookie` is session-local authority whose mode is ordinary or
paging-only; it MUST NOT be stored in a durable committed result, and a
fence, provider process exit, or epoch change closes every old cookie and
destroys every old volatile replay state. Recovery applies the durable OPEN
replay projection of `04-object-model.md` and obtains a fresh cookie through
REPLAY_OPEN (`ReplayOpenV2`, 104/8). The owning ring's reserved
open-lifecycle ReqId/control lane — not an application `max_inflight` slot —
serializes REPLAY_OPEN and any subsequent recovery CLEANUP/CLOSE phase, with
a fresh nonzero generation for each wire phase. Replay of every
already-committed LIVE or kernel-retained CLEANED open, including a
drain-only or PAGING_ONLY replay, can therefore precede resumption of its
retained cookie-dependent work even when all application slots are retained.

REPLAY_OPEN has no durable child row, reservation, or accounting charge. Per
bound session the provider keeps bounded volatile replay state keyed by
`(session_epoch, kernel_open_id)`: UNSEEN, then PENDING, then DONE, where
DONE stores the exact persistent-plus-volatile request projection and the
current-session cookie. Zero state flags require OPEN(LIVE);
`REPLAY_STATE_PAGING_ONLY = 0x0000000000000001` requires OPEN(CLEANED);
ABSENT always faults. Under the shared per-open serialization domain, and
only after its final mode-specific row revalidation, the provider installs
DONE with the complete projection, authority mode, and fresh cookie before
its success CQ Release. An exact duplicate in the same epoch serializes with
PENDING or returns the identical DONE cookie; a changed duplicate is a
protocol fault. Zero-flag replay after CLEANED, PAGING_ONLY replay before
CLEANED or after ABSENT, and every replay after complete ABSENT are protocol
faults without authority.

The kernel marks an open replay-ready for the current epoch only after
capturing its exact successful ordinary REPLAY_OPEN CQE; `DRAIN_REPLAY` sets
only the cleanup-drain authority (section 7.3), and a successful PAGING_ONLY
replay sets only stream readiness. A fence clears all three states. The
ATTACH open barrier is exhaustive: a LIVE handle with no lifecycle
transition pending must become replay-ready in the exact epoch;
`CLEANUP_PENDING`, including `DRAIN_REPLAY` and predecessor recovery, must
reach CLEANED/CLEANUP_DONE and then PAGING_ONLY readiness while its stream
gate remains open; an already CLEANED handle awaiting native CLOSE must
complete PAGING_ONLY replay before ACTIVE; `CLOSE_PENDING` must replay
paging authority only when retained stream predecessors need it, drain them,
and complete ABSENT; CLOSED/ABSENT has no barrier work. ACTIVE and provider
dispatch require every retained OPEN(LIVE) handle to have ordinary replay
readiness, and every retained OPEN(CLEANED) stream-open handle to have
PAGING_ONLY readiness, in that exact epoch. REPLAY_OPEN accepts SUCCESS
only, with `out_len = 24` and `information = 16` (the reply-grant echo).

### 17.2 The QUERY_OP phase-by-answer table

When EXACTLY_ONCE is selected, exactly COMMIT_OPEN, WRITE, and MUTATE are
journaled; QUERY_OP and ACK_RESULT exist only with the paired
HOT_RESTART+EXACTLY_ONCE features, and their emission or completion without
them is a protocol fault. An ordinary successful COMMIT_OPEN, WRITE, or
MUTATE CQE is only a candidate result: the kernel privately snapshots the
complete ordinary result, runs its grant rundown, and issues `QueryOpV2` on
the authenticated live session with the same OpId and operation digest; the
provider answers by reading its exact durable bundle, and only COMMITTED is
legal for that ordinary-path confirmation. Candidate-to-durable equality is
field-for-field after excluding only the explicitly session-local open
cookie.

As soon as any stable CQ cell carries the currently live semantic ReqId, the
CQ consumer enters the internal transient `CANDIDATE_CAPTURE` phase under
the operation lock before validating CQ kind, opcode, status, output, or
payload. While still holding the operation's rundown reference, it privately
copies the complete cell, validates every grant identity and range against
immutable kernel ownership state before dereference, copies only safely
bounded referenced bytes, validates that immutable snapshot, and atomically
installs FAILURE_CANDIDATE, SUCCESS_CANDIDATE, or INVALID_CANDIDATE plus the
complete snapshot under the same state gate before the CQ-head Release,
old-ReqId invalidation, or grant release. INVALID_CANDIDATE includes every
unregistered status, wrong kind/opcode, malformed or contradictory result
shape, invalid reference or referenced byte, and otherwise illegal terminal
candidate; none may fall back to NO_CANDIDATE. A session fence shares that
gate, waits for any `CANDIDATE_CAPTURE` to finish, and drains any
already-stable matching candidate cell with the same capture ordering before
it may classify the operation as NO_CANDIDATE.

The ten retained phases are:

```text
NO_CANDIDATE, FAILURE_CANDIDATE, SUCCESS_CANDIDATE,
INVALID_CANDIDATE, COMMITTED_VERIFIED,
APPLIED_NOTIFY_PENDING, APPLIED_ACK_UNSENT, APPLIED_ACK_SENT,
ACKNOWLEDGED, INDETERMINATE
```

and the provider answers NOT_FOUND, PREPARED, or COMMITTED
(`fsring-abi/src/msgs/recovery.rs`). The complete behavior table:

| Retained phase | NOT_FOUND | PREPARED | COMMITTED |
|---|---|---|---|
| NO_CANDIDATE | if cancelled, WRITE/MUTATE complete CANCELLED but COMMIT_OPEN first enters the retained ABORT_OPEN subprotocol; otherwise resubmit the exact same OpId/digest/request | if cancelled, issue the atomic ABORT_IF_PREPARED query; otherwise resume that exact transaction | validate retained request/digest/result, then COMMITTED_VERIFIED |
| FAILURE_CANDIDATE | WRITE/MUTATE complete the exact saved registered failure; COMMIT_OPEN first runs the retained ABORT_OPEN subprotocol and completes that saved failure only after Abort success | protocol contradiction: INDETERMINATE | durable success is authoritative; validate it, record the provider violation, then COMMITTED_VERIFIED |
| SUCCESS_CANDIDATE | INDETERMINATE; never resubmit | INDETERMINATE; never resume or resubmit | require exact candidate projection equality, then COMMITTED_VERIFIED; mismatch is INDETERMINATE |
| INVALID_CANDIDATE | INDETERMINATE; never resubmit | INDETERMINATE; never resume or resubmit | ignore the illegal candidate, validate the durable result against the original request/digest, record the violation, then COMMITTED_VERIFIED |
| COMMITTED_VERIFIED | protocol fault: INDETERMINATE | protocol fault: INDETERMINATE | exact repeat; enter fence-excluded APPLYING, apply once, then APPLIED_NOTIFY_PENDING |
| APPLIED_NOTIFY_PENDING | illegal pre-ACK pruning: INDETERMINATE, never reapply | protocol fault: INDETERMINATE | exact repeat; deliver the staged local event or cover it by rescan, then APPLIED_ACK_UNSENT; never reapply |
| APPLIED_ACK_UNSENT | illegal pre-ACK pruning: INDETERMINATE, never reapply | protocol fault: INDETERMINATE | prepare ACK_RESULT, enter APPLIED_ACK_SENT before its Release publication, then publish; never reapply |
| APPLIED_ACK_SENT | prior ACK deletion succeeded and its CQE was lost: ACKNOWLEDGED | protocol fault: INDETERMINATE | retry the identical ACK_RESULT; never reapply |
| ACKNOWLEDGED | no QUERY_OP is emitted | no QUERY_OP is emitted | no QUERY_OP is emitted |
| INDETERMINATE | administrative teardown only | administrative teardown only | administrative teardown only |

Only NO_CANDIDATE may resubmit a semantic operation, and it always reuses
the same OpId/digest/bytes. One logical journaled operation occupies one
`max_inflight` request-table slot through confirmation and acknowledgement:
QUERY_OP reuses the same slot index with the next generation, every legal
buffer-too-small retry does so again, and ACK_RESULT does so after the
QUERY_OP completion; every old generation remains stale. QUERY_OP phase
transitions and ACKNOWLEDGED are installed before their CQ-head Release and
ReqId retirement; the retained operation state is never stored only in the
per-wire-phase payload. Generation exhaustion retires the slot/session
rather than wrapping. The wire-shape rules are phase-independent:
`QueryOpResultV1.flags` and reserved are zero and OpId equals the request;
NOT_FOUND and PREPARED require a NONE result BufferRef; COMMITTED requires
the result-grant echo shrunk to the exact derived
`CommittedResultV1.struct_size`. The kernel validates inner opcode, result
kind, SUCCESS status, information, volume sequence, identities, sizes,
generations, and payload against the retained operation before the table
action. APPLYING, ApplyReserve, and the sorted domain-lock order are
`06-locking.md`; the durable digest and committed-result layouts are
`03-messages.md` section 8.

If a journaled operation returns a registered non-success terminal status
(including RETRY), the provider must prove no side effect was committed and
atomically delete/refund its exact PREPARED bundle before publishing that
CQE; the kernel snapshots the candidate failure and issues the same-session
QUERY_OP, and only NOT_FOUND confirms the terminal failure. A PREPARED
bundle is never silently pruned because of timeout or live-mount session
loss. Any unregistered status for COMMIT_OPEN, WRITE, or MUTATE is a session
protocol fault regardless of output shape: with EXACTLY_ONCE the kernel
retains the OpId, digest, request, and immutable inputs and resolves
QUERY_OP after authenticated attach through the INVALID_CANDIDATE row — it
never normalizes or terminally completes the candidate status and never uses
the NO_CANDIDATE replay rule; without EXACTLY_ONCE it quarantines and tears
down the mount and never reissues that semantic operation in the same mount
incarnation.

### 17.3 The ABORT_OPEN subprotocol

The COMMIT_OPEN NOT_FOUND actions never release the logical CREATE slot
while its separate open-prepare/index pair can exist. They enter
OPEN_ABORT_UNSENT, publish the exact `AbortOpenV1 { TransactionId }` with a
fresh generation on that same slot, and set OPEN_ABORT_MAY_BE_VISIBLE before
SQ Release. The provider resolves the TransactionId index and atomically
removes only that exact index/OpId open-prepare pair; absence of both is
idempotent SUCCESS, while a one-sided or mismatched pair is corruption. A
matching successful CQE installs OPEN_ABORTED before CQ-head Release, then
and only then completes the native IRP with the saved CANCELLED/failure and
releases the slot and Prepare charge. Session fencing preserves either Abort
phase and reissues the identical TransactionId after ATTACH. ABORT_OPEN has
no QUERY_OP and can never be bypassed by the generic WRITE/MUTATE table
action. An `ABORT_IF_PREPARED` query follows the same wire-result shape but
PREPARED is illegal; only its atomic NOT_FOUND or COMMITTED outcome is
accepted. If a zero-flag observation QUERY_OP was already visible when
cancellation arrived, an observed PREPARED causes a fresh-generation
abort-mode QUERY_OP rather than semantic resubmission. QUERY_OP publication
is recorded under the state lock before its SQ Release; on ambiguous
publication or session loss the same zero-flag query or idempotent
abort-mode query is issued again.

### 17.4 BTS retry, ACK ordering, and INDETERMINATE quarantine

`MAX_QUERY_OP_BTS_RETRIES = 1` (`fsring-abi/src/validate/messages.rs`). The
base-2.1 committed-result maximum is 224 bytes, and the ordinary
confirmation path reserves that complete grant from the U2K forward-progress
pool, so BUFFER_TOO_SMALL against the ordinary confirmation's 224-byte grant
is always a protocol fault. Recovery allocates the exact derived capacity
initially (WRITE=80, COMMIT_OPEN=136, base mutation=112, UNLINK=168,
LINK=216, RENAME=224 bytes). If an already-issued smaller recovery grant
receives BUFFER_TOO_SMALL, one retry is legal only when CQ information
equals that exact derived size, is strictly greater than the current grant
capacity, and no prior BTS retry occurred; repeated, equal/decreasing,
wrong-size, or out-of-range BTS is a protocol fault. QUERY_OP
BUFFER_TOO_SMALL has no result blob, reports the required bytes in CQ
information, and changes no journal, candidate, cancellation, or
retained-operation state; a legal retry reuses the same logical slot with
the next nonzero generation and never allocates a second application slot.

ACK ordering is exact: DELIVERED/COVERED_BY_RESCAN changes
`APPLIED_NOTIFY_PENDING` to APPLIED_ACK_UNSENT (an operation with NOT_DUE
performs that transition directly); only then may the application IRP
complete or the kernel reserve and fill
`AckResultV2 { OpId, operation_digest }`, entering APPLIED_ACK_SENT under
the state lock before the SQ cell/producer Release makes the ACK
observable. A pre-publication failure may roll back to APPLIED_ACK_UNSENT
only with the same proof of nonvisibility used for semantic publication; an
ambiguous case remains APPLIED_ACK_SENT and recovery safely retries or
infers the processed ACK. The provider atomically deletes/refunds only the
exact COMMITTED bundle matching both OpId and digest before returning
ACK_RESULT success; ACK_RESULT is idempotent only when the complete bundle
and all of its reservations are absent, and a partial bundle or any present
row with the same OpId and a different digest is corruption that cannot be
inferred as a prior ACK. Consuming the successful ACK_RESULT CQE enters
ACKNOWLEDGED before CQ-head Release and retires the logical slot only after
rundown. Within one live kernel mount incarnation, an unacknowledged
COMMITTED bundle survives daemon process exit and session fencing; session
loss alone is never acknowledgement.

INDETERMINATE is fail-closed: the kernel blocks new mount I/O,
conservatively invalidates caches, records a journal-integrity violation,
sends no ACK, performs no candidate state application, and permits only
bounded administrative teardown. The affected and queued application IRPs
complete with FILE_CORRUPT_ERROR(0xc0000102), zero information, and no
output only after the mount is quarantined, so no retry can enter that
MountId. The operation is never replayed in that MountId. This is the
deterministic response when a provider claims a possible side effect without
the durable evidence required by EXACTLY_ONCE.

### 17.5 BOUND_RECONCILING admission and the DETACH interlock

While a mount is BOUND_RECONCILING, only authenticated recovery-system SQ/CQ
traffic, exact reissue/QUERY_OP/ABORT/ACK of an already-retained logical
request, DONATE_BACKING needed for PT rebuild, ENTER, QUERY, and lifecycle
control are admitted; every new native filesystem IRP is held in its
existing bounded queue or fails through the terminal owner, and no newly
admitted semantic SQE is published. Classification and every later native
lifecycle transition first acquires the lifecycle-admission gate shared,
then the per-open gate, and registers a unit in the mount recovery-work
counter before releasing the gates in reverse order; no path may hold a
per-open gate while acquiring the lifecycle-admission gate. ACTIVE
publication takes that gate exclusively, closes registration, then
acquires/rechecks each classified per-open gate one at a time in the same
order; it commits only when every classification and the counter are
satisfied. Each open has one idempotent registered-unit bit, consumption
clears it exactly once, and checked u64 overflow terminalizes the mount
rather than wrapping. Consumption of the last open/PT/external READY barrier
before the retained GRACE deadline atomically publishes ACTIVE and opens
kernel ordinary admission; consequently no cleanup can fall between per-open
classification and READY/ACTIVE publication. The mount/session state
registry (`retire_mount_state`, GRACE, `RESTART_GRACE_TIMEOUT_MS = 30000`)
is `04-object-model.md`.

A clean DETACH is DEVICE_BUSY while any retained request is
PREPARED/COMMITTED or any ACK is outstanding; it succeeds only after the
journal handshake is drained. LIVE and CLEANED durable OPEN rows are equally
clean-DETACH blockers. The DETACH terminal-owner arbitration, the
admission-gate close, and the stable retained-blocker check are
`06-locking.md`; cross-boot retirement and the authenticated RETIRE_MOUNT
receipt handshake are `04-object-model.md` and `10-lifecycle.md`.

## 18. Completion status and output matrix

### 18.1 The six named failure arrays

The crate provides a source-level completion validator keyed by
`(kind, opcode, status)` with no severity-based catch-all
(`fsring-abi/src/validate/messages.rs`). The six sorted named arrays are
exact and closed; their complete NTSTATUS memberships are tabulated in
`03-messages.md` section 5 and are not repeated byte-for-byte here:

| Array | Members | Applies to | Class-distinctive members |
|---|---:|---|---|
| `OPEN_FAILURES` | 17 | PREPARE_OPEN, COMMIT_OPEN | OBJECT_NAME_COLLISION, SHARING_VIOLATION, DELETE_PENDING, FILE_IS_A_DIRECTORY, NOT_A_DIRECTORY |
| `READ_FAILURES` | 8 | READ | FILE_LOCK_CONFLICT |
| `WRITE_FAILURES` | 11 | WRITE | FILE_LOCK_CONFLICT, DISK_FULL, MEDIA_WRITE_PROTECTED, RETRY |
| `FLUSH_FAILURES` | 7 | FLUSH | no ACCESS_DENIED member; media and corruption members only |
| `QUERY_FAILURES` | 8 | QUERY_INFO, QUERY_VOLUME, QUERY_DIR, QUERY_SECURITY | NOT_SUPPORTED |
| `MUTATE_FAILURES` | 22 | MUTATE | PRIVILEGE_NOT_HELD, INVALID_SECURITY_DESCR, DIRECTORY_NOT_EMPTY, CANNOT_DELETE, RETRY, USER_MAPPED_FILE |

### 18.2 The per-opcode closed status table

| Opcode | Legal statuses |
|---|---|
| PREPARE_OPEN | SUCCESS, `OPEN_FAILURES` |
| COMMIT_OPEN | SUCCESS, RETRY(0xc000022d), `OPEN_FAILURES` |
| ABORT_OPEN / CLEANUP / CLOSE | SUCCESS only |
| READ | SUCCESS, END_OF_FILE(0xc0000011), `READ_FAILURES` |
| WRITE | SUCCESS, `WRITE_FAILURES` |
| FLUSH | SUCCESS, `FLUSH_FAILURES` |
| QUERY_INFO / QUERY_VOLUME | SUCCESS, `QUERY_FAILURES` |
| QUERY_DIR | SUCCESS, NO_MORE_FILES(0x80000006), NO_SUCH_FILE(0xc000000f), `QUERY_FAILURES` |
| QUERY_SECURITY | SUCCESS, `QUERY_FAILURES` |
| MUTATE | SUCCESS, `MUTATE_FAILURES` |
| REPLAY_OPEN / ACK_RESULT / PT_ROUTE_ACK / PT_EXTERNAL_SAFE_ACK / DIR_CHANGE_ACK | SUCCESS only |
| QUERY_OP | SUCCESS, BUFFER_TOO_SMALL(0xc0000023) |
| CANCEL | no CQE |
| ATTACH | control IOCTL only |
| FSCTL | no legal ABI 2.1 request or completion |

PREPARE_OPEN does not accept RETRY. STATUS_INTEGER_OVERFLOW from QueryDir
generation exhaustion is a local native completion and is deliberately
absent from the provider QUERY_DIR registry.

### 18.3 The out_len output matrix

Only `out_len` 0 or 24 is legal in a CQE:

| Case | `out_len` | `information` | Output |
|---|---:|---|---|
| PREPARE success | 24 | 136 | OControl echoing reply grant |
| COMMIT success | 24 | 112 | OControl echoing reply grant |
| MUTATE success | 24 | 112 | OControl echoing reply grant |
| REPLAY_OPEN success | 24 | 16 | OControl echoing reply grant |
| QUERY_OP success | 24 | 56 | OControl echoing reply grant |
| READ success | 24 | `1..=request length` | OControl echoing data grant, length = transferred bytes |
| WRITE success | 24 | `1..=request length` | OControl echoing the 56-byte `WriteResultV2` grant |
| QUERY_INFO / QUERY_VOLUME / QUERY_DIR success | 24 | exact valid canonical blob bytes | OControl echoing output grant |
| QUERY_SECURITY success | 24 | exact validated descriptor bytes, 20-65536 | OControl echoing descriptor grant shrunk to that length |
| BUFFER_TOO_SMALL for QUERY_OP | 0 | exact retained-op size in `{80,112,136,168,216,224}` and greater than current capacity | zero |
| RETRY, END_OF_FILE, NO_MORE_FILES, NO_SUCH_FILE | 0 | 0 | zero |
| registered ordinary failure | 0 | 0 | zero |
| ABORT/CLEANUP/CLOSE/FLUSH/ACK/PT/external-change ACK success | 0 | 0 | zero |
| CANCEL | no CQE | — | — |

When `out_len` is zero, all 24 output bytes are zero; OControl output uses
all 24 bytes. Output on a status that forbids it, a mismatched grant, an
invalid result size, nonzero reserved/unused bytes, impossible information,
or an illegal opcode/kind combination is a protocol fault. NOTIFY and
PROTOCOL CQE shapes are `03-messages.md` sections 5 and 9.

### 18.4 Pass-through prohibition and normalization

PENDING(0x00000103), BUFFER_OVERFLOW(0x80000005), REPARSE control statuses,
all other warning/informational values, and every unregistered error are
never passed through to a native IRP. Only a structurally empty unregistered
result for the observational READ, QUERY_INFO, QUERY_DIR, QUERY_VOLUME, or
QUERY_SECURITY opcodes is normalized to STATUS_IO_DEVICE_ERROR(0xc0000185),
recorded as a provider violation, and discarded. An unregistered result for
any state-changing, transactional, lifetime, acknowledgement, or protocol
opcode is a session protocol fault; the journaled-operation recovery rule of
section 17.2 takes precedence. Any nonempty or contradictory shape is also a
session protocol fault. For QUERY_SECURITY, a provider BUFFER_TOO_SMALL with
zero information and zero output is a structurally empty unregistered
observational result and therefore normalizes to IO_DEVICE_ERROR; any
nonzero information or output on that status is contradictory and faults the
session; neither form can supply a native required length. Adding a status
requires a registry change, exhaustive tests, and a compatible ABI-minor
rule.

### 18.5 The external-change DIR_CHANGE_ACK kernel path (summary)

At CQ consumption, ENTER copies and validates the complete external
DIR_CHANGE record into the one preallocated global external-lane work slot
and installs KERNEL_CAPTURED before CQ-head Release and credit refresh, then
becomes a detached handler. At PASSIVE_LEVEL it performs conservative cache
invalidation plus precise native reporting through the section 13 queue, or
for OVERFLOW cold-invalidates all provider-derived cache domains and
rescan-covers all registrations. Only then does it advance the external
high-watermark and install KERNEL_APPLIED_ACK_UNSENT before publishing
DIR_CHANGE_ACK with the complete `PDirChangeAckV1` and the distinct global
ReqId of section 3.1. The provider atomically deletes/advances only the
exact durable head and writes latest_processed before its SUCCESS CQ
Release; an exact ACK of latest_processed succeeds without repeating
deletion. No next external record may be CQ-published until that SUCCESS
Release: the ring-zero FIFO is the ordering barrier. A fence preserves the
external high-watermark/latest tuple and every CAPTURED or ACK-visible
state; captured work is delivered or covered by the fence's cold
cache/rescan result before GRACE. The ATTACH-time EXTERNAL_CHANGE_CUT/READY
reconciliation handshake is `03-messages.md` section 9 and
`04-object-model.md`; the cache-invalidation semantics behind the applied
floors are `07-cache-mm.md`.

DIR_CHANGE_ACK accepts SUCCESS only, with `out_len = 0` and zero
information.

## C4 role dispatch and mount publication

Each major-function thunk reads only the trusted leading `DeviceKind` and then
routes through a closed `match` — never a function-pointer table, because an
indirect edge the stack audit cannot resolve is exactly the shape that hides
one. The retained role roots are `fsring_dispatch_provider`,
`fsring_dispatch_fscontrol`, `fsring_dispatch_vdo`, `fsring_dispatch_volume`,
`fsring_dispatch_setup`, `fsring_dispatch_enter`, `fsring_dispatch_mount`,
`fsring_dispatch_verify`, and `fsring_dispatch_vdo_ioctl`.

Filesystem control accepts only root CREATE/CLEANUP/CLOSE bookkeeping and the
`IRP_MJ_FILE_SYSTEM_CONTROL` MOUNT/VERIFY minors. A VDO accepts root
bookkeeping and `IOCTL_STORAGE_CHECK_VERIFY{,2}` with a fixed unchanged-media
generation; it never sets `DO_VERIFY_VOLUME` and never returns
`STATUS_VERIFY_REQUIRED`, because a virtual volume has no removable media. A
mounted volume accepts only a root user CREATE and its CLEANUP/CLOSE.

MOUNT is thirteen effects. It acquires the VPB spin lock, validates the target
and VPB, takes the session reference, releases the lock for the fallible
mounted-device and VCB construction, then **reacquires** and revalidates target
identity, unchanged VPB binding, open mount admission, and an active session
immediately before binding and setting `VPB_MOUNTED`. All four revalidation
fields must be true; any false field enters the reverse unwind. VERIFY reads its
two facts under the same lock and returns `STATUS_VOLUME_DISMOUNTED` after
teardown.
