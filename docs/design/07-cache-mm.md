# 07 - Cache Manager and Memory Manager

Status: normative for FSRING ABI 2.1. This document defines the complete
Cache-Manager (Cc) and Memory-Manager (Mm) contract of the kernel driver:
when a stream owns a cache domain, the one-`SectionObjectPointers`-per-FCB
invariant, the size trio and `size_epoch` discipline, cached READ/WRITE and
cache-miss mechanics, the Cache-Manager/MM side of truncation, the
paging-write issue ledger, the `AdvanceOnly` trusted fast path, the
purge/coherency recipe for `INVALIDATE_FILE`, the optional lookup cache,
FastIO interaction with Cc, and Cc/Mm teardown. It supersedes the 2.0
cache/MM draft in full; no 2.0 STABLE label, doc-number cross-reference, or
Vietnamese cache narrative survives into 2.1.

The authoritative registries for this document are the unpacked crate
sources `fsring-abi/src/limits.rs`, `msgs/common.rs`, `msgs/mutation.rs`,
`msgs/notify.rs`, `layout.rs`, and `validate/messages.rs`, together with the
frozen generated header `fsring-abi/include/fsring_abi.h`. If prose,
generated archives, or an implementation disagree with those unpacked
sources, the unpacked sources win. Every wire value below is transcribed
from that registry: `MAX_FILE_SIZE = 0x7fff_ffff_ffff_ffff` (`limits.rs`,
the closed upper bound for every offset/length/size argument in this
document); the `SizeState` wire mirror `allocation_size`/`file_size`/
`valid_data_length`/`size_epoch` (32/8, `msgs/common.rs`); `SetSizeV1`
(24/8, `msgs/mutation.rs`); the closed notification codes
`INVALIDATE_FILE = 1` and `INVALIDATE_ENTRY = 2` with bodies
`InvalidateFileV1` (40/8) and `InvalidateEntryV1` (32/8) (`layout.rs`,
`msgs/notify.rs`); and the closed failure status
`USER_MAPPED_FILE = 0xc000_0243` in the `MUTATE_FAILURES` registry
(`validate/messages.rs`).

Kernel-behavior gate names, Cache-Manager/Memory-Manager entry points, and
bounded adapter constants that the crate does not carry as named constants
-- every `Cc*`/`Mm*` routine and FastIO callback named in this document
(`CcInitializeCacheMap`, `CcCopyRead`, `CcCopyWrite`, `CcSetFileSizes`,
`CcPurgeCacheSection`, `CcFlushCache`, `CcUninitializeCacheMap`,
`MmCanFileBeTruncated`, `MmFlushImageSection`, `MmForceSectionClosed`,
`AcquireFileForNtCreateSection`), the paging-write issue ledger's
`WriteIrpContext`/`last_issued`/`target_vdl` machinery, the `AdvanceOnly`
trusted fast path, and their bounded adapter constants
(`MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_FCB` and its `_PER_MOUNT`/`_GLOBAL`
siblings, `MAX_PENDING_ADVANCE_ONLY_IRPS_PER_FCB` and its siblings, and the
paging-write failure-interval bounds) -- are WDK Cache Manager/Memory
Manager APIs and corrective-design driver behavior that the `fsring-abi`
crate does not and will never carry, because the crate is the `no_std`
wire-format and validation library, not the driver itself. They are
transcribed from the corrective design
(`docs/superpowers/specs/2026-07-15-fsring-abi-v2.1-corrective-design.md`
sections 4.4, 8, and 10) and the original design
(`docs/superpowers/specs/2026-07-15-fsring-abi-v2-design.md` section 8).
`TRUNCATING` is `06-locking.md`'s binding name for the size-gate reduction
substate (`06-locking.md` section 3.3); this document does not redefine it,
only states the Cache-Manager/MM work that executes inside it.

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY are normative.

Wire message payloads and legality maps are defined in `03-messages.md`;
per-IRP-major dispatch, the direct-I/O admission machine, and the
mapping-flag table are defined in `05-irp-dispatch.md`; the universal lock
order, the per-FCB size gate, the `TRUNCATING` substate, the paging-write
sequencer's lock-nesting protocol, and the `AdvanceOnly` CSQ owner-state
machine belong to `06-locking.md`. This document states the Cache-Manager
and Memory-Manager operations that run inside those gates, not the gates
themselves: where a step requires a lock already defined elsewhere, this
document names the lock and cites the owning section instead of restating
its acquisition order. The full passthrough donation, routing, and
coherency-lease contract -- including the mmap-coherency variant of the
purge recipe in section 8 below -- belongs to `08-passthrough.md`.

## 1. Cache domain boundary

A ring-path FCB for a regular (non-directory) stream builds its cache map
lazily, on the first cached READ or WRITE, never at CREATE. Directory and
volume streams never build a cache map; directory enumeration is served
entirely through the `QUERY_DIR` operation family (`05-irp-dispatch.md`),
not through Cc.

A PT FCB never builds a ring-path cache domain of its own. The backing
filesystem's own cache (NTFS's Cc state for the donated backing stream)
serves cached I/O instead. This is the structural fact that makes
passthrough coherent by construction rather than by explicit
synchronization; the full forwarding mechanism, the coherency-lease
principle, and the mmap-specific incoherency window are `08-passthrough.md`'s
territory and are cross-referenced, not restated, in section 8 below.

An open with `FILE_NO_INTERMEDIATE_BUFFERING` is always noncached for the
life of that handle: no cache map is built for it, and every READ/WRITE on
it is dispatched through the noncached path subject to
`05-irp-dispatch.md`'s MDL validation, mapping-flag, and
`MAX_PENDING_ASYNC_*` admission rules. Noncached and cached opens of the
same stream still share the one cache/section domain defined in section 2:
a noncached writer's bytes are visible to a concurrent cached reader
through the shared `SectionObjectPointers`, subject to the ordinary
Windows noncached/cached coherency rules for a single volume.

## 2. One `SectionObjectPointers` per FCB

Each ring-path FCB owns exactly one `SectionObjectPointers` structure,
embedded in or adjacent to the FSRTL common header, and exactly one
internal stream `FILE_OBJECT` used to back it. This is the FCB's field
holding the same WDK `SECTION_OBJECT_POINTERS` structure that
`04-object-model.md` and `08-passthrough.md` reference by that bare type
name; the two spellings name the same structure. `FileObject->SectionObjectPointer`
is set to `&Fcb->SectionObjectPointers` at CREATE, before the object is
made visible to any other subsystem. Every `FILE_OBJECT` opened against the
same stream -- across every handle, every process -- points at that same
structure. This is what gives the stream one coherent cache domain and one
coherent set of data/image sections: Cc's cache map, Mm's data section, and
Mm's image section are all reached through that single pointer, so a write
through one handle is visible to a cached read through another handle
without an explicit cross-handle synchronization step.

The FCB, its `SectionObjectPointers`, and the internal stream `FILE_OBJECT`
survive until every cache map, data/image section, mapped view, and
dependent request against them has drained (section 11).

## 3. Size trio and `size_epoch`

The FSRTL common header carries the three ordered sizes that Cc and Mm
consult on every cached operation:

```text
AllocationSize >= FileSize (EOF) >= ValidDataLength (VDL)
```

The wire mirror of that trio is the crate's `SizeState` (32/8,
`msgs/common.rs`): `allocation_size`, `file_size`, `valid_data_length`, and
`size_epoch`. The daemon is the durable authority for these four values;
the kernel holds a serialized mirror in the FCB header that Cc and Mm read
directly, refreshed only through a successful size-changing response or a
resync. A successful size-changing response MUST return a `size_epoch`
strictly greater than the expected input epoch -- gaps are legal, so an
epoch that advances by more than one is not itself an error. A stale
(equal or lower) epoch is a protocol/state error and triggers
reconciliation, never silent acceptance -- the same `size_epoch` identity
that `04-object-model.md` and `05-irp-dispatch.md` already treat as closed
CQE-validation vocabulary.

`CcSetFileSizes(FileObject, &SizeState)` publishes the kernel's serialized
mirror to Cc. It MUST be called:

- when EOF increases (extend) -- **before** the corresponding
  `CcCopyWrite` runs, so Cc does not reject a write past the old EOF;
- when EOF decreases (truncate) -- as part of the Cache-Manager/MM
  truncate sequence in section 5, before the truncated tail is purged;
- when AllocationSize increases without an EOF change.

`CcSetFileSizes` MUST be called at PASSIVE_LEVEL. The paging-I/O path MUST
NOT call it: paging dispatch updates the FCB header fields directly under
the size gate (`06-locking.md` section 3.3) and lets Cc observe the new
values through the header it already holds a pointer to, rather than
re-entering Cc from a context where PASSIVE_LEVEL is not guaranteed.

Write-size ordering has three cases:

- **Extending write.** Reserve/commit the new EOF with the daemon first,
  update the FCB header and call `CcSetFileSizes`, then run `CcCopyWrite`
  into the newly visible range.
- **Write filled entirely within the retained VDL.** No size change; go
  straight to `CcCopyWrite`.
- **Write that creates or extends a range in `[VDL, offset)`.** Cc does not
  zero-fill that gap on its own behalf: `CcCopyRead` service of a read that
  lands in `[VDL, EOF)` misses in the cache map and Cc issues a paging READ
  to the FSD for that range (section 4). It is the paging-READ handler --
  the `05-irp-dispatch.md` op-READ dispatch reached through that miss --
  that MUST return zeros for any byte at or above VDL, never Cc directly.
  After a cached write that extends the written region past the retained
  VDL, the kernel advances `valid_data_length = max(VDL, offset + length)`
  once the written bytes are durable (or lets the paging-write ledger of
  section 6 / the lazy writer advance it), so that zero-fill is never
  required for bytes this write itself produced.

Uninitialized backing bytes are never exposed to a reader: every byte at or
above VDL that a reader observes is either data this driver wrote or an
explicit zero, never provider storage the daemon has not accounted for.

## 4. Cached READ/WRITE mechanics

On the first cached I/O against a stream that has no cache map yet,
dispatch calls:

```text
CcInitializeCacheMap(
    FileObject,
    (PCC_FILE_SIZES)&Fcb->Header.AllocationSize,
    FALSE,
    &FsringCacheCallbacks,
    Fcb);
```

`FsringCacheCallbacks` implements the four Cache-Manager callbacks with one
governing rule: **never acquire the FCB main resource from a lazy-write or
read-ahead callback**, only the paging resource, shared, and only for the
duration of the callback:

- `AcquireForLazyWrite(Context, Wait)`: acquire the FCB paging resource
  shared (sufficient, because a lazy-write of dirty pages never changes
  EOF), set the thread's top-level IRP context to the FSRTL cache
  sentinel, and return `TRUE`. Acquiring the main resource here would risk
  a deadlock against a foreground thread that already holds the main
  resource and is waiting on Cc.
- `ReleaseFromLazyWrite`: release the paging resource and restore the
  prior top-level context.
- `AcquireForReadAhead(Context, Wait)`: acquire the FCB paging resource
  shared, return `TRUE`.
- `ReleaseFromReadAhead`: release the paging resource.

Cached READ calls `CcCopyRead(FileObject, &FileOffset, Length, Wait, Buffer,
&IoStatus)` with `Wait = TRUE` when running at PASSIVE_LEVEL on the
originating thread. It returns the correct short read at EOF. As stated in
section 3, `CcCopyRead` does not itself zero-fill `[VDL, EOF)`; a read that
lands there is serviced as a cache miss.

Cached WRITE extends first when required (section 3), then calls
`CcCopyWrite(FileObject, &FileOffset, Length, Wait, Buffer)`. The resulting
dirty pages are flushed later by the lazy writer, which issues a paging
WRITE (section 6). For `FILE_WRITE_THROUGH` handles, dispatch calls
`CcFlushCache(SectionObjectPointer, &FileOffset, Length, &IoStatus)`
immediately after `CcCopyWrite` returns, waits for it, and checks
`IoStatus` before completing the write.

A cache miss inside `CcCopyRead` or `CcCopyWrite` makes Cc issue a paging
READ to this FSD **on the same thread**, with the top-level context already
set to the cache sentinel from the callback that is running. That paging
READ dispatches through the paging branch of `05-irp-dispatch.md`'s op-READ
path down to an actual op round trip with the daemon. Because the calling
thread is synchronously blocked inside `CcCopyRead`/`CcCopyWrite` waiting
for that paging READ to complete, the paging path MUST be asynchronous
end-to-end and MUST NOT synchronously wait on anything else while the
top-level context is the cache sentinel: a second synchronous wait on that
same thread, stacked under the first, is a self-deadlock, not merely slow.

## 5. Truncation -- the Cache-Manager/MM side

Shrinking `FileSize` or `AllocationSize` enters `06-locking.md`'s
`TRUNCATING` substate of the per-FCB size gate (`06-locking.md` section
3.3). That document owns the gate itself, the lock order, and the
oplock-arbitration precondition; this section states only the
Cache-Manager and Memory-Manager work that runs while `TRUNCATING` is
held:

1. **MM veto.** `MmCanFileBeTruncated(SectionObjectPointer, &NewFileSize)`
   is the truncation veto. If it returns `FALSE` -- an incompatible active
   mapping exists over the region being cut away -- the request completes
   **locally**, immediately, with `STATUS_USER_MAPPED_FILE`
   (`USER_MAPPED_FILE = 0xc000_0243`, `validate/messages.rs`), with no
   ReqId, grant, digest, or SQE ever allocated. This is the only outcome
   this document states for that veto: an application mapped the file and
   is trying to truncate below its mapped view. `CcPurgeCacheSection` does
   **not** itself invalidate active mappings and MUST NOT be treated as
   proof that mapped views have gone away -- `MmCanFileBeTruncated` is the
   actual veto, and it MUST run before any other reduction-only step.
2. **Publish the smaller size to Cc.** `CcSetFileSizes` is called with the
   new (smaller) `FileSize` **before** the purge below, so Cc already knows
   the new EOF when it discards pages.
3. **Purge the truncated tail.** `CcPurgeCacheSection(SectionObjectPointer,
   &NewFileSize, 0, FALSE)` discards cached pages beyond the new EOF so a
   later read cannot observe stale post-truncate bytes through the cache.
4. **Commit.** The `SET_END_OF_FILE`-class daemon transaction (the size
   body semantics of `03-messages.md`'s `SetSizeV1`) commits the new length
   as the durable value.
5. **Post-commit VDL clamp.** After the completion queue entry confirms the
   commit, the kernel sets `valid_data_length = min(VDL, EOF)`.

Extending `FileSize`/`AllocationSize` publishes the larger sizes to Cc
first and does **not** purge; no MM veto applies to an extension because no
existing mapped range is being cut away.

## 6. The paging-write issue ledger

The paging-write issue ledger is the mechanism that lets an FCB accept many
concurrent, possibly out-of-order paging WRITEs -- from the lazy writer
flushing dirty cached pages, from a mapped-page writer, and from ordinary
noncached WRITE -- while still being able to answer, at any instant, "which
byte ranges are provably committed, and which are not." It is this
document's centerpiece because it is what makes sections 3 and 7's
zero-fill and VDL-advance guarantees actually hold under concurrency rather
than only in the single-writer case.

Each FCB embeds a small volatile paging-WRITE sequencer header, protected
by the per-FCB sequencer spin lock. `06-locking.md` owns that spin lock's
position in the universal lock order
(`lifecycle-admission -> per-open lifecycle -> size gate -> sequencer ->
AdvanceOnly CSQ`, `06-locking.md` section 1) and the full lock-nesting
protocol around it; this section states what the sequencer tracks and why,
not how its lock is acquired relative to the others.

The sequencer retains `last_issued`, a checked monotonically increasing
nonzero counter, and an ordered set containing exactly the nonterminal
(still in-flight) issues. For each nonzero paging WRITE, dispatch first
performs checked extraction of the immutable native `[offset, end)` range,
then attempts to claim one bounded `WriteIrpContext` node from the
nonpaged mount/global pools, charged against the active-context limits
below in fixed global-then-mount-then-FCB order. If that claim fails, the
sequencer lock is taken once to allocate a checked issue, record the
**complete requested range** as an immediately terminal
`INSUFFICIENT_RESOURCES` failure through the allocation-free ledger
fallback described below, advance the terminal prefix if possible, and
complete the IRP -- no paging WRITE with a valid extracted range ever
returns an unnumbered failure. If the claim succeeds, the same critical
section allocates the issue and links the context into the intrusive
ordered active set; only after that linearization may dispatch validate
the MDL, reserve the common admission quota ticket, map pages, or take any
further fallible step.

The contiguous terminal prefix is computable in O(1) under the lock: it is
`last_issued` when the active set is empty, or `minimum_active_issue - 1`
otherwise, recomputed on every terminal removal. Out-of-order completion
therefore needs no retained terminal-issue table: a paging WRITE with issue
7 can complete after issue 9 without the ledger ever materializing a
sparse history of completed issues, because only the *lowest* still-open
issue determines how far the prefix has actually advanced.

Before advancing the prefix, each completed child paging WRITE records its
exact provider-committed byte coverage, and each terminal (failed) path
records every requested byte range it cannot prove committed -- a
synchronous early failure MAY conservatively record its full requested
range. Coverage intersection starts at the current VDL, so bytes already
below VDL never block a future prefix advance. Each unresolved interval
carries the lowest issue that touched it and that issue's registered
failure status; an unproven suffix following a short `SUCCESS` carries the
fail-closed `IO_DEVICE_ERROR` status rather than being assumed committed. A
later verified WRITE commit subtracts exactly its proven coverage from the
outstanding intervals; a verified, monotonically increasing returned VDL
trims each interval to the portion above that VDL and deletes any interval
that falls entirely below it.

Each FCB embeds exactly two ordinary interval slots inline plus one
allocation-free inline UNKNOWN accumulator; additional ordinary intervals
use bounded nonpaged overflow nodes reserved in fixed global-then-mount
order. If a split would exceed the per-FCB interval bound, an overflow-node
reservation fails, or exact checked representation cannot be maintained,
the ledger merges all affected evidence into the inline UNKNOWN span
covering the minimum unresolved start through the maximum unresolved end,
preserving the lowest issue and its status. Memory pressure therefore makes
the correctness proof strictly more conservative -- it never silently
drops evidence and never allocates while the sequencer lock is held. A
terminal update may preclaim at most `PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES`
nodes before entering the size gate/sequencer pair; any update that needs
more takes the inline UNKNOWN fallback instead of allocating under the
lock. UNKNOWN clears only when exact verified commits cover its remaining
span, a verified returned VDL reaches its end, or the FCB is finally torn
down; ordinary intervals clear only by that same range/VDL proof. Waiter
absence, timeout, CLEANUP, a session fence, or ATTACH never discards or
normalizes a recorded failure.

The bounded adapter state (corrective design section 10) is:

```text
MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_FCB           = 1024
MAX_ACTIVE_PAGING_WRITE_CONTEXTS_PER_MOUNT         = 16384
MAX_ACTIVE_PAGING_WRITE_CONTEXTS_GLOBAL            = 65536
INLINE_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB      = 2
MAX_PAGING_WRITE_FAILURE_INTERVALS_PER_FCB         = 64
PAGING_WRITE_FAILURE_UPDATE_RESERVE_NODES          = 2
MAX_PAGING_WRITE_FAILURE_OVERFLOW_NODES_PER_MOUNT  = 16384
MAX_PAGING_WRITE_FAILURE_OVERFLOW_NODES_GLOBAL     = 65536
```

There is no 1024-entry table embedded in every FCB: the per-FCB limit
bounds how many `WriteIrpContext` nodes an individual stream may hold
charged against the shared mount/global pools at once, not a fixed
per-FCB allocation. A terminal path returns its active-context charge to
those pools after it is removed from the sequencer and has made its last
IRP/MDL access. Mount or FCB teardown drains every active node before the
embedded sequencer header itself is released, so no paging WRITE issue can
outlive the FCB it was issued against.

## 7. `AdvanceOnly` -- the trusted fast path

`AdvanceOnly` is the Cache-Manager-triggered fast path Cc itself uses to
advance VDL after a lazy write commits data that was previously beyond it,
without going through the ordinary size-change oplock/gate arbitration a
user-mode `FileValidDataLengthInformation` request requires. It is legal
only for native `FileEndOfFileInformation` with kernel requestor mode, a
regular non-directory file, and the actual SetFile parameter block carrying
`AdvanceOnly = TRUE` -- never inferred from thread or process identity. It
is the sole path in this document's scope that bypasses ordinary oplock
arbitration, because the cached WRITE that produced the bytes being
advanced past already underwent that arbitration when it was issued.

The Cache-Manager precondition this document states is: the ordered write
barrier from section 6 -- the paging-write issue ledger's terminal-prefix
proof -- MUST precede the VDL advance. Concretely, the worker computes

```text
target_vdl = min(EndOfFile, current file_size)
```

and only advances VDL to `target_vdl` once the ledger shows no unresolved
or `UNKNOWN` evidence intersecting `[current VDL, target_vdl)`; if such
evidence exists, the lowest-issue unresolved interval becomes the local
failure candidate instead. This is what keeps `AdvanceOnly` from ever
exposing unwritten bytes despite skipping the ordinary strict-increase,
privilege, and oplock-adapter rules: it never advances VDL over a range
this document cannot already prove is written data or zero.

The queueing, cancellation, and completion protocol around `AdvanceOnly`
IRPs is owned by `06-locking.md`, not restated here: its closed owner
states are `INSERTING`, `BARRIER_WAIT`, `RESOURCE_READY`,
`POST_CLEANUP_HELD`, `ADMITTING`, and `TERMINAL` (`06-locking.md` sections
3.4-3.5), reached through the `sequencer -> AdvanceOnly CSQ` nesting that
document defines. This document's only interest in that machine is the
Cache-Manager precondition above and its bounded admission state:

```text
MAX_PENDING_ADVANCE_ONLY_IRPS_PER_FCB   = 64
MAX_PENDING_ADVANCE_ONLY_IRPS_PER_MOUNT = 4096
MAX_PENDING_ADVANCE_ONLY_IRPS_GLOBAL    = 16384
```

`AdvanceOnly` never reduces VDL, never changes AllocationSize/EOF, and
never carries a nonzero `SetSizeV1` or outer mutation flag: on the wire it
canonicalizes to an ordinary `SET_VALID_DATA_LENGTH`-class mutation with
`new_vdl = target_vdl` and the revalidated `size_epoch`, so daemon-side
crash recovery replays it like any other mutation with no special
persisted provenance bit.

## 8. Purge and coherency recipe

When the daemon reports that backing data changed outside this driver's
own I/O (the 2.1 `INVALIDATE_FILE` notification, code `INVALIDATE_FILE = 1`,
body `InvalidateFileV1` 40/8: `offset`, `length` -- zero meaning the whole
stream -- `content_epoch`, `flags`, `reserved`), or whenever a path needs
to force the next reader to reload from the daemon, the recipe is:

```text
// at a work item (never inline inside ring ENTER), PASSIVE_LEVEL:
acquire the size gate exclusive (06-locking.md section 1, position 3);
CcFlushCache(sop, range_or_null, &iosb);          // push dirty pages down first,
                                                   // when this side is the write source;
                                                   // a read-only invalidate MAY skip the flush
MmFlushImageSection(sop, MmFlushForWrite);        // only if an image section exists
CcPurgeCacheSection(sop, range_or_null, len, FALSE); // discard clean pages so the
                                                      // next read reloads them
invalidate any lookup-cache entry TTL for this file (section 9);
release the size gate;
```

`range_or_null`: `NULL` (or `offset = 0, length = 0`) means the whole
stream. When the daemon supplies an explicit `offset`/`length`, the kernel
purges only that range after rounding it out to page boundaries; it MUST
NOT purge a narrower range than requested.

This recipe is stated for the ring-path FCB, which owns a cache map of its
own (sections 1-2). A PT FCB has no ring-path cache map, so its mmap
coherency variant of this recipe applies only `MmFlushImageSection` and
`CcPurgeCacheSection` to the *virtual* section the application created over
the PT stream, forcing the next fault to forward through the passthrough
route again rather than reuse a stale mapped page. That variant, the
routing-revoked-versus-external-mutation-safe distinction, and the full
coherency-lease principle are `08-passthrough.md`'s rewrite and are
cross-referenced here, not restated.

## 9. Optional lookup cache

The kernel MAY hold a small, per-VCB, LRU-bounded name-to-`FileId` lookup
cache to let a fast repeated open of the same path skip the `PREPARE_OPEN`
round trip. It MUST respect the case-sensitivity flag from
`04-object-model.md` section 6's namespace identity. It is invalidated by
the `INVALIDATE_ENTRY` notification (code `INVALIDATE_ENTRY = 2`, body
`InvalidateEntryV1` 32/8: `namespace_generation`, an inline UTF-16 name
slice, `flags`, `reserved`; the envelope `FileId` is the parent directory)
and by any local rename or delete of the entry.

For v1.0 this lookup cache is **off by default**: correctness before
optimization, matching the same discipline `06-locking.md` and
`04-object-model.md` apply elsewhere. It MAY be enabled after coherency
testing (section 12) demonstrates it does not regress. The kernel MUST NOT
let a stale lookup-cache entry return a `FileId` that no longer names the
requested path; whenever staleness is possible, it MUST invalidate broadly
rather than risk returning a wrong `FileId`.

## 10. FastIO and Cc

`FsRtlCopyRead`/`FsRtlCopyWrite` are legal only when the stream already has
a cache map and the open is not oplock-questionable; when legal, they call
directly into Cc without a full IRP round trip.

`AcquireFileForNtCreateSection` is the FastIoDispatch callback Mm invokes
when it is about to create a section (a data or image section for mmap)
over this stream's `FILE_OBJECT`. It acquires the size gate exclusive
(`06-locking.md` section 1, position 3) before allowing the section to be
created, so section creation is serialized against a concurrent
truncation.

`AcquireForCcFlush`/`ReleaseForCcFlush` guard against double-acquisition
when Cc itself calls back into the FSD around a flush it initiates: they
acquire the FCB paging resource only if the calling thread does not
already own it, and release only what they acquired, so a flush issued
from a context that already holds the paging resource does not deadlock
against itself.

## 11. Cc/Mm teardown

When an FCB is dying, or at volume teardown, Cc/Mm state is unwound in this
order:

1. `CcFlushCache(sop, NULL, &iosb)` -- if the stream still has dirty pages
   and the daemon is still reachable.
2. `CcPurgeCacheSection(sop, NULL, 0, FALSE)`.
3. `CcUninitializeCacheMap(FileObject, NULL, NULL)` at the final CLOSE of
   the internal stream `FILE_OBJECT` -- truncate size `NULL` means no
   truncate-on-uninitialize -- and the kernel waits for Cc's release before
   proceeding.
4. Wait for `SectionObjectPointers` to drain every remaining Mm reference.
   An application that still holds a mapped view (data or image section)
   keeps the FCB alive under the ordinary NT model: real teardown happens
   only once every map has unmapped. Volume dismount MAY force this with
   `MmForceSectionClosed(sop, TRUE)`; that call MUST be used only for an
   actual dismount, and it can fail if an application still holds a
   mapping -- in that case dismount returns `CANT_DISMOUNT` and the VCB
   stays mounted rather than tearing down a section a client still has
   mapped.

## 12. DoD (stated, not executed)

The following are the release-gate criteria this document states as
requirements. They are not run as part of this rewrite; the executable
gates live in `12-test-plan.md`.

- winfsp-tests memmap and cached-I/O suites pass.
- IFS Test: cached I/O, truncation, and sharing-with-mapping suites pass.
- Truncate-under-mmap returns `STATUS_USER_MAPPED_FILE` exactly as section
  5 states.
- Coherency test: the daemon changes backing data and sends
  `INVALIDATE_FILE`; an application read after the purge recipe of section
  8 observes the new data.
- Stress test: the lazy writer and concurrent reads run together under
  Driver Verifier with data-hash corruption detection and show no
  corruption.
