# 02 - ABI 2.1 transport and shared-memory layout

Status: normative for FSRING ABI 2.1. ABI major 2 is intentionally
incompatible with the earlier wire format, and minor 1 is the first
interoperable minor of that major: minor 0 is a superseded pre-release draft
and is never selected by SETUP.

The authoritative registries for this document are the unpacked crate sources
`fsring-abi/src/layout.rs`, `ids.rs`, `slots.rs`, `limits.rs`, `features.rs`,
`ring.rs`, `msgs/*`, `control/*`, and `durable/*`, together with the frozen
generated header `fsring-abi/include/fsring_abi.h`. If prose, generated
archives, or an implementation disagree with those unpacked sources, the
unpacked sources win. Every size, alignment, offset, and constant below is
transcribed from that registry, except a small set of named driver-behavior
bounds that the crate does not carry as named constants and that are
transcribed from the corrective design instead: the `ReplayOpenV2`
state-flag value `REPLAY_STATE_PAGING_ONLY` (the crate carries `state_flags`
as a plain `u64`), `MAX_OPENING_BACKING_ATTEMPTS_PER_MOUNT`/`_GLOBAL`, and
`MAX_DURABLE_PT_LANE_RECORDS_PER_MOUNT`.

The terms MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY are normative. Correctness, memory safety, isolation, and bounded execution
are absolute requirements. A performance optimization is valid only when it
preserves every validation and lifetime rule below.

## 1. Wire conventions and fixed registries

All wire integers are little-endian fixed-width integers. All offsets in the
tables are byte offsets from the start of the containing structure. A receiver
MUST decode from a bounded local copy or through the atomic access rules in
Section 6; it MUST NOT cast untrusted bytes to a reference and then inspect
fields speculatively.

There is no implicit wire padding. Every byte is part of a named field or a
named reserved array. Senders MUST zero every reserved field, every named
alignment byte, and every unused byte in a fixed payload or output array.
Receivers MUST validate required-zero fields before using the containing
message. A future meaning for a required-zero bit or byte requires an ABI-minor
extension or a new ABI major as appropriate.

### 1.1 ABI constants

| Rust constant | C constant | Exact value | Meaning |
|---|---|---:|---|
| `FSRING_MAGIC` | `FSRING_MAGIC` | `0x47525346` (`1196577606`) | little-endian integer for ASCII bytes `FSRG` |
| `FSRING_ABI_MAJOR` | `FSRING_ABI_MAJOR` | `2` | incompatible wire generation |
| `FSRING_ABI_MINOR` | `FSRING_ABI_MINOR` | `1` | current compatible extension level |
| `FSRING_ABI_MIN_COMPAT_MINOR` | `FSRING_ABI_MIN_COMPAT_MINOR` | `1` | oldest minor this build interoperates with |
| `FSRING_ENDIAN_LITTLE` | `FSRING_ENDIAN_LITTLE` | `1` | only accepted byte order |
| `SLOT_CLASS_COUNT` | `FSRING_SLOT_CLASS_COUNT` | `4` | class descriptors in each directional arena |
| `SQE_PAYLOAD_LEN` | `FSRING_SQE_PAYLOAD_LEN` | `88` | bytes in `SqeBody.payload` |
| `CQE_OUT_LEN` | `FSRING_CQE_OUT_LEN` | `24` | bytes in `CqeBody.out` |
| `REQ_INDEX_BITS` | `FSRING_REQ_INDEX_BITS` | `24` | request-table slot bits |
| `REQ_GENERATION_BITS` | `FSRING_REQ_GENERATION_BITS` | `40` | request generation bits |
| `REQ_INDEX_MAX` | `FSRING_REQ_INDEX_MAX` | `0x00ff_ffff` (`16777215`) | maximum request slot index |
| `REQ_GENERATION_MAX` | `FSRING_REQ_GENERATION_MAX` | `0x00ff_ffff_ffff` (`1099511627775`) | maximum request generation |
| `SLOT_INDEX_MAX` | `FSRING_SLOT_INDEX_MAX` | `0x000f_ffff` (`1048575`) | maximum slot index |
| `SLOT_OFFSET_MAX` | `FSRING_SLOT_OFFSET_MAX` | `0x001f_ffff` (`2097151`) | maximum in-slot offset |
| `SLOT_LENGTH_MAX` | `FSRING_SLOT_LENGTH_MAX` | `0x001f_ffff` (`2097151`) | maximum encoded slot length |

The identity row values are exact: both the current minor and the minimum
compatible minor are 1. SETUP negotiates the minor from the caller's
`[min_abi_minor, max_abi_minor]` range: a range containing 0 and 1 selects 1;
minor 0 is never selected; and a range containing only minor 0 fails with
REVISION_MISMATCH, because that draft is not interoperable.

The Rust transport additionally fixes `MAX_RESERVE_RETRIES = 64` (`ring.rs`).
This is a bounded-algorithm constant, deliberately not a C wire constant; it
bounds every MPSC reservation loop in Section 6.

### 1.2 Feature and OS-capability sets

`FeatureSet` is two little-endian `u64` words. Bit `n` is
`words[n / 64] & (1 << (n % 64))`; valid indices are 0 through 127. Protocol
features and operating-system capabilities are independent sets.

| Protocol feature | Bit | ABI 2.1 selectability |
|---|---:|---|
| `PT` | 0 | selectable where the profile mask permits |
| `MMAP` | 1 | selectable where the profile mask permits |
| `HOT_RESTART` | 2 | selectable only as a pair with bit 3 |
| `EXACTLY_ONCE` | 3 | selectable only as a pair with bit 2 |
| `SECURITY` | 4 | REQUIRED for every successful session |
| `REPARSE` | 5 | assigned, unselectable in base 2.1 |
| `TOKEN_DONATION` | 6 | assigned, unselectable in base 2.1 |
| `MAPPED_IO` | 7 | selectable only with OS bits 0 and 1 |
| `NOTIFY_NAMES` | 8 | assigned, unselectable in base 2.1 |
| `CASE_SENSITIVE_NAMES` | 9 | assigned, unselectable in base 2.1 |

| OS capability | Bit |
|---|---:|
| `MDL_NO_WRITE` | 0 |
| `MDL_NO_EXECUTE` | 1 |
| `MODERN_COHERENCY` | 2 |
| `ARM64` | 3 |

The kernel alone publishes `os_capabilities`. The daemon MUST NOT manufacture
an OS bit. Selection is deterministic:
`selected = offered & runtime_protocol_mask`, where the runtime mask starts
from the platform profile mask and clears `MAPPED_IO` unless both
`MDL_NO_WRITE` and `MDL_NO_EXECUTE` were detected, and clears the
`HOT_RESTART`/`EXACTLY_ONCE` pair unless the dedicated service-SID predicate in
Section 10.8 holds. `SECURITY` (mask `0x10`) is the kernel-required base
feature of every session. Bits 5, 6, 8, and 9 (mask `0x360`) are
registry-stable but unselectable in base 2.1; requiring any of them fails
NOT_SUPPORTED. `HOT_RESTART` and `EXACTLY_ONCE` are an inseparable pair: within
each of the offered, required, and selected sets independently the two bits are
either both present or both absent, and unequal bits fail INVALID_PARAMETER.
Required protocol features and OS capabilities MUST be subsets of the selected
and detected sets or setup/attach fails deterministically. An offered bit
unknown to the peer remains unselected; an unknown required bit fails
negotiation. Absence from the current named registry does not by itself make a
bit required-zero.

The notification-name region behind bit 8 is disabled in ABI 2.1:
`GlobalHeader.notify_names` is exactly `{ offset: 0, length: 0 }`, no writable
name mapping is created, and notification names travel only in the
generation-stamped notification credits of Section 9.7. The registered
DONATE_SECURITY_CONTEXT control operation behind bit 6 remains in the registry,
but a well-formed authorized call returns NOT_SUPPORTED and never references
the supplied handle. A future minor may activate bits 5, 6, 8, or 9 only with
a complete encoding, ownership, protection, and lifetime contract.

### 1.3 Transport registry values

| Registry | Name | Value |
|---|---|---:|
| park state | `ACTIVE` | 0 |
| park state | `POLLING` | 1 |
| park state | `PARKED` | 2 |
| CQ kind | `COMPLETION` | 0 |
| CQ kind | `NOTIFY` | 1 |
| CQ kind | `PROTOCOL` | 2 |
| SQE flag | `NO_COMPLETION` | `1 << 0` |
| buffer kind | `NONE` | 0 |
| buffer kind | `SLOT` | 1 |
| buffer kind | `MAPPING` | 2 |
| buffer access | `K2U_READ_ONLY` | 1 |
| buffer access | `U2K_WRITE` | 2 |
| control version | `CONTROL_VERSION_V1` | 1 |
| control version | `CONTROL_VERSION_V2` | 2 |

The checked-in source and header publish no numeric constants or semantics for
`GlobalHeader.header_flags`, `GlobalHeader.flags`, `RingDesc.flags`,
`ProducerPage.flags`, `ConsumerPage.flags`, or `RingDesc.desc_version`. They
are layout fields only in this document: implementations MUST NOT infer a
required-zero rule or assign private cross-implementation meaning merely from
the absence of registered values. Any interoperable meaning requires an
authoritative source/header/test update and the appropriate ABI version rule.

### 1.4 ControlHeader and versioned-blob parsing

Every versioned control blob begins with `ControlHeader`, exactly size 8 and
alignment 4:

| Field | Offset | Type | Meaning |
|---|---:|---|---|
| `struct_size` | 0 | `u32` | complete structure size including tails |
| `struct_version` | 4 | `u16` | schema version for this opcode |
| `required_flags` | 6 | `u16` | bits the receiver must understand |

`CONTROL_VERSION_V1` is 1 and `CONTROL_VERSION_V2` is 2. Unless a schema
explicitly assigns a required flag, its accepted mask is zero.

Every versioned blob is bounded by an enclosing length: `BufferRef.length` for
a ring control blob and the IOCTL input/output length for a control request.
The parser performs these eight checks in order:

1. the enclosing length is at least `size_of::<ControlHeader>()` (8 bytes);
2. the eight header bytes are copied once into private storage;
3. `struct_version` is one of the versions legal for that opcode and ABI
   minor;
4. every unknown bit in `required_flags` is rejected deterministically;
5. `struct_size` is at least the registered minimum size of that known
   version;
6. `struct_size <= enclosing_length` using checked arithmetic;
7. every fixed-length/exact-size rule, reserved field, and alignment byte in
   the known prefix is validated;
8. every nested offset/range is checked against `[0, struct_size)` before
   use.

Once eight bytes are safely available, an unknown version has precedence and
maps to REVISION_MISMATCH, then unsupported required flags map to
NOT_SUPPORTED, then malformed size/range/reserved bytes map to
INVALID_PARAMETER. A length below eight cannot expose a version and is
INVALID_PARAMETER. The same ordering is used by every fixed control IOCTL and
nested ring body; ring faults use the Section 8.3 disposition rather than
returning these IOCTL statuses.

For a receiver whose known fixed size is `known_size`, bytes after the fixed
prefix are classified by the selected schema, not assumed optional. A schema
may define required variable payload ranges inside `[known_size, struct_size)`;
after those ranges it may explicitly permit an ignorable optional extension.
Any byte not covered by one of those two rules is rejected. Bytes at or after
`struct_size` are outside the structure. An unknown `struct_version` is
rejected with a revision mismatch; it is never accepted merely because the
prefix fits. Backward-compatible optional extensions keep the same version and
use `required_flags` for semantics that an older receiver must understand.

## 2. Exact foundational and physical layouts

The following layouts are C-compatible and are mechanically asserted in Rust
and C. Size and alignment are part of the ABI on both x64 and ARM64.

### 2.1 Layout summary

| Type | Size | Alignment |
|---|---:|---:|
| `FeatureSet` | 16 | 8 |
| `ReqId` | 8 | 8 |
| `OpId` | 16 | 8 |
| `FileId` | 16 | 8 |
| `LinkId` | 16 | 8 |
| `MountId` | 16 | 8 |
| `BootInstanceId` | 16 | 8 |
| `TransactionId` | 16 | 8 |
| `AckToken` | 16 | 8 |
| `RetireToken` | 16 | 8 |
| `SlotRef` | 8 | 8 |
| `SlotToken` | 8 | 8 |
| `ControlHeader` | 8 | 4 |
| `BlobSlice` | 8 | 4 |
| `SizeState` | 32 | 8 |
| `RegionDesc` | 16 | 8 |
| `SlotClassDesc` | 16 | 8 |
| `GlobalHeader` | 4096 | 4096 |
| `RingDesc` | 128 | 64 |
| `ProducerPage` | 4096 | 4096 |
| `ConsumerPage` | 4096 | 4096 |
| `SqeBody` | 120 | 8 |
| `Sqe` | 128 | 64 |
| `CqeBody` | 56 | 8 |
| `Cqe` | 64 | 64 |
| `BufferRef` | 24 | 8 |

### 2.2 `FeatureSet`, request ID, and 128-bit IDs

`FeatureSet` has one field:

| Field | Offset | Type |
|---|---:|---|
| `words` | 0 | `[u64; 2]` |

`ReqId` is a transparent `u64` with this exact packing:

```text
req_id = (generation << 24) | slot_index
req_id = { generation:40, slot_index:24 }
```

Bits 0 through 23 are `slot_index`; bits 24 through 63 are `generation`.
Construction rejects either component above the maxima in Section 1.1.

Each of `OpId`, `FileId`, `LinkId`, `MountId`, `BootInstanceId`,
`TransactionId`, `AckToken`, and `RetireToken` has this identical layout:

| Field | Offset | Type |
|---|---:|---|
| `lo` | 0 | `u64` |
| `hi` | 8 | `u64` |

The all-zero value exists for every 128-bit type, but whether it is legal is
message-specific. `OpId` is the durable mutation identity. `FileId` and
`LinkId` are stable stream and namespace-link identities. `MountId` identifies
one boot-local mount incarnation, `BootInstanceId` is the authenticated boot
identity from the permanent BootContext in Section 10.10, `TransactionId`
indexes a durable two-phase CREATE, `AckToken` identifies a notification
acknowledgement, and `RetireToken` is the authenticated retirement proof of
Section 10.12. None is a pointer or user handle.

### 2.3 Region descriptors

`RegionDesc` is size 16, alignment 8:

| Field | Offset | Type | Meaning |
|---|---:|---|---|
| `offset` | 0 | `u64` | byte offset from the shared-section base |
| `length` | 8 | `u64` | byte length |

`SlotClassDesc` is size 16, alignment 8:

| Field | Offset | Type | Meaning |
|---|---:|---|---|
| `slot_size` | 0 | `u32` | bytes per slot in the class |
| `slot_count` | 4 | `u32` | number of slots in the class |
| `data_offset` | 8 | `u64` | class-data byte offset from the shared-section base |

`SlotClassDesc.data_offset` is section-relative; Section 9.3 gives the exact
resolution and packing contract. Every `offset + length`,
`slot_size * slot_count`, array size, and alignment round-up MUST use checked
arithmetic before any pointer is formed. Every class range MUST lie wholly
inside its corresponding K2U or U2K arena and MUST NOT overlap a differently
owned range.

### 2.4 `GlobalHeader`

`GlobalHeader` is exactly 4096 bytes and 4096-byte aligned. Its meaningful
prefix is 272 bytes; its explicit reserved tail is 3824 bytes.

| Field | Offset | Type / bytes | Normative value or role |
|---|---:|---|---|
| `magic` | 0 | `u32` | `FSRING_MAGIC` |
| `header_size` | 4 | `u16` | 4096 |
| `abi_major` | 6 | `u16` | 2 |
| `abi_minor` | 8 | `u16` | 1 |
| `byte_order` | 10 | `u8` | `FSRING_ENDIAN_LITTLE` (1) |
| `header_flags` | 11 | `u8` | registry field; no values currently published |
| `page_size` | 12 | `u32` | 4096 for supported Windows profiles |
| `session_epoch` | 16 | `u64` | fresh, non-reused daemon-session epoch |
| `section_size` | 24 | `u64` | exact mapped section length |
| `ring_count` | 32 | `u32` | number of `RingDesc` records |
| `ring_desc_size` | 36 | `u32` | 128 |
| `ring_directory` | 40 | `RegionDesc` | ring descriptor array |
| `k2u_slots` | 56 | `RegionDesc` | kernel-to-user slot arena |
| `u2k_slots` | 72 | `RegionDesc` | user-to-kernel slot arena |
| `notify_names` | 88 | `RegionDesc` | disabled name region; exactly `{0, 0}` |
| `protocol_features` | 104 | `FeatureSet` | negotiated protocol features |
| `os_capabilities` | 120 | `FeatureSet` | kernel-published OS facilities |
| `max_inflight` | 136 | `u32` | actual per-volume application inflight cap |
| `flags` | 140 | `u32` | registry field; no values currently published |
| `k2u_slot_classes` | 144 | `[SlotClassDesc; 4]` | K2U class registry |
| `u2k_slot_classes` | 208 | `[SlotClassDesc; 4]` | U2K class registry |
| `reserved` | 272 | `[u8; 3824]` | required zero through byte 4095 |

`notify_names` MUST be exactly `{ offset: 0, length: 0 }` in every advertised
ABI 2.1 header; a nonzero value is a validation failure, not a feature.

### 2.5 `RingDesc`

`RingDesc` is exactly 128 bytes and 64-byte aligned.

| Field | Offset | Type / bytes | Normative value or role |
|---|---:|---|---|
| `magic` | 0 | `u32` | `FSRING_MAGIC` |
| `desc_size` | 4 | `u16` | 128 |
| `desc_version` | 6 | `u16` | descriptor-version field; no value currently published |
| `ring_index` | 8 | `u32` | unique zero-based ring index |
| `flags` | 12 | `u32` | registry field; no values currently published |
| `sq_capacity` | 16 | `u32` | SQ entry count |
| `cq_capacity` | 20 | `u32` | CQ entry count |
| `sq_entries` | 24 | `RegionDesc` | `Sqe` array |
| `sq_producer` | 40 | `RegionDesc` | SQ `ProducerPage` |
| `sq_consumer` | 56 | `RegionDesc` | SQ `ConsumerPage` |
| `cq_entries` | 72 | `RegionDesc` | `Cqe` array |
| `cq_producer` | 88 | `RegionDesc` | CQ `ProducerPage` |
| `cq_consumer` | 104 | `RegionDesc` | CQ `ConsumerPage` |
| `reserved` | 120 | `[u8; 8]` | required zero through byte 127 |

Both capacities MUST be powers of two inside the exact bounds of the Section
10.4 topology registry: `sq_capacity` in `[8, 65536]` and `cq_capacity` in
`[2, 65536]`. There is no required relationship between SQ and CQ sizes beyond
those bounds.

### 2.6 Producer and consumer pages

`ProducerPage` is exactly 4096 bytes and 4096-byte aligned:

| Field | Offset | Type / bytes | Ownership |
|---|---:|---|---|
| `tail` | 0 | `u64` | producer-owned monotonic reservation cursor |
| `wake_sequence` | 8 | `u64` | producer-owned hint/counter, initialized to zero |
| `flags` | 16 | `u32` | producer-owned registry field; no values currently published |
| `reserved0` | 20 | `[u8; 4]` | explicit required-zero alignment bytes |
| `reserved` | 24 | `[u8; 4072]` | required zero through byte 4095 |

`ConsumerPage` is exactly 4096 bytes and 4096-byte aligned:

| Field | Offset | Type / bytes | Ownership |
|---|---:|---|---|
| `head` | 0 | `u64` | consumer-owned monotonic consumed cursor |
| `park_state` | 8 | `u32` | consumer-owned 0/1/2 state |
| `flags` | 12 | `u32` | consumer-owned registry field; no values currently published |
| `heartbeat` | 16 | `u64` | consumer-owned liveness hint, initialized to zero |
| `reserved` | 24 | `[u8; 4072]` | required zero through byte 4095 |

`wake_sequence` and `heartbeat` are not publication edges in the current ring
algorithm and MUST NOT be used as the sole correctness or daemon-death signal.
If an owner updates either concurrently, all peer access to that field MUST be
atomic.

### 2.7 SQ entries

`SqeBody` is exactly 120 bytes and alignment 8:

| Field | Offset | Type / bytes |
|---|---:|---|
| `opcode` | 0 | `u16` |
| `flags` | 2 | `u16` |
| `payload_len` | 4 | `u16` |
| `reserved` | 6 | `u16` required zero |
| `req_id` | 8 | `u64` |
| `kernel_open_id` | 16 | `u64` |
| `ccb_sequence` | 24 | `u64` |
| `payload` | 32 | `[u8; 88]` |

`Sqe` is exactly 128 bytes and 64-byte aligned:

| Field | Offset | Type / bytes |
|---|---:|---|
| `sequence` | 0 | `u64` |
| `body` | 8 | `SqeBody` (120 bytes) |

Therefore `Sqe.req_id` is at full-entry offset 16 and `Sqe.payload` is at
full-entry offset 40. `payload_len` MUST be at most 88; bytes from
`payload_len` through byte 87 are zero on send.

### 2.8 CQ entries

`CqeBody` is exactly 56 bytes and alignment 8:

| Field | Offset | Type / bytes |
|---|---:|---|
| `kind` | 0 | `u16` |
| `opcode` | 2 | `u16` |
| `flags` | 4 | `u16` |
| `out_len` | 6 | `u16` |
| `req_id` | 8 | `u64` |
| `status` | 16 | `i32` |
| `reserved` | 20 | `u32` required zero |
| `information` | 24 | `u64` |
| `out` | 32 | `[u8; 24]` |

`Cqe` is exactly 64 bytes and 64-byte aligned:

| Field | Offset | Type / bytes |
|---|---:|---|
| `sequence` | 0 | `u64` |
| `body` | 8 | `CqeBody` (56 bytes) |

Therefore `Cqe.req_id` is at full-entry offset 16 and `Cqe.out` is at
full-entry offset 40. `out_len` MUST be at most 24; bytes from `out_len`
through byte 23 are zero on send.

`kind` is an independent field with the exact registry in Section 1.3. No bit
of `req_id` changes the CQ kind. A notification uses `kind = NOTIFY` and
`req_id = 0`; a generation with bit 39 set remains an ordinary 40-bit request
generation.

## 3. Shared-section construction and validation

The kernel creates one fresh shared section for each new daemon session. The
`GlobalHeader` begins at section offset zero. All pages are zeroed before their
first user mapping. The section is a serialization surface, not kernel object
state and not replay authority.

Before mapping or attaching a ring, both sides MUST validate all of the
following:

1. `magic`, header size, byte order, page size, descriptor sizes, and the
   current `session_epoch`;
2. `abi_major` is exactly 2 and `abi_minor` is at least
   `FSRING_ABI_MIN_COMPAT_MINOR` and at most the current minor — in base 2.1
   that means exactly 1; minor 0 is never selected and a header carrying it is
   rejected;
3. `section_size` equals the actual section length and is a multiple of 4096;
4. every region is aligned for its element and for page protection where
   ownership differs;
5. every region lies wholly within `section_size`, is non-overlapping with
   differently owned storage, and is large enough for its exact element count;
6. `ring_directory.length == ring_count * 128` using checked arithmetic;
7. each `ring_index` is unique and in `[0, ring_count)`;
8. `sq_entries.length == sq_capacity * 128` and
   `cq_entries.length == cq_capacity * 64`, with checked products;
9. every producer-page and consumer-page descriptor has length 4096 and a
   4096-aligned offset; capacities are powers of two inside the Section 10.4
   bounds;
10. feature sets satisfy Section 1.2 (base-required, unselectable, and
    restart-pair rules), `notify_names` is exactly `{0, 0}`, slot classes
    satisfy Section 9.3, and reserved bytes are zero.

Fresh rings start with producer `tail = 0`, consumer `head = 0`,
`park_state = ACTIVE`, and every entry `sequence = 0`. Other current page
fields start at zero. A new session always receives new storage; attach never
seeds new cursors from an old mapped ring.

## 4. Ownership and mapping protections

One writer owns every authoritative page or arena. Peer-owned pages are mapped
read-only wherever the OS supports separate views, and the Rust transport uses
read-only atomic loads for peer fields.

| Region | Sole writer | Peer view / rule |
|---|---|---|
| `GlobalHeader` and ring directory | kernel | daemon read-only |
| SQ entries, SQ sequences, SQ producer page | kernel MPSC producer family | daemon read-only |
| SQ consumer page (`head`, park state, hints) | single daemon SQ consumer | kernel reads as hostile peer state |
| CQ entries, CQ sequences, CQ producer page | single daemon CQ producer | kernel reads as hostile peer state |
| CQ consumer page (`head`, park state, hints) | single kernel CQ consumer | daemon read-only |
| K2U slot arena | kernel while allocated | daemon read-only |
| U2K slot arena | daemon only while granted | kernel validates before reading |

The daemon MUST NOT receive write access to the global header, ring
descriptors, SQ entries, the SQ producer page, the CQ consumer page, or K2U
data. It receives write access only to its SQ consumer page, its CQ entries
and producer page, and granted U2K storage. There is no notification-name
write grant in ABI 2.1; the row for that region is deliberately absent.

The kernel retains canonical request, object, authorization, mapping, slot,
and replay state outside the section. No wire field contains a raw kernel
pointer, an unreferenced user handle, or a trusted user virtual address.

### 4.1 Rust atomic-view rule

The wire structures deliberately contain plain `u64` and `u32` fields so the
C ABI remains exact. Concurrent code MUST access `tail`, `head`, `sequence`,
and `park_state` through naturally aligned, operation-scoped atomic views. It
MUST NOT create or retain a Rust shared or mutable reference to a whole page or
entry while any covered field can be concurrently mutated.

Loads from a peer read-only mapping use an ephemeral shared `AtomicU64` or
`AtomicU32` view that cannot store or perform an RMW. Writable atomic views are
formed only for locally owned writable fields. The producer raw-volatile-copies
the body before its Release sequence store; the consumer raw-volatile-copies
the body only after the matching Acquire sequence load. The transport is
compile-time restricted to `x86_64` and `aarch64`, the supported x64/ARM64
profiles.

## 5. Ring topology

Each daemon worker owns one ring pair:

- SQ is kernel MPSC: multiple kernel producers and exactly one daemon
  consumer;
- CQ is daemon SPSC: exactly one daemon producer and exactly one kernel drain
  consumer.

Parallel daemon workers use additional ring pairs. They MUST NOT add a second
consumer to an SQ or a second producer to a CQ. Concurrent ENTER calls that
select the same CQ are serialized through that ring's single-consumer
capability; completion processing may fan out only after the entry has been
claimed and copied locally.

`tail` is a reservation cursor, not a publication cursor. The per-entry
`sequence` Release/Acquire pair is the only payload publication edge. A
consumer does not use `tail` to decide whether a body is readable.

## 6. Normative ring algorithm and memory ordering

All cursor arithmetic is monotonic `u64` arithmetic. Every addition and
subtraction is checked. Cursors and sequences never wrap.

Let `capacity` be the ring capacity, `mask = capacity - 1`, `position` the
reserved producer position, and `next = position + 1`.

### 6.1 MPSC reservation and publication

An SQ producer executes one bounded `try_push` as follows:

1. Acquire-load the local `validated_head` floor.
2. Acquire-load the peer-owned `head`, then Relaxed-load the producer-owned
   `tail`. Loading tail after head is REQUIRED by the validated-cursor logic.
3. Reject `observed_head < validated_head` as `Regressed`. Reject
   `observed_head > tail` as `AheadOfProducer`. A rejected ahead value MUST NOT
   update the local floor.
4. If the observed head advances the floor, publish the maximum with an AcqRel
   `fetch_max`. If another producer has advanced the floor beyond the sampled
   tail, reload tail; if the relationship is still unresolved, consume one
   retry rather than misclassifying a valid concurrent observation.
5. Reject `tail == u64::MAX` as `Exhausted`. Compute
   `distance = tail.checked_sub(validated_head)`. If `distance == capacity`,
   return `Full` immediately. If `distance > capacity`, enter the
   over-capacity classification in Section 6.2 before touching any storage.
6. Compute `next = tail.checked_add(1)`. Attempt one weak CAS of tail from
   `tail` to `next` with Release success ordering and Relaxed failure
   ordering. A failed or spurious CAS consumes one retry.
7. After a successful reservation, select `index = position & mask`, raw-copy
   the complete `Copy` body into that cell, then Release-store
   `cell.sequence = next`.
8. Immediately perform the ring-bound wake check in Section 7 and return a
   receipt containing `{ position, should_wake }`.

One call performs at most `MAX_RESERVE_RETRIES = 64` reservation attempts.
Exhausting the bound returns `Contended`; it never spins without a bound. The
caller MAY retry under its bounded backpressure policy, but MUST yield, queue,
or fail rather than turn hostile contention into an unbounded kernel loop.

The common path where peer head has not advanced avoids an unnecessary RMW on
`validated_head`. This optimization MUST NOT weaken validation.

### 6.2 Over-capacity classification

`distance == capacity` is ordinary `Full`. A stable `distance > capacity` is
the structural cursor fault `Protocol(CursorFault::OverCapacity)`, but an MPSC
producer cannot classify it from one stale sample: a concurrent reservation
may have advanced `tail` after the head sample. On apparent over-capacity the
producer takes two Acquire snapshot pairs, loading `tail` first and then the
validated head in both snapshots. An unchanged pair whose checked distance
remains greater than capacity is stable and faults as
`Protocol(CursorFault::OverCapacity)`. Any progress between the snapshots
consumes one bounded retry and recomputes from the remote head. If progress
continues through the `MAX_RESERVE_RETRIES` bound, the call returns
`Contended`, never `OverCapacity`. SPSC has one producer and MAY classify a
stable `distance > capacity` directly. The pinned Loom model MUST cover the
stale-floor/concurrent-reservation execution and prove that it does not
produce a false protocol fault.

### 6.3 SPSC reservation and publication

The sole CQ producer keeps a local tail. It Acquire-loads and validates peer
head against its last validated head and local tail, rejects exhaustion, and
checks `tail - head < capacity` with the direct over-capacity rule above. It
then Relaxed-stores the producer-owned tail, raw-copies the body, and
Release-stores `cell.sequence = tail + 1`. It performs the same ring-bound
wake check. It does not use a CAS because the capability has exactly one owner
and is `Send` but not `Sync`.

### 6.4 Single-consumer acquisition

The sole consumer keeps a local head. For each pop it:

1. computes `expected = head.checked_add(1)`;
2. selects `index = head & mask`;
3. Acquire-loads `cell.sequence`;
4. returns empty/not-ready when `sequence < expected`;
5. reports `FutureSequence` when `sequence > expected`;
6. only when `sequence == expected`, raw-copies the complete body, then
   Release-stores the consumer-owned `head = expected` and updates its local
   head.

The consumer never writes an entry, producer page, or sequence. In particular,
it never clears a consumed cell. The producer never rolls a sequence back and
never writes consumer head. A later producer may reuse a cell only after its
Acquire observation of consumer head makes the consumer's prior Release head
store visible. Because sequence values and cursors increase monotonically, an
old sequence is distinguishable from a future one without modular arithmetic.

### 6.5 Exhaustion

If a ring cursor would advance beyond `u64::MAX`, the operation reports
`Exhausted` before modifying storage. The session is quiesced and replaced or
torn down; cursors are never reset in place and old cells are never re-seeded
under a live mapping.

## 7. Park, recheck, and wake

Park state belongs to the ring's sole consumer and has values `ACTIVE = 0`,
`POLLING = 1`, and `PARKED = 2`.

The consumer loop is:

1. Relaxed-store `ACTIVE` and drain the exact next sequences in batches.
2. Relaxed-store `POLLING` and perform only the configured bounded poll work.
3. SeqCst-store `PARKED`, then execute a SeqCst fence.
4. Acquire-recheck this same ring's exact next entry sequence.
5. If work or a protocol fault is visible, restore `ACTIVE` and do not sleep.
   Only an absent old sequence permits waiting on this ring's wake object.

Immediately after Release-publishing an entry, the producer executes a SeqCst
fence and Relaxed-loads this same ring's park state. The resulting
`should_wake` is carried in the mandatory-use push receipt. If true, the caller
signals only this ring instance's wake object. Cross-pairing a queue recheck or
wake object with another ring is forbidden.

Spurious and coalesced wakes are legal. A lost wake is not. The control path
establishes and retains one ring-bound wake object per ring without placing a
raw handle or kernel pointer in shared memory.

## 8. Request identity, CQ classification, and hostile validation

### 8.1 Request identity and the ReqId partition

The kernel owns the request table and assigns the full `ReqId`. The
`slot_index` selects a live record; `generation` distinguishes reuse of that
record within a session. Under the negotiated topology the 24-bit index space
is partitioned exactly:

| Index range | Class | Meaning |
|---|---|---|
| `[0, max_inflight)` | application | ordinary application logical requests |
| `[SYSTEM_REQID_BASE, SYSTEM_REQID_BASE + 3 * ring_count)` | system | per-ring reserved control lanes |
| `16777215` | global | the single `GLOBAL_EXTERNAL_CHANGE_ACK_REQID` slot |

`SYSTEM_REQID_BASE = 16777023` and
`GLOBAL_EXTERNAL_CHANGE_ACK_REQID = 16777215`. For ring `r`, index
`SYSTEM_REQID_BASE + 3*r` is the serialized open-lifecycle recovery slot,
base+1 is the `PT_ROUTE_ACK` lane, and base+2 is the `PT_EXTERNAL_SAFE_ACK`
lane. The open-lifecycle slot carries exactly one `REPLAY_OPEN`, recovery
CLEANUP, or recovery CLOSE phase at a time; ordinary same-session
CLEANUP/CLOSE remain application requests. Index 16777215 is the one global,
ring-zero external-change acknowledgement slot. The three per-ring system
entries and the global entry are never exposed through or borrowed by
application admission, and each has its own nonzero no-wrap generation.
Application indices, the up-to-192 ring-scoped reserved entries, and the final
global entry exactly fill but never exceed the 2^24 `ReqId` space. Every index
outside the three classes is unassigned, and a completion carrying one is a
protocol fault.

A completion is accepted only if all of these match kernel-owned state:

- current `session_epoch`;
- live slot index in a legal class for the completing opcode;
- all 40 generation bits;
- expected opcode and completion class;
- the request's current completion/cancel state.

The generation never wraps. After a slot completes its maximum generation,
that slot is retired for the session. If retirement would prevent further
allocation, the driver performs a controlled quiesce and creates a fresh
session/section with a fresh epoch, or fails the volume; it never reuses an
old `ReqId` in the same epoch.

`req_id` is session-scoped and is not an exactly-once identity. Durable
mutations use a separate 128-bit `OpId`.

### 8.2 CQ kind is independent

The kernel dispatches CQ records first by the explicit `kind` field:

- `COMPLETION = 0` completes a live request;
- `NOTIFY = 1` is an unsolicited provider notification and has `req_id = 0`;
- `PROTOCOL = 2` is a protocol-control record. ABI 2.1 registers exactly one
  PROTOCOL record, opcode `ABORT_SESSION = 1` with reason
  `PROVIDER_FATAL_STATE = 1`; its `ProtocolAbortV1` wire layout is defined in
  document 03. A valid record requests immediate quarantine and controlled
  teardown; any other PROTOCOL encoding is a structural protocol fault.

No request-ID bit is reserved for notification classification. The kernel
copies one acquired 56-byte `CqeBody` to kernel-owned local storage and
validates that copy before dispatch. It never validates one read and then uses
a second daemon-mutable read.

“Dispatches first by `kind`” selects the record schema; it does not authorize
discarding journaled-candidate provenance before the malformed envelope is
recorded. A valid NOTIFY or PROTOCOL record has `req_id = 0` and remains wholly
outside the request table. If a record claiming NOTIFY or PROTOCOL instead
carries the exact currently-live journaled semantic `ReqId`, the consumer first
enters `CANDIDATE_CAPTURE` under documents 05 section 17.2 and 06 section 9.3,
then installs `INVALID_CANDIDATE` for the wrong kind before releasing the CQ
head or invalidating that `ReqId`; the wrong-kind record still faults the
session. A nonzero `req_id` which is not that exact live journaled identity is
a structural protocol fault and acquires no application capability. Thus kind
selects the validation path first, while exact live journaled identity selects
the required capture ordering within the invalid-envelope path.

### 8.3 Hostile peer fields

All daemon-writable state is hostile input. The SQ kernel producer validates
daemon head with `validated_head <= observed_head <= current_tail`. The kernel
CQ consumer accepts only its exact next sequence. In addition, the kernel
validates on every CQ record:

- current session and live request identity within the Section 8.1 partition;
- registered `kind`, opcode, flags, and operation-specific status class;
- `out_len <= 24` and operation-specific `information` bounds;
- required-zero fields and unused output bytes;
- every slot, mapping, object, generation, token, and epoch referenced by the
  body.

A persistent cursor contradiction, regression, future sequence, malformed
section descriptor, stale epoch, invalid token lifetime, or other structural
contradiction is a session-level `PROTOCOL_FAULT`. The kernel atomically
quarantines that session, stops accepting its writable memory, and enters the
configured GRACE/attach path or teardown. It does not continue on
contradictory data, panic on daemon input, bugcheck on daemon input, or spin
waiting for hostile memory to become valid.

A validated operation-level provider error may fail one request. It MUST NOT
be silently promoted into trusted structural state. Conversely, a structural
fault MUST NOT be hidden by returning an ordinary request error and continuing
to use the session.

## 9. Directional slots, buffers, and grants

### 9.1 `SlotRef` is a published helper only

`SlotRef` is a transparent 64-bit value with this exact bit allocation:

| Field | Bits | Width | Maximum |
|---|---|---:|---:|
| `class` | 0..1 | 2 | 3 |
| `index` | 2..21 | 20 | 1048575 |
| `offset` | 22..42 | 21 | 2097151 |
| `len` | 43..63 | 21 | 2097151 |

```text
raw = class | (index << 2) | (offset << 22) | (len << 43)
```

`SlotRef::is_empty()` is exactly `len == 0`, so every encoding with a zero
length is empty; raw zero is the all-zero example, not a uniquely specified
canonical encoding. `SlotRef` remains a byte-stable published helper, but it
is not the meaning of `BufferRef.token` in ABI 2.1 and MUST NOT appear in a
2.1 message. Repacking the published helper would require a new ABI major.

### 9.2 `SlotToken`

ABI 2.1 defines the generation-stamped `SlotToken(u64)` as the exact meaning
of `BufferRef.token` for `kind == SLOT`:

```text
SlotToken = class:2 | index:20 | generation:42
raw = class | (index << 2) | (generation << 22)
```

| Field | Bits | Width | Maximum |
|---|---|---:|---:|
| `class` | 0..1 | 2 | 3 |
| `index` | 2..21 | 20 | 1048575 |
| `generation` | 22..63 | 42 | 4398046511103 |

Generation zero is invalid. A generation is never wrapped; the slot or session
is retired before reuse at the maximum value. A MAPPING token is a separate
opaque generation-stamped capability resolved through the kernel mapping
table; it is never interpreted as a pointer or `SlotToken`.

### 9.3 Section-relative slot addressing

`SlotClassDesc.data_offset` is a byte offset from the beginning of the shared
section. For each class, checked arithmetic MUST prove that

```text
data_offset + slot_size * slot_count
```

lies completely inside the corresponding `GlobalHeader.k2u_slots` or
`GlobalHeader.u2k_slots` region and the section. The resolved byte range for a
slot buffer is:

```text
slot_base = data_offset + index * slot_size
start     = slot_base + BufferRef.offset
end       = start + BufferRef.length
```

No pointer is formed until every product and sum has succeeded and the final
range is in-bounds.

`SLOT_ALIGNMENT` is 64 and `USER_VIEW_OFFSET_ALIGNMENT` is 65536. An active
class has count in `[1, 1048576]` and a power-of-two slot size in
`[256, 16777216]`; size and section-relative data offset are multiples of 64,
and every decoded index is strictly below that class's count. Active classes
are a contiguous prefix in strictly increasing slot-size order. The kernel
packs their non-overlapping ranges in class order from the 64-KiB-aligned
arena offset with checked 64-byte align-up. An inactive request class is
exactly `{slot_size: 0, slot_count: 0}` and its generated `SlotClassDesc` is
exactly `{slot_size: 0, slot_count: 0, data_offset: 0}`. Arena `RegionDesc`
values are 64-KiB-aligned, contain every active class, and contain no
unreported bytes except zeroed final padding through the next
`USER_VIEW_OFFSET_ALIGNMENT` boundary. Every region that has a writable
user-mode alias occupies a distinct protection extent beginning on such a
boundary; no two writable aliases and no writable alias plus read-only control
data share an extent.

### 9.4 `BufferRef` and the grant table

The fixed payloads use `BufferRef`, exactly size 24 and alignment 8:

| Field | Offset | Type | Rule |
|---|---:|---|---|
| `token` | 0 | `u64` | `SlotToken` for kind SLOT; opaque mapping capability for kind MAPPING |
| `offset` | 8 | `u32` | checked byte offset within the capability |
| `length` | 12 | `u32` | checked byte length |
| `kind` | 16 | `u16` | `NONE`, `SLOT`, or `MAPPING` |
| `access` | 18 | `u16` | `K2U_READ_ONLY` or `U2K_WRITE` when nonempty |
| `reserved` | 20 | `u32` | required zero |

The kernel owns an O(1) grant table indexed by direction, class, and index. A
live entry contains the exact generation, session epoch, owner request or
notification credit, access direction, maximum range, and rundown state. A
SLOT reference is valid only when all those fields match. `BufferRef` rules
are closed:

- NONE requires every other field to be zero;
- SLOT requires a live `SlotToken`, registered access, nonzero generation, and
  checked bounds within one slot;
- MAPPING requires a live mapping capability and a checked subrange;
- a request-result reference echoes the kernel-issued token, kind, access, and
  offset exactly; only `length` may shrink (`ShrinkOnly`);
- an `Exact` echo repeats the issued offset and length byte-for-byte;
- a schema-designated `DerivedSubrange` may change offset/length only when its
  complete checked range remains inside the original issued grant; no other
  derived reference is valid on the wire;
- an output grant is owned until completion/cancel arbitration selects one
  terminal owner and slot/mapping rundown finishes.

The kernel copies daemon-writable control/metadata bytes into private bounded
storage once, validates that snapshot, and never validates one shared snapshot
then consumes another. Large application mappings use their existing explicit
rundown and access protections. A syntactically valid reference is not proof
that the slot is allocated, current, correctly directed, or live.

### 9.5 Grant direction and capacity registry

Every output-producing request carries its kernel-issued U2K grants. The grant
rules are exact; K2U means access `K2U_READ_ONLY` and U2K means `U2K_WRITE`:

| Request field | Required direction/capacity | NONE legality | Result echo |
|---|---|---|---|
| Prepare requested SD, EA | K2U; exact validated input bytes | allowed independently | never echoed |
| Prepare reply | U2K, at least 136 bytes | forbidden | CQ OControl |
| Prepare result SD | U2K, exactly 65536 bytes | forbidden | `PrepareOpenResultV1.security_descriptor` |
| Commit reply | U2K, at least 112 bytes | forbidden | CQ OControl |
| Read data | U2K; requested capacity | forbidden | CQ OControl shrunk to transferred bytes |
| Write data | K2U; exact request length | forbidden | never echoed |
| Write reply | U2K, at least 56 bytes | forbidden | CQ OControl |
| Mutation body | K2U, exact body `struct_size` | forbidden | never echoed |
| Mutation reply | U2K, at least 112 bytes | forbidden | CQ OControl |
| Mutation kind result | U2K, exactly 112/104/56 bytes for RENAME/LINK/UNLINK | required NONE for all other kinds | `MutationResultV2.kind_result` |
| Replay reply | U2K, at least 16 bytes | forbidden | CQ OControl |
| QueryOp reply | U2K, at least 56 bytes | forbidden | CQ OControl |
| QueryOp committed result | U2K, 40-224 bytes; ordinary confirmation reserves 224 | forbidden | `QueryOpResultV1.result` only for COMMITTED |
| QuerySecurity descriptor | U2K, exactly 65536 bytes | forbidden | CQ OControl shrunk to the complete descriptor length |

A grant may be SLOT or MAPPING if the negotiated transport supports that kind.
Every ordinary result echoes token, kind, access, and offset exactly and
reduces length to its exact validated result size. The kernel always grants
the complete `MAX_SECURITY_DESCRIPTOR_BYTES` (65536) for a Prepare result SD
and a QUERY_SECURITY descriptor, so a provider BUFFER_TOO_SMALL on either is a
protocol fault and can never drive an internal retry.
`MIN_SECURITY_DESCRIPTOR_BYTES = 20` and `MAX_REPARSE_DATA_BYTES = 16384`.
QueryOp BUFFER_TOO_SMALL refers only to the committed-result grant, changes no
journal state, and reports the exact required bytes in CQ information under
the bounded retry rule of Section 10.21. The wire layouts of the version-2
request and result forms named here live in document 03.

### 9.6 Size domain and mount-wide ordering

`MAX_FILE_SIZE = 0x7fff_ffff_ffff_ffff` (`i64::MAX`). Every wire field that
represents allocation size, EOF/file size, VDL, file offset, byte-range end,
or a native volume byte total is an unsigned encoding of a value in
`[0, MAX_FILE_SIZE]`; it is rejected before conversion to `LARGE_INTEGER`
otherwise. For a nonempty file byte range, checked arithmetic MUST prove
`offset < MAX_FILE_SIZE`, `1 <= length <= MAX_FILE_SIZE`, and
`offset + length <= MAX_FILE_SIZE`. A schema whose zero length means the whole
stream additionally requires offset zero. These rules apply uniformly to
READ/WRITE, SizeState in every request/result/notification, size mutations,
committed results, query metadata, RESIZE, INVALIDATE_FILE, cache/MM calls,
and native volume conversions; no opcode may fall back to unsigned wrap or an
implementation-defined "volume maximum". A negative native `LARGE_INTEGER`
size completes locally with INVALID_PARAMETER, zero information, and no
ReqId/grant/SQ publication. A provider value outside the domain is a protocol
fault before any native or cache call.

`volume_commit_sequence` is one mount-wide `u64` transaction order shared by
successful COMMIT_OPEN, WRITE, MUTATE, RESIZE, and external DIR_CHANGE. Zero
is invalid. Every distinct committed provider or external transaction
allocates a value strictly greater than every previously allocated value; the
counter never wraps, and the mount is retired before another state-changing
transaction if `u64::MAX` has been allocated. Ordinary completion, durable
result, QUERY_OP, replay, and any notification for the same transaction repeat
its exact original value rather than allocating another. All outbox rows
produced by one external transaction repeat that transaction's sequence. Ring
delivery is explicitly not ordered by this counter; the kernel retains a
last-applied sequence plus compact provenance per affected domain and merges
validated results as follows:

| Observed vs retained | Rule |
|---|---|
| precise external event | installs an invalidation floor equal to its sequence on every affected domain; the floor stores a comparable domain generation only when the event schema carries one |
| OVERFLOW | cold-invalidates all provider-derived domains and advances the volume-wide `cold_floor_sequence` to its highest covered sequence; it is never precise provenance |
| at or below an applicable floor | may still complete, ACK, or repeat conservative invalidation, but may not install precise provider cache state; only a strictly greater sequence can |
| lower sequence | older committed result: the IRP still completes and its COMMITTED bundle is ACKed, but it cannot replace newer cached state; nonzero carried epochs/generations compare lower = stale, equal = full state must match, higher = protocol fault |
| equal sequence | legal only for the same retained OpId and semantic request, or the closed cross-form RESIZE/DIR_CHANGE exceptions of one transaction, with exact equality of every overlapping identity, SizeState, generation, count, and payload; any other reuse is a protocol fault |
| greater sequence | may advance: a lower size epoch or namespace/security generation is a protocol fault, an equal counter requires byte-identical corresponding state, a greater counter applies the full state; all affected domains become visible atomically |

A stale multi-entity namespace result performs only conservative invalidation
for the whole relation; the kernel never installs half a rename, link, unlink,
or replacement. These rules also apply after QUERY_OP recovery, so arrival
order cannot regress a SizeState or namespace/security generation.

`provider_open_cookie` is session-local authority whose mode is ordinary or
paging-only. It may appear in an ordinary `CommitOpenResultV2`, but it MUST
NOT be stored in a durable committed result. Recovery obtains a fresh cookie
through `REPLAY_OPEN` on the owning ring's reserved open-lifecycle
ReqId/control lane — never through an application `max_inflight` slot — with a
fresh nonzero generation for each wire phase. `REPLAY_OPEN` has no durable
child row, reservation, or accounting charge; the provider keeps bounded
volatile replay state keyed by `(session_epoch, kernel_open_id)` with states
`UNSEEN -> PENDING -> DONE`, returns the identical DONE cookie for an exact
same-epoch duplicate, and treats a changed duplicate as a protocol fault. A
fence, provider process exit, or epoch change closes every old cookie and
destroys every old volatile replay state.

### 9.7 Notification credits

Unsolicited notifications cannot invent U2K tokens. SETUP/ATTACH returns a
bounded tail array of `NotificationCreditV1` values, each containing an exact
U2K `BufferRef` and owning ring index. A daemon may publish one NOTIFY with a
credit assigned to that ring. Every credit BufferRef is distinct, has kind
SLOT, access `U2K_WRITE`, offset zero, length exactly the negotiated credit
size, and zero reserved field; its enclosing credit reserved field is also
zero. MAPPING and derived subranges are not credit forms. The NOTIFY OControl
MUST echo token/kind/access and offset while shrinking only length to the
validated envelope size — exactly `NotifyEnvelopeV2.struct_size` (the 56/8
envelope defined in document 03); the body slice starts exactly at byte 56
and lies wholly inside that length, and there is no nested BufferRef.

The policy constants are exact:

```text
MIN_NOTIFICATION_CREDIT_SIZE        = 2048
MAX_NOTIFICATION_CREDIT_SIZE        = 65536
MAX_NOTIFICATION_CREDITS_PER_RING   = 64
MAX_NOTIFICATION_CREDITS_PER_SESSION = 1024
MAX_NOTIFICATION_CREDIT_BYTES       = 16777216
```

Credit size is a power of two and a multiple of 64. Every ABI 2.1 session has
a nonzero pool with count in `[ring_count, min(64 * ring_count, 1024)]`,
distributed round-robin with a per-ring difference of at most one. The kernel
chooses the smallest U2K slot class whose slot size is at least the requested
credit size and that has enough distinct slots; otherwise SETUP fails. Credit
count, size, and checked product must satisfy all per-ring, per-session, and
byte caps before allocation.

Credits cannot consume all forward-progress storage. After credit reservation,
SETUP requires ring-affine progress reserves with
`MIN_CONTROL_SLOT_SIZE = 131072`, `MIN_K2U_PROGRESS_SLOTS_PER_RING = 4`, and
`MIN_U2K_PROGRESS_SLOTS_PER_RING = 2`. Feasibility is deterministic: sum the
counts of every active K2U class whose slot size is at least
`MIN_CONTROL_SLOT_SIZE`; that total must be at least
`MIN_K2U_PROGRESS_SLOTS_PER_RING * ring_count`. Sum the analogous U2K counts,
then subtract `notification_credit_count` exactly when the selected credit
class is itself at least `MIN_CONTROL_SLOT_SIZE`; the remainder must be at
least `MIN_U2K_PROGRESS_SLOTS_PER_RING * ring_count`. Every sum, product, and
subtraction is checked. Failure of this pre-allocation feasibility test is
INVALID_PARAMETER, not resource-driven clamping. The reserves are scheduler
reserves, not permanently idle slots.

During normal ENTER, the kernel reserves space for the refreshed credit in the
current output before it consumes a NOTIFY CQ record. It then claims and
privately copies only the advertised notification bytes, advances CQ head,
increments the generation after release, and returns the refreshed credit in
the same ENTER result. Claiming a credit atomically changes its grant-table
state and invalidates the old generation before the CQ-head Release store. The
credit cannot be reused until returned. Duplicate, stale, cross-ring, or
concurrent reuse is a protocol fault. The only exception is the old-session
fence drain in Section 10.20: it consumes the stable notification for
correctness, retires that credit with the old section, and ATTACH supplies a
fresh pool, so no descriptor is returned across epochs.

### 9.8 Native direct-I/O admission

Every mounted volume device sets `DO_DIRECT_IO`, clears `DO_BUFFERED_IO`, and
finishes those flags before clearing `DO_DEVICE_INITIALIZING`. This single
choice applies to every IRP-based READ, WRITE, QUERY_DIRECTORY, CHANGE_NOTIFY,
EA, and quota path that obeys volume flags; an opcode-specific adapter may not
assume a SystemBuffer. Base 2.1 advertises no data Fast-I/O callback, so
cache-manager or application data Fast-I/O probes return FALSE and fall back
to these IRPs.

For every legal nonzero native input/output range on those direct-I/O majors,
structural dispatch preflight requires a non-null `Irp->MdlAddress`,
`mdl->Next == NULL`, checked `MmGetMdlByteCount >= requested_length`, and
checked range/page-span arithmetic without touching caller bytes. After the
common quota ticket is reserved, dispatch requires one successful
`MmGetSystemAddressForMdlSafe` mapping before semantic filesystem state
mutation. The modern profile passes
`NormalPagePriority | MdlMappingNoExecute` and additionally
`MdlMappingNoWrite` only for input-only pages; output pages remain writable.
The Win7 profile passes only `NormalPagePriority`. A missing/short/chained MDL
completes `STATUS_INVALID_USER_BUFFER = 0xc00000e8`; a null mapping completes
INSUFFICIENT_RESOURCES. Both use zero information, touch no caller byte, and
create no ReqId/grant/SQE. Zero-length behavior is opcode-specific; neither
profile fabricates an MDL for a zero range.

Every asynchronous IRP that retains locked caller pages obeys these common
bounds:

```text
MAX_PENDING_ASYNC_IRPS_PER_IO_OWNER      = 1024
MAX_PENDING_ASYNC_IRPS_PER_MOUNT         = 16384
MAX_PENDING_ASYNC_IRPS_GLOBAL            = 65536
MAX_PENDING_ASYNC_MDL_BYTES_PER_IO_OWNER = 67108864
MAX_PENDING_ASYNC_MDL_BYTES_PER_MOUNT    = 268435456
MAX_PENDING_ASYNC_MDL_BYTES_GLOBAL       = 1073741824
```

The I/O owner is the live CCB for ordinary requests and a referenced per-FCB
paging-budget owner for paging I/O; it remains valid through completion. Every
nonzero accepted incoming MDL is a single chain element. Its byte charge is
the complete checked locked-page span, not the requested/logical subrange:

```text
ADDRESS_AND_SIZE_TO_SPAN_PAGES(
    MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl)) * PAGE_SIZE
```

All pointer, page-count, multiplication, and counter arithmetic is checked.
Admission reserves count and byte budgets in fixed global, mount, then
I/O-owner order with cacheline-separated atomic CAS before
`MmGetSystemAddressForMdlSafe`, grant/mapping creation, request-table
admission, queue visibility, ReqId, or SQ publication. Partial reservation or
mapping failure rolls every reservation back and returns the operation's
registered INSUFFICIENT_RESOURCES/zero result; invalid, forbidden-zero-range,
or chained MDLs return INVALID_USER_BUFFER/zero. No global dispatch-path lock
is introduced.

The resulting nonpaged quota ticket stores the exact charge and referenced
budget owners. Once the IRP may be visible to cancellation or a queue, that
ticket follows the one terminal-owner CAS; losing paths never refund it. The
charge survives READ/WRITE chunking, QUERY_SECURITY recovery, internal
QueryDir batches, every recoverable GRACE/ATTACH, notification FANOUT, and
deferred completion. The terminal owner refunds exactly once, only after the
last driver MDL/system-VA access and after `IoCompleteRequest` returns. The
per-opcode adapter details (paging-WRITE issue ordering, QUERY_SECURITY
conditional MDL, buffered query classes) are specified by the dispatch
documents.

### 9.9 Direction, lifetime, and per-volume caps

- K2U data is produced by the kernel and mapped read-only to the daemon. The
  kernel fills it before Release publication of the referring SQE.
- U2K data is writable by the daemon only for the explicit grant. The kernel
  reads it only after Acquire of the referring CQE and after validating the
  capability, direction, bounds, and returned length.
- A mapping is established through the authenticated control path from a
  locked MDL with the minimum rights supported by the running OS. The ring
  carries only its opaque token.
- Slot allocation, generation, direction, and lifetime are kernel-owned.
  Slots, MDLs, mapping objects, and request objects remain live until
  cancel/completion arbitration selects exactly one terminal owner and all
  readers have left rundown.
- Kernel-created storage is zeroed before first exposure and scrubbed before
  reuse whenever bytes could cross a security boundary.

For application WRITE on Windows 7 SP1 x64, `MDL_NO_WRITE` is unavailable.
The kernel therefore copies the application input into a K2U slot and maps
that slot read-only to the daemon. It MUST NOT expose a writable application
WRITE mapping. Application READ output remains U2K-writable. This fallback
changes performance only; message, ordering, completion, cache, and durability
semantics remain identical to the modern profile.

Every mount has finite caps for total section bytes, ring count and each
SQ/CQ capacity, slot size/count/total bytes in every class and direction,
concurrent mappings and total mapped bytes, inflight requests, and every
pending/backpressure queue. The numeric registry is Section 10.4; SETUP
records the accepted values in `GlobalHeader`, `RingDesc`, and
`SlotClassDesc`. All cap accounting reserves before allocating or mapping and
uses checked addition/multiplication. Cap exhaustion returns bounded
backpressure or a resource failure. It never creates an unbounded overflow
list, blocks a kernel producer indefinitely, or allocates until the system
fails.

## 10. Authenticated control registry and lifecycle

### 10.1 Control device and CREATE

The control device uses `FILE_DEVICE_UNKNOWN` (`0x22`), private function
values starting at `0x800`, `METHOD_BUFFERED`, and
`FILE_READ_ACCESS | FILE_WRITE_ACCESS`. `FILE_DEVICE_SECURE_OPEN` is a
required `DeviceCharacteristics` bit; it is not a packaging option. The device
is created securely with the SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (LocalSystem
and Builtin Administrators only), and the I/O manager access check is not
bypassed by a custom dispatch path.

`IRP_MJ_CREATE` accepts only a root control-device open whose
`FileObject->FileName` is empty and whose `RelatedFileObject` is null. CREATE
behavior is closed and uses this precedence: a non-UserMode create returns
ACCESS_DENIED; then a non-root create returns
OBJECT_NAME_NOT_FOUND (`0xc0000034`); then failure to allocate/reference the
per-file context returns INSUFFICIENT_RESOURCES. Every such failure has
`IoStatus.Information = 0` and installs no file context. A successful UserMode
root create atomically captures and references the IRP requestor `EPROCESS`
in that context before returning SUCCESS with `IoStatus.Information = 0`.
Cleanup/close releases the reference only after IOCTL rundown. No SETUP or
ATTACH has yet occurred at CREATE time.

Every subsequent IOCTL requires `RequestorMode == UserMode` and the IRP
requestor `EPROCESS` to equal the process captured at CREATE; use of a
duplicated or inherited handle from another process returns ACCESS_DENIED with
no mapping or side effect. There is no raw section handle in user mode. The
kernel creates the minimum-rights views in the authorized process and returns
each process-local user mapping address as a 64-bit value; the kernel never
accepts the address back as authority, and no returned value is a kernel
pointer. The driver validates both lengths and snapshots METHOD_BUFFERED input
before writing output.

### 10.2 IOCTL numeric registry

| IOCTL | Function | Value |
|---|---:|---:|
| `IOCTL_FSRING_SETUP` | `0x800` | `0x0022e000` |
| `IOCTL_FSRING_ENTER` | `0x801` | `0x0022e004` |
| `IOCTL_FSRING_ATTACH` | `0x802` | `0x0022e008` |
| `IOCTL_FSRING_DONATE_BACKING` | `0x803` | `0x0022e00c` |
| `IOCTL_FSRING_DONATE_SECURITY_CONTEXT` | `0x804` | `0x0022e010` |
| `IOCTL_FSRING_DETACH` | `0x805` | `0x0022e014` |
| `IOCTL_FSRING_RETIRE_MOUNT` | `0x806` | `0x0022e018` |

### 10.3 Fixed control structures

The fixed prefixes are exact; sizes are `size/alignment` and offsets are byte
offsets from structure start:

```text
SlotClassRequest: 8/4
  +0 slot_size:u32, +4 slot_count:u32

SetupRequestV1: 160/8
  +0   header:ControlHeader
  +8   abi_major:u16, +10 min_abi_minor:u16
  +12  max_abi_minor:u16, +14 reserved0:u16
  +16  offered_features:FeatureSet
  +32  required_features:FeatureSet
  +48  required_os_capabilities:FeatureSet
  +64  ring_count:u32, +68 sq_capacity:u32
  +72  cq_capacity:u32, +76 max_inflight:u32
  +80  k2u_slot_classes:[SlotClassRequest; 4]
  +112 u2k_slot_classes:[SlotClassRequest; 4]
  +144 notification_credit_count:u32, +148 notification_credit_size:u32
  +152 flags:u32, +156 reserved1:u32

UserViewDesc: 32/8
  +0  section_offset:u64, +8 length:u64, +16 user_address:u64
  +24 ring_index:u32, +28 kind:u16, +30 access:u16

NotificationCreditV1: 32/8
  +0  buffer:BufferRef, +24 ring_index:u32, +28 reserved:u32

SessionResultV1: 136/8 fixed prefix
  +0   header:ControlHeader     // struct_size includes both tail arrays
  +8   abi_major:u16, +10 abi_minor:u16, +12 reserved0:u32
  +16  mount_id:MountId
  +32  boot_instance_id:BootInstanceId
  +48  session_epoch:u64
  +56  section_size:u64
  +64  selected_features:FeatureSet, +80 os_capabilities:FeatureSet
  +96  view_count:u32, +100 view_desc_size:u32, +104 views_offset:u32
  +108 notification_credit_count:u32
  +112 notification_credit_desc_size:u32
  +116 notification_credits_offset:u32
  +120 ring_count:u32, +124 max_inflight:u32
  +128 flags:u32, +132 reserved1:u32
  views:[UserViewDesc; view_count]
  credits:[NotificationCreditV1; notification_credit_count]

AttachV1: 56/8
  +0  header:ControlHeader
  +8  prior_session_epoch:u64
  +16 requested_features:FeatureSet
  +32 mount_id:MountId
  +48 journal_version:u32, +52 flags:u32

EnterRequestV1: 48/8
  +0  header:ControlHeader
  +8  mount_id:MountId, +24 session_epoch:u64
  +32 ring_index:u32, +36 flags:u32
  +40 cq_budget:u32, +44 timeout_ms:u32

EnterResultV1: 48/8 fixed prefix
  +0  header:ControlHeader      // struct_size includes returned credits
  +8  session_epoch:u64, +16 ring_index:u32, +20 flags:u32
  +24 cq_drained:u32, +28 sq_ready:u32
  +32 notification_credit_count:u32
  +36 notification_credit_desc_size:u32
  +40 notification_credits_offset:u32, +44 reserved:u32
  credits:[NotificationCreditV1; notification_credit_count]

DetachRequestV1: 40/8
  +0  header:ControlHeader
  +8  mount_id:MountId, +24 session_epoch:u64
  +32 flags:u32, +36 reserved:u32

DonateBackingV2: 48/8 fixed prefix
  +0  header:ControlHeader      // struct_version = 2
  +8  file_id:FileId, +24 pt_epoch:u64
  +32 sector_size:u32, +36 flags:u32
  +40 backing_path:BlobSlice    // path bytes begin at byte 48

DonateSecurityContextV1: 32/8   // reserved, never accepted in 2.1
  +0  header:ControlHeader
  +8  security_context_id:u64, +16 daemon_handle:u64
  +24 flags:u32, +28 reserved:u32

RetireMountV1: 48/8
  +0  header:ControlHeader
  +8  mount_id:MountId, +24 token:RetireToken
  +40 action:u32, +44 reserved:u32

RetireMountResultV1: 96/8
  +0  header:ControlHeader
  +8  mount_id:MountId
  +24 boot_instance_id:BootInstanceId
  +40 proof_token:RetireToken
  +56 latest_session_epoch:u64
  +64 selected_features:FeatureSet
  +80 journal_version:u32
  +84 mount_state:u16, +86 flags:u16, +88 reserved:u64
```

In `SessionResultV1`, `MountId` is at offset 16, `BootInstanceId` at 32,
`session_epoch` at 48, and `section_size` at 56. In `RetireMountResultV1`,
`MountId` is at offset 8, `BootInstanceId` at 24, `proof_token` at 40,
`latest_session_epoch` at 56, `selected_features` at 64, `journal_version` at
80, and `mount_state` at 84. There is no implicit or tail padding inside
either fixed prefix.

The handle-bearing version-1 donation structure is registry-stable only.
DonateBackingV1 MUST NOT appear on the ABI 2.1 wire: it cannot prove that user
mode retained no alias to the same FileObject, so a well-formed authorized
call carrying structure version 1 returns NOT_SUPPORTED after the common
header precedence of Section 1.4. `DonateBackingV2` uses structure version 2;
every other structure version returns REVISION_MISMATCH.

The exact METHOD_BUFFERED schemas are SETUP `SetupRequestV1 ->
SessionResultV1`, ATTACH `AttachV1 -> SessionResultV1`, ENTER
`EnterRequestV1 -> EnterResultV1`, RETIRE_MOUNT QUERY
`RetireMountV1 -> RetireMountResultV1`, and no-output for both donations,
DETACH, and RETIRE_MOUNT ACK. Every fixed input has
`ControlHeader.struct_size == InputBufferLength ==` its listed size and
rejects trailing bytes. `DonateBackingV2` instead has
`struct_size == InputBufferLength == align8(48 + backing_path.length)` with
the path tail rules below. A successful donation, DETACH, or retirement
ACK returns no bytes and sets `IoStatus.Information = 0`; a successful
retirement QUERY returns exactly 96 zero-initialized-then-filled bytes.

`DonateBackingV2.backing_path` begins exactly at byte 48, is the only tail, is
2-32760 bytes of well-formed UTF-16LE, and is followed only by zero alignment
padding. It is an absolute `\Device\...` path with no NUL, slash, empty, dot,
or dot-dot component, no trailing separator, and no named-stream colon.
DOS-device and relative paths are rejected. Fixed fields, nonzero
FileId/epoch, power-of-two sector size in `[512, 65536]`, zero flags, and the
complete private path snapshot are validated before any open.

### 10.4 Topology constants and admission

The SETUP topology constants are exact:

```text
MIN_RING_COUNT = 1                MAX_RING_COUNT = 64
MIN_SQ_CAPACITY = 8               MIN_CQ_CAPACITY = 2
MAX_SQ_CAPACITY = 65536           MAX_CQ_CAPACITY = 65536
MAX_INFLIGHT = 16777023           CONTROL_SQ_RESERVE_PER_RING = 4
MAX_SECTION_BYTES = 1073741824    MAX_RESERVE_RETRIES = 64
SYSTEM_REQUEST_SLOTS_PER_RING = 3 SYSTEM_REQID_BASE = 16777023
GLOBAL_EXTERNAL_CHANGE_ACK_REQID = 16777215
MAX_RETAINED_OPENS_PER_RING = 4096
MAX_RETAINED_OPENS_PER_MOUNT = 262144
MAX_RETAINED_OPENS_GLOBAL = 1048576
```

SQ and CQ capacities are powers of two in their stated ranges. `max_inflight`
is independently in `[1, MAX_INFLIGHT]`; entries are reusable after daemon
consumption, so it is not coupled to instantaneous SQ capacity. It counts only
application logical requests and uses exactly indices `[0, max_inflight)`; the
Section 8.1 partition reserves the system and global indices above it. The
lifecycle system ReqId is legal only for `REPLAY_OPEN`, recovery CLEANUP, and
recovery CLOSE; CLEANUP/CLOSE may use it only for a lifecycle transition
retained into BOUND_RECONCILING, and `REPLAY_OPEN` never uses an application
ReqId. A reserved/application range, opcode, ring, mount state, or
retained-phase mismatch is a protocol fault.

At least one K2U and one U2K slot class are active in every accepted
topology. Every multiplication, alignment, cumulative section offset,
ring-directory length, entry-region length, slot-arena length, view length,
64-KiB protection-extent padding, and conversion to `usize` is checked before
allocation. The final 64-KiB-aligned section is nonzero and at most
`MAX_SECTION_BYTES`. SETUP accepts the requested topology exactly or fails; it
never silently clamps capacities, and resource failure returns
INSUFFICIENT_RESOURCES without shrinking any accepted value.

### 10.5 Control classes and the SQ reserve

Each SQ has four physical control cells (`CONTROL_SQ_RESERVE_PER_RING = 4`)
that application semantic admission may never reserve or borrow; at most
`sq_capacity - 4` application semantic cells may be outstanding. The control
scheduler uses the reserve for five bounded logical classes:

1. a retained logical request's next phase or PCancel;
2. the serialized open-lifecycle recovery system slot;
3. `PT_ROUTE_ACK`;
4. `PT_EXTERNAL_SAFE_ACK`;
5. `EXTERNAL_CHANGE_ACK`, which uses the same four-cell reserve and its
   distinct global ReqId.

At most one wire phase owns each system slot. Application control work uses a
per-ring FIFO of length at most `max_inflight`; each retained application
state embeds one intrusive ready node. Open-lifecycle recovery uses a separate
per-ring FIFO whose length is at most `MAX_RETAINED_OPENS_PER_RING`; each
retained open embeds one lifecycle ready node, independent of whether it
currently owns an application slot. Enqueue, dequeue, and cancel/fence removal
are O(1), and each node may be on at most one matching FIFO. FIFO order is the
fairness order within a class. Strict round-robin across all five logical
classes selects a class whenever any control cell frees, then removes its head
waiter, before new semantic admission. No scheduler path scans the
retained-operation table. Because application producers cannot consume the
reserve, continuous application load cannot starve QueryOp/Ack/Cancel,
open-lifecycle recovery, PT, or external change acknowledgement. The minimum
SQ capacity leaves four ordinary cells in addition to the four physical
control cells; five logical classes do not require five simultaneous cells for
progress.

### 10.6 Control registries and output formulas

```text
GLOBAL_RING_INDEX = 0xffff_ffff

view_kind:
  INVALID=0, SECTION_READ_ONLY=1, SQ_CONSUMER_PAGE=2,
  CQ_ENTRIES=3, CQ_PRODUCER_PAGE=4, U2K_ARENA=5
view_access:
  INVALID=0, READ_ONLY=1, READ_WRITE=2

enter_request_flags:
  DRAIN_CQ=0x0000_0001, WAIT_SQ=0x0000_0002
enter_result_flags:
  SQ_READY=0x0000_0001, CQ_REMAINING=0x0000_0002,
  TIMED_OUT=0x0000_0004, NOTIFY_BLOCKED=0x0000_0008,
  CQ_CONTENDED=0x0000_0010
retire_mount_action:
  QUERY=1, ACK=2
retire_mount_state:
  ABSENT=1, ACTIVE=2, GRACE=3, TERMINAL=4, BOUND_RECONCILING=5
```

SETUP, SessionResult, Attach, Detach, both donation types, RetireMount, and
every currently unassigned control flag mask are zero. Unknown bits and
INVALID enum values fail. Whole-section and U2K views use `GLOBAL_RING_INDEX`;
ring-local views and credits require an exact ring index. View access is
READ_ONLY for SECTION_READ_ONLY and READ_WRITE for the four alias kinds.

`SessionResultV1.views_offset` is 136, `view_desc_size` is 32, and
`view_count = 2 + 3 * ring_count`. The order is the whole-section view, three
aliases for each increasing ring index (SQ consumer page, CQ entries, CQ
producer page), then the U2K arena. A valid session has nonzero
64-KiB-aligned `GlobalHeader.k2u_slots` and `u2k_slots`; the last view
describes exactly the latter. A zero arena descriptor is legal only in a
zeroed, unpublished construction/teardown object, never in an advertised
GlobalHeader. `notification_credits_offset` is exactly
`136 + view_count * 32`; `notification_credit_desc_size` is 32; and
`struct_size = 136 + view_count * 32 + credit_count * 32`.

For `EnterResultV1`, `notification_credits_offset` is 48 when the credit
count is nonzero and zero otherwise, the descriptor size is 32, and
`struct_size = 48 + credit_count * 32`. Every count/product/sum is checked and
the total is at most the caller's output length and `u32::MAX`. SETUP and
ATTACH calculate and validate their entire output size before creating a view
or grant; insufficient output has no externally visible side effect. After
snapshotting input, a successful call zeroes the whole returned range, fills
exactly `header.struct_size` bytes, and sets `IoStatus.Information` to that
size.

### 10.7 SETUP staging and view mapping

SETUP runs at PASSIVE_LEVEL on a restricted control handle and binds the
mount to the authorized daemon `EPROCESS`, `MountId`, and new
`session_epoch = 1`. It validates the ABI 2.1 identity and minor range of
Section 1.1, the feature/capability rules of Section 1.2, the requested
topology against Section 10.4, and every per-volume cap, then allocates a
fresh zeroed section, pages, slot arenas, request table, mapping table, and
one ring-bound wake object per ring, constructs and re-validates all
descriptors with checked arithmetic, and maps only the minimum daemon views of
Section 4.

There is no SETUP confirmation ENTER. SETUP preconstructs the complete
output, section, views, mappings, grants, file binding, and routable volume
while its restart slot (if any) is STAGING. Its single success publication
Release-transitions STAGING to LIVE only after every fallible step and output
byte is ready, and before I/O manager completion. Before that CAS there is no
visible volume, producer authority, or filesystem I/O; rollback is complete
and every pre-LIVE error reverses unpublished routing, grants, mappings, and
objects in reverse order. After it, cleanup or a lost SETUP response must
follow fence/GRACE/terminal retirement and may not free the slot directly. A
second SETUP on an already initialized handle fails deterministically.
Cancellation before the LIVE commit returns CANCELLED with zero output; after
commit it cannot change the successful result.

Every view offset is 64-KiB-aligned, every view length is page-aligned, lies
inside the section, and has the minimum rights. Section-size construction
uses checked 64-KiB align-up before every separately protected alias, charges
all zero padding against `MAX_SECTION_BYTES`, and rejects rather than
coalesces protection extents. Modern builds use no-write/no-execute MDL
protections where available. The Windows 7 profile uses `ZwMapViewOfSection`
with the exact already-64-KiB-aligned `SectionOffset`, requires that offset
not to be adjusted, requests only PAGE_READONLY or PAGE_READWRITE, and uses
`ViewUnmap`, so a child process cannot inherit a producer mapping; it never
relies on the DDI's round-down behavior. Win7 and modern profiles expose the
same logical regions and zero padding bytes.

### 10.8 Feature selection and the dedicated service-SID predicate

Selecting `HOT_RESTART` requires the SETUP caller's primary token to contain
exactly one enabled, non-deny-only dedicated Windows service SID. The
predicate is byte-exact: SID revision 1, `SECURITY_NT_AUTHORITY` (5),
subauthority count 6, and subauthority 0 equal to
`SECURITY_SERVICE_ID_BASE_RID` (80), giving `S-1-5-80-a-b-c-d-e`. The generic
`S-1-5-80-0` (`NT SERVICE\ALL SERVICES`, count 2) and every other `S-1-5-80-*`
shape are excluded rather than counted. Exactly one token group must satisfy
the predicate with `SE_GROUP_ENABLED` set and `SE_GROUP_USE_FOR_DENY_ONLY`
clear. This identical parser/predicate is used by SETUP, ATTACH, RETIRE_MOUNT
QUERY/ACK, inventory selection, and post-removal HMAC verification; there is
no string conversion and no alternate user, LocalSystem, or Administrators
allow path.

The dedicated form has exact `RtlLengthSid = 32`. The kernel stores those 32
bytes and builds a non-exported mount-attach descriptor granting attach only
to that SID. If the predicate does not yield exactly one SID, the runtime mask
clears the `HOT_RESTART`/`EXACTLY_ONCE` pair and requiring the pair fails
ACCESS_DENIED. `FSRING_MOUNT_CONTROL = 0x00000001` is the only access bit. The
descriptor has LocalSystem owner/group, a present protected DACL with exactly
one ACCESS_ALLOWED_ACE granting that bit to the stored dedicated SID, and no
SACL; its four-entry `GENERIC_MAPPING` is all zero and generic desired bits
are invalid. For each decision the driver captures the requestor process
`EPROCESS`, calls `SeCaptureSubjectContextEx(NULL, process, ...)`, locks the
subject context, parses only its primary token groups with the exact predicate
above, and calls `SeAccessCheck(..., UserMode, FSRING_MOUNT_CONTROL, ...)`.
Thread impersonation is ignored.

`journal_version` is paired with the restart features: ATTACH accepts
`journal_version` 1 exactly when `HOT_RESTART` and `EXACTLY_ONCE` are
selected; otherwise it requires 0. The kernel never silently adds the
dependency; unequal restart-pair bits in the offered, required, or selected
set fail INVALID_PARAMETER, and requiring the pair without the SID
prerequisite fails ACCESS_DENIED. ATTACH also requires the exact `MountId`,
prior epoch equal to the retained current epoch, requested features equal to
the retained selected set, and zero flags. Setup starts `session_epoch = 1`;
each successful ATTACH publishes exactly `old + 1`, and epoch exhaustion
terminalizes the mount instead of wrapping. `MountId` is routing, not
authentication. Successful ATTACH returns a fresh `SessionResultV1`; old
views and tokens remain invalid.

### 10.9 GRACE deadline

`RESTART_GRACE_TIMEOUT_MS = 30000` is fixed in ABI 2.1 and is not daemon- or
registry-configurable. Entering GRACE snapshots checked
`KeQueryUnbiasedInterruptTime() + 300000000` (100-ns units), so
sleep/hibernate does not consume restart time and wall-clock changes cannot
extend it. A timer only schedules the PASSIVE lifecycle owner; the owner and
every QUERY/ATTACH/reconciliation entry recheck the same absolute deadline
under the lifecycle gate. ATTACH must win its epoch/binding commit before that
deadline, and the same original deadline remains armed while the new epoch is
BOUND_RECONCILING. The IOCTL may return its mappings after that commit because
the daemon needs them to reconcile; its SUCCESS means "bound", not "ordinary
I/O admitted". All open, PT, and external barriers must complete before the
deadline for the atomic transition to ACTIVE. Expiry terminalizes the
already-bound epoch through the one terminal-owner path; it is never an IOCTL
timeout and no completion after expiry can reactivate the mount.

The retained-open caps of Section 10.4 make reconciliation work finite: at
most 4096 open-lifecycle nodes are queued on one ring and rings service those
queues in parallel. The kernel scheduler contributes no sleep or table scan
between a freed control cell and the next ready lifecycle phase. This is a
resource and deadlock bound, not a promise that an untrusted or stalled
provider will answer all phases within 30 seconds; failure takes the safe
expiry path rather than extending the deadline or exposing ordinary I/O.

### 10.10 The permanent BootContext section

Same-boot restart retirement uses this exact permanent format:

```text
BOOT_CONTEXT_SECTION_BYTES = 65536
BOOT_CONTEXT_HEADER_BYTES  = 256
BOOT_CONTEXT_SLOT_BYTES    = 256
BOOT_CONTEXT_SLOT_COUNT    = 64
BOOT_CONTEXT_USED_BYTES    = 16640
BOOT_CONTEXT_MAGIC         = 0x4342474e49525346   // "FSRINGBC" LE
BOOT_CONTEXT_VERSION       = 1

BootContextHeaderV1: 256/64
  +0   magic:u64
  +8   format_version:u32
  +12  header_size:u32
  +16  context_size:u32
  +20  slot_size:u32
  +24  slot_count:u32
  +28  init_state:u32        // EMPTY=0, INITIALIZING=1, READY=2
  +32  flags:u32
  +36  reserved0:u32
  +40  header_sequence:u64
  +48  mount_sequence:u64
  +56  mount_sequence_complement:u64
  +64  load_generation:u64
  +72  load_generation_complement:u64
  +80  boot_instance_id:BootInstanceId
  +96  per_boot_retire_key:[u8; 32]
  +128 digest:[u8; 32]
  +160 reserved:[u8; 96]

BootContextSlotV1: 256/64
  +0   sequence:u64
  +8   state:u32             // FREE=0, STAGING=1, LIVE=2,
                             // TERMINALIZING=3, TERMINAL=4
  +12  service_sid_length:u32
  +16  load_generation:u64
  +24  mount_sequence:u64
  +32  mount_id:MountId
  +48  boot_instance_id:BootInstanceId
  +64  latest_session_epoch:u64
  +72  selected_features:FeatureSet
  +88  journal_version:u32
  +92  flags:u32
  +96  service_sid:[u8; 68]
  +164 reserved:[u8; 60]
  +224 digest:[u8; 32]
```

Header/slot alignment is section-relative. Bytes `[16640, 65536)` are
immutable zero. Every READY reserved/flag byte is zero.
STAGING/LIVE/TERMINALIZING/TERMINAL slots require `service_sid_length = 32`, a
valid dedicated SID, and zero bytes 128-163 after it; FREE requires length and
all 68 SID bytes zero. Complements equal `value ^ u64::MAX`. BootInstanceId,
key, counters, live IDs, epochs, and selected restart-pair bits are nonzero
where their state requires them. A FREE slot has zero bytes 8-223 except
`state = 0` and has a valid sequence/digest. All 64 slots are initialized this
way before READY is published. Every non-FREE slot has `boot_instance_id`
exactly equal to the header identity and `mount_id.lo` exactly equal to that
slot's burned `mount_sequence`; `mount_id.hi` is nonzero. A STAGING slot
additionally has `load_generation` exactly equal to the current header
generation; LIVE, TERMINALIZING, and TERMINAL retain the generation in which
the slot most recently became LIVE, and no reader accepts an impossible
future generation.

The header digest is `SHA256("FSRING-BOOT-HEADER-v1\0" || header[0..256])`;
the slot digest is
`SHA256("FSRING-BOOT-SLOT-v1\0" || slot_index_le:u32 || slot[0..256])`. For
hashing, the digest field is zero and the sequence field contains the final
even value. Initial READY header and slot sequences are exactly 2.

Sequence and every other naturally aligned 64-bit word of each 256-byte
record are accessed atomically; concurrent ordinary, volatile, or mixed-width
accesses are forbidden. A writer owning the named BootContext lock event
constructs the complete final record privately with sequence `s + 2`, zeroes
the digest
field while hashing, and computes the final digest. After validating even `s`
and `s <= u64::MAX - 2`, it atomically stores `s + 1` (odd), executes the
full compiler-and-processor `KeMemoryBarrier`, Relaxed-atomically stores every
non-sequence 64-bit word, and Release-stores `s + 2` (even).
`KeMemoryBarrierWithoutFence` is insufficient. A reader Acquire-loads
sequence `a`; zero or odd retries. It Relaxed-atomically copies every
non-sequence 64-bit word into private storage, executes `KeMemoryBarrier`,
then Acquire-loads sequence `b`. It validates the private image only when
`a == b`, `b != 0`, and `b` is even; otherwise it discards the copy and
retries. The accepted private image uses `b` as its sequence before digest
and invariant validation. Sequence, mount counter, and load generation never
wrap; exhaustion fails closed with STATUS_INTEGER_OVERFLOW. There is no
in-place repair of a plausible but invalid identity or key.

Sequence-space admission reserves every mandatory future persistent state. A
FREE slot is eligible for SETUP only if five `+2` publications remain
(STAGING, LIVE, TERMINALIZING, TERMINAL, FREE); a LIVE slot is eligible for
ATTACH only if four remain (new-epoch LIVE plus the final three). Startup's
direct LIVE-to-TERMINAL conversion requires two remaining publications
including eventual FREE; a header writer requires one. Ordinary failure paths
may consume fewer, but never lend the reserved final publications to another
attach. If free slots exist but none has the required sequence space, SETUP
returns INTEGER_OVERFLOW; ATTACH instead terminalizes while its reserved path
is still writable and returns INVALID_DEVICE_STATE. Thus even theoretical
counter exhaustion cannot strand a LIVE slot in a state that cannot be
retired.

The exact permanent names are `\KernelObjects\FsRingBootContext-v1` and
`\KernelObjects\FsRingBootContextLock-v1`. Both use
`OBJ_KERNEL_HANDLE | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE`; `OBJ_OPENIF` is
forbidden. The canonical security descriptor has LocalSystem owner/group, a
present, protected, non-null empty DACL (`AclSize = sizeof(ACL)`,
`AceCount = 0`), and no SACL, so no user-mode principal can open or map either
object. After typed object reference, the driver obtains each complete security
descriptor with `ObGetObjectSecurity`, validates the owner/group/protected-
empty-DACL/no-SACL contract, and always pairs the result with
`ObReleaseObjectSecurity`. It does not use `ZwQuerySecurityObject` for this
validation and does not add `ACCESS_SYSTEM_SECURITY` to either handle mask.

The lock object is exactly a permanent named `SynchronizationEvent`, never a
mutant or semaphore. Its desired access is exactly `EVENT_QUERY_STATE |
EVENT_MODIFY_STATE | SYNCHRONIZE | READ_CONTROL | DELETE = 0x00130003`. The
driver first calls `ZwOpenEvent`; only exact `STATUS_OBJECT_NAME_NOT_FOUND`
permits `ZwCreateEvent(..., SynchronizationEvent, TRUE)`. Only exact
`STATUS_OBJECT_NAME_COLLISION` from that create permits a reopen. Every other
open or create status fails unchanged. The event handle is referenced with
`ObReferenceObjectByHandle(..., *ExEventObjectType, KernelMode, ...)` before
use.

Acquisition is at PASSIVE_LEVEL and outside every mount/session/FCB lock. The
driver enters a critical region and waits with `KeWaitForSingleObject` in
`KernelMode`, non-alertably, using a fixed relative 30-second timeout
(`-300000000` 100-nanosecond units); exact `STATUS_SUCCESS` is the only
accepted wait result. A failed or timed-out wait leaves the critical region,
does not set the event, and fails closed. After a successful wait,
`KeReadStateEvent` must be zero; a nonzero state rejects a same-name
`NotificationEvent` collision without claiming ownership. The successful path
returns one affine guard that prohibits recursive acquisition and on release
calls `KeSetEvent(..., IO_NO_INCREMENT, FALSE)` exactly once, requires its
prior-state result to be zero, and then leaves the critical region. No path
steals or force-sets a timed-out event, and no path claims mutant-style
abandonment recovery. Ordinary failure and clean-unload paths release through
the same typed rollback before dereferencing or closing the event.

The BootContext section has exact desired access `SECTION_QUERY |
SECTION_MAP_READ | SECTION_MAP_WRITE | READ_CONTROL | DELETE` (never
`SECTION_MAP_EXECUTE`) and is referenced with
`ObReferenceObjectByHandle(..., *MmSectionObjectType, KernelMode, ...)`. It is
pagefile-backed (`FileHandle = NULL`), exactly 65536 bytes, `SEC_COMMIT`, and
`PAGE_READWRITE`; only kernel views are created.

For an existing section, the driver uses
`ZwQuerySection(SectionBasicInformation)` to require `MaximumSize = 65536` and
allocation attributes exactly `SEC_COMMIT`. Every kernel view is explicitly
requested PAGE_READONLY or PAGE_READWRITE and no executable mapping is ever
requested. The typed object and complete security-descriptor checks precede
content mapping. A type, size, attributes, descriptor, format,
sequence, digest, or invariant mismatch fails DriverEntry closed; because
every SessionResult uses this boot identity, a corrupt context is never
bypassed by a volatile identity or treated as a new context. A newly created
all-zero section is marked INITIALIZING, filled with kernel-mode CSPRNG
nonzero BootInstanceId/key, and finally Release-published with exactly
`header_sequence = 2`, `mount_sequence = 0`,
`mount_sequence_complement = 0xffffffffffffffff`, `load_generation = 1`,
`load_generation_complement = 0xfffffffffffffffe`, `init_state = READY`, and
zero flags/reserved/tail; every FREE slot has `sequence = 2` and bytes 8-223
zero. Any ordinary initializer failure before READY calls
`ZwMakeTemporaryObject` on that newly created section and closes its last
handle. An existing EMPTY/INITIALIZING section, an interrupted initializer, a
failed/timed-out lock-event wait, or a lock-event subtype mismatch is
fail-closed and is not reinitialized. The event has no abandonment result.
Closing
driver handles and ordinary unload never make a READY object temporary; thus
reload, S4, and Fast Startup retain the same context, and only a new Object
Manager boot namespace creates a new identity.

Creation and first READY publication are load generation 1. On each later
successful driver load of an existing READY context, while owning the
BootContext lock-event guard, the driver increments `load_generation`, changes
old-generation STAGING slots to FREE, and completes old-generation LIVE or
TERMINALIZING slots to TERMINAL; TERMINAL remains. It then publishes the header
digest/generation before admitting control opens. Only an authenticated
SessionResult or RetireMountResult establishes `BootInstanceId`; time, uptime,
PID, service restart, or driver reload is never reboot evidence.

### 10.11 Restart slots, volatile mounts, and DETACH arbitration

The BootContext identity and MountId counter are used by every session; the
permanent slot/tombstone/receipt protocol is scoped exactly to sessions that
selected the inseparable `HOT_RESTART`+`EXACTLY_ONCE` pair. Such a SETUP first
finds a FREE slot, then burns the next mount sequence even if later staging
fails, sets `MountId.lo = mount_sequence`, and generates a nonzero random
`MountId.hi`. It publishes STAGING with the exact dedicated SID, features,
journal version 1, and epoch 1. If no FREE slot exists it returns
INSUFFICIENT_RESOURCES without burning a sequence. Any prepublication error
returns that slot to FREE but never reuses the burned MountId.

Sessions without the restart pair burn the same permanent nonwrapping MountId
counter under the BootContext lock-event guard and use the current
BootInstanceId, but reserve no slot, capture no retirement SID, create no
durable provider root, and never use RETIRE_MOUNT. Their MountId is `lo = burned_sequence,
hi = nonzero_random`, so reload cannot impersonate reboot or reuse an ID.
Daemon loss, clean DETACH, protocol abort, unload, or grace-ineligible
teardown closes admission, drains all IRPs/mappings/PT/users, and directly
destroys the mount. Nothing survives for ATTACH; any purported durable row
for such a mount is an SDK error. While such a volatile MountId is still
present in the in-memory mount table, ATTACH and both RETIRE_MOUNT actions
return NOT_SUPPORTED; after destruction an exact retirement query sees
ordinary ABSENT because no durable classification survives.

For a restart mount, clean DETACH, grace expiry, protocol abort, irreversible
teardown, and unload contend on one lifecycle terminal-owner CAS. Persistent
LIVE covers in-memory ACTIVE, BOUND_RECONCILING, and GRACE. A valid DETACH
first acquires the mount's cancel-safe exclusive lifecycle-admission gate;
cancellation can win only before that acquisition and returns CANCELLED. The
exclusive gate closes all new filesystem/journal/ACK admission and makes the
exact retained-blocker count stable. If the count is nonzero, DETACH reopens
admission without a visibility gap and returns DEVICE_BUSY. Otherwise it
atomically claims the terminal owner and changes restart LIVE to
TERMINALIZING (or volatile ACTIVE to DETACHING) while the gate remains
closed. No post-check operation can appear.

After that linearization DETACH is noncancelable and must drain all
mappings/PT/IRPs/users and publish TERMINAL or complete volatile destruction;
it then returns SUCCESS. A DETACH that observes another terminal owner or
TERMINALIZING/DETACHING returns DEVICE_BUSY; one that observes
BOUND_RECONCILING returns DEVICE_BUSY without disturbing its retained
deadline or barriers; and one that observes TERMINAL, GRACE, or a noncurrent
epoch returns INVALID_DEVICE_STATE. Two concurrent valid calls therefore have
exactly one SUCCESS winner. Only authenticated retirement ACK changes a
restart slot TERMINAL to FREE; a MountId is never reused within its
BootInstanceId.

### 10.12 RETIRE_MOUNT QUERY and ACK

RETIRE_MOUNT is legal only on a fresh unbound root control handle. QUERY
requires `action = QUERY`, zero proof token/reserved, and output capacity
exactly 96. A nonzero input MountId is an exact state query. Authorization
always requires both primary-token membership and `SeAccessCheck` against the
exact one-SID descriptor (stored for a found slot, reconstructed from the
validated caller SID for ABSENT). After both checks it returns ACTIVE,
BOUND_RECONCILING, GRACE, or TERMINAL for a matching owned slot, and ABSENT
when no slot has that ID. An ID owned by a different SID is ACCESS_DENIED,
while STAGING or TERMINALIZING is DEVICE_BUSY. A zero MountId is recovery
inventory: among slots owned by the caller SID it selects the
lowest-mount-sequence GRACE slot, otherwise the lowest TERMINAL slot; it
never returns ACTIVE or BOUND_RECONCILING. With no candidate it returns
ABSENT and a zero result MountId. This ordering is stable until the caller
attaches, terminalizes, or retires the selected slot, so repeated scans
cannot skip an orphan.

ACTIVE/BOUND_RECONCILING/GRACE/TERMINAL results contain the exact retained
latest epoch, selected features, and journal version; ABSENT has those fields
zero. Every successful result, including ABSENT, returns the current nonzero
BootInstanceId. Result flags and reserved are zero. TERMINAL uses this proof
token:

```text
RetireToken = Truncate128(HMAC-SHA256(
  per_boot_retire_key,
  ASCII "FSRING-RETIRE-v2\0" ||
  BootInstanceId.lo_le || BootInstanceId.hi_le ||
  MountId.lo_le || MountId.hi_le ||
  service_sid_length_le:u32 || canonical_binary_service_sid))
```

Every other state uses:

```text
StateToken = Truncate128(HMAC-SHA256(
  per_boot_retire_key,
  ASCII "FSRING-MOUNT-STATE-v2\0" ||
  BootInstanceId.lo_le || BootInstanceId.hi_le ||
  result_MountId.lo_le || result_MountId.hi_le ||
  mount_state_le:u16 || zero_flags_le:u16 ||
  latest_session_epoch_le:u64 ||
  selected_features.lo_le || selected_features.hi_le ||
  journal_version_le:u32 ||
  service_sid_length_le:u32 || canonical_binary_service_sid))
```

For ABSENT, `result_MountId` is the requested nonzero ID or zero for
inventory, and the caller's validated dedicated SID is used. HMAC input
requires exact `RtlLengthSid = 32`; the remaining 36 bytes of each fixed SID
buffer are zero. The first 16 digest bytes are lo then hi in little-endian
order. The `per_boot_retire_key` never leaves the BootContext section.
StateToken is evidence for a provider audit but is never accepted as an ACK
token.

ACK requires nonzero MountId, `action = ACK`, zero reserved, no output, and
the exact RetireToken. While the tombstone exists the caller SID must match
it. After removal, the caller must again have exactly one dedicated SID and
the kernel reconstructs the exact one-SID descriptor; both membership and
`SeAccessCheck` must succeed before it recomputes the HMAC from that
SID/current BootInstanceId. Constant-time equality makes an exact
lost-response ACK idempotently successful without making the receipt a bearer
token. Bad action/zero/token shape is INVALID_PARAMETER; SID/access mismatch
or any well-shaped nonzero incorrect token is ACCESS_DENIED. Both the
tombstone-present and reconstructed post-removal paths compare the candidate
in constant time and return that same status, exposing no receipt-presence
oracle.

### 10.13 `ProviderMountRootV1` and the SDK durable transition table

The SDK durably stores one canonical `ProviderMountRootV1` value (160/8)
under the MountId ROOT key:

```text
ProviderMountRootV1: 160/8
  +0   version:u32               // exactly 1
  +4   state:u32                 // ACTIVE=1, RECOVERING=2, RETIRING=3
  +8   boot_instance_id:BootInstanceId
  +24  mount_id:MountId
  +40  latest_session_epoch:u64
  +48  selected_features:FeatureSet
  +64  journal_version:u32
  +68  service_sid_length:u32
  +72  service_sid:[u8; 68]      // zero-padded dedicated SID
  +140 reserved:[u8; 4]
  +144 latest_proof_token:RetireToken
```

Every ROOT transition is one serializable compare-and-swap transaction over
the complete canonical row, its two zero-valued bootstrap counters, all
corresponding accounting reservations, and the ordinary-byte/count totals.
The closed transition table is:

| Authenticated kernel observation | Required prior provider state | Atomic provider result |
|---|---|---|
| observed successful restart SETUP, exact ACTIVE | no MountId prefix or identical ROOT ACTIVE with both counters exactly zero | create or idempotently retain ROOT ACTIVE plus `VOLUME_COMMIT_COUNTER = 0` and `ORDINAL_COUNTER = 0` |
| inventory-discovered lost SETUP, exact GRACE | no MountId prefix, or matching ROOT ACTIVE/RECOVERING with both counters present | bootstrap if absent, otherwise refresh ROOT RECOVERING from the returned identity/epoch/StateToken |
| pre-ATTACH exact GRACE | matching ROOT ACTIVE or RECOVERING | ROOT RECOVERING with exactly the returned epoch/StateToken; an existing RECOVERING row may advance but never regress epoch |
| post-binding exact BOUND_RECONCILING | matching ROOT RECOVERING | refresh ROOT RECOVERING to exactly the bound epoch/StateToken |
| post-barrier exact ACTIVE | matching ROOT RECOVERING or identical ROOT ACTIVE | create or idempotently retain ROOT ACTIVE at exactly that epoch/StateToken |
| exact TERMINAL | matching ROOT ACTIVE or RECOVERING | ROOT RETIRING at exactly that epoch/RetireToken |
| exact TERMINAL retry | identical ROOT RETIRING | idempotently retain RETIRING and resume prefix deletion/receipt commit |
| inventory-discovered lost SETUP, exact TERMINAL | no MountId ordinary prefix and either no receipt or an identical `RECEIPT_PENDING_ACK` | atomically assert the complete ordinary prefix is empty and insert or idempotently retain the exact receipt using only receipt-reserved accounting; then execute the normal ACK/retry/receipt-delete protocol |

The absent-prefix bootstrap is legal only for the exact dedicated SID,
BootInstanceId, features, journal version, and MountId returned by the
successful SETUP handle or the zero-ID inventory GRACE result; an ordinary
exact ABSENT does not authorize it. Bootstrap requires that no child, index,
blob, reservation, or counter with that prefix exists. The empty-prefix
TERMINAL path is not ROOT bootstrap and creates neither ROOT, counter,
ordinary reservation, nor ordinary charge. Every other non-bootstrap
transition requires exact identity equality and nondecreasing epoch. A retry
of the same observed kernel state/epoch must repeat the identical proof
token; a table-authorized transition to a different kernel state at the same
epoch must replace it with the new state's exact StateToken, or with
RetireToken on TERMINAL. Any other same-state token change, epoch regression,
wrong proof for the observed state, unexpected counter absence, or unrelated
ROOT is corruption and no row changes.

Both initial SETUP and ATTACH start with the SDK's provider-side
ordinary-dispatch gate closed. After SETUP publishes LIVE/ACTIVE, the SDK
exact-queries ACTIVE and commits the absent-prefix ROOT/counter bootstrap
before it may consume, execute, or durably commit an ordinary SQE. After
ATTACH's last open/PT/external READY barrier, the kernel publishes ACTIVE and
may queue ordinary SQ work, but the same gate stays closed until the exact
ACTIVE query commits RECOVERING-to-ACTIVE. Recovery-system traffic is the
only traffic dispatchable before the applicable transaction. A crash before
either ROOT commit therefore has no ordinary provider side effect and the
kernel fences to GRACE. A SessionResult alone never supplies or synthesizes a
latest proof token; a lost ATTACH output is recovered by closing the unknown
mapping owner, waiting for BOUND_RECONCILING/ACTIVE to fence to GRACE,
exact-querying the new epoch, and attaching again. Exact ABSENT with matching
BootInstanceId/SID authorizes audited deletion of only an already existing
root; inventory ABSENT never authorizes bulk deletion because active/bound
mounts are intentionally omitted.

### 10.14 Durable key model and child kinds

Every ordinary recovery key begins with the exact 32-byte MountId range
prefix
`MountId.lo_le || MountId.hi_le || BootInstanceId.lo_le || BootInstanceId.hi_le`,
followed by `child_kind_le:u16` and that schema's minimally encoded identity
tail; `DURABLE_KEY_HEADER_BYTES = 34` and the maximum encoded key is
`DURABLE_KEY_MAX_BYTES = 90`. Every secondary index, blob chunk, and
reservation sidecar repeats this prefix; an unprefixed MountId reference is
corruption. The closed child kinds are:

```text
ROOT=1  ACCOUNTING_RESERVATION=2  OPEN=3  PREPARE=4
IMMUTABLE_REQUEST=6  COMMITTED_RESULT=7  JOURNAL=8
QUERY_DIR_SNAPSHOT=9  QUERY_DIR_ATTEMPT=10  QUERY_DIR_COOKIE=11
PT_EPOCH_INTENT=12  PT_EPOCH_COUNTER=13  PT_LANE=14
EXTERNAL_NOTIFY_OUTBOX=15  VOLUME_COMMIT_COUNTER=16  PREPARE_TX_INDEX=17
```

ROOT and VOLUME_COMMIT_COUNTER have no key tail. Unknown kinds are
corruption; a future kind is unusable until an ABI amendment adds its number
and retirement rule. Child kind 5 is explicitly unassigned in ABI 2.1: it is
not a durable replay record, and encountering it under a MountId prefix is
corruption. The later values remain fixed and are not renumbered.

Except for the fixed schemas called out below, a child value uses this one
canonical wrapper; it is never a database-native object serialization:

```text
DurableChildValueV1: 88/8 fixed prefix
  +0  header:ControlHeader          // struct_version = 1
  +8  value_kind:u16                // equals key child_kind
  +10 state:u16
  +12 flags:u32                     // zero
  +16 identity_digest:[u8; 32]      // SHA256(complete canonical key)
  +48 payload_digest:[u8; 32]       // SHA256(payload bytes), empty allowed
  +80 payload:BlobSlice             // absent or begins at 88, only tail
```

The wrapper `struct_size` includes its payload and zero eight-byte tail
padding. Every integer is little-endian and every stated key tail has exactly
the named fields with no delimiter, alignment gap, or remainder. This closed
table defines all ordinary key/value identities:

| Kind | Exact key tail | State and exact wrapper payload |
|---|---|---|
| ROOT | none | fixed `ProviderMountRootV1`, not wrapped |
| ACCOUNTING_RESERVATION | `target_key_digest:[u8;32]` | fixed 48-byte `AccountingReservationV1`, not wrapped |
| OPEN | `kernel_open_id:u64` | LIVE=1 or CLEANED=2; one `OpenRecoveryPayloadV1` |
| PREPARE | `OpId.lo:u64, OpId.hi:u64` | PREPARED=1; exactly one `PrepareRecoveryPayloadV1` |
| PREPARE_TX_INDEX | `TransactionId.lo:u64, TransactionId.hi:u64` | fixed `PrepareTxIndexValueV1`, not wrapped |
| IMMUTABLE_REQUEST | `OpId.lo:u64, OpId.hi:u64` | RETAINED=1; exact digest prefix plus semantic bytes |
| COMMITTED_RESULT | `OpId.lo:u64, OpId.hi:u64` | COMMITTED=1; exact canonical `CommittedResultV1` through its struct_size |
| JOURNAL | `OpId.lo:u64, OpId.hi:u64` | PREPARED=1 or COMMITTED=2; exactly `JournalStateV1` |
| QUERY_DIR_SNAPSHOT | `kernel_open_id:u64, generation:u64` | ACTIVE=1; exactly `QueryDirSnapshotPayloadV1` |
| QUERY_DIR_ATTEMPT | `kernel_open_id:u64, generation:u64, input_cookie:u64, attempt_digest:[u8;32]` | ACCEPTED=1; exact canonical `QueryDirResultV1` bytes |
| QUERY_DIR_COOKIE | `kernel_open_id:u64, generation:u64, cookie:u64` | ACTIVE=1; exactly `QueryDirCookiePayloadV1` |
| PT_EPOCH_INTENT | `FileId.lo:u64, FileId.hi:u64, pt_epoch:u64` | PENDING=1, ACCEPTED=2, or REVOKED=3; exactly `PtEpochIntentPayloadV1` |
| PT_EPOCH_COUNTER | `FileId.lo:u64, FileId.hi:u64` | one raw u64 last allocated epoch, not wrapped |
| PT_LANE | `ring_index:u8, kind_ordinal:u8` | PRESENT=1; exactly `PtLanePayloadV1` |
| EXTERNAL_NOTIFY_OUTBOX | closed subkind tail in Section 10.15 | fixed schemas, not wrapped |
| VOLUME_COMMIT_COUNTER | none | one raw u64 last allocated sequence, not wrapped |

`ring_index < ring_count` and the PT `kind_ordinal` is 1 or 2. Key
generations, cookies, epochs, OpIds, TransactionIds, and kernel-open IDs are
nonzero. The fixed payload prefixes are:

```text
OpenRecoveryPayloadV1: 152/8 fixed prefix
  +0   header:ControlHeader
  +8   file_id:FileId, +24 link_id:LinkId, +40 parent_id:FileId
  +56  sizes:SizeState
  +88  namespace_generation:u64, +96 security_generation:u64
  +104 kernel_open_id:u64
  +112 desired_access:u32, +116 granted_access:u32
  +120 share_access:u32, +124 create_options:u32
  +128 file_attributes:u32, +132 disposition:u32
  +136 name:BlobSlice, +144 security_descriptor:BlobSlice

PrepareRecoveryPayloadV1: 184/8 fixed prefix
  +0   header:ControlHeader
  +8   parent_id:FileId
  +24  transaction_id:TransactionId
  +40  result_file_id:FileId
  +56  result_link_id:LinkId
  +72  result_sizes:SizeState
  +104 result_namespace_generation:u64
  +112 result_security_generation:u64
  +120 desired_access:u32, +124 share_access:u32, +128 disposition:u32
  +132 create_options:u32, +136 file_attributes:u32, +140 open_flags:u32
  +144 result_object_flags:u32, +148 reserved:u32 = 0
  +152 name:BlobSlice, +160 requested_security_descriptor:BlobSlice
  +168 ea:BlobSlice, +176 result_security_descriptor:BlobSlice

PrepareTxIndexValueV1: 48/8
  +0  op_id:OpId
  +16 identity_digest:[u8; 32]     // SHA256(complete PREPARE_TX_INDEX key)

JournalStateV1: 64/8
  +0  header:ControlHeader
  +8  op_id:OpId
  +24 opcode:u16, +26 mutation_kind:u16, +28 state:u32
  +32 operation_digest:[u8; 32]

QueryDirSnapshotPayloadV1: 56/8 fixed prefix
  +0  header:ControlHeader
  +8  pattern_digest:[u8; 32]
  +40 entry_count:u64, +48 entries:BlobSlice

QueryDirCookiePayloadV1: 56/8
  +0  header:ControlHeader
  +8  next_cookie:u64, +16 result_flags:u32, +20 reserved:u32
  +24 attempt_digest:[u8; 32]

PtEpochIntentPayloadV1: 32/8 fixed prefix
  +0  header:ControlHeader
  +8  pt_epoch:u64, +16 sector_size:u32, +20 flags:u32
  +24 backing_path:BlobSlice

PtLanePayloadV1: 72/8 fixed prefix
  +0  header:ControlHeader
  +8  high_watermark:u64
  +16 latest_token:AckToken, +32 latest_file_id:FileId
  +48 latest_pt_epoch:u64
  +56 latest_notify_code:u16, +58 flags:u16, +60 reserved:u32
  +64 pending_envelope:BlobSlice
```

The OpenRecovery name/SD tail starts at byte 152 in that order.
PrepareRecovery's four tails begin at byte 184 in
name/requested-SD/EA/result-SD order with no gap; every slice is relative to
the payload start. Its request fields and variable bytes equal the exact
normalized Prepare semantic input, its result fields/SD equal the exact
successful Prepare result, its TransactionId is nonzero, and the Section 9.6
identity/size/generation invariants apply. The PREPARE key OpId is the record
identity and is deliberately not duplicated in this payload; its nonzero
TransactionId is simultaneously inserted as the unique PREPARE_TX_INDEX key
targeting that OpId, and a collision with another OpId is corruption. The
record, index, both accounting reservations, and ordinary counters are
created and deleted in the same transaction on Prepare success, successful
Commit, Abort, or terminal prefix retirement, so neither lookup direction can
be orphaned. The QueryDir snapshot entry slice starts at 56 and contains
exactly `entry_count` canonical `DirEntryV1` records; PT intent/path and
lane/envelope begin immediately after their fixed prefix. Absent slices are
`{0, 0}` and create no gap. All flags and reserved fields are zero. Journal
`state` equals the wrapper state and its OpId equals the key. The PT lane's
latest fields are all zero only at watermark zero; its optional pending
envelope is the exact canonical notification through struct_size.

OpenRecovery is an immutable open-time audit/replay record: its disposition
is the exact normalized PREPARE disposition; its sizes, generations,
parent/name, security descriptor, and attributes are the successful COMMIT
snapshot and are never rewritten by later mutation, and those snapshot fields
are not reinstalled as current cache state on ATTACH. `REPLAY_OPEN` compares
its `kernel_open_id`, FileId, LinkId, desired access, share access, create
options, and disposition exactly with the durable OPEN row. The ReplayOpen
state-flags registry is closed:

```text
REPLAY_STATE_PAGING_ONLY = 0x0000000000000001
```

Zero flags require OPEN(LIVE) and restore ordinary-plus-stream authority;
their `ccb_sequence` is the kernel-authoritative, nonzero, nonwrapping
current CCB sequence, must equal the enclosing SQE `ccb_sequence`, and may
stay equal or advance but never regress across epochs. `PAGING_ONLY` requires
OPEN(CLEANED), both replay and outer `ccb_sequence` zero, and restores only
the kernel stream paging/cache authority; it can never authorize a user/CCB
request. Same-epoch duplicates must repeat the complete mode-specific
projection exactly. Unknown/composed flags, a row-state/mode mismatch,
changed disposition, or sequence mismatch is a protocol fault.

`MAX_RETAINED_PREPARE_BYTES_PER_MOUNT = 67108864`. Before Prepare SQ
publication, kernel admission charges the name, requested SD, EA, fixed
request/result state, and a full 65536-byte kernel-transient reserve for the
variable successful result SD. The provider computes the final PREPARE plus
PREPARE_TX_INDEX rows/reservations charge from its exact constructed result
and atomically admits only that exact durable charge while creating both
rows; there is no provider-durable 64-KiB placeholder. The PREPARE row's
zero-tail fixed charge is 392 bytes and its exact charge is
`392 + align8(name_bytes + requested_sd_bytes + ea_bytes + result_sd_bytes)`.

### 10.15 Durable accounting and the external-notify metadata rows

An ACCOUNTING_RESERVATION key tail is exactly the 32-byte SHA-256 of its
target canonical key. Its value is the fixed `AccountingReservationV1`:

```text
AccountingReservationV1: 48/8
  +0  target_child_kind:u16, +2 flags:u16 = 0
  +4  target_key_length:u32
  +8  charged_bytes:u64
  +16 target_key_digest:[u8; 32]
```

The atomic admission charges both target and reservation row; the reservation
itself never creates another reservation, preventing recursive accounting.
Durable accounting is a protocol invariant, not a check-then-write
convention:

```text
MAX_DURABLE_RECOVERY_BYTES_GLOBAL             = 4294967296
DURABLE_RECORD_ACCOUNTING_OVERHEAD            = 64
RETIRE_RECEIPT_CHARGE_BYTES                   = 128
RETIRE_RECEIPT_RESERVED_BYTES                 = 8192
MAX_DURABLE_RETIRE_RECEIPTS                   = 64
MAX_DURABLE_ORDINARY_BYTES_GLOBAL             = 4294959104
MAX_DURABLE_QUERY_DIR_SNAPSHOTS_PER_OPEN      = 1
MAX_DURABLE_QUERY_DIR_SNAPSHOT_BYTES_PER_OPEN = 67108864
MAX_DURABLE_QUERY_DIR_BYTES_PER_MOUNT         = 268435456
```

Every record charge is
`align8(canonical_key_bytes + canonical_value_bytes) + 64`, checked for
overflow, and increments only ordinary counters. The receipt table key is
exactly MountId 16 followed by BootInstanceId 16; its 32-byte value is
RetireToken 16, `state:u32` (`RECEIPT_PENDING_ACK = 1`), and twelve zero
reserved bytes, so `align8(32 + 32) + 64 = 128` exactly. Accounting always
satisfies all of these equations:

```text
0 <= ordinary_charged_bytes
ordinary_charged_bytes <= 4294967296 - 8192
receipt_count <= 64
receipt_actual_bytes = receipt_count * 128
receipt_actual_bytes <= 8192
ordinary_charged_bytes + receipt_actual_bytes <= 4294967296
```

The 8192-byte reserve is not pre-added to either counter and a receipt is
never also charged as an ordinary row. Unused receipt capacity is not
lendable. Golden fixed-row charges are normative: ROOT `34+160 -> 264`,
reservation `66+48 -> 184`, maximum precise external row `44+1256 -> 1368`,
external OVERFLOW row `44+232 -> 344`, LATEST_PROCESSED `36+56 -> 160`, each
raw-u64 ORDINAL_COUNTER or VOLUME_COMMIT_COUNTER (`36+8` or `34+8`) `-> 112`,
ATTACH_CUT `44+8 -> 120`, the zero-tail PREPARE row `50+(88+184) -> 392`, and
the fixed PREPARE_TX_INDEX `50+48 -> 168`.

For every create, resize, or delete, the checked global and applicable
per-mount counter update, a durable reservation keyed by the record key, the
canonical record mutation, and any corresponding filesystem effect occur in
one serializable durable transaction. Idempotent retries find the same
reservation; they neither double-charge nor double-refund. Startup takes an
exclusive accounting gate, scans all canonical records and reservations,
recomputes counters, repairs only exact derivable counter differences in one
transaction, and admits no mount or work until the audit commits. An orphan,
duplicate key, impossible charge, or total above either bound fails closed
for operator repair. After an authenticated result exposes a different
BootInstanceId, prior-boot rows and receipts may be pruned in one audited
transaction; within the same BootInstanceId, including a driver reload,
reboot inference is forbidden and no timeout or failed ATTACH alone
authorizes pruning.

`VOLUME_COMMIT_COUNTER` and the `EXTERNAL_NOTIFY_OUTBOX` ORDINAL_COUNTER are
both materialized as charged zero-valued rows in the ROOT-creation
transaction; an existing ROOT with either counter absent is corruption, never
an implicit zero. Only a backing-state commit in the closed volume-sequenced
registry — successful COMMIT_OPEN, WRITE, MUTATE, or an external filesystem
transaction represented by DIR_CHANGE/RESIZE — checks the volume counter
below `u64::MAX`, increments it exactly once, and stores the new value in the
same durable transaction as the backing effect and every result/outbox row
whose schema carries that sequence. Control metadata neither consumes a
volume sequence nor claims to encode one. Nonrestart mounts keep both
counters only in volatile mount state. The counters are
charged/reserved/audited normally and are deleted only by authenticated
retirement.

The `EXTERNAL_NOTIFY_OUTBOX` key tail has a closed `subkind_le:u16`:
`OUTBOX_ROW = 1` then `first_ordinal_le:u64`; `LATEST_PROCESSED = 2` with no
remainder; `ORDINAL_COUNTER = 3` with no remainder; or `ATTACH_CUT = 4` then
`session_epoch_le:u64`. A row value is exactly the canonical
`NotifyEnvelopeV2` bytes through its struct_size; session OControl/credit
coordinates are not stored. LATEST_PROCESSED is 56/8: first ordinal, through
ordinal, and volume commit sequence as three u64 values followed by the
32-byte semantic digest. ORDINAL_COUNTER is the last allocated ordinal as one
u64 and survives row acknowledgement so an ordinal is never reused.
ATTACH_CUT is one u64 cut value for the current reconciliation; Section 10.22
gives its serializable get-or-create transaction. LATEST_PROCESSED and
ORDINAL_COUNTER are deleted only by the retirement transaction.

Receipt insertion is atomic with either (a) deletion/refund of every ordinary
prefixed child/reservation plus a zero-residual assertion, or (b) the
authenticated empty-prefix TERMINAL assertion of Section 10.13. The same
transaction makes the ordinary/receipt counter changes, so a committed
`RECEIPT_PENDING_ACK` proves that the ordinary prefix is empty. An unknown
child type, orphan reservation, nonzero residual count, or mismatched
existing receipt aborts the whole transaction for operator repair. Only after
commit does the SDK send ACK, and it deletes the receipt only after observing
ACK SUCCESS; crash/lost responses retry harmlessly. A global provider
recovery gate drains every committed receipt before admitting startup mount
work and forbids every new restart SETUP while any receipt remains; the 64
kernel slots imply at most 64 live receipts and the fixed reserve is
sufficient.

### 10.16 The durable open lifecycle

Restart mounts have this closed durable OPEN lifecycle:

```text
ABSENT --successful COMMIT_OPEN--> LIVE
LIVE   --successful CLEANUP-----> CLEANED
CLEANED--successful CLOSE-------> ABSENT
```

For one live MountId the kernel allocates `kernel_open_id` from a per-mount
monotonically increasing nonzero u64 allocator. Allocation is linearized
before the first PREPARE_OPEN publication, may be burned by any later
abort/failure, and is never reused after failed create, CLEANUP, CLOSE, or
row deletion until mount retirement. Value `u64::MAX` may be issued once and
then permanently latches CREATE-local STATUS_INTEGER_OVERFLOW/zero before
PREPARE/COMMIT visibility; zero is never issued. A driver reload terminalizes
old-generation mounts rather than resuming their kernel opens. This nonreuse
invariant is what makes a possibly visible CLOSE finding complete ABSENT
unambiguous.

Every CREATE is assigned one immutable owning ring before PREPARE. Before its
COMMIT effect, admission reserves retained-open counts in fixed global,
mount, then owning-ring order against `MAX_RETAINED_OPENS_GLOBAL`,
`MAX_RETAINED_OPENS_PER_MOUNT`, and `MAX_RETAINED_OPENS_PER_RING`. Partial
failure rolls back in reverse order and returns the registered nonmutating
INSUFFICIENT_RESOURCES result; checked counter overflow is the same failure.
Successful COMMIT transfers that ticket to the kernel open plus durable OPEN
reservation. CLOSE/ABSENT terminal ownership or terminal mount retirement
refunds it exactly once; CLEANUP, fence, replay, and journal ACK do not.
Volatile nonrestart opens use the identical in-memory ticket without a
durable row. Thus the lifecycle FIFO is bounded by charged live opens, not by
`max_inflight`.

Successful COMMIT_OPEN computes and admits the exact canonical OPEN row,
OpenRecovery payload/tails, reservation, and accounting delta before any
effect, then creates OPEN(LIVE) in the same transaction as the filesystem
effect, journal PREPARED-to-COMMITTED bundle transition, volume sequence, and
PREPARE/PREPARE_TX_INDEX deletion. Quota failure is a registered nonmutating
Commit failure and leaves no OPEN row. Journal ACK later deletes only the
COMMITTED bundle; it never deletes OPEN.

CLEANUP consumes no volume sequence and is an idempotent row-state
transaction. From LIVE it performs all provider per-handle cleanup and
publishes CLEANED atomically before its success CQ; an exact CLEANED retry
repeats success without repeating the effect, and ABSENT, an unknown state,
or a mismatched payload is corruption. CLEANED retains the canonical recovery
payload and a volatile paging-only stream authority until CLOSE, but owns no
ordinary CCB authority: an ordinary zero-flag `REPLAY_OPEN` or user/CCB
request against CLEANED is a protocol fault, while
`REPLAY_OPEN(PAGING_ONLY)` and the closed kernel stream lane remain valid.
That closed lane admits only KernelMode paging READ/WRITE carrying the
paging-I/O stack flag and wire `rw_flags.PAGING`, or the trusted Cache
Manager AdvanceOnly adapter canonicalized to SET_VALID_DATA_LENGTH; its SQE
has the same nonzero `kernel_open_id` but outer `ccb_sequence = 0`. From
CLEANED, provider CLOSE atomically deletes/refunds the OPEN row/reservation
and paging-only volatile state, and publishes success only after commit;
reissuing a possibly visible CLOSE finds complete ABSENT and succeeds
idempotently, while LIVE or a one-sided row/reservation is corruption. ABSENT
authorizes no other deletion.

One kernel per-open state gate serializes `REPLAY_OPEN`, CLEANUP, and CLOSE,
and the provider uses the same per-open serialization domain for all three
opcodes and both replay modes; `REPLAY_OPEN` revalidates either
OPEN(LIVE)/zero flags or OPEN(CLEANED)/PAGING_ONLY immediately before
installing authority. Zero-flag replay after CLEANED, PAGING_ONLY replay
before CLEANED or after ABSENT, and every replay after complete ABSENT are
protocol faults without authority. LIVE and CLEANED rows are clean-DETACH
blockers; terminal prefix retirement removes either through the ordinary
receipt transaction. Recovery CLEANUP and recovery CLOSE use the reserved
per-ring lifecycle slot and allocate no new application slot; these retained
recovery publications are legal in BOUND_RECONCILING despite the ban on new
semantic requests. The kernel-internal
CLEANUP_PENDING/CLOSE_PENDING/DRAIN_REPLAY predecessor machinery, the
POST_CLEANUP_HELD stream hold, and the ATTACH open-barrier bookkeeping are
specified by the lifecycle documents; their wire-visible effects are
exactly the rules above.

### 10.17 ATTACH and BOUND_RECONCILING

Control-handle cleanup and process ownership, not an untrusted heartbeat
alone, detect daemon loss. The volume atomically leaves ACTIVE, quarantines
the old epoch, stops accepting old CQ/U2K writes, and enters GRACE or
teardown under Section 10.20's fence order.

ATTACH is valid only on the authenticated control path, only when the restart
pair was negotiated, and only in GRACE before its deadline. It pre-stages and
validates the complete fresh section, views, grants, and output before a
single atomic GRACE-to-ATTACHING winner; a loser returns DEVICE_BUSY and
destroys only its private staging. While ATTACHING, every
failure/cancellation before commit unmaps private views and restores the
exact same GRACE authorization/deadline/epoch. Its sole commit point, under
the lifecycle gate and BootContext lock-event guard, atomically persists
`latest_session_epoch = old + 1` in the slot, binds the new handle/views, and
Release-publishes BOUND_RECONCILING with the already complete output. After
that point cancellation loses, rollback to the old epoch is forbidden, and
the IOCTL returns SUCCESS; output loss or process cleanup fences the new
epoch normally.

Only authenticated recovery-system SQ/CQ traffic, exact
reissue/QueryOp/ABORT/ACK of an already-retained logical request,
DONATE_BACKING needed for PT rebuild, ENTER, QUERY, and lifecycle control are
admitted in BOUND_RECONCILING; every new native filesystem IRP is held in its
existing bounded queue or fails through the terminal owner, and no newly
admitted semantic SQE is published. Consumption of the last open/PT/external
READY barrier before the retained deadline atomically publishes ACTIVE and
opens kernel ordinary admission; the SDK ordinary-dispatch gate of Section
10.13 remains closed until the exact ACTIVE query and durable ROOT
transaction. ATTACH never remaps the old section into the new session and
never treats old ring bytes as replay authority: the kernel retains canonical
immutable request descriptors outside mapped memory, locked application MDLs
receive new mapping capabilities, slot data is copied to new slots, and
replay begins only after all new mappings and descriptors are valid. Stale
epochs, mapping tokens, slot tokens, and provider cookies are rejected.
`session_epoch` never wraps or repeats for a mount; if a fresh epoch cannot
be allocated, attach fails and the volume takes the controlled teardown path.

### 10.18 ENTER

ENTER is the daemon's authenticated kick/wait operation. It validates the
caller process, control-handle binding, mount, epoch, and bounded ring
selection on every call. ENTER has two independent, bounded per-ring roles:
one CQ-drain owner and one SQ-wait owner. `DRAIN_CQ | WAIT_SQ` is invalid; a
DRAIN call never waits and a WAIT call never consumes CQ. At most one call of
each role may be outstanding, so a second call for the same role returns
DEVICE_BUSY, while one pure WAIT and one pure DRAIN may run concurrently. A
zero-flag readiness poll uses the SQ role for its bounded execution. This
split is mandatory: a provider worker may publish an asynchronous CQ and
issue a DRAIN while the dedicated SQ waiter remains blocked, so no CQ
doorbell or cancel-before-completion convention is required.

Request flag `DRAIN_CQ` requires `1 <= cq_budget <= min(cq_capacity, 4096)`;
without `DRAIN_CQ`, `cq_budget` is zero. `timeout_ms = 0` polls,
`0xffffffff` waits indefinitely but cancel-safely, and every other value is a
relative millisecond timeout converted with checked arithmetic. `WAIT_SQ`
absent requires timeout zero. A DRAIN performs the requested bounded CQ drain
and then one SQ readiness poll before returning. A non-DRAIN call performs
one SQ readiness poll; `WAIT_SQ` waits only when that poll reports not ready.

`WAIT_SQ` is level-triggered and cannot use a bare poll-then-wait. Each ring
has a nonpaged manual-reset `sq_ready_event`, a private nonwrapping u64
`sq_publish_generation`, and the sole `sq_wait_owner`. After the SQ cell/tail
Release publication, every successful kernel SQ producer Release-increments
the generation and sets the event. The waiter snapshots the generation with
Acquire, polls readiness/terminal state, and, only if still empty/live,
clears the event; it then Acquire-reloads the generation and repeats the
SQ/terminal poll before entering its cancel-safe wait. Every wake loops
through the poll; readiness is never inferred from the event alone.
Cancellation, timeout, and fence compete through the ENTER terminal-owner
CAS, Release-publish their terminal state, and set the same event, so a
waiter cannot remain asleep after teardown. Only the SQ owner clears the
event; CQ-role readiness polls never do. The session is fenced before the
generation could increment past `u64::MAX`.

Before draining, ENTER derives its return-credit capacity as
`floor((OutputBufferLength - 48) / 32)`. Before consuming each NOTIFY it
reserves one tail descriptor. If none remains, the NOTIFY and its CQ head
stay untouched; ENTER succeeds with `CQ_REMAINING | NOTIFY_BLOCKED` and the
committed prefix/tail. Ordinary completions before it remain committed. If
the output cannot hold the 48-byte prefix, ENTER returns BUFFER_TOO_SMALL and
drains nothing. Cancellation before any drain/credit commit returns CANCELLED
and no output; after the first commit, ENTER completes success with the
committed result. Progress on every bounded validation retry that never
yields a stable record returns `CQ_CONTENDED`, not `CQ_REMAINING` and not a
false protocol fault; the SDK immediately retries a successful ENTER carrying
`CQ_CONTENDED` with bounded cooperative yielding, and the kernel never spins
without returning control.

Every successful ENTER zero-initializes and fills exactly
`48 + notification_credit_count * 32` bytes and sets both
`header.struct_size` and `IoStatus.Information` to that value. Its field/flag
invariants are:

- `sq_ready` is exactly 0 or 1, and `SQ_READY` is set iff it is 1;
- `cq_drained <= cq_budget`; without `DRAIN_CQ`, `cq_drained`, the
  returned-credit count, `CQ_REMAINING`, `NOTIFY_BLOCKED`, and `CQ_CONTENDED`
  are all zero;
- the returned-credit count equals the number of NOTIFY records included in
  `cq_drained`, and every descriptor is the refreshed credit for one such
  record;
- `CQ_REMAINING` is set iff a validated ready CQ record remains unconsumed;
- `NOTIFY_BLOCKED` implies `CQ_REMAINING` and the next unconsumed record is
  NOTIFY;
- `CQ_CONTENDED` means the bounded validator observed progress throughout and
  could not establish whether a record is ready; it is mutually exclusive
  with `CQ_REMAINING` and `NOTIFY_BLOCKED`;
- `TIMED_OUT` requires a pure `WAIT_SQ` role, `sq_ready = 0`, and an expired
  timeout, and is mutually exclusive with `SQ_READY`, `CQ_REMAINING`,
  `NOTIFY_BLOCKED`, and `CQ_CONTENDED`;
- without `WAIT_SQ`, `TIMED_OUT` is zero; ENTER still performs one SQ
  readiness poll before returning.

ENTER may perform bounded work to release SQ backpressure, holds no
thread-owned filesystem resource across a wait, and retains no pointer into a
daemon-writable entry after advancing that entry. Two threads never own the
same CQ consumer simultaneously.

### 10.19 DONATE_BACKING and PT backing admission

DONATE_BACKING is legal only on the current bound session with PT selected.
In ACTIVE it must propose the exact next PT epoch. In BOUND_RECONCILING it is
legal only for a retained PT rebuild barrier, and its FileId, epoch, path
bytes/digest, sector size, and flags must equal the durable PT intent being
recovered; it may not create a new backing relationship. Every other state or
tuple returns INVALID_DEVICE_STATE with no open.

Before any name open, the kernel parses the first device-root component and
requires an exact component-boundary match in a driver-owned local-volume
target table built from mounted local `FILE_DEVICE_DISK_FILE_SYSTEM` volumes;
user mode cannot insert or override an entry. `\Device\Mup`, UNC/DOS aliases,
unlisted roots, stale PnP generations, prefix-only matches, FSRING volumes,
and non-local targets fail before a create can enter such a stack. At
PASSIVE_LEVEL the driver opens the file with `IoCreateFileEx`,
`IO_FORCE_ACCESS_CHECK | IO_STOP_ON_SYMLINK`, a `DeviceObjectHint` for the
allowlisted volume, `ShareAccess = 0`, `FILE_OPEN`, and exactly
`FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING |
FILE_OPEN_REQUIRING_OPLOCK`; the returned handle is never inserted into or
duplicated to any user-mode handle table.

Donation requires proof of exclusive mutation control, not merely share
flags: one kernel-owned asynchronous `FSCTL_REQUEST_OPLOCK`
(`REQUEST_OPLOCK_CURRENT_VERSION`, REQUEST,
`CACHE_READ | CACHE_WRITE | CACHE_HANDLE`) where only STATUS_PENDING is a
grant, then, while the oplock is held and before PT acceptance, both
`MmDoesFileHaveUserWritableReferences(SectionObjectPointer) == FALSE` and
`MmCanFileBeTruncated(SectionObjectPointer, NULL) == TRUE`. Failure to prove
every condition drains through the lower completion owner, closes the kernel
handle, and accepts no epoch. The retained kernel handle/reference and oplock
request survive DONATE_BACKING IOCTL completion; the pending donation
activates only on a matching PT_GRANT.

For a restart-pair mount the provider allocates `pt_epoch` from a durable
nonwrapping per-MountId/FileId counter in the same transaction that records
`PT_EPOCH_INTENT`; gaps are legal. A nonrestart mount uses the identical
nonwrapping algorithm in session-local volatile provider state. The kernel
accepts a new donation only when `pt_epoch > last_accepted_epoch` and burns
that value when the fully isolated pending tuple is installed. An exact
same-session retry with `pt_epoch == last_accepted_epoch` and the identical
retained tuple returns SUCCESS without a second open/oplock or state change;
every other equal/lower value, or a greater value while a distinct tuple is
pending/live, is INVALID_DEVICE_STATE. Counter exhaustion permanently retires
PT for that file. Every session fence moves any pending/live accepted epoch
to fully revoked, destroys all grants/routes/backing references and the
oplock context before GRACE, and retains `last_accepted_epoch`; no PT route,
grant, backing, or raw handle crosses a session epoch.

Every lower status is translated before the IOCTL terminal-owner CAS; no raw
filesystem/device status escapes the closed registry of Section 10.23. The
total mapping is:

| Source outcome | DONATE_BACKING status |
|---|---|
| pre-open syntax/header/sector validation failure | INVALID_PARAMETER |
| caller/control authorization failure, or lower ACCESS_DENIED/PRIVILEGE_NOT_HELD | ACCESS_DENIED |
| current OPENING/ISOLATING/CANCEL_DRAINING, or canonical-path/FileObject exclusion conflict | DEVICE_BUSY |
| epoch/tuple/session-state violation not classified as an in-progress conflict | INVALID_DEVICE_STATE |
| NO_MEMORY, INSUFFICIENT_RESOURCES, INSUFFICIENT_QUOTA, MDL/IRP/context allocation failure | INSUFFICIENT_RESOURCES |
| NOT_SUPPORTED, NOT_IMPLEMENTED, INVALID_DEVICE_REQUEST from the target/oplock stack | NOT_SUPPORTED |
| lower CANCELLED when the IOCTL cancellation owner won | CANCELLED |
| every other non-success, including symlink stops, reparse encounters, oplock/sharing failures, name-not-found, type mismatches, device failures, and post-open validation vetoes | INVALID_DEVICE_STATE |

`MAX_OPENING_BACKING_ATTEMPTS_PER_MOUNT = 8` and
`MAX_OPENING_BACKING_ATTEMPTS_GLOBAL = 64` are charged before the path-table
insert; exhaustion returns INSUFFICIENT_RESOURCES with no create. The
per-file OPENING/ISOLATING/PENDING/ACTIVE/BREAKING_CLOSED/REVOKED state
machine, its cancellation edges, and the oplock-break drain contract are
specified by the passthrough documents; their wire-visible
surface is exactly this subsection.

### 10.20 Session fence and notify-fence disposition

A session fence has a closed old-CQ disposition before old views are
discarded. Its state transition atomically blocks new filesystem I/O and SQ
publication, closes ENTER admission on every ring, revokes the old daemon's
producer authority, and signals every outstanding ENTER to leave its wait.
Atomic per-ring `cq_enter_owner` and `sq_wait_owner` bits admit the two ENTER
roles. Only the CQ owner takes the ring's sole-CQ-consumer token, and that
physical token protects only cursor/credit operations: stable cell capture,
bounded private validation, semantic ownership installation, credit
claim/refresh or retirement, and CQ-head Release. It is never held while
acquiring an FCB/CCB/namespace/domain lock, running an access check or
notification callback, waiting for SQ, or completing an IRP.

If a captured record needs such work, the token owner first installs a
complete preallocated `DETACHED_HANDLER` descriptor and terminal owner under
the record's state gate, increments the mount/ring detached-handler rundown,
performs the CQ-head Release, and stops this ENTER's drain. The work item and
descriptor are embedded in the ENTER context or retained
request/system-lane state; CQ handling never allocates them. The owner then
releases the physical token and performs domain locking, apply, notify
delivery, or access checks. No other CQ-role ENTER can execute on that ring
while `cq_enter_owner` is set, even though the token is free; the independent
SQ waiter may remain active. The configured semantic-owner bound is
`max_inflight + 3 * ring_count + 1 <= 16777216`; with at most one inline
unacknowledged-NOTIFY continuation per outstanding CQ-role ENTER, the total
execution-continuation bound is 16777280 at maximum topology, and live ENTER
IRP contexts are separately bounded by `2 * ring_count <= 128`. There is no
`IoCompleteRequest` under a ring token, domain/FCB/CCB lock, notification
gate, or mount rundown. A fence wake before any CQ commit completes
INVALID_DEVICE_STATE with zero output; after the first commit, ENTER returns
SUCCESS with exactly its committed prefix and credits.

The fence order is exact. After closing admission and signalling ENTER, it
removes the old daemon's writable producer mappings and waits only the
producer publication/mapping-capture rundown needed to prove that no later CQ
Release is possible. It then acquires every per-ring sole-consumer token in
increasing ring-index order and, retaining all tokens, walks each ring's
stable CQ prefix in order, at most `cq_capacity` cells, using one
SETUP-preallocated `MAX_NOTIFICATION_CREDIT_SIZE` scratch buffer. Each stable
completion, PROTOCOL record, and acknowledgement-required NOTIFY is privately
captured, assigned its preallocated semantic terminal owner under the normal
state gate, and CQ-head Released. Unacknowledged notifications are validated
and folded into the fence's conservative cold-invalidation state. No
domain/FCB/CCB/namespace lock, access check, callback, or blocking action
runs while a token is held. A fence-consumed notification credit is retired
with the old section rather than returned through ENTER; ATTACH creates and
returns a completely fresh credit pool. The walk stops at the first unready
sequence because no later cell is a published prefix member; it never skips a
cell or interprets bytes after the first gap. Only after every stable prefix
has been owned and all tokens released does the fence queue the newly
installed work, wait for every pre-existing or new shared ENTER continuation
and detached semantic owner that references the old CQ, grants, or views,
and then complete the remaining session/mapping rundown and discard the old
views.

Draining a stable prefix cannot prove that a provider died before an intended
notification Release. Therefore, before entering recoverable GRACE, the fence
also suspends every PT fast path and conservatively invalidates all clean
provider-derived data, name, negative-name, directory, size, security, and
coherency cache state for the MountId. Dirty/paging writes and journaled
operations remain blocked and follow their retained recovery states; they are
not silently discarded. If cache-section purge, mapped-section rundown, or PT
rundown cannot be proven complete, the mount enters deterministic teardown
instead of ATTACH.

Independently of which DIR_CHANGE records were in the stable prefix, the
notify-admission gate closes atomically with ENTER admission. The driver owns
every change-notify IRP in its own IO_CSQ; no FsRtl opaque notify
registration exists. The fence increments the nonzero, nonwrapping mount
`notify_fence_generation`, waits notification-event rundown, clears every
registration/accumulator, and removes each still-queued mount IRP through
IO_CSQ. Each successful removal has one completion owner and returns
`STATUS_NOTIFY_ENUM_DIR = 0x0000010c`, zero information, and untouched
output. A racing request that observes the closed gate receives the same
result without queueing. Every pre-existing directory CCB retains a
post-fence rescan marker; its first request after ATTACH returns the same
status and advances the marker even if an event owner completed an older IRP
just before the fence. A new post-ATTACH CCB starts at the current
generation. Generation exhaustion terminalizes the mount rather than
wrapping. This overflow outcome is installed before GRACE becomes externally
visible, so an unpublished provider change cannot be reported as silence.

### 10.21 Journal bundle lifecycle and acknowledgement

When EXACTLY_ONCE is selected, exactly COMMIT_OPEN, WRITE, and MUTATE are
journaled in base 2.1; all three use the PREPARED/COMMITTED/QUERY_OP/
ACK_RESULT handshake, and the operation digest and result wire schemas live
in document 03. When it is not selected, none creates a durable journal
bundle or digest, QUERY_OP and ACK_RESULT are never emitted, daemon loss
tears the mount down, and no operation is replayed into another session.

The physical journal registry has exactly three legal bundles. "Absent" means
that the row and its accounting reservation are both absent; "present" means
that both exist and their canonical charge is reflected in the counters:

| Logical state | IMMUTABLE_REQUEST | JOURNAL | COMMITTED_RESULT |
|---|---|---|---|
| ABSENT | absent | absent | absent |
| PREPARED | RETAINED | PREPARED | absent |
| COMMITTED | absent | COMMITTED | COMMITTED |

All present rows use the same MountId prefix and OpId, and their opcode,
mutation kind, operation digest, payload digest, and result projection
cross-check exactly. `ABSENT -> PREPARED` atomically creates the immutable
request and PREPARED journal rows, their reservations, and every accounting
delta before a backing effect. `PREPARED -> COMMITTED` atomically performs
the backing effect, allocates the volume sequence, changes JOURNAL to
COMMITTED, inserts COMMITTED_RESULT, deletes/refunds IMMUTABLE_REQUEST and
its reservation, and updates all accounting. COMMIT_OPEN additionally
deletes/refunds its PREPARE and PREPARE_TX_INDEX pair in that same
transaction. `ABORT_IF_PREPARED` and a registered terminal failure with no
effect atomically delete/refund the complete PREPARED bundle before reporting
NOT_FOUND. ACK_RESULT atomically deletes/refunds the complete COMMITTED
bundle; it is idempotent only when the complete bundle and all of its
reservations are absent, so a lost successful acknowledgement can be retried
without a permanent tombstone. A partial bundle or any present row with the
same OpId and a different digest is corruption and cannot be inferred as a
prior ACK.

QUERY_OP classifies NOT_FOUND only from complete ABSENT, PREPARED only from
the exact PREPARED bundle, and COMMITTED only from the exact COMMITTED
bundle. Any partial, one-sided, wrong-state, extra-row, mismatched-digest,
orphan-reservation, or inconsistent-charge combination is corruption and is
never normalized to NOT_FOUND. Retaining the potentially 16-MiB immutable
WRITE bytes only through PREPARED is deliberate: the provider needs only the
digest and canonical durable result after commit, while the kernel retains
its original request for result verification. QueryOp BUFFER_TOO_SMALL has no
result blob, reports the required committed-result bytes in CQ information,
changes no journal state, and admits exactly one bounded retry
(`MAX_QUERY_OP_BTS_RETRIES = 1`) on the same logical slot with the next
nonzero generation.

When EXACTLY_ONCE is selected, WRITE semantic bytes come only from a
kernel-owned immutable snapshot: locking an application MDL and mapping it
read-only into the daemon is insufficient because the original user alias can
still modify those pages. The kernel copies the source once into a K2U slot
or shadow MDL with no application-writable alias, computes the digest from
that same snapshot, and retains it through PREPARED recovery until a terminal
result and ACK/rundown. `MAX_JOURNALED_WRITE_BYTES_PER_REQUEST = 16777216`
and `MAX_IMMUTABLE_WRITE_BYTES_PER_MOUNT = 268435456`; larger application
writes are split in CCB order into independently identified chunks, and
snapshot-pool admission is bounded and cancel-safe. Without an immutable
shadow-mapping grant, the effective per-request chunk cap is
`min(MAX_JOURNALED_WRITE_BYTES_PER_REQUEST, largest K2U slot size)`. Each
chunk has its own OpId/digest and CQ byte count, while the parent IRP reports
the ordered committed prefix under normal Windows partial-write rules. No
digest is computed from one view and committed from another.

Within one live kernel mount incarnation, an unacknowledged COMMITTED bundle
survives daemon process exit and session fencing; it is discoverable by
QUERY_OP until ACK_RESULT deletion succeeds. Session loss alone is not
acknowledgement. A PREPARED bundle is never silently pruned because of
timeout or live-mount session loss. A clean DETACH is DEVICE_BUSY while any
retained request is PREPARED/COMMITTED or any ACK is outstanding; it succeeds
only after the journal handshake is drained. This ABI deliberately does not
claim kernel-ledger recovery across an OS crash: only after an authenticated
SessionResult/RetireMountResult reports a different BootInstanceId may
provider recovery retire its old-incarnation PREPARED and COMMITTED bundles,
their result/immutable blobs, and all corresponding reservations/accounting
atomically; it must never resubmit an old-incarnation bundle into the new
MountId.

### 10.22 Durable external-change outbox and PT acknowledgement lanes

Every provider/external mutation not initiated by an FSRING OpId must
atomically commit either one or more precise external-change outbox rows or
one covering OVERFLOW row with the backing effect. A separate change journal
is acceptable only if cursor advance and outbox append are one transaction; a
detected gap becomes OVERFLOW. A backend that cannot make this atomic must
reject/disable external mutation before effect; silence is never a fallback.
For restart mounts the outbox and latest-processed tuple are durable MountId
children charged under Section 10.15. For nonrestart mounts they use the same
bounded state machine in volatile provider memory and are destroyed on
daemon loss/direct teardown.

```text
MAX_DURABLE_EXTERNAL_OUTBOX_RECORDS = 4096
MAX_DURABLE_EXTERNAL_OUTBOX_BYTES   = 8388608
MAX_OUTSTANDING_EXTERNAL_CHANGE     = 1
```

Only 4095 slots and all but 2048 bytes admit precise rows; one slot and 2048
bytes are permanently reserved for overflow. This byte accounting includes
the exact key, canonical envelope/body, and Section 10.15 record overhead;
golden vectors prove each possible overflow row is charged at no more than
2048 bytes. Outbox ordinals are nonzero, contiguous, and nonwrapping. The
published head is immutable. If a precise tail cannot fit, one transaction
replaces every nonpublished tail row with an OVERFLOW spanning the earliest
discarded through newest ordinal; a tail overflow extends atomically.
Admission tests the final transactional charge, never a transient
delete-then-insert state. The 8-MiB queued-outbox byte bound sums the charged
bytes of OUTBOX_ROW values only; the fixed metadata rows remain in ordinary
accounting but are outside the queued row/byte counts.

DIR_CHANGE is ring-zero and acknowledgement-required. A new record starts
exactly at `kernel_external_high_watermark + 1`; a precise record has one
ordinal, and an overflow advances through its range. The kernel retains the
latest `(token, through_ordinal, volume_commit_sequence, semantic_digest)`
tuple until mount retirement, where

```text
semantic_digest = SHA256(
  ASCII "FSRING-EXTERNAL-DIR-CHANGE-v1\0" ||
  MountId.lo_le || MountId.hi_le ||
  canonical NotifyEnvelopeV2 bytes through struct_size)
```

Session credit/BufferRef coordinates are excluded. An exact latest duplicate
is not applied twice and is re-ACKed; a changed duplicate, old nonlatest,
gap, overlap, wrong ring/token, or second published record is a protocol
fault. Credit return is only transport ownership and never authorizes outbox
deletion. The DIR_CHANGE AckToken lane, the inline 64-byte `PDirChangeAckV1`
acknowledgement payload, and the `ExternalDirChangeV1`/`ExternalChangeCutV1`/
`ExternalChangeReadyV1` body layouts are defined in document 03; the
DIR_CHANGE_ACK SQE carries its payload inline with `payload_len = 64`, and a
PControl/BufferRef form is rejected. The acknowledgement uses the distinct
global ReqId `GLOBAL_EXTERNAL_CHANGE_ACK_REQID`. The provider atomically
deletes/advances only the exact durable head and writes latest_processed
before its SUCCESS CQ Release; an exact ACK of latest_processed succeeds
without repeating deletion. No next external record may be CQ-published until
that SUCCESS Release; ring-zero FIFO is the ordering barrier.

A fence preserves the external high-watermark/latest tuple and every
CAPTURED or ACK-visible state. Captured work is delivered or covered by the
fence's cold cache/rescan result before GRACE. A record beyond the old stable
prefix remains in the provider outbox and is republished with a fresh session
credit; the watermark and latest tuple are durable across fences.

ATTACH keeps native notify admission closed and reconciles with a
CUT/probe/READY handshake. In one serializable transaction the provider
requires the materialized ORDINAL_COUNTER and executes the ATTACH_CUT
get-or-create rule: it deletes/refunds every older-epoch cut/reservation,
then either returns the exact immutable current-epoch `stored_cut`
(validating its charge and `stored_cut <= ORDINAL_COUNTER`) or reads the
counter exactly once while atomically inserting the row, reservation, and
accounting delta with that snapshot. Zero is legal on creation exactly when
the counter snapshot is zero; on retry an existing zero remains valid even if
post-cut transactions have advanced the counter. A one-sided
row/reservation, duplicate current-epoch key, stored cut above the counter,
or attempted resize/replacement is corruption. The provider then publishes
`EXTERNAL_CHANGE_CUT` carrying the stored value before any probe or row. The
kernel accepts it once and requires
`kernel_external_high_watermark <= attach_cut`; an exact duplicate CUT before
any progress is idempotent, and a missing/changed duplicate or any duplicate
after progress is a protocol fault.

The kernel then prepares an idempotent DIR_CHANGE_ACK probe containing the
complete retained `PDirChangeAckV1` when its high-watermark is nonzero; no
zero-token probe is sent. The provider compares token, range, volume
sequence, and digest against the exact durable head or latest_processed,
then drains every row in `(kernel_high_watermark, attach_cut]`; post-cut rows
remain queued. After the final ACK SUCCESS Release it publishes ring-zero
`ExternalChangeReadyV1` with
`reconcile_cut == processed_high_watermark == stored kernel attach_cut` and
zero flags/reserved. The CUT and READY envelope FileId/AckToken/flags are
zero. READY is legal only during external reconciliation and after no
pre-cut head remains; the kernel requires stored cut, provider processed
high-watermark, and kernel high-watermark all equal. Early, mismatched,
cross-ring, backward, or post-active READY is a protocol fault; an exact
duplicate before activation is idempotent. Both READY watermarks may be zero
only when ORDINAL_COUNTER, the stored cut, and the kernel high-watermark are
zero. The provider deletes the current attach-epoch cut row and reservation
only in the transaction that makes READY publishable; that transaction
asserts no older cut remains, and the later ROOT ACTIVE transaction repeats
the zero-cut assertion. Only after READY and all PT/open replay barriers
does ATTACH reopen Windows notify admission. On initial SETUP the lane
starts at zero and needs no READY handshake.

The two PT acknowledgement kinds use per-`(MountId, ring, kind)` token lanes
with `MAX_OUTSTANDING_PT_ACKS_PER_KIND_PER_RING = 1`: a new token ordinal is
exactly the retained lane high-watermark plus one, never skipped, reused, or
wrapped. Kernel and provider each retain the lane high-watermark and latest
exact `(token, FileId, pt_epoch, notify_code)` tuple until mount retirement.
With the restart pair the provider durably stores PENDING before the
notification's CQ Release; without it the same bounded tuple is
session-local. PENDING preserves the lane's immediately preceding PROCESSED
tuple at the same time, so provider lane storage is exactly
`{latest_processed?, pending?}` — at most two records — and for restart
mounts `MAX_DURABLE_PT_LANE_RECORDS_PER_MOUNT = 4 * ring_count`, at most 256.
A second distinct notification while PENDING exists is a protocol fault. The
two kinds may progress concurrently, and neither consumes an application
`max_inflight` entry or an unbounded kernel queue. Publishing the
acknowledgement uses the owning ring's dedicated system ReqId/SQ lane and a
fresh generation; the `PNotifyAck` payload, AckToken encoding, and
`PtLaneReadyV1` body are defined in document 03.

On receiving the acknowledgement, the provider accepts either its exact
PENDING tuple or an exact repeat of latest_processed. For PENDING it
atomically performs the provider-side transition and replaces
latest_processed with that tuple before posting SUCCESS; an exact processed
repeat posts SUCCESS without repeating the transition. Unknown, lower,
skipped, cross-lane, or tuple-mismatched values are protocol faults. Session
fencing preserves the high-watermark/latest tuple and any
PT_ACK_UNSENT/PT_ACK_MAY_BE_VISIBLE state, discards old ReqId generations,
and leaves PT suspended. Before ATTACH returns SUCCESS, the kernel
prepublishes one reconciliation acknowledgement probe with a fresh generation
on every lane whose high-watermark is nonzero. After ATTACH the provider
drains a lane's present probe before publishing any notification on that
lane; a probe equal to PENDING processes it and suppresses republication, a
probe equal to latest_processed returns duplicate SUCCESS and any newer
durable PENDING is republished with the same semantic token/body under a
fresh credit, and a mismatch is a protocol fault. ATTACH initializes all
`2 * ring_count` per-session lane-ready bits false and enters PT_RECONCILING;
`PT_LANE_READY` is legal only in that state, and the kernel verifies its
high_watermark equals its own retained value. Every fence clears all ready
bits as well as all backing/grant state. No PT fast path is enabled until
READY has been consumed for both kinds on every ring and open replay is
complete; each file additionally requires a fresh current-session
DONATE_BACKING and matching PT_GRANT. No fence, attach, detach, timeout, or
credit path can lose PENDING or exceed the two-record lane bound.

### 10.23 The closed IOCTL status registry

The externally visible IOCTL statuses are a closed registry:

```text
SUCCESS                 0x00000000
DEVICE_BUSY             0x80000011
INVALID_PARAMETER       0xc000000d
ACCESS_DENIED           0xc0000022
BUFFER_TOO_SMALL        0xc0000023
REVISION_MISMATCH       0xc0000059
INTEGER_OVERFLOW        0xc0000095
INSUFFICIENT_RESOURCES  0xc000009a
NOT_SUPPORTED           0xc00000bb
CANCELLED               0xc0000120
INVALID_DEVICE_STATE    0xc0000184
```

| IOCTL | Exact legal statuses |
|---|---|
| SETUP | SUCCESS, DEVICE_BUSY, INVALID_PARAMETER, ACCESS_DENIED, BUFFER_TOO_SMALL, REVISION_MISMATCH, INTEGER_OVERFLOW, INSUFFICIENT_RESOURCES, NOT_SUPPORTED, CANCELLED |
| ATTACH | SUCCESS, DEVICE_BUSY, INVALID_PARAMETER, ACCESS_DENIED, BUFFER_TOO_SMALL, REVISION_MISMATCH, INSUFFICIENT_RESOURCES, NOT_SUPPORTED, CANCELLED, INVALID_DEVICE_STATE |
| ENTER | SUCCESS, DEVICE_BUSY, INVALID_PARAMETER, ACCESS_DENIED, BUFFER_TOO_SMALL, REVISION_MISMATCH, NOT_SUPPORTED, CANCELLED, INVALID_DEVICE_STATE |
| DONATE_BACKING | SUCCESS, DEVICE_BUSY, INVALID_PARAMETER, ACCESS_DENIED, REVISION_MISMATCH, INSUFFICIENT_RESOURCES, NOT_SUPPORTED, CANCELLED, INVALID_DEVICE_STATE |
| DONATE_SECURITY_CONTEXT | INVALID_PARAMETER, ACCESS_DENIED, REVISION_MISMATCH, NOT_SUPPORTED, INVALID_DEVICE_STATE |
| DETACH | SUCCESS, DEVICE_BUSY, INVALID_PARAMETER, ACCESS_DENIED, REVISION_MISMATCH, NOT_SUPPORTED, CANCELLED, INVALID_DEVICE_STATE |
| RETIRE_MOUNT | SUCCESS, DEVICE_BUSY, INVALID_PARAMETER, ACCESS_DENIED, BUFFER_TOO_SMALL, REVISION_MISMATCH, NOT_SUPPORTED, INVALID_DEVICE_STATE |

A normal ENTER wait timeout is SUCCESS with `TIMED_OUT`. Every failed call
sets `IoStatus.Information = 0` and has the
no-partial-output/no-uninitialized-output rule; the SDK computes required
variable output size from its accepted topology. Any other status is an
internal driver failure, not an ABI result. After requestor/process
authorization and an eight-byte header snapshot, every versioned IOCTL uses
Section 1.4's common mapping before opcode-specific validation: unsupported
required_flags is NOT_SUPPORTED and an unknown ABI minor or struct_version is
REVISION_MISMATCH. In particular a valid-version DONATE_SECURITY_CONTEXT is
NOT_SUPPORTED, while its unknown version is REVISION_MISMATCH. No
opcode-specific closed registry overrides that precedence.

## 11. Backpressure and hot-path requirements

`Full` is ordinary bounded ring backpressure. `Contended` means one bounded
MPSC call exhausted its `MAX_RESERVE_RETRIES = 64` reservation-attempt bound
under observed progress. `Protocol(CursorFault)` — including the two-snapshot
`OverCapacity` classification of Section 6.2 — is structural and follows
Section 8.3. These outcomes MUST remain distinguishable.

The steady-state push/pop path is O(1), allocation-free, and independent of a
volume-global lock. It touches only the selected ring, uses the per-entry
sequence as publication, and performs no validation scan proportional to
daemon-controlled input. Batching MAY amortize wake and ENTER overhead, but
each entry still has its own Release/Acquire edge, exact-sequence test,
bounds checks, local copy, and terminal ownership arbitration.

A release MUST preserve the byte tables above in Rust and generated C, pass
native MPSC/SPSC stress and park/wake tests, exercise reuse, publication, and
the over-capacity two-snapshot classification in the pinned Loom model,
verify peer read-only mappings on Windows, and fuzz hostile
descriptors/cursors/CQEs without panic, memory corruption, unbounded
execution, lost completion, or duplicate completion. Performance results are
invalid if any of those correctness checks are disabled.

## C4 native session transport

SETUP is a single ordered choreography of twenty-three effects with exactly one
commit. The order is `AcquireControlRundown`, `SnapshotAndValidateInput`,
`ValidateOutputCapacity`, `RejectDuplicate`, `AcquireBootLockEvent`,
`BurnMountId`, `ReleaseBootLockEvent`, `ComputeLayoutAndLedger`,
`AllocateSectionAndSystemView`, `ConstructAndValidateSection`, `AllocateGrants`,
`AllocateEventsAndScratch`, `CreateSecureVdo`, `CaptureProcess`,
`BuildProtectedViews`, `BuildOutput`, `ValidateOutput`,
`InstallStrongReferences`, `PublishActive`, `ClearVdoInitializing`,
`CopyOutputAndComplete`, `EmitSessionPublished`, `ReleaseControlRundown`.

Before `PublishActive` a failure or cancellation yields the exact reverse
unwind. At or after it there is no unwind: the Release store has made the
session reachable, every remaining action is designed infallible, and
cancellation loses. A burned MountId is never handed back for reuse; the
rollback carries `PreserveBurnedMountId` to say so explicitly.

The result geometry is derived by the driver from the validated request with the
frozen ABI's own checked arithmetic: `view_count = 2 + 3 * ring_count`, and the
complete size is `SESSION_RESULT_V1_PREFIX_SIZE` plus the view and credit tails.
No executor supplies those numbers, and a short output buffer is refused before
the burn. ENTER returns exactly `48 + credit_count * 32` bytes.

A session owns one negotiated-size DRAIN scratch per ring plus one independent
`MAX_NOTIFICATION_CREDIT_SIZE` fence scratch. Their identities come from one
roster, so no two rings can share a buffer.
